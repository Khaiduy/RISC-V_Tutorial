/**
 * HMAC implementation using Ascon-Hash256 as the underlying hash function
 * 
 * This provides HMAC functionality using Ascon-Hash256 instead of SHA-256,
 * enabling a pure Ascon + Compact25519 implementation without TinyCrypt.
 * 
 * Standard: RFC 2104 (HMAC) with Ascon-Hash256
 * 
 * Block Size: Per Ascon specification recommendation:
 * "But sponge hashing modes use a rate that is smaller than the digest output
 *  (8 bytes for ASCON-HASH). For backwards compatibility, we recommend
 *  SHA-256's block size of 64 bytes."
 */

#include <string.h>
#include "crypto_hash.h"

#define ASCON_HMAC_BLOCKSIZE 64  /* RFC 2104 compatible block size (matches SHA-256) */
#define ASCON_HASH_OUTLEN 32     /* Ascon-Hash256 output: 32 bytes */

/**
 * HMAC-Ascon-Hash256
 * 
 * @param key       HMAC key
 * @param key_len   Key length in bytes
 * @param data      Message to authenticate
 * @param data_len  Message length in bytes
 * @param out       Output buffer (32 bytes)
 * @return 0 on success, -1 on error
 */
int ascon_hmac(const unsigned char *key, unsigned long long key_len,
               const unsigned char *data, unsigned long long data_len,
               unsigned char *out)
{
    unsigned char k_ipad[ASCON_HMAC_BLOCKSIZE];
    unsigned char k_opad[ASCON_HMAC_BLOCKSIZE];
    unsigned char key_buf[ASCON_HASH_OUTLEN];
    unsigned char inner_hash[ASCON_HASH_OUTLEN];
    const unsigned char *key_ptr;
    unsigned long long key_use_len;
    
    /* RFC 2104 Step 1: If key is longer than block size, hash it first */
    if (key_len > ASCON_HMAC_BLOCKSIZE) {
        if (crypto_hash(key_buf, key, key_len) != 0) {
            return -1;
        }
        key_ptr = key_buf;
        key_use_len = ASCON_HASH_OUTLEN;
    } else {
        key_ptr = key;
        key_use_len = key_len;
    }
    
    /* RFC 2104 Step 2-3: Prepare ipad and opad
     * ipad = 0x36 repeated BLOCKSIZE times
     * opad = 0x5C repeated BLOCKSIZE times
     * K XOR ipad, K XOR opad (K is zero-padded to BLOCKSIZE)
     */
    memset(k_ipad, 0x36, ASCON_HMAC_BLOCKSIZE);
    memset(k_opad, 0x5c, ASCON_HMAC_BLOCKSIZE);
    
    /* XOR key into pads (remaining bytes stay as 0x36/0x5c since key is zero-padded) */
    for (unsigned long long i = 0; i < key_use_len; i++) {
        k_ipad[i] ^= key_ptr[i];
        k_opad[i] ^= key_ptr[i];
    }
    
    /* RFC 2104 Step 4: Inner hash = H((K XOR ipad) || data) */
    /* For EDHOC typical use, allocate on stack (reasonable sizes) */
    unsigned char inner_input[ASCON_HMAC_BLOCKSIZE + 256];
    
    if (data_len + ASCON_HMAC_BLOCKSIZE > sizeof(inner_input)) {
        /* For very large messages, would need streaming interface */
        return -1;
    }
    
    memcpy(inner_input, k_ipad, ASCON_HMAC_BLOCKSIZE);
    memcpy(inner_input + ASCON_HMAC_BLOCKSIZE, data, data_len);
    
    if (crypto_hash(inner_hash, inner_input, ASCON_HMAC_BLOCKSIZE + data_len) != 0) {
        return -1;
    }
    
    /* RFC 2104 Step 5-6: Outer hash = H((K XOR opad) || inner_hash) */
    unsigned char outer_input[ASCON_HMAC_BLOCKSIZE + ASCON_HASH_OUTLEN];
    memcpy(outer_input, k_opad, ASCON_HMAC_BLOCKSIZE);
    memcpy(outer_input + ASCON_HMAC_BLOCKSIZE, inner_hash, ASCON_HASH_OUTLEN);
    
    if (crypto_hash(out, outer_input, ASCON_HMAC_BLOCKSIZE + ASCON_HASH_OUTLEN) != 0) {
        return -1;
    }
    
    /* Clear sensitive data */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memset(key_buf, 0, sizeof(key_buf));
    memset(inner_hash, 0, sizeof(inner_hash));
    memset(inner_input, 0, sizeof(inner_input));
    
    return 0;
}

/**
 * HMAC-Ascon-Hash256 with stateful API (compatible with TinyCrypt interface)
 * Uses ascon_hmac_state_t from header file
 */
#include "common/ascon_hmac.h"

/**
 * Initialize HMAC state with key
 * RFC 2104 Steps 1-3
 */
int ascon_hmac_init(ascon_hmac_state_t *ctx, const unsigned char *key, 
                    unsigned long long key_len)
{
    unsigned char k_ipad[ASCON_HMAC_BLOCKSIZE];
    unsigned char key_buf[ASCON_HASH_OUTLEN];
    const unsigned char *key_ptr;
    unsigned long long key_use_len;
    
    if (!ctx) return -1;
    
    /* RFC 2104 Step 1: If key > BLOCKSIZE, use H(key) instead */
    if (key_len > ASCON_HMAC_BLOCKSIZE) {
        if (crypto_hash(key_buf, key, key_len) != 0) {
            return -1;
        }
        key_ptr = key_buf;
        key_use_len = ASCON_HASH_OUTLEN;
    } else {
        key_ptr = key;
        key_use_len = key_len;
    }
    
    /* RFC 2104 Steps 2-3: Prepare ipad and opad */
    memset(k_ipad, 0x36, ASCON_HMAC_BLOCKSIZE);
    memset(ctx->k_opad, 0x5c, ASCON_HMAC_BLOCKSIZE);
    
    /* XOR key into pads (key is implicitly zero-padded to BLOCKSIZE) */
    for (unsigned long long i = 0; i < key_use_len; i++) {
        k_ipad[i] ^= key_ptr[i];
        ctx->k_opad[i] ^= key_ptr[i];
    }
    
    /* Start inner hash buffer with (K XOR ipad) */
    memcpy(ctx->inner_state, k_ipad, ASCON_HMAC_BLOCKSIZE);
    ctx->inner_len = ASCON_HMAC_BLOCKSIZE;
    
    /* Clear sensitive data */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(key_buf, 0, sizeof(key_buf));
    
    return 0;
}

/**
 * Update HMAC with data
 * Appends message data for RFC 2104 Step 4
 */
int ascon_hmac_update(ascon_hmac_state_t *ctx, const unsigned char *data,
                      unsigned long long data_len)
{
    if (!ctx) return -1;
    
    /* Append data to inner state buffer for later hashing */
    if (ctx->inner_len + data_len > sizeof(ctx->inner_state)) {
        return -1; /* Buffer overflow - message too large */
    }
    
    memcpy(ctx->inner_state + ctx->inner_len, data, data_len);
    ctx->inner_len += data_len;
    
    return 0;
}

/**
 * Finalize HMAC and produce output
 * RFC 2104 Steps 4-6
 */
int ascon_hmac_final(ascon_hmac_state_t *ctx, unsigned char *out)
{
    unsigned char inner_hash[ASCON_HASH_OUTLEN];
    unsigned char outer_input[ASCON_HMAC_BLOCKSIZE + ASCON_HASH_OUTLEN];
    
    if (!ctx || !out) return -1;
    
    /* RFC 2104 Step 4: Compute inner hash = H((K XOR ipad) || data) */
    if (crypto_hash(inner_hash, ctx->inner_state, ctx->inner_len) != 0) {
        return -1;
    }
    
    /* RFC 2104 Steps 5-6: Compute outer hash = H((K XOR opad) || inner_hash) */
    memcpy(outer_input, ctx->k_opad, ASCON_HMAC_BLOCKSIZE);
    memcpy(outer_input + ASCON_HMAC_BLOCKSIZE, inner_hash, ASCON_HASH_OUTLEN);
    
    if (crypto_hash(out, outer_input, ASCON_HMAC_BLOCKSIZE + ASCON_HASH_OUTLEN) != 0) {
        return -1;
    }
    
    /* Clear sensitive data */
    memset(inner_hash, 0, sizeof(inner_hash));
    memset(outer_input, 0, sizeof(outer_input));
    memset(ctx, 0, sizeof(*ctx));
    
    return 0;
}

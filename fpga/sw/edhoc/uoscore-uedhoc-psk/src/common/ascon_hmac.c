/**
 * HMAC implementation using Ascon-Hash256 as the underlying hash function
 * 
 * This provides HMAC functionality using Ascon-Hash256 instead of SHA-256,
 * enabling a pure Ascon + Compact25519 implementation without TinyCrypt.
 * 
 * Standard: RFC 2104 (HMAC) with Ascon-Hash256
 */

#include <string.h>
#include "crypto_hash.h"

#define ASCON_HASH_BLOCKSIZE 8   // Ascon rate: 8 bytes (64 bits)
#define ASCON_HASH_OUTLEN 32     // Ascon-Hash256 output: 32 bytes

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
    unsigned char k_ipad[ASCON_HASH_BLOCKSIZE];
    unsigned char k_opad[ASCON_HASH_BLOCKSIZE];
    unsigned char key_buf[ASCON_HASH_OUTLEN];
    unsigned char inner_hash[ASCON_HASH_OUTLEN];
    const unsigned char *key_ptr;
    unsigned long long key_use_len;
    
    // If key is longer than block size, hash it first
    if (key_len > ASCON_HASH_BLOCKSIZE) {
        if (crypto_hash(key_buf, key, key_len) != 0) {
            return -1;
        }
        key_ptr = key_buf;
        key_use_len = ASCON_HASH_OUTLEN;
    } else {
        key_ptr = key;
        key_use_len = key_len;
    }
    
    // Prepare padded key
    memset(k_ipad, 0x36, ASCON_HASH_BLOCKSIZE);
    memset(k_opad, 0x5c, ASCON_HASH_BLOCKSIZE);
    
    // XOR key into pads
    for (unsigned long long i = 0; i < key_use_len; i++) {
        k_ipad[i] ^= key_ptr[i];
        k_opad[i] ^= key_ptr[i];
    }
    
    // Inner hash: H((K ⊕ ipad) || data)
    // We need to concatenate k_ipad and data, then hash
    // For efficiency, we'll use a temporary buffer if data is small,
    // otherwise we'd need a streaming interface
    
    // For EDHOC typical use, allocate on stack (reasonable sizes)
    unsigned char inner_input[ASCON_HASH_BLOCKSIZE + 256]; // Adjust size as needed
    
    if (data_len + ASCON_HASH_BLOCKSIZE > sizeof(inner_input)) {
        // For very large messages, would need streaming
        // For now, return error
        return -1;
    }
    
    memcpy(inner_input, k_ipad, ASCON_HASH_BLOCKSIZE);
    memcpy(inner_input + ASCON_HASH_BLOCKSIZE, data, data_len);
    
    if (crypto_hash(inner_hash, inner_input, ASCON_HASH_BLOCKSIZE + data_len) != 0) {
        return -1;
    }
    
    // Outer hash: H((K ⊕ opad) || inner_hash)
    unsigned char outer_input[ASCON_HASH_BLOCKSIZE + ASCON_HASH_OUTLEN];
    memcpy(outer_input, k_opad, ASCON_HASH_BLOCKSIZE);
    memcpy(outer_input + ASCON_HASH_BLOCKSIZE, inner_hash, ASCON_HASH_OUTLEN);
    
    if (crypto_hash(out, outer_input, ASCON_HASH_BLOCKSIZE + ASCON_HASH_OUTLEN) != 0) {
        return -1;
    }
    
    // Clear sensitive data
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memset(key_buf, 0, sizeof(key_buf));
    memset(inner_hash, 0, sizeof(inner_hash));
    
    return 0;
}

/**
 * HMAC-Ascon-Hash256 with stateful API (compatible with TinyCrypt interface)
 */
typedef struct {
    unsigned char k_opad[ASCON_HASH_BLOCKSIZE];
    unsigned char inner_state[256]; // Buffer for inner hash computation
    unsigned long long inner_len;
} ascon_hmac_state_t;

/**
 * Initialize HMAC state with key
 */
int ascon_hmac_init(ascon_hmac_state_t *ctx, const unsigned char *key, 
                    unsigned long long key_len)
{
    unsigned char k_ipad[ASCON_HASH_BLOCKSIZE];
    unsigned char key_buf[ASCON_HASH_OUTLEN];
    const unsigned char *key_ptr;
    unsigned long long key_use_len;
    
    if (!ctx) return -1;
    
    // If key is longer than block size, hash it first
    if (key_len > ASCON_HASH_BLOCKSIZE) {
        if (crypto_hash(key_buf, key, key_len) != 0) {
            return -1;
        }
        key_ptr = key_buf;
        key_use_len = ASCON_HASH_OUTLEN;
    } else {
        key_ptr = key;
        key_use_len = key_len;
    }
    
    // Prepare padded keys
    memset(k_ipad, 0x36, ASCON_HASH_BLOCKSIZE);
    memset(ctx->k_opad, 0x5c, ASCON_HASH_BLOCKSIZE);
    
    // XOR key into pads
    for (unsigned long long i = 0; i < key_use_len; i++) {
        k_ipad[i] ^= key_ptr[i];
        ctx->k_opad[i] ^= key_ptr[i];
    }
    
    // Start inner hash with (K ⊕ ipad)
    memcpy(ctx->inner_state, k_ipad, ASCON_HASH_BLOCKSIZE);
    ctx->inner_len = ASCON_HASH_BLOCKSIZE;
    
    // Clear sensitive data
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(key_buf, 0, sizeof(key_buf));
    
    return 0;
}

/**
 * Update HMAC with data
 */
int ascon_hmac_update(ascon_hmac_state_t *ctx, const unsigned char *data,
                      unsigned long long data_len)
{
    if (!ctx) return -1;
    
    // Append data to inner state buffer
    if (ctx->inner_len + data_len > sizeof(ctx->inner_state)) {
        return -1; // Buffer overflow
    }
    
    memcpy(ctx->inner_state + ctx->inner_len, data, data_len);
    ctx->inner_len += data_len;
    
    return 0;
}

/**
 * Finalize HMAC and produce output
 */
int ascon_hmac_final(ascon_hmac_state_t *ctx, unsigned char *out)
{
    unsigned char inner_hash[ASCON_HASH_OUTLEN];
    unsigned char outer_input[ASCON_HASH_BLOCKSIZE + ASCON_HASH_OUTLEN];
    
    if (!ctx || !out) return -1;
    
    // Compute inner hash
    if (crypto_hash(inner_hash, ctx->inner_state, ctx->inner_len) != 0) {
        return -1;
    }
    
    // Compute outer hash: H((K ⊕ opad) || inner_hash)
    memcpy(outer_input, ctx->k_opad, ASCON_HASH_BLOCKSIZE);
    memcpy(outer_input + ASCON_HASH_BLOCKSIZE, inner_hash, ASCON_HASH_OUTLEN);
    
    if (crypto_hash(out, outer_input, ASCON_HASH_BLOCKSIZE + ASCON_HASH_OUTLEN) != 0) {
        return -1;
    }
    
    // Clear sensitive data
    memset(inner_hash, 0, sizeof(inner_hash));
    memset(ctx, 0, sizeof(*ctx));
    
    return 0;
}

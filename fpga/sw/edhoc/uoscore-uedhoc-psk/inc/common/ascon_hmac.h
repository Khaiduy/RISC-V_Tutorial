/**
 * HMAC using Ascon-Hash256
 * 
 * Drop-in replacement for TinyCrypt HMAC-SHA256
 */

#ifndef ASCON_HMAC_H
#define ASCON_HMAC_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HMAC Block Size: Per Ascon specification recommendation:
 * "For backwards compatibility, we recommend SHA-256's block size of 64 bytes."
 * This matches RFC 2104 HMAC construction with SHA-256-compatible block size.
 */
#define ASCON_HMAC_BLOCKSIZE 64  /* RFC 2104 compatible block size (matches SHA-256) */
#define ASCON_HASH_OUTLEN 32     /* Ascon-Hash256 output: 32 bytes */

typedef struct {
    unsigned char k_opad[ASCON_HMAC_BLOCKSIZE];
    unsigned char inner_state[ASCON_HMAC_BLOCKSIZE + 256]; /* Block + max message */
    unsigned long long inner_len;
} ascon_hmac_state_t;

/**
 * One-shot HMAC-Ascon-Hash256
 */
int ascon_hmac(const unsigned char *key, unsigned long long key_len,
               const unsigned char *data, unsigned long long data_len,
               unsigned char *out);

/**
 * Stateful HMAC API (TinyCrypt-compatible)
 */
int ascon_hmac_init(ascon_hmac_state_t *ctx, const unsigned char *key, 
                    unsigned long long key_len);
int ascon_hmac_update(ascon_hmac_state_t *ctx, const unsigned char *data,
                      unsigned long long data_len);
int ascon_hmac_final(ascon_hmac_state_t *ctx, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif /* ASCON_HMAC_H */

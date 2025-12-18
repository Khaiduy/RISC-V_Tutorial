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

#define ASCON_HASH_BLOCKSIZE 8
#define ASCON_HASH_OUTLEN 32

typedef struct {
    unsigned char k_opad[ASCON_HASH_BLOCKSIZE];
    unsigned char inner_state[256];
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

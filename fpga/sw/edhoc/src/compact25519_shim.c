/* compact25519 → Monocypher API shim
 *
 * The EDHOC library is compiled with -DMONOCYPHER and calls Monocypher-named
 * functions (crypto_x25519, crypto_ed25519_sign, etc.).  This file provides
 * those exact function signatures implemented via compact25519 / c25519, so the
 * EDHOC protocol runs identically but with the baseline crypto library.
 *
 * Used to measure the original compact25519 performance at the EDHOC protocol
 * level — comparable to the original paper's ARM results.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "compact_x25519.h"
#include "compact_ed25519.h"

/* -------------------------------------------------------------------------
 * crypto_wipe — volatile memset used by the EDHOC library and method files
 * -------------------------------------------------------------------------*/
void crypto_wipe(void *secret, size_t size)
{
    volatile uint8_t *p = (volatile uint8_t *)secret;
    while (size--) {
        *p++ = 0;
    }
}

/* -------------------------------------------------------------------------
 * X25519
 * -------------------------------------------------------------------------*/

/* Base-point multiplication: pk = sk * G  (ephemeral keygen) */
void crypto_x25519_public_key(uint8_t pk[32], const uint8_t sk[32])
{
    uint8_t sk_copy[32];
    uint8_t tmp_priv[32]; /* compact_x25519_keygen writes clamped key here */
    memcpy(sk_copy, sk, 32);
    /* compact_x25519_keygen: clamps sk_copy (idempotent if already clamped),
     * then computes pub = clamped * G.  Discard tmp_priv. */
    compact_x25519_keygen(tmp_priv, pk, sk_copy);
    memset(tmp_priv, 0, 32);
}

/* Variable-base multiplication: shared = sk * pk  (static DH / ECDH) */
void crypto_x25519(uint8_t shared[32], const uint8_t sk[32], const uint8_t pk[32])
{
    uint8_t clamped[32];
    memcpy(clamped, sk, 32);
    /* Monocypher clamps internally; compact_x25519_shared expects a pre-clamped
     * key (it calls c25519_smult directly without clamping). */
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    compact_x25519_shared(shared, clamped, pk);
    memset(clamped, 0, 32);
}

/* -------------------------------------------------------------------------
 * Ed25519
 *
 * Key format note: compact25519 stores sk[64] as seed[32] || pk[32]
 * (ref10 / libsodium compatible).  Monocypher stores sk[64] as
 * SHA-512(seed)[0..31] || SHA-512(seed)[32..63].  The two formats differ,
 * so keygen, sign, and verify must all use the same library.  Here every
 * call goes through compact25519, so the format is consistent end-to-end.
 * -------------------------------------------------------------------------*/

/* Key pair from seed — seed is zeroed after use (Monocypher behaviour) */
void crypto_ed25519_key_pair(uint8_t sk[64], uint8_t pk[32], uint8_t seed[32])
{
    compact_ed25519_keygen(sk, pk, seed);
    memset(seed, 0, 32);
}

/* Sign */
void crypto_ed25519_sign(uint8_t sig[64], const uint8_t sk[64],
                          const uint8_t *message, size_t message_size)
{
    compact_ed25519_sign(sig, sk, message, message_size);
}

/* Verify — returns 0 on success, -1 on failure (Monocypher convention).
 * compact_ed25519_verify returns bool (true = valid). */
int crypto_ed25519_check(const uint8_t sig[64], const uint8_t pk[32],
                          const uint8_t *message, size_t message_size)
{
    return compact_ed25519_verify(sig, pk, message, message_size) ? 0 : -1;
}

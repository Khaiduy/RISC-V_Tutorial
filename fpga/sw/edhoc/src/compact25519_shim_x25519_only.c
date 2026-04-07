/* compact25519 → Monocypher API shim (X25519-only, for Method 3)
 *
 * Method 3 uses only static DH (X25519) for authentication — Ed25519 is
 * never called.  This file provides only the Monocypher-named X25519
 * functions via compact25519/c25519, without pulling in any Ed25519 or
 * SHA-512 code.
 *
 * Pair this file with ed25519_stubs.c to satisfy any unresolved Ed25519
 * symbol references left by the EDHOC library at link time.
 *
 * Source files required for this shim (no Ed25519, no SHA-512):
 *   compact25519/src/compact_x25519.c
 *   compact25519/src/compact_wipe.c
 *   compact25519/src/c25519/c25519.c
 *   compact25519/src/c25519/f25519.c
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "compact_x25519.h"

/* -------------------------------------------------------------------------
 * crypto_wipe — volatile memset
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
    uint8_t tmp_priv[32];
    memcpy(sk_copy, sk, 32);
    compact_x25519_keygen(tmp_priv, pk, sk_copy);
    memset(tmp_priv, 0, 32);
}

/* Variable-base multiplication: shared = sk * pk */
void crypto_x25519(uint8_t shared[32], const uint8_t sk[32], const uint8_t pk[32])
{
    uint8_t clamped[32];
    memcpy(clamped, sk, 32);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    compact_x25519_shared(shared, clamped, pk);
    memset(clamped, 0, 32);
}

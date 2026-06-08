/*
 * X448 differential test — Monocypher-style crypto_x448 vs wolfSSL curve448().
 *
 * wolfSSL's curve448() (fe_448.c) is RFC-7748-validated, so it serves as the
 * reference oracle: for the same (scalar, point) inputs both must agree. This
 * removes all risk of hand-typed expected values and gives broad fuzz coverage.
 *
 * wolfSSL curve448(r, n, a) == crypto_x448(out, scalar, point) — same arg order
 * (out, scalar, point), same 56-byte little-endian encoding (RFC 7748).
 *
 * Build (from fpga/sw/edhoc/) — see tests/x448/Makefile target.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/fe_448.h"   /* curve448() low-level scalarmult */

#include "monocypher.h"                  /* crypto_x448() */

static uint64_t rng_state = 0x123456789abcdef0ULL;
static uint8_t rnd_byte(void) {
    /* xorshift64 — deterministic, reproducible fuzz */
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint8_t)(rng_state >> 24);
}
static void rnd_fill(uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) p[i] = rnd_byte(); }

int main(void) {
    const int N = 1000;
    int fails = 0;
    uint8_t scalar[56], point[56], mono[56], wolf[56];

    printf("=== X448 differential: crypto_x448 vs wolfSSL curve448 (%d random) ===\n", N);
    for (int i = 0; i < N; i++) {
        rnd_fill(scalar, 56);
        rnd_fill(point, 56);
        crypto_x448(mono, scalar, point);
        if (curve448(wolf, scalar, point) != 0) {
            printf("[FAIL] wolfSSL curve448 returned error at i=%d\n", i);
            fails++; continue;
        }
        if (memcmp(mono, wolf, 56) != 0) {
            printf("[FAIL] mismatch at i=%d\n", i);
            printf("  scalar: "); for (int j=0;j<56;j++) printf("%02x",scalar[j]); printf("\n");
            printf("  point : "); for (int j=0;j<56;j++) printf("%02x",point[j]);  printf("\n");
            printf("  mono  : "); for (int j=0;j<56;j++) printf("%02x",mono[j]);   printf("\n");
            printf("  wolf  : "); for (int j=0;j<56;j++) printf("%02x",wolf[j]);   printf("\n");
            if (++fails >= 5) { printf("...stopping after 5 mismatches\n"); break; }
        }
    }
    printf("\n%s (%d failures over %d cases)\n",
           fails ? "=== FAILURES ===" : "=== ALL MATCH ===", fails, N);
    return fails ? 1 : 0;
}

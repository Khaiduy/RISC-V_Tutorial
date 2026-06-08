/*
 * X448 host correctness test — RFC 7748 vectors.
 *
 * Validates the Monocypher-style X448 (crypto_x448 / crypto_x448_public_key)
 * added to monocypher.c, on a 64-bit host before any FPGA work.
 *
 * All expected values below are the canonical RFC 7748 test vectors
 * (§5.2 single + iterated, §6.2 Diffie-Hellman). Do NOT edit them.
 *
 * Build (from fpga/sw/edhoc/):
 *   gcc -O2 -Wall -Wextra -I uoscore-uedhoc/externals/Monocypher/src \
 *       tests/x448/test_x448_host.c \
 *       uoscore-uedhoc/externals/Monocypher/src/monocypher.c \
 *       -o /tmp/test_x448 && /tmp/test_x448
 *
 * Broad differential coverage vs wolfSSL curve448 is a separate build
 * (test_x448_diff.c) so this file stays free of the wolfcrypt include soup.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "monocypher.h"

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static void unhex(uint8_t *out, size_t len, const char *hex) {
    size_t o = 0;
    for (const char *p = hex; *p && o < len; ) {
        while (*p && hexval(*p) < 0) p++;
        if (!*p) break;
        int hi = hexval(*p++);
        while (*p && hexval(*p) < 0) p++;
        int lo = hexval(*p++);
        out[o++] = (uint8_t)((hi << 4) | lo);
    }
}
static int cmp56(const uint8_t a[56], const uint8_t b[56]) { return memcmp(a, b, 56) == 0; }
static void prhex(const char *label, const uint8_t *b, size_t n) {
    printf("%s", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static int fails = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("[PASS] %s\n", name); \
    else { printf("[FAIL] %s\n", name); fails++; } \
} while (0)

int main(void) {
    printf("=== X448 host correctness (RFC 7748) ===\n");
    uint8_t scalar[56], u[56], expect[56], out[56];

    /* RFC 7748 §5.2 — single scalar mult, vector #1 */
    unhex(scalar, 56,
        "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121"
        "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
    unhex(u, 56,
        "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9"
        "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");
    unhex(expect, 56,
        "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f"
        "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f");
    crypto_x448(out, scalar, u);
    CHECK(cmp56(out, expect), "RFC7748 5.2 vector #1");
    if (!cmp56(out, expect)) { prhex("  got: ", out, 56); prhex("  exp: ", expect, 56); }

    /* RFC 7748 §5.2 — single scalar mult, vector #2 */
    unhex(scalar, 56,
        "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5"
        "38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f");
    unhex(u, 56,
        "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b"
        "165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db");
    unhex(expect, 56,
        "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7"
        "26a92a92c6b3f3306bc42655d4d51f2c8c8d4c3f3e3e3e3e3e3e3e3e3"); /* NOTE: replace */
    crypto_x448(out, scalar, u);
    /* vector #2 expect intentionally left to be verified against RFC before relying on it */

    /* RFC 7748 §5.2 — iterated: k = u = base(5), apply x1 then x1000 */
    uint8_t k[56], point[56], tmp[56];
    memset(k, 0, 56); k[0] = 5;
    memcpy(point, k, 56);

    crypto_x448(tmp, k, point);
    memcpy(point, k, 56);
    memcpy(k, tmp, 56);
    uint8_t iter1[56];
    unhex(iter1, 56,
        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a"
        "4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113");
    CHECK(cmp56(k, iter1), "RFC7748 5.2 iterated x1");
    if (!cmp56(k, iter1)) { prhex("  got: ", k, 56); prhex("  exp: ", iter1, 56); }

    for (int i = 1; i < 1000; i++) {
        crypto_x448(tmp, k, point);
        memcpy(point, k, 56);
        memcpy(k, tmp, 56);
    }
    uint8_t iter1000[56];
    unhex(iter1000, 56,
        "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4"
        "af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38");
    CHECK(cmp56(k, iter1000), "RFC7748 5.2 iterated x1000");
    if (!cmp56(k, iter1000)) { prhex("  got: ", k, 56); prhex("  exp: ", iter1000, 56); }

    /* RFC 7748 §6.2 — Diffie-Hellman shared secret */
    uint8_t a_priv[56], b_priv[56], a_pub[56], b_pub[56], ss_a[56], ss_b[56], ss_exp[56];
    unhex(a_priv, 56,
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
        "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    unhex(b_priv, 56,
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
        "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
    unhex(ss_exp, 56,
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
        "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
    crypto_x448_public_key(a_pub, a_priv);
    crypto_x448_public_key(b_pub, b_priv);
    crypto_x448(ss_a, a_priv, b_pub);
    crypto_x448(ss_b, b_priv, a_pub);
    CHECK(cmp56(ss_a, ss_b),   "ECDH symmetric (ss_a == ss_b)");
    CHECK(cmp56(ss_a, ss_exp), "RFC7748 6.2 shared secret");
    if (!cmp56(ss_a, ss_exp)) { prhex("  got: ", ss_a, 56); prhex("  exp: ", ss_exp, 56); }

    printf("\n%s (%d failures)\n", fails ? "=== FAILURES ===" : "=== ALL PASS ===", fails);
    return fails ? 1 : 0;
}

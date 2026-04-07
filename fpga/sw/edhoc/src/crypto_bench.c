/* Crypto Micro-Benchmark: X25519 and Ed25519 Operation Costs
 *
 * Measures cycle counts for each primitive in isolation:
 *   1. X25519 fixed-base  (crypto_x25519_public_key) - ephemeral keygen
 *   2. X25519 variable-base (crypto_x25519)          - static DH / ECDH
 *   3. Ed25519 key generation (crypto_ed25519_key_pair from seed)
 *   4. Ed25519 sign       (crypto_ed25519_sign)
 *   5. Ed25519 verify     (crypto_ed25519_check)
 *
 * Build: make crypto_bench CRYPTO_SUITE=0
 * Each operation is run BENCH_RUNS times; individual measurements are printed
 * so that variance can be observed (cache effects, pipeline, etc.).
 */

#include <stdint.h>
#include <string.h>
#include "kprintf.h"
#include "monocypher.h"
#include "optional/monocypher-ed25519.h"

#define BENCH_RUNS 10

#define UART1_BASE 0x64003000UL
#define REG32_UART1(i) (((volatile uint32_t *)UART1_BASE)[(i) >> 2])

static inline void uart1_putc(uint8_t c) {
    while ((int32_t)REG32_UART1(UART_REG_TXFIFO) < 0);
    REG32_UART1(UART_REG_TXFIFO) = c;
}

static inline int uart1_getc(void) {
    int32_t val = (int32_t)REG32_UART1(UART_REG_RXFIFO);
    return (val < 0) ? -1 : (val & 0xFF);
}


/* -------------------------------------------------------------------------
 * RISC-V cycle counter
 * rdcycle reads the lower 32 bits of the mcycle CSR.
 * At 50 MHz the counter wraps every ~86 seconds — safe for single ops.
 * -------------------------------------------------------------------------*/
static inline uint32_t read_cycles(void) {
    uint32_t c;
    __asm__ volatile ("rdcycle %0" : "=r"(c));
    return c;
}

/* -------------------------------------------------------------------------
 * Test vectors
 * RFC 7748 §6.1: Alice's secret key and Bob's public key (X25519)
 * RFC 8032 §5.1: Ed25519 seed for deterministic keypair derivation
 * -------------------------------------------------------------------------*/

/* Alice's X25519 secret scalar (RFC 7748 §6.1) */
static const uint8_t tv_x25519_sk[32] = {
    0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
    0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
    0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
    0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
};

/* Bob's X25519 public key (RFC 7748 §6.1) — used as the variable-base point */
static const uint8_t tv_x25519_peer_pk[32] = {
    0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,
    0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
    0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
    0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
};

/* Ed25519 seed — RFC 8032 §5.1 Test Vector 1 */
static const uint8_t tv_ed25519_seed[32] = {
    0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
    0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0x44,
    0xda,0x4d,0xa0,0x91,0x23,0x69,0x09,0x55,
    0x18,0x68,0x46,0x66,0x4f,0x15,0x76,0x77
};

/* 32-byte message for sign/verify (arbitrary) */
static const uint8_t tv_msg[32] = {
    0xaf,0x82,0x01,0x02,0x03,0x04,0x05,0x06,
    0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,
    0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
    0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e
};

/* -------------------------------------------------------------------------
 * 1. X25519 fixed-base (crypto_x25519_public_key)
 *    This is the ephemeral public key generation: pk = sk * G
 *    Monocypher uses the same Montgomery ladder as variable-base,
 *    but starting from the standard base point 9.
 * -------------------------------------------------------------------------*/
static void bench_x25519_fixed_base(void)
{
    uint8_t pk[32];
    uint32_t t0, t1;
    int i;

    kprintf("--- X25519 fixed-base  (crypto_x25519_public_key = ephem keygen) ---\r\n");
    for (i = 0; i < BENCH_RUNS; i++) {
        t0 = read_cycles();
        crypto_x25519_public_key(pk, tv_x25519_sk);
        t1 = read_cycles();
        kprintf("  [%2d] %lu cycles\r\n", i + 1, (unsigned long)(t1 - t0));
    }
    crypto_wipe(pk, sizeof(pk));
}

/* -------------------------------------------------------------------------
 * 2. X25519 variable-base (crypto_x25519)
 *    This is static DH / ECDH: shared = sk * peer_pk
 *    Uses the full Montgomery ladder with an arbitrary base point.
 * -------------------------------------------------------------------------*/
static void bench_x25519_variable_base(void)
{
    uint8_t shared[32];
    uint32_t t0, t1;
    int i;

    kprintf("--- X25519 variable-base (crypto_x25519 = static DH / ECDH) ---\r\n");
    for (i = 0; i < BENCH_RUNS; i++) {
        t0 = read_cycles();
        crypto_x25519(shared, tv_x25519_sk, tv_x25519_peer_pk);
        t1 = read_cycles();
        kprintf("  [%2d] %lu cycles\r\n", i + 1, (unsigned long)(t1 - t0));
    }
    crypto_wipe(shared, sizeof(shared));
}

/* -------------------------------------------------------------------------
 * 3. Ed25519 key generation (crypto_ed25519_key_pair)
 *    Derives a 64-byte secret key and 32-byte public key from a 32-byte seed.
 *    Internally: SHA-512(seed) -> scalar clamp -> fixed-base scalar mult.
 *    This is a one-time provisioning operation (not per-session).
 * -------------------------------------------------------------------------*/
static void bench_ed25519_keygen(void)
{
    uint8_t sk[64], pk[32];
    uint8_t seed_tmp[32];
    uint32_t t0, t1;
    int i;

    kprintf("--- Ed25519 key generation (crypto_ed25519_key_pair) ---\r\n");
    for (i = 0; i < BENCH_RUNS; i++) {
        /* seed is consumed by key_pair, copy each iteration */
        memcpy(seed_tmp, tv_ed25519_seed, 32);
        t0 = read_cycles();
        crypto_ed25519_key_pair(sk, pk, seed_tmp);
        t1 = read_cycles();
        kprintf("  [%2d] %lu cycles\r\n", i + 1, (unsigned long)(t1 - t0));
    }
    crypto_wipe(sk, sizeof(sk));
    crypto_wipe(pk, sizeof(pk));
}

/* -------------------------------------------------------------------------
 * 4. Ed25519 sign (crypto_ed25519_sign)
 *    Signs with the 64-byte secret key (sk = seed || pk).
 *    Internally: SHA-512 nonce + fixed-base scalar mult + SHA-512 challenge
 *    + scalar arithmetic.  Fixed base -> precomputed Niels tables -> fast.
 * -------------------------------------------------------------------------*/
static void bench_ed25519_sign(void)
{
    uint8_t sk[64], pk[32];
    uint8_t seed_tmp[32];
    uint8_t sig[64];
    uint32_t t0, t1;
    int i;

    /* Derive keypair once — not timed */
    memcpy(seed_tmp, tv_ed25519_seed, 32);
    crypto_ed25519_key_pair(sk, pk, seed_tmp);

    kprintf("--- Ed25519 sign (crypto_ed25519_sign) ---\r\n");
    for (i = 0; i < BENCH_RUNS; i++) {
        t0 = read_cycles();
        crypto_ed25519_sign(sig, sk, tv_msg, sizeof(tv_msg));
        t1 = read_cycles();
        kprintf("  [%2d] %lu cycles\r\n", i + 1, (unsigned long)(t1 - t0));
    }
    crypto_wipe(sk, sizeof(sk));
    crypto_wipe(sig, sizeof(sig));
}

/* -------------------------------------------------------------------------
 * 5. Ed25519 verify (crypto_ed25519_check)
 *    Verifies a signature against a public key.
 *    Internally: SHA-512 challenge + double scalar mult (one fixed, one
 *    variable-base) + SHA-512.  Two EC mults -> ~3x cost of sign.
 * -------------------------------------------------------------------------*/
static void bench_ed25519_verify(void)
{
    uint8_t sk[64], pk[32];
    uint8_t seed_tmp[32];
    uint8_t sig[64];
    uint32_t t0, t1;
    int result;
    int i;

    /* Derive keypair and produce a valid signature — not timed */
    memcpy(seed_tmp, tv_ed25519_seed, 32);
    crypto_ed25519_key_pair(sk, pk, seed_tmp);
    crypto_ed25519_sign(sig, sk, tv_msg, sizeof(tv_msg));
    crypto_wipe(sk, sizeof(sk));

    kprintf("--- Ed25519 verify (crypto_ed25519_check) ---\r\n");
    for (i = 0; i < BENCH_RUNS; i++) {
        t0 = read_cycles();
        result = crypto_ed25519_check(sig, pk, tv_msg, sizeof(tv_msg));
        t1 = read_cycles();
        kprintf("  [%2d] %lu cycles  (ok=%d)\r\n", i + 1,
                (unsigned long)(t1 - t0), (result == 0) ? 1 : 0);
    }
}

/* -------------------------------------------------------------------------
 * Entry point
 * -------------------------------------------------------------------------*/
int main(void)
{
    REG32(uart, UART_REG_DIV) = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV) = 868;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;

    kprintf("\r\n========================================\r\n");
    kprintf("  Crypto Micro-Benchmark\r\n");
    kprintf("  Platform : bare-metal RV32IMAC @ ~50 MHz\r\n");
    kprintf("  Runs/op  : %d\r\n", BENCH_RUNS);
    kprintf("========================================\r\n\r\n");

    bench_x25519_fixed_base();
    kprintf("\r\n");

    bench_x25519_variable_base();
    kprintf("\r\n");

    bench_ed25519_keygen();
    kprintf("\r\n");

    bench_ed25519_sign();
    kprintf("\r\n");

    bench_ed25519_verify();

    kprintf("\r\n========================================\r\n");
    kprintf("  Benchmark complete\r\n");
    kprintf("========================================\r\n");

    while (1); /* halt */
    return 0;
}

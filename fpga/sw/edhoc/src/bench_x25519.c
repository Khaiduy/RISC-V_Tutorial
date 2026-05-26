/* bench_x25519.c — Compare X25519 scalar-mult cost across three pure-C libs.
 *
 * Tests three implementations on the same inputs and reports cycle counts:
 *   1. wolfCrypt curve25519       (configured with CURVE25519_SMALL)
 *   2. Monocypher                 (single-file modern X25519)
 *   3. compact25519 / c25519      (Daniel Beer's reference impl)
 *
 * For each library we time:
 *   - fixed-base   (scalar * base_point   = public key from secret)
 *   - variable-base (scalar * peer_pubkey = shared DH secret)
 *
 * Each operation runs BENCH_RUNS times so variance (cache, branch) is visible.
 * After timing, the three DH outputs are compared byte-for-byte to confirm
 * all libraries agree.
 *
 * Build:  make bench_x25519
 * Run:    load like any other edhoc_* binary; UART prints results.
 */

#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "kprintf.h"

/* wolfCrypt */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/curve25519.h"

/* Monocypher */
#include "monocypher.h"

/* compact25519 — direct primitive access via c25519 */
#include "c25519/c25519.h"

#define BENCH_RUNS 5

/* RISC-V cycle counter — 32-bit lower half of mcycle. */
static inline uint32_t read_cycles(void)
{
    uint32_t c;
    __asm__ volatile ("rdcycle %0" : "=r"(c));
    return c;
}

/* Deterministic test vectors. The scalar is pre-masked per RFC 7748 §5 so all
 * three libraries agree on what to compute (library-internal masking is
 * idempotent on already-masked inputs).
 */
static uint8_t scalar[32] = {
    0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
    0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
    0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
    0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a,
};
static uint8_t peer_pub[32] = {
    0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,
    0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
    0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
    0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f,
};

static void mask_x25519_scalar(uint8_t s[32])
{
    s[0]  &= 248;
    s[31] &= 127;
    s[31] |=  64;
}

static void print_hex(const uint8_t *b, unsigned n)
{
    for (unsigned i = 0; i < n; i++) kprintf("%02x", b[i]);
}

/* Short busy-wait between large bursts of UART output so the host-side
 * ftdi_sio buffer can drain — avoids dropped bytes during hex dumps. */
static void uart_drain(void)
{
    for (volatile uint32_t i = 0; i < 2000000; i++) { /* ~40 ms at 50 MHz */ }
}

static void summarize(const char *label, uint32_t *samples, unsigned n)
{
    uint32_t mn = samples[0], mx = samples[0];
    uint64_t sum = 0;
    for (unsigned i = 0; i < n; i++) {
        if (samples[i] < mn) mn = samples[i];
        if (samples[i] > mx) mx = samples[i];
        sum += samples[i];
    }
    uint32_t mean = (uint32_t)(sum / n);
    /* kprintf supports only plain %s (no width specifier), so format manually. */
    kprintf("  %s : min=%lu  max=%lu  mean=%lu\r\n",
            label, (unsigned long)mn, (unsigned long)mx, (unsigned long)mean);
}

/* Library wrappers — each does ONE scalar multiplication. */

static void wolfssl_dh(uint8_t out[32], const uint8_t sk[32], const uint8_t pk[32])
{
    (void)wc_curve25519_generic(32, out, 32, sk, 32, pk);
}
static void wolfssl_pub(uint8_t out[32], const uint8_t sk[32])
{
    (void)wc_curve25519_make_pub(32, out, 32, (byte *)sk);
}

static void mono_dh(uint8_t out[32], const uint8_t sk[32], const uint8_t pk[32])
{
    crypto_x25519(out, sk, pk);
}
static void mono_pub(uint8_t out[32], const uint8_t sk[32])
{
    crypto_x25519_public_key(out, sk);
}

static void compact_dh(uint8_t out[32], const uint8_t sk[32], const uint8_t pk[32])
{
    c25519_smult(out, pk, sk);
}
static void compact_pub(uint8_t out[32], const uint8_t sk[32])
{
    c25519_smult(out, c25519_base_x, sk);
}

int main(void)
{
    /* UART setup — same divisor as other edhoc apps (57600 @ 50 MHz). */
    REG32(uart, UART_REG_DIV)    = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;

    kprintf("\r\n=== X25519 micro-benchmark ===\r\n");
    kprintf("BENCH_RUNS = %d   (cycles per scalar mult, rdcycle CSR)\r\n",
            BENCH_RUNS);

    mask_x25519_scalar(scalar);
    kprintf("Scalar (masked): "); print_hex(scalar, 32); kprintf("\r\n");
    kprintf("Peer pubkey   : "); print_hex(peer_pub, 32); kprintf("\r\n\r\n");

    uint32_t t0, t1;
    uint32_t samples[BENCH_RUNS];

    uint8_t wolf_pub[32]   = {0}, wolf_dh_out[32]   = {0};
    uint8_t mono_pub_o[32] = {0}, mono_dh_out[32]   = {0};
    uint8_t comp_pub_o[32] = {0}, comp_dh_out[32]   = {0};

    kprintf("[wolfCrypt curve25519 - CURVE25519_SMALL]\r\n");
    for (unsigned i = 0; i < BENCH_RUNS; i++) {
        t0 = read_cycles(); wolfssl_pub(wolf_pub, scalar); t1 = read_cycles();
        samples[i] = t1 - t0;
    }
    summarize("fixed-base (pubkey)", samples, BENCH_RUNS);
    for (unsigned i = 0; i < BENCH_RUNS; i++) {
        t0 = read_cycles(); wolfssl_dh(wolf_dh_out, scalar, peer_pub); t1 = read_cycles();
        samples[i] = t1 - t0;
    }
    summarize("variable-base (DH)  ", samples, BENCH_RUNS);
    uart_drain();

    kprintf("[Monocypher]\r\n");
    for (unsigned i = 0; i < BENCH_RUNS; i++) {
        t0 = read_cycles(); mono_pub(mono_pub_o, scalar); t1 = read_cycles();
        samples[i] = t1 - t0;
    }
    summarize("fixed-base (pubkey)", samples, BENCH_RUNS);
    for (unsigned i = 0; i < BENCH_RUNS; i++) {
        t0 = read_cycles(); mono_dh(mono_dh_out, scalar, peer_pub); t1 = read_cycles();
        samples[i] = t1 - t0;
    }
    summarize("variable-base (DH)  ", samples, BENCH_RUNS);
    uart_drain();

    kprintf("[compact25519 / c25519]\r\n");
    for (unsigned i = 0; i < BENCH_RUNS; i++) {
        t0 = read_cycles(); compact_pub(comp_pub_o, scalar); t1 = read_cycles();
        samples[i] = t1 - t0;
    }
    summarize("fixed-base (pubkey)", samples, BENCH_RUNS);
    for (unsigned i = 0; i < BENCH_RUNS; i++) {
        t0 = read_cycles(); compact_dh(comp_dh_out, scalar, peer_pub); t1 = read_cycles();
        samples[i] = t1 - t0;
    }
    summarize("variable-base (DH)  ", samples, BENCH_RUNS);

    kprintf("\r\nDH outputs:\r\n");
    kprintf("  wolfSSL   : "); print_hex(wolf_dh_out, 32); kprintf("\r\n");
    kprintf("  Monocypher: "); print_hex(mono_dh_out, 32); kprintf("\r\n");
    kprintf("  compact   : "); print_hex(comp_dh_out, 32); kprintf("\r\n");
    int wm = memcmp(wolf_dh_out, mono_dh_out, 32) == 0;
    int wc = memcmp(wolf_dh_out, comp_dh_out, 32) == 0;
    int mc = memcmp(mono_dh_out, comp_dh_out, 32) == 0;
    kprintf("Cross-check (wolf==mono): %s\r\n", wm ? "OK" : "MISMATCH");
    kprintf("Cross-check (wolf==comp): %s\r\n", wc ? "OK" : "MISMATCH");
    kprintf("Cross-check (mono==comp): %s\r\n", mc ? "OK" : "MISMATCH");

    kprintf("\r\nPublic-key outputs:\r\n");
    kprintf("  wolfSSL   : "); print_hex(wolf_pub, 32); kprintf("\r\n");
    kprintf("  Monocypher: "); print_hex(mono_pub_o, 32); kprintf("\r\n");
    kprintf("  compact   : "); print_hex(comp_pub_o, 32); kprintf("\r\n");

    kprintf("\r\nBENCH DONE\r\n");
    while (1) {}
    return 0;
}

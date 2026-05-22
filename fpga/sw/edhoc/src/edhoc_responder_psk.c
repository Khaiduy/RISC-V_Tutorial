/* EDHOC Responder - PSK Method 4 - parameterised by CRYPTO_SUITE.
 *
 * Mirrors edhoc_initiator_psk.c. Uses fixed PSK + fixed ID_CRED_PSK for
 * reproducible self-test against the matching initiator binary.
 *
 * Build:
 *   make edhoc_psk_responder CRYPTO_SUITE={0,7} TIMING=1 DEBUG=0
 *
 * Timing strategy: cycle counters bracket only the top-level edhoc_responder_run
 * call. Per-step kprintf in the PSK library is gated by TIMING_PRINT (off here),
 * so no UART transit cycles are attributed to the measured EDHOC compute. */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "edhoc.h"
#include "edhoc_method_type.h"
#include "suites.h"
/* X25519 keygen via library's ephemeral_dh_key_gen (wolfcrypt backend) */
#include "edhoc_transport.h"

#ifndef SUITE_BYTE
#  if !defined(EDHOC_CRYPTO_SUITE)
#    error "EDHOC_CRYPTO_SUITE must be defined by the Makefile"
#  endif
#  define SUITE_BYTE ((uint8_t)(EDHOC_CRYPTO_SUITE))
#endif

/* ---- fixed PSK + credentials (must match edhoc_initiator_psk.c) ---- */
static const uint8_t psk[16] = {
    0x82,0xc9,0x37,0x76,0x4d,0x6a,0xb1,0xab,
    0xea,0x05,0x6a,0x67,0xcc,0xa4,0x6d,0xb4
};
static const uint8_t id_cred_psk[] = { 0xa1, 0x04, 0x41, 0x0f };

/* CRED for both parties (PSK mode reuses the symmetric COSE_Key blob). */
static const uint8_t cred_i[] = {
    0xa2, 0x02, 0x77,
    0x32,0x33,0x2d,0x31,0x31,0x2d,0x35,0x38,0x2d,
    0x41,0x41,0x2d,0x42,0x33,0x2d,0x37,0x46,0x2d,
    0x31,0x30,
    0x08, 0xa1, 0x01, 0xa2, 0x01, 0x04, 0x02, 0x41, 0x0f
};
static const uint8_t cred_r[] = {
    0xa2, 0x02, 0x77,
    0x32,0x33,0x2d,0x31,0x31,0x2d,0x35,0x38,0x2d,
    0x41,0x41,0x2d,0x42,0x33,0x2d,0x37,0x46,0x2d,
    0x31,0x30,
    0x08, 0xa1, 0x01, 0xa2, 0x01, 0x04, 0x02, 0x41, 0x0f
};

/* Fixed ephemeral private — reproducible benchmark. */
static const uint8_t y_priv_seed[] = {
    0xab,0xcd,0xe1,0xf2,0x55,0x66,0x77,0x88,
    0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x10,
    0x21,0x32,0x43,0x54,0x65,0x76,0x87,0x98,
    0xa9,0xba,0xcb,0xdc,0xed,0xfe,0x0f,0x20
};

static uint8_t y_buf[32];
static uint8_t g_y[32];

static const uint8_t c_r[] = { 0x0e };
static const uint8_t suites[] = { SUITE_BYTE };

static void generate_public_key(const uint8_t *priv, uint8_t *pub) {
    /* Use the library's wolfcrypt-backed X25519 keygen. */
    uint8_t sk_buf[32];
    memcpy(sk_buf, priv, 32);
    struct byte_array sk_ba = { .ptr = sk_buf, .len = 32 };
    struct byte_array pk_ba = { .ptr = pub, .len = 32 };
    (void)ephemeral_dh_key_gen(X25519, 0, &sk_ba, &pk_ba);
}

int main(void) {
    /* UART0 = console (kprintf), UART1 = peer link. Same divisors as M3. */
    REG32(uart, UART_REG_DIV)    = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV)    = 868;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;

    kprintf("START (responder PSK suite=%d)\r\n", SUITE_BYTE);

    /* Silence-based UART1 RX drain: keep reading until we see ~100ms of
     * UART quiet. Eats any stale bytes left in the FIFO by a previous boot's
     * initiator firmware. Initiator-side startup delay (1s) guarantees we
     * finish draining before any new msg_1 arrives. */
    {
        uint32_t silence = 0;
        const uint32_t SILENCE_THRESHOLD = 5000000;  /* ~100ms @ 50MHz */
        while (silence < SILENCE_THRESHOLD) {
            int c = uart1_getc();
            if (c >= 0) silence = 0;
            else        silence++;
        }
    }

    /* Clamp Y per RFC 7748 §5 then derive G_Y. */
    memcpy(y_buf, y_priv_seed, 32);
    y_buf[0]  &= 0xF8;
    y_buf[31] &= 0x7F;
    y_buf[31] |= 0x40;
    generate_public_key(y_buf, g_y);

    /* Responder context (PSK fields populated; static-DH/sign fields unused). */
    struct edhoc_responder_context ctx_r = {0};
    ctx_r.c_r.ptr        = (uint8_t *)c_r;       ctx_r.c_r.len        = sizeof(c_r);
    ctx_r.suites_r.ptr   = (uint8_t *)suites;    ctx_r.suites_r.len   = sizeof(suites);
    ctx_r.g_y.ptr        = g_y;                  ctx_r.g_y.len        = 32;
    ctx_r.y.ptr          = y_buf;                ctx_r.y.len          = 32;
    ctx_r.psk.ptr        = (uint8_t *)psk;       ctx_r.psk.len        = sizeof(psk);
    ctx_r.id_cred_psk.ptr= (uint8_t *)id_cred_psk; ctx_r.id_cred_psk.len = sizeof(id_cred_psk);
    ctx_r.id_cred_r.ptr  = (uint8_t *)id_cred_psk; ctx_r.id_cred_r.len = sizeof(id_cred_psk);
    ctx_r.cred_r.ptr     = (uint8_t *)cred_r;    ctx_r.cred_r.len     = sizeof(cred_r);
    ctx_r.sock           = NULL;
    ctx_r.params_ead_process = NULL;

    /* Credentials we know about for the initiator (look-up by id_cred_psk).
     * PSK lib retrieve_cred returns the PSK bytes via the .pk field. */
    struct other_party_cred initiator_cred = {0};
    initiator_cred.id_cred.ptr = (uint8_t *)id_cred_psk;
    initiator_cred.id_cred.len = sizeof(id_cred_psk);
    initiator_cred.cred.ptr    = (uint8_t *)cred_i;
    initiator_cred.cred.len    = sizeof(cred_i);
    initiator_cred.pk.ptr      = (uint8_t *)psk;
    initiator_cred.pk.len      = sizeof(psk);

    struct cred_array cred_i_array = { .len = 1, .ptr = &initiator_cred };

    uint8_t err_msg_buf[128] = {0};
    struct byte_array err_msg = { .ptr = err_msg_buf, .len = sizeof(err_msg_buf) };
    uint8_t prk_out_buf[32]  = {0};
    struct byte_array prk_out = { .ptr = prk_out_buf, .len = sizeof(prk_out_buf) };

    /* Ephemeral keygen pre-EDHOC (compute) is the X25519 generate_public_key
     * above (timed below by re-reading). For benchmark, use the lib's own
     * compute-only counters populated inside edhoc_responder_run_extended. */
    extern volatile uint32_t _tb_psk_resp_msg2_cyc, _tb_psk_resp_msg3_cyc,
                              _tb_psk_resp_msg4_cyc, _tb_psk_resp_total_cyc;
    enum err r = edhoc_responder_run(&ctx_r, &cred_i_array, &err_msg, &prk_out,
                                     &tx_responder, &rx_responder, &ead_process);

    if (r != ok) {
        kprintf("EDHOC FAIL: %d\r\n", r);
        while (1);
    }
    kprintf("EDHOC OK!\r\n");
    kprintf("\r\n--- COMPUTE-ONLY Timing (cycles, no UART, no debug) ---\r\n");
    kprintf("Resp msg2_gen (+msg1 parse): %lu\r\n", (unsigned long)_tb_psk_resp_msg2_cyc);
    kprintf("Resp msg3_process          : %lu\r\n", (unsigned long)_tb_psk_resp_msg3_cyc);
    kprintf("Resp msg4_gen              : %lu\r\n", (unsigned long)_tb_psk_resp_msg4_cyc);
    kprintf("Resp COMPUTE TOTAL         : %lu\r\n", (unsigned long)_tb_psk_resp_total_cyc);
    kprintf("-----------------------\r\n");
    kprintf("PRK_out: (size %u):\r\n  ", (unsigned)prk_out.len);
    for (uint32_t i = 0; i < prk_out.len; i++) kprintf("%02X ", prk_out.ptr[i]);
    kprintf("\r\n");

    while (1);
    return 0;
}

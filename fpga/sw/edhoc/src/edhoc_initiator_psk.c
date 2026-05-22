/* EDHOC Initiator - PSK Method 4 — mirrors edhoc_initiator_m3.c shape so the
 * UART transport, CSPRNG seeding, and TIMING_BREAKDOWN integration are
 * identical to the working M3 path. Differences from M3:
 *   - Method 4 (PSK) — no static-DH key derivation
 *   - Context carries psk + id_cred_psk instead of static-DH fields
 *
 * Suite: 0 (X25519 + AES-CCM-16-64-128) or 7 (X25519 + Ascon-AEAD-128 +
 * Ascon-Hash-256), selectable via CRYPTO_SUITE Makefile var.
 */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "edhoc.h"
#include "edhoc/edhoc_method_type.h"
#include "edhoc/suites.h"
#include "edhoc_transport.h"

extern int  default_CSPRNG(uint8_t *dest, unsigned int size);
extern void csprng_add_entropy(const uint8_t *data, uint32_t len);

/* ── fixed PSK + ID_CRED_PSK (must match responder app) ───────────── */
static const uint8_t psk[16] = {
    0x82,0xc9,0x37,0x76,0x4d,0x6a,0xb1,0xab,
    0xea,0x05,0x6a,0x67,0xcc,0xa4,0x6d,0xb4
};
static const uint8_t id_cred_psk[] = { 0xa1, 0x04, 0x41, 0x0f };

/* CCS containing the responder's symmetric COSE_Key blob — for cred_array. */
static const uint8_t cred_r[] = {
    0xa2, 0x02, 0x77,
    0x32,0x33,0x2d,0x31,0x31,0x2d,0x35,0x38,0x2d,
    0x41,0x41,0x2d,0x42,0x33,0x2d,0x37,0x46,0x2d,
    0x31,0x30,
    0x08, 0xa1, 0x01, 0xa2, 0x01, 0x04, 0x02, 0x41, 0x0f
};
/* CCS for the initiator (we provide it; lib uses for transcript hashing). */
static const uint8_t cred_i[] = {
    0xa2, 0x02, 0x77,
    0x32,0x33,0x2d,0x31,0x31,0x2d,0x35,0x38,0x2d,
    0x41,0x41,0x2d,0x42,0x33,0x2d,0x37,0x46,0x2d,
    0x31,0x30,
    0x08, 0xa1, 0x01, 0xa2, 0x01, 0x04, 0x02, 0x41, 0x0f
};

/* Initiator ephemeral private key (X) — generated per session. */
static uint8_t x_i[32];
/* Ephemeral public key (G_X). */
static uint8_t g_x[32];

/* Connection identifier. */
static const uint8_t c_i[] = {0x2d};  /* C_I = -14 */
/* Suite advertised in msg_1 — selected via Makefile CRYPTO_SUITE. */
#ifndef EDHOC_CRYPTO_SUITE
#  error "EDHOC_CRYPTO_SUITE must be defined by the Makefile"
#endif
static const uint8_t suites[] = { (uint8_t)EDHOC_CRYPTO_SUITE };

int main(void) {
    REG32(uart, UART_REG_DIV)    = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV)    = 868;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;

#ifdef TIMING_BREAKDOWN
    uint64_t t_keygen_start = 0, t_keygen_end = 0;
#endif

    kprintf("START (initiator PSK suite=%d)\r\n", (int)EDHOC_CRYPTO_SUITE);

    /* Startup delay (~1s @ 50MHz) so responder's silence-based UART1 drain
     * finishes before we start TXing msg_1. Pairs with responder's drain. */
    for (volatile uint32_t d = 0; d < 50000000; d++);

    /* Mix entropy into CSPRNG so x_i differs per boot. */
    csprng_add_entropy(psk, sizeof(psk));

    /* Ephemeral keygen (timed). */
#ifdef TIMING_BREAKDOWN
    t_keygen_start = read_cycles();
#endif
    {
        struct byte_array x_ba  = {.ptr = x_i, .len = 32};
        struct byte_array gx_ba = {.ptr = g_x, .len = 32};
        default_CSPRNG(x_i, 32);
        ephemeral_dh_key_gen(X25519, 0, &x_ba, &gx_ba);
    }
#ifdef TIMING_BREAKDOWN
    t_keygen_end = read_cycles();
#endif

    /* ── EDHOC initiator context (PSK Method 4) ───────────────────── */
    struct edhoc_initiator_context ctx_i = {0};
    ctx_i.method        = INITIATOR_PSK_RESPONDER_PSK;
    ctx_i.c_i.ptr       = (uint8_t *)c_i;       ctx_i.c_i.len       = sizeof(c_i);
    ctx_i.suites_i.ptr  = (uint8_t *)suites;    ctx_i.suites_i.len  = sizeof(suites);
    ctx_i.x.ptr         = x_i;                  ctx_i.x.len         = 32;
    ctx_i.g_x.ptr       = g_x;                  ctx_i.g_x.len       = 32;
    ctx_i.psk.ptr       = (uint8_t *)psk;       ctx_i.psk.len       = sizeof(psk);
    ctx_i.id_cred_psk.ptr = (uint8_t *)id_cred_psk; ctx_i.id_cred_psk.len = sizeof(id_cred_psk);
    ctx_i.id_cred_i.ptr = (uint8_t *)id_cred_psk; ctx_i.id_cred_i.len = sizeof(id_cred_psk);
    ctx_i.cred_i.ptr    = (uint8_t *)cred_i;    ctx_i.cred_i.len    = sizeof(cred_i);
    ctx_i.ead_1.len     = 0;
    ctx_i.ead_3.len     = 0;
    ctx_i.sock          = NULL;
    ctx_i.params_ead_process = NULL;

    /* Responder credential (lookup by id_cred_psk → pk holds PSK). */
    struct other_party_cred responder_cred = {0};
    responder_cred.id_cred.ptr = (uint8_t *)id_cred_psk;
    responder_cred.id_cred.len = sizeof(id_cred_psk);
    responder_cred.cred.ptr    = (uint8_t *)cred_r;
    responder_cred.cred.len    = sizeof(cred_r);
    responder_cred.pk.ptr      = (uint8_t *)psk;
    responder_cred.pk.len      = sizeof(psk);
    struct cred_array cred_r_array = { .len = 1, .ptr = &responder_cred };

    /* Run buffers. */
    uint8_t err_msg_buf[64] = {0};
    struct byte_array err_msg = { .ptr = err_msg_buf, .len = sizeof(err_msg_buf) };
    uint8_t prk_out_buf[32] = {0};
    struct byte_array prk_out = { .ptr = prk_out_buf, .len = sizeof(prk_out_buf) };

    extern volatile uint32_t _tb_psk_init_msg1_cyc, _tb_psk_init_msg3_cyc,
                              _tb_psk_init_msg4_cyc, _tb_psk_init_total_cyc;
    enum err result = edhoc_initiator_run(&ctx_i, &cred_r_array, &err_msg, &prk_out,
                                          tx_initiator, rx_initiator, ead_process);

    if (result != ok) {
        kprintf("EDHOC FAIL: %d\r\n", result);
        while (1);
    }
    kprintf("EDHOC OK!\r\n");

#ifdef TIMING_BREAKDOWN
    {
        uint32_t keygen = (uint32_t)(t_keygen_end - t_keygen_start);
        kprintf("\r\n--- COMPUTE-ONLY Timing (cycles, no UART, no debug) ---\r\n");
        kprintf("Init ephemeral keygen      : %lu\r\n", (unsigned long)keygen);
        kprintf("Init msg1_gen              : %lu\r\n", (unsigned long)_tb_psk_init_msg1_cyc);
        kprintf("Init msg3_gen (+msg2 parse): %lu\r\n", (unsigned long)_tb_psk_init_msg3_cyc);
        kprintf("Init msg4_process          : %lu\r\n", (unsigned long)_tb_psk_init_msg4_cyc);
        kprintf("Init COMPUTE TOTAL (no kg) : %lu\r\n", (unsigned long)_tb_psk_init_total_cyc);
        kprintf("Init GRAND COMPUTE (+kg)   : %lu\r\n",
                (unsigned long)(keygen + _tb_psk_init_total_cyc));
    }
#endif
    kprintf("-----------------------\r\n");
    kprintf("PRK_out: (size %u):\r\n  ", (unsigned)prk_out.len);
    for (uint32_t i = 0; i < prk_out.len; i++) kprintf("%02X ", prk_out.ptr[i]);
    kprintf("\r\n");

    while (1);
    return 0;
}

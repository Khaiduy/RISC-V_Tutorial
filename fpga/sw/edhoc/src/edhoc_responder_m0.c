/* EDHOC Responder - Board B - Suite 0/1, Method 0
 *
 * Method 0: INITIATOR_SK_RESPONDER_SK
 * Suite 0: X25519 + AES-CCM-16-64-128 (8-byte tag) + SHA-256
 * Suite 1: X25519 + AES-CCM-16-128-128 (16-byte tag) + SHA-256
 *
 * Authentication: Ed25519 signature keys (both parties)
 *   - Responder signs with r_sign_sk, Initiator verifies with r_sign_pk
 *   - Initiator signs with i_sign_sk, Responder verifies with i_sign_pk
 */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "edhoc.h"
#include "crypto_wrapper.h"
#include "edhoc/edhoc_method_type.h"
#include "edhoc/suites.h"
#include "oscore.h"

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

enum err tx_responder(void *sock, struct byte_array *data) {
    (void)sock;
#ifdef DEBUG_PRINT
    kprintf("[R-TX] Sending %d bytes\r\n", data->len);
#endif
    uart1_putc((data->len >> 8) & 0xFF);
    uart1_putc(data->len & 0xFF);
    for (uint32_t i = 0; i < data->len; i++) {
        uart1_putc(data->ptr[i]);
        for (volatile int d = 0; d < 50000; d++);
    }
#ifdef DEBUG_PRINT
    kprintf("[R-TX] Done\r\n");
#endif
    return ok;
}

enum err rx_responder(void *sock, struct byte_array *data) {
    (void)sock;
    int timeout = 100000000, c;
#ifdef DEBUG_PRINT
    kprintf("[R-RX] Waiting...\r\n");
#endif
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
#ifdef DEBUG_PRINT
        kprintf("[R-RX] TIMEOUT\r\n");
#endif
        return transport_deinitialized;
    }
    uint32_t len = c << 8;
    timeout = 10000000;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
#ifdef DEBUG_PRINT
        kprintf("[R-RX] TIMEOUT len2\r\n");
#endif
        return transport_deinitialized;
    }
    len |= c;
#ifdef DEBUG_PRINT
    kprintf("[R-RX] Expecting %d bytes\r\n", len);
#endif
    if (len > data->len) {
#ifdef DEBUG_PRINT
        kprintf("[R-RX] Buffer too small\r\n");
#endif
        return buffer_to_small;
    }
    for (uint32_t i = 0; i < len; i++) {
        timeout = 10000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) {
#ifdef DEBUG_PRINT
            kprintf("[R-RX] TIMEOUT byte %d\r\n", i);
#endif
            return transport_deinitialized;
        }
        data->ptr[i] = c;
    }
    data->len = len;
#ifdef DEBUG_PRINT
    kprintf("[R-RX] Got %d bytes\r\n", len);
#endif
    return ok;
}

enum err ead_process(void *params, struct byte_array *ead) { (void)params; (void)ead; return ok; }

/*============================================================================
 * KEY MATERIAL
 *
 * Method 0 (SK-SK) requires:
 *   - Responder's Ed25519 keypair (r_sign_sk/pk) - long-term signing key
 *   - Ephemeral X25519 key (y_r, g_y) - generated fresh for each session
 *   - Initiator's Ed25519 public key (i_sign_pk) - pre-provisioned for verification
 *============================================================================*/

// Responder's EPHEMERAL private key (Y) - generated per session via ephemeral_dh_key_gen
static uint8_t y_r[32];

// Responder's Ed25519 seed - used to derive own signing keypair
static const uint8_t r_sign_seed[] = {
    0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
};
static uint8_t r_sign_sk[64];
static uint8_t r_sign_pk[32];

// Initiator's Ed25519 seed - used only to derive i_sign_pk for peer verification
static const uint8_t i_sign_seed[] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};
static uint8_t i_sign_pk[32]; // Initiator's Ed25519 public key (pre-provisioned)

// Computed at runtime
static uint8_t g_y[32];  // Ephemeral public key = X25519(y_r, basepoint)

// Connection identifier for responder
static const uint8_t c_r[] = {0x0e}; // C_R = 14

// Suite selection (set by Makefile CRYPTO_SUITE)
#if EDHOC_CRYPTO_SUITE == 0
static const uint8_t suites[] = {0x00}; // Suite 0: AES-CCM-16-64-128 (8-byte tag)
#elif EDHOC_CRYPTO_SUITE == 1
static const uint8_t suites[] = {0x01}; // Suite 1: AES-CCM-16-128-128 (16-byte tag)
#else
static const uint8_t suites[] = {0x00}; // Default to Suite 0
#endif

/*============================================================================
 * CREDENTIALS
 *
 * For Method 0, CRED_R/CRED_I contain Ed25519 public keys (crv=6).
 *
 * ID_CRED_R/I = { 4: kid } - compact reference by key ID
 *============================================================================*/

// ID_CRED_R = {4: 2}
static const uint8_t id_cred_r[] = {0xa1, 0x04, 0x02};

// CRED_R: CCS containing responder's Ed25519 public key (built at runtime)
static uint8_t cred_r[60];
static uint32_t cred_r_len;

// ID_CRED_I = {4: 1}
static const uint8_t id_cred_i[] = {0xa1, 0x04, 0x01};

// CRED_I: CCS containing initiator's Ed25519 public key (built after pre-provisioning)
static uint8_t cred_i[60];
static uint32_t cred_i_len;

/*============================================================================
 * HELPER FUNCTIONS
 *============================================================================*/

// Build CCS credential containing Ed25519 or X25519 public key
// OKP COSE_Key per RFC 9053 §7.2: kty=1(OKP), crv=-1, x=-2:pk
static uint32_t build_ccs_credential(uint8_t *buf, const char *name,
                                      const uint8_t *kid, uint32_t kid_len,
                                      const uint8_t *pk, uint32_t pk_len, uint8_t crv) {
    uint8_t *p = buf;
    uint32_t name_len = 0;
    while (name[name_len]) name_len++;

    *p++ = 0xa2;  // map(2)
    *p++ = 0x02;
    *p++ = 0x60 + (uint8_t)name_len;
    for (uint32_t i = 0; i < name_len; i++) *p++ = name[i];
    *p++ = 0x08;
    *p++ = 0xa1;  // map(1)
    *p++ = 0x01;
    *p++ = 0xa4;  // map(4): kty, kid, crv, x
    *p++ = 0x01; *p++ = 0x01;  // kty = 1 (OKP)
    *p++ = 0x02;
    *p++ = 0x40 + (uint8_t)kid_len;
    for (uint32_t i = 0; i < kid_len; i++) *p++ = kid[i];
    *p++ = 0x20; *p++ = crv;  // crv: 4=X25519, 6=Ed25519
    *p++ = 0x21; *p++ = 0x58; *p++ = (uint8_t)pk_len;
    for (uint32_t i = 0; i < pk_len; i++) *p++ = pk[i];

    return (uint32_t)(p - buf);
}

/* Read cycle counter */
static inline uint64_t read_cycles(void) {
    uint64_t cycles;
    asm volatile ("rdcycle %0" : "=r" (cycles));
    return cycles;
}

/*============================================================================
 * MAIN
 *============================================================================*/
int main(void) {
    REG32(uart, UART_REG_DIV) = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV) = 868;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;

    uint64_t t_keygen_start = 0, t_keygen_end = 0;

#ifdef DEBUG_PRINT
    kprintf("\r\n=================================\r\n");
    kprintf("EDHOC Responder - Method 0\r\n");
    kprintf("Suite 0/1 (X25519 + AES-CCM)\r\n");
    kprintf("=================================\r\n");
#endif

    // Pre-provisioning (not timed): derive long-term Ed25519 keypairs from seeds.
    // In production these are burned in at manufacturing and loaded from NVM.
    {
        uint8_t seed_tmp[32];
        struct byte_array sk_ba = {.ptr = r_sign_sk, .len = 64};
        struct byte_array pk_ba = {.ptr = r_sign_pk, .len = 32};
        memcpy(seed_tmp, r_sign_seed, 32);
        sign_key_gen(EdDSA, seed_tmp, &sk_ba, &pk_ba);
    }
    {
        uint8_t tmp_sk[64], seed_tmp[32];
        struct byte_array sk_ba = {.ptr = tmp_sk, .len = 64};
        struct byte_array pk_ba = {.ptr = i_sign_pk, .len = 32};
        memcpy(seed_tmp, i_sign_seed, 32);
        sign_key_gen(EdDSA, seed_tmp, &sk_ba, &pk_ba);
        memset(tmp_sk, 0, 64);
    }

    // Per-session ephemeral keygen (timed): X25519 base-point multiplication only
    t_keygen_start = read_cycles();
    {
        struct byte_array y_ba = {.ptr = y_r, .len = 32};
        struct byte_array gy_ba = {.ptr = g_y, .len = 32};
        ephemeral_dh_key_gen(X25519, 0x00000002U, &y_ba, &gy_ba);
    }
    t_keygen_end = read_cycles();

    // Build credentials with the computed public keys
    static const uint8_t kid_r[] = {0x02};
    static const uint8_t kid_i[] = {0x01};
    cred_r_len = build_ccs_credential(cred_r, "RespM0", kid_r, 1, r_sign_pk, 32, 6);
    cred_i_len = build_ccs_credential(cred_i, "InitM0", kid_i, 1, i_sign_pk, 32, 6);

#ifdef DEBUG_PRINT
    kprintf("\r\n=== RESPONDER KEY MATERIAL (M0) ===\r\n");
    kprintf("Ephemeral private (y): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", y_r[j]);
    kprintf("\r\n");
    kprintf("Ephemeral public (G_Y): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", g_y[j]);
    kprintf("\r\n");
    kprintf("Own Ed25519 public (R_sign_pk): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", r_sign_pk[j]);
    kprintf("\r\n");
    kprintf("Peer Ed25519 public (I_sign_pk): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", i_sign_pk[j]);
    kprintf("\r\n");
    kprintf("Method 0: Ed25519 signatures (both parties)\r\n");
#endif

    /*========================================================================
     * EDHOC RESPONDER CONTEXT SETUP - Method 0
     *========================================================================*/
    struct edhoc_responder_context ctx_r = {0};

    // Connection identifier
    ctx_r.c_r.ptr = (uint8_t *)c_r;
    ctx_r.c_r.len = sizeof(c_r);

    // Supported cipher suites
    ctx_r.suites_r.ptr = (uint8_t *)suites;
    ctx_r.suites_r.len = sizeof(suites);

    // Ephemeral keys (fresh per session)
    ctx_r.y.ptr = y_r;
    ctx_r.y.len = sizeof(y_r);
    ctx_r.g_y.ptr = g_y;
    ctx_r.g_y.len = sizeof(g_y);

    // Signature keys (Method 0) - Responder's long-term Ed25519 keys
    ctx_r.sk_r.ptr = r_sign_sk;
    ctx_r.sk_r.len = 64;
    ctx_r.pk_r.ptr = r_sign_pk;
    ctx_r.pk_r.len = 32;

    // Responder's credentials
    ctx_r.id_cred_r.ptr = (uint8_t *)id_cred_r;
    ctx_r.id_cred_r.len = sizeof(id_cred_r);
    ctx_r.cred_r.ptr = cred_r;
    ctx_r.cred_r.len = cred_r_len;

    /*========================================================================
     * INITIATOR CREDENTIAL VERIFICATION
     *========================================================================*/
    struct other_party_cred cred_i_entry = {0};
    cred_i_entry.id_cred.ptr = (uint8_t *)id_cred_i;
    cred_i_entry.id_cred.len = sizeof(id_cred_i);
    cred_i_entry.cred.ptr = cred_i;
    cred_i_entry.cred.len = cred_i_len;
    // For Method 0, the Ed25519 signing public key goes in the 'pk' field
    cred_i_entry.pk.ptr = i_sign_pk;
    cred_i_entry.pk.len = 32;
    struct cred_array cred_i_array = {.len = 1, .ptr = &cred_i_entry};

    /*========================================================================
     * RUN EDHOC
     *========================================================================*/
    uint8_t prk_out_buf[32], err_msg_buf[64];
    struct byte_array prk_out = {.ptr = prk_out_buf, .len = sizeof(prk_out_buf)};
    struct byte_array err_msg = {.ptr = err_msg_buf, .len = sizeof(err_msg_buf)};

#ifdef DEBUG_PRINT
    kprintf("\r\n=== EDHOC RESPONDER START ===\r\n");
#endif

    enum err result = edhoc_responder_run(&ctx_r, &cred_i_array, &err_msg, &prk_out,
                                          tx_responder, rx_responder, ead_process);

    if (result != ok) {
        kprintf("EDHOC FAIL: %d\r\n", result);
        while (1);
    }

    kprintf("EDHOC OK!\r\n");

    /* Timing results */
    kprintf("\r\n--- Timing (cycles) ---\r\n");
    kprintf("Ephemeral keygen: %lu\r\n", (unsigned long)(t_keygen_end - t_keygen_start));
#ifdef TIMING_BREAKDOWN
    extern volatile uint32_t _tb_msg2_cyc, _tb_msg3proc_cyc;
    kprintf("msg2_gen       : %lu\r\n", (unsigned long)_tb_msg2_cyc);
    kprintf("msg3_process   : %lu\r\n", (unsigned long)_tb_msg3proc_cyc);
    kprintf("EDHOC total    : %lu\r\n", (unsigned long)(_tb_msg2_cyc + _tb_msg3proc_cyc));
    kprintf("Grand total    : %lu\r\n",
            (unsigned long)((t_keygen_end - t_keygen_start) + _tb_msg2_cyc + _tb_msg3proc_cyc));
#endif
    kprintf("-----------------------\r\n");

#ifdef DEBUG_PRINT
    kprintf("PRK_out: ");
    for (uint32_t j = 0; j < prk_out.len; j++) kprintf("%x", prk_out.ptr[j]);
    kprintf("\r\n");
#endif

    while (1);
    return 0;
}

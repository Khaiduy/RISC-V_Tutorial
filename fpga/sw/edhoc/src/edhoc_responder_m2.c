/* EDHOC Responder - Board B - Suite 0/1, Method 2
 *
 * Method 2: INITIATOR_SDHK_RESPONDER_SK
 * Suite 0: X25519 + AES-CCM-16-64-128 (8-byte tag) + SHA-256
 * Suite 1: X25519 + AES-CCM-16-128-128 (16-byte tag) + SHA-256
 *
 * Authentication:
 *   - Initiator (SDHK): proves identity via static DH key (g_i, hardcoded)
 *   - Responder (SK):   proves identity via Ed25519 signature (r_sign_sk / r_sign_pk)
 */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "edhoc.h"
#include "monocypher.h"
#include "optional/monocypher-ed25519.h"
#include "edhoc/edhoc_method_type.h"
#include "edhoc/suites.h"
#include "oscore.h"
// #include "compact_x25519.h"

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
 * Method 2 (SDHK init, SK resp) requires:
 *   - Ephemeral keys (y_r, g_y)        - generated fresh for each session
 *   - Responder Ed25519 keypair         - long-term authentication keys
 *     (r_sign_seed -> r_sign_sk, r_sign_pk)
 *   - Initiator's DH public key (g_i)  - hardcoded for peer verification
 *     (M2 initiator is SDHK, no Ed25519 verification needed by responder)
 *============================================================================*/

// Responder's EPHEMERAL private key (Y) - generated per session
// TODO: In production, generate this randomly using TRNG
static const uint8_t y_r[] = {
    0xfb,0xfa,0xc8,0xdb,0x1d,0xc9,0xb2,0x57,0x14,0x4a,0xba,0xad,0x5a,0x1a,0x69,0xb7,
    0xa7,0xf6,0x66,0x12,0xc4,0xb7,0x13,0x1f,0x7b,0x15,0x58,0x56,0x16,0xd6,0x19,0x47
};

// Responder's Ed25519 seed - used to derive r_sign_sk and r_sign_pk
static const uint8_t r_sign_seed[] = {
    0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
};
static uint8_t r_sign_sk[64]; // Responder's Ed25519 private key (64 bytes)
static uint8_t r_sign_pk[32]; // Responder's Ed25519 public key

// Initiator's STATIC DH public key (G_I) - must match initiator's computed g_i
// This is X25519(i_sk=0x01, basepoint)
static const uint8_t g_i[] = {
    0xfd,0x33,0x84,0xe1,0x32,0xad,0x02,0xa5,0x6c,0x78,0xf4,0x55,0x47,0xee,0x40,0x03,
    0x8d,0xc7,0x90,0x02,0xb9,0x0d,0x29,0xed,0x90,0xe0,0x8e,0xee,0x76,0x2a,0xe7,0x15
};

// Public keys (computed at runtime)
static uint8_t g_y[32]; // Ephemeral public key = X25519(y_r, basepoint)

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
 * Method 2 credential layout:
 *   CRED_R: CCS containing responder's Ed25519 public key (crv=6, Ed25519)
 *     {2: "RespM2", 8: {1: {1: 1, 2: kid_r, -1: 6, -2: r_sign_pk}}}
 *   CRED_I: CCS containing initiator's static DH public key (crv=4, X25519)
 *     {2: "InitM2", 8: {1: {1: 1, 2: kid_i, -1: 4, -2: g_i}}}
 *
 * ID_CRED_R = {4: kid_r}, ID_CRED_I = {4: kid_i}
 *============================================================================*/

// ID_CRED_R = {4: 2}
static const uint8_t id_cred_r[] = {0xa1, 0x04, 0x02}; // {4: 2}

// CRED_R: CCS containing responder's Ed25519 public key (built dynamically)
static uint8_t cred_r[60];
static uint32_t cred_r_len;

// ID_CRED_I = {4: 1}
static const uint8_t id_cred_i[] = {0xa1, 0x04, 0x01}; // {4: 1}

// CRED_I: CCS containing initiator's static DH public key (built dynamically)
static uint8_t cred_i[60];
static uint32_t cred_i_len;

/*============================================================================
 * HELPER FUNCTIONS
 *============================================================================*/

// Compute X25519 public key from private key
static void generate_public_key(const uint8_t *priv_key, uint8_t *pub_key) {
    uint8_t e[32];
    memcpy(e, priv_key, 32);

    // Clamp private key (X25519 standard)
    e[0] &= 0xf8;
    e[31] &= 0x7f;
    e[31] |= 0x40;

    crypto_x25519_public_key(pub_key, e);
    memset(e, 0, 32);
}

// Build CCS credential containing a COSE_Key
// Supports crv=4 (X25519, static DH) and crv=6 (Ed25519, signature)
static uint32_t build_ccs_credential(uint8_t *buf, const char *name,
                                      const uint8_t *kid, uint32_t kid_len,
                                      const uint8_t *pk, uint32_t pk_len, uint8_t crv) {
    uint8_t *p = buf;
    uint32_t name_len = 0;
    while (name[name_len]) name_len++;  // Simple strlen

    // Outer map: {2: ..., 8: ...}
    *p++ = 0xa2;  // map(2)

    // Key 2: name (text string)
    *p++ = 0x02;
    *p++ = 0x60 + (uint8_t)name_len;  // text(name_len)
    for (uint32_t i = 0; i < name_len; i++) *p++ = name[i];

    // Key 8: cnf claim
    *p++ = 0x08;
    *p++ = 0xa1;  // map(1)

    // cnf key 1: COSE_Key (OKP, RFC 9053 §7.2)
    *p++ = 0x01;
    *p++ = 0xa4;  // map(4): kty, kid, crv, x

    // kty = 1 (OKP)  [RFC 9053 §7.1]
    *p++ = 0x01;
    *p++ = 0x01;

    // kid = bytes  [label 2]
    *p++ = 0x02;
    *p++ = 0x40 + (uint8_t)kid_len;  // bytes(kid_len)
    for (uint32_t i = 0; i < kid_len; i++) *p++ = kid[i];

    // crv  [label -1 = 0x20]: 4=X25519, 6=Ed25519
    *p++ = 0x20;  // -1 in CBOR
    *p++ = crv;

    // x = pk  [label -2 = 0x21]
    *p++ = 0x21;  // -2 in CBOR
    *p++ = 0x58;  // bytes with 1-byte length
    *p++ = (uint8_t)pk_len;
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
    kprintf("EDHOC Responder - Method 2\r\n");
    kprintf("Suite 0/1 (X25519 + AES-CCM)\r\n");
    kprintf("SDHK init, SK resp\r\n");
    kprintf("=================================\r\n");
#endif

    // Pre-provisioning (not timed): derive long-term Ed25519 keypair from seed.
    // In production this is burned in at manufacturing and loaded from NVM.
    // Initiator's DH key (g_i) is hardcoded constant — no computation needed.
    {
        uint8_t seed_tmp[32];
        memcpy(seed_tmp, r_sign_seed, 32);
        crypto_ed25519_key_pair(r_sign_sk, r_sign_pk, seed_tmp);
    }

    // Per-session ephemeral keygen (timed): X25519 base-point multiplication only
    t_keygen_start = read_cycles();
    generate_public_key(y_r, g_y);
    t_keygen_end = read_cycles();

    // Build credentials with the computed public keys
    static const uint8_t kid_r[] = {0x02};
    static const uint8_t kid_i[] = {0x01};
    // cred_r: responder uses Ed25519 (crv=6)
    cred_r_len = build_ccs_credential(cred_r, "RespM2", kid_r, 1, r_sign_pk, 32, 6);
    // cred_i: initiator uses DH key (crv=4, X25519)
    cred_i_len = build_ccs_credential(cred_i, "InitM2", kid_i, 1, g_i, 32, 4);

#ifdef DEBUG_PRINT
    kprintf("\r\n=== RESPONDER KEY MATERIAL ===\r\n");

    kprintf("Ephemeral private (y): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", y_r[j]);
    kprintf("...\r\n");

    kprintf("Ephemeral public (G_Y): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", g_y[j]);
    kprintf("...\r\n");

    kprintf("Ed25519 public (r_sign_pk): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", r_sign_pk[j]);
    kprintf("...\r\n");

    kprintf("Initiator DH public (G_I): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", g_i[j]);
    kprintf("...\r\n");

    kprintf("\r\nMethod 2: initiator=SDHK, responder=SK\r\n");
#endif

    /*========================================================================
     * EDHOC RESPONDER CONTEXT SETUP - Method 2
     *========================================================================*/
    struct edhoc_responder_context ctx_r = {0};

    // Connection identifier
    ctx_r.c_r.ptr = (uint8_t *)c_r;
    ctx_r.c_r.len = sizeof(c_r);

    // Supported cipher suites
    ctx_r.suites_r.ptr = (uint8_t *)suites;
    ctx_r.suites_r.len = sizeof(suites);

    // Ephemeral keys (fresh per session)
    ctx_r.y.ptr = (uint8_t *)y_r;
    ctx_r.y.len = sizeof(y_r);
    ctx_r.g_y.ptr = g_y;
    ctx_r.g_y.len = sizeof(g_y);

    // Signature keys (Method 2 responder is SK) - use sk_r/pk_r fields
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
    // Method 2 initiator is SDHK: DH public key goes in 'g' field
    cred_i_entry.g.ptr = (uint8_t *)g_i;
    cred_i_entry.g.len = sizeof(g_i);
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
    kprintf("Grand total    : %lu\r\n", (unsigned long)((t_keygen_end - t_keygen_start) + _tb_msg2_cyc + _tb_msg3proc_cyc));
#endif
    kprintf("-----------------------\r\n");

#ifdef DEBUG_PRINT
    kprintf("PRK_out: ");
    for (uint32_t j = 0; j < prk_out.len; j++) kprintf("%x", prk_out.ptr[j]);
    kprintf("\r\n");
#endif

//     /*========================================================================
//      * DERIVE OSCORE CONTEXT
//      *========================================================================*/
// #if EDHOC_CRYPTO_SUITE == 0
//     struct suite current_suite;
//     result = get_suite(SUITE_0, &current_suite);
// #elif EDHOC_CRYPTO_SUITE == 1
//     struct suite current_suite;
//     result = get_suite(SUITE_1, &current_suite);
// #else
//     struct suite current_suite;
//     result = get_suite(SUITE_0, &current_suite);
// #endif
//     if (result != ok) {
//         kprintf("get_suite FAIL: %d\r\n", result);
//         while (1);
//     }

//     // Derive PRK_exporter
//     uint8_t prk_exporter_buf[32];
//     struct byte_array prk_exporter = {.ptr = prk_exporter_buf, .len = sizeof(prk_exporter_buf)};
//     result = prk_out2exporter(current_suite.edhoc_hash, &prk_out, &prk_exporter);
//     if (result != ok) {
//         kprintf("prk_out2exporter FAIL: %d\r\n", result);
//         while (1);
//     }

//     // Derive OSCORE Master Secret
//     uint8_t oscore_master_secret_buf[16];
//     struct byte_array oscore_master_secret = {.ptr = oscore_master_secret_buf, .len = sizeof(oscore_master_secret_buf)};
//     result = edhoc_exporter(current_suite.edhoc_hash, OSCORE_MASTER_SECRET, &prk_exporter, &oscore_master_secret);
//     if (result != ok) {
//         kprintf("OSCORE MS FAIL: %d\r\n", result);
//         while (1);
//     }

// #ifdef DEBUG_PRINT
//     kprintf("OSCORE Master Secret: ");
//     for (uint32_t j = 0; j < oscore_master_secret.len; j++) kprintf("%x", oscore_master_secret.ptr[j]);
//     kprintf("\r\n");
// #endif

//     // Derive OSCORE Master Salt
//     uint8_t oscore_master_salt_buf[8];
//     struct byte_array oscore_master_salt = {.ptr = oscore_master_salt_buf, .len = sizeof(oscore_master_salt_buf)};
//     result = edhoc_exporter(current_suite.edhoc_hash, OSCORE_MASTER_SALT, &prk_exporter, &oscore_master_salt);
//     if (result != ok) {
//         kprintf("OSCORE Salt FAIL: %d\r\n", result);
//         while (1);
//     }

// #ifdef DEBUG_PRINT
//     kprintf("OSCORE Master Salt: ");
//     for (uint32_t j = 0; j < oscore_master_salt.len; j++) kprintf("%x", oscore_master_salt.ptr[j]);
//     kprintf("\r\n");
// #endif

//     // Initialize OSCORE context (Responder: sender_id = C_R, recipient_id = C_I)
//     static struct context oscore_ctx;
//     memset(&oscore_ctx, 0, sizeof(oscore_ctx));

//     // Per RFC 9528 App. A.1 Table 14: Responder's OSCORE Sender ID = C_I
//     static uint8_t sender_id_buf[1];
//     sender_id_buf[0] = 0x2D;  // C_I (Initiator's connection ID)
//     struct byte_array sender_id_ba = {.ptr = sender_id_buf, .len = 1};

//     struct oscore_init_params oscore_params = {
//         .master_secret = oscore_master_secret,
//         .sender_id = sender_id_ba,          // C_I per RFC 9528 Table 14
//         .recipient_id = ctx_r.c_r,          // C_R per RFC 9528 Table 14
//         .master_salt = oscore_master_salt,
//         .aead_alg = OSCORE_AES_CCM_16_64_128,
//         .hkdf = OSCORE_SHA_256,
//         .fresh_master_secret_salt = true
//     };

//     result = oscore_context_init(&oscore_params, &oscore_ctx);
//     if (result != ok) {
//         kprintf("OSCORE init FAIL: %d\r\n", result);
//         while (1);
//     }

//     kprintf("OSCORE READY\r\n");

    while (1);
    return 0;
}

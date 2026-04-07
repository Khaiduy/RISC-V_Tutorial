/* EDHOC Initiator - Board A - Suite 0/1, Method 2
 *
 * Method 2: INITIATOR_SDHK_RESPONDER_SK
 * Suite 0: X25519 + AES-CCM-16-64-128 (8-byte tag) + SHA-256
 * Suite 1: X25519 + AES-CCM-16-128-128 (16-byte tag) + SHA-256
 *
 * Authentication:
 *   - Initiator (SDHK): proves identity via static DH key (i_sk / g_i)
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

enum err tx_initiator(void *sock, struct byte_array *data) {
    (void)sock;
#ifdef DEBUG_PRINT
    kprintf("[I-TX] Sending %d bytes\r\n", data->len);
#endif
    uart1_putc((data->len >> 8) & 0xFF);
    uart1_putc(data->len & 0xFF);
    for (uint32_t i = 0; i < data->len; i++) {
        uart1_putc(data->ptr[i]);
        for (volatile int d = 0; d < 50000; d++);
    }
#ifdef DEBUG_PRINT
    kprintf("[I-TX] Done\r\n");
#endif
    return ok;
}

enum err rx_initiator(void *sock, struct byte_array *data) {
    (void)sock;
    int timeout = 1000000000, c;
#ifdef DEBUG_PRINT
    kprintf("[I-RX] Waiting...\r\n");
#endif
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
#ifdef DEBUG_PRINT
        kprintf("[I-RX] TIMEOUT\r\n");
#endif
        return transport_deinitialized;
    }
    uint32_t len = c << 8;
    timeout = 100000000;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
#ifdef DEBUG_PRINT
        kprintf("[I-RX] TIMEOUT len2\r\n");
#endif
        return transport_deinitialized;
    }
    len |= c;
#ifdef DEBUG_PRINT
    kprintf("[I-RX] Expecting %d bytes\r\n", len);
#endif
    if (len > data->len) {
#ifdef DEBUG_PRINT
        kprintf("[I-RX] Buffer too small\r\n");
#endif
        return buffer_to_small;
    }
    for (uint32_t i = 0; i < len; i++) {
        timeout = 100000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) {
#ifdef DEBUG_PRINT
            kprintf("[I-RX] TIMEOUT byte %d\r\n", i);
#endif
            return transport_deinitialized;
        }
        data->ptr[i] = c;
    }
    data->len = len;
#ifdef DEBUG_PRINT
    kprintf("[I-RX] Got %d bytes\r\n", len);
#endif
    return ok;
}

enum err ead_process(void *params, struct byte_array *ead) { (void)params; (void)ead; return ok; }

/*============================================================================
 * KEY MATERIAL
 *
 * Method 2 (SDHK init, SK resp) requires:
 *   - Ephemeral keys (x_i, g_x)    - generated fresh for each session
 *   - Static DH keys (i_sk, g_i)   - initiator's long-term authentication keys
 *   - Responder Ed25519 public key (r_sign_pk) - for verifying responder's signature
 *     (r_sign_seed kept only to derive r_sign_pk; secret key not needed by initiator)
 *============================================================================*/

// Initiator's EPHEMERAL private key (X) - generated per session
// TODO: In production, generate this randomly using TRNG
static const uint8_t x_i[] = {
    0xe9,0xac,0x11,0xbf,0x6c,0x77,0x17,0xd7,0xea,0xb5,0xea,0x74,0x56,0x8b,0xd0,0xbc,
    0x11,0xb4,0xa5,0xd7,0xe6,0xd7,0xa5,0x67,0x1c,0x3b,0xf1,0xab,0x49,0x18,0x6b,0x61
};

// Initiator's STATIC DH private key (I) - long-term authentication key
// TODO: Replace with your own static key
static const uint8_t i_sk[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};

// Responder's Ed25519 seed - used only to derive r_sign_pk for peer verification
static const uint8_t r_sign_seed[] = {
    0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
};
static uint8_t r_sign_pk[32]; // Responder's Ed25519 public key (computed at startup)

// Public keys (computed at runtime from private keys)
static uint8_t g_x[32]; // Ephemeral public key = X25519(x_i, basepoint)
static uint8_t g_i[32]; // Static DH public key = X25519(i_sk, basepoint)

// Connection identifier for initiator
static const uint8_t c_i[] = {0x2d}; // C_I = -14

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
 *   CRED_I: CCS containing initiator's static DH public key (crv=4, X25519)
 *     {2: "InitM2", 8: {1: {1: 1, 2: kid_i, -1: 4, -2: g_i}}}
 *   CRED_R: CCS containing responder's Ed25519 public key (crv=6, Ed25519)
 *     {2: "RespM2", 8: {1: {1: 1, 2: kid_r, -1: 6, -2: r_sign_pk}}}
 *
 * ID_CRED_I = {4: kid_i}, ID_CRED_R = {4: kid_r}
 *============================================================================*/

// ID_CRED_I = {4: 1}
static const uint8_t id_cred_i[] = {0xa1, 0x04, 0x01}; // {4: 1}

// CRED_I: CCS containing initiator's static DH public key (built dynamically)
static uint8_t cred_i[60];
static uint32_t cred_i_len;

// ID_CRED_R = {4: 2}
static const uint8_t id_cred_r[] = {0xa1, 0x04, 0x02}; // {4: 2}

// CRED_R: CCS containing responder's Ed25519 public key (built dynamically)
static uint8_t cred_r[60];
static uint32_t cred_r_len;

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
    kprintf("EDHOC Initiator - Method 2\r\n");
    kprintf("Suite 0/1 (X25519 + AES-CCM)\r\n");
    kprintf("SDHK init, SK resp\r\n");
    kprintf("=================================\r\n");
#endif

    // Pre-provisioning: compute responder's Ed25519 public key (not timed)
    {
        uint8_t tmp_sk[64], seed_tmp[32];
        memcpy(seed_tmp, r_sign_seed, 32);
        crypto_ed25519_key_pair(tmp_sk, r_sign_pk, seed_tmp);
        memset(tmp_sk, 0, 64);
    }
    
    // Pre-provisioning (not timed): derive static DH public key from long-term private key.
    // In production g_i is stored in NVM alongside i_sk.
    generate_public_key(i_sk, g_i);

    // Per-session ephemeral keygen (timed): X25519 base-point multiplication only
    t_keygen_start = read_cycles();
    generate_public_key(x_i, g_x);
    t_keygen_end = read_cycles();

    // Build credentials with the computed public keys
    static const uint8_t kid_i[] = {0x01};
    static const uint8_t kid_r[] = {0x02};
    // cred_i: initiator uses DH key (crv=4, X25519)
    cred_i_len = build_ccs_credential(cred_i, "InitM2", kid_i, 1, g_i, 32, 4);
    // cred_r: responder uses Ed25519 (crv=6)
    cred_r_len = build_ccs_credential(cred_r, "RespM2", kid_r, 1, r_sign_pk, 32, 6);

#ifdef DEBUG_PRINT
    kprintf("\r\n=== INITIATOR KEY MATERIAL ===\r\n");

    kprintf("Ephemeral private (x): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", x_i[j]);
    kprintf("...\r\n");

    kprintf("Ephemeral public (G_X): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", g_x[j]);
    kprintf("...\r\n");

    kprintf("Static DH private (I): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", i_sk[j]);
    kprintf("...\r\n");

    kprintf("Static DH public (G_I): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", g_i[j]);
    kprintf("...\r\n");

    kprintf("Responder Ed25519 pk (r_sign_pk): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", r_sign_pk[j]);
    kprintf("...\r\n");

    kprintf("\r\nMethod 2: initiator=SDHK, responder=SK\r\n");
#endif

    /*========================================================================
     * EDHOC INITIATOR CONTEXT SETUP - Method 2
     *========================================================================*/
    struct edhoc_initiator_context ctx_i = {0};

    // Method 2: Initiator uses Static DH, Responder uses Ed25519
    ctx_i.method = INITIATOR_SDHK_RESPONDER_SK;

    // Connection identifier
    ctx_i.c_i.ptr = (uint8_t *)c_i;
    ctx_i.c_i.len = sizeof(c_i);

    // Supported cipher suites
    ctx_i.suites_i.ptr = (uint8_t *)suites;
    ctx_i.suites_i.len = sizeof(suites);

    // Ephemeral keys (fresh per session)
    ctx_i.x.ptr = (uint8_t *)x_i;
    ctx_i.x.len = sizeof(x_i);
    ctx_i.g_x.ptr = g_x;
    ctx_i.g_x.len = sizeof(g_x);

    // Static DH keys (Method 2 initiator is SDHK) - use i/g_i fields
    ctx_i.i.ptr = (uint8_t *)i_sk;
    ctx_i.i.len = sizeof(i_sk);
    ctx_i.g_i.ptr = g_i;
    ctx_i.g_i.len = sizeof(g_i);

    // Initiator's credentials
    ctx_i.id_cred_i.ptr = (uint8_t *)id_cred_i;
    ctx_i.id_cred_i.len = sizeof(id_cred_i);
    ctx_i.cred_i.ptr = cred_i;
    ctx_i.cred_i.len = cred_i_len;

    /*========================================================================
     * RESPONDER CREDENTIAL VERIFICATION
     *========================================================================*/
    struct other_party_cred cred_r_entry = {0};
    cred_r_entry.id_cred.ptr = (uint8_t *)id_cred_r;
    cred_r_entry.id_cred.len = sizeof(id_cred_r);
    cred_r_entry.cred.ptr = cred_r;
    cred_r_entry.cred.len = cred_r_len;
    // Method 2 responder is SK: Ed25519 public key goes in 'pk' field
    cred_r_entry.pk.ptr = r_sign_pk;
    cred_r_entry.pk.len = 32;
    struct cred_array cred_r_array = {.len = 1, .ptr = &cred_r_entry};

    /*========================================================================
     * RUN EDHOC
     *========================================================================*/
    uint8_t prk_out_buf[32], err_msg_buf[64];
    struct byte_array prk_out = {.ptr = prk_out_buf, .len = sizeof(prk_out_buf)};
    struct byte_array err_msg = {.ptr = err_msg_buf, .len = sizeof(err_msg_buf)};

#ifdef DEBUG_PRINT
    kprintf("\r\n=== EDHOC INITIATOR START ===\r\n");
#endif

    enum err result = edhoc_initiator_run(&ctx_i, &cred_r_array, &err_msg, &prk_out,
                                          tx_initiator, rx_initiator, ead_process);

    if (result != ok) {
        kprintf("EDHOC FAIL: %d\r\n", result);
        while (1);
    }

    kprintf("EDHOC OK!\r\n");

    /* Timing results */
    kprintf("\r\n--- Timing (cycles) ---\r\n");
    kprintf("Ephemeral keygen: %lu\r\n", (unsigned long)(t_keygen_end - t_keygen_start));
#ifdef TIMING_BREAKDOWN
    extern volatile uint32_t _tb_msg1_cyc, _tb_msg3_cyc;
    kprintf("msg1_gen       : %lu\r\n", (unsigned long)_tb_msg1_cyc);
    kprintf("msg3_gen       : %lu\r\n", (unsigned long)_tb_msg3_cyc);
    kprintf("EDHOC total    : %lu\r\n", (unsigned long)(_tb_msg1_cyc + _tb_msg3_cyc));
    kprintf("Grand total    : %lu\r\n", (unsigned long)((t_keygen_end - t_keygen_start) + _tb_msg1_cyc + _tb_msg3_cyc));
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

//     // Initialize OSCORE context
//     static struct context oscore_ctx;
//     memset(&oscore_ctx, 0, sizeof(oscore_ctx));

//     // Per RFC 9528 App. A.1 Table 14: Initiator's OSCORE Sender ID = C_R
//     static uint8_t sender_id_buf[1];
//     sender_id_buf[0] = 0x0E;  // C_R (Responder's connection ID)
//     struct byte_array sender_id_ba = {.ptr = sender_id_buf, .len = 1};

//     struct oscore_init_params oscore_params = {
//         .master_secret = oscore_master_secret,
//         .sender_id = sender_id_ba,          // C_R per RFC 9528 Table 14
//         .recipient_id = ctx_i.c_i,          // C_I per RFC 9528 Table 14
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

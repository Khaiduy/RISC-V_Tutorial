/* EDHOC Responder - Board B - Suite 0/1, Method 3 (Static DH / Static DH)
 *
 * Method 3: Both Initiator and Responder authenticate with Static DH keys
 * Suite 0: X25519 + AES-CCM-16-64-128 (8-byte tag) + SHA-256
 * Suite 1: X25519 + AES-CCM-16-128-128 (16-byte tag) + SHA-256
 *
 * Authentication: Static DH keys (no signatures)
 *   - Initiator proves identity via ECDH(i, G_Y)
 *   - Responder proves identity via ECDH(r, G_X)
 */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "edhoc.h"
#include "monocypher.h"
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

enum err ead_process(void *params, struct byte_array *ead) { return ok; }

/*============================================================================
 * KEY MATERIAL
 * 
 * Method 3 requires:
 *   - Ephemeral keys (y_r, g_y) - generated fresh for each session
 *   - Static DH keys (r, g_r) - long-term authentication keys
 *============================================================================*/

// Responder's EPHEMERAL private key (Y) - generated per session
// TODO: In production, generate this randomly using TRNG
static const uint8_t y_r[] = {
    0xfb,0xfa,0xc8,0xdb,0x1d,0xc9,0xb2,0x57,0x14,0x4a,0xba,0xad,0x5a,0x1a,0x69,0xb7,
    0xa7,0xf6,0x66,0x12,0xc4,0xb7,0x13,0x1f,0x7b,0x15,0x58,0x56,0x16,0xd6,0x19,0x47
};

// Responder's STATIC DH private key (R) - long-term authentication key
// TODO: Replace with your own static key
static const uint8_t r_sk[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
};

// Public keys (computed at runtime from private keys)
static uint8_t g_y[32];  // Ephemeral public key = X25519(y_r, basepoint)
static uint8_t g_r[32];  // Static DH public key = X25519(r_sk, basepoint)

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
 * For Method 3, CRED_R contains the responder's static DH public key.
 * Format: CCS (CWT Claims Set) containing the public key
 *   CRED_R = { 2: "responder_id", 8: { 1: { 1: 4, 2: kid, -1: g_r } } }
 *   where: 1:4 = OKP key type, 2:kid = key id, -1:g_r = x-coordinate
 *
 * ID_CRED_R = { 4: kid } - compact reference to CRED_R
 *============================================================================*/

// ID_CRED_R = {4: 2} - key ID for responder's static DH key (integer KID)
static const uint8_t id_cred_r[] = {0xa1, 0x04, 0x02}; // {4: 2}

// CRED_R: CCS containing responder's static DH public key
// Will be built dynamically since g_r is computed at runtime
static uint8_t cred_r[60]; // Buffer for CRED_R
static uint32_t cred_r_len;

// Initiator's credentials (for verification)
// ID_CRED_I = {4: 1} - key ID for initiator's static DH key (integer KID)
static const uint8_t id_cred_i[] = {0xa1, 0x04, 0x01}; // {4: 1}

// Initiator's STATIC DH public key (G_I) - computed from i_sk=0x01
// This is X25519(i_sk, basepoint) - must match initiator's computed g_i
static const uint8_t g_i[] = {
    0xfd,0x33,0x84,0xe1,0x32,0xad,0x02,0xa5,0x6c,0x78,0xf4,0x55,0x47,0xee,0x40,0x03,
    0x8d,0xc7,0x90,0x02,0xb9,0x0d,0x29,0xed,0x90,0xe0,0x8e,0xee,0x76,0x2a,0xe7,0x15
};

// CRED_I: CCS containing initiator's static DH public key (pre-built)
static uint8_t cred_i[60]; // Buffer for CRED_I
static uint32_t cred_i_len;

/*============================================================================
 * HELPER FUNCTIONS
 *============================================================================*/

// Compute public key from private key using X25519
static void generate_public_key(const uint8_t *priv_key, uint8_t *pub_key) {
    extern int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);
    const uint8_t basepoint[32] = {9};
    
    uint8_t e[32];
    memcpy(e, priv_key, 32);
    
    // Clamp private key (X25519 standard)
    e[0] &= 0xf8;
    e[31] &= 0x7f;
    e[31] |= 0x40;
    
    //curve25519_donna(pub_key, e, basepoint); 
    crypto_x25519_public_key(pub_key, e);
    memset(e, 0, 32);
}

// Build CCS credential containing static DH public key
// Format: {2: "name", 8: {1: {1: 1, 2: kid_bytes, -1: 4, -2: pk_bytes}}}
// OKP/X25519 COSE_Key per RFC 9053 §7.2: kty=1(OKP), crv=-1:4(X25519), x=-2:pk
static uint32_t build_ccs_credential(uint8_t *buf, const char *name, 
                                      const uint8_t *kid, uint32_t kid_len,
                                      const uint8_t *pk, uint32_t pk_len) {
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
    
    // cnf key 1: COSE_Key (OKP/X25519, RFC 9053 §7.2)
    *p++ = 0x01;
    *p++ = 0xa4;  // map(4): kty, kid, crv, x
    
    // kty = 1 (OKP)  [RFC 9053 §7.1]
    *p++ = 0x01;
    *p++ = 0x01;
    
    // kid = bytes  [label 2]
    *p++ = 0x02;
    *p++ = 0x40 + (uint8_t)kid_len;  // bytes(kid_len)
    for (uint32_t i = 0; i < kid_len; i++) *p++ = kid[i];
    
    // crv = 4 (X25519)  [label -1 = 0x20, RFC 9053 §7.2 Table 18]
    *p++ = 0x20;  // -1 in CBOR
    *p++ = 0x04;  // 4 = X25519
    
    // x = pk  [label -2 = 0x21, RFC 9053 §7.2 Table 19]
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
    uint64_t t_edhoc_start = 0, t_edhoc_end = 0;

#ifdef DEBUG_PRINT
    kprintf("\r\n=================================\r\n");
    kprintf("EDHOC Responder - Method 3\r\n");
    kprintf("Suite 0/1 (X25519 + AES-CCM)\r\n");
    kprintf("=================================\r\n");
#endif
    
    generate_public_key(r_sk, g_r);   // Static DH public key
    // Generate public keys from private keys
    t_keygen_start = read_cycles();
    generate_public_key(y_r, g_y);    // Ephemeral public key
    t_keygen_end = read_cycles();
    
    // Build credentials with the computed public keys
    static const uint8_t kid_r[] = {0x02};
    static const uint8_t kid_i[] = {0x01};
    cred_r_len = build_ccs_credential(cred_r, "RespM3", kid_r, 1, g_r, 32);
    cred_i_len = build_ccs_credential(cred_i, "InitM3", kid_i, 1, g_i, 32);


#ifdef DEBUG_PRINT
    kprintf("\r\n=== RESPONDER KEY MATERIAL ===\r\n");
    
    kprintf("Ephemeral private (y): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", y_r[j]);
    kprintf("...\r\n");
    
    kprintf("Ephemeral public (G_Y): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", g_y[j]);
    kprintf("...\r\n");
    
    kprintf("Static DH private (R): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", r_sk[j]);
    kprintf("...\r\n");
    
    kprintf("Static DH public (G_R): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", g_r[j]);
    kprintf("...\r\n");
    
    kprintf("Initiator static (G_I): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%hx ", g_i[j]);
    kprintf("...\r\n");
    
    kprintf("\r\nMethod 3: Static DH authentication (both parties)\r\n");
#endif

    /*========================================================================
     * EDHOC RESPONDER CONTEXT SETUP - Method 3
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
    
    // Static DH keys (Method 3) - Responder's long-term keys
    ctx_r.r.ptr = (uint8_t *)r_sk;
    ctx_r.r.len = sizeof(r_sk);
    ctx_r.g_r.ptr = g_r;
    ctx_r.g_r.len = sizeof(g_r);
    
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
    // For Method 3, the static DH public key goes in the 'g' field
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

    t_edhoc_start = read_cycles();
    enum err result = edhoc_responder_run(&ctx_r, &cred_i_array, &err_msg, &prk_out,
                                          tx_responder, rx_responder, ead_process);
    t_edhoc_end = read_cycles();
    
    if (result != ok) {
        kprintf("EDHOC FAIL: %d\r\n", result);
        while (1);
    }
    
    kprintf("EDHOC OK!\r\n");
    
    /* Timing results */
    kprintf("\r\n--- Timing (cycles) ---\r\n");
    kprintf("Key generation:  %lu\r\n", (unsigned long)(t_keygen_end - t_keygen_start));
    kprintf("EDHOC protocol:  %lu\r\n", (unsigned long)(t_edhoc_end - t_edhoc_start));
    kprintf("TOTAL:           %lu\r\n", (unsigned long)(t_edhoc_end - t_keygen_start));
    kprintf("-----------------------\r\n");

#ifdef TIMING_BREAKDOWN
    extern volatile uint32_t _tb_msg2_cyc, _tb_msg3proc_cyc;
    uint32_t _tb_keygen = (uint32_t)(t_keygen_end - t_keygen_start);
    kprintf("\r\n--- Protocol Breakdown (no UART) ---\r\n");
    kprintf("Key generation : %lu cyc\r\n", (unsigned long)_tb_keygen);
    kprintf("msg2_gen       : %lu cyc\r\n", (unsigned long)_tb_msg2_cyc);
    kprintf("msg3_process   : %lu cyc\r\n", (unsigned long)_tb_msg3proc_cyc);
    kprintf("Total (no UART): %lu cyc\r\n",
            (unsigned long)(_tb_keygen + _tb_msg2_cyc + _tb_msg3proc_cyc));
    kprintf("------------------------------------\r\n");
#endif

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

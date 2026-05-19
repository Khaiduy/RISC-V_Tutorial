/* EDHOC Responder - Board B - Suites 0-5, Method 3 (Static DH / Static DH)
 *
 * Method 3: Both Initiator and Responder authenticate with Static DH keys
 * Suite 0: X25519 + AES-CCM-16-64-128 (8-byte tag) + SHA-256
 * Suite 1: X25519 + AES-CCM-16-128-128 (16-byte tag) + SHA-256
 * Suite 2: P-256  + AES-CCM-16-64-128 (8-byte tag) + SHA-256
 * Suite 3: P-256  + AES-CCM-16-128-128 (16-byte tag) + SHA-256
 * Suite 4: X25519 + AES-CCM-16-64-128 + SHA-256 (ChaCha20 AEAD)
 * Suite 5: P-256  + AES-CCM-16-64-128 + SHA-256 (ChaCha20 AEAD)
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
#include "crypto_wrapper.h"
#include "edhoc/edhoc_method_type.h"
#include "edhoc/suites.h"
#include "oscore.h"
#include "edhoc_suite_defs.h"
#include "edhoc_transport.h"
#include "edhoc_cred_builder.h"
#include "common/print_util.h"

/* Forward declarations -- resolved at link time, avoids IDE include-path issues */
extern int  default_CSPRNG(uint8_t *dest, unsigned int size);
extern void csprng_add_entropy(const uint8_t *data, uint32_t len);

/*============================================================================
 * KEY MATERIAL
 * 
 * Method 3 requires:
 *   - Ephemeral keys (y_r, g_y) - generated fresh for each session
 *   - Static DH keys (r, g_r) - long-term authentication keys
 *============================================================================*/

// Responder's EPHEMERAL private key (Y) - generated per session via ephemeral_dh_key_gen
static uint8_t y_r[32];

// Responder's STATIC DH seed - used to derive the actual P-256 or X25519 key pair
// For X25519: used directly (with clamping) as private key
// For P-256:  seed_key (32 bytes) is used directly as the private key scalar.
static const uint8_t r_sk_seed[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
};
// Actual static DH private key (may differ from seed for P-256)
static uint8_t r_sk[32];

// Public keys (computed at runtime from private keys)
static uint8_t g_y[32];  // Ephemeral public key = X25519(y_r, basepoint)
static uint8_t g_r[32];  // Static DH public key = X25519(r_sk, basepoint)

// Connection identifier for responder
static const uint8_t c_r[] = {0x0e}; // C_R = 14

// Suite selection (set by Makefile CRYPTO_SUITE)
static const uint8_t suites[] = {SUITE_BYTE};

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
static uint8_t cred_r[CRED_BUF_MAX]; // Buffer for CRED_R
static uint32_t cred_r_len;

// Initiator's credentials (for verification)
// ID_CRED_I = {4: 1} - key ID for initiator's static DH key (integer KID)
static const uint8_t id_cred_i[] = {0xa1, 0x04, 0x01}; // {4: 1}

// Initiator's STATIC DH private key (I) - known test value used to compute g_i
// In production, only g_i (public) is provisioned here; i_sk stays on the initiator.
// Must match i_sk in edhoc_initiator_m3.c exactly.
static const uint8_t i_sk_known[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};

// Initiator's STATIC DH public key (G_I) - computed at startup via x25519_public_from_private()
// so that the same library function is used on both sides.
static uint8_t g_i[32];

// CRED_I: CCS containing initiator's static DH public key (pre-built)
static uint8_t cred_i[CRED_BUF_MAX]; // Buffer for CRED_I
static uint32_t cred_i_len;

/*============================================================================
 * MAIN
 *============================================================================*/
int main(void) {
    REG32(uart, UART_REG_DIV) = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV) = 868;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;
    
#ifdef TIMING_BREAKDOWN
    uint64_t t_keygen_start = 0, t_keygen_end = 0;
#endif

#ifdef DEBUG_PRINT
    kprintf("\r\n=================================\r\n");
    kprintf("EDHOC Responder - Method 3\r\n");
    kprintf("Suite 0-5 (X25519/P-256 + AES-CCM)\r\n");
    kprintf("=================================\r\n");
#endif
    
    // Pre-provisioning (not timed): derive static DH keys from seeds.
    // For P-256, r_sk is used directly as the private key scalar.
    // g_i is peer's public key — only the public key matters for verification.
    {
        memcpy(r_sk, r_sk_seed, 32);
        struct byte_array rsk_ba = {.ptr = r_sk, .len = 32};
        struct byte_array gr_ba  = {.ptr = g_r, .len = 32};
        uint8_t isk_tmp[32];
        memcpy(isk_tmp, i_sk_known, 32);
        struct byte_array isk_ba = {.ptr = isk_tmp, .len = 32};
        struct byte_array gi_ba  = {.ptr = g_i, .len = 32};
        ephemeral_dh_key_gen(SUITE_ECDH_ALG, 0, &rsk_ba, &gr_ba);
        ephemeral_dh_key_gen(SUITE_ECDH_ALG, 0, &isk_ba, &gi_ba);
    }

    // Per-session ephemeral keygen (timed)
#ifdef TIMING_BREAKDOWN
    t_keygen_start = read_cycles();
#endif
    {
        struct byte_array y_ba = {.ptr = y_r, .len = 32};
        struct byte_array gy_ba = {.ptr = g_y, .len = 32};
        default_CSPRNG(y_ba.ptr, 32);
        ephemeral_dh_key_gen(SUITE_ECDH_ALG, 0, &y_ba, &gy_ba);
    }
#ifdef TIMING_BREAKDOWN
    t_keygen_end = read_cycles();
#endif
    
    // Build credentials with the computed public keys
    static const uint8_t kid_r[] = {0x02};
    static const uint8_t kid_i[] = {0x01};
    cred_r_len = build_ccs_credential(cred_r, "RespM3", kid_r, 1, g_r, 32, SUITE_CRV_DH);
    cred_i_len = build_ccs_credential(cred_i, "InitM3", kid_i, 1, g_i, 32, SUITE_CRV_DH);


#ifdef DEBUG_PRINT
    kprintf("\r\n=== RESPONDER KEY MATERIAL ===\r\n");
    
    kprintf("Ephemeral private (y): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", y_r[j]);
    kprintf("...\r\n");

    kprintf("Ephemeral public (G_Y): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", g_y[j]);
    kprintf("...\r\n");

    kprintf("Static DH private (R): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", r_sk[j]);
    kprintf("...\r\n");

    kprintf("Static DH public (G_R): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", g_r[j]);
    kprintf("...\r\n");

    kprintf("Initiator static (G_I): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", g_i[j]);
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
    ctx_r.y.ptr = y_r;
    ctx_r.y.len = sizeof(y_r);
    ctx_r.g_y.ptr = g_y;
    ctx_r.g_y.len = sizeof(g_y);
    
    // Static DH keys (Method 3) - Responder's long-term keys
    ctx_r.r.ptr = r_sk;
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

    enum err result = edhoc_responder_run(&ctx_r, &cred_i_array, &err_msg, &prk_out,
                                          tx_responder, rx_responder, ead_process);
    
    if (result != ok) {
        kprintf("EDHOC FAIL: %d\r\n", result);
        while (1);
    }
    
    kprintf("EDHOC OK!\r\n");
#ifdef TIMING_BREAKDOWN    
    kprintf("\r\n--- Timing (cycles) ---\r\n");
    kprintf("Ephemeral keygen: %lu\r\n", (unsigned long)(t_keygen_end - t_keygen_start));

    extern volatile uint32_t _tb_msg2_cyc, _tb_msg3proc_cyc;
    kprintf("msg2_gen       : %lu\r\n", (unsigned long)_tb_msg2_cyc);
    kprintf("msg3_process   : %lu\r\n", (unsigned long)_tb_msg3proc_cyc);
    kprintf("EDHOC total    : %lu\r\n", (unsigned long)(_tb_msg2_cyc + _tb_msg3proc_cyc));
    kprintf("Grand total    : %lu\r\n", (unsigned long)((t_keygen_end - t_keygen_start) + _tb_msg2_cyc + _tb_msg3proc_cyc));
#endif
    kprintf("-----------------------\r\n");


    print_labeled_array("PRK_out:", prk_out.ptr, prk_out.len);


//     /*========================================================================
//      * DERIVE OSCORE CONTEXT
//      *========================================================================*/
//     struct suite current_suite;
//     result = get_suite(SUITE_ENUM, &current_suite);
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

    zeroize(y_r,          sizeof(y_r));
    zeroize(r_sk,         sizeof(r_sk));
    zeroize(prk_out_buf,  sizeof(prk_out_buf));
    zeroize(&ctx_r,       sizeof(ctx_r));

    while (1);
    return 0;
}

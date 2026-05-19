/* EDHOC Initiator - Board A - Suite 0-5, Method 1
 *
 * Method 1: INITIATOR_SK_RESPONDER_SDHK
 * Suite 0: X25519 + AES-CCM-16-64-128 (8-byte tag)  + SHA-256
 * Suite 1: X25519 + AES-CCM-16-128-128 (16-byte tag) + SHA-256
 * Suite 2: P-256  + AES-CCM-16-64-128  (8-byte tag)  + SHA-256
 * Suite 3: P-256  + AES-CCM-16-128-128 (16-byte tag) + SHA-256
 * Suite 4: X25519 + AES-CCM-16-64-128  + SHA-384
 * Suite 5: P-256  + AES-CCM-16-64-128  + SHA-384
 *
 * Authentication: Initiator uses signature key (SK); Responder uses static DH (SDHK)
 *   - Initiator signs with i_sign_sk (Ed25519 for 0/1/4, ES256 for 2/3/5)
 *   - Responder proves identity via ECDH(r, G_X), Initiator verifies with pre-provisioned g_r
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
/* Forward declarations — resolved at link time, avoids IDE include-path issues */
extern int  default_CSPRNG(uint8_t *dest, unsigned int size);
extern void csprng_add_entropy(const uint8_t *data, uint32_t len);

/*============================================================================
 * KEY MATERIAL
 *
 * Method 1 (SK-SDHK) requires:
 *   - Initiator's signing keypair (Ed25519 for suites 0/1/4, ES256 for 2/3/5)
 *   - Ephemeral ECDH key (X25519 for suites 0/1/4, P-256 for 2/3/5)
 *   - Responder's static DH public key (pre-provisioned for verification)
 *============================================================================*/

// Initiator's EPHEMERAL private key (X) - generated per session via CSPRNG
static uint8_t x_i[32];

// Initiator's signing seed
static const uint8_t i_sign_seed[] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};
static uint8_t i_sign_sk[SUITE_SIGN_SK_LEN];
static uint8_t i_sign_pk[32];

// Public keys (computed at runtime from private keys)
static uint8_t g_x[32];  // Ephemeral public key = X25519(x_i, basepoint)

// Responder's STATIC DH private key (R) - known test value used to compute g_r
// In production, only g_r (public) is provisioned here; r_sk stays on the responder.
// Must match r_sk in edhoc_responder_m1.c exactly.
static const uint8_t r_sk_known[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
};

// Responder's STATIC DH public key (G_R) - computed at startup via ephemeral_dh_key_gen().
static uint8_t g_r[32];

// Connection identifier for initiator
static const uint8_t c_i[] = {0x2d}; // C_I = -14

// Suite selection (set by Makefile CRYPTO_SUITE)
static const uint8_t suites[] = {SUITE_BYTE};

/*============================================================================
 * CREDENTIALS
 *
 * For Method 1, CRED_I contains the initiator's Ed25519 public key.
 * CRED_R contains the responder's static DH public key.
 *
 * ID_CRED_I = { 4: kid } - compact reference to CRED_I
 *============================================================================*/

// ID_CRED_I = {4: 1} - key ID for initiator's Ed25519 key (integer KID)
static const uint8_t id_cred_i[] = {0xa1, 0x04, 0x01}; // {4: 1}

// CRED_I: CCS containing initiator's Ed25519 public key
// Will be built dynamically since i_sign_pk is computed at runtime
static uint8_t cred_i[CRED_BUF_MAX]; // Buffer for CRED_I
static uint32_t cred_i_len;

// Responder's credentials (for verification)
// ID_CRED_R = {4: 2} - key ID for responder's static DH key (integer KID)
static const uint8_t id_cred_r[] = {0xa1, 0x04, 0x02}; // {4: 2}

// CRED_R: CCS containing responder's static DH public key (pre-built)
static uint8_t cred_r[CRED_BUF_MAX]; // Buffer for CRED_R
static uint32_t cred_r_len;

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
    kprintf("EDHOC Initiator - Method 1\r\n");
    kprintf("Suite 0/1 (X25519 + AES-CCM)\r\n");
    kprintf("=================================\r\n");
#endif

    // Pre-provisioning (not timed): derive long-term signing keypair from seed.
    // In production this is burned in at manufacturing and loaded from NVM.
    // g_r is computed below (after ephemeral keygen) via ephemeral_dh_key_gen().
    {
        uint8_t seed_tmp[32];
        struct byte_array sk_ba = {.ptr = i_sign_sk, .len = SUITE_SIGN_SK_LEN};
        struct byte_array pk_ba = {.ptr = i_sign_pk, .len = 32};
        memcpy(seed_tmp, i_sign_seed, 32);
        sign_key_gen(SUITE_SIGN_ALG, seed_tmp, &sk_ba, &pk_ba);
    }

    // Per-session ephemeral keygen (timed)
#ifdef TIMING_BREAKDOWN
    t_keygen_start = read_cycles();
#endif
    {
        struct byte_array sk_ba = {.ptr = x_i, .len = 32};
        struct byte_array pk_ba = {.ptr = g_x, .len = 32};
        default_CSPRNG(x_i, 32);
        ephemeral_dh_key_gen(SUITE_ECDH_ALG, 0, &sk_ba, &pk_ba);
    }
#ifdef TIMING_BREAKDOWN
    t_keygen_end = read_cycles();
#endif

    // Compute responder's static DH public key from known test private key.
    // This ensures both sides agree on g_r.
    {
        uint8_t sk_tmp[32];
        memcpy(sk_tmp, r_sk_known, 32);
        struct byte_array sk_ba = {.ptr = sk_tmp, .len = 32};
        struct byte_array pk_ba = {.ptr = g_r, .len = 32};
        ephemeral_dh_key_gen(SUITE_ECDH_ALG, 0, &sk_ba, &pk_ba);
        memset(sk_tmp, 0, 32);
    }

    // Build credentials with the computed public keys
    static const uint8_t kid_i[] = {0x01};
    static const uint8_t kid_r[] = {0x02};
    cred_i_len = build_ccs_credential(cred_i, "InitM1", kid_i, 1, i_sign_pk, 32, SUITE_CRV_SIGN);
    cred_r_len = build_ccs_credential(cred_r, "RespM1", kid_r, 1, g_r, 32, SUITE_CRV_DH);

#ifdef DEBUG_PRINT
    kprintf("\r\n=== INITIATOR KEY MATERIAL ===\r\n");

    kprintf("Ephemeral private (x): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", x_i[j]);
    kprintf("...\r\n");

    kprintf("Ephemeral public (G_X): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", g_x[j]);
    kprintf("...\r\n");

    kprintf("Ed25519 public (i_sign_pk): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", i_sign_pk[j]);
    kprintf("...\r\n");

    kprintf("Responder static DH (G_R): ");
    for (uint32_t j = 0; j < 32; j++) kprintf("%02x ", g_r[j]);
    kprintf("...\r\n");

    kprintf("\r\nMethod 1: Initiator SK (Ed25519), Responder SDHK\r\n");
#endif

    /*========================================================================
     * EDHOC INITIATOR CONTEXT SETUP - Method 1
     *========================================================================*/
    struct edhoc_initiator_context ctx_i = {0};

    // Method 1: Initiator SK, Responder SDHK
    ctx_i.method = INITIATOR_SK_RESPONDER_SDHK;

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

    // Signature keys (Method 1) - Initiator's long-term signing keys
    ctx_i.sk_i.ptr = i_sign_sk;
    ctx_i.sk_i.len = SUITE_SIGN_SK_LEN;
    ctx_i.pk_i.ptr = i_sign_pk;
    ctx_i.pk_i.len = 32;

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
    // For Method 1, responder is SDHK: DH public key goes in the 'g' field
    cred_r_entry.g.ptr = (uint8_t *)g_r;
    cred_r_entry.g.len = sizeof(g_r);
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
#ifdef TIMING_BREAKDOWN
    /* Timing results */
    kprintf("\r\n--- Timing (cycles) ---\r\n");
    kprintf("Ephemeral keygen: %lu\r\n", (unsigned long)(t_keygen_end - t_keygen_start));

    extern volatile uint32_t _tb_msg1_cyc, _tb_msg3_cyc;
    kprintf("msg1_gen       : %lu\r\n", (unsigned long)_tb_msg1_cyc);
    kprintf("msg3_gen       : %lu\r\n", (unsigned long)_tb_msg3_cyc);
    kprintf("EDHOC total    : %lu\r\n", (unsigned long)(_tb_msg1_cyc + _tb_msg3_cyc));
    kprintf("Grand total    : %lu\r\n", (unsigned long)((t_keygen_end - t_keygen_start) + _tb_msg1_cyc + _tb_msg3_cyc));
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

    zeroize(x_i,          sizeof(x_i));
    zeroize(i_sign_sk,    sizeof(i_sign_sk));
    zeroize(prk_out_buf,  sizeof(prk_out_buf));
    zeroize(&ctx_i,       sizeof(ctx_i));
    while (1);
    return 0;
}

/* EDHOC Initiator - Board A - Suite 0/1, Method 0
 *
 * Method 0: INITIATOR_SK_RESPONDER_SK
 * Suite 0: X25519 + AES-CCM-16-64-128 (8-byte tag) + SHA-256
 * Suite 1: X25519 + AES-CCM-16-128-128 (16-byte tag) + SHA-256
 *
 * Authentication: Ed25519 signature keys (both parties)
 *   - Initiator signs with i_sign_sk, Responder verifies with i_sign_pk
 *   - Responder signs with r_sign_sk, Initiator verifies with r_sign_pk
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
 * Method 0 (SK-SK) requires:
 *   - Initiator's signing keypair (Ed25519 for suites 0/1/4, ES256 for 2/3/5)
 *   - Ephemeral ECDH key (X25519 for suites 0/1/4, P-256 for 2/3/5)
 *   - Responder's signing public key (pre-provisioned for verification)
 *============================================================================*/

// Initiator's EPHEMERAL private key (X)
static uint8_t x_i[SUITE_DH_LEN];

// Initiator's signing seed
static const uint8_t i_sign_seed[] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};
static uint8_t i_sign_sk[SUITE_SIGN_SK_LEN];
static uint8_t i_sign_pk[SUITE_SIGN_PK_LEN];

// Responder's signing seed
static const uint8_t r_sign_seed[] = {
    0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
};
static uint8_t r_sign_pk[SUITE_SIGN_PK_LEN];

// Computed at runtime
static uint8_t g_x[SUITE_DH_LEN];  // Ephemeral public key

// Connection identifier for initiator
static const uint8_t c_i[] = {0x2d}; // C_I = -14

// Suite selection (set by Makefile CRYPTO_SUITE)
static const uint8_t suites[] = {SUITE_BYTE};

/*============================================================================
 * CREDENTIALS
 *
 * For Method 0, CRED_I/CRED_R contain Ed25519 public keys (crv=6).
 * Format: CCS (CWT Claims Set) containing the public key
 *   CRED_I = { 2: "InitM0", 8: { 1: { 1: 1, 2: kid, -1: 6, -2: i_sign_pk } } }
 *
 * ID_CRED_I/R = { 4: kid } - compact reference by key ID
 *============================================================================*/

// ID_CRED_I = {4: 1}
static const uint8_t id_cred_i[] = {0xa1, 0x04, 0x01};

// CRED_I: CCS containing initiator's Ed25519 public key (built at runtime)
static uint8_t cred_i[CRED_BUF_MAX];
static uint32_t cred_i_len;

// ID_CRED_R = {4: 2}
static const uint8_t id_cred_r[] = {0xa1, 0x04, 0x02};

// CRED_R: CCS containing responder's Ed25519 public key (built after pre-provisioning)
static uint8_t cred_r[CRED_BUF_MAX];
static uint32_t cred_r_len;

/*============================================================================
 * MAIN
 *============================================================================*/
int main(void) {
    REG32(uart, UART_REG_DIV) = 868;    /* 50 MHz / 434 = 115207 baud, matches helloWorld default */
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV) = 434;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;

    kprintf("START (initiator)\r\n"); /* diagnostic: always printed, remove once stable */

#ifdef TIMING_BREAKDOWN
    uint64_t t_keygen_start = 0, t_keygen_end = 0;
#endif

#ifdef DEBUG_PRINT
    kprintf("\r\n=================================\r\n"
            "EDHOC Initiator - Method 0\r\n"
            "Suite 0/1 (X25519 + AES-CCM)\r\n"
            "=================================\r\n");
#endif

    // Pre-provisioning (not timed): derive long-term signing keypairs from seeds.
    // In production these are burned in at manufacturing and loaded from NVM.
    {
        uint8_t seed_tmp[SUITE_SIGN_SK_LEN];
        struct byte_array sk_ba = {.ptr = i_sign_sk, .len = SUITE_SIGN_SK_LEN};
        struct byte_array pk_ba = {.ptr = i_sign_pk, .len = SUITE_SIGN_PK_LEN};
        memset(seed_tmp, 0, sizeof(seed_tmp)); memcpy(seed_tmp, i_sign_seed, sizeof(i_sign_seed));
        sign_key_gen(SUITE_SIGN_ALG, seed_tmp, &sk_ba, &pk_ba);
    }
    {
        uint8_t tmp_sk[SUITE_SIGN_SK_LEN], seed_tmp[SUITE_SIGN_SK_LEN];
        struct byte_array sk_ba = {.ptr = tmp_sk, .len = SUITE_SIGN_SK_LEN};
        struct byte_array pk_ba = {.ptr = r_sign_pk, .len = SUITE_SIGN_PK_LEN};
        memset(seed_tmp, 0, sizeof(seed_tmp)); memcpy(seed_tmp, r_sign_seed, sizeof(i_sign_seed));
        sign_key_gen(SUITE_SIGN_ALG, seed_tmp, &sk_ba, &pk_ba);
        memset(tmp_sk, 0, SUITE_SIGN_SK_LEN);
    }

    /* Fold in this board's sign-key seed so the CSPRNG state is unique per
     * board, even if rdcycle/mtime values are identical between runs. */
    csprng_add_entropy(i_sign_seed, sizeof(i_sign_seed));

    /*------------------------------------------------------------------------
     * CSPRNG test: print 16 fresh bytes before using them.
     * If the PRNG is working, this output changes every power cycle.
     *------------------------------------------------------------------------*/
    {
        uint8_t rng_test[16];
        default_CSPRNG(rng_test, sizeof(rng_test));
        print_labeled_array("CSPRNG[16]:", rng_test, sizeof(rng_test));
    }

    /*------------------------------------------------------------------------
     * Per-session ephemeral keygen (timed).
     *
     * Old code used ephemeral_dh_key_gen(X25519, 0x00000001U, ...) which
     * always produces the same private key (4-byte seed → first 4 bytes of
     * a 32-byte key, rest zeros). Fixed: fill all 32 bytes from CSPRNG,
     * apply X25519 clamping (RFC 7748 §5), compute public key directly.
     *------------------------------------------------------------------------*/
#ifdef TIMING_BREAKDOWN
    t_keygen_start = read_cycles();
#endif
    {
        struct byte_array sk_ba = {.ptr = x_i, .len = SUITE_DH_LEN};
        struct byte_array pk_ba = {.ptr = g_x, .len = SUITE_DH_LEN};
        default_CSPRNG(x_i, SUITE_DH_LEN);
        ephemeral_dh_key_gen(SUITE_ECDH_ALG, 0, &sk_ba, &pk_ba);
    }
#ifdef TIMING_BREAKDOWN
    t_keygen_end = read_cycles();
#endif

    // Build credentials with the computed public keys
    static const uint8_t kid_i[] = {0x01};
    static const uint8_t kid_r[] = {0x02};
    cred_i_len = build_ccs_credential(cred_i, "InitM0", kid_i, 1, i_sign_pk, SUITE_SIGN_PK_LEN, SUITE_CRV_SIGN);
    cred_r_len = build_ccs_credential(cred_r, "RespM0", kid_r, 1, r_sign_pk, SUITE_SIGN_PK_LEN, SUITE_CRV_SIGN);
    
#ifdef DEBUG_PRINT
    kprintf("\r\n=== INITIATOR KEY MATERIAL (M0) ===\r\n");
    print_labeled_array("Ephemeral private (x):", x_i, 32);
    print_labeled_array("Ephemeral public (G_X):", g_x, 32);
    print_labeled_array("Own Ed25519 public (I_sign_pk):", i_sign_pk, 32);
    print_labeled_array("Peer Ed25519 public (R_sign_pk):", r_sign_pk, 32);
    kprintf("Method 0: Ed25519 signatures (both parties)\r\n");
#endif

    /*========================================================================
     * EDHOC INITIATOR CONTEXT SETUP - Method 0
     *========================================================================*/
    struct edhoc_initiator_context ctx_i = {0};
    
    // Method 0: Both use Static DH
    ctx_i.method = INITIATOR_SK_RESPONDER_SK;
    
    // Connection identifier
    ctx_i.c_i.ptr = (uint8_t *)c_i;
    ctx_i.c_i.len = sizeof(c_i);
    
    // Supported cipher suites
    ctx_i.suites_i.ptr = (uint8_t *)suites;
    ctx_i.suites_i.len = sizeof(suites);
    
    // Ephemeral keys (fresh per session)
    ctx_i.x.ptr = x_i;
    ctx_i.x.len = sizeof(x_i);
    ctx_i.g_x.ptr = g_x;
    ctx_i.g_x.len = sizeof(g_x);
    
    // Signature keys (Method 0) - Initiator's long-term signing keys
    ctx_i.sk_i.ptr = i_sign_sk;
    ctx_i.sk_i.len = SUITE_SIGN_SK_LEN;
    ctx_i.pk_i.ptr = i_sign_pk;
    ctx_i.pk_i.len = SUITE_SIGN_PK_LEN;
    
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
    // For Method 0, the Ed25519 signing public key goes in the 'pk' field
    cred_r_entry.pk.ptr = r_sign_pk;
    cred_r_entry.pk.len = SUITE_SIGN_PK_LEN;
    struct cred_array cred_r_array = {.len = 1, .ptr = &cred_r_entry};
    
    /*========================================================================
     * RUN EDHOC
     *========================================================================*/
    uint8_t prk_out_buf[SUITE_PRK_LEN], err_msg_buf[64];
    struct byte_array prk_out = {.ptr = prk_out_buf, .len = sizeof(prk_out_buf)};
    struct byte_array err_msg = {.ptr = err_msg_buf, .len = sizeof(err_msg_buf)};

    kprintf("EDHOC running...\r\n");

    enum err result = edhoc_initiator_run(&ctx_i, &cred_r_array, &err_msg, &prk_out,
                                          tx_initiator, rx_initiator, ead_process);
    
    if (result != ok) {
        kprintf("EDHOC FAIL: %d\r\n", result);
        while (1);
    }
    
    kprintf("EDHOC OK!\r\n");

    /* Timing results — single kprintf to avoid wire idle gaps between lines */
#ifdef TIMING_BREAKDOWN
    extern volatile uint32_t _tb_msg1_cyc, _tb_msg3_cyc;
    kprintf("\r\n--- Timing (cycles) ---\r\n"
            "Ephemeral keygen: %lu\r\n"
            "msg1_gen       : %lu\r\n"
            "msg3_gen       : %lu\r\n"
            "EDHOC total    : %lu\r\n"
            "Grand total    : %lu\r\n"
            "-----------------------\r\n",
            (unsigned long)(t_keygen_end - t_keygen_start),
            (unsigned long)_tb_msg1_cyc,
            (unsigned long)_tb_msg3_cyc,
            (unsigned long)(_tb_msg1_cyc + _tb_msg3_cyc),
            (unsigned long)((t_keygen_end - t_keygen_start) + _tb_msg1_cyc + _tb_msg3_cyc));
#endif


    print_labeled_array("PRK_out:", prk_out.ptr, prk_out.len);


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

    /* Task 2: Zeroize key material after use */
    zeroize(x_i,         sizeof(x_i));         /* ephemeral X25519 private key */
    zeroize(i_sign_sk,   sizeof(i_sign_sk));    /* long-term Ed25519 secret key */
    zeroize(prk_out_buf, sizeof(prk_out_buf));  /* session PRK_out */
    zeroize(&ctx_i,      sizeof(ctx_i));        /* EDHOC context (contains key pointers) */

    while (1);
    return 0;
}

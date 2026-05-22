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
 *   - Responder's signing keypair (Ed25519 for suites 0/1/4, ES256 for 2/3/5)
 *   - Ephemeral ECDH key (X25519 for suites 0/1/4, P-256 for 2/3/5)
 *   - Initiator's signing public key (pre-provisioned for verification)
 *============================================================================*/

// Responder's EPHEMERAL private key (Y)
static uint8_t y_r[SUITE_DH_LEN];

// Responder's signing seed
static const uint8_t r_sign_seed[] = {
    0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
};
static uint8_t r_sign_sk[SUITE_SIGN_SK_LEN];
static uint8_t r_sign_pk[SUITE_SIGN_PK_LEN];

// Initiator's signing seed
static const uint8_t i_sign_seed[] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};
static uint8_t i_sign_pk[SUITE_SIGN_PK_LEN];

// Computed at runtime
static uint8_t g_y[SUITE_DH_LEN];  // Ephemeral public key

// Connection identifier for responder
static const uint8_t c_r[] = {0x0e}; // C_R = 14

static const uint8_t suites[] = {SUITE_BYTE};

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
static uint8_t cred_r[CRED_BUF_MAX];
static uint32_t cred_r_len;

// ID_CRED_I = {4: 1}
static const uint8_t id_cred_i[] = {0xa1, 0x04, 0x01};

// CRED_I: CCS containing initiator's Ed25519 public key (built after pre-provisioning)
static uint8_t cred_i[CRED_BUF_MAX];
static uint32_t cred_i_len;

/*============================================================================
 * MAIN
 *============================================================================*/
int main(void) {
    REG32(uart, UART_REG_DIV) = 868;    /* 50 MHz / 434 = 115207 baud, matches helloWorld default */
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV) = 434;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;

    kprintf("START (responder)\r\n"); /* diagnostic: always printed, remove once stable */

#ifdef TIMING_BREAKDOWN
    uint64_t t_keygen_start = 0, t_keygen_end = 0;
#endif

#ifdef DEBUG_PRINT
    kprintf("\r\n=================================\r\n"
            "EDHOC Responder - Method 0\r\n"
            "Suite 0/1 (X25519 + AES-CCM)\r\n"
            "=================================\r\n");
#endif

    // Pre-provisioning (not timed): derive long-term signing keypairs from seeds.
    // In production these are burned in at manufacturing and loaded from NVM.
    {
        uint8_t seed_tmp[SUITE_SIGN_SK_LEN];
        struct byte_array sk_ba = {.ptr = r_sign_sk, .len = SUITE_SIGN_SK_LEN};
        struct byte_array pk_ba = {.ptr = r_sign_pk, .len = SUITE_SIGN_PK_LEN};
        memset(seed_tmp, 0, sizeof(seed_tmp)); memcpy(seed_tmp, r_sign_seed, sizeof(i_sign_seed));
        sign_key_gen(SUITE_SIGN_ALG, seed_tmp, &sk_ba, &pk_ba);
    }
    {
        uint8_t tmp_sk[SUITE_SIGN_SK_LEN], seed_tmp[SUITE_SIGN_SK_LEN];
        struct byte_array sk_ba = {.ptr = tmp_sk, .len = SUITE_SIGN_SK_LEN};
        struct byte_array pk_ba = {.ptr = i_sign_pk, .len = SUITE_SIGN_PK_LEN};
        memset(seed_tmp, 0, sizeof(seed_tmp)); memcpy(seed_tmp, i_sign_seed, sizeof(i_sign_seed));
        sign_key_gen(SUITE_SIGN_ALG, seed_tmp, &sk_ba, &pk_ba);
        memset(tmp_sk, 0, SUITE_SIGN_SK_LEN);
    }

    /* Fold in this board's sign-key seed so the CSPRNG state is unique per
     * board, even if rdcycle/mtime values are identical between runs. */
    csprng_add_entropy(r_sign_seed, sizeof(r_sign_seed));

    /*------------------------------------------------------------------------
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
     * Old code used ephemeral_dh_key_gen(X25519, 0x00000002U, ...) — same
     * 4-byte seed issue as in the initiator. Fixed: fill all 32 bytes from
     * CSPRNG, apply X25519 clamping (RFC 7748 §5), compute public key.
     *------------------------------------------------------------------------*/
#ifdef TIMING_BREAKDOWN
    t_keygen_start = read_cycles();
#endif
    {
        struct byte_array sk_ba = {.ptr = y_r, .len = SUITE_DH_LEN};
        struct byte_array pk_ba = {.ptr = g_y, .len = SUITE_DH_LEN};
        default_CSPRNG(y_r, SUITE_DH_LEN);
        ephemeral_dh_key_gen(SUITE_ECDH_ALG, 0, &sk_ba, &pk_ba);
    }
#ifdef TIMING_BREAKDOWN
    t_keygen_end = read_cycles();
#endif

    // Build credentials with the computed public keys
    static const uint8_t kid_r[] = {0x02};
    static const uint8_t kid_i[] = {0x01};
    cred_r_len = build_ccs_credential(cred_r, "RespM0", kid_r, 1, r_sign_pk, SUITE_SIGN_PK_LEN, SUITE_CRV_SIGN);
    cred_i_len = build_ccs_credential(cred_i, "InitM0", kid_i, 1, i_sign_pk, SUITE_SIGN_PK_LEN, SUITE_CRV_SIGN);

#ifdef DEBUG_PRINT
    kprintf("\r\n=== RESPONDER KEY MATERIAL (M0) ===\r\n");
    print_labeled_array("Ephemeral private (y):", y_r, 32);
    print_labeled_array("Ephemeral public (G_Y):", g_y, 32);
    print_labeled_array("Own Ed25519 public (R_sign_pk):", r_sign_pk, 32);
    print_labeled_array("Peer Ed25519 public (I_sign_pk):", i_sign_pk, 32);
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
    ctx_r.sk_r.len = SUITE_SIGN_SK_LEN;
    ctx_r.pk_r.ptr = r_sign_pk;
    ctx_r.pk_r.len = SUITE_SIGN_PK_LEN;

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
    cred_i_entry.pk.len = SUITE_SIGN_PK_LEN;
    struct cred_array cred_i_array = {.len = 1, .ptr = &cred_i_entry};

    /*========================================================================
     * RUN EDHOC
     *========================================================================*/
    uint8_t prk_out_buf[SUITE_PRK_LEN], err_msg_buf[64];
    struct byte_array prk_out = {.ptr = prk_out_buf, .len = sizeof(prk_out_buf)};
    struct byte_array err_msg = {.ptr = err_msg_buf, .len = sizeof(err_msg_buf)};

    /* Drain any stale bytes in UART1 RX FIFO from a previous initiator run
     * before entering edhoc_responder_run(), to avoid parsing garbage MSG1. */
    while (uart1_getc() >= 0);

    kprintf("EDHOC running...\r\n");

    enum err result = edhoc_responder_run(&ctx_r, &cred_i_array, &err_msg, &prk_out,
                                          tx_responder, rx_responder, ead_process);

    if (result != ok) {
        kprintf("EDHOC FAIL: %d\r\n", result);
        while (1);
    }

    kprintf("EDHOC OK!\r\n");

    /* Timing results */
#ifdef TIMING_BREAKDOWN
    extern volatile uint32_t _tb_msg2_cyc, _tb_msg3proc_cyc;
    kprintf("\r\n--- Timing (cycles) ---\r\n"
            "Ephemeral keygen: %lu\r\n"
            "msg2_gen       : %lu\r\n"
            "msg3_process   : %lu\r\n"
            "EDHOC total    : %lu\r\n"
            "Grand total    : %lu\r\n"
            "-----------------------\r\n",
            (unsigned long)(t_keygen_end - t_keygen_start),
            (unsigned long)_tb_msg2_cyc,
            (unsigned long)_tb_msg3proc_cyc,
            (unsigned long)(_tb_msg2_cyc + _tb_msg3proc_cyc),
            (unsigned long)((t_keygen_end - t_keygen_start) + _tb_msg2_cyc + _tb_msg3proc_cyc));
#endif

    print_labeled_array("PRK_out:", prk_out.ptr, prk_out.len);


    /* Task 2: Zeroize key material after use */
    zeroize(y_r,         sizeof(y_r));          /* ephemeral X25519 private key */
    zeroize(r_sign_sk,   sizeof(r_sign_sk));    /* long-term Ed25519 secret key */
    zeroize(prk_out_buf, sizeof(prk_out_buf));  /* session PRK_out */
    zeroize(&ctx_r,      sizeof(ctx_r));        /* EDHOC context (contains key pointers) */

    while (1);
    return 0;
}

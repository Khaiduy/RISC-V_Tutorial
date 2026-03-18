/* EDHOC Responder - Board B - Suite 0, PSK Mode (Method 4) */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "edhoc.h"
#include "edhoc/edhoc_method_type.h"
#include "edhoc/suites.h"
#include "oscore.h"
#include "compact_x25519.h"
#include "x25519.h"

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
    // Send immediately without printing (kprintf is SLOW and blocks)
    uart1_putc((data->len >> 8) & 0xFF);
    uart1_putc(data->len & 0xFF);
    for (uint32_t i = 0; i < data->len; i++) {
        uart1_putc(data->ptr[i]);
        // Longer delay - UART is slow (3600 baud), need ~3000 cycles per byte
        for (volatile int d = 0; d < 50000; d++);
    }
#ifdef DEBUG_PRINT
    kprintf("[R-TX] Done\r\n");
#endif
    return ok;
}

enum err rx_responder(void *sock, struct byte_array *data) {
    int timeout = 100000000, c;  // Increased 10x for software X25519 key generation
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
    timeout = 10000000;  // Increased 10x for software X25519
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
        timeout = 10000000;  // Increased 10x for software X25519
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

// Test vectors from draft-ietf-lake-edhoc-psk-06 Appendix
// Y (Responder's ephemeral private key)
static const uint8_t y_r[] = {
    0xfb,0xfa,0xc8,0xdb,0x1d,0xc9,0xb2,0x57,0x14,0x4a,0xba,0xad,0x5a,0x1a,0x69,0xb7,
    0xa7,0xf6,0x66,0x12,0xc4,0xb7,0x13,0x1f,0x7b,0x15,0x58,0x56,0x16,0xd6,0x19,0x47
};

// Public keys (to be computed from private keys using software X25519)
static uint8_t g_y[32]; // G_Y will be computed from y_r

// PSK Mode (Method 4) configuration
// C_R = 14 (CBOR: 0x0e)
static const uint8_t c_r[] = {0x0e};

// Suite selection based on CRYPTO_SUITE Makefile option:
//   CRYPTO_SUITE=0: Suite 0 - AES-CCM-16-64-128 (8-byte tag, 13-byte nonce)
//   CRYPTO_SUITE=1: Suite 1 - AES-CCM-16-128-128 (16-byte tag, 13-byte nonce)
//   CRYPTO_SUITE=7: Suite 7 - Ascon-AEAD-128 (16-byte tag, 16-byte nonce)
#if EDHOC_CRYPTO_SUITE == 0
static const uint8_t suites[] = {0x00}; // Suite 0: AES-CCM-16-64-128
#elif EDHOC_CRYPTO_SUITE == 1
static const uint8_t suites[] = {0x01}; // Suite 1: AES-CCM-16-128-128
#elif EDHOC_CRYPTO_SUITE == 7
static const uint8_t suites[] = {0x07}; // Suite 7: Ascon-AEAD-128
#endif

// PSK credentials for Suite 0 (AES-CCM-16-64-128) - MUST match initiator
static const uint8_t psk[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};

// ID_CRED_PSK = {4: h'32'} - identifies the PSK
static const uint8_t id_cred_psk[] = {0xa1,0x04,0x41,0x32}; // {4: h'32'}

// CRED_I: CWT Claims Set for Initiator (38 bytes) - MUST match initiator
// {2: "initiatr", 8: {1: {1: 4, 2: h'32', -1: <PSK>}}}
static const uint8_t cred_i[] = {
    0xa2,0x02,0x68,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,0x72,0x08,0xa1,0x01,0xa3,
    0x01,0x04,0x02,0x41,0x32,0x20,0x50,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
    0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};

// CRED_R: CWT Claims Set for Responder (38 bytes) - MUST match initiator
// {2: "respondr", 8: {1: {1: 4, 2: h'33', -1: <PSK>}}}
static const uint8_t cred_r[] = {
    0xa2,0x02,0x68,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,0x72,0x08,0xa1,0x01,0xa3,
    0x01,0x04,0x02,0x41,0x33,0x20,0x50,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
    0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};

// Note: bytes_to_words32 and words32_to_bytes are no longer needed
// The new hwx25519_init32_bytes and hwx25519_results32_bytes handle byte ordering internally

// Function to compute public key from private key using software X25519
// This mimics what crypto_wrapper.c does in shared_secret_derive()
static void generate_public_key(const uint8_t *priv_key, uint8_t *pub_key) {
    // Declare external functions from c25519
    extern void c25519_smult(uint8_t *result, const uint8_t *q, const uint8_t *e);
    extern const uint8_t c25519_base_x[32];
    
    // Copy and clamp the private key (same as shared_secret_derive does)
    uint8_t e[32];
    memcpy(e, priv_key, 32);
    
    // Clamp the private key (c25519_prepare)
    e[0] &= 0xf8;
    e[31] &= 0x7f;
    e[31] |= 0x40;
    
    // Compute public key = scalar_mult(e, base_point)
    c25519_smult(pub_key, c25519_base_x, e);
    
    // Clear the clamped key
    memset(e, 0, 32);
}

/* Read cycle counter for timing */
static inline uint64_t read_cycles(void) {
    uint64_t cycles;
    asm volatile ("rdcycle %0" : "=r" (cycles));
    return cycles;
}

int main(void) {
    REG32(uart, UART_REG_DIV) = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV) = 868;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;
    
    /* Timing measurements */
    uint64_t t_keygen_start = 0, t_keygen_end = 0;
    uint64_t t_edhoc_start = 0, t_edhoc_end = 0;
    
#ifdef DEBUG_PRINT
    kprintf("\r\nEDHOC Responder (Software X25519)\r\n");
#endif
    
    t_keygen_start = read_cycles();
    generate_public_key(y_r, g_y);
    t_keygen_end = read_cycles();
    
    // PSK Mode (Method 4) doesn't use static DH keys - authentication via PSK
#ifdef DEBUG_PRINT
    kprintf("\r\n=== RESPONDER INPUT PARAMETERS ===\r\n");
    
    kprintf("y_r (private key): ");
    for (uint32_t i = 0; i < 32; i++) {
        kprintf("%hx ", y_r[i]);
        if ((i + 1) % 16 == 0) {  // Check if we just printed the 16th byte
            kprintf("\r\n");
        }
    }
    kprintf("\r\n");
    
    kprintf("G_Y (public key): ");
    for (uint32_t i = 0; i < 32; i++) {
        kprintf("%hx ", g_y[i]);
        if ((i + 1) % 16 == 0) {  // Check if we just printed the 16th byte
            kprintf("\r\n");
        }
    }
    kprintf("\r\n");
    
    kprintf("C_R: ");
    for (uint32_t i = 0; i < sizeof(c_r); i++) {
        kprintf("%hx ", c_r[i]);
    }
    kprintf("\r\n");
    
    kprintf("PSK: ");
    for (uint32_t i = 0; i < sizeof(psk); i++) {
        kprintf("%hx ", psk[i]);
    }
    kprintf("\r\n");
    
    kprintf("ID_CRED_PSK: ");
    for (uint32_t i = 0; i < sizeof(id_cred_psk); i++) {
        kprintf("%hx ", id_cred_psk[i]);
    }
    kprintf("\r\n");
    
    kprintf("CRED_I: ");
    for (uint32_t i = 0; i < sizeof(cred_i); i++) {
        kprintf("%hx ", cred_i[i]);
        if ((i + 1) % 16 == 0) {  // Check if we just printed the 16th byte
            kprintf("\r\n");
        }
    }
    kprintf("\r\n");
    
    kprintf("CRED_R: ");
    for (uint32_t i = 0; i < sizeof(cred_r); i++) {
        kprintf("%hx ", cred_r[i]);
        if ((i + 1) % 16 == 0) {  // Check if we just printed the 16th byte
            kprintf("\r\n");
        }
    }
    kprintf("\r\n");
#endif
    
#ifdef DEBUG_PRINT
    kprintf("PSK Mode: Using pre-shared key for authentication\r\n");
#endif
        
    struct edhoc_responder_context ctx_r = {0};
    ctx_r.c_r.ptr = (uint8_t *)c_r; ctx_r.c_r.len = sizeof(c_r);
    ctx_r.suites_r.ptr = (uint8_t *)suites; ctx_r.suites_r.len = sizeof(suites);
    ctx_r.y.ptr = (uint8_t *)y_r; ctx_r.y.len = sizeof(y_r);
    ctx_r.g_y.ptr = (uint8_t *)g_y; ctx_r.g_y.len = sizeof(g_y);
    // PSK Mode (Method 4) configuration
    ctx_r.psk.ptr = (uint8_t *)psk; ctx_r.psk.len = sizeof(psk);
    ctx_r.id_cred_psk.ptr = (uint8_t *)id_cred_psk; ctx_r.id_cred_psk.len = sizeof(id_cred_psk);
    ctx_r.cred_r.ptr = (uint8_t *)cred_r; ctx_r.cred_r.len = sizeof(cred_r);
    
    struct other_party_cred cred_i_entry = {0};
    cred_i_entry.id_cred.ptr = (uint8_t *)id_cred_psk; cred_i_entry.id_cred.len = sizeof(id_cred_psk);
    cred_i_entry.cred.ptr = (uint8_t *)cred_i; cred_i_entry.cred.len = sizeof(cred_i);
    cred_i_entry.pk.ptr = (uint8_t *)psk; cred_i_entry.pk.len = sizeof(psk); // PSK stored in pk field
    struct cred_array cred_i_array = {.len = 1, .ptr = &cred_i_entry};
    
    uint8_t prk_out_buf[32], err_msg_buf[64];
    struct byte_array prk_out = {.ptr = prk_out_buf, .len = sizeof(prk_out_buf)};
    struct byte_array err_msg = {.ptr = err_msg_buf, .len = sizeof(err_msg_buf)};
    
#ifdef DEBUG_PRINT
    kprintf("\r\n=== RESPONDER START new ===\r\n");
#endif

    t_edhoc_start = read_cycles();
    enum err result = edhoc_responder_run(&ctx_r, &cred_i_array, &err_msg, &prk_out, tx_responder, rx_responder, ead_process);
    t_edhoc_end = read_cycles();
    
    if (result != ok) {
        kprintf("FAIL: %d\r\n", result);
        while (1);
    }
    
    kprintf("OK!\r\n");
    
    /* Print timing results */
    kprintf("\r\n--- Software Computation Time (cycles) ---\r\n");
    kprintf("Key generation:  %lu\r\n", (unsigned long)(t_keygen_end - t_keygen_start));
    kprintf("EDHOC protocol:  %lu\r\n", (unsigned long)(t_edhoc_end - t_edhoc_start));
    kprintf("TOTAL:           %lu\r\n", (unsigned long)(t_edhoc_end - t_keygen_start));
    kprintf("------------------------------------------\r\n");
    
#ifdef DEBUG_PRINT
    kprintf("PRK_out: ");
    for (uint32_t i = 0; i < prk_out.len; i++) kprintf("%x", prk_out.ptr[i]);
    kprintf("\r\n");
#endif
    
    // Get suite info to determine hash algorithm
    struct suite current_suite;
    result = get_suite(SUITE_7, &current_suite);
    if (result != ok) {
        kprintf("get_suite FAIL: %d\r\n", result);
        while (1);
    }
    
    // Derive OSCORE keys from PRK_out
    uint8_t prk_exporter_buf[32];
    struct byte_array prk_exporter = {.ptr = prk_exporter_buf, .len = sizeof(prk_exporter_buf)};
    
    result = prk_out2exporter(current_suite.edhoc_hash, &prk_out, &prk_exporter);
    if (result != ok) {
        kprintf("prk_out2exporter FAIL: %d\r\n", result);
        while (1);
    }
    
#ifdef DEBUG_PRINT
    kprintf("PRK_exporter: ");
    for (uint32_t i = 0; i < prk_exporter.len; i++) kprintf("%x", prk_exporter.ptr[i]);
    kprintf("\r\n");
#endif
    
    // Derive OSCORE Master Secret
    uint8_t oscore_master_secret_buf[16];
    struct byte_array oscore_master_secret = {.ptr = oscore_master_secret_buf, .len = sizeof(oscore_master_secret_buf)};
    
    result = edhoc_exporter(current_suite.edhoc_hash, OSCORE_MASTER_SECRET, &prk_exporter, &oscore_master_secret);
    if (result != ok) {
        kprintf("OSCORE MS derivation FAIL: %d\r\n", result);
        while (1);
    }
    
#ifdef DEBUG_PRINT
    kprintf("OSCORE Master Secret: ");
    for (uint32_t i = 0; i < oscore_master_secret.len; i++) kprintf("%x", oscore_master_secret.ptr[i]);
    kprintf("\r\n");
#endif
    
    // Derive OSCORE Master Salt
    uint8_t oscore_master_salt_buf[8];
    struct byte_array oscore_master_salt = {.ptr = oscore_master_salt_buf, .len = sizeof(oscore_master_salt_buf)};
    
    result = edhoc_exporter(current_suite.edhoc_hash, OSCORE_MASTER_SALT, &prk_exporter, &oscore_master_salt);
    if (result != ok) {
        kprintf("OSCORE Salt derivation FAIL: %d\r\n", result);
        while (1);
    }
    
#ifdef DEBUG_PRINT
    kprintf("OSCORE Master Salt: ");
    for (uint32_t i = 0; i < oscore_master_salt.len; i++) kprintf("%x", oscore_master_salt.ptr[i]);
    kprintf("\r\n");
#endif
    
    // Initialize OSCORE context (Responder is server, uses C_R as sender ID)
#ifdef DEBUG_PRINT
    kprintf("Initializing OSCORE context...\r\n");
#endif
    static struct context oscore_ctx;  // Static to avoid stack overflow
    memset(&oscore_ctx, 0, sizeof(oscore_ctx));  // Zero out before use
    
    // For demo: manually set recipient_id to initiator's C_I (extracted from EDHOC msg1 in real scenario)
    static uint8_t recipient_id_buf[1];
    recipient_id_buf[0] = 0x2D;  // Initiator's C_I value
    struct byte_array recipient_id = {.ptr = recipient_id_buf, .len = 1};
    
    struct oscore_init_params oscore_params = {
        .master_secret = oscore_master_secret,
        .sender_id = ctx_r.c_r,      // Responder's own ID
        .recipient_id = recipient_id,   // Initiator's ID
        .master_salt = oscore_master_salt,
        .aead_alg = OSCORE_ASCON_AEAD_128,  // Use Ascon-AEAD for Suite 7
        .hkdf = OSCORE_ASCON_HASH,          // Use HKDF with Ascon-Hash256 for Suite 7
        .fresh_master_secret_salt = true  // Derived from EDHOC
    };
    
    result = oscore_context_init(&oscore_params, &oscore_ctx);
    if (result != ok) {
        kprintf("OSCORE init FAIL: %d\r\n", result);
        while (1);
    }
    
    kprintf("OSCORE READY - Secure channel established\r\n");
    
//     // =========================================================================
//     // REAL-LIFE SCENARIO: Continuous sensor data reception loop
//     // Simulates an IoT gateway/server receiving encrypted telemetry from sensors
//     // =========================================================================
    
//     static uint8_t oscore_msg_received[256];
//     static uint8_t coap_decrypted[128];
//     uint32_t msg_count = 0;
    
//     kprintf("\r\n=== OSCORE Server: Waiting for sensor data ===\r\n");
    
//     while (1) {
//         // Wait for incoming encrypted message
//         struct byte_array oscore_msg_ba = {
//             .ptr = oscore_msg_received,
//             .len = sizeof(oscore_msg_received)
//         };
        
//         result = rx_responder(NULL, &oscore_msg_ba);
//         if (result != ok) {
//             kprintf("RX FAIL: %d (retrying...)\r\n", result);
//             continue;  // Timeout or error, keep listening
//         }
        
//         msg_count++;
        
// #ifdef DEBUG_PRINT
//         kprintf("[RX] Received %d bytes encrypted\r\n", oscore_msg_ba.len);
// #endif
        
//         // Decrypt OSCORE message back to CoAP
//         uint32_t coap_decrypted_len = sizeof(coap_decrypted);
//         result = oscore2coap(oscore_msg_received, oscore_msg_ba.len, 
//                             coap_decrypted, &coap_decrypted_len, &oscore_ctx);
//         if (result != ok) {
//             kprintf("[%d] Decrypt FAIL: %d\r\n", msg_count, result);
//             continue;  // Skip this message, wait for next
//         }
        
//         // Parse and display the decrypted CoAP message
//         // Extract payload (after 0xFF marker)
//         char payload_str[64] = {0};
//         uint32_t payload_idx = 0;
//         for (uint32_t i = 0; i < coap_decrypted_len; i++) {
//             if (coap_decrypted[i] == 0xFF && i + 1 < coap_decrypted_len) {
//                 for (uint32_t j = i + 1; j < coap_decrypted_len && payload_idx < 63; j++) {
//                     payload_str[payload_idx++] = coap_decrypted[j];
//                 }
//                 break;
//             }
//         }
        
//         // Display received sensor data
//         // In production: store to database, trigger alerts, etc.
//         kprintf("[%d] Sensor: %s\r\n", msg_count, payload_str);
        
// #ifdef DEBUG_PRINT
//         // Show CoAP details
//         uint8_t code = coap_decrypted[1];
//         uint8_t token = (coap_decrypted[0] & 0x0F) > 0 ? coap_decrypted[4] : 0;
//         kprintf("     Code: %d.%02d, Token: 0x%02x\r\n", 
//                 (code >> 5) & 0x07, code & 0x1F, token);
// #endif
//     }
    
    while (1);
}

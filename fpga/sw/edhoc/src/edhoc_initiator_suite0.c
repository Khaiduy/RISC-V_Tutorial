/* EDHOC Initiator - Board A - Suite 0, PSK Mode (Method 4) */
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

enum err tx_initiator(void *sock, struct byte_array *data) {
#ifdef DEBUG_PRINT
    kprintf("[I-TX] Sending %d bytes\r\n", data->len);
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
    kprintf("[I-TX] Done\r\n");
#endif
    return ok;
}

enum err rx_initiator(void *sock, struct byte_array *data) {
    int timeout = 1000000000, c;  // ~20 seconds for software X25519 (responder needs ~13s)
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
    timeout = 100000000;  // ~2 seconds for subsequent bytes
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
        timeout = 100000000;  // ~2 seconds for each byte
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

enum err ead_process(void *params, struct byte_array *ead) { return ok; }

// Test vectors from draft-ietf-lake-edhoc-psk-06 Appendix
// X (Initiator's ephemeral private key) in LITTLE-ENDIAN byte order (LSB first)
static const uint8_t x_i[] = {
    0xe9,0xac,0x11,0xbf,0x6c,0x77,0x17,0xd7,0xea,0xb5,0xea,0x74,0x56,0x8b,0xd0,0xbc,
    0x11,0xb4,0xa5,0xd7,0xe6,0xd7,0xa5,0x67,0x1c,0x3b,0xf1,0xab,0x49,0x18,0x6b,0x61
};

// Public keys (to be computed from private keys using software X25519)
static uint8_t g_x[32]; // G_X will be computed from x_i

// PSK Mode (Method 4) configuration
static const uint8_t c_i[] = {0x2d}; // C_I = -14 (0x2d in CBOR)

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

// PSK credentials for Suite 0 (AES-CCM-16-64-128)
static const uint8_t psk[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};

// ID_CRED_PSK = {4: h'32'} - identifies the PSK
static const uint8_t id_cred_psk[] = {0xa1,0x04,0x41,0x32}; // {4: h'32'}

// CRED_I: CWT Claims Set for Initiator (38 bytes)
// {2: "initiatr", 8: {1: {1: 4, 2: h'32', -1: <PSK>}}}
static const uint8_t cred_i[] = {
    0xa2,0x02,0x68,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,0x72,0x08,0xa1,0x01,0xa3,
    0x01,0x04,0x02,0x41,0x32,0x20,0x50,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
    0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};

// CRED_R: CWT Claims Set for Responder (38 bytes)
// {2: "respondr", 8: {1: {1: 4, 2: h'33', -1: <PSK>}}}
static const uint8_t cred_r[] = {
    0xa2,0x02,0x68,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,0x72,0x08,0xa1,0x01,0xa3,
    0x01,0x04,0x02,0x41,0x33,0x20,0x50,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
    0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};

// Hardware X25519 test function using 32-bit driver
// This properly handles byte ordering for RV32 systems
// static void hw_x25519_compute_32bit(const uint8_t *scalar_bytes, 
//                                      const uint8_t *point_bytes,
//                                      uint8_t *result_bytes)
// {
//     // The hardware expects clamped scalars, but per user: hardware handles clamping
//     // So we pass the scalar directly without software clamping
    
//     // Use the 32-bit byte-level driver functions with debug output
//     hwx25519_init32_bytes((void*)X25519_CTRL_ADDR, scalar_bytes, point_bytes);
//     hwx25519_results32_bytes((void*)X25519_CTRL_ADDR, result_bytes);
// }

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
    kprintf("\r\nEDHOC Initiator (Software X25519)\r\n");
#endif
    
    // Generate public keys from private keys using software X25519
    t_keygen_start = read_cycles();
    generate_public_key(x_i, g_x);
    t_keygen_end = read_cycles();
      
#ifdef DEBUG_PRINT
    kprintf("\r\n=== INITIATOR INPUT PARAMETERS ===\r\n");
    
    kprintf("x_i (private key): ");
    for (uint32_t i = 0; i < 32; i++) {
        kprintf("%hx ", x_i[i]);
        if ((i + 1) % 16 == 0) {  // Check if we just printed the 16th byte
            kprintf("\r\n");
        }
    }
    kprintf("\r\n");
    
    kprintf("G_X (public key): ");
    for (uint32_t i = 0; i < 32; i++) {
        kprintf("%hx ", g_x[i]);
        if ((i + 1) % 16 == 0) {  // Check if we just printed the 16th byte
            kprintf("\r\n");
        }
    }
    kprintf("\r\n");
    
    kprintf("C_I: ");
    for (uint32_t i = 0; i < sizeof(c_i); i++) {
        kprintf("%hx ", c_i[i]);
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
    
    kprintf("\r\nPSK Mode: Using pre-shared key for authentication\r\n");
#endif
        
    struct edhoc_initiator_context ctx_i = {0};
    ctx_i.method = INITIATOR_PSK_RESPONDER_PSK; // Method 4: PSK authentication
    ctx_i.c_i.ptr = (uint8_t *)c_i; ctx_i.c_i.len = sizeof(c_i);
    ctx_i.suites_i.ptr = (uint8_t *)suites; ctx_i.suites_i.len = sizeof(suites);
    ctx_i.x.ptr = (uint8_t *)x_i; ctx_i.x.len = sizeof(x_i);
    ctx_i.g_x.ptr = (uint8_t *)g_x; ctx_i.g_x.len = sizeof(g_x);
    // PSK Mode (Method 4) configuration
    ctx_i.psk.ptr = (uint8_t *)psk; ctx_i.psk.len = sizeof(psk);
    ctx_i.id_cred_psk.ptr = (uint8_t *)id_cred_psk; ctx_i.id_cred_psk.len = sizeof(id_cred_psk);
    ctx_i.cred_i.ptr = (uint8_t *)cred_i; ctx_i.cred_i.len = sizeof(cred_i);
    
    struct other_party_cred cred_r_entry = {0};
    cred_r_entry.id_cred.ptr = (uint8_t *)id_cred_psk; cred_r_entry.id_cred.len = sizeof(id_cred_psk);
    cred_r_entry.cred.ptr = (uint8_t *)cred_r; cred_r_entry.cred.len = sizeof(cred_r);
    cred_r_entry.pk.ptr = (uint8_t *)psk; cred_r_entry.pk.len = sizeof(psk); // PSK stored in pk field
    struct cred_array cred_r_array = {.len = 1, .ptr = &cred_r_entry};
    
    uint8_t prk_out_buf[32], err_msg_buf[64];
    struct byte_array prk_out = {.ptr = prk_out_buf, .len = sizeof(prk_out_buf)};
    struct byte_array err_msg = {.ptr = err_msg_buf, .len = sizeof(err_msg_buf)};
    

#ifdef DEBUG_PRINT
    kprintf("\r\n=== INITIATOR START ===\r\n");
#endif

    t_edhoc_start = read_cycles();
    enum err result = edhoc_initiator_run(&ctx_i, &cred_r_array, &err_msg, &prk_out, tx_initiator, rx_initiator, ead_process);
    t_edhoc_end = read_cycles();
    
    if (result != ok) {
        kprintf("EDHOC FAIL: %d\r\n", result);
        while (1);
    }
    
    kprintf("EDHOC OK!\r\n");
    
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
    
    // Initialize OSCORE context (Initiator is client, uses C_I as sender ID)
#ifdef DEBUG_PRINT
    kprintf("Initializing OSCORE context...\r\n");
#endif
    static struct context oscore_ctx;  // Static to avoid stack overflow
    memset(&oscore_ctx, 0, sizeof(oscore_ctx));  // Zero out before use
    
    // For demo: manually set recipient_id to responder's C_R (extracted from EDHOC msg2 in real scenario)
    static uint8_t recipient_id_buf[1];
    recipient_id_buf[0] = 0x0E;  // Responder's C_R value
    struct byte_array recipient_id = {.ptr = recipient_id_buf, .len = 1};
    
    struct oscore_init_params oscore_params = {
        .master_secret = oscore_master_secret,
        .sender_id = ctx_i.c_i,      // Initiator's own ID
        .recipient_id = recipient_id,   // Responder's ID
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
    
    // // =========================================================================
    // // REAL-LIFE SCENARIO: Continuous sensor data transmission loop
    // // Simulates an IoT sensor node sending encrypted telemetry to a server
    // // =========================================================================
    
    // static uint8_t coap_msg[128];
    // static uint8_t oscore_msg[256];
    // uint16_t msg_id = 0x1000;  // Message ID counter
    // uint32_t reading_count = 0;
    
    // // Simulated sensor readings (would come from real ADC in production)
    // int16_t temp_base = 250;  // 25.0°C in tenths
    
    // kprintf("\r\n=== OSCORE Client: Starting sensor transmission ===\r\n");
    
    // while (1) {
    //     reading_count++;
        
    //     // Simulate temperature variation (+/- 2°C from base)
    //     int16_t temp = temp_base + (reading_count % 40) - 20;
        
    //     // Build CoAP POST request with sensor data
    //     // Real scenario: POST /sensors/temp with JSON or CBOR payload
    //     uint8_t *p = coap_msg;
        
    //     // CoAP Header: Ver=1, Type=CON(0), TKL=1, Code=POST(0.02)
    //     *p++ = 0x41;  // Ver=1, T=0(CON), TKL=1
    //     *p++ = 0x02;  // Code=0.02 (POST)
    //     *p++ = (msg_id >> 8) & 0xFF;  // Message ID (MSB)
    //     *p++ = msg_id & 0xFF;         // Message ID (LSB)
    //     *p++ = (uint8_t)(reading_count & 0xFF);  // Token (1 byte for request matching)
        
    //     // Uri-Path option: /temp (Option Delta=11, Length=4)
    //     *p++ = 0xB4;  // Delta=11, Len=4
    //     *p++ = 't'; *p++ = 'e'; *p++ = 'm'; *p++ = 'p';
        
    //     // Content-Format option: text/plain (Delta=1, Length=1, Value=0)
    //     *p++ = 0x10;  // Delta=1(12-11), Len=0 (implicit text/plain)
        
    //     // Payload marker
    //     *p++ = 0xFF;
        
    //     // Payload: Simple format "T:XXX" where XXX is temp in tenths
    //     *p++ = 'T'; *p++ = ':';
    //     if (temp < 0) { *p++ = '-'; temp = -temp; }
    //     *p++ = '0' + (temp / 100) % 10;
    //     *p++ = '0' + (temp / 10) % 10;
    //     *p++ = '.';
    //     *p++ = '0' + temp % 10;
        
    //     uint32_t coap_len = p - coap_msg;
        
    //     // Encrypt and send
    //     uint32_t oscore_len = sizeof(oscore_msg);
    //     result = coap2oscore(coap_msg, coap_len, oscore_msg, &oscore_len, &oscore_ctx);
    //     if (result != ok) {
    //         kprintf("Encrypt FAIL: %d\r\n", result);
    //         continue;  // Skip this reading, try next
    //     }
        
    //     struct byte_array oscore_msg_ba = { .ptr = oscore_msg, .len = oscore_len };
    //     result = tx_initiator(NULL, &oscore_msg_ba);
    //     if (result != ok) {
    //         kprintf("TX FAIL: %d\r\n", result);
    //         continue;
    //     }
        
    //     kprintf("[%d] Sent temp=%d.%d C (%d bytes encrypted)\r\n", 
    //             reading_count, (temp_base + (reading_count % 40) - 20) / 10,
    //             ((temp_base + (reading_count % 40) - 20) % 10 + 10) % 10,
    //             oscore_len);
        
    //     msg_id++;
        
    //     // Delay between readings (simulate real sensor sampling interval)
    //     // In production: use timer interrupt or sleep mode
    //     for (volatile uint32_t d = 0; d < 5000000; d++);
    // }
    while (1);
    
    return 0;
}

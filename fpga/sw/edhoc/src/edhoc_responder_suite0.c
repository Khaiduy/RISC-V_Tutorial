/* EDHOC Responder - Board B - Suite 0, PSK Mode (Method 4) */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "edhoc.h"
#include "edhoc/edhoc_method_type.h"
#include "edhoc/suites.h"
#include "compact_x25519.h"

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

// Private keys (fixed for testing - in production these should be random)
// static const uint8_t r_priv[] = {0xfd,0x8c,0xd8,0x77,0xc9,0xea,0x38,0x16,0xb7,0x82,0x9a,0xf5,0xa4,0x6a,0x12,0xc6,0xf7,0x86,0x78,0x72,0x39,0xba,0x23,0x6f,0xf8,0x81,0x28,0x3a,0xc6,0xd4,0x4d,0x67};
static const uint8_t y_r[] = {0xec,0x88,0xd2,0xd5,0x1d,0xa5,0xed,0x67,0xfc,0x46,0x16,0x35,0x6b,0xc8,0xca,0x74,0xef,0x9e,0xbe,0x8b,0x38,0x7e,0x62,0x3a,0x36,0x0b,0xa4,0x80,0xb9,0xb2,0x9d,0x1c};

// Public keys (to be computed from private keys using software X25519)
// static uint8_t g_r[32]; // Responder static public key
static uint8_t g_y[32]; // Responder ephemeral public key

// PSK Mode (Method 4) configuration
// C_R must be CBOR-encoded: value 0-23 encodes to 1 byte
// Using value 7 -> CBOR 0x07 (1 byte)
static const uint8_t c_r[] = {0x07};
static const uint8_t suites[] = {0x00};
// PSK credentials (Method 4 uses PSK instead of certificates)
static const uint8_t psk[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10}; // 16-byte PSK (MUST match initiator)
static const uint8_t id_cred_psk[] = {0xa1,0x04,0x41,0x32}; // ID for PSK credential
static const uint8_t cred_i[] = {0xa2,0x02,0x41,0x32,0x20,0x01}; // Initiator credential
static const uint8_t cred_r[] = {0xa2,0x02,0x41,0x33,0x20,0x01}; // Responder credential

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

int main(void) {
    REG32(uart, UART_REG_DIV) = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV) = 868;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;
    
#ifdef DEBUG_PRINT
    kprintf("\r\nEDHOC Responder (Software X25519)\r\n");
#endif
    
    // Generate public keys from private keys using software X25519
    // kprintf("Generating public key g_r from r_priv...\r\n");
    // generate_public_key(r_priv, g_r);
    // kprintf("  -> g_r DONE\r\n");
    
#ifdef DEBUG_PRINT
    kprintf("Generating ephemeral public key G_Y from y_r...\r\n");
#endif
    generate_public_key(y_r, g_y);
#ifdef DEBUG_PRINT
    kprintf("  -> G_Y DONE\r\n");
#endif
    
    // PSK Mode (Method 4) doesn't use static DH keys - authentication via PSK
#ifdef DEBUG_PRINT
    kprintf("PSK Mode: Using pre-shared key for authentication\r\n");
#endif
    
    // Test X25519 hardware accelerator
    // kprintf("\r\n=== Testing X25519 Hardware ===\r\n");
    // extern void hwx25519_selftest(void* x25519ctrl);
    // hwx25519_selftest((void*)0x64004000);
    // kprintf("=== X25519 Test Complete ===\r\n\r\n");
    
    // // Test UART1 transport
    // kprintf("Testing UART1...\r\n");
    
    // // Test 1: Receive test bytes from initiator
    // kprintf("RX: Waiting for test bytes (10s timeout)...\r\n");
    // int timeout = 10000000;
    // int c;
    // while ((c = uart1_getc()) < 0 && timeout-- > 0);
    // if (c >= 0) {
    //     kprintf("RX: Got 0x"); kprintf("%x\r\n", c);
    //     // Read a few more bytes
    //     for (int i = 0; i < 3; i++) {
    //         timeout = 1000000;
    //         while ((c = uart1_getc()) < 0 && timeout-- > 0);
    //         if (c >= 0) { kprintf("RX: Got 0x"); kprintf("%x\r\n", c); }
    //     }
        
    //     // Echo back
    //     kprintf("TX: Echoing back...\r\n");
    //     uart1_putc(0xBB);
    //     uart1_putc(0x66);
    //     uart1_putc(0x43);
    //     uart1_putc(0x21);
    //     kprintf("TX: Sent 0xBB 0x66 0x43 0x21\r\n");
    // } else {
    //     kprintf("RX: TIMEOUT - no data from initiator\r\n");
    //     kprintf("Check: Is initiator running? Is UART1 wired correctly?\r\n");
    // }
    
    // // Test 2: Test transport functions - wait for message
    // kprintf("\r\nTesting transport functions...\r\n");
    // uint8_t rx_buf[64];
    // struct byte_array test_rx = {.ptr = rx_buf, .len = sizeof(rx_buf)};
    // kprintf("RX: Waiting for message (10s timeout)...\r\n");
    // enum err rx_result = rx_responder(NULL, &test_rx);
    // kprintf("RX result: %d (0=ok, 7=timeout)\r\n", rx_result);
    // if (rx_result == ok) {
    //     kprintf("RX: Got %d bytes: ", test_rx.len);
    //     for (uint32_t i = 0; i < test_rx.len && i < 16; i++) {
    //         kprintf("%x ", test_rx.ptr[i]);
    //     }
    //     kprintf("\r\n");
        
    //     // Echo it back
    //     kprintf("TX: Echoing message back...\r\n");
    //     enum err tx_result = tx_responder(NULL, &test_rx);
    //     kprintf("TX result: %d (0=ok)\r\n", tx_result);
    // }
    
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
    struct cred_array cred_i_array = {.len = 1, .ptr = &cred_i_entry};
    
    uint8_t prk_out_buf[32], err_msg_buf[64];
    struct byte_array prk_out = {.ptr = prk_out_buf, .len = sizeof(prk_out_buf)};
    struct byte_array err_msg = {.ptr = err_msg_buf, .len = sizeof(err_msg_buf)};
    
    kprintf("\r\n=== RESPONDER START ===\r\n");

    enum err result = edhoc_responder_run(&ctx_r, &cred_i_array, &err_msg, &prk_out, tx_responder, rx_responder, ead_process);
    
    if (result != ok) {
        kprintf("FAIL: %d\r\n", result);
        while (1);
    }
    
    kprintf("OK! Key: ");
    for (uint32_t i = 0; i < 16; i++) kprintf("%x", prk_out.ptr[i]);
    kprintf("\r\n");
    
    while (1);
}

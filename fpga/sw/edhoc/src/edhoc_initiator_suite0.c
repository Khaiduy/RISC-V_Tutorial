/* EDHOC Initiator - Board A - Suite 0, PSK Mode (Method 4) */
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
// X (Initiator's ephemeral private key)
static const uint8_t x_i[] = {
    0x89,0x2e,0xc2,0x8e,0x5c,0xb6,0x66,0x91,0x08,0x47,0x05,0x39,0x50,0x0b,0x70,0x5c,
    0x90,0xce,0xdb,0xd0,0xa9,0x9e,0x12,0xb0,0x59,0x2e,0x81,0x4f,0x2a,0xd9,0xc9,0x61
};

// Public keys (to be computed from private keys using software X25519)
static uint8_t g_x[32]; // G_X will be computed from x_i

// PSK Mode (Method 4) configuration - Suite 1 (AES-CCM-16-128-128, 16-byte tag)
static const uint8_t c_i[] = {0x2d}; // C_I = -14 (0x2d in CBOR)
static const uint8_t suites[] = {0x02}; // Suite 1: AES-CCM-16-128-128 (Tag=16)

// PSK credentials for Suite 0 (AES-CCM-16-64-128)
static const uint8_t psk[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};

// ID_CRED_PSK = {4: h'32'} - identifies the PSK
static const uint8_t id_cred_psk[] = {0xa1,0x04,0x41,0x32}; // {4: h'32'}

// CRED_I: CWT Claims Set for Initiator (39 bytes)
// {2: "initiator", 8: {1: {1: 4, 2: h'32', -1: <PSK>}}}
static const uint8_t cred_i[] = {
    0xa2,0x02,0x69,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,0x6f,0x72,0x08,0xa1,0x01,0xa3,
    0x01,0x04,0x02,0x41,0x32,0x20,0x50,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
    0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};

// CRED_R: CWT Claims Set for Responder (38 bytes)
// {2: "responder", 8: {1: {1: 4, 2: h'33', -1: <PSK>}}}
static const uint8_t cred_r[] = {
    0xa2,0x02,0x69,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,0x65,0x72,0x08,0xa1,0x01,0xa3,
    0x01,0x04,0x02,0x41,0x33,0x20,0x50,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
    0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};

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
    kprintf("\r\nEDHOC Initiator (Software X25519)\r\n");
#endif
    
    // Generate public keys from private keys using software X25519
    // kprintf("Generating public key g_i from i_priv...\r\n");
    // generate_public_key(i_priv, g_i);
    // kprintf("  -> g_i DONE\r\n");
    
#ifdef DEBUG_PRINT
    kprintf("Generating ephemeral public key G_X from x_i...\r\n");
#endif
    generate_public_key(x_i, g_x);
#ifdef DEBUG_PRINT
    kprintf("  -> G_X DONE\r\n");
#endif
    
    // PSK Mode (Method 4) doesn't use static DH keys - authentication via PSK
#ifdef DEBUG_PRINT
    kprintf("PSK Mode: Using pre-shared key for authentication\r\n");
#endif
    
    // // Test X25519 hardware accelerator
    // kprintf("\r\n=== Testing X25519 Hardware ===\r\n");
    // extern void hwx25519_selftest(void* x25519ctrl);
    // hwx25519_selftest((void*)0x64004000);
    // kprintf("=== X25519 Test Complete ===\r\n\r\n");
    
    // // Test UART1 transport
    // kprintf("Testing UART1...\r\n");
    
    // // Test 1: Send test message
    // kprintf("TX: Sending test bytes...\r\n");
    // uart1_putc(0xAA);
    // uart1_putc(0x55);
    // uart1_putc(0x12);
    // uart1_putc(0x34);
    // kprintf("TX: Sent 0xAA 0x55 0x12 0x34\r\n");
    
    // // Test 2: Try to receive (should timeout if responder not ready)
    // kprintf("RX: Waiting for response (10s timeout)...\r\n");
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
    // } else {
    //     kprintf("RX: TIMEOUT - no data received\r\n");
    //     kprintf("Check: Is responder running? Is UART1 wired correctly?\r\n");
    // }
    
    // // Test 3: Test transport functions with small message
    // kprintf("\r\nTesting transport functions...\r\n");
    // uint8_t test_msg[] = {0xDE, 0xAD, 0xBE, 0xEF};
    // struct byte_array test_tx = {.ptr = test_msg, .len = sizeof(test_msg)};
    // enum err tx_result = tx_initiator(NULL, &test_tx);
    // kprintf("TX result: %d (0=ok)\r\n", tx_result);
    
    // uint8_t rx_buf[64];
    // struct byte_array test_rx = {.ptr = rx_buf, .len = sizeof(rx_buf)};
    // kprintf("RX: Waiting for message (10s timeout)...\r\n");
    // enum err rx_result = rx_initiator(NULL, &test_rx);
    // kprintf("RX result: %d (0=ok, 7=timeout)\r\n", rx_result);
    // if (rx_result == ok) {
    //     kprintf("RX: Got %d bytes: ", test_rx.len);
    //     for (uint32_t i = 0; i < test_rx.len && i < 16; i++) {
    //         kprintf("%x ", test_rx.ptr[i]);
    //     }
    //     kprintf("\r\n");
    // }
    
    // for (volatile int i = 0; i < 5000000; i++);
    
    // kprintf("\r\nStarting EDHOC testing...\r\n");
    
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
    

    kprintf("\r\n=== INITIATOR START ===\r\n");


    enum err result = edhoc_initiator_run(&ctx_i, &cred_r_array, &err_msg, &prk_out, tx_initiator, rx_initiator, ead_process);
    
    if (result != ok) {
        kprintf("FAIL: %d\r\n", result);
        while (1);
    }
    
    kprintf("OK! Key: ");
    for (uint32_t i = 0; i < 16; i++) kprintf("%x", prk_out.ptr[i]);
    kprintf("\r\n");
    
    while (1);
}

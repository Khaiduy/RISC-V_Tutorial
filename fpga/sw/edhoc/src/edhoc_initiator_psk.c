/* EDHOC Initiator - PSK Method 4 - Suite 0 */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "edhoc.h"
#include "edhoc_method_type.h"
#include "suites.h"
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
    kprintf("[I-TX] Sending %d bytes\r\n", data->len);
    uart1_putc((data->len >> 8) & 0xFF);
    uart1_putc(data->len & 0xFF);
    for (uint32_t i = 0; i < data->len; i++) {
        uart1_putc(data->ptr[i]);
        for (volatile int d = 0; d < 50000; d++);
    }
    kprintf("[I-TX] Done\r\n");
    return ok;
}

enum err rx_initiator(void *sock, struct byte_array *data) {
    int timeout = 1000000000, c;
    kprintf("[I-RX] Waiting...\r\n");
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
        kprintf("[I-RX] TIMEOUT\r\n");
        return transport_deinitialized;
    }
    uint32_t len = c << 8;
    timeout = 100000000;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
        kprintf("[I-RX] TIMEOUT len2\r\n");
        return transport_deinitialized;
    }
    len |= c;
    kprintf("[I-RX] Expecting %d bytes\r\n", len);
    if (len > data->len) {
        kprintf("[I-RX] Buffer too small\r\n");
        return buffer_to_small;
    }
    for (uint32_t i = 0; i < len; i++) {
        timeout = 100000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) {
            kprintf("[I-RX] TIMEOUT byte %d\r\n", i);
            return transport_deinitialized;
        }
        data->ptr[i] = c;
    }
    data->len = len;
    kprintf("[I-RX] Got %d bytes\r\n", len);
    return ok;
}

enum err ead_process(void *params, struct byte_array *ead) { return ok; }

// PSK - Pre-Shared Key (external PSK for testing)
// In production, this should be provisioned securely
static const uint8_t psk[] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

// PSK identifier - used to retrieve the correct PSK
static const uint8_t id_cred_psk[] = {0xa1,0x04,0x41,0x0f}; // {4: h'0f'}

// Credentials for PSK mode - CWT Claims Set format
// CRED_I: Initiator credential
static const uint8_t cred_i[] = {
    0xa2, // map(2)
    0x02, 0x78, 0x18, // sub: "42-50-31-FF-EF-37-32-39"
    0x34,0x32,0x2d,0x35,0x30,0x2d,0x33,0x31,0x2d,
    0x46,0x46,0x2d,0x45,0x46,0x2d,0x33,0x37,0x2d,
    0x33,0x32,0x2d,0x33,0x39,
    0x08, 0xa1, // cnf: map(1)
    0x01, 0xa2, // COSE_Key: map(2)
    0x01, 0x04, // kty: 4 (Symmetric)
    0x02, 0x41, 0x0f // kid: h'0f'
};

// CRED_R: Responder credential
static const uint8_t cred_r[] = {
    0xa2, // map(2)
    0x02, 0x77, // sub: "23-11-58-AA-B3-7F-10"
    0x32,0x33,0x2d,0x31,0x31,0x2d,0x35,0x38,0x2d,
    0x41,0x41,0x2d,0x42,0x33,0x2d,0x37,0x46,0x2d,
    0x31,0x30,
    0x08, 0xa1, // cnf: map(1)
    0x01, 0xa2, // COSE_Key: map(2)
    0x01, 0x04, // kty: 4 (Symmetric)
    0x02, 0x41, 0x0f // kid: h'0f'
};

// Ephemeral key generation using software X25519
static const uint8_t x_priv[] = {
    0x89,0x2e,0xc2,0x8e,0x5c,0xb6,0x66,0x91,
    0x08,0x47,0x05,0x39,0x50,0x0b,0x70,0x5c,
    0x90,0xce,0xdb,0xd0,0xa9,0x9e,0x12,0xb0,
    0x59,0x2e,0x81,0x4f,0x2a,0xd9,0xc9,0x61
};

static uint8_t g_x[32]; // Ephemeral public key

// Connection identifiers
static const uint8_t c_i[] = {0x0a}; // Connection ID = 10
static const uint8_t suites[] = {0x00}; // Suite 0 for PSK mode

static void generate_public_key(const uint8_t *priv_key, uint8_t *pub_key) {
    extern void c25519_smult(uint8_t *result, const uint8_t *q, const uint8_t *e);
    extern const uint8_t c25519_base_x[32];
    c25519_smult(pub_key, c25519_base_x, priv_key);
}

int main(void) {
    kprintf("\r\n=== EDHOC Initiator - PSK Mode (Method 4) ===\r\n");
    kprintf("Cipher Suite: 0 (AES-CCM-16-64-128, SHA-256, X25519)\r\n");
    
    // Generate ephemeral public key
    kprintf("Generating ephemeral key G_X from X...\r\n");
    generate_public_key(x_priv, g_x);
    kprintf("G_X generated: ");
    for (int i = 0; i < 32; i++) kprintf("%02x", g_x[i]);
    kprintf("\r\n");

    // Initialize initiator context for PSK mode
    struct edhoc_initiator_context init_ctx = {0};
    
    // Ephemeral keys
    uint8_t x_buf[32];
    memcpy(x_buf, x_priv, 32);
    init_ctx.x.ptr = x_buf;
    init_ctx.x.len = 32;
    init_ctx.g_x.ptr = g_x;
    init_ctx.g_x.len = 32;
    
    // Connection identifier
    uint8_t c_i_buf[1];
    memcpy(c_i_buf, c_i, 1);
    init_ctx.c_i.ptr = c_i_buf;
    init_ctx.c_i.len = 1;
    
    // Method 4 = PSK
    init_ctx.method = INITIATOR_PSK_RESPONDER_PSK;
    
    // Cipher suites
    uint8_t suites_buf[1];
    memcpy(suites_buf, suites, 1);
    init_ctx.suites_i.ptr = suites_buf;
    init_ctx.suites_i.len = 1;
    
    // PSK and ID_CRED_PSK
    uint8_t psk_buf[16];
    memcpy(psk_buf, psk, 16);
    init_ctx.psk.ptr = psk_buf;
    init_ctx.psk.len = 16;
    
    uint8_t id_cred_psk_buf[4];
    memcpy(id_cred_psk_buf, id_cred_psk, 4);
    init_ctx.id_cred_psk.ptr = id_cred_psk_buf;
    init_ctx.id_cred_psk.len = 4;
    
    // For PSK mode, id_cred_i should point to id_cred_psk
    init_ctx.id_cred_i.ptr = id_cred_psk_buf;
    init_ctx.id_cred_i.len = 4;
    
    // Credentials
    uint8_t cred_i_buf[sizeof(cred_i)];
    memcpy(cred_i_buf, cred_i, sizeof(cred_i));
    init_ctx.cred_i.ptr = cred_i_buf;
    init_ctx.cred_i.len = sizeof(cred_i);
    
    // EAD (no external authorization data)
    init_ctx.ead_1.len = 0;
    init_ctx.ead_3.len = 0;
    
    // Socket handler
    init_ctx.sock = NULL;
    
    kprintf("\r\n--- Starting EDHOC PSK handshake ---\r\n");
    
    // Prepare credential array for responder
    struct other_party_cred responder_cred = {0};
    responder_cred.id_cred.ptr = (uint8_t*)id_cred_psk;
    responder_cred.id_cred.len = sizeof(id_cred_psk);
    responder_cred.cred.ptr = (uint8_t*)cred_r;
    responder_cred.cred.len = sizeof(cred_r);
    
    struct cred_array cred_r_array = {0};
    cred_r_array.len = 1;
    cred_r_array.ptr = &responder_cred;
    
    // Buffers for output
    uint8_t err_msg_buf[128] = {0};
    struct byte_array err_msg = {.ptr = err_msg_buf, .len = sizeof(err_msg_buf)};
    
    uint8_t prk_out_buf[32] = {0};
    struct byte_array prk_out = {.ptr = prk_out_buf, .len = sizeof(prk_out_buf)};
    
    // Perform EDHOC handshake
    enum err r = edhoc_initiator_run(&init_ctx, &cred_r_array, &err_msg,
                                      &prk_out, &tx_initiator, &rx_initiator,
                                      &ead_process);
    
    if (r == ok) {
        kprintf("\r\n=== EDHOC PSK HANDSHAKE SUCCESS ===\r\n");
        kprintf("PRK_out established - secure session ready!\r\n");
        kprintf("PRK_out: ");
        for (uint32_t i = 0; i < prk_out.len; i++) {
            kprintf("%02x", prk_out.ptr[i]);
        }
        kprintf("\r\n");
    } else {
        kprintf("\r\n=== EDHOC PSK HANDSHAKE FAILED ===\r\n");
        kprintf("Error code: %d\r\n", r);
        if (err_msg.len > 0) {
            kprintf("Error message: %s\r\n", err_msg.ptr);
        }
    }
    
    while (1);
    return 0;
}

/**
 * @file edhoc_hw_initiator.c
 * @brief EDHOC Initiator using Hardware Accelerator
 *
 * Hardware-accelerated EDHOC initiator for PSK Mode (Method 4)
 * Cipher Suite 7: X25519, ASCON-AEAD-128, ASCON-Hash-256
 */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "edhoc_hw.h"
#include <stdio.h>

/* Read cycle counter for timing */
static inline uint64_t read_cycles(void) {
    uint64_t cycles;
    asm volatile ("rdcycle %0" : "=r" (cycles));
    return cycles;
}

/* UART1 for communication with responder */
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

/* Send message via UART */
static int tx_msg(const uint8_t *data, uint8_t len) {
    // kprintf("[I-TX] Sending %d bytes\r\n", len);
    uart1_putc(0x00);           /* High byte of length */
    uart1_putc(len);            /* Low byte of length */
    for (int i = 0; i < len; i++) {
        uart1_putc(data[i]);
        /* Small delay for UART timing */
        for (volatile int d = 0; d < 50000; d++);
    }
    // kprintf("[I-TX] Done\r\n");
    return 0;
}

/* Receive message via UART */
static int rx_msg(uint8_t *data, uint8_t *len, uint8_t max_len) {
    int timeout = 1000000000, c;
    // kprintf("[I-RX] Waiting...\r\n");
    
    /* Read length (2 bytes) */
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
        kprintf("[I-RX] TIMEOUT\r\n");
        return -1;
    }
    uint16_t msg_len = c << 8;
    
    timeout = 100000000;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
        kprintf("[I-RX] TIMEOUT len2\r\n");
        return -1;
    }
    msg_len |= c;
    
    // kprintf("[I-RX] Expecting %d bytes\r\n", msg_len);
    
    if (msg_len > max_len) {
        kprintf("[I-RX] Buffer too small\r\n");
        return -1;
    }
    
    /* Read data */
    for (int i = 0; i < msg_len; i++) {
        timeout = 100000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) {
            kprintf("[I-RX] TIMEOUT byte %d\r\n", i);
            return -1;
        }
        data[i] = c;
    }
    
    *len = msg_len;
    // kprintf("[I-RX] Got %d bytes\r\n", msg_len);
    return 0;
}

/* Print hex buffer */
static void print_hex(const char *label, const uint8_t *data, int len) {
    kprintf("%s: ", label);
    for (int i = 0; i < len; i++) {
        kprintf("%hx", data[i]);
    }
    kprintf("\r\n");
}

/* ========================================================================== */
/* Test Data - Matching Hardware Testbench                                    */
/* ========================================================================== */

/* Initiator private ephemeral key X_I (from tb_edhoc_continuous.v) */
static const uint8_t X_I[32] = {
    0x19, 0x2e, 0xc2, 0x8e, 0x5c, 0x77, 0x66, 0x91,
    0x08, 0x45, 0x05, 0x39, 0x50, 0x0b, 0x70, 0x5c,
    0x90, 0xce, 0xd5, 0xd0, 0x56, 0xab, 0x42, 0xb0,
    0xab, 0xbb, 0x81, 0xff, 0x89, 0xc8, 0xcb, 0x61
};

/* Initiator identity (8 bytes) */
static const uint8_t ID_I[8] = {'i', 'n', 'i', 't', 'i', 'a', 't', 'r'};

/* Responder identity (8 bytes) */
static const uint8_t ID_R[8] = {'r', 'e', 's', 'p', 'o', 'n', 'd', 'r'};

int main(void) {

    REG32(uart, UART_REG_DIV) = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV) = 868;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;


    void *hw_base = (void *)EDHOC_CTRL_ADDR;
    edhoc_params_t params;
    uint8_t msg1[40], msg2[40], msg3[24], msg4[20];
    uint8_t msg1_len, msg2_len, msg3_len, msg4_len;
    int ret;
    
    /* Timing measurements - start and end for each phase */
    // uint64_t t_init_start = 0, t_init_end = 0;
    // uint64_t t_msg1_start = 0, t_msg1_end = 0;
    // uint64_t t_msg2_start = 0, t_msg2_end = 0;
    // uint64_t t_msg3_start = 0, t_msg3_end = 0;
    // uint64_t t_msg4_start = 0, t_msg4_end = 0;
    // uint64_t t_oscore_start = 0, t_oscore_end = 0;

    kprintf("\r\n");
    kprintf("\r\n");
    kprintf("\r\n");
    // kprintf("=====================================================\r\n");
    kprintf("  EDHOC Hardware-Accelerated Initiator\r\n");
    kprintf("\r\n");
    // kprintf("  Method: PSK (4)\r\n");
    // kprintf("  Suite: 7 (X25519, ASCON-AEAD-128, ASCON-Hash-256)\r\n");
    // kprintf("=====================================================\r\n");
    
    // /* Run self-test */
    // edhoc_hw_selftest(hw_base);
    
    /* Initialize parameters */
    memset(&params, 0, sizeof(params));
    /* Use fixed ephemeral key in bypass mode */
    memcpy(params.ephemeral_key, X_I, 32);
    params.c_x = EDHOC_C_I_DEFAULT;           /* C_I = 0x2D */
    params.method = EDHOC_METHOD_PSK;          /* Method 4 */
    params.suite = EDHOC_SUITE_ASCON;          /* Suite 7 */
    params.id_cred_psk = 0x32;                 /* PSK ID */
    params.kid_initiator = 0x32;               /* KID_I */
    params.kid_responder = 0x33;               /* KID_R */
    memcpy(params.id_initiator, ID_I, 8);
    memcpy(params.id_responder, ID_R, 8);
    
    // kprintf("\r\n--- Initializing EDHOC Hardware ---\r\n");
    // print_hex("Ephemeral Key X_I", params.ephemeral_key, 32);
    /* Start timing */
    // t_init_start = read_cycles();
    
    /* Reset hardware first */
    edhoc_hw_reset(hw_base);
    
    /* ===== XDRBG+TRNG MODE - Generate ephemeral key from TRNG ===== */
    kprintf("\r\n--- XDRBG+TRNG mode (hardware-generated key) ---\r\n");
    /* Set TRNG_CONTROL=0x01: xdrbg_bypass=0, trng_en=1
     * This tells hardware to collect TRNG entropy and generate key via XDRBG
     * IMPORTANT: Must set AFTER reset and BEFORE edhoc_hw_init() */
    _REG32(hw_base, EDHOC_REG_TRNG_CONTROL) = EDHOC_TRNG_EN;
    uint32_t trng_ctrl = _REG32(hw_base, EDHOC_REG_TRNG_CONTROL);
    kprintf("Using TRNG+XDRBG (TRNG_CTRL=0x%lx)\r\n", trng_ctrl);
    kprintf("Ephemeral key will be generated by hardware\r\n");
    
    /* Initialize hardware */
    edhoc_hw_init(hw_base, &params);
    
    /* Start as initiator */
    // kprintf("\r\n--- Starting EDHOC Protocol as Initiator ---\r\n");
    edhoc_hw_start_initiator(hw_base);
    
    /* ===== MSG1: Initiator -> Responder ===== */
    // kprintf("\r\n[MSG1] Waiting for output...\r\n");
    ret = edhoc_hw_wait_output_valid(hw_base);
    if (ret < 0) {
        kprintf("ERROR: MSG1 output not valid\r\n");
        goto error;
    }
    
    edhoc_hw_read_data_out(hw_base, msg1, &msg1_len);
    // t_msg1_end = read_cycles();
    
    /* Disable TRNG immediately after key generation completes
     * Ephemeral key X_I has been generated and stored in hardware.
     * Keeping TRNG enabled wastes power - ring oscillators consume ~mW */
    if (_REG32(hw_base, EDHOC_REG_TRNG_CONTROL) & EDHOC_TRNG_EN) {
        _REG32(hw_base, EDHOC_REG_TRNG_CONTROL) = 0x00;
        kprintf("TRNG disabled after key generation (power save)\r\n");
    }
    
    print_hex("MSG1", msg1, msg1_len);
    
    /* Send MSG1 via UART */
    kprintf("[MSG1] Sending to responder...\r\n");
    tx_msg(msg1, msg1_len);
    
    /* ===== MSG2: Responder -> Initiator ===== */
    // kprintf("\r\n[MSG2] Waiting for ready...\r\n");
    ret = edhoc_hw_wait_msg_ready(hw_base);
    if (ret < 0) {
        kprintf("ERROR: Not ready for MSG2\r\n");
        goto error;
    }
    
    /* Receive MSG2 via UART */
    kprintf("[MSG2] Waiting for responder...\r\n");
    ret = rx_msg(msg2, &msg2_len, sizeof(msg2));
    if (ret < 0) {
        kprintf("ERROR: Failed to receive MSG2\r\n");
        goto error;
    }
    
    print_hex("MSG2", msg2, msg2_len);
    
    /* Write MSG2 to hardware */
    // t_msg2_start = read_cycles();
    edhoc_hw_write_data_in(hw_base, msg2, msg2_len);
    edhoc_hw_set_msg_valid(hw_base);
    
    /* ===== MSG3: Initiator -> Responder ===== */
    // kprintf("\r\n[MSG3] Waiting for output...\r\n");
    /* Poll status to see OUTPUT_VALID appear */
    unsigned long timeout = 100000;
    uint32_t status;
    int saw_output_valid = 0;
    
    do {
        status = _REG32(hw_base, EDHOC_REG_STATUS);
        if (status & EDHOC_STATUS_OUTPUT_VALID) {
            saw_output_valid = 1;
            kprintf("[MSG3] OUTPUT_VALID set, status=0x%lx\r\n", status);
            break;
        }
        if (status & EDHOC_STATUS_ERROR) {
            kprintf("[MSG3] ERROR flag set, status=0x%lx\r\n", status);
            goto error;
        }
        timeout--;
    } while (timeout > 0);
    
    if (!saw_output_valid) {
        kprintf("[MSG3] OUTPUT_VALID never set, final status=0x%lx\r\n", status);
        goto error;
    }
    
    edhoc_hw_read_data_out(hw_base, msg3, &msg3_len);
    // t_msg3_end = read_cycles();
    print_hex("MSG3", msg3, msg3_len);
    
    /* Send MSG3 via UART */
    // kprintf("[MSG3] Sending to responder...\r\n");
    tx_msg(msg3, msg3_len);
    
    /* ===== MSG4: Responder -> Initiator ===== */
    // kprintf("\r\n[MSG4] Waiting for ready...\r\n");
    ret = edhoc_hw_wait_msg_ready(hw_base);
    if (ret < 0) {
        kprintf("ERROR: Not ready for MSG4\r\n");
        goto error;
    }
    
    /* Receive MSG4 via UART */
    // kprintf("[MSG4] Waiting for responder...\r\n");
    ret = rx_msg(msg4, &msg4_len, sizeof(msg4));
    if (ret < 0) {
        kprintf("ERROR: Failed to receive MSG4\r\n");
        goto error;
    }
    print_hex("MSG4", msg4, msg4_len);
    
    /* Write MSG4 to hardware */
    // t_msg4_start = read_cycles();
    edhoc_hw_write_data_in(hw_base, msg4, msg4_len);
    edhoc_hw_set_msg_valid(hw_base);
    
    /* ===== Wait for Protocol Completion ===== */
    // kprintf("\r\n--- Waiting for EDHOC completion ---\r\n");
    ret = edhoc_hw_wait_done(hw_base);
    if (ret < 0) {
        kprintf("ERROR: EDHOC protocol failed\r\n");
        goto error;
    }
    
    /* Check OSCORE keys */
    if (!edhoc_hw_oscore_keys_valid(hw_base)) {
        kprintf("ERROR: OSCORE keys not valid\r\n");
        goto error;
    }
    
    // t_oscore_end = read_cycles();
    
    // kprintf("\r\n");
    // kprintf("=====================================================\r\n");
    kprintf("  EDHOC HANDSHAKE SUCCESS!\r\n");
    // kprintf("=====================================================\r\n");
    // edhoc_hw_print_context(&oscore_ctx);
    
    /* Print timing results */
    // kprintf("\r\n--- Hardware Computation Time (cycles) ---\r\n");
    // kprintf("MSG1 generation: %lu\r\n", (unsigned long)(t_msg1_end - t_init_start));
    // kprintf("MSG2 processing: %lu\r\n", (unsigned long)(t_msg3_end - t_msg2_start));
    // kprintf("MSG4 processing: %lu\r\n", (unsigned long)(t_oscore_end - t_msg4_start));
    // kprintf("TOTAL calculation time:           %lu\r\n", (unsigned long)(t_msg1_end - t_init_start + t_msg3_end - t_msg2_start + t_oscore_end - t_msg4_start));
    // kprintf("------------------------------------------\r\n");
    // kprintf("=====================================================\r\n");
    // edhoc_hw_print_context(&oscore_ctx);
    
    // kprintf("\r\n--- Ready for OSCORE-protected communication ---\r\n");
    // kprintf("(All keys remain internal to hardware)\r\n");
    
    /* Continuous message exchange loop */
    // kprintf("\r\n--- Starting Continuous OSCORE Communication ---\r\n");
    
    /* Initialize AEAD parameters and variables */
    aead_params_t aead_params = {0};
    aead_result_t aead_result;
    uint8_t sender_id = params.kid_initiator;  /* Use Initiator's kid */
    uint32_t seq_num = 0;  /* Sequence number starts at 0 */
    
    /* Set sender_id for nonce construction */
    aead_params.sender_id = sender_id;
    aead_params.data_len = 12;
    aead_params.use_sender_key = 1;  /* Use sender key for encryption */
    
    /* Construct AAD template (will update PIV for each message) */
    memset(aead_params.aad, 0x00, 16);
    aead_params.aad[0] = 0x01;  /* OSCORE version 1 */
    aead_params.aad[1] = 0x18;  /* Algorithm: 24 (ASCON) */
    aead_params.aad[2] = 0x01;  /* KID length = 1 */
    aead_params.aad[3] = sender_id;  /* KID value */
    aead_params.aad[4] = 0x05;  /* PIV length = 5 */
    aead_params.aad_len = 10;
    
    while (1) {
        /* Wait a bit before sending next message */
        for (volatile long d = 0; d < 10000000; d++);
        
        /* Update partial_iv with current sequence number */
        aead_params.partial_iv[0] = 0;
        aead_params.partial_iv[1] = 0;
        aead_params.partial_iv[2] = 0;
        aead_params.partial_iv[3] = (seq_num >> 8) & 0xFF;
        aead_params.partial_iv[4] = seq_num & 0xFF;
        
        /* Update AAD with new PIV */
        memcpy(&aead_params.aad[5], aead_params.partial_iv, 5);
        
        /* Create message with sequence number - fill all 12 bytes */
        memset(aead_params.data_in, ' ', 12);  /* Fill with spaces */
        aead_params.data_in[0] = 'M';
        aead_params.data_in[1] = 's';
        aead_params.data_in[2] = 'g';
        aead_params.data_in[3] = ' ';
        
        /* Convert seq_num to string at the end (right-aligned) */
        uint32_t n = seq_num;
        int pos = 11;
        if (n == 0) {
            aead_params.data_in[pos] = '0';
        } else {
            while (n > 0 && pos >= 4) {
                aead_params.data_in[pos--] = '0' + (n % 10);
                n /= 10;
            }
        }
        
        kprintf("[I] Sending: ");
        for (int i = 0; i < 12; i++) {
            kprintf("%c", aead_params.data_in[i]);
        }
        kprintf("\r\n");
        /* Debug: print hex */
        // kprintf("    Hex: ");
        // for (int i = 0; i < 12; i++) {
        //     kprintf("%hx", aead_params.data_in[i]);
        // }
        // kprintf("\r\n");
        
        /* Encrypt */
        ret = edhoc_hw_aead_encrypt(hw_base, &aead_params, &aead_result);
        if (ret != 0) {
            kprintf("ERROR: Encrypt failed\r\n");
            break;
        }
        
        /* Build and send OSCORE packet */
        uint8_t oscore_msg[35];
        oscore_msg[0] = sender_id;
        oscore_msg[1] = 5;
        memcpy(oscore_msg + 2, aead_params.partial_iv, 5);
        memcpy(oscore_msg + 7, aead_result.data_out, 12);
        memcpy(oscore_msg + 19, aead_result.tag, 16);
        
        tx_msg(oscore_msg, 35);
        
        seq_num++;
    }
    
    return 0;
    
error:
    kprintf("\r\n=== EDHOC HANDSHAKE FAILED ===\r\n");
    while (1);
    return -1;
}

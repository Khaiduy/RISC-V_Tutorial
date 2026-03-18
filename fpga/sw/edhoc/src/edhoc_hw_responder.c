/**
 * @file edhoc_hw_responder.c
 * @brief EDHOC Responder using Hardware Accelerator
 *
 * Hardware-accelerated EDHOC responder for PSK Mode (Method 4)
 * Cipher Suite 7: X25519, ASCON-AEAD-128, ASCON-Hash-256
 */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "edhoc_hw.h"

/* Read cycle counter for timing */
static inline uint64_t read_cycles(void) {
    uint64_t cycles;
    asm volatile ("rdcycle %0" : "=r" (cycles));
    return cycles;
}

/* UART1 for communication with initiator */
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
    // kprintf("[R-TX] Sending %d bytes\r\n", len);
    uart1_putc(0x00);           /* High byte of length */
    uart1_putc(len);            /* Low byte of length */
    for (int i = 0; i < len; i++) {
        uart1_putc(data[i]);
        /* Small delay for UART timing */
        for (volatile int d = 0; d < 50000; d++);
    }
    // kprintf("[R-TX] Done\r\n");
    return 0;
}

/* Receive message via UART */
static int rx_msg(uint8_t *data, uint8_t *len, uint8_t max_len) {
    int timeout = 1000000000, c;
    // kprintf("[R-RX] Waiting...\r\n");
    
    /* Read length (2 bytes) */
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
        kprintf("[R-RX] TIMEOUT\r\n");
        return -1;
    }
    uint16_t msg_len = c << 8;
    
    timeout = 100000000;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
        kprintf("[R-RX] TIMEOUT len2\r\n");
        return -1;
    }
    msg_len |= c;
    
    // kprintf("[R-RX] Expecting %d bytes\r\n", msg_len);
    
    if (msg_len > max_len) {
        kprintf("[R-RX] Buffer too small\r\n");
        return -1;
    }
    
    /* Read data */
    for (int i = 0; i < msg_len; i++) {
        timeout = 100000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) {
            kprintf("[R-RX] TIMEOUT byte %d\r\n", i);
            return -1;
        }
        data[i] = c;
    }
    
    *len = msg_len;
    // kprintf("[R-RX] Got %d bytes\r\n", msg_len);
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

/* Responder private ephemeral key Y_R (from tb_edhoc_continuous.v) */
static const uint8_t Y_R[32] = {
    0xd3, 0x7e, 0x12, 0xfe, 0xbb, 0x5d, 0x8b, 0x45,
    0x54, 0x51, 0xb3, 0xeb, 0x21, 0x7d, 0xb4, 0xeb,
    0xb3, 0x19, 0xae, 0xca, 0xd5, 0xfb, 0xf7, 0xae,
    0xb3, 0xcf, 0x9a, 0x05, 0xf2, 0x90, 0x00, 0x48
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
    kprintf("  EDHOC Hardware-Accelerated Responder\r\n");
    kprintf("\r\n");
    // kprintf("  Method: PSK (4)\r\n");
    // kprintf("  Suite: 7 (X25519, ASCON-AEAD-128, ASCON-Hash-256)\r\n");
    // kprintf("=====================================================\r\n");
    
    /* Run self-test */
    // edhoc_hw_selftest(hw_base);
    
    /* Initialize parameters */
    memset(&params, 0, sizeof(params));
    /* Use fixed ephemeral key in bypass mode */
    memcpy(params.ephemeral_key, Y_R, 32);
    params.c_x = EDHOC_C_R_DEFAULT;           /* C_R = 0x0E */
    params.method = EDHOC_METHOD_PSK;          /* Method 4 */
    params.suite = EDHOC_SUITE_ASCON;          /* Suite 7 */
    params.id_cred_psk = 0x32;                 /* PSK ID */
    params.kid_initiator = 0x32;               /* KID_I */
    params.kid_responder = 0x33;               /* KID_R */
    memcpy(params.id_initiator, ID_I, 8);
    memcpy(params.id_responder, ID_R, 8);
    
    // kprintf("\r\n--- Initializing EDHOC Hardware ---\r\n");
    // print_hex("Ephemeral Key Y_R", params.ephemeral_key, 32);
    // kprintf("C_R: 0x%hx, Method: %hx, Suite: %d\r\n", 
    //         params.c_x, params.method, params.suite);

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
    
    /* Start as responder */
    // kprintf("\r\n--- Starting EDHOC Protocol as Responder ---\r\n");
    edhoc_hw_start_responder(hw_base);
    
    /* ===== MSG1: Initiator -> Responder ===== */
    // kprintf("\r\n[MSG1] Waiting for ready...\r\n");
    ret = edhoc_hw_wait_msg_ready(hw_base);
    if (ret < 0) {
        kprintf("ERROR: Not ready for MSG1\r\n");
        goto error;
    }
    // t_init_end = read_cycles();

    /* Receive MSG1 via UART */
    // kprintf("[MSG1] Waiting for initiator...\r\n");
    ret = rx_msg(msg1, &msg1_len, sizeof(msg1));
    if (ret < 0) {
        kprintf("ERROR: Failed to receive MSG1\r\n");
        goto error;
    }
    print_hex("MSG1", msg1, msg1_len);
    // kprintf("msg1_len:%hx\r\n", msg1_len);

    
    /* Write MSG1 to hardware */
    // t_msg1_start = read_cycles();
    edhoc_hw_write_data_in(hw_base, msg1, msg1_len);
    edhoc_hw_set_msg_valid(hw_base);
    
    /* ===== MSG2: Responder -> Initiator ===== */
    // kprintf("\r\n[MSG2] Waiting for output...\r\n");
    /* Poll status to see OUTPUT_VALID appear */
    unsigned long timeout = 100000;
    uint32_t status;
    int saw_output_valid = 0;
    
    do {
        status = _REG32(hw_base, EDHOC_REG_STATUS);
        if (status & EDHOC_STATUS_OUTPUT_VALID) {
            saw_output_valid = 1;
            kprintf("[MSG2] OUTPUT_VALID set, status=0x%lx\r\n", status);
            break;
        }
        if (status & EDHOC_STATUS_ERROR) {
            kprintf("[MSG2] ERROR flag set, status=0x%lx\r\n", status);
            goto error;
        }
        timeout--;
    } while (timeout > 0);
    
    if (!saw_output_valid) {
        kprintf("[MSG2] OUTPUT_VALID never set, final status=0x%lx\r\n", status);
        goto error;
    }
    
    edhoc_hw_read_data_out(hw_base, msg2, &msg2_len);
    // t_msg2_end = read_cycles();
    
    /* Disable TRNG immediately after key generation completes
     * Ephemeral key Y_R has been generated and stored in hardware.
     * Keeping TRNG enabled wastes power - ring oscillators consume ~mW */
    if (_REG32(hw_base, EDHOC_REG_TRNG_CONTROL) & EDHOC_TRNG_EN) {
        _REG32(hw_base, EDHOC_REG_TRNG_CONTROL) = 0x00;
        kprintf("TRNG disabled after key generation (power save)\r\n");
    }
    
    print_hex("MSG2", msg2, msg2_len);
    
    /* Send MSG2 via UART */
    // kprintf("[MSG2] Sending to initiator...\r\n");
    tx_msg(msg2, msg2_len);
    
    /* ===== MSG3: Initiator -> Responder ===== */
    // kprintf("\r\n[MSG3] Waiting for ready...\r\n");
    ret = edhoc_hw_wait_msg_ready(hw_base);
    if (ret < 0) {
        kprintf("ERROR: Not ready for MSG3\r\n");
        goto error;
    }
    
    /* Receive MSG3 via UART */
    // kprintf("[MSG3] Waiting for initiator...\r\n");
    ret = rx_msg(msg3, &msg3_len, sizeof(msg3));
    if (ret < 0) {
        kprintf("ERROR: Failed to receive MSG3\r\n");
        goto error;
    }
    print_hex("MSG3", msg3, msg3_len);
    
    /* Write MSG3 to hardware */
    // t_msg3_start = read_cycles();
    edhoc_hw_write_data_in(hw_base, msg3, msg3_len);
    edhoc_hw_set_msg_valid(hw_base);
    
    /* ===== MSG4: Responder -> Initiator ===== */
    // kprintf("\r\n[MSG4] Waiting for output...\r\n");
    ret = edhoc_hw_wait_output_valid(hw_base);
    if (ret < 0) {
        kprintf("ERROR: MSG4 output not valid\r\n");
        goto error;
    }
    else kprintf("delay longer\r\n");

    edhoc_hw_read_data_out(hw_base, msg4, &msg4_len);
    // t_msg4_end = read_cycles();

    
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
    
    /* Mark OSCORE context ready (keys stay internal to hardware) */
    // t_oscore_end = read_cycles();

    print_hex("MSG4", msg4, msg4_len);
    
    /* Send MSG4 via UART */
    // kprintf("[MSG4] Sending to initiator...\r\n");
    tx_msg(msg4, msg4_len);

    // kprintf("\r\n");
    // kprintf("====================================================="\r\n");
    kprintf("  EDHOC HANDSHAKE SUCCESS!\r\n");
    // kprintf("====================================================="\r\n");
    
    /* Print timing results */
    
    // kprintf("\r\n--- Hardware Computation Time (cycles) ---\r\n");
    // kprintf("MSG1 processing: %lu\r\n", (unsigned long)(t_msg2_end - t_msg1_start));
    // kprintf("MSG3 processing: %lu\r\n", (unsigned long)(t_msg4_end - t_msg3_start));
    // kprintf("OSCORE final:    %lu\r\n", (unsigned long)(t_oscore_end - t_msg4_end));
    // kprintf("TOTAL calculation time:           %lu\r\n", (unsigned long)(t_msg2_end - t_msg1_start + t_msg4_end - t_msg3_start + t_oscore_end - t_msg4_end));
    // kprintf("------------------------------------------\r\n");
    
    // kprintf("\r\n--- Ready for OSCORE-protected communication ---\r\n");
    // kprintf("(All keys remain internal to hardware)\r\n");
    
    /* Continuous message reception loop */
    // kprintf("\r\n--- Starting Continuous OSCORE Communication ---\r\n");
    
    /* Variables for OSCORE message processing */
    uint8_t oscore_msg[40];
    uint8_t oscore_len;
    uint8_t sender_id, piv_len;
    uint8_t partial_iv[5];
    int hdr_len, ct_len;
    aead_params_t aead_params;
    aead_result_t aead_result;
    
    while (1) {
        /* Receive OSCORE message */
        ret = rx_msg(oscore_msg, &oscore_len, sizeof(oscore_msg));
        if (ret < 0) {
            kprintf("ERROR: RX failed\r\n");
            continue;
        }
        
        if (oscore_len < 7) {
            kprintf("ERROR: Message too short\r\n");
            continue;
        }
        
        /* Parse OSCORE message */
        sender_id = oscore_msg[0];
        piv_len = oscore_msg[1];
        
        if (piv_len > 5) {
            kprintf("ERROR: Invalid PIV\r\n");
            continue;
        }
        
        /* Extract partial_iv */
        memset(partial_iv, 0, 5);
        memcpy(partial_iv + (5 - piv_len), oscore_msg + 2, piv_len);
        
        /* Calculate lengths */
        hdr_len = 2 + piv_len;
        ct_len = oscore_len - hdr_len - 16;
        
        if (ct_len <= 0 || ct_len > 16) {
            kprintf("ERROR: Invalid length\r\n");
            continue;
        }
        
        /* Set up AEAD for decryption */
        memset(&aead_params, 0, sizeof(aead_params));
        aead_params.sender_id = sender_id;  /* Use sender_id from OSCORE packet (initiator's kid) for nonce */
        memcpy(aead_params.partial_iv, partial_iv, 5);
        
        /* Construct AAD */
        memset(aead_params.aad, 0x00, 16);
        aead_params.aad[0] = 0x01;
        aead_params.aad[1] = 0x18;
        aead_params.aad[2] = 0x01;
        aead_params.aad[3] = sender_id;
        aead_params.aad[4] = 0x05;
        memcpy(&aead_params.aad[5], partial_iv, 5);
        aead_params.aad_len = 10;
        
        /* Extract ciphertext and tag */
        memcpy(aead_params.data_in, oscore_msg + hdr_len, ct_len);
        memcpy(aead_params.exp_tag, oscore_msg + hdr_len + ct_len, 16);
        aead_params.data_len = ct_len;
        aead_params.use_sender_key = 0;  /* Use recipient key: responder's recipient key == initiator's sender key */
        
        /* Decrypt */
        ret = edhoc_hw_aead_decrypt(hw_base, &aead_params, &aead_result);
        if (ret == 0 && aead_result.tag_valid) {
            kprintf("[R] Received: ");
            for (int i = 0; i < ct_len; i++) {
                kprintf("%c", aead_result.data_out[i]);
            }
            kprintf("\r\n");
            // /* Debug: print hex */
            // kprintf("    Hex: ");
            // for (int i = 0; i < ct_len; i++) {
            //     kprintf("%hx", aead_result.data_out[i]);
            // }
            // kprintf("\r\n");
        } else {
            kprintf("ERROR: Decrypt failed\r\n");
        }
    }
    
    return 0;
    
error:
    kprintf("\r\n=== EDHOC HANDSHAKE FAILED ===\r\n");
    while (1);
    return -1;
}

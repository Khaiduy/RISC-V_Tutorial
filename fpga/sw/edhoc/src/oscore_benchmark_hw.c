/**
 * @file oscore_benchmark_hw.c
 * @brief OSCORE Hardware Benchmark — ext_aead encrypt/decrypt payload sweep
 *
 * Mirrors oscore_benchmark.c methodology but uses the edhoc_m3_top ext_aead
 * hardware accelerator (AES-CCM-16-64-128) instead of tinycrypt.
 *
 * Flow:
 *   1. Run full EDHOC M3 handshake with a responder peer (derives OSCORE keys
 *      into internal RF[6]=SEND_KEY, RF[7]=RECV_KEY)
 *   2. Sweep payload sizes: benchmark ext_aead encrypt and decrypt
 *   3. Print results in same table format as oscore_benchmark.c
 *
 * Hardware limits: data_in is 20 x 32-bit = 80 bytes. With 10-byte AAD
 * (3 words = 12 bytes slot), max message = 68 bytes. Sweep: 10, 20, 50, 68.
 * SW benchmark reaches 1000 bytes; HW is bounded by the register file size.
 *
 * Usage: flash edhoc_m3_responder_hw on peer board, then run this on initiator.
 *   make oscore_benchmark_hw
 */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "edhoc_m3_hw.h"

/* ========================================================================== */
/* UART1 for peer communication                                               */
/* ========================================================================== */
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

static inline void uart1_drain_rx(void) {
    while (uart1_getc() >= 0);
}

static int tx_msg(const uint8_t *data, uint8_t len) {
    uart1_putc(0x00);
    uart1_putc(len);
    for (int i = 0; i < len; i++) {
        uart1_putc(data[i]);
        for (volatile int d = 0; d < 50000; d++);
    }
    return 0;
}

static int rx_msg(uint8_t *data, uint8_t *len, uint8_t max_len) {
    int timeout, c;

    timeout = 1000000000;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) return -1;
    uint16_t msg_len = c << 8;

    timeout = 100000000;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) return -1;
    msg_len |= c;

    if (msg_len > max_len) return -1;

    for (int i = 0; i < msg_len; i++) {
        timeout = 100000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) return -1;
        data[i] = c;
    }
    *len = msg_len;
    return 0;
}

static void print_hex(const char *label, const uint8_t *data, int len) {
    kprintf("%s: ", label);
    for (int i = 0; i < len; i++)
        kprintf("%hx", data[i]);
    kprintf("\r\n");
}

/* ========================================================================== */
/* Credentials & Keys (same as edhoc_m3_initiator_hw.c)                       */
/* ========================================================================== */
static const uint8_t CRED_I[55] = {
    0xA2, 0x02, 0x66, 0x49, 0x6E, 0x69, 0x74, 0x4D,
    0x33, 0x08, 0xA1, 0x01, 0xA4, 0x01, 0x01, 0x02,
    0x41, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0xFD,
    0x33, 0x84, 0xE1, 0x32, 0xAD, 0x02, 0xA5, 0x6C,
    0x78, 0xF4, 0x55, 0x47, 0xEE, 0x40, 0x03, 0x8D,
    0xC7, 0x90, 0x02, 0xB9, 0x0D, 0x29, 0xED, 0x90,
    0xE0, 0x8E, 0xEE, 0x76, 0x2A, 0xE7, 0x15
};

static const uint8_t CRED_R[55] = {
    0xA2, 0x02, 0x66, 0x52, 0x65, 0x73, 0x70, 0x4D,
    0x33, 0x08, 0xA1, 0x01, 0xA4, 0x01, 0x01, 0x02,
    0x41, 0x02, 0x20, 0x04, 0x21, 0x58, 0x20, 0xAD,
    0x8C, 0x48, 0xC2, 0x67, 0x65, 0xAE, 0xA7, 0xAD,
    0xC5, 0x36, 0x28, 0x96, 0x05, 0xC1, 0xAB, 0xEA,
    0x95, 0x05, 0x00, 0x93, 0xDB, 0xD2, 0x18, 0xC9,
    0x6A, 0xBD, 0x24, 0x81, 0xA0, 0x35, 0x65
};

static const uint8_t STATIC_PRIV_I[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static const uint8_t EPH_PRIV_I[32] = {
    0x36, 0x8E, 0xC1, 0xF6, 0x9A, 0xEB, 0x65, 0x9B,
    0xA3, 0x7D, 0x5A, 0x8D, 0x45, 0xB2, 0x1B, 0xDC,
    0x02, 0x99, 0xDC, 0xEA, 0xA8, 0xEF, 0x23, 0x5F,
    0x3C, 0xA4, 0x2C, 0xE3, 0x53, 0x0F, 0x95, 0x25
};

#define C_I   0x2D
#define C_R   0x0E
#define KID_I 0x01
#define KID_R 0x02
#define OSCORE_TAG_LEN 8

#ifndef BENCHMARK_CPU_HZ
#define BENCHMARK_CPU_HZ 50000000UL
#endif

#define N_ITER 100

/* Payload sizes for sweep (HW data_in cap: 80 bytes; 68 bytes max payload) */
static const uint8_t SWEEP_SIZES[] = { 10, 20, 50, 68 };
#define NUM_SWEEPS ((int)(sizeof(SWEEP_SIZES) / sizeof(SWEEP_SIZES[0])))

/* ========================================================================== */
/* Benchmark helpers                                                          */
/* ========================================================================== */

/**
 * Write AAD + message to data_in (word-aligned).
 * AAD occupies ceil(aad_len/4) words, message starts at next word boundary.
 */
static void write_aad_msg(const uint8_t *aad, int aad_len,
                           const uint8_t *msg, int msg_len)
{
    int aad_words = (aad_len + 3) / 4;
    int msg_start = aad_words * 4;
    int total_bytes = msg_start + msg_len;
    int total_words = (total_bytes + 3) / 4;

    for (int w = 0; w < 20; w++) {
        uint32_t val = 0;
        if (w < total_words) {
            for (int b = 0; b < 4; b++) {
                int idx = w * 4 + b;
                uint8_t byte = 0;
                if (idx < aad_len)
                    byte = aad[idx];
                else if (idx >= msg_start && idx < msg_start + msg_len)
                    byte = msg[idx - msg_start];
                val |= ((uint32_t)byte) << ((3 - b) * 8);
            }
        }
        m3_write(M3_DATA_IN(w), val);
    }
}

/* ========================================================================== */
/* Main                                                                       */
/* ========================================================================== */
int main(void)
{
    REG32(uart, UART_REG_DIV) = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV) = 868;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;

    uint8_t msg_buf[48];
    uint8_t msg_len;
    int ret;
    uint32_t t0, t1;

    for (volatile long d = 0; d < 3000000; d++);
    kprintf("\r\n\r\n");
    kprintf("=== OSCORE Hardware Benchmark (ext_aead AES-CCM-16-64-128) ===\r\n");
    kprintf("CPU: %lu Hz,  N_ITER: %d\r\n", (unsigned long)BENCHMARK_CPU_HZ, N_ITER);
    kprintf("Running EDHOC M3 handshake to derive OSCORE keys...\r\n\r\n");

    /* ================================================================== */
    /* EDHOC M3 Handshake (same as edhoc_m3_initiator_hw.c)               */
    /* ================================================================== */
    m3_sw_reset();
    m3_write_key256(M3_EPH_PRIV(0), EPH_PRIV_I);
    m3_write_key256(M3_STATIC_PRIV(0), STATIC_PRIV_I);
    m3_write_cred(M3_CRED_OWN(0), CRED_I);
    m3_write_cred(M3_CRED_PEER(0), CRED_R);
    m3_set_params(KID_I, KID_R, C_I, C_R);
    m3_start_initiator();

    /* MSG1: wait → send */
    ret = m3_wait_msg_ready(500000);
    if (ret < 0) { kprintf("ERROR: MSG1 timeout\r\n"); goto error; }
    msg_len = m3_get_msg_len();
    m3_read_data_out(msg_buf, msg_len);
    print_hex("MSG1", msg_buf, msg_len);

    /* Sync with responder */
    uart1_drain_rx();
    { int sc, to = 500000000; do { sc = uart1_getc(); } while (sc < 0 && --to > 0);
      if (to == 0) { kprintf("ERROR: sync timeout\r\n"); goto error; } }

    tx_msg(msg_buf, msg_len);
    m3_output_ack(1);

    /* MSG2: wait → receive → feed HW */
    ret = m3_wait_waiting(500000);
    if (ret < 0) { kprintf("ERROR: not waiting for MSG2\r\n"); goto error; }
    ret = rx_msg(msg_buf, &msg_len, 48);
    if (ret < 0) { kprintf("ERROR: MSG2 rx\r\n"); goto error; }
    print_hex("MSG2", msg_buf, msg_len);
    m3_write_data_in(msg_buf, msg_len);
    m3_input_ready(1);

    /* MSG3: wait → send */
    ret = m3_wait_msg_ready(500000);
    if (ret < 0) { kprintf("ERROR: MSG3 timeout\r\n"); goto error; }
    msg_len = m3_get_msg_len();
    m3_read_data_out(msg_buf, msg_len);
    print_hex("MSG3", msg_buf, msg_len);
    tx_msg(msg_buf, msg_len);
    m3_output_ack(1);

    /* MSG4: wait → receive → feed HW → done */
    ret = m3_wait_waiting(500000);
    if (ret < 0) { kprintf("ERROR: not waiting for MSG4\r\n"); goto error; }
    ret = rx_msg(msg_buf, &msg_len, 48);
    if (ret < 0) { kprintf("ERROR: MSG4 rx\r\n"); goto error; }
    print_hex("MSG4", msg_buf, msg_len);
    m3_write_msg4_tag(msg_buf, msg_len);
    m3_input_ready(1);
    ret = m3_wait_done(5000000);
    if (ret < 0) { kprintf("ERROR: handshake timeout\r\n"); goto error; }

    if (m3_status() & M3_STATUS_ERROR) {
        kprintf("ERROR: EDHOC handshake failed (MAC verify error)\r\n");
        goto error;
    }
    kprintf("\r\n=== EDHOC handshake SUCCESS — OSCORE keys derived ===\r\n\r\n");

    /* ================================================================== */
    /* OSCORE Hardware Benchmark: ext_aead payload sweep                   */
    /* ================================================================== */
    uint8_t sender_id = C_R;   /* Initiator SEND_KEY uses cx=C_R */

    /* ── Encrypt sweep ── */
    kprintf("[HW-ENCRYPT] ext_aead encrypt (N=%d per size):\r\n", N_ITER);
    kprintf("Payload |   Avg Cycles |   Avg us\r\n");
    kprintf("--------|--------------|----------\r\n");

    for (int ps = 0; ps < NUM_SWEEPS; ps++) {
        uint8_t plen = SWEEP_SIZES[ps];

        /* Construct AAD (10 bytes, same format as OSCORE messaging) */
        uint8_t aad[10];
        aad[0] = 0x01; aad[1] = 0x0A; aad[2] = 0x01; aad[3] = sender_id;
        aad[4] = 0x05; aad[5] = 0; aad[6] = 0; aad[7] = 0; aad[8] = 0; aad[9] = 0;

        /* Construct plaintext (sequential bytes) */
        uint8_t plain[68];
        for (int j = 0; j < plen; j++)
            plain[j] = (uint8_t)(j & 0xFF);

        /* Write AAD + plaintext to data_in (once — HW reads on each start) */
        write_aad_msg(aad, 10, plain, plen);

        /* Benchmark N_ITER encrypt operations */
        uint32_t total = 0;
        for (int i = 0; i < N_ITER; i++) {
            t0 = read_mcycle();
            m3_ea_encrypt(sender_id, (uint32_t)i, 10, plen, OSCORE_TAG_LEN);
            m3_ea_wait_done(100000);
            t1 = read_mcycle();
            total += (t1 - t0);

            /* Rewrite data_in for next iteration (nonce changes via partial_iv,
             * but data_in content stays same — just need to re-trigger) */
            write_aad_msg(aad, 10, plain, plen);
        }
        uint32_t avg = total / N_ITER;
        uint32_t us  = (uint32_t)(((uint64_t)avg * 1000000ULL) / BENCHMARK_CPU_HZ);
        kprintf("  %5u  |  %10lu  |  %lu\r\n",
                (unsigned)plen, (unsigned long)avg, (unsigned long)us);
    }

    /* ── Decrypt sweep ── */
    kprintf("\r\n[HW-DECRYPT] ext_aead decrypt (N=%d per size):\r\n", N_ITER);
    kprintf("Payload |   Avg Cycles |   Avg us\r\n");
    kprintf("--------|--------------|----------\r\n");

    for (int ps = 0; ps < NUM_SWEEPS; ps++) {
        uint8_t plen = SWEEP_SIZES[ps];

        /* For decrypt benchmark, first encrypt to get valid CT+tag,
         * then benchmark decrypt with recipient key */
        uint8_t aad[10];
        aad[0] = 0x01; aad[1] = 0x0A; aad[2] = 0x01; aad[3] = sender_id;
        aad[4] = 0x05; aad[5] = 0; aad[6] = 0; aad[7] = 0; aad[8] = 0; aad[9] = 0;

        uint8_t plain[68];
        for (int j = 0; j < plen; j++)
            plain[j] = (uint8_t)(j & 0xFF);

        /* Encrypt once to get ciphertext + tag */
        write_aad_msg(aad, 10, plain, plen);
        m3_ea_encrypt(sender_id, 0, 10, plen, OSCORE_TAG_LEN);
        m3_ea_wait_done(100000);

        uint8_t ct[68];
        m3_read_data_out(ct, plen);
        uint8_t tag[16];
        m3_ea_read_tag_out(tag);

        /* Benchmark N_ITER decrypt operations using sender_key
         * (same key for encrypt & decrypt in this self-loop test) */
        uint32_t total = 0;
        for (int i = 0; i < N_ITER; i++) {
            write_aad_msg(aad, 10, ct, plen);
            m3_ea_write_tag_exp(tag);

            t0 = read_mcycle();
            /* Decrypt with USE_SENDER_KEY=1 to match the key used for encrypt.
             * In real OSCORE, peer decrypts with its RECV_KEY, but for
             * self-loop benchmark we must use the same key. */
            m3_write(M3_EA_LENGTHS, ((uint32_t)10 << 16) | (uint32_t)plen);
            m3_write(M3_EA_NONCE(0), ((uint32_t)sender_id << 24));
            m3_write(M3_EA_NONCE(1), 0);
            m3_write(M3_EA_CONTROL, M3_EA_START | M3_EA_USE_SENDER_KEY |
                                    ((uint32_t)OSCORE_TAG_LEN << 3));
            m3_ea_wait_done(100000);
            t1 = read_mcycle();
            total += (t1 - t0);
        }
        uint32_t avg = total / N_ITER;
        uint32_t us  = (uint32_t)(((uint64_t)avg * 1000000ULL) / BENCHMARK_CPU_HZ);

        /* Verify first decrypt tag match */
        int match = m3_ea_tag_match();
        kprintf("  %5u  |  %10lu  |  %lu  %s\r\n",
                (unsigned)plen, (unsigned long)avg, (unsigned long)us,
                match ? "OK" : "TAG_FAIL");
    }

    kprintf("\r\n=== HW OSCORE Benchmark Done ===\r\n");
    kprintf("Compare with SW benchmark: make oscore_benchmark\r\n");

    while (1) {}
    return 0;

error:
    kprintf("\r\n=== EDHOC HANDSHAKE FAILED ===\r\n");
    kprintf("Status: 0x%lx\r\n", (unsigned long)m3_status());
    while (1);
    return -1;
}

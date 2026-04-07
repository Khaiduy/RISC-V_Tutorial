/**
 * @file edhoc_m3_responder.c
 * @brief EDHOC Method 3 Responder using Hardware Accelerator
 *
 * Hardware-accelerated EDHOC Responder for Method 3 (Signature + Static DH)
 * Cipher Suite 0: X25519 + AES-CCM-16-64-128 + HMAC-SHA-256
 *
 * Message flow:
 *   Responder receives MSG1 (37B), produces MSG2 (43B)
 *   Responder receives MSG3 (18B), produces MSG4 (8B tag)
 *
 * After handshake: OSCORE keys are derived internally.
 * Use ext_aead interface for AES-CCM encrypt/decrypt.
 */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
#include "edhoc_m3_hw.h"

/* ---------------------------------------------------------------------------
 * RV32 atomic 64-bit cycle counter
 * ---------------------------------------------------------------------------*/
static inline uint64_t rdcycle64(void)
{
    uint32_t lo, hi, hi2;
    do {
        asm volatile ("rdcycleh %0" : "=r"(hi));
        asm volatile ("rdcycle  %0" : "=r"(lo));
        asm volatile ("rdcycleh %0" : "=r"(hi2));
    } while (hi != hi2);
    return ((uint64_t)hi << 32) | lo;
}

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

/* Drain any stale bytes from UART1 RX FIFO */
static inline void uart1_drain_rx(void) {
    while (uart1_getc() >= 0);
}

/* Send message: 2-byte length header + data */
static int tx_msg(const uint8_t *data, uint8_t len) {
    uart1_putc(0x00);
    uart1_putc(len);
    for (int i = 0; i < len; i++) {
        uart1_putc(data[i]);
        for (volatile int d = 0; d < 50000; d++);
    }
    return 0;
}

/* Receive message: 2-byte length header + data */
static int rx_msg(uint8_t *data, uint8_t *len, uint8_t max_len) {
    int timeout, c;

    timeout = 1000000000;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) { kprintf("[R-RX] TIMEOUT len1\r\n"); return -1; }
    uint16_t msg_len = c << 8;

    timeout = 100000000;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) { kprintf("[R-RX] TIMEOUT len2\r\n"); return -1; }
    msg_len |= c;

    if (msg_len > max_len) { kprintf("[R-RX] Too long\r\n"); return -1; }

    for (int i = 0; i < msg_len; i++) {
        timeout = 100000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) { kprintf("[R-RX] TIMEOUT byte %d\r\n", i); return -1; }
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
/* Credentials — 55-byte CCS (CBOR Certificate by value)                      */
/* Must match the Initiator's peer credential                                 */
/* ========================================================================== */
static const uint8_t CRED_I[55] = {
    0xA2, 0x02, 0x66, 0x49, 0x6E, 0x69, 0x74, 0x4D,
    0x33, 0x08, 0xA1, 0x01, 0xA4, 0x01, 0x01, 0x02,
    0x41, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0xFD,
    0x33, 0x84, 0xE1, 0x32, 0xAD, 0x02, 0xA5, 0x6C,
    0x78, 0xF4, 0x55, 0x47, 0xEE, 0x40, 0x03, 0x8D,
    0xC7, 0x90, 0x02, 0xB9, 0x0D, 0x29, 0xED, 0x90,
    0xE0, 0x8E, 0xEE, 0x76, 0x2A, 0xE7, 0x15, 0x00
};

static const uint8_t CRED_R[55] = {
    0xA2, 0x02, 0x66, 0x52, 0x65, 0x73, 0x70, 0x4D,
    0x33, 0x08, 0xA1, 0x01, 0xA4, 0x01, 0x01, 0x02,
    0x41, 0x02, 0x20, 0x04, 0x21, 0x58, 0x20, 0xAD,
    0x8C, 0x48, 0xC2, 0x67, 0x65, 0xAE, 0xA7, 0xAD,
    0xC5, 0x36, 0x28, 0x96, 0x05, 0xC1, 0xAB, 0xEA,
    0x95, 0x05, 0x00, 0x93, 0xDB, 0xD2, 0x18, 0xC9,
    0x6A, 0xBD, 0x24, 0x81, 0xA0, 0x35, 0x65, 0x00
};

/* ========================================================================== */
/* Key Material                                                               */
/* ========================================================================== */
/* Static private key for Responder (32 bytes, big-endian) */
static const uint8_t STATIC_PRIV_R[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};

/* Ephemeral private key for Responder (32 bytes, big-endian)
 * Same as Initiator's for symmetric testing — change for production */
static const uint8_t EPH_PRIV_R[32] = {
    0x36, 0x8E, 0xC1, 0xF6, 0x9A, 0xEB, 0x65, 0x9B,
    0xA3, 0x7D, 0x5A, 0x8D, 0x45, 0xB2, 0x1B, 0xDC,
    0x02, 0x99, 0xDC, 0xEA, 0xA8, 0xEF, 0x23, 0x5F,
    0x3C, 0xA4, 0x2C, 0xE3, 0x53, 0x0F, 0x95, 0x25
};

/* Connection identifiers */
#define C_I   0x2D
#define C_R   0x0E
#define KID_I 0x01
#define KID_R 0x02

/* OSCORE tag length (AES-CCM-16-64-128 uses 8-byte tag) */
#define OSCORE_TAG_LEN 8

#ifndef BENCHMARK_CPU_HZ
#define BENCHMARK_CPU_HZ 50000000UL
#endif

#define N_ITER 100

/* Payload sizes for sweep — matches SW benchmark */
static const uint16_t SWEEP_SIZES[] = { 10, 20, 50, 100, 200, 500, 1000 };
#define NUM_SWEEPS ((int)(sizeof(SWEEP_SIZES) / sizeof(SWEEP_SIZES[0])))

/* ========================================================================== */
/* CoAP / OSCORE Software Overhead                                            */
/* ========================================================================== */

#define COAP_OPT_URI_HOST    3
#define COAP_OPT_URI_PORT    7
#define COAP_OPT_URI_PATH   11
#define COAP_OPT_URI_QUERY  15
#define COAP_OPT_OSCORE      9
#define COAP_OPT_PROXY_URI  35
#define COAP_OPT_PROXY_SCHEME 39
#define COAP_OPT_OBSERVE     6

#define MAX_OPTIONS   12
#define NONCE_LEN     13
#define MAX_PIV_LEN    5

struct coap_opt {
    uint16_t number;
    uint16_t len;
    const uint8_t *value;
};

struct coap_pkt {
    uint8_t  ver, type, tkl, code;
    uint16_t mid;
    const uint8_t *token;
    uint8_t  opt_cnt;
    struct coap_opt opts[MAX_OPTIONS];
    const uint8_t *payload;
    uint16_t payload_len;
};

static int coap_deser(const uint8_t *buf, uint16_t buf_len, struct coap_pkt *pkt)
{
    if (buf_len < 4) return -1;
    pkt->ver  = (buf[0] >> 6) & 0x03;
    pkt->type = (buf[0] >> 4) & 0x03;
    pkt->tkl  = buf[0] & 0x0F;
    pkt->code = buf[1];
    pkt->mid  = (uint16_t)(buf[2] << 8) | buf[3];
    const uint8_t *p = buf + 4;
    uint16_t rem = buf_len - 4;
    if (pkt->tkl > 8 || pkt->tkl > rem) return -1;
    pkt->token = (pkt->tkl > 0) ? p : (const uint8_t *)0;
    p   += pkt->tkl;
    rem -= pkt->tkl;
    pkt->opt_cnt = 0;
    pkt->payload = (const uint8_t *)0;
    pkt->payload_len = 0;
    uint16_t opt_num = 0;
    while (rem > 0) {
        if (*p == 0xFF) { p++; rem--; pkt->payload = p; pkt->payload_len = rem; break; }
        uint16_t delta = (*p >> 4) & 0x0F;
        uint16_t olen  = *p & 0x0F;
        p++; rem--;
        if (delta == 13) { delta = *p + 13; p++; rem--; }
        else if (delta == 14) { delta = (uint16_t)(p[0] << 8 | p[1]) + 269; p += 2; rem -= 2; }
        if (olen == 13) { olen = *p + 13; p++; rem--; }
        else if (olen == 14) { olen = (uint16_t)(p[0] << 8 | p[1]) + 269; p += 2; rem -= 2; }
        opt_num += delta;
        if (pkt->opt_cnt < MAX_OPTIONS) {
            pkt->opts[pkt->opt_cnt].number = opt_num;
            pkt->opts[pkt->opt_cnt].len    = olen;
            pkt->opts[pkt->opt_cnt].value  = p;
            pkt->opt_cnt++;
        }
        p += olen; rem -= olen;
    }
    return 0;
}

/** oscore_opt_parse — extract PIV and KID from OSCORE option value. */
static void oscore_opt_parse(const uint8_t *val, uint16_t vlen,
                             uint8_t *piv, uint8_t *piv_len,
                             uint8_t *kid, uint8_t *kid_len)
{
    if (vlen == 0) { *piv_len = 0; *kid_len = 0; return; }
    uint8_t flags = val[0];
    *piv_len = flags & 0x07;
    const uint8_t *p = val + 1;
    memcpy(piv, p, *piv_len); p += *piv_len;
    if (flags & 0x08) {
        *kid_len = (uint8_t)(vlen - 1 - *piv_len);
        memcpy(kid, p, *kid_len);
    } else {
        *kid_len = 0;
    }
}

/** build_aad — CBOR: [ver=1, [alg=10], kid, piv, options=empty]. */
static uint8_t build_aad(const uint8_t *kid, uint8_t kid_len,
                         const uint8_t *piv, uint8_t piv_len, uint8_t *out)
{
    uint8_t *p = out;
    *p++ = 0x85; *p++ = 0x01; *p++ = 0x81; *p++ = 0x0A;
    *p++ = 0x40 | kid_len; memcpy(p, kid, kid_len); p += kid_len;
    *p++ = 0x40 | piv_len; memcpy(p, piv, piv_len); p += piv_len;
    *p++ = 0x40;
    return (uint8_t)(p - out);
}

/** options_ser — delta-encode options into buffer. Returns bytes written. */
static uint16_t options_ser(const struct coap_opt *opts, uint8_t cnt, uint8_t *out)
{
    uint8_t *p = out;
    uint16_t prev = 0;
    for (int i = 0; i < cnt; i++) {
        uint16_t d = opts[i].number - prev, l = opts[i].len;
        prev = opts[i].number;
        uint8_t d4 = (d < 13) ? (uint8_t)d : 13;
        uint8_t l4 = (l < 13) ? (uint8_t)l : 13;
        *p++ = (d4 << 4) | l4;
        if (d4 == 13) *p++ = (uint8_t)(d - 13);
        if (l4 == 13) *p++ = (uint8_t)(l - 13);
        memcpy(p, opts[i].value, l); p += l;
    }
    return (uint16_t)(p - out);
}

/**
 * coap_reconstruct — rebuild original CoAP from decrypted plaintext + OSCORE pkt.
 * Mirrors o_coap_pkg_generate() + coap_serialize() in SW oscore2coap.
 * Extracts inner code + E-options from plaintext, merges with original header/token.
 * Returns serialized output length.
 */
static uint16_t coap_reconstruct(const struct coap_pkt *oscore_pkt,
                                 const uint8_t *pt_hdr, uint8_t pt_hdr_len,
                                 uint16_t payload_len, uint8_t *out)
{
    uint8_t *p = out;
    /* Original CoAP code from plaintext byte 0 */
    uint8_t inner_code = pt_hdr[0];
    /* Parse E-options from plaintext bytes 1..pt_hdr_len-2 (before 0xFF) */
    struct coap_opt e_opts[MAX_OPTIONS];
    uint8_t e_cnt = 0;
    const uint8_t *q = pt_hdr + 1;
    uint16_t qrem = (pt_hdr_len > 1 && pt_hdr[pt_hdr_len - 1] == 0xFF)
                    ? (pt_hdr_len - 2) : (pt_hdr_len - 1);
    uint16_t onum = 0;
    while (qrem > 0) {
        if (*q == 0xFF) break;  /* payload marker — stop parsing options */
        uint16_t delta = (*q >> 4) & 0x0F, olen = *q & 0x0F;
        q++; qrem--;
        if (delta == 13) { delta = *q + 13; q++; qrem--; }
        if (olen == 13) { olen = *q + 13; q++; qrem--; }
        onum += delta;
        if (e_cnt < MAX_OPTIONS) {
            e_opts[e_cnt].number = onum;
            e_opts[e_cnt].len    = olen;
            e_opts[e_cnt].value  = q;
            e_cnt++;
        }
        q += olen; qrem -= olen;
    }
    /* Serialize: header + token + E-options + 0xFF + payload (not copied) */
    *p++ = (oscore_pkt->ver << 6) | (oscore_pkt->type << 4) | oscore_pkt->tkl;
    *p++ = inner_code;
    *p++ = (uint8_t)(oscore_pkt->mid >> 8);
    *p++ = (uint8_t)(oscore_pkt->mid & 0xFF);
    if (oscore_pkt->tkl > 0) { memcpy(p, oscore_pkt->token, oscore_pkt->tkl); p += oscore_pkt->tkl; }
    p += options_ser(e_opts, e_cnt, p);
    if (payload_len > 0) *p++ = 0xFF;
    return (uint16_t)(p - out);
}

/* ========================================================================== */
/* Main                                                                       */
/* ========================================================================== */
int main(void) {
    /* UART setup */
    REG32(uart, UART_REG_DIV) = 868;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV) = 868;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;

    uint8_t msg_buf[48];
    uint8_t msg_len;
    int ret;


    /* ── Start as Responder ── */
    uint64_t t0, t1;
    uint64_t cyc_start_setup, cyc_msg12, cyc_msg34, cyc_done;

    /* Brief delay for serial terminal to synchronize */
    for (volatile long d = 0; d < 3000000; d++);
    kprintf("\r\n\r\n");
    kprintf("  EDHOC M3 Hardware-Accelerated Responder\r\n");
    kprintf("  Method 3 | Suite 0 (X25519 + AES-CCM + HMAC-SHA256)\r\n\r\n");

    t0 = rdcycle64();
    /* ── Reset hardware ── */
    m3_sw_reset();

    /* ── Write ephemeral private key ── */
    m3_write_key256(M3_EPH_PRIV(0), EPH_PRIV_R);

    /* ── Write static private key ── */
    m3_write_key256(M3_STATIC_PRIV(0), STATIC_PRIV_R);

    /* ── Write credentials (swapped: own = Responder, peer = Initiator) ── */
    m3_write_cred(M3_CRED_OWN(0), CRED_R);    /* Own = Responder */
    m3_write_cred(M3_CRED_PEER(0), CRED_I);   /* Peer = Initiator */

    /* ── Write parameters ──
     * Responder: kid_own=KID_R, kid_peer=KID_I, c_x=C_R, c_peer=C_I */
    m3_set_params(KID_R, KID_I, C_R, C_I);


    
    m3_start_responder();
    t1 = rdcycle64();
    cyc_start_setup = t1 - t0;
    // kprintf("[RESP] Starting EDHOC Responder...\r\n");
    /* ══════════════════════════════════════════════════════════════════
     * MSG1: Initiator → Responder (37 bytes)
     * Wait for HW to enter S_WAIT_EXT (waiting for MSG1)
     * ══════════════════════════════════════════════════════════════════ */
    ret = m3_wait_waiting(500000);
    if (ret < 0) { kprintf("ERROR: Wait for MSG1 slot timeout\r\n"); goto error; }

    /* Drain stale UART1 RX bytes, then signal Initiator we're ready */
    uart1_drain_rx();
    uart1_putc(0xAA);

    /* Receive MSG1 from Initiator via UART */
    kprintf("[MSG1] Waiting for initiator...\r\n");
    ret = rx_msg(msg_buf, &msg_len, sizeof(msg_buf));
    if (ret < 0) { kprintf("ERROR: Failed to receive MSG1\r\n"); goto error; }
    print_hex("MSG1", msg_buf, msg_len);

    t0 = rdcycle64();
    /* Write MSG1 to data_in[0..] and signal input_ready */
    m3_write_data_in(msg_buf, msg_len);
    
    m3_input_ready(0);

    /* ══════════════════════════════════════════════════════════════════
     * MSG2: Responder → Initiator (43 bytes)
     * HW processes MSG1, derives keys, packs MSG2
     * ══════════════════════════════════════════════════════════════════ */
    ret = m3_wait_msg_ready(500000);
    t1 = rdcycle64();
    cyc_msg12 = t1 - t0;
    if (ret < 0) { kprintf("ERROR: MSG2 timeout (ret=%d)\r\n", ret); goto error; }

    msg_len = m3_get_msg_len();
    m3_read_data_out(msg_buf, msg_len);
    print_hex("MSG2", msg_buf, msg_len);

    /* Send MSG2 via UART to Initiator */
    kprintf("[MSG2] Sending %d bytes to initiator...\r\n", msg_len);
    tx_msg(msg_buf, msg_len);

    /* Acknowledge output read — is_init=0 for Responder */
    m3_output_ack(0);

    /* ══════════════════════════════════════════════════════════════════
     * MSG3: Initiator → Responder (18 bytes)
     * Wait for HW to enter S_WAIT_EXT (waiting for MSG3 ciphertext)
     * MSG3 CT body goes to data_in[15:17], tag to data_in[18:19]
     * ══════════════════════════════════════════════════════════════════ */
    ret = m3_wait_waiting(500000);
    if (ret < 0) { kprintf("ERROR: Wait for MSG3 slot timeout\r\n"); goto error; }

    /* Receive MSG3 from Initiator via UART */
    kprintf("[MSG3] Waiting for initiator...\r\n");
    ret = rx_msg(msg_buf, &msg_len, sizeof(msg_buf));
    if (ret < 0) { kprintf("ERROR: Failed to receive MSG3\r\n"); goto error; }
    print_hex("MSG3", msg_buf, msg_len);

    /* Write MSG3 ciphertext to data_in starting at byte offset 60
     * (words 15-19: CT body + tag placed at the location the CTF FSM reads) */
    t0 = rdcycle64();
    m3_write_msg3_ct(msg_buf, msg_len);
    
    m3_input_ready(0);

    /* ══════════════════════════════════════════════════════════════════
     * MSG4: Responder → Initiator (8 bytes — tag only)
     * HW decrypts MSG3, verifies MAC_3, computes MAC_4, packs MSG4
     * ══════════════════════════════════════════════════════════════════ */
    ret = m3_wait_msg_ready(500000);
    t1 = rdcycle64();
    cyc_msg34 = t1 - t0;
    if (ret < 0) { kprintf("ERROR: MSG4 timeout (ret=%d)\r\n", ret); goto error; }

    msg_len = m3_get_msg_len();
    m3_read_data_out(msg_buf, msg_len);
    print_hex("MSG4", msg_buf, msg_len);

    /* Send MSG4 via UART to Initiator */
    kprintf("[MSG4] Sending %d bytes to initiator...\r\n", msg_len);
    tx_msg(msg_buf, msg_len);

    /* Acknowledge output read */
    t0 = rdcycle64();
    m3_output_ack(0);

    /* ══════════════════════════════════════════════════════════════════
     * Wait for EDHOC completion + OSCORE key derivation
     * ══════════════════════════════════════════════════════════════════ */
    ret = m3_wait_done(5000000);
    t1 = rdcycle64();
    cyc_done = t1 - t0;
    if (ret < 0) { kprintf("ERROR: EDHOC failed (ret=%d)\r\n", ret); goto error; }

    if (!m3_oscore_keys_valid()) {
        kprintf("ERROR: OSCORE keys not valid\r\n");
        goto error;
    }

    kprintf("  EDHOC M3 HANDSHAKE SUCCESS!\r\n");
    kprintf("  Timing (cycles):\r\n");
    kprintf("    Start->Setup:   %lu\r\n", (unsigned long)cyc_start_setup);
    kprintf("    MSG1->MSG2:    %lu\r\n", (unsigned long)cyc_msg12);
    kprintf("    MSG3->MSG4:    %lu\r\n", (unsigned long)cyc_msg34);
    kprintf("    MSG4->Done:    %lu\r\n", (unsigned long)cyc_done);
    kprintf("    Total HW:      %lu\r\n\r\n", (unsigned long)(cyc_start_setup + cyc_msg12 + cyc_msg34 + cyc_done));

#ifdef INCLUDE_OSCORE
    /* ================================================================== *
     * Minimal OSCORE: receive 1 OSCORE packet + decrypt + verify         *
     * Pulls in all oscore2coap SW overhead code for firmware size measurement. *
     * ================================================================== */
    {
        uint8_t aad_buf[20], piv_buf[MAX_PIV_LEN], kid_buf[4], coap_out[48];
        uint8_t oscore_rx[100]; /* 35-byte payload fits easily */
        struct coap_pkt pkt;

        /* Wait for initiator sync */
        kprintf("[RESP] Waiting for Initiator OSCORE sync...\r\n");
        { int sync, to = 500000000; do { sync = uart1_getc(); } while (sync != 0xBB && --to > 0); }

        /* Tell initiator we're ready */
        uart1_putc(0xCC);

        /* Receive OSCORE packet (2-byte length + data) */
        int c, rx_timeout;
        rx_timeout = 500000000;
        while ((c = uart1_getc()) < 0 && --rx_timeout > 0);
        uint16_t rpkt_len = (uint16_t)c << 8;
        rx_timeout = 100000000;
        while ((c = uart1_getc()) < 0 && --rx_timeout > 0);
        rpkt_len |= (uint16_t)c;
        for (uint16_t k = 0; k < rpkt_len && k < sizeof(oscore_rx); k++) {
            rx_timeout = 100000000;
            while ((c = uart1_getc()) < 0 && --rx_timeout > 0);
            if (c < 0) break;
            oscore_rx[k] = (uint8_t)c;
        }

        /* oscore2coap SW overhead */
        coap_deser(oscore_rx, rpkt_len, &pkt);
        uint8_t rpiv_len = 0, rkid_len = 0;
        for (int j = 0; j < pkt.opt_cnt; j++) {
            if (pkt.opts[j].number == COAP_OPT_OSCORE) {
                oscore_opt_parse(pkt.opts[j].value, pkt.opts[j].len,
                                 piv_buf, &rpiv_len, kid_buf, &rkid_len);
                break;
            }
        }
        uint32_t ssn = 0;
        for (int j = 0; j < rpiv_len; j++) ssn = (ssn << 8) | piv_buf[j];
        uint8_t aad_len = build_aad(kid_buf, rkid_len, piv_buf, rpiv_len, aad_buf);

        uint16_t ct_len = pkt.payload_len - OSCORE_TAG_LEN;
        const uint8_t *ct_ptr = pkt.payload;
        const uint8_t *tag_ptr = pkt.payload + ct_len;

        /* Feed AAD + ciphertext to HW */
        int aad_words = (aad_len + 3) / 4, w;
        for (w = 0; w < aad_words; w++)
            m3_write(M3_DATA_IN(w), m3_pack_word(aad_buf, w * 4, aad_len));
        int ct_off = 0;
        for (; w < 20 && ct_off < (int)ct_len; w++, ct_off += 4)
            m3_write(M3_DATA_IN(w), m3_pack_word(ct_ptr, ct_off, ct_len));

        uint8_t exp_tag[16] = {0};
        memcpy(exp_tag, tag_ptr, OSCORE_TAG_LEN);
        m3_ea_write_tag_exp(exp_tag);
        m3_ea_decrypt(kid_buf[0], ssn, aad_len, ct_len, OSCORE_TAG_LEN);
        m3_ea_wait_done(500000);

        int tag_ok = m3_ea_tag_match();

        /* Read plaintext using dout_count */
        uint8_t dec_pt[16];
        { uint32_t st = m3_read(M3_EA_STATUS); int dw = (st >> 8) & 0x1F;
          for (int r = 0; r < dw; r++) { uint32_t v = m3_read(M3_DATA_OUT(r));
            for (int b = 0; b < 4; b++) { int pos = r*4+b;
              if (pos < 16) dec_pt[pos] = (uint8_t)(v>>((3-b)*8)); }}}

        int read_len = ((int)ct_len < 16) ? (int)ct_len : 16;
        volatile uint16_t coap_len = coap_reconstruct(&pkt, dec_pt, (uint8_t)read_len, 35, coap_out);
        (void)coap_len;

        uart1_putc(tag_ok ? 0xAA : 0xFF);
        kprintf("  OSCORE decrypt+verify: %s\r\n", tag_ok ? "OK" : "FAIL");
    }
#endif /* INCLUDE_OSCORE */

#if 0  /* ── Full sweep benchmark (commented out for size measurement) ──── */
    /* ══════════════════════════════════════════════════════════════════
     * OSCORE Hardware Benchmark: oscore2coap with HW AES-CCM decrypt
     *
     * Paired with Initiator over UART for end-to-end verification:
     *   Initiator encrypts → sends OSCORE packet → Responder decrypts
     *   → verifies tag + plaintext → sends ACK.
     *
     * Includes all constant SW overhead from oscore2coap():
     *   coap_deserialize → oscore_option_parse → build_aad →
     *   HW AEAD decrypt → verify tag → read plaintext →
     *   coap_reconstruct (inner code + E-opts merge + serialize)
     * Nonce is constructed by HW internally (design advantage).
     * ══════════════════════════════════════════════════════════════════ */

    /* Wait for benchmark sync byte (0xBB) from Initiator */
    kprintf("[RESP] Waiting for Initiator OSCORE benchmark sync...\r\n");
    {
        int sync, sync_timeout = 500000000;
        do { sync = uart1_getc(); } while (sync != 0xBB && --sync_timeout > 0);
        if (sync_timeout == 0) { kprintf("ERROR: Benchmark sync timeout\r\n"); goto error; }
    }

    uint8_t aad_buf[20];
    uint8_t piv_buf[MAX_PIV_LEN];
    uint8_t kid_buf[4];
    uint8_t coap_out[48];

    /* Receive buffer for full OSCORE packets (header + ciphertext + tag) */
    uint8_t oscore_rx[1100];

    struct coap_pkt pkt;

    /* Replay window — matches SW library (32-entry sliding window).
     * Ensures fair comparison: SW oscore2coap() includes this check. */
    #define RW_SIZE 32
    uint64_t rw_window[RW_SIZE];
    int rw_zero_seen;

    kprintf("[HW-DECRYPT] oscore2coap + HW AES-CCM (N=%d per size):\r\n", N_ITER);
    kprintf("Payload |   Avg Cycles |   Avg us | Verify\r\n");
    kprintf("--------|--------------|----------|-------\r\n");

    /* Tell initiator we're ready to receive UART1 data */
    uart1_putc(0xCC);

    for (int ps = 0; ps < NUM_SWEEPS; ps++) {
        uint64_t total = 0;
        int failures = 0;
        uint16_t plen = SWEEP_SIZES[ps];

        /* Reset replay window for each payload size (mirrors SW: fresh context per sweep). */
        for (int rr = 0; rr < RW_SIZE; rr++) rw_window[rr] = 0;
        rw_zero_seen = 0;

        for (int i = 0; i < N_ITER; i++) {
            /* ── Receive OSCORE packet from Initiator ── */
            int c, rx_timeout;
            rx_timeout = 500000000;
            while ((c = uart1_getc()) < 0 && --rx_timeout > 0);
            if (c < 0) { failures++; uart1_putc(0xFF); continue; }
            uint16_t rpkt_len = (uint16_t)c << 8;
            rx_timeout = 100000000;
            while ((c = uart1_getc()) < 0 && --rx_timeout > 0);
            if (c < 0) { failures++; uart1_putc(0xFF); continue; }
            rpkt_len |= (uint16_t)c;

            if (rpkt_len > sizeof(oscore_rx)) { failures++; uart1_putc(0xFF); continue; }

            for (uint16_t k = 0; k < rpkt_len; k++) {
                rx_timeout = 100000000;
                while ((c = uart1_getc()) < 0 && --rx_timeout > 0);
                if (c < 0) break;
                oscore_rx[k] = (uint8_t)c;
            }

            /* ── TIMED: Full oscore2coap SW overhead + HW decrypt ── */
            t0 = rdcycle64();

            /* Step 1: Parse OSCORE CoAP packet */
            coap_deser(oscore_rx, rpkt_len, &pkt);

            /* Step 2: Find and parse OSCORE option (extract PIV + KID) */
            uint8_t rpiv_len = 0, rkid_len = 0;
            for (int j = 0; j < pkt.opt_cnt; j++) {
                if (pkt.opts[j].number == COAP_OPT_OSCORE) {
                    oscore_opt_parse(pkt.opts[j].value, pkt.opts[j].len,
                                     piv_buf, &rpiv_len, kid_buf, &rkid_len);
                    break;
                }
            }

            /* Step 3: PIV → SSN */
            uint32_t ssn = 0;
            for (int j = 0; j < rpiv_len; j++)
                ssn = (ssn << 8) | piv_buf[j];

            /* Step 3b: Replay window check (matches SW library logic) */
            {
                int rw_valid = 0;
                if (ssn == 0) {
                    rw_valid = (!rw_zero_seen && rw_window[0] == 0);
                } else if (ssn > rw_window[RW_SIZE - 1]) {
                    rw_valid = 1;
                } else if (ssn >= rw_window[0]) {
                    rw_valid = 1;
                    for (int rr = 0; rr < RW_SIZE; rr++) {
                        if (ssn == rw_window[rr]) { rw_valid = 0; break; }
                    }
                }
                /* Update window (insert + shift) */
                if (rw_valid) {
                    if (ssn == 0) {
                        rw_zero_seen = 1;
                    } else {
                        int idx = RW_SIZE - 1;
                        for (int rr = 0; rr < RW_SIZE - 1; rr++) {
                            if (rw_window[rr] < ssn && rw_window[rr+1] > ssn)
                                { idx = rr; break; }
                        }
                        for (int rr = 0; rr < idx; rr++)
                            rw_window[rr] = rw_window[rr + 1];
                        rw_window[idx] = ssn;
                    }
                }
                (void)rw_valid;
            }

            /* Step 4: Build AAD (CBOR) */
            uint8_t aad_len = build_aad(kid_buf, rkid_len, piv_buf, rpiv_len, aad_buf);

            /* Step 5: Separate ciphertext and tag from payload */
            uint16_t ct_len = pkt.payload_len - OSCORE_TAG_LEN;
            const uint8_t *ct_ptr = pkt.payload;
            const uint8_t *tag_ptr = pkt.payload + ct_len;

            /* Step 6: Feed AAD + ciphertext to HW */
            int aad_words = (aad_len + 3) / 4;
            int w;
            for (w = 0; w < aad_words; w++)
                m3_write(M3_DATA_IN(w), m3_pack_word(aad_buf, w * 4, aad_len));

            int ct_off = 0;
            for (; w < 20 && ct_off < (int)ct_len; w++, ct_off += 4)
                m3_write(M3_DATA_IN(w), m3_pack_word(ct_ptr, ct_off, ct_len));

            /* Write expected tag */
            uint8_t exp_tag[16] = {0};
            memcpy(exp_tag, tag_ptr, OSCORE_TAG_LEN);
            m3_ea_write_tag_exp(exp_tag);

            /* Start decrypt */
            m3_ea_decrypt(kid_buf[0], ssn, aad_len, ct_len, OSCORE_TAG_LEN);

            /* Feed remaining ciphertext chunks, draining output between each.
             * Must read data_out (using dout_count) before feeding next chunk,
             * otherwise the HW stalls with a full output buffer. */
            uint8_t dec_pt[16];
            int pt_off = 0;
            while (ct_off < (int)ct_len) {
                uint32_t st;
                while (!((st = m3_read(M3_EA_STATUS)) & M3_EA_STATUS_INPUT_RDY));
                /* Drain output using dout_count — save first 16 bytes */
                int dw = (st >> 8) & 0x1F;
                for (int r = 0; r < dw; r++) {
                    uint32_t v = m3_read(M3_DATA_OUT(r));
                    for (int b = 0; b < 4; b++) {
                        int pos = pt_off + r*4 + b;
                        if (pos < 16)
                            dec_pt[pos] = (uint8_t)(v >> ((3-b)*8));
                    }
                }
                pt_off += dw * 4;
                /* Feed next input chunk */
                for (w = 0; w < 20 && ct_off < (int)ct_len; w++, ct_off += 4)
                    m3_write(M3_DATA_IN(w), m3_pack_word(ct_ptr, ct_off, ct_len));
                m3_write(M3_EA_CHUNK, 0);
            }

            m3_ea_wait_done(500000);

            /* Step 7: Verify tag match */
            int tag_ok = m3_ea_tag_match();

            /* Step 8: Read final output chunk using dout_count */
            {
                uint32_t st = m3_read(M3_EA_STATUS);
                int dw = (st >> 8) & 0x1F;
                for (int r = 0; r < dw; r++) {
                    uint32_t v = m3_read(M3_DATA_OUT(r));
                    for (int b = 0; b < 4; b++) {
                        int pos = pt_off + r*4 + b;
                        if (pos < 16)
                            dec_pt[pos] = (uint8_t)(v >> ((3-b)*8));
                    }
                }
            }

            int read_len = (pt_off > 16) ? 16 : pt_off;
            if ((int)ct_len < read_len) read_len = (int)ct_len;
            volatile uint16_t coap_len = coap_reconstruct(
                &pkt, dec_pt, (uint8_t)read_len, plen, coap_out);

            t1 = rdcycle64();
            total += (t1 - t0);
            (void)coap_len;

            if (!tag_ok) failures++;

            /* Send ACK to Initiator */
            uart1_putc(tag_ok ? 0xAA : 0xFF);
        }

        uint32_t avg = (uint32_t)(total / N_ITER);
        uint32_t us  = (uint32_t)(((uint64_t)avg * 1000000ULL) / BENCHMARK_CPU_HZ);
        kprintf("  %5u  |  %10lu  |  %6lu  | %s\r\n",
                (unsigned)plen, (unsigned long)avg, (unsigned long)us,
                failures == 0 ? "OK" : "FAIL");
    }

    kprintf("\r\nIncludes CoAP parse/OSCORE opt parse/AAD/decrypt/reconstruct overhead.\r\n");
    kprintf("Nonce constructed by HW (design advantage).\r\n");
    kprintf("\r\n=== HW OSCORE Decrypt Benchmark Done ===\r\n");
#endif /* Full sweep benchmark */

    while (1) {}
    return 0;

error:
    kprintf("\r\n=== EDHOC M3 HANDSHAKE FAILED ===\r\n");
    kprintf("Status: 0x%lx\r\n", (unsigned long)m3_status());
    while (1);
    return -1;
}

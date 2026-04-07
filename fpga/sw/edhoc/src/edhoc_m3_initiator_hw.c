/**
 * @file edhoc_m3_initiator.c
 * @brief EDHOC Method 3 Initiator using Hardware Accelerator
 *
 * Hardware-accelerated EDHOC Initiator for Method 3 (Signature + Static DH)
 * Cipher Suite 0: X25519 + AES-CCM-16-64-128 + HMAC-SHA-256
 *
 * Message flow:
 *   Initiator produces MSG1 (37B), receives MSG2 (43B)
 *   Initiator produces MSG3 (18B), receives MSG4 (8B tag)
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
 * Reads rdcycleh / rdcycle / rdcycleh and retries on 32-bit carry.
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
    if (c < 0) { kprintf("[I-RX] TIMEOUT len1\r\n"); return -1; }
    uint16_t msg_len = c << 8;

    timeout = 100000000;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) { kprintf("[I-RX] TIMEOUT len2\r\n"); return -1; }
    msg_len |= c;

    if (msg_len > max_len) { kprintf("[I-RX] Too long\r\n"); return -1; }

    for (int i = 0; i < msg_len; i++) {
        timeout = 100000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) { kprintf("[I-RX] TIMEOUT byte %d\r\n", i); return -1; }
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
/* Must match the Responder's peer credential                                 */
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
/* Static private key for Initiator (32 bytes, big-endian) */
static const uint8_t STATIC_PRIV_I[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

/* Ephemeral private key for Initiator (32 bytes, big-endian)
 * Non-zero test vector for proper DH exchange */
static const uint8_t EPH_PRIV_I[32] = {
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

/** Generate a 32-bit word of sequential payload bytes at given byte offset */
static inline uint32_t gen_msg_word(int offset, int len) {
    uint32_t val = 0;
    for (int b = 0; b < 4; b++) {
        if (offset + b < len)
            val |= ((uint32_t)((offset + b) & 0xFF)) << ((3 - b) * 8);
    }
    return val;
}

/* ========================================================================== */
/* CoAP / OSCORE Software Overhead (mirrors coap2oscore constant-cost steps)  */
/*                                                                            */
/* These lightweight inline functions replicate the exact software overhead    */
/* that coap2oscore() performs, excluding the AEAD call itself.                */
/* This gives a realistic HW measurement that includes:                       */
/*   - CoAP deserialization (header + token + option parsing)                 */
/*   - Inner/outer option split (E vs U classification)                       */
/*   - Plaintext construction (code + E-options + 0xFF + payload)             */
/*   - SSN→PIV conversion + nonce construction (pad + XOR)                    */
/*   - OSCORE option generation (flags + PIV + KID)                           */
/*   - AAD construction (CBOR encoding)                                       */
/*   - Output OSCORE packet re-serialization                                  */
/* ========================================================================== */

/* CoAP option numbers (RFC 7252 + OSCORE) */
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

/* Lightweight CoAP option descriptor */
struct coap_opt {
    uint16_t number;
    uint16_t len;
    const uint8_t *value;
};

/* Parsed CoAP packet */
struct coap_pkt {
    uint8_t  ver, type, tkl, code;
    uint16_t mid;
    const uint8_t *token;
    uint8_t  opt_cnt;
    struct coap_opt opts[MAX_OPTIONS];
    const uint8_t *payload;
    uint16_t payload_len;
};

/**
 * coap_deser — parse raw CoAP bytes into struct.
 * Mirrors oscore_coap.c coap_deserialize() overhead.
 * Only reads header+options bytes; payload pointer is set but never dereferenced.
 */
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

/**
 * option_split — classify parsed options into E (inner) and U (outer) sets.
 */
static void option_split(const struct coap_pkt *pkt,
                         struct coap_opt *e_opts, uint8_t *e_cnt,
                         struct coap_opt *u_opts, uint8_t *u_cnt)
{
    *e_cnt = 0; *u_cnt = 0;
    for (int i = 0; i < pkt->opt_cnt; i++) {
        uint16_t n = pkt->opts[i].number;
        if (n == COAP_OPT_URI_HOST || n == COAP_OPT_URI_PORT ||
            n == COAP_OPT_OSCORE   || n == COAP_OPT_PROXY_URI ||
            n == COAP_OPT_PROXY_SCHEME) {
            if (*u_cnt < MAX_OPTIONS) u_opts[(*u_cnt)++] = pkt->opts[i];
        } else {
            if (*e_cnt < MAX_OPTIONS) e_opts[(*e_cnt)++] = pkt->opts[i];
        }
    }
}

/**
 * options_ser — delta-encode options into buffer. Returns bytes written.
 */
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
 * pt_hdr_build — build plaintext header: code + serialized E-options + 0xFF.
 * Does NOT include the payload body (fed to HW on-the-fly).
 * Returns header length. If has_payload, includes the 0xFF marker.
 */
static uint8_t pt_hdr_build(uint8_t code, const struct coap_opt *e_opts,
                            uint8_t e_cnt, int has_payload, uint8_t *out)
{
    uint8_t *p = out;
    *p++ = code;
    p += options_ser(e_opts, e_cnt, p);
    if (has_payload) *p++ = 0xFF;
    return (uint8_t)(p - out);
}

/** ssn2piv — SSN to big-endian PIV. Returns length. */
static uint8_t ssn2piv(uint32_t ssn, uint8_t piv[MAX_PIV_LEN])
{
    if (ssn == 0) { piv[0] = 0; return 1; }
    uint8_t tmp[MAX_PIV_LEN], len = 0;
    for (uint32_t s = ssn; s > 0; s >>= 8) tmp[len++] = (uint8_t)(s & 0xFF);
    for (uint8_t i = 0; i < len; i++) piv[i] = tmp[len - 1 - i];
    return len;
}

/* create_nonce is NOT needed — HW constructs nonce internally from
 * (sender_id, SSN, common_iv). This is a HW design advantage that
 * saves SW the memset + pad + XOR overhead of RFC 8613 §5.2. */

/** build_aad — manual CBOR: [ver=1, [alg=10], kid, piv, options=empty]. */
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

/** oscore_opt_gen — build OSCORE option value. */
static uint8_t oscore_opt_gen(const uint8_t *piv, uint8_t piv_len,
                              const uint8_t *kid, uint8_t kid_len, uint8_t *out)
{
    uint8_t *p = out, flags = 0;
    if (piv_len) flags |= piv_len & 0x07;
    if (kid_len) flags |= 0x08;
    *p++ = flags;
    memcpy(p, piv, piv_len); p += piv_len;
    memcpy(p, kid, kid_len); p += kid_len;
    return (uint8_t)(p - out);
}

/**
 * oscore_hdr_ser — serialize OSCORE output header + options (NO ciphertext).
 * Builds: header(4) + token + merged U-opts + OSCORE opt + 0xFF.
 * Returns header byte count. Caller appends ciphertext separately.
 */
static uint16_t oscore_hdr_ser(const struct coap_pkt *orig,
                               const struct coap_opt *u_opts, uint8_t u_cnt,
                               const uint8_t *oopt_val, uint8_t oopt_len,
                               uint8_t *out)
{
    uint8_t *p = out;
    *p++ = (orig->ver << 6) | (orig->type << 4) | orig->tkl;
    *p++ = 0x02; /* POST */
    *p++ = (uint8_t)(orig->mid >> 8);
    *p++ = (uint8_t)(orig->mid & 0xFF);
    if (orig->tkl > 0) { memcpy(p, orig->token, orig->tkl); p += orig->tkl; }

    uint8_t ui = 0; int osc_done = 0;
    uint16_t prev = 0;
    while (ui < u_cnt || !osc_done) {
        uint16_t nu = (ui < u_cnt) ? u_opts[ui].number : 0xFFFF;
        if (!osc_done && COAP_OPT_OSCORE <= nu) {
            uint16_t d = COAP_OPT_OSCORE - prev;
            *p++ = (uint8_t)((d < 13 ? d : 13) << 4) | (oopt_len < 13 ? oopt_len : 13);
            if (d >= 13) *p++ = (uint8_t)(d - 13);
            if (oopt_len >= 13) *p++ = (uint8_t)(oopt_len - 13);
            memcpy(p, oopt_val, oopt_len); p += oopt_len;
            prev = COAP_OPT_OSCORE; osc_done = 1;
        } else {
            uint16_t d = u_opts[ui].number - prev, l = u_opts[ui].len;
            *p++ = (uint8_t)((d < 13 ? d : 13) << 4) | (l < 13 ? (uint8_t)l : 13);
            if (d >= 13) *p++ = (uint8_t)(d - 13);
            if (l >= 13) *p++ = (uint8_t)(l - 13);
            memcpy(p, u_opts[ui].value, l); p += l;
            prev = u_opts[ui].number; ui++;
        }
    }
    *p++ = 0xFF;
    return (uint16_t)(p - out);
}

/* Fixed 23-byte CoAP header for payload sweep (matches SW benchmark).
 * GET coap://localhost/tv1 with token=0x003974 */
static const uint8_t COAP_HDR_23[23] = {
    0x44, 0x01, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x83, 0x74, 0x76, 0x31, 0xff
};


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

    uint64_t t0, t1;
    uint64_t cyc_msg1, cyc_msg23, cyc_msg4done;

    /* Brief delay for serial terminal to synchronize */
    for (volatile long d = 0; d < 3000000; d++);
    kprintf("\r\n\r\n");
    kprintf("  EDHOC M3 Hardware-Accelerated Initiator\r\n");
    kprintf("  Method 3 | Suite 0 (X25519 + AES-CCM + HMAC-SHA256)\r\n\r\n");

    t0 = rdcycle64();
    /* ── Reset hardware ── */
    m3_sw_reset();

    /* ── Write ephemeral private key ── */
    m3_write_key256(M3_EPH_PRIV(0), EPH_PRIV_I);

    /* ── Write static private key ── */
    m3_write_key256(M3_STATIC_PRIV(0), STATIC_PRIV_I);

    /* ── Write credentials ── */
    m3_write_cred(M3_CRED_OWN(0), CRED_I);    /* Own = Initiator */
    m3_write_cred(M3_CRED_PEER(0), CRED_R);   /* Peer = Responder */

    /* ── Write parameters ──
     * Initiator: kid_own=KID_I, kid_peer=KID_R, c_x=C_I, c_peer=C_R */
    m3_set_params(KID_I, KID_R, C_I, C_R);

    /* ── Start as Initiator ── */

    
    m3_start_initiator();

    /* ══════════════════════════════════════════════════════════════════
     * MSG1: Initiator → Responder (37 bytes)
     * HW computes G_X = X25519(eph_priv, basepoint) and packs MSG1
     * ══════════════════════════════════════════════════════════════════ */
    ret = m3_wait_msg_ready(500000);
    // t1 = rdcycle64();
    // cyc_msg1 = t1 - t0;
    if (ret < 0) { kprintf("ERROR: MSG1 timeout (ret=%d)\r\n", ret); goto error; }

    msg_len = m3_get_msg_len();
    m3_read_data_out(msg_buf, msg_len);
    print_hex("MSG1", msg_buf, msg_len);

    /* Wait for Responder "ready" sync byte (0xAA) before sending MSG1.
     * This ensures the Responder is in rx_msg() before we transmit,
     * preventing UART1 RX FIFO overflow. */
    kprintf("[MSG1] Waiting for responder ready...\r\n");
    {
        int sync_timeout = 500000000;
        int sc;
        do { sc = uart1_getc(); } while (sc < 0 && --sync_timeout > 0);
        if (sync_timeout == 0) { kprintf("ERROR: Responder sync timeout\r\n"); goto error; }
    }

    /* Send MSG1 via UART to Responder */
    kprintf("[MSG1] Sending %d bytes to responder...\r\n", msg_len);
    tx_msg(msg_buf, msg_len);

    /* Acknowledge output read — maintain is_init=1 */
    m3_output_ack(1);

    /* ══════════════════════════════════════════════════════════════════
     * MSG2: Responder → Initiator (43 bytes)
     * Wait for HW to enter S_WAIT_EXT (waiting for MSG2)
     * ══════════════════════════════════════════════════════════════════ */
    ret = m3_wait_waiting(500000);
    if (ret < 0) { kprintf("ERROR: Wait for MSG2 slot timeout\r\n"); goto error; }

    /* Receive MSG2 from Responder via UART */
    kprintf("[MSG2] Waiting for responder...\r\n");
    ret = rx_msg(msg_buf, &msg_len, sizeof(msg_buf));
    if (ret < 0) { kprintf("ERROR: Failed to receive MSG2\r\n"); goto error; }
    print_hex("MSG2", msg_buf, msg_len);

    // t0 = rdcycle64();
    /* Write MSG2 to data_in[0..] and signal input_ready */
    m3_write_data_in(msg_buf, msg_len);
    kprintf("[MSG2] Writing %d bytes to hardware...\r\n", msg_len);
    m3_input_ready(1);

    /* ══════════════════════════════════════════════════════════════════
     * MSG3: Initiator → Responder (18 bytes)
     * HW processes MSG2, derives keys, computes MAC_3, encrypts
     * ══════════════════════════════════════════════════════════════════ */
    ret = m3_wait_msg_ready(500000);
    // t1 = rdcycle64();
    // cyc_msg23 = t1 - t0;
    if (ret < 0) { kprintf("ERROR: MSG3 timeout (ret=%d)\r\n", ret); goto error; }

    msg_len = m3_get_msg_len();
    /* Round up to word boundary: the HW packs the 10-byte CT body into
       3 words (with 2-byte zero pad), then the 8-byte tag into 2 words.
       msg_len=18 only covers 6 of 8 tag bytes; reading 20 (5 full words)
       ensures the complete tag is sent to the responder. */
    uint8_t wire_len = ((msg_len + 3) / 4) * 4;
    m3_read_data_out(msg_buf, wire_len);
    print_hex("MSG3", msg_buf, wire_len);

    /* Send MSG3 via UART to Responder */
    kprintf("[MSG3] Sending %d bytes to responder...\r\n", wire_len);
    tx_msg(msg_buf, wire_len);

    /* Acknowledge output read */
    m3_output_ack(1);

    /* ══════════════════════════════════════════════════════════════════
     * MSG4: Responder → Initiator (8 bytes — tag only)
     * Wait for HW to enter S_WAIT_EXT again (waiting for MSG4 tag)
     * ══════════════════════════════════════════════════════════════════ */
    ret = m3_wait_waiting(500000);
    if (ret < 0) { kprintf("ERROR: Wait for MSG4 slot timeout\r\n"); goto error; }

    /* Receive MSG4 from Responder via UART */
    kprintf("[MSG4] Waiting for responder...\r\n");
    ret = rx_msg(msg_buf, &msg_len, sizeof(msg_buf));
    if (ret < 0) { kprintf("ERROR: Failed to receive MSG4\r\n"); goto error; }
    print_hex("MSG4", msg_buf, msg_len);

    // t0 = rdcycle64();
    /* Write MSG4 tag to data_in at word offset 18 (byte 72) */
    m3_write_msg4_tag(msg_buf, msg_len);
    
    m3_input_ready(1);

    /* ══════════════════════════════════════════════════════════════════
     * Wait for EDHOC completion + OSCORE key derivation
     * ══════════════════════════════════════════════════════════════════ */
    ret = m3_wait_done(5000000);
    t1 = rdcycle64();
    cyc_msg4done = t1 - t0;
    if (ret < 0) { kprintf("ERROR: EDHOC failed (ret=%d)\r\n", ret); goto error; }

    if (!m3_oscore_keys_valid()) {
        kprintf("ERROR: OSCORE keys not valid\r\n");
        goto error;
    }

    kprintf("  EDHOC M3 HANDSHAKE SUCCESS!\r\n");
    kprintf("  Timing (cycles):\r\n");
    kprintf("    MSG1 gen:      %lu\r\n", (unsigned long)cyc_msg1);
    kprintf("    MSG2->MSG3:    %lu\r\n", (unsigned long)cyc_msg23);
    kprintf("    MSG4->Done:    %lu\r\n", (unsigned long)cyc_msg4done);
    kprintf("    Total HW:      %lu\r\n\r\n", (unsigned long)(cyc_msg1 + cyc_msg23 + cyc_msg4done));

#ifdef INCLUDE_OSCORE
    /* ================================================================== *
     * Minimal OSCORE: 1 encrypt (payload=10) + send to responder         *
     * Pulls in all coap2oscore SW overhead code for firmware size measurement. *
     * ================================================================== */
    {
        uint8_t sid_buf[1] = { C_R };
        uint8_t pt_hdr[16], aad_buf[20], piv_buf[MAX_PIV_LEN];
        uint8_t oopt_buf[16], tag_tmp[16];
        uint8_t oscore_pkt[100]; /* 35-byte payload fits easily */
        struct coap_pkt pkt;
        struct coap_opt e_opts[MAX_OPTIONS], u_opts[MAX_OPTIONS];
        uint8_t e_cnt, u_cnt;
        uint16_t plen = 35;

        /* Sync with responder */
        uart1_putc(0xBB);
        uart1_drain_rx();
        { int rdy, to = 500000000; do { rdy = uart1_getc(); } while (rdy != 0xCC && --to > 0); }

        /* coap2oscore SW overhead */
        coap_deser(COAP_HDR_23, 23 + plen, &pkt);
        option_split(&pkt, e_opts, &e_cnt, u_opts, &u_cnt);
        uint8_t pt_hdr_len = pt_hdr_build(pkt.code, e_opts, e_cnt, 1, pt_hdr);
        uint16_t pt_total = pt_hdr_len + plen;
        uint8_t piv_len = ssn2piv(0, piv_buf);
        uint8_t aad_len = build_aad(sid_buf, 1, piv_buf, piv_len, aad_buf);
        uint8_t oopt_len = oscore_opt_gen(piv_buf, piv_len, sid_buf, 1, oopt_buf);
        uint16_t ohdr_len = oscore_hdr_ser(&pkt, u_opts, u_cnt, oopt_buf, oopt_len, oscore_pkt);

        /* Feed AAD + plaintext to HW */
        int w, aad_words = (aad_len + 3) / 4;
        for (w = 0; w < aad_words; w++)
            m3_write(M3_DATA_IN(w), m3_pack_word(aad_buf, w * 4, aad_len));
        int msg_off = 0;
        for (; w < 20 && msg_off < pt_hdr_len; w++, msg_off += 4)
            m3_write(M3_DATA_IN(w), m3_pack_word(pt_hdr, msg_off, pt_hdr_len));
        int pay_off = (msg_off >= pt_hdr_len) ? (msg_off - pt_hdr_len) : 0;
        for (; w < 20 && pay_off < plen; w++, pay_off += 4)
            m3_write(M3_DATA_IN(w), gen_msg_word(pay_off, plen));

        m3_ea_encrypt(sid_buf[0], 0, aad_len, pt_total, OSCORE_TAG_LEN);
        m3_ea_wait_done(500000);

        /* Read ciphertext using dout_count */
        { uint32_t st = m3_read(M3_EA_STATUS); int dw = (st >> 8) & 0x1F;
          for (int r = 0; r < dw; r++) { uint32_t v = m3_read(M3_DATA_OUT(r));
            for (int b = 0; b < 4; b++) { int pos = r*4+b;
              if (pos < (int)pt_total) oscore_pkt[ohdr_len+pos] = (uint8_t)(v>>((3-b)*8)); }}}

        m3_ea_read_tag_out(tag_tmp);
        memcpy(oscore_pkt + ohdr_len + pt_total, tag_tmp, OSCORE_TAG_LEN);
        uint16_t oscore_total = ohdr_len + pt_total + OSCORE_TAG_LEN;

        /* Send OSCORE packet + wait ACK */
        uart1_putc((uint8_t)(oscore_total >> 8));
        uart1_putc((uint8_t)(oscore_total & 0xFF));
        for (uint16_t k = 0; k < oscore_total; k++) uart1_putc(oscore_pkt[k]);
        int ack, ato = 500000000;
        do { ack = uart1_getc(); } while (ack < 0 && --ato > 0);
        kprintf("  OSCORE encrypt+send: %s\r\n", (ack == 0xAA) ? "OK" : "FAIL");
    }
#endif /* INCLUDE_OSCORE */

#if 0  /* ── Full sweep benchmark (commented out for size measurement) ──── */
    /* ================================================================== */
    /* OSCORE Hardware Benchmark: coap2oscore with HW AES-CCM              */
    /*                                                                     */
    /* Paired with Responder over UART for end-to-end verification:        */
    /*   Initiator encrypts → sends OSCORE packet → Responder decrypts     */
    /*   → verifies → sends ACK. Both sides measure timing.               */
    /*                                                                     */
    /* Includes all constant SW overhead from coap2oscore():                */
    /*   coap_deserialize → option_split → plaintext_build → ssn2piv →     */
    /*   build_aad → HW AEAD → oscore_opt_gen → oscore_serialize          */
    /* Nonce is constructed by HW internally (design advantage).           */
    /* ================================================================== */
    uint8_t sid_buf[1] = { C_R };

    uint8_t pt_hdr[16];
    uint8_t aad_buf[20];
    uint8_t piv_buf[MAX_PIV_LEN];
    uint8_t oopt_buf[16];
    uint8_t tag_tmp[16];

    /* OSCORE wire packet: header + ciphertext + tag.
     * Max = ~25 header + 1003 ciphertext + 8 tag ≈ 1036 bytes. */
    uint8_t oscore_pkt[1100];

    struct coap_pkt pkt;
    struct coap_opt e_opts[MAX_OPTIONS], u_opts[MAX_OPTIONS];
    uint8_t e_cnt, u_cnt;

    /* Signal responder that OSCORE benchmark is starting */
    uart1_putc(0xBB);

    /* ── Encrypt + Send sweep ── */
    kprintf("[HW-ENCRYPT] coap2oscore + HW AES-CCM (N=%d per size):\r\n", N_ITER);
    kprintf("Payload |   Avg Cycles |   Avg us | Verify\r\n");
    kprintf("--------|--------------|----------|-------\r\n");

    /* Wait for responder ready (ensures it finished printing headers
     * and is now listening on UART1 RX before we start sending data) */
    uart1_drain_rx();
    {
        int rdy, rdy_timeout = 500000000;
        do { rdy = uart1_getc(); } while (rdy != 0xCC && --rdy_timeout > 0);
    }

    for (int ps = 0; ps < NUM_SWEEPS; ps++) {
        uint16_t plen = SWEEP_SIZES[ps];

        uint64_t total = 0;
        int failures = 0;

        for (int i = 0; i < N_ITER; i++) {
            t0 = rdcycle64();

            /* Step 1: CoAP deserialize */
            coap_deser(COAP_HDR_23, 23 + plen, &pkt);

            /* Step 2: Option split */
            option_split(&pkt, e_opts, &e_cnt, u_opts, &u_cnt);

            /* Step 3: Plaintext header */
            uint8_t pt_hdr_len = pt_hdr_build(pkt.code, e_opts, e_cnt,
                                              pkt.payload_len > 0, pt_hdr);
            uint16_t pt_total = pt_hdr_len + plen;

            /* Step 4: SSN→PIV */
            uint8_t piv_len = ssn2piv((uint32_t)i, piv_buf);

            /* Step 5: AAD */
            uint8_t aad_len = build_aad(sid_buf, 1, piv_buf, piv_len, aad_buf);

            /* Step 6: OSCORE option */
            uint8_t oopt_len = oscore_opt_gen(piv_buf, piv_len,
                                              sid_buf, 1, oopt_buf);

            /* Step 7: Serialize OSCORE header to oscore_pkt[] */
            uint16_t ohdr_len = oscore_hdr_ser(
                &pkt, u_opts, u_cnt, oopt_buf, oopt_len, oscore_pkt);

            /* Step 8: Feed AAD + plaintext to HW, capture ciphertext */
            int w;
            int aad_words = (aad_len + 3) / 4;
            for (w = 0; w < aad_words; w++)
                m3_write(M3_DATA_IN(w), m3_pack_word(aad_buf, w * 4, aad_len));

            int msg_off = 0;
            for (; w < 20 && msg_off < pt_hdr_len; w++, msg_off += 4)
                m3_write(M3_DATA_IN(w), m3_pack_word(pt_hdr, msg_off, pt_hdr_len));

            int pay_off = (msg_off >= pt_hdr_len) ? (msg_off - pt_hdr_len) : 0;
            for (; w < 20 && pay_off < plen; w++, pay_off += 4)
                m3_write(M3_DATA_IN(w), gen_msg_word(pay_off, plen));

            m3_ea_encrypt(sid_buf[0], (uint32_t)i, aad_len, pt_total, OSCORE_TAG_LEN);

            /* Feed remaining chunks, reading output between each.
             * Use dout_count from EA_STATUS bits[12:8] to know how many
             * valid output words are in data_out. */
            int ct_off = 0;
            while (pay_off < plen) {
                uint32_t st;
                while (!((st = m3_read(M3_EA_STATUS)) & M3_EA_STATUS_INPUT_RDY));
                int dw = (st >> 8) & 0x1F;
                /* Read dw words of ciphertext from data_out */
                for (int r = 0; r < dw; r++) {
                    uint32_t v = m3_read(M3_DATA_OUT(r));
                    for (int b = 0; b < 4; b++) {
                        int pos = ct_off + r*4 + b;
                        if (pos < (int)pt_total)
                            oscore_pkt[ohdr_len + pos] = (uint8_t)(v >> ((3-b)*8));
                    }
                }
                ct_off += dw * 4;
                if (ct_off > (int)pt_total) ct_off = pt_total;
                /* Write next input chunk */
                for (w = 0; w < 20 && pay_off < plen; w++, pay_off += 4)
                    m3_write(M3_DATA_IN(w), gen_msg_word(pay_off, plen));
                m3_write(M3_EA_CHUNK, 0);
            }

            m3_ea_wait_done(500000);

            /* Read final output chunk using dout_count */
            {
                uint32_t st = m3_read(M3_EA_STATUS);
                int dw = (st >> 8) & 0x1F;
                for (int r = 0; r < dw; r++) {
                    uint32_t v = m3_read(M3_DATA_OUT(r));
                    for (int b = 0; b < 4; b++) {
                        int pos = ct_off + r*4 + b;
                        if (pos < (int)pt_total)
                            oscore_pkt[ohdr_len + pos] = (uint8_t)(v >> ((3-b)*8));
                    }
                }
            }

            /* Read tag, append to packet */
            m3_ea_read_tag_out(tag_tmp);
            memcpy(oscore_pkt + ohdr_len + pt_total, tag_tmp, OSCORE_TAG_LEN);

            uint16_t oscore_total = ohdr_len + pt_total + OSCORE_TAG_LEN;

            t1 = rdcycle64();
            total += (t1 - t0);

            /* ── Send OSCORE packet to Responder via UART ── */
            uart1_putc((uint8_t)(oscore_total >> 8));
            uart1_putc((uint8_t)(oscore_total & 0xFF));
            for (uint16_t k = 0; k < oscore_total; k++)
                uart1_putc(oscore_pkt[k]);

            /* Wait for ACK from Responder (0xAA=OK, 0xFF=fail) */
            int ack, ack_timeout = 500000000;
            do { ack = uart1_getc(); } while (ack < 0 && --ack_timeout > 0);
            if (ack != 0xAA) failures++;
        }

        uint32_t avg = (uint32_t)(total / N_ITER);
        uint32_t us  = (uint32_t)(((uint64_t)avg * 1000000ULL) / BENCHMARK_CPU_HZ);
        kprintf("  %5u  |  %10lu  |  %6lu  | %s\r\n",
                (unsigned)plen, (unsigned long)avg, (unsigned long)us,
                failures == 0 ? "OK" : "FAIL");
    }

    kprintf("\r\nIncludes CoAP parse/option split/plaintext/AAD/serialize + CT readback.\r\n");
    kprintf("Nonce constructed by HW (design advantage).\r\n");
    kprintf("\r\n=== HW OSCORE Encrypt Benchmark Done ===\r\n");
#endif /* Full sweep benchmark */

    while (1) {}
    return 0;

error:
    kprintf("\r\n=== EDHOC HANDSHAKE FAILED ===\r\n");
    kprintf("Status: 0x%lx\r\n", (unsigned long)m3_status());
    while (1);
    return -1;
}

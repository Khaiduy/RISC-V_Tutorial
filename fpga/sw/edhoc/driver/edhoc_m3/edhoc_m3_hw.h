// =============================================================================
// EDHOC Method 3 Hardware Accelerator — C Driver Header
//
// Register map matches edhoc_regmap.v (edhoc_m3_top internal bus).
// Suite 0: X25519 + HMAC-SHA256 + AES-CCM-16-64-128
//
// Data packing: big-endian word order (word 0 = MSB of 256-bit key).
// data_in[0] bits[31:24] = first byte of EDHOC message.
//
// Status bits: done, error, msg_ready, waiting, oscore_valid are live (not sticky).
// msg_ready is set by HW when output is ready, cleared by output_ack.
// =============================================================================
#ifndef EDHOC_M3_HW_H
#define EDHOC_M3_HW_H

#include <stdint.h>

// Base address — must match EDHOCM3Params.address in Scala config
#ifndef EDHOC_M3_BASE
#define EDHOC_M3_BASE 0x10040000UL
#endif

// =============================================================================
// Register Offsets (matches edhoc_regmap.v WA_* decode)
// =============================================================================
#define M3_EPH_PRIV(i)       (0x000 + (i) * 4)   // i=0..7, 256-bit ephemeral private key
#define M3_STATIC_PRIV(i)    (0x020 + (i) * 4)   // i=0..7, 256-bit static private key
#define M3_CONTROL            0x040               // Control register
#define M3_STATUS             0x044               // Status register (RO)
#define M3_PARAMS             0x048               // Protocol parameters
#define M3_CRED_OWN(i)       (0x050 + (i) * 4)   // i=0..13, 55-byte own credential
#define M3_CRED_PEER(i)      (0x090 + (i) * 4)   // i=0..13, 55-byte peer credential
#define M3_DATA_IN(i)        (0x0D0 + (i) * 4)   // i=0..19, 80-byte input data memory
#define M3_DATA_OUT(i)       (0x120 + (i) * 4)   // i=0..19, 80-byte output data memory (RO)
#define M3_MSG_LEN            0x170               // Message length in bytes (RO)

// External AEAD (OSCORE) registers
#define M3_EA_CONTROL         0x180               // [0]=start, [1]=encrypt, [2]=use_sender_key, [7:3]=tag_len
#define M3_EA_LENGTHS         0x184               // [15:0]=msg_len, [31:16]=aad_len
#define M3_EA_NONCE(i)       (0x188 + (i) * 4)   // i=0..1, nonce PIV data
#define M3_EA_TAG_EXP(i)     (0x198 + (i) * 4)   // i=0..3, 128-bit expected tag
#define M3_EA_STATUS          0x1A8               // [0]=done, [1]=tag_match, [2]=input_ready, [3]=output_valid, [12:8]=dout_count (RO)
#define M3_EA_TAG_OUT(i)     (0x1AC + (i) * 4)   // i=0..3, 128-bit tag output (RO)
#define M3_EA_CHUNK           0x1BC               // Write to signal chunk ready (any value, write-only)

// =============================================================================
// Control Register Bits (M3_CONTROL = 0x040)
//   Self-clearing pulses: start, input_ready, output_ack
//   Level signals: is_init, reset
// =============================================================================
#define M3_CTRL_START         (1 << 0)   // Start protocol (pulse)
#define M3_CTRL_IS_INIT       (1 << 1)   // 1=Initiator, 0=Responder (level)
#define M3_CTRL_INPUT_READY   (1 << 2)   // Input message written, proceed (pulse)
#define M3_CTRL_OUTPUT_ACK    (1 << 3)   // Acknowledge output read (pulse)
#define M3_CTRL_RESET         (1 << 31)  // Software reset (level, active high)

// =============================================================================
// Status Register Bits (M3_STATUS = 0x044, read-only)
// =============================================================================
#define M3_STATUS_DONE        (1 << 0)   // Protocol complete
#define M3_STATUS_ERROR       (1 << 1)   // AEAD tag verification failed
#define M3_STATUS_MSG_READY   (1 << 2)   // Output message available
#define M3_STATUS_WAITING     (1 << 3)   // Waiting for input (S_WAIT_EXT)
#define M3_STATUS_OSCORE_OK   (1 << 4)   // OSCORE keys derived
#define M3_STATUS_PHASE_MASK  (0x7 << 8) // Current FSM phase [10:8]
#define M3_STATUS_PHASE_SHIFT 8

// =============================================================================
// EA Control Register Bits (M3_EA_CONTROL = 0x180)
// =============================================================================
#define M3_EA_START           (1 << 0)   // Start ext AEAD operation (pulse)
#define M3_EA_ENCRYPT         (1 << 1)   // 1=encrypt, 0=decrypt
#define M3_EA_USE_SENDER_KEY  (1 << 2)   // 1=RF[6] (sender key), 0=RF[7] (recv key)
// tag_len in bits [7:3] — value is number of bytes (e.g., 8 for 64-bit tag)
// EA Status Register Bits (M3_EA_STATUS = 0x1A8, read-only)
#define M3_EA_STATUS_DONE      (1 << 0)
#define M3_EA_STATUS_TAG_OK    (1 << 1)
#define M3_EA_STATUS_INPUT_RDY (1 << 2)  // Chunked: FSM consumed buffer, needs next chunk
#define M3_EA_STATUS_OUTPUT_VLD (1 << 3) // Chunked: output data available in data_out
#define M3_EA_DOUT_COUNT(s)    (((s) >> 8) & 0x1F) // Number of output words captured

// =============================================================================
// Low-Level Access Macros
// =============================================================================
#define M3_REG(off)    (*(volatile uint32_t *)(EDHOC_M3_BASE + (off)))

static inline void     m3_write(uint32_t off, uint32_t v) { M3_REG(off) = v; }
static inline uint32_t m3_read(uint32_t off)              { return M3_REG(off); }

/** Read RISC-V mcycle CSR (cycle counter) for timing measurements */
static inline uint32_t read_mcycle(void) {
    uint32_t val;
    asm volatile ("csrr %0, mcycle" : "=r"(val));
    return val;
}

// =============================================================================
// Setup Helpers
// =============================================================================

/** Software reset: assert reset, brief delay, deassert */
static inline void m3_sw_reset(void) {
    m3_write(M3_CONTROL, M3_CTRL_RESET);
    for (volatile int i = 0; i < 100; i++);
    m3_write(M3_CONTROL, 0);
}

/** Write 256-bit key (big-endian word order: key[0..31] → reg[0..7]) */
static inline void m3_write_key256(uint32_t base_off, const uint8_t key[32]) {
    for (int i = 0; i < 8; i++) {
        uint32_t w = ((uint32_t)key[i*4+0] << 24) |
                     ((uint32_t)key[i*4+1] << 16) |
                     ((uint32_t)key[i*4+2] <<  8) |
                     ((uint32_t)key[i*4+3]);
        m3_write(base_off + i * 4, w);
    }
}

/** Write protocol parameters: kid_own, kid_peer, c_x, c_peer */
static inline void m3_set_params(uint8_t kid_own, uint8_t kid_peer,
                                  uint8_t c_x, uint8_t c_peer) {
    m3_write(M3_PARAMS, (uint32_t)kid_own          |
                        ((uint32_t)kid_peer  << 8)  |
                        ((uint32_t)c_x       << 16) |
                        ((uint32_t)c_peer    << 24));
}

/** Write 55-byte CCS credential (padded to 14 x 32-bit = 56 bytes) */
static inline void m3_write_cred(uint32_t base_off, const uint8_t cred[55]) {
    for (int i = 0; i < 14; i++) {
        uint32_t w = 0;
        for (int j = 0; j < 4; j++) {
            int byte_idx = i * 4 + j;
            if (byte_idx < 55)
                w |= ((uint32_t)cred[byte_idx]) << (24 - j * 8);
        }
        m3_write(base_off + i * 4, w);
    }
}

// =============================================================================
// Data I/O
//
// data_in/data_out: 20 x 32-bit (80 bytes), big-endian word order.
//   msg[0] → DATA_IN[0] bits[31:24]
//   msg[1] → DATA_IN[0] bits[23:16]
//   msg[2] → DATA_IN[0] bits[15:8]
//   msg[3] → DATA_IN[0] bits[7:0]
//   msg[4] → DATA_IN[1] bits[31:24]
//   ...
// =============================================================================

/** Write variable-length message to data_in starting at byte 0 (up to 80 bytes).
 *  Used for MSG1 (responder loads) and MSG2 (initiator loads).
 *  Packs 4 bytes into each 32-bit word locally (data_in is write-only). */
static inline void m3_write_data_in(const uint8_t *msg, int len) {
    int num_words = (len + 3) / 4;
    for (int w = 0; w < 20; w++) {
        uint32_t val = 0;
        if (w < num_words) {
            for (int b = 0; b < 4; b++) {
                int idx = w * 4 + b;
                if (idx < len)
                    val |= ((uint32_t)msg[idx]) << ((3 - b) * 8);
            }
        }
        m3_write(M3_DATA_IN(w), val);
    }
}

/** Write MSG3 ciphertext (18 bytes) into data_in at word offset 15 (byte 60).
 *  The HW CTF reads body from data_in[15:17] and tag from data_in[18:19].
 *  Used by Responder when loading received MSG3.
 *  Packs 4 bytes into each word locally (data_in is write-only). */
static inline void m3_write_msg3_ct(const uint8_t *msg3, int len) {
    int num_words = (len + 3) / 4;
    for (int w = 0; w < num_words && (15 + w) < 20; w++) {
        uint32_t val = 0;
        for (int b = 0; b < 4; b++) {
            int idx = w * 4 + b;
            if (idx < len)
                val |= ((uint32_t)msg3[idx]) << ((3 - b) * 8);
        }
        m3_write(M3_DATA_IN(15 + w), val);
    }
}

/** Write MSG4 tag (8 bytes) into data_in at word offset 18 (byte 72).
 *  Used by Initiator when loading received MSG4.
 *  Packs 4 bytes into each word locally (data_in is write-only). */
static inline void m3_write_msg4_tag(const uint8_t *msg4, int len) {
    int num_words = (len + 3) / 4;
    for (int w = 0; w < num_words && (18 + w) < 20; w++) {
        uint32_t val = 0;
        for (int b = 0; b < 4; b++) {
            int idx = w * 4 + b;
            if (idx < len)
                val |= ((uint32_t)msg4[idx]) << ((3 - b) * 8);
        }
        m3_write(M3_DATA_IN(18 + w), val);
    }
}

/** Write message words to data_in at a specific word offset */
static inline void m3_write_data_in_word(int word_idx, uint32_t val) {
    m3_write(M3_DATA_IN(word_idx), val);
}

/** Read message from data_out (up to 80 bytes) */
static inline void m3_read_data_out(uint8_t *msg, int len) {
    for (int i = 0; i < len && i < 80; i++) {
        int reg_idx  = i / 4;
        int byte_pos = 3 - (i % 4);
        uint32_t val = m3_read(M3_DATA_OUT(reg_idx));
        msg[i] = (uint8_t)(val >> (byte_pos * 8));
    }
}

/** Read msg_len register (HW-set after output generation) */
static inline uint8_t m3_get_msg_len(void) {
    return (uint8_t)(m3_read(M3_MSG_LEN) & 0xFF);
}

// =============================================================================
// Protocol Flow
// =============================================================================

/** Start as Initiator: set is_init=1, pulse start */
static inline void m3_start_initiator(void) {
    m3_write(M3_CONTROL, M3_CTRL_START | M3_CTRL_IS_INIT);
}

/** Start as Responder: set is_init=0, pulse start */
static inline void m3_start_responder(void) {
    m3_write(M3_CONTROL, M3_CTRL_START);
}

/** Signal that input data has been written to data_in.
 *  is_init: 1 for Initiator, 0 for Responder — must be set on EVERY control write. */
static inline void m3_input_ready(int is_init) {
    m3_write(M3_CONTROL, M3_CTRL_INPUT_READY | (is_init ? M3_CTRL_IS_INIT : 0));
}

/** Acknowledge that output has been read from data_out.
 *  is_init: 1 for Initiator, 0 for Responder. */
static inline void m3_output_ack(int is_init) {
    m3_write(M3_CONTROL, M3_CTRL_OUTPUT_ACK | (is_init ? M3_CTRL_IS_INIT : 0));
}

// =============================================================================
// Status Polling
// =============================================================================

static inline uint32_t m3_status(void)          { return m3_read(M3_STATUS); }
static inline int m3_is_done(void)               { return (m3_status() & M3_STATUS_DONE) != 0; }
static inline int m3_has_error(void)             { return (m3_status() & M3_STATUS_ERROR) != 0; }
static inline int m3_is_msg_ready(void)          { return (m3_status() & M3_STATUS_MSG_READY) != 0; }
static inline int m3_is_waiting(void)            { return (m3_status() & M3_STATUS_WAITING) != 0; }
static inline int m3_oscore_keys_valid(void)     { return (m3_status() & M3_STATUS_OSCORE_OK) != 0; }

// =============================================================================
// Blocking Wait Helpers (with timeout)
// =============================================================================

/** Wait for msg_ready (output available) */
static inline int m3_wait_msg_ready(uint32_t timeout) {
    for (uint32_t i = 0; i < timeout; i++) {
        if (m3_is_msg_ready()) return 0;
        if (m3_has_error())    return -1;
    }
    return -2;
}

/** Wait for waiting (HW is waiting for input) */
static inline int m3_wait_waiting(uint32_t timeout) {
    for (uint32_t i = 0; i < timeout; i++) {
        if (m3_is_waiting()) return 0;
        if (m3_has_error())  return -1;
    }
    return -2;
}

/** Wait for done (protocol complete) */
static inline int m3_wait_done(uint32_t timeout) {
    for (uint32_t i = 0; i < timeout; i++) {
        if (m3_is_done())    return 0;
        if (m3_has_error())  return -1;
    }
    return -2;
}

// =============================================================================
// External AEAD (OSCORE) Interface
//
// After EDHOC handshake completes (oscore_keys_valid=1), use the ext_aead
// interface to encrypt/decrypt OSCORE-protected CoAP payloads.
//
// Data flow:
//   1. Write AAD + plaintext/ciphertext to data_in[0..N]
//   2. Configure ea_lengths, ea_nonce, ea_control
//   3. Wait for ea_done
//   4. Read result from data_out[0..N] and tag from ea_tag_out
//
// Nonce construction (done by hardware):
//   nonce = {0x01, 48'h0, sender_id, partial_iv} XOR Common_IV
// =============================================================================

/** Start ext_aead encrypt operation */
static inline void m3_ea_encrypt(uint8_t sender_id, uint32_t partial_iv,
                                  uint16_t aad_len, uint16_t msg_len,
                                  uint8_t tag_len) {
    m3_write(M3_EA_LENGTHS, ((uint32_t)aad_len << 16) | (uint32_t)msg_len);
    m3_write(M3_EA_NONCE(0), ((uint32_t)sender_id << 24) | ((partial_iv >> 16) & 0xFFFFFF));
    m3_write(M3_EA_NONCE(1), (partial_iv & 0xFFFF) << 16);
    m3_write(M3_EA_CONTROL, M3_EA_START | M3_EA_ENCRYPT | M3_EA_USE_SENDER_KEY |
                            ((uint32_t)tag_len << 3));
}

/** Start ext_aead decrypt operation */
static inline void m3_ea_decrypt(uint8_t sender_id, uint32_t partial_iv,
                                  uint16_t aad_len, uint16_t msg_len,
                                  uint8_t tag_len) {
    m3_write(M3_EA_LENGTHS, ((uint32_t)aad_len << 16) | (uint32_t)msg_len);
    m3_write(M3_EA_NONCE(0), ((uint32_t)sender_id << 24) | ((partial_iv >> 16) & 0xFFFFFF));
    m3_write(M3_EA_NONCE(1), (partial_iv & 0xFFFF) << 16);
    m3_write(M3_EA_CONTROL, M3_EA_START | ((uint32_t)tag_len << 3));
    // encrypt=0, use_sender_key=0 (recipient key)
}

/** Wait for ext_aead done */
static inline int m3_ea_wait_done(uint32_t timeout) {
    for (uint32_t i = 0; i < timeout; i++) {
        if (m3_read(M3_EA_STATUS) & M3_EA_STATUS_DONE)
            return 0;
    }
    return -2;
}

/** Check ext_aead tag match (after decrypt) */
static inline int m3_ea_tag_match(void) {
    return (m3_read(M3_EA_STATUS) & M3_EA_STATUS_TAG_OK) != 0;
}

/** Write expected tag for decrypt verification */
static inline void m3_ea_write_tag_exp(const uint8_t tag[16]) {
    for (int i = 0; i < 4; i++) {
        uint32_t w = ((uint32_t)tag[i*4+0] << 24) |
                     ((uint32_t)tag[i*4+1] << 16) |
                     ((uint32_t)tag[i*4+2] <<  8) |
                     ((uint32_t)tag[i*4+3]);
        m3_write(M3_EA_TAG_EXP(i), w);
    }
}

/** Read tag output (after encrypt) */
static inline void m3_ea_read_tag_out(uint8_t tag[16]) {
    for (int i = 0; i < 4; i++) {
        uint32_t w = m3_read(M3_EA_TAG_OUT(i));
        tag[i*4+0] = (uint8_t)(w >> 24);
        tag[i*4+1] = (uint8_t)(w >> 16);
        tag[i*4+2] = (uint8_t)(w >>  8);
        tag[i*4+3] = (uint8_t)(w);
    }
}

// =============================================================================
// Chunked ext_aead (for payloads > 80 bytes)
//
// Reuse data_in[0..19] as an 80-byte input buffer and data_out[0..19]
// as an 80-byte output buffer. For payloads larger than one buffer:
//   1. Fill data_in with first chunk (AAD + msg), start operation
//   2. When FSM sets INPUT_READY: read data_out, fill data_in, write M3_EA_CHUNK
//   3. Repeat until all data fed, then wait for EA_DONE
//   4. Read final data_out and tag
// =============================================================================

/** Pack up to 4 bytes (big-endian) from a byte array starting at byte offset */
static inline uint32_t m3_pack_word(const uint8_t *data, int offset, int total_len) {
    uint32_t val = 0;
    for (int b = 0; b < 4; b++) {
        int idx = offset + b;
        if (idx < total_len)
            val |= ((uint32_t)data[idx]) << ((3 - b) * 8);
    }
    return val;
}

#endif // EDHOC_M3_HW_H

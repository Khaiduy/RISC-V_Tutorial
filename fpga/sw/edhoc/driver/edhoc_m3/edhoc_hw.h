// =============================================================================
// EDHOC Hardware Accelerator - C Driver Header
// Register map matches chipyard.crypto.edhoc.EDHOCCtrlRegs + EDHOCTLL wrapper
//
// Data packing convention (big-endian message order):
//   data_in[295:288] = first byte of EDHOC message (CBOR header)
//   In MMIO: DATA_IN[0][31:24] = data_in[295:288]
//
// The wrapper does: edhoc_inst.io.data_in := Cat(data_in.reverse)(319, 24)
//   i.e., reg[0] is MSB, reg[9] is LSB, bottom 24 bits discarded.
//
// Sticky status bits (done, msg_ready, oscore_valid, aead_done, aead_tag_valid)
//   must be cleared by writing control[6]=1 (CLEAR_FLAGS).
//   output_valid is NOT sticky - cleared by hardware via output_ack.
// =============================================================================
#ifndef EDHOC_HW_H
#define EDHOC_HW_H

#include <stdint.h>

// Base address - must match EDHOCParams.address in Scala config
#ifndef EDHOC_BASE
#define EDHOC_BASE 0x10040000UL
#endif

// =============================================================================
// Register Offsets (matches EDHOCCtrlRegs.scala)
// =============================================================================
#define EDHOC_TRNG_CONTROL     0x00  // [0]=trng_en, [1]=xdrbg_bypass
#define EDHOC_EPH_KEY(i)      (0x04 + (i) * 4)  // i=0..7, 256-bit ephemeral key
#define EDHOC_PARAMS_0         0x24  // [7:0]=c_x, [15:8]=method, [23:16]=suite, [31:24]=id_cred_psk
#define EDHOC_PARAMS_1         0x28  // [7:0]=kid_initiator, [15:8]=kid_responder
#define EDHOC_ID_INIT(i)      (0x2C + (i) * 4)  // i=0..1, 64-bit initiator ID
#define EDHOC_ID_RESP(i)      (0x34 + (i) * 4)  // i=0..1, 64-bit responder ID
#define EDHOC_CONTROL          0x3C  // Control register (see bits below)
#define EDHOC_STATUS           0x40  // Status register (read-only, see bits below)
#define EDHOC_DATA_IN(i)      (0x44 + (i) * 4)  // i=0..9, 296-bit message input
#define EDHOC_DATA_OUT(i)     (0x6C + (i) * 4)  // i=0..9, 296-bit message output (RO)
#define EDHOC_AEAD_SENDER_ID   0x94  // [7:0] sender ID for nonce
#define EDHOC_AEAD_PIV(i)    (0x98 + (i) * 4)  // i=0..1, 40-bit partial IV
#define EDHOC_AEAD_AAD(i)    (0xA0 + (i) * 4)  // i=0..3, 128-bit AAD
#define EDHOC_AEAD_LENGTHS     0xB0  // [3:0]=aad_len, [7:4]=data_len
#define EDHOC_AEAD_DIN(i)    (0xB4 + (i) * 4)  // i=0..3, 128-bit AEAD data in
#define EDHOC_AEAD_DOUT(i)   (0xC4 + (i) * 4)  // i=0..3, 128-bit AEAD data out (RO)
#define EDHOC_AEAD_TAG(i)    (0xD4 + (i) * 4)  // i=0..3, 128-bit AEAD tag (RO)
#define EDHOC_AEAD_ETAG(i)   (0xE4 + (i) * 4)  // i=0..3, 128-bit expected tag
#define EDHOC_MSG_VALID        0xF4  // Write 1 to pulse msg_valid
#define EDHOC_OUTPUT_ACK       0xF8  // Write 1 to pulse output_ack

// =============================================================================
// Control Register Bits (EDHOC_CONTROL = 0x3C)
// =============================================================================
#define CTRL_START              (1 << 0)  // Start EDHOC protocol (pulse)
#define CTRL_INITIATOR          (1 << 1)  // 1=Initiator, 0=Responder
#define CTRL_AEAD_START         (1 << 2)  // Start external AEAD op (pulse)
#define CTRL_AEAD_ENCRYPT       (1 << 3)  // 1=encrypt, 0=decrypt
#define CTRL_AEAD_USE_SENDER    (1 << 4)  // 1=sender key, 0=recipient key
#define CTRL_RESET              (1 << 5)  // Software reset (hold high = reset)
#define CTRL_CLEAR_FLAGS        (1 << 6)  // Clear sticky status (auto-clears)

// =============================================================================
// Status Register Bits (EDHOC_STATUS = 0x40, read-only)
// =============================================================================
#define STATUS_DONE              (1 << 0)  // Protocol complete (sticky)
#define STATUS_ERROR             (1 << 1)  // Error occurred (from HW)
#define STATUS_MSG_READY         (1 << 2)  // Ready for next input message (sticky)
#define STATUS_OUTPUT_VALID      (1 << 3)  // Output available (HW, cleared by output_ack)
#define STATUS_OSCORE_VALID      (1 << 4)  // OSCORE keys derived (sticky)
#define STATUS_AEAD_DONE         (1 << 5)  // External AEAD complete (sticky)
#define STATUS_AEAD_TAG_VALID    (1 << 6)  // AEAD tag verified OK (sticky)
// bit 7 reserved
#define STATUS_CURRENT_MSG_MASK  (0x3 << 8)
#define STATUS_CURRENT_MSG_SHIFT 8

// =============================================================================
// TRNG Control Bits (EDHOC_TRNG_CONTROL = 0x00)
// =============================================================================
#define TRNG_EN                 (1 << 0)
#define TRNG_XDRBG_BYPASS      (1 << 1)

// =============================================================================
// Low-Level Access
// =============================================================================
#define EDHOC_REG(off)   (*(volatile uint32_t *)(EDHOC_BASE + (off)))

static inline void     edhoc_write(uint32_t off, uint32_t v) { EDHOC_REG(off) = v; }
static inline uint32_t edhoc_read(uint32_t off)              { return EDHOC_REG(off); }

// =============================================================================
// Setup Helpers
// =============================================================================

static inline void edhoc_sw_reset(void) {
    edhoc_write(EDHOC_CONTROL, CTRL_RESET);
    for (volatile int i = 0; i < 100; i++);  // brief delay
    edhoc_write(EDHOC_CONTROL, 0);
}

static inline void edhoc_clear_flags(void) {
    uint32_t ctrl = edhoc_read(EDHOC_CONTROL);
    edhoc_write(EDHOC_CONTROL, ctrl | CTRL_CLEAR_FLAGS);
}

static inline void edhoc_set_params(uint8_t c_x, uint8_t method,
                                     uint8_t suite, uint8_t id_cred_psk) {
    edhoc_write(EDHOC_PARAMS_0,
        (uint32_t)c_x            |
        ((uint32_t)method << 8)  |
        ((uint32_t)suite  << 16) |
        ((uint32_t)id_cred_psk << 24));
}

static inline void edhoc_set_kids(uint8_t kid_i, uint8_t kid_r) {
    edhoc_write(EDHOC_PARAMS_1, (uint32_t)kid_i | ((uint32_t)kid_r << 8));
}

static inline void edhoc_set_id_initiator(uint64_t id) {
    edhoc_write(EDHOC_ID_INIT(0), (uint32_t)(id));
    edhoc_write(EDHOC_ID_INIT(1), (uint32_t)(id >> 32));
}

static inline void edhoc_set_id_responder(uint64_t id) {
    edhoc_write(EDHOC_ID_RESP(0), (uint32_t)(id));
    edhoc_write(EDHOC_ID_RESP(1), (uint32_t)(id >> 32));
}

static inline void edhoc_set_ephemeral_key(const uint32_t key[8]) {
    for (int i = 0; i < 8; i++)
        edhoc_write(EDHOC_EPH_KEY(i), key[i]);
}

// =============================================================================
// Data I/O (296 bits in 10 x 32-bit registers, big-endian byte order)
//
// Byte-to-register mapping:
//   msg[0] -> DATA_IN[0] bits[31:24]  (= Verilog data_in[295:288])
//   msg[1] -> DATA_IN[0] bits[23:16]  (= Verilog data_in[287:280])
//   msg[2] -> DATA_IN[0] bits[15:8]
//   msg[3] -> DATA_IN[0] bits[7:0]
//   msg[4] -> DATA_IN[1] bits[31:24]
//   ...
//   msg[36] -> DATA_IN[9] bits[31:24] (= Verilog data_in[7:0])
//
// Only bytes 0-36 (37 bytes = 296 bits) are meaningful.
// DATA_IN[9] only uses bits[31:24] (the rest is the 24-bit discard zone).
// =============================================================================

static inline void edhoc_write_data_in(const uint8_t *msg, int len) {
    for (int i = 0; i < 10; i++)
        edhoc_write(EDHOC_DATA_IN(i), 0);

    for (int i = 0; i < len && i < 37; i++) {
        int reg_idx  = i / 4;
        int byte_pos = 3 - (i % 4);  // big-endian: byte 0 -> bits[31:24]
        uint32_t val = edhoc_read(EDHOC_DATA_IN(reg_idx));
        val |= ((uint32_t)msg[i]) << (byte_pos * 8);
        edhoc_write(EDHOC_DATA_IN(reg_idx), val);
    }
}

static inline void edhoc_read_data_out(uint8_t *msg, int len) {
    for (int i = 0; i < len && i < 37; i++) {
        int reg_idx  = i / 4;
        int byte_pos = 3 - (i % 4);
        uint32_t val = edhoc_read(EDHOC_DATA_OUT(reg_idx));
        msg[i] = (uint8_t)(val >> (byte_pos * 8));
    }
}

// =============================================================================
// Protocol Flow
// =============================================================================

static inline void edhoc_start_initiator(int bypass) {
    edhoc_write(EDHOC_TRNG_CONTROL,
        TRNG_EN | (bypass ? TRNG_XDRBG_BYPASS : 0));
    edhoc_write(EDHOC_CONTROL, CTRL_START | CTRL_INITIATOR);
}

static inline void edhoc_start_responder(int bypass) {
    edhoc_write(EDHOC_TRNG_CONTROL,
        TRNG_EN | (bypass ? TRNG_XDRBG_BYPASS : 0));
    edhoc_write(EDHOC_CONTROL, CTRL_START);  // initiator=0
}

// =============================================================================
// Status Polling
// =============================================================================

static inline uint32_t edhoc_status(void)     { return edhoc_read(EDHOC_STATUS); }
static inline int edhoc_is_done(void)          { return (edhoc_status() & STATUS_DONE) != 0; }
static inline int edhoc_has_error(void)        { return (edhoc_status() & STATUS_ERROR) != 0; }
static inline int edhoc_is_msg_ready(void)     { return (edhoc_status() & STATUS_MSG_READY) != 0; }
static inline int edhoc_is_output_valid(void)  { return (edhoc_status() & STATUS_OUTPUT_VALID) != 0; }
static inline int edhoc_oscore_keys_valid(void){ return (edhoc_status() & STATUS_OSCORE_VALID) != 0; }
static inline int edhoc_aead_done(void)        { return (edhoc_status() & STATUS_AEAD_DONE) != 0; }

// =============================================================================
// Message Exchange
// =============================================================================

// Feed a message: write data_in, then pulse msg_valid
static inline void edhoc_feed_message(const uint8_t *msg, int len) {
    edhoc_write_data_in(msg, len);
    edhoc_write(EDHOC_MSG_VALID, 1);
}

// Capture output: read data_out, then pulse output_ack
static inline void edhoc_capture_output(uint8_t *msg, int len) {
    edhoc_read_data_out(msg, len);
    edhoc_write(EDHOC_OUTPUT_ACK, 1);
}

// =============================================================================
// Blocking Wait Helpers
// =============================================================================

static inline int edhoc_wait_output_valid(uint32_t timeout) {
    for (uint32_t i = 0; i < timeout; i++) {
        if (edhoc_is_output_valid()) return 0;
        if (edhoc_has_error())       return -1;
    }
    return -2;
}

static inline int edhoc_wait_msg_ready(uint32_t timeout) {
    for (uint32_t i = 0; i < timeout; i++) {
        if (edhoc_is_msg_ready()) return 0;
        if (edhoc_has_error())    return -1;
    }
    return -2;
}

static inline int edhoc_wait_done(uint32_t timeout) {
    for (uint32_t i = 0; i < timeout; i++) {
        if (edhoc_is_done())   return 0;
        if (edhoc_has_error()) return -1;
    }
    return -2;
}

static inline int edhoc_wait_aead_done(uint32_t timeout) {
    for (uint32_t i = 0; i < timeout; i++) {
        if (edhoc_aead_done()) return 0;
    }
    return -2;
}

#endif // EDHOC_HW_H

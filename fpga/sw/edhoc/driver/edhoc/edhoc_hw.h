/**
 * @file edhoc_hw.h
 * @brief EDHOC Hardware Accelerator Driver Header
 *
 * Driver for the EDHOC+OSCORE hardware accelerator.
 * Supports both Initiator and Responder roles with Cipher Suite 7
 * (X25519, ASCON-AEAD-128, ASCON-Hash-256).
 *
 * Protocol: EDHOC-PSK (Method 4)
 * Output: OSCORE keys (Common IV, Sender Key, Recipient Key)
 * External AEAD interface for CoAP encryption/decryption
 */

#ifndef EDHOC_HW_H
#define EDHOC_HW_H

#include <stdint.h>
#include "platform.h"

/* ==========================================================================
 * Register Offsets
 * ========================================================================== */

/* TRNG Control (NEW - for FPGA mode) */
#define EDHOC_REG_TRNG_CONTROL      0x000   /* bit[0]=trng_en, bit[1]=xdrbg_bypass */

/* Keys and Parameters */
#define EDHOC_REG_EPHEMERAL_KEY     0x004   /* 256-bit (8x32) - only for bypass mode */
#define EDHOC_REG_PARAMS_0          0x024   /* c_x, method, suite, id_cred_psk */
#define EDHOC_REG_PARAMS_1          0x028   /* kid_initiator, kid_responder */
#define EDHOC_REG_ID_INITIATOR      0x02C   /* 64-bit (2x32) */
#define EDHOC_REG_ID_RESPONDER      0x034   /* 64-bit (2x32) */

/* Control and Status */
#define EDHOC_REG_CONTROL           0x03C
#define EDHOC_REG_STATUS            0x040

/* Message Data I/O */
#define EDHOC_REG_DATA_IN           0x044   /* 296-bit (10x32) */
#define EDHOC_REG_DATA_OUT          0x084   /* 296-bit (10x32) */

/* AEAD Interface for CoAP - Hardware constructs nonce from sender_id + partial_iv */
#define EDHOC_REG_AEAD_SENDER_ID    0x100   /* 8-bit sender ID for nonce construction */
#define EDHOC_REG_AEAD_PARTIAL_IV   0x104   /* 40-bit partial IV / sequence number (2x32) */
#define EDHOC_REG_AEAD_AAD          0x110   /* 128-bit (4x32) */
#define EDHOC_REG_AEAD_LENGTHS      0x120   /* aad_len, data_len packed */
#define EDHOC_REG_AEAD_DATA_IN      0x124   /* 128-bit (4x32) */
#define EDHOC_REG_AEAD_DATA_OUT     0x140   /* 128-bit (4x32) */
#define EDHOC_REG_AEAD_TAG          0x150   /* 128-bit (4x32) - output tag */
#define EDHOC_REG_AEAD_EXP_TAG      0x160   /* 128-bit (4x32) - expected tag for decrypt */

/* Message Valid Signal */
#define EDHOC_REG_MSG_VALID         0x170

/* Output Acknowledge Signal (NEW - clears output_valid in hardware) */
#define EDHOC_REG_OUTPUT_ACK        0x174

/* ==========================================================================
 * TRNG Control Register Bits
 * ========================================================================== */
#define EDHOC_TRNG_EN               0x01    /* Enable TRNG collection */
#define EDHOC_XDRBG_BYPASS          0x02    /* 1=use ephemeral_key, 0=use TRNG+XDRBG */

/* ==========================================================================
 * Control Register Bits
 * ========================================================================== */
#define EDHOC_CTRL_START                0x01
#define EDHOC_CTRL_INITIATOR            0x02
#define EDHOC_CTRL_AEAD_START           0x04
#define EDHOC_CTRL_AEAD_ENCRYPT         0x08
#define EDHOC_CTRL_AEAD_USE_SENDER_KEY  0x10
#define EDHOC_CTRL_RESET                0x20
#define EDHOC_CTRL_CLEAR_FLAGS          0x40

/* ==========================================================================
 * Status Register Bits
 * ========================================================================== */
#define EDHOC_STATUS_DONE               0x01
#define EDHOC_STATUS_ERROR              0x02
#define EDHOC_STATUS_MSG_READY          0x04
#define EDHOC_STATUS_OUTPUT_VALID       0x08
#define EDHOC_STATUS_OSCORE_KEYS_VALID  0x10
#define EDHOC_STATUS_AEAD_DONE          0x20
#define EDHOC_STATUS_AEAD_TAG_VALID     0x40
#define EDHOC_STATUS_CURRENT_MSG_SHIFT  8
#define EDHOC_STATUS_CURRENT_MSG_MASK   0x300

/* ==========================================================================
 * Protocol Constants
 * ========================================================================== */
#define EDHOC_METHOD_PSK            0x04    /* EDHOC Method 4 (PSK) */
#define EDHOC_SUITE_ASCON           0x07    /* Cipher Suite 7: X25519, ASCON-AEAD-128, ASCON-Hash-256 */
#define EDHOC_C_I_DEFAULT           0x2D    /* Default C_I */
#define EDHOC_C_R_DEFAULT           0x0E    /* Default C_R */

/* Message sizes in bytes */
#define EDHOC_MSG1_SIZE             37      /* MSG1: METHOD || SUITES || G_X || C_I */
#define EDHOC_MSG2_SIZE             35      /* MSG2: G_Y || C_R_encrypted */
#define EDHOC_MSG3_SIZE             20      /* MSG3: CIPHERTEXT_3 || CIPHERTEXT_3B */
#define EDHOC_MSG4_SIZE             17      /* MSG4: CIPHERTEXT_4 */

/* Key sizes */
#define EDHOC_KEY_SIZE              32      /* X25519 key size */
#define EDHOC_OSCORE_KEY_SIZE       16      /* OSCORE key size */
#define EDHOC_OSCORE_IV_SIZE        13      /* OSCORE IV size (Common IV is 13 bytes) */
#define EDHOC_AEAD_TAG_SIZE         16      /* AEAD tag size */

/* ==========================================================================
 * MMIO Macros (only define if not already defined in platform.h)
 * ========================================================================== */
#ifndef _REG64
#define _REG64(p, i) (*(volatile uint64_t *)((char*)(p) + (i)))
#endif
#ifndef _REG32
#define _REG32(p, i) (*(volatile uint32_t *)((char*)(p) + (i)))
#endif
#ifndef _REG16
#define _REG16(p, i) (*(volatile uint16_t *)((char*)(p) + (i)))
#endif
#ifndef _REG8
#define _REG8(p, i)  (*(volatile uint8_t *)((char*)(p) + (i)))
#endif

/* ==========================================================================
 * Default Base Address
 * ========================================================================== */
#define EDHOC_CTRL_ADDR             0x64004000UL
static volatile uint32_t * const edhoc_base = (void *)(EDHOC_CTRL_ADDR);

/* ==========================================================================
 * Data Structures
 * ========================================================================== */

/**
 * @brief EDHOC Protocol Parameters
 */
typedef struct {
    uint8_t ephemeral_key[32];      /* Private key (X_I for initiator, Y_R for responder) */
    uint8_t c_x;                    /* Connection ID (C_I for initiator, C_R for responder) */
    uint8_t method;                 /* EDHOC method (4 for PSK) */
    uint8_t suite;                  /* Cipher suite (7 for X25519+ASCON) */
    uint8_t id_cred_psk;            /* PSK identifier */
    uint8_t kid_initiator;          /* KID for initiator */
    uint8_t kid_responder;          /* KID for responder */
    uint8_t id_initiator[8];        /* Initiator identity (8 bytes) */
    uint8_t id_responder[8];        /* Responder identity (8 bytes) */
} edhoc_params_t;

/**
 * @brief OSCORE Context (minimal - keys and IV are internal to hardware)
 * 
 * After EDHOC handshake completes, all OSCORE keys and the Common IV
 * are stored internally in the hardware. The AEAD interface uses these
 * internal keys directly based on the aead_use_sender_key flag.
 */
typedef struct {
    uint8_t oscore_ready;           /* Flag indicating OSCORE keys are valid */
} oscore_context_t;

/**
 * @brief OSCORE AEAD Operation Parameters
 * 
 * Hardware constructs the OSCORE nonce internally as:
 *   nonce = {S, padded_ID, padded_PIV} XOR Common_IV
 * where S = sender_id length (1 byte), padded_ID = sender_id left-padded,
 * and padded_PIV = partial_iv left-padded.
 */
typedef struct {
    uint8_t sender_id;              /* 8-bit sender ID (kid) for nonce construction */
    uint8_t partial_iv[5];          /* 40-bit partial IV / sequence number */
    uint8_t aad[16];                /* AAD (padded) */
    uint8_t aad_len;                /* AAD length (0-16) */
    uint8_t data_in[16];            /* Plaintext or Ciphertext */
    uint8_t data_len;               /* Data length (0-16) */
    uint8_t use_sender_key;         /* 1=sender key, 0=recipient key */
    uint8_t encrypt;                /* 1=encrypt, 0=decrypt */
    uint8_t exp_tag[16];            /* Expected tag for decryption verification */
} aead_params_t;

/**
 * @brief AEAD Result
 */
typedef struct {
    uint8_t data_out[16];           /* Result data */
    uint8_t tag[16];                /* Authentication tag */
    uint8_t tag_valid;              /* Tag verification passed (for decrypt) */
} aead_result_t;

/* ==========================================================================
 * Function Declarations
 * ========================================================================== */

/**
 * @brief Reset the EDHOC hardware accelerator
 * @param base Base address of EDHOC peripheral
 */
void edhoc_hw_reset(void* base);

/**
 * @brief Initialize EDHOC parameters
 * @param base Base address of EDHOC peripheral
 * @param params EDHOC parameters
 */
void edhoc_hw_init(void* base, const edhoc_params_t* params);

/**
 * @brief Start EDHOC protocol as Initiator
 * @param base Base address of EDHOC peripheral
 * @return 0 on success, -1 on error
 */
int edhoc_hw_start_initiator(void* base);

/**
 * @brief Start EDHOC protocol as Responder
 * @param base Base address of EDHOC peripheral
 * @return 0 on success, -1 on error
 */
int edhoc_hw_start_responder(void* base);

/**
 * @brief Wait for hardware to be ready for next message
 * @param base Base address of EDHOC peripheral
 * @return 0 on ready, -1 on error
 */
int edhoc_hw_wait_msg_ready(void* base);

/**
 * @brief Get current message number being output
 * @param base Base address of EDHOC peripheral
 * @return Current message number (1-4)
 */
int edhoc_hw_get_current_msg(void* base);

/**
 * @brief Wait for output message to be valid
 * @param base Base address of EDHOC peripheral
 * @return 0 on valid, -1 on error
 */
int edhoc_hw_wait_output_valid(void* base);

/**
 * @brief Write input message data
 * @param base Base address of EDHOC peripheral
 * @param data Message data (up to 37 bytes)
 * @param len Length of message data
 */
void edhoc_hw_write_data_in(void* base, const uint8_t* data, uint8_t len);

/**
 * @brief Signal that input message is valid
 * @param base Base address of EDHOC peripheral
 */
void edhoc_hw_set_msg_valid(void* base);

/**
 * @brief Acknowledge output has been captured
 * @param base Base address of EDHOC peripheral
 * 
 * This signals to the hardware that the output data has been read,
 * allowing the hardware to clear output_valid and proceed.
 */
void edhoc_hw_set_output_ack(void* base);

/**
 * @brief Read output message data
 * @param base Base address of EDHOC peripheral
 * @param data Buffer for message data (at least 37 bytes)
 * @param len Pointer to store length of message (or NULL)
 * 
 * Note: This function automatically sends output_ack after reading.
 */
void edhoc_hw_read_data_out(void* base, uint8_t* data, uint8_t* len);

/**
 * @brief Wait for protocol to complete
 * @param base Base address of EDHOC peripheral
 * @return 0 on success, -1 on error
 */
int edhoc_hw_wait_done(void* base);

/**
 * @brief Check if OSCORE keys are valid
 * @param base Base address of EDHOC peripheral
 * @return 1 if valid, 0 if not
 */
int edhoc_hw_oscore_keys_valid(void* base);

/**
 * @brief Get OSCORE context (checks if keys are ready)
 * @param base Base address of EDHOC peripheral
 * @param ctx Pointer to OSCORE context structure
 * 
 * Note: All keys (Sender Key, Recipient Key, Common IV) remain internal
 * to the hardware. The AEAD interface uses them directly.
 */
void edhoc_hw_get_oscore_context(void* base, oscore_context_t* ctx);

/**
 * @brief Perform AEAD encryption using OSCORE keys
 * @param base Base address of EDHOC peripheral
 * @param params AEAD parameters
 * @param result AEAD result
 * @return 0 on success, -1 on error
 */
int edhoc_hw_aead_encrypt(void* base, const aead_params_t* params, aead_result_t* result);

/**
 * @brief Perform AEAD decryption using OSCORE keys
 * @param base Base address of EDHOC peripheral
 * @param params AEAD parameters (data_in contains ciphertext)
 * @param result AEAD result (data_out contains plaintext, tag_valid indicates success)
 * @return 0 on success (tag valid), -1 on error (tag invalid)
 */
int edhoc_hw_aead_decrypt(void* base, const aead_params_t* params, aead_result_t* result);

/**
 * @brief Run complete EDHOC initiator handshake
 * @param base Base address of EDHOC peripheral
 * @param params EDHOC parameters
 * @param msg1_out Buffer for MSG1 output (at least 37 bytes)
 * @param msg1_len Pointer to store MSG1 length
 * @param msg2_in MSG2 input from responder
 * @param msg2_len MSG2 length
 * @param msg3_out Buffer for MSG3 output (at least 20 bytes)
 * @param msg3_len Pointer to store MSG3 length
 * @param msg4_in MSG4 input from responder
 * @param msg4_len MSG4 length
 * @param ctx Pointer to OSCORE context structure (for Common IV)
 * @return 0 on success, -1 on error
 */
int edhoc_hw_initiator_handshake(void* base, const edhoc_params_t* params,
                                  uint8_t* msg1_out, uint8_t* msg1_len,
                                  const uint8_t* msg2_in, uint8_t msg2_len,
                                  uint8_t* msg3_out, uint8_t* msg3_len,
                                  const uint8_t* msg4_in, uint8_t msg4_len,
                                  oscore_context_t* ctx);

/**
 * @brief Run complete EDHOC responder handshake
 * @param base Base address of EDHOC peripheral
 * @param params EDHOC parameters
 * @param msg1_in MSG1 input from initiator
 * @param msg1_len MSG1 length
 * @param msg2_out Buffer for MSG2 output (at least 35 bytes)
 * @param msg2_len Pointer to store MSG2 length
 * @param msg3_in MSG3 input from initiator
 * @param msg3_len MSG3 length
 * @param msg4_out Buffer for MSG4 output (at least 17 bytes)
 * @param msg4_len Pointer to store MSG4 length
 * @param ctx Pointer to OSCORE context structure (for Common IV)
 * @return 0 on success, -1 on error
 */
int edhoc_hw_responder_handshake(void* base, const edhoc_params_t* params,
                                  const uint8_t* msg1_in, uint8_t msg1_len,
                                  uint8_t* msg2_out, uint8_t* msg2_len,
                                  const uint8_t* msg3_in, uint8_t msg3_len,
                                  uint8_t* msg4_out, uint8_t* msg4_len,
                                  oscore_context_t* ctx);

/**
 * @brief Self-test function
 * @param base Base address of EDHOC peripheral
 */
void edhoc_hw_selftest(void* base);

/**
 * @brief Print OSCORE context (for debugging)
 * @param ctx Pointer to OSCORE context structure
 */
void edhoc_hw_print_context(const oscore_context_t* ctx);

#endif /* EDHOC_HW_H */

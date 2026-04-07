package chipyard.crypto.edhoc

/**
 * EDHOC Hardware Accelerator Register Map
 * 
 * This register map is designed for the EDHOC+OSCORE hardware accelerator.
 * The accelerator supports both Initiator and Responder roles with Cipher Suite 7
 * (X25519, ASCON-AEAD-128, ASCON-Hash-256).
 * 
 * Register Layout:
 * 0x000 - 0x003: trng_control (bit[0]=trng_en, bit[1]=xdrbg_bypass)
 * 0x004 - 0x023: ephemeral_key (256-bit, 8x32-bit) - only used when xdrbg_bypass=1
 * 0x024 - 0x027: params_0 (c_x, method, suite, id_cred_psk packed)
 * 0x028 - 0x02B: params_1 (kid_initiator, kid_responder, reserved)
 * 0x028 - 0x02F: id_initiator (64-bit, 2x32-bit)
 * 0x030 - 0x037: id_responder (64-bit, 2x32-bit)
 * 0x038 - 0x03B: control (start, initiator, aead_start, aead_encrypt, aead_use_sender_key, reset, clear_flags)
 * 0x03C - 0x03F: status (done, error, msg_ready, output_valid, oscore_keys_valid, aead_done, aead_tag_valid, current_msg)
 *                 Note: msg_ready and output_valid are sticky flags that remain set until cleared
 * 0x040 - 0x063: data_in (296-bit, 10x32-bit = 320 bits, use first 37 bytes)
 * 0x080 - 0x0A3: data_out (296-bit, 10x32-bit = 320 bits, read first 37 bytes)
 * 0x100 - 0x103: aead_sender_id (8-bit sender_id in [7:0], partial_iv[7:0] in [15:8])
 * 0x104 - 0x107: aead_partial_iv_hi (partial_iv[39:8], 32-bit)
 * 0x110 - 0x11F: aead_aad (128-bit, 4x32-bit)
 * 0x120 - 0x123: aead_lengths (aad_len, data_len packed)
 * 0x124 - 0x133: aead_data_in (128-bit, 4x32-bit)
 * 0x140 - 0x14F: aead_data_out (128-bit, 4x32-bit)
 * 0x150 - 0x15F: aead_tag (128-bit, 4x32-bit)
 * 0x160 - 0x16F: aead_exp_tag (128-bit expected tag for decryption, 4x32-bit)
 * 0x170 - 0x173: msg_valid (write 1 to pulse msg_valid signal)
 * 
 * NOTE: Sender Key and Recipient Key are NOT exposed to software.
 * They remain internal to the hardware for AEAD operations.
 * Use the AEAD interface to encrypt/decrypt with aead_use_sender_key to select the key.
 */
object EDHOCCtrlRegs {
  // ===== TRNG Control =====
  val trng_control  = 0x000   // [0] trng_en, [1] xdrbg_bypass (0=use TRNG, 1=use ephemeral_key)
  
  // ===== Keys and Parameters =====
  val ephemeral_key = 0x004   // 256-bit (8x32) private key (only used when xdrbg_bypass=1)
  val params_0      = 0x024   // [7:0] c_x, [15:8] method, [23:16] suite, [31:24] id_cred_psk
  val params_1      = 0x028   // [7:0] kid_initiator, [15:8] kid_responder, [31:16] reserved
  val id_initiator  = 0x02C   // 64-bit (2x32)
  val id_responder  = 0x034   // 64-bit (2x32)
  
  // ===== Control and Status =====
  val control       = 0x03C   // [0] start, [1] initiator, [2] aead_start, [3] aead_encrypt, [4] aead_use_sender_key, [5] reset, [6] clear_flags
  val status        = 0x040   // [0] done, [1] error, [2] msg_ready, [3] output_valid, [4] oscore_keys_valid,
                              // [5] aead_done, [6] aead_tag_valid, [9:8] current_msg
  
  // ===== Message Data I/O =====
  val data_in       = 0x044   // 296-bit (10x32 = 320 bits, use lower 296 bits)
  val data_out      = 0x084   // 296-bit (10x32 = 320 bits, read lower 296 bits)
  
  // ===== AEAD Interface for CoAP =====
  // Hardware constructs nonce from sender_id + partial_iv XOR Common_IV
  val aead_sender_id    = 0x100   // [7:0] sender_id (8-bit)
  val aead_partial_iv   = 0x104   // [39:0] partial_iv / sequence number (40-bit, use 2x32)
  val aead_aad      = 0x110   // 128-bit (4x32)
  val aead_lengths  = 0x120   // [3:0] aad_len, [7:4] data_len, [31:8] reserved
  val aead_data_in  = 0x124   // 128-bit (4x32) - plaintext or ciphertext
  val aead_data_out = 0x140   // 128-bit (4x32) - result
  val aead_tag      = 0x150   // 128-bit (4x32) - auth tag (output)
  val aead_exp_tag  = 0x160   // 128-bit (4x32) - expected tag for decryption verification
  
  // ===== Message Valid Signal =====
  val msg_valid     = 0x170   // Write 1 to pulse msg_valid
  
  // ===== Output Acknowledge Signal (NEW) =====
  val output_ack    = 0x174   // Write 1 to acknowledge output captured (clears output_valid)
}

// Control register bits
object EDHOCCtrl {
  val START               = 0x01
  val INITIATOR           = 0x02
  val AEAD_START          = 0x04
  val AEAD_ENCRYPT        = 0x08
  val AEAD_USE_SENDER_KEY = 0x10
  val RESET               = 0x20
  val CLEAR_FLAGS         = 0x40
}

// Status register bits
object EDHOCStatus {
  val DONE              = 0x01
  val ERROR             = 0x02
  val MSG_READY         = 0x04
  val OUTPUT_VALID      = 0x08
  val OSCORE_KEYS_VALID = 0x10
  val AEAD_DONE         = 0x20
  val AEAD_TAG_VALID    = 0x40
  val CURRENT_MSG_SHIFT = 8
  val CURRENT_MSG_MASK  = 0x300
}

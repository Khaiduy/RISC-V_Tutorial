package chipyard.crypto.edhoc

// Register map for EDHOC M3 hardware accelerator.
// Offsets match edhoc_regmap.v (WA_* decode) and edhoc_m3_hw.h.
// Base address is set by WithEDHOCM3 in EDHOCM3.scala (default 0x64004000).
//
// Data packing: big-endian word order (word 0 = MSB of 256-bit key).
// Suite 0: X25519 + HMAC-SHA256 + AES-CCM-16-64-128

object EDHOCM3CtrlRegs {

  // =========================================================================
  // Key Registers
  // =========================================================================

  // 256-bit ephemeral private key: 8 x 32-bit words (i = 0..7)
  def eph_priv(i: Int)    = 0x000 + i * 4   // 0x000..0x01C

  // 256-bit static private key: 8 x 32-bit words (i = 0..7)
  def static_priv(i: Int) = 0x020 + i * 4   // 0x020..0x03C

  // =========================================================================
  // Control / Status
  // =========================================================================

  val control = 0x040  // W: [0]=start, [1]=is_init, [2]=input_ready, [3]=output_ack, [31]=reset
  val status  = 0x044  // R: [0]=done, [1]=error, [2]=msg_ready, [3]=waiting, [4]=oscore_ok, [10:8]=phase
  val params  = 0x048  // W: [7:0]=kid_own, [15:8]=kid_peer, [23:16]=c_x, [31:24]=c_peer

  // =========================================================================
  // Credential Registers (55-byte CCS, padded to 14 x 32-bit = 56 bytes)
  // =========================================================================

  def cred_own(i: Int)  = 0x050 + i * 4   // i=0..13 → 0x050..0x08C
  def cred_peer(i: Int) = 0x090 + i * 4   // i=0..13 → 0x090..0x0CC

  // =========================================================================
  // Data I/O (80-byte buffers, big-endian word order)
  // =========================================================================

  def data_in(i: Int)  = 0x0D0 + i * 4   // i=0..19 → 0x0D0..0x11C  write-only
  def data_out(i: Int) = 0x120 + i * 4   // i=0..19 → 0x120..0x16C  read-only

  val msg_len = 0x170  // R: message length in bytes (set by HW after output ready)

  // =========================================================================
  // External AEAD (OSCORE) Interface
  // Available after EDHOC handshake completes (oscore_ok=1).
  // =========================================================================

  val ea_control = 0x180  // W: [0]=start, [1]=encrypt, [2]=use_sender_key, [7:3]=tag_len
  val ea_lengths = 0x184  // W: [15:0]=msg_len, [31:16]=aad_len

  def ea_nonce(i: Int)   = 0x188 + i * 4  // i=0..1  → 0x188..0x18C
  def ea_tag_exp(i: Int) = 0x198 + i * 4  // i=0..3  → 0x198..0x1A4

  val ea_status  = 0x1A8  // R: [0]=done, [1]=tag_match, [2]=input_ready, [3]=output_valid, [12:8]=dout_count

  def ea_tag_out(i: Int) = 0x1AC + i * 4  // i=0..3  → 0x1AC..0x1B8  read-only

  val ea_chunk   = 0x1BC  // W: write any value to signal chunk ready (chunked mode)

  // =========================================================================
  // Control Register Bit Masks
  // =========================================================================
  val CTRL_START        = 1 << 0
  val CTRL_IS_INIT      = 1 << 1
  val CTRL_INPUT_READY  = 1 << 2
  val CTRL_OUTPUT_ACK   = 1 << 3
  val CTRL_RESET        = 1 << 31

  // =========================================================================
  // Status Register Bit Masks
  // =========================================================================
  val STATUS_DONE       = 1 << 0
  val STATUS_ERROR      = 1 << 1
  val STATUS_MSG_READY  = 1 << 2
  val STATUS_WAITING    = 1 << 3
  val STATUS_OSCORE_OK  = 1 << 4
  val STATUS_PHASE_MASK = 0x7 << 8

  // =========================================================================
  // EA Control / Status Bit Masks
  // =========================================================================
  val EA_START             = 1 << 0
  val EA_ENCRYPT           = 1 << 1
  val EA_USE_SENDER_KEY    = 1 << 2

  val EA_STATUS_DONE       = 1 << 0
  val EA_STATUS_TAG_OK     = 1 << 1
  val EA_STATUS_INPUT_RDY  = 1 << 2
  val EA_STATUS_OUTPUT_VLD = 1 << 3
}

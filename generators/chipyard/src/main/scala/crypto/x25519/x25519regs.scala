package chipyard.crypto.x25519

object X25519CtrlRegs {
  val scalar = 0x00         // 256-bit scalar input (32 bytes)
  val point_in = 0x20       // 256-bit input point (32 bytes)
  val point_out = 0x40      // 256-bit output point (32 bytes)
  val control = 0x60        // Control register (start, reset)
  val status = 0x64         // Status register (valid, busy)
}

package chipyard.crypto.hmac_sha

object HMAC_SHACtrlRegs {
  val conf_data     = 0x100
//  val conf_data_1     = 0x108
  val conf_address    = 0x108
  val dout          = 0x110
//  val dout_1          = 0x120
  val conf_we         = 0x118

  val input_ready    = 0x120
  val endofpacket    = 0x128

  val resetn          = 0x130
  val ready           = 0x138
  val enable          = 0x140
}
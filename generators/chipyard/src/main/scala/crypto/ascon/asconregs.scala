package chipyard.crypto.ascon

object ASCONRegs {
  val IRESETN =               0x100
  val config_in =             0x108
  val input_fifo_wr_en =      0x110
  val input_fifo_wr_data =    0x118
  val output_fifo_rd_data =   0x120
  // val output_fifo_rd_valid =  0x128
  val output_fifo_rd_en =     0x128
  val key_in_0 =              0x130
  val key_in_1 =              0x138
  val key_wr_en =             0x140
  val nonce_in_0 =            0x148
  val nonce_in_1 =            0x150
  val nonce_wr_en =           0x158
  val status_out =            0x160
  val tag_out_0 =             0x168
  val tag_out_1 =             0x170
  val tag_out_2 =             0x178
  val tag_out_3 =             0x180

}
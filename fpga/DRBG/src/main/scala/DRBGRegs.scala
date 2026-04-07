//see LICENSE for license
//authors: Duc-Thuan Dam, UEC
package DRBG.src.main.scala

object DRBGRegs {
  val rst         = 0x48
  val enable      = 0x08
  val write_done  = 0x10
  val address     = 0x18
  val in_data     = 0x20
  val start       = 0x28
  val mode        = 0x30
  val out_data    = 0x38
  val done        = 0x40
}
package chipyard.crypto.ascon

import chisel3._
import chisel3.util._
import chisel3.util.random._
import chisel3.util.HasBlackBoxResource

import org.chipsalliance.cde.config.{Field, Parameters, Config}
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.interrupts._
import freechips.rocketchip.prci._
import freechips.rocketchip.regmapper._
import freechips.rocketchip.subsystem._
import freechips.rocketchip.tilelink._
import freechips.rocketchip.devices.tilelink._
import freechips.rocketchip.util._
import sifive.blocks.util.{DeviceParams, DeviceAttachParams}
import sifive.blocks.devices.pinctrl.{PinCtrl, Pin, BasePin, EnhancedPin, EnhancedPinCtrl}
import java.net.InetAddress
import os.write.over

case class ASCONParams  
(
  address: BigInt,
  version: Int = 1,
)

case object ASCONKey extends Field[Option[ASCONParams]](None)

class ascon_core extends BlackBox with HasBlackBoxResource {
  override def desiredName: String = "ascon_top"
  val io = IO(new Bundle {
    val clk = Input(Clock())
    val rst_n = Input(Bool())

    val config_in = Input(UInt(64.W))
    val input_fifo_wr_en = Input(Bool())
    val input_fifo_wr_data = Input(UInt(64.W))

    val output_fifo_rd_data = Output(UInt(64.W))
    // val output_fifo_rd_valid = Output(Bool())
    val output_fifo_rd_en = Input(Bool())

    val key_in = Input(UInt(128.W))
    val nonce_in = Input(UInt(128.W))
    val key_wr_en = Input(Bool())
    val nonce_wr_en = Input(Bool())


    val status_out = Output(UInt(10.W))
    val tag_out = Output(UInt(256.W))
  })
  addResource("/crypto-vsrc/ascon_top.v")
}

class ASCONTL(params: ASCONParams, beatBytes: Int)(implicit p: Parameters) extends ClockSinkDomain(ClockSinkParameters())(p) {
  val device = new SimpleDevice("Ascon", Seq("sifive,Ascon-0.1"))
  val node = TLRegisterNode(Seq(AddressSet(params.address, 4096-1)), device, "reg/control", beatBytes=beatBytes) // 64-bit bus

  override lazy val module = new AsconImpl
  class AsconImpl extends Impl {
    withClockAndReset(clock, reset) {
      // Registers
      val IRESETN = RegInit(0.U(1.W))

      val nonce_0 = RegInit(0.U(64.W))
      val nonce_1 = RegInit(0.U(64.W))

      // IKEY (128 bits) split into 2x64-bit registers
      val key_0 = RegInit(0.U(64.W))
      val key_1 = RegInit(0.U(64.W))

      val config_in = RegInit(0.U(64.W))
      val input_fifo_wr_en = RegInit(0.U(1.W))
      val input_fifo_wr_data = RegInit(0.U(64.W))
      val output_fifo_rd_en = RegInit(0.U(1.W))
      val output_fifo_rd_data = WireDefault(0.U(64.W))
      // val output_fifo_rd_valid = WireDefault(0.U(1.W))

      val key_wr_en = RegInit(0.U(1.W))
      val nonce_wr_en = RegInit(0.U(1.W))
      val key_in = Cat(key_1, key_0)
      val nonce_in = Cat(nonce_1, nonce_0)
      val status_out = WireDefault(0.U(10.W))
      val tag_out_0 = WireDefault(0.U(64.W))
      val tag_out_1 = WireDefault(0.U(64.W))
      val tag_out_2 = WireDefault(0.U(64.W))
      val tag_out_3 = WireDefault(0.U(64.W))

      val core_ascon = Module(new ascon_core)
      core_ascon.io.clk := clock
      core_ascon.io.rst_n := !reset.asBool & IRESETN

      core_ascon.io.config_in := config_in
      // core_ascon.io.input_fifo_wr_en := input_fifo_wr_en.asBool
      core_ascon.io.input_fifo_wr_data := input_fifo_wr_data
      // core_ascon.io.output_fifo_rd_en := output_fifo_rd_en.asBool
      output_fifo_rd_data := core_ascon.io.output_fifo_rd_data
      // output_fifo_rd_valid := core_ascon.io.output_fifo_rd_valid
      core_ascon.io.key_in := key_in
      core_ascon.io.nonce_in := nonce_in
      core_ascon.io.key_wr_en := key_wr_en.asBool
      core_ascon.io.nonce_wr_en := nonce_wr_en.asBool
      status_out := core_ascon.io.status_out
      tag_out_0 := core_ascon.io.tag_out(255, 192)
      tag_out_1 := core_ascon.io.tag_out(191, 128)
      tag_out_2 := core_ascon.io.tag_out(127, 64)
      tag_out_3 := core_ascon.io.tag_out(63, 0)


      val input_fifo_wr_trigger = RegInit(false.B)
      val input_fifo_wr_pulse = input_fifo_wr_trigger
      when(input_fifo_wr_trigger) {
        input_fifo_wr_trigger := false.B
      }
      core_ascon.io.input_fifo_wr_en := input_fifo_wr_pulse

      val output_fifo_rd_trigger = RegInit(false.B)
      val output_fifo_rd_pulse = output_fifo_rd_trigger
      when(output_fifo_rd_trigger) {
        output_fifo_rd_trigger := false.B
      }
      core_ascon.io.output_fifo_rd_en := output_fifo_rd_pulse

// Register mapping (updated for read-only fields and descriptions)
      node.regmap(
        ASCONRegs.IRESETN -> Seq(
          RegField(1, IRESETN, RegFieldDesc("IRESETN", "Reset register"))
        ),
        ASCONRegs.config_in -> Seq(  // Remove .r to make writable (assuming read-write needed)
          RegField(64, config_in, RegFieldDesc("CONFIG_IN", "Configuration input"))
        ),
        ASCONRegs.input_fifo_wr_en -> Seq(
          RegField.w(1, input_fifo_wr_trigger, RegFieldDesc("INPUT_FIFO_WR_EN", "Input FIFO write enable (write 1 to pulse)"))
        ),
        ASCONRegs.input_fifo_wr_data -> Seq(
          RegField(64, input_fifo_wr_data, RegFieldDesc("INPUT_FIFO_WR_DATA", "Input FIFO write data (64 bits)"))
        ),
        ASCONRegs.output_fifo_rd_data -> Seq(
          RegField.r(64, output_fifo_rd_data, RegFieldDesc("OUTPUT_FIFO_RD_DATA", "Output FIFO read data (64 bits)", volatile = true))  // Use .r for read-only Wire
        ),
        // ASCONRegs.output_fifo_rd_valid -> Seq(
        //   RegField.r(1, output_fifo_rd_valid, RegFieldDesc("OUTPUT_FIFO_RD_VALID", "Output FIFO read valid", volatile = true))  // Use .r
        // ),
        ASCONRegs.output_fifo_rd_en -> Seq(
          RegField.w(1, output_fifo_rd_trigger, RegFieldDesc("OUTPUT_FIFO_RD_EN", "Output FIFO read enable"))
        ),
        ASCONRegs.key_in_0 -> Seq(
          RegField(64, key_0, RegFieldDesc("KEY_0", "Key bits 127:64"))  // Corrected desc for 128-bit key
        ),
        ASCONRegs.key_in_1 -> Seq(
          RegField(64, key_1, RegFieldDesc("KEY_1", "Key bits 63:0"))  // Corrected
        ),
        ASCONRegs.key_wr_en -> Seq(
          RegField(1, key_wr_en, RegFieldDesc("KEY_WR_EN", "Key write enable"))
        ),
        ASCONRegs.nonce_in_0 -> Seq(
          RegField(64, nonce_0, RegFieldDesc("NONCE_0", "Nonce bits 127:64", reset = Some(0)))  // Corrected
        ),
        ASCONRegs.nonce_in_1 -> Seq(
          RegField(64, nonce_1, RegFieldDesc("NONCE_1", "Nonce bits 63:0", reset = Some(0)))  // Corrected
        ),
        ASCONRegs.nonce_wr_en -> Seq(
          RegField(1, nonce_wr_en, RegFieldDesc("NONCE_WR_EN", "Nonce write enable", reset = Some(0)))
        ),
        ASCONRegs.status_out -> Seq(
          RegField.r(9, status_out, RegFieldDesc("STATUS_OUT", "Status output", volatile = true))  // Use .r
        ),
        ASCONRegs.tag_out_0 -> Seq(
          RegField.r(64, tag_out_0, RegFieldDesc("TAG_OUT_0", "Tag bits 255:192", volatile = true))  // Corrected for 256-bit tag; use .r
        ),
        ASCONRegs.tag_out_1 -> Seq(
          RegField.r(64, tag_out_1, RegFieldDesc("TAG_OUT_1", "Tag bits 191:128", volatile = true))  // Corrected; use .r
        ),
        ASCONRegs.tag_out_2 -> Seq(
          RegField.r(64, tag_out_2, RegFieldDesc("TAG_OUT_2", "Tag bits 127:64", volatile = true))  // Corrected; use .r
        ),
        ASCONRegs.tag_out_3 -> Seq(
          RegField.r(64, tag_out_3, RegFieldDesc("TAG_OUT_3", "Tag bits 63:0", volatile = true))  // Corrected; use .r
        )
      )
    }
  }
}


object ASCONID {
  val nextId = {
    var i = -1; () => {
      i += 1; i
    }
  }
}

trait CanHavePeripheryASCON { this: BaseSubsystem =>
  private val portName = s"ascon_${ASCONID.nextId()}"
//  private val pbus = locateTLBusWrapper(PBUS)

  val ascon_busy = p(ASCONKey) match {
    case Some(params) => {
      val ascon = LazyModule(new ASCONTL(params, pbus.beatBytes))
      ascon.suggestName(portName)

      ascon.clockNode := pbus.fixedClockNode
      pbus.coupleTo(portName) { ascon.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }

      ascon
    }
    case None => None
  }
}

class WithASCON(address: BigInt) extends Config((site, here, up) => {
  case ASCONKey => {
    println(f"Setting ASCON address: 0x${address}%X")
    Some(ASCONParams(address = address))
  }
})
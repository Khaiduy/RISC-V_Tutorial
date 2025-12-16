package chipyard.crypto.hmac_sha

import chisel3._
import chisel3.util._
import chisel3.util.random._
import chisel3.util.HasBlackBoxResource

import org.chipsalliance.cde.config.{Field, Parameters, Config}
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.interrupts._
import freechips.rocketchip.interrupts.{IntXing, IntSourceNode, IntSinkNode, IntSourcePortSimple, IntSinkPortSimple}
import freechips.rocketchip.prci._
import freechips.rocketchip.regmapper._
import freechips.rocketchip.subsystem._
import freechips.rocketchip.tilelink._
import freechips.rocketchip.devices.tilelink._
import freechips.rocketchip.util._
import sifive.blocks.util.{DeviceParams,DeviceAttachParams}
import sifive.blocks.devices.pinctrl.{PinCtrl, Pin, BasePin, EnhancedPin, EnhancedPinCtrl}
import java.net.InetAddress
import os.write.over

case class HMAC_SHAParams
(
    address: BigInt,
    version: Int = 1,
){}

case object HMAC_SHAKeys extends Field[Option[HMAC_SHAParams]](None)

class hmac_sha extends BlackBox with HasBlackBoxResource {
    override def desiredName = "hmac_core"
  val io = IO(new Bundle {
    //Inputs
    val clk             = Input(Clock())
    val resetn          = Input(Bool())
    val ready           = Output(Bool())
    val enable          = Input(Bool())
    val mm_rdata        = Output(UInt(64.W))
    val mm_addr         = Input(UInt(7.W))
    val mm_wen          = Input(Bool())
    val mm_wdata        = Input(UInt(64.W))
    // Stream port
    val input_ready     = Output(Bool())
    val iendofpacket    = Input(Bool())
  })

  // add wrapper/blackbox after it is pre-processed
  addResource("/crypto-vsrc/hmac_sha_v2.preprocessed.v")
}

class HMAC_SHATL(params: HMAC_SHAParams, beatBytes: Int)(implicit p: Parameters) extends ClockSinkDomain(ClockSinkParameters())(p){
    val device = new SimpleDevice("HMAC_SHA", Seq("sifive,HMAC_SHA-0.1"))
    val node = TLRegisterNode(Seq(AddressSet(params.address, 4096-1)), device, "reg/control", beatBytes=beatBytes)

    override lazy val module = new HMAC_SHAImpl
    class HMAC_SHAImpl extends Impl {
        withClockAndReset(clock, reset){

          // Registers
          val conf_data     = RegInit(0.U(64.W))
//          val conf_data_1     = RegInit(0.U(32.W))
          val conf_address    = RegInit(0.U(7.W))
          val dout          = RegInit(0.U(64.W))
//          val dout_1          = RegInit(0.U(32.W))
          val conf_we        = RegInit(0.U(1.W))

          val input_ready       = WireDefault(0.U(1.W))
          val endofpacket       = WireDefault(0.U(1.W))

          val resetn          = RegInit(1.U(1.W))
          val ready          =  RegInit(0.U(1.W))
          val enable         =  RegInit(0.U(1.W))

          val core_hmac_sha = Module(new hmac_sha)
//          core_hmac_sha.io.mm_wdata   := Cat(conf_data_0,conf_data_1)
          core_hmac_sha.io.mm_wdata   := conf_data
          core_hmac_sha.io.mm_addr:= conf_address
          core_hmac_sha.io.mm_wen    := conf_we

          core_hmac_sha.io.iendofpacket   := endofpacket
          input_ready := core_hmac_sha.io.input_ready
          core_hmac_sha.io.clk     := clock

          core_hmac_sha.io.resetn := !reset.asBool & resetn //TODO: need to come from a register?
//          ready := core_hmac_sha.io.ready

          // Rising edge detection: Pulse high for one cycle on 0->1 transition
          val prevReady = RegNext(core_hmac_sha.io.ready)  // Delay the signal by one clock (init implicitly to false/0)
          val setPulse = core_hmac_sha.io.ready && !prevReady  // AND with inverted previous value

          core_hmac_sha.io.enable := enable

          //i//nt := core_hmac_sha.io.cmplt_irq
//          dout_1                  := core_hmac_sha.io.mm_rdata(31,0) //TODO: the MSB matter?
//          dout_0                  := core_hmac_sha.io.mm_rdata(63,32)
          dout                  := core_hmac_sha.io.mm_rdata

            node.regmap(
                HMAC_SHACtrlRegs.conf_data -> Seq(RegField(64, conf_data, RegFieldDesc("conf_data", "conf_data"))),
//                HMAC_SHACtrlRegs.conf_data_1 -> Seq(RegField(32, conf_data_1, RegFieldDesc("conf_data_1", "conf_data_1"))),
                HMAC_SHACtrlRegs.conf_address -> Seq(RegField(7, conf_address, RegFieldDesc("conf_address", "conf_address"))),
                HMAC_SHACtrlRegs.dout -> Seq(RegField.r(64, dout, RegFieldDesc("dout", "dout"))),
//                HMAC_SHACtrlRegs.dout_1 -> Seq(RegField.r(32, dout_1, RegFieldDesc("dout_1", "dout_1"))),
                HMAC_SHACtrlRegs.conf_we -> Seq(RegField(1, conf_we, RegFieldDesc("conf_we", "Write enable"))),
                HMAC_SHACtrlRegs.input_ready -> Seq(RegField.r(1, input_ready, RegFieldDesc("input_ready", "Input ready"))),
                HMAC_SHACtrlRegs.endofpacket -> Seq(RegField(1, endofpacket, RegFieldDesc("endofpacket", "End of packet"))),
                HMAC_SHACtrlRegs.resetn -> Seq(RegField(1, resetn, RegFieldDesc("resetn", "Resetn"))),
                HMAC_SHACtrlRegs.ready -> Seq(RegField.w1ToClear(1, ready, setPulse.asUInt, Some(RegFieldDesc("ready", "Ready status (write 1 to clear)")))),
                HMAC_SHACtrlRegs.enable -> Seq(RegField(1, enable, RegFieldDesc("enable", "Enable"))),
            )
        }
    }
}


object HMAC_SHAID{
    val nextId = {
        var i = -1; () => {
            i += 1; i
        }
    }
}

trait CanHavePeripheryHMAC_SHA { this: BaseSubsystem =>
    private val portName = s"HMAC_SHA_${HMAC_SHAID.nextId()}"
//    private val pbus = locateTLBusWrapper(PBUS)

    val HMAC_SHA_busy = p(HMAC_SHAKeys) match {
        case Some(params) => {
            val HMAC_SHA = LazyModule(new HMAC_SHATL(params, pbus.beatBytes))
            HMAC_SHA.suggestName(portName)

            HMAC_SHA.clockNode := pbus.fixedClockNode
            pbus.coupleTo(portName) { HMAC_SHA.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }

            HMAC_SHA
        }
        case None => None
    }
}

class WithHMAC_SHA(address: BigInt) extends Config((site, here, up) => {
    case HMAC_SHAKeys => {
        println(f"Setting HMAC_SHA address: 0x${address}%X")
        Some(HMAC_SHAParams(address = address))
    }
})
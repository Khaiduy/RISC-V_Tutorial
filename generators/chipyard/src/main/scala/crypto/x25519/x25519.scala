package chipyard.crypto.x25519

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

case class X25519Params
(
    address: BigInt,
    version: Int = 1,
){}

case object X25519Keys extends Field[Option[X25519Params]](None)

class x25519 extends BlackBox with HasBlackBoxResource {
    override def desiredName = "X25519_full"
    val io = IO(new Bundle {
    // Inputs
    val iClk              = Input(Clock())
    val iRstn             = Input(Bool())
    val iStart            = Input(Bool())
    val scalar            = Input(UInt(256.W))
    val point_in          = Input(UInt(256.W))

    // Outputs
    val valid             = Output(Bool())
    val point_out         = Output(UInt(256.W))
    })

  // add wrapper/blackbox after it is pre-processed
  addResource("/crypto-vsrc/X25519_full.v")
}

class X25519TL(params: X25519Params, beatBytes: Int)(implicit p: Parameters) extends ClockSinkDomain(ClockSinkParameters())(p){
    val device = new SimpleDevice("X25519", Seq("sifive,X25519-0.1"))
    val node = TLRegisterNode(Seq(AddressSet(params.address, 4096-1)), device, "reg/control", beatBytes=beatBytes)

    override lazy val module = new X25519Impl
    class X25519Impl extends Impl {
        withClockAndReset(clock, reset){

            // Registers
            val scalar = Reg(Vec(4, UInt(64.W)))
            val point_in = Reg(Vec(4, UInt(64.W)))
            val point_out = Reg(Vec(4, UInt(64.W)))
            val control = RegInit(0.U(2.W))  // Expand to 2 bits
            val status = WireInit(0.U(2.W))

            // BlackBox instantiation
            val x25519_inst = Module(new x25519)
            x25519_inst.io.iClk := clock
            x25519_inst.io.iRstn := !reset.asBool && !control(1)  // System reset OR software reset
            x25519_inst.io.iStart := control(0) && !RegNext(control(0))
            x25519_inst.io.scalar := Cat(scalar)
            x25519_inst.io.point_in := Cat(point_in)

            // Outputs
            point_out := x25519_inst.io.point_out.asTypeOf(Vec(4, UInt(64.W)))
            status := Cat(x25519_inst.io.valid, control(0))

            node.regmap(
                X25519CtrlRegs.scalar -> RegFieldGroup("scalar", Some("Scalar input"), scalar.map(RegField(64, _))),
                X25519CtrlRegs.point_in -> RegFieldGroup("point_in", Some("Input point"), point_in.map(RegField(64, _))),
                X25519CtrlRegs.point_out -> RegFieldGroup("point_out", Some("Output point"), point_out.map(RegField.r(64, _))),
                X25519CtrlRegs.control -> Seq(RegField(1, control, RegFieldDesc("control", "Control register"))),
                X25519CtrlRegs.status -> Seq(RegField.r(2, status, RegFieldDesc("status", "Status register")))
            )
        }
    }
}


object X25519ID{
    val nextId = {
        var i = -1; () => {
            i += 1; i
        }
    }
}

trait CanHavePeripheryX25519 { this: BaseSubsystem =>
    private val portName = s"x25519_${X25519ID.nextId()}"
//    private val pbus = locateTLBusWrapper(PBUS)

    val x25519_busy = p(X25519Keys) match {
        case Some(params) => {
            val x25519 = LazyModule(new X25519TL(params, pbus.beatBytes))
            x25519.suggestName(portName)

            x25519.clockNode := pbus.fixedClockNode
            pbus.coupleTo(portName) { x25519.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }

            x25519
        }
        case None => None
    }
}

class WithX25519(address: BigInt) extends Config((site, here, up) => {
    case X25519Keys => {
        println(f"Setting x25519 address: 0x${address}%X")
        Some(X25519Params(address = address))
    }
})
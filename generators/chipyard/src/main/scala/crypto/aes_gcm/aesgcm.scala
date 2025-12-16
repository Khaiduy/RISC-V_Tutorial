package chipyard.crypto.aes_gcm

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

case class AESGCMParams
(
  address: BigInt,
  version: Int = 1,
)

case object AESGCMKey extends Field[Option[AESGCMParams]](None)

class aes_gcm_core extends BlackBox with HasBlackBoxResource {
  override def desiredName: String = "aes_gcm_v4_TOP"
  val io = IO(new Bundle {
    val ICLK_core = Input(Clock())
    val IRSTN_core = Input(Bool())
    val ICTRL_core = Input(UInt(4.W))
    val OREADY_core = Output(Bool())

    val IIV_core = Input(UInt(96.W))
    val IIV_VALID_core = Input(Bool())
    val IKEY_core = Input(UInt(256.W))
    val IKEY_VALID_core = Input(Bool())
    val IKEYLEN_core = Input(Bool())

    val IAAD_core = Input(UInt(128.W))
    val IAAD_VALID_core = Input(Bool())

    val IBLOCK_core = Input(UInt(128.W))
    val IBLOCK_VALID_core = Input(Bool())

    val ITAG_core = Input(UInt(128.W))
    val ITAG_VALID_core = Input(Bool())

    val IBLOCK_BYTES_core = Input(UInt(4.W))

    val ORESULT_core = Output(UInt(128.W))
    val ORESULT_VALID_core = Output(Bool())
    val OTAG_core = Output(UInt(128.W))
    val OTAG_VALID_core = Output(Bool())
    val OAUTHENTIC_core = Output(Bool())
  })
  addResource("/crypto-vsrc/aes_gcm_small.preprocessed.v")
}

class AESGCMTL(params: AESGCMParams, beatBytes: Int)(implicit p: Parameters) extends ClockSinkDomain(ClockSinkParameters())(p) {
  val device = new SimpleDevice("aesgcm", Seq("sifive,aesgcm-0.1"))
  val node = TLRegisterNode(Seq(AddressSet(params.address, 4096-1)), device, "reg/control", beatBytes=beatBytes) // 64-bit bus

  override lazy val module = new aesgcmImpl
  class aesgcmImpl extends Impl {
    withClockAndReset(clock, reset) {
      // Registers
      val ICTRL = RegInit(0.U(4.W))
      val IBLOCK_BYTES = RegInit(0.U(4.W))
      val OREADY = WireDefault(0.U(1.W))

      // IIV (96 bits) split into 2x64-bit registers (padded to 128 bits)
      val IIV_0 = RegInit(0.U(64.W))
      val IIV_1 = RegInit(0.U(64.W))
      val IIV_VALID = RegInit(0.U(1.W))

      // IKEY (256 bits) split into 4x64-bit registers
      val IKEY_0 = RegInit(0.U(64.W))
      val IKEY_1 = RegInit(0.U(64.W))
      val IKEY_2 = RegInit(0.U(64.W))
      val IKEY_3 = RegInit(0.U(64.W))
      val IKEY_VALID = RegInit(0.U(1.W))
      val IKEYLEN = RegInit(0.U(1.W))

      // IAAD (128 bits) split into 2x64-bit registers
      val IAAD_0 = RegInit(0.U(64.W))
      val IAAD_1 = RegInit(0.U(64.W))
      val IAAD_VALID = RegInit(0.U(1.W))

      // IBLOCK (128 bits) split into 2x64-bit registers
      val IBLOCK_0 = RegInit(0.U(64.W))
      val IBLOCK_1 = RegInit(0.U(64.W))
      val IBLOCK_VALID = RegInit(0.U(1.W))

      // ITAG (128 bits) split into 2x64-bit registers
      val ITAG_0 = RegInit(0.U(64.W))
      val ITAG_1 = RegInit(0.U(64.W))
      val ITAG_VALID = RegInit(0.U(1.W))

      val IRESETN = RegInit(1.U(1.W))

      // Outputs
      val ORESULT_0 = RegInit(0.U(64.W))
      val ORESULT_1 = RegInit(0.U(64.W))
      val ORESULT_VALID = RegInit(0.U(1.W))
      val OTAG_0 = RegInit(0.U(64.W))
      val OTAG_1 = RegInit(0.U(64.W))
      val OTAG_VALID = RegInit(0.U(1.W))
      val OAUTHENTIC = RegInit(0.U(1.W))

      val core_aes_gcm = Module(new aes_gcm_core)
      core_aes_gcm.io.ICLK_core := clock
      core_aes_gcm.io.IRSTN_core := !reset.asBool & IRESETN

      core_aes_gcm.io.ICTRL_core := ICTRL
      core_aes_gcm.io.IBLOCK_BYTES_core := IBLOCK_BYTES
      OREADY := core_aes_gcm.io.OREADY_core

      // Concatenate 64-bit registers to form wide signals
      core_aes_gcm.io.IIV_core := Cat(IIV_0(63, 0), IIV_1(31, 0)) // Take 96 bits
      core_aes_gcm.io.IIV_VALID_core := IIV_VALID
      core_aes_gcm.io.IKEY_core := Cat(IKEY_0, IKEY_1, IKEY_2, IKEY_3)
      core_aes_gcm.io.IKEY_VALID_core := IKEY_VALID
      core_aes_gcm.io.IKEYLEN_core := IKEYLEN

      core_aes_gcm.io.IAAD_core := Cat(IAAD_0, IAAD_1)
      core_aes_gcm.io.IAAD_VALID_core := IAAD_VALID
      core_aes_gcm.io.IBLOCK_core := Cat(IBLOCK_0, IBLOCK_1)
      core_aes_gcm.io.IBLOCK_VALID_core := IBLOCK_VALID

      core_aes_gcm.io.ITAG_core := Cat(ITAG_0, ITAG_1)
      core_aes_gcm.io.ITAG_VALID_core := ITAG_VALID
      // Split 128-bit outputs into 2x64-bit registers
      ORESULT_1 := core_aes_gcm.io.ORESULT_core(63, 0)
      ORESULT_0 := core_aes_gcm.io.ORESULT_core(127, 64)
      ORESULT_VALID := core_aes_gcm.io.ORESULT_VALID_core

      OTAG_1 := core_aes_gcm.io.OTAG_core(63, 0)
      OTAG_0 := core_aes_gcm.io.OTAG_core(127, 64)
      OTAG_VALID := core_aes_gcm.io.OTAG_VALID_core

      OAUTHENTIC := core_aes_gcm.io.OAUTHENTIC_core

      // Register mapping for 64-bit CPU
      node.regmap(
        AES_GCMRegs.ICTRL -> Seq(
          RegField(4, ICTRL, RegFieldDesc("ICTRL", "Control register"))
        ),
        AES_GCMRegs.OREADY -> Seq(
          RegField.r(1, OREADY, RegFieldDesc("OREADY", "Ready status"))
        ),
        AES_GCMRegs.IIV_0 -> Seq(
          RegField(64, IIV_0, RegFieldDesc("IIV_0", "IV bits 95:32"))
        ),
        AES_GCMRegs.IIV_1 -> Seq(
          RegField(64, IIV_1, RegFieldDesc("IIV_1", "IV bits 31:0, padded"))
        ),
        AES_GCMRegs.IIV_VALID -> Seq(
          RegField(1, IIV_VALID, RegFieldDesc("IIV_VALID", "IV valid"))
        ),
        AES_GCMRegs.IKEY_0 -> Seq(
          RegField(64, IKEY_0, RegFieldDesc("IKEY_0", "Key bits 255:192"))
        ),
        AES_GCMRegs.IKEY_1 -> Seq(
          RegField(64, IKEY_1, RegFieldDesc("IKEY_1", "Key bits 191:128"))
        ),
        AES_GCMRegs.IKEY_2 -> Seq(
          RegField(64, IKEY_2, RegFieldDesc("IKEY_2", "Key bits 127:64"))
        ),
        AES_GCMRegs.IKEY_3 -> Seq(
          RegField(64, IKEY_3, RegFieldDesc("IKEY_3", "Key bits 63:0"))
        ),
        AES_GCMRegs.IKEY_VALID -> Seq(
          RegField(1, IKEY_VALID, RegFieldDesc("IKEY_VALID", "Key valid"))
        ),
        AES_GCMRegs.IKEYLEN -> Seq(
          RegField(1, IKEYLEN, RegFieldDesc("IKEYLEN", "Key length (0=128b, 1=256b)"))
        ),
        AES_GCMRegs.IAAD_0 -> Seq(
          RegField(64, IAAD_0, RegFieldDesc("IAAD_0", "AAD bits 127:64", reset = Some(0)))
        ),
        AES_GCMRegs.IAAD_1 -> Seq(
          RegField(64, IAAD_1, RegFieldDesc("IAAD_1", "AAD bits 63:0", reset = Some(0)))
        ),
        AES_GCMRegs.IAAD_VALID -> Seq(
          RegField(1, IAAD_VALID, RegFieldDesc("IAAD_VALID", "AAD valid", volatile = true))
        ),
        AES_GCMRegs.IBLOCK_0 -> Seq(
          RegField(64, IBLOCK_0, RegFieldDesc("IBLOCK_0", "Block bits 127:64", volatile = true))
        ),
        AES_GCMRegs.IBLOCK_1 -> Seq(
          RegField(64, IBLOCK_1, RegFieldDesc("IBLOCK_1", "Block bits 63:0", volatile = true))
        ),
        AES_GCMRegs.IBLOCK_VALID -> Seq(
          RegField(1, IBLOCK_VALID, RegFieldDesc("IBLOCK_VALID", "Block valid", volatile = true))
        ),
        AES_GCMRegs.ITAG_0 -> Seq(
          RegField(64, ITAG_0, RegFieldDesc("ITAG_0", "Tag bits 127:64", volatile = true))
        ),
        AES_GCMRegs.ITAG_1 -> Seq(
          RegField(64, ITAG_1, RegFieldDesc("ITAG_1", "Tag bits 63:0", volatile = true))
        ),
        AES_GCMRegs.ITAG_VALID -> Seq(
          RegField(1, ITAG_VALID, RegFieldDesc("ITAG_VALID", "Tag valid", volatile = true))
        ),
        AES_GCMRegs.ORESULT_0 -> Seq(
          RegField.r(64, ORESULT_0, RegFieldDesc("ORESULT_0", "Result bits 127:64", volatile = true))
        ),
        AES_GCMRegs.ORESULT_1 -> Seq(
          RegField.r(64, ORESULT_1, RegFieldDesc("ORESULT_1", "Result bits 63:0", volatile = true))
        ),
        AES_GCMRegs.ORESULT_VALID -> Seq(
          RegField.r(1, ORESULT_VALID, RegFieldDesc("ORESULT_VALID", "Result valid", volatile = true))
        ),
        AES_GCMRegs.OTAG_0 -> Seq(
          RegField.r(64, OTAG_0, RegFieldDesc("OTAG_0", "Tag bits 127:64", volatile = true))
        ),
        AES_GCMRegs.OTAG_1 -> Seq(
          RegField.r(64, OTAG_1, RegFieldDesc("OTAG_1", "Tag bits 63:0", volatile = true))
        ),
        AES_GCMRegs.OTAG_VALID -> Seq(
          RegField.r(1, OTAG_VALID, RegFieldDesc("OTAG_VALID", "Tag valid", volatile = true))
        ),
        AES_GCMRegs.OAUTHENTIC -> Seq(
          RegField.r(1, OAUTHENTIC, RegFieldDesc("OAUTHENTIC", "Authentication result", volatile = true))
        ),
        AES_GCMRegs.IRESETN -> Seq(
          RegField(1, IRESETN, RegFieldDesc("IRESETN", "Reset control", volatile = true))
        ),
        AES_GCMRegs.IBLOCK_BYTES -> Seq(
          RegField(4, IBLOCK_BYTES, RegFieldDesc("IBLOCK_BYTES", "Last block bytes register"))
        )
      )
    }
  }
}

object AESGCMID {
  val nextId = {
    var i = -1; () => {
      i += 1; i
    }
  }
}

trait CanHavePeripheryAESGCM { this: BaseSubsystem =>
  private val portName = s"aes_${AESGCMID.nextId()}"
//  private val pbus = locateTLBusWrapper(PBUS)

  val aes_busy = p(AESGCMKey) match {
    case Some(params) => {
      val aesgcm = LazyModule(new AESGCMTL(params, this.pbus.beatBytes))
      aesgcm.suggestName(portName)

      aesgcm.clockNode := this.pbus.fixedClockNode
      this.pbus.coupleTo(portName) { aesgcm.node := TLFragmenter(this.pbus.beatBytes, this.pbus.blockBytes) := _ }

      aesgcm
    }
    case None => None
  }
}

class WithAESGCM(address: BigInt) extends Config((site, here, up) => {
  case AESGCMKey => {
    println(f"Setting AES-GCM address: 0x${address}%X")
    Some(AESGCMParams(address = address))
  }
})
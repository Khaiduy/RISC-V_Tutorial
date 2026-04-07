package chipyard.crypto.trng

import chisel3._
import chisel3.util._
import org.chipsalliance.cde.config.{Parameters, Field, Config}
import freechips.rocketchip.subsystem.BaseSubsystem
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.regmapper.{HasRegMap, RegField, RegFieldDesc}
import freechips.rocketchip.tilelink._

case class TRNGParams(
  address: BigInt = 0x10030000,  // Base address for TRNG peripheral
  beatBytes: Int = 8
)

case object TRNGKey extends Field[Option[TRNGParams]](None)

// BlackBox wrapper for TRNG Verilog module
class TRNGBlackBox extends BlackBox with HasBlackBoxResource {
  val io = IO(new Bundle {
    val iClk   = Input(Clock())
    val iRst   = Input(Bool())
    val iStart = Input(Bool())
    val oRo    = Output(Bool())
    val oRNS   = Output(UInt(256.W))
    val oDone  = Output(Bool())
  })
  
  addResource("/trng_vsrc/TRNG.v")
  addResource("/trng_vsrc/TopTRNG.v")
  addResource("/trng_vsrc/LFSR_64.v")
  addResource("/trng_vsrc/ringOsc.v")
  addResource("/trng_vsrc/FF_D.v")
}

// Top-level TRNG module with sticky done bit
class TRNGModule(params: TRNGParams, beatBytes: Int)(implicit p: Parameters)
  extends LazyModule
{
  val device = new SimpleDevice("trng", Seq("chipyard,trng"))
  val node = TLRegisterNode(
    address = Seq(AddressSet(params.address, 4096-1)),
    device = device,
    beatBytes = beatBytes
  )

  lazy val module = new LazyModuleImp(this) {
    // Instantiate TRNG BlackBox
    val trng = Module(new TRNGBlackBox)
    
    // Connect clock and reset
    trng.io.iClk := clock
    trng.io.iRst := reset.asBool
    
    // Control and status registers
    val start_reg = RegInit(false.B)
    val done_sticky = RegInit(false.B)  // Sticky done bit - stays high until cleared
    val rns_regs = Reg(Vec(8, UInt(32.W)))  // 8x 32-bit registers for 256-bit output
    
    // Connect start signal
    trng.io.iStart := start_reg
    
    // Capture TRNG output when done
    when (trng.io.oDone) {
      done_sticky := true.B
      // Split 256-bit output into 8x 32-bit registers
      rns_regs(0) := trng.io.oRNS(31, 0)
      rns_regs(1) := trng.io.oRNS(63, 32)
      rns_regs(2) := trng.io.oRNS(95, 64)
      rns_regs(3) := trng.io.oRNS(127, 96)
      rns_regs(4) := trng.io.oRNS(159, 128)
      rns_regs(5) := trng.io.oRNS(191, 160)
      rns_regs(6) := trng.io.oRNS(223, 192)
      rns_regs(7) := trng.io.oRNS(255, 224)
    }
    
    // Auto-clear start after one cycle
    when (start_reg) {
      start_reg := false.B
    }
    
    // Register map
    node.regmap(
      // 0x00: Control register
      //   [0] = start (write 1 to start TRNG)
      0x00 -> Seq(RegField.w(1, start_reg)),
      
      // 0x04: Status register
      //   [0] = done_sticky (write 1 to clear)
      //   [1] = busy (read-only, inverse of done)
      0x04 -> Seq(
        RegField(1, done_sticky, RegFieldDesc("done", "Sticky done flag, write 1 to clear")),
        RegField.r(1, !done_sticky, RegFieldDesc("busy", "TRNG busy status"))
      ),
      
      // 0x10-0x2C: Random number output (8x 32-bit words = 256 bits)
      0x10 -> Seq(RegField.r(32, rns_regs(0), RegFieldDesc("rns0", "Random bits [31:0]"))),
      0x14 -> Seq(RegField.r(32, rns_regs(1), RegFieldDesc("rns1", "Random bits [63:32]"))),
      0x18 -> Seq(RegField.r(32, rns_regs(2), RegFieldDesc("rns2", "Random bits [95:64]"))),
      0x1C -> Seq(RegField.r(32, rns_regs(3), RegFieldDesc("rns3", "Random bits [127:96]"))),
      0x20 -> Seq(RegField.r(32, rns_regs(4), RegFieldDesc("rns4", "Random bits [159:128]"))),
      0x24 -> Seq(RegField.r(32, rns_regs(5), RegFieldDesc("rns5", "Random bits [191:160]"))),
      0x28 -> Seq(RegField.r(32, rns_regs(6), RegFieldDesc("rns6", "Random bits [223:192]"))),
      0x2C -> Seq(RegField.r(32, rns_regs(7), RegFieldDesc("rns7", "Random bits [255:224]")))
    )
  }
}

// Trait to add TRNG to subsystem
trait CanHavePeripheryTRNG { this: BaseSubsystem =>
  private val portName = "trng"
  
  val trng = p(TRNGKey).map { params =>
    val trng = LazyModule(new TRNGModule(params, pbus.beatBytes))
    pbus.coupleTo(portName) {
      trng.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _
    }
    trng
  }
}

// Mixin for top-level module
trait CanHavePeripheryTRNGModuleImp extends LazyModuleImp {
  val outer: CanHavePeripheryTRNG
}

// Config fragment to add TRNG
class WithTRNG(address: BigInt = 0x10030000) extends Config((site, here, up) => {
  case TRNGKey => Some(TRNGParams(address = address))
})

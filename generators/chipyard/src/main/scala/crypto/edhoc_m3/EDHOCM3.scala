package chipyard.crypto.edhoc

import chisel3._
import chisel3.util._
import chisel3.util.HasBlackBoxResource

import org.chipsalliance.cde.config.{Field, Parameters, Config}
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.prci._
import freechips.rocketchip.regmapper._
import freechips.rocketchip.subsystem._
import freechips.rocketchip.tilelink._
import freechips.rocketchip.devices.tilelink._
import freechips.rocketchip.util._
import sifive.blocks.util.{DeviceParams, DeviceAttachParams}

// =============================================================================
// EDHOC Method 3 Hardware Accelerator — Chipyard Integration
//
// The edhoc_m3_top already has a simple 32-bit register-mapped bus interface:
//   addr[8:0], wdata[31:0], wen, rdata[31:0]
//
// This wrapper bridges TileLink → edhoc_m3_top's native bus, so the Scala
// side is much simpler than the PSK wrapper (no wide-port packing needed).
// =============================================================================

/**
 * EDHOC Method 3 Accelerator Parameters
 */
case class EDHOCM3Params(
  address: BigInt,
  version: Int = 1
)

case object EDHOCM3Keys extends Field[Option[EDHOCM3Params]](None)

/**
 * BlackBox wrapper for edhoc_m3_top Verilog module
 *
 * edhoc_m3_top implements EDHOC Method 3 Suite 0:
 *   - X25519 + HMAC-SHA256 + AES-CCM-16-64-128
 *   - Signature-based authentication (static DH keys)
 *   - Full Initiator + Responder roles
 *   - OSCORE key derivation
 *   - External AEAD interface for post-handshake CoAP encryption
 */
class edhoc_m3_top extends BlackBox with HasBlackBoxResource {
  override def desiredName = "edhoc_m3_top"

  val io = IO(new Bundle {
    val clk   = Input(Clock())
    val rst   = Input(Bool())
    val addr  = Input(UInt(9.W))
    val wdata = Input(UInt(32.W))
    val wen   = Input(Bool())
    val rdata = Output(UInt(32.W))
  })

  // All Verilog source files composing edhoc_m3_top.
  // Verilog sources live in crypto-vsrc/edhoc_m3/ (flat — no subdirectories).
  // Order: leaf modules first, top-level last.
  // ── X25519 pipeline ──────────────────────────────────────────────────────
  addResource("/crypto-vsrc/edhoc_m3/ladder_rom.v")
  addResource("/crypto-vsrc/edhoc_m3/new_x25519/mac17_dsp.v")
  addResource("/crypto-vsrc/edhoc_m3/new_x25519/unified_modular_arith.v")
  addResource("/crypto-vsrc/edhoc_m3/x25519_proc_pipeline.v")
  // ── AES-CCM ───────────────────────────────────────────────────────────────
  addResource("/crypto-vsrc/edhoc_m3/aes_sbox.v")
  addResource("/crypto-vsrc/edhoc_m3/aes128_core.v")
  addResource("/crypto-vsrc/edhoc_m3/aes_ccm_32.v")
  // ── HMAC-SHA256 ───────────────────────────────────────────────────────────
  addResource("/crypto-vsrc/edhoc_m3/fa.v")
  addResource("/crypto-vsrc/edhoc_m3/adder_64.v")
  addResource("/crypto-vsrc/edhoc_m3/csa64.v")
  addResource("/crypto-vsrc/edhoc_m3/triple_adder_64.v")
  addResource("/crypto-vsrc/edhoc_m3/ch.v")
  addResource("/crypto-vsrc/edhoc_m3/maj.v")
  addResource("/crypto-vsrc/edhoc_m3/s0_32.v")
  addResource("/crypto-vsrc/edhoc_m3/s1_32.v")
  addResource("/crypto-vsrc/edhoc_m3/SIG0_32.v")
  addResource("/crypto-vsrc/edhoc_m3/SIG1_32.v")
  addResource("/crypto-vsrc/edhoc_m3/K_ROM.v")
  addResource("/crypto-vsrc/edhoc_m3/init_ROM.v")
  addResource("/crypto-vsrc/edhoc_m3/pos_adjust.v")
  addResource("/crypto-vsrc/edhoc_m3/w_unit.v")
  addResource("/crypto-vsrc/edhoc_m3/compress.v")
  addResource("/crypto-vsrc/edhoc_m3/memory.v")
  addResource("/crypto-vsrc/edhoc_m3/sha_pad.v")
  addResource("/crypto-vsrc/edhoc_m3/sha_padding.v")
  addResource("/crypto-vsrc/edhoc_m3/sha_controller.v")
  addResource("/crypto-vsrc/edhoc_m3/sha_core.v")
  addResource("/crypto-vsrc/edhoc_m3/hmac_padding.v")
  addResource("/crypto-vsrc/edhoc_m3/hmac_controller.v")
  addResource("/crypto-vsrc/edhoc_m3/hmac_core.v")
  // ── EDHOC protocol modules ────────────────────────────────────────────────
  addResource("/crypto-vsrc/edhoc_m3/stream_formatter.v")
  addResource("/crypto-vsrc/edhoc_m3/sym_controller.v")
  addResource("/crypto-vsrc/edhoc_m3/protocol_coordinator.v")
  addResource("/crypto-vsrc/edhoc_m3/edhoc_regmap.v")
  addResource("/crypto-vsrc/edhoc_m3/edhoc_m3_top.v")
}

/**
 * TileLink peripheral wrapper for EDHOC Method 3 accelerator
 *
 * Maps TileLink Get/Put to the simple addr/wdata/wen/rdata bus of edhoc_m3_top.
 * Address space: 512 bytes (addr[8:0] byte address → 128 word addresses).
 */
class EDHOCM3TLL(params: EDHOCM3Params, beatBytes: Int)(implicit p: Parameters)
    extends ClockSinkDomain(ClockSinkParameters())(p) {

  val device = new SimpleDevice("EDHOC-M3", Seq("sifive,EDHOC-M3-0.1"))
  val node = TLRegisterNode(
    Seq(AddressSet(params.address, 0x1FF)),  // 512 bytes
    device,
    "reg/control",
    beatBytes = beatBytes
  )

  override lazy val module = new EDHOCM3Impl

  class EDHOCM3Impl extends Impl {
    withClockAndReset(clock, reset) {

      // Instantiate the Verilog BlackBox
      val m3 = Module(new edhoc_m3_top)
      m3.io.clk := clock
      m3.io.rst := reset.asBool

      // ===== TileLink → Simple Bus Bridge =====
      // edhoc_m3_top uses byte addresses [8:0] directly.
      // TileLink regmap provides word-aligned access.
      //
      // We create a register-based bridge:
      //   - CPU write: latch addr+wdata, pulse wen for 1 cycle
      //   - CPU read: drive addr, read rdata combinationally

      val bus_addr  = Wire(UInt(9.W))
      val bus_wdata = Wire(UInt(32.W))
      val bus_wen   = Wire(Bool())
      val bus_rdata = Wire(UInt(32.W))

      bus_addr  := 0.U
      bus_wdata := 0.U
      bus_wen   := false.B

      m3.io.addr  := bus_addr
      m3.io.wdata := bus_wdata
      m3.io.wen   := bus_wen
      bus_rdata   := m3.io.rdata

      // Number of 32-bit registers in the 512-byte address space
      val numRegs = 128  // 512 / 4

      // Build regmap: each 32-bit word maps to a regField with custom read/write.
      //
      // Read path: edhoc_regmap.v has a purely combinational always @(*) read
      //   (rdata reflects waddr = addr[8:2] within the same cycle).
      //   We guard bus_addr assignment with when(ready) so that only the one
      //   register being accessed drives the shared bus_addr wire.
      //   Without this guard, all 128 lambdas would unconditionally assign
      //   bus_addr, and Chisel's last-write-wins would leave it stuck at 0x1FC.
      //
      // Write path: wen is driven high for exactly one TileLink beat (valid is
      //   asserted for one cycle since ready is always true).  edhoc_regmap.v
      //   samples wen on posedge clk, matching the testbench write protocol.
      val regFields = (0 until numRegs).map { i =>
        val byteAddr = (i * 4).U(9.W)

        (i * 4) -> Seq(RegField(32,
          // Read function — guard bus_addr with when(ready) to avoid multi-driver
          RegReadFn { ready =>
            when(ready) {
              bus_addr := byteAddr
              bus_wen  := false.B
            }
            (true.B, bus_rdata)
          },
          // Write function
          RegWriteFn { (valid, data) =>
            when(valid) {
              bus_addr  := byteAddr
              bus_wdata := data
              bus_wen   := true.B
            }
            true.B  // always ready
          },
          Some(RegFieldDesc(s"reg_${f"$i%03d"}", s"EDHOC M3 register at 0x${f"${i*4}%03X"}"))
        ))
      }

      node.regmap(regFields: _*)
    }
  }
}

/**
 * ID generator for multiple EDHOC M3 instances
 */
object EDHOCM3ID {
  val nextId = {
    var i = -1; () => {
      i += 1; i
    }
  }
}

/**
 * Trait to add EDHOC M3 peripheral to a subsystem
 */
trait CanHavePeripheryEDHOCM3 { this: BaseSubsystem =>
  private val portName = s"edhoc_m3_${EDHOCM3ID.nextId()}"

  val edhoc_m3 = p(EDHOCM3Keys) match {
    case Some(params) => {
      val m3 = LazyModule(new EDHOCM3TLL(params, pbus.beatBytes))
      m3.suggestName(portName)

      m3.clockNode := pbus.fixedClockNode
      pbus.coupleTo(portName) { m3.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }

      Some(m3)
    }
    case None => None
  }
}

/**
 * Configuration class to add EDHOC M3 to a design
 */
class WithEDHOCM3(address: BigInt) extends Config((site, here, up) => {
  case EDHOCM3Keys => {
    println(f"Setting EDHOC M3 address: 0x${address}%X")
    Some(EDHOCM3Params(address = address))
  }
})

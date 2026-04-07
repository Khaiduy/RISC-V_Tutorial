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

/**
 * EDHOC Hardware Accelerator Parameters
 */
case class EDHOCParams(
  address: BigInt,
  version: Int = 1
)

case object EDHOCKeys extends Field[Option[EDHOCParams]](None)

/**
 * BlackBox wrapper for edhoc_top Verilog module
 * 
 * The edhoc_top module implements the complete EDHOC+OSCORE protocol:
 * - EDHOC-PSK authentication (Method 4)
 * - Cipher Suite 7: X25519, ASCON-AEAD-128, ASCON-Hash-256
 * - Derives OSCORE keys (Common IV, Sender Key, Recipient Key)
 * - Provides external AEAD interface for CoAP encryption
 */
class edhoc_top extends BlackBox with HasBlackBoxResource {
  override def desiredName = "edhoc_top"
  
  val io = IO(new Bundle {
    // Clock and Reset
    val clk = Input(Clock())
    val rst = Input(Bool())
    
    // Control
    val start     = Input(Bool())
    val initiator = Input(Bool())
    val done      = Output(Bool())
    val error     = Output(Bool())
    
    // Message Handshake
    val msg_ready    = Output(Bool())
    val msg_valid    = Input(Bool())
    val output_valid = Output(Bool())
    val output_ack   = Input(Bool())        // Acknowledge output captured (clears output_valid)
    val current_msg  = Output(UInt(2.W))
    
    // TRNG Interface
    val trng_en       = Input(Bool())
    val trng_ro       = Output(Bool())
    
    // XDRBG Bypass (for testing)
    val xdrbg_bypass  = Input(Bool())
    val ephemeral_key = Input(UInt(256.W))
    
    // Keys and Parameters
    val c_x           = Input(UInt(8.W))
    val method        = Input(UInt(8.W))
    val suite         = Input(UInt(8.W))
    val id_cred_psk   = Input(UInt(8.W))
    val kid_initiator = Input(UInt(8.W))
    val kid_responder = Input(UInt(8.W))
    val id_initiator  = Input(UInt(64.W))
    val id_responder  = Input(UInt(64.W))
    
    // Message Data I/O
    val data_in  = Input(UInt(296.W))
    val data_out = Output(UInt(296.W))
    
    // OSCORE Keys Status
    val oscore_keys_valid = Output(Bool())
    
    // External AEAD Interface for CoAP
    // Hardware constructs nonce from sender_id + partial_iv + Common_IV
    val aead_start          = Input(Bool())
    val aead_encrypt        = Input(Bool())
    val aead_sender_id      = Input(UInt(8.W))   // Sender ID for nonce construction
    val aead_partial_iv     = Input(UInt(40.W))  // Partial IV / sequence number
    val aead_aad            = Input(UInt(128.W))
    val aead_aad_len        = Input(UInt(4.W))
    val aead_data_in        = Input(UInt(128.W))
    val aead_data_len       = Input(UInt(4.W))
    val aead_use_sender_key = Input(Bool())
    val aead_exp_tag        = Input(UInt(128.W)) // Expected tag for decryption verification
    val aead_data_out       = Output(UInt(128.W))
    val aead_tag            = Output(UInt(128.W))
    val aead_done           = Output(Bool())
    val aead_tag_valid      = Output(Bool())
  })
  
  // Add all Verilog resources
  addResource("/crypto-vsrc/edhoc/edhoc_top.v")
  addResource("/crypto-vsrc/edhoc/x25519_proc_pipeline.v")
  addResource("/crypto-vsrc/edhoc/ascon_wrapper.v")
  addResource("/crypto-vsrc/edhoc/ascon_unified.v")
  addResource("/crypto-vsrc/edhoc/asconp.v")
  addResource("/crypto-vsrc/edhoc/modular_multiplier_pipeline_opt.v")
  addResource("/crypto-vsrc/edhoc/addsubmod.v")
  addResource("/crypto-vsrc/edhoc/ladder_rom.v")
  addResource("/crypto-vsrc/edhoc/mac17.v")
  addResource("/crypto-vsrc/edhoc/TopTRNG.v")
  addResource("/crypto-vsrc/edhoc/FF_D.v")
  addResource("/crypto-vsrc/edhoc/LFSR_64.v")
  addResource("/crypto-vsrc/edhoc/ringOsc.v")
}

/**
 * TileLink peripheral wrapper for EDHOC accelerator
 */
class EDHOCTLL(params: EDHOCParams, beatBytes: Int)(implicit p: Parameters) 
    extends ClockSinkDomain(ClockSinkParameters())(p) {
  
  val device = new SimpleDevice("EDHOC", Seq("sifive,EDHOC-0.1"))
  val node = TLRegisterNode(
    Seq(AddressSet(params.address, 4096-1)), 
    device, 
    "reg/control", 
    beatBytes = beatBytes
  )
  
  override lazy val module = new EDHOCImpl
  
  class EDHOCImpl extends Impl {
    withClockAndReset(clock, reset) {
      
      // ===== Input Registers =====
      val trng_control  = RegInit(0.U(2.W))           // trng_en, xdrbg_bypass
      val ephemeral_key = Reg(Vec(8, UInt(32.W)))     // 256-bit (only for xdrbg_bypass mode)
      val params_0      = RegInit(0.U(32.W))          // c_x, method, suite, id_cred_psk
      val params_1      = RegInit(0.U(32.W))          // kid_initiator, kid_responder
      val id_initiator  = Reg(Vec(2, UInt(32.W)))     // 64-bit
      val id_responder  = Reg(Vec(2, UInt(32.W)))     // 64-bit
      val control       = RegInit(0.U(7.W))           // start, initiator, aead_start, aead_encrypt, aead_use_sender_key, reset, clear_flags
      val data_in       = Reg(Vec(10, UInt(32.W)))    // 320-bit (only lower 296 used)
      
      // AEAD interface registers - Hardware constructs nonce from sender_id + partial_iv
      val aead_sender_id    = RegInit(0.U(8.W))         // 8-bit sender ID
      val aead_partial_iv   = Reg(Vec(2, UInt(32.W)))   // 40-bit partial IV (use 2x32, only 40 bits used)
      val aead_aad        = Reg(Vec(4, UInt(32.W)))     // 128-bit
      val aead_lengths    = RegInit(0.U(32.W))          // aad_len, data_len
      val aead_data_in    = Reg(Vec(4, UInt(32.W)))     // 128-bit
      val aead_exp_tag    = Reg(Vec(4, UInt(32.W)))     // 128-bit expected tag for decryption
      
      // Message valid pulse register
      val msg_valid_reg = RegInit(false.B)
      val msg_valid_prev = RegNext(msg_valid_reg)
      val msg_valid_pulse = msg_valid_reg && !msg_valid_prev
      
      // Output acknowledge pulse register (mirrors msg_valid pattern)
      val output_ack_reg = RegInit(false.B)
      val output_ack_prev = RegNext(output_ack_reg)
      val output_ack_pulse = output_ack_reg && !output_ack_prev
      
      // ===== Output Registers =====
      val status        = WireInit(0.U(10.W))
      val data_out      = Reg(Vec(10, UInt(32.W)))    // 320-bit (only lower 296 used)
      val aead_data_out = Reg(Vec(4, UInt(32.W)))     // 128-bit
      val aead_tag      = Reg(Vec(4, UInt(32.W)))     // 128-bit
      
      // Sticky flags for msg_ready etc. (hold until cleared by software)
      // NOTE: output_valid is now handled by hardware with output_ack handshake
      val msg_ready_sticky = RegInit(false.B)
      val aead_tag_valid_sticky = RegInit(false.B)
      val done_sticky = RegInit(false.B)
      val aead_done_sticky = RegInit(false.B)
      val oscore_keys_valid_sticky = RegInit(false.B)
      
      // ===== BlackBox Instantiation =====
      val edhoc_inst = Module(new edhoc_top)
      
      // Clock and Reset
      edhoc_inst.io.clk := clock
      edhoc_inst.io.rst := reset.asBool || control(5)  // System reset OR software reset
      
      // Control signals - generate pulses for start and aead_start
      val start_pulse = control(0) && !RegNext(control(0))
      val aead_start_pulse = control(2) && !RegNext(control(2))
      
      edhoc_inst.io.start     := start_pulse
      edhoc_inst.io.initiator := control(1)
      
      // Message handshake
      edhoc_inst.io.msg_valid := msg_valid_pulse
      edhoc_inst.io.output_ack := output_ack_pulse
      // TRNG Interface
      edhoc_inst.io.trng_en      := trng_control(0)
      edhoc_inst.io.xdrbg_bypass := trng_control(1)
      
      // 
      // Keys and Parameters
      edhoc_inst.io.ephemeral_key := Cat(ephemeral_key.reverse)
      edhoc_inst.io.c_x           := params_0(7, 0)
      edhoc_inst.io.method        := params_0(15, 8)
      edhoc_inst.io.suite         := params_0(23, 16)
      edhoc_inst.io.id_cred_psk   := params_0(31, 24)
      edhoc_inst.io.kid_initiator := params_1(7, 0)
      edhoc_inst.io.kid_responder := params_1(15, 8)
      edhoc_inst.io.id_initiator  := Cat(id_initiator.reverse)
      edhoc_inst.io.id_responder  := Cat(id_responder.reverse)
      
      // Message Data I/O (296 bits = 37 bytes, padded to 320 bits = 10x32)
      edhoc_inst.io.data_in := Cat(data_in.reverse)(319, 24)
      
      // AEAD Interface - Hardware constructs nonce from sender_id + partial_iv + Common_IV
      edhoc_inst.io.aead_start          := aead_start_pulse
      edhoc_inst.io.aead_encrypt        := control(3)
      edhoc_inst.io.aead_sender_id      := aead_sender_id
      edhoc_inst.io.aead_partial_iv     := Cat(aead_partial_iv.reverse)(39, 0)
      edhoc_inst.io.aead_aad            := Cat(aead_aad.reverse)
      edhoc_inst.io.aead_aad_len        := aead_lengths(3, 0)
      edhoc_inst.io.aead_data_in        := Cat(aead_data_in.reverse)
      edhoc_inst.io.aead_data_len       := aead_lengths(7, 4)
      edhoc_inst.io.aead_use_sender_key := control(4)
      edhoc_inst.io.aead_exp_tag        := Cat(aead_exp_tag.reverse)
      
      // ===== Capture Outputs =====
      // Set sticky flags when hardware signals (for done, msg_ready, etc.)
      // NOTE: output_valid is now directly from hardware (stays HIGH until output_ack)
      when(edhoc_inst.io.msg_ready) {
        msg_ready_sticky := true.B
      }
      when(edhoc_inst.io.aead_tag_valid) {
        aead_tag_valid_sticky := true.B
      }
      when(edhoc_inst.io.done) {
        done_sticky := true.B
      }
      when(edhoc_inst.io.aead_done) {
        aead_done_sticky := true.B
      }
      when(edhoc_inst.io.oscore_keys_valid) {
        oscore_keys_valid_sticky := true.B
      }
      
      // Status register - output_valid comes directly from hardware (not sticky)
      status := Cat(
        edhoc_inst.io.current_msg,       // [9:8]
        0.U(1.W),                        // [7] reserved
        aead_tag_valid_sticky,           // [6] - sticky flag
        aead_done_sticky,                // [5] - sticky flag
        oscore_keys_valid_sticky,        // [4] - sticky flag
        edhoc_inst.io.output_valid,      // [3] - direct from hardware (cleared by output_ack)
        msg_ready_sticky,                // [2] - sticky flag
        edhoc_inst.io.error,             // [1]
        done_sticky                      // [0] - sticky flag
      )
      
      // Data out - capture when output_valid is asserted
      when(edhoc_inst.io.output_valid) {
        val shifted_data = edhoc_inst.io.data_out << 24  // Align to upper bits
        val data_out_full = shifted_data.asTypeOf(Vec(10, UInt(32.W)))
        for (i <- 0 until 10) {
          data_out(i) := data_out_full(9-i)
        }
      }
      
      // AEAD output - capture when aead_done is asserted
      when(edhoc_inst.io.aead_done) {
        aead_data_out := edhoc_inst.io.aead_data_out.asTypeOf(Vec(4, UInt(32.W)))
        aead_tag := edhoc_inst.io.aead_tag.asTypeOf(Vec(4, UInt(32.W)))
      }
      
      // Auto-clear msg_valid after pulse
      when(msg_valid_pulse) {
        msg_valid_reg := false.B
      }
      
      // Auto-clear output_ack after pulse
      when(output_ack_pulse) {
        output_ack_reg := false.B
      }
      
      // Clear sticky flags when clear_flags bit is set (bit 6)
      // NOTE: output_valid is now cleared by output_ack, not by clear_flags
      when(control(6)) {
        msg_ready_sticky := false.B
        aead_tag_valid_sticky := false.B
        done_sticky := false.B
        aead_done_sticky := false.B
        oscore_keys_valid_sticky := false.B
        control := control & ~64.U  // Auto-clear the clear_flags bit
      }
      
      // ===== Register Map =====
      node.regmap(
        // TRNG Control
        EDHOCCtrlRegs.trng_control -> Seq(RegField(2, trng_control,
          RegFieldDesc("trng_control", "bit[0]=trng_en, bit[1]=xdrbg_bypass"))),
        
        // Keys and Parameters (ephemeral_key only used in bypass mode)
        EDHOCCtrlRegs.ephemeral_key -> RegFieldGroup("ephemeral_key", Some("256-bit private key (bypass mode only)"), 
          ephemeral_key.map(RegField(32, _))),
        EDHOCCtrlRegs.params_0 -> Seq(RegField(32, params_0, 
          RegFieldDesc("params_0", "c_x, method, suite, id_cred_psk"))),
        EDHOCCtrlRegs.params_1 -> Seq(RegField(32, params_1, 
          RegFieldDesc("params_1", "kid_initiator, kid_responder"))),
        EDHOCCtrlRegs.id_initiator -> RegFieldGroup("id_initiator", Some("64-bit initiator ID"), 
          id_initiator.map(RegField(32, _))),
        EDHOCCtrlRegs.id_responder -> RegFieldGroup("id_responder", Some("64-bit responder ID"), 
          id_responder.map(RegField(32, _))),
        
        // Control and Status
        EDHOCCtrlRegs.control -> Seq(RegField(6, control, 
          RegFieldDesc("control", "Control register"))),
        EDHOCCtrlRegs.status -> Seq(RegField.r(10, status, 
          RegFieldDesc("status", "Status register"))),
        
        // Message Data I/O
        EDHOCCtrlRegs.data_in -> RegFieldGroup("data_in", Some("296-bit input data"), 
          data_in.map(RegField(32, _))),
        EDHOCCtrlRegs.data_out -> RegFieldGroup("data_out", Some("296-bit output data"), 
          data_out.map(RegField.r(32, _))),
        
        // AEAD Interface - Hardware constructs nonce from sender_id + partial_iv
        EDHOCCtrlRegs.aead_sender_id -> Seq(RegField(8, aead_sender_id, 
          RegFieldDesc("aead_sender_id", "8-bit sender ID for nonce construction"))),
        EDHOCCtrlRegs.aead_partial_iv -> RegFieldGroup("aead_partial_iv", Some("40-bit partial IV / seq num"), 
          aead_partial_iv.map(RegField(32, _))),
        EDHOCCtrlRegs.aead_aad -> RegFieldGroup("aead_aad", Some("128-bit AEAD AAD"), 
          aead_aad.map(RegField(32, _))),
        EDHOCCtrlRegs.aead_lengths -> Seq(RegField(32, aead_lengths, 
          RegFieldDesc("aead_lengths", "AAD and data lengths"))),
        EDHOCCtrlRegs.aead_data_in -> RegFieldGroup("aead_data_in", Some("128-bit AEAD input data"), 
          aead_data_in.map(RegField(32, _))),
        EDHOCCtrlRegs.aead_data_out -> RegFieldGroup("aead_data_out", Some("128-bit AEAD output data"), 
          aead_data_out.map(RegField.r(32, _))),
        EDHOCCtrlRegs.aead_tag -> RegFieldGroup("aead_tag", Some("128-bit AEAD tag (output)"), 
          aead_tag.map(RegField.r(32, _))),
        EDHOCCtrlRegs.aead_exp_tag -> RegFieldGroup("aead_exp_tag", Some("128-bit expected tag for decrypt"), 
          aead_exp_tag.map(RegField(32, _))),
        
        // Message Valid Signal
        EDHOCCtrlRegs.msg_valid -> Seq(RegField(1, msg_valid_reg, 
          RegFieldDesc("msg_valid", "Pulse to signal message is valid"))),
        
        // Output Acknowledge Signal (NEW: clears output_valid in hardware)
        EDHOCCtrlRegs.output_ack -> Seq(RegField(1, output_ack_reg, 
          RegFieldDesc("output_ack", "Pulse to acknowledge output captured")))
      )
    }
  }
}

/**
 * ID generator for multiple EDHOC instances
 */
object EDHOCID {
  val nextId = {
    var i = -1; () => {
      i += 1; i
    }
  }
}

/**
 * Trait to add EDHOC peripheral to a subsystem
 */
trait CanHavePeripheryEDHOC { this: BaseSubsystem =>
  private val portName = s"edhoc_${EDHOCID.nextId()}"
  
  val edhoc_busy = p(EDHOCKeys) match {
    case Some(params) => {
      val edhoc = LazyModule(new EDHOCTLL(params, pbus.beatBytes))
      edhoc.suggestName(portName)
      
      edhoc.clockNode := pbus.fixedClockNode
      pbus.coupleTo(portName) { edhoc.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }
      
      edhoc
    }
    case None => None
  }
}

/**
 * Configuration class to add EDHOC to a design
 */
class WithEDHOC(address: BigInt) extends Config((site, here, up) => {
  case EDHOCKeys => {
    println(f"Setting EDHOC address: 0x${address}%X")
    Some(EDHOCParams(address = address))
  }
})

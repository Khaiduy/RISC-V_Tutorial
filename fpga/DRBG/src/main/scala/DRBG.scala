package chipyard.DRBG.src.main.scala

import Chisel._
import DRBG.src.main.scala.DRBGRegs
import chisel3.WireInit
import chisel3.util.HasBlackBoxResource
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.regmapper.{RegField, RegFieldDesc}
import freechips.rocketchip.subsystem.BaseSubsystem
import freechips.rocketchip.tilelink.{TLFragmenter, TLRegisterNode}
import freechips.rocketchip.util.ElaborationArtefacts
import org.chipsalliance.cde.config._


case class DRBGParams
(
  Addr: BigInt = 0x06400000,
  dataWidth: Int = 64
){}

case object DRBGKeys extends Field[Option[DRBGParams]](None)

class TRNG_DF_DRBG()(implicit p: Parameters) extends BlackBox with HasBlackBoxResource {
  override def desiredName = "TRNG_DF_DRBG"
  val io = IO (new Bundle{
    val iClk    = Input(Clock())
    val iRst    = Input(Bool())
    val iEn     = Input(Bool())
    val iWrDone = Input(Bool())
    val iAddr   = Input(UInt(8.W))
    val iData   = Input(UInt(64.W))
    val iStart  = Input(Bool())
    val iMode   = Input(UInt(2.W))
    val oData   = Output(UInt(64.W))
    val oDone   = Output(Bool())
  })

  addResource("/trng_vsrc/TRNG_DF_DRBG.v")
  addResource("/trng_vsrc/TRNG.v")
  addResource("/trng_vsrc/AES_256_CTR.v")
  addResource("/trng_vsrc/AES_Controller.v")
  addResource("/trng_vsrc/ExpandKey.v")
  addResource("/trng_vsrc/SubBytes.v")
  addResource("/trng_vsrc/ShiftRows.v")
  addResource("/trng_vsrc/MixColumns.v")
  addResource("/trng_vsrc/FF_D.v")
  addResource("/trng_vsrc/LFSR_64.v")
  addResource("/trng_vsrc/ringOsc.v")
  addResource("/trng_vsrc/TopTRNG.v")

  ElaborationArtefacts.add(
    "DRBG" + ".shell.xdc",
    {
      val xdcPath = pathName.split("\\.").drop(1).mkString("/") + "/"
      var line = s""
//      for (i <- 1 until 201) {
//        val remainder1 = i % 4
//        val notLOC = (
//          if (remainder1 == 1) {
//            s"""set_property BEL D6LUT [get_cells {${xdcPath}RO_part/not${i}/LUT6_inst}]
//               |set_property LOC SLICE_X${idnX}Y200 [get_cells {${xdcPath}RO_part/not${i}/LUT6_inst}]
//               |
//               |""".stripMargin
//          } else if (remainder1 == 2) {
//            s"""set_property BEL C6LUT [get_cells {${xdcPath}RO_part/not${i}/LUT6_inst}]
//               |set_property LOC SLICE_X${idnX}Y200 [get_cells {${xdcPath}RO_part/not${i}/LUT6_inst}]
//               |
//               |""".stripMargin
//          } else if (remainder1 == 3) {
//            s"""set_property BEL B6LUT [get_cells {${xdcPath}RO_part/not${i}/LUT6_inst}]
//               |set_property LOC SLICE_X${idnX}Y200 [get_cells {${xdcPath}RO_part/not${i}/LUT6_inst}]
//               |
//               |""".stripMargin
//          } else {
//            s"""set_property BEL A6LUT [get_cells {${xdcPath}RO_part/not${i}/LUT6_inst}]
//               |set_property LOC SLICE_X${idnX}Y200 [get_cells {${xdcPath}RO_part/not${i}/LUT6_inst}]
//               |
//               |""".stripMargin
//          })
//        if (remainder1 == 0) {
//          idnX = idnX + 1
//        }
//        line = line + notLOC
//
//      }
        val not1LOC =
            s"""set_property BEL A6LUT [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/not1/LUT6_inst}]
               |set_property LOC SLICE_X6Y173 [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/not1/LUT6_inst}]
               |
               |""".stripMargin

        val not2LOC =
            s"""set_property BEL B6LUT [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/not2/LUT6_inst}]
               |set_property LOC SLICE_X6Y173 [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/not2/LUT6_inst}]
               |
               |""".stripMargin

        val not3LOC =
            s"""set_property BEL C6LUT [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/not3/LUT6_inst}]
               |set_property LOC SLICE_X6Y173 [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/not3/LUT6_inst}]
               |
               |""".stripMargin
        val not4LOC =
            s"""set_property BEL D6LUT [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/not4/LUT6_inst}]
               |set_property LOC SLICE_X6Y173 [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/not4/LUT6_inst}]
               |
               |""".stripMargin
        val not5LOC =
            s"""set_property BEL A6LUT [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/not5/LUT6_inst}]
              |set_property LOC SLICE_X6Y174 [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/not5/LUT6_inst}]
              |
              |""".stripMargin
        val not6LOC =
            s"""set_property BEL B6LUT [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/not6/LUT6_inst}]
              |set_property LOC SLICE_X6Y174 [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/not6/LUT6_inst}]
              |
              |""".stripMargin
      line = line + not1LOC + not2LOC + not3LOC + not4LOC + not5LOC + not6LOC

      val nandLOC =
        s"""set_property BEL D6LUT [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/nand0/LUT6_inst}]
           |set_property LOC SLICE_X6Y174 [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/nand0/LUT6_inst}]
           |
           |""".stripMargin

      val setWarning =
        s"""set_property SEVERITY {Warning} [get_drc_checks LUTLP-1]
           |set_property SEVERITY {Warning} [get_drc_checks NSTD-1]
           |
           |""".stripMargin

      val setLOOP =
        s"set_property ALLOW_COMBINATORIAL_LOOPS true [get_nets -of_objects [get_cells {${xdcPath}TRNG_inst/TRNG_core/RingOSC/nand0/LUT6_inst}]]"
//      s"set_property ALLOW_COMBINATORIAL_LOOPS true [get_nets [${xdcPath}TRNG_inst/TRNG_core/RingOSC/nand0/oRo]"

      line + nandLOC + setWarning + setLOOP
    }
  ) // ElaborationArtefacts
}

class DRBGDevice(val params: DRBGParams, beatBytes: Int = 8)(implicit p: Parameters)
  extends LazyModule {
  val device = new SimpleDevice("DRBG", Seq("SoC,DRBG"))
  //MMIO register node (manager)
  val mmioNode = TLRegisterNode(
    address   = Seq(AddressSet(params.Addr, 4096-1)),
    device    = device,
    beatBytes = beatBytes,
    concurrency = 1
  )
  lazy val module = new DRBGDeviceImp(this)
}


class DRBGDeviceImp(outer: DRBGDevice)(implicit p: Parameters)
  extends LazyModuleImp(outer) {

  val params = outer.params
  val drbg = Module(new TRNG_DF_DRBG())

  // ==== MMIO Registers ====
  val r_reset         = RegInit(false.B)
  val r_enable        = RegInit(false.B)
  val r_write_done    = RegInit(false.B)
  val r_address       = RegInit(0.U(8.W))
  val r_in_data       = RegInit(0.U(params.dataWidth.W))
  val r_start         = RegInit(false.B)
  val r_mode          = RegInit(0.U(2.W))
  val r_out_data      = WireInit(0.U(params.dataWidth.W))
  val r_done          = WireInit(false.B)


  drbg.io.iClk    := clock
  drbg.io.iRst    := r_reset //|| reset.asBool
  drbg.io.iEn     := r_enable
  drbg.io.iWrDone := r_write_done
  drbg.io.iAddr   := r_address
  drbg.io.iData   := r_in_data
  drbg.io.iStart  := r_start
  drbg.io.iMode   := r_mode
  r_out_data      := drbg.io.oData
  r_done          := drbg.io.oDone

  // ==== MMIO Mapping ====
  outer.mmioNode.regmap(
    DRBGRegs.rst        -> Seq(RegField(1, r_reset, RegFieldDesc("r_reset", "reset"))),
    DRBGRegs.enable     -> Seq(RegField(1, r_enable, RegFieldDesc("r_enable", "enable"))),
    DRBGRegs.write_done -> Seq(RegField(1, r_write_done, RegFieldDesc("r_write_done", "write_done"))),
    DRBGRegs.address    -> Seq(RegField(8, r_address, RegFieldDesc("r_address", "r_address"))),
    DRBGRegs.in_data    -> Seq(RegField(params.dataWidth, r_in_data, RegFieldDesc("r_in_data", "r_in_data"))),
    DRBGRegs.start      -> Seq(RegField(1, r_start, RegFieldDesc("r_start", "r_start"))),
    DRBGRegs.mode       -> Seq(RegField(2, r_mode, RegFieldDesc("r_mode", "mode"))),
    DRBGRegs.out_data   -> Seq(RegField.r(params.dataWidth, r_out_data, RegFieldDesc("r_out_data", "out_data"))),
    DRBGRegs.done       -> Seq(RegField.r(1, r_done, RegFieldDesc("r_done", "r_done"))),
  )
}

object DRBGID{
  val nextId = {
    var i = -1; () => {
      i += 1; i
    }
  }
}

trait CanHavePeripheryDRBG{ this: BaseSubsystem =>
  private val portName = "drbg"

  val DRBGDeviceOpt: Option[DRBGDevice] = p(DRBGKeys).map { params =>
    val drbgWrapper = LazyModule( new DRBGDevice(params, pbus.beatBytes)(p))
    pbus.coupleTo(s"drbg_mmio_at_${params.Addr.toString(16)}") {
      drbgWrapper.mmioNode := TLFragmenter(pbus) := _
    }
    drbgWrapper
  }
}

//trait HasPeripheryDRBGModuleImp extends LazyModuleImp {
//  val outer: CanHavePeripheryDRBG
//  val drbg_busy = outer.DRBGDeviceOpt.map { device =>
//    val busy_wire = IO(Output(Bool()))
//    busy_wire := device.module.reg_busy
//    busy_wire
//  }
//}

class WithDRBG (base: BigInt = 0x06400000, width: Int = 64) extends Config((site, here, up) => {
  case DRBGKeys => Some(DRBGParams(Addr = base, dataWidth = width))
})

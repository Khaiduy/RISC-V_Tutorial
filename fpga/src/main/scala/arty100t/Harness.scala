package chipyard.fpga.arty100t

import chipyard._
import chipyard.harness._
import chisel3._
import chisel3.util._
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.subsystem.SystemBusKey
import freechips.rocketchip.tilelink._
import org.chipsalliance.cde.config.Parameters
import sifive.blocks.devices.gpio.{GPIOPortIO, PeripheryGPIOKey}
import sifive.blocks.devices.spi.{PeripherySPIKey, SPIPortIO}
import sifive.blocks.devices.uart._
import sifive.fpgashells.clocks.{ClockGroup, ClockSinkNode, PLLFactoryKey, ResetWrangler}
import sifive.fpgashells.ip.xilinx.IBUF
import sifive.fpgashells.shell._

class Arty100TwoDDRHarness(override implicit val p: Parameters) extends Arty100TShellCustomOverlays
{
  def dp = designParameters

  // ========= Clock =================
  val sysClkNode = dp(ClockInputOverlayKey).head.place(ClockInputDesignInput()).overlayOutput.node
  val harnessSysPLL = dp(PLLFactoryKey)()
  harnessSysPLL := sysClkNode

  // create and connect to the dutClock
  val dutFreqMHz = (dp(SystemBusKey).dtsFrequency.get / (1000 * 1000)).toInt
  val dutClock = ClockSinkNode(freqMHz = dutFreqMHz)
  println(s"Arty35T FPGA Base Clock Freq: ${dutFreqMHz} MHz")
  val dutWrangler = LazyModule(new ResetWrangler())
  val dutGroup = ClockGroup()
  dutClock := dutWrangler.node := dutGroup := harnessSysPLL

  /*** JTAG ***/
  val jtagModule = dp(JTAGDebugOverlayKey).head.place(JTAGDebugDesignInput()).overlayOutput.jtag
  // BScan: tunnels through onboard FT2232H USB. Use WithArty100TJTAGBScanHarnessBinder.
  val jtagBScanModule = dp(JTAGDebugBScanOverlayKey).head.place(JTAGDebugBScanDesignInput()).overlayOutput.jtag

  /*** UART *****/
  val io_uart_bb = dp(PeripheryUARTKey).map(p => BundleBridgeSource(() => new UARTPortIO(p)))
  val uartOverlay = (dp(UARTOverlayKey) zip dp(PeripheryUARTKey)).zipWithIndex.map { case ((placer, params), i) =>
    placer.place(UARTDesignInput(io_uart_bb(i)))
  }

  /*** GPIO ***/
  val io_gpio_bb = dp(PeripheryGPIOKey).map(p => BundleBridgeSource(() => (new GPIOPortIO(p))))
  (dp(GPIOOverlayKey) zip dp(PeripheryGPIOKey)).zipWithIndex.map { case ((placer, params), i) =>
    placer.place(GPIODesignInput(params, io_gpio_bb(i)))
  }

  /*** SDIO ***/
  val io_spi_bb = dp(PeripherySPIKey).map(p => BundleBridgeSource(() => (new SPIPortIO(p))))
  (dp(SPIOverlayKey) zip dp(PeripherySPIKey)).zipWithIndex.map { case ((placer, params), i) =>
    placer.place(SPIDesignInput(params, io_spi_bb(i)))
  }

  // Module implementation
  override lazy val module = new Arty100TwoDDRHarnessImp(this)
}

class Arty100TwoDDRHarnessImp(_outer: Arty100TwoDDRHarness) extends LazyRawModuleImp(_outer)
  with HasHarnessInstantiators
{
  val athOuter = _outer

  val reset = IO(Input(Bool()))
  _outer.xdc.addBoardPin(reset, "reset")

  val reset_ibuf = Module(new IBUF)
  reset_ibuf.io.I := reset

  val sysclk: Clock = _outer.sysClkNode.out.head._1.clock

  _outer.pllReset := !reset_ibuf.io.O

  def referenceClockFreqMHz = _outer.dutFreqMHz
  def referenceClock = _outer.dutClock.in.head._1.clock
  def referenceReset = _outer.dutClock.in.head._1.reset
  def success = { require(false, "Unused"); false.B }

  childClock := referenceClock
  childReset := referenceReset

  instantiateChipTops()
}

class Arty100TDDRHarness(override implicit val p: Parameters) extends Arty100TShellCustomOverlays
{
  def dp = designParameters

  // ========= Clock =================
  val sysClkNode = dp(ClockInputOverlayKey).head.place(ClockInputDesignInput()).overlayOutput.node
  val harnessSysPLL = dp(PLLFactoryKey)()
  harnessSysPLL := sysClkNode

  // create and connect to the dutClock
  val dutFreqMHz = (dp(SystemBusKey).dtsFrequency.get / (1000 * 1000)).toInt
  val dutClock = ClockSinkNode(freqMHz = dutFreqMHz)
  println(s"Arty100T FPGA Base Clock Freq: ${dutFreqMHz} MHz")
  val dutWrangler = LazyModule(new ResetWrangler())
  val dutGroup = ClockGroup()
  dutClock := dutWrangler.node := dutGroup := harnessSysPLL

  // ========= DDR =================
  val ddrOverlay = dp(DDROverlayKey).head.place(DDRDesignInput(dp(ExtTLMem).get.master.base, dutWrangler.node, harnessSysPLL)).asInstanceOf[DDRArtyPlacedOverlay]
  val ddrClient = TLClientNode(Seq(TLMasterPortParameters.v1(Seq(TLMasterParameters.v1(
    name = "chip_ddr",
    sourceId = IdRange(0, 1 << dp(ExtTLMem).get.master.idBits)
  )))))
  val ddrBlockDuringReset = LazyModule(new TLBlockDuringReset(4))
  ddrOverlay.overlayOutput.ddr := ddrBlockDuringReset.node := ddrClient

  /*** JTAG ***/
  val jtagModule = dp(JTAGDebugOverlayKey).head.place(JTAGDebugDesignInput()).overlayOutput.jtag
  // BScan: tunnels through onboard FT2232H USB. Use WithArty100TJTAGBScanHarnessBinder.
  val jtagBScanModule = dp(JTAGDebugBScanOverlayKey).head.place(JTAGDebugBScanDesignInput()).overlayOutput.jtag

  /*** UART ***/
  val io_uart_bb = dp(PeripheryUARTKey).map(p => BundleBridgeSource(() => new UARTPortIO(p)))
  val uartOverlay = (dp(UARTOverlayKey) zip dp(PeripheryUARTKey)).zipWithIndex.map { case ((placer, params), i) =>
    placer.place(UARTDesignInput(io_uart_bb(i)))
  }

  /*** GPIO ***/
  val io_gpio_bb = dp(PeripheryGPIOKey).map(p => BundleBridgeSource(() => (new GPIOPortIO(p))))
  (dp(GPIOOverlayKey) zip dp(PeripheryGPIOKey)).zipWithIndex.map { case ((placer, params), i) =>
    placer.place(GPIODesignInput(params, io_gpio_bb(i)))
  }

  /*** SDIO ***/
  val io_spi_bb = dp(PeripherySPIKey).map(p => BundleBridgeSource(() => (new SPIPortIO(p))))
  (dp(SPIOverlayKey) zip dp(PeripherySPIKey)).zipWithIndex.map { case ((placer, params), i) =>
    placer.place(SPIDesignInput(params, io_spi_bb(i)))
  }

  // Module implementation
  override lazy val module = new Arty100TDDRHarnessImp(this)
}

class Arty100TDDRHarnessImp(_outer: Arty100TDDRHarness) extends LazyRawModuleImp(_outer)
  with HasHarnessInstantiators
{
  val athOuter = _outer

  val reset = IO(Input(Bool()))
  _outer.xdc.addBoardPin(reset, "reset")

  val reset_ibuf = Module(new IBUF)
  reset_ibuf.io.I := reset

  val sysclk: Clock = _outer.sysClkNode.out.head._1.clock

  _outer.pllReset := !reset_ibuf.io.O

  def referenceClockFreqMHz = _outer.dutFreqMHz
  def referenceClock = _outer.dutClock.in.head._1.clock
  def referenceReset = _outer.dutClock.in.head._1.reset
  def success = { require(false, "Unused"); false.B }

  _outer.ddrOverlay.mig.module.clock := harnessBinderClock
  _outer.ddrOverlay.mig.module.reset := harnessBinderReset
  _outer.ddrBlockDuringReset.module.clock := harnessBinderClock
  _outer.ddrBlockDuringReset.module.reset := harnessBinderReset.asBool || !_outer.ddrOverlay.mig.module.io.port.init_calib_complete

  childClock := referenceClock
  childReset := referenceReset

  instantiateChipTops()
}

class Arty100TWithoutDDRHarness(override implicit val p: Parameters) extends Arty100TShellCustomOverlays
{
  def dp = designParameters

  // ========= Clock =================
  val sysClkNode = dp(ClockInputOverlayKey).head.place(ClockInputDesignInput()).overlayOutput.node
  val harnessSysPLL = dp(PLLFactoryKey)()
  harnessSysPLL := sysClkNode

  // create and connect to the dutClock
  val dutFreqMHz = (dp(SystemBusKey).dtsFrequency.get / (1000 * 1000)).toInt
  val dutClock = ClockSinkNode(freqMHz = dutFreqMHz)
  println(s"Arty100T FPGA Base Clock Freq: ${dutFreqMHz} MHz")
  val dutWrangler = LazyModule(new ResetWrangler())
  val dutGroup = ClockGroup()
  dutClock := dutWrangler.node := dutGroup := harnessSysPLL

//  // ========= DDR =================
//  val ddrOverlay = dp(DDROverlayKey).head.place(DDRDesignInput(dp(ExtTLMem).get.master.base, dutWrangler.node, harnessSysPLL)).asInstanceOf[DDRArtyPlacedOverlay]
//  val ddrClient = TLClientNode(Seq(TLMasterPortParameters.v1(Seq(TLMasterParameters.v1(
//    name = "chip_ddr",
//    sourceId = IdRange(0, 1 << dp(ExtTLMem).get.master.idBits)
//  )))))
//  val ddrBlockDuringReset = LazyModule(new TLBlockDuringReset(4))
//  ddrOverlay.overlayOutput.ddr := ddrBlockDuringReset.node := ddrClient

  /*** JTAG ***/
  val jtagModule = dp(JTAGDebugOverlayKey).head.place(JTAGDebugDesignInput()).overlayOutput.jtag
  // BScan: tunnels through onboard FT2232H USB. Use WithArty100TJTAGBScanHarnessBinder.
  val jtagBScanModule = dp(JTAGDebugBScanOverlayKey).head.place(JTAGDebugBScanDesignInput()).overlayOutput.jtag

  /*** UART ***/
  val io_uart_bb = dp(PeripheryUARTKey).map(p => BundleBridgeSource(() => new UARTPortIO(p)))
  val uartOverlay = (dp(UARTOverlayKey) zip dp(PeripheryUARTKey)).zipWithIndex.map { case ((placer, params), i) =>
    placer.place(UARTDesignInput(io_uart_bb(i)))
  }

  /*** GPIO ***/
  val io_gpio_bb = dp(PeripheryGPIOKey).map(p => BundleBridgeSource(() => (new GPIOPortIO(p))))
  (dp(GPIOOverlayKey) zip dp(PeripheryGPIOKey)).zipWithIndex.map { case ((placer, params), i) =>
    placer.place(GPIODesignInput(params, io_gpio_bb(i)))
  }

  /*** SDIO ***/
  val io_spi_bb = dp(PeripherySPIKey).map(p => BundleBridgeSource(() => (new SPIPortIO(p))))
  (dp(SPIOverlayKey) zip dp(PeripherySPIKey)).zipWithIndex.map { case ((placer, params), i) =>
    placer.place(SPIDesignInput(params, io_spi_bb(i)))
  }

  // Module implementation
  override lazy val module = new Arty100TWithoutDDRHarnessImp(this)
}

class Arty100TWithoutDDRHarnessImp(_outer: Arty100TWithoutDDRHarness) extends LazyRawModuleImp(_outer)
  with HasHarnessInstantiators
{
  val athOuter = _outer

  val reset = IO(Input(Bool()))
  _outer.xdc.addBoardPin(reset, "reset")

  val reset_ibuf = Module(new IBUF)
  reset_ibuf.io.I := reset

  val sysclk: Clock = _outer.sysClkNode.out.head._1.clock

  _outer.pllReset := !reset_ibuf.io.O

  def referenceClockFreqMHz = _outer.dutFreqMHz
  def referenceClock = _outer.dutClock.in.head._1.clock
  def referenceReset = _outer.dutClock.in.head._1.reset
  def success = { require(false, "Unused"); false.B }

//  _outer.ddrOverlay.mig.module.clock := harnessBinderClock
//  _outer.ddrOverlay.mig.module.reset := harnessBinderReset
//  _outer.ddrBlockDuringReset.module.clock := harnessBinderClock
//  _outer.ddrBlockDuringReset.module.reset := harnessBinderReset.asBool || !_outer.ddrOverlay.mig.module.io.port.init_calib_complete

  childClock := referenceClock
  childReset := referenceReset

  instantiateChipTops()
}
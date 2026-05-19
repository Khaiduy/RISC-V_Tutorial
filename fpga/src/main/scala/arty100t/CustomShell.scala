package chipyard.fpga.arty100t

import Chisel.{Input, Module}
import chisel3.{Bool, Clock, Wire}
import freechips.rocketchip.diplomacy.{InModuleBody, LazyModule, LazyRawModuleImp, ValName}
import org.chipsalliance.cde.config.Parameters
import sifive.fpgashells.ip.xilinx.{IBUF, PowerOnResetFPGAOnly}
import sifive.fpgashells.shell.xilinx.Series7Shell
import sifive.fpgashells.shell.{ClockInputDesignInput, ClockInputOverlayKey, ClockInputShellInput, DDROverlayKey, DDRShellInput, DesignKey, GPIOOverlayKey, GPIOShellInput, JTAGDebugBScanOverlayKey, JTAGDebugBScanShellInput, JTAGDebugOverlayKey, JTAGDebugShellInput, SPIOverlayKey, SPIShellInput, UARTOverlayKey, UARTShellInput}

abstract class Arty100TShellCustomOverlays()(implicit p: Parameters) extends Series7Shell {
  // System
  val pllReset = InModuleBody { Wire(Bool()) }
  val sys_clock = Overlay(ClockInputOverlayKey, new SysClockArtyShellPlacer(this, ClockInputShellInput()))
  val ddr       = Overlay(DDROverlayKey, new DDRArtyShellPlacer(this, DDRShellInput()))

  // Peripheries
  val jtag     = Overlay(JTAGDebugOverlayKey, new JTAGDebugArtyShellPlacer(this, JTAGDebugShellInput()))
  val jtagBScan = Overlay(JTAGDebugBScanOverlayKey, new JTAGDebugBScanArtyCustomShellPlacer(this, JTAGDebugBScanShellInput()))
  val uart  = Seq.tabulate(2)(i => Overlay(UARTOverlayKey, new UARTArtyShellPlacer(this, UARTShellInput(index = i))(valName = ValName(s"uart_$i"))))
  val sdio  = Seq.tabulate(3)(i => Overlay(SPIOverlayKey, new SDIOArtyShellPlacer(this, SPIShellInput())(valName = ValName(s"sdio_$i"))))
  val gpio  = Overlay(GPIOOverlayKey, new GPIOArtyShellPlacer(this, GPIOShellInput()))
}
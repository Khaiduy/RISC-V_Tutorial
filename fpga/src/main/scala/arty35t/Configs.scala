// See LICENSE for license details.
package chipyard.fpga.arty35t

import chipyard.config.WithBroadcastManager
import freechips.rocketchip.devices.debug.DebugModuleKey
import freechips.rocketchip.devices.tilelink.BootROMLocated
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.subsystem._
import freechips.rocketchip.tile.XLen
import org.chipsalliance.cde.config._
import sifive.blocks.devices.spi.{PeripherySPIKey, SPIParams}
import sifive.blocks.devices.uart.{PeripheryUARTKey, UARTParams}
import sifive.fpgashells.shell.DesignKey
import testchipip.{CustomBootPinKey, SerialTLKey}

import scala.sys.process._
import sifive.blocks.devices.gpio.PeripheryGPIOKey
import sifive.blocks.devices.gpio.GPIOParams
// import chipyard.devices.gcd._

class WithSystemModifications extends Config((site, here, up) => {
  case DTSTimebase => BigInt{(1e6).toLong}
  case BootROMLocated(x) => up(BootROMLocated(x), site).map{ p =>
    val freqMHz = (site(SystemBusKey).dtsFrequency.get / (1000 * 1000)).toLong
    // Make sure that the bootrom is always rebuilt
    val clean = s"make -C fpga/src/main/resources/arty35t/sdboot clean"
    require (clean.! == 0, "Failed to clean")
    // Build the bootromt
    val make = s"make -C fpga/src/main/resources/arty35t/sdboot XLEN=${site(XLen)} PBUS_CLK=${freqMHz}"
    require (make.! == 0, "Failed to build bootrom")
    p.copy(hang = 0x10000, contentFileName = s"./fpga/src/main/resources/arty35t/sdboot/build/sdboot.bin")
  }
  case DesignKey => (p: Parameters) => new SimpleLazyModule()(p)
  case DebugModuleKey => up(DebugModuleKey).map{ debug =>
    debug.copy(clockGate = false)
  }
  case CustomBootPinKey => None
  case SerialTLKey => None
})

class WithDefaultPeripherals extends Config((site, here, up) => {
  case PeripheryUARTKey => List(UARTParams(address = BigInt(0x64000000L)))
  case PeripherySPIKey => List(SPIParams(rAddress = BigInt(0x64001000L)))
  case PeripheryGPIOKey => List(GPIOParams(address = BigInt(0x64002000L), width = 24))
  // case PeripheryGCDKey => List(GCDParams2(BigInt(0x64003000L)))
})

class WithTinyArty35TTweaks extends Config(
  // Clock configs
  new chipyard.harness.WithAllClocksFromHarnessClockInstantiator ++
  new chipyard.harness.WithHarnessBinderClockFreqMHz(50) ++
  new chipyard.config.WithMemoryBusFrequency(50.0) ++
  new chipyard.config.WithSystemBusFrequency(50.0) ++
  new chipyard.config.WithPeripheryBusFrequency(50.0) ++
  new chipyard.harness.WithAllClocksFromHarnessClockInstantiator ++
  new chipyard.clocking.WithPassthroughClockGenerator ++
  // Harness Binder
  new WithArty35TUARTHarnessBinder ++
  new WithArty35TSPISDCardHarnessBinder ++
  new WithArty35TJTAGHarnessBinder ++
  new WithArty35TGPIOHarnessBinder ++
  new WithArty35TTSITieoff ++
  // IO Binders
  new WithGPIOIOPassthrough ++
  new WithUARTIOPassthrough ++
  new WithSPIIOPassthrough ++
  new WithTLIOPassthrough ++
  // Other configurations
  new WithDefaultPeripherals ++
  new WithSystemModifications ++
  new freechips.rocketchip.subsystem.WithoutTLMonitors)

// class SmallRocketArty35TConfig extends Config(
//   new WithTinyArty35TTweaks ++
//   new chipyard.config.WithBroadcastManager ++
//   new chipyard.SmallRocketNTTConfig
// )

// RV32 SmallRocket for Arty35T (no X25519 hardware)
class SmallRocket32Arty35TConfig extends Config(
  new WithTinyArty35TTweaks ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocket32Config
)

// RV64 SmallRocket for Arty35T (with X25519 hardware) - original config
class SmallRocketArty35TConfig extends Config(
  new WithTinyArty35TTweaks ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocketConfig
)
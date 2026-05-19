// See LICENSE for license details.
package chipyard.fpga.arty100t

import chipyard.ExtTLMem
import chipyard.config.{WithBroadcastManager, WithTLBackingMemory}
import chipyard.crypto.trng.WithTRNG
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

class WithSystemModifications extends Config((site, here, up) => {
  case DTSTimebase => BigInt{(1e6).toLong}
  case BootROMLocated(x) => up(BootROMLocated(x), site).map{ p =>
    val freqMHz = (site(SystemBusKey).dtsFrequency.get / (1000 * 1000)).toLong
    // Make sure that the bootrom is always rebuilt
    val clean = s"make -C fpga/src/main/resources/arty35t/sdboot clean"
    require (clean.! == 0, "Failed to clean")
    // Build the bootrom
    val make = s"make -C fpga/src/main/resources/arty35t/sdboot XLEN=${site(XLen)} PBUS_CLK=${freqMHz}"
    require (make.! == 0, "Failed to build bootrom")
    p.copy(hang = 0x10000, size = 0x2000, contentFileName = s"./fpga/src/main/resources/arty35t/sdboot/build/sdboot.bin")
  }
  case DesignKey => (p: Parameters) => new SimpleLazyModule()(p)
  case DebugModuleKey => up(DebugModuleKey).map{ debug =>
    debug.copy(clockGate = false)
  }
  case CustomBootPinKey => None

})

class WithoutSerial extends Config((site, here, up) => {
  case SerialTLKey => None
})

class WithDDR extends Config((site, here, up) => {
  case ExtMem => None
  case ExtTLMem => up(ExtMem, site).map(x => x.copy(master = x.master.copy(size = site(ArtyDDRSize)))) // set extmem
})

class WithoutDDR extends Config((site, here, up) => {
  case ExtMem => None
  case ExtTLMem => None
})

class WithDefaultPeripherals extends Config((site, here, up) => {
  case PeripheryUARTKey => List(
    UARTParams(address = BigInt(0x64000000L)),  // UART0 - USB UART
    UARTParams(address = BigInt(0x64003000L)))  // UART1 - PMOD C
  case PeripherySPIKey => List(
    SPIParams(rAddress = BigInt(0x64001000L)),  // SPI0
    SPIParams(rAddress = BigInt(0x64006000L)),  // SPI1
    SPIParams(rAddress = BigInt(0x64005000L)))  // SPI2
  case PeripheryGPIOKey => List(GPIOParams(address = BigInt(0x64002000L), width = 8))
})

class WithTinyArty100TTweaks extends Config(
  // Clock configs
  new chipyard.harness.WithAllClocksFromHarnessClockInstantiator ++
  new chipyard.harness.WithHarnessBinderClockFreqMHz(50) ++
  new chipyard.config.WithMemoryBusFrequency(50.0) ++
  new chipyard.config.WithSystemBusFrequency(50.0) ++
  new chipyard.config.WithPeripheryBusFrequency(50.0) ++
  new chipyard.clocking.WithPassthroughClockGenerator ++
  // Harness Binder
  new WithArty100TUARTHarnessBinder ++    // from HarnessBinders, to connect the Harness to IO of module
  new WithArty100TSPISDCardHarnessBinder ++
  new WithArty100TJTAGHarnessBinder ++
  new WithArty100TGPIOHarnessBinder ++
  new WithArty100TTSITieoff ++
  // IO Binders
  new WithGPIOIOPassthrough ++
  new WithUARTIOPassthrough ++  // from IOBinders
  new WithSPIIOPassthrough ++
  new WithTLIOPassthrough ++
  // Other configurations
  new WithoutSerial ++
  new WithoutDDR ++
  new WithDefaultPeripherals ++
  new WithSystemModifications ++
  new freechips.rocketchip.subsystem.WithoutTLMonitors)

class WithDDRArty100TTweaks extends Config(
  // Clock configs
  new chipyard.harness.WithAllClocksFromHarnessClockInstantiator ++
  new chipyard.harness.WithHarnessBinderClockFreqMHz(50) ++
  new chipyard.config.WithMemoryBusFrequency(50.0) ++
  new chipyard.config.WithSystemBusFrequency(50.0) ++
  new chipyard.config.WithPeripheryBusFrequency(50.0) ++
  new chipyard.clocking.WithPassthroughClockGenerator ++
  // Harness Binder
  new WithArty100TUARTHarnessBinder ++
  new WithArty100TSPISDCardHarnessBinder ++
  new WithArty100TJTAGHarnessBinder ++
  new WithArty100TGPIOHarnessBinder ++
  new WithArty100TDDRMemHarnessBinder ++
  //new WithArty100TTSITieoff ++
  // IO Binders
  new WithGPIOIOPassthrough ++
  new WithUARTIOPassthrough ++
  new WithSPIIOPassthrough ++
  // Other configurations
  new WithoutSerial ++
  new WithDDR ++
  new WithDefaultPeripherals ++
  new WithSystemModifications ++
  new freechips.rocketchip.subsystem.WithoutTLMonitors)

class WithSerialTLRAMArty100TTweaks extends Config(
  // Clock configs
  new chipyard.harness.WithAllClocksFromHarnessClockInstantiator ++
    new chipyard.harness.WithHarnessBinderClockFreqMHz(20) ++
    new chipyard.config.WithMemoryBusFrequency(20.0) ++
    new chipyard.config.WithSystemBusFrequency(20.0) ++
    new chipyard.config.WithPeripheryBusFrequency(20.0) ++
    new chipyard.clocking.WithPassthroughClockGenerator ++
    // Harness Binder
    new WithArty100TUARTHarnessBinder ++
    new WithArty100TSPISDCardHarnessBinder ++
    new WithArty100TJTAGHarnessBinder ++
    new WithArty100TGPIOHarnessBinder ++
    new WithArty100TTSITieoff ++
    // IO Binders
    new WithGPIOIOPassthrough ++
    new WithUARTIOPassthrough ++
    new WithSPIIOPassthrough ++
    // Other configurations
    new WithDefaultPeripherals ++
    new WithSystemModifications ++
    // Set serial mem
    new testchipip.WithSerialTLWidth(8) ++
    new testchipip.WithSerialTLMem(
      base = BigInt(0x80000000L),
      size = BigInt((1 << 20) * 256L),
      isMainMemory=false) ++
    new testchipip.WithSerialTLBackingMemory ++
    new freechips.rocketchip.subsystem.WithoutTLMonitors)


class RocketOnChipSRAMArty100TConfig extends Config( // one small rocket CPU on-chip RAM only
  new WithTinyArty100TTweaks ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocketConfig
)

// RV32 version of SmallRocket for Arty 100T (with TRNG hardware)
class SmallRocket32Arty100TConfig extends Config(
  // new WithTRNG(0x10030000L) ++  // Add TRNG peripheral at address 0x10030000
  new WithTinyArty100TTweaks ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocket32Config
)

// RV32 version of SmallRocket for Arty 100T — pure software EDHOC (no hardware accelerator)
class SmallRocket32M3Arty100TConfig extends Config(
  new WithTinyArty100TTweaks ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocket32M3Config
)

// RV32 version of SmallRocket for Arty 100T — pure software EDHOC (no hardware accelerator)
class SmallRocket32M3HWArty100TConfig extends Config(
  new WithTinyArty100TTweaks ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocket32M3HWConfig
)

// class RocketDDRArty100TConfig extends Config(// one small rocket CPU with DDR
//   new WithDDRArty100TTweaks ++
//   new chipyard.config.WithBroadcastManager ++
//   new chipyard.RocketDDRConfig
// )

// class RocketSerRAMArty100TConfig extends Config(// dung serial RAM
//   new WithSerialTLRAMArty100TTweaks ++
//   new chipyard.config.WithBroadcastManager ++
//   new chipyard.RocketDDRConfig
// )
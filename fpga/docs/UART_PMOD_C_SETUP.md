# Adding Second UART on PMOD C for Arty A7 100T

## Overview

This modification adds a second UART interface to the Chipyard RISC-V SoC on the Arty A7 100T FPGA board. The second UART is mapped to PMOD C connector for external communication.

## Hardware Configuration

### UART0 (Existing - USB UART)
- **Base Address**: 0x64000000
- **TX Pin**: D10
- **RX Pin**: A9
- **Purpose**: Console/Debug output via USB

### UART1 (New - PMOD C)
- **Base Address**: 0x64003000
- **TX Pin**: V12 (PMOD C JC2 - Pin 2)
- **RX Pin**: U12 (PMOD C JC1 - Pin 1)
- **Purpose**: External communication module

### PMOD C Pinout (Arty A7 100T)

```
PMOD C Connector (JC):
  Top Row:    Bottom Row:
  ┌─────┐    ┌─────┐
  │ JC1 │────│ JC7 │  (U12/U14)
  │ JC2 │────│ JC8 │  (V12/V14)
  │ JC3 │────│ JC9 │  (V10/T13)
  │ JC4 │────│JC10 │  (V11/U13)
  └─────┘    └─────┘
    3.3V       GND
```

**UART1 Connection:**
- **JC1 (U12)**: UART1 RX - Connect to external device TX
- **JC2 (V12)**: UART1 TX - Connect to external device RX
- **JC7 (U14)** or **JC8 (V14)**: Can be used for flow control if needed
- **GND**: Connect to external device ground

## Software Changes

### 1. Peripheral Configuration (`Configs.scala`)

Modified `WithDefaultPeripherals` to include two UART peripherals:

```scala
class WithDefaultPeripherals extends Config((site, here, up) => {
  case PeripheryUARTKey => List(
    UARTParams(address = BigInt(0x64000000L)),  // UART0 - USB UART
    UARTParams(address = BigInt(0x64003000L)))  // UART1 - PMOD C
  case PeripherySPIKey => List(SPIParams(rAddress = BigInt(0x64001000L)))
  case PeripheryGPIOKey => List(GPIOParams(address = BigInt(0x64002000L), width = 24))
})
```

### 2. Shell Configuration (`CustomShell.scala`)

Updated `Arty100TShellCustomOverlays` to support multiple UART overlays:

```scala
val uart = Seq.tabulate(2)(i => Overlay(UARTOverlayKey, 
  new UARTArtyShellPlacer(this, UARTShellInput(index = i))(valName = ValName(s"uart_$i"))))
```

### 3. Pin Mapping (`CustomOverlay.scala`)

Added index-based pin mapping in `UARTArtyPlacedOverlay`:

```scala
val packagePinsWithPackageIOs = shellInput.index match {
  case 0 => Seq(
    ("A9", IOPin(io.rxd)),   // USB UART RX
    ("D10", IOPin(io.txd)))  // USB UART TX
  case 1 => Seq(
    ("U12", IOPin(io.rxd)),  // PMOD C JC1 (pin 1) - RX
    ("V12", IOPin(io.txd)))  // PMOD C JC2 (pin 2) - TX
  case _ => Seq()
}
```

### 4. Harness Binders (`HarnessBinders.scala`)

Updated `WithArty100TUARTHarnessBinder` to handle multiple UART ports:

```scala
class WithArty100TUARTHarnessBinder extends OverrideHarnessBinder({
  (system: HasPeripheryUARTModuleImp, th: BaseModule, ports: Seq[UARTPortIO]) => {
    th match {
      case ath: Arty100TDDRHarnessImp => {
        require(ports.size >= 1, "No UART ports found")
        (ath.athOuter.io_uart_bb zip ports).foreach { case (bb, port) =>
          bb.bundle <> port
        }
      }
      // ... similar for other harness types
    }
  }
})
```

### 5. Harness Implementation (`Harness.scala`)

Modified all three harness classes to create BundleBridges for each UART:

```scala
/*** UART ***/
val io_uart_bb = dp(PeripheryUARTKey).map(p => BundleBridgeSource(() => new UARTPortIO(p)))
val uartOverlay = (dp(UARTOverlayKey) zip dp(PeripheryUARTKey)).zipWithIndex.map { 
  case ((placer, params), i) => placer.place(UARTDesignInput(io_uart_bb(i)))
}
```

## Building the Design

1. **Clean previous build** (if any):
   ```bash
   cd /home/khaiduy/Workspace/RISC-V_Tutorial
   make -C fpga clean
   ```

2. **Build FPGA bitstream**:
   ```bash
   make -C fpga SUB_PROJECT=arty100t CONFIG=RocketOnChipSRAMArty100TConfig bitstream
   ```

3. **Program FPGA**:
   ```bash
   make -C fpga SUB_PROJECT=arty100t CONFIG=RocketOnChipSRAMArty100TConfig program
   ```

## Software Usage

### Device Tree Entries

The Linux kernel (or bare-metal software) will see two UART devices:

```
uart0@64000000 {
    compatible = "sifive,uart0";
    reg = <0x64000000 0x1000>;
    // This is the USB UART
};

uart1@64003000 {
    compatible = "sifive,uart0";
    reg = <0x64003000 0x1000>;
    // This is the PMOD C UART
};
```

### Bare-Metal Access

For your EDHOC demo, you can access UART1 directly:

```c
#define UART0_BASE 0x64000000L  // USB UART for debug
#define UART1_BASE 0x64003000L  // PMOD C for EDHOC communication

// Use UART0 for console output (kprintf)
void uart0_putc(char c) {
    volatile uint32_t *txdata = (uint32_t*)(UART0_BASE + 0x00);
    while (*txdata & 0x80000000);  // Wait if full
    *txdata = c;
}

// Use UART1 for EDHOC message exchange
void uart1_putc(char c) {
    volatile uint32_t *txdata = (uint32_t*)(UART1_BASE + 0x00);
    while (*txdata & 0x80000000);  // Wait if full
    *txdata = c;
}

char uart1_getc(void) {
    volatile uint32_t *rxdata = (uint32_t*)(UART1_BASE + 0x04);
    uint32_t data;
    do {
        data = *rxdata;
    } while (data & 0x80000000);  // Wait if empty
    return data & 0xFF;
}
```

### Register Map (SiFive UART)

Both UARTs have the same register layout:

| Offset | Register | Description |
|--------|----------|-------------|
| 0x00   | txdata   | Transmit data (bit 31 = full flag) |
| 0x04   | rxdata   | Receive data (bit 31 = empty flag) |
| 0x08   | txctrl   | Transmit control |
| 0x0C   | rxctrl   | Receive control |
| 0x10   | ie       | Interrupt enable |
| 0x14   | ip       | Interrupt pending |
| 0x18   | div      | Baud rate divisor |

## Wiring for EDHOC Communication

To use this for your EDHOC two-device demo:

**Device 1 (Initiator):**
- UART0 (USB): Console output
- UART1 (PMOD C): EDHOC communication

**Device 2 (Responder):**
- UART0 (USB): Console output  
- UART1 (PMOD C): EDHOC communication

**Physical Connections:**
```
Device 1 PMOD C          Device 2 PMOD C
─────────────────        ─────────────────
JC1 (U12) RX   ────────> JC2 (V12) TX
JC2 (V12) TX   <──────── JC1 (U12) RX
GND            ──────────  GND
```

## Testing

1. **Test UART0 (USB)**:
   ```bash
   screen /dev/ttyUSB0 115200
   # Should see boot messages and kprintf output
   ```

2. **Test UART1 (PMOD C)**:
   - Connect UART1 TX (V12) to RX of USB-to-Serial adapter
   - Connect UART1 RX (U12) to TX of USB-to-Serial adapter
   - Connect GND
   ```bash
   screen /dev/ttyUSB1 115200
   # Send test characters
   ```

## Memory Map Summary

```
0x64000000 - 0x64000FFF : UART0 (USB UART)
0x64001000 - 0x64001FFF : SPI
0x64002000 - 0x64002FFF : GPIO
0x64003000 - 0x64003FFF : UART1 (PMOD C)
```

## Troubleshooting

### Issue: Second UART not appearing
**Solution**: Check that `WithDefaultPeripherals` includes both UART entries and that the build includes the modified configuration.

### Issue: Pin conflicts
**Solution**: Verify that PMOD C pins U12 and V12 are not used by other peripherals in your configuration.

### Issue: No signal on UART1
**Solution**: 
1. Verify pin constraints in generated XDC file
2. Check UART baud rate divisor configuration
3. Use oscilloscope/logic analyzer to verify TX signal

### Issue: UART data corruption
**Solution**:
1. Ensure common ground between devices
2. Check baud rate matches (default 115200)
3. Verify 3.3V logic levels

## References

- Arty A7 Reference Manual: [Digilent Arty A7 Docs](https://reference.digilentinc.com/reference/programmable-logic/arty-a7/reference-manual)
- SiFive UART Specification: [SiFive IP Blocks](https://static.dev.sifive.com/SiFive-Interrupt-Cookbook-v1p2.pdf)
- Chipyard Documentation: [Chipyard Docs](https://chipyard.readthedocs.io/)

## Notes

- The PMOD C UART uses standard 3.3V LVCMOS logic levels
- Maximum supported baud rate depends on system clock frequency (typically up to 1Mbps)
- Both UARTs share the same clock domain and run at the same frequency
- No hardware flow control is implemented; use software flow control if needed
- FIFO depths are 256 entries for both TX and RX (configurable in WithDefaultPeripherals)

---

**Created**: 2025-11-11  
**Author**: System Configuration  
**Version**: 1.0

# Minimal Dual UART Test

**Binary Size:** 4.8 KB (4,820 bytes)

## Purpose
Simple test to verify:
1. Both UARTs are configured correctly
2. Two FPGAs can communicate via UART1 (PMOD C)

## Hardware Setup

### UART Connections
- **UART0** (0x64000000): USB UART - console I/O
- **UART1** (0x64003000): PMOD C (U12=RX, V12=TX)

### Two-Board Wiring
```
Board A              Board B
U12 (RX) ◄────────► V12 (TX)
V12 (TX) ◄────────► U12 (RX)
GND      ◄────────► GND
```

## Test Modes

### Mode 1: Board A (Sender)
- Press any key to send "HELLO_FROM_A"
- Waits for echo from Board B
- Displays received echo

### Mode 2: Board B (Responder)
- Receives messages on UART1
- Displays on UART0 console
- Echoes back on UART1

## Usage

1. **Build:**
   ```bash
   cd fpga/sw/test_uart
   make
   ```

2. **Program both FPGAs** with dual UART bitstream

3. **Load binary** onto both boards:
   ```
   fpga/sw/test_uart/build/main.bin
   ```

4. **Connect terminals** (115200 baud, 8N1):
   - Board A: `/dev/ttyUSB0`
   - Board B: `/dev/ttyUSB1`

5. **Run test:**
   - Board A: Press `1` → Press any key to send
   - Board B: Press `2` → Auto echoes

## Expected Output

**Board A:**
```
==================================
  Dual UART Test - Arty A7 100T
==================================

=== UART Configuration Test ===
UART0 (USB):   0x64000000
UART1 (PMOD):  0x64003000
UART0: TX=ON RX=ON
UART1: TX=ON RX=ON

Select mode:
  1 - Board A (send messages)
  2 - Board B (echo messages)
Press 1 or 2: 1

=== Board A Mode ===
Press any key to send message...
Sending: HELLO_FROM_A
Echo: HELLO_FROM_A
```

**Board B:**
```
==================================
  Dual UART Test - Arty A7 100T
==================================

=== UART Configuration Test ===
UART0 (USB):   0x64000000
UART1 (PMOD):  0x64003000
UART0: TX=ON RX=ON
UART1: TX=ON RX=ON

Select mode:
  1 - Board A (send messages)
  2 - Board B (echo messages)
Press 1 or 2: 2

=== Board B Mode ===
Waiting for messages on UART1...
HELLO_FROM_A
```

## Test Verification

✅ **Configuration test** shows both UARTs enabled
✅ **Board A** receives echo matching sent message
✅ **Board B** displays received message on console

## Code Summary

**Total:** ~80 lines of actual test code (minimal!)

**Functions:**
- `uart_putc()` - Send char to UART
- `uart_getc()` - Receive char from UART (non-blocking)
- `test_uart_config()` - Display UART status
- `test_board_a()` - Send messages, wait for echo
- `test_board_b()` - Echo received messages

**No external dependencies** - uses only:
- `kprintf()` - console output
- `platform.h` - memory map
- `uart.h` - register definitions

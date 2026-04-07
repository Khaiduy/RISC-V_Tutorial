# TRNG Peripheral Integration Summary

## What Was Done

### 1. Created TRNG Scala Peripheral ([TRNG.scala](generators/chipyard/src/main/scala/crypto/trng/TRNG.scala))
- **BlackBox wrapper** for existing TRNG.v Verilog module
- **TileLink register interface** with memory-mapped control/status/data registers
- **Sticky done bit** implementation to capture the 1-cycle hardware `oDone` signal
- Automatic resource inclusion for all TRNG Verilog files

### 2. Integrated TRNG into SoC

**Modified files:**
- [DigitalTop.scala](generators/chipyard/src/main/scala/DigitalTop.scala): Added `CanHavePeripheryTRNG` trait
- [Configs.scala](fpga/src/main/scala/arty100t/Configs.scala): Added `WithTRNG` config to SmallRocket32Arty100TConfig

**Address assignment:** `0x10030000` (configurable via WithTRNG parameter)

### 3. Created Firmware Test Suite

**Location:** [fpga/sw/trng_test/](fpga/sw/trng_test/)

**Files created:**
- `include/trng.h` - TRNG driver API header
- `src/trng.c` - TRNG driver implementation  
- `src/main.c` - Test application
- `src/start.S` - Startup assembly
- `linker/memory.lds` - Linker script
- `Makefile` - Build system
- `README.md` - Documentation

## Register Map

| Address | Name | Access | Description |
|---------|------|--------|-------------|
| 0x10030000 | CTRL | W | Control: bit[0]=start (write 1 to trigger) |
| 0x10030004 | STATUS | R/W | Status: bit[0]=done (sticky), bit[1]=busy |
| 0x10030010 | RNS0 | R | Random data bits [31:0] |
| 0x10030014 | RNS1 | R | Random data bits [63:32] |
| 0x10030018 | RNS2 | R | Random data bits [95:64] |
| 0x1003001C | RNS3 | R | Random data bits [127:96] |
| 0x10030020 | RNS4 | R | Random data bits [159:128] |
| 0x10030024 | RNS5 | R | Random data bits [191:160] |
| 0x10030028 | RNS6 | R | Random data bits [223:192] |
| 0x1003002C | RNS7 | R | Random data bits [255:224] |

## Key Features

### Sticky Done Implementation

**Problem:** Hardware `oDone` signal is only high for 1 clock cycle

**Solution:** Scala wrapper implements sticky register:
```scala
val done_sticky = RegInit(false.B)

when (trng.io.oDone) {
  done_sticky := true.B
  // Capture random data
  rns_regs(0) := trng.io.oRNS(31, 0)
  // ... capture all 8 words
}

// Software clears by writing 1
RegField(1, done_sticky, RegFieldDesc("done", "Sticky done flag, write 1 to clear"))
```

### Auto-Clear Start Signal

Start signal automatically clears after 1 cycle:
```scala
val start_reg = RegInit(false.B)

when (start_reg) {
  start_reg := false.B  // Auto-clear
}
```

## Usage Example

```c
#include "trng.h"

uint32_t random[8];  // 256 bits

// 1. Clear previous done flag
trng_clear_done();

// 2. Start TRNG
trng_start();

// 3. Wait for completion  
trng_wait_done();

// 4. Read random data
trng_read_256(random);

// Use random[0] through random[7]...
```

## Building and Testing

### 1. Generate Verilog
```bash
cd /path/to/RISC-V_Tutorial
source env.sh
cd fpga
make SUB_PROJECT=arty100t verilog
```

### 2. Build Firmware
```bash
cd fpga/sw/trng_test
make
```

This produces:
- `build/trng_test.elf`
- `build/trng_test.bin`  
- `build/trng_test.dump`

### 3. Load and Run

**Via JTAG:**
```bash
# Upload firmware to SRAM
openocd -f arty.cfg &
riscv64-unknown-elf-gdb build/trng_test.elf
(gdb) target remote :3333
(gdb) load
(gdb) continue
```

**Via SD Card Boot:**
1. Copy `build/trng_test.bin` to SD card
2. Configure bootloader to load from SD
3. Monitor UART output at 115200 baud

## Expected Output

```
=== TRNG Test ===

Test 1: Generating 256-bit random number...
TRNG started, waiting for completion...
TRNG done!
Random data (256 bits):
  Word 0: 0x12345678
  Word 1: 0x9ABCDEF0
  Word 2: 0x13579BDF
  Word 3: 0x2468ACE0
  Word 4: 0xFEDCBA98
  Word 5: 0x76543210
  Word 6: 0xABCDEF01
  Word 7: 0x23456789

Test 2: Generating 256-bit random number...
...
```

## Performance

- **Latency:** ~8192 cycles (2048 cycles warmup × 4 words)
- **At 50MHz:** ~164 microseconds per 256-bit generation
- **Throughput:** ~1.56 MB/s (6.25 Mbits/s)

## Hardware Resources Used

**Verilog Modules:**
- TRNG.v (main FSM, 256-bit collector)
- TopTRNG.v (ring oscillator + LFSR wrapper)
- LFSR_64.v (64-bit LFSR entropy conditioning)
- ringOsc.v (ring oscillator entropy source)
- FF_D.v (D flip-flop)

**Estimated FPGA Resources:**
- LUTs: ~600
- Registers: ~350  
- No Block RAM

## Next Steps

1. **Generate bitstream:**
   ```bash
   cd fpga
   make SUB_PROJECT=arty100t bitstream
   ```

2. **Program FPGA:**
   ```bash
   make SUB_PROJECT=arty100t program
   ```

3. **Monitor UART:** Connect to USB UART at 115200 baud

4. **Customize:** Modify TRNG address in `WithTRNG(0xYOUR_ADDRESS)` if needed

## Files Modified/Created

### Modified
- `generators/chipyard/src/main/scala/DigitalTop.scala` - Added TRNG trait
- `fpga/src/main/scala/arty100t/Configs.scala` - Added TRNG to config

### Created
- `generators/chipyard/src/main/scala/crypto/trng/TRNG.scala` - Peripheral wrapper
- `fpga/sw/trng_test/*` - Complete firmware test suite (7 files)

## Verification Checklist

- [x] TRNG Scala peripheral created with sticky done
- [x] Integrated into DigitalTop
- [x] Added to Arty100T configuration  
- [x] Firmware driver API created
- [x] Test application created
- [x] Documentation complete
- [ ] Verilog generation tested
- [ ] Firmware compilation tested
- [ ] Hardware test on FPGA

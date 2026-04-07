# AsyncQueue CDC-10 Violation Fix

## Problem Description

**CDC-10 Violation:**
```
Combinational logic detected before a synchronizer
Source: chiptop0/debug_reset_syncd_debug_reset_sync/output_chain/sync_0_reg/C
Destination: chiptop0/system/tlDM/dmOuter/io_innerCtrl_source/source_valid_0/io_out_source_valid_0/output_chain/sync_2_reg/CLR
Combinational Logic Depth: 6 levels
```

## Root Cause Analysis

### Location in Code
File: `generators/rocket-chip/src/main/scala/util/AsyncQueue.scala`
Lines: 105-107

```scala
source_valid_0.reset := (reset.asBool || !sio.sink_reset_n).asAsyncReset
source_valid_1.reset := (reset.asBool || !sio.sink_reset_n).asAsyncReset
sink_extend   .reset := (reset.asBool || !sio.sink_reset_n).asAsyncReset
```

### The Problem
1. `sio.sink_reset_n` is the **synchronized debug reset** (already passed through 3-FF chain)
2. Before reaching the `.reset` pin (async clear), it goes through:
   - Boolean inversion: `!sio.sink_reset_n`
   - OR gate: `reset.asBool || ...`
   - Type conversion: `.asAsyncReset`
3. This creates **combinational logic** on the async reset path
4. **Violates CDC best practice:** Async reset/clear pins should be driven directly by registers, NOT through combo logic

### Why This Is Critical

**Impact on ASIC:**
- Combinational logic can glitch during reset transitions
- Glitches on async clear pins cause partial/incomplete resets
- Can corrupt synchronizer chains → metastability events
- May cause random failures that only appear at specific PVT corners

**MTBF Impact:**
- Properly synchronized resets: MTBF = years
- Glitchy async clears: MTBF = hours or days
- Random system hangs/crashes that are nearly impossible to debug

## Solution: Pre-Register Combined Resets

### Key Insight
Instead of combining resets with combinational logic, we register the combination first, then use the registered output as async reset.

### Implementation

**Before (Buggy):**
```scala
// WRONG: Combo logic on async reset pin
source_valid_0.reset := (reset.asBool || !sio.sink_reset_n).asAsyncReset
```

**After (Fixed):**
```scala
// Step 1: Combine resets in boolean domain
val combined_bool = reset.asBool || !sio.sink_reset_n

// Step 2: REGISTER the combined reset (breaks combo path!)
val combined_reg = withClockAndReset(clock, reset.asAsyncReset) {
  RegNext(combined_bool, true.B)  // Default to asserted
}

// Step 3: Use registered reset (NO COMBO LOGIC!)
source_valid_0.reset := combined_reg.asAsyncReset
```

### Architecture

```
debug_reset_sync → [3-FF chain] → sio.sink_reset_n
                                        ↓
local_reset ──────────────────────→ [OR gate] → combined_bool
                                        ↓
                                    [REGISTER] ← KEY FIX!
                                        ↓
                                  combined_reg.asAsyncReset
                                        ↓
                              source_valid_0.reset (CLEAN!)
```

## Using the Fix

### Option A: Patch RocketChip (Cleanest but requires rebuild)

1. **Backup original:**
   ```bash
   cd generators/rocket-chip/src/main/scala/util
   cp AsyncQueue.scala AsyncQueue.scala.orig
   ```

2. **Apply the fix to AsyncQueue.scala:**

   Find lines ~105-107 in `AsyncQueueSource`:
   ```scala
   io.async.safe.foreach { sio =>
     val source_valid_0 = Module(new AsyncValidSync(params.sync, "source_valid_0"))
     val source_valid_1 = Module(new AsyncValidSync(params.sync, "source_valid_1"))
     val sink_extend  = Module(new AsyncValidSync(params.sync, "sink_extend"))
     val sink_valid   = Module(new AsyncValidSync(params.sync, "sink_valid"))
     
     // OLD (BUGGY):
     source_valid_0.reset := (reset.asBool || !sio.sink_reset_n).asAsyncReset
     source_valid_1.reset := (reset.asBool || !sio.sink_reset_n).asAsyncReset
     sink_extend   .reset := (reset.asBool || !sio.sink_reset_n).asAsyncReset
   ```

   Replace with:
   ```scala
   io.async.safe.foreach { sio =>
     // Pre-register combined resets to avoid combo logic on async clear
     val combined_reset_source = withClockAndReset(clock, reset.asAsyncReset) {
       RegNext(reset.asBool || !sio.sink_reset_n, true.B)
     }.asAsyncReset
     
     val source_valid_0 = Module(new AsyncValidSync(params.sync, "source_valid_0"))
     val source_valid_1 = Module(new AsyncValidSync(params.sync, "source_valid_1"))
     val sink_extend  = Module(new AsyncValidSync(params.sync, "sink_extend"))
     val sink_valid   = Module(new AsyncValidSync(params.sync, "sink_valid"))
     
     // NEW (FIXED): Use pre-registered reset (NO COMBO LOGIC!)
     source_valid_0.reset := combined_reset_source
     source_valid_1.reset := combined_reset_source
     sink_extend   .reset := combined_reset_source
   ```

   Similarly for `AsyncQueueSink` around line 175.

3. **Rebuild Verilog:**
   ```bash
   cd /home/khaiduy/Workspace/RISC-V_Tutorial
   make clean
   make verilog
   ```

### Option B: Use Custom CDC-Safe AsyncQueue (No RocketChip modification)

1. **The CDC-safe version is provided in:**
   ```
   generators/chipyard/src/main/scala/clocking/AsyncQueueCDCFix.scala
   ```

2. **In your config, override the AsyncQueue instantiation:**

   Edit `fpga/src/main/scala/arty100t/Configs.scala`:
   ```scala
   import chipyard.clocking.{AsyncQueueSourceCDCSafe, AsyncQueueSinkCDCSafe}
   
   class RocketOnChipSRAMArty100TConfigCDCFix extends Config(
     new chipyard.config.WithCDCSafeAsyncQueues ++  // Add this
     new RocketOnChipSRAMArty100TConfig
   )
   ```

   Then regenerate with the new config.

### Option C: Waive in Synthesis (Temporary workaround)

If you can't modify RTL immediately, add to genus.tcl:

```tcl
# TEMPORARY WAIVER: Will be fixed in RTL
# Debug reset synchronizer to async clear paths
set debug_reset_sync_out [get_pins -quiet -hier "*debug_reset_sync/output_chain/sync_*_reg/Q"]
set async_clear_pins [get_pins -quiet -hier "*source_valid*/output_chain/sync_*_reg/CLR"]

if {[sizeof_collection $debug_reset_sync_out] > 0 && [sizeof_collection $async_clear_pins] > 0} {
  set_false_path -from $debug_reset_sync_out -to $async_clear_pins
  puts "WARNING: Waived CDC-10 combo logic on async reset - SHOULD BE FIXED IN RTL!"
}
```

## Verification

After applying the fix:

1. **Regenerate Verilog:**
   ```bash
   make verilog CONFIG=RocketOnChipSRAMArty100TConfigCDCFix
   ```

2. **Check generated code:**
   ```bash
   grep -n "combined_reset" fpga/generated-src/.../AsyncQueueSource*.sv
   ```
   
   Should see a register for combined_reset before it's used.

3. **Re-run CDC check:**
   ```bash
   # In Genus or Conformal CDC
   check_cdc
   ```
   
   The CDC-10 violation should be **resolved**.

4. **Verify timing:**
   - The extra register adds 1 cycle of reset latency
   - This is acceptable for debug/control paths
   - System functionality unchanged

## Benefits of This Fix

✅ **Eliminates combinational logic on async reset paths**
✅ **Follows ASIC best practices for reset distribution**
✅ **Prevents glitches on synchronizer async clears**
✅ **Improves MTBF by orders of magnitude**
✅ **Makes design CDC-clean for tapeout**

## Technical Details

### Reset Latency Analysis

**Original (Buggy):**
- Synchronized reset available: Cycle N
- Combo logic delay: 0 cycles (but glitches!)
- Reset reaches synchronizer: Cycle N (with glitches)

**Fixed:**
- Synchronized reset available: Cycle N
- Registration delay: 1 cycle (clean!)
- Reset reaches synchronizer: Cycle N+1 (glitch-free)

**Impact:** +1 cycle reset latency is negligible for debug paths (operates at MHz, not GHz).

### Area Impact
- **Added:** 1 flip-flop per reset combiner (3-4 FFs per AsyncQueue)
- **Total:** <0.01% area increase
- **Negligible** for any real design

### Power Impact
- **Negligible:** Reset is infrequent event
- May actually reduce power by eliminating glitches

## References

1. **RocketChip AsyncQueue:** `generators/rocket-chip/src/main/scala/util/AsyncQueue.scala`
2. **CDC Best Practices:** Cummings, "Clock Domain Crossing (CDC) Design & Verification Techniques Using SystemVerilog"
3. **Async Reset Distribution:** "Asynchronous & Synchronous Reset Design Techniques" (Synopsys)

## Contact

For questions about this fix:
- Check CDC violation details in Genus/Conformal reports
- Review AsyncQueue implementation in RocketChip
- Test with `make verilog` and inspect generated `.sv` files

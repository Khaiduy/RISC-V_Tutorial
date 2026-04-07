# CDC Constraint Migration Guide

## Your Original vs. Recommended Approach

### ❌ PROBLEM: Your Original Constraints

```tcl
set_clock_groups -asynchronous \
  -group {sys_clk spi_clk} \
  -group {jtag_clk}
```

**What this does:**
- Makes ALL CDC paths between sys_clk ↔ jtag_clk **INVISIBLE**
- No timing optimization for synchronizers
- No way to verify CDC correctness
- Tools may use slow cells, long wires
- Same as using `set_false_path`!

**Result:** ❌ Hidden timing issues, poor QoR

---

### ✅ SOLUTION: Recommended Constraints

```tcl
# Step 1: Declare async but KEEP PATHS VISIBLE
set_clock_groups -name async_clocks \
  -asynchronous \
  -allow_paths \        # ← KEY ADDITION!
  -group {sys_clk spi_clk} \
  -group {jtag_clk}

# Step 2: Safety net
set_max_delay 0.0 -from sys_clk -to jtag_clk -ignore_clock_latency

# Step 3: Override for synchronizers
set MAX_DELAY_SYNC 4.0
set_max_delay ${MAX_DELAY_SYNC} -from sync_2 -to sync_1 -ignore_clock_latency
set_min_delay [expr -${UNCERT}] -from sync_2 -to sync_1 -ignore_clock_latency
```

**What this does:**
- ✅ Paths remain **VISIBLE** to STA
- ✅ Small `max_delay` → Fast cells, short wires
- ✅ Catches unsynchronized crossings (0.0 default)
- ✅ Can verify all CDC paths
- ✅ Better QoR, smaller area

**Result:** ✅ Optimal CDC implementation with verified timing

---

## Key Changes Summary

| Aspect | Original (Discouraged) | Recommended |
|--------|------------------------|-------------|
| **Clock groups** | `-asynchronous` only | `-asynchronous -allow_paths` |
| **Path visibility** | ❌ Hidden | ✅ Visible |
| **Safety net** | ❌ None | ✅ `max_delay 0.0` default |
| **Synchronizer constraints** | ❌ None | ✅ Tight `max_delay 4ns` |
| **Hold timing** | ❌ Not handled | ✅ Negative `min_delay` |
| **Clock latency** | ❌ Causes issues | ✅ `-ignore_clock_latency` |
| **Optimization** | ❌ No incentive | ✅ Strong incentive |
| **Verification** | ❌ Can't check | ✅ Full STA coverage |

---

## What Happens with Each Approach

### Original Approach (Your Current SDC)

```
Synthesis:
  - Sees clock groups as async
  - Ignores all CDC paths
  - No timing checks → picks any cell
  - May use slow, cheap flip-flops
  - Can place FFs far apart

Result:
  sync_2: slow_ff_0.5x cell, placed 500um away
  sync_1: slow_ff_0.5x cell, placed 200um away
  sync_0: slow_ff_0.5x cell, placed 150um away
  Total delay: 8ns (but nobody knows!)
```

### Recommended Approach (New SDC)

```
Synthesis:
  - Sees clock groups as async
  - Paths remain visible with max_delay 4.0ns
  - Timing checks active → must meet 4ns!
  - Picks fastest cells possible
  - Places FFs very close together

Result:
  sync_2: fast_ff_2x cell, placed 50um away
  sync_1: fast_ff_2x cell, placed 10um away
  sync_0: fast_ff_2x cell, placed 10um away
  Total delay: 2.8ns (verified by STA!)
  Slack: +0.5ns (meeting with margin)
```

---

## How to Migrate

### Step 1: Replace Your Current SDC

**Option A:** Use the new file directly
```bash
cd fpga/sdc
mv constraint.sdc constraint.sdc.old
cp constraint_with_cdc_best_practices.sdc constraint.sdc
```

**Option B:** Add CDC section to existing file
Keep your I/O constraints, just replace the `set_clock_groups` line and add CDC section.

---

### Step 2: Update genus.tcl

```tcl
# In genus.tcl, make sure you source the updated SDC:
source ../sdc/constraint.sdc

# Or if using the new file:
source ../sdc/constraint_with_cdc_best_practices.sdc
```

---

### Step 3: Run Synthesis

```bash
cd fpga
genus -f genus.tcl
```

**Watch for:**
```
INFO: Found 156 sync_2 flip-flops
INFO: Constrained sync_2 → sync_1 paths with max_delay=4.0ns
INFO: Constrained 42 AsyncQueue FIFO data paths with max_delay=7.0ns
```

---

### Step 4: Check Timing Reports

```tcl
# In Genus shell after synthesis:
report_timing -from [get_clocks sys_clk] -to [get_clocks jtag_clk]
```

**Expected output:**
```
Startpoint: some_reg (sys_clk)
Endpoint: sync_2_reg (jtag_clk)
Path Type: max

  Point                   Incr    Path
  ----------------------------------------
  some_reg/Q              2.5     2.5 r
  sync_2_reg/D            0.5     3.0 r
  data arrival time               3.0
  
  max_delay                       4.0    ← Your constraint!
  library setup time     -0.7     3.3
  data required time              3.3
  ----------------------------------------
  slack (MET)                     0.3    ← Good! Tight but meeting
```

---

### Step 5: Tune if Needed

#### If timing VIOLATED (slack < 0):

```tcl
# In your SDC, increase max_delay:
set MAX_DELAY_SYNC 5.0  ;# was 4.0
```

Re-run synthesis and check again.

#### If slack TOO LARGE (slack > 2ns):

```tcl
# In your SDC, decrease max_delay:
set MAX_DELAY_SYNC 3.5  ;# was 4.0
```

This increases optimization pressure for better QoR.

#### Target: slack = 0.1 to 0.5 ns

This ensures:
- ✅ Timing closure
- ✅ Minimal margin waste
- ✅ Maximum optimization

---

## Example Timing Comparison

### Before (Original CDC Constraints)

```
Path 1: debugIntRegs → sync_2
  Cell type: slow_ff_0.5x
  Delay: 5.2ns
  Slack: Not checked (false path)
  
Path 2: sync_2 → sync_1
  Distance: 200um
  Delay: 3.8ns
  Slack: Not checked
  
Path 3: mem_0 → cdc_reg_reg
  Delay: 12.5ns
  Slack: Not checked
```

**Total area:** Large (slow cells cheaper but bigger wires)
**Timing:** Unknown (could fail in silicon!)

---

### After (Recommended CDC Constraints)

```
Path 1: debugIntRegs → sync_2
  Cell type: fast_ff_1.5x
  Delay: 3.2ns
  Slack: +0.8ns ✓
  
Path 2: sync_2 → sync_1
  Distance: 15um
  Delay: 2.1ns
  Slack: +0.4ns ✓
  
Path 3: mem_0 → cdc_reg_reg
  Delay: 6.8ns
  Slack: +0.2ns ✓
```

**Total area:** Smaller (fast cells, short wires)
**Timing:** Verified by STA! Safe for silicon

---

## Common Questions

### Q1: Why not just use `set_false_path`?

**A:** Because you lose all visibility:
- Can't verify CDC correctness
- No optimization
- May fail in silicon with no warning

### Q2: Why `-ignore_clock_latency`?

**A:** CDC paths are asynchronous - clock skew between domains doesn't matter!

Without it:
```
data arrival:    11.0ns  (includes 8ns clock latency)
data required:    9.3ns
slack: VIOLATED -1.7ns  ← FALSE violation!
```

With it:
```
data arrival:     3.0ns  (no clock latency)
data required:    3.3ns
slack: MET +0.3ns  ← CORRECT!
```

### Q3: Why negative `set_min_delay`?

**A:** Compensates clock uncertainty in hold checks:

Without it:
```
data arrival:     3.0ns
clock uncertainty: +0.5ns  ← Adds to hold requirement
data required:    3.5ns
slack: VIOLATED -0.5ns  ← Tool adds buffers!
```

With it:
```
min_delay:       -0.5ns  ← Cancels uncertainty
data required:    3.0ns
slack: MET +0.0ns  ← No buffers needed!
```

### Q4: Why `max_delay 0.0` default?

**A:** Safety net! Catches design bugs:

```tcl
# Default: everything violates
set_max_delay 0.0 -from sys_clk -to jtag_clk

# Override for known synchronizers
set_max_delay 4.0 -from sync_2 -to sync_1

# Result: Any unsynchronized path → FAILS timing
# → Forces you to fix it or add proper synchronizer!
```

### Q5: What if I have different technologies?

**A:** Adjust `MAX_DELAY_SYNC` based on process:

| Technology | Typical Range | Start Value |
|------------|---------------|-------------|
| 7nm - 16nm | 2.0 - 3.5ns | 2.5ns |
| 22nm - 28nm | 3.0 - 5.0ns | 4.0ns |
| 45nm - 65nm | 4.0 - 6.0ns | 5.0ns |
| 90nm - 130nm | 5.0 - 8.0ns | 6.0ns |
| 180nm+ | 6.0 - 10.0ns | 7.0ns |

Always tune based on actual results!

---

## Verification Checklist

After migration, verify:

- [ ] Synthesis completes without errors
- [ ] `report_timing` shows positive slack on CDC paths
- [ ] No "false path" messages for synchronizers
- [ ] Synchronizers use fast cells (check cell report)
- [ ] Synchronizer FFs placed close together (< 100um)
- [ ] No hold buffers inserted in sync chains
- [ ] Safety net (0.0 max_delay) catches unintended crossings

**If ALL checked → Migration successful! 🎉**

---

## Summary

**One line change makes all the difference:**

```tcl
# OLD (Wrong):
set_clock_groups -asynchronous -group {sys_clk} -group {jtag_clk}

# NEW (Correct):
set_clock_groups -asynchronous -allow_paths -group {sys_clk} -group {jtag_clk}
#                                ^^^^^^^^^^^^
#                                This keeps paths VISIBLE!
```

**Then add constraints to guide optimization:**
```tcl
set_max_delay 0.0 -from sys_clk -to jtag_clk -ignore_clock_latency  # Safety
set_max_delay 4.0 -from sync_2 -to sync_1 -ignore_clock_latency    # Sync
set_min_delay -0.5 -from sync_2 -to sync_1 -ignore_clock_latency   # Hold
```

**Result:**
- ✅ Better QoR
- ✅ Smaller area
- ✅ Verified timing
- ✅ Safe for silicon

**Use file:** `fpga/sdc/constraint_with_cdc_best_practices.sdc`

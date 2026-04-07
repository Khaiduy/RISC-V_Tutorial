# CDC Constraints Quick Reference

## For Your RocketChip Design (sys_clk 100MHz, jtag_clk 50MHz)

### Minimum Required Constraints

```tcl
#==============================================================================
# 1. DECLARE ASYNCHRONOUS CLOCKS (keep paths visible!)
#==============================================================================
set_clock_groups -name async_clocks \
  -asynchronous \
  -allow_paths \
  -group [get_clocks sys_clk] \
  -group [get_clocks jtag_clk]

#==============================================================================
# 2. SAFE DEFAULT (catches bugs!)
#==============================================================================
set_max_delay 0.0 -from sys_clk -to jtag_clk -ignore_clock_latency
set_max_delay 0.0 -from jtag_clk -to sys_clk -ignore_clock_latency

#==============================================================================
# 3. SYNCHRONIZER CONSTRAINTS (tune MAX_DELAY_SYNC!)
#==============================================================================
set MAX_DELAY_SYNC 4.0  ;# Start here, adjust based on results
set UNCERT 0.5

# For each synchronizer path (src → sync_2, sync_2 → sync_1, sync_1 → sync_0):
set_max_delay ${MAX_DELAY_SYNC} -from <source> -to <sync_stage> -ignore_clock_latency
set_min_delay [expr -${UNCERT}] -from <source> -to <sync_stage> -ignore_clock_latency
```

---

## The Three Rules

### Rule 1: Always use `-ignore_clock_latency`
**Why:** Clock skew between async domains is irrelevant
```tcl
set_max_delay 4.0 ... -ignore_clock_latency  ← CRITICAL!
```

### Rule 2: Always pair max_delay with min_delay
**Why:** Prevents false hold violations and unnecessary buffers
```tcl
set_max_delay 4.0 ... -ignore_clock_latency
set_min_delay -0.5 ... -ignore_clock_latency  ← Don't forget!
```

### Rule 3: Start with tight constraints, relax if needed
**Why:** Forces optimal implementation
```tcl
set MAX_DELAY_SYNC 4.0  ;# Start tight
# If timing fails, increase to 5.0, 6.0, etc.
```

---

## Values to Tune

| Parameter | Typical Range | Your Starting Value |
|-----------|---------------|---------------------|
| `MAX_DELAY_SYNC` | 2.5ns - 6.0ns | **4.0ns** |
| `MAX_DELAY_FIFO` | 5.0ns - 10.0ns | **7.0ns** |
| `UNCERT` | 0.3ns - 1.0ns | **0.5ns** |

**Tuning process:**
1. Start with values above
2. Run synthesis
3. Check timing: `report_timing -from sys_clk -to jtag_clk`
4. **If slack < 0:** Increase `MAX_DELAY_SYNC` by 0.5ns
5. **If slack > 2ns:** Decrease `MAX_DELAY_SYNC` by 0.5ns
6. Target: **slack = 0.1 to 0.5ns** (tight but meeting)

---

## What NOT To Do

### ❌ DON'T: Use set_false_path
```tcl
set_false_path -from sys_clk -to jtag_clk  ← BAD!
```
**Why:** Paths become invisible, no optimization

### ❌ DON'T: Use set_clock_groups without -allow_paths
```tcl
set_clock_groups -asynchronous -group sys_clk -group jtag_clk  ← BAD!
# Missing: -allow_paths
```
**Why:** Same as false path, hides problems

### ❌ DON'T: Forget -ignore_clock_latency
```tcl
set_max_delay 4.0 -from src -to sync  ← BAD!
# Missing: -ignore_clock_latency
```
**Why:** Clock skew causes false violations

### ❌ DON'T: Skip min_delay constraints
```tcl
set_max_delay 4.0 -from src -to sync -ignore_clock_latency  ← INCOMPLETE!
# Missing: set_min_delay
```
**Why:** Hold violations → unwanted buffers

---

## Verification Commands

### Check CDC Paths Exist
```tcl
report_timing -from [get_clocks sys_clk] -to [get_clocks jtag_clk]
report_timing -from [get_clocks jtag_clk] -to [get_clocks sys_clk]
```

### Verify Synchronizer Timing
```tcl
report_timing -from *src* -to *sync_2* -max_paths 10
report_timing -from *sync_2* -to *sync_1* -max_paths 10
report_timing -from *sync_1* -to *sync_0* -max_paths 10
```

### Check for Hold Buffers (Should be NONE!)
```tcl
report_timing -delay_type min -from *sync_2* -to *sync_1*
# Look for inserted buffers in path
```

### Count Synchronizers
```tcl
sizeof_collection [get_cells -hier "*sync_0*" -filter "is_sequential==true"]
sizeof_collection [get_cells -hier "*sync_1*" -filter "is_sequential==true"]
sizeof_collection [get_cells -hier "*sync_2*" -filter "is_sequential==true"]
```

---

## Expected Results

### Good Timing Report
```
Startpoint: src/Q
Endpoint: sync_2/D
Path Group: sys_clk
Path Type: max

  Point                   Incr    Path
  ----------------------------------------
  src/Q                   3.0     3.0 r
  sync_2/D                0.0     3.0 r
  data arrival time               3.0
  
  max_delay                       4.0
  library setup time     -0.7     3.3
  data required time              3.3
  ----------------------------------------
  slack (MET)                     0.3  ← Good!
```

### Good Cell Placement
```
report_qor -summary

Synchronizer Cells:
  sync_2: Uses fast_ff_1x cell  ← Good!
  sync_1: Uses fast_ff_1x cell  ← Good!
  sync_0: Uses fast_ff_1x cell  ← Good!

Distance:
  src → sync_2: 50 um  ← Short!
  sync_2 → sync_1: 10 um  ← Very short!
  sync_1 → sync_0: 10 um  ← Very short!
```

---

## Files Created

1. **`fpga/sdc/cdc_constraints_recommended.sdc`**
   - Complete CDC constraints with all patterns
   - Use this in your synthesis flow
   
2. **`docs/CDC_Constraint_Strategies.md`**
   - Detailed explanation and comparison
   - Tuning guide
   
3. **`docs/CDC_FIX_AsyncQueue.md`**
   - RTL fix for CDC-10 violation
   
4. **`docs/asyncqueue_cdc_fix.patch`**
   - Patch for RocketChip AsyncQueue.scala

---

## Integration into genus.tcl

Add after clock definitions:
```tcl
# After create_clock commands
source ../sdc/cdc_constraints_recommended.sdc

# Or inline:
set_clock_groups -asynchronous -allow_paths -group sys_clk -group jtag_clk
set_max_delay 0.0 -from sys_clk -to jtag_clk -ignore_clock_latency
# ... rest of constraints
```

---

## Key Insight from Article

> **"The point is to keep CDC paths visible to timing engines and create path exceptions to incentivize implementation tools for desired properties (i.e. small delay and load)."**

Translation:
- **Visible paths** = STA can verify correctness
- **Small max_delay** = Forces fast cells and short routes
- **Negative min_delay** = Prevents hold fix buffers
- **Result** = Optimal CDC implementation with verified timing

---

## When in Doubt

**Ask these questions:**
1. Are my CDC paths visible? (Not using `set_false_path`?) ✓
2. Am I using `-ignore_clock_latency`? ✓
3. Do I have both `set_max_delay` AND `set_min_delay`? ✓
4. Is my `max_delay` tight enough (4-6ns)? ✓
5. Does timing meet with small slack (0.3ns)? ✓

**If all YES → You're doing it right!**

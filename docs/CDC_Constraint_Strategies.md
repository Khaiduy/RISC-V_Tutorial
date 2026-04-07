# CDC Constraint Strategies: Comparison and Recommendations

## Based on Analysis of Best Practices Article
https://gist.github.com/brabect1/7695ead3d79be47576890bbcd61fe426

---

## Three Approaches to CDC Constraints

### ❌ Approach 1: IGNORE CDC Paths (DISCOURAGED)

```tcl
# Method 1a: Using set_false_path
set_false_path -from sys_clk -to jtag_clk
set_false_path -from jtag_clk -to sys_clk

# Method 1b: Using set_clock_groups
set_clock_groups -asynchronous -group sys_clk -group jtag_clk
```

**Problems:**
- Paths become **invisible** to STA tools
- No optimization incentive for synthesis/P&R
- Can't verify if CDC is correct
- Synchronizers may use slow cells
- Long wires, high capacitance possible
- **Risk:** Hidden timing issues that only appear in silicon

**When to use:** NEVER for ASIC! Maybe acceptable for FPGA with proven CDC design.

---

### ⚠️ Approach 2: RELAX CDC Paths (DISCOURAGED)

```tcl
# Method 2a: Infinite max delay
set_max_delay infinity -from sys_clk -to jtag_clk

# Method 2b: No constraints (treat as synchronous)
# Just define clocks, no exceptions
```

**Problems:**
- Paths visible but **no optimization pressure**
- May allow buffers in synchronizer chains
- Can place synchronizer FFs far apart
- Clock latency differences cause false violations/fixes
- Setup checks too relaxed, hold checks may be wrong

**When to use:** Only for debugging, never in final constraints.

---

### ✅ Approach 3: CONSTRAIN CDC Paths Properly (RECOMMENDED)

```tcl
# Step 1: Declare async clocks but keep paths visible
set_clock_groups -asynchronous -allow_paths \
  -group sys_clk -group jtag_clk

# Step 2: Safe default - catches unsynchronized crossings
set_max_delay 0.0 -from sys_clk -to jtag_clk -ignore_clock_latency

# Step 3: Override with tight constraints for synchronizers
set MAX_DELAY_SYNC 4.0  ;# Technology-dependent, adjust based on results
set UNCERT 0.5

# Crossing path: source → sync_2
set_max_delay ${MAX_DELAY_SYNC} \
  -from <source_reg> -to <sync_2_reg> \
  -ignore_clock_latency

set_min_delay [expr -${UNCERT}] \
  -from <source_reg> -to <sync_2_reg> \
  -ignore_clock_latency

# Synchronizer chain: sync_2 → sync_1 → sync_0
set_max_delay ${MAX_DELAY_SYNC} \
  -from <sync_2_reg> -to <sync_1_reg> \
  -ignore_clock_latency

set_min_delay [expr -${UNCERT}] \
  -from <sync_2_reg> -to <sync_1_reg> \
  -ignore_clock_latency
```

**Benefits:**
- ✅ Paths remain **visible** to STA
- ✅ **Small max_delay** forces fast cells and short routes
- ✅ **Negative min_delay** prevents unnecessary hold buffers
- ✅ Can verify timing on all CDC paths
- ✅ Catches design bugs (unsynchronized crossings)
- ✅ Better QoR (Quality of Results)

**Why it works:**
1. `set_max_delay 4.0` → "This path must be ≤ 4ns" → Tools use fast FFs, place close
2. `-ignore_clock_latency` → Ignores clock skew differences between domains
3. Negative `set_min_delay` → Compensates clock uncertainty in hold checks
4. `set_max_delay 0.0` default → Any unsynchronized path violates → Catches bugs!

---

## Applying to Your RocketChip Design

### Your Design Characteristics:

**Clocks:**
- `sys_clk`: 100 MHz (10ns period)
- `jtag_clk`: 50 MHz (20ns period), asynchronous to sys_clk

**CDC Mechanisms:**
1. **3-stage synchronizers** (sync_0, sync_1, sync_2)
   - Used for: Gray counter sync, handshake signals
   - Pattern: `*output_chain/sync_*`

2. **AsyncQueue Gray FIFO**
   - Pointers: Synchronized via 3-FF chains
   - Data: Direct crossing, protected by handshake
   - Pattern: `*AsyncQueueSource*/mem_*` → `*AsyncQueueSink*/cdc_reg_reg*`

3. **DTM handshake** (JTAG → DMI)
   - No synchronizer (intentional!)
   - Safe due to slow JTAG + req/ready protocol
   - Use multicycle paths

---

## Recommended Values (Starting Point)

### For 28nm-65nm Process:

```tcl
set MAX_DELAY_SYNC 4.0   ;# For 3-FF synchronizers
set MAX_DELAY_FIFO 7.0   ;# For multi-bit async data with handshake
set UNCERT 0.5           ;# Clock uncertainty (adjust per technology)
```

### For 16nm-7nm Process:

```tcl
set MAX_DELAY_SYNC 2.5   ;# Faster logic, tighter timing
set MAX_DELAY_FIFO 5.0
set UNCERT 0.3
```

### For 180nm-130nm Process:

```tcl
set MAX_DELAY_SYNC 6.0   ;# Slower logic, need more margin
set MAX_DELAY_FIFO 10.0
set UNCERT 1.0
```

---

## Tuning Process

### Step 1: Start with Conservative Values
```tcl
set MAX_DELAY_SYNC 4.0
```

### Step 2: Run Synthesis
```bash
genus -f genus.tcl
```

### Step 3: Check Timing Reports
```tcl
report_timing -from [get_clocks sys_clk] -to [get_clocks jtag_clk]
```

### Step 4: Adjust Based on Results

**If timing VIOLATED (slack < 0):**
- Increase max_delay by 0.5-1.0 ns
- Check if synchronizers are being optimized away (use `dont_touch`)
- Verify cell library has fast enough flip-flops

**If timing MET with large slack (slack > 2ns):**
- Decrease max_delay by 0.5 ns
- This increases optimization pressure
- Results in faster, smaller synchronizers

**Target: Small positive slack (0.1-0.5 ns)**
- Ensures timing closure
- Maximizes optimization

### Step 5: Verify After Place & Route
```tcl
# Check actual delays
report_timing -from <sync_2> -to <sync_1>

# Check synchronizer placement
report_qor -summary
```

---

## Key Insights from Article

### 1. `-ignore_clock_latency` is CRITICAL

**Without it:**
```
clock CLKA (rise edge)     0.00    0.00
clock network delay        8.00    8.00  ← Clock skew included!
src/CK                     0.00    8.00
src/Q                      3.00   11.00
...
slack (VIOLATED)           -1.70   ← False violation!
```

**With it:**
```
src/CK                     0.00    0.00
src/Q                      3.00    3.00
...
slack (MET)                0.30    ← Correct!
```

**Reason:** CDC paths are asynchronous - clock skew between domains is irrelevant!

---

### 2. Negative `set_min_delay` Prevents Hold Buffers

**Problem:** Clock uncertainty adds to hold requirements:
```
clock uncertainty    3.0     3.0
library hold time    0.3     3.3
data required time           3.3
data arrival time           -3.0
slack (VIOLATED)            -0.3  ← Tool adds buffers!
```

**Solution:** Compensate with negative min_delay:
```tcl
set_min_delay [expr -${UNCERT}] -from sync_2 -to sync_1
```

**Result:**
```
min_delay               -3.0    -3.0
clock uncertainty        3.0     0.0  ← Canceled out!
library hold time        0.3     0.3
data required time               0.3
data arrival time               -3.0
slack (MET)                      2.7  ← No buffers needed!
```

---

### 3. `set_max_delay 0.0` as Safety Net

**Purpose:** Catch unsynchronized CDC paths

**Example:**
```tcl
# Safe default
set_max_delay 0.0 -from sys_clk -to jtag_clk -ignore_clock_latency

# Override for known synchronizers
set_max_delay 4.0 -from src_reg -to sync_2_reg -ignore_clock_latency
```

**Result:**
- Any path NOT explicitly constrained → Violates 0ns max_delay
- Forces you to identify and fix all CDC crossings
- Better than false paths that hide problems!

---

## Common Pitfalls to Avoid

### ❌ Pitfall 1: Forgetting `-ignore_clock_latency`
```tcl
set_max_delay 4.0 -from sys_clk -to jtag_clk
# Missing: -ignore_clock_latency
```
**Problem:** Clock latency differences cause false violations

---

### ❌ Pitfall 2: Only Constraining Max, Not Min
```tcl
set_max_delay 4.0 -from src -to sync_2 -ignore_clock_latency
# Missing: set_min_delay
```
**Problem:** Clock uncertainty causes hold violations → Tool adds buffers

---

### ❌ Pitfall 3: Too Relaxed max_delay
```tcl
set_max_delay 10.0 ...  # Way too loose for 3-FF synchronizer!
```
**Problem:** No optimization pressure → Slow cells, long wires, large area

---

### ❌ Pitfall 4: Constraining Multi-Bit Buses Same as Synchronizers
```tcl
set_max_delay 4.0 -from FF1A -to FF1B  # 32-bit bus!
```
**Problem:** May be too tight for parallel data with handshake

**Solution:** Use larger max_delay for multi-bit (7-10ns)

---

## Verification Checklist

After applying CDC constraints:

- [ ] All synchronizers have `set_max_delay` overrides
- [ ] All synchronizers have `set_min_delay` compensation
- [ ] `-ignore_clock_latency` used consistently
- [ ] `set_max_delay 0.0` default catches unintended crossings
- [ ] Timing reports show small positive slack (~0.3ns)
- [ ] No hold buffers inserted in synchronizer chains
- [ ] `report_cdc` (if available) shows all paths constrained
- [ ] Post-route verification confirms constraints hold

---

## Summary: What to Use for Your Design

**Use the file:** `fpga/sdc/cdc_constraints_recommended.sdc`

**Key settings:**
```tcl
# Declare async clocks, keep paths visible
set_clock_groups -asynchronous -allow_paths -group sys_clk -group jtag_clk

# Safety net
set_max_delay 0.0 -from sys_clk -to jtag_clk -ignore_clock_latency

# Synchronizers
set MAX_DELAY_SYNC 4.0
set_max_delay ${MAX_DELAY_SYNC} -from src -to sync_2 -ignore_clock_latency
set_min_delay [expr -${UNCERT}] -from src -to sync_2 -ignore_clock_latency

# AsyncQueue data
set MAX_DELAY_FIFO 7.0
set_max_delay ${MAX_DELAY_FIFO} -from mem_* -to cdc_reg_reg* -ignore_clock_latency
```

**Then tune based on actual timing results!**

---

## References

1. **Original Article:** https://gist.github.com/brabect1/7695ead3d79be47576890bbcd61fe426
2. **Author's Handshake Protocols:** https://github.com/brabect1/sv_handshake_comps
3. **Clifford Cummings CDC Paper:** "Clock Domain Crossing Design & Verification Techniques"
4. **Synopsys PrimeTime User Guide:** Section on CDC Timing

#==============================================================================
# CDC Timing Constraints for RocketChip JTAG Debug Module
# Based on best practices from:
# https://gist.github.com/brabect1/7695ead3d79be47576890bbcd61fe426
#
# Design: Arty100TWithoutDDRHarness with RocketOnChipSRAMArty100TConfig
# Clock Domains:
#   - sys_clk:  100 MHz (10ns period) - Main system clock
#   - jtag_clk:  50 MHz (20ns period) - JTAG debug clock (asynchronous)
#   - spi_clk:   50 MHz (20ns period) - SPI clock (derived from sys_clk)
#==============================================================================

#==============================================================================
# Clock Definitions (should be in main constraint.sdc)
#==============================================================================
# create_clock -name sys_clk  -period 10.0 [get_ports sys_clock]
# create_clock -name jtag_clk -period 20.0 [get_ports jtag_jtag_TCK]
# create_clock -name spi_clk  -period 20.0 [get_pins -hier *spi_clk*]

#==============================================================================
# Clock Uncertainty (for hold compensation)
#==============================================================================
set UNCERT 0.5
set_clock_uncertainty ${UNCERT} [all_clocks]

#==============================================================================
# PART 1: Declare Asynchronous Clock Groups
# Use -allow_paths to keep CDC paths visible for STA
#==============================================================================
set_clock_groups -name async_clocks \
  -asynchronous \
  -allow_paths \
  -group [get_clocks sys_clk] \
  -group [get_clocks jtag_clk] \
  -comment "sys_clk and jtag_clk are asynchronous, but CDC paths remain constrained"

# SPI clock is derived from sys_clk, so they are synchronous
# No need to add spi_clk to async groups

#==============================================================================
# PART 2: Safe Defaults - Catch Unsynchronized Crossings
# Any path not explicitly constrained will violate, alerting us to CDC bugs
#==============================================================================
set_max_delay 0.0 \
  -from [get_clocks sys_clk] \
  -to [get_clocks jtag_clk] \
  -ignore_clock_latency \
  -comment "Default: will violate if no proper CDC synchronizer exists"

set_max_delay 0.0 \
  -from [get_clocks jtag_clk] \
  -to [get_clocks sys_clk] \
  -ignore_clock_latency \
  -comment "Default: will violate if no proper CDC synchronizer exists"

#==============================================================================
# PART 3: Single-Bit 3-FF Synchronizers (AsyncResetSynchronizerShiftReg_d3)
#
# RocketChip uses 3-stage synchronizers with naming pattern:
#   <instance>/output_chain/sync_0, sync_1, sync_2
#
# Constraint Strategy:
#   - Crossing path (src → sync_2): Tight max_delay forces fast cells, short routes
#   - Sync path (sync_2 → sync_1 → sync_0): Same tight constraint
#   - Min delay: Negative to compensate clock uncertainty (prevents hold buffers)
#==============================================================================

# Choose max_delay based on technology and desired synchronizer speed
# - Start with 3-4ns for typical 65nm-28nm process
# - Adjust based on post-synthesis/post-route timing results
# - Too tight: May not meet timing
# - Too loose: Less optimization pressure, larger area

set MAX_DELAY_SYNC 4.0  ;# Adjust based on your technology

# JTAG → System Clock Crossings (Debug Module)
# Pattern: *output_chain* contains sync_0, sync_1, sync_2

# Get all synchronizer stages
set sync_output_chains [get_cells -quiet -hier "*output_chain*"]

if {[sizeof_collection $sync_output_chains] > 0} {
  puts "INFO: Found [sizeof_collection $sync_output_chains] synchronizer chains"
  
  # Method 1: Constrain by synchronizer hierarchy
  # This works if synchronizers are in separate hierarchical modules
  foreach_in_collection chain $sync_output_chains {
    set chain_name [get_object_name $chain]
    
    # Get flip-flops within this synchronizer chain
    set sync_ffs [get_cells -quiet -hier -filter "full_name=~${chain_name}/* && is_sequential==true"]
    
    if {[sizeof_collection $sync_ffs] > 0} {
      # Identify sync_0, sync_1, sync_2 by name
      set sync_2 [get_cells -quiet -hier -filter "full_name=~${chain_name}/sync_2*"]
      set sync_1 [get_cells -quiet -hier -filter "full_name=~${chain_name}/sync_1*"]
      set sync_0 [get_cells -quiet -hier -filter "full_name=~${chain_name}/sync_0*"]
      
      # Find source register (anything driving sync_2 that's not in the chain)
      set src_pins [all_fanin -to [get_pins -of $sync_2 -filter "direction==in"] -flat -only_cells]
      set src_regs [filter_collection $src_pins "is_sequential==true && full_name!~${chain_name}*"]
      
      if {[sizeof_collection $src_regs] > 0 && [sizeof_collection $sync_2] > 0} {
        # Crossing path: src → sync_2
        set_max_delay ${MAX_DELAY_SYNC} \
          -from [get_pins -of $src_regs -filter "direction==out"] \
          -to [get_pins -of $sync_2 -filter "direction==in"] \
          -ignore_clock_latency
        
        set_min_delay [expr -${UNCERT}] \
          -from [get_pins -of $src_regs -filter "direction==out"] \
          -to [get_pins -of $sync_2 -filter "direction==in"] \
          -ignore_clock_latency
        
        puts "INFO: Constrained crossing to ${chain_name}"
      }
      
      # Synchronizing paths: sync_2 → sync_1 → sync_0
      if {[sizeof_collection $sync_2] > 0 && [sizeof_collection $sync_1] > 0} {
        set_max_delay ${MAX_DELAY_SYNC} \
          -from [get_pins -of $sync_2 -filter "direction==out"] \
          -to [get_pins -of $sync_1 -filter "direction==in"] \
          -ignore_clock_latency
        
        set_min_delay [expr -${UNCERT}] \
          -from [get_pins -of $sync_2 -filter "direction==out"] \
          -to [get_pins -of $sync_1 -filter "direction==in"] \
          -ignore_clock_latency
      }
      
      if {[sizeof_collection $sync_1] > 0 && [sizeof_collection $sync_0] > 0} {
        set_max_delay ${MAX_DELAY_SYNC} \
          -from [get_pins -of $sync_1 -filter "direction==out"] \
          -to [get_pins -of $sync_0 -filter "direction==in"] \
          -ignore_clock_latency
        
        set_min_delay [expr -${UNCERT}] \
          -from [get_pins -of $sync_1 -filter "direction==out"] \
          -to [get_pins -of $sync_0 -filter "direction==in"] \
          -ignore_clock_latency
      }
    }
  }
} else {
  puts "WARNING: No synchronizer chains found. Check naming patterns."
}

# Method 2: Simpler pattern-based approach (if above doesn't work)
# Constrain all sync_2 → sync_1 and sync_1 → sync_0 paths

set all_sync_2 [get_cells -quiet -hier "*sync_2*" -filter "is_sequential==true"]
set all_sync_1 [get_cells -quiet -hier "*sync_1*" -filter "is_sequential==true"]
set all_sync_0 [get_cells -quiet -hier "*sync_0*" -filter "is_sequential==true"]

if {[sizeof_collection $all_sync_2] > 0} {
  puts "INFO: Found [sizeof_collection $all_sync_2] sync_2 registers"
  puts "INFO: Found [sizeof_collection $all_sync_1] sync_1 registers"
  puts "INFO: Found [sizeof_collection $all_sync_0] sync_0 registers"
  
  # Synchronizer internal paths
  if {[sizeof_collection $all_sync_2] > 0 && [sizeof_collection $all_sync_1] > 0} {
    set_max_delay ${MAX_DELAY_SYNC} \
      -from [get_pins -of $all_sync_2 -filter "direction==out"] \
      -to [get_pins -of $all_sync_1 -filter "direction==in"] \
      -ignore_clock_latency
    
    set_min_delay [expr -${UNCERT}] \
      -from [get_pins -of $all_sync_2 -filter "direction==out"] \
      -to [get_pins -of $all_sync_1 -filter "direction==in"] \
      -ignore_clock_latency
  }
  
  if {[sizeof_collection $all_sync_1] > 0 && [sizeof_collection $all_sync_0] > 0} {
    set_max_delay ${MAX_DELAY_SYNC} \
      -from [get_pins -of $all_sync_1 -filter "direction==out"] \
      -to [get_pins -of $all_sync_0 -filter "direction==in"] \
      -ignore_clock_latency
    
    set_min_delay [expr -${UNCERT}] \
      -from [get_pins -of $all_sync_1 -filter "direction==out"] \
      -to [get_pins -of $all_sync_0 -filter "direction==in"] \
      -ignore_clock_latency
  }
}

#==============================================================================
# PART 4: AsyncQueue Data Memory Crossings (Multi-bit CDC)
#
# AsyncQueue uses Gray-coded pointers with synchronizers, but data memory
# crosses asynchronously. This is safe because:
# - Data is stable in FIFO memory
# - Read only occurs after Gray pointer is synchronized
# - Handshake protocol guarantees data validity
#
# Constraint: Use larger max_delay since data path is guarded by handshake
#==============================================================================

set MAX_DELAY_FIFO 7.0  ;# Relaxed for multi-bit paths with handshake

# AsyncQueue source memory to sink data registers
# Pattern: *io_innerCtrl_source/mem_* → *io_innerCtrl_sink*/cdc_reg_reg*

set async_src_mem [get_cells -quiet -hier "*io_innerCtrl_source/mem_*" -filter "is_sequential==true"]
set async_sink_data [get_cells -quiet -hier "*io_innerCtrl_sink*/cdc_reg_reg*" -filter "is_sequential==true"]

if {[sizeof_collection $async_src_mem] > 0 && [sizeof_collection $async_sink_data] > 0} {
  set_max_delay ${MAX_DELAY_FIFO} \
    -from [get_pins -of $async_src_mem -filter "direction==out"] \
    -to [get_pins -of $async_sink_data -filter "direction==in"] \
    -ignore_clock_latency
  
  set_min_delay [expr -${UNCERT}] \
    -from [get_pins -of $async_src_mem -filter "direction==out"] \
    -to [get_pins -of $async_sink_data -filter "direction==in"] \
    -ignore_clock_latency
  
  puts "INFO: Constrained [sizeof_collection $async_src_mem] AsyncQueue data memory paths"
}

# Generic AsyncQueue patterns (if above doesn't match)
set all_async_src [get_cells -quiet -hier "*AsyncQueueSource*/mem_*" -filter "is_sequential==true"]
set all_async_sink [get_cells -quiet -hier "*AsyncQueueSink*/cdc_reg_reg*" -filter "is_sequential==true"]

if {[sizeof_collection $all_async_src] > 0 && [sizeof_collection $all_async_sink] > 0} {
  set_max_delay ${MAX_DELAY_FIFO} \
    -from [get_pins -of $all_async_src -filter "direction==out"] \
    -to [get_pins -of $all_async_sink -filter "direction==in"] \
    -ignore_clock_latency
  
  set_min_delay [expr -${UNCERT}] \
    -from [get_pins -of $all_async_src -filter "direction==out"] \
    -to [get_pins -of $all_async_sink -filter "direction==in"] \
    -ignore_clock_latency
}

#==============================================================================
# PART 5: Gray Counter Paths
#
# Gray counters (widx_gray, ridx_gray) cross clock domains
# These feed synchronizers, so use same tight constraints as single-bit sync
#==============================================================================

set gray_counters [get_cells -quiet -hier "*widx_gray* *ridx_gray*" -filter "is_sequential==true"]

if {[sizeof_collection $gray_counters] > 0} {
  # Limit fanout to keep paths fast
  set_max_fanout 4 $gray_counters
  
  puts "INFO: Constrained [sizeof_collection $gray_counters] Gray counter registers"
}

#==============================================================================
# PART 6: Debug Interrupt Signals
#
# Debug interrupt signals are edge-triggered and asynchronous by design
# Use relaxed constraints or false path
#==============================================================================

set debug_int_regs [get_cells -quiet -hier "*debugIntRegs*" -filter "is_sequential==true"]

if {[sizeof_collection $debug_int_regs] > 0} {
  # Option 1: False path (interrupts are edge-triggered, timing doesn't matter)
  set_false_path -from [get_pins -of $debug_int_regs -filter "direction==out"]
  
  # Option 2: Relaxed constraint (if you want visibility)
  # set_max_delay 10.0 -from [get_pins -of $debug_int_regs -filter "direction==out"]
  
  puts "INFO: Applied false path to [sizeof_collection $debug_int_regs] debug interrupt registers"
}

#==============================================================================
# PART 7: DTM Handshake Paths (JTAG → DMI)
#
# DebugTransportModuleJTAG uses handshake protocol without synchronizers
# This is safe because JTAG is slow (< 10MHz) and uses req/ready handshake
# Apply multicycle constraint to relax timing
#==============================================================================

set dtm_regs [get_cells -quiet -hier "*DebugTransportModuleJTAG*" -filter "is_sequential==true"]

if {[sizeof_collection $dtm_regs] > 0} {
  # Multicycle: JTAG is slow, allow 2 sys_clk cycles for setup
  set_multicycle_path 2 -setup \
    -from $dtm_regs \
    -to [get_clocks sys_clk]
  
  set_multicycle_path 1 -hold \
    -from $dtm_regs \
    -to [get_clocks sys_clk]
  
  puts "INFO: Applied multicycle paths to [sizeof_collection $dtm_regs] DTM registers"
}

#==============================================================================
# PART 8: Report CDC Paths (For Verification)
#==============================================================================

puts "=========================================="
puts "CDC Constraint Summary"
puts "=========================================="
puts "Max delay for synchronizers: ${MAX_DELAY_SYNC} ns"
puts "Max delay for FIFO data: ${MAX_DELAY_FIFO} ns"
puts "Clock uncertainty: ${UNCERT} ns"
puts "Min delay compensation: -${UNCERT} ns"
puts "=========================================="
puts ""
puts "Verify CDC paths with:"
puts "  report_timing -from \[get_clocks sys_clk\] -to \[get_clocks jtag_clk\]"
puts "  report_timing -from \[get_clocks jtag_clk\] -to \[get_clocks sys_clk\]"
puts "=========================================="

# End of CDC constraints

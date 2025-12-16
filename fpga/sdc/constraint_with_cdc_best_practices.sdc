###############################################################
# CDC CONSTRAINTS FOR CADENCE GENUS
# Based on actual generated Verilog analysis and CDC best practices
# Reference: https://gist.github.com/brabect1/7695ead3d79be47576890bbcd61fe426
#
# KEY IMPROVEMENTS FROM ORIGINAL:
# 1. Added -allow_paths to set_clock_groups (keeps CDC paths visible!)
# 2. Added set_max_delay 0.0 safety net (catches unsynchronized crossings)
# 3. Added specific constraints for 3-FF synchronizers
# 4. Added AsyncQueue FIFO data path constraints
# 5. Preserved all original I/O timing constraints
###############################################################

###############################################################
# CLOCK DEFINITIONS
###############################################################
# System clock - 100MHz (main clock for CPU/buses)
create_clock -name sys_clk -period 10.0 [get_ports sys_clock]

# JTAG clock - asynchronous, typically 10-50MHz
create_clock -name jtag_clk -period 20.0 [get_ports jtag_jtag_TCK]

# SPI/SD clock - generated from system clock
create_generated_clock -name spi_clk \
  -source [get_ports sys_clock] \
  -divide_by 2 \
  [get_ports sdio_spi_clk]

###############################################################
# CRITICAL: ASYNCHRONOUS CLOCK GROUPS
# Using -allow_paths to keep CDC paths VISIBLE for optimization!
# This is the RECOMMENDED approach per CDC best practices.
#
# OLD (DISCOURAGED):
#   set_clock_groups -asynchronous -group {sys_clk} -group {jtag_clk}
# NEW (RECOMMENDED):
#   set_clock_groups -asynchronous -allow_paths ...
###############################################################
set_clock_groups -name async_clocks \
  -asynchronous \
  -allow_paths \
  -group {sys_clk spi_clk} \
  -group {jtag_clk} \
  -comment "sys_clk and jtag_clk are asynchronous, but CDC paths remain visible for STA"

###############################################################
# CLOCK CHARACTERISTICS
###############################################################
set netDelay 0.287

set_clock_transition -min 0.5 [all_clocks]
set_clock_transition -max 1.0 [all_clocks]

set_clock_uncertainty $netDelay [all_clocks]

set_clock_latency -min 1.0 [all_clocks]
set_clock_latency -max 1.5 [all_clocks]

###############################################################
# CDC CONSTRAINTS - RECOMMENDED APPROACH
###############################################################

# CDC parameters (TUNE THESE based on timing results!)
set MAX_DELAY_SYNC 4.0  ;# For 3-FF synchronizers (start here, adjust if needed)
set MAX_DELAY_FIFO 7.0  ;# For AsyncQueue multi-bit data paths
set UNCERT $netDelay    ;# Use same as clock uncertainty

puts "INFO: CDC constraint parameters:"
puts "  MAX_DELAY_SYNC = ${MAX_DELAY_SYNC} ns"
puts "  MAX_DELAY_FIFO = ${MAX_DELAY_FIFO} ns"
puts "  UNCERT = ${UNCERT} ns"

#--------------------------------------------------------------
# PART 1: SAFETY NET - Catches unsynchronized CDC crossings!
# Any path not explicitly constrained will violate 0ns max_delay
# This helps catch design bugs where synchronizers are missing
#--------------------------------------------------------------
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

#--------------------------------------------------------------
# PART 2: 3-FF SYNCHRONIZERS
# RocketChip uses AsyncResetSynchronizerShiftReg_d3 with:
#   - sync_2 (input stage)
#   - sync_1 (middle stage)
#   - sync_0 (output stage)
#--------------------------------------------------------------

# Method: Pattern-based constraints for all synchronizer stages
# This overrides the 0.0 default for known synchronizer paths

# Get all synchronizer flip-flops
set all_sync_2 [get_cells -quiet -hier "*sync_2*" -filter "is_sequential==true"]
set all_sync_1 [get_cells -quiet -hier "*sync_1*" -filter "is_sequential==true"]
set all_sync_0 [get_cells -quiet -hier "*sync_0*" -filter "is_sequential==true"]

if {[sizeof_collection $all_sync_2] > 0} {
  puts "INFO: Found [sizeof_collection $all_sync_2] sync_2 flip-flops"
  puts "INFO: Found [sizeof_collection $all_sync_1] sync_1 flip-flops"
  puts "INFO: Found [sizeof_collection $all_sync_0] sync_0 flip-flops"
  
  # Synchronizer chain: sync_2 → sync_1
  if {[sizeof_collection $all_sync_1] > 0} {
    set_max_delay ${MAX_DELAY_SYNC} \
      -from [get_pins -of $all_sync_2 -filter "direction==out"] \
      -to [get_pins -of $all_sync_1 -filter "direction==in"] \
      -ignore_clock_latency
    
    set_min_delay [expr -${UNCERT}] \
      -from [get_pins -of $all_sync_2 -filter "direction==out"] \
      -to [get_pins -of $all_sync_1 -filter "direction==in"] \
      -ignore_clock_latency
    
    puts "INFO: Constrained sync_2 → sync_1 paths with max_delay=${MAX_DELAY_SYNC}ns"
  }
  
  # Synchronizer chain: sync_1 → sync_0
  if {[sizeof_collection $all_sync_0] > 0} {
    set_max_delay ${MAX_DELAY_SYNC} \
      -from [get_pins -of $all_sync_1 -filter "direction==out"] \
      -to [get_pins -of $all_sync_0 -filter "direction==in"] \
      -ignore_clock_latency
    
    set_min_delay [expr -${UNCERT}] \
      -from [get_pins -of $all_sync_1 -filter "direction==out"] \
      -to [get_pins -of $all_sync_0 -filter "direction==in"] \
      -ignore_clock_latency
    
    puts "INFO: Constrained sync_1 → sync_0 paths with max_delay=${MAX_DELAY_SYNC}ns"
  }
  
  # Crossing paths: source → sync_2
  # This is trickier because we need to find source registers
  # For now, rely on the 0.0 default catching violations
  # Then add specific constraints for those paths that violate
} else {
  puts "WARNING: No synchronizer flip-flops found with *sync_* pattern"
  puts "         Check naming conventions after synthesis"
}

#--------------------------------------------------------------
# PART 3: ASYNCQUEUE FIFO DATA PATHS
# Multi-bit data crosses asynchronously but is protected by
# Gray-coded pointer synchronization (handshake mechanism)
# Use relaxed constraints since handshake guarantees stability
#--------------------------------------------------------------

# AsyncQueue source memory to sink data registers
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
  
  puts "INFO: Constrained [sizeof_collection $async_src_mem] AsyncQueue FIFO data paths with max_delay=${MAX_DELAY_FIFO}ns"
}

# Generic AsyncQueue patterns (backup if above doesn't match)
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
  
  puts "INFO: Constrained AsyncQueue data memory crossings"
}

#--------------------------------------------------------------
# PART 4: GRAY COUNTER CONSTRAINTS
# Limit fanout to keep Gray counter paths fast and clean
#--------------------------------------------------------------
set gray_counters [get_cells -quiet -hier "*widx_gray* *ridx_gray*" -filter "is_sequential==true"]

if {[sizeof_collection $gray_counters] > 0} {
  set_max_fanout 4 $gray_counters
  puts "INFO: Limited fanout for [sizeof_collection $gray_counters] Gray counter flip-flops"
}

#--------------------------------------------------------------
# PART 5: DEBUG INTERRUPT PATHS
# These are asynchronous edge-triggered signals
# Timing doesn't matter, use false path
#--------------------------------------------------------------
set debug_int_regs [get_cells -quiet -hier "*debugIntRegs*" -filter "is_sequential==true"]

if {[sizeof_collection $debug_int_regs] > 0} {
  set_false_path -from [get_pins -of $debug_int_regs -filter "direction==out"]
  puts "INFO: Applied false paths to [sizeof_collection $debug_int_regs] debug interrupt registers"
}

#--------------------------------------------------------------
# PART 6: DTM HANDSHAKE PATHS (JTAG → DMI)
# DebugTransportModuleJTAG uses req/ready handshake without
# synchronizers (safe because JTAG is slow)
# Use multicycle constraint to relax timing
#--------------------------------------------------------------
set dtm_regs [get_cells -quiet -hier "*DebugTransportModuleJTAG*" -filter "is_sequential==true"]

if {[sizeof_collection $dtm_regs] > 0} {
  set_multicycle_path 2 -setup \
    -from $dtm_regs \
    -to [get_clocks sys_clk]
  
  set_multicycle_path 1 -hold \
    -from $dtm_regs \
    -to [get_clocks sys_clk]
  
  puts "INFO: Applied multicycle paths to [sizeof_collection $dtm_regs] DTM registers"
}

puts ""
puts "=========================================="
puts "CDC CONSTRAINT SUMMARY"
puts "=========================================="
puts "Approach: RECOMMENDED (paths visible + optimized)"
puts "  - Async clocks declared with -allow_paths"
puts "  - Safety net: max_delay 0.0 ns default"
puts "  - Synchronizers: max_delay ${MAX_DELAY_SYNC} ns"
puts "  - FIFO data: max_delay ${MAX_DELAY_FIFO} ns"
puts "  - All constraints use -ignore_clock_latency"
puts "=========================================="
puts ""

###############################################################
# INPUT/OUTPUT TIMING CONSTRAINTS
# (Preserved from original SDC)
###############################################################

# System clock domain inputs
set_input_delay -clock sys_clk -min [expr 0.207+$netDelay] [get_ports uart_rxd]
set_input_delay -clock sys_clk -max [expr 0.297+$netDelay] [get_ports uart_rxd]
set_input_delay -clock sys_clk -min [expr 0.207+$netDelay] [get_ports sdio_spi_dat_0]
set_input_delay -clock sys_clk -max [expr 0.297+$netDelay] [get_ports sdio_spi_dat_0]

# GPIO inputs
foreach i {0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23} {
  set_input_delay -clock sys_clk -min [expr 0.207+$netDelay] [get_ports gpio_gpio_in_${i}]
  set_input_delay -clock sys_clk -max [expr 0.297+$netDelay] [get_ports gpio_gpio_in_${i}]
}

# JTAG inputs (asynchronous, set for reference)
set_input_delay -clock jtag_clk -min 2.0 [get_ports jtag_jtag_TMS]
set_input_delay -clock jtag_clk -max 5.0 [get_ports jtag_jtag_TMS]
set_input_delay -clock jtag_clk -min 2.0 [get_ports jtag_jtag_TDI]
set_input_delay -clock jtag_clk -max 5.0 [get_ports jtag_jtag_TDI]

# System clock domain outputs
set_output_delay -clock sys_clk -min [expr 0.515+$netDelay] [get_ports uart_txd]
set_output_delay -clock sys_clk -max [expr 4.150+$netDelay] [get_ports uart_txd]
set_output_delay -clock sys_clk -min [expr 0.515+$netDelay] [get_ports sdio_spi_cs]
set_output_delay -clock sys_clk -max [expr 4.150+$netDelay] [get_ports sdio_spi_cs]
set_output_delay -clock sys_clk -min [expr 0.515+$netDelay] [get_ports sdio_spi_dat_3]
set_output_delay -clock sys_clk -max [expr 4.150+$netDelay] [get_ports sdio_spi_dat_3]

# GPIO outputs
foreach i {0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23} {
  set_output_delay -clock sys_clk -min [expr 0.515+$netDelay] [get_ports gpio_gpio_out_${i}]
  set_output_delay -clock sys_clk -max [expr 4.150+$netDelay] [get_ports gpio_gpio_out_${i}]
}

# JTAG output
set_output_delay -clock jtag_clk -min 2.0 [get_ports jtag_jtag_TDO]
set_output_delay -clock jtag_clk -max 8.0 [get_ports jtag_jtag_TDO]

# I/O characteristics
set_input_transition -min 0.5 [remove_from_collection [all_inputs] [all_clocks]]
set_input_transition -max 1.0 [remove_from_collection [all_inputs] [all_clocks]]
set_load 0.042 [all_inputs]
set_load 0.22 [all_outputs]
set_max_fanout 1 [remove_from_collection [all_inputs] [all_clocks]]

###############################################################
# END OF CONSTRAINTS
###############################################################

puts ""
puts "=========================================="
puts "VERIFICATION COMMANDS"
puts "=========================================="
puts "After synthesis, run these to verify CDC constraints:"
puts ""
puts "1. Check CDC timing:"
puts "   report_timing -from \[get_clocks sys_clk\] -to \[get_clocks jtag_clk\]"
puts "   report_timing -from \[get_clocks jtag_clk\] -to \[get_clocks sys_clk\]"
puts ""
puts "2. Verify synchronizer paths:"
puts "   report_timing -from *sync_2* -to *sync_1* -max_paths 10"
puts "   report_timing -from *sync_1* -to *sync_0* -max_paths 10"
puts ""
puts "3. Check for violations on safety net (should be NONE after overrides):"
puts "   report_timing -from sys_clk -to jtag_clk -max_paths 100 -slack_lesser_than 0"
puts ""
puts "4. Tuning: If timing fails, increase MAX_DELAY_SYNC to 5.0 or 6.0 ns"
puts "          If slack > 2ns, decrease MAX_DELAY_SYNC to 3.5 or 3.0 ns"
puts "          Target: slack = 0.1 to 0.5 ns (tight but meeting)"
puts "=========================================="
puts ""

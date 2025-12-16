## ─── General Settings ───────────────────────────────────────────────────────
set_property CONFIG_VOLTAGE 3.3 [current_design]
set_property CFGBVS VCCO      [current_design]
set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 4 [current_design]

## ─── Primary System Clock (50 MHz) ────────────────────────────────────────
set_property -dict {PACKAGE_PIN E3 IOSTANDARD LVCMOS33} [get_ports {top_sys_clock}]
create_clock -name sys_clk -period 10.0 [get_ports {top_sys_clock}] ;# 50 MHz

## ─── JTAG Clock (if present) ───────────────────────────────────────────────
create_clock -name JTCK -period 100.0 -waveform {0 50} [get_ports top_jtag_jtag_TCK]

## ─── Generated Clock after clk_div (50 MHz ÷ 24 = ~2.083 MHz) ─────────────────
create_generated_clock -name ram_clk \
  -source [get_pins clk_div_inst/iClk] \
  -divide_by 24 \
  [get_pins clk_div_inst/oClk]

set_clock_groups -asynchronous \
  -group [get_clocks top_sys_clock] \
  -group [get_clocks ram_clk] \
  -group [get_clocks JTCK]

## ─── Pmod Header JA (Serial output bits) ──────────────────────────────────
set_property PACKAGE_PIN D12 [get_ports serial_tl_bits_out_bits_0]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_out_bits_0]
set_property PACKAGE_PIN K16 [get_ports serial_tl_bits_out_bits_1]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_out_bits_1]
set_property PACKAGE_PIN A18 [get_ports serial_tl_bits_out_bits_2]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_out_bits_2]
set_property PACKAGE_PIN A11 [get_ports serial_tl_bits_out_bits_3]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_out_bits_3]
set_property PACKAGE_PIN G13 [get_ports serial_tl_bits_out_bits_4]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_out_bits_4]  
set_property PACKAGE_PIN B18 [get_ports serial_tl_bits_out_bits_5]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_out_bits_5]  
set_property PACKAGE_PIN B11 [get_ports serial_tl_bits_out_bits_6]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_out_bits_6]  
set_property PACKAGE_PIN D13 [get_ports serial_tl_bits_out_bits_7]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_out_bits_7]

## ─── Pmod Header JB (Serial input bits) ───────────────────────────────────
set_property PACKAGE_PIN C15 [get_ports serial_tl_bits_in_bits_0]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_in_bits_0] 
set_property PACKAGE_PIN J15 [get_ports serial_tl_bits_in_bits_1]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_in_bits_1]
set_property PACKAGE_PIN E15 [get_ports serial_tl_bits_in_bits_2]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_in_bits_2] 
set_property PACKAGE_PIN D15 [get_ports serial_tl_bits_in_bits_3]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_in_bits_3] 
set_property PACKAGE_PIN K15 [get_ports serial_tl_bits_in_bits_4]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_in_bits_4]
set_property PACKAGE_PIN J17 [get_ports serial_tl_bits_in_bits_5]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_in_bits_5] 
set_property PACKAGE_PIN J18 [get_ports serial_tl_bits_in_bits_6]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_in_bits_6] 
set_property PACKAGE_PIN E16 [get_ports serial_tl_bits_in_bits_7]      
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_in_bits_7] 

## ─── Pmod Header JC (Valid / Ready / Clock) ───────────────────────────────
set_property PACKAGE_PIN U12 [get_ports serial_tl_bits_in_valid]     
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_in_valid]
set_property PACKAGE_PIN V12 [get_ports serial_tl_bits_out_ready]    
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_out_ready]
set_property PACKAGE_PIN U14 [get_ports serial_tl_bits_in_ready]    
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_in_ready]
set_property PACKAGE_PIN V14 [get_ports serial_tl_bits_out_valid]   
set_property IOSTANDARD LVCMOS33 [get_ports serial_tl_bits_out_valid]
set_property PACKAGE_PIN {T13} [get_ports {top_clk_to_asic}]
set_property IOSTANDARD {LVCMOS33} [get_ports {top_clk_to_asic}]

## ─── Pmod Header JD (Reset to ASIC) ───────────────────────────────────────
set_property PACKAGE_PIN {E2} [get_ports {top_reset_to_asic}]
set_property IOSTANDARD {LVCMOS33} [get_ports {top_reset_to_asic}]

## ─── Board Reset (Input) ─────────────────────────────────────────────────
set_property PACKAGE_PIN {C2} [get_ports {top_reset}]
set_property IOSTANDARD {LVCMOS33} [get_ports {top_reset}]

## ─── (Optional) LED indicator ─────────────────────────────────────────────
set_property PACKAGE_PIN H5 [get_ports reset_led]      
set_property IOSTANDARD LVCMOS33 [get_ports reset_led] 

`timescale 1ns / 1ps

module serRAM(
  input wire top_sys_clock,
  input wire top_reset,

  output wire top_clk_to_asic,
  output wire top_reset_to_asic,
  output wire reset_led, 
  
  output wire serial_tl_bits_in_valid,
  output wire serial_tl_bits_in_bits_0,
  output wire serial_tl_bits_in_bits_1,
  output wire serial_tl_bits_in_bits_2,
  output wire serial_tl_bits_in_bits_3,
  output wire serial_tl_bits_in_bits_4,
  output wire serial_tl_bits_in_bits_5,
  output wire serial_tl_bits_in_bits_6,
  output wire serial_tl_bits_in_bits_7,
  output wire serial_tl_bits_out_ready,
  
  input wire serial_tl_bits_in_ready,
  input wire serial_tl_bits_out_valid,
  input wire serial_tl_bits_out_bits_0,
  input wire serial_tl_bits_out_bits_1,
  input wire serial_tl_bits_out_bits_2,
  input wire serial_tl_bits_out_bits_3,
  input wire serial_tl_bits_out_bits_4,
  input wire serial_tl_bits_out_bits_5,
  input wire serial_tl_bits_out_bits_6,
  input wire serial_tl_bits_out_bits_7  
);

  wire       PLL_clk_out1;	
  wire       PLL_locked;	
  wire       async_ram_reset;
  wire       ram_clk;	

clk_wiz_0  clk_wiz_0_clk_wiz(
  .clk_out1(PLL_clk_out1),
  .reset(~top_reset),
  .locked(PLL_locked),
  .clk_in1(top_sys_clock)
 );  

clk_div clk_div_inst(
	.iClk(PLL_clk_out1),
	.oClk(ram_clk)
    );
   ODDR #(
        .DDR_CLK_EDGE("SAME_EDGE"),
        .INIT(1'b0),
        .SRTYPE("SYNC")
    ) clk_out_oddr (
        .Q(top_clk_to_asic),
        .C(PLL_clk_out1),
        .CE(1'b1),
        .D1(1'b1),
        .D2(1'b0),
        .R(1'b0),
        .S(1'b0)
    );
assign async_ram_reset =  ~PLL_locked | ~top_reset; 
assign top_reset_to_asic = ~async_ram_reset;

wire [7:0] serial_tl_bits_in_bits;
wire [7:0] serial_tl_bits_out_bits;

assign serial_tl_bits_in_bits_0 = serial_tl_bits_in_bits[0];
assign serial_tl_bits_in_bits_1 = serial_tl_bits_in_bits[1];
assign serial_tl_bits_in_bits_2 = serial_tl_bits_in_bits[2];
assign serial_tl_bits_in_bits_3 = serial_tl_bits_in_bits[3];
assign serial_tl_bits_in_bits_4 = serial_tl_bits_in_bits[4];
assign serial_tl_bits_in_bits_5 = serial_tl_bits_in_bits[5];
assign serial_tl_bits_in_bits_6 = serial_tl_bits_in_bits[6];
assign serial_tl_bits_in_bits_7 = serial_tl_bits_in_bits[7];
assign serial_tl_bits_out_bits = {serial_tl_bits_out_bits_7, serial_tl_bits_out_bits_6, serial_tl_bits_out_bits_5, serial_tl_bits_out_bits_4, serial_tl_bits_out_bits_3, serial_tl_bits_out_bits_2, serial_tl_bits_out_bits_1, serial_tl_bits_out_bits_0};

wire serial_tl_bits_in_valid_wire;
wire serial_tl_bits_out_ready_wire;

assign reset_led = async_ram_reset;
assign serial_tl_bits_in_valid  = serial_tl_bits_in_valid_wire;
assign serial_tl_bits_out_ready = serial_tl_bits_out_ready_wire;

SerialRAM SerRam(
  .clock(ram_clk),
  .reset(async_ram_reset),
  .io_ser_in_ready(serial_tl_bits_in_ready),
  .io_ser_out_valid(serial_tl_bits_out_valid),
  .io_ser_out_bits(serial_tl_bits_out_bits),
  .io_ser_in_valid(serial_tl_bits_in_valid_wire),
  .io_ser_in_bits(serial_tl_bits_in_bits),
  .io_ser_out_ready(serial_tl_bits_out_ready_wire)
);

endmodule

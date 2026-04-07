`timescale 1ns / 1ps

(* dont_touch = "yes"*)
module ringOSC(
    input         iEn,
    output  [6:0] oRoInject,
    output        oRo 
    );
    
(*ALLOW_COMBINATORIAL_LOOPS = "true"*)(* dont_touch = "yes"*) wire [6:0] w;

   ROHM18NAND2P005 nand0 (.A (w[6]), .B(iEn), .Y(w[0]));
   ROHM18INVP005   not1  (.A (w[0]), .Y(w[1]));
   ROHM18INVP005   not2  (.A (w[1]), .Y(w[2]));
   ROHM18INVP005   not3  (.A (w[2]), .Y(w[3]));
   ROHM18INVP005   not4  (.A (w[3]), .Y(w[4]));
   ROHM18INVP005   not5  (.A (w[4]), .Y(w[5]));
   ROHM18INVP005   not6  (.A (w[5]), .Y(w[6]));
   
   assign oRoInject = w;
   assign oRo = w[6]; 
   
endmodule

//===========  INVERTER module =============== 
module ROHM18INVP005 (
	input  A,
	output Y
);
`ifdef VERILATOR
    // Dummy oscillator for simulation
    assign Y = ~A;
`else
LUT6 #(
    .INIT(64'h0000000000000001)
   ) LUT6_inst (
      .O(Y),
      .I0(A),
      .I1(0),
      .I2(0),
      .I3(0),
      .I4(0),
      .I5(0)
   );
`endif
endmodule

//========= NAND2 module ===================
module ROHM18NAND2P005(
	input  A,
	input  B,
	output Y
	);

`ifdef VERILATOR
    // Dummy oscillator for simulation
    assign Y = ~(A & B);
`else

	LUT6 #(
      .INIT(64'h0000000000000007)  // Specify LUT Contents
   ) LUT6_inst (
      .O(Y),
      .I0(A),
      .I1(B),
      .I2(0),
      .I3(0),
      .I4(0),
      .I5(0)
   );
`endif
endmodule
//==========================================
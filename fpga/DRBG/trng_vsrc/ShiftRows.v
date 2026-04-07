`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Module Name: ShiftRows
// Description: 
// -- The first row of State is not altered.
// -- For the second row, a 1-byte circular left shift is performed.
// -- For the third row, a 2-byte circular left shift is performed.
// -- For the fourth row, a 3-byte circular left shift is performed

// in_state:	ab0518e48b403f4e897ff02f35f1fcc4 
// out_state:   ab40f0c48b7ffce489f1184e35053f2f
// 
//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module ShiftRows(
	input  [127:0] iState,
	output [127:0] oState
	);
	
	wire [7:0] s00, s01, s02, s03;
	wire [7:0] s10, s11, s12, s13;
	wire [7:0] s20, s21, s22, s23;
	wire [7:0] s30, s31, s32, s33;
	
	// row 1
	assign s00 = iState[127:120];
	assign s01 = iState[ 95: 88];
	assign s02 = iState[ 63: 56];
	assign s03 = iState[ 31: 24];
	
	// row 2
	assign s13 = iState[119:112];
	assign s10 = iState[ 87: 80];
	assign s11 = iState[ 55: 48];
	assign s12 = iState[ 23: 16];
	
	// row 3	
	assign s22 = iState[111:104];
	assign s23 = iState[ 79: 72];
	assign s20 = iState[ 47: 40];
	assign s21 = iState[ 15:  8]; 
	
	// row 4
	assign s31 = iState[103:96];
	assign s32 = iState[ 71:64];
	assign s33 = iState[ 39:32]; 
	assign s30 = iState[  7: 0];
	
	// ShiftRows output
	assign oState = {s00, s10, s20, s30,
					  s01, s11, s21, s31,
					  s02, s12, s22, s32,
					  s03, s13, s23, s33}; 
	
endmodule

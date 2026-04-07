`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Module Name: ExpandKey

    /*
    Master Key: 256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4;
    */
// 
//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module ExpandKey(
	input iClk,
	input iRst,
	input iEnc,
	input  [255:0] iKey,	// original key
	output [127:0] oKey	   // round key for next rounds
	);
	
	// ----------------------------- internal wire and reg signals
	reg sel, clkDiv2;
	reg clkDiv2_d1, clkDiv2_d2;
	reg enable;
	wire [7:0] iRConst_pre, iRConst, oRConst;
	wire [255:0] iRoundKey_pre, iRoundKey, oRoundKey;
	reg [3:0] counter;

	// --------------------------------------- process_counter_var
	always @(posedge iClk)
	begin
		if (iRst)
			counter <= 4'd0;
		else begin
			if (counter == 4'd0) begin
				if (iEnc == 1'b0)
					counter <= 4'd0;
	            else
					counter <= 4'd1;
			end else begin
				if (counter < 4'd15)
					counter <= counter + 1'b1;
				else
					counter <= 4'd0;
			end
		end
	end
	//--------------------- iclkDiv2 delay ------------------------

	always @(posedge iClk) begin
	  if(iRst) begin
	    clkDiv2_d1 <= 1'b0;
	    clkDiv2_d2 <= 1'b0;
	  end
	  else begin
	    clkDiv2_d1 <= clkDiv2;
	    clkDiv2_d2 <= clkDiv2_d1;
	  end
	end

	// --------------------------------------- process_sel_signal
	always @(posedge iClk)
	begin
		if (iRst)
			sel <= 1'b0;
		else begin
			if (counter > 4'd1)
				sel <= 1'b1;
			else
			    sel <= 1'b0;
		end
	end

	// --------------------------------------- process_enable_signal
	always @(posedge iClk)
	begin
		if (iRst)
			enable <= 1'b0;
		else begin
			if (counter > 4'd0)
				enable <= 1'b1;
			else
			    enable <= 1'b0;
		end
	end

	// --------------------------------------- process_iClk_div2
	always @(posedge iClk)
	begin
		if (iRst | iEnc)
			clkDiv2 <= 1'b0;
		else
		    if (counter > 4'd0)
		      clkDiv2 <= ~ clkDiv2;
	end
	// ---------------------------------------

	// --- MUX_RC, REG_RC and RoundConstants
	Mux2 #(8) MUX_RC(
		.iA(8'h01),
		.iB(oRConst),
		.iSel(sel),
		.oC(iRConst_pre));

	RegN #(8) REG_RC(
		.iClk(iClk), // clkDiv2
		.iRst(iRst),
		.iEn(clkDiv2), // enable
		.iD(iRConst_pre),
		.oQ(iRConst));

	RoundConstants Round_Constants(
		.iRConst(iRConst),
		.oRConst(oRConst));

	// --- MUX_KS, REG_KS and KeySchedule
	Mux2 #(256) MUX_KS(
		.iA(iKey),
		.iB(oRoundKey),
		.iSel(sel),
		.oC(iRoundKey_pre));

	RegN #(256) REG_KS(
		.iClk(iClk), // clkDiv2
		.iRst(iRst),
		.iEn(clkDiv2), // enable
		.iD(iRoundKey_pre), 
		.oQ(iRoundKey));
		
	KeySchedule256 Key_Schedule(
		.iRoundKey(iRoundKey), 
		.iRConst(iRConst), 
		.oRoundKey(oRoundKey));
       
	// --- output 
	Mux2 #(128) MUX_selKey(
		.iA(iRoundKey[127:  0]), 
		.iB(iRoundKey[255:128]), 
		.iSel(clkDiv2 & enable), 
		.oC(oKey));

				
endmodule

//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module RoundConstants(
	input  [7:0] iRConst,
	output [7:0] oRConst
    );
	
	wire [7:0] r_shifted_state;
	wire [7:0] r_constant_xor;
	
	assign r_shifted_state = {iRConst[6:0], 1'b0};
	assign r_constant_xor  = {3'b000, iRConst[7], iRConst[7], 1'b0, iRConst[7], iRConst[7]};
	assign oRConst 	       = r_shifted_state ^ r_constant_xor;
	
endmodule


//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module KeySchedule256(
	input  [255:0] iRoundKey,
	input  [7:0] iRConst,
	output [255:0] oRoundKey
	);
	
	// -----------------------------------------------------
	wire [31:0] o_g, o_s;
	wire [31:0] i_w0, i_w1, i_w2, i_w3, i_w4, i_w5, i_w6, i_w7;
	wire [31:0] o_w0, o_w1, o_w2, o_w3, o_w4, o_w5, o_w6, o_w7;
	
	
	// -----------------------------------------------------
	
	assign i_w0 = iRoundKey[255:224];
	assign i_w1 = iRoundKey[223:192];
	assign i_w2 = iRoundKey[191:160];
	assign i_w3 = iRoundKey[159:128];
	assign i_w4 = iRoundKey[127: 96];
	assign i_w5 = iRoundKey[ 95: 64];
	assign i_w6 = iRoundKey[ 63: 32];
	assign i_w7 = iRoundKey[ 31:  0];
	
	function_g U_function_g(
		.iW(i_w7), .iRConst(iRConst), .oW(o_g));
		
	assign o_w0 = i_w0 ^ o_g;
	assign o_w1 = i_w1 ^ o_w0;
	assign o_w2 = i_w2 ^ o_w1;
	assign o_w3 = i_w3 ^ o_w2;
	
	function_s U_function_s(
		.iW(o_w3), .oW(o_s));
	
	assign o_w4 = i_w4 ^ o_s;
	assign o_w5 = i_w5 ^ o_w4;
	assign o_w6 = i_w6 ^ o_w5;
	assign o_w7 = i_w7 ^ o_w6;
	
	assign oRoundKey = {o_w0, o_w1, o_w2, o_w3, o_w4, o_w5, o_w6, o_w7};
	
endmodule


//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module function_s(
	input  [31:0] iW,
	output [31:0] oW
	);
	
	SBoxLUT Sbox0(iW[ 7: 0], oW[ 7: 0]);
	SBoxLUT Sbox1(iW[15: 8], oW[15: 8]);
	SBoxLUT Sbox2(iW[23:16], oW[23:16]);
	SBoxLUT Sbox3(iW[31:24], oW[31:24]);
	
endmodule

//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module function_g(
	input  [31:0] iW,
	input  [7:0] iRConst,
	output [31:0] oW
	);
	
	wire [7:0] b0, b1, b2, b3;
	wire [31:0] subwords; 	// output after Sbox
	wire [31:0] rotwords;
	
	assign b0 = iW[31:24];	
	assign b1 = iW[23:16];
	assign b2 = iW[15: 8];
	assign b3 = iW[ 7: 0];
	
	assign rotwords = {b1, b2, b3, b0};
	
	SBoxLUT Sbox_func0( rotwords[ 7: 0], subwords[ 7: 0]);
	SBoxLUT Sbox_func1( rotwords[15: 8], subwords[15: 8]);
	SBoxLUT Sbox_func2( rotwords[23:16], subwords[23:16]);
	SBoxLUT Sbox_func3( rotwords[31:24], subwords[31:24]);
	
	assign oW = {(subwords[31:24] ^ iRConst), subwords[23:0]};
	
endmodule
`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
    /* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/aes_ctr.pdf
    -- AES-128-CTR mode example
    -- iKey:        256'h603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4
                    603DEB10 15CA71BE 2B73AEF0 857D7781
                    1F352C07 3B6108D7 2D9810A3 0914DFF4
    
    -- iCtr:        F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF

    -- iMsg:        6BC1BEE2 2E409F96 E93D7E11 7393172A
                    AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
                    30C81C46 A35CE411 E5FBC119 1A0A52EF
                    F69F2445 DF4F9B17 AD2B417B E66C3710
                    
    -- oCipher:     601EC313 775789A5 B7A7F504 BBF3D228
                    F443E3CA 4D62B59A CA84E990 CACAF5C5
                    2B0930DA A23DE94C E87017BA 2D84988D
                    DFC9C58D B67AADA6 13C2DD08 457941A6       
    */
    
    /* ECB-AES
    Key is  603DEB10 15CA71BE 2B73AEF0 857D7781 
            1F352C07 3B6108D7 2D9810A3 0914DFF4 
    Plaintext is
            6BC1BEE2 2E409F96 E93D7E11 7393172A 
            AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 
            30C81C46 A35CE411 E5FBC119 1A0A52EF 
            F69F2445 DF4F9B17 AD2B417B E66C3710
    Ciphertext is
            F3EED1BD B5D2A03C 064B5A7E 3DB181F8 
            591CCB10 D410ED26 DC5BA74A 31362870 
            B6ED21B9 9CA6F4F9 F153E7B1 BEAFED1D 
            23304B7A 39F9F3FF 067D8D8F 9E24ECC7          
    */
//////////////////////////////////////////////////////////////////////////////////
module AES_256_CTR(
	input           iClk,
	input           iRst,
	input           iEnc,
	input           iDone,
	input           iMode, // 1 is CTR, 0 is ECB
	input  [255:0]  iKey,
	input  [127:0]  iCtr,
	input  [127:0]  iMsg,
	output [127:0]  oCipher,
	output          oFinish
	);
	
	// ----------------------------- internal wire and reg signals
	wire enc_1clk;
	
	wire sel_MUX_ARK, sel_MUX_MC, sel_MUX_FINAL, enable;
	
	wire [127:0] RoundKey, s_MUX_ARK, s_MUX_MC, s_REG_ARK, ctrVal;
	
	wire [127:0] s_AddRoundKey, s_SubBytes, s_ShiftRows, s_MixColumns;

	// ------------------ normalization i_enc
    normalPW Nomal_iEnc(
        .iClk(iClk),
        .iRst(iRst),
        .iPulse(iEnc),
        .oPulse(enc_1clk));
	
	AES_Controller Controller(
		.iClk(iClk),
		.iRst(iRst),
		.iEnc(enc_1clk),	
		.oSel_MUX_ARK(sel_MUX_ARK),
		.oSel_MUX_MC(sel_MUX_MC),
		.oSel_MUX_Final(sel_MUX_FINAL),
		.oEn(enable),		
		.oFinish(oFinish));
	// ----------------------------------------	
	ExpandKey Expand_Key(
		.iClk(iClk),
		.iRst(iRst),
		.iEnc(enc_1clk),		
		.iKey(iKey),
		.oKey(RoundKey));

	// ---------------------------------------- Update CtrVal
    incCounter inc_Counter(
        .iClk(iClk),
        .iRst(iRst),
        .iDone(iDone),
        .iInc(enc_1clk),
        .oCtrVal(ctrVal)
	);
		
	// ----------------------------------------
	Mux2 #(128) MUX_ARK(
		.iA(iMode ? (iCtr + ctrVal) : iMsg), // iMode: 1 is CTR, 0 is iMsg
		.iB(s_MUX_MC),
		.iSel(sel_MUX_ARK),
		.oC(s_MUX_ARK));
		
	AddRoundKey Add_Round_Key(
		.iKey(RoundKey),
		.iState(s_MUX_ARK),
		.oState(s_AddRoundKey));
		
	RegN #(128) REG_ARK(
		.iClk(iClk), 
		.iRst(iRst), 
		.iEn(enable), 
		.iD(s_AddRoundKey), 
		.oQ(s_REG_ARK));
	
	// ----------------------------------------
	SubBytes Sub_Bytes(
		.iState(s_REG_ARK),
		.oState(s_SubBytes));
	
	// ----------------------------------------	
	ShiftRows Shift_Rows(
		.iState(s_SubBytes),
		.oState(s_ShiftRows));
		
	// ----------------------------------------	
	MixColumns Mix_Columns(
		.iState(s_ShiftRows),
		.oState(s_MixColumns));
			
	Mux2 #(128) MUX_MC(
		.iA(s_MixColumns),
		.iB(s_ShiftRows),
		.iSel(sel_MUX_MC),
		.oC(s_MUX_MC));
	

	RegN #(128) REG_FINAL(
		.iClk(iClk), 
		.iRst(iRst), 
		.iEn(sel_MUX_FINAL), 
		.iD(iMode ? (s_REG_ARK ^ iMsg) : s_REG_ARK), // iMode: 1 is CTR, 0 is ECB 
		.oQ(oCipher));

	
endmodule

//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module AddRoundKey(
	input  [127:0] iKey,
	input  [127:0] iState,
	output [127:0] oState
	);
	
	assign oState = iKey ^ iState;
	
endmodule

//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module Mux2#
	(
		parameter N_width = 8
	)(
		input [N_width-1:0] iA,
		input [N_width-1:0] iB,
		input iSel,
		output [N_width-1:0] oC
	);
	
	assign oC = (iSel == 1'b0) ? iA : iB;
endmodule

//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module RegN#
	(
		parameter N_width = 8
	)(
		input iClk,
		input iRst,
		input iEn,
		input [N_width-1:0] iD,
		output reg [N_width-1:0] oQ
	);
	
	// --------------------------------------- process_register
	always @(posedge iClk)
	begin
		if (iRst)
			oQ <= 0;
		else if (iEn)
			oQ <= iD;
	end
endmodule

//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module normalPW(
	input iClk,
	input iRst,
	input iPulse,
	output reg oPulse
	);
	
	reg pulseDelay;
	
	// -------------------- process_Normalized Pulse Width
	always @(posedge iClk)
	begin
		if (iRst) begin
	       pulseDelay  <= 1'b0;
	       oPulse <= 1'b0;
	    end else begin
            pulseDelay <= iPulse;
            if ( (iPulse==1'b1) && (pulseDelay==1'b0) )
                oPulse <= 1'b1;
            else
                oPulse <= 1'b0;
	    end
	end
endmodule


//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module incCounter(
	input iClk,
	input iRst,
	input iDone,
	input iInc,
	output reg [127:0] oCtrVal
	);
	// -------------------- process_Counter
	always @(posedge iClk)
	begin
		if (iRst || iDone)
	       oCtrVal  <= 128'h0;
	    else begin
            if ( iInc )
                oCtrVal <= oCtrVal + 128'd1;
            else
                oCtrVal <= oCtrVal;
	    end
	end
endmodule

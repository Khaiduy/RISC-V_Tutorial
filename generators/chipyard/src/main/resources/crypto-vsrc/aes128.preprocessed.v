
//////////////////////////////////////////////////////////////////////////////////
//
// Description: 
// -- AES example
// -- plaintext:	0123456789abcdeffedcba9876543210
// -- key:			0f1571c947d9e8590cb7add6af7f6798
// -- ciphertext:	ff0b844a0853bf7c6934ab4364148fb9
 
// i_mode:      0 - Encryption   1 - Decryption
// i_init       --> Pre-calculating Expand Key
// 
//////////////////////////////////////////////////////////////////////////////////


module AES128(
	input i_clk,
	input i_rst,
	input i_init,
	input i_mode,
	input i_enc,
	input [127:0] i_key_AES,
	input [127:0] i_msg_AES,
	output [127:0] o_cipher_AES,
	output reg o_finish
	);
	
	// ----------------------------- internal wire and reg signals
	reg i_enc_d;
	reg enc_1clk;
	
	wire finish;
	
	reg i_init_d;
	reg init_1clk;
	
	
	wire sel_MUX_ARK, sel_MUX_MC, sel_MUX_FINAL, sel_MUX_INV, enable;
	
	wire [127:0] o_key, o_key_InvMC, RoundKey, s_MUX_ARK, s_MUX_MC, s_REG_ARK;
	
	wire [127:0] s_AddRoundKey, s_SubBytes, s_ShiftRows, s_MixColumns;
	
	wire [127:0] s_InvShiftRows, s_InvMixColumns;
	
	wire [127:0] s_MUX_ShiftRows, s_MUX_MixColumns;
	
	// --------------------------------------- normalization i_init
	always @(posedge i_clk)
	begin
	   if (i_rst == 1'b1) begin
	       i_init_d <= 1'b0;
	       init_1clk <= 1'b0;
	   end else begin
	       i_init_d <= i_init;
	       if ( (i_init == 1'b1) && (i_init_d==1'b0) )
	           init_1clk <= 1'b1;
	       else
               init_1clk <= 1'b0;
       end
	end
	
	// --------------------------------------- normalization i_enc
	always @(posedge i_clk)
	begin
		o_finish <= finish;
		if (i_rst == 1'b1) begin
	       i_enc_d  <= 1'b0;
	       enc_1clk <= 1'b0;
	    end else begin
            i_enc_d <= i_enc;
            if ( (i_enc==1'b1) && (i_enc_d==1'b0) )
                enc_1clk <= 1'b1;
            else
                enc_1clk <= 1'b0;
	    end
	end
	
	
	AES_Controller Controller(
		.i_clk(i_clk),
		.i_rst(i_rst),
		.i_enc(enc_1clk),
		.i_mode(i_mode),
		.o_sel_MUX_INV(sel_MUX_INV),		
		.o_sel_MUX_ARK(sel_MUX_ARK),
		.o_sel_MUX_MC(sel_MUX_MC),
		.o_sel_MUX_Final(sel_MUX_FINAL),
		.o_enable(enable),			
		.o_finish(finish));
	
	// ----------------------------------------	
	ExpandKey Expand_Key(
		.i_clk(i_clk),
		.i_init(init_1clk),
		.i_mode(i_mode),
		.i_rst(i_rst),
		.sel_Round(enable),
		.i_key(i_key_AES),
		.o_key(o_key));
	
	InvMixColumns Key_Mix_Columns(
		.i_state(o_key),
		.o_state(o_key_InvMC));
		
	Mux2 #(128) MUX_InvMC(
		.i_a(o_key),
		.i_b(o_key_InvMC),
		.i_sel(sel_MUX_INV),
		.o_c(RoundKey));
		
	// ----------------------------------------
	Mux2 #(128) MUX_ARK(
		.i_a(i_msg_AES),
		.i_b(s_MUX_MC),
		.i_sel(sel_MUX_ARK),
		.o_c(s_MUX_ARK));
		
	AddRoundKey Add_Round_Key(
		.i_key(RoundKey),
		.i_state(s_MUX_ARK),
		.o_state(s_AddRoundKey));
		
	RegN #(128) REG_ARK(
		.i_clk(i_clk), 
		.i_rst(i_rst), 
		.i_enable(enable), 
		.i_d(s_AddRoundKey), 
		.o_q(s_REG_ARK));
	
	// ----------------------------------------
	SubBytesDual Sub_Bytes(
	    .i_mode(i_mode),
		.i_state(s_REG_ARK),
		.o_state(s_SubBytes));
	

	// ----------------------------------------	
	ShiftRows Shift_Rows(
		.i_state(s_SubBytes),
		.o_state(s_ShiftRows));
	
	InvShiftRows Inv_Shift_Rows(
		.i_state(s_SubBytes),
		.o_state(s_InvShiftRows));
	
	Mux2 #(128) MUX_Shift_Rows(
		.i_a(s_ShiftRows),
		.i_b(s_InvShiftRows),
		.i_sel(i_mode),
		.o_c(s_MUX_ShiftRows));
		
	// ----------------------------------------	
	MixColumns Mix_Columns(
		.i_state(s_MUX_ShiftRows),
		.o_state(s_MixColumns));

	InvMixColumns Inv_Mix_Columns(
		.i_state(s_MUX_ShiftRows),
		.o_state(s_InvMixColumns));
	
	Mux2 #(128) MUX_MC0(
		.i_a(s_MixColumns),
		.i_b(s_InvMixColumns),
		.i_sel(i_mode),
		.o_c(s_MUX_MixColumns));
			
	Mux2 #(128) MUX_MC1(
		.i_a(s_MUX_MixColumns),
		.i_b(s_MUX_ShiftRows),
		.i_sel(sel_MUX_MC),
		.o_c(s_MUX_MC));
	

	RegN #(128) REG_FINAL(
		.i_clk(i_clk), 
		.i_rst(i_rst), 
		.i_enable(sel_MUX_FINAL), 
		.i_d(s_REG_ARK), 
		.o_q(o_cipher_AES));
	
endmodule

//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 09/23/2024 04:41:04 PM
// Design Name: 
// Module Name: AddRoundKey
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////

(* dont_touch = "yes"*)
module AddRoundKey(
	input  [127:0] i_key,
	input  [127:0] i_state,
	output [127:0] o_state
	);
	
	assign o_state = i_key ^ i_state;
	
endmodule



//////////////////////////////////////////////////////////////////////////////////

(* dont_touch = "yes"*)
module AES_Controller(
	input i_clk,
	input i_rst,
	input i_enc,
	input i_mode,
	output reg o_sel_MUX_INV,
	output reg o_sel_MUX_ARK,
	output reg o_sel_MUX_MC,
	output reg o_sel_MUX_Final,
	output reg o_enable,
	output reg o_finish
	);
	
	// ----------------------------- internal wire and reg signals
	localparam [2:0]s_Idle	 	= 3'd0,
					s_Round_0	= 3'd1,
					s_Round_1_9	= 3'd2,
					s_Round_f	= 3'd3,
					s_Done		= 3'd4;
					
	reg [2:0] state;
	
	reg [3:0] counter;
	
	// -------------------------------------------- process_state_Machine
	always @(posedge i_clk)
	begin
		if (i_rst == 1'b1) begin
			state  	 <= s_Idle;
			o_finish <= 1'b0;
			o_enable <= 1'b0;
			counter <= 4'd0;
			o_sel_MUX_INV   <= 1'b0;
			o_sel_MUX_ARK   <= 1'b0;
			o_sel_MUX_MC    <= 1'b0;
			o_sel_MUX_Final <= 1'b0;			
		end else begin
			case(state)			
			//----------------------- s_Idle
			s_Idle:	
				begin
					o_finish <= o_finish;
					o_enable <= 1'b0;
					o_sel_MUX_INV   <= 1'b0;
					o_sel_MUX_ARK   <= 1'b0;
					o_sel_MUX_MC    <= 1'b0;
					o_sel_MUX_Final <= 1'b0;
						
					if (i_enc == 1'b1)
						state <= s_Round_0;
					else	
						state <= s_Idle;
				end
				
			//----------------------- s_Round_0
			s_Round_0:	
				begin
					o_finish <= 1'b0;
					o_enable <= 1'b1;
					o_sel_MUX_ARK   <= 1'b0;
					o_sel_MUX_MC    <= 1'b0;
					o_sel_MUX_Final <= 1'b0;
					
					state <= s_Round_1_9;
				end
				
			//----------------------- s_Round_1_9
			s_Round_1_9:	
				begin
					o_finish <= 1'b0;
					o_enable <= 1'b1;
					o_sel_MUX_INV   <= 1'b1 & i_mode;
					o_sel_MUX_ARK   <= 1'b1;
					o_sel_MUX_MC    <= 1'b0;
					o_sel_MUX_Final <= 1'b0;
					
					if(counter < 8) begin
						counter <= counter + 1;
						state <= s_Round_1_9;
					end else
						state <= s_Round_f;
				end
				
			//----------------------- s_Round_f
			s_Round_f:	
				begin				
					o_finish <= 1'b0;
					o_enable <= 1'b1;
					o_sel_MUX_INV   <= 1'b0;
					o_sel_MUX_ARK   <= 1'b1;
					o_sel_MUX_MC    <= 1'b1;
					o_sel_MUX_Final <= 1'b0;
						
					state <= s_Done;
				end
				
			//----------------------- s_Done
			s_Done:	
				begin
					o_finish <= 1'b1;
					o_enable <= 1'b1;
					o_sel_MUX_ARK   <= 1'b0;
					o_sel_MUX_MC    <= 1'b0;
					o_sel_MUX_Final <= 1'b1;		
						
					counter <= 0;
					state   <= s_Idle;
				end	
				
			default:
				begin
					state <= s_Idle;
				end
			endcase
		end
	end
	
endmodule


//////////////////////////////////////////////////////////////////////////////////

(* dont_touch = "yes"*)
module ExpandKey(
	input i_clk,
	input i_rst,
	input i_init,
	input i_mode,
	input sel_Round,
	input  [127:0] i_key,	// original key
	output [127:0] o_key	// round key for next rounds
	);
	
	// ----------------------------- internal wire and reg signals
	reg i_sel;
	wire i_enable;
	wire [7:0] i_rconst_pre, i_rconst, o_rconst;
	wire [127:0] i_roundKey_pre, i_roundKey, o_roundKey;
	reg [3:0] counter;
	reg [3:0] idn_Round;
	reg [127:0] roundKey0, roundKey1, roundKey2, roundKey3,
	            roundKey4, roundKey5, roundKey6, roundKey7,
	            roundKey8, roundKey9, roundKey10; 

	
	// --------------------------------------- process_counter_var
	always @(posedge i_clk or posedge i_rst)
	begin
		if (i_rst == 1'b1)
			counter <= 0;
		else begin
			if (counter == 0) begin
				if (i_init == 1'b0)
					counter <= 0;
	            else
					counter <= 1;
			end else begin
				if (counter < 11)
					counter <= counter + 1;
				else
					counter <= 0;
			end
		end
	end
	
	// --------------------------------------- process_idn_Round
	always @(posedge i_clk or posedge i_rst)
	begin
	   if (i_rst == 1'b1) begin
	       if (i_mode == 1'b0)
	           idn_Round <= 0;
	       else
	           idn_Round <= 10;
	   end else begin
	       if (i_mode == 1'b0) begin       // encryption
               if (i_init == 1'b1)
                   idn_Round <= 0;
               else if (sel_Round == 1'b1 && idn_Round < 10)
                         idn_Round <= idn_Round + 1;
           end else begin
               if (i_init == 1'b1)         // decryption
                     idn_Round <= 10;
               else if (sel_Round == 1'b1 && idn_Round > 0)
                     idn_Round <= idn_Round - 1;
           end
	   end
	end
	
	// --------------------------------------- process_sel_signal
	always @(posedge i_clk)
	begin
		if (counter == 0)
			i_sel <= 1'b0;
		else
			i_sel <= 1'b1;
	end
	
	// --------------------------------------- write RoundKey to MatrixKey
	always @(posedge i_clk)
	begin
	   case(counter)
//            4'd0:   roundKey10  <= i_roundKey_pre;
            4'd1:   roundKey0  <= i_roundKey_pre;
            4'd2:   roundKey1  <= i_roundKey_pre;
            4'd3:   roundKey2  <= i_roundKey_pre;
            4'd4:   roundKey3  <= i_roundKey_pre;
            4'd5:   roundKey4  <= i_roundKey_pre;
            4'd6:   roundKey5  <= i_roundKey_pre;
            4'd7:   roundKey6  <= i_roundKey_pre;
            4'd8:   roundKey7  <= i_roundKey_pre;
            4'd9:   roundKey8  <= i_roundKey_pre;
            4'd10:  roundKey9  <= i_roundKey_pre;
            4'd11:  roundKey10  <= i_roundKey_pre;
       endcase	
	end
	
	// ---------------------------------------	
	assign i_enable = i_init | i_sel;
	
	// --- MUX_RC, REG_RC and RoundConstants
	Mux2 #(8) MUX_RC(
		.i_a(8'h01), 
		.i_b(o_rconst), 
		.i_sel(i_sel), 
		.o_c(i_rconst_pre));
	
	RegN #(8) REG_RC(
		.i_clk(i_clk), 
		.i_rst(i_rst), 
		.i_enable(i_enable), 
		.i_d(i_rconst_pre), 
		.o_q(i_rconst));
	
	RoundConstants Round_Constants(
		.i_rconst(i_rconst), 
		.o_rconst(o_rconst)); 	
		
	// --- MUX_KS, REG_KS and KeySchedule 	
	Mux2 #(128) MUX_KS(
		.i_a(i_key), 
		.i_b(o_roundKey), 
		.i_sel(i_sel), 
		.o_c(i_roundKey_pre));
	
	RegN #(128) REG_KS(
		.i_clk(i_clk), 
		.i_rst(i_rst), 
		.i_enable(i_enable), 
		.i_d(i_roundKey_pre), 
		.o_q(i_roundKey));
		
	KeySchedule Key_Schedule(
		.i_roundKey(i_roundKey), 
		.i_rconst(i_rconst), 
		.o_roundKey(o_roundKey));
	
	MatrixKey Matrix_Key(
        .idn_Round(idn_Round),
        .roundKey0(roundKey0),
        .roundKey1(roundKey1),
        .roundKey2(roundKey2),
        .roundKey3(roundKey3),
        .roundKey4(roundKey4),
        .roundKey5(roundKey5),
        .roundKey6(roundKey6),
        .roundKey7(roundKey7),
        .roundKey8(roundKey8),
        .roundKey9(roundKey9),
        .roundKey10(roundKey10),
        .o_key(o_key));
        
	// --- output 
//	assign o_key = i_roundKey;
endmodule

//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module RoundConstants(
	input  [7:0] i_rconst,
	output [7:0] o_rconst
    );
	
	wire [7:0] r_shifted_state;
	wire [7:0] r_constant_xor;
	
	assign r_shifted_state = {i_rconst[6:0], 1'b0};
	assign r_constant_xor  = {3'b000, i_rconst[7], i_rconst[7], 1'b0, i_rconst[7], i_rconst[7]};
	assign o_rconst 	   = r_shifted_state ^ r_constant_xor;
	
endmodule


//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module KeySchedule(
	input  [127:0] i_roundKey,
	input  [7:0] i_rconst,
	output [127:0] o_roundKey
	);
	
	// -----------------------------------------------------
	wire [31:0] o_g;
	wire [31:0] i_w0, i_w1, i_w2, i_w3;
	wire [31:0] o_w0, o_w1, o_w2, o_w3;
	
	
	// -----------------------------------------------------
	assign i_w0 = i_roundKey[127:96];
	assign i_w1 = i_roundKey[ 95:64];
	assign i_w2 = i_roundKey[ 63:32];
	assign i_w3 = i_roundKey[ 31: 0];
	
	function_g U_function_g(
		.i_w(i_w3), .i_rconst(i_rconst), .o_w(o_g));
		
	assign o_w0 = i_w0 ^ o_g;
	assign o_w1 = i_w1 ^ o_w0;
	assign o_w2 = i_w2 ^ o_w1;
	assign o_w3 = i_w3 ^ o_w2;
	
	assign o_roundKey = {o_w0, o_w1, o_w2, o_w3};
	
endmodule


//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module function_g(
	input  [31:0] i_w,
	input  [7:0] i_rconst,
	output [31:0] o_w
	);
	
	wire [7:0] b0, b1, b2, b3;
	wire [31:0] subwords; 	// output after Sbox
	wire [31:0] rotwords;
	
	assign b0 = i_w[31:24];	
	assign b1 = i_w[23:16];
	assign b2 = i_w[15: 8];
	assign b3 = i_w[ 7: 0];
	
	assign rotwords = {b1, b2, b3, b0};
	
	S_box_single Sbox_func0( rotwords[ 7: 0], subwords[ 7: 0]);
	S_box_single Sbox_func1( rotwords[15: 8], subwords[15: 8]);
	S_box_single Sbox_func2( rotwords[23:16], subwords[23:16]);
	S_box_single Sbox_func3( rotwords[31:24], subwords[31:24]);
	
	assign o_w = {(subwords[31:24] ^ i_rconst), subwords[23:0]};
	
endmodule


//////////////////////////////////////////////////////////////////////////////////
(* dont_touch = "yes"*)
module MatrixKey(
    input [3:0]   idn_Round,
    input [127:0] roundKey0,
    input [127:0] roundKey1,
    input [127:0] roundKey2,
    input [127:0] roundKey3,
    input [127:0] roundKey4,
    input [127:0] roundKey5,
    input [127:0] roundKey6,
    input [127:0] roundKey7,
    input [127:0] roundKey8,
    input [127:0] roundKey9,
    input [127:0] roundKey10,
    output [127:0] o_key
    );
    
    assign o_key = (idn_Round[3]) ?
					   ( (idn_Round[1]) ?
							  (roundKey10):
							  ((idn_Round[0]) ? roundKey9 : roundKey8 )  ):
					   ( (idn_Round[2]) ?
							( (idn_Round[1]) ?
								( (idn_Round[0]) ? roundKey7 : roundKey6 ) :
								( (idn_Round[0]) ? roundKey5 : roundKey4 ) ) :
							( (idn_Round[1]) ?
									( (idn_Round[0]) ? roundKey3 : roundKey2 ) :
									( (idn_Round[0]) ? roundKey1 : roundKey0 ) ) );
endmodule

//////////////////////////////////////////////////////////////////////////////////
//
// in_state:  b9e447c5948e20d657169af575513f3b
// out_state: ab40f0c48b7ffce489f1184e35053f2f 
// 
//////////////////////////////////////////////////////////////////////////////////

(* dont_touch = "yes"*)
module InvMixColumns(
	input  [127:0] i_state,		// state input from ShiftRows
	output [127:0] o_state		// state output from MixColumns 
	);
	
	wire [31:0] i_w3, i_w2, i_w1, i_w0; //input words
	wire [31:0] o_w3, o_w2, o_w1, o_w0; //output words
	
	assign i_w3 = i_state[127: 96];
	assign i_w2 = i_state[ 95: 64];
	assign i_w1 = i_state[ 63: 32];
	assign i_w0 = i_state[ 31:  0];
	
	
	
	InvMixWord Inv_Mix_Word3(
	   .i_w(i_w3),
	   .o_w(o_w3));
	   
	InvMixWord Inv_Mix_Word2(
	   .i_w(i_w2),
	   .o_w(o_w2));	   

	InvMixWord Inv_Mix_Word1(
	   .i_w(i_w1),
	   .o_w(o_w1));

	InvMixWord Inv_Mix_Word0(
	   .i_w(i_w0),
	   .o_w(o_w0));
	   	   	   
	// state output
	assign o_state = {o_w3, o_w2, o_w1, o_w0};
	
endmodule

(* dont_touch = "yes"*)
module InvMixWord (
	input	[31:0]	i_w,
	output	[31:0]	o_w
    );
    
    assign o_w[31] = i_w[30] ^ i_w[29] ^ i_w[28] ^ i_w[23] ^ i_w[22] ^ i_w[20] ^ i_w[15] ^ i_w[13] ^ i_w[12] ^ i_w[ 7] ^ i_w[ 4];
    assign o_w[30] = i_w[31] ^ i_w[29] ^ i_w[28] ^ i_w[27] ^ i_w[23] ^ i_w[22] ^ i_w[21] ^ i_w[19] ^ i_w[15] ^ i_w[14] ^ i_w[12] ^ i_w[11] ^ i_w[ 7] ^ i_w[ 6] ^ i_w[3];
    assign o_w[29] = i_w[30] ^ i_w[28] ^ i_w[27] ^ i_w[26] ^ i_w[23] ^ i_w[22] ^ i_w[21] ^ i_w[20] ^ i_w[18] ^ i_w[14] ^ i_w[13] ^ i_w[11] ^ i_w[10] ^ i_w[ 7] ^ i_w[6] ^ i_w[5] ^ i_w[2];
    assign o_w[28] = i_w[29] ^ i_w[27] ^ i_w[26] ^ i_w[25] ^ i_w[23] ^ i_w[22] ^ i_w[21] ^ i_w[20] ^ i_w[19] ^ i_w[17] ^ i_w[15] ^ i_w[13] ^ i_w[12] ^ i_w[10] ^ i_w[9] ^ i_w[6] ^ i_w[5] ^ i_w[4] ^ i_w[1];
    assign o_w[27] = i_w[30] ^ i_w[29] ^ i_w[26] ^ i_w[25] ^ i_w[24] ^ i_w[21] ^ i_w[19] ^ i_w[18] ^ i_w[16] ^ i_w[15] ^ i_w[14] ^ i_w[13] ^ i_w[11] ^ i_w[ 9] ^ i_w[8] ^ i_w[7] ^ i_w[5] ^ i_w[3] ^ i_w[0];
    assign o_w[26] = i_w[30] ^ i_w[25] ^ i_w[24] ^ i_w[23] ^ i_w[22] ^ i_w[18] ^ i_w[17] ^ i_w[14] ^ i_w[10] ^ i_w[ 8] ^ i_w[ 7] ^ i_w[ 6] ^ i_w[ 2];
    assign o_w[25] = i_w[29] ^ i_w[24] ^ i_w[23] ^ i_w[22] ^ i_w[21] ^ i_w[17] ^ i_w[16] ^ i_w[15] ^ i_w[13] ^ i_w[ 9] ^ i_w[ 6] ^ i_w[ 5] ^ i_w[ 1];
    assign o_w[24] = i_w[31] ^ i_w[30] ^ i_w[29] ^ i_w[23] ^ i_w[21] ^ i_w[16] ^ i_w[14] ^ i_w[13] ^ i_w[ 8] ^ i_w[ 5] ^ i_w[ 0];
    assign o_w[23] = i_w[31] ^ i_w[28] ^ i_w[22] ^ i_w[21] ^ i_w[20] ^ i_w[15] ^ i_w[14] ^ i_w[12] ^ i_w[ 7] ^ i_w[ 5] ^ i_w[ 4];
    assign o_w[22] = i_w[31] ^ i_w[30] ^ i_w[27] ^ i_w[23] ^ i_w[21] ^ i_w[20] ^ i_w[19] ^ i_w[15] ^ i_w[14] ^ i_w[13] ^ i_w[11] ^ i_w[ 7] ^ i_w[ 6] ^ i_w[4] ^ i_w[3];
    assign o_w[21] = i_w[31] ^ i_w[30] ^ i_w[29] ^ i_w[26] ^ i_w[22] ^ i_w[20] ^ i_w[19] ^ i_w[18] ^ i_w[15] ^ i_w[14] ^ i_w[13] ^ i_w[12] ^ i_w[10] ^ i_w[6] ^ i_w[5] ^ i_w[3] ^ i_w[2];
    assign o_w[20] = i_w[30] ^ i_w[29] ^ i_w[28] ^ i_w[25] ^ i_w[21] ^ i_w[19] ^ i_w[18] ^ i_w[17] ^ i_w[15] ^ i_w[14] ^ i_w[13] ^ i_w[12] ^ i_w[11] ^ i_w[9] ^ i_w[7] ^ i_w[5] ^ i_w[4] ^ i_w[2] ^ i_w[1];
    assign o_w[19] = i_w[31] ^ i_w[29] ^ i_w[27] ^ i_w[24] ^ i_w[22] ^ i_w[21] ^ i_w[18] ^ i_w[17] ^ i_w[16] ^ i_w[13] ^ i_w[11] ^ i_w[10] ^ i_w[ 8] ^ i_w[7] ^ i_w[6] ^ i_w[5] ^ i_w[3] ^ i_w[1] ^ i_w[0];
    assign o_w[18] = i_w[31] ^ i_w[30] ^ i_w[26] ^ i_w[22] ^ i_w[17] ^ i_w[16] ^ i_w[15] ^ i_w[14] ^ i_w[10] ^ i_w[ 9] ^ i_w[ 6] ^ i_w[ 2] ^ i_w[ 0];
    assign o_w[17] = i_w[30] ^ i_w[29] ^ i_w[25] ^ i_w[21] ^ i_w[16] ^ i_w[15] ^ i_w[14] ^ i_w[13] ^ i_w[ 9] ^ i_w[ 8] ^ i_w[ 7] ^ i_w[ 5] ^ i_w[ 1];
    assign o_w[16] = i_w[29] ^ i_w[24] ^ i_w[23] ^ i_w[22] ^ i_w[21] ^ i_w[15] ^ i_w[13] ^ i_w[ 8] ^ i_w[ 6] ^ i_w[ 5] ^ i_w[ 0];
    assign o_w[15] = i_w[31] ^ i_w[29] ^ i_w[28] ^ i_w[23] ^ i_w[20] ^ i_w[14] ^ i_w[13] ^ i_w[12] ^ i_w[ 7] ^ i_w[ 6] ^ i_w[ 4];
    assign o_w[14] = i_w[31] ^ i_w[30] ^ i_w[28] ^ i_w[27] ^ i_w[23] ^ i_w[22] ^ i_w[19] ^ i_w[15] ^ i_w[13] ^ i_w[12] ^ i_w[11] ^ i_w[ 7] ^ i_w[ 6] ^ i_w[5] ^ i_w[3];
    assign o_w[13] = i_w[30] ^ i_w[29] ^ i_w[27] ^ i_w[26] ^ i_w[23] ^ i_w[22] ^ i_w[21] ^ i_w[18] ^ i_w[14] ^ i_w[12] ^ i_w[11] ^ i_w[10] ^ i_w[ 7] ^ i_w[6] ^ i_w[5] ^ i_w[4] ^ i_w[2];
    assign o_w[12] = i_w[31] ^ i_w[29] ^ i_w[28] ^ i_w[26] ^ i_w[25] ^ i_w[22] ^ i_w[21] ^ i_w[20] ^ i_w[17] ^ i_w[13] ^ i_w[11] ^ i_w[10] ^ i_w[ 9] ^ i_w[7] ^ i_w[6] ^ i_w[5] ^ i_w[4] ^ i_w[3] ^ i_w[1];
    assign o_w[11] = i_w[31] ^ i_w[30] ^ i_w[29] ^ i_w[27] ^ i_w[25] ^ i_w[24] ^ i_w[23] ^ i_w[21] ^ i_w[19] ^ i_w[16] ^ i_w[14] ^ i_w[13] ^ i_w[10] ^ i_w[9] ^ i_w[8] ^ i_w[5] ^ i_w[3] ^ i_w[2] ^ i_w[0];
    assign o_w[10] = i_w[30] ^ i_w[26] ^ i_w[24] ^ i_w[23] ^ i_w[22] ^ i_w[18] ^ i_w[14] ^ i_w[ 9] ^ i_w[ 8] ^ i_w[ 7] ^ i_w[ 6] ^ i_w[ 2] ^ i_w[1];
    assign o_w[9]  = i_w[31] ^ i_w[29] ^ i_w[25] ^ i_w[22] ^ i_w[21] ^ i_w[17] ^ i_w[13] ^ i_w[ 8] ^ i_w[ 7] ^ i_w[ 6] ^ i_w[ 5] ^ i_w[ 1] ^ i_w[0];
    assign o_w[8]  = i_w[30] ^ i_w[29] ^ i_w[24] ^ i_w[21] ^ i_w[16] ^ i_w[15] ^ i_w[14] ^ i_w[13] ^ i_w[ 7] ^ i_w[ 5] ^ i_w[ 0];
    assign o_w[7]  = i_w[31] ^ i_w[30] ^ i_w[28] ^ i_w[23] ^ i_w[21] ^ i_w[20] ^ i_w[15] ^ i_w[12] ^ i_w[ 6] ^ i_w[ 5] ^ i_w[ 4];
    assign o_w[6]  = i_w[31] ^ i_w[30] ^ i_w[29] ^ i_w[27] ^ i_w[23] ^ i_w[22] ^ i_w[20] ^ i_w[19] ^ i_w[15] ^ i_w[14] ^ i_w[11] ^ i_w[ 7] ^ i_w[ 5] ^ i_w[ 4] ^ i_w[3];
    assign o_w[5]  = i_w[31] ^ i_w[30] ^ i_w[29] ^ i_w[28] ^ i_w[26] ^ i_w[22] ^ i_w[21] ^ i_w[19] ^ i_w[18] ^ i_w[15] ^ i_w[14] ^ i_w[13] ^ i_w[10] ^ i_w[ 6] ^ i_w[4] ^ i_w[3] ^ i_w[2];
    assign o_w[4]  = i_w[31] ^ i_w[30] ^ i_w[29] ^ i_w[28] ^ i_w[27] ^ i_w[25] ^ i_w[23] ^ i_w[21] ^ i_w[20] ^ i_w[18] ^ i_w[17] ^ i_w[14] ^ i_w[13] ^ i_w[12] ^ i_w[9] ^ i_w[5] ^ i_w[3] ^ i_w[2] ^ i_w[1];
    assign o_w[3]  = i_w[29] ^ i_w[27] ^ i_w[26] ^ i_w[24] ^ i_w[23] ^ i_w[22] ^ i_w[21] ^ i_w[19] ^ i_w[17] ^ i_w[16] ^ i_w[15] ^ i_w[13] ^ i_w[11] ^ i_w[ 8] ^ i_w[6] ^ i_w[5] ^ i_w[2] ^ i_w[1] ^ i_w[0];
    assign o_w[2]  = i_w[31] ^ i_w[30] ^ i_w[26] ^ i_w[25] ^ i_w[22] ^ i_w[18] ^ i_w[16] ^ i_w[15] ^ i_w[14] ^ i_w[10] ^ i_w[ 6] ^ i_w[1] ^ i_w[0];
    assign o_w[1]  = i_w[31] ^ i_w[30] ^ i_w[29] ^ i_w[25] ^ i_w[24] ^ i_w[23] ^ i_w[21] ^ i_w[17] ^ i_w[14] ^ i_w[13] ^ i_w[ 9] ^ i_w[ 5] ^ i_w[0];
    assign o_w[0]  = i_w[31] ^ i_w[29] ^ i_w[24] ^ i_w[22] ^ i_w[21] ^ i_w[16] ^ i_w[13] ^ i_w[ 8] ^ i_w[ 7] ^ i_w[ 6] ^ i_w[ 5];
    
endmodule


//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 09/23/2024 04:39:45 PM
// Design Name: 
// Module Name: InvShiftRows
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// -- The first row of State is not altered.
// -- For the second row, a 1-byte circular right shift is performed.
// -- For the third row, a 2-byte circular right shift is performed.
// -- For the fourth row, a 3-byte circular right shift is performed

// in_state:	ab40f0c48b7ffce489f1184e35053f2f
// out_state:   ab0518e48b403f4e897ff02f35f1fcc4 
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


(* dont_touch = "yes"*)
module InvShiftRows(
	input  [127:0] i_state,
	output [127:0] o_state
	);
	
	wire [7:0] s00, s01, s02, s03;
	wire [7:0] s10, s11, s12, s13;
	wire [7:0] s20, s21, s22, s23;
	wire [7:0] s30, s31, s32, s33;
	
	// row 1
	assign s00 = i_state[127:120];
	assign s01 = i_state[ 95: 88];
	assign s02 = i_state[ 63: 56];
	assign s03 = i_state[ 31: 24];
	
	// row 2
	assign s11 = i_state[119:112];
	assign s12 = i_state[ 87: 80];
	assign s13 = i_state[ 55: 48];
	assign s10 = i_state[ 23: 16];
	
	// row 3	
	assign s22 = i_state[111:104];
	assign s23 = i_state[ 79: 72];
	assign s20 = i_state[ 47: 40];
	assign s21 = i_state[ 15:  8]; 
	
	// row 4
	assign s33 = i_state[103:96];
	assign s30 = i_state[ 71:64];
	assign s31 = i_state[ 39:32]; 
	assign s32 = i_state[  7: 0];
	
	// InvShiftRows output
	assign o_state = {s00, s10, s20, s30,
					  s01, s11, s21, s31,
					  s02, s12, s22, s32,
					  s03, s13, s23, s33}; 
	
endmodule


//////////////////////////////////////////////////////////////////////////////////
//
// in_state:   ab40f0c48b7ffce489f1184e35053f2f 
// out_state:  b9e447c5948e20d657169af575513f3b
// 
//////////////////////////////////////////////////////////////////////////////////


(* dont_touch = "yes"*)
module MixColumns(
	input  [127:0] i_state,		// state input from ShiftRows
	output [127:0] o_state		// state output from MixColumns 
	);
	
	wire [7:0] a00, a01, a02, a03; //input four-byte row 1
	wire [7:0] a10, a11, a12, a13; //input four-byte row 2
	wire [7:0] a20, a21, a22, a23; //input four-byte row 3
	wire [7:0] a30, a31, a32, a33; //input four-byte row 4
	
	wire [7:0] b00, b01, b02, b03; //output four-byte row 1
	wire [7:0] b10, b11, b12, b13; //output four-byte row 2
	wire [7:0] b20, b21, b22, b23; //output four-byte row 3
	wire [7:0] b30, b31, b32, b33; //output four-byte row 4
	
	//row 1
	assign a00 = i_state[127:120];
	assign a10 = i_state[119:112];
	assign a20 = i_state[111:104];
	assign a30 = i_state[103: 96];
	
	//row 2
	assign a01 = i_state[95:88]; 
	assign a11 = i_state[87:80]; 
	assign a21 = i_state[79:72];
	assign a31 = i_state[71:64];
	
	//row 3
	assign a02 = i_state[63:56];
	assign a12 = i_state[55:48]; 
	assign a22 = i_state[47:40];
	assign a32 = i_state[39:32];
	
	//row 4
	assign a03 = i_state[31:24];
	assign a13 = i_state[23:16]; 
	assign a23 = i_state[15: 8];
	assign a33 = i_state[ 7: 0];
	
	// output column 1
	assign b00 = ((a00[7] ^ a10[7])==1'b1)	
				? ({a00[6:0], 1'b0} ^ {a10[6:0], 1'b0} ^ a10 ^ a20 ^ a30 ^ 8'h1b)
				: ({a00[6:0], 1'b0} ^ {a10[6:0], 1'b0} ^ a10 ^ a20 ^ a30);
	assign b10 = ((a10[7] ^ a20[7])==1'b1)	
				? ({a10[6:0], 1'b0} ^ {a20[6:0], 1'b0} ^ a20 ^ a30 ^ a00 ^ 8'h1b)
				: ({a10[6:0], 1'b0} ^ {a20[6:0], 1'b0} ^ a20 ^ a30 ^ a00);
	assign b20 = ((a20[7] ^ a30[7])==1'b1)	
				? ({a20[6:0], 1'b0} ^ {a30[6:0], 1'b0} ^ a30 ^ a00 ^ a10 ^ 8'h1b)
				: ({a20[6:0], 1'b0} ^ {a30[6:0], 1'b0} ^ a30 ^ a00 ^ a10);
	assign b30 = ((a30[7] ^ a00[7])==1'b1)	
				? ({a30[6:0], 1'b0} ^ {a00[6:0], 1'b0} ^ a00 ^ a10 ^ a20 ^ 8'h1b)
				: ({a30[6:0], 1'b0} ^ {a00[6:0], 1'b0} ^ a00 ^ a10 ^ a20);
	
	// output column 2
	assign b01 = ((a01[7] ^ a11[7])==1'b1)	
				? ({a01[6:0], 1'b0} ^ {a11[6:0], 1'b0} ^ a11 ^ a21 ^ a31 ^ 8'h1b)
				: ({a01[6:0], 1'b0} ^ {a11[6:0], 1'b0} ^ a11 ^ a21 ^ a31);
	assign b11 = ((a11[7] ^ a21[7])==1'b1)
				? ({a11[6:0], 1'b0} ^ {a21[6:0], 1'b0} ^ a21 ^ a31 ^ a01 ^ 8'h1b)
				: ({a11[6:0], 1'b0} ^ {a21[6:0], 1'b0} ^ a21 ^ a31 ^ a01);
	assign b21 = ((a21[7] ^ a31[7])==1'b1)	
				? ({a21[6:0], 1'b0} ^ {a31[6:0], 1'b0} ^ a31 ^ a01 ^ a11 ^ 8'h1b) 
				: ({a21[6:0], 1'b0} ^ {a31[6:0], 1'b0} ^ a31 ^ a01 ^ a11);
	assign b31 = ((a31[7] ^ a01[7])==1'b1)	
				? ({a31[6:0], 1'b0} ^ {a01[6:0], 1'b0} ^ a01 ^ a11 ^ a21 ^ 8'h1b)
				: ({a31[6:0], 1'b0} ^ {a01[6:0], 1'b0} ^ a01 ^ a11 ^ a21);
	
	// output column 3
	assign b02 = ((a02[7] ^ a12[7])==1'b1)	
				? ({a02[6:0], 1'b0} ^ {a12[6:0], 1'b0} ^ a12 ^ a22 ^ a32 ^ 8'h1b) 
				: ({a02[6:0], 1'b0} ^ {a12[6:0], 1'b0} ^ a12 ^ a22 ^ a32);
	assign b12 = ((a12[7] ^ a22[7])==1'b1)
				? ({a12[6:0], 1'b0} ^ {a22[6:0], 1'b0} ^ a22 ^ a32 ^ a02 ^ 8'h1b)
				: ({a12[6:0], 1'b0} ^ {a22[6:0], 1'b0} ^ a22 ^ a32 ^ a02);
	assign b22 = ((a22[7] ^ a32[7])==1'b1)	
				? ({a22[6:0], 1'b0} ^ {a32[6:0], 1'b0} ^ a32 ^ a02 ^ a12 ^ 8'h1b)
				: ({a22[6:0], 1'b0} ^ {a32[6:0], 1'b0} ^ a32 ^ a02 ^ a12);
	assign b32 = ((a32[7] ^ a02[7])==1'b1)
				? ({a32[6:0], 1'b0} ^ {a02[6:0], 1'b0} ^ a02 ^ a12 ^ a22 ^ 8'h1b)
				: ({a32[6:0], 1'b0} ^ {a02[6:0], 1'b0} ^ a02 ^ a12 ^ a22);
	
	// output column 4
	assign b03 = ((a03[7] ^ a13[7])==1'b1)
				? ({a03[6:0], 1'b0} ^ {a13[6:0], 1'b0} ^ a13 ^ a23 ^ a33 ^ 8'h1b)
				: ({a03[6:0], 1'b0} ^ {a13[6:0], 1'b0} ^ a13 ^ a23 ^ a33);
	assign b13 = ((a13[7] ^ a23[7])==1'b1)	
				? ({a13[6:0], 1'b0} ^ {a23[6:0], 1'b0} ^ a23 ^ a33 ^ a03 ^ 8'h1b) 
				: ({a13[6:0], 1'b0} ^ {a23[6:0], 1'b0} ^ a23 ^ a33 ^ a03);
	assign b23 = ((a23[7] ^ a33[7])==1'b1)
				? ({a23[6:0], 1'b0} ^ {a33[6:0], 1'b0} ^ a33 ^ a03 ^ a13 ^ 8'h1b) 
				: ({a23[6:0], 1'b0} ^ {a33[6:0], 1'b0} ^ a33 ^ a03 ^ a13);
	assign b33 = ((a33[7] ^ a03[7])==1'b1)
				? ({a33[6:0], 1'b0} ^ {a03[6:0], 1'b0} ^ a03 ^ a13 ^ a23 ^ 8'h1b)
				: ({a33[6:0], 1'b0} ^ {a03[6:0], 1'b0} ^ a03 ^ a13 ^ a23);

	// state output
	assign o_state = {b00, b10, b20, b30,
					   b01, b11, b21, b31,
					   b02, b12, b22, b32,
					   b03, b13, b23, b33};
	
endmodule

//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 09/23/2024 04:38:10 PM
// Design Name: 
// Module Name: Mux2
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module Mux2#
	(
		parameter N_width = 8
	)(
		input [N_width-1:0] i_a,
		input [N_width-1:0] i_b,
		input i_sel,
		output [N_width-1:0] o_c
	);
	
	assign o_c = (i_sel == 1'b0) ? i_a : i_b;
endmodule


//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 09/23/2024 04:37:47 PM
// Design Name: 
// Module Name: RegN
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module RegN#
	(
		parameter N_width = 8
	)(
		input i_clk,
		input i_rst,
		input i_enable,
		input [N_width-1:0] i_d,
		output reg [N_width-1:0] o_q
	);
	
	// --------------------------------------- process_register
	always @(posedge i_clk or posedge i_rst)
	begin
		if (i_rst == 1'b1)
			o_q <= 0;
		else if (i_enable == 1'b1)
			o_q <= i_d;
	end
endmodule


//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 09/23/2024 04:32:52 PM
// Design Name: 
// Module Name: S_box_affine_inv
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////

(* dont_touch = "yes"*)
module S_box_affine_inv(
	input  [7:0] i_a,
	output [7:0] o_b
	);
	
	assign o_b[7] = i_a[6] ^ i_a[4] ^ i_a[1] ^ 1'b0;
	assign o_b[6] = i_a[5] ^ i_a[3] ^ i_a[0] ^ 1'b0;
	assign o_b[5] = i_a[7] ^ i_a[4] ^ i_a[2] ^ 1'b0;
	assign o_b[4] = i_a[6] ^ i_a[3] ^ i_a[1] ^ 1'b0;
	assign o_b[3] = i_a[5] ^ i_a[2] ^ i_a[0] ^ 1'b0;
	assign o_b[2] = i_a[7] ^ i_a[4] ^ i_a[1] ^ 1'b1;
	assign o_b[1] = i_a[6] ^ i_a[3] ^ i_a[0] ^ 1'b0;
	assign o_b[0] = i_a[7] ^ i_a[5] ^ i_a[2] ^ 1'b1;
	
endmodule

//////////////////////////////////////////////////////////////////////////////////

(* dont_touch = "yes"*)
module S_box_affine(
	input  [7:0] i_a,
	output [7:0] o_b
	);
	
	assign o_b[7] = i_a[7] ^ i_a[6] ^ i_a[5] ^ i_a[4] ^ i_a[3] ^ 1'b0;
	assign o_b[6] = i_a[6] ^ i_a[5] ^ i_a[4] ^ i_a[3] ^ i_a[2] ^ 1'b1;
	assign o_b[5] = i_a[5] ^ i_a[4] ^ i_a[3] ^ i_a[2] ^ i_a[1] ^ 1'b1;
	assign o_b[4] = i_a[4] ^ i_a[3] ^ i_a[2] ^ i_a[1] ^ i_a[0] ^ 1'b0;
	assign o_b[3] = i_a[7] ^ i_a[3] ^ i_a[2] ^ i_a[1] ^ i_a[0] ^ 1'b0;
	assign o_b[2] = i_a[7] ^ i_a[6] ^ i_a[2] ^ i_a[1] ^ i_a[0] ^ 1'b0;
	assign o_b[1] = i_a[7] ^ i_a[6] ^ i_a[5] ^ i_a[1] ^ i_a[0] ^ 1'b1;
	assign o_b[0] = i_a[7] ^ i_a[6] ^ i_a[5] ^ i_a[4] ^ i_a[0] ^ 1'b1;
	
endmodule


//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 09/23/2024 04:35:56 PM
// Design Name: 
// Module Name: S_box_dual
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////

(* dont_touch = "yes"*)
module S_box_dual(
	input  i_mode,
	input  [7:0] i_a,
	output [7:0] o_b
	);
	
	(* dont_touch = "yes"*) wire [7:0] s_inv;
	
		
	(* dont_touch = "yes"*) wire [7:0] s_aff, s_aff_inv;

	(* dont_touch = "yes"*) wire [7:0] si_inv, so_inv;
	
	// ----------------------------------------
	S_box_affine_inv In_S_box_dynamic_affine_inv(
		.i_a(i_a),
		.o_b(s_aff_inv));	
			
	Mux2 #(8) MUX_IN(
		.i_a(i_a),
		.i_b(s_aff_inv),
		.i_sel(i_mode),
		.o_c(si_inv));
		
	// ----------------------------------- Inversion	
	S_box_GF28_inv U_S_box_GF28_inv(
		.i_a(si_inv),
		.o_b(so_inv));
		
	// ----------------------------------------	
	
	S_box_affine Out_S_box_dynamic_affine(
		.i_a(so_inv),
		.o_b(s_aff));
			
	Mux2 #(8) MUX_OUT(
		.i_a(s_aff),
		.i_b(so_inv),
		.i_sel(i_mode),
		.o_c(o_b));
	
endmodule


//////////////////////////////////////////////////////////////////////////////////

(* dont_touch = "yes"*)
module S_box_GF28_inv(
	input  [7:0] i_a,
	output [7:0] o_b
	);
	
	(* dont_touch = "yes"*) wire [7:0] s_isomorphic, s_isomorphic_inv;
	(* dont_touch = "yes"*) wire [3:0] i_GF24_mult, i_GF24_inv;
	(* dont_touch = "yes"*) wire [3:0] o_mult_0_k, o_mult_1_k, o_mult_2_k, o_mult_3_k;
	
	assign i_GF24_mult = s_isomorphic[7:4] ^ s_isomorphic[3:0];
	assign i_GF24_inv  = o_mult_1_k ^ o_mult_2_k;
	
	S_box_isomorphic U_S_box_isomorphic(
		.i_a(i_a), .o_b(s_isomorphic));
		
	S_box_GF24_square U0_GF24_square(
		.i_a(s_isomorphic[7:4]), .o_k(o_mult_0_k));
		
	S_box_GF24_mult_lambda U1_GF24_mult_lambda(
		.i_a(o_mult_0_k), .o_k(o_mult_1_k));
		
	S_box_GF24_mult U2_GF24_mult(
		.i_a(i_GF24_mult), .i_b(s_isomorphic[3:0]), .o_k(o_mult_2_k));
		
	S_box_GF24_inv U3_GF24_inv(
		.i_a(i_GF24_inv), .o_k(o_mult_3_k));
		
	S_box_GF24_mult U4_GF24_mult(
		.i_a(s_isomorphic[7:4]), .i_b(o_mult_3_k), .o_k(s_isomorphic_inv[7:4]));
		
	S_box_GF24_mult U5_GF24_mult(
		.i_a(i_GF24_mult), .i_b(o_mult_3_k), .o_k(s_isomorphic_inv[3:0]));
		
	S_box_isomorphic_inv U_S_box_isomorphic_inv(
		.i_a(s_isomorphic_inv), .o_b(o_b));
	
endmodule

// ---------------------------------------- S_box_isomorphic
(* dont_touch = "yes"*)
module S_box_isomorphic(
	input  [7:0] i_a,
	output [7:0] o_b
	);
	
	assign o_b[7] = i_a[7] ^ i_a[5];
	assign o_b[6] = i_a[7] ^ i_a[6] ^ i_a[4] ^ i_a[3] ^ i_a[2] ^ i_a[1];
	assign o_b[5] = i_a[7] ^ i_a[5] ^ i_a[3] ^ i_a[2];
	assign o_b[4] = i_a[7] ^ i_a[5] ^ i_a[3] ^ i_a[2] ^ i_a[1];
	assign o_b[3] = i_a[7] ^ i_a[6] ^ i_a[2] ^ i_a[1];
	assign o_b[2] = i_a[7] ^ i_a[4] ^ i_a[3] ^ i_a[2] ^ i_a[1];
	assign o_b[1] = i_a[6] ^ i_a[4] ^ i_a[1];
	assign o_b[0] = i_a[6] ^ i_a[1] ^ i_a[0];
	
endmodule


// ---------------------------------------- S_box_GF24_square
(* dont_touch = "yes"*)
module S_box_GF24_square(
	input  [3:0] i_a,
	output [3:0] o_k
    );
	
	assign o_k[3] = i_a[3];
	assign o_k[2] = i_a[3] ^ i_a[2];	
	assign o_k[1] = i_a[2] ^ i_a[1];	
	assign o_k[0] = i_a[3] ^ i_a[1] ^ i_a[0];
	
endmodule


// ---------------------------------------- S_box_GF24_mult_lambda
(* dont_touch = "yes"*)
module S_box_GF24_mult_lambda(
	input  [3:0] i_a,
	output [3:0] o_k
	);
	
	assign o_k[3] = i_a[2] ^ i_a[0];
	assign o_k[2] = i_a[3] ^ i_a[2] ^ i_a[1] ^ i_a[0];
	assign o_k[1] = i_a[3];
	assign o_k[0] = i_a[2];
	
endmodule


// ---------------------------------------- S_box_GF24_mult
(* dont_touch = "yes"*)
module S_box_GF24_mult(
	input  [3:0] i_a,
	input  [3:0] i_b,
	output [3:0] o_k
	);
	
	(* dont_touch = "yes"*) wire [1:0] i_a_mult, i_b_mult;
	(* dont_touch = "yes"*) wire [1:0] o_mult_0_k, o_mult_1_k, o_mult_2_k, o_mult_3_k;
	
	assign i_a_mult[1] = i_a[3] ^ i_a[1];
	assign i_a_mult[0] = i_a[2] ^ i_a[0];
	assign i_b_mult[1] = i_b[3] ^ i_b[1];
	assign i_b_mult[0] = i_b[2] ^ i_b[0];
	
	S_box_GF22_mult U0_GF22_mult(
		.i_a(i_a[3:2]), .i_b(i_b[3:2]), .o_k(o_mult_0_k));
	
	S_box_GF22_mult_phi U1_GF22_mult_phi(
		.i_a(o_mult_0_k), .o_k(o_mult_1_k));
	
	S_box_GF22_mult U2_GF22_mult(
		.i_a(i_a_mult), .i_b(i_b_mult), .o_k(o_mult_2_k));
		
	S_box_GF22_mult U3_GF22_mult(
		.i_a(i_a[1:0]), .i_b(i_b[1:0]), .o_k(o_mult_3_k));
		
	assign o_k[3] = o_mult_3_k[1] ^ o_mult_2_k[1];
	assign o_k[2] = o_mult_3_k[0] ^ o_mult_2_k[0];
	assign o_k[1] = o_mult_3_k[1] ^ o_mult_1_k[1];
	assign o_k[0] = o_mult_3_k[0] ^ o_mult_1_k[0];
	
endmodule

// ---------------------------------------- S_box_GF24_inv
(* dont_touch = "yes"*)
module S_box_GF24_inv(
	input  [3:0] i_a,
	output [3:0] o_k
	);
	
	(* dont_touch = "yes"*) wire [1:0] i_a_mult, i_a_inv;
	(* dont_touch = "yes"*) wire [1:0] o_mult_0_k, o_mult_1_k, o_mult_2_k, o_mult_3_k, o_mult_4_k, o_mult_5_k;
	
	assign i_a_mult = i_a[3:2] ^ i_a[1:0];
	assign i_a_inv  = o_mult_1_k ^ o_mult_2_k;
	
	S_box_GF22_square U0_GF22_square(
		.i_a(i_a[3:2]), .o_k(o_mult_0_k));
		
	S_box_GF22_mult_phi U1_GF22_mult_phi(
		.i_a(o_mult_0_k), .o_k(o_mult_1_k));
	
	S_box_GF22_mult U2_GF22_mult(
		.i_a(i_a_mult), .i_b(i_a[1:0]), .o_k(o_mult_2_k));
		
	S_box_GF22_square U3_GF22_inv(
		.i_a(i_a_inv), .o_k(o_mult_3_k));
	
	S_box_GF22_mult U4_GF22_mult(
		.i_a(i_a[3:2]), .i_b(o_mult_3_k), .o_k(o_mult_4_k));
		
	S_box_GF22_mult U5_GF22_mult(
		.i_a(i_a_mult), .i_b(o_mult_3_k), .o_k(o_mult_5_k));
		
	assign o_k[3:2] = o_mult_4_k;
	assign o_k[1:0] = o_mult_5_k;
	
endmodule

// ---------------------------------------- S_box_GF22_square
(* dont_touch = "yes"*)
module S_box_GF22_square(
	input  [1:0] i_a,
	output [1:0] o_k
    );
	
	assign o_k[1] = i_a[1];
	assign o_k[0] = i_a[1] ^ i_a[0];
endmodule

// ---------------------------------------- S_box_GF22_mult
(* dont_touch = "yes"*)
module S_box_GF22_mult(
	input  [1:0] i_a,
	input  [1:0] i_b,
	output [1:0] o_k
	);
    
   assign o_k[1] = (i_a[1] & i_b[1]) ^ (i_a[1] & i_b[0]) ^ (i_a[0] & i_b[1]);
   assign o_k[0] = (i_a[1] & i_b[1]) ^ (i_a[0] & i_b[0]);
   
endmodule

// ---------------------------------------- S_box_GF22_mult_phi
(* dont_touch = "yes"*)
module S_box_GF22_mult_phi(
	input  [1:0] i_a,
	output [1:0] o_k
	);
	
	assign o_k[1] = i_a[1] ^ i_a[0];
	assign o_k[0] = i_a[1];
endmodule

// ---------------------------------------- S_box_isomorphic_inv
(* dont_touch = "yes"*)
module S_box_isomorphic_inv(
	input  [7:0] i_a,
	output [7:0] o_b
	);
	
	assign o_b[7] = i_a[7] ^ i_a[6] ^ i_a[5] ^ i_a[1];
	assign o_b[6] = i_a[6] ^ i_a[2];
	assign o_b[5] = i_a[6] ^ i_a[5] ^ i_a[1];
	assign o_b[4] = i_a[6] ^ i_a[5] ^ i_a[4] ^ i_a[2] ^ i_a[1];
	assign o_b[3] = i_a[5] ^ i_a[4] ^ i_a[3] ^ i_a[2] ^ i_a[1];
	assign o_b[2] = i_a[7] ^ i_a[4] ^ i_a[3] ^ i_a[2] ^ i_a[1];
	assign o_b[1] = i_a[5] ^ i_a[4];
	assign o_b[0] = i_a[6] ^ i_a[5] ^ i_a[4] ^ i_a[2] ^ i_a[0];
	
endmodule


//////////////////////////////////////////////////////////////////////////////////

(* dont_touch = "yes"*)
module S_box_single(
	input  [7:0] i_a,
	output [7:0] o_b
	);
	
	(* dont_touch = "yes"*) wire [7:0] s_inv;
	
	S_box_GF28_inv U0_S_box_GF28_inv(
		.i_a(i_a), .o_b(s_inv));
		
	S_box_affine U1_S_box_affine(
		.i_a(s_inv), .o_b(o_b));
	
endmodule


//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 09/23/2024 04:46:47 PM
// Design Name: 
// Module Name: ShiftRows
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// -- The first row of State is not altered.
// -- For the second row, a 1-byte circular left shift is performed.
// -- For the third row, a 2-byte circular left shift is performed.
// -- For the fourth row, a 3-byte circular left shift is performed

// in_state:	ab0518e48b403f4e897ff02f35f1fcc4 
// out_state:   ab40f0c48b7ffce489f1184e35053f2f
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


(* dont_touch = "yes"*)
module ShiftRows(
	input  [127:0] i_state,
	output [127:0] o_state
	);
	
	wire [7:0] s00, s01, s02, s03;
	wire [7:0] s10, s11, s12, s13;
	wire [7:0] s20, s21, s22, s23;
	wire [7:0] s30, s31, s32, s33;
	
	// row 1
	assign s00 = i_state[127:120];
	assign s01 = i_state[ 95: 88];
	assign s02 = i_state[ 63: 56];
	assign s03 = i_state[ 31: 24];
	
	// row 2
	assign s13 = i_state[119:112];
	assign s10 = i_state[ 87: 80];
	assign s11 = i_state[ 55: 48];
	assign s12 = i_state[ 23: 16];
	
	// row 3	
	assign s22 = i_state[111:104];
	assign s23 = i_state[ 79: 72];
	assign s20 = i_state[ 47: 40];
	assign s21 = i_state[ 15:  8]; 
	
	// row 4
	assign s31 = i_state[103:96];
	assign s32 = i_state[ 71:64];
	assign s33 = i_state[ 39:32]; 
	assign s30 = i_state[  7: 0];
	
	// ShiftRows output
	assign o_state = {s00, s10, s20, s30,
					  s01, s11, s21, s31,
					  s02, s12, s22, s32,
					  s03, s13, s23, s33}; 
	
endmodule

//////////////////////////////////////////////////////////////////////////////////

(* dont_touch = "yes"*)
module SubBytesDual(
    input  i_mode,
	input  [127:0] i_state,
	output [127:0] o_state
    );
	
	S_box_dual Sbox0(i_mode, i_state[ 7: 0], o_state[ 7: 0]);
	S_box_dual Sbox1(i_mode, i_state[15: 8], o_state[15: 8]);
	S_box_dual Sbox2(i_mode, i_state[23:16], o_state[23:16]);
	S_box_dual Sbox3(i_mode, i_state[31:24], o_state[31:24]);
	S_box_dual Sbox4(i_mode, i_state[39:32], o_state[39:32]);
	S_box_dual Sbox5(i_mode, i_state[47:40], o_state[47:40]);
	S_box_dual Sbox6(i_mode, i_state[55:48], o_state[55:48]);
	S_box_dual Sbox7(i_mode, i_state[63:56], o_state[63:56]);
	S_box_dual Sbox8(i_mode, i_state[71:64], o_state[71:64]);
	S_box_dual Sbox9(i_mode, i_state[79:72], o_state[79:72]);
	S_box_dual SboxA(i_mode, i_state[87:80], o_state[87:80]);
	S_box_dual SboxB(i_mode, i_state[95:88], o_state[95:88]);
	
	S_box_dual SboxC(i_mode, i_state[103: 96], o_state[103: 96]);
	S_box_dual SboxD(i_mode, i_state[111:104], o_state[111:104]);
	S_box_dual SboxE(i_mode, i_state[119:112], o_state[119:112]);
	S_box_dual SboxF(i_mode, i_state[127:120], o_state[127:120]);

	
endmodule


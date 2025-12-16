`define WT_DCACHE
`define DISABLE_TRACER
`define SRAM_NO_INIT
`define VERILATOR
//======================================================================
//
// aes_core.v
// ----------
// The AES core. This core supports key size of 128, and 256 bits.
// Most of the functionality is within the submodules.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2013, 2014, Secworks Sweden AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module aes_corev2(
	input			iClk,
	input			iRstn,
	
	input			iInit,
	input			iNext,
	output			oReady,
	
	input	[255:0]	iKey,
	input			iKeylen,
	
	input	[127:0]	iBlock,
	output	[127:0]	oResult,
	output			oResult_valid
);
 
 //----------------------------------------------------------------
 // Registers including update variables and write enable.
 //----------------------------------------------------------------
 reg	[1:0]	aes_core_ctrl_reg;
 wire	[1:0]	aes_core_ctrl_new;
 wire			aes_core_ctrl_we;

 reg			result_valid_reg;
 wire			result_valid_new;
 wire			result_valid_we;

 reg			ready_reg;
 wire			ready_new;
 wire			ready_we;

 //----------------------------------------------------------------
 // Wires.
 //----------------------------------------------------------------
 wire			State0, State1, State2;
 wire			init_state;

 wire	[127:0]	round_key;
 wire			key_ready;

 wire			enc_next;
 wire	[3:0]	enc_round_nr;
 wire	[127:0]	enc_new_block;
 wire			enc_ready;
 wire	[31:0]	enc_sboxw;

 wire			dec_next;
 wire	[3:0]	dec_round_nr;
 wire	[127:0]	dec_new_block;
 wire			dec_ready;

 wire	[127:0]	muxed_new_block;
 wire	[3:0]	muxed_round_nr;
 wire			muxed_ready;

 wire	[31:0]	keymem_sboxw;

 wire	[31:0]	muxed_sboxw;
 wire	[31:0]	new_sboxw;
 
 assign State0 = ~aes_core_ctrl_reg[1] & ~aes_core_ctrl_reg[0];
 assign State1 = ~aes_core_ctrl_reg[1] &  aes_core_ctrl_reg[0];
 assign State2 =  aes_core_ctrl_reg[1] & ~aes_core_ctrl_reg[0];

 //----------------------------------------------------------------
 // Instantiations.
 //----------------------------------------------------------------
 aes_encipher_blockv2 enc_block(
	.iClk		(iClk),
	.iRstn		(iRstn),
	
	.iNext		(enc_next),
	
	.iKeylen	(iKeylen),
	.oRound		(enc_round_nr),
	.iRound_key	(round_key),
	
	.oSboxw		(enc_sboxw),
	.iNew_sboxw	(new_sboxw),
	
	.iBlock		(iBlock),
	.oNew_block	(enc_new_block),
	.oReady		(enc_ready)
 );

//  aes_decipher_block dec_block(
// 	.iClk		(iClk),
// 	.iRstn		(iRstn),
	
// 	.iNext		(dec_next),
	
// 	.iKeylen	(iKeylen),
// 	.oRound		(dec_round_nr),
// 	.iRound_key	(round_key),
	
// 	.iBlock		(iBlock),
// 	.oNew_block	(dec_new_block),
// 	.oReady		(dec_ready)
//  );

 aes_key_memv2 keymem(
	.iClk		(iClk),
	.iRstn		(iRstn),
	
	.iKey		(iKey),
	.iKeylen	(iKeylen),
	.iInit		(iInit),
	
	.iRound		(muxed_round_nr),
	.oRound_key	(round_key),
	.oReady		(key_ready),
	
	.oSboxw		(keymem_sboxw),
	.iNew_sboxw	(new_sboxw)
 );

 aes_sboxv2 sbox_inst(
	.in		(muxed_sboxw),
	.out	(new_sboxw)
 );

 //----------------------------------------------------------------
 // Concurrent connectivity for ports etc.
 //----------------------------------------------------------------
 assign oReady        = ready_reg;
 assign oResult       = muxed_new_block;
 assign oResult_valid = result_valid_reg;

 //----------------------------------------------------------------
 // reg_update
 //
 // Update functionality for all registers in the core.
 // All registers are positive edge triggered with asynchronous
 // active low reset. All registers have write enable.
 //----------------------------------------------------------------
 always@(posedge iClk) begin
	if(~iRstn)					result_valid_reg  <= 1'b0;
	else if(result_valid_we)	result_valid_reg <= result_valid_new;
	else						result_valid_reg <= result_valid_reg;
 end

 always@(posedge iClk) begin
	if(~iRstn) 			ready_reg <= 1'b1;
	else if(ready_we)	ready_reg <= ready_new;
	else				ready_reg <= ready_reg;
 end
 
 always@(posedge iClk) begin
	if(~iRstn)					aes_core_ctrl_reg <= 2'd0;
	else if(aes_core_ctrl_we)	aes_core_ctrl_reg <= aes_core_ctrl_new;
	else						aes_core_ctrl_reg <= aes_core_ctrl_reg;
 end

 //----------------------------------------------------------------
 // sbox_mux
 //
 // Controls which of the encipher datapath or the key memory
 // that gets access to the sbox.
 //----------------------------------------------------------------
 assign muxed_sboxw = (init_state) ? keymem_sboxw : enc_sboxw;

 //----------------------------------------------------------------
 // encdex_mux
 //
 // Controls which of the datapaths that get the iNext signal, have
 // access to the memory as well as the block processing result.
 //----------------------------------------------------------------
 //Todo: delete dec
 assign enc_next = iNext;
 assign muxed_round_nr = enc_round_nr;
 assign muxed_new_block = enc_new_block;
 assign muxed_ready = enc_ready;

//  assign enc_next = iEncdec & iNext;
//  assign dec_next = ~iEncdec & iNext;
//  assign muxed_round_nr = (iEncdec) ? enc_round_nr : dec_round_nr;
//  assign muxed_new_block = (iEncdec) ? enc_new_block : dec_new_block;
//  assign muxed_ready = (iEncdec) ? enc_ready : dec_ready;

 //----------------------------------------------------------------
 // aes_core_ctrl
 //
 // Control FSM for aes core. Basically tracks if we are in
 // key init, encipher or decipher modes and connects the
 // different submodules to shared resources and interface ports.
 //----------------------------------------------------------------
 /*
 always@(*) begin
	init_state        = 1'b0;
	ready_new         = 1'b0;
	ready_we          = 1'b0;
	result_valid_new  = 1'b0;
	result_valid_we   = 1'b0;
	aes_core_ctrl_new = 2'd0;
	aes_core_ctrl_we  = 1'b0;
	
	case(aes_core_ctrl_reg)
		2'd0: begin
			if(iInit) begin
				init_state        = 1'b1;
				ready_new         = 1'b0;
				ready_we          = 1'b1;
				result_valid_new  = 1'b0;
				result_valid_we   = 1'b1;
				aes_core_ctrl_new = 2'd1;
				aes_core_ctrl_we  = 1'b1;
			end
			else if(iNext) begin
				init_state        = 1'b0;
				ready_new         = 1'b0;
				ready_we          = 1'b1;
				result_valid_new  = 1'b0;
				result_valid_we   = 1'b1;
				aes_core_ctrl_new = 2'd2;
				aes_core_ctrl_we  = 1'b1;
			end
		end
		2'd1: begin
			init_state = 1'b1;
			result_valid_new = 1'b0;
			result_valid_we = 1'b0;
			if(key_ready) begin
				ready_new         = 1'b1;
				ready_we          = 1'b1;
				aes_core_ctrl_new = 2'd0;
				aes_core_ctrl_we  = 1'b1;
			end
		end
		2'd2: begin
			init_state = 1'b0;
			if(muxed_ready) begin
				ready_new         = 1'b1;
				ready_we          = 1'b1;
				result_valid_new  = 1'b1;
				result_valid_we   = 1'b1;
				aes_core_ctrl_new = 2'd0;
				aes_core_ctrl_we  = 1'b1;
			end
		end
	endcase
 end
 */
 
 /*
 always@(*) begin
	init_state = 1'b0;
	case(aes_core_ctrl_reg)
		2'd0: begin
			if(iInit)	init_state = 1'b1;
			else		init_state = 1'b0;
		end
		2'd1: begin
			init_state = 1'b1;
		end
		2'd2: begin
			init_state = 1'b0;
		end
	endcase
 end
 */
 assign init_state = (State0 & iInit) | State1;
 
 /*
 always@(*) begin
	ready_new = 1'b0;
	case(aes_core_ctrl_reg)
		2'd0: begin
			ready_new = 1'b0;
		end
		2'd1: begin
			if(key_ready) 	ready_new = 1'b1;
			else			ready_new = 1'b0;
		end
		2'd2: begin
			if(muxed_ready) ready_new = 1'b1;
			else			ready_new = 1'b0;
		end
	endcase
 end
 */
 assign ready_new = (State1 & key_ready) | (State2 & muxed_ready);
 
 /*
 always@(*) begin
	ready_we = 1'b0;
	case(aes_core_ctrl_reg)
		2'd0: begin
			if(iInit|iNext) 	ready_we = 1'b1;
			else				ready_we = 1'b0;
		end
		2'd1: begin
			if(key_ready) 	ready_we = 1'b1;
			else			ready_we = 1'b0;
		end
		2'd2: begin
			if(muxed_ready) ready_we = 1'b1;
			else			ready_we = 1'b0;
		end
	endcase
 end
 */
 assign ready_we = (State0 & (iInit|iNext)) | (State1 & key_ready) | (State2 & muxed_ready);
 
 /*
 always@(*) begin
	result_valid_new = 1'b0;
	case(aes_core_ctrl_reg)
		2'd0: begin
			result_valid_new = 1'b0;
		end
		2'd1: begin
			result_valid_new = 1'b0;
		end
		2'd2: begin
			if(muxed_ready) result_valid_new = 1'b1;
			else			result_valid_new = 1'b0;
		end
	endcase
 end
 */
 assign result_valid_new = State2 & muxed_ready;
 
 /*
 always@(*) begin
	result_valid_we = 1'b0;
	case(aes_core_ctrl_reg)
		2'd0: begin
			if(iInit|iNext) 	result_valid_we = 1'b1;
			else				result_valid_we = 1'b0;
		end
		2'd1: begin
			result_valid_we = 1'b0;
		end
		2'd2: begin
			if(muxed_ready)	result_valid_we = 1'b1;
			else			result_valid_we = 1'b0;
		end
	endcase
 end
 */
 assign result_valid_we = (State0 & (iInit|iNext)) | (State2 & muxed_ready);
 
 /*
 always@(*) begin
	aes_core_ctrl_new = 2'd0;
	case(aes_core_ctrl_reg)
		2'd0: begin
			if(iInit) 		aes_core_ctrl_new = 2'd1;
			else if(iNext) 	aes_core_ctrl_new = 2'd2;
			else			aes_core_ctrl_new = 2'd0;
		end
		2'd1: begin
			aes_core_ctrl_new = 2'd0;
		end
		2'd2: begin
			aes_core_ctrl_new = 2'd0;
		end
	endcase
 end
 */
 assign aes_core_ctrl_new[0] = State0 & iInit;
 assign aes_core_ctrl_new[1] = State0 & ~iInit & iNext;
 
 /*
 always@(*) begin
	aes_core_ctrl_we = 1'b0;
	case(aes_core_ctrl_reg)
		2'd0: begin
			if(iInit|iNext) 	aes_core_ctrl_we = 1'b1;
			else				aes_core_ctrl_we = 1'b0;
		end
		2'd1: begin
			if(key_ready) 	aes_core_ctrl_we = 1'b1;
			else			aes_core_ctrl_we = 1'b0;
		end
		2'd2: begin
			if(muxed_ready) aes_core_ctrl_we = 1'b1;
			else			aes_core_ctrl_we = 1'b0;
		end
	endcase
 end
 */
 assign aes_core_ctrl_we = (State0 & (iInit|iNext)) | (State1 & key_ready) | (State2 & muxed_ready);
 
endmodule

module mixwv2 (
	input	[31:0]	w,
	output	[31:0]	out
);

assign out[31] = w[30] ^ w[23] ^ w[22] ^ w[15] ^ w[7];
assign out[30] = w[29] ^ w[21] ^ w[22] ^ w[14] ^ w[6];
assign out[29] = w[28] ^ w[20] ^ w[21] ^ w[13] ^ w[5];
assign out[28] = w[31] ^ w[27] ^ w[23] ^ w[19] ^ w[20] ^ w[12] ^ w[4];
assign out[27] = w[31] ^ w[26] ^ w[23] ^ w[18] ^ w[19] ^ w[11] ^ w[3];
assign out[26] = w[25] ^ w[17] ^ w[18] ^ w[10] ^ w[2];
assign out[25] = w[31] ^ w[24] ^ w[23] ^ w[16] ^ w[17] ^ w[9]  ^ w[1];
assign out[24] = w[31] ^ w[23] ^ w[16] ^ w[8]  ^ w[0];
assign out[23] = w[31] ^ w[22] ^ w[14] ^ w[15] ^ w[7];
assign out[22] = w[30] ^ w[21] ^ w[13] ^ w[14] ^ w[6];
assign out[21] = w[29] ^ w[20] ^ w[12] ^ w[13] ^ w[5];
assign out[20] = w[28] ^ w[23] ^ w[19] ^ w[15] ^ w[11] ^ w[12] ^ w[4];
assign out[19] = w[27] ^ w[23] ^ w[18] ^ w[15] ^ w[10] ^ w[11] ^ w[3];
assign out[18] = w[26] ^ w[17] ^ w[9]  ^ w[10] ^ w[2];
assign out[17] = w[25] ^ w[23] ^ w[16] ^ w[15] ^ w[8]  ^ w[9]  ^ w[1];
assign out[16] = w[24] ^ w[23] ^ w[15] ^ w[8]  ^ w[0];
assign out[15] = w[31] ^ w[23] ^ w[14] ^ w[6]  ^ w[7];
assign out[14] = w[30] ^ w[22] ^ w[13] ^ w[5]  ^ w[6];
assign out[13] = w[29] ^ w[21] ^ w[12] ^ w[4]  ^ w[5];
assign out[12] = w[28] ^ w[20] ^ w[15] ^ w[11] ^ w[7]  ^ w[3]  ^ w[4];
assign out[11] = w[27] ^ w[19] ^ w[15] ^ w[10] ^ w[7]  ^ w[2]  ^ w[3];
assign out[10] = w[26] ^ w[18] ^ w[9]  ^ w[1]  ^ w[2];
assign out[9]  = w[25] ^ w[17] ^ w[15] ^ w[8]  ^ w[7]  ^ w[0]  ^ w[1];
assign out[8]  = w[24] ^ w[16] ^ w[15] ^ w[7]  ^ w[0];
assign out[7]  = w[30] ^ w[31] ^ w[23] ^ w[15] ^ w[6];
assign out[6]  = w[29] ^ w[30] ^ w[22] ^ w[14] ^ w[5];
assign out[5]  = w[28] ^ w[29] ^ w[21] ^ w[13] ^ w[4];
assign out[4]  = w[31] ^ w[27] ^ w[28] ^ w[20] ^ w[12] ^ w[7]  ^ w[3];
assign out[3]  = w[31] ^ w[26] ^ w[27] ^ w[19] ^ w[11] ^ w[7]  ^ w[2];
assign out[2]  = w[25] ^ w[26] ^ w[18] ^ w[10] ^ w[1];
assign out[1]  = w[31] ^ w[24] ^ w[25] ^ w[17] ^ w[9]  ^ w[7]  ^ w[0];
assign out[0]  = w[31] ^ w[24] ^ w[16] ^ w[8]  ^ w[7];

endmodule

module mixcolumnsv2 (
	input	[127:0]	data,
	output	[127:0]	out
);

mixwv2 u3 (
	.w		(data[127:96]),
	.out	(out[127:96])
);

mixwv2 u2 (
	.w		(data[95:64]),
	.out	(out[95:64])
);

mixwv2 u1 (
	.w		(data[63:32]),
	.out	(out[63:32])
);

mixwv2 u0 (
	.w		(data[31:0]),
	.out	(out[31:0])
);

endmodule

module aes_gcm_v4(
input iClk,
input iRstn,
	/* control signals */
// iCtrl[0] - iInit
// iCtrl[1] - iNext
// iCtrl[2] - iEncdec: 1 for ENC, 0 for DEC
// iCtrl[3] - aad_only
input [0:3] iCtrl,
output oReady,
	/* data */
input [0:95] iIV,
input iIV_valid,
input [0:255] iKey,
input iKey_valid,
input iKeylen,

input [0:127] iAad, //Additional Authentication Data and Length
input iAad_valid,

input [0:127] iBlock,
input iBlock_valid,

input [0:127] iTag,	//DEC_MODE: compare with newly generated TAG
input iTag_valid,

input [3:0] iBlock_bytes,
	//output
output [0:127] oResult,
output oResult_valid,
output [0:127] oTag,
output oTag_valid,
output oAuthentic
);

//----------------------------------------------------------------
// Registers and wire declare
//----------------------------------------------------------------
/* AES GCM */
//control
/*
ctrl_reg[0] - iInit
ctrl_reg[1] - iNext
ctrl_reg[2] - iEncdec
ctrl_reg[3] - aad_only
*/
reg [0:3] ctrl_reg;
reg next_reg;
wire next_rising;

reg aes_gcm_ready;
reg aes_gcm_tag_valid;
reg aes_gcm_result_valid;
//input
reg [0:127] dec_tag_reg;

/* FSM */
// parameter IDLE = 3'b000;
// parameter CAL_HASHKEY = 3'b001;
// parameter CAL_ADD = 3'b010;
// parameter CIPHER = 3'b011;
// parameter TAG = 3'b100; //Compute Y0 and generate TAG
wire IDLE;
wire CAL_HASHKEY;
wire CAL_ADD;
wire CIPHER;
wire TAG; //Compute Y0 and generate TAG

reg  [2:0] aes_gcm_state_reg;
wire  [2:0] aes_gcm_state_new;

/* GCTR */
//control
wire gctr_init;
wire gctr_hashkey_compute;
wire gctr_y0_compute;
//output
wire [0:127] gctr_result;
wire gctr_result_valid;
reg gctr_result_valid_reg;
wire gctr_result_rising;

/* GHASH */
//control
wire ghash_next;
wire [1:0] ghash_input_signal;
//input
wire [0:127] mux_ghash_input1;
wire [0:127] mux_ghash_input2;
wire ghash_input_valid;

reg [0:127] ghash_key_reg;
wire ghash_key_wen;
wire ghash_key_valid;

reg [0:127] y0_reg;
wire y0_wen;
//output
wire [0:127] ghash_result;
reg [0:127] ghash_result_reg;
wire ghash_result_wen;
wire ghash_result_valid;
reg ghash_result_valid_reg;
wire ghash_result_valid_rising;

// NEW: Compute bitmask for partial block zero-padding in GHASH
wire [0:127] ghash_ctext;  // NEW: Masked input for partial blocks
wire [7:0] valid_bytes = (iBlock_bytes == 4'd0) ? 8'd16 : {4'd0, iBlock_bytes};
wire [7:0] pad_bytes = 16 - valid_bytes;
wire [127:0] bitmask = {128{1'b1}} << (pad_bytes * 8);  // MSB valid bits 1, LSB pad bits 0
// Apply mask only in CIPHER state (for blocks); ensures GHASH sees actual data + zero-pad
assign ghash_ctext = (CIPHER) ? (mux_ghash_input2 & bitmask) : mux_ghash_input2;

//----------------------------------------------------------------
// Instantiations.
//----------------------------------------------------------------

//GCTR_BLOCK_v2 contain AES_CORE with only encryption mode
gctr_block_v2 GCTR(
	//control signal
.iClk(iClk),
.iRstn(iRstn),
.iInit(gctr_init),
.iHashKey(gctr_hashkey_compute), 
.iY0(gctr_y0_compute),
	//data
.iIV(iIV),				
.iIV_valid(iIV_valid),	
.iKey(iKey),		
.iKey_valid(iKey_valid),	
.iKeylen(iKeylen),
.iBlock(iBlock), 
.iBlock_valid(iBlock_valid),
	//output: ciphertext, hashkey, y0
.oResult(gctr_result),						
.oResult_valid(gctr_result_valid)
);

//GHASH_BLOCK_v2 computes GF(2^128) in 128 clock cycles
ghash_block_v2 GHASH(
.iClk(iClk),
.iRstn(iRstn),
	//control
.iNext(ghash_next),
	//data
.iCtext(ghash_ctext), 			    //AAD or Cipher text
.iCtext_valid(ghash_input_valid),
.iY(ghash_result_reg), 					//previous ghash result
.iHashkey(ghash_key_reg),				//hash key
.iHashkey_valid(ghash_key_valid),
	//output
.oY(ghash_result),						//new ghash result
.oY_valid(ghash_result_valid)
);

//----------------------------------------------------------------
// Registers
//----------------------------------------------------------------

/* AES GCM */
//control
always @(posedge iClk) begin
	if(~iRstn)	ctrl_reg <= 4'd0;
	else		ctrl_reg <= iCtrl;
end

always @(posedge iClk) begin
    if(~iRstn)  next_reg <= 1'b0;
    else        next_reg <= ctrl_reg[1];
end

//output
always @(posedge iClk) begin
	if(~iRstn | next_rising)              aes_gcm_result_valid <= 1'b0;
	else if(gctr_result_rising & CIPHER)  aes_gcm_result_valid <= 1'b1;
    else                                  aes_gcm_result_valid <= aes_gcm_result_valid;
end

always @(posedge iClk) begin
    if(~iRstn)                                aes_gcm_tag_valid <= 1'b0;
    else if(ghash_result_valid_rising & TAG)  aes_gcm_tag_valid <= 1'b1;
    else                                      aes_gcm_tag_valid <= aes_gcm_tag_valid;
end

always @(posedge iClk) begin
    if(~iRstn | next_rising)                                                 aes_gcm_ready <= 1'b0;
    else if((gctr_result_rising & CAL_HASHKEY) | ghash_result_valid_rising)  aes_gcm_ready <= 1'b1;
    else                                                                     aes_gcm_ready <= aes_gcm_ready;
end

/* GHASH */
//ghash key reg
always @(posedge iClk) begin
	if(~iRstn)			   ghash_key_reg <= 128'd0;
    else if(ghash_key_wen) ghash_key_reg <= gctr_result;
	else				   ghash_key_reg <= ghash_key_reg;
end
//ghash result reg
always @(posedge iClk) begin
	if(~iRstn)			        ghash_result_reg <= 128'd0;
    else if(ghash_result_wen)   ghash_result_reg <= ghash_result;
	else				        ghash_result_reg <= ghash_result_reg;
end
//ghash result valid reg
always @(posedge iClk) begin
	if(~iRstn)   ghash_result_valid_reg <= 1'b0;
	else		 ghash_result_valid_reg <= ghash_result_valid;
end
//gctr result valid reg
always @(posedge iClk) begin
	if(~iRstn)	 gctr_result_valid_reg <= 1'b0;
	else		 gctr_result_valid_reg <= gctr_result_valid;
end
//ghash key reg
always @(posedge iClk) begin
	if(~iRstn)		 y0_reg <= 128'd0;
    else if(y0_wen)  y0_reg <= gctr_result;
	else			 y0_reg <= y0_reg;
end
//decryption tag
always @(posedge iClk) begin
	if(~iRstn)			   dec_tag_reg <= 128'd0;
    else if(iTag_valid)    dec_tag_reg <= iTag;
	else				   dec_tag_reg <= dec_tag_reg;
end
/* FSM */
//State transition
always @(posedge iClk) begin
	if(~iRstn)		      aes_gcm_state_reg <= 3'd0;
	else if(ctrl_reg[0])  aes_gcm_state_reg <= aes_gcm_state_new;
	else			      aes_gcm_state_reg <= aes_gcm_state_reg;
end
//----------------------------------------------------------------
// Wire
//----------------------------------------------------------------
assign mux_ghash_input1 = (ghash_input_signal[0])? iAad : gctr_result;
assign mux_ghash_input2 = (ghash_input_signal[1])? iBlock : mux_ghash_input1;

assign ghash_result_valid_rising = ghash_result_valid & ~ghash_result_valid_reg; 
assign gctr_result_rising = gctr_result_valid & ~gctr_result_valid_reg;
assign next_rising = ctrl_reg[1] & ~next_reg;

assign oResult = gctr_result;
assign oResult_valid = aes_gcm_result_valid;
assign oTag = ghash_result_reg ^ y0_reg;					
assign oTag_valid = aes_gcm_tag_valid;		
assign oReady = aes_gcm_ready;
assign oAuthentic = (~ctrl_reg[2] & oTag_valid & (dec_tag_reg == oTag));
//----------------------------------------------------------------
// FSM
//----------------------------------------------------------------

// always @(*) begin
// 	case(aes_gcm_state_reg)
// 	3'b000: //IDLE
// 		if(ctrl_reg[0] & next_rising)   aes_gcm_state_new = CAL_HASHKEY;
// 		else		                    aes_gcm_state_new = IDLE;
// 	3'b001: //CAL_HASHKEY
// 		if(gctr_result_valid)	aes_gcm_state_new = CAL_ADD;
// 		else					aes_gcm_state_new = CAL_HASHKEY;
// 	3'b010: //CAL_AAD
// 		if(iBlock_valid & next_rising)		aes_gcm_state_new = CIPHER;
//         else if(ctrl_reg[3] & next_rising)  aes_gcm_state_new = TAG;
// 		else							    aes_gcm_state_new = CAL_ADD;
// 	3'b011: //CIPHER
// 		if (iAad_valid & next_rising)   aes_gcm_state_new = TAG;
// 		else 							aes_gcm_state_new = CIPHER;
// 	3'b100: //TAG
// 		if(ghash_result_valid_rising)	aes_gcm_state_new = IDLE;
// 		else					        aes_gcm_state_new = TAG;
// 	default:
// 		aes_gcm_state_new = IDLE;
// 	endcase
// end

assign IDLE 		= ~aes_gcm_state_reg[2] & ~aes_gcm_state_reg[1] & ~aes_gcm_state_reg[0];
assign CAL_HASHKEY 	= ~aes_gcm_state_reg[2] & ~aes_gcm_state_reg[1] &  aes_gcm_state_reg[0];
assign CAL_AAD		= ~aes_gcm_state_reg[2] &  aes_gcm_state_reg[1] & ~aes_gcm_state_reg[0];
assign CIPHER		= ~aes_gcm_state_reg[2] &  aes_gcm_state_reg[1] &  aes_gcm_state_reg[0];
assign TAG			=  aes_gcm_state_reg[2] & ~aes_gcm_state_reg[1] & ~aes_gcm_state_reg[0];

assign aes_gcm_state_new[0] =  (IDLE  & ctrl_reg[0] & next_rising)
                              |(CAL_HASHKEY & ~gctr_result_valid)
                              |(CAL_AAD & iBlock_valid & next_rising)
                              |(CIPHER & ~(iAad_valid & next_rising));
assign aes_gcm_state_new[1] =  (CAL_HASHKEY & gctr_result_valid)
                              |(CAL_AAD & (iBlock_valid | ~next_rising | ~ctrl_reg[3]))
                              |(CIPHER & ~(iAad_valid & next_rising));
assign aes_gcm_state_new[2] =  (CAL_AAD & ~iBlock_valid & next_rising & ctrl_reg[3])
                              |(CIPHER & iAad_valid & next_rising)
                              |(TAG & ~ghash_result_valid_rising);

// always @(*) begin
//     //gctr
//     gctr_init = 1'b0;
//     gctr_hashkey_compute = 1'b0;
//     gctr_y0_compute = 1'b0;
//     //ghash
//     ghash_next = 1'b0;
//     ghash_input_signal = 2'b00;
//     ghash_input_valid = 1'b0;
//     ghash_key_wen = 1'b0;
//     ghash_key_valid = 1'b0;
//     y0_wen = 1'b0;
//     ghash_result_wen = 1'b0;
//     case(aes_gcm_state_reg)
//         3'b000: begin   //IDLE         
//             //gctr
//             gctr_init = 1'b0;
//             gctr_hashkey_compute = 1'b0;
//             gctr_y0_compute = 1'b0;
//             //ghash
//             ghash_next = 1'b0;
//             ghash_input_signal = 2'b00;
//             ghash_input_valid = 1'b0;
//             ghash_key_wen = 1'b0;
//             ghash_key_valid = 1'b0;
//             y0_wen = 1'b0;
//             ghash_result_wen = 1'b0;
//         end
//         3'b001: begin //CAL_HASHKEY
//             //gctr
//             if(gctr_result_valid) gctr_init = 1'b0;
// 			else				  gctr_init = 1'b1;
//             gctr_hashkey_compute = 1'b1;
//             gctr_y0_compute = 1'b0;
//             //ghash
//             ghash_next = 1'b0;
//             ghash_input_signal[0] = 1'b0;
//             ghash_input_signal[1] = 1'b0;
//             ghash_input_valid = 1'b0;
//             if(gctr_result_valid) ghash_key_wen = 1'b1;
//             else                  ghash_key_wen = 1'b0;
//             if(gctr_result_valid) ghash_key_valid = 1'b1;
//             else                  ghash_key_valid = 1'b0;
//             y0_wen = 1'b0;
//             ghash_result_wen = 1'b0;
//         end
//         3'b010: begin //CAL_AAD
//             //gctr
//             if(next_rising & (iBlock_valid | ctrl_reg[3]))  gctr_init = 1'b1;
//             else                                            gctr_init = 1'b0;
//             gctr_hashkey_compute = 1'b0;
//             gctr_y0_compute = 1'b0;
//             //ghash
//             ghash_next = next_rising;
//             ghash_input_signal[0] = 1'b1; 	//iAAD input to GHASH
// 			ghash_input_signal[1] = 1'b0;
//             ghash_input_valid = iAad_valid;
//             ghash_key_wen = 1'b0;
//             ghash_key_valid = 1'b1;
//             y0_wen = 1'b0;
//             if(ghash_result_valid_rising) ghash_result_wen = 1'b1;
// 			else                          ghash_result_wen = 1'b0;
//         end
//         3'b011: begin //CIPHER
//             //gctr
//             if(next_rising)   gctr_init = 1'b1;
//             else              gctr_init = 1'b0;
//             gctr_hashkey_compute = 1'b0;
//             gctr_y0_compute = 1'b0;
//             //ghash
//             ghash_next = gctr_result_rising;
// 			ghash_input_signal[0] = 1'b0; 	//GCTR result input to GHASH
// 			if(ctrl_reg[2]) ghash_input_signal[1] = 1'b0;
// 			else		    ghash_input_signal[1] = 1'b1;
//             ghash_input_valid = gctr_result_valid;
//             ghash_key_wen = 1'b0;
//             ghash_key_valid = 1'b1;
//             y0_wen = 1'b0;
//             if(ghash_result_valid_rising)	ghash_result_wen = 1'b1;
// 			else					        ghash_result_wen = 1'b0;
//         end
//         3'b100: begin //TAG
//             //gctr
//             gctr_init = 1'b0;
//             gctr_hashkey_compute = 1'b0;
//             gctr_y0_compute = 1'b1;
//             //ghash
//             ghash_next = gctr_result_rising;
//             ghash_input_signal[0] = 1'b1;
//             ghash_input_signal[1] = 1'b0;
//             ghash_input_valid = gctr_result_valid;
//             ghash_key_wen = 1'b0;
//             ghash_key_valid = 1'b1;
//             if(gctr_result_rising) y0_wen = 1'b1;
//             else                   y0_wen = 1'b0;
//             if(ghash_result_valid_rising)	ghash_result_wen = 1'b1;
// 			else                            ghash_result_wen = 1'b0;
//         end
//         default: begin
//         //gctr
//         gctr_init = 1'b0;
//         gctr_hashkey_compute = 1'b0;
//         gctr_y0_compute = 1'b0;
//         //ghash
//         ghash_next = 1'b0;
//         ghash_input_signal = 2'b00;
//         ghash_input_valid = 1'b0;
//         ghash_key_wen = 1'b0;
//         ghash_key_valid = 1'b1;
//         y0_wen = 1'b0;
//         ghash_result_wen = 1'b0;
//         end
//     endcase
// end

/* gctr */
assign gctr_init = (CAL_HASHKEY & ~gctr_result_valid)
                  |(CAL_AAD & next_rising & (iBlock_valid | ctrl_reg[3]))
                  |(CIPHER & next_rising);
assign gctr_hashkey_compute = CAL_HASHKEY;
assign gctr_y0_compute = TAG;
/* ghash */
assign ghash_next = (CAL_AAD & next_rising)
                   |((CIPHER | TAG) & gctr_result_rising);
assign ghash_input_signal[0] =  (CAL_AAD | TAG);
assign ghash_input_signal[1] = (CIPHER & ~ctrl_reg[2]);
assign ghash_input_valid = (CAL_AAD & iAad_valid)
                          |((CIPHER|TAG) & gctr_result_valid);
assign ghash_key_wen = (CAL_HASHKEY & gctr_result_valid);
assign ghash_key_valid = (CAL_HASHKEY & ghash_key_valid)
                        |(CAL_AAD | CIPHER | TAG);
assign y0_wen = (TAG & gctr_result_rising);
assign ghash_result_wen = ((CAL_AAD | CIPHER | TAG) & ghash_result_valid_rising);

endmodule

module aes_sub_sboxv2(
	input		[7:0]	in,
	output	reg	[7:0]	out
);

 always@(*) begin
	case(in)
		8'h00: begin
			out = 8'h63;
		end
		8'h01: begin
			out = 8'h7c;
		end
		8'h02: begin
			out = 8'h77;
		end
		8'h03: begin
			out = 8'h7b;
		end
		8'h04: begin
			out = 8'hf2;
		end
		8'h05: begin
			out = 8'h6b;
		end
		8'h06: begin
			out = 8'h6f;
		end
		8'h07: begin
			out = 8'hc5;
		end
		8'h08: begin
			out = 8'h30;
		end
		8'h09: begin
			out = 8'h01;
		end
		8'h0a: begin
			out = 8'h67;
		end
		8'h0b: begin
			out = 8'h2b;
		end
		8'h0c: begin
			out = 8'hfe;
		end
		8'h0d: begin
			out = 8'hd7;
		end
		8'h0e: begin
			out = 8'hab;
		end
		8'h0f: begin
			out = 8'h76;
		end
		8'h10: begin
			out = 8'hca;
		end
		8'h11: begin
			out = 8'h82;
		end
		8'h12: begin
			out = 8'hc9;
		end
		8'h13: begin
			out = 8'h7d;
		end
		8'h14: begin
			out = 8'hfa;
		end
		8'h15: begin
			out = 8'h59;
		end
		8'h16: begin
			out = 8'h47;
		end
		8'h17: begin
			out = 8'hf0;
		end
		8'h18: begin
			out = 8'had;
		end
		8'h19: begin
			out = 8'hd4;
		end
		8'h1a: begin
			out = 8'ha2;
		end
		8'h1b: begin
			out = 8'haf;
		end
		8'h1c: begin
			out = 8'h9c;
		end
		8'h1d: begin
			out = 8'ha4;
		end
		8'h1e: begin
			out = 8'h72;
		end
		8'h1f: begin
			out = 8'hc0;
		end
		8'h20: begin
			out = 8'hb7;
		end
		8'h21: begin
			out = 8'hfd;
		end
		8'h22: begin
			out = 8'h93;
		end
		8'h23: begin
			out = 8'h26;
		end
		8'h24: begin
			out = 8'h36;
		end
		8'h25: begin
			out = 8'h3f;
		end
		8'h26: begin
			out = 8'hf7;
		end
		8'h27: begin
			out = 8'hcc;
		end
		8'h28: begin
			out = 8'h34;
		end
		8'h29: begin
			out = 8'ha5;
		end
		8'h2a: begin
			out = 8'he5;
		end
		8'h2b: begin
			out = 8'hf1;
		end
		8'h2c: begin
			out = 8'h71;
		end
		8'h2d: begin
			out = 8'hd8;
		end
		8'h2e: begin
			out = 8'h31;
		end
		8'h2f: begin
			out = 8'h15;
		end
		8'h30: begin
			out = 8'h04;
		end
		8'h31: begin
			out = 8'hc7;
		end
		8'h32: begin
			out = 8'h23;
		end
		8'h33: begin
			out = 8'hc3;
		end
		8'h34: begin
			out = 8'h18;
		end
		8'h35: begin
			out = 8'h96;
		end
		8'h36: begin
			out = 8'h05;
		end
		8'h37: begin
			out = 8'h9a;
		end
		8'h38: begin
			out = 8'h07;
		end
		8'h39: begin
			out = 8'h12;
		end
		8'h3a: begin
			out = 8'h80;
		end
		8'h3b: begin
			out = 8'he2;
		end
		8'h3c: begin
			out = 8'heb;
		end
		8'h3d: begin
			out = 8'h27;
		end
		8'h3e: begin
			out = 8'hb2;
		end
		8'h3f: begin
			out = 8'h75;
		end
		8'h40: begin
			out = 8'h09;
		end
		8'h41: begin
			out = 8'h83;
		end
		8'h42: begin
			out = 8'h2c;
		end
		8'h43: begin
			out = 8'h1a;
		end
		8'h44: begin
			out = 8'h1b;
		end
		8'h45: begin
			out = 8'h6e;
		end
		8'h46: begin
			out = 8'h5a;
		end
		8'h47: begin
			out = 8'ha0;
		end
		8'h48: begin
			out = 8'h52;
		end
		8'h49: begin
			out = 8'h3b;
		end
		8'h4a: begin
			out = 8'hd6;
		end
		8'h4b: begin
			out = 8'hb3;
		end
		8'h4c: begin
			out = 8'h29;
		end
		8'h4d: begin
			out = 8'he3;
		end
		8'h4e: begin
			out = 8'h2f;
		end
		8'h4f: begin
			out = 8'h84;
		end
		8'h50: begin
			out = 8'h53;
		end
		8'h51: begin
			out = 8'hd1;
		end
		8'h52: begin
			out = 8'h00;
		end
		8'h53: begin
			out = 8'hed;
		end
		8'h54: begin
			out = 8'h20;
		end
		8'h55: begin
			out = 8'hfc;
		end
		8'h56: begin
			out = 8'hb1;
		end
		8'h57: begin
			out = 8'h5b;
		end
		8'h58: begin
			out = 8'h6a;
		end
		8'h59: begin
			out = 8'hcb;
		end
		8'h5a: begin
			out = 8'hbe;
		end
		8'h5b: begin
			out = 8'h39;
		end
		8'h5c: begin
			out = 8'h4a;
		end
		8'h5d: begin
			out = 8'h4c;
		end
		8'h5e: begin
			out = 8'h58;
		end
		8'h5f: begin
			out = 8'hcf;
		end
		8'h60: begin
			out = 8'hd0;
		end
		8'h61: begin
			out = 8'hef;
		end
		8'h62: begin
			out = 8'haa;
		end
		8'h63: begin
			out = 8'hfb;
		end
		8'h64: begin
			out = 8'h43;
		end
		8'h65: begin
			out = 8'h4d;
		end
		8'h66: begin
			out = 8'h33;
		end
		8'h67: begin
			out = 8'h85;
		end
		8'h68: begin
			out = 8'h45;
		end
		8'h69: begin
			out = 8'hf9;
		end
		8'h6a: begin
			out = 8'h02;
		end
		8'h6b: begin
			out = 8'h7f;
		end
		8'h6c: begin
			out = 8'h50;
		end
		8'h6d: begin
			out = 8'h3c;
		end
		8'h6e: begin
			out = 8'h9f;
		end
		8'h6f: begin
			out = 8'ha8;
		end
		8'h70: begin
			out = 8'h51;
		end
		8'h71: begin
			out = 8'ha3;
		end
		8'h72: begin
			out = 8'h40;
		end
		8'h73: begin
			out = 8'h8f;
		end
		8'h74: begin
			out = 8'h92;
		end
		8'h75: begin
			out = 8'h9d;
		end
		8'h76: begin
			out = 8'h38;
		end
		8'h77: begin
			out = 8'hf5;
		end
		8'h78: begin
			out = 8'hbc;
		end
		8'h79: begin
			out = 8'hb6;
		end
		8'h7a: begin
			out = 8'hda;
		end
		8'h7b: begin
			out = 8'h21;
		end
		8'h7c: begin
			out = 8'h10;
		end
		8'h7d: begin
			out = 8'hff;
		end
		8'h7e: begin
			out = 8'hf3;
		end
		8'h7f: begin
			out = 8'hd2;
		end
		8'h80: begin
			out = 8'hcd;
		end
		8'h81: begin
			out = 8'h0c;
		end
		8'h82: begin
			out = 8'h13;
		end
		8'h83: begin
			out = 8'hec;
		end
		8'h84: begin
			out = 8'h5f;
		end
		8'h85: begin
			out = 8'h97;
		end
		8'h86: begin
			out = 8'h44;
		end
		8'h87: begin
			out = 8'h17;
		end
		8'h88: begin
			out = 8'hc4;
		end
		8'h89: begin
			out = 8'ha7;
		end
		8'h8a: begin
			out = 8'h7e;
		end
		8'h8b: begin
			out = 8'h3d;
		end
		8'h8c: begin
			out = 8'h64;
		end
		8'h8d: begin
			out = 8'h5d;
		end
		8'h8e: begin
			out = 8'h19;
		end
		8'h8f: begin
			out = 8'h73;
		end
		8'h90: begin
			out = 8'h60;
		end
		8'h91: begin
			out = 8'h81;
		end
		8'h92: begin
			out = 8'h4f;
		end
		8'h93: begin
			out = 8'hdc;
		end
		8'h94: begin
			out = 8'h22;
		end
		8'h95: begin
			out = 8'h2a;
		end
		8'h96: begin
			out = 8'h90;
		end
		8'h97: begin
			out = 8'h88;
		end
		8'h98: begin
			out = 8'h46;
		end
		8'h99: begin
			out = 8'hee;
		end
		8'h9a: begin
			out = 8'hb8;
		end
		8'h9b: begin
			out = 8'h14;
		end
		8'h9c: begin
			out = 8'hde;
		end
		8'h9d: begin
			out = 8'h5e;
		end
		8'h9e: begin
			out = 8'h0b;
		end
		8'h9f: begin
			out = 8'hdb;
		end
		8'ha0: begin
			out = 8'he0;
		end
		8'ha1: begin
			out = 8'h32;
		end
		8'ha2: begin
			out = 8'h3a;
		end
		8'ha3: begin
			out = 8'h0a;
		end
		8'ha4: begin
			out = 8'h49;
		end
		8'ha5: begin
			out = 8'h06;
		end
		8'ha6: begin
			out = 8'h24;
		end
		8'ha7: begin
			out = 8'h5c;
		end
		8'ha8: begin
			out = 8'hc2;
		end
		8'ha9: begin
			out = 8'hd3;
		end
		8'haa: begin
			out = 8'hac;
		end
		8'hab: begin
			out = 8'h62;
		end
		8'hac: begin
			out = 8'h91;
		end
		8'had: begin
			out = 8'h95;
		end
		8'hae: begin
			out = 8'he4;
		end
		8'haf: begin
			out = 8'h79;
		end
		8'hb0: begin
			out = 8'he7;
		end
		8'hb1: begin
			out = 8'hc8;
		end
		8'hb2: begin
			out = 8'h37;
		end
		8'hb3: begin
			out = 8'h6d;
		end
		8'hb4: begin
			out = 8'h8d;
		end
		8'hb5: begin
			out = 8'hd5;
		end
		8'hb6: begin
			out = 8'h4e;
		end
		8'hb7: begin
			out = 8'ha9;
		end
		8'hb8: begin
			out = 8'h6c;
		end
		8'hb9: begin
			out = 8'h56;
		end
		8'hba: begin
			out = 8'hf4;
		end
		8'hbb: begin
			out = 8'hea;
		end
		8'hbc: begin
			out = 8'h65;
		end
		8'hbd: begin
			out = 8'h7a;
		end
		8'hbe: begin
			out = 8'hae;
		end
		8'hbf: begin
			out = 8'h08;
		end
		8'hc0: begin
			out = 8'hba;
		end
		8'hc1: begin
			out = 8'h78;
		end
		8'hc2: begin
			out = 8'h25;
		end
		8'hc3: begin
			out = 8'h2e;
		end
		8'hc4: begin
			out = 8'h1c;
		end
		8'hc5: begin
			out = 8'ha6;
		end
		8'hc6: begin
			out = 8'hb4;
		end
		8'hc7: begin
			out = 8'hc6;
		end
		8'hc8: begin
			out = 8'he8;
		end
		8'hc9: begin
			out = 8'hdd;
		end
		8'hca: begin
			out = 8'h74;
		end
		8'hcb: begin
			out = 8'h1f;
		end
		8'hcc: begin
			out = 8'h4b;
		end
		8'hcd: begin
			out = 8'hbd;
		end
		8'hce: begin
			out = 8'h8b;
		end
		8'hcf: begin
			out = 8'h8a;
		end
		8'hd0: begin
			out = 8'h70;
		end
		8'hd1: begin
			out = 8'h3e;
		end
		8'hd2: begin
			out = 8'hb5;
		end
		8'hd3: begin
			out = 8'h66;
		end
		8'hd4: begin
			out = 8'h48;
		end
		8'hd5: begin
			out = 8'h03;
		end
		8'hd6: begin
			out = 8'hf6;
		end
		8'hd7: begin
			out = 8'h0e;
		end
		8'hd8: begin
			out = 8'h61;
		end
		8'hd9: begin
			out = 8'h35;
		end
		8'hda: begin
			out = 8'h57;
		end
		8'hdb: begin
			out = 8'hb9;
		end
		8'hdc: begin
			out = 8'h86;
		end
		8'hdd: begin
			out = 8'hc1;
		end
		8'hde: begin
			out = 8'h1d;
		end
		8'hdf: begin
			out = 8'h9e;
		end
		8'he0: begin
			out = 8'he1;
		end
		8'he1: begin
			out = 8'hf8;
		end
		8'he2: begin
			out = 8'h98;
		end
		8'he3: begin
			out = 8'h11;
		end
		8'he4: begin
			out = 8'h69;
		end
		8'he5: begin
			out = 8'hd9;
		end
		8'he6: begin
			out = 8'h8e;
		end
		8'he7: begin
			out = 8'h94;
		end
		8'he8: begin
			out = 8'h9b;
		end
		8'he9: begin
			out = 8'h1e;
		end
		8'hea: begin
			out = 8'h87;
		end
		8'heb: begin
			out = 8'he9;
		end
		8'hec: begin
			out = 8'hce;
		end
		8'hed: begin
			out = 8'h55;
		end
		8'hee: begin
			out = 8'h28;
		end
		8'hef: begin
			out = 8'hdf;
		end
		8'hf0: begin
			out = 8'h8c;
		end
		8'hf1: begin
			out = 8'ha1;
		end
		8'hf2: begin
			out = 8'h89;
		end
		8'hf3: begin
			out = 8'h0d;
		end
		8'hf4: begin
			out = 8'hbf;
		end
		8'hf5: begin
			out = 8'he6;
		end
		8'hf6: begin
			out = 8'h42;
		end
		8'hf7: begin
			out = 8'h68;
		end
		8'hf8: begin
			out = 8'h41;
		end
		8'hf9: begin
			out = 8'h99;
		end
		8'hfa: begin
			out = 8'h2d;
		end
		8'hfb: begin
			out = 8'h0f;
		end
		8'hfc: begin
			out = 8'hb0;
		end
		8'hfd: begin
			out = 8'h54;
		end
		8'hfe: begin
			out = 8'hbb;
		end
		8'hff: begin
			out = 8'h16;
		end
	endcase
 end

endmodule

module gctr_block_v2(
	//control signal
input iClk,
input iRstn,  
input iInit,
input iHashKey,
input iY0,
	//data
input [0:95] iIV,
input iIV_valid,
input [0:255] iKey,
input iKey_valid,
input iKeylen,
input [0:127] iBlock,
input iBlock_valid,
	//output
output [0:127] oResult,
output oResult_valid
);

//----------------------------------------------------------------
// Registers variables and enable.
//----------------------------------------------------------------
reg [0:31] counter_reg;
wire	   counter_en; //todo

reg [0:127] block_reg;
wire 		block_wen; //todo
reg			encdec_reg;

reg [0:95]  IV_reg;
wire		IV_wen; //todo

reg [0:255] key_reg;
wire 		key_wen; //todo
reg 		key_len;

reg hashkey_reg;
wire hashkey_wen; //todo

reg y0_reg;
wire y0_wen; //todo

reg [1:0] gctr_ctrl_reg;
wire [1:0] gctr_ctrl_new; //todo

wire gctr_result_valid; //todo
//----------------------------------------------------------------
// Wires.
//----------------------------------------------------------------
wire State0; //IDLE
wire State1; //INIT_AES
wire State2; //WAIT_KEY
wire State3; //CIPHER

wire [0:127] muxed_aes_core_input;
wire [0:127] aes_core_output;

wire aes_core_init;  //todo
wire aes_core_next; //todo
wire aes_core_oready;
wire aes_core_output_valid;

assign State0 = ~gctr_ctrl_reg[1] & ~gctr_ctrl_reg[0];
assign State1 = ~gctr_ctrl_reg[1] &  gctr_ctrl_reg[0]; 
assign State2 =  gctr_ctrl_reg[1] & ~gctr_ctrl_reg[0]; 
assign State3 =  gctr_ctrl_reg[1] &  gctr_ctrl_reg[0];
//----------------------------------------------------------------
// Instantiations.
//----------------------------------------------------------------
aes_corev2 U1(
.iClk(iClk),						
.iRstn(iRstn),
				
.iInit(aes_core_init),						
.iNext(aes_core_next),						
.oReady(aes_core_oready),				

.iKey(key_reg),						
.iKeylen(key_len),					

.iBlock(muxed_aes_core_input),					
.oResult(aes_core_output),					
.oResult_valid(aes_core_output_valid)
);

//----------------------------------------------------------------
// Reg
//----------------------------------------------------------------

//Sample input IV
always @(posedge iClk) begin
	if(~iRstn) 									IV_reg <= 128'd0;
	else if(IV_wen & iIV_valid)  	IV_reg <= iIV;				
	else 										IV_reg <= IV_reg;
end

//Sample input plaintext
always @(posedge iClk) begin
	if(~iRstn) 							block_reg <= 128'd0;
	else if(block_wen & iBlock_valid)  	block_reg <= iBlock;			
	else 								block_reg <= block_reg;
end

//Sample input key
always @(posedge iClk) begin
	if(~iRstn) 						key_reg <= 256'd0;
	else if(key_wen & iKey_valid)  	key_reg <= iKey;				
	else 							key_reg <= key_reg;
end

always @(posedge iClk) begin
	if(~iRstn) 						key_len <= 1'd0;
	else if(key_wen & iKey_valid)  	key_len <= iKeylen;				
	else 							key_len <= key_len;
end

always @(posedge iClk) begin
	if(~iRstn) 							hashkey_reg <= 1'b0;
	else if(hashkey_wen & iKey_valid)  	hashkey_reg <= iHashKey;				
	else 								hashkey_reg <= hashkey_reg;
end

always @(posedge iClk) begin
	if(~iRstn) 										y0_reg <= 1'b0;
	else if(y0_wen & iKey_valid)  		y0_reg <= iY0;				
	else 											y0_reg <= y0_reg;
end

//Counter
always @(posedge iClk) begin
	if(~iRstn)												counter_reg <= 32'd1;
	else if(counter_en & ~hashkey_reg & ~y0_reg)	counter_reg <= counter_reg + 1'd1; 
	else													counter_reg <= counter_reg;
end

//State transition
always @(posedge iClk) begin
	if(~iRstn)		gctr_ctrl_reg <= 2'd0;
	//else if(iInit)  gctr_ctrl_reg <= gctr_ctrl_new;
	else 			gctr_ctrl_reg <= gctr_ctrl_new;
end

//----------------------------------------------------------------
// Mux connection of the input and output of aes_core
//----------------------------------------------------------------
assign muxed_aes_core_input = (y0_reg)? {IV_reg, 31'd0, 1'b1} : 
							  (hashkey_reg)? {128{1'b0}} :  {IV_reg, counter_reg};  //Create Hashkey


assign oResult = (hashkey_reg | y0_reg)? aes_core_output : aes_core_output ^ block_reg; //Output Hashkey or y0


assign oResult_valid = gctr_result_valid;


//----------------------------------------------------------------
// gctr_block control
//
// Control FSM for gctr_block. Tasks:
// - Sample input Key, Keylen, IV, Block
// - Store Block
// - Pass necessary signal and data to aes_core and wait for return signal
//----------------------------------------------------------------

//---------------------------------------------------------------------------------------------------------------------------------
//State transition
// always @(*) begin
// 	case(gctr_ctrl_reg)
// 	2'b00:
// 		if(iInit & aes_core_oready) 	gctr_ctrl_new = 2'b01;	//start when init_signal = 1 and the aes_core is avaiable
// 		else							gctr_ctrl_new = 2'b00;
// 	2'b01:
// 		gctr_ctrl_new = 2'b10;									//after init, wait for the aes_core to generate keys
// 	2'b10:
// 		if(aes_core_oready) gctr_ctrl_new = 2'b11;					//the keys are generated, send data to enc/dec
// 		else gctr_ctrl_new = 2'b10;
// 	2'b11:
// 		if(aes_core_oready) 	gctr_ctrl_new = 2'b00;		//pass input to aes_core, go back to IDLE
// 		else					gctr_ctrl_new = 2'b11;
// 	endcase
// end

//-- Optim --
assign gctr_ctrl_new[0] = (State0 & iInit & aes_core_oready) | (State2 & aes_core_oready) | (State3 & ~aes_core_oready);
assign gctr_ctrl_new[1] = State1 | State2 | (State3 & ~aes_core_oready);
//---------------------------------------------------------------------------------------------------------------------------------

//---------------------------------------------------------------------------------------------------------------------------------
//Control signals
// always @(*) begin
// 	//input
// 	counter_en = 1'b0;
// 	block_wen = 1'b0;
// 	IV_wen = 1'b0;
// 	key_wen = 1'b0;
// 	hashkey_wen = 1'b0;
// 	//signal to aes_core
// 	aes_core_init = 1'b0;
// 	aes_core_next = 1'b0;
// 	case(gctr_ctrl_reg)
// 		2'b00: begin	//IDLE
// 			//input
// 			counter_en = 1'b0;
// 			block_wen = 1'b0;
// 			IV_wen = 1'b0;
// 			key_wen = 1'b0;
// 			hashkey_wen = 1'b0;
// 			//signal to aes_core
// 			aes_core_init = 1'b0;
// 			aes_core_next = 1'b0;
// 			gctr_result_valid = aes_core_output_valid;
// 		end
// 		2'b01: begin	//INIT_AES			//Start aes_core, sample all necessary input
// 			//input
// 			counter_en = 1'b0;
// 			block_wen = 1'b1;
// 			IV_wen = 1'b1;
// 			key_wen = 1'b1;
// 			hashkey_wen = 1'b1;
// 			y0_wen = 1'b1;
// 			//signal to aes_core
// 			aes_core_init = 1'b1;
// 			aes_core_next = 1'b0;
// 			gctr_result_valid = 1'b0;
// 		end
// 		2'b10: begin //WAIT_KEY
// 			//input
// 			counter_en = 1'b0;
// 			block_wen = 1'b0;
// 			IV_wen = 1'b0;
// 			key_wen = 1'b0;
// 			hashkey_wen = 1'b0;
// 			//signal to aes_core
// 			aes_core_init = 1'b0;
// 			aes_core_next = 1'b0;
// 			gctr_result_valid = 1'b0;
// 		end
// 		2'b11: begin //CIPHER
// 			//input
// 			counter_en = 1'b1;
// 			block_wen = 1'b0;
// 			IV_wen = 1'b0;
// 			key_wen = 1'b0;
// 			hashkey_wen = 1'b0;
// 			//signal to aes_core
// 			aes_core_init = 1'b0;
// 			aes_core_next = 1'b1;
// 			gctr_result_valid = 1'b0;
// 		end
// 	endcase
// end

assign counter_en = State3;
assign block_wen = State1;
assign IV_wen = State1;
assign key_wen = State1;
assign hashkey_wen = State1;
assign aes_core_init = State1;
assign aes_core_next = State3;
	//this reduce aes_core_output_valid signal to 1 clock cycle
//assign gctr_result_valid = (gctr_ctrl_new[1] & ~gctr_ctrl_new[0])? aes_core_output_valid : 1'b0;
assign gctr_result_valid = aes_core_output_valid;
assign y0_wen = State1;
//---------------------------------------------------------------------------------------------------------------------------------

endmodule

//======================================================================
//
// aes_key_memv2.v
// -------------
// The AES key memory including round key generator.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2013 Secworks Sweden AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module aes_key_memv2(
	input			iClk,
	input			iRstn,
	
	input	[255:0]	iKey,
	input			iKeylen,
	input			iInit,
	
	input	[3:0]	iRound,
	output	[127:0]	oRound_key,
	output			oReady,
	
	
	output	[31:0]	oSboxw,
	input	[31:0]	iNew_sboxw
);

 //----------------------------------------------------------------
 // Registers.
 //----------------------------------------------------------------
 reg	[127:0]	key_mem0,  key_mem1,  key_mem2,  key_mem3,
				key_mem4,  key_mem5,  key_mem6,  key_mem7,
				key_mem8,  key_mem9,  key_mem10, key_mem11,
				key_mem12, key_mem13, key_mem14;
 wire	[127:0]	key_mem_new;
 wire			key_mem_we;

 reg	[127:0]	prev_key0_reg;
 wire	[127:0]	prev_key0_new;
 wire			prev_key0_we;

 reg	[127:0]	prev_key1_reg;
 wire	[127:0]	prev_key1_new;
 wire			prev_key1_we;

 reg	[3:0]	round_ctr_reg;
 wire	[3:0]	round_ctr_new;
 wire			round_ctr_rst;
 wire			round_ctr_inc;
 wire			round_ctr_we;
 wire			round_ctr_0, round_ctr_1;

 reg	[1:0]	key_mem_ctrl_reg;
 wire	[1:0]	key_mem_ctrl_new;
 wire			key_mem_ctrl_we;
 wire			State0, State1, State2, State3;

 reg			ready_reg;
 wire			ready_new;
 wire			ready_we;

 reg	[7:0]	rcon_reg;
 wire	[7:0]	rcon_new;
 wire			rcon_we;
 wire			rcon_set;
 wire			rcon_next;
 
 wire	[31:0]	w0, w1, w2, w3, w4, w5, w6, w7;
 wire	[31:0]	k0, k1, k2, k3;
 wire	[31:0]	tw, trw;
 wire			round_ctr_reg_num_rounds;

 //----------------------------------------------------------------
 // Wires.
 //----------------------------------------------------------------
 wire			round_key_update;
 wire	[127:0]	tmp_round_key;

 //----------------------------------------------------------------
 // Concurrent assignments for ports.
 //----------------------------------------------------------------
 assign oRound_key = tmp_round_key;
 assign oReady     = ready_reg;
 assign oSboxw     = w7;
 
 assign State0 = ~key_mem_ctrl_reg[1] & ~key_mem_ctrl_reg[0];
 assign State1 = ~key_mem_ctrl_reg[1] &  key_mem_ctrl_reg[0];
 assign State2 =  key_mem_ctrl_reg[1] & ~key_mem_ctrl_reg[0];
 assign State3 =  key_mem_ctrl_reg[1] &  key_mem_ctrl_reg[0];
 
 assign round_ctr_0 = ~round_ctr_reg[3] & ~round_ctr_reg[2] & ~round_ctr_reg[1] & ~round_ctr_reg[0];
 assign round_ctr_1 = ~round_ctr_reg[3] & ~round_ctr_reg[2] & ~round_ctr_reg[1] &  round_ctr_reg[0];
 
 //wire [3:0] num_rounds;
 //assign num_rounds = (iKeylen) ? 14 : 10;
 //assign round_ctr_reg_num_rounds = round_ctr_reg==num_rounds;
 assign round_ctr_reg_num_rounds = round_ctr_reg[3] &
								   ~(iKeylen ^ round_ctr_reg[2]) &
								   round_ctr_reg[1] &
								   ~round_ctr_reg[0];
 
 //----------------------------------------------------------------
 // reg_update
 //
 // Update functionality for all registers in the core.
 // All registers are positive edge triggered with asynchronous
 // active low reset. All registers have write enable.
 //----------------------------------------------------------------
 /*
 always@(posedge iClk or negedge iRstn) begin: regupdate
	integer i;

	if(~iRstn) begin
		for(i=0; i<=AES_256_NUM_ROUNDS; i=i+1)
			key_mem[i] <= 128'h0;
			rcon_reg         <= 8'h0;
			ready_reg        <= 1'b0;
			round_ctr_reg    <= 4'h0;
			key_mem_ctrl_reg <= 2'd0;
		end
	else begin
		if(round_ctr_we)	round_ctr_reg <= round_ctr_new;
		if(ready_we)		ready_reg <= ready_new;
		if(rcon_we)			rcon_reg <= rcon_new;
		if(key_mem_we)		key_mem[round_ctr_reg] <= key_mem_new;
		if(prev_key0_we)	prev_key0_reg <= prev_key0_new;
		if(prev_key1_we)	prev_key1_reg <= prev_key1_new;
		if(key_mem_ctrl_we)	key_mem_ctrl_reg <= key_mem_ctrl_new;
	end
 end
 */
 always@(posedge iClk) begin
	if(~iRstn)				round_ctr_reg <= 4'h0;
	else if(round_ctr_we)	round_ctr_reg <= round_ctr_new;
	else					round_ctr_reg <= round_ctr_reg;
 end
 
 always@(posedge iClk) begin
	if(~iRstn)			ready_reg <= 1'b0;
	else if(ready_we)	ready_reg <= ready_new;
	else				ready_reg <= ready_reg;
 end
 
 always@(posedge iClk) begin
	if(~iRstn)			rcon_reg <= 8'h0;
	else if(rcon_we)	rcon_reg <= rcon_new;
	else				rcon_reg <= rcon_reg;
 end
 
 always@(posedge iClk) begin
	if(key_mem_we & ~round_ctr_reg[3] & ~round_ctr_reg[2] & ~round_ctr_reg[1] & ~round_ctr_reg[0])
			key_mem0 <= key_mem_new;
	else	key_mem0 <= key_mem0;
 end
 always@(posedge iClk) begin
	if(key_mem_we & ~round_ctr_reg[3] & ~round_ctr_reg[2] & ~round_ctr_reg[1] & round_ctr_reg[0])
			key_mem1 <= key_mem_new;
	else	key_mem1 <= key_mem1;
 end
 always@(posedge iClk) begin
	if(key_mem_we & ~round_ctr_reg[3] & ~round_ctr_reg[2] & round_ctr_reg[1] & ~round_ctr_reg[0])
			key_mem2 <= key_mem_new;
	else	key_mem2 <= key_mem2;
 end
 always@(posedge iClk) begin
	if(key_mem_we & ~round_ctr_reg[3] & ~round_ctr_reg[2] & round_ctr_reg[1] & round_ctr_reg[0])
			key_mem3 <= key_mem_new;
	else	key_mem3 <= key_mem3;
 end
 always@(posedge iClk) begin
	if(key_mem_we & ~round_ctr_reg[3] & round_ctr_reg[2] & ~round_ctr_reg[1] & ~round_ctr_reg[0])
			key_mem4 <= key_mem_new;
	else	key_mem4 <= key_mem4;
 end
 always@(posedge iClk) begin
	if(key_mem_we & ~round_ctr_reg[3] & round_ctr_reg[2] & ~round_ctr_reg[1] & round_ctr_reg[0])
			key_mem5 <= key_mem_new;
	else	key_mem5 <= key_mem5;
 end
 always@(posedge iClk) begin
	if(key_mem_we & ~round_ctr_reg[3] & round_ctr_reg[2] & round_ctr_reg[1] & ~round_ctr_reg[0])
			key_mem6 <= key_mem_new;
	else	key_mem6 <= key_mem6;
 end
 always@(posedge iClk) begin
	if(key_mem_we & ~round_ctr_reg[3] & round_ctr_reg[2] & round_ctr_reg[1] & round_ctr_reg[0])
			key_mem7 <= key_mem_new;
	else	key_mem7 <= key_mem7;
 end
 always@(posedge iClk) begin
	if(key_mem_we & round_ctr_reg[3] & ~round_ctr_reg[2] & ~round_ctr_reg[1] & ~round_ctr_reg[0])
			key_mem8 <= key_mem_new;
	else	key_mem8 <= key_mem8;
 end
 always@(posedge iClk) begin
	if(key_mem_we & round_ctr_reg[3] & ~round_ctr_reg[2] & ~round_ctr_reg[1] & round_ctr_reg[0])
			key_mem9 <= key_mem_new;
	else	key_mem9 <= key_mem9;
 end
 always@(posedge iClk) begin
	if(key_mem_we & round_ctr_reg[3] & ~round_ctr_reg[2] & round_ctr_reg[1] & ~round_ctr_reg[0])
			key_mem10 <= key_mem_new;
	else	key_mem10 <= key_mem10;
 end
 always@(posedge iClk) begin
	if(key_mem_we & round_ctr_reg[3] & ~round_ctr_reg[2] & round_ctr_reg[1] & round_ctr_reg[0])
			key_mem11 <= key_mem_new;
	else	key_mem11 <= key_mem11;
 end
 always@(posedge iClk) begin
	if(key_mem_we & round_ctr_reg[3] & round_ctr_reg[2] & ~round_ctr_reg[1] & ~round_ctr_reg[0])
			key_mem12 <= key_mem_new;
	else	key_mem12 <= key_mem12;
 end
 always@(posedge iClk) begin
	if(key_mem_we & round_ctr_reg[3] & round_ctr_reg[2] & ~round_ctr_reg[1] & round_ctr_reg[0])
			key_mem13 <= key_mem_new;
	else	key_mem13 <= key_mem13;
 end
 always@(posedge iClk) begin
	if(key_mem_we & round_ctr_reg[3] & round_ctr_reg[2] & round_ctr_reg[1])
			key_mem14 <= key_mem_new;
	else	key_mem14 <= key_mem14;
 end
 
 always@(posedge iClk) begin
	if(prev_key0_we)	prev_key0_reg <= prev_key0_new;
	else				prev_key0_reg <= prev_key0_reg;
 end
 
 always@(posedge iClk) begin
	if(prev_key1_we)	prev_key1_reg <= prev_key1_new;
	else				prev_key1_reg <= prev_key1_reg;
 end
 
 always@(posedge iClk) begin
	if(~iRstn)					key_mem_ctrl_reg <= 2'd0;
	else if(key_mem_ctrl_we)	key_mem_ctrl_reg <= key_mem_ctrl_new;
	else						key_mem_ctrl_reg <= key_mem_ctrl_reg;
 end
 
 //----------------------------------------------------------------
 // key_mem_read
 //
 // Combinational read port for the key memory.
 //----------------------------------------------------------------
 /*
 always@(*) begin
	tmp_round_key = key_mem[iRound];
 end // key_mem_read
 */
 //assign tmp_round_key = key_mem[iRound];
 assign tmp_round_key = (iRound[3]) ?
							( (iRound[2]) ?
								( (iRound[1]) ? key_mem14 :
									( (iRound[0]) ? key_mem13 : key_mem12 ) ) :
								( (iRound[1]) ?
									( (iRound[0]) ? key_mem11 : key_mem10 ) :
									( (iRound[0]) ? key_mem9 : key_mem8 ) ) ) :
							( (iRound[2]) ?
								( (iRound[1]) ?
									( (iRound[0]) ? key_mem7 : key_mem6 ) :
									( (iRound[0]) ? key_mem5 : key_mem4 ) ) :
								( (iRound[1]) ?
									( (iRound[0]) ? key_mem3 : key_mem2 ) :
									( (iRound[0]) ? key_mem1 : key_mem0 ) ) );
 
 //----------------------------------------------------------------
 // round_key_gen
 //
 // The round key generator logic for AES-128 and AES-256.
 //----------------------------------------------------------------
 assign w0 = prev_key0_reg[127:96];
 assign w1 = prev_key0_reg[95:64];
 assign w2 = prev_key0_reg[63:32];
 assign w3 = prev_key0_reg[31:0];
 assign w4 = prev_key1_reg[127:96];
 assign w5 = prev_key1_reg[95:64];
 assign w6 = prev_key1_reg[63:32];
 assign w7 = prev_key1_reg[31:0];
 
 assign trw[31:24] = iNew_sboxw[23:16] ^ rcon_reg;
 assign trw[23:0]  = {iNew_sboxw[15:0], iNew_sboxw[31:24]};
 assign tw = iNew_sboxw;
 
 /*
 always@(*) begin: roundkeygen
	reg [31:0] k0, k1, k2, k3;
	reg [31:0] rconw, rotstw, tw, trw;

	// Default assignments.
	key_mem_new   = 128'h0;
	key_mem_we    = 1'b0;
	prev_key0_new = 128'h0;
	prev_key0_we  = 1'b0;
	prev_key1_new = 128'h0;
	prev_key1_we  = 1'b0;

	k0 = 32'h0;
	k1 = 32'h0;
	k2 = 32'h0;
	k3 = 32'h0;

	rcon_set   = 1'b1;
	rcon_next  = 1'b0;

	// Extract words and calculate intermediate values.
	// Perform rotation of sbox word etc.
	
	rconw = {rcon_reg, 24'h0};
	tmp_sboxw = w7;
	rotstw = {iNew_sboxw[23:0], iNew_sboxw[31:24]};
	trw = rotstw ^ rconw;
	tw = iNew_sboxw;

	// Generate the specific round keys.
	if(round_key_update) begin
		rcon_set   = 1'b0;
		key_mem_we = 1'b1;
		case (iKeylen)
			1'b0: begin	//AES_128_BIT_KEY
				if(round_ctr_0) begin
					key_mem_new   = iKey[255:128];
					prev_key1_new = iKey[255:128];
					prev_key1_we  = 1'b1;
					rcon_next     = 1'b1;
				end
				else begin
					k0 = w4 ^ trw;
					k1 = w5 ^ w4 ^ trw;
					k2 = w6 ^ w5 ^ w4 ^ trw;
					k3 = w7 ^ w6 ^ w5 ^ w4 ^ trw;
					key_mem_new   = {k0, k1, k2, k3};
					prev_key1_new = {k0, k1, k2, k3};
					prev_key1_we  = 1'b1;
					rcon_next     = 1'b1;
				end
			end
			1'b1: begin	//AES_256_BIT_KEY
				if(round_ctr_0) begin
					key_mem_new   = iKey[255:128];
					prev_key0_new = iKey[255:128];
					prev_key0_we  = 1'b1;
				end
				else if(round_ctr_1) begin
					key_mem_new   = iKey[127:0];
					prev_key1_new = iKey[127:0];
					prev_key1_we  = 1'b1;
					rcon_next     = 1'b1;
				end
				else begin
					if(round_ctr_reg[0]==0) begin
						k0 = w0 ^ trw;
						k1 = w1 ^ w0 ^ trw;
						k2 = w2 ^ w1 ^ w0 ^ trw;
						k3 = w3 ^ w2 ^ w1 ^ w0 ^ trw;
					end
					else begin
						k0 = w0 ^ tw;
						k1 = w1 ^ w0 ^ tw;
						k2 = w2 ^ w1 ^ w0 ^ tw;
						k3 = w3 ^ w2 ^ w1 ^ w0 ^ tw;
						rcon_next = 1'b1;
					end
					// Store the generated round keys.
					key_mem_new   = {k0, k1, k2, k3};
					prev_key1_new = {k0, k1, k2, k3};
					prev_key1_we  = 1'b1;
					prev_key0_new = prev_key1_reg;
					prev_key0_we  = 1'b1;
				end
			end
		endcase // case (iKeylen)
	end
 end // round_key_gen
 */
 
 /*
 always@(*) begin
	key_mem_new = 128'h0;
	key_mem_we = 1'b0;
	// Generate the specific round keys.
	if(round_key_update) begin
		key_mem_we = 1'b1;
		case (iKeylen)
			1'b0: begin	//AES_128_BIT_KEY
				if(round_ctr_0)	key_mem_new = iKey[255:128];
				else			key_mem_new = {k0, k1, k2, k3};
			end
			1'b1: begin	//AES_256_BIT_KEY
				if(round_ctr_0)			key_mem_new = iKey[255:128];
				else if(round_ctr_1)	key_mem_new = iKey[127:0];
				else					key_mem_new = {k0, k1, k2, k3};
			end
		endcase
	end
 end
 */
 assign key_mem_new = (round_ctr_0) ? iKey[255:128] :
									  ( (iKeylen & round_ctr_1) ? iKey[127:0] : {k0, k1, k2, k3} );
 assign key_mem_we = round_key_update;
 
 /*
 always@(*) begin
	rcon_set = 1'b1;
	rcon_next = 1'b0;
	// Generate the specific round keys.
	if(round_key_update) begin
		rcon_set = 1'b0;
		case (iKeylen)
			1'b0: begin	//AES_128_BIT_KEY
				rcon_next = 1'b1;
			end
			1'b1: begin	//AES_256_BIT_KEY
				if(round_ctr_0)	rcon_next = 1'b0;
				else if(round_ctr_1 | ~round_ctr_reg[0])
						rcon_next = 1'b1;
				else	rcon_next = 1'b0;
			end
		endcase
	end
 end
 */
 assign rcon_set = ~round_key_update;
 assign rcon_next = ~iKeylen | (~round_ctr_0 & (round_ctr_1 | ~round_ctr_reg[0]));
 
 /*
 always@(*) begin
	prev_key0_new = 128'h0;
	prev_key0_we  = 1'b0;
	prev_key1_new = 128'h0;
	prev_key1_we  = 1'b0;
	// Generate the specific round keys.
	if(round_key_update) begin
		case (iKeylen)
			1'b0: begin	//AES_128_BIT_KEY
				if(round_ctr_0) begin
					prev_key1_new = iKey[255:128];
					prev_key1_we  = 1'b1;
				end
				else begin
					prev_key1_new = {k0, k1, k2, k3};
					prev_key1_we  = 1'b1;
				end
			end
			1'b1: begin	//AES_256_BIT_KEY
				if(round_ctr_0) begin
					prev_key0_new = iKey[255:128];
					prev_key0_we  = 1'b1;
				end
				else if(round_ctr_1) begin
					prev_key1_new = iKey[127:0];
					prev_key1_we  = 1'b1;
				end
				else begin
					// Store the generated round keys.
					prev_key1_new = {k0, k1, k2, k3};
					prev_key1_we  = 1'b1;
					prev_key0_new = prev_key1_reg;
					prev_key0_we  = 1'b1;
				end
			end
		endcase
	end
 end
 */
 assign prev_key0_new = {(128){iKeylen}} & {(128){~round_ctr_1}} &
						((round_ctr_0) ? iKey[255:128] : prev_key1_reg);
 assign prev_key0_we = iKeylen & ~round_ctr_1;
 assign prev_key1_new = (iKeylen) ? ({(128){~round_ctr_0}} & ((round_ctr_1) ? iKey[127:0] : {k0, k1, k2, k3})) :
						(round_ctr_0) ? iKey[255:128] : {k0, k1, k2, k3};
 assign prev_key1_we = ~iKeylen | ~round_ctr_0;
 
 /*
 always@(*) begin
	k0 = 32'h0;
	k1 = 32'h0;
	k2 = 32'h0;
	k3 = 32'h0;
	// Generate the specific round keys.
	if(round_key_update) begin
		case(iKeylen)
			1'b0: begin	//AES_128_BIT_KEY
				if(~round_ctr_0) begin
					k0 = w4 ^ trw;
					k1 = w5 ^ w4 ^ trw;
					k2 = w6 ^ w5 ^ w4 ^ trw;
					k3 = w7 ^ w6 ^ w5 ^ w4 ^ trw;
				end
			end
			1'b1: begin	//AES_256_BIT_KEY
				if(~round_ctr_0 & ~round_ctr_1) begin
					if(~round_ctr_reg[0]) begin
						k0 = w0 ^ trw;
						k1 = w1 ^ w0 ^ trw;
						k2 = w2 ^ w1 ^ w0 ^ trw;
						k3 = w3 ^ w2 ^ w1 ^ w0 ^ trw;
					end
					else begin
						k0 = w0 ^ tw;
						k1 = w1 ^ w0 ^ tw;
						k2 = w2 ^ w1 ^ w0 ^ tw;
						k3 = w3 ^ w2 ^ w1 ^ w0 ^ tw;
					end
				end
			end
		endcase
	end
 end
 */
 assign k0 = (iKeylen) ? ( (~round_ctr_0&~round_ctr_1&~round_ctr_reg[0]) ? (w0^trw) : (w0^tw) ) :
						 ( {(32){~round_ctr_0}} & (w4^trw) );
 assign k1 = (iKeylen) ? ( (~round_ctr_0&~round_ctr_1&~round_ctr_reg[0]) ? (w1^w0^trw) : (w1^w0^tw) ) :
						 ( {(32){~round_ctr_0}} & (w5^w4^trw) );
 assign k2 = (iKeylen) ? ( (~round_ctr_0&~round_ctr_1&~round_ctr_reg[0]) ? (w2^w1^w0^trw) : (w2^w1^w0^tw) ) :
						 ( {(32){~round_ctr_0}} & (w6^w5^w4^trw) );
 assign k3 = (iKeylen) ? ( (~round_ctr_0&~round_ctr_1&~round_ctr_reg[0]) ? (w3^w2^w1^w0^trw) : (w3^w2^w1^w0^tw) ) :
						 ( {(32){~round_ctr_0}} & (w7^w6^w5^w4^trw) );
 
 //----------------------------------------------------------------
 // rcon_logic
 //
 // Caclulates the rcon value for the different key expansion
 // iterations.
 //----------------------------------------------------------------
 /*
 always@(*) begin: rconlogic
	reg [7:0] tmp_rcon;
	rcon_new = 8'h00;
	rcon_we  = 1'b0;
	tmp_rcon = {rcon_reg[6:0], 1'b0} ^ (8'h1b & {8{rcon_reg[7]}});

	if(rcon_set) begin
		rcon_new = 8'h8d;
		rcon_we  = 1'b1;
	end
	
	if(rcon_next) begin
		rcon_new = tmp_rcon[7 : 0];
		rcon_we  = 1'b1;
	end
 end
 */
 assign rcon_new[7] = rcon_set | rcon_reg[6];
 assign rcon_new[6] = ~rcon_set & rcon_reg[5];
 assign rcon_new[5] = ~rcon_set & rcon_reg[4];
 assign rcon_new[4] = ~rcon_set & (rcon_reg[3] ^ rcon_reg[7]);
 assign rcon_new[3] = rcon_set | (rcon_reg[2] ^ rcon_reg[7]);
 assign rcon_new[2] = rcon_set | rcon_reg[1];
 assign rcon_new[1] = ~rcon_set & (rcon_reg[0] ^ rcon_reg[7]);
 assign rcon_new[0] = rcon_set | rcon_reg[7];
 assign rcon_we = rcon_set | rcon_next; 
 
 //----------------------------------------------------------------
 // round_ctr
 //
 // The round counter logic with increase and reset.
 //----------------------------------------------------------------
 /*
 always@(*) begin
	round_ctr_new = 4'h0;
	round_ctr_we  = 1'b0;

	if(round_ctr_rst) begin
		round_ctr_new = 4'h0;
		round_ctr_we  = 1'b1;
	end
	else if(round_ctr_inc) begin
		round_ctr_new = round_ctr_reg + 1'b1;
		round_ctr_we  = 1'b1;
	end
 end
 */
 wire [3:0] round_ctr_reg_p1;
 assign round_ctr_reg_p1 = round_ctr_reg + 1'b1;
 assign round_ctr_new = {(4){round_ctr_inc}} & round_ctr_reg_p1;
 assign round_ctr_we = round_ctr_rst | round_ctr_inc;
 
 //----------------------------------------------------------------
 // key_mem_ctrl
 //
 //
 // The FSM that controls the round key generation.
 //----------------------------------------------------------------
 /*
 always@(*) begin: keymemctrl
	reg [3:0] num_rounds;

	// Default assignments.
	ready_new        = 1'b0;
	ready_we         = 1'b0;
	round_key_update = 1'b0;
	round_ctr_rst    = 1'b0;
	round_ctr_inc    = 1'b0;
	key_mem_ctrl_new = 2'd0;
	key_mem_ctrl_we  = 1'b0;

	if(iKeylen)	num_rounds = AES_256_NUM_ROUNDS;
	else		num_rounds = AES_128_NUM_ROUNDS;

	case(key_mem_ctrl_reg)
		2'd0: begin
			if(iInit) begin
				ready_new        = 1'b0;
				ready_we         = 1'b1;
				round_key_update = 1'b0;
				round_ctr_rst    = 1'b0;
				round_ctr_inc    = 1'b0;
				key_mem_ctrl_new = 2'd1;
				key_mem_ctrl_we  = 1'b1;
			end
		end
		2'd1: begin
			ready_new		 = 1'b0;
			ready_we		 = 1'b0;
			round_key_update = 1'b0;
			round_ctr_rst    = 1'b1;
			round_ctr_inc    = 1'b0;
			key_mem_ctrl_new = 2'd2;
			key_mem_ctrl_we  = 1'b1;
		end
		2'd2: begin
			ready_new		 = 1'b0;
			ready_we		 = 1'b0;
			round_key_update = 1'b1;
			round_ctr_rst    = 1'b0;
			round_ctr_inc    = 1'b1;
			if(round_ctr_reg==num_rounds) begin
				key_mem_ctrl_new = 2'd3;
				key_mem_ctrl_we  = 1'b1;
			end
			else begin
				key_mem_ctrl_new = 2'd0;
				key_mem_ctrl_we  = 1'b0;
			end
		end
		2'd3: begin
			ready_new        = 1'b1;
			ready_we         = 1'b1;
			round_key_update = 1'b0;
			round_ctr_rst    = 1'b0;
			round_ctr_inc    = 1'b0;
			key_mem_ctrl_new = 2'd0;
			key_mem_ctrl_we  = 1'b1;
		end
	endcase // case (key_mem_ctrl_reg)
 end // key_mem_ctrl
 */
 
 /*
 always@(*) begin
	ready_new = 1'b0;
	case(key_mem_ctrl_reg)
		2'd0: begin
			ready_new = 1'b0;
		end
		2'd1: begin
			ready_new = 1'b0;
		end
		2'd2: begin
			ready_new = 1'b0;
		end
		2'd3: begin
			ready_new = 1'b1;
		end
	endcase
 end
 */
 assign ready_new = State3;
 
 /*
 always@(*) begin
	ready_we = 1'b0;
	case(key_mem_ctrl_reg)
		2'd0: begin
			if(iInit)	ready_we = 1'b1;
			else		ready_we = 1'b0;
		end
		2'd1: begin
			ready_we = 1'b0;
		end
		2'd2: begin
			ready_we = 1'b0;
		end
		2'd3: begin
			ready_we = 1'b1;
		end
	endcase
 end
 */
 assign ready_we = (State0 & iInit) | State3;
 
 /*
 always@(*) begin
	round_key_update = 1'b0;
	case(key_mem_ctrl_reg)
		2'd0: begin
			round_key_update = 1'b0;
		end
		2'd1: begin
			round_key_update = 1'b0;
		end
		2'd2: begin
			round_key_update = 1'b1;
		end
		2'd3: begin
			round_key_update = 1'b0;
		end
	endcase
 end
 */
 assign round_key_update = State2;
 
 /*
 always@(*) begin
	round_ctr_rst = 1'b0;
	case(key_mem_ctrl_reg)
		2'd0: begin
			round_ctr_rst = 1'b0;
		end
		2'd1: begin
			round_ctr_rst = 1'b1;
		end
		2'd2: begin
			round_ctr_rst = 1'b0;
		end
		2'd3: begin
			round_ctr_rst = 1'b0;
		end
	endcase
 end
 */
 assign round_ctr_rst = State1;
 
 /*
 always@(*) begin
	round_ctr_inc = 1'b0;
	case(key_mem_ctrl_reg)
		2'd0: begin
			round_ctr_inc = 1'b0;
		end
		2'd1: begin
			round_ctr_inc = 1'b0;
		end
		2'd2: begin
			round_ctr_inc = 1'b1;
		end
		2'd3: begin
			round_ctr_inc = 1'b0;
		end
	endcase
 end
 */
 assign round_ctr_inc = State2;
 
 /*
 always@(*) begin
	key_mem_ctrl_new = 2'd0;
	case(key_mem_ctrl_reg)
		2'd0: begin
			if(iInit)	key_mem_ctrl_new = 2'd1;
			else		key_mem_ctrl_new = 2'd0;
		end
		2'd1: begin
			key_mem_ctrl_new = 2'd2;
		end
		2'd2: begin
			if(round_ctr_reg==num_rounds)	key_mem_ctrl_new = 2'd3;
			else							key_mem_ctrl_new = 2'd0;
		end
		2'd3: begin
			key_mem_ctrl_new = 2'd0;
		end
	endcase
 end
 */
 assign key_mem_ctrl_new[0] = (State0 & iInit) | (State2 & round_ctr_reg_num_rounds);
 assign key_mem_ctrl_new[1] = State1 | (State2 & round_ctr_reg_num_rounds);
 
 /*
 always@(*) begin
	key_mem_ctrl_we = 1'b0;
	case(key_mem_ctrl_reg)
		2'd0: begin
			if(iInit)	key_mem_ctrl_we = 1'b1;
			else		key_mem_ctrl_we = 1'b0;
		end
		2'd1: begin
			key_mem_ctrl_we = 1'b1;
		end
		2'd2: begin
			if(round_ctr_reg==num_rounds)	key_mem_ctrl_we = 1'b1;
			else							key_mem_ctrl_we = 1'b0;
		end
		2'd3: begin
			key_mem_ctrl_we = 1'b1;
		end
	endcase
 end
 */
 assign key_mem_ctrl_we = (State0 & iInit) | State1 | State3 |
						  (State2 & round_ctr_reg_num_rounds);
 
endmodule

module gfmul_v2(
input iClk,
input iRstn,
	//control
input iNext,
	//data
input [0:127] iCtext,
input iCtext_valid,
input [0:127] iHashkey,
input iHashkey_valid,
output [0:127] oResult,
output oResult_valid
);
//----------------------------------------------------------------
// reg and wire
//----------------------------------------------------------------
reg [0:127] Z;
reg [0:127] V;
reg next_reg;
wire next;

wire [0:127] iR;
assign iR = {8'b1110_0001, 120'd0};
wire [0:127] V_and_xor;
wire [0:127] Z_and_xor;
reg [7:0] cnt;
wire overflow;
wire [0:127] mux_Z_1;
wire [0:127] mux_Z_2;
wire [0:127] mux_V;
wire mux_sel;

//----------------------------------------------------------------
// function
//----------------------------------------------------------------
function [0:127]and_xor;
	input [0:127] in1;
	input [0:127] in2;
	input [0:127] in3;
	begin
		and_xor = in1 ^ (in2 & in3);
	end
endfunction

//----------------------------------------------------------------
// register
//----------------------------------------------------------------
always@(posedge iClk) begin
	if(~iRstn | next)					cnt <= 8'd0;
	else if(iCtext_valid & iHashkey_valid & ~overflow) cnt <= cnt + 1'b1;
	else if(overflow)					 cnt <= cnt;
	else cnt <= cnt;
end


always@(posedge iClk) begin
	if(iHashkey_valid) 	V <= V_and_xor;
	else 				V <= V;
end

always@(posedge iClk) begin
	if(iCtext_valid && iHashkey_valid) 	Z <= Z_and_xor;
	else 				Z <= Z;
end

always@(posedge iClk) begin
	next_reg <= iNext;
end


//----------------------------------------------------------------
// assignment
//----------------------------------------------------------------
assign next = iNext & ~next_reg;
assign overflow = cnt[7];
assign oResult_valid = overflow;
assign oResult = Z;

assign mux_sel = (cnt == 7'd0)? 1'b1 : 1'b0;

assign mux_V = (mux_sel)? iHashkey : V;
assign V_and_xor = and_xor({1'b0, mux_V[0:126]}, iR, {128{mux_V[127]}});

assign mux_Z_1 = (mux_sel)? iHashkey : V;
assign mux_Z_2 = (mux_sel)? 128'd0 : Z;
assign Z_and_xor = and_xor(mux_Z_2, mux_Z_1, {128{iCtext[cnt[6:0]]}});

endmodule

//======================================================================
//
// aes_encipher_blockv2.v
// --------------------
// The AES encipher round. A pure combinational module that implements
// the initial round, main round and final round logic for
// enciper operations.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2013, 2014, Secworks Sweden AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module aes_encipher_blockv2(
	input			iClk,
	input			iRstn,
	
	input			iNext,
	
	input			iKeylen,
	output	[3:0]	oRound,
	input	[127:0]	iRound_key,
	
	output	[31:0]	oSboxw,
	input	[31:0]	iNew_sboxw,
	
	input	[127:0]	iBlock,
	output	[127:0]	oNew_block,
	output			oReady
);

 //----------------------------------------------------------------
 // Registers including update variables and write enable.
 //----------------------------------------------------------------
 reg	[1:0]	sword_ctr_reg;
 wire	[1:0]	sword_ctr_new;
 wire			sword_ctr_we;
 wire			sword_ctr_inc;
 wire			sword_ctr_rst;

 reg	[3:0]	round_ctr_reg;
 wire	[3:0]	round_ctr_new;
 wire			round_ctr_we;
 wire			round_ctr_rst;
 wire			round_ctr_inc;

 wire	[127:0]	block_new;
 reg	[31:0]	block_w0_reg;
 reg	[31:0]	block_w1_reg;
 reg	[31:0]	block_w2_reg;
 reg	[31:0]	block_w3_reg;
 wire			block_w0_we;
 wire			block_w1_we;
 wire			block_w2_we;
 wire			block_w3_we;

 reg			ready_reg;
 wire			ready_new;
 wire			ready_we;

 reg	[1:0]	enc_ctrl_reg;
 wire	[1:0]	enc_ctrl_new;
 wire			enc_ctrl_we;

 wire	[2:0]	update_type;
 wire	[31:0]	muxed_sboxw;
 wire	[3:0]	num_rounds;
 
 wire			sword_ctr0, sword_ctr1, sword_ctr2, sword_ctr3;
 wire			enc_ctrl0, enc_ctrl1, enc_ctrl2, enc_ctrl3;
 //wire			update_type0;
 wire			update_type1, update_type2, update_type3, update_type4;
 wire			round_ctr_reg_num_rounds;
 
 //----------------------------------------------------------------
 // Concurrent connectivity for ports etc.
 //----------------------------------------------------------------
 assign oRound     = round_ctr_reg;
 assign oSboxw     = muxed_sboxw;
 assign oNew_block = {block_w0_reg, block_w1_reg, block_w2_reg, block_w3_reg};
 assign oReady     = ready_reg;
 
 /*
 always@(*) begin
	if(iKeylen)	num_rounds = 4'he;	//AES256_ROUNDS
	else		num_rounds = 4'ha;	//AES128_ROUNDS
 end
 */
 assign num_rounds[3] = 1'b1;
 assign num_rounds[2] = iKeylen;
 assign num_rounds[1] = 1'b1;
 assign num_rounds[0] = 1'b0;
 
 assign sword_ctr0 = ~sword_ctr_reg[1] & ~sword_ctr_reg[0];
 assign sword_ctr1 = ~sword_ctr_reg[1] &  sword_ctr_reg[0];
 assign sword_ctr2 =  sword_ctr_reg[1] & ~sword_ctr_reg[0];
 assign sword_ctr3 =  sword_ctr_reg[1] &  sword_ctr_reg[0];
 
 assign enc_ctrl0 = ~enc_ctrl_reg[1] & ~enc_ctrl_reg[0];
 assign enc_ctrl1 = ~enc_ctrl_reg[1] &  enc_ctrl_reg[0];
 assign enc_ctrl2 =  enc_ctrl_reg[1] & ~enc_ctrl_reg[0];
 assign enc_ctrl3 =  enc_ctrl_reg[1] &  enc_ctrl_reg[0];
 
 //assign update_type0 = ~update_type[2] & ~update_type[1] & ~update_type[0];
 assign update_type1 = ~update_type[2] & ~update_type[1] &  update_type[0];
 assign update_type2 = ~update_type[2] &  update_type[1] & ~update_type[0];
 assign update_type3 = ~update_type[2] &  update_type[1] &  update_type[0];
 assign update_type4 =  update_type[2] & ~update_type[1] & ~update_type[0];

 assign round_ctr_reg_num_rounds = (round_ctr_reg < num_rounds);
 
 //----------------------------------------------------------------
 // reg_update
 //
 // Update functionality for all registers in the core.
 // All registers are positive edge triggered with asynchronous
 // active low reset. All registers have write enable.
 //----------------------------------------------------------------
 /*
 always@(posedge iClk or negedge iRstn) begin
	if(~iRstn) begin
		block_w0_reg  <= 32'h0;
		block_w1_reg  <= 32'h0;
		block_w2_reg  <= 32'h0;
		block_w3_reg  <= 32'h0;
		sword_ctr_reg <= 2'h0;
		round_ctr_reg <= 4'h0;
		ready_reg     <= 1'b1;
		enc_ctrl_reg  <= 2'd0;
	end
	else begin
		if(block_w0_we)		block_w0_reg <= block_new[127:96];
		if(block_w1_we)		block_w1_reg <= block_new[95:64];
		if(block_w2_we)		block_w2_reg <= block_new[63:32];
		if(block_w3_we)		block_w3_reg <= block_new[31:0];
		if(sword_ctr_we)	sword_ctr_reg <= sword_ctr_new;
		if(round_ctr_we)	round_ctr_reg <= round_ctr_new;
		if(ready_we)		ready_reg <= ready_new;
		if(enc_ctrl_we)		enc_ctrl_reg <= enc_ctrl_new;
	end
 end // reg_update
 */
 always@(posedge iClk) begin
	if(~iRstn)			block_w0_reg <= 32'b0;
	else if(block_w0_we)	block_w0_reg <= block_new[127:96];
	else					block_w0_reg <= block_w0_reg;
 end
 
 always@(posedge iClk) begin
	if(~iRstn)			block_w1_reg <= 32'b0;
	else if(block_w1_we)	block_w1_reg <= block_new[95:64];
	else					block_w1_reg <= block_w1_reg;
 end
 
 always@(posedge iClk) begin
	if(~iRstn)			block_w2_reg <= 32'b0;
	else if(block_w2_we)	block_w2_reg <= block_new[63:32];
	else					block_w2_reg <= block_w2_reg;
 end
 
 always@(posedge iClk) begin
	if(~iRstn)			block_w3_reg <= 32'b0;
	else if(block_w3_we)	block_w3_reg <= block_new[31:0];
	else					block_w3_reg <= block_w3_reg;
 end
 
 always@(posedge iClk) begin
	if(~iRstn)			sword_ctr_reg <= 2'b0;
	else if(sword_ctr_we)	sword_ctr_reg <= sword_ctr_new;
	else					sword_ctr_reg <= sword_ctr_reg;
 end
 
 always@(posedge iClk) begin
	if(~iRstn)			round_ctr_reg <= 4'b0;
	else if(round_ctr_we)	round_ctr_reg <= round_ctr_new;
	else					round_ctr_reg <= round_ctr_reg;
 end
 
 always@(posedge iClk) begin
	if(~iRstn)		ready_reg <= 1'b1;
	else if(ready_we)	ready_reg <= ready_new;
	else				ready_reg <= ready_reg;
 end
 
 always@(posedge iClk) begin
	if(~iRstn)			enc_ctrl_reg <= 2'd0;
	else if(enc_ctrl_we)	enc_ctrl_reg <= enc_ctrl_new;
	else					enc_ctrl_reg <= enc_ctrl_reg;
 end
 
 //----------------------------------------------------------------
 // round_logic
 //
 // The logic needed to implement init, main and final rounds.
 //----------------------------------------------------------------
 wire [127:0] mixcolumns_shiftrows_block;
 wire [127:0] shiftrows_block;
 assign shiftrows_block = {block_w0_reg[31:24], block_w1_reg[23:16], block_w2_reg[15:8], block_w3_reg[7:0],
						   block_w1_reg[31:24], block_w2_reg[23:16], block_w3_reg[15:8], block_w0_reg[7:0],
						   block_w2_reg[31:24], block_w3_reg[23:16], block_w0_reg[15:8], block_w1_reg[7:0],
						   block_w3_reg[31:24], block_w0_reg[23:16], block_w1_reg[15:8], block_w2_reg[7:0]};
 mixcolumnsv2 mixcolumns_inst (
	.data	(shiftrows_block),
	.out	(mixcolumns_shiftrows_block)
 );
 
 /*
 always@(*) begin: roundlogic
	block_new   = 128'h0;
	muxed_sboxw = 32'h0;
	block_w0_we = 1'b0;
	block_w1_we = 1'b0;
	block_w2_we = 1'b0;
	block_w3_we = 1'b0;
	case(update_type)
		3'd1: begin
			block_new   = iBlock ^ iRound_key;
			block_w0_we = 1'b1;
			block_w1_we = 1'b1;
			block_w2_we = 1'b1;
			block_w3_we = 1'b1;
		end
		3'd2: begin
			block_new = {iNew_sboxw, iNew_sboxw, iNew_sboxw, iNew_sboxw};
			case(sword_ctr_reg)
				2'h0: begin
					muxed_sboxw = block_w0_reg;
					block_w0_we = 1'b1;
				end
				2'h1: begin
					muxed_sboxw = block_w1_reg;
					block_w1_we = 1'b1;
				end
				2'h2: begin
					muxed_sboxw = block_w2_reg;
					block_w2_we = 1'b1;
				end
				2'h3: begin
					muxed_sboxw = block_w3_reg;
					block_w3_we = 1'b1;
				end
			endcase
		end
		3'd3: begin
			block_new   = mixcolumns_shiftrows_block ^ iRound_key;
			block_w0_we = 1'b1;
			block_w1_we = 1'b1;
			block_w2_we = 1'b1;
			block_w3_we = 1'b1;
		end
		3'd4: begin
			block_new   = shiftrows_block ^ iRound_key;
			block_w0_we = 1'b1;
			block_w1_we = 1'b1;
			block_w2_we = 1'b1;
			block_w3_we = 1'b1;
		end
	endcase
 end
 */
 
 /*
 always@(*) begin
	case(update_type)
		3'd1: begin
			block_new = iBlock ^ iRound_key;
		end
		3'd2: begin
			block_new = {iNew_sboxw, iNew_sboxw, iNew_sboxw, iNew_sboxw};
		end
		3'd3: begin
			block_new = mixcolumns_shiftrows_block ^ iRound_key;
		end
		3'd4: begin
			block_new = shiftrows_block ^ iRound_key;
		end
	endcase
 end
 */
 assign block_new = (update_type1) ? (iBlock ^ iRound_key) :
					(update_type2) ? {iNew_sboxw, iNew_sboxw, iNew_sboxw, iNew_sboxw} :
					(update_type3) ? (mixcolumns_shiftrows_block ^ iRound_key) :
									 (shiftrows_block ^ iRound_key);
 
 /*
 always@(*) begin
	case(update_type)
		3'd1: begin
			muxed_sboxw = 32'h0;
		end
		3'd2: begin
			case(sword_ctr_reg)
				2'h0: begin
					muxed_sboxw = block_w0_reg;
				end
				2'h1: begin
					muxed_sboxw = block_w1_reg;
				end
				2'h2: begin
					muxed_sboxw = block_w2_reg;
				end
				2'h3: begin
					muxed_sboxw = block_w3_reg;
				end
			endcase
		end
		3'd3: begin
			muxed_sboxw = 32'h0;
		end
		3'd4: begin
			muxed_sboxw = 32'h0;
		end
	endcase
 end
 */
 assign muxed_sboxw = (sword_ctr0) ? block_w0_reg :
					  (sword_ctr1) ? block_w1_reg :
					  (sword_ctr2) ? block_w2_reg : block_w3_reg;
 
 /*
 always@(*) begin
	block_w0_we = 1'b0;
	block_w1_we = 1'b0;
	block_w2_we = 1'b0;
	block_w3_we = 1'b0;
	case(update_type)
		3'd1: begin
			block_w0_we = 1'b1;
			block_w1_we = 1'b1;
			block_w2_we = 1'b1;
			block_w3_we = 1'b1;
		end
		3'd2: begin
			case(sword_ctr_reg)
				2'h0: begin
					block_w0_we = 1'b1;
				end
				2'h1: begin
					block_w1_we = 1'b1;
				end
				2'h2: begin
					block_w2_we = 1'b1;
				end
				2'h3: begin
					block_w3_we = 1'b1;
				end
			endcase
		end
		3'd3: begin
			block_w0_we = 1'b1;
			block_w1_we = 1'b1;
			block_w2_we = 1'b1;
			block_w3_we = 1'b1;
		end
		3'd4: begin
			block_w0_we = 1'b1;
			block_w1_we = 1'b1;
			block_w2_we = 1'b1;
			block_w3_we = 1'b1;
		end
	endcase
 end
 */
 assign block_w0_we = update_type1 | (update_type2 & sword_ctr0) | update_type3 | update_type4;
 assign block_w1_we = update_type1 | (update_type2 & sword_ctr1) | update_type3 | update_type4;
 assign block_w2_we = update_type1 | (update_type2 & sword_ctr2) | update_type3 | update_type4;
 assign block_w3_we = update_type1 | (update_type2 & sword_ctr3) | update_type3 | update_type4;
 
 //----------------------------------------------------------------
 // sword_ctr
 //
 // The subbytes word counter with reset and increase logic.
 //----------------------------------------------------------------
 /*
 always@(*) begin
	sword_ctr_new = 2'h0;
	sword_ctr_we  = 1'b0;
	if(sword_ctr_rst) begin
		sword_ctr_new = 2'h0;
		sword_ctr_we  = 1'b1;
	end
	else if(sword_ctr_inc) begin
		sword_ctr_new = sword_ctr_reg + 1'b1;
		sword_ctr_we  = 1'b1;
	end
 end
 */
 wire [1:0] sword_ctr_reg_p1;
 assign sword_ctr_reg_p1 = sword_ctr_reg + 1'b1;
 assign sword_ctr_new = {(2){sword_ctr_inc}} & sword_ctr_reg_p1;
 assign sword_ctr_we = sword_ctr_rst | sword_ctr_inc;
 
 //----------------------------------------------------------------
 // round_ctr
 //
 // The round counter with reset and increase logic.
 //----------------------------------------------------------------
 /*
 always@(*) begin
	round_ctr_new = 4'h0;
	round_ctr_we  = 1'b0;
	if(round_ctr_rst) begin
		round_ctr_new = 4'h0;
		round_ctr_we  = 1'b1;
	end
	else if(round_ctr_inc) begin
		round_ctr_new = round_ctr_reg + 1'b1;
		round_ctr_we  = 1'b1;
	end
 end
 */
 wire [3:0] round_ctr_reg_p1;
 assign round_ctr_reg_p1 = round_ctr_reg + 1'b1;
 assign round_ctr_new = {(4){round_ctr_inc}} & round_ctr_reg_p1;
 assign round_ctr_we = round_ctr_rst | round_ctr_inc;
 
 //----------------------------------------------------------------
 // encipher_ctrl
 //
 // The FSM that controls the encipher operations.
 //----------------------------------------------------------------
 /*
 always@(*) begin: encipherctrl
	reg [3:0] num_rounds;
	
	// Default assignments.
	sword_ctr_inc = 1'b0;
	sword_ctr_rst = 1'b0;
	round_ctr_inc = 1'b0;
	round_ctr_rst = 1'b0;
	ready_new     = 1'b0;
	ready_we      = 1'b0;
	update_type   = 3'd0;
	enc_ctrl_new  = 2'd0;
	enc_ctrl_we   = 1'b0;
	
	if(iKeylen)	num_rounds = 4'he;	//AES256_ROUNDS
	else		num_rounds = 4'ha;	//AES128_ROUNDS

	case(enc_ctrl_reg)
		2'd0: begin
			if(iNext) begin
				round_ctr_rst = 1'b1;
				ready_new     = 1'b0;
				ready_we      = 1'b1;
				enc_ctrl_new  = 2'd1;
				enc_ctrl_we   = 1'b1;
			end
		end
		2'd1: begin
			round_ctr_inc = 1'b1;
			sword_ctr_rst = 1'b1;
			update_type   = 3'd1;
			enc_ctrl_new  = 2'd2;
			enc_ctrl_we   = 1'b1;
		end
		2'd2: begin
			sword_ctr_inc = 1'b1;
			update_type   = 3'd2;
			if(sword_ctr3) begin
				enc_ctrl_new  = 2'd3;
				enc_ctrl_we   = 1'b1;
			end
		end
		2'd3: begin
			sword_ctr_rst = 1'b1;
			round_ctr_inc = 1'b1;
			if(round_ctr_reg_num_rounds) begin
				update_type   = 3'd3;
				enc_ctrl_new  = 2'd2;
				enc_ctrl_we   = 1'b1;
			end
			else begin
				update_type  = 3'd4;
				ready_new    = 1'b1;
				ready_we     = 1'b1;
				enc_ctrl_new = 2'd0;
				enc_ctrl_we  = 1'b1;
			end
		end
	endcase
 end
 */
 
 /*
 always@(*) begin
	case(enc_ctrl_reg)
		2'd0: begin
			sword_ctr_inc = 1'b0;
			sword_ctr_rst = 1'b0;
		end
		2'd1: begin
			sword_ctr_inc = 1'b0;
			sword_ctr_rst = 1'b1;
		end
		2'd2: begin
			sword_ctr_inc = 1'b1;
			sword_ctr_rst = 1'b0;
		end
		2'd3: begin
			sword_ctr_inc = 1'b0;
			sword_ctr_rst = 1'b1;
		end
	endcase
 end
 */
 assign sword_ctr_inc = enc_ctrl2;
 assign sword_ctr_rst = enc_ctrl1 | enc_ctrl3;
 
 /*
 always@(*) begin
	case(enc_ctrl_reg)
		2'd0: begin
			round_ctr_inc = 1'b0;
			if(iNext)	round_ctr_rst = 1'b1;
			else		round_ctr_rst = 1'b0;
		end
		2'd1: begin
			round_ctr_inc = 1'b1;
			round_ctr_rst = 1'b0;
		end
		2'd2: begin
			round_ctr_inc = 1'b0;
			round_ctr_rst = 1'b0;
		end
		2'd3: begin
			round_ctr_inc = 1'b1;
			round_ctr_rst = 1'b0;
		end
	endcase
 end
 */
 assign round_ctr_inc = enc_ctrl1 | enc_ctrl3;
 assign round_ctr_rst = enc_ctrl0 & iNext;
 
 /*
 always@(*) begin
	case(enc_ctrl_reg)
		2'd0: begin
			ready_new = 1'b0;
			if(iNext)	ready_we = 1'b1;
			else		ready_we = 1'b0;
		end
		2'd1: begin
			ready_new = 1'b0;
			ready_we  = 1'b0;
		end
		2'd2: begin
			ready_new = 1'b0;
			ready_we  = 1'b0;
		end
		2'd3: begin
			if(round_ctr_reg_num_roundss) begin
				ready_new = 1'b0;
				ready_we  = 1'b0;
			end
			else begin
				ready_new = 1'b1;
				ready_we  = 1'b1;
			end
		end
	endcase
 end
 */
 assign ready_new = enc_ctrl3 & ~round_ctr_reg_num_rounds;
 assign ready_we = (enc_ctrl0 & iNext) | ready_new;
 
 /*
 always@(*) begin
	case(enc_ctrl_reg)
		2'd0: begin
			update_type = 3'd0;
		end
		2'd1: begin
			update_type = 3'd1;
		end
		2'd2: begin
			update_type = 3'd2;
		end
		2'd3: begin
			if(round_ctr_reg_num_rounds)	update_type = 3'd3;
			else							update_type = 3'd4;
		end
	endcase
 end
 */
 assign update_type[0] = enc_ctrl1 | (enc_ctrl3 & round_ctr_reg_num_rounds);
 assign update_type[1] = enc_ctrl2 | (enc_ctrl3 & round_ctr_reg_num_rounds);
 assign update_type[2] = enc_ctrl3 & ~round_ctr_reg_num_rounds;
 
 /*
 always@(*) begin
	case(enc_ctrl_reg)
		2'd0: begin
			if(iNext) begin
				enc_ctrl_new = 2'd1;
				enc_ctrl_we  = 1'b1;
			end
			else begin
				enc_ctrl_new = 2'd0;
				enc_ctrl_we  = 1'b0;
			end
		end
		2'd1: begin
			enc_ctrl_new = 2'd2;
			enc_ctrl_we  = 1'b1;
		end
		2'd2: begin
			if(sword_ctr3) begin
				enc_ctrl_new = 2'd3;
				enc_ctrl_we  = 1'b1;
			end
			else begin
				enc_ctrl_new = 2'd0;
				enc_ctrl_we  = 1'b0;
			end
		end
		2'd3: begin
			enc_ctrl_we = 1'b1;
			if(round_ctr_reg_num_rounds)	enc_ctrl_new = 2'd2;
			else							enc_ctrl_new = 2'd0;
		end
	endcase
 end
 */
 assign enc_ctrl_new[0] = (enc_ctrl0 & iNext) | (enc_ctrl2 & sword_ctr3);
 assign enc_ctrl_new[1] = enc_ctrl1 | (enc_ctrl2 & sword_ctr3) | (enc_ctrl3 & round_ctr_reg_num_rounds);
 assign enc_ctrl_we = (enc_ctrl0 & iNext) | enc_ctrl1 | (enc_ctrl2 & sword_ctr3) | enc_ctrl3;
 
endmodule

//======================================================================
//
// aes_sboxv2.v
// ----------
// The AES S-box. Basically a 256 Byte ROM. This implementation
// contains four parallel S-boxes to handle a 32 bit word.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2014, Secworks Sweden AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module aes_sboxv2(
	input	[31:0]	in,
	output	[31:0]	out
);

 aes_sub_sboxv2 sub_box_3 (
	.in		(in[31:24]),
	.out	(out[31:24])
 );
 
 aes_sub_sboxv2 sub_box_2 (
	.in		(in[23:16]),
	.out	(out[23:16])
 );
 
 aes_sub_sboxv2 sub_box_1 (
	.in		(in[15:8]),
	.out	(out[15:8])
 );
 
 aes_sub_sboxv2 sub_box_0 (
	.in		(in[7:0]),
	.out	(out[7:0])
 );

endmodule

module ghash_block_v2 (
input 	iClk,
input 	iRstn,
	//control
input iNext,
	//data
input 	[0:127] iCtext,
input 	iCtext_valid,
input 	[0:127] iY,
input 	[0:127] iHashkey,
input 	iHashkey_valid,
	//output
output 	[0:127] oY,
output 	oY_valid
);

wire [0:127] wXor;

gfmul_v2 GFMUL(
.iClk(iClk),
.iRstn(iRstn),
	//control
.iNext(iNext),
	//data
.iCtext(wXor),
.iCtext_valid(iCtext_valid),
.iHashkey(iHashkey),
.iHashkey_valid(iHashkey_valid),
	//output
.oResult(oY),
.oResult_valid(oY_valid)
);

assign wXor = iCtext ^ iY;

endmodule

module aes_gcm_v4_TOP(
//6 pins
input ICLK_core,
input IRSTN_core,
input [0:3] ICTRL_core,
output OREADY_core,

//355 pins
input [0:95] IIV_core,
input IIV_VALID_core,
input [0:255] IKEY_core,
input IKEY_VALID_core,
input IKEYLEN_core,

//130 pins
input [0:127] IAAD_core,
input IAAD_VALID_core,

//130 pins
input [0:127] IBLOCK_core,
input IBLOCK_VALID_core,

//129 pins
input [0:127] ITAG_core,
input ITAG_VALID_core,

input [3:0] IBLOCK_BYTES_core,

//259 pins
output [0:127] ORESULT_core,
output ORESULT_VALID_core,
output [0:127] OTAG_core,
output OTAG_VALID_core,
output OAUTHENTIC_core
);

aes_gcm_v4 U1(
.iClk(ICLK_core),
.iRstn(IRSTN_core),
.iCtrl(ICTRL_core),
.oReady(OREADY_core),

.iIV(IIV_core),
.iIV_valid(IIV_VALID_core),
.iKey(IKEY_core),
.iKey_valid(IKEY_VALID_core),
.iKeylen(IKEYLEN_core),

.iAad(IAAD_core), //Len
.iAad_valid(IAAD_VALID_core),

.iBlock(IBLOCK_core),
.iBlock_valid(IBLOCK_VALID_core),

.iTag(ITAG_core),
.iTag_valid(ITAG_VALID_core),

.iBlock_bytes(IBLOCK_BYTES_core),

.oResult(ORESULT_core),
.oResult_valid(ORESULT_VALID_core),
.oTag(OTAG_core),
.oTag_valid(OTAG_VALID_core),
.oAuthentic(OAUTHENTIC_core)
);

endmodule

`undef WT_DCACHE
`undef DISABLE_TRACER
`undef SRAM_NO_INIT
`undef VERILATOR

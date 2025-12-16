`define WT_DCACHE
`define DISABLE_TRACER
`define SRAM_NO_INIT
`define VERILATOR
module sha_pad(
	pad_message,
	pad_en,
	pad_special,
	pad_line,
	pad_last,
	block_idx,
	col_idx,
	ibitcount,
	imessage,
	mode64	);

	output	[63:0]	pad_message;
	
	input		pad_en;
	input		pad_special;
	input	[3:0]	pad_line;
	input		pad_last;
	input	[3:0]	block_idx;
	input	[2:0]	col_idx;
	input	[127:0]	ibitcount;
	input	[63:0]	imessage;
	input		mode64;
	
	wire		allow_pad = pad_en & (pad_line >= block_idx);
	wire	[7:0]	msg_0 = imessage[7:0];
	wire	[7:0]	msg_1 = imessage[15:8];
	wire	[7:0]	msg_2 = imessage[23:16];
	wire	[7:0]	msg_3 = imessage[31:24];
	wire	[7:0]	msg_4 = imessage[39:32];
	wire	[7:0]	msg_5 = imessage[47:40];
	wire	[7:0]	msg_6 = imessage[55:48];
	wire	[7:0]	msg_7 = imessage[63:56];
	
	wire	[7:0]	pmsg_0 = (col_idx==3'd7) ? ( (pad_line==block_idx) ? 8'h80 : 8'h00 ) : 8'h00;
	wire	[7:0]	pmsg_1 = (col_idx==3'd6) ? ( (pad_line==block_idx) ? 8'h80 : 8'h00 ) : ( (col_idx>3'd6) ? imessage[15:8] : 8'h00 );
	wire	[7:0]	pmsg_2 = (col_idx==3'd5) ? ( (pad_line==block_idx) ? 8'h80 : 8'h00 ) : ( (col_idx>3'd5) ? imessage[23:16] : 8'h00 );
	wire	[7:0]	pmsg_3 = (col_idx==3'd4) ? ( (pad_line==block_idx) ? 8'h80 : 8'h00 ) : ( (col_idx>3'd4) ? imessage[31:24] : 8'h00 );
	wire	[7:0]	pmsg_4 = (col_idx==3'd3) ? ( (pad_line==block_idx) ? 8'h80 : 8'h00 ) : ( (col_idx>3'd3) ? imessage[39:32] : 8'h00 );
	wire	[7:0]	pmsg_5 = (col_idx==3'd2) ? ( (pad_line==block_idx) ? 8'h80 : 8'h00 ) : ( (col_idx>3'd2) ? imessage[47:40] : 8'h00 );
	wire	[7:0]	pmsg_6 = (col_idx==3'd1) ? ( (pad_line==block_idx) ? 8'h80 : 8'h00 ) : ( (col_idx>3'd1) ? imessage[55:48] : 8'h00 );
	wire	[7:0]	pmsg_7 = (col_idx==3'd0) ? ( (pad_line==block_idx) ? 8'h80 : 8'h00 ) : imessage[63:56] ;
	
	wire	[7:0]	omsg_0 = (allow_pad) ? pmsg_0 : msg_0;
	wire	[7:0]	omsg_1 = (allow_pad) ? pmsg_1 : msg_1;
	wire	[7:0]	omsg_2 = (allow_pad) ? pmsg_2 : msg_2;
	wire	[7:0]	omsg_3 = (allow_pad) ? pmsg_3 : msg_3;
	wire	[7:0]	omsg_4 = (allow_pad) ? pmsg_4 : msg_4;
	wire	[7:0]	omsg_5 = (allow_pad) ? pmsg_5 : msg_5;
	wire	[7:0]	omsg_6 = (allow_pad) ? pmsg_6 : msg_6;
	wire	[7:0]	omsg_7 = (allow_pad) ? pmsg_7 : msg_7;
	
	reg	[63:0]	omsg;
	
	always@(*) begin
		if(pad_en) begin
			if(pad_last)			omsg = {omsg_7, omsg_6, omsg_5, omsg_4, omsg_3, omsg_2, omsg_1, omsg_0};
			else if(pad_line==4'd14)	omsg = ibitcount[127:64];
			else if(pad_line==4'd15)	omsg = ibitcount[63:0];
			else				omsg = {omsg_7, omsg_6, omsg_5, omsg_4, omsg_3, omsg_2, omsg_1, omsg_0}; end
		else if(pad_special) begin
			//if(pad_line==4'd0) omsg = mode64? 64'h8000_0000_0000_0000: 64'h0000_0000_8000_0000;
			if(pad_line==4'd0)		omsg = {mode64 & ~pad_last, 31'd0, ~mode64 & ~pad_last, 31'd0};
			else if(pad_line==4'd14)	omsg = ibitcount[127:64];
			else if(pad_line==4'd15)	omsg = ibitcount[63:0];
			else				omsg = 64'd0; end
		else omsg = imessage;
	end
	
	assign pad_message = omsg;
	
endmodule
module hmac_padding (
	pad,
	skey,
	padmode	);

	parameter MODE_INNER = 1'b0,
		MODE_OUTER = 1'b1;
	
	output	[63:0]	pad;

	input	[63:0]	skey;
	input		padmode;

	assign pad =  skey ^ {8{1'b0, padmode, ~padmode, 1'b1, padmode, 1'b1, ~padmode, 1'b0}};
	
endmodule
/*
	sigma0 (256) = rotr7(x) ^ rotr18(x) ^ shiftr3(x)
*/

module s0_32(
	out,
	x	);
	
	output	[31:0]	out;
	
	input	[31:0]	x;
	
	wire	[31:0]	tmp1, tmp2, tmp3;
	
	assign tmp1 = {x[6:0],  x[31:7] }; // rotate right 7
	assign tmp2 = {x[17:0], x[31:18]}; // rotate right 18
	assign tmp3 = {3'd0,    x[31:3] }; // shift  right 3
		
	assign out = tmp1 ^ tmp2 ^ tmp3;
	
endmodule
/*
	SIGMA0 (256) = rotr2(x) ^ rotr13(x) ^ rotr22(x)
*/

module SIG0_32(
	out,
	x	);
	
	output	[31:0]	out;
	
	input	[31:0]	x;
	
	wire	[31:0]	tmp1, tmp2, tmp3;
	
	assign tmp1 = {x[1:0],  x[31:2] }; // rotate right 2
	assign tmp2 = {x[12:0], x[31:13]}; // rotate right 13
	assign tmp3 = {x[21:0], x[31:22]}; // rotate right 22
		
	assign out = tmp1 ^ tmp2 ^ tmp3;

endmodule

	
module adder_64 (
	sum,
	in_0,
	in_1	);

	output	[63:0]	sum;
	
	input	[63:0]	in_0, in_1;
	
	assign sum = in_0 + in_1;

endmodule
module init_ROM (
	clk,
	addr,
	dout,
	mode64	);
	
	input		clk;
	input	[3:0]	addr;
	input		mode64;
	
	output	[63:0]	dout;
	
	reg	[63:0]	r_dout;
	
	reg	[63:0]	wdata;

	always@(*)begin
		case(addr)
			4'd0:  wdata = 64'h5be0cd19137e2179;
			4'd1:  wdata = 64'h1f83d9abfb41bd6b;
			4'd2:  wdata = 64'h9b05688c2b3e6c1f;
			4'd3:  wdata = 64'h510e527fade682d1;
			4'd4:  wdata = 64'ha54ff53a5f1d36f1;
			4'd5:  wdata = 64'h3c6ef372fe94f82b;
			4'd6:  wdata = 64'hbb67ae8584caa73b;
			4'd7:  wdata = 64'h6a09e667f3bcc908;
			4'd8:  wdata = 64'h47b5481dbefa4fa4;
			4'd9:  wdata = 64'hdb0c2e0d64f98fa7;
			4'd10: wdata = 64'h8eb44a8768581511;
			4'd11: wdata = 64'h67332667ffc00b31;
			4'd12: wdata = 64'h152fecd8f70e5939;
			4'd13: wdata = 64'h9159015a3070dd17;
			4'd14: wdata = 64'h629a292a367cd507;
			4'd15: wdata = 64'hcbbb9d5dc1059ed8;
			default: wdata = 64'd0;
		endcase
	end

	always@(posedge clk) begin
		r_dout <= wdata;
	end
	
	assign dout[31:0] = (mode64) ? r_dout[31:0] : r_dout[63:32];
	assign dout[63:32] = {32{mode64}} & r_dout[63:32];
	
endmodule

/*
	sigma0 (512) = rotr1(x) ^ rotr8(x) ^ shiftr7(x)
*/

module s0_64 (
	out,
	x	);
	
	output	[63:0]	out;
	
	input	[63:0]	x;
	
	wire	[63:0]	tmp1, tmp2, tmp3;
	
	assign tmp1 = {x[0:0], x[63:1]}; // rotate right 1
	assign tmp2 = {x[7:0], x[63:8]}; // rotate right 8
	assign tmp3 = {7'd0,   x[63:7]}; // shift  right 7
		
	assign out = tmp1 ^ tmp2 ^ tmp3;

endmodule
/*
	SIGMA0 (512) = rotr28(x) ^ rotr34(x) ^ rotr39(x)
*/

module SIG0_64(
	out,
	x	);
	
	output	[63:0]	out;
	
	input	[63:0]	x;
	
	wire	[63:0]	tmp1, tmp2, tmp3;
	
	assign tmp1 = {x[27:0], x[63:28]}; // rotate right 28
	assign tmp2 = {x[33:0], x[63:34]}; // rotate right 34
	assign tmp3 = {x[38:0], x[63:39]}; // rotate right 39

	assign out = tmp1 ^ tmp2 ^ tmp3;

endmodule

	
/*
	out = xy ^ ~xz
*/

module ch (
	out,
	x,
	y,
	z	);

	output	[63:0]	out;
	
	input	[63:0]	x, y, z;

	wire	[63:0]	and1, and2;
		
	assign and1 = x & y;
	assign and2 = ~x & z;
			
	assign out = and1 ^ and2;
	
endmodule
module K_ROM (
	clk,
	addr,
	dout,
	mode64	);
	
	input		clk;
	input	[6:0]	addr;
	input		mode64;
	
	output	[63:0]	dout;
	
	reg	[63:0]	r_dout;
	
	reg	[63:0]	wdata;
	
	always@(*) begin
		case(addr)
			7'd0:  wdata = 64'h428a2f98d728ae22;
			7'd1:  wdata = 64'h7137449123ef65cd;
			7'd2:  wdata = 64'hb5c0fbcfec4d3b2f;
			7'd3:  wdata = 64'he9b5dba58189dbbc;
			7'd4:  wdata = 64'h3956c25bf348b538;
			7'd5:  wdata = 64'h59f111f1b605d019;
			7'd6:  wdata = 64'h923f82a4af194f9b;
			7'd7:  wdata = 64'hab1c5ed5da6d8118;
			7'd8:  wdata = 64'hd807aa98a3030242;
			7'd9:  wdata = 64'h12835b0145706fbe;
			7'd10: wdata = 64'h243185be4ee4b28c;
			7'd11: wdata = 64'h550c7dc3d5ffb4e2;
			7'd12: wdata = 64'h72be5d74f27b896f;
			7'd13: wdata = 64'h80deb1fe3b1696b1;
			7'd14: wdata = 64'h9bdc06a725c71235;
			7'd15: wdata = 64'hc19bf174cf692694;
			7'd16: wdata = 64'he49b69c19ef14ad2;
			7'd17: wdata = 64'hefbe4786384f25e3;
			7'd18: wdata = 64'h0fc19dc68b8cd5b5;
			7'd19: wdata = 64'h240ca1cc77ac9c65;
			7'd20: wdata = 64'h2de92c6f592b0275;
			7'd21: wdata = 64'h4a7484aa6ea6e483;
			7'd22: wdata = 64'h5cb0a9dcbd41fbd4;
			7'd23: wdata = 64'h76f988da831153b5;
			7'd24: wdata = 64'h983e5152ee66dfab;
			7'd25: wdata = 64'ha831c66d2db43210;
			7'd26: wdata = 64'hb00327c898fb213f;
			7'd27: wdata = 64'hbf597fc7beef0ee4;
			7'd28: wdata = 64'hc6e00bf33da88fc2;
			7'd29: wdata = 64'hd5a79147930aa725;
			7'd30: wdata = 64'h06ca6351e003826f;
			7'd31: wdata = 64'h142929670a0e6e70;
			7'd32: wdata = 64'h27b70a8546d22ffc;
			7'd33: wdata = 64'h2e1b21385c26c926;
			7'd34: wdata = 64'h4d2c6dfc5ac42aed;
			7'd35: wdata = 64'h53380d139d95b3df;
			7'd36: wdata = 64'h650a73548baf63de;
			7'd37: wdata = 64'h766a0abb3c77b2a8;
			7'd38: wdata = 64'h81c2c92e47edaee6;
			7'd39: wdata = 64'h92722c851482353b;
			7'd40: wdata = 64'ha2bfe8a14cf10364;
			7'd41: wdata = 64'ha81a664bbc423001;
			7'd42: wdata = 64'hc24b8b70d0f89791;
			7'd43: wdata = 64'hc76c51a30654be30;
			7'd44: wdata = 64'hd192e819d6ef5218;
			7'd45: wdata = 64'hd69906245565a910;
			7'd46: wdata = 64'hf40e35855771202a;
			7'd47: wdata = 64'h106aa07032bbd1b8;
			7'd48: wdata = 64'h19a4c116b8d2d0c8;
			7'd49: wdata = 64'h1e376c085141ab53;
			7'd50: wdata = 64'h2748774cdf8eeb99;
			7'd51: wdata = 64'h34b0bcb5e19b48a8;
			7'd52: wdata = 64'h391c0cb3c5c95a63;
			7'd53: wdata = 64'h4ed8aa4ae3418acb;
			7'd54: wdata = 64'h5b9cca4f7763e373;
			7'd55: wdata = 64'h682e6ff3d6b2b8a3;
			7'd56: wdata = 64'h748f82ee5defb2fc;
			7'd57: wdata = 64'h78a5636f43172f60;
			7'd58: wdata = 64'h84c87814a1f0ab72;
			7'd59: wdata = 64'h8cc702081a6439ec;
			7'd60: wdata = 64'h90befffa23631e28;
			7'd61: wdata = 64'ha4506cebde82bde9;
			7'd62: wdata = 64'hbef9a3f7b2c67915;
			7'd63: wdata = 64'hc67178f2e372532b;
			7'd64: wdata = 64'hca273eceea26619c;
			7'd65: wdata = 64'hd186b8c721c0c207;
			7'd66: wdata = 64'heada7dd6cde0eb1e;
			7'd67: wdata = 64'hf57d4f7fee6ed178;
			7'd68: wdata = 64'h06f067aa72176fba;
			7'd69: wdata = 64'h0a637dc5a2c898a6;
			7'd70: wdata = 64'h113f9804bef90dae;
			7'd71: wdata = 64'h1b710b35131c471b;
			7'd72: wdata = 64'h28db77f523047d84;
			7'd73: wdata = 64'h32caab7b40c72493;
			7'd74: wdata = 64'h3c9ebe0a15c9bebc;
			7'd75: wdata = 64'h431d67c49c100d4c;
			7'd76: wdata = 64'h4cc5d4becb3e42b6;
			7'd77: wdata = 64'h597f299cfc657e2a;
			7'd78: wdata = 64'h5fcb6fab3ad6faec;
			7'd79: wdata = 64'h6c44198c4a475817;
			default: wdata = 64'd0;
		endcase
	end

	always@(posedge clk) begin
		r_dout <= wdata;
	end
	
	assign dout[31:0] = (mode64) ? r_dout[31:0] : r_dout[63:32];
	assign dout[63:32] = {32{mode64}} & r_dout[63:32];
	
endmodule

/*
	sigma1 (256) = rotr17(x) ^ rotr19(x) ^ shiftr10(x)
*/

module s1_32(
	out,
	x	);
	
	output	[31:0]	out;
	
	input	[31:0]	x;
	
	wire	[31:0]	tmp1, tmp2, tmp3;
	
	
	assign tmp1 = {x[16:0], x[31:17]}; // rotate right 7
	assign tmp2 = {x[18:0], x[31:19]}; // rotate right 18
	assign tmp3 = {10'd0,   x[31:10]}; // shift  right 10
		
	assign out = tmp1 ^ tmp2 ^ tmp3;
	
endmodule
/*
	SIGMA1 (256) = rotr6(x) ^ rotr11(x) ^ rotr25(x)
*/

module SIG1_32(
	out,
	x	);	

	output	[31:0]	out;
	
	input	[31:0]	x;
	
	wire	[31:0]	tmp1, tmp2, tmp3;
	
	assign tmp1 = {x[5:0],  x[31:6] }; // rotate right 6
	assign tmp2 = {x[10:0], x[31:11]}; // rotate right 11
	assign tmp3 = {x[24:0], x[31:25]}; // rotate right 25
		
	assign out = tmp1 ^ tmp2 ^ tmp3;

endmodule
module compress (
	clk,
	resetn,
	init,	// initial data
	load,	// load digest
	run,	// run compression
	read,
	hout,
	K,
	W,
	load_data,
	mode64	);

	input		clk;
	input		resetn;
	input		init, load, run, read;
	
	output	[63:0]	hout;
	
	input	[63:0]	K, W;
	input	[63:0]	load_data;
	input		mode64;	
	
	reg	[63:0]	A, B, C, D, E, F, G, H;
	reg	[63:0]	h0, h1, h2, h3, h4, h5, h6, h7;
	
	
// Computation 64 bits
	wire	[63:0]	A_new, E_new;
	wire	[63:0]	w1_64, w2, w3_64, w4, w5, w6;
	wire	[31:0]	w1_32, w3_32;
	wire	[63:0]	w1_select, w3_select;
	
	wire	[63:0]	T1, T2;
	wire	[63:0]	A_select, E_select;
	
	wire	[63:0]	new_dm = h7 + H;
	
	always@(posedge clk) begin
		if(!resetn)	{h0, A, E} <= 192'd0;
		else if(init)	{h0, A, E} <= {load_data, load_data, D};
		else if(run)	{h0, A, E} <= {h0, A_new, E_new};
		else if(load)	{h0, A, E} <= {new_dm, new_dm, D};
		else if(read)	{h0, A, E} <= {h7, A, E};
		else		{h0, A, E} <= {h0, A, E};
	end
	always@(posedge clk) begin
		if(init|run|load)	{B,C,D,F,G,H} <= {A,B,C,E,F,G};
		else			{B,C,D,F,G,H} <= {B,C,D,F,G,H};
	end
	always@(posedge clk) begin
		if(init|load|read)	{h1,h2,h3,h4,h5,h6,h7} <= {h0,h1,h2,h3,h4,h5,h6};
		else			{h1,h2,h3,h4,h5,h6,h7} <= {h1,h2,h3,h4,h5,h6,h7};
	end
	
	SIG0_64 SIG0_64_inst0 (
		.out	(w1_64),
		.x	(A)	);

	SIG0_32 SIG0_32_inst0 (
		.out	(w1_32),
		.x	(A[31:0])	);
	
	maj maj_inst0 (
		.out	(w2),
		.x	(A),
		.y	(B),
		.z	(C)	);

	SIG1_64 SIG1_64_inst0 (
		.out	(w3_64),
		.x	(E)	);	
	
	SIG1_32 SIG1_32_inst0 (
		.out	(w3_32),
		.x	(E[31:0])	);	
	
	ch ch_inst0 (
		.out	(w4),
		.x	(E),
		.y	(F),
		.z	(G)	);
	
	triple_adder_64 t3_adder_inst0 (
		.s	(w5),
		.carry	(),
		.a	(H),
		.b	(K),
		.c	(W)	);

	assign w1_select = (mode64) ? w1_64 : w1_32;
	assign w3_select = (mode64) ? w3_64 : w3_32;
	assign w6 = D;

	//======================
	
	adder_64 adder_64_w1w2 (
		.sum	(T2),
		.in_0	(w1_select),
		.in_1	(w2)	);

	triple_adder_64 t3_adder_inst1 (
		.s	(T1),
		.carry	(),
		.a	(w3_select),
		.b	(w4),
		.c	(w5)	);
	
	adder_64 adder_T1T2 (
		.sum	(A_new),
		.in_0	(T1),
		.in_1	(T2)	);
	
	adder_64 adder_T1w6 (
		.sum	(E_new),
		.in_0	(T1),
		.in_1	(w6)	);
	
	assign hout = h7;
endmodule
/*
	out = xy ^ xz ^ yz
*/

module maj (
	out,
	x,
	y,
	z	);
	
	output	[63:0]	out;
	
	input	[63:0]	x, y, z;

	wire	[63:0]	and1, and2, and3;
	
	assign and1 = x & y;
	assign and2 = x & z;
	assign and3 = y & z;
			
	assign out = and1 ^ and2 ^ and3;
	
endmodule
/*
	sigma1 (512) = rotr19(x) ^ rotr61(x) ^ shiftr6(x)
*/

module s1_64(
	out,
	x	);
	
	output	[63:0]	out;
	
	input	[63:0]	x;
	
	wire	[63:0]	tmp1, tmp2, tmp3;
	
	assign tmp1 = {x[18:0], x[63:19]}; // rotate right 19
	assign tmp2 = {x[60:0], x[63:61]}; // rotate right 61
	assign tmp3 = {6'd0,    x[63:6] }; // shift  right 6
		
	assign out = tmp1 ^ tmp2 ^ tmp3;
	
endmodule
/*
	SIGMA1 (512) = rotr14(x) ^ rotr18(x) ^ rotr41(x)
*/

module SIG1_64(
	out,
	x	);
	
	output	[63:0]	out;
	
	input	[63:0]	x;
	
	wire	[63:0]	tmp1, tmp2, tmp3;
	
	assign tmp1 = {x[13:0], x[63:14]}; // rotate right 14
	assign tmp2 = {x[17:0], x[63:18]}; // rotate right 18
	assign tmp3 = {x[40:0], x[63:41]}; // rotate right 41
		
	assign out = tmp1 ^ tmp2 ^ tmp3;

endmodule
module csa64 (
	s,
	cout,
	a,
	b,
	c	);

	output	[64:0]	s;
	output		cout;
	
	input	[63:0]	a, b, c;

	wire	[63:0]	s1, c1;
	
	wire	[64:0]	s2 = {1'b0, s1}; 
	wire	[64:0]	c2 = {c1, 1'b0};
	
	fa fa0_inst0 (s1[0], c1[0], a[0], b[0], c[0]);
	fa fa0_inst1 (s1[1], c1[1], a[1], b[1], c[1]);
	fa fa0_inst2 (s1[2], c1[2], a[2], b[2], c[2]);
	fa fa0_inst3 (s1[3], c1[3], a[3], b[3], c[3]);
	fa fa0_inst4 (s1[4], c1[4], a[4], b[4], c[4]);
	fa fa0_inst5 (s1[5], c1[5], a[5], b[5], c[5]);
	fa fa0_inst6 (s1[6], c1[6], a[6], b[6], c[6]);
	fa fa0_inst7 (s1[7], c1[7], a[7], b[7], c[7]);
	fa fa0_inst8 (s1[8], c1[8], a[8], b[8], c[8]);
	fa fa0_inst9 (s1[9], c1[9], a[9], b[9], c[9]);
	fa fa0_inst10 (s1[10], c1[10], a[10], b[10], c[10]);
	fa fa0_inst11 (s1[11], c1[11], a[11], b[11], c[11]);
	fa fa0_inst12 (s1[12], c1[12], a[12], b[12], c[12]);
	fa fa0_inst13 (s1[13], c1[13], a[13], b[13], c[13]);
	fa fa0_inst14 (s1[14], c1[14], a[14], b[14], c[14]);
	fa fa0_inst15 (s1[15], c1[15], a[15], b[15], c[15]);
	fa fa0_inst16 (s1[16], c1[16], a[16], b[16], c[16]);
	fa fa0_inst17 (s1[17], c1[17], a[17], b[17], c[17]);
	fa fa0_inst18 (s1[18], c1[18], a[18], b[18], c[18]);
	fa fa0_inst19 (s1[19], c1[19], a[19], b[19], c[19]);
	fa fa0_inst20 (s1[20], c1[20], a[20], b[20], c[20]);
	fa fa0_inst21 (s1[21], c1[21], a[21], b[21], c[21]);
	fa fa0_inst22 (s1[22], c1[22], a[22], b[22], c[22]);
	fa fa0_inst23 (s1[23], c1[23], a[23], b[23], c[23]);
	fa fa0_inst24 (s1[24], c1[24], a[24], b[24], c[24]);
	fa fa0_inst25 (s1[25], c1[25], a[25], b[25], c[25]);
	fa fa0_inst26 (s1[26], c1[26], a[26], b[26], c[26]);
	fa fa0_inst27 (s1[27], c1[27], a[27], b[27], c[27]);
	fa fa0_inst28 (s1[28], c1[28], a[28], b[28], c[28]);
	fa fa0_inst29 (s1[29], c1[29], a[29], b[29], c[29]);
	fa fa0_inst30 (s1[30], c1[30], a[30], b[30], c[30]);
	fa fa0_inst31 (s1[31], c1[31], a[31], b[31], c[31]);
	fa fa0_inst32 (s1[32], c1[32], a[32], b[32], c[32]);
	fa fa0_inst33 (s1[33], c1[33], a[33], b[33], c[33]);
	fa fa0_inst34 (s1[34], c1[34], a[34], b[34], c[34]);
	fa fa0_inst35 (s1[35], c1[35], a[35], b[35], c[35]);
	fa fa0_inst36 (s1[36], c1[36], a[36], b[36], c[36]);
	fa fa0_inst37 (s1[37], c1[37], a[37], b[37], c[37]);
	fa fa0_inst38 (s1[38], c1[38], a[38], b[38], c[38]);
	fa fa0_inst39 (s1[39], c1[39], a[39], b[39], c[39]);
	fa fa0_inst40 (s1[40], c1[40], a[40], b[40], c[40]);
	fa fa0_inst41 (s1[41], c1[41], a[41], b[41], c[41]);
	fa fa0_inst42 (s1[42], c1[42], a[42], b[42], c[42]);
	fa fa0_inst43 (s1[43], c1[43], a[43], b[43], c[43]);
	fa fa0_inst44 (s1[44], c1[44], a[44], b[44], c[44]);
	fa fa0_inst45 (s1[45], c1[45], a[45], b[45], c[45]);
	fa fa0_inst46 (s1[46], c1[46], a[46], b[46], c[46]);
	fa fa0_inst47 (s1[47], c1[47], a[47], b[47], c[47]);
	fa fa0_inst48 (s1[48], c1[48], a[48], b[48], c[48]);
	fa fa0_inst49 (s1[49], c1[49], a[49], b[49], c[49]);
	fa fa0_inst50 (s1[50], c1[50], a[50], b[50], c[50]);
	fa fa0_inst51 (s1[51], c1[51], a[51], b[51], c[51]);
	fa fa0_inst52 (s1[52], c1[52], a[52], b[52], c[52]);
	fa fa0_inst53 (s1[53], c1[53], a[53], b[53], c[53]);
	fa fa0_inst54 (s1[54], c1[54], a[54], b[54], c[54]);
	fa fa0_inst55 (s1[55], c1[55], a[55], b[55], c[55]);
	fa fa0_inst56 (s1[56], c1[56], a[56], b[56], c[56]);
	fa fa0_inst57 (s1[57], c1[57], a[57], b[57], c[57]);
	fa fa0_inst58 (s1[58], c1[58], a[58], b[58], c[58]);
	fa fa0_inst59 (s1[59], c1[59], a[59], b[59], c[59]);
	fa fa0_inst60 (s1[60], c1[60], a[60], b[60], c[60]);
	fa fa0_inst61 (s1[61], c1[61], a[61], b[61], c[61]);
	fa fa0_inst62 (s1[62], c1[62], a[62], b[62], c[62]);
	fa fa0_inst63 (s1[63], c1[63], a[63], b[63], c[63]);
	
	assign {cout, s} = s2 + c2;
	
endmodule
module memory (
	clk,
	resetn,
	hmac_mode,
	sha_mode,
	pad_mode,
	update_len,
	bitcount,
	q,
	we,
	addr,
	data	);
	
	parameter SHA_MODE256 = 3'b001,
		SHA_MODE384 = 3'b010,
		SHA_MODE512 = 3'b100;
	
	parameter HMAC_MODE = 2'b10,
		SHA_MODE = 2'b01;
	
	parameter PAD_INNER = 1'b0,
		PAD_OUTER = 1'b1;

//=========================================
//======= Begin Port declarations =========
//=========================================
	input		clk;
	input		resetn;
	
	output	[1:0]	hmac_mode;
	output	[2:0]	sha_mode;
	output	[127:0]	bitcount;
	input		pad_mode;
	input		update_len;
	
	output	[63:0]	q;
	input		we;
	input	[5:0]	addr;
	input	[63:0]	data;

//=========================================
//======= End Port declarations ===========
//=========================================
	wire		mode64 = (sha_mode[2]|sha_mode[1]);
	
	// Declare the RAM variable
	reg	[4:0]	stats;
	reg	[127:0]	rbitcount;

// ========== RAM FPGA
	reg	[63:0]	q_out;
	(* ram_style = "distributed" *) reg	[63:0]	ram[0:63];
	always@(posedge clk) begin
		if(we)	ram[addr] <= data;
	end
	always@(posedge clk) begin
		if(~we)	q_out <= ram[addr];
		else	q_out <= q_out;
	end
// ========== End RAM FPGA

// ========== RAM ASIC
	/*wire	[63:0]	q_out;
	wire	[31:0]	qH, qL;
	RSPB18_128X32M4_G1 _128w32b_H (
		.CLK	(clk),
		.ME	(1'b1),		//input		: Master Enable (1: selected; 0: not selected)
		.ADR	({1'b0,addr}),	//input [6:0]	: Address
		.WE	(we),		//input		: Write Enable (1: Write;  0: Read)
		.WEM	(4'hF),		//input [3:0]	: Write Enable Mask (1: data in; 0: data not in)
		.D	(data[63:32]),	//input [31:0]	: Write Data
		.OE	(1'b1),		//input		: Output Enable (1: enable; 0: disable)
		.Q	(qH)	);	//output [31:0]	: Read Data
	RSPB18_128X32M4_G1 _128w32b_L (
		.CLK	(clk),
		.ME	(1'b1),		//input		: Master Enable (1: selected; 0: not selected)
		.ADR	({1'b0,addr}),	//input [6:0]	: Address
		.WE	(we),		//input		: Write Enable (1: Write;  0: Read)
		.WEM	(4'hF),		//input [3:0]	: Write Enable Mask (1: data in; 0: data not in)
		.D	(data[31:0]),	//input [31:0]	: Write Data
		.OE	(1'b1),		//input		: Output Enable (1: enable; 0: disable)
		.Q	(qL)	);	//output [31:0]	: Read Data
	assign q_out = {qH, qL};*/
// ========== End ASIC

	wire	[127:0]	inc = (mode64) ? 128'd1024 : 128'd512;
	//wire	[127:0]	outer_len = (mode64) ? 128'd1536 : 128'd768;
	
	always@(posedge clk) begin
		if(!resetn)			stats <= 5'b10100;
		else if(we&(addr==6'd34))	stats <= data[4:0];
		else				stats <= stats;
	end
	always@(posedge clk) begin
		if(!resetn)	rbitcount <= 128'd0;
		else if (we)begin
			if(addr==6'd32)		rbitcount <= {rbitcount[127:64],data};
			else if(addr==6'd33)	rbitcount <= {data,rbitcount[63:0]};
			else			rbitcount <= rbitcount; end
		else if(update_len&hmac_mode[1]) begin
			if(pad_mode==PAD_INNER)	rbitcount <= rbitcount + inc;
			else if(sha_mode[2])	rbitcount <= 128'd1536; // HMAC-512
			else if(sha_mode[1])	rbitcount <= 128'd1408; // HMAC-384
			else			rbitcount <= 128'd768; end // HMAC-256
		else	rbitcount <= rbitcount;
	end
	
	assign q = q_out;
	
	assign hmac_mode = stats[4:3];
	assign sha_mode = stats[2:0];
	assign bitcount = rbitcount;
	
endmodule
module sha_controller (
	clk,
	resetn,
	start,
	sha_valid,
	ready2load,
	w_load,
	w_run,
	compress_init,
	compress_load,
	comresss_run,
	Kaddr,
	init_addr,
	pad_run,
	bitcount,
	ibitcount,
	msg_valid,
	load_counter,
	load_finish,
	padreset,
	padspecial,
	pad_zero,
	pad_en,
	padnextupdate,
	padnext,
	padlast,
	mode	);
	
	parameter S_IDLE = 0, 
		S_INIT = 1,
		S_CALCPAD = 2,
		S_MSGLOAD = 3,
		S_COMPRESS = 4,
		S_WAIT = 5,
		S_UPDATE = 6,
		S_FIN = 7;
	
	parameter MODE_256 = 3'b001,
		MODE_384 = 3'b010,
		MODE_512 = 3'b100;
				
	input		clk;
	input		resetn;
	input		start;
	
	output		sha_valid;
	output		ready2load;
	
	output		w_load;
	output		w_run;
	
	output		compress_init;
	output		compress_load;
	output		comresss_run;
	
	output	[6:0]	Kaddr;
	output	[3:0]	init_addr;
	
	output		pad_run;
	output	[127:0]	bitcount;
	
	input	[127:0]	ibitcount;
	input		msg_valid;
	output	[3:0]	load_counter;
	input		load_finish;
	
	output		padreset;
	output		padspecial;
	input		pad_zero;
	input		pad_en;
	output		padnextupdate;
	input		padnext;
	input		padlast;
	
	input	[2:0]	mode;
	
	reg	[2:0]	state, next_state;
	reg	[3:0]	rloadcounter;
	
	reg		rpadreset;
	reg		rpadspecial;
	reg		rskip;
	
	wire		sidle     = (state == S_IDLE);
	wire		sinit     = (state == S_INIT);
	wire		scalcpad  = (state == S_CALCPAD);
	wire		smsgload  = (state == S_MSGLOAD);
	wire		scompress = (state == S_COMPRESS);
	wire		swait     = (state == S_WAIT);
	wire		supdate   = (state == S_UPDATE);
	wire		sfin      = (state == S_FIN);
	
	reg	[3:0]	counter_init_update;
	reg	[5:0]	counter_calcpad;
	reg	[6:0]	counter_compress;
	reg	[127:0]	rbitcount;
	
	reg		nload;
	//reg		rcomresss_run;
	reg		rw_run;
	reg		r_padnext;
	
	wire		mode64 = (mode[1]|mode[2]);
	
	wire	[127:0]	bitcount_sub = (mode64) ? 127'd1024 : 127'd512;
	
	wire	[6:0]	iter = (mode64) ? 7'd79 : 7'd63;
	wire	[6:0]	iterplusone = (mode64) ? 7'd80 : 7'd64;
	wire		compress_fin = (counter_compress==iterplusone);
	
	always@(posedge clk) begin
		if(!resetn)	state <= S_IDLE;
		else		state <= next_state;
	end
	
	always@(*) begin
		case(state)
			S_IDLE:		next_state = (start) ? S_INIT : S_IDLE;
			S_INIT:		next_state = (counter_init_update[3]) ? S_CALCPAD : S_INIT; 	
			S_CALCPAD: begin
				if(counter_calcpad[5]) begin
					if(pad_zero&~r_padnext)
						next_state = S_IDLE;
					else	next_state = S_MSGLOAD; end
				else next_state = S_CALCPAD;
				//next_state = counter_calcpad[5]? (pad_zero? S_IDLE: S_MSGLOAD): S_CALCPAD;
			end
			S_MSGLOAD:	next_state = (load_finish | ((&rloadcounter[3:0])&rpadspecial)) ? S_COMPRESS : S_MSGLOAD;
			S_COMPRESS:	next_state = (compress_fin) ? S_WAIT : S_COMPRESS;
			S_WAIT:		next_state = S_UPDATE;
			S_UPDATE:	next_state = (&counter_init_update[2:0]) ? S_FIN : S_UPDATE;
			S_FIN: begin
				if (rskip)	next_state = S_IDLE;
				else		next_state = (pad_zero & ~padnext) ? S_IDLE : S_CALCPAD; end
			default:	next_state = S_IDLE;
		endcase
	end
	
	always@(posedge clk) begin
		if(sidle)	rpadreset <= 1'b0;
		else		rpadreset <= sfin & padnext;
	end
	always@(posedge clk) begin
		if(sidle)		rskip <= 1'b0;
		else if(rpadreset)	rskip <= 1'b1;
		else			rskip <= rskip;
	end
	always@(posedge clk) begin
		if(sidle)		rpadspecial <= 1'b0;
		else if(sfin&padnext)	rpadspecial <= 1'b1;
		else			rpadspecial <= rpadspecial;
	end
	always@(posedge clk) begin
		if(sinit|supdate|swait)	counter_init_update <= counter_init_update + 1'b1;
		else			counter_init_update <= 4'd0;
	end
	always@(posedge clk) begin
		if(scalcpad)	counter_calcpad <= counter_calcpad + 1'b1;
		else		counter_calcpad <= 6'd0;
	end
	always@(posedge clk) begin
		if(scompress)	counter_compress <= counter_compress + 1'b1;
		else		counter_compress <= 7'd0;
	end
	always@(posedge clk) begin
		if(sinit)		rbitcount <= ibitcount;
		else if(swait) begin
			if(pad_en)	rbitcount <= 128'd0;
			else		rbitcount <= rbitcount - bitcount_sub; end
		else			rbitcount <= rbitcount;
	end
	always@(posedge clk) begin
		if(!resetn)	rw_run <= 1'b0; //rcomresss_run <= 1'b0;
		else		rw_run <=  scompress & (counter_compress <= iter); //rcomresss_run <= rw_run;
	end
	always@(posedge clk) begin
		if(!resetn)						rloadcounter <= 4'd0;
		else if ((smsgload&msg_valid)|(smsgload&rpadspecial))	rloadcounter <= rloadcounter + 1'b1;
		else							rloadcounter <= 4'd0;
	end
	always@(posedge clk) begin
		if(!resetn)		nload <= 1'b0;
		else if(padnext)	nload <= 1'b1;
		else			nload <= nload;
	end
	always@(posedge clk) begin
		if(sidle)			r_padnext <= 1'b0;
		else if(supdate&padnext)	r_padnext <= 1'b1;
		else				r_padnext <= r_padnext;
	end
	
	assign sha_valid = sidle;
	assign ready2load = (smsgload&~nload);
	
	assign w_load = (smsgload&msg_valid) | (smsgload&rpadspecial);
	assign w_run  = rw_run;
	
	assign compress_init = sinit;
	assign compress_load = (swait|supdate);
	assign comresss_run  = rw_run;
	
	assign Kaddr = counter_compress;
	assign init_addr = {mode[1], counter_init_update[2:0]};
	
	assign load_counter = rloadcounter;
	
	assign padreset = rpadreset;
	assign padspecial = rpadspecial;
	assign pad_run = scalcpad;
	assign bitcount = rbitcount;
	
	assign padnextupdate = supdate;
	
endmodule
module triple_adder_64(
	s,
	carry,
	a,
	b,
	c	);

	output	[63:0]	s;
	output		carry;

	input	[63:0]	a, b, c;
	
	wire	[64:0]	ws;
	
	csa64 csa64_inst0 (
		.s	(ws),
		.cout	(carry),
		.a	(a),
		.b	(b),
		.c	(c)	);

	assign s = ws[63:0];
	
endmodule
module fa (
	sum,
	cout,
	a,
	b,
	cin	);

	output	sum, cout;

	input	a, b, cin;

	assign {cout, sum} = a + b + cin;
	
endmodule

module pos_adjust (
	out_pos,
	in_pos,
	mode64	);

	output	[6:0]	out_pos;
	
	input	[6:0]	in_pos;
	input		mode64;

	wire	[1:0]	in_line    = in_pos[6:5];
	wire	[1:0]	in_subline = in_pos[4:3];
	wire	[2:0]	in_col     = in_pos[2:0];
	
	wire	[1:0]	new_line;
	wire	[1:0]	new_subline;
	wire	[2:0]	new_col;
	
	assign new_col = {1'b1, in_col[1:0]};
	
	assign new_subline[0] = in_col[2];
	assign new_subline[1] = in_subline[0];
	
	assign new_line[0] = in_subline[1];
	assign new_line[1] = in_line[0];
	
	assign out_pos = (mode64) ? in_pos : {new_line, new_subline, new_col};
	
endmodule
module sha_core (
	clk,
	resetn,
	start,
	sha_valid,
	digest,
	read,
	ready2load,
	imessage,
	msg_valid,
	load_finish,
	ibitCount,
	mode	);
	
	parameter MODE_256 = 3'b001,
		MODE_384 = 3'b010,
		MODE_512 = 3'b100;
	
	input		clk;
	input		resetn;
	input		start;
	
	output		sha_valid;
	output	[63:0]	digest;
	
	input		read;
	output		ready2load;
	input	[63:0]	imessage;
	input		msg_valid;
	input		load_finish;
	input	[127:0]	ibitCount;
	
	input	[2:0]	mode;
		
	wire		mode64 = (mode[1]|mode[2]);
	
	// Controller signals
	wire		ctrl_finish;
	
	// W unit signals
	wire	[63:0]	W;
	wire		w_load;
	wire		w_run;
	wire	[63:0]	w_in;
	
	// Compress signals
	wire		compress_init;
	wire		compress_load;
	wire		comresss_run;
	wire		compress_read;
	wire	[63:0]	compress_data;
	
	// K rom singnals
	wire	[6:0]	Kaddr;
	wire	[63:0]	K;
	
	// init rom signals
	wire	[3:0]	init_addr;
	wire	[63:0]	init_data;
	
	// Pad signals
	wire		pad_run;
	wire		pad_zero;
	wire		pad_last;
	wire	[6:0]	pad_prepos;
	wire		pad_valid, pad_enable;
	wire		pad_processing;
	wire	[127:0]	bit_count;
	wire	[6:0]	pad_pos;
	wire		padnextupdate;
	
	wire	[3:0]	sha_loadCounter;
	
	wire		pad_reset;
	wire		pad_special;
	wire		pad_next;
	wire	[63:0]	pad_omessage;
	wire	[6:0]	pad_pos_adjust;
	
	sha_controller sha_controller_inst0 (
		.clk		(clk),
		.resetn		(resetn),
		.start		(start),
		.sha_valid	(ctrl_finish),
		.ready2load	(ready2load),
		.w_load		(w_load),
		.w_run		(w_run),
		.compress_init	(compress_init),
		.compress_load	(compress_load),
		.comresss_run	(comresss_run),
		.Kaddr		(Kaddr),
		.init_addr	(init_addr),
		.pad_run	(pad_run),
		.bitcount	(bit_count),
		.ibitcount	(ibitCount),
		.msg_valid	(msg_valid),
		.load_counter	(sha_loadCounter),
		.load_finish	(load_finish),
		.padreset	(pad_reset),
		.padspecial	(pad_special),
		.pad_zero	(pad_zero),
		.pad_en		(pad_enable),
		.padnextupdate	(padnextupdate),
		.padnext	(pad_next),
		.padlast	(pad_last),
		.mode		(mode)	);
	
	//wire	[63:0]	W;
	//wire		w_load;
	//wire		w_run;
	//wire	[63:0]	w_in;
	assign w_in = pad_omessage;
	
	w_unit w_unit_inst0 (
		.clk		(clk),
		.resetn		(resetn),
		.wout		(W),
		.load		(w_load),
		.run		(w_run),
		.imessage	(w_in),
		.mode64		(mode64)	);
	
	//wire		compress_init;
	//wire		compress_load;
	//wire		comresss_run;
	//wire		compress_read;
	//wire	[63:0]	compress_data;
	
	assign compress_read = read;
	
	compress compress_inst0 (
		.clk		(clk),
		.resetn		(resetn),
		.init		(compress_init),
		.load		(compress_load),
		.run		(comresss_run),
		.read		(compress_read),
		.hout		(compress_data),
		.K		(K),
		.W		(W),
		.load_data	(init_data),
		.mode64		(mode64)	);
	
	//wire	[6:0]	Kaddr;
	//wire	[63:0]	K;
	
	K_ROM K_ROM_inst0 (
		.clk	(clk),
		.addr	(Kaddr),
		.dout	(K),
		.mode64	(mode64)	);
	
	//wire	[3:0]	init_addr;
	//wire	[63:0]	init_data;
	
	init_ROM init_ROM_inst0 (
		.clk	(clk),
		.addr	(init_addr),
		.dout	(init_data),
		.mode64	(mode64)	);

	//wire		pad_run;
	//wire		pad_zero;
	//wire	[6:0]	pad_prepos;
	//wire		pad_valid, pad_enable;
	//wire		pad_processing;
	//wire	[127:0]	bit_count;
	
	sha_padding sha_padding_inst0 (
		.clk		(clk),
		.resetn		(resetn),
		.resetpad	(pad_reset),
		.run		(pad_run),
		.zero_len	(pad_zero),
		.pad_last	(pad_last),
		.padnext	(pad_next),
		.pad_pos	(pad_prepos),
		.pad_valid	(pad_valid),
		.pad_processing	(pad_processing),
		.pad_enable	(pad_enable),
		.bit_count	(bit_count),
		.padnextupdate	(padnextupdate),
		.mode64		(mode64)	);
	
	//wire	[63:0]	pad_omessage;
	wire	[6:0]	pad_position = (mode64) ? pad_prepos : pad_pos_adjust;
	
	sha_pad sha_pad_inst0 (
		.pad_message	(pad_omessage),
		.pad_en		(pad_enable),
		.pad_special	(pad_special),
		.pad_line	(sha_loadCounter),
		.pad_last	(pad_last),
		.block_idx	(pad_position[6:3]),
		.col_idx	(pad_position[2:0]),
		.ibitcount	(ibitCount),
		.imessage	(imessage),
		.mode64		(mode64)	);
	
	//wire	[6:0]	pad_pos_adjust;
	
	pos_adjust pos_adjust_inst0 (
		.out_pos	(pad_pos_adjust),
		.in_pos		(pad_prepos),
		.mode64		(mode64)	);
	
	assign sha_valid = ctrl_finish;
	assign digest = {{32{mode64}}, 32'hffff_ffff} & compress_data;
	
endmodule
module w_unit(
	clk,
	resetn,
	wout,
	load,
	run,
	imessage,
	mode64	);
	
	input		clk;
	input		resetn;
	
	output	[63:0]	wout;
	
	input		load;
	input		run;
	input	[63:0]	imessage;
	input		mode64;
	
	reg	[63:0]	w0 , w1 , w2 , w3 ,
			w4 , w5 , w6 , w7 ,
			w8 , w9 , w10, w11,
			w12, w13, w14, w15;
	
// Calculate W[n]
	wire	[63:0]	w_new;
	
	wire	[63:0]	in_0 = w0;
	wire	[63:0]	in_1 = w1;
	wire	[63:0]	in_2 = w9;
	wire	[63:0]	in_3 = w14;
	
	wire	[63:0]	delta0_result;
	wire	[63:0]	delta1_result;
	wire	[63:0]	adder_result;
	
	wire	[63:0]	delta0_result64;
	wire	[63:0]	delta1_result64;
	wire	[31:0]	delta0_result32;
	wire	[31:0]	delta1_result32;
	
	wire	[63:0]	csa_result;
	
	always@(posedge clk) begin
		if(!resetn)	w15 <= 64'd0;
		else if(load)	w15 <= imessage;
		else if(run)	w15 <= w_new;
		else		w15 <= w15;
	end
	always@(posedge clk) begin
		if(load|run)	{w0,w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14} <= {w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14,w15};
		else		{w0,w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14} <= {w0,w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14};
	end
	
// First stage
	// 64 bits - 512/384
	s0_64 s0_64_inst0 (
		.out	(delta0_result64),
		.x	(in_1)	);
	
	s1_64 s1_64_inst0 (
		.out	(delta1_result64),
		.x	(in_3)	);
	
	adder_64 adder_64_inst0 (
		.sum	(adder_result),
		.in_0	(in_0), 
		.in_1	(in_2)	);
	
	// 32 bits - 256
	s0_32 s0_32_inst0 (
		.out	(delta0_result32),
		.x	(in_1[31:0])	);
	
	s1_32 s1_32_inst0 (
		.out	(delta1_result32),
		.x	(in_3[31:0])	);
	
	assign delta0_result = (mode64) ? delta0_result64 : {32'd0, delta0_result32};
	assign delta1_result = (mode64) ? delta1_result64 : {32'd0, delta1_result32};
	
// Second stage
	triple_adder_64 csa_inst0 (
		.s	(csa_result),
		.carry	(),
		.a	(delta0_result),
		.b	(delta1_result),
		.c	(adder_result)	);

	assign w_new = csa_result;
	assign wout = w0;
	
endmodule
module hmac_controller (
	clk,
	resetn,
	enable,
	hmac_ready,
	usr_mode,
	sys_mode,
	read_digest,
	padmode,
	update_len,
	localresetn,
	sha_start,
	sha_read,
	sha_loadpad,
	sha_loadingmessage,
	sha_loadedmessage,
	sha_loaddigest,
	sha_ready2load,
	sha_fin,
	mem_addr,
	mem_we,
	sha_mode,
	iendofpacket	);

	parameter S_IDLE = 0,
		S_START0 = 1,
		S_WAIT0 = 2,
		S_IPAD = 3,
		S_WAIT1 = 4,
		S_WAIT1_0 = 5,
		S_MSGCOMPRESS = 6,
		S_STALL	 = 7,
		S_LOADMSG = 8,
		S_WAIT2 = 9,
		S_LOADHASH = 10,
		S_RESET = 11,
		S_START1 = 12,
		S_WAIT3 = 13,
		S_OPAD = 14,
		S_WAIT4 = 15,
		S_WAIT4_0 = 16,
		S_READDIG = 17,
		S_WAIT5 = 18,
		S_LOADRESULT = 19;
				
	parameter SHA_MODE256 = 3'b001,
		SHA_MODE384 = 3'b010,
		SHA_MODE512 = 3'b100;
	
	parameter HMAC_MODE = 2'b10,
		SHA_MODE = 2'b01;
				
	parameter PAD_INNER = 1'b0,
		PAD_OUTER = 1'b1;
	
	parameter ADDR_STATS = 7'd106,
		ADDR_LEN0 = 7'd104,
		ADDR_LEN1 = 7'd105,
		ADDR_SKEYBASE = 7'd96,
		ADDR_FDIGESTBASE = 7'd88;
				
//=========================================
//======= Begin Port declarations =========
//=========================================
	input		clk;
	input		resetn;
	input		enable;
	
	output		hmac_ready;
	output		usr_mode;
	output		sys_mode;
	output		read_digest;
	
	output		padmode;
	output		update_len;
	
	output		localresetn;
	output		sha_start;
	output		sha_read;
	output	[2:0]	sha_loadpad;
	output		sha_loadingmessage;
	output		sha_loadedmessage;
	output		sha_loaddigest;
	input		sha_ready2load;
	input		sha_fin;
	
	output	[5:0]	mem_addr;
	output		mem_we;
	
	input		sha_mode;
	input		iendofpacket;
	
//=========================================
//======= End Port declarations ===========
//=========================================
	reg	[4:0]	state, next_state;
	
	wire		sidle 		= (state == S_IDLE);
	wire		sstart0 	= (state == S_START0);
	//wire		swait0 		= (state == S_WAIT0);
	wire		sipad 		= (state == S_IPAD);
	//wire		swait1 		= (state == S_WAIT1);
	wire		smsgcompress	= (state == S_MSGCOMPRESS);
	wire		sloadmsg	= (state == S_LOADMSG);
	//wire		swait2		= (state == S_WAIT2);
	wire		sloadhash	= (state == S_LOADHASH);
	wire		sreset		= (state == S_RESET);
	wire		sstart1 	= (state == S_START1);
	//wire		swait3 		= (state == S_WAIT3);
	wire		sopad 		= (state == S_OPAD);
	//wire		swait4 		= (state == S_WAIT4);
	wire		sreaddig 	= (state == S_READDIG);
	//wire		swait5 		= (state == S_WAIT5);
	wire		sloadresult 	= (state == S_LOADRESULT);
	
	reg	[4:0]	counter;
	reg	[4:0]	rmem_addr;
	
	//wire		rsha_loadedmessage;
	reg		rpadmode;
	
	always@(posedge clk) begin
		if(!resetn)	state <= S_IDLE;
		else		state <= next_state;
	end
	
	always@(*) begin
		case(state)
			S_IDLE:		next_state = (enable) ? S_START0 : S_IDLE;
			S_START0:	next_state = S_WAIT0;
			S_WAIT0: begin
				if(sha_ready2load) begin
					if(sha_mode)	next_state = S_WAIT2;
					else		next_state = S_IPAD; end
				else	next_state = S_WAIT0;
			end
			S_IPAD:		next_state = (counter[4]) ? S_WAIT1 : S_IPAD;
			S_WAIT1:	next_state = S_WAIT1_0;
			S_WAIT1_0:	next_state = (sha_ready2load) ? S_WAIT2 : S_WAIT1_0;
			S_MSGCOMPRESS:	next_state = (counter[4]) ? S_STALL : S_MSGCOMPRESS;
			S_STALL:	next_state = S_WAIT2;
			S_WAIT2: begin
				if(sha_fin)	next_state = S_LOADHASH;
				else		next_state = sha_ready2load? S_LOADMSG: S_WAIT2;
				//if(sha_ready2load) next_state = iendofpacket? S_MSGCOMPRESS: S_WAIT2;
				//if(sha_ready2load) next_state = S_LOADMSG;
				//else next_state = S_WAIT2;
			end
			S_LOADMSG:	next_state = (iendofpacket) ? S_MSGCOMPRESS : S_LOADMSG;
			S_LOADHASH: begin
				if(&counter[2:0]) begin
					if(sha_mode)	next_state = S_IDLE;
					else		next_state = S_RESET; end
				else	next_state = S_LOADHASH;
			end
			S_RESET:	next_state = S_START1;
			S_START1:	next_state = S_WAIT3;
			S_WAIT3:	next_state = (sha_ready2load) ? S_OPAD : S_WAIT3;
			S_OPAD:		next_state = (counter[4]) ? S_WAIT4 : S_OPAD;
			S_WAIT4:	next_state = S_WAIT4_0;
			S_WAIT4_0:	next_state = (sha_ready2load) ? S_READDIG : S_WAIT4_0;
			S_READDIG:	next_state = (counter[4]) ? S_WAIT5 : S_READDIG;
			S_WAIT5:	next_state = (sha_fin) ? S_LOADRESULT : S_WAIT5;
			S_LOADRESULT:	next_state = (counter[3]) ? S_IDLE : S_LOADRESULT;
			default: next_state = S_IDLE;
		endcase
	end
	
	always@(posedge clk) begin
		if(sipad|sloadhash|sopad|sloadresult|sreaddig|smsgcompress)
			counter <= counter + 5'b1;
		else	counter <= 5'd0;
	end
	always@(posedge clk) begin
		if(sidle)		rpadmode <= 1'b0;
		else if(sloadhash)	rpadmode <= 1'b1;
		else			rpadmode <= rpadmode;
	end
	
	always@(*) begin
		//if(sipad|sopad)			rmem_addr = {2'b10, counter[2:0]};
		//else if(smsgcompress)			rmem_addr = {1'b0, counter[3:0]};
		//else if(sloadhash|sloadresult)	rmem_addr = {2'b11, counter[2:0]};
		//else					rmem_addr = {1'b0,  counter[3:0]};
		if(sipad|sopad|sloadhash|sloadresult) begin
			if(sloadhash|sloadresult)	rmem_addr = {2'b11, ~counter[2:0]};
			else				rmem_addr = {2'b10, counter[2:0]}; end
		else if(sreaddig)			rmem_addr = {2'b11, counter[2:0]};
		else					rmem_addr = {1'b0,  counter[3:0]};
	end
	//assign rsha_loadedmessage = (counter==16);
	
	assign hmac_ready = sidle;
	//assign usr_mode = (sidle|swait2);
	assign usr_mode = (sidle|sloadmsg);
	assign sys_mode = ~usr_mode;
	assign read_digest = sreaddig;
	
	assign padmode = rpadmode;
	assign update_len = (sstart0|sstart1);
	
	assign localresetn = ~sreset;
	assign sha_start = (sstart0|sstart1);
	assign sha_read = (sloadhash|sloadresult);
	assign sha_loadpad[0] = (sipad|sopad);
	assign sha_loadpad[1] = (counter>5'd8);
	assign sha_loadpad[2] = sha_loadpad[0] & (counter>5'd0) & (counter<=16);
	assign sha_loadingmessage = smsgcompress & (counter!=0);
	assign sha_loadedmessage = (counter==17);
	assign sha_loaddigest = sreaddig & (counter>5'd0) & (counter<=16);
	
	assign mem_addr = {1'b0, rmem_addr};
	assign mem_we = (sloadhash|sloadresult);
	
endmodule
module sha_padding (
	clk,
	resetn,
	resetpad,
	run,
	zero_len,
	pad_last,
	padnext,
	pad_pos,
	pad_valid,
	pad_processing,
	pad_enable,
	bit_count,
	padnextupdate,
	mode64	);

	input		clk;
	input		resetn;
	input		resetpad;
	input		run;
	
	output		zero_len;
	output		pad_last;
	output		padnext;
	output	[6:0]	pad_pos;
	output		pad_valid, pad_enable;
	output		pad_processing;
	
	input	[127:0]	bit_count;
	input		padnextupdate;
	input		mode64;
	
	wire		c0 = bit_count[3];
	wire	[2:0]	col_pad;
	wire	[1:0]	subline_pad;
	wire	[1:0]	line_pad;
	wire	[1:0]	line_pad32, line_pad64;
	
	wire		enable_c0;
	reg		enable_c1;
	wire		enable_c2;
	reg		r_padenable;
	
	reg	[3:0]	cmp_sel;
	reg	[4:0]	index;
	
	reg		r_zeroLen;
	reg		r_1024;
	reg		r_padnext;
	reg		r_pad_last;
	
	assign col_pad = {~bit_count[5:4], ~c0};
	assign line_pad64 = (~bit_count[11]&bit_count[10]) ? 2'b00 : bit_count[9:8];
	assign line_pad32 = {1'b0, line_pad64[0]};
	assign line_pad = (mode64) ? line_pad64: line_pad32;
	assign subline_pad = bit_count[7:6];
	assign enable_c0 = ~(bit_count[11]|bit_count[10]);
	assign enable_c2 = (mode64) ? 1'b1: ~line_pad64[1];
	
	wire bitcount_lt1024 = enable_c1 & (bit_count[11:0]>=12'd896) & (bit_count[11:0]<12'd1024);
	wire bitcount_lt512  = enable_c1 & (bit_count[11:0]>=12'd448) & (bit_count[11:0]<12'd512);
	wire bitcount_cmp1024 = (bit_count[11:0]==12'd1024);
	wire bitcount_cmp512  = (bit_count[11:0]==12'd512);
	wire bitcount_lt = (mode64) ? bitcount_lt1024 : bitcount_lt512;
	wire bitcount_eq = (mode64) ? (bitcount_cmp1024|bitcount_lt1024) : (bitcount_cmp512|bitcount_lt512);
	
	always@(posedge clk) begin
		if(~resetn) begin
			index <= 5'd0;
			enable_c1 <= 1'b1; end
		else if(~run) begin
			index <= 5'd0;
			enable_c1 <= 1'b1; end
		else if(&index) begin
			index <= index;
			enable_c1 <= enable_c1 & ~|(cmp_sel); end
		else begin
			index <= index + 1'b1;
			enable_c1 <= enable_c1 & ~|(cmp_sel); end
	end
	always@(posedge clk) begin
		if(resetpad|!resetn)
			r_1024 <= 1'b0;
		else if(bitcount_eq&enable_c1&(&index))
			r_1024 <= 1'b1;
		else if(zero_len)
			r_1024 <= 1'b0;
		else	r_1024 <= r_1024;
	end
	always@(posedge clk) begin
		r_padnext <= r_1024 & padnextupdate;
	end
	always@(posedge clk) begin
		if(!resetn)
			r_pad_last <= 1'b0;
		else if(bitcount_lt&~r_pad_last)
			r_pad_last <= 1'b1;
		else	r_pad_last <= r_pad_last;
	end
	always@(posedge clk) begin
		if(!resetn)	r_zeroLen <= 1'b0;
		else if(&index)	r_zeroLen <= ~|(bit_count[11:0]) & enable_c1;
		else		r_zeroLen <= r_zeroLen;
	end
	always@(posedge clk) begin	
		if(!resetn)	r_padenable <= 1'b0;
		else if(&index)	r_padenable <= enable_c0 & enable_c1 & enable_c2 & ~(~|(bit_count[11:0]) & enable_c1);
		else		r_padenable <= r_padenable;
	end
	
	always@(*) begin
		case(index)
			5'd0: cmp_sel = bit_count[15:12];
			5'd1: cmp_sel = bit_count[15:12];
			5'd2: cmp_sel = bit_count[15:12];
			5'd3: cmp_sel = bit_count[15:12];
			5'd4: cmp_sel = bit_count[19:16];
			5'd5: cmp_sel = bit_count[23:20];
			5'd6: cmp_sel = bit_count[27:24];
			5'd7: cmp_sel = bit_count[31:28];
			5'd8: cmp_sel = bit_count[35:32];
			5'd9: cmp_sel = bit_count[39:36];
			5'd10: cmp_sel = bit_count[43:40];
			5'd11: cmp_sel = bit_count[47:44];
			5'd12: cmp_sel = bit_count[51:48];
			5'd13: cmp_sel = bit_count[55:52];
			5'd14: cmp_sel = bit_count[59:56];
			5'd15: cmp_sel = bit_count[63:60];
			5'd16: cmp_sel = bit_count[67:64];
			5'd17: cmp_sel = bit_count[71:68];
			5'd18: cmp_sel = bit_count[75:72];
			5'd19: cmp_sel = bit_count[79:76];
			5'd20: cmp_sel = bit_count[83:80];
			5'd21: cmp_sel = bit_count[87:84];
			5'd22: cmp_sel = bit_count[91:88];
			5'd23: cmp_sel = bit_count[95:92];
			5'd24: cmp_sel = bit_count[99:96];
			5'd25: cmp_sel = bit_count[103:100];
			5'd26: cmp_sel = bit_count[107:104];
			5'd27: cmp_sel = bit_count[111:108];
			5'd28: cmp_sel = bit_count[115:112];
			5'd29: cmp_sel = bit_count[119:116];
			5'd30: cmp_sel = bit_count[123:120];
			5'd31: cmp_sel = bit_count[127:124];
		endcase
	end
	
	assign zero_len = r_zeroLen;
	assign padnext = r_padnext;
	assign pad_valid = (&index);
	assign pad_processing = run & ~pad_valid;
	assign pad_enable = r_padenable;
	assign pad_pos = {line_pad, subline_pad, ~col_pad};
	assign pad_last = r_pad_last;
	
endmodule
module hmac_core (
	clk,
	resetn,
	ready,
	enable,
	// Memory-mapped interface
	mm_rdata,
	mm_addr,
	mm_wen,
	mm_wdata,
	// Stream port
	input_ready,
	iendofpacket	);

//=========================================
//======= Begin Port declarations =========
//=========================================
	input		clk;
	input		resetn;

	output		ready;
	input		enable;
	
	output	[63:0]	mm_rdata;
	input	[5:0]	mm_addr;
	input		mm_wen;
	input	[63:0]	mm_wdata;
	
	output input_ready;
	input iendofpacket;

//=========================================
//======= End Port declarations ===========
//=========================================
	wire	[1:0]	hmac_mode;
	wire	[2:0]	sha_mode;
	
	wire	[63:0]	pad_opad;
	wire	[63:0]	pad_iskey;
	wire		pad_imode;
	
	wire		sha_istart;
	wire		sha_ovalid;
	wire	[63:0]	sha_odigest;
	wire		sha_iread;
	wire		sha_oready2load;
	reg 	[63:0]	sha_imessage;
	wire		sha_imsgValid;
	wire		sha_iloadFinish;
	wire	[127:0]	sha_ibitCount;
	
	wire		update_len;
	wire		memory_iwe;
	wire	[63:0]	memory_oq;
	wire	[63:0]	memory_idata;
	wire	[5:0]	memory_iaddr;
	
	wire		ctrl_ready;
	wire		ctrl_usrmode;
	wire		ctrl_sysmode;
	wire		ctrl_readdigest;
	wire	[5:0]	ctrl_mem_addr;
	wire		ctrl_mem_we;
	wire	[2:0]	ctrl_loadpad;
	wire		ctrl_loadingmessage;
	wire		ctrl_loadedmessage;
	wire		ctrl_shaLoaddigest;
	//wire		ctrl_loadmessage;
	
	wire		localresetn;
	
	hmac_controller hmac_controller_inst0 (
		.clk			(clk),
		.resetn			(resetn),
		.enable			(enable),
		.hmac_ready		(ctrl_ready),
		.usr_mode		(ctrl_usrmode),
		.sys_mode		(ctrl_sysmode),
		.read_digest		(ctrl_readdigest),
		.padmode		(pad_imode),
		.update_len		(update_len),
		.localresetn		(localresetn),
		.sha_start		(sha_istart),
		.sha_read		(sha_iread),
		.sha_loadpad		(ctrl_loadpad),
		.sha_loadingmessage	(ctrl_loadingmessage),
		.sha_loadedmessage	(ctrl_loadedmessage),
		.sha_loaddigest		(ctrl_shaLoaddigest),
		//.sha_loadmessage	(ctrl_loadmessage),
		.sha_ready2load		(sha_oready2load),
		.sha_fin		(sha_ovalid),
		.mem_addr		(ctrl_mem_addr),
		.mem_we			(ctrl_mem_we),
		.sha_mode		(hmac_mode[0]),
		.iendofpacket		(iendofpacket)	);
	
	//wire	[63:0]	pad_opad;
	//wire	[63:0]	pad_iskey;
	//wire		pad_imode;
	assign pad_iskey = memory_oq;
	
	hmac_padding hmac_padding_inst0 (
		.pad		(pad_opad),
		.skey		(pad_iskey),
		.padmode	(pad_imode)	);
	
	//wire		sha_istart;
	//wire		sha_ovalid;
	//wire	[63:0]	sha_odigest;
	//wire		sha_iread;
	//wire		sha_iready2load;
	//wire	[63:0]	sha_imessage;
	//wire		sha_imsgValid;
	//wire		sha_iloadFinish;
	//wire	[127:0]	sha_ibitCount;
	
	always @(*) begin
		if (ctrl_loadpad[0]) begin
			if (ctrl_loadpad[1])	sha_imessage = (pad_imode) ? 64'h5c5c5c5c5c5c5c5c : 64'h3636363636363636;
			else			sha_imessage = pad_opad; end
		else				sha_imessage = memory_oq;
	end
	
	assign sha_imsgValid = ctrl_loadingmessage | ctrl_loadpad[2] | ctrl_shaLoaddigest;
	assign sha_iloadFinish = ctrl_loadedmessage;
	
	sha_core sha_core_inst0 (
		.clk		(clk),
		.resetn		(resetn & localresetn),
		.start		(sha_istart),
		.sha_valid	(sha_ovalid),
		.digest		(sha_odigest),
		.read		(sha_iread),
		.ready2load	(sha_oready2load),
		.imessage	(sha_imessage),
		.msg_valid	(sha_imsgValid),
		.load_finish	(sha_iloadFinish),
		.ibitCount	(sha_ibitCount),
		.mode		(sha_mode)	);
	
	//wire		memory_iwe;
	//wire	[63:0]	memory_oq;
	//wire	[63:0]	memory_idata;
	//wire	[5:0]	memory_iaddr;
	
	assign memory_iwe = (ctrl_usrmode) ? mm_wen : ctrl_mem_we;
	assign memory_idata = (ctrl_usrmode) ? mm_wdata : sha_odigest;
	assign memory_iaddr = (ctrl_usrmode) ? mm_addr : ctrl_mem_addr;
	
	memory memory_inst0 (
		.clk		(clk),
		.resetn		(resetn),
		.hmac_mode	(hmac_mode),
		.sha_mode	(sha_mode),
		.pad_mode	(pad_imode),
		.update_len	(update_len),
		.bitcount	(sha_ibitCount),
		.q		(memory_oq),
		.we		(memory_iwe),
		.addr		(memory_iaddr),
		.data		(memory_idata)	);
	
	assign ready = ctrl_ready;
	assign mm_rdata = memory_oq;
	assign input_ready = sha_oready2load & ctrl_usrmode;
	
endmodule
`undef WT_DCACHE
`undef DISABLE_TRACER
`undef SRAM_NO_INIT
`undef VERILATOR

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
	padnextupdate	);

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
	
	input	[63:0]	bit_count;
	input		padnextupdate;
	
	wire		c0 = bit_count[3];
	wire	[2:0]	col_pad;
	wire	[1:0]	subline_pad;
	wire	[1:0]	line_pad;
	wire	[1:0]	line_pad64;
	
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
	assign line_pad = {1'b0, line_pad64[0]};
	assign subline_pad = bit_count[7:6];
	assign enable_c0 = ~(bit_count[11]|bit_count[10]);
	assign enable_c2 = ~line_pad64[1];
	
	wire bitcount_lt512  = enable_c1 & (bit_count[11:0]>=12'd448) & (bit_count[11:0]<12'd512);
	wire bitcount_cmp512 = (bit_count[11:0]==12'd512);
	wire bitcount_lt = bitcount_lt512;
	wire bitcount_eq = bitcount_cmp512 | bitcount_lt512;
	
	always@(posedge clk) begin
		if(~resetn) begin
			index <= 5'd0;
			enable_c1 <= 1'b1;
		end
		else if(~run) begin
			index <= 5'd0;
			enable_c1 <= 1'b1;
		end
		else if(&index) begin
			index <= index;
			enable_c1 <= enable_c1 & ~|(cmp_sel);
		end
		else begin
			index <= index + 1'b1;
			enable_c1 <= enable_c1 & ~|(cmp_sel);
		end
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
			5'd0:  cmp_sel = bit_count[15:12];
			5'd1:  cmp_sel = bit_count[15:12];
			5'd2:  cmp_sel = bit_count[15:12];
			5'd3:  cmp_sel = bit_count[15:12];
			5'd4:  cmp_sel = bit_count[19:16];
			5'd5:  cmp_sel = bit_count[23:20];
			5'd6:  cmp_sel = bit_count[27:24];
			5'd7:  cmp_sel = bit_count[31:28];
			5'd8:  cmp_sel = bit_count[35:32];
			5'd9:  cmp_sel = bit_count[39:36];
			5'd10: cmp_sel = bit_count[43:40];
			5'd11: cmp_sel = bit_count[47:44];
			5'd12: cmp_sel = bit_count[51:48];
			5'd13: cmp_sel = bit_count[55:52];
			5'd14: cmp_sel = bit_count[59:56];
			5'd15: cmp_sel = bit_count[63:60];
			default: cmp_sel = 4'd0;
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

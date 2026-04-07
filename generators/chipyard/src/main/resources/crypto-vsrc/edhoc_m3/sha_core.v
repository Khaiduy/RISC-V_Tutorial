`timescale 1ns / 1ps

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
	ibitCount	);
	
	input		clk;
	input		resetn;
	input		start;
	
	output		sha_valid;
	output	[31:0]	digest;
	
	input		read;
	output		ready2load;
	input	[31:0]	imessage;
	input		msg_valid;
	input		load_finish;
	input	[63:0]	ibitCount;
	
	wire		ctrl_finish;
	
	wire	[31:0]	W;
	wire		w_load;
	wire		w_run;
	wire	[31:0]	w_in;
	
	wire		compress_init;
	wire		compress_load;
	wire		comresss_run;
	wire		compress_read;
	wire	[31:0]	compress_data;
	
	wire	[6:0]	Kaddr;
	wire	[31:0]	K;
	
	wire	[3:0]	init_addr;
	wire	[31:0]	init_data;
	
	wire		pad_run;
	wire		pad_zero;
	wire		pad_last;
	wire	[6:0]	pad_prepos;
	wire		pad_valid, pad_enable;
	wire		pad_processing;
	wire	[63:0]	bit_count;
	wire	[6:0]	pad_pos;
	wire		padnextupdate;
	
	wire	[3:0]	sha_loadCounter;
	
	wire		pad_reset;
	wire		pad_special;
	wire		pad_next;
	wire	[31:0]	pad_omessage;
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
		.padlast	(pad_last)	);
	
	assign w_in = pad_omessage;
	
	w_unit w_unit_inst0 (
		.clk		(clk),
		.resetn		(resetn),
		.wout		(W),
		.load		(w_load),
		.run		(w_run),
		.imessage	(w_in)	);
	
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
		.load_data	(init_data)	);
	
	K_ROM K_ROM_inst0 (
		.clk	(clk),
		.addr	(Kaddr[5:0]),
		.dout	(K)	);
	
	init_ROM init_ROM_inst0 (
		.clk	(clk),
		.addr	(init_addr[2:0]),
		.dout	(init_data)	);

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
		.padnextupdate	(padnextupdate)	);
	
	wire	[6:0]	pad_position = pad_pos_adjust;
	
	sha_pad sha_pad_inst0 (
		.pad_message	(pad_omessage),
		.pad_en		(pad_enable),
		.pad_special	(pad_special),
		.pad_line	(sha_loadCounter),
		.pad_last	(pad_last),
		.block_idx	(pad_position[6:3]),
		.col_idx	(pad_position[2:0]),
		.ibitcount	(ibitCount),
		.imessage	(imessage)	);
	
	pos_adjust pos_adjust_inst0 (
		.out_pos	(pad_pos_adjust),
		.in_pos		(pad_prepos)	);
	
	assign sha_valid = ctrl_finish;
	assign digest = compress_data;
	
endmodule

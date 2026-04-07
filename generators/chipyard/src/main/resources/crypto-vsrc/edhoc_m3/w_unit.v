module w_unit(
	clk,
	resetn,
	wout,
	load,
	run,
	imessage	);
	
	input		clk;
	input		resetn;
	
	output	[31:0]	wout;
	
	input		load;
	input		run;
	input	[31:0]	imessage;
	
	reg	[31:0]	w0 , w1 , w2 , w3 ,
			w4 , w5 , w6 , w7 ,
			w8 , w9 , w10, w11,
			w12, w13, w14, w15;
	
// Calculate W[n]
	wire	[31:0]	w_new;
	
	wire	[31:0]	in_0 = w0;
	wire	[31:0]	in_1 = w1;
	wire	[31:0]	in_2 = w9;
	wire	[31:0]	in_3 = w14;
	
	wire	[31:0]	delta0_result;
	wire	[31:0]	delta1_result;
	wire	[31:0]	adder_result;
	
	wire	[31:0]	csa_result;
	
	always@(posedge clk) begin
		if(!resetn)	w15 <= 32'd0;
		else if(load)	w15 <= imessage;
		else if(run)	w15 <= w_new;
		else		w15 <= w15;
	end
	always@(posedge clk) begin
		if(load|run)	{w0,w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14} <= {w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14,w15};
		else		{w0,w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14} <= {w0,w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14};
	end
	
	s0_32 s0_32_inst0 (
		.out	(delta0_result),
		.x	(in_1)	);
	
	s1_32 s1_32_inst0 (
		.out	(delta1_result),
		.x	(in_3)	);
	
	adder_32 adder_32_inst0 (
		.sum	(adder_result),
		.in_0	(in_0), 
		.in_1	(in_2)	);
	
	triple_adder_32 csa_inst0 (
		.s	(csa_result),
		.carry	(),
		.a	(delta0_result),
		.b	(delta1_result),
		.c	(adder_result)	);

	assign w_new = csa_result;
	assign wout = w0;
	
endmodule

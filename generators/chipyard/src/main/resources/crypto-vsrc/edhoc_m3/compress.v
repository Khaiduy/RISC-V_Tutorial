module compress (
	clk,
	resetn,
	init,
	load,
	run,
	read,
	hout,
	K,
	W,
	load_data	);

	input		clk;
	input		resetn;
	input		init, load, run, read;
	
	output	[31:0]	hout;
	
	input	[31:0]	K, W;
	input	[31:0]	load_data;
	
	reg	[31:0]	A, B, C, D, E, F, G, H;
	reg	[31:0]	h0, h1, h2, h3, h4, h5, h6, h7;
	
	wire	[31:0]	A_new, E_new;
	wire	[31:0]	w1_32, w3_32;
	wire	[31:0]	w2, w4, w5, w6;
	
	wire	[31:0]	T1, T2;
	
	wire	[31:0]	new_dm = h7 + H;
	
	always@(posedge clk) begin
		if(!resetn)	{h0, A, E} <= 96'd0;
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
	
	SIG0_32 SIG0_32_inst0 (
		.out	(w1_32),
		.x	(A)	);
	
	maj maj_inst0 (
		.out	(w2),
		.x	(A),
		.y	(B),
		.z	(C)	);

	SIG1_32 SIG1_32_inst0 (
		.out	(w3_32),
		.x	(E)	);
	
	ch ch_inst0 (
		.out	(w4),
		.x	(E),
		.y	(F),
		.z	(G)	);
	
	triple_adder_32 t3_adder_inst0 (
		.s	(w5),
		.carry	(),
		.a	(H),
		.b	(K),
		.c	(W)	);

	assign w6 = D;

	adder_32 adder_32_w1w2 (
		.sum	(T2),
		.in_0	(w1_32),
		.in_1	(w2)	);

	triple_adder_32 t3_adder_inst1 (
		.s	(T1),
		.carry	(),
		.a	(w3_32),
		.b	(w4),
		.c	(w5)	);
	
	adder_32 adder_T1T2 (
		.sum	(A_new),
		.in_0	(T1),
		.in_1	(T2)	);
	
	adder_32 adder_T1w6 (
		.sum	(E_new),
		.in_0	(T1),
		.in_1	(w6)	);
	
	assign hout = h7;
endmodule

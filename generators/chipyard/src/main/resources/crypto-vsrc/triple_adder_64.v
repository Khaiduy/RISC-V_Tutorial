module triple_adder_32(
	s,
	carry,
	a,
	b,
	c	);

	output	[31:0]	s;
	output		carry;

	input	[31:0]	a, b, c;
	
	wire	[32:0]	ws;
	
	csa32 csa32_inst0 (
		.s	(ws),
		.cout	(carry),
		.a	(a),
		.b	(b),
		.c	(c)	);

	assign s = ws[31:0];
	
endmodule

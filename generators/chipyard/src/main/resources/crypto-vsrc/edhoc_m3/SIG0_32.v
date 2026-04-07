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

	

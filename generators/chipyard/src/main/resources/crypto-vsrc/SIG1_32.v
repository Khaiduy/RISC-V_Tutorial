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

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

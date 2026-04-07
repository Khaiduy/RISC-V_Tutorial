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

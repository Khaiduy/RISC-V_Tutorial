/*
	out = xy ^ xz ^ yz
*/

module maj (
	out,
	x,
	y,
	z	);
	
	output	[31:0]	out;
	
	input	[31:0]	x, y, z;

	wire	[31:0]	and1, and2, and3;
	
	assign and1 = x & y;
	assign and2 = x & z;
	assign and3 = y & z;
			
	assign out = and1 ^ and2 ^ and3;
	
endmodule

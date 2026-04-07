/*
	out = xy ^ ~xz
*/

module ch (
	out,
	x,
	y,
	z	);

	output	[31:0]	out;

	input	[31:0]	x, y, z;

	wire	[31:0]	and1, and2;

	assign and1 = x & y;
	assign and2 = ~x & z;

	assign out = and1 ^ and2;

endmodule

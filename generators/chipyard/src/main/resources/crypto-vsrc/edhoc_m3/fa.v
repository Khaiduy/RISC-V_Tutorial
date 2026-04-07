module fa (
	sum,
	cout,
	a,
	b,
	cin	);

	output	sum, cout;

	input	a, b, cin;

	assign {cout, sum} = a + b + cin;
	
endmodule

module csa32 (
	s,
	cout,
	a,
	b,
	c	);

	output	[32:0]	s;
	output		cout;
	
	input	[31:0]	a, b, c;

	wire	[31:0]	s1, c1;
	
	wire	[32:0]	s2 = {1'b0, s1}; 
	wire	[32:0]	c2 = {c1, 1'b0};
	
	fa fa0_inst0  (s1[0],  c1[0],  a[0],  b[0],  c[0]);
	fa fa0_inst1  (s1[1],  c1[1],  a[1],  b[1],  c[1]);
	fa fa0_inst2  (s1[2],  c1[2],  a[2],  b[2],  c[2]);
	fa fa0_inst3  (s1[3],  c1[3],  a[3],  b[3],  c[3]);
	fa fa0_inst4  (s1[4],  c1[4],  a[4],  b[4],  c[4]);
	fa fa0_inst5  (s1[5],  c1[5],  a[5],  b[5],  c[5]);
	fa fa0_inst6  (s1[6],  c1[6],  a[6],  b[6],  c[6]);
	fa fa0_inst7  (s1[7],  c1[7],  a[7],  b[7],  c[7]);
	fa fa0_inst8  (s1[8],  c1[8],  a[8],  b[8],  c[8]);
	fa fa0_inst9  (s1[9],  c1[9],  a[9],  b[9],  c[9]);
	fa fa0_inst10 (s1[10], c1[10], a[10], b[10], c[10]);
	fa fa0_inst11 (s1[11], c1[11], a[11], b[11], c[11]);
	fa fa0_inst12 (s1[12], c1[12], a[12], b[12], c[12]);
	fa fa0_inst13 (s1[13], c1[13], a[13], b[13], c[13]);
	fa fa0_inst14 (s1[14], c1[14], a[14], b[14], c[14]);
	fa fa0_inst15 (s1[15], c1[15], a[15], b[15], c[15]);
	fa fa0_inst16 (s1[16], c1[16], a[16], b[16], c[16]);
	fa fa0_inst17 (s1[17], c1[17], a[17], b[17], c[17]);
	fa fa0_inst18 (s1[18], c1[18], a[18], b[18], c[18]);
	fa fa0_inst19 (s1[19], c1[19], a[19], b[19], c[19]);
	fa fa0_inst20 (s1[20], c1[20], a[20], b[20], c[20]);
	fa fa0_inst21 (s1[21], c1[21], a[21], b[21], c[21]);
	fa fa0_inst22 (s1[22], c1[22], a[22], b[22], c[22]);
	fa fa0_inst23 (s1[23], c1[23], a[23], b[23], c[23]);
	fa fa0_inst24 (s1[24], c1[24], a[24], b[24], c[24]);
	fa fa0_inst25 (s1[25], c1[25], a[25], b[25], c[25]);
	fa fa0_inst26 (s1[26], c1[26], a[26], b[26], c[26]);
	fa fa0_inst27 (s1[27], c1[27], a[27], b[27], c[27]);
	fa fa0_inst28 (s1[28], c1[28], a[28], b[28], c[28]);
	fa fa0_inst29 (s1[29], c1[29], a[29], b[29], c[29]);
	fa fa0_inst30 (s1[30], c1[30], a[30], b[30], c[30]);
	fa fa0_inst31 (s1[31], c1[31], a[31], b[31], c[31]);
	
	assign {cout, s} = s2 + c2;
	
endmodule

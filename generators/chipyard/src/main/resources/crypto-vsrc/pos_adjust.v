module pos_adjust (
	out_pos,
	in_pos	);

	output	[6:0]	out_pos;
	
	input	[6:0]	in_pos;

	wire	[1:0]	in_line    = in_pos[6:5];
	wire	[1:0]	in_subline = in_pos[4:3];
	wire	[2:0]	in_col     = in_pos[2:0];
	
	wire	[1:0]	new_line;
	wire	[1:0]	new_subline;
	wire	[2:0]	new_col;
	
	assign new_col = {1'b1, in_col[1:0]};
	
	assign new_subline[0] = in_col[2];
	assign new_subline[1] = in_subline[0];
	
	assign new_line[0] = in_subline[1];
	assign new_line[1] = in_line[0];
	
	assign out_pos = {new_line, new_subline, new_col};
	
endmodule

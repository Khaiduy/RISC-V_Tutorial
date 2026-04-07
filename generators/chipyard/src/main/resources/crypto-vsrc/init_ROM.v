module init_ROM (
	clk,
	addr,
	dout	);
	
	input		clk;
	input	[2:0]	addr;
	
	output	[31:0]	dout;
	
	reg	[31:0]	r_dout;
	
	reg	[31:0]	wdata;

	always@(*) begin
		case(addr)
			3'd0:  wdata = 32'h5be0cd19;
			3'd1:  wdata = 32'h1f83d9ab;
			3'd2:  wdata = 32'h9b05688c;
			3'd3:  wdata = 32'h510e527f;
			3'd4:  wdata = 32'ha54ff53a;
			3'd5:  wdata = 32'h3c6ef372;
			3'd6:  wdata = 32'hbb67ae85;
			3'd7:  wdata = 32'h6a09e667;
			default: wdata = 32'd0;
		endcase
	end

	always@(posedge clk) begin
		r_dout <= wdata;
	end
	
	assign dout = r_dout;
	
endmodule

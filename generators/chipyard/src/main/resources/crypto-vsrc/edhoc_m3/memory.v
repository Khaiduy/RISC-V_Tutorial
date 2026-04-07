module memory (
	clk,
	resetn,
	hmac_mode,
	pad_mode,
	update_len,
	bitcount,
	q,
	we,
	addr,
	data	);
	
	parameter HMAC_MODE = 2'b10,
		SHA_MODE = 2'b01;
	
	parameter PAD_INNER = 1'b0,
		PAD_OUTER = 1'b1;

	input		clk;
	input		resetn;
	
	output	[1:0]	hmac_mode;
	output	[63:0]	bitcount;
	input		pad_mode;
	input		update_len;
	
	output	[31:0]	q;
	input		we;
	input	[5:0]	addr;
	input	[31:0]	data;
	
	reg	[4:0]	stats;
	reg	[63:0]	rbitcount;

// ========== RAM FPGA
	reg	[31:0]	q_out;
	reg	[31:0]	ram[0:63];
	always@(posedge clk) begin
		if(we)	ram[addr] <= data;
	end
	always@(posedge clk) begin
		if(~we)	q_out <= ram[addr];
		else	q_out <= q_out;
	end
// ========== End RAM FPGA

	wire	[63:0]	inc = 64'd512;
	
	always@(posedge clk) begin
		if(!resetn)			stats <= 5'b10100;
		else if(we&(addr==6'd34))	stats <= data[4:0];
		else				stats <= stats;
	end
	always@(posedge clk) begin
		if(!resetn)	rbitcount <= 64'd0;
		else if (we) begin
			if(addr==6'd32)		rbitcount <= {rbitcount[63:32], data};
			else if(addr==6'd33)	rbitcount <= {data, rbitcount[31:0]};
			else			rbitcount <= rbitcount;
		end
		else if(update_len&hmac_mode[1]) begin
			if(pad_mode==PAD_INNER)	rbitcount <= rbitcount + inc;
			else			rbitcount <= 64'd768;
		end
		else	rbitcount <= rbitcount;
	end
	
	assign q = q_out;
	
	assign hmac_mode = stats[4:3];
	assign bitcount = rbitcount;
	
endmodule

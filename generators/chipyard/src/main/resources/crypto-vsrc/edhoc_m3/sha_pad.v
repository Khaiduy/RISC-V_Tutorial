module sha_pad(
	pad_message,
	pad_en,
	pad_special,
	pad_line,
	pad_last,
	block_idx,
	col_idx,
	ibitcount,
	imessage	);

	output	[31:0]	pad_message;
	
	input		pad_en;
	input		pad_special;
	input	[3:0]	pad_line;
	input		pad_last;
	input	[3:0]	block_idx;
	input	[2:0]	col_idx;
	input	[63:0]	ibitcount;
	input	[31:0]	imessage;
	
	wire		allow_pad = pad_en & (pad_line >= block_idx);
	
	// Byte position within 32-bit word where 0x80 goes
	// col_idx from pos_adjust: 4=byte[31:24], 5=[23:16], 6=[15:8], 7=[7:0]
	// Mapping: byte_pos = ~col_idx[1:0] (3=MSB, 0=LSB)
	wire	[1:0]	bpos = ~col_idx[1:0];
	wire		at_block = (pad_line == block_idx);
	
	// For each byte: if above pad position pass through, at position -> 0x80, below -> 0x00
	wire	[7:0]	pmsg_3 = (at_block & (2'd3 > bpos))  ? imessage[31:24]
			       : (at_block & (2'd3 == bpos)) ? 8'h80
			       : 8'h00;
	wire	[7:0]	pmsg_2 = (at_block & (2'd2 > bpos))  ? imessage[23:16]
			       : (at_block & (2'd2 == bpos)) ? 8'h80
			       : 8'h00;
	wire	[7:0]	pmsg_1 = (at_block & (2'd1 > bpos))  ? imessage[15:8]
			       : (at_block & (2'd1 == bpos)) ? 8'h80
			       : 8'h00;
	wire	[7:0]	pmsg_0 = (at_block & (2'd0 == bpos)) ? 8'h80
			       : 8'h00;
	
	wire	[7:0]	omsg_3 = (allow_pad) ? pmsg_3 : imessage[31:24];
	wire	[7:0]	omsg_2 = (allow_pad) ? pmsg_2 : imessage[23:16];
	wire	[7:0]	omsg_1 = (allow_pad) ? pmsg_1 : imessage[15:8];
	wire	[7:0]	omsg_0 = (allow_pad) ? pmsg_0 : imessage[7:0];
	
	reg	[31:0]	omsg;
	
	always@(*) begin
		if(pad_en) begin
			if(pad_last)			omsg = {omsg_3, omsg_2, omsg_1, omsg_0};
			else if(pad_line==4'd14)	omsg = ibitcount[63:32];
			else if(pad_line==4'd15)	omsg = ibitcount[31:0];
			else				omsg = {omsg_3, omsg_2, omsg_1, omsg_0};
		end
		else if(pad_special) begin
			if(pad_line==4'd0)		omsg = {~pad_last, 31'd0};
			else if(pad_line==4'd14)	omsg = ibitcount[63:32];
			else if(pad_line==4'd15)	omsg = ibitcount[31:0];
			else				omsg = 32'd0;
		end
		else omsg = imessage;
	end
	
	assign pad_message = omsg;
	
endmodule

module hmac_padding (
	pad,
	skey,
	padmode	);

	parameter MODE_INNER = 1'b0,
		MODE_OUTER = 1'b1;
	
	output	[31:0]	pad;

	input	[31:0]	skey;
	input		padmode;

	assign pad = skey ^ {4{1'b0, padmode, ~padmode, 1'b1, padmode, 1'b1, ~padmode, 1'b0}};
	
endmodule

module sha_controller (
	clk,
	resetn,
	start,
	sha_valid,
	ready2load,
	w_load,
	w_run,
	compress_init,
	compress_load,
	comresss_run,
	Kaddr,
	init_addr,
	pad_run,
	bitcount,
	ibitcount,
	msg_valid,
	load_counter,
	load_finish,
	padreset,
	padspecial,
	pad_zero,
	pad_en,
	padnextupdate,
	padnext,
	padlast	);
	
	parameter S_IDLE = 0, 
		S_INIT = 1,
		S_CALCPAD = 2,
		S_MSGLOAD = 3,
		S_COMPRESS = 4,
		S_WAIT = 5,
		S_UPDATE = 6,
		S_FIN = 7;
				
	input		clk;
	input		resetn;
	input		start;
	
	output		sha_valid;
	output		ready2load;
	
	output		w_load;
	output		w_run;
	
	output		compress_init;
	output		compress_load;
	output		comresss_run;
	
	output	[6:0]	Kaddr;
	output	[3:0]	init_addr;
	
	output		pad_run;
	output	[63:0]	bitcount;
	
	input	[63:0]	ibitcount;
	input		msg_valid;
	output	[3:0]	load_counter;
	input		load_finish;
	
	output		padreset;
	output		padspecial;
	input		pad_zero;
	input		pad_en;
	output		padnextupdate;
	input		padnext;
	input		padlast;
	
	reg	[2:0]	state, next_state;
	reg	[3:0]	rloadcounter;
	
	reg		rpadreset;
	reg		rpadspecial;
	reg		rskip;
	
	wire		sidle     = (state == S_IDLE);
	wire		sinit     = (state == S_INIT);
	wire		scalcpad  = (state == S_CALCPAD);
	wire		smsgload  = (state == S_MSGLOAD);
	wire		scompress = (state == S_COMPRESS);
	wire		swait     = (state == S_WAIT);
	wire		supdate   = (state == S_UPDATE);
	wire		sfin      = (state == S_FIN);
	
	reg	[3:0]	counter_init_update;
	reg	[5:0]	counter_calcpad;
	reg	[6:0]	counter_compress;
	reg	[63:0]	rbitcount;
	
	reg		nload;
	reg		rw_run;
	reg		r_padnext;
	
	wire	[63:0]	bitcount_sub = 64'd512;
	
	wire	[6:0]	iter = 7'd63;
	wire	[6:0]	iterplusone = 7'd64;
	wire		compress_fin = (counter_compress==iterplusone);
	
	always@(posedge clk) begin
		if(!resetn)	state <= S_IDLE;
		else		state <= next_state;
	end
	
	always@(*) begin
		case(state)
			S_IDLE:		next_state = (start) ? S_INIT : S_IDLE;
			S_INIT:		next_state = (counter_init_update[3]) ? S_CALCPAD : S_INIT;
			S_CALCPAD: begin
				if(counter_calcpad[5]) begin
					if(pad_zero&~r_padnext)
						next_state = S_IDLE;
					else	next_state = S_MSGLOAD;
				end
				else next_state = S_CALCPAD;
			end
			S_MSGLOAD:	next_state = (load_finish | ((&rloadcounter[3:0])&rpadspecial)) ? S_COMPRESS : S_MSGLOAD;
			S_COMPRESS:	next_state = (compress_fin) ? S_WAIT : S_COMPRESS;
			S_WAIT:		next_state = S_UPDATE;
			S_UPDATE:	next_state = (&counter_init_update[2:0]) ? S_FIN : S_UPDATE;
			S_FIN: begin
				if (rskip)	next_state = S_IDLE;
				else		next_state = (pad_zero & ~padnext) ? S_IDLE : S_CALCPAD;
			end
			default:	next_state = S_IDLE;
		endcase
	end
	
	always@(posedge clk) begin
		if(sidle)	rpadreset <= 1'b0;
		else		rpadreset <= sfin & padnext;
	end
	always@(posedge clk) begin
		if(sidle)		rskip <= 1'b0;
		else if(rpadreset)	rskip <= 1'b1;
		else			rskip <= rskip;
	end
	always@(posedge clk) begin
		if(sidle)		rpadspecial <= 1'b0;
		else if(sfin&padnext)	rpadspecial <= 1'b1;
		else			rpadspecial <= rpadspecial;
	end
	always@(posedge clk) begin
		if(sinit|supdate|swait)	counter_init_update <= counter_init_update + 1'b1;
		else			counter_init_update <= 4'd0;
	end
	always@(posedge clk) begin
		if(scalcpad)	counter_calcpad <= counter_calcpad + 1'b1;
		else		counter_calcpad <= 6'd0;
	end
	always@(posedge clk) begin
		if(scompress)	counter_compress <= counter_compress + 1'b1;
		else		counter_compress <= 7'd0;
	end
	always@(posedge clk) begin
		if(sinit)		rbitcount <= ibitcount;
		else if(swait) begin
			if(pad_en)	rbitcount <= 64'd0;
			else		rbitcount <= rbitcount - bitcount_sub;
		end
		else			rbitcount <= rbitcount;
	end
	always@(posedge clk) begin
		if(!resetn)	rw_run <= 1'b0;
		else		rw_run <=  scompress & (counter_compress <= iter);
	end
	always@(posedge clk) begin
		if(!resetn)						rloadcounter <= 4'd0;
		else if ((smsgload&msg_valid)|(smsgload&rpadspecial))	rloadcounter <= rloadcounter + 1'b1;
		else							rloadcounter <= 4'd0;
	end
	always@(posedge clk) begin
		if(!resetn)		nload <= 1'b0;
		else if(sidle)		nload <= 1'b0;
		else if(padnext)	nload <= 1'b1;
		else			nload <= nload;
	end
	always@(posedge clk) begin
		if(sidle)			r_padnext <= 1'b0;
		else if(supdate&padnext)	r_padnext <= 1'b1;
		else				r_padnext <= r_padnext;
	end
	
	assign sha_valid = sidle;
	assign ready2load = (smsgload&~nload);
	
	assign w_load = (smsgload&msg_valid) | (smsgload&rpadspecial);
	assign w_run  = rw_run;
	
	assign compress_init = sinit;
	assign compress_load = (swait|supdate);
	assign comresss_run  = rw_run;
	
	assign Kaddr = counter_compress;
	assign init_addr = {1'b0, counter_init_update[2:0]};
	
	assign load_counter = rloadcounter;
	
	assign padreset = rpadreset;
	assign padspecial = rpadspecial;
	assign pad_run = scalcpad;
	assign bitcount = rbitcount;
	
	assign padnextupdate = supdate;
	
endmodule

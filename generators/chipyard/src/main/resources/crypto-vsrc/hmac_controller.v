module hmac_controller (
	clk,
	resetn,
	enable,
	hmac_ready,
	usr_mode,
	sys_mode,
	read_digest,
	padmode,
	update_len,
	localresetn,
	sha_start,
	sha_read,
	sha_loadpad,
	sha_loadingmessage,
	sha_loadedmessage,
	sha_loaddigest,
	sha_ready2load,
	sha_fin,
	mem_addr,
	mem_we,
	sha_mode,
	iendofpacket	);

	parameter S_IDLE = 0,
		S_START0 = 1,
		S_WAIT0 = 2,
		S_IPAD = 3,
		S_WAIT1 = 4,
		S_WAIT1_0 = 5,
		S_MSGCOMPRESS = 6,
		S_STALL	 = 7,
		S_LOADMSG = 8,
		S_WAIT2 = 9,
		S_LOADHASH = 10,
		S_RESET = 11,
		S_START1 = 12,
		S_WAIT3 = 13,
		S_OPAD = 14,
		S_WAIT4 = 15,
		S_WAIT4_0 = 16,
		S_READDIG = 17,
		S_WAIT5 = 18,
		S_LOADRESULT = 19;
				
	parameter SHA_MODE256 = 3'b001;
	
	parameter HMAC_MODE = 2'b10,
		SHA_MODE = 2'b01;
				
	parameter PAD_INNER = 1'b0,
		PAD_OUTER = 1'b1;
	
	parameter ADDR_STATS = 7'd106,
		ADDR_LEN0 = 7'd104,
		ADDR_LEN1 = 7'd105,
		ADDR_SKEYBASE = 7'd96,
		ADDR_FDIGESTBASE = 7'd88;
				
//=========================================
//======= Begin Port declarations =========
//=========================================
	input		clk;
	input		resetn;
	input		enable;
	
	output		hmac_ready;
	output		usr_mode;
	output		sys_mode;
	output		read_digest;
	
	output		padmode;
	output		update_len;
	
	output		localresetn;
	output		sha_start;
	output		sha_read;
	output	[2:0]	sha_loadpad;
	output		sha_loadingmessage;
	output		sha_loadedmessage;
	output		sha_loaddigest;
	input		sha_ready2load;
	input		sha_fin;
	
	output	[5:0]	mem_addr;
	output		mem_we;
	
	input		sha_mode;
	input		iendofpacket;
	
//=========================================
//======= End Port declarations ===========
//=========================================
	reg	[4:0]	state, next_state;
	
	wire		sidle 		= (state == S_IDLE);
	wire		sstart0 	= (state == S_START0);
	//wire		swait0 		= (state == S_WAIT0);
	wire		sipad 		= (state == S_IPAD);
	//wire		swait1 		= (state == S_WAIT1);
	wire		smsgcompress	= (state == S_MSGCOMPRESS);
	wire		sloadmsg	= (state == S_LOADMSG);
	//wire		swait2		= (state == S_WAIT2);
	wire		sloadhash	= (state == S_LOADHASH);
	wire		sreset		= (state == S_RESET);
	wire		sstart1 	= (state == S_START1);
	//wire		swait3 		= (state == S_WAIT3);
	wire		sopad 		= (state == S_OPAD);
	//wire		swait4 		= (state == S_WAIT4);
	wire		sreaddig 	= (state == S_READDIG);
	//wire		swait5 		= (state == S_WAIT5);
	wire		sloadresult 	= (state == S_LOADRESULT);
	
	reg	[4:0]	counter;
	reg	[4:0]	rmem_addr;
	
	//wire		rsha_loadedmessage;
	reg		rpadmode;
	
	always@(posedge clk) begin
		if(!resetn)	state <= S_IDLE;
		else		state <= next_state;
	end
	
	always@(*) begin
		case(state)
			S_IDLE:		next_state = (enable) ? S_START0 : S_IDLE;
			S_START0:	next_state = S_WAIT0;
			S_WAIT0: begin
				if(sha_ready2load) begin
					if(sha_mode)	next_state = S_WAIT2;
					else		next_state = S_IPAD; end
				else	next_state = S_WAIT0;
			end
			S_IPAD:		next_state = (counter[4]) ? S_WAIT1 : S_IPAD;
			S_WAIT1:	next_state = S_WAIT1_0;
			S_WAIT1_0:	next_state = (sha_ready2load) ? S_WAIT2 : S_WAIT1_0;
			S_MSGCOMPRESS:	next_state = (counter[4]) ? S_STALL : S_MSGCOMPRESS;
			S_STALL:	next_state = S_WAIT2;
			S_WAIT2: begin
				if(sha_fin)	next_state = S_LOADHASH;
				else		next_state = sha_ready2load? S_LOADMSG: S_WAIT2;
				//if(sha_ready2load) next_state = iendofpacket? S_MSGCOMPRESS: S_WAIT2;
				//if(sha_ready2load) next_state = S_LOADMSG;
				//else next_state = S_WAIT2;
			end
			S_LOADMSG:	next_state = (iendofpacket) ? S_MSGCOMPRESS : S_LOADMSG;
			S_LOADHASH: begin
				if(&counter[2:0]) begin
					if(sha_mode)	next_state = S_IDLE;
					else		next_state = S_RESET; end
				else	next_state = S_LOADHASH;
			end
			S_RESET:	next_state = S_START1;
			S_START1:	next_state = S_WAIT3;
			S_WAIT3:	next_state = (sha_ready2load) ? S_OPAD : S_WAIT3;
			S_OPAD:		next_state = (counter[4]) ? S_WAIT4 : S_OPAD;
			S_WAIT4:	next_state = S_WAIT4_0;
			S_WAIT4_0:	next_state = (sha_ready2load) ? S_READDIG : S_WAIT4_0;
			S_READDIG:	next_state = (counter[4]) ? S_WAIT5 : S_READDIG;
			S_WAIT5:	next_state = (sha_fin) ? S_LOADRESULT : S_WAIT5;
			S_LOADRESULT:	next_state = (counter[3]) ? S_IDLE : S_LOADRESULT;
			default: next_state = S_IDLE;
		endcase
	end
	
	always@(posedge clk) begin
		if(sipad|sloadhash|sopad|sloadresult|sreaddig|smsgcompress)
			counter <= counter + 5'b1;
		else	counter <= 5'd0;
	end
	always@(posedge clk) begin
		if(sidle)		rpadmode <= 1'b0;
		else if(sloadhash)	rpadmode <= 1'b1;
		else			rpadmode <= rpadmode;
	end
	
	always@(*) begin
		//if(sipad|sopad)			rmem_addr = {2'b10, counter[2:0]};
		//else if(smsgcompress)			rmem_addr = {1'b0, counter[3:0]};
		//else if(sloadhash|sloadresult)	rmem_addr = {2'b11, counter[2:0]};
		//else					rmem_addr = {1'b0,  counter[3:0]};
		if(sipad|sopad|sloadhash|sloadresult) begin
			if(sloadhash|sloadresult)	rmem_addr = {2'b11, ~counter[2:0]};
			else				rmem_addr = {2'b10, counter[2:0]}; end
		else if(sreaddig)			rmem_addr = {2'b11, counter[2:0]};
		else					rmem_addr = {1'b0,  counter[3:0]};
	end
	//assign rsha_loadedmessage = (counter==16);
	
	assign hmac_ready = sidle;
	//assign usr_mode = (sidle|swait2);
	assign usr_mode = (sidle|sloadmsg);
	assign sys_mode = ~usr_mode;
	assign read_digest = sreaddig;
	
	assign padmode = rpadmode;
	assign update_len = (sstart0|sstart1);
	
	assign localresetn = ~sreset;
	assign sha_start = (sstart0|sstart1);
	assign sha_read = (sloadhash|sloadresult);
	assign sha_loadpad[0] = (sipad|sopad);
	assign sha_loadpad[1] = (counter>5'd8);
	assign sha_loadpad[2] = sha_loadpad[0] & (counter>5'd0) & (counter<=16);
	assign sha_loadingmessage = smsgcompress & (counter!=0);
	assign sha_loadedmessage = (counter==17);
	assign sha_loaddigest = sreaddig & (counter>5'd0) & (counter<=16);
	
	assign mem_addr = {1'b0, rmem_addr};
	assign mem_we = (sloadhash|sloadresult);
	
endmodule

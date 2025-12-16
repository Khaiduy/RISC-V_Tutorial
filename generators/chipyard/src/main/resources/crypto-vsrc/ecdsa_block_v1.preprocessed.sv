`define WT_DCACHE
`define DISABLE_TRACER
`define SRAM_NO_INIT
`define VERILATOR
package elliptic_curve_structs;

typedef struct packed {
    logic [255:0] x;
    logic [255:0] y;
} curve_point_t;


typedef struct packed {
    logic [255:0] p;
    logic [255:0] n;
    logic [255:0] a;
    logic [255:0] b;
    curve_point_t base_point;
} secp256k1_parameters;

secp256k1_parameters params = '{p:256'hffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
                                n:256'hffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
                                a:256'hffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
                                b:256'h5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
								base_point:{256'h6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
										    256'h4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5}};


typedef struct packed {
    logic m;            // m = 1 for secp256k1
    logic k;            // k = 256 for secp256k1
} barrett_constants_t;

barrett_constants_t barrett_constants = '{m:1, k:256};

typedef struct packed {
    logic [255:0] r;
    logic [255:0] s;
} signature_t;

endpackage : elliptic_curve_structs

import elliptic_curve_structs::*;
//import elliptic_curve_structs::*;

module add
	(input logic [255:0] a, b,
	 input logic op,
	output logic [255:0] sum);

logic [256:0] temp1, temp2;
	// op = 1, a-b mod p
	// op = 0, a+b mod p

always_comb
begin
	if(op) begin
			temp1 = a-b;
			temp2 = (a-b) + params.p;
			if(/*temp1[256]*/temp1 >= params.p)
				sum = temp2[255:0];
			else
				sum = temp1[255:0];
	end
	else begin
		temp1 = a + b;
		temp2 = (a + b) - params.p;
		if(temp1 >= params.p)
			sum = temp2[255:0];
		else
			sum = temp1[255:0];
	end
end
endmodule

//import elliptic_curve_structs::*;

/*module gen_point (
	input 	logic 			clk, Reset,
	input 	logic [255:0] 	privKey,
	input 	logic [255:0]  	in_point_x,
	input 	logic [255:0]  	in_point_y,
	output 	logic [255:0]  	out_point_y,
	output 	logic [255:0]  	out_point_x,
	output 	logic 			Done
);

enum logic [2:0] {Init, init_load,
	// find_start,
	Inc, Double, Add, dummy_op,
	Finish} State, Next_State;


	logic [255:0] priv_in, priv_out, x_in, x_out, y_in, y_out;
	logic [255:0] add_x_out, add_y_out, mult_x_out, mult_y_out, mult_x_in, mult_y_in, point_doub_x, point_doub_y;
	logic [7:0] count_in, count_out;
	logic priv_load, x_load, y_load, add_done, mult_done, count_load, add_reset, mult_reset, mult_x_load, mult_y_load;

	logic [255:0] gx, gy;
	assign gx = in_point_x;
	assign gy = in_point_y;

	//Private key register - will be shifted each round to check LSB
	reg_256 priv(.clk, .Load(priv_load), .Data(priv_in), .Out(priv_out));

	//Registers responsible for point doubling: 1G -> 2G -> 4G -> ...
	reg_256 mult_x(.clk, .Load(mult_x_load), .Data(mult_x_in), .Out(mult_x_out));
	reg_256 mult_y(.clk, .Load(mult_y_load), .Data(mult_y_in), .Out(mult_y_out));

	//Registers keeping track of public key calculation
	reg_256 x(.clk, .Load(x_load), .Data(x_in), .Out(x_out));
	reg_256 y(.clk, .Load(y_load), .Data(y_in), .Out(y_out));

	//Counter
	logic start_bit_load;
	logic [7:0] start_bit_in, start_bit_out;
	reg_256 #(8) count_reg(.clk, .Load(count_load), .Data(count_in), .Out(count_out));
	reg_256 #(8) start_bit_reg(.clk, .Load(start_bit_load), .Data(start_bit_in), .Out(start_bit_out));


	//Point addition and point doubling module instantiations
// TODO make less messy
curve_point_t add_R, add_P, add_Q;
assign add_P.x = mult_x_out;
assign add_Q.x = x_out;
assign add_P.y = mult_y_out;
assign add_Q.y = y_out;
point_add add0(.clk, .Reset(add_reset),
	.P_x(add_P.x),
	.P_y(add_P.y), 
	.Q_x(add_Q.x),
	.Q_y(add_Q.y),
	.R_x(add_R.x),
	.R_y(add_R.y),
	.Done(add_done)
);
assign add_x_out = add_R.x;
assign add_y_out = add_R.y;



curve_point_t doub_R, doub_P;
assign doub_P.x = mult_x_out;
assign doub_P.y = mult_y_out;
point_double doub0(.clk, .Reset(mult_reset),
	.P(doub_P),
	.R(doub_R),
	.Done(mult_done)
);
assign point_doub_x = doub_R.x;
assign point_doub_y = doub_R.y;

logic flag;
assign flag = priv_out[0];

    always_ff @ (posedge clk)
    begin
        if(Reset)
		begin
            State <= Init;
		end
        else begin
            State <= Next_State;
		end
    end

//Next state logic
always_comb begin
    Next_State = State;
    unique case(State)
		Init: Next_State = init_load;
		// find_start : begin
		// 	if(privKey[start_bit_out-1] == 1'b1)
		// 		Next_State = Add;
		// 	else Next_State = find_start;
		// end
		init_load : Next_State = Add;
		Inc: Next_State = Add;	//Skips doubling for the first round since the multiplication register are init to Gx, Gy
		Double:
		begin
			if(mult_done == 1'b1)	//Stays in this state until point double does its thing
				Next_State = Inc;
			else
				Next_State = Double;
		end
		dummy_op : if(add_done == 1'b1) Next_State = Double;
		Add:
		begin
			if(x_out == 0 && y_out == 0 && priv_out[0] == 1'b1)
				Next_State = Double;
			else if(add_done == 1'b0 && priv_out[0] == 1'b1)	//Stays here until point add finishes up
				Next_State = Add;
			else if(count_out == 8'd255)
			begin
				Next_State = Finish;
			end
			else if(priv_out[0] == 1'b0)
				Next_State = dummy_op;
			else Next_State = Double;
		end
		Finish: Next_State = Finish;
		default: ;
	endcase

	//Default vals
	priv_in = privKey;
	x_in = x_out;
	y_in = y_out;
	count_in = count_out;
	mult_x_in = mult_x_out;
	mult_y_in = mult_y_out;

	priv_load = 1'b0;
	x_load = 1'b0;
	y_load = 1'b0;
	count_load = 1'b0;
	mult_x_load = 1'b0;
	mult_y_load = 1'b0;

	add_reset = 1'b0;
	mult_reset = 1'b0;
	Done = 1'b0;

	out_point_x = 256'd0;
	out_point_y = 256'd0;

	start_bit_load = 0;
	start_bit_in = 8'd256;

	unique case(State)
		Init:
		begin
			add_reset = 1'b1;
			mult_reset = 1'b1;

			//Initialize public key registers with (0,0), a point not on the curve
			//add_point will not work properly with this point, so this provides a check
			x_load = 1'b1;
			y_load = 1'b1;
			x_in = 0;
			y_in = 0;

			//Init counter to 0
			count_in = 8'b0;
			count_load = 1'b1;
			start_bit_load = 1'b1;
			start_bit_in = 8'd256;

			//multiplier registers hold value of generator to start
			mult_x_in = gx;
			mult_y_in = gy;
			mult_x_load = 1'b1;
			mult_y_load = 1'b1;

			//Load private key reg


		end

		init_load : begin
			priv_load = 1'b1;
			priv_in = privKey;
		end
		//
		// find_start : begin
		// 	priv_in = privKey;
		// 	priv_load = 1'b1;
		// 	start_bit_load = 1'b1;
		// 	start_bit_in = start_bit_out - 1;
		// end

		Inc:
		begin
			//increment counter
			count_load = 1'b1;
			count_in = count_out + 8'b01;
			add_reset = 1'b1;

			//Shift private key register right
			priv_in = priv_out >> 1;
			priv_load = 1'b1;
		end
		Double:
		begin
			//Update multiplication registers
			mult_x_load = 1'b1;
			mult_y_load = 1'b1;
			if(mult_done == 1'b1)
			begin
				mult_x_in = point_doub_x;
				mult_y_in = point_doub_y;
			end
			else
			begin
				mult_x_in = mult_x_out;
				mult_y_in = mult_y_out;
			end
		end

		dummy_op:
		begin
			if(add_done == 1'b1)
				mult_reset = 1'b1;
		end

		Add:
		begin
			mult_reset = 1'b1;
			if(priv_out[0] == 1'b1)
			begin
				x_load = 1'b1;
				y_load = 1'b1;
				if(x_out == 0 && y_out == 0)//Since (0,0) does not lie on the curve, we use it to indicate no adds have been completed yet
				begin
					x_in = mult_x_out;
					y_in = mult_y_out;
				end
				else	//Normal point addition
				begin
					if(add_done == 1'b1)
					begin
						x_in = add_x_out;
						y_in = add_y_out;
					end
				end
			end
			else if(priv_out[0] == 1'b0)
				add_reset = 1'b1;
			else	//Do nothing
			begin
				x_in = x_out;
				y_in = y_out;
			end
		end
		Finish:
		begin
			out_point_x = x_out;
			out_point_y = y_out;
			Done = 1'b1;
		end
		default:;
	endcase

end

endmodule*/

module gen_point (
	input 	logic 			clk, Reset,
	input 	logic [255:0] 	privKey,
	input 	logic [255:0]  	in_point_x,
	input 	logic [255:0]  	in_point_y,
	output 	logic [255:0]  	out_point_y,
	output 	logic [255:0]  	out_point_x,
	output 	logic 			Done
);

enum logic [3:0] {Init, Cal_r1,Save_r1, Counter_init,Counter_down, Counter,R02, Save_r02, R12,Save_r12,Resett, Finish} State, Next_State;


	logic [255:0] r0_x_in, r0_y_in, r1_x_in, r1_y_in;
	logic [255:0] r0_x_out, r0_y_out, r1_x_out, r1_y_out;
	logic [7:0] count_in, count_out;
	logic r0_x_load, r0_y_load, r1_x_load, r1_y_load, count_load;

	logic [255:0] gx, gy;
	assign gx = in_point_x;
	assign gy = in_point_y;

    logic add_reset,mult_reset;
    logic add_done, mult_done;
    logic r1_select;
    
    logic [255:0] point_doub_x,point_doub_y;
    
    logic [255:0] add_out_x, double_out_x, add_out_y, double_out_y;

	//Registers responsible for point doubling: 1G -> 2G -> 4G -> ...
	reg_256 r0_x(.clk, .Load(r0_x_load), .Data(r0_x_in), .Out(r0_x_out));
	reg_256 r0_y(.clk, .Load(r0_y_load), .Data(r0_y_in), .Out(r0_y_out));

	//Registers keeping track of public key calculation
	reg_256 r1_x(.clk, .Load(r1_x_load), .Data(r1_x_in), .Out(r1_x_out));
	reg_256 r1_y(.clk, .Load(r1_y_load), .Data(r1_y_in), .Out(r1_y_out));

	//Counter
	reg_256 #(8) count_reg(.clk, .Load(count_load), .Data(count_in), .Out(count_out));


	//Point addition and point doubling module instantiations
// TODO make less messy

point_add add0(.clk, .Reset(add_reset),
	.P_x(r0_x_out),
	.P_y(r0_y_out), 
	.Q_x(r1_x_out),
	.Q_y(r1_y_out),
	.R_x(add_out_x),
	.R_y(add_out_y),
	.Done(add_done)
);

curve_point_t doub_R, doub_P;
assign doub_P.x =(r1_select)? r1_x_out: r0_x_out;
assign doub_P.y =(r1_select)? r1_y_out: r0_y_out;

point_double doub0(.clk, .Reset(mult_reset),
	.P(doub_P),
	.R(doub_R),
	.Done(mult_done)
);
assign point_doub_x = doub_R.x;
assign point_doub_y = doub_R.y;

    always_ff @ (posedge clk)
    begin
        if(Reset)
		begin
            State <= Init;
		end
        else begin
            State <= Next_State;
		end
    end

//Next state logic
always_comb begin
    Next_State = State;
    unique case(State)
		Init: Next_State = Cal_r1;
        Cal_r1:
        begin
            if(mult_done == 1'b1)	//Stays in this state until point double does its thing
				Next_State = Save_r1;
			else
				Next_State = Cal_r1;
        end
        Save_r1 : Next_State = Counter_init;
		Counter_init :
		begin
		  if(privKey[count_out] == 1'b1)	//Stays in this state until point double does its thing
				Next_State = Counter;
		  else
				Next_State = Counter_down;
        end
        Counter_down :
				Next_State = Counter_init;
        Counter :
        begin
		  if(privKey[count_out-1] == 1'b1)	//Stays in this state until point double does its thing
				Next_State = R12;
		  else
				Next_State = R02;
        end
		R02 :
        begin
		  if(add_done == 1'b0 || mult_done == 1'b0)	//Stays in this state until point double does its thing
				Next_State = R02;
		  else
				Next_State = Save_r02;
        end
		R12 :
        begin
		  if(add_done == 1'b0 || mult_done == 1'b0)	//Stays in this state until point double does its thing
				Next_State = R12;
		  else
				Next_State = Save_r12;
        end
        Save_r02: 
        begin
        Next_State = Resett;
        end
        Save_r12:
        begin
        Next_State = Resett;
        end
        Resett:
        begin
        if(count_out == 1'b0)	//Stays in this state until point double does its thing
				Next_State = Finish;
		else
        Next_State = Counter;
        end
		Finish: Next_State = Finish;
		default: ;
	endcase

	//Default vals
	r0_x_in = r0_x_out;
	r0_y_in = r0_y_out;
	r1_x_in = r1_x_out; 
	r1_y_in = r1_y_out;
	count_in = count_out;
	r0_x_load = 1'b0; 
	r0_y_load = 1'b0; 
	r1_x_load = 1'b0; 
	r1_y_load = 1'b0; 
	count_load = 1'b0;
    add_reset= 1'b1;;
    mult_reset= 1'b1;
    r1_select = 1'b0;
    Done = 0;
    out_point_x = 0;
    out_point_y = 0;
	unique case(State)
		Init:
		begin
			add_reset = 1'b1;
			mult_reset = 1'b1;
			r0_x_load = 1'b1;
			r0_y_load = 1'b1;
			r0_x_in = gx;
			r0_y_in = gy;
			count_in = 8'b11111111;
			count_load = 1'b1;
            r1_select = 0;
		end
		Cal_r1 : begin
			mult_reset= 1'b0;
		end
		Save_r1: begin
            r1_y_load = 1;
            r1_x_load = 1;
            r1_x_in= point_doub_x;
            r1_y_in= point_doub_y;
		end
        Counter_init :
		begin
		
		//count_in =count_out -1 ;
        //count_load = 1'b1;
        end
        Counter_down:
		begin
		count_in =count_out -1 ;
        count_load = 1'b1;
        end
        Counter :
        begin
		count_in =count_out -1 ;
        count_load = 1'b1;  
        end
		R02 :
        begin
            add_reset = 1'b0;
            mult_reset = 1'b0;
            r1_select=0; 
            r0_x_in= point_doub_x;
            r0_y_in= point_doub_y;
            r1_x_in = add_out_x;
            r1_y_in = add_out_y;
        end
        Save_r02:
        begin
        r1_select=0; 
        add_reset = 1'b0;
		mult_reset = 1'b0;
        r1_x_in= add_out_x ;
        r1_y_in= add_out_y;
        r1_x_load=1'b1;
        r1_y_load=1'b1;
        r0_x_load=1'b1;
        r0_y_load=1'b1;
        r0_x_in =point_doub_x ;
        r0_y_in =point_doub_y ;
        end
		R12 :
        begin
            add_reset = 1'b0;
			mult_reset = 1'b0;
			r1_select=1; 
			r1_x_in= point_doub_x;
            r1_y_in= point_doub_y;
            r0_x_in = add_out_x;
            r0_y_in = add_out_y;
        end
        Save_r12:
        begin
         r1_select=1;
         add_reset = 1'b0;
		 mult_reset = 1'b0;
         r0_x_in= add_out_x;
         r0_y_in= add_out_y;
         r0_x_load=1'b1;
         r0_y_load=1'b1;
         r1_x_in =point_doub_x ;
         r1_y_in =point_doub_y ;
         r1_x_load=1'b1;
         r1_y_load=1'b1;
        end
        Resett:
        begin
        end
		Finish:
		begin
			out_point_x = r0_x_out;
			out_point_y = r0_y_out;
			Done = 1'b1;
		end
		default:;
	endcase

end

endmodule

/*import elliptic_curve_structs::*;

module modular_inverse (
	input logic clk, Reset,
	input logic [511:0] in,
	output logic [255:0] out,
	output logic Done
);

	//Since Z = 2 for the case of binary polynomials, all divisions can be preformed via a right shift, and all
	//**divisibility checks can be preformed by checking the least signifigant bit.
	//**Since the only elliptic curve operations we have to worry about are point doubling and point adding, we're
	//**not concerned with numbers greater than 2P, which will be limited to 257 bits
	//**
	//**UPDATE 11/22: Ditched that assumption, now allows inputs up to 512 bits instead of 257

	//Control Signals
	logic u_load, v_load, g1_load, g2_load, status, count_load;
	logic [511:0] u_in, u_out, g1_in, g1_out, g2_in, g2_out;
	logic [511:0] v_in, v_out;
	logic [10:0] count_in, count_out;

	//State machine states
	enum logic [2:0] {Init, Start, Check_u, Check_v, Check_deg, Finish, Waitt} State, Next_State;


	//Register Instatntations
	reg_256 #(512) u(.clk, .Load(u_load), .Data(u_in), .Out(u_out));
	reg_256 #(512) v(.clk, .Load(v_load), .Data(v_in), .Out(v_out));
	reg_256 #(512) g1(.clk, .Load(g1_load), .Data(g1_in), .Out(g1_out));
	reg_256 #(512) g2(.clk, .Load(g2_load), .Data(g2_in), .Out(g2_out));

	reg_256 #(11) counter(.clk, .Load(count_load), .Data(count_in), .Out(count_out));

	//State machine behavior
	always_ff @ (posedge clk)
	begin
		if(Reset)
		    State <= Init;
		else
		    State <= Next_State;
	end

	//Next State Logic
	always_comb
	begin
		Next_State = State;
		unique case(State)
			Init:
			begin
				Next_State = Start;
			end
			Start:
			begin
				if(u_out == 512'b01 || v_out == 512'b01)
					Next_State = Waitt;
				else if(u_out[0] == 0)
					Next_State = Check_u;
				else if(v_out[0] == 0)
					Next_State = Check_v;
				else
					Next_State = Check_deg;
			end
			Check_u:
			begin
				 if(u_out[0] == 0)
					Next_State = Check_u;
				else if(v_out[0] == 0)
					Next_State = Check_v;
				else
					Next_State = Check_deg;
			end
			Check_v:
			begin
				 if(v_out[0] == 0)
					Next_State = Check_v;
				else
					Next_State = Check_deg;
			end
			Check_deg:
			begin
				Next_State = Start;
			end
			Waitt : if(count_out == 11'd470) Next_State = Finish;
			Finish:
			begin
				Next_State = Finish;
			end
			default: Next_State = Init;
		endcase

		//Default values
		u_in = u_out;
		v_in = v_out;
		g1_in = g1_out;
		g2_in = g2_out;
		u_load = 1'b0;
		v_load = 1'b0;
		g1_load = 1'b0;
		g2_load = 1'b0;
		out = 256'b0;
		Done = 1'b0;
		count_load = 1'b1;
		count_in = count_out + 1;
	//Preform algorithm steps
		unique case(State)
			Init:
			begin
				u_in = in;
				v_in = params.p;
				Done = 1'b0;
				g1_in = 512'b01;
				g2_in = 512'b0;
				u_load = 1'b1;
				v_load = 1'b1;
				g1_load = 1'b1;
				g2_load = 1'b1;
				count_in = 0;
			end
			Start:
			begin
			end
			Check_u:
			begin
				u_in = u_out >> 1;	//Divide by z (z=2)
				if(g1_out[0] == 0)
					g1_in = g1_out >> 1;
				else
					g1_in = (g1_out + params.p) >> 1;
				if(u_out != 512'b01 && u_out[0] == 0)
				begin
					u_load = 1'b1;
					g1_load = 1'b1;
				end
			end
			Check_v:
			begin
				v_in = v_out >> 1;
				if(g2_out[0] == 0)
					g2_in = g2_out >> 1;
				else
					g2_in = (g2_out + params.p) >> 1;
				if(v_out != 512'b01 && v_out[0] == 0)
				begin
					v_load = 1'b1;
					g2_load = 1'b1;
				end
			end
			Check_deg:
			begin
				//Checks if deg(u) > deg(v)
				if(u_out > v_out && u_out >= ((v_out << 1) - v_out))
				begin
					u_in = u_out + v_out;
					g1_in = g1_out + g2_out;
					u_load = 1'b1;
					g1_load = 1'b1;
				end
				else
				begin
					v_in = v_out + u_out;
					g2_in = g2_out + g1_out;
					v_load = 1'b1;
					g2_load = 1'b1;
				end
			end
			Waitt : begin
				if(count_out != 11'd470)
					count_in = count_out + 1;
			end
			Finish:
			begin
				Done = 1'b1;
				if(u_out == 512'b01)
					out = g1_out[255:0];
				else
					out = g2_out[255:0];
			end
			default: ;
		endcase
	end


endmodule*/

//import elliptic_curve_structs::*;

module modular_inverse (
	input logic clk, Reset,
	input logic [255:0] in,
	output logic [255:0] out,
	output logic Done
);

	//Since Z = 2 for the case of binary polynomials, all divisions can be preformed via a right shift, and all
	//**divisibility checks can be preformed by checking the least signifigant bit.
	//**Since the only elliptic curve operations we have to worry about are point doubling and point adding, we're
	//**not concerned with numbers greater than 2P, which will be limited to 257 bits
	//**
	//**UPDATE 11/22: Ditched that assumption, now allows inputs up to 512 bits instead of 257
	

	//Control Signals
	logic u_load, v_load, g1_load, g2_load, status, count_load;
	logic [511:0] u_in, u_out, g1_in, g1_out, g2_in, g2_out;
	logic [511:0] v_in, v_out;
	logic [10:0] count_in, count_out;

	//State machine states
	enum logic [3:0] {Init, Start, Check_u, Check_v, Check_uv, Check_deg,Check_g1,Check_g2, Finish, Waitt} State, Next_State;


	//Register Instatntations
	reg_256 #(512) u(.clk, .Load(u_load), .Data(u_in), .Out(u_out));
	reg_256 #(512) v(.clk, .Load(v_load), .Data(v_in), .Out(v_out));
	reg_256 #(512) g1(.clk, .Load(g1_load), .Data(g1_in), .Out(g1_out));
	reg_256 #(512) g2(.clk, .Load(g2_load), .Data(g2_in), .Out(g2_out));

	reg_256 #(11) counter(.clk, .Load(count_load), .Data(count_in), .Out(count_out));

	//State machine behavior
	always_ff @ (posedge clk)
	begin
		if(Reset)
		    State <= Init;
		else
		    State <= Next_State;
	end

	//Next State Logic
	always_comb
	begin
		Next_State = State;
		unique case(State)
			Init:
			begin
				Next_State = Start;
			end
			Start:
			begin
				if(u_out == 512'b01 && v_out == 512'b01)
					Next_State = Waitt;
				else if(u_out[0] == 0)
					Next_State = Check_u;
				else if(v_out[0] == 0)
					Next_State = Check_v;
				else if(u_out > v_out)
					Next_State = Check_uv;
				else
					Next_State = Check_deg;
			end
			Check_u:
			begin
				 Next_State = Start;
			end
			Check_v:
			begin
				Next_State = Start;
			end
			Check_uv:
			begin
				Next_State = Check_g1;
			end
			Check_g1:
			begin
				Next_State = Start;
			end
			Check_deg:
			begin
				Next_State = Check_g2;
			end
			Check_g2:
			begin
				Next_State = Start;
			end
			Waitt :Next_State = Finish;
			Finish:
			begin
				Next_State = Finish;
			end
			default: Next_State = Init;
		endcase

		//Default values
		u_in = u_out;
		v_in = v_out;
		g1_in = g1_out;
		g2_in = g2_out;
		u_load = 1'b0;
		v_load = 1'b0;
		g1_load = 1'b0;
		g2_load = 1'b0;
		out = 256'b0;
		Done = 1'b0;
		count_load = 1'b1;
		count_in = count_out + 1;
	//Preform algorithm steps
		unique case(State)
			Init:
			begin
				u_in = {256'b0,in};
				v_in = params.p;
				Done = 1'b0;
				g1_in = 512'b01;
				g2_in = 512'b0;
				u_load = 1'b1;
				v_load = 1'b1;
				g1_load = 1'b1;
				g2_load = 1'b1;
				count_in = 0;
			end
			Start:
			begin
			end
			Check_u:
			begin
				u_in = u_out >> 1;	//Divide by z (z=2)
				if(g1_out[0] == 0)
					g1_in = g1_out >> 1;
				else
					g1_in = (g1_out + params.p) >> 1;
				//if(u_out != 512'b01 && u_out[0] == 0)
				///begin
					u_load = 1'b1;
					g1_load = 1'b1;
				//end
			end
			Check_v:
			begin
				v_in = v_out >> 1;
				if(g2_out[0] == 0)
					g2_in = g2_out >> 1;
				else
					g2_in = (g2_out + params.p) >> 1;
				//if(v_out != 512'b01 && v_out[0] == 0)
				//begin
					v_load = 1'b1;
					g2_load = 1'b1;
				//end
			end
			Check_uv:
			begin
				u_in = (u_out - v_out) >> 1;
				if(g1_out>g2_out)
					g1_in =g1_out-g2_out;
				else
					g1_in = (g1_out-g2_out + params.p);
				//if(v_out != 512'b01 && v_out[0] == 0)
				//begin
					u_load = 1'b1;
					g1_load = 1'b1;
				//end
			end
			Check_g1:
			begin
				if(g1_out[0]== 0)
					g1_in =g1_out>>1;
				else
					g1_in = (g1_out + params.p)>>1;
				//if(v_out != 512'b01 && v_out[0] == 0)
				//begin
					g1_load = 1'b1;
				//end
			end
			Check_deg:
			begin
				v_in = (v_out - u_out) >> 1;
				if(g2_out>g1_out)
					g2_in =g2_out-g1_out;
				else
					g2_in = (g2_out-g1_out + params.p);
				//if(v_out != 512'b01 && v_out[0] == 0)
				//begin
					v_load = 1'b1;
					g2_load = 1'b1;
				//end
			end
			Check_g2:
			begin
				if(g2_out[0]== 0)
					g2_in =g2_out>>1;
				else
					g2_in = (g2_out + params.p)>>1;
				//if(v_out != 512'b01 && v_out[0] == 0)
				//begin
					g2_load = 1'b1;
				//end
			end
			Waitt : begin
				if(count_out <= 11'd470)
					count_in = count_out + 1;
			end
			Finish:
			begin
				Done = 1'b1;
				//if(u_out == 512'b01)
					out = g1_out[255:0];
				//else
				//	out = g2_out[255:0];
			end
			default: ;
		endcase
	end


endmodule

//import elliptic_curve_structs::*;

module multiplier (
	input 	logic 				clk, Reset,
	input 	logic [255:0] 		a, b,
	output 	logic 				Done,
	output 	logic [255:0] 		product
);

/* multiplication using bit shifting and adding */

logic [255:0] a_in, a_out, count_in, count_out;
logic [257:0] b_in, b_out,c_in, c_out;
logic a_load, b_load, c_load, count_load;

reg_256 a_reg(.clk, .Load(a_load), .Data(a_in), .Out(a_out));
reg_256 #(258) b_reg(.clk, .Load(b_load), .Data(b_in), .Out(b_out));
reg_256 #(258) c_reg(.clk, .Load(c_load), .Data(c_in), .Out(c_out));
reg_256 #(256) count(.clk, .Load(count_load), .Data(count_in), .Out(count_out));

enum logic [2:0] {
	Init, Start,
	setB, redB, setC,
	Finish
}	State, Next_State;

always_ff @ (posedge clk)
begin
    if(Reset)
	begin
        State <= Init;
	end
    else
        State <= Next_State;
end


always_comb begin
    Next_State = State;
    unique case(State)
		Init: Next_State = Start;
		Start: Next_State = setB;
		setB:
		begin
			if((b_out << 1) >= {2'b00,params.p})
				Next_State = redB;
			else
				Next_State = setC;
		end
		redB:
		begin
			if(b_out >= {2'b00,params.p})
				Next_State = redB;
			else
				Next_State = setC;
		end
		setC:
		begin
			if(count_out == 8'd254)
				Next_State = Finish;
			else
				Next_State = setB;
		end
		Finish:
			Next_State = Finish;
		default: ;
	endcase

	count_in = count_out;
	b_in = b_out;
	c_in = c_out;
	a_in = a_out;

	count_load = 1'b0;
	a_load = 1'b0;
	b_load = 1'b0;
	c_load = 1'b0;
	product = 256'b0;
	Done = 1'b0;

	unique case(State)
		Init:
		begin
			Done = 1'b0;
			count_in = 8'b0;
			a_in = a;
			b_in = {2'b0, b};
			c_in = 258'b0;

			count_load = 1'b1;
			a_load = 1'b1;
			b_load = 1'b1;
			c_load = 1'b1;
		end
		Start:
		begin
			if(a[0] == 1)
				c_in = b_out;
			else
				c_in = 258'b0;
			c_load = 1'b1;
		end
		setB:
		begin
			a_in = a_out >> 1;
			a_load = 1'b1;
			b_load = 1'b1;
			b_in = b_out << 1;
		end
		redB:
		begin
			b_load = 1'b1;
			if(b_out >= {2'b00, params.p})
				b_in = b_out - {2'b00,params.p};
			else
				b_in = b_out;
		end
		setC:
		begin
			c_load = 1'b1;
			if(a_out[0] == 1'b1)
			begin
				if((c_out + b_out) >= {2'b00, params.p})
					c_in = (c_out + b_out) - {2'b00, params.p};
				else
					c_in = c_out + b_out;
			end
			else
			begin
				if(c_out >= {2'b00, params.p})
					c_in = c_out - params.p;
				else
					c_in = c_out;
			end
			//increment counter
			count_in = count_out + 8'b01;
			count_load = 1'b1;
		end
		Finish:
		begin
			if(c_out < params.p)
			begin
				Done = 1'b1;
				product = c_out[255:0];
			end
			else
			begin
				c_in = c_out - {2'b00,params.p};
				c_load = 1'b1;
				Done = 1'b0;
			end
		end
		default: ;
	endcase
end

endmodule

/*import elliptic_curve_structs::*;

module modular_inverse (
	input logic clk, Reset,
	input logic [511:0] in,
	output logic [255:0] out,
	output logic Done
);

	//Since Z = 2 for the case of binary polynomials, all divisions can be preformed via a right shift, and all
	//**divisibility checks can be preformed by checking the least signifigant bit.
	//**Since the only elliptic curve operations we have to worry about are point doubling and point adding, we're
	//**not concerned with numbers greater than 2P, which will be limited to 257 bits
	//**
	//**UPDATE 11/22: Ditched that assumption, now allows inputs up to 512 bits instead of 257

	//Control Signals
	logic u_load, v_load, g1_load, g2_load, status, count_load;
	logic [511:0] u_in, u_out, g1_in, g1_out, g2_in, g2_out;
	logic [511:0] v_in, v_out;
	logic [10:0] count_in, count_out;

	//State machine states
	enum logic [2:0] {Init, Start, Check_u, Check_v, Check_deg, Finish, Waitt} State, Next_State;


	//Register Instatntations
	reg_256 #(512) u(.clk, .Load(u_load), .Data(u_in), .Out(u_out));
	reg_256 #(512) v(.clk, .Load(v_load), .Data(v_in), .Out(v_out));
	reg_256 #(512) g1(.clk, .Load(g1_load), .Data(g1_in), .Out(g1_out));
	reg_256 #(512) g2(.clk, .Load(g2_load), .Data(g2_in), .Out(g2_out));

	reg_256 #(11) counter(.clk, .Load(count_load), .Data(count_in), .Out(count_out));

	//State machine behavior
	always_ff @ (posedge clk)
	begin
		if(Reset)
		    State <= Init;
		else
		    State <= Next_State;
	end

	//Next State Logic
	always_comb
	begin
		Next_State = State;
		unique case(State)
			Init:
			begin
				Next_State = Start;
			end
			Start:
			begin
				if(u_out == 512'b01 || v_out == 512'b01)
					Next_State = Waitt;
				else if(u_out[0] == 0)
					Next_State = Check_u;
				else if(v_out[0] == 0)
					Next_State = Check_v;
				else
					Next_State = Check_deg;
			end
			Check_u:
			begin
				 if(u_out[0] == 0)
					Next_State = Check_u;
				else if(v_out[0] == 0)
					Next_State = Check_v;
				else
					Next_State = Check_deg;
			end
			Check_v:
			begin
				 if(v_out[0] == 0)
					Next_State = Check_v;
				else
					Next_State = Check_deg;
			end
			Check_deg:
			begin
				Next_State = Start;
			end
			Waitt : if(count_out == 11'd470) Next_State = Finish;
			Finish:
			begin
				Next_State = Finish;
			end
			default: Next_State = Init;
		endcase

		//Default values
		u_in = u_out;
		v_in = v_out;
		g1_in = g1_out;
		g2_in = g2_out;
		u_load = 1'b0;
		v_load = 1'b0;
		g1_load = 1'b0;
		g2_load = 1'b0;
		out = 256'b0;
		Done = 1'b0;
		count_load = 1'b1;
		count_in = count_out + 1;
	//Preform algorithm steps
		unique case(State)
			Init:
			begin
				u_in = in;
				v_in = params.n;
				Done = 1'b0;
				g1_in = 512'b01;
				g2_in = 512'b0;
				u_load = 1'b1;
				v_load = 1'b1;
				g1_load = 1'b1;
				g2_load = 1'b1;
				count_in = 0;
			end
			Start:
			begin
			end
			Check_u:
			begin
				u_in = u_out >> 1;	//Divide by z (z=2)
				if(g1_out[0] == 0)
					g1_in = g1_out >> 1;
				else
					g1_in = (g1_out + params.n) >> 1;
				if(u_out != 512'b01 && u_out[0] == 0)
				begin
					u_load = 1'b1;
					g1_load = 1'b1;
				end
			end
			Check_v:
			begin
				v_in = v_out >> 1;
				if(g2_out[0] == 0)
					g2_in = g2_out >> 1;
				else
					g2_in = (g2_out + params.n) >> 1;
				if(v_out != 512'b01 && v_out[0] == 0)
				begin
					v_load = 1'b1;
					g2_load = 1'b1;
				end
			end
			Check_deg:
			begin
				//Checks if deg(u) > deg(v)
				if(u_out > v_out && u_out >= ((v_out << 1) - v_out))
				begin
					u_in = u_out + v_out;
					g1_in = g1_out + g2_out;
					u_load = 1'b1;
					g1_load = 1'b1;
				end
				else
				begin
					v_in = v_out + u_out;
					g2_in = g2_out + g1_out;
					v_load = 1'b1;
					g2_load = 1'b1;
				end
			end
			Waitt : begin
				if(count_out != 11'd470)
					count_in = count_out + 1;
			end
			Finish:
			begin
				Done = 1'b1;
				if(u_out == 512'b01)
					out = g1_out[255:0];
				else
					out = g2_out[255:0];
			end
			default: ;
		endcase
	end


endmodule*/

//import elliptic_curve_structs::*;

module modular_inverse_n (
	input logic clk, Reset,
	input logic [255:0] in,
	output logic [255:0] out,
	output logic Done
);

	//Since Z = 2 for the case of binary polynomials, all divisions can be preformed via a right shift, and all
	//**divisibility checks can be preformed by checking the least signifigant bit.
	//**Since the only elliptic curve operations we have to worry about are point doubling and point adding, we're
	//**not concerned with numbers greater than 2P, which will be limited to 257 bits
	//**
	//**UPDATE 11/22: Ditched that assumption, now allows inputs up to 512 bits instead of 257
	

	//Control Signals
	logic u_load, v_load, g1_load, g2_load, status, count_load;
	logic [511:0] u_in, u_out, g1_in, g1_out, g2_in, g2_out;
	logic [511:0] v_in, v_out;
	logic [10:0] count_in, count_out;

	//State machine states
	enum logic [3:0] {Init, Start, Check_u, Check_v, Check_uv, Check_deg,Check_g1,Check_g2, Finish, Waitt} State, Next_State;


	//Register Instatntations
	reg_256 #(512) u(.clk, .Load(u_load), .Data(u_in), .Out(u_out));
	reg_256 #(512) v(.clk, .Load(v_load), .Data(v_in), .Out(v_out));
	reg_256 #(512) g1(.clk, .Load(g1_load), .Data(g1_in), .Out(g1_out));
	reg_256 #(512) g2(.clk, .Load(g2_load), .Data(g2_in), .Out(g2_out));

	reg_256 #(11) counter(.clk, .Load(count_load), .Data(count_in), .Out(count_out));

	//State machine behavior
	always_ff @ (posedge clk)
	begin
		if(Reset)
		    State <= Init;
		else
		    State <= Next_State;
	end

	//Next State Logic
	always_comb
	begin
		Next_State = State;
		unique case(State)
			Init:
			begin
				Next_State = Start;
			end
			Start:
			begin
				if(u_out == 512'b01 && v_out == 512'b01)
					Next_State = Waitt;
				else if(u_out[0] == 0)
					Next_State = Check_u;
				else if(v_out[0] == 0)
					Next_State = Check_v;
				else if(u_out > v_out)
					Next_State = Check_uv;
				else
					Next_State = Check_deg;
			end
			Check_u:
			begin
				 Next_State = Start;
			end
			Check_v:
			begin
				Next_State = Start;
			end
			Check_uv:
			begin
				Next_State = Check_g1;
			end
			Check_g1:
			begin
				Next_State = Start;
			end
			Check_deg:
			begin
				Next_State = Check_g2;
			end
			Check_g2:
			begin
				Next_State = Start;
			end
			Waitt :Next_State = Finish;
			Finish:
			begin
				Next_State = Finish;
			end
			default: Next_State = Init;
		endcase

		//Default values
		u_in = u_out;
		v_in = v_out;
		g1_in = g1_out;
		g2_in = g2_out;
		u_load = 1'b0;
		v_load = 1'b0;
		g1_load = 1'b0;
		g2_load = 1'b0;
		out = 256'b0;
		Done = 1'b0;
		count_load = 1'b1;
		count_in = count_out + 1;
	//Preform algorithm steps
		unique case(State)
			Init:
			begin
				u_in = {256'b0,in};
				v_in = params.n;
				Done = 1'b0;
				g1_in = 512'b01;
				g2_in = 512'b0;
				u_load = 1'b1;
				v_load = 1'b1;
				g1_load = 1'b1;
				g2_load = 1'b1;
				count_in = 0;
			end
			Start:
			begin
			end
			Check_u:
			begin
				u_in = u_out >> 1;	//Divide by z (z=2)
				if(g1_out[0] == 0)
					g1_in = g1_out >> 1;
				else
					g1_in = (g1_out + params.n) >> 1;
				//if(u_out != 512'b01 && u_out[0] == 0)
				///begin
					u_load = 1'b1;
					g1_load = 1'b1;
				//end
			end
			Check_v:
			begin
				v_in = v_out >> 1;
				if(g2_out[0] == 0)
					g2_in = g2_out >> 1;
				else
					g2_in = (g2_out + params.n) >> 1;
				//if(v_out != 512'b01 && v_out[0] == 0)
				//begin
					v_load = 1'b1;
					g2_load = 1'b1;
				//end
			end
			Check_uv:
			begin
				u_in = (u_out - v_out) >> 1;
				if(g1_out>g2_out)
					g1_in =g1_out-g2_out;
				else
					g1_in = (g1_out-g2_out + params.n);
				//if(v_out != 512'b01 && v_out[0] == 0)
				//begin
					u_load = 1'b1;
					g1_load = 1'b1;
				//end
			end
			Check_g1:
			begin
				if(g1_out[0]== 0)
					g1_in =g1_out>>1;
				else
					g1_in = (g1_out + params.n)>>1;
				//if(v_out != 512'b01 && v_out[0] == 0)
				//begin
					g1_load = 1'b1;
				//end
			end
			Check_deg:
			begin
				v_in = (v_out - u_out) >> 1;
				if(g2_out>g1_out)
					g2_in =g2_out-g1_out;
				else
					g2_in = (g2_out-g1_out + params.n);
				//if(v_out != 512'b01 && v_out[0] == 0)
				//begin
					v_load = 1'b1;
					g2_load = 1'b1;
				//end
			end
			Check_g2:
			begin
				if(g2_out[0]== 0)
					g2_in =g2_out>>1;
				else
					g2_in = (g2_out + params.n)>>1;
				//if(v_out != 512'b01 && v_out[0] == 0)
				//begin
					g2_load = 1'b1;
				//end
			end
			Waitt : begin
				if(count_out <= 11'd470)
					count_in = count_out + 1;
			end
			Finish:
			begin
				Done = 1'b1;
				//if(u_out == 512'b01)
					out = g1_out[255:0];
				//else
				//	out = g2_out[255:0];
			end
			default: ;
		endcase
	end


endmodule

//import elliptic_curve_structs::*;

module multiplier_n (
	input 	logic 				clk, Reset,
	input 	logic [255:0] 		a, b,
	output 	logic 				Done,
	output 	logic [255:0] 		product
);

/* multiplication using bit shifting and adding */

logic [255:0] a_in, a_out, count_in, count_out;
logic [257:0] b_in, b_out,c_in, c_out;
logic a_load, b_load, c_load, count_load;

reg_256 a_reg(.clk, .Load(a_load), .Data(a_in), .Out(a_out));
reg_256 #(258) b_reg(.clk, .Load(b_load), .Data(b_in), .Out(b_out));
reg_256 #(258) c_reg(.clk, .Load(c_load), .Data(c_in), .Out(c_out));
reg_256 #(256) count(.clk, .Load(count_load), .Data(count_in), .Out(count_out));

enum logic [2:0] {
	Init, Start,
	setB, redB, setC,
	Finish
}	State, Next_State;

always_ff @ (posedge clk)
begin
    if(Reset)
	begin
        State <= Init;
	end
    else
        State <= Next_State;
end


always_comb begin
    Next_State = State;
    unique case(State)
		Init: Next_State = Start;
		Start: Next_State = setB;
		setB:
		begin
			if((b_out << 1) >= {2'b00,params.n})
				Next_State = redB;
			else
				Next_State = setC;
		end
		redB:
		begin
			if(b_out >= {2'b00,params.n})
				Next_State = redB;
			else
				Next_State = setC;
		end
		setC:
		begin
			if(count_out == 8'd254)
				Next_State = Finish;
			else
				Next_State = setB;
		end
		Finish:
			Next_State = Finish;
		default: ;
	endcase

	count_in = count_out;
	b_in = b_out;
	c_in = c_out;
	a_in = a_out;

	count_load = 1'b0;
	a_load = 1'b0;
	b_load = 1'b0;
	c_load = 1'b0;
	product = 256'b0;
	Done = 1'b0;

	unique case(State)
		Init:
		begin
			Done = 1'b0;
			count_in = 8'b0;
			a_in = a;
			b_in = {2'b0, b};
			c_in = 258'b0;

			count_load = 1'b1;
			a_load = 1'b1;
			b_load = 1'b1;
			c_load = 1'b1;
		end
		Start:
		begin
			if(a[0] == 1)
				c_in = b_out;
			else
				c_in = 258'b0;
			c_load = 1'b1;
		end
		setB:
		begin
			a_in = a_out >> 1;
			a_load = 1'b1;
			b_load = 1'b1;
			b_in = b_out << 1;
		end
		redB:
		begin
			b_load = 1'b1;
			if(b_out >= {2'b00, params.n})
				b_in = b_out - {2'b00,params.n};
			else
				b_in = b_out;
		end
		setC:
		begin
			c_load = 1'b1;
			if(a_out[0] == 1'b1)
			begin
				if((c_out + b_out) >= {2'b00, params.n})
					c_in = (c_out + b_out) - {2'b00, params.n};
				else
					c_in = c_out + b_out;
			end
			else
			begin
				if(c_out >= {2'b00, params.n})
					c_in = c_out - params.n;
				else
					c_in = c_out;
			end
			//increment counter
			count_in = count_out + 8'b01;
			count_load = 1'b1;
		end
		Finish:
		begin
			if(c_out < params.n)
			begin
				Done = 1'b1;
				product = c_out[255:0];
			end
			else
			begin
				c_in = c_out - {2'b00,params.n};
				c_load = 1'b1;
				Done = 1'b0;
			end
		end
		default: ;
	endcase
end

endmodule

//import elliptic_curve_structs::*;

module point_add (
	input 	logic 			clk, Reset,
	//input  	curve_point_t 	P, Q,
	input 	logic [255:0]  	P_x,
	input 	logic [255:0]  	P_y,
	input 	logic [255:0]  	Q_x,
	input 	logic [255:0]  	Q_y,
	output 	logic 			Done,
	//output 	curve_point_t 	R
	output 	logic [255:0]  	R_x,
	output 	logic [255:0]  	R_y
);

	logic mult0_done, inv_done, mult1_done, mult2_done;
	logic[255:0] sum0, sum1, sum2, sum3, sum4, sum5, sum6, sum7, sum8, s;
	logic[255:0] inv1;
	logic[255:0] prod1, prod2, prod3;
	logic reset0, reset1, reset2, inv_reset;

	logic[2:0] counter;

	//s = (Py + Qy) / (Px + Qx)
	//Rx = s*s + s + Px + Qx
	//Ry = s(Px + Rx) + Rx + Py

	// s = (Py - Qy) / (Px - Qx)
	// Rx = s*s - Px - Qx
	// Ry = s(Px - Rx) - Py

	/* code for testbench */
	always_ff @ (posedge clk)
	begin
		if(Reset) begin
			counter <= 0;
			reset2 <= 1'b0;
		end

		else
		begin
			if(mult1_done)
				counter <= counter + 1'b1;
			if(counter > 5)
				reset2 <= 1'b1;
		end
	end

	add add0(.a(P_y), .b(Q_y), .op(1'b1), .sum(sum0));	// Py - Qy
	add add1(.a(P_x), .b(Q_x), .op(1'b1), .sum(sum1));	// Px - Qx
	modular_inverse inv0(.clk(clk), .Reset(Reset), .in( sum1), .out(inv1), .Done(inv_done)); //1/Px-Qx

	multiplier mult0(.clk, .Reset(~inv_done | Reset), .a(sum0), .b(inv1), .Done(mult0_done), .product(s)); //slope

	multiplier mult1(.clk, .Reset(~mult0_done | Reset), .a(s), .b(s), .Done(mult1_done), .product(prod2)); // s^2
	add add2(.a(P_x), .b(Q_x), .op(1'b0), .sum(sum3));	// Px + Qx
	add add3(.a(prod2), .b(sum3), .op(1'b1), .sum(sum4)); // s^2 - (Px + Qx)
	add add4(.a(P_x), .b(sum4), .op(1'b1), .sum(sum5));	// Px - Rx
	add add5(.a(prod3), .b(P_y), .op(1'b1), .sum(sum6)); // s(Px-Rx) - Py
	multiplier mult2(.clk, .Reset(~reset2 | Reset), .a(s), .b(sum5), .Done(mult2_done), .product(prod3)); //s(Px - Rx)
	/* to use a nonzero a, uncomment below line and replace all "sum4" with "sum8" */
	//add #(17) 
	add add7(.a(sum4), .b(params.p), .op(1'b0/*1'b0*/), .sum(sum8)); // Rx + a (for x^3 + 2x + 2, a is 2) //


	assign R_x = sum8;
	assign R_y = sum6;
	assign Done = mult0_done & inv_done & mult1_done & mult2_done;

endmodule

//import elliptic_curve_structs::*;

module point_double	(
	input logic clk, Reset,
	input curve_point_t  P,
	output logic Done,
	output curve_point_t R
);

logic mult0_done, mult1_done, inv_done, mult2_done, mult3_done;
logic[255:0] sum0, sum1, sum2, sum3, sum4, sum5;
logic[255:0] inv1;
logic[255:0] prod0, prod1, prod2, prod3;
// logic mult0_reset;
// logic [4:0] counter;

logic [255:0] temp_prod0;

//s = Px + (Py / Px)
//Rx = s*s + s
//Ry = Px^2 + (s + 1)Rx

// s = (3*Px*Px)+a / (2*Py)
// Rx = s^2 - 2*Px
// Ry = s*(Px - Rx) - Py

//always_ff @ (posedge clk)
//begin
//	if(Reset) begin
//		mult0_reset <= 1'b0;
//		// counter <= 0;
//	end
//	/* perf counting code */
//	// else begin
//	// 	if(counter > 3)
//	// 		mult0_reset <= 1'b1;
//	// 	counter <= counter + 5'b01;
//	// end
//end

/* Registers for tracking if parameters change (e.g. multiplier) */

/* Calculate s. prod0*inv1 (prod0 = 3*Px*Px, inv1 is inv_mod of 2*Py)
	Note: We need to reset mutiplier and mod_inverse whenever parameters change.
	Mod inverse is not being reset because sum2 is loaded instantly, so it's ok */
add add0(.a(P.x), .b(P.x),
	.op(1'b0),
	.sum(sum0)
); // sum0 = 2*Px
add add1(.a(P.x), .b(sum0), .op(1'b0), .sum(sum1)); // sum1 = 3*Px
add add2(.a(P.y), .b(P.y), .op(1'b0), .sum(sum2)); // sum2 = 2*Py
multiplier mult0(.clk, .Reset(Reset /* mult0_reset */), .a(P.x), .b(sum1), .Done(mult0_done), .product(prod0)); // prod0 = Px*sum1
modular_inverse inv0(.clk, .Reset, .in(sum2), .out(inv1), .Done(inv_done));	// 1/2*Py
multiplier mult1(.clk, .Reset(Reset | ~(inv_done && mult0_done)), .a(temp_prod0), .b(inv1), .Done(mult1_done), .product(prod1)); // s

/* To test for a != 0, put in line */
	add  add6(.a(params.a), .b(prod0), .op(1'b0), .sum(temp_prod0));
/* and use "temp_prod0" for "prod0"	in mult1.a()*/

/* Calculate Rx. s*s - 2*Px (prod1*prod1 - sum0) */
multiplier mult2(.clk, .Reset(Reset | ~mult1_done),
	.a(prod1), .b(prod1),
	.Done(mult2_done), .product(prod2)); // s*s
add add3(.a(prod2), .b(sum0), .op(1'b1), .sum(sum3)); // Rx = s*s - 2*Px

/* Calculate Ry. s*(Px - Rx) - Py */
add add4(.a(P.x), .b(sum3), .op(1'b1), .sum(sum4)); // sum4 = Px - Rx. modp of course!
multiplier mult3(.clk, .Reset(Reset | ~mult2_done), .a(prod1), .b(sum4), .Done(mult3_done), .product(prod3)); // s*(Px - Rx)
add add5(.a(prod3), .b(P.y), .op(1'b1), .sum(sum5)); // sum5 = Ry = s*(Px-Rx) - Py

assign R.x = sum3;
assign R.y = sum5;
assign Done = mult0_done & mult1_done & inv_done & mult2_done & mult3_done;	//Make sure everything finishes

endmodule

module reg_256 #(parameter size = 256)
(
	input  logic clk, Load,
  	input  logic [size-1:0]  Data,
  	output logic [size-1:0]  Out
);

always_ff @ (posedge clk)
begin
	if (Load)
		  Out <= Data;
	else
		  Out <= Out;
end

endmodule


module ecdsa_block(
	// Common
	input wire clk,
	//Gen point
	input wire in_gen_point_reset,
	input wire [255:0] in_point_x,
	input wire [255:0] in_point_y,
	input wire [255:0] in_S,
	output wire [255:0] out_point_x,
	output wire [255:0] out_point_y,
	output wire  done_point,
	//modInv
	input wire in_modInv_reset,
	input wire [255:0] in_modInv,
	output wire [255:0] out_modInv,
	output wire  done_modInv,
	//multmod
	input wire in_reset_modmult,
	input wire [255:0] in_a_modmult, 
	input wire [255:0] in_b_modmult,
	output wire done_modmult,
	output wire [255:0] out_modmult,
	//add point a != b
	input wire in_reset_add,
	input wire [255:0] in_p_x,
	input wire [255:0] in_p_y,
	input wire [255:0] in_q_x,
	input wire [255:0] in_q_y,
	output wire done_add,
	output wire [255:0] out_r_x,
	output wire [255:0] out_r_y
);

gen_point init_point (
	.clk(clk), 
	.Reset(in_gen_point_reset),
	.privKey(in_S),
	.in_point_x(in_point_x),
	.in_point_y(in_point_y),
	.out_point_y(out_point_y),
	.out_point_x(out_point_x),
	.Done(done_point)
);

modular_inverse_n modular_inverse_n (
	.clk(clk), 
	.Reset(in_modInv_reset),
	.in(in_modInv),
	.out(out_modInv),
	.Done(done_modInv)
);

multiplier_n multmod_n (
	.clk(clk), 
	.Reset(in_reset_modmult),
	.a(in_a_modmult), 
	.b(in_b_modmult),
	.Done(done_modmult),
	.product(out_modmult)
);

point_add point_add (
	.clk(clk), 
	.Reset(in_reset_add),
	//input  	curve_point_t 	P, Q,
	.P_x(in_p_x),
	.P_y(in_p_y),
	.Q_x(in_q_x),
	.Q_y(in_q_y),
	.Done(done_add),
	//output 	curve_point_t 	R
	.R_x(out_r_x),
	.R_y(out_r_y)
);

endmodule

`undef WT_DCACHE
`undef DISABLE_TRACER
`undef SRAM_NO_INIT
`undef VERILATOR

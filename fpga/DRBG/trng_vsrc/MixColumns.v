`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
//
// in_state:   ab40f0c48b7ffce489f1184e35053f2f 
// out_state:  b9e447c5948e20d657169af575513f3b
// 
//////////////////////////////////////////////////////////////////////////////////


(* dont_touch = "yes"*)
module MixColumns(
	input  [127:0] iState,		// state input from ShiftRows
	output [127:0] oState		// state output from MixColumns 
	);
	
	wire [7:0] a00, a01, a02, a03; //input four-byte row 1
	wire [7:0] a10, a11, a12, a13; //input four-byte row 2
	wire [7:0] a20, a21, a22, a23; //input four-byte row 3
	wire [7:0] a30, a31, a32, a33; //input four-byte row 4
	
	wire [7:0] b00, b01, b02, b03; //output four-byte row 1
	wire [7:0] b10, b11, b12, b13; //output four-byte row 2
	wire [7:0] b20, b21, b22, b23; //output four-byte row 3
	wire [7:0] b30, b31, b32, b33; //output four-byte row 4
	
	//row 1
	assign a00 = iState[127:120];
	assign a10 = iState[119:112];
	assign a20 = iState[111:104];
	assign a30 = iState[103: 96];
	
	//row 2
	assign a01 = iState[95:88]; 
	assign a11 = iState[87:80]; 
	assign a21 = iState[79:72];
	assign a31 = iState[71:64];
	
	//row 3
	assign a02 = iState[63:56];
	assign a12 = iState[55:48]; 
	assign a22 = iState[47:40];
	assign a32 = iState[39:32];
	
	//row 4
	assign a03 = iState[31:24];
	assign a13 = iState[23:16]; 
	assign a23 = iState[15: 8];
	assign a33 = iState[ 7: 0];
	
	// output column 1
	assign b00 = ((a00[7] ^ a10[7])==1'b1)	
				? ({a00[6:0], 1'b0} ^ {a10[6:0], 1'b0} ^ a10 ^ a20 ^ a30 ^ 8'h1b)
				: ({a00[6:0], 1'b0} ^ {a10[6:0], 1'b0} ^ a10 ^ a20 ^ a30);
	assign b10 = ((a10[7] ^ a20[7])==1'b1)	
				? ({a10[6:0], 1'b0} ^ {a20[6:0], 1'b0} ^ a20 ^ a30 ^ a00 ^ 8'h1b)
				: ({a10[6:0], 1'b0} ^ {a20[6:0], 1'b0} ^ a20 ^ a30 ^ a00);
	assign b20 = ((a20[7] ^ a30[7])==1'b1)	
				? ({a20[6:0], 1'b0} ^ {a30[6:0], 1'b0} ^ a30 ^ a00 ^ a10 ^ 8'h1b)
				: ({a20[6:0], 1'b0} ^ {a30[6:0], 1'b0} ^ a30 ^ a00 ^ a10);
	assign b30 = ((a30[7] ^ a00[7])==1'b1)	
				? ({a30[6:0], 1'b0} ^ {a00[6:0], 1'b0} ^ a00 ^ a10 ^ a20 ^ 8'h1b)
				: ({a30[6:0], 1'b0} ^ {a00[6:0], 1'b0} ^ a00 ^ a10 ^ a20);
	
	// output column 2
	assign b01 = ((a01[7] ^ a11[7])==1'b1)	
				? ({a01[6:0], 1'b0} ^ {a11[6:0], 1'b0} ^ a11 ^ a21 ^ a31 ^ 8'h1b)
				: ({a01[6:0], 1'b0} ^ {a11[6:0], 1'b0} ^ a11 ^ a21 ^ a31);
	assign b11 = ((a11[7] ^ a21[7])==1'b1)
				? ({a11[6:0], 1'b0} ^ {a21[6:0], 1'b0} ^ a21 ^ a31 ^ a01 ^ 8'h1b)
				: ({a11[6:0], 1'b0} ^ {a21[6:0], 1'b0} ^ a21 ^ a31 ^ a01);
	assign b21 = ((a21[7] ^ a31[7])==1'b1)	
				? ({a21[6:0], 1'b0} ^ {a31[6:0], 1'b0} ^ a31 ^ a01 ^ a11 ^ 8'h1b) 
				: ({a21[6:0], 1'b0} ^ {a31[6:0], 1'b0} ^ a31 ^ a01 ^ a11);
	assign b31 = ((a31[7] ^ a01[7])==1'b1)	
				? ({a31[6:0], 1'b0} ^ {a01[6:0], 1'b0} ^ a01 ^ a11 ^ a21 ^ 8'h1b)
				: ({a31[6:0], 1'b0} ^ {a01[6:0], 1'b0} ^ a01 ^ a11 ^ a21);
	
	// output column 3
	assign b02 = ((a02[7] ^ a12[7])==1'b1)	
				? ({a02[6:0], 1'b0} ^ {a12[6:0], 1'b0} ^ a12 ^ a22 ^ a32 ^ 8'h1b) 
				: ({a02[6:0], 1'b0} ^ {a12[6:0], 1'b0} ^ a12 ^ a22 ^ a32);
	assign b12 = ((a12[7] ^ a22[7])==1'b1)
				? ({a12[6:0], 1'b0} ^ {a22[6:0], 1'b0} ^ a22 ^ a32 ^ a02 ^ 8'h1b)
				: ({a12[6:0], 1'b0} ^ {a22[6:0], 1'b0} ^ a22 ^ a32 ^ a02);
	assign b22 = ((a22[7] ^ a32[7])==1'b1)	
				? ({a22[6:0], 1'b0} ^ {a32[6:0], 1'b0} ^ a32 ^ a02 ^ a12 ^ 8'h1b)
				: ({a22[6:0], 1'b0} ^ {a32[6:0], 1'b0} ^ a32 ^ a02 ^ a12);
	assign b32 = ((a32[7] ^ a02[7])==1'b1)
				? ({a32[6:0], 1'b0} ^ {a02[6:0], 1'b0} ^ a02 ^ a12 ^ a22 ^ 8'h1b)
				: ({a32[6:0], 1'b0} ^ {a02[6:0], 1'b0} ^ a02 ^ a12 ^ a22);
	
	// output column 4
	assign b03 = ((a03[7] ^ a13[7])==1'b1)
				? ({a03[6:0], 1'b0} ^ {a13[6:0], 1'b0} ^ a13 ^ a23 ^ a33 ^ 8'h1b)
				: ({a03[6:0], 1'b0} ^ {a13[6:0], 1'b0} ^ a13 ^ a23 ^ a33);
	assign b13 = ((a13[7] ^ a23[7])==1'b1)	
				? ({a13[6:0], 1'b0} ^ {a23[6:0], 1'b0} ^ a23 ^ a33 ^ a03 ^ 8'h1b) 
				: ({a13[6:0], 1'b0} ^ {a23[6:0], 1'b0} ^ a23 ^ a33 ^ a03);
	assign b23 = ((a23[7] ^ a33[7])==1'b1)
				? ({a23[6:0], 1'b0} ^ {a33[6:0], 1'b0} ^ a33 ^ a03 ^ a13 ^ 8'h1b) 
				: ({a23[6:0], 1'b0} ^ {a33[6:0], 1'b0} ^ a33 ^ a03 ^ a13);
	assign b33 = ((a33[7] ^ a03[7])==1'b1)
				? ({a33[6:0], 1'b0} ^ {a03[6:0], 1'b0} ^ a03 ^ a13 ^ a23 ^ 8'h1b)
				: ({a33[6:0], 1'b0} ^ {a03[6:0], 1'b0} ^ a03 ^ a13 ^ a23);

	// state output
	assign oState = {b00, b10, b20, b30,
					   b01, b11, b21, b31,
					   b02, b12, b22, b32,
					   b03, b13, b23, b33};
	
endmodule
`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////

(* dont_touch = "yes"*)
module AES_Controller(
	input  wire iClk,
	input  wire iRst,
	input  wire iEnc,
	output reg  oSel_MUX_ARK,
	output reg  oSel_MUX_MC,
	output reg  oSel_MUX_Final,
	output reg  oEn,
	output reg  oFinish
	);
	
	// ----------------------------- internal wire and reg signals
	localparam [2:0]s_Idle	 	= 3'd0,
					s_Round_0	= 3'd1,
					s_Round_M	= 3'd2,
					s_Round_f	= 3'd3,
					s_Done		= 3'd4;
					
	reg finish;
	reg [2:0] state;	
	reg [3:0] counter;

//	assign oFinish = (state == s_Done)? 1'b1 : 1'b0;
	
	// -------------------------------------------- process_state_Machine
	always @(posedge iClk)
	begin
		if (iRst) begin
			state  	     <= s_Idle;
			oFinish      <= 1'b0;
			finish       <= 1'b0;
			oEn          <= 1'b0;
			counter      <= 4'd0;
			oSel_MUX_ARK   <= 1'b0;
			oSel_MUX_MC    <= 1'b0;
			oSel_MUX_Final <= 1'b0;
		end else begin
		    oFinish <= finish;
			case(state)			
			//----------------------- s_Idle
			s_Idle:	
				begin
					finish         <= finish;
					oEn            <= 1'b0;
					oSel_MUX_ARK   <= 1'b0;
					oSel_MUX_MC    <= 1'b0;
					oSel_MUX_Final <= 1'b0;
						
					if (iEnc)
						state <= s_Round_0;
					else	
						state <= s_Idle;
				end
				
			//----------------------- s_Round_0
			s_Round_0:	
				begin
					finish         <= 1'b0;
					oEn            <= 1'b1;
					oSel_MUX_ARK   <= 1'b0;
					oSel_MUX_MC    <= 1'b0;
					oSel_MUX_Final <= 1'b0;
					
					state <= s_Round_M;
				end
				
			//----------------------- s_Round_M
			s_Round_M:	
				begin
					finish         <= 1'b0;
					oEn            <= 1'b1;
					oSel_MUX_ARK   <= 1'b1;
					oSel_MUX_MC    <= 1'b0;
					oSel_MUX_Final <= 1'b0;
					
					if(counter < 4'd12) begin
						counter <= counter + 4'd1;
						state   <= s_Round_M;
					end else
						state   <= s_Round_f;
				end
				
			//----------------------- s_Round_f
			s_Round_f:	
				begin				
					finish         <= 1'b0;
					oEn            <= 1'b1;
					oSel_MUX_ARK   <= 1'b1;
					oSel_MUX_MC    <= 1'b1;
					oSel_MUX_Final <= 1'b0;
						
					state <= s_Done;
				end
				
			//----------------------- s_Done
			s_Done:	
				begin
					finish         <= 1'b1;
					oEn            <= 1'b1;
					oSel_MUX_ARK   <= 1'b0;
					oSel_MUX_MC    <= 1'b0;
					oSel_MUX_Final <= 1'b1;		
						
					counter        <= 4'd0;
					state          <= s_Idle;
				end	
				
			default:
				begin
					state <= s_Idle;
				end
			endcase
		end
	end
	
endmodule

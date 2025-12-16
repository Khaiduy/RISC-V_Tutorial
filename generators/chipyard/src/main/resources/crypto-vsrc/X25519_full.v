module X25519_full #(
                parameter BIT_LENGTH = 256       
                )
                (
				//-- Clock and Reset Signals
				input  wire iClk,					
				input  wire iRstn,			
				input  wire iStart,			
				//-- Scalar k
				input wire [BIT_LENGTH-1:0] scalar,
				//-- u-coordinate from Point P
				input wire [BIT_LENGTH-1:0] point_in,
				//-- u-coordinate from Point R = [k]P
				output reg [BIT_LENGTH-1:0] point_out,
				//-- Output is valid
				output reg valid
				);
  
    
    //------------------------------------------------------------------------------------------------
	//-- Parameters             
	//------------------------------------------------------------------------------------------------

	//-- Curve Parameter A24 = (A-2)/4
	localparam A24 = 256'd121665;
	

	//------------------------------------------------------------------------------------------------
	//-- Wires and Registers               
	//------------------------------------------------------------------------------------------------
	
	//-- Scalar and Point Decoded
	wire [BIT_LENGTH-1:0] scalar_dec;
//	wire [BIT_LENGTH-1:0] point_dec;
	
	assign scalar_dec = {2'b01, scalar[5:0], scalar[15:8], scalar[23:16], scalar[31:24], scalar[39:32], scalar[47:40], scalar[55:48], scalar[63:56], scalar[71:64], scalar[79:72], scalar[87:80], scalar[95:88],
                               scalar[103:96], scalar[111:104], scalar[119:112], scalar[127:120], scalar[135:128], scalar[143:136], scalar[151:144], scalar[159:152], scalar[167:160], scalar[175:168], 
                               scalar[183:176], scalar[191:184], scalar[199:192], scalar[207:200], scalar[215:208], scalar[223:216], scalar[231:224], scalar[239:232], scalar[247:240], scalar[255:251], 3'b000};
    
//    assign point_dec = {1'b0, point_in[6:0], point_in[15:8], point_in[23:16], point_in[31:24], point_in[39:32], point_in[47:40], point_in[55:48], point_in[63:56], point_in[71:64], point_in[79:72], point_in[87:80], point_in[95:88],
//                               point_in[103:96], point_in[111:104], point_in[119:112], point_in[127:120], point_in[135:128], point_in[143:136], point_in[151:144], point_in[159:152], point_in[167:160], point_in[175:168], 
//                               point_in[183:176], point_in[191:184], point_in[199:192], point_in[207:200], point_in[215:208], point_in[223:216], point_in[231:224], point_in[239:232], point_in[247:240], point_in[255:248]};
	
	//-- Point Coordinates
	reg [BIT_LENGTH-1:0] x_1;
	reg [BIT_LENGTH-1:0] x_2;
	reg [BIT_LENGTH-1:0] x_3;
	reg [BIT_LENGTH-1:0] z_2;
	reg [BIT_LENGTH-1:0] z_3;
	//-- Temporary Intermediate Values
	reg [BIT_LENGTH-1:0] temp_R1;

    //-- Scalar Bits & Ladder Counter
	reg [7:0] bit_counter;
	reg [7:0] ladder_counter;
	wire scalar_bit;
	
	wire bit_counter_255 = ~&bit_counter; //bit_counter < 255
	assign scalar_bit = bit_counter_255 ? scalar_dec[bit_counter] : scalar_dec[0];
//	assign scalar_bit = (~&bit_counter) ? scalar_dec[bit_counter] : scalar_dec[0];
	
	//-- Conditional Swap
	reg swap;
	wire swap_xor;
//	wire [BIT_LENGTH-1:0] cswap_x_2;
//	wire [BIT_LENGTH-1:0] cswap_x_3;
//	wire [BIT_LENGTH-1:0] cswap_z_2;
//	wire [BIT_LENGTH-1:0] cswap_z_3;
	
	assign swap_xor = swap ^ scalar_bit;
	
//	assign cswap_x_2 = (swap_xor) ? x_3 : x_2;
//	assign cswap_x_3 = (swap_xor) ? x_2 : x_3;
//	assign cswap_z_2 = (swap_xor) ? z_3 : z_2;
//	assign cswap_z_3 = (swap_xor) ? z_2 : z_3;
	
    
	reg                   mul_en;
	reg  [BIT_LENGTH-1:0] temp_A;
	reg  [BIT_LENGTH-1:0] temp_B;
	wire [BIT_LENGTH-1:0] temp_C;
	
	wire MP_done;
	
	modular_multiplier_pipeline multiplier (
				.iClk(iClk),
				.iRstn(iRstn),
				.iEn(mul_en),
				.iA(temp_A),
				.iB(temp_B),
				.oP(temp_C),
				.oReady(mul_ready),
				.oValid(MP_done)
				);

    //------------------------------------------------------------------------------------------------
	//-- Adder/Subtractor        
	//------------------------------------------------------------------------------------------------
    
    reg  add_sub_mode;
    reg  add_sub_start;
    reg  [BIT_LENGTH-1:0] add_sub_A;
    reg  [BIT_LENGTH-1:0] add_sub_B;
    wire [BIT_LENGTH-1:0] add_sub_C;

    wire add_sub_ready;
    wire mul_ready;
    
    modular_adder_subtractor_256_hp add_sub(
			   .iClk(iClk),
			   .rst_n(iRstn),
			   .start(add_sub_start),
			   .done(add_sub_ready),
			   .sub(add_sub_mode),
               .a(add_sub_A),
               .b(add_sub_B),
               .result(add_sub_C)
			   );
	
	
	//--------------------------------------------------------------------------------------------------------------------
	//-- Logic Controller               
	//--------------------------------------------------------------------------------------------------------------------	
	
	localparam IDLE 				   = 0;
	//-- CONDITIONAL SWAP
	localparam CSWAP                   = 1;
	//-- SCALAR MULTIPLICATION
	localparam SCALAR_MUL              = 2;
	//-- INVERSION
	localparam INV_SELECT              = 3;
	localparam INVERSION               = 4;
	//-- FINAL MULTIPLICATION
	localparam LAST_MUL                = 5;
	//-- END
	localparam END  				   = 6;
    // Minimal inversion control
    reg [4:0] inv_step;        // Step 0-19 (20 steps total)
//    reg [7:0] inv_counter;     // For loop counting
    reg [2:0] inv_state;       // Only 4 states needed
    
    // Inversion sub-states - reduced from 6 to 4 states
    localparam INV_START = 0, INV_WAIT = 1, INV_LOOP = 2, INV_LOOP_WAIT = 3;
    reg [2:0] state;
    
//    wire is_single_op = (inv_step < 7) || (!inv_step[0] && inv_step != 0);
    wire is_loop_op = (inv_step > 6) && inv_step[0];
                        
always @(posedge iClk) begin
    if (!iRstn) begin
        x_1              <= 0;
        x_2              <= 0;
        x_3              <= 0;
        z_2              <= 0;
        z_3              <= 0;
        temp_R1          <= 0;
        bit_counter      <= 0;
        ladder_counter   <= 0;
        swap             <= 0; 
        
        point_out        <= 0;
        valid            <= 0;
        state            <= IDLE;
        
        inv_step         <= 0;
//        inv_counter      <= 0;
        inv_state        <= INV_START;
    
    end
    else begin
        case (state)
                    
            //-------------------------------------------
            //-- IDLE STATE     
            //-------------------------------------------
            
            (IDLE): begin 
               if(iStart) begin              
                   x_1 <= {1'b0, point_in[6:0], point_in[15:8], point_in[23:16], point_in[31:24], point_in[39:32], point_in[47:40], point_in[55:48], point_in[63:56], point_in[71:64], point_in[79:72], point_in[87:80], point_in[95:88],
                               point_in[103:96], point_in[111:104], point_in[119:112], point_in[127:120], point_in[135:128], point_in[143:136], point_in[151:144], point_in[159:152], point_in[167:160], point_in[175:168], 
                               point_in[183:176], point_in[191:184], point_in[199:192], point_in[207:200], point_in[215:208], point_in[223:216], point_in[231:224], point_in[239:232], point_in[247:240], point_in[255:248]};
                   x_2 <= 1;
                   x_3 <= {1'b0, point_in[6:0], point_in[15:8], point_in[23:16], point_in[31:24], point_in[39:32], point_in[47:40], point_in[55:48], point_in[63:56], point_in[71:64], point_in[79:72], point_in[87:80], point_in[95:88],
                               point_in[103:96], point_in[111:104], point_in[119:112], point_in[127:120], point_in[135:128], point_in[143:136], point_in[151:144], point_in[159:152], point_in[167:160], point_in[175:168], 
                               point_in[183:176], point_in[191:184], point_in[199:192], point_in[207:200], point_in[215:208], point_in[223:216], point_in[231:224], point_in[239:232], point_in[247:240], point_in[255:248]};
                   z_2 <= 0;
                   z_3 <= 1;  
                   
                   bit_counter    <= 254;
                   ladder_counter <= 1;
                   
                   swap <= 0;
                   valid <= 0;
                   inv_step <= 0;
                   inv_state <= 0;
                   state <= CSWAP;
               end
               else state <= IDLE;
            end
            
            
            //-------------------------------------------
            //-- CONDITIONAL SWAP
            //-------------------------------------------
            
            (CSWAP): begin
                if (swap_xor) begin
                    {x_2, x_3} <= {x_3, x_2};
                    {z_2, z_3} <= {z_3, z_2};
                end
               
               swap <= scalar_bit;

               ladder_counter <= 1;
               
               if (bit_counter_255)
                  state <= SCALAR_MUL;
               else             
                  state <= INVERSION;
            end 
        
            //-------------------------------------------
            //-- SCALAR MULTIPLICATION
            //-------------------------------------------
            
            (SCALAR_MUL): begin
               ladder_counter <= ladder_counter + 1;
              
               case (ladder_counter)
                   13: begin
                      x_2             <= add_sub_C;  //Save A to x2
                   end
                   31: begin
                      z_2             <= add_sub_C; //Save B to z2
                   end
                   48: begin
                      temp_R1         <= temp_C; //Save AA
                   end
                   66, 169: begin
                      z_2             <= temp_C; //Save BB, erase B
                   end
                   84, 151: begin
                      x_3             <= temp_C; //Save CB
                   end
                   102, 206: begin
                      z_3             <= temp_C; //Save DA
                   end
                   120: begin
                      x_2             <= temp_C;//Save x2 = AA * BB, erase A (DONE)
                   end
//                   151: begin
//                      x_3             <= temp_C; //Save x3 = (DA + CB) ^ 2, erase CB (DONE)
//                   end
//                   169: begin
//                      z_2             <= temp_C; //Save (DA - CB) ^ 2, erase BB
//                   end
                   187: begin
                      z_2             <= temp_C; //Save temp4 = a24 * E, erase (DA - CB) ^ 2
                      z_3             <= add_sub_C; //temporary save E to z3
                   end
//                   206: begin
//                      z_3             <= temp_C; //Save z3 = x1 * (DA - CB) ^ 2, erase DA (DONE)
//                   end
                   235: begin
                      z_2             <= temp_C; //Save z2 = E * temp5, erase temp4 (DONE)
                      //-- Return to Conditional Swapping
                      bit_counter    <= bit_counter - 1;
                      if (bit_counter == 0) begin
                         swap <= 0;
                         state <= INVERSION;  // Go to inversion when done with all bits
                         ladder_counter <= 0;
//                         inv_state <= S_Z2_START;
                      end
                      else begin
                         state <= CSWAP;     // Continue with next bit
                      end
                   end
                   default: begin
                       // Handle unexpected ladder_counter values
                       // Could add error handling here if needed
                   end
               endcase
               
            end 
            
            //-------------------------------------------
            //-- INVERSION STATE
            //-------------------------------------------
            
            (INVERSION): begin
                case (inv_state)
                    INV_START: begin
//                        case (inv_step)
//                            // Single operations - go directly to wait
//                            0, 1, 2, 3, 4, 5, 6: inv_state <= INV_WAIT;
                            
//                            // Loop operations - set counter and go to loop
//                            7, 21: begin ladder_counter <= 5; inv_state <= INV_LOOP; end     // Square 5 times
//                            9, 13: begin ladder_counter <= 10; inv_state <= INV_LOOP; end    // Square 10 times
//                            11: begin ladder_counter <= 20; inv_state <= INV_LOOP; end   // Square 20 times
////                            13: begin ladder_counter <= 10; inv_state <= INV_LOOP; end   // Square 10 times
//                            15, 19: begin ladder_counter <= 50; inv_state <= INV_LOOP; end   // Square 50 times
//                            17: begin ladder_counter <= 100; inv_state <= INV_LOOP; end  // Square 100 times
////                            19: begin ladder_counter <= 50; inv_state <= INV_LOOP; end   // Square 50 times
////                            21: begin ladder_counter <= 5; inv_state <= INV_LOOP; end    // Square 5 times
                            
//                            // Single multiplications (including final one)
//                            8, 10, 12, 14, 16, 18, 20, 22: inv_state <= INV_WAIT;
                            
//                            default: begin
//                                // Inversion complete - go to final multiplication
//                                state <= LAST_MUL;
//                            end
//                        endcase
                        
                            case (inv_step[4:1])  // Divide by 2, only look at loop operations
                                4'd3: ladder_counter <= 5;    // step 7
                                4'd4: ladder_counter <= 10;   // step 9
                                4'd5: ladder_counter <= 20;   // step 11
                                4'd6: ladder_counter <= 10;   // step 13
                                4'd7: ladder_counter <= 50;   // step 15
                                4'd8: ladder_counter <= 100;  // step 17
                                4'd9: ladder_counter <= 50;   // step 19
                                4'd10: ladder_counter <= 5;   // step 21
                                default: ladder_counter <= 0;
                            endcase 
    
                        if (inv_step > 22)
                            state <= LAST_MUL;
                        else
                            inv_state <= is_loop_op ? INV_LOOP : INV_WAIT;   
                    end
                    
                    INV_WAIT: begin
                        if (MP_done) begin
                            // Store result and update intermediate values
                            temp_R1 <= temp_C;
                            
                            case (inv_step)
                                0, 4: x_3 <= temp_C;      // Save z^2, then Save z^11
                                3: z_3 <= temp_C;      // Save z^9
//                                4: x_3 <= temp_C;      // Save z^11
                                6, 8, 14: x_1 <= temp_C;      // Save z^(2^5-1), then Save z^(2^10-1), then Save z^(2^50-1)
//                                8: x_1 <= temp_C;      // Save z^(2^10-1)
                                10, 12, 16: z_2 <= temp_C;     // Save z^(2^20-1)
//                                12: z_2 <= temp_C;     // Save z^(2^40-1)
//                                14: x_1 <= temp_C;     // Save z^(2^50-1)
//                                16: z_2 <= temp_C;     // Save z^(2^100-1)
                                18: /* z^(2^200-1) - temp_R1 already updated */;
                                22: begin
                                    // Final multiplication complete - go to LAST_MUL
                                    state <= LAST_MUL;
                                end
                            endcase
                            
                            // Only increment step if not final step
                            if (inv_step < 22) begin
                                inv_step <= inv_step + 1;
                                inv_state <= INV_START;
                            end
                        end
                    end

                    INV_LOOP: begin 
                        inv_state <= INV_LOOP_WAIT;
                    end
                    
                    INV_LOOP_WAIT: begin
                        if (MP_done) begin
                            temp_R1 <= temp_C;
                            ladder_counter <= ladder_counter - 1;
                            
                            if (ladder_counter == 1) begin
                                // Loop complete
                                inv_step <= inv_step + 1;
                                inv_state <= INV_START;
                            end
                            else begin
                                inv_state <= INV_LOOP;
                            end
                        end
                    end
                endcase 
            end
            
            //-------------------------------------------
            //-- FINAL MULTIPLICATION   
            //-------------------------------------------
            
            (LAST_MUL): begin
                state <= END;
            end
            
            //-------------------------------------------
            //-- END STATE
            //-------------------------------------------
            
            (END): begin
               if (MP_done) begin
                  point_out <= {temp_C[7:0], temp_C[15:8], temp_C[23:16], temp_C[31:24], temp_C[39:32], temp_C[47:40], temp_C[55:48], temp_C[63:56], temp_C[71:64], temp_C[79:72], temp_C[87:80], temp_C[95:88],
                                temp_C[103:96], temp_C[111:104], temp_C[119:112], temp_C[127:120], temp_C[135:128], temp_C[143:136], temp_C[151:144], temp_C[159:152], temp_C[167:160], temp_C[175:168], 
                                temp_C[183:176], temp_C[191:184], temp_C[199:192], temp_C[207:200], temp_C[215:208], temp_C[223:216], temp_C[231:224], temp_C[239:232], temp_C[247:240], temp_C[255:248]};
                  
                  valid <= 1;
                  state <= IDLE;
               end
            end
            
            //-------------------------------------------
            //-- DEFAULT CASE
            //-------------------------------------------
            
            default: begin
                // Handle unexpected states - could add error recovery
                state <= IDLE;
            end
            
        endcase
    end
end

always @(*) begin
    
        // Default assignments to prevent latches
        temp_A           = 0;
        temp_B           = 0;
        mul_en           = 0;
        add_sub_mode     = 0;
        add_sub_start    = 0;
        add_sub_A        = 0;
        add_sub_B        = 0;
        
        case (state)
            //-------------------------------------------
            //-- SCALAR MULTIPLICATION
            //-------------------------------------------
            
            (SCALAR_MUL): begin        
               case (ladder_counter)
                   (1): begin
                       //-- R1 = X2 + Z2 (A)
                       add_sub_mode    = 0;
                       add_sub_start   = 1;
                       add_sub_A       = x_2;
                       add_sub_B       = z_2;
                   end
                   (12): begin
                      //-- R1 = R1 x R1 (AA)
                      temp_A          = add_sub_C;
                      temp_B          = add_sub_C;
                      mul_en          = 1;
                   end
                   (13): begin
                      //-- R2 = X2 - Z2 (B)    
                      add_sub_mode    = 1;
                      add_sub_start   = 1;
                      add_sub_A       = x_2;
                      add_sub_B       = z_2;
                   end
                   (30): begin
                      //-- R2 x R2 (BB) AND R3 = X3 + Z3 (C)
                      temp_A          = add_sub_C;
                      temp_B          = add_sub_C;
                      mul_en          = 1;
                      // Parallel add operation
                      add_sub_mode    = 0;
                      add_sub_start   = 1;
                      add_sub_A       = x_3;
                      add_sub_B       = z_3;
                   end
                   (48): begin
                      //R2 x add_sub (CB) AND R4 = X3 - Z3 (D)    
                      temp_A          = z_2;
                      temp_B          = add_sub_C;
                      mul_en          = 1;
                      // Parallel subtract operation
                      add_sub_mode    = 1;
                      add_sub_start   = 1;
                      add_sub_A       = x_3;
                      add_sub_B       = z_3;
                   end
                   (66): begin
                      //R1 x add_sub (DA)
                      temp_A          = x_2;
                      temp_B          = add_sub_C;
                      mul_en          = 1;
                   end
                   (84): begin
                      //AA * BB AND E = AA - BB
                      temp_A          = temp_R1;
                      temp_B          = z_2;
                      mul_en          = 1;
                      // Parallel subtract operation
                      add_sub_mode    = 1;
                      add_sub_start   = 1;
                      add_sub_A       = temp_R1;
                      add_sub_B       = z_2;
                   end
                   (103): begin
                      //add_res3 = DA + CB
                      add_sub_mode    = 0;
                      add_sub_start   = 1;
                      add_sub_A       = z_3;
                      add_sub_B       = x_3;
                   end
                   (115): begin
                      //(DA + CB) ^ 2 AND sub_res3 = DA - CB
                      temp_A          = add_sub_C;
                      temp_B          = add_sub_C;
                      mul_en          = 1;
                      // Parallel subtract operation
                      add_sub_mode    = 1;
                      add_sub_start   = 1;
                      add_sub_A       = z_3;
                      add_sub_B       = x_3;
                   end
                   (133): begin
                      //(DA - CB) ^ 2 AND sub_res4 = AA - BB
                      temp_A          = add_sub_C;
                      temp_B          = add_sub_C;
                      mul_en          = 1;
                      // Parallel subtract operation
                      add_sub_mode    = 1;
                      add_sub_start   = 1;
                      add_sub_A       = temp_R1;
                      add_sub_B       = z_2;
                   end
                   (151): begin
                      //temp4 = a24 * E
                      temp_A          = A24;
                      temp_B          = add_sub_C;
                      mul_en          = 1;
                   end
                   (170): begin
                      //mul_res7 = x1 * (DA - CB) ^ 2
                      temp_A          = z_2;
                      temp_B          = x_1;
                      mul_en          = 1;
                   end
                   (188): begin
                      //temp5 = AA + temp4
                      add_sub_mode    = 0;
                      add_sub_start   = 1;
                      add_sub_A       = temp_R1;
                      add_sub_B       = z_2;
                   end
                   (199): begin
                      //z2_new = E * temp5
                      temp_A          = z_3;
                      temp_B          = add_sub_C;
                      mul_en          = 1;
                   end
                   default: begin
                       // Default case for ladder_counter
                       // All signals already have default values assigned above
                   end
               endcase
            end 
            
            //-------------------------------------------
            //-- INVERSION
            //-------------------------------------------
            
            (INVERSION): begin
                case (inv_state)
                    INV_START: begin
                        case (inv_step)
                            0: begin  // z^2
                                temp_A = z_2;
                                temp_B = z_2;
                                mul_en = 1;
                            end
                            1, 2, 5: begin  // z^4, z^8, z^22 (squares)
                                temp_A = temp_R1;
                                temp_B = temp_R1;
                                mul_en = 1;
                            end
                            3: begin  // z^9 = z^8 * z
                                temp_A = temp_R1;
                                temp_B = z_2;  // Original z
                                mul_en = 1;
                            end
                            4, 22: begin  // z^11 = z^9 * z^2
                                temp_A = temp_R1;
                                temp_B = x_3;  // z^2 stored here
                                mul_en = 1;
                            end
                            6: begin  // z^(2^5-1) = z^22 * z^9
                                temp_A = temp_R1;
                                temp_B = z_3;  // z^9 stored here
                                mul_en = 1;
                            end
                            8, 10, 14, 16, 20: begin  // Multiply by saved intermediate
                                temp_A = temp_R1;
                                temp_B = x_1;  // Intermediate value
                                mul_en = 1;
                            end
                            12, 18: begin  // Multiply by z^(2^20-1) or z^(2^200-1)
                                temp_A = temp_R1;
                                temp_B = z_2;  // Stored intermediate
                                mul_en = 1;
                            end
                            default: mul_en = 0;
                        endcase
                    end
                    
                    INV_WAIT: mul_en = 0;
                    
                    INV_LOOP: begin
                        // Always square in loop
                        temp_A = temp_R1;
                        temp_B = temp_R1;
                        mul_en = 1;
                    end
                    
                    INV_LOOP_WAIT: mul_en = 0;
                    
                    default: mul_en = 0;
                endcase 
            end
            
            //-------------------------------------------
            //-- FINAL MULTIPLICATION
            //-------------------------------------------
            
            (LAST_MUL): begin
                temp_A = temp_R1;
                temp_B = x_2;
                mul_en = 1;
            end
            
            default: begin
                // Default case for state
                // All signals already have default values assigned above
            end
        endcase
end

endmodule

module modular_multiplier_pipeline (
	input			iClk,		// system clock
	input			iRstn,		// active-low async reset

	input			iEn,		// enable input
	output			oReady,		// ready output
	output          oValid,

	input	[255:0]	iA,			// operand A (full 256-bit)
	input	[255:0]	iB,			// operand B (full 256-bit)
	output	[255:0]	oP			// current word of P,
);


 // FSM
// reg	[37:0]	fsm_shreg;
 reg	[17:0]	fsm_shreg_stage1;
 reg	[17:0]	fsm_shreg_stage2;

 wire	[14:0]	fsm_shreg_mul;
 wire	     	fsm_shreg_partial_sum_1;
 wire	     	fsm_shreg_partial_sum_2;
 wire	     	fsm_shreg_shift_p;
// reg			flag_enable_mac_ab;
// reg			flag_shreg_partial_sum_1;
// reg			flag_shreg_partial_sum_2;
// reg			flag_shreg_store_p;

 reg	[254:0]	buf_a_wide;
 reg	[254:0]	buf_b_wide;
 reg	[14:0]	mac_wrap;
 reg 	[21:0]	mac_accum[0:14];


wire [42:0] out_mac_0;
wire [42:0] out_mac_1;
wire [42:0] out_mac_2;
wire [42:0] out_mac_3;
wire [42:0] out_mac_4;
wire [42:0] out_mac_5;
wire [42:0] out_mac_6;
wire [42:0] out_mac_7;
wire [42:0] out_mac_8;
wire [42:0] out_mac_9;
wire [42:0] out_mac_10;
wire [42:0] out_mac_11;
wire [42:0] out_mac_12;
wire [42:0] out_mac_13;
wire [42:0] out_mac_14;

 reg [16:0] iA_mac0;
 reg [16:0] iA_mac1;
 reg [16:0] iA_mac2;
 reg [16:0] iA_mac3;
 reg [16:0] iA_mac4;
 reg [16:0] iA_mac5;
 reg [16:0] iA_mac6;
 reg [16:0] iA_mac7;
 reg [16:0] iA_mac8;
 reg [16:0] iA_mac9;
 reg [16:0] iA_mac10;
 reg [16:0] iA_mac11;
 reg [16:0] iA_mac12;
 reg [16:0] iA_mac13;
 reg [16:0] iA_mac14;

 reg [16:0] iB_mac;

  wire [42:0] iC_mac0;
  wire [42:0] iC_mac1;
  wire [42:0] iC_mac2;
  wire [42:0] iC_mac3;
  wire [42:0] iC_mac4;
  wire [42:0] iC_mac5;
  wire [42:0] iC_mac6;
  wire [42:0] iC_mac7;
  wire [42:0] iC_mac8;
  wire [42:0] iC_mac9;
  wire [42:0] iC_mac10;
  wire [42:0] iC_mac11;
  wire [42:0] iC_mac12;
  wire [42:0] iC_mac13;
  wire [42:0] iC_mac14;

 assign oReady = !(|fsm_shreg_stage1[17:0]);
 assign oValid = fsm_shreg_stage2[0];

 assign fsm_shreg_mul                    = fsm_shreg_stage1[17:3];
 assign fsm_shreg_partial_sum_1          = fsm_shreg_stage1[2];
 assign fsm_shreg_partial_sum_2          = fsm_shreg_stage1[1];
 assign fsm_shreg_shift_p                = fsm_shreg_stage1[0];

 wire flag_fsm_shreg_mul          = |fsm_shreg_mul;
 wire flag_partial_sum_1          = |fsm_shreg_partial_sum_1;
 wire flag_partial_sum_2          = |fsm_shreg_partial_sum_2;
 wire flag_shreg_shift_p          = |fsm_shreg_shift_p;

// always@(posedge iClk) begin
//	if(~iRstn) begin
//		flag_enable_mac_ab <= 1'b0;
//		flag_shreg_store_p <= 1'b0;
//		flag_shreg_partial_sum_1 <= 1'b0;
//		flag_shreg_partial_sum_2 <= 1'b0;
//	end
//	else begin
//		flag_enable_mac_ab        <= flag_fsm_shreg_mul;
//		flag_shreg_store_p        <= flag_shreg_shift_p;
//		flag_shreg_partial_sum_1  <= flag_partial_sum_1;
//		flag_shreg_partial_sum_2  <= flag_partial_sum_2;
//	end
// end

 // FSM Logic
 always@(posedge iClk) begin
	if(~iRstn)		fsm_shreg_stage1 <= 18'h0;
	else if(iEn)	fsm_shreg_stage1 <= {1'b1, 17'b0};
	else			fsm_shreg_stage1 <= {1'b0, fsm_shreg_stage1[17:1]};
 end

 always@(posedge iClk) begin
	if(~iRstn)		               fsm_shreg_stage2 <= 18'h1;
	else if(flag_shreg_shift_p)	   fsm_shreg_stage2 <= {1'b1, 17'b0};
	else			               fsm_shreg_stage2 <= {1'b0, fsm_shreg_stage2[17:1]};
 end

 // Wide Operand Buffer for B
 always@(posedge iClk) begin
	if(~iRstn)					buf_b_wide <= 255'b0;  // Reset on active-low reset
	else if(iEn)				buf_b_wide <= iB[254:0];      // Store full 256-bit B operand on enable
	else if(flag_fsm_shreg_mul)	buf_b_wide <= {17'b0, buf_b_wide[254:17]};      // Store full 256-bit B operand on enable
	else						buf_b_wide <= buf_b_wide;
 end

 always@(posedge iClk) begin
	if(~iRstn)					                    buf_a_wide <= 255'b0;  // Reset on active-low reset
    else if(iEn)	                                buf_a_wide <= iA[254:0];
    else if(flag_partial_sum_1)	            buf_a_wide <= {8'b0, out_mac_14 [42:34], 8'b0, out_mac_13 [42:34], 8'b0, out_mac_12 [42:34],
		                                                           8'b0, out_mac_11 [42:34], 8'b0, out_mac_10 [42:34], 8'b0, out_mac_9  [42:34],
		                                                           8'b0, out_mac_8  [42:34], 8'b0, out_mac_7  [42:34], 8'b0, out_mac_6  [42:34],
		                                                           8'b0, out_mac_5  [42:34], 8'b0, out_mac_4  [42:34], 8'b0, out_mac_3  [42:34],
		                                                           8'b0, out_mac_2  [42:34], 8'b0, out_mac_1  [42:34], 8'b0, out_mac_0  [42:34]};
	else						                    buf_a_wide <= buf_a_wide;
 end



  // MAC Clear Logic
always @(posedge iClk) begin
    if (!iRstn) mac_wrap <= 15'h0;
    else if (flag_fsm_shreg_mul) mac_wrap <= fsm_shreg_stage1[3] ? {1'b0, 14'b1} : {1'b1, mac_wrap[14:1]};
    else if (flag_partial_sum_1) mac_wrap <= {1'b1, 14'b01};
    else mac_wrap <= 15'h0;
end

wire mac_en;
wire mac_sum2;
assign mac_en = mac_sum2 | flag_partial_sum_1;
assign mac_sum2 = flag_fsm_shreg_mul | flag_partial_sum_2;


// wire [2:0] base[3:14];
//wire [2:0] thresh[3:14];
//wire [2:0] carry_in[3:15];  // carry_in[0] = 0, up to [12] for potential overflow

//assign carry_in[3] = 3'b000;

//generate
//  genvar j;
//  for (j = 3; j < 15; j = j + 1) begin : gen_thresh_base
//    wire [17:0] t_temp = 18'h20000 - {1'b0, mac_accum[j][16:0]};  // 2^17 - v_j (mac_accum low 17 bits)
//    assign base[j] = {1'b0, mac_accum[j][18:17]};
//    assign thresh[j] = (t_temp > 4) ? 3'b101 : t_temp[2:0];  // Cap at 5 for "never overflow"
//  end
//endgenerate

//// Combinational ripple chain for carries (linear, low area)
//generate
//  for (genvar i = 3; i < 15; i = i + 1) begin : carry_chain
//    wire delta = (carry_in[i] >= thresh[i]);
//    assign carry_in[i+1] = base[i] + {2'b00, delta};  // 3-bit add
//  end
//endgenerate

// always@(posedge iClk) begin
//    if(!iRstn) begin
//        mac_accum [0] <= 22'b0;
//        mac_accum [1] <= 22'b0;
//        mac_accum [2] <= 22'b0;
//        mac_accum [3] <= 22'b0;
//        mac_accum [4] <= 22'b0;
//        mac_accum [5] <= 22'b0;
//        mac_accum [6] <= 22'b0;
//        mac_accum [7] <= 22'b0;
//        mac_accum [8] <= 22'b0;
//        mac_accum [9] <= 22'b0;
//        mac_accum [10] <= 22'b0;
//        mac_accum [11] <= 22'b0;
//        mac_accum [12] <= 22'b0;
//        mac_accum [13] <= 22'b0;
//        mac_accum [14] <= 22'b0;
//    end
//    else if(flag_shreg_shift_p) begin
//	   mac_accum [0] <= out_mac_14[21:0];
//	   mac_accum [1] <= out_mac_0[21:0];
//	   mac_accum [2] <= out_mac_1[21:0];
//	   mac_accum [3] <= out_mac_2[21:0];
//	   mac_accum [4] <= out_mac_3[21:0];
//	   mac_accum [5] <= out_mac_4[21:0];
//	   mac_accum [6] <= out_mac_5[21:0];
//	   mac_accum [7] <= out_mac_6[21:0];
//	   mac_accum [8] <= out_mac_7[21:0];
//	   mac_accum [9] <= out_mac_8[21:0];
//	   mac_accum [10] <= out_mac_9[21:0];
//	   mac_accum [11] <= out_mac_10[21:0];
//	   mac_accum [12] <= out_mac_11[21:0];
//	   mac_accum [13] <= out_mac_12[21:0];
//	   mac_accum [14] <= out_mac_13[21:0];
//	end
//	else if(fsm_shreg_stage2[17]) begin
//         mac_accum[1] <= mac_accum[1] + {17'b0, mac_accum[0][21:17]};
//         mac_accum[0] <= {5'b0, mac_accum[0][16:0]};  // Clear upper bits
//    end
//    else if(fsm_shreg_stage2[16]) begin
//         mac_accum[2] <= mac_accum[2] + {17'b0, mac_accum[1][21:17]};
//         mac_accum[1] <= {5'b0, mac_accum[1][16:0]};
//    end
//    else if(fsm_shreg_stage2[15]) begin
//         mac_accum[3] <= mac_accum[3] + {17'b0, mac_accum[2][21:17]};
//         mac_accum[2] <= {5'b0, mac_accum[2][16:0]};
//    end
////    else if(fsm_shreg_stage2[14]) begin
////         mac_accum[4] <= mac_accum[4] + {17'b0, mac_accum[3][21:17]};
////    end
////    else if(fsm_shreg_stage2[13]) begin
////         mac_accum[5] <= mac_accum[5] + {17'b0, mac_accum[4][21:17]};
////    end
////    else if(fsm_shreg_stage2[12]) begin
////         mac_accum[6] <= mac_accum[6] + {17'b0, mac_accum[5][21:17]};
////    end
////    else if(fsm_shreg_stage2[11]) begin
////         mac_accum[7] <= mac_accum[7] + {17'b0, mac_accum[6][21:17]};
////    end
////    else if(fsm_shreg_stage2[10]) begin
////         mac_accum[8] <= mac_accum[8] + {17'b0, mac_accum[7][21:17]};
////    end
////    else if(fsm_shreg_stage2[9]) begin
////         mac_accum[9] <= mac_accum[9] + {17'b0, mac_accum[8][21:17]};
////    end
////    else if(fsm_shreg_stage2[8]) begin
////         mac_accum[10] <= mac_accum[10] + {17'b0, mac_accum[9][21:17]};
////    end
////    else if(fsm_shreg_stage2[7]) begin
////         mac_accum[11] <= mac_accum[11] + {17'b0, mac_accum[10][21:17]};
////    end
////    else if(fsm_shreg_stage2[6]) begin
////         mac_accum[12] <= mac_accum[12] + {17'b0, mac_accum[11][21:17]};
////    end
////    else if(fsm_shreg_stage2[5]) begin
////         mac_accum[13] <= mac_accum[13] + {17'b0, mac_accum[12][21:17]};
////    end
////    else if(fsm_shreg_stage2[4]) begin
////         mac_accum[14] <= mac_accum[14] + {17'b0, mac_accum[13][21:17]};
////    end
//    // Phase 2: 2-bit carry lookahead for limbs 4-14
//    // Cycle 14: Compute generate/propagate signals
////    else if(fsm_shreg_stage2[14]) begin


////    end
//    // Cycle 13: Parallel prefix - Level 1
//    else if(fsm_shreg_stage2[13]) begin

//    end

//    else if(fsm_shreg_stage2[12]) begin
//        mac_accum[3] <= {5'b0, mac_accum[3][16:0]};  // Clear upper bits of limb 3

//        // Apply carries and normalize all remaining limbs
//        mac_accum[4] <= {5'b0, mac_accum[4][16:0]} + {20'b0, carry_in[4]};
//        mac_accum[5] <= {5'b0, mac_accum[5][16:0]} + {20'b0, carry_in[5]};
//        mac_accum[6] <= {5'b0, mac_accum[6][16:0]} + {20'b0, carry_in[6]};
//        mac_accum[7] <= {5'b0, mac_accum[7][16:0]} + {20'b0, carry_in[7]};
//        mac_accum[8] <= {5'b0, mac_accum[8][16:0]} + {20'b0, carry_in[8]};
//        mac_accum[9] <= {5'b0, mac_accum[9][16:0]} + {20'b0, carry_in[9]};
//        mac_accum[10] <= {5'b0, mac_accum[10][16:0]} + {20'b0, carry_in[10]};
//        mac_accum[11] <= {5'b0, mac_accum[11][16:0]} + {20'b0, carry_in[11]};
//        mac_accum[12] <= {5'b0, mac_accum[12][16:0]} + {20'b0, carry_in[12]};
//        mac_accum[13] <= {5'b0, mac_accum[13][16:0]} + {20'b0, carry_in[13]};
//        mac_accum[14] <= mac_accum[14] + {20'b0, carry_in[14]};
//    end
//    else if(fsm_shreg_stage2[11]) begin
//        // First wraparound
//        mac_accum[0] <= mac_accum[0][16:0] + mac_accum[14][21:17]*19;
//    end
//    else if(fsm_shreg_stage2[10]) begin
//        // Second pass - this handles the edge case!
//        mac_accum[1] <= mac_accum[1][16:0] + {17'b0, mac_accum[0][21:17]};
//        mac_accum[0] <= {5'b0, mac_accum[0][16:0]};
//    end
//    else if(fsm_shreg_stage2[9]) begin
//        mac_accum[2] <= mac_accum[2][16:0] + {17'b0, mac_accum[1][21:17]};
//        mac_accum[1] <= {5'b0, mac_accum[1][16:0]};
//    end
//    else if(fsm_shreg_stage2[8]) begin
//        mac_accum[3] <= mac_accum[3][16:0] + {17'b0, mac_accum[2][21:17]};
//        mac_accum[2] <= {5'b0, mac_accum[2][16:0]};
//    end
//    else if(fsm_shreg_stage2[7]) begin

//    end
////    else if(fsm_shreg_stage2[6]) begin

////    end

//    else if(fsm_shreg_stage2[5]) begin
//        mac_accum[3] <= {5'b0, mac_accum[3][16:0]};  // Clear upper bits of limb 3

//        // Apply carries and normalize all remaining limbs
//        mac_accum[4] <= {5'b0, mac_accum[4][16:0]} + {20'b0, carry_in[4]};
//        mac_accum[5] <= {5'b0, mac_accum[5][16:0]} + {20'b0, carry_in[5]};
//        mac_accum[6] <= {5'b0, mac_accum[6][16:0]} + {20'b0, carry_in[6]};
//        mac_accum[7] <= {5'b0, mac_accum[7][16:0]} + {20'b0, carry_in[7]};
//        mac_accum[8] <= {5'b0, mac_accum[8][16:0]} + {20'b0, carry_in[8]};
//        mac_accum[9] <= {5'b0, mac_accum[9][16:0]} + {20'b0, carry_in[9]};
//        mac_accum[10] <= {5'b0, mac_accum[10][16:0]} + {20'b0, carry_in[10]};
//        mac_accum[11] <= {5'b0, mac_accum[11][16:0]} + {20'b0, carry_in[11]};
//        mac_accum[12] <= {5'b0, mac_accum[12][16:0]} + {20'b0, carry_in[12]};
//        mac_accum[13] <= {5'b0, mac_accum[13][16:0]} + {20'b0, carry_in[13]};
//        mac_accum[14] <= {5'b0, mac_accum[14][16:0]} + {20'b0, carry_in[14]};
//    end
//    else begin
//        mac_accum [0] <= mac_accum [0];
//        mac_accum [1] <= mac_accum [1];
//        mac_accum [2] <= mac_accum [2];
//        mac_accum [3] <= mac_accum [3];
//        mac_accum [4] <= mac_accum [4];
//        mac_accum [5] <= mac_accum [5];
//        mac_accum [6] <= mac_accum [6];
//        mac_accum [7] <= mac_accum [7];
//        mac_accum [8] <= mac_accum [8];
//        mac_accum [9] <= mac_accum [9];
//        mac_accum [10] <= mac_accum [10];
//        mac_accum [11] <= mac_accum [11];
//        mac_accum [12] <= mac_accum [12];
//        mac_accum [13] <= mac_accum [13];
//        mac_accum [14] <= mac_accum [14];
//    end
// end

wire [2:0] carry_in[4:15];  // 3 bits sufficient (<=3 initial, <=4 max)
wire [1:0] base[4:14];  // 2 bits
wire [2:0] thresh[4:14];  // 3 bits (cap to 5)

// Threshold and base for limbs 4-14
generate
  genvar j;
  for (j = 4; j < 15; j = j + 1) begin : gen_thresh_base
    wire [17:0] t_temp = 18'h20000 - {1'b0, mac_accum[j][16:0]};
    assign base[j] = mac_accum[j][18:17];  // 2 bits (<=3)
    assign thresh[j] = (t_temp > 4) ? 3'd5 : t_temp[2:0];  // Cap to 5 (>4 never triggers)
  end
endgenerate

// Starting carry from limb[3] overflow (now <=3)
assign carry_in[4] = {1'b0, mac_accum[3][18:17]};  // Extend to 3 bits

// Combinational ripple chain for i=4 to 14: 3-bit ops
generate
  for (genvar i = 4; i < 15; i = i + 1) begin : carry_chain
    wire delta = (carry_in[i] >= thresh[i]);
    assign carry_in[i+1] = {1'b0, base[i]} + delta;  // <=4, incrementer
  end
endgenerate

// In the always block (excerpt; replace relevant ifs)
always @(posedge iClk) begin
    if(!iRstn) begin
        mac_accum [0] <= 22'b0;
        mac_accum [1] <= 22'b0;
        mac_accum [2] <= 22'b0;
        mac_accum [3] <= 22'b0;
        mac_accum [4] <= 22'b0;
        mac_accum [5] <= 22'b0;
        mac_accum [6] <= 22'b0;
        mac_accum [7] <= 22'b0;
        mac_accum [8] <= 22'b0;
        mac_accum [9] <= 22'b0;
        mac_accum [10] <= 22'b0;
        mac_accum [11] <= 22'b0;
        mac_accum [12] <= 22'b0;
        mac_accum [13] <= 22'b0;
        mac_accum [14] <= 22'b0;
    end
    else if(flag_shreg_shift_p) begin
	   mac_accum [0] <= out_mac_14[21:0];
	   mac_accum [1] <= out_mac_0[21:0];
	   mac_accum [2] <= out_mac_1[21:0];
	   mac_accum [3] <= out_mac_2[21:0];
	   mac_accum [4] <= out_mac_3[21:0];
	   mac_accum [5] <= out_mac_4[21:0];
	   mac_accum [6] <= out_mac_5[21:0];
	   mac_accum [7] <= out_mac_6[21:0];
	   mac_accum [8] <= out_mac_7[21:0];
	   mac_accum [9] <= out_mac_8[21:0];
	   mac_accum [10] <= out_mac_9[21:0];
	   mac_accum [11] <= out_mac_10[21:0];
	   mac_accum [12] <= out_mac_11[21:0];
	   mac_accum [13] <= out_mac_12[21:0];
	   mac_accum [14] <= out_mac_13[21:0];

  end else if (fsm_shreg_stage2[17]) begin
    mac_accum[1] <= mac_accum[1] + {17'b0, mac_accum[0][21:17]};
    mac_accum[0] <= {5'b0, mac_accum[0][16:0]};
  end else if (fsm_shreg_stage2[16]) begin
    mac_accum[2] <= mac_accum[2] + {17'b0, mac_accum[1][21:17]};
    mac_accum[1] <= {5'b0, mac_accum[1][16:0]};
  end else if (fsm_shreg_stage2[15]) begin
    mac_accum[3] <= mac_accum[3] + {17'b0, mac_accum[2][21:17]};
    mac_accum[2] <= {5'b0, mac_accum[2][16:0]};
  end else if (fsm_shreg_stage2[14]) begin  // First pass final
    mac_accum[3] <= {5'b0, mac_accum[3][16:0]};  // Normalize [3]
    // Normalize [4-13]
    mac_accum[4] <= {5'b0, (mac_accum[4][16:0] + {14'b0, carry_in[4]})};
    mac_accum[5] <= {5'b0, (mac_accum[5][16:0] + {14'b0, carry_in[5]})};
    mac_accum[6] <= {5'b0, (mac_accum[6][16:0] + {14'b0, carry_in[6]})};
    mac_accum[7] <= {5'b0, (mac_accum[7][16:0] + {14'b0, carry_in[7]})};
    mac_accum[8] <= {5'b0, (mac_accum[8][16:0] + {14'b0, carry_in[8]})};
    mac_accum[9] <= {5'b0, (mac_accum[9][16:0] + {14'b0, carry_in[9]})};
    mac_accum[10] <= {5'b0, (mac_accum[10][16:0] + {14'b0, carry_in[10]})};
    mac_accum[11] <= {5'b0, (mac_accum[11][16:0] + {14'b0, carry_in[11]})};
    mac_accum[12] <= {5'b0, (mac_accum[12][16:0] + {14'b0, carry_in[12]})};
    mac_accum[13] <= {5'b0, (mac_accum[13][16:0] + {14'b0, carry_in[13]})};
    // [14] full add
    mac_accum[14] <= mac_accum[14] + {19'b0, carry_in[14]};
  end else if (fsm_shreg_stage2[13]) begin
    mac_accum[0] <= {5'b0, mac_accum[0][16:0]} + {mac_accum[14][21:17], 1'b0} + {mac_accum[14][21:17], 4'b0000} + mac_accum[14][21:17];  // Optimized *19 = *16 + *2 + *1 (shift/add)
//    mac_accum[0] <= mac_accum[0][16:0] + mac_accum[14][21:17]*19;
  end else if (fsm_shreg_stage2[12]) begin
    mac_accum[1] <= mac_accum[1] + {17'b0, mac_accum[0][21:17]};
    mac_accum[0] <= {5'b0, mac_accum[0][16:0]};
  end else if (fsm_shreg_stage2[11]) begin
    mac_accum[2] <= mac_accum[2] + {17'b0, mac_accum[1][21:17]};
    mac_accum[1] <= {5'b0, mac_accum[1][16:0]};
  end else if (fsm_shreg_stage2[10]) begin
    mac_accum[3] <= mac_accum[3] + {17'b0, mac_accum[2][21:17]};
    mac_accum[2] <= {5'b0, mac_accum[2][16:0]};
  end else if (fsm_shreg_stage2[9]) begin  // Second pass final (match [12])
    mac_accum[3] <= {5'b0, mac_accum[3][16:0]};
    mac_accum[4] <= (mac_accum[4][16:0] + {14'b0, carry_in[4]});
    mac_accum[5] <= (mac_accum[5][16:0] + {14'b0, carry_in[5]});
    mac_accum[6] <= (mac_accum[6][16:0] + {14'b0, carry_in[6]});
    mac_accum[7] <= (mac_accum[7][16:0] + {14'b0, carry_in[7]});
    mac_accum[8] <= (mac_accum[8][16:0] + {14'b0, carry_in[8]});
    mac_accum[9] <= (mac_accum[9][16:0] + {14'b0, carry_in[9]});
    mac_accum[10] <= (mac_accum[10][16:0] + {14'b0, carry_in[10]});
    mac_accum[11] <= (mac_accum[11][16:0] + {14'b0, carry_in[11]});
    mac_accum[12] <= (mac_accum[12][16:0] + {14'b0, carry_in[12]});
    mac_accum[13] <= (mac_accum[13][16:0] + {14'b0, carry_in[13]});
    mac_accum[14] <= mac_accum[14] + {17'b0, carry_in[14]};
  end
end

always@(*) begin
    if(mac_sum2) begin
        iA_mac0 = buf_a_wide[16:0];
        iA_mac1 = buf_a_wide[33:17];
        iA_mac2 = buf_a_wide[50:34];
        iA_mac3 = buf_a_wide[67:51];
        iA_mac4 = buf_a_wide[84:68];
        iA_mac5 = buf_a_wide[101:85];
        iA_mac6 = buf_a_wide[118:102];
        iA_mac7 = buf_a_wide[135:119];
        iA_mac8 = buf_a_wide[152:136];
        iA_mac9 = buf_a_wide[169:153];
        iA_mac10 = buf_a_wide[186:170];
        iA_mac11 = buf_a_wide[203:187];
        iA_mac12 = buf_a_wide[220:204];
        iA_mac13 = buf_a_wide[237:221];
        iA_mac14 = buf_a_wide[254:238];
    end
//	else if(flag_shreg_partial_sum_1) begin
	else begin
        iA_mac0 = out_mac_0[33:17];
        iA_mac1 = out_mac_1[33:17];
		iA_mac2 = out_mac_2[33:17];
		iA_mac3 = out_mac_3[33:17];
		iA_mac4 = out_mac_4[33:17];
		iA_mac5 = out_mac_5[33:17];
		iA_mac6 = out_mac_6[33:17];
		iA_mac7 = out_mac_7[33:17];
		iA_mac8 = out_mac_8[33:17];
		iA_mac9 = out_mac_9[33:17];
		iA_mac10 = out_mac_10[33:17];
		iA_mac11 = out_mac_11[33:17];
		iA_mac12 = out_mac_12[33:17];
		iA_mac13 = out_mac_13[33:17];
		iA_mac14 = out_mac_14[33:17];
    end
end

always@(*) begin
    if(flag_fsm_shreg_mul) begin
        iB_mac = buf_b_wide[16:0];
    end
    else begin
        iB_mac = 17'b1;
    end
end

 assign iC_mac0[16:0] = out_mac_1[16:0];
 assign iC_mac1[16:0] = out_mac_2[16:0];
 assign iC_mac2[16:0] = out_mac_3[16:0];
 assign iC_mac3[16:0] = out_mac_4[16:0];
 assign iC_mac4[16:0] = out_mac_5[16:0];
 assign iC_mac5[16:0] = out_mac_6[16:0];
 assign iC_mac6[16:0] = out_mac_7[16:0];
 assign iC_mac7[16:0] = out_mac_8[16:0];
 assign iC_mac8[16:0] = out_mac_9[16:0];
 assign iC_mac9[16:0] = out_mac_10[16:0];
 assign iC_mac10[16:0] = out_mac_11[16:0];
 assign iC_mac11[16:0] = out_mac_12[16:0];
 assign iC_mac12[16:0] = out_mac_13[16:0];
 assign iC_mac13[16:0] = out_mac_14[16:0];
 assign iC_mac14[16:0] = out_mac_0[16:0];

 assign iC_mac0[42:17] = (mac_sum2) ? out_mac_1[42:17] : 26'b0;
 assign iC_mac1[42:17] = (mac_sum2) ? out_mac_2[42:17] : 26'b0;
 assign iC_mac2[42:17] = (mac_sum2) ? out_mac_3[42:17] : 26'b0;
 assign iC_mac3[42:17] = (mac_sum2) ? out_mac_4[42:17] : 26'b0;
 assign iC_mac4[42:17] = (mac_sum2) ? out_mac_5[42:17] : 26'b0;
 assign iC_mac5[42:17] = (mac_sum2) ? out_mac_6[42:17] : 26'b0;
 assign iC_mac6[42:17] = (mac_sum2) ? out_mac_7[42:17] : 26'b0;
 assign iC_mac7[42:17] = (mac_sum2) ? out_mac_8[42:17] : 26'b0;
 assign iC_mac8[42:17] = (mac_sum2) ? out_mac_9[42:17] : 26'b0;
 assign iC_mac9[42:17] = (mac_sum2) ? out_mac_10[42:17] : 26'b0;
 assign iC_mac10[42:17] = (mac_sum2) ? out_mac_11[42:17] : 26'b0;
 assign iC_mac11[42:17] = (mac_sum2) ? out_mac_12[42:17] : 26'b0;
 assign iC_mac12[42:17] = (mac_sum2) ? out_mac_13[42:17] : 26'b0;
 assign iC_mac13[42:17] = (mac_sum2) ? out_mac_14[42:17] : 26'b0;
 assign iC_mac14[42:17] = (mac_sum2) ? out_mac_0[42:17] : 26'b0;



 mac17 mac17_inst0 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[0]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac0),
	.iB		(iB_mac),
	.iC     (iC_mac0),
	.oS		(out_mac_0)
 );

 mac17 mac17_inst1 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[1]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac1),
	.iB		(iB_mac),
	.iC     (iC_mac1),
	.oS		(out_mac_1)
 );

 mac17 mac17_inst2 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[2]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac2),
	.iB		(iB_mac),
	.iC     (iC_mac2),
	.oS		(out_mac_2)
 );

 mac17 mac17_inst3 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[3]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac3),
	.iB		(iB_mac),
	.iC     (iC_mac3),
	.oS		(out_mac_3)
 );

 mac17 mac17_inst4 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[4]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac4),
	.iB		(iB_mac),
	.iC     (iC_mac4),
	.oS		(out_mac_4)
 );

 mac17 mac17_inst5 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[5]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac5),
	.iB		(iB_mac),
	.iC     (iC_mac5),
	.oS		(out_mac_5)
 );

 mac17 mac17_inst6 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[6]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac6),
	.iB		(iB_mac),
	.iC     (iC_mac6),
	.oS		(out_mac_6)
 );

 mac17 mac17_inst7 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[7]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac7),
	.iB		(iB_mac),
	.iC     (iC_mac7),
	.oS		(out_mac_7)
 );

 mac17 mac17_inst8 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[8]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
	.iEn    (mac_en),
	.iA		(iA_mac8),
	.iB		(iB_mac),
	.iC     (iC_mac8),
	.oS		(out_mac_8)
 );

 mac17 mac17_inst9 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[9]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac9),
	.iB		(iB_mac),
	.iC     (iC_mac9),
	.oS		(out_mac_9)
 );

 mac17 mac17_inst10 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[10]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac10),
	.iB		(iB_mac),
	.iC     (iC_mac10),
	.oS		(out_mac_10)
 );

 mac17 mac17_inst11 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[11]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac11),
	.iB		(iB_mac),
	.iC     (iC_mac11),
	.oS		(out_mac_11)
 );

 mac17 mac17_inst12 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[12]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac12),
	.iB		(iB_mac),
	.iC     (iC_mac12),
	.oS		(out_mac_12)
 );

 mac17 mac17_inst13 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[13]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac13),
	.iB		(iB_mac),
	.iC     (iC_mac13),
	.oS		(out_mac_13)
 );

 mac17 mac17_inst14 (
	.iClk	(iClk),
	.iWrap	(mac_wrap[14]),
	.iRstn	(iRstn),
	.iAccum_rst(iEn),
    .iEn    (mac_en),
	.iA		(iA_mac14),
	.iB		(iB_mac),
	.iC     (iC_mac14),
	.oS		(out_mac_14)
 );

 reg [255:0] p_dout_reg;

wire [254:0] p_temp =     {mac_accum[14][16:0], mac_accum[13][16:0], mac_accum[12][16:0],
                           mac_accum[11][16:0], mac_accum[10][16:0], mac_accum[9] [16:0],
                           mac_accum[8] [16:0], mac_accum[7] [16:0], mac_accum[6] [16:0],
                           mac_accum[5] [16:0], mac_accum[4] [16:0], mac_accum[3] [16:0],
                           mac_accum[2] [16:0], mac_accum[1] [16:0], mac_accum[0] [16:0]};
 wire [255:0] p_plus_19 = {1'b0, p_temp} + 5'd19;
 wire need_reduction = p_plus_19[255];

 always@(*) begin
	if(fsm_shreg_stage2[0])	p_dout_reg = need_reduction ? {1'b0, p_plus_19[254:0]} : {1'b0, p_temp};
	else                    p_dout_reg = 256'b0;
 end

  assign oP = p_dout_reg;

endmodule

module mac17 (
    input           iClk,   // clock
    input           iRstn,  // reset (active-low)
    input           iEn,    // enable accumulation
    input           iAccum_rst,    // reset accumulation
    input           iWrap,  // multiply by 19 if set
    input  [16:0]   iA,     // 17-bit input A
    input  [16:0]   iB,     // 17-bit input B
    input  [42:0]   iC,     // accumulator input
    output [42:0]   oS      // accumulator output
);


    wire [21:0] b_eff;
    assign b_eff = iWrap ? (iB << 4) + (iB << 1) + iB : {5'b0, iB};
        
    // Intermediate 17x17 multiply (34-bit product)
    wire [38:0] p_raw;
    assign p_raw = iA * b_eff;
    
    reg [42:0] s_reg;
    always @(posedge iClk) begin
        if (!iRstn | iAccum_rst)
            s_reg <= 43'b0;
        else if (iEn)
            s_reg <= p_raw + iC;
    end

    assign oS = s_reg;

endmodule

module modular_adder_subtractor_256_hp (
    input               iClk,
    input               rst_n,
    input               start,
    input       [255:0] a,
    input       [255:0] b,
    input               sub,        // 1 for subtract, 0 for add
    output reg  [255:0] result,
    output reg          done
);

    localparam [255:0] P = 256'h7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;

    // A fixed, linear state machine for constant-time execution
    localparam [2:0] IDLE             = 3'b000;
    localparam [2:0] CALC_MAIN        = 3'b001; // Stage 1: a +/- b
    localparam [2:0] CHECK            = 3'b010;
    localparam [2:0] CALC_CORRECTION  = 3'b011; // Stage 2: (dummy or real) tmp +/- P
    localparam [2:0] FINISH           = 3'b100;

    reg [2:0] state;

    // Pipeline registers
    reg [255:0] a_reg, b_reg;
    reg         sub_reg_pipe;
//    reg [255:0] main_result_pipe; // Stores result of stage 1, input to stage 2
    
    // Datapath signals
    reg [1:0]   chunk_counter;
    reg         carry_reg;
    reg [63:0]  a_chunk, b_chunk;
    reg         sub_chunk, cin_chunk;
    wire [63:0] result_chunk;
    wire        cout_chunk;

    // This wire combinationally implements the check "main_result_pipe >= P"
    wire main_result_ge_P;
    assign main_result_ge_P = result[255] || ((&result[254:5]) && (result[4] || (result[3] & result[2] & result[0]) || (result[3] & result[2] & result[1])));
                    
    adder_subtractor_64_with_cin adder_inst (
        .a(a_chunk), 
        .b(b_chunk), 
        .sub(sub_chunk), 
        .cin_ext(cin_chunk),
        .result(result_chunk), 
        .cout(cout_chunk), 
        .overflow()
    );

    // These registers hold the decision made at the end of CALC_MAIN
    // for use during the CALC_CORRECTION stage.
    reg needs_correction_reg;
    reg correction_is_add_reg;
    
    wire chunk_counter_all_one = &chunk_counter;
    wire chunk_counter_all_zero = ~|chunk_counter;
    
    always @(posedge iClk) begin
        if (!rst_n) begin
            state <= IDLE;
            chunk_counter <= 3'b0;
            done <= 1'b0;
            result <= 256'b0;
            needs_correction_reg <= 1'b0;
        end else begin
            done <= 1'b0;

            case (state)
                IDLE: begin
                    if (start) begin
                        a_reg <= a;
                        b_reg <= b;
                        sub_reg_pipe <= sub;
                        chunk_counter <= 3'b0;
                        carry_reg <= 1'b0;
                        state <= CALC_MAIN;
                    end
                end

                CALC_MAIN: begin
                    result[(chunk_counter * 64) +: 64] <= result_chunk;
                    carry_reg <= cout_chunk;

                    if (chunk_counter_all_one) begin
                        // Latch the control signals for the NEXT stage.
                        // Use cout_chunk directly, as it IS the final carry in this specific cycle.
                        
                        correction_is_add_reg <= sub_reg_pipe;

                        chunk_counter <= 3'b0;
                        carry_reg <= ~sub_reg_pipe;
                        state <= CHECK;
                    end else begin
                        chunk_counter <= chunk_counter + 1;
                    end
                end
                CHECK: begin
                    needs_correction_reg <= main_result_ge_P;
                    state <= CALC_CORRECTION;        
                end

                CALC_CORRECTION: begin
                    // The output of this stage IS the final result.
                    result[(chunk_counter * 64) +: 64] <= result_chunk;
                    carry_reg <= cout_chunk;

                    if (chunk_counter_all_one) begin
                        state <= FINISH;
                    end else begin
                        chunk_counter <= chunk_counter + 1;
                    end
                end

                FINISH: begin
                    // This state now only serves to signal completion.
                    // The result has already been calculated and stored.
                        result <= {1'b0, result[254:0]};
                        done <= 1'b1;
                        state <= IDLE;
                end
                default: begin
                    state <= IDLE;
                end
            endcase
        end
    end

    // Combinational logic for driving the single adder datapath
    always @(*) begin
        case (state)
            CALC_MAIN: begin
                a_chunk = a_reg[(chunk_counter * 64) +: 64];
                b_chunk = b_reg[(chunk_counter * 64) +: 64];
                sub_chunk = sub_reg_pipe;
                cin_chunk = (chunk_counter_all_zero) ? sub_reg_pipe : carry_reg;
            end
            CALC_CORRECTION: begin
                a_chunk = result[(chunk_counter * 64) +: 64];
                b_chunk = needs_correction_reg ? P[(chunk_counter * 64) +: 64] : 64'b0;
                sub_chunk = ~correction_is_add_reg;
                cin_chunk = (chunk_counter_all_zero) ? ~correction_is_add_reg : carry_reg;
            end
            default: begin
                a_chunk = 64'b0;
                b_chunk = 64'b0;
                sub_chunk = 1'b0;
                cin_chunk = 1'b0;
            end
        endcase
    end

endmodule

module adder_subtractor_64_with_cin (
    input [63:0] a,
    input [63:0] b,
    input sub,
    input cin_ext,
    output [63:0] result,
    output cout,
    output overflow
);
    wire [63:0] b_xor;
    wire [15:0] c_out;
    
    assign b_xor = b ^ {64{sub}};
    
    // First 32 bits (bits 0-31)
    cla_4bit cla0  (.a(a[3:0]),   .b(b_xor[3:0]),   .cin(cin_ext),   .sum(result[3:0]),   .cout(c_out[0]));
    cla_4bit cla1  (.a(a[7:4]),   .b(b_xor[7:4]),   .cin(c_out[0]),  .sum(result[7:4]),   .cout(c_out[1]));
    cla_4bit cla2  (.a(a[11:8]),  .b(b_xor[11:8]),  .cin(c_out[1]),  .sum(result[11:8]),  .cout(c_out[2]));
    cla_4bit cla3  (.a(a[15:12]), .b(b_xor[15:12]), .cin(c_out[2]),  .sum(result[15:12]), .cout(c_out[3]));
    cla_4bit cla4  (.a(a[19:16]), .b(b_xor[19:16]), .cin(c_out[3]),  .sum(result[19:16]), .cout(c_out[4]));
    cla_4bit cla5  (.a(a[23:20]), .b(b_xor[23:20]), .cin(c_out[4]),  .sum(result[23:20]), .cout(c_out[5]));
    cla_4bit cla6  (.a(a[27:24]), .b(b_xor[27:24]), .cin(c_out[5]),  .sum(result[27:24]), .cout(c_out[6]));
    cla_4bit cla7  (.a(a[31:28]), .b(b_xor[31:28]), .cin(c_out[6]),  .sum(result[31:28]), .cout(c_out[7]));
    
    // Second 32 bits (bits 32-63)
    cla_4bit cla8  (.a(a[35:32]), .b(b_xor[35:32]), .cin(c_out[7]),  .sum(result[35:32]), .cout(c_out[8]));
    cla_4bit cla9  (.a(a[39:36]), .b(b_xor[39:36]), .cin(c_out[8]),  .sum(result[39:36]), .cout(c_out[9]));
    cla_4bit cla10 (.a(a[43:40]), .b(b_xor[43:40]), .cin(c_out[9]),  .sum(result[43:40]), .cout(c_out[10]));
    cla_4bit cla11 (.a(a[47:44]), .b(b_xor[47:44]), .cin(c_out[10]), .sum(result[47:44]), .cout(c_out[11]));
    cla_4bit cla12 (.a(a[51:48]), .b(b_xor[51:48]), .cin(c_out[11]), .sum(result[51:48]), .cout(c_out[12]));
    cla_4bit cla13 (.a(a[55:52]), .b(b_xor[55:52]), .cin(c_out[12]), .sum(result[55:52]), .cout(c_out[13]));
    cla_4bit cla14 (.a(a[59:56]), .b(b_xor[59:56]), .cin(c_out[13]), .sum(result[59:56]), .cout(c_out[14]));
    cla_4bit cla15 (.a(a[63:60]), .b(b_xor[63:60]), .cin(c_out[14]), .sum(result[63:60]), .cout(c_out[15]));
    
    assign cout = c_out[15];
    // Overflow detection using carry bits from the two most significant positions
    assign overflow = c_out[14] ^ c_out[15];
endmodule

module adder_subtractor_32_with_cin (
    input [31:0] a,
    input [31:0] b,
    input sub,
    input cin_ext,
    output [31:0] result,
    output cout,
    output overflow
);

    wire [31:0] b_xor;
    wire [7:0] c_out;
    
    assign b_xor = b ^ {32{sub}};
    //wire initial_carry = sub ? 1'b1 : cin_ext; 
    
    cla_4bit cla0 (.a(a[3:0]), .b(b_xor[3:0]), .cin(cin_ext), .sum(result[3:0]), .cout(c_out[0]));
    cla_4bit cla1 (.a(a[7:4]), .b(b_xor[7:4]), .cin(c_out[0]), .sum(result[7:4]), .cout(c_out[1]));
    cla_4bit cla2 (.a(a[11:8]), .b(b_xor[11:8]), .cin(c_out[1]), .sum(result[11:8]), .cout(c_out[2]));
    cla_4bit cla3 (.a(a[15:12]), .b(b_xor[15:12]), .cin(c_out[2]), .sum(result[15:12]), .cout(c_out[3]));
    cla_4bit cla4 (.a(a[19:16]), .b(b_xor[19:16]), .cin(c_out[3]), .sum(result[19:16]), .cout(c_out[4]));
    cla_4bit cla5 (.a(a[23:20]), .b(b_xor[23:20]), .cin(c_out[4]), .sum(result[23:20]), .cout(c_out[5]));
    cla_4bit cla6 (.a(a[27:24]), .b(b_xor[27:24]), .cin(c_out[5]), .sum(result[27:24]), .cout(c_out[6]));
    cla_4bit cla7 (.a(a[31:28]), .b(b_xor[31:28]), .cin(c_out[6]), .sum(result[31:28]), .cout(c_out[7]));
    
    assign cout = c_out[7];
    // For addition: overflow when same signs produce different sign
    // For subtraction: overflow when different signs produce wrong sign
    //assign overflow = sub ? 
    //    ((a[31] != b[31]) && (result[31] != a[31])) :     // Subtraction overflow
    //    ((a[31] == b[31]) && (result[31] != a[31]));      // Addition overflow
    assign overflow = c_out[6] ^ c_out[7];
endmodule

// 4-bit Carry Lookahead Adder
module cla_4bit (
    input [3:0] a,
    input [3:0] b,
    input cin,
    output [3:0] sum,
    output cout
);

    wire [3:0] p, g;
    wire [3:0] c;
    
    assign p = a ^ b;
    assign g = a & b;
    
    assign c[0] = cin;
    assign c[1] = g[0] | (p[0] & c[0]);
    assign c[2] = g[1] | (p[1] & g[0]) | (p[1] & p[0] & c[0]);
    assign c[3] = g[2] | (p[2] & g[1]) | (p[2] & p[1] & g[0]) | (p[2] & p[1] & p[0] & c[0]);
    
    assign sum = p ^ c;
    assign cout = g[3] | (p[3] & g[2]) | (p[3] & p[2] & g[1]) | (p[3] & p[2] & p[1] & g[0]) | (p[3] & p[2] & p[1] & p[0] & cin);

endmodule

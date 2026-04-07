`timescale 1ns/1ps

module ladder_rom (
    input wire [5:0] addr,
    output reg [14:0] instruction // <-- REDUCED FROM 20 TO 15 BITS!
);
    // Instruction Format: [14:12] Op, [11:9] Dest, [8:6] SrcA, [5:3] SrcB, [2:0] Sq_ID

    // Opcodes
    localparam OP_ADD    = 3'd0;
    localparam OP_SUB    = 3'd1;
    localparam OP_MUL    = 3'd2; 
    localparam OP_SQRN   = 3'd3; 
    localparam OP_CSWAP  = 3'd4; 
    localparam OP_CONST  = 3'd5; 
    localparam OP_EXIT   = 3'd7; 
    
    // Register Map
    localparam X1=3'd0, X2=3'd1, Z2=3'd2, X3=3'd3, Z3=3'd4, T1=3'd5, T2=3'd6, ZERO=3'd7;

    // Squaring Count IDs (The compression map)
    localparam SQ_1   = 3'd0; // Maps to 1
    localparam SQ_5   = 3'd1; // Maps to 5
    localparam SQ_10  = 3'd2; // Maps to 10
    localparam SQ_20  = 3'd3; // Maps to 20
    localparam SQ_50  = 3'd4; // Maps to 50
    localparam SQ_100 = 3'd5; // Maps to 100
    localparam SQ_X   = 3'd7; // Don't care (for non-SQRN ops)

    always @(*) begin
        case (addr)
            // ============================================================
            // MONTGOMERY LADDER STEP
            // ============================================================
            
            // Note: Last field is now the 3-bit ID, not the 8-bit value
            6'd00: instruction = {OP_CSWAP, 3'd0, 3'd0, 3'd0, SQ_X}; 
            
            // Compute A = x_2 + z_2, B = x_2 - z_2
            6'd01: instruction = {OP_ADD, T1, X2, Z2, SQ_X}; 
            6'd02: instruction = {OP_SUB, T2, X2, Z2, SQ_X}; 
            
            // Compute C = x_3 + z_3, D = x_3 - z_3  
            6'd03: instruction = {OP_ADD, X2, X3, Z3, SQ_X}; 
            6'd04: instruction = {OP_SUB, Z2, X3, Z3, SQ_X}; 
            
            // Compute DA = D * A, CB = C * B
            6'd05: instruction = {OP_MUL, Z3, Z2, T1, SQ_X}; 
            6'd06: instruction = {OP_MUL, X3, X2, T2, SQ_X}; 
            
            // Compute new x_3 = (DA + CB)^2
            6'd07: instruction = {OP_ADD, X2, Z3, X3, SQ_X}; 
            6'd08: instruction = {OP_SQRN, X2, X2, 3'd0, SQ_1};   // ID for 1
            6'd09: instruction = {OP_SUB, Z2, Z3, X3, SQ_X}; 
            6'd10: instruction = {OP_SQRN, Z2, Z2, 3'd0, SQ_1};   // ID for 1
            6'd11: instruction = {OP_MUL, Z2, X1, Z2, SQ_X}; 
            
            // Move new x_3, z_3
            6'd12: instruction = {OP_ADD, X3, X2, ZERO, SQ_X}; 
            6'd13: instruction = {OP_ADD, Z3, Z2, ZERO, SQ_X}; 
            
            // Compute AA = A^2, BB = B^2
            6'd14: instruction = {OP_SQRN, T1, T1, 3'd0, SQ_1};   // ID for 1
            6'd15: instruction = {OP_SQRN, T2, T2, 3'd0, SQ_1};   // ID for 1
            
            // Compute E = AA - BB
            6'd16: instruction = {OP_SUB, X2, T1, T2, SQ_X}; 
            
            // Compute new z_2
            6'd17: instruction = {OP_CONST, Z2, X2, 3'd0, SQ_X}; 
            6'd18: instruction = {OP_ADD, Z2, Z2, T1, SQ_X}; 
            6'd19: instruction = {OP_MUL, Z2, X2, Z2, SQ_X}; 
            
            // Compute new x_2
            6'd20: instruction = {OP_MUL, X2, T1, T2, SQ_X}; 
            
            // Done!
            6'd21: instruction = {OP_EXIT, 3'd0, 3'd0, 3'd0, SQ_X}; 
            
            // --- INVERSION CHAIN (Using compressed constants!) ---
            6'd22: instruction = {OP_SQRN, T1, Z2, 3'd0, SQ_1}; 
            6'd23: instruction = {OP_SQRN, T2, T1, 3'd0, SQ_1}; 
            6'd24: instruction = {OP_SQRN, T2, T2, 3'd0, SQ_1}; 
            6'd25: instruction = {OP_MUL, T2, T2, Z2, SQ_X}; 
            6'd26: instruction = {OP_MUL, X1, T2, T1, SQ_X}; 
            6'd27: instruction = {OP_SQRN, T1, X1, 3'd0, SQ_1}; 
            6'd28: instruction = {OP_MUL, T1, T1, T2, SQ_X}; 
            
            // Large counts use IDs now:
            6'd29: instruction = {OP_SQRN, T2, T1, 3'd0, SQ_5};   // ID for 5
            6'd30: instruction = {OP_MUL, X3, T2, T1, SQ_X}; 
            
            6'd31: instruction = {OP_SQRN, T1, X3, 3'd0, SQ_10};  // ID for 10
            6'd32: instruction = {OP_MUL, T1, T1, X3, SQ_X}; 
            
            6'd33: instruction = {OP_SQRN, T2, T1, 3'd0, SQ_20};  // ID for 20
            6'd34: instruction = {OP_MUL, T2, T2, T1, SQ_X}; 
            
            6'd35: instruction = {OP_SQRN, T1, T2, 3'd0, SQ_10};  // ID for 10
            6'd36: instruction = {OP_MUL, Z3, T1, X3, SQ_X}; 
            
            6'd37: instruction = {OP_SQRN, T1, Z3, 3'd0, SQ_50};  // ID for 50
            6'd38: instruction = {OP_MUL, T1, T1, Z3, SQ_X}; 
            
            6'd39: instruction = {OP_SQRN, T2, T1, 3'd0, SQ_100}; // ID for 100
            6'd40: instruction = {OP_MUL, T2, T2, T1, SQ_X}; 
            
            6'd41: instruction = {OP_SQRN, T1, T2, 3'd0, SQ_50};  // ID for 50
            6'd42: instruction = {OP_MUL, T1, T1, Z3, SQ_X}; 
            
            6'd43: instruction = {OP_SQRN, T1, T1, 3'd0, SQ_5};   // ID for 5
            6'd44: instruction = {OP_MUL, T1, T1, X1, SQ_X}; 
            
            6'd45: instruction = {OP_MUL, X2, X2, T1, SQ_X}; 
            6'd46: instruction = {OP_EXIT, 3'd0, 3'd0, 3'd0, SQ_X}; 
            
            default: instruction = 15'd0;
        endcase
    end
endmodule

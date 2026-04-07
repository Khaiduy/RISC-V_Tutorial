`timescale 1ns / 1ps

// Simplified TRNG for 256-bit ephemeral key generation
// Collects 4×64-bit words directly from ring oscillator + LFSR
// No DRBG, no AES - just raw entropy output

module SimpleTRNG(
    input         iClk,
    input         iRst,
    output [255:0] oRng,      // 256-bit output (4 words)
    output         oReady     // High when new entropy available
);

    // State machine
    localparam IDLE     = 3'd0;
    localparam WARMUP   = 3'd1;
    localparam COLLECT  = 3'd2;
    localparam DONE     = 3'd3;
    
    reg [2:0]  state, next_state;
    reg [11:0] warmup_cnt;     // 2048 cycles warmup per word
    reg [2:0]  word_cnt;       // Collect 4 words (0-3)
    reg [255:0] rng_buffer;    // Store collected entropy
    reg        ready_flag;
    
    // TopTRNG instance - ring oscillator + LFSR
    wire [63:0] trng_out;
    wire        trng_en;
    
    TopTRNG trng_inst(
        .iClk(iClk),
        .iRst(iRst),
        .iEn(trng_en),
        .oRng(trng_out)
    );
    
    assign trng_en = (state == WARMUP) || (state == COLLECT);
    assign oRng = rng_buffer;
    assign oReady = ready_flag;
    
    // State machine
    always @(posedge iClk or posedge iRst) begin
        if (iRst) begin
            state <= IDLE;
            warmup_cnt <= 12'd0;
            word_cnt <= 3'd0;
            rng_buffer <= 256'd0;
            ready_flag <= 1'b0;
        end else begin
            state <= next_state;
            
            case (state)
                IDLE: begin
                    warmup_cnt <= 12'd0;
                    word_cnt <= 3'd0;
                    ready_flag <= 1'b0;
                end
                
                WARMUP: begin
                    warmup_cnt <= warmup_cnt + 1;
                end
                
                COLLECT: begin
                    // Collect 64-bit word into buffer
                    case (word_cnt)
                        3'd0: rng_buffer[63:0]    <= trng_out;
                        3'd1: rng_buffer[127:64]  <= trng_out;
                        3'd2: rng_buffer[191:128] <= trng_out;
                        3'd3: rng_buffer[255:192] <= trng_out;
                    endcase
                    
                    if (word_cnt < 3'd3) begin
                        word_cnt <= word_cnt + 1;
                        warmup_cnt <= 12'd0;
                    end
                end
                
                DONE: begin
                    ready_flag <= 1'b1;
                end
            endcase
        end
    end
    
    // Next state logic
    always @(*) begin
        next_state = state;
        
        case (state)
            IDLE: begin
                next_state = WARMUP;
            end
            
            WARMUP: begin
                if (warmup_cnt >= 12'd2047)
                    next_state = COLLECT;
            end
            
            COLLECT: begin
                if (word_cnt == 3'd3)
                    next_state = DONE;
                else
                    next_state = WARMUP;
            end
            
            DONE: begin
                // Stay in DONE until reset or re-read
                // Can add auto-restart logic here if needed
                next_state = DONE;
            end
        endcase
    end

endmodule

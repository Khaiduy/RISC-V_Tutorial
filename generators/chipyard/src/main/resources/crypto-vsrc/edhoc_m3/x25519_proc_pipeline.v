`timescale 1ns / 1ps

// X25519 Processor using unified_modular_arith
// All field ops (MUL, ADD, SUB) routed through one unified_modular_arith instance.
// FSM simplified: S_EXEC/S_EXEC2/S_WAIT_MUL merged into S_WAIT_ARITH.
// SQRN auto-restart: on oValid, arith_en is re-pulsed immediately; oReady is
// guaranteed on the very next cycle (stage2 FSM clears one cycle after oValid).
// RF uses distributed LUTRAM: S_INIT writes one register per cycle (init_cnt).
// unified_modular_arith has a registered output (oP_r), so oValid is 1 cycle
// later than before — SQRN restart timing adjusted accordingly.

module x25519_proc_pipeline (
    input wire clk,
    input wire rst,
    input wire start,
    input wire [255:0] scalar,    // RFC 7748 byte-big-endian format
    input wire [255:0] u_in,
    output reg done,
    output wire [255:0] res_out
);

    // -------------------------------------------------------------------------
    // 1. Constants & byte-reversal (RFC ↔ internal little-endian)
    // -------------------------------------------------------------------------
    localparam [254:0] A24 = 255'd121665;

    wire [255:0] scalar_le, u_in_le;
    genvar i;
    generate
        for (i = 0; i < 32; i = i + 1) begin : byte_rev_in
            assign scalar_le[8*i +: 8] = scalar[8*(31-i) +: 8];
            assign u_in_le  [8*i +: 8] = u_in  [8*(31-i) +: 8];
        end
    endgenerate

    // Scalar clamping (RFC 7748)
    wire [255:0] clamped_scalar;
    assign clamped_scalar = {1'b0, 1'b1, scalar_le[253:3], 3'b000};

    wire [254:0] u_clamped;
    assign u_clamped = u_in_le[254:0];

    // -------------------------------------------------------------------------
    // 2. Register file — 7 × 255-bit field elements in distributed LUTRAM.
    //    Index 7 is virtual ZERO (op_b mux); never written.
    //    Canonical template: single always block with explicit wr_en/wr_addr/wr_data
    //    so Vivado infers RAM64X1S (depth-8, 3-bit address, 255 columns).
    // -------------------------------------------------------------------------
    (* ram_style = "distributed" *) reg [254:0] rf [0:6];

    reg [2:0] init_cnt;   // counts 0..6 during S_INIT

    // Combinatorial write-data mux for INIT (constant per init_cnt slot)
    reg [254:0] rf_init_data;
    always @(*) begin
        case (init_cnt)
            3'd0:    rf_init_data = u_clamped;   // X1 = u
            3'd1:    rf_init_data = 255'd1;      // X2 = 1
            3'd2:    rf_init_data = 255'd0;      // Z2 = 0
            3'd3:    rf_init_data = u_clamped;   // X3 = u
            3'd4:    rf_init_data = 255'd1;      // Z3 = 1
            default: rf_init_data = 255'd0;      // covers 3'd5, 3'd6 (and unused 3'd7)
        endcase
    end

    // -------------------------------------------------------------------------
    // 3. Instruction ROM & decode
    // -------------------------------------------------------------------------
    reg  [5:0]  pc;
    wire [14:0] inst;
    ladder_rom u_rom (.addr(pc), .instruction(inst));

    wire [2:0] op_code   = inst[14:12];
    wire [2:0] log_dest  = inst[11: 9];
    wire [2:0] log_srcA  = inst[ 8: 6];
    wire [2:0] log_srcB  = inst[ 5: 3];
    wire [2:0] rom_sq_id = inst[ 2: 0];

    // SQRN loop-count decode
    reg [7:0] loop_count_target;
    always @(*) begin
        case (rom_sq_id)
            3'd0: loop_count_target = 8'd1;
            3'd1: loop_count_target = 8'd5;
            3'd2: loop_count_target = 8'd10;
            3'd3: loop_count_target = 8'd20;
            3'd4: loop_count_target = 8'd50;
            3'd5: loop_count_target = 8'd100;
            default: loop_count_target = 8'd1;
        endcase
    end

    // -------------------------------------------------------------------------
    // 4. Register-pointer swap (Montgomery ladder CSWAP)
    // -------------------------------------------------------------------------
    reg  swap_state;
    wire [2:0] phys_dest, phys_srcA, phys_srcB;

    wire [2:0] swd = (log_dest==3'd1||log_dest==3'd3) ? 3'd2 :
                     (log_dest==3'd2||log_dest==3'd4) ? 3'd6 : 3'd0;
    wire [2:0] swa = (log_srcA==3'd1||log_srcA==3'd3) ? 3'd2 :
                     (log_srcA==3'd2||log_srcA==3'd4) ? 3'd6 : 3'd0;
    wire [2:0] swb = (log_srcB==3'd1||log_srcB==3'd3) ? 3'd2 :
                     (log_srcB==3'd2||log_srcB==3'd4) ? 3'd6 : 3'd0;

    assign phys_dest = swap_state ? (log_dest ^ swd) : log_dest;
    assign phys_srcA = swap_state ? (log_srcA ^ swa) : log_srcA;
    assign phys_srcB = swap_state ? (log_srcB ^ swb) : log_srcB;

    // -------------------------------------------------------------------------
    // 5. Operand mux
    // -------------------------------------------------------------------------
    reg  use_dest_reg;  // 1 → read from phys_dest (SQRN auto-restart)

    wire [2:0]   addr_a     = use_dest_reg ? phys_dest : phys_srcA;
    wire [2:0]   addr_b_safe = (phys_srcB == 3'd7) ? 3'd0 : phys_srcB;
    wire [254:0] rf_val_a   = rf[addr_a];
    wire [254:0] rf_val_b   = rf[addr_b_safe];

    reg [254:0] op_a, op_b;
    always @(*) op_a = rf_val_a;
    always @(*) begin
        if      (op_code == 3'd5)   op_b = A24;       // CONST: multiply by a24
        else if (phys_srcB == 3'd7) op_b = 255'd0;    // virtual ZERO register
        else                        op_b = rf_val_b;
    end

    // iB for the arith unit:
    //   SQRN (squaring): use op_a as B  →  A^2
    //   MUL/CONST:       use op_b as B
    //   ADD/SUB:         use op_b as B  (is_squaring=0 so same formula)
    wire is_squaring = (op_code == 3'd3);
    wire [254:0] arith_b = is_squaring ? op_a : op_b;

    // -------------------------------------------------------------------------
    // 6. Unified modular arithmetic unit + LUTRAM write port
    //
    // Input-register stage: op_a_r / arith_b_r / arith_mode_r are captured
    // one cycle before arith_en fires.  This breaks the critical path
    //   pc_reg → ROM → swap-logic → LUTRAM addr → RAMD32 → DSP A
    // into two register-to-register hops, each ≪ 10 ns.
    //
    // arith_capture (combinatorial) fires when we want to sample the operands.
    // arith_start_r (registered) = arith_capture delayed 1 cycle → drives arith_en.
    // sqrn_restart_cap replaces arith_restart: fires 1 cycle after arith_valid
    // for SQRN loop, giving time for the LUTRAM to reflect the just-written result.
    // -------------------------------------------------------------------------
    localparam S_IDLE=0, S_INIT=1, S_FETCH=2, S_WAIT_ARITH=3,
               S_NEXT_BIT=4, S_DONE=5;
    reg [2:0] state;
    reg sqrn_restart_cap;   // triggers capture + re-start for SQRN loop

    wire [1:0] arith_mode_comb = (op_code == 3'd0) ? 2'b01 :   // ADD
                                  (op_code == 3'd1) ? 2'b10 :   // SUB
                                                      2'b00;    // MUL (default)

    wire arith_capture = (state == S_FETCH && (op_code == 3'd0 || op_code == 3'd1 ||
                          op_code == 3'd2 || op_code == 3'd3 || op_code == 3'd5)) ||
                         sqrn_restart_cap;

    reg [254:0] op_a_r, arith_b_r;
    reg [1:0]   arith_mode_r;
    reg         arith_start_r;

    always @(posedge clk) begin
        if (rst) begin
            arith_start_r <= 0;
            op_a_r        <= 255'b0;
            arith_b_r     <= 255'b0;
            arith_mode_r  <= 2'b00;
        end else begin
            arith_start_r <= arith_capture;
            if (arith_capture) begin
                op_a_r       <= op_a;
                arith_b_r    <= arith_b;
                arith_mode_r <= arith_mode_comb;
            end
        end
    end

    wire arith_en = arith_start_r;

    wire       arith_ready, arith_valid;
    wire [254:0] arith_out;

    unified_modular_arith u_arith (
        .iClk   (clk),
        .iRstn  (~rst),
        .iEn    (arith_en),
        .iMode  (arith_mode_r),
        .iA     (op_a_r),
        .iB     (arith_b_r),
        .oReady (arith_ready),
        .oValid (arith_valid),
        .oP     (arith_out)
    );

    wire        rf_wr_en   = (state == S_INIT) ||
                             (state == S_WAIT_ARITH && arith_valid);
    wire [2:0]  rf_wr_addr = (state == S_INIT) ? init_cnt : phys_dest;
    wire [254:0] rf_wr_data = (state == S_INIT) ? rf_init_data : arith_out;

    always @(posedge clk) begin
        if (rf_wr_en) rf[rf_wr_addr] <= rf_wr_data;
    end

    // -------------------------------------------------------------------------
    // 7. Main FSM
    // -------------------------------------------------------------------------
    reg [7:0] bit_idx;
    reg       prev_bit;
    reg [7:0] sqr_cnt;

    always @(posedge clk) begin
        if (rst) begin
            state             <= S_IDLE;
            pc                <= 0;
            done              <= 0;
            sqrn_restart_cap  <= 0;
            swap_state        <= 0;
            use_dest_reg      <= 0;
            bit_idx           <= 0;
            prev_bit          <= 0;
            sqr_cnt           <= 0;
            init_cnt          <= 0;
        end else begin
            case (state)

                // ---------------------------------------------------------
                S_IDLE: if (start) begin
                    state    <= S_INIT;
                    init_cnt <= 0;
                    done     <= 0;
                end

                // ---------------------------------------------------------
                // S_INIT: LUTRAM write handled externally (rf_wr_en/addr/data).
                // 7 cycles total (init_cnt 0..6), then → S_FETCH.
                S_INIT: begin
                    init_cnt <= init_cnt + 1;
                    if (init_cnt == 3'd6) begin
                        bit_idx    <= 254;
                        prev_bit   <= 0;
                        swap_state <= 0;
                        pc         <= 0;
                        state      <= S_FETCH;
                    end
                end

                // ---------------------------------------------------------
                S_FETCH: begin
                    use_dest_reg <= 0;
                    case (op_code)
                        3'd0: begin // ADD
                            state      <= S_WAIT_ARITH;
                        end
                        3'd1: begin // SUB
                            state      <= S_WAIT_ARITH;
                        end
                        3'd2, 3'd5: begin // MUL, CONST(×A24)
                            state      <= S_WAIT_ARITH;
                        end
                        3'd3: begin // SQRN
                            sqr_cnt    <= loop_count_target;
                            state      <= S_WAIT_ARITH;
                        end
                        3'd4: begin // CSWAP
                            if ((clamped_scalar[bit_idx] ^ prev_bit) == 1'b1)
                                swap_state <= ~swap_state;
                            prev_bit <= clamped_scalar[bit_idx];
                            pc <= pc + 1;
                            // stay in S_FETCH
                        end
                        3'd7: begin // EXIT
                            state <= (pc >= 6'd22) ? S_DONE : S_NEXT_BIT;
                        end
                        default: pc <= pc + 1;
                    endcase
                end

                // ---------------------------------------------------------
                S_WAIT_ARITH: begin
                    sqrn_restart_cap <= 0;  // clear 1-cycle capture trigger

                    if (arith_valid) begin
                        // RF write handled by rf_wr_en/rf_wr_addr/rf_wr_data block above

                        if (op_code == 3'd3) begin // SQRN
                            if (sqr_cnt == 1) begin
                                pc           <= pc + 1;
                                use_dest_reg <= 0;
                                state        <= S_FETCH;
                            end else begin
                                // sqrn_restart_cap fires this cycle → arith_capture
                                // fires next cycle (capturing the newly-written result)
                                // → arith_start_r fires the cycle after that.
                                sqr_cnt          <= sqr_cnt - 1;
                                use_dest_reg     <= 1;
                                sqrn_restart_cap <= 1;
                            end
                        end else begin
                            pc    <= pc + 1;
                            state <= S_FETCH;
                        end
                    end
                end

                // ---------------------------------------------------------
                S_NEXT_BIT: begin
                    if (bit_idx == 0) begin
                        pc    <= 22;     // jump to inversion chain
                        state <= S_FETCH;
                    end else begin
                        bit_idx <= bit_idx - 1;
                        pc      <= 0;
                        state   <= S_FETCH;
                    end
                end

                // ---------------------------------------------------------
                S_DONE: begin
                    done  <= 1;
                    state <= S_IDLE;
                end

            endcase
        end
    end

    // -------------------------------------------------------------------------
    // 8. Output (byte-reverse back to RFC format)
    // -------------------------------------------------------------------------
    wire [2:0]   final_x2  = swap_state ? 3'd3 : 3'd1;
    wire [254:0] result_reg = rf[final_x2];
    wire [255:0] result_le  = {1'b0, result_reg};

    generate
        for (i = 0; i < 32; i = i + 1) begin : byte_rev_out
            assign res_out[8*i +: 8] = result_le[8*(31-i) +: 8];
        end
    endgenerate

endmodule

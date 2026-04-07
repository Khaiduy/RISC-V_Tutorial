`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// AES-128 Encrypt-Only Core — 4-S-Box Column-Serial Architecture
//
// Processes one column per sub-cycle using 4 shared S-box instances (reduced
// from 20 in the parallel version). ShiftRows is folded into the S-box input
// selection, so each sub-cycle produces one post-ShiftRows column directly.
//
// Architecture rationale (acceleration-focused):
//   X25519 scalar multiplication dominates EDHOC at ~80,000 cycles per call
//   (3 calls = 240,000 cycles). AES-CCM processes ~10-15 blocks per handshake,
//   contributing <1% of total execution time. Using 20 S-boxes for 11-cycle
//   AES wastes ~130 LUTs for a negligible 0.02% improvement in total handshake
//   time. This 4-S-box design saves ~130 LUTs (16 fewer S-box instances) while
//   only increasing AES latency by ~4.7x — invisible at protocol level.
//
// Timing: 52 cycles per block (1 init + 10 rounds × 5 sub-cycles + 1 done)
//   Sub-cycle 0: Key expansion (4 S-boxes compute SubWord for next round key)
//   Sub-cycle 1-4: SubBytes+ShiftRows for columns 0-3 (4 S-boxes per column)
//                  MixColumns + AddRoundKey applied per-column (combinational)
//
// Interface: identical to the 11-cycle parallel version (drop-in replacement)
//   start    : pulse high for 1 cycle to begin encryption
//   key_in   : 128-bit key (latched on start)
//   data_in  : 128-bit plaintext (latched on start)
//   data_out : 128-bit ciphertext (valid when done=1)
//   done     : high for 1 cycle when result ready
//   busy     : high while processing
//////////////////////////////////////////////////////////////////////////////////

module aes128_core (
    input  wire         clk,
    input  wire         rst,
    input  wire         start,
    input  wire [127:0] key_in,
    input  wire [127:0] data_in,
    output reg  [127:0] data_out,
    output reg          done,
    output wire         busy
);

    // ========================================================================
    // FSM phases (3-bit encoding for 5 active phases + idle)
    // ========================================================================
    localparam [2:0] PH_IDLE    = 3'd0;
    localparam [2:0] PH_KEY_EXP = 3'd1;  // Key expansion using S-boxes
    localparam [2:0] PH_SUB0    = 3'd2;  // SubBytes+ShiftRows column 0
    localparam [2:0] PH_SUB1    = 3'd3;  // SubBytes+ShiftRows column 1
    localparam [2:0] PH_SUB2    = 3'd4;  // SubBytes+ShiftRows column 2
    localparam [2:0] PH_SUB3    = 3'd5;  // SubBytes+ShiftRows column 3

    // ========================================================================
    // State registers
    // ========================================================================
    reg [2:0]   phase;
    reg [3:0]   round;          // Current round (1-10)
    reg [127:0] state_reg;      // AES state matrix (column-major)
    reg [127:0] round_key;      // Current round key
    reg [95:0]  sb_result;      // Accumulates columns 0-2 (column 3 → direct)
    reg [7:0]   rcon;           // Round constant (GF(2^8) doubling)
    reg         running;

    assign busy = running;

    // ========================================================================
    // 4 shared S-Box instances (time-multiplexed: key expansion OR SubBytes)
    // ========================================================================
    wire [7:0] sb_out [0:3];
    reg  [7:0] sb_in  [0:3];

    // Explicit instantiation (avoids Vivado Synth 8-196 with unpacked
    // array genvar indexing in generate blocks)
    aes_sbox u_sbox_0 (.in(sb_in[0]), .out(sb_out[0]));
    aes_sbox u_sbox_1 (.in(sb_in[1]), .out(sb_out[1]));
    aes_sbox u_sbox_2 (.in(sb_in[2]), .out(sb_out[2]));
    aes_sbox u_sbox_3 (.in(sb_in[3]), .out(sb_out[3]));

    // ========================================================================
    // State byte extraction (column-major layout)
    // ========================================================================
    // Column 0: state_reg[127:96] = {s00, s10, s20, s30}
    // Column 1: state_reg[95:64]  = {s01, s11, s21, s31}
    // Column 2: state_reg[63:32]  = {s02, s12, s22, s32}
    // Column 3: state_reg[31:0]   = {s03, s13, s23, s33}
    wire [7:0] s00 = state_reg[127:120], s10 = state_reg[119:112];
    wire [7:0] s20 = state_reg[111:104], s30 = state_reg[103:96];
    wire [7:0] s01 = state_reg[95:88],   s11 = state_reg[87:80];
    wire [7:0] s21 = state_reg[79:72],   s31 = state_reg[71:64];
    wire [7:0] s02 = state_reg[63:56],   s12 = state_reg[55:48];
    wire [7:0] s22 = state_reg[47:40],   s32 = state_reg[39:32];
    wire [7:0] s03 = state_reg[31:24],   s13 = state_reg[23:16];
    wire [7:0] s23 = state_reg[15:8],    s33 = state_reg[7:0];

    // ========================================================================
    // S-Box input muxing
    // ========================================================================
    // KEY_EXP: RotWord of last key column = {k13, k23, k33, k03}
    // SUB0-3:  ShiftRows-reordered bytes for each output column
    //
    // ShiftRows mapping:
    //   Post-shift col 0 = {s00, s11, s22, s33}  (row shifts: 0,1,2,3)
    //   Post-shift col 1 = {s01, s12, s23, s30}
    //   Post-shift col 2 = {s02, s13, s20, s31}
    //   Post-shift col 3 = {s03, s10, s21, s32}
    always @(*) begin
        case (phase)
            PH_KEY_EXP: begin
                sb_in[0] = round_key[23:16];   // k13 (RotWord byte 0)
                sb_in[1] = round_key[15:8];    // k23
                sb_in[2] = round_key[7:0];     // k33
                sb_in[3] = round_key[31:24];   // k03
            end
            PH_SUB0: begin  // Column 0 after ShiftRows
                sb_in[0] = s00; sb_in[1] = s11;
                sb_in[2] = s22; sb_in[3] = s33;
            end
            PH_SUB1: begin  // Column 1 after ShiftRows
                sb_in[0] = s01; sb_in[1] = s12;
                sb_in[2] = s23; sb_in[3] = s30;
            end
            PH_SUB2: begin  // Column 2 after ShiftRows
                sb_in[0] = s02; sb_in[1] = s13;
                sb_in[2] = s20; sb_in[3] = s31;
            end
            PH_SUB3: begin  // Column 3 after ShiftRows
                sb_in[0] = s03; sb_in[1] = s10;
                sb_in[2] = s21; sb_in[3] = s32;
            end
            default: begin
                sb_in[0] = 8'd0; sb_in[1] = 8'd0;
                sb_in[2] = 8'd0; sb_in[3] = 8'd0;
            end
        endcase
    end

    // ========================================================================
    // GF(2^8) multiply by 2 (xtime) for MixColumns
    // ========================================================================
    function [7:0] xtime;
        input [7:0] b;
        begin
            xtime = {b[6:0], 1'b0} ^ (8'h1b & {8{b[7]}});
        end
    endfunction

    // ========================================================================
    // MixColumns on current S-box output column (combinational)
    // Only instantiated once — time-multiplexed across 4 columns
    // ========================================================================
    wire [7:0] a = sb_out[0], b = sb_out[1], c = sb_out[2], d = sb_out[3];

    wire [7:0] mc0 = xtime(a) ^ (xtime(b) ^ b) ^ c ^ d;
    wire [7:0] mc1 = a ^ xtime(b) ^ (xtime(c) ^ c) ^ d;
    wire [7:0] mc2 = a ^ b ^ xtime(c) ^ (xtime(d) ^ d);
    wire [7:0] mc3 = (xtime(a) ^ a) ^ b ^ c ^ xtime(d);

    // Select MixColumns or bypass (last round skips MixColumns)
    wire last_round = (round == 4'd10);
    wire [31:0] round_col = last_round ? {a, b, c, d} : {mc0, mc1, mc2, mc3};

    // AddRoundKey: XOR with the corresponding round key column
    wire [31:0] rk_col = (phase == PH_SUB0) ? round_key[127:96] :
                          (phase == PH_SUB1) ? round_key[95:64]  :
                          (phase == PH_SUB2) ? round_key[63:32]  :
                                               round_key[31:0];

    wire [31:0] col_result = round_col ^ rk_col;

    // ========================================================================
    // Key expansion (computed during PH_KEY_EXP)
    // ========================================================================
    wire [31:0] sub_word   = {sb_out[0] ^ rcon, sb_out[1], sb_out[2], sb_out[3]};
    wire [31:0] new_k0     = round_key[127:96] ^ sub_word;
    wire [31:0] new_k1     = round_key[95:64]  ^ new_k0;
    wire [31:0] new_k2     = round_key[63:32]  ^ new_k1;
    wire [31:0] new_k3     = round_key[31:0]   ^ new_k2;

    // ========================================================================
    // Main FSM
    // ========================================================================
    always @(posedge clk) begin
        if (rst) begin
            phase     <= PH_IDLE;
            round     <= 4'd0;
            state_reg <= 128'd0;
            round_key <= 128'd0;
            sb_result <= 96'd0;
            data_out  <= 128'd0;
            done      <= 1'b0;
            running   <= 1'b0;
            rcon      <= 8'h00;
        end else begin
            done <= 1'b0;

            case (phase)
                PH_IDLE: begin
                    if (start) begin
                        // Initial AddRoundKey (round 0)
                        state_reg <= data_in ^ key_in;
                        round_key <= key_in;
                        round     <= 4'd1;
                        rcon      <= 8'h01;
                        running   <= 1'b1;
                        phase     <= PH_KEY_EXP;
                    end
                end

                PH_KEY_EXP: begin
                    // S-boxes have computed SubWord(RotWord(last_key_col))
                    // Latch expanded round key for this round
                    round_key <= {new_k0, new_k1, new_k2, new_k3};
                    // Advance Rcon: multiply by 2 in GF(2^8)
                    rcon      <= {rcon[6:0], 1'b0} ^ (rcon[7] ? 8'h1b : 8'h00);
                    phase     <= PH_SUB0;
                end

                PH_SUB0: begin
                    // Column 0: SubBytes+ShiftRows+MixColumns+AddRoundKey
                    sb_result[95:64] <= col_result;
                    phase <= PH_SUB1;
                end

                PH_SUB1: begin
                    // Column 1
                    sb_result[63:32] <= col_result;
                    phase <= PH_SUB2;
                end

                PH_SUB2: begin
                    // Column 2
                    sb_result[31:0] <= col_result;
                    phase <= PH_SUB3;
                end

                PH_SUB3: begin
                    // Column 3: write full state from accumulated + current
                    state_reg <= {sb_result[95:64], sb_result[63:32],
                                  sb_result[31:0], col_result};

                    if (last_round) begin
                        // AES complete
                        data_out <= {sb_result[95:64], sb_result[63:32],
                                     sb_result[31:0], col_result};
                        done     <= 1'b1;
                        running  <= 1'b0;
                        phase    <= PH_IDLE;
                    end else begin
                        round <= round + 4'd1;
                        phase <= PH_KEY_EXP;
                    end
                end

                default: phase <= PH_IDLE;
            endcase
        end
    end

endmodule

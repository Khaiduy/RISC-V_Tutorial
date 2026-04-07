`timescale 1ns / 1ps
//-----------------------------------------------------------------------------
// unified_modular_arith.v — Unified Modular Arithmetic for X25519
//
// Single port interface with mode selector:
//   iMode = 2'b00 → Modular multiply (27-cycle latency; iA/iB must stay stable until oValid)
//   iMode = 2'b01 → Modular add      ( 2-cycle latency)
//   iMode = 2'b10 → Modular subtract ( 2-cycle latency)
//
// BREG=1 optimization: a_limb stored in DSP B pipeline register (eliminates buf_a_wide).
// Counter optimization: b_limb_ctr indexes iB directly (eliminates buf_b_wide).
// Interface contract: iA and iB must remain stable from iEn until oValid.
//
// All operands and results are 255-bit GF(2^255-19) field elements.
// 15 DSP48E1 slices handle both multiply and add/sub operations.
//-----------------------------------------------------------------------------

module unified_modular_arith (
    input           iClk,
    input           iRstn,
    input           iEn,            // 1-cycle pulse: start operation
    input  [1:0]    iMode,          // 00=MUL, 01=ADD, 10=SUB
    input  [254:0]  iA,
    input  [254:0]  iB,
    output          oReady,
    output          oValid,
    output [254:0]  oP
);

    // P = 2^255 - 19
    localparam [254:0] P25519 = 255'd57896044618658097711785492504343953926634992332820282019728792003956564819949;

    // =========================================================================
    // 1. Signal Declarations
    // =========================================================================

    // FSM shift registers
    reg [18:0]  fsm_shreg_stage1;   // 19-bit: bit[18:4]=15 MACs, [3]=b_load, [2]=PS1, [1]=PS2, [0]=shift
    reg [7:0]   fsm_shreg_stage2;
    reg [1:0]   fsm_shreg_addsub;

    wire [14:0] fsm_shreg_mul;
    wire        flag_fsm_shreg_mul;
    wire        flag_b_load;        // extra cycle to load BREG with P(15)[33:17]
    wire        flag_partial_sum_1;
    wire        flag_partial_sum_2;
    wire        flag_shreg_shift_p;
    wire        flag_as_mac;
    wire        flag_as_valid;

    // Mode decode
    wire        mul_en    = iEn & (iMode == 2'b00);
    wire        addsub_en = iEn & (iMode != 2'b00);

    // Registered mode (latched at iEn)
    reg  [1:0]  iMode_r;
    wire        iSub_r = iMode_r[1];

    // b-limb counter (replaces buf_b_wide shift register)
    reg  [3:0]   b_limb_ctr;
    wire [288:0] iB_safe;       // iB zero-padded to 289 bits (34 extra zeros) for safe look-ahead

    // Data buffers (reduced: only mac_wrap and mac_accum remain)
    reg [14:0]  mac_wrap;
    reg [21:0]  mac_accum[0:14];

    // MAC interconnects
    wire [42:0] out_mac [0:14];
    reg  [16:0] iB_mac;
    wire [42:0] iC_mac  [0:14];
    wire [21:0] iB_mac_array [0:14];
    reg  [21:0] b_eff_r;        // registered ×19 of look-ahead b-limb
    wire        mac_en;
    wire        mac_sum2;

    // DSP B port mux (per DSP) and combined CEB
    wire [16:0] iA_dsp_b [0:14];
    wire        dsp_ceb;

    // Carry chain
    wire [2:0]  carry_in [4:15];
    wire [1:0]  base     [4:14];
    wire [2:0]  thresh   [4:14];
    reg  [2:0]  thresh_reg [4:14];
    reg  [1:0]  base_reg   [4:14];

    // Multiply output
    wire [254:0] p_temp;
    wire [255:0] p_plus_19;
    wire         need_reduction;
    wire [254:0] final_result;

    // Addsub result
    wire [14:0]  as_carry;
    wire [254:0] as_data_255;
    wire [254:0] as_sparse_255;
    wire [255:0] raw_256;
    wire [255:0] adj_256;
    wire         select;
    wire [254:0] as_result;

    // b_eff for addsub (18-bit; bit[17] handles SUB carry)
    wire [17:0]  b_eff_as_wide [0:14];

    // OPMODE and CARRYIN for mac17_dsp instances
    wire [6:0]   dsp_opmode [0:14];
    wire         dsp_carryin [0:14];

    integer r;

    // =========================================================================
    // 2. Control Logic & FSM
    // =========================================================================

    assign oReady = !(|fsm_shreg_stage1) && !(|fsm_shreg_stage2) && !(|fsm_shreg_addsub);

    assign fsm_shreg_mul      = fsm_shreg_stage1[18:4];
    assign flag_fsm_shreg_mul = |fsm_shreg_mul;
    assign flag_b_load        = fsm_shreg_stage1[3];
    assign flag_partial_sum_1 = fsm_shreg_stage1[2];
    assign flag_partial_sum_2 = fsm_shreg_stage1[1];
    assign flag_shreg_shift_p = fsm_shreg_stage1[0];
    assign flag_as_mac        = fsm_shreg_addsub[1];
    assign flag_as_valid      = fsm_shreg_addsub[0];

    // Stage 1: multiply (use mul_en, not iEn)
    always @(posedge iClk) begin
        if (~iRstn)      fsm_shreg_stage1 <= 19'h0;
        else if (mul_en) fsm_shreg_stage1 <= {1'b1, 18'b0};
        else             fsm_shreg_stage1 <= {1'b0, fsm_shreg_stage1[18:1]};
    end

    // Stage 2: reduction
    always @(posedge iClk) begin
        if (~iRstn)                  fsm_shreg_stage2 <= 8'b0;
        else if (flag_shreg_shift_p) fsm_shreg_stage2 <= {1'b1, 7'b0};
        else                         fsm_shreg_stage2 <= {1'b0, fsm_shreg_stage2[7:1]};
    end

    // Addsub: 2-bit pipeline
    always @(posedge iClk) begin
        if (~iRstn)         fsm_shreg_addsub <= 2'b0;
        else if (addsub_en) fsm_shreg_addsub <= 2'b10;
        else                fsm_shreg_addsub <= {1'b0, fsm_shreg_addsub[1]};
    end

    // Latch mode on iEn
    always @(posedge iClk) begin
        if (~iRstn)   iMode_r <= 2'b0;
        else if (iEn) iMode_r <= iMode;
    end

    // =========================================================================
    // 3. Datapath Buffers
    // =========================================================================

    // iB zero-padded to 289 bits: safe look-ahead when b_limb_ctr=14 (reads [271:255]=0) or 15 (reads [288:272]=0)
    assign iB_safe = {34'b0, iB};

    // b_limb_ctr: tracks current b-limb index (replaces buf_b_wide shift)
    always @(posedge iClk) begin
        if (~iRstn)              b_limb_ctr <= 4'b0;
        else if (mul_en)         b_limb_ctr <= 4'b0;
        else if (flag_fsm_shreg_mul) b_limb_ctr <= b_limb_ctr + 1;
    end

    // mac_wrap control (last MAC cycle now at stage1[4] in 19-bit FSM)
    always @(posedge iClk) begin
        if (!iRstn)                  mac_wrap <= 15'h0;
        else if (flag_fsm_shreg_mul) mac_wrap <= fsm_shreg_stage1[4] ? {1'b0, 14'd1} : {1'b1, mac_wrap[14:1]};
        else if (flag_partial_sum_1) mac_wrap <= {1'b1, 14'd1};
        else if (!flag_b_load)       mac_wrap <= 15'h0;  // hold during flag_b_load to preserve 15'h0001 for PS1
    end

    // =========================================================================
    // 4. Combinational Carry Chain
    // =========================================================================

    generate
        genvar j;
        for (j = 4; j < 15; j = j + 1) begin : gen_thresh_base
            assign base[j]  = mac_accum[j][18:17];
            wire [16:0] low_bits      = mac_accum[j][16:0];
            wire        near_overflow = (low_bits >= 17'h1FFFB);
            wire [17:0] diff          = 18'h20000 - {1'b0, low_bits};
            assign thresh[j] = near_overflow ? diff[2:0] : 3'd5;
        end
    endgenerate

    assign carry_in[4] = {1'b0, mac_accum[3][18:17]};

    generate
        genvar jj;
        for (jj = 4; jj < 15; jj = jj + 1) begin : carry_chain
            wire delta = (carry_in[jj] >= thresh_reg[jj]);
            assign carry_in[jj+1] = {1'b0, base_reg[jj]} + delta;
        end
    endgenerate

    // =========================================================================
    // 5. Main Accumulator Logic
    // =========================================================================

    wire [21:0] accum1_after_carry0 = mac_accum[1] + {17'b0, mac_accum[0][21:17]};
    wire [21:0] accum0_after_19     = {5'b0, mac_accum[0][16:0]} +
                                      {mac_accum[14][21:17], 1'b0} +
                                      {mac_accum[14][21:17], 4'b0000} +
                                      {17'b0, mac_accum[14][21:17]};

    always @(posedge iClk) begin
        if (!iRstn) begin
            for (r = 0; r < 15; r = r + 1) mac_accum[r] <= 22'b0;
            for (r = 4; r < 15; r = r + 1) begin
                thresh_reg[r] <= 3'd5;
                base_reg[r]   <= 2'd0;
            end
        end
        else if (flag_shreg_shift_p) begin
            mac_accum[0]  <= out_mac[14][21:0];
            mac_accum[1]  <= out_mac[0][21:0];
            mac_accum[2]  <= out_mac[1][21:0];
            mac_accum[3]  <= out_mac[2][21:0];
            mac_accum[4]  <= out_mac[3][21:0];
            mac_accum[5]  <= out_mac[4][21:0];
            mac_accum[6]  <= out_mac[5][21:0];
            mac_accum[7]  <= out_mac[6][21:0];
            mac_accum[8]  <= out_mac[7][21:0];
            mac_accum[9]  <= out_mac[8][21:0];
            mac_accum[10] <= out_mac[9][21:0];
            mac_accum[11] <= out_mac[10][21:0];
            mac_accum[12] <= out_mac[11][21:0];
            mac_accum[13] <= out_mac[12][21:0];
            mac_accum[14] <= out_mac[13][21:0];
        end
        else if (fsm_shreg_stage2[7]) begin
            mac_accum[0] <= {5'b0, mac_accum[0][16:0]};
            mac_accum[1] <= {5'b0, accum1_after_carry0[16:0]};
            mac_accum[2] <= mac_accum[2] + {17'b0, accum1_after_carry0[21:17]};
        end
        else if (fsm_shreg_stage2[6]) begin
            mac_accum[3] <= mac_accum[3] + {17'b0, mac_accum[2][21:17]};
            mac_accum[2] <= {5'b0, mac_accum[2][16:0]};
            thresh_reg[4]  <= thresh[4];  base_reg[4]  <= base[4];
            thresh_reg[5]  <= thresh[5];  base_reg[5]  <= base[5];
            thresh_reg[6]  <= thresh[6];  base_reg[6]  <= base[6];
            thresh_reg[7]  <= thresh[7];  base_reg[7]  <= base[7];
            thresh_reg[8]  <= thresh[8];  base_reg[8]  <= base[8];
            thresh_reg[9]  <= thresh[9];  base_reg[9]  <= base[9];
            thresh_reg[10] <= thresh[10]; base_reg[10] <= base[10];
            thresh_reg[11] <= thresh[11]; base_reg[11] <= base[11];
            thresh_reg[12] <= thresh[12]; base_reg[12] <= base[12];
            thresh_reg[13] <= thresh[13]; base_reg[13] <= base[13];
            thresh_reg[14] <= thresh[14]; base_reg[14] <= base[14];
        end
        else if (fsm_shreg_stage2[5]) begin
            mac_accum[3]  <= {5'b0, mac_accum[3][16:0]};
            mac_accum[4]  <= {5'b0, (mac_accum[4][16:0]  + {14'b0, carry_in[4]})};
            mac_accum[5]  <= {5'b0, (mac_accum[5][16:0]  + {14'b0, carry_in[5]})};
            mac_accum[6]  <= {5'b0, (mac_accum[6][16:0]  + {14'b0, carry_in[6]})};
            mac_accum[7]  <= {5'b0, (mac_accum[7][16:0]  + {14'b0, carry_in[7]})};
            mac_accum[8]  <= {5'b0, (mac_accum[8][16:0]  + {14'b0, carry_in[8]})};
            mac_accum[9]  <= {5'b0, (mac_accum[9][16:0]  + {14'b0, carry_in[9]})};
            mac_accum[10] <= {5'b0, (mac_accum[10][16:0] + {14'b0, carry_in[10]})};
            mac_accum[11] <= {5'b0, (mac_accum[11][16:0] + {14'b0, carry_in[11]})};
            mac_accum[12] <= {5'b0, (mac_accum[12][16:0] + {14'b0, carry_in[12]})};
            mac_accum[13] <= {5'b0, (mac_accum[13][16:0] + {14'b0, carry_in[13]})};
            mac_accum[14] <= mac_accum[14] + {19'b0, carry_in[14]};
        end
        else if (fsm_shreg_stage2[4]) begin
            mac_accum[14] <= {5'b0, mac_accum[14][16:0]};
            mac_accum[0]  <= {5'b0, accum0_after_19[16:0]};
            mac_accum[1]  <= mac_accum[1] + {17'b0, accum0_after_19[21:17]};
        end
        else if (fsm_shreg_stage2[3]) begin
            mac_accum[2] <= mac_accum[2] + {17'b0, mac_accum[1][21:17]};
            mac_accum[1] <= {5'b0, mac_accum[1][16:0]};
        end
        else if (fsm_shreg_stage2[2]) begin
            mac_accum[3] <= mac_accum[3] + {17'b0, mac_accum[2][21:17]};
            mac_accum[2] <= {5'b0, mac_accum[2][16:0]};
            thresh_reg[4]  <= thresh[4];  base_reg[4]  <= base[4];
            thresh_reg[5]  <= thresh[5];  base_reg[5]  <= base[5];
            thresh_reg[6]  <= thresh[6];  base_reg[6]  <= base[6];
            thresh_reg[7]  <= thresh[7];  base_reg[7]  <= base[7];
            thresh_reg[8]  <= thresh[8];  base_reg[8]  <= base[8];
            thresh_reg[9]  <= thresh[9];  base_reg[9]  <= base[9];
            thresh_reg[10] <= thresh[10]; base_reg[10] <= base[10];
            thresh_reg[11] <= thresh[11]; base_reg[11] <= base[11];
            thresh_reg[12] <= thresh[12]; base_reg[12] <= base[12];
            thresh_reg[13] <= thresh[13]; base_reg[13] <= base[13];
            thresh_reg[14] <= thresh[14]; base_reg[14] <= base[14];
        end
        else if (fsm_shreg_stage2[1]) begin
            mac_accum[3]  <= {5'b0, mac_accum[3][16:0]};
            mac_accum[4]  <= (mac_accum[4][16:0]  + {14'b0, carry_in[4]});
            mac_accum[5]  <= (mac_accum[5][16:0]  + {14'b0, carry_in[5]});
            mac_accum[6]  <= (mac_accum[6][16:0]  + {14'b0, carry_in[6]});
            mac_accum[7]  <= (mac_accum[7][16:0]  + {14'b0, carry_in[7]});
            mac_accum[8]  <= (mac_accum[8][16:0]  + {14'b0, carry_in[8]});
            mac_accum[9]  <= (mac_accum[9][16:0]  + {14'b0, carry_in[9]});
            mac_accum[10] <= (mac_accum[10][16:0] + {14'b0, carry_in[10]});
            mac_accum[11] <= (mac_accum[11][16:0] + {14'b0, carry_in[11]});
            mac_accum[12] <= (mac_accum[12][16:0] + {14'b0, carry_in[12]});
            mac_accum[13] <= (mac_accum[13][16:0] + {14'b0, carry_in[13]});
            mac_accum[14] <= mac_accum[14] + {17'b0, carry_in[14]};
        end
    end

    // =========================================================================
    // 6. MAC Inputs and Instantiation
    // =========================================================================

    // iB_mac: current b-limb indexed via counter (multiply) or 1 (reduction phases)
    always @(*) begin
        if (flag_fsm_shreg_mul) iB_mac = iB_safe[b_limb_ctr*17 +: 17];
        else                    iB_mac = 17'b1;
    end

    // b_eff_r: registered ×19 of look-ahead b-limb
    // Uses b_limb_ctr+1 (old pre-increment value) to look ahead one limb.
    // Hold 22'd19 through: last MAC cycle, flag_b_load, AND flag_partial_sum_1
    // (PS2 needs b_eff_r=19 for mac_wrap[0] and mac_wrap[14] to reduce upper-9-bit overflow)
    always @(posedge iClk) begin
        if (flag_b_load | flag_partial_sum_1 | (flag_fsm_shreg_mul & fsm_shreg_stage1[4]))
            b_eff_r <= 22'd19;
        else
            b_eff_r <= ({5'b0, iB_safe[(b_limb_ctr+1)*17 +: 17]} << 4)
                     + ({5'b0, iB_safe[(b_limb_ctr+1)*17 +: 17]} << 1)
                     +  {5'b0, iB_safe[(b_limb_ctr+1)*17 +: 17]};
    end

    assign mac_sum2 = flag_fsm_shreg_mul | flag_partial_sum_2;
    assign mac_en   = mac_sum2 | flag_partial_sum_1 | flag_as_mac;

    // DSP B port clock enable: load BREG at mul_en, addsub_en, flag_b_load, flag_partial_sum_1
    assign dsp_ceb = mul_en | addsub_en | flag_b_load | flag_partial_sum_1;

    // b_eff for addsub: 18-bit, read directly from iB (stable during addsub)
    generate
        genvar n;
        for (n = 0; n < 15; n = n + 1) begin : b_eff_gen
            assign b_eff_as_wide[n] = iSub_r
                ? {1'b0, ~iB[n*17 +: 17]}  // one's complement (DSP CARRYIN adds +1 for mm=0)
                : {1'b0,  iB[n*17 +: 17]};
        end
    endgenerate

    // Per-DSP B port input mux (for BREG loading)
    generate
        genvar bm;
        for (bm = 0; bm < 15; bm = bm + 1) begin : dsp_b_mux
            assign iA_dsp_b[bm] = flag_b_load       ? out_mac[bm][33:17]
                                 : flag_partial_sum_1 ? {8'b0, out_mac[bm][42:34]}
                                 :                      iA[bm*17 +: 17];
        end
    endgenerate

    // iC_mac: circular chain (multiply) or b_eff_as (addsub)
    generate
        genvar m;
        for (m = 0; m < 15; m = m + 1) begin : mac_c_assign
            wire [42:0] src_mac;
            if (m == 14) assign src_mac = out_mac[0];
            else         assign src_mac = out_mac[m+1];

            assign iC_mac[m][16:0]  = flag_as_mac ? b_eff_as_wide[m][16:0] : src_mac[16:0];
            assign iC_mac[m][17]    = flag_as_mac ? b_eff_as_wide[m][17]
                                                   : (mac_sum2 ? src_mac[17] : 1'b0);
            assign iC_mac[m][42:18] = flag_as_mac ? 25'b0
                                                   : (mac_sum2 ? src_mac[42:18] : 25'b0);
        end
    endgenerate

    // OPMODE: MUL/reduction = C+A*B, ADDSUB = C+{D,A} (bypass multiplier)
    // CARRYIN: only DSP[0] during SUB (two's complement +1)
    generate
        genvar mm;
        for (mm = 0; mm < 15; mm = mm + 1) begin : mac_ctrl
            // A port: b_eff for multiply, a_limb directly from iA for addsub
            assign iB_mac_array[mm] = flag_as_mac
                ? 22'b0                                          // addsub: A port=0; a_limb via BREG (loaded at addsub_en)
                : (mac_wrap[mm] ? b_eff_r : {5'b0, iB_mac});   // multiply: b_eff

            assign dsp_opmode[mm] = flag_as_mac ? 7'b0110011   // C + {D,A}
                                                 : 7'b0110101;  // C + A*B

            if (mm == 0)
                assign dsp_carryin[mm] = flag_as_mac & iSub_r; // SUB two's-complement +1
            else
                assign dsp_carryin[mm] = 1'b0;

            mac17_dsp mac_u (
                .iClk      (iClk),
                .iRstn     (iRstn),
                .iAccum_rst(mul_en),    // reset PREG only at multiply start
                .iEn       (mac_en),
                .iCEB      (dsp_ceb),   // BREG clock enable
                .iA        (iA_dsp_b[mm]),
                .iB        (iB_mac_array[mm]),
                .iC        (iC_mac[mm]),
                .iOpmode   (dsp_opmode[mm]),
                .iCarryIn  (dsp_carryin[mm]),
                .oS        (out_mac[mm])
            );
        end
    endgenerate

    // =========================================================================
    // 7. Addsub Result Assembly
    // =========================================================================

    assign as_carry = {out_mac[14][17], out_mac[13][17], out_mac[12][17],
                       out_mac[11][17], out_mac[10][17], out_mac[9][17],
                       out_mac[8][17],  out_mac[7][17],  out_mac[6][17],
                       out_mac[5][17],  out_mac[4][17],  out_mac[3][17],
                       out_mac[2][17],  out_mac[1][17],  out_mac[0][17]};

    assign as_data_255 = {out_mac[14][16:0], out_mac[13][16:0], out_mac[12][16:0],
                          out_mac[11][16:0], out_mac[10][16:0], out_mac[9][16:0],
                          out_mac[8][16:0],  out_mac[7][16:0],  out_mac[6][16:0],
                          out_mac[5][16:0],  out_mac[4][16:0],  out_mac[3][16:0],
                          out_mac[2][16:0],  out_mac[1][16:0],  out_mac[0][16:0]};

    assign as_sparse_255 = {
        16'b0, as_carry[13],
        16'b0, as_carry[12],
        16'b0, as_carry[11],
        16'b0, as_carry[10],
        16'b0, as_carry[9],
        16'b0, as_carry[8],
        16'b0, as_carry[7],
        16'b0, as_carry[6],
        16'b0, as_carry[5],
        16'b0, as_carry[4],
        16'b0, as_carry[3],
        16'b0, as_carry[2],
        16'b0, as_carry[1],
        16'b0, as_carry[0],
        17'b0
    };

    assign raw_256  = {as_carry[14], as_data_255} + {1'b0, as_sparse_255};
    assign adj_256  = raw_256 + (iSub_r ? {1'b0, P25519} : 256'd19);
    assign select   = iSub_r ? ~raw_256[255] : adj_256[255];
    assign as_result = select ? adj_256[254:0] : raw_256[254:0];

    // =========================================================================
    // 8. Multiply Final Output
    // =========================================================================

    assign p_temp = {mac_accum[14][16:0], mac_accum[13][16:0], mac_accum[12][16:0],
                     mac_accum[11][16:0], mac_accum[10][16:0], mac_accum[9][16:0],
                     mac_accum[8][16:0],  mac_accum[7][16:0],  mac_accum[6][16:0],
                     mac_accum[5][16:0],  mac_accum[4][16:0],  mac_accum[3][16:0],
                     mac_accum[2][16:0],  mac_accum[1][16:0],  mac_accum[0][16:0]};

    assign p_plus_19      = {1'b0, p_temp} + 5'd19;
    assign need_reduction = p_plus_19[255];
    assign final_result   = need_reduction ? p_plus_19[254:0] : p_temp;

    // =========================================================================
    // 9. Registered output stage
    //    Breaks the 255-bit carry chain (DSP PREG → p_plus_19 / raw_256 → RF)
    //    into two register-to-register hops, cutting the critical path.
    //    oValid fires 1 cycle after the internal result is ready.
    //    oReady is still FSM-based; it goes high on the same cycle as oValid
    //    (FSM bits clear the cycle after the last computation fires).
    // =========================================================================
    reg [254:0] oP_r;
    reg         oValid_r;

    always @(posedge iClk) begin
        if (~iRstn) begin
            oP_r     <= 255'b0;
            oValid_r <= 1'b0;
        end else begin
            oValid_r <= fsm_shreg_stage2[0] | fsm_shreg_addsub[0];
            if (fsm_shreg_stage2[0])
                oP_r <= final_result;
            else if (fsm_shreg_addsub[0])
                oP_r <= as_result;
        end
    end

    assign oP    = oP_r;
    assign oValid = oValid_r;

endmodule

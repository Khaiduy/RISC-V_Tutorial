`timescale 1ns / 1ps
//─────────────────────────────────────────────────────────────────────────────
// sym_controller.v — Symmetric-key orchestrator for EDHOC Method 3 / Suite 0
//
// Contains:
//   - sym_rf: 8-slot × 256-bit LUTRAM register file (distributed RAM)
//   - Word-select read mux for stream_formatter narrow RF port
//   - Write port for HMAC results and external X25519 results
//   - Microcode ROM: op_rom[0:31] maps op_sel → {key_rf, msg_rf, dst_rf,
//                    msg_seq, label, len_byte, do_xor, msg_bytes}
//   - FSM: shared HMAC call path (key + msg + latch + optional XOR)
//
// Adding a new opcode = one line in op_rom init + one localparam.
// The FSM itself never changes.
//─────────────────────────────────────────────────────────────────────────────
module sym_controller (
    input  wire         clk,
    input  wire         rst,

    // ═════ Control ═════
    input  wire         start,          // pulse to begin operation
    output reg          busy,
    output reg          done,

    // ═════ Operation select ═════
    // Which HMAC/SHA operation to perform (expanded in T3+)
    input  wire [4:0]   op_sel,         // operation selector

    // ═════ Stream formatter interface ═════
    // sym_controller drives stream_formatter; formatter reads RF via narrow port
    output reg  [7:0]   sf_seq_start,   // ROM sequence address
    output reg  [2:0]   sf_rf_src,      // RF slot for formatter to read
    output reg          sf_start,       // pulse to start formatter
    input  wire         sf_busy,
    input  wire         sf_done,
    // Narrow RF port — formatter requests, we respond combinatorially
    input  wire [2:0]   sf_rf_reg_id,   // which RF slot
    input  wire [2:0]   sf_rf_word_idx, // which 32-bit word (0-7)
    output wire [31:0]  sf_rf_data,     // combinatorial read result
    // Formatter output stream (directly wired to HMAC core)
    input  wire [31:0]  sf_fmt_data,
    input  wire         sf_fmt_valid,
    input  wire         sf_fmt_last,
    input  wire [1:0]   sf_fmt_bytes,
    input  wire         sf_dest_sel,    // 0=HMAC, 1=AES-CCM
    // Flow control: stall formatter during data phase when HMAC not ready
    output wire         sf_receiver_ready,
    // Scalar parameters driven to stream_formatter
    output reg  [7:0]   sf_label,
    output reg  [7:0]   sf_length_byte,
    input  wire [7:0]   sf_c_x,         // C_I or C_R — set by protocol coordinator
    input  wire         sf_cred_sel,    // 0=cred_own, 1=cred_peer — set by coordinator

    // ═════ HMAC core interface ═════
    output reg          hmac_start,
    output reg          hmac_mode,      // 0=SHA-256, 1=HMAC
    input  wire         hmac_ready,
    input  wire         hmac_done,
    input  wire         hmac_busy,
    // Key feed (from formatter via seq 0x40)
    output wire [31:0]  hmac_key_in,
    output wire         hmac_key_valid,
    output wire         hmac_key_last,
    input  wire         hmac_key_ready,
    // Data feed (from formatter via seq 0x30/0x50/etc.)
    output wire [31:0]  hmac_data_in,
    output wire         hmac_data_valid,
    output wire         hmac_data_last,
    input  wire         hmac_data_ready,
    // Length and result
    output reg  [63:0]  hmac_msg_len,   // total message length in bits
    input  wire [255:0] hmac_hash_out,
    input  wire         hmac_hash_valid,

    // ═════ External RF write port (X25519 results) ═════
    input  wire         ext_rf_wen,     // write enable
    input  wire [2:0]   ext_rf_waddr,   // slot address
    input  wire [255:0] ext_rf_wdata,   // 256-bit data

    // ═════ CIPHERTEXT_2 / plaintext_2 (T4: KS_2 XOR) ═════
    input  wire [87:0]  ciphertext_2,   // 11 bytes from message_2
    output reg  [87:0]  ks_2_stream,    // first 11 bytes of KS_2 keystream

    // ═════ AES-CCM interface ═════
    output reg          ccm_start,
    output wire         ccm_decrypt,     // from op_rom is_decrypt bit
    output wire [127:0] ccm_key,         // from RF[key_rf][255:128]
    output wire [103:0] ccm_nonce,       // from RF[dst_rf][255:152]
    output wire [4:0]   ccm_tag_len,     // hardcoded 8 (Suite 0)
    output wire [15:0]  ccm_aad_len,     // from label field
    output wire [15:0]  ccm_msg_len,     // from len_byte field
    output wire [31:0]  ccm_data_in,
    output wire         ccm_data_valid,
    output wire         ccm_data_last,
    output wire [1:0]   ccm_data_bytes,
    output wire         ccm_aad_phase,
    input  wire         ccm_data_ready,
    input  wire         ccm_done,
    input  wire         ccm_ready,

    // ═════ External ciphertext input (AEAD decrypt msg phase) ═════
    input  wire [31:0]  ct_din,          // ciphertext body data
    input  wire         ct_din_valid,    // data word valid
    input  wire         ct_din_last,     // last word of ciphertext body
    input  wire [1:0]   ct_din_bytes,    // valid bytes in last word

    // ═════ External RF read port (time-multiplexed, async) ═════
    input  wire         ext_rf_rd_en,     // 1=use ext_rf_raddr, 0=use sf_rf_reg_id
    input  wire [2:0]   ext_rf_raddr,     // external read address
    output wire [255:0] ext_rf_rdata      // 256-bit async read data
);

    // ═════════════════════════════════════════════════════════════════════════
    // sym_rf: 8 × 256-bit Distributed RAM (LUTRAM)
    // ═════════════════════════════════════════════════════════════════════════
    // Slot layout (canonical, role-agnostic):
    //   RF[0] = own_eph_pub (G_X or G_Y)
    //   RF[1] = peer_eph_pub (G_Y or G_X)
    //   RF[2] = G_XY → G_IY (temporal reuse)
    //   RF[3] = rolling TH  (H_MSG1 → TH_2 → TH_3 → TH_4)
    //   RF[4] = rolling PRK (PRK_2e → SALT_3e2m → PRK_3e2m → ...)
    //   RF[5] = G_RX → SALT_4e3m (temporal reuse)
    //   RF[6] = scratch (OSCORE intermediates)
    //   RF[7] = scratch
    // ═════════════════════════════════════════════════════════════════════════
    (* ram_style = "distributed" *) reg [255:0] sym_rf [0:7];

    integer rf_i;
    initial begin
        for (rf_i = 0; rf_i < 8; rf_i = rf_i + 1)
            sym_rf[rf_i] = 256'h0;
    end

    // ─────────────────────────────────────────────────────────────────────────
    // RF Read Port A: shared between stream_formatter and external reader
    // When ext_rf_rd_en=1, external addr is used (top-level reads RF).
    // When ext_rf_rd_en=0, formatter addr is used (formatter reads RF).
    // Total async read ports = 3 (A + key_rf + result_rf) → fits RAM32M.
    // ─────────────────────────────────────────────────────────────────────────
    wire [2:0]   rd_addr_a = ext_rf_rd_en ? ext_rf_raddr : sf_rf_reg_id;
    wire [255:0] rd_data_a = sym_rf[rd_addr_a];

    // External read data (full 256-bit async output)
    assign ext_rf_rdata = rd_data_a;

    reg [31:0] sf_rf_data_r;
    always @(*) begin
        case (sf_rf_word_idx)
            3'd0: sf_rf_data_r = rd_data_a[255:224];
            3'd1: sf_rf_data_r = rd_data_a[223:192];
            3'd2: sf_rf_data_r = rd_data_a[191:160];
            3'd3: sf_rf_data_r = rd_data_a[159:128];
            3'd4: sf_rf_data_r = rd_data_a[127: 96];
            3'd5: sf_rf_data_r = rd_data_a[ 95: 64];
            3'd6: sf_rf_data_r = rd_data_a[ 63: 32];
            3'd7: sf_rf_data_r = rd_data_a[ 31:  0];
        endcase
    end
    assign sf_rf_data = sf_rf_data_r;

    // ─────────────────────────────────────────────────────────────────────────
    // RF Write: pre-muxed single write port (helps LUTRAM inference).
    // rf_wen has priority over ext_rf_wen (they never collide in practice).
    // ─────────────────────────────────────────────────────────────────────────
    reg         rf_wen;
    reg [2:0]   rf_waddr;
    wire [255:0] rf_wdata = hmac_hash_out;  // direct wire — saves 256 FFs

    wire         rf_we_any   = rf_wen | ext_rf_wen;
    wire [2:0]   rf_wa_mux   = rf_wen ? rf_waddr : ext_rf_waddr;
    wire [255:0] rf_wd_mux   = rf_wen ? rf_wdata : ext_rf_wdata;

    always @(posedge clk)
        if (rf_we_any)
            sym_rf[rf_wa_mux] <= rf_wd_mux;

    // ═════════════════════════════════════════════════════════════════════════
    // HMAC Core Feed Logic
    // ═════════════════════════════════════════════════════════════════════════
    // stream_formatter drives fmt_data/fmt_valid/fmt_last. We route these
    // to either hmac_key_* or hmac_data_* depending on the current phase.
    //
    // Phase 0 (key):   formatter runs seq 0x40 (HMAC_KEY32) → hmac_key_*
    // Phase 1 (data):  formatter runs data sequence → hmac_data_*
    // ─────────────────────────────────────────────────────────────────────────
    reg hmac_phase;  // 0=key feed, 1=data feed

    // Key feed: active when phase=0 and dest_sel=0 (HMAC)
    assign hmac_key_in    = sf_fmt_data;
    assign hmac_key_valid = sf_fmt_valid & ~hmac_phase & ~sf_dest_sel;
    assign hmac_key_last  = sf_fmt_last  & ~hmac_phase & ~sf_dest_sel;

    // Data feed: active when phase=1 and dest_sel=0 (HMAC)
    assign hmac_data_in    = sf_fmt_data;
    assign hmac_data_valid = sf_fmt_valid &  hmac_phase & ~sf_dest_sel;
    assign hmac_data_last  = sf_fmt_last  &  hmac_phase & ~sf_dest_sel;

    // ─────────────────────────────────────────────────────────────────────────
    // AES-CCM Feed: AAD from formatter (dest_sel=1), msg from formatter or ct_din
    // For decrypt msg phase: route external ct_din → ccm instead of formatter
    // ─────────────────────────────────────────────────────────────────────────
    // Forward-declare flags used in combinational mux (assigned in S_IDLE)
    reg is_aead;       // 1=AES-CCM mode (AEAD encrypt/decrypt)
    reg is_decrypt;    // registered from op_rom[44]
    wire use_ct_din = is_aead & is_decrypt & hmac_phase;  // msg phase of AEAD decrypt

    assign ccm_data_in    = use_ct_din ? ct_din       : sf_fmt_data;
    assign ccm_data_valid = use_ct_din ? ct_din_valid  : (sf_fmt_valid & sf_dest_sel);
    assign ccm_data_last  = use_ct_din ? ct_din_last   : (sf_fmt_last  & sf_dest_sel);
    assign ccm_data_bytes = use_ct_din ? ct_din_bytes  : sf_fmt_bytes;
    assign ccm_aad_phase  = ~hmac_phase;  // phase 0 = AAD, phase 1 = message
    assign ccm_decrypt    = is_decrypt;
    assign ccm_tag_len    = 5'd8;  // Suite 0: AES-CCM-16-64-128
    assign ccm_aad_len    = {8'd0, sf_label};
    assign ccm_msg_len    = {8'd0, sf_length_byte};

    // Flow control: stall formatter based on active destination
    assign sf_receiver_ready = sf_dest_sel ? ccm_data_ready
                                           : (hmac_phase ? hmac_data_ready : 1'b1);

    // ═════════════════════════════════════════════════════════════════════════
    // FSM
    // ═════════════════════════════════════════════════════════════════════════
    // One HMAC call: key feed → wait for data_ready → msg feed → latch result.
    //
    // Flow (optimized — 3 states eliminated vs. original):
    //   IDLE → START_HMAC → WAIT_KEY_DONE → WAIT_DATA_RDY →
    //   WAIT_MSG_DONE → WAIT_HMAC_DONE → LATCH_RESULT → (XOR_KS) → DONE
    //
    // S_LOAD_KEY merged into S_START_HMAC (saves 1 cycle/op)
    // S_LOAD_MSG merged into S_WAIT_KEY_DONE/S_WAIT_DATA_RDY (saves 1 cycle/op)
    // S_TURNAROUND eliminated — S_DONE provides the idle gap (saves 1 cycle/op)
    // ─────────────────────────────────────────────────────────────────────────
    localparam [3:0] S_IDLE           = 4'd0;
    localparam [3:0] S_START_HMAC     = 4'd1;  // pulse hmac_start + launch key/AAD formatter
    // S_LOAD_KEY merged into S_START_HMAC (save 1 cycle)
    localparam [3:0] S_WAIT_KEY_DONE  = 4'd3;  // wait for key seq to finish
    localparam [3:0] S_WAIT_DATA_RDY  = 4'd4;  // wait for hmac_core data_ready + launch msg
    // S_LOAD_MSG merged into S_WAIT_KEY_DONE/S_WAIT_DATA_RDY (save 1 cycle)
    localparam [3:0] S_WAIT_MSG_DONE  = 4'd6;  // wait for msg seq to finish
    localparam [3:0] S_WAIT_HMAC_DONE = 4'd7;  // wait for hmac_done
    localparam [3:0] S_LATCH_RESULT   = 4'd8;  // write HMAC result to RF
    localparam [3:0] S_XOR_KS         = 4'd9;  // XOR keystream vs ciphertext
    // S_TURNAROUND eliminated — S_DONE provides idle gap (save 1 cycle)
    localparam [3:0] S_DONE           = 4'd11;

    reg [3:0] state;

    // ─────────────────────────────────────────────────────────────────────────
    // Operation parameters — decoded from op_sel at start, consumed by FSM
    // ─────────────────────────────────────────────────────────────────────────
    reg [2:0] key_rf_slot;     // RF slot holding HMAC key
    reg [2:0] msg_rf_slot;     // RF slot read during message
    reg [7:0] msg_seq;         // formatter sequence for message
    reg [2:0] result_rf_slot;  // RF slot to write result into

    // AES-CCM config — combinatorial from RF (stable at ccm_start time)
    assign ccm_key   = sym_rf[key_rf_slot][255:128];
    assign ccm_nonce = sym_rf[result_rf_slot][255:152];

    // ─────────────────────────────────────────────────────────────────────────
    // Microcode ROM — one entry per opcode, replaces case-based decoder.
    // Adding a new opcode = one line below + one localparam. FSM unchanged.
    // ─────────────────────────────────────────────────────────────────────────
    // Layout [40:0]:
    //   [2:0]   key_rf      — RF slot for HMAC key
    //   [5:3]   msg_rf      — RF slot for message data / context
    //   [8:6]   dst_rf      — RF slot to write HMAC result
    //   [16:9]  msg_seq     — formatter sequence for message phase
    //   [24:17] label       — EDHOC info label byte
    //   [32:25] len_byte    — KDF output length byte
    //   [33]    do_xor      — XOR keystream against ciphertext after HMAC
    //   [40:34] msg_bytes   — message length in bytes (×8 → hmac_msg_len)
    //   [41]    is_sha      — 1=SHA-256 (skip key phase), 0=HMAC
    //   [42]    is_aead     — 1=AES-CCM mode (reinterpret label/len_byte)
    //   [43]    key_short   — 1=16B key (seq 0xD8), 0=32B key (seq 0x40)
    //   [44]    is_decrypt  — 1=AES-CCM decrypt mode
    // ─────────────────────────────────────────────────────────────────────────
    reg [44:0] op_rom [0:31];
    wire [44:0] ucode = op_rom[op_sel];

    // Opcode indices (§5.2 — derivation chain steps)
    localparam [4:0] OP_PRK_2E    = 5'd0;
    localparam [4:0] OP_KS_2      = 5'd1;
    localparam [4:0] OP_SALT_3E2M = 5'd2;
    localparam [4:0] OP_PRK_3E2M  = 5'd3;
    localparam [4:0] OP_H_MSG1    = 5'd4;  // SHA-256(MSG1) → RF[3]
    localparam [4:0] OP_TH_2      = 5'd5;  // SHA-256(TH_2 input) → RF[3]
    localparam [4:0] OP_MAC_2     = 5'd6;  // KDF(PRK_3e2m, 2, ctx_2, 8) → RF[6]
    localparam [4:0] OP_TH_3      = 5'd7;  // SHA-256(TH_3 input) → RF[3]
    localparam [4:0] OP_K_3       = 5'd8;  // KDF(PRK_3e2m, 3, TH_3, 16) → RF[6]
    localparam [4:0] OP_IV_3      = 5'd9;  // KDF(PRK_3e2m, 4, TH_3, 13) → RF[7]
    localparam [4:0] OP_SALT_4E3M = 5'd10; // KDF(PRK_3e2m, 5, TH_3, 32) → RF[5]
    localparam [4:0] OP_AEAD_3    = 5'd11; // AES-CCM encrypt: PT_3 → CT_3
    localparam [4:0] OP_PRK_4E3M  = 5'd12; // HMAC(SALT_4e3m, G_IY) → RF[4]
    localparam [4:0] OP_MAC_3     = 5'd13; // KDF(PRK_4e3m, 6, ctx_3, 8) → RF[6]
    localparam [4:0] OP_TH_4      = 5'd14; // SHA-256(TH_4 input 99B) → RF[3]
    localparam [4:0] OP_K_4       = 5'd15; // KDF(PRK_4e3m, 8, TH_4, 16) → RF[6]
    localparam [4:0] OP_IV_4      = 5'd16; // KDF(PRK_4e3m, 9, TH_4, 13) → RF[7]
    localparam [4:0] OP_PRK_OUT   = 5'd17; // KDF(PRK_4e3m, 7, TH_4, 32) → RF[4]
    localparam [4:0] OP_PRK_EXP   = 5'd18; // KDF(PRK_out, 10, h'', 32) → RF[4]  (RFC 9528 Fig.6: empty context)
    localparam [4:0] OP_M_SECRET  = 5'd19; // KDF(PRK_exp, 0, '', 16) → RF[6]
    localparam [4:0] OP_M_SALT    = 5'd20; // KDF(PRK_exp, 1, '', 8) → RF[7]
    localparam [4:0] OP_COMMON_IV = 5'd21; // HMAC(M_Secret, cv_info 9B) → RF[5]
    localparam [4:0] OP_SEND_KEY  = 5'd22; // HMAC(M_Secret, key_info 11B) → RF[6]
    localparam [4:0] OP_RECV_KEY  = 5'd23; // HMAC(M_Secret, key_info 11B) → RF[7]
    localparam [4:0] OP_TH_2_R    = 5'd24; // SHA-256(TH_2 input), G_Y from RF[0]
    localparam [4:0] OP_AEAD_3_D  = 5'd25; // AES-CCM decrypt MSG3 (ct_din input)
    localparam [4:0] OP_AEAD_4    = 5'd26; // AES-CCM encrypt MSG4 (empty PT)
    localparam [4:0] OP_AEAD_4_D  = 5'd27; // AES-CCM decrypt MSG4 (verify tag)
    localparam [4:0] OP_H_MSG1_R  = 5'd28; // SHA-256(MSG1) → RF[3], G_X from RF[1]

    integer uc_i;
    initial begin
        for (uc_i = 0; uc_i < 32; uc_i = uc_i + 1) op_rom[uc_i] = 45'd0;
        //                   dec|kshrt|aead|sha|msg_B |xor|len_byte|label  |msg_seq |dst|msg|key
        op_rom[OP_PRK_2E   ] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd32, 1'b0, 8'h00, 8'h00, 8'h29, 3'd4, 3'd2, 3'd3};
        op_rom[OP_KS_2     ] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd37, 1'b1, 8'h0B, 8'h00, 8'h1F, 3'd6, 3'd3, 3'd4};
        op_rom[OP_SALT_3E2M] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd38, 1'b0, 8'h20, 8'h01, 8'h52, 3'd4, 3'd3, 3'd4};
        op_rom[OP_PRK_3E2M ] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd32, 1'b0, 8'h00, 8'h00, 8'h29, 3'd4, 3'd5, 3'd4};
        op_rom[OP_H_MSG1   ] = {1'b0, 1'b0, 1'b0, 1'b1, 7'd37, 1'b0, 8'h00, 8'h00, 8'h00, 3'd3, 3'd0, 3'd0};
        op_rom[OP_TH_2     ] = {1'b0, 1'b0, 1'b0, 1'b1, 7'd68, 1'b0, 8'h00, 8'h00, 8'h0E, 3'd3, 3'd1, 3'd0};
        op_rom[OP_MAC_2    ] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd98, 1'b0, 8'h08, 8'h02, 8'h39, 3'd6, 3'd3, 3'd4};
        op_rom[OP_TH_3     ] = {1'b0, 1'b0, 1'b0, 1'b1,7'd100, 1'b0, 8'h00, 8'h00, 8'h15, 3'd3, 3'd3, 3'd0};
        op_rom[OP_K_3      ] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd37, 1'b0, 8'h10, 8'h03, 8'h1F, 3'd6, 3'd3, 3'd4};
        op_rom[OP_IV_3     ] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd37, 1'b0, 8'h0D, 8'h04, 8'h1F, 3'd7, 3'd3, 3'd4};
        op_rom[OP_SALT_4E3M] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd38, 1'b0, 8'h20, 8'h05, 8'h52, 3'd5, 3'd3, 3'd4};
        // AEAD encrypt: aad_len=45, msg_len=10, pt_3 seq=0x33, nonce=RF[7], TH=RF[3], key=RF[6]
        op_rom[OP_AEAD_3   ] = {1'b0, 1'b0, 1'b1, 1'b0, 7'd10, 1'b0, 8'd10, 8'd45, 8'h33, 3'd7, 3'd3, 3'd6};
        // ── T9 opcodes ───────────────────────────────────────────────────
        op_rom[OP_PRK_4E3M ] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd32, 1'b0, 8'h00, 8'h00, 8'h29, 3'd4, 3'd2, 3'd5};
        op_rom[OP_MAC_3    ] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd97, 1'b0, 8'h08, 8'h06, 8'h46, 3'd5, 3'd3, 3'd4};
        op_rom[OP_TH_4     ] = {1'b0, 1'b0, 1'b0, 1'b1, 7'd99, 1'b0, 8'h00, 8'h00, 8'h05, 3'd3, 3'd3, 3'd0};
        op_rom[OP_K_4      ] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd37, 1'b0, 8'h10, 8'h08, 8'h1F, 3'd6, 3'd3, 3'd4};
        op_rom[OP_IV_4     ] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd37, 1'b0, 8'h0D, 8'h09, 8'h1F, 3'd7, 3'd3, 3'd4};
        op_rom[OP_PRK_OUT  ] = {1'b0, 1'b0, 1'b0, 1'b0, 7'd38, 1'b0, 8'h20, 8'h07, 8'h52, 3'd4, 3'd3, 3'd4};
        op_rom[OP_PRK_EXP  ] = {1'b0, 1'b0, 1'b0, 1'b0,  7'd5, 1'b0, 8'h20, 8'h0A, 8'h71, 3'd4, 3'd0, 3'd4};
        op_rom[OP_M_SECRET ] = {1'b0, 1'b0, 1'b0, 1'b0,  7'd4, 1'b0, 8'h10, 8'h00, 8'h5A, 3'd6, 3'd0, 3'd4};
        op_rom[OP_M_SALT   ] = {1'b0, 1'b0, 1'b0, 1'b0,  7'd4, 1'b0, 8'h08, 8'h01, 8'h5A, 3'd7, 3'd0, 3'd4};
        op_rom[OP_COMMON_IV] = {1'b0, 1'b1, 1'b0, 1'b0,  7'd9, 1'b0, 8'h00, 8'h00, 8'h63, 3'd5, 3'd0, 3'd6};
        op_rom[OP_SEND_KEY ] = {1'b0, 1'b1, 1'b0, 1'b0, 7'd11, 1'b0, 8'h00, 8'h00, 8'h69, 3'd6, 3'd0, 3'd6};
        op_rom[OP_RECV_KEY ] = {1'b0, 1'b1, 1'b0, 1'b0, 7'd11, 1'b0, 8'h00, 8'h00, 8'h69, 3'd7, 3'd0, 3'd6};
        // ── Responder & AEAD decrypt/MSG4 opcodes ────────────────────────
        op_rom[OP_TH_2_R   ] = {1'b0, 1'b0, 1'b0, 1'b1, 7'd68, 1'b0, 8'h00, 8'h00, 8'h0E, 3'd3, 3'd0, 3'd0};
        // AEAD decrypt: ct_din feeds ciphertext body (formatter unused for msg)
        op_rom[OP_AEAD_3_D ] = {1'b1, 1'b0, 1'b1, 1'b0, 7'd10, 1'b0, 8'd10, 8'd45, 8'h00, 3'd7, 3'd3, 3'd6};
        // MSG4 AEAD: aad_len=45, msg_len=0 (empty plaintext), key=RF[6], nonce=RF[7]
        op_rom[OP_AEAD_4   ] = {1'b0, 1'b0, 1'b1, 1'b0,  7'd0, 1'b0,  8'd0, 8'd45, 8'h00, 3'd7, 3'd3, 3'd6};
        op_rom[OP_AEAD_4_D ] = {1'b1, 1'b0, 1'b1, 1'b0,  7'd0, 1'b0,  8'd0, 8'd45, 8'h00, 3'd7, 3'd3, 3'd6};
        op_rom[OP_H_MSG1_R ] = {1'b0, 1'b0, 1'b0, 1'b1, 7'd37, 1'b0, 8'h00, 8'h00, 8'h00, 3'd3, 3'd1, 3'd0};
    end

    // Flags for post-HMAC actions
    reg do_xor;   // after LATCH_RESULT, perform KS XOR against ciphertext
    reg is_sha;   // 1=SHA-256 mode (skip key phase), 0=HMAC mode
    // is_aead declared above (near ccm feed logic, forward declaration)
    reg key_short; // 1=16B key (seq 0xD8), 0=32B key (seq 0x40)
    // is_decrypt declared above (near ccm feed logic)

    always @(posedge clk) begin
        if (rst) begin
            state          <= S_IDLE;
            busy           <= 1'b0;
            done           <= 1'b0;
            sf_start       <= 1'b0;
            sf_seq_start   <= 8'h0;
            sf_rf_src      <= 3'd0;
            sf_label       <= 8'h0;
            sf_length_byte <= 8'h0;
            hmac_start     <= 1'b0;
            hmac_mode      <= 1'b0;
            hmac_msg_len   <= 64'd0;
            hmac_phase     <= 1'b0;
            ccm_start      <= 1'b0;
            rf_wen         <= 1'b0;
            rf_waddr       <= 3'd0;
            key_rf_slot    <= 3'd0;
            msg_rf_slot    <= 3'd0;
            msg_seq        <= 8'h0;
            result_rf_slot <= 3'd0;
            do_xor         <= 1'b0;
            is_sha         <= 1'b0;
            is_aead        <= 1'b0;
            is_decrypt     <= 1'b0;
            key_short      <= 1'b0;
            ks_2_stream    <= 88'd0;
        end else begin
            // Default: clear one-cycle pulses
            sf_start          <= 1'b0;
            hmac_start        <= 1'b0;
            ccm_start         <= 1'b0;
            done              <= 1'b0;
            rf_wen            <= 1'b0;

            case (state)

                // ─────────────────────────────────────────────────────────
                // Decode op_sel → set operation parameters
                S_IDLE: begin
                    if (start) begin
                        busy           <= 1'b1;
                        // Unpack microcode ROM — one read replaces case decoder
                        key_rf_slot    <= ucode[2:0];
                        msg_rf_slot    <= ucode[5:3];
                        result_rf_slot <= ucode[8:6];
                        msg_seq        <= ucode[16:9];
                        sf_label       <= ucode[24:17];
                        sf_length_byte <= ucode[32:25];
                        do_xor         <= ucode[33];
                        is_sha         <= ucode[41];
                        is_aead        <= ucode[42];
                        key_short      <= ucode[43];
                        is_decrypt     <= ucode[44];
                        hmac_msg_len   <= {54'd0, ucode[40:34], 3'b000};
                        state          <= S_START_HMAC;
                    end
                end

                // ─────────────────────────────────────────────────────────
                // Pulse hmac/ccm_start AND launch key/AAD formatter in one cycle
                // (merged S_LOAD_KEY into S_START_HMAC — saves 1 cycle/op)
                S_START_HMAC: begin
                    if (is_aead) begin
                        ccm_start    <= 1'b1;
                        hmac_phase   <= 1'b0;  // AAD phase first
                        sf_seq_start <= 8'h2C;  // AEAD_AAD sequence
                        sf_rf_src    <= msg_rf_slot;
                        sf_start     <= 1'b1;
                        state        <= S_WAIT_KEY_DONE;
                    end else if (is_sha) begin
                        hmac_start <= 1'b1;
                        hmac_mode  <= 1'b0;  // SHA-256 mode
                        hmac_phase <= 1'b1;  // data phase (skip key)
                        state      <= S_WAIT_DATA_RDY;
                    end else begin
                        hmac_start   <= 1'b1;
                        hmac_mode    <= 1'b1;  // HMAC mode
                        hmac_phase   <= 1'b0;  // key phase first
                        sf_seq_start <= key_short ? 8'h60 : 8'h26;
                        sf_rf_src    <= key_rf_slot;
                        sf_start     <= 1'b1;
                        state        <= S_WAIT_KEY_DONE;
                    end
                end

                // ─────────────────────────────────────────────────────────
                // Wait for key/AAD sequence to complete, then launch msg
                // formatter for AEAD (merged S_LOAD_MSG for AEAD path)
                S_WAIT_KEY_DONE: begin
                    if (sf_done) begin
                        hmac_phase <= 1'b1;  // switch to data/message phase
                        if (is_aead) begin
                            if (is_decrypt || sf_length_byte == 8'd0) begin
                                // Decrypt: ct_din feeds msg data externally.
                                // msg_len=0: no msg data (MSG4 empty PT).
                                // Skip formatter, wait for CCM to finish.
                                state <= S_WAIT_HMAC_DONE;
                            end else begin
                                // Encrypt with msg data: launch msg formatter
                                sf_seq_start <= msg_seq;
                                sf_rf_src    <= msg_rf_slot;
                                sf_start     <= 1'b1;
                                state        <= S_WAIT_MSG_DONE;
                            end
                        end else begin
                            state <= S_WAIT_DATA_RDY;
                        end
                    end
                end

                // ─────────────────────────────────────────────────────────
                // Wait for HMAC core to finish ipad processing, then
                // launch message formatter directly (merged S_LOAD_MSG).
                S_WAIT_DATA_RDY: begin
                    if (hmac_data_ready) begin
                        sf_seq_start <= msg_seq;
                        sf_rf_src    <= msg_rf_slot;
                        sf_start     <= 1'b1;
                        state        <= S_WAIT_MSG_DONE;
                    end
                end

                // ─────────────────────────────────────────────────────────
                // Wait for message sequence to complete
                S_WAIT_MSG_DONE: begin
                    if (sf_done) begin
                        state <= S_WAIT_HMAC_DONE;
                    end
                end

                // ─────────────────────────────────────────────────────────
                // Wait for HMAC/CCM to produce result
                S_WAIT_HMAC_DONE: begin
                    if (is_aead ? ccm_done : hmac_done) begin
                        state <= S_LATCH_RESULT;
                    end
                end

                // ─────────────────────────────────────────────────────────
                // Write HMAC result to RF slot, then XOR if flagged
                // rf_wdata is now a wire (= hmac_hash_out), saves 256 FFs
                S_LATCH_RESULT: begin
                    if (is_aead) begin
                        state <= S_DONE;
                    end else begin
                        rf_wen   <= 1'b1;
                        rf_waddr <= result_rf_slot;
                        if (do_xor)
                            state <= S_XOR_KS;
                        else
                            state <= S_DONE;
                    end
                end

                // ─────────────────────────────────────────────────────────
                // XOR first 11 bytes of HMAC result against ciphertext_2
                // hmac_hash_out[255:168] = bytes 0–10 (MSB-first)
                S_XOR_KS: begin
                    ks_2_stream      <= hmac_hash_out[255:168];
                    do_xor            <= 1'b0;
                    state             <= S_DONE;
                end

                // ─────────────────────────────────────────────────────────
                S_DONE: begin
                    done  <= 1'b1;
                    busy  <= 1'b0;
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;

            endcase
        end
    end

endmodule

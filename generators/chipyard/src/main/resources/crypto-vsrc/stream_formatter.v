`timescale 1ns / 1ps
//─────────────────────────────────────────────────────────────────────────────
// stream_formatter.v — Micro-op ROM driven byte-accurate 32-bit stream formatter
//
// Converts structured EDHOC/CBOR data fields into 32-bit word streams for
// HMAC-SHA256 (hmac_core v2) and AES-CCM-32.  A small ROM controls all
// formatting — no format-specific mux trees.
//
// Micro-op ROM entry (24-bit):
//   [23:20] CMD   — see CMD_* parameters
//   [19:16] ARG   — cmd-specific argument (header index / slice / byte value)
//   [15: 8] LIT   — burst count (CMD_DATA_SLI/CMD_CRED_WRD), literal byte (CMD_LIT1)
//   [ 7: 0] NEXT  — address of next micro-op (7-bit, 128 entries max)
//
// Supported CMDs:
//   CMD_HDR      (0)  Emit 1–4 constant bytes from hdr_rom[ARG]
//   CMD_SET_SRC  (1)  Set rf_src_cur = ARG[2:0] (no data output)
//   CMD_DATA_SLI (2)  LIT≤1: emit single RF word at slice ARG
//                     LIT≥2: burst — emit LIT consecutive RF words from slice ARG
//   CMD_CRED_WRD (3)  LIT≤1: emit single CRED word at ARG
//                     LIT≥2: burst — emit LIT consecutive CRED words from ARG
//   CMD_CONST1   (4)  Emit single byte from named register (ARG selects)
//   CMD_CONST4   (5)  Emit 4 bytes from const4_rom[ARG] lookup
//   CMD_DEST_HMAC(8)  Switch dest_sel to 0 (HMAC), no data output
//   CMD_DEST_AES (9)  Switch dest_sel to 1 (AES-CCM), no data output
//   CMD_LIT1     (10) Emit literal byte from LIT field
//   CMD_STOP     (15) End sequence, assert done
//
// ARG for CMD_HDR indexes into a small constant header ROM:
//   0: {0x58, 0x20}        — CBOR bstr header for 32B (2 bytes)
//   1: {0x40}              — CBOR empty bstr (1 byte)
//   2: {0x83,0x68,0x45,0x6E} — AEAD Enc0 prefix bytes 0-3 (4 bytes)
//   3: {0x63,0x72,0x79,0x70} — AEAD Enc0 bytes 4-7 "cryp" (4 bytes)
//   4: {0x74,0x30,0x40}    — AEAD Enc0 bytes 8-10 "t0@" (3 bytes)
//   5: {0x58, 0x5D}        — CBOR bstr header for 93B ctx_2 (2 bytes)
//   6: {0x58, 0x5C}        — CBOR bstr header for 92B ctx_3 (2 bytes)
//   7: {0x01}              — HKDF counter byte (1 byte, always at end of KDF)
//
// Output stream protocol (same as hmac_core v2 and aes_ccm_32):
//   - fmt_data valid when fmt_valid=1
//   - fmt_last=1 on last word of sequence
//   - fmt_bytes[1:0]: valid bytes in last word (0=4, 1=1, 2=2, 3=3)
//   - dest_sel=0 → HMAC; dest_sel=1 → AES-CCM
//   - busy=1 while sequence in progress
//─────────────────────────────────────────────────────────────────────────────

module stream_formatter (
    input  wire         clk,
    input  wire         rst,

    // ── Control ──────────────────────────────────────────────────────────────
    input  wire [7:0]   seq_start,      // ROM entry point for new sequence
    input  wire         start,          // Pulse to begin sequence
    output reg          busy,
    output reg          done,           // One-cycle pulse when sequence complete

    // ── RF narrow read port (sym_rf in sym_controller) ───────────────────────
    input  wire [2:0]   rf_src,         // RF slot to read — latched at start
    output wire [2:0]   rf_reg_id,      // = rf_src_cur (registered)
    output wire [2:0]   rf_word_idx,    // = cur_arg[2:0] for CMD_DATA_SLI
    input  wire [31:0]  rf_data,        // word from sym_rf[rf_reg_id][word_idx]

    // ── Scalar protocol parameters ────────────────────────────────────────────
    input  wire [7:0]   c_x,            // Connection identifier C_I or C_R
    input  wire [7:0]   kid_i,          // ID_CRED_I kid byte
    input  wire [7:0]   kid_r,          // ID_CRED_R kid byte
    input  wire [7:0]   label,          // EDHOC-KDF label byte (for CMD_CONST1)
    input  wire [7:0]   length_byte,    // CBOR-encoded output length byte
    input  wire [7:0]   cred_i_len,     // CRED_I length in bytes
    input  wire [7:0]   cred_r_len,     // CRED_R length in bytes

    // ── CRED memory interface ─────────────────────────────────────────────────
    // The CRED registers (cred_i[]/cred_r[]) in edhoc_m3_top are accessed
    // word-by-word.  The formatter outputs a word index; the top-level returns
    // the 32-bit word on the next cycle (1-cycle latency).
    output reg  [3:0]   cred_word_idx,  // Word index 0–15 into CRED_I or CRED_R
    input  wire         cred_sel,       // 0=CRED_I, 1=CRED_R — set by caller before start
    input  wire [31:0]  cred_data,      // Word from CRED register file

    // ── Flow control ──────────────────────────────────────────────────────────
    input  wire         receiver_ready, // 1=receiver can accept data, 0=stall

    // ── Output stream ─────────────────────────────────────────────────────────
    output reg  [31:0]  fmt_data,
    output reg          fmt_valid,
    output reg          fmt_last,
    output reg  [1:0]   fmt_bytes,
    output reg          dest_sel        // 0=HMAC, 1=AES-CCM
);

    // ─────────────────────────────────────────────────────────────────────────
    // CMD encodings
    // ─────────────────────────────────────────────────────────────────────────
    localparam CMD_HDR       = 4'd0;
    localparam CMD_SET_SRC   = 4'd1;   // set rf_src_cur = ARG[2:0] (no data)
    localparam CMD_DATA_SLI  = 4'd2;   // push sym_rf[rf_src_cur] word at slice ARG
    localparam CMD_CRED_WRD  = 4'd3;   // push CRED word at ARG index
    localparam CMD_CONST1    = 4'd4;   // push 1B from named register (ARG selects)
    localparam CMD_CONST4    = 4'd5;   // push 4B from const4_rom[ARG]
    localparam CMD_DEST_HMAC = 4'd8;   // switch dest_sel to HMAC (no data)
    localparam CMD_DEST_AES  = 4'd9;   // switch dest_sel to AES-CCM (no data)
    localparam CMD_LIT1      = 4'd10;  // push literal byte from LIT field
    localparam CMD_STOP      = 4'd15;

    // ARG sub-constants for CMD_CONST1 (values ≥128 → use named register)
    localparam CONST_LABEL   = 8'hA0;  // emit label byte
    localparam CONST_LEN     = 8'hA1;  // emit length_byte
    localparam CONST_C_X     = 8'hA2;  // emit c_x byte
    localparam CONST_KID_I   = 8'hA3;  // emit kid_i byte
    localparam CONST_KID_R   = 8'hA4;  // emit kid_r byte

    // ─────────────────────────────────────────────────────────────────────────
    // Header ROM (8 entries, up to 4 bytes each)
    // Format: {byte_count[1:0], b3, b2, b1, b0}  (b0 emitted first)
    // byte_count: 0→1B, 1→2B, 2→3B, 3→4B
    // ─────────────────────────────────────────────────────────────────────────
    reg [33:0] hdr_rom [0:15];
    // {byte_count[1:0], byte3, byte2, byte1, byte0}
    initial begin
        // idx 0: 0x58, 0x20 — CBOR bstr header for 32B (2 bytes)
        hdr_rom[0] = {2'd1, 8'h00, 8'h00, 8'h20, 8'h58};
        // idx 1: 0x40 — CBOR empty bstr (1 byte)
        hdr_rom[1] = {2'd0, 8'h00, 8'h00, 8'h00, 8'h40};
        // idx 2: 0x83, 0x68, 0x45, 0x6E — AEAD Enc0 "Encrypt0" CBOR array prefix
        hdr_rom[2] = {2'd3, 8'h6E, 8'h45, 8'h68, 8'h83};
        // idx 3: 0x63, 0x72, 0x79, 0x70 — "cryp"
        hdr_rom[3] = {2'd3, 8'h70, 8'h79, 8'h72, 8'h63};
        // idx 4: 0x74, 0x30, 0x40 — "t0@" (3 bytes)
        hdr_rom[4] = {2'd2, 8'h00, 8'h40, 8'h30, 8'h74};
        // idx 5: 0x58, 0x5D — CBOR bstr header for 93B ctx_2 (2 bytes)
        hdr_rom[5] = {2'd1, 8'h00, 8'h00, 8'h5D, 8'h58};
        // idx 6: 0x58, 0x5C — CBOR bstr header for 92B ctx_3 (2 bytes)
        hdr_rom[6] = {2'd1, 8'h00, 8'h00, 8'h5C, 8'h58};
        // idx 7: 0x01 — HKDF counter byte (1 byte)
        hdr_rom[7] = {2'd0, 8'h00, 8'h00, 8'h00, 8'h01};
        // idx 8: 0x85 0x40 0x40 0x0A — OSCORE Common_IV: array(5)+bstr(0)+bstr(0)+uint(10)
        hdr_rom[8]  = {2'd3, 8'h0A, 8'h40, 8'h40, 8'h85};
        // idx 9: 0x62 0x49 0x56 — tstr(2) "IV" (3 bytes)
        hdr_rom[9]  = {2'd2, 8'h00, 8'h56, 8'h49, 8'h62};
        // idx 10: 0x85 0x41 — OSCORE Key: array(5)+bstr(1) (2 bytes)
        hdr_rom[10] = {2'd1, 8'h00, 8'h00, 8'h41, 8'h85};
        // idx 11: 0x40 0x0A 0x63 0x4B — bstr(0)+uint(10)+tstr(3)+'K'
        hdr_rom[11] = {2'd3, 8'h4B, 8'h63, 8'h0A, 8'h40};
        // idx 12: 0x65 0x79 — "ey" (2 bytes)
        hdr_rom[12] = {2'd1, 8'h00, 8'h00, 8'h79, 8'h65};
    end

    // ─────────────────────────────────────────────────────────────────────────
    // Micro-op ROM (256 entries × 24 bits)
    // Entry format: {CMD[3:0], ARG[3:0], LIT[7:0], NEXT[7:0]}
    //   CMD  — command code (see CMD_* localparams)
    //   ARG  — 4-bit argument (slice index, header index, named-reg selector)
    //   LIT  — 8-bit literal byte (used by CMD_LIT1; 0 for other commands)
    //   NEXT — address of next micro-op
    //
    // Sequence map (seq_start values).  Caller sets rf_src before start.
    // Sequence map (seq_start values — burst-optimized 128-entry ROM):
    //   0x00  MSG1: METHOD+SUITE+0x5820+G_X(32)+C_I  →HMAC
    //   0x05  TH_4: 0x5820+TH_3+kid_I+0x48+MAC_3+CRED_I →HMAC (99B)
    //   0x0E  TH_2: 0x5820+G_Y+SET_SRC(3)+0x5820+H_MSG1 →HMAC (68B)
    //   0x15  TH_3: 0x5820+TH_2+C_R+kid_R+0x48+MAC_2+CRED_R →HMAC (100B)
    //   0x1F  KDF_TH32: label+0x5820+TH+len+0x01 →HMAC (37B, len≤23)
    //   0x26  HMAC_KEY32: emit RF[rf_src] as 32B HMAC key
    //   0x29  IKM_32B: emit RF[rf_src] as 32B HMAC message
    //   0x2C  AEAD_AAD: Enc0 header+0x5820+TH →AES (45B)
    //   0x33  PT_3: kid_I+0x48+MAC_3 →AES (10B)
    //   0x39  ctx_2: label+0x585D+C_R+ID_CRED_R+0x5820+TH_2+CRED_R+len+0x01 (98B)
    //   0x46  ctx_3: label+0x585C+ID_CRED_I+0x5820+TH_3+CRED_I+len+0x01 (97B)
    //   0x52  KDF_TH32_L32: label+0x5820+TH+0x18+len+0x01 →HMAC (38B, len≥24)
    //   0x5A  KDF_EMPTY: label+0x40+len+0x01 →HMAC (4B)
    //   0x60  IKM_16B: emit RF top 4 words as 16B HMAC message
    //   0x63  OSCORE_COMMON_IV: 85+40+F6+0A+62+49+56+0D+01 (9B)
    //   0x69  OSCORE_KEY: 85+41+kid+F6+0A+63+4B+65+79+10+01 (11B)
    // ─────────────────────────────────────────────────────────────────────────
    reg [23:0] uop_rom [0:127];
    initial begin : rom_init
        integer i;
        for (i = 0; i < 128; i = i + 1) uop_rom[i] = {CMD_STOP, 4'd0, 8'h00, 8'd0};

        // ═══════════════════════════════════════════════════════════════════
        // Burst-optimized µop ROM layout (128 entries, 7-bit addressing)
        // CMD_DATA_SLI with LIT≥2 → hardware counter emits LIT words
        // CMD_CRED_WRD with LIT≥2 → hardware counter emits LIT CRED words
        // This replaces ~125 repetitive entries with ~15 burst entries.
        // ═══════════════════════════════════════════════════════════════════

        // ── Sequence 0x00: MSG1 hash input (37B → SHA-256) ───────────────
        // {METHOD,SUITE,0x58,0x20}(4B) + G_X(32B) + C_I(1B) = 37B
        uop_rom[7'h00] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h01};
        uop_rom[7'h01] = {CMD_CONST4,     4'd0,  8'h00, 8'h02}; // {03,00,58,20}
        uop_rom[7'h02] = {CMD_DATA_SLI,   4'd0,  8'd08, 8'h03}; // G_X 8-word burst
        uop_rom[7'h03] = {CMD_CONST1,  CONST_C_X[3:0], 8'h00, 8'h04}; // C_I
        uop_rom[7'h04] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x05: TH_4 input (99B → SHA-256) ──────────────────
        // 0x5820(2)+TH_3(32)+kid_I(1)+0x48(1)+MAC_3(8)+CRED_I(55)=99B
        uop_rom[7'h05] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h06};
        uop_rom[7'h06] = {CMD_HDR,        4'd0,  8'h00, 8'h07}; // 58 20
        uop_rom[7'h07] = {CMD_DATA_SLI,   4'd0,  8'd08, 8'h08}; // TH_3 8-word burst
        uop_rom[7'h08] = {CMD_CONST1, CONST_KID_I[3:0], 8'h00, 8'h09}; // kid_I
        uop_rom[7'h09] = {CMD_LIT1,       4'd0,  8'h48, 8'h0A}; // 0x48 bstr(8)
        uop_rom[7'h0A] = {CMD_SET_SRC,    4'd5,  8'h00, 8'h0B}; // RF[5]=MAC_3
        uop_rom[7'h0B] = {CMD_DATA_SLI,   4'd0,  8'd02, 8'h0C}; // MAC_3 2-word burst
        uop_rom[7'h0C] = {CMD_CRED_WRD,   4'd0,  8'd14, 8'h0D}; // CRED_I 14-word burst
        uop_rom[7'h0D] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x0E: TH_2 input (68B → SHA-256) ───────────────────
        // 0x5820(2)+G_Y(32)+0x5820(2)+H_MSG1(32)=68B
        uop_rom[7'h0E] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h0F};
        uop_rom[7'h0F] = {CMD_HDR,        4'd0,  8'h00, 8'h10}; // 58 20
        uop_rom[7'h10] = {CMD_DATA_SLI,   4'd0,  8'd08, 8'h11}; // G_Y 8-word burst
        uop_rom[7'h11] = {CMD_SET_SRC,    4'd3,  8'h00, 8'h12}; // RF[3]=H_MSG1
        uop_rom[7'h12] = {CMD_HDR,        4'd0,  8'h00, 8'h13}; // 58 20
        uop_rom[7'h13] = {CMD_DATA_SLI,   4'd0,  8'd08, 8'h14}; // H_MSG1 8-word burst
        uop_rom[7'h14] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x15: TH_3 input (100B → SHA-256) ──────────────────
        // 0x5820(2)+TH_2(32)+C_R(1)+kid_R(1)+0x48(1)+MAC_2(8)+CRED_R(55)=100B
        uop_rom[7'h15] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h16};
        uop_rom[7'h16] = {CMD_HDR,        4'd0,  8'h00, 8'h17}; // 58 20
        uop_rom[7'h17] = {CMD_DATA_SLI,   4'd0,  8'd08, 8'h18}; // TH_2 8-word burst
        uop_rom[7'h18] = {CMD_CONST1, CONST_C_X[3:0],  8'h00, 8'h19}; // C_R
        uop_rom[7'h19] = {CMD_CONST1, CONST_KID_R[3:0], 8'h00, 8'h1A}; // kid_R
        uop_rom[7'h1A] = {CMD_LIT1,       4'd0,  8'h48, 8'h1B}; // 0x48 bstr(8)
        uop_rom[7'h1B] = {CMD_SET_SRC,    4'd6,  8'h00, 8'h1C}; // RF[6]=MAC_2
        uop_rom[7'h1C] = {CMD_DATA_SLI,   4'd0,  8'd02, 8'h1D}; // MAC_2 2-word burst
        uop_rom[7'h1D] = {CMD_CRED_WRD,   4'd0,  8'd14, 8'h1E}; // CRED_R 14-word burst
        uop_rom[7'h1E] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x1F: KDF_TH32 (37B HMAC msg, len ≤ 23) ────────────
        // label(1)+0x5820(2)+TH(32)+len(1)+0x01(1)=37B
        uop_rom[7'h1F] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h20};
        uop_rom[7'h20] = {CMD_CONST1, CONST_LABEL[3:0], 8'h00, 8'h21}; // label
        uop_rom[7'h21] = {CMD_HDR,        4'd0,  8'h00, 8'h22}; // 58 20
        uop_rom[7'h22] = {CMD_DATA_SLI,   4'd0,  8'd08, 8'h23}; // TH 8-word burst
        uop_rom[7'h23] = {CMD_CONST1, CONST_LEN[3:0],  8'h00, 8'h24}; // len
        uop_rom[7'h24] = {CMD_HDR,        4'd7,  8'h00, 8'h25}; // 0x01
        uop_rom[7'h25] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x26: HMAC_KEY32 (32B key) ─────────────────────────
        uop_rom[7'h26] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h27};
        uop_rom[7'h27] = {CMD_DATA_SLI,   4'd0,  8'd08, 8'h28}; // key 8-word burst
        uop_rom[7'h28] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x29: HKDF_EXTRACT_IKM (32B message) ───────────────
        uop_rom[7'h29] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h2A};
        uop_rom[7'h2A] = {CMD_DATA_SLI,   4'd0,  8'd08, 8'h2B}; // IKM 8-word burst
        uop_rom[7'h2B] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x2C: AEAD_AAD (45B → AES-CCM) ─────────────────────
        // 83 68 45 6E(4) 63 72 79 70(4) 74 30 40(3) 58 20(2) TH(32) = 45B
        uop_rom[7'h2C] = {CMD_DEST_AES,   4'd0,  8'h00, 8'h2D};
        uop_rom[7'h2D] = {CMD_HDR,        4'd2,  8'h00, 8'h2E}; // 83 68 45 6E
        uop_rom[7'h2E] = {CMD_HDR,        4'd3,  8'h00, 8'h2F}; // 63 72 79 70
        uop_rom[7'h2F] = {CMD_HDR,        4'd4,  8'h00, 8'h30}; // 74 30 40
        uop_rom[7'h30] = {CMD_HDR,        4'd0,  8'h00, 8'h31}; // 58 20
        uop_rom[7'h31] = {CMD_DATA_SLI,   4'd0,  8'd08, 8'h32}; // TH 8-word burst
        uop_rom[7'h32] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x33: Plaintext_3 (10B → AES-CCM message) ──────────
        // kid_I(1)+0x48(1)+MAC_3(8 from RF[5])=10B
        uop_rom[7'h33] = {CMD_DEST_AES,   4'd0,  8'h00, 8'h34};
        uop_rom[7'h34] = {CMD_CONST1, CONST_KID_I[3:0], 8'h00, 8'h35}; // kid_I
        uop_rom[7'h35] = {CMD_LIT1,       4'd0,  8'h48, 8'h36}; // 0x48 bstr(8)
        uop_rom[7'h36] = {CMD_SET_SRC,    4'd5,  8'h00, 8'h37}; // RF[5]=MAC_3
        uop_rom[7'h37] = {CMD_DATA_SLI,   4'd0,  8'd02, 8'h38}; // MAC_3 2-word burst
        uop_rom[7'h38] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x39: KDF ctx_2 (98B HMAC msg, MAC_2) ──────────────
        // label(1)+0x585D(2)+C_R(1)+{A1,04,kid_r}(3)+0x5820(2)+TH_2(32)+CRED_R(55)+len(1)+0x01(1)
        uop_rom[7'h39] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h3A};
        uop_rom[7'h3A] = {CMD_CONST1, CONST_LABEL[3:0], 8'h00, 8'h3B}; // label
        uop_rom[7'h3B] = {CMD_HDR,        4'd5,  8'h00, 8'h3C}; // 58 5D
        uop_rom[7'h3C] = {CMD_CONST1, CONST_C_X[3:0],  8'h00, 8'h3D}; // C_R
        uop_rom[7'h3D] = {CMD_LIT1,       4'd0,  8'hA1, 8'h3E}; // 0xA1 map(1)
        uop_rom[7'h3E] = {CMD_LIT1,       4'd0,  8'h04, 8'h3F}; // 0x04 label
        uop_rom[7'h3F] = {CMD_CONST1, CONST_KID_R[3:0], 8'h00, 8'h40}; // kid_r
        uop_rom[7'h40] = {CMD_HDR,        4'd0,  8'h00, 8'h41}; // 58 20
        uop_rom[7'h41] = {CMD_DATA_SLI,   4'd0,  8'd08, 8'h42}; // TH_2 8-word burst
        uop_rom[7'h42] = {CMD_CRED_WRD,   4'd0,  8'd14, 8'h43}; // CRED_R 14-word burst
        uop_rom[7'h43] = {CMD_CONST1, CONST_LEN[3:0],  8'h00, 8'h44}; // len=8
        uop_rom[7'h44] = {CMD_HDR,        4'd7,  8'h00, 8'h45}; // 0x01
        uop_rom[7'h45] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x46: KDF ctx_3 (97B HMAC msg, MAC_3) ──────────────
        // label(1)+0x585C(2)+{A1,04,kid_i}(3)+0x5820(2)+TH_3(32)+CRED_I(55)+len(1)+0x01(1)
        uop_rom[7'h46] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h47};
        uop_rom[7'h47] = {CMD_CONST1, CONST_LABEL[3:0], 8'h00, 8'h48}; // label
        uop_rom[7'h48] = {CMD_HDR,        4'd6,  8'h00, 8'h49}; // 58 5C
        uop_rom[7'h49] = {CMD_LIT1,       4'd0,  8'hA1, 8'h4A}; // 0xA1 map(1)
        uop_rom[7'h4A] = {CMD_LIT1,       4'd0,  8'h04, 8'h4B}; // 0x04 label
        uop_rom[7'h4B] = {CMD_CONST1, CONST_KID_I[3:0], 8'h00, 8'h4C}; // kid_i
        uop_rom[7'h4C] = {CMD_HDR,        4'd0,  8'h00, 8'h4D}; // 58 20
        uop_rom[7'h4D] = {CMD_DATA_SLI,   4'd0,  8'd08, 8'h4E}; // TH_3 8-word burst
        uop_rom[7'h4E] = {CMD_CRED_WRD,   4'd0,  8'd14, 8'h4F}; // CRED_I 14-word burst
        uop_rom[7'h4F] = {CMD_CONST1, CONST_LEN[3:0],  8'h00, 8'h50}; // len
        uop_rom[7'h50] = {CMD_HDR,        4'd7,  8'h00, 8'h51}; // 0x01
        uop_rom[7'h51] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x52: KDF_TH32_L32 (38B, len ≥ 24, CBOR 2-byte) ────
        // label(1)+0x5820(2)+TH(32)+0x18(1)+len(1)+0x01(1)=38B
        uop_rom[7'h52] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h53};
        uop_rom[7'h53] = {CMD_CONST1, CONST_LABEL[3:0], 8'h00, 8'h54}; // label
        uop_rom[7'h54] = {CMD_HDR,        4'd0,  8'h00, 8'h55}; // 58 20
        uop_rom[7'h55] = {CMD_DATA_SLI,   4'd0,  8'd08, 8'h56}; // TH 8-word burst
        uop_rom[7'h56] = {CMD_LIT1,       4'd0,  8'h18, 8'h57}; // 0x18 CBOR prefix
        uop_rom[7'h57] = {CMD_CONST1, CONST_LEN[3:0],  8'h00, 8'h58}; // len
        uop_rom[7'h58] = {CMD_HDR,        4'd7,  8'h00, 8'h59}; // 0x01
        uop_rom[7'h59] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x5A: KDF_EMPTY (4B, empty-context KDF) ─────────────
        // label(1)+0x40(1)+len(1)+0x01(1)=4B
        uop_rom[7'h5A] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h5B};
        uop_rom[7'h5B] = {CMD_CONST1, CONST_LABEL[3:0], 8'h00, 8'h5C}; // label
        uop_rom[7'h5C] = {CMD_HDR,        4'd1,  8'h00, 8'h5D}; // 0x40
        uop_rom[7'h5D] = {CMD_CONST1, CONST_LEN[3:0],  8'h00, 8'h5E}; // len
        uop_rom[7'h5E] = {CMD_HDR,        4'd7,  8'h00, 8'h5F}; // 0x01
        uop_rom[7'h5F] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x60: IKM_16B (16B from RF top 4 words) ────────────
        uop_rom[7'h60] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h61};
        uop_rom[7'h61] = {CMD_DATA_SLI,   4'd0,  8'd04, 8'h62}; // 4-word burst (16B)
        uop_rom[7'h62] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x63: OSCORE_COMMON_IV info (9B, all constant) ──────
        // 85 40 F6 0A 62 49 56 0D 01
        uop_rom[7'h63] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h64};
        uop_rom[7'h64] = {CMD_HDR,        4'd8,  8'h00, 8'h65}; // 85 40 F6 0A
        uop_rom[7'h65] = {CMD_HDR,        4'd9,  8'h00, 8'h66}; // 62 49 56
        uop_rom[7'h66] = {CMD_LIT1,       4'd0,  8'h0D, 8'h67}; // 0x0D (uint 13)
        uop_rom[7'h67] = {CMD_HDR,        4'd7,  8'h00, 8'h68}; // 0x01
        uop_rom[7'h68] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x69: OSCORE_KEY info (11B, kid from c_x) ───────────
        // 85 41 [kid] F6 0A 63 4B 65 79 10 01
        uop_rom[7'h69] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h6A};
        uop_rom[7'h6A] = {CMD_HDR,       4'd10,  8'h00, 8'h6B}; // 85 41
        uop_rom[7'h6B] = {CMD_CONST1, CONST_C_X[3:0],  8'h00, 8'h6C}; // kid
        uop_rom[7'h6C] = {CMD_HDR,       4'd11,  8'h00, 8'h6D}; // F6 0A 63 4B
        uop_rom[7'h6D] = {CMD_HDR,       4'd12,  8'h00, 8'h6E}; // 65 79
        uop_rom[7'h6E] = {CMD_LIT1,       4'd0,  8'h10, 8'h6F}; // 0x10 (uint 16)
        uop_rom[7'h6F] = {CMD_HDR,        4'd7,  8'h00, 8'h70}; // 0x01
        uop_rom[7'h70] = {CMD_STOP,       4'd0,  8'h00, 8'h00};

        // ── Sequence 0x71: KDF_EMPTY_L32 (5B, empty-context, len>=24) ────
        // label(1)+0x40(1)+0x18(1)+len(1)+0x01(1)=5B
        uop_rom[7'h71] = {CMD_DEST_HMAC,  4'd0,  8'h00, 8'h72};
        uop_rom[7'h72] = {CMD_CONST1, CONST_LABEL[3:0], 8'h00, 8'h73}; // label
        uop_rom[7'h73] = {CMD_HDR,        4'd1,  8'h00, 8'h74}; // 0x40
        uop_rom[7'h74] = {CMD_LIT1,       4'd0,  8'h18, 8'h75}; // 0x18 CBOR prefix
        uop_rom[7'h75] = {CMD_CONST1, CONST_LEN[3:0],  8'h00, 8'h76}; // len
        uop_rom[7'h76] = {CMD_HDR,        4'd7,  8'h00, 8'h77}; // 0x01
        uop_rom[7'h77] = {CMD_STOP,       4'd0,  8'h00, 8'h00};
    end

    // ─────────────────────────────────────────────────────────────────────────
    // Const4 ROM (lookup table for 4-byte constants parameterized at runtime)
    // Entry 0: {0x03, 0x00, 0x58, 0x20} — MSG1 first word (METHOD SUITE 0x58 0x20)
    // Entry 1: {0xA1, 0x04, kid_r, 0x00} — ID_CRED_R map (3B useful)
    // Entry 2: {0xA1, 0x04, kid_i, 0x00} — ID_CRED_I map (3B useful)
    // These are computed combinatorially from inputs
    // ─────────────────────────────────────────────────────────────────────────
    reg [31:0] const4_rom [0:3];
    always @(*) begin
        const4_rom[0] = {8'h03, 8'h00, 8'h58, 8'h20}; // METHOD=3 SUITE=0 0x58 0x20
        const4_rom[1] = {8'hA1, 8'h04, kid_r,  8'h00}; // ID_CRED_R (3B)
        const4_rom[2] = {8'hA1, 8'h04, kid_i,  8'h00}; // ID_CRED_I (3B)
        const4_rom[3] = 32'h0;
    end

    // ─────────────────────────────────────────────────────────────────────────
    // FSM states
    // ─────────────────────────────────────────────────────────────────────────
    localparam ST_IDLE     = 3'd0;
    localparam ST_FETCH    = 3'd1;
    localparam ST_CRED_REQ = 3'd2;   // wait 1 cycle for LUTRAM, then push
    localparam ST_BURST    = 3'd3;   // data burst: push consecutive RF words

    reg [2:0]  state;
    reg [6:0]  pc;           // micro-op PC (7-bit, 128-entry ROM)

    // 64-bit left-justified byte accumulator.
    // All data flows through here: 1B/2B/3B/4B pushes pack into 32-bit words.
    // acc[63:56] = oldest buffered byte.  acc_cnt = valid bytes in acc (0-3).
    reg [63:0] acc;
    reg [2:0]  acc_cnt;
    reg        cred_partial;  // 1 when fetching CRED word 13 (3 valid bytes)

    // ─────────────────────────────────────────────────────────────────────────
    // RF source register (latched from rf_src at start; CMD_SET_SRC updates it)
    // ─────────────────────────────────────────────────────────────────────────
    reg [2:0] rf_src_cur;

    // ─────────────────────────────────────────────────────────────────────────
    // Burst counter registers (shared by DATA_SLI and CRED_WRD bursts)
    // ─────────────────────────────────────────────────────────────────────────
    reg [3:0]  burst_cnt;     // words remaining in burst (0 = last word)
    reg [3:0]  burst_idx;     // current slice/word index (auto-increments)
    reg [6:0]  burst_next;    // PC after burst completes
    reg        in_burst;      // 1 = CRED burst in progress (ST_CRED_REQ loop)



    // ─────────────────────────────────────────────────────────────────────────
    // Current micro-op decode
    // ─────────────────────────────────────────────────────────────────────────
    wire [23:0] cur_uop  = uop_rom[pc];
    wire [3:0]  cur_cmd  = cur_uop[23:20];
    wire [3:0]  cur_arg  = cur_uop[19:16];
    wire [7:0]  cur_lit  = cur_uop[15: 8];
    wire [7:0]  cur_next = cur_uop[ 7: 0];

    // Narrow RF read port: combinatorial outputs to sym_controller
    // In ST_BURST, burst_idx overrides cur_arg for consecutive word access
    assign rf_reg_id  = rf_src_cur;
    assign rf_word_idx = (state == ST_BURST) ? burst_idx[2:0] : cur_arg[2:0];
    
    // ─────────────────────────────────────────────────────────────────────────
    // CONST1 byte value decode
    // ─────────────────────────────────────────────────────────────────────────
    wire [7:0] const1_byte;
    assign const1_byte = (cur_arg == CONST_LABEL[3:0]) ? label      :
                         (cur_arg == CONST_LEN[3:0]  ) ? length_byte :
                         (cur_arg == CONST_C_X[3:0]  ) ? c_x         :
                         (cur_arg == CONST_KID_I[3:0]) ? kid_i        :
                         (cur_arg == CONST_KID_R[3:0]) ? kid_r        :
                                                          {4'b0, cur_arg};

    // ─────────────────────────────────────────────────────────────────────────
    // Combinatorial helpers for the byte accumulator
    // ─────────────────────────────────────────────────────────────────────────

    // HDR entry decode (active during CMD_HDR in ST_FETCH)
    wire [1:0]  cur_hdr_bcnt = hdr_rom[cur_arg][33:32]; // 0→1B,1→2B,2→3B,3→4B
    wire [7:0]  cur_hdr_b0   = hdr_rom[cur_arg][ 7: 0]; // first byte out (MSB)
    wire [7:0]  cur_hdr_b1   = hdr_rom[cur_arg][15: 8];
    wire [7:0]  cur_hdr_b2   = hdr_rom[cur_arg][23:16];
    wire [7:0]  cur_hdr_b3   = hdr_rom[cur_arg][31:24]; // last byte (LSB) for 4B

    // Word to push for push_4b commands (combinatorial mux)
    // CMD_DATA_SLI reads from sym_rf via the narrow RF port (rf_data arrives
    // combinatorially from sym_controller's LUTRAM — no wait state needed).
    wire [31:0] cur_push_word =
        (cur_cmd == CMD_DATA_SLI) ? rf_data                                        :
        (cur_cmd == CMD_CONST4)   ? const4_rom[cur_arg[1:0]]                        :
        (cur_cmd == CMD_HDR)      ? {cur_hdr_b0,cur_hdr_b1,cur_hdr_b2,cur_hdr_b3} :
                                     32'h0;

    // Look-ahead: is the next instruction a STOP?
    wire next_is_stop = (uop_rom[cur_next[6:0]][23:20] == CMD_STOP);

    // Burst look-ahead: is the instruction after the burst a STOP?
    wire burst_next_is_stop = (uop_rom[burst_next][23:20] == CMD_STOP);

    // Unified push_1b byte source (shared by CMD_CONST1 and CMD_LIT1)
    wire [7:0] push_1b_val = (cur_cmd == CMD_CONST1) ? const1_byte : cur_lit;

    // Burst push word: in ST_BURST, rf_word_idx drives burst_idx → rf_data valid
    wire [31:0] burst_push_word = rf_data;

    always @(posedge clk) begin
        if (rst) begin
            state         <= ST_IDLE;
            pc            <= 7'h0;
            busy          <= 1'b0;
            done          <= 1'b0;
            fmt_valid     <= 1'b0;
            fmt_last      <= 1'b0;
            fmt_data      <= 32'h0;
            fmt_bytes     <= 2'b0;
            dest_sel      <= 1'b0;
            cred_word_idx <= 4'h0;
            // cred_sel is an input — no reset needed
            cred_partial  <= 1'b0;
            acc           <= 64'h0;
            acc_cnt       <= 3'h0;
            rf_src_cur    <= 3'd0;
            burst_cnt     <= 4'd0;
            burst_idx     <= 4'd0;
            burst_next    <= 7'd0;
            in_burst      <= 1'b0;
        end else begin
            // Default: clear one-cycle signals each cycle
            // HOLD logic: keep output valid until receiver accepts,
            // preventing data loss at block boundaries.
            if (!fmt_valid || receiver_ready) begin
                fmt_valid <= 1'b0;
                fmt_last  <= 1'b0;
                fmt_bytes <= 2'b0;
            end
            done      <= 1'b0;

            case (state)

                // ─────────────────────────────────────────────────────────
                ST_IDLE: begin
                    if (start) begin
                        pc         <= seq_start[6:0];
                        busy       <= 1'b1;
                        acc        <= 64'h0;
                        acc_cnt    <= 3'h0;
                        rf_src_cur <= rf_src;   // latch RF slot for this sequence
                        state      <= ST_FETCH;
                    end
                end

                // ─────────────────────────────────────────────────────────
                // Execute current micro-op.
                // ALL data flows through the 64-bit left-justified accumulator:
                //   push_4b: always emits 1 word, acc_cnt unchanged
                //   push_3b: emits iff acc_cnt >= 1
                //   push_2b: emits iff acc_cnt >= 2
                //   push_1b: emits iff acc_cnt == 3
                //   STOP:    flushes acc if acc_cnt > 0 (fmt_last=1)
                // fmt_last on a non-flush emit: set when acc_cnt==0 after emit
                //   AND next cmd is STOP (nothing more to flush).
                // ─────────────────────────────────────────────────────────
                ST_FETCH: begin
                  // Control commands (no data output) execute unconditionally
                  if (cur_cmd == CMD_DEST_HMAC) begin
                      dest_sel <= 1'b0;
                      pc       <= cur_next[6:0];
                  end else if (cur_cmd == CMD_DEST_AES) begin
                      dest_sel <= 1'b1;
                      pc       <= cur_next[6:0];
                  end else if (cur_cmd == CMD_SET_SRC) begin
                      rf_src_cur <= cur_arg[2:0];
                      pc         <= cur_next[6:0];
                  end else if (receiver_ready) begin
                    case (cur_cmd)

                        // ── push_4b: DATA_SLI (single or burst), CONST4 ──
                        CMD_DATA_SLI, CMD_CONST4: begin
                            case (acc_cnt)
                                3'd0: begin
                                    fmt_data <= cur_push_word;
                                    acc      <= 64'h0;
                                end
                                3'd1: begin
                                    fmt_data <= {acc[63:56], cur_push_word[31:8]};
                                    acc      <= {cur_push_word[7:0],  56'h0};
                                end
                                3'd2: begin
                                    fmt_data <= {acc[63:48], cur_push_word[31:16]};
                                    acc      <= {cur_push_word[15:0], 48'h0};
                                end
                                3'd3: begin
                                    fmt_data <= {acc[63:40], cur_push_word[31:24]};
                                    acc      <= {cur_push_word[23:0], 40'h0};
                                end
                                default: begin fmt_data <= cur_push_word; acc <= 64'h0; end
                            endcase
                            fmt_valid <= 1'b1;
                            // Burst mode: CMD_DATA_SLI with LIT >= 2
                            if (cur_cmd == CMD_DATA_SLI && cur_lit > 8'd1) begin
                                // First word pushed above; set up counter for remaining
                                burst_idx  <= cur_arg + 4'd1;
                                burst_cnt  <= cur_lit[3:0] - 4'd2; // remaining after 2nd push
                                burst_next <= cur_next[6:0];
                                state      <= ST_BURST;
                            end else begin
                                // Single word or CONST4 — original behavior
                                if (next_is_stop && acc_cnt == 3'd0) fmt_last <= 1'b1;
                                pc <= cur_next[6:0];
                            end
                        end

                        // ── CMD_HDR: push 1/2/3/4 constant bytes inline ───
                        CMD_HDR: begin
                            case (cur_hdr_bcnt)

                                // 1-byte push
                                2'd0: case (acc_cnt)
                                    3'd0: begin acc<={cur_hdr_b0,56'h0};              acc_cnt<=3'd1; end
                                    3'd1: begin acc<={acc[63:56],cur_hdr_b0,48'h0};   acc_cnt<=3'd2; end
                                    3'd2: begin acc<={acc[63:48],cur_hdr_b0,40'h0};   acc_cnt<=3'd3; end
                                    3'd3: begin
                                        fmt_data<={acc[63:40],cur_hdr_b0}; fmt_valid<=1'b1;
                                        acc<=64'h0; acc_cnt<=3'd0;
                                        if (next_is_stop) fmt_last<=1'b1;
                                    end
                                    default:;
                                endcase

                                // 2-byte push
                                2'd1: case (acc_cnt)
                                    3'd0: begin acc<={cur_hdr_b0,cur_hdr_b1,48'h0};              acc_cnt<=3'd2; end
                                    3'd1: begin acc<={acc[63:56],cur_hdr_b0,cur_hdr_b1,40'h0};   acc_cnt<=3'd3; end
                                    3'd2: begin
                                        fmt_data<={acc[63:48],cur_hdr_b0,cur_hdr_b1}; fmt_valid<=1'b1;
                                        acc<=64'h0; acc_cnt<=3'd0;
                                        if (next_is_stop) fmt_last<=1'b1;
                                    end
                                    3'd3: begin
                                        fmt_data<={acc[63:40],cur_hdr_b0}; fmt_valid<=1'b1;
                                        acc<={cur_hdr_b1,56'h0}; acc_cnt<=3'd1;
                                        // new_cnt=1, STOP will flush if needed
                                    end
                                    default:;
                                endcase

                                // 3-byte push
                                2'd2: case (acc_cnt)
                                    3'd0: begin acc<={cur_hdr_b0,cur_hdr_b1,cur_hdr_b2,40'h0};  acc_cnt<=3'd3; end
                                    3'd1: begin
                                        fmt_data<={acc[63:56],cur_hdr_b0,cur_hdr_b1,cur_hdr_b2}; fmt_valid<=1'b1;
                                        acc<=64'h0; acc_cnt<=3'd0;
                                        if (next_is_stop) fmt_last<=1'b1;
                                    end
                                    3'd2: begin
                                        fmt_data<={acc[63:48],cur_hdr_b0,cur_hdr_b1}; fmt_valid<=1'b1;
                                        acc<={cur_hdr_b2,56'h0}; acc_cnt<=3'd1;
                                    end
                                    3'd3: begin
                                        fmt_data<={acc[63:40],cur_hdr_b0}; fmt_valid<=1'b1;
                                        acc<={cur_hdr_b1,cur_hdr_b2,48'h0}; acc_cnt<=3'd2;
                                    end
                                    default:;
                                endcase

                                // 4-byte push (same structure as DATA_SLI group)
                                2'd3: begin
                                    case (acc_cnt)
                                        3'd0: begin fmt_data<=cur_push_word; acc<=64'h0; end
                                        3'd1: begin fmt_data<={acc[63:56],cur_push_word[31:8]};  acc<={cur_push_word[7:0], 56'h0}; end
                                        3'd2: begin fmt_data<={acc[63:48],cur_push_word[31:16]}; acc<={cur_push_word[15:0],48'h0}; end
                                        3'd3: begin fmt_data<={acc[63:40],cur_push_word[31:24]}; acc<={cur_push_word[23:0],40'h0}; end
                                        default: begin fmt_data<=cur_push_word; acc<=64'h0; end
                                    endcase
                                    fmt_valid<=1'b1;
                                    if (next_is_stop && acc_cnt==3'd0) fmt_last<=1'b1;
                                end

                            endcase
                            pc <= cur_next[6:0];
                        end

                        // ── CMD_CONST1 / CMD_LIT1: unified push_1b ───────
                        CMD_CONST1, CMD_LIT1: begin
                            case (acc_cnt)
                                3'd0: begin acc<={push_1b_val,56'h0};              acc_cnt<=3'd1; end
                                3'd1: begin acc<={acc[63:56],push_1b_val,48'h0};   acc_cnt<=3'd2; end
                                3'd2: begin acc<={acc[63:48],push_1b_val,40'h0};   acc_cnt<=3'd3; end
                                3'd3: begin
                                    fmt_data<={acc[63:40],push_1b_val}; fmt_valid<=1'b1;
                                    acc<=64'h0; acc_cnt<=3'd0;
                                    if (next_is_stop) fmt_last<=1'b1;
                                end
                                default:;
                            endcase
                            pc <= cur_next[6:0];
                        end

                        // ── CMD_CRED_WRD: request CRED word (single or burst) ──
                        CMD_CRED_WRD: begin
                            cred_word_idx <= cur_arg;
                            cred_partial  <= (cur_arg == 4'd13);
                            if (cur_lit > 8'd1) begin
                                // CRED burst: self-loop in ST_CRED_REQ
                                in_burst   <= 1'b1;
                                burst_cnt  <= cur_lit[3:0] - 4'd1;
                                burst_idx  <= cur_arg + 4'd1;
                                burst_next <= cur_next[6:0];
                            end else begin
                                in_burst <= 1'b0;
                            end
                            state         <= ST_CRED_REQ;
                            pc            <= cur_next[6:0];
                        end

                        // ── CMD_STOP: flush accumulator as last word ──────
                        CMD_STOP: begin
                            if (acc_cnt != 3'd0) begin
                                fmt_data  <= acc[63:32];
                                fmt_valid <= 1'b1;
                                fmt_last  <= 1'b1;
                                fmt_bytes <= acc_cnt[1:0]; // 1→1B,2→2B,3→3B valid
                                acc       <= 64'h0;
                                acc_cnt   <= 3'h0;
                            end
                            busy  <= 1'b0;
                            done  <= 1'b1;
                            state <= ST_IDLE;
                        end

                        default: pc <= cur_next[6:0];

                    endcase
                  end // receiver_ready
                end // ST_FETCH

                // ─────────────────────────────────────────────────────────
                // ST_BURST: Data burst — emit consecutive RF words using
                // burst_idx as slice counter. 1 word per cycle.
                // burst_push_word = rf_data (driven by rf_word_idx = burst_idx).
                ST_BURST: begin
                  if (receiver_ready) begin
                    // push_4b: same accumulator logic as CMD_DATA_SLI
                    case (acc_cnt)
                        3'd0: begin fmt_data<=burst_push_word;                              acc<=64'h0;                          end
                        3'd1: begin fmt_data<={acc[63:56],burst_push_word[31:8]};            acc<={burst_push_word[7:0], 56'h0};  end
                        3'd2: begin fmt_data<={acc[63:48],burst_push_word[31:16]};           acc<={burst_push_word[15:0],48'h0};  end
                        3'd3: begin fmt_data<={acc[63:40],burst_push_word[31:24]};           acc<={burst_push_word[23:0],40'h0};  end
                        default: begin fmt_data<=burst_push_word; acc<=64'h0; end
                    endcase
                    fmt_valid <= 1'b1;
                    if (burst_cnt == 4'd0) begin
                        // Last word of burst
                        if (burst_next_is_stop && acc_cnt == 3'd0) fmt_last <= 1'b1;
                        pc    <= burst_next;
                        state <= ST_FETCH;
                    end else begin
                        burst_idx <= burst_idx + 4'd1;
                        burst_cnt <= burst_cnt - 4'd1;
                    end
                  end
                end

                // ─────────────────────────────────────────────────────────
                // CRED: 1-cycle LUTRAM latency, then push cred_data.
                // In burst mode (in_burst=1), self-loops until burst_cnt=0.
                // pc points to post-burst instruction; cur_cmd = uop_rom[pc].
                // Gate on receiver_ready to respect HMAC block-boundary stalls.
                ST_CRED_REQ: begin
                  if (receiver_ready) begin
                    if (cred_partial) begin
                        // push_3b: cred_data[31:8] = 3 valid bytes {B0,B1,B2}
                        case (acc_cnt)
                            3'd0: begin acc<={cred_data[31:8],40'h0}; acc_cnt<=3'd3; end
                            3'd1: begin
                                fmt_data<={acc[63:56],cred_data[31:8]}; fmt_valid<=1'b1;
                                acc<=64'h0; acc_cnt<=3'd0;
                                if ((!in_burst || burst_cnt == 4'd0) && cur_cmd == CMD_STOP) fmt_last<=1'b1;
                            end
                            3'd2: begin
                                fmt_data<={acc[63:48],cred_data[31:16]}; fmt_valid<=1'b1;
                                acc<={cred_data[15:8],56'h0}; acc_cnt<=3'd1;
                            end
                            3'd3: begin
                                fmt_data<={acc[63:40],cred_data[31:24]}; fmt_valid<=1'b1;
                                acc<={cred_data[23:8],48'h0}; acc_cnt<=3'd2;
                            end
                            default:;
                        endcase
                    end else begin
                        // push_4b: all 4 bytes of cred_data valid
                        case (acc_cnt)
                            3'd0: begin fmt_data<=cred_data;                              acc<=64'h0;                    end
                            3'd1: begin fmt_data<={acc[63:56],cred_data[31:8]};           acc<={cred_data[7:0], 56'h0};  end
                            3'd2: begin fmt_data<={acc[63:48],cred_data[31:16]};          acc<={cred_data[15:0],48'h0};  end
                            3'd3: begin fmt_data<={acc[63:40],cred_data[31:24]};          acc<={cred_data[23:0],40'h0};  end
                            default: begin fmt_data<=cred_data; acc<=64'h0; end
                        endcase
                        fmt_valid <= 1'b1;
                        if ((!in_burst || burst_cnt == 4'd0) && cur_cmd == CMD_STOP && acc_cnt == 3'd0) fmt_last <= 1'b1;
                    end
                    // Burst loop: request next CRED word and stay
                    if (in_burst && burst_cnt != 4'd0) begin
                        cred_word_idx <= burst_idx;
                        cred_partial  <= (burst_idx == 4'd13);
                        burst_idx     <= burst_idx + 4'd1;
                        burst_cnt     <= burst_cnt - 4'd1;
                        // Stay in ST_CRED_REQ (self-loop; LUTRAM latency = state transition)
                    end else begin
                        if (in_burst) begin
                            in_burst <= 1'b0;
                            pc       <= burst_next;
                        end
                        state <= ST_FETCH;
                    end
                  end // receiver_ready
                end

                default: state <= ST_IDLE;

            endcase
        end
    end

endmodule

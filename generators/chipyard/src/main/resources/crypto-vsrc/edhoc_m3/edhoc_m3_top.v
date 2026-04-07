`timescale 1ns / 1ps
// ═══════════════════════════════════════════════════════════════════════════
// edhoc_m3_top.v — Top-level EDHOC Method 3 accelerator (T15+T16)
//
// Instantiates: edhoc_regmap, protocol_coordinator, x25519_proc_pipeline,
//   sym_controller, stream_formatter, hmac_core, aes_ccm_32
//
// Features:
//   - Full EDHOC Method 3 Suite 0 (initiator + responder)
//   - AES-CCM mux: shared between EDHOC mode and ext_aead mode
//   - ext_aead FSM: post-EDHOC OSCORE AEAD using keys from sym_rf
//   - CPU bus interface via edhoc_regmap
// ═══════════════════════════════════════════════════════════════════════════
module edhoc_m3_top (
    input  wire        clk,
    input  wire        rst,

    // ── CPU bus ──
    input  wire [8:0]  addr,
    input  wire [31:0] wdata,
    input  wire        wen,
    output wire [31:0] rdata
);

    // ═══════════════════════════════════════════════════════════════════════
    // Regmap wires
    // ═══════════════════════════════════════════════════════════════════════
    wire [255:0] eph_priv_w, static_priv_w, g_peer_w, peer_eph_pub_w;
    wire         ctrl_start_w, ctrl_is_init_w, ctrl_input_ready_w;
    wire         ctrl_output_ack_w, ctrl_reset_w;
    wire [7:0]   kid_own_w, kid_peer_w, c_x_w, c_peer_w;

    // Credential read port (merged)
    wire [3:0]   cred_idx_w;
    wire         cred_sel_w;
    wire [31:0]  cred_word_w;

    // data_in indexed read
    wire [4:0]   data_in_idx_w;
    wire [31:0]  data_in_word_w;

    // data_out HW write
    wire [31:0]  dout_hw_wdata_w;
    wire [4:0]   dout_hw_waddr_w;
    wire         dout_hw_wen_w;

    // msg_len HW write
    wire [7:0]   msg_len_hw_w;
    wire         msg_len_hw_wen_w;

    // ext_aead config from regmap (OSCORE PIV)
    wire         ea_start_w, ea_encrypt_w;
    wire [7:0]   ea_sender_id_w;
    wire [39:0]  ea_partial_iv_w;
    wire         ea_use_sender_key_w;
    wire [4:0]   ea_tag_len_w;
    wire [15:0]  ea_aad_len_w, ea_msg_len_w;
    wire [127:0] ea_tag_expected_w;

    // ext_aead results to regmap
    reg          ea_done_r;
    reg          ea_tag_match_r;
    reg  [127:0] ea_tag_out_r;

    // ext_aead chunked buffer wires
    wire         ea_chunk_ready_w;
    reg          ea_output_valid_r;

    // Message field extractions
    wire [87:0]  ciphertext_2_w;
    wire [127:0] edhoc_tag_expected_w;

    // Status wires
    reg          sts_done_r, sts_msg_ready_r;
    wire         sts_error_w, sts_waiting_w, sts_oscore_valid_w;
    wire [2:0]   sts_phase_w;

    // ═══════════════════════════════════════════════════════════════════════
    // Protocol coordinator wires
    // ═══════════════════════════════════════════════════════════════════════
    wire         pc_busy, pc_done, pc_msg_out_ready;
    wire [3:0]   pc_state;
    wire [5:0]   pc_step;

    // X25519 interface
    wire         x_start, x_done;
    wire [255:0] x_scalar, x_u_in, x_res;

    // ext_rf interface
    wire         ext_rf_wen;
    wire [2:0]   ext_rf_waddr;
    wire [255:0] ext_rf_wdata;

    // sym interface
    wire         sym_start_w;
    wire [4:0]   sym_op_w;
    wire         sym_cred_sel_w;
    wire [7:0]   sym_c_x_w;
    wire         sc_busy, sc_done;

    // ═══════════════════════════════════════════════════════════════════════
    // Formatter wires
    // ═══════════════════════════════════════════════════════════════════════
    wire [7:0]   sf_seq_start;
    wire [2:0]   sf_rf_src;
    wire         sf_start_w, sf_busy, sf_done_w;
    wire [2:0]   sf_rf_reg_id, sf_rf_word_idx;
    wire [31:0]  sf_rf_data;
    wire [31:0]  sf_fmt_data;
    wire         sf_fmt_valid, sf_fmt_last;
    wire [1:0]   sf_fmt_bytes;
    wire         sf_dest_sel;
    wire         sf_receiver_ready;
    wire [7:0]   sf_label, sf_length_byte;
    wire [3:0]   sf_cred_word_idx;

    // ═══════════════════════════════════════════════════════════════════════
    // HMAC wires
    // ═══════════════════════════════════════════════════════════════════════
    wire         hmac_start, hmac_mode;
    wire         hmac_ready, hmac_done_w, hmac_busy;
    wire [31:0]  hmac_key_in;
    wire         hmac_key_valid, hmac_key_last, hmac_key_ready;
    wire [31:0]  hmac_data_in;
    wire         hmac_data_valid, hmac_data_last, hmac_data_ready;
    wire [63:0]  hmac_msg_len;
    wire [255:0] hmac_hash_out;
    wire         hmac_hash_valid;

    // ═══════════════════════════════════════════════════════════════════════
    // AES-CCM wires (sym_controller side)
    // ═══════════════════════════════════════════════════════════════════════
    wire         sym_ccm_start, sym_ccm_decrypt;
    wire [127:0] sym_ccm_key;
    wire [103:0] sym_ccm_nonce;
    wire [4:0]   sym_ccm_tag_len;
    wire [15:0]  sym_ccm_aad_len, sym_ccm_msg_len;
    wire [31:0]  sym_ccm_data_in;
    wire         sym_ccm_data_valid, sym_ccm_data_last;
    wire [1:0]   sym_ccm_data_bytes;
    wire         sym_ccm_aad_phase;

    // AES-CCM common output wires
    wire         ccm_data_ready_w;
    wire [31:0]  ccm_ct_out;
    wire         ccm_ct_valid, ccm_ct_last;
    wire [1:0]   ccm_ct_bytes;
    wire [127:0] ccm_tag_out;
    wire         ccm_done_w, ccm_ready_w, ccm_tag_match_w;

    // sym_controller ct_din (for EDHOC AEAD decrypt)
    wire [31:0]  ct_din_w;
    wire         ct_din_valid_w, ct_din_last_w;
    wire [1:0]   ct_din_bytes_w;

    // KS_2 keystream (from sym_controller KS XOR)
    wire [87:0]  ks_2_stream;

    // External RF read port (replaces fixed-index taps for LUTRAM inference)
    reg          ext_rf_rd_en_r;
    reg  [2:0]   ext_rf_raddr_r;
    wire [255:0] ext_rf_rdata_w;

    // ═══════════════════════════════════════════════════════════════════════
    // ext_aead CCM drive signals
    // ═══════════════════════════════════════════════════════════════════════
    reg          ea_ccm_start;
    reg          ea_ccm_decrypt;
    reg  [127:0] ea_ccm_key;
    reg  [103:0] ea_ccm_nonce;
    reg          ea_ccm_data_valid;

    // ext_aead FSM state
    reg  [2:0]   ea_state;
    localparam [2:0]
        EA_IDLE      = 3'd0,
        EA_LATCH_KEY = 3'd1,
        EA_LOAD_IV   = 3'd2,
        EA_START_CCM = 3'd3,
        EA_FEED      = 3'd4,
        EA_WAIT_DONE  = 3'd5,
        EA_DONE       = 3'd6,
        EA_CHUNK_WAIT = 3'd7;

    reg  [103:0] ea_common_iv;
    reg  [4:0]   ea_din_idx;      // data_in read index for feed
    reg  [15:0]  ea_aad_rem;      // AAD bytes remaining
    reg  [15:0]  ea_msg_rem;      // msg bytes remaining
    reg          ea_input_ready_r; // chunk: FSM needs next input chunk
    wire         ea_active = (ea_state != EA_IDLE && ea_state != EA_DONE);

    // ═══════════════════════════════════════════════════════════════════════
    // EDHOC ct_din feeder (for AEAD decrypt: MSG3/MSG4)
    // ═══════════════════════════════════════════════════════════════════════
    // Convention: CPU writes CT body at data_in[15:17], tag at data_in[18:19]
    reg  [2:0]   ctf_state;
    localparam [2:0]
        CTF_IDLE    = 3'd0,
        CTF_WAIT    = 3'd1,  // wait for msg phase
        CTF_FEED    = 3'd2,
        CTF_DONE    = 3'd3;

    reg  [4:0]   ctf_idx;         // data_in index (starts at 15)
    reg  [3:0]   ctf_remain;      // bytes remaining
    reg  [31:0]  ctf_data_r;      // latched data_in word
    reg          ctf_data_valid_r;

    // ═══════════════════════════════════════════════════════════════════════
    // AES-CCM input mux
    // ═══════════════════════════════════════════════════════════════════════
    wire edhoc_ccm_sel = pc_busy;

    // ext_aead combinational outputs for data_last, data_bytes, aad_phase
    // (must be combinational so CCM sees them same cycle as handshake)
    wire ea_in_aad  = (ea_state == EA_FEED) && (ea_aad_rem > 16'd0);
    wire ea_in_msg  = (ea_state == EA_FEED) && (ea_aad_rem == 16'd0) && (ea_msg_rem > 16'd0);
    wire ea_data_last_comb = ea_in_aad ? (ea_aad_rem <= 16'd4) :
                             ea_in_msg ? (ea_msg_rem <= 16'd4) : 1'b0;
    wire [1:0] ea_data_bytes_comb = ea_data_last_comb ?
                                    (ea_in_aad ? ea_aad_rem[1:0] : ea_msg_rem[1:0]) : 2'd0;
    wire ea_aad_phase_comb = ea_in_aad;

    wire        ccm_start_m    = edhoc_ccm_sel ? sym_ccm_start      : ea_ccm_start;
    wire        ccm_decrypt_m  = edhoc_ccm_sel ? sym_ccm_decrypt     : ea_ccm_decrypt;
    wire [127:0] ccm_key_m     = edhoc_ccm_sel ? sym_ccm_key         : ea_ccm_key;
    wire [103:0] ccm_nonce_m   = edhoc_ccm_sel ? sym_ccm_nonce       : ea_ccm_nonce;
    // OSCORE ext_aead mode: tag length from CPU register (default 8)
    wire [4:0]  ccm_tag_len_m  = edhoc_ccm_sel ? sym_ccm_tag_len     : ea_tag_len_w;
    wire [15:0] ccm_aad_len_m  = edhoc_ccm_sel ? sym_ccm_aad_len     : ea_aad_len_w;
    wire [15:0] ccm_msg_len_m  = edhoc_ccm_sel ? sym_ccm_msg_len     : ea_msg_len_w;
    wire [31:0] ccm_data_in_m  = edhoc_ccm_sel ? sym_ccm_data_in     : data_in_word_w;
    wire        ccm_data_val_m = edhoc_ccm_sel ? sym_ccm_data_valid   : ea_ccm_data_valid;
    wire        ccm_data_lst_m = edhoc_ccm_sel ? sym_ccm_data_last    : ea_data_last_comb;
    wire [1:0]  ccm_data_byt_m = edhoc_ccm_sel ? sym_ccm_data_bytes   : ea_data_bytes_comb;
    wire        ccm_aad_ph_m   = edhoc_ccm_sel ? sym_ccm_aad_phase    : ea_aad_phase_comb;
    wire [127:0] tag_exp_m     = edhoc_ccm_sel ? edhoc_tag_expected_w : ea_tag_expected_w;

    // ═══════════════════════════════════════════════════════════════════════
    // Credential read port (merged in regmap, single indexed read)
    // ═══════════════════════════════════════════════════════════════════════
    assign cred_idx_w = sf_cred_word_idx;
    assign cred_sel_w = sym_cred_sel_w;

    // ═══════════════════════════════════════════════════════════════════════
    // data_in index mux (EDHOC ct_din feeder vs ext_aead feeder)
    // ═══════════════════════════════════════════════════════════════════════
    assign data_in_idx_w = ea_active ? ea_din_idx : ctf_idx;

    // ═══════════════════════════════════════════════════════════════════════
    // data_out HW write mux (CCM output capture)
    // ═══════════════════════════════════════════════════════════════════════
    reg [4:0]  dout_wr_idx;
    reg        dout_wr_active;

    // Packed protocol-message writer (CPU-visible EDHOC output path)
    reg [4:0]  msg_pack_idx;
    reg [4:0]  msg_pack_words;
    reg [7:0]  msg_pack_len;
    reg        msg_pack_active;
    reg        msg_ready_evt;
    reg [5:0]  pc_step_d;
    reg [255:0] gx_msg1_latched;

    // Message type for combinational word select (replaces msg_pack_mem array)
    localparam [1:0] MT_MSG1 = 2'd0, MT_MSG2 = 2'd1, MT_MSG3 = 2'd2, MT_MSG4 = 2'd3;
    reg [1:0]  msg_type;

    // MSG3 CT word registers (replaces edhoc_ct_buf[0:19] array)
    reg [31:0] ct3_w0, ct3_w1, ct3_w2;
    reg [127:0] edhoc_tag_buf;

    wire [7:0] c_i_actual = ctrl_is_init_w ? c_x_w    : c_peer_w;
    wire [7:0] c_r_actual = ctrl_is_init_w ? c_peer_w : c_x_w;
    wire init_msg1_evt_comb = ctrl_is_init_w && (pc_step_d == 6'd0) && (pc_step == 6'd1);
    reg  init_msg1_evt;
    always @(posedge clk) init_msg1_evt <= rst ? 1'b0 : init_msg1_evt_comb;
    wire resp_msg2_evt = !ctrl_is_init_w && (pc_step_d == 6'd13) && (pc_step == 6'd14);
    wire init_msg3_evt =  ctrl_is_init_w && (pc_step_d == 6'd21) && (pc_step == 6'd22);
    wire resp_msg4_evt = !ctrl_is_init_w && (pc_step_d == 6'd26) && (pc_step == 6'd27);
    localparam [7:0] CBOR_BSTR_8 = 8'h48; // CBOR: byte string, 8 bytes follow (MAC_2/MAC_3)
    wire [87:0] responder_pt2_w = {c_r_actual, kid_own_w, CBOR_BSTR_8, ext_rf_rdata_w[255:192]};
    wire [87:0] responder_ct2_w = ks_2_stream ^ responder_pt2_w;

    // MAC_2 / MAC_3 verification events
    // Initiator: after MAC_2 computed (step 12→13), verify against received ciphertext_2
    // Responder: after MAC_3 computed (step 21→22), verify against AEAD_3_D plaintext output
    wire init_mac2_verify_evt =  ctrl_is_init_w && (pc_step_d == 6'd12) && (pc_step == 6'd13);
    wire resp_mac3_verify_evt = !ctrl_is_init_w && (pc_step_d == 6'd21) && (pc_step == 6'd22);
    wire [87:0] plaintext_2_w = ciphertext_2_w ^ ks_2_stream;
    wire [63:0] received_mac_3_w = {ct3_w0[15:0], ct3_w1[31:0], ct3_w2[31:16]};

    // Combinational word select (replaces msg_pack_mem indexed read)
    reg [31:0] msg_word_comb;
    always @(*) begin
        msg_word_comb = 32'd0;
        case (msg_type)
            MT_MSG1: case (msg_pack_idx)
                5'd0: msg_word_comb = 32'h0300_5820;
                5'd1: msg_word_comb = gx_msg1_latched[255:224];
                5'd2: msg_word_comb = gx_msg1_latched[223:192];
                5'd3: msg_word_comb = gx_msg1_latched[191:160];
                5'd4: msg_word_comb = gx_msg1_latched[159:128];
                5'd5: msg_word_comb = gx_msg1_latched[127:96];
                5'd6: msg_word_comb = gx_msg1_latched[95:64];
                5'd7: msg_word_comb = gx_msg1_latched[63:32];
                5'd8: msg_word_comb = gx_msg1_latched[31:0];
                5'd9: msg_word_comb = {c_i_actual, 24'h0};
                default: msg_word_comb = 32'd0;
            endcase
            MT_MSG2: case (msg_pack_idx)
                5'd0:  msg_word_comb = gx_msg1_latched[255:224];
                5'd1:  msg_word_comb = gx_msg1_latched[223:192];
                5'd2:  msg_word_comb = gx_msg1_latched[191:160];
                5'd3:  msg_word_comb = gx_msg1_latched[159:128];
                5'd4:  msg_word_comb = gx_msg1_latched[127:96];
                5'd5:  msg_word_comb = gx_msg1_latched[95:64];
                5'd6:  msg_word_comb = gx_msg1_latched[63:32];
                5'd7:  msg_word_comb = gx_msg1_latched[31:0];
                5'd8:  msg_word_comb = responder_ct2_w[87:56];
                5'd9:  msg_word_comb = responder_ct2_w[55:24];
                5'd10: msg_word_comb = {responder_ct2_w[23:0], 8'h00};
                default: msg_word_comb = 32'd0;
            endcase
            MT_MSG3: case (msg_pack_idx)
                5'd0: msg_word_comb = ct3_w0;
                5'd1: msg_word_comb = ct3_w1;
                5'd2: msg_word_comb = ct3_w2;
                5'd3: msg_word_comb = edhoc_tag_buf[127:96];
                5'd4: msg_word_comb = edhoc_tag_buf[95:64];
                default: msg_word_comb = 32'd0;
            endcase
            MT_MSG4: case (msg_pack_idx)
                5'd0: msg_word_comb = edhoc_tag_buf[127:96];
                5'd1: msg_word_comb = edhoc_tag_buf[95:64];
                default: msg_word_comb = 32'd0;
            endcase
        endcase
    end

    always @(posedge clk) begin
        if (rst) begin
            dout_wr_idx    <= 5'd0;
            dout_wr_active <= 1'b0;
            ct3_w0         <= 32'd0;
            ct3_w1         <= 32'd0;
            ct3_w2         <= 32'd0;
            edhoc_tag_buf  <= 128'd0;
        end else begin
            // Start capture on any CCM start
            if (ccm_start_m) begin
                dout_wr_idx    <= 5'd0;
                dout_wr_active <= 1'b1;
            end
            // Chunk reset: CPU signals next chunk
            else if (ea_state == EA_CHUNK_WAIT && ea_chunk_ready_w && ccm_data_ready_w) begin
                dout_wr_idx <= 5'd0;
            end
            // Advance on output word
            if (dout_wr_active && ccm_ct_valid) begin
                dout_wr_idx <= dout_wr_idx + 5'd1;
                if (edhoc_ccm_sel) begin
                    case (dout_wr_idx)
                        5'd0: ct3_w0 <= ccm_ct_out;
                        5'd1: ct3_w1 <= ccm_ct_out;
                        5'd2: ct3_w2 <= ccm_ct_out;
                    endcase
                end
            end
            // Stop on done
            if (ccm_done_w) begin
                dout_wr_active <= 1'b0;
                if (edhoc_ccm_sel)
                    edhoc_tag_buf <= ccm_tag_out;
            end
        end
    end

    assign dout_hw_wdata_w = msg_pack_active ? msg_word_comb   : ccm_ct_out;
    assign dout_hw_waddr_w = msg_pack_active ? msg_pack_idx    : dout_wr_idx;
    assign dout_hw_wen_w   = msg_pack_active ? 1'b1            :
                             (dout_wr_active & ccm_ct_valid & (dout_wr_idx < 5'd20));

    // ═══════════════════════════════════════════════════════════════════════
    // msg_len: driven when the packed protocol message is ready for CPU pickup
    // ═══════════════════════════════════════════════════════════════════════
    // MSG1 = 37B (0x25): {03,00,58,20} + G_X + C_I
    // MSG2 = 43B (0x2B): G_Y + CIPHERTEXT_2
    // MSG3 = 18B (0x12): CIPHERTEXT_3 body + tag
    // MSG4 = 8B  (0x08): 8B CIPHERTEXT_4
    reg [7:0]  msg_len_r;
    reg        msg_len_wen_r;

    always @(posedge clk) begin
        if (rst) begin
            msg_len_r     <= 8'd0;
            msg_len_wen_r <= 1'b0;
        end else begin
            msg_len_wen_r <= 1'b0;
            if (msg_ready_evt) begin
                msg_len_wen_r <= 1'b1;
                msg_len_r <= msg_pack_len;
            end
        end
    end

    assign msg_len_hw_w     = msg_len_r;
    assign msg_len_hw_wen_w = msg_len_wen_r;

    // ═══════════════════════════════════════════════════════════════════════
    // Status signal generation
    // ═══════════════════════════════════════════════════════════════════════
    // Latch done and msg_ready (coordinator pulses → CPU-polled levels)
    always @(posedge clk) begin
        if (rst || ctrl_start_w) begin
            sts_done_r      <= 1'b0;
            sts_msg_ready_r <= 1'b0;
        end else begin
            if (pc_done)            sts_done_r      <= 1'b1;
            if (msg_ready_evt)      sts_msg_ready_r <= 1'b1;
            if (ctrl_output_ack_w)  sts_msg_ready_r <= 1'b0;
        end
    end

    // EDHOC AEAD tag verification (OPT-9) + MAC_2/MAC_3 verification
    reg sts_error_r;
    always @(posedge clk) begin
        if (rst || ctrl_start_w)
            sts_error_r <= 1'b0;
        else if (ccm_done_w && edhoc_ccm_sel && sym_ccm_decrypt && !ccm_tag_match_w)
            sts_error_r <= 1'b1;
        else if (init_mac2_verify_evt && (plaintext_2_w[63:0] != ext_rf_rdata_w[255:192]))
            sts_error_r <= 1'b1;
        else if (resp_mac3_verify_evt && (received_mac_3_w != ext_rf_rdata_w[255:192]))
            sts_error_r <= 1'b1;
    end
    assign sts_error_w = sts_error_r;
    assign sts_waiting_w      = (pc_state == 4'd6); // S_WAIT_EXT
    assign sts_oscore_valid_w = sts_done_r;
    assign sts_phase_w        = pc_state[2:0];

    // ═══════════════════════════════════════════════════════════════════════
    // Module: edhoc_regmap
    // ═══════════════════════════════════════════════════════════════════════
    edhoc_regmap u_regmap (
        .clk                (clk),
        .rst                (rst),
        .addr               (addr),
        .wdata              (wdata),
        .wen                (wen),
        .rdata              (rdata),
        .eph_priv           (eph_priv_w),
        .static_priv        (static_priv_w),
        .g_peer_from_cred   (g_peer_w),
        .ctrl_start         (ctrl_start_w),
        .ctrl_is_init       (ctrl_is_init_w),
        .ctrl_input_ready   (ctrl_input_ready_w),
        .ctrl_output_ack    (ctrl_output_ack_w),
        .ctrl_reset         (ctrl_reset_w),
        .kid_own            (kid_own_w),
        .kid_peer           (kid_peer_w),
        .c_x                (c_x_w),
        .c_peer             (c_peer_w),
        .cred_idx           (cred_idx_w),
        .cred_sel           (cred_sel_w),
        .cred_word          (cred_word_w),
        .data_in_idx        (data_in_idx_w),
        .data_in_word       (data_in_word_w),
        .peer_eph_pub       (peer_eph_pub_w),
        .data_out_hw_wdata  (dout_hw_wdata_w),
        .data_out_hw_waddr  (dout_hw_waddr_w),
        .data_out_hw_wen    (dout_hw_wen_w),
        .msg_len_hw         (msg_len_hw_w),
        .msg_len_hw_wen     (msg_len_hw_wen_w),
        .sts_done           (sts_done_r),
        .sts_error          (sts_error_w),
        .sts_msg_ready      (sts_msg_ready_r),
        .sts_waiting        (sts_waiting_w),
        .sts_oscore_valid   (sts_oscore_valid_w),
        .sts_phase          (sts_phase_w),
        .ea_start           (ea_start_w),
        .ea_encrypt         (ea_encrypt_w),
        .ea_sender_id       (ea_sender_id_w),
        .ea_partial_iv      (ea_partial_iv_w),
        .ea_use_sender_key  (ea_use_sender_key_w),
        .ea_tag_len         (ea_tag_len_w),
        .ea_aad_len         (ea_aad_len_w),
        .ea_msg_len         (ea_msg_len_w),
        .ea_tag_expected    (ea_tag_expected_w),
        .ea_chunk_ready     (ea_chunk_ready_w),
        .ea_input_ready     (ea_input_ready_r),
        .ea_output_valid    (ea_output_valid_r),
        .ea_dout_count      (dout_wr_idx),
        .ea_done            (ea_done_r),
        .ea_tag_match       (ea_tag_match_r),
        .ea_tag_out         (ea_tag_out_r),
        .ciphertext_2_out   (ciphertext_2_w),
        .edhoc_tag_expected (edhoc_tag_expected_w)
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Module: protocol_coordinator
    // ═══════════════════════════════════════════════════════════════════════
    protocol_coordinator u_coord (
        .clk                (clk),
        .rst                (rst),
        .start              (ctrl_start_w),
        .is_init            (ctrl_is_init_w),
        .busy               (pc_busy),
        .done               (pc_done),
        .eph_priv           (eph_priv_w),
        .static_priv        (static_priv_w),
        .g_peer_from_cred   (g_peer_w),
        .peer_eph_pub       (peer_eph_pub_w),
        .peer_eph_loaded    (ctrl_input_ready_w),
        .c_i                (ctrl_is_init_w ? c_x_w : c_peer_w),
        .c_r                (ctrl_is_init_w ? c_peer_w : c_x_w),
        .kid_own            (kid_own_w),
        .kid_peer           (kid_peer_w),
        .msg_in_valid       (ctrl_input_ready_w),
        .msg_out_ready      (pc_msg_out_ready),
        .x25519_start       (x_start),
        .x25519_scalar      (x_scalar),
        .x25519_u_in        (x_u_in),
        .x25519_done        (x_done),
        .x25519_res         (x_res),
        .ext_rf_wen         (ext_rf_wen),
        .ext_rf_waddr       (ext_rf_waddr),
        .ext_rf_wdata       (ext_rf_wdata),
        .sym_start          (sym_start_w),
        .sym_op_sel         (sym_op_w),
        .sym_done           (sc_done),
        .sym_cred_sel       (sym_cred_sel_w),
        .sym_c_x            (sym_c_x_w),
        .state_out          (pc_state),
        .step_out           (pc_step)
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Module: x25519_proc_pipeline
    // ═══════════════════════════════════════════════════════════════════════
    x25519_proc_pipeline u_x25519 (
        .clk     (clk),
        .rst     (rst),
        .start   (x_start),
        .scalar  (x_scalar),
        .u_in    (x_u_in),
        .done    (x_done),
        .res_out (x_res)
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Module: sym_controller
    // ═══════════════════════════════════════════════════════════════════════
    sym_controller u_sym_ctrl (
        .clk                (clk),
        .rst                (rst),
        .start              (sym_start_w),
        .busy               (sc_busy),
        .done               (sc_done),
        .op_sel             (sym_op_w),
        .sf_seq_start       (sf_seq_start),
        .sf_rf_src          (sf_rf_src),
        .sf_start           (sf_start_w),
        .sf_busy            (sf_busy),
        .sf_done            (sf_done_w),
        .sf_rf_reg_id       (sf_rf_reg_id),
        .sf_rf_word_idx     (sf_rf_word_idx),
        .sf_rf_data         (sf_rf_data),
        .sf_fmt_data        (sf_fmt_data),
        .sf_fmt_valid       (sf_fmt_valid),
        .sf_fmt_last        (sf_fmt_last),
        .sf_fmt_bytes       (sf_fmt_bytes),
        .sf_dest_sel        (sf_dest_sel),
        .sf_receiver_ready  (sf_receiver_ready),
        .sf_label           (sf_label),
        .sf_length_byte     (sf_length_byte),
        .sf_c_x             (sym_c_x_w),
        .sf_cred_sel        (sym_cred_sel_w),
        .hmac_start         (hmac_start),
        .hmac_mode          (hmac_mode),
        .hmac_ready         (hmac_ready),
        .hmac_done          (hmac_done_w),
        .hmac_busy          (hmac_busy),
        .hmac_key_in        (hmac_key_in),
        .hmac_key_valid     (hmac_key_valid),
        .hmac_key_last      (hmac_key_last),
        .hmac_key_ready     (hmac_key_ready),
        .hmac_data_in       (hmac_data_in),
        .hmac_data_valid    (hmac_data_valid),
        .hmac_data_last     (hmac_data_last),
        .hmac_data_ready    (hmac_data_ready),
        .hmac_msg_len       (hmac_msg_len),
        .hmac_hash_out      (hmac_hash_out),
        .hmac_hash_valid    (hmac_hash_valid),
        .ext_rf_wen         (ext_rf_wen),
        .ext_rf_waddr       (ext_rf_waddr),
        .ext_rf_wdata       (ext_rf_wdata),
        .ciphertext_2       (ciphertext_2_w),
        .ks_2_stream        (ks_2_stream),
        // CCM outputs go to mux, not directly to CCM module
        .ccm_start          (sym_ccm_start),
        .ccm_decrypt        (sym_ccm_decrypt),
        .ccm_key            (sym_ccm_key),
        .ccm_nonce          (sym_ccm_nonce),
        .ccm_tag_len        (sym_ccm_tag_len),
        .ccm_aad_len        (sym_ccm_aad_len),
        .ccm_msg_len        (sym_ccm_msg_len),
        .ccm_data_in        (sym_ccm_data_in),
        .ccm_data_valid     (sym_ccm_data_valid),
        .ccm_data_last      (sym_ccm_data_last),
        .ccm_data_bytes     (sym_ccm_data_bytes),
        .ccm_aad_phase      (sym_ccm_aad_phase),
        // CCM feedback (directly from CCM module)
        .ccm_data_ready     (ccm_data_ready_w),
        .ccm_done           (ccm_done_w),
        .ccm_ready          (ccm_ready_w),
        // ct_din (for EDHOC AEAD decrypt)
        .ct_din             (ct_din_w),
        .ct_din_valid       (ct_din_valid_w),
        .ct_din_last        (ct_din_last_w),
        .ct_din_bytes       (ct_din_bytes_w),
        // External RF read port (time-multiplexed)
        .ext_rf_rd_en       (ext_rf_rd_en_r),
        .ext_rf_raddr       (ext_rf_raddr_r),
        .ext_rf_rdata       (ext_rf_rdata_w)
    );

    always @(posedge clk) begin
        if (rst) begin
            msg_pack_idx    <= 5'd0;
            msg_pack_words  <= 5'd0;
            msg_pack_len    <= 8'd0;
            msg_pack_active <= 1'b0;
            msg_ready_evt   <= 1'b0;
            pc_step_d       <= 6'd0;
            gx_msg1_latched <= 256'd0;
            msg_type        <= MT_MSG1;
        end else begin
            msg_ready_evt <= 1'b0;
            pc_step_d     <= pc_step;

            if (ext_rf_wen && (ext_rf_waddr == 3'd0))
                gx_msg1_latched <= ext_rf_wdata;

            if (!msg_pack_active) begin
                if (init_msg1_evt) begin
                    msg_type        <= MT_MSG1;
                    msg_pack_idx    <= 5'd0;
                    msg_pack_words  <= 5'd10;
                    msg_pack_len    <= 8'd37;
                    msg_pack_active <= 1'b1;
                end else if (resp_msg2_evt) begin
                    msg_type        <= MT_MSG2;
                    msg_pack_idx    <= 5'd0;
                    msg_pack_words  <= 5'd11;
                    msg_pack_len    <= 8'd43;
                    msg_pack_active <= 1'b1;
                end else if (init_msg3_evt) begin
                    msg_type        <= MT_MSG3;
                    msg_pack_idx    <= 5'd0;
                    msg_pack_words  <= 5'd5;
                    msg_pack_len    <= 8'd18;
                    msg_pack_active <= 1'b1;
                end else if (resp_msg4_evt) begin
                    msg_type        <= MT_MSG4;
                    msg_pack_idx    <= 5'd0;
                    msg_pack_words  <= 5'd2;
                    msg_pack_len    <= 8'd8;
                    msg_pack_active <= 1'b1;
                end
            end else if (msg_pack_idx == (msg_pack_words - 1'b1)) begin
                msg_pack_active <= 1'b0;
                msg_ready_evt   <= 1'b1;
            end else begin
                msg_pack_idx <= msg_pack_idx + 5'd1;
            end
        end
    end

    // ═══════════════════════════════════════════════════════════════════════
    // Module: stream_formatter
    // ═══════════════════════════════════════════════════════════════════════
    stream_formatter u_fmt (
        .clk                (clk),
        .rst                (rst),
        .seq_start          (sf_seq_start),
        .start              (sf_start_w),
        .busy               (sf_busy),
        .done               (sf_done_w),
        .rf_src             (sf_rf_src),
        .rf_reg_id          (sf_rf_reg_id),
        .rf_word_idx        (sf_rf_word_idx),
        .rf_data            (sf_rf_data),
        .c_x                (sym_c_x_w),
        .kid_i              (ctrl_is_init_w ? kid_own_w : kid_peer_w),
        .kid_r              (ctrl_is_init_w ? kid_peer_w : kid_own_w),
        .label              (sf_label),
        .length_byte        (sf_length_byte),
        .cred_i_len         (8'h37),       // 55 bytes (hardcoded Method 3)
        .cred_r_len         (8'h37),
        .cred_word_idx      (sf_cred_word_idx),
        .cred_sel           (sym_cred_sel_w),
        .cred_data          (cred_word_w),
        .receiver_ready     (sf_receiver_ready),
        .fmt_data           (sf_fmt_data),
        .fmt_valid          (sf_fmt_valid),
        .fmt_last           (sf_fmt_last),
        .fmt_bytes          (sf_fmt_bytes),
        .dest_sel           (sf_dest_sel)
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Module: hmac_core (active-low resetn!)
    // ═══════════════════════════════════════════════════════════════════════
    hmac_core u_hmac (
        .clk                (clk),
        .resetn             (~rst),
        .start              (hmac_start),
        .mode               (hmac_mode),
        .ready              (hmac_ready),
        .done               (hmac_done_w),
        .busy               (hmac_busy),
        .key_in             (hmac_key_in),
        .key_valid          (hmac_key_valid),
        .key_last           (hmac_key_last),
        .key_ready          (hmac_key_ready),
        .data_in            (hmac_data_in),
        .data_valid         (hmac_data_valid),
        .last_block         (hmac_data_last),
        .data_bytes         (sf_fmt_bytes),
        .data_ready         (hmac_data_ready),
        .msg_len            (hmac_msg_len),
        .hash_out           (hmac_hash_out),
        .hash_valid         (hmac_hash_valid)
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Module: aes_ccm_32 (driven by muxed signals)
    // ═══════════════════════════════════════════════════════════════════════
    aes_ccm_32 u_ccm (
        .clk                (clk),
        .rst                (rst),
        .start              (ccm_start_m),
        .decrypt            (ccm_decrypt_m),
        .key                (ccm_key_m),
        .nonce              (ccm_nonce_m),
        .tag_len            (ccm_tag_len_m),
        .aad_len            (ccm_aad_len_m),
        .msg_len            (ccm_msg_len_m),
        .data_in            (ccm_data_in_m),
        .data_valid         (ccm_data_val_m),
        .data_last          (ccm_data_lst_m),
        .data_bytes         (ccm_data_byt_m),
        .aad_phase          (ccm_aad_ph_m),
        .data_ready         (ccm_data_ready_w),
        .tag_expected       (tag_exp_m),
        .ct_out             (ccm_ct_out),
        .ct_valid           (ccm_ct_valid),
        .ct_last            (ccm_ct_last),
        .ct_bytes           (ccm_ct_bytes),
        .tag_out            (ccm_tag_out),
        .done               (ccm_done_w),
        .ready              (ccm_ready_w),
        .tag_match          (ccm_tag_match_w)
    );

    // ═══════════════════════════════════════════════════════════════════════
    // EDHOC ct_din feeder FSM
    //
    // For AEAD decrypt ops (OP_AEAD_3_D=25, OP_AEAD_4_D=27):
    //   Body at data_in[15:17], 10 bytes for MSG3 decrypt, 0 for MSG4.
    //   Triggered by sym_start with AEAD decrypt opcode.
    // ═══════════════════════════════════════════════════════════════════════
    always @(posedge clk) begin
        if (rst) begin
            ctf_state        <= CTF_IDLE;
            ctf_idx          <= 5'd15;
            ctf_remain       <= 4'd0;
            ctf_data_valid_r <= 1'b0;
        end else begin
            case (ctf_state)
                CTF_IDLE: begin
                    ctf_data_valid_r <= 1'b0;
                    // Detect AEAD decrypt start
                    if (sym_start_w && (sym_op_w == 5'd25)) begin
                        // OP_AEAD_3_D: 10 byte body
                        ctf_state  <= CTF_WAIT;
                        ctf_idx    <= 5'd15;
                        ctf_remain <= 4'd10;
                    end
                    // OP_AEAD_4_D (op=27): 0 byte body, no feeding needed
                end

                CTF_WAIT: begin
                    // Wait for CCM to enter msg phase (aad_phase goes low)
                    if (!sym_ccm_aad_phase && ccm_data_ready_w) begin
                        ctf_state        <= CTF_FEED;
                        ctf_data_valid_r <= 1'b1;
                    end
                end

                CTF_FEED: begin
                    if (ccm_data_ready_w && ctf_data_valid_r) begin
                        ctf_idx    <= ctf_idx + 5'd1;
                        if (ctf_remain <= 4'd4) begin
                            ctf_state        <= CTF_DONE;
                            ctf_data_valid_r <= 1'b0;
                        end else begin
                            ctf_remain <= ctf_remain - 4'd4;
                        end
                    end
                end

                CTF_DONE: begin
                    ctf_data_valid_r <= 1'b0;
                    if (ccm_done_w)
                        ctf_state <= CTF_IDLE;
                end

                default: ctf_state <= CTF_IDLE;
            endcase
        end
    end

    assign ct_din_w       = data_in_word_w;
    assign ct_din_valid_w = ctf_data_valid_r;
    assign ct_din_last_w  = (ctf_remain <= 4'd4) && ctf_data_valid_r;
    assign ct_din_bytes_w = (ctf_remain >= 4'd4) ? 2'd0 :
                            (ctf_remain == 4'd3) ? 2'd3 :
                            (ctf_remain == 4'd2) ? 2'd2 : 2'd1;

    // ═══════════════════════════════════════════════════════════════════════
    // ext_aead FSM — Post-EDHOC OSCORE AEAD
    //
    // Keys from sym_rf via ext_rf_rdata (time-multiplexed read port):
    //   RF[5] = Common_IV [255:152] (104 bits)
    //   RF[6] = Sender_Key [255:128] (128 bits)
    //   RF[7] = Recipient_Key [255:128] (128 bits)
    //
    // Data from regmap data_in (CPU writes AAD then payload sequentially).
    // Output captured to regmap data_out.
    // Nonce = ea_nonce_xor ^ Common_IV
    // ═══════════════════════════════════════════════════════════════════════

    // Combinational ext_rf addressing — drive ext_rf_raddr based on FSM need
    always @(*) begin
        ext_rf_rd_en_r = 1'b0;
        ext_rf_raddr_r = 3'd0;
        if (init_mac2_verify_evt) begin
            // MAC_2 verify: read RF[6] = locally computed MAC_2
            ext_rf_rd_en_r = 1'b1;
            ext_rf_raddr_r = 3'd6;
        end else if (resp_mac3_verify_evt) begin
            // MAC_3 verify: read RF[5] = locally computed MAC_3
            ext_rf_rd_en_r = 1'b1;
            ext_rf_raddr_r = 3'd5;
        end else if ((ea_state == EA_IDLE || ea_state == EA_DONE) &&
             ea_start_w && sts_done_r && !pc_busy) begin
            // Pre-request RF[5] for Common_IV (read in SAME cycle, latch at posedge)
            ext_rf_rd_en_r = 1'b1;
            ext_rf_raddr_r = 3'd5;
        end else if (ea_state == EA_LOAD_IV) begin
            // Pre-request RF[6] or RF[7] for key (latch at next posedge)
            ext_rf_rd_en_r = 1'b1;
            ext_rf_raddr_r = ea_use_sender_key_w ? 3'd6 : 3'd7;
        end else if (msg_type == MT_MSG2 && msg_pack_active) begin
            // MSG2 packing needs RF[6][255:192] for responder_pt2_w
            ext_rf_rd_en_r = 1'b1;
            ext_rf_raddr_r = 3'd6;
        end
    end

    always @(posedge clk) begin
        if (rst) begin
            ea_state          <= EA_IDLE;
            ea_done_r         <= 1'b0;
            ea_tag_match_r    <= 1'b0;
            ea_tag_out_r      <= 128'd0;
            ea_ccm_start      <= 1'b0;
            ea_ccm_decrypt    <= 1'b0;
            ea_ccm_key        <= 128'd0;
            ea_ccm_nonce      <= 104'd0;
            ea_ccm_data_valid <= 1'b0;
            ea_common_iv      <= 104'd0;
            ea_din_idx        <= 5'd0;
            ea_aad_rem        <= 16'd0;
            ea_msg_rem        <= 16'd0;
            ea_input_ready_r  <= 1'b0;
            ea_output_valid_r <= 1'b0;
        end else begin
            // Default: clear start pulse
            ea_ccm_start <= 1'b0;

            case (ea_state)
                EA_IDLE: begin
                    ea_ccm_data_valid <= 1'b0;
                    ea_input_ready_r  <= 1'b0;
                    ea_output_valid_r <= 1'b0;
                    if (ea_start_w && sts_done_r && !pc_busy) begin
                        ea_done_r      <= 1'b0;
                        ea_tag_match_r <= 1'b0;
                        // Latch Common_IV from ext_rf_rdata (addr=5, driven combinationally)
                        ea_common_iv   <= ext_rf_rdata_w[255:152];
                        ea_state       <= EA_LOAD_IV;
                    end
                end

                EA_LOAD_IV: begin
                    // Latch key from ext_rf_rdata (addr=6 or 7, driven combinationally)
                    ea_ccm_key <= ext_rf_rdata_w[255:128];
                    ea_state   <= EA_LATCH_KEY;
                end

                EA_LATCH_KEY: begin
                    // Compute nonce from latched Common_IV
                    ea_ccm_nonce   <= {8'h01, 48'd0, ea_sender_id_w, ea_partial_iv_w} ^ ea_common_iv;
                    ea_ccm_decrypt <= ~ea_encrypt_w;
                    ea_state       <= EA_START_CCM;
                end

                EA_START_CCM: begin
                    ea_ccm_start   <= 1'b1;
                    ea_din_idx     <= 5'd0;
                    ea_aad_rem     <= ea_aad_len_w;
                    ea_msg_rem     <= ea_msg_len_w;
                    ea_input_ready_r <= 1'b0;
                    ea_output_valid_r <= 1'b0;
                    ea_state       <= EA_FEED;
                end

                EA_FEED: begin
                    // Chunk boundary: data_in[0:19] exhausted, more data remains
                    // (combinational using pre-update values)
                    // In AAD phase: more if aad_rem>4 or msg_rem>0
                    // In MSG phase: more if msg_rem>4
                    if (ea_aad_rem > 16'd0) begin
                        // AAD phase
                        ea_ccm_data_valid <= 1'b1;
                        if (ccm_data_ready_w && ea_ccm_data_valid) begin
                            ea_din_idx <= ea_din_idx + 5'd1;
                            if (ea_aad_rem <= 16'd4) begin
                                ea_aad_rem        <= 16'd0;
                                ea_ccm_data_valid <= 1'b0;
                            end else begin
                                ea_aad_rem <= ea_aad_rem - 16'd4;
                            end
                            // Buffer exhausted?
                            if (ea_din_idx == 5'd19 &&
                                ((ea_aad_rem > 16'd4) || (ea_msg_rem > 16'd0))) begin
                                ea_ccm_data_valid <= 1'b0;
                                ea_state          <= EA_CHUNK_WAIT;
                            end
                        end
                    end else if (ea_msg_rem > 16'd0) begin
                        // Message phase
                        ea_ccm_data_valid <= 1'b1;
                        if (ccm_data_ready_w && ea_ccm_data_valid) begin
                            ea_din_idx <= ea_din_idx + 5'd1;
                            if (ea_msg_rem <= 16'd4) begin
                                ea_msg_rem        <= 16'd0;
                                ea_ccm_data_valid <= 1'b0;
                            end else begin
                                ea_msg_rem <= ea_msg_rem - 16'd4;
                            end
                            // Buffer exhausted?
                            if (ea_din_idx == 5'd19 && ea_msg_rem > 16'd4) begin
                                ea_ccm_data_valid <= 1'b0;
                                ea_state          <= EA_CHUNK_WAIT;
                            end
                        end
                    end else begin
                        // All data fed, wait for CCM done
                        ea_ccm_data_valid <= 1'b0;
                        ea_state          <= EA_WAIT_DONE;
                    end
                end

                EA_CHUNK_WAIT: begin
                    // Wait for CCM to finish pending AES block output
                    ea_ccm_data_valid <= 1'b0;
                    if (ccm_data_ready_w) begin
                        // All pending output captured
                        ea_input_ready_r  <= 1'b1;
                        ea_output_valid_r <= 1'b1;
                        if (ea_chunk_ready_w) begin
                            ea_input_ready_r  <= 1'b0;
                            ea_output_valid_r <= 1'b0;
                            ea_din_idx        <= 5'd0;
                            ea_state          <= EA_FEED;
                        end
                    end
                end

                EA_WAIT_DONE: begin
                    if (ccm_done_w) begin
                        ea_tag_out_r      <= ccm_tag_out;
                        ea_tag_match_r    <= ccm_tag_match_w;
                        ea_done_r         <= 1'b1;
                        ea_output_valid_r <= 1'b1;
                        ea_state          <= EA_DONE;
                    end
                end

                EA_DONE: begin
                    ea_input_ready_r <= 1'b0;
                    // Handle start directly from DONE (ea_start is 1-cycle pulse)
                    if (ea_start_w && sts_done_r && !pc_busy) begin
                        ea_done_r         <= 1'b0;
                        ea_tag_match_r    <= 1'b0;
                        ea_output_valid_r <= 1'b0;
                        ea_common_iv   <= ext_rf_rdata_w[255:152];
                        ea_state       <= EA_LOAD_IV;
                    end
                end

                default: ea_state <= EA_IDLE;
            endcase
        end
    end

endmodule

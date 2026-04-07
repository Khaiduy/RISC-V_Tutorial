// ═══════════════════════════════════════════════════════════════════════════
// edhoc_regmap.v — Register map for EDHOC Method 3 accelerator (§9.8 v2)
//
// Simple 32-bit bus: addr[8:0] byte address, wdata/wen, rdata (combinational).
// 46 CPU writes per session (8+8+1+14+14+1).
// ═══════════════════════════════════════════════════════════════════════════
module edhoc_regmap (
    input  wire        clk,
    input  wire        rst,

    // ── CPU bus interface ──
    input  wire [8:0]  addr,
    input  wire [31:0] wdata,
    input  wire        wen,
    output reg  [31:0] rdata,

    // ── Key material (256-bit, big-endian word order) ──
    output wire [255:0] eph_priv,
    output wire [255:0] static_priv,
    output wire [255:0] g_peer_from_cred,

    // ── Control register outputs ──
    output reg          ctrl_start,         // 1-cycle pulse
    output wire         ctrl_is_init,       // level
    output reg          ctrl_input_ready,   // 1-cycle pulse
    output reg          ctrl_output_ack,    // 1-cycle pulse
    output wire         ctrl_reset,         // level

    // ── Params ──
    output wire [7:0]   kid_own,
    output wire [7:0]   kid_peer,
    output wire [7:0]   c_x,
    output wire [7:0]   c_peer,

    // ── Credential LUTRAM read port (merged own+peer) ──
    input  wire [3:0]   cred_idx,
    input  wire         cred_sel,       // 0=own, 1=peer
    output wire [31:0]  cred_word,

    // ── data_in indexed read (for message parsing) ──
    input  wire [4:0]   data_in_idx,
    output wire [31:0]  data_in_word,

    // ── Peer ephemeral extracted from data_in (combinational, OPT-2) ──
    output wire [255:0] peer_eph_pub,

    // ── data_out write port (HW → buffer, CPU reads) ──
    input  wire [31:0]  data_out_hw_wdata,
    input  wire [4:0]   data_out_hw_waddr,
    input  wire         data_out_hw_wen,

    // ── msg_len write (HW → register, CPU reads) ──
    input  wire [7:0]   msg_len_hw,
    input  wire         msg_len_hw_wen,

    // ── Status inputs (from coordinator / sym_controller) ──
    input  wire         sts_done,
    input  wire         sts_error,
    input  wire         sts_msg_ready,
    input  wire         sts_waiting,
    input  wire         sts_oscore_valid,
    input  wire [2:0]   sts_phase,

    // ── ext_aead configuration outputs (OSCORE PIV) ──
    output reg          ea_start,
    output wire         ea_encrypt,
    output wire [7:0]   ea_sender_id,
    output wire [39:0]  ea_partial_iv,
    output wire         ea_use_sender_key,
    output wire [4:0]   ea_tag_len,
    output wire [15:0]  ea_aad_len,
    output wire [15:0]  ea_msg_len,
    output wire [127:0] ea_tag_expected,

    // ── ext_aead result inputs ──
    input  wire         ea_done,
    input  wire         ea_tag_match,
    input  wire [127:0] ea_tag_out,

    // ── ext_aead chunked buffer handshake ──
    output reg          ea_chunk_ready,    // 1-cycle pulse: next chunk loaded
    input  wire         ea_input_ready,    // from top FSM: needs next input chunk
    input  wire         ea_output_valid,   // from top FSM: output chunk ready
    input  wire [4:0]   ea_dout_count,     // from top: output words in data_out

    // ── EDHOC message field extractions ──
    output wire [87:0]  ciphertext_2_out,
    output wire [127:0] edhoc_tag_expected
);

    // ═══════════════════════════════════════════════════════════════════════
    // Word address decode
    // ═══════════════════════════════════════════════════════════════════════
    wire [6:0] waddr = addr[8:2];

    localparam [6:0]
        WA_EPH_BASE       = 7'h00,  // 0x000  eph_priv[0:7]
        WA_STATIC_BASE    = 7'h08,  // 0x020  static_priv[0:7]
        WA_CONTROL        = 7'h10,  // 0x040
        WA_STATUS         = 7'h11,  // 0x044
        WA_PARAMS         = 7'h12,  // 0x048
        WA_CRED_OWN_BASE  = 7'h14,  // 0x050  cred_own[0:15]
        WA_CRED_PEER_BASE = 7'h24,  // 0x090  cred_peer[0:15]
        WA_DIN_BASE       = 7'h34,  // 0x0D0  data_in[0:19]
        WA_DOUT_BASE      = 7'h48,  // 0x120  data_out[0:19]
        WA_MSG_LEN        = 7'h5C,  // 0x170
        WA_EA_CONTROL     = 7'h60,  // 0x180
        WA_EA_LENGTHS     = 7'h61,  // 0x184
        WA_EA_NONCE_BASE  = 7'h62,  // 0x188  [0:3]
        WA_EA_TAGX_BASE   = 7'h66,  // 0x198  tag_expected[0:3]
        WA_EA_STATUS      = 7'h6A,  // 0x1A8  (read-only)
        WA_EA_TOUT_BASE   = 7'h6B,  // 0x1AC  tag_out[0:3] (read-only)
        WA_EA_CHUNK       = 7'h6F;  // 0x1BC  chunk_ready pulse (write-only)

    // ═══════════════════════════════════════════════════════════════════════
    // Register storage
    // ═══════════════════════════════════════════════════════════════════════
    reg [31:0] eph_priv_mem    [0:7];
    reg [31:0] static_priv_mem [0:7];
    reg        ctrl_is_init_r;
    reg        ctrl_reset_r;
    reg [31:0] params_reg;
    reg [31:0] cred_mem        [0:31];  // [0:15]=own, [16:31]=peer
    reg [31:0] data_in_mem     [0:19];
    reg [31:0] data_out_mem    [0:19];
    reg [7:0]  msg_len_reg;

    // ext_aead configuration storage (OSCORE PIV)
    reg        ea_encrypt_r;
    reg        ea_use_sender_key_r;
    reg [4:0]  ea_tag_len_r;
    reg [31:0] ea_lengths_reg;
    reg [31:0] ea_piv_mem    [0:1];   // PIV: [0]={sender_id,piv[39:16]}, [1]={piv[15:0],16'h0}
    reg [31:0] ea_tag_exp_mem [0:3];

    // ═══════════════════════════════════════════════════════════════════════
    // Write logic
    // ═══════════════════════════════════════════════════════════════════════
    integer i;
    always @(posedge clk) begin
        if (rst) begin
            ctrl_start       <= 1'b0;
            ctrl_is_init_r   <= 1'b0;
            ctrl_input_ready <= 1'b0;
            ctrl_output_ack  <= 1'b0;
            ctrl_reset_r     <= 1'b0;
            params_reg       <= 32'h0;
            msg_len_reg      <= 8'h0;
            for (i = 0; i < 8; i = i + 1) begin
                eph_priv_mem[i]    <= 32'h0;
                static_priv_mem[i] <= 32'h0;
            end
            for (i = 0; i < 32; i = i + 1)
                cred_mem[i] <= 32'h0;
            for (i = 0; i < 20; i = i + 1) begin
                data_in_mem[i]  <= 32'h0;
                data_out_mem[i] <= 32'h0;
            end
            ea_start            <= 1'b0;
            ea_encrypt_r        <= 1'b0;
            ea_use_sender_key_r <= 1'b0;
            ea_tag_len_r        <= 5'd8;
            ea_lengths_reg      <= 32'h0;
            ea_piv_mem[0]       <= 32'h0;
            ea_piv_mem[1]       <= 32'h0;
            for (i = 0; i < 4; i = i + 1)
                ea_tag_exp_mem[i] <= 32'h0;
            ea_chunk_ready      <= 1'b0;
        end else begin
            // Self-clearing pulse defaults
            ctrl_start       <= 1'b0;
            ctrl_input_ready <= 1'b0;
            ctrl_output_ack  <= 1'b0;
            ea_start         <= 1'b0;
            ea_chunk_ready   <= 1'b0;

            // CPU writes
            if (wen) begin
                if (waddr >= WA_EPH_BASE && waddr < WA_EPH_BASE + 8)
                    eph_priv_mem[waddr[2:0]] <= wdata;

                else if (waddr >= WA_STATIC_BASE && waddr < WA_STATIC_BASE + 8)
                    static_priv_mem[waddr[2:0]] <= wdata;

                else if (waddr == WA_CONTROL) begin
                    ctrl_start       <= wdata[0];
                    ctrl_is_init_r   <= wdata[1];
                    ctrl_input_ready <= wdata[2];
                    ctrl_output_ack  <= wdata[3];
                    ctrl_reset_r     <= wdata[31];
                end

                else if (waddr == WA_PARAMS)
                    params_reg <= wdata;

                else if (waddr >= WA_CRED_OWN_BASE && waddr < WA_CRED_OWN_BASE + 16)
                    cred_mem[waddr - WA_CRED_OWN_BASE] <= wdata;

                else if (waddr >= WA_CRED_PEER_BASE && waddr < WA_CRED_PEER_BASE + 16)
                    cred_mem[16 + waddr - WA_CRED_PEER_BASE] <= wdata;

                else if (waddr >= WA_DIN_BASE && waddr < WA_DIN_BASE + 20)
                    data_in_mem[waddr - WA_DIN_BASE] <= wdata;

                // ext_aead registers
                else if (waddr == WA_EA_CONTROL) begin
                    ea_start            <= wdata[0];
                    ea_encrypt_r        <= wdata[1];
                    ea_use_sender_key_r <= wdata[2];
                    ea_tag_len_r        <= wdata[7:3];
                end
                else if (waddr == WA_EA_LENGTHS)
                    ea_lengths_reg <= wdata;
                else if (waddr >= WA_EA_NONCE_BASE && waddr < WA_EA_NONCE_BASE + 2)
                    ea_piv_mem[waddr - WA_EA_NONCE_BASE] <= wdata;
                else if (waddr >= WA_EA_TAGX_BASE && waddr < WA_EA_TAGX_BASE + 4)
                    ea_tag_exp_mem[waddr - WA_EA_TAGX_BASE] <= wdata;
                else if (waddr == WA_EA_CHUNK) begin
                    ea_chunk_ready <= 1'b1;
                end
            end

            // HW write to data_out
            if (data_out_hw_wen)
                data_out_mem[data_out_hw_waddr] <= data_out_hw_wdata;

            // HW write to msg_len
            if (msg_len_hw_wen)
                msg_len_reg <= msg_len_hw;
        end
    end

    // ═══════════════════════════════════════════════════════════════════════
    // CPU read logic (combinational)
    // ═══════════════════════════════════════════════════════════════════════
    wire [31:0] control_readback = {ctrl_reset_r, 27'b0,
                                    ctrl_output_ack, ctrl_input_ready,
                                    ctrl_is_init_r, ctrl_start};

    wire [31:0] status_reg = {21'b0, sts_phase, 3'b0,
                              sts_oscore_valid, sts_waiting,
                              sts_msg_ready, sts_error, sts_done};

    always @(*) begin
        rdata = 32'h0;
        if (waddr == WA_CONTROL)
            rdata = control_readback;
        else if (waddr == WA_STATUS)
            rdata = status_reg;
        else if (waddr >= WA_DOUT_BASE && waddr < WA_DOUT_BASE + 20)
            rdata = data_out_mem[waddr - WA_DOUT_BASE];
        else if (waddr == WA_MSG_LEN)
            rdata = {24'b0, msg_len_reg};

        // ext_aead read-back
        else if (waddr == WA_EA_CONTROL)
            rdata = {24'b0, ea_tag_len_r, ea_use_sender_key_r, ea_encrypt_r, 1'b0};
        else if (waddr == WA_EA_LENGTHS)
            rdata = ea_lengths_reg;
        else if (waddr == WA_EA_STATUS)
            rdata = {19'b0, ea_dout_count, 4'b0, ea_output_valid, ea_input_ready, ea_tag_match, ea_done};
        else if (waddr == WA_EA_TOUT_BASE)
            rdata = ea_tag_out[127:96];
        else if (waddr == WA_EA_TOUT_BASE + 7'd1)
            rdata = ea_tag_out[95:64];
        else if (waddr == WA_EA_TOUT_BASE + 7'd2)
            rdata = ea_tag_out[63:32];
        else if (waddr == WA_EA_TOUT_BASE + 7'd3)
            rdata = ea_tag_out[31:0];
    end

    // ═══════════════════════════════════════════════════════════════════════
    // Output assignments
    // ═══════════════════════════════════════════════════════════════════════

    // Key material (big-endian: word 0 = MSB)
    assign eph_priv = {eph_priv_mem[0], eph_priv_mem[1],
                       eph_priv_mem[2], eph_priv_mem[3],
                       eph_priv_mem[4], eph_priv_mem[5],
                       eph_priv_mem[6], eph_priv_mem[7]};

    assign static_priv = {static_priv_mem[0], static_priv_mem[1],
                          static_priv_mem[2], static_priv_mem[3],
                          static_priv_mem[4], static_priv_mem[5],
                          static_priv_mem[6], static_priv_mem[7]};

    // G_peer extraction from cred_peer — §9.6, zero LUTs
    // G_x sits at byte offset 23 inside the 55-byte CCS credential
    // Peer data is at cred_mem[16:31]
    assign g_peer_from_cred = {
        cred_mem[21][7:0],          // G_x byte 0
        cred_mem[22],              // G_x bytes 1–4
        cred_mem[23],              // G_x bytes 5–8
        cred_mem[24],              // G_x bytes 9–12
        cred_mem[25],              // G_x bytes 13–16
        cred_mem[26],              // G_x bytes 17–20
        cred_mem[27],              // G_x bytes 21–24
        cred_mem[28],              // G_x bytes 25–28
        cred_mem[29][31:8]         // G_x bytes 29–31
    };

    // Control
    assign ctrl_is_init = ctrl_is_init_r;
    assign ctrl_reset   = ctrl_reset_r;

    // Params
    assign kid_own  = params_reg[7:0];
    assign kid_peer = params_reg[15:8];
    assign c_x      = params_reg[23:16];
    assign c_peer   = params_reg[31:24];

    // Credential indexed read (merged array)
    assign cred_word = cred_mem[{cred_sel, cred_idx}];

    // data_in indexed read
    assign data_in_word = data_in_mem[data_in_idx];

    // Peer ephemeral extraction from data_in (combinational, OPT-2)
    //   Initiator (MSG2): G_Y at bytes 0–31 → words 0–7
    //   Responder (MSG1): G_X at bytes 4–35 → words 1–8
    //   Safe: data_in_mem[0:8] stable from first msg arrival until consumed
    assign peer_eph_pub = ctrl_is_init_r ?
        {data_in_mem[0], data_in_mem[1], data_in_mem[2], data_in_mem[3],
         data_in_mem[4], data_in_mem[5], data_in_mem[6], data_in_mem[7]} :
        {data_in_mem[1], data_in_mem[2], data_in_mem[3], data_in_mem[4],
         data_in_mem[5], data_in_mem[6], data_in_mem[7], data_in_mem[8]};

    // ext_aead configuration
    assign ea_encrypt        = ea_encrypt_r;
    assign ea_use_sender_key = ea_use_sender_key_r;
    assign ea_tag_len        = ea_tag_len_r;
    assign ea_aad_len        = ea_lengths_reg[31:16];
    assign ea_msg_len        = ea_lengths_reg[15:0];
    // PIV: sender_id (8b) + partial_iv (40b) from 2 words
    assign ea_sender_id  = ea_piv_mem[0][31:24];
    assign ea_partial_iv = {ea_piv_mem[0][23:0], ea_piv_mem[1][31:16]};
    assign ea_tag_expected = {ea_tag_exp_mem[0], ea_tag_exp_mem[1],
                              ea_tag_exp_mem[2], ea_tag_exp_mem[3]};

    // CT_2 extraction: 11 bytes at data_in[8:10] (MSG2 for initiator)
    assign ciphertext_2_out = {data_in_mem[8], data_in_mem[9], data_in_mem[10][31:8]};
    // EDHOC AEAD tag: CPU writes tag to data_in[18:19], zero-padded to 128b
    assign edhoc_tag_expected = {data_in_mem[18], data_in_mem[19], 64'h0};

endmodule

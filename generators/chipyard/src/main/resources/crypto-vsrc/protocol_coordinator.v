`timescale 1ns / 1ps

// Protocol Coordinator — Full EDHOC Method 3 sequencer
// Schedule-ROM FSM: orchestrates X25519, sym_controller, and message I/O
// G_IY hidden behind message transit latency (Plans A+B+C)

module protocol_coordinator (
    input  wire         clk,
    input  wire         rst,

    // ═══ Control ═══
    input  wire         start,
    input  wire         is_init,
    output reg          busy,
    output reg          done,

    // ═══ Key material ═══
    input  wire [255:0] eph_priv,
    input  wire [255:0] static_priv,
    input  wire [255:0] g_peer_from_cred,
    input  wire [255:0] peer_eph_pub,
    input  wire         peer_eph_loaded,

    // ═══ Protocol parameters ═══
    input  wire [7:0]   c_i,            // Connection identifier C_I
    input  wire [7:0]   c_r,            // Connection identifier C_R
    input  wire [7:0]   kid_own,        // Own KID (init: kid_I, resp: kid_R)
    input  wire [7:0]   kid_peer,       // Peer KID (init: kid_R, resp: kid_I)

    // ═══ Message flow ═══
    input  wire         msg_in_valid,   // MSG2/MSG3/MSG4 arrived
    output reg          msg_out_ready,  // MSG1/MSG3/MSG4 can be sent

    // ═══ X25519 interface ═══
    output reg          x25519_start,
    output reg  [255:0] x25519_scalar,
    output reg  [255:0] x25519_u_in,
    input  wire         x25519_done,
    input  wire [255:0] x25519_res,

    // ═══ RF write-back to sym_controller ═══
    output reg          ext_rf_wen,
    output reg  [2:0]   ext_rf_waddr,
    output wire [255:0] ext_rf_wdata,

    // ═══ sym_controller interface ═══
    output reg          sym_start,
    output reg  [4:0]   sym_op_sel,
    input  wire         sym_done,
    output reg          sym_cred_sel,   // → sf_cred_sel on sym_controller
    output reg  [7:0]   sym_c_x,        // → sf_c_x on sym_controller

    // ═══ Debug ═══
    output wire [3:0]   state_out,
    output wire [5:0]   step_out
);

    // ═════════════════════════════════════════════════════════════════════════
    // Constants
    // ═════════════════════════════════════════════════════════════════════════
    localparam [255:0] BASEPOINT = {8'h09, 248'h0};

    // Schedule entry types (3 bits)
    localparam [2:0]
        T_X25519 = 3'd0,
        T_SYM    = 3'd1,
        T_WPEER  = 3'd2,
        T_WMSG   = 3'd3,
        T_LDRF1  = 3'd4,
        T_OUTMSG = 3'd5,
        T_DONE   = 3'd7;

    // FSM states
    localparam [3:0]
        S_IDLE       = 4'd0,
        S_DECODE     = 4'd1,
        S_X25519_GO  = 4'd2,
        S_X25519_WAIT= 4'd3,
        S_SYM_GO     = 4'd4,
        S_SYM_WAIT   = 4'd5,
        S_WAIT_EXT   = 4'd6,
        S_DONE       = 4'd8;

    // ═════════════════════════════════════════════════════════════════════════
    // Schedule ROMs — 12-bit entries: {type[11:9], payload[8:0]}
    //
    // X25519 payload: {scalar_sel[8], u_in_sel[7:6], wb_rf[5:3], 3'b0}
    //   scalar_sel: 0=eph_priv, 1=static_priv
    //   u_in_sel:   00=BASEPOINT, 01=peer_eph, 10=g_peer_from_cred
    //   wb_rf:      destination sym_rf slot
    //
    // SYM payload: {par[8], cred_sel[7], c_x_mode[6:5], op_sel[4:0]}
    //   par:        1=start parallel X25519 simultaneously
    //   cred_sel:   0=CRED_I, 1=CRED_R
    //   c_x_mode:   00=unchanged, 01=c_r, 10=c_i, 11=(reserved)
    //   op_sel:     sym_controller opcode
    // ═════════════════════════════════════════════════════════════════════════

    reg [11:0] init_rom [0:33];
    reg [11:0] resp_rom [0:34];

    initial begin
        // ─── Initiator schedule (34 steps) ───
        init_rom[ 0] = {T_X25519, 1'b0, 2'b00, 3'd0, 3'b0}; // G_X  = X25519(eph, base) → RF[0]
        init_rom[ 1] = {T_X25519, 1'b0, 2'b10, 3'd5, 3'b0}; // G_RX = X25519(eph, G_R) → RF[5]
        init_rom[ 2] = {T_WPEER,  9'd0};                      // Wait peer eph (G_Y from MSG2)
        init_rom[ 3] = {T_LDRF1,  9'd0};                      // Load peer_eph → RF[1]
        init_rom[ 4] = {T_X25519, 1'b0, 2'b01, 3'd2, 3'b0}; // G_XY = X25519(eph, peer) → RF[2]
        // SYM phase 1
        init_rom[ 5] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd4};    // H_MSG1
        init_rom[ 6] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd5};    // TH_2
        init_rom[ 7] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd0};    // PRK_2E
        init_rom[ 8] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd1};    // KS_2
        init_rom[ 9] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd2};    // SALT_3E2M
        // G_IY sequential (was parallel), hidden behind G_RX overlap with MSG1
        init_rom[10] = {T_X25519, 1'b1, 2'b01, 3'd2, 3'b0}; // G_IY = X25519(static, peer) → RF[2]
        // SYM phase 2
        init_rom[11] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd3};    // PRK_3E2M
        init_rom[12] = {T_SYM, 1'b0, 1'b1, 2'b01, 5'd6};    // MAC_2 (cred=R, cx=c_r)
        init_rom[13] = {T_SYM, 1'b0, 1'b1, 2'b00, 5'd7};    // TH_3 (cred_sel=1 → CRED_R)
        init_rom[14] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd8};    // K_3
        init_rom[15] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd9};    // IV_3
        init_rom[16] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd10};   // SALT_4E3M
        // SYM phase 3
        init_rom[17] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd12};   // PRK_4E3M
        init_rom[18] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd13};   // MAC_3
        init_rom[19] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd11};   // AEAD_3 (must read TH_3 from RF[3] before TH_4 overwrites it)
        init_rom[20] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd14};   // TH_4  (writes RF[3])
        init_rom[21] = {T_OUTMSG, 9'd0};                       // MSG3 ready
        init_rom[22] = {T_WMSG,  9'd0};                        // Wait MSG4
        // SYM phase 4
        init_rom[23] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd15};   // K_4
        init_rom[24] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd16};   // IV_4
        init_rom[25] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd27};   // AEAD_4_D
        // OSCORE
        init_rom[26] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd17};   // PRK_OUT
        init_rom[27] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd18};   // PRK_EXP
        init_rom[28] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd19};   // M_SECRET
        init_rom[29] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd20};   // M_SALT
        init_rom[30] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd21};   // COMMON_IV
        init_rom[31] = {T_SYM, 1'b0, 1'b0, 2'b10, 5'd23};   // RECV_KEY (cx=c_i, Initiator Recipient ID=C_I)
        init_rom[32] = {T_SYM, 1'b0, 1'b0, 2'b01, 5'd22};   // SEND_KEY (cx=c_r, Initiator Sender ID=C_R)
        init_rom[33] = {T_DONE, 9'd0};
    end

    initial begin
        // ─── Responder schedule (35 steps) ───
        // Phase 1: Key generation
        resp_rom[ 0] = {T_X25519, 1'b0, 2'b00, 3'd0, 3'b0}; // G_Y  = X25519(eph, base) → RF[0]
        resp_rom[ 1] = {T_WPEER,  9'd0};                      // Wait peer eph (G_X)
        resp_rom[ 2] = {T_LDRF1,  9'd0};                      // Load peer_eph → RF[1]
        resp_rom[ 3] = {T_X25519, 1'b0, 2'b01, 3'd2, 3'b0}; // G_XY = X25519(eph, peer) → RF[2]
        // Phase 2: Derivation chain (order: KS_2 before SALT_3E2M, TH_3 after MAC_2)
        resp_rom[ 4] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd28};   // H_MSG1_R → RF[3] (G_X from RF[1])
        resp_rom[ 5] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd24};   // TH_2_R → RF[3] (G_Y from RF[0])
        resp_rom[ 6] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd0};    // PRK_2E → RF[4]
        resp_rom[ 7] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd1};    // KS_2 → RF[6] + XOR (key=RF[4]=PRK_2E)
        resp_rom[ 8] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd2};    // SALT_3E2M → RF[4] (key=RF[4]=PRK_2E, then overwrite)
        resp_rom[ 9] = {T_X25519, 1'b1, 2'b01, 3'd5, 3'b0}; // G_RX = X25519(static, peer) → RF[5]
        resp_rom[10] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd3};    // PRK_3E2M → RF[4] (key=RF[4]=SALT_3E2M, msg=RF[5]=G_RX)
        resp_rom[11] = {T_SYM, 1'b0, 1'b0, 2'b01, 5'd6};    // MAC_2 → RF[6] (cred=own=R, cx=c_r)
        resp_rom[12] = {T_SYM, 1'b0, 1'b0, 2'b01, 5'd7};    // TH_3 → RF[3] (cred=own=R, cx=c_r, reads MAC_2 from RF[6])
        resp_rom[13] = {T_OUTMSG, 9'd0};                       // MSG2 ready
        resp_rom[14] = {T_X25519, 1'b0, 2'b10, 3'd2, 3'b0}; // G_IY = X25519(eph, g_peer) → RF[2] (hidden behind MSG2→MSG3 transit)
        resp_rom[15] = {T_WMSG,  9'd0};                        // Wait MSG3
        // Phase 3: MSG3 processing
        resp_rom[16] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd8};    // K_3 → RF[6]
        resp_rom[17] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd9};    // IV_3 → RF[7]
        resp_rom[18] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd10};   // SALT_4E3M → RF[5]
        resp_rom[19] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd25};   // AEAD_3_D
        resp_rom[20] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd12};   // PRK_4E3M → RF[4]
        resp_rom[21] = {T_SYM, 1'b0, 1'b1, 2'b00, 5'd13};   // MAC_3 (cred=peer=I) → RF[5]
        resp_rom[22] = {T_SYM, 1'b0, 1'b1, 2'b00, 5'd14};   // TH_4 (cred=peer=I) → RF[3]
        resp_rom[23] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd15};   // K_4 → RF[6]
        resp_rom[24] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd16};   // IV_4 → RF[7]
        resp_rom[25] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd26};   // AEAD_4
        resp_rom[26] = {T_OUTMSG, 9'd0};                       // MSG4 ready
        // Phase 4: OSCORE derivation
        resp_rom[27] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd17};   // PRK_OUT → RF[4]
        resp_rom[28] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd18};   // PRK_EXP → RF[4]
        resp_rom[29] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd19};   // M_SECRET → RF[6]
        resp_rom[30] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd20};   // M_SALT → RF[7]
        resp_rom[31] = {T_SYM, 1'b0, 1'b0, 2'b00, 5'd21};   // COMMON_IV → RF[5]
        resp_rom[32] = {T_SYM, 1'b0, 1'b0, 2'b01, 5'd23};   // RECV_KEY (cx=c_r) → RF[7]
        resp_rom[33] = {T_SYM, 1'b0, 1'b0, 2'b10, 5'd22};   // SEND_KEY (cx=c_i) → RF[6]
        resp_rom[34] = {T_DONE, 9'd0};
    end

    // ═════════════════════════════════════════════════════════════════════════
    // Schedule entry decode (combinational)
    // ═════════════════════════════════════════════════════════════════════════
    reg [5:0]  step;
    reg [3:0]  state;
    reg        is_init_r;

    wire [11:0] cur_entry = is_init_r ? init_rom[step] : resp_rom[step];
    wire [2:0]  entry_type = cur_entry[11:9];

    // X25519 fields
    wire        x_scalar_sel = cur_entry[8];
    wire [1:0]  x_u_in_sel   = cur_entry[7:6];
    wire [2:0]  x_wb_rf      = cur_entry[5:3];

    // SYM fields
    wire        s_cred       = cur_entry[7];
    wire [1:0]  s_cx_mode    = cur_entry[6:5];
    wire [4:0]  s_op         = cur_entry[4:0];

    // ═════════════════════════════════════════════════════════════════════════
    // X25519 input muxes (registered params → combinational mux)
    // ═════════════════════════════════════════════════════════════════════════
    reg        sca_sel_r;
    reg [1:0]  u_sel_r;
    reg [2:0]  wb_rf_r;

    wire [255:0] x25519_scalar_mux = sca_sel_r ? static_priv : eph_priv;
    wire [255:0] x25519_u_in_mux   = (u_sel_r == 2'b00) ? BASEPOINT :
                                     (u_sel_r == 2'b01) ? peer_eph_pub :
                                                          g_peer_from_cred;

    // c_x value mux
    reg [7:0] c_x_val;
    always @(*) begin
        case (s_cx_mode)
            2'b01:   c_x_val = c_r;
            2'b10:   c_x_val = c_i;
            2'b11:   c_x_val = sym_c_x;  // reserved
            default: c_x_val = sym_c_x;  // hold current
        endcase
    end

    // ═════════════════════════════════════════════════════════════════════════
    // Edge detection
    // ═════════════════════════════════════════════════════════════════════════
    reg x25519_done_d;
    wire x25519_done_rise = x25519_done & ~x25519_done_d;

    reg sym_done_d;
    wire sym_done_rise = sym_done & ~sym_done_d;

    always @(posedge clk) begin
        if (rst) begin
            x25519_done_d <= 1'b0;
            sym_done_d    <= 1'b0;
        end else begin
            x25519_done_d <= x25519_done;
            sym_done_d    <= sym_done;
        end
    end

    // ═════════════════════════════════════════════════════════════════════════
    // RF write-data mux: peer_eph_pub for LDRF1, x25519_res otherwise
    // ═════════════════════════════════════════════════════════════════════════
    reg rf_wdata_sel;  // 0 = x25519_res, 1 = peer_eph_pub
    assign ext_rf_wdata = rf_wdata_sel ? peer_eph_pub : x25519_res;

    // ═════════════════════════════════════════════════════════════════════════
    // Outputs
    // ═════════════════════════════════════════════════════════════════════════
    assign state_out = state;
    assign step_out  = step;

    // ═════════════════════════════════════════════════════════════════════════
    // Main FSM
    // ═════════════════════════════════════════════════════════════════════════
    always @(posedge clk) begin
        if (rst) begin
            state         <= S_IDLE;
            step          <= 6'd0;
            is_init_r     <= 1'b0;
            busy          <= 1'b0;
            done          <= 1'b0;
            x25519_start  <= 1'b0;
            ext_rf_wen    <= 1'b0;
            rf_wdata_sel  <= 1'b0;
            sym_start     <= 1'b0;
            sym_op_sel    <= 5'd0;
            sym_cred_sel  <= 1'b0;
            sym_c_x       <= 8'd0;
            msg_out_ready <= 1'b0;
            sca_sel_r     <= 1'b0;
            u_sel_r       <= 2'b0;
            wb_rf_r       <= 3'd0;
        end else begin
            // Default pulse deassertions
            x25519_start  <= 1'b0;
            ext_rf_wen    <= 1'b0;
            rf_wdata_sel  <= 1'b0;
            sym_start     <= 1'b0;
            done          <= 1'b0;
            msg_out_ready <= 1'b0;

            case (state)

                // ─────────────────────────────────────────────────────
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        is_init_r     <= is_init;
                        busy          <= 1'b1;
                        step          <= 6'd0;
                        sym_c_x       <= c_i;  // Set C_I for H_MSG1
                        state         <= S_DECODE;
                    end
                end

                // ─────────────────────────────────────────────────────
                S_DECODE: begin
                    case (entry_type)
                        T_X25519: begin
                            sca_sel_r <= x_scalar_sel;
                            u_sel_r   <= x_u_in_sel;
                            wb_rf_r   <= x_wb_rf;
                            state     <= S_X25519_GO;
                        end

                        T_SYM: begin
                            sym_op_sel   <= s_op;
                            sym_cred_sel <= s_cred;
                            if (s_cx_mode != 2'b00)
                                sym_c_x <= c_x_val;
                            state <= S_SYM_GO;
                        end

                        T_WPEER: state <= S_WAIT_EXT;
                        T_WMSG:  state <= S_WAIT_EXT;

                        T_LDRF1: begin
                            ext_rf_wen   <= 1'b1;
                            ext_rf_waddr <= 3'd1;
                            rf_wdata_sel <= 1'b1;  // select peer_eph_pub
                            step  <= step + 1;
                            state <= S_DECODE;
                        end

                        T_OUTMSG: begin
                            msg_out_ready <= 1'b1;
                            step  <= step + 1;
                            state <= S_DECODE;
                        end

                        T_DONE:  state <= S_DONE;
                        default: state <= S_DONE;
                    endcase
                end

                // ─────────────────────────────────────────────────────
                S_X25519_GO: begin
                    x25519_start  <= 1'b1;
                    x25519_scalar <= x25519_scalar_mux;
                    x25519_u_in   <= x25519_u_in_mux;
                    state         <= S_X25519_WAIT;
                end

                S_X25519_WAIT: begin
                    if (x25519_done_rise) begin
                        ext_rf_wen   <= 1'b1;
                        ext_rf_waddr <= wb_rf_r;
                        step  <= step + 1;
                        state <= S_DECODE;
                    end
                end

                // ─────────────────────────────────────────────────────
                S_SYM_GO: begin
                    sym_start <= 1'b1;
                    state <= S_SYM_WAIT;
                end

                S_SYM_WAIT: begin
                    if (sym_done_rise) begin
                        step  <= step + 1;
                        state <= S_DECODE;
                    end
                end

                // ─────────────────────────────────────────────────────
                S_WAIT_EXT: begin
                    // entry_type is still valid since step hasn't changed
                    if (entry_type == T_WPEER && peer_eph_loaded) begin
                        step  <= step + 1;
                        state <= S_DECODE;
                    end
                    if (entry_type == T_WMSG && msg_in_valid) begin
                        step  <= step + 1;
                        state <= S_DECODE;
                    end
                end

                // ─────────────────────────────────────────────────────
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

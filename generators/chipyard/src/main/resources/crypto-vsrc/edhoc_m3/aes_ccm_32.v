`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// AES-CCM Encrypt/Decrypt with 32-bit Streaming Interface
//
// NIST SP 800-38C / RFC 3610: 128-bit key, 13-byte nonce, configurable tag.
//
// This module accepts 32-bit streaming input, compatible with the unified
// data formatter output. It internally packs 4 x 32-bit words into 128-bit
// blocks before AES processing.
//
// Cipher Suites:
//   Suite 0: AES-CCM-16-64-128  (Tlen=8)
//   Suite 2: AES-CCM-16-128-128 (Tlen=16)
//
// Features:
//   - 32-bit streaming input (compatible with formatter output)
//   - Internal 4-word (128-bit) packing buffer
//   - AAD carry buffer for 2-byte length header shift
//   - Hardware auto-padding for partial final blocks
//   - Hardware tag truncation
//   - Constant-time tag verification
//   - Soft-reset: start pulse works from any FSM state
//
// Protocol:
//   1. Configure params, pulse start (wait for ready)
//   2. Assert aad_phase=1, stream AAD via data_in 32-bit at a time
//      Assert data_last on final AAD word, set data_bytes for partial
//   3. Assert aad_phase=0, stream message (PT for encrypt, CT for decrypt)
//      Assert data_last on final message word
//   4. Collect ct_data on ct_valid (32-bit streaming output)
//   5. done=1: tag_out valid (truncated to tag_len bytes)
//      For decrypt: tag_match = constant-time comparison with tag_expected
//////////////////////////////////////////////////////////////////////////////////

module aes_ccm_32 (
    input  wire         clk,
    input  wire         rst,

    // ════════════════════════════════════════════════════════════════════════
    // CONTROL INTERFACE
    // ════════════════════════════════════════════════════════════════════════
    input  wire         start,          // Start operation (latches all config)
    input  wire         decrypt,        // 0=encrypt, 1=decrypt
    input  wire [127:0] key,            // AES-128 key
    input  wire [103:0] nonce,          // 13-byte nonce
    input  wire [4:0]   tag_len,        // Tag length in bytes (4,6,8,10,12,14,16)
    input  wire [15:0]  aad_len,        // Total AAD bytes
    input  wire [15:0]  msg_len,        // Total message bytes

    // ════════════════════════════════════════════════════════════════════════
    // 32-BIT STREAMING INPUT (compatible with formatter output)
    // ════════════════════════════════════════════════════════════════════════
    input  wire [31:0]  data_in,        // 32-bit input word (MSB-first)
    input  wire         data_valid,     // Input word valid
    input  wire         data_last,      // Last word of current segment
    input  wire [1:0]   data_bytes,     // Valid bytes in last word: 0=4, 1=1, 2=2, 3=3
    input  wire         aad_phase,      // 1=feeding AAD, 0=feeding message
    output wire         data_ready,     // Ready to accept input

    // ════════════════════════════════════════════════════════════════════════
    // DECRYPT TAG VERIFICATION
    // ════════════════════════════════════════════════════════════════════════
    input  wire [127:0] tag_expected,   // Expected tag for constant-time comparison

    // ════════════════════════════════════════════════════════════════════════
    // 32-BIT STREAMING OUTPUT
    // ════════════════════════════════════════════════════════════════════════
    output reg  [31:0]  ct_out,         // 32-bit output word
    output reg          ct_valid,       // Output word valid
    output reg          ct_last,        // Last word of output
    output reg  [1:0]   ct_bytes,       // Valid bytes in last word

    // ════════════════════════════════════════════════════════════════════════
    // COMPLETION
    // ════════════════════════════════════════════════════════════════════════
    output reg  [127:0] tag_out,        // Authentication tag (truncated)
    output reg          done,           // Operation complete
    output wire         ready,          // Ready for new operation
    output wire         tag_match       // Constant-time tag verification
);

    // ========================================================================
    // FSM States
    // ========================================================================
    localparam [4:0] S_IDLE          = 5'd0;
    localparam [4:0] S_B0_WAIT       = 5'd1;
    localparam [4:0] S_AAD_PACK      = 5'd2;   // Packing 32-bit AAD words
    localparam [4:0] S_AAD_PROCESS   = 5'd3;   // Processing packed AAD block
    localparam [4:0] S_AAD_WAIT      = 5'd4;   // Waiting for AES on AAD
    localparam [4:0] S_MSG_PACK      = 5'd5;   // Packing 32-bit message words
    localparam [4:0] S_ENC_CBC_WAIT  = 5'd6;   // Encrypt: CBC-MAC AES wait
    localparam [4:0] S_ENC_CTR_WAIT  = 5'd7;   // Encrypt: CTR AES wait
    localparam [4:0] S_ENC_OUTPUT    = 5'd8;   // Encrypt: Output CT words
    localparam [4:0] S_A0_WAIT       = 5'd9;   // Computing E(A0) for tag
    localparam [4:0] S_DEC_CTR_WAIT  = 5'd10;  // Decrypt: CTR AES wait
    localparam [4:0] S_DEC_OUTPUT    = 5'd11;  // Decrypt: Output PT words
    localparam [4:0] S_DEC_CBC_WAIT  = 5'd12;  // Decrypt: CBC-MAC AES wait
    localparam [4:0] S_DONE          = 5'd13;

    reg [4:0] state;

    // ========================================================================
    // Configuration registers (latched on start)
    // ========================================================================
    reg         r_decrypt;
    reg [127:0] r_key;
    reg [103:0] r_nonce;
    reg [4:0]   r_tag_len;
    reg [15:0]  r_aad_len;
    reg [15:0]  r_msg_len;

    // ========================================================================
    // Working registers
    // ========================================================================
    reg [127:0] cbc_state;          // CBC-MAC accumulator
    reg [127:0] e_a0;               // Saved E(A0) for tag computation
    reg [127:0] pack_buf;           // 4-word (128-bit) packing buffer
    reg [127:0] ct_buf;             // Output buffer (128-bit)
    reg [1:0]   pack_cnt;           // Words packed (0-3)
    reg [1:0]   out_cnt;            // Output word counter (0-3)
    reg [15:0]  aad_remaining;      // AAD bytes remaining to receive
    reg [15:0]  msg_remaining;      // Message bytes remaining
    reg [15:0]  ctr_idx;            // CTR counter (1,2,...)
    reg         aad_first;          // First AAD block needs length header
    reg [15:0]  aad_carry;          // 2-byte carry buffer for AAD shift
    reg [15:0]  aad_blk_rem;        // Internal 16B AAD blocks remaining
    reg [4:0]   final_bytes;        // Valid bytes in final output block (1-16)
    reg         is_final_blk;       // Current block is the final one
    reg         aad_data_pending;   // pack_buf has valid AAD data to process

    // ========================================================================
    // AES Core
    // ========================================================================
    reg          aes_start;
    reg  [127:0] aes_din;
    wire [127:0] aes_dout;
    wire         aes_done;
    wire         aes_busy;

    aes128_core u_aes (
        .clk      (clk),
        .rst      (rst),
        .start    (aes_start),
        .key_in   (r_key),
        .data_in  (aes_din),
        .data_out (aes_dout),
        .done     (aes_done),
        .busy     (aes_busy)
    );

    // ========================================================================
    // Ready and data_ready signals
    // ========================================================================
    assign ready = (state == S_IDLE);
    assign data_ready = (state == S_AAD_PACK) || (state == S_MSG_PACK);

    // ========================================================================
    // Tag truncation mask
    // ========================================================================
    reg [127:0] tag_mask;
    always @(*) begin
        case (r_tag_len)
            5'd4:    tag_mask = 128'hFFFFFFFF_00000000_00000000_00000000;
            5'd6:    tag_mask = 128'hFFFFFFFFFFFF_0000_00000000_00000000;
            5'd8:    tag_mask = 128'hFFFFFFFF_FFFFFFFF_00000000_00000000;
            5'd10:   tag_mask = 128'hFFFFFFFF_FFFFFFFF_FFFF0000_00000000;
            5'd12:   tag_mask = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_00000000;
            5'd14:   tag_mask = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFF0000;
            5'd16:   tag_mask = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF;
            default: tag_mask = 128'hFFFFFFFF_FFFFFFFF_00000000_00000000;
        endcase
    end

    // ========================================================================
    // Constant-time tag verification
    // ========================================================================
    assign tag_match = ((tag_out ^ tag_expected) & tag_mask) == 128'h0;

    // ========================================================================
    // Auto-padding mask for partial final message block
    // ========================================================================
    reg [127:0] auto_pad_mask;
    always @(*) begin
        case (final_bytes)
            4'd1:    auto_pad_mask = 128'hFF000000_00000000_00000000_00000000;
            4'd2:    auto_pad_mask = 128'hFFFF0000_00000000_00000000_00000000;
            4'd3:    auto_pad_mask = 128'hFFFFFF00_00000000_00000000_00000000;
            4'd4:    auto_pad_mask = 128'hFFFFFFFF_00000000_00000000_00000000;
            4'd5:    auto_pad_mask = 128'hFFFFFFFF_FF000000_00000000_00000000;
            4'd6:    auto_pad_mask = 128'hFFFFFFFF_FFFF0000_00000000_00000000;
            4'd7:    auto_pad_mask = 128'hFFFFFFFF_FFFFFF00_00000000_00000000;
            4'd8:    auto_pad_mask = 128'hFFFFFFFF_FFFFFFFF_00000000_00000000;
            4'd9:    auto_pad_mask = 128'hFFFFFFFF_FFFFFFFF_FF000000_00000000;
            4'd10:   auto_pad_mask = 128'hFFFFFFFF_FFFFFFFF_FFFF0000_00000000;
            4'd11:   auto_pad_mask = 128'hFFFFFFFF_FFFFFFFF_FFFFFF00_00000000;
            4'd12:   auto_pad_mask = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_00000000;
            4'd13:   auto_pad_mask = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_FF000000;
            4'd14:   auto_pad_mask = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFF0000;
            4'd15:   auto_pad_mask = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFF00;
            default: auto_pad_mask = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF;
        endcase
    end

    // ========================================================================
    // B0 formatting (combinational, valid when start asserted)
    // B0 = Flags(1) || Nonce(13) || Q(2)
    // Flags = 0 | Adata | (t-2)/2 | (q-1)    q=2 for 13-byte nonce
    // ========================================================================
    wire        has_aad  = (aad_len > 16'd0);
    wire [2:0]  t_field  = (tag_len - 5'd2) >> 1;
    wire [7:0]  b0_flags = {1'b0, has_aad, t_field, 3'b001};

    // ========================================================================
    // AAD block count: ceil((aad_len + 2) / 16)
    // ========================================================================
    wire [16:0] aad_plus17   = {1'b0, aad_len} + 17'd17;
    wire [15:0] aad_blk_count = aad_plus17[16:4];

    // ========================================================================
    // Bytes packed calculation (for partial last word)
    // ========================================================================
    wire [3:0] bytes_in_word = (data_bytes == 2'd0) ? 4'd4 :
                               (data_bytes == 2'd1) ? 4'd1 :
                               (data_bytes == 2'd2) ? 4'd2 : 4'd3;

    // ========================================================================
    // Combinational: compute new pack_buf value when accepting a word
    // This allows us to use the NEW value in same-cycle AES operations
    // ========================================================================
    reg [127:0] pack_buf_next;
    always @(*) begin
        pack_buf_next = pack_buf;
        if (data_valid) begin
            case (pack_cnt)
                2'd0: pack_buf_next[127:96] = data_in;
                2'd1: pack_buf_next[95:64]  = data_in;
                2'd2: pack_buf_next[63:32]  = data_in;
                2'd3: pack_buf_next[31:0]   = data_in;
            endcase
        end
    end

    // ========================================================================
    // Combinational: compute final_bytes for current word
    // ========================================================================
    wire [4:0] final_bytes_next = {1'b0, pack_cnt, 2'b00} + {1'b0, bytes_in_word};

    // ========================================================================
    // Combinational: auto_pad_mask for incoming final block
    // ========================================================================
    reg [127:0] auto_pad_mask_next;
    always @(*) begin
        case (final_bytes_next)
            5'd1:    auto_pad_mask_next = 128'hFF000000_00000000_00000000_00000000;
            5'd2:    auto_pad_mask_next = 128'hFFFF0000_00000000_00000000_00000000;
            5'd3:    auto_pad_mask_next = 128'hFFFFFF00_00000000_00000000_00000000;
            5'd4:    auto_pad_mask_next = 128'hFFFFFFFF_00000000_00000000_00000000;
            5'd5:    auto_pad_mask_next = 128'hFFFFFFFF_FF000000_00000000_00000000;
            5'd6:    auto_pad_mask_next = 128'hFFFFFFFF_FFFF0000_00000000_00000000;
            5'd7:    auto_pad_mask_next = 128'hFFFFFFFF_FFFFFF00_00000000_00000000;
            5'd8:    auto_pad_mask_next = 128'hFFFFFFFF_FFFFFFFF_00000000_00000000;
            5'd9:    auto_pad_mask_next = 128'hFFFFFFFF_FFFFFFFF_FF000000_00000000;
            5'd10:   auto_pad_mask_next = 128'hFFFFFFFF_FFFFFFFF_FFFF0000_00000000;
            5'd11:   auto_pad_mask_next = 128'hFFFFFFFF_FFFFFFFF_FFFFFF00_00000000;
            5'd12:   auto_pad_mask_next = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_00000000;
            5'd13:   auto_pad_mask_next = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_FF000000;
            5'd14:   auto_pad_mask_next = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFF0000;
            5'd15:   auto_pad_mask_next = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFF00;
            default: auto_pad_mask_next = 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF; // 16 or 0
        endcase
    end

    // ========================================================================
    // Main FSM
    // ========================================================================
    always @(posedge clk) begin
        if (rst) begin
            state          <= S_IDLE;
            aes_start      <= 1'b0;
            aes_din        <= 128'h0;
            done           <= 1'b0;
            ct_valid       <= 1'b0;
            ct_last        <= 1'b0;
            ct_out         <= 32'h0;
            ct_bytes       <= 2'd0;
            cbc_state      <= 128'h0;
            e_a0           <= 128'h0;
            tag_out        <= 128'h0;
            pack_buf       <= 128'h0;
            ct_buf         <= 128'h0;
            pack_cnt       <= 2'd0;
            out_cnt        <= 2'd0;
            r_decrypt      <= 1'b0;
            r_key          <= 128'h0;
            r_nonce        <= 104'h0;
            r_tag_len      <= 5'd0;
            r_aad_len      <= 16'h0;
            r_msg_len      <= 16'h0;
            aad_remaining  <= 16'h0;
            msg_remaining  <= 16'h0;
            ctr_idx        <= 16'h0;
            aad_first      <= 1'b0;
            aad_carry      <= 16'h0;
            aad_blk_rem    <= 16'h0;
            final_bytes    <= 5'd0;
            is_final_blk   <= 1'b0;
            aad_data_pending <= 1'b0;
        end else begin
            // Default: clear single-cycle pulses
            aes_start <= 1'b0;
            done      <= 1'b0;
            ct_valid  <= 1'b0;
            ct_last   <= 1'b0;

            if (start) begin
                // ============================================================
                // Soft-reset from ANY state: latch config, begin B0
                // ============================================================
                r_decrypt      <= decrypt;
                r_key          <= key;
                r_nonce        <= nonce;
                r_tag_len      <= tag_len;
                r_aad_len      <= aad_len;
                r_msg_len      <= msg_len;
                aad_remaining  <= aad_len;
                aad_blk_rem    <= (aad_len > 16'd0) ? aad_blk_count : 16'd0;
                msg_remaining  <= msg_len;
                cbc_state      <= 128'h0;
                e_a0           <= 128'h0;
                tag_out        <= 128'h0;
                pack_buf       <= 128'h0;
                pack_cnt       <= 2'd0;
                out_cnt        <= 2'd0;
                ctr_idx        <= 16'h1;
                aad_first      <= 1'b1;
                aad_carry      <= 16'h0;
                final_bytes    <= 5'd0;
                is_final_blk   <= 1'b0;
                aad_data_pending <= 1'b0;

                // Start: E_K(B0)
                aes_din   <= {b0_flags, nonce, msg_len};
                aes_start <= 1'b1;
                state     <= S_B0_WAIT;

            end else begin
                case (state)

                    // ========================================================
                    S_IDLE: begin
                        // Waiting for start
                    end

                    // ========================================================
                    // B0 AES done → cbc = E(B0)
                    // ========================================================
                    S_B0_WAIT: begin
                        if (aes_done) begin
                            cbc_state <= aes_dout;
                            if (r_aad_len > 16'd0) begin
                                pack_buf <= 128'h0;
                                pack_cnt <= 2'd0;
                                state    <= S_AAD_PACK;
                            end else if (r_msg_len > 16'd0) begin
                                pack_buf <= 128'h0;
                                pack_cnt <= 2'd0;
                                if (r_decrypt) begin
                                    // For decrypt, compute E(A0) first
                                    aes_din   <= {8'h01, r_nonce, 16'h0000};
                                    aes_start <= 1'b1;
                                    state     <= S_A0_WAIT;
                                end else begin
                                    state <= S_MSG_PACK;
                                end
                            end else begin
                                // No AAD, no message — just compute tag
                                aes_din   <= {8'h01, r_nonce, 16'h0000};
                                aes_start <= 1'b1;
                                state     <= S_A0_WAIT;
                            end
                        end
                    end

                    // ========================================================
                    // AAD: Pack 32-bit words into 128-bit buffer
                    // ========================================================
                    S_AAD_PACK: begin
                        if (data_valid && aad_phase) begin
                            // Store new word using combinational next value
                            pack_buf <= pack_buf_next;
                            aad_data_pending <= 1'b1;  // Mark that pack_buf has valid data

                            // Update bytes remaining
                            if (aad_remaining >= {12'h0, bytes_in_word})
                                aad_remaining <= aad_remaining - {12'h0, bytes_in_word};
                            else
                                aad_remaining <= 16'd0;

                            if (data_last || pack_cnt == 2'd3) begin
                                // Block complete or last AAD word - go process
                                state <= S_AAD_PROCESS;
                            end else begin
                                pack_cnt <= pack_cnt + 2'd1;
                            end
                        end else if (aad_remaining == 16'd0 && aad_blk_rem > 16'd0) begin
                            // Flush remaining carry (no new data)
                            aad_data_pending <= 1'b0;
                            state <= S_AAD_PROCESS;
                        end
                    end

                    // ========================================================
                    // AAD: Process packed block (with 2-byte header shift)
                    // ========================================================
                    S_AAD_PROCESS: begin
                        if (aad_first) begin
                            // First block: {2B aad_len header, 14B data}
                            aes_din   <= cbc_state ^ {r_aad_len, pack_buf[127:16]};
                            aad_carry <= pack_buf[15:0];
                            aad_first <= 1'b0;
                        end else if (aad_data_pending) begin
                            // Subsequent: {2B carry, 14B new data}
                            aes_din   <= cbc_state ^ {aad_carry, pack_buf[127:16]};
                            aad_carry <= pack_buf[15:0];
                        end else begin
                            // Flush carry (zero-padded)
                            aes_din <= cbc_state ^ {aad_carry, 112'h0};
                        end
                        aes_start        <= 1'b1;
                        aad_data_pending <= 1'b0;  // Clear pending flag after use
                        pack_buf         <= 128'h0;
                        pack_cnt         <= 2'd0;  // Reset counter for next block
                        state            <= S_AAD_WAIT;
                    end

                    // ========================================================
                    // AAD: Wait for AES completion
                    // ========================================================
                    S_AAD_WAIT: begin
                        if (aes_done) begin
                            cbc_state   <= aes_dout;
                            aad_blk_rem <= aad_blk_rem - 16'd1;

                            if (aad_blk_rem > 16'd1) begin
                                // More AAD blocks needed
                                if (aad_remaining > 16'd0)
                                    state <= S_AAD_PACK;
                                else
                                    state <= S_AAD_PROCESS; // Flush remaining
                            end else if (r_msg_len > 16'd0) begin
                                // AAD done, process message
                                pack_buf <= 128'h0;
                                pack_cnt <= 2'd0;
                                if (r_decrypt) begin
                                    aes_din   <= {8'h01, r_nonce, 16'h0000};
                                    aes_start <= 1'b1;
                                    state     <= S_A0_WAIT;
                                end else begin
                                    state <= S_MSG_PACK;
                                end
                            end else begin
                                // No message, compute tag
                                aes_din   <= {8'h01, r_nonce, 16'h0000};
                                aes_start <= 1'b1;
                                state     <= S_A0_WAIT;
                            end
                        end
                    end

                    // ========================================================
                    // MSG: Pack 32-bit words into 128-bit buffer
                    // ========================================================
                    S_MSG_PACK: begin
                        if (data_valid && !aad_phase) begin
                            // Store new word into pack_buf
                            pack_buf <= pack_buf_next;

                            // Track final block
                            if (data_last) begin
                                final_bytes <= final_bytes_next;
                                is_final_blk <= 1'b1;
                            end

                            // Update remaining
                            if (msg_remaining >= {12'h0, bytes_in_word})
                                msg_remaining <= msg_remaining - {12'h0, bytes_in_word};
                            else
                                msg_remaining <= 16'd0;

                            if (data_last || pack_cnt == 2'd3) begin
                                // Process block - use pack_buf_next (includes current data_in)
                                pack_cnt <= 2'd0;
                                if (r_decrypt) begin
                                    // Decrypt: CTR first
                                    aes_din   <= {8'h01, r_nonce, ctr_idx};
                                    aes_start <= 1'b1;
                                    state     <= S_DEC_CTR_WAIT;
                                end else begin
                                    // Encrypt: CBC-MAC first
                                    // Use pack_buf_next and auto_pad_mask_next for same-cycle data
                                    if (data_last)
                                        aes_din <= cbc_state ^ (pack_buf_next & auto_pad_mask_next);
                                    else
                                        aes_din <= cbc_state ^ pack_buf_next;
                                    aes_start <= 1'b1;
                                    state     <= S_ENC_CBC_WAIT;
                                end
                            end else begin
                                pack_cnt <= pack_cnt + 2'd1;
                            end
                        end
                    end

                    // ========================================================
                    // ENCRYPT: CBC-MAC AES done → start CTR
                    // ========================================================
                    S_ENC_CBC_WAIT: begin
                        if (aes_done) begin
                            cbc_state <= aes_dout;
                            aes_din   <= {8'h01, r_nonce, ctr_idx};
                            aes_start <= 1'b1;
                            state     <= S_ENC_CTR_WAIT;
                        end
                    end

                    // ========================================================
                    // ENCRYPT: CTR AES done → output ciphertext
                    // ========================================================
                    S_ENC_CTR_WAIT: begin
                        if (aes_done) begin
                            if (is_final_blk)
                                ct_buf <= (pack_buf ^ aes_dout) & auto_pad_mask;
                            else
                                ct_buf <= pack_buf ^ aes_dout;
                            out_cnt   <= 2'd0;
                            ctr_idx   <= ctr_idx + 16'd1;
                            state     <= S_ENC_OUTPUT;
                        end
                    end

                    // ========================================================
                    // ENCRYPT: Stream out 32-bit CT words
                    // ========================================================
                    S_ENC_OUTPUT: begin
                        // Output current word
                        case (out_cnt)
                            2'd0: ct_out <= ct_buf[127:96];
                            2'd1: ct_out <= ct_buf[95:64];
                            2'd2: ct_out <= ct_buf[63:32];
                            2'd3: ct_out <= ct_buf[31:0];
                        endcase
                        ct_valid <= 1'b1;

                        // Check for last output word
                        if (is_final_blk) begin
                            // Determine if this is the last word with valid bytes
                            // final_bytes is 1-16, determine which word contains the last valid byte
                            if ((out_cnt == 2'd0 && final_bytes <= 5'd4) ||
                                (out_cnt == 2'd1 && final_bytes <= 5'd8 && final_bytes > 5'd4) ||
                                (out_cnt == 2'd2 && final_bytes <= 5'd12 && final_bytes > 5'd8) ||
                                (out_cnt == 2'd3 && final_bytes <= 5'd16 && final_bytes > 5'd12)) begin
                                ct_last <= 1'b1;
                                // Set valid bytes for last word
                                case (final_bytes[1:0])
                                    2'd0: ct_bytes <= 2'd0; // 4 bytes (or 8, 12, 16)
                                    2'd1: ct_bytes <= 2'd1;
                                    2'd2: ct_bytes <= 2'd2;
                                    2'd3: ct_bytes <= 2'd3;
                                endcase
                                // Go compute tag
                                pack_buf     <= 128'h0;
                                is_final_blk <= 1'b0;
                                aes_din      <= {8'h01, r_nonce, 16'h0000};
                                aes_start    <= 1'b1;
                                state        <= S_A0_WAIT;
                            end else begin
                                out_cnt <= out_cnt + 2'd1;
                            end
                        end else begin
                            if (out_cnt == 2'd3) begin
                                // Full block done, get more input
                                state <= S_MSG_PACK;
                            end else begin
                                out_cnt <= out_cnt + 2'd1;
                            end
                        end
                    end

                    // ========================================================
                    // A0: Compute E(A0) for tag
                    // ========================================================
                    S_A0_WAIT: begin
                        if (aes_done) begin
                            e_a0    <= aes_dout;
                            tag_out <= (cbc_state ^ aes_dout) & tag_mask;

                            if (r_decrypt && r_msg_len > 16'd0 && msg_remaining == r_msg_len) begin
                                // Start decrypt message processing
                                pack_buf <= 128'h0;
                                pack_cnt <= 2'd0;
                                state    <= S_MSG_PACK;
                            end else begin
                                done  <= 1'b1;
                                state <= S_DONE;
                            end
                        end
                    end

                    // ========================================================
                    // DECRYPT: CTR AES done → output plaintext
                    // ========================================================
                    S_DEC_CTR_WAIT: begin
                        if (aes_done) begin
                            if (is_final_blk)
                                ct_buf <= (pack_buf ^ aes_dout) & auto_pad_mask;
                            else
                                ct_buf <= pack_buf ^ aes_dout;
                            out_cnt <= 2'd0;
                            state   <= S_DEC_OUTPUT;
                        end
                    end

                    // ========================================================
                    // DECRYPT: Stream out 32-bit PT words, then CBC-MAC
                    // ========================================================
                    S_DEC_OUTPUT: begin
                        // Output current word
                        case (out_cnt)
                            2'd0: ct_out <= ct_buf[127:96];
                            2'd1: ct_out <= ct_buf[95:64];
                            2'd2: ct_out <= ct_buf[63:32];
                            2'd3: ct_out <= ct_buf[31:0];
                        endcase
                        ct_valid <= 1'b1;

                        // Check for last output word of this block
                        if (is_final_blk) begin
                            if ((out_cnt == 2'd0 && final_bytes <= 5'd4) ||
                                (out_cnt == 2'd1 && final_bytes <= 5'd8 && final_bytes > 5'd4) ||
                                (out_cnt == 2'd2 && final_bytes <= 5'd12 && final_bytes > 5'd8) ||
                                (out_cnt == 2'd3 && final_bytes <= 5'd16 && final_bytes > 5'd12)) begin
                                ct_last <= 1'b1;
                                case (final_bytes[1:0])
                                    2'd0: ct_bytes <= 2'd0;
                                    2'd1: ct_bytes <= 2'd1;
                                    2'd2: ct_bytes <= 2'd2;
                                    2'd3: ct_bytes <= 2'd3;
                                endcase
                                // Start CBC-MAC on plaintext
                                aes_din   <= cbc_state ^ (ct_buf & auto_pad_mask);
                                aes_start <= 1'b1;
                                state     <= S_DEC_CBC_WAIT;
                            end else begin
                                out_cnt <= out_cnt + 2'd1;
                            end
                        end else begin
                            if (out_cnt == 2'd3) begin
                                // Block output done, start CBC-MAC
                                aes_din   <= cbc_state ^ ct_buf;
                                aes_start <= 1'b1;
                                state     <= S_DEC_CBC_WAIT;
                            end else begin
                                out_cnt <= out_cnt + 2'd1;
                            end
                        end
                    end

                    // ========================================================
                    // DECRYPT: CBC-MAC AES done
                    // ========================================================
                    S_DEC_CBC_WAIT: begin
                        if (aes_done) begin
                            cbc_state <= aes_dout;
                            ctr_idx   <= ctr_idx + 16'd1;

                            if (msg_remaining == 16'd0) begin
                                // All done, compute final tag
                                tag_out <= (aes_dout ^ e_a0) & tag_mask;
                                done    <= 1'b1;
                                state   <= S_DONE;
                            end else begin
                                // Get more input
                                pack_buf     <= 128'h0;
                                is_final_blk <= 1'b0;
                                state        <= S_MSG_PACK;
                            end
                        end
                    end

                    // ========================================================
                    S_DONE: begin
                        state <= S_IDLE;
                    end

                    default: state <= S_IDLE;
                endcase
            end
        end
    end

endmodule

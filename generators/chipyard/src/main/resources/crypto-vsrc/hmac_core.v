`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// HMAC-SHA256 Core with Native Streaming Interface (Optimized v2)
//
// Optimizations vs. initial streaming version:
//   1. Removed dead state S_MSG_LOAD
//   2. Removed dead signals (inner_idx, inner_word)
//   3. Merged S_IPAD_WAIT/S_OPAD_WAIT into parent states
//   4. Reduced state count from 19 to 16, state reg from 5 to 4 bits
//   5. Fixed digest read order (compress outputs H7-first via shift)
//   6. Added pre-read pulse for proper compress pipeline priming
//
// Note: 16-word msg_buf retained because SHA controller's rloadcounter
//   resets on any cycle without msg_valid, which drives sha_pad's pad_line.
//   Continuous feeding (no gaps) is required for correct padding.
//
// Modes:
//   mode=0: Pure SHA-256 hash (no key)
//   mode=1: HMAC-SHA256 with key
//
// Protocol:
//   1. Set mode (msg_len optional - auto-computed from data_bytes)
//   2. Pulse start
//   3. For HMAC: feed key chunks via key_in/key_valid (32-bit, MSB-first)
//   4. Feed message chunks via data_in/data_valid (32-bit, MSB-first)
//      Use data_bytes to indicate valid bytes in each word (especially last)
//   5. Assert last_block with final chunk
//   6. Wait for done=1
//   7. Read hash_out (256-bit result)
//
// data_bytes encoding (compatible with AES-CCM-32):
//   0 = 4 bytes valid
//   1 = 1 byte valid (MSB)
//   2 = 2 bytes valid
//   3 = 3 bytes valid
//////////////////////////////////////////////////////////////////////////////////

module hmac_core (
    input  wire         clk,
    input  wire         resetn,

    // ===== Control =====
    input  wire         start,
    input  wire         mode,           // 0=SHA-256, 1=HMAC-SHA256
    output wire         ready,
    output reg          done,
    output wire         busy,

    // ===== Key Input (HMAC mode only) =====
    input  wire [31:0]  key_in,
    input  wire         key_valid,
    input  wire         key_last,
    output wire         key_ready,

    // ===== Message Input (32-bit streaming, compatible with formatter) =====
    input  wire [31:0]  data_in,
    input  wire         data_valid,
    input  wire         last_block,
    input  wire [1:0]   data_bytes,     // Valid bytes: 0=4, 1=1, 2=2, 3=3
    output wire         data_ready,

    // ===== Length Configuration (optional: 0 = auto-compute from data_bytes) =====
    input  wire [63:0]  msg_len,        // Total message length in bits

    // ===== Output =====
    output wire [255:0] hash_out,
    output reg          hash_valid
);

    // ========================================================================
    // FSM States (16 states, 4-bit encoding)
    // ========================================================================
    localparam [3:0] S_IDLE         = 4'd0;
    localparam [3:0] S_KEY_LOAD     = 4'd1;
    localparam [3:0] S_SHA_START    = 4'd2;
    localparam [3:0] S_IPAD         = 4'd3;   // Feed K^ipad + wait (merged)
    localparam [3:0] S_MSG_FILL     = 4'd4;   // Accept user data into msg_buf
    localparam [3:0] S_MSG_PROCESS  = 4'd5;   // Feed msg_buf to SHA (no gaps)
    localparam [3:0] S_MSG_WAIT     = 4'd6;   // Wait for SHA block done
    localparam [3:0] S_INNER_DONE   = 4'd7;
    localparam [3:0] S_SAVE_INNER   = 4'd8;
    localparam [3:0] S_SHA_RESET    = 4'd9;
    localparam [3:0] S_SHA_START2   = 4'd10;
    localparam [3:0] S_OPAD         = 4'd11;  // Feed K^opad + wait (merged)
    localparam [3:0] S_INNER_FEED   = 4'd12;
    localparam [3:0] S_OUTER_WAIT   = 4'd13;
    localparam [3:0] S_READ_DIGEST  = 4'd14;
    localparam [3:0] S_DONE         = 4'd15;

    reg [3:0] state;

    // ========================================================================
    // Configuration Registers
    // ========================================================================
    reg         r_mode;
    reg [63:0]  r_msg_len;
    reg         r_auto_len;         // 1 = auto-compute msg_len from data_bytes

    // ========================================================================
    // Byte Counter (for auto-computing message length)
    // ========================================================================
    reg [63:0]  byte_cnt;           // Total message bytes received

    // ========================================================================
    // Key Storage (256-bit = 8 x 32-bit words)
    // ========================================================================
    (* ram_style = "distributed" *) reg [31:0] key_buf [0:7];
    reg [3:0]  key_cnt;
    reg        key_loaded;

    // ========================================================================
    // Message Block Buffer (512-bit = 16 x 32-bit words)
    // Required: SHA controller's rloadcounter resets on msg_valid gaps,
    // which corrupts sha_pad's pad_line. Must feed continuously.
    // ========================================================================
    (* ram_style = "distributed" *) reg [31:0] msg_buf [0:15];
    reg [4:0]  msg_idx;             // Fill position in msg_buf (0-15)
    reg        block_full;          // Buffer ready to feed to SHA
    reg        msg_all_fed;         // All user message data received

    // ========================================================================
    // Partial byte handling
    // ========================================================================
    wire [2:0] bytes_in_word = (data_bytes == 2'd0) ? 3'd4 :
                               (data_bytes == 2'd1) ? 3'd1 :
                               (data_bytes == 2'd2) ? 3'd2 : 3'd3;

    // Mask for partial last word (MSB-first)
    reg [31:0] last_word_masked;
    always @(*) begin
        case (data_bytes)
            2'd0: last_word_masked = data_in;                              // 4 bytes
            2'd1: last_word_masked = {data_in[31:24], 24'h0};              // 1 byte
            2'd2: last_word_masked = {data_in[31:16], 16'h0};              // 2 bytes
            2'd3: last_word_masked = {data_in[31:8], 8'h0};                // 3 bytes
        endcase
    end

    // ========================================================================
    // Block Position Counter (shared: ipad/opad/msg_process/inner_feed)
    // ========================================================================
    reg [4:0]  word_cnt;

    // ========================================================================
    // Inner Hash Storage (for HMAC outer pass)
    // ========================================================================
    reg [255:0] inner_hash;

    // ========================================================================
    // Digest Output
    // ========================================================================
    reg [255:0] digest_buf;
    reg [2:0]   digest_idx;
    assign hash_out = digest_buf;

    // ========================================================================
    // SHA Core Interface
    // ========================================================================
    reg         sha_start;
    wire        sha_valid;
    wire [31:0] sha_digest;
    reg         sha_read;
    wire        sha_ready2load;
    reg  [31:0] sha_message;
    reg         sha_msg_valid;
    reg         sha_load_finish;
    reg  [63:0] sha_bitcount;

    wire        sha_resetn;
    reg         local_reset;
    assign sha_resetn = resetn & ~local_reset;

    // ========================================================================
    // SHA Core Instance
    // ========================================================================
    sha_core sha_core_inst (
        .clk        (clk),
        .resetn     (sha_resetn),
        .start      (sha_start),
        .sha_valid  (sha_valid),
        .digest     (sha_digest),
        .read       (sha_read),
        .ready2load (sha_ready2load),
        .imessage   (sha_message),
        .msg_valid  (sha_msg_valid),
        .load_finish(sha_load_finish),
        .ibitCount  (sha_bitcount)
    );

    // ========================================================================
    // Status Signals
    // ========================================================================
    assign ready     = (state == S_IDLE);
    assign busy      = (state != S_IDLE);
    assign key_ready = (state == S_KEY_LOAD) && !key_loaded;
    assign data_ready = (state == S_MSG_FILL) && !block_full && !msg_all_fed;

    // ========================================================================
    // FSM: Sequential
    // ========================================================================
    integer i;

    always @(posedge clk or negedge resetn) begin
        if (!resetn) begin
            state           <= S_IDLE;
            r_mode          <= 1'b0;
            r_msg_len       <= 64'd0;
            r_auto_len      <= 1'b0;
            byte_cnt        <= 64'd0;
            key_cnt         <= 4'd0;
            key_loaded      <= 1'b0;
            msg_idx         <= 5'd0;
            block_full      <= 1'b0;
            msg_all_fed     <= 1'b0;
            word_cnt        <= 5'd0;
            inner_hash      <= 256'd0;
            digest_buf      <= 256'd0;
            digest_idx      <= 3'd0;
            sha_start       <= 1'b0;
            sha_read        <= 1'b0;
            sha_message     <= 32'd0;
            sha_msg_valid   <= 1'b0;
            sha_load_finish <= 1'b0;
            sha_bitcount    <= 64'd0;
            local_reset     <= 1'b0;
            done            <= 1'b0;
            hash_valid      <= 1'b0;
            for (i = 0; i < 8; i = i + 1) key_buf[i] <= 32'd0;
            for (i = 0; i < 16; i = i + 1) msg_buf[i] <= 32'd0;
        end else begin
            // Default: clear single-cycle pulses
            sha_start       <= 1'b0;
            sha_msg_valid   <= 1'b0;
            sha_load_finish <= 1'b0;
            sha_read        <= 1'b0;
            local_reset     <= 1'b0;
            done            <= 1'b0;

            case (state)
                // ============================================================
                S_IDLE: begin
                    hash_valid <= 1'b0;
                    if (start) begin
                        r_mode       <= mode;
                        r_msg_len    <= msg_len;
                        r_auto_len   <= (msg_len == 64'd0);  // Auto-compute if msg_len not provided
                        byte_cnt     <= 64'd0;
                        key_cnt      <= 4'd0;
                        key_loaded   <= 1'b0;
                        msg_idx      <= 5'd0;
                        block_full   <= 1'b0;
                        msg_all_fed  <= 1'b0;
                        word_cnt     <= 5'd0;
                        digest_idx   <= 3'd0;
                        digest_buf   <= 256'd0;
                        for (i = 0; i < 8; i = i + 1) key_buf[i] <= 32'd0;
                        for (i = 0; i < 16; i = i + 1) msg_buf[i] <= 32'd0;

                        if (mode) begin
                            state <= S_KEY_LOAD;
                        end else begin
                            // For SHA-256 mode: set bitcount or placeholder
                            if (msg_len != 64'd0)
                                sha_bitcount <= msg_len;
                            else
                                sha_bitcount <= 64'hFFFF_FFFF_FFFF_FFFF; // Placeholder for auto-len
                            state <= S_SHA_START;
                        end
                    end
                end

                // ============================================================
                // Load key words into buffer
                // ============================================================
                S_KEY_LOAD: begin
                    if (key_valid && !key_loaded) begin
                        key_buf[key_cnt[2:0]] <= key_in;
                        key_cnt <= key_cnt + 1;
                        if (key_last || key_cnt >= 4'd7) begin
                            key_loaded <= 1'b1;
                        end
                    end
                    if (key_loaded) begin
                        // For non-auto mode, set bitcount now
                        // For auto mode, use max placeholder (prevents early padding)
                        if (r_auto_len)
                            sha_bitcount <= 64'hFFFF_FFFF_FFFF_FFFF;
                        else
                            sha_bitcount <= 64'd512 + r_msg_len;
                        state <= S_SHA_START;
                    end
                end

                // ============================================================
                // Start SHA core
                // ============================================================
                S_SHA_START: begin
                    sha_start <= 1'b1;
                    word_cnt  <= 5'd0;
                    if (r_mode) begin
                        state <= S_IPAD;
                    end else begin
                        state <= S_MSG_FILL;
                    end
                end

                // ============================================================
                // HMAC: Feed K XOR ipad (16 words) + wait for next block
                // (Merged S_IPAD + S_IPAD_WAIT)
                // ============================================================
                S_IPAD: begin
                    if (sha_ready2load) begin
                        if (word_cnt < 5'd16) begin
                            if (word_cnt < 5'd8)
                                sha_message <= key_buf[word_cnt[2:0]] ^ 32'h36363636;
                            else
                                sha_message <= 32'h36363636;
                            sha_msg_valid <= 1'b1;
                            if (word_cnt == 5'd15)
                                sha_load_finish <= 1'b1;
                            word_cnt <= word_cnt + 1;
                        end else begin
                            // word_cnt==16: ipad done, SHA ready for message
                            word_cnt  <= 5'd0;
                            msg_idx   <= 5'd0;
                            block_full <= 1'b0;
                            state     <= S_MSG_FILL;
                        end
                    end
                end

                // ============================================================
                // Accept user data into msg_buf (decoupled from SHA timing)
                // ============================================================
                S_MSG_FILL: begin
                    if (data_valid && !msg_all_fed && !block_full) begin
                        // Use masked word for partial last word, else full word
                        if (last_block)
                            msg_buf[msg_idx[3:0]] <= last_word_masked;
                        else
                            msg_buf[msg_idx[3:0]] <= data_in;

                        // Track byte count
                        byte_cnt <= byte_cnt + {61'd0, bytes_in_word};
                        msg_idx  <= msg_idx + 1;

                        if (last_block) begin
                            msg_all_fed <= 1'b1;
                            block_full  <= 1'b1;
                            // For auto-len mode, compute final bitcount now
                            if (r_auto_len) begin
                                if (r_mode)
                                    sha_bitcount <= 64'd512 + ((byte_cnt + {61'd0, bytes_in_word}) << 3);
                                else
                                    sha_bitcount <= (byte_cnt + {61'd0, bytes_in_word}) << 3;
                            end
                        end else if (msg_idx == 5'd15) begin
                            block_full <= 1'b1;
                        end
                    end
                    if (block_full) begin
                        word_cnt <= 5'd0;
                        state    <= S_MSG_PROCESS;
                    end
                end

                // ============================================================
                // Feed msg_buf to SHA continuously (no gaps in msg_valid)
                // ============================================================
                S_MSG_PROCESS: begin
                    if (sha_ready2load) begin
                        sha_message   <= msg_buf[word_cnt[3:0]];
                        sha_msg_valid <= 1'b1;
                        word_cnt      <= word_cnt + 1;
                        if (word_cnt == 5'd15) begin
                            sha_load_finish <= 1'b1;
                            state <= S_MSG_WAIT;
                        end
                    end
                end

                // ============================================================
                // Wait for SHA block processing
                // ============================================================
                S_MSG_WAIT: begin
                    if (sha_valid) begin
                        if (r_mode)
                            state <= S_INNER_DONE;
                        else begin
                            digest_idx <= 3'd0;
                            sha_read   <= 1'b1;
                            state <= S_READ_DIGEST;
                        end
                    end else if (sha_ready2load && !msg_all_fed) begin
                        // More message blocks: reset buffer for next block
                        for (i = 0; i < 16; i = i + 1) msg_buf[i] <= 32'd0;
                        msg_idx    <= 5'd0;
                        block_full <= 1'b0;
                        word_cnt   <= 5'd0;
                        state      <= S_MSG_FILL;
                    end
                end

                // ============================================================
                // HMAC: Inner hash complete, begin reading digest
                // ============================================================
                S_INNER_DONE: begin
                    digest_idx <= 3'd0;
                    sha_read   <= 1'b1;
                    state      <= S_SAVE_INNER;
                end

                // ============================================================
                // Save inner hash (8 x 32-bit reads, H7-first from compress)
                // ============================================================
                S_SAVE_INNER: begin
                    sha_read <= 1'b1;
                    case (digest_idx)
                        3'd0: inner_hash[31:0]    <= sha_digest;
                        3'd1: inner_hash[63:32]   <= sha_digest;
                        3'd2: inner_hash[95:64]   <= sha_digest;
                        3'd3: inner_hash[127:96]  <= sha_digest;
                        3'd4: inner_hash[159:128] <= sha_digest;
                        3'd5: inner_hash[191:160] <= sha_digest;
                        3'd6: inner_hash[223:192] <= sha_digest;
                        3'd7: inner_hash[255:224] <= sha_digest;
                    endcase
                    digest_idx <= digest_idx + 1;
                    if (digest_idx == 3'd7)
                        state <= S_SHA_RESET;
                end

                // ============================================================
                // Reset SHA for outer hash
                // ============================================================
                S_SHA_RESET: begin
                    local_reset  <= 1'b1;
                    sha_bitcount <= 64'd768;    // 512 (opad) + 256 (inner hash)
                    word_cnt     <= 5'd0;
                    state        <= S_SHA_START2;
                end

                // ============================================================
                // Start SHA for outer hash
                // ============================================================
                S_SHA_START2: begin
                    sha_start <= 1'b1;
                    state     <= S_OPAD;
                end

                // ============================================================
                // HMAC: Feed K XOR opad (16 words) + wait for ready
                // (Merged S_OPAD + S_OPAD_WAIT)
                // ============================================================
                S_OPAD: begin
                    if (sha_ready2load) begin
                        if (word_cnt < 5'd16) begin
                            if (word_cnt < 5'd8)
                                sha_message <= key_buf[word_cnt[2:0]] ^ 32'h5c5c5c5c;
                            else
                                sha_message <= 32'h5c5c5c5c;
                            sha_msg_valid <= 1'b1;
                            if (word_cnt == 5'd15)
                                sha_load_finish <= 1'b1;
                            word_cnt <= word_cnt + 1;
                        end else begin
                            // word_cnt==16: opad done, feed inner hash
                            word_cnt <= 5'd0;
                            state    <= S_INNER_FEED;
                        end
                    end
                end

                // ============================================================
                // Feed inner hash as outer message (8 words + 8 zeros)
                // ============================================================
                S_INNER_FEED: begin
                    if (sha_ready2load) begin
                        if (word_cnt < 5'd8) begin
                            case (word_cnt[2:0])
                                3'd0: sha_message <= inner_hash[255:224];
                                3'd1: sha_message <= inner_hash[223:192];
                                3'd2: sha_message <= inner_hash[191:160];
                                3'd3: sha_message <= inner_hash[159:128];
                                3'd4: sha_message <= inner_hash[127:96];
                                3'd5: sha_message <= inner_hash[95:64];
                                3'd6: sha_message <= inner_hash[63:32];
                                3'd7: sha_message <= inner_hash[31:0];
                            endcase
                            sha_msg_valid <= 1'b1;
                        end else if (word_cnt < 5'd16) begin
                            sha_message   <= 32'd0;
                            sha_msg_valid <= 1'b1;
                        end
                        word_cnt <= word_cnt + 1;
                        if (word_cnt == 5'd15) begin
                            sha_load_finish <= 1'b1;
                            state <= S_OUTER_WAIT;
                        end
                    end
                end

                // ============================================================
                // Wait for outer hash to complete
                // ============================================================
                S_OUTER_WAIT: begin
                    if (sha_valid) begin
                        digest_idx <= 3'd0;
                        sha_read   <= 1'b1;
                        state <= S_READ_DIGEST;
                    end
                end

                // ============================================================
                // Read final digest (H7-first from compress shift register)
                // ============================================================
                S_READ_DIGEST: begin
                    sha_read <= 1'b1;
                    case (digest_idx)
                        3'd0: digest_buf[31:0]    <= sha_digest;
                        3'd1: digest_buf[63:32]   <= sha_digest;
                        3'd2: digest_buf[95:64]   <= sha_digest;
                        3'd3: digest_buf[127:96]  <= sha_digest;
                        3'd4: digest_buf[159:128] <= sha_digest;
                        3'd5: digest_buf[191:160] <= sha_digest;
                        3'd6: digest_buf[223:192] <= sha_digest;
                        3'd7: digest_buf[255:224] <= sha_digest;
                    endcase
                    digest_idx <= digest_idx + 1;
                    if (digest_idx == 3'd7)
                        state <= S_DONE;
                end

                // ============================================================
                S_DONE: begin
                    done       <= 1'b1;
                    hash_valid <= 1'b1;
                    state      <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule

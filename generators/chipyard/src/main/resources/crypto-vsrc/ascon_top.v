// ascon_top: Multi-Mode Cryptographic Accelerator
// Supports: HMAC, AEAD (ASCON-128), HASH (ASCON-Hash-256), CXOF (ASCON-CXOF)
// 
// Config format (mode-specific interpretation):
// - HMAC: {msg_size[49:0], key_size[9:0], start[3], mode[2:0]}
// - AEAD: {pt_size[29:0], ad_size[19:0], output_len[8:0], encrypt[4], start[3], mode[2:0]}
// - HASH: {msg_size[49:0], output_len[9:0], start[3], mode[2:0]}
// - CXOF: {msg_size[29:0], custom_size[19:0], output_len[9:0], start[3], mode[2:0]}

module ascon_top (
    input wire clk,
    input wire rst_n,
    
    // ===== Configuration Register =====
    input wire [63:0] config_in,
    
    // ===== Input Data FIFO (CPU writes) =====
    input wire input_fifo_wr_en,
    input wire [63:0] input_fifo_wr_data,
    
    // ===== Output Data FIFO (CPU reads - for AEAD/CXOF) =====
    output wire [63:0] output_fifo_rd_data,
    // output wire output_fifo_rd_valid,
    input wire output_fifo_rd_en,
    
    // ===== AEAD Key/Nonce (Dedicated Registers) =====
    input wire [127:0] key_in,
    input wire [127:0] nonce_in,
    input wire key_wr_en,
    input wire nonce_wr_en,
    
    // ===== Status Output =====
    output wire [9:0] status_out,
    // [0]     = busy
    // [1]     = done
    // [2]     = tag_valid
    // [3]     = fifo_underflow (error)
    // [4]     = message_phase (HMAC)
    // [5]     = input_fifo_full
    // [6]     = input_fifo_empty
    // [7]     = output_fifo_full
    // [8]     = output_fifo_empty
    // [9]     = output_fifo_valid

    // ===== Tag Output =====
    output wire [255:0] tag_out
);

// DUT connections
reg [127:0] dut_data_in;
reg dut_data_in_valid;
reg dut_start;
reg dut_last_block;
reg [3:0] dut_last_bytes;
reg [2:0] dut_mode;
reg [8:0] dut_output_length;  // Not used in HMAC; reserved
reg [127:0] dut_key_in;       // Not used; reserved
reg [127:0] dut_nonce_in;     // Not used
reg dut_encrypt;              // Not used
// Note: expected_tag and expected_tag_valid are not used in current design
// They are tied to 0 to avoid synthesis warnings
wire [127:0] dut_expected_tag = 128'b0;
wire dut_expected_tag_valid = 1'b0;
reg [63:0] dut_hmac_key_in;
reg [9:0] dut_hmac_key_size;
reg dut_hmac_key_valid;
reg dut_hmac_key_last;
reg [2:0] dut_hmac_key_bytes;
wire dut_hmac_key_ready;
wire hmac_message_ready;

wire [127:0] dut_data_out;
wire dut_data_valid;
wire dut_busy;
wire dut_message_phase;
wire dut_done;
wire [255:0] dut_tag_out;
wire dut_tag_valid;

ascon_wrapper wrapper(
    .clk(clk),
    .rst_n(rst_n),
    .data_in(dut_data_in),
    .data_in_valid(dut_data_in_valid),
    .start(dut_start),
    .last_block(dut_last_block),
    .last_bytes(dut_last_bytes),
    .mode(dut_mode),
    .output_length(dut_output_length),
    .key_in(dut_key_in),
    .nonce_in(dut_nonce_in),
    .encrypt(dut_encrypt),
    .expected_tag(dut_expected_tag),
    .expected_tag_valid(dut_expected_tag_valid),
    .hmac_key_in(dut_hmac_key_in),
    .hmac_key_size(dut_hmac_key_size),
    .hmac_key_valid(dut_hmac_key_valid),
    .hmac_key_last(dut_hmac_key_last),
    .hmac_key_bytes(dut_hmac_key_bytes),
    .hmac_key_ready(dut_hmac_key_ready),
    .hmac_message_ready(hmac_message_ready),
    .data_out(dut_data_out),
    .data_valid(dut_data_valid),
    .busy(dut_busy),
    .message_phase(dut_message_phase),
    .done(dut_done),
    .tag_out(dut_tag_out),
    .tag_valid(dut_tag_valid)
);

// Mode definitions
localparam [2:0] MODE_XOF  = 3'b000;
localparam [2:0] MODE_HASH = 3'b001;
localparam [2:0] MODE_CXOF = 3'b010;
localparam [2:0] MODE_AEAD = 3'b011;
localparam [2:0] MODE_HMAC = 3'b100;

// Internal config registers
reg [2:0] mode_reg;
reg start_reg;

// HMAC-specific config
reg [9:0] key_size_reg;
reg [49:0] msg_size_reg;

// AEAD-specific config
reg [19:0] ad_size_reg;
reg [29:0] pt_size_reg;
reg encrypt_reg;
reg [8:0] aead_output_len_reg;

// HASH-specific config
reg [49:0] hash_msg_size_reg;
reg [9:0] hash_output_len_reg;

// CXOF-specific config
reg [19:0] custom_size_reg;
reg [29:0] cxof_msg_size_reg;
reg [9:0] cxof_output_len_reg;

// AEAD key/nonce latched registers
reg [127:0] key_reg;
reg [127:0] nonce_reg;

// Latch AEAD key/nonce when write enables asserted
always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        key_reg <= 128'b0;
        nonce_reg <= 128'b0;
    end else begin
        if (key_wr_en) begin
            key_reg <= key_in;
        end
        if (nonce_wr_en) begin
            nonce_reg <= nonce_in;
        end
    end
end

// Latch config on start pulse - mode-specific parsing
always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        mode_reg <= 0;
        start_reg <= 0;
        key_size_reg <= 0;
        msg_size_reg <= 0;
        ad_size_reg <= 0;
        pt_size_reg <= 0;
        encrypt_reg <= 0;
        aead_output_len_reg <= 0;
        hash_msg_size_reg <= 0;
        hash_output_len_reg <= 0;
        custom_size_reg <= 0;
        cxof_msg_size_reg <= 0;
        cxof_output_len_reg <= 0;
    end else begin
        // Start pulse logic: set on config_in[3], auto-clear next cycle
        if (config_in[3]) begin
            start_reg <= 1'b1;
        end else begin
            start_reg <= 1'b0;
        end
        
        if (config_in[3]) begin  // Latch on start
            mode_reg <= config_in[2:0];
            
            case (config_in[2:0])
                MODE_HMAC: begin
                    key_size_reg <= config_in[13:4];
                    msg_size_reg <= config_in[63:14];
                end
                
                MODE_AEAD: begin
                    encrypt_reg <= config_in[4];
                    aead_output_len_reg <= config_in[13:5];
                    ad_size_reg <= config_in[33:14];
                    pt_size_reg <= config_in[63:34];
                end
                
                MODE_HASH: begin
                    hash_output_len_reg <= config_in[13:4];
                    hash_msg_size_reg <= config_in[63:14];
                end
                
                MODE_CXOF, MODE_XOF: begin
                    cxof_output_len_reg <= config_in[13:4];
                    custom_size_reg <= config_in[33:14];
                    cxof_msg_size_reg <= config_in[63:34];
                end
                
                default: begin
                    // Default to HMAC config for safety
                    key_size_reg <= config_in[13:4];
                    msg_size_reg <= config_in[63:14];
                end
            endcase
        end
    end
end

// Input FIFO (CPU writes, FSM reads)
wire input_fifo_full, input_fifo_almost_full, input_fifo_empty, input_fifo_almost_empty, input_fifo_rd_valid;
reg input_fifo_rd_en;
wire [63:0] input_fifo_rd_data;

//fifo_sync #(
//    .WIDTH(64),
//    .DEPTH(16)
//) input_fifo (
//    .clk(clk),
//    .rst_n(rst_n),
//    .wr_en(input_fifo_wr_en),
//    .wr_data(input_fifo_wr_data),
//    .full(input_fifo_full),
//    .almost_full(input_fifo_almost_full),
//    .rd_en(input_fifo_rd_en),
//    .rd_data(input_fifo_rd_data),
//    .rd_valid(input_fifo_rd_valid),
//    .empty(input_fifo_empty),
//    .almost_empty(input_fifo_almost_empty)
//);

// Output FIFO (FSM writes, CPU reads - for AEAD/CXOF output)
wire output_fifo_full, output_fifo_almost_full, output_fifo_empty, output_fifo_almost_empty;
reg output_fifo_wr_en;
reg [63:0] output_fifo_wr_data;

//fifo_sync #(
//    .WIDTH(64),
//    .DEPTH(16)
//) output_fifo (
//    .clk(clk),
//    .rst_n(rst_n),
//    .wr_en(output_fifo_wr_en),
//    .wr_data(output_fifo_wr_data),
//    .full(output_fifo_full),
//    .almost_full(output_fifo_almost_full),
//    .rd_en(output_fifo_rd_en),
//    .rd_data(output_fifo_rd_data),
//    .rd_valid(output_fifo_rd_valid),
//    .empty(output_fifo_empty),
//    .almost_empty(output_fifo_almost_empty)
//);

fifo #(
    .DATA_WIDTH(64),
    .DEPTH_WIDTH(1)
) input_fifo (
    .clk(clk),
    .rst(!rst_n),
    .wr_en_i(input_fifo_wr_en),
    .wr_data_i(input_fifo_wr_data),
    .full_o(input_fifo_full),
//    .almost_full(input_fifo_almost_full),
    .rd_en_i(input_fifo_rd_en),
    .rd_data_o(input_fifo_rd_data),
    .valid(input_fifo_rd_valid),
    .empty_o(input_fifo_empty)
//    .almost_empty(input_fifo_almost_empty)
);

fifo #(
    .DATA_WIDTH(64),
    .DEPTH_WIDTH(1)
) output_fifo (
    .clk(clk),
    .rst(!rst_n),
    .wr_en_i(output_fifo_wr_en),
    .wr_data_i(output_fifo_wr_data),
    .full_o(output_fifo_full),
//    .almost_full(output_fifo_almost_full),
    .rd_en_i(output_fifo_rd_en),
    .rd_data_o(output_fifo_rd_data),
    .valid(output_fifo_rd_valid),
    .empty_o(output_fifo_empty)
//    .almost_empty(output_fifo_almost_empty)
);


// Status packing
// status_out[0] = dut_busy
// status_out[1] = dut_done  
// status_out[2] = dut_tag_valid
// status_out[3] = fifo_underflow (error flag)
// status_out[4] = dut_message_phase
// status_out[5] = fifo_full
// status_out[6] = fifo_empty
// status_out[7] = fifo_almost_full
// status_out[8] = fifo_almost_empty
// status_out[9] = reserved


// FSM (mimics TB: stream key, wait phase, feed msg)
localparam [3:0] S_IDLE = 4'd0;
localparam [3:0] S_SETUP = 4'd1;
localparam [3:0] S_KEY_WAIT = 4'd2;
localparam [3:0] S_KEY_READ = 4'd3;
localparam [3:0] S_KEY_PRESENT = 4'd4;
localparam [3:0] S_KEY_CLEAR = 4'd5;
localparam [3:0] S_MSG_WAIT = 4'd6;
localparam [3:0] S_MSG_READ = 4'd7;
localparam [3:0] S_MSG_PRESENT = 4'd8;
localparam [3:0] S_MSG_CLEAR = 4'd9;
localparam [3:0] S_AEAD_READ_UPPER = 4'd10;  // AEAD: Read first 64-bit (upper half)
localparam [3:0] S_AEAD_READ_LOWER = 4'd11;  // AEAD: Read second 64-bit (lower half)

reg [3:0] state;
reg [31:0] rem_bytes;  // Remaining in phase (use msg_size_reg if >32-bit needed)
reg phase_key;         // 1=key, 0=msg (HMAC only)
reg phase_custom;      // 1=custom string, 0=message (CXOF only)
reg core_was_busy;     // Track if core has been busy (to avoid reading FIFO during start window)
reg [63:0] aead_data_buffer;  // Buffer for first 64-bit word in AEAD mode
reg fifo_underflow;
reg last_key_chunk;    // Flag to track last key chunk
reg last_msg_chunk;    // Flag to track last message chunk

// Status output packing
assign status_out = {
    output_fifo_rd_valid,         // [9]
    output_fifo_empty,            // [8]
    output_fifo_full,             // [7]
    input_fifo_empty,             // [6]
    input_fifo_full,              // [5]
    dut_message_phase,            // [4]
    fifo_underflow,               // [3]
    dut_tag_valid,                // [2]
    dut_done,                     // [1]
    dut_busy                      // [0]
};

assign tag_out = dut_tag_out;

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        state <= S_IDLE;
        rem_bytes <= 0;
        phase_key <= 0;
        dut_start <= 0;
        dut_data_in <= 0;
        dut_data_in_valid <= 0;
        dut_hmac_key_in <= 0;
        dut_hmac_key_valid <= 0;
        dut_hmac_key_last <= 0;
        dut_hmac_key_bytes <= 0;
        dut_last_block <= 0;
        dut_last_bytes <= 0;
        input_fifo_rd_en <= 0;
        fifo_underflow <= 0;
        last_key_chunk <= 0;
        last_msg_chunk <= 0;
        phase_custom <= 0;
        core_was_busy <= 0;
        aead_data_buffer <= 0;
        // Initialize signals that are assigned in FSM states to avoid Set/Reset priority warnings
        dut_mode <= 3'b0;
        dut_hmac_key_size <= 10'b0;
        dut_key_in <= 128'b0;
        dut_nonce_in <= 128'b0;
        dut_encrypt <= 1'b0;
        dut_output_length <= 9'b0;
    end else begin
        // Default: clear one-cycle signals
        input_fifo_rd_en <= 0;
        dut_start <= 0;
        
        // Track if core has been busy
        if (dut_busy) begin
            core_was_busy <= 1;
        end
        
        case (state)
            S_IDLE: begin
                dut_last_block <= 0;
                dut_last_bytes <= 0;
                // Wait for start command
                if (start_reg) begin
                    state <= S_SETUP;
                    // start_reg auto-clears in config always block, no need to clear here
                    dut_mode <= mode_reg;
                    dut_hmac_key_size <= key_size_reg;
                    rem_bytes <= {22'b0, key_size_reg};  // Start with key
                    phase_key <= 1;  // Key phase
                    last_key_chunk <= 0;
                    fifo_underflow <= 0;  // Clear error flag on new operation
                end
            end
            
            S_SETUP: begin
                // Route to appropriate next state based on mode
                // Clear core_was_busy flag since we're starting a new operation
                core_was_busy <= 0;
                
                case (mode_reg)
                    MODE_HMAC: begin
                        // HMAC: Stream key through S_KEY_* states
                        dut_start <= 1;
                        state <= S_KEY_WAIT;
                    end
                    MODE_AEAD: begin
                        // AEAD: Latch key/nonce registers to wrapper, then start
                        dut_key_in <= key_reg;
                        dut_nonce_in <= nonce_reg;
                        dut_encrypt <= encrypt_reg;
                        dut_start <= 1;
                        dut_output_length <= aead_output_len_reg;
                        // Start with AD phase if ad_size > 0, otherwise go to plaintext phase
                        if (ad_size_reg > 0) begin
                            rem_bytes <= {12'b0, ad_size_reg};
                            phase_custom <= 1;  // Reuse phase_custom flag for AD phase
                            // Initialize last_block flags for first block
                            if (ad_size_reg <= 16) begin
                                dut_last_block <= 1'b1;
                                if (ad_size_reg < 16 && ad_size_reg != 0)
                                    dut_last_bytes <= ad_size_reg[3:0];
                                else
                                    dut_last_bytes <= 4'd0;
                            end else begin
                                dut_last_block <= 1'b0;
                                dut_last_bytes <= 4'd0;
                            end
                        end else begin
                            rem_bytes <= {2'b0, pt_size_reg};
                            phase_custom <= 0;  // Plaintext/ciphertext phase
                            // Initialize last_block flags for first block
                            if (pt_size_reg <= 16) begin
                                dut_last_block <= 1'b1;
                                if (pt_size_reg < 16 && pt_size_reg != 0)
                                    dut_last_bytes <= pt_size_reg[3:0];
                                else
                                    dut_last_bytes <= 4'd0;
                            end else begin
                                dut_last_block <= 1'b0;
                                dut_last_bytes <= 4'd0;
                            end
                        end
                        core_was_busy <= 0;
                        state <= S_MSG_WAIT;
                    end
                    MODE_HASH: begin
                        // HASH: Stream message data through S_MSG_* states
                        dut_start <= 1;
                        rem_bytes <= hash_msg_size_reg[31:0];  // Use HASH-specific msg_size
                        dut_output_length <= {1'b0, hash_output_len_reg[7:0]};  // Truncate to 9 bits
                        // Initialize last_block flags for first block
                        if (hash_msg_size_reg <= 8) begin
                            dut_last_block <= 1'b1;
                            if (hash_msg_size_reg < 8 && hash_msg_size_reg != 0)
                                dut_last_bytes <= hash_msg_size_reg[3:0];
                            else
                                dut_last_bytes <= 4'd0;
                        end else begin
                            dut_last_block <= 1'b0;
                            dut_last_bytes <= 4'd0;
                        end
                        state <= S_MSG_WAIT;
                    end
                    MODE_CXOF: begin
                        // CXOF: Stream custom + message data through S_MSG_* states
                        dut_start <= 1;
                        // Start with custom string phase if custom_size > 0
                        if (custom_size_reg > 0) begin
                            rem_bytes <= {12'b0, custom_size_reg};
                            phase_custom <= 1;  // Custom string phase first
                            // Initialize last_block flags for first block
                            if (custom_size_reg <= 8) begin
                                dut_last_block <= 1'b1;
                                if (custom_size_reg < 8 && custom_size_reg != 0)
                                    dut_last_bytes <= custom_size_reg[3:0];
                                else
                                    dut_last_bytes <= 4'd0;
                            end else begin
                                dut_last_block <= 1'b0;
                                dut_last_bytes <= 4'd0;
                            end
                        end else begin
                            rem_bytes <= {2'b0, cxof_msg_size_reg};  // Use CXOF-specific msg_size
                            phase_custom <= 0;  // Skip to message phase
                            // Initialize last_block flags for first block
                            if (cxof_msg_size_reg <= 8) begin
                                dut_last_block <= 1'b1;
                                if (cxof_msg_size_reg < 8 && cxof_msg_size_reg != 0)
                                    dut_last_bytes <= cxof_msg_size_reg[3:0];
                                else
                                    dut_last_bytes <= 4'd0;
                            end else begin
                                dut_last_block <= 1'b0;
                                dut_last_bytes <= 4'd0;
                            end
                        end
                        dut_output_length <= {1'b0, cxof_output_len_reg[7:0]};  // Truncate to 9 bits
                        state <= S_MSG_WAIT;
                    end
                    default: begin
                        // Unknown mode, return to IDLE
                        state <= S_IDLE;
                    end
                endcase
            end
            
            // ========================================
            // KEY STREAMING STATE MACHINE
            // ========================================
            S_KEY_WAIT: begin
                // Wait for hardware ready AND FIFO not empty (like testbench: while(busy) @(posedge clk))
                // If FIFO is empty, FSM naturally waits here until CPU writes more data
                // Check core_was_busy to avoid reading during the brief start window where core_busy=0
                if (dut_hmac_key_ready && !input_fifo_empty && !dut_busy && core_was_busy) begin
                    // Request read from FIFO
                    input_fifo_rd_en <= 1;
                    state <= S_KEY_READ;
                end
                // Otherwise, stay in this state and wait for conditions to be met
            end
            
            S_KEY_READ: begin
                // Wait for FIFO read data to be valid
                if (input_fifo_rd_valid) begin
                    // Capture valid data from FIFO
                    dut_hmac_key_in <= input_fifo_rd_data;
                    dut_hmac_key_valid <= 1;
                    state <= S_KEY_PRESENT;
                end
                // Stay in this state until input_fifo_rd_valid is asserted
            end
            
            S_KEY_PRESENT: begin
                // Present key data with valid signal (like testbench: hmac_key_valid = 1)
                // Use buffered data that was validated in S_KEY_READ
                
                // Check if this is the last key chunk
                last_key_chunk <= (rem_bytes <= 8);
                
                // Set last_key flag one block ahead (when sending second-to-last block)
                // This allows ascon_unified to see the flag when it's ready to absorb the last block
                if (rem_bytes <= 16 && rem_bytes > 8) begin
                    // We're sending the second-to-last block, assert last_key for next block
                    dut_hmac_key_last <= 1'b1;
                    // Calculate valid bytes for the NEXT block (the actual last block)
                    if ((rem_bytes - 8) > 0 && (rem_bytes - 8) < 8 && ((rem_bytes - 8) & 3'h7) != 3'h0)
                        dut_hmac_key_bytes <= (rem_bytes - 8) & 3'h7;
                    else
                        dut_hmac_key_bytes <= 3'd0;  // 0 means all 8 bytes valid in last block
                end else if (rem_bytes <= 8) begin
                    // We're sending the actual last block, keep flags as they were set previously
                    // Don't change dut_hmac_key_last or dut_hmac_key_bytes here
                end else begin
                    // Not near the end yet, clear flags
                    dut_hmac_key_last <= 1'b0;
                    dut_hmac_key_bytes <= 3'd0;
                end
                
                // Update remaining bytes
                rem_bytes <= rem_bytes - 8;
                
                state <= S_KEY_CLEAR;
            end
            
            S_KEY_CLEAR: begin
                // Clear signals after one cycle (like testbench: hmac_key_valid = 0)
                dut_hmac_key_valid <= 0;
                dut_hmac_key_in <= 64'b0;
                
                // Check if we need more key chunks or transition to message
                if (last_key_chunk) begin
                    // Key streaming complete, prepare for message phase and clear last_key flags
                    dut_hmac_key_last <= 0;
                    dut_hmac_key_bytes <= 0;
                    phase_key <= 0;
                    rem_bytes <= msg_size_reg[31:0];  // Switch to message size
                    state <= S_MSG_WAIT;
                    last_key_chunk <= 0;
                end else begin
                    // More key chunks to stream
                    state <= S_KEY_WAIT;
                end
            end
            
            // ========================================
            // MESSAGE STREAMING STATE MACHINE
            // ========================================
            S_MSG_WAIT: begin
                // For HMAC: Wait for message_phase signal from wrapper
                // For HASH/CXOF: Can proceed directly (no message_phase required)
                // For AEAD: Route to 128-bit block assembly
                // If FIFO is empty, FSM naturally waits here until CPU writes more data
                // Check core_was_busy to avoid reading during the brief start window where core_busy=0
                if (!input_fifo_empty && !dut_busy && core_was_busy) begin
                    // Check mode-specific readiness
                    if ((mode_reg == MODE_HMAC && dut_message_phase && hmac_message_ready) ||
                        (mode_reg == MODE_HASH || mode_reg == MODE_CXOF)) begin
                        // Request read from FIFO for 64-bit modes
                        input_fifo_rd_en <= 1;
                        state <= S_MSG_READ;
                    end else if (mode_reg == MODE_AEAD) begin
                        // AEAD: Start reading first 64-bit word (upper half of 128-bit block)
                        input_fifo_rd_en <= 1;
                        state <= S_AEAD_READ_UPPER;
                    end
                end
                // Otherwise, stay in this state and wait for conditions to be met
            end
            
            S_MSG_READ: begin
                // Wait for FIFO read data to be valid
                if (input_fifo_rd_valid) begin
                    // Capture valid data from FIFO
                    dut_data_in <= {64'b0, input_fifo_rd_data};  // Lower 64 bits for HMAC
                    dut_data_in_valid <= 1;

                    state <= S_MSG_PRESENT;
                end
                // Stay in this state until input_fifo_rd_valid is asserted
            end
            
            S_MSG_PRESENT: begin
                // Present message data with valid signal (like testbench: data_in_valid = 1)
                // Use buffered data that was validated in S_MSG_READ (or S_AEAD_READ_LOWER for AEAD)
                // last_block and last_bytes flags are already set from previous S_MSG_CLEAR or initial setup
                
                if (mode_reg == MODE_AEAD) begin
                    // AEAD: 16-byte (128-bit) blocks
                    last_msg_chunk <= (rem_bytes <= 16);
                    // Update remaining bytes (16 per block for AEAD)
                    rem_bytes <= rem_bytes - 16;
                end else begin
                    // HASH/CXOF/HMAC: 8-byte (64-bit) blocks
                    last_msg_chunk <= (rem_bytes <= 8);
                    
                    // Update remaining bytes (8 per block for non-AEAD)
                    rem_bytes <= rem_bytes - 8;
                end
                
                state <= S_MSG_CLEAR;
            end
            
            S_MSG_CLEAR: begin
                // Clear signals after one cycle (like testbench: data_in_valid = 0)
                dut_data_in_valid <= 0;
                dut_data_in <= 0;
                
                // Check if we need more message chunks or transition to idle/next phase
                if (last_msg_chunk) begin
                    // Check for phase transitions
                    if (mode_reg == MODE_CXOF && phase_custom) begin
                        // CXOF: Transition from custom to message phase
                        core_was_busy <= 0;
                        phase_custom <= 0;
                        rem_bytes <= {2'b0, cxof_msg_size_reg};
                        last_msg_chunk <= 0;
                        // Initialize flags for new phase (message phase)
                        if (cxof_msg_size_reg <= 8) begin
                            dut_last_block <= 1'b1;
                            if (cxof_msg_size_reg < 8 && cxof_msg_size_reg != 0)
                                dut_last_bytes <= cxof_msg_size_reg[3:0];
                            else
                                dut_last_bytes <= 4'd0;
                        end else begin
                            dut_last_block <= 1'b0;
                            dut_last_bytes <= 4'd0;
                        end
                        state <= S_MSG_WAIT;
                    end else if (mode_reg == MODE_AEAD && phase_custom) begin
                        // AEAD: Transition from AD to plaintext phase
                        core_was_busy <= 0;
                        phase_custom <= 0;
                        rem_bytes <= {2'b0, pt_size_reg};
                        last_msg_chunk <= 0;
                        // Initialize flags for new phase (plaintext phase)
                        if (pt_size_reg <= 16) begin
                            dut_last_block <= 1'b1;
                            if (pt_size_reg < 16 && pt_size_reg != 0)
                                dut_last_bytes <= pt_size_reg[3:0];
                            else
                                dut_last_bytes <= 4'd0;
                        end else begin
                            dut_last_block <= 1'b0;
                            dut_last_bytes <= 4'd0;
                        end
                        state <= S_MSG_WAIT;
                    end else begin
                        // Phase complete, return to idle and clear flags
//                        dut_last_block <= 0;
//                        dut_last_bytes <= 0;
                        state <= S_IDLE;
                        last_msg_chunk <= 0;
                        phase_custom <= 0;
                    end
                end else begin
                    // More chunks to stream in current phase
                    // Update last_block and last_bytes flags for the NEXT block
                    
                    if (mode_reg == MODE_AEAD) begin
                        // AEAD: 16-byte (128-bit) blocks
                        // rem_bytes already updated in S_MSG_PRESENT (decreased by 16)
                        if (rem_bytes <= 16) begin
                            // Next block is the last one
                            dut_last_block <= 1'b1;
                            if (rem_bytes < 16 && rem_bytes != 0)
                                dut_last_bytes <= rem_bytes[3:0];
                            else
                                dut_last_bytes <= 4'd0;  // 0 means all 16 bytes valid
                        end else begin
                            // Not the last block yet
                            dut_last_block <= 1'b0;
                            dut_last_bytes <= 4'd0;
                        end
                    end else begin
                        // HASH/CXOF/HMAC: 8-byte (64-bit) blocks
                        // rem_bytes already updated in S_MSG_PRESENT (decreased by 8)
                        if (rem_bytes <= 8) begin
                            // Next block is the last one
                            dut_last_block <= 1'b1;
                            if (rem_bytes < 8 && rem_bytes != 0)
                                dut_last_bytes <= rem_bytes[3:0];
                            else
                                dut_last_bytes <= 4'd0;  // 0 means all 8 bytes valid
                        end else begin
                            // Not the last block yet
                            dut_last_block <= 1'b0;
                            dut_last_bytes <= 4'd0;
                        end
                    end
                    
                    state <= S_MSG_WAIT;
                end
            end
            
            // ========================================
            // AEAD-SPECIFIC 128-BIT BLOCK ASSEMBLY
            // ========================================
            S_AEAD_READ_UPPER: begin
                // Wait for first 64-bit word (upper half of 128-bit block)
                // Keep rd_en asserted until we get valid data (handles case where FIFO was empty)
                if (!input_fifo_empty) begin
                    input_fifo_rd_en <= 1;
                end
                
                if (input_fifo_rd_valid) begin
                    // Buffer the upper 64 bits
                    aead_data_buffer <= input_fifo_rd_data;
                    // Request second 64-bit word (lower half)
                    input_fifo_rd_en <= 1;
                    state <= S_AEAD_READ_LOWER;
                end
            end
            
            S_AEAD_READ_LOWER: begin
                // Wait for second 64-bit word (lower half of 128-bit block)
                // Keep rd_en asserted until we get valid data (handles case where FIFO was empty)
                if (!input_fifo_empty) begin
                    input_fifo_rd_en <= 1;
                end
                
                if (input_fifo_rd_valid) begin
                    // Combine buffered upper + current lower into 128-bit block
                    dut_data_in <= {aead_data_buffer, input_fifo_rd_data};  // [127:64] = upper, [63:0] = lower
                    dut_data_in_valid <= 1;
                    state <= S_MSG_PRESENT;  // Reuse existing present/clear states
                end
            end
            
            default: begin
                state <= S_IDLE;
            end
        endcase
        
        // Error detection: reading from empty FIFO
        if (input_fifo_rd_en && input_fifo_empty) begin
            fifo_underflow <= 1;
        end
    end
end

// ========================================
// Output FIFO Write Logic (AEAD/CXOF Output Streaming)
// ========================================
// For AEAD: Convert 128-bit data_out to 2x 64-bit FIFO writes
// For CXOF: Write 64-bit data_out[63:0] directly
reg output_write_phase;  // 0=write upper 64 bits, 1=write lower 64 bits (AEAD only)
reg [127:0] output_buffer;

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        output_fifo_wr_en <= 1'b0;
        output_fifo_wr_data <= 64'b0;
        output_write_phase <= 1'b0;
        output_buffer <= 128'b0;
    end else begin
        // Default: no write
        output_fifo_wr_en <= 1'b0;
        
        if (mode_reg == MODE_AEAD) begin
            // AEAD: 128-bit output needs 2 FIFO writes
            if (dut_data_valid && !output_fifo_full && output_write_phase == 1'b0) begin
                // Wrapper produced output, buffer it and write upper 64 bits
                output_buffer <= dut_data_out;
                output_fifo_wr_en <= 1'b1;
                output_fifo_wr_data <= dut_data_out[127:64];  // Write upper 64 bits first
                output_write_phase <= 1'b1;  // Next cycle: write lower 64 bits
            end else if (output_write_phase == 1'b1 && !output_fifo_full) begin
                // Write lower 64 bits on next cycle
                output_fifo_wr_en <= 1'b1;
                output_fifo_wr_data <= output_buffer[63:0];
                output_write_phase <= 1'b0;
                output_buffer <= 128'b0;  // Clear buffer
            end
        end else if (mode_reg == MODE_CXOF || mode_reg == MODE_XOF) begin
            // CXOF/XOF: Direct 64-bit write (lower 64 bits)
            if (dut_data_valid && !output_fifo_full) begin
                output_fifo_wr_en <= 1'b1;
                output_fifo_wr_data <= dut_data_out[63:0];
            end
        end
        // HMAC and HASH don't produce streaming output, only tag_out at the end
    end
end

endmodule

module ascon_wrapper (
    input wire clk,
    input wire rst_n,
   
    // Common inputs
    input wire [127:0] data_in, // Input data (128-bit, lower 64 for hash-like modes)
    input wire data_in_valid,
    input wire start, // Start operation
    input wire last_block, // Last block indicator
    input wire [3:0] last_bytes, // Valid bytes in last block (0-16)
   
    // Mode selection (3 bits: 000=XOF, 001=HASH-256, 010=CXOF, 011=AEAD, 100=HMAC)
    input wire [2:0] mode,
    input wire [8:0] output_length, // Output length in 64-bit blocks (for XOF/CXOF)
   
    // AEAD-specific inputs
    input wire [127:0] key_in, // 128-bit key (AEAD only)
    input wire [127:0] nonce_in, // 128-bit nonce (AEAD only)
    input wire encrypt, // 1=encrypt, 0=decrypt (AEAD only)
    input wire [127:0] expected_tag, // Expected tag for AEAD decrypt
    input wire expected_tag_valid,
   
    // HMAC-specific inputs
    input wire [63:0] hmac_key_in, // HMAC key input (64-bit chunks)
    input wire [9:0] hmac_key_size, // HMAC key size in bytes (0-1023+)
    input wire hmac_key_valid, // Valid signal for HMAC key chunk
    input wire hmac_key_last, // Last key chunk indicator
    input wire [2:0] hmac_key_bytes, // Valid bytes in last key chunk (0-8)
    output wire hmac_key_ready,
    output wire hmac_message_ready,
   
    // Outputs
    output reg [127:0] data_out, // Output data
    output reg data_valid, // Output valid
    output wire busy, // Busy signal
    output reg message_phase, // input message
    output reg done, // Done signal
   
    // AEAD/HMAC-specific outputs
    output reg [255:0] tag_out, // Tag for AEAD or HMAC (lower 128 for 256-bit HMAC)
    output reg tag_valid // Tag valid or verification result
);

// Internal Ascon core instantiation
wire [127:0] core_data_out;
wire core_data_valid;
wire core_busy;
wire core_done;
wire [255:0] core_tag_out;  // 256-bit for HASH, lower 128-bit for AEAD
wire core_tag_valid;

// Internal signals for wrapper logic (declared above before ascon_core)
reg [127:0] internal_data_in;
reg internal_data_valid;
reg internal_start;
reg internal_last_block;
reg [3:0] internal_last_bytes;
reg [1:0] internal_mode;
reg [8:0] internal_output_length;
reg [127:0] internal_key_in;
reg [127:0] internal_nonce_in;
reg internal_encrypt;
reg [127:0] internal_expected_tag;
reg internal_expected_tag_valid;


ascon_unified ascon_core (
    .clk(clk),
    .rst_n(rst_n),
    .data_in(internal_data_in),
    .data_in_valid(internal_data_valid),
    .start(internal_start),
    .last_block(internal_last_block),
    .last_bytes(internal_last_bytes),
    .mode(internal_mode),
    .output_length(internal_output_length),
    .key_in(internal_key_in),
    .nonce_in(internal_nonce_in),
    .encrypt(internal_encrypt),
    .expected_tag(internal_expected_tag),
    .expected_tag_valid(internal_expected_tag_valid),
    .data_out(core_data_out),
    .data_valid(core_data_valid),
    .busy(core_busy),
    .done(core_done),
    .tag_out(core_tag_out),
    .tag_valid(core_tag_valid)
);

reg busy_prev; // Track previous busy
always @(posedge clk) busy_prev <= core_busy;

// HMAC-specific regs and wires (streaming approach)
reg [2:0] hmac_state; // 000=IDLE, 001=KEY_HASH (case b), 010=INNER_ABSORB, 011=INNER_COLLECT, 100=OUTER_ABSORB, 101=OUTER_COLLECT
reg hmac_busy;
reg [9:0] key_size_bytes; // Total key size in bytes
reg [511:0] hashed_key; // For case b: 256-bit H(K) when key > 64 bytes
reg key_hash_done; // Flag if key hashing complete
reg [3:0] pad_chunk_cnt; // Counter for padding K0 to 64 bytes
reg feeding_k0; // Flag during K0 absorption (with ipad/opad XOR)
reg [2:0] collect_cnt; // Counter for collecting 4 x 64-bit squeeze blocks
reg chunk_sent; // Flag to prevent multiple increments per chunk

// Compute mask for partial last chunk
wire is_last_key_chunk = hmac_key_last && (pad_chunk_cnt * 8 > hmac_key_size);  // If this chunk includes the end
wire [3:0] valid_bytes_this_chunk = is_last_key_chunk ? (hmac_key_size - pad_chunk_cnt * 8) : 8;  // Valid in this chunk
wire [63:0] mask = (64'hFFFFFFFFFFFFFFFF >> ((8 - valid_bytes_this_chunk) * 8));  // Mask LSB valid bytes (little-endian)

assign busy = hmac_busy || core_busy;
assign hmac_key_ready = !busy & feeding_k0;
assign hmac_message_ready = !busy & message_phase;

// Constants
localparam MODE_XOF = 3'b000;
localparam MODE_HASH = 3'b001;
localparam MODE_CXOF = 3'b010;
localparam MODE_AEAD = 3'b011;
localparam MODE_HMAC = 3'b100;

localparam B_BYTES = 64; // Block size in bytes
localparam HASH_LEN_BYTES = 32; // Ascon-Hash256 output in bytes
localparam CHUNK_BYTES = 8; // 64 bits / 8 = 8 bytes per chunk
localparam B_CHUNKS = B_BYTES / CHUNK_BYTES; // 8 chunks for B
localparam HASH_CHUNKS = HASH_LEN_BYTES / CHUNK_BYTES; // 4 chunks for 256 bits

localparam IPAD_CHUNK = 64'h3636363636363636;
localparam OPAD_CHUNK = 64'h5C5C5C5C5C5C5C5C;

// HMAC state machine parameters
localparam [2:0] HMAC_IDLE           = 3'd0;  // Idle state, waiting for start
localparam [2:0] HMAC_SETUP          = 3'd1;  // Setup phase, determine key case
localparam [2:0] HMAC_KEY_HASH       = 3'd2;  // Hash key for Case B (key > 64 bytes)
localparam [2:0] HMAC_INNER_ABSORB   = 3'd3;  // Absorb K0⊕ipad + message
localparam [2:0] HMAC_INNER_COLLECT  = 3'd4;  // Collect inner hash result
localparam [2:0] HMAC_OUTER_ABSORB   = 3'd5;  // Absorb K0⊕opad + inner_hash
localparam [2:0] HMAC_TRANSITION     = 3'd6;  // Transition state for setup
localparam [2:0] HMAC_TRANSITION_2   = 3'd7;  // Transition state for setup

// Wrapper logic
always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        // Reset outputs and internals
        data_out <= 128'b0;
        data_valid <= 1'b0;
//        busy <= 1'b0;
        done <= 1'b0;
        tag_out <= 256'b0;
        tag_valid <= 1'b0;
       
        hmac_state <= HMAC_IDLE;
        hmac_busy <= 1'b0;
        key_size_bytes <= 10'b0;
        hashed_key <= 512'b0;
        key_hash_done <= 1'b0;
        pad_chunk_cnt <= 4'b0;
        feeding_k0 <= 1'b0;
        message_phase <= 1'b0;
        collect_cnt <= 3'b0;
        chunk_sent <= 1'b0;
       
        // Internal core signals reset
        internal_data_in <= 128'b0;
        internal_data_valid <= 1'b0;
        internal_start <= 1'b0;
        internal_last_block <= 1'b0;
        internal_last_bytes <= 4'b0;
        internal_mode <= 2'b00;
        internal_output_length <= 9'b0;
        internal_key_in <= 128'b0;
        internal_nonce_in <= 128'b0;
        internal_encrypt <= 1'b0;
        internal_expected_tag <= 128'b0;
        internal_expected_tag_valid <= 1'b0;
        
        
    end else begin
        // Default passthrough for base modes
        if (mode < MODE_HMAC) begin
//            busy <= core_busy;
            done <= core_done;
            data_out <= core_data_out;
            data_valid <= core_data_valid;
            tag_out <= core_tag_out;  // Pass through full 256-bit tag
            tag_valid <= core_tag_valid;
           
            internal_data_in <= data_in;
            internal_data_valid <= data_in_valid;
            internal_start <= start;
            internal_last_block <= last_block;
            internal_last_bytes <= last_bytes;
            internal_mode <= mode[1:0];
            internal_output_length <= output_length;
            internal_key_in <= key_in;
            internal_nonce_in <= nonce_in;
            internal_encrypt <= encrypt;
            internal_expected_tag <= expected_tag;
            internal_expected_tag_valid <= expected_tag_valid;
        end else if (mode == MODE_HMAC) begin
            case (hmac_state)
                HMAC_IDLE: begin
                    if(start) begin
                        done <= 1'b0;
    
                        hmac_busy <= 1'b1;
                        hmac_state <= HMAC_SETUP; // Start with INNER_ABSORB - process key on-the-fly
    
                        // Start inner hash immediately
                        internal_mode <= MODE_HASH[1:0];
                        internal_output_length <= 9'd4; // 4 blocks for 256-bit hash
                        internal_start <= 1'b1;
                        
                        hashed_key <= 512'b0;

                    end
                end
                HMAC_SETUP: begin // Setup phase
                    feeding_k0 <= 1'b1;
                    key_hash_done <= 1'b0;
                    chunk_sent <= 1'b0;  // Reset chunk_sent flag
                    internal_start <= 1'b0;
                    if(hmac_key_size > B_BYTES) begin 
                        hmac_state <= HMAC_KEY_HASH;
                    end
                    else hmac_state <= HMAC_INNER_ABSORB;
                end
               
                HMAC_KEY_HASH: begin
                    hmac_busy <= 1'b0;
                    // Default: clear control signals
                    internal_data_valid <= 1'b0;
                    internal_start <= 1'b0; // Clear start signal after one cycle
                    internal_data_in <= 128'b0;
                    
                    if (hmac_key_valid && !core_busy) begin
                        hmac_busy <= 1'b1;
                        // Send single-cycle pulse for message data
                        internal_data_in <= {64'b0, hmac_key_in}; // Use lower 64 bits for hash
                        internal_data_valid <= 1'b1;
                        internal_last_block <= hmac_key_last;
                        internal_last_bytes <= {1'b0, hmac_key_bytes};

                    end
                    // Collect hashed key result
                    if (core_data_valid) begin
                        case (collect_cnt)
                            0: hashed_key[255:192] <= core_data_out[63:0];
                            1: hashed_key[191:128] <= core_data_out[63:0];
                            2: hashed_key[127:64] <= core_data_out[63:0];
                            3: hashed_key[63:0] <= core_data_out[63:0];
                        endcase
                        collect_cnt <= collect_cnt + 1;
                    end
                    if (core_done) begin 
                        hmac_state <= HMAC_TRANSITION; 
                        message_phase <= 1'b0;
                        internal_start <= 1'b1;
                        internal_last_block <= 1'b0;
                        internal_last_bytes <= 4'b0;
                        key_hash_done <= 1'b1;
                        collect_cnt <= 3'b0;
                    end    
                end
                
                HMAC_TRANSITION: begin
                    hmac_state <= HMAC_TRANSITION_2;
                    internal_start <= 1'b0;
                    chunk_sent <= 1'b0;  // Reset chunk_sent flag before entering INNER_ABSORB
                end
                HMAC_TRANSITION_2: begin
                    hmac_state <= HMAC_INNER_ABSORB;
                end
                HMAC_INNER_ABSORB: begin // INNER_ABSORB: Feed K0 ^ ipad + message (streaming)
                    hmac_busy <= 1'b0;
                    // Default: clear control signals
                    internal_data_valid <= 1'b0;
//                    internal_start <= 1'b0; // Clear start signal after one cycle
                    internal_data_in <= 128'b0;
                    
                    // Clear chunk_sent flag when core becomes busy (processing previous chunk)
                    if (core_busy) begin
                        chunk_sent <= 1'b0;
                    end
                    
                    if (feeding_k0 && pad_chunk_cnt < 8 && !core_busy && !chunk_sent) begin
                        // Determine if we can proceed with this chunk
                        // For non-hashed keys (Case A/C), wait for hmac_key_valid if within key size
                        if (!key_hash_done && pad_chunk_cnt * 8 < hmac_key_size && !hmac_key_valid) begin
                            // Wait for valid key data - don't proceed yet
                            // hmac_busy <= 1'b1;  // Stay busy waiting for key data
                        end else begin
                            // We can proceed: either have valid key data, or past key size (padding), or using hashed key
                            hmac_busy <= 1'b1;
                            
                            // Send K0 ^ ipad to core
                            if(key_hash_done) begin // Case B: hashed_key + pad zeros
                                if (pad_chunk_cnt < 4) begin
                                case (collect_cnt)
                                    0: begin 
                                        internal_data_in <= {64'b0, hashed_key[255:192] ^ IPAD_CHUNK}; 
                                        hashed_key <= {hashed_key[447:0], hashed_key[255:192] ^ OPAD_CHUNK};
                                    end 
                                    1: begin 
                                        internal_data_in <= {64'b0, hashed_key[191:128] ^ IPAD_CHUNK}; 
                                        hashed_key <= {hashed_key[447:0], hashed_key[191:128] ^ OPAD_CHUNK};
                                    end
                                    2: begin
                                         internal_data_in <= {64'b0, hashed_key[127:64]  ^ IPAD_CHUNK}; 
                                         hashed_key <= {hashed_key[447:0], hashed_key[127:64] ^ OPAD_CHUNK};
                                     end
                                    3: begin 
                                        internal_data_in <= {64'b0, hashed_key[63:0]    ^ IPAD_CHUNK}; 
                                        hashed_key <= {hashed_key[447:0], hashed_key[63:0] ^ OPAD_CHUNK};
                                    end
                                endcase 
                                end
                                else begin
                                    internal_data_in <= {64'b0, IPAD_CHUNK}; // Zero pad
                                    hashed_key <= {hashed_key[447:0], OPAD_CHUNK};
                                end 
                            end else if (pad_chunk_cnt * 8 < hmac_key_size) begin
                                // Case A: Within key size, use provided key data (hmac_key_valid is guaranteed here)
                                internal_data_in <= {64'b0, (hmac_key_in & mask) ^ IPAD_CHUNK};
                                hashed_key <= {hashed_key[447:0], (hmac_key_in & mask) ^ OPAD_CHUNK};
                            end else begin
                                // Case C: Pad with zeros (beyond key size)
                                internal_data_in <= {64'b0, IPAD_CHUNK};
                                hashed_key <= {hashed_key[447:0], OPAD_CHUNK};
                            end 

                            internal_data_valid <= 1'b1;
                            pad_chunk_cnt <= pad_chunk_cnt + 1;
                            chunk_sent <= 1'b1;  // Mark this chunk as sent
                           
                            if (pad_chunk_cnt == 7) begin
                                feeding_k0 <= 1'b0;
                                message_phase <= 1'b1;
                            end
                        end
                    end 
                    else if (message_phase && data_in_valid && !core_busy) begin
                        hmac_busy <= 1'b1;
                        // Send single-cycle pulse for message data
                        internal_data_in <= {64'b0, data_in[63:0]}; // Use lower 64 bits for hash
                        internal_data_valid <= 1'b1;
                        internal_last_block <= last_block;
                        internal_last_bytes <= last_bytes;

                    end
                    // Collect hashed key result
                    if (core_data_valid) begin
                        case (collect_cnt)
                            0: tag_out[255:192] <= core_data_out[63:0];
                            1: tag_out[191:128] <= core_data_out[63:0];
                            2: tag_out[127:64] <= core_data_out[63:0];
                            3: tag_out[63:0] <= core_data_out[63:0];
                        endcase
                        collect_cnt <= collect_cnt + 1;
                    end
                    if (core_done) begin 
                        hmac_state <= HMAC_INNER_COLLECT; // To INNER_COLLECT
                        message_phase <= 1'b0;
                        internal_start <= 1'b1;
                    end    
                end
               
                HMAC_INNER_COLLECT: begin // INNER_COLLECT: Collect 256-bit inner_hash from core squeezes                
                    if (collect_cnt == HASH_CHUNKS) begin
                        collect_cnt <= 3'b0;
                        internal_start <= 1'b0;
                        hmac_state <= HMAC_OUTER_ABSORB; // To OUTER_ABSORB
                        internal_mode <= MODE_HASH[1:0];
                        internal_output_length <= 9'd4; // 4 blocks for 256-bit hash
                        feeding_k0 <= 1'b1;
                        pad_chunk_cnt <= 4'b0;
                        internal_last_bytes <= 4'b0;
                        internal_last_block <= 1'b0;  
                    end
                end
               
                HMAC_OUTER_ABSORB: begin // OUTER_ABSORB: Feed K0 ^ opad + inner_hash (streaming)
                    hmac_busy <= 1'b0;
                    internal_data_valid <= 1'b0;

                    if (feeding_k0 && pad_chunk_cnt < 13 && busy_prev && !core_busy) begin
                        hmac_busy <= 1'b1;
                        internal_data_in <= {64'b0, hashed_key[511:448]};
                        internal_data_valid <= 1'b1;
                        hashed_key <= {hashed_key[447:0], tag_out[255:192]};
                        tag_out <= {tag_out[191:0], 64'b0};
                        
                        if(pad_chunk_cnt==11) begin
                            internal_last_block <= 1'b1;
                            feeding_k0 <= 1'b0;
                        end

                        pad_chunk_cnt <= pad_chunk_cnt + 1;
                    end 
                    if (core_data_valid) begin
                        internal_last_block <= 1'b0;
                        case (collect_cnt)
                            0: tag_out[255:192] <= core_data_out[63:0];   // Bits 255:192
                            1: tag_out[191:128] <= core_data_out[63:0];     // Bits 191:128  
                            2: tag_out[127:64]  <= core_data_out[63:0];        // Bits 127:64
                            3: tag_out[63:0]    <= core_data_out[63:0];          // Bits 63:0
                        endcase
                        collect_cnt <= collect_cnt + 1;
                    end
                    if (core_done) begin 
                        hmac_state <= HMAC_IDLE; // Back to IDLE
                        done <= 1'b1;
                        tag_valid <= 1'b1;  // Tag is now valid
                    end
                end
            endcase
        end
    end
end
endmodule


module ascon_unified (
    input wire           clk,
    input wire           rst_n,
    input wire [127:0]   data_in,       // Input data (128-bit, use lower 64 for hash modes)
    input wire           data_in_valid,
    input wire           start,         // Start operation
    input wire           last_block,    // Indicates last block of data
    input wire [3:0]     last_bytes,    // Valid bytes in last block (0-16 for 128-bit)
    
    // Mode selection
    input wire [1:0]     mode,           // 00=XOF, 01=HASH-256, 10=CXOF, 11=AEAD
    input wire [8:0]     output_length,  // Desired output length in 64-bit blocks (XOF/CXOF modes)
    
    // AEAD-specific inputs
    input wire [127:0]   key_in,         // 128-bit key (AEAD mode only)
    input wire [127:0]   nonce_in,       // 128-bit nonce (AEAD mode only)
    input wire           encrypt,        // 1=encrypt, 0=decrypt (AEAD mode only)
    input wire [127:0]   expected_tag,   // Expected authentication tag for decryption
    input wire           expected_tag_valid, // Indicates expected_tag is valid for comparison
    
    output reg [127:0]   data_out,       // Output data (128-bit, use lower 64 for hash modes)
    output reg           data_valid,     // Output data valid
    output reg           busy,           // Module busy
    output reg           done,           // Operation complete
    
    // AEAD-specific outputs
    output reg [255:0]   tag_out,        // Authentication tag (128-bit for AEAD, 256-bit for HASH)
    output reg           tag_valid       // Tag verification result (AEAD decrypt only)
);

    // FSM states (need 4 bits for up to 16 states)
    localparam [3:0] 
        S_IDLE          = 4'd0,
        S_INIT          = 4'd1,
        S_ABSORB        = 4'd2,  // Unified absorption for custom/AD and message/PT/CT data
        S_PAD           = 4'd5,  // Unified padding for all modes
        S_PERMUTE       = 4'd6,
        S_SQUEEZE       = 4'd7,
        // AEAD-specific states
        S_AEAD_OUTPUT   = 4'd8,  // AEAD ciphertext/plaintext output generation
        S_AEAD_FINAL    = 4'd9, // AEAD finalization and tag generation/verification
        S_TAG           = 4'd10;
        
    // Padding context definitions
    localparam [0:0]
        CONTEXT_CUSTOM  = 1'd0,  // Customization/AD padding
        CONTEXT_MESSAGE = 1'd1;  // Message/PT/CT padding
    
    // Updated parameters for ASCON modes per latest NIST SP 800-232
    localparam [63:0] XOF_IV  = 64'h0000080000cc0003;     // ASCON-XOF128 IV per NIST SP 800-232
    localparam [63:0] HASH_IV = 64'h0000080100cc0002;     // ASCON-Hash256 IV per NIST SP 800-232 
    localparam [63:0] CXOF_IV = 64'h0000080000cc0004;     // ASCON-CXOF128 IV per NIST SP 800-232
    localparam [63:0] AEAD_IV = 64'h00001000808c0001;     // ASCON-AEAD128 IV per NIST SP 800-232
    
    // Mode definitions
    localparam [1:0] MODE_XOF  = 2'b00;
    localparam [1:0] MODE_HASH = 2'b01;
    localparam [1:0] MODE_CXOF = 2'b10;
    localparam [1:0] MODE_AEAD = 2'b11;
    
    // ASCON permutation round constants
    localparam [3:0] ROUNDS_8  = 4'd8;   // AEAD data processing rounds
    localparam [3:0] ROUNDS_12 = 4'd12;  // Initialization, finalization, and hash rounds
    localparam [3:0] ROUNDS_1  = 4'd1;   // Final round indicator
    
    // Ascon state
    reg [63:0] x0, x1, x2, x3, x4;
    wire [63:0] x0_out, x1_out, x2_out, x3_out, x4_out;
    
    // Control registers
    reg [3:0]  state;                    // Expanded to 4 bits for AEAD states
    reg just_padded;
    reg just_squeezed;
    reg just_padded_custom;      // Flag indicating customization padding completed
    reg custom_done;             // Flag indicating customization phase completed
    reg full_block_absorbed;     // Flag indicating full 64-bit last block was absorbed
    reg [0:0] padding_context;   // Context for unified padding state
    reg absorbing_custom_data;   // Flag to distinguish custom/AD vs message/PT/CT absorption
    
    // AEAD-specific control registers
    reg aead_initialized;        // Flag indicating AEAD initialization completed
    reg aead_key_xor_pending;    // Flag indicating AEAD key XOR after permutation is pending
    reg first_data_block_processed; // Flag to ensure domain separation only happens once
    reg first_ad_block;          // Flag to track first AD block for key XOR
    
    // Domain separation constants per NIST SP 800-232
//    localparam [63:0] DOMAIN_SEP_AD = 64'h0000000000000001;  // S ⊕ (0^319 ∥ 1) - bit 0 of S[4]
    
    // Dynamic permutation round count based on mode and state
    wire [3:0] permutation_rounds;
    assign permutation_rounds = (mode == MODE_AEAD && aead_initialized && !just_padded) ? ROUNDS_8 : ROUNDS_12;

    reg [3:0]  round;
    reg [8:0] bytes_output;         // Count of 64-bit blocks produced

    function [63:0] swap_bytes64;
        input [63:0] value;
        begin
            swap_bytes64 = {value[7:0], value[15:8], value[23:16], value[31:24],
                            value[39:32], value[47:40], value[55:48], value[63:56]};
        end
    endfunction

    // Shared mask calculations for S_PAD and S_ABSORB states
    wire is_x0_only_bytes = (last_bytes < 4'd8);
    wire [63:0] x0_preserve_mask = ~((64'hFFFFFFFFFFFFFFFF) >> ((4'd8 - last_bytes) * 8));
    wire [63:0] x0_replace_mask = ((64'hFFFFFFFFFFFFFFFF) >> ((4'd8 - last_bytes) * 8));
    wire [63:0] x1_preserve_mask = ~((64'hFFFFFFFFFFFFFFFF) >> ((5'd16 - last_bytes) * 8));
    wire [63:0] x1_replace_mask = ((64'hFFFFFFFFFFFFFFFF) >> ((5'd16 - last_bytes) * 8));
    // Note: Padding values are different per ASCON spec - 0x80 for data, 0x01 for domain separation

    wire [127:0] final_tag_value;
    assign final_tag_value = { swap_bytes64(x3 ^ swap_bytes64(key_in[127:64])), swap_bytes64(x4 ^ swap_bytes64(key_in[63:0])) };

    wire use_128bit_rate = (mode == MODE_AEAD);  // AEAD uses 128-bit rate for both AD and plaintext/ciphertext
    wire [63:0] data_in_64 = data_in[63:0];     // Lower 64 bits for hash modes
    wire [127:0] data_in_128 = data_in;         // Full 128 bits for AEAD plaintext/ciphertext
    
    wire [8:0] final_output_length;
    assign final_output_length = (mode == MODE_HASH) ? 9'd4 : output_length;
    

    wire output_complete = (bytes_output == final_output_length);

    // Both HASH and XOF modes use 64-bit rate
    //wire block_complete = data_block_count;  // True when data_block_count is 1
    
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= S_IDLE;
            busy <= 1'b0;
            done <= 1'b0;
            data_valid <= 1'b0;
            bytes_output <= 9'd0;
            just_padded  <= 1'b0;
            just_squeezed<= 1'b0;
            just_padded_custom <= 1'b0;
            custom_done  <= 1'b0;
            full_block_absorbed <= 1'b0;
            absorbing_custom_data <= 1'b0;
            aead_initialized <= 1'b0;
            aead_key_xor_pending <= 1'b0;
            first_data_block_processed <= 1'b0;
            first_ad_block <= 1'b1;  // Initialize to true for first AD block
            padding_context <= CONTEXT_CUSTOM;  // Initialize padding context to avoid Set/Reset priority warning
            x0 <= 64'd0;
            x1 <= 64'd0;
            x2 <= 64'd0;
            x3 <= 64'd0;
            x4 <= 64'd0;
            round <= 4'd0;
            data_out <= 128'd0;
            tag_out <= 256'd0;
            tag_valid <= 1'b0;
                        
        end
        else begin
            case (state)
                S_IDLE: begin
                    if (start) begin
                        // Initialize
                        state <= S_INIT;
                        done <= 1'b0;
                        data_valid <= 1'b0;
                        tag_valid  <= 1'b0;
                        tag_out    <= 256'd0;
                        bytes_output <= 9'd0;
                        
                        just_padded  <= 1'b0;
                        just_squeezed<= 1'b0;
                        custom_done  <= (mode != MODE_CXOF && mode != MODE_AEAD); // Skip customization for non-CXOF/AEAD modes
                        full_block_absorbed <= 1'b0;
                        absorbing_custom_data <= 1'b1;  // Start with custom/AD absorption
                        padding_context <= CONTEXT_CUSTOM;  // Default padding context
                        aead_initialized <= 1'b0;
                        first_ad_block <= 1'b1;  // Initialize to true at start of operation
                        first_data_block_processed <= 1'b0;
                        
                        x0 <= 64'h0;
                        x1 <= 64'h0;
                        x2 <= 64'h0;
                        x3 <= 64'h0;
                        x4 <= 64'h0;
                    end
                end
                
                S_INIT: begin
                    if (mode == MODE_AEAD) begin
                        x0 <= AEAD_IV;                          // IV = 0x00001000808c0001
                        x1 <= swap_bytes64(key_in[127:64]);     // K upper 64 bits
                        x2 <= swap_bytes64(key_in[63:0]);       // K lower 64 bits
                        x3 <= swap_bytes64(nonce_in[127:64]);   // N upper 64 bits
                        x4 <= swap_bytes64(nonce_in[63:0]);     // N lower 64 bits
                        
                        aead_initialized <= 1'b1;
                        aead_key_xor_pending <= 1'b1;  // Key XOR needed after permutation
                        
                    end else if(mode == MODE_HASH) begin
                        x0 <= HASH_IV;
                    end else if(mode == MODE_XOF) begin
                        x0 <= XOF_IV;
                    end else begin
                        x0 <= CXOF_IV;
                    end
                    
                    round <= ROUNDS_12;
                    state <= S_PERMUTE;
                    busy <= 1'b1;
                end
                
                S_ABSORB: begin
                    // Unified absorption for both custom/AD and message/PT/CT data
                    if (data_in_valid) begin
                        if (use_128bit_rate) begin
                            // AEAD mode: 128-bit processing
                            if (absorbing_custom_data) begin
                                // Custom/AD phase: Simple absorption (no output)
                                x0 <= x0 ^ swap_bytes64(data_in_128[127:64]);
                                x1 <= x1 ^ swap_bytes64(data_in_128[63:0]);
                                
                                // Key XOR should only happen for the first AD block
                                if (first_ad_block) begin
                                    x3 <= x3 ^ swap_bytes64(key_in[127:64]);   // S[3] ^= K[127:64]
                                    x4 <= x4 ^ swap_bytes64(key_in[63:0]);    // S[4] ^= K[63:0]       
                                    first_ad_block <= 1'b0;  // Clear flag after first block
                                end
                                data_valid <= 1'b0;  // No output for custom/AD data
                            end else begin
                                // Message/PT/CT phase: Complex processing with potential output
                                // Domain separation: only for the FIRST ciphertext block after AD
                                if (!first_data_block_processed) begin
                                    x4[63] <= x4[63] ^ 1'b1;  // XOR 0x0000000000000001 into x4
                                    first_data_block_processed <= 1'b1;
                                end
                                if (encrypt) begin
                                    // Encryption: XOR plaintext with state to get ciphertext
                                    // Update state with plaintext for authentication
                                    x0 <= x0 ^ swap_bytes64(data_in_128[127:64]);
                                    x1 <= x1 ^ swap_bytes64(data_in_128[63:0]);
                                end else begin
                                    // Decryption: XOR ciphertext with state to get plaintext  
                                    data_out <= {swap_bytes64(x0 ^ swap_bytes64(data_in_128[127:64])) , swap_bytes64(x1 ^ swap_bytes64(data_in_128[63:0]))};  // Output current state as ciphertext/plaintext
                                    data_valid <= 1'b1;
                                                                    
                                    // ASCON decryption state update: Full vs Partial block handling
                                    if (last_block && last_bytes != 4'd0) begin
                                        // Partial block: Selective state replacement with shared mask logic
                                        if (is_x0_only_bytes) begin
                                            // Partial data only in x0
                                            x0 <= (x0 & x0_preserve_mask) |
//                                                  (swap_bytes64(data_in_128[127:64]) & x0_replace_mask) | 64'h01 << (last_bytes * 8));
                                                  (swap_bytes64(data_in_128[127:64]) & x0_replace_mask);
                                            // x1 unchanged for partial blocks <= 8 bytes
                                        end else begin
                                            // Partial data extends to x1, x0 fully replaced
                                            x0 <= swap_bytes64(data_in_128[127:64]);
                                            x1 <= (x1 & x1_preserve_mask) |
//                                                  (swap_bytes64(data_in_128[63:0]) & x1_replace_mask) | (64'h01 << ((last_bytes - 4'd8) * 8));
                                                  (swap_bytes64(data_in_128[63:0]) & x1_replace_mask);
                                        end
                                    end else begin
                                        // Full block: Complete state replacement
                                        x0 <= swap_bytes64(data_in_128[127:64]);
                                        x1 <= swap_bytes64(data_in_128[63:0]);
                                    end
                                end
                                
                                // AEAD modes: Always go to output state after updating state
                                state <= S_AEAD_OUTPUT;
                            end
                        end else begin
                            // 64-bit modes: Hash/XOF/CXOF - identical processing regardless of phase
                            x0 <= x0 ^ swap_bytes64(data_in_64[63:0]);
                            data_valid <= 1'b0;  // No output until squeezing phase
                        end
                        
                        // Common last block handling logic (preserved from both original states)
                        if (!use_128bit_rate || absorbing_custom_data) begin
                            // For 64-bit modes OR 128-bit custom/AD phase, use standard flow control
                            if (last_block) begin
                                padding_context <= absorbing_custom_data ? CONTEXT_CUSTOM : CONTEXT_MESSAGE;
                                if (last_bytes == 4'd0) begin
                                    // Full last block: absorb data first, then need separate padding
                                    state <= S_PERMUTE;
                                    busy <= 1'b1;
                                    round <= permutation_rounds;
                                    full_block_absorbed <= 1'b1;
                                    
                                end else begin
                                    // Partial last block: can pad immediately in same cycle
                                    state <= S_PAD;
//                                    padding_context <= absorbing_custom_data ? CONTEXT_CUSTOM : CONTEXT_MESSAGE;
                                end
                            end else begin
                                // Not the last block - continue absorbing after permutation
                                state <= S_PERMUTE;
                                busy <= 1'b1;
                                round <= permutation_rounds;
                            end
                        end
                        // Note: 128-bit message/PT/CT phase handles state transition in AEAD branch above
                    end
                    else begin
                        state <= S_ABSORB;
                    end
                end
                
                S_PAD: begin
                    // Unified padding state for all modes (Custom/AD and Message/PT/CT)
                    // For full blocks (last_bytes=0), just add padding at bit 0
                    // For partial blocks, add padding after valid bytes (already XORed with data)
                    data_valid <= 1'b0;
                    if (use_128bit_rate) begin
                        // AEAD mode: 128-bit rate padding
                        if (last_bytes == 4'd0) begin
                            // Full 128-bit block case: add padding at first bit position
                            x0 <= x0 ^ 64'h01;  // Padding at bit position 0 of x0
                        end else if (last_bytes < 4'd8) begin
                            // Partial block in x0: add padding after valid bytes
                            x0 <= x0 ^ (64'h01 << (last_bytes * 8));
                        end else begin
                            // Partial block extends to x1: add padding in x1
                            x1 <= x1 ^ (64'h01 << ((last_bytes - 4'd8) * 8));
                        end
                    end else begin
                        // Hash/XOF/CXOF modes: 64-bit rate padding
                        if (last_bytes == 4'd0) begin
                            // Full 64-bit block case: add padding at first bit position
                            x0 <= x0 ^ 64'h01;  // Padding at bit position 0
                        end else begin
                            // Partial block case: add padding after the valid bytes
                            x0 <= x0 ^ (64'h01 << (last_bytes * 8));
                        end
                    end
                    
                    // Context-aware state transitions
                    case (padding_context)
                        CONTEXT_CUSTOM: begin
                            // Customization/AD padding complete
                            custom_done <= 1'b1;
                            just_padded_custom <= 1'b1;
                            state <= S_PERMUTE;
                            busy <= 1'b1;
                            round <= permutation_rounds;  // 8 rounds for AEAD AD, 12 for CXOF
                        end
                        CONTEXT_MESSAGE: begin
                            // Message/PT/CT padding complete
                            if (mode == MODE_AEAD) begin
                                // AEAD: go to finalization after message padding
                                state <= S_AEAD_FINAL;
                            end else begin
                                // Hash/XOF/CXOF: go to permutation then squeeze
                                state <= S_PERMUTE;
                                busy <= 1'b1;
                                round <= ROUNDS_12;  // Always 12 rounds for final padding in hash modes
                                just_padded  <= 1'b1;
                                just_squeezed<= 1'b0;
                            end
                        end
                        default: begin
                            // Fallback - should not happen
                            state <= S_PERMUTE;
                            busy <= 1'b1;
                            round <= ROUNDS_12;
                        end
                    endcase
                end
                
                S_AEAD_FINAL: begin
                    // AEAD finalization per NIST SP 800-232
                    // First: XOR key into S[rate//8] positions (S[2]||S[3] for rate=16)
                    x2 <= x2 ^ swap_bytes64(key_in[127:64]); // S[2] ^= K[127:64]
                    x3 <= x3 ^ swap_bytes64(key_in[63:0]);    // S[3] ^= K[63:0]
                    // Apply 12-round permutation, then final key XOR into S[3]||S[4]
                    round <= ROUNDS_12;
                    state <= S_PERMUTE;
                    busy <= 1'b1;
                    just_padded <= 1'b1;  // Reuse this flag to indicate AEAD finalization
                end
                
                S_PERMUTE: begin
                    // Update state with permutation output
                    {x0, x1, x2, x3, x4} <= {x0_out, x1_out, x2_out, x3_out, x4_out};
                    data_valid <= 1'b0;
                    
                    if (round == ROUNDS_1) begin
                        busy <= 1'b0;
                        
                        // Decide next state based on current context (priority order):
                        if (aead_key_xor_pending) begin
                            aead_key_xor_pending <= 1'b0;
                            state <= S_ABSORB;
                            absorbing_custom_data <= ((mode == MODE_CXOF || mode == MODE_AEAD) && !custom_done);
                        end
                        else if (just_padded) begin
                            state <= (mode == MODE_AEAD) ? S_TAG : S_SQUEEZE;
                            just_padded <= 1'b0;
                        end
                        else if (just_padded_custom) begin
                            state <= S_ABSORB;
                            absorbing_custom_data <= 1'b0;  // Switch to message/PT/CT phase
                            just_padded_custom <= 1'b0;
                        end
                        else if (just_squeezed) begin
                            state <= output_complete ? S_IDLE : S_SQUEEZE;
                            done <= output_complete;
                            // For HASH mode: set tag_valid when all output blocks collected
                            if (mode == MODE_HASH && output_complete) begin
                                tag_valid <= 1'b1;
                            end
                            just_squeezed <= 1'b0;
                        end
                        else if (full_block_absorbed) begin
                            state <= S_PAD;
                            // padding_context already set appropriately
                            full_block_absorbed <= 1'b0;
                        end
                        else begin
                            // Default: choose absorption phase based on mode and completion status
                            state <= S_ABSORB;
                            absorbing_custom_data <= ((mode == MODE_CXOF || mode == MODE_AEAD) && !custom_done);
                        end
                    end
                    else begin
                        round <= round - ROUNDS_1;
                    end
                end
                
                S_AEAD_OUTPUT: begin
                    // Generate AEAD ciphertext/plaintext output from updated state
                    // State has already been updated with input data in S_ABSORB unified state
                    // AEAD mode: Process plaintext/ciphertext with 128-bit rate
                    if (encrypt) begin
                        data_out <= {swap_bytes64(x0), swap_bytes64(x1)};  // Output current state as ciphertext/plaintext
                        data_valid <= 1'b1;
                    end
                            
                    // Handle flow control for next state
                    if (last_block) begin
                        padding_context <= CONTEXT_MESSAGE;
                        if (last_bytes == 4'd0) begin
                            // Full last block: need separate padding
                            state <= S_PERMUTE;
                            busy <= 1'b1;
                            round <= ROUNDS_8;
                            full_block_absorbed <= 1'b1;
//                            padding_context <= CONTEXT_MESSAGE;
                        end 
//                        else if(!encrypt) begin
//                            state <= S_PAD;
////                            busy <= 1'b1;
////                            round <= ROUNDS_12;
////                            full_block_absorbed <= 1'b1;
//                            padding_context <= CONTEXT_MESSAGE;
//                        end
                        else begin
                            // Partial last block: can pad immediately
                            state <= S_PAD;
                            
                        end
                    end else begin
                        // Not the last block - continue with permutation
                        state <= S_PERMUTE;
                        busy <= 1'b1;
                        round <= ROUNDS_8;
                    end
                end
                
                S_SQUEEZE: begin
                    // Only for Hash/XOF/CXOF modes (AEAD outputs during processing)
                    data_valid <= 1'b1;
                    just_squeezed<= 1'b1;
                    just_padded  <= 1'b0;
                    
                    // Hash/XOF/CXOF modes: Output 64 bits with byte reversal for endianness
                    data_out <= {64'b0, swap_bytes64(x0[63:0])};
                    bytes_output <= bytes_output + 9'd1; // 8 bytes per output (1 x 64-bit block)
                    
                    // For HASH mode: accumulate output into tag_out (256 bits = 4 x 64-bit blocks)
                    if (mode == MODE_HASH) begin
                        case (bytes_output)
                            9'd0: tag_out[255:192] <= swap_bytes64(x0[63:0]);  // First 64 bits (bytes 0-7)
                            9'd1: tag_out[191:128] <= swap_bytes64(x0[63:0]);  // Second 64 bits (bytes 8-15)
                            9'd2: tag_out[127:64]  <= swap_bytes64(x0[63:0]);  // Third 64 bits (bytes 16-23)
                            9'd3: tag_out[63:0]    <= swap_bytes64(x0[63:0]);  // Fourth 64 bits (bytes 24-31)
                        endcase
                    end
                                        
                    // After each output, perform permutation to get the next block
                    state <= S_PERMUTE;
                    busy <= 1'b1;
                    round <= ROUNDS_12;
                end
                S_TAG: begin
                    // AEAD: finalization complete, apply final key XOR and generate/verify tag
                    tag_out[127:0] <= final_tag_value;  // AEAD uses lower 128 bits
                    tag_out[255:128] <= 128'd0;          // Clear upper bits
                    if (encrypt) begin
                        // Encryption: tag is generated and always considered valid
                        tag_valid <= 1'b1;
                    end else if (expected_tag_valid) begin
                        // Decryption: verify provided tag matches computed tag
                        tag_valid <= (final_tag_value == expected_tag);
                    end else begin
                        // No tag provided for verification
                        tag_valid <= 1'b0;
                    end 
    
                      state <= S_IDLE;
                      done <= 1'b1;    
                end
            endcase
        end
    end
    
    // Ascon permutation instance
    asconp permutation (
        .rcon(round),
        .x0_in(x0),
        .x1_in(x1),
        .x2_in(x2),
        .x3_in(x3),
        .x4_in(x4),
        .x0_out(x0_out),
        .x1_out(x1_out),
        .x2_out(x2_out),
        .x3_out(x3_out),
        .x4_out(x4_out)
    );

endmodule

//module fifo_sync #(
// parameter WIDTH = 32,
// parameter DEPTH = 16,
// parameter AE_THRESH = 1,
// parameter AF_THRESH = DEPTH - 1
//)(
// input wire clk,
// input wire rst_n,
// // Write interface
// input wire wr_en,
// input wire [WIDTH-1:0] wr_data,
// output wire full,
// output wire almost_full,
// // Read interface
// input wire rd_en,
// output wire [WIDTH-1:0] rd_data,
// output wire rd_valid,
// output wire empty,
// output wire almost_empty
//);
//// // ------------------------------------------------------------
//// // Internal signals
//// // ------------------------------------------------------------
//reg [WIDTH-1:0] mem [0:DEPTH-1];
//reg [$clog2(DEPTH)-1:0] wr_ptr;
//reg [$clog2(DEPTH)-1:0] rd_ptr;
//reg [$clog2(DEPTH+1)-1:0] count;
//reg [WIDTH-1:0] rd_data_r;
//reg rd_valid_r;
//assign rd_data = rd_data_r;
//assign rd_valid = rd_valid_r;
//// // ------------------------------------------------------------
//// // Status flags
//// // ------------------------------------------------------------
//assign empty = (count == 0);
//assign full = (count == DEPTH);
//assign almost_empty = (count <= AE_THRESH);
//assign almost_full = (count >= AF_THRESH);
//wire writable = wr_en && !full;
//wire readable = rd_en && !empty;
//// // ------------------------------------------------------------
//// // Memory write (separated to avoid synthesis warning)
//// // ------------------------------------------------------------
//always @(posedge clk) begin
//  if (writable) begin
//    mem[wr_ptr] <= wr_data;
//  end
//end
//// // ------------------------------------------------------------
//// // Sequential logic for pointers and control
//// // ------------------------------------------------------------
//always @(posedge clk or negedge rst_n) begin
//  if (!rst_n) begin
//    wr_ptr <= 0;
//    rd_ptr <= 0;
//    count <= 0;
//    rd_data_r <= {WIDTH{1'b0}};
//    rd_valid_r <= 1'b0;
//  end else begin
//    // Handle pointer and counter updates
//    case ({writable, readable})
//      2'b10: begin
//        // Write only
//        wr_ptr <= wr_ptr + 1;
//        count <= count + 1;
//        rd_valid_r <= 1'b0; // no read this cycle
//      end
//      2'b01: begin
//        // Read only
//        rd_data_r <= mem[rd_ptr];
//        rd_ptr <= rd_ptr + 1;
//        count <= count - 1;
//        rd_valid_r <= 1'b1;
//      end
//      2'b11: begin
//        // Simultaneous read and write
//        wr_ptr <= wr_ptr + 1;
//        rd_data_r <= mem[rd_ptr];
//        rd_ptr <= rd_ptr + 1;
//        // Count unchanged
//        rd_valid_r <= 1'b1;
//      end
//      default: begin
//        rd_valid_r <= 1'b0;
//      end
//    endcase
//  end
//end
//endmodule
/******************************************************************************
 This Source Code Form is subject to the terms of the
 Open Hardware Description License, v. 1.0. If a copy
 of the OHDL was not distributed with this file, You
 can obtain one at http://juliusbaxter.net/ohdl/ohdl.txt

 Description: Store buffer
 Currently a simple single clock FIFO, but with the ambition to
 have combining and reordering capabilities in the future.

 Copyright (C) 2013 Stefan Kristiansson <stefan.kristiansson@saunalahti.fi>

 ******************************************************************************/

module fifo
  #(
    parameter DEPTH_WIDTH = 0,
    parameter DATA_WIDTH = 0
    )
   (
    input 		    clk,
    input 		    rst,

    input [DATA_WIDTH-1:0]  wr_data_i,
    input 		    wr_en_i,

    output [DATA_WIDTH-1:0] rd_data_o,
    input 		    rd_en_i,

    output 		    full_o,
    output reg    valid,
    output        empty_o
    );

   localparam DW = (DATA_WIDTH  < 1) ? 1 : DATA_WIDTH;
   localparam AW = (DEPTH_WIDTH < 1) ? 1 : DEPTH_WIDTH;

   //synthesis translate_off
   initial begin
      if(DEPTH_WIDTH < 1) $display("%m : Warning: DEPTH_WIDTH must be > 0. Setting minimum value (1)");
      if(DATA_WIDTH < 1) $display("%m : Warning: DATA_WIDTH must be > 0. Setting minimum value (1)");
   end
   //synthesis translate_on

   reg [AW:0] write_pointer;
   reg [AW:0] read_pointer;
   
   wire 	       empty_int = (write_pointer[AW] ==
				    read_pointer[AW]);
   wire 	       full_or_empty = (write_pointer[AW-1:0] ==
					read_pointer[AW-1:0]);
   
   assign full_o  = full_or_empty & !empty_int;
   assign empty_o = full_or_empty & empty_int;
   
always @(posedge clk) begin
    if (wr_en_i & !full_o)
      write_pointer <= write_pointer + 1'd1;
    if (rd_en_i & !empty_o) begin
      valid <= 1'b1;
      read_pointer <= read_pointer + 1'd1;
    end else begin
      valid <= 1'b0;
    end
    if (rst) begin
      read_pointer <= 0;
      write_pointer <= 0;
      valid <= 1'b0;
    end
  end
   simple_dpram_sclk
     #(
       .ADDR_WIDTH(AW),
       .DATA_WIDTH(DW),
       .ENABLE_BYPASS(1)
       )
   fifo_ram
     (
      .clk			(clk),
      .dout			(rd_data_o),
      .raddr			(read_pointer[AW-1:0]),
      .re			(rd_en_i),
      .waddr			(write_pointer[AW-1:0]),
      .we			(wr_en_i),
      .din			(wr_data_i)
      );

endmodule


/******************************************************************************
 This Source Code Form is subject to the terms of the
 Open Hardware Description License, v. 1.0. If a copy
 of the OHDL was not distributed with this file, You
 can obtain one at http://juliusbaxter.net/ohdl/ohdl.txt

 Description:
 Simple single clocked dual port ram (separate read and write ports),
 with optional bypass logic.

 Copyright (C) 2012 Stefan Kristiansson <stefan.kristiansson@saunalahti.fi>

 ******************************************************************************/

module simple_dpram_sclk
  #(
    parameter ADDR_WIDTH = 32,
    parameter DATA_WIDTH = 32,
    parameter ENABLE_BYPASS = 1
    )
   (
    input 		    clk,
    input [ADDR_WIDTH-1:0]  raddr,
    input 		    re,
    input [ADDR_WIDTH-1:0]  waddr,
    input 		    we,
    input [DATA_WIDTH-1:0]  din,
    output [DATA_WIDTH-1:0] dout
    );

   reg [DATA_WIDTH-1:0]     mem[(1<<ADDR_WIDTH)-1:0];
   reg [DATA_WIDTH-1:0]     rdata;

generate
if (ENABLE_BYPASS) begin : bypass_gen
   reg [DATA_WIDTH-1:0]     din_r;
   reg 			    bypass;

   assign dout = bypass ? din_r : rdata;

   always @(posedge clk)
     if (re)
       din_r <= din;

   always @(posedge clk)
     if (waddr == raddr && we && re)
       bypass <= 1;
     else if (re)
       bypass <= 0;
end else begin
   assign dout = rdata;
end
endgenerate

   always @(posedge clk) begin
      if (we)
	mem[waddr] <= din;
      if (re) begin
	rdata <= mem[raddr];
	end
   end

endmodule



module asconp
    #(                  parameter                   STATE_WORDS     = 64,
                        parameter                   BYTE_WIDTH      = 8,
                        parameter   [3:0]           ROUND_16        = 4'hF,   
                        parameter   [3:0]           ROUND_12        = 4'hC   
    )
    (
                        //input       [319:0]         state_in,
                        input       [3:0]           rcon,
                        //output      [319:0]         state_out,
                        output wire      [63:0]          x0_out,    
                        output wire      [63:0]          x1_out,    
                        output wire      [63:0]          x2_out,    
                        output wire      [63:0]          x3_out,    
                        output wire      [63:0]          x4_out,    
                        input wire       [63:0]          x0_in,    
                        input wire       [63:0]          x1_in,    
                        input wire       [63:0]          x2_in,    
                        input wire       [63:0]          x3_in,    
                        input wire      [63:0]          x4_in    
    );
    
//wire [STATE_WORDS - 1:0] x0, x1, x2, x3, x4;
wire [STATE_WORDS - 1:0] x0_r, x1_r, x2_r, x3_r, x4_r;
wire [STATE_WORDS - 1:0] t0, t1;
wire [STATE_WORDS - 1:0] x0_first, x1_first, x2_first, x3_first, x4_first;
wire [STATE_WORDS - 1:0] x0_second, x1_second, x2_second, x3_second, x4_second;
wire [STATE_WORDS - 1:0] x0_third, x1_third, x2_third, x3_third, x4_third;
//wire [STATE_WORDS - 1:0] x0_rotated, x1_rotated, x2_rotated, x3_rotated, x4_rotated;
//wire [STATE_WORDS - 1:0] x0_out, x1_out, x2_out, x3_out, x4_out;
wire [BYTE_WIDTH - 1:0] round_constant;
wire [BYTE_WIDTH - 1:0] x2_constant;
wire [55: 0] x2_no_constant;
wire [3:0]               t2;

assign x0_r = x0_in;
assign x1_r = x1_in;
assign x2_r = x2_in;
assign x3_r = x3_in;
assign x4_r = x4_in;
//Linear operation and addition of round constant

assign x0_first = x0_r ^ x4_r;

assign x1_first = x1_r;

assign t2 = ROUND_12 - rcon;
assign round_constant [7:4] = ROUND_16 - t2;
assign round_constant [3:0] = t2;
assign x2_constant = x2_r[7:0] ^ x1_r[7:0] ^ round_constant;
assign x2_no_constant  = x2_r[63:8] ^ x1_r[63:8];
assign x2_first = {x2_no_constant, x2_constant};

assign x3_first = x3_r;

assign x4_first = x4_r ^ x3_r;

//Nonlinear operation
assign t0 = x0_first;
assign t1 = x1_first;
assign x0_second = x0_first ^ ((~x1_first) & x2_first);
assign x1_second = x1_first ^ ((~x2_first) & x3_first);
assign x2_second = x2_first ^ ((~x3_first) & x4_first);
assign x3_second = x3_first ^ ((~x4_first) & x0_first);
assign x4_second = x4_first ^ ((~t0) & t1);

//Linear operation
assign x0_third = x0_second ^ x4_second;
assign x1_third = x1_second ^ x0_second;
assign x2_third = ~x2_second;
assign x3_third = x2_second ^ x3_second;
assign x4_third = x4_second;

//Lane rotation
/*
assign x0_rotated = x0_third ^ {x0_third[18:0], x0_third[63:19]} ^ {x0_third[27:0], x0_third[63:28]}; 
assign x1_rotated = x1_third ^ {x1_third[60:0], x1_third[63:61]} ^ {x1_third[38:0], x1_third[63:39]}; 
assign x2_rotated = x2_third ^ {x2_third[0:0],  x2_third[63:1]}  ^ {x2_third[5:0],  x2_third[63:6]}; 
assign x3_rotated = x3_third ^ {x3_third[9:0],  x3_third[63:10]} ^ {x3_third[16:0], x3_third[63:17]}; 
assign x4_rotated = x4_third ^ {x4_third[6:0],  x4_third[63:7]}  ^ {x4_third[40:0], x4_third[63:41]}; 
*/

assign x0_out = x0_third ^ {x0_third[18:0], x0_third[63:19]} ^ {x0_third[27:0], x0_third[63:28]}; 
assign x1_out = x1_third ^ {x1_third[60:0], x1_third[63:61]} ^ {x1_third[38:0], x1_third[63:39]}; 
assign x2_out = x2_third ^ {x2_third[0:0],  x2_third[63:1]}  ^ {x2_third[5:0],  x2_third[63:6]}; 
assign x3_out = x3_third ^ {x3_third[9:0],  x3_third[63:10]} ^ {x3_third[16:0], x3_third[63:17]}; 
assign x4_out = x4_third ^ {x4_third[6:0],  x4_third[63:7]}  ^ {x4_third[40:0], x4_third[63:41]}; 

//Map 5 x 64-bit lanes to 320 bit vector output

//assign state_out [STATE_WORDS -1 + 4 * STATE_WORDS : 4 * STATE_WORDS] = x0_out;
//assign state_out [STATE_WORDS -1 + 3 * STATE_WORDS : 3 * STATE_WORDS] = x1_out;
//assign state_out [STATE_WORDS -1 + 2 * STATE_WORDS : 2 * STATE_WORDS] = x2_out;
//assign state_out [STATE_WORDS -1 + 1 * STATE_WORDS : 1 * STATE_WORDS] = x3_out;
//assign state_out [STATE_WORDS -1 + 0 * STATE_WORDS : 0 * STATE_WORDS] = x4_out;


endmodule

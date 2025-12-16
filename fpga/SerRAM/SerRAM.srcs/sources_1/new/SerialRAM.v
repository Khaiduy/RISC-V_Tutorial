`timescale 1ns / 1ps

module SerialRAM(
  input        clock,
               reset,
               io_ser_in_ready,
               io_ser_out_valid,
  input  [7:0] io_ser_out_bits,
  output       io_ser_in_valid,
  output [7:0] io_ser_in_bits,
  output       io_ser_out_ready
);

  wire        _buffer_1_auto_in_a_ready;	// @[Buffer.scala:69:28]
  wire        _buffer_1_auto_in_d_valid;	// @[Buffer.scala:69:28]
  wire [63:0] _buffer_1_auto_in_d_bits_data;	// @[Buffer.scala:69:28]
  wire        _buffer_1_auto_out_a_valid;	// @[Buffer.scala:69:28]
  wire [2:0]  _buffer_1_auto_out_a_bits_opcode;	// @[Buffer.scala:69:28]
  wire [2:0]  _buffer_1_auto_out_a_bits_param;	// @[Buffer.scala:69:28]
  wire [3:0]  _buffer_1_auto_out_a_bits_size;	// @[Buffer.scala:69:28]
  wire        _buffer_1_auto_out_a_bits_source;	// @[Buffer.scala:69:28]
  wire [31:0] _buffer_1_auto_out_a_bits_address;	// @[Buffer.scala:69:28]
  wire [7:0]  _buffer_1_auto_out_a_bits_mask;	// @[Buffer.scala:69:28]
  wire [63:0] _buffer_1_auto_out_a_bits_data;	// @[Buffer.scala:69:28]
  wire        _buffer_1_auto_out_a_bits_corrupt;	// @[Buffer.scala:69:28]
  wire        _buffer_1_auto_out_d_ready;	// @[Buffer.scala:69:28]
  wire        _fragmenter_auto_in_a_ready;	// @[Fragmenter.scala:335:34]
  wire        _fragmenter_auto_in_d_valid;	// @[Fragmenter.scala:335:34]
  wire [2:0]  _fragmenter_auto_in_d_bits_opcode;	// @[Fragmenter.scala:335:34]
  wire [1:0]  _fragmenter_auto_in_d_bits_param;	// @[Fragmenter.scala:335:34]
  wire [2:0]  _fragmenter_auto_in_d_bits_size;	// @[Fragmenter.scala:335:34]
  wire [6:0]  _fragmenter_auto_in_d_bits_source;	// @[Fragmenter.scala:335:34]
  wire        _fragmenter_auto_in_d_bits_sink;	// @[Fragmenter.scala:335:34]
  wire        _fragmenter_auto_in_d_bits_denied;	// @[Fragmenter.scala:335:34]
  wire [63:0] _fragmenter_auto_in_d_bits_data;	// @[Fragmenter.scala:335:34]
  wire        _fragmenter_auto_in_d_bits_corrupt;	// @[Fragmenter.scala:335:34]
  wire        _fragmenter_auto_out_a_valid;	// @[Fragmenter.scala:335:34]
  wire [2:0]  _fragmenter_auto_out_a_bits_opcode;	// @[Fragmenter.scala:335:34]
  wire [2:0]  _fragmenter_auto_out_a_bits_param;	// @[Fragmenter.scala:335:34]
  wire [1:0]  _fragmenter_auto_out_a_bits_size;	// @[Fragmenter.scala:335:34]
  wire [10:0] _fragmenter_auto_out_a_bits_source;	// @[Fragmenter.scala:335:34]
  wire [31:0] _fragmenter_auto_out_a_bits_address;	// @[Fragmenter.scala:335:34]
  wire [7:0]  _fragmenter_auto_out_a_bits_mask;	// @[Fragmenter.scala:335:34]
  wire [63:0] _fragmenter_auto_out_a_bits_data;	// @[Fragmenter.scala:335:34]
  wire        _fragmenter_auto_out_a_bits_corrupt;	// @[Fragmenter.scala:335:34]
  wire        _fragmenter_auto_out_d_ready;	// @[Fragmenter.scala:335:34]
  wire        _buffer_auto_in_a_ready;	// @[Buffer.scala:69:28]
  wire        _buffer_auto_in_d_valid;	// @[Buffer.scala:69:28]
  wire [2:0]  _buffer_auto_in_d_bits_opcode;	// @[Buffer.scala:69:28]
  wire [1:0]  _buffer_auto_in_d_bits_param;	// @[Buffer.scala:69:28]
  wire [1:0]  _buffer_auto_in_d_bits_size;	// @[Buffer.scala:69:28]
  wire [10:0] _buffer_auto_in_d_bits_source;	// @[Buffer.scala:69:28]
  wire        _buffer_auto_in_d_bits_sink;	// @[Buffer.scala:69:28]
  wire        _buffer_auto_in_d_bits_denied;	// @[Buffer.scala:69:28]
  wire [63:0] _buffer_auto_in_d_bits_data;	// @[Buffer.scala:69:28]
  wire        _buffer_auto_in_d_bits_corrupt;	// @[Buffer.scala:69:28]
  wire        _buffer_auto_out_a_valid;	// @[Buffer.scala:69:28]
  wire [2:0]  _buffer_auto_out_a_bits_opcode;	// @[Buffer.scala:69:28]
  wire [1:0]  _buffer_auto_out_a_bits_size;	// @[Buffer.scala:69:28]
  wire [10:0] _buffer_auto_out_a_bits_source;	// @[Buffer.scala:69:28]
  wire [31:0] _buffer_auto_out_a_bits_address;	// @[Buffer.scala:69:28]
  wire [7:0]  _buffer_auto_out_a_bits_mask;	// @[Buffer.scala:69:28]
  wire [63:0] _buffer_auto_out_a_bits_data;	// @[Buffer.scala:69:28]
  wire        _buffer_auto_out_d_ready;	// @[Buffer.scala:69:28]
  wire        _srams_auto_in_a_ready;	// @[TSIHarness.scala:102:17]
  wire        _srams_auto_in_d_valid;	// @[TSIHarness.scala:102:17]
  wire [2:0]  _srams_auto_in_d_bits_opcode;	// @[TSIHarness.scala:102:17]
  wire [1:0]  _srams_auto_in_d_bits_size;	// @[TSIHarness.scala:102:17]
  wire [10:0] _srams_auto_in_d_bits_source;	// @[TSIHarness.scala:102:17]
  wire [63:0] _srams_auto_in_d_bits_data;	// @[TSIHarness.scala:102:17]
  wire        _serdesser_auto_manager_in_a_ready;	// @[TSIHarness.scala:91:29]
  wire        _serdesser_auto_manager_in_d_valid;	// @[TSIHarness.scala:91:29]
  wire [2:0]  _serdesser_auto_manager_in_d_bits_opcode;	// @[TSIHarness.scala:91:29]
  wire [1:0]  _serdesser_auto_manager_in_d_bits_param;	// @[TSIHarness.scala:91:29]
  wire [3:0]  _serdesser_auto_manager_in_d_bits_size;	// @[TSIHarness.scala:91:29]
  wire        _serdesser_auto_manager_in_d_bits_source;	// @[TSIHarness.scala:91:29]
  wire [1:0]  _serdesser_auto_manager_in_d_bits_sink;	// @[TSIHarness.scala:91:29]
  wire        _serdesser_auto_manager_in_d_bits_denied;	// @[TSIHarness.scala:91:29]
  wire [63:0] _serdesser_auto_manager_in_d_bits_data;	// @[TSIHarness.scala:91:29]
  wire        _serdesser_auto_manager_in_d_bits_corrupt;	// @[TSIHarness.scala:91:29]
  wire        _serdesser_auto_client_out_a_valid;	// @[TSIHarness.scala:91:29]
  wire [2:0]  _serdesser_auto_client_out_a_bits_opcode;	// @[TSIHarness.scala:91:29]
  wire [2:0]  _serdesser_auto_client_out_a_bits_param;	// @[TSIHarness.scala:91:29]
  wire [2:0]  _serdesser_auto_client_out_a_bits_size;	// @[TSIHarness.scala:91:29]
  wire [6:0]  _serdesser_auto_client_out_a_bits_source;	// @[TSIHarness.scala:91:29]
  wire [31:0] _serdesser_auto_client_out_a_bits_address;	// @[TSIHarness.scala:91:29]
  wire [7:0]  _serdesser_auto_client_out_a_bits_mask;	// @[TSIHarness.scala:91:29]
  wire [63:0] _serdesser_auto_client_out_a_bits_data;	// @[TSIHarness.scala:91:29]
  wire        _serdesser_auto_client_out_a_bits_corrupt;	// @[TSIHarness.scala:91:29]
  wire        _serdesser_auto_client_out_d_ready;	// @[TSIHarness.scala:91:29]
  wire        _tsi2tl_auto_out_a_valid;	// @[TSIHarness.scala:90:26]
  wire [2:0]  _tsi2tl_auto_out_a_bits_opcode;	// @[TSIHarness.scala:90:26]
  wire [3:0]  _tsi2tl_auto_out_a_bits_size;	// @[TSIHarness.scala:90:26]
  wire [31:0] _tsi2tl_auto_out_a_bits_address;	// @[TSIHarness.scala:90:26]
  wire [7:0]  _tsi2tl_auto_out_a_bits_mask;	// @[TSIHarness.scala:90:26]
  wire [63:0] _tsi2tl_auto_out_a_bits_data;	// @[TSIHarness.scala:90:26]
  wire        _tsi2tl_auto_out_d_ready;	// @[TSIHarness.scala:90:26]
  TSIToTileLink tsi2tl (	// @[TSIHarness.scala:90:26]
    .clock                   (clock),
    .reset                   (reset),
    .auto_out_a_ready        (_buffer_1_auto_in_a_ready),	// @[Buffer.scala:69:28]
    .auto_out_d_valid        (_buffer_1_auto_in_d_valid),	// @[Buffer.scala:69:28]
    .auto_out_d_bits_data    (_buffer_1_auto_in_d_bits_data),	// @[Buffer.scala:69:28]
    .auto_out_a_valid        (_tsi2tl_auto_out_a_valid),
    .auto_out_a_bits_opcode  (_tsi2tl_auto_out_a_bits_opcode),
    .auto_out_a_bits_size    (_tsi2tl_auto_out_a_bits_size),
    .auto_out_a_bits_address (_tsi2tl_auto_out_a_bits_address),
    .auto_out_a_bits_mask    (_tsi2tl_auto_out_a_bits_mask),
    .auto_out_a_bits_data    (_tsi2tl_auto_out_a_bits_data),
    .auto_out_d_ready        (_tsi2tl_auto_out_d_ready)
  );
  TLSerdesser_1 serdesser (	// @[TSIHarness.scala:91:29]
    .clock                          (clock),
    .reset                          (reset),
    .auto_manager_in_a_valid        (_buffer_1_auto_out_a_valid),	// @[Buffer.scala:69:28]
    .auto_manager_in_a_bits_opcode  (_buffer_1_auto_out_a_bits_opcode),	// @[Buffer.scala:69:28]
    .auto_manager_in_a_bits_param   (_buffer_1_auto_out_a_bits_param),	// @[Buffer.scala:69:28]
    .auto_manager_in_a_bits_size    (_buffer_1_auto_out_a_bits_size),	// @[Buffer.scala:69:28]
    .auto_manager_in_a_bits_source  (_buffer_1_auto_out_a_bits_source),	// @[Buffer.scala:69:28]
    .auto_manager_in_a_bits_address (_buffer_1_auto_out_a_bits_address),	// @[Buffer.scala:69:28]
    .auto_manager_in_a_bits_mask    (_buffer_1_auto_out_a_bits_mask),	// @[Buffer.scala:69:28]
    .auto_manager_in_a_bits_data    (_buffer_1_auto_out_a_bits_data),	// @[Buffer.scala:69:28]
    .auto_manager_in_a_bits_corrupt (_buffer_1_auto_out_a_bits_corrupt),	// @[Buffer.scala:69:28]
    .auto_manager_in_d_ready        (_buffer_1_auto_out_d_ready),	// @[Buffer.scala:69:28]
    .auto_client_out_a_ready        (_fragmenter_auto_in_a_ready),	// @[Fragmenter.scala:335:34]
    .auto_client_out_d_valid        (_fragmenter_auto_in_d_valid),	// @[Fragmenter.scala:335:34]
    .auto_client_out_d_bits_opcode  (_fragmenter_auto_in_d_bits_opcode),	// @[Fragmenter.scala:335:34]
    .auto_client_out_d_bits_param   (_fragmenter_auto_in_d_bits_param),	// @[Fragmenter.scala:335:34]
    .auto_client_out_d_bits_size    (_fragmenter_auto_in_d_bits_size),	// @[Fragmenter.scala:335:34]
    .auto_client_out_d_bits_source  (_fragmenter_auto_in_d_bits_source),	// @[Fragmenter.scala:335:34]
    .auto_client_out_d_bits_sink    (_fragmenter_auto_in_d_bits_sink),	// @[Fragmenter.scala:335:34]
    .auto_client_out_d_bits_denied  (_fragmenter_auto_in_d_bits_denied),	// @[Fragmenter.scala:335:34]
    .auto_client_out_d_bits_data    (_fragmenter_auto_in_d_bits_data),	// @[Fragmenter.scala:335:34]
    .auto_client_out_d_bits_corrupt (_fragmenter_auto_in_d_bits_corrupt),	// @[Fragmenter.scala:335:34]
    .io_ser_in_valid                (io_ser_out_valid),
    .io_ser_in_bits                 (io_ser_out_bits),
    .io_ser_out_ready               (io_ser_in_ready),
    .auto_manager_in_a_ready        (_serdesser_auto_manager_in_a_ready),
    .auto_manager_in_d_valid        (_serdesser_auto_manager_in_d_valid),
    .auto_manager_in_d_bits_opcode  (_serdesser_auto_manager_in_d_bits_opcode),
    .auto_manager_in_d_bits_param   (_serdesser_auto_manager_in_d_bits_param),
    .auto_manager_in_d_bits_size    (_serdesser_auto_manager_in_d_bits_size),
    .auto_manager_in_d_bits_source  (_serdesser_auto_manager_in_d_bits_source),
    .auto_manager_in_d_bits_sink    (_serdesser_auto_manager_in_d_bits_sink),
    .auto_manager_in_d_bits_denied  (_serdesser_auto_manager_in_d_bits_denied),
    .auto_manager_in_d_bits_data    (_serdesser_auto_manager_in_d_bits_data),
    .auto_manager_in_d_bits_corrupt (_serdesser_auto_manager_in_d_bits_corrupt),
    .auto_client_out_a_valid        (_serdesser_auto_client_out_a_valid),
    .auto_client_out_a_bits_opcode  (_serdesser_auto_client_out_a_bits_opcode),
    .auto_client_out_a_bits_param   (_serdesser_auto_client_out_a_bits_param),
    .auto_client_out_a_bits_size    (_serdesser_auto_client_out_a_bits_size),
    .auto_client_out_a_bits_source  (_serdesser_auto_client_out_a_bits_source),
    .auto_client_out_a_bits_address (_serdesser_auto_client_out_a_bits_address),
    .auto_client_out_a_bits_mask    (_serdesser_auto_client_out_a_bits_mask),
    .auto_client_out_a_bits_data    (_serdesser_auto_client_out_a_bits_data),
    .auto_client_out_a_bits_corrupt (_serdesser_auto_client_out_a_bits_corrupt),
    .auto_client_out_d_ready        (_serdesser_auto_client_out_d_ready),
    .io_ser_in_ready                (io_ser_out_ready),
    .io_ser_out_valid               (io_ser_in_valid),
    .io_ser_out_bits                (io_ser_in_bits)
  );
  TLRAM_1 srams (	// @[TSIHarness.scala:102:17]
    .clock                  (clock),
    .reset                  (reset),
    .auto_in_a_valid        (_buffer_auto_out_a_valid),	// @[Buffer.scala:69:28]
    .auto_in_a_bits_opcode  (_buffer_auto_out_a_bits_opcode),	// @[Buffer.scala:69:28]
    .auto_in_a_bits_size    (_buffer_auto_out_a_bits_size),	// @[Buffer.scala:69:28]
    .auto_in_a_bits_source  (_buffer_auto_out_a_bits_source),	// @[Buffer.scala:69:28]
    .auto_in_a_bits_address (_buffer_auto_out_a_bits_address),	// @[Buffer.scala:69:28]
    .auto_in_a_bits_mask    (_buffer_auto_out_a_bits_mask),	// @[Buffer.scala:69:28]
    .auto_in_a_bits_data    (_buffer_auto_out_a_bits_data),	// @[Buffer.scala:69:28]
    .auto_in_d_ready        (_buffer_auto_out_d_ready),	// @[Buffer.scala:69:28]
    .auto_in_a_ready        (_srams_auto_in_a_ready),
    .auto_in_d_valid        (_srams_auto_in_d_valid),
    .auto_in_d_bits_opcode  (_srams_auto_in_d_bits_opcode),
    .auto_in_d_bits_size    (_srams_auto_in_d_bits_size),
    .auto_in_d_bits_source  (_srams_auto_in_d_bits_source),
    .auto_in_d_bits_data    (_srams_auto_in_d_bits_data)
  );
  TLBuffer_18 buffer (	// @[Buffer.scala:69:28]
    .clock                   (clock),
    .reset                   (reset),
    .auto_in_a_valid         (_fragmenter_auto_out_a_valid),	// @[Fragmenter.scala:335:34]
    .auto_in_a_bits_opcode   (_fragmenter_auto_out_a_bits_opcode),	// @[Fragmenter.scala:335:34]
    .auto_in_a_bits_param    (_fragmenter_auto_out_a_bits_param),	// @[Fragmenter.scala:335:34]
    .auto_in_a_bits_size     (_fragmenter_auto_out_a_bits_size),	// @[Fragmenter.scala:335:34]
    .auto_in_a_bits_source   (_fragmenter_auto_out_a_bits_source),	// @[Fragmenter.scala:335:34]
    .auto_in_a_bits_address  (_fragmenter_auto_out_a_bits_address),	// @[Fragmenter.scala:335:34]
    .auto_in_a_bits_mask     (_fragmenter_auto_out_a_bits_mask),	// @[Fragmenter.scala:335:34]
    .auto_in_a_bits_data     (_fragmenter_auto_out_a_bits_data),	// @[Fragmenter.scala:335:34]
    .auto_in_a_bits_corrupt  (_fragmenter_auto_out_a_bits_corrupt),	// @[Fragmenter.scala:335:34]
    .auto_in_d_ready         (_fragmenter_auto_out_d_ready),	// @[Fragmenter.scala:335:34]
    .auto_out_a_ready        (_srams_auto_in_a_ready),	// @[TSIHarness.scala:102:17]
    .auto_out_d_valid        (_srams_auto_in_d_valid),	// @[TSIHarness.scala:102:17]
    .auto_out_d_bits_opcode  (_srams_auto_in_d_bits_opcode),	// @[TSIHarness.scala:102:17]
    .auto_out_d_bits_size    (_srams_auto_in_d_bits_size),	// @[TSIHarness.scala:102:17]
    .auto_out_d_bits_source  (_srams_auto_in_d_bits_source),	// @[TSIHarness.scala:102:17]
    .auto_out_d_bits_data    (_srams_auto_in_d_bits_data),	// @[TSIHarness.scala:102:17]
    .auto_in_a_ready         (_buffer_auto_in_a_ready),
    .auto_in_d_valid         (_buffer_auto_in_d_valid),
    .auto_in_d_bits_opcode   (_buffer_auto_in_d_bits_opcode),
    .auto_in_d_bits_param    (_buffer_auto_in_d_bits_param),
    .auto_in_d_bits_size     (_buffer_auto_in_d_bits_size),
    .auto_in_d_bits_source   (_buffer_auto_in_d_bits_source),
    .auto_in_d_bits_sink     (_buffer_auto_in_d_bits_sink),
    .auto_in_d_bits_denied   (_buffer_auto_in_d_bits_denied),
    .auto_in_d_bits_data     (_buffer_auto_in_d_bits_data),
    .auto_in_d_bits_corrupt  (_buffer_auto_in_d_bits_corrupt),
    .auto_out_a_valid        (_buffer_auto_out_a_valid),
    .auto_out_a_bits_opcode  (_buffer_auto_out_a_bits_opcode),
    .auto_out_a_bits_size    (_buffer_auto_out_a_bits_size),
    .auto_out_a_bits_source  (_buffer_auto_out_a_bits_source),
    .auto_out_a_bits_address (_buffer_auto_out_a_bits_address),
    .auto_out_a_bits_mask    (_buffer_auto_out_a_bits_mask),
    .auto_out_a_bits_data    (_buffer_auto_out_a_bits_data),
    .auto_out_d_ready        (_buffer_auto_out_d_ready)
  );
  TLFragmenter_11 fragmenter (	// @[Fragmenter.scala:335:34]
    .clock                   (clock),
    .reset                   (reset),
    .auto_in_a_valid         (_serdesser_auto_client_out_a_valid),	// @[TSIHarness.scala:91:29]
    .auto_in_a_bits_opcode   (_serdesser_auto_client_out_a_bits_opcode),	// @[TSIHarness.scala:91:29]
    .auto_in_a_bits_param    (_serdesser_auto_client_out_a_bits_param),	// @[TSIHarness.scala:91:29]
    .auto_in_a_bits_size     (_serdesser_auto_client_out_a_bits_size),	// @[TSIHarness.scala:91:29]
    .auto_in_a_bits_source   (_serdesser_auto_client_out_a_bits_source),	// @[TSIHarness.scala:91:29]
    .auto_in_a_bits_address  (_serdesser_auto_client_out_a_bits_address),	// @[TSIHarness.scala:91:29]
    .auto_in_a_bits_mask     (_serdesser_auto_client_out_a_bits_mask),	// @[TSIHarness.scala:91:29]
    .auto_in_a_bits_data     (_serdesser_auto_client_out_a_bits_data),	// @[TSIHarness.scala:91:29]
    .auto_in_a_bits_corrupt  (_serdesser_auto_client_out_a_bits_corrupt),	// @[TSIHarness.scala:91:29]
    .auto_in_d_ready         (_serdesser_auto_client_out_d_ready),	// @[TSIHarness.scala:91:29]
    .auto_out_a_ready        (_buffer_auto_in_a_ready),	// @[Buffer.scala:69:28]
    .auto_out_d_valid        (_buffer_auto_in_d_valid),	// @[Buffer.scala:69:28]
    .auto_out_d_bits_opcode  (_buffer_auto_in_d_bits_opcode),	// @[Buffer.scala:69:28]
    .auto_out_d_bits_param   (_buffer_auto_in_d_bits_param),	// @[Buffer.scala:69:28]
    .auto_out_d_bits_size    (_buffer_auto_in_d_bits_size),	// @[Buffer.scala:69:28]
    .auto_out_d_bits_source  (_buffer_auto_in_d_bits_source),	// @[Buffer.scala:69:28]
    .auto_out_d_bits_sink    (_buffer_auto_in_d_bits_sink),	// @[Buffer.scala:69:28]
    .auto_out_d_bits_denied  (_buffer_auto_in_d_bits_denied),	// @[Buffer.scala:69:28]
    .auto_out_d_bits_data    (_buffer_auto_in_d_bits_data),	// @[Buffer.scala:69:28]
    .auto_out_d_bits_corrupt (_buffer_auto_in_d_bits_corrupt),	// @[Buffer.scala:69:28]
    .auto_in_a_ready         (_fragmenter_auto_in_a_ready),
    .auto_in_d_valid         (_fragmenter_auto_in_d_valid),
    .auto_in_d_bits_opcode   (_fragmenter_auto_in_d_bits_opcode),
    .auto_in_d_bits_param    (_fragmenter_auto_in_d_bits_param),
    .auto_in_d_bits_size     (_fragmenter_auto_in_d_bits_size),
    .auto_in_d_bits_source   (_fragmenter_auto_in_d_bits_source),
    .auto_in_d_bits_sink     (_fragmenter_auto_in_d_bits_sink),
    .auto_in_d_bits_denied   (_fragmenter_auto_in_d_bits_denied),
    .auto_in_d_bits_data     (_fragmenter_auto_in_d_bits_data),
    .auto_in_d_bits_corrupt  (_fragmenter_auto_in_d_bits_corrupt),
    .auto_out_a_valid        (_fragmenter_auto_out_a_valid),
    .auto_out_a_bits_opcode  (_fragmenter_auto_out_a_bits_opcode),
    .auto_out_a_bits_param   (_fragmenter_auto_out_a_bits_param),
    .auto_out_a_bits_size    (_fragmenter_auto_out_a_bits_size),
    .auto_out_a_bits_source  (_fragmenter_auto_out_a_bits_source),
    .auto_out_a_bits_address (_fragmenter_auto_out_a_bits_address),
    .auto_out_a_bits_mask    (_fragmenter_auto_out_a_bits_mask),
    .auto_out_a_bits_data    (_fragmenter_auto_out_a_bits_data),
    .auto_out_a_bits_corrupt (_fragmenter_auto_out_a_bits_corrupt),
    .auto_out_d_ready        (_fragmenter_auto_out_d_ready)
  );
  TLBuffer_19 buffer_1 (	// @[Buffer.scala:69:28]
    .clock                   (clock),
    .reset                   (reset),
    .auto_in_a_valid         (_tsi2tl_auto_out_a_valid),	// @[TSIHarness.scala:90:26]
    .auto_in_a_bits_opcode   (_tsi2tl_auto_out_a_bits_opcode),	// @[TSIHarness.scala:90:26]
    .auto_in_a_bits_size     (_tsi2tl_auto_out_a_bits_size),	// @[TSIHarness.scala:90:26]
    .auto_in_a_bits_address  (_tsi2tl_auto_out_a_bits_address),	// @[TSIHarness.scala:90:26]
    .auto_in_a_bits_mask     (_tsi2tl_auto_out_a_bits_mask),	// @[TSIHarness.scala:90:26]
    .auto_in_a_bits_data     (_tsi2tl_auto_out_a_bits_data),	// @[TSIHarness.scala:90:26]
    .auto_in_d_ready         (_tsi2tl_auto_out_d_ready),	// @[TSIHarness.scala:90:26]
    .auto_out_a_ready        (_serdesser_auto_manager_in_a_ready),	// @[TSIHarness.scala:91:29]
    .auto_out_d_valid        (_serdesser_auto_manager_in_d_valid),	// @[TSIHarness.scala:91:29]
    .auto_out_d_bits_opcode  (_serdesser_auto_manager_in_d_bits_opcode),	// @[TSIHarness.scala:91:29]
    .auto_out_d_bits_param   (_serdesser_auto_manager_in_d_bits_param),	// @[TSIHarness.scala:91:29]
    .auto_out_d_bits_size    (_serdesser_auto_manager_in_d_bits_size),	// @[TSIHarness.scala:91:29]
    .auto_out_d_bits_source  (_serdesser_auto_manager_in_d_bits_source),	// @[TSIHarness.scala:91:29]
    .auto_out_d_bits_sink    (_serdesser_auto_manager_in_d_bits_sink),	// @[TSIHarness.scala:91:29]
    .auto_out_d_bits_denied  (_serdesser_auto_manager_in_d_bits_denied),	// @[TSIHarness.scala:91:29]
    .auto_out_d_bits_data    (_serdesser_auto_manager_in_d_bits_data),	// @[TSIHarness.scala:91:29]
    .auto_out_d_bits_corrupt (_serdesser_auto_manager_in_d_bits_corrupt),	// @[TSIHarness.scala:91:29]
    .auto_in_a_ready         (_buffer_1_auto_in_a_ready),
    .auto_in_d_valid         (_buffer_1_auto_in_d_valid),
    .auto_in_d_bits_data     (_buffer_1_auto_in_d_bits_data),
    .auto_out_a_valid        (_buffer_1_auto_out_a_valid),
    .auto_out_a_bits_opcode  (_buffer_1_auto_out_a_bits_opcode),
    .auto_out_a_bits_param   (_buffer_1_auto_out_a_bits_param),
    .auto_out_a_bits_size    (_buffer_1_auto_out_a_bits_size),
    .auto_out_a_bits_source  (_buffer_1_auto_out_a_bits_source),
    .auto_out_a_bits_address (_buffer_1_auto_out_a_bits_address),
    .auto_out_a_bits_mask    (_buffer_1_auto_out_a_bits_mask),
    .auto_out_a_bits_data    (_buffer_1_auto_out_a_bits_data),
    .auto_out_a_bits_corrupt (_buffer_1_auto_out_a_bits_corrupt),
    .auto_out_d_ready        (_buffer_1_auto_out_d_ready)
  );
endmodule


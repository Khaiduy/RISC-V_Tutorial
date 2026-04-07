//==================== New version ================================
`timescale 1ns / 1ps

module TRNG_DF_DRBG(
    input               iClk,
    input               iRst,
    input               iEn,
    input               iWrDone,
    input       [7:0]   iAddr,
    input       [63:0]  iData,
    input               iStart,
    input       [1:0]   iMode,
    output reg  [63:0]  oData,
    output reg          oDone
    );

localparam
    s_idle	       = 5'b0,
	s_write        = 5'b1,
	s_trng         = 5'd2,

	s_pre_bcc      = 5'd17,
	s_bcc          = 5'd3,
	s_wait_bcc     = 5'd4,

    s_pre_ecb      = 5'd5,
    s_xecb         = 5'd6,
    s_wait_xecb    = 5'd7,

	s_pre_update   = 5'd8,
	s_update       = 5'd9,
	s_wait_update  = 5'd10,

    s_ins          = 5'd11,
    s_wait_ins     = 5'd12,

    s_pre_gen      = 5'd13,
    s_gen          = 5'd14,
    s_wait_gen     = 5'd15,

    s_done         = 5'd16;

reg [4:0]  state;
wire [383:0] w_data_from_trng;

//----------------- TRNG ----------------------
reg r_start_trng;
wire w_trng_done;

TRNG TRNG_inst(
    .iClk(iClk),
    .iRst(iRst),
    .iStart(r_start_trng),
    .oRo(),
    .oRNS(w_data_from_trng),
    .oDone(w_trng_done)
);
//----------------------------------------------

//-------------- AES CORE ----------------------
reg          r_aesTrigger;
reg          r_aesDone;
reg          r_aesMode;
reg  [127:0] r_aesV;
reg  [255:0] r_aesKey;
reg  [127:0] r_aesMsg;
wire [127:0] w_aesCipher;
wire         w_aesFinish;

AES_256_CTR AES_Block_Enc(
		.iClk(iClk),
		.iRst(iRst),
		.iEnc(r_aesTrigger),
		.iDone(r_aesDone),
		.iMode(r_aesMode),
		.iCtr(r_aesV),
		.iKey(r_aesKey),
		.iMsg(r_aesMsg),
		.oCipher(w_aesCipher),
		.oFinish(w_aesFinish)
);
//----------------------------------------------
reg aesFinish_d;
always @(posedge iClk) begin
  if (iRst) begin
    aesFinish_d <= 1'b0;
  end else begin
    aesFinish_d <= w_aesFinish;
  end
end

wire aesFinish_rise = w_aesFinish & ~aesFinish_d;
//==============================================

reg [127:0] r_mem [0:4];
reg [127:0] r_temp;
//========== Reading data when r_done = 1 ============
always @(posedge iClk) begin
  if(iRst) begin
    oData <= 64'd0;
  end
  else begin
    if(oDone) begin
      case (iAddr)
        8'd0: oData <= r_mem[0][127:64];
        8'd1: oData <= r_mem[0][63:0];
        8'd2: oData <= r_mem[1][127:64];
        8'd3: oData <= r_mem[1][63:0];
        default:
              oData <= 64'd0;
      endcase
    end
  end
end
//-=============================================================


reg [2:0]   r_out_idx;
reg [2:0]   r_loop5;
reg [1:0]   r_iv_vec;
//------- Rising of iStart -------
reg start_d;
always @(posedge iClk) begin
  if (iRst) begin
    start_d <= 1'b0;
  end else begin
    start_d <= iStart;
  end
end
wire start_rise = iStart & ~start_d;
///================= MAIN FSM ===============================
always @(posedge iClk) begin
  if(iRst) begin
    state   <= s_idle;
    oDone   <= 1'b0;
    r_start_trng <= 1'b0;
    r_aesTrigger <= 1'b0;
    r_aesDone    <= 1'b0;
    r_aesMode    <= 1'b0;
    r_aesV       <= 128'd0;
    r_aesKey     <= 256'd0;
    r_aesMsg     <= 128'd0;
    r_mem[0]     <= 128'd0;
    r_mem[1]     <= 128'd0;
    r_mem[2]     <= 128'd0;
    r_mem[3]     <= 128'd0;
    r_mem[4]     <= 128'd0;
  end
  else begin
    r_aesTrigger <= 1'b0;
    r_aesDone    <= 1'b0;
    case(state)
      //------------ State IDLE ------------------------
      s_idle: begin
        r_out_idx     <= 3'd0;
        r_iv_vec      <= 2'd0;
        r_loop5       <= 3'd0;

        if(start_rise) begin
          oDone <= 1'b0;
          if(iMode == 2'd0 || iMode == 2'd2) begin  // 0: TRNG 2: TRNG + DRBG
            r_start_trng <= 1'b1;
            state <= s_trng;
          end
          else if(iMode == 2'd1) begin // CPU + DRBG
            state <= s_write;
          end
          else if(iMode == 2'd3) begin // next gen
            state <= s_pre_gen;
          end
        end
      end
      //------ Mode = 0, get data from TRNG ------------
      s_trng: begin
        r_start_trng <= 1'b0;
        if(w_trng_done) begin
          r_mem[0] <= w_data_from_trng[383:256];
          r_mem[1] <= w_data_from_trng[255:128];
          if(iMode == 2'd0)
            state   <= s_done;
          else
          if (iMode == 2'd2) begin
            state     <= s_pre_bcc;
          end
        end
      end
      //------ Mode = 1, write data from CPU ------------
      s_write: begin
        if (iEn && iAddr < 8'd6) begin
          case(iAddr)
            8'd0: r_mem[0][127:64] <= iData;
            8'd1: r_mem[0][63:0]   <= iData;
            8'd2: r_mem[1][127:64] <= iData;
            8'd3: r_mem[1][63:0]   <= iData;
            8'd4: r_mem[2][127:64] <= iData;
            8'd5: r_mem[2][63:0]   <= iData;

          endcase
        end
        if(iWrDone) begin
          state        <= s_pre_bcc;
        end
      end
      //---------------- prepare for bcc ---------------
      s_pre_bcc: begin
        r_aesMode <= 1'b0;
        r_aesKey  <= 256'h000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F;
        r_aesV    <= 128'd0;
        r_temp    <= r_mem[2];
        state     <= s_bcc;
      end

      //-------- Start aes -------------
      s_bcc: begin
         case(r_loop5)
            3'd0: r_aesMsg <= {30'b0, r_iv_vec, 96'b0};
            3'd1: r_aesMsg <= {32'h30, 32'h30, r_mem[0][127:64]} ^ w_aesCipher;
            3'd2: r_aesMsg <= {r_mem[0][63:0], r_mem[1][127:64]} ^ w_aesCipher;
            3'd3: r_aesMsg <= {r_mem[1][63:0], r_temp[127:64]} ^ w_aesCipher;
            3'd4: r_aesMsg <= {r_temp[63:0], 8'h80, 56'h0} ^ w_aesCipher;
        endcase
        r_aesTrigger <= 1'b1;
        r_aesDone    <= 1'b1;
        state        <= s_wait_bcc;
      end
      //-------- wait for done ----------
      s_wait_bcc: begin
        if(aesFinish_rise) begin
          if(r_out_idx < 3'd3) begin
            if(r_loop5 < 3'd4) begin
              r_mem[r_out_idx + 3'd2]   <= w_aesCipher;
              r_loop5                 <= r_loop5 + 3'd1;
              state                   <= s_bcc;
            end
            else begin
              r_mem[r_out_idx + 3'd2]   <= w_aesCipher;
              if(r_out_idx == 3'd2) begin
                state <= s_pre_ecb;
              end
              else begin
                r_loop5   <= 3'd0;
                r_iv_vec  <= r_iv_vec + 1'b1;
                r_out_idx <= r_out_idx + 1'b1;
                state     <= s_bcc;
              end
            end
           end
         else
           begin
             state <= s_pre_ecb;
           end
        end
      end
      //----------------- Prepare for X-ECB ------------------
      s_pre_ecb: begin
        r_aesMode    <= 1'b0;
        r_aesKey     <= {r_mem[2], r_mem[3]};
        r_aesV       <= 128'd0;
        r_out_idx    <= 3'd2;
        state        <= s_xecb;
      end
      //--------------- Execute ecb ---------------------------
      s_xecb: begin
        r_aesMsg     <= r_mem[r_out_idx + 3'd2];
        r_aesTrigger <= 1'b1;
        r_aesDone    <= 1'b1;
        r_out_idx    <= (r_out_idx == 3'd2) ? 3'd0 : r_out_idx + 3'd1;
        state        <= s_wait_xecb;
      end
      //------------- wait ecb-----------------------
      s_wait_xecb: begin
        if(aesFinish_rise) begin
          r_mem[r_out_idx + 3'd2]   <= w_aesCipher;
          if(r_out_idx == 3'd2) begin
            r_aesMode    <= 1'b0;
            r_aesKey     <= 256'h0;
            r_aesV       <= 128'd0;
            r_out_idx    <= 3'd0;
            state        <= s_ins;
          end
          else
            state <= s_xecb;
        end
      end

      //--------------- Execute ins ---------------------
      s_ins: begin
        r_aesMsg     <= r_mem[r_out_idx + 3'd2];
        r_aesTrigger <= 1'b1;
        r_aesDone    <= 1'b1;
        state        <= s_wait_ins;
      end
      //------------ wait for the cipher -----------------
      s_wait_ins: begin
        if(aesFinish_rise) begin
          r_mem[r_out_idx + 3'd2]   <= w_aesCipher;
          if(r_out_idx == 3'd2) begin
            state <= s_pre_update; //here
          end
          else begin
            r_out_idx <= r_out_idx + 3'd1;
            state     <= s_ins;
          end
        end
      end
      //---------- prepare updating ----------------
      s_pre_update: begin
        r_aesMode    <= 1'b1;
        r_aesKey     <= {r_mem[2], r_mem[3]};
        r_aesV       <= r_mem[4];
        r_out_idx    <= 3'd0;
        r_aesMsg     <= 128'd0;
        state        <= s_update;
      end
      //------------ execute update -----------------
      s_update: begin
        r_aesTrigger <= 1'b1;
        r_aesDone    <= (r_out_idx == 3'd0);
        state        <= s_wait_update;
      end
      //------------ wait for the aes finish ------------
      s_wait_update: begin
        if(aesFinish_rise) begin
          r_mem[r_out_idx + 3'd2]   <= w_aesCipher;
          if(r_out_idx == 3'd2) begin
            state <= s_pre_gen;
          end else begin
            r_out_idx <= r_out_idx + 3'd1;
            state <= s_update;
          end
        end
      end
      //-------- Gen preparing ----------------
      s_pre_gen: begin
        r_aesMode    <= 1'b1;
        r_aesKey     <= {r_mem[2], r_mem[3]};
        r_aesV       <= r_mem[4];
        r_out_idx    <= 3'd0;
        r_aesMsg     <= 128'd0;
        state        <= s_gen;
      end
      //--------- Generate random ------------
      s_gen: begin
        r_aesTrigger <= 1'b1;
        r_aesDone    <= (r_out_idx == 3'd0);
        state        <= s_wait_gen;
      end
      //---------- wait gen finish -------------
      s_wait_gen: begin
        if(aesFinish_rise) begin
          r_mem[r_out_idx]   <= w_aesCipher;
          if(r_out_idx == 3'd4) begin
            state <= s_done;
          end else begin
            r_out_idx <= r_out_idx + 3'd1;
            state <= s_gen;
          end
        end
      end
      //-------------------- State Done -----------------------
        s_done: begin
          oDone <= 1'b1;
          state <= s_idle;
        end
      //------------------- Default --------------------------
        default: state <= s_idle;
    endcase
  end
end
endmodule


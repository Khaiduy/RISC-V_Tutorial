`timescale 1ns / 1ps


module TRNG(
    input               iClk,
    input               iRst,
    input               iStart,
    output              oRo,
    output  reg [255:0] oRNS,
    output  reg         oDone
    );
    
localparam [3:0] 
    s_idle        = 4'd0,
    s_trngReset   = 4'd1,
    s_wait        = 4'd2,
    s_getData     = 4'd3,
    s_done        = 4'd9;
    

reg [3:0]  state;
reg [10:0] cnt_2048;
reg        r_reset_trng, r_en_trng; 
wire [63:0] w_random_out;
reg  [2:0]  word_cnt;

// ------------ TRNG instance -------------
TopTRNG TRNG_core(
    .iClk(iClk),
    .iRst(r_reset_trng),
    .iEn(r_en_trng),
    .oRng(w_random_out),
    .oRo(oRo)
);

always @(posedge iClk) begin
  if(iRst) begin
    oRNS  <= 384'd0;
    oDone <= 1'b0;
    state <= s_idle;
    cnt_2048 <= 11'd0;
    r_reset_trng <= 1'b0;
    r_en_trng <= 1'b0;
    word_cnt  <= 3'd0;
  end
  else begin
    case(state) 
//-----------------------------------    
      s_idle: begin
        if(iStart) begin
          oDone <= 1'b0;
          r_en_trng <= 1'b1;
          state <= s_trngReset;
        end
      end
//-----------------------------------
      s_trngReset: begin
        r_reset_trng <= 1'b1;
        state        <= s_wait;
      end
//-----------------------------------  
      s_wait: begin
        r_reset_trng <= 1'b0;
        if(cnt_2048 < 11'd2047) begin
          cnt_2048 <= cnt_2048 + 11'd1;
        end
        else begin
          cnt_2048 <= 11'd0;
          state    <= s_getData;
        end 
      end
s_getData: begin
  oRNS <= {oRNS[191:0], w_random_out}; // shift left
  if(word_cnt == 3'd3) begin
    state <= s_done;
    word_cnt <= 3'd0;
  end 
    else begin
      word_cnt <= word_cnt + 1'b1;
  end
end
//-------------------------------------------
      s_done: begin
        oDone    <= 1'b1;
        state    <= s_idle;
      end
//------------------------------------               
    endcase
  end
end    
endmodule

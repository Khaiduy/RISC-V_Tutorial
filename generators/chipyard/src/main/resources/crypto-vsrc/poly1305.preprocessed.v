`define WT_DCACHE
`define DISABLE_TRACER
`define SRAM_NO_INIT
`define VERILATOR
//======================================================================
//
// poly1305_final.v
// ----------------
// Implementation of the final processing.
//
// Copyright (c) 2020, Assured AB
// Joachim Strömbergson
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module poly1305_final(
                      input wire          clk,
                      input wire          reset_n,

                      input wire          start,
                      output wire         ready,

                      input wire [31 : 0] h0,
                      input wire [31 : 0] h1,
                      input wire [31 : 0] h2,
                      input wire [31 : 0] h3,
                      input wire [31 : 0] h4,

                      input wire [31 : 0] s0,
                      input wire [31 : 0] s1,
                      input wire [31 : 0] s2,
                      input wire [31 : 0] s3,

                      output wire [31 : 0] hres0,
                      output wire [31 : 0] hres1,
                      output wire [31 : 0] hres2,
                      output wire [31 : 0] hres3
                      );



  //----------------------------------------------------------------
  // Parameters and symbolic values.
  //----------------------------------------------------------------
  localparam PIPE_CYCLES    = 4'h6;

  localparam CTRL_IDLE      = 2'h0;
  localparam CTRL_PIPE_WAIT = 2'h1;


  //----------------------------------------------------------------
  // Registers.
  //----------------------------------------------------------------
  reg [63 : 0] u0_reg;
  reg [63 : 0] u0_new;
  reg [63 : 0] u1_reg;
  reg [63 : 0] u1_new;
  reg [63 : 0] u2_reg;
  reg [63 : 0] u2_new;
  reg [63 : 0] u3_reg;
  reg [63 : 0] u3_new;
  reg [63 : 0] u4_reg;
  reg [63 : 0] u4_new;

  reg [63 : 0] uu0_reg;
  reg [63 : 0] uu0_new;
  reg [63 : 0] uu1_reg;
  reg [63 : 0] uu1_new;
  reg [63 : 0] uu2_reg;
  reg [63 : 0] uu2_new;
  reg [63 : 0] uu3_reg;
  reg [63 : 0] uu3_new;

  reg [3 : 0]  cycle_ctr_reg;
  reg [3 : 0]  cycle_ctr_new;
  reg          cycle_ctr_we;
  reg          cycle_ctr_rst;
  reg          cycle_ctr_inc;

  reg          ready_reg;
  reg          ready_new;
  reg          ready_we;

  reg [1 : 0]  final_ctrl_reg;
  reg [1 : 0]  final_ctrl_new;
  reg          final_ctrl_we;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign ready = ready_reg;

  assign hres0 = uu0_reg[31 : 0];
  assign hres1 = uu1_reg[31 : 0];
  assign hres2 = uu2_reg[31 : 0];
  assign hres3 = uu3_reg[31 : 0];


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset.
  //----------------------------------------------------------------
   always @ (posedge clk)
     begin : reg_update
       if (!reset_n)
         begin
           u0_reg        <= 64'h0;
           u1_reg        <= 64'h0;
           u2_reg        <= 64'h0;
           u3_reg        <= 64'h0;
           u4_reg        <= 64'h0;
           uu0_reg       <= 64'h0;
           uu1_reg       <= 64'h0;
           uu2_reg       <= 64'h0;
           uu3_reg       <= 64'h0;
          cycle_ctr_reg  <= 4'h0;
          ready_reg      <= 1'h1;
          final_ctrl_reg <= CTRL_IDLE;
         end
       else
         begin
           u0_reg  <= u0_new;
           u1_reg  <= u1_new;
           u2_reg  <= u2_new;
           u3_reg  <= u3_new;
           u4_reg  <= u4_new;

           uu0_reg <= uu0_new;
           uu1_reg <= uu1_new;
           uu2_reg <= uu2_new;
           uu3_reg <= uu3_new;

           if (cycle_ctr_we)
             cycle_ctr_reg <= cycle_ctr_new;

           if (ready_we)
             ready_reg <= ready_new;

           if (final_ctrl_we)
             final_ctrl_reg <= final_ctrl_new;
         end
     end // reg_update


   //----------------------------------------------------------------
   // final_logic
   //----------------------------------------------------------------
   always @*
     begin : final_logic
       u0_new = 64'h5                    + {32'h0, h0}; // <= 1_00000004
       u1_new = {32'h0, u0_reg[63 : 32]} + {32'h0, h1}; // <= 1_00000000
       u2_new = {32'h0, u1_reg[63 : 32]} + {32'h0, h2}; // <= 1_00000000
       u3_new = {32'h0, u2_reg[63 : 32]} + {32'h0, h3}; // <= 1_00000000
       u4_new = {32'h0, u3_reg[63 : 32]} + {32'h0, h4}; // <=          5

       uu0_new = (u4_reg[63 : 2] * 5)      + {32'h0, h0} + {32'h0, s0}; // <= 2_00000003
       uu1_new = {32'h0, uu0_reg[63 : 32]} + {32'h0, h1} + {32'h0, s1}; // <= 2_00000000
       uu2_new = {32'h0, uu1_reg[63 : 32]} + {32'h0, h2} + {32'h0, s2}; // <= 2_00000000
       uu3_new = {32'h0, uu2_reg[63 : 32]} + {32'h0, h3} + {32'h0, s3}; // <= 2_00000000
     end


  //----------------------------------------------------------------
  // cycle_ctr
  //----------------------------------------------------------------
  always @*
    begin : cycle_ctr
      cycle_ctr_new = 4'h0;
      cycle_ctr_we  = 1'h0;

      if (cycle_ctr_rst)
        begin
          cycle_ctr_new = 4'h0;
          cycle_ctr_we  = 1'h1;
        end
      else if (cycle_ctr_inc)
        begin
          cycle_ctr_new = cycle_ctr_reg + 1'h1;
          cycle_ctr_we  = 1'h1;
        end
    end


  //----------------------------------------------------------------
  // final_ctrl
  //----------------------------------------------------------------
  always @*
    begin : final_ctrl
      ready_new      = 1'h1;
      ready_we       = 1'h0;
      cycle_ctr_rst  = 1'h0;
      cycle_ctr_inc  = 1'h0;
      final_ctrl_new = CTRL_IDLE;
      final_ctrl_we  = 1'h0;

      case (final_ctrl_reg)
        CTRL_IDLE:
          begin
            if (start)
              begin
                ready_new      = 1'h0;
                ready_we       = 1'h1;
                cycle_ctr_rst  = 1'h1;
                final_ctrl_new = CTRL_PIPE_WAIT;
                final_ctrl_we  = 1'h1;
              end
          end

        CTRL_PIPE_WAIT:
          begin
            cycle_ctr_inc = 1'h1;
            if (cycle_ctr_reg == PIPE_CYCLES)
              begin
                ready_new      = 1'h1;
                ready_we       = 1'h1;
                final_ctrl_new = CTRL_IDLE;
                final_ctrl_we  = 1'h1;
              end
          end

        default:
          begin
          end
      endcase // case (final_ctrl_reg)
    end // block: final_ctrl

endmodule // poly1305_final

//======================================================================
// EOF poly1305_final.v
//======================================================================
//======================================================================
//
// poly1305_mulacc.v
// -----------------
// Multiply-accumulate with five sets of operands.
//
//
// Copyright (c) 2020, Assured AB
// Joachim Strömbergson
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module poly1305_mulacc(
                       input wire           clk,
                       input wire           reset_n,

                       input wire           start,
                       output wire          ready,
                       
                       input wire [63 : 0]  opb0,
                       input wire [63 : 0]  opb1,
                       input wire [63 : 0]  opb2,
                       input wire [63 : 0]  opb3,
                       input wire [63 : 0]  opb4,

                       input wire [31 : 0]  opa0_0,
                       input wire [31 : 0]  opa0_1,
                       input wire [31 : 0]  opa0_2,
                       input wire [31 : 0]  opa0_3,

                       input wire [31 : 0]  opa1_0,
                       input wire [31 : 0]  opa1_1,
                       input wire [31 : 0]  opa1_2,
                       input wire [31 : 0]  opa1_3,
                      
                       input wire [31 : 0]  opa2_0,
                       input wire [31 : 0]  opa2_1,
                       input wire [31 : 0]  opa2_2,
                       input wire [31 : 0]  opa2_3,

                       input wire [31 : 0]  opa3_0,
                       input wire [31 : 0]  opa3_1,
                       input wire [31 : 0]  opa3_2,
                       input wire [31 : 0]  opa3_3,

                       input wire [31 : 0]  opa4_0,
                       input wire [31 : 0]  opa4_1,
                       input wire [31 : 0]  opa4_2,
                       input wire [31 : 0]  opa4_3,

                       output wire [63 : 0] sum_0,
                       output wire [63 : 0] sum_1,
                       output wire [63 : 0] sum_2,
                       output wire [63 : 0] sum_3                                                                     
                      );


  //----------------------------------------------------------------
  // Parameters and symbolic values.
  //----------------------------------------------------------------
  localparam CTRL_IDLE     = 5'h0;
  localparam CTRL_OP1      = 5'h1;
  localparam CTRL_OP2      = 5'h2;
  localparam CTRL_OP3      = 5'h3;
  localparam CTRL_OP4      = 5'h4;
  localparam CTRL_SUM_0    = 5'h5;
  localparam CTRL_OP5      = 5'h6;
  localparam CTRL_OP6      = 5'h7;
  localparam CTRL_OP7      = 5'h8;
  localparam CTRL_OP8      = 5'h9;
  localparam CTRL_OP9      = 5'ha;
  localparam CTRL_SUM_1    = 5'hb;
  localparam CTRL_OP10     = 5'hc;
  localparam CTRL_OP11     = 5'hd;
  localparam CTRL_OP12     = 5'he;
  localparam CTRL_OP13     = 5'hf;
  localparam CTRL_OP14     = 5'h10;  
  localparam CTRL_SUM_2    = 5'h11;
  localparam CTRL_OP15     = 5'h12;
  localparam CTRL_OP16     = 5'h13;
  localparam CTRL_OP17     = 5'h14;  
  localparam CTRL_OP18     = 5'h15;  
  localparam CTRL_OP19     = 5'h16;   
  localparam CTRL_SUM_3    = 5'h17;

  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [63 : 0] mul_reg;
  reg [63 : 0] mul_new;
  reg          mul_we;

  reg [63 : 0] sum_0_reg;
  reg [63 : 0] sum_1_reg;
  reg [63 : 0] sum_2_reg;
  reg [63 : 0] sum_3_reg;
  reg [63 : 0] sum_new;
  reg          sum_we;

  reg          ready_reg;
  reg          ready_new;
  reg          ready_we;

  reg [4 : 0]  mulacc_ctrl_reg;
  reg [4 : 0]  mulacc_ctrl_new;
  reg          mulacc_ctrl_we;


  //----------------------------------------------------------------
  // wires
  //----------------------------------------------------------------
  reg [4 : 0]  mulop_select;
  reg          update_mul;
  reg          clear_sum;
  reg          update_sum;

  //----------------------------------------------------------------
  // counter control
  //----------------------------------------------------------------

  reg [1 : 0]  control_operator;

  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign sum_0   = sum_0_reg;
  assign sum_1   = sum_1_reg;
  assign sum_2   = sum_2_reg;
  assign sum_3   = sum_3_reg;
  assign ready = ready_reg;


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin : reg_update
      if (!reset_n)
        begin
          mul_reg         <= 64'h0;
          sum_0_reg       <= 64'h0;
          sum_1_reg       <= 64'h0;
          sum_2_reg       <= 64'h0;
          sum_3_reg       <= 64'h0;
          ready_reg       <= 1'h0;
          mulacc_ctrl_reg <= CTRL_IDLE;
        end
      else
        begin
          if (mul_we)
            mul_reg <= mul_new;

          if (sum_we)
          
            case (control_operator)
                0:
                begin
                    sum_0_reg <= sum_new;
                end

                1:
                begin
                    sum_1_reg <= sum_new;
                end

                2:
                begin
                    sum_2_reg <= sum_new;
                end

                3:
                begin
                    sum_3_reg <= sum_new;
                end
        
                default:
                begin
                end
            endcase // case (control_operator) 
            

          if (ready_we)   
            ready_reg <= ready_new;

          if (mulacc_ctrl_we)
            mulacc_ctrl_reg <= mulacc_ctrl_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // mulacc_logic
  //----------------------------------------------------------------
  always @*
    begin : mulacc_logic
      reg [31 : 0] mul_opa;
      reg [63 : 0] mul_opb;

      mul_opa = 32'h0;
      mul_opb = 64'h0;
      mul_new = 64'h0;
      mul_we  = 1'h0;
      sum_new = 64'h0;
      sum_we  = 1'h0;


      case (mulop_select)
        0:
          begin
            mul_opa = opa0_0;
            mul_opb = opb0;
          end

        1:
          begin
            mul_opa = opa1_0;
            mul_opb = opb1;
          end

        2:
          begin
            mul_opa = opa2_0;
            mul_opb = opb2;
          end

        3:
          begin
            mul_opa = opa3_0;
            mul_opb = opb3;
          end

        4:
          begin
            mul_opa = opa4_0;
            mul_opb = opb4;
          end

        5:
          begin
            mul_opa = opa0_1;
            mul_opb = opb0;
          end
 
         6:
          begin
            mul_opa = opa1_1;
            mul_opb = opb1;
          end
          
         7:
          begin
            mul_opa = opa2_1;
            mul_opb = opb2;
          end

        8:
          begin
            mul_opa = opa3_1;
            mul_opb = opb3;
          end
          
        9:
          begin
            mul_opa = opa4_1;
            mul_opb = opb4;
          end          
 
         10:
          begin
            mul_opa = opa0_2;
            mul_opb = opb0;
          end
 
         11:
          begin
            mul_opa = opa1_2;
            mul_opb = opb1;
          end
 
         12:
          begin
            mul_opa = opa2_2;
            mul_opb = opb2;
          end
 
         13:
          begin
            mul_opa = opa3_2;
            mul_opb = opb3;
          end

        14:
          begin
            mul_opa = opa4_2;
            mul_opb = opb4;
          end

        15:
          begin
            mul_opa = opa0_3;
            mul_opb = opb0;
          end

        16:
          begin
            mul_opa = opa1_3;
            mul_opb = opb1;
          end

        17:
          begin
            mul_opa = opa2_3;
            mul_opb = opb2;
          end

        18:
          begin
            mul_opa = opa3_3;
            mul_opb = opb3;
          end

        19:
          begin
            mul_opa = opa4_3;
            mul_opb = opb4;
          end


        default:
          begin
          end
      endcase // case (mulop_select)


      if (update_mul)
        begin
          mul_new = mul_opa * mul_opb;
          mul_we  = 1'h1;
        end

      if (clear_sum)
        begin
          sum_new = 64'h0;
          sum_we  = 1;
        end

      if (update_sum)
        begin
        
        case (control_operator)
            0:
            begin
                sum_new = sum_0_reg + mul_reg;
                sum_we  = 1;
            end

          1:
             begin
               sum_new = sum_1_reg + mul_reg;
               sum_we  = 1;
             end

           2:
             begin
                sum_new = sum_2_reg + mul_reg;
                sum_we  = 1;
              end

           3:
             begin
               sum_new = sum_3_reg + mul_reg;
               sum_we  = 1;
          end
        
            default:
             begin
             end
         endcase // case (control_operator) 

        end
    end


  //----------------------------------------------------------------
  // mulacc_ctrl
  //----------------------------------------------------------------
  always @*
    begin : mulacc_ctrl
      mulop_select    = 5'h0;
      update_mul      = 1'h0;
      clear_sum       = 1'h0;
      update_sum      = 1'h0;
      ready_new       = 1'h0;
      ready_we        = 1'h0;
      mulacc_ctrl_new = CTRL_IDLE;
      mulacc_ctrl_we  = 1'h0;
      control_operator= 2'h0;

      case (mulacc_ctrl_reg)
        CTRL_IDLE:
          begin
            if (start)
              begin
                mulop_select    = 5'h0;
                ready_new       = 1'h0;
                ready_we        = 1'h1;
                update_mul      = 1'h1;
                clear_sum       = 1'h1;
                mulacc_ctrl_new = CTRL_OP1;
                mulacc_ctrl_we  = 1'h1;
                control_operator= 2'h0;
              end
          end

        CTRL_OP1:
          begin
            mulop_select    = 5'h1;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP2;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h0;
          end

        CTRL_OP2:
          begin
            mulop_select    = 5'h2;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP3;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h0;
          end

        CTRL_OP3:
          begin
            mulop_select    = 5'h3;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP4;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h0;
          end

        CTRL_OP4:
          begin
            mulop_select    = 5'h4;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_SUM_0;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h0;
          end

        CTRL_SUM_0:
          begin
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP5;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h0;            
          end
          
        CTRL_OP5:
          begin
            mulop_select    = 5'h5;
            update_mul      = 1'h1;
            update_sum      = 1'h0;           
            clear_sum       = 1'h1;
            mulacc_ctrl_new = CTRL_OP6;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h1;
          end

        CTRL_OP6:
          begin
            mulop_select    = 5'h6;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP7;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h1;
          end

        CTRL_OP7:
          begin
            mulop_select    = 5'h7;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP8;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h1;
          end
          
         CTRL_OP8:
          begin
            mulop_select    = 5'h8;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP9;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h1;
          end
          
        CTRL_OP9:
          begin
            mulop_select    = 5'h9;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_SUM_1;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h1;
          end

        CTRL_SUM_1:
          begin
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP10;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h1;            
          end

        CTRL_OP10:
          begin
            mulop_select    = 5'ha;
            update_mul      = 1'h1;
            update_sum      = 1'h0;           
            clear_sum       = 1'h1;
            mulacc_ctrl_new = CTRL_OP11;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h2;
          end

        CTRL_OP11:
          begin
            mulop_select    = 5'hb;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP12;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h2;
          end

        CTRL_OP12:
          begin
            mulop_select    = 5'hc;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP13;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h2;
          end
          
         CTRL_OP13:
          begin
            mulop_select    = 5'hd;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP14;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h2;
          end
          
        CTRL_OP14:
          begin
            mulop_select    = 5'he;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_SUM_2;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h2;
          end

        CTRL_SUM_2:
          begin
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP15;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h2;            
          end
          
        CTRL_OP15:
          begin
            mulop_select    = 5'hf;
            update_mul      = 1'h1;
            update_sum      = 1'h0;           
            clear_sum       = 1'h1;
            mulacc_ctrl_new = CTRL_OP16;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h3;
          end

        CTRL_OP16:
          begin
            mulop_select    = 5'h10;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP17;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h3;
          end

        CTRL_OP17:
          begin
            mulop_select    = 5'h11;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP18;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h3;
          end
          
         CTRL_OP18:
          begin
            mulop_select    = 5'h12;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_OP19;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h3;
          end
          
        CTRL_OP19:
          begin
            mulop_select    = 5'h13;
            update_mul      = 1'h1;
            update_sum      = 1'h1;
            mulacc_ctrl_new = CTRL_SUM_3;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h3;
          end  

        CTRL_SUM_3:
          begin
            update_sum      = 1'h1;
            ready_new       = 1'h1;
            ready_we        = 1'h1;
            mulacc_ctrl_new = CTRL_IDLE;
            mulacc_ctrl_we  = 1'h1;
            control_operator= 2'h3;            
          end

        default:
          begin
          end
      endcase // case (mulacc_ctrl_reg)
    end

endmodule // poly1305_mulacc

//======================================================================
// EOF poly1305_mulacc.v
//======================================================================
//======================================================================
//
// poly1305_pblock.v
// -----------------
// Implementation of the polynomial processing of a block.
//
// Copyright (c) 2017, Assured AB
// Joachim Strömbergson
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module poly1305_pblock(
                       input wire          clk,
                       input wire          reset_n,

                       input wire          start,
                       output wire         ready,

                       input wire [31 : 0] h0,
                       input wire [31 : 0] h1,
                       input wire [31 : 0] h2,
                       input wire [31 : 0] h3,
                       input wire [31 : 0] h4,

                       input wire [31 : 0] c0,
                       input wire [31 : 0] c1,
                       input wire [31 : 0] c2,
                       input wire [31 : 0] c3,
                       input wire [31 : 0] c4,

                       input wire [31 : 0] r0,
                       input wire [31 : 0] r1,
                       input wire [31 : 0] r2,
                       input wire [31 : 0] r3,

                       output wire [31 : 0] h0_new,
                       output wire [31 : 0] h1_new,
                       output wire [31 : 0] h2_new,
                       output wire [31 : 0] h3_new,
                       output wire [31 : 0] h4_new
                      );


  //----------------------------------------------------------------
  // Parameters and symbolic values.
  //----------------------------------------------------------------
  localparam PRE_CYCLES  = 4'h1;
  localparam POST_CYCLES = 4'h2;

  localparam CTRL_IDLE      = 4'h0;
  localparam CTRL_PRE_WAIT  = 4'h1;
  localparam CTRL_MULACC    = 4'h2;
  localparam CTRL_POST_WAIT = 4'h3;


  //----------------------------------------------------------------
  // Registers (Variables)
  //----------------------------------------------------------------
  reg [63 : 0] u0_reg;
  reg [63 : 0] u0_new;
  reg [63 : 0] u1_reg;
  reg [63 : 0] u1_new;
  reg [63 : 0] u2_reg;
  reg [63 : 0] u2_new;
  reg [63 : 0] u3_reg;
  reg [63 : 0] u3_new;
  reg [31 : 0] u4_reg;
  reg [31 : 0] u4_new;
  reg [63 : 0] u5_reg;
  reg [63 : 0] u5_new;

  reg [63 : 0] s0_reg;
  reg [63 : 0] s0_new;
  reg [63 : 0] s1_reg;
  reg [63 : 0] s1_new;
  reg [63 : 0] s2_reg;
  reg [63 : 0] s2_new;
  reg [63 : 0] s3_reg;
  reg [63 : 0] s3_new;
  reg [63 : 0] s4_reg;
  reg [63 : 0] s4_new;

  reg [31 : 0] rr0_reg;
  reg [31 : 0] rr0_new;
  reg [31 : 0] rr1_reg;
  reg [31 : 0] rr1_new;
  reg [31 : 0] rr2_reg;
  reg [31 : 0] rr2_new;
  reg [31 : 0] rr3_reg;
  reg [31 : 0] rr3_new;

  wire [63 : 0] x0_new;
  wire [63 : 0] x1_new;
  wire [63 : 0] x2_new;
  wire [63 : 0] x3_new;
  reg [63 : 0]  x4_reg;
  reg [63 : 0]  x4_new;

  reg [3 : 0]   cycle_ctr_reg;
  reg [3 : 0]   cycle_ctr_new;
  reg           cycle_ctr_we;
  reg           cycle_ctr_rst;
  reg           cycle_ctr_inc;

  reg           ready_reg;
  reg           ready_new;
  reg           ready_we;

  reg [3 : 0]   pblock_ctrl_reg;
  reg [3 : 0]   pblock_ctrl_new;
  reg           pblock_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg  mulacc_start;
  wire mulacc0_ready;
  //wire mulacc1_ready;
  //wire mulacc2_ready;
  //wire mulacc3_ready;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign ready   = ready_reg;

  assign h0_new  = u0_reg[31 : 0];
  assign h1_new  = u1_reg[31 : 0];
  assign h2_new  = u2_reg[31 : 0];
  assign h3_new  = u3_reg[31 : 0];
  assign h4_new  = u4_reg;


  //----------------------------------------------------------------
  // mulacc instances.
  //----------------------------------------------------------------
  poly1305_mulacc mulacc0(
                          .clk(clk),
                          .reset_n(reset_n),
                          .start(mulacc_start),
                          .ready(mulacc0_ready),
                          //r clam
                          .opa0_0(r0), 
                          .opa0_1(r1),
                          .opa0_2(r2),
                          .opa0_3(r3),
                          //s clam
                          .opb0(s0_reg),
                          .opb1(s1_reg),
                          .opb2(s2_reg),
                          .opb3(s3_reg),
                          .opb4(s4_reg),
                          //uno
                          .opa1_0(rr3_reg),
                          .opa1_1(r0),
                          .opa1_2(r1),
                          .opa1_3(r2),
                          //dos
                          .opa2_0(rr2_reg),
                          .opa2_1(rr3_reg),
                          .opa2_2(r0),
                          .opa2_3(r1),
                          //tres
                          .opa3_0(rr1_reg),
                          .opa3_1(rr2_reg),
                          .opa3_2(rr3_reg),
                          .opa3_3(r0),
                          //cuatro
                          .opa4_0(rr0_reg),
                          .opa4_1(rr1_reg),
                          .opa4_2(rr2_reg),
                          .opa4_3(rr3_reg),
                          //
                          .sum_0(x0_new),
                          .sum_1(x1_new),
                          .sum_2(x2_new),
                          .sum_3(x3_new)
                          );

 /* poly1305_mulacc mulacc1(
                          .clk(clk),
                          .reset_n(reset_n),
                          .start(mulacc_start),
                          .ready(mulacc1_ready),
                          .opa0(r1),
                          .opb0(s0_reg),
                          .opa1(r0),
                          .opb1(s1_reg),
                          .opa2(rr3_reg),
                          .opb2(s2_reg),
                          .opa3(rr2_reg),
                          .opb3(s3_reg),
                          .opa4(rr1_reg),
                          .opb4(s4_reg),
                          .sum(x1_new)
                          );

  poly1305_mulacc mulacc2(
                          .clk(clk),
                          .reset_n(reset_n),
                          .start(mulacc_start),
                          .ready(mulacc2_ready),
                          .opa0(r2),
                          .opb0(s0_reg),
                          .opa1(r1),
                          .opb1(s1_reg),
                          .opa2(r0),
                          .opb2(s2_reg),
                          .opa3(rr3_reg),
                          .opb3(s3_reg),
                          .opa4(rr2_reg),
                          .opb4(s4_reg),
                          .sum(x2_new)
                          );

  poly1305_mulacc mulacc3(
                          .clk(clk),
                          .reset_n(reset_n),
                          .start(mulacc_start),
                          .ready(mulacc3_ready),
                          .opa0(r3),
                          .opb0(s0_reg),
                          .opa1(r2),
                          .opb1(s1_reg),
                          .opa2(r1),
                          .opb2(s2_reg),
                          .opa3(r0),
                          .opb3(s3_reg),
                          .opa4(rr3_reg),
                          .opb4(s4_reg),
                          .sum(x3_new)
                          );

*/
  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin : reg_update
      if (!reset_n)
        begin
          s0_reg          <= 64'h0;
          s1_reg          <= 64'h0;
          s2_reg          <= 64'h0;
          s3_reg          <= 64'h0;
          s4_reg          <= 64'h0;
          rr0_reg         <= 32'h0;
          rr1_reg         <= 32'h0;
          rr2_reg         <= 32'h0;
          rr3_reg         <= 32'h0;
          x4_reg          <= 64'h0;
          u0_reg          <= 64'h0;
          u1_reg          <= 64'h0;
          u2_reg          <= 64'h0;
          u3_reg          <= 64'h0;
          u4_reg          <= 32'h0;
          u5_reg          <= 64'h0;
          cycle_ctr_reg   <= 4'h0;
          ready_reg       <= 1'h1;
          pblock_ctrl_reg <= CTRL_IDLE;
        end
      else
        begin
          s0_reg  <= s0_new;
          s1_reg  <= s1_new;
          s2_reg  <= s2_new;
          s3_reg  <= s3_new;
          s4_reg  <= s4_new;

          rr0_reg <= rr0_new;
          rr1_reg <= rr1_new;
          rr2_reg <= rr2_new;
          rr3_reg <= rr3_new;

          x4_reg  <= x4_new;

          u0_reg  <= u0_new;
          u1_reg  <= u1_new;
          u2_reg  <= u2_new;
          u3_reg  <= u3_new;
          u4_reg  <= u4_new;
          u5_reg  <= u5_new;

          if (cycle_ctr_we)
            cycle_ctr_reg <= cycle_ctr_new;

          if (ready_we)
            ready_reg <= ready_new;

          if (pblock_ctrl_we)
            pblock_ctrl_reg <= pblock_ctrl_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // pblock_logic
  //----------------------------------------------------------------
  always @*
    begin : pblock_logic
      // s = h + c, no carry propagation.
      s0_new = {32'h0, h0} + {32'h0, c0};
      s1_new = {32'h0, h1} + {32'h0, c1};
      s2_new = {32'h0, h2} + {32'h0, c2};
      s3_new = {32'h0, h3} + {32'h0, c3};
      s4_new = {32'h0, h4} + {32'h0, c4};


      // Multiply r.
      rr0_new = {2'h0, r0[31 : 2]} * 32'h5;
      rr1_new = {2'h0, r1[31 : 2]} + r1;
      rr2_new = {2'h0, r2[31 : 2]} + r2;
      rr3_new = {2'h0, r3[31 : 2]} + r3;


      // x0..x3 are calculated by the mulacc modules.
      // We don't need registers for x0..x3.
      x4_new = s4_reg * {32'h0, (r0 & 32'h3)};


      // partial reduction modulo 2^130 - 5
      u5_new = x4_reg + {32'h0, x3_new[63 : 32]};
      u0_new = ({2'h0, u5_reg[31 : 2]} * 5) + {32'h0, x0_new[31 : 0]};
      u1_new = {32'h0, u0_reg[63 : 32]} + {32'h0, x1_new[31 : 0]} + {32'h0, x0_new[63 : 32]};
      u2_new = {32'h0, u1_reg[63 : 32]} + {32'h0, x2_new[31 : 0]} + {32'h0, x1_new[63 : 32]};
      u3_new = {32'h0, u2_reg[63 : 32]} + {32'h0, x3_new[31 : 0]} + {32'h0, x2_new[63 : 32]};
      u4_new = u3_reg[63 : 32] + {30'h0, (u5_reg[1 : 0] & 2'h3)};
    end // pblock_logic


  //----------------------------------------------------------------
  // cycle_ctr
  //----------------------------------------------------------------
  always @*
    begin : cycle_ctr
      cycle_ctr_new = 4'h0;
      cycle_ctr_we  = 1'h0;

      if (cycle_ctr_rst)
        begin
          cycle_ctr_new = 4'h0;
          cycle_ctr_we  = 1'h1;
        end
      else if (cycle_ctr_inc)
        begin
          cycle_ctr_new = cycle_ctr_reg + 1'h1;
          cycle_ctr_we  = 1'h1;
        end
    end


  //----------------------------------------------------------------
  // pblock_ctrl
  //----------------------------------------------------------------
  always @*
    begin : pblock_ctrl
      ready_new       = 1'h1;
      ready_we        = 1'h0;
      mulacc_start    = 1'h0;
      cycle_ctr_rst   = 1'h0;
      cycle_ctr_inc   = 1'h0;
      pblock_ctrl_new = CTRL_IDLE;
      pblock_ctrl_we  = 1'h0;

      case (pblock_ctrl_reg)
        CTRL_IDLE:
          begin
            if (start)
              begin
                ready_new       = 1'h0;
                ready_we        = 1'h1;
                cycle_ctr_rst   = 1'h1;
                pblock_ctrl_new = CTRL_PRE_WAIT;
                pblock_ctrl_we  = 1'h1;
              end
          end

        CTRL_PRE_WAIT:
          begin
            cycle_ctr_inc = 1'h1;
            if (cycle_ctr_reg == PRE_CYCLES)
              begin
                mulacc_start    = 1'h1;
                pblock_ctrl_new = CTRL_MULACC;
                pblock_ctrl_we  = 1'h1;
              end
          end

        CTRL_MULACC:
          begin
            //if ((mulacc0_ready) || (mulacc1_ready) ||
            //    (mulacc2_ready) || (mulacc3_ready))
            if (mulacc0_ready)
              begin
                cycle_ctr_rst   = 1'h1;
                pblock_ctrl_new = CTRL_POST_WAIT;
                pblock_ctrl_we  = 1'h1;
              end
          end

        CTRL_POST_WAIT:
          begin
            cycle_ctr_inc = 1'h1;
            if (cycle_ctr_reg == POST_CYCLES)
              begin
                ready_new       = 1'h1;
                ready_we        = 1'h1;
                pblock_ctrl_new = CTRL_IDLE;
                pblock_ctrl_we  = 1'h1;
              end
          end

        default:
          begin
          end
      endcase // case (pblock_ctrl_reg)
    end

endmodule // poly1305_pblock

//======================================================================
// EOF poly1305_pblock.v
//======================================================================
//======================================================================
//
// poly1305_core.v
// ---------------
// Core functionality of the poly1305 mac.
//
// Copyright (c) 2017, Secworks Sweden AB
// Joachim Strömbergson
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module poly1305_core(
                     input wire            clk,
                     input wire            reset_n,

                     input wire            init,
                     input wire            next,
                     input wire            finish,

                     output wire           ready,

                     input wire [255 : 0]  key,

                     input wire [127 : 0]  block,
                     input wire [4 : 0]    blocklen,

                     output wire [127 : 0] mac
                    );


  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam CTRL_IDLE      = 3'h0;
  localparam CTRL_INIT      = 3'h1;
  localparam CTRL_NEXT      = 3'h2;
  localparam CTRL_NEXT_WAIT = 3'h3;
  localparam CTRL_FINAL     = 3'h4;
  localparam CTRL_READY     = 3'h7;


  //----------------------------------------------------------------
  // Internal functions.
  //----------------------------------------------------------------
  function [31 : 0] le(input [31 : 0] w);
    le = {w[7 : 0], w[15 : 8], w[23 : 16], w[31 : 24]};
  endfunction // le


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg  [31 : 0] h_reg [0 : 4];
  reg  [31 : 0] h_new [0 : 4];
  reg           h_we;

  reg [31 : 0]  c_reg [0 : 4];
  reg [31 : 0]  c_new [0 : 4];
  reg           c_we;

  reg [31 : 0]  r_reg [0 : 3];
  reg [31 : 0]  r_new [0 : 3];
  reg           r_we;

  reg [31 : 0]  s_reg [0 : 3];
  reg [31 : 0]  s_new [0 : 3];
  reg           s_we;

  reg [31 : 0]  mac_reg [0 : 3];
  reg [31 : 0]  mac_new [0 : 3];
  reg           mac_we;

  reg           ready_reg;
  reg           ready_new;
  reg           ready_we;

  reg [2 : 0]   poly1305_core_ctrl_reg;
  reg [2 : 0]   poly1305_core_ctrl_new;
  reg           poly1305_core_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg  pblock_start;
  wire pblock_ready;

  reg  final_start;
  wire final_ready;

  reg state_init;
  reg state_update;
  reg load_block;
  reg mac_update;

  wire [31 : 0] hres0;
  wire [31 : 0] hres1;
  wire [31 : 0] hres2;
  wire [31 : 0] hres3;

  wire [31 : 0] pblock_h_new [0 : 4];


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign mac[031 : 000] = mac_reg[0];
  assign mac[063 : 032] = mac_reg[1];
  assign mac[095 : 064] = mac_reg[2];
  assign mac[127 : 096] = mac_reg[3];

  assign ready = ready_reg;


  //----------------------------------------------------------------
  // Module instantiations.
  //----------------------------------------------------------------
  poly1305_pblock pblock_inst(
                              .clk(clk),
                              .reset_n(reset_n),

                              .start(pblock_start),
                              .ready(pblock_ready),

                              .h0(h_reg[0]),
                              .h1(h_reg[1]),
                              .h2(h_reg[2]),
                              .h3(h_reg[3]),
                              .h4(h_reg[4]),

                              .c0(c_reg[0]),
                              .c1(c_reg[1]),
                              .c2(c_reg[2]),
                              .c3(c_reg[3]),
                              .c4(c_reg[4]),

                              .r0(r_reg[0]),
                              .r1(r_reg[1]),
                              .r2(r_reg[2]),
                              .r3(r_reg[3]),

                              .h0_new(pblock_h_new[0]),
                              .h1_new(pblock_h_new[1]),
                              .h2_new(pblock_h_new[2]),
                              .h3_new(pblock_h_new[3]),
                              .h4_new(pblock_h_new[4])
                             );

  poly1305_final final_inst(
                            .clk(clk),
                            .reset_n(reset_n),

                            .start(final_start),
                            .ready(final_ready),

                            .h0(h_reg[0]),
                            .h1(h_reg[1]),
                            .h2(h_reg[2]),
                            .h3(h_reg[3]),
                            .h4(h_reg[4]),

                            .s0(s_reg[0]),
                            .s1(s_reg[1]),
                            .s2(s_reg[2]),
                            .s3(s_reg[3]),

                            .hres0(hres0),
                            .hres1(hres1),
                            .hres2(hres2),
                            .hres3(hres3)
                           );


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin : reg_update
      integer i;
      if (!reset_n)
        begin
          for (i = 0 ; i < 5 ; i = i + 1)
            begin
              h_reg[i] <= 32'h0;
              c_reg[i] <= 32'h0;
            end

          for (i = 0 ; i < 4 ; i = i + 1)
            begin
              r_reg[i]   <= 32'h0;
              s_reg[i]   <= 32'h0;
              mac_reg[i] <= 32'h0;
            end

          ready_reg              <= 1'h1;
          poly1305_core_ctrl_reg <= CTRL_IDLE;
        end
      else
        begin
          if (ready_we)
            ready_reg <= ready_new;

          if (h_we)
            begin
              for (i = 0 ; i < 5 ; i = i + 1)
                h_reg[i] <= h_new[i];
            end

          if (c_we)
            begin
              for (i = 0 ; i < 5 ; i = i + 1)
                c_reg[i] <= c_new[i];
            end

          if (r_we)
            begin
              for (i = 0 ; i < 4 ; i = i + 1)
                r_reg[i] <= r_new[i];
            end

          if (s_we)
            begin
              for (i = 0 ; i < 4 ; i = i + 1)
                s_reg[i] <= s_new[i];
            end

          if (mac_we)
            begin
              for (i = 0 ; i < 4 ; i = i + 1)
                mac_reg[i] <= mac_new[i];
            end

          if (poly1305_core_ctrl_we)
            poly1305_core_ctrl_reg <= poly1305_core_ctrl_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // poly1305_core_logic
  //----------------------------------------------------------------
  always @*
    begin : poly1305_core_logic
      integer i;
      reg [31 : 0] b0;
      reg [31 : 0] b1;
      reg [31 : 0] b2;
      reg [31 : 0] b3;

      for (i = 0 ; i < 5 ; i = i + 1)
        h_new[i] = 32'h0;
      h_we = 1'h0;

      for (i = 0 ; i < 5 ; i = i + 1)
        c_new[i] = 32'h0;
      c_we = 1'h0;

      for (i = 0 ; i < 4 ; i = i + 1)
        r_new[i] = 32'h0;
      r_we = 1'h0;

      for (i = 0 ; i < 4 ; i = i + 1)
        s_new[i] = 32'h0;
      s_we = 1'h0;

      for (i = 0 ; i < 4 ; i = i + 1)
        mac_new[i] = 32'h0;
      mac_we = 1'h0;

      b0 = le(block[031 : 000]);
      b1 = le(block[063 : 032]);
      b2 = le(block[095 : 064]);
      b3 = le(block[127 : 096]);

      if (state_init)
        begin
          c_we     = 1'h1;
          h_we     = 1'h1;

          // Clamping of the key when assigning r.
          r_new[0] = le(key[255 : 224]) & 32'h0fffffff;
          r_new[1] = le(key[223 : 192]) & 32'h0ffffffc;
          r_new[2] = le(key[191 : 160]) & 32'h0ffffffc;
          r_new[3] = le(key[159 : 128]) & 32'h0ffffffc;
          r_we     = 1'h1;

          s_new[0] = le(key[127 : 096]);
          s_new[1] = le(key[095 : 064]);
          s_new[2] = le(key[063 : 032]);
          s_new[3] = le(key[031 : 000]);
          s_we     = 1'h1;
        end

      // Note that we only check bits 0..3 in blocklen.
      // This means that a blocklen of 0 and 16 are
      // handled the same way.
      if (load_block)
        begin
          if (blocklen[3 : 0] > 0)
            begin
              // Handling of partial (final) blocks.
              case (blocklen[3 : 0])
                0: begin
                  c_new[0] = 32'h1;
                end

                1: begin
                  c_new[0] = {24'h1, b3[7 : 0]};
                end

                2: begin
                  c_new[0] = {16'h1, b3[15 : 0]};
                end

                3: begin
                  c_new[0] = {8'h1, b3[23 : 0]};
                end

                4: begin
                  c_new[0] = b3;
                  c_new[1] = 32'h1;
                end

                5: begin
                  c_new[0] = b3;
                  c_new[1] = {24'h1, b2[7 : 0]};
                end

                6: begin
                  c_new[0] = b3;
                  c_new[1] = {16'h1, b2[15 : 0]};
                end

                7: begin
                  c_new[0] = b3;
                  c_new[1] = {8'h1, b2[23 : 0]};
                end

                8: begin
                  c_new[0] = b3;
                  c_new[1] = b2;
                  c_new[2] = 32'h1;
                end

                9: begin
                  c_new[0] = b3;
                  c_new[1] = b2;
                  c_new[2] = {24'h1, b1[7 : 0]};
                end

                10: begin
                  c_new[0] = b3;
                  c_new[1] = b2;
                  c_new[2] = {16'h1, b1[15 : 0]};
                end

                11: begin
                  c_new[0] = b3;
                  c_new[1] = b2;
                  c_new[2] = {8'h1, b1[23 : 0]};
                end

                12: begin
                  c_new[0] = b3;
                  c_new[1] = b2;
                  c_new[2] = b1;
                  c_new[3] = 32'h1;
                end

                13: begin
                  c_new[0] = b3;
                  c_new[1] = b2;
                  c_new[2] = b1;
                  c_new[3] = {24'h1, b0[7 : 0]};
                end

                14: begin
                  c_new[0] = b3;
                  c_new[1] = b2;
                  c_new[2] = b1;
                  c_new[3] = {16'h1, b0[15 : 0]};
                end

                15: begin
                  c_new[0] = b3;
                  c_new[1] = b2;
                  c_new[2] = b1;
                  c_new[3] = {8'h1, b0[23 : 0]};
                end
              endcase // case (blocklen[3 : 0])
              c_new[4] = 32'h0;
              c_we     = 1'h1;
            end
          else
            begin
              // Handling of full blocks.
              c_new[0] = b3;
              c_new[1] = b2;
              c_new[2] = b1;
              c_new[3] = b0;
              c_new[4] = 32'h1;
              c_we     = 1'h1;
            end
        end


      if (state_update)
        begin
          for (i = 0 ; i < 5 ; i = i + 1)
            h_new[i] = pblock_h_new[i];
          h_we = 1'h1;
        end


      if (mac_update)
        begin
          mac_new[3] = le(hres0);
          mac_new[2] = le(hres1);
          mac_new[1] = le(hres2);
          mac_new[0] = le(hres3);
          mac_we     = 1'h1;
        end
    end // poly1305_core_logic


  //----------------------------------------------------------------
  // poly1305_core_ctrl
  //----------------------------------------------------------------
  always @*
    begin : poly1305_core_ctrl
      state_init             = 1'h0;
      load_block             = 1'h0;
      state_update           = 1'h0;
      pblock_start           = 1'h0;
      final_start            = 1'h0;
      mac_update             = 1'h0;
      ready_new              = 1'h0;
      ready_we               = 1'h0;
      poly1305_core_ctrl_new = CTRL_IDLE;
      poly1305_core_ctrl_we  = 1'h0;


      case (poly1305_core_ctrl_reg)
        CTRL_IDLE:
          begin
            if (init)
              begin
                state_init             = 1'h1;
                ready_new              = 1'h0;
                ready_we               = 1'h1;
                poly1305_core_ctrl_new = CTRL_READY;
                poly1305_core_ctrl_we  = 1'h1;
              end

            if (next)
              begin
                load_block             = 1'h1;
                ready_new              = 1'h0;
                ready_we               = 1'h1;

                if (blocklen > 0)
                  begin
                    poly1305_core_ctrl_new = CTRL_NEXT;
                    poly1305_core_ctrl_we  = 1'h1;
                  end
                else
                  begin
                    poly1305_core_ctrl_new = CTRL_READY;
                    poly1305_core_ctrl_we  = 1'h1;
                  end
              end

            if (finish)
              begin
                final_start            = 1'h1;
                ready_new              = 1'h0;
                ready_we               = 1'h1;
                poly1305_core_ctrl_new = CTRL_FINAL;
                poly1305_core_ctrl_we  = 1'h1;
              end
          end


        CTRL_NEXT:
          begin
            pblock_start           = 1'h1;
            poly1305_core_ctrl_new = CTRL_NEXT_WAIT;
            poly1305_core_ctrl_we  = 1'h1;
          end


        CTRL_NEXT_WAIT:
          begin
            if (pblock_ready)
              begin
                state_update           = 1'h1;
                poly1305_core_ctrl_new = CTRL_READY;
                poly1305_core_ctrl_we  = 1'h1;
              end
          end


        CTRL_FINAL:
          begin
            if (final_ready)
              begin
                mac_update             = 1'h1;
                ready_new              = 1'h1;
                ready_we               = 1'h1;
                poly1305_core_ctrl_new = CTRL_IDLE;
                poly1305_core_ctrl_we  = 1'h1;
              end
          end


        CTRL_READY:
          begin
            ready_new              = 1'h1;
            ready_we               = 1'h1;
            poly1305_core_ctrl_new = CTRL_IDLE;
            poly1305_core_ctrl_we  = 1'h1;
          end

        default:
          begin
          end
      endcase // case (poly1305_core_ctrl_reg)
    end

endmodule // poly1305_core

//======================================================================
// EOF poly1305_core.v
//======================================================================
`undef WT_DCACHE
`undef DISABLE_TRACER
`undef SRAM_NO_INIT
`undef VERILATOR

`timescale 1ns / 1ps
(* dont_touch = "yes"*)
module TopTRNG(
    input               iClk,
    input               iRst,
    input               iEn,
    output     [63:0]   oRng,
    output              oRo
    );

(* dont_touch = "yes"*) wire [6:0]  inject_point;
(* dont_touch = "yes"*) wire [63:0] random_out;
    
LFSR_64 LFSR(
    .iClk(iClk),
    .iRst(iRst),
    .iRoInject(inject_point),
    .oRng(random_out)
);


ringOSC RingOSC(
    .iEn(iEn),
    .oRoInject(inject_point),
    .oRo(oRo)
    );
    
assign oRng = random_out;

endmodule

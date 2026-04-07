`timescale 1ns / 1ps

module FF_D(
    input       iClk,
    input       iRst,
    input       iD,
    output reg  oQ
    );
    
always @ (posedge iClk or posedge iRst) begin
  if(iRst) begin
    oQ <= 1'b0;
  end
  else
    oQ <= iD;
end    
endmodule

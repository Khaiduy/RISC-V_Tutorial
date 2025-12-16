`timescale 1ns / 1ps

module clk_div(
	input  iClk,
	output oClk
    );
	
    reg [9:0] cnt = 10'd0;
    reg clk_buf = 1'b0;

    always @(posedge iClk) begin
        if (cnt == 10'd11) begin
            cnt <= 10'd0;
            clk_buf <= ~clk_buf;
        end else begin
            cnt <= cnt + 10'd1;
        end
    end

    assign oClk = clk_buf;
endmodule

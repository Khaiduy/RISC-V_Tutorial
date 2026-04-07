module adder_32 (
sum,
in_0,
in_1);

output[31:0]sum;

input[31:0]in_0, in_1;

assign sum = in_0 + in_1;

endmodule

`timescale 1ns / 1ps
//-----------------------------------------------------------------------------
// mac17_dsp.v — Explicit DSP48E1 instantiation for GF(p) arithmetic
//
// Port mapping:
//   iB (22-bit) → DSP A port  (b_eff for MUL, {5'b0, a_limb} for ADD/SUB)
//   iA (17-bit) → DSP B port  (a_limb for MUL, unused for ADD/SUB)
//   iC (43-bit) → DSP C port  (circular chain for MUL, b_eff_as for ADD/SUB)
//
// OPMODE:
//   7'b0110101 = C + A*B    (MUL / partial-sum / reduction phases)
//   7'b0110011 = C + {D,A}  (ADD/SUB bypass — skips multiplier)
//
// Register config: AREG=0, BREG=1, MREG=0, PREG=1, CREG=0
//   BREG=1 stores a_limb (on DSP B port) inside DSP, eliminating buf_a_wide.
//   iCEB controls when BREG loads: mul_en, flag_b_load, flag_partial_sum_1.
//-----------------------------------------------------------------------------

module mac17_dsp (
    input        iClk,
    input        iRstn,
    input        iEn,
    input        iAccum_rst,   // synchronous reset of PREG (asserted at mul start)
    input        iCEB,         // clock enable for BREG (DSP B register)
    input [16:0] iA,           // → DSP B port
    input [21:0] iB,           // → DSP A port
    input [42:0] iC,           // → DSP C port
    input [6:0]  iOpmode,      // OPMODE: 7'b0110101=MUL, 7'b0110011=ADDSUB
    input        iCarryIn,     // CARRYIN (1 on DSP[0] for SUB two's-complement +1)
    output [42:0] oS
);

    wire [47:0] dsp_p;

    DSP48E1 #(
        .A_INPUT          ("DIRECT"),
        .B_INPUT          ("DIRECT"),
        .USE_DPORT        ("FALSE"),
        .USE_MULT         ("DYNAMIC"),
        .USE_SIMD         ("ONE48"),
        .USE_PATTERN_DETECT("NO_PATDET"),
        .AUTORESET_PATDET ("NO_RESET"),
        .ACASCREG         (0),   // must match AREG
        .AREG             (0),
        .BCASCREG         (1),   // must match BREG
        .BREG             (1),
        .CREG             (0),
        .DREG             (1),
        .ADREG            (1),
        .MREG             (0),
        .PREG             (1),
        .OPMODEREG        (0),
        .ALUMODEREG       (0),
        .CARRYINREG       (0),
        .CARRYINSELREG    (0),
        .INMODEREG        (1),
        .MASK             (48'h3fffffffffff),
        .PATTERN          (48'h000000000000),
        .SEL_MASK         ("MASK"),
        .SEL_PATTERN      ("PATTERN")
    ) dsp_inst (
        .CLK          (iClk),
        // Data ports
        .A            ({8'b0, iB}),     // 30-bit: {8'b0, 22-bit b_eff or {5'b0,a_limb}}
        .B            ({1'b0, iA}),     // 18-bit: {1'b0, 17-bit a_limb}
        .C            ({5'b0, iC}),     // 48-bit: {5'b0, 43-bit chain or b_eff_as}
        .D            (25'b0),
        // Control
        .OPMODE       (iOpmode),
        .ALUMODE      (4'b0000),        // P = Z + (X + Y + CIN)
        .INMODE       (5'b00000),
        .CARRYINSEL   (3'b000),         // CARRYIN from CARRYIN pin
        .CARRYIN      (iCarryIn),
        // Clock enables
        .CEA1         (1'b0), .CEA2     (1'b0),   // AREG=0
        .CEB1         (1'b0), .CEB2     (iCEB),    // BREG=1: CEB2 controlled externally
        .CEC          (1'b0),                      // CREG=0
        .CED          (1'b0), .CEAD     (1'b0),
        .CEM          (1'b0),                      // MREG=0
        .CEP          (iEn),
        .CECTRL       (1'b0),
        .CEALUMODE    (1'b0),
        .CECARRYIN    (1'b0),
        .CEINMODE     (1'b0),
        // Synchronous resets
        .RSTA         (1'b0), .RSTB          (1'b0),
        .RSTC         (1'b0), .RSTD          (1'b0),
        .RSTM         (1'b0), .RSTP          (~iRstn | iAccum_rst),
        .RSTALUMODE   (1'b0), .RSTCTRL       (1'b0),
        .RSTALLCARRYIN(1'b0), .RSTINMODE     (1'b0),
        // Cascade inputs (unused)
        .ACIN         (30'b0), .BCIN    (18'b0), .PCIN(48'b0),
        .CARRYCASCIN  (1'b0),  .MULTSIGNIN(1'b0),
        // Outputs
        .P            (dsp_p),
        // Unused outputs
        .ACOUT        (), .BCOUT        (),
        .PCOUT        (), .CARRYCASCOUT (),
        .MULTSIGNOUT  (), .CARRYOUT     (),
        .OVERFLOW     (), .UNDERFLOW    (),
        .PATTERNDETECT(), .PATTERNBDETECT()
    );

    assign oS = dsp_p[42:0];

endmodule

/*
 * ascon_p12_rv32.S — void ascon_p12(uint64_t x[5])
 *
 * Thin shim that runs the 12-round Ascon permutation by reusing ascon_permute()
 * from the asm_rv32i AEAD (externals/ascon-c/.../asm_rv32i/ascon.S). This lets
 * Ascon-Hash256 (ascon_hash256_rv32.c) share the SAME permutation as the AEAD,
 * eliminating the ~618 B duplicate that the ref C hash carried.
 *
 * ascon_permute ABI (from ascon.S):
 *   - 320-bit state in s0..s9 (s0=x0h, s1=x0l, s2=x1h, s3=x1l, ... s8=x4h, s9=x4l)
 *   - start round constant in t1 (x6); 0xf0 selects 12 rounds
 *   - return address in t0 (x5); returns via `jalr zero, 0(t0)`
 *   - clobbers t3..t6; leaves the permuted state in s0..s9
 *
 * State words use the same (hi32,lo32) split + little-endian byte packing as the
 * ascon-c ref, so the result is byte-exact with ref P12.
 */
    .text
    .align 2
    .globl ascon_p12
    .type ascon_p12,@function
ascon_p12:                      /* a0 = uint64_t x[5] */
    addi sp, sp, -48
    sw   ra, 44(sp)
    sw   s0,  0(sp)
    sw   s1,  4(sp)
    sw   s2,  8(sp)
    sw   s3, 12(sp)
    sw   s4, 16(sp)
    sw   s5, 20(sp)
    sw   s6, 24(sp)
    sw   s7, 28(sp)
    sw   s8, 32(sp)
    sw   s9, 36(sp)
    /* load state: little-endian uint64 in memory → lo32 at +0, hi32 at +4 */
    lw   s1,  0(a0)             /* x0l */
    lw   s0,  4(a0)             /* x0h */
    lw   s3,  8(a0)             /* x1l */
    lw   s2, 12(a0)             /* x1h */
    lw   s5, 16(a0)             /* x2l */
    lw   s4, 20(a0)             /* x2h */
    lw   s7, 24(a0)             /* x3l */
    lw   s6, 28(a0)             /* x3h */
    lw   s9, 32(a0)             /* x4l */
    lw   s8, 36(a0)             /* x4h */
    li   t1, 0xf0              /* 12-round start constant */
    jal  t0, ascon_permute
    sw   s1,  0(a0)
    sw   s0,  4(a0)
    sw   s3,  8(a0)
    sw   s2, 12(a0)
    sw   s5, 16(a0)
    sw   s4, 20(a0)
    sw   s7, 24(a0)
    sw   s6, 28(a0)
    sw   s9, 32(a0)
    sw   s8, 36(a0)
    lw   ra, 44(sp)
    lw   s0,  0(sp)
    lw   s1,  4(sp)
    lw   s2,  8(sp)
    lw   s3, 12(sp)
    lw   s4, 16(sp)
    lw   s5, 20(sp)
    lw   s6, 24(sp)
    lw   s7, 28(sp)
    lw   s8, 32(sp)
    lw   s9, 36(sp)
    addi sp, sp, 48
    ret

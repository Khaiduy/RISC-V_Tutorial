# EDHOC Hardware Benchmarks (Arty A7-100T, RV32IMAC @ 50 MHz)

All numbers measured on Arty A7-100T FPGA pairs running the Chipyard-built
bare-metal Rocket core at 50 MHz with software wolfcrypt (no hardware
accelerator). Builds use `TIMING=1 DEBUG=0` so debug-print code is gated out.

All cycle counts are **compute-only** — UART transmission time is excluded
because the library's `_tb_msg*_cyc` rdcycle brackets surround only the
`msg{1,2,3,4}_gen/_process` paths. The "compute" totals reported by the apps =
`ephemeral_keygen + msg1_gen + msg3_gen` (initiator) or
`ephemeral_keygen + msg2_gen + msg3_process` (responder).

**Coverage**: All 4 methods (M0..M3) × all 9 suites (0..6, 24, 25), plus PSK
Method 4 × suites 0 and 7. **38/38 configurations verified end-to-end on
hardware** with matching `PRK_out` on both sides.

## Method × Suite matrix (standard library) — 36/36 OK

| Cfg       | Method        | Suite                                    | init `.text` | resp `.text` | init `.rodata` | resp `.rodata` | init compute (cycles) | resp compute (cycles) |
|-----------|---------------|------------------------------------------|-------------:|-------------:|---------------:|---------------:|----------------------:|----------------------:|
| M0 S0     | Sig/Sig       | X25519 + AES-CCM-16-64-128 + SHA-256     |       42,524 |       42,798 |          6,528 |          6,536 |           751,910,494 |           751,980,220 |
| M0 S1     | Sig/Sig       | X25519 + AES-CCM-16-128-128 + SHA-256    |       42,524 |       42,798 |          6,528 |          6,536 |           751,923,280 |           751,963,990 |
| M0 S2     | Sig/Sig       | P-256 + AES-CCM-16-64-128 + SHA-256      |       57,910 |       58,182 |          8,952 |          8,952 |           140,312,228 |           140,701,064 |
| M0 S3     | Sig/Sig       | P-256 + AES-CCM-16-128-128 + SHA-256     |       57,910 |       58,182 |          8,952 |          8,952 |           140,300,073 |           141,028,722 |
| M0 S4     | Sig/Sig       | X25519 + ChaCha20-Poly1305 + SHA-256     |       39,328 |       39,578 |          2,392 |          2,392 |           752,486,305 |           752,134,989 |
| M0 S5     | Sig/Sig       | P-256 + ChaCha20-Poly1305 + SHA-256      |       54,604 |       54,868 |          4,816 |          4,816 |           138,750,496 |           139,008,911 |
| M0 S6     | Sig/Sig       | X25519 + ES256 + A128GCM + SHA-256       |       69,042 |       69,378 |          9,668 |          9,668 |           321,151,637 |           306,769,025 |
| M0 S24    | Sig/Sig       | P-384 + AES-256-GCM + SHA-384            |       72,418 |       72,090 |         10,136 |         10,136 |           463,030,341 |           462,774,844 |
| M0 S25    | Sig/Sig       | X448 + Ed448 + ChaCha + SHAKE-256        |       47,430 |       47,434 |          2,593 |          2,597 |         2,428,452,373 |         2,429,823,884 |
| M1 S0     | Sig/StaticDH  | X25519 + AES-CCM-16-64-128               |       41,326 |       41,316 |          6,460 |          6,528 |           559,155,277 |           631,230,098 |
| M1 S1     | Sig/StaticDH  | X25519 + AES-CCM-16-128-128              |       41,326 |       41,316 |          6,460 |          6,528 |           559,160,204 |           631,247,107 |
| M1 S2     | Sig/StaticDH  | P-256 + AES-CCM-16-64-128                |       54,984 |       56,958 |          8,876 |          8,944 |           113,602,350 |           141,357,338 |
| M1 S3     | Sig/StaticDH  | P-256 + AES-CCM-16-128-128               |       54,984 |       56,958 |          8,876 |          8,944 |           113,631,415 |           141,359,521 |
| M1 S4     | Sig/StaticDH  | X25519 + ChaCha20-Poly1305               |       38,096 |       38,082 |          2,324 |          2,392 |           558,295,939 |           629,862,130 |
| M1 S5     | Sig/StaticDH  | P-256 + ChaCha20-Poly1305                |       51,692 |       53,676 |          4,740 |          4,808 |           115,056,797 |           140,483,701 |
| M1 S6     | Sig/StaticDH  | X25519 + ES256 + A128GCM                 |       63,568 |       68,216 |          9,556 |          9,660 |           383,804,221 |           389,316,268 |
| M1 S24    | Sig/StaticDH  | P-384 + AES-256-GCM                      |       69,432 |       69,954 |         10,036 |         10,104 |           376,789,944 |           464,260,754 |
| M1 S25    | Sig/StaticDH  | X448 + Ed448 + ChaCha + SHAKE-256        |       45,848 |       45,410 |          2,491 |          2,563 |         1,688,250,337 |         1,708,466,635 |
| M2 S0     | StaticDH/Sig  | X25519 + AES-CCM-16-64-128               |       41,232 |       41,622 |          6,456 |          6,460 |           591,237,557 |           595,905,270 |
| M2 S1     | StaticDH/Sig  | X25519 + AES-CCM-16-128-128              |       41,232 |       41,622 |          6,456 |          6,460 |           591,399,969 |           596,002,054 |
| M2 S2     | StaticDH/Sig  | P-256 + AES-CCM-16-64-128                |       56,372 |       55,268 |          8,876 |          8,876 |           140,918,194 |           113,634,721 |
| M2 S3     | StaticDH/Sig  | P-256 + AES-CCM-16-128-128               |       56,372 |       55,268 |          8,876 |          8,876 |           141,097,893 |           113,770,254 |
| M2 S4     | StaticDH/Sig  | X25519 + ChaCha20-Poly1305               |       38,000 |       38,390 |          2,320 |          2,324 |           590,838,877 |           595,004,930 |
| M2 S5     | StaticDH/Sig  | P-256 + ChaCha20-Poly1305                |       53,078 |       51,972 |          4,740 |          4,740 |           140,591,693 |           114,480,964 |
| M2 S6     | StaticDH/Sig  | X25519 + ES256 + A128GCM                 |       67,540 |       63,954 |          9,592 |          9,556 |           410,682,201 |           384,166,413 |
| M2 S24    | StaticDH/Sig  | P-384 + AES-256-GCM                      |       69,298 |       69,212 |         10,036 |         10,036 |           462,854,150 |           375,362,612 |
| M2 S25    | StaticDH/Sig  | X448 + Ed448 + ChaCha + SHAKE-256        |       45,414 |       46,004 |          2,495 |          2,495 |         1,732,001,134 |         1,665,770,385 |
| M3 S0     | StaticDH × 2  | X25519 + AES-CCM-16-64-128               |       26,742 |       27,130 |          5,192 |          5,192 |           473,667,755 |           444,315,734 |
| M3 S1     | StaticDH × 2  | X25519 + AES-CCM-16-128-128              |       26,742 |       27,130 |          5,192 |          5,192 |           473,787,006 |           444,508,374 |
| M3 S2     | StaticDH × 2  | P-256 + AES-CCM-16-64-128                |       52,596 |       52,966 |          8,692 |          8,692 |           113,971,044 |           114,553,390 |
| M3 S3     | StaticDH × 2  | P-256 + AES-CCM-16-128-128               |       52,596 |       52,966 |          8,692 |          8,692 |           114,218,529 |           114,691,287 |
| M3 S4     | StaticDH × 2  | X25519 + ChaCha20-Poly1305               |       23,494 |       23,886 |          1,056 |          1,056 |           443,845,208 |           473,226,559 |
| M3 S5     | StaticDH × 2  | P-256 + ChaCha20-Poly1305                |       49,378 |       49,734 |          4,556 |          4,556 |           113,379,615 |           113,167,892 |
| M3 S6     | StaticDH × 2  | X25519 + ES256 + A128GCM                 |       38,486 |       38,826 |          5,528 |          5,532 |           444,158,432 |           473,460,603 |
| M3 S24    | StaticDH × 2  | P-384 + AES-256-GCM                      |       64,574 |       64,518 |          9,748 |          9,748 |           378,960,066 |           379,377,775 |
| M3 S25    | StaticDH × 2  | X448 + Ed448 + ChaCha + SHAKE-256        |       31,348 |       31,568 |          1,545 |          1,545 |           999,385,369 |           982,211,731 |

## PSK Method 4 — 2/2 OK

| Cfg         | Suite                                                | init `.text` | resp `.text` | init `.rodata` | resp `.rodata` | init compute | resp compute |
|-------------|------------------------------------------------------|-------------:|-------------:|---------------:|---------------:|-------------:|-------------:|
| PSK S0      | X25519 + AES-CCM-16-64-128 + SHA-256                 |       21,186 |       22,688 |          5,608 |          5,648 |  227,459,746 |  ~235 M (boot+run) |
| PSK S7      | X25519 + Ascon-AEAD-128 + Ascon-Hash-256             |       17,218 |       18,728 |          1,482 |          1,522 |  241,041,758 |  ~227 M (boot+run) |

PSK responder's `g_y` derivation (1 × X25519 ≈ 110 M cycles) runs at boot
before `edhoc_responder_run`, so the bracketed `_tb_psk_resp_total_cyc` only
covers the in-handshake X25519 (≈ 110 M) plus AEAD/hash. Total comparable
figure ≈ boot + run ≈ 230–240 M.

## Sweep methodology

The sweep that produced this table runs `make` + HW test for each config
sequentially. Some configs occasionally fail the initial run because the
**FT2232H JTAG cable becomes transiently unreliable** under back-to-back load
cycles (OpenOCD reports `Failed read (NOP) at 0x11; value=0x0, status=1` /
`unable to halt hart 0`). The fix is automatic retry: every config that
failed the initial sweep passed on the first or second retry attempt with
a 10 s settle pause. No real binary bugs were found.

Reproduce:

```bash
cd fpga/sw/edhoc
# Build + test one config:
make edhoc_m${M}_initiator CRYPTO_SUITE=${S} TIMING=1 DEBUG=0
make edhoc_m${M}_responder CRYPTO_SUITE=${S} TIMING=1 DEBUG=0
INITIATOR_ELF=$(pwd)/build/edhoc_m${M}_initiator.elf \
RESPONDER_ELF=$(pwd)/build/edhoc_m${M}_responder.elf \
  bash ../test_uart/load_edhoc.sh m${M} ${S}
# Cycles in /tmp/edhoc_<timestamp>/{initiator,responder}.log "Grand total" lines.

# PSK:
make edhoc_psk_initiator CRYPTO_SUITE=${0|7} TIMING=1 DEBUG=0
make edhoc_psk_responder CRYPTO_SUITE=${0|7} TIMING=1 DEBUG=0
# METHOD=psk
```

## Reading the numbers

### X25519 / scalar-mult cost dominates compute time

| Curve        | ~Cost per scalar mult | Source |
|--------------|----------------------:|--------|
| X25519       | ~110 M cycles | wolfcrypt `curve25519.c` + `fe_low_mem.c` |
| P-256        | ~28 M cycles  | wolfcrypt `ecc.c` + `sp_int.c` |
| P-384        | ~95 M cycles  | wolfcrypt with `sp_int.c` |
| X448         | ~400 M cycles | wolfcrypt `curve448.c` |
| Ed25519 sign | ~110 M cycles | one scalar mult on Ed25519 base |
| ES256 sign   | ~28 M cycles  | one P-256 scalar mult |
| Ed448 sign   | ~600 M cycles | dominates Suite 25 totals |

Per-method DH/sign counts:

| Method        | ECDH ops per side | Sign ops per side |
|---------------|------------------:|------------------:|
| Sig/Sig (M0)        | 2 | 1 sign + 1 verify |
| Sig/StaticDH (M1)   | 3 | 1 (one side) |
| StaticDH/Sig (M2)   | 3 | 1 (one side) |
| StaticDH × 2 (M3)   | 4 | 0 |
| PSK (Method 4)      | 2 | 0 |

Example check — M3 S0 init = 4 X25519 ≈ 440 M; measured 473 M (≈ 7 %
overhead for SHA-256, HKDF, AES-CCM, CBOR encode/decode).

### Software-size patterns

- **AES vs Ascon `.rodata`**: AES `Te[]` table = 4,096 B; Ascon round
  constants = 12 B. Suite 7 vs Suite 0 saves ~4 KB constant data per binary.
- **Methods**: M3 (no signing/verification) saves ~15 KB `.text` vs
  M0/M1/M2 because the EDHOC sig/MAC layer + Ed25519/ECDSA signing code
  drops out.
- **Suite 25**: strips AES from `.rodata` (~−5 KB) but adds X448+Ed448
  code (~+4 KB `.text`).
- **PSK Method 4**: smallest by far. PSK S7 is ~17 KB total `.text`, half
  the size of M0 S0 (~42 KB).

## Provenance

- Measured: 2026-05-22 on Arty A7-100T pair, JTAG via two C232HM cables.
- Toolchain: `riscv64-unknown-elf-gcc` (in `/home/khaiduy/opt/riscv/bin`).
- wolfssl: v5.9.1-stable (submodule, commit `1d363f3a`) + overrides in
  `wolfssl-overrides/`.
- Build flags: `-march=rv32imac_zicsr_zifencei -mabi=ilp32 -Os -flto -g0
  -ffunction-sections -fdata-sections`. LTO + `--gc-sections` at link.
- Raw sweep data: `/tmp/bench_v2.tsv`, `/tmp/retry_v2.tsv`, merged into
  `/tmp/bench_final.tsv`.

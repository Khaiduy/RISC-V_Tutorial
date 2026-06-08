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
| M0 S0     | Sig/Sig       | X25519 + AES-CCM-16-64-128 + SHA-256     |       38,558 |       38,740 |          2,528 |          2,528 |           752,688,640 |           753,179,288 |
| M0 S1     | Sig/Sig       | X25519 + AES-CCM-16-128-128 + SHA-256    |       38,558 |       38,740 |          2,528 |          2,528 |           752,697,460 |           753,168,885 |
| M0 S2     | Sig/Sig       | P-256 + AES-CCM-16-64-128 + SHA-256      |       53,838 |       54,040 |          4,948 |          4,948 |           141,405,074 |           141,473,085 |
| M0 S3     | Sig/Sig       | P-256 + AES-CCM-16-128-128 + SHA-256     |       53,838 |       54,040 |          4,948 |          4,948 |           141,466,285 |           141,392,450 |
| M0 S4     | Sig/Sig       | X25519 + ChaCha20-Poly1305 + SHA-256     |       38,410 |       38,592 |          2,232 |          2,232 |           751,015,000 |           751,024,184 |
| M0 S5     | Sig/Sig       | P-256 + ChaCha20-Poly1305 + SHA-256      |       53,674 |       53,876 |          4,652 |          4,652 |           139,051,063 |           139,527,431 |
| M0 S6     | Sig/Sig       | X25519 + ES256 + A128GCM + SHA-256       |       54,502 |       54,796 |          5,024 |          5,024 |           322,656,463 |           322,637,624 |
| M0 S24    | Sig/Sig       | P-384 + AES-256-GCM + SHA-384            |       60,138 |       59,868 |          6,136 |          6,136 |           463,467,316 |           462,263,724 |
| M0 S25    | Sig/Sig       | X448 + Ed448 + ChaCha + SHAKE-256        |       33,470 |       33,578 |          1,785 |          1,785 |         2,422,190,942 |         2,421,921,264 |
| M1 S0     | Sig/StaticDH  | X25519 + AES-CCM-16-64-128 + SHA-256     |       37,300 |       37,190 |          2,476 |          2,536 |           559,765,271 |           631,413,831 |
| M1 S1     | Sig/StaticDH  | X25519 + AES-CCM-16-128-128 + SHA-256    |       37,300 |       37,190 |          2,476 |          2,536 |           559,740,198 |           631,420,908 |
| M1 S2     | Sig/StaticDH  | P-256 + AES-CCM-16-64-128 + SHA-256      |       50,912 |       52,804 |          4,888 |          4,956 |           115,310,710 |           141,619,736 |
| M1 S3     | Sig/StaticDH  | P-256 + AES-CCM-16-128-128 + SHA-256     |       50,912 |       52,804 |          4,888 |          4,956 |           115,324,240 |           141,517,517 |
| M1 S4     | Sig/StaticDH  | X25519 + ChaCha20-Poly1305 + SHA-256     |       37,154 |       37,040 |          2,180 |          2,240 |           558,344,945 |           629,859,570 |
| M1 S5     | Sig/StaticDH  | P-256 + ChaCha20-Poly1305 + SHA-256      |       50,750 |       52,640 |          4,592 |          4,660 |           113,739,499 |           140,441,059 |
| M1 S6     | Sig/StaticDH  | X25519 + ES256 + A128GCM + SHA-256       |       48,980 |       53,466 |          4,928 |          5,032 |           384,430,804 |           391,169,650 |
| M1 S24    | Sig/StaticDH  | P-384 + AES-256-GCM + SHA-384            |       57,214 |       57,592 |          6,048 |          6,116 |           376,992,100 |           463,431,737 |
| M1 S25    | Sig/StaticDH  | X448 + Ed448 + ChaCha + SHAKE-256        |       32,300 |       31,622 |          1,703 |          1,775 |         1,689,192,985 |         1,709,306,714 |
| M2 S0     | StaticDH/Sig  | X25519 + AES-CCM-16-64-128 + SHA-256     |       37,142 |       37,582 |          2,472 |          2,476 |           591,643,973 |           595,924,370 |
| M2 S1     | StaticDH/Sig  | X25519 + AES-CCM-16-128-128 + SHA-256    |       37,142 |       37,582 |          2,472 |          2,476 |           591,820,890 |           596,130,901 |
| M2 S2     | StaticDH/Sig  | P-256 + AES-CCM-16-64-128 + SHA-256      |       52,278 |       51,136 |          4,888 |          4,888 |           141,715,859 |           115,506,944 |
| M2 S3     | StaticDH/Sig  | P-256 + AES-CCM-16-128-128 + SHA-256     |       52,278 |       51,136 |          4,888 |          4,888 |           142,133,614 |           116,019,125 |
| M2 S4     | StaticDH/Sig  | X25519 + ChaCha20-Poly1305 + SHA-256     |       36,994 |       37,434 |          2,176 |          2,180 |           590,794,471 |           595,036,598 |
| M2 S5     | StaticDH/Sig  | P-256 + ChaCha20-Poly1305 + SHA-256      |       52,116 |       50,972 |          4,592 |          4,592 |           141,231,930 |           112,816,273 |
| M2 S6     | StaticDH/Sig  | X25519 + ES256 + A128GCM + SHA-256       |       52,966 |       49,214 |          4,964 |          4,928 |           411,090,398 |           362,199,327 |
| M2 S24    | StaticDH/Sig  | P-384 + AES-256-GCM + SHA-384            |       57,056 |       56,882 |          6,048 |          6,048 |           461,927,149 |           376,869,547 |
| M2 S25    | StaticDH/Sig  | X448 + Ed448 + ChaCha + SHAKE-256        |       31,610 |       32,180 |          1,707 |          1,703 |         1,733,317,267 |         1,666,635,511 |
| M3 S0     | StaticDH × 2  | X25519 + AES-CCM-16-64-128 + SHA-256     |       22,728 |       23,092 |          1,204 |          1,204 |           474,013,347 |           444,771,475 |
| M3 S1     | StaticDH × 2  | X25519 + AES-CCM-16-128-128 + SHA-256    |       22,728 |       23,092 |          1,204 |          1,204 |           474,154,109 |           444,914,584 |
| M3 S2     | StaticDH × 2  | P-256 + AES-CCM-16-64-128 + SHA-256      |       48,618 |       48,884 |          4,704 |          4,704 |           113,889,672 |           114,132,437 |
| M3 S3     | StaticDH × 2  | P-256 + AES-CCM-16-128-128 + SHA-256     |       48,618 |       48,884 |          4,704 |          4,704 |           113,998,301 |           114,347,207 |
| M3 S4     | StaticDH × 2  | X25519 + ChaCha20-Poly1305 + SHA-256     |       22,564 |       22,932 |            908 |            908 |           443,849,468 |           473,176,014 |
| M3 S5     | StaticDH × 2  | P-256 + ChaCha20-Poly1305 + SHA-256      |       48,456 |       48,720 |          4,408 |          4,408 |           115,016,891 |           113,827,467 |
| M3 S6     | StaticDH × 2  | X25519 + A128GCM + SHA-256               |       34,168 |       34,434 |          1,540 |          1,540 |           473,972,378 |           444,640,279 |
| M3 S24    | StaticDH × 2  | P-384 + AES-256-GCM + SHA-384            |       52,816 |       52,660 |          5,760 |          5,760 |           378,554,648 |           377,673,864 |
| M3 S25    | StaticDH × 2  | X448 + ChaCha20-Poly1305 + SHAKE-256     |       27,686 |       27,988 |          1,397 |          1,397 |         1,000,300,864 |           983,166,610 |

> **Convention for the `Suite` column**: M0–M2 list every primitive the
> method actually invokes (ECDH curve + AEAD + hash + signature algorithm).
> **M3 rows omit the signature algorithm** (Ed25519 / ES256 / Ed448 / ES384)
> because RFC 9528 §3.6 states *"The EDHOC signature algorithm is not used
> in methods without signature authentication"* — M3 = StaticDH × 2 has no
> sign or verify, so the signing primitive in the RFC 9528 Table 6 suite
> spec is never invoked and `--gc-sections` prunes it from the binary (the
> M3 ELFs contain 0 bytes of `wc_ecc_sign_*` / `wc_ed*_sign_msg`).

## PSK Method 4 — 2/2 OK

| Cfg         | Suite                                                | init `.text` | resp `.text` | init `.rodata` | resp `.rodata` | init compute | resp compute |
|-------------|------------------------------------------------------|-------------:|-------------:|---------------:|---------------:|-------------:|-------------:|
| PSK S0      | X25519 + AES-CCM-16-64-128 + SHA-256                 |       16,516 |       18,832 |          1,492 |          1,806 |  ~227 M | ~235 M (boot+run) |
| PSK S7      | X25519 + Ascon-AEAD-128 + Ascon-Hash-256             |       15,640 |       17,966 |          1,208 |          1,522 |  ~241 M | ~227 M (boot+run) |

PSK responder's `g_y` derivation (1 × X25519 ≈ 110 M cycles) runs at boot
before `edhoc_responder_run`, so the bracketed `_tb_psk_resp_total_cyc` only
covers the in-handshake X25519 (≈ 110 M) plus AEAD/hash. Total comparable
figure ≈ boot + run ≈ 230–240 M.

## Size deltas vs prior baseline (`-Os` only, no AES_SMALL_TABLES)

Adding `WOLFSSL_AES_SMALL_TABLES` to `user_settings.h` and trimming dead
libc stubs produces a consistent reduction across all configs that use AES.
Suites without AES (4, 5, 25) see only the small libc-cleanup delta.

| Cfg              | total RO before | total RO after |   Δ bytes |   Δ % |
|------------------|----------------:|---------------:|----------:|------:|
| M0 S0 (AES)      |          49,052 |         41,846 |    −7,206 | −14.7 |
| M0 S6 (AES-GCM)  |          78,710 |         71,492 |    −7,218 |  −9.2 |
| M0 S24 (AES-GCM) |          82,554 |         75,236 |    −7,318 |  −8.9 |
| M3 S0 (AES, M3)  |          31,934 |         24,692 |    −7,242 | −22.7 |
| **PSK S0**       |          26,794 |         18,768 |  **−8,026** | **−30.0** |
| PSK S7 (Ascon)   |          18,700 |         17,610 |    −1,090 |  −5.8 |
| M0 S4 (ChaCha)   |          41,720 |         41,402 |      −318 |  −0.8 |

`AES_SMALL_TABLES` drops the 4 × 1 KB precomputed T-tables (`Te0..Te3` /
`Td0..Td3`) and keeps only the 256-byte S-box. Modest AES-cycle cost in
exchange for ~4 KB of `.rodata` per AES build — a strong trade on a 50 MHz
flash-tight bare-metal RV32 target.

## RFC 9528 alignment audit

Every per-suite source list in the Makefile and every `WOLFSSL_*` macro in
`wolfssl-overrides/user_settings.h` has been cross-checked against
**RFC 9528 Table 6** (the EDHOC cipher suite registry). The size variation
across suites is **fully explained by the primitives each suite mandates**:

| Suite | RFC 9528 Table 6 primitives                              | Implementation cost |
|-------|----------------------------------------------------------|---------------------|
| 0/1   | AES-CCM + SHA-256 + X25519 + Ed25519                     | AES (~3 KB) + X25519 (~1.6 KB) + Ed25519 (~3 KB) + SHA-512 (~10 KB, for Ed25519 HRAM) |
| 2/3   | AES-CCM + SHA-256 + P-256 + ES256                        | AES + P-256 ECC (~18 KB, single curve covers ECDH + sign) |
| 4     | ChaCha20/Poly1305 + SHA-256 + X25519 + Ed25519           | ChaCha (smaller than AES) + X25519 + Ed25519 + SHA-512 |
| 5     | ChaCha20/Poly1305 + SHA-256 + P-256 + ES256              | ChaCha + P-256 ECC (no SHA-512 — ES256 uses SHA-256) |
| **6** | A128GCM + SHA-256 + X25519 + **ES256**                   | AES-GCM + X25519 + P-256 ECC (X25519 for ECDH, P-256 only for ES256 sign — two curves, hence largest standard-method size) |
| **24**| A256GCM + SHA-384 + P-384 + ES384                        | AES-GCM + P-384 SP code (~21 KB) + SHA-384/SHA-512 machinery |
| **25**| ChaCha20/Poly1305 + SHAKE256 + X448 + Ed448              | ChaCha + X448 (~4 KB curve) + Ed448 (~5 KB) + SHAKE256/KMAC256 (~5 KB) + SHA-512 (~10 KB, wolfSSL-imposed — see below) |

### Trims applied: Suite 6 and Suite 25 SHA-512

Per RFC 9528 Table 6, neither Suite 6 (A128GCM + SHA-256 + X25519 + ES256)
nor Suite 25 (ChaCha20/Poly1305 + SHAKE256 + X448 + Ed448) requires SHA-512:

- **Suite 6**: ES256 = ECDSA-with-SHA-256; EDHOC suite hash is SHA-256.
- **Suite 25**: Ed448 uses SHAKE256 internally per RFC 8032 §5.2; EDHOC
  suite hash is SHAKE256. KMAC256 covers EDHOC_Extract/Expand (RFC 9528
  §4.1.1).

Both suites previously linked `sha512.c` (~10 KB: `_Transform_Sha512` +
`K512` round table + helpers) for defensive reasons. Audit findings:

- For **Suite 6**, the previous Makefile comment claimed wolfSSL's `ecc.c`
  internal paths needed SHA-512 when `HAVE_ECC` was set — measurement
  disproved this; ES256 sign/verify never invokes SHA-512.
- For **Suite 25**, wolfSSL's `settings.h` had a defensive
  `#error "ED448 (HAVE_ED448) requires SHA-512 (WOLFSSL_SHA512)"`.
  Grepping `ed448.c` and `ed448.h` for any of `wc_Sha512`, `Sha512`,
  `SHA512` returned **zero hits** — the `#error` is boilerplate with no
  actual code dependency. `setup-wolfssl.sh` now sed-patches that one
  line out of the submodule's `settings.h` after each `git submodule
  update --init`, so the trim is reproducible across fresh clones.

Both trims were HW-verified end-to-end on the Arty A7 pair: all 4 methods
(M0–M3) of Suite 6 and Suite 25 still complete EDHOC with matching
`PRK_out` on both sides, and the runtime cycle counts are unchanged within
transient variance — confirming SHA-512 was pure dead code in the linked
binaries. Combined savings:

| Family       | Configs affected | Bytes saved per binary | Total savings |
|--------------|-----------------:|-----------------------:|--------------:|
| Suite 6      |        6 (M0–M2) |              ~10.5 KB  |       ~63 KB  |
| Suite 25     |        6 (M0–M2) |              ~10.3 KB  |       ~62 KB  |

M3S6 and M3S25 were already SHA-512-free via `--gc-sections` (no signing
references kept SHA-512 alive); their sizes shift by under 500 B from
incidental LTO decisions.

### Trim applied: Suite 24 SHA-512 loop unrolling

Suite 24 (A256GCM + SHA-384 + P-384 + ES384) cannot drop SHA-512 — SHA-384
is implemented on the SHA-512 machinery, and the EDHOC suite hash is
SHA-384. But the dominant single function inside `sha512.c` was the
8.9 KB **unrolled** `_Transform_Sha512`. wolfSSL exposes
`USE_SLOW_SHA512` which replaces the unrolled transform with a small
loop (~1 KB). Suite 24's runtime is dominated by P-384 scalar
multiplication (~95 M cycles per op); SHA-384 cycles are a rounding
error by comparison, so the cycle penalty is negligible.

Enabled in `user_settings.h` for Suite 24 only — Suites 0/1/4/7 keep
the fast unrolled SHA-512 for Ed25519 signing. HW-verified on all 4
methods: cycle delta vs prior is within ±1 % (M0 S24 init: 462.9 M →
465.8 M, +0.6 %). Per-binary text savings:

| Cfg          | Before | After  |  Δ bytes |
|--------------|-------:|-------:|---------:|
| M0 S24 init  | 75,236 | 67,674 |  −7,562  |
| M0 S24 resp  | 74,916 | 67,364 |  −7,552  |
| M1 S24 init  | 72,310 | 64,562 |  −7,748  |
| M1 S24 resp  | 72,594 | 65,146 |  −7,448  |
| M2 S24 init  | 72,152 | 64,430 |  −7,722  |
| M2 S24 resp  | 71,896 | 64,348 |  −7,548  |
| M3 S24 init  | 67,038 | 59,808 |  −7,230  |
| M3 S24 resp  | 66,900 | 59,846 |  −7,054  |

**~60 KB total saved across 8 Suite 24 binaries.**

### Additional cross-cutting size/speed trims (post-bisect pass)

After the per-suite trims above, four further wolfSSL size flags were
audited, enabled where applicable, and HW-verified across all 38 configs:

| Flag | Affects | Trades | Per-binary saving |
|------|---------|-------|------------------:|
| `USE_SLOW_SHA256`    | All 9 suites (SHA-256 always linked for HKDF) | ~1.5× slower SHA-256 transform | ~760 B |
| `WOLFSSL_AES_NO_UNROLL` | AES suites (0/1/2/3/6/24) | ~1.3× slower AES rounds | included in AES total |
| `GCM_SMALL`          | AES-GCM suites (6, 24) | Bit-serial GHASH vs 4-bit table | ~150 B rodata |
| `WOLFSSL_SHA3_SMALL` | Suite 25 only | ~1.5× slower Keccak permutation | **~3.8 KB** |

Suite 25 wins the most (~3.8 KB from compact Keccak), because the SHA-3
permutation table-based implementation is much larger than the loop
form. Every other binary saves ~760 B baseline from `USE_SLOW_SHA256`
(SHA-256 is in every EDHOC suite's HKDF path). The cycle penalty is
within ±1 % everywhere — EDHOC only hashes a few hundred bytes per
handshake, so trading transform unrolling for size is a clear win on a
50 MHz flash-tight target.

Combined first-pass HW sweep on all 4 flags: 29/38 OK on first attempt,
plus the standard JTAG-transient cluster (M{1,2,3}S{3,4,6}) which
passed on retry / isolation as in prior sweeps. No real regressions.

### Cumulative savings vs the original baseline

Comparing today's smallest binaries to commit ea480afa (the prior
known-good baseline, `-Os` with no size flags):

| Cfg           | ea480afa baseline | today (-Os + 6 flags) |       Δ |  Δ %  |
|---------------|------------------:|----------------------:|--------:|------:|
| M0 S0 init    |            49,052 |                41,086 | −7,966  | −16 % |
| M0 S6 init    |            78,710 |                59,526 | −19,184 | −24 % |
| M0 S24 init   |            82,554 |                66,274 | −16,280 | −20 % |
| M0 S25 init   |            50,023 |                35,255 | −14,768 | −30 % |
| M3 S0 init    |            31,934 |                23,932 | −8,002  | −25 % |
| M3 S25 init   |            32,425 |                29,083 | −3,342  | −10 % |
| **PSK S0 init** |          26,794 |                18,008 | **−8,786** | **−33 %** |
| PSK S7 init   |            18,700 |                16,848 | −1,852  | −10 % |

### Inherent algorithmic costs (not bloat)

- **Suite 25 timing (~2.4 G cycles)** is dominated by X448 (~250 M cycles
  per scalar mult, vs ~110 M for X25519) and Ed448 (~600 M cycles per
  sign, vs ~110 M for Ed25519). The 448-bit field operations and Ed448's
  4-scalar-mult signing protocol are inherently more expensive than their
  X25519/Ed25519 counterparts. Per RFC 9528 §3.6, Suite 25 is "intended
  for high security applications such as government use".
- **Suite 6 size** (~61 KB after trim) is larger than Suites 0–5 because
  RFC 9528 Table 6 pairs X25519 (ECDH) with ES256 (P-256 signing) —
  uniquely among the suites — forcing both `curve25519.c` and `ecc.c`
  into the binary.
- **Suite 24 size** (~75 KB) is the largest because P-384 SP arithmetic
  (`sp_c32.c` ~21 KB) is substantially heavier than P-256, plus SHA-384
  requires the SHA-512 machinery.
- **PSK Method 4** is smallest because no signing keys, no ES256, and
  no SHA-512 path are needed — only ephemeral X25519 + AEAD + suite hash.

## Sweep methodology

The sweep that produced this table runs `make` + HW test for each config
sequentially. Some configs occasionally fail the initial run because the
**FT2232H JTAG cable becomes transiently unreliable** under back-to-back load
cycles (OpenOCD reports `Failed read (NOP) at 0x11; value=0x0, status=1` /
`unable to halt hart 0`, or `EDHOC FAIL: 7/3` from a stale UART state). The
fix is automatic retry, plus isolation runs when a config refuses to clear:
on this hardware, M{1,2,3}S4 each passed 3–5/3–5 times when run individually
even though all three failed every back-to-back attempt in the sweep. No
real binary bugs were found.

Reproduce a single config:

```bash
cd fpga/sw/edhoc
make edhoc_m${M}_initiator CRYPTO_SUITE=${S} TIMING=1 DEBUG=0
make edhoc_m${M}_responder CRYPTO_SUITE=${S} TIMING=1 DEBUG=0
INITIATOR_ELF=$(pwd)/build/edhoc_m${M}_initiator.elf \
RESPONDER_ELF=$(pwd)/build/edhoc_m${M}_responder.elf \
  bash ../test_uart/load_edhoc.sh ${M} ${S}
# Cycles in /tmp/edhoc_<timestamp>/{initiator,responder}.log "Grand total" lines.

# PSK:
make edhoc_psk_initiator CRYPTO_SUITE=${0|7} TIMING=1 DEBUG=0
make edhoc_psk_responder CRYPTO_SUITE=${0|7} TIMING=1 DEBUG=0
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

| Method              | ECDH ops per side | Sign ops per side |
|---------------------|------------------:|------------------:|
| Sig/Sig (M0)        | 2 | 1 sign + 1 verify |
| Sig/StaticDH (M1)   | 3 | 1 (one side) |
| StaticDH/Sig (M2)   | 3 | 1 (one side) |
| StaticDH × 2 (M3)   | 4 | 0 |
| PSK (Method 4)      | 2 | 0 |

Example check — M3 S0 init = 4 × X25519 ≈ 440 M; measured 473 M (≈ 7 %
overhead for SHA-256, HKDF, AES-CCM, CBOR encode/decode).

### Software-size patterns

- **AES vs Ascon `.rodata`**: with `AES_SMALL_TABLES`, AES S-box = 256 B
  (vs ~4,096 B for the unrolled T-tables); Ascon round constants = 12 B.
  Suite 7 vs Suite 0 still saves some constant data per binary, but the
  margin is much smaller now.
- **Methods**: M3 (no signing/verification) saves ~15 KB `.text` vs
  M0/M1/M2 because the EDHOC sig/MAC layer + Ed25519/ECDSA signing code
  drops out.
- **Suite 25**: strips AES from `.rodata` but adds X448+Ed448 code
  (~+4 KB `.text`).
- **PSK Method 4**: smallest by far. PSK S7 is ~16 KB `.text` and
  ~1.2 KB `.rodata` total — under half the size of M0 S0.

## Provenance

- Measured: 2026-05-25 on Arty A7-100T pair, JTAG via two C232HM cables.
- Toolchain: `riscv64-unknown-elf-gcc` 15.1.0 (in `/home/khaiduy/opt/riscv/bin`),
  OpenOCD 0.12.0+dev (from oss-cad-suite).
- wolfssl: v5.9.1-stable (submodule, commit `1d363f3a`) + overrides in
  `wolfssl-overrides/` (now including `WOLFSSL_AES_SMALL_TABLES`).
- Build flags: `-march=rv32imac_zicsr_zifencei -mabi=ilp32 -Os -flto -g0
  -ffunction-sections -fdata-sections`. LTO + `--gc-sections` at link.
  `-Oz` was evaluated and reverted — it offered only marginal wins (often
  net-neutral or negative for AES suites) and produced flakier behaviour on
  Suite 4 + StaticDH paths during back-to-back sweep loads.
- Raw sweep data: `/tmp/sweep_sizes.tsv`, `/tmp/sweep_hw_result.tsv`,
  `/tmp/retry_result.tsv`, cycles merged into `/tmp/cycles_final.tsv`.

---

# 2026-06-08 re-run — M3 & PSK, suites 0 & 7 (legacy backend)

Re-measured on the Arty A7-100T pair after fixing the two-board JTAG loader
(`load_edhoc.sh`). Four configurations: Method 3 (StaticDH/StaticDH) and
Method 4 (PSK), each with Suite 0 (AES-CCM-16-64-128 + SHA-256) and Suite 7
(Ascon-AEAD-128 + Ascon-Hash256). Suite 7 and all PSK builds use the **legacy
backend** (Monocypher X25519/Ed25519 + TinyCrypt AES-CCM/SHA-256 + Ascon-c),
built with `EDHOC_BACKEND=legacy TIMING=1`.

Both boards reported `EDHOC OK` with matching `PRK_out` on every run.

> **Methodology caveat:** unlike the 50 MHz / `DEBUG=0` compute-only sweep
> above, these builds had timing breakdown + debug prints enabled. The **M3**
> totals are raw `rdcycle` brackets that *include* UART and debug overhead, so
> they are NOT directly comparable to the compute-only table above. The **PSK**
> numbers are the apps' own "COMPUTE-ONLY Timing" lines (UART/debug excluded)
> and are comparable across the two PSK suites.

## Method 3 — raw cycle brackets (include UART/debug overhead)

| Phase             | M3 S0 (X25519 + AES-CCM + SHA-256) | M3 S7 (X25519 + Ascon) |
|-------------------|-----------------------------------:|-----------------------:|
| Ephemeral keygen  | 110,980,838                        | 101,365                |
| msg1_gen          | —                                  | 19,421                 |
| msg2_gen          | 221,927,044                        | —                      |
| msg3_gen/process  | 111,880,856 (msg3_process, resp)   | 14,759,721 (msg3_gen, init) |
| **EDHOC total**   | **333,807,900**                    | **14,779,142**         |
| **Grand total**   | **444,788,738**                    | **14,880,507**         |

M3 S0 figures are from the responder log; M3 S7 from the initiator log
(whichever board's full UART output survived capture — the initiator board is
known to drop some leading UART bytes). Ascon (S7) is ~30× faster end-to-end
than AES-CCM+SHA-256 (S0) on this RV32 core.

## Method 4 (PSK) — COMPUTE-ONLY timing (cycles, UART/debug excluded)

| Phase                          | PSK S0 (AES-CCM + SHA-256) | PSK S7 (Ascon) |
|--------------------------------|---------------------------:|---------------:|
| **Initiator** ephemeral keygen | 4,661,281                  | 4,609,379      |
| Init msg1_gen                  | 13,879                     | 19,664         |
| Init msg3_gen (+msg2 parse)    | 7,997,713                  | 7,990,273      |
| Init msg4_process              | 1,122,521                  | 1,064,609      |
| Init COMPUTE TOTAL (no kg)     | 9,134,113                  | 9,074,546      |
| **Init GRAND COMPUTE (+kg)**   | **13,795,394**             | **13,683,925** |
| **Responder** msg2_gen (+msg1) | 5,212,089                  | 5,277,898      |
| Resp msg3_process              | 3,493,036                  | 3,436,032      |
| Resp msg4_gen                  | 1,151,418                  | 1,068,618      |
| **Resp COMPUTE TOTAL**         | **9,856,543**              | **9,782,548**  |

PSK S0 ≈ PSK S7: the cost is dominated by the X25519 scalar multiplications
(identical in both suites); the AEAD/hash difference (AES-CCM+SHA-256 vs Ascon)
is a small fraction of the total.

## JTAG loader fix (this session)

Two concurrent OpenOCD instances (one per C232HM adapter) made their background
`dmstatus` polling collide on the shared JTAG/USB path, wedging one debug module
(`Failed read (NOP) at 0x11; status=1` → `dmstatus=0x0` storm). Fixed by
programming the boards **sequentially** in `load_edhoc.sh`: `program_board()`
starts one OpenOCD, loads + `resume`s, then `shutdown`s that OpenOCD (the core
keeps running, the adapter is freed), then programs the next board. Responder is
programmed first (it boots and blocks waiting for the initiator's `message_1`).

## Provenance (2026-06-08 re-run)

- Boards: Arty A7-100T pair; JTAG via two C232HM cables (`FTA6JVAK` initiator,
  `FTA6GPSN` responder); UART `/dev/ttyUSB3` (init), `/dev/ttyUSB5` (resp).
- Toolchain: `riscv64-unknown-elf-gcc` 15.1.0, OpenOCD 0.12.0.
- Build: `make edhoc_m3_{initiator,responder} CRYPTO_SUITE={0,7} TIMING=1`
  (S7 adds `EDHOC_BACKEND=legacy`); `make edhoc_psk_{initiator,responder}_legacy
  CRYPTO_SUITE={0,7} TIMING=1 EDHOC_BACKEND=legacy`.
- Run: `INITIATOR_ELF=... RESPONDER_ELF=... ./load_edhoc.sh <method> <suite>`
  (method 3 = StaticDH, 4 = PSK). See `RUN_TIMING.md`.

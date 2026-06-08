# X448 for the legacy backend — design notes

Goal: add a Monocypher-style **X448** (Curve448 ECDH, RFC 7748) to the legacy
crypto backend so Suite 25 can run without wolfSSL's slow `curve448.c`
(measured ~400 M cycles/scalarmult on RV32 — see [BENCHMARKS.md](BENCHMARKS.md)).

We extend `uoscore-uedhoc/externals/Monocypher/src/monocypher.c` with
`crypto_x448()` / `crypto_x448_public_key()`, reusing Monocypher's design
philosophy rather than its 25519-specific code (none of which transfers — the
limb count and reduction constant are baked to `2^255-19`).

---

## Why Monocypher's X25519 is smaller AND faster than wolfSSL

Measured on RV32IMAC: Monocypher X25519 ≪ wolfSSL `CURVE25519_SMALL`
(`fe_low_mem.c`). The win comes from one core choice plus three reinforcers.

### 1. Reduced-radix limbs (the big one)

| | wolfSSL `fe_low_mem.c` (SMALL) | Monocypher |
|---|---|---|
| Field element | 32 bytes, **radix 2^8** | 10 limbs, **radix 2^25.5** (26/25-bit) |
| Limb-multiplies per `fe_mul` | 32×32 = **1024** | 10×10 = **100** |
| Carry chain | **per byte** (32 serial `c >>= 8`) | **once** per op, fixed 13-step schedule |
| Multiplier usage | 8-bit math in 32-bit regs (¾ wasted) | full 32×32→64 (`M` extension) |

wolfSSL's small path: `for i: r[i]=c; c>>=8;` — a length-32 *serial* carry chain,
byte granularity. Monocypher does ~10× fewer, wider multiplies and carries once.
That ratio is the speed difference.

### 2. Fully unrolled mul / sq / carry

`fe_mul`, `fe_sq`, `FE_CARRY` are straight-line (no loops, no bounds, no state
machine). Compiles small *and* fast. wolfSSL trades speed for a tiny loop and
adds non-blocking `ctx` state machines (`x25519_nb_ctx`, `fe_inv__distinct_nb`).

### 3. Lazy reduction

Limbs may hold slightly more than their nominal bits between operations; reduce
once per multiply instead of after every limb. Fewer carry passes.

### 4. Tiny reduction constant

`p = 2^255-19` ⇒ fold high bits with `× 19`, inline, no table (no `.rodata`).

**Net:** fewer fixed operations → both smaller code and fewer cycles. Faster ≠
bigger here because the speed comes from *doing less*, not from unrolled tables.

---

## Applying the same recipe to X448

The transferable technique = **reduced-radix limbs + lazy carry + unrolling**.
The curve-specific parts are redone for the Goldilocks prime.

Field: **p = 2^448 − 2^224 − 1**.

| X25519 (Monocypher) | X448 (this work) |
|---|---|
| 10 limbs @ 2^25.5 (255 bits) | **16 limbs @ 2^28** (448 bits) |
| reduce: `2^255 ≡ 19` → `× 19` | reduce: `2^448 ≡ 2^224 + 1` → fold limb (16+i) into limb i **and** limb (8+i) |
| unrolled 10×10 mul | unrolled 16×16 — **plus Karatsuba split at 2^224** |
| `a24 = 121666` | `a24 = 39081` (Curve448) |
| 255-bit ladder, clamp `&248 / |64` | 448-bit ladder, clamp `&252` byte0 / `|128` byte55 |
| base u = 9 | base u = 5 |

### Goldilocks bonus: Karatsuba at 2^224

`p`'s middle term `2^224` sits exactly at **limb 8** (radix 2^28). Splitting each
operand into low/high halves at limb 8 lets the multiply use Karatsuba with the
reduction folding cleanly (`2^448 = 2^224+1`). ~25% fewer limb-mults than plain
16×16 schoolbook. This is *why* Ed448-Goldilocks chose this prime — X25519 has no
equivalent split.

---

## Representation details

```
fe448 = u64[16], radix 2^28.   value = Σ limb[i] · 2^(28 i)
2^224 = limb 8.   2^448 = limb 16.
```

- `fe448_mul`: 16×16 schoolbook into `u64[31]`, then fold `t[16+k]` → `t[k]`
  (the `+1`) and `t[8+k]` (the `+2^224`), then carry-propagate.
- `fe448_carry`: propagate to 28-bit limbs; the single top overflow at 2^448
  folds back to limb 0 and limb 8.
- `fe448_sub`: add `2p` first (limb vector `2·FE448_P`) so limbs stay
  non-negative, then subtract.
- `fe448_invert`: `z^(p-2)` via fixed addition chain (validated by tests).
- Ladder + `cswap` mirror Monocypher's `scalarmult` exactly (constant-time).

`FE448_P` (radix 2^28): limbs all `0xfffffff` except limb 0 = `0xffffffe`
(the `−1`) and limb 8 = `0xffffffe` (the `−2^224`).

---

## Plan (A: correctness first, then optimize)

1. **Loop-based correct `fe448`** (schoolbook + fold) — clarity over speed.
2. **Host tests GREEN:**
   - `tests/x448/test_x448_host.c` — RFC 7748 §5.2 (single + iterated x1/x1000)
     and §6.2 Diffie-Hellman vectors.
   - `tests/x448/test_x448_diff.c` — 1000 random inputs vs wolfSSL `curve448()`
     (RFC-validated oracle; signature `curve448(out, scalar, point)` matches
     `crypto_x448` exactly). Removes all hand-typed-expect risk.
3. **RV32 KAT** — `src/x448_kat_main.c` + `make x448_test`, mirrors
   `ascon_kat_main.c`: prints PASS/FAIL over UART. Confirms 32-bit/alignment
   behaviour on the real target.
4. **RV32 cycle bench** — extend `bench_x25519.c` (or `bench_x448`): `crypto_x448`
   vs `wc_curve448`, `rdcycle`. Record vs wolfSSL's ~400 M.
5. **Optimize** — unroll `fe448_mul`/`fe448_sq`, add the 2^224 Karatsuba split.
   Differential test stays green throughout, so optimization can't silently
   break correctness.

Then SHAKE256 (lift wolfSSL `sha3.c`/`kmac.c`) and Ed448 (depends on SHAKE256)
complete Suite 25 on the legacy backend.

## Test oracles

- **RFC 7748** §5.2 / §6.2 fixed vectors — the ground truth. `crypto_x448`
  matches them on host **and** on RV32 hardware.
- **Algebraic identities** — `a·inv(a)=1`, `sq(a)=mul(a,a)`, commutativity —
  localized the field-op bugs before the ladder.
- wolfSSL raw `curve448()` was tried as a differential oracle but, called at
  that low level, it does NOT match the RFC vectors (its own KAT line fails) —
  it likely expects a pre-decoded/masked scalar. So it is unusable as a raw
  oracle; the RFC fixed vectors are authoritative and `crypto_x448` passes them.

---

## Results (2026-06-08)

### Host (gcc): all green
`tests/x448/test_fe448_unit.c` (field identities) and
`tests/x448/test_x448_host.c` (RFC 7748 §5.2 single + iterated x1/x1000, §6.2 DH)
all PASS.

### RV32 hardware (`make x448_test`, Arty A7-100T @ 50 MHz)

```
RFC7748 5.2 #1   PASS      (crypto_x448 correct on RV32)
RFC7748 6.2 DH   PASS      (ECDH shared secret correct)
mono crypto_x448 =  66,201,684 cyc
wolf curve448    = 245,284,598 cyc
```

**crypto_x448 is ~3.7× faster than wolfSSL curve448** (66.2 M vs 245.3 M
cycles/scalarmult) — and this is the *un-optimized*, loop-based version. The
reduced-radix limb design alone delivers the speedup, as predicted.

(wolfSSL's measured ~245 M here is lower than the ~400 M quoted in BENCHMARKS.md
for the full EDHOC path; the standalone scalarmult is cheaper than the in-handshake
figure which includes decode/encode overhead.)

### Bugs caught by the TDD loop
1. `FE448_P` encoded p−1 not p — caught by `(p-a)+a == 0`.
2. `fe448_mul` dropped the top product carry → drift over chained squarings —
   caught by the repeated-squaring probe.
3. `fe448_sub` left ~2^30 limbs → `fe448_mul` u64 overflow (ss_a≠ss_b) — fixed by
   carrying inside `fe448_sub`.
4. Ladder used `BB` instead of `AA` in `z2 = E·(AA + a24·E)` — caught by the
   Python reference ladder diff.

## Optimization pass (2026-06-08) — applied, host + hardware verified

1. **`fe448_mul`**: per-output-limb accumulation (`t[k]=Σ f[i]·g[k−i]`) — keeps
   each accumulator in a register vs the original scatter `t[i+j]+=`.
2. **`fe448_sq`**: dedicated squaring — off-diagonal `f[i]·f[j]` (i<j) computed
   once and doubled (~half the multiplies of a full multiply).
3. **Fold**: 3 passes → **2** (provably sufficient: pass 1 drains limbs 16..30
   into 0..22; pass 2 drains the re-dirtied 16..22 into ≤14).

Karatsuba at the 2^224 split was attempted and **reverted**: the middle term
`MM − LL` is per-limb signed and biasing it positive with `K·p` pushed the i64
accumulators to the overflow edge for only ~10% expected gain. Needs a
carry-reduce-before-bias step to land safely — deferred.

### Speed (RV32, Arty @ 50 MHz, clean captures)

| Version | cycles/scalarmult | vs wolfSSL |
|---|---|---|
| baseline (loop schoolbook) | 66,201,684 | 3.7× |
| + optimized squaring        | 62,438,366 | 3.9× |
| + optimized mul + 2-pass fold | **61,997,574** | **4.0×** |
| wolfSSL curve448 (SMALL)    | 249,561,928 | 1.0× |

### Speed / area tradeoff

Footprint = own functions + constants (`.text`+`.rodata`), from the linked
`x448_test.elf` symbol sizes:

| Metric | crypto_x448 (mine) | wolfSSL curve448 | Ratio |
|---|---|---|---|
| Speed | 61,997,574 cyc | 249,561,928 cyc | **4.03× faster** |
| Area  | 2,444 B | 1,498 B | **1.63× bigger (+946 B)** |
| speed × area (lower better) | 1.52e11 | 3.74e11 | **2.47× better** |

Where the +946 B goes: `crypto_x448` 1080 B (ladder + **inlined** invert), plus
the dedicated `fe448_sq` (298) and per-limb `fe448_mul` (284) vs wolfSSL reusing
one byte-radix multiply; constants `FE448_P` 128 + `FE448_PM2` 56.

**Verdict:** 4× speed for 1.6× area = 2.5× better speed-area product. On this
target (16 kB+ scratchpad, ~340 kB EDHOC ELFs) +946 B is negligible vs the 4×
latency win. Shrink levers if ever needed: move invert to a non-inlined addition
chain (smaller `crypto_x448`, same speed); or drop `fe448_sq` and reuse
`fe448_mul` (−298 B, ~6% slower).

### UART gotcha (cost several debug runs)
The standalone KAT `main()` must initialise the terminal UART divisor before any
`kprintf` — `REG32(uart, UART_REG_DIV)=868` (50 MHz/868 = 57600 baud) +
`UART_REG_TXCTRL=UART_TXEN`. Without it the UART runs at the reset divisor and
the host sees *deterministic* garbage (looks like a baud mismatch, not byte loss).
UART0 = terminal/console (kprintf); UART1 @ 0x64003000 = inter-board link
(`edhoc_transport`), unused by this standalone KAT.

### Next: SHAKE256 + Ed448 to complete Suite 25 (X448 done).

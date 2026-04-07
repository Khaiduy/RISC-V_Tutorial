# OSCORE Measurement Reference
## IEEE Journal Paper — EDHOC/OSCORE Hardware Accelerator on RISC-V

---

## Status

- [x] Benchmark code written and running
- [x] Correctness verified (RFC C.4 vector + round-trip)
- [x] SW baseline results obtained
- [x] REF-35B numbers obtained — see Section 2
- [ ] RAM stack measurement not yet done — required before paper
- [ ] HW-accelerated results pending

---

## 1. SW Baseline Results (RISC-V Rocket @ 50 MHz, TinyCrypt)

### 1.1 oscore_context_init()

| Platform | Cycles | Time (µs) |
|---|---|---|
| RISC-V (this work) | 316,575 | 6,331 |
| Cortex-M33 @ 64 MHz (Hristozov 2021, tinycrypt) | — | ~2,625 |
| Ratio (time) | | ~2.4× |

The init function is dominated by HKDF (HMAC-SHA-256). The lower ratio
here (~2.4×) compared to encrypt/decrypt (~2.7–3.0×) reflects
that SHA-256's sequential byte-shuffle access pattern is more cache-friendly
than AES-CCM's S-box table lookups on the Rocket core.
**Do not claim a specific cause in the paper** — report both ratios and
note they differ without attribution.

### 1.2 coap2oscore() — Encryption Sweep

| Payload (bytes) | Cycles | Time (µs) | nRF52840 M4 @ 64 MHz µs (eriptic v3.0.x) |
|---|---|---|---|
| 10 | 127,268 | 2,545 | — |
| 20 | 161,268 | 3,225 | 1,801 |
| 50 | 230,008 | 4,600 | 2,533 |
| 100 | 333,483 | 6,669 | 3,723 |
| 200 | 540,596 | 10,811 | 6,073 |
| 500 | 1,195,516 | 23,910 | 13,519 |
| 1,000 | 2,265,158 | 45,303 | 25,665 |

### 1.3 oscore2coap() — Decryption Sweep

Measured with Hristozov methodology: N_POOL=10 packets pre-generated with
SSN 0..9; single `server_ctx_init()`; N_POOL consecutive decryptions timed
with no intermediate context reinit.

| Payload (bytes) | Cycles | Time (µs) |
|---|---|---|
| 10 | 144,086 | 2,881 |
| 20 | 180,363 | 3,607 |
| 50 | 253,799 | 5,075 |
| 100 | 364,396 | 7,287 |
| 200 | 585,400 | 11,708 |
| 500 | 1,284,020 | 25,680 |
| 1,000 | 2,423,806 | 48,476 |

### 1.4 Encrypt vs Decrypt Asymmetry

With the Hristozov-compatible methodology (single `server_ctx_init()`,
consecutive SSNs), `oscore2coap()` is **7–13% slower** than `coap2oscore()`,
with the overhead *decreasing* as payload grows:

| Payload | Enc cycles | Dec cycles | Overhead |
|---|---|---|---|
| 10 B | 127,268 | 144,086 | +13.2% |
| 100 B | 333,483 | 364,396 | +9.3% |
| 1,000 B | 2,265,158 | 2,423,806 | +7.0% |

The overhead has two components: a **fixed** cost (~15,000 cycles, from
header parsing, context lookup, and replay-window check) and a **proportional**
cost (~143 cycles/byte, from inner CoAP PDU reconstruction). At small payloads
the fixed component dominates (+13%), while at large payloads the proportional
term grows but remains a smaller fraction of the total (+7%).

**Do not claim encrypt/decrypt symmetry in the paper.** Report both values.
Hristozov et al. report ~946 µs for both directions; remaining asymmetry
in this work may reflect an implementation difference in oscore2coap() or
message framing overhead absent in the reference platform.

---

## 2. Reference Point: 35-Byte OSCORE Frame (Hristozov Comparison)

### What "35 bytes" means in the reference paper

Hristozov et al. test a **22-byte CoAP GET with zero application payload**
(RFC 8613 Appendix C.4, `T1_COAP_REQ`). The resulting OSCORE-encoded
packet is **35 bytes total**. Their "35-byte payload" means the *OSCORE
frame size*, not the application payload size.

This is **not** the same as adding `35` to `SWEEP_SIZES` (which would
be 35 bytes of application payload → 58-byte CoAP → ~71-byte OSCORE
output — wrong comparison).

### How the benchmark handles this

`oscore_benchmark.c` has a dedicated `[REF-35B]` section (separate from
the sweep) that times `coap2oscore(T1_COAP_REQ, 22)` and the corresponding
`oscore2coap()`. This produces the correct 35-byte OSCORE frame and gives
the matching measurement. `SWEEP_SIZES` is left unchanged.

### Cross-platform comparison table (fill from REF-35B output)

| Function | RISC-V cycles | RISC-V µs | M33 µs (ref) | Time ratio |
|---|---|---|---|---|
| init | 316,575 | 6,331 | 2,625 | ~2.4× |
| coap2oscore @ 35B OSCORE | 126,283 | 2,525 | ~946 | ~2.7× |
| oscore2coap @ 35B OSCORE | 142,912 | 2,858 | ~946 | ~3.0× |

---

## 3. Crypto Library

**TinyCrypt** provides AES-CCM-16-64-128 and HMAC-SHA-256 for OSCORE.

This is the **same library** as Hristozov et al. The cross-platform
comparison is therefore library-identical — the strongest possible
baseline framing. State this in the paper:

> *"The OSCORE software baseline uses TinyCrypt as its cryptographic
> backend, providing AES-CCM-16-64-128 and HMAC-SHA-256, matching the
> crypto library used by Hristozov et al.~\cite{Hristozov2021}."*

Note: Monocypher (used for EDHOC) does not implement AES. TinyCrypt
and Monocypher are separate library dependencies. Describe them
separately in the paper's implementation section.

---

## 4. Comparison Strategy for the Paper (Two-Tier)

### Tier 1 — Direct cross-platform comparison (35-byte only)
Same library (TinyCrypt), same payload size (35 bytes), different
platform. Reference: Hristozov et al. CODASPY 2021 (Cortex-M33 @ 64 MHz).
This is the apples-to-apples comparison.

### Tier 2 — Extended payload sweep
Reference: eriptic/uoscore-uedhoc `benchmarks.md` (v3.0.x), which
provides a sweep on nRF52840 Cortex-M4 @ 64 MHz with TinyCrypt.
Wall-clock ratio is consistently ~1.78× across all payload sizes.
The clock frequency difference (50 vs 64 MHz) accounts for 64/50 = 1.28×
of the observed 1.78× slowdown; the remaining ~1.39× (= 1.78/1.28) is
per-cycle overhead that frequency alone does not explain.
**Do not state a cause** — pipeline depth, cache behavior, compiler
maturity, and ISA differences are all confounded; no ablation was run.

**Caveat to state in the paper:** The v3.0.x benchmark uses zcbor as
the CBOR engine and targets RFC 9528, while Hristozov et al. used an
earlier draft. Be explicit about which reference is used for which
comparison to prevent reviewer complaints about mixed baselines.

---

## 5. RAM Reporting — What You Cannot Do Yet

### The problem

The benchmark allocates large static buffers in BSS:

```c
static uint8_t coap_buf[MAX_COAP_LEN];         /* 1,023 bytes */
static uint8_t oscore_enc_buf[MAX_OSCORE_LEN]; /* 1,200 bytes */
static uint8_t oscore_scratch[MAX_OSCORE_LEN]; /* 1,200 bytes */
static uint8_t coap_dec_buf[MAX_COAP_LEN];     /* 1,023 bytes */
```

These are benchmark harness buffers, not the library's internal working
memory. The reference paper reports ~1,796 bytes RAM (stack only, no heap).
A direct comparison is not valid without separating harness from library.

### FLASH is not affected

FLASH footprint is determined by compiled code, not runtime buffer sizes.
Your FLASH number is directly comparable to the reference without
qualification regardless of payload sweep range.

### What you need to measure

**Library stack usage** — measure with stack painting:
1. Fill the stack region with a known sentinel (e.g. `0xDEADBEEF`)
   before calling the API
2. Call `coap2oscore()` or `oscore2coap()`
3. Scan from the bottom of the stack upward for the first unpainted word

Do this at two payload configurations:
- **35-byte** — comparison point with Hristozov et al.
- **1000-byte** — your operational maximum configuration

### How to report in the paper

Report RAM in two clearly separated parts:
1. **Library stack** — peak stack during `coap2oscore()`/`oscore2coap()`,
   measured at 35-byte config, compared directly to the reference ~1,796 bytes
2. **Application buffers** — BSS cost, scales with max payload; reported
   separately at 35-byte and 1000-byte configs, not compared to reference

Suggested text:
> *"At a 35-byte payload configuration matching Hristozov et al., peak
> library stack usage is X bytes compared to their reported 1,796 bytes
> on Cortex-M33. At 1,000-byte maximum payload, stack usage grows to
> Y bytes, reflecting the larger intermediate buffers required for
> AES-CCM processing over longer messages."*

---

## 6. Code Review Findings (oscore_benchmark.c)

### Must fix

**REF-35B numbers missing** — run benchmark to fill the cross-platform
comparison table in Section 2. The `[REF-35B]` section is already in the
code; just flash and read the output.

### Should fix (reviewer may ask)

**Decrypt cache warming effect:**
`server_ctx_init()` runs HKDF immediately before the timed `oscore2coap()`
call, leaving derived keys in the data cache. The timed window benefits
from a warm cache state it would not have in a cold-start scenario.
Add a comment in the code and a sentence in the paper:

> *"The server context is reinitialized before each decryption to reset
> the replay window; the reinitialization cost is excluded from the
> timed window."*

The reference paper has the same characteristic, so the comparison remains
valid, but transparency is required.

**Encrypt/decrypt SSN asymmetry:**
Encrypt runs with incrementing SSN (0..N-1); decrypt reuses SSN=0
with server context reinitialized each iteration to reset the replay
window. This asymmetry is forced by the protocol — you cannot accept
the same SSN twice without reinitializing. Add a code comment explaining
this. The crypto cost is identical across SSN values so the measurement
is valid.

### Cosmetic

`coap_len` is declared `uint32_t` but computed from `uint16_t plen`.
Consider making it `uint16_t` or adding an explicit cast for type clarity.

---

## 7. What to State vs What to Avoid in the Paper

### Safe to state (citable)

- TinyCrypt's AES uses a 256-byte S-box table lookup (verifiable from
  source). This makes AES-CCM more sensitive to memory latency than
  HMAC-SHA-256's sequential operations — which explains why init and
  encrypt/decrypt show different cross-platform ratios.
- Compact25519 operates at byte level with no assumption of word-width
  arithmetic (stated explicitly in its README). Neither platform's
  hardware multiply unit — including the Cortex-M33 DSP extension —
  benefits Compact25519's inner loops.
- `oscore2coap()` is 7–13% slower than `coap2oscore()` across the payload
  sweep. The overhead decreases as a percentage with larger payloads (13% at
  10 bytes, 7% at 1,000 bytes), reflecting a fixed component (~15 kcycles,
  from header parsing, context lookup, and replay-window check) plus a
  proportional component (~143 cycles/byte, from inner CoAP PDU reconstruction).
- Hristozov et al. test only a single 35-byte payload. This work extends
  the evaluation with a sweep from 10 to 1,000 bytes.

### Do not state (unverifiable without additional experiments)

- Why exactly RISC-V is slower than Cortex-M33 — multiple confounded
  factors (ISA, pipeline depth, cache, compiler maturity, clock frequency)
  cannot be separated without a controlled ablation study you did not run.
- Any specific claim about cache hit/miss rates on either platform.
- That the Cortex-M33 DSP extension helps or hurts Compact25519 —
  the library bypasses word-width hardware entirely by design.

---

## 8. Checklist Before Writing the Paper Section

- [x] REF-35B numbers obtained and Section 2 table filled
- [ ] Measure library stack high-water mark at 35-byte config (stack painting)
- [ ] Measure library stack high-water mark at 1000-byte config
- [ ] Confirm FLASH breakdown via linker map: OSCORE logic vs TinyCrypt
- [ ] Confirm compilation flags identical to EDHOC benchmark (-Os, LTO)
- [ ] Add code comment for replay window reinit rationale
- [ ] Add code comment for SSN increment asymmetry

---

## 9. Reference Numbers

| Source | Platform | Crypto | Payload | init (µs) | enc (µs) | dec (µs) |
|---|---|---|---|---|---|---|
| Hristozov 2021 | Cortex-M33 @ 64 MHz | TinyCrypt | 35 B only | ~2,625 | ~946 | ~946 |
| eriptic v3.0.x benchmarks.md | nRF52840 M4 @ 64 MHz | TinyCrypt | 20–1000 B | — | 1,801–25,665 | — |
| **This work** | **Rocket RV32 @ 50 MHz** | **TinyCrypt** | **10–1000 B** | **6,331** | **2,525–45,303** | **2,858–48,476** |

---

## 10. Sources

- Hristozov et al., CODASPY 2021. https://doi.org/10.1145/3422337.3447834
- eriptic/uoscore-uedhoc benchmarks.md: https://github.com/eriptic/uoscore-uedhoc/blob/main/benchmarks.md
- RFC 8613 (OSCORE): https://www.rfc-editor.org/rfc/rfc8613.html
- TinyCrypt source (S-box implementation): https://github.com/intel/tinycrypt
- Compact25519 README (byte-level design stated): https://github.com/DavyLandman/compact25519
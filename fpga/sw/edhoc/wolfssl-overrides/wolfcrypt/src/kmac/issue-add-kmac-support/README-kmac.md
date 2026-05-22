# Add KMAC-SHA3 (NIST SP 800-185) to wolfCrypt

## Feature

Adds **KMAC** — the Keccak Message Authentication Code defined in
NIST SP 800-185 §4 — as a new wolfCrypt primitive. Supported variants:

| Variant   | Underlying XOF | Rate (bytes) |
|-----------|----------------|--------------|
| KMAC128   | SHAKE128       | 168          |
| KMAC256   | SHAKE256       | 136          |

Both **fixed-output mode** (the MAC mode of NIST KMAC) and **XOF mode**
(variable-length output) are implemented. Output length is supplied at
finalization time, so the same context can produce any digest size the
caller asks for.

The implementation lives in two new files and a small extension of the
existing SHA-3 code:

- `wolfssl/wolfcrypt/kmac.h` — public header
- `wolfcrypt/src/kmac.c`     — implementation
- `wolfcrypt/src/sha3.c`     — adds `wc_Sha3_cSHAKE128_Final` /
                              `wc_Sha3_cSHAKE256_Final`, internal
                              cSHAKE finalize helpers (domain byte
                              `0x04` instead of SHAKE's `0x1F`)

KMAC is built on cSHAKE; cSHAKE itself is **not** exposed as a public
API in this drop. If a downstream caller needs cSHAKE directly, the
internal helpers can be promoted later without touching KMAC.

## Specs Coded Against

- **NIST SP 800-185** "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash,
  and ParallelHash" (December 2016) — §2 (encoding helpers), §3 (cSHAKE),
  §4 (KMAC). This is the primary specification.
- **NIST FIPS 202** "SHA-3 Standard" — for the underlying SHAKE128 /
  SHAKE256 XOFs and Keccak-p[1600,24] permutation. (wolfCrypt's existing
  SHAKE implementation is reused unchanged.)

The encoding primitives `left_encode`, `right_encode`, `encode_string`,
and `bytepad` were re-implemented from the SP 800-185 text — not copied
from any existing implementation. OpenSSL 4.0.0
(`providers/implementations/macs/kmac_prov.c`,
`crypto/sha/sha3_encode.c`) was consulted only for structural reference
and as a cross-check source of NIST test vectors. Its source is
Apache-2.0 licensed, which is incompatible with verbatim inclusion in
wolfSSL (GPLv2 / commercial dual), so a clean-room implementation was
required.

## Algorithm summary

For `KMAC{128,256}(K, X, L, S)`:

```
newX = bytepad(encode_string(K), rate)  ||  X  ||  right_encode(L_in_bits)
T    = bytepad(encode_string("KMAC") || encode_string(S), rate)
return cSHAKE{128,256}_inner(T || newX, L)
```

In XOF mode, `right_encode(L_in_bits)` is replaced by `right_encode(0)`
— this is what tells the verifier that the output is variable-length
rather than tied to a specific tag size.

`cSHAKE{128,256}_inner` is identical to `SHAKE{128,256}` except for the
domain-separation byte: `0x04` instead of `0x1F`. The new
`wc_Sha3_cSHAKE{128,256}_Final` helpers in `sha3.c` provide that
single-byte difference; everything else (Keccak permutation, padding,
absorbing) is reused.

## Public API

```c
#include <wolfssl/wolfcrypt/kmac.h>

typedef enum KmacType {
    WC_KMAC_128 = 1,
    WC_KMAC_256 = 2
} KmacType;

typedef struct Kmac Kmac;

int wc_InitKmac(Kmac* kmac, int type,
                const byte* key,    word32 keyLen,
                const byte* custom, word32 customLen,
                void* heap, int devId);

int wc_KmacSetXof(Kmac* kmac, int xof);   /* call before first Update */

int wc_KmacUpdate(Kmac* kmac, const byte* in, word32 inSz);

int wc_KmacFinal(Kmac* kmac, byte* out, word32 outSz);

int wc_KmacFree(Kmac* kmac);
```

### Notes

- `customLen` may be 0 (and `custom` may be `NULL`) — that produces a
  bare KMAC with the empty customization string `S = ""`.
- `keyLen` may be 0 in principle, though it produces a degenerate MAC
  not useful for authentication.
- `outSz` for `wc_KmacFinal` is the number of bytes written and (in
  fixed-output mode) becomes part of the MAC computation via
  `right_encode`. **Changing the requested output size changes the
  MAC**: a KMAC tagged at 32 bytes is *not* a prefix of the same
  KMAC tagged at 64 bytes. This is by design (SP 800-185 §4.3) — it
  is what makes KMAC tag-length-agnostic without ambiguity.
- `wc_KmacSetXof` must be called before the first `wc_KmacUpdate`. In
  XOF mode the same caveat does **not** apply: any output length is a
  prefix of any longer output of the same context.
- A single context is for one MAC computation: after `wc_KmacFinal`,
  further `Update`/`Final` calls return `BAD_STATE_E`. Call
  `wc_KmacFree` then `wc_InitKmac` again to compute another tag.
- No streaming-XOF (`Squeeze`) API is exposed in this drop — call
  `wc_KmacFinal` once with the total output length you need. (OpenSSL's
  EVP_MAC API has the same limitation.)

### Example

```c
Kmac kmac;
byte key[32]    = { /* ... */ };
byte data[]     = { 0x00, 0x01, 0x02, 0x03 };
byte custom[]   = "My Tagged Application";
byte tag[32];

if (wc_InitKmac(&kmac, WC_KMAC_128,
                key, sizeof(key),
                custom, sizeof(custom) - 1,   /* drop NUL terminator */
                NULL, INVALID_DEVID) != 0)    goto err;
if (wc_KmacUpdate(&kmac, data, sizeof(data)) != 0)  goto err;
if (wc_KmacFinal(&kmac, tag, sizeof(tag))   != 0)   goto err;
wc_KmacFree(&kmac);
```

## Configuration

KMAC is **disabled by default**. To enable it:

```sh
./configure --enable-sha3 --enable-shake128 --enable-shake256 --enable-kmac
```

Required dependencies (configure will error out if these are missing):

- `--enable-sha3` (or any config that defines `WOLFSSL_SHA3`)
- At least one of `--enable-shake128` / `--enable-shake256`
  (defining `WOLFSSL_SHAKE128` / `WOLFSSL_SHAKE256`)

### FIPS

KMAC is gated off for FIPS builds older than v6 (matching the existing
SHAKE128/256 gating, since both rely on the same XOFs). On FIPS v6+ and
non-FIPS builds, `--enable-kmac` works.

This drop is **non-FIPS only** — KMAC is not currently part of any
wolfCrypt FIPS module bundle. The plumbing is structured so that adding
FIPS support later is a matter of including `kmac.c` in the FIPS source
list rather than touching the algorithm.

### Build flag summary

| Flag                  | Effect                                                    |
|-----------------------|-----------------------------------------------------------|
| `WOLFSSL_KMAC`        | Compile and link `kmac.c`; expose KMAC public API.        |
| `WOLFSSL_SHA3`        | Required.                                                  |
| `WOLFSSL_SHAKE128`    | Required for `WC_KMAC_128`.                                |
| `WOLFSSL_SHAKE256`    | Required for `WC_KMAC_256`.                                |

If only one of SHAKE128 or SHAKE256 is enabled, the corresponding
`WC_KMAC_*` enum value is rejected at runtime by `wc_InitKmac`.

## Tests

A new `kmac_test()` is added to `wolfcrypt/test/test.c`, gated on
`WOLFSSL_KMAC`. Vectors:

| Case                           | Source                             |
|--------------------------------|------------------------------------|
| KMAC128, K(32B), X=`00010203`, S=`""`, L=32   | NIST SP 800-185 sample 1 |
| KMAC128, same with custom string              | NIST SP 800-185 sample 2 |
| KMAC128 XOF, custom string                    | NIST SP 800-185           |
| KMAC256, custom string, L=64                  | NIST SP 800-185 sample 4 |
| KMAC256 XOF, custom string                    | NIST SP 800-185           |

Plus:

- A split-`Update` test (input fed in two pieces) to confirm that
  streaming and one-shot produce identical output.
- Negative tests: `NULL` `Kmac*`, invalid `type`, `Update` after `Final`,
  `SetXof` after `Update`.

Running:

```sh
./wolfcrypt/test/testwolfcrypt
# ... look for: KMAC     test passed!
```

## Verification done

1. `--enable-kmac` build: clean compile, all wolfCrypt tests pass
   including the new `KMAC test passed!` line.
2. Default build (no `--enable-kmac`): clean compile, `kmac_test()`
   not invoked, no other regressions — confirms gating is correct.
3. Output bytes for every vector match NIST SP 800-185 expected values
   exactly.

## Files changed

| File                              | Change |
|-----------------------------------|--------|
| `configure.ac`                    | New `--enable-kmac` knob, FIPS<6 guard, `BUILD_KMAC` automake conditional, status-summary line. |
| `src/include.am`                  | `BUILD_KMAC` block adding `wolfcrypt/src/kmac.c` to non-FIPS sources. |
| `wolfcrypt/src/sha3.c`            | New `wc_Sha3_cSHAKE128_Final` and `wc_Sha3_cSHAKE256_Final` (gated on `WOLFSSL_KMAC`). |
| `wolfcrypt/src/kmac.c`            | **New.** SP 800-185 implementation. |
| `wolfcrypt/test/test.c`           | New `kmac_test()` and wire-up. |
| `wolfssl/wolfcrypt/include.am`    | `kmac.h` added to `nobase_include_HEADERS`. |
| `wolfssl/wolfcrypt/kmac.h`        | **New.** Public API. |
| `wolfssl/wolfcrypt/sha3.h`        | `WOLFSSL_LOCAL` declarations of the cSHAKE finals. |

## Patch

The full patch is in `kmac.patch` alongside this README. Apply with:

```sh
cd /path/to/wolfssl
git apply wolfssl-issues/issue-add-kmac-support/kmac.patch
```

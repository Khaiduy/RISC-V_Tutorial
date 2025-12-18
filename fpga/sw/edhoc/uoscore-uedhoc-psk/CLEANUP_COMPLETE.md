# PSK-Only Implementation Cleanup - COMPLETE ✅

## Summary

Successfully cleaned the PSK implementation by removing all Method 0-3 authentication code, keeping only PSK Mode (Method 4) functionality.

## Changes Made

### Core Files Modified

#### 1. `src/edhoc/initiator.c`
**Lines Removed**: ~75

**Changes**:
- Commented out `#include "edhoc/signature_or_mac_msg.h"`
- Simplified `msg2_process()` - removed MAC_2 verification, static DH logic
- Simplified `msg3_only_gen()` - removed MAC_3 generation
- Hardcoded PSK mode flags in `msg3_gen()`

**Before**: 471 lines (mixed Method 0-4)  
**After**: 396 lines (PSK-only)

#### 2. `src/edhoc/responder.c`
**Lines Removed**: ~130

**Changes**:
- Commented out `#include "edhoc/signature_or_mac_msg.h"`
- Hardcoded authentication type to PSK
- Removed static DH from PRK_3e2m derivation
- Removed MAC_2 generation block (~17 lines)
- Simplified ciphertext_gen call
- Removed MAC_3 verification block
- Simplified credential retrieval to PSK-only
- Removed non-PSK PRK_4e3m derivation
- Simplified TH_3/TH_4 to PSK-only formulas

**Before**: ~507 lines (mixed Method 0-4)  
**After**: ~377 lines (PSK-only)

### Files Already Optimized

#### 3. `src/edhoc/ciphertext.c`
**Status**: No changes needed

The file already has well-organized PSK branches:
- Two-layer encryption (lines 145-334 decrypt, 436-600 encrypt)
- Clear separation between PSK and non-PSK paths
- Non-PSK paths retained for CIPHERTEXT2/4 compatibility

#### 4. `src/edhoc/prk.c`
**Status**: No changes needed

Both functions are required:
- `prk_derive_psk()` - PSK-specific key derivation
- `prk_derive()` - Ephemeral DH (needed for PRK_2e/PRK_3e2m in PSK mode)

## Total Code Reduction

**Lines Removed**: ~205 lines of Method 0-3 code
- initiator.c: 75 lines
- responder.c: 130 lines

**Percentage**: ~15% reduction in core protocol files

## Build Verification

```bash
cd /home/khaiduy/Workspace/RISC-V_Tutorial/fpga/sw/edhoc/uoscore-uedhoc-psk
make clean && make
```

**Result**: ✅ Build successful with no errors

## Remaining PSK-Only Features

### Message 2
- PLAINTEXT_2A = (C_R, ?EAD_2)
- No ID_CRED_R, no MAC_2
- Encrypted with KEYSTREAM_2

### Message 3
- Two-layer encryption (XOR + AEAD)
- PLAINTEXT_3A = (ID_CRED_PSK compact, CIPHERTEXT_3B)
- CIPHERTEXT_3B uses external_aad = << ID_CRED_PSK, TH_3, CRED_I, CRED_R >>
- K_3/IV_3 from PRK_4e3m (derived from PSK)
- No MAC_3

### Key Derivation
- PRK_2e: From ephemeral G_XY
- PRK_3e2m: EDHOC_KDF(PRK_2e, SALT_3e2m, TH_2)
- SALT_4e3m: EDHOC_KDF(PRK_3e2m, label=5, TH_3)
- PRK_4e3m: EDHOC_Extract(SALT_4e3m, PSK)
- PRK_out: EDHOC_KDF(PRK_4e3m, label=7, TH_4)

### Transcript Hashes
- TH_2: H(TH_2 input)
- TH_3: H(TH_2, PLAINTEXT_2A) - PSK formula
- TH_4: H(TH_3, ID_CRED_PSK, PLAINTEXT_3B, CRED_I, CRED_R) - PSK formula

## Specification Compliance

- **RFC 9528**: EDHOC base protocol
- **draft-ietf-lake-edhoc-psk-06**: PSK extension
- **Method**: 4 (INITIATOR_PSK_RESPONDER_PSK)

## Testing Configuration

```c
/* PSK Configuration */
method = INITIATOR_PSK_RESPONDER_PSK;  // 4
uint8_t psk[16] = {0x01, ..., 0x10};
uint8_t id_cred_psk[] = {0xa1, 0x04, 0x41, 0x32};  // { 4 : h'32' }
```

## Directory Structure

```
/home/khaiduy/Workspace/RISC-V_Tutorial/fpga/sw/edhoc/
├── uoscore-uedhoc/      # ORIGINAL: Method 0-3 (29MB, no PSK)
└── uoscore-uedhoc-psk/  # PSK-ONLY: Method 4 cleaned (191MB)
```

## Next Steps

1. Test on FPGA (Arty A7-100T)
2. Verify Message 2/3 exchange
3. Measure performance improvements from code reduction
4. Document any behavioral changes

---

**Cleanup Date**: 2024
**Status**: ✅ COMPLETE - Build verified successful
**Approval**: Ready for testing

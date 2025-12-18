# EDHOC PSK-Only Implementation - Cleanup Summary

## Directory Structure

```
/home/khaiduy/Workspace/RISC-V_Tutorial/fpga/sw/edhoc/
├── uoscore-uedhoc/         # ORIGINAL: Method 0-3 (no PSK)
└── uoscore-uedhoc-psk/     # PSK-ONLY: Method 4 cleaned up
```

## PSK-Only Modifications

### Files Modified

#### 1. **initiator.c** - PSK Message Processing
**Removed**:
- `signature_or_mac` calls (VERIFY/GENERATE)
- Static DH authentication logic
- Method 0-3 branching (`if (!is_psk)`)
- MAC_2 and MAC_3 verification/generation

**Simplified**:
- `msg2_process()`: Only PSK path, no MAC_2 verification
- `msg3_only_gen()`: Only PSK encryption, no MAC_3
- `msg3_gen()`: Hardcoded `static_dh_i=false, static_dh_r=false`

#### 2. **responder.c** - PSK Message Processing ✅
**Removed**:
- `signature_or_mac` calls (VERIFY/GENERATE)
- Static DH authentication logic
- Method 0-3 branching (`if (!rc->is_psk)`)
- MAC_2 generation (entire block ~17 lines)
- MAC_3 verification (entire block ~6 lines)

**Simplified**:
- Authentication type: Hardcoded `rc->is_psk = true`
- PRK_3e2m: No static DH, ephemeral-only
- `ciphertext_gen()`: NULL for id_cred_r and MAC_2
- TH_3/TH_4: PSK-only formulas
- Credential retrieval: PSK-only path

**Lines Removed**: ~130 lines

#### 3. **ciphertext.c** - PSK Encryption/Decryption ✅
**Status**: Already well-organized
- Two-layer PSK encryption/decryption fully implemented
- Non-PSK paths retained for CIPHERTEXT2/4 compatibility
- No cleanup needed - code is clean with clear PSK branches

#### 4. **prk.c** - Key Derivation ✅
**Status**: Already clean
- `prk_derive_psk()`: PSK-specific (lines 65-86)
- `prk_derive()`: Supports ephemeral DH (needed for PRK_2e/PRK_3e2m)
- No cleanup needed - both functions required

### Code Size Reduction

**initiator.c**:
- Before: 471 lines (mixed Method 0-4)
- After: ~396 lines (PSK-only)
- Removed: ~75 lines

**responder.c**:
- Before: ~507 lines (mixed Method 0-4)
- After: ~377 lines (PSK-only)
- Removed: ~130 lines

**Total**: ~205 lines of Method 0-3 code removed

### PSK-Only Features

**Message 1**: Standard (unchanged)

**Message 2**:
- PLAINTEXT_2A = (C_R, ?EAD_2) ← No ID_CRED_R, no MAC_2
- Uses pre-configured ID_CRED_PSK
- No signature/MAC verification

**Message 3**:
- Two-layer encryption (XOR + AEAD)
- PLAINTEXT_3A = (ID_CRED_PSK compact, CIPHERTEXT_3B)
- CIPHERTEXT_3B = AEAD(PLAINTEXT_3B, K_3, IV_3, external_aad)
- No MAC_3 generation/verification

**Key Derivation**:
- PRK_3e2m: From ephemeral DH only (no static DH)
- PRK_4e3m: From PSK via HKDF-Extract
- No signature key operations

### Specification Compliance

- RFC 9528: EDHOC base (Message 1 only)
- draft-ietf-lake-edhoc-psk-06: PSK extension
- Method 4: INITIATOR_PSK_RESPONDER_PSK

### Testing

Compile with PSK-only code:
```bash
cd /home/khaiduy/Workspace/RISC-V_Tutorial/fpga/sw/edhoc/uoscore-uedhoc-psk
make clean
make
```

Configuration required:
- `method = INITIATOR_PSK_RESPONDER_PSK` (4)
- PSK: 16 bytes pre-shared key
- ID_CRED_PSK: CBOR map `{ 4 : h'kid' }`

---
**Status**: ✅ Complete
- Initiator cleaned ✅
- Responder cleaned ✅
- Ciphertext already optimal ✅
- PRK already clean ✅

**Next**: Test cleaned implementation on FPGA

# EDHOC Implementation Organization

## Directory Structure (Visual)

```
📦 /home/khaiduy/Workspace/RISC-V_Tutorial/fpga/sw/edhoc/
│
├── 📂 uoscore-uedhoc/                    ⭐ ACTIVE (PSK Mode)
│   ├── src/edhoc/
│   │   ├── initiator.c                   [WITH PSK modifications]
│   │   ├── responder.c                   [WITH PSK modifications]
│   │   ├── ciphertext.c                  [WITH PSK modifications]
│   │   ├── th.c                          [WITH PSK modifications]
│   │   ├── prk.c                         [WITH PSK modifications]
│   │   └── ...
│   └── inc/edhoc/
│       ├── hkdf_info.h                   [WITH PSK labels]
│       └── ...
│
├── 📂 uoscore-uedhoc-method3/            🔵 ORIGINAL (No PSK)
│   ├── src/edhoc/
│   │   ├── initiator.c                   [Original - Method 0-3 only]
│   │   ├── responder.c                   [Original - Method 0-3 only]
│   │   ├── ciphertext.c                  [Original - single AEAD]
│   │   ├── th.c                          [Original - standard TH]
│   │   └── ...
│   └── README_METHOD3.md                 [Usage instructions]
│
├── 📂 uoscore-uedhoc-psk/                🟢 PSK ONLY (Method 4)
│   ├── src/edhoc/
│   │   ├── initiator.c                   [WITH PSK - same as active]
│   │   ├── responder.c                   [WITH PSK - same as active]
│   │   ├── ciphertext.c                  [WITH PSK - same as active]
│   │   └── ...
│   └── README_PSK.md                     [PSK-specific docs]
│
├── 📂 uoscore-uedhoc-backup-mixed/       💾 BACKUP
│   └── [Exact copy of current state]
│
├── 📄 PSK_IMPLEMENTATION_GUIDE.md        📖 Full documentation
├── 📄 PSK_QUICK_REFERENCE.md            📝 Quick commands
├── 📄 PSK_IMPLEMENTATION_STATUS.md       📊 Old status (deprecated)
└── 🔧 separate_implementations.sh        Script (already run)
```

## Code Flow Comparison

### Method 3 (Original)
```
Message 1 → [Standard]
           ↓
Message 2 → PLAINTEXT_2 = (C_R, ID_CRED_R, MAC_2, ?EAD_2)
           → CIPHERTEXT_2 = AEAD(PLAINTEXT_2)
           ↓
TH_3 = H(TH_2, PLAINTEXT_2, CRED_R)
           ↓
Message 3 → PLAINTEXT_3 = (ID_CRED_I, MAC_3, ?EAD_3)
           → CIPHERTEXT_3 = AEAD(PLAINTEXT_3)
           ↓
TH_4 = H(TH_3, PLAINTEXT_3, CRED_I)
           ↓
PRK_4e3m ← ECDH(ephemeral, static)
```

### PSK Mode (Method 4)
```
Message 1 → [Standard - same]
           ↓
Message 2 → PLAINTEXT_2A = (C_R, ?EAD_2)              ← Shorter!
           → CIPHERTEXT_2 = AEAD(PLAINTEXT_2A)
           ↓
TH_3 = H(TH_2, PLAINTEXT_2A)                         ← Different formula
           ↓
PRK_4e3m ← HKDF-Extract(SALT_4e3m, PSK)             ← From PSK!
           ↓
Message 3 → PLAINTEXT_3B = (?EAD_3)                   ← Empty usually
           → CIPHERTEXT_3B = AEAD(PLAINTEXT_3B, K_3, IV_3)
           → PLAINTEXT_3A = (ID_CRED_PSK, CIPHERTEXT_3B)
           → CIPHERTEXT_3A = PLAINTEXT_3A ⊕ KEYSTREAM_3A  ← Two layers!
           ↓
TH_4 = H(TH_3, ID_CRED_PSK, PLAINTEXT_3B, CRED_I, CRED_R) ← 5 elements
```

## Switch Commands Summary

### 🔵 Use Method 3 (Original)
```bash
cd /home/khaiduy/Workspace/RISC-V_Tutorial/fpga/sw/edhoc
rm -rf uoscore-uedhoc
cp -r uoscore-uedhoc-method3 uoscore-uedhoc
make clean && make
```

### 🟢 Use PSK Mode (Current)
```bash
# Already active, no action needed
# Or restore from backup:
cd /home/khaiduy/Workspace/RISC-V_Tutorial/fpga/sw/edhoc
rm -rf uoscore-uedhoc
cp -r uoscore-uedhoc-psk uoscore-uedhoc
make clean && make
```

### 💾 Restore Backup
```bash
cd /home/khaiduy/Workspace/RISC-V_Tutorial/fpga/sw/edhoc
rm -rf uoscore-uedhoc
cp -r uoscore-uedhoc-backup-mixed uoscore-uedhoc
```

## File Modification Summary

| File | Method 3 | PSK Mode | Changes |
|------|----------|----------|---------|
| `initiator.c` | 473 lines | 473 lines | +80 PSK logic |
| `responder.c` | 504 lines | 504 lines | +100 PSK logic |
| `ciphertext.c` | 668 lines | 684 lines | +200 two-layer crypto |
| `th.c` | ~130 lines | ~200 lines | +70 PSK formulas |
| `prk.c` | ~90 lines | ~113 lines | +25 PSK derivation |
| `edhoc_method_type.c` | ~50 lines | ~60 lines | +10 Method 4 |
| `hkdf_info.h` | ~30 lines | ~32 lines | +2 PSK labels |

## Key Differences in Code

### Method 3: Single AEAD
```c
// Message 3 encryption (Method 3)
plaintext_3 = (ID_CRED_I, MAC_3, ?EAD_3);
ciphertext_3 = AEAD_encrypt(plaintext_3, K_3, IV_3, aad);
```

### PSK: Two-Layer Encryption
```c
// Message 3 encryption (PSK Mode)
plaintext_3b = (?EAD_3);                              // Inner layer
ciphertext_3b = AEAD_encrypt(plaintext_3b, K_3, IV_3, external_aad);

plaintext_3a = (ID_CRED_PSK, ciphertext_3b);         // Outer layer
keystream_3a = EDHOC_KDF(PRK_3e2m, 12, TH_3, len);
ciphertext_3a = plaintext_3a ⊕ keystream_3a;         // XOR encryption
```

## Testing Checklist

After switching implementations:

- [ ] Clean build: `make clean && make`
- [ ] Check method in test code matches implementation
- [ ] For PSK: Verify PSK and ID_CRED_PSK configured
- [ ] For Method 3: Verify certificates/keys configured
- [ ] Upload to FPGA: `sudo ./upload_*.sh`
- [ ] Monitor UART output for errors
- [ ] Verify handshake completes successfully

## Debug Output Differences

### Method 3 Output
```
[I] Computing signature/MAC...
[I] MAC_3 generation...
[I] CIPHERTEXT_3 = AEAD(...)
```

### PSK Output
```
[I] Deriving PRK_4e3m from PSK...
[I-ENC] Empty PLAINTEXT_3B - generating authentication tag
[I-ENC] KEYSTREAM_3A generation...
[CRYPTO] ENCRYPT: in_len=0, aad_len=XX, tag_len=8
```

## Implementation Status

✅ **COMPLETED**:
- PSK Mode separated into dedicated directory
- Original Method 3 preserved unchanged
- Full documentation created
- Switch mechanism established
- Backup created

🔄 **CURRENT STATE**:
- Active: PSK Mode (uoscore-uedhoc/)
- Ready: Method 3 (uoscore-uedhoc-method3/)
- Backup: Mixed (uoscore-uedhoc-backup-mixed/)

📝 **NEXT STEPS** (if needed):
- Test PSK mode on FPGA
- Switch to Method 3 for comparison
- Generate detailed diff report

---
Created: December 15, 2025
Implementation: Clean separation of PSK and Method 3

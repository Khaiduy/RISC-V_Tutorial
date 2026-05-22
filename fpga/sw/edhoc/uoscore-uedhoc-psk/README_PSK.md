# EDHOC PSK Mode Implementation (Method 4)

This implementation adds PSK Mode (Method 4) support following draft-ietf-lake-edhoc-psk-07
(updated from -06; substantive alignment changes: uniform indistinguishable failure handling
for message_3 processing per §9, and wire-format error message generation per RFC 9528 §6).

## Features
- Method 4: PSK authentication for both Initiator and Responder
- Two-layer Message 3 encryption (XOR + AEAD)
- Compact ID_CRED encoding per RFC 9528 Section 3.5.3.2
- Empty PLAINTEXT_3B handling
- TinyCrypt CCM AEAD

## Modified Files
See PSK_IMPLEMENTATION_GUIDE.md for full list of changes.

## To Use
```bash
cd /home/khaiduy/Workspace/RISC-V_Tutorial/fpga/sw/edhoc
rm -rf uoscore-uedhoc
cp -r uoscore-uedhoc-psk uoscore-uedhoc
```

## Specifications
- RFC 9528: EDHOC base (§6 wire-format errors integrated)
- draft-ietf-lake-edhoc-psk-07: PSK extension
  - §9 uniform-error helper applied for all message_3 processing failures
  - **TODO (constant-time)**: §9 also mandates no secret-dependent timing in
    msg_3 processing; current ciphertext_decrypt_split_psk_msg3 has not been
    timing-audited and may early-return on intermediate failures. Future
    work: process all branches before returning the (still uniform) error.
- Labels: KEYSTREAM_3A=12, K_3=3, IV_3=4, SALT_4e3m=5

## Testing
- Arty A7-100T FPGA
- RV32IMAC @ 50MHz
- TinyCrypt AES-CCM-16-64-128

# EDHOC Method 3 Implementation (Original)

This is the original uoscore-uedhoc library implementation supporting:
- Method 0: Initiator SK, Responder SK
- Method 1: Initiator SK, Responder Static DH
- Method 2: Initiator Static DH, Responder SK  
- Method 3: Initiator Static DH, Responder Static DH

**Does NOT include**: PSK Mode (Method 4)

## Source
Copied from: `EDHOC_doc/edhoc-psk-interop-ietf123/base/uoscore-uedhoc-3.0.5-orig/`

## To Use
```bash
cd /home/khaiduy/Workspace/RISC-V_Tutorial/fpga/sw/edhoc
rm -rf uoscore-uedhoc
cp -r uoscore-uedhoc-method3 uoscore-uedhoc
```

## Specifications
- RFC 9528: EDHOC base specification
- Supports signatures and static DH authentication

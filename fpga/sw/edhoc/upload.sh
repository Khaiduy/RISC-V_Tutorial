#!/bin/bash

# Universal SD Card Upload Script for EDHOC
# Usage: sudo ./upload.sh <binary_name> [device]
# Examples:
#   sudo ./upload.sh initiator sdc1
#   sudo ./upload.sh responder sdc1
#   sudo ./upload.sh main sdc1

BINARY_NAME=${1:-main}
DEVICE=${2:-sdc1}

# Determine binary path based on name
case "$BINARY_NAME" in
    initiator|init|i)
        BINARY="build/edhoc_m0_initiator.bin"
        DESC="EDHOC Initiator (PSK Mode)"
        ;;
    responder|resp|r)
        BINARY="build/edhoc_m0_responder.bin"
        DESC="EDHOC Responder (PSK Mode)"
        ;;
    main|m)
        BINARY="build/main.bin"
        DESC="Main Application"
        ;;
    *)
        echo "Error: Unknown binary name: $BINARY_NAME"
        echo ""
        echo "Usage: sudo ./upload.sh <binary_name> [device]"
        echo ""
        echo "Available binaries:"
        echo "  initiator, init, i  - Upload EDHOC Initiator"
        echo "  responder, resp, r  - Upload EDHOC Responder"
        echo "  main, m             - Upload Main Application"
        echo ""
        echo "Examples:"
        echo "  sudo ./upload.sh initiator sdc1"
        echo "  sudo ./upload.sh responder sdc1"
        echo "  sudo ./upload.sh main sdc1"
        exit 1
        ;;
esac

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found: $BINARY"
    echo ""
    echo "Build commands:"
    echo "  make edhoc_initiator  - Build initiator"
    echo "  make edhoc_responder  - Build responder"
    echo "  make                  - Build main"
    exit 1
fi

# Check if device exists
DEVICE_PATH="/dev/$DEVICE"
if [ ! -b "$DEVICE_PATH" ]; then
    echo "Error: Device $DEVICE_PATH does not exist"
    echo ""
    echo "Available devices:"
    lsblk -o NAME,SIZE,TYPE,MOUNTPOINT | grep -E "sd[a-z][0-9]|mmcblk[0-9]p[0-9]"
    exit 1
fi

# Display upload info
echo "=========================================="
echo "  SD Card Upload - Arty 100T FPGA"
echo "=========================================="
echo "Binary: $DESC"
echo "File:   $BINARY"
echo "Size:   $(stat -c%s "$BINARY") bytes"
echo "Device: $DEVICE_PATH"
echo ""

# Confirm upload
read -p "Continue with upload? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
    echo "Upload cancelled."
    exit 0
fi

# Upload using dd
echo "Writing binary to SD card..."
dd if="$BINARY" of="$DEVICE_PATH" bs=1M conv=fsync status=progress

if [ $? -eq 0 ]; then
    echo ""
    echo "=========================================="
    echo "  Upload Complete!"
    echo "=========================================="
    echo "You can now:"
    echo "  1. Eject the SD card safely"
    echo "  2. Insert into Arty 100T board"
    echo "  3. Power on the board"
    echo "  4. Connect to UART0 (115200 baud)"
    echo ""
else
    echo ""
    echo "Error: Upload failed!"
    exit 1
fi

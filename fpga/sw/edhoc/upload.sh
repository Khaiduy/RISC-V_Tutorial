#!/bin/bash

# Universal SD Card Upload Script for EDHOC
# Usage: sudo ./upload.sh <target> [device]
#
# Targets — Monocypher builds (optimized software):
#   m0i  | m0-initiator  - Method 0 Initiator (SK-SK)
#   m0r  | m0-responder  - Method 0 Responder (SK-SK)
#   m1i  | m1-initiator  - Method 1 Initiator (SK initiator, SDHK responder)
#   m1r  | m1-responder  - Method 1 Responder (SK initiator, SDHK responder)
#   m2i  | m2-initiator  - Method 2 Initiator (SDHK initiator, SK responder)
#   m2r  | m2-responder  - Method 2 Responder (SDHK initiator, SK responder)
#   m3i  | m3-initiator  - Method 3 Initiator (SDHK-SDHK)
#   m3r  | m3-responder  - Method 3 Responder (SDHK-SDHK)
#
# Targets — compact25519 builds (baseline, comparable to original ARM paper):
#   m0i-c  | m0-initiator-compact  - Method 0 Initiator (SK-SK)
#   m0r-c  | m0-responder-compact  - Method 0 Responder (SK-SK)
#   m1i-c  | m1-initiator-compact  - Method 1 Initiator (SK initiator, SDHK responder)
#   m1r-c  | m1-responder-compact  - Method 1 Responder (SK initiator, SDHK responder)
#   m2i-c  | m2-initiator-compact  - Method 2 Initiator (SDHK initiator, SK responder)
#   m2r-c  | m2-responder-compact  - Method 2 Responder (SDHK initiator, SK responder)
#   m3i-c  | m3-initiator-compact  - Method 3 Initiator (SDHK-SDHK)
#   m3r-c  | m3-responder-compact  - Method 3 Responder (SDHK-SDHK)
#
# Targets — Method 3 hardware-accelerated (SmallRocket32M3HWConfig, edhoc_m3_top):
#   hw-m3i | hw-m3-initiator  - Method 3 Initiator (X25519+AES-CCM+HMAC-SHA256 in HW)
#   hw-m3r | hw-m3-responder  - Method 3 Responder (X25519+AES-CCM+HMAC-SHA256 in HW)
#
# Benchmark targets:
#   bench             - Monocypher crypto micro-benchmark
#   bench-compact     - compact25519 crypto micro-benchmark
#   oscore-bench      - OSCORE benchmark (TinyCrypt)
#   oscore_benchmark_hw - OSCORE hardware benchmark (ext_aead)
#
# Legacy aliases (kept for compatibility):
#   initiator | init | i  - same as m3i
#   responder | resp | r  - same as m3r
#   main      | m         - Upload Main Application
#
# Examples:
#   sudo ./upload.sh m0i sdc1
#   sudo ./upload.sh m0i-c sdc1
#   sudo ./upload.sh m1-responder-compact sdc1
#   sudo ./upload.sh m3i sdc1

TARGET_ARG=${1:-main}
DEVICE=${2:-sdc1}

case "$TARGET_ARG" in
    m0i|m0-initiator)
        BINARY="build/edhoc_m0_initiator.bin"
        DESC="EDHOC Method 0 Initiator (SK-SK)"
        BUILD_TARGET="edhoc_m0_initiator"
        ;;
    m0r|m0-responder)
        BINARY="build/edhoc_m0_responder.bin"
        DESC="EDHOC Method 0 Responder (SK-SK)"
        BUILD_TARGET="edhoc_m0_responder"
        ;;
    m1i|m1-initiator)
        BINARY="build/edhoc_m1_initiator.bin"
        DESC="EDHOC Method 1 Initiator (SK initiator, SDHK responder)"
        BUILD_TARGET="edhoc_m1_initiator"
        ;;
    m1r|m1-responder)
        BINARY="build/edhoc_m1_responder.bin"
        DESC="EDHOC Method 1 Responder (SK initiator, SDHK responder)"
        BUILD_TARGET="edhoc_m1_responder"
        ;;
    m2i|m2-initiator)
        BINARY="build/edhoc_m2_initiator.bin"
        DESC="EDHOC Method 2 Initiator (SDHK initiator, SK responder)"
        BUILD_TARGET="edhoc_m2_initiator"
        ;;
    m2r|m2-responder)
        BINARY="build/edhoc_m2_responder.bin"
        DESC="EDHOC Method 2 Responder (SDHK initiator, SK responder)"
        BUILD_TARGET="edhoc_m2_responder"
        ;;
    m3i|m3-initiator|initiator|init|i)
        BINARY="build/edhoc_m3_initiator.bin"
        DESC="EDHOC Method 3 Initiator (SDHK-SDHK)"
        BUILD_TARGET="edhoc_m3_initiator"
        ;;
    m3r|m3-responder|responder|resp|r)
        BINARY="build/edhoc_m3_responder.bin"
        DESC="EDHOC Method 3 Responder (SDHK-SDHK) [Monocypher]"
        BUILD_TARGET="edhoc_m3_responder"
        ;;
    # ── compact25519 baseline builds ──────────────────────────────────────
    m0i-c|m0-initiator-compact)
        BINARY="build/edhoc_m0_initiator_compact.bin"
        DESC="EDHOC Method 0 Initiator (SK-SK) [compact25519]"
        BUILD_TARGET="edhoc_m0_initiator_compact"
        ;;
    m0r-c|m0-responder-compact)
        BINARY="build/edhoc_m0_responder_compact.bin"
        DESC="EDHOC Method 0 Responder (SK-SK) [compact25519]"
        BUILD_TARGET="edhoc_m0_responder_compact"
        ;;
    m1i-c|m1-initiator-compact)
        BINARY="build/edhoc_m1_initiator_compact.bin"
        DESC="EDHOC Method 1 Initiator (SK initiator, SDHK responder) [compact25519]"
        BUILD_TARGET="edhoc_m1_initiator_compact"
        ;;
    m1r-c|m1-responder-compact)
        BINARY="build/edhoc_m1_responder_compact.bin"
        DESC="EDHOC Method 1 Responder (SK initiator, SDHK responder) [compact25519]"
        BUILD_TARGET="edhoc_m1_responder_compact"
        ;;
    m2i-c|m2-initiator-compact)
        BINARY="build/edhoc_m2_initiator_compact.bin"
        DESC="EDHOC Method 2 Initiator (SDHK initiator, SK responder) [compact25519]"
        BUILD_TARGET="edhoc_m2_initiator_compact"
        ;;
    m2r-c|m2-responder-compact)
        BINARY="build/edhoc_m2_responder_compact.bin"
        DESC="EDHOC Method 2 Responder (SDHK initiator, SK responder) [compact25519]"
        BUILD_TARGET="edhoc_m2_responder_compact"
        ;;
    m3i-c|m3-initiator-compact)
        BINARY="build/edhoc_m3_initiator_compact.bin"
        DESC="EDHOC Method 3 Initiator (SDHK-SDHK) [compact25519]"
        BUILD_TARGET="edhoc_m3_initiator_compact"
        ;;
    m3r-c|m3-responder-compact)
        BINARY="build/edhoc_m3_responder_compact.bin"
        DESC="EDHOC Method 3 Responder (SDHK-SDHK) [compact25519]"
        BUILD_TARGET="edhoc_m3_responder_compact"
        ;;
    # ── benchmark targets ─────────────────────────────────────────────────
    bench)
        BINARY="build/crypto_bench.bin"
        DESC="Crypto Micro-Benchmark [Monocypher]"
        BUILD_TARGET="crypto_bench"
        ;;
    bench-compact)
        BINARY="build/crypto_bench_compact.bin"
        DESC="Crypto Micro-Benchmark [compact25519]"
        BUILD_TARGET="crypto_bench_compact"
        ;;
    hw-m3r|hw-m3-responder)
        BINARY="build/edhoc_m3_responder_hw.bin"
        DESC="EDHOC Method 3 Responder (SDHK-SDHK) [HW accelerated]"
        BUILD_TARGET="edhoc_m3_responder_hw"
        ;;
    hw-m3i|hw-m3-initiator)
        BINARY="build/edhoc_m3_initiator_hw.bin"
        DESC="EDHOC Method 3 Initiator (SDHK-SDHK) [HW accelerated]"
        BUILD_TARGET="edhoc_m3_initiator_hw"
        ;;
    oscore_benchmark_hw)
        BINARY="build/oscore_benchmark_hw.bin"
        DESC="OSCORE Hardware Benchmark (ext_aead)"
        BUILD_TARGET="oscore_benchmark_hw"
        ;;
    oscore-bench)
        BINARY="build/oscore_benchmark.bin"
        DESC="OSCORE Benchmark [TinyCrypt]"
        BUILD_TARGET="oscore_benchmark"
        ;;
    main|m)
        BINARY="build/main.bin"
        DESC="Main Application"
        BUILD_TARGET="all"
        ;;
    *)
        echo "Error: Unknown target: $TARGET_ARG"
        echo ""
        echo "Usage: sudo ./upload.sh <target> [device]"
        echo ""
        echo "Monocypher builds (optimized software):"
        echo "  m0i | m0-initiator   - Method 0 Initiator (SK-SK)"
        echo "  m0r | m0-responder   - Method 0 Responder (SK-SK)"
        echo "  m1i | m1-initiator   - Method 1 Initiator (SK+SDHK)"
        echo "  m1r | m1-responder   - Method 1 Responder (SK+SDHK)"
        echo "  m2i | m2-initiator   - Method 2 Initiator (SDHK+SK)"
        echo "  m2r | m2-responder   - Method 2 Responder (SDHK+SK)"
        echo "  m3i | m3-initiator   - Method 3 Initiator (SDHK-SDHK)"
        echo "  m3r | m3-responder   - Method 3 Responder (SDHK-SDHK)"
        echo ""
        echo "compact25519 builds (baseline, comparable to original ARM paper):"
        echo "  m0i-c | m0-initiator-compact   - Method 0 Initiator (SK-SK)"
        echo "  m0r-c | m0-responder-compact   - Method 0 Responder (SK-SK)"
        echo "  m1i-c | m1-initiator-compact   - Method 1 Initiator (SK+SDHK)"
        echo "  m1r-c | m1-responder-compact   - Method 1 Responder (SK+SDHK)"
        echo "  m2i-c | m2-initiator-compact   - Method 2 Initiator (SDHK+SK)"
        echo "  m2r-c | m2-responder-compact   - Method 2 Responder (SDHK+SK)"
        echo "  m3i-c | m3-initiator-compact   - Method 3 Initiator (SDHK-SDHK)"
        echo "  m3r-c | m3-responder-compact   - Method 3 Responder (SDHK-SDHK)"
        echo ""
        echo "Benchmark targets:"
        echo "  bench         - Crypto Micro-Benchmark (Monocypher)"
        echo "  bench-compact - Crypto Micro-Benchmark (compact25519)"
        echo "  oscore-bench  - OSCORE Benchmark (TinyCrypt)"
        echo ""
        echo "Hardware-accelerated targets (SmallRocket32M3HWConfig):"
        echo "  hw-m3i | hw-m3-initiator  - Method 3 Initiator (HW crypto)"
        echo "  hw-m3r | hw-m3-responder  - Method 3 Responder (HW crypto)"
        echo "  oscore_benchmark_hw       - OSCORE Hardware Benchmark (ext_aead)"
        echo ""
        echo "Build command for missing binary:"
        echo "  make <build_target> CRYPTO_SUITE=0 DEBUG=0"
        echo ""
        echo "Examples:"
        echo "  sudo ./upload.sh m0i sdc1"
        echo "  sudo ./upload.sh m1-responder sdc1"
        echo "  sudo ./upload.sh m3i sdc1"
        exit 1
        ;;
esac

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found: $BINARY"
    echo ""
    echo "Build it first:"
    echo "  make $BUILD_TARGET CRYPTO_SUITE=0 DEBUG=0"
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
echo "Target: $DESC"
echo "Binary: $BINARY"
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

#!/bin/bash
# Initialises the wolfssl submodule and copies our local overrides on top.
# Run once after `git clone` (and any time the submodule is re-checked out).
#
# Overrides:
#   - user_settings.h          (new — bare-metal RV32 config)
#   - wolfcrypt/src/sha3.c     (modified — fixes for RV32)
#   - wolfssl/wolfcrypt/sha3.h (modified)
#   - wolfcrypt/src/kmac.{c,h} (new — KMAC256 for Suite 25)
#   - wolfcrypt/src/kmac/      (KMAC support directory)
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/.."/..  # repo root
git submodule update --init --recursive -- fpga/sw/edhoc/wolfssl
cd "$HERE"
echo "[setup-wolfssl] applying overrides from wolfssl-overrides/ ..."
cp -v wolfssl-overrides/user_settings.h          wolfssl/user_settings.h
cp -v wolfssl-overrides/wolfcrypt/src/sha3.c     wolfssl/wolfcrypt/src/sha3.c
cp -v wolfssl-overrides/wolfssl/wolfcrypt/sha3.h wolfssl/wolfssl/wolfcrypt/sha3.h
cp -v wolfssl-overrides/wolfcrypt/src/kmac.c     wolfssl/wolfcrypt/src/kmac.c
cp -v wolfssl-overrides/wolfssl/wolfcrypt/kmac.h wolfssl/wolfssl/wolfcrypt/kmac.h
mkdir -p wolfssl/wolfcrypt/src/kmac
cp -rv wolfssl-overrides/wolfcrypt/src/kmac/.    wolfssl/wolfcrypt/src/kmac/
echo "[setup-wolfssl] done."

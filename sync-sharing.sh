#!/bin/bash
# sync-sharing.sh
# Syncs riscv-edhoc-sharing from the current rocc branch.
# Strips all hardware accelerator files and replaces HW configs
# with the explicit pure-SW overrides stored in .pure-sw/
#
# Run from the repo root while on the rocc branch.
#
# RULE: When you add new HW to any config file on rocc,
#       also update the corresponding .pure-sw/ version to exclude it.
#       The 3 files to keep in sync:
#         .pure-sw/generators/chipyard/src/main/scala/config/RocketConfigs.scala
#         .pure-sw/fpga/src/main/scala/arty35t/Configs.scala
#         .pure-sw/fpga/src/main/scala/arty100t/Configs.scala

set -e

CURRENT=$(git branch --show-current)
if [ "$CURRENT" != "rocc" ]; then
    echo "ERROR: Must be on rocc branch (currently on '$CURRENT')"
    exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "ERROR: You have uncommitted changes on rocc. Commit or stash first."
    exit 1
fi

echo "[1/5] Resetting pure-sw branch to match rocc..."
git checkout -B pure-sw

echo "[2/5] Removing hardware accelerator Scala generators..."
git rm -rf --quiet generators/chipyard/src/main/scala/crypto/ 2>/dev/null || true

echo "[3/5] Removing hardware accelerator RTL..."
git rm -rf --quiet generators/chipyard/src/main/resources/crypto-vsrc/ 2>/dev/null || true

echo "[4/5] Removing hardware SW drivers..."
for f in \
    fpga/sw/edhoc/src/edhoc_hw_initiator.c \
    fpga/sw/edhoc/src/edhoc_hw_responder.c \
    fpga/sw/edhoc/src/edhoc_m3_initiator_hw.c \
    fpga/sw/edhoc/src/edhoc_m3_responder_hw.c \
    fpga/sw/edhoc/src/oscore_benchmark_hw.c; do
    git rm -f --quiet "$f" 2>/dev/null || true
done

echo "[5/5] Applying pure-SW config overrides..."
cp .pure-sw/generators/chipyard/src/main/scala/config/RocketConfigs.scala \
   generators/chipyard/src/main/scala/config/RocketConfigs.scala
cp .pure-sw/fpga/src/main/scala/arty35t/Configs.scala \
   fpga/src/main/scala/arty35t/Configs.scala
cp .pure-sw/fpga/src/main/scala/arty100t/Configs.scala \
   fpga/src/main/scala/arty100t/Configs.scala

git add \
    generators/chipyard/src/main/scala/config/RocketConfigs.scala \
    fpga/src/main/scala/arty35t/Configs.scala \
    fpga/src/main/scala/arty100t/Configs.scala

git commit -m "Sync pure-SW from rocc: remove hardware accelerator"
git push sharing pure-sw:main --force

echo ""
echo "Done. Switching back to rocc..."
git checkout rocc
echo "riscv-edhoc-sharing is up to date."

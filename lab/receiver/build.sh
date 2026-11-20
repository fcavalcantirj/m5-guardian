#!/usr/bin/env bash
# Build only. Never opens a device or flashes firmware.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../../tools/guardian-local.sh"
STORE="$(guardian_store)" || exit 1   # GUARDIAN_STORE (lab/local.conf.example): mounted share + sentinel
IDF_ROOT="${GUARDIAN_IDF_PATH:-$HOME/esp/esp-idf}"
test "$(git -C "$IDF_ROOT" rev-parse HEAD)" = 67c1de1eebe095d554d281952fde63c16ee2dca0
export IDF_PYTHON_ENV_PATH="${GUARDIAN_IDF_PYTHON_ENV:-$HOME/.espressif/python_env/idf5.4_py3.10_env}"
export PATH="$IDF_PYTHON_ENV_PATH/bin:$PATH"
source "$IDF_ROOT/export.sh" >/dev/null
SCRATCH="${GUARDIAN_RX_BUILD:-${TMPDIR:-/tmp}/guardian-receiver-build}"
OUT="$STORE/builds/$(date +%Y%m%d-%H%M%S)-receiver"
mkdir -p "$OUT" "$SCRATCH"
idf.py -C "$HERE" -B "$SCRATCH" -D "SDKCONFIG=$SCRATCH/sdkconfig" build 2>&1 | tee "$OUT/build.log"
cp "$SCRATCH/guardian_receiver.bin" "$SCRATCH/flasher_args.json" "$SCRATCH/sdkconfig" "$OUT/"
cp "$SCRATCH/bootloader/bootloader.bin" "$SCRATCH/partition_table/partition-table.bin" "$OUT/"
(cd "$OUT" && shasum -a 256 *.bin > SHA256SUMS)
echo "Build saved: $OUT. No device touched."

#!/bin/bash
# Build only; no device access.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PROJECT="$(cd "$HERE/../.." && pwd)"
. "$PROJECT/tools/guardian-local.sh"
STORE="$(guardian_store)" || exit 1   # GUARDIAN_STORE (lab/local.conf.example): mounted share + sentinel
OUT="$STORE/builds/$(date +%Y%m%d-%H%M%S)-cardputer-client"
mkdir "$OUT"
export IDF_PYTHON_ENV_PATH="${GUARDIAN_IDF_PYTHON_ENV:-$HOME/.espressif/python_env/idf5.4_py3.10_env}"
export PATH="$IDF_PYTHON_ENV_PATH/bin:$PATH"
SDK="${GUARDIAN_IDF_PATH:-$HOME/esp/esp-idf}"
python "$PROJECT/firmware/boards/sticks3/tools/build_support.py" sdk "$SDK" > "$OUT/sdk-qualification.json"
source "$SDK/export.sh" >/dev/null
idf.py -C "$HERE" -B "$OUT" -D "SDKCONFIG=$OUT/sdkconfig" build 2>&1 | tee "$OUT/build.log"
echo "Client build: $OUT. No device changed."

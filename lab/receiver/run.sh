#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${GUARDIAN_RX_PYTHON:-$HOME/.espressif/python_env/idf5.4_py3.10_env/bin/python}"
exec "$PYTHON" "$HERE/receiver.py" "$@"

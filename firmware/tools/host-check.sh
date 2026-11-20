#!/usr/bin/env bash
# Reviewer host check for the portable Guardian library (G03).
#
#   firmware/tools/host-check.sh            configure + build + ctest, plain and sanitized
#   firmware/tools/host-check.sh plain      only the plain build
#   firmware/tools/host-check.sh asan       only the ASan+UBSan build
#   firmware/tools/host-check.sh print      print the equivalent raw commands, run nothing
#   GUARDIAN_LIBWIFI_DIR=$GUARDIAN_STORE/third-party/libwifi firmware/tools/host-check.sh
#                                           additionally builds and runs the G04 libwifi differential oracle
#
# Policy: everything that is not source goes to the artifact store (GUARDIAN_STORE, environment or
# ~/.config/m5-guardian/local.conf; template lab/local.conf.example). The cmake build trees and
# every log live under $GUARDIAN_STORE/builds/<stamp>-host-<unique>/.
# The script fails closed when the store fails its check (mounted share, sentinel); it
# never falls back to the Mac disk (README "Do not fall back"). If cmake or the
# compiler cannot work on the SMB tree, the failure is reported verbatim for an
# explicit decision; no silent relocation. No device, radio or network action.
set -euo pipefail

FIRMWARE="$(cd "$(dirname "$0")/.." && pwd)"
. "$FIRMWARE/../tools/guardian-local.sh"
STORE_ROOT="$(guardian_store_path || true)"   # checked by require_store before any write
MODE="${1:-all}"
JOBS="${GUARDIAN_JOBS:-4}"

die() { echo "host-check.sh: $*" >&2; exit 1; }

require_store() {
  STORE_ROOT="$(guardian_store)" || die "artifact store unavailable (GUARDIAN_STORE: mounted share + .guardian-store-root sentinel); refusing to build without it"
}

print_commands() {
  cat <<CMD
# plain
cmake -S "$FIRMWARE" -B "<out>/build-plain" -DCMAKE_BUILD_TYPE=Debug -DGUARDIAN_LIBWIFI_DIR="${GUARDIAN_LIBWIFI_DIR:-}"
cmake --build "<out>/build-plain" -j $JOBS
ctest --test-dir "<out>/build-plain" --output-on-failure
# sanitized (AddressSanitizer + UndefinedBehaviorSanitizer, no recovery)
cmake -S "$FIRMWARE" -B "<out>/build-asan" -DCMAKE_BUILD_TYPE=Debug -DGUARDIAN_SANITIZE=ON -DGUARDIAN_LIBWIFI_DIR="${GUARDIAN_LIBWIFI_DIR:-}"
cmake --build "<out>/build-asan" -j $JOBS
ctest --test-dir "<out>/build-asan" --output-on-failure
# <out> = $STORE_ROOT/builds/<stamp>-host-<unique>
CMD
}

one_build() {   # $1 = plain|asan, $2 = out dir
  local flavour="$1" out="$2" bdir="$2/build-$1"
  # One scalar, not an array: macOS /bin/bash 3.2 treats "${empty[@]}" under
  # set -u as unbound and kills the configure silently (found in the first real
  # run, evidence dir 20261114-000719-host: empty configure-plain.log).
  local sanitize="-DGUARDIAN_SANITIZE=OFF"
  [ "$flavour" = asan ] && sanitize="-DGUARDIAN_SANITIZE=ON"
  # G04: optional independent decoder. Empty (default) keeps the build free of third-party code.
  local oracle="-DGUARDIAN_LIBWIFI_DIR=${GUARDIAN_LIBWIFI_DIR:-}"
  echo "== configure ($flavour) -> $bdir"
  cmake -S "$FIRMWARE" -B "$bdir" -DCMAKE_BUILD_TYPE=Debug "$sanitize" "$oracle" 2>&1 | tee "$out/configure-$flavour.log" || {
    echo "configure ($flavour) failed; build/tests not run" | tee -a "$out/summary.txt"
    return 1
  }
  echo "== build ($flavour)"
  cmake --build "$bdir" -j "$JOBS" 2>&1 | tee "$out/build-$flavour.log" || {
    echo "build ($flavour) failed; tests not run" | tee -a "$out/summary.txt"
    return 1
  }
  echo "== ctest ($flavour)"
  local rc=0
  ctest --test-dir "$bdir" --output-on-failure 2>&1 | tee "$out/ctest-$flavour.log" || rc=$?
  # Per-executable full output (ctest only shows failures by default).
  local exes="contracts core_baseline presenter_baseline canvas_baseline fixture_loader_check parser_check rating_check core_check detector_check advice_check headless_replay"
  [ -n "${GUARDIAN_LIBWIFI_DIR:-}" ] && exes="$exes parser_oracle_libwifi"
  for exe in $exes; do
    if [ -x "$bdir/$exe" ]; then
      "$bdir/$exe" > "$out/run-$flavour-$exe.log" 2>&1 || {
        echo "exit=$? $exe" >> "$out/run-$flavour-$exe.log"
        rc=1
      }
    else
      echo "missing expected executable: $bdir/$exe" >> "$out/summary.txt"
      rc=1
    fi
  done
  echo "ctest ($flavour) exit=$rc" | tee -a "$out/summary.txt"
  return "$rc"
}

case "$MODE" in
  print) print_commands ;;
  plain|asan|all)
    require_store
    STAMP="$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$STORE_ROOT/builds"
    OUT="$(mktemp -d "$STORE_ROOT/builds/$STAMP-host-XXXXXX")"
    {
      echo "stamp: $STAMP"
      echo "firmware: $FIRMWARE"
      echo "host: $(uname -srm)"
      echo "cmake: $(cmake --version | head -1)"
      echo "compiler: $(c++ --version | head -1)"
      # G22: everything firmware/CMakeLists.txt compiles is pinned. Until 2026-11-19 the list stopped at
      # components + tests + examples, while the checks also build adapters/ and files of boards/sticks3/main.
      echo "sources sha256 (components + adapters + boards/sticks3/main + tests + examples + CMakeLists):"
      ( cd "$FIRMWARE" && find components adapters boards/sticks3/main tests examples CMakeLists.txt -type f ! -name '._*' ! -name '*.pyc' | LC_ALL=C sort | xargs shasum -a 256 )
    } > "$OUT/toolchain.txt"
    print_commands > "$OUT/commands.txt"
    : > "$OUT/summary.txt"
    rc=0
    if [ "$MODE" = plain ] || [ "$MODE" = all ]; then one_build plain "$OUT" || rc=1; fi
    if [ "$MODE" = asan ] || [ "$MODE" = all ]; then one_build asan "$OUT" || rc=1; fi
    ( cd "$OUT" && find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name '._*' | LC_ALL=C sort | xargs shasum -a 256 > SHA256SUMS )
    echo "evidence: $OUT"
    cat "$OUT/summary.txt"
    exit "$rc"
    ;;
  *) die "unknown mode $MODE" ;;
esac

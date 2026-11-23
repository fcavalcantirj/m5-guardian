#!/usr/bin/env bash
# Native build and evidence archive only. No action here flashes a device.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SUPPORT="$HERE/tools/build_support.py"
. "$(cd "$HERE/../../.." && pwd)/tools/guardian-local.sh"   # GUARDIAN_STORE: environment, else ~/.config/m5-guardian/local.conf
STORE_ROOT="$(guardian_store_path || true)"   # checked by require_store before any write
if [ -n "$STORE_ROOT" ]; then export GUARDIAN_STORE="$STORE_ROOT"; fi   # build_support.py accepts <store>/build-cache
BUILD_DIR="${GUARDIAN_BUILD_DIR:-/private/tmp/m5-guardian-sticks3-build}"
IDF_PATH_PINNED="${IDF_PATH_PINNED:-$HOME/esp/esp-idf}"
IDF_COMMIT_PINNED="67c1de1eebe095d554d281952fde63c16ee2dca0"
IDF_PYTHON="${GUARDIAN_IDF_PYTHON:-$HOME/.espressif/python_env/idf5.4_py3.10_env/bin/python}"
# G16B: owner OTA signing key (RSA-3072, Secure Boot V2 scheme). It lives ONLY on
# the owner's Mac, outside the repository and outside the store; never committed,
# copied or printed. Override the path with GUARDIAN_OTA_SIGNING_KEY.
SIGNING_KEY="${GUARDIAN_OTA_SIGNING_KEY:-$HOME/.config/m5-guardian/ota-signing-rsa3072.pem}"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
CMD="${1:-build}"
die(){ echo "build.sh: $*" >&2; exit 1; }
require_store(){
  STORE_ROOT="$(guardian_store)" || die 'artifact store unavailable (GUARDIAN_STORE: mounted share + .guardian-store-root sentinel)'
}
require_idf(){
  [ -x "$IDF_PYTHON" ] || die 'Set GUARDIAN_IDF_PYTHON to the installed IDF v5.4 Python'
  [ "$(git -C "$IDF_PATH_PINNED" rev-parse HEAD)" = "$IDF_COMMIT_PINNED" ] || die 'Wrong IDF revision'
  "$IDF_PYTHON" "$SUPPORT" sdk "$IDF_PATH_PINNED" >/dev/null
  export PATH="$(dirname "$IDF_PYTHON"):$PATH"
  export IDF_PYTHON_ENV_PATH="$(cd "$(dirname "$IDF_PYTHON")/.." && pwd)"
  . "$IDF_PATH_PINNED/export.sh" >/dev/null
}
require_key(){
  [ -f "$SIGNING_KEY" ] || die "OTA signing key missing at $SIGNING_KEY (create it once with: build.sh keygen)"
  local real; real="$(cd "$(dirname "$SIGNING_KEY")" && pwd -P)/$(basename "$SIGNING_KEY")"
  case "$real" in "$REPO_ROOT"/*|/Volumes/*) die 'the signing key must live outside the repository and outside the store/external volumes';; esac
  [ "$(stat -f %Lp "$real")" = 600 ] || die "signing key permissions must be 600: $real"
}
sign_build(){   # $1 build dir: sign, verify, record (key content never printed)
  local b="$1"
  "$IDF_PYTHON" -m espsecure sign_data --version 2 --keyfile "$SIGNING_KEY" --output "$b/guardian_sticks3-signed.bin" "$b/guardian_sticks3.bin" >/dev/null
  "$IDF_PYTHON" -m espsecure verify_signature --version 2 --keyfile "$SIGNING_KEY" "$b/guardian_sticks3-signed.bin" > "$b/signature-verify.txt" 2>&1 || die 'signature self-check failed'
  "$IDF_PYTHON" -m espsecure extract_public_key --version 2 --keyfile "$SIGNING_KEY" "$b/ota-signing-public.pem" >/dev/null
  "$IDF_PYTHON" - "$b" <<'PY'
import hashlib,json,sys
from pathlib import Path
b=Path(sys.argv[1]);h=lambda n:hashlib.sha256((b/n).read_bytes()).hexdigest()
(b/'signing.json').write_text(json.dumps({'scheme':'rsa3072-sbv2','tool':'espsecure sign_data --version 2',
 'unsigned_sha256':h('guardian_sticks3.bin'),'signed_sha256':h('guardian_sticks3-signed.bin'),
 'public_key_sha256':h('ota-signing-public.pem'),'app_version':(b/'guardian_app_version.txt').read_text().strip(),
 'private_key':'owner Mac only, outside the repository and the store (firmware/README.md)'},indent=2)+'\n')
PY
}
# $1 = variant ("" normal, "selftest-fail" reviewer rollback image), uses BUILD_DIR.
do_build(){
  local variant="$1" defaults="sdkconfig.defaults" suffix=""
  if [ "$variant" = selftest-fail ]; then defaults="sdkconfig.defaults;sdkconfig.selftest-fail";suffix="-stfail";fi
  # G16H: Wi-Fi/BLE coexistence spike image (passive BLE scanning, BLESPIKE console command).
  if [ "$variant" = ble-spike ]; then defaults="sdkconfig.defaults;sdkconfig.ble-spike";suffix="-blespk";fi
  # G16Q: art bench image (candidate portraits on the glass, no radio capture). Its frames must be exactly
  # what firmware/art/bench/manifest.json pins before anything is built.
  if [ "$variant" = art-bench ]; then
    defaults="sdkconfig.defaults;sdkconfig.art-bench";suffix="-bench"
    python3 "$REPO_ROOT/tools/art/candidates.py" verify >/dev/null || die 'bench frames differ from firmware/art/bench/manifest.json (tools/art/candidates.py verify)'
  fi
  # G23: battery-life measurement image (the CPU frequency while dark follows TUNE power.dark_cpu_mhz; needs CONFIG_PM_ENABLE).
  if [ "$variant" = dark-cpu ]; then defaults="sdkconfig.defaults;sdkconfig.dark-cpu";suffix="-dcpu";fi
  # G26: the public release image (sdkconfig.release: world safe country "01" with 802.11d adoption, ESP-IDF
  # reproducible build). tools/release_package.sh runs it twice from a clean tree with one fixed version.
  if [ "$variant" = release ]; then defaults="sdkconfig.defaults;sdkconfig.release";suffix="-rel";fi
  require_store;require_idf;require_key
  BUILD_DIR="$("$IDF_PYTHON" "$SUPPORT" init "$BUILD_DIR")"
  STAMP="$(date +%Y%m%d-%H%M%S)-$$"
  LOGDIR="$STORE_ROOT/builds/$STAMP-sticks3$suffix-build-logs"
  OUT="$STORE_ROOT/builds/$STAMP-sticks3$suffix"
  # G16B: one version per build (<= 31 chars, [A-Za-z0-9._-]); the OTA manifest and STATUS report it.
  # G16C rework: task-neutral stamp guardian-<date>-<time> (build_support.py version-stamp).
  local version
  if [ -n "${GUARDIAN_APP_VERSION:-}" ]; then version="$GUARDIAN_APP_VERSION$suffix"
  else version="$("$IDF_PYTHON" "$SUPPORT" version-stamp "$([ -n "$suffix" ] && echo "${suffix#-}" || echo none)")"; fi
  printf '%s' "$version" | grep -Eq '^[A-Za-z0-9._-]{1,31}$' || die "bad app version: $version"
  printf '%s\n' "$version" > "$BUILD_DIR/guardian_app_version.txt"
  mkdir -p "$LOGDIR"
  git -C "$IDF_PATH_PINNED" status --short > "$LOGDIR/sdk-worktree.txt"
  git -C "$IDF_PATH_PINNED" submodule status --recursive > "$LOGDIR/sdk-submodules.txt"
  { echo "ESP-IDF $IDF_COMMIT_PINNED"; "$IDF_PYTHON" --version; xtensa-esp32s3-elf-gcc --version; } > "$LOGDIR/toolchain.txt"
  # Preserve the exact precompiled S3 Wi-Fi input (the vendor original; build_support.py qualify_sdk refuses any SDK change).
  SDK_RADIO="$IDF_PATH_PINNED/components/esp_wifi/lib/esp32s3/libnet80211.a"
  SDK_HASH="$(shasum -a 256 "$SDK_RADIO" | cut -d ' ' -f 1)"
  SDK_STORE="$STORE_ROOT/third-party/sdk-inputs"
  mkdir -p "$SDK_STORE"
  if [ ! -f "$SDK_STORE/$SDK_HASH-libnet80211.a" ]; then cp "$SDK_RADIO" "$SDK_STORE/$SDK_HASH-libnet80211.a"; fi
  [ "$(shasum -a 256 "$SDK_STORE/$SDK_HASH-libnet80211.a" | cut -d ' ' -f 1)" = "$SDK_HASH" ] || die 'SDK input archive hash mismatch'
  echo "S3 libnet80211 SHA256=$SDK_HASH stored=$SDK_STORE/$SDK_HASH-libnet80211.a" >> "$LOGDIR/toolchain.txt"
  mkdir -p "$BUILD_DIR/sdk-inputs"
  "$IDF_PYTHON" "$SUPPORT" sdk "$IDF_PATH_PINNED" > "$BUILD_DIR/sdk-inputs/qualification.json"
  cp "$SDK_RADIO" "$BUILD_DIR/sdk-inputs/libnet80211.a"
  cp "$IDF_PATH_PINNED/components/esp_wifi/lib/LICENSE" "$BUILD_DIR/sdk-inputs/LICENSE"
  [ "$(shasum -a 256 "$BUILD_DIR/sdk-inputs/libnet80211.a" | cut -d ' ' -f 1)" = "$SDK_HASH" ] || die 'SDK snapshot mismatch'
  # Review 2026-11-17: regenerate the sdkconfig from the defaults on every build; an old one in a
  # reused build directory keeps stale values (build_support.py check_config refuses those too).
  rm -f "$BUILD_DIR/sdkconfig"
  (cd "$HERE" && idf.py -B "$BUILD_DIR" -D "SDKCONFIG=$BUILD_DIR/sdkconfig" -D "SDKCONFIG_DEFAULTS=$defaults" build) 2>&1 | tee "$LOGDIR/build.log"
  [ "${PIPESTATUS[0]}" = 0 ] || die 'idf.py build failed'
  sign_build "$BUILD_DIR"
  (cd "$HERE" && idf.py -B "$BUILD_DIR" size) > "$LOGDIR/size.txt" 2>&1
  cp "$LOGDIR/toolchain.txt" "$LOGDIR/sdk-worktree.txt" "$LOGDIR/sdk-submodules.txt" "$LOGDIR/size.txt" "$BUILD_DIR/"
  "$IDF_PYTHON" "$SUPPORT" sdk "$IDF_PATH_PINNED" >/dev/null
  [ "$(shasum -a 256 "$SDK_RADIO" | cut -d ' ' -f 1)" = "$SDK_HASH" ] || die 'SDK input changed during build'
  "$IDF_PYTHON" "$SUPPORT" archive "$BUILD_DIR" "$OUT"
  echo "Artifacts: $OUT (version $version, signed); logs: $LOGDIR; hardware acceptance remains unverified."
}
case "$CMD" in
 build) do_build "" ;;
 # G16B reviewer image: identical except CONFIG_GUARDIAN_OTA_SELFTEST_FAIL=y, own build dir and archive.
 build-selftest-fail) BUILD_DIR="${GUARDIAN_BUILD_DIR:-/private/tmp/m5-guardian-sticks3-build-stfail}";do_build selftest-fail ;;
 # G16H spike image: CONFIG_GUARDIAN_BLE_SPIKE=y (sdkconfig.ble-spike), own build directory and archive.
 build-ble-spike) BUILD_DIR="${GUARDIAN_BUILD_DIR:-/private/tmp/m5-guardian-sticks3-build-blespk}";do_build ble-spike ;;
 # G16Q art bench image: CONFIG_GUARDIAN_ART_BENCH=y (sdkconfig.art-bench), own build directory and archive.
 build-art-bench) BUILD_DIR="${GUARDIAN_BUILD_DIR:-/private/tmp/m5-guardian-sticks3-build-bench}";do_build art-bench ;;
 # G23 battery-life image: CONFIG_PM_ENABLE + CONFIG_GUARDIAN_DARK_CPU (sdkconfig.dark-cpu), own build directory and archive.
 build-dark-cpu) BUILD_DIR="${GUARDIAN_BUILD_DIR:-/private/tmp/m5-guardian-sticks3-build-dcpu}";do_build dark-cpu ;;
 # G26 public release image: CONFIG_GUARDIAN_RELEASE=y (sdkconfig.release), own build directory and archive.
 build-release) BUILD_DIR="${GUARDIAN_BUILD_DIR:-/private/tmp/m5-guardian-sticks3-build-rel}";do_build release ;;
 keygen)
  [ ! -e "$SIGNING_KEY" ] || die "refusing to overwrite the existing signing key at $SIGNING_KEY"
  require_idf
  mkdir -p "$(dirname "$SIGNING_KEY")";chmod 700 "$(dirname "$SIGNING_KEY")"
  (umask 077;"$IDF_PYTHON" -m espsecure generate_signing_key --version 2 --scheme rsa3072 "$SIGNING_KEY" >/dev/null)
  chmod 600 "$SIGNING_KEY";require_key
  echo "OTA signing key created at $SIGNING_KEY (600). Back it up offline; it never goes to the repository or the store."
  ;;
 size) require_idf; BUILD_DIR="$("$IDF_PYTHON" "$SUPPORT" resolve "$BUILD_DIR")"; (cd "$HERE" && idf.py -B "$BUILD_DIR" size) ;;
 clean) python3 "$SUPPORT" clean "$BUILD_DIR" ;;
 flash-command)
  [ -n "${GUARDIAN_PORT:-}" ] && [ -n "${GUARDIAN_ARTIFACT_DIR:-}" ] || die 'Set GUARDIAN_PORT and GUARDIAN_ARTIFACT_DIR explicitly after checking device identity and its own backup'
  [ -f "$GUARDIAN_ARTIFACT_DIR/COMPLETE.json" ] || die 'Archive is not complete'
  printf 'cd %q && %q -m esptool --chip esp32s3 --port %q write_flash @flash_args\n' "$GUARDIAN_ARTIFACT_DIR" "$IDF_PYTHON" "$GUARDIAN_PORT"
  ;;
 monitor-command)
  [ -n "${GUARDIAN_PORT:-}" ] || die 'Set GUARDIAN_PORT to the identified device'
  printf '%q -m serial.tools.miniterm %q 115200\n' "$IDF_PYTHON" "$GUARDIAN_PORT"
  ;;
 *) die "unknown command: $CMD" ;;
esac

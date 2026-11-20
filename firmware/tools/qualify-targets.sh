#!/usr/bin/env bash
# G12 deterministic qualification; no device access, RF, install or acceptance.
# Usage: qualify-targets.sh host|esp32s3|esp32c3
# GUARDIAN_QUALIFICATION_PARENT may select a writable directory below the artifact store.
set -euo pipefail
FIRMWARE="$(cd "$(dirname "$0")/.." && pwd)"
. "$FIRMWARE/../tools/guardian-local.sh"
STORE="$(guardian_store)" || exit 1   # GUARDIAN_STORE (lab/local.conf.example): mounted share + sentinel
PARENT="${GUARDIAN_QUALIFICATION_PARENT:-$STORE/builds}"
MODE="${1:-host}"
case "$MODE" in host|esp32s3|esp32c3) ;; *) echo 'Expected host, esp32s3 or esp32c3' >&2; exit 2;; esac
# Resolve existing parents before writing, rejecting symlink escapes and local fallback.
PARENT="$(cd "$PARENT" && pwd -P)"
case "$PARENT/" in "$STORE/"*) ;; *) echo 'Output must be below the Guardian the store' >&2; exit 1;; esac
OUT="$(mktemp -d "$PARENT/G12-$MODE-XXXXXX")"
echo "evidence: $OUT"
exec > "$OUT/session.log" 2>&1
trap 'rc=$?; echo "exit=$rc" > "$OUT/exit.txt"; exit "$rc"' EXIT
export PYTHONDONTWRITEBYTECODE=1
export CCACHE_DISABLE=1
export IDF_COMPONENT_MANAGER=0
{
  uname -srm
  cmake --version
  ninja --version
  df -h "$STORE"
} > "$OUT/environment.txt"
# Capture maintained inputs, not generated build products or sibling projects.
python3 - "$FIRMWARE" "$OUT/source-sha256.json" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
paths = [root / 'CMakeLists.txt', root / 'boards/sticks3/tools/build_support.py']
for name in ('components/guardian_core', 'components/guardian_presenter',
             'components/guardian_canvas', 'tests', 'qualification', 'examples', 'tools'):
    paths.extend(p for p in (root / name).rglob('*') if p.is_file()
                 and not p.name.startswith('._') and '__pycache__' not in p.parts)
pathlib.Path(sys.argv[2]).write_text(json.dumps({str(p.relative_to(root)):
    hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}, indent=2)+'\n')
PY
if [ "$MODE" = host ]; then
  c++ --version > "$OUT/compiler.txt"
  for flavour in plain asan; do
    SANITIZE=OFF
    [ "$flavour" != asan ] || SANITIZE=ON
    BDIR="$OUT/$flavour"
    set -x
    cmake -G Ninja -S "$FIRMWARE" -B "$BDIR" -DCMAKE_BUILD_TYPE=Debug -DGUARDIAN_SANITIZE="$SANITIZE" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    cmake --build "$BDIR" -j 4
    ctest --test-dir "$BDIR" --output-on-failure -V
    set +x
  done
else
  SDK="${IDF_PATH_PINNED:-$HOME/esp/esp-idf}"
  IDF_PYTHON="${GUARDIAN_IDF_PYTHON:-$HOME/.espressif/python_env/idf5.4_py3.10_env/bin/python}"
  "$IDF_PYTHON" "$FIRMWARE/boards/sticks3/tools/build_support.py" sdk "$SDK" > "$OUT/sdk-qualification.json"
  export PATH="$(dirname "$IDF_PYTHON"):$PATH"
  export IDF_PYTHON_ENV_PATH="$(cd "$(dirname "$IDF_PYTHON")/.." && pwd)"
  . "$SDK/export.sh"
  case "$MODE" in
    esp32s3) PREFIX=xtensa-esp32s3-elf;;
    esp32c3) PREFIX=riscv32-esp-elf;;
  esac
  "$PREFIX-g++" --version > "$OUT/compiler.txt"
  # Reconfigure one native tree after archiving the core-only link. This reuses
  # unchanged SDK objects; each layer's ELF/map/config/commands remain separate.
  BDIR="$OUT/build"
  if [ -n "${GUARDIAN_QUALIFICATION_REUSE:-}" ]; then
    BDIR="$(cd "$GUARDIAN_QUALIFICATION_REUSE" && pwd -P)"
    case "$BDIR/" in "$STORE/"*) ;; *) echo 'Reuse tree must be below the store'; exit 1;; esac
    grep -Fxq "CMAKE_HOME_DIRECTORY:INTERNAL=$FIRMWARE/qualification" "$BDIR/CMakeCache.txt" || {
      echo 'Refusing reuse of a different project'; exit 1;
    }
    grep -Fxq "IDF_TARGET:STRING=$MODE" "$BDIR/CMakeCache.txt" || {
      echo 'Refusing reuse of a different target'; exit 1;
    }
    echo "Reusing existing qualification build only: $BDIR"
  fi
  for layer in core presenter; do
    set -x
    cmake -G Ninja -S "$FIRMWARE/qualification" -B "$BDIR" \
      -DIDF_TARGET="$MODE" -DGUARDIAN_LAYER="$layer" \
      -DSDKCONFIG="$BDIR/sdkconfig" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    cmake --build "$BDIR" -j 8 --target "guardian_qualify_$layer.elf"
    "$PREFIX-readelf" -h "$BDIR/guardian_qualify_$layer.elf" > "$OUT/$layer-elf-header.txt"
    "$PREFIX-nm" -C --defined-only "$BDIR/guardian_qualify_$layer.elf" > "$OUT/$layer-symbols.txt"
    "$PREFIX-size" "$BDIR/guardian_qualify_$layer.elf" > "$OUT/$layer-size.txt"
    set +x
    # Native no-PSRAM configuration and separate link graphs are evidence.
    if grep -q '^CONFIG_SPIRAM=y' "$BDIR/sdkconfig"; then echo 'Unexpected PSRAM enabled'; exit 1; fi
    if grep -E 'lib(esp_wifi|guardian_canvas|M5[^/]*)\.a' "$BDIR/guardian_qualify_$layer.map"; then
      echo 'Unexpected radio/renderer library linked'; exit 1
    fi
    if [ "$layer" = core ] && grep -q 'libguardian_presenter.a' "$BDIR/guardian_qualify_$layer.map"; then
      echo 'Core probe unexpectedly links presenter'; exit 1
    fi
    python3 - "$BDIR" "$OUT/linked-$layer" "$layer" <<'PY'
import hashlib, pathlib, shutil, sys
source, dest, layer = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
dest.mkdir()
names = [f'guardian_qualify_{layer}.elf', f'guardian_qualify_{layer}.map',
         'sdkconfig', 'compile_commands.json', 'project_description.json',
         'esp-idf/guardian_core/libguardian_core.a']
if layer == 'presenter':
    names.append('esp-idf/guardian_presenter/libguardian_presenter.a')
for name in names:
    original, copy = source/name, dest/name
    copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(original, copy)
    assert hashlib.sha256(original.read_bytes()).digest() == hashlib.sha256(copy.read_bytes()).digest(), name
PY
  done
  "$IDF_PYTHON" "$FIRMWARE/boards/sticks3/tools/build_support.py" sdk "$SDK" > "$OUT/sdk-qualification-after.json"
fi
# Verify recorded source bytes did not change while qualification was running.
python3 - "$FIRMWARE" "$OUT/source-sha256.json" <<'PY'
import hashlib, json, pathlib, sys
root, manifest = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
expected = json.loads(manifest.read_text())
changed = [name for name, digest in expected.items()
           if not (root/name).is_file()
           or hashlib.sha256((root/name).read_bytes()).hexdigest() != digest]
if changed:
    raise SystemExit('Qualification inputs changed during the run: ' + ', '.join(changed))
print('Recorded source inputs unchanged at completion.')
PY
python3 - "$OUT" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
names = {'sdkconfig', 'compile_commands.json', 'project_description.json'}
paths = [p for p in root.rglob('*') if p.is_file() and not p.name.startswith('._')
         and (p.suffix in ('.elf', '.bin', '.map', '.a') or p.name in names
              or (p.parent.name in ('plain', 'asan') and not p.suffix
                  and not p.name.startswith('.')))]
(root/'artifact-sha256.json').write_text(json.dumps({str(p.relative_to(root)):
    hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}, indent=2)+'\n')
PY
echo 'Qualification commands completed; native binaries have NOT been executed or flashed.'

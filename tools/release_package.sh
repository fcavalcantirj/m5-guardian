#!/usr/bin/env bash
# G26 release package: build-only, never touches a device, never uploads.
#  1. the tree: refuses uncommitted changes (tracked or untracked-not-ignored) and exports `git archive HEAD`
#     into a scratch directory, so nothing outside the commit is compiled. --worktree exports the working
#     tree instead (tracked + untracked-not-ignored files) for a TEST package: it is marked "tree: dirty"
#     and tools/release_publish.sh refuses it;
#  2. the version: release/version.txt (version, build) and the app version guardian-<commit time UTC>-rel,
#     the same for both builds;
#  3. two clean builds of firmware/boards/sticks3 (tools/build.sh build-release: the normal Guardian with the
#     world safe radio country "01" and 802.11d adoption, ESP-IDF reproducible build) in two different
#     fresh build directories, each signed with the owner's OTA key and archived on the store as usual;
#  4. the two builds must give the same sha256 for bootloader, partition table, ota_data_initial and the
#     UNSIGNED app (fail otherwise). The signature block differs between signings (RSA-PSS salt), so the
#     package ships build 1's signed app, checked to be its unsigned app plus a signature block;
#  5. <store>/releases/<tag>/ with ONLY the four flash files, SHA256SUMS and BUILD_INFO.txt (never the ELF,
#     map, source tarball or SDK inputs: they stay in the build archives).
# Usage: tools/release_package.sh [--worktree]      (prints the package directory last)
# Environment: GUARDIAN_STORE (else ~/.config/m5-guardian/local.conf), the build.sh variables.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/tools/guardian-local.sh"
PY="${GUARDIAN_RELEASE_PYTHON:-python3}"
SUPPORT="$ROOT/tools/release_support.py"
MODE=head
case "${1:-}" in
  "") ;;
  --worktree) MODE=worktree ;;
  -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
  *) echo "usage: $0 [--worktree]" >&2; exit 2 ;;
esac
fail() { echo "FAIL package: $*"; exit 1; }

STORE="$(guardian_store)" || fail 'artifact store unavailable (GUARDIAN_STORE: mounted share + .guardian-store-root sentinel)'
"$PY" "$SUPPORT" number > /dev/null || fail 'release/version.txt'
cd "$ROOT"
COMMIT="$(git rev-parse HEAD)"
dirty="$(git status --porcelain --untracked-files=all)"
if [[ "$MODE" == head ]]; then
  [[ -z "$dirty" ]] || { echo "$dirty" | head -20; fail 'uncommitted changes: commit them first (or --worktree for a test package that can never be published)'; }
  TREE=clean
else
  TREE=dirty
  echo "INFO package: --worktree, a TEST package from the working tree (tree: dirty, never published)"
fi
STAMP="$("$PY" "$SUPPORT" stamp "$(git log -1 --format=%ct HEAD)")"

SCRATCH="/private/tmp/m5-guardian-release-$$"
SRC="$SCRATCH/src"
# Fresh build directories inside the scratch (build.sh's owner marker pins the source path, which is per run).
BUILD_A="$SCRATCH/build-1"
BUILD_B="$SCRATCH/build-2"
LOGS="$STORE/releases/logs/$(date +%Y%m%d-%H%M%S)-$$"
[[ ! -e "$SCRATCH" ]] || fail "$SCRATCH exists"
df_free_kb="$(df -k /private/tmp | awk 'NR==2 {print $4}')"
((df_free_kb > 1024 * 1024)) || fail "less than 1 GB free on the Mac disk for two build directories (about 200 MB each)"
mkdir -p "$SRC" "$LOGS"
trap 'rm -rf "$SCRATCH"' EXIT   # the export and both build directories (the archives stay on the store)
if [[ "$MODE" == head ]]; then
  git archive HEAD | tar -x -C "$SRC"
else
  git ls-files -z --cached --others --exclude-standard | while IFS= read -r -d '' f; do [[ -f "$f" ]] && printf '%s\0' "$f"; done |
    tar --null -T - -cf - | tar -x -C "$SRC"
fi
echo "OK tree: $TREE, commit $COMMIT exported to $SRC, app version $STAMP-rel"

BUILDSH="$SRC/firmware/boards/sticks3/tools/build.sh"
build_once() {  # $1 = n, $2 = build directory; prints the archive directory
  local n="$1" dir="$2"
  [[ ! -e "$dir" ]] || fail "$dir exists before build $n"
  if ! GUARDIAN_BUILD_DIR="$dir" GUARDIAN_APP_VERSION="$STAMP" bash "$BUILDSH" build-release > "$LOGS/build-$n.log" 2>&1; then
    tail -n 15 "$LOGS/build-$n.log"; fail "build $n failed (see $LOGS/build-$n.log)"
  fi
  local out; out="$(sed -nE 's/^Artifacts: ([^ ]+) \(version .*/\1/p' "$LOGS/build-$n.log" | tail -n 1)"
  [[ -n "$out" && -f "$out/COMPLETE.json" ]] || fail "build $n left no complete archive (see $LOGS/build-$n.log)"
  echo "$out"
}
ARCH_A="$(build_once 1 "$BUILD_A")"; echo "OK build 1: $ARCH_A"
ARCH_B="$(build_once 2 "$BUILD_B")"; echo "OK build 2: $ARCH_B"
"$PY" "$SUPPORT" compare "$ARCH_A" "$ARCH_B" --record "$LOGS/reproduced.json" > "$LOGS/compare.log" 2>&1 ||
  { cat "$LOGS/compare.log"; fail 'the two clean builds differ'; }
echo "OK reproducible: two clean builds, same sha256:"; sed 's/^/  /' "$LOGS/compare.log"

PKG="$("$PY" "$SUPPORT" package "$ARCH_A" "$STORE/releases" --record "$LOGS/reproduced.json" --commit "$COMMIT" --tree "$TREE" \
  --toolchain "$ARCH_A/toolchain.txt" 2> "$LOGS/package.err")" || { cat "$LOGS/package.err"; fail 'packaging refused'; }
"$PY" "$SUPPORT" check "$PKG" > "$LOGS/check.log" || fail "the new package does not check ($PKG)"
echo "OK package: $(sed -n 's/^tag=//p' "$LOGS/check.log") (tree $TREE), logs $LOGS"
cat "$PKG/SHA256SUMS"
echo "$PKG"

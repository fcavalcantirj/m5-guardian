#!/usr/bin/env bash
# G26 publish a release package as a GitHub Release of fcavalcantirj/m5-guardian, the files the website's
# install page (W07) flashes. DRY RUN by default; --publish uploads. The OWNER runs --publish, never an
# agent session. Modelled on Doutor VPD's tools/release_publish.sh.
#  1. package: a tools/release_package.sh directory (tools/release_support.py check): exactly the four flash
#     files, BUILD_INFO.txt and SHA256SUMS, every sha256 matching, the name equal to its tag
#     guardian-<version>-b<build>-<sha12 of the signed app>, built from a CLEAN tree (a --worktree test
#     package is refused);
#  2. app signature: guardian_sticks3-signed.bin verifies with the owner's OTA key (espsecure
#     verify_signature --version 2): every stick that runs it trusts that key for its later images;
#  3. release key: ~/.config/m5-guardian/release-signing-p256.pem (mode 600, outside the repository) is the
#     pair of the committed public key release/release-public-key.json (fingerprint checked);
#  4. what is published now: the API's releases/latest (404 = nothing yet, build 0; any other failure
#     refuses with its HTTP status); its manifest.json + manifest.sig are fetched BY ITS TAG, the
#     signature must verify with the release key and the manifest must parse; the package's build must be
#     HIGHER than the published one;
#  5. writes <package>/manifest.json {tag, version, build, date, notes, parts[{file, offset, sha256, size}]},
#     checks it with the website's rules (release_support.py parse-manifest), signs it (openssl dgst -sha256
#     -sign, DER -> manifest.sig) and verifies the signature, and that a changed byte is refused;
#  6. dry run: prints the manifest and the gh commands, never calls gh. --publish: gh auth switch --user
#     fcavalcantirj, gh release create <tag> --target <commit> --latest with the four parts, manifest.json
#     and manifest.sig (nothing else), then ALWAYS gh auth switch back to the account that was active
#     before (read with `gh api user`; also on
#     failure), then the round trip: by tag every asset is the package's bytes and the signature verifies,
#     and the API's latest is the new tag.
#
# Usage: tools/release_publish.sh <package-dir> --notes <text> [--publish]
# Environment (tests only; the defaults are the real ones):
#   GUARDIAN_RELEASE_KEY_DIR      default ~/.config/m5-guardian
#   GUARDIAN_RELEASE_PUBLIC_KEY   default release/release-public-key.json
#   GUARDIAN_RELEASE_API_URL      default https://api.github.com/repos/fcavalcantirj/m5-guardian/releases/latest
#   GUARDIAN_RELEASE_DOWNLOAD_URL default https://github.com/fcavalcantirj/m5-guardian/releases/download
#   GUARDIAN_RELEASE_ROUNDTRIP_TRIES / _WAIT   default 12 tries, 5 s apart
#   GUARDIAN_IDF_PYTHON, GUARDIAN_OTA_SIGNING_KEY   as build.sh (the espsecure check of step 2)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="fcavalcantirj/m5-guardian"
PUBLISH_USER="fcavalcantirj"
KEY_DIR="${GUARDIAN_RELEASE_KEY_DIR:-$HOME/.config/m5-guardian}"
KEY="$KEY_DIR/release-signing-p256.pem"
PUBLIC="${GUARDIAN_RELEASE_PUBLIC_KEY:-$ROOT/release/release-public-key.json}"
API_URL="${GUARDIAN_RELEASE_API_URL:-https://api.github.com/repos/$REPO/releases/latest}"
DOWNLOAD_URL="${GUARDIAN_RELEASE_DOWNLOAD_URL:-https://github.com/$REPO/releases/download}"
TRIES="${GUARDIAN_RELEASE_ROUNDTRIP_TRIES:-12}"
WAIT="${GUARDIAN_RELEASE_ROUNDTRIP_WAIT:-5}"
IDF_PYTHON="${GUARDIAN_IDF_PYTHON:-$HOME/.espressif/python_env/idf5.4_py3.10_env/bin/python}"
OTA_KEY="${GUARDIAN_OTA_SIGNING_KEY:-$HOME/.config/m5-guardian/ota-signing-rsa3072.pem}"
PY="${GUARDIAN_RELEASE_PYTHON:-python3}"
SUPPORT="$ROOT/tools/release_support.py"
APP="guardian_sticks3-signed.bin"
PARTS=(bootloader.bin partition-table.bin ota_data_initial.bin "$APP")
ASSETS=("${PARTS[@]}" manifest.json manifest.sig)

usage() { echo "usage: $0 <package-dir> --notes <text> [--publish]" >&2; exit 2; }
refuse() { echo "REFUSED publish: $*"; exit 1; }

PKG="" NOTES="" PUBLISH=0
while (($#)); do
  case "$1" in
    --notes) (($# >= 2)) || usage; NOTES="$2"; shift 2 ;;
    --publish) PUBLISH=1; shift ;;
    -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
    -*) usage ;;
    *) [[ -z "$PKG" ]] || usage; PKG="$1"; shift ;;
  esac
done
[[ -n "$PKG" && -n "$NOTES" ]] || usage
for tool in openssl curl "$PY" shasum; do command -v "$tool" >/dev/null || refuse "$tool not found"; done
[[ "$(openssl version)" == "OpenSSL 3."* ]] || refuse "openssl is '$(openssl version)', need OpenSSL 3.x"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/guardian-publish.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# --- 1. the package -----------------------------------------------------------------------------
[[ -d "$PKG" ]] || refuse "no package directory $PKG"
PKG="$(cd "$PKG" && pwd)"
rm -f "$PKG/manifest.json" "$PKG/manifest.sig"   # written again below (a dry run leaves them for reading)
"$PY" "$SUPPORT" check "$PKG" > "$WORK/facts" 2> "$WORK/facts.err" || refuse "$(cat "$WORK/facts.err")"
fact() { sed -n "s/^$1=//p" "$WORK/facts"; }
TAG="$(fact tag)" VERSION="$(fact version)" BUILD="$(fact build)" TREE="$(fact tree)" COMMIT="$(fact commit)"
[[ "$TREE" == clean ]] || refuse "$TAG was packaged from a $TREE tree (--worktree test package): package a commit"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || refuse "BUILD_INFO.txt has no git commit"
echo "OK package: $TAG (version $VERSION build $BUILD, commit $COMMIT), four parts match SHA256SUMS"

# --- 2. the app is signed with the owner's OTA key ----------------------------------------------------
[[ -x "$IDF_PYTHON" ]] || refuse "no IDF Python at $IDF_PYTHON (GUARDIAN_IDF_PYTHON)"
[[ -f "$OTA_KEY" ]] || refuse "no OTA signing key at $OTA_KEY (GUARDIAN_OTA_SIGNING_KEY)"
"$IDF_PYTHON" -m espsecure verify_signature --version 2 --keyfile "$OTA_KEY" "$PKG/$APP" > "$WORK/ota-verify.log" 2>&1 ||
  refuse "$APP does not verify with the owner's OTA key: $(tail -n 2 "$WORK/ota-verify.log")"
echo "OK app: $APP verifies with the owner's OTA key (sticks running it trust that key for later images)"

# --- 3. the release key pairs with the committed public key ------------------------------------------
[[ -f "$KEY" ]] || refuse "no release key at $KEY (create it once with tools/release_keygen.sh; restore it from the offline backup)"
perm="$(stat -f %Lp "$KEY" 2>/dev/null || stat -c %a "$KEY")"
[[ "$perm" == 600 ]] || refuse "$KEY has mode $perm, expected 600"
[[ -f "$PUBLIC" ]] || refuse "no committed public key $PUBLIC (tools/release_keygen.sh writes it)"
"$PY" - "$PUBLIC" "$WORK/pub.pem" "$WORK/pub.fp" <<'PY' || refuse "$PUBLIC is not a release public key file"
import json, sys
d = json.load(open(sys.argv[1]))
open(sys.argv[2], 'w').write(d['spki_pem']); open(sys.argv[3], 'w').write(d['spki_der_sha256'])
PY
openssl pkey -pubin -in "$WORK/pub.pem" -outform DER -out "$WORK/pub.der" 2>/dev/null || refuse "$PUBLIC does not hold a readable public key"
want_fp="$(cat "$WORK/pub.fp")"
[[ "$(openssl dgst -sha256 -r "$WORK/pub.der" | cut -d' ' -f1)" == "$want_fp" ]] || refuse "$PUBLIC: the public key does not match its own fingerprint"
openssl pkey -in "$KEY" -pubout -outform DER -out "$WORK/key-pub.der" 2>/dev/null || refuse "$KEY is not a readable private key"
cmp -s "$WORK/pub.der" "$WORK/key-pub.der" || refuse "$KEY is not the pair of the committed public key $PUBLIC (the website would refuse the manifest)"
echo "OK release key: pairs with $(basename "$PUBLIC") (fingerprint $want_fp)"
verify_sig() { openssl dgst -sha256 -verify "$WORK/pub.pem" -signature "$2" "$1" > /dev/null 2>&1; }

# --- 4. what is published now ---------------------------------------------------------------------------
get() {  # $1 = URL, $2 = out file; prints the HTTP status (000 = no answer)
  curl -sS -L --max-time 60 -o "$2" -w '%{http_code}' "$1" 2> "$WORK/curl.err" || true
}
api_tag() {  # $1 = out file; prints the API's latest tag_name and returns 0, or prints the status
  local code
  code="$(curl -sS -L --max-time 60 -H 'Accept: application/vnd.github+json' -o "$1" -w '%{http_code}' "$API_URL" 2> "$WORK/curl.err" || true)"
  [[ "$code" == 200 ]] || { echo "$code"; return 1; }
  "$PY" -c 'import json, sys; print(json.load(open(sys.argv[1]))["tag_name"])' "$1" 2>/dev/null || { echo "200 without tag_name"; return 1; }
}
mkdir -p "$WORK/latest"
if LATEST="$(api_tag "$WORK/api.json")"; then
  [[ "$LATEST" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || refuse "the API's latest tag '$LATEST' is not a plain tag"
  code="$(get "$DOWNLOAD_URL/$LATEST/manifest.json" "$WORK/latest/manifest.json")"
  [[ "$code" == 200 ]] || refuse "the API's latest is $LATEST but its manifest.json = HTTP $code"
  code="$(get "$DOWNLOAD_URL/$LATEST/manifest.sig" "$WORK/latest/manifest.sig")"
  [[ "$code" == 200 ]] || refuse "the API's latest $LATEST has manifest.json but manifest.sig = HTTP $code"
  verify_sig "$WORK/latest/manifest.json" "$WORK/latest/manifest.sig" ||
    refuse "the latest release $LATEST is NOT signed with the release key ($want_fp): look at it before publishing over it"
  "$PY" "$SUPPORT" parse-manifest "$WORK/latest/manifest.json" > "$WORK/latest.fields" 2> "$WORK/latest.err" ||
    refuse "the latest signed manifest does not parse: $(cat "$WORK/latest.err")"
  [[ "$(sed -n 's/^tag=//p' "$WORK/latest.fields")" == "$LATEST" ]] || refuse "the latest release's manifest names another tag than $LATEST"
  PUBLISHED="$(sed -n 's/^build=//p' "$WORK/latest.fields")"
  echo "OK latest: $LATEST build $PUBLISHED, signature valid"
elif [[ "$LATEST" == 404 ]]; then
  PUBLISHED=0; echo "OK latest: none published yet (HTTP 404), first publish"
else
  refuse "cannot read the API's latest ($API_URL: HTTP $LATEST: $(head -c 200 "$WORK/curl.err"); a rate limit is 403/429 - wait and rerun)"
fi
((BUILD > PUBLISHED)) || refuse "package build $BUILD is not higher than the published build $PUBLISHED (raise build in release/version.txt, re-package)"

# --- 5. manifest.json, checked, signed and verified -----------------------------------------------------
"$PY" "$SUPPORT" manifest "$PKG" --date "$(date -u +%Y-%m-%d)" --notes "$NOTES" > /dev/null 2> "$WORK/manifest.err" ||
  refuse "manifest: $(cat "$WORK/manifest.err")"
"$PY" "$SUPPORT" parse-manifest "$PKG/manifest.json" > "$WORK/new.fields" 2>&1 || refuse "the new manifest breaks the website's rules: $(cat "$WORK/new.fields")"
[[ "$(sed -n 's/^tag=//p' "$WORK/new.fields")" == "$TAG" && "$(sed -n 's/^build=//p' "$WORK/new.fields")" == "$BUILD" ]] ||
  refuse "the manifest reads other values than written"
openssl dgst -sha256 -sign "$KEY" -out "$PKG/manifest.sig" "$PKG/manifest.json"
verify_sig "$PKG/manifest.json" "$PKG/manifest.sig" || refuse "the new signature does not verify with $PUBLIC"
cp "$PKG/manifest.json" "$WORK/changed.json"; printf ' ' >> "$WORK/changed.json"
! verify_sig "$WORK/changed.json" "$PKG/manifest.sig" || refuse "a changed manifest still verified"
"$PY" "$SUPPORT" check "$PKG" --published > /dev/null || refuse "the package changed while signing"
echo "OK manifest: $(wc -c < "$PKG/manifest.json" | tr -d ' ') B, manifest.sig $(wc -c < "$PKG/manifest.sig" | tr -d ' ') B verifies, a changed byte is refused"

title="M5 Guardian $VERSION (build $BUILD)"
body="$(printf '%s\n\nFlash it from the website onto your own M5Stack StickS3. Four parts (bootloader 0x0, partition table 0x8000, ota_data_initial 0x10000, signed app 0x20000); manifest.json lists each sha256 and is signed (manifest.sig, ECDSA P-256).' "$NOTES")"
echo "--- manifest.json"; cat "$PKG/manifest.json"; echo
echo "--- gh"
echo "gh auth switch --user $PUBLISH_USER"
echo "(cd $PKG && gh release create $TAG --repo $REPO --target $COMMIT --title '$title' --notes <notes> --latest ${ASSETS[*]})"
echo "gh auth switch --user <the account active before>"
if ((PUBLISH == 0)); then
  echo "OK dry run: nothing uploaded. Publish (the owner): $0 $PKG --notes <...> --publish"
  exit 0
fi

# --- 6. publish -------------------------------------------------------------------------------------------
command -v gh >/dev/null || refuse "gh not found"
HOME_USER="$(gh api user --jq .login 2> "$WORK/gh-user.err")" || refuse "gh api user failed: $(head -c 200 "$WORK/gh-user.err")"
[[ "$HOME_USER" =~ ^[A-Za-z0-9-]{1,39}$ ]] || refuse "gh api user returned '$HOME_USER'"
switch_back() {
  if gh auth switch --user "$HOME_USER" > "$WORK/switch-back.log" 2>&1; then echo "OK gh: switched back to $HOME_USER"
  else echo "WARN gh: could not switch back to $HOME_USER: $(cat "$WORK/switch-back.log")"; fi
}
trap 'switch_back; rm -rf "$WORK"' EXIT
gh auth switch --user "$PUBLISH_USER" || refuse "gh auth switch --user $PUBLISH_USER failed"
(cd "$PKG" && gh release create "$TAG" --repo "$REPO" --target "$COMMIT" --title "$title" --notes "$body" --latest "${ASSETS[@]}") ||
  refuse "gh release create $TAG failed (nothing is verified as published; is commit $COMMIT pushed?)"
echo "OK gh: release $TAG created"

mkdir -p "$WORK/round"
ok=0
for ((try = 1; try <= TRIES; try++)); do
  good=1
  for f in "${ASSETS[@]}"; do
    [[ "$(get "$DOWNLOAD_URL/$TAG/$f" "$WORK/round/$f")" == 200 ]] && cmp -s "$WORK/round/$f" "$PKG/$f" || { good=0; break; }
  done
  if ((good)) && verify_sig "$WORK/round/manifest.json" "$WORK/round/manifest.sig"; then
    echo "OK round trip: $DOWNLOAD_URL/$TAG serves the six files byte for byte, signature valid (try $try)"; ok=1; break
  fi
  ((try < TRIES)) && sleep "$WAIT"
done
((ok)) || { echo "FAIL round trip: after $TRIES tries $DOWNLOAD_URL/$TAG does not serve this release's files - check the release page"; exit 1; }
ok=0
for ((try = 1; try <= TRIES; try++)); do
  seen="$(api_tag "$WORK/round/api.json")" || true
  if [[ "$seen" == "$TAG" ]]; then echo "OK API: the latest release is $TAG (try $try)"; ok=1; break; fi
  ((try < TRIES)) && sleep "$WAIT"
done
((ok)) || { echo "FAIL API: after $TRIES tries the API's latest is $seen, not $TAG - check the release page (--latest)"; exit 1; }
echo "OK published: $TAG"

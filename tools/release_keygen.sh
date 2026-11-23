#!/usr/bin/env bash
# G26 release signing key, ONE TIME (the owner runs it). Creates the ECDSA P-256 private key
# ~/.config/m5-guardian/release-signing-p256.pem (directory 700, file 600; `openssl ecparam -name
# prime256v1`) and writes ONLY its public key to release/release-public-key.json, the file the website
# (W07) verifies manifest.sig with and the one key file committed to the repository. The private key is
# never printed, never copied into the tree or the store, and an existing key is never overwritten:
# replacing it means the website refuses every earlier signed manifest. Keep an OFFLINE BACKUP of it.
#
# This key signs only the release manifest (tools/release_publish.sh). The app image itself is signed with
# the separate OTA key (firmware/boards/sticks3/tools/build.sh keygen, RSA-3072), which every flashed stick
# then trusts for its later updates.
#
# Before it writes the public file it proves the pair: a throwaway message signed with the new private
# key (openssl dgst -sha256 -sign, DER: the manifest.sig format) verifies with the extracted public key,
# and a changed message does not.
#
# Usage: tools/release_keygen.sh                 create the key (refuses when one exists)
#        tools/release_keygen.sh --public-only   rewrite release/release-public-key.json from the existing key
# Environment (tests only; the defaults are the real ones):
#   GUARDIAN_RELEASE_KEY_DIR     default ~/.config/m5-guardian
#   GUARDIAN_RELEASE_PUBLIC_KEY  default release/release-public-key.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEY_DIR="${GUARDIAN_RELEASE_KEY_DIR:-$HOME/.config/m5-guardian}"
KEY="$KEY_DIR/release-signing-p256.pem"
PUBLIC="${GUARDIAN_RELEASE_PUBLIC_KEY:-$ROOT/release/release-public-key.json}"
MODE=create
case "${1:-}" in
  "") ;;
  --public-only) MODE=public ;;
  -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
  *) echo "usage: $0 [--public-only]" >&2; exit 2 ;;
esac

command -v openssl >/dev/null || { echo "FAIL keygen: openssl not found"; exit 1; }
[[ "$(openssl version)" == "OpenSSL 3."* ]] || { echo "FAIL keygen: openssl is '$(openssl version)', need OpenSSL 3.x"; exit 1; }
real_key_dir="$(mkdir -p "$KEY_DIR" && cd "$KEY_DIR" && pwd -P)"
case "$real_key_dir/" in
  "$(cd "$ROOT" && pwd -P)"/*|/Volumes/*) echo "REFUSED keygen: the release key must live outside the repository and outside the store/external volumes ($real_key_dir)"; exit 1 ;;
esac
umask 077
WORK="$(mktemp -d "${TMPDIR:-/tmp}/guardian-keygen.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if [[ "$MODE" == create ]]; then
  if [[ -e "$KEY" ]]; then
    echo "REFUSED keygen: $KEY already exists - a release key is never overwritten"
    echo "  (to rewrite only the public file from it: $0 --public-only)"
    exit 1
  fi
  chmod 700 "$KEY_DIR"
  NEW="$(mktemp "$KEY_DIR/.release-signing.XXXXXX")"
  if ! openssl ecparam -name prime256v1 -genkey -noout -out "$NEW" 2>"$WORK/gen.err"; then
    rm -f "$NEW"; echo "FAIL keygen: openssl ecparam failed:"; cat "$WORK/gen.err"; exit 1
  fi
  chmod 600 "$NEW"
  # Hard link + unlink: atomic, and never replaces a key that appeared meanwhile.
  if ! ln "$NEW" "$KEY" 2>/dev/null; then
    rm -f "$NEW"; echo "REFUSED keygen: $KEY appeared while generating - not overwritten"; exit 1
  fi
  rm -f "$NEW"
  echo "OK keygen: created $KEY (ECDSA P-256, mode $(stat -f %Lp "$KEY" 2>/dev/null || stat -c %a "$KEY"))"
else
  [[ -f "$KEY" ]] || { echo "FAIL keygen: no key at $KEY"; exit 1; }
fi

perm="$(stat -f %Lp "$KEY" 2>/dev/null || stat -c %a "$KEY")"
[[ "$perm" == 600 ]] || { echo "FAIL keygen: $KEY has mode $perm, expected 600"; exit 1; }
openssl ec -in "$KEY" -noout -text 2>/dev/null | grep -q 'ASN1 OID: prime256v1' ||
  { echo "FAIL keygen: $KEY is not a prime256v1 (P-256) key"; exit 1; }
openssl ec -in "$KEY" -pubout -out "$WORK/pub.pem" 2>/dev/null
openssl ec -in "$KEY" -pubout -outform DER -out "$WORK/pub.der" 2>/dev/null
der_len="$(wc -c < "$WORK/pub.der" | tr -d ' ')"
[[ "$der_len" == 91 ]] || { echo "FAIL keygen: public key DER is $der_len bytes, expected 91"; exit 1; }

printf 'm5-guardian release key self-test %s\n' "$(date -u +%Y%m%dT%H%M%SZ)" > "$WORK/msg"
openssl dgst -sha256 -sign "$KEY" -out "$WORK/msg.sig" "$WORK/msg"
openssl dgst -sha256 -verify "$WORK/pub.pem" -signature "$WORK/msg.sig" "$WORK/msg" >/dev/null ||
  { echo "FAIL keygen: self-test signature did not verify with the extracted public key"; exit 1; }
printf 'x' >> "$WORK/msg"
if openssl dgst -sha256 -verify "$WORK/pub.pem" -signature "$WORK/msg.sig" "$WORK/msg" >/dev/null 2>&1; then
  echo "FAIL keygen: self-test signature verified a changed message"; exit 1
fi
echo "OK keygen: self-test sign/verify (DER, SHA-256) good, changed message refused"

fp="$(openssl dgst -sha256 -r "$WORK/pub.der" | cut -d' ' -f1)"
python3 - "$WORK/pub.pem" "$fp" "$WORK/public.json" <<'PY'
import json, sys
pem, fp, out = sys.argv[1:]
json.dump({'purpose': 'M5 Guardian release manifest signature (manifest.sig over manifest.json, tools/release_publish.sh)',
           'algorithm': 'ECDSA P-256 with SHA-256', 'signature_encoding': 'DER (openssl dgst -sha256 -sign)',
           'spki_pem': open(pem).read(), 'spki_der_sha256': fp}, open(out, 'w'), indent=2)
open(out, 'a').write('\n')
PY
mkdir -p "$(dirname "$PUBLIC")"
cp "$WORK/public.json" "$PUBLIC"
chmod 644 "$PUBLIC"
echo "OK keygen: wrote the public key to $PUBLIC (fingerprint sha256 $fp); commit it, back the private key up offline"

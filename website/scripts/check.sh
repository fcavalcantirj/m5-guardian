#!/usr/bin/env bash
# Website quality gate: pinned toolchain, Next type generation, TypeScript,
# every unit test file (discovery checked against the files on disk) and a
# production build. Any failure exits nonzero.
#
# Usage (from anywhere, after a frozen install):
#   website/scripts/check.sh
# Environment:
#   PNPM               pnpm command to verify (default: pnpm)
#   WEBSITE_CHECK_OUT  where the test report goes (default: website/.cache/website-check)
set -euo pipefail

site="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$site"
out="${WEBSITE_CHECK_OUT:-$site/.cache/website-check}"
mkdir -p "$out"
bin="$site/node_modules/.bin"

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'website-check: FAIL: %s\n' "$*" >&2; exit 1; }

[ -x "$bin/next" ] && [ -x "$bin/tsc" ] || fail "dependencies missing: run pnpm install --frozen-lockfile in website/"

step "toolchain"
node_version="$(node --version)"
pinned_pnpm="$(node -p 'require("./package.json").packageManager.replace(/^pnpm@/, "")')"
echo "node $node_version"
case "$node_version" in v24.*) ;; *) fail "Node 24.x required, found $node_version" ;; esac
pnpm_version="$(${PNPM:-pnpm} --version)" || fail "pnpm did not start (${PNPM:-pnpm})"
echo "pnpm $pnpm_version (packageManager pins $pinned_pnpm)"
[ "$pnpm_version" = "$pinned_pnpm" ] || fail "pnpm $pinned_pnpm required, found $pnpm_version"

step "next typegen"
"$bin/next" typegen

step "tsc --noEmit"
"$bin/tsc" --noEmit

step "unit tests (package.json test script)"
junit="$out/unit-tests.junit.xml"
rm -f "$junit"
test_cmd="$(node -p 'require("./package.json").scripts.test')"
NODE_OPTIONS="--test-reporter=spec --test-reporter-destination=stdout --test-reporter=junit --test-reporter-destination=$junit" \
  sh -c "$test_cmd"

step "test discovery"
expected="$(find . -name '*.test.ts' -not -path './node_modules/*' -not -path './.*' | sed 's|^\./||' | sort)"
ran="$(grep -o 'file="[^"]*"' "$junit" | sed -e 's/^file="//' -e 's/"$//' -e "s|^$site/||" | sort -u)"
echo "test files on disk: $(echo "$expected" | grep -c .)"
echo "test files run:     $(echo "$ran" | grep -c .)"
missing="$(comm -23 <(echo "$expected") <(echo "$ran"))"
[ -z "$missing" ] || fail "test files not run by the test command: $(echo $missing)"

step "next build (production)"
"$bin/next" build

printf '\nwebsite-check: PASS\n'

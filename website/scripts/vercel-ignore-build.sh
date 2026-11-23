#!/usr/bin/env bash
# Vercel Ignored Build Step for the website project (Root Directory website/,
# configured as ignoreCommand in website/vercel.json).
#
# Vercel runs this in the Root Directory of its shallow clone (depth 10) with
#   VERCEL_GIT_COMMIT_SHA    the commit being deployed
#   VERCEL_GIT_PREVIOUS_SHA  the last successful deployment of this project and
#                            branch (empty on the branch's first deployment)
# Exit 0 = skip the build (Vercel records the deployment as CANCELED).
# Exit 1 = build.
#
# The build is skipped only when the two commits are both present and valid,
# differ, and the diff between them, taken from the Git root and restricted to
# the website directory, is empty: a firmware-only change. Everything else
# builds: a website addition, modification, deletion or rename (in, out or
# within), a first deployment, a missing or malformed commit id, a commit
# absent from the clone, any comparison error, a redeploy of the same commit,
# and WEBSITE_FORCE_BUILD=1 (or true) for an explicit forced build.
set -uo pipefail

build() {
  printf 'vercel-ignore-build: BUILD: %s\n' "$*"
  exit 1
}
skip() {
  printf 'vercel-ignore-build: SKIP: %s\n' "$*"
  exit 0
}

case "${WEBSITE_FORCE_BUILD:-}" in
  1 | true) build "forced by WEBSITE_FORCE_BUILD" ;;
esac

command -v git >/dev/null 2>&1 || build "git is not available"

site="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P)" || build "cannot resolve the website directory"
root="$(git -C "$site" rev-parse --show-toplevel 2>/dev/null)" || build "the website is not a Git checkout"
prefix="$(git -C "$site" rev-parse --show-prefix 2>/dev/null)" || build "cannot resolve the website path in the repository"
[ -n "$prefix" ] || build "the website is the repository root; nothing to restrict the diff to"

current="${VERCEL_GIT_COMMIT_SHA:-}"
previous="${VERCEL_GIT_PREVIOUS_SHA:-}"
[ -n "$current" ] || build "VERCEL_GIT_COMMIT_SHA is empty"
[ -n "$previous" ] || build "no previous deployment of this branch (first deployment)"

full_id() { [[ "$1" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]; }
full_id "$current" || build "VERCEL_GIT_COMMIT_SHA is not a full commit id: $current"
full_id "$previous" || build "VERCEL_GIT_PREVIOUS_SHA is not a full commit id: $previous"
[ "$current" != "$previous" ] || build "same commit as the last deployment ($current): an explicit rebuild"

for id in "$previous" "$current"; do
  [ "$(git -C "$root" cat-file -t "$id" 2>/dev/null)" = commit ] || build "commit $id is not in this clone"
done

changes="$(git -C "$root" -c core.quotePath=false diff --no-ext-diff --no-textconv --name-status "$previous" "$current" -- "$prefix" 2>&1)"
status=$?
[ "$status" -eq 0 ] || build "git diff failed (exit $status): $changes"

echo "vercel-ignore-build: compared ${previous:0:12}..${current:0:12} under $prefix"
if [ -n "$changes" ]; then
  printf '%s\n' "$changes" | head -n 20
  build "$(printf '%s\n' "$changes" | wc -l | tr -d ' ') change(s) under $prefix"
fi
skip "no change under $prefix since the last deployment"

#!/bin/bash
# No-LLM Ralph watcher (owner, 2026-11-17: "keep watching and validating, on every task, without spending LLM").
# Polls the runner's handoffs in the store. For every NEW awaiting_review handoff it freezes a snapshot of the tree,
# runs the reviewer checks on that frozen copy and writes a SUMMARY; it never edits the tree, the ledger or
# any device, and it never calls a model. It keeps running across tasks until the runner stops (then exits).
#
#   tools/ralph_watch.sh            # foreground
#   nohup tools/ralph_watch.sh > "$GUARDIAN_STORE/builds/ralph-watch/watch.log" 2>&1 &
#
# Per handoff <TASK>-<attempt> under $OUT: SUMMARY, host-plain.log, host-asan.log, tools.log, bs.log, build.log,
# src/ (the frozen snapshot). Checks: firmware/tools/host-check.sh plain + asan (build trees in the store as the
# script's policy says), python -m pytest tools/tests, boards/sticks3 build-support tests, and the signed
# firmware archive via boards/sticks3/tools/build.sh (the shipped artifact), each with its exit code.
set -u
R=${GUARDIAN_REPO:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)}
. "$R/tools/guardian-local.sh"   # GUARDIAN_STORE: environment, else ~/.config/m5-guardian/local.conf
STORE=$(guardian_store) || { echo "artifact store unavailable; refusing"; exit 2; }   # fail-closed: share mounted + sentinel
RD=$STORE/ralph
OUT=${GUARDIAN_WATCH_OUT:-$STORE/builds/ralph-watch}
SNAP=${GUARDIAN_WATCH_SNAP:-/private/tmp/m5-guardian-ralph-watch}     # snapshots + IDF build need a POSIX disk
POLL=${GUARDIAN_WATCH_POLL:-60}
mkdir -p "$OUT" "$SNAP"; seen="$OUT/seen.txt"; touch "$seen"
log(){ echo "$(date '+%F %T') $*"; }

handoffs(){ python3 -I - "$RD/handoffs.json" <<'EOF' 2>/dev/null
import json, sys
w = json.load(open(sys.argv[1])); w = w.get('tasks', w) if isinstance(w, dict) else w
for k, v in w.items():
    if isinstance(v, dict) and v.get('status') == 'awaiting_review' and v.get('attempt'):
        print(k, v['attempt'])
EOF
}

check_one(){   # $1 task id, $2 attempt
  local tid=$1 att=$2
  local D="$OUT/$tid-$att" S="$SNAP/$tid-$att"   # separate: a local line expands its words before it assigns
  mkdir -p "$D"; rm -rf "$S"; mkdir -p "$S"
  log "HANDOFF $tid attempt $att: snapshot + checks -> $D"
  # The snapshot is exactly the file list `git add -A` would take (tracked + untracked-not-ignored), so the
  # checks see what a commit would publish: AGENTS.md, CLAUDE.md, licenses and scripts included.
  git -C "$R" ls-files -z --cached --others --exclude-standard \
    | rsync -a --from0 --files-from=- "$R/" "$S/" 2>"$D/rsync.err"
  date '+%F %T' > "$D/snapshot_time"
  # MEASURED 2026-11-18: host-check.sh generates its build tree in the store (smbfs) and the cmake generation of thousands
  # of small files took >1 h in uninterruptible IO wait; the watcher builds on the Mac disk (same cmake flags as
  # host-check.sh, logs still in the store) like the proven 2026-11-17 batch watcher.
  for fl in plain asan; do
    san=OFF; [ "$fl" = asan ] && san=ON
    ( cmake -S "$S/firmware" -B "$SNAP/build-$fl" -DCMAKE_BUILD_TYPE=Debug -DGUARDIAN_SANITIZE=$san -DGUARDIAN_LIBWIFI_DIR= \
        && cmake --build "$SNAP/build-$fl" -j 6 && ctest --test-dir "$SNAP/build-$fl" --output-on-failure; echo "RC_host_$fl=$?" ) > "$D/host-$fl.log" 2>&1
    rm -rf "$SNAP/build-$fl"
  done
  ( cd "$S" && python3 -I -m pytest -q tools/tests; echo "RC_tools=$?" ) > "$D/tools.log" 2>&1
  ( cd "$S/firmware/boards/sticks3" && python3 -I -m pytest -q tests/test_build_support.py; echo "RC_bs=$?" ) > "$D/bs.log" 2>&1
  # build_support.py marks the IDF build dir with its owning project path ("wrong build owner" otherwise): one dir per snapshot
  ( GUARDIAN_BUILD_DIR="$SNAP/idf-build-$tid-$att" "$S/firmware/boards/sticks3/tools/build.sh" build; echo "RC_build=$?" ) > "$D/build.log" 2>&1
  rm -rf "$SNAP/idf-build-$tid-$att"
  {
    echo "TASK $tid attempt $att snapshot $(cat "$D/snapshot_time") checked $(date '+%F %T')"
    grep -h "^RC_" "$D"/*.log
    grep -h "tests passed\|tests failed\|Total Test time\| passed in\| failed\|archive:\|version=\|SHA256SUMS\|signature" "$D"/*.log | sort -u | head -40
  } > "$D/SUMMARY"
  cat "$D/SUMMARY"
  rm -rf "$S"   # the frozen source copy is only needed while the checks run; logs and the archive stay in the store
}

checked=0
log "watching $RD (poll ${POLL}s); outputs in $OUT"
while true; do
  while read -r tid att; do
    [ -z "${tid:-}" ] && continue
    grep -q "^$tid $att\$" "$seen" && continue
    echo "$tid $att" >> "$seen"
    check_one "$tid" "$att"; checked=$((checked + 1))
  done < <(handoffs)
  if ! pgrep -f "python3.*[r]alph_runner\.py" >/dev/null; then   # ralph.sh execs python3 on the runner; a shell that merely names it does not count
    log "RUNNER NOT RUNNING; last receipt: $(python3 -I -c "import json;s=json.load(open('$RD/state.json'));print(s.get('status'),s.get('task_id'),s.get('attempt'))" 2>/dev/null)"
    [ "${GUARDIAN_WATCH_EXIT_ON_IDLE:-1}" = 1 ] && [ "$checked" -gt 0 ] && { log "exiting after $checked handoff(s)"; exit 0; }   # before the first handoff it waits for the runner to start
  fi
  sleep "$POLL"
done

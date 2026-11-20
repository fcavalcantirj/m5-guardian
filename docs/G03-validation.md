# G03 supervising validation — 2026-11-14

G03 is accepted with this correction package. The installer applies the reviewed
bytes/evidence before setting only G03's passes flag. The portable host harness
is ready for G04–G08 implementation batching; parser/detector/live/board acceptance
is not claimed.

## Checks and evidence

- Plain and ASan/UBSan builds of the worker source snapshot: 7/7 tests passed.
- Verified the final worker firmware sources byte-match that inspected snapshot,
  and the ledger matches the worker's ledger-before.json.
- Checked all 21 worker evidence hashes in `builds/20261114-001140-host/SHA256SUMS`.
  Its plain/sanitized runs both passed; its eight mutation checks are recorded as
  worker evidence, not falsely claimed as independently rerun.
- Reproduced four false-pass paths BEFORE fixes: configure failure followed by
  successful ctest (driver exit 0), empty case mixed with a real case (exit 0),
  a misspelled requested case mixed with a real one (exit 0), and matching replay
  output from a child exiting 9 (CTest passed because of PASS_REGULAR_EXPRESSION).
- AFTER fixes: 14/14 CTests pass in plain and ASan/UBSan builds. Added positive and
  negative child-process checks ensure expected failures remain failures.
- Six driver scenarios: configure, build, ctest, executable failure and missing
  executable all return failure; the positive control succeeds. Configure failure
  invokes neither build nor ctest; build failure invokes no ctest.

Reviewer evidence is copied to
`$GUARDIAN_STORE/evidence-raw/G03-review-20261114/` by the installer.
The review ran from an explicit temporary source/build copy under
`/private/tmp/guardian-G03-review-20261114` because the session cannot write the
project or the store. This is a documented reviewer staging constraint, not a new
silent artifact fallback in host-check.sh. The worker's actual $GUARDIAN_STORE/builds
remain untouched. No new agent, radio, device or firmware was invoked by review.

## Fixes

- Explicitly propagate configure/build failures despite Bash's ignored errexit
  inside a function called in an `||` conditional. Missing/failed executable
  runs also make the result fail. Unique output directories avoid stale runs.
- Require both a successful replay process exit and its final expected output.
- Reject unknown requested case names, including mixed valid/invalid selections;
  reject each assertion-free case even if another case made assertions.
- Correct the initial hidden-SSID fixture's libwifi provenance: it is a passing
  G02 control, not the later-empty-IE defect. Fixture bytes are unchanged.
- Clarify known-limit baseline migration: write the desired failing assertion
  first, then fix the library. Existing baseline checks are not retrospective TDD.

No production `components/` code changed. Sign-conversion cleanup and the known
Core/presenter limitations remain in their owning tasks. G04 must compare parser
fixtures against an independent decoder; source-only fixture expectations are
not such a comparison. Choosing/installing a scoped host decoder is part of that
work, not evidence already delivered by G03.

## Next run

The bounded runner update is installed alongside this acceptance. After G01–G03
are true, `./ralph-claude.sh 5` implements G04–G08, preserving their passes=false.
It stops on errors/blocked/incomplete handoffs and before a later phase. The
supervising assistant reviews/fixes the batch afterward. Claude's separate
independent ledger review remains refused/incomplete; no external approval is
invented. No batch starts unless the installer receives `--start-batch` or the
owner explicitly launches the command.

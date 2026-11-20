# G08 supervisor validation — 2026-11-14

**Decision:** accept G08 for portable host presentation/interaction after these
corrections and evidence are installed. This completes the G04–G08 host batch.
It does not accept RF detection, board integration, storage hardware or rendered
art. L01 equipment/interface qualification is next; L02 real host-library RF
validation and G09 foundation review remain before new board integration.

## Review and corrections

Reviewed the face reducer, evidence/incident priority, stale and historical
handling, DEMO transitions, label bounds, exact identity selection, candidate
admission/expiry/capacity, request ownership, persistence validation/transactional
restore and details pagination. The implementation stays in portable C++17;
physical input, display painting, serialization and storage remain adapters.

Two additional regressions failed against the worker's implementation:

1. **A reused candidate slot changed the highlighted network.** With an older
   first entry expired and a later entry still highlighted, an arriving AP reused
   the earlier storage slot. Rebuilding the picker kept the numeric cursor and
   highlighted the new AP; confirming selected that new AP. The fix preserves
   the existing highlight by exact network identity when inserting a candidate.
2. **A pending approval survived a selection change.** A request created while
   network A was selected could remain pending after an external update selected
   network B. `update()` now clears pending requests when the selected identity
   changes, as it already did for invalid time and epoch changes. Updates within
   the same selection keep the pending request intact.

`red-review.log`: 25 presenter cases / 377 assertions; the two new cases failed
four assertions, while the existing 23 cases passed. The fixes then passed both
normal and sanitized builds. No runner or unrelated library behavior changed.

Applications still apply requests coherently to Core, ApprovedScope and storage,
check operation results and keep the borrowed scope alive. The presenter cannot
make external application/storage operations atomic. Its request clearing and
identity-based cursor are local guarantees, not a replacement for that contract.

## Executed evidence

Archive after installation:
`$GUARDIAN_STORE/evidence-raw/G08-review-20261114/`.

| Check | Result |
|---|---|
| Full normal host baseline before review changes | 22/22 CTest entries passed |
| Final full normal host suite | 22/22 passed |
| Final full ASan + UBSan suite, non-recovering | 22/22 passed; no sanitizer report |
| Presenter behavior | 25 cases / 377 assertions passed in each build |
| Pure presenter policy | 2 cases / 13 assertions passed in each build |
| Preserved presenter baseline | 10 cases / 48 assertions passed in each build |
| Public headers | Independently compiled by the normal and sanitized builds |
| Worker artifact checksums | 32/32 matched |
| Worker source hashes | 73/73 matched the review snapshot |

The full suites include the prior parser, rating, evidence core, detectors,
advice, canvas, contract, fixture-loader, framework failure checks, linked
headless replay and vetted libwifi comparison. The pinned host-only libwifi
copy from the preceding review was reused; no production dependency changed.
Commands/output are in `baseline.log`, `red-review.log`, `final-plain.log`,
`final-asan.log` and `run-*.log`; the summary is `final-verification.json`.

The worker's earlier API red was a link failure for missing implementations,
not a runtime behavioral failure. Its later behavior failures and the two
supervisor regressions are preserved without rewriting that chronology. The
existing reducer/partial header are not claimed as newly written TDD code.

## Limits and installation

Inputs were hand-built snapshots/actions and imported frame fixtures. Tests
using the LiveRadio enum are synthetic source-isolation checks, not measured
live radio activity. No device was flashed, radio operated, Pi job changed,
new worker started, commit made or deployment performed. Physical text fit,
rendering, button debounce, power/performance, NVS integrity/atomic writes and
live calibration remain later work.

The independent Claude ledger/foundation review is still incomplete. This
supervisor acceptance is not Claude approval and does not bypass G09.

The session staged the small source/build copy in
`/private/tmp/guardian-G08-review-20261114` under the established permission
workflow. The installer archives checksums, logs, source and backups to mounted
the store; checks current source hashes, Ralph state and its lock; installs the fixes;
then changes only G08's acceptance field last. It starts nothing. Until it
succeeds, the actual repository ledger remains unchanged.

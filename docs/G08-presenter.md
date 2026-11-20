# G08 portable presentation and interaction

Worker implementation, subsequently validated and corrected by the supervisor;
see [G08 validation](G08-validation.md). The original evidence below is the worker record. This task owns no ledger acceptance,
radio operation, board integration, storage writes or art. The earlier StickS3 spike remains
unchanged. G05–G07 handoffs and their result records were read before this work; their
current supervisor acceptance is documented in `G04-G07-validation.md`.

## Boundary and policy

`present(Snapshot)` remains a pure face reducer. `Presenter` owns interaction state and
copies snapshots and up to 16 candidate advertisements. It consumes typed `Action`s and an
injected epoch-qualified `Instant`; it never reads buttons, clocks, storage or frames from
hardware. `candidate_from()` reduces the existing parser output. `details()` includes the
real G07 advice, reasons, next step, local signal, owner checks and uncertainty. The optional
`ApprovedScope` is borrowed read-only and must outlive its use by the presenter.

Five rated faces remain VeryGood, Good, Medium, Bad, Horrible. Unknown means **Not rated**,
with a separate evidence overlay. Checking/stale/degraded/unrated views suppress the face
and mute art. Imported replay can show its computed grade but is explicitly historical,
muted and never celebrates; a previous-epoch security record has no face or comparable age.
The top face is the large grin/cigar expression; `celebrate` permits that flourish only
with a fresh VeryGood grade and no incident. `animate` also requires a supported display
and animation capability. Art and board rendering remain later work.

An independent `IncidentBanner` coexists with the evidence overlay. Priority is observed
disconnect traffic, unexpected AP, then changed settings. The banner carries the number of
current incident kinds and the selected incident's counts, threshold, window, retry,
protected-frame and EAPOL context, saturation, listening coverage, BSSID and change bits. Details
retain all G07 incident explanation items. None attributes a transmitter or confirms a
client disconnect. The legacy reducer keeps `Overlay::Incident` on fresh incident views;
`Presenter` uses the separate banner so unsupported evidence remains labelled too.

DEMO uses five marked built-in snapshots. It cannot open a picker, expose candidates or
emit/persist requests. Live updates continue behind DEMO. A current live incident returns
the UI to the live face and prevents entering DEMO until cleared. An unconsumed owner
request also prevents entering DEMO. The face/details `source_label` is LIVE, IMPORTED or DEMO independently of navigation
mode. Details retain the complete coverage report and its age even without an incident.
The live snapshot input must match the configured origin; foreign snapshots are ignored. Fixture tests use an Imported presenter and never
relabel captured fixture bytes as live RF evidence.

## Interaction and selection

| Screen | Primary | Secondary | Primary long | Secondary long / Back |
| --- | --- | --- | --- | --- |
| Face | Details | Next DEMO face; live no-op | Toggle DEMO/live | Open live picker / no-op |
| Details | Advance settings, explanation pages, evidence, owner checks, then face | Face | Toggle DEMO/live | Open live picker / face |
| Picker | Next entry, wrap | Emit selection, return to face | Emit approve/revoke for related AP | Cancel to face |

Selection requests carry **SSID bytes and BSSID**, never sanitized display text. Same-name
APs carry full formatted BSSIDs plus a short disambiguator. Different byte strings that
sanitize identically remain distinct. Related approval requires the same SSID bytes and a
different BSSID. An approval flag is shown only when the supplied scope selection matches
the snapshot, and the approved entry has the same full identity. The application must
apply the request explicitly, clear incompatible related approvals on selection changes,
update Core/scope together, and report storage errors. Receiving frames never approves an AP.

At most one request is pending; further selection/approval actions cannot overwrite it.
A change of selected identity clears pending requests from the previous selection.
`take_request()` consumes it. The application supplies fresh snapshots regularly; ticks
also expire candidate entries and conservatively age the held evidence, but never upgrade
coverage or recompute a rating. An epoch change invalidates candidates and pending requests.

Candidates expire at 60 seconds, reject future/foreign/unknown times and foreign origins,
reject invalid identities, and cannot overwrite a newer observation. Full capacity refuses
new identities rather than evicting an entry under the cursor. Reusing an expired
storage slot preserves the current highlighted network by its exact identity. A selection/approval action
cannot select a replacement when its highlighted entry expires during that same action.
Incomplete advertisements can be selected for observation, but only complete receive-verified
advertisements offer settings/channel baseline facts for explicit approval.

SSID text is bounded printable ASCII: other bytes become `?` and set `altered`. Hidden and
absent names are marked. Impossible lengths clamp to 32 and set `invalid`, and are refused
as candidate/persisted identities. No original identity bytes are modified.

## Persistence and output adapters

`SelectionStore` is only a virtual load/save contract; the host fake exercises failure and
roundtrip. No board adapter or serialization format is implemented. The adapter must encode
fields explicitly (not dump padded C++ structs), validate sizes/enums and its own integrity
check before constructing a record, and use an atomic write/recovery strategy. There are
no timestamps or demo state in `PersistedSelection`: restored identities/baselines are owner
configuration, never fresh evidence. `persist()` retains up to the full ApprovedScope
capacity. `restore()` validates version, counts, identity, unique BSSIDs, related SSID bytes
known channel bounds, fingerprint enums and reserved mask bits; it applies to a copy and leaves the destination untouched on
failure, including a smaller configured scope capacity. An empty valid record clears scope.
The bounded read-only `ApprovedScope::approved_at()` accessor exists solely to enumerate
configuration without exposing mutation.

Details paginate explanation **items**, not measured text lines. A supported display
reports rows = height/8 and columns = width/6, clamped to 255. Two rows are reserved for
navigation/title; at least one item is offered on a small display. Headless/unknown display
has zero rows and receives all explanation items on one page. Renderers must wrap/scroll
full text and retain badges, reasons, age and coverage; this task makes no physical-fit or
screenshot claim.

## Evidence

Evidence directory (external the store storage):

`$GUARDIAN_STORE/ralph/20261114-150802-930810-task-8/g08-evidence/`

`RUNS.md` records commands, outcomes and honest limitations. `before-presenter.cpp` and
`before-presenter.hpp` preserve the actual starting point. The existing reducer and partial
header are not claimed as new TDD work.

| Stage | Measured result |
| --- | --- |
| Existing presenter + relevant G05–G07 baseline | 5/5 CTest entries pass |
| New policy RED, old reducer | 2 cases, 13 assertions; 11 failed assertions, exit 1 |
| New interaction API RED | Test code compiles; missing declared implementations fail link, exit 1 (not runtime TDD) |
| Initial GREEN | Presenter 17 cases / 293 assertions; policy 2 / 13; baseline 10 / 48 |
| Own-review RED | Expanded suite 23 cases / 361 assertions; 3 cases / 27 assertions fail |
| Final normal build | All public headers compile; 9/9 scoped CTest entries pass |
| Final presenter behavior | 23 cases / 361 assertions; policy 2 / 13; baseline 10 / 48, all pass |

The own-review failing checks exposed missing source/coverage view data, invalid persisted
fingerprints and inconsistent DEMO fixture facts. These were fixed. The intermediate
correction still lacked the RSNE default group-management cipher and failed six assertions;
that failure is retained in `review-checks-2.log`, followed by a passing final run. DEMO
fixtures now match the actual `assess()` policy for all five moods.

Fixture-source coverage uses the real parser, reductions, Core and Presenter with
Origin::Imported: WPA3 fresh/stale/age/reason/signal, hidden SSID, non-UTF-8 SSID and truncated
RSN. Hand-built typed inputs cover actions, exact identity/colliding labels, duplicate names,
approval/revoke/pending requests, bounded picker/time rejection, stale/incident coexistence,
DEMO isolation, coverage measurements, persistence roundtrip/corruption/capacity, epoch reset,
expiration during selection and explanation pagination. G03 baseline names (including its
old `KNOWN_LIMIT_demo_origin_still_celebrates` name) remain unchanged; explicit DEMO top-mood
celebration is now intentional and labelled, never live evidence.

The same nine scoped checks pass in a separate ASan/UBSan build (exit 0), with no
sanitizer report. See `asan-configure.log`, `asan-build.log` and `asan-checks.log`.
All public headers also compile in that build. No oracle/framework/canvas suites were run.

## Review limits and remaining work

- Supervisor host acceptance is recorded in [G08 validation](G08-validation.md);
  the original worker left the ledger unchanged. Live/board acceptance remains pending.
- No live RF, independent foundation review, board link, button debounce, storage writes,
  screenshots, asset validation or flash was performed. Those are separate gates/tasks.
- Candidate TTL (60 seconds), incident ordering and two reserved detail rows are explicit
  policy choices for reviewer confirmation. Text items still need renderer wrapping/scrolling.
- The application must refresh Core snapshots, keep the borrowed scope alive, apply owner
  requests coherently, surface rejected scope/storage operations, and serialize persistence
  with integrity and atomic-write checks. Portable `restore()` itself is transactional.
- Imported fixtures and hand-built snapshots prove deterministic host policy only. They
  cannot satisfy the mandatory live-host gate or later physical/art acceptance.

## Changed files

- `firmware/components/guardian_presenter/include/guardian/presenter.hpp`
- `firmware/components/guardian_presenter/presenter.cpp`
- `firmware/components/guardian_core/include/guardian/detectors.hpp` (read-only bounded enumeration only)
- `firmware/tests/presenter_policy_check.cpp`
- `firmware/tests/presenter_check.cpp`
- `firmware/CMakeLists.txt` (two focused check targets)
- `README.md`
- `docs/contracts.md`
- `docs/G08-presenter.md`

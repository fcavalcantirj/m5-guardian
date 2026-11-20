# G01 supervising validation and fixes — 2026-11-13

**Decision:** accept G01's contracts after this correction package is installed
unchanged. Installation copies the saved compiler record to the store under
`reviews/G01-20261113/`. This does not accept parser/detector behavior, a host test harness,
a live radio path or any firmware. All other tasks remain unpassed.

## Findings fixed

| Finding | Correction |
|---|---|
| Dequeue time refreshed old frames | RxMeta keeps acquisition Instant and separate processing Instant; callback stamps before queueing; replay retains scheduled acquisition offset |
| Epoch type had no end-to-end propagation | Nonzero source/timebase ID + boot generation; validity explicit; acquisition instants carried into source metadata, observations, ticks and coverage |
| WPA and RSN shared one group cipher | Independent protocol elements with bounded raw suite lists, mapped flags and separate group/PMF fields |
| Unsupported settings erased known weak evidence | Per-element structural validity and explicit partial versus complete settings; malformed siblings cannot supply trusted fields |
| FCS-free promise allowed unknown trailers | All delivered spans are FCS-free; unknown convention is dropped/counted; length normalization precedes pool truncation |
| ISR APIs in a task callback | Nonblocking task-context queues, allocation checks and failed-publication slot return |
| Replay hardware support / dependency documentation was misleading | Physical passive capability Unsupported for headless; runtime coverage separate; dependency arrows and future-enforcement caveats corrected |
| Existing replay could overread stored fixture bytes with larger caller buffers | Copy bounded by both stored bytes and caller capacity; declared larger length remains truncated |

## What was checked

- Read corrected contracts and both examples; checked SDK-free public includes,
  fixed-capacity results, caller/pool ownership, source-qualified time semantics,
  partial-evidence rules and migration responsibilities.
- Host clang++ C++17 with `-Wall -Wextra -Wpedantic -Werror -fsyntax-only`:
  core.cpp, presenter.cpp and headless_replay.cpp succeeded.
- All nine public core/presenter headers compiled independently as C++17
  translation units with the same warnings-as-errors policy.
- The SDK sketch passed Xtensa syntax checking using the installed ESP-IDF v5.4
  build configuration and explicit esp_wifi/esp_event/esp_netif include paths.
  The existing compile database identifies its IDF as v5.4-dirty; this is not
  proof of a clean pinned native rebuild. No SDK example was linked or booted.
- Ledger dependency order and G01 receipt compatibility were reviewed. Only
  passes changes within G01, preserving its content hash for the old handoff.

## Limits and TDD distinction

These fixes were implemented and compiler-reviewed, not developed in a red/green
TDD cycle. No test suite, executable scenario, RF action, device flash or new
Ralph session ran during this correction. Do not claim compiler checks as
behavior or hardware evidence.

Existing Core still consumes legacy observed_at and has known epoch/channel
limitations. Its enforcement is G05; the corrected G01 contracts now carry the
necessary information. Detector implementation and construction failure handling
are G06. The SDK sketch lacks production stop/restart lifecycle and is not a
ready capture driver. Replay remains a stand-in parser, never live evidence.

G03 establishes the host baseline/harness. G04-G08 require actual host TDD.
L01 qualifies capture and offensive control; L02 must automatically exercise
real RF with the production library on the host before G09/G10 board progression.
The assistant validates, fixes, verifies and owns each acceptance.

The installer copies only reviewed changes, keeps backups, checks source hashes,
then updates G01 acceptance last. If installation fails, the original ledger
must not be treated as accepted. Logs/history and the earlier board spike remain.

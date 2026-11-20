# G14 companion: picker, buttons, persistence and ALERT on real observations

Implementation record for ledger task G14. **Accepted 2026-11-16** by the
supervising assistant (`passes=true`). History of this record:

- 2026-11-15, Ralph worker (Claude): first implementation (companion adapter,
  screens, NVS record, StickS3 companion mode), host TDD, firmware build; not flashed.
- 2026-11-15, supervising assistant: flashed five successive images on the real
  StickS3 (`LAB-STICK-1`), reproduced defects by hand and by harness, fixed them
  with red/green host checks, ran live lab scenarios against the companion image
  and recorded an owner video. Evidence: `$GUARDIAN_STORE/evidence-raw/G14-validation-20261115/`.
- 2026-11-16, Ralph worker (Claude, re-dispatch of the same ledger entry): audited
  the current source against every ledger step, re-baselined the host suite, verified
  the source on disk is byte-identical to the last flashed archive, and corrected
  this record, which still described the pre-supervisor button map and screens.
  No library, adapter or board source was changed in this session.

- 2026-11-16, supervising assistant: re-flashed archive `20261115-171921-22108-sticks3`
  (elf `bc741e8d…` matches COMPLETE.json) to `LAB-STICK-1` with a full 8 MB rollback
  backup first (the store `backups/stick-backup-pre-g14-20261116-112505.bin`). Live STATUS
  confirmed companion boot and NVS persistence (`store=1` restored). Host plain+ASan
  25/25 on current source. 11-15 hands-on (picker select `store 1→3`, power-cycle
  restore, `alert=1`, owner video) and live scenarios (`settings-01`, `stale-01`,
  `harness-5` 92 tests OK) reviewed. Both prior `unexplained` items (heap 42791,
  picker_dropped) explained as long-session/dense-RF counters, healthy on power-cycle.
  **Accepted: `passes=true`.** Evidence: `firmware/evidence/sticks3-G14-boot-20261116.log`.

Neither worker session flashed, opened a serial device, started a live scenario
or edited the ledger. Everything physical below is the supervisor's work.

## What the code does (current source, 2026-11-16)

| Layer | Files | Role |
| --- | --- | --- |
| Portable core | `components/guardian_core/{core.cpp, detectors.cpp, include/guardian/detector.hpp, detectors.hpp}` | Supervisor fixes (2026-11-15): stale evidence wins over fresh degraded coverage; `DetectorLimits::cooldown_ms` 45 s so a still-observed condition never lapses from the 60 s incident window; `ApprovedAp::watch_impostors` (owner watch list, default off). |
| Presenter (portable) | `components/guardian_presenter/{presenter.cpp, include/guardian/presenter.hpp}` | `ViewModel::alert` / `alert_reason`, `alert_text()` (owner requirement 2026-11-14). Picker ordered strongest-first when opened, order kept while open, a full list admits a stronger newcomer (supervisor). |
| Measurement adapter | `adapters/measurement/measurement.{hpp,cpp}` | `Monitor::receive(packet, Candidate*, bool*)` reduces the **same** parse to a picker candidate; `Monitor::select(ApprovedAp)`, `approve`, `revoke`, `restore`, `set_watch`, `scope()`; `Survey::hold_discovery()`. |
| Companion adapter (SDK-free) | `adapters/companion/{companion.hpp, companion.cpp, screens.cpp}` | Key debounce/long-press decoder, explicit selection record codec + `EncodedSelectionStore` (`BlobRead` Absent/Ok/Error), `Companion` controller (Monitor, Presenter, store, shown-once onboarding), screen composer (2x text) and diagnostic painter. |
| StickS3 | `boards/sticks3/main/{measurement_main.cpp, measurement_radio.hpp, nvs_blob.{hpp,cpp}, Kconfig.projbuild, CMakeLists.txt}`, `sdkconfig.defaults`, `sdkconfig` | Companion mode at boot, NVS blobs, console hand-off, `GUARDIAN_COUNTRY`, main stack 12 KiB (both config files agree; the earlier 8192/12288 mismatch is gone). |
| Host build | `firmware/CMakeLists.txt`, `tests/companion_check.cpp`, `tests/presenter_check.cpp`, `tests/core_check.cpp`, `tests/detector_check.cpp`, `tests/contracts.cpp` | `guardian_companion` library, `companion_check` (14 cases), new presenter/core/detector/contract cases. |

Rating policy, freshness (29 s) and incident visibility (60 s) are unchanged.
The screens only format presenter output; no policy lives in rendering code.

## Boot and radio

1. Board init (G11); NVS already initialized by the board (never erased).
2. `Companion::boot()` reads NVS namespace `guardian`, key `onboarded` (1 byte).
   Absent or unreadable: the three welcome pages are shown first (owner request
   2026-11-15, "shown once"); any short press advances, holds are ignored, and
   the flag is written only after the last page.
3. `Companion::boot()` then loads NVS `guardian/selection`. A valid record
   restores the owner's **identity and approved baseline facts only** (never
   evidence): the face starts at Checking. A corrupt, foreign or invalid record
   is not used and the status line says "Saved record unreadable; not used". A
   storage read error is reported the same way, never as "No saved network".
4. Passive, receive-only listening: `esp_wifi_set_country_code(CONFIG_GUARDIAN_COUNTRY, false)`
   (Kconfig, default `BR`, the owner lab's measured scope; empty = radio off),
   `WIFI_MODE_NULL`, promiscuous management-frame filter, G13 queue and length
   validation (`copy_rx`), acquisition time and tuned channel per frame. No scan
   request, association, AP interface, transmit or password.
5. Survey: hops the country's channels 1..13 (300 ms dwell) and locks only on a
   verified advertisement of the exact selected network. While the picker is
   open or nothing is selected, `hold_discovery` keeps hopping and never claims
   a lock, so coverage is honestly degraded/unknown during picking.

## Buttons (StickS3: front key = BLUE = Primary, side key = SIDE = Secondary)

Debounce 30 ms; hold = 800 ms (fires once while held, no short press afterwards).
A key held during boot is ignored until released. Owner direction 2026-11-15:
"KISS, no one needs a manual", so the device list has two actions only.

| Screen | BLUE (short) | BLUE hold | SIDE (short) | SIDE hold |
| --- | --- | --- | --- | --- |
| Welcome pages | next page | ignored | next page | ignored |
| Face (LIVE) | details | DEMO on | – | open network list |
| Face (DEMO) | details | back to LIVE | next of the five faces | ignored |
| Details | next page (after the last: face) | DEMO toggle | back to face | network list (LIVE only) |
| Network list | move highlight to the next row | **nothing** (blocked by `Companion::input`) | **choose the highlighted network** | back to face, nothing chosen |

Changing the selected network is the deliberate two-step action *hold SIDE,
then SIDE on the chosen row*. Choosing binds the exact SSID bytes and BSSID and
the baseline facts offered by that advertisement; it is saved immediately. A
same-name AP on another BSSID is **never trusted automatically**: its
advertisements do not renew the selected network's evidence. The device offers
no trust/untrust or watch gesture (the portable presenter keeps that API for
other front ends; the lab console still has `APPROVE_AP`/`WATCH_AP`). With the
default `watch_impostors = false`, a radio that merely uses the chosen name does
not raise an ALERT (phone hotspots restart with random BSSIDs); the list shows
the chosen network in green and the highlighted row in yellow with `>`, with
no other markers.

## Persistence record (`adapters/companion/companion.cpp`)

Fixed 1,051-byte little-endian blob: `GSEL`, format 1, PersistedSelection
version, has_selection, approved count, 17 fixed AP slots (1 selected + 16 =
`ApprovedScope::capacity`; each 61 bytes: BSSID, 32 SSID bytes, length, flags
incl. `watch_impostors`, band, channel, 19-byte settings fingerprint), CRC-32.
Unused fields must be zero. Decoding requires exact size, magic, format, CRC,
`watch_impostors` only on the selection, and `PersistedSelection::valid()`
(identity, enum ranges, reserved bits, same-SSID approvals). DEMO never writes;
console `select` never writes. A failed write keeps the choice in RAM and the
status line says "Choice NOT saved (storage)".

## Screens (diagnostic visuals until art is accepted)

Everything the owner must read at arm's length is 2x (12 px glyphs); 1x is
used only for hints, the radio/store line and the details pages.

- **Face**: header `LIVE <name, 8 chars> <last BSSID bytes xx:yy>` (red while
  ALERT), a placeholder face block coloured by mood (Horrible is magenta so it
  never looks like ALERT red), the mood label, `Seen N s ago` (minutes after
  99 s) or `No reading`, the evidence overlay (`Checking`, `No fresh data`,
  `Listening coverage degraded`, `Not rated`) in 2x, the radio state or a
  store problem in 1x, and the hint `blue: info    hold side: networks`.
  No selection: `No network selected` / `hold side: choose a network`.
  Offline/stale: grey muted block with closed eyes, `No fresh data`, no grade
  colour, no Medium/Bad/Horrible label, `Radio off: ...` when the radio is off.
- **ALERT**: red face block with `!`, red frame, `ALERT: Disconnect burst
  detected` (or `Unapproved AP using this name`, `Advertised settings changed`)
  in 2x and `N in W s, A s ago; cause unknown`. Independent of the grade, no
  celebration, the coverage state (`No fresh data`, `Degraded`, `Checking`,
  `Not rated`) stays visible beside the face, scoped by Core/detectors to the
  selected/approved BSSIDs; clears only when the presenter expires the evidence
  (60 s) and never prints an all-clear.
- **DEMO**: header `DEMO n/5` in yellow, `not a real reading`, the five rated
  faces in order, hint `side: next face   hold blue: exit`. DEMO never offers
  candidates, never writes and never changes the live selection.
- **Details**: `Advertised Wi-Fi settings`, rating (or `Not rated (...)`),
  mode, cipher (group), PMF, `Evidence age: N s, heard on ch C`, and: *Not
  measured: password strength, router patch status, 5 GHz, actual client
  negotiation. Weak signal, Internet loss or a dictionary test never change
  it.* Further pages: evidence and explanation (G07 advice), signal and
  listening coverage with incident counters, owner checks (unverified).
- **Network list**: `Choose network`, up to 6 rows at 2x out of 16 live
  candidates (60 s TTL), `>` on the highlighted row, name truncated to 9
  glyphs, then the RSSI or, for duplicate names, the `..:xx:yy` disambiguator;
  `Listening...` plus the radio state while the list is empty.
- **Welcome (shown once)**: `Welcome!` (listening only, no password), `Two
  buttons` (BLUE next/info, SIDE choose, HOLD SIDE list, hold BLUE demo),
  `Let's start` (1 hold SIDE, 2 BLUE: your Wi-Fi, 3 press SIDE; red = alert,
  grey = no fresh reading).

## Console hand-off (lab harness compatibility)

`info`, `sync` and the read-only `STATUS` keep companion mode. `STATUS` prints
one `G14 STATUS` line: control, onboarding page, screen, mode, selected BSSID,
radio, store, alert, face, overlay, picker count, picker dropped count, minimum
internal heap and main-task stack headroom. Any other console command first
stops companion reception, restarts the receiver counters and hands radio and
screen to the unchanged G13 protocol until reboot. Companion mode emits no
unsolicited serial lines. The banner remains `GRX1 INFO guardian-sticks3/1.0`;
the country in a console `select` must equal the companion's (BR) or the G13
reboot rule applies.

## Evidence

### Worker TDD, 2026-11-15 (the store `builds/20261115-g14-tdd/evidence/`)

| Step | Log | Result |
| --- | --- | --- |
| Baseline | `baseline-ctest.log` | 24/24 pass before any change |
| Alert red (API absent) | `red-01-presenter-alert.log` | compile failure: no `alert` |
| Alert red (stub) | `red-02-presenter-alert.log` | 8 of 35 assertions fail |
| Alert green | `green-02-presenter-alert.log` | 26 cases pass |
| Companion red (API absent) | `red-03-companion-build.log` | `companion.hpp` not found |
| Companion red (stubs) | `red-04-companion.log` | keys/codec fail, store case crashes (SIGSEGV) |
| Companion fixes | `green-05/06-*.log` | record size 62→61 bytes found by the codec check; Rejected vs Empty and live-view origin fixed |
| Companion green | `green-07-companion.log` | 10 cases, 178 assertions |
| Channel line red/green | `red-08-channel.log`, `green-08-channel.log` | detail shows the heard channel |
| Full suites | `final-plain-ctest.log`; `builds/20261115-135606-host-UOPXZb` | plain 25/25; host-check ASan/UBSan 25/25 |

First firmware (not flashed): ELF `2aa81fd6…25bd`, archive
`builds/20261115-141720-37998-sticks3`.

### Supervisor validation and fixes, 2026-11-15 (`evidence-raw/G14-validation-20261115/`)

Each fix has a failing-before log and plain + ASan/UBSan green logs beside it.

| Finding | Red log | Fix (test case) |
| --- | --- | --- |
| A storage read error looked like "No saved network" | `storage-read-red.log` | `BlobRead` Absent/Error distinction (`storage_errors_are_not_reported_as_empty`) |
| Fresh degraded coverage hid stale evidence | `stale-over-degraded-red.log` | Core: stale wins (`stale_evidence_wins_over_fresh_degraded_coverage`) |
| List order jumped while open; full list refused stronger APs | `picker-red.log` | Presenter ordering/eviction (`opening_the_picker_lists_strongest_first…`, `full_picker_admits_a_stronger_newcomer…`) |
| 1x text unreadable on the panel | `legibility-red.log` | 2x screens (`screens_label_settings_state_limits_and_no_data_age`, demo and alert cases) |
| ALERT lapsed a few seconds every minute with a persisting rogue AP | `alert-continuity-red*.log` | `cooldown_ms` 45 s (`a_persisting_unapproved_ap_keeps_the_alert_continuous`, `detector_limits_carry_the_documented_uncalibrated_defaults`) |
| Impostor alerts need an explicit owner watch | `watch-red-build.log` | `watch_impostors` / `set_watch` |
| Trust/watch gestures on the device were confusing | `kiss-red.log` | Two-button list (`device_list_is_two_buttons_and_same_name_radios_never_alert`) |
| First use needed instructions | `onboarding-red.log` | Shown-once welcome pages (`onboarding_is_shown_once_and_any_button_advances`) |

Device work on `LAB-STICK-1`: five app-only writes with backup, rollback and
`verify_flash` checks (`sticks3-flash-write-01` … `-05`, archives
`20261115-153105-37302`, `-160553-31045`, `-163407-60266`, `-165705-95779`,
`20261115-171921-22108-sticks3`; last ELF `bc741e8d…cb22`, bin `1b77e719…4113`,
836,016 B). Live scenarios through the companion image's console hand-off all
passed their assertions and cleanup: `stale-01` (415 frames), `settings-02`
(1,832), `related-approved-02` (963), `related-unapproved-02` (1,011);
`settings-01`, `related-*-01` and the `hotspot-recheck-*` runs are retained as
history. `lab/live` harness: 92/92 (`harness-5.log`). Owner video:
`owner-video-VID_20261115_172510.mp4`. Hands-on log (`handson-watch.log`):
after the owner power-cycled the StickS3 (17:37–17:48) the 17:49 `STATUS`
reported the same selected BSSID with `store=1` (Restored) and `face=0`,
`overlay=1` (Checking), that is, identity restored and no evidence restored.
During the preceding long session the same log shows `heap_internal_min=42791`
and `task_stack_free=3440` with `picker_dropped=2541`; after the power cycle
`heap_internal_min=96323`, `task_stack_free=4448`.

### Re-baseline, 2026-11-16 (this session; `builds/20261116-g14-worker-attempt2/evidence/`)

- No source file has changed since 2026-11-15 17:18; `source-sha256.json` of
  the last flashed archive `20261115-171921-22108-sticks3` matches the working
  tree for all 127 listed files (0 different, 0 missing). The installed image
  is the current source.
- `firmware/tools/host-check.sh plain`: 25/25 (`baseline-host-check-plain.log`,
  build `builds/20261116-112149-host-vOxzG6`). The supervisor's ASan/UBSan run
  of the same morning on the same source: 25/25 (`builds/20261116-111210-host-blu6td`).
- Per-binary summaries from that plain build: `companion_check` 14 cases /
  255 assertions, `presenter_check` 28 / 448, `measurement_check` 11 / 162,
  all PASS (`baseline-plain-*.log`).
- Ledger step audit against the source (inspection, not new tests): picker
  binds SSID bytes + BSSID with a duplicate-name disambiguator and persists;
  same-name APs are not trusted; passive-only radio with length validation and
  per-frame time/channel; details page labelled `Advertised Wi-Fi settings`
  with the not-measured statement; v1 = face, details, list (plus the owner's
  welcome pages); labelled DEMO that never writes; muted no-data overlay with
  the last observation age; presenter wired to the real Monitor with no policy
  in `screens.cpp`; ALERT trigger, scoping, expiry and stale coexistence covered
  by `companion_check`. No defect found; this record was the only drift.

## Not established by these sessions

- The acceptance verdict itself: button feel, legibility, DEMO/live switch,
  AP-off no-data timing on the companion screen and a controlled-incident ALERT
  on the board are the supervisor's physical checks (video and hands-on logs
  above are their evidence, not a worker claim).
- The cause of the 42,791 B minimum internal heap seen during the long
  2026-11-15 session (96 kB after a power cycle) and the meaning of a large
  `picker_dropped` count in a dense environment; both are observations to
  re-measure, not diagnosed faults.
- `host-check.sh` saves per-binary `run-*.log` files only for the original
  G03 test list; `companion_check`, `presenter_check` and `measurement_check`
  results appear in `ctest-*.log` only (observation, G03 tooling, not changed here).
- Placeholder faces are diagnostic only; the five original 3D expressions remain art tasks.

# G05 — evidence freshness and the five advertised-settings ratings (worker handoff, 2026-11-14)

## Supervisor review — 2026-11-14

G04–G07 passed independent host review after in-scope fixes. See
[G04–G07 validation](G04-G07-validation.md) for the failing regressions,
normal/sanitized results and limits. The original worker record below is
historical; it is not the acceptance record. No RF/device effectiveness is claimed.


Worker deliverable for ledger entry G05. **Pending independent review**; nothing
here is accepted, no device was flashed, no radio was used, every input is a
hand-assembled `Origin::Imported` fixture or a hand-built value. Labels:
**MEASURED** = executed on this Mac (Apple clang 21.0.0, cmake 4.1.2) with the log
in the store; **SOURCE** = read in the cited code or standard; **DECISION** = a product
policy choice made here, open to the reviewer; **LIMIT** = known gap left for its owner.

Evidence root: `$GUARDIAN_STORE/evidence-raw/G05-worker-20261114/`
(baseline, red/green logs, mutation check, hashes, MANIFEST.md). Reviewer build
trees and per-executable logs: `$GUARDIAN_STORE/builds/<run>`
(section 8). Dependency used: the G04 handoff `docs/G04-parser.md` (status
`awaiting_review` in `ralph/handoffs.json`); its parser was built and run here
(67/67 cases) before anything depended on it. It is not independently validated.

## 1. What was built

| File | Role |
|---|---|
| `firmware/components/guardian_core/include/guardian/rating.hpp` | new: the documented rating policy (`assess`) and the reductions `observe_security` / `observe_signal` from `ParseResult` + `RxMeta` |
| `firmware/components/guardian_core/rating.cpp` | new: the policy implementation (section 2) |
| `firmware/components/guardian_core/include/guardian/core.hpp` | rewritten: `SecurityObservation` is raw facts + the `AdvertisedSettings` record (no mode/cipher summary, no `observed_at`); `SignalObservation`; `Assessment` with `Unrated` and `legacy_risk`; `Rejections`; `Snapshot` with historical/signal/coverage/rejection fields; `Core(const MonotonicClock&, ChannelSet, Origin)` with `signal()`, `coverage()`, `snapshot()` |
| `firmware/components/guardian_core/core.cpp` | rewritten: epoch-qualified freshness (section 3) |
| `firmware/components/guardian_core/include/guardian/radio.hpp` | `CoverageReport` moved here from detector.hpp (Core needs it; detector.hpp includes core.hpp) |
| `firmware/components/guardian_core/include/guardian/detector.hpp` | `CoverageReport` definition removed (pointer comment); `CoverageSource` unchanged |
| `firmware/tests/rating_check.cpp` | new, 40 cases written and run RED first (section 5; the 40th came from the mutation check, section 7) |
| `firmware/tests/core_check.cpp` | new, 29 cases written and run RED first (section 5) |
| `firmware/tests/core_baseline.cpp` | G03 baseline ported to the G05 API; the three `KNOWN_LIMIT_*` cases became intended behavior in `core_check.cpp`; the `assess_*` table moved to `rating_check.cpp` |
| `firmware/tests/contracts.cpp` | two cases rewritten for the new observation shape; includes `rating.hpp` |
| `firmware/examples/headless_replay.cpp` | runs the real `SecurityFrameParser` + real G05 policy over embedded fixture bytes; shows fresh -> unrated -> stale -> reboot/historical |
| `firmware/CMakeLists.txt`, `components/guardian_core/CMakeLists.txt`, `firmware/tools/host-check.sh` | `rating.cpp` in both builds, `rating.hpp` in the self-containment list, `rating_check` / `core_check` targets, new executables in the per-exe log list, replay expectation updated |
| `README.md`, `docs/contracts.md`, `firmware/examples/README.md` | pointers and the G01 migration ledger rows closed by this task |

Not changed: `parser.cpp`, `security_parser.hpp`, `parser.hpp`, presenter, canvas,
fixtures and their generator, the ledger, Ralph scripts, receipts. The StickS3
spike (`firmware/boards/sticks3/main/app_main.cpp`) still constructs the pre-G05
`Core(Origin)` and calls `snapshot(now_ms)`; it is not built by the host harness
and is G10's to repair (section 9).

## 2. The rating (product policy, not a certification)

`assess(const SecurityObservation&)` rates what the selected AP **advertises**.
It cannot see negotiated options, password strength or who transmitted a frame;
header addresses are spoofable facts about bytes. Every rule below has a case in
`rating_check.cpp`; the fixture-driven ones run the real G04 parser.

Order of evaluation (first hit wins), after computing the weakest-advertised
summary (`Assessment::mode/pairwise/group/pmf`) from every Valid element:

1. **Separately confirmed legacy risk** (`legacy_risk`, `Finding::Legacy`) is
   computed first and survives every later gate: a Valid original-WPA vendor
   element, or TKIP/WEP-40/WEP-104 in the pairwise list or group cipher of a Valid
   RSNE/WPA element (docs/contracts.md section 6: partial legacy evidence next to a
   malformed or unknown sibling).
2. `Unrated::Incomplete`: parse status not `Complete`, frame not a Beacon/Probe
   Response, `settings_present` false or the capability field not validated.
3. `Unrated::ReceiveUnverified`: `RxMeta::status` not `Ok` (**DECISION**: the G04
   handoff left "RxStatus::Unknown is parsed structurally; the checksum uncertainty
   stays in RxMeta for G05". An adapter that cannot say whether the bytes passed the
   checksum cannot deliver a grade; the ESP-IDF path reports `rx_state`, so a live
   adapter is not affected. Relaxing this is a one-line documented decision).
4. `Unrated::UnknownOption`: an unmapped AKM, pairwise, group or group-management
   selector in a Valid element. Checked before the parser's `settings_complete`
   flag so the reason is named; the known weaker options stay in the summary.
5. `Unrated::Incomplete` again if `settings_complete` is false for any other reason.
6. `Unrated::Inconsistent`: RSN/WPA advertised with the Privacy bit clear; an OWE
   Transition element on a BSS whose AKMs do not include OWE; a BIP (management
   only) cipher offered as a data cipher; any SAE-family AKM with PMF Disabled
   (SAE requires MFPC, WPA3 Specification; SOURCE).
7. `Unrated::Owe`: OWE AKM, or a Complete beacon with no RSN/WPA element and a
   Valid OWE Transition element (the open side of an OWE pair). Never "unencrypted".
8. `Unrated::Enterprise`: any 802.1X / Suite B AKM (RSN `1,3,5,11,12`, WPA
   802.1X), including the **standard default** when an RSNE omits its AKM list
   (**DECISION** on the G04 question: the default is what the AP means by the
   standard, so it is treated like an advertised 802.1X AKM; fixture
   `beacon_rsn_minimal_version_only` therefore reads Enterprise/unrated).
9. The five rows, weakest option first:

| Mood | Rule (all Valid elements, both WPA and RSN, every AKM, pairwise and group) | Finding |
|---|---|---|
| Horrible | Privacy clear, no RSN/WPA/OWE-transition element (open) | Unencrypted |
| Horrible | Privacy set, no RSN/WPA element (WEP), or any WEP-40/104 selector | Legacy |
| Bad | a Valid original-WPA element (any cipher), or any TKIP option anywhere | Legacy |
| Very good | SAE family only (SAE, FT-SAE, SAE-EXT-KEY), pairwise and group all in {CCMP-128, CCMP-256, GCMP-128, GCMP-256}, PMF Required | StrongSettings |
| Good | WPA2-Personal family only (PSK, PSK-SHA256, FT-PSK), pairwise and group exactly CCMP-128, PMF Required | Wpa2PmfRequired |
| Medium | WPA2-Personal family, CCMP-128, PMF Optional or Disabled | PmfNotRequired |
| Medium | PSK family and SAE family together (transition), strong ciphers, PMF Optional or Required | CompatibilityMode |
| unrated `Unspecified` | SAE-only with PMF Optional (`Finding::PmfNotRequired` names the limitation); WPA2-Personal with GCMP or CCMP-256; `Pmf::Unknown` on a Valid RSNE | — |

Weakest-advertised details: a pairwise "Use group cipher" selector takes the group
cipher; the summary cipher is the weakest across both elements (WEP < TKIP < CCMP <
GCMP); `mode` is `Wpa1` whenever a WPA element is Valid (the weakest advertised
mode), else from the RSN AKM families; `pmf` is the RSNE's value, or `Disabled`
when there is no RSNE (original WPA, open, WEP) because PMF cannot be offered.
Transition mode is reported as a valid compatibility choice (Medium with
`CompatibilityMode`), never as broken. Hidden SSIDs, frame subtype (beacon vs
probe response), HT Control headers and unrelated elements change nothing.

**DECISION** (literal ledger reading): "Good/Medium = WPA2-Personal with CCMP" is
implemented as CCMP-128 only; GCMP or CCMP-256 under a PSK AKM is `Unspecified`,
not silently promoted or demoted. Relaxing it is one comparison and one test.

## 3. Evidence freshness (Core)

`Core` borrows a `MonotonicClock`; its epoch defines "live". Every reading keeps
source (`Origin`), raw SSID bytes and BSSID (`Network`), epoch-tagged acquisition
`Instant`, band/channel, RX status, frame kind and parse status; the
`AdvertisedSettings` record travels with it so the display can show the weaker
options after reduction. Rules, each with a case in `core_check.cpp`:

| Input | Accepted as live when | Otherwise |
|---|---|---|
| `security()` | selected; origin equal; `Network` byte-equal (BSSID + SSID length + bytes); `parse != Unrelated`; band/channel in the configured `ChannelSet`; `acquired` valid, same epoch, `<= now`; not older than the held live reading | counted in `Snapshot::rejected` (`not_selected`, `origin`, `network`, `unrelated`, `channel`, `invalid_time`, `future`, `older`, `foreign_epoch`) |
| `security()` from another epoch | kept as the **historical** record only while nothing is held; never graded, never displaces anything | `foreign_epoch` |
| `signal()` | BSSID equal (non-advertisement frames carry no SSID); same time rules; never historical | counted; never touches security evidence |
| `coverage()` | `sampled_at` valid, same epoch, `<= now`, not older than the held report | counted |
| `incident()` | selected, origin, `affected` byte-equal, kind in range, same time rules | counted |

`snapshot()` (reads the clock): live security evidence younger than 30 s is
`Fresh` and graded with `assess()`; 30 s or older is `Stale` ("No fresh data") with
the record still readable and no mood. With no live sample, the view is `Checking`
for 30 s after `select()` in the current epoch, then `Stale`; a historical record
(restored from a previous boot, or demoted by a clock epoch change) is flagged
`security_historical` with `age_ms = 0` because age across timebases is unknown. A
coverage report younger than 30 s that says channel 0, drops in the window, or
(live core only) passive receive not `Supported` makes the view `Degraded` and
clears the grade; a 30 s-old report is shown with its age and does not degrade.
Signals have their own age. Incidents are visible for 60 s from their acquisition
instant in the current epoch. `select()` resets everything, including counters.

Consequences the ledger asked for: a future-stamped sample is rejected and cannot
block later live samples; a delayed sample is already stale on arrival (acquired
1 s, drained 40 s); a reboot demotes held evidence to historical; RSSI/activity and
clean coverage reports never renew security evidence; a newer malformed, truncated
or unverified sample removes the grade without becoming stale; demo/imported/live
are separate; channel 0, 15 and 36 are rejected by a 2.4 GHz capability set, 36 is
accepted by a 5 GHz set in the 5 GHz band, and an empty (Unknown) set rejects
everything.

**DECISION**: identity stays exact bytes. Selecting a network by its hidden
beacon (zero-length SSID) accepts hidden beacons and rejects the probe response
that names the SSID; selecting by name does the reverse. How the picker approves
both faces of a hidden AP is G14's call (section 9).

## 4. Commands

```sh
firmware/tools/host-check.sh                      # plain + ASan/UBSan: all targets, per-exe logs in the store
<build>/rating_check --list                       # 40 policy cases; <build>/rating_check <case> runs one
<build>/core_check --list                         # 29 freshness/isolation cases
<build>/headless_replay                           # parser -> policy -> core -> presenter on fixture bytes
```

## 5. TDD record (MEASURED)

1. `before-sha256.txt`: every `firmware/` source before the task;
   `baseline-before-ctest-plain.log`: the pre-G05 tree, 15/15 ctest (plain).
2. Headers were written first (`core.hpp`, `rating.hpp`, the `CoverageReport`
   move), then a **stub** `rating.cpp` (`assess()` returns everything Unknown; the
   `observe_*` plumbing written in full) and a **skeleton** `core.cpp` (the pre-G05
   draft logic ported mechanically onto the new API: `acquired.at` for
   `observed_at`, the injected clock for the `now` argument, no epoch/future/
   capability/historical/signal/coverage policy), then the tests.
3. **RED** (`red-*.log`, hashes in `red-sources-sha256.txt`): `rating_check` 38
   cases, **37 failed** (the one pass is the `observe_security` plumbing case);
   `core_check` 29 cases, **28 failed** (the one pass, delayed-sample age, holds
   under the old arithmetic too); `core_baseline` 12 cases, 2 failed (the 30 s
   Checking window did not exist); `contracts` 18 cases, 2 failed (`Unrated`
   expectations); ctest 12/17 (`headless_replay_runs` failed on the old
   expectation). Exit codes 1, 1, 1, 1, 8.
4. Implementation written. First green attempt: `rating_check` 36/38. The two
   failures were in the tests, not the policy: a loop case had only
   `CHECK_FAIL` branches and so executed no assertion (the framework rightly
   refuses that; positive assertions added), and the `beacon_ht_control_order_bit`
   fixture is **defective** (section 6). A 39th case pins that defect.
5. **GREEN** (`green-*-plain-scratch.log`): `rating_check` 39/39 (325 assertions; 40/40, 342 after the mutation-check case),
   `core_check` 29/29 (180), `core_baseline` 12/12, `contracts` 18/18,
   `parser_check` 67/67 unchanged, ctest 17/17 plain and 17/17 ASan/UBSan with no
   sanitizer report (`green-ctest-*-scratch.log`).
6. Refactor: none beyond comments; the code is as first written.

Iteration used disposable cmake trees in `/tmp` (deleted at the end); the
reviewer-grade runs are the store trees in section 8.

## 6. Historical G04 fixture finding (fixed by supervisor review)

The current generator now places HT Control before the fixed body. The old
KNOWN_DEFECT test was replaced with a positive privacy-bit/rating regression.
The following describes the original worker finding, not the current bytes.

`firmware/tests/fixtures/make_fixtures.py::beacon()` appends the 4-byte HT
Control **after** Timestamp / Beacon Interval / Capability when the Order bit is
set (its own offset notes show Capability at 34 and HT Control at 36). IEEE
802.11-2020 9.3.3.2 places HT Control in the MAC header, directly after Sequence
Control and before the frame body (SOURCE). The G04 parser follows the standard
(28-byte header), so on `beacon_ht_control_order_bit` it reads timestamp bytes
`33 22 11 00` as HT Control and the Capability field lands on `00 00`: Privacy
clear next to a Valid RSNE. The first element still starts at offset 40 in both
layouts, which is why G04's `order_bit_means_a_28_byte_header_with_ht_control`
(status, sequence, RSNE, DS, `settings_complete`) did not notice; it never asserted
the capability. The G05 policy refuses to grade the contradiction
(`Unrated::Inconsistent`), which is the correct behavior on those bytes.

Pinned as `KNOWN_DEFECT_G04_ht_control_fixture_puts_ht_control_after_the_fixed_fields`
in `rating_check.cpp` (asserts `privacy_bit == false`, RSNE Valid, Inconsistent) so
the generator fix flips it visibly. Suggested fix for the fixture owner: in
`make_fixtures.py` move the HT Control append from after `beacon_fixed()` into the
header (between Sequence Control and the fixed fields) and regenerate; then change
the pinned case to expect Medium / `PmfNotRequired` and add it back to the
"all rate Medium" loop. Changing the predecessor's generator was outside this task.

## 7. Mutation check: the tests bite (MEASURED, `mutation-check.sh` / `mutation-check.log`)

Twenty-four deliberate defects on throwaway copies of `firmware/`, each built and
run against `rating_check` and `core_check`; the unmodified control copy passes.

| Mutant | Edit | Result |
|---|---|---|
| m1 | the Bad rule ignores a Valid WPA element (only TKIP counts) | **survived the first pass** (every WPA fixture also carries TKIP); case `original_wpa_with_ccmp_only_is_still_bad_and_a_legacy_finding` added, now caught |
| m2 | TKIP in the group cipher ignored | caught: transition_with_a_tkip_option_is_bad |
| m3 | WPA2 PMF Optional graded Good | caught: fixture_wpa2_ccmp_pmf_optional…, probe/hidden/… loop, 4 core cases |
| m4 | SAE-only with PMF Optional graded Very good | caught: wpa3_sae_only_with_pmf_optional… |
| m5 | unknown options do not block | caught: fixture_unknown_akm…, unknown_cipher_or_akm… (first attempt did not compile: unused variable; edit fixed) |
| m6 | Privacy clear always Open (OWE transition ignored) | caught: privacy_clear_with_owe_transition_element… |
| m7 | non-Complete parse may grade | caught: fixture_malformed_truncated…, privacy_set_with_no_security_element… |
| m8 | RxStatus::Unknown grades | caught: fixture_rx_status_not_ok…, newer_sample_with_unverified_receive_status… |
| m9 | legacy_risk not set by a Valid WPA element | **survived the first pass** (same reason as m1); caught by the added case |
| m10 | Enterprise AKM next to PSK graded | caught: enterprise_akms_are_unrated… |
| m11 | pairwise Use-group not resolved | caught: use_group_pairwise_takes_the_group_cipher |
| m12 | SAE with PMF Disabled rated | caught: sae_without_pmf_capability_is_inconsistent (first attempt did not compile; edit fixed) |
| c1 | future instants accepted | caught: future_sample_is_rejected…, signal_is_scoped… |
| c2 | foreign epochs treated as live | caught: restored_record…, another_devices_epoch… |
| c3 | stale evidence graded | caught: live_sample_is_fresh…, delayed_sample… |
| c4 | historical record graded | caught: reboot_demotes…, restored_record… |
| c5 | channel capability unchecked | caught: channel_outside…, a_5ghz_capable_radio… |
| c6 | Unrelated frames accepted as security | caught: unrelated_frames_from_the_selected_bssid… |
| c7 | foreign-epoch reading displaces live | caught: restored_record…, another_devices_epoch… |
| c8 | Checking forever (no 30 s window) | caught: startup_shows_checking…, reboot_demotes… (first attempt did not compile; edit fixed) |
| c9 | drops do not degrade | caught: coverage_report_never_refreshes… |
| c10 | stale coverage report degrades | caught: stale_foreign_or_future_coverage_reports… |
| c11 | older sample replaces newer | caught: older_sample_arriving_after_a_newer_one… |
| c12 | a signal renews security evidence | caught: signal_readings_do_not_refresh… |

The first pass and the re-run of m1, m5, m9, m12, c8 and the control are both in
`mutation-check.log`. The two survivors were real test gaps (a WPA v1 + AES
network would have fallen to `Unspecified` instead of Bad); the policy code was
already correct for them, so the fix was a test, recorded in section 5 step 5.

## 8. Reviewer-grade run in the store (MEASURED)

`GUARDIAN_LIBWIFI_DIR=… GUARDIAN_JOBS=8 firmware/tools/host-check.sh all`, trees and
logs in `builds/20261114-121327-host-89oMKA/` (`host-check-stdout.log` in the
evidence root). `host-check exit=0`; `SHA256SUMS` over the 29 log/metadata files
verifies (`shasum -c`, 29 OK); the source hashes in `toolchain.txt` are identical to
the repository's `components/`, `tests/`, `examples/` and `CMakeLists.txt` at
handoff (diff empty). An earlier run `builds/20261114-121119-host-WkddU1/` was
stopped by the worker during configure because a test file changed after it
started (the mutation-check case); it holds no results and can be removed.

| Flavour | ctest | rating_check | core_check | core_baseline | contracts | parser_check | parser_oracle_libwifi |
|---|---|---|---|---|---|---|---|
| plain | 18/18 passed | 40 cases, 342 assertions, 0 failed | 29 cases, 180 assertions, 0 failed | 12 / 42 / 0 | 18 / 139 / 0 | 67 / 9303 / 0 (unchanged) | 4 / 182 / 0 |
| ASan + UBSan, no recovery | 18/18 passed, **no sanitizer report in any log** | same | same | same | same | same | same |

`headless_replay_runs` asserts the full sequence (fresh VeryGood at t=1000,
unrated `Unspecified` with `PmfNotRequired` at t=11000, stale at t=41000,
historical record after the clock reboot); its stdout is
`green-headless_replay-stdout.log`.

## 9. Limitations and open points (LIMIT)

- **Pending independent review**: G04 and G05 are worker handoffs inside the
  host batch; neither is accepted. No live or board evidence exists; every input
  is a fixture or a hand-built value.
- **StickS3 spike** `firmware/boards/sticks3/main/app_main.cpp` uses the pre-G05
  `Core(Origin)` / `snapshot(Millis)`; it needs a `MonotonicClock` adapter
  (esp_timer) and `RadioCapabilities::channels` at construction. Not built by the
  host harness; G10 owns the repair. The ESP-IDF sketch does not construct Core.
- **Hidden SSID identity** (section 3 DECISION): G14 decides how a picker approves
  both the hidden beacon identity and the named probe-response identity.
- **Coverage policy is minimal**: degraded = not tuned, any drop in the window, or
  a live core without Supported passive receive, evaluated only on a report younger
  than 30 s. Listening-time windows, hop accounting and their use in burst counting
  are G06. "Degraded clears the grade" is the G03 baseline behavior kept; G08
  decides how the overlay and the last grade are shown together.
- **Unspecified rows** (section 2): SAE-only with PMF Optional, WPA2-Personal with
  GCMP/CCMP-256. Deliberate; each is one comparison to relax.
- **ReceiveUnverified** blocks grading for `RxStatus::Unknown` (section 2 DECISION).
- **Signals are not yet produced by the application loop** beyond the example:
  `observe_signal()` exists and is tested; G06/G07 wire RSSI display and detector
  input.
- **Checking after an epoch change without re-select** shows `Stale`, not
  `Checking`: a rebooted application is expected to call `select()` again (the 30 s
  window restarts there).
- **Age across timebases is 0 by design**, flagged by `security_historical`; a
  WallClock label for "last seen" is display work (G07/G08), never an evidence clock.

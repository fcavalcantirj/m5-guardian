# G06 — portable disconnect-burst and baseline-change detectors (worker handoff, 2026-11-14)

## Supervisor review — 2026-11-14

G04–G07 passed independent host review after in-scope fixes. See
[G04–G07 validation](G04-G07-validation.md) for the failing regressions,
normal/sanitized results and limits. The original worker record below is
historical; it is not the acceptance record. No RF/device effectiveness is claimed.


Worker deliverable for ledger entry G06. **Pending independent review**; nothing
here is accepted, no device was flashed, no radio was used, every input is a
hand-assembled `Origin::Imported` fixture (or a fixture with its spoofable header
bytes patched in the test) and the clock is a fake. Labels: **MEASURED** =
executed on this Mac (Apple clang 21.0.0, cmake 4.1.2) with the log in the store;
**SOURCE** = read in the cited code or standard; **DECISION** = a product policy
choice made here, open to the reviewer; **LIMIT** = known gap left for its owner.

Evidence root: `$GUARDIAN_STORE/evidence-raw/G06-worker-20261114/`
(baseline, red/green logs, mutation check, hashes, MANIFEST.md). Reviewer build
trees and per-executable logs: `$GUARDIAN_STORE/builds/<run>`
(section 9). Dependencies used: the G04 parser and the G05 core/policy handoffs
(`awaiting_review` in `ralph/handoffs.json`); both were built and run here before
anything depended on them (baseline 17/17 ctest). Neither is independently
validated; this handoff inherits that status.

**Replay-only confidence.** Every case below passed on replayed bytes. That shows
the counting and comparison policy behaves as documented; it is not evidence that
a real deauthentication flood or a real rogue AP is detected on hardware, and
not a false-positive rate. Physical calibration is G13/L02 (section 10).

## 1. What was built

| File | Role |
|---|---|
| `firmware/components/guardian_core/include/guardian/detectors.hpp` | new: `SettingsFingerprint`, `ApprovedAp`, `ApprovedScope`, `DisconnectDetector`, `BaselineDetector`, `DisconnectStats`, `BaselineStats` |
| `firmware/components/guardian_core/detectors.cpp` | new: the implementation (sections 2–5) |
| `firmware/components/guardian_core/include/guardian/core.hpp` | `IncidentObservation` gained the evidence/uncertainty record (`bssid`, `threshold`, `raw_frames`, `retries_deduped`, `protected_frames`, `eapol_frames`, `saturated`, `coverage_known`, `listened_ms`, `coverage_window_ms`, `hopping`, `changes`); new `change::` bit constants. Additive: `Core` itself is unchanged |
| `firmware/components/guardian_core/include/guardian/detector.hpp` | `DetectorLimits` gained `dedupe_ms` (1000), `change_threshold` (2), `max_window_events` (128); the five G01 defaults are unchanged |
| `firmware/tests/detector_check.cpp` | new, 29 cases written and run RED first (section 7) |
| `firmware/tests/fixtures/make_fixtures.py` + 3 new `.hex` | `beacon()` takes `bssid` / `ds_channel` (defaults = the old constants; the 25 earlier fixtures regenerate byte-identically, MEASURED against the G05 run's hashes: 25 OK); new `beacon_wpa3_channel_11`, `beacon_wpa3_extender_bssid_56`, `beacon_same_ssid_other_bssid_wpa2` |
| `firmware/examples/headless_replay.cpp` | runs both detectors on the same frames through `Core` (explicit baseline from the first beacon, as a picker would offer it); the asserted output is unchanged (`incident=0`: no disconnect frames, one differing beacon is below `change_threshold`) |
| `firmware/CMakeLists.txt`, `components/guardian_core/CMakeLists.txt`, `firmware/tools/host-check.sh` | `detectors.cpp` in both builds, `detectors.hpp` in the self-containment list, `detector_check` target and per-exe log |
| `README.md`, `docs/contracts.md`, `firmware/examples/README.md` | pointers and the G01 rows closed by this task |

Not changed: `parser.cpp`, `rating.cpp`, `core.cpp`, presenter, canvas, the 25
earlier fixtures, the ledger, Ralph scripts, receipts. The presenter already
shows an incident over any mood and suppresses the celebration (G03 baseline
`incident_overlay_beats_celebration_and_keeps_the_face`); G06 proves the path
from frames to that view (section 6) and leaves presenter policy to G08.

## 2. Scope and ownership (what counts as "ours")

> **G16R amendment (2026-11-18, pending review).** For the disconnect burst, and for every later rule that
> asks "is this about the picked network", the scope is `ApprovedScope::in_network`: the selected BSSID, the
> approved list and the bounded set of BSSIDs heard advertising the picked network's exact name
> (`ApprovedScope::hear`, 8 entries, forgotten on a new pick). The baseline detector below still uses the
> approved scope only (`find`), so an unapproved same-name BSSID is still reported. Rules and limits:
> `guardian/detectors.hpp` and firmware/README.md, "Your network is its name".

> **G16S amendment (2026-11-19, pending review).** The disconnect detector also keeps a record of its last
> burst (`DisconnectDetector::last_burst`, `BurstRecord` in `guardian/shapes.hpp`): up to 8 tuples of
> receiver / sender / BSSID / channel with their counted frames, taken from the window ring when the threshold
> is reached (also inside a cooldown) and extended by every counted frame until a whole window passes without
> one. Ring entries carry the tuned channel for it. The report's `IncidentObservation::top` is the most
> frequent tuple at that moment. Counting, deduplication, thresholds and cooldowns are unchanged; the record
> is evidence about received header bytes, never an attribution. `sizeof(DisconnectDetector)` is 5,928 B on
> the host (limit 6 KiB, `tests/detector_check.cpp`). Format and limits: firmware/README.md, "Burst forensics".

> **G16T amendment (2026-11-19, pending review).** The disconnect detector itself is unchanged: its window,
> threshold, deduplication, cooldown and record still count only frames whose BSSID is the picked network's,
> and a few such frames report nothing. What changed is the nearby detector (`AreaDisconnectDetector`,
> `guardian/threats.hpp`): when one of its rules is reached and the same burst holds at least one counted
> disconnect frame naming the picked network in Address 1, 2 or 3, its report is `IncidentScope::Network`
> (`NetworkPattern`, red) with `IncidentObservation::own_frames` > 0, instead of Area. The measured reason
> (2026-11-19): a burst spread over a channel's access points left the picked network below this detector's
> threshold while the nearby rule was reached. One ordinary disconnect frame of the picked network inside a
> neighbour's burst therefore makes that burst red; the frames stay header bytes as received, never an
> attribution. Rule, record and wording: firmware/README.md, "A nearby burst that also names your network".
> `sizeof(DisconnectDetector)` is still 5,928 B.


`ApprovedScope` holds the selected network and up to `max_approved_aps` (8 by
default, 16 fixed storage) owner-approved related APs (mesh nodes, extenders),
each with optional, explicit baseline facts: a `SettingsFingerprint` and/or a
band + channel. **Nothing is learned from traffic**: entries come only from
`select()` / `approve()` calls (the picker/persistence in G08/G14), `approve()`
refuses when the list is full instead of growing, the selected BSSID is never
also a related entry, and a BSSID that appears on the air a hundred times is
still unapproved (case `approval_is_explicit_bounded_and_never_learned_from_traffic`).

A frame is in scope when its BSSID (Address 3 for management frames, the
To/From-DS choice for data, as G04 reports it) is the selected or an approved
AP. Both detectors emit `IncidentObservation::affected = selected network` (that
is Core's scope; `Core::incident` rejects anything else) and name the AP the
evidence was seen under in `bssid`. Header addresses are spoofable bytes; no
field of the record is a transmitter identity.

## 3. Disconnect bursts (`DisconnectDetector`)

| Rule | Implementation | Case |
|---|---|---|
| What counts | `Deauthentication` / `Disassociation` with `header_valid` and an in-scope BSSID | `frames_for_another_bssid_without_a_valid_header_or_of_other_kinds_are_not_our_evidence` |
| Window | sliding `window_ms` (10 s) anchored at the newest acquisition instant seen (frames or ticks); a delayed frame lands by its own instant | `twenty_disconnects_spread_over_more_than_the_window_are_no_burst`, `ticks_expire_the_window_without_traffic` |
| Threshold | deduplicated count ≥ `burst_threshold` (20) → `DisconnectBurst` with the frame that reached it as `acquired` | `nineteen_distinct_disconnects_in_ten_seconds_are_no_burst_the_twentieth_is` |
| Cooldown | after a report, no new report until `cooldown_ms` (60 s) after it; the next report carries what the window holds then, not a running total; `suppressed_by_cooldown` counts the rest | `a_sustained_burst_reports_once_per_cooldown_with_the_current_count` |
| Retry dedupe | a Retry-bit frame whose full header (subtype, Address 1, Address 2, BSSID, sequence, fragment) equals a **counted** observation within `dedupe_ms` (1 s) is a retransmission (`retries_deduped`, not counted). Without the bit, outside the gap, or without a seen original, it counts. The gap is measured from the counted observation, so a chain of copies cannot stretch it | `retry_copies_inside_the_dedupe_gap_are_retransmissions_not_new_observations`, `a_retry_without_a_seen_original_or_outside_the_gap_counts_and_the_bit_alone_drops_nothing` |
| Sequence numbers | never an identity: wrap (4095 → 0) and equal numbers without the Retry bit are distinct observations | `sequence_numbers_wrap_and_are_counted_as_distinct_observations` |
| Protected / malformed | counted from the header; `protected_frames` names how many had a protected body. **No reason code is read anywhere in G06** (the parser already refuses encrypted ones; the detector does not need readable ones either), no MIC is claimed | `protected_and_malformed_disconnects_count_from_their_header_and_no_reason_is_ever_read` |
| EAPOL context | unprotected LLC/SNAP 88-8E data frames in scope are stored as context (`eapol_frames` in the window) and never counted or evaluated | `eapol_after_disconnects_is_context_in_the_report_never_a_verdict` |
| Coverage | the latest same-epoch `CoverageReport` sampled inside the window rides with the report (`coverage_known`, `listened_ms`, `coverage_window_ms`, `hopping`); a gap (channel 0) shows as listened 0; an old/foreign/invalid report is "unknown", never a guess. Coverage never changes the count | `coverage_facts_ride_with_the_report_and_never_change_the_count` |
| Bound | ring of `max_window_events` (128 default, ≤ `capacity` 128) entries; when the evicted entry is still inside the window the report says `saturated` (count is a lower bound) until the window moves past it; `evicted_in_window` counts it | `bounded_state_saturates_and_says_so_instead_of_growing` |
| Time | the first valid instant fixes the epoch; foreign-epoch frames/ticks/reports and invalid instants are ignored and counted (`foreign_epoch`, `invalid_time`) and can neither count nor expire anything; `reset()` clears state, counters and the epoch | `foreign_epochs_and_invalid_instants_cannot_count_expire_or_renew_the_window` |
| Configuration | `configured()` is false for window 0, threshold 0, `max_window_events` 0 or > capacity, threshold > `max_window_events`, or a scope asking for more approved APs than its storage; a misconfigured detector counts and reports nothing | `defaults_are_configured_and_limits_that_cannot_be_honoured_are_refused_visibly` |
| Calibration (replay) | two minutes of a client leaving, a phone roaming to the approved extender, the AP rebooting with retransmitted broadcast deauths and clients re-keying: 6 counted, 7 deduped, 5 EAPOL, 0 reports | `benign_reconnects_roaming_retries_and_an_ap_reboot_do_not_report` |

**DECISION**: thresholds stay the G01/G02 hypotheses (10 s / 20 / 60 s, from the
AntiHunter constants recorded in docs/research/reuse-decisions.md); `dedupe_ms` =
1 s is a new hypothesis (802.11 retransmissions happen within milliseconds; a
copy a second later is not evidence of the same event). All are `DetectorLimits`
fields, tunable per board, and shown in every report (`window_ms`, `threshold`).
No two-tier (1 s / 12) window was added: one window with a documented threshold
is easier to calibrate in L02; a second tier is one more `DetectorLimits` field.

**DECISION**: `on_tick` only moves the anchor and prunes; it never emits. A
sustained burst re-reports on the next counted frame after the cooldown. An
adapter wanting "burst over" messages reads `in_window()` or Core's 60 s
visibility window.

## 4. Baseline changes (`BaselineDetector`)

`SettingsFingerprint::of(AdvertisedSettings)` is the typed comparison record the
G02 decision asked for instead of an IE-order hash: privacy bit; for each of the
WPA and RSN elements its state and, **only when Valid**, the AKM / pairwise kind
masks and group kind; RSN group-management kind and PMF (Unknown when no Valid
RSNE); OWE-transition element state. Element order, supported rates, DS channel,
HT/VHT, vendor elements and the SSID presentation are not part of it. `diff()`
returns `change::` bits (`Privacy`, `Wpa`, `Rsn`, `Pmf`, `OweTransition`) so the
report names the field, not a hash (case `settings_fingerprint_is_over_valid_fields_only_and_names_what_differs`:
WPA3 vs WPA2-PMF-optional = `Rsn|Pmf`; vs open = `Privacy|Rsn|Pmf`; an appended
vendor element changes nothing; a Truncated RSNE is a different state, never
zeroed into equality).

Only a **Complete, receive-verified** (`RxStatus::Ok`) Beacon / Probe Response
with a validated capability field is compared; everything else is
`skipped_incomplete` / `skipped_unverified` and proves nothing about a change
(case `incomplete_or_unverified_advertisements_prove_nothing_about_a_change`).

| Observation | Rule | Report |
|---|---|---|
| `SettingsChanged` | the selected or an approved AP whose fingerprint differs from its approved `settings` and/or whose DS channel or band differs from its approved `channel`/`band`; only approved facts are compared (`no_baseline` when none) | after `change_threshold` (2) differing advertisements inside `window_ms`; `count` = differing advertisements, `changes` = union of the differing fields in the window, `bssid` = the AP |
| `UnexpectedAp` | an unapproved BSSID advertising the selected SSID's exact bytes (hidden/absent SSIDs and other byte sequences are `neighbours`; a hidden selection matches no name) | after `change_threshold` such advertisements; `count` = distinct unapproved BSSIDs in the window (bounded by the 32-entry ring, `saturated` when exceeded), `raw_frames` = advertisements, `bssid` = the newest, `changes` = `Bssid` plus the differences against the **selected** AP's approved settings/channel when it has them |

Approved related APs are compared against their **own** baseline and never raise
`UnexpectedAp` (case `an_approved_extender_with_the_same_ssid_is_handled_like_the_selected_ap`);
cooldown, window, epoch handling and the bound work as for bursts (case
`baseline_reports_follow_the_window_cooldown_and_bound_like_bursts`).

What the record does **not** say, by construction: a `Bssid` change is "the
selected name from an AP the owner did not approve", not an evil twin; a
`Channel` change is "DS Parameter ≠ approved channel", not an attack; the
`Rsn|Pmf` bits are "weaker/other advertised options", not a downgrade attack;
RSSI is not an input to any incident (G07 shows it separately); "deauth
followed by EAPOL" is the `eapol_frames` context number in a burst report and
nothing else. No tool name, no transmitter identity, no "sniffer" claim exists
in the code or the types.

## Supervisor corrections to evidence admission

Both detectors bind to the first eligible frame's Origin until reset. Imported,
Demo and LiveRadio traffic cannot contribute to the same alert window; rejected
origins increment `foreign_origin` without moving time or cooldown state.
The application must reset on source/scope changes and supply ticks and coverage
from the same adapter pipeline. Core still independently checks the incident's
Origin. Disconnect counting now requires `RxStatus::Ok`, matching the baseline
comparator: unverified bytes increment `skipped_unverified`, never a burst.

## 5. Bounded resources (MEASURED by `static_assert` and the allocation ban)

`sizeof(DisconnectDetector) <= 6 KiB`, `sizeof(BaselineDetector) <= 2 KiB`,
`sizeof(ApprovedScope) <= 4 KiB` are asserted at compile time in
`detector_check.cpp`; every `on_frame` / `on_tick` / `coverage` call in the
checks runs with `operator new` replaced by `abort()` (as the G04 parser check
does), including the 300-frame saturation runs and the all-fixtures replay.
Per-frame work is a scan over at most `max_window_events` entries (bounded,
constant for a given configuration; the G01 "O(1) amortised" wording should be
read as "bounded by the configured ring", recorded here for the reviewer).

## 6. Through Core and the presenter (MEASURED)

`a_burst_reaches_core_and_stays_visible_over_a_very_good_rating_without_celebration`
and `an_unexpected_ap_reaches_core_with_its_evidence_and_the_grade_stays`: the
real `Core` receives the incidents through `ObservationSink`, `Snapshot::
incidents[kind]` is set with the full `evidence[kind]` record (count 20 / window
10000 / threshold 20 / acquired 2900), the fresh `VeryGood` grade stays, and
`present()` gives `Overlay::Incident`, `face = VeryGood`, `celebrate = false`;
with a degraded coverage report both facts stay visible (`incident_visible`,
`Overlay::CoverageDegraded`). Core's 60 s visibility and the 30 s freshness
expire independently; an Imported detector cannot raise an incident in a
`LiveRadio` core (`rejected.origin`).

**LIMIT (G08)**: the presenter still shows one overlay slot; when coverage is
degraded or stale the incident is only the `incident_visible` flag (pinned by
the G03 presenter baseline `incident_flag_is_visible_even_while_checking_or_stale`).
How count/window/uncertainty are rendered is G08's; the data is in `Snapshot::evidence`.

## 7. TDD record (MEASURED)

1. `before-sha256.txt`: every `firmware/` source before the task;
   `baseline-before-ctest-plain.log`: the pre-G06 tree, **17/17** ctest (plain).
2. Headers written first (`detectors.hpp`, the `IncidentObservation` /
   `DetectorLimits` additions), then a **stub** `detectors.cpp` (`ApprovedScope`
   plumbing in full, `SettingsFingerprint` returning zero, both detectors doing
   nothing), the CMake wiring, the three fixtures, then `detector_check.cpp`.
3. **RED** (`red-detector_check.log`, hashes in `red-sources-sha256.txt`): 29
   cases, **29 failed**, 191 failed assertions, exit 1; ctest 18/19 (only
   `detector_check` failed, `red-ctest-plain.log`).
4. Implementation written. First green attempt (`/tmp`, not kept as a file; the
   failures are recorded here): 24/29. Two **implementation** defects were found
   by the tests and fixed: (a) retry dedupe matched against an earlier
   *deduped* copy, so a chain of copies stretched the gap — now only counted
   observations anchor the gap; (b) a frame with an invalid header was
   classified by kind before the header check. Three **test** mistakes were
   corrected: the recording sink's `last()` was wrong past 64 reports; an
   invalid tick is (rightly) counted as `invalid_time` alongside the invalid
   frame; an Imported core never celebrates, so a pre-burst "celebrate" check
   was meaningless and became an "`overlay == None`, no incident" check.
5. **GREEN** (`green-*-plain-scratch.log`): `detector_check` **29/29, 396
   assertions** (409 after the two cases added by the mutation check, section 8); `contracts` 18/18, `core_check` 29/29, `core_baseline` 12/12,
   `rating_check` 40/40, `presenter_baseline` 10/10, `parser_check` 67/67 (9306
   assertions: the sweep now includes the 3 new fixtures), `fixture_loader_check`
   6/6 (485); ctest **18/18** plain and **18/18** ASan/UBSan with no sanitizer
   report (`green-ctest-*-scratch.log`, `green-*-asan-scratch.log`);
   `headless_replay` output byte-identical to the asserted pattern with the
   detectors wired in (`green-headless_replay-stdout.log`).
6. Refactor: none beyond comments; the code is as first written plus the two fixes above.

Scratch cmake trees in `/tmp` were deleted at the end; the reviewer-grade runs are
the store trees in section 9.

## 8. Mutation check: the tests bite (MEASURED, `mutation-check.sh` / `mutation-check.log`)

Twenty-eight deliberate defects on throwaway copies of `firmware/`, each built
and run against `detector_check`; the unmodified control copy passes (both passes
and the control are in `mutation-check.log`).

| Mutant | Edit | Result |
|---|---|---|
| d1 | threshold off by one (19 reports) | caught: nineteen_distinct…, retry_copies… |
| d2 | window ignored (count everything held) | caught: twenty_disconnects_spread…, a_sustained_burst… |
| d3 | Retry bit discards blindly (AntiHunter's rule) | caught: a_retry_without_a_seen_original…, benign_reconnects… |
| d4 | no dedupe at all | first edit did not compile (unused variable under -Werror; edit corrected), then caught: retry_copies…, a_retry_without… |
| d5 | dedupe ignores the time gap | caught: a_retry_without…, mixed_replay… |
| d6 | dedupe by sequence number only | caught: a_retry_without… (receiver-address copy), mixed_replay… |
| d7 | scope ignored (any BSSID counts) | caught: frames_for_another_bssid…, an_approved_extender_is_in_scope… |
| d8 | invalid header counted | caught: frames_for_another_bssid… |
| d9 | no cooldown | caught: a_sustained_burst… |
| d10 | foreign epoch accepted | caught: coverage_facts…, foreign_epochs… |
| d11 | saturation silent | caught: bounded_state_saturates… |
| d12 | EAPOL counted as disconnect | caught: benign_reconnects…, eapol_after_disconnects… |
| d13 | threshold > ring not refused | caught: defaults_are_configured… |
| d14 | coverage always "known" | caught: coverage_facts… |
| d15 | protected disconnects not counted | caught: protected_and_malformed…, mixed_replay… |
| d16 | tick does not move/prune the window | **survived the first pass** (no case observed the tick's effect); the late-drained-frame DECISION case was added to `ticks_expire_the_window_without_traffic`, now caught |
| b1 | learns the baseline from traffic | caught: approval_is_explicit…, no_approved_baseline… |
| b2 | Truncated/Malformed advertisements compared | caught: incomplete_or_unverified…, mixed_replay… |
| b3 | RxStatus not Ok compared | caught: incomplete_or_unverified… |
| b4 | PMF not in the fingerprint | caught: settings_fingerprint…, the_selected_ap_advertising… |
| b5 | channel ignored | caught: the_selected_ap_advertising…, an_approved_extender_with_the_same_ssid… |
| b6 | hidden SSID matches the selected name | caught: neighbours_with_other_or_hidden_ssids… |
| b7 | approved extender treated as unexpected | caught: approval_is_explicit…, an_approved_extender_with_the_same_ssid… |
| b8 | change threshold forced to 1 | caught: the_selected_ap_advertising…, the_selected_ssid_from_an_unapproved_bssid… |
| b9 | UnexpectedAp count = advertisements, not distinct BSSIDs | first edit did not compile (unused variable; corrected), then caught: the_selected_ssid_from_an_unapproved_bssid…, an_unexpected_ap_reaches_core… |
| b10 | approve() grows past max_approved_aps | caught: approval_is_explicit… |
| b11 | WPA element not in the fingerprint | caught: settings_fingerprint…, the_selected_ap_advertising… |
| b12 | fingerprint reads fields of non-Valid elements | **survived the first pass**: equivalent on parser output (G04 zeroes invalid element payloads); a hand-built Malformed/Conflicting `AdvertisedSettings` case was added to `settings_fingerprint…`, now caught |

The two survivors were test gaps, not policy defects (the code already behaved as
documented); the fix in each case was a test, recorded in section 7 step 5 counts
(409 assertions after the additions).

## 9. Reviewer-grade run in the store (MEASURED)

`GUARDIAN_LIBWIFI_DIR=… GUARDIAN_JOBS=6 firmware/tools/host-check.sh all`, trees and
logs in `builds/20261114-130008-host-k5Shp3/` (`host-check-stdout.log` in the
evidence root). `host-check exit=0`; `SHA256SUMS` over the 31 log/metadata files
verifies (`shasum -c`, 31 OK); the 73 source hashes in `toolchain.txt` are
identical to the repository's `components/`, `tests/` (fixtures included),
`examples/` and `CMakeLists.txt` at handoff (no mismatch).

| Flavour | ctest | detector_check | parser_check | rating_check | core_check | contracts | fixture_loader_check | parser_oracle_libwifi |
|---|---|---|---|---|---|---|---|---|
| plain | 19/19 passed | 29 cases, 409 assertions, 0 failed | 67 / 9306 / 0 | 40 / 342 / 0 | 29 / 180 / 0 | 18 / 139 / 0 | 6 / 485 / 0 | 4 / 182 / 0 |
| ASan + UBSan, no recovery | 19/19 passed, **no sanitizer report in any log** | same | same | same | same | same | same | same |

`headless_replay_runs` asserts the unchanged eight-line sequence with both
detectors wired in (`incident=0` throughout).

## 10. Limitations and open points (LIMIT)

- **Replay-only confidence**: no live, no board, no physical false-positive
  rate. G13 records normal-traffic false positives; L02 calibrates the
  thresholds against the lab rig. Until then every number in `DetectorLimits`
  is a hypothesis with provenance, not a signature.
- **G04/G05 unreviewed**: this task depends on both handoffs; a change in the
  parser's `header_valid`, `identity.bssid`, `kind` or `protected_frame`
  semantics changes what these detectors count.
- **One window, one threshold** per detector (DECISION, section 3). A second
  tier (AntiHunter's 1 s / 12) is one more field if L02 shows it is needed.
- **Dedupe is header equality within 1 s**: a flood that varies the sequence
  number or the receiver address per frame is counted in full (by design: that
  is observed disconnect traffic); a flood that repeats one exact header with
  the Retry bit every 900 ms is counted once per second (documented heuristic).
- **UnexpectedAp needs the SSID bytes in the advertisement**: an unapproved AP
  that hides its SSID and answers probes is seen only through its probe
  responses (`ProbeResponse` is compared like a beacon). Owner-approved hidden
  selections match no name (G05's byte-identity decision, G14 owns the picker).
- **Fingerprint granularity**: kind masks, not raw selectors; two different
  unmapped selectors compare equal (both `Unknown`), and a vendor-specific
  cipher swap between two unknown selectors is not a reported change.
- **Band in the channel comparison** uses `RxMeta::band` (the tuned band), the
  only band the adapter knows for a beacon; the DS Parameter element carries a
  channel number only.
- **Coverage in the report is the adapter's latest report** sampled inside the
  window; listening-time accounting per burst (how much of *this* window was
  listened) needs the adapter to report at least once per window (G13 cadence).
- **Presenter**: one overlay slot (section 6, G08).
- **StickS3 spike** (`boards/sticks3/main/app_main.cpp`) is unchanged and still
  pre-G05; G10 wires `ApprovedScope` and the detectors there.

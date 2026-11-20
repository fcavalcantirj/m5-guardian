# G07 — evidence-based advice without overstating Wi-Fi health (worker handoff, 2026-11-14)

## Supervisor review — 2026-11-14

G04–G07 passed independent host review after in-scope fixes. See
[G04–G07 validation](G04-G07-validation.md) for the failing regressions,
normal/sanitized results and limits. The original worker record below is
historical; it is not the acceptance record. No RF/device effectiveness is claimed.


Worker deliverable for ledger entry G07. **Pending independent review**; nothing
here is accepted, no device was flashed, no radio was used, no network request
was made, every input is a hand-assembled `Origin::Imported` fixture or a
hand-built `Snapshot`, and the clock is a fake. Labels: **MEASURED** = executed on
this Mac (Apple clang 21.0.0, cmake 4.1.2) with the log in the store; **SOURCE** = read
in the cited document; **DECISION** = a product policy choice made here, open to
the reviewer; **LIMIT** = known gap left for its owner.

Evidence root: `$GUARDIAN_STORE/evidence-raw/G07-worker-20261114/`
(baseline, red/green logs, mutation check, hashes, MANIFEST.md). Reviewer build
trees and per-executable logs: `$GUARDIAN_STORE/builds/<run>`
(section 9). Dependencies used: the G05 core/policy and G06 detector handoffs
(`awaiting_review` in `ralph/handoffs.json`); both were built and run here before
anything depended on them (baseline 18/18 ctest, plain, no libwifi oracle in the
baseline tree). Neither is independently validated; this handoff inherits that
status.

## 1. What was built

| File | Role |
|---|---|
| `firmware/components/guardian_core/include/guardian/advice.hpp` | new: `advise(Snapshot[, ConnectivityResult])` -> `Advice`; `AdviceId`, `NextStep`, `OwnerCheckId`, `Verification`, `SignalView`; the contract-only `ConnectivityProbePlan` / `ConnectivityResult`; `advice_text()` |
| `firmware/components/guardian_core/advice.cpp` | new: the reduction and the simple-language texts (sections 2–6) |
| `firmware/components/guardian_core/include/guardian/core.hpp` | additive: `Snapshot::signal_interval_known` / `signal_interval_ms`; two private `Core` fields |
| `firmware/components/guardian_core/core.cpp` | `Core::signal()` computes the interval between the last two accepted live samples of the same epoch; `select()` resets it; `snapshot()` exports it with the signal (section 3) |
| `firmware/tests/advice_check.cpp` | new, 24 cases written and run RED first (section 7; the 24th and one assertion block came from the mutation check, section 8) |
| `firmware/CMakeLists.txt`, `components/guardian_core/CMakeLists.txt`, `firmware/tools/host-check.sh` | `advice.cpp` in both builds, `advice.hpp` in the self-containment list, `advice_check` target and per-exe log |
| `README.md`, `docs/contracts.md` | pointers (current state, layout, dependency arrow, header row) |

Not changed: `parser.cpp`, `rating.cpp`, `detectors.cpp`, presenter, canvas,
fixtures, `headless_replay.cpp` (its asserted output is unchanged; wiring
`advise()` into it would change the asserted line and is left to G08, which owns
the view model), the ledger, Ralph scripts, receipts. No new app, website, account
or companion service; the advice is a value type the G08 presenter and a board
renderer consume.

## 2. What the advice says (and from what)

`advise()` is a pure reduction of a `Snapshot`. Every item is an `AdviceId` code
with one static-storage text (`advice_text()`, string literals, no allocation;
the renderer wraps). Display order = the order `push()` is called:

1. **Current incidents** (`Snapshot::incidents[k]`): `DisconnectTrafficObserved`,
   `UnexpectedApObserved`, `SettingsChangeObserved`. Texts name the benign causes
   (router reboot, roaming, interference; an unapproved extender or a neighbour's
   router) and say "not proof of an attack". `Advice::transmitter_identity` is
   always `NotMeasured`: no field ever names who sent a frame.
2. **State of the evidence**: `LastKnownFromEarlierBoot` when
   `security_historical`; then `NoSampleYet` (Checking), `NoFreshData` (Stale) or
   `ListeningDegraded` (Degraded). The degraded/stale texts point at this device's
   listening ("the network is not judged").
3. **Why there is no grade** (Fresh only), one per `Unrated` reason:
   `IncompleteAdvertisement` ("does not mean the network is open"),
   `ReceiveUnverified`, `UnknownOptionAdvertised` ("known weaker options are still
   shown"), `ContradictoryAdvertisement`, `OweNotPlainOpen` ("not the same as an
   open network"), `EnterpriseNotRated`, `OutsideDocumentedRows` (+ `PmfNotRequired`
   when the G05 reason is `PmfNotRequired`, i.e. SAE-only with PMF optional).
4. **What the advertised settings mean** (Fresh only), from the G05 mood/reason
   (SOURCE for the wording: Apple router guidance, Espressif Wi-Fi security guide,
   via docs/research/wifi-audit.md):

| Mood / reason | Item | Next step |
|---|---|---|
| VeryGood / StrongSettings | `Wpa3Strong` ("the preferred setting") | `KeepRouterUpdated` (owner check) |
| Good / Wpa2PmfRequired | `Wpa2AesPmfRequired` ("WPA3 is the stronger option") | `ConsiderWpa3` |
| Medium / PmfNotRequired | `PmfNotRequired` (devices that skip PMF can be disconnected by forged frames) | `RequirePmfOrEnableWpa3` |
| Medium / CompatibilityMode | `TransitionIsCompatibility` ("a reasonable compatibility choice … Not broken") | `MoveToWpa3OnlyWhenReady` |
| Bad / Legacy | `LegacyWpaTkip` ("deprecated and weak") | `RemoveWpaTkip` |
| Horrible / Unencrypted | `OpenUnencrypted` ("anyone nearby can read this traffic") | `EnableWpa2AesOrWpa3` |
| Horrible / Legacy, WEP in the weakest-advertised summary | `WepIsBroken` | `ReplaceWep` |
| unrated, `legacy_risk` set | the legacy item above is still pushed (G05's separately confirmed finding survives a blocked grade) | `RemoveWpaTkip` / `ReplaceWep` |

5. **No credit**: `HiddenSsidOrMacFilteringNoCredit` when the fresh reading's
   `ssid_kind` is `Hidden`. The mood is identical to the visible network's (case
   `hidden_ssid_gets_no_credit_and_rates_the_same_as_the_visible_network`, real
   parser on `beacon_hidden_ssid_wpa2` vs `beacon_wpa2_ccmp_pmf_optional`: both
   Medium / PmfNotRequired / `RequirePmfOrEnableWpa3`). MAC filtering has no input
   anywhere in the library, so it cannot earn anything; the text says so.
6. **Local and not measured**: `SignalIsLocalOnly` whenever a signal reading
   exists; `ConnectionNotMeasured` (or `EndpointFailureIsNotWifiFailure`, section
   5); `PasswordStrengthNotMeasured` over fresh evidence ("never asked for").

**Exactly one `NextStep`**, from the most current evidence down: disconnect burst
> unexpected AP > settings change > historical (`WaitForLiveSample`) > Checking
(`KeepListening`) > Stale/Degraded (`CheckDeviceListening`) > unrated with a
confirmed legacy risk (`RemoveWpaTkip` / `ReplaceWep`) > unrated
(Incomplete/ReceiveUnverified/Inconsistent -> `WaitForAnotherSample`; UnknownOption/
Owe/Enterprise/Unspecified -> `NotRatedByPolicy`) > the rated rows above.

**The mood is copied, never recomputed** (`Advice::mood/reason/unrated` are
`Snapshot::settings` fields), and **DECISION**: it is reported only when
`coverage == Fresh`. Core already blanks the `Assessment` when stale or degraded;
`advise()` additionally refuses to show a grade a hand-assembled or future
`Snapshot` might still carry (mutation a6 found this gap, section 8). Nothing in
`advise()` reads RSSI, AP counts, the connectivity result or the owner checks to
choose the mood or an item about the settings.

Texts are guarded by a banned-word check (`texts_never_claim_an_attacker_safety_or_a_password_verdict`):
no "attacker", "hacker", "safe", "unhackable", "secure network", "evil twin",
"sniffer", "password is", "strong/weak password", "Internet is down", "no
Internet" anywhere in the advice, next-step or owner-check texts; every id has a
non-empty, distinct text of at most 200 characters (next steps 120).

## 3. Signal at this device (`SignalView`)

From `Snapshot::last_signal` / `signal_age_ms` plus the new interval fields:
`available`, `rssi_valid`, `rssi_dbm` (0 when the adapter marked it invalid),
`age_ms`, `interval_known`, `interval_ms`, `band`, `channel`. The struct has no
field for speed, congestion, Internet access, interference or coverage, and the
text says the value is what this device receives here.

**Core change (additive)**: the sampling interval is the gap between the
acquisition instants of the last two accepted live signal samples of the same
epoch (`Core::signal()`); unknown after one sample, after `select()`, and for the
first sample after an epoch change; a rejected older sample (queue reordering)
does not disturb it; a late-drained sample is measured by its acquisition instant,
not the drain time (mutation c3, section 8). It never touches security evidence:
the signal cases assert the beacon's `age_ms` keeps counting while deauth frames
refresh the signal (G05 rule unchanged).

Reviewer line, executable: `good_rssi_cannot_improve_the_grade_and_bad_rssi_cannot_lower_it`
feeds the same Medium advertisement at -30 dBm and -92 dBm and the open network
at -30 dBm through the real parser and Core: Medium stays Medium, Horrible stays
Horrible, `connection_health` stays `NotMeasured`.

## 4. Owner checks (`OwnerCheck`, always Unverified)

Seven items in ledger order (SOURCE: FTC home Wi-Fi guidance via wifi-audit.md):
long unique Wi-Fi passphrase; unique router-admin credentials; supported firmware
with updates; WPS off unless needed ("seeing WPS advertised proves nothing either
way"); remote administration off; UPnP off unless needed; guest and smart-home
separation ("a guest name alone does not prove isolation"). Listed on every
Snapshot, even an empty one, each with `Verification::Unverified`; a later
authorized router integration could set `Observed`. No owner check is an input to
anything: the case `owner_checks_are_the_seven_ledger_items_all_unverified_and_never_change_the_mood`
runs them against Unknown, VeryGood and Horrible snapshots. `password_strength`
is a constant `NotMeasured`; there is no input for a password, a dictionary test
or a cracking result anywhere in the library.

## 5. Later associated probes: contract only (no implementation)

`ConnectivityProbePlan` fixes, before any implementation: user-visible opt-in
(off by default), `CredentialSource::OwnerEntered` (stored by the board's
key-value adapter; the passive path never reads it, no mood for having it),
destinations (DHCP gateway, one DNS name, one HTTPS host — named, never learned
from traffic), per-step timeout (3 s default), probe interval (10 min default),
and the longest allowed interruption of passive listening (15 s default), which
must be reported through `CoverageReport` (channel 0 / `listened_ms`), never
hidden. `ConnectivityResult` carries `Support measured` (v1: `Unsupported`), the
sample instant and three `EndpointState`s with timings.

`advise()` echoes the result and labels it: `connection_health` is `Observed`
only when `measured == Supported` **and** at least one endpoint was sampled;
`Support::Unknown` is never Observed. A `Failed`/`TimedOut` endpoint adds
`EndpointFailureIsNotWifiFailure` ("a fact about that endpoint, not by itself a
Wi-Fi problem or an attack") and changes nothing else: the mood, the next step and
the incident list are identical to the passive advice (cases
`connection_health_is_not_measured_in_passive_v1_and_a_failed_endpoint_is_not_an_attack`,
`absent_sensor_data_or_lost_internet_cannot_imply_an_rf_attack_or_password_strength`:
nothing selected + Internet gone, stale + Internet gone, degraded + Internet gone
-> no incident item, mood Unknown). Reached endpoints add no security credit.

## 6. Bounds

`Advice` is trivially copyable, `sizeof(Advice) <= 512` (static_assert), at most
`max_items = 12` items with no duplicates (`push()` refuses both), the busiest
realistic snapshot (hidden network, legacy risk under an unknown option, three
incidents, signal, failed probe) fits without truncation
(`items_are_bounded_ordered_and_free_of_duplicates_on_the_busiest_snapshot`). No
allocation, no time read, no SDK include (portability_check passes with the new
files: 22 portable sources).

## 7. TDD record (MEASURED)

1. `before-sha256.txt`: every `firmware/` source before the task;
   `baseline-before-ctest-plain.log`: the pre-G07 tree, **18/18** ctest (plain).
2. `advice.hpp` written first, then the `Snapshot`/`Core` interval fields, a
   **stub** `advice.cpp` (returns `Advice{}`, texts ""), the CMake wiring, then
   `advice_check.cpp` (23 cases).
3. **RED** (`red-advice_check.log`, `red-ctest-plain.log`, hashes in
   `red-sources-sha256.txt`): **23/23 cases failed**, 340 of 464 assertions, exit
   1; ctest 18/19 (only `advice_check`). Honesty note: the `Core::signal()`
   interval logic was already written at that point, so the interval assertions
   are not red in that log. The isolating failing-before for the Core change is
   `red-core-interval-skeleton.log`: the REAL `advice.cpp` against a `core.cpp`
   with the interval fields declared but never computed -> exactly the two
   interval cases fail, **6 assertions**, all of them `interval_known` /
   `interval_ms` (nothing else in the suite depends on the Core change).
4. Implementation written. First green attempt: 21/23; the two failures were a
   **test** mistake (incidents injected with an acquisition instant 200 ms after
   the fake clock's now, which Core rightly rejects as `future`; the clock is now
   advanced first). No policy change.
5. **GREEN** (`green-*-plain-scratch.log`): `advice_check` 23/23 (280
   assertions; **24/24, 304** after the mutation-check additions), every other
   executable unchanged (`contracts` 18/18, `core_check` 29/29, `core_baseline`
   12/12, `rating_check` 40/40, `detector_check` 29/29, `presenter_baseline`
   10/10, `parser_check` 67/67, `fixture_loader_check` 6/6); ctest **19/19**
   plain and **19/19** ASan/UBSan with no sanitizer report
   (`green-ctest-*-scratch.log`, `green-advice_check-asan-scratch.log`), re-run
   on the final code after step 8; `headless_replay` output unchanged
   (`green-headless_replay-stdout.log`).
6. Refactor: the not-fresh grade blanking (section 2 DECISION) was added after
   mutation a6; otherwise the code is as first written.

Scratch cmake trees in `/tmp` were deleted at the end; the reviewer-grade runs
are the store trees in section 9.

## 8. Mutation check: the tests bite (MEASURED, `mutation-check.sh` / `mutation-check.log`)

Fifteen deliberate defects on throwaway copies of `firmware/`, each built and run
against `advice_check`; the unmodified control copy passes. First pass: 12 caught,
2 survived, 1 did not compile (the edit left `legacy_named` set-but-unused under
`-Werror`; rewritten as the real defect). Second pass over the final code: all 15
caught (a1 re-run alone after its pattern was corrected for the new mood line).

| Mutant | Edit | Result |
|---|---|---|
| a1 | a strong RSSI promotes Medium to Good | caught: good_rssi_cannot_improve… |
| a2 | a disconnect burst is not listed | caught: incidents_are_reported…, two_current_incidents…, items_are_bounded… |
| a3 | a burst does not set the next step | caught: same three |
| a4 | a hidden SSID lowers the mood | caught: hidden_ssid_gets_no_credit…, items_are_bounded… |
| a5 | owner checks marked Observed | caught: owner_checks_are_the_seven… |
| a6 | settings items shown while not fresh (`fresh || has_security`) | **survived the first pass** (Core already blanks the Assessment, so no fixture reaches it); case `a_snapshot_that_still_carries_a_grade_while_not_fresh_shows_no_grade` added and `advise()` now reports mood/reason/unrated only when Fresh; caught |
| a7 | legacy risk kept only when rated | first edit did not compile; corrected edit caught: a_confirmed_legacy_risk…, items_are_bounded… |
| a8 | transition mode called legacy | caught: hand_built_rows… |
| a9 | the burst text says "an attacker is sending them" | caught: texts_never_claim… |
| a10 | duplicate items allowed | caught: two_current_incidents…, items_are_bounded… |
| a11 | `Support::Unknown` counts as Observed | caught: connection_health_is_not_measured… |
| a12 | a failed endpoint sets the burst next step | caught: connection_health…, absent_sensor_data… |
| c1 | Core never computes the interval | caught: signal_view_shows…, signal_interval_survives… |
| c2 | interval computed across epochs | caught: signal_interval_survives… |
| c3 | interval measured from the clock's now instead of the sample instants | **survived the first pass** (every test drained its sample at its acquisition instant); the second sample in `signal_view_shows…` is now drained 500 ms late; caught |

## 9. Reviewer-grade run in the store (MEASURED)

`GUARDIAN_LIBWIFI_DIR=… GUARDIAN_JOBS=6 firmware/tools/host-check.sh all`, trees and
logs in `builds/20261114-133804-host-jvp0ul/` (`host-check-stdout.log` in the
evidence root). `host-check exit=0`; `SHA256SUMS` over the 33 log/metadata files
verifies (`shasum -c`, 33 OK); the source hashes in `toolchain.txt` are identical
to the repository's `components/`, `tests/` (fixtures included), `examples/` and
`CMakeLists.txt` at handoff (diff empty).

| Flavour | ctest | advice_check | core_check | rating_check | detector_check | contracts | parser_check | parser_oracle_libwifi |
|---|---|---|---|---|---|---|---|---|
| plain | 20/20 passed | 24 cases, 304 assertions, 0 failed | 29 / 180 / 0 | 40 / 342 / 0 | 29 / 409 / 0 | 18 / 139 / 0 | 67 / 9306 / 0 | 4 / 182 / 0 |
| ASan + UBSan, no recovery | 20/20 passed, **no sanitizer report in any log** | same | same | same | same | same | same | same |

`core_baseline` 12/42/0, `presenter_baseline` 10/48/0, `fixture_loader_check`
6/485/0 and `headless_replay_runs` (unchanged eight-line pattern) also pass in both
flavours.

## 10. Limitations and open points (LIMIT)

- **Pending independent review**: G05/G06 are worker handoffs; this depends on
  both. No live or board evidence exists; every input is a fixture or a
  hand-built value, so the texts have been checked against fixture evidence only.
- **Presenter integration is G08**: `present()` and `ViewModel` are unchanged;
  the one-overlay-slot limit from G06 stands. G08 decides how `Advice::items`,
  `next_step`, `SignalView` and the owner checks are laid out and how the
  historical/DEMO labels (presenter policy, not advice) accompany them. Wiring
  `advise()` into `headless_replay` is left to G08 for the same reason.
- **Texts are English only and sized for a 40-column 5x7 display by wrapping**,
  not by a measured layout; G08/G15 measure. Nothing is localized.
- **`SignalView::interval_ms` is between accepted samples**, i.e. frames Core
  accepted for the selected BSSID; a frame rejected for channel/origin/time does
  not count as a sample. It is not the adapter's dwell cadence (that is
  `CoverageReport`).
- **Connectivity probes are a contract**: no code associates, resolves or
  fetches; the defaults in `ConnectivityProbePlan` are hypotheses to revisit when
  the probe is implemented (after v1, if ever).
- **Hand-built rows**: Good, Transition, WEP, SAE-with-PMF-optional and
  Inconsistent have no fixture (no WEP/transition fixture exists in
  `tests/fixtures`); their cases hand-build the `Snapshot` as Core would produce
  it. Adding fixtures for them is G04/G05's generator work.
- **`Horrible / Legacy` without a WEP indicator** in the weakest-advertised
  summary cannot be produced by `assess()`; `advise()` falls back to
  `LegacyWpaTkip` there (defensive, untested because unreachable from Core).
- **Mood blanking when not Fresh** (section 2 DECISION) duplicates Core's
  behavior on purpose; if the reviewer prefers a single source of truth the
  three lines in `advise()` and the case named in section 8 (a6) are the change.

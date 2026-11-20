> Current update — 2026-11-19: G22 integrated review (worker's own review plus the independent Claude review) is
> recorded in the first section below. Acceptance of every row stays in `guardian-tasks.json`; a review passes nothing.
> The 2026-11-15 note ("G13 accepted, next is G14") and everything under "Task acceptance" are history.

# Review status

## G22 integrated review (2026-11-19, Ralph task 42; pending supervisor validation)

Scope: the integrated product as it stands in this tree (ledger, portable library since G09, adapters, StickS3 board
code, device/art/performance evidence). Labels: **[SOURCE]** read in the code this session, **[RUN]** executed this
session, **[RECORD]** read in a ledger/evidence record (not re-measured), **[UNKNOWN]** not measured by anyone yet.

### What was checked (own review)

- [RUN] Ledger structure: 43 rows, unique ids, every dependency exists and precedes its row, no accepted row depends
  on an unaccepted one. Open rows: G16H, G22, G23.
- [RUN] Python tool and build-support tests: `python3 -m pytest -q tools/tests firmware/boards/sticks3/tests` = 145 passed.
- [RUN] Full host check of the current tree, plain and ASan/UBSan: see "Host check of the reviewed tree" below.
- [SOURCE] Read in full: `guardian_core` `parser.cpp`, `detectors.cpp` + `detectors.hpp`, `threats.cpp`, `datapath.cpp`,
  `ble.cpp`; adapters `setup/setup.cpp`, `companion/inflate.cpp`, `tune/session.*`; the update / self-fetch / setup
  paths of `boards/sticks3/main/measurement_main.cpp`. Not read line by line: presenter, canvas, persona/burst/motion
  art code, power, IMU, OTA state machine, measurement adapter, the test sources (1.17 MB).
- [SOURCE] No out-of-bounds read or write found in the files read in full: every index is checked against the span
  or a fixed capacity before use (parser cursor and element walks, EAPOL key data, BLE AD structures, form decoder,
  name-service answer, inflater). This is a reading, not a proof; the sanitized host run is the executed evidence.

### Findings (own review)

Severity is the worker's proposal. "Open" means no change was made by this task.

| # | Sev | Finding | Evidence | State |
|---|-----|---------|----------|-------|
| O1 | high | **The unattended self-fetch pauses listening and can open a TUNE session nobody confirmed.** `ota.auto_s` defaults to 120 s. Every 120 s the main loop calls `run_update()` with no key press: it stops the survey and the receiver, joins the stored Wi-Fi (join timeout 20 s), fetches `tune/offer` over plain HTTP (4 s), and when an offer is served starts a TUNE session of up to 1800 s with monitoring paused. The offer and the commands are not authenticated (the session id comes from the server). `TUNE <key> <value>` is accepted in a session, is applied at once and persisted in NVS, and reaches `detect.burst` (to 128), `detect.twin` (to 0), `detect.window_ms`, every `t.*` threshold and `ota.auto_s` itself. So any host that answers at the provisioned URL (the Mac's address while the Mac is off, or a spoofed one) can silence the detectors persistently and pause listening for 30 minutes at a time, with no gesture on the stick. The signed image check still protects the firmware itself. `adapters/tune/session.hpp` still says "Entry is exactly the UPDATE entry (G16B): the owner's gesture ... then the on-screen yes", which is no longer true. | [SOURCE] `measurement_main.cpp` 294-295, 1271-1298, 1590, 1783-1788; `adapters/tune/session.hpp` 9-23, `session.cpp` `allowed()`; `tune.hpp` 9 | Open. Owner decision (his deploy loop depends on it). Options: (a) `ota.auto_s` default 0 in the delivered image, the lab sets 120 by TUNE; (b) the self-fetch path takes signed images only and a TUNE offer needs the gesture; (c) sign the offer with the OTA key. Recommended: (b) plus (a) for G23. **G22A (2026-11-19, pending supervisor validation and the device): option (c) implemented, signed offers only; see `firmware/README.md`, "Self-fetch OTA and TUNE: signed offers only".** |
| O2 | medium | **The self-fetch pause is not among the stated blind spots and its length is not measured.** `firmware/README.md` (G16N limits) says the poll "still pauses listening for its join in every state"; the list "What it cannot see" in `docs/attack-coverage.md` and the Limits page on the glass (`screens.cpp` `DetailsPage::Limits`) did not mention it. After a poll the radio resumes through a new channel survey (`companion_radio_resume` -> `survey.begin`), so the gap is join + fetch + survey + relock. | [SOURCE] `measurement_main.cpp` 1245-1255, 1276-1285; `screens.cpp` 517-538. [UNKNOWN] seconds of listening lost per 120 s, with the Mac serving and with it off | Doc line added to `docs/attack-coverage.md` by this task. Glass text and the measurement stay open (a glass line needs host goldens, a board build and the device). |
| O3 | medium | **G23 does not carry every "CARRY-OVER into G23" that accepted rows name.** G23 lists G16O, G16M, G16N, G16Q. Missing: G16D (BATTRUN on battery, 10 sleep/wake cycles, 10-minute runs, DEMO and video checks), G16F (karma with the SD list, auth/SAE flood live proofs, 12 h benign soak reading), G16G (device load with the data path off/on, the owner's live deauth + reconnect proof), G16I (shake-burst and upright checks on the glass with `motion.upright=1`), G16J (data-path load spike, sweep-loss spike, the live matrix rows with the owner's kit, the 12 h soak at the new defaults). | [RECORD] acceptance notes of those rows against G23's steps in `guardian-tasks.json` | Open. Suggested ledger amendment (supervisor): add one CARRY-OVER step per row to G23, text copied from each acceptance note. |
| O4 | medium | **G21 is accepted without the device items of its own Verify step.** The step asks for 20 fps or more with the head turning (`FRAMES kind=rated`), no flicker at a grid boundary, `heap_internal_min` / `task_stack_free`, a 30-minute soak across five moods, evidence in `firmware/evidence/sticks3-G21-*.log`. No such file exists. The acceptance note records the pipeline, a booted image and one inflate of 14.8 ms, then the owner's ruling that the 3D frames are not the approved design (`head.on=0`). Only two moods have a 3D set (`firmware/art/persona/v3/frames`: `VeryGood.bin`, `Medium.bin`). | [RUN] `ls firmware/evidence`, `ls firmware/art/persona/v3/frames`. [RECORD] G21 steps | Open. The row's accepted scope should say "pipeline + firmware path, head off by default; device performance with the head on not measured" (an `accepted_scope` field like G10-G12 have). |
| O5 | medium | **G23 still asks for "one video showing all five 3D expressions" and G15's description says "3D persona"; the accepted art is the five 2D v4 portraits plus the red ALERT treatment.** All five requested states exist and are pinned (Very good with grin and cigar, Good, Medium, Bad, Horrible; `persona_check`), and the portable architecture is intact. The contradiction is in the wording of the delivery row, which cannot be met as written while `head.on=0` and three moods have no 3D set. | [RECORD] G15, G21, G23 text; README G15 paragraph | Open. Owner/supervisor wording decision before G23 runs. |
| O6 | low | **README, `docs/ledger-order.md` and this file's older sections are stale against the ledger.** README "Current state" stops at G16B ("Next: G16C", "22/22"); nine README bullets still say "pending review" / "nothing is proven on the stick" / "pending the glass comparison" for rows the ledger has accepted with device records (G16J, G16M, G21, G16O, G16P, G16Q, G16R, G16S, G16T). `docs/ledger-order.md` opens with "G13 is next". Below, "G13 validation in progress ... not accepted" contradicts the accepted row. | [RUN] read of the three files against `guardian-tasks.json` | Header of this file corrected. README and ledger-order left to the supervisor (each bullet needs the wording of its own acceptance note). |
| O7 | low | **The host check does not pin everything it compiles.** `firmware/tools/host-check.sh` writes sha256 of `components tests examples CMakeLists.txt`, while `firmware/CMakeLists.txt` also builds `adapters/*` (companion, measurement, tune, ota, setup, power, imu, coex) and files of `boards/sticks3/main` (`art_bench.cpp`, headers). A change there leaves the recorded source hashes unchanged. | [SOURCE] `host-check.sh` toolchain block; `CMakeLists.txt` 96-320 | Fixed by this task (see "Changes made"). |
| O8 | low | **`tools/review-with-claude.py` was pinned to `claude-fable-5-1`** while the ledger pins `claude-fable-5-2` for G22, and it had no scope for the integrated product. | [SOURCE] the tool, G22 step 3 | Fixed by this task. |
| O9 | low | **Scope by 32-bit name hash.** `OweTwinDetector` decides Network scope by comparing FNV-1a hashes of the SSID with the selected name, and the G16F/G16J name tables compare hashes only. A collision would mislabel a name; the contracts ask for exact byte identity of the network. No collision was constructed. | [SOURCE] `threats.cpp` 705-706, `name_key` | Open, low. Suggested: compare the bytes where the selected network's SSID is at hand. |
| O10 | low | **Single-frame red.** One receive-verified frame is enough for a Network incident in three rules: a switch announcement with count >= 50, a Quiet element >= 1000 TU, and (data path on) one handshake start with an all-zero nonce or template PMKID (`fake_m1=1`). Header addresses are spoofable, so one forged frame turns the face red for the cooldown. The text says what was received, which is true; the cost is nuisance alerts, not a false claim. | [SOURCE] `threats.cpp` 566-584, `datapath.cpp` 164-181, `ThreatLimits` defaults | Open. Calibration decision; no benign-soak count for these rules on the owner's network is recorded. |
| O11 | low | **The same-name set can be flooded.** Eight entries, least-recently-heard replaced. A beacon flood under the picked name from more than eight addresses between two beacons of a real second access point evicts that access point, and a burst against it is then counted as nearby until its next beacon. The selected address is never evicted. | [SOURCE] `detectors.cpp` 149-176 | Open, low. `same_name_evictions()` exists; STATUS could print it. |
| O12 | info | **The repository has no commit.** `git log` on `main`: "does not have any commits yet"; every file is untracked. Source identity rests on sha256 lists inside evidence folders in the store. | [RUN] `git status`, `git log` | Open. Owner decision (commits only on his word). |

### Missing tests and unperformed checks (left visible)

- [UNKNOWN] G16H: no BLE scan has run on the stick; the coexistence spike is not run; every `t.ble_*` number is an
  uncalibrated hypothesis; row stays `passes=false`.
- [UNKNOWN] No `tools/live_matrix.py` row is recorded for any attack of `docs/attack-coverage.md`; the device proofs
  that exist are the owner's Bruce runs in `firmware/evidence/sticks3-G16{R,S,T}-20261119.log` (deauth on the picked
  network, nearby burst naming it) and the 2026-11-17 probe/beacon floods.
- [UNKNOWN] Karma, auth flood, SAE flood, association-sleep, channel-switch, name-mismatch, OWE twin, marked beacon,
  lure, handshake rules: host-tested only, never exercised by a real transmitter against the stick.
- [UNKNOWN] Data path (`detect.datapath`) device load, sweep loss, 12 h soak at the current defaults.
- [UNKNOWN] The credential vault: the stick reports `cred_store=plain cred_vault=no_partition`; the Wi-Fi password
  is stored unencrypted until the owner's USB sitting (G23 carry-over).
- [UNKNOWN] Loss of fresh evidence on the device (G16/G16A/G16C carried item, the shielded-stick check): no record
  found in the ledger notes of G16C that it was performed.
- [RECORD] G16P: `check_awake_ms` 974 / 986 against a budget of 1000, a margin of 14 to 26 ms; no unplugged key wake
  after the timer sleep was recorded.
- [RECORD] Measured performance on the stick (2026-11-19, `sticks3-G16O-20261119.log`): `kind=rated` 24.9 fps, render
  18.5 ms + push 9.8 ms, worst frame 39.9 ms; `kind=burst` worst 33.7 ms. With the 3D head on: not measured.
- Missing tests: none for the self-fetch decision itself (it lives in `measurement_main.cpp`, which no host check
  builds); no test that a TUNE offer is refused without a gesture, because today it is not refused.


### Independent review (record)

- Command: `python3 tools/review-with-claude.py --scope integrated` (normal `claude` 2.1.329, never `claude-work-profile`;
  `-p --model claude-fable-5-2 --effort high --no-session-persistence --tools '' --strict-mcp-config
  --setting-sources project --disable-slash-commands`, run in its evidence folder with the parent session's
  `CLAUDE*` variables removed). No fallback model, no retry.
- Evidence: `$GUARDIAN_STORE/reviews/20261119-201500-007595-integrated-independent/`
  (`prompt.txt` 1,431,974 B, `request.json` with the sha256 of the 107 supplied files, `stream.jsonl`, `response.json`,
  `session.json`, `review-status.json`, `SHA256SUMS`; response sha256 `63197a56...418cc9f`).
- [RUN] Completed with the requested model: `modelUsage` names only `claude-fable-5-2`; the session's init record
  shows `model=claude-fable-5-2`, `tools=[]`, `mcp_servers=[]`, `skills=[]`; `stop_reason=end_turn`, no safety stop,
  exit 0; 608,810 input tokens, 60,841 output tokens of which 53,241 thinking; 659 s. Outcome `review_received`.
- Effort: `--effort high` was sent; the CLI's result does not echo the effort level, so it is evidenced by the
  recorded argv only.
- Supplied: ledger, README, `firmware/README.md`, attack coverage, contracts, architecture, notices, the 19 small
  device logs `firmware/evidence/sticks3-G16*`, the portable core and presenter, the measurement / OTA / setup / TUNE
  adapters, the companion screens and inflater, the board code. Withheld: this file (so the findings are the
  reviewer's own), the test sources (1.2 MB; the prompt says so), art / IMU / power / spike code.
- The reviewer read the tree **before** the changes below. Its verdict: **REVISE INTEGRATED**.
- A review passes nothing: no ledger row was changed by this task, and "the reviewer found no counterexample in the
  parsers" is a reading, not test or hardware evidence.

### Dispositions of the independent findings

"Confirmed" = checked by this task in the source [SOURCE] or by a failing test [TEST]. "Open" = valid, not changed here.

| Id | Reviewer's finding (short) | Checked | Disposition |
|----|----------------------------|---------|-------------|
| S1 (critical) | Anyone answering HTTP at the provisioned URL opens a TUNE session with no gesture and rewrites every detector limit (persisted) | Confirmed [SOURCE], same as O1 | **Open, owner decision.** The reviewer's one-line fix (`if(!update_quiet)` around the offer probe) is right for the delivered product and was not applied: every device read of the lab runs over this poll today (the stick's USB is only its charger), and the change lives in `measurement_main.cpp`, which no host check builds and only the stick can prove. `session.hpp` now states the real entry conditions. **G22A (2026-11-19, pending supervisor validation and the device): a session opens only for an offer signed with the OTA key over the stick's nonce, an expiry and the command list; host-tested and built, not proven on the stick.** |
| H1 (high) | The poll has no alert term: it paints "UPDATING" over a red ALERT, blocks up to 20 s on the join, then surveys again; documents and the glass say "passive", "never joins outside UPDATE mode" | Confirmed [SOURCE] (`measurement_main.cpp` 1783: no alert/caution term; `run_update` shows the Joining screen unconditionally) | **Open** with S1. Doc line added to "What it cannot see". Suggested: skip the poll while `view().alert` or `view().caution`, a Limits line, a STATUS field with the measured blind ms per poll. **G22A (2026-11-19, pending supervisor validation and the device): a due poll is deferred while a red ALERT is active (`ota_auto_deferred`); amber does not defer; the Limits line and the measured blind time stay open.** |
| S2 (high) | Unattended install has no version check: replay of any owner-signed image (also a variant), reinstall loop, and a failed check writes NVS and holds the glass 5 s every poll | Confirmed [SOURCE]: `ota.cpp` validates the version's characters only; `update_failed` is quiet only for `JoinFailed` / `ManifestFetch` | **Open, owner decision** (variants are deployed through this path on purpose). Suggested: quiet mode installs only a version greater than the running one and makes every quiet failure silent. |
| D1 (high) | A Retry-bit flood with one sequence number is counted as one frame by all three disconnect paths | Confirmed [TEST]: four new cases red before the fix (`red-*.log`; a fifth red case is H5) | **Fixed** (see "Changes made"). Host evidence only: no transmitter in the lab sends this shape, so no live proof exists. |
| E1 (high) | G16J is accepted while "every attack ... proven live with a measured time-to-alert" and its Verify items are not recorded | Confirmed [RECORD]: G16J Verify step against its acceptance note and `docs/attack-coverage.md` | **Open, supervisor.** Suggested: an `accepted_scope` on G16J ("host rules, defaults, limits page; device matrix carried into G23") and the carry-over in G23 (O3). |
| E2 (high) | G23 misses the carry-overs of G16D, G16F, G16G, G16I, G16J; the device "evidence removed -> no data" check vanished after G16C | Confirmed [RECORD], same as O3 | **Open, supervisor** (ledger edit). |
| H2 (medium) | The dim view shows "NO DATA" during a current ALERT or amber when the last screen was Details or the list | Confirmed [SOURCE]: only `face_screen` sets `alert` / `caution` / `art`; `draw_dim` keys on them; the board renders the current screen for the dim frame. Not reproduced by a test | **Open.** Glass behaviour: needs a `companion_check` golden, a board build and a look at the stick. Suggested fix as the reviewer wrote it. **G23 (2026-11-20, worker, pending supervisor validation):** reproduced by `companion_check` case `dim_view_shows_the_alert_and_the_rating_whatever_screen_was_left_open` (red: 14 failed assertions; it also showed "NO DATA" with a fresh rating), fixed by composing the Face screen's decision for the dim view (`compose_dim`, `Companion::render_dim`; the open screen and its lit frame are unchanged; the welcome pages keep their own frame). Green on the host; in the G23 delivery image; not yet seen on the glass. |
| H3 (medium) | A transmitter copying the picked BSSID, name, settings and channel is "unchanged" and keeps the evidence fresh | Confirmed [SOURCE] (`BaselineDetector::on_frame`, unchanged path) | Doc line added to "What it cannot see". Detector rule (per-BSSID timestamp regression) **open**: new behaviour, needs its own row. |
| S3 (medium) | Setup access point: 8 symbols of 29 (38.9 bits), WPA2/WPA3 mixed with PMF optional, password posted over plain HTTP: an offline attack on a captured WPA2 join reads the home password | Facts confirmed [SOURCE] (`setup.hpp` `ap_pass_len = 8`, `setup.cpp` 29 symbols, `setup_board.cpp` 116-118). The attack cost is the reviewer's estimate, not measured | **Open.** Suggested: 16 symbols (one 1x row) or WPA3-only with PMF required. **G23 (2026-11-20, worker, pending supervisor validation):** the password is now 10 symbols (48.6 bits, min-entropy 48.3), the number the ledger's G23 step names; host TDD red then green (`one_time_password_is_ten_symbols_and_fits_the_glass`). The reviewer's stronger options (16 symbols on a 1x row, WPA3-only with PMF required) and the plain-HTTP page are unchanged and stay open. |
| S4 (medium) | Credential stored plain although G16M's description says NVS encryption; the join pins no BSSID; a join every 120 s hands a fresh handshake to any sniffer | Confirmed [RECORD] (`cred_store=plain cred_vault=no_partition`; vault is a G23 carry-over) and [SOURCE] (`ota_board.cpp` 62-63). The handshake exposure is inferred | **Open** with S1 (poll period) and the vault carry-over. |
| D2 (medium) | The router's own automatic channel change gives "Advertised settings changed" (red) every 45 s until the owner picks again | Confirmed [SOURCE]: `presenter.cpp` `approval()` stores the DS channel at the pick; `BaselineDetector` sets `change::Channel` | **Open, owner policy** (G14 asks for an ALERT on a baseline change). Suggested: channel-only change is amber with a re-approve hint. |
| D3 (medium) | `probe_flood` threshold 16 against a benign maximum of 15 in a partial soak; no soak at today's defaults | Confirmed [RECORD] (`sticks3-G16J-spike-c-benign-ceiling-20261118.log`: `in_window_max=15`, "PARTIAL; re-run ... before any threshold is frozen") | **Open:** the 12 h soak at the current defaults is a G16J carry-over (O3). |
| E3 (medium) | Rows whose Verify is not met by the record (G16R same-name set never non-zero on the device, G16T red inferred on the fixed image, G16G spike not run, G16M, G16N, G16O, G16P, G21, G16C) | Partly checked [RECORD]: G16R, G16P and G21 as stated in their own acceptance notes; the others not re-checked item by item | **Open, supervisor:** each acceptance note already names its limit; an `accepted_scope` field per row would make it visible. |
| E4 (medium) | The image on the stick (`guardian-20261119-195724`) has one boot STATUS only; time-to-alert is recorded nowhere | Not re-checked beyond `sticks3-G16H-20261119.log` | **Open** (left visible). |
| E5 (medium) | The host-live gate was not repeated for the rules added after L02 (G16F onward went host TDD -> stick) | Not re-checked; consistent with `lab/live` holding the ten L02 cases | **Open, owner:** the order rule in AGENTS.md is not met for those rules; record it or add live scenarios. |
| E6 (medium) | Document contradictions | Confirmed [SOURCE]: upright and `head.on` defaults, the 60 s cooldown, the README bullets, `evidence/README.md` "no Guardian image has been flashed yet" | `firmware/README.md` (upright off, `head.on` 0) and `docs/contracts.md` (45 s) **corrected**. README bullets, `evidence/README.md` and the `watch_impostors` comment **open** (O6); "105 of 112" not re-checked. |
| P1 (medium) | The image links a modified `libnet80211.a` with no recorded provenance | Confirmed [SOURCE]: `firmware/README.md` 44 and `build.sh` 80-91 (hash recorded per build, bytes preserved); THIRD_PARTY_NOTICES has no entry | **Closed 2026-11-20:** the vendor original was restored on the SDK install on the owner's delegated decision (sha256 5b90eb4f…4ba9, submodule status empty), the allowance was removed from `build_support.py` (a modified library is now refused like any SDK change, test red first), and the delivery image is built from vendor SDK files only; measurement in THIRD_PARTY_NOTICES.md. Earlier state, kept: **Open.** What the modification does is not established here; the reviewer's guess is not evidence. Suggested: build against the pristine pinned library, or record hash, diff and reason. **G23 (2026-11-20, worker):** provenance measured and recorded in THIRD_PARTY_NOTICES.md ("ESP-IDF and the precompiled Wi-Fi library"): 4 bytes differ from the pinned original, all in `ieee80211_raw_frame_sanity_check` of `ieee80211_output.o`; that function and `esp_wifi_80211_tx` are discarded by the linker in the Guardian image (map and symbol table), so the changed bytes are not in the image. Who changed the SDK file is not recorded. Restoring the pinned original on the shared SDK install stays the owner's decision. |
| P3 (medium) | Notices lack the persona art, the Meshy heads, ESP-IDF and its components; the G16J behaviour source has no commit hash | Confirmed [RUN] (no such entries in `THIRD_PARTY_NOTICES.md`). **Rejected in part:** the zlib / puff notice for the inflater is there (line 144) | **Open.** |
| P4 (medium) | "Five 3D expressions" cannot be met as G23 is written | Confirmed, same as O5 | **Open, owner wording.** |
| H4 (low) | Onboarding and DEMO hide incidents | `!v.demo` on the amber flag confirmed [SOURCE] (`screens.cpp` 364); the onboarding order not read | **Open, low.** |
| H5 (low) | A new pick did not clear the pattern detectors' burst records | Confirmed [TEST] (red: the record stayed known, 25 events kept) | **Fixed.** |
| S5 (low) | Receive path bound derived from `sig_len`; STATUS `snprintf` result unchecked | `snprintf` result unchecked: confirmed [SOURCE]. Whether a cut can happen today was not established here (a session note of 2026-11-19 says the board build stops on `format-truncation` when the compiler's worst case passes the buffer; not re-run); the `sig_len` point not checked | **Open, low:** check the return value anyway. |
| D4 (low) | TUNE allows cooldowns longer than the 60 s visibility | Confirmed [SOURCE] (`detect.cooldown_ms` to 300000) | **Open, low.** |
| D5 (low) | Only element 37 in beacons / probe responses is read; extended switch (60) and action frames are not | Confirmed [SOURCE] (`parser.cpp` element switch) | **Open:** belongs in `docs/attack-coverage.md` row 11 (supervisor). |
| P2 (low) | `NoiseFloorDetector::channel_capacity = 15` and "2.4 GHz" literals in the screens | Confirmed [SOURCE] | **Open, low** (matters for the C5 node). |

Rejected or not adopted, with the reason: the zlib-notice part of P3 (already present); S1's one-line patch, S2's
version rule and H1's poll gate as *changes in this task* (valid, but board behaviour the owner's lab loop depends on
and that only the stick can prove; they are owner decisions, recorded above); the reviewer's reading of what the
modified Wi-Fi library is for (a guess).

### Changes made by this task (all pending supervisor validation)

1. **Retry copies are bounded (D1).** `guardian/detector.hpp` `retry_copies_max = 7`; `DisconnectDetector` keeps the
   copies as a number on the counted entry (a copy takes no ring entry), `AreaDisconnectDetector` and
   `HandshakeDetector` cap the copies per header and time the gap from the counted frame. A frame and its retry
   chain is still one observation. An existing expectation changed on purpose:
   `area_disconnect_retries_selected_network_and_roaming_never_fire` fed 40 copies and expected one observation;
   it now feeds a retry chain (7), and the 41-frame sequence is pinned as six observations and no incident.
2. **A new pick clears every detector (H5).** `Monitor::select(const Network&)` calls `registry_.reset()`.
3. Red, then green, through the CMake targets in `$GUARDIAN_STORE/builds/20261119-g22-tdd/`:
   - red (`red-*.log`): `detector_check` 2 failed cases / 3 assertions, `threat_detectors_check` 2 / 6,
     `datapath_check` 1 / 1;
   - green (`green-*.log`): `detector_check` 41 cases 465 assertions, `threat_detectors_check` 34 / 514,
     `datapath_check` 21 / 1264, `coverage_check` 61 / 13452, `measurement_check` 12 / 198, `threat_check` 16 / 191,
     0 failed; `portability_check.cmake` passes.
   - board build (compile, sign, archive; **not flashed, not served**): `guardian-20261119-205954`,
     `builds/20261119-205954-44620-sticks3`, log `20261119-g22-tdd/board-build.log`. It proves the changed library
     builds for the stick, nothing more; its archive predates the last document edits.
4. `firmware/tools/host-check.sh` pins `adapters/` and `boards/sticks3/main/` too (220 files, was 146) (O7).
5. `tools/review-with-claude.py`: scope `integrated`, model pin `claude-fable-5-2`, clean child environment, stream
   capture of the session's init record; 8 new unit tests (`tools/tests/test_foundation_review.py`), tool tests 112 passed.
6. Documents: this section; `docs/attack-coverage.md` (two blind spots: the update check, the copied BSSID);
   `firmware/README.md` (upright off by default, `head.on` 0); `docs/contracts.md` (45 s cooldown);
   `firmware/adapters/tune/session.hpp` (comment: the real entry conditions of a TUNE session).

Not changed: `guardian-tasks.json`, the Ralph files, any device, any radio.

### Host check of the reviewed tree

- [RUN] Before any change of this task: `firmware/tools/host-check.sh all`, evidence
  `$GUARDIAN_STORE/builds/20261119-200623-host-AMXGVu`: plain 53/53, ASan+UBSan 53/53. Its source
  list matched the tree except `tests/tune_session_check.cpp`, which had changed after the previous full run
  (`20261119-191422-host-sZOnUF`); this run covers it.
- [RUN] After the changes: `firmware/tools/host-check.sh all`, evidence
  `$GUARDIAN_STORE/builds/20261119-210222-host-qfipj3`: plain 53/53, ASan+UBSan 53/53. Its
  `toolchain.txt` lists 220 sources (now with `adapters/` and `boards/sticks3/main/`), and `shasum -c` of that list
  against this tree is clean. The hashes of the 19 files this task changed are in
  `builds/20261119-g22-tdd/changed-sources-sha256.txt` (this file's own hash there predates this paragraph).
- [RUN] `python3 -m pytest -q tools/tests firmware/boards/sticks3/tests`: 153 passed (112 + 41).
- [RUN] `guardian-tasks.json` is byte-for-byte the runner's `ledger-before.json` of this attempt.
- Logs: `$GUARDIAN_STORE/reviews/G22-20261119-own/` (`host-check.log`, `host-check-final.log`,
  `independent-run.log`, `cli-smoke/` = two one-word calls that checked the reviewer command before the real one).

## Task acceptance

- G01 accepted after its contract corrections: [G01 validation](G01-validation.md).
  Compiler syntax checks were not runtime or TDD proof.
- G02 accepted with source/provenance corrections, complete reviewer sanitizer
  evidence and M5 notices: [G02 validation](G02-validation.md). Seven libwifi host
  cases ran; no Guardian/device/RF behavior is accepted by those experiments.
- G03 accepted after independent host builds and harness corrections:
  [G03 validation](G03-validation.md). Both plain and ASan/UBSan runs pass 14/14
  checks; failure-injection probes reject incomplete builds and false passes.
- G04–G07 accepted after supervisor source review, failing-first corrections,
  full normal/sanitized host checks and vetted libwifi decoding comparisons:
  [batch validation](G04-G07-validation.md). This is host/replay acceptance only.
- G08 accepted after the authorized Codex retry and supervisor corrections:
  [G08 validation](G08-validation.md). The full normal/sanitized host suites pass
  22/22; 25 presenter behavior cases pass 377 assertions in each build.
  Highlight identity and request context bugs were reproduced and fixed.
- L01/L02 accepted after supervisor fixes, live execution and evidence audit:
  [live validation](L02-live-validation.md). Ten real-radio cases pass, including
  mid-batch stop and recovery. Both radios are idle. G09 is accepted after corrections and independent Codex approval; see
  [G09 validation and fixes](G09-validation.md). No new product-board integration is accepted.
- Old code remains honestly labelled baseline; neither G03's pre-existing
  helpers nor G07's pre-red signal interval addition gain retrospective TDD claims.

## Historical independent Claude ledger review

Normal `claude`, requested `claude-fable-5-1`, effort `high`; never `claude-work-profile`.
The user's 2026-11-13 attempt identified that model but returned a provider cyber
refusal. Evidence: `$GUARDIAN_STORE/reviews/20261113-233521-710039-ledger-independent`.
**Review incomplete. No independent approval.** The initial G08 attempt hit
the Fable usage limit (the owner later used Codex for implementation); the supervisor host review does not replace that
independent ledger/foundation review. Earlier assistant-side login
failures do not describe the user's working terminal login. Do not switch
accounts/models or automatically retry a refusal.

`tools/review-with-claude.py --report EVIDENCE_DIR` classifies saved output without
calling Claude. The helper distinguishes provider refusal, transport/API error,
unverified model and missing/incomplete review text. A successful response is
still findings for supervising assessment, never automatic task acceptance.

## Storage and hardware

Sources live here; dependencies and lasting evidence in the store. G02 reviewer
corrections/evidence were staged in `/private/tmp` because this session's writable
roots exclude this project and the store; the guarded installer copies both before
changing G02 acceptance. It starts no jobs or radio actions.

The original spike artifact remains preserved. Its repaired successor now has
separate G10/G11 evidence on owner-approved LAB-STICK-1.
Host TDD -> L01 equipment qualification -> L02 automated real host-library RF
validation -> independent foundation review -> new ESP32 integration -> repeat
live acceptance -> art. Never substitute replay/browser fixtures for live proof.

## Live equipment and evidence

[Equipment record](../lab/receiver/STATUS.md) and [accepted live matrix](L02-live-validation.md).
Original flash backups verified; designated Cardputer receiver and Pi emitter/AP
retain their lab firmware, both idle. The head-pointer unit was originally excluded; later explicit authorization
allowed its backed-up G10/G11 bring-up. L01/L02
passes are supervisor-owned. G09 now has its separate Codex approval and disposition record.

## 2026-11-14 owner-authorized StickS3 follow-up

The earlier untouched-board statements above describe the original L01/L02 scope.
The owner subsequently authorized LAB-STICK-1 for foundation/bring-up spikes.
Its own full flash is backed up and verified. Ten on-chip Imported-fixture checks
passed with RF off, followed by a real LCD bring-up. G10/G11 evidence is separate;
Cardputer remains the designated live receiver. See firmware/README.md and
docs/G10-validation.md for current facts. No Pi jobs or Cardputer firmware changed.

## G10/G11 acceptance

All six substantive Codex findings were reproduced or inspected, fixed and
verified. Final source review approved; 14 build-helper checks and native
compilation/archive verification pass. See [G10](G10-validation.md).
Owner videos plus USB logs confirm screen orientation/colour repair, buttons,
PSRAM and retained boot counts. See [G11](G11-device-validation.md).
No completed live receiver or final artwork is implied. G12 is next.

## G12 acceptance

Host reruns pass 23/23 normal and sanitized; four native ELFs independently
verified for architecture, symbols and component isolation. Source-drift evidence
gap reproduced and fixed in the wrapper. [G12 validation](G12-validation.md).
S3/C3 native execution remains unmeasured for these qualification apps. G13 is next.

## G13 validation in progress

[Supervisor validation and fixes](G13-validation.md): 11 real-board scenarios
pass; 87 harness checks and 162 sanitized adapter assertions pass. Normal client
reconnect and physical screen/video evidence remain pending. G13 is not accepted;
leave Ralph stopped. The ledger and worker receipts remain unchanged.

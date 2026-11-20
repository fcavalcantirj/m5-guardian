# G13 supervisor validation — accepted

## Supervisor acceptance — 2026-11-15 (current status)

**G13 is accepted.** This closing decision supersedes earlier pending-status notes below, which remain historical evidence. Review record: `$GUARDIAN_STORE/evidence-raw/G13-video-20261115/planner-G13-acceptance.json`.

Supervisor independently verified 109 submitted source hashes, rehashed the original owner video, inspected the physical settings-transition and stale-edge frames, and checked actual live result/cleanup records. Independent reruns passed 24/24 plain, 24/24 ASan/UBSan and 92/92 harness checks. A test-fixture file/thread cleanup leak was fixed; the final harness run treats ResourceWarning as an error and is clean. Physical No fresh data appears at displayed age29,000ms, meeting the measured AP-off30s criterion with roughly1s margin. This does not establish a universal worst-case timing bound.

New firmware ELF: `a9c84eeb5d601dd0c939e37855bb91713dbcc0ad93af850a64d19f27446f5213`. The portable29s policy intentionally supersedes the older source hashes; historical manifests and failed runs are retained. The device-unplug event was owner action, not evidence of a firmware fault. G14 (picker/buttons/persistence) is next; art and G14 physical acceptance remain later work. Ralph has not been started.

## Historical validation journal

Acceptance remains **pending**. Keep Ralph stopped until this record and the ledger
report actual board acceptance. The owner enabled LAB-PI-2 and connected an iPhone;
StickS3 LAB-STICK-1 is the receiver. Evidence lives in the store under
`evidence-raw/G13-supervisor-20261115/` and `reviews/G13-20261115-supervisor/`.

## Defects reproduced and fixed

- A controlled AP could not start: receiver readiness required an advertisement
  from an AP that had not been started. Settings validation now explicitly holds
  its scoped channel with bounded `listen`; listening does not claim AP lock.
- Older queued advertisements regressed survey freshness. Last-seen time now
  advances monotonically.
- The SDK returned only nine ELF hash characters by default. Real board identity
  validation rejected it. Configuration and a compile-time assertion require all
  64 characters; live identity now matches the archived ELF.
- The first quiet run raised a false channel-change alert: the radio heard an AP
  advertising channel 5 while tuned to adjacent channel 6. The baseline now uses
  the advertised channel, and passive discovery follows that channel within the
  configured regulatory bounds, requiring a new advertisement before lock.
  Receiver and advertised channel remain distinct; neither overwrites RX metadata.

Focused host checks: 11 cases / 162 assertions under ASan/UBSan, with preserved
runtime failing-before evidence for the channel defect; 80 Python live-harness
checks pass. Runtime heap/minimum heap/main-task stack headroom are now recorded
inside CRC-protected board telemetry. These measurements do not establish Wi-Fi
callback stack margin or throughput capacity under all traffic loads.

## Actual hardware observations so far

The exact StickS3 has booted the compiled measurement firmware. Its own original
8 MB flash backup was hashed before each write; complete flash bundles and write
logs remain in the store. The current firmware archive is
`builds/20261115-085524-60351-sticks3/`.

The first quiet run received 1,328 frames with zero transport gaps, errors or
receiver drops, but **failed** because of the false baseline alert above. It is
retained as failure evidence, not accepted quiet behavior. Independent pinned
libwifi decoding of the actual hotspot beacon confirms channel 5, RSN version 1,
PSK AKM 2, CCMP suite 4, and capabilities 0x000c (PMF disabled).

The Pi ESP32 LAB-PI-EMITTER-STA was idle before installing the already reviewed native
emitter 1.2 stop fix. Its original 4 MB flash backup and all install artifacts were
hashed. The CP2102 bridge repeated partial output and kernel control timeouts;
a reset of that identified USB bridge restored communication. The no-RF stop /
bootloader-reset qualification then passed. This is not itself RF validation.

## Completed board validation

All **11** completed scenarios passed their actual on-board assertions and
cleanup. Reception, parser, policy and presenter executed on StickS3; the host
only controlled scenarios and independently checked telemetry/raw frames.

| Scenario | Received frames | Result |
| --- | ---: | --- |
| quiet | 795 | Pass |
| drop | 1101 | Pass |
| stale | 313 | Pass |
| burst | 881 | Pass |
| stop | 820 | Pass |
| stop-inflight | 717 | Pass |
| recovery | 3025 | Pass |
| settings | 923 | Pass |
| channel | 1594 | Pass |
| related-approved | 2942 | Pass |
| related-unapproved | 2839 | Pass |

The burst witness observed all 24 bounded test frames; threshold-to-report
latency was 959 ms. Recovery cleared the incident after the actual library's
expiry. Approved same-name AP: 138 advertisements, no unexpected-AP alert;
unapproved same-name AP: 164 advertisements, visible incident. A failed earlier
same-name run is retained: the phone had moved from channel 5 to 11 after its
scope file was written. Guardian rediscovered it, but the controller still used
5. Admission now checks the fresh observed channel before GO; an obsolete scope
is refused. Requalification on 11 passed both cases. Legacy fixed-channel host
receivers retain their heartbeat interface; current host output additionally
separates advertised and received channels.

The host adapter had the same baseline-channel mix-up as the board adapter.
Its Imported regression failed before the fix and passes now. **87** Python
harness checks pass against the freshly compiled ASan/UBSan host engine. The
accepted **21 core/presenter files remain byte-identical** to G12; neither
adapter fix introduces a second rating/detection policy.

The dedicated AP moved 13 → 6 → 13 while the StickS3 used passive discovery.
Both transitions have observed unknown/degraded coverage between fresh channel
states. The stricter re-audit rejects startup-only gaps and passes the actual
records. This is real channel movement, not a synthetic capability fixture.

The bounded Pi fixture is now native-emitter **1.3**. Its new `apchannel` operation
requires an already active, unexpired test AP, no associated clients, an unarmed
stimulus limiter and channel 1..13. It cannot start an AP or extend its deadline.
SDK failure/mismatched readback invokes reviewed shutdown. Parser and fault-path
checks pass under ASan/UBSan; original backup, 1.2 artifact, 1.3 source/binaries,
flash logs, no-RF stop qualification and live channel receipts are retained.
The AP starts on 13 and, for same-name tests, retunes to the explicitly scoped
channel before its controller reports readiness for observation.

Pinned libwifi independently decoded the actual received hotspot/test-AP
beacons: channels agree, WPA2 PSK/CCMP and WPA3 SAE/CCMP agree with the commanded
settings, and PMF capability/requirement flags agree with the board results.
This checks parsing of received bytes, not cryptographic transmitter identity
or radio FCS validation.

Lowest observed free internal heap: **96,823 bytes**. Lowest reported
main-task stack headroom: **2,056 bytes**. No board resets or transport
corruption occurred in the passing scenarios. The stale-input test counted one
queued record discarded during explicit receiver stop; other passing scenarios
reported zero receiver drops. These bounded runs are not worst-case throughput,
Wi-Fi driver-task stack, long-duration or universal false-positive guarantees.

After the controlled AP stopped, the board returned to Unknown/stale. The first
1 Hz stale telemetry sample was **30.167 s after the stop acknowledgement**;
the policy expires at 30 s since the last valid advertisement. This sampled
result does not prove the exact physical LCD transition time. Keep that visual
timing check pending instead of rounding the evidence into a stronger claim.

## Automated ordinary reconnect with the Cardputer lab client — 2026-11-15 (pending review)

Evidence root: `$GUARDIAN_STORE/evidence-raw/G13-cardputer-client-20261115-103949`.
The earlier iOS/Android attempts did not pass (no association; the Android run
saw the hotspot itself restart). The owner's Cardputer ADV `LAB-CARDPUTER`
now runs `lab/client` (`guardian-client/1.1`, an ordinary ESP-IDF station, no raw
TX) as the client; the Android phone only provides the hotspot.

- Build: first attempt failed at link-time compile (`esp_app_desc.h` needs
  `esp_app_format`; log `build-attempt1-failed.log`), fixed and rebuilt in the same
  tree. Client bin `4af82b5e…7c17` (686,688 B), ELF `fa66005a…162e`.
- Install: the Cardputer's bootloader/table are the 2026-11-14 receiver install
  (single-app factory 0x10000, 1 MiB, no otadata), not the original image;
  references archived in `layout-reference/`. App-only write at 0x10000,
  `verify_flash` digest match (`flash-write-01/`). Recovery: receiver app
  `d5d4aa…` at 0x10000, or the original full 8 MB backup.
- Opening the host port with DTR=0/RTS=0 reset the client 1 of 2 times; with
  DTR=1/RTS=0, 0 of 4 (`open-reset-probe-01/`). The controller uses DTR=1/RTS=0.
- Qualification: no-RF identity/idle/stop/4 rejected commands (`qualify-norf-01/`);
  10 s on-device deadline proven twice in one boot (nonce `c59674323e466d45`):
  port open, device span 10.050 s; port closed 15 s then reopened, span 10.037 s
  (`qualify-rf-01/`).
- Scope: the hotspot had restarted; fresh passive discovery found exactly one
  `LAB-PI-2`, BSSID `ea:29:2f:06:2a:44`, advertised channel 1, WPA2-PSK/CCMP, no
  MFPR (`hotspot-recheck-01/`). WPA2 means no SAE client change was needed.
- `reconnect-01`: **pass**. Two cycles at observer 15 s / 40 s; each has one clean
  Cardputer association request (~0.5 s after its join) and one status-0
  association response inside the cycle window (clock envelope 13.4 ms), plus a
  connection-count rise with DHCP. StickS3 library: 76 live states, incident
  kind 0 throughout, no burst/unexpected-AP/settings change, max age 282 ms,
  3,122 frames, zero transport errors/gaps/drops, association count 0 -> 22 after
  baseline, min internal heap 112,251 B, min task stack 2,200 B. Cleanup confirmed.
- `reconnect-02`: **fail**, same client/witness/no-incident results, but one
  receiver drop: the StickS3 stopped itself at its own 75 s receiver deadline
  (+74.81 s device time) during the host's final drain, and that stop discarded one
  queued record (first non-zero `queue_drops` is the stop-status record). The
  harness started the receiver with the same duration as the host window. The
  failed run is kept as evidence.
- Harness fix (planner-approved, entry 12334): `lab/live/board.py` sends the host
  window + 5 s as the board's receiver deadline (backstop only; also for the
  channel-release restart) and rejects board windows above 295 s in the
  constructor, before any port or output. `result.json` now reports
  `observation_receiver_drops` (asserted, unchanged) and `post_window_stop_discards`
  from the confirmed cleanup stop. Red `board-backstop-tests-red.log`,
  `board-backstop2-tests-red.log`; green full `lab/live` suite 90/90
  (`board-backstop2-tests-green.log`) with a fresh sanitized engine built from
  repo source. The old `/private/tmp/guardian-live-build` tree compiles a stale
  copy (`/private/tmp/guardian-live-prep`) and fails one engine test.
- `reconnect-03`: **pass** on the fixed harness; no receiver stop inside the
  window (cleanup stop at +75.6 s), 0 observation drops, 0 post-window discards,
  75 states with incident kind 0, assoc count 39.
- `reconnect-04`: **fail**. Second rejoin got AUTH_EXPIRE: the Cardputer sent a
  probe request and 32 retransmitted Open-System auth requests; the phone sent no
  probe response or auth reply. The client deliberately makes one SDK attempt.
  Guardian stayed clean (64 states, incident kind 0). The controller now stops
  and retries a failed join after 1 s, at most 3 attempts (red
  `join-retry-tests-red.log`, green `join-retry-tests-green-2.log`, 29/29).
- `reconnect-05`: **pass** (scope `hotspot-recheck-03`, unchanged). Attempts per
  join 2 / 3 / 1, so the phone hotspot ignored fresh auth several times. Both
  cycles witnessed (request + status-0 response), 4,046 frames, 0 drops/gaps,
  76 states incident kind 0, assoc count 96, min internal heap 112,251 B,
  **min task stack 1,976 B** (lower than the earlier 2,056 B). Planner review
  (entry 12352): 1,976 B is about 24 % of the 8,192 B main stack, an observed
  minimum with no overflow/reset evidence, not a worst-case bound; re-measure as
  UI/load grows. Connection was intermittent; no AP reply was observed in the
  failed attempts, which does not isolate RF loss vs AP behaviour.
- Host error paths (entry 12352): only a typed `ClientTimeout` is retryable in
  `Client.join`; reboot, protocol (`GCLIENT ERROR`) and identity errors abort into
  cleanup. The observer stdout pipe is closed after the reader joins. Red
  `review12352-tests-red.log`, green `review12352-tests-green.log` (34/34 with
  `-W error::ResourceWarning`).
- Engine provenance: the planner's 87-check review used
  `reviews/G13-20261115-supervisor/guardian-live-engine-asan` (sha256 `5c6b6841…4ab5`);
  this session's 90-check runs used `/private/tmp/guardian-live-build-20261115`
  built from repo source. Always pass `GUARDIAN_ENGINE` explicitly.

Host checks: `lab/client/tests` 29/29 (earlier 27/27) (red logs `reconnect-tests-red.log`,
`review12288-tests-red.log`; green logs beside them). Credential scan of evidence and
client source: 0 hits.

## Physical screen video and the 29 s freshness budget — 2026-11-15 (pending review)

Evidence root: `$GUARDIAN_STORE/evidence-raw/G13-video-20261115`.

- `settings-video-01`: run aborted at ~1 s. `start_emitter()` created two log files
  on the store inside the reception loop; each open measured 560-641 ms
  (`smb-latency-probe-01`), delaying board telemetry >1 s. Fixed by
  `prepare_emitter_logs()` before reception (red/green `emitter-logs-tests-*.log`).
- `settings-video-02`: run passed and the owner video (`settings-video-02-owner-*.mp4`)
  showed every settings/incident transition, but **failed the timing criterion**:
  the screen first showed No fresh data at displayed age 30,209 ms, about 30.18 s
  after the AP stop acknowledgement. Causes: expiry counted 30 s from the last
  advertisement, plus a 250 ms redraw cadence.
- Fix (planner decision 12390, owner: strict requirement): `Core::fresh_ms`
  30,000 -> **29,000** (single portable policy; advice text "No new reading for 29
  seconds"), and the StickS3 measurement screen redraws exactly at the expiry
  deadline (`boards/sticks3/main/redraw.hpp`). Red: `host-ctest-red.log`
  (contracts), `redraw-check-red.log`; green: plain and sanitized host suites 24/24,
  `redraw-check-green.log`, `lab/live` 92/92 with a rebuilt engine. One boundary
  test (`presenter_check`) now uses `Core::fresh_ms` instead of literals. The 21
  accepted core/presenter files are deliberately changed; prior manifests remain
  historical.
- StickS3 firmware `a9c84eeb…5213` (archive `builds/20261115-124632-29142-sticks3`,
  bootloader/table/SDK input identical to the reviewed build) written app-only
  after exact-MAC, backup and rollback (`e92ef949…`) checks; `verify_flash` matched
  and the board reported the new ELF. Board `stale` regression passed
  (`stale-fresh29-01`).
- `settings-video-03`: **pass**, with owner video pulled over adb
  (`settings-video-03-owner-VID_20261115_130646.mp4`, sha256 `69fb28bb…e3af`). Screen
  shows WPA2 -> WPA3 with red incident -> WPA2 -> incident cleared -> **No fresh data
  at displayed age 29,000 ms** (previous frame 28,800 ms). The stop ack came
  86.5 ms after the last advertisement, so the screen went stale 28.9-29.0 s after
  the AP turned off, plus unmeasured panel transfer time (tens of ms). This run meets
  the 30 s criterion with about 1 s margin; it is not a universal worst-case proof.
  Min task stack 2,184 B, min internal heap 112,251 B.

## Remaining owner-assisted acceptance

1. ~~Observe a normal client Wi-Fi reconnect~~ — automated above with the
   Cardputer; passes: `reconnect-01`, `-03`, `-05`; failures kept: `-02`
   (harness, fixed), `-04` (hotspot ignored auth, controller retry added).
   Awaiting planner review.
2. ~~Record the diagnostic screen~~ — done in `settings-video-03` above; awaiting
   planner review.
   Earlier G11 colour/button videos do not prove the new measurement path.

**G13 passes remains false; do not restart Ralph yet.** The next implementation
is G14 only after those remaining observations are reviewed. All completed
scenario cleanup receipts confirm receiver stop; the Pi final read-only query
confirms Wi-Fi stopped and the stimulus limiter unarmed. Nothing is transmitting
or running as an unattended Guardian test after this review turn.

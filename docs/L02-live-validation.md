# Live validation — accepted 2026-11-14

**Supervisor acceptance: L01 and L02 pass for the measured host scope below.**
The actual portable C++ parser, detectors, Core and presenter processed real RF
while scenarios ran. This is not product firmware/UI acceptance, universal attack
detection, or independent G09 approval. Work stops here; no next task was started.

## Equipment and scope

- Host: Mac, actual repository components linked by `lab/live/CMakeLists.txt`,
  ASan/UBSan enabled. Python orchestrates and transports; it is not the detector.
- Receiver: designated Cardputer ADV `LAB-CARDPUTER`, native acquisition-only
  `guardian-rx/1.2`. It does not run Guardian business logic or initialize its screen.
- Stimulus/test AP: Pi `LAB-PI-HOST`, WROOM station MAC `LAB-PI-EMITTER-STA`,
  SoftAP `LAB-PI-EMITTER-AP`, native `native-emitter/1.1`. nRF24 unused.
- Owner hotspot `LAB-PI-2`, SSID hex `4c41422d50492d32`, channel 13. Initial BSSID
  `5a:1a:f4:41:9a:56`; after the owner restarted it, passive discovery twice
  verified `12:44:19:79:ba:6c`, still channel 13. Scope files preserve each run's
  identity. Never reuse these addresses as an assumed future authorization.
- The iPhone provided normal client traffic. Its reconnect was owner-operated;
  capture, library processing and assertions were automated.
- Security-change and related-AP cases used the separate controlled native AP,
  not imagined phone settings. It uses a random ephemeral secret, never logged,
  no service/credential collection, channel 13 and a device-enforced deadline.
- Excluded StickS3/head pointer `LAB-STICK-1` untouched. Pi uplink and unrelated
  jobs/devices unchanged. The earlier Guardian board spike remains unaccepted.

## Measured acceptance matrix

Evidence root: `$GUARDIAN_STORE/evidence-raw/live-20261114/`.
`final-review/final-audit.json` maps each case to source evidence hashes. The
supervisor re-read raw records and C++ output rather than trusting pass labels.

| Case / directory | Actual observation and accepted assertion |
|---|---|
| Quiet / `quiet-02` | 621 received frames, 29 fresh states; no burst, unexpected AP, settings-change or incident banner. |
| Benign reconnect / `reconnect-01` | 2,248 frames, four authentication/association frames after baseline; no false incident. |
| Stale / `stale-01` | 156 frames; receiver stopped at 10 s, host kept ticking; final evidence age 35,121 ms, Unknown face, degraded coverage. |
| Drop / `drop-01` | 434 actual received frames; deliberately withheld 24 at the host adapter, 410 reached C++; degraded/Unknown during loss, then fresh recovery. This tests adapter loss, not simulated RF or a claim of driver overflow. |
| Settings / `settings-01` | 1,477 frames; received advertisements show WPA2-Personal → WPA3-Personal with PMF required → WPA2-Personal; settings-change banner; controlled AP cessation observed. |
| Unexpected AP / `related-unapproved-01` | 821 frames, 175 related-AP advertisements; UnexpectedAp and incident banner; AP cessation observed. |
| Approved AP / `related-approved-01` | 784 frames, 175 related-AP advertisements; no unexpected-AP/settings/burst incident or banner; AP cessation observed. |
| Stop between batches / `stop-native-02` | Three stimulus frames received, one completed group; requested-stop ACK 8.23 ms; on-air cessation observed. |
| Stop inside batch / `stop-inflight-02` | One of three planned frames received; zero completed groups, one submitted; interrupted-inflight flag, ACK 16.08 ms, cessation observed. |
| Burst and recovery / `recovery-native-02` | 23 of 24 requested TX calls observed as matching frames; unchanged threshold 20/10 s; real incident reported 315 ms after the Core's threshold-closing acquisition timestamp (budget 1,500 ms); fresh no-incident recovery after at least 60 s. |

All ten cases had sufficient fresh live observations, no reported transport error
or sequence gap and no sanitizer stderr. Observed clock envelopes were 12.884–
17.144 ms. Zero adapter/transport drops does not mean every RF frame arrived:
the final burst observed 23/24, not 24/24. A first final-audit assertion wrongly
required exactly 24 receptions; it was corrected to the original requirement of
20–24 observations, without changing the detector threshold or live data. Both
audit versions are retained. The earlier recovery run observed 24/24; the final
run additionally records the Core's exact threshold timestamp.

## Controls, fixes and checks

The original emitter rejected channel 13 and used a blocking loop. Its old
source/binary equivalence was never certified. The replacement sets SDK country
BR with channel readback, accepts only the exact scoped BSSID/channel, limits an
arm to 24 TX calls and four seconds, reads stop between 20 ms spaced calls, and
stops on errors. It boots Wi-Fi off. The AP role is separate, mutually exclusive,
and limited to 120 seconds. Stop shuts Wi-Fi down. The host adds deadlines and a
qualified ROM-reset fallback; the legacy failed channel run was not counted as a
pass. Native no-TX checks measured the four-second expiry at 4,007.07 ms, an
armed stop at 7.11 ms and successful ROM fallback. Those are observations, not
universal worst-case timing guarantees.

Other defects fixed and verified: SMB logging stalls (bounded asynchronous
writers); unavailable radio FCS (no invented checksum); clock mapping and stale
host ticks; receiver witness comparison after SDK rewrote Duration bytes;
truthful stop/reset failure reporting; cleanup continuing after USB errors;
reader joining and explicit current acquisition timestamp in the host output.
The witness ignores only Duration, retaining frame/address/sequence/reason checks.

54 focused Python/actual-engine checks passed. Native limiter/command and receiver
wire/SYNC checks passed under ASan/UBSan and the native images compiled for their
chips. Red/green records are retained. Initial integration checks were baselines,
not retrospective TDD. The previous 22/22 foundation suite remains its own earlier
record; it was not claimed as a newly repeated run. Core/presenter production
behavior sources were unchanged in this live-adapter work.

## Cleanup, provenance and limits

`final-review/final-idle-pi.jsonl`: exact emitter reports Wi-Fi off, unarmed, AP
inactive; no controller process. `final-review/final-idle-mac.json`: Cardputer
reception off, no host engine; both original full-flash backup SHA-256 values
verified. Newer runs have `cleanup.json`; earlier runs retain their normal
stop/exit evidence and final idle confirmation, not fabricated cleanup receipts.
The two boards retain their lab firmware; restoring Bruce is a separate action.
The hotspot can be off and the iPhone disconnected. No more RF is planned.

- Host binary, linked static libraries, CMake/link identity and source snapshots:
  `builds/20261114-guardian-live-host-final/` in the store.
- Receiver image/flash evidence: `builds/20261114-cardputer-receiver-sync/`.
- Emitter/AP image/flash evidence: `builds/20261114-native-emitter-ap/`.
- Pinned installed IDF v5.4 commit `67c1de1eebe095d554d281952fde63c16ee2dca0`;
  installed SDK working tree was already dirty, so this is not a pristine-tag claim.
- Original backups: `device-backups/LAB-CARDPUTER-20261114/flash-full-8MB.bin` and
  `device-backups/LAB-PI-EMITTER-STA-20261114/flash-full-4MB.bin`.
- Preparation source manifests/snapshots, failing experiments and fixes remain
  intact. Final review archives latest logs, audit scripts, manifests and docs.
  Per-run `full_L02_acceptance:false` stays unchanged: a single run never accepts
  the whole matrix. This document and the ledger record supervisor acceptance.

This qualifies 2.4 GHz channel-13 lab cases, not 5 GHz, every channel, RF noise,
throughput, password strength or every possible attack. Radio FCS is unavailable;
USB CRC is not radio CRC. Clock brackets are observed envelopes, not hard drift
bounds. Coverage describes listening/counters, not omniscient reception. A frame
match does not authenticate its sender, and observed deauth does not prove a
client disconnected. Independent G09 review and later board/live/display checks
remain pending. No Claude independent approval is claimed.

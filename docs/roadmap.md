> **Release 1 scope (owner, 2026-11-19 22:xx):** Wi-Fi guard, graphics, battery life, and finishing what exists. Bluetooth is
> RELEASE 2 and needs a full spec first (G16H's library detector stays unfed; the stick does not scan; G16U toggle and the C5
> node G16K wait for that spec). Release 1 closes with G22A (self-fetch hardening) and G23 (delivery with its carry-overs).
>
> **Current update — 2026-11-19 00:5x (resume here).** Ledger 32/42. On the stick: `guardian-20261119-001104` = G16Q Part 2
> (owner's pick D on the art bench: linear-light LANCZOS, unsharp 0.6/120/1, Floyd-Steinberg to RGB565; "its the difuser.
> perfect") + G16R (same-name RED rule) + G16P/N/O/M. **Open bug, the one that matters:** a Bruce deauth against the owner's
> router still shows AMBER, not RED (00:23: area_disconnect events=16, incidents=1, `same_name=0`: the stick heard no second
> address under the owner's name, so G16R had nothing to match). The frames' addresses are UNKNOWN; no guess is written.
> Two ways to get them: (a) `lab/live/deauth_truth.py` over USB (console verbs `listen`/`select`/`SNAPSHOT` are in the
> shipped image; needs a cable, none at hand tonight), or (b) **G16S, burst forensics in STATUS and on the glass** (inserted
> after G16R; a Ralph row, lands by self-fetch, no cable). The G16R fix is written from those addresses. Supervisor of record:
> session `m5-guardian-supervision-takeover` (handover `docs/handovers/2026-11-18-guardian-day-end/`). Runner idle at
> awaiting_review G16R; next pick G16S.
>
> **Current update — 2026-11-17 night (resume here).** Ledger 29/34 accepted. Today: v4 art pack (Very good green
> eyes, Horrible blood-red eyes, red-eye ALERT for every mood, sharpened portraits) shipped as `guardian-20261117-203615`;
> G16D/G16F/G16G accepted with device carry-overs into G23; G17–G20 accepted on the v4 pack; G16H (BLE) deferred to
> the end with a research step first; G16I (upright by gravity + shake burst, all spikes measured) running in Ralph
> continuous with the no-LLM watcher `tools/ralph_watch.sh`; G21 rewritten to the measured 3D path (Meshy heads i1/i2
> in the store `art-exports/G21-3d/`, 80 credits spent, the original master projected on the head with
> `tools/face3d/project_views.py`, one mood at 15×7 angles = 1.64 MB of the 1.9 MB budget).
>
> **Defense coverage, the honest state: NOT every attack yet.** Proven on the stick: Bruce deauth on our network = RED,
> Brucegotchi nearby = amber, Evil-M5 probe flood = amber (at measured thresholds). Blind today: evil twin (watch off),
> handshake/PMKID/fake-M1 (data path off), everything on 5 GHz (radio is 2.4 GHz), other channels while locked, BLE.
> The full kit × attack matrix, the AntiHunter upstream comparison and the plan are in
> [attack-coverage.md](attack-coverage.md). Order from here: **G16I → G16J (attack coverage: every kit attack proven
> live, evil twin on, data path on after a load spike, measured thresholds, karma probe-then-answer rule, honesty on
> the glass) → G21 3D head → G16H BLE (research first) → G22 → G23.**
>
> **G16K, the 5 GHz + BLE eye (owner, 2026-11-18 00:50: "this is a defense system, should be complete, include BLE";
> plan approved, spike tomorrow):** a second Guardian node on the owner's ESP32-C5-DevKitC-1 (dual band, 8 MB flash,
> no PSRAM) running the SAME portable library on 5 GHz plus BLE, with the Android phone as its screen through
> Droidputer's existing USB OTG pixel protocol (no app change: the app already opened this C5 on 2026-09-16). The stick
> keeps its 2.4 GHz capture untouched. Spike first (S-1 C5 on its own pinned IDF, the installed v5.4 lists esp32c5 as
> preview; S-2 passive capture of the router's 5 GHz beacons; S-3 Droidputer shows frames from the C5 over OTG and
> sends keys back; S-4 BLE + 5 GHz coexistence on the C5). Brief and commands: [c5-node.md](c5-node.md). Then the
> ledger row G16K; G16L candidate = the stick showing the companion's 5 GHz incident (passive receive, spike-gated).
> BLE detection moves from the stick (G16H) to the C5 node. Code facts for the adapter are in the brief: the 2.4 GHz
> hard-coding to widen (measurement.cpp:11,70,122; measurement_radio.cpp:26-28; measurement_main.cpp:1023), no
> external-observation input exists on the stick (console verbs are read-only or picker/TUNE), and the incident record
> has no band or sensor field yet.
>
> **Setup over Bluetooth (owner question, 2026-11-19 15:4x):** the ai-usage stick pairs over BLE because a Mac DAEMON holds the
> Wi-Fi settings and sends them after a six-digit pairing; the Guardian's partner is a phone, which has no daemon, so BLE
> setup needs an app on the phone (Espressif's provisioning app, or a Guardian/Droidputer app), while the G16M page works on
> any phone with no app. ESP-IDF ships the BLE scheme (`components/wifi_provisioning/src/scheme_ble.c`), so it can be added
> beside the page later, after G16H measures BLE coexistence on the stick; a phone app is the real cost. Decision: keep the
> page as the product path; BLE setup = optional follow-up once a Guardian phone app exists.
>
> Previous update — 2026-11-16. Ledger 20/33 accepted. Today: G15 v2 persona, G16 Very-good
> portrait, G16A upright portrait + BMI270 IMU + live TUNE, G16B signed OTA (RSA-3072) with rollback and battery.
> The stick now updates only over Wi-Fi (owner gesture: FRONT pressed three times fast, then FRONT = yes).
> In progress: G16C (face for every rating + techy HUD + IMU motion) — first attempt measured 12 fps and USB-stall
> dropouts; rework running. Open bug: an Evil Cardputer deauth against the home AP did not turn the stick red
> (ground-truth capture prepared, `lab/live/deauth_truth.py`).
>
> **Next phases**
> 1. G16C accept → IMU axis calibration (3 poses) → live tuning standing, over Wi-Fi.
> 2. G16D battery: dim after 30 s still, deep sleep after 2 min on battery, a click wakes.
> 3. Defense coverage from the full AntiHunter map ([reuse-decisions §10](research/reuse-decisions.md)):
>    G16E detection platform (probe requests, nearby "amber" vs your-network "red", threat radar),
>    G16F management attacks (probe/beacon floods, karma, auth/SAE/assoc floods, CSA, SSID confusion,
>    pwnagotchi, OWE, deauth per source), G16G data path (PMKID harvest, deauth→handshake, frame-loss
>    jamming; load spike first), G16H BLE popup spam (2026-11-19: library detector and rules host-proven; coexistence
>    spike measured beacon loss = scan duty, so NO-GO for a BLE scan on the stick; unfed there by design, the C5 node G16K feeds it).
> 4. Live proof for every detector with the owner's Evil Cardputer as attacker (owner runs, supervisor
>    prepares), a ≥12 h quiet-home soak (0 false alerts), the camera on the glass, Cardputer log/pcap pull.
> 5. G17–G20 mood polish, G21 budgets, G22 reviews, G23 delivery.
>
> **Learning track for the owner:** [Learn RF with the Guardian](learn-rf.md) — modulation, 802.11 frames and
> attacks, nRF24 vs ESP32, BLE, sub-GHz, each lesson paired with a lab exercise on the owner's gear.

> Current update — 2026-11-15: G13 accepted by supervising review; see [G13 acceptance](G13-validation.md). Next is G14, one Claude Ralph session. Earlier pending G13 notes below are historical.

# Guardian roadmap

Current host acceptance: G01–G08. [G08 supervisor validation](G08-validation.md)
records the completed host batch and fixes. L01/L02 are now accepted for the
[measured real RF scope](L02-live-validation.md). G09 is accepted after fixes and independent Codex approval; see
[G09 validation](G09-validation.md). G10/G11 bring-up is accepted; see [physical evidence](G11-device-validation.md).
G12 target qualification is accepted: [review and fix](G12-validation.md).
Current: G13 integration is flashed; 11 live board scenarios pass. Finish normal
reconnect and physical screen/video acceptance before G14. See [G13 validation](G13-validation.md).

**Host TDD -> automated live RF validation of the host library -> embed the same
library in StickS3 or another ESP32 -> repeat end-to-end checks -> art.**

## Gates

| Gate | Deliverable | What permits moving on |
|---|---|---|
| G01 | Portable contracts and adapter boundaries | Supervising source review and compiler checks; no claim of working detectors |
| G02 | Reuse/provenance decisions | Pinned native components, licensing and candidate live-test interfaces |
| G03 | Host build/harness and honest baseline for existing code | Linked host targets and meaningful baseline checks |
| G04–G08 | Parser, freshness/grade policy, detectors, advice and presenter | Host TDD: recorded failing checks, minimal fixes, passing checks and refactoring; supervisor verifies |
| L01 | Qualify live-test equipment after host TDD | Real capture and offensive-control interfaces established; missing hardware blocks live testing, not earlier host development |
| L02 | Scripted live RF lab, actual library on the host | Automated offensive stimulus, separate real receiver, live library outputs, assertions and cleanup; required scenarios pass |
| G09 | Foundation review | Own findings fixed, independent review completed, host TDD and L02 evidence accepted |
| G10–G12 | ESP32 adapters and first-board acceptance | Integrate the accepted library, repair retained spike, qualify target profiles and real hardware |
| G13–G14 | On-board live behavior and physical controls | Repeat host live scenarios with board acquisition/output; actual radio-to-display and buttons/persistence evidence |
| G15–G23 | Original 3D persona, five moods, performance and delivery | Real-device visual/performance evidence and final review |

The host library is the production library, not a mock or a duplicate Python
implementation. Host and firmware differ at acquisition, clock, storage and
output boundaries. StickS3 is the first board adapter, never a business-logic
dependency.

## Live means live

The CLI harness automates controlled offensive actions (Bruce if the installed
firmware exposes a verified command interface), live capture from a separate
receiver, execution of the real library, assertions and bounded cleanup. It
must show detections while the events occur. No recorded PCAP, synthetic event,
mock parser or UI animation can satisfy L02. Replays remain useful host tests.

The host can be a Mac or Linux/Pi machine according to verified radio/driver
support. An existing ESP may bridge raw captures if that path is proven, but
Guardian's library runs on the host for L02. This is not permission to move
Guardian onto StickS3 early as a substitute for the host gate.

## Validation ownership

Validation means inspect, fix in-scope defects and verify the fixes. Workers
perform relevant TDD development checks; the supervising assistant independently
owns acceptance. Ralph has no automatic verifier or automatic passes updates.
The live harness is explicitly invoked with configured lab scope; running Ralph
or installing the project does not start RF interference.

Existing pre-TDD code gets an honest baseline. Later tests of that code are
regression evidence, not retrospective proof that it was written using TDD.
“Fully tested” means the documented acceptance cases passed with recorded limits,
not a guarantee against every possible input, environment or attack.

## Preserved work

The earlier unflashed StickS3 spike, canvas, identity evidence and full-flash
backup remain. They save future work but do not bypass host/library gates.
Unknown hardware/control capability blocks the relevant gate; it never becomes
a simulated pass. See [live lab](live-lab.md) and [ordered ledger](ledger-order.md).

## Implementation batches versus acceptance

G03 is reviewed before the host behavior batch. G04–G08 may then be implemented
in sequence with scoped TDD and explicit completion handoffs, without pausing
for manual acceptance after every task. The assistant independently reviews and
fixes that batch afterward. This scheduling choice does not claim that unreviewed
work passed. The runner stops before later live/board phases; L02 remains required
before new ESP32 integration. See [Ralph batching](ralph.md).

# Development history

The dated log that used to open the root README, moved here on 2026-11-20 (G23). The entries are kept as
they were written, in order; each one describes the state on its own date, in the words of that date
("pending review", "nothing is proven on the stick", "accepted for ... scope"). They are not the current
status: the acceptance of each row is in [guardian-tasks.json](../guardian-tasks.json), the measured
status table is in the [README](../README.md), and the evidence for each row is listed in the
[G23 delivery record](G23-delivery.md).

## State log, 2026-11-14 to 2026-11-19

**Current state:** G01–G08 are accepted for their documented host scope after
supervisor validation and fixes. The portable library now includes parsing,
settings ratings, freshness, incident detection, advice and face/details/picker
interaction. The full host suite passes **22/22** entries in both normal and
ASan/UBSan builds. See [G04–G07 review](G04-G07-validation.md) and
[G08 review](G08-validation.md).

L01 and L02 are **accepted for the measured host scope**: all ten live cases
passed with the actual C++ library, including reliable mid-batch stop, burst
recovery, AP/security changes, and stale/drop handling. Both radios are idle.
See [live validation](L02-live-validation.md) and [harness](../lab/live/README.md).
G09 is **accepted for portable foundation scope** after fixes, current-source
normal/sanitized checks, saved-RF re-audit and independent Codex approval.
See [G09 validation](G09-validation.md). **G10 and G11 are now accepted**:
[board repairs](G10-validation.md) passed native build and independent
Codex review; [physical bring-up](G11-device-validation.md) confirms the
corrected screen, both buttons, PSRAM and persistent boot counts on LAB-STICK-1.
The ten-check no-RF ESP32 probe also passed. **G12 is accepted** for host behavior
and Xtensa/RISC-V compile/link qualification; see [supervisor validation](G12-validation.md).
**G13 is accepted** after independent review, host checks and real-board/physical video validation, including the corrected freshness deadline. See [G13 acceptance](G13-validation.md). **G14 (picker/buttons/persistence/ALERT) is accepted** (2026-11-16): host plain+ASan 25/25, on-device companion boot and NVS persistence re-verified, 11-15 owner hands-on and live scenarios reviewed. See [G14 record](G14-companion.md).
**G15 (Guy Fawkes persona) is accepted** (2026-11-16) on owner look-gate: the accepted
face is the owner-supplied v2 "Cyber Guardian" 2D sprite pack (a deliberate amendment of
the original editable-3D contract; trademark risk accepted for personal-lab use only, not
cleared for public release; the owner changed this on 2026-11-20, see the G15 record). On-device display is deferred to a separate integration task.
See [G15 record](G15-persona.md). **G16 (animated Very-good portrait) is accepted**
(2026-11-16): host plain+ASan 26/26, archived build flashed and healthy, owner saw it on the glass.
The on-device video and no-data check move to G16A (portrait). See
[G16 device record](../firmware/evidence/sticks3-G16-boot-20261116.log). **G16A (upright portrait,
USB down; native BMI270 IMU; live TUNE) is accepted** (2026-11-16): host plain+ASan 29/29, archived build
flashed, IMU 200 Hz with 0 drops, TUNE persists across reboot, owner video on the glass. See
[G16A device record](../firmware/evidence/sticks3-G16A-boot-20261116.log). **G16B (signed OTA, rollback, battery) is accepted** (2026-11-16): good update, bad-signature refusal and
self-test rollback all proven over Wi-Fi on the stick; updates are now OTA only (FRONT x3 fast, then yes). See
[G16B device record](../firmware/evidence/sticks3-G16B-ota-20261116.log). Next: G16C Guardian face for every rating +
techy HUD reacting to the IMU.

- [Implementation ledger](../guardian-tasks.json), [execution order](ledger-order.md) and [roadmap](roadmap.md)
- [Attack coverage](attack-coverage.md): every attack the owner's kit can send versus the detectors, what is proven on the stick, what the Guardian cannot see (5 GHz, other channels while locked, silent sniffers, LAN attacks after joining, BLE until G16H). G16J (2026-11-18, pending review): same-name watch on by default, tool shapes, probe-then-answer, noise-floor rule and the "What it cannot see" page are implemented and host-tested; no row is proven on the device yet (`tools/live_matrix.py` records each one when the owner runs it), and [the C5 node](c5-node.md) that will give the Guardian a 5 GHz and BLE eye with the phone as its screen
- [Phone setup (G16M, 2026-11-18, pending review)](../firmware/README.md): hold SIDE 3 s on the home network in the list (or FRONT x3 with no Wi-Fi stored), join the one-time `Guardian-xxxx` access point from the phone, type the network's password on its one page; the stick checks it by joining once and only then stores it. Implemented, host-tested and built; nothing is proven on the stick. Storing the password encrypted needs one eFuse key and one USB sitting (owner decision, see "Credential vault"); until then it is stored plain as before, and the glass and STATUS say so
- [3D head (G21, 2026-11-18, pending review)](../firmware/README.md): the pipeline (Blender projection, `tools/face3d/pack_frames.py`) and the firmware path are implemented and host-tested with the current render set (Very good and Medium, 9 x 3 angles each, 907,351 B embedded); nothing is proven on the stick, and the measured room for frames is about 1.0 MB, not the ledger's 1.9 MB
- [Shake particles obey gravity (G16O, 2026-11-18, pending review)](../firmware/README.md): after a shake the particles fall and pile up on the side of the stick that is down, follow it for as long as the stick is handled, and reform into the face only once it has been held still for 0.6 s (or 20 s after the last shake). Implemented and host-tested (stillness defaults measured on the recorded IMU traces); nothing is proven on the stick
- [A plugged-in Guardian wakes by itself (G16P, 2026-11-18, pending review)](../firmware/README.md): deep sleep also arms a timer (`power.sleep_check_s`, default 300 s); a timer wake reads the PM1 power source before the display, the radio or the IMU are touched, boots when USB power is there and is otherwise counted and back asleep; STATUS and BATTRUN show the checks and what they cost. Implemented, host-tested and built; nothing is proven on the stick, and the "asleep again within a second" number (`check_awake_ms`) depends on the boot time before `app_main`, which is not measured for today's image
- [Art bench (G16Q, owner picked D 2026-11-18; part 2 2026-11-19, pending the glass comparison)](../firmware/README.md): a build variant of the same app (`build.sh build-art-bench`, version suffix `-bench`) boots into a bench that shows candidate renderings of the approved v4 portraits on the real glass, one at a time (today's pipeline, linear-light resize, tuned unsharp, dither, full height, the panel gamma table, 100 % backlight, still versus breathing, a grey ramp), FRONT = next, SIDE = backlight; the frames come from `tools/art/candidates.py`, pinned by sha256. On the stick 2026-11-18 by self-fetch; the owner picked D (linear-light resize, unsharp 0.6/120/1, Floyd-Steinberg dither). Part 2 (2026-11-19): the Guardian's portraits are now D byte for byte; host-tested and built; the glass comparison of the Guardian image is pending
- [Your network is its name (G16R, 2026-11-18, pending review)](../firmware/README.md): a deauth or disassoc burst against any address the stick has heard advertising the picked network's exact name is red (the same-name set is learned from live beacons and probe responses: 8 addresses, forgotten on a new pick, nothing hard-coded), a burst against another name stays amber, the same-name warning keeps its own rule, and the red text reads "Disconnect burst on <name>". Implemented and host-tested; nothing is proven on the stick
- [Burst forensics (G16S, 2026-11-19, pending review)](../firmware/README.md): for the last disconnect burst of each scope the stick keeps up to 8 tuples of receiver / sender / BSSID / channel with their frame counts, the total and the time, and STATUS prints them as `last_burst_network=` and `last_burst_area=` (4 tuples each), so the addresses of a run are read over the TUNE poll with no USB capture; the Details screen shows the top tuple in short form. The TUNE reply buffer grew from 4096 to 8192 so the longer STATUS line is not cut. Implemented and host-tested; nothing is proven on the stick, and the G16R fix direction waits for the first recorded run
- [A nearby burst that also names your network is red (G16T, 2026-11-19, pending review)](../firmware/README.md): the recorded run showed a burst spread over the access points of the channel, with too few frames at the picked network for the red rule, so the stick stayed amber. Now a nearby disconnect burst holding at least one frame that names the picked network (the selected or an approved address, or one heard under its name) is a Network incident, red, with the sentence "Nearby burst also on <name>"; a burst with no such frame stays amber. STATUS prints that tuple with `:own` and the count as `own:<n>` in the burst record. Implemented and host-tested; nothing is proven on the stick
- [Bluetooth pairing-popup spam (G16H, 2026-11-19, pending review; HOST ONLY)](research/ble-popup-spam.md): the portable library now classifies the pairing-popup adverts of the four vendor formats and has two rules, both amber "nearby": several different popup messages from several short-lived addresses inside one second ("Pairing-popup spam nearby"), and one address announcing three Fast Pair products in five seconds. Every number is a `t.ble_*` TUNE key and an uncalibrated hypothesis. Implemented and host-tested; **no BLE scan runs on the stick**: the owner-run Wi-Fi/BLE coexistence spike (`tools/build.sh build-ble-spike`, `BLESPIKE start`) has not been run, so the detector is unfed (`ble_popup:...,unconfigured` in STATUS, no radar slot) and BLE stays a blind spot on the glass
- [Self-fetch lane: signed offers only (G22A, 2026-11-19, pending review)](../firmware/README.md): the stick opens a TUNE session only for an offer signed with the OTA signing key over its own fresh nonce, an expiry and the command list (RSA-3072 PKCS#1 v1.5 SHA-256, checked with the public key it verifies update images with); unsigned, badly signed, replayed, expired or out-of-allowlist offers are refused and counted in STATUS (`tune_offers_refused*`). The update poll is deferred while a red ALERT is active (`ota_auto_deferred`), and an image is installed only when its build stamp is later than the running one (`ota_not_newer`). `tools/tune_session.py` signs with the key file `build.sh` uses and never prints it. Implemented, host-tested and built; nothing is proven on the stick
- [Automated host live RF gate](live-lab.md) and [G01 validation](G01-validation.md)
- [Architecture and platform decision](architecture.md) and [portable contracts and boundaries](contracts.md)
- [Research](research/research.md), [AntiHunter audit](research/wifi-audit.md) and [G02 reuse decisions](research/reuse-decisions.md)
- [Own review and independent review status](review-status.md)

## Independent review notes


G09 uses the owner-selected independent **Codex** CLI, after the recorded Fable usage limit and Opus refusal. See [review dispositions](G09-validation.md) for the actual responses and source hashes. The optional `tools/review-with-claude.py --scope foundation` remains available when Claude is explicitly selected; it is never an automatic fallback. Independent reviewers are read-only, and neither an API failure nor a review alone marks tasks passed.

G22 (final integrated review, 2026-11-19, pending supervisor validation): `tools/review-with-claude.py --scope integrated` ran normal `claude` with `claude-fable-5-2` at high effort and no tools; the verdict was **REVISE INTEGRATED**. The worker's own findings, the reviewer's findings with their dispositions, the two library fixes made with host TDD and everything left open (first of all the unattended, unauthenticated self-fetch TUNE path) are in [docs/review-status.md](review-status.md). The "Current state" paragraphs and the "pending review" bullets above are older than the ledger; `guardian-tasks.json` holds the acceptance of each row.

# Current qualification status — accepted 2026-11-14

L01 is supervisor-accepted. [L02 live validation](L02-live-validation.md) records
qualified identities, exact scope, controls, real reception and reliable stop.
The original worker's blocked record below is historical and superseded by the
owner-authorized equipment preparation and live evidence. G09 remains pending.

## Historical worker record (not current status)

# L01 — capture and stimulus qualification, 2026-11-14

**BLOCKED.** No available pair of independent radios is qualified for the host
live gate. No lab AP has been designated for this task. This is a worker's
qualification record, not reviewer acceptance, RF proof, or an implemented
harness. G02 is accepted in the ledger; L01 remains false. L02 and new ESP32
integration must wait.

Evidence directory (abbreviated `E/` below):
`$GUARDIAN_STORE/ralph/20261114-154815-299021-task-9/qualification/`.
Source snapshots, hashes, commands, stdout, stderr and exit codes are retained
there. No captures, credentials, jobs or device configurations were changed.
No serial port was opened, interface changed, scan started, stimulus sent,
dependency installed, firmware built or flashed. Only documentation changed in
Guardian. Behavior TDD is not applicable to this documentation-only task; no
library checks or retrospective red/green claims are made.

## Inventory and actual hardware observations

Read the home-automations `INVENTORY.md`, Wi-Fi lab `LAB-INVENTORY.md`, RF lab
studies and adapters, Guardian G02 research, device identity and Ralph journal.
`E/inputs-manifest.json` pins the files read. Older RF lab notes about a working
AR9271 do not override the later inventory saying it arrived dead and was
discarded. Historical AntiHunter detections are not runs of Guardian's library.

| Asset | Identity/evidence | Bands and role decision |
|---|---|---|
| Pi `LAB-PI-HOST` | Read-only SSH through existing trusted hostname/key; kernel `6.18.34+rpt-rpi-2712`. `E/pi-readonly.json`. This is distinct from the home automation Pi `LAB-PI-2`. | Existing host candidate; preserve its jobs and uplink. No receiver qualified. |
| Pi `phy0`, `wlan0` | MAC `LAB-PI-WLAN`, SDIO `02D0:4345`, driver `brcmfmac`; only WLAN found by `iw dev`. `iw phy` lists managed/AP/P2P/IBSS, **no monitor mode**. | Reports 2.4/5 GHz frequencies. Active managed uplink on channel 132, default route through wlan0; Ethernet has no carrier. Neither band is qualified for raw monitoring. Do not repurpose it. |
| USB receiver on Pi | `lsusb`: CP210x bridge, Toshiba disk, root hubs; no USB Wi-Fi dongle. | AR9271 unavailable. Old-box generic dongle lacks current chipset, driver, physical assignment and receive evidence. No inferred support. |
| Pi serial device | VID:PID `10c4:ea60`, `/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0` → `ttyUSB0`. | Bridge identity only; board, installed firmware and role unknown. Unprivileged `fuser` returned 1/no output; that is not an exclusive-ownership guarantee. Left closed. |
| Preserved Bruce StickS3 | Previously identified USB serial/MAC `LAB-BRUCE-STICK`; exact 8 MiB flash backup hash rechecked below. Not currently visible as that USB identity. | ESP32-S3, 2.4 GHz only; candidate emitter, not qualified. Existing spike and recovery backup preserved. |
| LILYGO T-Embed CC1101 Plus / Cardputer ADV | Existing inventory and user-reported Bruce use; neither exact installed build nor stable current USB identity established here. | S3 Wi-Fi is 2.4 GHz; CC1101/nRF24 do not add 5 GHz Wi-Fi. Do not equate shared VID/PID with the identified StickS3. |
| AntiHunter ESP | Existing records describe an S3 N16R8 and detector telemetry; installed build/connection not established in this session. | Existing adapters return counters/incidents, not a qualified raw-frame serial feed for Guardian. C5 inventory does not prove an available dual-band bridge. |
| Mac USB | Initial serial listing had no USB serial device. Later `E/mac-usb.json` found `M5AccessibilityS3 Head Pointer`, serial `LAB-STICK-1`, VID:PID `303a:1001`. | A different device with an existing assistive role; excluded and untouched. No qualified Mac receiver/emitter. |

Initial sandbox DNS failed. The historical numeric Pi address `.166` failed
strict SSH host-key validation; no trust entry was added or bypassed. A read-only
network escalation using `LAB-PI-HOST` succeeded; the actual default-route
source address was `.229`. The first shell's PATH omitted `/usr/sbin`, so its
`iw: command not found` was corrected by checking absolute paths. **iw is
installed** (`6.9-1+b1`). These access/tool-path issues are not hardware failures.

## Host capture backend: selected interface, missing receiver

Use Linux **libpcap** on a dedicated, fixed-channel monitor radio, separate from
the emitter and uplink. Installed Pi packages are `libpcap0.8t64 1.10.5-2` and
`tcpdump 4.99.5-2`; tcpdump reports libpcap 1.10.5 with TPACKET_V3.
`E/pi-tool-interfaces.json` records package versions. Dumpcap was not found at
the inspected standard path; it is not an installed dependency or requirement.

The documented read interface for a later host adapter is `pcap_create`, capture
options, `pcap_activate`, `pcap_datalink`, `pcap_next_ex`/`pcap_dispatch`,
`pcap_stats`, and `pcap_close`. Monitor capability can be queried with
`pcap_can_set_rfmon`; `pcap_set_rfmon` configures it. These are **not called in
L01**. A timeout on the capture buffer is not a hard process deadline.
[libpcap 1.10.5 API reference](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.5/pcap.3pcap.in).

Qualification must record the new receiver's USB serial/location, VID/PID,
chipset, driver/firmware, kernel, phy/interface and actual supported band/channel.
Then verify live radiotap + 802.11 input (`DLT_IEEE802_11_RADIO`), frame lengths,
capture timestamps, tuned frequency, RSSI availability, FCS convention and drop
statistics. An Ethernet/cooked datalink from a managed interface cannot pass.
A monitor capability flag alone is insufficient; actual received management
bytes and metadata still need evidence. No replay fallback.

Adapter constraints follow `guardian/radio.hpp`: strip radiotap and known FCS
before bounded copy; preserve caplen versus reported length and truncation;
channel comes from acquisition metadata rather than advertised DS parameters.
Unknown RSSI/error/FCS information stays unknown or causes a counted drop as the
contract requires. Count kernel, interface and application queue losses
separately; unsupported counters are not zero-loss proof. Fixed-channel listening
intervals and interruptions must be measured, not inferred from process uptime.
Preserve capture-time freshness through buffering and transport; a new host
receipt time must not refresh old frames. Record clock domains, mappings and
uncertainty before asserting latency. Prefer running acquisition and Guardian on
the same Linux host once its build and resource suitability are verified in L02.

AntiHunter's existing `serial_guard.py` (RF lab revision below) sends
`DEAUTH_START:<secs>` and reads `[BLUE]` counters / `[DETECT]` summaries at 115200.
Those lines lack the MAC-header bytes, security IEs and per-frame metadata
Guardian needs. Its comments also report reset-on-open. The original AntiHunter
`network.cpp` at `c6ef921e6fffa1e2969c539c2dddb496d24c120a` serves
`GET /api/deauth.jsonl` from an SD log. A log or saved PCAP is not a continuous
live raw feed. Do not run the existing guard: it can arm detectors, install a
service and send notifications. No proven existing ESP raw bridge was found.

## Bruce: installed-image evidence versus upstream interfaces

Re-read only the preserved flash image, never NVS/config contents. Its SHA-256
remains `c6de1ad11aa1da226d0022ef654d9a49e4ed5b8dcc60c89a5179d8944d2b91e8`.
`E/backup-inspection.json` records the app partition at `0x180000`, descriptor at
relative offset 32, project `arduino-lib-builder`, descriptor version
`idf-master-104-g43a8f6d-dirty`, IDF `v5.5.4-dirty`, build Aug 26 2026 17:43:27.
The app contains `board_M5StickS3`, `1.10.3`, `optionsJSON` and `run_from_buffer`.
This inspection did **not** find the exact combined literal `Bruce StickS3
(BETA)` reported in the older identity note. Preserve that note as historical
evidence; do not promote its probable version into a confirmed runtime version.
Neither `1.10.3` nor `v1.10.3` resolved as an upstream commit/tag through the
connector. A binary string is not a source revision, active-partition proof,
enabled-feature proof or successful command response.

Official upstream reference inspected and archived: Bruce
`2b6ba4d490bfcf94ce2574c6154537dbd5838c3d` (commit message `1.17`), **not claimed
to match the installed image**. `E/bruce-source-manifest.json` records SHA-256
and Git blob hashes; `E/bruce-source/` retains the six inspected files/license.

| Source / exact interface | Finding and qualification limit |
|---|---|
| [Official serial protocol](https://wiki.bruce.computer/controlling-device/serial/) | 115200, 8N1, no flow control. Serial commands or WebUI `POST /cm` with `cmnd` form field are documented. WebUI availability/authentication and response behavior are unverified on the installed unit. |
| [util_commands.cpp](https://github.com/BruceDevices/firmware/blob/2b6ba4d490bfcf94ce2574c6154537dbd5838c3d/src/core/serial_commands/util_commands.cpp), `infoCallback`, `createUtilCommands` | `info` prints version, Git hash, SDK, MAC and device; `help`, `optionsJSON`, `options` and `loader list` exist. `options <index>`, `loader open <app>`, `nav <command> [duration]` drive menus. Navigation acknowledgments mean key/menu activity, not RF start/stop acknowledgment. No commands sent. |
| [wifi_commands.cpp](https://github.com/BruceDevices/firmware/blob/2b6ba4d490bfcf94ce2574c6154537dbd5838c3d/src/core/serial_commands/wifi_commands.cpp), `createWifiCommands` | Registers `wifi`, `webui`, `arp`, `listen`, `sniffer`; no dedicated BSSID/channel/count/rate deauth command. `sniffer` enters UI and explicitly has a serial-exit TODO. `wifi off` is not a proven stimulus-stop protocol. |
| [interpreter_commands.cpp](https://github.com/BruceDevices/firmware/blob/2b6ba4d490bfcf94ce2574c6154537dbd5838c3d/src/core/serial_commands/interpreter_commands.cpp) and [wifi_js.cpp](https://github.com/BruceDevices/firmware/blob/2b6ba4d490bfcf94ce2574c6154537dbd5838c3d/src/modules/bjs_interpreter/wifi_js.cpp) | `js run_from_buffer <size>` and `js exit` depend on build flags. The reviewed Wi-Fi JS file provides scan/connect/disconnect/HTTP/address functions, not a bounded raw deauth API. Script execution does not establish one. |

Bruce is programmatically navigable in this upstream source. It is **not
qualified here for unattended bounded scenarios**: installed command support,
menu transitions, target binding, count/rate/deadline enforcement and effective
stop all lack runtime proof. Do not claim that Bruce universally lacks remote
control. `nav esc`, `js exit`, closing serial or power commands are not accepted
emergency-stop guarantees without verification of the actual running function.

The local Wi-Fi lab `bruce_usb.py` opens at 115200 with DTR/RTS false, sends
`display stop` then `info`, writes newline-terminated commands and waits for a
`# ` prompt. Its script transport uses an `EOF` line and binary storage reads to
transfer existing files. This is neither a pure passive probe nor live radio
control; it was inspected, not imported or executed.

## Alternative emitters and exact control limits

**Existing ESP backend rejected for qualification.** RF lab commit
`749fb4884a9515b18882126e1d596bbe60b3c935` contains
`firmware/esp32-wifi-deauth/esp32-wifi-deauth.ino` and
`rf-brow-cli/src/brow/adapters/esp32wifi.py`. The inspected bytes match those Git
objects (`E/local-source-manifest.json`). An unrelated dirty tracker file was
left untouched. The documented line protocol is 115200:
`help`, `scan`, `deauth <bssid> <channel> <count>`, `stop`; responses include
`OK deauth start ...`, `PROGRESS ...`, `OK deauth done ...`, `OK stop` or `ERR`.

Source defects prevent accepting that protocol as bounded control:

- `cmd_deauth` blocks inside `handle_line`; only the outer Arduino `loop` reads
  serial. Therefore `stop` cannot be parsed during that send loop.
- Each requested count causes three transmit calls, whose return codes are
  ignored. The completion count is iterations, not confirmed RF frames. No
  upper count, duration watchdog or configurable rate limit is enforced.
- `PyserialEsp32Port.command` stops on the first `OK ` line, including the start
  response; its adapter can mistake start for completion and even maps an empty
  response to `OK`. Port opening may reset hardware; current firmware identity
  is unknown. Its automatic scan is active and outside this session's work.

These are source findings, not new runtime experiments. Repairing the sibling
project or flashing this firmware is outside L01. No code was copied into Guardian.

**Documented lab-only fallback: Linux aireplay-ng on a second dedicated
injection-capable radio.** It is already installed on the Pi:
`aircrack-ng 1:1.7+git20230807.4bf83f1a-2`. Only `--help` was run (exit 1 with
usage output). Pin the corresponding upstream base
`4bf83f1a7631d6721c17a35597d2f71b35ff30bf`; retained source and license are in
`E/aircrack-source/`. Debian packaging patches and actual driver behavior are
not verified by matching that base revision.

The exact command interface for a **future explicitly scoped** directed burst
is `aireplay-ng --deauth 1 -a <LAB_BSSID> -c <LAB_CLIENT_MAC> <EMITTER_MONITOR_IF>`.
This is a non-executed interface specification with unresolved placeholders.
No count zero, omitted client, broad target discovery, replay input or other
attack mode belongs in this plan. Both AP and client must be designated lab
devices. The emitter interface must be on a physically different phy from the
receiver and must not be the host's uplink.

One count is **128 transmit calls**, 64 in each direction, not one frame.
`do_attack_deauth` sleeps 2 ms after each call; `-x` does not implement a deauth
rate limiter in that function. Thus the source has nominal pacing no faster
than 500 calls/s, not a measured airtime guarantee. Driver retries/queueing and
delayed cancellation need physical qualification. Stdout/ACK counters do not
prove what Guardian received. [Official command documentation](https://www.aircrack-ng.org/doku.php?id=deauthentication),
[pinned implementation](https://github.com/aircrack-ng/aircrack-ng/blob/4bf83f1a7631d6721c17a35597d2f71b35ff30bf/src/aireplay-ng/aireplay-ng.c).

No separate injection radio is currently identified. This is a supported
software interface, **not a qualified installed hardware backend**. A different
available radio or a verified bounded Bruce controller could replace it after
qualification; no hardware purchase or firmware change is prescribed here.

## Lab scope and proposed bounds — not an enabled configuration

| Required field | Recorded value / blocker |
|---|---|
| Owner-designated lab SSID and raw SSID bytes | **UNSET**. Do not derive consent from a capture filename, current uplink or historical RF test. |
| Lab BSSID / approved related BSSIDs | **UNSET**. Exact allowlist required; no same-name wildcard. |
| Channel / width / band | **UNSET**. Propose one fixed 2.4 GHz 20 MHz channel after AP designation, consistent with existing S3 candidates. No hopping or 5/6 GHz acceptance inferred. |
| Dedicated test client | **UNSET**. Needed for directed fallback stimulus and ordinary reconnect controls. |
| Receiver stable identity / phy / interface | **UNSET**; Pi uplink and discarded AR9271 rejected. |
| Emitter stable identity / installed version | **UNSET**; Bruce image candidate identified historically, runtime unresolved. |
| AP configuration/readback/restore interface | **UNSET**; no router automation or spare controlled AP established. |
| Effective independent emergency stop | **UNSET**; host process stop and physical power isolation must be proved for chosen emitter. |
| RF operation allowed in this worker session | **None**: duration 0, frame budget 0. |

Proposed future session ceiling is 180 seconds per explicit scenario. For the
Linux fallback, at most one directed group (128 transmit calls), a 5-second
emitter-process deadline, 2 ms source pacing and no automatic retry. At most
one group per explicit run, with at least 120 seconds between groups. A tighter
instantaneous rate requirement would need another qualified backend; do not
pretend `-x` supplies it. These are reviewable proposed limits, not installed
enforcement or permission to target the home's uplink.

| Required scenario | Proposed bound and control | Present status |
|---|---|---|
| Quiet baseline / ordinary reconnect | 60 s receive-only baseline; at most two owner-designated test-client reconnects in a separate 60 s control | Blocked: receiver/AP/client identities and client control absent |
| Disconnect burst | One directed group above; observe ≥10 s before and ≥15 s after; qualify against actual 20-observation/10 s detector default, deduplication and coverage | Blocked: receiver and bounded installed emitter missing |
| Cooldown / recovery | Continue real observation for ≥70 s after the burst; 180 s total ceiling covers the default 60 s cooldown | Blocked: live capture unavailable; no repeated group silently added |
| Approved / unexpected baseline changes | ≤2 controlled AP configuration transitions in 120 s; exact AP identities in scope, explicit baseline approval separate from observations | Blocked: controlled AP identities and controller/readback absent. The default threshold is two qualifying advertisements, which may come from one unapproved BSSID; distinct BSSIDs are reported separately, not used as that threshold |
| Receiver interruption / drops | One ≤5 s interruption of this run's acquisition only; ≤60 s scenario; retain pre/post counters and source epochs | Blocked: no receiver; never interrupt Pi uplink or another job |
| AP security-mode change | One designated spare AP change plus restore in ≤120 s, verify advertised bytes after each | Blocked: AP/control API/restore snapshot absent; controller intent cannot substitute for received frames |

An elapsed duration is not adequate observation. Packet loss, incomplete
metadata, protected bodies, duplicate sequences, absent acknowledgments or
failed cleanup require FAIL/INCONCLUSIVE/UNSUPPORTED as appropriate, never a
fresh reassuring grade. Required cases remain visible even if a candidate
backend supports only disconnect bursts. No credentials, data payload capture,
password recovery, captive portal, broad beacon spam or RF jammer is required.

For later Linux control, the deadline must run on the emitter host, survive
controller/SSH loss and own only this run's process group. On success, error,
interrupt or lost heartbeat: stop that group (SIGTERM, then SIGKILL after a
bounded 1 s grace), verify exit, and independently observe cessation; a driver
may still drain queued frames. Physical power isolation of the **identified
emitter only** is the recovery path if cessation cannot be established. Finish
capture/stats, close handles, remove only interfaces created by the run and
restore the designated AP's saved state with readback. Save cleanup failures;
do not retry or advance. Never use global `pkill`, `airmon-ng check kill`, change
wlan0, stop another service, or delete existing captures. No such cleanup was
needed here because no scenario was started.

## Provenance, checks and handoff

Bruce and AntiHunter carry AGPL-3.0 licenses in the inspected revisions. The
local ESP emitter header instead says GPL-3.0 and asserts Bruce derivation
without a pinned original revision: that discrepancy needs provenance review
before reuse. Aircrack's pinned LICENSE is GPL version 2; retain its file-level
notices and applicable source obligations if distributing it. Libpcap remains
an external host dependency candidate; preserve the applicable version/file
notices if later linked or redistributed. No third-party implementation is
imported or linked into Guardian by L01; source/license copies are review
artifacts in the store, not native ESP dependencies. External emitter firmware does
not relax Guardian's native ESP-IDF/no-Arduino architecture.

Actual checks: the store existed and evidence writes succeeded; Pi USB/driver/phy,
package and help queries were read-only; saved flash size/hash/descriptor were
reproduced; three local adapter/firmware files match pinned Git objects; Bruce
snapshots have content and blob hashes. Final documentation/link/manifest and
unchanged-ledger checks are in `E/verification.json`. SSH scripts' exit 1 values
are retained (`fuser` no accessible holder; aireplay help), not converted into
successful radio tests. Earlier failed SSH attempts and the failed XML ioreg
read are documented in `E/access-notes.txt`; the later descriptor query is the
usable USB evidence.

To unblock L01, the supervisor needs a designated AP/SSID/BSSID/channel/client
and AP control/restore path; an available independent raw receiver with live
byte/metadata proof; the actual emitter connected and identified, with installed
control support, effective bounds and stop behavior demonstrated. Qualified
identities must replace every UNSET field before any explicit live launch.
No replay or telemetry-summary substitution, automatic L02 advance, or board
integration is justified. The supervising assistant alone validates/fixes and
sets acceptance; this handoff deliberately ends **BLOCKED**.

## Supervisor review — 2026-11-14

The qualification evidence supports BLOCKED, not a live-library failure.
See [supervisor review](L01-review.md). The unexpected-AP scenario above was
corrected against `BaselineDetector::maybe_report`: its threshold counts
qualifying advertisements, not distinct AP identities. No library behavior changed.

## Owner-authorized receiver preparation update

The subsequent [hardware preparation record](../lab/receiver/STATUS.md) identifies
the Pi WROOM and Cardputer, preserves both original flash images, and records
the installed acquisition-only Cardputer bridge. The earlier inventory above is
historical, not a claim that the bridge is still absent. L01 remains unaccepted
pending complete scope/control/timing qualification. The portable library stays
on the host; no Guardian UI/business logic was moved onto a board.

# Attack coverage: what the Guardian sees, what it proves, what it cannot see

Owner's question (2026-11-17): *"for every single attack that I try, our guardian must guard and alert. Is it true
now?"* This page is the honest answer and the plan to make it true for everything a 2.4 GHz passive listener can
see. It is kept current by the G16J work; every "proven" row names its evidence file.

Status words: **proven** = the incident fired on the real StickS3 with time-to-alert recorded; **unproven** = a
detector exists, never exercised by this attack on the device; **blind** = no detector, or physics; **scope** = out of
scope by decision.

## State of the G16J work (2026-11-18, worker handoff, pending supervisor review)

**Still no on the device.** What changed is on the HOST: the rules below are implemented in the portable library
and proven by host fixtures (an attack stream firing once per cooldown, a benign twin never firing;
`firmware/tests/coverage_check.cpp`, 36 cases, and the rewritten noise cases in `firmware/tests/datapath_check.cpp`).
The image `guardian-20261118-012503` builds and is signed, and was **not flashed and not run on the stick**: no row
below moved to "proven" in this handoff. The owner runs every attack; `tools/live_matrix.py` records each row.

| limit of 2026-11-17 | now (host) | still open |
|---|---|---|
| 1. one channel while locked | optional area sweep behind TUNE `detect.sweep_ms` (100 ms every 2 s), **default 0 = off**; the Details page says "channel N only" or "channel N + area sweep" | spike (b) decides the default: not run (needs the Pi emitter's burst and the stick) |
| 2. 5 GHz invisible | printed on the glass: Details page "What it cannot see" | physics |
| 3. evil-twin watch off, no control | **on for every picked network** (and a selection saved earlier is upgraded once); TUNE `detect.twin`; "hold blue: my AP" in the list approves the owner's own other APs; RED text "Another device is using your network's name" | live rows 5, 6 |
| 4. data path off | unchanged: **default off**, Details prints "handshake watch: off"; the noise-floor watch no longer needs the data path | spike (a) decides the default: prepared (`tools/datapath_spike.py`), not run (the stick was busy with the 12 h soak) |

Spikes (ledger: recorded before any threshold is written):

| spike | state | evidence / command |
|---|---|---|
| (a) data-path load, 10 min off then on | **not run** (the 12 h benign soak held the USB port until about 11:48 on 2026-11-18; a worker session never touches the device) | `tools/datapath_spike.py --port /dev/cu.usbmodemXXXX` writes `firmware/evidence/sticks3-G16J-spike-a-datapath-<date>.log` and the verdict "on" / "off (load)" |
| (b) own-channel loss under the area sweep | **not run** (needs live RF: the Pi emitter's burst at threshold) | flash the new image, then `TUNE detect.sweep_ms=100`, run `lab/live` scenario `burst` twice (sweep 0, sweep 100) and compare `burst_count`, `rx_queue_full`, `rx_discarded`; keep 0 if the red path loses frames |
| (c) benign ceiling per detector | **recorded for 56 min; the 12 h run was still going** | `firmware/evidence/sticks3-G16J-spike-c-benign-ceiling-20261118.log` (`tools/soak_ceiling.py <soak.jsonl>`); re-run on `evidence-raw/soak-benign-20261118-001818.jsonl` when it ends |
| (d) karma shape of Evil Spear / Marauder Karma | **not captured** (the owner runs the tools) | Mac: `sudo tcpdump -I -i en0 -w karma-<tool>-<date>.pcap 'type mgt'` on the tool's channel while a phone probes a remembered name; the probe-then-answer rule's 10 s / 2 frames / 30 s learn time are hypotheses until then |

Thresholds written without their spike (and why that is safe to review): only the probe defaults moved
(80 / 60 / 5 s to 16 / 12 / 10 s), and they are the values the owner's stick already ran: proven on the Evil-M5 probe
flood on 2026-11-17 and silent through the benign soak (in_window_max 15 against 16, spike (c)). Every other number
is unchanged or a new hypothesis marked "Guardian" in `guardian/threats.hpp`, a TUNE key, default chosen to fail
quiet. The two spike-gated defaults stayed at their safe side (data path off, sweep 0).

## The honest answer on 2026-11-17

**No.** Proven live so far (run lines in `firmware/evidence/G16D-H-batch-desk-review-20261117.log:138-189`):

| attack | tool | result |
|---|---|---|
| deauth flood on the selected network | Bruce (LilyGO) | RED, `disconnect` 2 incidents (128 frames), `area_disconnect` 4 |
| deauth against neighbouring APs | Brucegotchi | amber, `area_disconnect`, rating unchanged |
| probe flood | Evil-M5 Cardputer | amber only after TUNE `t.probe_flood=16`, `t.probe_flood_sources=12`, `t.probe_window_ms=10000`; the code defaults (80 / 60 / 5 s) gave 0 incidents |
| deauth | Evil-M5 Cardputer (this build) | 0 frames on air: the tool did not transmit, not a Guardian miss |
| beacon spam | Evil-M5 Cardputer | `beacon_flood` fired (amber); counts not recorded (peer session, 2026-11-17) |

Four facts bound "every attack":

1. **One channel at a time.** The radio locks to the selected network's channel and does not scan while locked
   (`firmware/adapters/measurement/measurement.cpp:132-148`, `firmware/boards/sticks3/main/measurement_radio.cpp:66-75`).
   Attacks on the owner's AP happen on that channel, so they are heard. Area attacks elsewhere are heard only when
   the attacker passes over this channel: the probe-flood run heard about 1/13 of a 13-channel hopper.
2. **5 GHz is invisible.** The ESP32-S3 radio is 2.4 GHz only (`measurement_radio.cpp:21-29`;
   `docs/research/research.md:83`). The owner's router is dual band. An ESP32-C5-based attacker (Bruce, Evil-M5 and
   Poseidon all have C5 nodes) deauthing the 5 GHz side is never seen. Physics, not a bug: it goes on the glass.
3. **The evil-twin watch is off.** `UnexpectedAp` (same network name from a new BSSID = RED) needs `watch_impostors`,
   default off, with no on-device control (`firmware/components/guardian_core/detectors.cpp:466`,
   `detectors.hpp:81-84`, `firmware/adapters/companion/companion.cpp:226-228`). The most common consumer attack
   (clone the SSID, then deauth) shows only its deauth half today.
4. **The data path is off.** `handshake` (PMKID harvest, fake M1, deauth then handshake) and `frame_loss` stay
   "unconfigured" until TUNE `detect.datapath=1` (`measurement.cpp:156`, `measurement_main.cpp:1039`;
   `firmware/evidence/sticks3-G16F-attack-baseline-20261117.log:2`). The device load numbers that gate it were never
   taken.

Measured by the peer session on the probe flood: Evil-M5 "Probe Attack" hops channel on EVERY probe (about 33 per second over 13 channels), so one channel hears about 1/13: quiet 0-4 probes per 5 s, attack 10-14. Under the Bruce deauth flood `rx_queue_full` grew 1324 to 1391 and detection survived; coverage flapped 35-38 times before the 3 s hysteresis fix, once after. OTA fails while a deauth flood is live.

Also: the thresholds are AntiHunter's hypotheses, not measured on this radio on one channel (the probe flood shows
they are too high for a single-channel listener); karma on the kit's tools is one SSID per SoftAP with a rotating MAC,
which the "one transmitter answers many names" rule can miss; silent sniffing and LAN attacks after joining (ARP spoof,
rogue DHCP, Responder) leave no management frame to see.

## The owner's kit versus the detectors

Sources read 2026-11-17: ESP32 Marauder v1.18.0 (`WiFiScan.cpp`, `MenuFunctions.cpp`), Evil-Cardputer v1.5.8
(`Evil-Cardputer-v1-5-8.ino`, `src/wifi_csa.h`, `src/wifi_sae.h`), AntiHunter `upstream/main` (lukeswitz, 2026-11-17),
M5PORKCHOP / POSEIDON / M5Gotchi / Palnagotchi READMEs. Bruce and GhostESP were not on disk: their rows are from
memory and marked. No code was copied from any of them (AntiHunter is AGPL-3.0; behaviour only, constants as
hypotheses; see `research/reuse-decisions.md`).

| # | attack (2.4 GHz) | tools that send it | frames | Guardian detector | scope / colour | status |
|---|---|---|---|---|---|---|
| 1 | deauth flood, broadcast, spoofed as the AP | all | deauth 0xC0 | `disconnect` ≥20 in 10 s on the selected or approved BSSID; `area_disconnect` elsewhere. **G16R (accepted 2026-11-19):** the count covers every address heard advertising the picked network's exact name (one window for all of them), because a tool that targets by name walks all of a router's addresses | Network RED / Area amber | **proven** on the selected address (Bruce RED; Brucegotchi amber). By name against a router with several addresses: 2026-11-18 it gave amber twice (red count 4-7, nearby 43-58); the G16R fix is host-tested only (`g16r_*` in `coverage_check`), **unproven on the device**. **G16T (accepted 2026-11-19):** the recorded run (12:12) was a burst spread over the channel's access points with at most a few frames at the picked network, so `area_disconnect` reached its threshold and `disconnect` did not; now a nearby burst holding at least one frame that names the picked network (Address 1, 2 or 3) is Network RED ("Nearby burst also on <name>", `own:<n>` and the `:own` tuple in `last_burst_network`), and one with none stays amber. **RED, proven 2026-11-19** on the device: the owner's Bruce run against his own name gave the red "Nearby burst also on <name>" on the glass (video 13:28) and `last_burst_network` `own:4` with the selected address's `:own` tuples (13:47, guardian-20261119-133525; the record now persists after a later nearby-only burst). Evidence `firmware/evidence/sticks3-G16T-20261119.log` |
| 2 | targeted deauth to one client | all | deauth to one station | `disconnect` counts it; G16J: the pair rule (≥12 in 1 s, ≥6 with a tool shape) on the selected network too (`area_disconnect`, network pattern "Disconnects aimed at one device on your network") | Network RED | unproven on the device; host: `targeted_pair_on_the_selected_network_is_red_once_per_cooldown` |
| 3 | disassoc (reason 8) | PORKCHOP, Spacehuhn (memory) | disassoc 0xA0 | `disconnect` counts disassoc | Network RED | unproven on the device; host fixture `disassociation_reason_8_burst_is_red_once_per_cooldown_and_roaming_never` (baseline, green from the start) |
| 4 | beacon spam (random, list, rickroll) | all | beacons | `beacon_flood` ≥40 BSSIDs at ≥ -65 dBm in 10 s | Area amber | **proven** on Evil-M5 (fired; counts and time-to-alert still to record) |
| 5 | AP clone spam (copies real SSIDs) | Marauder, Bruce, GhostESP | beacons with real names | G16J: `UnexpectedAp` **on by default**; `rotation` / `beacon_flood` at half the count when the beacons carry a tool shape (static timestamp, interval 1000, placeholder address) | Network RED when it is the owner's name | unproven on the device (host: `picking_a_network_turns_the_same_name_watch_on`) |
| 6 | evil twin / evil portal with the owner's SSID, plus deauth | all | SoftAP beacons + probe responses + deauth | G16J: `UnexpectedAp` on by default + `disconnect` | Network RED | unproven on the device |
| 7 | open lure portal ("Free WiFi", "Starbucks") | all | open beacons with lure names | G16J: `rotation` LurePortal: an open lure-word name from an Espressif-assigned address, ≥3 beacons in 5 s (376 prefixes from the IEEE registry). Lure words are ours: free, guest, public, open, hotspot, airport, hotel ("Starbucks" alone is NOT one) | Area amber | unproven on the device; a tool that randomizes its address is missed by this rule |
| 8 | karma (one SSID per SoftAP, MAC rotates per target) | Evil-M5 (Karma Auto waits for named probes, none at home; Karma Spear needs `/evil/KarmaList.txt` on an SD card), Marauder, Bruce | probe responses / beacons for names phones asked for | G16J: `responder` probe-then-answer: a device asks for X, within 10 s a BSSID never heard before the ask sends ≥2 frames with X (not approved, name not already advertised, after 30 s of listening); the old many-names rule halves for the placeholder address 12:34:56:78:9A:BC | Area amber | unproven on the device; needs spike (d) and a phone probing a known name or the SD list. Known look-alike: a hotspot switched on within 10 s of a device asking for it by name |
| 9 | probe flood (random or custom SSIDs) | Evil-M5, Marauder, Spacehuhn | probe requests | `probe_flood`, G16J defaults 16 / 12 / 10 s; half of that when ≥3 probes carry sequence control 0x0001 | Area amber | **proven** at 16 / 12 / 10 s (now the code defaults) |
| 10 | pwngrid / pwnagotchi beacons | Evil-M5, Bruce (Brucegotchi), Palnagotchi, M5Gotchi | beacons from DE:AD:BE:EF:DE:AD, element 222 | `marked_beacon` | Area amber | unproven |
| 11 | channel-switch attack (CSA beacon) | Evil-M5 (`wifi_csa.h`), Marauder | spoofed beacon with CSA | `channel_switch`: count ≥50, or a flap on the selected AP; G16J: count 0xFF is marked as a tool shape | Network RED / Area amber | unproven on the device |
| 12 | Quiet element | Marauder | spoofed beacon with Quiet | `channel_switch`: Quiet ≥1000 TU | Network / Area | unproven |
| 13 | SAE commit flood | Evil-M5 (`wifi_sae.h`), Marauder | auth, algorithm 3 | `sae_commit`: commits minus confirms ≥10 in 5 s | Network / Area | unproven; the router must be WPA3 |
| 14 | auth flood | Spacehuhn-class tools (none in the kit) | open-system auth | `auth_flood` ≥60 frames from ≥16 sources in 5 s | Network / Area | unproven; Pi emitter replay |
| 15 | assoc-sleep | Marauder | (re)assoc request with the power-management bit | `assoc_sleep` ≥8 frames or ≥4 sources in 5 s | Network / Area | unproven |
| 16 | "Bad Msg": forged EAPOL M1 to clients | Marauder | data frame, EAPOL, all-zero ANonce | `handshake` fake-M1 (data path off); G16J: also a template PMKID (16 equal bytes or a 11 22 33 ... ramp) | Network RED | **blind** until the data path is on (spike (a)) |
| 17 | PMKID or handshake capture with deauth | all | deauth, then EAPOL | `handshake` deauth-then-handshake (off) + `disconnect`; G16J: after SHAPED disconnect frames the burst halves (5 to 3) and the handshake counts for 30 s instead of 8 s; replay counter 0xF000..0xFFFE or a template PMKID halve the harvest rule (3 APs to 2) | Network RED | deauth half only until the data path is on |
| 17b | jamming (noise) | SDR, nRF24 jammers, microwave ovens | no frames: the noise floor rises | G16J `noise_floor` (replaces `frame_loss`): ≥8 dB above the channel's own 60 s average for 3 s; needs no data path; the receive-error share is printed as evidence on the Nearby page when checksum-failed frames are delivered | Area amber | unproven on the device; a jammer that stops ALL reception leaves no reading (then the network goes "No fresh data") |
| 18 | silent PMKID / handshake sniff, wardriving | all | nothing transmitted | none, by physics | | **blind** (physics) |
| 19 | hostile SSIDs (CIW Zeroclick, 157 payloads) | Poseidon, Evil-M5 | beacons with hostile names | parser and text robustness, not a detector | | host fuzz fixtures green from the start (baseline): 12 hostile names through parser, rating, labels, every screen, JSON and STATUS, plus overlong and cut name elements (`hostile_names_never_crash_never_change_the_rating_and_are_clipped`, run under ASan by host-check). Device row: `pi-hostile-ssid` |
| 20 | BLE spam (Apple, Samsung, Swift Pair, Fast Pair, Flipper) | all | BLE advertising | G16H (2026-11-19, host only): `ble_popup`: >= 3 different popup messages from >= 3 short-lived addresses in 1 s; one address with >= 3 Fast Pair models in 5 s ([sources, gaps](research/ble-popup-spam.md)) | Area amber | **library ready, stick NO-GO at useful duty, C5 node.** MEASURED 2026-11-19 (coexistence spike run A, `firmware/evidence/sticks3-G16H-coex-spike-20261119.log`): selected-AP beacon loss = scan duty (3.3 / 10.3-11.0 / 26.6 / 51.5 % at 3 / 10 / 25 / 50 % passive duty), heap and queue fine; any duty that could feed these rules costs the Guardian a quarter to a half of its frames, so the stick runs no BLE scan by design (Details "What it cannot see" lists Bluetooth). The live feed comes from the C5 node (G16K, [c5-node.md](c5-node.md)). Rules host-tested only. Not covered at the defaults: one product from ever-new addresses, an address change slower than 1 s, one fixed address with a non-Fast-Pair format, Flipper's own advert |
| 21 | anything on 5 GHz (C5 nodes) | Bruce, Evil-M5, Poseidon with C5 | | none, 2.4 GHz radio | | **blind** (physics) |
| 22 | LAN attacks after joining (ARP spoof, rogue DHCP, Responder, MITM) | Evil-M5, Bruce, GhostESP | data frames inside the network | none (no data inspection) | | scope |

## What it cannot see (goes on the glass and in the README)

- 5 GHz and 6 GHz: the radio is 2.4 GHz only.
- Other channels while locked: area threats are heard on the owner's channel (plus strong neighbours) only.
- Silent sniffers: a listener that never transmits leaves nothing to see.
- Attacks inside the network after a client joined (ARP, DHCP, DNS, HTTP): no data inspection.
- BLE floods: the rules exist in the library since G16H (host-tested); the stick runs no BLE scan by design (coexistence NO-GO at useful duty, measured 2026-11-19); the C5 node (G16K) will feed them.
- WPS PIN attacks, KRACK (client-side counters), rogue RADIUS: no passive frame signature.
- While it checks for an update: every `ota.auto_s` seconds (default 120) the stick stops listening, joins the home
  Wi-Fi, asks the Mac for a TUNE offer or a signed image, then surveys the channels again. Nothing is heard during that
  time, and a TUNE session it finds pauses listening for the whole session. The length of the gap is not measured yet
  and this line is not on the glass yet (G22 review, findings O1 and O2 in [review-status.md](review-status.md)).
  Since G22A (2026-11-19, pending review, not yet proven on the stick) only an offer signed with the OTA signing key
  opens a session, and a due check is put off while a red ALERT is active, so the check no longer interrupts an
  incident; it still interrupts listening at every other time.
- A copy of the picked access point's own address: a transmitter that beacons with the picked BSSID, name, settings
  and channel is counted as the network itself. It raises no "another device is using your network's name" and its
  beacons keep the evidence fresh, also while the real access point is off. Nothing compares beacon timestamps or
  sequence numbers per address yet (G22 independent review, finding H3; not on the glass yet).
- Who is attacking: the Guardian names the behaviour ("deauth burst on your network"), never a tool or a person.

## AntiHunter upstream (2026-11-17) against ours: adopt or reject, as hypotheses

AntiHunter moved 505 commits since our read (c6ef921, Aug 2026). Its core thresholds are unchanged; it added tool
shapes and rewrote jamming. The AGPL rule holds: behaviour and constants only, re-implemented independently.

| ours | AntiHunter today | decision |
|---|---|---|
| `disconnect` ≥20 in 10 s on the selected AP, retries deduplicated | DEAUTH_FLOOD 20 in 10 s per source with ≥8 gaps ≤150 ms; pair burst 12 in 1 s; shapes: reason 2 + sequence 0xFFF0, reason 7 + duration 0x013A, rising sequence, deauth/disassoc alternation | adopt the pair burst on the selected network; adopt the four shapes as confidence (threshold halves when the shape matches); keep retries deduplicated, never dropped |
| `area_disconnect` | same per source | add the gap timing to cut false bursts from AP reboots |
| `baseline` UnexpectedAp (off) | SELF_CLONE with a 60 s grace; SSID_COLLISION (learns OUIs 300 s, then 2+ OUIs within ≤4 BSSIDs in 60 s); TWIN_MULTICH (same BSSID on two channels, 4 flips in 15 s); TSF_RESTART (two backward jumps in 30 s) | on by default when a network is picked, with "approve this AP"; adopt TSF restart and multi-channel twin as two more evidences |
| `probe_flood` 80 / 60 / 5 s, single 60×3, behavioural 40 | identical, plus Marauder probe sequence 0x0001 (≥10 in 5 s per SSID) | measured defaults (16 / 12 / 10 s proven here); adopt the 0x0001 shape as confidence |
| `beacon_flood` 40 BSSIDs ≥ -65 dBm in 10 s | identical; pauses the other beacon checks except CSA/Quiet while active | adopt the pause; measure Evil-M5 and Bruce spam counts on one channel first |
| `rotation` 12 names in 5 s, OpenLure | FORGE_SSID_ROTATE 12 in 5 s; FORGE_EVIL_PORTAL_ESP (open + Espressif OUI + lure word); TSF static, beacon interval 1000, CSA count 0xFF, Bruce karma transmitter 12:34:56:78:9A:BC | adopt all as confidence shapes; no tool names on the glass |
| `responder` (karma) ≥4 names or ≥2 asked names from one transmitter | KARMA_CAND 2 names in 60 s, confirmed by bait probes (transmits: rejected) | new passive probe-then-answer rule: a phone asks for X, then within 10 s a never-seen BSSID answers or beacons X → amber |
| `name_mismatch` | SSID_CONFUSION, same rule | keep |
| `marked_beacon` | PWNAGOTCHI, same rule | keep; prove with Palnagotchi and Brucegotchi |
| `channel_switch` count ≥50, Quiet ≥1000, flap | same, plus CSA count 0xFF | adopt 0xFF |
| `owe_twin` on | OWE_ABUSE, default off there | keep on |
| `auth_flood` 60 / 16 / 5 s, `sae_commit` 10 in 5 s, `assoc_sleep` 8 or 4 in 5 s | identical | keep; prove SAE once the router runs WPA3; auth flood from the Pi emitter |
| `handshake` (off): PMKID orphan 3 BSSIDs in 10 s, zero ANonce, deauth then handshake | same, plus hcxdumptool replay counter 0xF000..0xFFFE, a forged PMKID pattern, handshake pairs within 5 s of a deauth burst, EAPOL within 30 s of a deauth ("bait") | on by default after the load spike; adopt the replay range, the pattern and the bait timing as confidence |
| `frame_loss` (off): error-ratio rule | rewritten: noise floor ≥8 dB above a 60 s moving average for 3 s, per channel; "silence" rule opt-in | our rule is the one they dropped; adopt the noise-floor rule (`noise_floor` is in `wifi_pkt_rx_ctrl_t`), keep the error ratio as evidence text |
| — | RECON probe scoring, randomized-MAC identity linking | reject: tracking people is out of scope |
| — | FRAG (FragAttacks) | deferred (`research/reuse-decisions.md`) |
| — | JAMMING_BASELINE silence | adopt as evidence text only while locked ("no frames for N s on your channel") |

### What of that table G16J implemented, and what it did not (2026-11-18)

Implemented on the host (independent code, no AntiHunter code read into the library; the upstream file was read for
BEHAVIOUR on 2026-11-18, and the constants it shows are facts about frames tools send): the pair burst on the selected
network; the shapes reason 2 + sequence control 0xFFF0, reason 7 + Duration 0x013A, rising sequence (ours: only to ONE
destination, so an AP saying goodbye to each client never matches), deauthentication / disassociation alternation,
CSA count 0xFF, probe sequence control 0x0001, a timestamp that never advances (ours: any repeated value over 5
beacons and 500 ms, not one hard-coded constant), beacon interval 1000, transmitter 12:34:56:78:9A:BC, replay counter
0xF000..0xFFFE, a template PMKID (ours: 16 equal bytes or a constant-step ramp; the PMKID value is still never kept),
the 30 s bait window (ours: only after shaped disconnect frames), the open lure name from an Espressif-assigned
address, the probe-then-answer rule, the noise-floor rule with the error ratio as evidence only.

Not implemented (still open, none of them silently dropped): the ≥8-gaps-≤150 ms timing on area deauth floods; TSF
restart and same-BSSID-on-two-channels as extra evil-twin evidence; SSID_COLLISION by learned OUIs; pausing the
other beacon checks while a beacon flood is active; the "no frames for N s on your channel" evidence text. Rejected as
before: bait probes (transmits), tracking people, naming a tool.

## How a row becomes "proven"

The owner runs every live attack; sessions only prepare. One command per row:

```
tools/live_matrix.py --list                                   # the rows, what to start, the benign twin
tools/live_matrix.py --port /dev/cu.usbmodemXXXX --row bruce-deauth
```

It only LISTENS (STATUS over USB, MAC-gated to the StickS3; the same recorder as `tools/threat_watch.py`): 10 s
quiet, then the owner starts the attack and presses Enter (the mark), 60 s attack, the owner stops it and presses
Enter, 60 s benign twin. It writes the raw stream to the store `evidence-raw/matrix-<tool>-<attack>-<stamp>.jsonl` and
`firmware/evidence/sticks3-G16J-<tool>-<attack>-<date>.log`, and prints the status cell to paste into the table
above. PASS = an expected detector fired within 1.75 s of the mark (1.5 s plus one 0.25 s poll) and the twin stayed
silent.

Honest limit of that number: it is measured from the owner's key press to the first STATUS showing the incident, so
it includes the tool's start-up and the frames needed to reach the threshold. It is an upper bound on "alert after the
closing frame"; the detectors report ON the closing frame (host cases assert the acquisition time), and the closing
frame's own time on air needs the second receiver (Pi or Mac capture).

Rows the kit cannot send are meant to be replayed by the Pi ESP emitter through `lab/live/` (`pi-*` rows). **Not
built in this handoff:** the emitter firmware still sends only its bounded 26-byte deauthentication template (at most
24 frames) and the test AP; the scenarios disassoc, targeted pair, auth flood, PMKID orphan, fake M1, CSA 0xFF,
Quiet and hostile SSIDs need new frame templates, limits and a re-flash of the Pi's ESP32, each with its own review.
Note: that template is reason 2 with sequence control 0xFFF0, so the existing `burst` scenario already exercises the
fixed-sequence shape (red at 10 frames instead of 20). Rows nothing can send stay "blind" with the reason, never
silently dropped.

## Thresholds: what is measured and what is a hypothesis

| rule | default | source | evidence |
|---|---|---|---|
| `probe_flood` random sources | 16 probes from 12 addresses in 10 s | **measured** on this radio, one channel | attack: `firmware/evidence/G16D-H-batch-desk-review-20261117.log`; benign ceiling 15 in 10 s: `sticks3-G16J-spike-c-benign-ceiling-20261118.log` |
| `disconnect` burst (selected network) | 20 in 10 s; 10 with a tool shape | 20: proven on the Bruce flood (128 frames); the half: hypothesis | G16D-H log; host `shaped_disconnects_halve_the_red_burst_threshold_once_per_cooldown` |
| pair rule (selected network and nearby) | 12 in 1 s; 6 with a tool shape | hypothesis (AntiHunter-described) | host only |
| `beacon_flood` | 40 BSSIDs at ≥ -65 dBm in 10 s; 20 shaped | hypothesis; benign: 197 strong beacons in 10 s were seen (distinct BSSIDs not recorded by STATUS) | spike (c); Evil-M5 / Bruce counts still to record |
| `auth_flood` | 60 frames from 16 addresses in 5 s | hypothesis; benign ceiling 2 in 5 s | spike (c) |
| `area_disconnect` source | 20 in 10 s; 10 shaped | hypothesis; benign ceiling 1 in 10 s | spike (c) |
| probe-then-answer | answer within 10 s, 2 frames, after 30 s of listening | 10 s: ledger; the rest: hypothesis | needs spike (d) |
| lure portal | 3 open lure beacons in 5 s from an Espressif-assigned address | hypothesis | host only |
| tool shapes | 3 frames with a per-frame shape, or a run of 6; 5 beacons repeating one timestamp over ≥500 ms; bait window 30 s | hypothesis (behaviour described for AntiHunter upstream) | host only |
| `noise_floor` | ≥8 dB above the channel's 60 s average for 3 s, ≥5 frames a second, ≥10 seconds of average | 8 dB / 60 s / 3 s: ledger; the rest: hypothesis | host only; no noise-floor readings were ever recorded on this stick (STATUS does not print them) |
| data path | off | waits for spike (a) | - |
| area sweep | off | waits for spike (b) | - |

Every row is a TUNE key (`t.*`, `detect.*`); the registry holds 105 of 112.

## Order of work (G16J, after G16I, before the 3D head G21)

1. Spikes, recorded first: data-path load on the stick (fps, drops, heap, 10 min off / on); own-channel loss under a
   bounded area sweep (100 ms every 2 s) with the Pi emitter's deauth burst at threshold; karma shape of Evil Spear
   and Marauder Karma captured on the Mac or the Pi; the benign ceiling per detector from the 12 h soak
   (`$GUARDIAN_STORE/evidence-raw/soak-benign-20261117-232211.jsonl` 23:22-23:53, 0 incidents; `soak-benign-20261118-001818.jsonl` 00:18 to about 11:48).
2. Evil twin on by default plus the approve flow. 3. Data path on by default if the spike allows. 4. Thresholds set
   from measurements. 5. Karma probe-then-answer rule. 6. Confidence shapes. 7. Disassoc and hostile-SSID fixtures.
   8. The honesty line on the Details screen and in the README. 9. Live matrix with the owner, row by row.

Done in the 2026-11-18 handoff (host): 2, 5, 6, 7, 8, the probe part of 4, the tools for 1(a), 1(c) and 9. Open: the
spikes (a), (b), (d) themselves, 3 (waits for (a)), the remaining thresholds of 4, the Pi-emitter scenarios, and 9
(every row on the device).

G16K (approved 2026-11-18, spike first): a 5 GHz + BLE eye, a second Guardian node on the owner's ESP32-C5 with the phone
as its screen through Droidputer over USB OTG; see [c5-node.md](c5-node.md). Rows 20 and 21 move from "blind" to "C5 node"
once proven. BLE (G16H) comes last, after a read of open-source BLE-spam detectors (Wall of Flippers, AntiHunter's
removed BLE signatures, GhostESP and Marauder detect modes).

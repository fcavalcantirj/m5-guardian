# G23 delivery record

Worker handoff of 2026-11-20 (attempt `20261120-003149-572201-task-44`), pending supervisor
validation. **G23 is open.** This record separates what was measured from what is prepared and what
only the owner can run.

Labels used below: **[DEVICE]** = recorded on the real StickS3 (the file is named); **[LIVE-HOST]** =
real radio received by the library on the host; **[HOST]** = host check on fixtures or generated
packets (not radio evidence); **[SOURCE]** = read in the code or a pinned file; **[OPEN]** = not done.

## 1. What this attempt did, and what it did not

Done by the worker (no device, no radio, no flash, no ledger edit):

| Item | Result |
|---|---|
| Channel-lock losses per reason (ledger step "CARRY-OVER for the worker") | `Survey` counts each reason; STATUS prints `lock_loss_by=silence:<n>,followed:<n>,held:<n>,stopped:<n>` after `last_lock_loss=`. Lock behaviour unchanged. Host TDD: red 11 failed assertions, green 0 [HOST] |
| Dim view during an ALERT when left on Details or the list (G22 review H2) | Reproduced by a test (it also showed "NO DATA" with a fresh rating), then fixed: the dim view always takes the Face screen's decision. Host TDD: red 14 failed assertions, green 0 [HOST]. The look on the glass is [OPEN] |
| Setup access-point password (G22 review carry-over) | 8 symbols (38.9 bits) raised to 10 (48.6 bits; min-entropy 48.3). 10 glyphs at 2x fit the row. Host TDD: red 4 failed assertions, green 0 [HOST]. On the glass [OPEN] |
| `libnet80211.a` provenance | Measured and written into THIRD_PARTY_NOTICES.md: until 2026-11-20 the builds read a modified file (4 bytes in one function that was never in an image); the vendor original was restored on 2026-11-20 and the delivery image is built from vendor SDK files only (section 6) |
| Stillness gate (G16O carry-over) | **Not tuned: no slow-tilt recording exists.** The nine recorded traces hold no slow tilt. A measurement tool and the numbers of the nine traces are ready (section 7); the defaults are unchanged |
| Root README for a public reader; the state log moved to docs/history.md | done |
| firmware/README.md: delivery section (build, assets, USB device, install, restore), headings re-read against the ledger | done |
| Native-resolution stills of the five moods | Host renders only, labelled as fixtures (section 5). Device stills and the video are [OPEN] |
| Public tree | `python3 -I tools/public_check.py --require-map`: 0 findings, with the owner's private map applied, on the tree the delivery image is built from (the count of files and the output are in the handoff) |
| Delivery image | Built last, from the tree that holds this record, so the archive's `source.tar.gz` contains this file and the record cannot name its own stamp: it is the newest `builds/20261120-*-sticks3` archive, named with its version and hashes in the handoff. Signed and archived only: not installed, not run |

Checks run by the worker on the final sources (all [HOST]; logs under
`$GUARDIAN_STORE/builds/20261120-g23-tdd/` and `builds/20261120-005617-host-ytWTff/`):

| Check | Result |
|---|---|
| Red, through the CMake targets, with stubs holding the pre-task behaviour | `measurement_check` 1 failed case (11 assertions), `companion_check` 1 (14), `setup_check` 1 (4); every older case still passed |
| Green, the same targets plus `idle_check` | 0 failed cases |
| `firmware/tools/host-check.sh`, plain | 54 of 54 |
| `firmware/tools/host-check.sh`, ASan/UBSan | 53 of 54 in the full run. The one failure was the new lock-loss test itself: it stated a capacity of 50 for a 32-byte buffer, and the sanitizer stopped it. The library was right to write up to the stated capacity. The test line was corrected and `measurement_check` rebuilt in the same two build trees: plain pass, ASan/UBSan pass (227 assertions). Of the 226 hashed sources only that test file differs from the full run. The full sanitizer run was not repeated |
| Portability rule (`portability_check.cmake`) | pass: 33 portable sources |
| Python suites (`tools/tests`, `boards/sticks3/tests`) | 215 passed, 2 skipped (the two need the built offer verifier and the ESP-IDF Python; untouched code) |
| Board build (first, before the documents) | signed archive `guardian-20261120-005434`: SHA256SUMS 25 of 25, 2,887,680 B signed, 258,048 B of the slot free, the new STATUS field present in the signed image |

Not done, and not doable by a worker session (each needs the device, the owner's hands or the owner's
own test traffic): the stills and the video from the device, the live incident recording with its
expiry, the unrelated-network negative case, the alert-first proof, every carry-over device line of
section 4, the credential vault, the slow-tilt recording, the ALERT-eyes measurement on the panel.
Section 8 is the prepared run sheet.

## 2. Versions

| | |
|---|---|
| ESP-IDF | v5.4, commit `67c1de1eebe095d554d281952fde63c16ee2dca0` |
| Compiler (firmware) | xtensa-esp-elf-gcc esp-14.2.0_20241119 (14.2.0) |
| Build Python | 3.10.10 (the ESP-IDF environment) |
| Host checks | CMake 4.1.2, Apple clang 21.0.0 (clang-2100.4.1.1), Darwin arm64; plain and ASan/UBSan (`firmware/tools/host-check.sh`, run `builds/20261120-005617-host-ytWTff`); Python 3.10.10 with pytest for the tool suites |
| Delivery image | version `guardian-20261120-<time>`, read from the archive's `guardian_app_version.txt` (see section 1) |
| Image on the stick at the last read (2026-11-19 23:45) | `guardian-20261119-221810` (G22A) [DEVICE: firmware/evidence/sticks3-G22A-20261119.log] |
| TUNE registry version on the stick | 1.31 (2026-11-19 21:52 read) [DEVICE: sticks3-G22-20261119.log] |

The delivery image has **not** been installed or run. Its numbers on the stick (STATUS, frame times,
heap) do not exist yet.

## 3. Requirement-to-evidence table

### 3.1 By requirement (ledger step 6)

| Requirement | Evidence | Kind | Limits and what is untested |
|---|---|---|---|
| Source audit and licensing | docs/G02-validation.md, docs/research/reuse-decisions.md, docs/research/wifi-audit.md, THIRD_PARTY_NOTICES.md, LICENSE, firmware/art/LICENSE | [SOURCE] | Every SDK input is the vendor original since 2026-11-20; the earlier modified radio library is recorded (section 6). Publication of the persona art and of the lab stimulus firmware: owner's decisions, not stated here |
| Native build | `firmware/boards/sticks3/tools/build.sh build`; archive with SHA256SUMS, sdkconfig, SDK revisions, signed image; docs/G10-validation.md, docs/G12-validation.md | build + [DEVICE] boot logs | Built on one machine. The USB restore route was written down and never exercised |
| Raw-frame parser | `parser_check`, `mgmt_parser_check`, hostile-name fixtures, the optional libwifi comparison (docs/G04-parser.md, docs/G04-G07-validation.md); live frames in L02 and G13 | [HOST] + [LIVE-HOST] + [DEVICE] | Malformed frames are covered by fixtures and a sanitizer run, not by a fuzzing campaign |
| Real access-point setting change | L02 `settings-01`: WPA2-Personal to WPA3-Personal (PMF required) and back, 1,477 frames (docs/L02-live-validation.md); G13 `settings`: 923 frames on the board, and the owner video `settings-video-03` (docs/G13-validation.md) | [LIVE-HOST] + [DEVICE] | Only that one change, on the lab access point. Other transitions are fixtures (section 3.3) |
| Stale data | L02 and G13 `stale` and `drop`; the board showed "No fresh data" after the incident cleared in `settings-video-03`; host: `removing_fresh_evidence_replaces_the_portrait_with_no_data` | [LIVE-HOST] + [DEVICE] + [HOST] | The no-data demonstration with the delivery image (the owner's shielded stick) is [OPEN] |
| Passive coverage | Coverage report and channel lock in STATUS; G13 `channel`, `quiet`; the "What it cannot see" page; docs/attack-coverage.md | [DEVICE] + [SOURCE] | One channel while locked; 2.4 GHz only; listening stops during each update check. The length of that gap is not measured. Channel-lock losses exceed update polls (section 9) |
| Anomaly false positives | Benign soak: 0 false incidents in 9.8 h outside the owner's own 17-minute test window (firmware/evidence/sticks3-G16J-spike-c-benign-ceiling-20261118.log); L02 `quiet`, `reconnect`; G13 `quiet` | [DEVICE] + [LIVE-HOST] | One site, one night. The 12 h soak at the present defaults is [OPEN] (G16J carry-over) |
| Advice | `advice_check` (docs/G07-advice.md); the wording on the glass in the owner's G16 to G20 looks | [HOST] + owner look | Advice follows advertised settings only. It says nothing about password strength |
| The five expressions | Accepted v4 portraits, sha-pinned (`persona_check`, firmware/art/persona/v2/manifest.json); owner on the glass 2026-11-17 and 2026-11-19 (ledger G15 to G20, G16Q); host stills of section 5 | owner look + [HOST] | The contract was amended by the owner on 2026-11-16: the accepted faces are 2D portraits. The 3D head exists and is off (section 3.2, G21). Device stills and video for this delivery are [OPEN] |
| Buttons | firmware/evidence/sticks3-LAB-STICK-1-buttons-20261114.log; `keys_debounce_short_and_long_presses`; owner hands-on 2026-11-15 | [DEVICE] + [HOST] | |
| Physical performance | 24.9 frames a second; particle frame worst 33.7 ms (sticks3-G16O-20261119.log); dark wake on an incident 53 ms to evidence, 101 ms to frame (ledger G16N); timer-wake USB check 974 and 986 ms of 1000 (sticks3-G16P-20261119.log); 3D frame inflate 14.8 ms (ledger G21) | [DEVICE] | Battery life from full to empty with BATTRUN is [OPEN] (G16D carry-over). RSA check time on the stick is not measured |

### 3.2 By ledger row

| Row | Subject | Ledger | Evidence | Open inside the row (carried into G23) |
|---|---|---|---|---|
| G01 | Portable contracts | accepted | docs/G01-validation.md, docs/contracts.md | |
| G02 | Reuse and licensing review | accepted | docs/G02-validation.md | |
| G03 | Host build and harness | accepted | docs/G03-validation.md | |
| G04-G07 | Parser, ratings and freshness, detectors, advice | accepted | docs/G04-G07-validation.md | |
| G08 | Presenter | accepted | docs/G08-validation.md | |
| L01, L02 | Live radio on the host | accepted | docs/L01-review.md, docs/L02-live-validation.md | |
| G09 | Foundation review | accepted | docs/G09-validation.md | |
| G10-G12 | Board repairs, bring-up, target profiles | accepted | docs/G10-validation.md, docs/G11-device-validation.md, docs/G12-validation.md | |
| G13 | Live scenarios through the ESP32 adapter | accepted | docs/G13-validation.md (11 scenarios) | |
| G14 | List, keys, persistence, ALERT | accepted | docs/G14-companion.md, firmware/evidence/sticks3-G14-boot-20261116.log | |
| G15 | Persona | accepted | docs/G15-persona.md | |
| G16, G16A | Very good portrait; upright platform, motion sensor, TUNE | accepted | sticks3-G16-boot-20261116.log, sticks3-G16A-boot-20261116.log | |
| G16B | Signed updates, rollback, battery state | accepted | sticks3-G16B-ota-20261116.log | |
| G16C | Faces and HUD on every screen | accepted | sticks3-G16C-20261117.log | |
| G16D | Dim, deep sleep, key wake | accepted | sticks3-G16D-codec-sleep-fixed-20261117.log, G16D-H-batch-desk-review-20261117.log | BATTRUN on battery, 10 sleep and wake cycles, 10-minute runs, DEMO and video checks |
| G16E | Detection platform, nearby scope, radar | accepted | G16D-H-batch-desk-review-20261117.log | |
| G16F | Management-frame detectors | accepted | sticks3-G16F-attack-baseline-20261117.log, G16D-H-batch-desk-review-20261117.log | responder (needs the tool's list on an SD card), authentication and SAE flood live proofs, 12 h soak reading |
| G16G | Data-path detectors | accepted (host) | `datapath_check` | device load with the data path off and on (`tools/datapath_spike.py`), the owner's live proof per tool mode |
| G17-G20 | Good, Medium, Bad, Horrible | accepted | ledger notes of 2026-11-17 (v4 pack in `guardian-20261117-203615`) | |
| G16I | Upright by gravity, shake burst | accepted | nine recorded traces (firmware/evidence/sticks3-imu-shake-*-20261117.txt), ledger note | the owner's shake and upright checks on the glass with `motion.upright=1` |
| G16J | Attack coverage | accepted | sticks3-G16J-spike-c-benign-ceiling-20261118.log, docs/attack-coverage.md | **no `sticks3-G16J` device log of the Verify items**: data-path load spike, sweep-loss spike, the live matrix rows (`tools/live_matrix.py`), the 12 h soak |
| G21 | 3D head | accepted, off by default | ledger note: one inflate 14.8 ms on the stick; room for frames about 1.0 MB, not 1.9 MB | **no `sticks3-G21-*.log`**. Recorded as optional: `head.on=0`, two of five moods have frame sets (845,551 B in the image) |
| G16M | Phone setup | accepted | sticks3-G16M-20261119.log | the credential vault (owner's decisions); the 10-symbol password on the glass |
| G16N | Guard in the dark | accepted | sticks3-G16N-spike-20261118.log | S3 as one sequence: second burst re-lights, battery floor sleeps |
| G16O | Particles obey gravity | accepted | sticks3-G16O-20261119.log | the pile reforms during a slow tilt (section 7) |
| G16P | Self wake on USB power | accepted | sticks3-G16P-20261119.log | |
| G16R-G16T | Network by name, burst records, nearby burst that names the network | accepted | sticks3-G16R-20261119.log, sticks3-G16S-20261119.log, sticks3-G16T-20261119.log | |
| G16Q | Art pipeline | accepted | sticks3-G16Q-artbench-20261118.log | ALERT eyes: measure on the panel before any change; no new art |
| G16H | Bluetooth popup-spam rule | accepted (host only) | sticks3-G16H-20261119.log, sticks3-G16H-coex-spike-20261119.log | not watched on the stick, by design |
| G22 | Integrated review | accepted | sticks3-G22-20261119.log, docs/review-status.md | findings carried into G22A and G23 |
| G22A | Signed session offers, alert-first poll, newer-only update | accepted | sticks3-G22A-20261119.log | the alert-first device proof |
| G23 | Delivery | **open** | this record | everything marked [OPEN] here |
| G16U | Bluetooth guard | open (release 2) | | not built |

### 3.3 Router modes

| Advertised mode | Rating | Seen live | Where |
|---|---|---|---|
| WPA3-Personal, PMF required | Very good | yes, lab access point | L02 `settings-01` [LIVE-HOST]; G13 `settings` and video [DEVICE] |
| WPA2-Personal (CCMP), PMF not required | Medium | yes, lab access point (PMF disabled) | the same runs |
| The owner's home router | Medium on 2026-11-16 | yes | firmware/evidence/sticks3-G16A-boot-20261116.log ("real LIVE rating (Medium, 0 s ago)") [DEVICE]. The advertised fields of that reading are not in the log |
| WPA2-Personal with PMF required | Good | **no** | fixtures and the DEMO walk only |
| WPA/TKIP (legacy) | Bad | **no** | fixtures and the DEMO walk only |
| Open, WEP | Horrible | **no** | fixtures and the DEMO walk only |
| WPA2/WPA3 transition mode | Medium | **no** | fixtures only |
| WPA3-Enterprise, OWE, 6 GHz-only settings | by the rating policy, or shown as not rated | **no** | fixtures (`rating_check`, `parser_check`) or not covered |

The five faces were all seen on the glass through the labelled DEMO walk, which is a display check and
not a reading.

### 3.4 Detector limits and unsupported threat types

- Proven on the device: a disconnect burst on the picked network (red), a disconnect burst nearby
  (amber), a probe flood (amber), a beacon flood (fired; counts not recorded). Every other family is
  host-tested only. The table with each row's state is docs/attack-coverage.md.
- Not seen at all: 5 GHz and 6 GHz, other channels while locked, a listener that never transmits,
  traffic inside the network after a client joined, Bluetooth on this board, WPS PIN attempts, client-side
  key reinstallation, a rogue authentication server.
- Counted as the network itself: a transmitter that copies the picked access point's address, name,
  settings and channel (G22 review H3). Open.
- Thresholds: the probe-flood numbers and the 20-in-10-s disconnect burst were measured on this radio.
  The other numbers are hypotheses taken from the reviewed reference or written here, each a TUNE key.
- An incident states counts, scope and a time window. The cause is always "unknown". No claim of
  detecting every attack, and none of identifying who sent the frames.
- The update check is a listening gap of unmeasured length every 120 s; it waits for a red ALERT, not
  for an amber one.

## 4. Carry-overs: state after this attempt

"Device line" is the evidence line the ledger asks for before G23 can pass. None of them exists yet.

| Carry-over | State now | Device line still needed |
|---|---|---|
| G16O pile reforms while tilted | Not tuned; tool and nine-trace numbers ready (section 7) | A slow-tilt recording (`IMU 10` while tilting slowly), `still_trace` output, the Author's values, then the owner's look |
| G16M credential vault | Untouched (owner's decisions; firmware/README.md "Credential vault") | `cred_store=encrypted cred_vault=<state>` after the USB sitting |
| G16N S3 as one sequence | Untouched | `darks`, `dark_wakes` after two bursts, and a STATUS or BATTRUN field naming the floor sleep |
| G16Q ALERT eyes | Untouched (measure first; no new art) | desk-camera frames of the ALERT pair on the panel |
| G16D battery and sleep items | Untouched | BATTRUN from a run on battery, 10 sleep and wake cycles |
| G16F | Untouched | live rows for the responder and the authentication floods, or their recorded absence |
| G16G data path per tool mode | Untouched | `tools/datapath_spike.py` log, then the owner's run per mode |
| G16I upright and burst | Untouched | the owner's look with `motion.upright=1` |
| G16J device Verify items | Untouched | `firmware/evidence/sticks3-G16J-*.log` from `tools/live_matrix.py` |
| G21 | Recorded as optional and off, with the measured numbers (section 3.2) | none asked beyond this record; a `sticks3-G21` log if the head is ever switched on |
| Dim view shows NO DATA during an ALERT on Details | **Fixed on the host** (red then green) and in the delivery image | a camera frame of the dimmed stick left on Details during an incident: red edge and "ALERT" |
| Setup password strength | **Raised to 10 symbols** on the host and in the delivery image | the 10-character password on the setup screen |
| `libnet80211.a` provenance | **Restored** to the vendor original on 2026-11-20 (owner's delegated decision); history and measurements in THIRD_PARTY_NOTICES.md | none (a document item) |
| READMEs against the ledger | **Done** (root README rewritten; firmware/README.md headings and the stale lines corrected) | none |
| G22A alert-first | Host proof exists; device proof prepared (section 8, step 5) | `ota_auto_deferred` +1 with the ALERT on the glass, then the poll after the alert |
| Lock losses per reason | **Implemented** (host TDD) and in the delivery image | one STATUS read of `lock_loss_by=` after 30 minutes or more; then the Author rules on a fix |

## 5. Stills, video, live observation

| Asked | State |
|---|---|
| One native-resolution still per mood | **Host renders only** [HOST]: `$GUARDIAN_STORE/art-exports/G23/20261120-host-stills/` (19 PNG files of 135x240, SHA256SUMS, a 2x contact sheet). Written by `companion_preview` with the real composer, renderer and the shipped portraits; the input is generated packets. Not device evidence |
| The same from the device | [OPEN]. The firmware has no framebuffer capture command, so a still from the device is a camera photo, not native resolution. A capture command over USB would give exact 135x240 frames; it does not exist and was not added here (not asked) |
| One video of all five faces and the transitions | [OPEN] (owner; the DEMO walk shows the five faces in order) |
| A live observation and a no-data demonstration | [OPEN] for the delivery image. Earlier device records: the live Medium reading of 2026-11-16 and the G13 video ending in "No fresh data" |
| Live incident turning the face red, then expiry and no-data | [OPEN] for the delivery image. Earlier device records: the owner's runs of 2026-11-19 (sticks3-G16T-20261119.log: red on the glass in the 13:28 video, burst record read at 13:47) |
| Unrelated-network negative case | [OPEN] as a deliberate run. What exists: a nearby-only burst stayed amber on 2026-11-19 (it was not a run aimed at a chosen other network) |

What the host stills show (looked at on 2026-11-20): Very good has the wide grin and the cigar with
smoke; Good smiles without a cigar; Medium has a closed, level mouth; Bad has raised inner brows and a
downturned mouth; Horrible bares its teeth with red eyes. The ALERT pair has red eyes and a red frame;
no fresh data is a grey outline with the words and the age. This confirms what is in the image's
pixels. It does not confirm how the panel shows them.

## 6. The SDK radio library (modified until 2026-11-20, vendor original since)

Measured 2026-11-20; the text for readers is in THIRD_PARTY_NOTICES.md. The commands below record the
state before the restore of 2026-11-20; since then `git -C $L status --short` prints nothing and the
file's sha256 is the pinned original's (5b90eb4f...4ba9), and `build_support.py` refuses any SDK change.

```sh
L=<idf>/components/esp_wifi/lib
git -C $L status --short                       # " M esp32s3/libnet80211.a" and nothing else
git -C $L show HEAD:esp32s3/libnet80211.a | shasum -a 256     # 5b90eb4f...4ba9 (pinned original)
shasum -a 256 $L/esp32s3/libnet80211.a                          # 5c9bb61b...56d1 (the file the builds read)
cmp -l <original> <modified> | wc -l           # 4
```

The 4 bytes are in the archive member `ieee80211_output.o`, section
`.text.ieee80211_raw_frame_sanity_check`, offset 95 of 508. In the image the section is discarded:

```sh
A=$GUARDIAN_STORE/builds/<stamp>-sticks3
awk '/^Discarded input sections/{d=1} /^Memory Configuration/{d=0} d && /\.text\.(ieee80211_raw_frame_sanity_check|esp_wifi_80211_tx)$/' $A/guardian_sticks3.map
xtensa-esp32s3-elf-nm $A/guardian_sticks3.elf | grep -c -E 'raw_frame_sanity|esp_wifi_80211_tx'
```

Result on `guardian-20261120-001058` and on `guardian-20261120-005434` (this attempt's first build,
with the three code changes): both sections printed (discarded), symbol count 0. The same two commands
are run on the delivery image; their output is in the handoff.

Not measured: an image built from the pinned original, for a byte comparison. A build step that
refuses an image in which either function is linked would turn "the firmware has no raw-frame
transmit call" into a per-build proof; it was not added here (a build-tool change nobody asked for).

## 7. Stillness gate: measurements, no change

The owner's observation (2026-11-19): during a slow tilt the particles came back sooner than they
should. The gate calls a frame "moving" when the up vector turned faster than `burst.still_dps`
(12 degrees/s) since the frame before, and starts the reform after `burst.calm_s` (0.6 s) without a
moving frame. A tilt slower than 12 degrees/s therefore passes as still by construction [SOURCE:
`Burst::stirred`]; at that limit the stick may turn 7.2 degrees inside the calm time.

**No recorded trace contains a slow tilt**, so no number was changed. What the nine G16I recordings
give [HOST, recorded device traces through the real motion model at 25 frames a second;
`$GUARDIAN_STORE/builds/20261120-g23-tdd/still_trace-nine-traces.txt`]:

| trace | net turn of the up vector over 0.6 s (p50 / p99 / max, degrees) | calm reached at the defaults |
|---|---|---|
| `still` (held in the hand) | 0.4 / 1.0 / 1.0 | 2 times |
| `setdown` | 0.3 / 1.3 / 1.3 | 1 time |
| `walk` (a stick lying still) | 0.3 / 1.6 / 2.3 | 1 time |
| `tap` (continuous handling) | 30.5 / 101.4 / 104.1 | 1 time, in a 0.68 s pause |
| `shake`, `softshake`, `front3`, `drop2` | 7.9 to 38.6 / 34.4 to 111.3 / 35.2 to 113.5 | never |
| `drop` | 7.8 / 45.0 / 48.0 | 1 time |

Lowering `burst.still_dps` alone costs the hand-held case: on `still`, 12 % of the frames are
"moving" at 6 degrees/s, 26 % at 4, 49 % at 2. A hand-held stick turns at most 1.0 to 1.3 degrees
net in 0.6 s, while a tilt of 5 degrees/s turns 3 degrees in the same time: the net turn over the calm
window may separate the two where the frame-to-frame rate does not. That is a hypothesis until a
slow-tilt recording is measured.

One command gives the numbers for any recording (built by the host build; a tool, not a test):

```sh
<host build>/still_trace <recording.txt> [<recording.txt> ...]
```

It prints the turn and shove percentiles, the net turn over 0.6, 1.0 and 1.5 s, and, for the
firmware defaults and a grid of `still_dps` by `calm_s`, how often the calm time was reached. A
slow-tilt recording should reach calm 0 times; a hand-held one at least once.

## 8. Prepared owner run (not run)

The owner starts every step that needs the stick or test traffic. Commands are for the Mac the stick
was provisioned with; `<stamp>` is the delivery archive of section 1.

1. **Install.** `python3 tools/ota_serve.py $GUARDIAN_STORE/builds/<stamp>-sticks3 --port 8070`
   (the stick fetches it within one poll period, 120 s). Then
   `python3 tools/tune_session.py --port 8070 --seconds 60 --command STATUS --command BATTRUN --no-prompt`.
   Expect `app_version=<delivery version>`, `last_update_result=ok:<delivery version>` and a field
   `lock_loss_by=silence:<n>,followed:<n>,held:<n>,stopped:<n>` whose four numbers sum to `lock_losses`.
2. **No SD card, no computer.** Power the stick from its battery. It boots to the face of the stored
   network, or to "No network selected" with the hint to hold the side key.
3. **Five faces and transitions (video, five photos).** On the face, hold the front key: DEMO 1/5.
   The side key steps through the five faces; hold the front key to leave. Film the whole walk.
4. **Live observation and no-data.** Film the live face of the home network with its rating, the
   reason on the details page, then shield the stick (the ledger's method: inside a switched-off
   microwave oven) until "No fresh data" and the age appear (29 s after the last heard frame).
5. **Live incident, alert-first, expiry.** Read STATUS and note `ota_auto_deferred` and
   `ota_auto_checks`. The owner runs his own bounded test traffic against his own network, on its
   channel, for at least 130 s, so that one poll falls due while the alert is active. Film the red
   face and its sentence. Read STATUS at once after the run: `alert=1`, `last_burst_network=` with
   `own:<n>`, `ota_auto_deferred` one higher. Keep filming until the red ends (60 s after the last
   counted frame) and the rating or "No fresh data" returns; a later STATUS shows `ota_auto_checks`
   higher (the deferred poll ran).
6. **Unrelated-network negative.** The same traffic aimed at another network of the owner's, on the
   same channel and with a different name: the face stays its rating, at most the amber notice shows,
   `alert=0`, and only `last_burst_area=` changes (no `own:`).
7. **Dim view from Details.** On battery, leave the stick on the details page and still until it dims
   (30 s), then repeat step 5's traffic for 20 s: the dimmed screen shows the ALERT portrait with the
   red edge and the word ALERT (camera frame). Before this delivery it showed "NO DATA".
8. **Dark guard as one sequence (G16N S3).** On battery, let it go dark; one burst lights it; let it
   go dark again; a second burst lights it again; read `darks=` and `dark_wakes=`.
9. **Setup password.** In the network list hold the side key 3 s on the home network: the setup
   screen shows a password of 10 characters. Any key cancels; nothing is changed.
10. **Lock losses.** After 30 minutes or more of normal guarding, one STATUS read of `lock_loss_by=`.
11. **Slow tilt.** With the stick on USB and the console open (`build.sh monitor-command` prints the
    command), type `IMU 10` and tilt the stick slowly from side to side for the 10 s; save the
    output to a file and run `still_trace` on it (section 7).
12. **Owner's decisions, unchanged:** the credential vault (firmware/README.md "Credential vault"),
    the ALERT eyes (desk-camera frames first).

Each result goes to `firmware/evidence/sticks3-G23-<date>.log` with the image version and the read
times; the videos and photos go to `$GUARDIAN_STORE/evidence-raw/` with their sha256 in that log.

## 9. Channel-lock losses

Measured before this attempt [DEVICE: sticks3-G22A-20261119.log]: 84 losses against 51 polls in
104 minutes on the G22 image; on the G22A image `lock_losses=7` at 241 s (2 polls) and 10 at 481 s
(4 polls), `last_lock_loss=stopped`. Each update poll stops the survey once (reason `stopped`)
[SOURCE: `run_update()` calls `survey.stop()`], so polls alone explain at most 2 and 4 of those losses,
not 7 and 10. Which reason makes the rest is not known:
STATUS printed only the last one. The delivery image prints all four counts. No behaviour was
changed; the fix is the Author's ruling after the first read.

## 10. Limits of this record

- Nothing in this attempt ran on the device. Every [HOST] line is a host check.
- The delivery image differs from the image on the stick by three behaviours (the dim view's frame,
  the 10-symbol setup password, one more STATUS field); none of them has been seen on the glass.
- The STATUS line grew by the new field (at most 86 characters); the reply limit of the TUNE session
  is 8,192 and the line measured 3,692 characters on 2026-11-19, so it is expected to fit. Not read on
  the device.
- The Guardian does not claim to protect a network. It reports what one 2.4 GHz receiver heard.

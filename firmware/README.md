# Guardian firmware

The firmware of the M5 Guardian for the StickS3: the portable detection library, the SDK-free
adapters around it and the ESP-IDF board project. What the product is, what it detects and what it
cannot see is in the [root README](../README.md); the evidence for every ledger row is in the
[G23 delivery record](../docs/G23-delivery.md).

**How to read this file.** "Delivery" below holds the commands that are current: build, assets, the
USB device, install, restore. The sections after it are the hand-off notes of each task, kept as they
were written, in task order. Where such a note says "pending" or "nothing is proven on the stick",
that was true on its date: the heading now carries the ledger's state, and
[guardian-tasks.json](../guardian-tasks.json) holds the acceptance and what was carried into G23.

## Delivery (G23): build, assets, USB device, install, restore

Nothing in this section starts a radio test, and no command here flashes by itself: the two device
writes (first install, restore) are commands that a script prints for a person to run.

### Reproducible build

```sh
# settings once: the artifact store (see ../lab/local.conf.example)
#   ~/.config/m5-guardian/local.conf  ->  GUARDIAN_STORE=<folder holding an empty .guardian-store-root>

firmware/tools/host-check.sh                               # library + adapters on the host: plain, then ASan/UBSan
cmake -DROOT=$PWD/firmware -P firmware/tests/portability_check.cmake   # the portable components include no SDK or stdio
python3 firmware/boards/sticks3/tests/test_build_support.py            # the build script's own rules
firmware/boards/sticks3/tools/build.sh build               # signed image + archive (never flashes)
python3 -I tools/public_check.py                           # the tree holds no personal or machine value
```

- Pinned inputs: ESP-IDF v5.4 at `67c1de1eebe095d554d281952fde63c16ee2dca0` in `~/esp/esp-idf`
  (override `IDF_PATH_PINNED`), compiler xtensa-esp-elf esp-14.2.0_20241119. `build.sh` refuses an SDK
  whose files or submodules differ from that revision, with one recorded exception
  ([third-party notices](../THIRD_PARTY_NOTICES.md), "ESP-IDF and the precompiled Wi-Fi library").
- The image is signed with your own key (`build.sh keygen` once; the key stays in
  `~/.config/m5-guardian/`, outside the tree and the store).
- Output: `$GUARDIAN_STORE/builds/<date>-<time>-<pid>-sticks3/` with the bootloader, partition table,
  the signed app, ELF and map, sdkconfig, `flash_args`, the source tar with its hashes, the SDK
  revisions, `SHA256SUMS` and `COMPLETE.json`; the logs are in the sibling `-build-logs` folder. The app
  version is `guardian-<date>-<time>` and is what STATUS and the update manifest report.
- The host check writes `$GUARDIAN_STORE/builds/<date>-<time>-host-<id>/` (toolchain, source hashes,
  build and test logs, `summary.txt`). Python tool tests: `python3 -m pytest tools/tests` with the
  interpreter that has pytest, Pillow 11.3.0 and numpy 1.26.4 (the versions the art manifest pins).

### Asset export

The faces in the image are the 16 portraits under `art/persona/v2/portrait/` (135x160, little-endian
RGB565): five ratings, two ALERT frames for each, one no-data outline. They are made from the accepted
v4 masters, which live in the store, and pinned by sha256.

```sh
python3 firmware/art/persona/v2/build_assets.py portraits $GUARDIAN_STORE/art-exports/G15/20261117-v4/masters_png
python3 tools/art/candidates.py verify                 # bench frames on disk = art/bench/manifest.json
python3 -m pytest tools/tests/test_art_candidates.py   # the shipped portraits = pipeline D, byte for byte
```

`persona_check` (host check) re-hashes the portraits against `art/persona/v2/manifest.json`, and
`build.sh` embeds them with a size check. Rebuilding from the same masters with the pinned tool
versions gives the same bytes. The 3D head (optional, off by default) has its own pipeline in the G21
section; its frame sets are embedded for two moods only.

### The selected USB device

One physical unit is the Guardian: **LAB-STICK-1** (ESP32-S3-PICO-1 rev 0.2, 8 MB flash, 8 MB PSRAM).
Its USB serial number is its radio address; that value is kept outside the tree
(`GUARDIAN_LAB_STICK_MAC` in `local.conf`). Find the port by that serial, never by the port name:

```sh
python3 -m serial.tools.list_ports -v      # the entry whose SER= is your GUARDIAN_LAB_STICK_MAC (the lab tools compare it in upper case)
```

A second StickS3 on the bench, **LAB-BRUCE-STICK**, carries the Bruce test firmware. It is a different
unit with its own backup (below). Do not write a Guardian image to it or its backup to the Guardian.

### Install

```sh
# 1. a full backup of the unit you are about to write, and its hash, before anything else
python -m esptool --chip esp32s3 --port /dev/cu.usbmodemNNN read_flash 0x0 0x800000 flash-full-8MB.bin
shasum -a 256 flash-full-8MB.bin

# 2. first install over USB: the script prints the exact esptool command for a complete archive
GUARDIAN_PORT=/dev/cu.usbmodemNNN GUARDIAN_ARTIFACT_DIR=$GUARDIAN_STORE/builds/<stamp>-sticks3 \
    firmware/boards/sticks3/tools/build.sh flash-command
GUARDIAN_PORT=/dev/cu.usbmodemNNN firmware/boards/sticks3/tools/build.sh monitor-command

# 3. every later image over Wi-Fi (the stick fetches a signed, newer image at its next poll, 120 s by default)
python3 tools/ota_serve.py $GUARDIAN_STORE/builds/<stamp>-sticks3 --port 8070
python3 tools/tune_session.py --port 8070 --seconds 60 --command STATUS --no-prompt     # read back app_version
```

`python` in step 1 is the ESP-IDF Python environment (esptool v4). LAB-STICK-1 has had its USB
install (2026-11-16) and takes images over Wi-Fi since; its home Wi-Fi is given from the phone (G16M
section) or with `tools/ota_provision.py` over USB.

### Restore

| Unit | Full backup in the store | sha256 |
|---|---|---|
| LAB-STICK-1 (as it was before the Guardian) | `device-backups/LAB-STICK-1-20261114-220350/flash-full-8MB.bin` | `acccb5b9711c456b833eac402216c97c1b15a9e573570abe3e14e65697753dca` |
| LAB-STICK-1 (the Guardian of 2026-11-16, read before the partition table changed) | `backups/stick-backup-pre-g16b-20261116-203615.bin` | `c3d0898e7e09388ba173af1ee83d5d65483d84c8a315e092518f56faf336b1bf` |
| LAB-BRUCE-STICK (Launcher + Bruce, its settings and captures) | `device-backups/LAB-BRUCE-STICK-20261113/flash-full-8MB.bin` | `c6de1ad11aa1da226d0022ef654d9a49e4ed5b8dcc60c89a5179d8944d2b91e8` |

(The folder names in the store carry each unit's own address in place of the placeholder.)

```sh
# check the unit's identity and the backup's hash first, then:
python -m esptool --chip esp32s3 --port /dev/cu.usbmodemNNN write_flash 0x0 flash-full-8MB.bin
python -m esptool --chip esp32s3 --port /dev/cu.usbmodemNNN verify_flash 0x0 flash-full-8MB.bin
```

- **Bruce restoration** is that command with the LAB-BRUCE-STICK backup on the LAB-BRUCE-STICK unit.
  It restores the launcher, Bruce, its settings and its capture files together, because the image is a
  byte copy of the whole flash. If the chip stays in download mode afterwards, press the side key once.
- **The files exported from Bruce** (`fs-spiffs/` beside that backup: one capture file and two
  configuration files, listed with their hashes in `dump-report.json` and in
  [evidence/device-identity-20261113.md](evidence/device-identity-20261113.md)) stay in the store,
  separate from every Guardian artifact. They are never copied into this repository (the
  configuration may hold credentials) and never edited. Checked 2026-11-20: the backup and the capture
  file still have the recorded sha256.
- A full restore also restores that backup's settings storage and partition table. Neither restore
  has been exercised: the commands are written down, not proven.
- The emergency route for any unit is the ROM download mode over USB; no eFuse has been burned.


## Layers and platform

- `components/guardian_core`: portable C++17 parser, evidence, detectors and advice.
- `components/guardian_presenter`: portable UI policy and selection state.
- `components/guardian_canvas`: RGB565 drawing; no SDK or board pins.
- `boards/sticks3`: native ESP-IDF project with PM1, LCD, buttons and NVS glue.
- `tests` and `tools/host-check.sh`: host normal and ASan/UBSan checks.
- `../validation/spikes/esp32-foundation`: no-RF on-chip library probe.

Native ESP-IDF v5.4 at `67c1de1eebe095d554d281952fde63c16ee2dca0`,
Xtensa esp-14.2.0_20241119, no Arduino/M5 library dependency. Zephyr is deferred:
our required passive receive/display/power path has not been qualified there.
Pins and derived power sequences cite pinned M5 source in
`boards/sticks3/main/sticks3_pins.hpp` and [third-party notices](../THIRD_PARTY_NOTICES.md).

## Builds and archives

From the repository root:

```sh
firmware/tools/host-check.sh
firmware/boards/sticks3/tools/build.sh build
python3 firmware/boards/sticks3/tests/test_build_support.py
```

The board wrapper requires the mounted the store sentinel and pinned SDK. It uses a
marked, disposable `/private/tmp/m5-guardian-sticks3-build` directory (override
`GUARDIAN_BUILD_DIR`). This is an explicit small-build scratch exception: lasting
artifacts and logs remain under `$GUARDIAN_STORE/builds/`.
`build.sh clean` refuses unowned directories, source paths and symlink targets.

Archives include the bootloader, partition table, application, ELF/map, sdkconfig,
relocatable flash arguments, source hashes/tar with notices, compiler identity,
recursive SDK revisions and checksums. Copy digests are compared with original
inputs before `COMPLETE.json` is written. Logs are in the sibling `*-build-logs`
directory. Every SDK input is the vendor original (a modified S3 `libnet80211.a` was
restored on 2026-11-20, see THIRD_PARTY_NOTICES.md); the wrapper preserves the
library's exact bytes and license and refuses any dirty SDK file or
moved/missing submodule. This bring-up does not start Wi-Fi.

## Current physical unit and recovery

Owner-approved unit: **LAB-STICK-1**, ESP32-S3-PICO-1 rev 0.2, 8 MB GD flash,
8 MB octal PSRAM. Its previous app was M5AccessibilityS3 Head Pointer.
Rediscover the USB port by this serial; do not identify a unit by port alone.

Its verified full backup is in the store at:
`device-backups/LAB-STICK-1-20261114-220350/flash-full-8MB.bin`.
SHA-256: `acccb5b9711c456b833eac402216c97c1b15a9e573570abe3e14e65697753dca`.
The original image was read and `verify_flash` matched it before writing Guardian.
The older `LAB-BRUCE-STICK-20261113` Bruce backup is a different unit; retain it.

For an explicitly identified port and complete archive, command printers are:

```sh
GUARDIAN_PORT=/dev/cu.usbmodemNNN GUARDIAN_ARTIFACT_DIR=$GUARDIAN_STORE/builds/CHOSEN-sticks3 firmware/boards/sticks3/tools/build.sh flash-command
GUARDIAN_PORT=/dev/cu.usbmodemNNN firmware/boards/sticks3/tools/build.sh monitor-command
```

They print commands; they do not flash or save monitor output automatically.
Use the installed IDF Python environment for esptool v4. Its restore command is
`python -m esptool --chip esp32s3 --port PORT write_flash 0x0 BACKUP.bin`, followed
by `verify_flash 0x0 BACKUP.bin`. Check unit identity and the backup SHA first.
Do not use another unit's full-flash image. Full restore also restores that
backup's NVS and partitions. The restore route has not yet been exercised.

## Bring-up evidence and remaining work

G16A: the display is upright portrait 135×240 (the StickS3 stands on its USB
connector; vendor rotation 0, gap 52/40, no auto-rotation; see
`boards/sticks3/main/orientation.hpp`). Before G16A it was 240×135 landscape
with gap (40,52), which left one controller column unwritten (rainbow strip).
It uses one 64,800-byte internal DMA framebuffer.
The transfer guard forbids writes until callback completion and permanently
rejects reuse after timeout/failure. A 256 KiB PSRAM pattern probe is freed after
checking. PM1 raw ID response is reported separately from owner-selected board
identity. NVS is never auto-erased on an initialization error; boot count is
reported only after checked read/write/commit.

The first real boot logged flash=8388608, psram=8388608, successful PSRAM/NVS,
boot_count=1 and repeated completed display transfers. Owner photo/video shows
upright text and a complete border, and the next video confirms the RGB correction in bringup-0.3. Boot count
advanced from 1 to 2 across restart/reflash. Both physical buttons have matching USB events and owner video (front x3, side x1);
a further reset retained boot count 3. `assets` is only a reserved 5056 KiB partition, not a mounted
filesystem; no SD card is used. The screen says Unknown/checking because no
radio acquisition is wired to this board app yet.

See [G10 repairs](../docs/G10-validation.md) and the ledger. Later tasks integrate
live radio, repeat end-to-end board validation, then implement the five original
3D moods. A displayed test screen does not satisfy those later tasks.


## G13 measurement image (ledger G13: accepted; record docs/G13-validation.md)

The StickS3 project's entry point now builds `measurement_main.cpp`. The earlier
bring-up implementation remains in `app_main.cpp` as `guardian_bringup_main`;
the G11 recovery image and original device backup are retained. G13 is now flashed
and has passed 11 bounded live scenarios; reconnect and physical screen/video
acceptance remain pending ([supervisor evidence](../docs/G13-validation.md)). The new image boots with reception
stopped and needs explicit country/network/duration configuration. It uses the
same accepted portable library, a bounded Wi-Fi task queue and separate native
diagnostic rendering. See [G13 protocol and evidence](../docs/G13-measurement.md)
for the source/build checks and explicit reviewer live-validation procedure.
Builds do not flash, receive, transmit or start lab scenarios.

## G14 companion image (ledger G14: accepted 2026-11-16)

From G14 the same image boots as the **companion**: face, details and network
picker on the two keys, the owner's choice persisted in NVS, and passive,
receive-only 2.4 GHz listening started at boot in `CONFIG_GUARDIAN_COUNTRY`
(Kconfig, default `BR`; empty keeps the radio off). The first scoped console
command (`select`, `start`, `listen`, `stop`, ...) hands radio and screen to the
unchanged G13 measurement protocol until reboot; console selections are never
persisted. Three welcome pages are shown once (NVS flag `onboarded`). BLUE
switches face/details; changing the selected network is the deliberate two-step
action *hold SIDE, then SIDE on the chosen row*; hold BLUE on the face toggles
the labelled DEMO. Full button map, persistence format and evidence:
[G14 companion](../docs/G14-companion.md).

## G16B signed OTA, rollback and battery (accepted 2026-11-16; device record firmware/evidence/sticks3-G16B-ota-20261116.log)

**Partition table** (`boards/sticks3/partitions.csv`): `nvs` 0x9000/24 KiB and
`phy_init` 0xF000 keep their earlier offsets (the owner's selection, TUNE values
and boot counter survive), `otadata` 0x10000, `ota_0` 0x20000 and `ota_1`
0x320000 (3 MiB each; the measured G16B app is 1,245,184 B = 41 %), `assets`
0x620000 to the end of the 8 MB flash. Installing it is the **last USB flash**:
the reviewer does it after a fresh verified backup of LAB-STICK-1, with
`build.sh flash-command` (its `flash_args` write bootloader, table,
`ota_data_initial.bin` and the **signed** app at 0x20000). ROM USB download mode
stays the emergency route; no eFuse is burned.

**Signing.** ESP-IDF app signature verification without hardware secure boot
(`CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT`, `CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT`).
On the ESP32-S3, IDF v5.4 offers **only the RSA-3072 Secure Boot V2 scheme** for
this (`soc_caps.h`: `SOC_SECURE_BOOT_V2_RSA`; the ECDSA schemes need
`SOC_SECURE_BOOT_V1`/`SOC_SECURE_BOOT_V2_ECC`, which the S3 lacks), so the ledger's
"ECDSA" is not available on this chip. The trusted key is the signature block of
the **running** app, so the USB-installed image must itself be owner-signed.
The private key lives only at `~/.config/m5-guardian/ota-signing-rsa3072.pem`
(mode 600, outside the repository and the store; override `GUARDIAN_OTA_SIGNING_KEY`).
`build.sh keygen` creates it once and refuses to overwrite it; back it up offline.
`build.sh build` writes the app version (`g16b-<date>-<time>`), builds unsigned,
signs with `espsecure sign_data --version 2`, verifies the signature, extracts the
public key and records `signing.json`; the archive refuses a build whose sdkconfig
lacks signing/rollback, whose signing record differs from the images, or whose
image version differs from the requested one.

**Rollback** (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`). A new image boots on
probation; after the first frame it runs the self-test (display presented, NVS
usable and the selection not rejected, passive radio initialised and tuned; IMU
reported but optional) and only then marks itself valid. A failure saves
`rolled_back:selftest` and calls the IDF rollback; a reset before the self-test
makes the bootloader return to the previous slot, reported as
`rolled_back:reset_before_selftest`. `build.sh build-selftest-fail` builds the
reviewer test image (`CONFIG_GUARDIAN_OTA_SELFTEST_FAIL`, version suffix `-stfail`).

**UPDATE mode** (owner only): on the face, press **FRONT three times fast** (one-handed; or hold both keys ~3 s;
since G24 the three presses count only on the face, so stepping the details pages fast never opens it),
then after ~1 s FRONT = yes, SIDE = no
(15 s timeout = no). Monitoring pauses; the stick joins the provisioned network,
fetches `<url>/manifest` and `<url>/image`, checks size, Content-Length, sha256 and
then the signature (inside `esp_ota_end`, before `esp_ota_set_boot_partition`),
switches slot and reboots. Any failure keeps the running image, shows the reason
and resumes passive monitoring. Outside UPDATE mode the Guardian never joins a
network. Serial progress lines: `G16B UPDATE ...`, boot outcome: `G16B BOOT ...`.

**Mac side.** Provision once over USB (values never printed by tool or device):
`python3 tools/ota_provision.py --port /dev/cu.usbmodemNNN` (asks SSID, password
via getpass; URL defaults to `http://<this Mac>:8070`; `--clear` erases). Console
`OTA?` shows only whether values are set. Serve one update:
`python3 tools/ota_serve.py $GUARDIAN_STORE/builds/<stamp>-sticks3`
(re-verifies the archive, serves `/manifest` + `/image`, exits after one transfer).
`--bad-signature-test` serves the same app signed by a throwaway key (deleted on exit).

**Battery.** PM1 VBAT (0x22), PWR_SRC (0x04) and GPIO0 charge status (0x12 bit 0,
low = charging), sources in `adapters/power/battery.hpp`. The level is the vendor
linear **voltage estimate**, marked `~usb` while external power is present. A
small indicator sits in the reserved top-right corner; low (≤ 3.45 V on battery)
and critical (≤ 3.35 V) show a bar on the last hint row; ratings are never changed.
`BATTRUN` prints the last run on battery (saved once a minute in NVS, kept until
the next run on battery starts). STATUS adds `ota_slot=`, `app_version=`,
`last_update_result=`, `ota_provisioned=`, `selftest=` and `batt=`/`charging=`/`power=`.

**Reviewer acceptance (not done by the worker):** backup, USB install of the
archive; OTA of a newer archive from the Mac succeeds (`last_update_result=ok:`);
`--bad-signature-test` is refused (`failed:signature`, slot unchanged); the
`-stfail` archive installs, fails its self-test and returns to the previous slot
(`rolled_back:selftest`); a full-to-empty battery run with passive monitoring and
the animated face, read back with `BATTRUN`.

## G16C every screen is the Guardian (implemented 2026-11-16; ledger G16C: accepted 2026-11-17)

Archive `builds/20261116-213510-51981-sticks3` (version `g16c-20261116-213505`, signed; app 1,900,544 B,
signed 1,904,640 B = 60.5 % of the 3 MiB OTA slot; the 16 portraits are 691,200 B of it, each found once in the bin).
Host evidence: `builds/20261116-g16c-tdd/g16c-evidence.tgz` (red/green logs, plain and ASan/UBSan 33/33,
preview renders of every screen) and `G16C-preview-sheet.png`.

- **Faces:** `art/persona/v2/build_assets.py portraits <the store masters_png>` crops all 15 accepted v2 masters
  (same box/resample/matte as G16A; v4 masters from `alert_eyes.py`: Very good green eyes, Horrible red eyes, ALERT frames red eyes without corona; then an unsharp mask (1.0 / 90 % / 2) on the opaque layer; VeryGood is now `ab4177d5...`) plus `NoData`, an outline-only silhouette
  (no eyes, mouth or colour of any rating). Hashes in `manifest.json`; `persona_check` re-hashes them.
  Rated face only for a fresh rating; ALERT alternates the rating's two pulse frames (450 ms); no fresh
  rating (stale, checking, not rated, imported, no network) shows the silhouette with the reason in large text.
- **Header / HUD:** tag plate (LIVE / DEMO n/5 / ALERT) and BSSID tail on row 1, the network name alone on its
  own 22-glyph row (longer: `~` marker). Pure black background. HUD: rating, badges (mode, cipher, PMF), SEEN
  age, RSSI bars + dBm (fresh valid reading only), channel lock / sweep / radio state, `ADV ONLY`.
- **Details pages:** planned by wrapped rows (`Presenter::set_text_budget`); a page indicator replaces the old
  unreachable "more".
- **IMU:** `adapters/companion/motion.*` (damped spring, calm/tap/set-down). It stays inactive until the axis map
  is set from a recorded trace. Record three 3 s traces with `IMU 3` (standing USB down, flat screen up, and
  optionally on its right edge), then run
  `python3 tools/imu_axis_map.py --standing s.log --lying l.log [--right-edge r.log]` and send its three
  `TUNE imu.*` lines. TUNE keys: `persona.sway_deg` (default 0, so it is calm at rest), `motion.*`, `imu.right|up|out`
  and `display.frame_ms` (default 40).
- **Measurement:** STATUS adds `art=`, `motion=`, `imu_map=`, `taps=`, `frame_ms=avg/max`, `render_ms=`, `push_ms=`,
  `fps=` and `imu_glass_ms=avg/max`. `FRAMES` prints per-screen totals (rated/alert/nodata/demo/other); `FRAMES 0`
  resets them.
- **Reviewer on the stick (not done by the worker):**
  1. OTA install.
  2. DEMO walk of all 5 ratings, plus the real network.
  3. Record the axis traces and TUNE them.
  4. Video of the stick standing and being handled.
  5. `FRAMES` on the face screens: target at least 20 fps, with no rise in G13 drops (STATUS/coverage).
  6. `heap_internal_min` and `task_stack_free`.
  7. Microwave no-data check.
  8. Full-to-empty `BATTRUN` with power=battery and charging=no.

### G16C supervisor rework (2026-11-16, attempt `...-task-21` second run; accepted with G16C)

Archive `builds/20261116-230644-36448-sticks3` (version `guardian-20261116-230644`, signed). Static DIRAM
223,347 B (reviewed build `20261116-214116-69711`: 219,539 B); IRAM unchanged at 99.99 %. Host evidence under
`builds/20261116-g16c-rework/` (red/green logs, benchmark, full host check).

1. **Speed.** Measured on the host first (`render_bench`): the portrait warp was ~85 % of draw time.
   - The warp quantizes its pose (tilt 1/32°, scale 1/1024, shift 1/16 px) and uses integer RGB565 bilinear
     sampling (1/32 px weights). The identity pose and whole-pixel shifts stay exact copies.
   - `persona::WarpCache`: the current portrait is decoded once into **PSRAM** (43,200 B) and the warped band is
     kept beside it (43,200 B). Total 86,400 B PSRAM, **0 B internal heap**. While the art, the quantized pose and
     the placement are unchanged, the band is copied back instead of re-warped (at rest, breathing only, about 1
     frame in 3 warps). Same pixels with or without the cache (host-tested).
   - `boards/sticks3/main/dirty_rows.hpp`: only changed rows go to the panel (per-row hash, nearby runs merged,
     at most 4 transactions), with a full push every second to heal any hash collision.
   - The render path (`screens/persona/motion/companion.cpp`, canvas component) is compiled `-O2`; the rest
     of the app keeps `-Og` because IRAM is full.
   - Host bench (relative, `-O2`): rated at rest 152 → 41 µs draw; handled 155 → 93 µs.
   - STATUS adds `art_ram=psram art_ram_bytes=86400 warps= warp_reuses= art_copies= push_rows_avg= full_pushes=`.
   - **Not measured on the stick:** whether render + push ≤ 40 ms. Read `FRAMES` / `frame_ms` after install.
2. **Rating dropouts.** Cause not proven; these counters make it measurable. STATUS adds:
   - `rx_received`, `rx_queue_full` (24-deep queue full), `rx_discarded` (flushed on a hop or stop), `rx_bad`;
   - `lock_losses`, `last_lock_loss` (`silence_5s`, `followed_channel`, `held`, `stopped`);
   - since G23: `lock_loss_by=silence:<n>,followed:<n>,held:<n>,stopped:<n>`, the count of each reason since boot
     (the four sum to `lock_losses`). `stopped` rises once for every update poll, setup or sleep that found the
     channel locked. Host-tested; not yet read on the stick;
   - since G23 (silence log): `silence_log=<t>:ch<c>:gap<ms>:age<s>:other<n>:rssi<dBm>:sweep<n>:<pwr>;...`, the last
     4 of the last 8 silence losses, oldest first (`none` before the first): uptime at the loss, channel, time since the
     last accepted frame, lock age, frames heard on that channel since then, RSSI of the last accepted frame, sweep
     excursions in the gap, power state (`awake`/`dim`/`dark`). Diagnostics only; docs/G23-delivery.md section 12.
     Host-tested; not yet read on the stick;
   - `console_writes`, `console_drops`, `console_stall_ms=total/max`, `log_lines`, `log_drops`;
   - `degraded_transitions`, `nodata_transitions`.

   Console writes can no longer block observation:
   - Companion writes never wait (timeout 0), and a lost console line no longer counts as a lost radio frame,
     so it no longer degrades coverage. The G13 lab console keeps its 5 ms / frame-drop policy.
   - ESP_LOG goes through a non-blocking sink with counted drops, and stdio uses the driver.
   - Every tag is at WARN after boot, which ends the `wifi:ic_*_sniffer` lines on each hop.

   The reviewer's 10-minute runs, in three states (battery, plugged with the port closed, plugged and read),
   decide whether the dropouts are gone.
3. **Network list:** a name longer than its 10-glyph slot ends in `~`. This is the header rule, host-tested.
4. **Version stamp:** `guardian-<date>-<time>` (`build_support.py version-stamp`); `-stfail` on the reviewer image.
5. **TUNE over Wi-Fi.** (Since G22A the offer is a signed envelope that carries the commands and the stick asks for
   no further command: see "Self-fetch OTA and TUNE: signed offers only" below. The start gesture, the session
   screen and the allowlist described here still hold.) Run `tools/tune_session.py --port <provisioned port>` on the
   provisioned Mac instead of `ota_serve.py`.
   - **Start:** on the stick, FRONT x3 fast (or both keys ~3 s), then FRONT=yes. This is the UPDATE gesture and
     confirmation. The stick joins the provisioned network and finds the tool's TUNE offer, so it opens a
     bounded session (30–1800 s, default 300). With `ota_serve.py` instead, the offer probe gets 404 and the
     signed update proceeds as before.
   - **During the session:** the stick is only an HTTP client of the Mac tool and never listens. It accepts
     only `STATUS`, `FRAMES`, `FRAMES 0`, `TUNE?` and `TUNE ...`. Passive monitoring is paused, and the glass
     shows `TUNE WI-FI <s>` / `any key: end tune` (`RADIO OFF` in the HUD).
   - **End:** the deadline, any key, `quit` in the tool, or three consecutive network failures. The stick then
     leaves the network and passive listening resumes.
   - USB TUNE is unchanged. While a session runs, USB lab commands are refused.
   - STATUS: `tune_wifi=off|active:<s>|ending tune_wifi_last_end= tune_wifi_commands= tune_wifi_refused=`.

## G16D battery life: dim, deep sleep, key wake (implemented 2026-11-17; ledger G16D: accepted 2026-11-17, battery and sleep device items carried into G23)

Policy, power-source debounce, IMU activity, wake-press guard, teardown order and the
RTC sleep record are SDK-free in `adapters/power/idle.{hpp,cpp}` (sources cited there:
ESP-IDF v5.4 `sleep_modes.rst`/`system_time.rst`, the owner's `sticks3-ai-usage`
`power.cpp` and `DEVICES.md`) and host-tested in `tests/idle_check.cpp`.

- **Active -> Dim** after `power.dim_s` (TUNE, default 30 s) with no IMU movement, no key
  and no new ALERT, only on battery. Dim: backlight `power.dim_pct` (default 10 %), one
  frame a second, the rating glyph in its mood colour (red "!" while an ALERT is shown,
  empty grey outline + "NO DATA" without a fresh rating). Passive monitoring continues.
  Since G23 the dim view is the Face screen's decision whatever screen was left open
  (`Companion::render_dim`): before, a stick left on Details or on the network list dimmed to
  the grey outline and "NO DATA", also during a red ALERT and with a fresh rating (G22 review
  H2, reproduced by `companion_check` and fixed on the host; not yet seen on the glass).
  Movement (any axis, the same `motion.rest_gyro` / `motion.rest_acc` thresholds as the
  face, 4 samples in a row; independent of the `imu.*` axis map), a key or a new ALERT
  returns to Active. The key that brightens it is swallowed.
- **Dim -> deep sleep** (since G16N only with `power.dark_s=0`, or from Dark at the battery floor; by default the
  screen now goes Dark and the Guardian keeps guarding, see the G16N section below) after `power.sleep_s`
  (default 120 s) more: "sleeping / press to
  wake" for about 1 s (a key cancels), then radio off (`esp_wifi_stop`), IMU sampler
  stopped, display sleep, LCD rail off (PM1 GPIO2), BMI270 suspend, ES8311 low power,
  PA off (PM1 GPIO3), ext1 ANY_LOW on GPIO11|GPIO12 (pull-up on, pull-down off), deep
  sleep. No IMU wake, never the PM1 IRQ line (G16P adds a timer wake that only looks for USB
  power, see its section below). If ext1 cannot be armed it restarts instead of sleeping unarmed.
- **Never** dims or sleeps on USB or unknown power (PWR_SRC 5V bits or VIN > 4000 mV
  is USB at once; battery needs 3 consecutive readable battery readings, one a second),
  during UPDATE confirmation, a TUNE session, onboarding, the lab console or EDGE/IMU
  streams. An ALERT that stays shown may dim but never sleeps.
- **Wake:** either key boots it (`wake_cause=ext1`); that press never reaches the UI.
  The screen starts exactly like a cold boot (nothing was observed while asleep).
- **STATUS** adds `power_state power_hold power_source vbus_mv still_s dim_s sleep_s
  wake_cause wake_key asleep_s sleep_count asleep_total_s sleep_faults wake_swallowed`
  (`sleep_count`/`asleep_total_s`/`sleep_faults` are RTC-retained). Serial lines:
  `G16D WAKE`, `G16D POWER`, `G16D SLEEP start|cancelled|enter`.
- **BATTRUN** (record format 2; a G16B format-1 record still reads) continues one run
  across key wakes: `active_s sleeps asleep_s sleep_mv wake_mv standby_drop_mv`,
  `end=asleep` when the last record was written going to sleep.

Reviewer checks on the stick (installed over OTA, unplugged): dims after 30 s still;
deep-sleeps 120 s later; FRONT and SIDE each wake it (`wake_cause=ext1 wake_key=...`);
plugged in it never dims or sleeps; ten sleep/wake cycles without a PM1 I2C hang;
`BATTRUN` active runtime and an overnight standby drop; plus the checks carried over
from G16B/G16C in the ledger entry. Unproven on hardware: the ES8311/BMI270 writes
through the ESP-IDF I2C master (the owner's values were measured through M5Unified),
the standby current, and whether the BMI270 gyro noise at rest stays under 4 deg/s.

## G16N guard in the dark (implemented 2026-11-18; ledger G16N: accepted 2026-11-19, the S3 sequence carried into G23)

Owner (2026-11-18): "device now has screen pitch black to save battery, BUT it should be monitoring, any deauth
packets should bring screen UP, alert." Before G16N the Guardian deep-slept `power.sleep_s` after dimming and stopped
guarding. Design and code facts: `firmware/evidence/G16N-plan-dark-guard-20261118.md`. Policy in
`adapters/power/idle.{hpp,cpp}` (state `Dark`), host-tested in `tests/idle_check.cpp`.

- **Active -> Dim -> Dark**, on battery only. Dim as before (`power.dim_s`, `power.dim_pct`). After `power.dark_s`
  (TUNE 0..3600, default 60) more in Dim the screen goes **Dark**: one grey sentence, "guarding in the dark / press to
  look", for 2 s at the dim level, then backlight 0 and no frame is drawn. The radio, the detectors, the IMU and the
  main loop keep running; STATUS `frames=` keep counting. The panel is never put to sleep for Dark (`display_sleep()`
  revokes the canvas until reboot): `set_backlight(0)` only.
- **What lights it again** (60 %, full redraw): a key (swallowed, like the Dim press), movement, any hold (USB plugged
  in, UPDATE, a TUNE session, the console) and **every new incident report, red or amber**. `Snapshot::incident_seq`
  counts each report the Core accepts (Network or Area); the view carries it (`ViewModel::incident_seq`, the live count
  also while DEMO is shown) and `Idle::step` treats a changed count as activity in every state. So a second incident
  re-lights a screen that dimmed under the first one's banner (before G16N the input was one bool, already true).
  A detector that keeps reporting (every `detect.cooldown_ms` while the traffic lasts) lights the screen each time.
- **A shown ALERT never goes dark**: the dim view keeps the red sign; the `power.dark_s` countdown restarts when the
  ALERT ends. An amber (nearby) observation does not hold the screen: it may go dark and the next report lights it.
- **Deep sleep is only the floor**: Dark -> the G16D deep sleep (keys-only wake, nothing observed while asleep) when the
  battery percent is KNOWN and at or below `power.dark_floor_pct` (TUNE 5..90, default 20; the vendor's linear
  voltage estimate, 20 % = 3460 mV). An unknown percent never sleeps. A new incident at the floor still lights the
  screen first. `power.sleep_s` is used only while `power.dark_s=0`.
- **`power.dark_s=0` turns it off**: Dim -> deep sleep after `power.sleep_s`, exactly the G16D behaviour.
- **STATUS** adds `power_state=dark`, `dark_s` and `dark_floor_pct` (the TUNE values, like `dim_s`/`sleep_s`), `darks`
  (times Dark was entered), `dark_total_s` (time spent dark since boot), `dark_wakes=<key>/<motion>/<incident>`,
  `dark_last_wake=none|key|motion|incident|hold`, and for the device spike `dark_wake_evidence_ms` (from the evidence
  instant of the incident that lit the screen to the backlight command) and `dark_wake_frame_ms` (to the first frame
  pushed); -1 = none since boot. Serial: `G16D POWER dark`, `G16N DARK wake cause= evidence_ms= dark_total_s=`.
- **BATTRUN** (record format 3; formats 1 and 2 still read) adds the drain per screen state over the battery run, kept
  across deep sleeps: `drain_mv_10min=active:<n>,dim:<n>,dark:<n> drain_s=active:<s>,dim:<s>,dark:<s>`. mV the cell
  fell per 10 minutes; the first 30 s after each state change are not measured (the cell voltage steps with the load),
  and a rate is `-` until 300 s were measured in that state. A voltage trend, not a current: mA needs the spike.
- **Details, "What it cannot see"**: `dark guard: about N h left` (from the present cell voltage to the floor's
  voltage at the MEASURED dark rate; "under 1 h left" below one hour), `dark guard: not measured yet`, or
  `dark guard: off`. Never a number without a measurement.
- Two TUNE keys: the StickS3 registers 51 board keys + 61 `t.*` keys = 112 of `tune::max_params` 112 (G16O raised
  the registry to 120 for its four `burst.*` keys).

Not measured yet (the device spike S1-S3 of the ledger, numbers to `firmware/evidence/sticks3-G16N-spike-<date>.log`):
the current in each state and the hours of guarding on the 250 mAh cell; the time from a deauth burst to the lit red
stare; the second burst re-lighting; the floor's deep sleep. Known limits: the receiver stays on in Dark, so Dark saves
the backlight and the drawing, not the radio; the self-fetch poll (`ota.auto_s`, default 120 s) still pauses listening
for its join in every state, Dark included; a shown ALERT keeps the screen dimmed and never sleeps, also under the floor.
If the spike measures more than 150 mA in Dark, the default becomes `power.dark_s=0` (ledger).

### Self-fetch OTA and TUNE: signed offers only (2026-11-18; hardened by G22A 2026-11-19; ledger G22A: accepted 2026-11-19, the alert-first device proof carried into G23)
Owner: "from here on you got OTA". The stick asks the Mac for a signed image by itself every `ota.auto_s` seconds (TUNE,
default 120, 0 = gesture only) through the update path (`run_update`), quietly when nothing is served
(`G16B AUTO no update (<reason>)`, STATUS `ota_auto_checks= ota_auto_last=`). The poll asks for a TUNE offer first, so
`tools/tune_session.py --command ...` sessions land the same way. Proven 13:21 on 2026-11-18 with the old, unsigned
offer: an unattended TUNE session restored `power.dim_s`/`power.sleep_s`
(`firmware/evidence/sticks3-imu-after-software-restart-20261118.log`).

The G22 review (2026-11-19) found that this lane let any host answering at the provisioned URL open a TUNE session with
no gesture and no proof of origin, that the poll painted the update screen over a red ALERT, and that an older signed
image would be installed. G22A changes three things. **Implemented, host-tested and built; nothing of it is proven on
the stick yet.**

1. **Signed offers only.** The stick draws 16 random bytes for each request and asks
   `GET <url>/tune/offer?nonce=<32 hex>`. The answer opens a session only when it is this envelope:

   ```text
   GUARDIAN-TUNE 2
   nonce=<the stick's 32 hex>
   expires=<30..1800 seconds, counted by the stick from the moment it drew the nonce>
   cmd=<one console line>          1 to 8 lines
   end
   sig=<768 hex>                   RSA-3072 PKCS#1 v1.5 SHA-256 over every byte from the header through "end\n"
   ```

   - The signature is made on the Mac by `tools/tune_session.py` with the OTA signing key: the key file `build.sh`
     signs images with (`$GUARDIAN_OTA_SIGNING_KEY`, default `~/.config/m5-guardian/ota-signing-rsa3072.pem`). The tool
     hands the key's path to `/usr/bin/openssl` and never reads, prints or copies the key. It refuses to start when
     the key is missing, is not mode 600, lives in the repository or on an external volume, or is not RSA-3072.
   - The stick checks it with the public key in its running image's own signature block, which is the key
     `esp_ota_end()` checks update images against (`ota_board.cpp` `signing_key`), using mbedtls
     (`adapters/tune/offer_rsa.cpp`). No key is in the source.
   - Refused, counted and opening nothing: an unsigned offer (the old `GUARDIAN-TUNE 1` or no `sig` line), a bad
     signature, another nonce (a recorded offer replayed at a later poll), an offer past its expiry, a command
     outside the allowlist, a malformed text, and any offer when the running image has no signature block. After a
     refusal the poll goes on to the update check and monitoring resumes as if nothing had been offered.
     STATUS: `tune_offers_ok= tune_offers_refused= tune_offers_refused_last=<reason>
     tune_offers_refused_by=unsigned:<n>,format:<n>,nokey:<n>,signature:<n>,nonce:<n>,expired:<n>,command:<n>
     tune_key=<ota|none|unread>`; the console prints `G22A TUNE offer refused reason=<reason>`.
   - The commands of a session are the signed list and nothing else. The stick no longer asks the Mac for a next
     command (`/tune/next` is gone); it runs the list in order, posts each reply to `/tune/reply?s=<nonce>` and
     ends with `/tune/end?s=<nonce>&why=done`. The allowlist (`session.cpp` `allowed()`) is unchanged, and a
     signature does not widen it.
   - On the Mac: `tools/tune_session.py --port 8070 --seconds 60 --command STATUS --no-prompt` waits for the stick's
     next poll (`--wait`, default 180 s), prints the replies and exits 0 once every command was answered. At the
     prompt, typed commands leave with the next poll. A command leaves once: one that was offered and never
     answered is reported, not sent again.
   - Reviewer acceptance on the stick, without the owner's key: `tools/tune_session.py --unsigned-test` serves the
     offer with no `sig` line and `--bad-signature-test` signs it with a throwaway key made in a temporary
     directory. The stick must refuse both (`tune_offers_refused_by=unsigned:` / `signature:` go up by one, read
     with a normal signed `STATUS` afterwards); each run exits 0 when the offer was fetched and no reply came.
2. **Alert first.** While a red ALERT is active a due poll is deferred: the stick does not join, the incident stays
   on the glass and the radio keeps listening. The deferral is counted once per due poll (STATUS
   `ota_auto_deferred=`), and the poll runs at the first loop after the alert has ended (`guardian::ota::AutoPoll`).
   An amber notice does not defer the poll.
3. **Only a newer image.** `guardian::ota::run` compares build stamps (`guardian-<YYYYMMDD>-<HHMMSS>[-suffix]`). The
   manifest's version must be later than `app_version`, or nothing is downloaded. The version inside the image
   (its ESP-IDF app descriptor, which the image signature covers, unlike the manifest's text) must be later too, or
   the transfer stops at its first 80 bytes. Both give `not_newer` ("Not newer than running"), counted in STATUS
   `ota_not_newer=`; the poll stays silent about it (`ota_auto_last=not_newer`) and the owner's gesture shows it.
   The same build, a variant of the same build and every version outside the stamp format are refused. A running
   image whose own version is outside the format counts as older than every stamped build.

Host checks: `tune_session_check` (shape, nonce, expiry, allowlist, counters), `tune_offer_check` (real RSA-3072
signatures with key pairs generated in the check), `ota_check` (version order, the image's own version, the deferral),
`tools/tests/test_tune_session.py` (the signer with a throwaway key; with
`GUARDIAN_OFFER_VERIFY=<build dir>/tune_offer_verify` its offers also go through the firmware's check). The host build
now reads twelve mbedtls source files from the pinned ESP-IDF checkout (`GUARDIAN_MBEDTLS_DIR`, default
`~/esp/esp-idf/components/mbedtls/mbedtls`) and stops at configure time when they are missing.

Limits, stated plainly: the transport is still plain HTTP, so a session's replies (STATUS) can be read on the network;
each poll still pauses listening for its join and fetch; the Mac tool signs its queued commands for whoever asks with a
well-formed nonce, which lets another host on the network use up a queued batch (the stick then refuses that envelope:
other nonce) but not make the stick run anything.

### Software restarts and the IMU (2026-11-18)
After the first OTA of the G16I/G16J/G21 image the BMI270 did not initialise (`imu=init-failed`, `motion=no_imu`) until a
hardware reset; the same image ran fine after a USB reset (`firmware/evidence/sticks3-imu-after-software-restart-20261118.log`).
The install path had called `esp_restart()` with the IMU sampler still on the bus. Every software restart now runs
`power::prepare_restart` first (radio off, sampler stopped, BMI270 soft reset; host-tested in `idle_check`), the driver
makes one more init attempt after 50 ms (`imu_check`), the console verb `RESTART` (USB only) reproduces the software-reset
boot with the port open, and STATUS names the failing init step (`imu=init-failed:<why>`).

## G16P a plugged-in Guardian wakes by itself (implemented 2026-11-18; ledger G16P: accepted 2026-11-19)

Owner (2026-11-18, after plugging a deep-asleep stick into a charger): "have to click button to wake screen. crazy."
Until G16P the two keys were the only wake source, and the PM1 reports USB power only to a running ESP32. The PM1
interrupt line stays unused (owner ORDER #29), so deep sleep now also arms the **RTC timer**, and a timer wake asks one
question: is there USB power? Policy, record and decision are SDK-free in `adapters/power/idle.{hpp,cpp}`
(`timer_check`, `CheckPort`), tested in `tests/idle_check.cpp`; the BATTRUN part is in `adapters/power/battery.{hpp,cpp}`.

- **Going to sleep:** the teardown is the G16D one; after ext1 on the keys it arms `esp_sleep_enable_timer_wakeup` with
  `power.sleep_check_s` (TUNE 60..3600 s, default 300; whole seconds). If the timer cannot be armed it still sleeps on
  the keys and STATUS shows `sleep_faults=0x200`.
- **A timer wake** runs first thing in `app_main`, before `Board::init()`: `sticks3::QuickPower` opens the internal I2C
  bus, reads PM1 PWR_SRC, VIN and VBAT (20 ms timeouts) and closes the bus. It writes no PM1 register and makes no
  display, rail, radio, IMU, codec or NVS call: the panel and the rails stay as the teardown left them.
  - **USB power** (the `SourceFilter` rule: a 5 V bit in PWR_SRC, or VIN above 4000 mV) -> a normal boot:
    `wake_cause=timer`, the sleep is closed with its length like a key wake, the reading seeds the power filter so the
    first loop already holds on USB (`power_hold=usb`), the screen is on and the self-fetch poll runs. No key press is
    swallowed.
  - **No USB power** (both registers read, neither shows it) -> the check is counted in the RTC record, the keys and
    the timer are armed again, and the stick is back in deep sleep. The pending sleep is not closed: `asleep_s` after
    the final wake covers the whole sleep, the checks in between included.
  - **No usable PM1 reading** -> it reads again, at most 3 readings and only while less than half of the 1 s budget is
    used, then goes back to sleep and counts `check_faults`. It does not boot on a failed read: a booted stick with a
    dead PM1 bus holds "power unknown" and never sleeps again (an empty cell); one that stays asleep costs at most one
    period until the next check, and the keys still wake it.
  - Keys cannot be armed -> it boots (`wake_check=unarmed`); the rule "never asleep without the key wake" is G16D's.
- **Key wake** is unchanged (`wake_cause=ext1`, the press swallowed).
- **STATUS** adds `sleep_check_s` (the TUNE value), `sleep_checks` and `check_faults` (RTC-retained counts since
  power-on, like `sleep_count`), `wake_checks` (the checks of the sleep this boot woke from),
  `check_awake_ms=<latest>/<longest>` and `wake_check=-|usb|slept|no_record|unarmed|pm1_bus_failed` (this boot's
  check). `check_awake_ms` is measured on the RTC clock from the instant the timer was due to the call that sleeps
  again, so it contains the ROM, the bootloader and the IDF start before `app_main`: it is the number for the ledger's
  "back to sleep within a second". Serial: `G16D WAKE ... wake_checks= sleep_checks= check_faults= check_awake_ms=
  wake_check=`, `G16D SLEEP enter ... check_s=`.
- **BATTRUN** (record format 4, 73 bytes; formats 1 to 3 still read) adds `checks` (over the run) and, for the latest
  deep sleep, `last_checks check_s check_first_mv check_last_mv check_drop_uv standby_uv_h`. Each check that slept
  again read the cell once with the display, the radio and the IMU off, so `check_first_mv - check_last_mv` is the drop
  between checks at the same light load. `check_drop_uv` is that drop per check interval and `standby_uv_h` per hour
  ("-" until two checks have a reading). Both contain the deep sleep's own standby current; the checks' share is the
  difference between two runs with different `power.sleep_check_s` (for example 60 and 3600), compared by
  `standby_uv_h`. `standby_drop_mv` (`sleep_mv - wake_mv`) stays as it was.
- **TUNE:** one key, `power.sleep_check_s`: 56 board keys + 61 `t.*` keys = 117 of `tune::max_params` 120.
- **Also fixed here:** the BATTRUN reply's `else` branch had been swallowed by a comment (the reply was unset without a
  run log; the log always exists once the loop runs, so nothing was observed).

Host TDD (`$GUARDIAN_STORE/builds/20261118-g16p-tdd/`): red with the API declared and stubbed
(`red-run-idle_check.log`: 8 failing cases, 99 assertions; `red-run-battery_check.log`: 3 cases, 23 assertions; every
untouched case passed), green `green-run-idle_check.log` 38/38 cases and `green-run-battery_check.log` 15/15. Full
host check `builds/20261118-192222-host-PGNr5j`: plain 51/51 and ASan/UBSan 51/51 tests. Board
build: signed archive `builds/20261118-194409-23411-sticks3` (`guardian-20261118-194409`, 2,830,348 B, RTC slow data
64 B), not flashed.

Not proven on the stick (owner, image by OTA; evidence `firmware/evidence/sticks3-G16P-*.log`):
1. On battery let it reach deep sleep (`power.dark_s=0` reaches it after `power.sleep_s`; with the dark guard on it
   sleeps only at `power.dark_floor_pct`). Plug the charger, press nothing: the screen must light within
   `power.sleep_check_s` (set it to 60 for the test). STATUS then shows `wake_cause=timer wake_check=usb
   power_hold=usb`.
2. Unplugged, asleep for several periods, then a key: STATUS shows `wake_cause=ext1`, `wake_checks` and
   `sleep_checks` counted, `check_faults=0`, and `check_awake_ms`; BATTRUN shows the `check_*` numbers.
3. `check_awake_ms` at or below 1000. **This is the open risk.** Measured on this stick on 2026-11-14 with a 0.9 MB
   image (`evidence/sticks3-LAB-STICK-1-20261114.log`): `app_main` starts 537 ms after reset, 426 ms of it the PSRAM
   memory test. Today's image is 2.83 MB and the bootloader hashes it on every wake; that time is not measured. If the
   number is above the budget there are two documented settings, both owner decisions and neither changed here:
   `CONFIG_SPIRAM_MEMTEST=n` (app side, lands by OTA; the boot keeps its own 256 KB PSRAM pattern test) and
   `CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP=y` (ESP-IDF `bootloader.rst` "Fast Boot from Deep-Sleep"; the
   bootloader is not updated over the air, so it needs one USB write).
4. Unknowns the device decides: the PM1 answering on I2C right after a timer wake without the boot's PM1 setup (it
   keeps its "I2C awake" bit from the last full boot; a failure shows as `check_faults`), the cost of a check in
   battery terms (BATTRUN), and the ext1 pull-ups when re-armed from the quick path (same function as the normal path).

## G23 battery life in dark guard (worker 2026-11-20; ledger G23 open)

The owner's overnight soak (2026-11-20, image `guardian-20261119-221810`) measured the dark drain at 60 mV per 10
minutes (BATTRUN `drain_mv_10min dark:60`); where that current goes is not measured. This adds the means to
measure and reduce it without a new image per trial. **Every default is the behaviour before G23**; nothing here
claims an improvement. The power inventory, the duty-cycle design note and the owner's measurement sheet are in
[docs/G23-delivery.md](../docs/G23-delivery.md) section 11.

- **TUNE `ota.auto_batt_s`** (-1..3600, default -1): the self-fetch period while the stick runs on battery (the
  debounced `power_source=battery`). -1 = follow `ota.auto_s` (as before); 0 = no poll on battery; USB and unknown
  power always use `ota.auto_s`. A TUNE session reaches the stick only through that poll, so with 0 the stick is read
  again after it is plugged in. `guardian::ota::poll_period_ms` (tests/ota_check.cpp).
- **TUNE `power.dark_cpu_mhz`** (80..240, default 160): the CPU frequency while Dark (nearest of 80 / 160 / 240; 160
  in every other state). Applied **only** by the dark-cpu image: a runtime change needs `esp_pm_configure`, which
  returns `ESP_ERR_NOT_SUPPORTED` without `CONFIG_PM_ENABLE`, and the normal image does not set it.
  `guardian::power::dark_cpu_mhz`, `cpu_mhz` (tests/idle_check.cpp).
- **Dark-cpu image** (default off):

  ```sh
  firmware/boards/sticks3/tools/build.sh build-dark-cpu   # sdkconfig.dark-cpu: CONFIG_PM_ENABLE + CONFIG_GUARDIAN_DARK_CPU, suffix -dcpu
  ```

  Own build directory and archive (`COMPLETE.json` `dark_cpu_image: true`); `build_support.py` refuses a `-dcpu`
  label without both options and the options without the label. It boots at 160 MHz (`CONFIG_PM_DFS_INIT_AUTO` off)
  and calls `esp_pm_configure` with max = min (no light sleep) when the screen goes dark and again when it lights.
  Power management itself changes the image (interrupt latency, timer accuracy: ESP-IDF Kconfig help), so compare
  its segments with each other (the same image at 160 and at 80), not with the normal image. Not run on the stick.
- **STATUS** `ota_auto_batt_s=<-1|s> poll_s=<the period now> cpu_mhz=<applied now> dark_cpu_mhz=<used while dark>
  dark_cpu=<built|unbuilt> cpu_set_fail=<n> cpu_switches=<n>` (after the power fragment; `cpu_switches` counts the
  frequency changes `esp_pm_configure` accepted: two per dark stretch at a value other than 160, always 0 in the normal
  image).
- **BATTRUN** (record format 5, 207 bytes; formats 1 to 4 still read) adds drain **segments**: a new segment starts
  with each battery run and whenever the values in effect change on battery (update-poll period on battery, dark CPU
  MHz, dim backlight percent), and is measured per screen state exactly like the run (30 s settle after the change,
  a rate after 300 s). The latest four are kept:
  `segs=<started> seg<n>=poll_s:<s>,dark_mhz:<MHz>,dim_pct:<%>,start_mv:<mV>,active:<mV/10min>/<s>,dim:...,dark:...`
  ("-" before the rate, as `drain_mv_10min`). A deep-sleep wake continues the segment; USB ends it with the run. The
  board's reply buffer is `battery::run_text_max` (1024; battery_check proves the longest line fits).
- **TUNE capacity:** 40 literal + 18 `motion.*` = 58 board keys, + 68 `t.*` = 126 of `tune::max_params` 128.

## G24 Settings: guard on battery, brightness, unused parts off (worker 2026-11-21; ledger G24 open)

Release 1's Settings screen, Bruce-style (one big option per page), with every number taken from the G24 battery
spike ([evidence/sticks3-G24-spike-20261121.log](evidence/sticks3-G24-spike-20261121.log)). **The defaults are the
behaviour before G24** (guard Always, brightness 60 %); only the unused parts change from boot. Implemented and
host-tested; nothing of G24 is measured on the stick yet (the supervisor's device acceptance is in the ledger row).

- **Entry and keys** (single key, the owner is one-handed; owner 2026-11-21 after the first device look: "like side
  opens net list, blue opens settings", and DEMO "is for development, ditch"). Face: FRONT = Details (first page
  Advertised Wi-Fi settings, as before G24), **hold FRONT = Settings screen**, hold SIDE = network list. Details:
  FRONT = next page (Advertised Wi-Fi settings, Explanation, Signal and evidence, Owner checks, What it cannot see,
  Nearby while something is nearby, then the face), SIDE = face, **hold FRONT = Settings screen**, hold SIDE = network
  list. No details page opens Settings (the DEVICE SETTINGS page of the first attempt is gone). On the Settings
  screen: FRONT = next value (wraps); hold FRONT = save this page (green `SAVED` plate for 1 s, then the next page,
  after the last page the face; `SAVE FAILED` on a red plate in the same place keeps the value in effect and stays on
  the page); SIDE (or a hold of SIDE) = back to the face, nothing more saved. The network list keeps its keys (hold
  FRONT = "this AP is mine too" on a same-name row). **No key enters DEMO**: the capability stays behind
  `Presenter::set_demo(bool)` / `Companion::set_demo(bool)` for tests and tools (there is no console verb for it);
  if the stick is somehow in DEMO, hold FRONT returns to LIVE. The Buttons onboarding page says `Hold BLUE: settings`.
  **FRONT x3 fast** (UPDATE, or SETUP with no Wi-Fi stored) counts only on the face (boards/sticks3/main/
  measurement_main.cpp): on Details, Settings and the list FRONT is just "next", however fast. A hold (800 ms) is
  longer than the triple-tap gap (450 ms), so a tap the counter holds back is delivered before a hold fires and never
  reaches the Settings screen as a stray "next value". `guardian::Presenter` (`Screen::Settings`, `settings()`,
  `take_settings_save()` / `settings_saved()`, `lit_brightness_pct()`, `set_demo()`); tests/presenter_check.cpp
  `g24_*`, tests/companion_check.cpp `g24_*`.
- **The look** is the owner-approved one (evidence/sticks3-G24-settings-look-20261121.png, "perfect"): existing font
  and colours, no new art. `companion_preview` renders the pages through the real Companion as `24-settings-1..7`
  (opened with a hold of FRONT on the face); `tools/settings_look_compare.py <preview dir>` compares pages 1 to 6
  with the approved PNG pixel by pixel (2026-11-21: 0 differing pixels on each), and companion_check compares the composed
  lines with the look's own construction.
- **Guard on battery** (`guardian::guard_cycle_plan`, components/guardian_core/guard_cycle.*, tests/guard_cycle_check.cpp):
  ALWAYS = the radio listens all the time, no other lever (exactly as before); EVERY 30 S = listen 10 s / off 20 s;
  EVERY MINUTE = listen 10 s / off 50 s (the spike's mode G). The cycled choices act only on battery while the screen
  is Dark after its 2 s notice, listening first from that instant. Then every lever of mode G, ported from the
  never-merged `spike/power-exp` into production code: the IMU in its low-power motion mode (accelerometer only,
  25 Hz; a change above 0.08 g is motion and lights the screen as before), the LCD rail (PM1 GPIO2) cut, the radio
  stopped in each off period (`esp_wifi_stop`) and 80 MHz light sleep only while it is off. A key, motion, USB power
  or a counted burst (G16N) lights the screen and restores every lever at once (rail and panel setup first, the
  ES8311 power-down re-sent because the codec returns with the rail), and the radio listens at once. The update poll
  keeps its own period: it gets the radio and the panel back before its join, and the next loop re-applies the plan.
  While Dark nothing is drawn, so a planned off period never draws "No fresh data"; once lit, freshness and every rule
  apply from the resume as before. What a listen period cannot see: docs/G23-delivery.md section 11.4.
- **Brightness**: the backlight percent while lit (awake), 10 / 30 / 60 / 80 / 100, default 60
  (`sticks3::Board::backlight_active_pct`); the page previews the value on the glass at once and the screen returns to
  the value in effect when the page is left without saving. The dim level stays TUNE `power.dim_pct`. The update and
  sleep messages that light a dark screen use the same value.
- **Hours table** (adapters/companion/device_settings.cpp, one constant table, each entry citing its spike log line):
  ALWAYS 2 h 05 min (line 38, lowest, measured), EVERY MINUTE 7 h 14 min (line 43, highest, measured), EVERY 30 S and
  every brightness "not measured yet" (line 56). Highest and lowest are computed over the measured entries only
  (fewer than two measured: neither). The supervisor enters EVERY 30 S after its full drain; nothing is interpolated.
- **Storage**: the two values in their own record (NVS key `settings`, magic `GSET`, format 1, 12 bytes, CRC-32), never
  TUNE keys (the registry stays at 126 of 128). Absent: the defaults; unreadable, foreign or corrupt: the defaults and
  the record is kept (never silently erased). tests/device_settings_check.cpp (round trip, every flipped bit,
  absent, corrupt, failed write).
- **Unused parts off from boot, in every choice** (`sticks3::Board::parts_off`): green status LED (PM1 PWR_CFG 0x06
  bit 4), 5 V boost (bit 3), speaker amplifier (PM1 GPIO_OUT bit 3), IR TX gate G46 driven low with pad hold; the
  codec power-down at boot is unchanged. PM1 GPIO1 (the IRQ line, owner order #29) is never touched.
- **STATUS** (three space-separated tokens after the G23 energy fragment; the line buffer grew 7848 -> 8120, under
  the 8192 TUNE reply):
  `settings=guard:<always|every_30s|every_minute>,bright:<pct>,store:<default|restored|corrupt|saved|failed>`
  (`saved` / `failed`: the owner's latest save in this boot),
  `guard_cycle=<choice>,listen_ms=<n>,off_ms=<n>,cycles=<n>,resume_fail=<n>,relock_ms_avg=<n>` (Always prints 0 and 0:
  no cycle; `resume_fail` counts every lever switch that failed: radio stop or restart, rail, power management;
  `relock_ms_avg` is from a radio restart to the next lock on the picked network),
  `parts=led:<0|1|?>,ir:<low|?>,boost5v:<0|1|?>,amp:<0|1|?>,codec:<down|?>` read back from the PM1 registers, the G46
  output-enable and output registers and ES8311 register 0x0D (0xFC after the power-down; no answer, for example
  with the rail cut, prints `?`).
- **Power management in every image.** `sdkconfig.defaults` now sets `CONFIG_PM_ENABLE=y` and
  `CONFIG_FREERTOS_USE_TICKLESS_IDLE=y` (the G23 note above, "the normal image does not set it", is superseded), and
  `build_support.py` refuses an image without them (test_build_support.py). MEASURED on the built image
  `guardian-20261121-132309` against the delivery image `guardian-20261121-103138`: the built sdkconfig gains exactly
  `CONFIG_PM_ENABLE=y`, `CONFIG_FREERTOS_USE_TICKLESS_IDLE=y`, `CONFIG_FREERTOS_IDLE_TIME_BEFORE_SLEEP=3`,
  `CONFIG_PM_LIGHTSLEEP_RTC_OSC_CAL_INTERVAL=1` and `CONFIG_PM_SLP_DISABLE_GPIO=y` (GPIOs are disabled during an
  automatic light sleep; the keys are read when the loop wakes, at most every 100 ms, as in the spike);
  `CONFIG_PM_DFS_INIT_AUTO` stays off, so every image boots and runs at 160 MHz and nothing calls `esp_pm_configure`
  unless a cycled guard choice has the radio off. The bootloader is **byte-identical** (bootloader.bin sha256
  a5df9165...9d93 in both) and so is the partition table. The dark-cpu image keeps its own `esp_pm_configure` and
  never applies the guard's light sleep.
- **Carry-overs from the G23 owner run**: the shake stillness defaults are `burst.still_dps` 10 (from 12) and
  `burst.calm_s` 1.0 s (from 0.6), MEASURED with still_trace (evidence/sticks3-G23-20261121.log step 11: the slow
  tilt reaches calm 0 times); TUNE keys unchanged (tests/burst_check.cpp). **Alert-first**: when a NEW red ALERT
  starts, the presenter goes to the face whatever page or screen was open (a Settings draft is dropped, nothing is
  saved); the owner can still open another page while it lasts, and further reports of the same alert do not pull
  the screen again; amber keeps the open page (tests/presenter_check.cpp
  `g24_alert_first_a_new_red_alert_returns_to_the_face_amber_does_not`).
- **Not done here (the supervisor's acceptance, ledger row):** install over USB; STATUS `parts=` all off and
  `settings=`; the Settings screen photographed against the look; full drains for EVERY MINUTE, ALWAYS and EVERY 30 S
  (its hours then entered in the table, with the log line); zero `resume_fail`; any `reset=brownout` stops it.

## G16I upright by gravity and the snow-globe burst (implemented 2026-11-17; ledger G16I: accepted 2026-11-18, upright mode off by default by the owner's ruling)

Owner direction (2026-11-17): "fawkes should always stand facing up, independent of the
direction. his correct position is USB facing down, so he always stands up. if we shake
it: THOUSAND PARTICLES LIKE SNOW GLOBE, slowly reforming face". Scope: the 2D v4 portraits
(the 3D head is G21). Design, spikes and measured numbers:
[plan and spike results](evidence/G16I-plan-upright-burst-20261117.md).

**Upright** is a mode of the motion model (`adapters/companion/motion.{hpp,cpp}`), **off by
default since the owner's ruling of 2026-11-18** (`motion.upright=0`, the bounded floating tilt of G16C;
`TUNE motion.upright=1` turns it on; corrected by the G22 review, this paragraph said "on by default"):

- The face turns back by the whole roll, continuously, like a level (`tilt = -roll`), not
  in four snaps. The held angle follows the roll on the nearest turn, so crossing upside
  down (+-180 degrees) is a small step and never a spin.
- Lying flat (in-plane gravity under 0.3 g, about 17 degrees from flat) the roll is
  undefined: the last angle is HELD. Flat from the first sample shows the USB-down picture.
- A 0.5 degree deadband on the held angle keeps sensor noise out of a resting picture; the
  idle bob and sway (`motion.bob`, `motion.sway`) still move it on purpose.
- `motion.upright_fit` (default 1): turned, the 133x157 hood (130x157 before G16Q part 2) no longer fits the 135x160
  band, so the face shrinks just enough (`persona::fit_scale`: 1.00 standing, 0.66 at 45
  degrees, 0.85 on its side). `0` keeps the size and cuts the hood corners while turned.
- In this mode `motion.roll_gain`, `motion.max_roll` and `motion.drift` are not used (no
  tank wall on the rotation, no sideways drift with the roll). Pitch, yaw swirl, shoves,
  bob and sway are unchanged. A red ALERT is still a stare at the fixed USB-down pose.

**Shake** (`adapters/companion/shake.{hpp,cpp}`, fed every IMU sample, independent of the
`imu.*` axis map): gravity = each axis low-passed with a 1 s time constant; a peak = the
dominant axis beyond `shake.g` (default 1.2 g) after gravity is removed; an alternation = a
peak of the other sign at least 60 ms after the previous one; a shake = `shake.peaks`
(default 8) alternations inside `shake.window_ms` (default 1500), then nothing for 1 s.
On the nine traces recorded on the stick (`tests/fixtures/imu/`, the same bytes as
`evidence/sticks3-imu-shake-*-20261117.txt`): hard shake 16 and gentlest shake 11
alternations in the best window (fire); FRONT x3 update gesture 6, hands-off drops 5,
tap / still / walking / set down 0 (never fire). One short wiggle (about three swings)
cannot be told from FRONT x3 by count and does not fire.

**Burst** (`adapters/companion/burst.{hpp,cpp}`): one particle per lit 3x3 block of the
portrait on the screen (1,357 to 1,391 per rated face; capacity 1600 x 10 B = 16,000 B,
placed once at boot by `psram.hpp`). A particle paints its own home pixels, so the face
keeps its colours. `burst.s` (default 3.5 s) is the whole show: explode 0.5 s (outward at
120..300 px/s plus the shove), drift 1.0 s (gravity along the motion model's up vector,
drag, bounces off the edges of the face band), reform 2.0 s (every block eases to its home;
the last frame has every block exactly home). Shaking again while it runs throws the
particles again. Rules, all in `draw()` and host-tested:

- Only a fresh rated face bursts (`burst_allowed`): never NoData, never an ALERT portrait,
  never another screen. An ALERT, lost evidence, a changed rating or a missing art set
  cancels a running burst in the frame that shows it; the red stare is never hidden.
- Header, HUD, borders and every text pixel are painted exactly as without a burst. An
  amber nearby observation does not cancel (its dashed border stays).
- The board also ends a burst for the dim view, sleep, the update question, the EDGE
  pattern and the lab console, never starts one during a TUNE session, and drops a shake
  that no face frame used within 250 ms. A burst never keeps the screen awake by itself.

Deviation from the approved plan, on purpose: the plan reformed to the identity pose and
let the warp snap to the live pose afterwards. With upright on, that showed a sideways
face whenever the stick was shaken while turned. Here the homes follow the live pose
(rotation, fit scale, shift): the cloud leaves from where the face is drawn and lands
where it will be drawn. At the identity pose the last frame is still pixel-identical to
the portrait (`final_frame_equals_the_identity_portrait`). Blocks stay axis-aligned and
show their pixels turned by the nearest quarter turn, so on its side or upside down the
landed face is the turned portrait (`a_face_on_its_side_or_upside_down_lands_as_the_turned_portrait`);
at angles in between it lands as a 3x3 mosaic for the last frames before the warp takes over.

**Console.** TUNE keys (6 new, registry 94 of 96): `motion.upright`, `motion.upright_fit`,
`shake.g` 0.5..4, `shake.peaks` 2..16, `shake.window_ms` 200..3000, `burst.s` 1.5..10.
STATUS adds `shakes= bursts= burst_ram= burst_ram_bytes=`; `FRAMES` gains `kind=burst`.

**Host evidence** (not device proof). `tests/motion_check.cpp` (6 upright cases),
`tests/shake_check.cpp` (12 cases, the nine recorded traces among them), `tests/burst_check.cpp`
(13), `tests/companion_check.cpp` (7 draw-rule cases), `tests/frame_stats_check.cpp`,
`tests/persona_check.cpp` (hood box, fit scale, cache accessors). `render_bench` keeps a
`rated-burst` scenario: on the host debug build a burst frame draws in 254 us against 590 us
for a warped moving frame (1,373 particles; relative numbers only). Rendered frames from the
real composer (`companion_preview`), kept in the store with the red and green run logs because
`evidence/` holds device output only: `$GUARDIAN_STORE/builds/20261117-g16i-tdd/`
`G16I-upright-preview.png` (top: the panel; bottom: the stick as held), `G16I-burst-preview.png`
(the burst phases, standing and on its side) and `G16I-burst-roll90-closeup.png`.

**Not done here, for the owner on the stick (OTA):** every device check of the ledger entry
(roll through 360 degrees and flat, 30 s still, tap / FRONT x3 / walking / three shakes
against `shakes=`, `FRAMES kind=burst` render + push, ALERT during a burst, heap and stack
against `guardian-20261117-203615`). No `evidence/sticks3-G16I-*.log` exists until then.

**Known limits, left as they are:**
- A red ALERT keeps its stare at the fixed USB-down pose (G16E rule: the IMU pose is ignored
  during an ALERT), so with the stick turned the ALERT face is not upright. The dim view is
  the still USB-down portrait too.
- The Very good smoke curl rises up the glass and is clipped to its fixed box; with the face
  turned far, the ember follows the cigar but the smoke is cut or absent.
- The NoData silhouette is 1 px wider than the hood box (column 131); turned, it can lose
  that column at the band edge.
- The shake numbers come from one owner and one stick (nine 10 s traces); the margin is two
  alternations on each side at 1.2 g.

## G16O the shake particles obey gravity (implemented 2026-11-18; ledger G16O: accepted 2026-11-19, the slow-tilt stillness carried into G23)

Owner direction (2026-11-18): "when shake, particles should assume physics, fall... if one keeps
tilting to sides, particles should fall (gravity)... it only comes back with no or very few
tilting... if one shakes and keeps shaking, particles keep falling on gravity". G16I reformed the
face 1.5 s after the shake on a fixed timer, whatever the hands did. Now (`adapters/companion/burst.{hpp,cpp}`):

- **Fall and pile.** After the 0.5 s explode the particles fall along the motion model's up vector
  (as before: 250 px/s^2, drag, bounces off the other edges of the face band) and SETTLE on the edge
  that is down: a block that reaches the floor or a lying block stays there (no bounce), in a 3 px
  cell of its own. The pile map is one bit per cell (45 x 53 cells standing on the band's bottom
  edge, 424 B); flying blocks pass through each other and only meet lying ones while moving toward
  down, so a frame is one pass over the particles (no particle-against-particle search). About
  1,380 blocks make a pile about 31 rows high over the whole width; blocks never overlap.
- **It follows the stick.** For as long as the stick is handled the pile obeys the down of the
  moment (one of eight directions: an edge, or a corner beyond 22.5 degrees of lean): a lying block
  whose next cell toward down is free falls again, one with a free cell diagonally below topples
  into it (a heap keeps a 45 degree slope, no towers), layer by layer, one cell per 20 ms. MEASURED
  on the host: turned on its side, the heap has moved over and is completely at rest about 6 s
  later (most of it within 3 s). Lying flat (under 0.2 of gravity across the glass) there is no
  down: nothing settles or slides.
- **The reform waits for a still stick.** A frame is "moving" when the up vector turned faster than
  `burst.still_dps` since the frame before, or the shove is above `burst.still_g`. The reform starts
  once the stick has been still for `burst.calm_s`; never earlier than explode + drift after the
  last shake (so a shake on a stick that is then left alone is still the 3.5 s show of G16I), and
  never later than `burst.max_s` after the last shake. Held still after handling, the face is back
  2.6 s later (0.6 s calm + 2.0 s reform), every block exactly on its home as before. A reform that
  has started runs to its end; only a new shake interrupts it.
- **A new shake** (kick) throws everything again: blocks that lay in the pile are thrown away from
  the floor they lay on, and both clocks (stillness, maximum) start again. So a stick that is shaken
  on and on never reforms; one that is only carried about reforms after `burst.max_s`.
- An ALERT, lost evidence, another screen and the board's own stops cancel the burst exactly as in
  G16I (`companion_check` unchanged).

**Stillness defaults, MEASURED** on the nine traces recorded on the stick for G16I
(`tests/fixtures/imu/`), through the real motion model at 25 frames a second (spike source and
output: `$GUARDIAN_STORE/builds/20261118-g16o-tdd/spike/still_spike*`). Per frame,
the turn of the up vector (degrees/s) and the shove across the glass (g):

| trace | turn p50 / p99 | shove p99 | moving at 12 dps, 0.10 g | reaches 0.6 s of calm |
|---|---|---|---|---|
| `still`, `setdown` (held in the hand) | 2.0 / 15.0, 2.2 / 7.8 | 0.05, 0.01 | 2 %, 0 % | yes |
| `walk` (this recording is a stick lying still: gyro about 1 degree/s) | 0.9 / 10.9 | 0.02 | 1 % | yes |
| `tap` (this recording is continuous handling: gyro about 80 degrees/s) | 62 / 255 | 0.20 | 92 % | once, in a 0.68 s pause |
| `front3`, `softshake`, `drop2` | 92 / 497, 90 / 426, 113 / 913 | 1.1, 1.1, 1.7 | 96 %, 97 %, 98 % | never |
| `shake` (three hard shakes with pauses) | 26 / 217 | 3.0 | 70 % | never |

So `burst.still_dps` 12 and `burst.still_g` 0.10 keep a hand-held stick "still" and gentle
handling "moving". They are host numbers from recorded traces; the owner tunes them on the glass.

**Console.** Four TUNE keys: `burst.still_dps` 2..60 (12), `burst.still_g` 0.02..1 (0.10),
`burst.calm_s` 0.2..5 (0.6), `burst.max_s` 5..120 (20); `burst.s` keeps its meaning (explode 1/7,
shortest fall 2/7, reform 4/7 of it). The registry was full (112 of 112), so `tune::max_params` is
now 120: 55 board keys + 61 `t.*` keys = 116. Stored TUNE blobs load unchanged (entries are keyed by
name). STATUS and FRAMES are unchanged (`kind=burst`); the burst object grows by 488 B (host `sizeof`
16,080 to 16,568: the pile map and the clocks), still placed in PSRAM; STATUS `burst_ram_bytes`
shows the device value.

**Host evidence** (not device proof). `tests/burst_check.cpp`, six new cases:
`gravity_follows_the_stick_down_while_tilted`, `particles_settle_on_the_floor_and_pile_up`,
`continuous_tilting_postpones_the_reform`, `calm_starts_the_reform_and_lands_exactly`,
`max_time_always_reforms`, `a_new_shake_rescatters_a_pile`. Three G16I cases changed with the
behaviour: the object-size bound (the pile map); `particles_stay_inside_the_band_in_every_phase`
(its hand never stopped swinging, which now postpones the reform, so it stops after 200 frames);
`step_is_frame_rate_independent` (block by block for the flight, as before; for the fall the cloud
as a whole: which block lands first, so which lies on which, differs between 20 ms and 50 ms frames:
MEASURED mean 9.9 px block by block, the middle of the cloud 0.4 px apart, 1,200 against 1,225
blocks lying). `render_bench` adds `rated-burst-handled` (the stick turned and swung the whole time,
the pile sliding): on the host debug build 322..336 us a frame against 468..475 us for a warped
moving frame and 274 us for the burst on a still stick (three runs of 2,000 frames; relative
numbers only). Red and green logs, the spikes and the rendered frames (`preview/G16O-pile-sheet.png`,
frames `26-pile-*` of `companion_preview`): `$GUARDIAN_STORE/builds/20261118-g16o-tdd/`.
`firmware/tools/host-check.sh` on the final source: 51 of 51 plain and 51 of 51 ASan/UBSan
(`$GUARDIAN_STORE/builds/20261118-162912-host-kwLhyN/`). Board build: signed archive
`guardian-20261118-162646` (`builds/20261118-162646-86544-sticks3/`: SHA256SUMS 25 of 25, the four new
key names present in the signed image; 2,883,584 B, 8 % of the slot free). Built and archived only: not
flashed, not sent over OTA, not run.

**Not done here, for the owner on the stick (OTA):** shake and keep tilting (the pile follows
gravity for as long as he tilts), hold still (the face is back in about 2.6 s), `FRAMES kind=burst`
render + push at or below 40 ms, `evidence/sticks3-G16O-*.log`. Nothing of G16O is proven on the
device; the burst frame cost on the device has never been measured (G16I's device checks are also
still open).

**Known limits, left as they are:**
- The stillness rule sees the up vector and the shove across the glass, at the frame rate. A turn
  about the vertical (yaw) and a shove straight through the glass do not count as moving.
- Gravity for the particles is the up vector only; a shove moves them only through a new shake.
- With the upright face off (the default since 2026-11-18) the face itself floats within 20
  degrees while the pile follows the real down: on its side the particles lie on the side of the
  glass and the face reforms where the floating face is drawn.
- A heap keeps its 45 degree slope until the lean passes 22.5 degrees; a slightly tilted stick
  does not level its pile like water.
- An image older than G16O that is rolled back to after a TUNE save keeps the first 112 stored
  values only (the last four `t.*` values return to their defaults).

## G16J attack coverage (implemented 2026-11-18; ledger G16J: accepted 2026-11-18, the device Verify items carried into G23)

Owner direction (2026-11-17): "for every single attack that I try, our guardian must guard and alert".
The full kit-by-attack matrix, what is proven and the plan are in
[docs/attack-coverage.md](../docs/attack-coverage.md). This section is the firmware side. Image
`guardian-20261118-012503` builds and is signed (`builds/20261118-012503-81639-sticks3` in the store; the earlier `guardian-20261118-010855` and `-011846` of the same night are superseded);
**it was not flashed and not run on the stick in this handoff.**

**Detectors (16 registry entries, STATUS `detectors=`; 17 since G16H added the unfed `ble_popup`, see its section), red = about the selected network, amber = seen nearby:**

| STATUS name | what it reports | colour |
|---|---|---|
| `disconnect` | deauthentication / disassociation burst on the picked network: the selected or an approved AP, or (**G16R**) any address heard advertising the picked network's exact name | red |
| `baseline` | the selected name from another device (same-name watch, **on by default since G16J**); approved AP settings changed | red |
| `probe_flood` | probe-request floods: many random addresses, one address, many askers of one name | amber |
| `beacon_flood` | many strong BSSIDs beaconing at once | amber |
| `responder` | one radio answering for many names; **G16J: a new radio answering a name a device just asked for** | amber |
| `auth_flood`, `sae_commit`, `assoc_sleep` | join floods against one BSSID | red on yours, amber nearby |
| `channel_switch` | channel-switch count out of the ordinary, long Quiet, a switch your AP's own beacons do not keep announcing | red / amber |
| `name_mismatch`, `owe_twin`, `marked_beacon` | probe-response name differs from the beacons; open copy of an OWE network; element 222 / DE:AD:BE:EF:DE:AD | red / amber |
| `area_disconnect` | disconnect frames on other networks; **G16J: many aimed at one device on YOUR network too**; **G16T: a burst on other networks that also names YOUR network** | amber / red |
| `rotation` | one radio rotating names; **G16J: an open lure-word name from an Espressif-assigned address** | amber |
| `handshake` | unanswered handshake starts, forged-looking start, clients pushed off then reconnected. Needs the data path (**default off**) | red / amber |
| `noise_floor` | **G16J, replaces `frame_loss`:** the channel's noise floor ≥8 dB above its own 60 s average for 3 s. Needs no data path | amber |

**Tool shapes (G16J).** Frames that match a shape widely used tools send (fixed sequence control 0xFFF0 with
reason 2, Duration 0x013A with reason 7, a rising-sequence run to one destination, deauthentication /
disassociation alternation, channel-switch count 0xFF, probe sequence control 0x0001, a beacon timestamp that
never advances, beacon interval 1000, transmitter 12:34:56:78:9A:BC, handshake replay counter 0xF000..0xFFFE, a
template PMKID, a handshake within 30 s of shaped disconnect frames) **halve the count threshold** and add one
sentence on the glass: "looks like a known attack tool". The tool is never named, the sender never identified:
addresses and counters are spoofable bytes, and a shape is a hypothesis (TUNE `t.shape_frames`, `t.shape_run`,
`t.tsf_static_beacons`, `t.tsf_static_ms`, `t.bait_ms`).

**What it cannot see** (also on the glass: Details, page "What it cannot see"):

- 5 GHz and 6 GHz: the ESP32-S3 radio is 2.4 GHz only. A dual-band router's 5 GHz side is never heard.
- Other channels while locked: the radio stays on the selected network's channel. The optional area sweep
  (`TUNE detect.sweep_ms`, a dwell every 2 s) is **off by default**; with it on the page says
  "channel N + area sweep" and the coverage report says "hopping" with the time away taken off.
- The handshake watch while the data path is off: the page says "handshake watch: off" ("off (load)" only
  after spike (a) measured a load that forces it off; "on" when `TUNE detect.datapath=1`).
- Radios that only listen (silent PMKID / handshake sniffing, wardriving): nothing is transmitted.
- Attacks inside the network after a device joined (ARP, DHCP, DNS, HTTP): no data inspection.
- Bluetooth floods (G16H, deferred). WPS PIN attacks, KRACK, rogue RADIUS: no passive frame signature.
- A jammer strong enough to stop all reception: no frames, so no noise reading; the selected network then
  shows "No fresh data". A microwave oven raises the noise floor too: the observation says the channel got
  noisy, never why.
- Who is attacking: it says what it saw, never who sent it.

**Thresholds.** The table of every default, its source (measured on this radio or hypothesis) and its evidence
file is in [docs/attack-coverage.md](../docs/attack-coverage.md), section "Thresholds". Measured so far: the
probe-flood defaults (16 probes from 12 addresses in 10 s) and the red burst (20 in 10 s). Everything else is a
hypothesis until its live row is recorded.

**Same-name watch and "this AP is mine".** Every network picked from the list is watched: the same name from a
BSSID that is neither the selected one nor approved is a red ALERT, "Another device is using your network's
name". A selection saved by an earlier image is upgraded once at boot (and saved). A home with a mesh node, an
extender or a second 2.4 GHz radio using the same name will ALERT until the owner approves it: open the list
(hold SIDE), move to the row with the same name (it shows the `..:AA:BB` address tail), **hold BLUE** ("hold
blue: my AP"); holding again takes it back ("hold blue: not mine"). Approved rows are green like the chosen
one. `TUNE detect.twin=0` restores the earlier behaviour (no watch).

**Your network is its name, not one address (G16R, 2026-11-18, pending review).** Measured on the stick: a
deauth run aimed at the owner's router by NAME gave amber twice, because the red detector counted only the
frames naming the selected address (4-7) while the nearby detector counted the rest (43-58): the router answers
to the picked name from more than one 2.4 GHz address. Now the Network scope is the selected BSSID, the
approved list **and every BSSID the stick has heard beaconing or probe-answering the picked network's exact
name since it was picked**. Rules (`ApprovedScope::hear` / `in_network`, `guardian/detectors.hpp`):

- Learned from the air only: a Beacon or Probe Response the receiver vouched for, with the name byte-equal to
  the picked one. A device ASKING for the name (probe request) teaches nothing. A picked hidden network has no
  name to match. No name, address or vendor list is in the code; the name comes from the picker / saved
  selection.
- Bounded: 8 addresses besides the selected and approved ones. A ninth replaces the one heard longest ago (an
  AP that keeps beaconing is never the one replaced). Forgotten on every new pick; kept when the same network
  is only re-approved or its watch is switched.
- One window: disconnect frames against ANY of those addresses add up in the one red burst count
  (`disconnect`), so a tool that walks the addresses of one name reaches the threshold. They no longer count
  for the amber `area_disconnect`. The other "on your network" rules (pair, join floods, channel switch, name
  mismatch, handshake) read the same set. A burst against another name stays amber.
- Heard is not approved. An unapproved address using the name is still the red "Another device is using your
  network's name" (`baseline`, unchanged), and a burst against it is red too; both can be current at once.
  Honest limit: a device that beacons the picked name makes frames "against" its own address count as the
  picked network's. That is the owner's rule (red when the name is hit); the address is spoofable evidence.
- The glass names the network, never an address: "Disconnect burst on <name>" (the name shortened with `~` to
  one row; "on your network" when the picked network hides its name). The address the frames named stays in
  the evidence record.
- STATUS adds ` same_name=<addresses learned> same_name_evicted=<replacements>` after `area_visible=`.
- Limit that stays: one channel at a time. An address of the name on another channel is learned only while
  the radio is there (searching, the list open, or the optional sweep), and a burst on that other channel is
  not heard at all.

Host evidence (not device proof): `tests/coverage_check.cpp` cases `g16r_*` (8) and `tests/presenter_check.cpp`
case `g16r_*`, red and green logs in `$GUARDIAN_STORE/builds/20261118-g16r-tdd/`. Two G14
glass assertions that pinned "Disconnect burst detected" now expect the new sentence (comment `G16R:`).
**Not proven on the stick:** the owner's run against his own router (RED within the 10 s window, STATUS
`disconnect` counters and `same_name=` recorded in `firmware/evidence/sticks3-G16R-*.log`) and a run against a
neighbour's name (amber).

**Burst forensics: who the frames named (G16S, 2026-11-19, pending review).** After G16R the owner's run still
gave amber (`area_disconnect events=16 incidents=1`, `same_name=0`), and the addresses in those frames were not
known. The stick now keeps them, so they are read over the TUNE poll with no USB capture. Nothing is decided
from them in this change: the G16R fix direction is written from the first recorded run.

- What is kept: for the last disconnect burst of each scope, up to 8 tuples of (receiver = Address 1, sender =
  Address 2, BSSID = Address 3, the channel the radio was tuned to) with the counted frames of each (after the
  detector's own Retry-bit deduplication), the burst's total and the time of the frame that reached the
  threshold. Header bytes as received: spoofable, never a device or a person proven.
- A burst starts when a disconnect rule reaches its threshold: the red burst (`disconnect`, 20 in 10 s, 10 with
  a tool shape) or one of the `area_disconnect` rules (source, pair, broadcast). The record takes the frames of
  the window at that moment and then every further counted frame, for as long as the burst lasts (its counts
  never slide). It closes when a whole window (10 s) passes without a counted frame and stays readable until
  the next burst. A second burst inside the 45 s cooldown of the first makes no new alert and is recorded all
  the same, so a quick second run is not hidden behind the first.
- Network record: the red burst's (`DisconnectDetector`, exact: the frames of its window ring), or the pair
  rule's on the picked network (`AreaDisconnectDetector`), whichever reached its threshold later. Area record:
  frames under BSSIDs that are not the picked network's (`AreaDisconnectDetector`, a sliding table in 5
  sub-slots of 2 s like its other counters, so the part before the threshold covers 8 to 10 s).
- Bounded: 8 tuples per record (`BurstRecord`, `guardian/shapes.hpp`). A ninth replaces the one with the fewest
  frames (equal: heard longest ago); the replaced frames stay in the total and print as `unlisted`. A flood
  that changes an address on every frame therefore shows many `unlisted` frames and tuples of one frame each,
  never a made-up top address. Cost on the host: `DisconnectDetector` 5,928 B (limit 6,144), `Monitor` 80,360 B.
- STATUS adds two fields after `same_name_evicted=` (their own 704 B buffer, so they are never lost with the
  detector list): ` last_burst_network=<record> last_burst_area=<record>`. `<record>` is `none`, or
  `rule:<burst|deauth_source|deauth_pair|deauth_broadcast>,total:<frames>,unlisted:<frames>,tuples:<kept>,`
  `age_s:<since the threshold>,open:<1 while the window is open>,top:<t>;<t>;...` with up to 4 tuples, most
  frequent first, each `<a1>/<a2>/<bssid>/<ch>:<n>` (12 hex digits per address). No space and no `=` inside a
  record (`tools/threat_watch.py` splits on them). Example with the synthetic addresses of the host check
  (14 broadcast frames naming one access point, 6 to one device naming another, read 13 s later):
  `last_burst_area=rule:deauth_broadcast,total:20,unlisted:0,tuples:2,age_s:13,open:0,top:<t1>;<t2>` with
  `<t1>` = `ffffffffffff/0066778899aa/0066778899aa/6:14` and `<t2>` = `3c1000000009/001000005a01/001000005a01/6:6`.
- The records are counters: a new pick, a changed `detect.*` / `t.*` limit and a restart clear them, so read
  STATUS before changing a TUNE value. Starting a TUNE session does not clear them (the counters of the 00:23
  run were read at 00:28).
- On the glass: the most frequent tuple at the moment of the alert, in two white rows with the last two bytes
  of each address, `to FF:FF from 4E:5F` and `AP 4E:5F ch6 x12`. Red: Details, page "Signal and listening
  coverage", under `Seen N (raw M)`. Amber: Details, page "Nearby observations", under the newest disconnect
  entry (once: the entries of one burst share it). The rows are left
  out when the page has no room for them (STATUS always has the record). The red sentence still names the
  network and never an address (G16R).
- TUNE reply size: one STATUS line was 3,692 characters on the stick (2026-11-19) and the reply buffer held
  4,095, so the two records (up to 673 characters) would have cut the end of the line without a word.
  `tune::wifi::kMaxReply` is now 8192, the size `tools/tune_session.py` reads of one reply.

Host evidence (not device proof): `tests/coverage_check.cpp` cases `g16s_*` (6: the table and its bound, a
mixed burst on two addresses of the picked name, a mixed burst against two other access points, the STATUS
text, the Details rows) and `tests/presenter_check.cpp` case `g16s_*`; red and green logs in
`$GUARDIAN_STORE/builds/20261119-g16s-tdd/`. **Not proven on the stick:** one Bruce run with
STATUS read over the TUNE poll (the supervisor records it in `firmware/evidence/sticks3-G16S-<date>.log`).

**A nearby burst that also names your network is red (G16T, 2026-11-19, pending review).** The first recorded
run (`firmware/evidence/sticks3-G16S-20261119.log`, 12:12, `guardian-20261119-021247`) showed the cause of the
amber: the burst was spread over the access points of the channel (`area_disconnect events=40 incidents=1`, 7
tuples on channel 11), and the picked network got at most a few frames per window (`disconnect events=3
incidents=0`), below the red burst's own threshold. The owner saw amber for an event that reached his network.

- The rule (`AreaDisconnectDetector`, `guardian/threats.hpp`): when a nearby disconnect rule is reached
  (source, pair or broadcast, thresholds unchanged) and the same burst holds at least one counted disconnect
  frame that names the picked network, the report is a Network incident (`NetworkPattern`, red) instead of an
  Area one. No such frame: Area, amber, as before.
- "Names the picked network": Address 1, 2 or 3 of the frame is the selected address, an approved address or
  one heard under the picked name (the G16R set). Nothing is configured or hard-coded: the addresses come from
  the pick and from the air.
- "The same burst": the 10 s source window before the rule is reached, then every counted frame for as long as
  the burst is being counted (it closes after 10 s without one). A frame at the picked network that arrives
  after the amber report turns that burst red at that frame; a frame after the burst has closed does not.
- Unchanged: the red burst (`disconnect`, 20 in 10 s, 10 with a tool shape) and the pair rule on the picked
  network. A few frames at the picked network with no nearby burst report nothing. One Network report per
  rule per 45 s cooldown, as for every pattern.
- The report (`IncidentObservation`): `pattern`, `count`, `threshold` and `window_ms` are the nearby rule that
  was reached; the new `own_frames` is how many frames of the burst named the picked network so far; `top` is
  the most frequent tuple naming it and `bssid` the picked network's address in that tuple.
- On the glass: the red sentence is `Nearby burst also on <name>` (the first row is 20 glyphs, the name starts
  the second; a long name ends in `~`; a network without a printable name reads `your network`). Details,
  page "Signal and listening coverage", shows that tuple under `Seen N (raw M)`, for example
  `to FF:FF from 44:55` and `AP 44:55 ch6 x1`. `ViewModel::alert_reason` is
  `Disconnect burst nearby also on your network`.
- The burst record (G16S) of a nearby burst now holds every counted disconnect frame of the burst, the picked
  network's too. A tuple naming the picked network is marked and is never the one replaced while another
  tuple is listed, so three frames stay listed inside a burst of hundreds.
- STATUS: in such a record `,own:<frames>` follows `tuples:` (the key is absent when no frame named the picked
  network, so the records of G16S read as before), every tuple naming the picked network ends `:own`, and it
  is printed also below the four most frequent (a record prints up to 8 tuples). The same record is then both
  `last_burst_network` and `last_burst_area`: one burst, nearby and on the picked network. Example from the
  host replay (40 frames over seven access points, 3 at the picked address, read 4 s after the threshold):
  `last_burst_network=rule:deauth_broadcast,total:40,unlisted:0,tuples:7,own:3,age_s:4,open:1,top:<t1>;<t2>;<t3>;<t4>;<t5>`
  with `<t5>` = `ffffffffffff/001122334455/001122334455/6:3:own`.
- `total` in that record counts the picked network's frames as well, so it can be larger than the
  `area_disconnect` `events` of the same seconds (those count frames under other BSSIDs only).
- Buffers: the two records at their longest are 1,199 characters, so `Monitor::burst_text_max` is 1280 (was
  704) and the board's STATUS line buffer 7168 (was 6144); the TUNE reply stays 8192.
- Honest limits: header addresses are spoofable bytes, so the record says what was heard, never who sent it
  or who was hit for certain. One ordinary disconnect frame of the picked network (a device leaving) inside
  a neighbour's burst makes that burst red too: the rule is "at least one", as the ledger sets it, and
  `own:` shows the count so the owner can judge. The glass tuple and `own_frames` are the values at the
  moment of the alert; the whole burst is in STATUS.

Host evidence (not device proof): `tests/coverage_check.cpp` cases `g16t_*` (9: the 40-frame replay with 3
frames at the picked address, its twin with none, the same through the same-name set and the approved list, a
frame after the amber report, the window bounds and the unchanged red threshold, Address 1 / 2, the table
bound, the STATUS text, the glass) and `tests/presenter_check.cpp` case `g16t_*`; red and green logs in
`$GUARDIAN_STORE/builds/20261119-g16t-tdd/`. **Not proven on the stick:** the same Bruce run
must give red with the picked network's tuple and `own:` in the record, and a run that avoids the picked
network must stay amber (`firmware/evidence/sticks3-G16T-<date>.log`, owner over the TUNE poll).

**Console.** TUNE keys: `detect.twin` 0..1 (default 1), `detect.sweep_ms` 0..500 (default 0); 14 new `t.*`
keys (`t.noise_rise_db`, `t.noise_average_ms`, `t.noise_hold_ms`, `t.noise_min_frames`,
`t.noise_baseline_samples`, `t.shape_frames`, `t.shape_run`, `t.tsf_static_beacons`, `t.tsf_static_ms`,
`t.bait_ms`, `t.karma_answer_ms`, `t.karma_answers`, `t.karma_learn_ms`, `t.lure_beacons`); the five
`t.loss_*` keys are gone (a stored value for them is ignored). `t.probe_window_ms` / `t.probe_flood` /
`t.probe_flood_sources` now default to 10000 / 16 / 12. Registry: 105 of 112 (`tune::max_params` raised from
96). STATUS adds `twin=` and `sweep_ms=`; the detector list shows `noise_floor` instead of `frame_loss`. The
G13 JSON adds `shapes` per area observation, `network_pattern_shapes`, `burst_shapes`, `burst_threshold`.

**Host evidence** (not device proof): `tests/coverage_check.cpp` (36 cases: each new rule with an attack
stream firing once per cooldown and a benign twin never firing; same-name watch, approval, wording, the limits
page, hostile names, TUNE keys, the sweep) and `tests/datapath_check.cpp` (noise-floor cases). Red and green
logs: `$GUARDIAN_STORE/builds/20261118-g16j-tdd/`. Older cases whose generated frames happened
to match a tool shape (consecutive sequence numbers, a constant timestamp, a constant PMKID) were made
unshaped, and the G14 case that pinned "hold blue does nothing / a same-name radio never alerts" was rewritten
for the new owner direction; each such edit carries a `G16J:` comment.

**Not done here, for the owner on the stick:** every live row (`tools/live_matrix.py --list`), spike (a)
(`tools/datapath_spike.py`), spike (b) (sweep against the Pi emitter's burst), spike (d) (karma capture), the
12 h soak at the new defaults, heap / stack / fps with the new image, the photographed limits page, and the
shipped-artifact boot check of `guardian-20261118-012503`. The board wiring (noise readings into the meter,
`detect.twin`, `detect.sweep_ms`, the sweep's coverage accounting, the limits status) compiles and is
**untested on hardware**.

**Known limits, left as they are:**
- The lure-portal rule sees only Espressif-assigned addresses; a tool that randomizes its address is missed.
- Probe-then-answer can also match a hotspot switched on within 10 s of a device asking for it by name, and
  is silent while its table of heard BSSIDs is saturated (more than 128 advertisers inside a minute); an AP
  heard so rarely that it left that table can look new when it answers.
- The rising-sequence shape assumes a real AP does not send six consecutive distinct disconnect frames to one
  device; an AP that does halves its own burst threshold (20 to 10), nothing more.
- The area sweep costs two retunes every 2 s, and each retune discards the frames still queued; that loss is
  what spike (b) must measure before the default can leave 0.
- The noise-floor rule has never seen a real reading from this radio: STATUS does not print the noise floor,
  so the 8 dB / 5 frames numbers are untested against this home's normal variation.

## G16H Bluetooth pairing-popup observations (host library 2026-11-19; NOT watched on the StickS3 by design; ledger G16H: accepted for that scope)

**Verdict 2026-11-19 (MEASURED, coexistence spike run A, `evidence/sticks3-G16H-coex-spike-20261119.log`):** on the
ESP32-S3 a passive BLE scan costs the Wi-Fi capture about its own duty in selected-AP beacons (3.3 / 10.3-11.0 /
26.6 / 51.5 % at 3 / 10 / 25 / 50 %); heap (NimBLE 38,340 B) and queue were fine. Any duty that could feed the
popup rules would cost a quarter to a half of the Guardian's frames, so this device does not watch Bluetooth (Details
"What it cannot see" says so) and the detector stays unfed; the radar's Bluetooth glyph appears only with a feed. The
C5 node (G16K, `docs/c5-node.md`) feeds it later.

What exists (portable, host-tested, `tests/ble_check.cpp`; sources and limits in
[docs/research/ble-popup-spam.md](../docs/research/ble-popup-spam.md)):

- `guardian/ble.hpp`: `BleAdvert` (one legacy advertising report from a passive scan) and `parse_ble_popup()`, a
  bounded classifier for the pairing-popup messages of four vendor formats. A cut or hostile advert classifies nothing.
- `BlePopupDetector` (`guardian/threats.hpp`, registry entry 16, name `ble_popup`, family `bluetooth`): two rules,
  both Area scope (amber, never an ALERT, never the rating):
  `pairing_popup_flood` "Pairing-popup spam nearby" = at least `t.ble_popup_messages` (3) different messages from at
  least `t.ble_popup_sources` (3) short-lived addresses inside `t.ble_popup_window_ms` (1 s), after
  `t.ble_learn_ms` (30 s) of listening, an address staying known for `t.ble_address_memory_ms` (60 s);
  `fast_pair_rotation` "One address spamming pairing popups nearby" = one address with at least
  `t.ble_rotation_models` (3) Fast Pair model IDs inside `t.ble_rotation_window_ms` (5 s).
- `Monitor::set_ble_scan(bool)`, `Monitor::ble_advert(const BleAdvert&)`, `Monitor::ble_coverage(const CoverageReport&)`:
  the feed an adapter with a passive BLE scan uses. Off by default.
- The radar's tenth slot (a rune) and its rates offset appear only while the scan feeds the detector.
- TUNE: seven `t.ble_*` keys; `tune::max_params` 120 -> 128 (56 board keys + 68 `t.*` = 124).

What does NOT exist: any BLE scan in the Guardian image. `set_ble_scan` is never called on the StickS3, so STATUS
prints `ble_popup:frames=0,...,unconfigured`, the radar has nine slots as before and "What it cannot see" still
lists BLE. The spike variant (`tools/build.sh build-ble-spike`, console verb `BLESPIKE start`, section "G16H spike"
of the 2026-11-17 attempt) only counts adverts; its 2026-11-19 verdict (above) keeps the scan off this device. The
board adapter, the benign soak with the owner's real earbuds and one live run per tool mode move to the C5 node.

Spike over Wi-Fi (supervisor, 2026-11-19; the stick's USB is only its charger now): in the spike image the TUNE
session also accepts `BLESPIKE`, `BLESPIKE start [<phase_s> <rounds>]`, `BLESPIKE stop`, `BLESPIKE report` and
`BLESPIKE phases`. Over Wi-Fi `start` only ARMS the run: it starts after that session ends, once the Guardian
monitors the selected AP again (it gives up after 180 s, `last_end=not_monitoring`). While a run is armed or running
the self-fetch poll and the dim/sleep policy wait, so the next TUNE session reaches the stick only after the run
ends; then `BLESPIKE report` (levels, verdict, END) and `BLESPIKE phases` (every phase line) read it. A TUNE session,
an update or the setup page during the run still ends it (`last_end=tune/update/setup`), so nobody touches the keys. The normal image answers
these verbs `TUNE ERROR unsupported`.

## G21 the 3D Guardian head (implemented 2026-11-18; ledger G21: accepted 2026-11-18, off by default by the owner's ruling)

Owner direction (2026-11-17): "the face is the repo art, in 3D", "we can polish on the end". The head is not
rendered on the stick. The owner's 512x512 master is projected on the Meshy head in Blender and rendered from a
grid of angles; the frames are packed, embedded in the app, and the stick shows the one frame that matches its
yaw and pitch. A better render set is one rerun of the two commands below and a normal build: no firmware change.
**Nothing here was run on the stick in this handoff.**

**Pipeline (rerunnable).** Inputs in the store (`$GUARDIAN_STORE/art-exports`), no Meshy call:

| Mood | Head (GLB, sha256) | Master (PNG, sha256) |
|---|---|---|
| Very good | `G21-3d/20261117-222822/i2.glb` `fdf61851...63b40a6` | `G15/20261117-v4/masters_png/VeryGood.png` `234557de...751eb5` |
| Medium | `G21-3d/20261117-222822/i1.glb` `2118ae55...b389ba` | `G15/20261117-v4/masters_png/Medium.png` `803cb9b9...58d6a1` |

```sh
S=$GUARDIAN_STORE/art-exports; V=$S/G21-3d/20261118-g21-views-r3
# 1. render one mood's angle grid (Blender 5.2; about 45 s for 27 views at 540x640)
/Applications/Blender.app/Contents/MacOS/Blender -b -P tools/face3d/project_views.py -- \
  $S/G21-3d/20261117-222822/i1.glb $S/G15/20261117-v4/masters_png/Medium.png $V/Medium-on-i1 \
  --yaw -30,30,9 --pitch -15,15,3 --scale 4 --fill 0,0,0 --graze 0.05,0.25
/Applications/Blender.app/Contents/MacOS/Blender -b -P tools/face3d/project_views.py -- \
  $S/G21-3d/20261117-222822/i2.glb $S/G15/20261117-v4/masters_png/VeryGood.png $V/VeryGood-on-i2 \
  --yaw -30,30,9 --pitch -15,15,3 --scale 4 --fill 0,0,0 --graze 0.05,0.25
# (2026-11-18, owner: 'exactly like the approved image'): black fill, narrow grazing fade, and the render camera framed
# like the 2D crop (project_views.py), so the yaw-0 frame matches the shipped 2D portrait: mean |diff| 5/255, lit 12/255,
# luminance 0.92 (was 20 / 37 / 0.85 with the teal fill and the mesh-box framing).
# 2. pack every mood that has views (always the whole pack; a mood not named loses its set)
python3 tools/face3d/pack_frames.py pack --out firmware/art/persona/v3/frames \
  VeryGood=$V/VeryGood-on-i2 Medium=$V/Medium-on-i1
python3 tools/face3d/pack_frames.py verify firmware/art/persona/v3/frames
# 3. host check, then the signed image (its archive step re-checks the image itself)
firmware/tools/host-check.sh && firmware/boards/sticks3/tools/build.sh build
```

`pack_frames.py` puts each view on black, downscales it to 135x160 (LANCZOS), converts it to little-endian RGB565
(43,200 B, the same bytes as a 2D portrait file) and deflates it alone (zlib level 9, raw deflate). It writes
`firmware/art/persona/v3/frames/<Mood>.bin` (layout in `adapters/companion/head3d.hpp`) and `manifest.json`: the
grid, and per frame the offset, size, adler32, the sha256 of the inflated frame and the sha256 of its view. The
same views give the same bytes. It refuses, before writing anything, a grid with a hole, a view that is not
135:160, more than 32 x 16 angles, and a pack above the budget.

`project_views.py` fix (2026-11-18): its bake loop never finished (one run was 2 h 35 min old with no frame). A
stack sample showed why: it read `v.normal` right after writing a vertex colour, and each write invalidates the
normals cache, so every vertex recomputed the normals of the whole mesh. Reading all normals first and writing
the attribute once makes the bake 2.6 s for 451,061 vertices (same weights). The earlier note that blamed the ray
cast was a guess.

**Budget (MEASURED, and not the ledger's 1.9 MB).** The sets are embedded in the app so they arrive by signed OTA
with rollback, and the app must fit one 3,145,728 B OTA slot. The G16J app was 1,970,176 B, so there never was
room for 1.9 MB of frames (that number is the size of the unused `assets` partition, which OTA does not write).

| | bytes |
|---|---|
| OTA slot (`partitions.csv`, ota_0 = ota_1) | 3,145,728 |
| signed app without frame sets (G21 code included) | 1,980,329 |
| reserve kept for code growth | 150,000 |
| **budget for frame sets** (`pack_frames.py default_budget()`) | **1,015,399** |
| shipped: Very good 27 frames 469,464 + Medium 27 frames 437,887 | 907,351 (89 %) |
| signed app, build `20261118-023215-26731-sticks3` | 2,887,680 (91.8 % of the slot, 258,048 free) |

Frames average 17.4 KB (Very good) and 16.2 KB (Medium), so the budget holds about 60 frames: two moods at
9 x 3, or five moods at 4 x 3. Getting the ledger's five moods at 7 x 3 (about 1.75 MB) needs a decision that is
the owner's: larger OTA slots (drop the unused `assets` partition; one USB flash of a new partition table), or
frames kept in `assets` with an update path for it. Good, Bad and Horrible have no 3D set today and show their
2D portraits.

**On the stick** (`adapters/companion/head3d.*`, `inflate.*`, `choose_head` in `screens.cpp`):

- The motion model's yaw and pitch pick the frame, each axis on its own, with hysteresis: a frame changes only
  once the angle is past the boundary to its neighbour by `head.hyst` (default 0.2) of the gap, so a stick held
  on a boundary does not flip between two frames. Outside the grid the end frame is held. Pitch is an absolute
  held angle; yaw comes from the gyroscope and eases back to the front in about 1.5 s (`motion.yaw_return`),
  because there is no absolute yaw reference.
- One frame is inflated when the chosen frame changes (at most one per drawn frame), into the buffer that is not
  shown; the two buffers swap only when the frame is whole and its adler32 matches. Going back to the previous
  frame costs nothing (it is still in the other buffer).
- The chosen frame is just the art: the G16I upright rotation, breathing, the amber glance and the snow-globe
  burst read it like a 2D portrait. A running burst keeps the frame it was made from until it lands.
- Only a fresh rated face uses it. An ALERT pulse, the NoData silhouette, the dim view and every other screen
  keep their 2D art. A rating without a set, a set whose pack is refused at boot, a frame that fails to inflate
  or fails its check (the whole set is then dropped until reboot), no PSRAM, or `head.on = 0`: the 2D portrait.
- Snap, not cross-fade (host measurement, `render_bench` line `3d-cost`, -O2): a fade would add a blend of two
  whole frames and a forced re-warp to every frame while it fades, and 43,200 B more PSRAM; a snap costs one
  inflate (about three warps on the host) on the frame that changes, nothing otherwise. Two neighbouring frames
  differ in 12,239 of 21,600 pixels (mean 18 of 255), which a fade would show as two heads at once.
- The inflater is this project's own bounded one (RFC 1951, `inflate.cpp`), not the ROM's `tinfl_decompress`:
  the same source runs in the host checks, so every shipped frame is proven byte-exact on the host; ROM code
  cannot run there. It never reads or writes outside its buffers and never allocates.

**Memory** (measured at build; heap on the device is the owner's to read): PSRAM 2 x 43,200 B frame buffers +
the head object (inflater tables; `head_ram_bytes` in STATUS), allocated once at boot, never freed, no internal
fallback. Static DIRAM 154,251 B (+40 B against the G16J image), IRAM unchanged, flash code +7,412 B.

**Console.** TUNE keys (4 new, registry 109 of 112): `head.on` 0..1 (default 0 since the owner's ruling of 2026-11-18: the 2D portrait shows; corrected by the G22 review), `head.yaw_gain` and
`head.pitch_gain` -2..2 (defaults 1 and -0.5; a negative value mirrors the axis, 0 keeps it in the middle),
`head.hyst` 0..0.45. The two default signs are worked out from the Blender and motion-model conventions and
have **not been seen on the glass**: if the head turns the wrong way, flip the sign. STATUS adds
`head=on|off|no_sets|none head_sets=<usable>/<embedded> head_frames= head_refused= head_at=<mood>:<yaw>,<pitch>
head_inflates= head_reuses= head_fail=<n>:<reason> head_ms=<avg>/<max> head_ram= head_ram_bytes=`
(`head_ms` = what choosing a new frame cost inside render, the inflate included). `FRAMES kind=rated` counts
these frames as before.

**Host evidence** (not device proof): `tests/inflate_check.cpp` (10 cases: zlib reference streams, the farthest
and overlapping matches, every truncation, output bounds, malformed blocks, 3,000 corrupted streams),
`tests/head3d_check.cpp` (16: pack parsing and refusals, hysteresis, held tilt with the real motion model,
fallbacks, failure handling, and **all 54 shipped frames inflated with the device's inflater and compared with
the manifest's sha256**), `tests/companion_check.cpp` (7 draw-rule cases), `tools/tests/test_face3d_pack.py`
(11), `boards/sticks3/tests/test_build_support.py` (7 new), and `render_bench` scenarios `rated-3d-rest` /
`rated-3d-turning` kept permanently. Red and green logs, the benchmark and the timing spikes:
`$GUARDIAN_STORE/builds/20261118-g21-tdd/`. Views and their contact sheets:
`art-exports/G21-3d/20261118-g21-views/`.

**Shipped artifact.** `build.sh build` now refuses to archive an image that does not hold every set the manifest
pins, byte for byte and exactly once (unsigned and signed image), a frames folder with a set the manifest does
not list, or a signed app larger than the OTA slot; `COMPLETE.json` records `head3d` (sets, sha256, offset in the
app, slot room). The image was not booted: that needs the stick.

**Not done here, for the owner on the stick (OTA):** the head turning with the stick at 20 fps or more
(`FRAMES kind=rated`, `head_ms`), no flicker at a grid boundary, `heap_internal_min` and `task_stack_free`,
which way yaw and pitch turn, the 30-minute USB soak across the five moods with detail visits and AP
disappearance, and the look of the art itself. No `evidence/sticks3-G21-*.log` exists until then.

**Known limits, left as they are:**
- The time of one inflate on the ESP32-S3 at 160 MHz is not measured. Estimate from the counted work per frame
  (about 9,700 literals, 3,100 matches, 43,200 bytes out): around 10 ms. If `head_ms` shows more than the frame
  can spare, the remedy is a coarser grid or the ROM inflater, not a guess now.
- Very good has no ember glow or smoke on the 3D head: the cigar tip is at another place in every frame and the
  pack does not carry it. The cigar itself is in the art.
- The 3D frames are lit up to columns 2..132 and rows 2..157; the upright fit (`persona::fit_scale`) uses the 2D
  hood box (130 x 157), so a head turned far on its side can lose a pixel or two at the band edge.
- Lit 3x3 blocks reach 1,566 (Medium) and 1,525 (Very good) of the burst's 1,600; a fuller render set would
  stop bursting. `pack_frames.py` prints the number.
- The dim view and the ALERT stare are the 2D portrait, so the face changes from the 3D frame to the 2D painting
  when the stick dims or an ALERT shows.
- The fill colour of surfaces the projector cannot paint is visibly teal on the Very good head (the render set's
  look, the owner's polish pass).

## G16M product setup from the phone (implemented 2026-11-18; ledger G16M: accepted 2026-11-19, the credential vault carried into G23)

Owner direction (2026-11-18): "I never set wifi password via stick, this is NOT a product if firmware needs hard
coding". Nothing was ever compiled in (the name and password were sent once over USB by `tools/ota_provision.py`),
but a product sets up with the phone alone. Status: **host-tested and built; nothing of this section has run on the
stick.** The portable part is `adapters/setup/` (`tests/setup_check.cpp`, 20 cases); the board part is
`boards/sticks3/main/setup_board.cpp` (access point, page, name service) and `cred_vault.cpp` (encrypted store).

**What the owner does.**

1. Open the device list, move to the home network, **hold SIDE for 3 s** (the list closes at 0.8 s as before; keep
   holding). With no Wi-Fi stored yet, **FRONT x3 fast** does the same for the watched network (with Wi-Fi stored it
   stays the UPDATE question).
2. The glass shows `SETUP`, the access point name `Guardian-xxxx` (last two bytes of the MAC) and its **one-time
   password** (10 characters since G23, 8 before; new for every session). Join it from the phone.
3. The phone opens one page (or open `http://192.168.4.1`). It names the network and asks **only its password**;
   "Advanced" holds one optional field, the update server on the Mac (see below).
4. The access point goes down, the glass says `CHECKING`, the stick joins the home network once (up to 20 s).
   Joined: the credential is stored and the glass says `SAVED`. Not joined: `NOT SAVED` with the reason (password
   not accepted / network not in range / could not join), and nothing changed. Then passive listening resumes
   ("Listening again.").

The access point lives at most 5 minutes, any key cancels it, and the gesture is refused while an ALERT is shown or
while the UPDATE question, an update, a TUNE session or a console measurement is running. The stick transmits only
inside this owner-started session (access point beacons, then one join).

**Facts that differ from the ledger text** (both read from the pinned ESP-IDF `67c1de1e` source, not assumed):

- `components/wifi_provisioning` has **no browser page**. Its SoftAP scheme serves protobuf endpoints for
  Espressif's phone app (no file in the component contains HTML or a captive handler). "Phone only, no app" needs
  `esp_http_server` plus a name service that answers every lookup with the stick's address, as in ESP-IDF's
  `examples/protocols/http_server/captive_portal`. That is what is built; `wifi_provisioning` is not used. The page,
  the form parser and the name-service answer are our own code, host-tested (`setup_check`).
- **NVS encryption on the ESP32-S3 without flash encryption needs one eFuse key.** `CONFIG_NVS_ENCRYPTION` depends on
  `SECURE_FLASH_ENC_ENABLED || SOC_HMAC_SUPPORTED`; the `nvs_keys`-partition scheme depends on flash encryption, so
  the only scheme left is the HMAC one, whose key lives in an eFuse block (irreversible). G16B was built on "no
  eFuse is burned", so this is an **owner decision**, see "Credential vault" below. Until it is taken the phone setup
  works and stores the credential as before (plain), and says so on the glass and in STATUS.

**Decisions taken here (for the supervisor to confirm or change).**

- The access point is **WPA2/WPA3 with a one-time password on the glass**, not open: on an open access point the
  home password would cross the air in clear. Phones with WPA3 use SAE (no offline guessing of the password);
  a WPA2-only phone leaves a handshake that could be attacked offline later, and the page it protects carries the
  home password. So since G23 the password is 10 characters of 29 symbols: 48.6 bits (min-entropy 48.3 with the
  byte-to-symbol mapping), against 38.9 bits for the 8 characters before. Host-tested; not yet seen on the glass.
- **The password is checked before it is stored** (one join). A password that does not join is never saved, so a
  typing mistake cannot replace a working credential.
- **The update server URL is optional on the page** ("Advanced"). The page asks only the password; an existing URL
  is kept. A stick wiped with `OTA CLEAR` has no URL, so after a phone setup it reports `wifi_provisioned=yes
  ota_provisioned=no` and the glass says "No update server yet" until the URL is typed under Advanced (or sent with
  `tools/ota_provision.py`). The ledger's device step "STATUS ota_provisioned=yes from a wiped credential" therefore
  needs the URL typed once on the page. Finding the Mac by itself (mDNS) would need the `mdns` managed component and
  a change in `tools/ota_serve.py`; not done.
- **Which network.** SIDE-hold takes the list row under the cursor when the press begins. A row other than the
  watched network is treated as protected (the list does not carry its settings), so an open network is set up by
  selecting it first.

**STATUS** (appended to `G14 STATUS`; no value ever appears): `setup=idle|open|checking|saved|failed|notice`,
`setup_count` (access points opened), `setup_saved`, `setup_refused` (gesture refused: ALERT or busy), `setup_last`
(`none|saved|timeout|key|alert|password|not_found|join_failed|store_failed|access_point`), `setup_pages`,
`setup_form_refused`, `setup_ap_error`, `wifi_provisioned`, `cred_store=plain|encrypted|error`,
`cred_vault=ready|no_partition|no_key|scheme_failed|key_derivation_failed|open_failed`, `cred_migrated`,
`cred_plain_cleared`. Console lines: `G16M CRED ...` at boot, `G16M SETUP request ...`, `G16M SETUP state=...`.

### Credential vault (owner decision and one USB sitting)

The credential record (`otacfg`: name, password, server URL) moves into its own partition `nvs_cred`
(0x12000, 16 KiB, in the gap that was unused between `otadata` and `ota_0`; nothing else moves) opened with NVS
encryption. The XTS keys are derived at boot by the HMAC peripheral from a key in eFuse block `KEY0`
(`CONFIG_GUARDIAN_CRED_HMAC_KEY_ID`). The default `nvs` partition is not encrypted and not touched, so the
selection, TUNE values, boot counter and update record stay readable by every earlier image and an update rollback
loses nothing (encrypting the default partition would make a rollback to a pre-G16M image lose all of them).

**The firmware never generates or burns the key.** It checks the block's purpose first and only derives
(`nvs_flash_read_security_cfg_v2`). Checked in the archived ELF `20261118-134815-29451-sticks3` with `nm`:
`nvs_flash_generate_keys_v2` and `nvs_flash_generate_keys` are not linked. ESP-IDF's static `generate_keys_hmac`
(the function that would burn) is linked, because registering the HMAC scheme stores its address, but its only
callers are those two absent functions, so nothing in the image can reach it. Without the partition or the key: `cred_vault=no_partition|no_key`, `cred_store=plain`, everything works as
before. A vault that exists but cannot be opened is `cred_store=error`: nothing is stored anywhere and nothing is
erased, until the owner repairs it.

What the eFuse key costs and gives: one of six key blocks, forever; flashing, download mode and updates are
unchanged. A flash dump (`esptool read_flash`) no longer contains the password. It does **not** stop someone who
holds the stick and flashes their own firmware (no secure boot), because that firmware can ask the HMAC peripheral
for the same keys. Closing that needs secure boot, a separate and much larger decision.

One sitting over USB, by the owner (none of these commands was run by the worker; the key file is a secret like the
signing key and stays on the Mac, outside the repository and the store):

```sh
P=~/.espressif/python_env/idf5.4_py3.10_env/bin/python; PORT=/dev/cu.usbmodemXXXX; K=~/.config/m5-guardian
# 0. fresh verified backup of the whole flash first (firmware/README.md "Current physical unit and recovery")
# 1. the HMAC key and the NVS keys derived from it (vendor tool; writes keys/hmac_key.bin + keys/nvs_keys.bin)
(umask 077; $P -m esp_idf_nvs_partition_gen generate-key --key_protect_hmac --kp_hmac_keygen \
   --kp_hmac_keyfile hmac_key.bin --keyfile nvs_keys.bin --outdir $K/vault)
# 2. the gap may hold bytes of an older firmware: erase exactly the new partition, then write the new table
$P -m esptool --chip esp32s3 --port $PORT erase_region 0x12000 0x4000
$P -m esptool --chip esp32s3 --port $PORT write_flash 0x8000 <archive>/partition_table/partition-table.bin
# 3. IRREVERSIBLE: burn the key into KEY0 with the HMAC purpose (espefuse asks to type BURN)
$P -m espefuse --chip esp32s3 --port $PORT burn_key BLOCK_KEY0 $K/vault/keys/hmac_key.bin HMAC_UP
```

At the next boot `G16M CRED store=encrypted vault=ready migrated=1 plain_cleared=1` (a stored plain credential is
copied into the vault, read back, and the plain record is overwritten with the empty record).

**Left in the old partition.** NVS marks a replaced blob erased but does not overwrite its bytes
(`nvs_page.cpp`, `eraseEntryAndSpan` only changes the entry state), so the password sent over USB on 2026-11-16 can
still be read in a raw dump of `nvs` (0x9000) until that page is recycled. Removing it for certain means erasing
`nvs` (`erase_region 0x9000 0x6000`: the selection, TUNE values and counters are lost and must be set again) or
changing the Wi-Fi password. Not done by the firmware: it would put the owner's tuned values at risk on every boot.

**Reviewer check on the device** (ledger: "NVS read back with the encryption key shows the credential only through
the API"). The host round trip of these vendor commands with throwaway keys is recorded in
`evidence-raw/G16M-setup-tdd-20261118/vault-tool-spike/spike.log` (the tool's keys equal HMAC-SHA256 of the
firmware's two seeds); the same on a real dump is not yet run:

```sh
$P -m esptool --chip esp32s3 --port $PORT read_flash 0x12000 0x4000 nvs_cred.bin
grep -a -c '<the home password>' nvs_cred.bin                      # expected 0
$P -m esp_idf_nvs_partition_gen decrypt nvs_cred.bin $K/vault/keys/nvs_keys.bin nvs_cred.dec.bin
$P ~/esp/esp-idf/components/nvs_flash/nvs_partition_tool/nvs_tool.py nvs_cred.dec.bin -d minimal   # guardian:otacfg
```

**Honest limits.**

- Nothing here ran on the stick: the access point, WPA3 with real phones, the captive sheet of iOS and Android, the
  20 s join, the reason codes behind "password not accepted", the vault and the migration are all unproven.
- The page is plain HTTP inside the WPA-protected access point; anyone who knows the one-time password during those
  minutes could read or submit the form.
- Passwords are 8..63 printable ASCII characters (the G16B rule); a 64-hex PSK or non-ASCII password is refused.
- While the access point is up and during the check, the Guardian is not listening (the glass says so).

## G16Q art bench (part 1 on the stick 2026-11-18, owner picked D; part 2 2026-11-19; ledger G16Q: accepted 2026-11-19, the ALERT eyes carried into G23)

Owner (2026-11-18): the approved set is the v4 pack; "THIS IS THE DESIRED RESOLUTION, our stick MUST look like it,
which it isn't"; a separate firmware to advance the art is allowed, then it comes to the Guardian. The face band is
135x160 pixels and the master 512x512: no firmware makes 135 px equal 512 px. What can change is every step between
the master and the glass, and none of them was tuned. The bench puts one candidate per step on the real glass so the
owner picks. Plan and code facts: `firmware/evidence/G16Q-plan-artbench-20261118.md`.

**Candidates** (`tools/art/candidates.py`, frames in `firmware/art/bench/`, 135x240 little-endian RGB565, 64,800 B
each, pinned by sha256 in `manifest.json`), for Very good, Horrible and Medium:

| | what changes | frame |
|---|---|---|
| A | today's pipeline: crop (40,0,472,512), LANCZOS on sRGB codes, unsharp 1.0/90/2, rounded to 565 | `A_<Mood>`: its face band is the shipped portrait byte for byte |
| B | the resize in linear light (sRGB decoded, premultiplied alpha, LANCZOS, encoded), no unsharp | `B_<Mood>` |
| C | B + unsharp 0.6/120/1 | `C_<Mood>` |
| D | C + Floyd-Steinberg dither to 565 instead of rounding | `D_<Mood>` |
| E | D's steps over all 240 rows: master crop (112,0,400,512), no HUD room | `E_<Mood>` |
| F | D + the ST7789 gamma table (0xE0/0xE1, the M5GFX values) | D's frame |
| G | F at 100 % backlight | D's frame |
| H | D through the Guardian's own portrait painter: `H-still` (breath 0, the exact pixels) and `H-breath` (default breath 0.008: a bilinear resample on every frame, what the Guardian shows today) | D's frame |
| ramp | five grey bands, 0/25/50/75/100 % top to bottom (565 words 0x0000 0x4208 0x8410 0xBDF7 0xFFFF), without and with the gamma table (`ramp`, `ramp-gamma`) | `ramp` |

A to D hold the 135x160 portrait in rows 20..179 (the Guardian's face zone) on black. E cuts the hood's sides:
MEASURED on the three masters, 62 to 65 master px each side = about 30 glass px each side (the plan's "48 px" was an
estimate; the geometry is forced by 135:240 at full height).

**Commands** (repository root; the owner launches the serve step):

```sh
python3 tools/art/candidates.py build $GUARDIAN_STORE/art-exports/G15/20261117-v4/masters_png \
    --previews $GUARDIAN_STORE/art-exports/G16Q/<date>-candidates     # rebuild: same sha256 or the test fails
python3 tools/art/candidates.py verify                    # frames on disk = manifest.json
python3 tools/tests/test_art_candidates.py                # 20 tests; two read the masters in the store and fail without it
firmware/boards/sticks3/tools/build.sh build-art-bench    # sdkconfig.art-bench, version suffix -bench, own build dir and archive
tools/ota_serve.py $GUARDIAN_STORE/builds/<stamp>-sticks3-bench     # announces [ART BENCH IMAGE]; the stick fetches it by itself
```

**On the stick** (`CONFIG_GUARDIAN_ART_BENCH`; logic in `boards/sticks3/main/art_bench.{hpp,cpp}`, SDK-free, tested by
`tests/art_bench_check.cpp`): boots into the bench, one candidate at a time, 29 entries: A B C D E F G H-still H-breath
for Very good, then Horrible, then Medium, then `ramp` and `ramp-gamma`.
- **FRONT** = next candidate. **SIDE** = backlight 60 → 80 → 100 → 60 %. A new candidate starts at its own
  backlight (60 %, G 100 %).
- A label (candidate, mood, backlight, position) shows in the bottom rows 196..239 for 2 s after every change, then
  the exact frame. Photograph after the label is gone.
- `STATUS` ends with `bench=<name> bench_index=<n>/29 bench_bl=<pct> bench_gamma=<0|1> bench_motion=<exact|still|breath>
  bench_frames=<ok|missing> bench_gamma_errors=<n>`. Names: `A-VeryGood` … `G-Medium`, `H-still-<Mood>`,
  `H-breath-<Mood>`, `ramp`, `ramp-gamma`.
- USB console: `BENCH` (state), `BENCH NEXT`, `BENCH PREV`, `BENCH GO <name>`, `BENCH BL <60|80|100>`, `BENCH LIST`.
  Every change prints `G16Q BENCH candidate|backlight …`. TUNE, BATTRUN, RESTART and the provisioning commands work
  as in the Guardian; the lab verbs that capture (`select`, `start`, `listen`) are refused.
- The gamma table is sent when a candidate with `bench_gamma=1` is entered. Leaving it is a panel hardware reset plus
  the normal setup (the only certain way back to the panel's own gamma: the SPI link is write-only), with the
  backlight off for that moment.

**What stays as in the Guardian:** the signed image, the boot self-test and rollback, and the self-fetch poll
(`ota.auto_s`, default 120 s: the update screen shows for the seconds each check takes, then the candidate returns).
Serving a normal archive brings the Guardian back the same way.

**What the bench image does not do:** it never captures (the Wi-Fi driver is started for the poll only; promiscuous
listening is never switched on, STATUS shows `radio=0` (Off), and the self-test's radio criterion is "driver up"); it has
no idle policy (never dims or sleeps: keep it on USB); it has no 3D head frame sets (the OTA slot has 258,048 B free
with them and the 16 frames need 1,036,800 B; MEASURED bench image 2,953,216 B signed, 192,512 B free); it takes no
TUNE session over Wi-Fi and has no key gesture for UPDATE (the keys are the bench's).

**Recording the pick** (part 2 starts from it): `firmware/evidence/sticks3-G16Q-artbench-<date>.log` with the image
version, one line per candidate (`<name> bl=<pct> verdict=<owner's words>`), the camera sheets' paths and sha256, and
the pick. Reference images for the sheets (what each frame holds, and the master crops) are written by `--previews`.

**Not proven (nothing here ran on the device):** the bench has never booted on the stick; the keys, the label, the
gamma commands and the panel reset path are exercised by host tests and a build only. What the gamma table does on
this glass is unknown: the values are a source observation from M5GFX, which also sets panel voltages (VCOMS 0x28,
VRHS 0x10, VDVSET 0x20, GCTRL 0x35, PWCTRL1) that the stock ESP-IDF init and this bench leave at their reset values, so
F and G are "this table at default voltages", not "the M5GFX look". No tool compares a camera frame with a render yet.
The frames are pinned for Pillow 11.3.0 and numpy 1.26.4 (recorded in the manifest).

**The pick (owner on the glass, 2026-11-18):** D, "its the difuser. perfect" (all 27 portrait entries "perfect"; the
two gradient images are the grey ramps). Record: `firmware/evidence/sticks3-G16Q-artbench-20261118.log`. Not chosen:
E (full height), F/G (gamma table, 100 % backlight), H still (the breathing stays).

**Part 2 (supervisor, 2026-11-19):** `art/persona/v2/build_assets.py portraits` renders every rated and ALERT portrait
as candidate D through `tools/art/candidates.py`'s own functions (`portrait_565`: linear-light LANCZOS with premultiplied
alpha = the black matte, unsharp 0.6/120/1, Floyd-Steinberg to RGB565); the no-data silhouette is flat colour and keeps
its rounding (bytes unchanged). The panel init, gamma, backlight and `persona.breath` are unchanged. Pins: the art
manifest, `persona_check` (Very good sha256), and `tools/tests/test_art_candidates.py`, which now proves candidate D's
face band equals the shipped portraits byte for byte (A stays the pre-G16Q bench reference). Measured consequence: the
linear-light resize keeps more light on the anti-aliased right rim, so the hood box is re-measured to columns 1..133
(`persona::hood_w` 133, was 130; `fit_scale(45°)` 0.654, was 0.663) and Good's detached specks under the chin are 10 on
rows 157..159 (was 6). Evidence: `$GUARDIAN_STORE/builds/20261119-g16q-part2/` (red and green logs).

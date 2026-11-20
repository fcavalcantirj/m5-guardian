# StickS3 identity, installed firmware and recovery route (2026-11-13)

Rediscovered live, not assumed. All reads were non-destructive (esptool `flash_id` and `read_flash`); nothing was written to the board.

## USB identity (ioreg, 21:33 local)

| Field | Value |
|---|---|
| Product | Espressif "USB JTAG_serial debug unit" |
| idVendor / idProduct | 0x303A / 0x1001 (12346 / 4097) |
| USB serial | `LAB-BRUCE-STICK` (matches the unit last observed) |
| Port today | `/dev/cu.usbmodem101` (location based, was `usbmodem1101` on 2026-08-05) |
| Other serial ports present | Bluetooth, two speakers; no other ESP device was attached |

## Chip and flash (esptool v4.12.0 `flash_id`, log: `device-flash-id-20261113.log`)

ESP32-S3-PICO-1 (LGA56) revision v0.2, features WiFi + BLE, embedded 8 MB GD flash (manufacturer c8, device 4017), embedded 8 MB PSRAM (AP_3v3), crystal 40 MHz, USB mode USB-Serial/JTAG, MAC `LAB-BRUCE-STICK`. eFuse: flash type quad, flash voltage 3.3 V. The PSRAM label says AP_3v3 but the board only works in octal mode (measured 2026-08-05).

## Full flash backup (restoration route)

| Item | Value |
|---|---|
| File | `$GUARDIAN_STORE/device-backups/LAB-BRUCE-STICK-20261113/flash-full-8MB.bin` |
| Size | 8,388,608 bytes, read in 733.9 s over USB-JTAG |
| sha256 | `c6de1ad11aa1da226d0022ef654d9a49e4ed5b8dcc60c89a5179d8944d2b91e8` |
| Restore | `python -m esptool --port <port> --chip esp32s3 write_flash 0x0 flash-full-8MB.bin` (then press the side key once if the chip stays in download mode) |

The esptool log is `read_flash.log` next to the image. The write-back has **not** been tested; the image is a byte-exact copy, so it restores Launcher, Bruce, NVS and the LittleFS captures together.

## Installed firmware found in the backup

Partition table at 0x8000 (parsed from the dump):

| Name | Type | Offset | Size | Content found |
|---|---|---|---|---|
| nvs | data/nvs | 0x9000 | 0x4000 | |
| otadata | data/ota | 0xd000 | 0x2000 | |
| phy_init | data/phy | 0xf000 | 0x1000 | |
| app0 | app/ota_0 | 0x10000 | 0x160000 | M5 **Launcher** (strings "Press the button to enter the Launcher!", "LauncherHub"); app descriptor project `arduino-lib-builder`, IDF `v5.5.4-dirty`, built Jul 31 2026 |
| coredump | data/coredump | 0x170000 | 0x10000 | |
| bruces | app/ota_1 | 0x180000 | 0x490000 | **Bruce**, build string "Bruce StickS3 (BETA)", PlatformIO env `m5stack-sticks3`; descriptor `arduino-lib-builder`, IDF `v5.5.4-dirty`, built Aug 26 2026. A version literal `1.10.3` sits near Bruce settings keys; it is the likely Bruce version but is **not confirmed** from the device UI |
| spiffs | data/spiffs (0x82) | 0x610000 | 0x1f0000 | actually a **LittleFS** image (mounted with littlefs-python 0.19.0, lfs 2.11, block 4096) |

Bruce's serial banner was not used: a 4-second passive listen on the port produced no bytes, and no command was sent to Bruce.

## Bruce captures exported

Extracted from the LittleFS partition image, not over Bruce's serial or web UI:

| Path on device | Size | sha256 | Where |
|---|---|---|---|
| `/BrucePCAP/handshakes/HS_OWNER-AP-1_OWNER-NETWORK.pcap` | 1,025 bytes, pcap magic d4c3b2a1, linktype 105 (802.11) | `9a1c269716f6ca40f239d3462af15ba7003f747f14ed82559762be709ea913ce` | `$GUARDIAN_STORE/device-backups/LAB-BRUCE-STICK-20261113/fs-spiffs/BrucePCAP/handshakes/` |
| `/bruce.conf` | 1,576 bytes | in `dump-report.json` | same directory; **may hold Wi-Fi credentials, stays in the store only** |
| `/brucePins.conf` | 1,719 bytes | in `dump-report.json` | same directory |

Machine-readable record: `$GUARDIAN_STORE/device-backups/LAB-BRUCE-STICK-20261113/dump-report.json` (partition table, app descriptors, file list with hashes). The extraction script used was a throwaway at `/tmp/guardian-tools/inspect_dump.py` run with `python -I` against the dump; re-create from this description if needed.

## Not done in this lane

- No Guardian image was flashed; the board still runs Launcher + Bruce.
- The hard reset after `read_flash` was esptool's RTS reset. Whether Bruce resumed on screen was not observed (no camera in this lane). If the screen is dark, press the side key once.

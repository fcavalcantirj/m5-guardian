# G16K: the 5 GHz + BLE eye — an ESP32-C5 Guardian node with the phone as its screen

Owner (2026-11-18): "m5guardian sticks3 plus droidputer with any c5 board via usb otg using app, so guardian also has
5 GHz ... this is a defense system, should be complete. also include BLE at defense. spike tomorrow with droidputer and
esp via usb otg."

## Why
The StickS3 radio is 2.4 GHz only and the owner's router is dual band: every 5 GHz attack is invisible
([attack-coverage.md](attack-coverage.md), rows 20-21). BLE floods are blind too, because BLE scanning on the stick
costs 2.4 GHz capture time (G16H deferred). A second node with a dual-band radio takes both blind spots off the stick.

## Design (approved 2026-11-18)
The C5 is a **second Guardian node running the same portable library**, watching the selected network's 5 GHz BSS
(same name, different BSSID) and BLE, with the **Android phone as its screen** through Droidputer's existing USB OTG
protocol. The stick is untouched. Two independent eyes; a later, spike-gated G16L may let the stick show the
companion's 5 GHz incident ("5 GHz: companion sees X").

- Board adapter `firmware/boards/c5/` on its own pinned ESP-IDF (the stick's pin stays 67c1de1 / v5.4).
- Output adapter: a **DP frame writer** over native USB-Serial/JTAG. Droidputer's wire protocol
  (`~/dev/droidputter/docs/PROTOCOL.md:14-29`): `D7 50 | type u8 | len u16 LE | payload | crc8(poly 0x07 over type,
  length, payload)`; ESP→phone HELLO 0x01 (55 B board/app strings), FILL 0x02, RECT 0x03, RECT_RLE 0x04, STATS 0x05,
  PING 0x06, LOG 0x07; phone→ESP KEY 0x81, GPS 0x82, PING_IN 0x83, HELLO_ACK 0x84. The phone sends PING_IN once a
  second until HELLO and starts mirroring on HELLO_ACK; it decodes 0x01-0x05 today, so a board that writes those frames
  gets the phone as a screen with no app change. KEY frames map to FRONT/SIDE.
- BLE on the C5 (moves G16H off the stick): research step first (open-source BLE-spam detectors, behaviour only), then
  detectors behind the measured coexistence number.
- Honesty: the stick's Details keeps "2.4 GHz only"; the phone screen says "5 GHz (C5 node)"; the coverage matrix gains
  a band column.

## Facts (read 2026-11-18)
- Owner's board: ESP32-C5-DevKitC-1 rev 1.2, 8 MB flash, **no PSRAM**, dual band (`~/dev/wifi-lab/LAB-INVENTORY.md:10`;
  earlier a Marauder boot-loop and an ESPHome test image; current firmware unknown).
- Installed ESP-IDF v5.4 (`~/esp/esp-idf`) has the band API (`wifi_band_mode_t` 2G_ONLY / 5G_ONLY / AUTO,
  `components/esp_wifi/include/esp_wifi_types_generic.h:378-388`) but lists esp32c5 as a **preview** target
  (`tools/idf_py_actions/constants.py:37`). The C5 needs its own pinned checkout (5.5 line, to verify).
- Droidputer (`~/dev/droidputter`): USB host via usb-serial-for-android, matches VID 0x303A, native USB-Serial/JTAG
  only; **it opened this C5 on 2026-09-16** (`progress.txt:220`). One device at a time, no relay, link lives with the
  activity; flasher and shim are S3-only (irrelevant here: the C5 writes the frames itself).
- Guardian boundary (all cites under `firmware/`): adapter = `FrameSource` (`components/guardian_core/include/guardian/radio.hpp:163-175`),
  `MonotonicClock` (`time.hpp:60-64`), `BoardCapabilities` with `Band::Ghz5` and channels to 177 already
  (`capabilities.hpp:23-26,126-137`), `BlobStorage` (`adapters/companion/blob.hpp:10-15`), `StatusOutput`
  (`guardian_presenter/include/guardian/output.hpp:12`). `adapters/measurement` (Monitor + detectors) is SDK-free and
  reusable; `tune`, `ota`, `power` too; `nvs_blob`, `ota_board`, `tune_link` are reusable on any ESP-IDF chip.
  **2.4 GHz hard-coding to widen:** `adapters/measurement/measurement.cpp:11` (channels 1..13), `:70` (`Band::Ghz2_4`),
  `:122` (14-channel survey) and `measurement.hpp:44`; `boards/sticks3/main/measurement_radio.cpp:26-28` and
  `current_band()`; `measurement_main.cpp:1023` (`profiles::all_2g4_channels()`). Nothing in production builds a
  `BoardCapabilities` yet (examples and tests only). `tools/qualify-targets.sh` accepts host, esp32s3, esp32c3 only.
- Stick inputs: no console verb injects observations (`measurement_main.cpp:664-711`); the Wi-Fi links are pull-only
  HTTP to the Mac and pause monitoring; the incident record has no band or sensor field, Core rejects foreign origins
  and clock epochs (`core.cpp:129-148,160-190`), Area slots are keyed by family only. That is the G16L work, not G16K.

## Spike (tomorrow, the owner's hands; sessions prepare; every result recorded in firmware/evidence/c5-spike-<n>-<date>.log)
| # | what | GO |
|---|---|---|
| S-1 | second IDF checkout pinned for the C5 (record the commit), `idf.py set-target esp32c5`, the IDF `scan` example with band mode 5G_ONLY | the router's 5 GHz BSS listed (name, BSSID, channel, RSSI) |
| S-2 | the stick's acquisition path built for the C5 target, management frames on the router's 5 GHz channel for 60 s | beacons counted, 0 drops; frames/s and free heap recorded (no PSRAM: the Monitor tables must fit) |
| S-3 | a ~200-line IDF test program on the C5 writes HELLO + FILL + RECT_RLE frames over USB-Serial/JTAG; the phone runs Droidputer over OTG | pixels on the phone, HELLO_ACK and KEY frames back; sustained frame rate at 135x240 recorded |
| S-4 | BLE scan duty 0 / 25 / 50 % while S-2 runs | beacon loss per duty recorded; the owner picks the acceptable number |

NO-GO on S-1 or S-2 means the C5 node is not built and this page records why.

## After the spike
Ledger row **G16K** (placed by the owner once the numbers exist): `boards/c5` adapter, the DP writer as a portable
output adapter host-tested byte-exact against PROTOCOL.md fixtures, 5 GHz acquisition on the same library, STATUS over
the same USB console, signed OTA for the C5 with the same tools, BLE research + detectors behind the coexistence
number, coverage matrix band column, phone screenshots as evidence. Candidate **G16L**: the companion's observation
shown on the stick (passive receive; the stick never transmits; whether the companion may transmit is the owner's
call after its own spike).

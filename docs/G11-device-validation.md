# G11 physical StickS3 bring-up evidence

Measured on 2026-11-14, owner-approved **LAB-STICK-1**. This is the native
bring-up app, not completed radio/UI integration or final art. G11 is accepted for this measured bring-up scope after G10 source review closed.

## Identity and recovery

ESP32-S3-PICO-1 rev 0.2, 8 MB flash/8 MB PSRAM. Original app: M5AccessibilityS3
Head Pointer. Full 8 MB original flash is archived and esptool verified it against
the device before replacement. Backup:
`$GUARDIAN_STORE/device-backups/LAB-STICK-1-20261114-220350/`.
SHA-256 `acccb5b9711c456b833eac402216c97c1b15a9e573570abe3e14e65697753dca`.
The older LAB-BRUCE-STICK backup is retained and belongs to another unit.
No other board was flashed or opened during this bring-up.

## Actual observations

| Check | Evidence and result |
|---|---|
| Same portable library on chip | Separate RF-off probe: 10 checks, zero failures, explicit Imported origin |
| Native boot | ESP-IDF v5.4, bringup-0.3; repeat boot logs |
| Flash/PSRAM | 8,388,608 bytes each; 256 KiB PSRAM write/read pattern passed |
| PM1 | Four-byte response 0x4f052050, checked configuration succeeds; profile owner-selected |
| Display | Upright 240×135 landscape, full border, advancing uptime; owner videos |
| Colour repair | First BGR trial swapped R/B. RGB setting corrects channel mapping in second video; no calibrated colour claim |
| Transfer ownership | Repeated completed callbacks; same transfer guard passes submission/timeout host fault checks |
| Physical front button | USB events GPIO11 counts 1, 2, 3; final video shows 2→3 on press |
| Physical side button | USB event GPIO12 count 1; same final video shows side x1 |
| Storage | Checked NVS commit; boot count 1→2→3 across reflash/reset and monitor reconnect |
| No SD/Pi dependency | Standalone app boots and refreshes without either; USB supplies power/console |

A USB_UART_CHIP_RESET occurred when the console was reattached. It booted normally
and preserved NVS (boot 3). This is observed reconnect behavior, not a power-loss
stress test. No power-switch/battery endurance or exhaustive flash-fault test is
claimed. The 5056 KiB assets partition is reserved, not a mounted asset filesystem.

## Evidence locations

the store original before media/logs: `evidence-raw/sticks3-20261114-220919/`.
Corrected screen and button originals/logs: `evidence-raw/sticks3-20261114-221640/`.
Each owner video has a SHA-256 record; source media is preserved unedited.
[Frame from corrected video](../firmware/evidence/sticks3-LAB-STICK-1-20261114.jpg)
[boot console](../firmware/evidence/sticks3-LAB-STICK-1-20261114.log), and
[button event excerpt](../firmware/evidence/sticks3-LAB-STICK-1-buttons-20261114.log).

Flashed images: `builds/20261114-221430-65455-sticks3/`; later corrected tooling
archive `builds/20261114-222028-80323-sticks3/` has byte-identical application,
bootloader and partition-table images. All 20 final archive hashes verified.
The source/build repairs and independent findings are recorded in
[G10 validation](G10-validation.md).

## Limits and next step

The device is left running Guardian bringup-0.3. The original head-pointer image
is preserved, not restored. Its full-image restore route is documented but has
not been exercised. The display deliberately shows Unknown/checking: no live
radio adapter is integrated yet. The portable library's earlier host RF evidence
and on-chip Imported probe do not turn this screen into a live detector.

Next is G12 target-profile qualification, then G13 actual receive-to-library-to-screen
integration and repeated controlled live validation, then G14 picker/persistence.
The five original art/mood tasks remain later, unimplemented work.

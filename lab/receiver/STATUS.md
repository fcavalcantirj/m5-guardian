# Current receiver status — accepted 2026-11-14

Cardputer acquisition-only receiver 1.2 supplied real frames to the actual host
library in all ten accepted live checks. Cable reconnection was completed and
verified. Reception is now off; the Pi native emitter/AP is also off and unarmed.
Both original flash backups were rehashed successfully. The boards retain lab
firmware, not restored Bruce. No further RF was run in this validation session. Later owner-authorized StickS3
bring-up is recorded below and in docs/G11-device-validation.md.
See [accepted evidence and limits](../../docs/L02-live-validation.md).

## Historical preparation record (superseded where stated above)

# Receiver preparation status — 2026-11-14

Owner authorized the Pi-connected ESP32-WROOM for the lab and dedicated the
Cardputer ADV as receiver. Test AP will be a phone hotspot, currently off.
No test transmissions, network association or offensive scenarios ran.

## Hardware identities and backups

- Cardputer ADV: native USB serial/MAC `LAB-CARDPUTER`, ESP32-S3 revision
  v0.2, embedded 8 MB GD flash. Startup firmware identified Cardputer ADV;
  Bruce version was not confirmed via `info`. Full original image:
  `$GUARDIAN_STORE/device-backups/LAB-CARDPUTER-20261114/flash-full-8MB.bin`.
  SHA-256 `96dd01501bb0115b1b0b694477a22d81e8eab374612ae81e8eaf32f41f6bbe10`.
  This preserves internal captures/configuration; it is not a separate filesystem
  export. No SD was mounted in the observed Bruce startup. Receiver firmware is
  now installed on this board; USB serial remains the same. The display/keyboard
  are not initialized by this acquisition-only image.
- Excluded StickS3/head pointer: serial `LAB-STICK-1`; no port opens, resets or
  writes were performed on it. All Cardputer ROM/flash operations checked the
  Cardputer serial explicitly. Do not identify a board by shared VID/PID alone.
- Pi `LAB-PI-HOST`, CP2102 `/dev/ttyUSB0`: ESP32-D0WD-V3 revision 3.1,
  MAC `LAB-PI-EMITTER-STA`, 4 MB flash. ROM chip identification reports 40 MHz;
  one already-running-stub reconnect misreported the crystal, so it is not used
  as a hardware fact. Full backup:
  `$GUARDIAN_STORE/device-backups/LAB-PI-EMITTER-STA-20261114/flash-full-4MB.bin`.
  SHA-256 `256a11d57e60bac62efe80edd9f9905721271f4b4d08916952f3d871cec7cf08`.
  Embedded app descriptor: arduino-lib-builder, version ee57070, IDF v5.5.5.
  The image contains the custom `commands: scan | deauth` banner. Neither
  AntiHunter nor nRF24 firmware markers were found; absence of strings is not
  exhaustive proof of all behavior. Owner identifies this as the board wired to
  the nRF24. Current source-to-installed-image equivalence is unverified.
  Original flash unchanged; left in bootloader after backup, not running the
  emitter application. Six brownout messages were observed in a four-second
  passive read before bootloader entry. A 460800-baud read lost serial data;
  the final complete 115200-baud read succeeded in 374.5 seconds. Bootloader
  stability does not prove radio-power stability. No emitter qualification pass.
- Other Pi `LAB-PI-2`: C5 serial `LAB-C5`, only USB enumeration read.
  Not assigned or repurposed.

## What was built and checked

The native ESP-IDF v5.4 receiver, protocol encoder, bounded host capture helper,
port lister and actual-Guardian-parser qualification decoder are in this folder.
Build artifacts and evidence reside in the store:
`builds/20261114-cardputer-receiver-prep/` (initial image),
`builds/20261114-cardputer-receiver-fixed/` (corrected image),
`evidence-raw/receiver-prep-20261114/`.

13 Python protocol checks cover framing, CRC corruption, bounds, command limits,
truncation and unknown FCS. Failing-before evidence was saved for Python
behavior and the live-discovered FCS correction. The C++ encoder/command-parser
checks are post-write checks, including ASan/UBSan and a cross-language vector.
Native firmware compiled; esptool verified flashed application hashes.

First passive channel-6 capture: 427 frames in ten seconds, no USB CRC errors or
sequence gaps, automatic stop observed. An experimental trailing-FCS read
failed all 427 comparisons. Those bytes are not treated as an exposed FCS.
The fixed image never reads beyond the logical FCS-free length and explicitly
marks FCS unavailable; no false checksum pass. The packet length convention was
checked separately: Guardian's actual C++ parser processed all 427 saved frames
under ASan/UBSan, yielding 420 Complete and 7 Unsupported, no Malformed/Truncated,
and 344 complete advertised-settings observations. This was an imported-capture
qualification, NOT the full live parser/detector/core/presenter harness.

Final capture/stop evidence and counts are recorded in `hardware-checks.json` in
the evidence directory. Failures and first-attempt logs remain; no retrospective
claim that the initial image was already correct.

## Still open

L01/L02 remain unaccepted. Confirm phone hotspot BSSID/channel/client when enabled;
qualify reliable emitter power plus bounded commands/stop on installed firmware;
measure receiver clock mapping, latency, coverage and drops under load. The old
emitter source has a blocking transmit loop, so its serial stop is not a proven
interrupt mechanism. Current installed binary is not certified from its banner.

No automatic retry, Ralph run, offense, Pi firmware replacement or Guardian board
integration is authorized by these preparation tools. A phone may lack the
programmatic security-mode/restore controls needed by every L02 case. Keep those
cases unresolved rather than silently narrowing acceptance.

## Subsequent Pi check

The board subsequently booted into the expected headless Wi-Fi emitter and
answered `help`. No brownout warning occurred in that check. It is now running
the original application, no longer held in bootloader. Pi USB high-current
mode is enabled and the USB overcurrent flag was zero. The cause of the earlier
resets remains unresolved; port colour was not a diagnosis. No cable/port
change is presently required on the strength of those older observations alone.
Evidence: `evidence-raw/receiver-prep-20261114/pi-current-state.json` in the store.
This does not qualify sustained radio operation or the emitter's stop behavior.
No offensive command or Pi flash write was performed.

## 2026-11-14 owner-authorized StickS3 follow-up

The earlier untouched-board statements above describe the original L01/L02 scope.
The owner subsequently authorized LAB-STICK-1 for foundation/bring-up spikes.
Its own full flash is backed up and verified. Ten on-chip Imported-fixture checks
passed with RF off, followed by a real LCD bring-up. G10/G11 evidence is separate;
Cardputer remains the designated live receiver. See firmware/README.md and
docs/G10-validation.md for current facts. No Pi jobs or Cardputer firmware changed.

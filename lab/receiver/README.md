# Guardian lab receiver — preparation

Native ESP-IDF v5.4 acquisition-only firmware for an ESP32-S3 with native USB.
The owner designated the Cardputer ADV (`LAB-CARDPUTER`). Never auto-select
another port. `LAB-STICK-1` is the Guardian's own StickS3 (a head pointer when this was written) and is excluded.
This is lab instrumentation for L01, not Guardian's board UI or L02 acceptance.

The firmware uses no Arduino or M5 runtime. No screen, keyboard, SD, BLE,
association, active scan, raw transmit or nRF24 code. It boots with capture off.
`info`, `sync NONCE`, `start CHANNEL SECONDS` and `stop` are accepted. Reception is fixed
channel, management frames only, 1–300 seconds, subject to Brazil's 1–13 channel
configuration. Unsupported channel requests fail. A device deadline remains
active if the host disconnects. Stop/deadline flushes pending queue entries;
old timestamps cannot leak into the next session. A receiver stop was measured separately; see STATUS.md. The host live harness
uses version 1.2 clock synchronization, not receipt-time freshness.

## Commands

`./lab/receiver/build.sh` builds and archives in the store; it does not flash.
`./lab/receiver/run.sh ports` lists identities without opening serial devices.
It reuses the existing IDF Python environment (pyserial), not base/Conda pip.

After the exact Cardputer is backed up, flashed and its identity checked:

```sh
./lab/receiver/run.sh capture --port CARDPUTER_PORT --channel CHANNEL --seconds 30 \
  --out $GUARDIAN_STORE/evidence-raw/receiver-session.jsonl
```

This is a passive qualification capture, not a security grade or an offensive
scenario. A real receiver identity response is required before starting.
The owner chose a phone hotspot; use 2.4 GHz and a distinct SSID. AP BSSID/channel
and a controlled client are now recorded in [live validation](../../docs/L02-live-validation.md). No Wi-Fi
password is needed for passive reception. A phone may not expose all automatic
AP configuration/restore controls required by L02; unsupported cases stay open.

## GRX1 protocol

ASCII lines `GRX1 HEX\n`. HEX contains a little-endian 56-byte header, bounded
FCS-free frame bytes, and CRC32 of header+payload. The trailer CRC protects USB
metadata and payload; it is not the Wi-Fi FCS. Kind 1 = frame, 2 = heartbeat,
3 reserved status, 4 = stopped. Flags: bit 0 listening, bit 1 truncated, bit 2 actual FCS available (false
on the qualified S3 path).

Header: magic 4B; version/kind/flags/channel 1B each; boot ID 8B; transport
sequence 4B; callback acquisition time 8B microseconds; driver radio timestamp
4B; reported length 2B (includes FCS); copied length 2B; RSSI/noise/rx-state/
reserved 1B each; received/queue-or-transport drops/bad-input counters 4B each;
optional received FCS 4B (zero/unknown when availability bit is false).

The pinned SDK documents `sig_len` including logical FCS. The bridge subtracts
four from the *full reported length before truncating* and stores at most 1536
bytes. First live qualification found none of 427 inspected trailing values
matched frame CRC32; those bytes cannot be claimed as an exposed FCS. Version
1.1 does not read that trailing storage and explicitly reports FCS unavailable.
Host `fcs_matches` is null when unavailable, never a fabricated pass/failure.
Structural frame parsing is a separate check of the logical-length convention.
Driver `rx_state` remains
raw: zero means no driver error; other values are undocumented. Noise and radio
timestamp semantics are pinned SDK claims until measured.

A 24-slot queue separates driver callbacks from USB. Callback work is bounded;
no USB writes or Guardian logic run there. Frames carry acquisition timestamps
through queues unchanged. Host receipt time is separate and must NOT replace
acquisition time. USB latency/clock mapping and receiver coverage are not yet
qualified. Counters include explicit queue/USB drops; unobservable losses cannot
be interpreted as zero. Buffer truncation, corruption, reboot and sequence gaps
remain visible. The qualification helper does not assert L02 success.

## Verification and recovery

`python3 -m unittest discover -s lab/receiver/tests` checks protocol faults and
bounds. `tests/wire_check.cpp` checks the firmware encoder/command parser under
ASan/UBSan and emits a cross-language vector. Python behavior had a recorded
failing stub before implementation; C++ checks are an honest post-write baseline.
No portable Guardian library source or accepted test behavior was changed.

Before writing, preserve the full original 8 MB flash in the store, verify its hash,
and confirm chip MAC/USB serial. The full backup includes internal filesystem
captures/settings; it is not copied into Git. Restore is an explicit full-image
write at offset 0 on this exact board, followed by verification. Flash/restore
commands are intentionally not performed by build or capture helpers.

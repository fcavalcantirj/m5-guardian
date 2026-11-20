# Cardputer lab client

A separate native ESP-IDF station for ordinary reconnect validation. This is lab
instrumentation, not the Guardian library or its display. The owner designated
Cardputer ADV `LAB-CARDPUTER`; firmware refuses to initialize Wi-Fi on another
MAC. StickS3 `LAB-STICK-1` remains the independent observer.

Boot is idle. `join BSSIDHEX CHANNEL SSIDHEX PASSWORDHEX SECONDS` requests one
normal connection to that exact AP. Brazil channels 1–13; maximum 90 seconds;
no automatic application reconnect, AP mode or raw-frame transmission. `stop`
disconnects, stops Wi-Fi and clears its RAM configuration. The deadline is on the
device and still applies if the USB controller disappears. `info` and periodic
state lines report identity, connection count, disconnect reason and DHCP status.
No credentials are printed or saved in NVS. SSIDs are 1–32 bytes without NUL;
passphrases are 8–63 printable ASCII bytes. This is a deliberately limited lab
interface, not a general network manager.

Protocol `guardian-client/1.1`: `INFO` and the 1 Hz `STATE` line carry a random
per-boot nonce (`boot=`), so a host can tell an autonomous stop from a reset.
`STATE` also reports `deadline_stops`, `command_stops`, `last_join_us` and
`last_stop_us` (device microseconds); a deadline expiry prints
`GCLIENT STOPPED deadline`.

`build.sh` only builds in the store. It never flashes or operates radios. Use the
installed IDF v5.4 Python for `reconnect.py`; it identifies the exact Cardputer
and ELF hash before sending a connection request. It runs the existing G13
on-board reconnect harness, performs two ordinary reconnects, checks Guardian
assertions, independently finds Cardputer association frames, then confirms
both devices stopped. An interrupted observer is stopped with SIGINT; the
client has a separate device deadline as backup.

The owner-approved credential file is local, outside Git:
`~/.config/m5-guardian/lab-credentials.json` (mode 0600), mapping SSID to an object
with a `password` field. Do not copy it into evidence. CLI arguments contain only
paths and scope; passwords are sent over local USB without command logging.
Keep both USB cables connected and the scoped 2.4 GHz hotspot enabled. No phone
client or Pi emitter is needed for this ordinary reconnect test.

```sh
# Explicitly launches live, ordinary station connections to the configured AP.
IDF_PYTHON lab/client/reconnect.py --config BROW_SCOPE_JSON \
  --client-elf BROW_CLIENT_ELF --out NEW_BROW_EVIDENCE_DIRECTORY
```

Qualification (explicit, after flashing): `IDF_PYTHON lab/client/qualify.py --config
BROW_SCOPE_JSON --client-elf BROW_CLIENT_ELF --out NEW_BROW_DIR [--no-rf]` checks
identity, idle boot, stop and four rejected commands without RF; without
`--no-rf` it also proves the 10 s on-device deadline twice in one boot: port open,
then host port closed for 15 s and reopened.

`reconnect.py` stamps actions with CLOCK_MONOTONIC (the harness `micros()` domain),
schedules the two cycles from the observer's own progress reports (>=15 s and
>=40 s, after its 10 s association baseline), and fails on a missing, stale or
ended observer. Each cycle needs a clean association/reassociation request
Cardputer->AP whose whole possible acquisition interval (mapped ms + 999 us +
clock-sync uncertainty) lies between that cycle's join request and the next stop
(or observer exit), plus a rise in the client's connection count with DHCP.
Successful association responses are recorded as extra corroboration.

Host checks: `IDF_PYTHON -m unittest discover -s lab/client/tests -p 'test_*.py'`
(pure helpers, simulated device protocol, simulated observer end-to-end) and the
sanitized parser check `tests/command.cpp`.

Recovery: the original full 8 MB image is preserved at
`$GUARDIAN_STORE/device-backups/LAB-CARDPUTER-20261114/`.
The previously qualified receiver image is in
`builds/20261114-cardputer-receiver-sync/guardian_receiver.bin` under that store.
Before any application replacement, verify serial/MAC, original backup hash,
installed partition layout and a readback of the current receiver application.
Application-only writes at 0x10000 preserve the existing bootloader and partition
table. Restoration is explicit; no build/test helper restores firmware silently.

Validation status and measured results are recorded in `docs/G13-validation.md`.

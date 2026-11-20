# G13 measurement adapter — worker evidence and review boundary

This work adds the real native acquisition-to-library-to-diagnostic path and an
L02 transport adapter. G13 acceptance is **pending**. The worker did not open a
serial device, flash, change an AP, launch the live harness, operate an emitter,
or modify the ledger. G11 and G12 are accepted in their supervisor records;
L02 and G09 acceptance precede this integration. The G12 predecessor result and
engine handoff were inspected, alongside the supervisor source manifest.

## Boundaries and implementation

`firmware/adapters/measurement` contains SDK-free adapter mechanics: bounded
normalization, byte identity/escaping, passive survey timing, and application
wiring into the existing SecurityFrameParser, Core, DisconnectDetector,
BaselineDetector and presenter. It contains no replacement security policy.
The same code is exercised with explicitly Imported host inputs. All 21
accepted core/presenter files match the G12 supervisor manifest.

The StickS3 implementation separates `measurement_radio.cpp` (SDK callback and
queue), `measurement_main.cpp` (application task/serial/coverage), and
`measurement_display.cpp` (diagnostic painting). The earlier bring-up source
is retained as `guardian_bringup_main`; G13 supplies `app_main`. The G11 flashed
image and original device backup are untouched. No picker, persistence, art or
G14 implementation is included.

Boot leaves reception stopped and selection unset. An explicit command supplies
country, exact BSSID and SSID bytes; `start CHANNEL SECONDS` supplies the initial
channel and a 1–300 second passive measurement duration. There is no active scan,
association, AP interface, BLE initialization, health probe or transmit call.
The SDK country code is configured with 802.11d adoption disabled and queried
back. The SDK's contiguous regulatory range must fit this adapter's 1–13
contract; unsupported ranges fail initialization (including a 14-channel range). A failed
radio initialization requires reboot. A different country requires reboot.

Discovery dwells 300 ms per permitted channel. Only a complete, receive-verified,
exact-selected advertisement locks its **receive** channel. Five seconds without
one resumes passive discovery. A channel switch disables reception, drains/counts
queued losses, retunes, then resumes. Discovery, transitions and stopped input
report unknown/degraded coverage; settled monitoring reports just one channel.
The device never claims simultaneous all-channel coverage. Acquisition uses the
64-bit monotonic `esp_timer` clock and an immutable random boot epoch. The
wrapping 32-bit driver timestamp is diagnostic only, never the aging clock.

The radio implements the accepted `FrameSource` pull API and `AcquisitionStats`.
Null/zero-capacity caller buffers do not consume a queued frame; smaller buffers
remain FCS-free and marked truncated, preserving acquisition metadata.
The Wi-Fi callback copies at most 1,536 FCS-free bytes and bounded metadata into
a static 24-slot queue using task-context `xQueueSend(..., 0)`. It never parses,
draws, prints, writes files or allocates. Queue/bad-input counters are atomic;
USB writes and parsing run in the application task, with bounded per-loop work.
Application and transport losses degrade coverage, and the harness rejects
unexplained receiver drops. The driver task queue is internal static memory;
physical stack/heap and rate adequacy still need measurement.

## Pinned receive semantics and provenance

Source examined: ESP-IDF v5.4 commit
`67c1de1eebe095d554d281952fde63c16ee2dca0`,
`components/esp_wifi/include/local/esp_wifi_types_native.h`, lines 64, 83–85,
and `components/esp_wifi/include/esp_wifi.h`. `sig_len` includes the logical
four-byte FCS; that length is removed **before** the capacity clamp. The callback
never reads or claims an actual FCS trailer. SDK `rx_state == 0` becomes Ok;
all nonzero values become DriverError (the codes are not public). GRX telemetry
normalizes nonzero RX state to 1. `radio_timestamp_us` is preserved with sleep
explicitly disabled. The callback context is corroborated by Espressif's
[Wi-Fi driver documentation](https://docs.espressif.com/projects/esp-idf/en/v5.4.4/esp32s3/api-guides/wifi.html).
The pinned local source, rather than that later patch documentation, controls
this build. Hardware must still confirm the installed firmware/length convention.

No third-party parser was imported. Existing Guardian parser validation handles
header/body/IE bounds, OUI/type, optional defaults, duplicate conflicts, PMF and
suite counts. Existing notices remain binding. The GRX serializer is reused
verbatim from `lab/receiver/main/wire.hpp`, and the board build's source archive
includes this dependency. The installed SDK has the already-recorded modified
S3 `libnet80211.a`; its bytes/license and qualification are evidence inputs,
not a claim of an unmodified upstream SDK or RF equivalence.

## Diagnostic output and protocol

The screen shows selected BSSID, escaped SSID with exact byte length, observed
SSID kind, receive channel/RSSI/age, complete/invalid/drop counts and security
fields. Long escaped labels rotate through 37-character chunks. Nonprintable,
non-ASCII and backslash bytes become `\xHH`; empty and zero-filled SSIDs retain
different byte identities. Complete raw `ssid_hex` is always in serial output.
No fixture ingestion command exists on the board. Host tests use a separate
Imported instance; the renderer labels any non-live input DEMO/Imported.

Security numbers are diagnostics, not grades: element state 0 absent, 1 valid,
2 malformed, 3 truncated, 4 conflicting; SSID kind 0 absent, 1 hidden, 2 present;
Parse status is 0 complete, 1 unsupported, 2 malformed, 3 truncated, 4 unrelated.
PMF is 0 unknown, 1 disabled, 2 optional, 3 required. AKM/cipher masks use the named
bits in `guardian/parser.hpp` and are separate for WPA and RSN. Privacy is a
separate capability. OWE AKM and OWE-transition state are distinct. Malformed or
unverified input cannot become an open/WEP grade. Old fields remain explicitly
aged; the screen shows **No fresh data** at 29 seconds since the last observation (redrawn at that deadline), so it appears within 30 seconds of the AP turning off (2026-11-15 budget change).

Commands (ASCII, newline terminated, bounded line buffer):

- `info`, `sync NONCE`, `stop` work while stopped.
- `select BSSID_HEX SSID_HEX COUNTRY` selects while stopped. `-` is a zero-length
  SSID for manual diagnostics. The existing L02 scenario scope requires a visible
  SSID of 1–32 bytes. Selection resets observations and related approvals.
- `start CHANNEL SECONDS` begins bounded passive discovery/monitoring.
- `BASELINE` approves only currently fresh, complete and trusted selected facts.
- `WATCH_AP BSSID_HEX` / `APPROVE_AP BSSID_HEX` supply explicit related-AP policy.
- `DROP 24` deliberately withholds the next 24 real callback packets from the
  board core for the scoped L02 loss scenario. Raw evidence is still exported;
  completion is acknowledged. This generates no RF frames.
- `SNAPSHOT` emits existing evidence; it never renews acquisition time.

Raw management frames and heartbeat/stopped receipts retain GRX1 framing/CRC.
On-device library states use `G13 BOOT_HEX CRC32_HEX JSON`. CRC32 covers the exact
JSON bytes. The JSON reuses L02 state field names and adds diagnostic fields.
The exact source JSON and CRC are retained with each translated state.
These CRCs protect serial transport; neither authenticates radio transmitters.
The current acquisition filter matches L02's management-only path; it does not
claim data/EAPOL observation. No password or client-identity assessment is made.

## L02 reuse and explicit reviewer launch

`lab/live/run_board.py` uses the existing Session orchestration, emitter/AP
controller, ClockMap, RadioWitness, ListeningWitness, `assessment.py`, evidence
writers and cleanup. Only serial identity, library input/output and deliberate
loss adapters differ. The host path still launches its own C++ engine. The board
path never launches a host policy engine and never forwards FRAME/COVER input to
the board; its library receives only callback packets. Board states must match
the selected boot/network/live origin and CRC. Mapping preserves acquisition
time; report latency uses actual host receipt, with 250 ms maximum telemetry
lag and a 2.5-second missing-state timeout. Clock uncertainty retains L02's
100 ms limit. Synthetic transport tests cannot satisfy this live gate.

After supervisor source review, explicit flash authorization, device identity/
backup verification and backend requalification, an example **manual launch** is:

```sh
python3 lab/live/run_board.py \
  --config /PATH/TO/CURRENT-OWNER-SCOPE.json \
  --out $GUARDIAN_STORE/evidence-raw/UNIQUE-G13-RUN \
  --scenario quiet --seconds 30
```

The config is the existing L02 exact scope plus an explicit country, e.g. `BR`
for this owner's lab, and `firmware_elf_sha256`: the lowercase SHA-256 of the
exact reviewed ELF used to produce the supervised flash image. The board
reports its IDF embedded ELF hash and MAC; both must match before a run. The
actual banner is preserved in `receiver-identity.json`. The receiver serial is **LAB-STICK-1**, the G11 unit;
no generic VID/PID selection and no automatic fallback to another board. Every
scenario remains an explicit owner launch. Emission scenarios retain the existing
bounded controller and fresh-scope interlocks. Requalify/deploy the corrected
emitter 1.2/controller separately before those launches; historical L02 1.1 success
does not prove the corrected failure path deployed. This worker did not do so.

## Worker checks and remaining acceptance

Evidence directory:
`$GUARDIAN_STORE/ralph/20261114-234045-149903-task-15/g13-evidence/`.

- `red-direct.log`: actual failing adapter behavior with stubs (25 failures).
- `pipeline-red.log`: boundary checks green, new wiring checks fail (11 failures).
- `review-red.log`: reproduces related-approval retention across selection.
- `delivery-green-asan.log`: 7 cases / 82 assertions, ASan/UBSan, no failures.
  `delivery-red.log` preserves the failing standard FrameSource delivery check.
- `focused-ctest.log`: unchanged parser/core/detector baseline and adapter checks
  pass (4/4); final adapter-only rerun follows the review fix.
- Board transport red/green logs cover wrong origin/scope/boot, time mapping,
  delayed telemetry, no console frame injection, and CRC validation.
- Existing affected lifecycle, receiver-stop, assessment and review-control tests
  pass; no RF tools are executed by those deterministic tests.
- `accepted-library-unchanged.json` records byte identity against G12 acceptance.

The first strict stub compile exposed unused fields and a signed test literal;
that is test-authoring evidence, not a product failure. The direct red runs above
are runtime assertion failures. Initial CMake generation on SMB was slow; an
accidental overlapping configure and an early CTest invocation found no tests.
That invocation is **not** a baseline/pass. The later populated-tree CTest run
is the actual baseline. Early intermediate build logs are retained as history.

Native compilation/linking and application-image generation passed; the verified
artifact record is below. No boot,
visible-screen, callback throughput, RAM/stack high-water, real-radio false-positive
rate, physical event, security/channel change, AP-off video, or independent packet
comparison is claimed by these host checks. Supervisor acceptance must execute
all relevant accepted L02 scenarios on this board; compare controlled AP settings
with independent decoding; change security/channel and observe rediscovery;
turn the AP off and save No-fresh-data evidence within 30 seconds; record quiet/
normal-reconnect false positives, controlled-event observations, logs and video.
Replay or host fixtures do not close any of those requirements.


Native object checks also caught host/ESP32 `uint32_t` printf ABI differences.
Explicit argument conversions fixed the format errors; the four new translation
units then compiled with the real pinned Xtensa compiler. `native-stack-frames.json`
records compiler frame sizes: callback 1,952 bytes, application entry 2,176 bytes,
JSON formatter 1,968 bytes. These are individual frames, not measured call-chain
high-water marks. Full native link evidence and physical stack margins remain
separate. `archive-red.log`/`archive-green.log` additionally reproduce and fix
omission of the reused GRX header from the board source archive.


Scoped reproduction from the repository root (choose fresh directories on the
mounted Guardian the store, not local build directories):

```sh
cmake -G Ninja -S firmware -B $GUARDIAN_STORE/builds/G13-host-review -DGUARDIAN_SANITIZE=ON
cmake --build $GUARDIAN_STORE/builds/G13-host-review --target measurement_check parser_check core_check detector_check -j 8
ctest --test-dir $GUARDIAN_STORE/builds/G13-host-review -R '^(measurement_check|parser_check|core_check|detector_check)$' --output-on-failure
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s lab/live/tests -p test_board.py
```

The exact native configure/build commands are preserved in the evidence directory's
`build-native.sh`; that script only compiles/links and records symbols. It is not
a flash installer, scenario launcher or worker verifier.


## Final native result and review inventory

The final Xtensa ESP32-S3 ELF links successfully. Defined symbols include the
real Core, SecurityFrameParser, DisconnectDetector, BaselineDetector, portable
presenter, MeasurementRadio receive callback, Monitor and board renderer. Each
of the five accepted core translation units appears exactly once in the native
compile database. The frozen build-input manifest still matches all source.
No native assertions, boot or RF work were executed.

The application image is **804,576 bytes**, fits the 3 MiB factory app
partition and leaves 74% of that partition free. Its embedded ELF SHA-256 matches
the linked file:

`2dfcb904f5770edd95c4ab04fe138bb3ed1ee4ddd62ed55ec13b3f177a53c97c`

`native-link-verification.json` records this check; `native-artifact-sha256.json`
contains eight read-back-verified artifacts (ELF, binary, map, configuration,
compile database, project description and partition binary). `native-size.json`
is the SDK's static size report, not free runtime heap or a stack high-water
measurement. This is an application-image review artifact, **not a complete
flash bundle**; no bootloader was rebuilt for installation and no device was
opened. Preserve the existing G11 recovery route for any later authorized flash.

The first native attempt hit host/ESP printf ABI errors in isolated object
checks, then the newly added ELF identity API exposed a missing explicit
`esp_app_format` dependency. Corrected source compiled; `native-resume.log`
records the successful full link. The initial application-image command lacked
the SDK Python environment and failed importing `pyparsing` during linker-script
generation. Re-running in the existing installed SDK environment succeeded
(`native-app-final.log`); nothing was installed. Partial SDK rebuilds and SMB
latency account for the long build, not radio execution. Failed logs remain
available and do not count as successful validation.

The source archive contains 208 maintained firmware, test, lab, documentation
and provenance files, with a verified SHA-256 manifest. `changed-files.json`
lists **9 modified and 12 added files**. Modified integration points are the
host CMake file, StickS3 CMake/retained entry point/build archive helper and its
archive test, L02 Session hooks, and the root/firmware/live READMEs. New files
are the measurement adapter pair, five board integration/rendering files, the
host adapter test, three board-harness/transport-test files and this handoff.
The ledger, runner and all accepted core/presenter files remain unchanged.

Worker status: implementation ready for supervisor review. **G13 physical
acceptance remains unverified**, including exact-board boot, real callback
fields/throughput, field comparison, channel/security changes, AP-off timing
and video, normal-traffic false positives and controlled physical events.

Supervisor follow-up: [G13 validation and fixes](G13-validation.md). Acceptance remains pending.

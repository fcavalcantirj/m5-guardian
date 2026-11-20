# Portable defense-library contracts — G01

These are portable interface contracts, not a completed detector library. G05
(2026-11-14, pending independent review) implemented the capability, epoch and
advertised-settings enforcement that G01 deferred; the G05 changes are marked
below. SDK adapter examples are not production drivers.

## 1. Dependency direction

Arrows below mean **includes / depends on**:

```text
capabilities.hpp -> time.hpp
radio.hpp        -> capabilities.hpp, identity.hpp, time.hpp
parser.hpp       -> radio.hpp, identity.hpp
core.hpp         -> capabilities.hpp, parser.hpp, radio.hpp, identity.hpp, time.hpp
rating.hpp       -> core.hpp, parser.hpp, radio.hpp
detector.hpp     -> core.hpp, parser.hpp, radio.hpp
advice.hpp       -> core.hpp, capabilities.hpp, time.hpp
presenter.hpp    -> core.hpp
output.hpp       -> presenter.hpp, capabilities.hpp

board adapter -> portable interfaces + its SDK
renderer     -> output.hpp + optional guardian_canvas + display driver
```

The core, parser, detectors and presenter use standard C++ value types and
`guardian/` headers. They do not include Arduino, ESP-IDF, FreeRTOS, M5Stack,
graphics, filesystem, sockets or clocks. Adapters own queues, device reads,
clock reads and rendering. A headless output does not link guardian_canvas.

## 2. Headers and boundaries

| Header | Responsibility |
|---|---|
| `time.hpp` | `Millis`, source-qualified `TimeEpoch`, `Instant`, injected `MonotonicClock`, optional `WallClock`, `Support` |
| `identity.hpp` | Byte-preserving `Mac`, `Network` and input `Origin` |
| `capabilities.hpp` | Banded channel set; radio/display/input/BLE/memory/storage capabilities; headless profile |
| `radio.hpp` | FCS-free frame span, caller buffer, acquisition/processing metadata, source counters, pull API and (since G05) the epoch-tagged `CoverageReport` |
| `parser.hpp` | Structural parse states, independent WPA/RSN elements, raw and mapped suite selectors, identity and reason-code results. G04 added two documented `ParseError` outcomes (`SuiteCountZero`, `BadElementLength`) |
| `security_parser.hpp` | G04: the concrete `SecurityFrameParser` (independent implementation, `parser.cpp`); status/default rules documented in the header and docs/G04-parser.md |
| `core.hpp` | Evidence core (G05): clock-injected `Core`, `SecurityObservation` carrying the `AdvertisedSettings` record, `SignalObservation`, `IncidentObservation`, `Assessment` with the `Unrated` overlay, `Rejections` counters, `Snapshot` |
| `rating.hpp` | G05: `assess()` (the documented five-mood policy, weakest-advertised rule), `observe_security()` / `observe_signal()` reductions from `ParseResult` + `RxMeta` |
| `detector.hpp` | Bounded detector limits (G06 added `dedupe_ms`, `change_threshold`, `max_window_events`), frame/tick inputs and the `CoverageSource` pull interface (`CoverageReport` moved to radio.hpp in G05) |
| `detectors.hpp` | G06: the concrete `DisconnectDetector` / `BaselineDetector` behind `FrameDetector`, the owner-approved `ApprovedScope` and the typed `SettingsFingerprint`; policy in docs/G06-detectors.md |
| `advice.hpp` | G07: `advise(Snapshot)` -> `Advice` (explanation `AdviceId`s, one `NextStep`, `SignalView` at this device, always-Unverified `OwnerCheck`s, `Verification` labels for what v1 does not measure), static-storage texts `advice_text()`, and the contract-only `ConnectivityProbePlan` / `ConnectivityResult` for a later associated probe; policy in docs/G07-advice.md. `core.hpp` gained `Snapshot::signal_interval_known` / `signal_interval_ms` (G07) |
| `presenter.hpp` | G08: typed actions and face/details/picker view models, sanitized labels with byte-exact identity, independent incident/evidence overlays, DEMO isolation, bounded owner requests and persistence adapter contract; policy and evidence in [G08-presenter.md](G08-presenter.md) |
| `output.hpp` | Borrowed view/snapshot output and static display capability; no drawing API in the presenter |

## 3. Ownership and execution

1. The radio adapter owns a bounded pool. A driver-task callback copies bounded
   bytes, stamps acquisition, queues an index and counts drops. It never calls
   Core, parses, draws or blocks on a queue.
2. `FrameSource::next()` copies into the caller's `FrameBuffer`. On success,
   `span.bytes == into.data` and `span.size <= into.capacity`. Null/zero-capacity
   input returns false without consuming a frame. A false return means no frame
   was delivered; the caller must not consume previous output values as new data.
3. The caller keeps this buffer valid through parser/detector calls and must not
   refill it until those calls return. Neither keeps a pointer into it. Results
   own fixed-size arrays and copied values.
4. One application task owns Core, detector state and snapshot/presentation.
   Interfaces are borrowed; application lifetime owns their implementations.
   `StatusOutput` must copy anything needed beyond its call. Its capability
   reference stays valid for the output object's lifetime.
5. Parser/core/presenter allocate nothing after construction. Detector state is
   bounded by `DetectorLimits`; since G06 `DisconnectDetector::configured()` /
   `BaselineDetector::configured()` / `ApprovedScope::configured()` report limits
   that the fixed storage cannot honour, a misconfigured detector counts nothing,
   and `ApprovedScope::approve()` refuses when full rather than growing.
6. The ESP-IDF promiscuous callback is in the **Wi-Fi driver task** (pinned local
   `docs/en/api-guides/wifi.rst`, Wi-Fi Sniffer Mode section). The example uses
   `xQueueReceive(..., 0)` / `xQueueSend(..., 0)`, not ISR variants. It checks queue
   allocation/publication and returns an unpublished pool slot. Stop/restart
   synchronization is explicitly absent from this sketch and remains G13 work.

## 4. Acquisition time, queue delay and epochs

`RxMeta::acquired` is an `Instant` stamped at acquisition, before queueing.
It is immutable across the queue and caller copy. `processed` is optional
processing-time diagnostics, never evidence freshness. The adapter may use a
bounded task-safe monotonic read in the callback; it must not substitute a
later dequeue timestamp. Callback-arrival time measures arrival at this sensor,
not exact over-the-air time; driver latency is a measurement limit. A driver
hardware timestamp may supplement it only with an explicit conversion and
uncertainty model.

An Instant is usable only when `known` and its epoch is valid. `TimeEpoch`
combines a nonzero application-assigned 128-bit source/timebase ID and a boot
or generation counter. Independent devices/import sessions must have distinct
source IDs. A counter reset requires a new source ID; a reboot changes the
counter. The epoch is immutable during capture and queue contents are flushed
before restart. Comparing equal boot counters from two devices is not valid.
Default zero values are unknown, not a usable timestamp.

A frame acquired at 1 s and drained at 40 s is 39 s old. A replay frame scheduled
at offset 5 s keeps that offset even when drained later. The example snapshots
its replay epoch at construction and refuses to continue across a clock epoch
change. Timestamp arithmetic must guard overflow. A replay/import may map
recorded offsets to a dedicated playback timebase, but stays `Origin::Imported`;
time conversion cannot turn it into live evidence.

Acquisition epochs flow into `SecurityObservation`, `IncidentObservation`,
`SignalObservation`, `CoverageReport` and source statistics. **Since G05 Core
enforces this**: it borrows a `MonotonicClock`, and an input is live evidence only
when its `Instant` is valid, in the clock's epoch and not after the clock's now;
invalid and future inputs are rejected and counted (`Snapshot::rejected`), a
foreign-epoch security reading is kept only as a historical record while no live
reading exists, and a foreign-epoch signal, coverage report or incident is
rejected. The compatibility field `observed_at` was removed. **Since G06** the
detectors anchor their windows on acquisition instants, fix their epoch from the
first valid instant, ignore and count foreign-epoch frames/ticks/coverage, and
emit `IncidentObservation::acquired` = the instant of the frame that reached the
threshold. `FrameDetector::on_tick` and coverage use Instant already.

WallClock is display/persistence-label metadata only, never an evidence clock.

## 5. Byte identity and FCS normalization

- `Network` retains BSSID, SSID length and all original SSID bytes (0–32).
  Display escaping never changes identity. Absent, empty/all-zero hidden and
  present SSIDs have explicit state; length and bytes retain their distinction.
- Frame byte zero is IEEE 802.11 Frame Control. No radiotap, driver prefix or
  leading padding. **Every delivered FrameSpan excludes FCS.**
- An adapter first establishes its full FCS-free payload length from the
  documented source convention and actual available bytes, then applies the
  pool/caller capacity. For a driver reporting a present FCS, subtract four
  from the full length before truncation; never subtract four from a truncated
  copy. Already FCS-free sources subtract nothing. A known FCS-present length
  below four is invalid.
- An unknown trailer convention is dropped and counted as bad input, not
  passed to the parser under a flag or guessed away. It degrades coverage.
- `size` counts readable copied bytes; `reported_length` is only driver metadata.
  A caller/pool truncation keeps the prefix FCS-free and sets `truncated`.
  A parser may not classify the truncated frame as open or fully understood.
- Tuned band/channel is separate from the beacon's advertised DS channel.
  Header addresses are spoofable observations, not authenticated identities.

## 6. Security elements and partial evidence

WPA and RSN have separate `SecurityElement` records. Each retains its own AKMs,
pairwise list, group cipher and raw selectors. RSN alone supplies PMF and group
management cipher fields. This can represent WPA/TKIP and RSN/CCMP together
without replacing one group cipher with the other.

A `SuiteList` keeps at most 16 raw selectors, encoded OUI in the upper 24 bits
and type in the low 8, plus recognized bit flags. An unknown selector retains
its raw value and adds the Unknown bit. Overflow rejects the element; never
silently take a prefix. Fields in a SecurityElement are trusted only when its
state is Valid. Unknown selectors may be structurally valid without being
understood by policy. Invalid/truncated/conflicting element payloads are zeroed;
conflicting duplicate IEs invalidate that entire protocol record.

FcsError and DriverError inputs are rejected before a trusted parse. Unknown RX
status is not a claim of a verified checksum; the input adapter must document
what its source guarantees and preserve that uncertainty.

`ParseResult::header_valid` gates use of addresses/sequence in detectors.
`settings_present` means some explicitly valid settings fields exist, not a
full security decode. `settings_complete` additionally requires that the
relevant security data is complete, consistent and understood. A full grade
requires `status == Complete && settings_present && settings_complete` and
valid acquisition metadata. Failed parsing cannot become Open/WEP by default.

A structurally valid WPA/TKIP element can survive an unsupported or malformed
RSN sibling as **partial legacy-risk evidence**. The overall decode cannot earn
a complete grade, but G05 may report the independently confirmed legacy risk.
It must not use invalid fields or treat a missing/truncated element as absent.
OWE-transition state is also explicit; unknown/invalid transition information
blocks an assumption of plain unencrypted open access.

A protected-management bit does not by itself mean encrypted payload: group
management can be integrity-only. The reason is readable only for structurally
supported unprotected/integrity-only formats. Encrypted unicast or unsupported
protected formats keep `reason_readable=false`. Readable never means MIC-verified.

## 7. Capacity and capability rules

| Limit | Contract |
|---|---|
| SSID / MAC | 32 / 6 bytes; reject oversized SSID elements |
| Suite lists | 16 selectors per protocol/list; reject overflow explicitly |
| Channels | 3 bands × 256 bits = 96 bytes; adapter applies regulatory availability |
| Frame size | adapter-chosen `max_frame_bytes`; bounded caller/pool copies |
| Detector defaults | 64 sources, 8 approved APs (16 fixed storage), 10 s window, 45 s cooldown (60 s until the G14 board finding of 2026-11-15; corrected here by the G22 review), threshold 20; G06: 1 s retry-dedupe gap, change threshold 2, 128 window entries (ring, saturation reported); hypotheses, not calibrated signatures |
| Queue budget | includes slot metadata and OS queue overhead, not only payload bytes; measured in G13 |
| Counters | epoch-scoped unsigned deltas; G05 (`Rejections`) and G06 (`DisconnectStats`, `BaselineStats`) count per select/reset; window counts are bounded by the rings and report `saturated` |

Static capabilities describe supported hardware/interface features, not current
health. Runtime coverage reports whether the sensor is actually listening and
when that information was sampled. Unknown is never Supported. Mutable runtime
availability is not encoded by rewriting static capabilities behind consumers.

The headless profile has no physical passive radio, display, controls, BLE or
storage. Its FrameSource may still supply Imported fixture data; replay ability
is not passive RF capability. Live Core must not accept it as a live sensor.
Future dual-band/no-PSRAM/headless profiles are represented without board-name
branches. Since G05 Core takes the radio's `ChannelSet` at construction and rejects a reading
whose band/channel is outside it; an empty set (capability Unknown) rejects every
reading, because Unknown is never Supported.

## 8. Pinned SDK mapping and platform limits

Prior source inspection used ESP-IDF `67c1de1e`,
`components/esp_wifi/include/local/esp_wifi_types_native.h`:

| Driver field | Portable mapping and limitation |
|---|---|
| signed `rssi` | RSSI + explicit validity; sensor-local, not throughput |
| 4-bit `channel` | band/channel metadata for S3; wider uint8 portable channel supports future bands |
| `secondary_channel` | None / Above / Below / Unknown |
| 32-bit microsecond `timestamp` | optional raw hardware timestamp; wrapping and sleep precision caveats; never blindly compare with Guardian milliseconds |
| `noise_floor` | signed dBm plus validity; exposed on pinned S3 header |
| 12-bit `sig_len` | documented including FCS; normalize before pool cap |
| `rx_state` | zero reports no driver error; other codes are not publicly decoded |

This is documented source behavior, not proof from a live Guardian capture.
G13 validates actual metadata/FCS convention and regulatory tuning on hardware.
G04 validates portable parsing with explicitly normalized host fixtures.

Native ESP-IDF remains the first platform. The prior worker reported checking
Zephyr `main` without pinning a commit and found no monitor-mode operations in
the inspected ESP32 Wi-Fi driver file. Treat that as an unpinned research lead,
not a current support guarantee or proof of impossibility. G02 must pin any
source used for a decision. No Zephyr footprint, passive capture or display
performance has been measured here. A later Zephyr adapter must demonstrate
those capabilities; the core contract does not require Zephyr or ESP-IDF.

## 9. Migration ledger

| Existing item | G01 change / later ownership |
|---|---|
| Millis, Mac, Network, Origin, Pmf | shared header ownership established; Network equality remains in core.cpp |
| Parse / FrameView / Detector | ParseStatus alias retained; unused drafts replaced by typed source/parser/detector boundaries |
| SecurityObservation / IncidentObservation | G05: acquisition Instant is normative, `observed_at` removed; the mode/cipher summary moved from the observation to `Assessment`; `SecurityObservation` carries `AdvertisedSettings`, band, RX status, frame kind, parse flags |
| Core clock and channel checks | G05: `Core(const MonotonicClock&, ChannelSet, Origin)`, `snapshot()` reads the clock; rejects invalid/foreign/future time and out-of-capability channels; historical records after an epoch change |
| Core security policy | G05: `assess()` in rating.hpp consumes separate WPA/RSN settings with the weakest-option policy, `Unrated` overlay and `legacy_risk` partial finding |
| set_coverage_degraded | G05: replaced by `Core::coverage(const CoverageReport&)` (fresh, same-epoch report; degraded when not tuned, drops in window, or a live core without Supported passive receive); G06: `DisconnectDetector::coverage()` copies the report sampled inside the burst window into the incident record (`coverage_known`, `listened_ms`, `coverage_window_ms`, `hopping`) |
| Detector / IncidentObservation | G06: `IncidentObservation` carries count, window, threshold, raw/deduped/protected/EAPOL counts, saturation, coverage facts and `change::` bits; `ApprovedScope` is the explicit baseline; see docs/G06-detectors.md |
| Core::signal | G05: new `SignalObservation` input (BSSID-scoped RSSI/activity) with its own age; never renews security evidence |
| presenter sources | unchanged; G08 consumes capabilities and preserves incident/stale priority |
| StatusOutput | new borrowed view/snapshot boundary; SDK renderer stays outside |
| guardian_canvas | retained renderer helper; no headless/core dependency |
| StickS3 board spike | preserved; G10 fixes display ownership, error handling, archival and storage exception; G13 adds synchronized capture lifecycle |
| host CMake target | missing tests/contracts.cpp remains G03; G01 does not claim host behavior acceptance |
| archived browser | not migrated and not RF evidence |

## 10. Examples and validation boundary

`firmware/examples/headless_replay.cpp` uses a fake clock (with a reboot),
scheduled Imported frames (fixture bytes), the real `SecurityFrameParser`, the real
G05 `observe_security()`/`Core`, the real G06 detectors (explicit baseline, reset
on the epoch change) and stdout output. It illustrates ownership and
pipeline wiring on the host; it is Imported replay, never live evidence.
`espidf_adapter_sketch.cpp` illustrates task-context queues, FCS normalization,
acquisition stamps and static capabilities; it has no production stop/restart
path and is not a device-ready driver. Neither is a firmware target.

Reviewer-owned syntax checks do not establish behavioral, radio or physical
acceptance. See `docs/G01-validation.md` for exactly what was checked and fixed.

## G04–G07 supervisor clarifications (2026-11-14)

RSN and WPA selector namespaces are distinct. A recognized cipher number under
the wrong OUI stays Unknown with its raw selector retained. Group-management
ciphers must be a supported BIP suite; invalid/unknown choices cannot earn a
positive PMF rating. Management fragments are header-only Unsupported input;
Guardian does not reassemble them or treat their prefixes as complete settings.
Legacy-risk findings also require receive-verified bytes.

Detector windows belong to one Origin until reset. Switching live/demo/imported
sources requires reset (or separate instances). Clock ticks/coverage come from
the same pipeline. Unverified disconnect frames do not enter incident counts.
See [supervisor evidence](G04-G07-validation.md).

## G08 supervisor clarification (2026-11-14)

A picker insertion preserves the currently highlighted exact network identity,
including when it reuses an earlier expired storage slot. A selected-identity
change clears any pending owner request from the prior selection. Requests are
still applied explicitly by the application; Core/scope/storage coherence and
error reporting remain the application's responsibility. See [G08 validation](G08-validation.md).

## G09 corrections

Absent SSID is not a zero-length hidden SSID: Core/picker identity admission must
have a parsed SSID element. Incident acquisition remains the triggering frame's
instant even when a later tick anchors the active window. Settings-change counts,
field union and cooldown are per BSSID; unexpected-AP aggregation is scope-wide.
OWE transition advertisements distinguish open side, positively advertised OWE
AKM and inconsistent/unverified combinations. Weak cipher identities from valid
elements survive a malformed sibling for specifically worded partial advice.
See [G09 validation](G09-validation.md) for regressions and API additions.

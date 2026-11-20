# Architecture decision

```text
host live receiver OR ESP-IDF adapter → bounded frame queue → parser/detector adapters
                                              ↓ typed observations
                                        portable defense core
                                              ↓ snapshot
                                         UI presenter
                                              ↓ view model
                             board renderer / headless output adapter
```

The core owns selected-network scope, evidence age, configuration policy and incident state. The presenter owns display precedence and expression selection. The renderer owns pixels, asset decoding and animation timing. Drivers own pins, screen/power initialization and actual radio calls. The driver callback must not paint the screen or run heavy parsing.

Capability data, not board-name conditionals in business logic, controls bands/channels, display/input, BLE and memory limits. Tests must cover a headless board, no PSRAM and a future dual-band profile without pretending those boards were physically tested.

Native ESP-IDF is the initial platform because the existing radio projects use its APIs. Zephyr has a current StickS3 target; OS portability comes from the adapter boundary rather than requiring two firmware stacks at once.

Candidates: [libwifi](https://github.com/libwifi/libwifi) for parsing, [AntiHunter](https://github.com/lukeswitz/AntiHunter) for detector extraction, [M5GFX](https://github.com/m5stack/M5GFX) and [M5Unified](https://github.com/m5stack/M5Unified) for the M5 board layer. None is accepted solely on its README. Pin, test and record provenance before reuse. G02 pinned these revisions and decided reuse versus independent implementation in [research/reuse-decisions.md](research/reuse-decisions.md): parser and detectors are independent portable C++ under the G01 contracts; libwifi is a host-only test oracle; M5GFX/M5Unified are the register-sequence reference for the board adapter.

Typed contracts for every arrow above, with ownership, byte identity, capacity and unknown semantics, are in [contracts.md](contracts.md) (G01).

## Platform decision record

2026-11-13, task 1: **ESP-IDF v5.4 (commit `67c1de1e`), native, no Arduino**, for the StickS3 first board. Zephyr's `m5stack_sticks3` board was reviewed and deferred: no display or audio entry in its supported-features table and passive Wi-Fi was not demonstrated there. Details, pinned toolchain and pin provenance: [firmware/README.md](../firmware/README.md).

## Integration gate

The first live integration is on the host: the L02 CLI harness controls a qualified offensive backend and separate real receiver, and links the actual portable parser/detector/core/presenter. Host TDD precedes it. Only after L02 and G09 acceptance does new ESP32 integration begin. G13 repeats these live scenarios through the firmware adapters. See [roadmap](roadmap.md) and [live-lab requirements](live-lab.md).

The earlier board spike is preserved as feasibility work. It does not determine the library architecture or bypass host acceptance. Static capabilities describe support; runtime coverage and evidence determine what was actually observed.

## Red incident face — owner requirement, 2026-11-14

For a current supported incident scoped to the monitored network, the original
Guy Fawkes-inspired face turns red with an ALERT label and an observed reason,
such as "Disconnect burst detected". This overlays any normal mood; it does not
change the advertised-settings grade or add a sixth rated mood. Celebration and
cigar are suppressed. Stale/coverage warnings remain visible. On evidence expiry
the face returns to its current justified mood or no-data state; silence is not
a guarantee that an attack ended. Unrelated networks cannot drive the alert.

The renderer will distinguish this alert from Horrible's static red treatment
through the label, expression and a restrained pulse. Existing incident contracts
provide the evidence boundary; rendering and its physical live proof are future
G14/G15/G23 work. Detection covers supported signals, not every offensive action.

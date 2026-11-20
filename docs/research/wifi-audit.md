# Guardian Wi-Fi implementation audit

Reviewed 2026-11-13. This is a source audit and implementation specification, **not a firmware test report**. No Guardian firmware exists yet. All entries in [guardian-tasks.json](../../guardian-tasks.json) remain false.

The current direction is a standalone, USB-powered StickS3 with native ESP-IDF, no Arduino or SD card, and an original 3D persona with five expressions. The older browser study does not satisfy this requirement. Its tests cannot establish radio reception or defense effectiveness.

## What our AntiHunter branch actually contains

Both checkouts were clean when inspected. Findings are pinned to these local commits, not claims about every AntiHunter version.

| Evidence | Finding | Consequence for Guardian |
|---|---|---|
| Original checkout `c6ef921`, platformio.ini (the owner's local AntiHunter checkout, outside this repository), lines 6, 37, 72 | Arduino framework; full/headless set `AH_SENTINEL=0` | Do not assume the local build runs always-on Sentinel. Other manually activated detectors are a separate question. |
| Prepared rebase `e7646f5`, `/private/tmp/guardian-antihunter-rebase-20261113/platformio.ini`, lines 46, 94 | Full/headless enable Sentinel | The prepared branch is separate; it has not been applied to the original checkout or demonstrated on the board. |
| Prepared `detect.cpp`, line 3562, `sentinel_startAlwaysOn` | Runtime user enable, scanning state and task creation still gate startup | A compile flag is not evidence of a running sensor. Require startup and fresh observation evidence. |
| Original detect.cpp (the owner's local AntiHunter checkout, outside this repository), `extractSSID`, line 355 | Non-ASCII bytes become `?` for display | Keep raw SSID bytes for identity. Display sanitization must not collapse different networks into one. |
| Same file, `hasOpenAuth`, line 376 | Checks for RSN/WPA elements without reading the capability Privacy bit | This helper is not a complete open/WEP/OWE/security classifier. Do not reuse it as the five-mood parser. |
| Same file, line 1154, self-SSID clone path | A different BSSID using the device's own SSID can produce an `EVILTWIN` incident | This path concerns its own AP identity, not automatically the selected home AP. Normal mesh/extender SSID reuse must not become proof of an attacker. |
| Same file, `handleDeauthFrame`, line 1680 | Reads bytes 24–25 as a reason without a preceding protected-body check in that function | Before reusing this code, review the caller and frame protection rules. An encrypted body cannot be interpreted as a plaintext reason. This is a porting concern, not a confirmed exploit. |
| Prepared `detect.cpp`, lines 1910–1911 and following | Flood heuristics include a 10-second window, 20-frame threshold, timing conditions and cooldowns | Thresholds require calibration against normal traffic and actual channel dwell. They are not universal attack signatures. |
| Prepared `detect.cpp`, `EAPOL_CAPTURE_BAIT` | Correlates disconnect frames and subsequent authentication traffic | A reconnect can create similar evidence. It does not detect an otherwise silent passive listener. |
| Original detect_features.cpp (the owner's local AntiHunter checkout, outside this repository), `attacker_kick`, line 483 | Schedules tracking/triangulation and reports an incident | Despite the name, this function is not itself a deauthentication transmitter. Do not describe its name as evidence of an attack feature. |
| Prepared `scanner.cpp`, `sniffer_cb`, line 2431 | Length/error checks and bounded copies exist; callback also uses ISR-style APIs | Preserve bounds/error handling; review execution context for the pinned SDK rather than copying APIs blindly. |
| LICENSE (the owner's local AntiHunter checkout, outside this repository) and build targets | AGPLv3, Arduino, XIAO/N16R8 targets; no demonstrated native StickS3 target | Reuse requires provenance/license review and real porting. An AntiHunter image is not a StickS3 Guardian image. |

The prepared QEMU target disables radio and Sentinel. Emulator screenshots cannot validate either. Previous lint results do not replace an actual build; the saved [validation record](../../validation/guardian-prototype-2026-11-13.json) records build/download and hardware limitations. The source-referenced detector-verification document was not present in the original checkout, so it is not available as test evidence.

## What each display claim must mean

| Display | Evidence needed | Cannot establish |
|---|---|---|
| Advertised Wi-Fi settings | Valid recent frames from selected BSSID, parsed security elements and channel | Password strength, router patches, actual client negotiation, authenticated AP identity |
| Signal | RSSI samples at this sensor, sample age and channel | Internet speed, available bandwidth or all-room coverage |
| Disconnect burst | Scoped deauth/disassoc observations, time window, deduplication, channel coverage | Identity or intent of a transmitter; whether clients accepted those frames |
| Unexpected AP/settings | Owner-approved baseline and a newly observed difference | Confirmed evil twin merely from a shared SSID, changed channel or MAC |
| Connection health | An associated probe's timed gateway/DNS/HTTPS measurements | Anything from passive beacons alone; Ethernet-Pi results cannot stand in for Wi-Fi-client results |
| No issue observed | Fresh observations plus explicit coverage | “Safe”, “unhackable”, or proof no attack occurred |

The StickS3 is an ESP32-S3 with a 135×240 display, 8 MB flash and 8 MB PSRAM. Board drivers, memory use and timing still need physical verification. Its radio does not cover 5/6 GHz. [M5Stack specifications](https://docs.m5stack.com/en/core/StickS3).

Native ESP-IDF is the initial choice because it exposes the needed radio APIs. Passive discovery must be selected explicitly: the normal scan default is active. Promiscuous processing runs in the Wi-Fi driver task; defer parsing/rendering to an application task through bounded queues. Record drops and listening time, and do not promise uninterrupted multi-channel monitoring. This is an engineering choice, not a claim that Zephyr is incapable. [Espressif Wi-Fi guide](https://docs.espressif.com/projects/esp-idf/en/v5.5.3/esp32s3/api-guides/wifi.html).

## Five moods: a transparent product policy

These labels rate **advertised personal-network settings**, not the whole home's security and not an industry certification.

| Mood | Initial supported configuration |
|---|---|
| Very good | SAE-only WPA3-Personal, supported CCMP/GCMP suites, PMF required |
| Good | WPA2-Personal only, CCMP, PMF required |
| Medium | WPA2-Personal CCMP with PMF optional or disabled; or valid WPA2/WPA3 transition with strong ciphers |
| Bad | Recognized original WPA or TKIP fallback |
| Horrible | Confirmed unencrypted open access or legacy WEP configuration |

Unknown suites, unsupported AKMs, malformed/inconsistent elements, Enterprise and OWE need an **unknown/unsupported overlay**, not an invented grade. An absent optional RSN field is different from a truncated one: implement documented defaults only for valid encodings. Check group and pairwise ciphers and all advertised AKMs. Keep explicit legacy-risk findings even if another unparsed field prevents a complete grade. Never infer strong settings by ignoring an unknown option.

WPA3 Personal is preferred; WPA2/WPA3 transition is a reasonable compatibility choice, and WPA2 AES remains appropriate where stronger modes cannot be used. Our Medium label must explain that tradeoff, not call transition mode broken. Hidden SSIDs and MAC filtering do not earn security credit. [Apple router guidance](https://support.apple.com/en-us/102766).

PMF protects robust management exchanges; required/optional/disabled differ. A beacon's PMF claim does not establish every client's negotiation or resistance to RF interference. OWE provides encryption without conventional password authentication and must not be mistaken for plain open Wi-Fi. [Espressif security guide](https://docs.espressif.com/projects/esp-idf/en/v5.5.6/esp32s3/api-guides/wifi-security.html).

## Advice that the sensor cannot verify by listening

Recommend unique strong Wi-Fi and router-admin passwords, supported firmware and updates, disabling unneeded remote administration/WPS/UPnP, and guest separation. Label these as owner checks unless an authorized router integration actually verifies them. A guest SSID alone does not prove isolation. A WPS advertisement does not prove an exploitable PIN, and its absence is not proof WPS is disabled. [FTC home Wi-Fi guidance](https://consumer.ftc.gov/articles/how-secure-your-home-wi-fi-network).

Do not store passwords to award mood points. Do not combine owner statements, suspected incidents and measured settings into a fabricated precision percentage. Keep the five moods; add a conspicuous incident/coverage overlay when warranted so a happy face cannot conceal a current observation problem.

## Mandatory proof before calling it working

1. Build and boot the exact identified StickS3 using the pinned native toolchain. Preserve Bruce captures and a restoration route first.
2. Before polishing art, display live BSSID/channel/RSSI/security fields with age and receive counters. Compare the parsed fields with a controlled AP configuration and independent packet decoding.
3. Change the test AP's security configuration and verify the displayed evidence changes. Power it off: within the specified 30 seconds, show no fresh data. Repeat through reboot and channel change.
4. Exercise malformed/truncated frames, unknown suites, WEP/open/OWE separation and PMF variants using fixtures. These prove parser behavior only; document which modes were also observed on hardware.
5. Exercise benign reconnects, known multiple APs and channel changes without false attacker claims. Test burst handling with offline replay and separately document any controlled physical validation. No disruptive transmitter is part of Guardian.
6. Record actual listening gaps, drops, memory, button latency and animation timing during a physical soak. Never count radio-disabled QEMU tests or browser fixtures as sensor validation.
7. Keep every ledger entry false until its own evidence exists. No rebase, flash, deployment or protection claim follows from this audit alone.

## Audit outcome

The source review supports a feasible native firmware direction, but does not establish a working sensor. The revised ledger puts real radio proof before art and covers parsing, freshness, false positives, useful advice and reproducible physical acceptance. Firmware implementation, deployment of the prepared AntiHunter branch and exact-board validation remain unfinished.

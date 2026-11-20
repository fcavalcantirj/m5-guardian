# G02 — reusable parsers and detector components with provenance

Reviewed 2026-11-13 (UTC 2026-11-14 02:00–02:30 for the host spikes). This is a
source, license and architecture review. It implements no parser, flashes no
device, transmits nothing and operates no offensive tool. Evidence labels used below:

- **SOURCE** — read in the pinned revision; a claim about the code, not about a run.
- **MEASURED** — executed on this Mac (Apple clang 21.0.0, AddressSanitizer +
  UndefinedBehaviorSanitizer) against the pinned libwifi files; logs in the store.

Nothing here is device validation. No AntiHunter, M5 or Guardian firmware ran.

## 1. Pinned revisions and licenses

Downloads live under `$GUARDIAN_STORE/third-party/` (git clones,
read-only use). The Mac keeps only what was already installed. Manifest with
hashes: `$GUARDIAN_STORE/third-party/MANIFEST-G02-20261113.json`.

| Component | Pinned revision | Date | License | Where |
|---|---|---|---|---|
| libwifi (`libwifi/libwifi`) | `c38dbc8d7d7836759300a9512d80a3d2d3e41a4b` = `main`, "Bump version to 0.0.11"; latest tag is `0.0.9` (`0a36a18`, 2023-04-22), 5 commits behind this HEAD | 2026-01-23 | Apache-2.0 (`LICENSE`); vendored `src/libwifi/core/radiotap/` is ISC (dual GPL-2 text in headers, ISC per `COPYING`) | the store `third-party/libwifi` |
| ESP-IDF `wpa_supplicant` component | ESP-IDF `v5.4` tag `67c1de1eebe095d554d281952fde63c16ee2dca0` (the already-pinned firmware toolchain) | 2024-12-31 | BSD 3-clause (component `README`/`COPYING`, Jouni Malinen and contributors); the ESP-IDF tree itself is Apache-2.0 | Mac `~/esp/esp-idf` |
| ESP-IDF `esp_wifi` public types | same `v5.4` commit; `esp_wifi_types_generic.h`, `local/esp_wifi_types_native.h` | 2024-12-31 | Apache-2.0 (headers); the Wi-Fi driver library is a closed binary blob | Mac `~/esp/esp-idf` |
| AntiHunter, original checkout | `c6ef921e6fffa1e2969c539c2dddb496d24c120a`, branch `agent/repository-guidelines`, clean tree, remote `fcavalcantirj/AntiHunter` | 2026-08-14 | AGPL-3.0 (`LICENSE`); `wifi.c`, `odid_wifi.h`, `opendroneid.[ch]` carry Apache-2.0 SPDX (Open Drone ID) | Mac `~/dev/AntiHunter` |
| AntiHunter, prepared rebase | `e7646f585463dc955eaef6bfb25388f8474d17af`, branch `guardian/upstream-refresh`, clean tree, origin = the local original checkout; upstream `main` fetched at `c891485` is **not** present in the original checkout (`git log c891485` fails there) | 2026-11-13 | AGPL-3.0 | Mac `/private/tmp/guardian-antihunter-rebase-20261113` (tmp; not durable) |
| M5GFX | tag `0.2.28` = `d91077b9a607b59404e4e4a49f775c792bfae382` | 2026-08-25 | MIT (M5Stack 2021) | the store `third-party/M5GFX`; local copy `~/.platformio/lib/M5GFX` (no `.git`, `library.json` 0.2.28) |
| M5Unified | tag `0.2.21` = `3eaaf828adfd0923c71ccc2e233a0199d9958faa` | 2026-08-26 | MIT (M5Stack 2021) | the store `third-party/M5Unified`; local copy `~/.platformio/lib/M5Unified` (no `.git`, `library.json` 0.2.21, requires m5gfx ≥ 0.2.28) |

Both AntiHunter revisions match `docs/research/wifi-audit.md`; nothing changed.
Worker comparison: recursive `diff -rq` found no differences within the compared
M5GFX/M5Unified source subsets; it excluded git metadata, docs, PlatformIO files
and, for M5GFX, PNG files. This is not whole-tree byte identity. Reviewer
source/commit/local-copy hashes for the specific PM1, display, power and build
files are recorded in the G02 reviewer evidence.
The prepared rebase lives in `/private/tmp`; macOS may purge it. Its local changes are
preserved as a patch (sha256 `5065dd1f9130dfe91b187dc8147089d01ddf9432b53dd262ecb21ec2face62d5`, recorded in
`validation/migration.json`). The patch is AGPL-3.0 upstream material, so it is kept outside this repository
(owner's artifact store, `$GUARDIAN_STORE/third-party/antihunter-upstream-refresh-20261113.patch`) and is reproduced from
upstream commit ids: the reviewer verified that the patch equals `git diff c891485 e7646f5`; it is not a complete checkout and requires the
upstream base to reconstruct source contents (not commit metadata). Neither revision establishes what is flashed on
any board.

Git on the SMB share works but macOS writes AppleDouble `._*` files into `.git`;
`git log` in the store prints "non-monotonic index" warnings for `._pack-*.idx` and
`git status` lists `._*` as untracked. Do not ignore these warnings as proof of integrity. Verify relevant worktree
files against both the recorded manifest and `git show REV:path`; HEAD alone
does not establish file contents. Any failed read blocks reliance on that file.

## 2. Decision table

"Independent" = Guardian implements it in portable C++17 inside `guardian_core`
under the G01 contracts, using the named source only as a reference for format
knowledge. "Ported" = code is copied with its license text and provenance
comment. "Differential reference" = compiled on the host only, in tests, never linked
into firmware; expected results must be established independently for each fixture. "Later adapter" = an external evidence source behind a `FrameSource`
or observation adapter, out of v1.

| Feature | Candidates read | Decision | Reason (SOURCE unless marked) | License obligation |
|---|---|---|---|---|
| 802.11 MAC header, type/subtype, addresses, seq/frag, Protected/Retry bits | libwifi `core/frame/frame.c`; AntiHunter `handleDeauthFrame` | **Independent** | Trivial fixed layout; libwifi's optional radiotap path allocates and its frame struct borrows input pointers; adapting it requires respecting G01's ownership and allocation limits | none |
| Beacon/probe-response fixed body, Privacy bit | libwifi `parse/management/beacon.c` | **Independent** | libwifi `malloc`s and copies the whole tagged-parameter area per frame (`bss->tags.parameters = malloc(...)`); G01 §3.5 requires no allocation after construction | none |
| IE walk with bounds | libwifi `core/frame/tag_iterator.c`; AntiHunter `extractSSID` loop | **Independent** | MEASURED: libwifi's `next()` stops when advancing to a zero-length element (`tag_len <= 0 → return -1`), so an RSN element after one is never read and a privacy-bit BSS stays flagged `WEP` (spike `zero_len_tag_spike.c`: `wep=1 wpa2=0 rsn_akm_count=0`). AntiHunter's loop is a source reference, not a verified general parser; no AGPL code is adopted | none |
| RSN element (id 48): version, group, pairwise list, AKM list, capabilities/PMF, PMKID count, group-management cipher | libwifi `libwifi_get_rsn_info`; ESP-IDF `wpa_parse_wpa_ie_rsn` | **Independent**, with the SDK parser's control flow as the format reference and libwifi as a host **differential reference for individually vetted fixtures only** | libwifi: MEASURED heap over-reads at `security.c:44` (direct call, element < 6 bytes) and `security.c:103` (capabilities read when the element ends after the AKM list, reachable from `libwifi_parse_beacon`); MEASURED count misread (`uint16_t suite_count = *data` takes the low byte only: count 0x0100 → 0 suites, rc=0); MEASURED silent clamp to `LIBWIFI_MAX_CIPHER_SUITES` (6) desynchronises the walk (7 pairwise suites → 6 kept, AKM count read from the 7th suite → 0, rc=0). Two of these four direct-call cases return incorrect success; two terminate under ASan. The separate IE-walk case also returns incorrect success. The count256 input is malformed: it declares 256 suites but supplies one. SDK parser (source inspection only): LE16 counts, `count == 0` and overrun rejected, but it is a **private** include (`src/common/wpa_common.h`, not in the component's `INCLUDE_DIRS`), maps unknown selectors to `0` (silently erased, violates G01 Unknown preservation), zeroes-and-defaults missing fields to CCMP/802.1X (the IEEE defaults, acceptable only when the element is otherwise valid), rejects the whole element on an unsupported group-management cipher (`-10`), keeps a pointer to the PMKID list, ignores leftover trailing bytes rather than rejecting them, and depends on `wpa_printf`/`os_*`/config macros | libwifi test dependency: preserve its Apache-2.0 license/attributions and applicable notices; any SDK code adoption or adaptation needs BSD provenance/notice review (none adopted here) |
| WPA vendor element (00-50-F2 type 1) | libwifi `libwifi_get_wpa_info`; SDK `wpa_parse_wpa_ie_wpa` | **Independent** (same code path as RSN, separate record) | libwifi has the identical low-byte count and clamp defects (`security.c:335-338`); G01 §6 requires separate WPA/RSN records and per-element validity/unknowns. libwifi DOES retain separate `wpa_info` and `rsn_info` structs as well as a combined `encryption_info` mask; the SDK returns one `wpa_ie_data` per call. Separate storage is not a reason to reject either; bounds, capacity and evidence semantics are the deciding limitations | none |
| OWE transition element (50-6F-9A type 28) | AntiHunter `extractOweTransition` | **Independent** | 15-line vendor-IE walk; AntiHunter's version copies the BSSID/SSID of the paired open BSS, which Guardian only needs as an "OWE transition present/valid" state | none |
| SSID identity | libwifi `libwifi_handle_ssid_tag`; AntiHunter `extractSSID` | **Independent** | libwifi truncates to 32 bytes silently and `memcpy`s into a `char[33]`; AntiHunter replaces every byte outside 32..126 with `?` (display logic inside the parser, collapses identities — audit item kept) | none |
| Deauth/disassoc reason code | libwifi `libwifi_parse_deauth`; AntiHunter `handleDeauthFrame` | **Independent** | libwifi: `tags_len` computed without checking `frame->len` covers header+2, then `malloc(tags_len)` and `memcpy(&deauth->tags.parameters, …)` copies into the address of the pointer field (SOURCE, `deauthentication.c`). AntiHunter: reads bytes 24–25 as reason with only `len < 26` and the Retry bit checked, no Protected Frame check in that function (audit item kept) | none |
| Disconnect-burst detector | AntiHunter `detect.cpp` constants and `handleDeauthFrame`/flood path | **Independent**, thresholds recorded as hypotheses with provenance | Portable idea, non-portable code: `PsramMap` (`heap_caps_malloc(MALLOC_CAP_SPIRAM)`), `std::recursive_mutex g_mtx`, Arduino `String`, `Serial.printf`, SD logging, mesh and `attacker_kick` calls are interleaved with the counting. Constants at `c6ef921`: `DEAUTH_PAIR_WIN_MS=1000`, `DEAUTH_PAIR_THRESH=12`, `MAX_DEAUTH_PAIR_MAP=96`, `DEAUTH_FLOOD_WIN_MS=10000`, `DEAUTH_FLOOD_THRESH=20`, `DEAUTH_RATE_GAP_MS=150`, `DEAUTH_ALERT_COOLDOWN_MS=60000`, `DEAUTH_ATTRIB_WIN_MS=8000`; Retry-bit frames are dropped before counting. G01 `DetectorLimits` already carries 10 s / 20 / 60 s as **uncalibrated** defaults | none (ideas and numbers, no code) |
| Tool fingerprinting (`classifyDeauthTool`: reason 2 + seq 0xFFF0 → "MARAUDER", reason 14 → "MICHAEL_TKIP") | AntiHunter | **Not reused** | Names a tool from spoofable header bytes; Guardian must not present attacker identity (audit, product rule) | — |
| Baseline-change detector | AntiHunter `hashIeSet` (FNV-1a over IE ids/lengths plus RSN/HT/VHT/ExtCap/Vendor values) and `baseline.cpp` | **Independent**: adopt the idea of a stable "advertised-settings fingerprint" over validated fields, not an IE-order hash | A hash over raw IE order and vendor bytes changes on firmware updates and vendor-IE churn; Guardian compares typed `AdvertisedSettings` against the owner-approved baseline and reports *which* field changed, with uncertainty. `baseline.cpp` is 1 777 lines around SD persistence, `std::map` in PSRAM and BLE — not a parser | none |
| Evil-twin / self-clone path | AntiHunter `detect.cpp` ~1154 | **Not reused** | Compares against the device's own SoftAP SSID; a different BSSID with the same SSID is an *unexpected AP* observation in Guardian, never confirmed attacker evidence (audit item kept) | — |
| `attacker_kick` | AntiHunter `detect_features.cpp:483` | **Not reused** | Schedules RSSI tracking/trilateration; not a transmitter, not a detector (audit item kept) | — |
| Promiscuous callback and queue | AntiHunter `scanner.cpp` `sniffer_cb` (original line 2314, prepared line 2431); ESP-IDF v5.4 Wi-Fi guide | **Independent** (the G01 `espidf_adapter_sketch.cpp` pattern) | Both AntiHunter revisions call `portENTER_CRITICAL_ISR` and `xQueueSendFromISR` from the promiscuous callback, which ESP-IDF documents as running in the Wi-Fi task; they drop `sig_len < 24` and `rx_state != 0` first (retain status rejection; apply the 24-byte minimum to management-header parsing only) and cap copies at a fixed payload size (keep). G01 already specifies task-context queue calls and FCS normalisation; AntiHunter does **not** subtract the FCS from `sig_len` | none |
| Prepared-branch auth classifier (`scanner.cpp` before `sniffer_cb`, returns `wifi_auth_mode_t`) | AntiHunter `e7646f5` only (absent at `c6ef921`) | **Not reused** | Falls through to `WIFI_AUTH_WEP` whenever Privacy is set without a recognised RSN/WPA; an RSN element whose AKMs are all unknown returns `WIFI_AUTH_WPA2_PSK`; OWE transition is not considered. Exactly the "complete security classifier" the audit forbids | — |
| Advertised-settings via driver scan (`wifi_ap_record_t.authmode/pairwise_cipher/group_cipher`) | ESP-IDF `esp_wifi_scan_start` + `esp_wifi_scan_get_ap_records` | **Later adapter** (optional cross-check, not v1 evidence) | Produced inside the closed Wi-Fi blob by a scan, which retunes across channels and so opens a coverage gap on the selected channel; the enum collapses options (no PMF state, no raw suites, unknown AKMs folded). Usable only as a labelled secondary observation with its own coverage gap | none |
| AntiHunter runtime evidence (HTTP incidents/health, serial diagnostics) | AntiHunter network/CLI | **Later adapter**, per ledger step 6 | Requires detector runtime state, firmware/features, capture time and coverage in every record; `AH_SENTINEL=0` at `c6ef921` means the always-on Sentinel is compiled out there; the prepared branch compiles it in but `sentinel_startAlwaysOn()` still returns unless the user enabled it, scanning is idle and the task was created (`detect.cpp:3562`). Standalone v1 stays independent of this adapter | No AntiHunter code adopted. Reassess exact integration/distribution and applicable license terms before any future adapter; JSON alone does not settle that review |
| Display/button/power on StickS3 | M5GFX 0.2.28 `M5GFX.cpp` autodetect; M5Unified 0.2.21 PM1/Button/Power classes; ESP-IDF `esp_lcd` ST7789 (already in the retained spike) | **Independent board adapter** on `esp_lcd` + `driver/i2c_master`, with M5Unified/M5GFX pinned as the **register-sequence reference** and as the fallback renderer if G11 shows the spike's panel init is wrong on the device | Both libraries provide native ESP-IDF component build descriptions (not compiled here) (`idf_component.yml`, `CMakeLists.txt` requiring `nvs_flash efuse driver esp_timer esp_lcd esp_mm`; `__has_include(<driver/i2c_master.h>)` picks the new I2C driver on v5.4, same driver family the spike uses; coexistence and resource ownership remain untested). But M5GFX autodetect probes the PM1 over I2C and drives pins through LovyanGFX, pulls fonts and the whole LGFX engine, and M5Unified's board layer initialises speaker, IMU and RTC paths Guardian does not use. The portable canvas already renders RGB565; a renderer only needs a panel push. The PM1 register sequence in `sticks3_board.cpp` was *derived* from M5Unified/M5GFX sources (recorded in `sticks3_pins.hpp`) — the reviewer adds the full MIT notice in `THIRD_PARTY_NOTICES.md` and a source-file reference | MIT: keep copyright + permission notice where derived sequences are used; nothing in `guardian_core` |
| Host live receiver / radiotap | libwifi radiotap (ISC) | **Decide in L01** | Only relevant if the L01 receiver delivers radiotap; libwifi's FCS flag handling (`IEEE80211_RADIOTAP_F_FCS`) is a usable reference for the host adapter's FCS normalisation | ISC notice if copied |

## 3. libwifi versus SDK supplicant parser — tradeoffs

| Aspect | libwifi `c38dbc8` | ESP-IDF v5.4 `wpa_common.c` | Guardian need (G01) |
|---|---|---|---|
| Language / build | C99, CMake, builds `SHARED` and `STATIC`; compiles on macOS clang with `-std=c99` (MEASURED for `security.c`, `common.c`, `tag_iterator.c`) | C, inside the IDF component; depends on `utils/includes.h`, `os_*`, `wpa_printf`, Kconfig macros; not buildable standalone on the host without a shim | C++17, host first, then Xtensa |
| Public API | yes (`libwifi.h`) | **no** — `src/common/wpa_common.h` is a private include of the component | needs a stable boundary |
| Allocation | `malloc` per parsed beacon/deauth; caller frees | none in the IE parsers | none after construction |
| Count decoding | low byte only (MEASURED wrong) | `WPA_GET_LE16` (SOURCE correct) | LE16, bounded to 16 |
| Over capacity | silent clamp to 6, walk desynchronised (MEASURED) | n/a (bitfield union, no cap) | reject the element |
| Unknown selectors | kept as raw OUI/type in fixed arrays (good), but ignored by `libwifi_enumerate_rsn_suites` | mapped to `0` and lost | raw value + Unknown bit |
| Missing optional fields | capabilities read past the end (MEASURED over-read) | IEEE defaults applied (CCMP / 802.1X / AES-128-CMAC) | explicit "absent" vs "truncated" |
| Group-management cipher | not decoded | decoded; unsupported value rejects the element | decoded, unknown preserved |
| Zero-length IE | `next()` stops on a later zero-length IE; initial hidden SSID is a different path (MEASURED) | n/a (`for_each_element` in `ieee802_11_common.c` handles it) | continue |
| WPA and RSN kept apart | yes (`wpa_info` + `rsn_info`); combined summary mask also exists | yes (one struct per call) | yes |
| Test suite | 13 generation/parse tests, no malformed-RSN case | ESP test apps, not host-runnable here | malformed-first fixtures |
| License | Apache-2.0 | BSD 3-clause | preserve applicable terms if adopted; no blanket distribution approval |

Decision: neither candidate is adopted unchanged as Guardian's parser. Their APIs
and outputs do not satisfy the full G01 ownership and evidence contract. G04 should
still reuse appropriate bounded helpers behind adapters when justified; this is
not permission to rewrite every component without comparison.

The SDK count handling is a useful source reference, not a formally verified parser
or a behavior oracle. It also ignores trailing bytes. libwifi is only a secondary
comparison for individually vetted fixtures, including complete common RSN/WPA
examples with supported counts. “Valid input” alone is insufficient: a missing
optional field can still trigger its bounds bug. Establish expected bytes/fields
independently from the format and a second decoder/reference; never derive all
expected values from libwifi, and never weaken Guardian to match a known bug.
Keep malformed, optional-field, unknown-selector and over-capacity fixtures under
Guardian's own contract assertions. Upstream repair is outside G02.

## 4. AntiHunter: ideas worth keeping, code not portable

Kept as documented hypotheses (G06 calibrates them in L02): the two-tier
disconnect heuristic, bounded windows and cooldowns. Do NOT adopt AntiHunter's
blanket Retry-bit discard. Deduplicate only with a bounded identity/time policy;
the bit alone does not prove we received the original. Sequence numbers wrap and
can be spoofed. Likewise, a source MAC matching this device is not proof that
this device transmitted the frame. Treat attribution as unverified without
independent local evidence.

At acquisition, reject bad receive status and normalize FCS before bounded copy.
For management-header parsing require 24 readable bytes; do not make this a
universal 802.11 minimum, since control frames may be shorter. A filter must be
reported in coverage; filtered control traffic is not malformed management data.

Not portable: PSRAM-only STL allocators, recursive mutex around every detector
map, Arduino `String`/`Serial`, SD/LittleFS logging, mesh/serial fan-out and
tracking calls inside the detection path, and ISR-variant FreeRTOS calls from a
task callback. AntiHunter is AGPL-3.0; no such implementation is adopted here. Any future
copy/adaptation requires an explicit provenance and license review, rather than
a blanket claim about all integrations. Constants are attributed to the source
locations and hashes in the reviewer evidence; they remain uncalibrated.

## 5. Adapter plan

```text
firmware/components/guardian_core/      parser.hpp/detector.hpp contracts (G01)  → add parser.cpp,
                                        detectors.cpp (G04/G06, independent, no alloc)
firmware/tests/                          G03 host harness; fixtures/malformed-first (G04)
tools/oracle/libwifi/                    host-only CMake target linking $GUARDIAN_STORE/third-party/libwifi static
                                        (Apache-2.0 notices), secondary checks on individually vetted fixtures, never sole oracle
firmware/boards/sticks3/main/            acquisition adapter (ESP-IDF promiscuous → bounded pool → task queue),
                                        esp_lcd ST7789 renderer, i2c_master PM1 (MIT-derived sequence noted)
later: adapters/antihunter_evidence/     observation adapter with runtime-state/coverage requirements (ledger step 6)
later: adapters/espidf_scan/             wifi_ap_record_t as a labelled secondary observation
```

Boundaries: `FrameParser::parse(FrameSpan, RxMeta)` is the only entry; it emits
`ParseResult` values and never keeps a pointer. The acquisition adapter owns FCS
normalisation (`sig_len` includes FCS on v5.4) before the pool cap. Detectors
consume `(FrameSpan, RxMeta, ParseResult)` and `DetectorLimits`. Nothing in
`guardian_core` includes libwifi, the SDK or M5 headers.

## 6. Candidate live-test interface (pointer for L01, not qualified here)

The sibling lab already has a Bruce USB transport,
`~/dev/wifi-lab/bruce_usb.py` (pyserial at 115200, identifies the device, runs
Bruce JS via `require("serial")`, CRC-checked file transfer). It was read, not
run. It shows a scripting channel exists; whether it can start and stop a
bounded disconnect stimulus against the lab AP is L01's question. No Bruce
source was downloaded or pinned in G02.

## 7. Evidence in the store

`$GUARDIAN_STORE/evidence-raw/G02-20261113/libwifi-spike/`:
`rsn_bounds_spike.c`, `run.log` (cases `short`, `count256`, `seven`, `nocaps`),
`zero_len_tag_spike.c`, `run-zero-len.log`, each log headed by the libwifi
commit and the sha256 of every compiled libwifi file. The worker's `exit=141`
comes from a `head` pipeline: those reports are truncated, not complete, although
the visible summaries establish the reported over-reads. The supervisor reran all
five cases without a truncating pipe and added two controls. See
[the G02 validation record](../G02-validation.md). Scratch binaries are disposable.

## 8. Remaining uncertainties

- No candidate was compiled for Xtensa in this task; "native compatibility" for
  M5GFX/M5Unified is from their component manifests and source, not a Guardian
  build.
- The prepared AntiHunter rebase is in `/private/tmp`; if it disappears, the
  patch in `validation/` preserves only the delta from upstream `c891485`.
- libwifi `main` has no tag for 0.0.10/0.0.11; the pin is the commit hash.
- Whether the L01 receiver delivers radiotap (and therefore whether the ISC
  radiotap code matters) is unknown until L01.
- Detector thresholds above are AntiHunter's choices for its hardware and are
  unvalidated for Guardian's channel dwell; L02 measures them.

## 9. Other requested references

Keep [Wi-Fi Guardian](https://github.com/jeffreyesdavid/wifi-guardian) and
[PocketLab-StickS3](https://github.com/Withphildev/PocketLab-StickS3) in the existing
[research index](research.md). They remain product/architecture references, not
adopted dependencies in G02: Wi-Fi Guardian informs approved baselines and alerts;
PocketLab informs surveys, signal history and power/UX. Neither establishes our
portable raw-frame parser or a validated live receiver. No code from either is
copied by this task; adoption would require a pinned source/license review first.

## 10. Full AntiHunter detector map (2026-11-16, owner request after an Evil Cardputer probe attack)

AntiHunter `~/dev/AntiHunter` at commit `c6ef921`, **AGPL-3.0-only** (vendored Open Drone ID
files Apache-2.0). Policy unchanged: **no code copied**; behaviour and constants re-implemented
independently as uncalibrated hypotheses (TUNE parameters), calibrated by live Evil Cardputer runs
and a ≥12 h benign soak. Numbers refer to the 32-detector inventory (`full/src/`, mostly
`detect.cpp`, `detect_features.cpp`). Sentinel and BLE attack checks are compiled out in its
default build (`AH_SENTINEL=0`, `AH_CS_BLE=0`).

| # | AntiHunter detector | Guardian decision | Task |
|---|---|---|---|
| 1, 3 | Deauth flood per source / pair / broadcast | Adopt idea; area scope added to today's selected-BSSID burst; never read Protected reasons; retries deduplicated (not blanket-dropped) | G16F |
| 2 | Deauth tool fingerprints (Marauder/MDK4/aireplay/bettercap) | Reject (spoofable bytes; never name a tool) | — |
| 4, 6 | EAPOL bait / handshake reconstruction after deauth | Adopt narrowed: selected network only, worded "pushed off and reconnected (a handshake was exchanged)" | G16G |
| 5a, 5d | PMKID harvest (M1 without M2 across ≥3 BSSIDs), zero-ANonce fake M1 | Adopt (data path, after load spike) | G16G |
| 5b, 5c | hcxdumptool replay counter / Marauder fixed PMKID | Reject (tool naming) | — |
| 7 | Auth flood | Adopt | G16F |
| 8 | SAE commit flood (Dragonblood DoS) | Adopt | G16F |
| 9 | Assoc-sleep | Adopt | G16F |
| 10 | Beacon flood (RSSI-gated) | Adopt | G16F |
| 11 | Beacon forgery | Adopt the factual signals only (SSID rotation, open lure portal); reject fixed-byte tool signatures | G16F |
| 12 | CSA / Quiet abuse | Adopt | G16F |
| 13 | Evil twin variants | Keep G06 `UnexpectedAp`; self-clone path rejected (no own AP) | G06 |
| 14 | OWE transition abuse | Adopt | G16F |
| 15 | SSID confusion (CVE-2023-52424) | Adopt with the hidden NUL-SSID false positive fixed | G16F |
| 16 | Probe floods (random, single MAC, per SSID) | Adopt | G16F |
| 17 | KARMA/MANA | Adopt passive half (one transmitter answering many SSIDs); reject bait transmission | G16F |
| 18 | Pwnagotchi beacon | Adopt | G16F |
| 19 | FragAttacks | Defer (data volume vs S3 loop; revisit with G16G numbers) | — |
| 20 | Jamming (PDR + FCS errors) | Adopt; frame-loss jamming only, limits stated | G16G |
| 21 | SoftAP-based attacks | Reject (Guardian runs no AP) | — |
| 22, 23 | BLE popup/pairing spam, malformed adverts | Candidate after coexistence spike | G16H |
| 24, 25 | Drone Remote ID, RID spoof | Reject (not home defence; spoof check needs GPS) | — |
| 26, 27, 29 | MAC-randomization identity linking, recon score, probe watch lists | Reject (tracking people, not defending the home) | — |
| 28 | Baseline anomaly via active scans | Reject (transmits); G06 approved-baseline stays | — |
| 30–32 | Mesh guard, quorum, triangulation / attacker_kick | Reject (needs mesh/GPS; not a detector) | — |

Wording rule for all adopted detectors: observations with count, window and uncertainty
("seen nearby", "on your network"); never "hacked", never an attacker's identity or tool.

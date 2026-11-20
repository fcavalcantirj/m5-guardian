# G04 — bounded portable Wi-Fi security-frame parsing (worker handoff, 2026-11-14)

## Supervisor review — 2026-11-14

G04–G07 passed independent host review after in-scope fixes. See
[G04–G07 validation](G04-G07-validation.md) for the failing regressions,
normal/sanitized results and limits. The original worker record below is
historical; it is not the acceptance record. No RF/device effectiveness is claimed.


Worker deliverable for ledger entry G04. **Pending independent review**; nothing
here is accepted, no device was flashed, no radio was used, every input is a
hand-assembled `Origin::Imported` fixture. Labels: **MEASURED** = executed on this
Mac (Apple clang 21.0.0, cmake 4.1.2) with the log in the store; **SOURCE** = read in
the cited code or standard; **LIMIT** = known gap left for its owner.

Evidence root: `$GUARDIAN_STORE/evidence-raw/G04-worker-20261114/`
(red/green logs, mutation check, libwifi probes, hashes). Reviewer build trees and
per-executable logs: `$GUARDIAN_STORE/builds/<run>` (see section 7).

## 1. What was built

| File | Role |
|---|---|
| `firmware/components/guardian_core/include/guardian/security_parser.hpp` | public header: `SecurityFrameParser final : FrameParser`, `make_selector()`, OUI constants, the binding status/default rules |
| `firmware/components/guardian_core/parser.cpp` | the independent implementation (no libwifi, SDK or AntiHunter code; IEEE 802.11-2020 clauses cited inline) |
| `firmware/components/guardian_core/include/guardian/parser.hpp` | G01 contract, additive change only: two documented `ParseError` outcomes, `SuiteCountZero` and `BadElementLength` |
| `firmware/tests/parser_check.cpp` | 67 behavior cases, written and run RED first (section 3) |
| `firmware/tests/fixtures/make_fixtures.py` + 15 new `.hex` | OWE/OWE-transition, WPA vendor, WPA+RSN, version-only RSNE, PMKID+group-management, PMF inconsistent, four pairwise suites, unknown AKM, duplicate conflict, later empty element, probe response, HT Control header, non-UTF-8 SSID, BIP deauth with MME, protected unicast deauth; the ten G03 fixtures are byte-identical |
| `firmware/tests/parser_oracle_libwifi.cpp` + CMake option `GUARDIAN_LIBWIFI_DIR` | opt-in host-only differential check against the pinned libwifi (section 5) |
| `firmware/CMakeLists.txt`, `components/guardian_core/CMakeLists.txt`, `firmware/tools/host-check.sh` | `parser.cpp` in both builds; `parser_check` target; oracle option and `GUARDIAN_LIBWIFI_DIR` passthrough; new executables in the per-exe log list |
| `firmware/tests/fixture_loader_check.cpp` | one rule relaxed: a deauth fixture may be longer than 26 bytes (the MME fixture) |
| `THIRD_PARTY_NOTICES.md`, `README.md`, `docs/contracts.md`, `firmware/examples/README.md` | libwifi notice (host-only oracle), pointers to this document |

No other production file changed. `core.cpp`, presenter and canvas are untouched.

## 2. Parser rules (binding, each one has a test)

Input: a `FrameSpan` starting at Frame Control, **FCS already removed by the
adapter** (guardian/radio.hpp). The parser never adapts ESP-IDF `sig_len`; that
is G13's acquisition adapter. `RxStatus::FcsError` -> `Malformed/FcsFailed` and
`DriverError` -> `Malformed/ReceiveFailed` before any byte is read.
`RxStatus::Unknown` is parsed structurally; the checksum uncertainty stays in
`RxMeta` for G05.

Frame control: protocol version != 0 -> `Unsupported/UnsupportedVersion`.
Control frames -> `Unrelated`, `header_valid=false`. Data frames -> `Unrelated`
with header addresses and the BSSID chosen by To/From DS; an unprotected
LLC/SNAP `88-8E` body -> `FrameKind::EapolData`, `Unsupported` (body not decoded).
Management header is 24 bytes, 28 with the Order bit (HT Control); shorter ->
`ShortMacHeader` (`Truncated` when `FrameSpan::truncated`, else `Malformed`).
Addresses, sequence/fragment, Retry and Protected bits are reported as received
(spoofable facts about bytes, never identity). `identity.bssid` = Address 3.

Beacon / Probe Response: 12-byte fixed body or `ShortFixedBody`. Privacy =
Capability bit 4. Element walk validates `id,len` against the remaining span
before every read; an element claiming more than remains -> status `Truncated`,
`IeOverrun`, earlier elements keep their state (an unread RSNE becomes
`ElementState::Truncated`). A dangling single byte is also `Truncated`. The
adapter's `truncated` flag demotes a clean decode to `Truncated`. Zero-length
and unknown elements are skipped by length (the G02 libwifi iterator defect is a
counterexample fixture).

| Element | Rule |
|---|---|
| SSID (0) | 0 bytes or all-zero bytes -> `Hidden` (length kept); otherwise `Present`; `ssid_utf8` = strict RFC 3629 validity only; bytes copied exactly, no substitution; > 32 bytes -> `Malformed/BadElementLength`, identity cleared; conflicting duplicate -> `DuplicateConflict`, identity cleared; identical duplicate tolerated |
| DS Parameter (3) | exactly 1 byte else `BadElementLength`; conflicting duplicate -> `DuplicateConflict`; value reported raw (capability check is G05) |
| RSNE (48) | version must be 1; fields in 9.4.2.24 order; every field after Version optional **at the end only**; absent fields take the standard defaults (CCMP-128 / {CCMP-128} / {802.1X} / caps 0 -> PMF Disabled / BIP-CMAC-128) with `SuiteSelector::present=false` for defaulted selectors; count 0 -> `SuiteCountZero`; count > 16 or count*4 > remaining -> `SuiteCountOverflow` (whole element rejected, never a prefix); field cut inside -> `BadElementLength`; MFPR without MFPC -> `PmfInconsistent`; PMKID list bounded by the element, not stored; trailing bytes after the group management cipher -> `BadElementLength`; conflicting duplicate -> `Conflicting`, zeroed |
| WPA vendor (221, 00-50-F2 type 1) | same machinery, WPA selectors, defaults TKIP / {TKIP} / {802.1X}, optional 2-byte capabilities as the last field, `pmf` stays `Unknown`, no group management |
| OWE Transition (221, 50-6F-9A type 28) | BSSID(6) + SSID length(1) + SSID(<=32) + optional band/channel(2) exactly; else `Malformed`; state only, pair identity not stored |
| Vendor (221) shorter than 3 bytes | `Malformed/BadVendorOui` (strict; see LIMIT in section 8) |
| Other vendor / other ids | skipped by length |

Selectors keep their raw 32-bit value (OUI<<8 | type); unmapped ones add the
`Unknown` bit. 00-0F-AC:0 is `UseGroup` in a pairwise list and `Unknown` as a
group cipher. `settings_present` = privacy valid or any Valid element or a DS
channel. `settings_complete` = `status == Complete` and no `Unknown` kind in any
Valid element and OWE transition Absent or Valid. **The parser never emits an
open/WEP classification**; a Malformed or Truncated frame cannot reach
`settings_complete`, and a privacy-only Complete beacon is a fact for G05, not a
WEP verdict from a parse failure.

Deauthentication / Disassociation: Protected bit -> `Unsupported`,
`reason_readable=false` (encrypted unicast body). Otherwise 2-byte reason then
an element walk: vendor elements allowed, Management MIC element (76) must be 16
or 24 bytes. `reason_readable` is true when the fixed body was present and no
rule failed (a cut tail stays readable, a malformed tail does not). Readable is
**structural only, never MIC-verified** (BIP needs the IGTK). Association,
Authentication, Action and other management bodies -> `Unsupported` with a valid
header.

Allocation: none (the test replaces `operator new` with `abort()` while parsing
every fixture). No pointer into the frame survives the call (`ParseResult` is
trivially copyable, G01 static_assert). Arithmetic is on `std::size_t` with
explicit remaining-byte checks; no pointer is compared after an add.

## 3. TDD record (MEASURED)

1. `before-sha256.txt`: hashes of every `firmware/` source before this task.
2. `security_parser.hpp` and a stub `parser.cpp` returning `ParseResult{}` were
   written first, then `parser_check.cpp` (66 cases) and the new fixtures.
3. **RED**: `red-parser_check.log` — 66 cases run, **65 failed**, 443 failed
   assertions, exit 1, against the stub (`red-sources-sha256.txt` pins the stub
   and the test file). The one passing case is the mutation sweep, which checks
   invariants a default result satisfies trivially; it exists for sanitizer
   coverage, not as a specification.
4. Implementation written; first run `green-attempt1-two-test-expectation-errors.log`:
   64/66, two **test** expectations were wrong against the G01 contract text and
   were corrected (not the parser): a declared count of 3 with exactly 12 bytes
   left is structurally plausible (now asserted as Complete-but-Unknown, with a
   count of 4 as the real overflow), and a cut inside a suite *list* is
   `SuiteCountOverflow` by the contract's own definition, not `BadElementLength`.
5. **GREEN**: `green-parser_check-after-test-corrections.log` 66/66; the
   mutation check (section 4) found one untested rule, a 67th case was added,
   `green-parser_check-final-plain-scratch.log` 67/67, 9303 assertions.
6. Refactor: none needed beyond the header comment; the code is as first written.

Iteration used a disposable cmake tree in `/tmp` (deleted at the end, as the G03
worker did); the reviewer-grade runs are the store trees in section 7.

## 4. Mutation check: the tests bite (MEASURED, `mutation-check.log` / `.sh`)

Fourteen deliberate defects on throwaway copies of `firmware/`, each built and
run with `parser_check`; an unmodified control copy passes.

| Mutant | Edit | Result |
|---|---|---|
| m1 | drop the `count > 16` bound | caught: count_above_capacity_rejects_the_element… |
| m2 | read the suite count from the low byte only (libwifi's defect) | caught: pairwise_count_256_fixture… |
| m3 | drop the MFPR-without-MFPC check | caught: pmf_required_without_capable…, malformed_rsn_does_not_erase… |
| m4 | stop the walk at a zero-length element (libwifi's defect) | caught: later_zero_length_element… |
| m5 | accept a conflicting duplicate RSNE/WPA silently | caught: duplicate_rsn…, conflicting_duplicate_wpa… |
| m6 | accept count 0 | caught: zero_suite_counts… |
| m7 | report an adapter-truncated frame as Complete | caught: adapter_truncation_flag… |
| m8 | trim an oversized SSID to 32 bytes (libwifi's behavior) | caught: oversized_ssid_element… |
| m9 | drop the bounds check before the group management cipher | **survived the plain build** (an over-read that lands on the trailing-bytes check gives the same verdict); caught under **ASan** (`mutant-m9-asan.log`, container-overflow). A 67th case `group_management_cipher_cut_inside_is_bad_element_length` was added as its witness; under plain it is equivalent, so the sanitized reviewer run is the gate for this class |
| m10 | recognise EAPOL inside a protected data frame | caught: eapol_data_is_recognized… |
| m11 | ignore the Order bit (24-byte header) | caught: order_bit_means_a_28_byte_header… |
| m12 | keep the reason readable after a malformed tail | caught: group_deauth_with_mme… |
| m13 | drop the element-overrun check | caught: truncated_rsn_fixture…, deauth_trailing_element_overrun… |
| m14 | read the Privacy bit from bit 0 | caught: open_beacon_fixture… |

## 5. Independent decoder: libwifi differential oracle (MEASURED)

`tshark`, Wireshark and `scapy` are still not installed on this Mac; installing
them is the owner's call (G03 LIMIT). This task instead makes the G02 plan
executable: an opt-in host-only target compiles the pinned libwifi checkout on
the store (`c38dbc8`, Apache-2.0; no code copied; never linked into `guardian_core`)
and `parser_oracle_libwifi` compares it with Guardian on **14 vetted fixtures**
that none of libwifi's measured defects can touch (counts <= 6, RSN capabilities
present, no empty element before the RSNE): BSSID, transmitter/receiver (beacons;
`libwifi_parse_probe_resp` fills only the BSSID, SOURCE), SSID bytes and hidden
flag, DS channel, WPA/RSN presence, group/pairwise/AKM selectors one by one,
version, and PMF derived from libwifi's raw capabilities. Result: **4 cases, 182
assertions, 0 failures**, plain and ASan/UBSan (`oracle-libwifi-*-scratch.log`,
and the store run in section 7). The known iterator defect is pinned as an
asserted disagreement so a future pin change is visible.

Two **new libwifi observations** (MEASURED, `libwifi-dump-*.c/.log`), recorded
for the G02 decision table, not fixed here:

- `libwifi_check_capabilities(x, cap)` is `(BYTESWAP16(x) & (1 << cap))`
  (`core/misc/types.h:199`). On this little-endian host the Privacy bit of
  capability `0x0011` is tested in the wrong byte: a privacy-only beacon gets
  `encryption_info == 0`, not WEP. The G02 spike pre-set WEP by hand, so its
  "WEP retained" statement describes the tag parser, not `libwifi_parse_beacon`.
- Through the full `libwifi_parse_beacon` path the later-empty-element fixture
  returns success with no RSN record and no WPA2 flag (and, because of the point
  above, no WEP flag either).

The oracle confirms Guardian's reading of the vetted fixtures by an unrelated
implementation; it does not replace a tshark/scapy comparison if the reviewer
wants one, and it cannot vouch for the malformed-case expectations (those rest
on Guardian's contract and the standard).

## 6. Running it

```sh
firmware/tools/host-check.sh                      # plain + ASan/UBSan, no third-party code
GUARDIAN_LIBWIFI_DIR=$GUARDIAN_STORE/third-party/libwifi firmware/tools/host-check.sh
                                                  # same, plus the libwifi oracle target and its log
<build>/parser_check --list                       # case names; <build>/parser_check <case> runs one
python3 -I firmware/tests/fixtures/make_fixtures.py   # regenerates the 25 fixtures byte-identically (MEASURED)
```

## 7. Reviewer-grade run in the store (MEASURED)

`GUARDIAN_LIBWIFI_DIR=… GUARDIAN_JOBS=8 firmware/tools/host-check.sh all`,
trees and logs in `builds/20261114-112252-host-BFimOH/`:

`host-check exit=0`; `SHA256SUMS` over the 25 log/metadata files verifies
(`shasum -c`, 25 OK); `toolchain.txt` source hashes equal the repository's
`components/`, `tests/`, `examples/` and `CMakeLists.txt` files except
`examples/README.md`, a documentation file edited after the run started (no code
differs). Wall time about 20 min on the SMB share (plain configure ~4.5 min, the
oracle adds a C-compiler probe and 37 third-party translation units).

| Flavour | ctest | parser_check | parser_oracle_libwifi | fixture_loader_check | other targets |
|---|---|---|---|---|---|
| plain | 16/16 passed | 67 cases, 9303 assertions, 0 failed | 4 cases, 182 assertions, 0 failed | 6 cases, 434 assertions | contracts, baselines, headless_replay, framework probes, portability_check unchanged and green |
| ASan + UBSan, no recovery | 16/16 passed, **no sanitizer report in any log** | same | same | same | same |

The byte-mutation sweep (every byte of six fixtures x 8 values, every prefix
length, with and without the adapter truncation flag; about 3700 parses) ran
under the sanitizers as part of `parser_check` with no report.

## 8. Limitations and open points (LIMIT)

- **Policy decisions deferred to G05**: the parser reports facts (`privacy_bit`,
  per-element validity, `Unknown` kinds, OWE transition state); open/WEP/grade
  derivation, the weakest-advertised rule and capability checks are not here.
  `SecurityObservation` is not produced by this task; `headless_replay` still
  uses its stand-in.
- **Strictness choices that live traffic may challenge**: a vendor element
  shorter than 3 bytes, trailing bytes after the last RSNE field, and a
  malformed MME all make the frame `Malformed` (never a grade). Real APs with
  nonconformant elements would show as ungradeable rather than misread. L02
  measures whether this happens on the lab AP; relaxing any rule is an explicit
  documented decision, not a silent change.
- **Defaults**: absent RSNE/WPA fields are filled with the standard defaults and
  flagged `present=false` (selectors) / count 1 (lists). G05 decides whether a
  defaulted 802.1X AKM is graded like an advertised one.
- **BIP**: a group-addressed deauth with an MME is structurally readable; the MIC
  is never verified and the Protected-bit-clear convention for BIP is from the
  standard (SOURCE), not from a capture.
- **Data frames**: only header identity and EAPOL recognition; QoS/A-MSDU/HT
  variants beyond the header-length rules are not decoded; 4-address frames get
  no BSSID.
- **No independent decoder beyond libwifi**: see section 5.
- **No live or board evidence**: fixtures are hand-assembled from the standard;
  acquisition metadata (`RxMeta`) is synthetic in every test. L01/L02 and G13 own
  the real-frame proof.
- **Element id 255 (extension) and HT/VHT/HE operation**: skipped by length;
  not needed for advertised security settings.

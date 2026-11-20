# G03 — host build and reviewer validation harness (worker handoff, 2026-11-14)

Worker deliverable for ledger entry G03, followed by supervising corrections.
See [G03 validation](G03-validation.md) for independent acceptance and the
updated 14-test harness; the worker results below remain historical evidence. Everything below was run on this
Mac (Apple clang 21.0.0, cmake 4.1.2); nothing was flashed, no radio was used,
no fixture is a capture. Labels: **MEASURED** = executed here with the log on
the store; **SOURCE** = read in the code; **LIMIT** = known gap, left for its owner task.

## 1. What the host build now is

`firmware/CMakeLists.txt` builds the portable layers on the host without ESP-IDF
or M5Stack and links every test against those real libraries.

| Target | Kind | Sources | Purpose |
|---|---|---|---|
| `guardian_core`, `guardian_presenter`, `guardian_canvas` | static libraries | the same `components/*/` sources the ESP-IDF component CMakeLists register | the production library, host-compiled |
| `guardian_header_selfcontained` | object library | one generated TU per public header | each header compiles alone, `-Werror` |
| `guardian_test_support` | static library | `tests/support/check.{hpp,cpp}`, `tests/support/fixtures.{hpp,cpp}` | 90-line check framework (no download, no license) + strict hex fixture loader; host-only, never linked into firmware |
| `contracts` | test executable | `tests/contracts.cpp` (the formerly missing target) | G01 contract checks with counterexamples; 18 cases |
| `core_baseline` | test executable | `tests/core_baseline.cpp` | honest baseline of the draft `Core`/`assess()`; 27 cases incl. 3 `KNOWN_LIMIT_*` |
| `presenter_baseline` | test executable | `tests/presenter_baseline.cpp` | baseline of `present()`; 10 cases incl. 1 `KNOWN_LIMIT_*` |
| `canvas_baseline` | test executable | `tests/canvas_baseline.cpp` | baseline of RGB565 canvas + 5x7 glyphs; 10 cases |
| `fixture_loader_check` | test executable | `tests/fixture_loader_check.cpp` | loader strictness + every fixture matches its declared metadata; 6 cases |
| `headless_replay` | executable + ctest | `examples/headless_replay.cpp` | the G01 pipeline example now links and runs; ctest asserts its final stale/historical line |
| `portability_check` | ctest (cmake script) | `tests/portability_check.cmake` | portable sources include only `guardian/*.hpp` and 9 allow-listed std headers; no SDK identifiers outside comments |

A test run exits non-zero on any failed assertion, on zero registered cases or
on zero executed assertions (`check.cpp`), so an empty harness cannot pass.
`<exe> --list` prints case names; `<exe> <case>` runs one case.

Warning policy: libraries and the example keep the policy G01 was reviewed under
(`-Wall -Wextra -Wpedantic -Werror`). New test code adds `-Wshadow -Wconversion
-Wsign-conversion`. **Finding (SOURCE, not fixed):** `guardian_canvas` has six
`int -> size_t` implicit conversions (`canvas.hpp:37`, `canvas.cpp:9,14,25`) that
`-Wsign-conversion` rejects; changing library code for warnings is outside G03,
so `canvas_baseline` relaxes that one flag. Owner: G10/G11 renderer work, or a
deliberate hygiene step the assistant approves.

Nothing in `components/` was modified by this task.

## 2. Reviewer commands

```sh
firmware/tools/host-check.sh            # plain + ASan/UBSan: configure, build, ctest, per-exe logs -> the store
firmware/tools/host-check.sh asan       # sanitized flavour only
firmware/tools/host-check.sh print      # the raw cmake/ctest commands, runs nothing
```

Raw equivalents (`<out>` = `$GUARDIAN_STORE/builds/<stamp>-host`):

```sh
cmake -S firmware -B <out>/build-plain -DCMAKE_BUILD_TYPE=Debug
cmake --build <out>/build-plain -j 4
ctest --test-dir <out>/build-plain --output-on-failure
cmake -S firmware -B <out>/build-asan -DCMAKE_BUILD_TYPE=Debug -DGUARDIAN_SANITIZE=ON
cmake --build <out>/build-asan -j 4
ctest --test-dir <out>/build-asan --output-on-failure
```

New driver runs use a unique `<stamp>-host-<suffix>` directory. Configure/build
failures stop that flavour immediately; failed or missing per-executable logs
cannot produce success. See G03 validation for the failure-injection evidence.

`GUARDIAN_SANITIZE=ON` adds `-fsanitize=address,undefined -fno-omit-frame-pointer
-fno-sanitize-recover=all -g` to every library, test and the example (verified in
`CMakeFiles/*/flags.make`). The script fails closed without the smbfs mount and
the `.guardian-store-root` sentinel and never relocates to the Mac disk.

## 3. Evidence in the store

| Path under `$GUARDIAN_STORE/` | Content |
|---|---|
| `builds/20261114-001140-host/` | **worker baseline run**: `toolchain.txt` (compiler, cmake, sha256 of every source), `commands.txt`, `configure-*.log`, `build-*.log`, `ctest-*.log`, `run-<flavour>-<exe>.log` (full per-case output), `summary.txt`, `SHA256SUMS`, both cmake trees |
| `builds/20261114-000719-host/` | first real run, kept as the record of a script defect: `configure-plain.log` is empty because macOS `/bin/bash` 3.2 treats `"${empty_array[@]}"` under `set -u` as unbound (`extra[@]: unbound variable`); plain flavour never configured, sanitized flavour ran. Fixed in `host-check.sh` (scalar flag), re-proved with the exact sequence against a fake store root before the re-run. |
| `evidence-raw/G03-worker-20261114/mutation-check.log` + `.sh` | 8 deliberate defects on throwaway copies, each detected (section 5) |

## 4. Results (MEASURED)

Accepted run `builds/20261114-001140-host/` (`host-check.sh all`, exit 0,
`SHA256SUMS` over 21 files verified with `shasum -c`; `toolchain.txt` source
hashes equal the repository files).

| Flavour | ctest | contracts | core_baseline | presenter_baseline | canvas_baseline | fixture_loader_check | headless_replay |
|---|---|---|---|---|---|---|---|
| plain | 7/7 passed | 18 cases, 126 assertions | 27 cases, 87 assertions | 10 cases, 48 assertions | 10 cases, 699 assertions | 6 cases, 186 assertions | 8 output lines, final line stale + historical |
| ASan + UBSan, no recovery | 7/7 passed, no sanitizer report | same | same | same | same | same | same |

The pre-existing library compiled under `-Wall -Wextra -Wpedantic -Werror` and
linked into every test on the first attempt; the only compile failures during
the task were in new test code and in the stricter warning experiment (section 1).
The baselines passed on their first run, as expected for a baseline; the
mutation check (section 5) is the evidence that they are not vacuous.

Scratch iteration note: test-code typos were shaken out in a disposable cmake
tree under `/tmp` (deleted afterwards). No artifact was stored on the Mac; the
evidence runs above are the store trees.

## 5. Mutation check: the harness bites

Each mutant is one edit on a throwaway copy of `firmware/`; the named test target
must fail (`evidence-raw/G03-worker-20261114/mutation-check.log`). All 8 detected,
unmodified control copy 7/7 green.

| Mutant | Edit | Caught by |
|---|---|---|
| m1 | `Core::snapshot`: fresh window `<` -> `<=` | `core_baseline` security_fresh_under_30s_then_stale_and_ungraded |
| m2 | `Core::security`: drop the origin check | `core_baseline` security_ignored_when_origin_differs_from_core_origin |
| m3 | `present()`: celebrate during an incident | `presenter_baseline` incident_overlay_beats_celebration_and_keeps_the_face |
| m4 | `Canvas::put`: remove clipping | `canvas_baseline` put_and_get_clip_outside_the_canvas (guard buffer) |
| m5 | flip the RSNE id byte in a fixture | `fixture_loader_check` every_fixture_matches_its_declared_metadata |
| m6 | `Network::operator==`: ignore `ssid_size` | `contracts` network_equality_is_byte_identity. **This mutant survived the first version** of the test (the "shorter SSID" counterexample failed for the wrong reason: the next byte differed). A length-only counterexample (same bytes, length 4 vs 5) was added; now caught in both directions. |
| m7 | `ChannelSet::contains`: always read band 0 | `contracts` channel_set_tracks_channels_per_band_without_aliasing |
| m8 | `assess()`: grade anything not Unrelated | `contracts` incomplete_parse_never_grades_even_with_strong_fields |

## 6. Fixtures: provenance and limits

`firmware/tests/fixtures/*.hex` are **hand-assembled from IEEE 802.11-2020**
(clauses cited per field inside each file) by `make_fixtures.py`, standard
library only, deterministic (regenerated twice, identical sha256). No capture,
no third-party parser output, no pcap. Format: `#` comments, hex pairs, and
`# expect.<key>: <value>` metadata (length, first byte, BSSID at offset 16, RSNE
offset, reason code, retry bit) that `fixture_loader_check` asserts against the
bytes. The loader is strict: odd nibbles, non-hex tokens or run-together bytes
are errors, never a silently shorter frame. Fixture bytes are FCS-free, as a
`FrameSpan` requires, and are `Origin::Imported` by definition.

| Fixture | Bytes | What it scaffolds | sha256 |
|---|---|---|---|
| `beacon_open` | 55 | Privacy clear, no RSNE | `8c72f30d…da094d` |
| `beacon_wpa2_ccmp_pmf_optional` | 77 | RSNE PSK/CCMP, MFPC only | `0159e17f…66d873` |
| `beacon_wpa3_sae_pmf_required` | 77 | RSNE SAE/CCMP, MFPC+MFPR | `f03a0e9e…54fd4` |
| `beacon_hidden_ssid_wpa2` | 73 | initial zero-length SSID then RSNE (G02 control succeeds; its bug concerns a later empty IE) | `ffec692889e8008d3746afe2d171169ef80a74a048184af570621dac070042c8` |
| `beacon_rsn_truncated_ie` | 71 | RSNE length 20, frame ends 6 bytes early (counterexample) | `3babf143…7a91d` |
| `beacon_rsn_pairwise_count_256` | 77 | pairwise count `00 01` = 256 LE with one suite (G02 libwifi finding, counterexample) | `93f52f52…48be9e` |
| `beacon_wpa2_mixed_tkip` | 81 | group TKIP, pairwise CCMP+TKIP, no PMF (weakest-advertised case for G05) | `39cbaada…cf7876` |
| `deauth_reason7` | 26 | unprotected deauth, reason 7 | `735afd5a…b15689` |
| `disassoc_retry_reason8` | 26 | Retry bit set, same sequence as the deauth (G06 dedupe scaffolding) | `b485406a…574126` |
| `mgmt_header_short_23` | 23 | one byte short of a management header (counterexample) | `b4741f35…1dfdc8` |

Full hashes: `shasum -a 256 firmware/tests/fixtures/*.hex` (also in each
build's `toolchain.txt`). `make_fixtures.py` sha256 `3b99ec9047003a40e681aa634b8996d22a3206e635dfc53eee800717882028e7`.

**LIMIT — no independent decoder was run on these fixtures.** `tshark`,
Wireshark and `scapy` are not installed on this Mac, and a read-only check of
the Pi (`LAB-PI-HOST`) found none there either. The G04 reviewer acceptance
("compare valid fields with independent decoding") therefore needs an explicit
decision: install tshark or scapy on the Mac or Pi, or decode on another
machine. Until then the "Expected G04 reading" lines in each fixture are the
author's reading of the standard, not a verified decode. The fixtures test no
parser today; `fixture_loader_check` only proves they are what they say they are.

## 7. Baseline, not TDD

`core.cpp`, `presenter.cpp`, `canvas.cpp` and `font5x7.cpp` predate the TDD rule.
The `*_baseline` suites record their current behavior; they were written after
the code and passed on the first run, which is what a baseline is. They are not
retrospective TDD evidence. Cases named `KNOWN_LIMIT_*` pin behavior that
`docs/contracts.md` §9 or `docs/review-status.md` already list as migration
items; they document, they do not endorse. Its owner task first changes/adds the
assertion for the intended behavior, observes that fail, then fixes the library:

| Case | Pinned behavior (MEASURED) | Owner |
|---|---|---|
| `KNOWN_LIMIT_channel_range_is_hardcoded_2g4_not_capability_driven` | a valid 5 GHz channel (36) is marked `Malformed` | G05 |
| `KNOWN_LIMIT_future_timestamp_blocks_later_live_samples` | one far-future `observed_at` wins every later comparison; the real sample is dropped (age reads 0, Stale, ungraded) | G05 |
| `KNOWN_LIMIT_acquired_instant_is_not_enforced_only_observed_at` | an invalid acquisition `Instant` with a plausible `observed_at` is accepted and graded | G05 |
| `KNOWN_LIMIT_demo_origin_still_celebrates` | `present()` suppresses celebration for Imported but not Demo | G08 |

Other behaviors recorded (not defects by the draft policy, listed so G05 sees
them): WPA2 with GCMP is ungraded; Transition with PMF Disabled is ungraded;
Open with a cipher set is ungraded; `set_coverage_degraded` clears the grade but
keeps `has_security`/age; the coverage overlay wins over the incident overlay
when evidence is stale (incident stays visible as a flag).

G04–G08 add behavior under recorded red -> minimal green -> refactor using this
harness. Nothing here tests the Ralph runner, by design.

## 8. SMB constraint (MEASURED)

The host build runs with its cmake tree **on the SMB share**, as the ledger asks;
no Mac fallback was added. It works, it is just slow. Measured on the sanitized
flavour, same sources, same compiler, `-j 4`:

| Phase | the store (`builds/20261114-000719-host/build-asan`, file mtimes) | Mac disk (`bash time`) |
|---|---|---|
| configure (cmake, incl. 10 header TUs) | about 2.5 min (`Configuring done (44.4s)` plus generation) | 0.47 s |
| build (3 libs, support lib, 5 tests, example, 10 header TUs) | 70 s | 2.4 s |
| ctest (7 tests) | 10 s wall, 6.1 s test time | 1.5 s |
| tree size | 186 files, 12 MB | 197 files |

Accepted run `20261114-001140-host` (file mtimes): plain configure 2 min 34 s,
build 70 s, ctest 8 s; sanitized configure 2 min 36 s, build 72 s, ctest 8 s;
whole `host-check.sh all` 7 min 52 s. The ~2.5 min configure is cmake's compiler
probing and generation writing hundreds of small files to the share (consistent
with the measured ~20 small files a minute under load noted in CLAUDE.md).

Conclusion: no toolchain or build step is prevented by the share; a full plain +
sanitized cycle costs minutes, not seconds. No decision is required to continue
G04-G08 with the trees in the store. If the assistant later prefers a faster inner
loop, that is a policy choice (an explicit scratch directory like the StickS3
build uses), not a workaround this task introduced. The two first-run
directories are small enough to keep.

## 9. Remaining uncertainties

- Independent decoder absent (section 6): reviewer decision needed before G04 acceptance.
- The supervisor replaced `PASS_REGULAR_EXPRESSION` with an exit-and-output wrapper; replay now requires exit 0 AND its exact final stale/historical line. The original worker run used the weaker regex property.
- `portability_check` is a source-text guard; the real proof of SDK independence is that the host link succeeds, which it does.
- Test support uses `<vector>`, `<string>`, `<filesystem>`; that is host test code and is excluded from the portability allow-list on purpose.
- The build trees in the store carry macOS AppleDouble `._*` shadows; the loader, the portability script and the hash lists skip them.

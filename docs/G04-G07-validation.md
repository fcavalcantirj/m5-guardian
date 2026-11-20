# G04–G07 supervisor validation — 2026-11-14

**Decision:** accept G04–G07 for their documented portable host/replay scope
once this correction package and evidence are installed. G08 remains false.
The real library was reviewed, corrected and linked into normal and sanitized
host checks. This does not accept live radio detection, board integration,
physical calibration, UI/art or the complete product.

## Defects reproduced and fixed

| Area | Failing counterexample | Correction |
|---|---|---|
| G04 cipher namespaces | Microsoft cipher selectors inside an RSNE, or RSN selectors in a WPA vendor element, were recognized as normal ciphers | Decode against the enclosing protocol namespace; retain unknown raw selectors and block a complete settings grade |
| G04/G05 management protection | A data cipher such as TKIP/CCMP in the group-management slot could still earn a positive PMF rating | Only supported BIP suites map as group-management ciphers; typed policy input also rejects data ciphers in that slot |
| G04 fragmented management input | A first fragment or continuation carrying plausible beacon bytes could be called complete | Retain the header, mark the body Unsupported; no fragment reassembly or settings inferred from a prefix |
| G04 fixture/G05 regression | HT Control was placed after the beacon fixed fields, making the parser read the wrong Privacy bit | Move it between the MAC header and fixed body; regenerate the fixture and assert Privacy plus the expected Medium rating |
| G06 source isolation | An imported observation followed by live input reached a threshold and emitted a live-labelled alert | Bind each detector to its first eligible Origin until reset; reject foreign origins before mutating time/window/cooldown state |
| G06 unverified receive | Unknown receive status contributed to a disconnect burst | Require receive-verified bytes and expose `skipped_unverified` |
| G05/G07 unverified legacy risk | Unverified TKIP bytes produced a separately “confirmed” legacy-risk finding | Preserve legacy findings across incomplete siblings only when the receiver verifies the bytes |
| G07 wording | Open Wi-Fi advice implied every application payload was readable | Distinguish absent Wi-Fi encryption from HTTPS content protection |

Ten review counterexamples failed before their corresponding implementation
fixes. Nine are recorded in `red-review.log` (parser/rating/detector/advice);
the additional unverified-legacy case is in `red-unverified-risk.log`.
Existing cases stayed green in those runs. The HT case replaces the worker's
KNOWN_DEFECT pin with the intended behavior rather than blessing the bad fixture.

Origin isolation does not authenticate wireless transmitters. Header addresses
remain spoofable. Changing live/demo/imported inputs requires resetting the
detector or using separate instances. Ticks and coverage must come from the
same adapter pipeline; those records themselves have no Origin field.

## Executed evidence

Destination after installation:
`$GUARDIAN_STORE/evidence-raw/G04-G07-review-20261114/`.
The installer archives the evidence and reviewed firmware source snapshot before
changing acceptance. The existing worker evidence is preserved.

- Normal build: **20/20 CTest entries passed**.
- AddressSanitizer + UndefinedBehaviorSanitizer build: **20/20 passed**, no
  sanitizer findings, non-recovering sanitizer flags enabled.
- Direct executable checks: parser 70 cases, rating 42, detector 32, advice 25,
  plus the existing contracts, core checks and real linked headless replay.
- Vetted libwifi comparison: 4 cases / 182 assertions, including 14 normal
  fixtures and the explicitly recorded known-decoder disagreement. The pinned
  source is host-only; it is not linked into the production library.
- Worker artifact checksums: G04 25/25, G05 29/29, G06 31/31, G07 33/33.
- Fixture regeneration is deterministic. Of 28 fixtures, only the HT Control
  fixture changes from the supplied repository snapshot.
- The repository remained byte-identical to the initial review snapshot while
  fixes/builds ran in temporary staging. No device, RF activity, Pi job, runner,
  commit or deployment was started.

Commands and compiler output are in `final-plain.log`, `final-asan.log`,
`green-plain.log`, `green-asan.log`; executable output is in `run-*.log`.
`final-verification.json` records counts and source continuity. Checksums cover
all archived payloads. The reviewer used the existing pinned libwifi source,
verified a 101-file byte copy, and made no production dependency changes.

## Source continuity and partial G08 work

The final G07 worker manifest matches 75 current firmware files. One does not:
`components/guardian_presenter/include/guardian/presenter.hpp`. Its old hash
`215959e2904610a64f2ba0a43cbebffa182a9cc40c5d627857c8d7558b81e56a`
was the 539-byte legacy header; the review snapshot contains expanded G08 draft
API declarations, hash
`8de65b215c36ca9223b4d3c661faba2a4300ce3412bf52071248a6c03ffa5825`.
These declarations were already present at review start and are preserved.
Their authorship is not inferred from the quota error. Their comments describe
intended G08 behavior, not verified implementation: the implementation file
still contains only legacy `present()`, and no `presenter_check` target exists.

The first strict source-manifest assertion caught this mismatch. After inspecting
it, the reviewer recorded it explicitly rather than treating the worker build as
proof of these new APIs. Current independent builds include the draft header and
validate G04–G07 plus legacy `present()`; they do not validate uncalled G08 methods.
G08 has no completed implementation handoff and remains unaccepted.

## Source checks and limits

The separate protocol mappings and management-cipher validation were checked
against the pinned [ESP-IDF v5.4 supplicant source](https://github.com/espressif/esp-idf/blob/v5.4/components/wpa_supplicant/src/common/wpa_common.c)
(`rsn_selector_to_bitfield`, `wpa_selector_to_bitfield`,
`wpa_cipher_valid_mgmt_group`). The management HT Control length agrees with
[Linux's `ieee80211_hdrlen`](https://github.com/torvalds/linux/blob/master/net/wireless/util.c).
These were source comparisons; no SDK/Linux code was copied into Guardian.

The libwifi oracle has known defects and covers individually vetted inputs only;
there is no claim of complete IEEE conformance. Strict malformed-frame handling,
receiver length/FCS conventions, real-world false-positive rates, thresholds,
channel coverage and cross-target resources remain for L01/L02 and later gates.
The five grades are advertised-configuration policy, not measured password
strength or a safety certificate. No claim of authenticated AP identity is made.

The G07 signal-interval work predates its recorded red test; later regression
proof is preserved without inventing TDD chronology. Existing presenter and
canvas baselines are likewise not rewritten as TDD claims.

Normal Claude/Fable independent ledger review is still incomplete. G08's saved
CLI output reports the Fable usage limit, resetting November 16 at 05:00
America/Sao_Paulo. No automatic retry, alternate account/model or external
approval is claimed. After quota availability, the owner can explicitly retry
one G08 session with `./ralph-claude.sh 1 --retry`; installing this package starts
nothing.

## Installation boundary

This session can read the project and the store but cannot write either. Review fixes
and small build trees were explicitly staged in
`/private/tmp/guardian-G04-G07-review-20261114`, not silently substituted for the
project's lasting the store storage. The guarded installer checks source hashes,
Ralph state and its execution lock, archives evidence/backups in the mounted store,
installs reviewed files and writes G04–G07 acceptance last. Before that command
runs successfully, the actual project remains unchanged and its ledger false.

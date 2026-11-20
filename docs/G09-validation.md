# G09 foundation validation — 2026-11-14

Status: **G09 accepted for portable foundation scope.** Supervisor fixes and
verification are complete; independent Codex final review returned APPROVE
FOUNDATION. The one remaining comment correction is installed. No new RF,
flashing, board integration or Ralph job was started by this review.

## Independent review and resolved findings

The owner explicitly selected Codex after Fable returned a usage-limit error and
Opus returned a provider refusal. Those were not reviews or approvals. Normal
Codex CLI, gpt-6-astra/high, read-only review, supplied source, no tool execution.
The first independent response was **REVISE FOUNDATION**, with ten findings:
`$GUARDIAN_STORE/reviews/20261114-212034-G09-codex-independent/`.
The request records source hashes and the explicit owner override; response and
CLI events are retained. No model/account substitution happened silently.

| Finding | Fix and evidence |
|---|---|
| First termination signal during cleanup could skip remaining steps. | One lifecycle-wide handler records the first SIGINT/SIGTERM; explicit acquisition checkpoints raise cancellation. Cleanup never swaps handlers and cannot replace the first signal status. Real POSIX signal checks cover normal/error cleanup and repeated signals. |
| A full stdin pipe could block before the timeout. | Nonblocking deadline-bounded pipe delivery for every host engine/emitter command. Cleanup terminates/reaps on timeout. Real child with a deliberately filled pipe reproduces the old hang and now finishes. |
| Elapsed time alone could claim post-stop RF coverage. | Independent scoped listening intervals require consecutive transport records, stable boot/loss counters, correct channel and heartbeat gaps <=1.5 s. A continuous interval spans ACK +/- clock uncertainty through at least 3 s afterward. No coverage means no stop proof. |
| Receiver close was mislabeled confirmed stop. | Command delivery, close and confirmed stopped status are separate. Matching boot, fresh sequence/time, CRC-checked kind-4 stopped status is required, within 2 s. Missing/wrong ACK fails cleanup. |
| Detector reports replaced acquisition time with a later tick. | Reports retain the triggering frame acquisition; window/cooldown time stays separate. Expired delayed triggers cannot report a current burst. |
| Settings changes pooled different APs. | Threshold, field reduction and cooldown are per BSSID. Unexpected-AP scope aggregation remains intentional. Two-AP regressions cover independent thresholds and cooldowns. |
| Absent SSID could alias a valid empty hidden SSID. | Core and picker refuse absent SSID identity; valid hidden SSID remains supported. Unrelated activity retains its own rejection classification. |
| Confirmed WEP could get WPA/TKIP advice when another element was malformed. | Preserve independently confirmed weak cipher identity before early policy returns. Parser-to-advice regression verifies WEP text and replacement advice. |
| Open OWE transition side could be described as encrypted. | New appended AdviceId distinguishes the open side advertising a counterpart. Counterpart/client connection remain unverified. Both encrypted-side fixture and derived open-side fixture are checked. |
| Legacy help banner still admitted an unqualified emitter. | Emission refuses any backend without the qualified native identity. Legacy help may still be inspected by the explicit no-TX qualification operation. |

Earlier supervisor fixes also moved partial resource initialization inside the
cleanup region, reported nonzero child exits as failure, and supplied actual
foundation implementation to the independent-review helper. Helper model override
changes instructions only, never the supplied source bytes.

Behavior regressions were run failing first where recorded (lifecycle, full pipe,
coverage, missing stop confirmation, detector timing/cross-AP counts, missing SSID,
WEP advice). Extra boundary checks were added afterward. The first OWE test
mistakenly used an encrypted-side fixture; corrected to derive the open side by
removing RSNE and clearing Privacy. That test-writing correction is not itself a
product defect. A strict signedness compile error in its vector erase was fixed.
Intermediate failing logs are preserved; only successful final builds count.

## Measured verification

- Portable source: **22/22 CTest normal and 22/22 ASan+UBSan**, including public
  header compilation, independent vetted libwifi fixture oracle and portability.
- Rebuilt actual C++ host engine, linked to the revised library. **72 Python
  live-harness/engine checks** pass, including real OS signals and full-pipe child.
  USB is simulated in fault checks; no simulated test is described as live RF.
- Review-helper checks run separately; exact evidence logs and source hashes are
  in the supervisor archive. Source files remain in this repository.
- Native emitter source is now 1.2 with a shutdown reset backstop; the previously
  installed 1.1 image has not yet been replaced. No G09 binary has been exercised on RF;
  the earlier L02 captures qualify the recorded radio path and scenarios.

## Saved live evidence re-audit

`live-reaudit.json` applies the stronger continuous-listening rule to immutable
original receiver records with source SHA-256 hashes. Scoped post-stop coverage
passes for stop-inflight-02, recovery-native-02, settings-01, related-approved-01
and related-unapproved-01. Both disconnect scenarios also satisfy the observed
stimulus-template cessation rule. Recovery's twentieth matching frame acquisition
is 3894963592 ms, exactly the original report's acquisition field; report latency
remains **315 ms** after fixing the delayed-frame semantics.

The older stop-native-02 receipt lacks a host ACK timestamp. Its stricter temporal
stop proof is **unconfirmed**; no timestamp was invented. Later stop-inflight and
recovery records supply the qualified stop evidence. Old cleanup receipts prove
command delivery only; separate final-idle device records remain the evidence of
idle state. New cleanup uses the explicit stopped-status handshake.

## Acceptance boundary and next task

Standard C++17 core/presenter contracts remain independent of ESP-IDF, Arduino,
M5 and storage. No third-party implementation was newly imported. Two AdviceIds
were appended, preserving prior enum values. Private detector bookkeeping adds
bounded per-AP cooldown slots; integrated radio/UI RAM and stack usage remain unmeasured.

Later hardware work must still verify callback/queue integration, transport loss,
RAM/stack, selected-channel coverage, persistent storage/power loss, framebuffer
ownership, PM1/NVS failures, display rotation/colors, buttons and RF-to-screen
latency. G10 repairs/builds the existing StickS3 adapter; **G11 owns flash/boot
verification**, and later tasks wire live acquisition. G10 is not a claim that the
finished device already exists. Keep all original backup images and the spike.

L02 is a bounded 2.4 GHz channel-13 lab qualification, not universal detection,
physical attacker attribution or password-strength proof. No radio FCS validation
or hard clock-drift guarantee. The adapter must reset detector state after scope
or epoch changes. Unknown cipher selectors remain ungraded. SIGKILL/power loss
cannot execute host cleanup; device deadlines remain the backstop.

Evidence destination:
`$GUARDIAN_STORE/reviews/G09-20261114-supervisor/`.
The archive preserves failing and successful checks, source snapshots, build
identities, review attempts and the raw-record audit. Ledger acceptance belongs
to the supervising assistant after the final independent disposition.

## Follow-up findings and fixes

The first follow-up (`reviews/20261114-213926-G09-codex-followup`) returned
REVISE FOUNDATION: cleanup-context entry still raced; a different second signal
could replace the first; and Privacy-set transition-only OWE still overclaimed
encryption. Both cases were reproduced failing, then fixed. The lifecycle now
uses one non-raising handler across acquisition and cleanup, preserves the first
signal, and raises only at checkpoints. Transition-only Privacy-set advertisements
are inconsistent; encrypted-side advice requires positive OWE AKM evidence.

That review also found a native AP shutdown failure cleared the deadline before
stopping Wi-Fi. The actual before/after stop() functions were extracted verbatim
and run with a fault-injected SDK stop: before aborts the assertion, after passes
and invokes reset while preserving pending state. The source image is now 1.2;
controllers refuse older versions. Host limiter/parser/wire/shutdown checks pass
under ASan/UBSan. This does not claim new firmware is installed or RF-qualified.

An authorized no-RF probe under `validation/spikes/esp32-foundation` ran the
same core/presenter on owner-approved StickS3 **LAB-STICK-1**. All ten Imported
fixture checks passed on-chip, including freshness expiry, hidden/absent SSID
identity, scoping and delayed-frame timing. PSRAM: 8,388,608 bytes; reported free
internal heap 367,191 bytes and stack headroom 9,000 bytes at the probe point.
These are probe measurements, not integrated radio/UI memory guarantees.
The original head-pointer flash was backed up in full and verified against flash
before any write. The backup and probe artifacts are in the store:
`device-backups/LAB-STICK-1-20261114-220350/` and
`builds/20261114-G09-esp32-foundation-probe/`. This is real ESP32 execution of
Imported fixtures with RF off, not new RF acceptance. The older LAB-BRUCE-STICK
backup belongs to a different unit and must not be used for this board.

Final independent review: `$GUARDIAN_STORE/reviews/20261114-214942-G09-codex-final`. It approved the corrected
foundation, not device integration or physical RF behavior of a revised binary.
The reviewer was read-only and did not run the supplied tests.

# G10 retained StickS3 adapter — validation and repairs

Status: ACCEPTED after supervisor fixes, verified native builds/archive and independent Codex approval.
G09 foundation acceptance is recorded separately. G11 physical acceptance is
not implied by a compile, transfer callback, or this document.

## Defects reproduced and fixed

- The retained app used obsolete Core constructor/snapshot signatures. Its build
  failed against the current headers; it now injects a real `esp_timer` clock
  with a per-boot random source epoch and declared 2.4 GHz channel capabilities.
- The app formerly ignored display submission status and reused one mutable
  framebuffer after a fixed delay. A tested transfer guard now owns that buffer
  through the ESP-IDF color-transfer callback and semaphore completion. Failed
  submissions/timeouts permanently revoke access until reboot. No delayed
  callback can make a failed transfer reusable. DMA memory remains allocated.
- PM1 setup errors propagate into display readiness. Four bytes of register 0
  are reported as raw response, following M5Unified's read width; its source
  does not establish a magic identity constant. The board profile is explicitly
  owner-selected, not inferred from any successful I2C response.
- PM1 setup, panel initialization, completed transfers and visible pixels are
  different facts in logs. Visible pixels stay unverified until observed.
- NVS open/read/write/commit failures cannot report successful persistence.
  A missing boot counter is handled, overflow refused, handle always closed.
  Initialization failure no longer silently erases an existing partition.
- GPIO setup failure cannot be reported as valid button input.
- Build archive creation fails for missing required images/ELF/map/sdkconfig or
  toolchain metadata. Flash-image relative paths are preserved, source and hashes
  included, and COMPLETE.json appears only after the required outputs verify.
- Clean requires a matching owner marker in a dedicated scratch/cache child.
  Root/source/unowned/symlink targets are refused. Command printers require an
  explicit port/artifact; they no longer embed another board's backup or a stale
  guessed port.

## Evidence and storage

Actual failing-before compiler log, transfer guard RED/GREEN and initial six archive/clean
checks: `/private/tmp/guardian-g10` during review; lasting bundle in the store under
`reviews/G10-20261114-supervisor` after final acceptance. Transfer checks run with
ASan/UBSan and exercise the same guard used by the native adapter. Archive tests
use temporary fixture files, never hardware. Native build and wrapper archive
are separately exercised against the installed ESP-IDF v5.4 toolchain.

The explicit scratch policy exception is `/private/tmp/m5-guardian-sticks3-build`
(or a validated dedicated override), with lasting artifacts in the store. This avoids
SMB small-file overhead and preserves the original spike's scratch tree. There
is no silent fallback if the store is missing. The default build owns its marker and
can be cleaned only through the guarded helper.

The SDK HEAD is pinned to 67c1de1e; its S3 Wi-Fi archive was already locally
modified, so the SDK is **not pristine**. Record that archive's SHA-256 and the
SDK/submodule identities with the build. This bring-up app initializes no radio;
G13 must qualify the actual chosen receive path and SDK inputs.

## Remaining physical checks

Owner-authorized current unit: LAB-STICK-1 (formerly head-pointer firmware).
It is a different unit from LAB-BRUCE-STICK in the original Guardian spike record.
Use its own full backup. The no-RF foundation probe is separate validation code,
with explicitly Imported fixtures; it is not a product receiver or UI.

Actual boot/PSRAM/NVS/transfer logs, display orientation and RGB appearance,
button presses, persistence across reboot and a recovery image belong in G11.
Live receive-to-library-to-screen behavior remains G13/G14. Do not mark those
passes based on this build or the historical host RF records.

## Chronological review repairs (resolved by final acceptance below)

Codex review `reviews/20261114-220811-G10-codex-independent` requested four fixes:
source license/provenance omission, unverified copies, incomplete flash maps and
unrecoverable dirty SDK inputs. All four are implemented. Three new checks failed
against the old archive helper; twelve focused checks now pass. The SDK guard
rejects unrelated dirty files and moved/missing recursive submodules. Exact allowed
radio-library bytes and license travel in each archive. A fresh native build,
not just incremental linking, was subsequently recorded. Follow-up approval was pending at this stage.

Owner photo/video is retained with hashes under
`evidence-raw/sticks3-20261114-220919/` in the store. It proves upright landscape and
refreshing output/full border; red and blue swatches were reversed. The RGB
element-order correction in bringup-0.3 was then verified in the next owner video.
Boot 1 reports full flash/PSRAM, passed PSRAM pattern check, PM1 response/config,
checked NVS commit, and completed display transfers. Button evidence followed later.

Second independent review (`reviews/20261114-221645-G10-codex-independent`)
found a staged-gitlink bypass and discarded canonical build path. Both were
reproduced as failing checks and fixed: superproject staged changes are rejected,
and build/size retain the validated absolute path before changing directory.
The size regression invokes the actual shell wrapper from another directory
with fake SDK commands; no hardware is simulated as evidence. All 14 helper
checks pass. Full fresh compile log: `builds/20261114-221430-65455-sticks3-build-logs`.

Bringup-0.3 was flashed to the approved unit. Its boot log shows NVS boot count 2
after count 1, preserving storage across reflash/restart. The owner's second video
confirms the RGB reversal is corrected; full border and upright text remain good.
Original media, SHA-256 and console: `evidence-raw/sticks3-20261114-221640`.
A real frame from that video and a console copy are under `firmware/evidence/`.
Button counters were zero in that second video. The third video and matching USB
events subsequently closed this check; see the G11 acceptance record.

## Final acceptance

Codex `reviews/20261114-222129-G10-codex-independent` returned
APPROVE BOARD SOURCE with no changed reviewed inputs. Its colour-documentation
note is resolved by separately reviewed owner video and serial evidence in
[G11 validation](G11-device-validation.md); the review prompt's earlier
"physically pending" wording was stale. The reviewer did not inspect hardware.

Final tooling archive: `builds/20261114-222028-80323-sticks3/`; all 20 hashes
verified and three flash images match the actually flashed corrected build
byte-for-byte. Fourteen helper regressions pass, including the two failing-first
edge cases; transfer guard passes ASan/UBSan. The earlier full fresh native build
compiled/linked successfully. No portable library source changed after G09.

Supervisor acceptance/source/evidence receipt:
`reviews/G10-20261114-supervisor/acceptance.json` in the store.

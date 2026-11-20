# G12 supervisor validation and fix

Status: **ACCEPTED** for host behavior and representative native compile/link
qualification. No new native runtime, hardware, flash or RF execution is claimed.
The worker handoff is [G12 portability](G12-portability.md).

## Independent checks

- Rebuilt both existing host qualification trees against current source, then
  reran verbose CTest: **23/23 normal and 23/23 ASan/UBSan** passed.
- Recomputed the worker native artifact manifests: **13/13 per architecture**.
  Both native source manifests matched all maintained inputs before this review's
  wrapper-only correction. The early host manifest has the documented development
  differences; it was not used as a current-source claim. The fresh supervisor
  rebuild/rerun establishes the current host result.
- Independently ran toolchain readelf/nm against four archived native ELFs:
  ESP32-S3/Xtensa core-only and presenter, ESP32-C3/RISC-V core-only and presenter.
  Verified architecture, real Core/parser/disconnect/advice symbols, and presenter
  symbols only in the presenter variants. Compile commands contain all five core
  implementations exactly once, and presenter.cpp only in its variant. Link maps
  omit Wi-Fi, canvas, M5 and PSRAM libraries.
- Read the synthetic headless, no-PSRAM/display and dual-band checks. All use
  Imported observations; synthetic channel 36 does not grant StickS3 5 GHz.
  Native main reserves 32 KiB stack for qualification, not a product memory budget.
- Portable core/presenter implementation and interfaces remain unchanged from
  the accepted foundation. No new toolchain was downloaded or SDK modified.

## Reproduced defect and repair

The wrapper recorded source hashes at startup but never checked them at the end.
It could report successful qualification after an input changed during the run.
An isolated test invokes the actual wrapper with simulated build commands: the
unchanged control passed; deliberate source mutation incorrectly passed too.

The wrapper now verifies every recorded input before writing its successful
artifact manifest and includes the SDK qualification helper in those inputs.
After the fix, unchanged inputs exit 0 and mutation exits 1. The permanent check
is `firmware/qualification/tests/source_guard_check.py`. It requires mounted the store,
rejects an outside output path, and never runs a radio, SDK build or flash.
These simulated commands test wrapper bookkeeping only, not library or hardware.

Run it from the repository root:

```sh
python3 firmware/qualification/tests/source_guard_check.py
```

The shell wrapper also passes `bash -n`. No product-library behavior changed,
so the existing behavior is an honest baseline, not retrospective TDD.

## Evidence and acceptance boundary

Supervisor logs, ELF inspection, red/green regression results, current source
manifest and acceptance receipt are in the store at:
`$GUARDIAN_STORE/reviews/G12-20261114-supervisor/`.
The worker's successful archives remain immutable under its G12 attempt.

This review independently inspected and executed checks; it is not an additional
LLM-only review. Native ELF inspection verifies the worker's recorded links, not
an independently repeated full native SDK build. Native assertions have not run
on S3/C3 for these particular qualification apps. Earlier G11 physical evidence
belongs to its own different app. That distinction satisfies G12's requested
compile/link scope; it does not accept G13 live integration.

Next: G13 implements the actual receive-to-library-to-screen path. Its controlled
live verification remains required before accepting the picker or final art.

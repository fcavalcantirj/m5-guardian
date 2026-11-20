# G12 portability qualification — worker handoff

Worker handoff below is retained as history. **Supervisor accepted G12 after
validation and an evidence-wrapper fix:** see [G12 validation](G12-validation.md).
The ledger is unchanged. G09/G10 acceptance was checked before implementation;
their supervisor records, rather than the older G04–G08 worker receipts, establish
the dependency gate. No radio, device, flash, independent-review CLI or later task
was started here.

## Scope and implementation

- `firmware/tests/qualification/profile_checks.cpp` adds shared checks of existing
  library behavior. It compiles as a core-only executable and a separate presenter
  executable on the host, and verbatim into two native ESP-IDF apps per target.
- `firmware/qualification` adds the minimal native project. It reuses the existing
  core/presenter component registrations, disables PSRAM, and excludes the canvas,
  board renderer and radio. A build property carries the selected layer through
  IDF's separate early dependency-expansion process.
- `firmware/tools/qualify-targets.sh` records commands, SDK/compiler identities,
  source hashes, build maps, ELF headers/symbols, sdkconfig and artifact hashes.
  It uses the G10 SDK guard, never downloads tools, and fails without the mounted
  external store. It has no flash, serial, RF or acceptance operation.
- `firmware/CMakeLists.txt` registers the two new host executables alongside the
  unchanged behavior suite. No portable library implementation or public API changed.

`reviewed-library-unchanged.json` compares all 21 core/presenter files (including
component registrations) with the accepted G10 source archive: every byte matches.
The G09 and G10 supervisor acceptance receipts were also inspected directly.

This is an honest baseline and portability extension for reviewed behavior,
not retrospective TDD. The initial syntax check found a missing `rating.hpp`
include in the new test; correcting it made strict core and presenter syntax
checks pass. This was a test-authoring mistake, not a product defect.

## Measured outcomes

| Profile / target | Compile and link | Executed behavior |
|---|---|---|
| Unchanged Apple arm64 host baseline | Passed, existing separate core/presenter libraries | 21/21 CTest entries |
| Expanded Apple arm64 host, normal | Passed, core-only and presenter executables | 23/23 CTest entries, including 54 core-profile and 80 presenter-profile assertions |
| Expanded Apple arm64 host, ASan/UBSan | Passed, core-only and presenter executables | 23/23 CTest entries; same 54 and 80 profile assertions |
| ESP32-S3 / Xtensa, core-only and presenter | Passed: two ELF32 EXEC links, expected Xtensa architecture | Not run on target |
| ESP32-C3 / RISC-V, core-only and presenter | Passed: two ELF32 EXEC links, expected RISC-V architecture | Not run on target |

The profile counters printed by each executable are cumulative across its three
profiles. The 54 and 80 counts above are totals, not per-profile counts.
The core archive is byte-identical between the core-only and presenter links
within each native target. The native link maps and defined symbols contain the
real Core, parser, disconnect detector, advice reducer and, where selected,
Presenter. Each compile-command archive contains all five core implementation
files and exactly one presenter implementation only in the presenter variant.
Both native component graphs omit canvas, Wi-Fi and PSRAM. This is an effective
no-PSRAM native configuration, not a measurement of a physical board's RAM.

## Evidence location and execution

Qualification build trees and evidence are below:

`$GUARDIAN_STORE/ralph/20261114-222756-306485-task-14/g12-evidence/`

| Record below that directory | Contents |
|---|---|
| `baseline-configure.log`, `baseline-build.log`, `baseline-ctest.log` | Unchanged pre-G12 host build and 21-test baseline |
| `G12-host-9pOoij/` | Normal and ASan/UBSan builds, verbose 23-test runs, compiler metadata; all 32 executable hashes rechecked |
| `G12-esp32s3-ZkTVXW/` | Successful Xtensa run; `linked-core/` and `linked-presenter/` hold separate verified link records |
| `G12-esp32c3-o5Oqh3/` | Successful RISC-V run; same separate link records |
| `qualification-results.json` | Final worker verification: architectures, compiled sources, component isolation, host counts and artifact hashes; acceptance explicitly pending |
| `reviewed-library-unchanged.json` | All 21 core/presenter files match the accepted G10 archive |
| `qualified-source.tar.gz`, `qualified-source-sha256.json`, `SHA256SUMS` | Final source snapshot and evidence index checksums |

Each successful native run exited zero, and all **13 archived artifact hashes
per target** were recomputed after completion. Before/after SDK
qualification records agree. Their startup source manifests still match every
maintained input after the run. The reused build trees remain under the earlier
`G12-esp32s3-jG81U3/core` and `G12-esp32c3-2HsMWZ/core` directories; those trees
now reflect the presenter configuration. Use the successful runs' `linked-*`
copies for each layer's original map, sdkconfig and compile commands.

The first host manifest and `qualified-inputs-sha256.json` are earlier development
snapshots: the test's missing include and redundant PSRAM default were corrected
while configuration was still in progress. They are retained, not rewritten as
final inputs. The successful native manifests and final source snapshot identify
the finished source. Host compilation and both host runs used the corrected test;
no library behavior changed. Initial syntax-check output is also retained in the
attempt's `engine.log`.

The ordinary host wrapper first failed because its default `builds` directory
is outside this worker's writable sandbox. It did not build on the Mac instead.
The raw baseline and qualification commands use the writable attempt directory
on the same the store. Three early wrapper attempts failed because the sandbox
refused shell process substitution (`/dev/fd`); logging now uses direct file
redirection. Failed attempts are retained and do not count as qualification.
The initial native configure also warned that `CONFIG_SPIRAM=n` was unknown:
the minimal project omits the PSRAM component and its Kconfig definition.
That redundant default was removed; absence of enabled PSRAM is checked in the
generated configuration, separately from any claim about physical memory.
The first full native builds were deliberately interrupted (exit 130) after slow
SMB configuration and partial SDK compilation. Their logs remain intact. The
revised wrapper resumes their same-target qualification caches, uses eight
compile jobs, and builds the required ELF target without generating flash images
or rebuilding a bootloader. It verifies separate copies of each layer's ELF,
map, sdkconfig and compile commands before reusing the SDK objects for the next
link. The interrupted attempts themselves are not successful qualification.

Reproduction (from the repository root, with this directory already present):

```sh
export GUARDIAN_QUALIFICATION_PARENT=$GUARDIAN_STORE/ralph/20261114-222756-306485-task-14/g12-evidence
bash firmware/tools/qualify-targets.sh host
bash firmware/tools/qualify-targets.sh esp32s3
bash firmware/tools/qualify-targets.sh esp32c3
```

The native toolchain is the installed ESP-IDF v5.4 at
`67c1de1eebe095d554d281952fde63c16ee2dca0`, with Espressif GCC
`esp-14.2.0_20241119` for both architectures. The SDK has the pre-existing S3
Wi-Fi archive modification recorded by G10. The qualification apps do not link
that archive. No SDK or toolchain was acquired or modified for this task.

## Evidence boundaries

The profiles are **synthetic**: headless 2.4 GHz; a display with zero PSRAM and
animation unsupported; and headless dual-band with a declared 5 GHz channel 36.
All observations are Imported and passive reception is Unsupported. The 5 GHz
case changes receiver metadata synthetically and verifies band/channel policy.
It is neither a capture nor an assertion that StickS3 supports 5 GHz.

No new board was physically tested. Native compilation/linking cannot establish
boot success, executed assertions, radio capability, runtime memory/stack fit,
RF coverage or performance. The test app reserves a 32 KiB main-task stack; that
is not an integrated product budget. G11's earlier physical StickS3 evidence is
separate and is not reused as proof for these new binaries. Cross-target test
execution remains unmeasured unless separately authorized and recorded.

The host's existing fixture suite runs without an M5Stack SDK. The optional
libwifi differential oracle is not enabled by this wrapper; G09 retains that
earlier independent-parser evidence. Synthetic tests, cross-builds and physical
coverage must remain distinct in supervisor acceptance.

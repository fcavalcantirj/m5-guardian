# G12 portable target qualification

This native ESP-IDF project compiles and links the existing portable library
without the StickS3 renderer, M5Stack SDK, radio initialization or PSRAM. It is
qualification source, not a replacement product firmware. Nothing here flashes
or opens a device. The earlier foundation spike remains unchanged.

Run from the repository root:

```sh
bash firmware/tools/qualify-targets.sh host
bash firmware/tools/qualify-targets.sh esp32s3
bash firmware/tools/qualify-targets.sh esp32c3
```

The wrapper uses the installed native ESP-IDF v5.4 revision and the existing
G10 SDK qualification guard. It never installs toolchains. All generated files
go to a newly created directory on the store. Set
`GUARDIAN_QUALIFICATION_PARENT` to an **existing writable directory below
`$GUARDIAN_STORE`** when the sandbox restricts the default
`builds` destination. There is no local scratch fallback. Each invocation prints
its directory; command output is in `session.log`, with a nonzero `exit.txt` on
failure. Review source hashes, compile commands, maps, ELF headers/symbols,
sdkconfig, tool versions and artifact hashes there. No acceptance flag is set.
An interrupted native build can be reused by setting `GUARDIAN_QUALIFICATION_REUSE`
to its existing build directory. The wrapper checks the canonical the store path,
exact qualification source directory and target in CMakeCache before rebuilding.
It writes fresh evidence to a new output directory and never cleans the old tree.

Host mode runs the existing core/presenter behavior tests and two additional
executables in normal and ASan/UBSan builds. `qualification_core` links just the
core; `qualification_presenter` adds the presenter. The native modes build two
separate ESP-IDF app ELFs with the same checks, one with the core alone and one
with the presenter. Each ELF/map/config/compile-command set is copied and verified
under `linked-core` or `linked-presenter` before reusing unchanged SDK objects in
the build tree. Both use the existing component registrations. Core source has
no SDK additions. Native map checks reject radio/renderer libraries and reject
a presenter dependency in the core-only app.

`tests/qualification/profile_checks.cpp` is shared verbatim between host and
native builds. It checks three synthetic profiles: headless 2.4 GHz, a display
with no PSRAM or animation, and headless dual-band (2.4 GHz plus channel 36).
All fixtures have `Origin::Imported`; passive reception is Unsupported. The
5 GHz test changes receiver metadata synthetically and checks channel policy;
it is not a 5 GHz frame capture or a claim about StickS3 radio capabilities.
Each profile checks parser-to-core grading, band/channel rejection, disconnect
evidence, stale grading and advice; the presenter variant also checks incident
visibility, imported labels, pagination and stale output.

Native builds disable PSRAM in sdkconfig. The profiles' RAM numbers are declared
fixture values, not measurements of free heap or a proven product budget.
The probe reserves a 32 KiB main-task stack for test objects; actual integrated
product memory, stack and peripheral behavior require separate measurement.

Only host executables run in this task. Native ELF output
proves cross-compilation and linking for the selected target ABI. It does not
prove the checks ran on ESP32-S3/C3, boot, real reception, RF performance or
physical coverage of another board. No emulator is silently substituted for
hardware. G11's prior StickS3 evidence remains its own recorded scope.

See [G12 evidence and handoff](../../docs/G12-portability.md) for actual outcomes
and limitations. This task adds qualification of pre-existing behavior; it
does not claim retrospective failing-first library TDD.

Supervisor acceptance: [G12 validation](../../docs/G12-validation.md). The wrapper
now rejects changes to recorded source inputs during a run before declaring
success. Its isolated bookkeeping regression is
`python3 firmware/qualification/tests/source_guard_check.py`; this invokes
simulated build commands and is not native runtime or RF evidence.

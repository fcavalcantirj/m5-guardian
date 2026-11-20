# Guardian host live lab

This harness feeds actual received management frames through the same C++ parser,
detectors, Core and presenter linked by the firmware project. Python handles
transport, timing, orchestration and evidence; it does not replace those detectors.
PCAP/fixture checks remain explicitly imported, never live.

This is an explicitly launched lab tool, not a background service or Ralph task.
The configured owner hotspot is `LAB-PI-2`; its current BSSID/channel must be
rediscovered after a hotspot restart. No password is required or stored.

The test-stimulus firmware that `lab/live/emitter.py` controls on a separate lab board is not in
the public repository; the owner keeps it outside it.

## Build and checks

Use the installed C++ toolchain and an existing Python environment with pyserial.
`cmake -S lab/live -B /private/tmp/guardian-live-build -DGUARDIAN_ROOT="$PWD" -DGUARDIAN_SANITIZE=ON`
then `cmake --build /private/tmp/guardian-live-build --target guardian_live_engine`.
Run focused checks with `GUARDIAN_ENGINE=/private/tmp/guardian-live-build/guardian_live_engine python3 -m unittest discover -s lab/live/tests`.
Artifacts and lasting logs go in the store; local scratch is small and temporary.

## Explicit live run

`python3 lab/live/run.py --config /PATH/TO/SCOPED-CONFIG.json --engine /PATH/TO/guardian_live_engine --out $GUARDIAN_STORE/evidence-raw/UNIQUE-RUN --scenario quiet --seconds 30`

Config fields: exact `ssid_hex`, `bssid`, `channel` (1..13), `groups` (1..8),
`deadline_s` (1..4). The current acquisition adapter identifies only the owner's
Cardputer by serial `LAB-CARDPUTER`, never by a generic USB VID/PID. It requires
receiver firmware 1.2. The excluded StickS3/head pointer is never opened.

`quiet` and `stale` do not start the emitter. `stale` stops reception at ten
seconds and needs at least 45 seconds to prove independent host-clock aging.
`stop`, `burst` and `recovery` explicitly start the separate Pi controller after
fresh exact-scope AP evidence. Recovery needs at least 85 seconds. Those are
bounded RF stimuli for the configured owned lab only. No auto-retry, scan,
password recovery, service installation or background job is performed.

The Pi helper uses its existing RF-lab venv and CP2102 by-id path. Its native
backend additionally verifies the known MAC and BR country/channel report.
The legacy original firmware is preserved as evidence, not certified just from
its banner. Source/binary equivalence was not established for that old build.

## Timing and evidence limits

Receiver SYNC replies bracket device microseconds against host CLOCK_MONOTONIC.
The smallest observed lower offset conservatively ages frames; a >100 ms sample
or accumulated interval fails the run. Samples repeat every three seconds. This
is an observed envelope, not a hard oscillator-drift bound. USB receipt time is
never substituted for frame acquisition. Python and C++ use the same host clock.
The C++ engine also ticks when reception stops, preventing frozen fresh evidence.

GRX1 CRC covers USB transport, not radio FCS. Actual trailing FCS is unavailable;
RX status is the SDK driver's report, not an independent integrity guarantee.
Coverage is adapter listening time and drop counters, not proof of hearing every
frame or every channel. Out-of-scope frames cannot become the selected AP's grade.

Bounded asynchronous log writers keep the store/SMB stalls off the reception path.
Overflow, sequence gaps, clock problems, device reboot and early engine exit
fail visibly. Evidence includes raw receiver bytes, host-library JSON, emitter
acknowledgments, scope, failures and assertion results. A template match cannot
cryptographically identify the emitter; it is correlated with isolated lab timing.
No observed deauth burst proves client disconnection or attacker identity.

Full L02 acceptance is separate from any single scenario result. Benign
reconnect, setting changes, related/unexpected AP changes and failure cleanup
must have their own real evidence; unsupported cases remain explicit.

## Accepted scenarios and final state — 2026-11-14

[Supervisor matrix](../../docs/L02-live-validation.md): L01/L02 pass for the
measured scope. All supported scenario names: `quiet`, `reconnect`, `stale`,
`drop`, `stop`, `stop-inflight`, `burst`, `recovery`, `settings`,
`related-approved`, `related-unapproved`.

`reconnect` observes an owner-operated normal client reconnect. `drop` deliberately
withholds 24 real received frames at the host adapter, records each loss, checks
degradation and recovery; it does not synthesize RF. `stop-inflight` requests stop
inside a three-call batch. `settings` uses the separate bounded native AP for
WPA2/WPA3 transitions; related-AP cases compare explicit approval policies.
AP cases use channel 13, ephemeral unsaved credentials and automatic/explicit stop.
The detection budget is 1,500 ms from the Core's threshold-closing acquisition
timestamp to reported incident, not from the first stimulus frame.

Cleanup attempts receiver stop, emitter stop/EOF, engine exit and reader joins
even after an earlier cleanup error. `cleanup.json` and `run_complete_pass` give
the final result; the earlier console summary alone cannot establish cleanup.
Both devices were finally checked idle, no controller/engine remained. Source,
binaries, final audit and original-backup hashes are retained in the store. A fresh
explicit scope check is required for a future run; setup never starts scenarios.

## G09 lifecycle hardening

The host records the first termination signal and raises cancellation only at
safe acquisition checkpoints. Cleanup retains that signal status while writing
failure/cleanup receipts. Pipe commands have write deadlines; receiver stop needs
a fresh, matching-boot stopped status, separately from command delivery or close.
Post-stop proof requires continuous scoped receiver heartbeat coverage, not just
elapsed host time. See [G09 validation](../../docs/G09-validation.md).

The source controller now requires native emitter **1.2**, which adds a reset
backstop on driver shutdown failure. Version 1.1 live results remain historical
successful-path evidence; they do not prove the corrected failure path. Do not
claim the 1.2 image deployed until its flash/boot record exists. Future use must
sync the controller and its dependencies to the Pi as well as qualify the image.

## G13 board adapter (acceptance pending)

`run_board.py` reuses this harness with the exact G11 StickS3 and the library
running on that board. It requires an explicit country in the scope config and
uses no host engine. See [G13 implementation/evidence](../../docs/G13-measurement.md)
for the protocol, deterministic checks, manual launch and pending physical gate.
Setup/build never launches it. The existing host run entry point remains intact.

### G13 supervisor follow-up

The board path has passed 11 bounded live scenarios; see
[measured validation](../../docs/G13-validation.md). `--scenario channel` is a
board-only scenario requiring at least 70 seconds (95 includes AP-off aging).
The receiver holds the initial channel until AP startup, then releases to normal
passive discovery; the fixture moves 13 → 6 → 13 without extending its deadline.
The Pi fixture is 1.3, with explicit channel admission and no associated clients
permitted during retuning. Same-name cases use the currently qualified hotspot
channel. Setup/build still never launches a scenario.

Rebuild the host engine after source changes; set `GUARDIAN_ENGINE` to that
compiled binary when running `python -m unittest discover -s lab/live/tests`.
The supervisor's sanitized host engine and exact source are archived under
`reviews/G13-20261115-supervisor/`. Imported checks are not RF evidence.

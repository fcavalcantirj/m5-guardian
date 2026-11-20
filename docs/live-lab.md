# Automated host live RF validation — L01/L02

The required matrix below remains the acceptance contract. An initial
[implemented host harness](../lab/live/README.md), acquisition bridge and bounded
Pi stimulus firmware now exist. [Current validation](L02-live-validation.md)
records the actual passes and open cases. The initial [L01 inventory](L01-qualification.md)
is retained as history, not a claim that the newly prepared equipment is absent.
L01/L02 are accepted for the measured matrix on 2026-11-14. Both radios are idle.
G09 is accepted. G13 real-board validation is now underway; see
[G13 supervisor evidence](G13-validation.md) for passed scenarios and remaining
physical acceptance.

## Pipeline

```text
explicit scoped CLI launch
  -> scenario controller -> verified offensive backend (Bruce when supported)
  -> real RF at the configured owned lab AP/channel
  -> separate qualified receiver -> host FrameSource
  -> actual C++ parser / detectors / Core / presenter
  -> timestamped console events + assertions + the store evidence
  -> stop emitter and restore lab state, including on failure/interrupt
```

Capture and offense need independent, verified observation paths. A receiver
that stops listening while the same radio transmits must not claim uninterrupted
coverage. Backend support must be checked against installed firmware and source;
there are no assumed Bruce serial commands.

## CLI behavior and acceptance contract

- A capability/plan operation reports hardware identities, supported bands,
  actual monitor/raw-frame support and documented offensive-control methods.
  It must not transmit.
- A live run explicitly names the lab configuration and scenario. Configuration
  binds AP SSID/BSSID/channel, receiver, emitter, bounded duration/rate and
  cleanup actions. No broad selection of nearby networks.
- The harness starts live acquisition and the production library before the
  offensive stimulus. It checks both emitter acknowledgment and receiver
  evidence. Failure to emit or receive is failure/inconclusive, not a clean pass.
- Console output and machine-readable records report incident type, counts,
  observation/acquisition timestamps, evidence age, selected AP, coverage/drop
  counters and expectation results. Define clock synchronization/uncertainty
  before asserting cross-machine latency.
- Every scenario has a hard deadline, emitter stop and lab-state cleanup on
  success, error and interrupt. No password recovery, credential collection,
  indefinite interference or unconfigured targets are required.

## Required scenario matrix

| Scenario | Automatic assertion |
|---|---|
| Quiet baseline and ordinary reconnects | Sufficient actual observation; bounded false positives |
| Scoped disconnect-frame burst | Expected burst evidence after configured threshold within the stated latency budget |
| Cooldown and recovery | No indefinite repeated incident; evidence ages correctly |
| Approved and unexpected baseline changes | Approved related APs handled normally; unexpected changes labeled uncertain |
| Receiver interruption/drop conditions | Coverage becomes degraded/stale, never a fresh reassuring grade |
| Controlled AP security-mode change | Advertised settings and explanation update from received bytes, not controller intent |

L01 records which lab backend supports each scenario. Missing support means an
unresolved required case; do not silently omit it or substitute replay. Additional
attack types require their own detector policy and evidence rather than a broad
claim that Guardian detects everything Bruce can do. Deauth traffic is observed
traffic; it does not prove client disconnection or an identified attacker.

## Evidence and gate

Store raw captures, offensive acknowledgments, receiver statistics, live library
logs, parameters, source hashes, firmware/toolchain identities, timing uncertainty,
assertion results and cleanup outcome in the store. Results distinguish PASS, FAIL,
INCONCLUSIVE and UNSUPPORTED. Only adequate real observations satisfy PASS.

The supervisor executes, inspects, fixes and reruns affected scenarios. L02 must
pass before G09 foundation acceptance and G10 board integration. G13 repeats the
same scenarios through the board's adapters to catch integration differences.

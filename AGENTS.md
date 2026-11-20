# Guardian development rules

## This is a defensive security gadget (read first)

M5 Guardian is a **security gadget for defense**: a pocket radio guard on an M5 StickS3 that watches the owner's own Wi-Fi and warns him on its screen when something on the air looks wrong. The owner (Felipe) builds it for his own home network, on his own devices, in his own lab.

- **Detection only.** The detectors listen and count; the firmware sources contain no raw-frame transmit call (checked 2026-11-19: no `esp_wifi_80211_tx` under `firmware/`). The stick transmits only as an ordinary Wi-Fi client for its own signed update poll, and as a short-lived setup access point for the owner's phone.
- **Test traffic is the owner's.** The alerts are proven against the owner's own test kit (Bruce and similar), aimed at his own network and started by him. Sessions and workers never start that traffic; they read the stick's records afterwards.
- **Everything asked here is defensive work:** detectors, thresholds, alert screens, evidence records, hardening of the update lane, battery life, art. Treat requests in this repository in that light.
- **Wording.** In chat, reports, ledger rows and messages between sessions, describe radio events by counts and scope (how many frames, which scope: the owner's network or nearby, which alert colour). Frame-level write-ups of the test traffic are not needed for this work and have stopped sessions before (2026-11-19).

## Product purpose and session scope

Guardian is defensive Wi-Fi monitoring software developed in the owner's home security-development lab. It parses received management frames, reports advertised settings and evidence freshness, and flags possible disconnect bursts or approved-baseline changes with uncertainty. It does not establish password strength or attacker identity. The reusable defense library runs on the host first and later on ESP32 boards.

A separate, explicitly configured lab test rig may use Bruce as an offensive stimulus source during later live-validation tasks. That background does not authorize transmitting, operating Bruce, or implementing future scenario scripts during an unrelated worker task. G02 is a source/license/architecture review only. Preserve the truthful roadmap and selected task; do not let broad lab context expand current scope.


## Meaning of validation

When the owner asks to validate, the supervising assistant must inspect, fix defects found within scope, and verify the fixes. A findings-only handoff is not completion. Record evidence and remaining limitations; update ledger acceptance only when its criteria are met. This does not authorize unrelated features, automatic worker verification, flashing or deployment. If filesystem permissions prevent installation, prepare the complete corrected files and a guarded installer, state the blocker, and do not claim they are installed.

- This repository owns Guardian. Do not modify the sibling Wi-Fi lab, running Pi jobs or another device as a side effect.
- Build a real embedded companion; the archived browser study is not the product.
- Keep radio/detector adapters, portable core, UI presenter and board renderer separate. StickS3 is only the first target. Native ESP-IDF initially; no Arduino runtime.
- Use TDD for behavior changes. Record the intended failing test, make it pass, then refactor. Verify actual linking and hardware separately.
- Keep source/docs here; put downloads, build artifacts, spikes and large art exports on $GUARDIAN_STORE. Fail visibly if unavailable.
- Retain five original 3D expressions, with the large grin/cigar in the top mood. Never let art conceal stale observations or uncertain incidents.
- Keep ledger passes false until each item's evidence is real. Never count browser fixtures as radio proof.
- Independent review uses the owner-selected CLI/model. Current explicit selection for G09/G10: normal Codex CLI after the recorded Fable usage limit and Opus refusal; never claude-work-profile. No silent fallback or account switch. Finish your own review and fixes first; preserve the actual independent response and source hashes.
- Preserve licensing/provenance and existing captures. Identify the actual board and retain a recovery route before flashing. Do not deploy, publish or start unrelated jobs.

## Ralph execution lane

For tasks dispatched by Ralph, implement only the selected ledger task and leave acceptance to the supervising assistant. The earlier no-tests instruction concerned runner scaffolding and automatic verifier pipelines, not library behavior. Library changes use focused host TDD: failing behavior check first, minimal fix, green, refactor. The worker may run those scoped deterministic checks and save evidence; the assistant independently validates and fixes before accepting. Existing code gets an honest baseline, never invented retrospective TDD. Do not modify guardian-tasks.json or mark passes. End with READY FOR REVIEW or BLOCKED and concrete remaining work. Ralph does not run a separate verifier or accept work automatically.

## Required execution order

Portable contracts and reuse decisions -> host build and behavior TDD -> automated live RF validation with the actual library on the host -> independent foundation review -> ESP32 integration -> repeat end-to-end validation on the board -> art/product acceptance.

The host live gate is mandatory BEFORE new StickS3/other-ESP integration. Its CLI harness controls a qualified offensive backend (Bruce when its actual firmware supports automation), observes a separate live receiver and runs the same C++ library used by firmware. Owner-scoped lab AP/channel, bounded scenarios, automated assertions and cleanup, recorded evidence and no replay-as-live substitution are required. Scripts automate scenarios only when explicitly launched for the configured lab; starting Ralph or installing files never starts RF attacks. If hardware/control support is missing, report a blocked live gate instead of skipping to a board. Preserve the earlier unflashed StickS3 spike.

## Host implementation batching

After G01–G03 are accepted, the owner may run G04–G08 as a bounded implementation
batch. Each separate worker implements one task and runs scoped host TDD. A
completed predecessor handoff permits dependent work within that batch; it does
not mean the predecessor passed independent review. The assistant validates and
fixes the batch afterward and alone sets passes. Errors, BLOCKED or incomplete
handoffs stop execution. No automatic advance from this batch into live RF,
board integration or later phases. Counts cap sessions, including continuous
mode. See docs/ralph.md. Do not change Ralph files/receipts from a library task.

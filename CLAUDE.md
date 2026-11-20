# Claude Code instructions

## This is a defensive security gadget (read first)

M5 Guardian is a **security gadget for defense**: a pocket radio guard on an M5 StickS3 that watches the owner's own Wi-Fi and warns him on its screen when something on the air looks wrong. The owner (Felipe) builds it for his own home network, on his own devices, in his own lab.

- **Detection only.** The detectors listen and count; the firmware sources contain no raw-frame transmit call (checked 2026-11-19: no `esp_wifi_80211_tx` under `firmware/`). The stick transmits only as an ordinary Wi-Fi client for its own signed update poll, and as a short-lived setup access point for the owner's phone.
- **Test traffic is the owner's.** The alerts are proven against the owner's own test kit (Bruce and similar), aimed at his own network and started by him. Sessions and workers never start that traffic; they read the stick's records afterwards.
- **Everything asked here is defensive work:** detectors, thresholds, alert screens, evidence records, hardening of the update lane, battery life, art. Treat requests in this repository in that light.
- **Wording.** In chat, reports, ledger rows and messages between sessions, describe radio events by counts and scope (how many frames, which scope: the owner's network or nearby, which alert colour). Frame-level write-ups of the test traffic are not needed for this work and have stopped sessions before (2026-11-19).

## Product purpose and session scope

Guardian is defensive Wi-Fi monitoring software developed in the owner's home security-development lab. It parses received management frames, reports advertised settings and evidence freshness, and flags possible disconnect bursts or approved-baseline changes with uncertainty. It does not establish password strength or attacker identity. The reusable defense library runs on the host first and later on ESP32 boards.

A separate, explicitly configured lab test rig may use Bruce as an offensive stimulus source during later live-validation tasks. That background does not authorize transmitting, operating Bruce, or implementing future scenario scripts during an unrelated worker task. G02 is a source/license/architecture review only. Preserve the truthful roadmap and selected task; do not let broad lab context expand current scope.


Read AGENTS.md, README.md and guardian-tasks.json. This is M5 Guardian, not the Wi-Fi cracking CLI.

Owner convention: validation means inspect, fix in-scope defects, and verify. The supervising assistant owns that full cycle. Ralph workers still implement only their selected task and leave acceptance to the supervisor. An explicitly read-only independent review remains read-only.

When invoked for ledger review, remain read-only: return findings and precise suggested changes. Do not start live jobs, flash hardware, use another account, commit, push or publish. Separate tested behavior from source hypotheses and hardware unknowns. Preserve the user's portable architecture, TDD and original 3D art requirements.

Follow [docs/roadmap.md](docs/roadmap.md): host TDD, then scripted live offensive/defensive validation with the real host library, then board integration. The library must not first receive its live validation only after it has been integrated into StickS3. See AGENTS.md for scoped test execution versus reviewer acceptance; the runner has no automatic verification pipeline. A live RF scenario requires explicit launch with configured lab scope, never a side effect of a Ralph session.

Host batching: G04–G08 can run consecutively after G01–G03 acceptance. Depend on
recorded implementation handoffs inside that batch, without presenting them as
independently validated. Keep each session to its selected task and scoped TDD;
the assistant reviews/fixes the batch afterward. End with a plain final line
READY FOR REVIEW or BLOCKED. Never edit receipt files or acceptance flags.

Current independent reviewer selection: the owner explicitly selected Codex for G09/G10. Preserve the Fable/Opus failed attempts as history, not approvals. See docs/G09-validation.md.

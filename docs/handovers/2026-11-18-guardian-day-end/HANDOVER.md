---
slug: guardian-day-end
date: 2026-11-18
status: approved
round: 0
author_session: Claude Code session 7f9e96d0 (M5 Guardian supervisor, 2026-11-17 evening to 2026-11-18 21:40), context at 96 %
---

# Handover — M5 Guardian: supervisor duties, open device proofs, Ralph queue

## Mission
The M5 Guardian is Felipe's passive home Wi-Fi monitor on an M5 StickS3 (`~/dev/m5/m5-guardian`, zero git commits, Ralph
ledger `guardian-tasks.json`). The supervising session validates Ralph handoffs, accepts ledger rows, serves images to
the stick (which now fetches them by itself), and keeps the owner's rulings. "Done" for this handover: the Builder
takes over as supervisor with the same rules, accepts G16M/G16N/G16O/G16P/G16Q/G16R from their device proofs, and keeps
the stick on the approved design.

## Where things stand (verified)
- [REAL] Stick LAB-STICK-1 runs `guardian-20261118-195811` (G16P image: contains G16M phone setup, G16N dark guard,
  G16O particle gravity, rest thresholds 20 deg/s / 0.15 g, auto-OTA). Verified 21:11 over a TUNE session:
  `app_version=guardian-20261118-195811 last_update_result=ok imu=running@0x68 batt=4147mV/100%~usb power=usb`.
- [REAL] Self-fetch: the stick polls the Mac every `ota.auto_s` (120 s, TUNE) for a signed image or a TUNE offer; proven
  2026-11-18 13:21 (`ota_auto_checks=1`, TUNE landed with no gesture). No FRONT x3 is ever needed; the owner forbade
  asking for it. Evidence: `firmware/evidence/sticks3-imu-after-software-restart-20261118.log`.
- [REAL] Serving commands (run from the repo, the stick fetches within 2 min; one update per server run):
  ```
  python3 tools/ota_serve.py $GUARDIAN_STORE/builds/<archive>-sticks3 --port 8070
  python3 tools/tune_session.py --port 8070 --seconds 60 --command STATUS --no-prompt
  ```
  Only one of them can hold port 8070 at a time; loop the TUNE offer (it waits 3 min per run) until a STATUS lands.
- [REAL] Ledger 32/40 accepted. Handed off, host-green, on the device, NOT accepted: G16M (phone Wi-Fi setup), G16N
  (dark guard), G16O (particle gravity), G16P (timer wake on USB). Being built: G16Q (art bench, attempt
  20261118-211211-040659-task-37, Fable 5.2); its receipt will read `ledger_changed` because G16R was inserted while it
  ran: the work is valid, accept by hand, no `--retry`. Next pick after it: G16R (same-name RED bug). Deferred: G16H (BLE,
  research first). Then G22, G23.
- [REAL] No-LLM watcher `tools/ralph_watch.sh` runs persistent (pid 60012 since 03:09, `GUARDIAN_WATCH_EXIT_ON_IDLE=0`);
  per handoff it writes `$GUARDIAN_STORE/builds/ralph-watch/<TASK>-<attempt>/SUMMARY` (host plain+ASan,
  tools, build-support, signed build). Restart if gone:
  ```
  GUARDIAN_WATCH_EXIT_ON_IDLE=0 nohup tools/ralph_watch.sh >> $GUARDIAN_STORE/builds/ralph-watch/watch.log 2>&1 &
  ```
- [REAL] Ralph command (owner runs it; `claude` without a count = one session):
  `CLAUDE_MODEL=claude-fable-5-2 ./ralph-continuous.sh claude 10`. Fable 5.2 worked for every row today.
- [REAL] Dark-guard drain: about 5 battery points per 10 min at 25-30 %, radio and CPU on (S1,
  `firmware/evidence/sticks3-G16N-spike-20261118.log`); the stick hit the 20 % floor and deep-slept at ~18:15.
- [REAL] Bruce deauth against the owner's router: RED once (yesterday, matching address), amber three times today; the
  Network detector counted 4-7 frames, the nearby one 43-58 (STATUS). Owner ruling: "your network is its name" → G16R.
- [REAL] Dark wakes were booked as MOTION with the old rest rule (4 deg/s / 0.05 g); traces show 20 / 0.15 quiet at rest;
  now firmware defaults (idle.hpp) and saved TUNE (version 1.31).
- [TEST] Host-check on the final tree: 51/51 plain and ASan (18:49). Tools 82, build-support 35.
- [UNVERIFIED] Dark-wake attribution after the new rest defaults (needs a battery session).
- [UNVERIFIED] G16M setup page, G16O pile on the glass, G16P timer wake: never exercised on the device.

## Blocking constraints (builder: restate these before planning)
1. NEVER run `ralph.sh`/`ralph-continuous.sh`/any loop runner yourself, never flash, never commit, never ask the owner
   for FRONT x3; the stick fetches images by itself when you serve them.
2. NEVER edit `guardian-tasks.json` while a worker runs (`pgrep -f ralph_runner.py`); an edit marks the attempt
   `ledger_changed` (work still valid, accept by hand).
3. The approved art is the v4 pack (green eyes Very good, red eyes Horrible, cyan middle, red-eye ALERT). No new art,
   no Meshy spend (80 credits spent, owner: "stop generating art"). The 3D head frames stay `head.on=0`. G16Q only
   changes how faithfully the panel renders the approved masters.
4. Nothing hard-coded: no network names, addresses or credentials in code or tests (owner, 2026-11-18).
5. Opening the stick's USB port resets it; USB is the charger now, not the Mac. All device reads go over the TUNE poll.
6. the store write rules: smbfs mount + sentinel `$GUARDIAN_STORE/.guardian-store-root`, copy + sha256.
7. TUNE writes are SAVED on the stick; current non-default saved values: motion.rest_gyro=20, motion.rest_acc=0.15,
   head.on=0, ota.auto_s=120, power.dim_s=30, power.sleep_s=120 (restored).

## Accepted residuals / Refuted — don't fix
- `tools/ralph_watch.sh` builds on the Mac disk on purpose: `host-check.sh` builds in the store and its cmake generation
  took >9 min over SMB.
- The Blender projection bake (`tools/face3d/project_views.py`) stalled twice before the G21 worker fixed the
  per-vertex normals recompute; it now takes 2.6 s. Do not reintroduce per-vertex `v.normal` reads in a loop.
- Meshy textures were rejected as "clay"; the owner's master projected on the geometry is the only acceptable 3D look,
  and even that is parked (head off).
- The upright-by-gravity mode is OFF by default (owner: the floating face is the approved behaviour; the
  hold-when-flat rule moved the picture when the stick was laid down).
- The learn-track lesson texts (KRACK, WPA2 vs WPA3) could not be written by a coding session (safety classifier
  stops); the owner pastes them.
- Fable 5.1 refused the Guardian worker prompt on 2026-11-16; Fable 5.2 and Opus 5.5 work.

## Hard rules & human-reserved decisions
- Owner runs every live attack and every loop; sessions prepare and validate.
- Burning the eFuse HMAC key for the credential vault (irreversible) IS FELIPE'S CALL.
- Erasing the old `nvs` partition (plaintext residue) IS FELIPE'S CALL.
- Whether the full-height crop wins in G16Q (loses hood edges, HUD moves) IS FELIPE'S CALL from the glass.
- The five-mood 3D question (partition table vs assets partition) is deferred while the head is off.

## Acceptance checklist (the author approves the plan ONLY against these)
1. The plan restates all seven blocking constraints correctly.
2. It names the exact device proofs it will collect for G16M, G16N, G16O, G16P (each: what the owner does, what STATUS
   field proves it, which evidence file) and accepts rows only from those.
3. It handles the G16Q `ledger_changed` receipt by manual acceptance, not `--retry`.
4. It serves every new image with `tools/ota_serve.py` and reads STATUS over `tools/tune_session.py`, never USB.
5. It keeps the watcher running and reads its SUMMARY before accepting any handoff.
6. It lists which open items need Felipe (Bruce target address, eFuse key, nvs erase, glass checks) and asks nothing else.
7. It updates `~/.claude/projects/-Users-OWNER-dev-wifi-lab/memory/guardian-resume-20261117.md` (the resume
   memory) at the end of its session.

## next_action
Read `$GUARDIAN_STORE/ralph/state.json` and the watcher's latest SUMMARY; if G16Q has handed off,
validate it from the SUMMARY and the engine.log report, serve its archive with `tools/ota_serve.py`, and confirm the
install over a TUNE STATUS.

## Open questions
1. Bruce's target address on the amber runs (owner has not read it yet).
2. Why the dark wakes counted as motion under the old thresholds on a cushion: re-check `dark_wakes` on the next battery
   session with the new defaults.

## Pointers
- Resume memory: `~/.claude/projects/-Users-OWNER-dev-wifi-lab/memory/guardian-resume-20261117.md` (full day log).
- Plans copied into the repo: `firmware/evidence/G16I-plan-upright-burst-20261117.md`, `G16N-plan-dark-guard-20261118.md`,
  `G16Q-plan-artbench-20261118.md`; docs: `docs/attack-coverage.md`, `docs/c5-node.md`, `docs/roadmap.md`,
  `docs/ledger-order.md`.
- Evidence: `firmware/evidence/sticks3-imu-after-software-restart-20261118.log`, `sticks3-G16N-spike-20261118.log`.
- the store: `$GUARDIAN_STORE/{builds,ralph,reviews,art-exports,evidence-raw,backups}`; backup of the tree
  before today's Ralph runs: `backups/guardian-pre-g16i-ralph-20261117-225843.tgz`.
- Camera: claude-code-eyes, config `~/.config/claude-code-eyes/config` (phone IP Webcam).
- Credentials: never in the repo; the stick's Wi-Fi credential sits in its NVS (plain); the OTA signing key at
  `~/.config/m5-guardian/ota-signing-rsa3072.pem` (never copy, never print).

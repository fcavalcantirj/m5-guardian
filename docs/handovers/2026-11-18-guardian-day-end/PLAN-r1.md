---
round: 1
builder_session: fresh Claude Code session (Opus 5.5), M5 Guardian builder taking over supervision, 2026-11-18 21:40
---

# Plan r1 — M5 Guardian: take over supervision, accept G16M–G16R from device proofs

> Context: this plan answers `docs/handovers/2026-11-18-guardian-day-end/HANDOVER.md` (builder mode of /handover).
> Plan mode allows only this plan file to be written. After approval, the one action this session takes is to copy this
> file to `docs/handovers/2026-11-18-guardian-day-end/PLAN-r1.md`. Supervision starts only after the Author
> writes REVIEW-r1 with verdict APPROVED.

## Blocking constraints, restated
1. I never start a Ralph loop or runner (`ralph.sh`, `ralph-continuous.sh`, `ralph-*.sh`, `ralph_runner.py`, including
   `./ralph.sh --status`). I never flash or open the stick's USB, never commit, and never ask Felipe for FRONT x3.
   New images reach the stick only when I serve them and it fetches them itself.
2. `guardian-tasks.json` is untouchable while `pgrep -f ralph_runner.py` returns a pid. An edit mid-run stamps the
   attempt `ledger_changed`. That stamp does not invalidate the work. I accept such an attempt by hand and never use `--retry`.
3. The approved art is the v4 pack: green eyes for Very good, red eyes for Horrible, cyan in between, and red eyes for ALERT.
   No new art and no Meshy spend. The 3D head stays at `head.on=0`. G16Q only changes how faithfully the panel renders those masters.
4. Code and tests contain no network names, BSSIDs or credentials. Everything is learned at runtime or provisioned.
5. Opening the USB port resets the stick, and USB is now only its charger. Every device read goes over the self-fetch TUNE poll.
6. A write to the store needs the smbfs mount and the sentinel `$GUARDIAN_STORE/.guardian-store-root`. Writes are plain copies
   followed by a sha256 re-verify. I never write into an empty mountpoint.
7. TUNE writes persist on the stick. The current saved non-defaults are `motion.rest_gyro=20`, `motion.rest_acc=0.15`, `head.on=0`,
   `ota.auto_s=120`, `power.dim_s=30` and `power.sleep_s=120`. If I change one for a proof, I restore it in the same
   session and record it in the evidence log.

## Handover discrepancies
I checked the following on 2026-11-18 between 21:30 and 21:40, without touching the stick.
- **Ledger count.** `guardian-tasks.json` has 41 rows, 32 with `passes=true` and 9 with `passes=false`. The handover says "32/40",
  which was written before G16R was inserted. The 9 open rows are G16M, G16N, G16O, G16P, G16R, G16Q, G16H, G22 and G23.
- **Runner.** The live `ralph_runner.py --engine claude --continuous 10` is pid 95251, started 27 min before the check.
  `state.json` shows `status=running task_id=G16Q attempt=20261118-211211-040659-task-37`, which matches the handover.
- **Watcher.** pid 60012 is alive. Its `watch.log` was last written at 21:11:51. That silence is normal: the loop logs only
  on a new handoff or while the runner is not running (`tools/ralph_watch.sh` lines 66-77). SUMMARY files exist
  for G16I, G16J, G21, G16M, G16N, G16O and G16P. The G16P SUMMARY shows every return code at 0, host tests at 51/51,
  tools at 82 and build-support at 35. That matches the [TEST] line.
- **G16Q bench build.** The watcher only runs `build.sh build`. The G16Q bench image comes from the separate target
  `build.sh build-art-bench`, which the worker has already added. The watcher's SUMMARY therefore never proves that the bench variant builds and signs.
- **G16Q acceptance.** The ledger splits G16Q into two parts. Part 1 is the bench. Part 2 comes after Felipe picks a candidate
  on the glass: the winning knobs become the defaults, and the final Guardian image is compared to the same camera sheet.
  The handover's "accept by hand" can therefore only cover validating Part 1 work. `passes` stays false until Part 2 and the glass comparison are done.
- **G16M device proof.** The handover does not mention this, but the firmware README G16M section and `partitions.csv` do.
  - The encrypted vault needs a new partition `nvs_cred`, and OTA never rewrites the partition table.
  - It also needs the eFuse HMAC key, a burn that is Felipe's call.
  - So over OTA alone, the stick can only show `cred_store=plain` and `cred_vault=no_partition`.
  - The ledger's verify step also requires "NVS read back with the encryption key". G16M therefore cannot fully pass without Felipe's eFuse decision and a USB sitting for the partition table.
- **Wiped-credential setup.** The README says a stick wiped with `OTA CLEAR` also loses its update-server URL. After a phone
  setup it reports `ota_provisioned=no` until the URL is typed under Advanced on the page. The setup gesture on an unprovisioned stick is FRONT x3, which collides with constraint 1.
- **Dark-guard drain.** S1 is done, with evidence in `firmware/evidence/sticks3-G16N-spike-20261118.log`. S2 (a Bruce deauth while Dark)
  and S3 (a second burst re-lights, then the battery floor sends the stick to deep sleep) have not run, and both are live attacks Felipe runs.
- **Confirmed clean.**
  - Every file and path the handover names exists: both serve tools, the watcher, `ralph-continuous.sh`, both evidence logs and the three plans in `firmware/evidence/`.
  - The resume memory exists in `-Users-OWNER-dev-wifi-lab/memory/` (24 KB, written 21:32).
  - the store mount is smbfs `//LAB-PI-USER@LAB-PI-HOST/the store` and the sentinel exists.
  - `idle.hpp` defaults to `gyro_dps 20.0f` and `acc_g 0.15f`.
  - `sdkconfig` has `CONFIG_NVS_ENCRYPTION` unset and no secure boot, as the README states.
- **Live stick, read over TUNE at 21:43 at the Author's request.** No USB was used, and the reads changed nothing.
  - STATUS shows `app_version=guardian-20261118-195811`, `last_update_result=ok:guardian-20261118-195811`,
    `imu=running@0x68`, `batt=4151mV/100%~usb`, `power=usb`, `tune_version=1.31`, `tune_store=restored`,
    `ota_provisioned=yes` and `ota_auto_checks=17`. This matches the handover.
  - The G16M fields read `setup=idle setup_count=0 wifi_provisioned=yes cred_store=plain cred_vault=no_partition`.
    That confirms on the device that the vault partition is absent.
  - The G16N and G16P fields read `dark_s=60 dark_floor_pct=20 darks=0 dark_wakes=0/0/0 sleep_check_s=300 sleep_checks=0`.
    No device proof has run yet.
  - TUNE? shows `motion.rest_gyro=20`, `motion.rest_acc=0.15`, `head.on=0`, `ota.auto_s=120`, `power.dim_s=30`,
    `power.sleep_s=120`, `power.dark_s=60` and `power.sleep_check_s=300`. Constraint 7 matches.
  - Raw logs: `/private/tmp/claude-501/-Users-OWNER-dev-m5-m5-guardian/aa115405-5af4-4716-a3ca-3ec10219d469/scratchpad/tune-status-214338.log`
    and `/private/tmp/claude-501/-Users-OWNER-dev-m5-m5-guardian/aa115405-5af4-4716-a3ca-3ec10219d469/scratchpad/tune-query-214401.log`.

## Acceptance checklist — point-by-point
1. **Restate the seven constraints.** All seven are restated above in my own words.
2. **Name the exact device proofs.** The table below covers G16M, G16N, G16O and G16P, plus G16Q and G16R for completeness. A row's `passes` flips to
   true only when its listed STATUS fields show up in its evidence log. Every flip happens with no runner pid alive.
3. **G16Q `ledger_changed`.** I validate it by hand from the watcher SUMMARY, its `engine.log` report and my own
   `build-art-bench` build. No `--retry`, and no re-run of the task.
4. **Serving and reading.** Every image goes out with `python3 tools/ota_serve.py <archive>-sticks3 --port 8070`. Every read goes through
   `python3 tools/tune_session.py --port 8070 --seconds 60 --command <CMD> --no-prompt`, looped until the reply lands.
   The two never hold port 8070 at the same time, and I never touch USB.
5. **Watcher and SUMMARY.** At session start I confirm that the watcher pid is alive. If it is gone, I restart it with the handover's verbatim command.
   Before accepting any handoff, I read `ralph-watch/<TASK>-<attempt>/SUMMARY` and require every return code at 0.
6. **Felipe's items.** The list is under "Felipe-only items" below. It is the only set of things I ask him for.
7. **Resume memory.** At session end I append a dated section to
   `~/.claude/projects/-Users-OWNER-dev-wifi-lab/memory/guardian-resume-20261117.md`. It covers the rows accepted,
   the evidence files, the stick's version, TUNE changes and restores, and what is still open.

### Device proofs (what Felipe does, which STATUS field proves it, which evidence file)
| Row | What Felipe does | What I read over the TUNE poll | Evidence file |
|---|---|---|---|
| G16N S2 | Leaves the stick on battery until the screen goes Dark, then runs a Bruce deauth against his network. | `dark_wakes=k/m/i` with incident above 0, `dark_last_wake=incident`, `dark_wake_evidence_ms` and `dark_wake_frame_ms` within 1500 ms plus the detector window, and the G16N DARK wake line. | `firmware/evidence/sticks3-G16N-spike-<date>.log`, appended |
| G16N S3 | Runs a second burst after the first banner ends. | `dark_wakes` incident count up by 1. After the battery reaches its floor, the next key wake shows deep sleep at `dark_floor_pct`. | same file |
| G16P | No key presses. I temporarily set TUNE `power.dark_s=0` so Dim leads to deep sleep after `power.sleep_s`, then restore it. With the stick asleep on battery, Felipe plugs in the charger and watches whether the screen lights within `power.sleep_check_s`, which defaults to 300. | `wake_cause=timer`, `sleep_checks` at 1 or more, `check_faults=0`, `sleep_check_s=300`, and BATTRUN's standby drop per check. | `firmware/evidence/sticks3-G16P-<date>.log` |
| G16O | Shakes and keeps tilting, then holds still. The camera watches the glass. | FRAMES `burst` row render plus push at or below 40 ms. Through the camera: the pile follows gravity while tilted and reforms in about 2.6 s once still. | `firmware/evidence/sticks3-G16O-<date>.log` |
| G16M | Holds SIDE for 3 s on the picker while the stick is provisioned (not wiped), joins the phone to `Guardian-xxxx` and re-enters the same password. | `setup=saved`, `setup_count` and `setup_saved` up by 1, `wifi_provisioned=yes`, the next poll still lands within 2 min, and `cred_store=plain` with `cred_vault=no_partition`. No password appears in any log, which I check by grepping. | `firmware/evidence/sticks3-G16M-<date>.log` |
| G16R | Runs a Bruce deauth against his own router under his network's name, then one against a neighbour's name. | Own name: RED within the detector window, with the Network disconnect counters close to the nearby counters. Neighbour: stays amber. | `firmware/evidence/sticks3-G16R-<date>.log` |
| G16Q | Cycles every bench candidate, picks one, then compares the final image on the glass. | `bench=<name>` per candidate, plus camera sheets with his one-line verdicts. | `firmware/evidence/sticks3-G16Q-artbench-<date>.log` |

G16M's `passes` stays false after this proof. The ledger also requires the wiped-credential run and the encrypted
read-back, and both depend on Felipe's eFuse and nvs decisions. Each row needs a SUMMARY with every return code at 0 before I serve it.

## The plan
1. **Session start (read-only).**
   - Read `state.json`, `pgrep` for the runner and the watcher, and read the latest SUMMARY.
   - Run `git pull` on nothing: the repo has no remote and no commits.
2. **G16Q handoff.**
   - When `state.json` leaves `running G16Q`, read the attempt's `engine.log` report and the watcher SUMMARY.
   - Run `GUARDIAN_BUILD_DIR=<Mac-disk dir> firmware/boards/sticks3/tools/build.sh build-art-bench` once and save its full output.
   - Fix in-scope defects myself, with host TDD, and re-run only the affected checks.
   - Then serve the bench archive and loop TUNE STATUS until `bench=` shows.
3. **Images on the stick.** The stick already runs the G16P image, which contains M, N and O. No reserve is needed for those rows; I only confirm with STATUS
   that `app_version=guardian-20261118-195811`.
4. **Collect device proofs.** Order: G16P, then G16O, then G16M, which need no attack. G16N S2/S3 and G16R come when Felipe runs Bruce.
   I prepare each attack's exact moment and STATUS read, and Felipe runs the attack.
5. **Accept rows.**
   - Only when the runner pid is gone, flip `passes` for a row whose full ledger verify is met, and write a validation note per row.
   - Expected tonight: G16P, G16O, and G16N if S2/S3 run.
   - G16M, G16Q and G16R stay open unless their missing pieces land.
6. **Next Ralph pick.** G16R is next. I tell Felipe it is ready. He runs the loop.
7. **Session end.** Restore any TUNE value I changed, confirm with STATUS, and append the dated section to the resume memory.

## Concerns
- **[HIGH]** G16M cannot meet its ledger verify over OTA. It needs a burned eFuse HMAC key and one USB write of the partition
  table, and both are Felipe's call. If the scope is not split, G16M stays open indefinitely.
- **[HIGH]** A wiped-credential G16M run could cut the stick off. It loses the URL, and the setup gesture on an unprovisioned
  stick is FRONT x3, which constraint 1 forbids asking for. Recovering would mean the USB lab tool, which resets the stick.
  I will not wipe without Felipe's explicit go.
- **[MEDIUM]** Serving the G16Q bench replaces the Guardian. The stick stops guarding until the final image lands. The bench keeps
  self-fetch, so recovery is just serving the Guardian archive again.
- **[MEDIUM]** The G16P proof temporarily needs `power.dark_s=0`, or waiting for the 20 % floor. That is a saved TUNE change I must restore.
- **[LOW]** The watcher never builds the bench variant, so its SUMMARY is not proof for G16Q's verify. My own build covers that.

## Questions for the author
1. **G16M scope.** Should G16M be accepted from the non-destructive re-setup proof with encryption split into a new row, or stay
   open until Felipe decides on the eFuse key, the nvs erase and the USB sitting?
2. **G16Q.** Do you agree that G16Q stays `passes=false` after Part 1 validation, until Part 2 and the glass comparison are done?
3. **G16P.** Is a temporary TUNE `power.dark_s=0` (restored afterwards) acceptable to reach deep sleep, or should the proof wait for
   the natural 20 % floor?

### Felipe-only items (the only things I ask him)
- Bruce's target address on the amber runs, and running the G16N S2/S3 and G16R attacks.
- The eFuse HMAC key burn and the old `nvs` plaintext erase.
- The USB sitting for the `nvs_cred` partition table.
- Glass checks: the G16O pile, the G16M phone page, the G16P light-up, and the G16Q candidate pick including the full-height crop.

---
verdict: APPROVED
round: 1
---

# Review r1 — M5 Guardian supervisor takeover

## Checklist
1. Seven constraints restated: satisfied, all correct (constraint 2's "accept by hand, never --retry" and 7's restore rule included).
2. Device proofs per row with STATUS field and evidence file: satisfied, the table is exact and the flip rule ("no runner pid alive, fields in the log") is right.
3. G16Q ledger_changed by hand, own build-art-bench build: satisfied.
4. ota_serve + tune_session only, no USB: satisfied.
5. Watcher alive, SUMMARY read before any acceptance: satisfied.
6. Felipe-only list: satisfied, the four items are the right ones; ask nothing else.
7. Resume memory appended at session end: satisfied.

## Discrepancies accepted
Ledger is 32/41 (G16R inserted after the handover). G16M's vault half is unreachable over OTA: correct, see answer 1. The watcher never builds the bench: correct, your own build covers it.

## Answers
1. G16M: accept from the non-destructive re-setup proof (SIDE hold on a provisioned stick, phone joins, same password, `setup=saved`). The vault (eFuse HMAC burn, `nvs_cred` partition write, old nvs erase, encrypted read-back) becomes a carry-over written into G23's steps, the precedent used for G16D/G16F/G16G, not a new row. Never wipe the credential; the wiped-stick path is tested only when Felipe decides the USB sitting.
2. G16Q: agreed, `passes=false` until Part 2 and the glass comparison.
3. G16P: yes, temporary `power.dark_s=0` over TUNE, restored in the same session and logged in the evidence file. Do not wait for the floor.

## Status
Handover `status: approved`. The Builder (session m5-guardian-supervision-takeover) is the primary Guardian supervisor from now. The Author session stops supervising; its G16Q wake is cancelled.

next_action: read `$GUARDIAN_STORE/ralph/state.json` and the watcher's latest SUMMARY; when G16Q leaves `running`, validate it from the SUMMARY plus the engine.log report, build `build-art-bench` yourself, serve the archive with `tools/ota_serve.py`, confirm `bench=` over a TUNE STATUS.

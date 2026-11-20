# Firmware evidence

> **Redaction 2026-11-19 (before the first commit):** the owner's access-point address and network name were replaced by the placeholders `OWNER-AP-1` and `OWNER-NETWORK` everywhere in this directory (11 files) and in `guardian-tasks.json`; the same placeholder stands for the same value in every file. The unredacted originals, with a SHA256SUMS read back from the share, are on the store under `wifi-lab/guardian/evidence-raw/pre-redaction-20261119/`.

Only real device output belongs here: serial logs captured from the identified StickS3, photographs of its screen, and identity reads. Nothing in this directory may be produced by a host build, an emulator or a fixture.

Re-read against the ledger on 2026-11-20 (G23). Five files here are not device output and are named so that nobody counts them as such: three plan notes (`G16I-plan-*.md`, `G16N-plan-*.md`, `G16Q-plan-*.md`) and two host preview images written by `companion_preview` (`G16C-imu-strength-candidates-20261117.png`, `G16D-dim-view-portrait-preview-20261117.png`). They were left where the logs cite them.

| File | What it proves | Status |
|---|---|---|
| `device-identity-20261113.md` | Which physical unit this is, what firmware it ran, where its full flash backup and Bruce captures are | recorded 2026-11-13 |
| `sticks3-LAB-STICK-1-20261114.log`, `.jpg`, `sticks3-LAB-STICK-1-buttons-20261114.log` | First boot of the bring-up image on the Guardian's unit: flash, PSRAM, storage, the screen, both keys (ledger G11) | recorded 2026-11-14 |
| `sticks3-G<row>-...-<date>.log` | The supervisor's device record of one ledger row: image version, the STATUS, FRAMES or BATTRUN lines read from the stick, the owner's words, the acceptance | one or more per row from G14 to G22A; which row has none is listed in [the G23 delivery record](../../docs/G23-delivery.md) |
| `sticks3-imu-*-20261117.txt`, `sticks3-imu-axis-map-20261117.json` | The stick's own motion-sensor recordings (poses and nine handling traces) and the axis map computed from them; the traces are also the host fixtures `tests/fixtures/imu/` | recorded 2026-11-17 |
| `G16D-H-batch-desk-review-20261117.log` | The supervisor's desk review of the G16D to G16H batch with its device reads and live runs | recorded 2026-11-17 |
| `sticks3-G23-<date>.log` | The delivery run: stills, video, live incident, expiry, negative case, carry-over lines | **pending (G23 is open)** |

Naming: `<stamp>` is the build directory stamp in the store (`$GUARDIAN_STORE/builds/<stamp>-sticks3/`), so each log and photo points at the exact image. Raw, uncut monitor logs stay in the store under `evidence-raw/`; the copy here may be trimmed but not edited.

# G15: Guardian persona (Guy Fawkes-inspired), StickS3 art

Status: **accepted on 2026-11-16 by owner look-gate** for the art deliverable.
The accepted face is the **v2 "Cyber Guardian" pack** (owner-supplied). On-device
inspection is deferred to the integration task (see "Not established" below).
Ledger `passes` set true by the supervising assistant after the owner's verdict.

## Owner decision (2026-11-16)

The worker's v1 persona (procedural Blender generator, porcelain-gnome look) was
reviewed and **rejected** by the owner at the look-gate. The owner supplied an
external **v2 pack** (`guardian_art_v2`) with a different, stronger direction and
chose "go v2 as-is." This is a deliberate amendment of the original G15 contract:

- The original steps asked for an **editable 3D source** (Blender/`.blend`) and
  **on-StickS3 inspection** before acceptance. v2 has **neither**: it is a set of
  pre-rendered **2D raster sprites** (AI-rendered 3D-style illustration, not a
  rigged mesh), and it has not been flashed. The owner accepted the art on look
  alone and moved on-device work to a separate integration task.
- **Trademark:** v2 is close to the stock V-for-Vendetta / "Anonymous" Guy Fawkes
  mask, which is a trademarked design. v1 had deliberately avoided it. The owner
  **accepted the trademark risk for personal/learning-lab use** and was told that
  public/product use would carry real exposure. Not cleared for public release.
  **Amended 2026-11-20:** the owner chose to publish the artwork with the public
  repository, all rights reserved (`firmware/art/LICENSE`). No clearance from any
  third party was sought or obtained; the exposure named above is the owner's
  accepted risk.

## Accepted assets (v2)

| Item | Where |
| --- | --- |
| Firmware-consumable RGB565 frames (15 × 64,800 B, little-endian) | `firmware/art/persona/v2/rgb565/` |
| 1x RGB565 previews (what the screen shows) | `firmware/art/persona/v2/preview565/` |
| Review sheets (moods 1x/3x, alert, mock-labels) + 2x moods | `firmware/art/persona/v2/sheets/`, `moods_at_2x.png` |
| Manifest + asset map (sha256, per-state metadata) | `firmware/art/persona/v2/manifest.json`, `asset-map.json` |
| Pipeline scripts (Pillow + NumPy) | `firmware/art/persona/v2/build_assets.py`, `make_sheets.py` |
| Pack README + integration notes | `firmware/art/persona/v2/PACK-README.md`, `INTEGRATION_NOTES.md` |
| Full canonical pack (masters PNG/WebP 512², render_4x, icons_128, alert GIF/WebP animations, source contact sheet) | `$GUARDIAN_STORE/art-exports/G15/20261116-v2/` |

Heavy review-only assets (masters, 4x renders, icons, animations, source sheet)
live in the store only; the repo keeps the firmware inputs and small review copies.

## Design (v2)

Five ratings mapped to `guardian::Mood`, expression by **shape** not colour alone:

| Mood | Face |
| --- | --- |
| Very good | wide toothy grin, **cigar** (lit), cyan eyes |
| Good | closed smile, curled moustache |
| Medium | skeptical side-eye, one brow up |
| Bad | worried frown, inner brows raised |
| Horrible | bared gritted teeth, hard-V angry brows |

Common identity: porcelain Guy Fawkes mask, cyan glowing eyes, red/blue hooded
cowl, **padlock crest** on the forehead, circuit-line face markings, cheek shield
icons. Persona occupies x 0..151 (near full height); text zone x 152..239 stays
black/empty in the art and is owned by the renderer.

**ALERT** is an independent incident overlay for any rating (two pulse phases):
bright crimson eyes + an angular spiked warning corona. It is **not a sixth
rating**, never inferred from `Horrible`, and the underlying mood face is kept.
`Horrible` (non-alert, cyan eyes, no corona) stays visually distinct from ALERT.

At 1x on the simulated 240×135 frame the face stays recognizable, cyan eyes pop,
the cigar reads on Very good, and the ALERT corona + red eyes are clear.

## Not established / for the integration task

- **On-device inspection pending.** The accepted previews are monitor simulations
  of RGB565, not the StickS3 glass. The integration task must flash and inspect.
- **Integration is real firmware work, not flash-and-done** (see `v2/INTEGRATION_NOTES.md`):
  `firmware/adapters/companion/screens.cpp::draw()` still paints a 64×64 placeholder
  at (4,16) (`companion.hpp Frame::face_x=4,face_y=16,face_size=64`), which conflicts
  with the designed 0..151 full-height persona; the full-width header and bottom
  status/hint text would overlap the face and need a layout redesign. Byte order:
  the export is little-endian RGB565 while `Canvas` can push big-endian over SPI —
  match the transfer mode and add a host unit test. The `assets` partition
  (~5 MiB) is reserved but unmounted; 15 frames need ~950 KiB stored. Keep ALERT
  an independent overlay with a text reason; never conceal ALERT when the rating
  portrait is muted/Unknown, and never map `Unknown`/stale to a happy portrait.
- No idle/blink animation and no `Unknown`/stale persona art yet; existing
  diagnostic screens keep handling those states until the owner asks for art there.

## Provenance and licence

v2 is an **AI-rendered 2D illustration pack** supplied by the owner (not a
procedural mesh; `manifest.json model_type: rendered_3d_style_illustration`).
Pipeline: `build_assets.py`/`make_sheets.py` (Pillow + NumPy) post-process a
source contact sheet into frames, RGB565 and sheets. Design is close to the
trademarked Anonymous mask — **accepted for personal lab use, not cleared for
public release** (owner's informed decision, 2026-11-16). **2026-11-20:** the owner
chose to publish it with the public repository, all rights reserved, without
third-party clearance (see the amendment above and `firmware/art/LICENSE`).

## v1 history (superseded, retained)

The rejected v1 (procedural Blender 5.2.2 generator, porcelain mask + gold
signal-crest, no stock-mask reuse) was removed from the tree on 2026-11-21 (owner: outdated art out of
the public repo). Its sources (`guardian_persona.py`, `guardian_persona.blend` sha256 `ac3d0a3b…`,
`make_sheets.py`) and sheets are kept in `$GUARDIAN_STORE/art-exports/G15/20261116-v1/` (sources in
`sources/`). It is not the accepted face and was never consumed by firmware.

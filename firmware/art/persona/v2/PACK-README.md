# M5 Guardian — Cyber Guardian v2 asset pack

Generated against the source of `m5-guardian.zip` (2026-11-16). This is a **rendered 3D-looking 2D art pack**, not a rigged `.blend` or `.glb` mesh. It is a visual replacement concept based on the FIRST cyan/red, lock-crested Guy Fawkes image in the chat.

## Security policy respected

Exactly five ratings, matching `guardian::Mood`: `VeryGood`, `Good`, `Medium`, `Bad`, `Horrible`. Expression identity comes from the actual repo's G15 contract (`docs/G15-persona.md`). VeryGood celebrates with cigar; Good smiles; Medium is skeptical; Bad frowns; Horrible bares teeth. **ALERT is an independent incident overlay for every rating** (two visual pulse phases, red eyes and a distinctive angular/spiked warning corona). It is NOT a sixth rating. The facial expression under ALERT is preserved.

`Unknown`, checking, stale and degraded must NOT be presented as fresh ratings. The existing Presenter determines whether the portrait can be shown. Do not map `Unknown` to a generic happy/neutral portrait. DEMO needs an explicit 'not a real reading' label owned by the renderer, not baked into the PNG.

## Assets

- `masters_png/`: 15 transparent 512x512 PNG art renders (5 ratings + 5 x ALERT p0/p1)
- `masters_webp/`: same in WebP (for website / preview)
- `icons_128/`: small RGBA PNG avatars
- `render_4x/`: 15 960x540 RGB compositions ready as input to original repo's `make_sheets.py`
- `exports/frames/`: 15 240x135 PNG, screen aspect, text zone black and empty
- `exports/rgb565/`: 15 **64,800-byte** little-endian packed RGB565 frames
- `exports/preview565/`: images expanded from RGB565, for inspection before flashing
- `exports/sheet-moods-1x.png`, `exports/sheet-alert-1x.png`, `exports/sheet-mock-labels-1x.png`
- `animations/`: 5 alert-pulse GIF and animated WebP previews (NOT required by firmware)
- `asset-map.json`: mapping and file metadata
- `source/moods_contact_sheet.png`: original AI-rendered 5-mood contact sheet
- `build_assets.py`, `make_sheets.py`: reproducible postprocessing pipeline

## Display and integration constraints

**Not integrated or flashed.** `firmware/adapters/companion/screens.cpp::draw()` still draws a placeholder 64x64 block at `(4,16)`; actual `Frame::face_x=4,face_y=16,face_size=64` in `companion.hpp`. The G15 art plan assumes a full-height face on **x=0..151**, and text on **x=152..239**. This conflicts with the existing full-width header and bottom status/hint text and requires explicit screen-layout changes before using a full-size face. Do not silently paste these full-screen images on top of those fields.

The board display is 240x135 RGB565 with a 64,800-byte DMA framebuffer; `Canvas` can encode big-endian values when pushing SPI, while `make_sheets.py` produces **little-endian raw RGB565**. If blitting raw bytes verbatim, match byte order to the display transfer mode; a host unit test + physical display test is required. `assets` partition currently reserved but not mounted, so the existence of raw frames does NOT mean firmware can load them. All 15 frames require ~972,000 bytes of raw stored flash (~950 KiB).

On ALERT, the firmware must still show its live alert reason and evidence/coverage state. These renders contain **no text**. `Horrible` is non-alert with cyan eyes; an ALERT has bright crimson eyes and an angular corona even when the underlying rating is VeryGood.

## Rebuild

`python3 build_assets.py` (requires Pillow and NumPy; input sheet and make_sheets.py included).

## Notes

Contact sheets are quality review artifacts. The rendered masks have facial/hood detail that will be lost at 240x135; review the actual RGB565 previews at 1x on the StickS3 before accepting G15. The G15 `.blend` in the supplied repository is an *older, different* 3D model; these new images do not update its geometry and should not be described as a rigged 3D replacement.

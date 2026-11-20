# The approved art on the glass, as close to the master as the panel allows — "G16Q" (art bench first)

## Context
Owner (2026-11-18 19:0x, with the v3/v4 review sheet): the approved set is green eyes on Very good, red eyes on Horrible,
cyan in the middle, red-eye ALERT for all five (= the v4 pack on the stick). "THIS IS THE DESIRED RESOLUTION. Our stick
MUST look like it, which it isn't." He allows a separate firmware to advance the art on the real glass; when it looks
right, the Guardian takes it over.
Physics first: the face band is 135x160 pixels, the master 512x512. No firmware turns 135 px into 512 px. What can
change is everything between the master and the glass, and today none of it is tuned.

## Facts (read 2026-11-18; cites under firmware/)
- Pipeline `art/persona/v2/build_assets.py`: crop (40,0,472,512) → one LANCZOS step to 135x160 in sRGB on straight
  alpha (:31) → black matte (:32) → unsharp 1.0/90/2 (:34) → RGB565 by rounding, no dither (`make_sheets.py:48`).
  No linear-light resize, no gamma, no dither anywhere.
- Panel: stock IDF ST7789 init sends only SLPOUT/MADCTL/COLMOD/RAMCTRL; **no gamma registers (0x26/0xE0/0xE1)**, INVON on
  (`boards/sticks3/main/sticks3_board.cpp:209-231`); backlight LEDC 8-bit, Active 60 %, never 100 %
  (`sticks3_board.hpp:69`, `sticks3_board.cpp:235-260`); framebuffer and canvas do no colour transform.
- Draw path: `persona.cpp warp()` bilinear in RGB565 space runs on every animated frame because breath scale is ±0.008
  by default (`persona.hpp:31`, TUNE `persona.breath`): every frame is a resampled, softened copy of the portrait. The dim
  view paints the exact pixels (`screens.cpp:804-812`).
- Layout: face always rows 20..179, HUD always shown, rule at row 179, listening dot at (124,174) inside the face zone
  (`companion.hpp:193-206`, `screens.cpp:558,570`). No full-height art mode exists.
- 3D head is off by default (owner ruling), so the 2D portrait is what shows.
- Build variants: sdkconfig overlays + a `build-<name>` case in `boards/sticks3/tools/build.sh` (ble-spike pattern) give
  a separately versioned, signed, OTA-able image of the SAME app, which keeps the self-fetch poll alive.
- Camera: claude-code-eyes (phone IP Webcam) + `tools/face3d`-style sheets; no camera-vs-render tool exists yet.

## Design (decided)
1. **Art bench, a build variant of the Guardian app** (`CONFIG_GUARDIAN_ART_BENCH`, `sdkconfig.art-bench`,
   `build-art-bench` in build.sh): boots into a bench screen, keeps the self-fetch poll and signing, no radio capture.
   It shows one candidate frame at a time, full 135x240, FRONT = next candidate, SIDE = cycle backlight 60/80/100 %,
   a 2 s label (candidate name) on entry, STATUS `bench=<name>`. Candidates are embedded 135x240 RGB565 frames
   produced by a new `tools/art/candidates.py` from the v4 masters (Very good and Horrible, the two with coloured eyes,
   plus Medium), one candidate per knob setting, so the glass and the camera judge:
   - A today's pipeline (reference), B linear-light LANCZOS, C B + unsharp 0.6/120/1, D C + Floyd-Steinberg dither
     to 565, E D with the full 240 rows (master scaled to 240 high, hood sides cropped 48 px each), F D + panel gamma
     table (M5GFX's ST7789 PVGAMCTRL/NVGAMCTRL values sent at init, a bench-only init path), G F at 100 % backlight,
     H the still portrait with breath 0 (no per-frame resample) versus the warped copy.
2. **Judging**: the camera sheet (candidate frame on the glass next to the master crop at the same size) for each
   candidate plus the owner's eyes at the desk; a one-line verdict per candidate in the evidence log. The owner picks.
3. **Bring it to the Guardian**: the winning knobs become `build_assets.py` defaults (resample in linear light, unsharp,
   dither; crop/full-height if chosen), the board init (gamma table, backlight default) and `persona.breath` default
   (0 if H wins), all under the normal pipeline with new pins, host-check, signed build, self-fetch. If E wins, the
   layout work (HUD on a toggle, listening dot moved) is its own follow-up row.

## Spike inside the bench (what gets measured, recorded in firmware/evidence/sticks3-G16Q-artbench-<date>.log)
- Per candidate: camera frame of the glass at 60 % and 100 %, mean |diff| against the master crop downscaled the same
  way (so pipeline and panel effects separate), owner verdict. Gamma table: the panel's response measured with a
  5-step grey ramp candidate (black, 25, 50, 75, 100 %) read by the camera.

## Files
- Add: tools/art/candidates.py (+ tests/test_art_candidates.py: byte-exact frames, dither determinism, full-height crop),
  firmware/art/bench/*.rgb565 (generated, pinned), boards/sticks3/main/art_bench.{hpp,cpp}, sdkconfig.art-bench,
  Kconfig flag, build.sh case, evidence log.
- Change (only after the pick): art/persona/v2/build_assets.py + manifest pins + persona_check pin, sticks3_board.cpp
  (gamma table), sticks3_board.hpp (backlight default), persona.hpp (breath default), README.
- Ledger: row G16Q after G16P (owner-approved text from this plan); the bench build is the spike, the Guardian change
  is the row's second half.

## Verification
- Host: candidates byte-exact and pinned; the bench variant builds and signs with the normal tools; host-check unchanged.
- Device: the bench image lands by self-fetch, the owner cycles candidates, camera sheets per candidate, the Guardian
  image with the winning knobs lands by self-fetch and the glass is compared again to the same sheet.

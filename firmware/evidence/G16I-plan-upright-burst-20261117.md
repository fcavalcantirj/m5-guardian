# Guardian face: upright-by-gravity + snow-globe burst (StickS3) — "G16I"

## Context
Owner (2026-11-17, after accepting the v4 portraits — Very good green eyes, Horrible red eyes, red-eye ALERT, sharpened —
and running `guardian-20261117-203615` over OTA): "Fawkes should always stand facing up, independent of the direction. His
correct position is USB facing down, so he always stands up. 3D. If we shake it: thousand particles like a snow globe,
slowly reforming the face."

Decisions taken with the owner:
- Upright: CONTINUOUS counter-rotation by the gravity angle (like a level), not 4-way snapping.
- Burst: fires on a real SHAKE only (not taps, not walking); particles keep the face colours; HUD rating/text stays;
  an ALERT cancels the burst (red face wins — art never hides an incident).
- Scope: upright + burst on the existing 2D v4 portraits now. The Meshy 3D head is a separate later job.

## Facts from the code (read-only; paths under firmware/)
- Panel 135x240 fixed portrait ("portrait-usb-down", boards/sticks3/main/orientation.hpp:57-62). Bands: header y 0..18,
  face y 20..179 (135x160 art), rule row 180, HUD y 181..239 (adapters/companion/companion.hpp:178-205).
- Painter: adapters/companion/screens.cpp `draw()` :667-698 — clears the canvas, `pick_art` :595-600,
  `Placement at{zone_top,0,0,0}`, IMU pose only when `moving && !f.alert` (:675), `persona::paint_portrait(..., in.cache)`,
  then NoData bands, ALERT/amber borders, DEMO plate, HUD (hud_dx/dy parallax), text. `DrawInput{art, anim_ms, motion,
  imu, cache}` (companion.hpp:226-232) already passes board-owned mutable state (`WarpCache*`).
- Warp: persona.cpp `warp<Src>()` :94-123, inverse-mapped 16.16 fixed point, bilinear, cos/sin + 1/k scale, pivot {67,80}
  (:14), overwrites the whole 135x160 band (outside-art = black). `quantize` :68-72 (tilt 1/32°, scale 1/1024, shift
  1/16 px). `WarpCache` (persona.hpp:93-105, persona.cpp:186-218): `source_` = decoded portrait (135x160 u16), `band_` =
  last warped band, key = quantised pose + origin_y; both 43,200 B in PSRAM. README: warp ≈ 85 % of draw time.
- Canvas (components/guardian_canvas): fill_rect/draw_rect/put/get/text/pixels(); no blit, no alpha. Framebuffer 64,800 B
  internal DMA, big-endian.
- Motion model adapters/companion/motion.{hpp,cpp} ("floating fish"): complementary filter on `up_` (gyro-rotated;
  accel trust = max(0, 1-||acc|-1|/0.5), so a hard shake leaves the gyro alone); `lin_` = acc - up smoothed 30 ms.
  `step()` :93-143: `roll = atan2(-up_[0], up_[1])` (full ±180°, exported unclamped as `Output::roll_deg`), `pitch`,
  `w = min(1, in_plane/0.5)`; tilt target `clamp(w*roll_gain*roll + sway, max_roll_deg)` (defaults roll_gain -0.8,
  max_roll 20°) through an underdamped spring with a "tank wall" clamp. Sign: `tilt_deg` + = clockwise on the glass;
  upright = `tilt = -roll` (today's gain is already that direction, scaled and clamped). 16 `motion.*` TUNE keys
  (boards/sticks3/main/measurement_main.cpp:155-173, `configure_motion` :281-286).
- No shake detector exists; IMU taps were removed (white-flash complaint). `gp::MotionActivity` (adapters/power/idle.cpp
  :52-61) only feeds dim/wake: any shake keeps the screen Active; sleep is key-wake only (owner rule).
- IMU BMI270 200 Hz ±8 g ±2000 dps (adapters/imu/bmi270.hpp:34-42), imu task core 1 → Ring<64> → `drain_imu`
  (measurement_main.cpp:506-528) → `motion_model.sample`, `activity.sample`, `imu_pose.add`. Axis map imu.right=2
  imu.up=-1 imu.out=3. Console `IMU <s>` streams raw samples (used by tools/imu_axis_map.py).
- Loop: single main task (core 0, 16 KiB stack); face screens every `display.frame_ms` (default 40 ms); `motion_model.step`
  once per drawn frame; dirty-row push (max_runs 4), full push each 1000 ms; `frame_stats.add(frame_category(frame), …)`
  :1239-1258; `FRAMES` / STATUS report render_ms/push_ms/fps/warps/warp_reuses.
- MEASURED on the stick: render 5.8-13.2 ms, push 6.9-11.4 ms, frame avg 14-25 ms, 20-27 fps. heap_internal_min
  114-122 KB. PSRAM via `sticks3::psram::make` (never DMA/ISR). App 1,904,640 B = 60.5 % of the OTA slot.
- Portrait pixels MEASURED: lit (non-black) 9,631-9,956 px per rated/ALERT face (46 % of the band), hood bbox
  x 1..130, y 0..159 (≈130x157). Lit 3x3 blocks ≈ 1,357-1,391 per face (2x2 ≈ 2,900; 4x4 ≈ 820). NoData 1,575 blocks.
- TUNE registry: max_params 96, 88 used (8 free), keys ≤31 chars; `add_threat_limits` (52 keys, all-or-nothing) runs
  AFTER the board keys (measurement_main.cpp:1040) — new board keys must leave room (plan adds 6 → 94/96).
- Tests to extend: tests/motion_check.cpp (`Rig`, `rolled()/pitched()` helpers), tests/persona_check.cpp,
  tests/companion_check.cpp (`imu_motion_moves_face_and_decoration_but_never_the_text`,
  `alert_never_hides_behind_the_portrait`, `still_input()`), tests/frame_stats_check.cpp, tests/render_bench.cpp.

## Design

### A. Upright (counter-rotation by roll) — a mode inside `motion::Model`
New `Params::upright` (0/1) and `Params::upright_fit` (0..1); screens.cpp and the warp path stay unchanged (they already
take `imu.tilt_deg` / `imu.scale`). In `Model::step()` when upright:
1. Tilt target = `unwrap(-roll, pos_[2])` — the representative of `-roll + k·360` nearest the current `pos_[2]`, so the
   ±180° crossing never spins a full turn; wrap `pos_[2]` and the target together into (-180, 180]. Sway still added.
2. No tank wall on axis 2 (`bound[2]` = none); `max_roll_deg` ignored in this mode (documented in motion.hpp).
3. Lying flat (`in_plane < 0.3`, ≈17° from flat): HOLD the last target (no spin, no return to 0). No `w` fade (fading
   would rotate the face back toward 0 while the stick is laid down).
4. Rest deadband 0.5° (constant): the target only moves when `|new − held| > 0.5°`, so the quantised pose is exactly
   constant at rest and `WarpCache` hits. Spike S2b decides whether it is mandatory.
5. Scale at angle: `fit(θ) = min(1, 135/(W|cosθ|+H|sinθ|), 160/(W|sinθ|+H|cosθ|))` with the measured hood W=130,
   H=157 (new `persona::hood_w/hood_h`, asserted in persona_check); 1.0 at 0°, 0.66 at 45°, 0.86 at 90°.
   `scale = 1 − upright_fit·(1 − fit(pos_[2]))`: `upright_fit=1` never clips the hood, `0` keeps the size and clips hood
   corners (eyes/mouth/cigar stay within ~45 px of the pivot, never clipped). Owner picks live over TUNE.
6. New `Output` fields for the burst: `up_x, up_y` (screen-plane gravity = −up_) and `lin_x, lin_y` (the shove); 0 when
   inactive.
Cost: the inverse-mapped warp is angle-independent per pixel; while rotating = today's "handled" cost (one warp per
frame), at rest (deadband) = today's rest cost (band copy). Nothing new in the per-frame path.
TUNE: `motion.upright` (0..1, default 0 on the first OTA so the owner flips it live; 1 after acceptance),
`motion.upright_fit` (0..1, default 1). Ranges as `upright_range` / `upright_fit_range` in motion.hpp, rows in
`motion_keys[]`.

### B. Shake detector — `adapters/companion/shake.{hpp,cpp}` (portable, axis-map independent)
Fed `acc_g[3]` in `drain_imu` beside `activity.sample`. Per axis a slow gravity low-pass (τ 1 s); `hp = acc − g`.
An ALTERNATION is counted when the dominant axis crosses `+g_thr` after last being below `−g_thr` (or vice versa);
timestamps in a ring of 16. Fire when ≥ `peaks` alternations fall inside `window_ms`; refractory 1,000 ms (constant).
`take()` once per event (same shape as `MotionActivity::take`), `events()` for STATUS `shakes=`.
Rejections by construction: a tap = one impulse (1 alternation); walking ≈ 2 Hz ≤ 0.3 g < threshold; a drop = one-sided
free fall + one impact; a steady spin = one-sided centripetal; the FRONT x3 update gesture is key-driven (`ota::TripleTap`)
and the board also refuses `burst.begin` while `update_confirm.is_open()`.
`shake::Params { float g{1.2f}; uint8_t peaks{8}; uint16_t window_ms{1500}; }`, `class Detector { configure; sample(acc_g,
t_us); take; events }`. TUNE (3): `shake.g` 0.5..4.0 (1.2), `shake.peaks` 2..16 (8), `shake.window_ms` 200..3000 (1500).
Thresholds are the MEASURED S3/S3b values (see Spike results); min gap 60 ms and refractory 1000 ms are constants.

### C. Burst — `adapters/companion/burst.{hpp,cpp}` (portable)
- Particle = one lit 3x3 block of the current portrait (grid 45x54; ≈1,380 per face — the owner's "thousand").
  `capacity = 1600`; `begin` refuses an art with more lit blocks (NoData never bursts anyway) — never a partial face.
  `Particle { int16 x, y (1/64 px); int16 vx, vy (1/64 px/s); uint16 home; }` = 10 B → 16,000 B, board-owned in PSRAM
  via `psram::make<burst::Burst>`; host: plain object. Colours are not stored: `paint` reads the 9 home pixels through a
  `persona::PixelSource` (`NativeArt`/`ByteArt` moved public into persona.hpp; `WarpCache` gains `art()` and `source()`).
- API: `begin(art, PixelSource, now, impulse_x, impulse_y, seed)`, `kick(...)` (a shake during drift/reform re-scatters,
  snow-globe style), `step(now, g_x, g_y)` (dt clamped 10..100 ms), `cancel()`, `active()`, `art()`, `paint(Canvas&,
  origin_y)`, `phase()`.
- Phases, scaled by TUNE `burst.s` (total, default 3.5 s): explode 0.5 s (radial velocity 120..300 px/s from the pivot,
  xorshift32 jitter from `seed`, + 2× the shake impulse `lin_x/lin_y`), drift 1.0 s (gravity 250 px/s² along
  (−up_x, −up_y) from the motion output, default +y when inactive; drag 0.96/frame; bounce off the band walls = the
  glass), reform 2.0 s (`pos = drift_pos + (home − drift_pos)·smoothstep(t)`; the final frame lands every block exactly
  on its integer home → the band equals the identity-pose portrait; "slowly reforming"). Positions clipped to the band.
- Background during the burst: black band + HUD/text intact (Canvas has no alpha; a ghost face would need a second warp).
- Rules, all inside `draw()` (host-tested): `burst_allowed(f) = face_shown && persona && art == FaceArt::Rated && !alert`.
  If `in.burst && in.burst->active()`: when `!burst_allowed(f)` or `in.burst->art() != pick_art(...)` → `cancel()` and
  paint normally; else `in.burst->paint(c, zone_top)` and skip `paint_portrait` (no warp, no ember/smoke, no glance; the
  cache is untouched and resumes after reform with one warp). So: ALERT cancels at once (red stare paints), amber does not
  cancel (its dashed border + HUD stay), NoData never bursts, a rating change or pulse cancels, celebrate suppressed.
- Board wiring (measurement_main.cpp): `drain_imu` → `shake.sample`; in the animated-frame branch before `draw`:
  `if (shake.take() && burst_allowed(frame) && idle Active && !update_confirm.is_open() && !tune_session.active() &&
  control==Companion && warp_cache && warp_cache->art()==art) burst->begin(...)`; `burst->step(now, in.imu.up_x,
  in.imu.up_y)`; `in.burst = burst`. `burst->cancel()` on Dim/Sleep, console, EDGE, UPDATE. The burst never feeds
  `gp::Inputs` (never delays sleep). `FrameKind::Burst` via `frame_category(const Frame&, bool burst)` so `FRAMES`
  prints `kind=burst`; STATUS adds `shakes= bursts=`.
- CPU estimate (INFERRED, spike S1 measures it): 1,380 × (integrate + 9 PSRAM reads + 9 writes) ≈ 1 ms at 160 MHz,
  cheaper than one warp (21,600 bilinear samples). Push: the band changes every frame → ~160 dirty rows (≈ ⅔ of a full
  push, ≈ 8 ms).

### D. Where state lives
`Frame` stays information-only (no burst/shake fields). `DrawInput` gains `burst::Burst* burst{}` (board-owned, like
`cache`). `motion::Output` gains `up_x, up_y, lin_x, lin_y`. New portable files `adapters/companion/shake.*` and
`burst.*` join `guardian_companion` (firmware/CMakeLists.txt) and the sticks3 component sources (the `-O2` group with
persona/motion/screens in boards/sticks3/main/CMakeLists.txt:39-45). Board code only wires TUNE, PSRAM placement,
trigger/cancel, STATUS/FRAMES.

## Files to change / add
- Change: adapters/companion/motion.hpp, motion.cpp (upright mode, unwrap/hold/deadband/fit, Output fields, ranges)
- Change: adapters/companion/persona.hpp, persona.cpp (`hood_w/hood_h`, `PixelSource` public, `WarpCache::art()/source()`)
- Change: adapters/companion/companion.hpp (`DrawInput::burst`), screens.cpp (`burst_allowed`, draw rule)
- Add: adapters/companion/shake.hpp/.cpp, burst.hpp/.cpp
- Change: boards/sticks3/main/measurement_main.cpp (6 TUNE keys: `motion.upright`, `motion.upright_fit`, `shake.g`,
  `shake.peaks`, `shake.window_ms`, `burst.s` → 94/96; shake feed; burst trigger/cancel; STATUS), frame_stats.hpp
  (`FrameKind::Burst`), boards/sticks3/main/CMakeLists.txt (sources)
- Change: firmware/CMakeLists.txt (sources, `shake_check`, `burst_check` targets), tests/render_bench.cpp (`rated-burst`)
- Add tests: tests/shake_check.cpp, tests/burst_check.cpp, tests/fixtures/imu/ (recorded traces from S3);
  extend motion_check.cpp, persona_check.cpp, companion_check.cpp, frame_stats_check.cpp
- Docs/evidence: firmware/README.md section; firmware/evidence/sticks3-G16I-*.log; ledger row G16I (owner-approved text)

## Spikes FIRST (throwaway, recorded; the plan is not final until these numbers exist)
- S1 (host): throwaway `rated-burst` scenario in render_bench with 1,380 3x3 particles painted from `source_` (and a
  2,900 × 2x2 variant). GO if `draw_us(rated-burst) ≤ draw_us(rated-moving)` on the same build, and the extrapolated
  device render (host→device ratio from the existing rated-moving pair: host 93 µs ↔ device `FRAMES kind=rated`
  render_ms) ≤ 15 ms, so render + band push ≤ 40 ms. NO-GO → 4x4 blocks (~820) and re-run.
- S2 (device, today's image, owner opens a TUNE session): (a) `TUNE motion.roll_gain=-2`, `motion.max_roll=45`, roll the
  stick ±25° slowly for 60 s → `FRAMES 0` … `FRAMES`: GO if `kind=rated` fps ≥ 20 and `total_max_ms ≤ 60` with a warp
  per frame (STATUS `warps` ≈ frames). (b) still 30 s → `warps` vs `warp_reuses`: reuses < 50 % at rest ⇒ the 0.5°
  deadband is mandatory. Record `heap_internal_min`.
- S3 (device + owner, USB console `IMU 10`, 10 s each, saved verbatim to firmware/evidence/sticks3-imu-shake-<label>-
  <date>.txt and tests/fixtures/imu/): still; one tap on the body; the real FRONT x3 (then SIDE = no); walking in hand;
  three hard shakes; set down hard; (owner's call) a 10 cm drop onto a cushion. Offline python over the traces: GO if
  every shake gives ≥ 2×`peaks` alternations above `shake.g` and every non-shake trace ≤ `peaks − 2`. Not separable ⇒
  change the rule (e.g. ≥ 2 alternations of each sign) before writing shake.cpp.

### Spike results
- S1 DONE 2026-11-17 (host, clang -O2, scratchpad/spike-s1/bench.cpp, 300 frames, includes the canvas clear):
  warp per frame (tilt changing each frame, WarpCache miss) **85.5 µs**; particles painted from `source_` with
  integrate + walls: 3x3 n=1,388 **15.0 µs** (Medium) / 12.6 µs (VeryGood); 2x2 n=2,898 17.3 µs; 4x4 n=813 8.1 µs.
  → a particle frame costs ≈ 1/6 of a warp. **GO for 3x3 (≈1,380 particles).** Device render stays below today's
  "handled" case; push dominates (band changes every frame).
- S2 DONE (device, USB console, 2026-11-17): rotation handled by the owner with `motion.roll_gain=-2`,
  `max_roll=45`: `kind=rated` 235 frames, render 19.0 ms, push 11.9 ms, total_max 36.0 ms, 24.9 fps, a warp per
  frame → **GO**. Rest MEASURED later the same evening (face screen, stick still 30 s): 903 frames, warps 961, warp_reuses 31
  (3 %), render 19.0 / push 11.9 ms, 24.9 fps, total_max 37.7 ms: today's code already warps EVERY frame at rest
  because the breath scale (4 s period, quantised 1/1024) and the idle sway change the cache key each frame. So
  upright adds NO rest cost, and the 0.5° deadband is for a jitter-free picture, not for the cache. TUNE restored:
  roll_gain -0.8, max_roll 20, version 1.22 saved. Side finding: `imu_drops` ≈ 24 % of samples (ring overflow, pre-existing);
  the port open over USB resets the stick (every session starts from boot). The two TUNE values were SAVED by the
  spike and must be restored (-0.8 / 20).
- S3 DONE (7 traces, 10 s each, firmware/evidence/sticks3-imu-shake-<label>-20261117.txt; offline rule: gravity
  low-pass τ 1 s, dominant-axis sign alternation with ±thr hysteresis, min gap 60 ms):
  still/walk/setdown/tap: 0 alternations at 1.2 g (tap peaks 2.08 g but one impulse). front3 (the FRONT x3 update
  gesture): peak 3.07 g, 7 alternations, max 5 in 700 ms / 6 in 1500 ms. shake (three hard shakes): peak 5.05 g,
  23 alternations at ~8-9 Hz (gaps 80-120 ms), 8 in 700 ms / 16 in 1500 ms. "drop" (10 cm onto a cushion): looks
  like a shake (27 alternations over 2.9 s, 5.35 g) — probably handling/bounce; to be re-recorded hands-off.
  → the plan's defaults (4 peaks / 700 ms) would FIRE on FRONT x3.
- S3b DONE (2 more traces, same rule, scratchpad/spike-s3/analyse.py): `softshake` (owner's gentlest shake, held
  ~8 s at ~4 Hz, peak 2.39 g): 24 alternations, **11 in 1500 ms**, fires at 3.35 s. `drop2` (hands-off drops onto a
  cushion; three impacts 7.3 / 6.5 / 8.8 g): 15 alternations spread over 8.3 s, **max 5 in 1500 ms**, never fires. The
  first "drop" trace was handling, not a drop. Threshold sweep: 1.0 g makes front3 reach 8 (fires at peaks 8); 1.5 g
  drops softshake to 3 (never fires). 1.2 g is the only threshold with a gap.
  **FINAL defaults: shake.g 1.2, shake.window_ms 1500, shake.peaks 8, min gap 60 ms (constant), refractory 1000 ms.**
  Separation at 1.2 g / 1.5 s: shake 16, softshake 11 ≥ 8 fire; front3 6, drop2 5, tap/still/walk/setdown 0 < 8 do
  not. Margin 2 alternations each side. A one-wiggle shake (≈3 oscillations ≈ 6 alternations) is indistinguishable
  from FRONT x3 by count and must not burst (the board also refuses `begin` while `update_confirm.is_open()`). All
  nine traces become tests/fixtures/imu/ with their labels (`recorded_device_traces_classify_as_labelled`).

## Step order (TDD: failing test named, minimal code, green, refactor)
1. S1-S3; write the numbers into the handoff; fix block size, deadband, thresholds.
2. persona: `hood_w/hood_h`, `PixelSource` public, `WarpCache::art()/source()`. Tests: extend
   `art_matches_the_documented_size_and_cigar_anchor` (every rated portrait's bbox within 130x157); new
   `warp_cache_exposes_the_decoded_source_and_its_art`.
3. motion upright. New motion_check cases: `upright_counter_rotates_fully_through_a_quarter_turn`,
   `upright_crosses_minus_180_without_spinning`, `upright_holds_the_last_angle_when_lying_flat`,
   `upright_fit_scale_keeps_the_hood_inside_the_band_at_every_angle`,
   `upright_is_exactly_still_under_sensor_noise_at_rest` (identical tilt across 100 frames with ±0.2° roll noise),
   `upright_mode_exposes_gravity_and_shove_for_the_burst`; extend `defaults_lie_inside_their_tune_ranges`. Board: 2 keys.
4. shake: tests/shake_check.cpp — `a_single_tap_is_not_a_shake`, `three_fast_taps_like_the_update_gesture_are_not_a_shake`,
   `walking_two_hz_under_point_three_g_is_not_a_shake`, `a_drop_free_fall_then_impact_is_not_a_shake`,
   `a_steady_spin_is_not_a_shake`, `a_real_shake_five_hz_two_g_fires_once`, `a_weak_shake_under_threshold_does_not_fire`,
   `a_second_shake_inside_the_refractory_is_ignored_then_a_later_one_fires`, `thresholds_follow_configure`,
   `defaults_lie_inside_their_tune_ranges`, `recorded_device_traces_classify_as_labelled` (fixtures from S3).
   Board: `shake.sample` in `drain_imu`, 3 keys, STATUS `shakes=`.
5. burst: tests/burst_check.cpp — `begin_takes_one_particle_per_lit_block_and_refuses_oversized_art`,
   `particles_stay_inside_the_band_in_every_phase`, `explode_moves_every_particle_away_from_the_pivot`,
   `gravity_follows_the_given_up_vector`, `reform_lands_every_block_exactly_on_its_home`,
   `final_frame_equals_the_identity_portrait` (vs `paint_portrait` with tilt_max 0, breath 0),
   `kick_during_reform_rescatters`, `step_is_frame_rate_independent`, `cancel_stops_painting`.
   companion_check new: `burst_never_paints_outside_the_band`, `alert_cancels_burst_and_paints_the_red_stare`,
   `text_and_hud_untouched_during_burst`, `burst_reforms_to_exact_pixels`, `no_burst_without_a_rated_face`,
   `a_changed_portrait_cancels_the_burst`, `caution_border_stays_during_burst`. frame_stats_check:
   `burst_frames_are_counted_as_their_own_kind`. render_bench: `rated-burst` kept permanently.
   Board: `psram::make<Burst>`, trigger, cancel on Dim/console/UPDATE, `FrameKind::Burst`, `burst.s`, STATUS `bursts=`.
6. `firmware/tools/host-check.sh` (plain + ASan/UBSan) green; `companion_preview` sheet with a mid-burst frame; signed
   archive via boards/sticks3/tools/build.sh; shipped-artifact check (SHA256SUMS, signature, 16 portraits in the bin).

## Verification on device (owner handles the stick; sessions read the records)
- Owner: OTA (FRONT x3) of the archive; `tools/tune_session.py` for live TUNE.
- Upright: `TUNE motion.upright=1`; roll slowly through 360°, lay it flat: face stays upright, no spin at ±180°, holds
  when flat; `FRAMES kind=rated` ≥ 20 fps, `total_max_ms` recorded; still 30 s → `warp_reuses` ≥ 50 % of frames;
  owner picks `upright_fit` 0 or 1.
- Shake: one tap, FRONT x3 (answer SIDE), walk, three shakes → STATUS `shakes=` increments only on the shakes; burst
  visible, HUD text steady, reform completes ≈ 3.5 s; `FRAMES kind=burst` render + push ≤ 40 ms, fps ≥ 20.
- ALERT during a burst (DEMO walk, or a lab scenario the owner launches explicitly): red stare at once.
- `heap_internal_min` and `task_stack_free` unchanged vs `guardian-20261117-203615`; +16,000 B PSRAM reported.
- Evidence: firmware/evidence/sticks3-G16I-upright-burst-<stamp>.log (boot, FRAMES before/after, STATUS), S3 trace
  files, owner video (claude-code-eyes camera if offered); host logs on $GUARDIAN_STORE/builds/<stamp>-g16i-tdd/.
- Out of scope here: the Meshy 3D head (separate job; the IMU already outputs held roll/pitch/yaw for angle frames).

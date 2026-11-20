# M5 Guardian G15 visual integration notes

**Based on the uploaded `m5-guardian.zip`, inspected 2026-11-16.**

## What was verified in source

- `firmware/adapters/companion/screens.cpp::draw()` still draws placeholder rectangles, not Blender/PNG assets. No existing code path consumes the newly generated `.rgb565` files.
- `firmware/adapters/companion/companion.hpp::Frame` defines `face_x=4`, `face_y=16`, `face_size=64`; this conflicts with the designed `0..151 × 0..134` G15 persona area.
- The display is `240×135` RGB565. `guardian_canvas` is portable and draws into a buffer; the display-facing buffer may need byte swapping (see constructor `big_endian`). The raw frame exporter writes little-endian 565 bytes.
- `docs/G08-presenter.md` specifies five rated faces, `Unknown` when not rated, suppressed celebration when data are stale/degraded, and ALERT as an independent safety signal. The `ViewModel` and `Frame` carry `face`, `muted`, `alert`, and `celebrate`.
- G15 remains awaiting owner/art and device inspection; this pack is not a flashed or runtime-tested integration.

## Recommended asset selection

```cpp
// Concept only, adapt to the actual asset loader.
if (frame.muted || frame.face == Mood::Unknown) {
    // Do NOT show a confident security rating. Keep the evidence overlay and text.
} else {
    const char *base = mood_to_asset_stem(frame.face);  // VeryGood, Good, etc.
    if (frame.alert)
        use_frame(base, pulse_phase ? "_ALERT_p1" : "_ALERT_p0");
    else
        use_frame(base);
}
```

Alert may still need to be drawn even when there is no fresh usable *rating*; that must be a **separate UI signal with reason**. Do not conceal ALERT because the rated portrait is muted. Never infer an alert from `Mood::Horrible` or a mood from an alert.

## Layout blocker to fix before device use

The new stills reserve x=152..239 for application text and occupy almost the full height of x=0..151. The current renderer places a full-width header at y=0 and full-width status/hints y=84..134. If blitted with the existing implementation, art and text overlap. A new G15 face layout must reposition or defer text to details pages, or use smaller art. This is a design/firmware change, not an art export setting.

## Asset storage and drawing

15 raw frames × 64,800 bytes = 972,000 bytes (~949 KiB). The 5056 KiB `assets` partition is reserved but unmounted in the uploaded code. Possible integration options:

1. Mount an approved read-only asset partition and decode 240×135 RGB565 into the existing display frame, with correct byte order; validate transfer completion and bounds.
2. Embed compiled compressed images and decode one image at a time into the existing framebuffer; bench memory/flash impact.
3. For static display budgets, store only 5 portraits, derive two alert phases procedurally **after** selecting the rated portrait; keep the alert noncolor shape cue.

Do not change rating policy or source-of-truth status for the sake of art. Host render tests should assert exactly 5 moods, valid filenames, no wrong phase selection, no text overlap. Physical StickS3 inspection still required.

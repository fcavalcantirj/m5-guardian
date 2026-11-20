#pragma once
#include <cstddef>
#include <cstdint>
#include <array>
#include "guardian/canvas.hpp"
#include "guardian/core.hpp"
#include "guardian/time.hpp"

// G16: the "Very good" portrait renderer. SDK-free and host-tested. G16A: the
// art is the upright 135x160 crop of the accepted G15 v2 master
// (art/persona/v2/portrait/VeryGood_portrait.rgb565, little-endian RGB565,
// 43,200 bytes, built by build_assets.py portrait); it fills the face zone at
// the top of the 135x240 panel. This module adds the motion the still lacks: a
// gentle head tilt, subtle breathing, a restrained ember glow on the cigar and
// a small looping curl of smoke. It only paints the face zone (y < art_h); the
// information zone below is the composer's. It never decides a mood: the
// caller shows it only for a fresh, rated Very good with no incident.
namespace guardian::companion::persona {

constexpr int art_w = 135, art_h = 160, portrait_w = art_w;
constexpr std::size_t art_pixels = static_cast<std::size_t>(art_w) * art_h;
constexpr std::size_t art_bytes = art_pixels * 2;
// All motion repeats exactly after this many milliseconds (lcm of the periods).
constexpr Millis loop_ms = 28000;

// G16C: dx/dy (screen px) shift the whole portrait (IMU inertia); identity by default.
struct Pose { float tilt_deg{}; float scale{1.0f}; float dx{}; float dy{}; };
// G16A live-tunable motion (TUNE persona.*); defaults are the accepted G16 motion.
struct Motion {
    float tilt_max_deg{1.2f};     // head tilt amplitude
    float breath_amount{0.008f};  // breathing scale amplitude
    float ember_peak{0.30f};      // ember glow blend at its brightest
    float smoke_alpha{0.62f};     // smoke puff opacity at mid-curl
};
// Pure function of time: identity at t = 0, |tilt| <= tilt_max_deg, |scale - 1| <= breath_amount.
Pose pose_at(Millis t, const Motion& = {});

struct Point { float x{}, y{}; };
// The portrait turns and scales about this point of the art (the middle of the mask).
constexpr Point pivot{67.0f, 80.0f};
// Lit end of the cigar in the art's own coordinates (measured on
// VeryGood_portrait.rgb565: orange ember pixels x 30..34, y 105..110).
constexpr Point cigar_tip{32.0f, 108.0f};
// Art coordinates to screen coordinates under a pose.
Point map_point(Pose, Point);

struct Rect { int x0, y0, x1, y1; };     // x1/y1 exclusive
// G16I: the hood of every rated and ALERT portrait lies inside this box of the art (MEASURED on the
// 15 frames 2026-11-17: lit columns 1..130, hood rows 0..155; persona_check keeps it true). 130x157.
// G16Q part 2 (candidate D, 2026-11-19): the linear-light resize keeps more light on the anti-aliased right
// rim, so the 15 frames now light columns 1..133 (dim rim pixels, rows ~75..90); hood rows still 0..155. 133x157.
constexpr int hood_w = 133, hood_h = 157;
constexpr Rect hood_box{1, 0, 1 + hood_w, hood_h};
// G16I upright: the largest scale <= 1 at which the hood box, turned by tilt_deg about the pivot,
// stays inside the 135x160 band. 1 at 0 degrees (today's exact placement), about 0.66 at 45, 0.85 at 90.
float fit_scale(float tilt_deg);
// Smoke never leaves this box: left of the glowing eyes (x >= 36, y 50..70),
// above the ember, inside the face zone and so clear of all text.
constexpr Rect smoke_zone{4, 64, 36, 112};

struct Layers { bool portrait{true}, ember{true}, smoke{true}; };
// `art` points at art_bytes bytes. Writes x < portrait_w, y < art_h only.
void paint_very_good(Canvas&, const std::uint8_t* art, Millis t, Layers = {}, const Motion& = {});

// ---- G16C: every rating, ALERT pulses, the no-data silhouette -----------------
// The 16 embedded portraits (art/persona/v2/portrait/*_portrait.rgb565, built by
// build_assets.py portraits): one per rating, two ALERT pulses per rating
// and the expression-free NoData silhouette. Indexed by rated mood (VeryGood
// .. Horrible); Unknown has no rated portrait by design.
struct ArtSet {
    std::array<const std::uint8_t*, 5> rated{};
    std::array<std::array<const std::uint8_t*, 2>, 5> alert{};
    const std::uint8_t* no_data{};
    bool complete() const;   // all 16 frames present
};
// 0..4 for VeryGood..Horrible, -1 for Unknown (no rated portrait exists for it).
int rated_index(Mood);
// ALERT pulse phase (0/1) at time t: the two ALERT masters alternate.
constexpr Millis alert_pulse_ms = 450;
inline int alert_pulse(Millis t) { return static_cast<int>((t / alert_pulse_ms) & 1u); }
// Where and how the portrait is drawn: face zone top row, IMU shift/tilt.
// scale (review 2026-11-17): < 1 pulls a moving face back from the glass edges (the hood fills the
// panel edge to edge at rest); multiplies the breathing scale. 1 = today's exact placement.
struct Placement { int origin_y{0}; float dx{}, dy{}, tilt_deg{}; float scale{1.0f}; };
// Paints `art` (art_bytes) into rows [origin_y, origin_y + art_h) under the idle
// motion at t plus the placement; `cigar` adds the Very good ember and smoke.
// Writes nothing outside that band.
void paint_portrait(Canvas&, const std::uint8_t* art, Millis t, const Placement&, Layers, const Motion&, bool cigar);
// Breathing/sway of the idle pose plus a placement (pure).
Pose pose_with(Millis t, const Motion&, const Placement&);

// ---- G16C rework: fast warp, portrait in fast RAM, still frames not re-warped ----
// The warp quantizes its pose (tilt 1/32 deg, scale 1/1024, shift 1/16 px: at
// most ~0.05 px anywhere on the portrait) and samples with 1/32-pixel bilinear
// weights in integer RGB565 arithmetic. The identity pose and whole-pixel
// shifts remain exact copies. Ember and smoke use the exact pose.
//
// WarpCache (optional, owned by the board): `source` and `band` each hold
// art_pixels values. The current portrait is decoded into `source` once per
// change of art (StickS3: PSRAM, never the internal heap the radio needs); the
// warped band (canvas encoding) is kept in `band` and copied back, without a
// warp, while the art, the quantized pose and the placement row are unchanged.
// Painting through the cache gives exactly the pixels painting without it does.
//
// G16I: a portrait's pixels for readers other than the warp (the burst): the decoded native copy
// (WarpCache::source) or the little-endian art bytes. x < art_w, y < art_h; the caller keeps bounds.
struct NativeArt {
    const std::uint16_t* p;
    std::uint16_t at(int x, int y) const { return p[y * art_w + x]; }
};
struct ByteArt {
    const std::uint8_t* p;
    std::uint16_t at(int x, int y) const {
        const auto i = static_cast<std::size_t>(y * art_w + x) * 2;
        return static_cast<std::uint16_t>(p[i] | (p[i + 1] << 8));
    }
};
struct PixelSource {
    const std::uint16_t* native{};   // art_pixels decoded values, or
    const std::uint8_t* bytes{};     // art_bytes little-endian bytes
    bool valid() const { return native || bytes; }
    std::uint16_t at(int x, int y) const { return native ? NativeArt{native}.at(x, y) : ByteArt{bytes}.at(x, y); }
};
class WarpCache {
public:
    WarpCache(std::uint16_t* source, std::uint16_t* band) : source_(source), band_(band) {}
    void invalidate() { art_ = nullptr; valid_ = false; }
    // G16I: which portrait the decoded copy holds (nullptr: none yet) and that copy.
    const std::uint8_t* art() const { return art_; }
    PixelSource source() const { return art_ ? PixelSource{source_, nullptr} : PixelSource{}; }
    std::uint32_t copies{}, warps{}, reuses{};   // portraits decoded, bands warped, bands reused
private:
    friend void paint_portrait(Canvas&, const std::uint8_t*, Millis, const Placement&, Layers, const Motion&, bool, WarpCache*);
    std::uint16_t* source_;
    std::uint16_t* band_;
    const std::uint8_t* art_{};
    bool valid_{};
    std::array<std::int32_t, 7> key_{};
};
void paint_portrait(Canvas&, const std::uint8_t* art, Millis t, const Placement&, Layers, const Motion&, bool cigar, WarpCache* cache);
// Full-precision float reference of the portrait warp (exact pose, 1/256 px
// weights; the pre-rework renderer). Host checks only: bounds the quantized warp.
void paint_portrait_reference(Canvas&, const std::uint8_t* art, Millis t, const Placement&, const Motion& = {});

} // namespace guardian::companion::persona

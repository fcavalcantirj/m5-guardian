#pragma once
// G16Q art bench (build variant CONFIG_GUARDIAN_ART_BENCH, `tools/build.sh build-art-bench`):
// the approved v4 portraits rendered by candidate pipelines, shown one at a time on the real
// glass so the owner picks the knobs that later become the Guardian's defaults.
//
// This file and art_bench.cpp are SDK-free and host-tested (tests/art_bench_check.cpp): the
// candidate catalogue, the key handling (FRONT = next, SIDE = backlight 60/80/100 %), the 2 s
// label, the STATUS fragment and the drawing. The board glue in measurement_main.cpp only
// applies what this says (backlight percent, gamma table on or off) and pushes the canvas.
//
// Frames: firmware/art/bench/<A..E>_<Mood>.rgb565 and ramp.rgb565, 135x240 little-endian
// RGB565 (64,800 B each), made and pinned by tools/art/candidates.py. A..D hold the 135x160
// portrait in rows 20..179 (the Guardian's face zone) on black; E fills all 240 rows.
// F, G and H show D's frame: F with the gamma table, G with the gamma table at 100 %
// backlight, H through the Guardian's own portrait painter, still (breath 0) and breathing
// (the default breath, a bilinear resample on every frame).
#include <array>
#include <cstddef>
#include <cstdint>

#include "guardian/canvas.hpp"
#include "persona.hpp"

namespace sticks3::artbench {

constexpr int frame_w = 135, frame_h = 240;
constexpr std::size_t frame_bytes = static_cast<std::size_t>(frame_w) * frame_h * 2;
constexpr int face_row = 20;                 // the companion layout's face zone: rows 20..179
constexpr std::uint32_t label_ms = 2000;     // the candidate's name stays this long, then the exact frame
constexpr std::uint32_t debounce_ms = 30;    // a key must have been up this long before a press counts
constexpr int label_top = 196;               // the label box: rows label_top..frame_h-1 (below the face zone)

constexpr int pipelines = 5;                 // A..E (embedded frames)
constexpr int moods = 3;
constexpr std::array<const char*, moods> mood_names{"VeryGood", "Horrible", "Medium"};
constexpr std::array<const char*, moods> mood_labels{"Very good", "Horrible", "Medium"};
constexpr std::array<std::uint8_t, 3> backlight_steps{60, 80, 100};

// The embedded frames; every pointer addresses frame_bytes bytes.
struct Frames {
    std::array<std::array<const std::uint8_t*, moods>, pipelines> art{};   // [A..E][mood]
    const std::uint8_t* ramp{};
    bool complete() const;
};

enum class Motion : std::uint8_t {
    Exact,    // the frame's bytes, copied
    Still,    // the face band through persona::paint_portrait with breath 0 (what persona.breath = 0 shows)
    Breath,   // the same with the default breath: a resampled copy on every frame (what the Guardian shows today)
};
struct Entry {
    const char* name;            // STATUS bench=<name>
    const char* label;           // first label line on the glass
    std::int8_t pipeline;        // 0..4 = A..E, -1 = the grey ramp
    std::int8_t mood;            // 0..2 (mood_names), -1 = the grey ramp
    bool gamma;                  // the M5GFX gamma table is sent to the panel
    std::uint8_t backlight_pct;  // the backlight this candidate starts with
    Motion motion;
};
// Per mood: A, B, C, D, E, F, G, H-still, H-breath; then the grey ramp without and with the gamma table.
constexpr std::size_t entry_count = static_cast<std::size_t>(moods) * 9 + 2;
const Entry& entry(std::size_t index);   // index % entry_count
// The frame an entry shows; nullptr when it is not embedded.
const std::uint8_t* frame_of(const Entry&, const Frames&);

// ST7789 positive / negative voltage gamma control as M5GFX sends them for the StickS3
// (M5GFX 0.2.28, commit d91077b9a607b59404e4e4a49f775c792bfae382,
// src/lgfx/v1/panel/Panel_ST7789.hpp list0; a Lovyan GFX file, "FreeBSD" licence per its header: see
// THIRD_PARTY_NOTICES.md; values only). Source observation, not a
// measurement: what they do on this glass is what the bench is for.
struct GammaCommand { std::uint8_t command; std::array<std::uint8_t, 14> data; };
extern const std::array<GammaCommand, 2> m5gfx_gamma;

class Bench {
public:
    struct Change {
        bool entry{}, backlight{};
        bool any() const { return entry || backlight; }
    };
    // Raw key levels (true = down) every loop. A press is a key going down after it was up for
    // debounce_ms; a key held since boot is not a press. FRONT: next candidate. SIDE: next backlight step.
    Change keys(bool front, bool side, std::uint32_t now_ms);
    void next(std::uint32_t now_ms);
    void prev(std::uint32_t now_ms);
    bool go(const char* name, std::uint32_t now_ms);           // false: no candidate with this name
    bool set_backlight(int percent, std::uint32_t now_ms);     // false: not one of backlight_steps

    std::size_t index() const { return index_; }
    const Entry& current() const { return entry(index_); }
    std::uint8_t backlight_pct() const { return backlight_; }
    bool gamma() const { return current().gamma; }
    bool animated() const { return current().motion == Motion::Breath; }
    // True from a candidate or backlight change (and from boot) until label_ms later.
    bool label_visible(std::uint32_t now_ms) const;
    // " bench=<name> bench_index=<n>/<count> bench_bl=<pct> bench_gamma=<0|1> bench_motion=<exact|still|breath>
    //   bench_frames=<ok|missing>"; returns the length written (0 when it does not fit).
    std::size_t status(char* out, std::size_t cap, bool frames_ok) const;

private:
    struct KeyState { bool down{true}; std::uint32_t up_since{}; };   // "down" until first seen up
    static bool pressed(KeyState&, bool level, std::uint32_t now_ms);
    void enter(std::size_t index, std::uint32_t now_ms);
    std::size_t index_{};
    std::uint8_t backlight_{60};
    std::uint32_t changed_at_{};
    KeyState front_{}, side_{};
};

const char* motion_text(Motion);
// Paints the whole 135x240 canvas for the bench's current candidate at now_ms: the frame (exact, or
// its face band through the persona painter), then the label box while it is visible. Missing frames
// paint a plain "frames missing" message. `cache` is the board's portrait warp cache (optional).
void draw(guardian::Canvas&, const Bench&, const Frames&, std::uint32_t now_ms,
          guardian::companion::persona::WarpCache* cache = nullptr);

} // namespace sticks3::artbench

// G16Q art bench: catalogue, keys, label, STATUS fragment and drawing (SDK-free; see art_bench.hpp).
#include "art_bench.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace sticks3::artbench {
namespace {
namespace persona = guardian::companion::persona;
using guardian::Canvas;

// One mood's nine candidates. F, G and H show D's frame (pipeline 3).
#define GUARDIAN_BENCH_MOOD(NAME, INDEX)                                    \
    Entry{"A-" NAME, "A today", 0, INDEX, false, 60, Motion::Exact},        \
    Entry{"B-" NAME, "B linear", 1, INDEX, false, 60, Motion::Exact},       \
    Entry{"C-" NAME, "C unsharp", 2, INDEX, false, 60, Motion::Exact},      \
    Entry{"D-" NAME, "D dither", 3, INDEX, false, 60, Motion::Exact},       \
    Entry{"E-" NAME, "E full 240", 4, INDEX, false, 60, Motion::Exact},     \
    Entry{"F-" NAME, "F gamma", 3, INDEX, true, 60, Motion::Exact},         \
    Entry{"G-" NAME, "G gamma 100", 3, INDEX, true, 100, Motion::Exact},    \
    Entry{"H-still-" NAME, "H still", 3, INDEX, false, 60, Motion::Still},  \
    Entry{"H-breath-" NAME, "H breath", 3, INDEX, false, 60, Motion::Breath}
const std::array<Entry, entry_count> kEntries{{
    GUARDIAN_BENCH_MOOD("VeryGood", 0),
    GUARDIAN_BENCH_MOOD("Horrible", 1),
    GUARDIAN_BENCH_MOOD("Medium", 2),
    Entry{"ramp", "ramp", -1, -1, false, 60, Motion::Exact},
    Entry{"ramp-gamma", "ramp gamma", -1, -1, true, 60, Motion::Exact},
}};
#undef GUARDIAN_BENCH_MOOD

constexpr std::uint16_t kLabelDim = guardian::rgb565(170, 170, 170);

std::uint16_t encoded(const Canvas& c, std::uint16_t v) {
    return c.big_endian() ? static_cast<std::uint16_t>((v << 8) | (v >> 8)) : v;
}
// The frame's pixels, exactly, into the canvas (anything outside the frame is black).
void copy_frame(Canvas& c, const std::uint8_t* frame) {
    if (c.width() != frame_w || c.height() != frame_h) c.clear(guardian::color::black);
    const int w = std::min(c.width(), frame_w), h = std::min(c.height(), frame_h);
    std::uint16_t* px = c.pixels();
    const auto stride = static_cast<std::size_t>(c.width());
    for (int y = 0; y < h; ++y) {
        const std::uint8_t* row = frame + static_cast<std::size_t>(y) * frame_w * 2;
        std::uint16_t* out = px + static_cast<std::size_t>(y) * stride;
        for (int x = 0; x < w; ++x)
            out[x] = encoded(c, static_cast<std::uint16_t>(row[2 * x] | (row[2 * x + 1] << 8)));
    }
}
void draw_label(Canvas& c, const Bench& b) {
    const Entry& e = b.current();
    c.fill_rect(0, label_top, c.width(), c.height() - label_top, guardian::color::black);
    c.text(2, label_top + 2, e.label, guardian::color::white, 2);
    if (e.mood >= 0 && e.mood < moods) c.text(2, label_top + 18, mood_labels[static_cast<std::size_t>(e.mood)], kLabelDim, 2);
    char line[24];
    std::snprintf(line, sizeof line, "bl %u%%  %u/%u", unsigned(b.backlight_pct()), unsigned(b.index() + 1), unsigned(entry_count));
    c.text(2, label_top + 35, line, kLabelDim, 1);
}
} // namespace

const std::array<GammaCommand, 2> m5gfx_gamma{{
    {0xE0, {0xd0, 0x00, 0x02, 0x07, 0x0a, 0x28, 0x32, 0x44, 0x42, 0x06, 0x0e, 0x12, 0x14, 0x17}},   // PVGAMCTRL
    {0xE1, {0xd0, 0x00, 0x02, 0x07, 0x0a, 0x28, 0x31, 0x54, 0x47, 0x0e, 0x1c, 0x17, 0x1b, 0x1e}},   // NVGAMCTRL
}};

bool Frames::complete() const {
    for (const auto& pipeline : art)
        for (const std::uint8_t* frame : pipeline)
            if (!frame) return false;
    return ramp != nullptr;
}
const Entry& entry(std::size_t index) { return kEntries[index % entry_count]; }
const std::uint8_t* frame_of(const Entry& e, const Frames& f) {
    if (e.pipeline < 0) return f.ramp;
    if (e.pipeline >= pipelines || e.mood < 0 || e.mood >= moods) return nullptr;
    return f.art[static_cast<std::size_t>(e.pipeline)][static_cast<std::size_t>(e.mood)];
}
const char* motion_text(Motion m) {
    switch (m) {
    case Motion::Exact: return "exact";
    case Motion::Still: return "still";
    case Motion::Breath: return "breath";
    }
    return "exact";
}

bool Bench::pressed(KeyState& k, bool level, std::uint32_t now_ms) {
    if (!level) {
        if (k.down) { k.down = false; k.up_since = now_ms; }
        return false;
    }
    if (k.down) return false;                  // held (or down since boot)
    k.down = true;
    return now_ms - k.up_since >= debounce_ms;
}
void Bench::enter(std::size_t index, std::uint32_t now_ms) {
    index_ = index % entry_count;
    backlight_ = current().backlight_pct;
    changed_at_ = now_ms;
}
Bench::Change Bench::keys(bool front, bool side, std::uint32_t now_ms) {
    Change change;
    if (pressed(front_, front, now_ms)) { next(now_ms); change.entry = true; }
    if (pressed(side_, side, now_ms)) {
        std::size_t at = 0;
        for (std::size_t i = 0; i < backlight_steps.size(); ++i)
            if (backlight_steps[i] == backlight_) at = i;
        backlight_ = backlight_steps[(at + 1) % backlight_steps.size()];
        changed_at_ = now_ms;
        change.backlight = true;
    }
    return change;
}
void Bench::next(std::uint32_t now_ms) { enter(index_ + 1, now_ms); }
void Bench::prev(std::uint32_t now_ms) { enter(index_ + entry_count - 1, now_ms); }
bool Bench::go(const char* name, std::uint32_t now_ms) {
    if (!name || !*name) return false;
    for (std::size_t i = 0; i < entry_count; ++i)
        if (!std::strcmp(kEntries[i].name, name)) { enter(i, now_ms); return true; }
    return false;
}
bool Bench::set_backlight(int percent, std::uint32_t now_ms) {
    for (const std::uint8_t step : backlight_steps)
        if (percent == step) { backlight_ = step; changed_at_ = now_ms; return true; }
    return false;
}
bool Bench::label_visible(std::uint32_t now_ms) const { return now_ms - changed_at_ < label_ms; }
std::size_t Bench::status(char* out, std::size_t cap, bool frames_ok) const {
    if (!out || !cap) return 0;
    const Entry& e = current();
    const int n = std::snprintf(out, cap, " bench=%s bench_index=%u/%u bench_bl=%u bench_gamma=%d bench_motion=%s bench_frames=%s",
                                e.name, unsigned(index_ + 1), unsigned(entry_count), unsigned(backlight_), e.gamma ? 1 : 0,
                                motion_text(e.motion), frames_ok ? "ok" : "missing");
    if (n < 0 || static_cast<std::size_t>(n) >= cap) { out[0] = 0; return 0; }
    return static_cast<std::size_t>(n);
}

void draw(Canvas& c, const Bench& b, const Frames& frames, std::uint32_t now_ms, persona::WarpCache* cache) {
    const Entry& e = b.current();
    const std::uint8_t* frame = frame_of(e, frames);
    if (!frame) {
        c.clear(guardian::color::black);
        c.text(2, 60, "bench frame", guardian::color::red, 2);
        c.text(2, 78, "missing", guardian::color::red, 2);
        c.text(2, 100, e.name, guardian::color::white, 1);
        return;
    }
    if (e.motion == Motion::Exact) copy_frame(c, frame);
    else {
        // H: the face band through the Guardian's own painter, at the Guardian's face row. No idle sway
        // (the Guardian's default), no ember or smoke: only the breathing resample differs from the still.
        c.clear(guardian::color::black);
        persona::Motion motion;
        motion.tilt_max_deg = 0.0f;
        if (e.motion == Motion::Still) motion.breath_amount = 0.0f;
        persona::Placement at;
        at.origin_y = face_row;
        persona::Layers layers;
        layers.ember = false; layers.smoke = false;
        persona::paint_portrait(c, frame + static_cast<std::size_t>(face_row) * frame_w * 2, now_ms, at, layers, motion, false, cache);
    }
    if (b.label_visible(now_ms)) draw_label(c, b);
}

} // namespace sticks3::artbench

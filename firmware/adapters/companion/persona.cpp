// G16 Very good portrait motion. Single-precision float only (the ESP32-S3 FPU
// is single precision): the per-pixel loop is integer fixed point.
#include "persona.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>

namespace guardian::companion::persona {
namespace {
constexpr float two_pi = 6.28318530717958647692f;
constexpr Millis breath_ms = 4000, tilt_ms = 7000, smoke_ms = 4000, ember_ms = 2000;
static_assert(loop_ms % breath_ms == 0 && loop_ms % tilt_ms == 0 && loop_ms % smoke_ms == 0 && loop_ms % ember_ms == 0,
              "every motion period divides the documented loop");

float phase(Millis t, Millis period) { return static_cast<float>(t % period) / static_cast<float>(period); }

struct Rgb { float r, g, b; };
Rgb unpack(std::uint16_t v) {
    return {static_cast<float>((v >> 11) & 31) * 255.0f / 31.0f, static_cast<float>((v >> 5) & 63) * 255.0f / 63.0f,
            static_cast<float>(v & 31) * 255.0f / 31.0f};
}
std::uint16_t pack(Rgb c) {
    const auto q = [](float v) { return static_cast<std::uint8_t>(std::min(255.0f, std::max(0.0f, v)) + 0.5f); };
    return rgb565(q(c.r), q(c.g), q(c.b));
}
// Blend `target` over the canvas pixel with weight a in [0, 1], inside `zone` (screen coordinates) only.
void blend(Canvas& c, const Rect& zone, int x, int y, Rgb target, float a) {
    if (x < zone.x0 || x >= zone.x1 || y < zone.y0 || y >= zone.y1 || x < 0 || y < 0 || x >= c.width() || y >= c.height()) return;
    const auto old = unpack(c.get(x, y));
    c.put(x, y, pack({old.r + (target.r - old.r) * a, old.g + (target.g - old.g) * a, old.b + (target.b - old.b) * a}));
}
Rect band(int origin_y) { return {0, origin_y, portrait_w, origin_y + art_h}; }
std::uint16_t art_at(const std::uint8_t* art, int x, int y) {
    if (x < 0 || y < 0 || x >= art_w || y >= art_h) return 0;   // outside the art: black
    const auto i = (static_cast<std::size_t>(y) * art_w + static_cast<std::size_t>(x)) * 2;
    return static_cast<std::uint16_t>(art[i] | (art[i + 1] << 8));
}

// Inverse-mapped bilinear blit of the portrait area under `pose`, into rows
// [origin_y, origin_y + art_h). Exact copy at identity. G16C rework: kept as the
// full-precision reference (paint_portrait_reference); the board path is warp().
void blit(Canvas& c, const std::uint8_t* art, Pose pose, int origin_y) {
    const float th = pose.tilt_deg * (two_pi / 360.0f), cs = std::cos(th), sn = std::sin(th), k = pose.scale;
    const int w = std::min(portrait_w, c.width());
    const int y0 = std::max(0, origin_y), y1 = std::min(origin_y + art_h, c.height());
    const long step_x = std::lround(cs / k * 65536.0f), step_y = std::lround(-sn / k * 65536.0f);
    for (int y = y0; y < y1; ++y) {
        const float dx = 0.0f - pose.dx - pivot.x, dy = static_cast<float>(y - origin_y) - pose.dy - pivot.y;
        long sx = std::lround((pivot.x + (dx * cs + dy * sn) / k) * 65536.0f);
        long sy = std::lround((pivot.y + (-dx * sn + dy * cs) / k) * 65536.0f);
        for (int x = 0; x < w; ++x, sx += step_x, sy += step_y) {
            const int ix = static_cast<int>(sx >> 16), iy = static_cast<int>(sy >> 16);
            const unsigned fx = static_cast<unsigned>(sx >> 8) & 255u, fy = static_cast<unsigned>(sy >> 8) & 255u;
            const auto p00 = art_at(art, ix, iy), p10 = art_at(art, ix + 1, iy);
            const auto p01 = art_at(art, ix, iy + 1), p11 = art_at(art, ix + 1, iy + 1);
            const unsigned w00 = (256 - fx) * (256 - fy), w10 = fx * (256 - fy), w01 = (256 - fx) * fy, w11 = fx * fy;
            const auto mix = [&](unsigned shift, unsigned mask) {
                return ((((p00 >> shift) & mask) * w00 + ((p10 >> shift) & mask) * w10 + ((p01 >> shift) & mask) * w01
                         + ((p11 >> shift) & mask) * w11) >> 16);
            };
            c.put(x, y, static_cast<std::uint16_t>((mix(11, 31) << 11) | (mix(5, 63) << 5) | mix(0, 31)));
        }
    }
}

// ---- G16C rework: the fast warp -------------------------------------------------
struct QPose { std::int32_t tilt, scale, dx, dy; };   // 1/32 deg, 1/1024, 1/16 px, 1/16 px
QPose quantize(const Pose& p) {
    return {static_cast<std::int32_t>(std::lround(p.tilt_deg * 32.0f)), static_cast<std::int32_t>(std::lround((p.scale - 1.0f) * 1024.0f)),
            static_cast<std::int32_t>(std::lround(p.dx * 16.0f)), static_cast<std::int32_t>(std::lround(p.dy * 16.0f))};
}
Pose dequantize(const QPose& q) {
    return {static_cast<float>(q.tilt) / 32.0f, 1.0f + static_cast<float>(q.scale) / 1024.0f, static_cast<float>(q.dx) / 16.0f,
            static_cast<float>(q.dy) / 16.0f};
}
// RGB565 spread into 0x07E0F81F so one multiply scales all three channels.
constexpr std::uint32_t spread_mask = 0x07E0F81Fu;
inline std::uint32_t spread(std::uint16_t c) { return (c | (static_cast<std::uint32_t>(c) << 16)) & spread_mask; }
inline std::uint32_t lerp32(std::uint32_t a, std::uint32_t b, std::uint32_t w) { return ((a * (32u - w) + b * w) >> 5) & spread_mask; }
inline std::uint16_t unspread(std::uint32_t s) { return static_cast<std::uint16_t>(s | (s >> 16)); }
// Pixel sources: NativeArt (the fast-RAM copy) or ByteArt (the little-endian art bytes), persona.hpp.
template <class Src>
void warp(Canvas& c, Src src, const Pose& pose, int origin_y) {
    const float th = pose.tilt_deg * (two_pi / 360.0f), cs = std::cos(th), sn = std::sin(th), k = pose.scale;
    const int w = std::min(portrait_w, c.width());
    const int y0 = std::max(0, origin_y), y1 = std::min(origin_y + art_h, c.height());
    const long step_x = std::lround(cs / k * 65536.0f), step_y = std::lround(-sn / k * 65536.0f);
    const bool swap = c.big_endian();
    for (int y = y0; y < y1; ++y) {
        const float dx = 0.0f - pose.dx - pivot.x, dy = static_cast<float>(y - origin_y) - pose.dy - pivot.y;
        long sx = std::lround((pivot.x + (dx * cs + dy * sn) / k) * 65536.0f);
        long sy = std::lround((pivot.y + (-dx * sn + dy * cs) / k) * 65536.0f);
        std::uint16_t* row = c.pixels() + static_cast<std::size_t>(y) * static_cast<std::size_t>(c.width());
        for (int x = 0; x < w; ++x, sx += step_x, sy += step_y) {
            const int ix = static_cast<int>(sx >> 16), iy = static_cast<int>(sy >> 16);
            const auto fx = static_cast<std::uint32_t>(sx >> 11) & 31u, fy = static_cast<std::uint32_t>(sy >> 11) & 31u;
            std::uint32_t s00, s10, s01, s11;
            if (static_cast<unsigned>(ix) < static_cast<unsigned>(art_w - 1) && static_cast<unsigned>(iy) < static_cast<unsigned>(art_h - 1)) {
                s00 = spread(src.at(ix, iy)); s10 = spread(src.at(ix + 1, iy));
                s01 = spread(src.at(ix, iy + 1)); s11 = spread(src.at(ix + 1, iy + 1));
            } else {   // the border: samples outside the art are black
                const auto get = [&](int xx, int yy) -> std::uint32_t {
                    return xx < 0 || yy < 0 || xx >= art_w || yy >= art_h ? 0u : spread(src.at(xx, yy));
                };
                s00 = get(ix, iy); s10 = get(ix + 1, iy); s01 = get(ix, iy + 1); s11 = get(ix + 1, iy + 1);
            }
            const std::uint16_t v = unspread(lerp32(lerp32(s00, s10, fx), lerp32(s01, s11, fx), fy));
            row[x] = swap ? static_cast<std::uint16_t>((v << 8) | (v >> 8)) : v;
        }
    }
}

// A warm, restrained glow on the lit end of the cigar; it breathes with the ember period.
void ember(Canvas& c, Point tip, Millis t, float peak, const Rect& zone) {
    constexpr float radius = 8.0f;
    const float pulse = 0.675f + 0.325f * std::sin(two_pi * phase(t, ember_ms));
    for (int y = static_cast<int>(tip.y - radius) - 1; y <= static_cast<int>(tip.y + radius) + 1; ++y)
        for (int x = static_cast<int>(tip.x - radius) - 1; x <= static_cast<int>(tip.x + radius) + 1; ++x) {
            const float ex = static_cast<float>(x) - tip.x, ey = static_cast<float>(y) - tip.y;
            if (ex * ex + ey * ey >= radius * radius) continue;
            const float d = std::sqrt(ex * ex + ey * ey);
            const float f = 1.0f - d / radius;
            blend(c, zone, x, y, {255.0f, 150.0f, 40.0f}, peak * pulse * f * f);
        }
}

// Fourteen overlapping soft puffs rise along one slow S-curve and fade at both ends: a small curl, no seam.
void smoke(Canvas& c, Point tip, Millis t, float opacity, const Rect& zone) {
    constexpr int puffs = 14;
    const float base = phase(t, smoke_ms);
    for (int i = 0; i < puffs; ++i) {
        float s = base + static_cast<float>(i) / static_cast<float>(puffs);
        s -= std::floor(s);
        // The S-curve is fixed; a slow travelling sway (period = smoke_ms) makes the curl visibly drift.
        const float cx = tip.x - 2.0f - 9.0f * s + 5.0f * s * std::sin(two_pi * 1.3f * s)
            + 2.5f * s * std::sin(two_pi * (base - 0.9f * s));
        const float cy = tip.y - 4.0f - 30.0f * s;
        const float r = 1.6f + 3.4f * s, alpha = opacity * std::sin(3.14159265f * s);
        for (int y = static_cast<int>(cy - r) - 1; y <= static_cast<int>(cy + r) + 1; ++y)
            for (int x = static_cast<int>(cx - r) - 1; x <= static_cast<int>(cx + r) + 1; ++x) {
                const float ex = static_cast<float>(x) - cx, ey = static_cast<float>(y) - cy;
                if (ex * ex + ey * ey >= (r + 0.5f) * (r + 0.5f)) continue;
                const float d = std::sqrt(ex * ex + ey * ey);
                blend(c, zone, x, y, {205.0f, 205.0f, 215.0f}, alpha * (1.0f - d / (r + 0.5f)));
            }
    }
}
} // namespace

Pose pose_at(Millis t, const Motion& m) {
    return {m.tilt_max_deg * std::sin(two_pi * phase(t, tilt_ms)), 1.0f + m.breath_amount * std::sin(two_pi * phase(t, breath_ms)), 0.0f, 0.0f};
}

Pose pose_with(Millis t, const Motion& m, const Placement& at) {
    auto p = pose_at(t, m);
    p.tilt_deg += at.tilt_deg; p.dx = at.dx; p.dy = at.dy; p.scale *= at.scale;
    return p;
}

Point map_point(Pose pose, Point p) {
    const float th = pose.tilt_deg * (two_pi / 360.0f), cs = std::cos(th), sn = std::sin(th);
    const float dx = p.x - pivot.x, dy = p.y - pivot.y;
    return {pivot.x + pose.scale * (dx * cs - dy * sn) + pose.dx, pivot.y + pose.scale * (dx * sn + dy * cs) + pose.dy};
}

// G16I: every corner of the hood box, turned about the pivot, must stay inside the band; the scale is
// the smallest ratio of room to reach over the four corners and the four band edges.
float fit_scale(float tilt_deg) {
    const float th = tilt_deg * (two_pi / 360.0f), cs = std::cos(th), sn = std::sin(th);
    const float room_l = pivot.x, room_r = static_cast<float>(art_w) - pivot.x, room_t = pivot.y, room_b = static_cast<float>(art_h) - pivot.y;
    float s = 1.0f;
    for (int i = 0; i < 4; ++i) {
        const float cx = static_cast<float>(i & 1 ? hood_box.x1 : hood_box.x0) - pivot.x;
        const float cy = static_cast<float>(i & 2 ? hood_box.y1 : hood_box.y0) - pivot.y;
        const float x = cx * cs - cy * sn, y = cx * sn + cy * cs;
        if (x > room_r) s = std::min(s, room_r / x);
        if (-x > room_l) s = std::min(s, room_l / -x);
        if (y > room_b) s = std::min(s, room_b / y);
        if (-y > room_t) s = std::min(s, room_t / -y);
    }
    return s;
}

void paint_portrait(Canvas& c, const std::uint8_t* art, Millis t, const Placement& at, Layers layers, const Motion& m, bool cigar) {
    paint_portrait(c, art, t, at, layers, m, cigar, nullptr);
}

void paint_portrait_reference(Canvas& c, const std::uint8_t* art, Millis t, const Placement& at, const Motion& m) {
    if (art) blit(c, art, pose_with(t, m, at), at.origin_y);
}

void paint_portrait(Canvas& c, const std::uint8_t* art, Millis t, const Placement& at, Layers layers, const Motion& m, bool cigar,
                    WarpCache* cache) {
    const auto pose = pose_with(t, m, at);
    auto tip = map_point(pose, cigar_tip); tip.y += static_cast<float>(at.origin_y);
    const Rect zone = band(at.origin_y);
    if (layers.portrait && art) {
        const auto q = quantize(pose);
        const Pose warped = dequantize(q);
        if (!cache) warp(c, ByteArt{art}, warped, at.origin_y);
        else {
            if (cache->art_ != art) {   // the portrait changed: decode it once into fast RAM
                for (std::size_t i = 0; i < art_pixels; ++i) cache->source_[i] = static_cast<std::uint16_t>(art[2 * i] | (art[2 * i + 1] << 8));
                cache->art_ = art; cache->valid_ = false; ++cache->copies;
            }
            const std::array<std::int32_t, 7> key{q.tilt, q.scale, q.dx, q.dy, at.origin_y, c.width(), c.big_endian() ? 1 : 0};
            const int w = std::min(portrait_w, c.width());
            const int y0 = std::max(0, at.origin_y), y1 = std::min(at.origin_y + art_h, c.height());
            std::uint16_t* px = c.pixels();
            const auto stride = static_cast<std::size_t>(c.width());
            if (cache->valid_ && cache->key_ == key) {
                for (int y = y0; y < y1; ++y)
                    std::memcpy(px + static_cast<std::size_t>(y) * stride, cache->band_ + static_cast<std::size_t>(y - at.origin_y) * portrait_w,
                                static_cast<std::size_t>(w) * 2);
                ++cache->reuses;
            } else {
                warp(c, NativeArt{cache->source_}, warped, at.origin_y);
                for (int y = y0; y < y1; ++y)
                    std::memcpy(cache->band_ + static_cast<std::size_t>(y - at.origin_y) * portrait_w, px + static_cast<std::size_t>(y) * stride,
                                static_cast<std::size_t>(w) * 2);
                cache->key_ = key; cache->valid_ = true; ++cache->warps;
            }
        }
    }
    if (!cigar) return;
    if (layers.ember && m.ember_peak > 0.0f) ember(c, tip, t, m.ember_peak, zone);
    if (layers.smoke && m.smoke_alpha > 0.0f) {
        // The smoke box moves with the face (it stays left of the eyes, above the ember).
        const int ox = static_cast<int>(std::lround(at.dx)), oy = at.origin_y + static_cast<int>(std::lround(at.dy));
        const Rect sz{std::max(zone.x0, smoke_zone.x0 + ox), std::max(zone.y0, smoke_zone.y0 + oy),
                      std::min(zone.x1, smoke_zone.x1 + ox), std::min(zone.y1, smoke_zone.y1 + oy)};
        smoke(c, tip, t, m.smoke_alpha, sz);
    }
}

void paint_very_good(Canvas& c, const std::uint8_t* art, Millis t, Layers layers, const Motion& m) {
    paint_portrait(c, art, t, Placement{}, layers, m, true);
}

bool ArtSet::complete() const {
    if (!no_data) return false;
    for (std::size_t i = 0; i < rated.size(); ++i) if (!rated[i] || !alert[i][0] || !alert[i][1]) return false;
    return true;
}

int rated_index(Mood m) {
    switch (m) {
    case Mood::VeryGood: return 0; case Mood::Good: return 1; case Mood::Medium: return 2;
    case Mood::Bad: return 3; case Mood::Horrible: return 4; case Mood::Unknown: return -1;
    }
    return -1;
}

} // namespace guardian::companion::persona

#pragma once
// G16C: frame-time, fps and IMU-to-glass latency accounting for the StickS3
// companion loop. SDK-free so the host can check it (tests/frame_stats_check.cpp);
// the board feeds esp_timer microseconds. Per screen kind since boot (FRAMES
// console command) and over the most recent frames (STATUS fields).
//   render  = compose + draw into the framebuffer (+ battery icon)
//   push    = the panel transfer (Board::present, waits for completion)
//   fps     = frames / time between consecutive presents of the same kind
//   imu_glass = present end - time of the newest IMU sample the frame used
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include "companion.hpp"

namespace sticks3 {

enum class FrameKind : std::uint8_t { Rated, Alert, NoData, Demo, Other, Burst, Count };   // G16I: Burst = the particle frames
inline const char* frame_kind_text(FrameKind k) {
    switch (k) {
    case FrameKind::Rated: return "rated"; case FrameKind::Alert: return "alert"; case FrameKind::NoData: return "nodata";
    case FrameKind::Demo: return "demo"; case FrameKind::Other: return "other"; case FrameKind::Burst: return "burst";
    case FrameKind::Count: break;
    }
    return "?";
}
inline FrameKind frame_category(const guardian::companion::Frame& f) {
    using guardian::companion::FaceArt;
    if (!f.face_shown) return FrameKind::Other;
    if (f.demo_badge) return FrameKind::Demo;
    switch (f.art) {
    case FaceArt::Rated: return FrameKind::Rated; case FaceArt::Alert: return FrameKind::Alert;
    case FaceArt::NoData: return FrameKind::NoData; case FaceArt::None: break;
    }
    return FrameKind::Other;
}

// G16I: `burst` = this frame painted the particles instead of the portrait (their cost is its own row).
inline FrameKind frame_category(const guardian::companion::Frame& f, bool burst) {
    return burst && f.face_shown ? FrameKind::Burst : frame_category(f);
}

class FrameStats {
public:
    static constexpr std::size_t recent = 32;
    static constexpr std::int64_t max_gap_us = 1000000;   // a longer gap is a pause, not a frame interval
    // since_prev_us: since the previous present (0 = first); imu_us: < 0 when no IMU sample was used.
    void add(FrameKind k, std::int64_t render_us, std::int64_t push_us, std::int64_t since_prev_us, std::int64_t imu_us) {
        if (k >= FrameKind::Count) return;
        auto& s = kinds_[static_cast<std::size_t>(k)];
        const auto total = clamp(render_us) + clamp(push_us);
        ++s.frames; s.render_us += clamp(render_us); s.push_us += clamp(push_us);
        if (total > s.max_total_us) s.max_total_us = total;
        const bool interval = since_prev_us > 0 && since_prev_us < max_gap_us && have_last_ && last_ == k;
        if (interval) { s.span_us += clamp(since_prev_us); ++s.spans; }
        if (imu_us >= 0) { s.imu_us += clamp(imu_us); ++s.imu_n; if (clamp(imu_us) > s.imu_max_us) s.imu_max_us = clamp(imu_us); }
        auto& r = ring_[head_ % recent]; ++head_;
        r = {total, clamp(render_us), clamp(push_us), interval ? clamp(since_prev_us) : 0, imu_us >= 0 ? clamp(imu_us) : 0, imu_us >= 0};
        last_ = k; have_last_ = true;
    }
    void reset() { *this = FrameStats{}; }
    std::uint32_t frames(FrameKind k) const { return kinds_[static_cast<std::size_t>(k)].frames; }
    // fps x10 of kind k since boot/reset (0 when unknown).
    std::uint32_t fps10(FrameKind k) const {
        const auto& s = kinds_[static_cast<std::size_t>(k)];
        return s.span_us ? static_cast<std::uint32_t>(std::uint64_t(s.spans) * 10000000u / s.span_us) : 0;
    }
    // " frame_ms=a/m render_ms=a push_ms=a fps=f imu_glass_ms=a/m" over the recent frames.
    void status_text(char* out, std::size_t n) const {
        const std::size_t count = head_ < recent ? head_ : recent;
        std::uint64_t total = 0, render = 0, push = 0, span = 0, imu = 0; std::uint32_t max = 0, spans = 0, imu_n = 0, imu_max = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const auto& r = ring_[i];
            total += r.total; render += r.render; push += r.push; if (r.total > max) max = r.total;
            if (r.since) { span += r.since; ++spans; }
            if (r.has_imu) { imu += r.imu; ++imu_n; if (r.imu > imu_max) imu_max = r.imu; }
        }
        const auto ms = [](std::uint64_t us, std::size_t d, char* b, std::size_t bn) {
            const auto v = d ? us / d : 0; std::snprintf(b, bn, "%u.%u", unsigned(v / 1000), unsigned((v / 100) % 10)); };
        char a[16], m[16], r[16], p[16], ia[16], im[16];
        ms(total, count, a, sizeof a); ms(max, 1, m, sizeof m); ms(render, count, r, sizeof r); ms(push, count, p, sizeof p);
        ms(imu, imu_n, ia, sizeof ia); ms(imu_max, 1, im, sizeof im);
        const unsigned fps10 = span ? unsigned(std::uint64_t(spans) * 10000000u / span) : 0;
        std::snprintf(out, n, "frame_ms=%s/%s render_ms=%s push_ms=%s fps=%u.%u imu_glass_ms=%s/%s frames=%u",
                      a, m, r, p, fps10 / 10, fps10 % 10, imu_n ? ia : "none", imu_n ? im : "none", unsigned(head_));
    }
    // One "G16C FRAMES ..." line per kind that has frames, then "G16C FRAMES END".
    void table(char* out, std::size_t n) const {
        std::size_t used = 0;
        const auto append = [&](const char* line) {
            for (; *line && used + 1 < n; ++line) out[used++] = *line;
            if (n) out[used] = 0;
        };
        if (n) out[0] = 0;
        for (std::size_t i = 0; i < kinds_.size(); ++i) {
            const auto& s = kinds_[i]; if (!s.frames) continue;
            const auto f10 = fps10(static_cast<FrameKind>(i));
            char line[200];
            std::snprintf(line, sizeof line,
                "G16C FRAMES kind=%s frames=%u render_ms=%u.%u push_ms=%u.%u total_max_ms=%u.%u fps=%u.%u imu_glass_ms=%u.%u/%u.%u\n",
                frame_kind_text(static_cast<FrameKind>(i)), unsigned(s.frames),
                unsigned(s.render_us / s.frames / 1000), unsigned(s.render_us / s.frames / 100 % 10),
                unsigned(s.push_us / s.frames / 1000), unsigned(s.push_us / s.frames / 100 % 10),
                unsigned(s.max_total_us / 1000), unsigned(s.max_total_us / 100 % 10), unsigned(f10 / 10), unsigned(f10 % 10),
                unsigned(s.imu_n ? s.imu_us / s.imu_n / 1000 : 0), unsigned(s.imu_n ? s.imu_us / s.imu_n / 100 % 10 : 0),
                unsigned(s.imu_max_us / 1000), unsigned(s.imu_max_us / 100 % 10));
            append(line);
        }
        append("G16C FRAMES END\n");
    }
private:
    static std::uint32_t clamp(std::int64_t v) { return v < 0 ? 0u : v > 0x7fffffff ? 0x7fffffffu : static_cast<std::uint32_t>(v); }
    struct Kind { std::uint32_t frames{}, max_total_us{}, spans{}, imu_n{}, imu_max_us{}; std::uint64_t render_us{}, push_us{}, span_us{}, imu_us{}; };
    struct Recent { std::uint32_t total{}, render{}, push{}, since{}, imu{}; bool has_imu{}; };
    std::array<Kind, static_cast<std::size_t>(FrameKind::Count)> kinds_{};
    std::array<Recent, recent> ring_{};
    std::size_t head_{};
    FrameKind last_{FrameKind::Other};
    bool have_last_{};
};

} // namespace sticks3

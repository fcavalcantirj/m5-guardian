#pragma once
// G16C rework: push only the framebuffer rows that changed since the last push.
// SDK-free so the host can check it (tests/dirty_rows_check.cpp).
//
// Each row is reduced to a 32-bit hash (FNV-1a over pixel pairs) and
// compared with the hash of the same row at the previous push. Changed rows
// are grouped into runs; runs closer than merge_gap rows merge (one panel
// transaction is cheaper than two small ones), and more than max_runs runs
// collapse into one span. The first push, a forced push and a frame taller
// than max_height send the whole frame. A hash collision could leave one stale
// row on the glass; the caller forces a full push periodically (StickS3: every
// second) so such a row heals within that period.
#include <array>
#include <cstddef>
#include <cstdint>

namespace sticks3 {

class DirtyRows {
public:
    static constexpr int max_height = 320;
    static constexpr std::size_t max_runs = 4;
    static constexpr int merge_gap = 8;
    struct Run { int y0{}; int rows{}; };
    struct Plan {
        std::array<Run, max_runs> runs{};
        std::size_t count{};
        bool full{};
    };
    // Forget the panel contents (after anything else drew on the glass).
    void invalidate() { valid_ = false; }
    // Plans the push of `px` (w x h, row-major) and records it as pushed.
    Plan plan(const std::uint16_t* px, int w, int h, bool force_full) {
        Plan p;
        if (h > max_height || w <= 0 || h <= 0) { p.full = true; p.count = 1; p.runs[0] = {0, h > 0 ? h : 0}; valid_ = false; return p; }
        const bool full = force_full || !valid_ || h != height_;
        std::array<Run, max_runs + 1> found{};
        std::size_t n = 0;
        bool overflow = false;
        int first = -1, last = -1;
        for (int y = 0; y < h; ++y) {
            const std::uint32_t hash = row_hash(px + static_cast<std::size_t>(y) * static_cast<std::size_t>(w), w);
            const bool changed = full || hash != hash_[static_cast<std::size_t>(y)];
            hash_[static_cast<std::size_t>(y)] = hash;
            if (!changed) continue;
            if (first < 0) first = y;
            last = y;
            if (n && y - (found[n - 1].y0 + found[n - 1].rows) < merge_gap) { found[n - 1].rows = y - found[n - 1].y0 + 1; continue; }
            if (n < found.size()) found[n++] = {y, 1}; else overflow = true;
        }
        valid_ = true; height_ = h;
        if (full) { p.full = true; p.count = 1; p.runs[0] = {0, h}; return p; }
        if (first < 0) return p;
        if (overflow || n > max_runs) { p.count = 1; p.runs[0] = {first, last - first + 1}; return p; }
        for (std::size_t i = 0; i < n; ++i) p.runs[i] = found[i];
        p.count = n;
        return p;
    }
private:
    static std::uint32_t row_hash(const std::uint16_t* row, int w) {
        // Two pixels per step (half the dependent multiplies); an odd last pixel alone.
        std::uint32_t h = 2166136261u;
        int x = 0;
        for (; x + 1 < w; x += 2) { h ^= static_cast<std::uint32_t>(row[x]) | (static_cast<std::uint32_t>(row[x + 1]) << 16); h *= 16777619u; }
        if (x < w) { h ^= row[x]; h *= 16777619u; }
        return h;
    }
    std::array<std::uint32_t, max_height> hash_{};
    int height_{};
    bool valid_{};
};

} // namespace sticks3

// G16I snow-globe burst, G16O gravity pile: see burst.hpp. Integer per-particle work (1/64 px,
// 1/64 px/s); float only once per frame and once per particle when a burst starts or is kicked.
#include "burst.hpp"
#include <algorithm>
#include <cmath>

namespace guardian::companion::burst {
namespace {
constexpr std::int32_t unit = 64;
constexpr std::int32_t cell = block * unit;                              // one pile cell, 3 px
constexpr std::int32_t pivot_x = 67 * unit, pivot_y = 80 * unit;        // persona::pivot
constexpr std::int32_t max_x = (persona::art_w - block) * unit;
constexpr std::int32_t pile_y0 = (persona::art_h - pile_h * block) * unit;   // the cells stand on the band's bottom edge (1 px free above)
constexpr float gravity_px_s2 = 250.0f;
constexpr float drag_per_s = 1.0205f;                                    // 0.96 per 40 ms frame
constexpr float speed_lo = 120.0f, speed_hi = 300.0f;                    // explode, px/s
constexpr float shove_px_s_per_g = 60.0f, shove_max_px_s = 240.0f;
constexpr std::int32_t max_step_ms = 100;                                // a stalled frame integrates at most this much
// G16O:
constexpr std::uint16_t home_mask = 0x0fff, lying = 0x8000;             // Particle::home
constexpr std::int32_t release_speed = 30 * unit;                        // a lying block that falls again starts this fast
constexpr std::int32_t touch = unit / 8;                                 // "against" the floor or a lying block: within 1/8 px
constexpr float flat_in_plane = 0.2f;                                    // less gravity across the glass: no down, nothing settles or slides
constexpr float diagonal_part = 0.3827f;                                 // sin 22.5 degrees: beyond it an axis takes part in "down"
constexpr std::int32_t slide_step_ms = 20, max_slides = 5;               // a lying block moves at most one cell per pass (150 px/s)
static_assert(grid_w * block == persona::art_w, "the grid covers every column");
static_assert(persona::pivot.x == 67.0f && persona::pivot.y == 80.0f, "pivot_x/pivot_y are persona::pivot");
static_assert(grid_w * grid_h <= home_mask, "a home fits 12 bits");
static_assert(pile_w <= 64 && pile_y0 >= 0 && pile_y0 < cell, "a pile row is one 64-bit word; the cells reach the bottom edge");

int cell_of(const Particle& p) { return p.home & home_mask; }
int rows_of(int home) { return home / grid_w == grid_h - 1 ? persona::art_h - (grid_h - 1) * block : block; }
std::int32_t max_y(int home) { return (persona::art_h - rows_of(home)) * unit; }
std::uint32_t next(std::uint32_t& s) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
float unit_random(std::uint32_t& s) { return static_cast<float>(next(s) & 0xffffu) / 65535.0f; }   // 0..1
std::int32_t clampi(std::int32_t v, std::int32_t lo, std::int32_t hi) { return v < lo ? lo : v > hi ? hi : v; }
std::int32_t absi(std::int32_t v) { return v < 0 ? -v : v; }
std::int16_t sat16(std::int32_t v) { return static_cast<std::int16_t>(clampi(v, -32767, 32767)); }
float finite_or(float v, float fallback) { return std::isfinite(v) ? v : fallback; }
float ranged(float v, Range r, float fallback) { return std::isfinite(v) ? std::max(r.lo, std::min(r.hi, v)) : fallback; }
bool lit(const persona::PixelSource& src, int gx, int gy) {
    for (int y = gy * block; y < gy * block + block && y < persona::art_h; ++y)
        for (int x = gx * block; x < gx * block + block; ++x) if (src.at(x, y)) return true;
    return false;
}
// The pile cell under the middle of a block whose top-left corner is x, y (h = its height, 1/64 px).
int col_mid(std::int32_t x) { return clampi((x + cell / 2) / cell, 0, pile_w - 1); }
int row_mid(std::int32_t y, std::int32_t h) { return clampi((y + h / 2 - pile_y0) / cell, 0, pile_h - 1); }   // (y + h / 2 - pile_y0 > -cell: the quotient is 0 above the cells)
}

void Burst::configure(float total_s) { params_.total_s = ranged(total_s, total_s_range, default_total_s); }

void Burst::configure(const Params& p) {
    const Params d;
    configure(p.total_s);
    params_.still_dps = ranged(p.still_dps, still_dps_range, d.still_dps);
    params_.still_g = ranged(p.still_g, still_g_range, d.still_g);
    params_.calm_s = ranged(p.calm_s, calm_s_range, d.calm_s);
    params_.max_s = ranged(p.max_s, max_s_range, d.max_s);
}

void Burst::set_pose(const persona::Pose& pose) {
    const float k = std::isfinite(pose.scale) && pose.scale > 0.05f ? std::min(pose.scale, 2.0f) : 1.0f;
    const float th = finite_or(pose.tilt_deg, 0.0f) * 0.01745329252f;
    // The nearest quarter turn: each block shows its own pixels turned that far (paint()).
    quarter_ = static_cast<std::uint8_t>(((std::lround(finite_or(pose.tilt_deg, 0.0f) / 90.0f) % 4) + 4) % 4);
    cos_q14_ = static_cast<std::int32_t>(std::lround(k * std::cos(th) * 16384.0f));
    sin_q14_ = static_cast<std::int32_t>(std::lround(k * std::sin(th) * 16384.0f));
    const float limit = static_cast<float>(persona::art_h);
    tx_ = pivot_x + static_cast<std::int32_t>(std::lround(std::max(-limit, std::min(limit, finite_or(pose.dx, 0.0f))) * static_cast<float>(unit)));
    ty_ = pivot_y + static_cast<std::int32_t>(std::lround(std::max(-limit, std::min(limit, finite_or(pose.dy, 0.0f))) * static_cast<float>(unit)));
}

// The block's middle pixel, turned and scaled about the pivot like the portrait, back to its top-left
// corner. Pixel-index coordinates, as the warp and persona::pivot use them, so a quarter or half turn
// lands every block on the turned pixel grid. At the identity pose this is exactly the home (integer
// arithmetic, no rounding loss).
Burst::Px Burst::target(const Particle& p) const {
    const int home = cell_of(p), rows = rows_of(home);
    const std::int32_t half_w = (block - 1) * unit / 2, half_h = (rows - 1) * unit / 2;
    const std::int32_t cx = (home % grid_w) * block * unit + half_w - pivot_x;
    const std::int32_t cy = (home / grid_w) * block * unit + half_h - pivot_y;
    const std::int32_t x = tx_ + ((cx * cos_q14_ - cy * sin_q14_ + 8192) >> 14) - half_w;
    const std::int32_t y = ty_ + ((cx * sin_q14_ + cy * cos_q14_ + 8192) >> 14) - half_h;
    return {clampi(x, 0, max_x), clampi(y, 0, max_y(home))};
}

Burst::Px Burst::now_at(const Particle& p) const {
    if (phase_ != Phase::Reform) return {p.x, p.y};
    const Px t = target(p);   // x, y hold where the block had drifted to
    return {p.x + (((t.x - p.x) * reform_q16_) >> 16), p.y + (((t.y - p.y) * reform_q16_) >> 16)};
}

// Every particle gets a velocity away from the middle of the face (direction jittered, speed
// speed_lo..speed_hi) plus the shove: loose snow lags behind the stick, so against its acceleration.
// G16O: a block that lay in the pile is thrown away from the floor it lay on (the part of its
// velocity that points down is turned round), so a shaken pile flies up into the band.
void Burst::scatter(float lin_x, float lin_y, std::uint32_t seed) {
    std::uint32_t s = seed ? seed : 0x9E3779B9u;
    float sx = -shove_px_s_per_g * finite_or(lin_x, 0.0f), sy = -shove_px_s_per_g * finite_or(lin_y, 0.0f);
    const float shove = std::sqrt(sx * sx + sy * sy);
    if (shove > shove_max_px_s) { sx *= shove_max_px_s / shove; sy *= shove_max_px_s / shove; }
    const float down_n = std::sqrt(static_cast<float>(down_x_ * down_x_ + down_y_ * down_y_));
    const float down_x = down_n > 0 ? static_cast<float>(down_x_) / down_n : 0.0f, down_y = down_n > 0 ? static_cast<float>(down_y_) / down_n : 0.0f;
    for (std::size_t i = 0; i < count_; ++i) {
        auto& p = p_[i];
        float dx = static_cast<float>(p.x + block * unit / 2 - tx_), dy = static_cast<float>(p.y + rows_of(cell_of(p)) * unit / 2 - ty_);
        float len = std::sqrt(dx * dx + dy * dy);
        if (len < 0.5f * static_cast<float>(unit)) { dx = unit_random(s) - 0.5f; dy = unit_random(s) - 0.5f; len = std::sqrt(dx * dx + dy * dy); }
        if (len < 1e-3f) { dx = 1.0f; dy = 0.0f; len = 1.0f; }
        dx /= len; dy /= len;
        const float j = (unit_random(s) - 0.5f) * 0.7f;                  // direction jitter: up to about 19 degrees either way
        const float jn = std::sqrt(1.0f + j * j);
        float jx = (dx - dy * j) / jn, jy = (dy + dx * j) / jn;
        if (p.home & lying) {
            const float into = jx * down_x + jy * down_y;
            if (into > 0) { jx -= 2.0f * into * down_x; jy -= 2.0f * into * down_y; }
        }
        const float speed = speed_lo + (speed_hi - speed_lo) * unit_random(s);
        p.vx = sat16(static_cast<std::int32_t>(std::lround((jx * speed + sx) * static_cast<float>(unit))));
        p.vy = sat16(static_cast<std::int32_t>(std::lround((jy * speed + sy) * static_cast<float>(unit))));
    }
}

void Burst::wake() {
    if (resting_) for (std::size_t i = 0; i < count_; ++i) p_[i].home &= home_mask;
    pile_.fill(0); resting_ = 0; slide_ms_ = 0;
}

void Burst::lay(Particle& p, int c, int r) {
    pile_[static_cast<std::size_t>(r)] |= std::uint64_t{1} << c;
    p.x = static_cast<std::int16_t>(c * cell);
    p.y = static_cast<std::int16_t>(pile_y0 + (r + 1) * cell - rows_of(cell_of(p)) * unit);   // on the bottom of its cell
    p.vx = p.vy = 0;
    if (!(p.home & lying)) { p.home |= lying; ++resting_; }
}

void Burst::lift(Particle& p, int c, int r) {
    pile_[static_cast<std::size_t>(r)] &= ~(std::uint64_t{1} << c);
    if (p.home & lying) { p.home &= home_mask; --resting_; }
}

// The block at x, y is held by the floor or by lying blocks: it lies down in the cell under its
// middle, or, when a block that arrived in the same frame took that one, in the first free cell
// back the way it came. False (it keeps flying) when there is none.
bool Burst::try_rest(Particle& p, std::int32_t x, std::int32_t y) {
    int c = col_mid(x), r = row_mid(y, rows_of(cell_of(p)) * unit);
    for (int k = 0; k < pile_h && c >= 0 && c < pile_w && r >= 0 && r < pile_h; ++k, c -= down_x_, r -= down_y_)
        if (!taken(c, r)) { lay(p, c, r); return true; }
    return false;
}

// One pass over the lying blocks, toward the down of this frame (down_x_, down_y_; gx, gy = gravity
// across the glass). A block whose next cell toward down is free falls again; otherwise it topples
// into a free cell 45 degrees to either side of down (the side gravity leans to first). Every move
// takes a block further down, so a pile at rest under a steady down stays at rest.
void Burst::slide(float gx, float gy) {
    const int dx = down_x_, dy = down_y_;
    const bool diagonal = dx && dy;
    int ax, ay, bx, by, prefer;   // the two ways to topple; prefer: +1 = a first, -1 = b first, 0 = take turns
    if (diagonal) { ax = dx; ay = 0; bx = 0; by = dy; prefer = std::fabs(gx) >= std::fabs(gy) ? 1 : -1; }
    else if (dx) { ax = dx; ay = 1; bx = dx; by = -1; prefer = gy > 0.05f ? 1 : gy < -0.05f ? -1 : 0; }
    else { ax = 1; ay = dy; bx = -1; by = dy; prefer = gx > 0.05f ? 1 : gx < -0.05f ? -1 : 0; }
    const float gn = std::sqrt(gx * gx + gy * gy);
    const auto fall_vx = sat16(static_cast<std::int32_t>(std::lround(gx / gn * static_cast<float>(release_speed))));
    const auto fall_vy = sat16(static_cast<std::int32_t>(std::lround(gy / gn * static_cast<float>(release_speed))));
    ++passes_;
    for (std::size_t i = 0; i < count_; ++i) {
        auto& p = p_[i];
        if (!(p.home & lying)) continue;
        const int c = p.x / cell, r = (p.y + rows_of(cell_of(p)) * unit - 1 - pile_y0) / cell;
        if (free_cell(c + dx, r + dy)) {
            // Straight down is free: it falls (flies) again. Diagonally, only when it is not wedged
            // between two neighbours; wedged, it hops through the gap.
            if (!diagonal || free_cell(c + dx, r) || free_cell(c, r + dy)) { lift(p, c, r); p.vx = fall_vx; p.vy = fall_vy; }
            else { lift(p, c, r); lay(p, c + dx, r + dy); }
            continue;
        }
        const bool a_first = prefer > 0 || (prefer == 0 && ((i + passes_) & 1u));
        const int c1 = c + (a_first ? ax : bx), r1 = r + (a_first ? ay : by), c2 = c + (a_first ? bx : ax), r2 = r + (a_first ? by : ay);
        if (free_cell(c1, r1)) { lift(p, c, r); lay(p, c1, r1); }
        else if (free_cell(c2, r2)) { lift(p, c, r); lay(p, c2, r2); }
    }
}

// The stillness rule for one frame: true when the up vector turned faster than still_dps since the
// frame before, or the shove is above still_g. ux, uy: the up vector across the glass (finite).
bool Burst::stirred(Millis now, float ux, float uy, float lin_x, float lin_y) {
    float u[3] = {ux, uy, 0.0f};
    const float in2 = ux * ux + uy * uy;
    if (in2 > 1.0f) { const float n = std::sqrt(in2); u[0] /= n; u[1] /= n; } else u[2] = std::sqrt(1.0f - in2);
    bool moving = false;
    if (have_up_ && now > up_at_) {
        const float cx = u[1] * up_[2] - u[2] * up_[1], cy = u[2] * up_[0] - u[0] * up_[2], cz = u[0] * up_[1] - u[1] * up_[0];
        const float turned_deg = std::atan2(std::sqrt(cx * cx + cy * cy + cz * cz), u[0] * up_[0] + u[1] * up_[1] + u[2] * up_[2]) * 57.29577951f;
        moving = turned_deg * 1000.0f > params_.still_dps * static_cast<float>(now - up_at_);
    }
    for (int i = 0; i < 3; ++i) up_[i] = u[i];
    up_at_ = now; have_up_ = true;
    const float lx = finite_or(lin_x, 0.0f), ly = finite_or(lin_y, 0.0f);
    return moving || lx * lx + ly * ly > params_.still_g * params_.still_g;
}

bool Burst::begin(const std::uint8_t* art, persona::PixelSource src, Millis now, const persona::Pose& pose,
                  float lin_x, float lin_y, std::uint32_t seed) {
    if (!art || !src.valid()) return false;
    std::size_t n = 0;   // counted first: a refusal changes nothing, not even a burst that is running
    for (int gy = 0; gy < grid_h; ++gy) for (int gx = 0; gx < grid_w; ++gx) n += lit(src, gx, gy);
    if (!n || n > capacity) return false;
    src_ = src; art_ = art; count_ = 0; resting_ = 0;
    set_pose(pose);
    phase_ = Phase::Explode; landed_ = false; reform_q16_ = 0; t0_ = last_ = still_since_ = now;
    have_up_ = false; down_x_ = down_y_ = 0;
    for (int gy = 0; gy < grid_h; ++gy) for (int gx = 0; gx < grid_w; ++gx) {
        if (!lit(src, gx, gy)) continue;
        auto& p = p_[count_++];
        p.home = static_cast<std::uint16_t>(gy * grid_w + gx);
        const Px at = target(p);
        p.x = static_cast<std::int16_t>(at.x); p.y = static_cast<std::int16_t>(at.y);
    }
    wake();
    scatter(lin_x, lin_y, seed);
    ++started_;
    return true;
}

bool Burst::kick(Millis now, float lin_x, float lin_y, std::uint32_t seed) {
    if (!active()) return false;
    for (std::size_t i = 0; i < count_; ++i) {   // from where each block is now (mid-reform included)
        const Px at = now_at(p_[i]);
        p_[i].x = static_cast<std::int16_t>(at.x); p_[i].y = static_cast<std::int16_t>(at.y);
    }
    phase_ = Phase::Explode; landed_ = false; reform_q16_ = 0; t0_ = last_ = still_since_ = now;   // a shake is not stillness
    scatter(lin_x, lin_y, seed);   // reads which blocks lay, and on which floor
    wake(); down_x_ = down_y_ = 0;
    return true;
}

void Burst::step(Millis now, float up_x, float up_y, const persona::Pose& pose, float lin_x, float lin_y) {
    if (!active()) return;
    if (landed_) { cancel(); return; }   // the frame with every block home has been shown
    set_pose(pose);
    const float total_ms = params_.total_s * 1000.0f;
    const auto explode_ms = static_cast<Millis>(total_ms * explode_part), drift_ms = static_cast<Millis>(total_ms * drift_part);
    const auto reform_ms = static_cast<Millis>(total_ms) - explode_ms - drift_ms;
    const Millis elapsed = now > t0_ ? now - t0_ : 0;
    const std::int32_t dt_ms = now > last_ ? static_cast<std::int32_t>(std::min<Millis>(now - last_, max_step_ms)) : 0;
    last_ = now;
    const float ux = std::max(-1.5f, std::min(1.5f, finite_or(up_x, 0.0f))), uy = std::max(-1.5f, std::min(1.5f, finite_or(up_y, 0.0f)));
    if (phase_ != Phase::Reform) {
        // G16O: the reform waits for a still stick. It starts calm_s after the last moving frame, not
        // before the shortest show (explode + drift) and not after max_s, both counted from the last shake.
        if (stirred(now, ux, uy, lin_x, lin_y)) still_since_ = now;
        const Millis shortest = explode_ms + drift_ms, longest = std::max(shortest, static_cast<Millis>(params_.max_s * 1000.0f));
        const Millis calm_at = (still_since_ > t0_ ? still_since_ - t0_ : 0) + static_cast<Millis>(params_.calm_s * 1000.0f);
        const Millis start = std::min(longest, std::max(shortest, calm_at));
        if (elapsed >= start) { phase_ = Phase::Reform; reform_at_ = t0_ + start; wake(); down_x_ = down_y_ = 0; }
    }
    if (phase_ == Phase::Reform) {   // x, y stay where the block lay or flew; now_at() eases it home
        const Millis into = now > reform_at_ ? now - reform_at_ : 0;
        float u = reform_ms ? static_cast<float>(into) / static_cast<float>(reform_ms) : 1.0f;
        if (u >= 1.0f) { u = 1.0f; landed_ = true; }
        reform_q16_ = landed_ ? 65536 : static_cast<std::int32_t>(std::lround(u * u * (3.0f - 2.0f * u) * 65536.0f));
        return;
    }
    const bool drift = elapsed >= explode_ms;
    phase_ = drift ? Phase::Drift : Phase::Explode;
    if (dt_ms <= 0) return;
    const float dt = static_cast<float>(dt_ms) * 0.001f;
    const auto drag_q15 = static_cast<std::int32_t>(std::lround(std::exp(-drag_per_s * dt) * 32768.0f));
    const auto dt_q16 = static_cast<std::int32_t>(dt_ms * 65536 / 1000);
    // Gravity only while drifting: along -up, weaker as the glass lies flatter (|up| in the plane < 1).
    const float gx = -ux, gy = -uy, gn = std::sqrt(gx * gx + gy * gy);
    const auto dvx = drift ? static_cast<std::int32_t>(std::lround(gx * gravity_px_s2 * static_cast<float>(unit) * dt)) : 0;
    const auto dvy = drift ? static_cast<std::int32_t>(std::lround(gy * gravity_px_s2 * static_cast<float>(unit) * dt)) : 0;
    // Down as a grid step: the floor is the edge (or the two edges) gravity pushes against.
    down_x_ = down_y_ = 0;
    if (drift && gn >= flat_in_plane) {
        if (std::fabs(gx) > diagonal_part * gn) down_x_ = gx > 0 ? 1 : -1;
        if (std::fabs(gy) > diagonal_part * gn) down_y_ = gy > 0 ? 1 : -1;
    }
    const int ddx = down_x_, ddy = down_y_;
    if ((ddx || ddy) && resting_) {   // the pile follows the down of this frame
        slide_ms_ += dt_ms;
        for (int n = 0; n < max_slides && slide_ms_ >= slide_step_ms; ++n) { slide_ms_ -= slide_step_ms; slide(gx, gy); }
        if (slide_ms_ > slide_step_ms) slide_ms_ = slide_step_ms;
    } else slide_ms_ = 0;
    for (std::size_t i = 0; i < count_; ++i) {
        auto& p = p_[i];
        if (p.home & lying) continue;
        const int home = cell_of(p);
        const std::int32_t h = rows_of(home) * unit, top = max_y(home);
        std::int32_t vx = clampi(((p.vx * drag_q15) >> 15) + dvx, -32767, 32767), vy = clampi(((p.vy * drag_q15) >> 15) + dvy, -32767, 32767);
        const std::int32_t mx = ((p.vx + vx) * dt_q16) >> 17, my = ((p.vy + vy) * dt_q16) >> 17;   // mean of old and new velocity
        std::int32_t x = p.x, y = p.y;
        // At most one cell per move, so a fast block cannot jump over the pile. The edges of the band are
        // the glass: it bounces back in, losing half the speed. Not from the floor (the edge that is down)
        // or from a lying block below it: there it stops, like snow. Only a block moving toward down
        // meets the pile; sideways and upward it passes (and then comes to lie on top), so where a
        // block ends up does not depend on which neighbour happened to land a frame earlier.
        const std::int32_t moves = 1 + std::max(absi(mx), absi(my)) / cell;
        bool stop_x = false, stop_y = false;
        for (std::int32_t k = 1; k <= moves && !(stop_x && stop_y); ++k) {
            const std::int32_t sx = stop_x ? 0 : mx * k / moves - mx * (k - 1) / moves, sy = stop_y ? 0 : my * k / moves - my * (k - 1) / moves;
            if (sx) {
                std::int32_t nx = x + sx; bool hit = false;
                if (nx < 0) { nx = 0; hit = true; } else if (nx > max_x) { nx = max_x; hit = true; }
                else if (resting_ && ddx && (ddx > 0) == (sx > 0)) {
                    const int to = (sx > 0 ? nx + cell - 1 : nx) / cell, from = (sx > 0 ? x + cell - 1 : x) / cell;
                    if (to != from && taken(to, row_mid(y, h))) { nx = sx > 0 ? (to - 1) * cell : (to + 1) * cell; hit = true; }
                }
                x = nx;
                if (hit) { stop_x = true; vx = ddx && (ddx > 0) == (sx > 0) ? 0 : -vx / 2; }
            }
            if (sy) {
                std::int32_t ny = y + sy; bool hit = false;
                if (ny < 0) { ny = 0; hit = true; } else if (ny > top) { ny = top; hit = true; }
                else if (resting_ && ddy && (ddy > 0) == (sy > 0)) {
                    const std::int32_t lead = (sy > 0 ? ny + h - 1 : ny) - pile_y0, was = (sy > 0 ? y + h - 1 : y) - pile_y0;
                    if (lead >= 0) {   // (the band's top pixel row is above the cells)
                        const int to = lead / cell, from = was >= 0 ? was / cell : -1;
                        if (to != from && taken(col_mid(x), to)) { ny = sy > 0 ? pile_y0 + to * cell - h : pile_y0 + (to + 1) * cell; hit = true; }
                    }
                }
                y = ny;
                if (hit) { stop_y = true; vy = ddy && (ddy > 0) == (sy > 0) ? 0 : -vy / 2; }
            }
        }
        p.x = static_cast<std::int16_t>(x); p.y = static_cast<std::int16_t>(y);
        p.vx = sat16(vx); p.vy = sat16(vy);
        if (!ddx && !ddy) continue;
        // Held: against the floor or a lying block on every axis that down has, and not moving away from it.
        bool held = true;
        if (ddx) {
            held = vx * ddx >= 0;
            if (held && ddx > 0 && x < max_x) { const int to = (x + cell - 1 + touch) / cell; held = to >= pile_w || (to != (x + cell - 1) / cell && taken(to, row_mid(y, h))); }
            else if (held && ddx < 0 && x > 0) { const std::int32_t lead = x - touch; held = lead < 0 || (lead / cell != x / cell && taken(lead / cell, row_mid(y, h))); }
        }
        if (held && ddy) {
            held = vy * ddy >= 0;
            if (held && ddy > 0 && y < top) {
                const std::int32_t lead = y + h - 1 + touch - pile_y0, was = y + h - 1 - pile_y0;
                const int to = lead >= 0 ? lead / cell : -1;
                held = to >= pile_h || (to >= 0 && to != (was >= 0 ? was / cell : -1) && taken(col_mid(x), to));
            } else if (held && ddy < 0 && y > 0) {
                const std::int32_t lead = y - touch - pile_y0, was = y - pile_y0;
                held = lead < 0 ? y <= touch : (lead / cell != (was >= 0 ? was / cell : -1) && taken(col_mid(x), lead / cell));
            }
        }
        if (held) try_rest(p, x, y);
    }
}

void Burst::paint(Canvas& c, int origin_y) const {
    if (!active() || !src_.valid()) return;
    const int w = std::min(persona::art_w, c.width());
    const bool swap = c.big_endian();
    std::uint16_t* px = c.pixels();
    const auto stride = static_cast<std::size_t>(c.width());
    for (std::size_t i = 0; i < count_; ++i) {
        const auto& p = p_[i];
        const int home = cell_of(p), rows = rows_of(home), hx = (home % grid_w) * block, hy = (home / grid_w) * block;
        const Px at = now_at(p);
        const int x0 = clampi((at.x + unit / 2) >> 6, 0, persona::art_w - block), y0 = clampi((at.y + unit / 2) >> 6, 0, persona::art_h - rows);
        const int turn = rows == block ? quarter_ : 0;   // the 1-row blocks of the last art row are not turned
        for (int yy = 0; yy < rows; ++yy) {
            const int y = origin_y + y0 + yy;
            if (y < 0 || y >= c.height()) continue;
            std::uint16_t* row = px + static_cast<std::size_t>(y) * stride;
            for (int xx = 0; xx < block && x0 + xx < w; ++xx) {
                // Which home pixel shows here: the block's pixels turned clockwise by `turn` quarter turns.
                const int u = turn == 0 ? xx : turn == 1 ? yy : turn == 2 ? block - 1 - xx : block - 1 - yy;
                const int v2 = turn == 0 ? yy : turn == 1 ? block - 1 - xx : turn == 2 ? block - 1 - yy : xx;
                const std::uint16_t v = src_.at(hx + u, hy + v2);
                if (v) row[x0 + xx] = swap ? static_cast<std::uint16_t>((v << 8) | (v >> 8)) : v;   // black is the cleared band
            }
        }
    }
}

Point Burst::position(std::size_t i) const {
    if (i >= count()) return {};
    const Px at = now_at(p_[i]);
    return {static_cast<float>(at.x) / static_cast<float>(unit), static_cast<float>(at.y) / static_cast<float>(unit)};
}

Point Burst::home(std::size_t i) const {
    if (i >= count()) return {};
    const int home = cell_of(p_[i]);
    return {static_cast<float>((home % grid_w) * block), static_cast<float>((home / grid_w) * block)};
}

bool Burst::resting(std::size_t i) const { return i < count() && (p_[i].home & lying); }

} // namespace guardian::companion::burst

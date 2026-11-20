// G16I snow-globe burst (adapters/companion/burst.hpp) over the real embedded portraits
// (art/persona/v2/portrait/*.rgb565). Host, deterministic; nothing here is radio evidence.
#include "check.hpp"
#include "burst.hpp"
#include "persona.hpp"
#include <array>
#include <cmath>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

using namespace guardian;
using namespace guardian::companion;
using burst::Burst;
using burst::Phase;

namespace {
std::vector<std::uint8_t> load_named(const char* name) {
    std::vector<std::uint8_t> out;
    const std::string path = std::string(GUARDIAN_ART_DIR "/portrait/") + name + "_portrait.rgb565";
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return out;
    out.resize(persona::art_bytes);
    if (std::fread(out.data(), 1, persona::art_bytes, f) != persona::art_bytes) out.clear();
    std::fclose(f);
    return out;
}
std::uint16_t art_px(const std::vector<std::uint8_t>& a, int x, int y) {
    const auto i = (static_cast<std::size_t>(y) * persona::art_w + static_cast<std::size_t>(x)) * 2;
    return static_cast<std::uint16_t>(a[i] | (a[i + 1] << 8));
}
int lit_blocks(const std::vector<std::uint8_t>& a) {
    int n = 0;
    for (int gy = 0; gy < burst::grid_h; ++gy) for (int gx = 0; gx < burst::grid_w; ++gx) {
        bool lit = false;
        for (int y = gy * 3; y < gy * 3 + 3 && y < persona::art_h; ++y) for (int x = gx * 3; x < gx * 3 + 3; ++x) lit = lit || art_px(a, x, y);
        n += lit;
    }
    return n;
}
constexpr int panel_w = 135, panel_h = 240, zone = 20;
constexpr std::uint16_t untouched = 0x1234;
struct Shot {
    std::array<std::uint16_t, panel_w * panel_h> px{};
    Canvas canvas;
    explicit Shot(bool big_endian = false, std::uint16_t fill = 0) : canvas(px.data(), panel_w, panel_h, big_endian) { canvas.clear(fill); }
    std::uint16_t at(int x, int y) const { return canvas.get(x, y); }
};
persona::PixelSource bytes_of(const std::vector<std::uint8_t>& a) { return persona::PixelSource{nullptr, a.data()}; }
// Heap, like the board's PSRAM object (16 KB is not a stack object).
struct Rig {
    std::vector<std::uint8_t> art; std::unique_ptr<Burst> b{new Burst}; Millis t{1000};
    explicit Rig(const char* name = "Medium") : art(load_named(name)) {}
    bool ok() const { return art.size() == persona::art_bytes; }
    bool begin(std::uint32_t seed = 7, const persona::Pose& pose = {}) { return b->begin(art.data(), bytes_of(art), t, pose, 0, 0, seed); }
    void run(Millis ms, Millis frame = 40, float up_x = 0, float up_y = -1, const persona::Pose& pose = {}) {
        for (Millis e = 0; e < ms; e += frame) { t += frame; b->step(t, up_x, up_y, pose); }
    }
    Millis explode_ms() const { return static_cast<Millis>(b->total_s() * burst::explode_part * 1000.0f); }
    Millis drift_ms() const { return static_cast<Millis>(b->total_s() * burst::drift_part * 1000.0f); }
};
bool in_band(const Burst& b) {
    for (std::size_t i = 0; i < b.count(); ++i) {
        const auto p = b.position(i); const int rows = b.home(i).y >= 159.0f ? 1 : 3;
        if (p.x < 0 || p.x > persona::art_w - 3 || p.y < 0 || p.y > static_cast<float>(persona::art_h - rows)) return false;
    }
    return true;
}
float dist_from_pivot(burst::Point p) { return std::hypot(p.x + 1.5f - persona::pivot.x, p.y + 1.5f - persona::pivot.y); }
} // namespace

GUARDIAN_CASE(begin_takes_one_particle_per_lit_block_and_refuses_oversized_art) {
    CHECK_EQ(burst::grid_w, 45); CHECK_EQ(burst::grid_h, 54); CHECK_EQ(burst::capacity, std::size_t{1600});
    CHECK_EQ(sizeof(burst::Particle), std::size_t{10}); CHECK(sizeof(Burst) < 16000 + 640);   // G16I "+16,000 B PSRAM"; G16O adds the pile map
    for (const char* name : {"VeryGood", "Good", "Medium", "Bad", "Horrible"}) {
        Rig r(name); CHECK(r.ok()); if (!r.ok()) continue;
        const int lit = lit_blocks(r.art);
        // "about a thousand" (MEASURED 1,357..1,391 on the G16C portraits). G16Q part 2 (candidate D, dithered, MEASURED
        // 2026-11-19): 1,461..1,509 on the 5 rated frames (1,461..1,509 with the ALERT pulses): the dither lights faint
        // rim blocks. Still below capacity (1,600), so a shake always bursts.
        CHECK(lit >= 1400 && lit <= 1560); CHECK(lit < static_cast<int>(burst::capacity));
        CHECK(!r.b->active()); CHECK_EQ(r.b->count(), std::size_t{0}); CHECK(r.b->art() == nullptr);
        CHECK(r.begin()); CHECK(r.b->active()); CHECK(r.b->phase() == Phase::Explode);
        CHECK_EQ(r.b->count(), static_cast<std::size_t>(lit)); CHECK(r.b->art() == r.art.data());
        // Every particle starts on its own home block, each home once, each block lit.
        std::vector<int> seen(burst::grid_w * burst::grid_h); int off_home = 0, dark = 0;
        for (std::size_t i = 0; i < r.b->count(); ++i) {
            const auto h = r.b->home(i), p = r.b->position(i);
            off_home += p.x != h.x || p.y != h.y;
            const int gx = static_cast<int>(h.x) / 3, gy = static_cast<int>(h.y) / 3; ++seen[gy * burst::grid_w + gx];
            bool lit_block = false;
            for (int y = gy * 3; y < gy * 3 + 3 && y < persona::art_h; ++y) for (int x = gx * 3; x < gx * 3 + 3; ++x) lit_block = lit_block || art_px(r.art, x, y);
            dark += !lit_block;
        }
        int twice = 0; for (int n : seen) twice += n > 1;
        CHECK_EQ(off_home, 0); CHECK_EQ(dark, 0); CHECK_EQ(twice, 0);
    }
    Rig nd("NoData"); CHECK(nd.ok()); if (!nd.ok()) return;
    CHECK(lit_blocks(nd.art) <= static_cast<int>(burst::capacity));     // 1,575: it fits, the composer never bursts it
    std::vector<std::uint8_t> full(persona::art_bytes, 0xff);           // every block lit: 2,430 > capacity
    Burst* b = new Burst;
    CHECK(!b->begin(full.data(), bytes_of(full), 0, {}, 0, 0, 1)); CHECK(!b->active()); CHECK_EQ(b->started(), 0u);
    CHECK(!b->begin(nd.art.data(), persona::PixelSource{}, 0, {}, 0, 0, 1));   // no pixels: refused
    CHECK(!b->begin(nullptr, bytes_of(nd.art), 0, {}, 0, 0, 1));
    CHECK(!b->kick(0, 0, 0, 1));                                          // nothing to kick
    delete b;
}

GUARDIAN_CASE(particles_stay_inside_the_band_in_every_phase) {
    Rig r("Horrible"); CHECK(r.ok()); if (!r.ok()) return; CHECK(r.begin(99));
    int frames = 0, outside_band = 0, off = 0, reform_frames = 0; bool saw[4] = {}, kicked_in_reform = false;
    while (r.b->active() && frames < 900) {
        // A shaken stick: gravity swings round and a hard shove now and then. G16O: while it swings the
        // particles keep falling, so the hand stops after 200 frames (and once more after the last shake).
        const float ang = static_cast<float>(frames < 200 ? frames : 200) * 0.3f;
        r.t += 40; r.b->step(r.t, 1.4f * std::cos(ang), 1.4f * std::sin(ang));
        reform_frames += r.b->phase() == Phase::Reform;
        const bool mid_reform = !kicked_in_reform && reform_frames == 10;
        if (frames == 5 || frames == 30 || frames == 100 || mid_reform) {  // shaken again: mid-explode, mid-drift, in the pile, mid-reform
            r.b->kick(r.t, 4.0f * std::cos(ang * 3), -4.0f, static_cast<std::uint32_t>(frames));
            kicked_in_reform = kicked_in_reform || mid_reform;
        }
        if (!r.b->active()) break;
        saw[static_cast<int>(r.b->phase())] = true;
        off += !in_band(*r.b);
        Shot s(false, untouched); r.b->paint(s.canvas, zone);
        for (int y = 0; y < panel_h; ++y) for (int x = 0; x < panel_w; ++x)
            if ((y < zone || y >= zone + persona::art_h) && s.at(x, y) != untouched) ++outside_band;
        ++frames;
    }
    CHECK(frames > 80); CHECK(frames < 900); CHECK(saw[1]); CHECK(saw[2]); CHECK(saw[3]); CHECK(kicked_in_reform);
    CHECK_EQ(off, 0); CHECK_EQ(outside_band, 0);
    // A band at the very bottom of a short canvas is clipped, never written past.
    Rig c; CHECK(c.begin()); c.run(400);
    std::array<std::uint16_t, 135 * 100 + 16> small{}; small.fill(untouched);
    Canvas canvas(small.data(), 135, 100, true); c.b->paint(canvas, 40);
    for (std::size_t i = 135 * 100; i < small.size(); ++i) CHECK_EQ(small[i], untouched);
}

GUARDIAN_CASE(explode_moves_every_particle_away_from_the_pivot) {
    Rig r; CHECK(r.ok()); if (!r.ok()) return; CHECK(r.begin(3));
    r.run(40, 20);                                                       // two 20 ms steps: 5..12 px at 120..300 px/s
    int inward = 0, slow = 0, far = 0;
    for (std::size_t i = 0; i < r.b->count(); ++i) {
        const auto h = r.b->home(i), p = r.b->position(i);
        const float d0 = dist_from_pivot(h), d1 = dist_from_pivot(p);
        const bool near_wall = h.x < 14 || h.x > persona::art_w - 17 || h.y < 14 || h.y > persona::art_h - 17;
        if (d1 < d0 - 0.5f && !near_wall) ++inward;
        if (!near_wall && d0 > 6.0f) { ++far; if (d1 - d0 < 3.0f || d1 - d0 > 13.0f) ++slow; }
    }
    CHECK(far > 800); CHECK_EQ(inward, 0); CHECK_EQ(slow, 0);
    CHECK(r.b->phase() == Phase::Explode);
    // The shove throws the whole cloud the other way (the stick pushed right: the snow lags left).
    Rig a, b; CHECK(a.begin(3)); CHECK(b.b->begin(b.art.data(), bytes_of(b.art), b.t, {}, 3.0f, 0, 3));
    a.run(80, 20); b.run(80, 20);
    double ax = 0, bx = 0; for (std::size_t i = 0; i < a.b->count(); ++i) { ax += a.b->position(i).x; bx += b.b->position(i).x; }
    CHECK(bx / static_cast<double>(b.b->count()) < ax / static_cast<double>(a.b->count()) - 4.0);
}

GUARDIAN_CASE(gravity_follows_the_given_up_vector) {
    const struct { float up_x, up_y; float want_x, want_y; } cases[] = {
        {0, -1, 0, 1},      // standing, USB down: the snow settles on the band's bottom edge
        {0, 1, 0, -1},      // upside down: on the top edge
        {-1, 0, 1, 0},      // quarter turn clockwise: the world's down is the screen's right
        {1, 0, -1, 0}};
    // How far the middle of the cloud is from the middle of the face it came from.
    const auto moved = [](const Burst& b, double& dx, double& dy) {
        dx = dy = 0;
        for (std::size_t i = 0; i < b.count(); ++i) { dx += b.position(i).x - b.home(i).x; dy += b.position(i).y - b.home(i).y; }
        dx /= static_cast<double>(b.count()); dy /= static_cast<double>(b.count());
    };
    for (const auto& k : cases) {
        Rig r; CHECK(r.ok()); if (!r.ok()) return; CHECK(r.begin(11));
        r.run(r.explode_ms() + r.drift_ms() - 80, 40, k.up_x, k.up_y);
        CHECK(r.b->phase() == Phase::Drift);
        double mx, my; moved(*r.b, mx, my);
        std::printf("     up %+.0f,%+.0f: cloud moved %+.1f,%+.1f px\n", double(k.up_x), double(k.up_y), mx, my);
        CHECK(mx * k.want_x + my * k.want_y > 20.0);                    // well toward "down"
        CHECK(std::fabs(mx * k.want_y - my * k.want_x) < 8.0);          // and not sideways
    }
    // Lying flat (no gravity across the glass): the cloud stays about where the face was.
    Rig f; CHECK(f.begin(11)); f.run(f.explode_ms() + f.drift_ms() - 80, 40, 0, 0);
    double mx, my; moved(*f.b, mx, my);
    CHECK(std::fabs(mx) < 8.0); CHECK(std::fabs(my) < 8.0);
}

GUARDIAN_CASE(reform_lands_every_block_exactly_on_its_home) {
    Rig r("Bad"); CHECK(r.ok()); if (!r.ok()) return; CHECK(r.begin(5));
    const Millis start = r.t; float prev_err = 1e9f; int grew = 0, frames = 0; bool was_reform = false;
    Millis landed_at = 0;
    while (r.b->active() && frames < 300) {
        r.run(40); ++frames;
        if (!r.b->active()) break;
        if (r.b->phase() != Phase::Reform) continue;
        was_reform = true;
        float err = 0; for (std::size_t i = 0; i < r.b->count(); ++i) { const auto p = r.b->position(i), h = r.b->home(i); err += std::fabs(p.x - h.x) + std::fabs(p.y - h.y); }
        if (err > prev_err + 1e-3f) ++grew;
        prev_err = err;
        if (err == 0.0f && !landed_at) landed_at = r.t;
    }
    CHECK(was_reform); CHECK_EQ(grew, 0);                               // it only ever closes in ("slowly reforming")
    CHECK(landed_at != 0);                                              // one frame with every block exactly home ...
    CHECK(!r.b->active()); CHECK(r.b->phase() == Phase::Idle);          // ... then the burst is over
    const double total_ms = static_cast<double>(landed_at - start);
    CHECK(total_ms >= 3500.0 && total_ms <= 3500.0 + 80.0);             // the default 3.5 s
    CHECK_EQ(r.b->started(), 1u);
}

GUARDIAN_CASE(final_frame_equals_the_identity_portrait) {
    persona::Motion still{}; still.tilt_max_deg = 0; still.breath_amount = 0;
    for (const char* name : {"VeryGood", "Good", "Medium", "Bad", "Horrible"}) for (bool big : {false, true}) {
        Rig r(name); CHECK(r.ok()); if (!r.ok()) continue; CHECK(r.begin(21));
        Shot mid(big); r.run(1000); r.b->paint(mid.canvas, zone);
        Shot last(big), want(big); int frames = 0;
        while (r.b->active() && frames++ < 300) { last.canvas.clear(0); r.b->paint(last.canvas, zone); r.run(40); }
        persona::paint_portrait(want.canvas, r.art.data(), 0, persona::Placement{zone, 0, 0, 0}, persona::Layers{true, false, false}, still, false);
        int differing = 0, mid_differing = 0;
        for (std::size_t i = 0; i < last.px.size(); ++i) { differing += last.px[i] != want.px[i]; mid_differing += mid.px[i] != want.px[i]; }
        if (differing) std::printf("     %s big=%d: %d pixels differ\n", name, int(big), differing);
        CHECK_EQ(differing, 0);                                         // the last burst frame IS the still portrait
        CHECK(mid_differing > 4000);                                    // and mid-burst it was nothing like it
    }
}

GUARDIAN_CASE(particles_keep_the_colours_of_the_face) {
    Rig r("VeryGood"); CHECK(r.ok()); if (!r.ok()) return; CHECK(r.begin(8)); r.run(900);
    Shot s; r.b->paint(s.canvas, zone);
    std::vector<bool> in_art(65536);
    for (int y = 0; y < persona::art_h; ++y) for (int x = 0; x < persona::art_w; ++x) in_art[art_px(r.art, x, y)] = true;
    int foreign = 0, lit = 0;
    for (int y = zone; y < zone + persona::art_h; ++y) for (int x = 0; x < panel_w; ++x) { const auto v = s.at(x, y); lit += v != 0; foreign += !in_art[v]; }
    CHECK_EQ(foreign, 0); CHECK(lit > 3000);
}

GUARDIAN_CASE(kick_during_reform_rescatters) {
    Rig r; CHECK(r.ok()); if (!r.ok()) return; CHECK(r.begin(5));
    r.run(r.explode_ms() + r.drift_ms() + 1600);                        // most of the way home
    CHECK(r.b->phase() == Phase::Reform);
    float err0 = 0; std::vector<burst::Point> before;
    for (std::size_t i = 0; i < r.b->count(); ++i) { const auto p = r.b->position(i), h = r.b->home(i); err0 += std::hypot(p.x - h.x, p.y - h.y); before.push_back(p); }
    CHECK(r.b->kick(r.t, 0, 0, 77)); CHECK(r.b->phase() == Phase::Explode);
    int jumped = 0;
    for (std::size_t i = 0; i < r.b->count(); ++i) { const auto p = r.b->position(i); jumped += std::hypot(p.x - before[i].x, p.y - before[i].y) > 1.0f; }
    CHECK_EQ(jumped, 0);                                                // thrown from where it was, no teleport
    r.run(400);
    float err1 = 0; for (std::size_t i = 0; i < r.b->count(); ++i) { const auto p = r.b->position(i), h = r.b->home(i); err1 += std::hypot(p.x - h.x, p.y - h.y); }
    CHECK(err1 > err0 * 2.0f);                                          // scattered again
    CHECK_EQ(r.b->started(), 1u);                                       // one burst, kicked
    int frames = 0; while (r.b->active() && frames++ < 300) r.run(40);  // and the full show runs again from the kick
    CHECK(!r.b->active()); CHECK(frames > 70);
}

GUARDIAN_CASE(step_is_frame_rate_independent) {
    Rig a, b; CHECK(a.ok()); if (!a.ok()) return; CHECK(a.begin(42)); CHECK(b.begin(42));
    // What two runs have in common, block by block and as a cloud.
    struct Apart { double mean, worst, cx, cy, columns, rows; };
    const auto apart = [](const Burst& p, const Burst& q) {
        Apart r{}; double px = 0, py = 0, qx = 0, qy = 0; std::array<int, 45> pc{}, qc{}; std::array<int, 54> pr{}, qr{};
        for (std::size_t i = 0; i < p.count(); ++i) {
            const auto u = p.position(i), v = q.position(i); const double d = std::hypot(u.x - v.x, u.y - v.y);
            r.mean += d; r.worst = std::max(r.worst, d); px += u.x; py += u.y; qx += v.x; qy += v.y;
            ++pc[std::min<std::size_t>(44, static_cast<std::size_t>(u.x + 1.5f) / 3)]; ++qc[std::min<std::size_t>(44, static_cast<std::size_t>(v.x + 1.5f) / 3)];
            ++pr[std::min<std::size_t>(53, static_cast<std::size_t>(u.y + 1.5f) / 3)]; ++qr[std::min<std::size_t>(53, static_cast<std::size_t>(v.y + 1.5f) / 3)];
        }
        const double n = static_cast<double>(p.count());
        for (std::size_t c = 0; c < pc.size(); ++c) r.columns += std::abs(pc[c] - qc[c]);
        for (std::size_t y = 0; y < pr.size(); ++y) r.rows += std::abs(pr[y] - qr[y]);
        r.mean /= n; r.cx = (px - qx) / n; r.cy = (py - qy) / n; r.columns /= n; r.rows /= n;
        return r;
    };
    // The flight (explode: nothing lies yet): every block is in the same place at 50 fps and at 20 fps.
    a.run(a.explode_ms(), 20); b.run(b.explode_ms(), 50);
    CHECK(a.b->phase() == b.b->phase());
    Apart gap = apart(*a.b, *b.b);
    std::printf("     20 ms vs 50 ms steps after %u ms: mean %.2f px, worst %.1f px, centroid %.2f,%.2f px apart\n", unsigned(a.explode_ms()), gap.mean, gap.worst, gap.cx, gap.cy);
    CHECK(gap.mean < 3.0); CHECK(std::fabs(gap.cx) < 1.5); CHECK(std::fabs(gap.cy) < 1.5);
    // The fall. G16O: the blocks settle, and which of two blocks lands first (so which lies on which) is a
    // matter of milliseconds, so block by block the two runs differ in their stacking order (MEASURED
    // 2026-11-18: mean 9.9 px, almost all of it up and down). The cloud is the same: its middle, how much
    // of it lies, and its profile (blocks per 3 px column and per 3 px row).
    const Millis fall = a.drift_ms() - 100;
    a.run(fall, 20); b.run(fall, 50);
    CHECK(a.b->phase() == Phase::Drift); CHECK(b.b->phase() == Phase::Drift);
    gap = apart(*a.b, *b.b);
    const double lying_a = static_cast<double>(a.b->resting()), lying_b = static_cast<double>(b.b->resting()), n = static_cast<double>(a.b->count());
    std::printf("     ... and after %u ms: block by block mean %.2f px, worst %.1f px; centroid %.2f,%.2f px apart; lying %.0f vs %.0f of %.0f; profile apart %.1f %% by column, %.1f %% by row\n",
                unsigned(a.explode_ms() + fall), gap.mean, gap.worst, gap.cx, gap.cy, lying_a, lying_b, n, 100.0 * gap.columns, 100.0 * gap.rows);
    CHECK(std::fabs(gap.cx) < 3.0); CHECK(std::fabs(gap.cy) < 3.0);
    CHECK(std::fabs(lying_a - lying_b) < 0.08 * n); CHECK(lying_a > 0.5 * n);
    CHECK(gap.columns < 0.20); CHECK(gap.rows < 0.20); CHECK(gap.mean < 20.0);   // MEASURED 10.4 % and 5.6 %
    // The show's length never depends on the frame rate, and a stalled frame is absorbed.
    Rig c, d; CHECK(c.begin(1)); CHECK(d.begin(1));
    c.run(3600, 20); d.run(1000, 100); d.t += 1500; d.b->step(d.t, 0, -1); CHECK(d.b->active()); d.run(1100, 100);
    CHECK(!c.b->active()); CHECK(!d.b->active());
}

GUARDIAN_CASE(total_time_follows_configure) {
    Rig r; CHECK(r.ok()); if (!r.ok()) return;
    CHECK_EQ(r.b->total_s(), burst::default_total_s);
    CHECK(burst::default_total_s >= burst::total_s_range.lo && burst::default_total_s <= burst::total_s_range.hi);
    r.b->configure(7.0f); CHECK_EQ(r.b->total_s(), 7.0f); CHECK(r.begin());
    r.run(6800); CHECK(r.b->active()); r.run(400); CHECK(!r.b->active());
    r.b->configure(0.1f); CHECK_EQ(r.b->total_s(), burst::total_s_range.lo);
    r.b->configure(99.0f); CHECK_EQ(r.b->total_s(), burst::total_s_range.hi);
}

GUARDIAN_CASE(cancel_stops_painting) {
    Rig r; CHECK(r.ok()); if (!r.ok()) return; CHECK(r.begin()); r.run(600);
    Shot painted(false, untouched); r.b->paint(painted.canvas, zone);
    int lit = 0; for (auto v : painted.px) lit += v != untouched;
    CHECK(lit > 3000);
    r.b->cancel(); CHECK(!r.b->active()); CHECK(r.b->phase() == Phase::Idle); CHECK(r.b->art() == nullptr);
    Shot s(false, untouched); r.b->paint(s.canvas, zone);
    int touched = 0; for (auto v : s.px) touched += v != untouched;
    CHECK_EQ(touched, 0);
    r.run(200); CHECK(!r.b->active());                                  // stepping a cancelled burst does nothing
    CHECK(r.begin()); CHECK(r.b->active()); CHECK_EQ(r.b->started(), 2u);
}

// The face may be turned (G16I upright) or shifted when the stick is shaken: the cloud leaves from
// where the face is drawn and reforms where it will be drawn.
GUARDIAN_CASE(homes_follow_the_face_pose) {
    const persona::Pose turned{-90.0f, persona::fit_scale(-90.0f), 0, 0};
    Rig r; CHECK(r.ok()); if (!r.ok()) return; CHECK(r.begin(5, turned));
    const auto posed = [&](std::size_t i, const persona::Pose& pose) {
        const auto h = r.b->home(i); const float rows = h.y >= 159.0f ? 1.0f : 3.0f;
        // The middle pixel of the block (pixel-index coordinates, like the warp and persona::pivot).
        auto c = persona::map_point(pose, persona::Point{h.x + 1.0f, h.y + (rows - 1) / 2});
        return burst::Point{c.x - 1.0f, c.y - (rows - 1) / 2};
    };
    float worst = 0;
    for (std::size_t i = 0; i < r.b->count(); ++i) { const auto p = r.b->position(i), w = posed(i, turned); worst = std::fmax(worst, std::hypot(p.x - w.x, p.y - w.y)); }
    CHECK(worst < 1.0f);                                                // it starts as the turned face
    // While it is in the air the stick is stood upright again: it reforms to the pose of that moment.
    const persona::Pose shifted{0.0f, 1.0f, 2.0f, -1.0f};
    int frames = 0; std::vector<burst::Point> last;
    while (r.b->active() && frames++ < 300) {
        last.clear(); for (std::size_t i = 0; i < r.b->count(); ++i) last.push_back(r.b->position(i));
        r.run(40, 40, 0, -1, shifted);
    }
    CHECK(!r.b->active()); CHECK(!last.empty());
    Rig ref; CHECK(ref.begin(5, shifted));
    worst = 0; for (std::size_t i = 0; i < last.size(); ++i) { const auto w = ref.b->position(i); worst = std::fmax(worst, std::hypot(last[i].x - w.x, last[i].y - w.y)); }
    CHECK_EQ(worst, 0.0f);                                              // landed exactly where a face at that pose starts
    CHECK(in_band(*ref.b));
}

// Turned by a quarter or half turn (the stick on its side or upside down), the landed mosaic IS the
// turned portrait: every block sits on the turned pixel grid and shows its own pixels turned with it.
GUARDIAN_CASE(a_face_on_its_side_or_upside_down_lands_as_the_turned_portrait) {
    for (const float tilt : {180.0f, 90.0f, -90.0f}) {
        Rig r("VeryGood"); CHECK(r.ok()); if (!r.ok()) return;
        const persona::Pose pose{tilt, 1.0f, 0, 0};
        CHECK(r.begin(9, pose));
        Shot last; int frames = 0;
        while (r.b->active() && frames++ < 300) { last.canvas.clear(0); r.b->paint(last.canvas, zone); r.run(40, 40, 0, -1, pose); }
        // Every art pixel well inside the band after the turn (a block pushed back from an edge is not compared).
        int compared = 0, wrong = 0;
        for (int ay = 0; ay < persona::art_h; ++ay) for (int ax = 0; ax < persona::art_w; ++ax) {
            const int cx = ax - 67, cy = ay - 80;
            const int sx = 67 + (tilt == 180.0f ? -cx : tilt == 90.0f ? -cy : cy), sy = 80 + (tilt == 180.0f ? -cy : tilt == 90.0f ? cx : -cx);
            if (sx < 4 || sx >= persona::art_w - 4 || sy < 4 || sy >= persona::art_h - 4 || ay >= 156) continue;
            ++compared; wrong += last.at(sx, zone + sy) != art_px(r.art, ax, ay);
        }
        if (wrong) std::printf("     tilt %.0f: %d of %d pixels differ\n", double(tilt), wrong, compared);
        CHECK(compared > 15000); CHECK_EQ(wrong, 0);
    }
}

// ---- G16O: the particles obey gravity; the reform waits for a still stick -----------------------
// Owner 2026-11-18: "when shake, particles should assume physics, fall... if one keeps tilting to
// sides, particles should fall (gravity)... it only comes back with no or very few tilting... if one
// shakes and keeps shaking, particles keep falling on gravity".
namespace {
constexpr float to_rad = 0.01745329252f;
constexpr int pile_cols = 45, pile_rows = 53;   // 3 px cells; row 52 stands on the band's bottom edge (y 157..159)
// A hand on the stick. The world's down points `centre` degrees clockwise from the screen's down
// (0 = standing, 90 = down is the screen's right, 180 = upside down) and swings +-swing about it at
// `hz`; a shove of +-shove_g rides along. One 40 ms face frame per step.
struct Hand {
    Rig& r; float at_deg{};
    void step(float centre, float swing, float hz, float shove_g) {
        r.t += 40;
        const float s = std::sin(6.2831853f * hz * static_cast<float>(r.t % 100000) / 1000.0f);
        at_deg = centre + swing * s;
        r.b->step(r.t, -std::sin(at_deg * to_rad), -std::cos(at_deg * to_rad), {}, shove_g * s, 0.0f);
    }
    void tilt(Millis ms, float centre, float swing = 12.0f, float hz = 1.0f, float shove_g = 0.0f) { for (Millis e = 0; e < ms; e += 40) step(centre, swing, hz, shove_g); }
    void hold() { r.t += 40; r.b->step(r.t, -std::sin(at_deg * to_rad), -std::cos(at_deg * to_rad)); }   // exactly still, where the hand stopped
};
// The settled particles as cells of the pile.
struct Pile {
    std::vector<int> cell = std::vector<int>(pile_cols * pile_rows);
    int resting{}, off_grid{}, shared{};
    int at(int c, int row) const { return c < 0 || c >= pile_cols || row < 0 || row >= pile_rows ? 1 : cell[static_cast<std::size_t>(row * pile_cols + c)]; }
};
Pile pile_of(const Burst& b) {
    Pile p;
    for (std::size_t i = 0; i < b.count(); ++i) {
        if (!b.resting(i)) continue;
        ++p.resting;
        const auto at = b.position(i); const int rows = b.home(i).y >= 159.0f ? 1 : 3;
        const int x = static_cast<int>(std::lround(at.x)), bottom = static_cast<int>(std::lround(at.y)) + rows;
        if (at.x != static_cast<float>(x) || at.y != std::floor(at.y) || x % 3 || (bottom - 1) % 3 || bottom < 4 || bottom > persona::art_h || x > persona::art_w - 3) { ++p.off_grid; continue; }
        if (p.cell[static_cast<std::size_t>((bottom - 4) / 3 * pile_cols + x / 3)]++) ++p.shared;
    }
    return p;
}
void centre_of(const Burst& b, double& x, double& y) {   // the middle of the cloud, from the middle of the band
    x = y = 0;
    for (std::size_t i = 0; i < b.count(); ++i) { x += b.position(i).x + 1.5; y += b.position(i).y + 1.5; }
    x = x / static_cast<double>(b.count()) - persona::art_w / 2.0; y = y / static_cast<double>(b.count()) - persona::art_h / 2.0;
}
burst::Params long_show() { burst::Params p; p.max_s = 120.0f; return p; }   // the tests that handle the stick longer than burst.max_s
} // namespace

GUARDIAN_CASE(gravity_follows_the_stick_down_while_tilted) {
    Rig r; CHECK(r.ok()); if (!r.ok()) return; r.b->configure(long_show()); CHECK(r.begin(11));
    Hand h{r};
    // Standing, on its right side, upside down, on its left side, then leaning 45 degrees: the hand never
    // stops moving, and each time the particles end up against the side that is down.
    const struct { float deg, want_x, want_y; } turns[] = {{0, 0, 1}, {90, 1, 0}, {180, 0, -1}, {270, -1, 0}, {405, 0.7071f, 0.7071f}};
    double was_x = 0, was_y = 0;                                        // the cloud starts as the face, in the middle of the band
    for (const auto& k : turns) {
        h.tilt(5000, k.deg);
        CHECK(r.b->active()); CHECK(r.b->phase() == Phase::Drift);       // G16I would have reformed 3.5 s after the shake
        double x, y; centre_of(*r.b, x, y);
        const double toward = x * k.want_x + y * k.want_y, across = x * k.want_y - y * k.want_x;
        const double moved = (x - was_x) * k.want_x + (y - was_y) * k.want_y;
        std::printf("     down at %3.0f deg: the cloud's middle is %+.1f,%+.1f px from the band's (%.1f toward down, %.1f across; it moved %.1f toward down), %zu of %zu at rest\n",
                    double(k.deg), x, y, toward, across, moved, r.b->resting(), r.b->count());
        CHECK(toward > 15.0);                                           // gathered against the side that is down ...
        CHECK(std::fabs(across) < toward);                              // ... more than against any other (a heap keeps its 45 degree slope)
        CHECK(moved > 15.0);                                            // and it went there from where the last turn left it
        CHECK(r.b->resting() * 10 >= r.b->count() * 9);                 // lying there, not floating
        CHECK(in_band(*r.b));
        was_x = x; was_y = y;
    }
}

GUARDIAN_CASE(particles_settle_on_the_floor_and_pile_up) {
    Rig r("VeryGood"); CHECK(r.ok()); if (!r.ok()) return; r.b->configure(long_show()); CHECK(r.begin(4));
    Hand h{r}; h.tilt(8000, 0.0f, 8.0f);                                 // standing, the hand never quite still
    CHECK(r.b->phase() == Phase::Drift);
    const Pile p = pile_of(*r.b);
    std::printf("     %d of %zu particles at rest\n", p.resting, r.b->count());
    CHECK(static_cast<std::size_t>(p.resting) == r.b->resting());
    CHECK(static_cast<std::size_t>(p.resting) * 100 >= r.b->count() * 97);
    CHECK_EQ(p.off_grid, 0);                                            // a block lies in a 3 px cell ...
    CHECK_EQ(p.shared, 0);                                              // ... of its own: a pile, not a heap of overlapping blocks
    int unsupported = 0, floor_blocks = 0, used_rows = 0, steepest = 0; std::array<int, pile_cols> height{};
    for (int row = 0; row < pile_rows; ++row) {
        int in_row = 0;
        for (int c = 0; c < pile_cols; ++c) if (p.at(c, row)) { ++in_row; ++height[static_cast<std::size_t>(c)]; unsupported += !p.at(c, row + 1); }
        used_rows += in_row > 0; if (row == pile_rows - 1) floor_blocks = in_row;
    }
    for (int c = 1; c < pile_cols; ++c) steepest = std::max(steepest, std::abs(height[static_cast<std::size_t>(c)] - height[static_cast<std::size_t>(c - 1)]));
    std::printf("     floor row %d of %d cells, %d rows high, steepest step %d blocks\n", floor_blocks, pile_cols, used_rows, steepest);
    CHECK_EQ(unsupported, 0);                                           // every block stands on the floor or on a block
    CHECK_EQ(floor_blocks, pile_cols);                                  // the band's bottom edge is covered ...
    CHECK(used_rows >= 25 && used_rows <= 40);                          // ... and about 1,380 blocks stack about 31 rows on it
    CHECK(steepest <= 1);                                               // loose blocks topple: no towers
    // On the glass: the pile is drawn as whole blocks in the lower part of the band, in the face's colours.
    Shot s; r.b->paint(s.canvas, zone);
    int lit_low = 0, lit_high = 0;
    for (int y = 0; y < persona::art_h; ++y) for (int x = 0; x < panel_w; ++x) (y >= persona::art_h - 60 ? lit_low : lit_high) += s.at(x, zone + y) != 0;
    std::printf("     lit pixels: %d of %d in the lowest 60 rows, %d of %d above\n", lit_low, 135 * 60, lit_high, 135 * 100);
    CHECK(lit_low > 135 * 60 * 7 / 10); CHECK(lit_high < 135 * 100 * 35 / 100);   // a block is about 7 lit pixels of 9 (MEASURED 9,631..9,956 px in 1,357..1,391 blocks)
    // Lying flat there is no down across the glass: nothing settles.
    Rig f; f.b->configure(long_show()); CHECK(f.begin(4));
    for (int i = 0; i < 150; ++i) { f.t += 40; f.b->step(f.t, 0.0f, 0.0f, {}, 0.3f * static_cast<float>(i % 2 ? 1 : -1), 0.0f); }
    CHECK(f.b->phase() == Phase::Drift); CHECK_EQ(f.b->resting(), std::size_t{0});
}

GUARDIAN_CASE(continuous_tilting_postpones_the_reform) {
    // Tilted to and fro for 12 s: never a reform, the particles are still down there.
    Rig r; CHECK(r.ok()); if (!r.ok()) return; CHECK(r.begin(6));
    Hand h{r}; int reforming = 0;
    for (int i = 0; i < 300; ++i) { h.tilt(40, 0.0f, 25.0f); reforming += r.b->phase() == Phase::Reform || !r.b->active(); }
    CHECK_EQ(reforming, 0); CHECK(r.b->active()); CHECK(r.b->phase() == Phase::Drift); CHECK(r.b->resting() > 0);
    // Shoved to and fro without tilting (the stick kept upright and shaken gently): the same.
    Rig s; CHECK(s.begin(6)); Hand hs{s}; reforming = 0;
    for (int i = 0; i < 300; ++i) { hs.tilt(40, 0.0f, 0.0f, 2.0f, 0.3f); reforming += s.b->phase() != Phase::Drift && s.b->phase() != Phase::Explode; }
    CHECK_EQ(reforming, 0); CHECK(s.b->active());
    // A stick merely held in the hand (the recorded "still" traces: about 2 degrees/s, under 0.06 g)
    // is still: the show ends on time, as when it stands on the desk.
    Rig q; CHECK(q.begin(6)); Hand hq{q};
    hq.tilt(3400, 0.0f, 0.5f, 2.0f, 0.04f); CHECK(q.b->active()); CHECK(q.b->phase() == Phase::Reform);
    hq.tilt(200, 0.0f, 0.5f, 2.0f, 0.04f); CHECK(!q.b->active());
    // The two thresholds decide it (TUNE burst.still_dps, burst.still_g): a gentle sway is "moving" by default ...
    Rig g; CHECK(g.begin(6)); Hand hg{g}; hg.tilt(6000, 0.0f, 4.0f, 1.0f); CHECK(g.b->phase() == Phase::Drift);   // 25 degrees/s at most
    // ... and "still" for an owner who raises the threshold.
    Rig w; burst::Params loose; loose.still_dps = 40.0f; w.b->configure(loose); CHECK(w.begin(6)); Hand hw{w};
    hw.tilt(3400, 0.0f, 4.0f, 1.0f); CHECK(w.b->phase() == Phase::Reform); hw.tilt(200, 0.0f, 4.0f, 1.0f); CHECK(!w.b->active());
}

GUARDIAN_CASE(calm_starts_the_reform_and_lands_exactly) {
    persona::Motion still{}; still.tilt_max_deg = 0; still.breath_amount = 0;
    for (const char* name : {"Bad", "VeryGood"}) {
        Rig r(name); CHECK(r.ok()); if (!r.ok()) continue; CHECK(r.begin(5));
        Hand h{r}; h.tilt(6000, 60.0f, 20.0f);                           // handled for 6 s, leaning: the pile lies in a corner
        CHECK(r.b->phase() == Phase::Drift); CHECK(r.b->resting() * 2 > r.b->count());
        const Millis still_from = r.t; Millis reform_at = 0, landed_at = 0; float prev_err = 1e9f; int grew = 0, frames = 0;
        Shot last, want;
        while (r.b->active() && frames++ < 200) {                       // then held exactly still, still leaning
            h.hold();
            if (!r.b->active()) break;
            if (r.b->phase() != Phase::Reform) continue;
            if (!reform_at) { reform_at = r.t; CHECK_EQ(r.b->resting(), std::size_t{0}); }
            float err = 0; for (std::size_t i = 0; i < r.b->count(); ++i) { const auto p = r.b->position(i), hm = r.b->home(i); err += std::fabs(p.x - hm.x) + std::fabs(p.y - hm.y); }
            if (err > prev_err + 1e-3f) ++grew;
            prev_err = err;
            if (err == 0.0f && !landed_at) { landed_at = r.t; r.b->paint(last.canvas, zone); }
        }
        std::printf("     %s: reform began %u ms and landed %u ms after the hand stopped\n", name, unsigned(reform_at - still_from), unsigned(landed_at - still_from));
        CHECK(reform_at != 0); CHECK(landed_at != 0); CHECK_EQ(grew, 0); CHECK(!r.b->active());
        CHECK(reform_at - still_from >= 600 && reform_at - still_from <= 600 + 40);      // burst.calm_s, default 0.6 s
        CHECK(landed_at - still_from >= 2600 && landed_at - still_from <= 2600 + 80);    // "it reforms in about 2.6 s"
        persona::paint_portrait(want.canvas, r.art.data(), 0, persona::Placement{zone, 0, 0, 0}, persona::Layers{true, false, false}, still, false);
        int differing = 0; for (std::size_t i = 0; i < last.px.size(); ++i) differing += last.px[i] != want.px[i];
        CHECK_EQ(differing, 0);                                         // the landed frame IS the still portrait
    }
    // The calm time follows configure; a move before it is over starts the wait again.
    Rig c; burst::Params p; p.calm_s = 2.0f; c.b->configure(p); CHECK(c.begin(5));
    Hand h{c}; h.tilt(4000, 0.0f, 20.0f);
    for (int i = 0; i < 45; ++i) h.hold();                               // 1.8 s still: not yet
    CHECK(c.b->phase() == Phase::Drift);
    h.tilt(400, 0.0f, 20.0f);                                            // moved again
    for (int i = 0; i < 45; ++i) h.hold();
    CHECK(c.b->phase() == Phase::Drift);
    for (int i = 0; i < 6; ++i) h.hold();                                // 2.04 s still
    CHECK(c.b->phase() == Phase::Reform);
}

GUARDIAN_CASE(max_time_always_reforms) {
    const burst::Params d;
    CHECK_EQ(d.still_dps, 12.0f); CHECK_EQ(d.still_g, 0.10f); CHECK_EQ(d.calm_s, 0.6f); CHECK_EQ(d.max_s, 20.0f); CHECK_EQ(d.total_s, burst::default_total_s);
    CHECK(d.still_dps >= burst::still_dps_range.lo && d.still_dps <= burst::still_dps_range.hi);
    CHECK(d.still_g >= burst::still_g_range.lo && d.still_g <= burst::still_g_range.hi);
    CHECK(d.calm_s >= burst::calm_s_range.lo && d.calm_s <= burst::calm_s_range.hi);
    CHECK(d.max_s >= burst::max_s_range.lo && d.max_s <= burst::max_s_range.hi);
    for (const float max_s : {20.0f, 6.0f}) {
        Rig r; CHECK(r.ok()); if (!r.ok()) return;
        burst::Params p; p.max_s = max_s; r.b->configure(p); CHECK_EQ(r.b->params().max_s, max_s); CHECK(r.begin(9));
        Hand h{r}; const Millis start = r.t; Millis reform_at = 0, ended_at = 0; int frames = 0;
        while (r.b->active() && frames++ < 1000) {                      // the hand never stops
            h.tilt(40, 0.0f, 25.0f);
            if (r.b->phase() == Phase::Reform && !reform_at) reform_at = r.t;
            if (!r.b->active()) ended_at = r.t;
        }
        const auto max_ms = static_cast<Millis>(max_s * 1000.0f);
        std::printf("     max %.0f s: reform began at %u ms, the face was back at %u ms\n", double(max_s), unsigned(reform_at - start), unsigned(ended_at - start));
        CHECK(reform_at - start >= max_ms && reform_at - start <= max_ms + 40);
        CHECK(ended_at - start >= max_ms + 2000 && ended_at - start <= max_ms + 2000 + 80);   // the 2.0 s reform, then over
    }
    // A new shake (kick) starts the clock again: 15 s, shake, 15 s more is still a falling cloud.
    Rig k; CHECK(k.begin(9)); Hand h{k};
    h.tilt(15000, 0.0f, 25.0f); CHECK(k.b->kick(k.t, 0, 0, 3)); h.tilt(15000, 0.0f, 25.0f);
    CHECK(k.b->active()); CHECK(k.b->phase() == Phase::Drift);
    // Out-of-range and non-finite values are clamped; the old one-value configure keeps the rest.
    Rig c; burst::Params wild; wild.total_s = 99.0f; wild.still_dps = 0.0f; wild.still_g = 9.0f; wild.calm_s = 0.0f; wild.max_s = 1.0f;
    c.b->configure(wild);
    CHECK_EQ(c.b->params().total_s, burst::total_s_range.hi); CHECK_EQ(c.b->params().still_dps, burst::still_dps_range.lo);
    CHECK_EQ(c.b->params().still_g, burst::still_g_range.hi); CHECK_EQ(c.b->params().calm_s, burst::calm_s_range.lo); CHECK_EQ(c.b->params().max_s, burst::max_s_range.lo);
    burst::Params nan; nan.still_dps = nan.still_g = nan.calm_s = nan.max_s = std::nanf("");
    c.b->configure(nan);
    CHECK_EQ(c.b->params().still_dps, d.still_dps); CHECK_EQ(c.b->params().still_g, d.still_g); CHECK_EQ(c.b->params().calm_s, d.calm_s); CHECK_EQ(c.b->params().max_s, d.max_s);
    c.b->configure(wild); c.b->configure(5.0f);
    CHECK_EQ(c.b->params().total_s, 5.0f); CHECK_EQ(c.b->total_s(), 5.0f); CHECK_EQ(c.b->params().max_s, burst::max_s_range.lo);
}

GUARDIAN_CASE(a_new_shake_rescatters_a_pile) {
    Rig r; CHECK(r.ok()); if (!r.ok()) return; CHECK(r.begin(5));
    Hand h{r}; h.tilt(6000, 0.0f, 8.0f);                                 // a pile on the floor
    CHECK(r.b->phase() == Phase::Drift); CHECK(r.b->resting() * 100 >= r.b->count() * 95);
    double x0, y0; centre_of(*r.b, x0, y0);
    std::vector<burst::Point> before; for (std::size_t i = 0; i < r.b->count(); ++i) before.push_back(r.b->position(i));
    CHECK(r.b->kick(r.t, 0, 0, 77));
    CHECK(r.b->phase() == Phase::Explode); CHECK_EQ(r.b->resting(), std::size_t{0}); CHECK_EQ(r.b->started(), 1u);
    int jumped = 0; for (std::size_t i = 0; i < r.b->count(); ++i) { const auto p = r.b->position(i); jumped += std::hypot(p.x - before[i].x, p.y - before[i].y) > 1.0f; }
    CHECK_EQ(jumped, 0);                                                // thrown from where it lay, no teleport
    h.tilt(400, 0.0f, 8.0f);
    double x1, y1; centre_of(*r.b, x1, y1);
    int high = 0; for (std::size_t i = 0; i < r.b->count(); ++i) high += r.b->position(i).y < 60.0f;
    std::printf("     the cloud's middle rose %.1f px in 0.4 s, %d particles above the pile\n", y0 - y1, high);
    CHECK(y0 - y1 > 15.0);                                              // thrown up off the floor, into the band
    CHECK(high > 200);                                                  // where no block of the pile was (it lay below y 60)
    CHECK(in_band(*r.b));
    h.tilt(6000, 0.0f, 8.0f);                                            // the hand keeps moving: it falls and piles again
    CHECK(r.b->phase() == Phase::Drift); CHECK(r.b->resting() * 100 >= r.b->count() * 95);
    int frames = 0; while (r.b->active() && frames++ < 200) h.hold();   // held still: the face comes back
    CHECK(!r.b->active()); CHECK(frames >= 65 && frames <= 68);         // 0.6 s calm + 2.0 s reform (+ the landed frame)
}

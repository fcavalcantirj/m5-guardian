// G16: Very good portrait motion checks (host, deterministic). G16A: the art is
// the upright 135x160 crop of the accepted G15 v2 master
// (art/persona/v2/portrait/VeryGood_portrait.rgb565, built by build_assets.py
// portrait); the panel is 135x240 with text below the face zone. Nothing here
// is radio evidence.
#include "check.hpp"
#include "persona.hpp"
#include "sha256.hpp"
#include <array>
#include <cmath>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <string>

using namespace guardian;
using namespace guardian::companion::persona;
using guardian::fixtures::sha256_hex;

namespace {
std::vector<std::uint8_t> load_art() {
    std::vector<std::uint8_t> out;
    std::FILE* f = std::fopen(GUARDIAN_ART_DIR "/portrait/VeryGood_portrait.rgb565", "rb");
    if (!f) return out;
    out.resize(art_bytes);
    if (std::fread(out.data(), 1, art_bytes, f) != art_bytes) out.clear();
    std::fclose(f);
    return out;
}
std::uint16_t art_px(const std::vector<std::uint8_t>& a, int x, int y) {
    const auto i = (static_cast<std::size_t>(y) * art_w + static_cast<std::size_t>(x)) * 2;
    return static_cast<std::uint16_t>(a[i] | (a[i + 1] << 8));
}
constexpr int panel_w = 135, panel_h = 240;   // upright StickS3
struct Shot {
    std::array<std::uint16_t, panel_w * panel_h> px{};
    Canvas canvas;
    explicit Shot(bool big_endian) : canvas(px.data(), panel_w, panel_h, big_endian) { canvas.clear(rgb565(1, 2, 3)); }
    std::uint16_t at(int x, int y) const { return canvas.get(x, y); }
};
int ch_r(std::uint16_t c) { return (c >> 11) & 31; }
int ch_g(std::uint16_t c) { return (c >> 5) & 63; }
int ch_b(std::uint16_t c) { return c & 31; }
bool inside(const Rect& r, int x, int y) { return x >= r.x0 && x < r.x1 && y >= r.y0 && y < r.y1; }
// Glowing cyan eyes of the portrait (measured on VeryGood_portrait.rgb565).
constexpr Rect eyes{36, 50, 100, 70};
}

GUARDIAN_CASE(portrait_art_is_the_upright_face_zone) {
    CHECK_EQ(art_w, 135); CHECK_EQ(art_h, 160); CHECK_EQ(portrait_w, 135);
    CHECK_EQ(art_bytes, std::size_t{43200});
    // Smoke stays left of the eyes and inside the face zone; the ember sits on the art.
    CHECK(smoke_zone.x1 <= eyes.x0 || smoke_zone.y1 <= eyes.y0 || smoke_zone.y0 >= eyes.y1);
    CHECK(smoke_zone.x0 >= 0 && smoke_zone.y0 >= 0 && smoke_zone.x1 <= art_w && smoke_zone.y1 <= art_h);
    CHECK(inside(smoke_zone, static_cast<int>(cigar_tip.x) - 3, static_cast<int>(cigar_tip.y) - 5));
}

GUARDIAN_CASE(tuned_motion_is_applied_and_zero_motion_is_still) {
    Motion still{}; still.tilt_max_deg = 0; still.breath_amount = 0;
    for (Millis t = 0; t < loop_ms; t += 500) {
        const auto p = pose_at(t, still);
        CHECK(std::fabs(p.tilt_deg) < 1e-6f); CHECK(std::fabs(p.scale - 1.0f) < 1e-6f);
    }
    Motion big{}; big.tilt_max_deg = 2.0f;
    float m = 0; for (Millis t = 0; t < loop_ms; t += 50) m = std::fmax(m, std::fabs(pose_at(t, big).tilt_deg));
    CHECK(m > 1.9f && m <= 2.0001f);
    const auto art = load_art(); CHECK_EQ(art.size(), art_bytes); if (art.size() != art_bytes) return;
    Motion no_smoke{}; no_smoke.smoke_alpha = 0;
    Shot a(false), b(false);
    paint_very_good(a.canvas, art.data(), 1000, Layers{true, false, true}, no_smoke);
    paint_very_good(b.canvas, art.data(), 1000, Layers{true, false, false}, no_smoke);
    int differing = 0;
    for (int y = 0; y < panel_h; ++y) for (int x = 0; x < panel_w; ++x) if (a.at(x, y) != b.at(x, y)) ++differing;
    CHECK_EQ(differing, 0);
}

GUARDIAN_CASE(art_matches_the_documented_size_and_cigar_anchor) {
    const auto art = load_art();
    CHECK_EQ(art.size(), art_bytes);
    if (art.size() != art_bytes) return;
    // The documented cigar tip must sit on the warm orange ember of the real frame.
    const auto p = art_px(art, static_cast<int>(cigar_tip.x), static_cast<int>(cigar_tip.y));
    CHECK(ch_r(p) >= 22);                       // 5-bit red high
    CHECK(ch_g(p) >= 20 && ch_g(p) <= 45);      // orange, not white
    CHECK(ch_b(p) <= 8);                        // little blue
}

GUARDIAN_CASE(pose_is_gentle_and_loops_exactly) {
    CHECK(std::fabs(pose_at(0).tilt_deg) < 1e-6f); CHECK(std::fabs(pose_at(0).scale - 1.0f) < 1e-6f);
    float max_tilt = 0, max_scale = 0;
    for (Millis t = 0; t < loop_ms; t += 50) {
        const auto p = pose_at(t);
        max_tilt = std::fmax(max_tilt, std::fabs(p.tilt_deg)); max_scale = std::fmax(max_scale, std::fabs(p.scale - 1.0f));
        const auto q = pose_at(t + loop_ms);
        CHECK(std::fabs(p.tilt_deg - q.tilt_deg) < 1e-4f); CHECK(std::fabs(p.scale - q.scale) < 1e-5f);
    }
    CHECK(max_tilt > 0.9f && max_tilt <= 1.2001f);     // visible but gentle
    CHECK(max_scale > 0.006f && max_scale <= 0.0081f); // subtle breathing
}

GUARDIAN_CASE(neutral_pose_copies_the_art_exactly_in_both_byte_orders) {
    const auto art = load_art(); CHECK_EQ(art.size(), art_bytes); if (art.size() != art_bytes) return;
    for (bool big : {false, true}) {
        Shot s(big);
        paint_very_good(s.canvas, art.data(), 0, Layers{true, false, false});
        int differing = 0;
        for (int y = 0; y < art_h; ++y) for (int x = 0; x < portrait_w; ++x) if (s.at(x, y) != art_px(art, x, y)) ++differing;
        CHECK_EQ(differing, 0);
    }
}

GUARDIAN_CASE(information_zone_is_never_touched) {
    const auto art = load_art(); CHECK_EQ(art.size(), art_bytes); if (art.size() != art_bytes) return;
    for (Millis t = 0; t < loop_ms; t += 1750) {
        Shot s(false); paint_very_good(s.canvas, art.data(), t);
        int touched = 0;
        for (int y = art_h; y < panel_h; ++y) for (int x = 0; x < panel_w; ++x) if (s.at(x, y) != rgb565(1, 2, 3)) ++touched;
        CHECK_EQ(touched, 0);
    }
}

GUARDIAN_CASE(head_tilt_and_breathing_move_the_portrait) {
    const auto art = load_art(); CHECK_EQ(art.size(), art_bytes); if (art.size() != art_bytes) return;
    Shot a(false), b(false);
    paint_very_good(a.canvas, art.data(), 0, Layers{true, false, false});
    paint_very_good(b.canvas, art.data(), 1750, Layers{true, false, false});   // quarter tilt period, near peak breath
    int differing = 0;
    for (int y = 0; y < art_h; ++y) for (int x = 0; x < portrait_w; ++x) if (a.at(x, y) != b.at(x, y)) ++differing;
    CHECK(differing > 200);
    // ...but the face stays recognisable: the pose is small enough that the eye/mouth anchors move < 3 px.
    const auto m = map_point(pose_at(1750), Point{48.0f, 60.0f});
    CHECK(std::fabs(m.x - 48.0f) < 3.0f && std::fabs(m.y - 60.0f) < 3.0f);
    const auto tip = map_point(pose_at(1750), cigar_tip);
    CHECK(std::fabs(tip.x - cigar_tip.x) < 3.0f && std::fabs(tip.y - cigar_tip.y) < 3.0f);
}

GUARDIAN_CASE(smoke_is_a_small_visible_loop_that_never_covers_eyes_or_text) {
    const auto art = load_art(); CHECK_EQ(art.size(), art_bytes); if (art.size() != art_bytes) return;
    for (Millis t = 0; t < 4000; t += 250) {
        Shot with(false), without(false);
        paint_very_good(with.canvas, art.data(), t, Layers{true, false, true});
        paint_very_good(without.canvas, art.data(), t, Layers{true, false, false});
        int changed = 0, outside = 0, in_eyes = 0;
        for (int y = 0; y < panel_h; ++y) for (int x = 0; x < panel_w; ++x) {
            if (with.at(x, y) == without.at(x, y)) continue;
            ++changed; if (!inside(smoke_zone, x, y)) ++outside; if (inside(eyes, x, y)) ++in_eyes;
        }
        CHECK(changed >= 12);            // always visible somewhere along the curl
        CHECK(changed <= 800);           // small: under 4 % of the 135x160 face zone
        CHECK_EQ(outside, 0); CHECK_EQ(in_eyes, 0);
    }
    // loops: the frame one full smoke period later is identical.
    Shot a(false), b(false);
    paint_very_good(a.canvas, art.data(), 1000, Layers{true, false, true});
    paint_very_good(b.canvas, art.data(), 1000 + loop_ms, Layers{true, false, true});
    int differing = 0;
    for (int y = 0; y < art_h; ++y) for (int x = 0; x < art_w; ++x) if (a.at(x, y) != b.at(x, y)) ++differing;
    CHECK_EQ(differing, 0);
}

GUARDIAN_CASE(smoke_moves_over_time) {
    const auto art = load_art(); CHECK_EQ(art.size(), art_bytes); if (art.size() != art_bytes) return;
    Shot a(false), b(false);
    paint_very_good(a.canvas, art.data(), 0, Layers{false, false, true});
    paint_very_good(b.canvas, art.data(), 1000, Layers{false, false, true});
    int differing = 0;
    for (int y = 0; y < art_h; ++y) for (int x = 0; x < art_w; ++x) if (a.at(x, y) != b.at(x, y)) ++differing;
    CHECK(differing > 10);
}

GUARDIAN_CASE(ember_glow_is_restrained_local_and_pulses) {
    const auto art = load_art(); CHECK_EQ(art.size(), art_bytes); if (art.size() != art_bytes) return;
    int lo = 1 << 20, hi = 0;
    for (Millis t = 0; t < 2400; t += 200) {
        Shot with(false), without(false);
        paint_very_good(with.canvas, art.data(), t, Layers{true, true, false});
        paint_very_good(without.canvas, art.data(), t, Layers{true, false, false});
        const auto tip = map_point(pose_at(t), cigar_tip);
        int changed = 0, far = 0, strongest = 0, sum = 0;
        for (int y = 0; y < art_h; ++y) for (int x = 0; x < art_w; ++x) {
            const auto p = with.at(x, y), q = without.at(x, y);
            if (p == q) continue;
            ++changed;
            if (std::hypot(static_cast<float>(x) - tip.x, static_cast<float>(y) - tip.y) > 9.5f) ++far;
            // at most a modest brightening step per channel (5/6-bit units)
            strongest = std::max({strongest, ch_r(p) - ch_r(q), (ch_g(p) - ch_g(q)) / 2, ch_b(p) - ch_b(q)});
            sum += ch_r(p) + ch_g(p) / 2 + ch_b(p) - ch_r(q) - ch_g(q) / 2 - ch_b(q);
        }
        CHECK(changed > 0); CHECK_EQ(far, 0); CHECK(strongest <= 11);
        lo = std::min(lo, sum); hi = std::max(hi, sum);
    }
    CHECK(hi > lo);   // the glow pulses
}

// ---- G16C: every rating, ALERT pulses, the no-data silhouette, placement -------
namespace {
const char* const portrait_names[16] = {"VeryGood", "Good", "Medium", "Bad", "Horrible",
    "VeryGood_ALERT_p0", "VeryGood_ALERT_p1", "Good_ALERT_p0", "Good_ALERT_p1", "Medium_ALERT_p0", "Medium_ALERT_p1",
    "Bad_ALERT_p0", "Bad_ALERT_p1", "Horrible_ALERT_p0", "Horrible_ALERT_p1", "NoData"};
std::vector<std::uint8_t> load_named(const char* name) {
    char path[512]; std::snprintf(path, sizeof path, GUARDIAN_ART_DIR "/portrait/%s_portrait.rgb565", name);
    std::vector<std::uint8_t> out; std::FILE* f = std::fopen(path, "rb"); if (!f) return out;
    out.resize(art_bytes + 1);
    const auto n = std::fread(out.data(), 1, out.size(), f); std::fclose(f);
    out.resize(n); return out;   // a wrong size stays visible
}
// The manifest's recorded sha256 for portrait/<name>_portrait.rgb565 (64 hex chars, empty when absent).
std::string manifest_sha(const char* name) {
    std::FILE* f = std::fopen(GUARDIAN_ART_DIR "/manifest.json", "rb"); if (!f) return {};
    std::string text; char buf[4096]; std::size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) text.append(buf, n);
    std::fclose(f);
    const std::string key = std::string("\"portrait/") + name + "_portrait.rgb565\": \"";
    const auto at = text.find(key); if (at == std::string::npos) return {};
    return text.substr(at + key.size(), 64);
}
}

GUARDIAN_CASE(all_sixteen_portraits_exist_at_size_and_match_the_manifest) {
    CHECK_EQ(sha256_hex({'a', 'b', 'c'}), std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    std::size_t total = 0;
    for (const char* name : portrait_names) {
        const auto a = load_named(name);
        CHECK_EQ(a.size(), art_bytes); total += a.size();
        const auto want = manifest_sha(name);
        CHECK_EQ(want.size(), std::size_t{64});
        if (a.size() == art_bytes && want.size() == 64 && sha256_hex(a) != want) { std::printf("     sha mismatch: %s\n", name); CHECK(false); }
    }
    CHECK_EQ(total, std::size_t{16} * 43200);
    CHECK_EQ(manifest_sha("VeryGood"), std::string("c203eceaa77e35e3000e57fe6db39b80482d08c393fd9a21227554d88493fcc7"));   // G16Q part 2: candidate D (linear light, unsharp 0.6/120/1, Floyd-Steinberg), owner pick 2026-11-18
}

GUARDIAN_CASE(art_set_is_complete_only_with_every_frame_and_unknown_has_no_rated_face) {
    ArtSet s; CHECK(!s.complete());
    static const std::uint8_t dummy[2] = {0, 0};
    for (std::size_t i = 0; i < 5; ++i) { s.rated[i] = dummy; s.alert[i] = {dummy, dummy}; }
    CHECK(!s.complete()); s.no_data = dummy; CHECK(s.complete());
    s.alert[3][1] = nullptr; CHECK(!s.complete());
    CHECK_EQ(rated_index(Mood::VeryGood), 0); CHECK_EQ(rated_index(Mood::Horrible), 4); CHECK_EQ(rated_index(Mood::Unknown), -1);
    CHECK_EQ(alert_pulse(0), 0); CHECK_EQ(alert_pulse(alert_pulse_ms), 1); CHECK_EQ(alert_pulse(2 * alert_pulse_ms + 1), 0);
}

GUARDIAN_CASE(no_data_silhouette_carries_no_expression) {
    const auto nd = load_named("NoData"); CHECK_EQ(nd.size(), art_bytes); if (nd.size() != art_bytes) return;
    std::vector<std::uint16_t> colours;
    for (int y = 0; y < art_h; ++y) for (int x = 0; x < art_w; ++x) {
        const auto p = art_px(nd, x, y);
        if (std::find(colours.begin(), colours.end(), p) == colours.end()) colours.push_back(p);
        CHECK(ch_r(p) <= 8 && ch_g(p) <= 20 && ch_b(p) <= 12);   // dim: never a bright eye or a lit face
    }
    CHECK(colours.size() <= 4);                                     // flat fill + rim + background: no features
    for (int i = 0; i < 5; ++i) {                                   // and it is none of the rated faces
        const auto r = load_named(portrait_names[i]); if (r.size() != art_bytes) continue;
        int same = 0; for (std::size_t b = 0; b < art_bytes; b += 2) same += (r[b] == nd[b] && r[b + 1] == nd[b + 1]);
        CHECK(same < static_cast<int>(art_bytes / 2) * 6 / 10);
    }
}

GUARDIAN_CASE(portrait_paints_only_its_band_at_any_placement) {
    const auto art = load_named("Bad"); CHECK_EQ(art.size(), art_bytes); if (art.size() != art_bytes) return;
    const Placement placements[] = {{20, 0, 0, 0}, {20, 4, -4, 5}, {20, -4, 4, -5}};
    for (const auto& at : placements) {
        Shot s(false); paint_portrait(s.canvas, art.data(), 1234, at, Layers{}, Motion{}, false);
        int outside = 0;
        for (int y = 0; y < panel_h; ++y) for (int x = 0; x < panel_w; ++x)
            if ((y < at.origin_y || y >= at.origin_y + art_h) && s.at(x, y) != rgb565(1, 2, 3)) ++outside;
        CHECK_EQ(outside, 0);
    }
    // Identity placement at the face-zone origin is an exact copy, 20 rows down.
    Shot s(false); Motion still{}; still.tilt_max_deg = 0; still.breath_amount = 0;
    paint_portrait(s.canvas, art.data(), 0, Placement{20, 0, 0, 0}, Layers{true, false, false}, still, false);
    int differing = 0;
    for (int y = 0; y < art_h; ++y) for (int x = 0; x < art_w; ++x) if (s.at(x, y + 20) != art_px(art, x, y)) ++differing;
    CHECK_EQ(differing, 0);
    // An integer IMU shift moves the picture by exactly that many pixels.
    Shot m(false); paint_portrait(m.canvas, art.data(), 0, Placement{20, 3, 2, 0}, Layers{true, false, false}, still, false);
    differing = 0;
    for (int y = 0; y + 2 < art_h; ++y) for (int x = 0; x + 3 < art_w; ++x) if (m.at(x + 3, y + 22) != art_px(art, x, y)) ++differing;
    CHECK_EQ(differing, 0);
}

// Review 2026-11-17 (owner: IMU "weird on its edges"): the hood fills the panel edge to edge, so a
// moving face is pulled back (scaled down) to keep it inside the glass instead of chopping it.
GUARDIAN_CASE(a_pulled_back_portrait_stays_inside_the_glass) {
    std::vector<std::uint8_t> art(art_bytes);
    const std::uint16_t c = rgb565(40, 60, 20);
    for (std::size_t i = 0; i < art_bytes; i += 2) { art[i] = c & 0xff; art[i + 1] = c >> 8; }
    Motion still{}; still.tilt_max_deg = 0; still.breath_amount = 0;
    Shot s(false);
    Placement back{20, 0, 0, 0}; back.scale = 0.9f;
    paint_portrait(s.canvas, art.data(), 0, back, Layers{true, false, false}, still, false);
    // ~6.75 px margin each side at 0.9: the outer columns of the band are black, the centre is the art.
    for (int y = 40; y < 150; ++y) {
        CHECK_EQ(s.at(0, y), rgb565(0, 0, 0)); CHECK_EQ(s.at(art_w - 1, y), rgb565(0, 0, 0));
        CHECK_EQ(s.at(art_w / 2, y), c);
    }
    // scale 1 is today's exact copy (default)
    Shot one(false); paint_portrait(one.canvas, art.data(), 0, Placement{20, 0, 0, 0}, Layers{true, false, false}, still, false);
    CHECK_EQ(one.at(0, 60), c);
    // map_point (ember, smoke) follows the scaled face: the centre stays put, the edges move inward
    Pose p0 = pose_with(0, still, Placement{20, 0, 0, 0}), p1 = pose_with(0, still, back);
    const Point e0 = map_point(p0, {0, 80}), e1 = map_point(p1, {0, 80});
    CHECK(e1.x > e0.x + 5.0f);
}

GUARDIAN_CASE(only_the_cigar_portrait_gets_ember_and_smoke_and_they_follow_the_face) {
    const auto vg = load_named("VeryGood"); CHECK_EQ(vg.size(), art_bytes); if (vg.size() != art_bytes) return;
    Shot plain(false), cig(false);
    paint_portrait(plain.canvas, vg.data(), 1000, Placement{20, 0, 0, 0}, Layers{}, Motion{}, false);
    paint_portrait(cig.canvas, vg.data(), 1000, Placement{20, 0, 0, 0}, Layers{}, Motion{}, true);
    int differing = 0; for (int y = 0; y < panel_h; ++y) for (int x = 0; x < panel_w; ++x) differing += plain.at(x, y) != cig.at(x, y);
    CHECK(differing > 12);
    // With the IMU shift, ember pixels stay within 9.5 px of the shifted tip.
    Shot a(false), b(false); const Placement at{20, 4, -3, 0};
    paint_portrait(a.canvas, vg.data(), 600, at, Layers{true, true, false}, Motion{}, true);
    paint_portrait(b.canvas, vg.data(), 600, at, Layers{true, false, false}, Motion{}, true);
    auto tip = map_point(pose_with(600, Motion{}, at), cigar_tip); tip.y += 20;
    int far = 0, changed = 0;
    for (int y = 0; y < panel_h; ++y) for (int x = 0; x < panel_w; ++x) if (a.at(x, y) != b.at(x, y)) {
        ++changed; if (std::hypot(static_cast<float>(x) - tip.x, static_cast<float>(y) - tip.y) > 9.5f) ++far;
    }
    CHECK(changed > 0); CHECK_EQ(far, 0);
}

// ---- G16C rework (1): the warp is fast and skipped while the pose is still -------
// The board keeps the current portrait in fast RAM and the warped band beside it
// (persona::WarpCache). Painting through the cache must give exactly the same
// pixels as painting without it, and a frame whose quantized pose and art are
// unchanged must reuse the band instead of warping again.
namespace {
struct CacheRig {
    std::vector<std::uint16_t> source = std::vector<std::uint16_t>(art_pixels), band = std::vector<std::uint16_t>(art_pixels);
    WarpCache cache{source.data(), band.data()};
};
int differing(const Shot& a, const Shot& b) {
    int n = 0; for (int y = 0; y < panel_h; ++y) for (int x = 0; x < panel_w; ++x) n += a.at(x, y) != b.at(x, y);
    return n;
}
}
GUARDIAN_CASE(warp_cache_gives_identical_pixels_at_every_pose) {
    const auto vg = load_named("VeryGood"), bad = load_named("Bad");
    CHECK_EQ(vg.size(), art_bytes); CHECK_EQ(bad.size(), art_bytes); if (vg.size() != art_bytes || bad.size() != art_bytes) return;
    CacheRig rig; int bad_frames = 0;
    const Placement placements[] = {{20, 0, 0, 0}, {20, 2.5f, -1.25f, 3.7f}, {20, -4, 4, -5}, {0, 0.3f, 0.2f, 0.1f}};
    for (bool big : {false, true}) for (const auto& at : placements) for (Millis t = 0; t < 8000; t += 650)
        for (const auto* art : {&vg, &bad}) {
            Shot a(big), b(big);
            paint_portrait(a.canvas, art->data(), t, at, Layers{}, Motion{}, art == &vg);
            paint_portrait(b.canvas, art->data(), t, at, Layers{}, Motion{}, art == &vg, &rig.cache);
            if (differing(a, b)) ++bad_frames;
        }
    CHECK_EQ(bad_frames, 0);
}
GUARDIAN_CASE(warp_cache_reuses_the_band_while_the_quantized_pose_is_unchanged) {
    const auto vg = load_named("VeryGood"), good = load_named("Good");
    CHECK_EQ(vg.size(), art_bytes); if (vg.size() != art_bytes || good.size() != art_bytes) return;
    CacheRig rig; Motion still{}; still.tilt_max_deg = 0; still.breath_amount = 0;
    Shot s(true);
    for (int i = 0; i < 10; ++i) paint_portrait(s.canvas, vg.data(), static_cast<Millis>(40 * i), Placement{20, 0, 0, 0}, Layers{}, still, true, &rig.cache);
    CHECK_EQ(rig.cache.warps, 1u); CHECK_EQ(rig.cache.reuses, 9u); CHECK_EQ(rig.cache.copies, 1u);   // ember/smoke still animate on top
    // Another portrait: copied once into fast RAM, warped once.
    for (int i = 0; i < 5; ++i) paint_portrait(s.canvas, good.data(), 400, Placement{20, 0, 0, 0}, Layers{}, still, false, &rig.cache);
    CHECK_EQ(rig.cache.copies, 2u); CHECK_EQ(rig.cache.warps, 2u); CHECK_EQ(rig.cache.reuses, 13u);
    // A real move (IMU shift) warps again; a sub-quantum change does not.
    paint_portrait(s.canvas, good.data(), 400, Placement{20, 1.0f, 0, 0}, Layers{}, still, false, &rig.cache);
    CHECK_EQ(rig.cache.warps, 3u);
    paint_portrait(s.canvas, good.data(), 400, Placement{20, 1.01f, 0, 0}, Layers{}, still, false, &rig.cache);
    CHECK_EQ(rig.cache.warps, 3u);
    // Idle breathing at rest at 25 fps: most frames reuse the band (power and time).
    CacheRig r2; Shot b(true); Motion device{}; device.tilt_max_deg = 0;   // the StickS3 default (TUNE persona.sway_deg = 0)
    for (int i = 0; i < 100; ++i) paint_portrait(b.canvas, good.data(), static_cast<Millis>(40 * i), Placement{20, 0, 0, 0}, Layers{}, device, false, &r2.cache);
    CHECK(r2.cache.warps < 60u); CHECK(r2.cache.warps > 10u);
}
GUARDIAN_CASE(quantized_warp_keeps_the_motion_visible_and_gentle) {
    const auto art = load_named("Medium"); CHECK_EQ(art.size(), art_bytes); if (art.size() != art_bytes) return;
    // Over one breathing cycle the band changes (breathing still visible) ...
    Shot a(false), b(false);
    paint_portrait(a.canvas, art.data(), 0, Placement{20, 0, 0, 0}, Layers{}, Motion{}, false);
    paint_portrait(b.canvas, art.data(), 1000, Placement{20, 0, 0, 0}, Layers{}, Motion{}, false);
    CHECK(differing(a, b) > 200);
    // ... and a quantized pose never differs from its exact pose by a visible amount:
    // each output pixel is within a small per-channel distance of the full-precision warp.
    int far = 0;
    for (Millis t = 0; t < 7000; t += 333) {
        Shot q(false); paint_portrait(q.canvas, art.data(), t, Placement{20, 1.3f, -0.7f, 2.2f}, Layers{}, Motion{}, false);
        Shot r(false); paint_portrait_reference(r.canvas, art.data(), t, Placement{20, 1.3f, -0.7f, 2.2f});
        for (int y = 20; y < 180; ++y) for (int x = 0; x < panel_w; ++x) {
            const auto u = q.at(x, y), v = r.at(x, y);
            if (std::abs(ch_r(u) - ch_r(v)) > 6 || std::abs(ch_g(u) - ch_g(v)) > 12 || std::abs(ch_b(u) - ch_b(v)) > 6) ++far;
        }
    }
    CHECK(far < 40);   // only isolated edge pixels of hard outlines may move by a quantum
}

// ---- G16I: the hood box (upright fit), public pixel sources, what the cache holds ----
GUARDIAN_CASE(hood_of_every_rated_and_alert_portrait_lies_inside_the_documented_box) {
    CHECK_EQ(hood_w, 133); CHECK_EQ(hood_h, 157);   // G16Q part 2: re-measured on the candidate D frames
    CHECK_EQ(hood_box.x1 - hood_box.x0, hood_w); CHECK_EQ(hood_box.y1 - hood_box.y0, hood_h);
    for (int n = 0; n < 15; ++n) {   // the 5 rated and 10 ALERT frames (NoData is a wider silhouette)
        const auto a = load_named(portrait_names[n]); CHECK_EQ(a.size(), art_bytes); if (a.size() != art_bytes) continue;
        // The hood = the longest run of consecutive lit rows (Good and VeryGood carry 1..6 detached
        // specks on rows 158..159, MEASURED 2026-11-17; they are counted, not hidden). G16Q part 2 (candidate D,
        // dithered, MEASURED 2026-11-19): Good carries 10 specks on rows 157..159, columns 63..69; VeryGood 1.
        int best0 = 0, best1 = -1, run0 = -1, stray = 0, x0 = art_w, x1 = -1;
        for (int y = 0; y <= art_h; ++y) {
            bool lit = false;
            if (y < art_h) for (int x = 0; x < art_w; ++x) if (art_px(a, x, y)) { lit = true; x0 = std::min(x0, x); x1 = std::max(x1, x); }
            if (lit && run0 < 0) run0 = y;
            if (!lit && run0 >= 0) { if (y - 1 - run0 > best1 - best0) { best0 = run0; best1 = y - 1; } run0 = -1; }
        }
        for (int y = 0; y < art_h; ++y) for (int x = 0; x < art_w; ++x)
            if (art_px(a, x, y) && (x < hood_box.x0 || x >= hood_box.x1 || y < hood_box.y0 || y >= hood_box.y1)) ++stray;
        const bool ok = x0 >= hood_box.x0 && x1 < hood_box.x1 && best0 >= hood_box.y0 && best1 < hood_box.y1 && stray <= 10;
        if (!ok) std::printf("     %s: columns %d..%d hood rows %d..%d stray %d\n", portrait_names[n], x0, x1, best0, best1, stray);
        CHECK(ok);
    }
}

GUARDIAN_CASE(fit_scale_keeps_the_hood_box_inside_the_band_at_every_angle) {
    CHECK_EQ(fit_scale(0.0f), 1.0f);                       // standing: today's exact placement
    CHECK(std::fabs(fit_scale(45.0f) - 0.66f) < 0.02f); CHECK(std::fabs(fit_scale(90.0f) - 0.85f) < 0.02f);
    CHECK(std::fabs(fit_scale(180.0f) - 1.0f) < 0.05f);
    int outside = 0, slack = 0;
    for (int i = -720; i <= 720; ++i) {
        const float deg = static_cast<float>(i) * 0.5f, s = fit_scale(deg);
        if (!(s > 0.6f && s <= 1.0f)) ++outside;
        float reach = 0;   // how close the turned box comes to the band (1 = touching an edge)
        for (int k = 0; k < 4; ++k) {
            const auto p = map_point(Pose{deg, s, 0, 0}, Point{static_cast<float>(k & 1 ? hood_box.x1 : hood_box.x0), static_cast<float>(k & 2 ? hood_box.y1 : hood_box.y0)});
            if (p.x < -0.01f || p.x > static_cast<float>(art_w) + 0.01f || p.y < -0.01f || p.y > static_cast<float>(art_h) + 0.01f) ++outside;
            reach = std::fmax(reach, std::fmax(std::fmax((pivot.x - p.x) / pivot.x, (p.x - pivot.x) / (art_w - pivot.x)),
                                               std::fmax((pivot.y - p.y) / pivot.y, (p.y - pivot.y) / (art_h - pivot.y))));
        }
        if (s < 1.0f && reach < 0.999f) ++slack;           // never smaller than needed
    }
    CHECK_EQ(outside, 0); CHECK_EQ(slack, 0);
}

GUARDIAN_CASE(warp_cache_exposes_the_decoded_source_and_its_art) {
    const auto vg = load_named("VeryGood"), bad = load_named("Bad");
    CHECK_EQ(vg.size(), art_bytes); CHECK_EQ(bad.size(), art_bytes); if (vg.size() != art_bytes || bad.size() != art_bytes) return;
    CacheRig rig; Shot s(true);
    CHECK(rig.cache.art() == nullptr); CHECK(!rig.cache.source().valid());
    paint_portrait(s.canvas, vg.data(), 0, Placement{20, 0, 0, 0}, Layers{}, Motion{}, true, &rig.cache);
    CHECK(rig.cache.art() == vg.data()); CHECK(rig.cache.source().valid());
    const PixelSource native = rig.cache.source(), bytes{nullptr, vg.data()};
    int differing_px = 0;
    for (int y = 0; y < art_h; ++y) for (int x = 0; x < art_w; ++x)
        differing_px += native.at(x, y) != art_px(vg, x, y) || bytes.at(x, y) != art_px(vg, x, y);
    CHECK_EQ(differing_px, 0);
    paint_portrait(s.canvas, bad.data(), 0, Placement{20, 0, 0, 0}, Layers{}, Motion{}, false, &rig.cache);
    CHECK(rig.cache.art() == bad.data()); CHECK_EQ(rig.cache.source().at(60, 80), art_px(bad, 60, 80));
    rig.cache.invalidate(); CHECK(rig.cache.art() == nullptr); CHECK(!rig.cache.source().valid());
}

// G21: the 3D head's frame sets and frame choice (adapters/companion/head3d.*), host only.
// Synthetic packs (tests/support/head_pack.hpp: flat frames in stored blocks) pin the rules; the
// SHIPPED packs (art/persona/v3/frames, built by tools/face3d/pack_frames.py) are inflated frame by
// frame with the device's inflater and compared with the manifest's sha256. Nothing here is radio
// evidence, and nothing here proves the frame rate on the StickS3.
#include "check.hpp"
#include "head3d.hpp"
#include "head_pack.hpp"
#include "motion.hpp"
#include "sha256.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace guardian::companion;
using namespace guardian::companion::head3d;
using guardian::fixtures::PackSpec;
using guardian::fixtures::make_pack;
using Bytes = std::vector<std::uint8_t>;

namespace {
struct Rig {
    Bytes a = Bytes(persona::art_bytes), b = Bytes(persona::art_bytes);
    std::unique_ptr<Head> head{new Head(a.data(), b.data())};
    std::vector<Bytes> packs;   // kept alive: the Head points into them, as it points into flash
    PackError add(const PackSpec& s) { packs.push_back(make_pack(s)); return head->add(packs.back().data(), packs.back().size()); }
    PackError add_bytes(Bytes p) { packs.push_back(std::move(p)); return head->add(packs.back().data(), packs.back().size()); }
    Rig() { Params p; p.on = true; p.yaw_gain = 1; p.pitch_gain = 1; head->configure(p); }   // plain angles unless a case says otherwise
};
std::uint16_t first_px(const std::uint8_t* art) { return static_cast<std::uint16_t>(art[0] | (art[1] << 8)); }
bool all_px(const std::uint8_t* art, std::uint16_t colour) {
    for (std::size_t i = 0; i < persona::art_bytes; i += 2) if (art[i] != (colour & 0xff) || art[i + 1] != (colour >> 8)) return false;
    return true;
}
std::uint16_t colour(int mood, int yi, int pi) { return guardian::fixtures::head_colour(mood, yi, pi); }
PackSpec spec(int mood) { PackSpec s; s.mood = mood; return s; }
const std::int16_t grid5[5] = {-300, -150, 0, 150, 300};
std::string read_file(const std::string& path) {
    std::string out; std::FILE* f = std::fopen(path.c_str(), "rb"); if (!f) return out;
    char buf[65536]; std::size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.append(buf, n);
    std::fclose(f); return out;
}
const char* const mood_names[5] = {"VeryGood", "Good", "Medium", "Bad", "Horrible"};
}

// ---- the pack -------------------------------------------------------------------
GUARDIAN_CASE(a_well_formed_pack_is_parsed_with_its_grid_and_table) {
    PackSpec s = spec(2); s.yaw_tenths = {-300, -75, 0, 75, 300}; s.pitch_tenths = {-150, 150};
    const auto pack = make_pack(s);
    FrameSet set; CHECK(parse(pack.data(), pack.size(), set) == PackError::Ok);
    CHECK(set.valid()); CHECK_EQ(int(set.mood), 2); CHECK_EQ(int(set.yaw_count), 5); CHECK_EQ(int(set.pitch_count), 2);
    CHECK_EQ(set.frames(), std::size_t{10}); CHECK_EQ(int(set.yaw[1]), -75); CHECK_EQ(int(set.pitch[1]), 150);
    const auto first = set.entry(0, 0), last = set.entry(4, 1);
    CHECK_EQ(first.offset, static_cast<std::uint32_t>(header_bytes + 2 * 7 + entry_bytes * 10));
    CHECK_EQ(last.offset + last.size, static_cast<std::uint32_t>(pack.size()));
    CHECK_EQ(first.adler, guardian::fixtures::plain_adler32(guardian::fixtures::flat_frame(colour(2, 0, 0))));
    CHECK_EQ(std::string(pack_error_text(PackError::Ok)), std::string("ok"));
}

GUARDIAN_CASE(a_damaged_pack_is_refused_whole) {
    const auto good = make_pack(spec(1));
    FrameSet untouched; untouched.mood = 9;
    const auto refuse = [&](Bytes p, PackError want) {
        FrameSet s; s.mood = 9;
        const auto got = parse(p.data(), p.size(), s);
        return got == want && s.mood == 9 && !s.valid();   // refused for the stated reason, `out` untouched
    };
    CHECK(parse(nullptr, 100, untouched) == PackError::TooShort);
    CHECK(refuse(Bytes(good.begin(), good.begin() + 23), PackError::TooShort));
    { auto p = good; p[0] = 'X'; CHECK(refuse(p, PackError::Magic)); }
    { auto p = good; p[4] = 2; CHECK(refuse(p, PackError::Format)); }
    { auto p = good; p[6] = 5; CHECK(refuse(p, PackError::Mood)); }
    { auto p = good; p[8] = 134; CHECK(refuse(p, PackError::Geometry)); }
    { auto p = good; p[10] = 161; CHECK(refuse(p, PackError::Geometry)); }
    { auto p = good; p[12] = 0; CHECK(refuse(p, PackError::Grid)); }
    { auto p = good; p[13] = static_cast<std::uint8_t>(max_pitch + 1); CHECK(refuse(p, PackError::Grid)); }
    { auto p = good; guardian::fixtures::put16(p, 24 + 2, 0xfed4); CHECK(refuse(p, PackError::Grid)); }       // yaw -300, -300, 300: not ascending
    { auto p = good; guardian::fixtures::put16(p, 24 + 6 + 4, 0xff6a); CHECK(refuse(p, PackError::Grid)); }   // pitch -150, 0, -150
    { auto p = good; p.push_back(0); CHECK(refuse(p, PackError::Size)); }                                     // longer than it says
    { auto p = good; p.pop_back(); CHECK(refuse(p, PackError::Size)); }
    { auto p = good; guardian::fixtures::put32(p, 20, guardian::fixtures::get32(p, 20) + 1); CHECK(refuse(p, PackError::Table)); }
    const std::size_t table = guardian::fixtures::pack_table_offset(spec(1));
    { auto p = good; guardian::fixtures::put32(p, table + 4, guardian::fixtures::get32(p, table + 4) + 1); CHECK(refuse(p, PackError::Table)); }   // a stream overlaps the next
    { auto p = good; guardian::fixtures::put32(p, table + 12, guardian::fixtures::get32(p, table + 12) + 1); CHECK(refuse(p, PackError::Table)); } // a gap
    { auto p = good; guardian::fixtures::put32(p, table + 12 * 8 + 4, 0x7fffffffu); CHECK(refuse(p, PackError::Table)); }                           // the last stream runs past the file
    { auto p = good; guardian::fixtures::put32(p, table + 4, 0); CHECK(refuse(p, PackError::Table)); }                                              // an empty stream
    // A header that promises more table than the file holds.
    { Bytes p(good.begin(), good.begin() + 40); guardian::fixtures::put32(p, 16, 40); CHECK(refuse(p, PackError::Size)); }
}

// ---- one axis ---------------------------------------------------------------------
GUARDIAN_CASE(with_nothing_shown_the_nearest_frame_is_chosen) {
    CHECK_EQ(choose(grid5, 5, -1, 0.0f, 0.2f), 2); CHECK_EQ(choose(grid5, 5, -1, 7.4f, 0.2f), 2); CHECK_EQ(choose(grid5, 5, -1, 7.6f, 0.2f), 3);
    CHECK_EQ(choose(grid5, 5, -1, -29.0f, 0.2f), 0); CHECK_EQ(choose(grid5, 5, -1, 500.0f, 0.2f), 4); CHECK_EQ(choose(grid5, 5, -1, -500.0f, 0.2f), 0);
    CHECK_EQ(choose(grid5, 5, 9, 16.0f, 0.2f), 3);            // an index outside the grid counts as nothing shown
    CHECK_EQ(choose(grid5, 0, -1, 0.0f, 0.2f), -1); CHECK_EQ(choose(nullptr, 5, -1, 0.0f, 0.2f), -1);
    const std::int16_t one[1] = {0}; CHECK_EQ(choose(one, 1, -1, 99.0f, 0.2f), 0); CHECK_EQ(choose(one, 1, 0, -99.0f, 0.2f), 0);
}

GUARDIAN_CASE(a_frame_changes_only_past_the_boundary_by_the_hysteresis) {
    // Frames at 0 and 15 degrees: the midpoint is 7.5, hysteresis 0.2 x 15 = 3 degrees each side.
    CHECK_EQ(choose(grid5, 5, 2, 7.6f, 0.2f), 2); CHECK_EQ(choose(grid5, 5, 2, 10.4f, 0.2f), 2); CHECK_EQ(choose(grid5, 5, 2, 10.6f, 0.2f), 3);
    CHECK_EQ(choose(grid5, 5, 3, 7.4f, 0.2f), 3); CHECK_EQ(choose(grid5, 5, 3, 4.6f, 0.2f), 3); CHECK_EQ(choose(grid5, 5, 3, 4.4f, 0.2f), 2);
    CHECK_EQ(choose(grid5, 5, 2, -10.4f, 0.2f), 2); CHECK_EQ(choose(grid5, 5, 2, -10.6f, 0.2f), 1);
    // No hysteresis: the plain midpoint. More than 0.45 is treated as 0.45 (a frame must stay reachable).
    CHECK_EQ(choose(grid5, 5, 2, 7.6f, 0.0f), 3); CHECK_EQ(choose(grid5, 5, 2, 14.0f, 5.0f), 2); CHECK_EQ(choose(grid5, 5, 2, 14.5f, 5.0f), 3);
    CHECK_EQ(choose(grid5, 5, 2, 7.6f, -1.0f), 3);
    // A fast turn crosses several frames in one call; outside the grid the end frame is held.
    CHECK_EQ(choose(grid5, 5, 0, 29.0f, 0.2f), 4); CHECK_EQ(choose(grid5, 5, 4, -100.0f, 0.2f), 0); CHECK_EQ(choose(grid5, 5, 4, 100.0f, 0.2f), 4);
    // An unusable angle changes nothing.
    CHECK_EQ(choose(grid5, 5, 3, NAN, 0.2f), 3); CHECK_EQ(choose(grid5, 5, 1, INFINITY, 0.2f), 1); CHECK_EQ(choose(grid5, 5, -1, NAN, 0.2f), 2);
    // An uneven grid uses each gap's own midpoint and width.
    const std::int16_t uneven[3] = {-300, 0, 100};
    CHECK_EQ(choose(uneven, 3, 1, 6.9f, 0.2f), 1); CHECK_EQ(choose(uneven, 3, 1, 7.1f, 0.2f), 2);       // 5 + 0.2 x 10
    CHECK_EQ(choose(uneven, 3, 1, -20.9f, 0.2f), 1); CHECK_EQ(choose(uneven, 3, 1, -21.1f, 0.2f), 0);   // -15 - 0.2 x 30
}

GUARDIAN_CASE(an_angle_resting_on_a_boundary_never_flickers) {
    // The stick held exactly between two frames, with sensor noise smaller than the band (+-2 of +-3 degrees).
    for (const float centre : {7.5f, -7.5f, 22.5f, -22.5f}) {
        int index = choose(grid5, 5, -1, centre + 2.0f, 0.2f), changes = 0; std::uint32_t seed = 3;
        for (int i = 0; i < 5000; ++i) {
            seed = seed * 1664525u + 1013904223u;
            const float noise = (static_cast<float>(seed >> 8) / 16777216.0f - 0.5f) * 4.0f;
            const int next = choose(grid5, 5, index, centre + noise, 0.2f);
            changes += next != index; index = next;
        }
        CHECK_EQ(changes, 0);
    }
    // Without hysteresis the same noise does flip it: the rule above is what prevents the flicker.
    int index = 2, changes = 0; std::uint32_t seed = 3;
    for (int i = 0; i < 5000; ++i) {
        seed = seed * 1664525u + 1013904223u;
        const int next = choose(grid5, 5, index, 7.5f + (static_cast<float>(seed >> 8) / 16777216.0f - 0.5f) * 4.0f, 0.0f);
        changes += next != index; index = next;
    }
    CHECK(changes > 1000);
}

// ---- the head ---------------------------------------------------------------------
GUARDIAN_CASE(the_frame_for_the_pose_is_inflated_byte_for_byte) {
    Rig r; CHECK(r.add(spec(0)) == PackError::Ok);
    CHECK(r.head->has(0)); CHECK_EQ(int(r.head->sets()), 1); CHECK_EQ(int(r.head->frames()), 9); CHECK_EQ(r.head->shown_mood(), -1);
    const auto* centre = r.head->frame(0, 0.0f, 0.0f);
    CHECK(centre != nullptr);
    if (centre) CHECK(all_px(centre, colour(0, 1, 1)));
    CHECK_EQ(r.head->yaw_index(), 1); CHECK_EQ(r.head->pitch_index(), 1); CHECK_EQ(r.head->shown_mood(), 0); CHECK_EQ(r.head->inflates(), 1u);
    const auto* corner = r.head->frame(0, 30.0f, -15.0f);
    CHECK(corner != nullptr && corner != centre);                 // a new frame is a new pointer (the warp cache keys on it)
    if (corner) CHECK(all_px(corner, colour(0, 2, 0)));
    CHECK_EQ(r.head->inflates(), 2u); CHECK_EQ(r.head->failures(), 0u);
}

GUARDIAN_CASE(a_still_pose_inflates_nothing_and_keeps_its_pointer) {
    Rig r; r.add(spec(0));
    const auto* first = r.head->frame(0, 3.0f, 2.0f);
    for (int i = 0; i < 200; ++i) CHECK(r.head->frame(0, 3.0f + 0.01f * static_cast<float>(i % 7), 2.0f) == first);
    CHECK_EQ(r.head->inflates(), 1u); CHECK_EQ(r.head->reuses(), 0u);
}

GUARDIAN_CASE(going_back_to_the_previous_frame_reuses_the_other_buffer) {
    Rig r; r.add(spec(0));
    const auto* centre = r.head->frame(0, 0.0f, 0.0f);
    const auto* right = r.head->frame(0, 30.0f, 0.0f);
    const auto* back = r.head->frame(0, 0.0f, 0.0f);
    CHECK(back == centre); CHECK(right != centre);
    if (back) CHECK(all_px(back, colour(0, 1, 1)));
    CHECK_EQ(r.head->inflates(), 2u); CHECK_EQ(r.head->reuses(), 1u);
    const auto* up = r.head->frame(0, 0.0f, 15.0f);               // a third frame replaces the one not shown
    CHECK(up == right);
    if (up) CHECK(all_px(up, colour(0, 1, 2)));
    CHECK_EQ(r.head->inflates(), 3u);
}

GUARDIAN_CASE(gains_scale_and_mirror_the_pose) {
    Rig r; r.add(spec(0));
    Params p; p.on = true; p.yaw_gain = -1.0f; p.pitch_gain = 0.5f; r.head->configure(p);
    r.head->frame(0, 30.0f, 30.0f);
    CHECK_EQ(r.head->yaw_index(), 0); CHECK_EQ(r.head->pitch_index(), 2);      // yaw mirrored, pitch 15
    r.head->frame(0, -30.0f, 10.0f);
    CHECK_EQ(r.head->yaw_index(), 2); CHECK_EQ(r.head->pitch_index(), 2);      // pitch 5 degrees: above 7.5 - 3, the +15 frame stays
    r.head->frame(0, -30.0f, 8.0f);
    CHECK_EQ(r.head->pitch_index(), 1);                                        // pitch 4 degrees: past the band, the 0 frame
    p.yaw_gain = 0.0f; p.pitch_gain = 0.0f; r.head->configure(p);              // 0 = that axis never leaves the middle
    r.head->frame(0, 30.0f, 30.0f);
    CHECK_EQ(r.head->yaw_index(), 1); CHECK_EQ(r.head->pitch_index(), 1);
    const Params d{};
    CHECK(!d.on);   // owner 2026-11-18: off by default, the approved 2D portrait shows
    CHECK(d.yaw_gain >= gain_range.lo && d.yaw_gain <= gain_range.hi);
    CHECK(d.pitch_gain >= gain_range.lo && d.pitch_gain <= gain_range.hi);
    CHECK(d.hysteresis >= hysteresis_range.lo && d.hysteresis <= hysteresis_range.hi);
}

GUARDIAN_CASE(a_mood_without_a_set_falls_back_to_the_2d_portrait) {
    Rig r; r.add(spec(2));
    CHECK(!r.head->has(0)); CHECK(r.head->has(2)); CHECK(r.head->set(0) == nullptr); CHECK(r.head->set(2) != nullptr);
    CHECK(r.head->frame(0, 0.0f, 0.0f) == nullptr);              // Very good has no 3D set: nullptr = the 2D portrait
    CHECK(r.head->frame(-1, 0.0f, 0.0f) == nullptr); CHECK(r.head->frame(5, 0.0f, 0.0f) == nullptr);   // Unknown has no face at all
    CHECK_EQ(r.head->inflates(), 0u);
    const auto* medium = r.head->frame(2, 0.0f, 0.0f);
    CHECK(medium != nullptr);
    if (medium) CHECK_EQ(first_px(medium), colour(2, 1, 1));
    // Two moods with sets: each shows its own frames.
    CHECK(r.add(spec(4)) == PackError::Ok); CHECK_EQ(int(r.head->sets()), 2); CHECK_EQ(int(r.head->frames()), 18);
    const auto* horrible = r.head->frame(4, -30.0f, 15.0f);
    CHECK(horrible != nullptr);
    if (horrible) CHECK_EQ(first_px(horrible), colour(4, 0, 2));
    CHECK_EQ(r.head->shown_mood(), 4);
}

GUARDIAN_CASE(switched_off_or_without_buffers_it_is_always_the_2d_portrait) {
    Rig r; r.add(spec(0));
    Params p; p.on = false; r.head->configure(p);
    CHECK(r.head->frame(0, 0.0f, 0.0f) == nullptr); CHECK_EQ(r.head->inflates(), 0u);
    p.on = true; r.head->configure(p);
    CHECK(r.head->frame(0, 0.0f, 0.0f) != nullptr);
    Bytes one(persona::art_bytes);
    const auto pack = make_pack(spec(0));
    Head none(nullptr, nullptr); CHECK(none.add(pack.data(), pack.size()) == PackError::Ok); CHECK(none.frame(0, 0.0f, 0.0f) == nullptr);
    Head half(one.data(), nullptr); half.add(pack.data(), pack.size()); CHECK(half.frame(0, 0.0f, 0.0f) == nullptr);
    Head same(one.data(), one.data()); same.add(pack.data(), pack.size()); CHECK(same.frame(0, 0.0f, 0.0f) == nullptr);   // one buffer twice is not two
    CHECK_EQ(none.inflates() + half.inflates() + same.inflates(), 0u);
}

GUARDIAN_CASE(a_second_pack_for_a_mood_or_a_bad_pack_is_refused_at_boot) {
    Rig r; CHECK(r.add(spec(3)) == PackError::Ok);
    PackSpec again = spec(3); again.yaw_tenths = {0};
    CHECK(r.add(again) == PackError::Duplicate);
    CHECK_EQ(int(r.head->set(3)->yaw_count), 3);                 // the first one stays
    auto bad = make_pack(spec(1)); bad[1] = 'h';
    CHECK(r.add_bytes(bad) == PackError::Magic); CHECK(!r.head->has(1)); CHECK_EQ(int(r.head->sets()), 1);
}

GUARDIAN_CASE(hold_keeps_the_frame_while_the_stick_moves) {
    Rig r; r.add(spec(0));
    const auto* centre = r.head->frame(0, 0.0f, 0.0f);
    for (float yaw = -30.0f; yaw <= 30.0f; yaw += 5.0f) CHECK(r.head->frame(0, yaw, 15.0f, true) == centre);   // a burst is in the air
    CHECK_EQ(r.head->inflates(), 1u); CHECK_EQ(r.head->yaw_index(), 1);
    const auto* after = r.head->frame(0, 30.0f, 15.0f);          // it landed: the head follows again
    CHECK(after != centre);
    if (after) CHECK(all_px(after, colour(0, 2, 2)));
    // Held on the 2D portrait (no set): it stays 2D, even once a set could answer.
    Rig n; n.add(spec(2));
    CHECK(n.head->frame(0, 0.0f, 0.0f) == nullptr); CHECK(n.head->frame(0, 0.0f, 0.0f, true) == nullptr);
    Params off; off.on = false; off.yaw_gain = 1; off.pitch_gain = 1; n.head->configure(off);
    CHECK(n.head->frame(2, 0.0f, 0.0f) == nullptr);
    off.on = true; n.head->configure(off);
    CHECK(n.head->frame(2, 0.0f, 0.0f, true) == nullptr);        // the burst began on the 2D face: it keeps it
    CHECK(n.head->frame(2, 0.0f, 0.0f) != nullptr);
    // Hold is per mood: another mood's first frame is chosen normally.
    CHECK(r.add(spec(1)) == PackError::Ok);
    const auto* good = r.head->frame(1, 0.0f, 0.0f, true);
    CHECK(good != nullptr);
    if (good) CHECK_EQ(first_px(good), colour(1, 1, 1));
}

GUARDIAN_CASE(a_frame_that_fails_is_never_shown_and_its_set_is_dropped) {
    // (a) a corrupt stream, (b) a stream that inflates to the wrong size, (c) right size, wrong bytes (adler32).
    for (int kind = 0; kind < 3; ++kind) {
        Rig r;
        PackSpec s = spec(0);
        auto pack = make_pack(s);
        const std::size_t table = guardian::fixtures::pack_table_offset(s), right = table + 12 * (1 * 3 + 2);   // yaw 30, pitch 0
        const std::size_t stream = guardian::fixtures::get32(pack, right);
        if (kind == 0) pack[stream] = 0x07;                                     // reserved block type
        if (kind == 1) { pack[stream + 1] = 0xbf; pack[stream + 3] = 0x40; }    // LEN 43,199 (the pair still agrees): one byte short
        if (kind == 2) pack[stream + 5 + 100] ^= 0x01;                          // one pixel bit flipped
        CHECK(r.add_bytes(pack) == PackError::Ok); CHECK(r.add(spec(2)) == PackError::Ok);
        const auto* centre = r.head->frame(0, 0.0f, 0.0f);
        CHECK(centre != nullptr); CHECK_EQ(r.head->failures(), 0u);
        CHECK(r.head->frame(0, 30.0f, 0.0f) == nullptr);                        // the bad frame: the 2D portrait instead
        CHECK_EQ(r.head->failures(), 1u); CHECK(!r.head->has(0)); CHECK_EQ(int(r.head->sets()), 1);
        CHECK_EQ(r.head->last_failure_was_check(), kind != 0);
        if (kind == 0) CHECK(r.head->last_failure() == inflate::Result::BadBlock);
        if (centre) CHECK(all_px(centre, colour(0, 1, 1)));                     // the frame that was shown is intact
        CHECK(r.head->frame(0, 0.0f, 0.0f) == nullptr);                         // the whole set stays off: no face that half works
        CHECK_EQ(r.head->failures(), 1u);
        const auto* medium = r.head->frame(2, 0.0f, 0.0f);                      // other moods are unaffected
        CHECK(medium != nullptr);
        if (medium) CHECK(all_px(medium, colour(2, 1, 1)));
    }
}

GUARDIAN_CASE(a_held_tilt_keeps_its_frame_and_a_turn_eases_back) {
    // The real motion model (identity axis map: x right, y up, z out). Top tipped away by 20 degrees
    // and HELD for 20 s: pitch 20 x the default gain -0.5 = -10, the -15 frame, and it stays there.
    Rig r; r.add(spec(0)); Params on; on.on = true; r.head->configure(on);
    motion::Model m; motion::Params mp; mp.bob_px = 0; mp.sway_deg = 0; m.configure(motion::AxisMap{1, 2, 3}, mp);
    std::int64_t t = 0; int changes = 0, last_pitch = -2, frames = 0;
    const float tilt = 20.0f * 0.01745329252f;
    const auto feed = [&](int ms, float gyro_up_dps) {
        for (int i = 0; i < ms / 5; ++i) {
            t += 5000; motion::Reading rd; rd.t_us = t;
            rd.acc_g[1] = std::cos(tilt); rd.acc_g[2] = std::sin(tilt);
            rd.gyr_dps[1] = gyro_up_dps * std::cos(tilt); rd.gyr_dps[2] = gyro_up_dps * std::sin(tilt);   // about the world's vertical
            m.sample(rd);
            if (i % 8 == 7) {                                                   // one drawn frame every 40 ms
                const auto& o = m.step(t);
                CHECK(r.head->frame(0, o.yaw_deg, o.pitch_deg) != nullptr); ++frames;
                if (last_pitch != -2) changes += r.head->pitch_index() != last_pitch;
                last_pitch = r.head->pitch_index();
            }
        }
    };
    feed(20000, 0.0f);
    CHECK(frames > 400); CHECK_EQ(changes, 0); CHECK_EQ(r.head->pitch_index(), 0); CHECK_EQ(r.head->yaw_index(), 1);
    CHECK(std::fabs(m.output().pitch_deg - 20.0f) < 1.0f);
    // A quick quarter-second turn about the vertical: the head turns, then eases back to the front
    // (the model's yaw has no absolute reference and returns to centre; motion.hpp).
    feed(250, 160.0f);
    const int turned = r.head->yaw_index();
    CHECK(turned != 1);
    feed(8000, 0.0f);
    CHECK_EQ(r.head->yaw_index(), 1); CHECK_EQ(r.head->pitch_index(), 0);
    CHECK_EQ(r.head->failures(), 0u);
}

// ---- the shipped packs ----------------------------------------------------------------
GUARDIAN_CASE(every_shipped_frame_round_trips_through_the_device_inflater) {
    const std::string dir = GUARDIAN_HEAD_DIR;
    const std::string manifest = read_file(dir + "/manifest.json");
    CHECK(!manifest.empty());
    Bytes a(persona::art_bytes), b(persona::art_bytes);
    std::unique_ptr<Head> head{new Head(a.data(), b.data())};
    std::vector<std::string> keep; keep.reserve(5);
    static inflate::Workspace work;
    unsigned sets = 0, frames = 0, bad = 0; std::size_t total = 0;
    for (int mood = 0; mood < 5; ++mood) {
        const std::string file = std::string(mood_names[mood]) + ".bin", key = "\"file\": \"" + file + "\"";
        const auto at = manifest.find(key);
        const std::string bytes = read_file(dir + "/" + file);
        if (at == std::string::npos) { CHECK(bytes.empty()); continue; }      // no set in the manifest: no stray file either
        ++sets; total += bytes.size();
        CHECK(!bytes.empty());
        keep.push_back(bytes);
        const auto* data = reinterpret_cast<const std::uint8_t*>(keep.back().data());
        // The file is the one the manifest pins.
        const std::string file_key = "\"file_sha256\": \"";
        const auto fs = manifest.find(file_key, at);
        CHECK(fs != std::string::npos);
        if (fs != std::string::npos) CHECK_EQ(guardian::fixtures::sha256_hex(Bytes(data, data + bytes.size())), manifest.substr(fs + file_key.size(), 64));
        FrameSet set;
        CHECK(parse(data, bytes.size(), set) == PackError::Ok); CHECK_EQ(int(set.mood), mood);
        if (!set.valid()) continue;
        CHECK(head->add(data, bytes.size()) == PackError::Ok);
        // Every frame, in table order, against the manifest's sha256 of the RGB565 bytes the pipeline packed.
        std::size_t cursor = at; const std::string frame_key = "\"frame_sha256\": \"";
        for (int p = 0; p < set.pitch_count; ++p) for (int y = 0; y < set.yaw_count; ++y) {
            const auto e = set.entry(y, p);
            Bytes out(persona::art_bytes); std::size_t n = 0;
            const auto res = inflate::raw(work, data + e.offset, e.size, out.data(), out.size(), n);
            cursor = manifest.find(frame_key, cursor);
            const std::string want = cursor == std::string::npos ? std::string() : manifest.substr(cursor + frame_key.size(), 64);
            if (cursor != std::string::npos) cursor += frame_key.size();
            const bool ok = res == inflate::Result::Ok && n == persona::art_bytes && inflate::adler32(out.data(), n) == e.adler
                && want.size() == 64 && guardian::fixtures::sha256_hex(out) == want;
            if (!ok) { ++bad; std::printf("     frame mismatch: %s yaw %d pitch %d (%s)\n", file.c_str(), y, p, inflate::result_text(res)); }
            ++frames;
            // And through the Head, at exactly this frame's angles.
            Params plain; plain.on = true; plain.yaw_gain = 1; plain.pitch_gain = 1; head->configure(plain);
            const auto* art = head->frame(mood, static_cast<float>(set.yaw[static_cast<std::size_t>(y)]) * 0.1f,
                                          static_cast<float>(set.pitch[static_cast<std::size_t>(p)]) * 0.1f);
            if (!art || std::memcmp(art, out.data(), persona::art_bytes) != 0 || head->yaw_index() != y || head->pitch_index() != p) ++bad;
        }
        // The manifest lists exactly this many frames for this set (the next set, or the end, follows).
        const auto next_frame = manifest.find(frame_key, cursor), next_set = manifest.find("\"file\": \"", at + key.size());
        CHECK(next_frame == std::string::npos || (next_set != std::string::npos && next_frame > next_set));
    }
    CHECK(sets >= 1u);                                           // the current render set is on board
    CHECK(frames >= 9u); CHECK_EQ(bad, 0u); CHECK_EQ(head->failures(), 0u);
    CHECK_EQ(unsigned(head->sets()), sets); CHECK_EQ(unsigned(head->frames()), frames);
    // The pack fits the budget its manifest states, and the manifest's total is the files' total.
    const auto number_after = [&](const char* k) -> std::size_t {
        const auto p = manifest.find(k); return p == std::string::npos ? 0 : static_cast<std::size_t>(std::strtoul(manifest.c_str() + p + std::strlen(k), nullptr, 10));
    };
    const std::size_t budget = number_after("\"budget_bytes\": "), stated = number_after("\"total_bytes\": ");
    CHECK(budget > 0); CHECK_EQ(stated, total); CHECK(total <= budget);
    std::printf("     shipped: %u sets, %u frames, %zu B of %zu B\n", sets, frames, total, budget);
}

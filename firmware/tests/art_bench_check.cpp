// G16Q: the StickS3 art bench (boards/sticks3/main/art_bench.{hpp,cpp}, SDK-free). Checks the
// candidate catalogue (A..H for the three moods, then the grey ramp), the keys (FRONT = next,
// SIDE = backlight 60/80/100 %), the 2 s label, the STATUS fragment, that a still candidate
// reaches the canvas byte for byte, that the "still" H candidate through the Guardian's painter
// equals the exact frame while the "breath" one is a resampled copy, and that the pinned frames
// under firmware/art/bench have the embedded size and layout.
#include "check.hpp"
#include "art_bench.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace sticks3::artbench;
using guardian::Canvas;

namespace {
// Deterministic synthetic frames: every (pipeline, mood) differs, and the face band has a gradient
// with edges so a resample changes pixels. Rows outside 20..179 are black like the real A..D frames.
std::vector<std::uint8_t> synthetic(int pipeline, int mood) {
    std::vector<std::uint8_t> f(frame_bytes, 0);
    for (int y = face_row; y < face_row + 160; ++y)
        for (int x = 0; x < frame_w; ++x) {
            const unsigned r = static_cast<unsigned>((x * 7 + pipeline * 3) & 31);
            const unsigned g = static_cast<unsigned>((y * 5 + mood * 11 + ((x / 9) & 1) * 40) & 63);
            const unsigned b = static_cast<unsigned>(((x + y) / 3 + pipeline) & 31);
            const unsigned v = (r << 11) | (g << 5) | b;
            const auto i = static_cast<std::size_t>(y * frame_w + x) * 2;
            f[i] = static_cast<std::uint8_t>(v & 0xffu);
            f[i + 1] = static_cast<std::uint8_t>(v >> 8);
        }
    return f;
}
struct Set {
    std::vector<std::vector<std::uint8_t>> store;
    Frames frames;
    Set() {
        store.reserve(static_cast<std::size_t>(pipelines * moods + 1));
        for (int p = 0; p < pipelines; ++p)
            for (int m = 0; m < moods; ++m) {
                store.push_back(synthetic(p, m));
                frames.art[static_cast<std::size_t>(p)][static_cast<std::size_t>(m)] = store.back().data();
            }
        store.emplace_back(frame_bytes, std::uint8_t{0x55});
        frames.ramp = store.back().data();
    }
};
struct Glass {
    std::vector<std::uint16_t> px;
    Canvas canvas;
    explicit Glass(bool big_endian = true)
        : px(static_cast<std::size_t>(frame_w * frame_h), 0xdeadu), canvas(px.data(), frame_w, frame_h, big_endian) {}
};
std::uint16_t frame_px(const std::uint8_t* f, int x, int y) {
    const auto i = static_cast<std::size_t>(y * frame_w + x) * 2;
    return static_cast<std::uint16_t>(f[i] | (f[i + 1] << 8));
}
// Pixels of rows [y0, y1) that differ between the canvas and the frame.
int differing(const Canvas& c, const std::uint8_t* f, int y0, int y1) {
    int n = 0;
    for (int y = y0; y < y1; ++y)
        for (int x = 0; x < frame_w; ++x) n += c.get(x, y) != frame_px(f, x, y) ? 1 : 0;
    return n;
}
int lit(const Canvas& c, int y0, int y1) {
    int n = 0;
    for (int y = y0; y < y1; ++y)
        for (int x = 0; x < frame_w; ++x) n += c.get(x, y) != 0 ? 1 : 0;
    return n;
}
std::vector<std::uint8_t> load(const std::string& name) {
    std::vector<std::uint8_t> out;
    const std::string path = std::string(GUARDIAN_BENCH_DIR) + "/" + name;
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return out;
    std::uint8_t buf[4096];
    for (;;) {
        const std::size_t n = std::fread(buf, 1, sizeof buf, f);
        if (!n) break;
        out.insert(out.end(), buf, buf + n);
    }
    std::fclose(f);
    return out;
}
const char* kLetters[] = {"A", "B", "C", "D", "E"};
}

GUARDIAN_CASE(catalogue_lists_every_candidate_per_mood_then_the_grey_ramp) {
    CHECK_EQ(entry_count, std::size_t{29});
    const char* codes[] = {"A", "B", "C", "D", "E", "F", "G", "H-still", "H-breath"};
    const int pipeline[] = {0, 1, 2, 3, 4, 3, 3, 3, 3};
    for (int m = 0; m < moods; ++m)
        for (int k = 0; k < 9; ++k) {
            const Entry& e = entry(static_cast<std::size_t>(m * 9 + k));
            const std::string want = std::string(codes[k]) + "-" + mood_names[static_cast<std::size_t>(m)];
            CHECK_EQ(std::string(e.name), want);
            CHECK_EQ(int(e.pipeline), pipeline[k]);
            CHECK_EQ(int(e.mood), m);
            CHECK_EQ(e.gamma, k == 5 || k == 6);                         // F and G only
            CHECK_EQ(int(e.backlight_pct), k == 6 ? 100 : 60);           // G only
            CHECK(e.motion == (k == 7 ? Motion::Still : k == 8 ? Motion::Breath : Motion::Exact));
            CHECK(e.label && std::strlen(e.label) > 0 && std::strlen(e.label) <= 11);   // fits 135 px at scale 2
        }
    const Entry& ramp = entry(27);
    const Entry& ramp_gamma = entry(28);
    CHECK_EQ(std::string(ramp.name), std::string("ramp"));
    CHECK_EQ(std::string(ramp_gamma.name), std::string("ramp-gamma"));
    CHECK_EQ(int(ramp.pipeline), -1); CHECK_EQ(int(ramp.mood), -1); CHECK(!ramp.gamma);
    CHECK_EQ(int(ramp_gamma.pipeline), -1); CHECK(ramp_gamma.gamma);
    CHECK_EQ(int(ramp.backlight_pct), 60); CHECK_EQ(int(ramp_gamma.backlight_pct), 60);
    CHECK_EQ(std::string(entry(entry_count).name), std::string("A-VeryGood"));   // wraps
    for (std::size_t i = 0; i < entry_count; ++i)                               // names are unique
        for (std::size_t j = i + 1; j < entry_count; ++j) CHECK(std::strcmp(entry(i).name, entry(j).name) != 0);
}

GUARDIAN_CASE(entries_show_the_frame_of_their_pipeline_and_mood) {
    Set s;
    CHECK(s.frames.complete());
    for (std::size_t i = 0; i < entry_count; ++i) {
        const Entry& e = entry(i);
        const std::uint8_t* want = e.pipeline < 0 ? s.frames.ramp
            : s.frames.art[static_cast<std::size_t>(e.pipeline)][static_cast<std::size_t>(e.mood < 0 ? 0 : e.mood)];
        CHECK(frame_of(e, s.frames) == want);
        CHECK(frame_of(e, s.frames) != nullptr);
    }
    Frames missing = s.frames;
    missing.art[3][1] = nullptr;
    CHECK(!missing.complete());
    CHECK(frame_of(entry(9 + 3), missing) == nullptr);     // D-Horrible
    Frames none;
    CHECK(!none.complete());
    missing = s.frames; missing.ramp = nullptr;
    CHECK(!missing.complete());
}

GUARDIAN_CASE(gamma_table_is_the_m5gfx_st7789_list) {
    const std::array<std::uint8_t, 14> positive{0xd0, 0x00, 0x02, 0x07, 0x0a, 0x28, 0x32, 0x44, 0x42, 0x06, 0x0e, 0x12, 0x14, 0x17};
    const std::array<std::uint8_t, 14> negative{0xd0, 0x00, 0x02, 0x07, 0x0a, 0x28, 0x31, 0x54, 0x47, 0x0e, 0x1c, 0x17, 0x1b, 0x1e};
    CHECK_EQ(int(m5gfx_gamma[0].command), 0xE0);
    CHECK_EQ(int(m5gfx_gamma[1].command), 0xE1);
    CHECK(m5gfx_gamma[0].data == positive);
    CHECK(m5gfx_gamma[1].data == negative);
}

GUARDIAN_CASE(front_press_steps_to_the_next_candidate_once_per_press_and_wraps) {
    Bench b;
    CHECK_EQ(b.index(), std::size_t{0});
    CHECK(!b.keys(false, false, 0).any());
    auto c = b.keys(true, false, 100);
    CHECK(c.entry); CHECK(!c.backlight);
    CHECK_EQ(b.index(), std::size_t{1});
    CHECK(!b.keys(true, false, 150).any());            // held: one step only
    CHECK(!b.keys(true, false, 900).any());
    CHECK(!b.keys(false, false, 1000).any());
    CHECK(!b.keys(true, false, 1010).any());           // up for 10 ms only: contact bounce
    CHECK_EQ(b.index(), std::size_t{1});
    CHECK(!b.keys(false, false, 1020).any());
    CHECK(b.keys(true, false, 1100).entry);            // up for 80 ms: a press
    CHECK_EQ(b.index(), std::size_t{2});
    std::uint32_t t = 2000;
    for (std::size_t i = 2; i < entry_count; ++i) {    // on to the end and around
        b.keys(false, false, t); t += 100;
        CHECK(b.keys(true, false, t).entry); t += 100;
    }
    CHECK_EQ(b.index(), std::size_t{0});
}

GUARDIAN_CASE(key_held_since_boot_is_not_a_press) {
    Bench b;
    CHECK(!b.keys(true, true, 0).any());
    CHECK(!b.keys(true, true, 500).any());
    CHECK_EQ(b.index(), std::size_t{0}); CHECK_EQ(int(b.backlight_pct()), 60);
    CHECK(!b.keys(false, false, 600).any());
    CHECK(b.keys(true, false, 700).entry);
    CHECK_EQ(b.index(), std::size_t{1});
}

GUARDIAN_CASE(side_press_cycles_the_backlight_and_a_new_candidate_resets_it) {
    Bench b;
    b.keys(false, false, 0);
    CHECK_EQ(int(b.backlight_pct()), 60);
    auto c = b.keys(false, true, 100);
    CHECK(c.backlight); CHECK(!c.entry); CHECK_EQ(int(b.backlight_pct()), 80);
    b.keys(false, false, 200);
    CHECK(b.keys(false, true, 300).backlight); CHECK_EQ(int(b.backlight_pct()), 100);
    b.keys(false, false, 400);
    CHECK(b.keys(false, true, 500).backlight); CHECK_EQ(int(b.backlight_pct()), 60);
    CHECK_EQ(b.index(), std::size_t{0});
    CHECK(b.set_backlight(100, 600)); CHECK_EQ(int(b.backlight_pct()), 100);
    CHECK(!b.set_backlight(70, 700)); CHECK_EQ(int(b.backlight_pct()), 100);
    b.next(800);                                        // B starts at its own 60 %
    CHECK_EQ(int(b.backlight_pct()), 60);
    CHECK(b.go("G-VeryGood", 900));
    CHECK_EQ(int(b.backlight_pct()), 100); CHECK(b.gamma());
    b.next(1000);                                       // H-still: gamma off, 60 %
    CHECK_EQ(std::string(b.current().name), std::string("H-still-VeryGood"));
    CHECK_EQ(int(b.backlight_pct()), 60); CHECK(!b.gamma()); CHECK(!b.animated());
    b.next(1100);
    CHECK(b.animated());
}

GUARDIAN_CASE(go_and_prev_select_candidates_by_name_and_backwards) {
    Bench b;
    b.prev(10);
    CHECK_EQ(std::string(b.current().name), std::string("ramp-gamma"));
    CHECK(b.gamma());
    b.next(20);
    CHECK_EQ(b.index(), std::size_t{0});
    CHECK(b.go("E-Medium", 30));
    CHECK_EQ(b.index(), std::size_t{2 * 9 + 4});
    CHECK(!b.go("Z-Nothing", 40));
    CHECK(!b.go("", 50));
    CHECK(!b.go(nullptr, 60));
    CHECK_EQ(b.index(), std::size_t{2 * 9 + 4});
}

GUARDIAN_CASE(label_shows_for_two_seconds_after_boot_and_every_change) {
    Bench b;
    CHECK(b.label_visible(0)); CHECK(b.label_visible(1999)); CHECK(!b.label_visible(2000));
    b.next(5000);
    CHECK(b.label_visible(5000)); CHECK(b.label_visible(6999)); CHECK(!b.label_visible(7000));
    CHECK(b.set_backlight(80, 9000));
    CHECK(b.label_visible(10999)); CHECK(!b.label_visible(11000));
    CHECK(!b.set_backlight(55, 12000));                 // refused: no new label
    CHECK(!b.label_visible(12000));
}

GUARDIAN_CASE(status_fragment_names_the_candidate_and_the_panel_state) {
    Bench b;
    char out[160];
    std::size_t n = b.status(out, sizeof out, true);
    CHECK_EQ(std::string(out, n), std::string(" bench=A-VeryGood bench_index=1/29 bench_bl=60 bench_gamma=0 bench_motion=exact bench_frames=ok"));
    CHECK(b.go("G-Horrible", 10));
    n = b.status(out, sizeof out, true);
    CHECK_EQ(std::string(out, n), std::string(" bench=G-Horrible bench_index=16/29 bench_bl=100 bench_gamma=1 bench_motion=exact bench_frames=ok"));
    CHECK(b.go("H-breath-Medium", 20));
    n = b.status(out, sizeof out, false);
    CHECK_EQ(std::string(out, n), std::string(" bench=H-breath-Medium bench_index=27/29 bench_bl=60 bench_gamma=0 bench_motion=breath bench_frames=missing"));
    char small[16];
    CHECK_EQ(b.status(small, sizeof small, true), std::size_t{0});   // never a cut fragment
    CHECK_EQ(b.status(nullptr, 0, true), std::size_t{0});
}

GUARDIAN_CASE(still_candidate_reaches_the_canvas_byte_for_byte_once_the_label_is_gone) {
    Set s;
    for (bool big : {true, false}) {
        Glass g(big);
        Bench b;
        CHECK(b.go("E-Horrible", 0));
        const std::uint8_t* f = frame_of(b.current(), s.frames);
        CHECK(f != nullptr); if (!f) return;
        draw(g.canvas, b, s.frames, 500);                       // label showing
        CHECK_EQ(differing(g.canvas, f, 0, label_top), 0);      // the art above the label box is exact
        draw(g.canvas, b, s.frames, 2000);                      // label gone
        CHECK_EQ(differing(g.canvas, f, 0, frame_h), 0);
    }
    Glass g;
    Bench b;                                                     // A: rows 196..239 of the frame are black
    const std::uint8_t* f = frame_of(b.current(), s.frames);
    CHECK(f != nullptr); if (!f) return;
    draw(g.canvas, b, s.frames, 100);
    CHECK(lit(g.canvas, label_top, frame_h) > 40);              // the label's glyphs
    CHECK_EQ(differing(g.canvas, f, 0, label_top), 0);
    draw(g.canvas, b, s.frames, 2500);
    CHECK_EQ(lit(g.canvas, label_top, frame_h), 0);
    CHECK_EQ(differing(g.canvas, f, 0, frame_h), 0);
}

GUARDIAN_CASE(ramp_and_gamma_candidates_paint_their_frame_exactly) {
    Set s; Glass g;
    Bench b;
    CHECK(b.go("ramp", 0));
    draw(g.canvas, b, s.frames, 3000);
    CHECK_EQ(differing(g.canvas, s.frames.ramp, 0, frame_h), 0);
    CHECK(b.go("F-Medium", 4000));                               // D's Medium frame; the gamma table is the board's job
    draw(g.canvas, b, s.frames, 7000);
    CHECK_EQ(differing(g.canvas, s.frames.art[3][2], 0, frame_h), 0);
}

GUARDIAN_CASE(still_through_the_painter_is_exact_and_breathing_is_a_resampled_copy) {
    Set s; Glass still, breath;
    Bench b;
    CHECK(b.go("H-still-VeryGood", 0));
    const std::uint8_t* f = frame_of(b.current(), s.frames);
    CHECK(f != nullptr); if (!f) return;
    for (std::uint32_t t : {2000u, 3500u, 9000u, 20000u}) {
        draw(still.canvas, b, s.frames, t);
        CHECK_EQ(differing(still.canvas, f, 0, frame_h), 0);     // breath 0 = the exact pixels, at any time
    }
    CHECK(b.go("H-breath-VeryGood", 30000));
    int most = 0;
    for (std::uint32_t t : {32000u, 33500u, 35000u, 37000u, 41000u}) {
        draw(breath.canvas, b, s.frames, t);
        CHECK_EQ(lit(breath.canvas, 0, face_row), 0);            // the painter stays inside the face zone
        CHECK_EQ(lit(breath.canvas, face_row + 160, frame_h), 0);
        const int d = differing(breath.canvas, f, face_row, face_row + 160);
        if (d > most) most = d;
    }
    CHECK(most > 500);                                           // breathing resamples the portrait
}

GUARDIAN_CASE(missing_frames_paint_a_message_instead_of_art) {
    Glass g;
    Frames none;
    Bench b;
    draw(g.canvas, b, none, 5000);
    CHECK(lit(g.canvas, 0, frame_h) > 40);                       // a readable message
    CHECK(lit(g.canvas, 0, frame_h) < frame_w * frame_h / 4);    // on black, not a stale frame
    for (int y = 0; y < frame_h; ++y) CHECK(g.canvas.get(0, y) != 0xdeadu);
}

GUARDIAN_CASE(pinned_bench_frames_have_the_embedded_size_and_layout) {
    for (const char* letter : kLetters)
        for (const char* mood : mood_names) {
            const std::string name = std::string(letter) + "_" + mood + ".rgb565";
            const auto f = load(name);
            if (!CHECK_EQ(f.size(), frame_bytes)) continue;
            if (letter[0] == 'E') continue;                      // full height: no black rows
            int outside = 0;
            for (std::size_t i = 0; i < f.size(); ++i) {
                const int y = static_cast<int>(i / 2) / frame_w;
                if ((y < face_row || y >= face_row + 160) && f[i] != 0) ++outside;
            }
            CHECK_EQ(outside, 0);                                // A..D: the portrait in rows 20..179 on black
        }
    const auto ramp = load("ramp.rgb565");
    CHECK_EQ(ramp.size(), frame_bytes);
}

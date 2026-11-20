// BASELINE of the pre-existing RGB565 canvas and 5x7 glyph set (G03). Not TDD.
//
// guardian_canvas is a renderer helper with no core dependency; it is built on
// the host here to prove it needs no SDK. These cases pin clipping, byte order,
// glyph lookup and text metrics so a later board renderer can rely on them.
#include "check.hpp"

#include "guardian/canvas.hpp"

#include <array>

using namespace guardian;

namespace {
constexpr int W = 16;
constexpr int H = 8;
struct Frame {
    std::array<std::uint16_t, W * H> px{};
    std::array<std::uint16_t, W * H> guard_after{}; // stays zero if clipping holds
};
} // namespace

GUARDIAN_CASE(rgb565_packs_the_documented_bit_layout) {
    CHECK_EQ(color::black, 0x0000);
    CHECK_EQ(color::white, 0xFFFF);
    CHECK_EQ(color::red, 0xF800);
    CHECK_EQ(color::green, 0x07E0);
    CHECK_EQ(color::blue, 0x001F);
    CHECK_EQ(rgb565(0x08, 0x04, 0x08), 0x0821); // lowest bit of each channel
    CHECK_EQ(rgb565(0x07, 0x03, 0x07), 0x0000); // truncated low bits
}

GUARDIAN_CASE(put_and_get_round_trip_in_both_byte_orders) {
    Frame f;
    Canvas le(f.px.data(), W, H, false);
    le.put(3, 2, color::red);
    CHECK_EQ(le.get(3, 2), color::red);
    CHECK_EQ(f.px[2 * W + 3], color::red);
    Canvas be(f.px.data(), W, H, true);
    be.put(4, 2, color::red);
    CHECK_EQ(be.get(4, 2), color::red);         // logical value is unchanged
    CHECK_EQ(f.px[2 * W + 4], 0x00F8);           // stored swapped for the SPI panel
    CHECK_EQ(be.size_bytes(), std::size_t{W * H * 2});
}

GUARDIAN_CASE(put_and_get_clip_outside_the_canvas) {
    Frame f;
    Canvas c(f.px.data(), W, H, false);
    c.put(-1, 0, color::white);
    c.put(0, -1, color::white);
    c.put(W, 0, color::white);
    c.put(0, H, color::white);
    for (auto v : f.px) CHECK_EQ(v, 0);
    for (auto v : f.guard_after) CHECK_EQ(v, 0);
    CHECK_EQ(c.get(-1, 0), 0);
    CHECK_EQ(c.get(W, H), 0);
}

GUARDIAN_CASE(fill_rect_clips_negative_origin_and_overhang) {
    Frame f;
    Canvas c(f.px.data(), W, H, false);
    c.fill_rect(-2, -2, 4, 4, color::green);  // only the 2x2 corner lands
    int painted = 0;
    for (int y = 0; y < H; ++y)
        for (int x = 0; x < W; ++x)
            if (c.get(x, y) == color::green) ++painted;
    CHECK_EQ(painted, 4);
    CHECK_EQ(c.get(1, 1), color::green);
    CHECK_EQ(c.get(2, 2), 0);
    c.fill_rect(W - 1, H - 1, 10, 10, color::blue); // overhang clipped to one pixel
    CHECK_EQ(c.get(W - 1, H - 1), color::blue);
    for (auto v : f.guard_after) CHECK_EQ(v, 0);
    c.fill_rect(5, 5, 0, 3, color::red);   // zero width paints nothing
    c.fill_rect(5, 5, -3, 3, color::red);  // negative width paints nothing
    CHECK_EQ(c.get(5, 5), 0);
}

GUARDIAN_CASE(clear_fills_every_pixel) {
    Frame f;
    Canvas c(f.px.data(), W, H, false);
    c.clear(color::dark);
    for (auto v : f.px) CHECK_EQ(v, color::dark);
}

GUARDIAN_CASE(draw_rect_paints_only_the_border) {
    Frame f;
    Canvas c(f.px.data(), W, H, false);
    c.draw_rect(2, 1, 5, 4, color::yellow); // x 2..6, y 1..4
    CHECK_EQ(c.get(2, 1), color::yellow);
    CHECK_EQ(c.get(6, 4), color::yellow);
    CHECK_EQ(c.get(4, 1), color::yellow);
    CHECK_EQ(c.get(2, 3), color::yellow);
    CHECK_EQ(c.get(3, 2), 0); // interior untouched
    CHECK_EQ(c.get(7, 1), 0); // just outside
    c.draw_rect(0, 0, 0, 5, color::red); // degenerate: nothing
    CHECK_EQ(c.get(0, 0), 0);
}

GUARDIAN_CASE(font_lookup_covers_printable_ascii_and_falls_back_to_question_mark) {
    const std::uint8_t* q = font5x7_glyph('?');
    CHECK(q != nullptr);
    CHECK(font5x7_glyph(' ') != q);
    CHECK(font5x7_glyph('~') != q);
    CHECK(font5x7_glyph('\x1f') == q);  // below range
    CHECK(font5x7_glyph('\x7f') == q);  // DEL
    CHECK(font5x7_glyph(static_cast<char>(0xE9)) == q); // non-ASCII byte, no UB
    // 'A' is the conventional 5x7 shape: columns 7E 11 11 11 7E (bit0 = top row).
    const std::uint8_t* a = font5x7_glyph('A');
    CHECK_EQ(a[0], 0x7E);
    CHECK_EQ(a[1], 0x11);
    CHECK_EQ(a[4], 0x7E);
    // Space is blank.
    for (int i = 0; i < 5; ++i) CHECK_EQ(font5x7_glyph(' ')[i], 0);
}

GUARDIAN_CASE(text_advances_six_pixels_per_glyph_times_scale) {
    Frame f;
    Canvas c(f.px.data(), W, H, false);
    CHECK_EQ(c.text(0, 0, "", color::white), 0);
    CHECK_EQ(c.text(1, 0, "ab", color::white), 1 + 2 * Canvas::glyph_advance);
    CHECK_EQ(c.text(0, 0, "a", color::white, 2), 2 * Canvas::glyph_advance);
    CHECK_EQ(c.text(0, 0, "a", color::white, 0), Canvas::glyph_advance); // scale < 1 clamps to 1
    CHECK_EQ(c.text(0, 0, nullptr, color::white), 0);
}

GUARDIAN_CASE(text_draws_the_glyph_columns_and_background_variant_paints_behind) {
    Frame f;
    Canvas c(f.px.data(), W, H, false);
    c.text(1, 0, "|", color::white); // '|' is a single centre column 0x7F, 7 rows
    for (int row = 0; row < 7; ++row) CHECK_EQ(c.get(1 + 2, row), color::white);
    CHECK_EQ(c.get(1 + 1, 3), 0);
    CHECK_EQ(c.get(1 + 3, 3), 0);
    CHECK_EQ(c.get(1 + 2, 7), 0); // 8th row is the line gap
    Frame g;
    Canvas d(g.px.data(), W, H, false);
    d.text(0, 0, "|", color::white, color::grey, 1);
    CHECK_EQ(d.get(0, 0), color::grey);       // background covers the cell
    CHECK_EQ(d.get(2, 0), color::white);      // glyph on top
    CHECK_EQ(d.get(5, 7), color::grey);       // gap row and gap column painted
    CHECK_EQ(d.get(6, 0), 0);                 // next cell untouched
}

GUARDIAN_CASE(text_clips_at_the_canvas_edge_without_writing_past_the_buffer) {
    Frame f;
    Canvas c(f.px.data(), W, H, false);
    c.text(W - 2, H - 3, "WW", color::white, 3);
    for (auto v : f.guard_after) CHECK_EQ(v, 0);
}

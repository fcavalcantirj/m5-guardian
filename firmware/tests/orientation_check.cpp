// G16A: StickS3 upright-portrait orientation (host, SDK-free). Encodes the
// vendor M5GFX 0.2.28 rotation/gap formula and the 2026-11-16 spike/owner
// video observation of the G14-G16 landscape window; nothing here drives a panel.
#include "check.hpp"
#include "orientation.hpp"
#include <vector>

using namespace sticks3::orientation;

namespace {
constexpr int glass_col0 = 52, glass_row0 = 40, glass_w = 135, glass_h = 240;
// Every logical pixel lands on the glass, and every glass cell is written exactly once.
bool covers_glass_exactly(const Rotation& r) {
    std::vector<int> hits(static_cast<std::size_t>(glass_w * glass_h), 0);
    for (int y = 0; y < r.height; ++y) for (int x = 0; x < r.width; ++x) {
        const auto a = to_controller(r, x, y);
        const int c = a.column - glass_col0, w = a.row - glass_row0;
        if (c < 0 || c >= glass_w || w < 0 || w >= glass_h) return false;
        ++hits[static_cast<std::size_t>(w * glass_w + c)];
    }
    for (int h : hits) if (h != 1) return false;
    return true;
}
const Rotation legacy_landscape{1, 240, 135, true, true, false, 40, 52};   // sticks3_board.cpp before G16A
} // namespace

GUARDIAN_CASE(vendor_gaps_match_m5gfx_setrotation_for_the_sticks3_panel) {
    const int gaps[4][2] = {{52, 40}, {40, 53}, {53, 40}, {40, 52}};
    for (int r = 0; r < 4; ++r) {
        const auto rot = rotation(r);
        CHECK_EQ(rot.gap_x, gaps[r][0]); CHECK_EQ(rot.gap_y, gaps[r][1]);
        CHECK_EQ(rot.width, (r & 1) ? 240 : 135); CHECK_EQ(rot.height, (r & 1) ? 135 : 240);
        CHECK(covers_glass_exactly(rot));
    }
}

GUARDIAN_CASE(the_g14_g16_landscape_window_leaves_one_controller_column_unwritten) {
    // The rainbow strip seen on the glass in G14, G16 and the spike video.
    CHECK(!covers_glass_exactly(legacy_landscape));
    int missing = 0;
    for (int row = glass_row0; row < glass_row0 + glass_h; ++row) {
        bool written = false;
        for (int y = 0; y < 135 && !written; ++y) for (int x = 0; x < 240 && !written; ++x) {
            const auto a = to_controller(legacy_landscape, x, y);
            written = a.column == glass_col0 && a.row == row;
        }
        if (!written) ++missing;
    }
    CHECK_EQ(missing, glass_h);   // the whole first glass column
}

GUARDIAN_CASE(spike_observation_places_the_upright_frame_on_the_native_rows_and_columns) {
    // Spike + owner video, StickS3 standing USB down: in the landscape buffer x
    // runs down from the screen top and y = 0 is at the screen right. So, seen
    // upright, controller rows grow downwards and columns grow to the right.
    const auto top = to_controller(legacy_landscape, 0, 60), bottom = to_controller(legacy_landscape, 239, 60);
    const auto right = to_controller(legacy_landscape, 100, 0), left = to_controller(legacy_landscape, 100, 134);
    CHECK(top.row < bottom.row); CHECK_EQ(top.column, bottom.column);
    CHECK(right.column > left.column); CHECK_EQ(right.row, left.row);
}

GUARDIAN_CASE(board_uses_the_native_upright_portrait_window) {
    CHECK_EQ(display.width, 135); CHECK_EQ(display.height, 240);
    CHECK_EQ(display.width * display.height * 2, 64800);          // same framebuffer bytes
    CHECK(covers_glass_exactly(display));
    // Upright identity: logical (x, y) is glass column x from the left, row y from the top.
    int wrong = 0;
    for (int y = 0; y < display.height; ++y) for (int x = 0; x < display.width; ++x) {
        const auto a = to_controller(display, x, y);
        if (a.column != glass_col0 + x || a.row != glass_row0 + y) ++wrong;
    }
    CHECK_EQ(wrong, 0);
    CHECK_EQ(display.index, 0); CHECK(!display.swap_xy); CHECK(!display.mirror_x); CHECK(!display.mirror_y);
}

// G16C rework (1): the StickS3 pushes only the framebuffer rows that changed
// since the last push (boards/sticks3/main/dirty_rows.hpp, SDK-free). Checks
// that every changed row is planned, unchanged rows are skipped, nearby runs
// merge into few panel transactions, and a forced push sends everything.
#include "check.hpp"
#include "dirty_rows.hpp"
#include <array>
#include <cstdint>

using sticks3::DirtyRows;

namespace {
constexpr int w = 135, h = 240;
struct Fb { std::array<std::uint16_t, w * h> px{}; void set(int x, int y, std::uint16_t v) { px[static_cast<std::size_t>(y * w + x)] = v; } };
bool covers(const DirtyRows::Plan& p, int y) {
    for (std::size_t i = 0; i < p.count; ++i) if (y >= p.runs[i].y0 && y < p.runs[i].y0 + p.runs[i].rows) return true;
    return false;
}
int planned_rows(const DirtyRows::Plan& p) { int n = 0; for (std::size_t i = 0; i < p.count; ++i) n += p.runs[i].rows; return n; }
}

GUARDIAN_CASE(first_and_forced_pushes_send_the_whole_frame) {
    Fb fb; DirtyRows d;
    auto p = d.plan(fb.px.data(), w, h, false);
    CHECK(p.full); CHECK_EQ(p.count, std::size_t{1}); CHECK_EQ(p.runs[0].y0, 0); CHECK_EQ(p.runs[0].rows, h);
    p = d.plan(fb.px.data(), w, h, false);
    CHECK(!p.full); CHECK_EQ(p.count, std::size_t{0});            // nothing changed: nothing pushed
    p = d.plan(fb.px.data(), w, h, true);
    CHECK(p.full); CHECK_EQ(planned_rows(p), h);
    d.invalidate();
    p = d.plan(fb.px.data(), w, h, false); CHECK(p.full);
}
GUARDIAN_CASE(every_changed_row_is_pushed_and_unchanged_rows_are_not) {
    Fb fb; DirtyRows d; d.plan(fb.px.data(), w, h, false);
    const int rows[] = {0, 5, 119, 120, 200, 239};
    for (int y : rows) fb.set(y % w, y, 0x1234);
    auto p = d.plan(fb.px.data(), w, h, false);
    for (int y : rows) CHECK(covers(p, y));
    CHECK(p.count <= DirtyRows::max_runs);
    CHECK(planned_rows(p) < h);
    // One pixel in the last column of a row is a change too.
    d.plan(fb.px.data(), w, h, false);
    fb.set(w - 1, 77, 0x0001); p = d.plan(fb.px.data(), w, h, false);
    CHECK(covers(p, 77)); CHECK_EQ(planned_rows(p), 1);
    // Writing the same value again is not a change.
    fb.set(w - 1, 77, 0x0001); p = d.plan(fb.px.data(), w, h, false); CHECK_EQ(p.count, std::size_t{0});
}
GUARDIAN_CASE(nearby_runs_merge_and_many_runs_collapse_to_one_span) {
    Fb fb; DirtyRows d; d.plan(fb.px.data(), w, h, false);
    fb.set(1, 30, 7); fb.set(1, 34, 7);                          // gap of 3 rows: one transaction
    auto p = d.plan(fb.px.data(), w, h, false);
    CHECK_EQ(p.count, std::size_t{1}); CHECK_EQ(p.runs[0].y0, 30); CHECK_EQ(p.runs[0].rows, 5);
    for (int y = 0; y < h; y += 20) fb.set(2, y, static_cast<std::uint16_t>(y + 1));   // 12 runs far apart
    p = d.plan(fb.px.data(), w, h, false);
    CHECK(p.count <= DirtyRows::max_runs);
    for (int y = 0; y < h; y += 20) CHECK(covers(p, y));
}
GUARDIAN_CASE(a_frame_taller_than_the_planner_is_always_pushed_whole) {
    std::array<std::uint16_t, 10 * (DirtyRows::max_height + 1)> big{}; DirtyRows d;
    d.plan(big.data(), 10, DirtyRows::max_height + 1, false);
    const auto p = d.plan(big.data(), 10, DirtyRows::max_height + 1, false);
    CHECK(p.full); CHECK_EQ(p.runs[0].rows, DirtyRows::max_height + 1);
}

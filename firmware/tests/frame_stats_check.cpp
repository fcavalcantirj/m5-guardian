// G16C: StickS3 frame-time / fps / IMU-to-glass accounting (SDK-free board header).
// Deterministic fake timings; the real numbers come from the device (STATUS, FRAMES).
#include "check.hpp"
#include "frame_stats.hpp"
#include <cstring>
#include <string>

using namespace sticks3;
using guardian::companion::FaceArt;
using guardian::companion::Frame;

GUARDIAN_CASE(frames_are_categorised_by_what_the_face_zone_shows) {
    Frame f; CHECK(frame_category(f) == FrameKind::Other);
    f.face_shown = true; f.art = FaceArt::Rated; CHECK(frame_category(f) == FrameKind::Rated);
    f.art = FaceArt::Alert; CHECK(frame_category(f) == FrameKind::Alert);
    f.art = FaceArt::NoData; CHECK(frame_category(f) == FrameKind::NoData);
    f.art = FaceArt::Rated; f.demo_badge = true; CHECK(frame_category(f) == FrameKind::Demo);
}

GUARDIAN_CASE(fps_render_push_and_imu_latency_are_measured_per_kind) {
    FrameStats s;
    // 50 rated frames every 40 ms: 12 ms render, 14 ms push, IMU sample 9 ms old at present.
    for (int i = 0; i < 50; ++i) s.add(FrameKind::Rated, 12000, 14000, i ? 40000 : 0, 9000);
    CHECK_EQ(s.frames(FrameKind::Rated), 50u); CHECK_EQ(s.fps10(FrameKind::Rated), 250u);
    // Switching kind: the first interval of the new kind is not counted as its frame interval.
    s.add(FrameKind::Other, 3000, 14000, 40000, -1); s.add(FrameKind::Other, 3000, 14000, 250000, -1);
    CHECK_EQ(s.fps10(FrameKind::Other), 40u);
    // A long pause is not a frame interval.
    s.add(FrameKind::Other, 3000, 14000, 5000000, -1); CHECK_EQ(s.fps10(FrameKind::Other), 40u);
    char line[200]; s.status_text(line, sizeof line);
    const std::string t = line;
    CHECK(t.find("frame_ms=") != std::string::npos); CHECK(t.find("fps=") != std::string::npos); CHECK(t.find("imu_glass_ms=9.0/9.0") != std::string::npos);
    char table[1024]; s.table(table, sizeof table);
    const std::string tt = table;
    CHECK(tt.find("kind=rated frames=50 render_ms=12.0 push_ms=14.0 total_max_ms=26.0 fps=25.0 imu_glass_ms=9.0/9.0") != std::string::npos);
    CHECK(tt.find("kind=other frames=3") != std::string::npos); CHECK(tt.find("G16C FRAMES END") != std::string::npos);
    CHECK(tt.find("kind=alert") == std::string::npos);
    s.reset(); CHECK_EQ(s.frames(FrameKind::Rated), 0u);
    s.status_text(line, sizeof line); CHECK(std::string(line).find("imu_glass_ms=none/none") != std::string::npos);
}

GUARDIAN_CASE(recent_window_reports_the_latest_frames_only) {
    FrameStats s;
    for (int i = 0; i < 40; ++i) s.add(FrameKind::Rated, 60000, 14000, i ? 80000 : 0, -1);   // slow
    for (int i = 0; i < 40; ++i) s.add(FrameKind::Rated, 10000, 14000, 30000, 5000);          // fast
    char line[200]; s.status_text(line, sizeof line);
    const std::string t = line;
    CHECK(t.find("frame_ms=24.0/24.0") != std::string::npos);
    CHECK(t.find("fps=33.3") != std::string::npos);
}

// G16I: the particle frames are timed apart from the warped portrait (FRAMES kind=burst).
GUARDIAN_CASE(burst_frames_are_counted_as_their_own_kind) {
    Frame f; f.face_shown = true; f.art = FaceArt::Rated;
    CHECK(frame_category(f, false) == FrameKind::Rated); CHECK(frame_category(f, true) == FrameKind::Burst);
    f.demo_badge = true; CHECK(frame_category(f, true) == FrameKind::Burst); CHECK(frame_category(f, false) == FrameKind::Demo);
    Frame other; CHECK(frame_category(other, true) == FrameKind::Other);       // no face on this screen: nothing burst
    CHECK_EQ(std::string(frame_kind_text(FrameKind::Burst)), std::string("burst"));
    FrameStats s;
    for (int i = 0; i < 30; ++i) s.add(FrameKind::Rated, 19000, 11900, i ? 40000 : 0, 9000);
    for (int i = 0; i < 88; ++i) s.add(FrameKind::Burst, 6000, 12000, 40000, 9000);
    CHECK_EQ(s.frames(FrameKind::Burst), 88u); CHECK_EQ(s.frames(FrameKind::Rated), 30u); CHECK_EQ(s.fps10(FrameKind::Burst), 250u);
    char table[1024]; s.table(table, sizeof table); const std::string t = table;
    CHECK(t.find("kind=burst frames=88 render_ms=6.0 push_ms=12.0 total_max_ms=18.0 fps=25.0") != std::string::npos);
    CHECK(t.find("kind=rated frames=30") != std::string::npos);
}

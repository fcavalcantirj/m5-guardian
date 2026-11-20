// G16I shake detector (adapters/companion/shake.hpp). Generated 200 Hz accelerometer samples in g
// for the gestures that must NOT fire, and the nine traces recorded on the StickS3 on 2026-11-17
// (tests/fixtures/imu/*.txt = firmware/evidence/sticks3-imu-shake-*-20261117.txt, byte for byte).
// Nothing here is radio evidence.
#include "check.hpp"
#include "shake.hpp"
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>

using namespace guardian::companion::shake;

namespace {
constexpr float two_pi = 6.28318530718f;
// The stick standing USB down reads -1 g on the IMU x axis (firmware/evidence/sticks3-imu-axis-map-20261117.json).
struct Rig {
    Detector d; std::int64_t t{1000000}; std::uint32_t fired{};
    Rig() { still(1500); }
    void sample(float x, float y, float z) {
        const float a[3] = {-1.0f + x, y, z}; t += 5000; d.sample(a, t);
        if (d.take()) ++fired;
    }
    void still(int ms) { for (int i = 0; i < ms / 5; ++i) sample(0, 0, 0); }
    // A sine of `amp` g at `hz` on the IMU y axis for `ms`.
    void shake(int ms, float hz, float amp) {
        for (int i = 0; i < ms / 5; ++i) sample(0, amp * std::sin(two_pi * hz * static_cast<float>(i) * 0.005f), 0);
    }
    // One knock: a sharp peak, a smaller rebound 70 ms later and a last ring 70 ms after that.
    void tap(float peak) {
        for (int i = 0; i < 3; ++i) sample(0, 0, peak);
        still(55);
        for (int i = 0; i < 3; ++i) sample(0, 0, -0.8f * peak);
        still(55);
        for (int i = 0; i < 3; ++i) sample(0, 0, 0.5f * peak);
    }
};
// "IMU <t_us> <sensortime> ax ay az gx gy gz" lines at 4096 LSB per g (the console's IMU stream).
std::uint32_t fires_in_trace(const char* label, int& samples) {
    const std::string path = std::string(GUARDIAN_IMU_FIXTURE_DIR) + "/" + label + ".txt";
    std::FILE* f = std::fopen(path.c_str(), "r"); samples = 0;
    if (!f) return 0xffffffffu;
    Detector d; std::uint32_t fired = 0; char line[200];
    while (std::fgets(line, sizeof line, f)) {
        long long t = 0; unsigned long st = 0; int ax, ay, az, gx, gy, gz;
        if (std::sscanf(line, "IMU %lld %lu %d %d %d %d %d %d", &t, &st, &ax, &ay, &az, &gx, &gy, &gz) != 8) continue;
        const float a[3] = {static_cast<float>(ax) / 4096.0f, static_cast<float>(ay) / 4096.0f, static_cast<float>(az) / 4096.0f};
        d.sample(a, t); ++samples;
        if (d.take()) ++fired;
    }
    std::fclose(f);
    return fired == d.events() ? fired : 0xfffffffeu;
}
} // namespace

GUARDIAN_CASE(a_single_tap_is_not_a_shake) {
    Rig r; r.tap(2.1f); r.still(2000);                 // the recorded tap peaked at 2.08 g
    CHECK_EQ(r.fired, 0u); CHECK_EQ(r.d.events(), 0u);
    r.tap(6.0f); r.still(2000);                        // a hard knock is still one knock
    CHECK_EQ(r.fired, 0u);
}

GUARDIAN_CASE(three_fast_taps_like_the_update_gesture_are_not_a_shake) {
    Rig r;                                             // FRONT x3 fast = UPDATE (ota::TripleTap): three knocks, each ringing
    for (int i = 0; i < 3; ++i) { r.tap(3.0f); r.still(150); }
    r.still(2000);
    CHECK_EQ(r.fired, 0u);
    for (int i = 0; i < 3; ++i) { r.tap(3.0f); r.still(60); }   // faster than a person presses
    r.still(2000);
    CHECK_EQ(r.fired, 0u);
}

GUARDIAN_CASE(walking_two_hz_under_point_three_g_is_not_a_shake) {
    Rig r; r.shake(20000, 2.0f, 0.3f);
    CHECK_EQ(r.fired, 0u);
    r.shake(20000, 2.0f, 0.9f);                        // even a hard jog stays under the 1.2 g threshold
    CHECK_EQ(r.fired, 0u);
}

GUARDIAN_CASE(a_drop_free_fall_then_impact_is_not_a_shake) {
    Rig r;
    for (int drop = 0; drop < 3; ++drop) {             // the recorded hands-off drops: three falls, 7..9 g impacts
        for (int i = 0; i < 30; ++i) r.sample(1.0f, 0, 0);           // 150 ms of free fall: the accelerometer reads 0 g
        for (int i = 0; i < 2; ++i) r.sample(1.0f, 0, 8.0f);         // the impact
        r.still(70);
        for (int i = 0; i < 2; ++i) r.sample(0, 0, -2.5f);           // one bounce
        r.still(70);
        for (int i = 0; i < 2; ++i) r.sample(0, 0, 1.5f);
        r.still(2000);
    }
    CHECK_EQ(r.fired, 0u);
}

GUARDIAN_CASE(a_steady_spin_is_not_a_shake) {
    Rig r;                                             // swung in a circle: 2.5 g pulling one way for 5 s, then released
    for (int i = 0; i < 1000; ++i) r.sample(-2.5f, 0, 0);
    r.still(5000);
    CHECK_EQ(r.fired, 0u);
}

GUARDIAN_CASE(a_weak_shake_under_threshold_does_not_fire) {
    Rig r; r.shake(5000, 5.0f, 1.0f);
    CHECK_EQ(r.fired, 0u);
    Rig s; s.shake(450, 5.0f, 2.0f); s.still(3000);    // one short wiggle: 4 alternations, not a shake
    CHECK_EQ(s.fired, 0u);
}

GUARDIAN_CASE(a_real_shake_five_hz_two_g_fires_once) {
    Rig r; r.shake(1500, 5.0f, 2.0f); r.still(3000);
    CHECK_EQ(r.fired, 1u); CHECK_EQ(r.d.events(), 1u);
    CHECK(!r.d.take());                                // taken once
    // Any direction: the detector works on the IMU's own axes, whatever the screen map says.
    Detector d; std::int64_t t = 0; std::uint32_t fired = 0;
    for (int i = 0; i < 600; ++i) {
        const float w = i < 300 ? 0.0f : 2.2f * std::sin(two_pi * 4.0f * static_cast<float>(i) * 0.005f);
        const float a[3] = {0.2f + 0.7f * w, -0.3f - 0.4f * w, 0.93f + 0.5f * w}; t += 5000; d.sample(a, t);
        fired += d.take();
    }
    CHECK_EQ(fired, 1u);
}

GUARDIAN_CASE(a_second_shake_inside_the_refractory_is_ignored_then_a_later_one_fires) {
    Rig r; r.shake(1000, 5.0f, 2.0f);                  // fires within the first second
    CHECK_EQ(r.fired, 1u);
    r.shake(800, 5.0f, 2.0f);                          // still shaking 0.8 s later: inside the 1 s refractory
    CHECK_EQ(r.fired, 1u);
    r.still(2000); r.shake(1500, 5.0f, 2.0f); r.still(1500);
    CHECK_EQ(r.fired, 2u); CHECK_EQ(r.d.events(), 2u);
    // Kept shaking for 6 s: it fires again and again (the board kicks the burst), never faster than the refractory.
    Rig k; k.shake(6000, 5.0f, 2.0f);
    CHECK(k.fired >= 3u && k.fired <= 4u);
}

GUARDIAN_CASE(thresholds_follow_configure) {
    Params strict; strict.g = 2.5f;
    Rig a; a.d.configure(strict); a.shake(3000, 5.0f, 2.0f); CHECK_EQ(a.fired, 0u);      // 2 g swings no longer count
    Params quick; quick.peaks = 4; quick.window_ms = 700;
    Rig b; b.d.configure(quick); b.shake(600, 5.0f, 2.0f); b.still(2000); CHECK_EQ(b.fired, 1u);
    Rig c; c.shake(600, 5.0f, 2.0f); c.still(2000); CHECK_EQ(c.fired, 0u);              // the defaults need 8
    Params narrow; narrow.window_ms = 400;                                               // 8 alternations cannot fit in 400 ms at 5 Hz
    Rig e; e.d.configure(narrow); e.shake(3000, 5.0f, 2.0f); CHECK_EQ(e.fired, 0u);
    // Out-of-range values are clamped to the TUNE ranges.
    Detector d; Params wild; wild.g = 0.1f; wild.peaks = 1; wild.window_ms = 50; d.configure(wild);
    CHECK_EQ(d.params().g, g_range.lo); CHECK_EQ(int(d.params().peaks), int(peaks_range.lo)); CHECK_EQ(int(d.params().window_ms), int(window_ms_range.lo));
    wild.g = 9.0f; wild.peaks = 200; wild.window_ms = 60000; d.configure(wild);
    CHECK_EQ(d.params().g, g_range.hi); CHECK_EQ(int(d.params().peaks), int(peaks_range.hi)); CHECK_EQ(int(d.params().window_ms), int(window_ms_range.hi));
}

GUARDIAN_CASE(reset_forgets_a_pending_shake_but_keeps_the_count) {
    Detector d; std::int64_t t = 0;
    for (int i = 0; i < 500; ++i) { const float a[3] = {0, 2.0f * std::sin(two_pi * 5.0f * static_cast<float>(i) * 0.005f), 1}; t += 5000; d.sample(a, t); }
    CHECK_EQ(d.events(), 1u);
    d.reset(); CHECK(!d.take()); CHECK_EQ(d.events(), 1u);
}

GUARDIAN_CASE(defaults_lie_inside_their_tune_ranges) {
    const Params d{};
    CHECK(d.g >= g_range.lo && d.g <= g_range.hi);
    CHECK(float(d.peaks) >= peaks_range.lo && float(d.peaks) <= peaks_range.hi);
    CHECK(float(d.window_ms) >= window_ms_range.lo && float(d.window_ms) <= window_ms_range.hi);
    CHECK_EQ(d.g, 1.2f); CHECK_EQ(int(d.peaks), 8); CHECK_EQ(int(d.window_ms), 1500);   // the measured S3/S3b values
}

GUARDIAN_CASE(recorded_device_traces_classify_as_labelled) {
    // Shakes fired per 10 s trace with the defaults (MEASURED offline 2026-11-17, same rule):
    // "drop" is the first attempt at a drop, which was handling and reads as a shake; "drop2" is the
    // real hands-off drops (three impacts of 6.5..8.8 g).
    const struct { const char* label; std::uint32_t fires; } traces[] = {
        {"still", 0}, {"tap", 0}, {"front3", 0}, {"walk", 0}, {"setdown", 0}, {"drop2", 0},
        {"shake", 1}, {"softshake", 1}, {"drop", 2}};
    for (const auto& tr : traces) {
        int samples = 0; const auto fired = fires_in_trace(tr.label, samples);
        if (fired != tr.fires || samples < 1600) std::printf("     %s: fired %u (want %u), samples %d\n", tr.label, unsigned(fired), unsigned(tr.fires), samples);
        CHECK(samples >= 1600); CHECK_EQ(fired, tr.fires);
    }
}

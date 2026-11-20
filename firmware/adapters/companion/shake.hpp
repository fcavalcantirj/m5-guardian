#pragma once
#include <array>
#include <cstdint>

// G16I: "the stick is being shaken" from raw accelerometer samples. SDK-free, host-tested, and
// independent of the screen axis map (it works on the IMU's own three axes).
//
// Rule, proven on nine traces recorded on the StickS3 on 2026-11-17 (tests/fixtures/imu/, spike
// results in firmware/evidence/G16I-plan-upright-burst-20261117.md):
//  * gravity = each axis low-passed with a 1 s time constant; motion = sample - gravity;
//  * the DOMINANT axis (largest |motion|) is above +g or below -g: a signed peak;
//  * an ALTERNATION = a peak of the other sign than the peak before it, at least 60 ms after it;
//  * a SHAKE = `peaks` alternations inside `window_ms`; then nothing fires for 1000 ms.
// Measured alternations in the best 1500 ms at 1.2 g: hard shake 16, gentlest shake 11 (fire);
// the FRONT x3 update gesture 6, hands-off drops onto a cushion 5, tap / still / walking / set
// down 0 (never fire). A tap is one impulse, walking stays under the threshold, a drop is one
// impact per fall and a steady spin pulls one way only, so none of them alternates enough.
// What it cannot tell apart by count: one short wiggle (about three swings) and FRONT x3; neither fires.
namespace guardian::companion::shake {

struct Range { float lo, hi; };
// Live TUNE ranges (single source for the board's shake.* keys; shake_check keeps defaults inside).
constexpr Range g_range{0.5f, 4.0f}, peaks_range{2.0f, 16.0f}, window_ms_range{200.0f, 3000.0f};
constexpr std::int64_t min_gap_us = 60000;        // two peaks closer than this are one swing (ringing)
constexpr std::int64_t refractory_us = 1000000;   // after a shake fires
constexpr float gravity_tau_s = 1.0f;

struct Params {
    float g{1.2f};                 // peak threshold on the dominant axis, gravity removed
    std::uint8_t peaks{8};         // alternations needed ...
    std::uint16_t window_ms{1500}; // ... inside this window
};

class Detector {
public:
    // Values outside the TUNE ranges are clamped. Pending alternations are dropped; the gravity estimate stays.
    void configure(const Params&);
    const Params& params() const { return p_; }
    // One accelerometer sample in g (IMU axes) with its monotonic time.
    void sample(const float acc_g[3], std::int64_t t_us);
    // True once per shake (the board asks every loop).
    bool take() { const bool f = pending_; pending_ = false; return f; }
    std::uint32_t events() const { return events_; }   // shakes since boot (STATUS shakes=)
    void reset();                                      // IMU absent or faulted: forget everything but the count
private:
    Params p_{};
    bool have_{}, pending_{}, fired_{};
    float gravity_[3]{};
    std::int64_t last_us_{}, peak_us_{}, fired_us_{};
    int sign_{};                   // sign of the last peak (0: none yet)
    std::array<std::int64_t, 16> at_{};   // times of the latest alternations (ring)
    std::uint8_t head_{}, count_{};
    std::uint32_t events_{};
};

} // namespace guardian::companion::shake

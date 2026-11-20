// Face motion (rewritten 2026-11-17, see adapters/companion/motion.hpp): a body floating in water
// inside the stick. Fake samples in screen axes (identity map: IMU x = right, y = up, z = out). At rest
// the accelerometer reads the UP vector (+1 g on the axis pointing up). Roll clockwise (as the viewer
// sees it) by t: up = (-sin t, cos t, 0); top tipped away by p: up = (0, cos p, sin p).
#include "check.hpp"
#include "motion.hpp"
#include "persona.hpp"
#include <cmath>
#include <cstdint>

using namespace guardian::companion::motion;

namespace {
constexpr float d2r = 0.01745329252f;
const AxisMap identity{1, 2, 3};
Params quiet() { Params p; p.bob_px = 0; p.sway_deg = 0; return p; }   // no idle life: exact values (upright off, the default since 2026-11-18)
Params level() { Params p = quiet(); p.upright = 1; return p; }        // G16I upright mode, switched on explicitly
Params fish() { Params p = quiet(); p.upright = 0; return p; }          // the bounded floating tilt (TUNE motion.upright = 0)
float turn_diff(float a, float b) { float d = std::fmod(a - b, 360.0f); if (d > 180.0f) d -= 360.0f; if (d < -180.0f) d += 360.0f; return d; }
struct Rig {
    Model m; std::int64_t t{0};
    explicit Rig(Params p = {}) { m.configure(identity, p); }
    void feed(int ms, const float acc[3], const float gyr[3] = nullptr) {
        for (int i = 0; i < ms / 5; ++i) {
            t += 5000; Reading r; r.t_us = t;
            for (int k = 0; k < 3; ++k) { r.acc_g[k] = acc[k]; r.gyr_dps[k] = gyr ? gyr[k] : 0.0f; }
            m.sample(r); m.step(t);
        }
    }
    const Output& o() const { return m.output(); }
};
void rolled(float deg, float a[3]) { a[0] = -std::sin(deg * d2r); a[1] = std::cos(deg * d2r); a[2] = 0; }
void pitched(float deg, float a[3]) { a[0] = 0; a[1] = std::cos(deg * d2r); a[2] = std::sin(deg * d2r); }
bool finite(const Output& o) {
    return std::isfinite(o.dx) && std::isfinite(o.dy) && std::isfinite(o.tilt_deg) && std::isfinite(o.scale)
        && std::isfinite(o.hud_dx) && std::isfinite(o.hud_dy);
}
const float upright[3] = {0, 1, 0};
} // namespace

GUARDIAN_CASE(axis_map_from_tune_values_accepts_only_signed_distinct_axes) {
    const auto m = axis_map_from(2, -1, 3); CHECK(m.valid()); CHECK_EQ(int(m.right), 2); CHECK_EQ(int(m.up), -1); CHECK_EQ(int(m.out), 3);
    CHECK(!axis_map_from(0, 0, 0).valid()); CHECK(!axis_map_from(1, 1, 3).valid()); CHECK(!axis_map_from(1, -1, 3).valid());
    CHECK(!axis_map_from(1.5f, 2, 3).valid()); CHECK(!axis_map_from(4, 2, 3).valid()); CHECK(!axis_map_from(NAN, 2, 3).valid());
}

GUARDIAN_CASE(no_imu_or_unmapped_is_inactive_and_exactly_still) {
    Model none; none.configure(AxisMap{}, {}); Reading r; r.t_us = 1000; r.acc_g[1] = 1; none.sample(r);
    const auto& o = none.step(2000);
    CHECK(!o.active); CHECK_EQ(o.dx, 0.0f); CHECK_EQ(o.dy, 0.0f); CHECK_EQ(o.tilt_deg, 0.0f); CHECK_EQ(o.scale, 1.0f);
    Model empty; empty.configure(identity, {}); CHECK(!empty.step(1000000).active);   // mapped, no samples
}

GUARDIAN_CASE(standing_upright_without_idle_life_is_centred) {
    Rig r(quiet()); r.feed(3000, upright);
    CHECK(r.o().active); CHECK(std::fabs(r.o().tilt_deg) < 0.1f); CHECK(std::fabs(r.o().dx) < 0.1f); CHECK(std::fabs(r.o().dy) < 0.1f);
}

GUARDIAN_CASE(it_is_alive_when_the_stick_is_still) {
    Rig r; const Params d{}; r.feed(2000, upright);
    float ymin = 1e9f, ymax = -1e9f, tmin = 1e9f, tmax = -1e9f;
    for (int i = 0; i < 1600; ++i) {   // 8 s
        r.feed(5, upright);
        ymin = std::fmin(ymin, r.o().dy); ymax = std::fmax(ymax, r.o().dy);
        tmin = std::fmin(tmin, r.o().tilt_deg); tmax = std::fmax(tmax, r.o().tilt_deg);
    }
    CHECK(ymax - ymin > d.bob_px);                      // a slow bob, never frozen
    CHECK(tmax - tmin > d.sway_deg);                    // and a slow sway
    CHECK(ymax < d.bob_px * 2.0f && ymin > -d.bob_px * 2.0f);   // gentle, around the centre
}

// The owner's bug (2026-11-17): the old model forgot a held tilt. Held = shown, for as long as held.
GUARDIAN_CASE(a_held_roll_keeps_it_level_in_the_water_and_drifts_it_to_the_high_side) {
    const Params d = fish();
    Rig r(d); r.feed(1000, upright);
    float a[3]; rolled(15, a); r.feed(5000, a);
    CHECK(std::fabs(r.o().roll_deg - 15.0f) < 0.5f);
    CHECK(std::fabs(r.o().tilt_deg - d.roll_gain * 15.0f) < 0.4f);    // roll_gain < 0: it rotates back, staying level
    CHECK(std::fabs(r.o().dx + d.drift_px_per_deg * 15.0f) < 0.3f);  // right side down: it drifts left, to the high side
    r.feed(10000, a);                                                  // still held 10 s later
    CHECK(std::fabs(r.o().tilt_deg - d.roll_gain * 15.0f) < 0.4f);
    CHECK(std::fabs(r.o().dx + d.drift_px_per_deg * 15.0f) < 0.3f);
    // roll_gain > 0 turns it WITH the stick instead (live TUNE motion.roll_gain).
    Params with = d; with.roll_gain = 0.8f; Rig w(with); w.feed(1000, upright); w.feed(5000, a);
    CHECK(std::fabs(w.o().tilt_deg - 12.0f) < 0.4f);
}

GUARDIAN_CASE(a_big_roll_meets_the_tank_wall_and_is_pulled_back) {
    Rig r(fish()); const Params d{}; float a[3]; rolled(60, a); r.feed(5000, a);
    CHECK(std::fabs(std::fabs(r.o().tilt_deg) - d.max_roll_deg) < 0.2f);
    CHECK(std::fabs(r.o().scale - (1.0f - d.pull_back)) < 0.01f);
    CHECK(finite(r.o()));
}

GUARDIAN_CASE(a_held_pitch_sinks_or_raises_it_and_stays) {
    const Params d = quiet(); Rig r(d); float a[3];
    pitched(20, a); r.feed(5000, a);
    CHECK(std::fabs(r.o().dy - d.pitch_px_per_deg * 20.0f) < 0.4f);
    pitched(-20, a); r.feed(5000, a);
    CHECK(std::fabs(r.o().dy + d.pitch_px_per_deg * 20.0f) < 0.4f);
}

GUARDIAN_CASE(water_gives_a_soft_wobble_then_rest) {
    const Params d = fish(); Rig r(d); r.feed(1000, upright);
    float a[3]; rolled(15, a);
    // A real 15-degree roll in 100 ms (gyro + accelerometer), then held.
    for (int i = 1; i <= 20; ++i) { float s[3]; rolled(15.0f * static_cast<float>(i) / 20.0f, s); const float g[3] = {0, 0, -150}; r.feed(5, s, g); }
    const float target = d.roll_gain * 15.0f;
    float peak = 0;
    for (int i = 0; i < 400; ++i) { r.feed(5, a); peak = std::fmin(peak, r.o().tilt_deg); }   // 2 s
    CHECK(peak < target * 1.05f);                       // past the target: a wobble, like a body in water
    CHECK(peak > target * 1.6f);                        // but soft
    r.feed(4000, a);
    CHECK(std::fabs(r.o().tilt_deg - target) < 0.03f * std::fabs(target) + 0.1f);   // then rest
}

GUARDIAN_CASE(a_shove_makes_it_lag_behind_then_swim_back) {
    const Params d = quiet(); Rig r(d); r.feed(2000, upright);
    const float shove[3] = {0.5f, 1.0f, 0.0f};          // the tank pushed to the right, no rotation
    float low = 0;
    for (int i = 0; i < 30; ++i) { r.feed(5, shove); low = std::fmin(low, r.o().dx); }
    for (int i = 0; i < 60; ++i) { r.feed(5, upright); low = std::fmin(low, r.o().dx); }
    CHECK(low < -2.0f);                                  // it lagged: moved left as the tank went right
    r.feed(6000, upright);
    CHECK(std::fabs(r.o().dx) < 1.0f);                   // and swam back
}

GUARDIAN_CASE(a_turn_swirls_it_then_it_eases_back) {
    const Params d = quiet(); Rig r(d); r.feed(1000, upright);
    const float spin[3] = {0, 90, 0};                    // 90 deg/s about the vertical
    r.feed(500, upright, spin);
    CHECK(std::fabs(r.o().yaw_deg) > 25.0f);
    CHECK(std::fabs(r.o().dx) > 3.0f); CHECK(std::fabs(r.o().dx) <= d.max_x_px + 1e-3f);
    r.feed(7000, upright);
    CHECK(std::fabs(r.o().dx) < 1.0f);
}

GUARDIAN_CASE(a_jolt_barely_moves_the_pose_estimate) {
    Rig r(quiet()); r.feed(2000, upright);
    const float jolt[3] = {2.0f, 1.0f, 0.0f};            // |acc| 2.2 g, no rotation
    r.feed(100, jolt);
    CHECK(std::fabs(r.o().roll_deg) < 2.0f);
}

GUARDIAN_CASE(lying_flat_is_calm_and_finite) {
    Rig r(quiet()); const float flat[3] = {0, 0, 1}; r.feed(3000, flat);
    CHECK(std::fabs(r.o().tilt_deg) < 0.5f); CHECK(std::fabs(r.o().dx) < 0.5f); CHECK(finite(r.o()));
}

GUARDIAN_CASE(shaking_stays_inside_the_tank_and_finite) {
    Params d; d.upright = 0; Rig r(d);
    for (int i = 0; i < 2000; ++i) {
        const float tt = static_cast<float>(i) * 0.005f;
        const float a[3] = {1.5f * std::sin(tt * 31.0f), 1.0f + std::cos(tt * 23.0f), 0.8f * std::sin(tt * 17.0f)};
        const float w[3] = {400.0f * std::sin(tt * 13.0f), 300.0f * std::cos(tt * 11.0f), 500.0f * std::sin(tt * 7.0f)};
        r.feed(5, a, w);
        CHECK(finite(r.o()));
        CHECK(std::fabs(r.o().tilt_deg) <= d.max_roll_deg + 1e-3f);
        CHECK(std::fabs(r.o().dx) <= d.max_x_px + 1e-3f); CHECK(std::fabs(r.o().dy) <= d.max_y_px + 1e-3f);
    }
}

GUARDIAN_CASE(samples_stopping_returns_to_inactive) {
    Rig r; r.feed(500, upright);
    CHECK(r.o().active);
    CHECK(!r.m.step(r.t + 2000000).active);
}

GUARDIAN_CASE(defaults_lie_inside_their_tune_ranges) {
    const Params d{};
    const auto in = [](float v, Range r) { return v >= r.lo && v <= r.hi; };
    CHECK(in(d.roll_gain, roll_gain_range)); CHECK(in(d.max_roll_deg, max_roll_range));
    CHECK(in(d.drift_px_per_deg, drift_gain_range)); CHECK(in(d.max_x_px, max_x_range));
    CHECK(in(d.pitch_px_per_deg, pitch_gain_range)); CHECK(in(d.max_y_px, max_y_range));
    CHECK(in(d.yaw_px_per_deg, yaw_gain_range)); CHECK(in(d.yaw_return_s, yaw_return_range));
    CHECK(in(d.inertia_px_per_g, inertia_range)); CHECK(in(d.float_hz, float_hz_range));
    CHECK(in(d.water_damping, water_damping_range)); CHECK(in(d.bob_px, bob_px_range)); CHECK(in(d.sway_deg, sway_deg_range));
    CHECK(in(d.fusion_tau_s, fusion_tau_range)); CHECK(in(d.pull_back, pull_back_range)); CHECK(in(d.parallax, parallax_range));
    CHECK(in(d.upright, upright_range)); CHECK(in(d.upright_fit, upright_fit_range));
    CHECK_EQ(d.upright, 0.0f); CHECK_EQ(d.upright_fit, 1.0f);   // owner 2026-11-18: upright off by default (the approved floating face), hood never clipped when on
    CHECK(d.water_damping < 1.0f);                       // water: underdamped by design
}

// ---- G16I: always upright by gravity (TUNE motion.upright = 1, the default) -------------------
// Owner 2026-11-17: "fawkes should always stand facing up, independent of the direction. his correct
// position is USB facing down, so he always stands up." Continuous counter-rotation, never 4-way snapping.
GUARDIAN_CASE(upright_counter_rotates_fully_through_a_quarter_turn) {
    Rig r(level()); r.feed(1000, upright); float a[3];
    for (float deg : {15.0f, 30.0f, 45.0f, 60.0f, 75.0f, 90.0f}) {     // every angle on the way, not four snaps
        rolled(deg, a); r.feed(3000, a);
        CHECK(std::fabs(r.o().roll_deg - deg) < 0.5f);
        CHECK(std::fabs(r.o().tilt_deg + deg) < 1.0f);                  // the whole roll, far past max_roll_deg: no tank wall
        CHECK(std::fabs(r.o().dx) < 0.5f);                              // and it stays centred (no drift to a side)
    }
    Rig l(level()); l.feed(1000, upright); rolled(-90, a); l.feed(4000, a);
    CHECK(std::fabs(l.o().tilt_deg - 90.0f) < 1.0f);                    // the other way round
    CHECK(finite(r.o())); CHECK(finite(l.o()));
}

GUARDIAN_CASE(upright_crosses_minus_180_without_spinning) {
    Rig r(level()); r.feed(1000, upright); float a[3];
    rolled(150, a); r.feed(4000, a);
    float prev = r.o().tilt_deg, worst = 0, most_forward = -1.0f;
    CHECK(std::fabs(turn_diff(prev, -150.0f)) < 1.0f);
    for (int deg = 152; deg <= 210; deg += 2) {                         // on through upside down: roll wraps +180 -> -180
        rolled(static_cast<float>(deg), a);
        for (int i = 0; i < 20; ++i) {                                  // 100 ms per 2 degrees, every 5 ms frame watched
            r.feed(5, a);
            worst = std::fmax(worst, std::fabs(turn_diff(r.o().tilt_deg, prev))); prev = r.o().tilt_deg;
            most_forward = std::fmax(most_forward, std::cos(r.o().tilt_deg * d2r));
        }
    }
    r.feed(4000, a);
    CHECK(worst < 3.0f);                                                // no jump between frames
    CHECK(most_forward < -0.7f);                                        // it never swung round through the front (stays within 45 degrees of upside down)
    CHECK(std::fabs(turn_diff(r.o().tilt_deg, 150.0f)) < 1.0f);        // -210 is the same picture as +150
    CHECK(std::fabs(r.o().tilt_deg) <= 181.0f);                         // the angle is kept on one turn
}

GUARDIAN_CASE(upright_holds_the_last_angle_when_lying_flat) {
    Rig r(level()); r.feed(1000, upright); float a[3];
    rolled(70, a); r.feed(4000, a);
    const float held = r.o().tilt_deg; CHECK(std::fabs(held + 70.0f) < 1.0f);
    const float flat[3] = {0, 0, 1}; r.feed(6000, flat);               // laid on its back: roll is undefined
    CHECK(std::fabs(r.o().tilt_deg - held) < 0.5f);                    // held: no spin and no return to 0
    const float nearly[3] = {0.15f, -0.1f, 0.98f}; r.feed(3000, nearly);   // in-plane gravity 0.18 < 0.3: still held
    CHECK(std::fabs(r.o().tilt_deg - held) < 0.5f);
    rolled(-20, a); r.feed(4000, a);                                    // picked up again: it follows again
    CHECK(std::fabs(r.o().tilt_deg - 20.0f) < 1.0f);
    Rig f(quiet()); f.feed(3000, flat);                                 // flat from the first sample: USB-down picture
    CHECK(f.o().active); CHECK(std::fabs(f.o().tilt_deg) < 0.5f); CHECK(finite(f.o()));
}

GUARDIAN_CASE(upright_fit_scale_keeps_the_hood_inside_the_band_at_every_angle) {
    namespace persona = guardian::companion::persona;
    Rig r(level()); r.feed(1000, upright); float a[3]; int outside = 0; float smallest = 1.0f;
    for (int deg = 0; deg <= 360; deg += 15) {
        rolled(static_cast<float>(deg), a); r.feed(3000, a);
        const auto& o = r.o(); smallest = std::fmin(smallest, o.scale);
        CHECK(std::fabs(turn_diff(o.tilt_deg, -static_cast<float>(deg))) < 1.0f);
        for (int k = 0; k < 4; ++k) {
            const auto p = persona::map_point(persona::Pose{o.tilt_deg, o.scale, o.dx, o.dy},
                persona::Point{static_cast<float>(k & 1 ? persona::hood_box.x1 : persona::hood_box.x0), static_cast<float>(k & 2 ? persona::hood_box.y1 : persona::hood_box.y0)});
            if (p.x < -0.5f || p.x > persona::art_w + 0.5f || p.y < -0.5f || p.y > persona::art_h + 0.5f) { ++outside; std::printf("     %d deg: corner %d at %.1f,%.1f\n", deg, k, double(p.x), double(p.y)); }
        }
    }
    CHECK_EQ(outside, 0);
    CHECK(smallest > 0.6f && smallest < 0.7f);                          // 45 degrees is the tightest fit (0.66)
    CHECK(std::fabs(r.o().scale - 1.0f) < 0.01f);                       // back standing: full size
    // motion.upright_fit = 0: it keeps its size (the owner's choice; the hood corners are cut while turned).
    Params keep = level(); keep.upright_fit = 0; Rig k(keep); k.feed(1000, upright); rolled(45, a); k.feed(3000, a);
    CHECK(std::fabs(k.o().scale - 1.0f) < 0.005f); CHECK(std::fabs(k.o().tilt_deg + 45.0f) < 1.0f);
}

GUARDIAN_CASE(upright_is_exactly_still_under_sensor_noise_at_rest) {
    for (float base : {0.0f, 30.0f, -117.0f}) {
        Rig r(level()); float a[3]; rolled(base, a); r.feed(4000, a);
        // +-0.2 degrees of roll noise, slow enough (1 s each way) to get through the fusion filter.
        const auto noisy = [&](int frames, bool watch) {
            const float t0 = r.o().tilt_deg, s0 = r.o().scale; int moved = 0;
            for (int i = 0; i < frames; ++i) {
                rolled(base + ((i / 25) % 2 ? 0.2f : -0.2f), a); r.feed(40, a);
                // The tilt is bit-identical; the scale may breathe by less than one warp quantum (1/1024)
                // with the tiny shove the same noise makes.
                if (watch && (r.o().tilt_deg != t0 || std::fabs(r.o().scale - s0) > 0.0009f)) ++moved;
            }
            return moved;
        };
        noisy(100, false);                                              // let the deadband take its last step
        CHECK_EQ(noisy(100, true), 0);                                  // 100 frames at 25 fps: the same tilt, bit for bit
        CHECK(std::fabs(turn_diff(r.o().tilt_deg, -base)) < 0.8f);     // and still upright (within the deadband)
    }
}

GUARDIAN_CASE(upright_mode_exposes_gravity_and_shove_for_the_burst) {
    Rig r(level()); CHECK_EQ(r.o().up_x, 0.0f); CHECK_EQ(r.o().up_y, 0.0f); CHECK_EQ(r.o().lin_x, 0.0f); CHECK_EQ(r.o().lin_y, 0.0f);
    r.feed(2000, upright);
    CHECK(std::fabs(r.o().up_x) < 0.02f); CHECK(std::fabs(r.o().up_y + 1.0f) < 0.02f);       // standing: up is up the glass (-y)
    CHECK(std::fabs(r.o().lin_x) < 0.02f); CHECK(std::fabs(r.o().lin_y) < 0.02f);
    float a[3]; rolled(90, a); r.feed(4000, a);                         // clockwise quarter turn: the world's up is the screen's left
    CHECK(std::fabs(r.o().up_x + 1.0f) < 0.02f); CHECK(std::fabs(r.o().up_y) < 0.02f);
    const float flat[3] = {0, 0, 1}; r.feed(4000, flat);               // on its back: nothing falls across the glass
    CHECK(std::fabs(r.o().up_x) < 0.05f); CHECK(std::fabs(r.o().up_y) < 0.05f);
    Rig s(quiet()); s.feed(2000, upright);
    const float shove[3] = {0.8f, 0.6f, 0.0f};                          // pushed to the right and dropped a little
    s.feed(100, shove);
    CHECK(s.o().lin_x > 0.3f); CHECK(s.o().lin_y > 0.15f);             // +x right, +y down the glass
    CHECK(!s.m.step(s.t + 2000000).active);                             // samples stop: inactive, everything 0 again
    CHECK_EQ(s.o().up_x, 0.0f); CHECK_EQ(s.o().up_y, 0.0f); CHECK_EQ(s.o().lin_x, 0.0f); CHECK_EQ(s.o().lin_y, 0.0f);
}

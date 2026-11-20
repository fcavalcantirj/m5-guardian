#pragma once
#include <cstdint>
#include "guardian/time.hpp"

// How the Guardian's face reacts to the stick being handled (rewritten 2026-11-17 after the owner
// rejected the G16C spring model: "radically weak", "doesn't tilt", white flashes). SDK-free and
// host-tested with fake samples.
//
// Method (the owner's own Stackfall, ~/dev/m5/sticks3-tetris, proven on this board: an ABSOLUTE
// held angle from gravity, never a spring that forgets it; axes per the StickS3 manual p.6-7 and
// Stackfall include/imu_axes.h: X along the stick toward USB-C, Y right, Z out of the screen):
//  * A complementary filter keeps the "up" direction: the gyroscope rotates it (fluid, instant),
//    the accelerometer pulls it back (no drift; short jolts barely move it).
//  * Three axes, held for as long as the stick is held:
//      roll  (rotation about the screen normal) -> it keeps itself level in the water (roll_gain < 0;
//            > 0 turns WITH the stick) and drifts toward the high side (buoyancy),
//      pitch (top tipping away / toward)        -> it sinks / rises a little,
//      yaw   (turning about the vertical; gyro only, no absolute reference) -> a sideways swirl that
//            eases back to centre over yaw_return_s.
//  * Shoves (linear acceleration = accelerometer minus "up") push it the other way (inertia).
//  * "Up" is the calibrated screen axis (TUNE imu.*): standing upright = centred. Nothing adapts a
//    "rest" pose, and nothing snaps the face back while the stick is held still at an angle.
//  * Water: an underdamped oscillator per axis (float_hz, water_damping) - soft wobble, then rest;
//    a slow bob and sway keep it alive when the stick is still.
//  * pull_back scales the face down at the bounds so the hood (edge to edge at rest) stays on the glass.
// Unmapped axes or no IMU: inactive, every output exactly 0 (scale 1). Decoration only: it never
// changes what is displayed about Wi-Fi.
namespace guardian::companion::motion {

// Signed IMU axis per screen axis: +1/-1 = +x/-x, 2 = y, 3 = z; 0 = unset.
struct AxisMap {
    std::int8_t right{}, up{}, out{};
    bool valid() const;   // each axis set exactly once, signs free
};
// From TUNE values (floats): each an exact integer in -3..3, nonzero, the three distinct; else unset.
AxisMap axis_map_from(float right, float up, float out);

// Live TUNE ranges (single source for the board's motion.* keys; motion_check keeps defaults inside).
struct Range { float lo, hi; };
constexpr Range roll_gain_range{-2.0f, 2.0f}, max_roll_range{0.0f, 45.0f}, drift_gain_range{0.0f, 2.0f},
                max_x_range{0.0f, 30.0f}, pitch_gain_range{0.0f, 2.0f}, max_y_range{0.0f, 30.0f},
                yaw_gain_range{0.0f, 2.0f}, yaw_return_range{0.2f, 10.0f}, inertia_range{0.0f, 60.0f},
                float_hz_range{0.3f, 6.0f}, water_damping_range{0.05f, 1.5f}, bob_px_range{0.0f, 6.0f},
                sway_deg_range{0.0f, 6.0f}, fusion_tau_range{0.05f, 2.0f}, pull_back_range{0.0f, 0.3f},
                parallax_range{0.0f, 1.0f}, upright_range{0.0f, 1.0f}, upright_fit_range{0.0f, 1.0f};

// 2026-11-17 owner: "imagine he's almost a fish living inside, floating... reacting to the environment".
// The face is a body floating in water inside the stick: it keeps itself level, lags behind shoves,
// drifts toward the high side when tipped, wobbles softly, and is never frozen (slow bob and sway).
struct Params {
    float roll_gain{-0.8f};       // on-glass rotation per degree of roll: - = it keeps itself level in the water, + = with the stick
    float max_roll_deg{20.0f};    // rotation bound
    float drift_px_per_deg{0.25f};// buoyancy: drifts toward the high side when the stick is tipped sideways
    float max_x_px{14.0f};        // horizontal bound (the tank walls)
    float pitch_px_per_deg{0.3f}; // top tipping away -> it sinks a little (px down per degree)
    float max_y_px{12.0f};        // vertical bound
    float yaw_px_per_deg{0.5f};   // turning the stick swirls it sideways ...
    float yaw_return_s{1.5f};     // ... and the swirl eases back to centre
    float inertia_px_per_g{14.0f};// a shove: it lags behind the tank by this much per g of linear acceleration
    float float_hz{1.2f};         // water: slow natural frequency
    float water_damping{0.3f};    // zeta < 1: a couple of soft wobbles before it settles
    float bob_px{1.5f};           // alive when still: slow vertical bob ...
    float bob_s{3.2f};
    float sway_deg{1.5f};         // ... and a slow sway
    float sway_s{4.7f};
    float fusion_tau_s{0.3f};     // accelerometer correction time constant (gyro carries faster motion)
    float pull_back{0.10f};       // scale lost at the bounds (keeps the hood on the glass)
    float parallax{0.6f};         // HUD decoration offset as a fraction of the face shift
    // G16I (owner 2026-11-17: "fawkes should always stand facing up ... USB facing down, so he always
    // stands up"): >= 0.5 = the face counter-rotates by the WHOLE roll, continuously, like a level
    // (tilt = -roll, taken the short way across +-180, so no spin). In this mode there is no tank wall
    // on the rotation (max_roll_deg and roll_gain are not used) and no sideways drift with the roll
    // (it would hold the face off centre and clip the hood); lying flat (in-plane gravity under 0.3)
    // HOLDS the last angle; a 0.5 degree deadband keeps sensor noise out of a resting picture.
    // 0 = the bounded floating tilt above (roll_gain, max_roll_deg, drift).
    float upright{0.0f};  // OWNER 2026-11-18: off by default (the approved floating face); 1 = stand up by gravity (G16I), holds when flat
    // G16I: 1 = the face shrinks just enough at each angle that the hood never leaves the glass
    // (persona::fit_scale); 0 = it keeps its size and the hood corners are cut while turned.
    float upright_fit{1.0f};
};

struct Reading {
    std::int64_t t_us{};          // monotonic time of the sample
    float acc_g[3]{};             // IMU axes
    float gyr_dps[3]{};
};

struct Output {
    bool active{};                // mapped axes and samples are flowing
    float dx{}, dy{};             // face shift (screen px, +x right, +y down)
    float tilt_deg{};             // face rotation (degrees, + = clockwise on the glass)
    float scale{1.0f};            // face pull-back (1 when centred)
    float roll_deg{}, pitch_deg{}, yaw_deg{};   // the device pose (for STATUS)
    float hud_dx{}, hud_dy{};     // HUD decoration parallax (px)
    std::int64_t newest_us{};     // time of the newest sample used (IMU-to-glass latency)
    // G16I, for the burst (screen axes: +x right, +y DOWN the glass; 0 when inactive):
    float up_x{}, up_y{};         // the world's up in the screen plane (standing: 0, -1); things fall along -up
    float lin_x{}, lin_y{};       // the stick's linear acceleration, g (a shove; loose things lag the other way)
};

class Model {
public:
    void configure(const AxisMap&, const Params&);
    void sample(const Reading&);                 // one IMU reading (the board feeds the 200 Hz ring)
    const Output& step(std::int64_t now_us);     // advance the follower to now_us (Reading clock)
    const Output& output() const { return out_; }
    void reset();                                // inactive (IMU absent/faulted, or the map changed)
private:
    AxisMap map_{};
    Params p_{};
    Output out_{};
    bool have_up_{};
    float up_[3]{};               // estimated "up" (unit vector), screen axes
    float lin_[3]{};              // the tank's linear acceleration (g), screen axes, lightly smoothed
    float yaw_{};                 // integrated yaw, degrees (leaks to 0)
    float pos_[3]{}, vel_[3]{};   // follower state: dx, dy, tilt
    bool have_hold_{};            // G16I upright: the held tilt target exists
    float hold_{};                // ... degrees, in (-180, 180]; pos_[2] is kept on the same turn
    std::int64_t last_us_{}, last_step_us_{};
};

} // namespace guardian::companion::motion

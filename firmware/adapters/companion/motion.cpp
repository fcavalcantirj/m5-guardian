// Guardian face motion (rewritten 2026-11-17): complementary-filter "up", three held axes, a body
// floating in water (underdamped, inertia, buoyancy, idle bob/sway). See motion.hpp. Float only.
#include "motion.hpp"
#include "persona.hpp"
#include <algorithm>
#include <cmath>
#include <cstdlib>

namespace guardian::companion::motion {
namespace {
constexpr float rad_to_deg = 57.29577951f, deg_to_rad = 0.01745329252f;
constexpr std::int64_t stale_us = 1000000; // no sample for 1 s: inactive
constexpr float max_dt_s = 0.05f;          // one sample never integrates more than this (stalls)
constexpr float step_s = 0.002f;           // follower substep
constexpr float max_integrate_s = 0.25f;   // after a stall, the follower integrates at most this much
// G16I upright:
constexpr float flat_in_plane = 0.3f;      // in-plane gravity below this (about 17 degrees from flat): roll is not trusted, hold
constexpr float rest_deadband_deg = 0.5f;  // the held target moves only for a change larger than this (sensor noise stays out)
constexpr float settle_deg = 0.02f, settle_dps = 0.1f;   // closer and slower than this: it IS at the target (under one warp quantum)
float clampf(float v, float lim) { return std::max(-lim, std::min(lim, v)); }
bool axis_ok(std::int8_t a) { return a != 0 && a >= -3 && a <= 3; }
void normalize(float v[3]) {
    const float n = std::sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
    if (n > 1e-6f) for (int i = 0; i < 3; ++i) v[i] /= n;
}
}

bool AxisMap::valid() const {
    if (!axis_ok(right) || !axis_ok(up) || !axis_ok(out)) return false;
    const int r = std::abs(right), u = std::abs(up), o = std::abs(out);
    return r != u && r != o && u != o;
}

AxisMap axis_map_from(float right, float up, float out) {
    AxisMap m{};
    const float v[3] = {right, up, out};
    std::int8_t a[3]{};
    for (int i = 0; i < 3; ++i) {
        if (!std::isfinite(v[i]) || v[i] != std::round(v[i]) || v[i] < -3.0f || v[i] > 3.0f) return {};
        a[i] = static_cast<std::int8_t>(v[i]);
    }
    m.right = a[0]; m.up = a[1]; m.out = a[2];
    return m.valid() ? m : AxisMap{};
}

void Model::configure(const AxisMap& m, const Params& p) {
    const bool same = m.right == map_.right && m.up == map_.up && m.out == map_.out;
    map_ = m; p_ = p;
    if (!same) reset();
}

void Model::reset() {
    have_up_ = false; yaw_ = 0; have_hold_ = false; hold_ = 0;
    for (int i = 0; i < 3; ++i) { up_[i] = lin_[i] = pos_[i] = vel_[i] = 0; }
    last_us_ = last_step_us_ = 0;
    out_ = {};
}

void Model::sample(const Reading& r) {
    if (!map_.valid()) return;
    // IMU axes -> screen axes (right, up, out).
    const std::int8_t axes[3] = {map_.right, map_.up, map_.out};
    float acc[3], gyr[3];
    for (int i = 0; i < 3; ++i) {
        const int a = std::abs(axes[i]) - 1; const float s = axes[i] > 0 ? 1.0f : -1.0f;
        acc[i] = s * r.acc_g[a]; gyr[i] = s * r.gyr_dps[a] * deg_to_rad;
    }
    if (!have_up_) {   // first sample: the accelerometer is the best "up" we have
        for (int i = 0; i < 3; ++i) up_[i] = acc[i];
        normalize(up_); have_up_ = true; last_us_ = r.t_us; out_.newest_us = r.t_us;
        return;
    }
    const float dt = std::min(max_dt_s, std::max(0.0f, static_cast<float>(r.t_us - last_us_) * 1e-6f));
    last_us_ = r.t_us; out_.newest_us = r.t_us;
    // Gyro: a world-fixed vector seen from the rotating body turns by -omega x v.
    const float c0 = gyr[1] * up_[2] - gyr[2] * up_[1];
    const float c1 = gyr[2] * up_[0] - gyr[0] * up_[2];
    const float c2 = gyr[0] * up_[1] - gyr[1] * up_[0];
    up_[0] -= c0 * dt; up_[1] -= c1 * dt; up_[2] -= c2 * dt;
    // Accelerometer: pull back toward measured gravity (drift-free), weighted by how close |acc| is to 1 g
    // so a jolt (|acc| far from 1 g) is mostly ignored.
    const float mag = std::sqrt(acc[0] * acc[0] + acc[1] * acc[1] + acc[2] * acc[2]);
    if (mag > 1e-3f) {
        const float trust = std::max(0.0f, 1.0f - std::fabs(mag - 1.0f) / 0.5f);
        const float alpha = trust * dt / (p_.fusion_tau_s + dt);
        for (int i = 0; i < 3; ++i) up_[i] += alpha * (acc[i] / mag - up_[i]);
    }
    normalize(up_);
    // The tank's linear acceleration: what the accelerometer reads beyond gravity (lightly smoothed).
    {   const float k = dt / (0.03f + dt);
        for (int i = 0; i < 3; ++i) lin_[i] += k * ((acc[i] - up_[i]) - lin_[i]); }
    // Yaw: rotation rate about "up" (the world vertical), integrated, easing back to centre.
    const float yaw_rate = (gyr[0] * up_[0] + gyr[1] * up_[1] + gyr[2] * up_[2]) * rad_to_deg;
    yaw_ += yaw_rate * dt;
    yaw_ *= std::exp(-dt / std::max(0.05f, p_.yaw_return_s));
}

const Output& Model::step(std::int64_t now_us) {
    if (!map_.valid() || !have_up_ || now_us - last_us_ > stale_us) {
        if (have_up_ && now_us - last_us_ > stale_us) reset();   // samples stopped: back to inactive
        out_.active = false; out_.dx = out_.dy = out_.tilt_deg = out_.hud_dx = out_.hud_dy = 0;
        out_.roll_deg = out_.pitch_deg = out_.yaw_deg = 0; out_.scale = 1.0f;
        out_.up_x = out_.up_y = out_.lin_x = out_.lin_y = 0;
        return out_;
    }
    // Device pose from "up" in screen axes. Upright: up = (0, 1, 0).
    // Roll (clockwise as the viewer sees it, +): the world's up leans toward the screen's left.
    const float roll = std::atan2(-up_[0], up_[1]) * rad_to_deg;
    // Pitch (top tipping away from the viewer, +): the world's up gains the screen's out direction.
    const float pitch = std::atan2(up_[2], std::sqrt(up_[0] * up_[0] + up_[1] * up_[1])) * rad_to_deg;
    // Lying flat, the in-plane roll is undefined: weight it by how upright the stick is.
    const float in_plane = std::sqrt(up_[0] * up_[0] + up_[1] * up_[1]);
    const float w = std::min(1.0f, in_plane / 0.5f);
    // Where the floating body wants to be (targets), plus its slow life when still.
    const float t_s = static_cast<float>(now_us % 600000000LL) * 1e-6f;
    const float bob = p_.bob_px * std::sin(2.0f * 3.14159265f * t_s / std::max(0.5f, p_.bob_s));
    const float sway = p_.sway_deg * std::sin(2.0f * 3.14159265f * t_s / std::max(0.5f, p_.sway_s));
    // G16I upright: the face turns back by the whole roll, like a level. The held target follows -roll
    // on the turn nearest to itself (crossing +-180 is a small step, never a spin), only while the
    // roll is defined (not lying flat) and only for a change beyond the deadband.
    const bool level = p_.upright >= 0.5f;
    if (level) {
        if (in_plane >= flat_in_plane) {
            float want = -roll;
            if (have_hold_) want += 360.0f * std::round((hold_ - want) / 360.0f);
            if (!have_hold_ || std::fabs(want - hold_) > rest_deadband_deg) { hold_ = want; have_hold_ = true; }
        } else if (!have_hold_) { hold_ = 0; have_hold_ = true; }   // flat since the first sample: the USB-down picture
        // Keep the angle on one turn; the follower moves with it, so nothing is seen.
        if (hold_ > 180.0f) { hold_ -= 360.0f; pos_[2] -= 360.0f; }
        else if (hold_ <= -180.0f) { hold_ += 360.0f; pos_[2] += 360.0f; }
    } else have_hold_ = false;
    const float target[3] = {
        clampf((level ? 0.0f : -p_.drift_px_per_deg * w * roll) + p_.yaw_px_per_deg * yaw_, p_.max_x_px),   // buoyancy + swirl
        clampf(p_.pitch_px_per_deg * pitch + bob, p_.max_y_px),                             // sink/rise + bob
        level ? hold_ + sway : clampf(w * p_.roll_gain * roll + sway, p_.max_roll_deg)};    // upright, or stays level + sway
    // Inertia: the tank's acceleration pushes the body the other way (screen +y is down).
    const float push[2] = {-p_.inertia_px_per_g * lin_[0], p_.inertia_px_per_g * lin_[1]};
    // Water: an underdamped oscillator per axis (soft wobble, then rest).
    const float w0 = 2.0f * 3.14159265f * std::max(0.1f, p_.float_hz), z = std::max(0.01f, p_.water_damping);
    float remaining = last_step_us_ ? std::min(max_integrate_s, std::max(0.0f, static_cast<float>(now_us - last_step_us_) * 1e-6f)) : 0.0f;
    if (!last_step_us_) { for (int i = 0; i < 3; ++i) { pos_[i] = target[i]; vel_[i] = 0; } }   // first frame: start in place
    last_step_us_ = now_us;
    const float bound[3] = {p_.max_x_px, p_.max_y_px, p_.max_roll_deg};
    while (remaining > 0) {
        const float h = std::min(step_s, remaining); remaining -= h;
        for (int i = 0; i < 3; ++i) {
            const float drive = i < 2 ? w0 * w0 * push[i] : 0.0f;
            vel_[i] += (w0 * w0 * (target[i] - pos_[i]) - 2.0f * z * w0 * vel_[i] + drive) * h;
            pos_[i] += vel_[i] * h;
            if (level && i == 2) continue;                                                             // upright: no wall on the rotation
            if (std::fabs(pos_[i]) > bound[i]) { pos_[i] = clampf(pos_[i], bound[i]); vel_[i] = 0; }   // the tank wall
        }
    }
    // Upright at rest: the follower has arrived, so the tilt is exactly constant frame after frame.
    if (level && std::fabs(target[2] - pos_[2]) < settle_deg && std::fabs(vel_[2]) < settle_dps) { pos_[2] = target[2]; vel_[2] = 0; }
    out_.active = true;
    out_.dx = pos_[0]; out_.dy = pos_[1]; out_.tilt_deg = pos_[2];
    out_.roll_deg = roll; out_.pitch_deg = pitch; out_.yaw_deg = yaw_;
    const float sx = p_.max_x_px > 0 ? std::fabs(pos_[0]) / p_.max_x_px : 0.0f;
    const float sy = p_.max_y_px > 0 ? std::fabs(pos_[1]) / p_.max_y_px : 0.0f;
    const float st = !level && p_.max_roll_deg > 0 ? std::fabs(pos_[2]) / p_.max_roll_deg : 0.0f;
    out_.scale = 1.0f - p_.pull_back * std::min(1.0f, std::max(sx, std::max(sy, st)));
    // Upright: turned, the 133x157 hood (130x157 before G16Q part 2) no longer fits the 135x160 band; shrink it just enough.
    if (level) out_.scale *= 1.0f - std::max(0.0f, std::min(1.0f, p_.upright_fit)) * (1.0f - persona::fit_scale(pos_[2]));
    out_.up_x = up_[0]; out_.up_y = -up_[1];        // screen +y is down the glass
    out_.lin_x = lin_[0]; out_.lin_y = -lin_[1];
    out_.hud_dx = clampf(p_.parallax * pos_[0], p_.max_x_px * p_.parallax);
    out_.hud_dy = clampf(p_.parallax * pos_[1], p_.max_y_px * p_.parallax);
    return out_;
}

} // namespace guardian::companion::motion

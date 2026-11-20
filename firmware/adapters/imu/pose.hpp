#pragma once
// Review 2026-11-17: the still-pose reading that lets the owner calibrate the IMU axis map
// over Wi-Fi (the stick's real pose, upright with the USB port on the table, cannot have the
// cable in). SDK-free, header-only, host-tested in tests/imu_check.cpp.
//
// The firmware feeds every BMI270 sample; each completed block of `block_samples` (2 s at
// 200 Hz) is kept as the latest pose: the mean acceleration per axis (LSB) and the mean
// rotation-rate magnitude (deg/s), the same two numbers tools/imu_axis_map.py derives from a
// raw "IMU <s>" stream (read_trace: mean_g, gyro_dps), so its stillness, 1 g and
// dominant-axis rules apply unchanged. "IMU POSE" (USB and Wi-Fi) prints the latest block.
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include "bmi270.hpp"

namespace guardian::imu {

struct Pose {
    std::uint32_t samples{};
    std::array<float, 3> acc_mean_lsb{};
    float gyro_dps{};            // mean |gyro| over the block
    std::int64_t end_us{};       // t_us of the block's last sample
};

class PoseMeter {
public:
    static constexpr std::uint32_t block_samples = 2 * sample_hz;
    void add(const Sample& s) {
        for (int k = 0; k < 3; ++k) acc_sum_[k] += s.acc[k];
        const double gx = s.gyr[0] / double(gyr_lsb_per_dps), gy = s.gyr[1] / double(gyr_lsb_per_dps), gz = s.gyr[2] / double(gyr_lsb_per_dps);
        gyro_sum_ += std::sqrt(gx * gx + gy * gy + gz * gz);
        if (++n_ < block_samples) return;
        Pose p; p.samples = n_; p.end_us = s.t_us;
        for (int k = 0; k < 3; ++k) p.acc_mean_lsb[k] = float(double(acc_sum_[k]) / n_);
        p.gyro_dps = float(gyro_sum_ / n_);
        last_ = p; has_ = true; ++blocks_;
        n_ = 0; acc_sum_ = {}; gyro_sum_ = 0;
    }
    // Drops a partial block (the IMU stopped or restarted): the next pose is whole again.
    void reset_partial() { n_ = 0; acc_sum_ = {}; gyro_sum_ = 0; }
    bool latest(Pose& out) const { if (has_) out = last_; return has_; }
    std::uint32_t blocks() const { return blocks_; }
private:
    std::uint32_t n_{}, blocks_{};
    std::array<std::int64_t, 3> acc_sum_{};
    double gyro_sum_{};
    Pose last_{};
    bool has_{};
};

// One '\n'-terminated line; returns the length, 0 if it did not fit.
//   G16C IMU POSE samples=400 age_ms=812 acc_mean=12.5,-4089.0,40.2 gyro_dps=0.31 acc_lsb_per_g=4096
//   G16C IMU POSE none reason=<why>
inline std::size_t pose_text(const PoseMeter& m, bool running, std::int64_t now_us, char* out, std::size_t n) {
    Pose p; int w;
    if (!running) w = std::snprintf(out, n, "G16C IMU POSE none reason=imu_not_running\n");
    else if (!m.latest(p)) w = std::snprintf(out, n, "G16C IMU POSE none reason=no_block_yet\n");
    else {
        const long long age = now_us >= p.end_us ? (now_us - p.end_us) / 1000 : 0;
        w = std::snprintf(out, n, "G16C IMU POSE samples=%u age_ms=%lld acc_mean=%.1f,%.1f,%.1f gyro_dps=%.2f acc_lsb_per_g=%.0f\n",
                          unsigned(p.samples), age, double(p.acc_mean_lsb[0]), double(p.acc_mean_lsb[1]), double(p.acc_mean_lsb[2]),
                          double(p.gyro_dps), double(acc_lsb_per_g));
    }
    return w > 0 && static_cast<std::size_t>(w) < n ? static_cast<std::size_t>(w) : 0;
}

} // namespace guardian::imu

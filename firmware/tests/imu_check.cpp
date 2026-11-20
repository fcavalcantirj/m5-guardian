// G16A: BMI270 driver core against a register model of the device (host).
// The model follows the datasheet/Bosch upload semantics; it is not hardware
// proof. On-device streams are the reviewer's IMU command check.
#include "check.hpp"
#include "bmi270.hpp"
#include "bmi270_config.hpp"
#include "pose.hpp"
#include <cmath>
#include <cstring>
#include <vector>

using namespace guardian::imu;

namespace {
std::uint32_t crc32(const std::uint8_t* p, std::size_t n) {
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < n; ++i) { c ^= p[i]; for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u))); }
    return ~c;
}
class Fake final : public RegisterBus {
public:
    std::uint8_t at{0x68};            // 0 = nothing answers
    std::uint8_t chip{0x24};
    std::array<std::uint8_t, 128> r{};
    std::vector<std::uint8_t> image = std::vector<std::uint8_t>(bmi270_config_bytes, 0);
    bool adv_off_during_upload{true}, corrupt_load{}, fail_io{};
    unsigned corrupt_loads{};         // corrupt only the first N configuration loads (a transient failure)
    unsigned writes{}, reads{}, delays_ms{};
    std::vector<std::uint8_t> probed;
    std::vector<std::pair<std::uint8_t, std::uint8_t>> log;   // (reg, first byte) of each write
    bool read(std::uint8_t a, std::uint8_t reg, std::uint8_t* out, std::size_t n) override {
        ++reads; if (reg == 0) probed.push_back(a);
        if (fail_io || a != at) return false;
        for (std::size_t i = 0; i < n; ++i) {
            const auto x = static_cast<std::uint8_t>(reg + i);
            out[i] = x == 0 ? chip : r[x];
        }
        if (reg <= 0x03 && reg + n > 0x03) r[0x03] = 0;     // data-ready cleared by the read
        return true;
    }
    bool write(std::uint8_t a, std::uint8_t reg, const std::uint8_t* d, std::size_t n) override {
        ++writes; if (fail_io || a != at || n == 0) return false;
        log.emplace_back(reg, d[0]);
        if (reg == 0x5E) {
            const std::size_t base = (static_cast<std::size_t>(r[0x5C]) << 4 | (r[0x5B] & 0x0F)) * 2;
            if (r[0x7C] & 1) adv_off_during_upload = false;
            for (std::size_t i = 0; i < n && base + i < image.size(); ++i) image[base + i] = d[i];
            return true;
        }
        for (std::size_t i = 0; i < n; ++i) r[static_cast<std::uint8_t>(reg + i)] = d[i];
        if (reg == 0x7E && d[0] == 0xB6) { r.fill(0); r[0x7C] = 0x03; }   // soft reset: adv power save on
        if (reg == 0x59 && d[0] == 1) {
            const bool ok = !corrupt_load && corrupt_loads == 0 && adv_off_during_upload
                && std::memcmp(image.data(), bmi270_config_file, bmi270_config_bytes) == 0;
            if (corrupt_loads) --corrupt_loads;
            r[0x21] = ok ? 0x01 : 0x02;
        }
        return true;
    }
    void delay_ms(std::uint32_t ms) override { delays_ms += ms; }
    void sample(std::int16_t ax, std::int16_t ay, std::int16_t az, std::int16_t gx, std::int16_t gy, std::int16_t gz, std::uint32_t st) {
        const std::int16_t v[6] = {ax, ay, az, gx, gy, gz};
        for (int i = 0; i < 6; ++i) { r[0x0C + 2 * i] = std::uint8_t(v[i] & 0xFF); r[0x0D + 2 * i] = std::uint8_t((v[i] >> 8) & 0xFF); }
        r[0x18] = std::uint8_t(st); r[0x19] = std::uint8_t(st >> 8); r[0x1A] = std::uint8_t(st >> 16);
        r[0x03] = 0xC0;   // drdy_acc | drdy_gyr
    }
};
}

GUARDIAN_CASE(config_blob_is_bosch_v2_113_0) {
    CHECK_EQ(bmi270_config_bytes, std::size_t{8192});
    CHECK_EQ(crc32(bmi270_config_file, bmi270_config_bytes), bmi270_config_crc32);
    CHECK_EQ(bmi270_config_file[0], 0xc8); CHECK_EQ(bmi270_config_file[1], 0x2e);   // first bytes of the Bosch array
}

GUARDIAN_CASE(probes_0x68_first_then_0x69_and_reports_absence_without_writing) {
    Fake f; f.at = 0x69; Bmi270 imu;
    CHECK(imu.begin(f) == State::Running); CHECK_EQ(imu.address(), 0x69);
    CHECK(f.probed.size() >= 2u); if (f.probed.size() >= 2u) { CHECK_EQ(f.probed[0], 0x68); CHECK_EQ(f.probed[1], 0x69); }
    Fake none; none.at = 0; Bmi270 absent;
    CHECK(absent.begin(none) == State::Absent); CHECK_EQ(none.writes, 0u);
    CHECK(std::strlen(absent.failure()) > 0);
    Fake other; other.chip = 0x26; Bmi270 wrong;                    // something else answers at 0x68/0x69
    CHECK(wrong.begin(other) == State::Absent); CHECK_EQ(other.writes, 0u);
}

GUARDIAN_CASE(init_uploads_the_exact_blob_and_configures_200_hz) {
    Fake f; Bmi270 imu;
    CHECK(imu.begin(f) == State::Running); CHECK_EQ(imu.address(), 0x68);
    CHECK(std::memcmp(f.image.data(), bmi270_config_file, bmi270_config_bytes) == 0);
    CHECK(f.adv_off_during_upload);
    CHECK_EQ(f.r[reg::pwr_ctrl], 0x0E); CHECK_EQ(f.r[reg::acc_conf], 0xA9); CHECK_EQ(f.r[reg::gyr_conf], 0xA9);
    CHECK_EQ(f.r[reg::acc_range], 0x02); CHECK_EQ(f.r[reg::gyr_range], 0x00); CHECK_EQ(f.r[reg::pwr_conf], 0x02);
    CHECK(f.delays_ms >= 20u);                                       // waited for the load result
    // Order: reset before upload, INIT_CTRL 0 before data, INIT_CTRL 1 after it, sensors enabled last.
    std::size_t reset = 99999, ctrl0 = 99999, first_data = 99999, ctrl1 = 99999, enable = 99999;
    for (std::size_t i = 0; i < f.log.size(); ++i) {
        const auto [r, v] = f.log[i];
        if (r == 0x7E && v == 0xB6 && reset == 99999) reset = i;
        if (r == 0x59 && v == 0 && ctrl0 == 99999) ctrl0 = i;
        if (r == 0x5E && first_data == 99999) first_data = i;
        if (r == 0x59 && v == 1) ctrl1 = i;
        if (r == 0x7D) enable = i;
    }
    CHECK(reset < ctrl0); CHECK(ctrl0 < first_data); CHECK(first_data < ctrl1); CHECK(ctrl1 < enable);
}

// 2026-11-18 (device, MEASURED): after the OTA's software restart the BMI270 answered its chip id but the init
// failed, and it came back only after a hardware reset. One more attempt after a pause recovers a transient state.
GUARDIAN_CASE(a_transient_configuration_failure_is_retried_once_after_a_pause) {
    Fake f; f.corrupt_loads = 1; Bmi270 imu;
    CHECK(imu.begin(f) == State::Running);
    unsigned resets = 0; for (const auto& w : f.log) if (w.first == 0x7E && w.second == 0xB6) ++resets;
    CHECK_EQ(resets, 2u);                                             // a full second attempt, soft reset included
    CHECK(f.delays_ms >= Bmi270::init_retry_delay_ms);
    Sample s; f.sample(1, 2, 3, 4, 5, 6, 7); CHECK(imu.poll(f, 1000, s));
}

GUARDIAN_CASE(a_persistent_configuration_failure_is_reported_after_two_attempts) {
    Fake f; f.corrupt_load = true; Bmi270 imu;
    CHECK(imu.begin(f) == State::InitFailed); CHECK(std::strlen(imu.failure()) > 0);
    unsigned resets = 0; for (const auto& w : f.log) if (w.first == 0x7E && w.second == 0xB6) ++resets;
    CHECK_EQ(resets, 2u);
    CHECK_EQ(f.r[reg::pwr_ctrl], 0x00);                              // sensors never enabled
    Sample s; CHECK(!imu.poll(f, 1000, s));
    Fake io; Bmi270 broken; io.at = 0x68;
    CHECK(broken.begin(io) == State::Running);
    io.fail_io = true; Sample t;
    for (std::uint32_t i = 0; i < Bmi270::fault_after; ++i) CHECK(!broken.poll(io, 1000 + i, t));
    CHECK(broken.state() == State::Faulted); CHECK_EQ(broken.bus_errors(), Bmi270::fault_after);
    io.fail_io = false; io.sample(1, 2, 3, 4, 5, 6, 7); CHECK(!broken.poll(io, 5000, t));   // stays faulted until reboot
}

GUARDIAN_CASE(poll_decodes_signed_little_endian_samples_only_when_ready) {
    Fake f; Bmi270 imu; CHECK(imu.begin(f) == State::Running);
    Sample s;
    CHECK(!imu.poll(f, 100, s));                                     // no data ready yet
    f.sample(4096, -4096, -1, 32767, -32768, 16, 0xABCDEF);
    CHECK(imu.poll(f, 12345, s));
    CHECK_EQ(s.t_us, std::int64_t{12345}); CHECK_EQ(s.sensor_time, 0xABCDEFu);
    CHECK_EQ(s.acc[0], 4096); CHECK_EQ(s.acc[1], -4096); CHECK_EQ(s.acc[2], -1);
    CHECK_EQ(s.gyr[0], 32767); CHECK_EQ(s.gyr[1], -32768); CHECK_EQ(s.gyr[2], 16);
    CHECK(!imu.poll(f, 12350, s));                                   // the read consumed data-ready
}

GUARDIAN_CASE(ring_is_fifo_counts_drops_and_never_blocks_the_producer) {
    Ring<8> ring; Sample s;
    CHECK(!ring.pop(s));
    for (int i = 0; i < 10; ++i) { Sample x; x.t_us = i; ring.push(x); }
    CHECK_EQ(ring.pushed(), 8u); CHECK_EQ(ring.dropped(), 2u);
    for (int i = 0; i < 8; ++i) { CHECK(ring.pop(s)); CHECK_EQ(s.t_us, std::int64_t{i}); }
    CHECK(!ring.pop(s));
    Sample y; y.t_us = 42; CHECK(ring.push(y)); CHECK(ring.pop(s)); CHECK_EQ(s.t_us, std::int64_t{42});
}

// Review 2026-11-17: IMU POSE (Wi-Fi calibration) reports what tools/imu_axis_map.py reads.
GUARDIAN_CASE(pose_meter_reports_the_mean_of_each_complete_block) {
    PoseMeter m; Pose p; char line[160];
    CHECK(!m.latest(p));
    CHECK(pose_text(m, true, 0, line, sizeof line) > 0);
    CHECK(std::strstr(line, "none reason=no_block_yet") != nullptr);
    for (std::uint32_t i = 0; i + 1 < PoseMeter::block_samples; ++i) { Sample s; s.t_us = i; s.acc = {10, -4096, 30}; m.add(s); }
    CHECK(!m.latest(p));                                             // one sample short: nothing yet
    Sample last; last.t_us = 5000000; last.acc = {10, -4096, 30}; m.add(last);
    CHECK(m.latest(p)); CHECK_EQ(p.samples, PoseMeter::block_samples); CHECK_EQ(m.blocks(), 1u);
    CHECK(std::fabs(p.acc_mean_lsb[0] - 10.0f) < 0.01f); CHECK(std::fabs(p.acc_mean_lsb[1] + 4096.0f) < 0.01f);
    CHECK(std::fabs(p.gyro_dps) < 1e-6f); CHECK_EQ(p.end_us, std::int64_t{5000000});
    CHECK(pose_text(m, true, 5250000, line, sizeof line) > 0);
    CHECK(std::strstr(line, "G16C IMU POSE samples=400 age_ms=250 acc_mean=10.0,-4096.0,30.0 gyro_dps=0.00 acc_lsb_per_g=4096\n") != nullptr);
}

GUARDIAN_CASE(pose_meter_gyro_is_the_mean_rotation_magnitude) {
    PoseMeter m; Pose p;
    // Whole-LSB samples (49, -66, 0): |gyro| = sqrt(49^2 + 66^2) / 16.384 deg/s per sample.
    for (std::uint32_t i = 0; i < PoseMeter::block_samples; ++i) { Sample s; s.gyr = {49, -66, 0}; m.add(s); }
    const float expected = std::sqrt(49.0f * 49.0f + 66.0f * 66.0f) / gyr_lsb_per_dps;
    CHECK(m.latest(p)); CHECK(std::fabs(p.gyro_dps - expected) < 0.001f);
}

GUARDIAN_CASE(pose_meter_new_block_replaces_the_old_and_partials_are_dropped) {
    PoseMeter m; Pose p;
    for (std::uint32_t i = 0; i < PoseMeter::block_samples; ++i) { Sample s; s.acc = {4096, 0, 0}; m.add(s); }
    for (std::uint32_t i = 0; i < 100; ++i) { Sample s; s.acc = {0, 0, -4096}; m.add(s); }
    m.reset_partial();                                               // the IMU restarted: the 100 are dropped
    for (std::uint32_t i = 0; i < PoseMeter::block_samples; ++i) { Sample s; s.acc = {0, 4096, 0}; m.add(s); }
    CHECK(m.latest(p)); CHECK_EQ(m.blocks(), 2u);
    CHECK(std::fabs(p.acc_mean_lsb[0]) < 0.01f); CHECK(std::fabs(p.acc_mean_lsb[1] - 4096.0f) < 0.01f); CHECK(std::fabs(p.acc_mean_lsb[2]) < 0.01f);
}

GUARDIAN_CASE(pose_text_says_when_the_imu_is_not_running_and_never_overflows) {
    PoseMeter m; char line[160];
    for (std::uint32_t i = 0; i < PoseMeter::block_samples; ++i) { Sample s; s.acc = {-32768, 32767, -32768}; s.gyr = {32767, 32767, 32767}; m.add(s); }
    CHECK(pose_text(m, false, 0, line, sizeof line) > 0);
    CHECK(std::strstr(line, "none reason=imu_not_running") != nullptr);
    CHECK(pose_text(m, true, 0, line, sizeof line) > 0);              // widest values fit 160
    char tiny[20]; CHECK_EQ(pose_text(m, true, 0, tiny, sizeof tiny), std::size_t{0});
}

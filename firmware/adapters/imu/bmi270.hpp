#pragma once
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

// G16A native BMI270 driver core. SDK-free and host-tested against a register
// model: the board supplies a RegisterBus (ESP-IDF i2c_master on StickS3's
// internal bus, SDA 47 / SCL 48, shared with the PM1). No Arduino, no Bosch
// API linked: only Bosch's configuration blob (bmi270_config.hpp).
//
// Sequence (BMI270 datasheet quick start, Bosch BMI270_SensorAPI v2.113.0
// bmi2.c write_config_file/upload_file): probe CHIP_ID 0x24 at 0x68 then
// 0x69; soft reset; PWR_CONF.adv_power_save off; INIT_CTRL 0; upload the
// 8 KiB blob to INIT_DATA in chunks with INIT_ADDR_0/1 = (offset/2) & 0x0F /
// (offset/2) >> 4; INIT_CTRL 1; INTERNAL_STATUS message must read 1
// (init_ok); then accelerometer and gyroscope at 200 Hz.
namespace guardian::imu {

class RegisterBus {
public:
    virtual ~RegisterBus() = default;
    virtual bool read(std::uint8_t address, std::uint8_t reg, std::uint8_t* out, std::size_t n) = 0;
    virtual bool write(std::uint8_t address, std::uint8_t reg, const std::uint8_t* data, std::size_t n) = 0;
    virtual void delay_ms(std::uint32_t ms) = 0;
};

namespace reg {
constexpr std::uint8_t chip_id = 0x00, err = 0x02, status = 0x03, acc_x = 0x0C, gyr_x = 0x12, sensortime = 0x18;
constexpr std::uint8_t internal_status = 0x21, acc_conf = 0x40, acc_range = 0x41, gyr_conf = 0x42, gyr_range = 0x43;
constexpr std::uint8_t init_ctrl = 0x59, init_addr_0 = 0x5B, init_data = 0x5E;
constexpr std::uint8_t pwr_conf = 0x7C, pwr_ctrl = 0x7D, cmd = 0x7E;
}
// Chosen configuration: 200 Hz, normal filter, performance mode.
constexpr std::uint8_t acc_conf_200hz = 0xA9;   // filter_perf | bwp normal | odr 200 Hz
constexpr std::uint8_t gyr_conf_200hz = 0xA9;   // filter_perf | bwp normal | odr 200 Hz
constexpr std::uint8_t acc_range_8g = 0x02;     // 4096 LSB/g
constexpr std::uint8_t gyr_range_2000 = 0x00;   // 16.384 LSB/(deg/s)
constexpr std::uint8_t pwr_ctrl_acc_gyr_temp = 0x0E;
constexpr std::uint8_t pwr_conf_running = 0x02; // adv_power_save off, fifo_self_wake on
constexpr float acc_lsb_per_g = 4096.0f, gyr_lsb_per_dps = 16.384f;
constexpr std::uint32_t sample_hz = 200;

struct Sample {
    std::int64_t t_us{};            // host monotonic time of the read (caller's clock)
    std::uint32_t sensor_time{};    // BMI270 SENSORTIME, 24 bit, 39.0625 us per LSB
    std::array<std::int16_t, 3> acc{}, gyr{};
};

enum class State : std::uint8_t { Off, Absent, InitFailed, Running, Faulted };
const char* state_text(State);

class Bmi270 {
public:
    static constexpr std::uint8_t addresses[2] = {0x68, 0x69};   // 0x68 measured on this StickS3 unit
    static constexpr std::uint8_t expected_chip_id = 0x24;
    static constexpr std::size_t upload_chunk = 64;               // even, divides 8192
    static constexpr std::uint32_t fault_after = 10;              // consecutive bus errors while running

    // Probes and configures. Never retries forever: Absent/InitFailed are final until reboot.
    // Probe, soft reset, configuration upload, sensor setup. 2026-11-18 (device): one more full attempt after
    // init_retry_delay_ms when the first fails after the chip answered (a software restart mid-transaction
    // left the sensor in a state the first attempt rejected). Absent (no chip id) is not retried.
    static constexpr std::uint32_t init_retry_delay_ms = 50;
    State begin(RegisterBus&);
    // One sample if the device reports new data; false otherwise (including errors).
    bool poll(RegisterBus&, std::int64_t now_us, Sample& out);

    State state() const { return state_; }
    std::uint8_t address() const { return address_; }
    const char* failure() const { return failure_; }      // static text, "" when none
    std::uint32_t bus_errors() const { return bus_errors_; }
private:
    State attempt(RegisterBus&);
    State fail(State s, const char* why) { state_ = s; failure_ = why; return s; }
    bool set(RegisterBus&, std::uint8_t r, std::uint8_t v);
    State state_{State::Off};
    std::uint8_t address_{};
    const char* failure_{""};
    std::uint32_t bus_errors_{}, consecutive_{};
};

// Single-producer / single-consumer ring of timestamped samples (the IMU task
// produces, the companion loop consumes). Lock-free; full means the newest
// sample is dropped and counted, so the producer never waits.
template <std::size_t N>
class Ring {
    static_assert(N >= 2 && (N & (N - 1)) == 0, "power of two");
public:
    bool push(const Sample& s) {
        const auto h = head_.load(std::memory_order_relaxed);
        if (h - tail_.load(std::memory_order_acquire) >= N) { dropped_.fetch_add(1, std::memory_order_relaxed); return false; }
        buf_[h & (N - 1)] = s;
        head_.store(h + 1, std::memory_order_release);
        pushed_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    bool pop(Sample& out) {
        const auto t = tail_.load(std::memory_order_relaxed);
        if (t == head_.load(std::memory_order_acquire)) return false;
        out = buf_[t & (N - 1)];
        tail_.store(t + 1, std::memory_order_release);
        return true;
    }
    std::uint32_t pushed() const { return pushed_.load(std::memory_order_relaxed); }
    std::uint32_t dropped() const { return dropped_.load(std::memory_order_relaxed); }
private:
    std::array<Sample, N> buf_{};
    std::atomic<std::uint32_t> head_{0}, tail_{0}, pushed_{0}, dropped_{0};
};

} // namespace guardian::imu

// G16A BMI270 driver core. SDK-free; the board's RegisterBus does the I2C.
#include "bmi270.hpp"
#include "bmi270_config.hpp"

namespace guardian::imu {

const char* state_text(State s) {
    switch (s) {
    case State::Off: return "off"; case State::Absent: return "absent"; case State::InitFailed: return "init-failed";
    case State::Running: return "running"; case State::Faulted: return "faulted";
    }
    return "?";
}

bool Bmi270::set(RegisterBus& bus, std::uint8_t r, std::uint8_t v) { return bus.write(address_, r, &v, 1); }

State Bmi270::begin(RegisterBus& bus) {
    const State first = attempt(bus);
    if (first != State::InitFailed) return first;
    bus.delay_ms(init_retry_delay_ms);
    return attempt(bus);   // the second attempt's outcome and failure text stand
}

State Bmi270::attempt(RegisterBus& bus) {
    state_ = State::Off; failure_ = ""; address_ = 0;
    for (const auto a : addresses) {
        std::uint8_t id = 0;
        if (bus.read(a, reg::chip_id, &id, 1) && id == expected_chip_id) { address_ = a; break; }
    }
    if (!address_) return fail(State::Absent, "no chip id 0x24 at 0x68 or 0x69");
    // Soft reset to a known state, then wait for the device to restart (>= 2 ms).
    if (!set(bus, reg::cmd, 0xB6)) return fail(State::InitFailed, "soft reset write failed");
    bus.delay_ms(3);
    // Advanced power save off before the upload; the datasheet asks for >= 450 us.
    if (!set(bus, reg::pwr_conf, 0x00)) return fail(State::InitFailed, "PWR_CONF write failed");
    bus.delay_ms(1);
    if (!set(bus, reg::init_ctrl, 0x00)) return fail(State::InitFailed, "INIT_CTRL write failed");
    for (std::size_t at = 0; at < bmi270_config_bytes; at += upload_chunk) {
        const std::size_t word = at / 2;
        const std::uint8_t addr[2] = {static_cast<std::uint8_t>(word & 0x0F), static_cast<std::uint8_t>(word >> 4)};
        if (!bus.write(address_, reg::init_addr_0, addr, 2) || !bus.write(address_, reg::init_data, bmi270_config_file + at, upload_chunk))
            return fail(State::InitFailed, "configuration upload write failed");
    }
    if (!set(bus, reg::init_ctrl, 0x01)) return fail(State::InitFailed, "INIT_CTRL start failed");
    // The datasheet allows up to 20 ms for the load; poll a little longer.
    std::uint8_t status = 0; bool ok = false;
    for (int tries = 0; tries < 10 && !ok; ++tries) {
        bus.delay_ms(tries == 0 ? 20 : 10);
        ok = bus.read(address_, reg::internal_status, &status, 1) && (status & 0x0F) == 0x01;
    }
    if (!ok) return fail(State::InitFailed, "configuration load not acknowledged (INTERNAL_STATUS != init_ok)");
    // 200 Hz accelerometer and gyroscope, then leave the low-power configuration.
    if (!set(bus, reg::acc_conf, acc_conf_200hz) || !set(bus, reg::acc_range, acc_range_8g)
        || !set(bus, reg::gyr_conf, gyr_conf_200hz) || !set(bus, reg::gyr_range, gyr_range_2000)
        || !set(bus, reg::pwr_ctrl, pwr_ctrl_acc_gyr_temp) || !set(bus, reg::pwr_conf, pwr_conf_running))
        return fail(State::InitFailed, "sensor configuration write failed");
    // Read back what the device accepted; a configuration error is a failed init.
    std::uint8_t back[4]{}, err = 0xFF;
    if (!bus.read(address_, reg::acc_conf, back, 4) || back[0] != acc_conf_200hz || back[1] != acc_range_8g
        || back[2] != gyr_conf_200hz || back[3] != gyr_range_2000 || !bus.read(address_, reg::err, &err, 1)
        || (err & 0x1F) != 0)   // fatal_err / internal_err; FIFO and AUX bits are unused here
        return fail(State::InitFailed, "sensor configuration not accepted (read-back or ERR_REG)");
    consecutive_ = 0;
    state_ = State::Running;
    return state_;
}

bool Bmi270::poll(RegisterBus& bus, std::int64_t now_us, Sample& out) {
    if (state_ != State::Running) return false;
    // STATUS (0x03) .. SENSORTIME_2 (0x1A) in one burst: data-ready bits, data, time.
    std::uint8_t b[0x1B - reg::status]{};
    if (!bus.read(address_, reg::status, b, sizeof b)) {
        ++bus_errors_;
        if (++consecutive_ >= fault_after) fail(State::Faulted, "repeated I2C read failures");
        return false;
    }
    consecutive_ = 0;
    if ((b[0] & 0xC0) == 0) return false;   // drdy_acc | drdy_gyr
    const auto s16 = [&](std::uint8_t r) {
        const auto i = static_cast<std::size_t>(r - reg::status);
        return static_cast<std::int16_t>(static_cast<std::uint16_t>(b[i] | (b[i + 1] << 8)));
    };
    out.t_us = now_us;
    for (int k = 0; k < 3; ++k) {
        out.acc[static_cast<std::size_t>(k)] = s16(static_cast<std::uint8_t>(reg::acc_x + 2 * k));
        out.gyr[static_cast<std::size_t>(k)] = s16(static_cast<std::uint8_t>(reg::gyr_x + 2 * k));
    }
    const auto t = static_cast<std::size_t>(reg::sensortime - reg::status);
    out.sensor_time = std::uint32_t(b[t]) | (std::uint32_t(b[t + 1]) << 8) | (std::uint32_t(b[t + 2]) << 16);
    return true;
}

} // namespace guardian::imu

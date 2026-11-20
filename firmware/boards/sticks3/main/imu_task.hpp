#pragma once
// G16A: StickS3 BMI270 on the internal I2C bus (SDA 47 / SCL 48, shared with
// the PM1; the bus handle is owned by sticks3::Board). A low-priority task on
// core 1 initializes the IMU and samples it at 200 Hz into a lock-free ring.
// Nothing here can block the observation loop or the Wi-Fi receive callback:
// the companion loop only drains the ring; if the IMU is absent or fails, the
// state says so and the art stays static.
#include <cstdint>
#include "bmi270.hpp"
namespace sticks3::imu {
using Ring = guardian::imu::Ring<64>;
struct Status {
    guardian::imu::State state{guardian::imu::State::Off};
    std::uint8_t address{};
    const char* failure{""};
    std::uint32_t samples{}, ring_drops{}, bus_errors{};
    bool started{};
};
// Starts the task once; `i2c_bus` is the board's i2c_master_bus_handle_t (nullptr: state stays off).
bool start(void* i2c_bus);
Status status();
Ring& ring();
// G16D: stops the sampler before deep sleep (the BMI270 suspend writes follow);
// waits up to timeout_ms for the task to leave the bus. True when it no longer runs.
bool stop(std::uint32_t timeout_ms);
} // namespace sticks3::imu

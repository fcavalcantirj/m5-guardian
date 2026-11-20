// G16A: ESP-IDF adapter for the SDK-free BMI270 core (adapters/imu).
#include "imu_task.hpp"
#include <atomic>
#include <cstring>
#include "driver/i2c_master.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace sticks3::imu {
namespace {
constexpr const char* TAG = "imu";
constexpr std::uint32_t bmi270_hz = 400 * 1000;   // M5Unified 0.2.21 BMI270_Class default on this bus
constexpr int xfer_timeout_ms = 20;

class I2cBus final : public guardian::imu::RegisterBus {
public:
    explicit I2cBus(i2c_master_bus_handle_t bus) : bus_(bus) {}
    bool read(std::uint8_t address, std::uint8_t reg, std::uint8_t* out, std::size_t n) override {
        auto* dev = device(address);
        return dev && i2c_master_transmit_receive(dev, &reg, 1, out, n, xfer_timeout_ms) == ESP_OK;
    }
    bool write(std::uint8_t address, std::uint8_t reg, const std::uint8_t* data, std::size_t n) override {
        auto* dev = device(address);
        if (!dev || n + 1 > sizeof buf_) return false;
        buf_[0] = reg; std::memcpy(buf_ + 1, data, n);
        return i2c_master_transmit(dev, buf_, n + 1, xfer_timeout_ms) == ESP_OK;
    }
    void delay_ms(std::uint32_t ms) override { vTaskDelay(pdMS_TO_TICKS(ms ? ms : 1)); }
private:
    i2c_master_dev_handle_t device(std::uint8_t address) {
        const int slot = address == 0x68 ? 0 : address == 0x69 ? 1 : -1;
        if (slot < 0) return nullptr;
        if (!dev_[slot]) {
            i2c_device_config_t cfg{};
            cfg.dev_addr_length = I2C_ADDR_BIT_LEN_7; cfg.device_address = address; cfg.scl_speed_hz = bmi270_hz;
            if (i2c_master_bus_add_device(bus_, &cfg, &dev_[slot]) != ESP_OK) dev_[slot] = nullptr;
        }
        return dev_[slot];
    }
    i2c_master_bus_handle_t bus_;
    i2c_master_dev_handle_t dev_[2]{};
    std::uint8_t buf_[1 + guardian::imu::Bmi270::upload_chunk]{};
};

Ring ring_;
std::atomic<guardian::imu::State> state_{guardian::imu::State::Off};
std::atomic<std::uint8_t> address_{0};
std::atomic<const char*> failure_{""};
std::atomic<std::uint32_t> bus_errors_{0};
std::atomic<bool> started_{false};
std::atomic<bool> stop_requested_{false}, running_{false};
i2c_master_bus_handle_t bus_handle;

void task(void*) {
    static I2cBus bus(bus_handle);
    static guardian::imu::Bmi270 bmi;
    const auto s = bmi.begin(bus);
    address_ = bmi.address(); failure_ = bmi.failure(); state_ = s;
    ESP_LOGI(TAG, "BMI270 %s addr=0x%02x %s", guardian::imu::state_text(s), bmi.address(), bmi.failure());
    if (s != guardian::imu::State::Running) { vTaskDelete(nullptr); return; }
    running_ = true;
    TickType_t last = xTaskGetTickCount();
    const TickType_t period = pdMS_TO_TICKS(1000 / guardian::imu::sample_hz);   // 5 ticks at 1 kHz
    for (;;) {
        vTaskDelayUntil(&last, period ? period : 1);
        if (stop_requested_) { running_ = false; vTaskDelete(nullptr); return; }   // G16D: before deep sleep
        guardian::imu::Sample sample;
        if (bmi.poll(bus, esp_timer_get_time(), sample)) ring_.push(sample);
        bus_errors_ = bmi.bus_errors();
        if (bmi.state() != guardian::imu::State::Running) {
            failure_ = bmi.failure(); state_ = bmi.state();
            ESP_LOGW(TAG, "BMI270 %s: %s", guardian::imu::state_text(bmi.state()), bmi.failure());
            running_ = false; vTaskDelete(nullptr); return;
        }
    }
}
} // namespace

bool start(void* i2c_bus) {
    if (started_.exchange(true)) return false;
    if (!i2c_bus) { failure_ = "no I2C bus"; state_ = guardian::imu::State::Absent; return false; }
    bus_handle = static_cast<i2c_master_bus_handle_t>(i2c_bus);
    // Priority 2 on core 1: Wi-Fi and the main observation loop run on core 0.
    if (xTaskCreatePinnedToCore(task, "imu", 4096, nullptr, 2, nullptr, 1) != pdPASS) {
        failure_ = "task create failed"; state_ = guardian::imu::State::InitFailed; return false;
    }
    return true;
}

Status status() {
    Status s;
    s.state = state_; s.address = address_; s.failure = failure_; s.samples = ring_.pushed();
    s.ring_drops = ring_.dropped(); s.bus_errors = bus_errors_; s.started = started_;
    return s;
}
Ring& ring() { return ring_; }
bool stop(std::uint32_t timeout_ms) {
    stop_requested_ = true;
    // A task still initializing (running_ false) is the only unbounded case: it
    // may touch the bus once more; the wait below covers the normal sampling loop.
    for (std::uint32_t waited = 0; running_ && waited < timeout_ms; waited += 5) vTaskDelay(pdMS_TO_TICKS(5));
    return !running_;
}
} // namespace sticks3::imu

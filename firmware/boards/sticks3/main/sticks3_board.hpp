#pragma once
#include <cstddef>
#include <cstdint>

#include "guardian/canvas.hpp"
#include "sticks3_pins.hpp"
#include "transfer.hpp"
#include "dirty_rows.hpp"
#include "battery.hpp"

// StickS3 board adapter: owns pins, PM1 power sequencing, the esp_lcd panel,
// backlight and raw button reads. It never decides what to draw.
namespace sticks3 {

struct BoardInfo {
    bool pm1_present{};
    std::uint32_t pm1_device_id{}; // raw four-byte value, not a validated board ID
    bool pm1_config_ok{};
    bool buttons_ok{};
    bool panel_setup_ok{};
    std::uint8_t pm1_power_source{};
    const char* chip_model{"?"};
    int chip_revision{};
    int cores{};
    std::uint32_t flash_bytes{};
    std::size_t psram_bytes{};
    bool psram_test_ok{};
    std::size_t heap_free{};
    bool nvs_ok{};
    std::uint32_t boot_count{};
    std::uint32_t assets_partition_bytes{};
    bool sd_card{false}; // the StickS3 has no SD slot; stays false by design
};

class Board {
public:
    // Brings up PM1 (LCD rail on, PA off), SPI panel, backlight, buttons, NVS.
    // Returns false if the display path failed; info is still filled.
    bool init(BoardInfo& info);
    guardian::Canvas* canvas() { return ready_ && transfer_.writable() ? &canvas_ : nullptr; }
    // Returns only after DMA completion. Failure permanently revokes canvas access
    // until reboot; queued data is never reused on a timeout/submission error.
    bool present();
    // G16C rework: pushes only the planned full-width row runs (one DMA
    // transaction each, waited for in turn); same failure rule as present().
    bool present_rows(const DirtyRows::Plan& plan);
    bool set_backlight(std::uint8_t percent);
    // Raw levels: true = line reads LOW (pressed, per M5Unified's active-low wiring).
    bool key_front_down() const;
    bool key_side_down() const;
    // G16A: the internal I2C bus (i2c_master_bus_handle_t, SDA 47 / SCL 48) that
    // the PM1 and the BMI270 share; nullptr until init() created it.
    void* i2c_bus() const { return i2c_bus_; }
    // G16B: raw M5PM1 power registers (VBAT 0x22/0x23, PWR_SRC 0x04, GPIO_IN
    // 0x12; see adapters/power/battery.hpp for the source). Each field says
    // whether its own read succeeded; nothing is guessed here.
    void read_power(guardian::battery::Raw& out) const;
    // G16D deep-sleep primitives (order and register values: adapters/power/idle.hpp).
    // Backlight off, panel display off and SLPIN; the canvas is revoked until reboot.
    bool display_sleep();
    // PM1 GPIO_OUT bit `pin` low (2 = LCD rail, 3 = speaker PA). Never the IRQ pin.
    bool pm1_gpio_low(std::uint8_t pin);
    // One register write to another device on the internal bus (temporary handle).
    bool i2c_write(std::uint8_t addr, std::uint8_t reg, std::uint8_t value);
    int i2c_write_err(std::uint8_t addr, std::uint8_t reg, std::uint8_t value);   // esp_err_t of the write (0 = ESP_OK)
    // Review 2026-11-17: address-only probe (i2c_master_probe: START, address, ACK?, STOP);
    // no register is read or written. Never the PM1 (its own handle owns 0x6E).
    bool i2c_present(std::uint8_t addr);
    // G16Q art bench only (defined under CONFIG_GUARDIAN_ART_BENCH; the Guardian image never calls it).
    // true: sends the two 14-byte ST7789 gamma tables (0xE0 positive, 0xE1 negative). false: restores the
    // panel's own power-on gamma the only certain way, a hardware reset and the normal setup again (the
    // glass is blank until the next full frame). False when a panel call failed.
    bool set_panel_gamma(bool on, const std::uint8_t* positive14, const std::uint8_t* negative14);
    static constexpr std::uint8_t backlight_active_pct = 60;   // init duty 153/255
    static constexpr int width = screen_w;
    static constexpr int height = screen_h;

private:
    bool init_pm1(BoardInfo& info);
    bool init_display();
    bool setup_panel();   // reset, vendor init, inversion, orientation, display on (init_display and the bench)
    bool init_backlight();
    bool init_buttons();
    void init_storage(BoardInfo& info);
    void probe_memory(BoardInfo& info);

    bool ready_{};
    Transfer transfer_{};
    void* transfer_done_{nullptr}; // binary semaphore, callback only signals it
    std::uint16_t* frame_{nullptr};
    guardian::Canvas canvas_{nullptr, 0, 0, true};
    void* panel_{nullptr};    // esp_lcd_panel_handle_t
    void* panel_io_{nullptr}; // esp_lcd_panel_io_handle_t
    void* i2c_bus_{nullptr};  // i2c_master_bus_handle_t
    void* pm1_dev_{nullptr};  // i2c_master_dev_handle_t
};

// G16P: the PM1 power registers alone, for the timer-wake USB check that runs BEFORE Board::init().
// open() creates the internal I2C bus and the PM1 handle; read() reads PWR_SRC, VIN and VBAT; close()
// removes both again so Board::init() can create the bus as usual. It never writes a PM1 register:
// the LCD rail, the PA, the GPIO modes and the PM1's "I2C stays awake" bit remain exactly as the last
// full boot and the deep-sleep teardown left them, and no display, radio or IMU call is made.
class QuickPower {
public:
    ~QuickPower() { close(); }
    bool open();
    // Each field says whether its own read succeeded (gpio_in is not read: gpio_ok stays false).
    void read(guardian::battery::Raw& out) const;
    void close();
private:
    void* bus_{nullptr};  // i2c_master_bus_handle_t
    void* dev_{nullptr};  // i2c_master_dev_handle_t
};

} // namespace sticks3

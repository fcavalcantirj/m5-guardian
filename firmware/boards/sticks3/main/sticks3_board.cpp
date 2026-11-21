// Derived M5Stack display/power sequences: see THIRD_PARTY_NOTICES.md at repo root
// for the full MIT notice and pinned source provenance.
#include "sticks3_board.hpp"
#include "sdkconfig.h"   // G16Q: CONFIG_GUARDIAN_ART_BENCH

#include <cstring>

#include "driver/gpio.h"
#include "soc/gpio_reg.h"   // G24: G46 output enable / output level read back for STATUS parts=
#include "soc/soc.h"
#include "driver/rtc_io.h"
#include "driver/i2c_master.h"
#include "driver/ledc.h"
#include "driver/spi_master.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_psram.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "sticks3_pins.hpp"
#include "orientation.hpp"

namespace sticks3 {
namespace {
constexpr const char* TAG = "sticks3";

// M5PM1 registers, names from M5Unified 0.2.21 M5PM1_Class.cpp.
constexpr std::uint8_t PM1_REG_DEVICE_ID = 0x00;
constexpr std::uint8_t PM1_REG_PWR_SRC = 0x04;
constexpr std::uint8_t PM1_REG_I2C_CFG = 0x09;
constexpr std::uint8_t PM1_REG_GPIO_MODE = 0x10;
constexpr std::uint8_t PM1_REG_GPIO_OUT = 0x11;
constexpr std::uint8_t PM1_REG_PWR_CFG = 0x06;            // G24: bit 4 green status LED, bit 3 5 V boost (G24 spike S2: 0x17 at boot)
constexpr std::uint8_t PM1_PWR_CFG_LED = 1u << 4;
constexpr std::uint8_t PM1_PWR_CFG_BOOST5V = 1u << 3;
constexpr std::uint8_t PM1_REG_GPIO_DRV = 0x13;
constexpr std::uint8_t PM1_REG_GPIO_FUNC0 = 0x16;
// G16B battery (M5Unified 0.2.21 M5PM1_Class.cpp register names; StickS3 charge
// status = PM1 GPIO0, low = charging, from Power_Class.cpp isCharging()).
constexpr std::uint8_t PM1_REG_GPIO_IN = 0x12;
constexpr std::uint8_t PM1_REG_VBAT_L = 0x22;
constexpr std::uint8_t PM1_REG_VIN_L = 0x24;   // G16D: M5PM1_Class getVBUSVoltage (VIN_L/H, mV)
constexpr std::uint8_t PM1_GPIO0_CHG_STAT = 1u << 0;
constexpr std::uint8_t PM1_FUNC0_GPIO0_MASK = 0x03; // FUNC0 holds 2 bits per pin; GPIO0 = bits 1:0, 00 = plain GPIO
constexpr std::uint8_t PM1_GPIO2_LCD_POWER = 1u << 2; // "L3B Enable, LCD Power On" (M5GFX)
constexpr std::uint8_t PM1_GPIO3_PA_CONTROL = 1u << 3; // speaker amplifier enable (M5Unified)

bool color_done(esp_lcd_panel_io_handle_t, esp_lcd_panel_io_event_data_t*, void* context) {
    BaseType_t wake = pdFALSE;
    xSemaphoreGiveFromISR(static_cast<SemaphoreHandle_t>(context), &wake);
    return wake == pdTRUE;
}

constexpr int kBacklightTimer = LEDC_TIMER_0;
constexpr int kBacklightChannel = LEDC_CHANNEL_0;

bool pm1_read(i2c_master_dev_handle_t dev, std::uint8_t reg, std::uint8_t& out) {
    return i2c_master_transmit_receive(dev, &reg, 1, &out, 1, 50) == ESP_OK;
}
bool pm1_write(i2c_master_dev_handle_t dev, std::uint8_t reg, std::uint8_t val) {
    const std::uint8_t buf[2] = {reg, val};
    return i2c_master_transmit(dev, buf, 2, 50) == ESP_OK;
}
bool pm1_update(i2c_master_dev_handle_t dev, std::uint8_t reg, std::uint8_t mask, bool set) {
    std::uint8_t v{};
    if (!pm1_read(dev, reg, v)) return false;
    v = set ? static_cast<std::uint8_t>(v | mask) : static_cast<std::uint8_t>(v & ~mask);
    return pm1_write(dev, reg, v);
}
} // namespace

bool Board::init(BoardInfo& info) {
    probe_memory(info);
    info.pm1_config_ok = init_pm1(info);
    info.panel_setup_ok = info.pm1_config_ok && init_display();
    ready_ = info.panel_setup_ok && init_backlight();
    info.buttons_ok = init_buttons();
    init_storage(info);
    info.heap_free = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    return ready_;
}

void Board::probe_memory(BoardInfo& info) {
    esp_chip_info_t chip{};
    esp_chip_info(&chip);
    info.chip_model = chip.model == CHIP_ESP32S3 ? "ESP32-S3" : "other";
    info.chip_revision = chip.revision;
    info.cores = chip.cores;
    std::uint32_t flash = 0;
    if (esp_flash_get_size(nullptr, &flash) == ESP_OK) info.flash_bytes = flash;
    info.psram_bytes = esp_psram_is_initialized() ? esp_psram_get_size() : 0;
    info.psram_test_ok = false;
    if (info.psram_bytes) {
        // Allocate from external RAM explicitly and check a write/read pattern.
        constexpr std::size_t n = 256 * 1024;
        auto* p = static_cast<std::uint32_t*>(heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
        if (p) {
            bool ok = true;
            for (std::size_t i = 0; i < n / 4; ++i) p[i] = static_cast<std::uint32_t>(i * 2654435761u);
            for (std::size_t i = 0; i < n / 4 && ok; ++i) ok = p[i] == static_cast<std::uint32_t>(i * 2654435761u);
            heap_caps_free(p);
            info.psram_test_ok = ok;
        }
    }
}

bool Board::init_pm1(BoardInfo& info) {
    i2c_master_bus_config_t bus{};
    bus.i2c_port = I2C_NUM_1;
    bus.sda_io_num = static_cast<gpio_num_t>(i2c_sda);
    bus.scl_io_num = static_cast<gpio_num_t>(i2c_scl);
    bus.clk_source = I2C_CLK_SRC_DEFAULT;
    bus.glitch_ignore_cnt = 7;
    bus.flags.enable_internal_pullup = true;
    i2c_master_bus_handle_t bus_h{};
    if (i2c_new_master_bus(&bus, &bus_h) != ESP_OK) {
        ESP_LOGE(TAG, "i2c bus init failed");
        return false;
    }
    i2c_bus_ = bus_h;
    i2c_device_config_t dev{};
    dev.dev_addr_length = I2C_ADDR_BIT_LEN_7;
    dev.device_address = pm1_addr;
    dev.scl_speed_hz = pm1_hz;
    i2c_master_dev_handle_t dev_h{};
    if (i2c_master_bus_add_device(bus_h, &dev, &dev_h) != ESP_OK) {
        ESP_LOGE(TAG, "pm1 device add failed");
        return false;
    }
    pm1_dev_ = dev_h;

    // M5Unified reads four bytes at 0x00 but does not validate a constant ID.
    // Report raw response only; board profile is selected by the owner, not inferred.
    std::uint8_t id[4]{};const std::uint8_t reg=PM1_REG_DEVICE_ID;
    if (i2c_master_transmit_receive(dev_h,&reg,1,id,sizeof id,50)!=ESP_OK) {
        ESP_LOGW(TAG,"PM1 register read failed");return false;
    }
    info.pm1_present=true;
    for(unsigned i=0;i<4;++i) info.pm1_device_id |= std::uint32_t(id[i]) << (8*i);
    if (!pm1_read(dev_h,PM1_REG_PWR_SRC,info.pm1_power_source)) return false;

    // LCD rail: PM1 GPIO2 as plain GPIO, output, push-pull, high (M5GFX sequence).
    bool ok = pm1_update(dev_h, PM1_REG_GPIO_FUNC0, PM1_GPIO2_LCD_POWER, false);
    ok &= pm1_update(dev_h, PM1_REG_GPIO_MODE, PM1_GPIO2_LCD_POWER, true);
    ok &= pm1_update(dev_h, PM1_REG_GPIO_DRV, PM1_GPIO2_LCD_POWER, false);
    ok &= pm1_update(dev_h, PM1_REG_GPIO_OUT, PM1_GPIO2_LCD_POWER, true);
    // Speaker amplifier off until an audio feature exists (M5Unified sequence).
    ok &= pm1_update(dev_h, PM1_REG_GPIO_FUNC0, PM1_GPIO3_PA_CONTROL, false);
    ok &= pm1_update(dev_h, PM1_REG_GPIO_MODE, PM1_GPIO3_PA_CONTROL, true);
    ok &= pm1_update(dev_h, PM1_REG_GPIO_DRV, PM1_GPIO3_PA_CONTROL, false);
    ok &= pm1_update(dev_h, PM1_REG_GPIO_OUT, PM1_GPIO3_PA_CONTROL, false);
    // G16B: GPIO0 = charge status input (M5Unified Power_Class, board_M5StickS3:
    // setGPIOFunction(gpio0, gpio) + setGPIOMode(gpio0, input)). FUNC0 is a
    // 2-bit-per-pin field (M5PM1_Class::setGPIOFunction), so clear bits 1:0.
    ok &= pm1_update(dev_h, PM1_REG_GPIO_FUNC0, PM1_FUNC0_GPIO0_MASK, false);
    ok &= pm1_update(dev_h, PM1_REG_GPIO_MODE, PM1_GPIO0_CHG_STAT, false);
    // Keep the PM1 I2C awake; it is always powered and remembers this bit.
    ok &= pm1_write(dev_h, PM1_REG_I2C_CFG, 0x00);
    if (!ok) ESP_LOGW(TAG, "pm1 configuration had I2C errors");
    vTaskDelay(pdMS_TO_TICKS(100)); // rail settle, as M5GFX does
    return ok;
}

bool Board::init_display() {
    frame_ = static_cast<std::uint16_t*>(heap_caps_malloc(
        static_cast<std::size_t>(screen_w) * screen_h * 2, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL));
    if (!frame_) {
        ESP_LOGE(TAG, "framebuffer allocation failed");
        return false;
    }
    canvas_ = guardian::Canvas(frame_, screen_w, screen_h, true);
    canvas_.clear(guardian::color::black);

    spi_bus_config_t bus{};
    bus.mosi_io_num = lcd_mosi;
    bus.miso_io_num = -1;
    bus.sclk_io_num = lcd_sclk;
    bus.quadwp_io_num = -1;
    bus.quadhd_io_num = -1;
    bus.max_transfer_sz = screen_w * screen_h * 2;
    if (spi_bus_initialize(SPI3_HOST, &bus, SPI_DMA_CH_AUTO) != ESP_OK) {
        ESP_LOGE(TAG, "spi bus init failed");
        return false;
    }

    esp_lcd_panel_io_spi_config_t io{};
    io.cs_gpio_num = lcd_cs;
    io.dc_gpio_num = lcd_dc;
    io.spi_mode = 0;
    io.pclk_hz = lcd_spi_hz;
    io.trans_queue_depth = 1;
    transfer_done_ = xSemaphoreCreateBinary();
    if (!transfer_done_) return false;
    io.on_color_trans_done = color_done;
    io.user_ctx = transfer_done_;
    io.lcd_cmd_bits = 8;
    io.lcd_param_bits = 8;
    esp_lcd_panel_io_handle_t io_h{};
    if (esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI3_HOST, &io, &io_h) != ESP_OK) {
        ESP_LOGE(TAG, "panel io init failed");
        return false;
    }
    panel_io_ = io_h;

    esp_lcd_panel_dev_config_t dev{};
    dev.reset_gpio_num = lcd_rst;
    dev.rgb_ele_order = LCD_RGB_ELEMENT_ORDER_RGB; // physical BGR trial swapped R/B; verify RGB swatches on this panel
    dev.data_endian = LCD_RGB_DATA_ENDIAN_BIG;     // the canvas already stores MSB first
    dev.bits_per_pixel = 16;
    esp_lcd_panel_handle_t panel{};
    if (esp_lcd_new_panel_st7789(io_h, &dev, &panel) != ESP_OK) {
        ESP_LOGE(TAG, "st7789 panel create failed");
        return false;
    }
    panel_ = panel;
    return setup_panel();
}

// Reset through GPIO 21 (all controller registers back to their power-on values), then the same setup
// as ever. G16Q moved these lines out of init_display() unchanged so the art bench can repeat them.
bool Board::setup_panel() {
    const auto panel = static_cast<esp_lcd_panel_handle_t>(panel_);
    if (!panel) return false;
    if (esp_lcd_panel_reset(panel) != ESP_OK) return false;
    if (esp_lcd_panel_init(panel) != ESP_OK) return false;
    if (esp_lcd_panel_invert_color(panel, true) != ESP_OK) return false; // M5GFX cfg.invert = true
    // G16A: upright portrait, USB down = the panel's native frame (vendor
    // rotation 0). Flags and gap come from the host-checked M5GFX formula in
    // orientation.hpp; the old landscape gap (40,52) left one column unwritten.
    namespace o = orientation;
    static_assert(o::display.width == screen_w && o::display.height == screen_h, "framebuffer matches the rotation");
    if (esp_lcd_panel_swap_xy(panel, o::display.swap_xy) != ESP_OK) return false;
    if (esp_lcd_panel_mirror(panel, o::display.mirror_x, o::display.mirror_y) != ESP_OK) return false;
    if (esp_lcd_panel_set_gap(panel, o::display.gap_x, o::display.gap_y) != ESP_OK) return false;
    if (esp_lcd_panel_disp_on_off(panel, true) != ESP_OK) return false;
    return true;
}

// ---- G24: unused parts off, their register reads, the LCD rail ------------------------------------
bool Board::parts_off() {
    auto* dev = static_cast<i2c_master_dev_handle_t>(pm1_dev_);
    bool ok = dev != nullptr;
    if (dev) {
        ok &= pm1_update(dev, PM1_REG_PWR_CFG, static_cast<std::uint8_t>(PM1_PWR_CFG_LED | PM1_PWR_CFG_BOOST5V), false);
        ok &= pm1_update(dev, PM1_REG_GPIO_OUT, PM1_GPIO3_PA_CONTROL, false);
    }
    // vpd holdIrTxLow: G46 (the IR TX gate) driven low and its pad held, so nothing can light the IR LED.
    const auto ir = static_cast<gpio_num_t>(46);
    gpio_hold_dis(ir);
    ok &= gpio_set_pull_mode(ir, GPIO_PULLDOWN_ONLY) == ESP_OK;
    ok &= gpio_set_level(ir, 0) == ESP_OK;
    ok &= gpio_set_direction(ir, GPIO_MODE_OUTPUT) == ESP_OK;
    ok &= gpio_hold_en(ir) == ESP_OK;
    return ok;
}

void Board::read_parts(int& pwr_cfg, int& gpio_out, int& ir_oe, int& ir_level) const {
    auto* dev = static_cast<i2c_master_dev_handle_t>(pm1_dev_);
    std::uint8_t v{};
    pwr_cfg = dev && pm1_read(dev, PM1_REG_PWR_CFG, v) ? v : -1;
    gpio_out = dev && pm1_read(dev, PM1_REG_GPIO_OUT, v) ? v : -1;
    const std::uint32_t bit46 = 1u << (46 - 32);
    ir_oe = (REG_READ(GPIO_ENABLE1_REG) & bit46) ? 1 : 0;
    ir_level = (REG_READ(GPIO_OUT1_REG) & bit46) ? 1 : 0;
}

bool Board::lcd_rail(bool on) {
    auto* dev = static_cast<i2c_master_dev_handle_t>(pm1_dev_);
    if (!dev) return false;
    if (!on) {
        set_backlight(0);
        const bool ok = pm1_update(dev, PM1_REG_GPIO_OUT, PM1_GPIO2_LCD_POWER, false);
        if (ok) rail_on_ = false;
        return ok;
    }
    if (!pm1_update(dev, PM1_REG_GPIO_OUT, PM1_GPIO2_LCD_POWER, true)) return false;
    rail_on_ = true;
    vTaskDelay(pdMS_TO_TICKS(100));   // rail settle, as at boot
    return setup_panel();
}

int Board::i2c_read(std::uint8_t addr, std::uint8_t reg) {
    auto* bus = static_cast<i2c_master_bus_handle_t>(i2c_bus_);
    if (!bus || addr == pm1_addr) return -1;
    i2c_device_config_t cfg{};
    cfg.dev_addr_length = I2C_ADDR_BIT_LEN_7; cfg.device_address = addr; cfg.scl_speed_hz = pm1_hz;
    i2c_master_dev_handle_t dev{};
    if (i2c_master_bus_add_device(bus, &cfg, &dev) != ESP_OK) return -1;
    std::uint8_t v{};
    const esp_err_t r = i2c_master_transmit_receive(dev, &reg, 1, &v, 1, 50);
    i2c_master_bus_rm_device(dev);
    return r == ESP_OK ? v : -1;
}

#if CONFIG_GUARDIAN_ART_BENCH
bool Board::set_panel_gamma(bool on, const std::uint8_t* positive14, const std::uint8_t* negative14) {
    if (!ready_ || !panel_io_ || !panel_) return false;
    if (!on) return setup_panel();
    if (!positive14 || !negative14) return false;
    const auto io = static_cast<esp_lcd_panel_io_handle_t>(panel_io_);
    return esp_lcd_panel_io_tx_param(io, 0xE0, positive14, 14) == ESP_OK   // PVGAMCTRL
        && esp_lcd_panel_io_tx_param(io, 0xE1, negative14, 14) == ESP_OK;  // NVGAMCTRL
}
#endif

bool Board::init_backlight() {
    ledc_timer_config_t t{};
    t.speed_mode = LEDC_LOW_SPEED_MODE;
    t.duty_resolution = LEDC_TIMER_8_BIT;
    t.timer_num = static_cast<ledc_timer_t>(kBacklightTimer);
    t.freq_hz = 5000;
    t.clk_cfg = LEDC_AUTO_CLK;
    if (ledc_timer_config(&t)!=ESP_OK) return false;
    ledc_channel_config_t c{};
    c.gpio_num = lcd_backlight;
    c.speed_mode = LEDC_LOW_SPEED_MODE;
    c.channel = static_cast<ledc_channel_t>(kBacklightChannel);
    c.timer_sel = static_cast<ledc_timer_t>(kBacklightTimer);
    c.duty = 0;
    c.hpoint = 0;
    if (ledc_channel_config(&c)!=ESP_OK) return false;
    return ledc_set_duty(LEDC_LOW_SPEED_MODE,static_cast<ledc_channel_t>(kBacklightChannel),153)==ESP_OK
        && ledc_update_duty(LEDC_LOW_SPEED_MODE,static_cast<ledc_channel_t>(kBacklightChannel))==ESP_OK;
}

bool Board::set_backlight(std::uint8_t percent) {
    if (percent > 100) percent = 100;
    const std::uint32_t duty = (255u * percent) / 100u;
    return ledc_set_duty(LEDC_LOW_SPEED_MODE, static_cast<ledc_channel_t>(kBacklightChannel), duty)==ESP_OK
        && ledc_update_duty(LEDC_LOW_SPEED_MODE, static_cast<ledc_channel_t>(kBacklightChannel))==ESP_OK;
}

bool Board::init_buttons() {
    // G16D: after an ext1 wake the key pads may still be routed to the RTC IO
    // mux (sleep_modes.rst: reconfigure a wakeup pad with rtc_gpio_deinit before
    // using it as a digital GPIO). Harmless on a cold boot.
    rtc_gpio_deinit(static_cast<gpio_num_t>(key_front));
    rtc_gpio_deinit(static_cast<gpio_num_t>(key_side));
    gpio_config_t cfg{};
    cfg.pin_bit_mask = (1ULL << key_front) | (1ULL << key_side);
    cfg.mode = GPIO_MODE_INPUT;
    cfg.pull_up_en = GPIO_PULLUP_ENABLE;
    cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    cfg.intr_type = GPIO_INTR_DISABLE;
    return gpio_config(&cfg)==ESP_OK;
}

bool Board::key_front_down() const { return gpio_get_level(static_cast<gpio_num_t>(key_front)) == 0; }
bool Board::key_side_down() const { return gpio_get_level(static_cast<gpio_num_t>(key_side)) == 0; }

void Board::init_storage(BoardInfo& info) {
    // Initialization errors do not authorize erasing an existing NVS partition.
    info.nvs_ok=false;
    if (nvs_flash_init()==ESP_OK) {
        nvs_handle_t h{};
        if (nvs_open("guardian",NVS_READWRITE,&h)==ESP_OK) {
            std::uint32_t count=0;const auto read=nvs_get_u32(h,"boot_count",&count);
            if ((read==ESP_OK || read==ESP_ERR_NVS_NOT_FOUND) && count!=UINT32_MAX) {
                ++count;
                if (nvs_set_u32(h,"boot_count",count)==ESP_OK && nvs_commit(h)==ESP_OK) {
                    info.nvs_ok=true;info.boot_count=count;
                }
            }
            nvs_close(h);
        }
    }
    const esp_partition_t* assets = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, static_cast<esp_partition_subtype_t>(0x83), "assets");
    info.assets_partition_bytes = assets ? assets->size : 0;
    info.sd_card = false; // no SD slot on this board; nothing is mounted
}

void Board::read_power(guardian::battery::Raw& out) const {
    out = {};
    auto* dev = static_cast<i2c_master_dev_handle_t>(pm1_dev_);
    if (!dev) return;
    std::uint8_t vbat[2]{};
    const std::uint8_t reg = PM1_REG_VBAT_L;
    out.vbat_ok = i2c_master_transmit_receive(dev, &reg, 1, vbat, 2, 50) == ESP_OK;
    if (out.vbat_ok) out.vbat_mv = static_cast<std::uint16_t>(vbat[0] | (vbat[1] << 8));
    out.src_ok = pm1_read(dev, PM1_REG_PWR_SRC, out.pwr_src);
    out.gpio_ok = pm1_read(dev, PM1_REG_GPIO_IN, out.gpio_in);
    std::uint8_t vin[2]{};
    const std::uint8_t vin_reg = PM1_REG_VIN_L;
    out.vin_ok = i2c_master_transmit_receive(dev, &vin_reg, 1, vin, 2, 50) == ESP_OK;
    if (out.vin_ok) out.vin_mv = static_cast<std::uint16_t>(vin[0] | (vin[1] << 8));
}

// ---- G16P: PM1 power registers before the board is brought up ------------------------
namespace {
constexpr int quick_timeout_ms = 20;   // a 2-byte register read at 100 kHz takes under 1 ms; Board uses 50
}
bool QuickPower::open() {
    if (dev_) return true;
    i2c_master_bus_config_t bus{};   // the same bus Board::init_pm1 creates (closed again before it runs)
    bus.i2c_port = I2C_NUM_1;
    bus.sda_io_num = static_cast<gpio_num_t>(i2c_sda);
    bus.scl_io_num = static_cast<gpio_num_t>(i2c_scl);
    bus.clk_source = I2C_CLK_SRC_DEFAULT;
    bus.glitch_ignore_cnt = 7;
    bus.flags.enable_internal_pullup = true;
    i2c_master_bus_handle_t bus_h{};
    if (i2c_new_master_bus(&bus, &bus_h) != ESP_OK) return false;
    i2c_device_config_t dev{};
    dev.dev_addr_length = I2C_ADDR_BIT_LEN_7;
    dev.device_address = pm1_addr;
    dev.scl_speed_hz = pm1_hz;
    i2c_master_dev_handle_t dev_h{};
    if (i2c_master_bus_add_device(bus_h, &dev, &dev_h) != ESP_OK) { i2c_del_master_bus(bus_h); return false; }
    bus_ = bus_h; dev_ = dev_h;
    return true;
}

void QuickPower::read(guardian::battery::Raw& out) const {
    out = {};
    auto* dev = static_cast<i2c_master_dev_handle_t>(dev_);
    if (!dev) return;
    const std::uint8_t src_reg = PM1_REG_PWR_SRC;
    out.src_ok = i2c_master_transmit_receive(dev, &src_reg, 1, &out.pwr_src, 1, quick_timeout_ms) == ESP_OK;
    std::uint8_t vin[2]{};
    const std::uint8_t vin_reg = PM1_REG_VIN_L;
    out.vin_ok = i2c_master_transmit_receive(dev, &vin_reg, 1, vin, 2, quick_timeout_ms) == ESP_OK;
    if (out.vin_ok) out.vin_mv = static_cast<std::uint16_t>(vin[0] | (vin[1] << 8));
    std::uint8_t vbat[2]{};
    const std::uint8_t vbat_reg = PM1_REG_VBAT_L;
    out.vbat_ok = i2c_master_transmit_receive(dev, &vbat_reg, 1, vbat, 2, quick_timeout_ms) == ESP_OK;
    if (out.vbat_ok) out.vbat_mv = static_cast<std::uint16_t>(vbat[0] | (vbat[1] << 8));
}

void QuickPower::close() {
    if (dev_) i2c_master_bus_rm_device(static_cast<i2c_master_dev_handle_t>(dev_));
    if (bus_) i2c_del_master_bus(static_cast<i2c_master_bus_handle_t>(bus_));
    dev_ = nullptr; bus_ = nullptr;
}

bool Board::display_sleep() {
    bool ok = set_backlight(0);
    auto* panel = static_cast<esp_lcd_panel_handle_t>(panel_);
    ready_ = false;   // nothing is drawn after this
    if (panel) {
        ok = esp_lcd_panel_disp_on_off(panel, false) == ESP_OK && ok;
        ok = esp_lcd_panel_disp_sleep(panel, true) == ESP_OK && ok;
    }
    return ok;
}

bool Board::pm1_gpio_low(std::uint8_t pin) {
    auto* dev = static_cast<i2c_master_dev_handle_t>(pm1_dev_);
    if (!dev || (pin != 2 && pin != 3)) return false;   // LCD rail / PA only; GPIO1 is the IRQ line (never)
    return pm1_update(dev, PM1_REG_GPIO_OUT, static_cast<std::uint8_t>(1u << pin), false);
}

bool Board::i2c_write(std::uint8_t addr, std::uint8_t reg, std::uint8_t value) {
    return i2c_write_err(addr, reg, value) == ESP_OK;
}

int Board::i2c_write_err(std::uint8_t addr, std::uint8_t reg, std::uint8_t value) {
    auto* bus = static_cast<i2c_master_bus_handle_t>(i2c_bus_);
    if (!bus || addr == pm1_addr) return ESP_ERR_INVALID_ARG;
    i2c_device_config_t cfg{};
    cfg.dev_addr_length = I2C_ADDR_BIT_LEN_7;
    cfg.device_address = addr;
    cfg.scl_speed_hz = pm1_hz;
    i2c_master_dev_handle_t dev{};
    const esp_err_t added = i2c_master_bus_add_device(bus, &cfg, &dev);
    if (added != ESP_OK) return added;
    const std::uint8_t buf[2] = {reg, value};
    const esp_err_t sent = i2c_master_transmit(dev, buf, 2, 50);
    i2c_master_bus_rm_device(dev);
    return sent;
}

bool Board::i2c_present(std::uint8_t addr) {
    auto* bus = static_cast<i2c_master_bus_handle_t>(i2c_bus_);
    if (!bus || addr == pm1_addr) return false;
    return i2c_master_probe(bus, addr, 50) == ESP_OK;
}

bool Board::present() {
    if (!ready_ || !panel_) return false;
    const bool ok=transfer_.present([&](){
        return esp_lcd_panel_draw_bitmap(static_cast<esp_lcd_panel_handle_t>(panel_),0,0,screen_w,screen_h,frame_)==ESP_OK;
    },[&](){return xSemaphoreTake(static_cast<SemaphoreHandle_t>(transfer_done_),pdMS_TO_TICKS(500))==pdTRUE;});
    if(!ok){ready_=false;ESP_LOGE(TAG,"display submission/completion failed; framebuffer retained");}
    return ok;
}

bool Board::present_rows(const DirtyRows::Plan& plan) {
    if (!ready_ || !panel_) return false;
    // Full-width rows are contiguous in the framebuffer, so each run is one
    // window. ESP32-S3 SPI TX DMA has no address/length alignment requirement
    // (IDF v5.4 spi_master.c setup_priv_desc: tx_unaligned = false off L1-cached internal memory).
    for (std::size_t i = 0; i < plan.count; ++i) {
        const auto run = plan.runs[i];
        if (run.rows <= 0 || run.y0 < 0 || run.y0 + run.rows > screen_h) continue;
        const bool ok = transfer_.present([&]() {
            return esp_lcd_panel_draw_bitmap(static_cast<esp_lcd_panel_handle_t>(panel_), 0, run.y0, screen_w, run.y0 + run.rows,
                                             frame_ + static_cast<std::size_t>(run.y0) * screen_w) == ESP_OK;
        }, [&]() { return xSemaphoreTake(static_cast<SemaphoreHandle_t>(transfer_done_), pdMS_TO_TICKS(500)) == pdTRUE; });
        if (!ok) { ready_ = false; ESP_LOGE(TAG, "display row submission/completion failed; framebuffer retained"); return false; }
    }
    return true;
}

} // namespace sticks3

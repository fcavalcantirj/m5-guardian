// Derived M5Stack display/power sequences: see THIRD_PARTY_NOTICES.md at repo root
// for the full MIT notice and pinned source provenance.
#pragma once
// M5Stack StickS3 (SKU K150) pin map for the Guardian board adapter.
//
// Provenance (recorded 2026-11-13):
//  [DOC]  https://docs.m5stack.com/en/core/StickS3 (ESP32-S3-PICO-1-N8R8, 8 MB flash,
//         8 MB octal PSRAM, ST7789P3 135x240, MOSI G39, SCK G40, CS G41, RS/DC G45,
//         RST G21, BL G38, KEY1 G11, KEY2 G12, M5PM1 at I2C 0x6E, IR TX G46 / RX G42).
//         The M5 page lists the PM1 bus as SCL G47/SDA G48 but the codec as SCL G48/
//         SDA G47; the two local, board-proven libraries below both use SDA 47 / SCL 48.
//  [SRC]  M5GFX 0.2.28 autodetect (board_M5StickS3): i2c init SDA 47 / SCL 48, PM1 id
//         read at reg 0x00, PM1 GPIO2 = "L3B Enable, LCD Power On", SPI3 40 MHz, panel
//         offsets x 52 / y 40, invert on, backlight PWM on G38.
//  [SRC]  M5Unified 0.2.21: internal I2C SCL 48 / SDA 47; buttons G11, G12 inputs; PM1
//         GPIO3 output low = speaker PA control.
//  [REAL] home-automations builds/m5sticks3.md: KEY G11 and side button G12 both wake
//         the ESP32 (ext1), PSRAM only works in octal mode, USB is the native
//         USB-Serial/JTAG (VID 0x303A PID 0x1001), serial 02:00:00:00:0B:02.
// Rotation/mirror flags and button polarity are HYPOTHESES until the first boot
// photograph and log are saved under firmware/evidence/.
namespace sticks3 {
constexpr int lcd_mosi = 39;
constexpr int lcd_sclk = 40;
constexpr int lcd_cs = 41;
constexpr int lcd_dc = 45;
constexpr int lcd_rst = 21;
constexpr int lcd_backlight = 38;
constexpr int lcd_panel_w = 135; // portrait panel geometry
constexpr int lcd_panel_h = 240;
constexpr int lcd_offset_x = 52; // controller RAM is 240x320; the glass is a window
constexpr int lcd_offset_y = 40;
constexpr int lcd_spi_hz = 40 * 1000 * 1000;

constexpr int i2c_sda = 47;
constexpr int i2c_scl = 48;
constexpr int pm1_addr = 0x6E;
constexpr int pm1_hz = 100 * 1000;

constexpr int key_front = 11; // large front key, "KEY1" / BtnA
constexpr int key_side = 12;  // the BIG side button, "KEY2" / BtnB (docs/G11-device-validation.md: physical side
                              // button -> GPIO12). The SMALL side button is the PM1 power/reset button
                              // (click = on/reset, double click = off, long = download mode), not a GPIO key.

// G16A: upright portrait 135x240, the StickS3 standing with its USB connector down
// (vendor rotation 0; see orientation.hpp). Same 64,800-byte framebuffer as before.
constexpr int screen_w = 135;
constexpr int screen_h = 240;
} // namespace sticks3

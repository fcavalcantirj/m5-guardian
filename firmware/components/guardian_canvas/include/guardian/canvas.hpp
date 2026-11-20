#pragma once

#include <cstddef>
#include <cstdint>

// Portable RGB565 software canvas. No ESP-IDF, no allocation, no board pins.
// The board renderer hands it a pixel buffer and later pushes that buffer to
// the panel. Pixels are stored byte-swapped (MSB first) when `big_endian` is
// set so that an SPI LCD can take the buffer verbatim.
namespace guardian {

constexpr std::uint16_t rgb565(std::uint8_t r, std::uint8_t g, std::uint8_t b) {
    return static_cast<std::uint16_t>(((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3));
}

namespace color {
constexpr std::uint16_t black = rgb565(0, 0, 0);
constexpr std::uint16_t white = rgb565(255, 255, 255);
constexpr std::uint16_t red = rgb565(255, 0, 0);
constexpr std::uint16_t green = rgb565(0, 255, 0);
constexpr std::uint16_t blue = rgb565(0, 0, 255);
constexpr std::uint16_t yellow = rgb565(255, 220, 0);
constexpr std::uint16_t orange = rgb565(255, 128, 0);
constexpr std::uint16_t grey = rgb565(96, 96, 96);
constexpr std::uint16_t dark = rgb565(16, 16, 24);
} // namespace color

class Canvas {
public:
    Canvas(std::uint16_t* pixels, int width, int height, bool big_endian)
        : px_(pixels), w_(width), h_(height), big_endian_(big_endian) {}

    int width() const { return w_; }
    int height() const { return h_; }
    std::uint16_t* pixels() { return px_; }
    const std::uint16_t* pixels() const { return px_; }
    std::size_t size_bytes() const { return static_cast<std::size_t>(w_) * h_ * 2; }
    // Pixels are stored byte-swapped (MSB first) for an SPI panel.
    bool big_endian() const { return big_endian_; }

    void clear(std::uint16_t c);
    void fill_rect(int x, int y, int w, int h, std::uint16_t c);
    void draw_rect(int x, int y, int w, int h, std::uint16_t c);
    void put(int x, int y, std::uint16_t c);
    // 5x7 glyphs with a 1-pixel gap, scaled by an integer factor. Returns the
    // x after the last glyph. Unknown bytes draw as '?'.
    int text(int x, int y, const char* s, std::uint16_t fg, int scale = 1);
    int text(int x, int y, const char* s, std::uint16_t fg, std::uint16_t bg, int scale);
    // Logical (not scaled) reading of a pixel, for host tests.
    std::uint16_t get(int x, int y) const;

    static constexpr int glyph_w = 5;
    static constexpr int glyph_h = 7;
    static constexpr int glyph_advance = 6;

private:
    std::uint16_t encode(std::uint16_t c) const {
        return big_endian_ ? static_cast<std::uint16_t>((c << 8) | (c >> 8)) : c;
    }
    std::uint16_t* px_;
    int w_;
    int h_;
    bool big_endian_;
};

// Column-major 5x7 bitmap for printable ASCII 32..126; bit0 = top row.
const std::uint8_t* font5x7_glyph(char c);

} // namespace guardian

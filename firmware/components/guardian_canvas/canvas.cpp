#include "guardian/canvas.hpp"

namespace guardian {

void Canvas::clear(std::uint16_t c) { fill_rect(0, 0, w_, h_, c); }

void Canvas::put(int x, int y, std::uint16_t c) {
    if (x < 0 || y < 0 || x >= w_ || y >= h_) return;
    px_[static_cast<std::size_t>(y) * w_ + x] = encode(c);
}

std::uint16_t Canvas::get(int x, int y) const {
    if (x < 0 || y < 0 || x >= w_ || y >= h_) return 0;
    const std::uint16_t v = px_[static_cast<std::size_t>(y) * w_ + x];
    return big_endian_ ? static_cast<std::uint16_t>((v << 8) | (v >> 8)) : v;
}

void Canvas::fill_rect(int x, int y, int w, int h, std::uint16_t c) {
    int x0 = x < 0 ? 0 : x;
    int y0 = y < 0 ? 0 : y;
    int x1 = x + w > w_ ? w_ : x + w;
    int y1 = y + h > h_ ? h_ : y + h;
    const std::uint16_t e = encode(c);
    for (int yy = y0; yy < y1; ++yy) {
        std::uint16_t* row = px_ + static_cast<std::size_t>(yy) * w_;
        for (int xx = x0; xx < x1; ++xx) row[xx] = e;
    }
}

void Canvas::draw_rect(int x, int y, int w, int h, std::uint16_t c) {
    if (w <= 0 || h <= 0) return;
    fill_rect(x, y, w, 1, c);
    fill_rect(x, y + h - 1, w, 1, c);
    fill_rect(x, y, 1, h, c);
    fill_rect(x + w - 1, y, 1, h, c);
}

int Canvas::text(int x, int y, const char* s, std::uint16_t fg, int scale) {
    if (scale < 1) scale = 1;
    for (; s && *s; ++s) {
        const std::uint8_t* g = font5x7_glyph(*s);
        for (int col = 0; col < glyph_w; ++col) {
            const std::uint8_t bits = g[col];
            for (int row = 0; row < glyph_h; ++row) {
                if (bits & (1u << row)) {
                    fill_rect(x + col * scale, y + row * scale, scale, scale, fg);
                }
            }
        }
        x += glyph_advance * scale;
    }
    return x;
}

int Canvas::text(int x, int y, const char* s, std::uint16_t fg, std::uint16_t bg, int scale) {
    if (scale < 1) scale = 1;
    int len = 0;
    for (const char* p = s; p && *p; ++p) ++len;
    fill_rect(x, y, len * glyph_advance * scale, (glyph_h + 1) * scale, bg);
    return text(x, y, s, fg, scale);
}

} // namespace guardian

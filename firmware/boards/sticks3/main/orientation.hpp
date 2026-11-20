#pragma once
// G16A: StickS3 display orientation, SDK-free so the host can check it.
//
// Panel facts (M5GFX 0.2.28 src/M5GFX.cpp, board_M5StickS3): ST7789, visible
// glass 135x240, offset_x 52, offset_y 40, offset_rotation 0; ST7789 memory
// 240 columns x 320 rows. Rotation table and gap formula: M5GFX 0.2.28
// src/lgfx/v1/panel/Panel_LCD.cpp Panel_LCD::setRotation and
// Panel_LCD.hpp getMadCtl (MH/ML only change refresh order, not addressing).
//
// Addressing model used below: esp_lcd adds gap_x to the column-address
// window (CASET, logical x) and gap_y to the row-address window (RASET,
// logical y). MV exchanges which address drives the physical column and row;
// MX then mirrors physical columns, MY physical rows. This is the model under
// which M5GFX's gaps are exact (r1 needs 53, not 52, because MX mirrors the
// physical column that logical y drives under MV).
namespace sticks3::orientation {

struct Panel {
    int panel_w, panel_h;    // visible glass in the native (rotation 0) frame
    int offset_x, offset_y;  // glass window inside controller memory
    int memory_w, memory_h;  // controller RAM, native frame
};
constexpr Panel sticks3_panel{135, 240, 52, 40, 240, 320};

struct Rotation {
    int index{};             // M5GFX rotation 0..3
    int width{}, height{};   // logical framebuffer size
    bool swap_xy{}, mirror_x{}, mirror_y{};
    int gap_x{}, gap_y{};
};

// M5GFX Panel_LCD::setRotation for offset_rotation 0 (rotations 0..3).
constexpr Rotation rotation(int r, const Panel& p = sticks3_panel) {
    r &= 3;
    int ox = p.offset_x, oy = p.offset_y, pw = p.panel_w, ph = p.panel_h, mw = p.memory_w, mh = p.memory_h;
    if (r & 1) { int t = ox; ox = oy; oy = t; t = pw; pw = ph; ph = t; t = mw; mw = mh; mh = t; }
    Rotation out{};
    out.index = r; out.width = pw; out.height = ph;
    out.gap_x = (r & 2) ? mw - (pw + ox) : ox;
    out.gap_y = ((1 << r) & 0b10010110) ? mh - (ph + oy) : oy;
    // getMadCtl: r0 = 0, r1 = MV|MX, r2 = MX|MY, r3 = MV|MY.
    out.swap_xy = (r & 1) != 0;
    out.mirror_x = r == 1 || r == 2;
    out.mirror_y = r == 2 || r == 3;
    return out;
}

struct Address { int column, row; };   // physical controller RAM cell (native frame)
constexpr Address to_controller(const Rotation& rot, int x, int y, const Panel& p = sticks3_panel) {
    const int caset = x + rot.gap_x, raset = y + rot.gap_y;
    int column = rot.swap_xy ? raset : caset, row = rot.swap_xy ? caset : raset;
    if (rot.mirror_x) column = p.memory_w - 1 - column;
    if (rot.mirror_y) row = p.memory_h - 1 - row;
    return {column, row};
}

// The configuration the board applies. The StickS3 stands on the table with
// its USB connector down; there is no auto-rotation (owner decision). The
// spike showed upright = the panel's native frame, i.e. vendor rotation 0
// (MADCTL 0, gap 52/40), 135x240: the same 64,800-byte framebuffer.
constexpr Rotation display = rotation(0);
constexpr const char* display_name = "portrait-usb-down";

} // namespace sticks3::orientation

#pragma once
// G21 host test support: builds 3D-head packs (adapters/companion/head3d.hpp layout) from plain
// frames, without a compressor: every frame is a raw-deflate stream of STORED blocks. The real,
// compressed packs are covered by head3d_check through art/persona/v3/frames and its manifest.
// The adler32 here is written independently of the library's.
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>
#include "persona.hpp"

namespace guardian::fixtures {

inline std::uint32_t plain_adler32(const std::vector<std::uint8_t>& d) {
    std::uint32_t a = 1, b = 0;
    for (const auto v : d) { a = (a + v) % 65521u; b = (b + a) % 65521u; }
    return (b << 16) | a;
}
// One raw-deflate stream holding `raw` in stored blocks of at most `block` bytes.
inline std::vector<std::uint8_t> stored_stream(const std::vector<std::uint8_t>& raw, std::size_t block = 65535) {
    std::vector<std::uint8_t> out; std::size_t at = 0;
    do {
        const std::size_t n = raw.size() - at < block ? raw.size() - at : block;
        out.push_back(at + n == raw.size() ? 1 : 0);   // BFINAL, BTYPE = 00, then the byte boundary
        out.push_back(static_cast<std::uint8_t>(n)); out.push_back(static_cast<std::uint8_t>(n >> 8));
        out.push_back(static_cast<std::uint8_t>(~n)); out.push_back(static_cast<std::uint8_t>(~n >> 8));
        out.insert(out.end(), raw.begin() + static_cast<std::ptrdiff_t>(at), raw.begin() + static_cast<std::ptrdiff_t>(at + n));
        at += n;
    } while (at < raw.size());
    return out;
}
// A flat frame whose colour names its place in the grid (never black, so every block is "lit").
inline std::uint16_t head_colour(int mood, int yaw_index, int pitch_index) {
    return static_cast<std::uint16_t>(((mood + 1) << 13) | ((yaw_index + 1) << 6) | ((pitch_index + 1) << 1) | 1);
}
inline std::vector<std::uint8_t> flat_frame(std::uint16_t colour) {
    std::vector<std::uint8_t> f(companion::persona::art_bytes);
    for (std::size_t i = 0; i < f.size(); i += 2) { f[i] = static_cast<std::uint8_t>(colour); f[i + 1] = static_cast<std::uint8_t>(colour >> 8); }
    return f;
}
inline void put16(std::vector<std::uint8_t>& o, std::size_t at, std::uint32_t v) { o[at] = static_cast<std::uint8_t>(v); o[at + 1] = static_cast<std::uint8_t>(v >> 8); }
inline void put32(std::vector<std::uint8_t>& o, std::size_t at, std::uint32_t v) { put16(o, at, v & 0xffffu); put16(o, at + 2, v >> 16); }
inline std::uint32_t get32(const std::vector<std::uint8_t>& o, std::size_t at) {
    return o[at] | (std::uint32_t{o[at + 1]} << 8) | (std::uint32_t{o[at + 2]} << 16) | (std::uint32_t{o[at + 3]} << 24);
}
// A well-formed pack. `frame(yaw index, pitch index)` gives each frame's bytes (default: flat_frame
// of head_colour); `stream` turns a frame into its stream (default: stored blocks).
struct PackSpec {
    int mood{};
    std::vector<int> yaw_tenths{-300, 0, 300};
    std::vector<int> pitch_tenths{-150, 0, 150};
    std::function<std::vector<std::uint8_t>(int, int)> frame;
    std::function<std::vector<std::uint8_t>(const std::vector<std::uint8_t>&)> stream;
};
inline std::size_t pack_table_offset(const PackSpec& s) { return 24 + 2 * (s.yaw_tenths.size() + s.pitch_tenths.size()); }
inline std::vector<std::uint8_t> make_pack(const PackSpec& s) {
    const std::size_t ny = s.yaw_tenths.size(), np = s.pitch_tenths.size(), table = pack_table_offset(s);
    std::vector<std::uint8_t> out(table + 12 * ny * np);
    out[0] = 'G'; out[1] = 'H'; out[2] = '3'; out[3] = 'D';
    put16(out, 4, 1); out[6] = static_cast<std::uint8_t>(s.mood); out[7] = 0;
    put16(out, 8, 135); put16(out, 10, 160); out[12] = static_cast<std::uint8_t>(ny); out[13] = static_cast<std::uint8_t>(np);
    for (std::size_t i = 0; i < ny; ++i) put16(out, 24 + 2 * i, static_cast<std::uint32_t>(s.yaw_tenths[i]) & 0xffffu);
    for (std::size_t i = 0; i < np; ++i) put16(out, 24 + 2 * ny + 2 * i, static_cast<std::uint32_t>(s.pitch_tenths[i]) & 0xffffu);
    put32(out, 20, static_cast<std::uint32_t>(out.size()));
    for (std::size_t p = 0; p < np; ++p) for (std::size_t y = 0; y < ny; ++y) {
        const auto raw = s.frame ? s.frame(static_cast<int>(y), static_cast<int>(p))
                                 : flat_frame(head_colour(s.mood, static_cast<int>(y), static_cast<int>(p)));
        const auto z = s.stream ? s.stream(raw) : stored_stream(raw);
        const std::size_t e = table + 12 * (p * ny + y);
        put32(out, e, static_cast<std::uint32_t>(out.size())); put32(out, e + 4, static_cast<std::uint32_t>(z.size()));
        put32(out, e + 8, plain_adler32(raw));
        out.insert(out.end(), z.begin(), z.end());
    }
    put32(out, 16, static_cast<std::uint32_t>(out.size()));
    return out;
}

} // namespace guardian::fixtures

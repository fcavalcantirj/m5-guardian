// G21: bounded raw-deflate inflater. See inflate.hpp.
#include "inflate.hpp"

namespace guardian::companion::inflate {
namespace {
constexpr int max_bits = 15, max_lit = 286, max_dist = 30, fixed_lit = 288;   // 286 usable literal/length codes; the fixed code spans 288
constexpr std::uint16_t length_base[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr std::uint8_t length_extra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr std::uint16_t dist_base[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
                                         4097, 6145, 8193, 12289, 16385, 24577};
constexpr std::uint8_t dist_extra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
constexpr std::uint8_t code_order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

// LSB-first bit reader. Past the end it supplies zero bytes and counts them; using one of those
// bits is an error the caller sees through spent(), so nothing ever reads outside the input.
struct Bits {
    const std::uint8_t* in; std::size_t size; std::size_t pos{};
    std::uint32_t buf{}; int cnt{}; int padded{};   // padded: zero bytes supplied past the end
    void fill() {
        while (cnt <= 24) {
            std::uint32_t byte = 0;
            if (pos < size) byte = in[pos++]; else if (padded < 8) ++padded;
            buf |= byte << cnt; cnt += 8;
        }
    }
    std::uint32_t peek(int n) { if (cnt < n) fill(); return buf & ((1u << n) - 1u); }
    void drop(int n) { buf >>= n; cnt -= n; }
    std::uint32_t take(int n) { if (!n) return 0; const auto v = peek(n); drop(n); return v; }
    // True once a bit that was never in the input has been consumed.
    bool spent() const { return padded > 0 && cnt < padded * 8; }
};

// Builds the canonical code for n symbols with the given lengths (0 = unused).
// Returns 0 for a complete code, > 0 for an incomplete one, < 0 for an over-subscribed one.
int construct(Huffman& h, const std::uint8_t* lengths, int n) {
    for (int len = 0; len <= max_bits; ++len) h.count[len] = 0;
    for (int s = 0; s < n; ++s) ++h.count[lengths[s]];
    for (auto& f : h.fast) f = 0;
    if (h.count[0] == n) return 0;   // no codes at all: complete, and every decode fails
    int left = 1;
    for (int len = 1; len <= max_bits; ++len) {
        left <<= 1; left -= h.count[len];
        if (left < 0) return left;
    }
    std::uint16_t offs[max_bits + 1]; offs[1] = 0;
    for (int len = 1; len < max_bits; ++len) offs[len + 1] = static_cast<std::uint16_t>(offs[len] + h.count[len]);
    for (int s = 0; s < n; ++s) if (lengths[s]) h.symbol[offs[lengths[s]]++] = static_cast<std::uint16_t>(s);
    // The one-read table: each short code, bit-reversed (codes arrive most significant bit first in an
    // LSB-first stream), repeated for every value of the bits above it.
    unsigned code = 0; int index = 0;
    for (int len = 1; len <= fast_bits; ++len) {
        for (int i = 0; i < h.count[len]; ++i, ++code, ++index) {
            unsigned rev = 0;
            for (int b = 0; b < len; ++b) rev |= ((code >> b) & 1u) << (len - 1 - b);
            const auto entry = static_cast<std::uint16_t>((h.symbol[index] << 4) | len);
            for (unsigned at = rev; at < (1u << fast_bits); at += 1u << len) h.fast[at] = entry;
        }
        code <<= 1;
    }
    return left;
}

// One symbol, or -1 for a bit pattern no code uses.
int decode(Bits& b, const Huffman& h) {
    const std::uint32_t window = b.peek(max_bits);
    if (const auto e = h.fast[window & ((1u << fast_bits) - 1u)]) { b.drop(e & 15); return e >> 4; }
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= max_bits; ++len) {
        code |= static_cast<int>((window >> (len - 1)) & 1u);
        const int count = h.count[len];
        if (code - count < first) { b.drop(len); return h.symbol[index + (code - first)]; }
        index += count; first += count; first <<= 1; code <<= 1;
    }
    return -1;
}

struct Out { std::uint8_t* p; std::size_t cap; std::size_t n{}; };

Result codes(Bits& b, Out& o, const Huffman& lit, const Huffman& dist) {
    for (;;) {
        const int sym = decode(b, lit);
        if (b.spent()) return Result::InputEnded;
        if (sym < 0) return Result::BadCode;
        if (sym < 256) {
            if (o.n >= o.cap) return Result::OutputFull;
            o.p[o.n++] = static_cast<std::uint8_t>(sym);
            continue;
        }
        if (sym == 256) return Result::Ok;
        const int li = sym - 257;
        if (li >= 29) return Result::BadCode;
        const std::size_t len = length_base[li] + b.take(length_extra[li]);
        const int ds = decode(b, dist);
        if (b.spent()) return Result::InputEnded;
        if (ds < 0 || ds >= max_dist) return Result::BadCode;
        const std::size_t back = dist_base[ds] + b.take(dist_extra[ds]);
        if (b.spent()) return Result::InputEnded;
        if (back > o.n) return Result::BadDistance;
        if (len > o.cap - o.n) return Result::OutputFull;
        const std::uint8_t* from = o.p + o.n - back;
        std::uint8_t* to = o.p + o.n;
        for (std::size_t i = 0; i < len; ++i) to[i] = from[i];   // byte by byte: a match may overlap itself
        o.n += len;
    }
}

Result stored(Bits& b, Out& o) {
    b.drop(b.cnt & 7);   // to the next byte boundary
    const std::uint32_t len = b.take(16), nlen = b.take(16);
    if (b.spent()) return Result::InputEnded;
    if (len != (~nlen & 0xffffu)) return Result::BadBlock;
    if (len > o.cap - o.n) return Result::OutputFull;
    for (std::uint32_t i = 0; i < len; ++i) {
        o.p[o.n + i] = static_cast<std::uint8_t>(b.take(8));
        if (b.spent()) return Result::InputEnded;
    }
    o.n += len;
    return Result::Ok;
}

Result fixed(Workspace& w, Bits& b, Out& o) {
    int s = 0;
    for (; s < 144; ++s) w.lengths[s] = 8;
    for (; s < 256; ++s) w.lengths[s] = 9;
    for (; s < 280; ++s) w.lengths[s] = 7;
    for (; s < fixed_lit; ++s) w.lengths[s] = 8;
    construct(w.lit, w.lengths, fixed_lit);
    for (s = 0; s < max_dist; ++s) w.lengths[s] = 5;
    construct(w.dist, w.lengths, max_dist);
    return codes(b, o, w.lit, w.dist);
}

Result dynamic(Workspace& w, Bits& b, Out& o) {
    const int nlen = static_cast<int>(b.take(5)) + 257, ndist = static_cast<int>(b.take(5)) + 1, ncode = static_cast<int>(b.take(4)) + 4;
    if (b.spent()) return Result::InputEnded;
    if (nlen > max_lit || ndist > max_dist) return Result::BadCode;
    int i = 0;
    for (; i < ncode; ++i) w.lengths[code_order[i]] = static_cast<std::uint8_t>(b.take(3));
    for (; i < 19; ++i) w.lengths[code_order[i]] = 0;
    if (b.spent()) return Result::InputEnded;
    if (construct(w.lit, w.lengths, 19) != 0) return Result::BadCode;   // the code-length code must be complete
    for (i = 0; i < nlen + ndist;) {
        const int sym = decode(b, w.lit);
        if (b.spent()) return Result::InputEnded;
        if (sym < 0) return Result::BadCode;
        if (sym < 16) { w.lengths[i++] = static_cast<std::uint8_t>(sym); continue; }
        std::uint8_t value = 0; int repeat;
        if (sym == 16) {
            if (i == 0) return Result::BadCode;
            value = w.lengths[i - 1]; repeat = 3 + static_cast<int>(b.take(2));
        } else if (sym == 17) repeat = 3 + static_cast<int>(b.take(3));
        else repeat = 11 + static_cast<int>(b.take(7));
        if (b.spent()) return Result::InputEnded;
        if (i + repeat > nlen + ndist) return Result::BadCode;
        while (repeat--) w.lengths[i++] = value;
    }
    if (w.lengths[256] == 0) return Result::BadCode;   // no end-of-block code
    // The literal/length lengths stay in place; the distance lengths follow them.
    int err = construct(w.lit, w.lengths, nlen);
    if (err < 0 || (err > 0 && nlen != w.lit.count[0] + w.lit.count[1])) return Result::BadCode;   // incomplete only as one 1-bit code
    err = construct(w.dist, w.lengths + nlen, ndist);
    if (err < 0 || (err > 0 && ndist != w.dist.count[0] + w.dist.count[1])) return Result::BadCode;
    return codes(b, o, w.lit, w.dist);
}
} // namespace

const char* result_text(Result r) {
    switch (r) {
    case Result::Ok: return "ok"; case Result::InputEnded: return "input_ended"; case Result::OutputFull: return "output_full";
    case Result::BadBlock: return "bad_block"; case Result::BadCode: return "bad_code"; case Result::BadDistance: return "bad_distance";
    }
    return "?";
}

Result raw(Workspace& w, const std::uint8_t* in, std::size_t in_size, std::uint8_t* out, std::size_t out_capacity, std::size_t& out_size) {
    Bits b{in, in ? in_size : 0};
    Out o{out, out ? out_capacity : 0};
    Result r = Result::Ok;
    for (;;) {
        const bool last = b.take(1) != 0;
        const std::uint32_t type = b.take(2);
        if (b.spent()) { r = Result::InputEnded; break; }
        r = type == 0 ? stored(b, o) : type == 1 ? fixed(w, b, o) : type == 2 ? dynamic(w, b, o) : Result::BadBlock;
        if (r != Result::Ok || last) break;
    }
    out_size = o.n;
    return r;
}

std::uint32_t adler32(const std::uint8_t* p, std::size_t n) {
    std::uint32_t a = 1, b = 0;
    while (n) {
        std::size_t chunk = n < 5552 ? n : 5552;   // the largest run before b can overflow 32 bits
        n -= chunk;
        while (chunk--) { a += *p++; b += a; }
        a %= 65521u; b %= 65521u;
    }
    return (b << 16) | a;
}

} // namespace guardian::companion::inflate

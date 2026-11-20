// G21: the bounded raw-deflate inflater the StickS3 uses for the 3D head frames
// (adapters/companion/inflate.*; the same source runs here and on the device). Reference streams
// were produced by Python zlib (zlib.compressobj(9, DEFLATED, -15)); their plain bytes are
// regenerated here from the same formulas. Malformed input must fail without reading or writing
// outside the given buffers (the ASan/UBSan build is the witness). Host input only, no radio.
#include "check.hpp"
#include "head_pack.hpp"
#include "inflate.hpp"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace guardian::companion::inflate;
using Bytes = std::vector<std::uint8_t>;

namespace {
Bytes from_hex(const char* h) {
    Bytes out; const std::size_t n = std::strlen(h);
    const auto nib = [](char c) { return static_cast<std::uint8_t>(c <= '9' ? c - '0' : c - 'a' + 10); };
    for (std::size_t i = 0; i + 1 < n; i += 2) out.push_back(static_cast<std::uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    return out;
}
struct Run { Result r; Bytes out; };
// Inflates into a buffer of EXACTLY `capacity` bytes (heap, so ASan sees one byte too many).
Run run(const Bytes& in, std::size_t capacity) {
    static Workspace w;   // 3.6 KB: static here, as the device keeps it inside the Head object
    Run x; x.out.resize(capacity); std::size_t n = 0;
    Bytes copy(in);       // exact-size heap copy: a read past the end is caught too
    x.r = raw(w, copy.data(), copy.size(), x.out.data(), capacity, n);
    if (n > capacity) n = capacity + 1;   // never trusted: checked by the callers
    x.out.resize(n <= capacity ? n : capacity);
    return x;
}
// zlib.compressobj(9, DEFLATED, -15) of b'hello hello hello hello' (one fixed-Huffman block).
const char* const fixed_hex = "cb48cdc9c957c8402701";
// ... of dynamic_plain() (one dynamic-Huffman block, 93 bytes), adler32 0x43185169.
const char* const dynamic_hex =
    "b591310ac0300c0307096cb0b7e441c9efd35f55dd4397c41881b16f101c60a34543005f16d00cb63034080b981e2708999e74923e7b76a636e521bb"
    "d31f4ecd1172b7ee06b95b7783d40ad0a15680905a014aad0021b50284fc747901";
// ... of the same bytes with a Z_FULL_FLUSH after 400 (dynamic block, empty stored block, dynamic block).
const char* const multi_hex =
    "ac8e310a00200c0387045a68b7f641fa7bfd95757370534220901b0e9016163060770021908156818941ea78414857a792d49e9ef45ad549a652277b"
    "e509f9ab7b41feea5e90d365010000ffffad8e310ac04008048b5d50d0ee7cd0ddefbd5fc50748204496812da69804964012bb0613830090bd6cc1ea"
    "15f95951a792d4131ef47ac52543a997a746ffa7cce636ca6c6ea3cce636ca4bcb03";
Bytes dynamic_plain() {
    static const int pick[10] = {3, 3, 3, 7, 7, 11, 19, 200, 3, 64};
    Bytes d;
    for (int i = 0; i < 900; ++i) d.push_back(static_cast<std::uint8_t>(pick[(i * i + i / 7) % 10] + ((i / 97) & 1)));
    return d;
}
// Writes a deflate bit stream: plain fields least significant bit first, Huffman codes most significant bit first.
struct BitWriter {
    Bytes out; int used{};
    void bit(unsigned b) { if (!used) out.push_back(0); out.back() = static_cast<std::uint8_t>(out.back() | ((b & 1u) << used)); used = (used + 1) & 7; }
    void field(unsigned v, int n) { for (int i = 0; i < n; ++i) bit(v >> i); }
    void code(unsigned v, int n) { for (int i = n - 1; i >= 0; --i) bit(v >> i); }
    void align() { used = 0; }
};
// The fixed code's symbols used below: literal/length 256 = 0000000 (7), 285 = 11000101 (8); distance codes are 5 bits.
void fixed_match_258(BitWriter& w, unsigned distance_code, unsigned extra, int extra_bits) {
    w.code(0xC5, 8);                       // length symbol 285 = 258 bytes, no extra bits
    w.code(distance_code, 5); w.field(extra, extra_bits);
}
Bytes noise(std::size_t n, std::uint32_t seed) {
    Bytes d(n);
    for (auto& b : d) { seed = seed * 1664525u + 1013904223u; b = static_cast<std::uint8_t>(seed >> 24); }
    return d;
}
}

GUARDIAN_CASE(stored_blocks_round_trip) {
    const auto plain = noise(70000, 7);                          // two stored blocks (65,535 + 4,465)
    const auto stream = guardian::fixtures::stored_stream(plain);
    const auto x = run(stream, plain.size());
    CHECK(x.r == Result::Ok); CHECK(x.out == plain);
    const auto small = run(guardian::fixtures::stored_stream(noise(10, 1), 3), 10);   // four tiny blocks
    CHECK(small.r == Result::Ok); CHECK(small.out == noise(10, 1));
}

GUARDIAN_CASE(fixed_huffman_block_matches_zlib) {
    const auto x = run(from_hex(fixed_hex), 64);
    CHECK(x.r == Result::Ok);
    CHECK_EQ(std::string(x.out.begin(), x.out.end()), std::string("hello hello hello hello"));
    const auto empty = run(from_hex("0300"), 8);                 // zlib's stream for no bytes at all
    CHECK(empty.r == Result::Ok); CHECK_EQ(empty.out.size(), std::size_t{0});
}

GUARDIAN_CASE(dynamic_huffman_block_matches_zlib) {
    const auto plain = dynamic_plain();
    const auto x = run(from_hex(dynamic_hex), plain.size());
    CHECK(x.r == Result::Ok); CHECK(x.out == plain);
    CHECK_EQ(adler32(x.out.data(), x.out.size()), 0x43185169u);
}

GUARDIAN_CASE(several_blocks_in_one_stream_match_zlib) {
    const auto plain = dynamic_plain();
    const auto x = run(from_hex(multi_hex), plain.size() + 5);   // room to spare: the size comes from the stream
    CHECK(x.r == Result::Ok); CHECK(x.out == plain);
}

GUARDIAN_CASE(longest_match_at_the_farthest_distance_and_an_overlapping_run) {
    // 32,768 noise bytes in a stored block, then a fixed block: 258 bytes copied from 32,768 back
    // (distance code 29, base 24577 + 8191), then 258 bytes from 1 back (a run of the last byte).
    const auto head = noise(32768, 99);
    BitWriter w; w.out = {0, 0x00, 0x80, 0xff, 0x7f}; w.out.insert(w.out.end(), head.begin(), head.end());
    w.field(1, 1); w.field(1, 2);                                // final block, fixed Huffman
    fixed_match_258(w, 29, 8191, 13);
    fixed_match_258(w, 0, 0, 0);                                 // distance 1
    w.code(0, 7);                                                // end of block
    Bytes want = head;
    for (int i = 0; i < 258; ++i) want.push_back(head[static_cast<std::size_t>(i)]);
    const std::uint8_t last = want.back();
    for (int i = 0; i < 258; ++i) want.push_back(last);
    const auto x = run(w.out, want.size());
    CHECK(x.r == Result::Ok); CHECK(x.out == want);
    // The same match with nothing before it points outside the output.
    BitWriter bad; bad.field(1, 1); bad.field(1, 2); fixed_match_258(bad, 29, 8191, 13); bad.code(0, 7);
    const auto y = run(bad.out, 4096);
    CHECK(y.r == Result::BadDistance); CHECK_EQ(y.out.size(), std::size_t{0});
}

GUARDIAN_CASE(every_truncation_fails_and_stays_inside_the_buffers) {
    const auto plain = dynamic_plain();
    for (const char* hex : {dynamic_hex, multi_hex, fixed_hex}) {
        const auto stream = from_hex(hex);
        unsigned ok = 0, over = 0;
        for (std::size_t cut = 0; cut < stream.size(); ++cut) {
            const auto x = run(Bytes(stream.begin(), stream.begin() + static_cast<std::ptrdiff_t>(cut)), plain.size());
            ok += x.r == Result::Ok; over += x.out.size() > plain.size();
        }
        CHECK_EQ(ok, 0u); CHECK_EQ(over, 0u);
    }
    static Workspace w; std::size_t n = 77; std::uint8_t one = 0;
    CHECK(raw(w, nullptr, 0, &one, 1, n) == Result::InputEnded); CHECK_EQ(n, std::size_t{0});
    CHECK(raw(w, nullptr, 50, &one, 1, n) == Result::InputEnded);   // a null input is an empty input
}

GUARDIAN_CASE(output_is_never_written_past_its_capacity) {
    const auto plain = dynamic_plain();
    for (const std::size_t cap : {std::size_t{0}, std::size_t{1}, std::size_t{257}, plain.size() - 1}) {
        const auto x = run(from_hex(dynamic_hex), cap);
        CHECK(x.r == Result::OutputFull); CHECK(x.out.size() <= cap);
        CHECK(std::equal(x.out.begin(), x.out.end(), plain.begin()));   // what was written is the right prefix
    }
    const auto stored = run(guardian::fixtures::stored_stream(noise(100, 3)), 99);
    CHECK(stored.r == Result::OutputFull);
    static Workspace w; std::size_t n = 0; const auto s = from_hex(fixed_hex);
    CHECK(raw(w, s.data(), s.size(), nullptr, 100, n) == Result::OutputFull);   // no output buffer: no capacity
}

GUARDIAN_CASE(malformed_blocks_are_refused) {
    CHECK(run({0x07}, 16).r == Result::BadBlock);                              // final block of the reserved type 3
    CHECK(run({0x01, 0x05, 0x00, 0x00, 0x00, 1, 2, 3, 4, 5}, 16).r == Result::BadBlock);   // stored: LEN and NLEN disagree
    // Dynamic block whose 19 code-length codes all have length 1: over-subscribed.
    BitWriter w; w.field(1, 1); w.field(2, 2); w.field(0, 5); w.field(0, 5); w.field(15, 4);
    for (int i = 0; i < 19; ++i) w.field(1, 3);
    w.field(0, 16);
    CHECK(run(w.out, 16).r == Result::BadCode);
    // Dynamic block with no end-of-block code: lengths for 257 literals all zero.
    BitWriter e; e.field(1, 1); e.field(2, 2); e.field(0, 5); e.field(0, 5); e.field(15, 4);
    // code-length code: symbols 0 and 18 get length 1 (order 16 17 18 0 ...), the rest 0
    for (int i = 0; i < 19; ++i) e.field(i == 2 || i == 3 ? 1 : 0, 3);
    // 258 lengths of zero: symbol 18 (code 1) with 7 extra bits = 138 zeros, then 120 zeros
    e.code(1, 1); e.field(127, 7); e.code(1, 1); e.field(109, 7);
    e.field(0, 16);
    CHECK(run(e.out, 16).r == Result::BadCode);
    // Fixed block using length symbol 286, which the fixed code has but deflate never assigns.
    BitWriter l; l.field(1, 1); l.field(1, 2); l.code(0xC6, 8); l.field(0, 16);
    CHECK(run(l.out, 600).r == Result::BadCode);
    CHECK_EQ(std::string(result_text(Result::BadCode)), std::string("bad_code"));
    CHECK_EQ(std::string(result_text(Result::Ok)), std::string("ok"));
}

GUARDIAN_CASE(corrupted_streams_always_end_inside_the_buffers) {
    // 3,000 single- and double-byte corruptions of the two reference streams: any result is allowed,
    // but it must return, and the output never exceeds the buffer (ASan checks the bytes themselves).
    const auto plain = dynamic_plain();
    std::uint32_t seed = 12345; unsigned over = 0, runs = 0, still_ok = 0;
    for (const char* hex : {dynamic_hex, multi_hex}) {
        const auto base = from_hex(hex);
        for (int i = 0; i < 1500; ++i) {
            auto s = base;
            for (int k = 0; k < 1 + (i & 1); ++k) {
                seed = seed * 1664525u + 1013904223u;
                s[(seed >> 8) % s.size()] ^= static_cast<std::uint8_t>(1u << ((seed >> 28) & 7u));
            }
            const auto x = run(s, plain.size());
            ++runs; over += x.out.size() > plain.size(); still_ok += x.r == Result::Ok;
        }
    }
    CHECK_EQ(runs, 3000u); CHECK_EQ(over, 0u);
    CHECK(still_ok < runs);   // most corruptions are noticed by deflate itself; the rest is what the adler32 is for
}

GUARDIAN_CASE(adler32_matches_the_reference_values) {
    const std::string w = "Wikipedia";
    CHECK_EQ(adler32(reinterpret_cast<const std::uint8_t*>(w.data()), w.size()), 0x11E60398u);
    CHECK_EQ(adler32(nullptr, 0), 1u);
    const auto big = noise(200000, 5);                           // longer than one 5,552-byte run
    CHECK_EQ(adler32(big.data(), big.size()), guardian::fixtures::plain_adler32(big));
}

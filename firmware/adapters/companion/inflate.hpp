#pragma once
#include <cstddef>
#include <cstdint>

// G21: a bounded raw-deflate inflater (RFC 1951; no zlib or gzip wrapper) for the 3D head frames.
// SDK-free: the SAME source runs in the host checks and on the StickS3, so "the frame the pipeline
// packed is the frame the device paints" is proven on the host for every shipped frame
// (tests/head3d_check.cpp inflates each one and compares its sha256 with the manifest).
//
// Why not the ESP32-S3 ROM inflater (tinfl_decompress, esp_rom/include/miniz.h, ROM 0x40000828):
// it cannot run on the host, so the byte-exact round trip could only be proven on the device.
//
// Bounds: never reads past in + in_size, never writes past out + out_capacity, never allocates,
// keeps its tables in a caller-owned Workspace (about 3.6 KB; not on the stack) and always
// terminates (every step consumes input; a stream that runs past its end is an error).
// Stored, fixed-Huffman and dynamic-Huffman blocks. Written from RFC 1951; the canonical-code
// construction follows the method of zlib's contrib/puff (Mark Adler), no code copied.
namespace guardian::companion::inflate {

enum class Result : std::uint8_t {
    Ok,           // the final block ended; out_size bytes were written
    InputEnded,   // the stream needs more bytes than in_size
    OutputFull,   // the stream holds more than out_capacity bytes
    BadBlock,     // reserved block type, or a stored block whose length check fails
    BadCode,      // code lengths that do not form a usable Huffman code, or an unassigned code
    BadDistance,  // a match that points before the start of the output
};
const char* result_text(Result);

constexpr int fast_bits = 9;   // codes up to this length decode with one table read
struct Huffman {
    std::uint16_t count[16];              // codes of each length
    std::uint16_t symbol[288];            // symbols in canonical order
    std::uint16_t fast[1u << fast_bits];  // (symbol << 4) | length for short codes, 0 = use the slow walk
};
struct Workspace {
    Huffman lit, dist;
    std::uint8_t lengths[320];            // 288 literal/length + 32 distance code lengths
};

// Inflates one complete raw-deflate stream. out_size = the bytes written, also on failure (the
// caller decides what a partial output is worth: the head never shows one).
Result raw(Workspace&, const std::uint8_t* in, std::size_t in_size, std::uint8_t* out, std::size_t out_capacity,
           std::size_t& out_size);

// Adler-32 (RFC 1950) of the inflated frame: the per-frame check the pack carries.
std::uint32_t adler32(const std::uint8_t*, std::size_t);

} // namespace guardian::companion::inflate

#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include "inflate.hpp"
#include "persona.hpp"

// G21: the 3D Guardian head. Owner 2026-11-17: "the face is the repo art, in 3D". The head is not
// rendered on the device: tools/face3d/project_views.py renders the owner's master, projected on
// the Meshy head, from a grid of yaw x pitch angles; tools/face3d/pack_frames.py packs one mood's
// grid into one file (layout below); the board embeds the files and this module picks ONE frame by
// the stick's yaw and pitch and inflates it into a caller-owned buffer. That frame is then simply
// the art the portrait warp (upright rotation, breathing) and the snow-globe burst read.
// SDK-free and host-tested. Decoration only: it never changes what is shown about Wi-Fi, and it is
// used for a fresh rated face only (never an ALERT pulse, never the NoData silhouette).
//
// Pack layout (little-endian; pack_frames.py is the writer, parse() the only reader):
//    0  char[4] "GH3D"      4  u16 format = 1      6  u8 mood (0..4 = VeryGood..Horrible)   7  u8 0
//    8  u16 width = 135    10  u16 height = 160   12  u8 yaw count   13  u8 pitch count    14  u16 0
//   16  u32 file size      20  u32 offset of the first stream
//   24  i16[yaw count]   yaw angles, tenths of a degree, ascending
//       i16[pitch count] pitch angles, tenths of a degree, ascending
//       {u32 offset, u32 size, u32 adler32 of the inflated frame}[pitch count x yaw count], pitch-major
//       the raw-deflate streams, back to back, in table order, to the end of the file
// A frame inflates to exactly persona::art_bytes (135x160 little-endian RGB565), the same bytes as a
// 2D portrait file.
namespace guardian::companion::head3d {

constexpr std::size_t max_yaw = 32, max_pitch = 16, moods = 5;
constexpr std::uint16_t pack_format = 1;
constexpr std::size_t header_bytes = 24, entry_bytes = 12;

enum class PackError : std::uint8_t { Ok, TooShort, Magic, Format, Mood, Geometry, Grid, Size, Table, Duplicate };
const char* pack_error_text(PackError);

struct Entry { std::uint32_t offset{}, size{}, adler{}; };
struct FrameSet {
    const std::uint8_t* data{};              // the whole pack (flash); nullptr = no set
    std::uint32_t size{};
    std::uint8_t mood{}, yaw_count{}, pitch_count{};
    std::array<std::int16_t, max_yaw> yaw{};      // tenths of a degree
    std::array<std::int16_t, max_pitch> pitch{};
    std::uint32_t table{};                   // offset of the entry table
    bool valid() const { return data != nullptr; }
    std::size_t frames() const { return static_cast<std::size_t>(yaw_count) * pitch_count; }
    Entry entry(int yaw_index, int pitch_index) const;   // the caller keeps the indexes inside the grid
};
// Validates every header field, both angle lists and the whole table (each stream inside the file,
// streams back to back, the last one ending the file). `out` is written only on Ok.
PackError parse(const std::uint8_t* data, std::size_t size, FrameSet& out);

// One axis of the grid with hysteresis. `current` < 0 (nothing shown yet): the nearest angle.
// Otherwise the index only moves once the angle is PAST the midpoint to a neighbour by `hysteresis`
// x that gap (0..0.45), so an angle resting on a boundary never flips between two frames. Outside
// the grid the end frame is held. A non-finite angle keeps `current` (or the nearest to 0).
int choose(const std::int16_t* tenths, int count, int current, float angle_deg, float hysteresis);

// Live TUNE ranges (the board's head.* keys; head3d_check keeps the defaults inside).
struct Range { float lo, hi; };
constexpr Range gain_range{-2.0f, 2.0f}, hysteresis_range{0.0f, 0.45f};
struct Params {
    bool on{false};             // OWNER 2026-11-18: the approved design is the v4 2D portrait; the 3D frames show only when the owner turns head.on=1
    // Frame angle per degree of the stick's pose (motion::Output yaw_deg / pitch_deg). Signs follow
    // project_views.py (yaw + = the head turns to the viewer's right, pitch + = it looks down) and
    // motion.hpp (yaw + = the stick turned anticlockwise seen from above, pitch + = its top tipped
    // away): +1 / -1 is "a head fixed inside the stick". The pitch default is half of that because the
    // stick's useful pitch range in a hand is about twice the +-15 degree pitch grid. INFERRED from
    // the two conventions, not yet seen on the glass: flip a sign with TUNE if it turns the wrong way.
    float yaw_gain{1.0f};
    float pitch_gain{-0.5f};
    float hysteresis{0.2f};     // fraction of the gap between two neighbouring frames
};

class Head {
public:
    // Two buffers of persona::art_bytes each, caller-owned (StickS3: PSRAM, placed once at boot). A new
    // frame is inflated into the one NOT shown and they swap only when it is complete and its check
    // passes, so the pointer names the pixels: the warp cache and the burst compare pointers.
    Head(std::uint8_t* buffer_a, std::uint8_t* buffer_b);
    // Boot: one mood's pack. A pack that fails parse(), or a second pack for a mood, is refused.
    PackError add(const std::uint8_t* pack, std::size_t size);
    void configure(const Params&);
    const Params& params() const { return params_; }
    // The art (art_bytes) for rated mood index `mood` with the stick at yaw / pitch (degrees), or
    // nullptr = paint the 2D portrait (off, no buffers, no set for this mood, or a set that failed).
    // `hold`: answer exactly as the previous call for this mood did (a running burst owns the frame).
    // At most one frame is inflated per call; nothing is allocated.
    const std::uint8_t* frame(int mood, float yaw_deg, float pitch_deg, bool hold = false);
    // A usable set for this mood (present and never failed).
    bool has(int mood) const;
    const FrameSet* set(int mood) const;
    std::uint8_t sets() const;                   // usable sets
    std::uint16_t frames() const;                // frames in usable sets
    std::uint32_t inflates() const { return inflates_; }     // frames inflated since boot
    std::uint32_t reuses() const { return reuses_; }         // frame changes served by the other buffer
    std::uint32_t failures() const { return failures_; }     // frames that failed (their set is then unused)
    inflate::Result last_failure() const { return last_failure_; }
    bool last_failure_was_check() const { return check_failed_; }   // inflated, but size or adler32 differed
    int shown_mood() const { return shown_.mood; }           // -1: no frame is loaded
    int yaw_index() const { return shown_.yaw; }
    int pitch_index() const { return shown_.pitch; }
private:
    struct Key {
        int mood{-1}, yaw{-1}, pitch{-1};
        bool operator==(const Key& o) const { return mood == o.mood && yaw == o.yaw && pitch == o.pitch; }
    };
    std::array<FrameSet, moods> sets_{};
    std::array<bool, moods> failed_{};
    std::array<std::uint8_t*, 2> buffers_{};
    std::array<Key, 2> holds_{};                 // what each buffer holds
    int current_{};                              // the buffer that is shown
    Key shown_{};
    Params params_{};
    bool have_last_{};
    int last_mood_{-1};
    const std::uint8_t* last_{};
    std::uint32_t inflates_{}, reuses_{}, failures_{};
    inflate::Result last_failure_{inflate::Result::Ok};
    bool check_failed_{};
    inflate::Workspace work_{};
};

} // namespace guardian::companion::head3d

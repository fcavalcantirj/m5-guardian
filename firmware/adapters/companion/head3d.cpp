// G21: the 3D head's frame sets and frame choice. See head3d.hpp. No allocation, no SDK.
#include "head3d.hpp"
#include <cmath>

namespace guardian::companion::head3d {
namespace {
std::uint16_t le16(const std::uint8_t* p) { return static_cast<std::uint16_t>(p[0] | (p[1] << 8)); }
std::uint32_t le32(const std::uint8_t* p) { return le16(p) | (static_cast<std::uint32_t>(le16(p + 2)) << 16); }
float degrees(const std::int16_t* tenths, int i) { return static_cast<float>(tenths[i]) * 0.1f; }
}

const char* pack_error_text(PackError e) {
    switch (e) {
    case PackError::Ok: return "ok"; case PackError::TooShort: return "too_short"; case PackError::Magic: return "magic";
    case PackError::Format: return "format"; case PackError::Mood: return "mood"; case PackError::Geometry: return "geometry";
    case PackError::Grid: return "grid"; case PackError::Size: return "size"; case PackError::Table: return "table";
    case PackError::Duplicate: return "duplicate";
    }
    return "?";
}

Entry FrameSet::entry(int yaw_index, int pitch_index) const {
    const std::uint8_t* e = data + table + entry_bytes * (static_cast<std::size_t>(pitch_index) * yaw_count + static_cast<std::size_t>(yaw_index));
    return {le32(e), le32(e + 4), le32(e + 8)};
}

PackError parse(const std::uint8_t* data, std::size_t size, FrameSet& out) {
    if (!data || size < header_bytes) return PackError::TooShort;
    if (data[0] != 'G' || data[1] != 'H' || data[2] != '3' || data[3] != 'D') return PackError::Magic;
    if (le16(data + 4) != pack_format) return PackError::Format;
    if (data[6] >= moods || data[7] != 0) return PackError::Mood;
    if (le16(data + 8) != persona::art_w || le16(data + 10) != persona::art_h) return PackError::Geometry;
    FrameSet s{};
    s.mood = data[6]; s.yaw_count = data[12]; s.pitch_count = data[13];
    if (!s.yaw_count || s.yaw_count > max_yaw || !s.pitch_count || s.pitch_count > max_pitch || le16(data + 14) != 0) return PackError::Grid;
    if (size > 0xffffffffu || le32(data + 16) != size) return PackError::Size;
    s.table = static_cast<std::uint32_t>(header_bytes + 2u * (s.yaw_count + s.pitch_count));
    const std::size_t first = s.table + entry_bytes * s.frames();
    if (first > size) return PackError::Size;
    const std::uint8_t* angles = data + header_bytes;
    for (int i = 0; i < s.yaw_count; ++i) {
        s.yaw[static_cast<std::size_t>(i)] = static_cast<std::int16_t>(le16(angles + 2 * i));
        if (i && s.yaw[static_cast<std::size_t>(i)] <= s.yaw[static_cast<std::size_t>(i - 1)]) return PackError::Grid;
    }
    angles += 2 * s.yaw_count;
    for (int i = 0; i < s.pitch_count; ++i) {
        s.pitch[static_cast<std::size_t>(i)] = static_cast<std::int16_t>(le16(angles + 2 * i));
        if (i && s.pitch[static_cast<std::size_t>(i)] <= s.pitch[static_cast<std::size_t>(i - 1)]) return PackError::Grid;
    }
    if (le32(data + 20) != first) return PackError::Table;
    // The streams lie back to back from the end of the table to the end of the file.
    s.data = data; s.size = static_cast<std::uint32_t>(size);
    std::size_t at = first;
    for (int p = 0; p < s.pitch_count; ++p) for (int y = 0; y < s.yaw_count; ++y) {
        const Entry e = s.entry(y, p);
        if (e.offset != at || e.size == 0 || e.size > size - at) return PackError::Table;
        at += e.size;
    }
    if (at != size) return PackError::Table;
    out = s;
    return PackError::Ok;
}

int choose(const std::int16_t* tenths, int count, int current, float angle_deg, float hysteresis) {
    if (!tenths || count <= 0) return -1;
    const bool usable = std::isfinite(angle_deg);
    if (current < 0 || current >= count) {   // nothing shown yet: the nearest angle (to 0 when the angle is unusable)
        const float want = usable ? angle_deg : 0.0f;
        int best = 0; float best_d = std::fabs(degrees(tenths, 0) - want);
        for (int i = 1; i < count; ++i) {
            const float d = std::fabs(degrees(tenths, i) - want);
            if (d < best_d) { best_d = d; best = i; }
        }
        return best;
    }
    if (!usable) return current;
    const float h = hysteresis < hysteresis_range.lo ? hysteresis_range.lo : hysteresis > hysteresis_range.hi ? hysteresis_range.hi : hysteresis;
    int i = current;
    for (; i + 1 < count; ++i) {
        const float lo = degrees(tenths, i), hi = degrees(tenths, i + 1);
        if (!(angle_deg > (lo + hi) * 0.5f + h * (hi - lo))) break;
    }
    for (; i > 0; --i) {
        const float lo = degrees(tenths, i - 1), hi = degrees(tenths, i);
        if (!(angle_deg < (lo + hi) * 0.5f - h * (hi - lo))) break;
    }
    return i;
}

Head::Head(std::uint8_t* buffer_a, std::uint8_t* buffer_b) {
    if (buffer_a && buffer_b && buffer_a != buffer_b) buffers_ = {buffer_a, buffer_b};   // two distinct buffers, or none
}

PackError Head::add(const std::uint8_t* pack, std::size_t size) {
    FrameSet s;
    const auto e = parse(pack, size, s);
    if (e != PackError::Ok) return e;
    if (sets_[s.mood].valid()) return PackError::Duplicate;
    sets_[s.mood] = s; failed_[s.mood] = false;
    return PackError::Ok;
}

void Head::configure(const Params& p) {
    params_ = p;
    const auto clamp = [](float v, Range r) { return !(v >= r.lo) ? r.lo : v > r.hi ? r.hi : v; };
    params_.yaw_gain = clamp(p.yaw_gain, gain_range); params_.pitch_gain = clamp(p.pitch_gain, gain_range);
    params_.hysteresis = clamp(p.hysteresis, hysteresis_range);
}

bool Head::has(int mood) const {
    return mood >= 0 && mood < static_cast<int>(moods) && sets_[static_cast<std::size_t>(mood)].valid() && !failed_[static_cast<std::size_t>(mood)];
}
const FrameSet* Head::set(int mood) const { return has(mood) ? &sets_[static_cast<std::size_t>(mood)] : nullptr; }
std::uint8_t Head::sets() const {
    std::uint8_t n = 0;
    for (int m = 0; m < static_cast<int>(moods); ++m) n = static_cast<std::uint8_t>(n + (has(m) ? 1 : 0));
    return n;
}
std::uint16_t Head::frames() const {
    std::size_t n = 0;
    for (int m = 0; m < static_cast<int>(moods); ++m) if (has(m)) n += sets_[static_cast<std::size_t>(m)].frames();
    return static_cast<std::uint16_t>(n);
}

const std::uint8_t* Head::frame(int mood, float yaw_deg, float pitch_deg, bool hold) {
    if (hold && have_last_ && last_mood_ == mood) return last_;
    const auto answer = [&](const std::uint8_t* art) { have_last_ = true; last_mood_ = mood; last_ = art; return art; };
    if (!params_.on || !buffers_[0] || !has(mood)) return answer(nullptr);
    const FrameSet& s = sets_[static_cast<std::size_t>(mood)];
    const bool same_mood = shown_.mood == mood;
    Key want;
    want.mood = mood;
    want.yaw = choose(s.yaw.data(), s.yaw_count, same_mood ? shown_.yaw : -1, yaw_deg * params_.yaw_gain, params_.hysteresis);
    want.pitch = choose(s.pitch.data(), s.pitch_count, same_mood ? shown_.pitch : -1, pitch_deg * params_.pitch_gain, params_.hysteresis);
    if (want == shown_) return answer(buffers_[static_cast<std::size_t>(current_)]);
    const int other = current_ ^ 1;
    if (holds_[static_cast<std::size_t>(other)] == want) {   // the frame it just left: still inflated in the other buffer
        current_ = other; shown_ = want; ++reuses_;
        return answer(buffers_[static_cast<std::size_t>(current_)]);
    }
    // Inflate into the buffer that is NOT shown; it becomes the shown one only when it is whole and its check passes.
    holds_[static_cast<std::size_t>(other)] = Key{};
    const Entry e = s.entry(want.yaw, want.pitch);
    std::uint8_t* out = buffers_[static_cast<std::size_t>(other)];
    std::size_t n = 0;
    const auto result = inflate::raw(work_, s.data + e.offset, e.size, out, persona::art_bytes, n);
    const bool checked = result == inflate::Result::Ok && n == persona::art_bytes && inflate::adler32(out, n) == e.adler;
    if (!checked) {   // never a partial or wrong frame, and never a face that works at some angles only
        ++failures_; last_failure_ = result; check_failed_ = result == inflate::Result::Ok;
        failed_[static_cast<std::size_t>(mood)] = true;
        for (auto& h : holds_) if (h.mood == mood) h = Key{};
        if (shown_.mood == mood) shown_ = Key{};
        return answer(nullptr);
    }
    ++inflates_;
    holds_[static_cast<std::size_t>(other)] = want; current_ = other; shown_ = want;
    return answer(buffers_[static_cast<std::size_t>(current_)]);
}

} // namespace guardian::companion::head3d

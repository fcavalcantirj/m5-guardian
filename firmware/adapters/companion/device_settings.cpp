// G24 device settings: the blob codec and store, the measured-hours table, the STATUS fragments.
#include "device_settings.hpp"
#include <array>
#include <cstdio>
#include <cstring>

namespace guardian::companion {
namespace {
constexpr char magic[4] = {'G', 'S', 'E', 'T'};
constexpr std::uint16_t format = 1;
// CRC-32 (reflected 0xEDB88320, initial and final inversion: the zlib value), bitwise: 12 bytes only.
std::uint32_t crc32_of(const std::uint8_t* data, std::size_t n) {
    std::uint32_t crc = 0xffffffffu;
    for (std::size_t i = 0; i < n; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}
void put32(std::uint8_t* p, std::uint32_t v) { for (int i = 0; i < 4; ++i) p[i] = static_cast<std::uint8_t>(v >> (8 * i)); }
std::uint32_t get32(const std::uint8_t* p) { std::uint32_t v = 0; for (int i = 3; i >= 0; --i) v = (v << 8) | p[i]; return v; }

// ---- the measured hours (awake minutes from full to the 20 % floor), MEASURED on the StickS3 ----
// Each entry cites its line of firmware/evidence/sticks3-G24-spike-20261121.log. Nothing is interpolated:
// a choice the spike did not drain says "not measured yet" until a full drain is entered here.
constexpr char kAlwaysSource[] = "firmware/evidence/sticks3-G24-spike-20261121.log:38 (always listening, 2 h 05 min to 2 h 08 min; the lower bound)";
constexpr char kMinuteSource[] = "firmware/evidence/sticks3-G24-spike-20261121.log:43 (mode G = listen 10 s / off 50 s with every lever, about 7 h 14 min)";
constexpr char kNotMeasured[] = "firmware/evidence/sticks3-G24-spike-20261121.log:56 (not measured: listen 10 s / off 20 s with every lever; backlight levels while lit)";
struct GuardRow { GuardCycle choice; Hours hours; };
constexpr std::array<GuardRow, guard_cycle_count> kGuardHours{{
    {GuardCycle::Always, {true, 125, kAlwaysSource}},
    {GuardCycle::Every30s, {false, 0, kNotMeasured}},
    {GuardCycle::EveryMinute, {true, 434, kMinuteSource}},
}};
struct BrightRow { std::uint8_t pct; Hours hours; };
constexpr std::array<BrightRow, brightness_choices.size()> kBrightHours{{
    {10, {false, 0, kNotMeasured}}, {30, {false, 0, kNotMeasured}}, {60, {false, 0, kNotMeasured}},
    {80, {false, 0, kNotMeasured}}, {100, {false, 0, kNotMeasured}},
}};
// Highest / lowest over the MEASURED entries of one table; fewer than two measured: neither.
template <typename Rows>
Extreme extreme_of(const Rows& rows, std::size_t index) {
    if (index >= rows.size() || !rows[index].hours.measured) return Extreme::None;
    std::size_t measured = 0; std::uint16_t lo = 0xffff, hi = 0;
    for (const auto& r : rows) if (r.hours.measured) {
        ++measured;
        if (r.hours.minutes < lo) lo = r.hours.minutes;
        if (r.hours.minutes > hi) hi = r.hours.minutes;
    }
    if (measured < 2 || lo == hi) return Extreme::None;
    const auto m = rows[index].hours.minutes;
    return m == hi ? Extreme::Highest : m == lo ? Extreme::Lowest : Extreme::None;
}
std::size_t guard_index(GuardCycle c) {
    for (std::size_t i = 0; i < kGuardHours.size(); ++i) if (kGuardHours[i].choice == c) return i;
    return kGuardHours.size();
}
std::size_t bright_index(std::uint8_t pct) {
    for (std::size_t i = 0; i < kBrightHours.size(); ++i) if (kBrightHours[i].pct == pct) return i;
    return kBrightHours.size();
}
// The length snprintf reported, or 0 with an empty string when it did not fit (never cut).
std::size_t fit(int n, char* out, std::size_t capacity) {
    if (n < 0 || static_cast<std::size_t>(n) >= capacity) { out[0] = 0; return 0; }
    return static_cast<std::size_t>(n);
}
} // namespace

std::size_t encode_settings(const DeviceChoices& c, std::uint8_t* out, std::size_t capacity) {
    if (!out || capacity < settings_record_bytes || !c.valid()) return 0;
    std::memcpy(out, magic, 4);
    out[4] = static_cast<std::uint8_t>(format & 0xff); out[5] = static_cast<std::uint8_t>(format >> 8);
    out[6] = static_cast<std::uint8_t>(c.guard); out[7] = c.bright_pct;
    put32(out + 8, crc32_of(out, 8));
    return settings_record_bytes;
}

bool decode_settings(const std::uint8_t* in, std::size_t size, DeviceChoices& out) {
    if (!in || size != settings_record_bytes || std::memcmp(in, magic, 4) != 0) return false;
    if (get32(in + 8) != crc32_of(in, 8)) return false;
    if ((in[4] | (in[5] << 8)) != format) return false;
    DeviceChoices c;
    if (!guard_cycle_from(in[6], c.guard)) return false;
    c.bright_pct = in[7];
    if (!c.valid()) return false;
    out = c;
    return true;
}

const char* settings_store_text(SettingsStore s) {
    switch (s) {
    case SettingsStore::Default: return "default";
    case SettingsStore::Restored: return "restored";
    case SettingsStore::Corrupt: return "corrupt";
    case SettingsStore::Saved: return "saved";
    case SettingsStore::Failed: return "failed";
    }
    return "?";
}

const DeviceChoices& DeviceSettingsStore::load() {
    std::array<std::uint8_t, settings_record_bytes> buf{}; std::size_t size = 0;
    current_ = DeviceChoices{};
    switch (storage_.read(buf.data(), buf.size(), size)) {
    case BlobRead::Absent: state_ = SettingsStore::Default; return current_;
    case BlobRead::Error: state_ = SettingsStore::Corrupt; return current_;
    case BlobRead::Ok: break;
    }
    DeviceChoices read;
    if (size <= buf.size() && decode_settings(buf.data(), size, read)) { current_ = read; state_ = SettingsStore::Restored; }
    else state_ = SettingsStore::Corrupt;   // the defaults; the record stays (never silently erased)
    return current_;
}

bool DeviceSettingsStore::save(const DeviceChoices& c) {
    std::array<std::uint8_t, settings_record_bytes> buf{};
    const auto n = encode_settings(c, buf.data(), buf.size());
    if (n == 0 || !storage_.write(buf.data(), n)) { state_ = SettingsStore::Failed; return false; }
    current_ = c; state_ = SettingsStore::Saved;
    return true;
}

Hours guard_hours(GuardCycle c) {
    const auto i = guard_index(c);
    return i < kGuardHours.size() ? kGuardHours[i].hours : Hours{false, 0, kNotMeasured};
}
Hours brightness_hours(std::uint8_t pct) {
    const auto i = bright_index(pct);
    return i < kBrightHours.size() ? kBrightHours[i].hours : Hours{false, 0, kNotMeasured};
}
Extreme guard_extreme(GuardCycle c) { return extreme_of(kGuardHours, guard_index(c)); }
Extreme brightness_extreme(std::uint8_t pct) { return extreme_of(kBrightHours, bright_index(pct)); }

std::size_t hours_text(std::uint16_t minutes, char* out, std::size_t capacity) {
    if (!out || !capacity) return 0;
    return fit(std::snprintf(out, capacity, "%uh %02um", unsigned(minutes / 60), unsigned(minutes % 60)), out, capacity);
}

std::size_t settings_status(const DeviceChoices& c, SettingsStore s, char* out, std::size_t capacity) {
    if (!out || !capacity) return 0;
    return fit(std::snprintf(out, capacity, "settings=guard:%s,bright:%u,store:%s", guard_cycle_name(c.guard), unsigned(c.bright_pct),
                             settings_store_text(s)), out, capacity);
}

std::size_t guard_cycle_status(GuardCycle c, const CycleStats& s, char* out, std::size_t capacity) {
    const auto t = cycle_timing(c);
    if (!out || !capacity) return 0;
    return fit(std::snprintf(out, capacity, "guard_cycle=%s,listen_ms=%u,off_ms=%u,cycles=%u,resume_fail=%u,relock_ms_avg=%u", guard_cycle_name(c),
                             unsigned(t.listen_ms), unsigned(t.off_ms), unsigned(s.cycles()), unsigned(s.resume_fail()), unsigned(s.relock_ms_avg())),
               out, capacity);
}

std::size_t parts_status(const PartsRead& r, char* out, std::size_t capacity) {
    const auto bit = [](int reg, std::uint8_t mask) { return reg < 0 ? "?" : (reg & mask) ? "1" : "0"; };
    const char* ir = r.ir_oe == 1 && r.ir_level == 0 ? "low" : "?";   // driven low (held), from the pad registers
    const char* codec = r.codec_0d == es8311_0d_powered_down ? "down" : "?";
    if (!out || !capacity) return 0;
    return fit(std::snprintf(out, capacity, "parts=led:%s,ir:%s,boost5v:%s,amp:%s,codec:%s", bit(r.pwr_cfg, pm1_pwr_cfg_led), ir,
                             bit(r.pwr_cfg, pm1_pwr_cfg_boost5v), bit(r.gpio_out, pm1_gpio_out_amp), codec), out, capacity);
}

} // namespace guardian::companion

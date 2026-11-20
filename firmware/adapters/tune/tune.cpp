// G16A live tuning: registry, console parser and blob persistence. SDK-free.
#include "tune.hpp"
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace guardian::tune {
namespace {
constexpr std::uint8_t magic[4] = {'G', 'T', 'U', 'N'};

std::uint32_t crc32(const std::uint8_t* p, std::size_t n) {
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < n; ++i) {
        c ^= p[i];
        for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}
bool key_char(char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_'; }
bool valid_key(const char* k, std::size_t n) {
    if (!k || n == 0 || n > max_key) return false;
    for (std::size_t i = 0; i < n; ++i) if (!key_char(k[i])) return false;
    return true;
}
std::uint32_t float_bits(float f) { std::uint32_t u; std::memcpy(&u, &f, 4); return u; }
float bits_float(std::uint32_t u) { float f; std::memcpy(&f, &u, 4); return f; }

struct Writer {
    std::uint8_t* p; std::size_t cap, at{}; bool ok{true};
    void bytes(const void* d, std::size_t n) { if (at + n > cap) { ok = false; return; } std::memcpy(p + at, d, n); at += n; }
    void u8(std::uint8_t v) { bytes(&v, 1); }
    void u16(std::uint16_t v) { const std::uint8_t b[2] = {std::uint8_t(v), std::uint8_t(v >> 8)}; bytes(b, 2); }
    void u32(std::uint32_t v) { const std::uint8_t b[4] = {std::uint8_t(v), std::uint8_t(v >> 8), std::uint8_t(v >> 16), std::uint8_t(v >> 24)}; bytes(b, 4); }
};
struct Reader {
    const std::uint8_t* p; std::size_t size, at{}; bool ok{true};
    bool take(void* d, std::size_t n) { if (at + n > size) { ok = false; return false; } std::memcpy(d, p + at, n); at += n; return true; }
    std::uint8_t u8() { std::uint8_t v{}; take(&v, 1); return v; }
    std::uint16_t u16() { std::uint8_t b[2]{}; take(b, 2); return std::uint16_t(b[0] | (b[1] << 8)); }
    std::uint32_t u32() { std::uint8_t b[4]{}; take(b, 4); return std::uint32_t(b[0]) | (std::uint32_t(b[1]) << 8) | (std::uint32_t(b[2]) << 16) | (std::uint32_t(b[3]) << 24); }
};
// Appends printf output to out[0..n) at `used`; returns false once full.
bool append(char* out, std::size_t n, std::size_t& used, const char* format, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 4, 5)))
#endif
    ;
bool append(char* out, std::size_t n, std::size_t& used, const char* format, ...) {
    if (used >= n) return false;
    va_list args; va_start(args, format);
    const int w = std::vsnprintf(out + used, n - used, format, args);
    va_end(args);
    if (w < 0 || static_cast<std::size_t>(w) >= n - used) { used = n; return false; }
    used += static_cast<std::size_t>(w); return true;
}
const char* skip_spaces(const char* s) { while (*s == ' ') ++s; return s; }
} // namespace

const char* store_text(Store s) {
    switch (s) {
    case Store::Defaults: return "defaults"; case Store::Restored: return "restored";
    case Store::Rejected: return "rejected"; case Store::Saved: return "saved"; case Store::SaveFailed: return "save-failed";
    }
    return "?";
}

int Registry::add(const char* key, float min, float max, float def) {
    const std::size_t n = key ? std::strlen(key) : 0;
    if (!valid_key(key, n) || count_ >= max_params || find(key) >= 0) return -1;
    if (!std::isfinite(min) || !std::isfinite(max) || !std::isfinite(def) || min > max || def < min || def > max) return -1;
    auto& p = params_[count_];
    std::memcpy(p.key.data(), key, n); p.key[n] = 0;
    p.min = min; p.max = max; p.def = def; p.value = def;
    return static_cast<int>(count_++);
}

int Registry::find(const char* key) const {
    for (std::size_t i = 0; i < count_; ++i) if (!std::strcmp(params_[i].key.data(), key)) return static_cast<int>(i);
    return -1;
}

void Registry::version(char* out, std::size_t n) const {
    std::snprintf(out, n, "%u.%u", unsigned(format), unsigned(revision_));
}

std::size_t Registry::encode(std::uint8_t* out, std::size_t capacity, std::uint32_t revision) const {
    Writer w{out, capacity};
    w.bytes(magic, 4); w.u16(format); w.u16(static_cast<std::uint16_t>(count_)); w.u32(revision);
    for (std::size_t i = 0; i < count_; ++i) {
        const auto& p = params_[i]; const auto n = std::strlen(p.key.data());
        w.u8(static_cast<std::uint8_t>(n)); w.bytes(p.key.data(), n); w.u32(float_bits(p.value));
    }
    if (!w.ok || w.at + 4 > capacity) return 0;
    w.u32(crc32(out, w.at));
    return w.ok ? w.at : 0;
}

Store Registry::load() {
    revision_ = 0;
    // Off the task stack: blob_ and parsed_ are Registry members (see tune.hpp).
    std::uint8_t* const blob = blob_.data(); std::size_t size = 0;
    const auto read = storage_.read(blob, blob_.size(), size);
    if (read == BlobRead::Absent) return store_ = Store::Defaults;
    if (read != BlobRead::Ok || size < 16) return store_ = Store::Rejected;
    Reader crc_reader{blob + size - 4, 4};
    if (crc_reader.u32() != crc32(blob, size - 4)) return store_ = Store::Rejected;
    Reader r{blob, size - 4};
    std::uint8_t m[4]{}; r.take(m, 4);
    if (std::memcmp(m, magic, 4) != 0 || r.u16() != format) return store_ = Store::Rejected;
    const std::uint16_t entries = r.u16(); const std::uint32_t revision = r.u32();
    // Parse everything before applying anything: a malformed body changes nothing.
    auto& parsed = parsed_; std::size_t kept = 0;
    for (std::uint16_t e = 0; e < entries && r.ok; ++e) {
        const std::uint8_t n = r.u8(); char key[max_key + 1]{};
        if (!r.ok || n == 0 || n > max_key || !r.take(key, n) || !valid_key(key, n)) return store_ = Store::Rejected;
        const float v = bits_float(r.u32());
        if (!r.ok) return store_ = Store::Rejected;
        if (kept < max_params) { std::memcpy(parsed[kept].key, key, n + 1u); parsed[kept].value = v; ++kept; }
    }
    if (!r.ok || r.at != r.size) return store_ = Store::Rejected;
    for (std::size_t i = 0; i < kept; ++i) {
        const int idx = find(parsed[i].key);
        if (idx < 0) continue;                                   // no longer registered: ignored
        auto& p = params_[static_cast<std::size_t>(idx)];
        const float v = parsed[i].value;
        if (std::isfinite(v) && v >= p.min && v <= p.max) p.value = v;   // else today's default stays
    }
    revision_ = revision;
    return store_ = Store::Restored;
}

bool Registry::save() {
    const auto n = encode(blob_.data(), blob_.size(), revision_ + 1);   // member buffer (see load)
    if (!n || !storage_.write(blob_.data(), n)) { store_ = Store::SaveFailed; return false; }
    ++revision_; store_ = Store::Saved; return true;
}

bool Registry::set(const char* key, float value, const char*& reason) {
    const int idx = find(key);
    if (idx < 0) { reason = "unknown key"; return false; }
    auto& p = params_[static_cast<std::size_t>(idx)];
    if (!std::isfinite(value)) { reason = "not a number"; return false; }
    if (value < p.min || value > p.max) { reason = "out of range"; return false; }
    p.value = value;
    if (!save()) { reason = "not saved (storage)"; return false; }
    return true;
}

bool Registry::command(const char* line, char* out, std::size_t n) {
    if (!line || std::strncmp(line, "TUNE", 4) != 0 || (line[4] != 0 && line[4] != ' ' && line[4] != '?')) return false;
    std::size_t used = 0; if (n) out[0] = 0;
    char v[16]; version(v, sizeof v);
    if (!std::strcmp(line, "TUNE?") || !std::strncmp(line, "TUNE? ", 6)) {
        // "TUNE?" lists everything, "TUNE? <prefix>" one group (e.g. t.probe). A listing
        // that does not fit ends with a visible MORE line, never a cut line.
        const char* prefix = line[5] ? skip_spaces(line + 5) : "";
        const std::size_t plen = std::strlen(prefix);
        constexpr std::size_t trailer = 120;   // room kept for the MORE and OK lines
        std::size_t shown = 0, matching = 0; bool more = false;
        for (std::size_t i = 0; i < count_; ++i) {
            const auto& p = params_[i];
            if (plen && std::strncmp(p.key.data(), prefix, plen) != 0) continue;
            ++matching;
            if (more) continue;
            char row[128];
            const int w = std::snprintf(row, sizeof row, "TUNE %s=%g min=%g max=%g default=%g\n", p.key.data(), double(p.value), double(p.min), double(p.max), double(p.def));
            if (w < 0 || static_cast<std::size_t>(w) >= sizeof row || used + static_cast<std::size_t>(w) + trailer >= n) { more = true; continue; }
            append(out, n, used, "%s", row); ++shown;
        }
        if (more) append(out, n, used, "TUNE MORE %u not shown; use TUNE? <prefix>\n", unsigned(matching - shown));
        if (plen) append(out, n, used, "TUNE OK params=%u of %u prefix=%s version=%s store=%s\n", unsigned(matching), unsigned(count_), prefix, v, store_text(store_));
        else append(out, n, used, "TUNE OK params=%u version=%s store=%s\n", unsigned(count_), v, store_text(store_));
        return true;
    }
    const char* s = skip_spaces(line + 4);
    const char* eq = std::strchr(s, '=');
    std::size_t klen = eq ? static_cast<std::size_t>(eq - s) : 0;
    while (klen && s[klen - 1] == ' ') --klen;
    if (line[4] == '?' || !eq || !valid_key(s, klen)) { append(out, n, used, "TUNE ERROR use TUNE key=value or TUNE?\n"); return true; }
    char key[max_key + 1]{}; std::memcpy(key, s, klen);
    const int idx = find(key);
    if (idx < 0) { append(out, n, used, "TUNE ERROR unknown key %s\n", key); return true; }
    const char* num = skip_spaces(eq + 1); char* end = nullptr;
    const float value = *num ? std::strtof(num, &end) : NAN;
    if (!end || end == num || *skip_spaces(end) != 0 || !std::isfinite(value)) { append(out, n, used, "TUNE ERROR not a number\n"); return true; }
    const auto& p = params_[static_cast<std::size_t>(idx)];
    if (value < p.min || value > p.max) {
        append(out, n, used, "TUNE ERROR out of range %s [%g, %g]\n", key, double(p.min), double(p.max)); return true;
    }
    const char* reason = nullptr;
    if (set(key, value, reason)) { version(v, sizeof v); append(out, n, used, "TUNE OK %s=%g version=%s saved\n", key, double(value), v); }
    else append(out, n, used, "TUNE ERROR %s; %s=%g applied until reboot\n", reason, key, double(value));
    return true;
}

} // namespace guardian::tune

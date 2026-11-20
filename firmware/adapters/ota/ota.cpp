// G16B OTA decisions (see ota.hpp). SDK-free: the StickS3 adapter supplies the
// Wi-Fi/HTTP transport and the esp_ota slot.
#include "ota.hpp"
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace guardian::ota {
namespace {

// ---- small helpers ----------------------------------------------------------
std::uint32_t crc32(const std::uint8_t* p, std::size_t n) {
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < n; ++i) {
        c ^= p[i];
        for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}
struct Writer {
    std::uint8_t* p; std::size_t at{};
    void u8(std::uint8_t v) { p[at++] = v; }
    void u16(std::uint16_t v) { u8(static_cast<std::uint8_t>(v)); u8(static_cast<std::uint8_t>(v >> 8)); }
    void u32(std::uint32_t v) { u16(static_cast<std::uint16_t>(v)); u16(static_cast<std::uint16_t>(v >> 16)); }
    void raw(const void* d, std::size_t n) { std::memcpy(p + at, d, n); at += n; }
};
struct Reader {
    const std::uint8_t* p; std::size_t at{};
    std::uint8_t u8() { return p[at++]; }
    std::uint16_t u16() { const auto lo = u8(); return static_cast<std::uint16_t>(lo | (u8() << 8)); }
    std::uint32_t u32() { const std::uint32_t lo = u16(); return lo | (static_cast<std::uint32_t>(u16()) << 16); }
    void raw(void* d, std::size_t n) { std::memcpy(d, p + at, n); at += n; }
};
int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
int hex_digit_any(char c) { return c >= 'A' && c <= 'F' ? c - 'A' + 10 : hex_digit(c); }
// Decodes exactly n hex chars into n/2 bytes; false on odd length or a non-hex char.
bool decode_hex(const char* s, std::size_t n, std::uint8_t* out, bool lower_only) {
    if (n % 2) return false;
    for (std::size_t i = 0; i < n; i += 2) {
        const int a = lower_only ? hex_digit(s[i]) : hex_digit_any(s[i]);
        const int b = lower_only ? hex_digit(s[i + 1]) : hex_digit_any(s[i + 1]);
        if (a < 0 || b < 0) return false;
        out[i / 2] = static_cast<std::uint8_t>(a * 16 + b);
    }
    return true;
}
bool version_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}
bool valid_version(const char* s, std::size_t n) {
    if (n == 0 || n > max_version) return false;
    for (std::size_t i = 0; i < n; ++i) if (!version_char(s[i])) return false;
    return true;
}

constexpr std::uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
constexpr std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
} // namespace

// ---- SHA-256 ------------------------------------------------------------------
void Sha256::reset() {
    const std::uint32_t init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::memcpy(h_, init, sizeof h_);
    used_ = 0; bits_ = 0;
}
void Sha256::block(const std::uint8_t* p) {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (std::uint32_t(p[4 * i]) << 24) | (std::uint32_t(p[4 * i + 1]) << 16) | (std::uint32_t(p[4 * i + 2]) << 8) | p[4 * i + 3];
    for (int i = 16; i < 64; ++i) {
        const auto s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const auto s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (int i = 0; i < 64; ++i) {
        const auto t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
        const auto t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}
void Sha256::update(const std::uint8_t* data, std::size_t n) {
    bits_ += static_cast<std::uint64_t>(n) * 8u;
    while (n) {
        const std::size_t take = std::min(n, sizeof buf_ - used_);
        std::memcpy(buf_ + used_, data, take);
        used_ += take; data += take; n -= take;
        if (used_ == sizeof buf_) { block(buf_); used_ = 0; }
    }
}
void Sha256::finish(std::uint8_t out[32]) {
    const std::uint64_t bits = bits_;
    const std::uint8_t one = 0x80, zero = 0;
    update(&one, 1);
    while (used_ != 56) update(&zero, 1);
    std::uint8_t len[8];
    for (int i = 0; i < 8; ++i) len[i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
    update(len, 8);
    for (int i = 0; i < 8; ++i) {
        out[4 * i] = static_cast<std::uint8_t>(h_[i] >> 24); out[4 * i + 1] = static_cast<std::uint8_t>(h_[i] >> 16);
        out[4 * i + 2] = static_cast<std::uint8_t>(h_[i] >> 8); out[4 * i + 3] = static_cast<std::uint8_t>(h_[i]);
    }
    reset();
}

// ---- manifest -------------------------------------------------------------------
const char* manifest_error_text(ManifestError e) {
    switch (e) {
    case ManifestError::None: return "ok";
    case ManifestError::Header: return "header";
    case ManifestError::Field: return "unknown field";
    case ManifestError::Duplicate: return "duplicate field";
    case ManifestError::Missing: return "missing field";
    case ManifestError::Version: return "version";
    case ManifestError::Size: return "size";
    case ManifestError::Hash: return "sha256";
    case ManifestError::Scheme: return "signature scheme";
    case ManifestError::End: return "no end line";
    }
    return "?";
}

ManifestError parse_manifest(const char* text, std::size_t n, Manifest& out) {
    if (!text || n > max_manifest) return ManifestError::Header;
    Manifest m;
    bool header = false, have_version = false, have_size = false, have_sha = false, have_scheme = false, ended = false;
    std::size_t at = 0;
    while (at < n && !ended) {
        std::size_t end = at;
        while (end < n && text[end] != '\n') ++end;
        std::size_t len = end - at;
        if (len && text[at + len - 1] == '\r') --len;
        const char* line = text + at;
        at = end < n ? end + 1 : n;
        if (!header) {
            if (len != 14 || std::memcmp(line, "GUARDIAN-OTA 1", 14)) return ManifestError::Header;
            header = true; continue;
        }
        if (len == 3 && !std::memcmp(line, "end", 3)) { ended = true; break; }
        const char* eq = static_cast<const char*>(std::memchr(line, '=', len));
        if (!eq) return ManifestError::Field;
        const std::size_t klen = static_cast<std::size_t>(eq - line), vlen = len - klen - 1;
        const char* v = eq + 1;
        const auto key = [&](const char* name) { return klen == std::strlen(name) && !std::memcmp(line, name, klen); };
        if (key("version")) {
            if (have_version) return ManifestError::Duplicate;
            if (!valid_version(v, vlen)) return ManifestError::Version;
            std::memcpy(m.version.data(), v, vlen); m.version[vlen] = 0; have_version = true;
        } else if (key("size")) {
            if (have_size) return ManifestError::Duplicate;
            if (vlen == 0 || vlen > 8) return ManifestError::Size;
            std::uint32_t s = 0;
            for (std::size_t i = 0; i < vlen; ++i) { if (v[i] < '0' || v[i] > '9') return ManifestError::Size; s = s * 10 + static_cast<std::uint32_t>(v[i] - '0'); }
            if (s == 0 || s > 16u * 1024u * 1024u) return ManifestError::Size;
            m.size = s; have_size = true;
        } else if (key("sha256")) {
            if (have_sha) return ManifestError::Duplicate;
            if (vlen != 64 || !decode_hex(v, 64, m.sha256.data(), true)) return ManifestError::Hash;
            have_sha = true;
        } else if (key("signature")) {
            if (have_scheme) return ManifestError::Duplicate;
            if (vlen != 12 || std::memcmp(v, "rsa3072-sbv2", 12)) return ManifestError::Scheme;
            have_scheme = true;
        } else {
            return ManifestError::Field;
        }
    }
    if (!header) return ManifestError::Header;
    if (!have_version || !have_size || !have_sha || !have_scheme) return ended ? ManifestError::Missing : ManifestError::End;
    if (!ended) return ManifestError::End;
    out = m;
    return ManifestError::None;
}

// ---- reasons ------------------------------------------------------------------
const char* reason_text(Reason r) {
    switch (r) {
    case Reason::None: return "ok";
    case Reason::NotProvisioned: return "not_provisioned";
    case Reason::JoinFailed: return "join";
    case Reason::ManifestFetch: return "manifest_fetch";
    case Reason::ManifestInvalid: return "manifest";
    case Reason::TooLarge: return "too_large";
    case Reason::NoSlot: return "no_slot";
    case Reason::Download: return "download";
    case Reason::Truncated: return "truncated";
    case Reason::Oversize: return "oversize";
    case Reason::LengthMismatch: return "length";
    case Reason::ShaMismatch: return "sha256";
    case Reason::SignatureInvalid: return "signature";
    case Reason::ImageInvalid: return "image";
    case Reason::WriteFailed: return "flash_write";
    case Reason::SwitchFailed: return "slot_switch";
    case Reason::Cancelled: return "cancelled";
    case Reason::SelfTest: return "selftest";
    case Reason::CrashBeforeSelfTest: return "reset_before_selftest";
    case Reason::NotNewer: return "not_newer";
    }
    return "unknown";
}
const char* reason_line(Reason r) {   // <= 22 glyphs
    switch (r) {
    case Reason::None: return "Update installed";
    case Reason::NotProvisioned: return "Not set up over USB";
    case Reason::JoinFailed: return "Wi-Fi join failed";
    case Reason::ManifestFetch: return "Mac server unreachable";
    case Reason::ManifestInvalid: return "Bad update manifest";
    case Reason::TooLarge: return "Image too big for slot";
    case Reason::NoSlot: return "No update slot";
    case Reason::Download: return "Download failed";
    case Reason::Truncated: return "Download cut short";
    case Reason::Oversize: return "Image longer than said";
    case Reason::LengthMismatch: return "Size mismatch";
    case Reason::ShaMismatch: return "SHA-256 mismatch";
    case Reason::SignatureInvalid: return "Signature refused";
    case Reason::ImageInvalid: return "Image refused";
    case Reason::WriteFailed: return "Flash write failed";
    case Reason::SwitchFailed: return "Slot switch failed";
    case Reason::Cancelled: return "Update cancelled";
    case Reason::SelfTest: return "Self-test failed";
    case Reason::CrashBeforeSelfTest: return "New image reset";
    case Reason::NotNewer: return "Not newer than running";
    }
    return "Unknown";
}

// ---- the attempt ----------------------------------------------------------------
namespace {
void tell(Observer* o, Phase p, std::uint32_t done = 0, std::uint32_t total = 0) { if (o) o->phase(p, done, total); }
// Reads a whole small body (the manifest). -1: error/too long.
long read_small(Transport& t, char* out, std::size_t capacity) {
    std::size_t used = 0;
    for (;;) {
        if (used == capacity) { std::uint8_t probe; return t.read(&probe, 1) == 0 ? static_cast<long>(used) : -1; }
        const int r = t.read(reinterpret_cast<std::uint8_t*>(out + used), capacity - used);
        if (r < 0) return -1;
        if (r == 0) return static_cast<long>(used);
        used += static_cast<std::size_t>(r);
    }
}
Outcome fetch_and_install(Transport& t, Slot& slot, const char* running_version, Observer* obs) {
    Outcome o;
    tell(obs, Phase::Manifest);
    std::int32_t length = -1;
    if (!t.open("manifest", length)) { o.reason = Reason::ManifestFetch; return o; }
    char text[max_manifest];
    const long got = read_small(t, text, sizeof text);
    t.close();
    if (got < 0) { o.reason = Reason::ManifestFetch; return o; }
    if (parse_manifest(text, static_cast<std::size_t>(got), o.manifest) != ManifestError::None) { o.reason = Reason::ManifestInvalid; return o; }
    // G22A: nothing is downloaded for a version that is not newer than the running one.
    if (!newer(o.manifest.version.data(), running_version)) { o.reason = Reason::NotNewer; return o; }
    const auto size = o.manifest.size;
    if (slot.capacity() == 0) { o.reason = Reason::NoSlot; return o; }
    if (size > slot.capacity()) { o.reason = Reason::TooLarge; return o; }

    tell(obs, Phase::Download, 0, size);
    if (!t.open("image", length)) { o.reason = Reason::Download; return o; }
    if (length >= 0 && static_cast<std::uint32_t>(length) != size) { t.close(); o.reason = Reason::LengthMismatch; return o; }
    if (!slot.begin(size)) { t.close(); o.reason = Reason::NoSlot; return o; }
    Sha256 hash;
    std::uint8_t buf[1024];
    // G22A: the image's own descriptor (its first 80 bytes) as it streams in. The manifest's version is
    // plain text from the network; this one is inside the bytes the signature check covers.
    std::uint8_t head[app_desc_bytes];
    std::size_t head_used = 0;
    bool head_checked = false;
    Reason failed = Reason::None;
    for (;;) {
        const int r = t.read(buf, sizeof buf);
        if (r < 0) { failed = Reason::Download; break; }
        if (r == 0) { if (o.received < size) failed = Reason::Truncated; break; }
        const auto n = static_cast<std::uint32_t>(r);
        if (o.received + n > size) { failed = Reason::Oversize; break; }
        if (!head_checked) {
            const std::size_t take = std::min<std::size_t>(n, sizeof head - head_used);
            std::memcpy(head + head_used, buf, take); head_used += take;
            if (head_used == sizeof head) {
                std::array<char, max_version + 1> inside{};
                if (!image_version(head, sizeof head, inside)) { failed = Reason::ImageInvalid; break; }
                if (!newer(inside.data(), running_version)) { failed = Reason::NotNewer; break; }
                head_checked = true;
            }
        }
        hash.update(buf, n);
        if (!slot.write(buf, n)) { failed = Reason::WriteFailed; break; }
        o.received += n;
        tell(obs, Phase::Download, o.received, size);
    }
    t.close();
    if (failed == Reason::None && !head_checked) failed = Reason::ImageInvalid;   // shorter than an app descriptor
    if (failed == Reason::None) {
        std::uint8_t digest[32];
        hash.finish(digest);
        if (std::memcmp(digest, o.manifest.sha256.data(), 32)) failed = Reason::ShaMismatch;
    }
    if (failed != Reason::None) { slot.abort(); o.reason = failed; return o; }

    tell(obs, Phase::Verify);
    switch (slot.finish()) {
    case Finish::Ok: break;
    case Finish::SignatureInvalid: o.reason = Reason::SignatureInvalid; return o;
    case Finish::ImageInvalid:
    case Finish::Failed: o.reason = Reason::ImageInvalid; return o;
    }
    tell(obs, Phase::Switch);
    if (!slot.activate()) o.reason = Reason::SwitchFailed;
    return o;
}
} // namespace

// ---- G22A: version order and the self-fetch poll -------------------------------
bool version_stamp(const char* version, std::uint64_t& stamp) {
    static const char prefix[] = "guardian-";
    if (!version || std::strncmp(version, prefix, sizeof prefix - 1) != 0) return false;
    const char* p = version + sizeof prefix - 1;
    std::uint64_t value = 0;
    for (int i = 0; i < 15; ++i) {   // YYYYMMDD-HHMMSS
        const char c = p[i];
        if (i == 8) { if (c != '-') return false; continue; }
        if (c < '0' || c > '9') return false;
        value = value * 10u + static_cast<std::uint64_t>(c - '0');
    }
    if (p[15] != 0 && !(p[15] == '-' && p[16] != 0)) return false;   // the end, or "-<suffix>"
    stamp = value;
    return true;
}

bool newer(const char* offered, const char* running) {
    std::uint64_t a = 0, b = 0;
    if (!version_stamp(offered, a)) return false;
    if (!version_stamp(running, b)) return true;   // a hand-named running build is older than every stamped one
    return a > b;
}

bool image_version(const std::uint8_t* image, std::size_t n, std::array<char, max_version + 1>& out) {
    if (!image || n < app_desc_bytes || image[0] != 0xE9) return false;
    if (image[32] != 0x32 || image[33] != 0x54 || image[34] != 0xCD || image[35] != 0xAB) return false;   // 0xABCD5432, little-endian
    std::array<char, max_version + 1> v{};
    for (std::size_t i = 0; i < max_version && image[48 + i]; ++i) v[i] = static_cast<char>(image[48 + i]);
    out = v;
    return true;
}

AutoPoll::Decision AutoPoll::sample(std::uint64_t now_ms, std::uint64_t period_ms, bool busy, bool alert) {
    if (!period_ms) { deferred_ = false; return Decision::Wait; }
    if (now_ms - last_ < period_ms) return Decision::Wait;
    if (alert) {   // alert first: the incident keeps the glass and the radio
        if (!deferred_) { deferred_ = true; ++deferrals_; }
        return Decision::Deferred;
    }
    if (busy) return Decision::Wait;
    deferred_ = false; last_ = now_ms; ++checks_;
    return Decision::Run;
}

Outcome run(Transport& t, Slot& slot, const char* running_version, Observer* obs) {
    tell(obs, Phase::Joining);
    if (!t.join()) { t.leave(); Outcome o; o.reason = Reason::JoinFailed; return o; }
    const Outcome o = fetch_and_install(t, slot, running_version, obs);
    t.leave();
    return o;
}

// ---- boot record ----------------------------------------------------------------
namespace { constexpr std::uint16_t record_format = 1, credentials_format = 1; }
std::size_t encode(const Record& r, std::uint8_t* out, std::size_t capacity) {
    if (!out || capacity < record_bytes) return 0;
    Writer w{out};
    w.raw("GOTA", 4); w.u16(record_format);
    w.u8(static_cast<std::uint8_t>(r.state)); w.u8(static_cast<std::uint8_t>(r.reason));
    w.u8(r.from_slot); w.u8(r.target_slot);
    std::array<char, max_version + 1> v{}; std::memcpy(v.data(), r.version.data(), max_version); v[max_version] = 0;
    w.raw(v.data(), v.size());
    w.u32(crc32(out, w.at));
    return w.at;
}
bool decode(const std::uint8_t* in, std::size_t size, Record& out) {
    if (!in || size != record_bytes || std::memcmp(in, "GOTA", 4)) return false;
    if (crc32(in, record_bytes - 4) != Reader{in, record_bytes - 4}.u32()) return false;
    Reader r{in, 4};
    if (r.u16() != record_format) return false;
    Record x;
    const auto state = r.u8(), reason = r.u8();
    if (state > static_cast<std::uint8_t>(State::RolledBack) || reason > static_cast<std::uint8_t>(Reason::NotNewer)) return false;
    x.state = static_cast<State>(state); x.reason = static_cast<Reason>(reason);
    x.from_slot = r.u8(); x.target_slot = r.u8();
    r.raw(x.version.data(), x.version.size());
    if (x.version[max_version] != 0) return false;
    out = x;
    return true;
}
bool load(const BlobStorage& s, Record& out) {
    std::uint8_t buf[record_bytes]; std::size_t n = 0;
    if (s.read(buf, sizeof buf, n) != BlobRead::Ok) return false;
    return decode(buf, n, out);
}
bool save(BlobStorage& s, const Record& r) {
    std::uint8_t buf[record_bytes];
    const auto n = encode(r, buf, sizeof buf);
    return n && s.write(buf, n);
}
void result_text(const Record& r, char* out, std::size_t n) {
    if (!out || !n) return;
    switch (r.state) {
    case State::None: std::snprintf(out, n, "none"); break;
    case State::Pending: std::snprintf(out, n, "pending:%s", r.version.data()); break;
    case State::Succeeded: std::snprintf(out, n, "ok:%s", r.version.data()); break;
    case State::Failed: std::snprintf(out, n, "failed:%s", reason_text(r.reason)); break;
    case State::RolledBack: std::snprintf(out, n, "rolled_back:%s", reason_text(r.reason)); break;
    }
}

BootDecision decide_boot(Record& record, const BootFacts& boot, const SelfTest& test) {
    BootDecision d;
    const bool pending = record.state == State::Pending;
    if (pending && boot.running_slot != record.target_slot) {
        // We are the previous image again: the new one never validated itself.
        record.state = State::RolledBack; record.reason = Reason::CrashBeforeSelfTest;
        d.changed = true;
        return d;
    }
    if (!boot.pending_verify) {
        if (pending) { record.state = State::Succeeded; record.reason = Reason::None; d.changed = true; }
        return d;
    }
    // On probation: validate only after the self-test.
    if (test.passed()) {
        d.action = BootAction::MarkValid;
        if (pending) { record.state = State::Succeeded; record.reason = Reason::None; d.changed = true; }
    } else {
        d.action = BootAction::Rollback;
        record.state = State::RolledBack; record.reason = Reason::SelfTest;
        if (!pending) { record.from_slot = boot.running_slot; record.target_slot = boot.running_slot; }
        d.changed = true;
    }
    return d;
}

// ---- gesture / confirmation ----------------------------------------------------
bool Gesture::sample(bool front_down, bool side_down, std::uint32_t now_ms) {
    const bool both = front_down && side_down;
    if (both) involved_ = true;
    if (!front_down && !side_down) involved_ = false;
    if (both && !both_) { since_ = now_ms; fired_ = false; }
    both_ = both;
    if (both && !fired_ && now_ms - since_ >= hold_ms) { fired_ = true; return true; }
    return false;
}
TripleTap::Tap TripleTap::tap(std::uint32_t now_ms) {
    count_ = (count_ > 0 && now_ms - last_ <= gap_ms) ? static_cast<std::uint8_t>(count_ + 1) : 1;
    last_ = now_ms;
    if (count_ >= 3) { count_ = 0; held_ = false; return Tap::Fire; }
    if (count_ == 2) { held_ = true; return Tap::Hold; }
    held_ = false;
    return Tap::Deliver;
}
bool TripleTap::expire(std::uint32_t now_ms) {
    if (!held_ || now_ms - last_ <= gap_ms) return false;
    held_ = false; count_ = 0;
    return true;
}
Answer Confirmation::sample(bool front_pressed, bool side_pressed, std::uint32_t now_ms) {
    if (!open_) return Answer::Pending;
    if (side_pressed || (front_pressed && side_pressed) || static_cast<std::int32_t>(now_ms - deadline_) >= 0) { open_ = false; return Answer::No; }
    if (front_pressed && now_ms - opened_ >= arm_ms) { open_ = false; return Answer::Yes; }
    return Answer::Pending;
}
std::uint32_t Confirmation::remaining_ms(std::uint32_t now_ms) const {
    const auto left = static_cast<std::int32_t>(deadline_ - now_ms);
    return left > 0 ? static_cast<std::uint32_t>(left) : 0;
}

// ---- provisioning ----------------------------------------------------------------
bool valid_url(const char* url) {
    if (!url || std::strncmp(url, "http://", 7)) return false;
    const auto n = std::strlen(url);
    if (n <= 7 || n > max_url) return false;
    if (url[7] == '/' || url[7] == ':') return false;   // host required
    for (std::size_t i = 0; i < n; ++i) if (url[i] <= 32 || url[i] >= 127) return false;
    return true;
}
std::size_t encode(const Credentials& c, std::uint8_t* out, std::size_t capacity) {
    if (!out || capacity < credentials_bytes || c.ssid_len > max_ssid || c.pass_len > max_pass) return 0;
    Writer w{out};
    w.raw("GOCF", 4); w.u16(credentials_format);
    w.u8(c.ssid_len); w.raw(c.ssid.data(), c.ssid.size());
    w.u8(c.pass_len);
    std::array<char, max_pass + 1> p{}; std::memcpy(p.data(), c.pass.data(), c.pass_len); w.raw(p.data(), p.size());
    std::array<char, max_url + 1> u{}; std::memcpy(u.data(), c.url.data(), max_url); w.raw(u.data(), u.size());
    w.u32(crc32(out, w.at));
    return w.at;
}
bool decode(const std::uint8_t* in, std::size_t size, Credentials& out) {
    if (!in || size != credentials_bytes || std::memcmp(in, "GOCF", 4)) return false;
    if (crc32(in, credentials_bytes - 4) != Reader{in, credentials_bytes - 4}.u32()) return false;
    Reader r{in, 4};
    if (r.u16() != credentials_format) return false;
    Credentials c;
    c.ssid_len = r.u8(); r.raw(c.ssid.data(), c.ssid.size());
    c.pass_len = r.u8(); r.raw(c.pass.data(), c.pass.size());
    r.raw(c.url.data(), c.url.size());
    if (c.ssid_len > max_ssid || c.pass_len > max_pass || c.pass[c.pass_len] != 0 || c.url[max_url] != 0) return false;
    if (std::strlen(c.pass.data()) != c.pass_len) return false;
    if (c.url[0] && !valid_url(c.url.data())) return false;
    out = c;
    return true;
}
void Provisioner::load() {
    std::uint8_t buf[credentials_bytes]; std::size_t n = 0;
    Credentials c;
    if (storage_.read(buf, sizeof buf, n) == BlobRead::Ok && decode(buf, n, c)) saved_ = c;
    staged_ = saved_;
    ssid_set_ = saved_.ssid_len > 0; pass_set_ = ssid_set_; url_set_ = saved_.url[0] != 0;
}
bool Provisioner::store(const Credentials& c) {   // G16M: the phone setup's save (name + password [+ server URL])
    if (!c.wifi() || c.ssid_len > max_ssid || c.pass_len > max_pass || (c.url[0] && !valid_url(c.url.data()))) return false;
    std::uint8_t buf[credentials_bytes];
    const auto len = encode(c, buf, sizeof buf);
    const bool ok = len && storage_.write(buf, len);
    for (auto& b : buf) { volatile std::uint8_t* v = &b; *v = 0; }   // no password copy left on the stack
    if (!ok) return false;
    saved_ = staged_ = c;
    ssid_set_ = pass_set_ = true; url_set_ = c.url[0] != 0;
    return true;
}
bool Provisioner::command(const char* line, char* out, std::size_t n) {
    if (!line || !out || !n) return false;
    if (!std::strcmp(line, "OTA?")) {
        std::snprintf(out, n, "OTA provisioned=%s staged_ssid=%s staged_pass=%s staged_url=%s\n",
                      provisioned() ? "yes" : "no", ssid_set_ ? "set" : "unset", pass_set_ ? "set" : "unset", url_set_ ? "set" : "unset");
        return true;
    }
    if (std::strncmp(line, "OTA ", 4)) return false;
    const char* rest = line + 4;
    const auto arg = [&](const char* verb) -> const char* {
        const auto k = std::strlen(verb);
        return !std::strncmp(rest, verb, k) && rest[k] == ' ' ? rest + k + 1 : nullptr;
    };
    if (const char* v = arg("SSID")) {
        const auto len = std::strlen(v);
        std::uint8_t bytes[max_ssid];
        if (len == 0 || len > 2 * max_ssid || !decode_hex(v, len, bytes, false)) { std::snprintf(out, n, "OTA ERROR ssid must be 1..32 bytes as hex\n"); return true; }
        staged_.ssid = {}; std::memcpy(staged_.ssid.data(), bytes, len / 2); staged_.ssid_len = static_cast<std::uint8_t>(len / 2);
        ssid_set_ = true; std::snprintf(out, n, "OTA ACK ssid staged len=%u\n", unsigned(len / 2)); return true;
    }
    if (const char* v = arg("PASS")) {
        if (!std::strcmp(v, "-")) { staged_.pass = {}; staged_.pass_len = 0; pass_set_ = true; std::snprintf(out, n, "OTA ACK open network staged\n"); return true; }
        const auto len = std::strlen(v);
        std::uint8_t bytes[max_pass];
        if (len < 16 || len > 2 * max_pass || !decode_hex(v, len, bytes, false)) { std::snprintf(out, n, "OTA ERROR pass must be 8..63 bytes as hex, or -\n"); return true; }
        for (std::size_t i = 0; i < len / 2; ++i) if (bytes[i] < 32 || bytes[i] > 126) { std::snprintf(out, n, "OTA ERROR pass must be printable ASCII\n"); return true; }
        staged_.pass = {}; std::memcpy(staged_.pass.data(), bytes, len / 2); staged_.pass_len = static_cast<std::uint8_t>(len / 2);
        pass_set_ = true; std::snprintf(out, n, "OTA ACK pass staged\n"); return true;
    }
    if (const char* v = arg("URL")) {
        if (!valid_url(v)) { std::snprintf(out, n, "OTA ERROR url must be http://host[:port][/path], <= 120 chars\n"); return true; }
        staged_.url = {}; std::memcpy(staged_.url.data(), v, std::strlen(v));
        url_set_ = true; std::snprintf(out, n, "OTA ACK url staged\n"); return true;
    }
    if (!std::strcmp(rest, "SAVE")) {
        if (!ssid_set_ || !pass_set_ || !url_set_ || !staged_.complete()) { std::snprintf(out, n, "OTA ERROR stage SSID, PASS and URL first\n"); return true; }
        std::uint8_t buf[credentials_bytes];
        const auto len = encode(staged_, buf, sizeof buf);
        if (!len || !storage_.write(buf, len)) { std::snprintf(out, n, "OTA ERROR save failed; nothing changed\n"); return true; }
        saved_ = staged_;
        std::snprintf(out, n, "OTA SAVED provisioned=yes\n"); return true;
    }
    if (!std::strcmp(rest, "CLEAR")) {
        const Credentials empty{};
        std::uint8_t buf[credentials_bytes];
        const auto len = encode(empty, buf, sizeof buf);
        if (!len || !storage_.write(buf, len)) { std::snprintf(out, n, "OTA ERROR clear failed\n"); return true; }
        saved_ = staged_ = empty; ssid_set_ = pass_set_ = url_set_ = false;
        std::snprintf(out, n, "OTA CLEARED provisioned=no\n"); return true;
    }
    std::snprintf(out, n, "OTA ERROR use OTA SSID|PASS|URL <value>, OTA SAVE, OTA CLEAR or OTA?\n");
    return true;
}

} // namespace guardian::ota
// ---- UPDATE screens --------------------------------------------------------------
namespace guardian::ota {
namespace {
constexpr std::uint16_t cyan = rgb565(0, 200, 220);
#if defined(__GNUC__)
__attribute__((format(printf, 5, 6)))
#endif
void line(Screen& s, int y, std::uint16_t color, std::uint8_t scale, const char* format, ...) {
    if (s.count >= s.lines.size()) { ++s.overflow; return; }
    auto& l = s.lines[s.count++];
    char wide[64];
    va_list args; va_start(args, format);
    const int w = std::vsnprintf(wide, sizeof wide, format, args);
    va_end(args);
    const std::size_t limit = scale == 2 ? 11u : 22u;
    if (w < 0 || static_cast<std::size_t>(w) > limit) ++s.overflow;   // never cut silently
    std::snprintf(l.text.data(), l.text.size(), "%.*s", static_cast<int>(limit), wide);
    l.y = static_cast<std::int16_t>(y); l.color = color; l.scale = scale;
}
// A version (<= 31 chars) on one or two 1x lines, never cut.
int version_lines(Screen& s, int y, const char* label, const char* v) {
    line(s, y, color::grey, 1, "%s", label); y += 10;
    const auto n = std::strlen(v);
    if (!n) { line(s, y, color::grey, 1, "(unknown)"); return y + 10; }
    line(s, y, color::white, 1, "%.22s", v); y += 10;
    if (n > 22) { line(s, y, color::white, 1, "%.22s", v + 22); y += 10; }
    return y;
}
const char* phase_text(Phase p) {
    switch (p) {
    case Phase::Joining: return "Joining owner Wi-Fi";
    case Phase::Manifest: return "Asking the Mac";
    case Phase::Download: return "Downloading";
    case Phase::Verify: return "Checking signature";
    case Phase::Switch: return "Switching slot";
    }
    return "?";
}
} // namespace

void compose(const View& v, Screen& s) {
    s = Screen{};
    switch (v.stage) {
    case Stage::Confirm: {
        line(s, 8, color::yellow, 2, "UPDATE?");
        int y = 36;
        line(s, y, color::white, 1, "Update or TUNE from"); y += 10;   // G16C: the Mac tool decides which
        line(s, y, color::white, 1, "the owner's Mac."); y += 14;
        line(s, y, color::grey, 1, "Monitoring pauses and"); y += 10;
        line(s, y, color::grey, 1, "the stick joins Wi-Fi"); y += 10;
        line(s, y, color::grey, 1, "only until it ends."); y += 16;
        line(s, y, color::green, 2, "FRONT=yes"); y += 20;
        line(s, y, color::red, 2, "SIDE=no"); y += 22;
        line(s, y, color::grey, 1, "auto-no in %u s", unsigned((v.remaining_ms + 999) / 1000)); y += 14;
        version_lines(s, y, "running:", v.running_version);
        break;
    }
    case Stage::Working: {
        line(s, 8, cyan, 2, "UPDATING");
        int y = 36;
        if (v.phase == Phase::Download && v.total) {
            s.progress = true;
            s.percent = static_cast<std::uint8_t>(static_cast<std::uint64_t>(v.done) * 100u / v.total);
            line(s, y, color::white, 1, "%s %u%%", phase_text(v.phase), unsigned(s.percent));
        } else {
            line(s, y, color::white, 1, "%s", phase_text(v.phase));
        }
        y = 70;
        line(s, y, color::grey, 1, "Keep it powered."); y += 10;
        line(s, y, color::grey, 1, "Old firmware stays"); y += 10;
        line(s, y, color::grey, 1, "until all checks pass"); y += 16;
        version_lines(s, y, "new:", v.new_version);
        break;
    }
    case Stage::Installed: {
        line(s, 8, color::green, 2, "INSTALLED");
        int y = 36;
        line(s, y, color::white, 1, "Signature + SHA-256 ok"); y += 10;
        line(s, y, color::white, 1, "Rebooting into:"); y += 10;
        y = version_lines(s, y, "new:", v.new_version) + 6;
        line(s, y, color::grey, 1, "The boot self-test"); y += 10;
        line(s, y, color::grey, 1, "decides if it stays;"); y += 10;
        line(s, y, color::grey, 1, "else it rolls back."); 
        break;
    }
    case Stage::Failed: {
        line(s, 8, color::red, 2, "NOT DONE");
        int y = 36;
        line(s, y, color::white, 1, "%s", reason_line(v.reason)); y += 10;
        line(s, y, color::grey, 1, "%s", reason_text(v.reason)); y += 16;
        line(s, y, color::green, 1, "Current firmware kept"); y += 10;
        line(s, y, color::grey, 1, "Monitoring resumes."); 
        break;
    }
    }
}

void draw(Canvas& c, const View& v) {
    Screen s; compose(v, s);
    c.clear(color::black);
    if (s.progress) {
        c.draw_rect(4, 50, c.width() - 8, 10, color::white);
        const int w = (c.width() - 12) * s.percent / 100;
        if (w > 0) c.fill_rect(6, 52, w, 6, cyan);
    }
    for (std::uint8_t i = 0; i < s.count; ++i) c.text(2, s.lines[i].y, s.lines[i].text.data(), s.lines[i].color, s.lines[i].scale);
}
} // namespace guardian::ota

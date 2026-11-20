// G16C rework (5): TUNE/STATUS over the owner's Wi-Fi; G22A: signed offers only (see session.hpp).
#include "session.hpp"
#include <cstdio>
#include <cstring>

namespace guardian::tune::wifi {
namespace {
bool printable(char c) { return c >= 32 && c <= 126; }
bool starts(const char* s, const char* prefix) { return std::strncmp(s, prefix, std::strlen(prefix)) == 0; }
} // namespace

// ---- G22A: the signed offer ------------------------------------------------------
Nonce make_nonce(const std::uint8_t random[kNonceBytes], std::uint32_t now_ms) {
    Nonce n;
    if (!random) return n;
    static const char digits[] = "0123456789abcdef";
    for (std::size_t i = 0; i < kNonceBytes; ++i) { n.hex[2 * i] = digits[random[i] >> 4]; n.hex[2 * i + 1] = digits[random[i] & 15]; }
    n.hex[kNonceHex] = 0;
    n.issued_ms = now_ms; n.valid = true;
    return n;
}

bool offer_path(const Nonce& nonce, char* out, std::size_t n) {
    if (!nonce.valid || !out || !n) return false;
    const int w = std::snprintf(out, n, "tune/offer?nonce=%s", nonce.hex.data());
    return w > 0 && static_cast<std::size_t>(w) < n;
}

const char* refusal_text(Refusal r) {
    switch (r) {
    case Refusal::None: return "none"; case Refusal::Unsigned: return "unsigned"; case Refusal::Format: return "format";
    case Refusal::NoKey: return "nokey"; case Refusal::Signature: return "signature"; case Refusal::Nonce: return "nonce";
    case Refusal::Expired: return "expired"; case Refusal::Command: return "command";
    }
    return "?";
}

namespace {
bool lower_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }
std::uint8_t nibble(char c) { return static_cast<std::uint8_t>(c <= '9' ? c - '0' : c - 'a' + 10); }
// One line of `text` from `at`: [at, end) without its newline; `next` is where the following line starts.
// False: no complete line (the text ended without a newline).
bool line_at(const char* text, std::size_t n, std::size_t at, std::size_t& end, std::size_t& next) {
    end = at;
    while (end < n && text[end] != '\n') ++end;
    if (end >= n) return false;
    next = end + 1;
    return true;
}
bool is(const char* text, std::size_t at, std::size_t end, const char* word) {
    const std::size_t len = std::strlen(word);
    return end - at == len && std::memcmp(text + at, word, len) == 0;
}
bool has(const char* text, std::size_t at, std::size_t end, const char* prefix) {
    const std::size_t len = std::strlen(prefix);
    return end - at >= len && std::memcmp(text + at, prefix, len) == 0;
}
} // namespace

Refusal verify_offer(const char* text, std::size_t n, const Nonce& nonce, std::uint32_t now_ms,
                     const SignatureVerifier* key, Offer& out) {
    if (!text || !n || n > kMaxOffer) return Refusal::Format;
    std::size_t at = 0, end = 0, next = 0;
    // 1. The shape, in fixed order. Nothing is believed yet.
    if (!line_at(text, n, at, end, next)) return Refusal::Format;
    if (is(text, at, end, "GUARDIAN-TUNE 1")) return Refusal::Unsigned;   // the offer of every tool before G22A
    if (!is(text, at, end, "GUARDIAN-TUNE 2")) return Refusal::Format;
    at = next;
    if (!line_at(text, n, at, end, next) || !has(text, at, end, "nonce=") || end - at != 6 + kNonceHex) return Refusal::Format;
    const char* offered_nonce = text + at + 6;
    for (std::size_t i = 0; i < kNonceHex; ++i) if (!lower_hex(offered_nonce[i])) return Refusal::Format;
    at = next;
    if (!line_at(text, n, at, end, next) || !has(text, at, end, "expires=")) return Refusal::Format;
    std::uint32_t seconds = 0;
    {
        const std::size_t digits = end - (at + 8);
        if (!digits || digits > 4 || text[at + 8] == '0') return Refusal::Format;
        for (std::size_t i = at + 8; i < end; ++i) {
            if (text[i] < '0' || text[i] > '9') return Refusal::Format;
            seconds = seconds * 10u + static_cast<std::uint32_t>(text[i] - '0');
        }
        if (seconds < kMinSeconds || seconds > kMaxSeconds) return Refusal::Format;
    }
    at = next;
    Offer o;
    for (;;) {
        if (!line_at(text, n, at, end, next)) return Refusal::Format;
        if (is(text, at, end, "end")) break;
        if (!has(text, at, end, "cmd=") || o.command_count >= kMaxCommands || end - (at + 4) > kMaxCommand) return Refusal::Format;
        std::memcpy(o.commands[o.command_count].data(), text + at + 4, end - (at + 4));
        o.commands[o.command_count][end - (at + 4)] = 0;
        ++o.command_count;
        at = next;
    }
    if (!o.command_count) return Refusal::Format;
    const std::size_t signed_bytes = next;   // everything through "end\n"
    // 2. The signature line: absent = unsigned; present, it must be the last thing in the text.
    if (signed_bytes == n) return Refusal::Unsigned;
    at = signed_bytes; end = at;
    while (end < n && text[end] != '\n') ++end;
    if (end < n && end + 1 != n) return Refusal::Format;   // something follows the signature line
    if (!has(text, at, end, "sig=")) return Refusal::Format;
    if (end - at == 4) return Refusal::Unsigned;
    if (end - at != 4 + 2 * kSignatureBytes) return Refusal::Signature;
    std::array<std::uint8_t, kSignatureBytes> signature{};
    for (std::size_t i = 0; i < kSignatureBytes; ++i) {
        const char hi = text[at + 4 + 2 * i], lo = text[at + 5 + 2 * i];
        if (!lower_hex(hi) || !lower_hex(lo)) return Refusal::Signature;
        signature[i] = static_cast<std::uint8_t>(nibble(hi) << 4 | nibble(lo));
    }
    // 3. Origin: the exact bytes received, checked with the OTA public key.
    if (!key) return Refusal::NoKey;
    if (!key->verify(reinterpret_cast<const std::uint8_t*>(text), signed_bytes, signature.data(), signature.size())) return Refusal::Signature;
    // 4. Freshness: this stick's nonce of this request, inside the signed expiry on this stick's clock.
    if (!nonce.valid || std::memcmp(offered_nonce, nonce.hex.data(), kNonceHex) != 0) return Refusal::Nonce;
    if (now_ms - nonce.issued_ms >= seconds * 1000u) return Refusal::Expired;
    // 5. The allowlist is not widened by a signature.
    for (std::size_t i = 0; i < o.command_count; ++i) if (!allowed(o.commands[i].data())) return Refusal::Command;
    std::memcpy(o.session.data(), nonce.hex.data(), kNonceHex + 1);
    o.seconds = seconds;
    out = o;
    return Refusal::None;
}

void OfferCounts::note(Refusal r) {
    if (r == Refusal::None) { ++accepted; return; }
    ++refused; last = r;
    const auto i = static_cast<std::size_t>(r);
    if (i < by.size()) ++by[i];
}

bool OfferCounts::status(char* out, std::size_t n) const {
    if (!out || !n) return false;
    const auto of = [this](Refusal r) { return static_cast<unsigned>(by[static_cast<std::size_t>(r)]); };
    const int w = std::snprintf(out, n, "tune_offers_ok=%u tune_offers_refused=%u tune_offers_refused_last=%s"
        " tune_offers_refused_by=unsigned:%u,format:%u,nokey:%u,signature:%u,nonce:%u,expired:%u,command:%u",
        static_cast<unsigned>(accepted), static_cast<unsigned>(refused), refusal_text(last), of(Refusal::Unsigned), of(Refusal::Format),
        of(Refusal::NoKey), of(Refusal::Signature), of(Refusal::Nonce), of(Refusal::Expired), of(Refusal::Command));
    return w > 0 && static_cast<std::size_t>(w) < n;
}

bool allowed(const char* line) {
    if (!line) return false;
    const std::size_t n = std::strlen(line);
    if (!n || n > kMaxCommand) return false;
    for (std::size_t i = 0; i < n; ++i) if (!printable(line[i])) return false;
    if (!std::strcmp(line, "STATUS") || !std::strcmp(line, "FRAMES") || !std::strcmp(line, "FRAMES 0") || !std::strcmp(line, "TUNE?")) return true;
    if (!std::strcmp(line, "IMU POSE")) return true;   // review 2026-11-17: one still-pose reading (adapters/imu/pose.hpp)
    if (!std::strcmp(line, "BATTRUN")) return true;    // review 2026-11-17: the battery run log, read-only
    // Supervisor 2026-11-19 (G16H): the coexistence spike over Wi-Fi, the stick's USB being only its charger.
    // Only the spike image acts on them (it arms the run for after the session); the normal image says unsupported.
    if (!std::strcmp(line, "BLESPIKE") || !std::strcmp(line, "BLESPIKE report") || !std::strcmp(line, "BLESPIKE phases") ||
        !std::strcmp(line, "BLESPIKE stop") || !std::strcmp(line, "BLESPIKE start")) return true;
    if (starts(line, "BLESPIKE start ")) {   // "BLESPIKE start <phase_s> <rounds>": two numbers of 1..3 digits, one space each
        std::size_t i = 15, a = 0, b = 0;
        while (i < n && line[i] >= '0' && line[i] <= '9') { ++i; ++a; }
        if (!a || a > 3 || i >= n || line[i] != ' ') return false;
        ++i;
        while (i < n && line[i] >= '0' && line[i] <= '9') { ++i; ++b; }
        return b == 1 && i == n;
    }
    if (starts(line, "TUNE? ")) {   // one group of the registry, e.g. "TUNE? t.probe" (review 2026-11-17)
        if (n == 6) return false;
        for (std::size_t i = 6; i < n; ++i) { const char c = line[i]; if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_')) return false; }
        return true;
    }
    return starts(line, "TUNE ") && n > 5;
}

const char* end_text(End e) {
    switch (e) {
    case End::None: return "none"; case End::Timeout: return "timeout"; case End::Key: return "key";
    case End::Done: return "done"; case End::Network: return "network";
    }
    return "?";
}

bool reply_path(const Offer& o, char* out, std::size_t n) {
    const int w = std::snprintf(out, n, "tune/reply?s=%s", o.session.data());
    return w > 0 && static_cast<std::size_t>(w) < n;
}
bool end_path(const Offer& o, End why, char* out, std::size_t n) {
    const int w = std::snprintf(out, n, "tune/end?s=%s&why=%s", o.session.data(), end_text(why));
    return w > 0 && static_cast<std::size_t>(w) < n;
}

} // namespace guardian::tune::wifi

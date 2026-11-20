// G16J attack coverage (TDD: written and run RED first against the stub stage of
// guardian/shapes.hpp and the unchanged detectors; logs in
// $GUARDIAN_STORE/builds/20261118-g16j-tdd/red-coverage_check.log).
//
// Every case feeds hand-built 802.11 frames through the real SecurityFrameParser
// into the detector under test, or through measurement::Monitor / Companion end
// to end. Each new pattern has an attack stream that must report exactly once
// per cooldown and a benign twin that must report nothing. Generated frames are
// host input, never radio proof: the live matrix (docs/attack-coverage.md) is
// what proves a row on the StickS3.
#include "check.hpp"
#include "companion.hpp"
#include "measurement.hpp"
#include "threat_tune.hpp"

#include "guardian/presenter.hpp"
#include "guardian/rating.hpp"
#include "guardian/security_parser.hpp"
#include "guardian/shapes.hpp"
#include "guardian/threats.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace guardian;
using guardian::companion::Companion;
using guardian::measurement::Monitor;
using guardian::measurement::Packet;
using guardian::measurement::Survey;

namespace {

// ---- time, addresses, frames ----------------------------------------------------------
TimeEpoch epoch() { TimeEpoch e{}; e.source_id[0] = 7; e.boot_id = 1; return e; }
class Clock final : public MonotonicClock {
public:
    Millis at{1000};
    Millis now() const override { return at; }
    TimeEpoch epoch() const override { return ::epoch(); }
};

constexpr Mac kBroadcast{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
constexpr Mac kHome{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
constexpr Mac kNeighbour{0x00, 0x66, 0x77, 0x88, 0x99, 0xaa};
constexpr Mac kTemplate{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
constexpr Mac kPhone{0x3c, 0x10, 0x00, 0x00, 0x00, 0x09};
Mac mac(std::uint8_t a, std::uint32_t i) {
    return Mac{static_cast<std::uint8_t>(a & 0xfc), 0x10, static_cast<std::uint8_t>(i >> 16), static_cast<std::uint8_t>(i >> 8),
               static_cast<std::uint8_t>(i), 0x01};
}
Mac random_mac(std::uint32_t i) { Mac m = mac(0x58, i); m[0] = 0x5a; return m; }   // locally administered
Mac board_mac(std::uint32_t i) {   // AC:27:6E = a block the IEEE registry assigns to Espressif
    return Mac{0xac, 0x27, 0x6e, static_cast<std::uint8_t>(i >> 8), static_cast<std::uint8_t>(i), 0x02};
}

struct Bytes {
    std::array<std::uint8_t, 600> b{};
    std::size_t n{};
    Bytes& u8(std::size_t v) { b[n++] = static_cast<std::uint8_t>(v); return *this; }
    Bytes& u16(std::size_t v) { u8(v & 0xff); return u8((v >> 8) & 0xff); }
    Bytes& be16(std::size_t v) { u8((v >> 8) & 0xff); return u8(v & 0xff); }
    Bytes& be64(std::uint64_t v) { for (int i = 7; i >= 0; --i) u8(static_cast<std::size_t>((v >> (8 * i)) & 0xff)); return *this; }
    Bytes& le64(std::uint64_t v) { for (int i = 0; i < 8; ++i) u8(static_cast<std::size_t>((v >> (8 * i)) & 0xff)); return *this; }
    Bytes& addr(const Mac& m) { for (auto x : m) u8(x); return *this; }
    Bytes& fill(std::size_t count, std::size_t v) { for (std::size_t i = 0; i < count; ++i) u8(v); return *this; }
    Bytes& raw(const std::uint8_t* s, std::size_t len) { for (std::size_t i = 0; i < len; ++i) u8(s[i]); return *this; }
    Bytes& ssid(const std::string& s) { u8(0); u8(s.size()); for (char c : s) u8(static_cast<std::uint8_t>(c)); return *this; }
};
// `seq_ctrl` is the raw Sequence Control field (sequence << 4 | fragment); `duration` the Duration/ID field.
Bytes header(std::uint32_t subtype, const Mac& a1, const Mac& a2, const Mac& a3, std::uint32_t seq_ctrl = 0, std::uint32_t fc1 = 0,
             std::uint32_t duration = 0) {
    Bytes f; f.u8(subtype << 4).u8(fc1).u16(duration).addr(a1).addr(a2).addr(a3).u16(seq_ctrl);
    return f;
}
struct BeaconOptions {
    bool privacy{true};
    std::uint64_t tsf{};
    std::uint32_t interval{100};
    int csa_count{-1};
};
Bytes beacon(const Mac& bssid, const std::string& name, const BeaconOptions& o = {}, std::uint32_t subtype = 8, const Mac& to = kBroadcast) {
    Bytes f = header(subtype, to, bssid, bssid);
    // tsf 0 = "an ordinary AP": every frame gets a later timestamp. A case that needs a timestamp
    // that never moves sets one explicitly.
    static std::uint64_t ordinary = 3600000000ull;
    ordinary += 102400;
    f.le64(o.tsf ? o.tsf : ordinary).u16(o.interval).u16(o.privacy ? 0x0011 : 0x0001);
    f.ssid(name);
    f.u8(3).u8(1).u8(6);
    if (o.privacy) f.u8(48).u8(20).u16(1).u8(0).u8(0x0f).u8(0xac).u8(4).u16(1).u8(0).u8(0x0f).u8(0xac).u8(4)
                    .u16(1).u8(0).u8(0x0f).u8(0xac).u8(2).u16(0x0000);
    if (o.csa_count >= 0) f.u8(37).u8(3).u8(1).u8(11).u8(static_cast<std::uint32_t>(o.csa_count));
    return f;
}
Bytes probe_response(const Mac& bssid, const std::string& name, const Mac& to, const BeaconOptions& o = {}) { return beacon(bssid, name, o, 5, to); }
Bytes probe_request(const Mac& from, const std::string& name, std::uint32_t seq_ctrl = 0x0100) {
    Bytes f = header(4, kBroadcast, from, kBroadcast, seq_ctrl);
    f.ssid(name).u8(1).u8(4).u8(0x82).u8(0x84).u8(0x8b).u8(0x96);
    return f;
}
struct Disc {
    std::uint32_t seq{};          // 12-bit sequence number
    std::uint32_t reason{3};
    std::uint32_t duration{};
    bool disassoc{};
    bool retry{};
    bool protected_frame{};
};
Bytes disconnect(const Mac& from, const Mac& to, const Mac& bssid, const Disc& d = {}) {
    Bytes f = header(d.disassoc ? 10 : 12, to, from, bssid, (d.seq & 0x0fff) << 4, (d.retry ? 0x08u : 0u) | (d.protected_frame ? 0x40u : 0u), d.duration);
    f.u16(d.reason);
    return f;
}
constexpr Disc kToolDeauth{0xfff, 2, 0, false, false, false};   // reason 2, sequence control 0xFFF0

// EAPOL-Key M1 / M2 (data frames). pmkid: 0 = none, 1 = keyed-hash-looking, 2 = all zero, 3 = the 11 22 33 ... ramp.
Bytes eapol(const Mac& ap, const Mac& station, bool m2 = false, std::uint64_t replay = 1, int pmkid = 0, bool zero_nonce = false) {
    Bytes f;
    f.u8(0x08).u8(m2 ? 0x01 : 0x02).u16(0);
    if (m2) f.addr(ap).addr(station).addr(ap); else f.addr(station).addr(ap).addr(ap);
    f.u16(0);
    Bytes kd;
    if (!m2 && pmkid) {
        kd.u8(0xdd).u8(20).u8(0x00).u8(0x0f).u8(0xac).u8(0x04);
        static constexpr std::uint8_t hash[16] = {0x9c, 0x13, 0xe7, 0x40, 0x2b, 0xd8, 0x55, 0xa1, 0x0e, 0xf6, 0x73, 0x3a, 0xc9, 0x84, 0x1d, 0x62};
        static constexpr std::uint8_t ramp[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11};
        if (pmkid == 1) kd.raw(hash, 16); else if (pmkid == 2) kd.fill(16, 0); else kd.raw(ramp, 16);
    }
    if (m2) kd.u8(48).u8(20).u16(1).u8(0).u8(0x0f).u8(0xac).u8(4).u16(1).u8(0).u8(0x0f).u8(0xac).u8(4).u16(1).u8(0).u8(0x0f).u8(0xac).u8(2).u16(0);
    const std::size_t body = 95 + kd.n;
    f.u8(0xaa).u8(0xaa).u8(0x03).u8(0x00).u8(0x00).u8(0x00).u8(0x88).u8(0x8e);
    f.u8(2).u8(3).be16(body);
    const std::size_t info = 0x0002u | key_info::Pairwise | (m2 ? key_info::Mic : key_info::Ack);
    f.u8(2).be16(info).be16(16).be64(replay);
    f.fill(32, zero_nonce ? 0 : 0x42);
    f.fill(16, 0).fill(8, 0).fill(8, 0);
    f.fill(16, m2 ? 0x77 : 0);
    f.be16(kd.n);
    for (std::size_t i = 0; i < kd.n; ++i) f.u8(kd.b[i]);
    return f;
}

RxMeta meta(Millis at, int rssi = -50) {
    RxMeta m{};
    m.acquired = Instant{epoch(), at, true};
    m.origin = Origin::LiveRadio; m.status = RxStatus::Ok; m.channel = 6;
    m.rssi_dbm = static_cast<std::int8_t>(rssi); m.rssi_valid = true;
    return m;
}

class Sink final : public ObservationSink {
public:
    void security(const SecurityObservation&) override {}
    void incident(const IncidentObservation& i) override { if (count < got.size()) got[count] = i; ++count; }
    std::array<IncidentObservation, 64> got{};
    std::size_t count{};
    const IncidentObservation& last() const { return got[count == 0 ? 0 : (count - 1 < got.size() ? count - 1 : got.size() - 1)]; }
};
std::size_t count_pattern(const Sink& s, Pattern p) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < s.count && i < s.got.size(); ++i) n += s.got[i].pattern == p;
    return n;
}
std::size_t count_kind(const Sink& s, IncidentKind k) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < s.count && i < s.got.size(); ++i) n += s.got[i].kind == k && s.got[i].scope == IncidentScope::Network;
    return n;
}

Network home_network() { Network n{}; n.bssid = kHome; n.ssid_size = 4; std::memcpy(n.ssid.data(), "home", 4); return n; }
struct Rig {
    ApprovedScope scope{};
    Sink sink{};
    SecurityFrameParser parser{};
    Rig() { ApprovedAp home{}; home.network = home_network(); scope.select(home); }
    ParseResult parse(const Bytes& f, const RxMeta& m) const { return parser.parse(FrameSpan{f.b.data(), static_cast<std::uint16_t>(f.n), false}, m); }
    void feed(FrameDetector& d, const Bytes& f, const RxMeta& m) {
        const FrameSpan span{f.b.data(), static_cast<std::uint16_t>(f.n), false};
        d.on_frame(span, m, parser.parse(span, m), sink);
    }
};

// ---- companion rig ----------------------------------------------------------------------
class MemoryBlob final : public companion::BlobStorage {
public:
    std::vector<std::uint8_t> bytes; bool exists{}; unsigned writes{};
    companion::BlobRead read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const override {
        if (!exists) return companion::BlobRead::Absent;
        if (bytes.size() > capacity) return companion::BlobRead::Error;
        std::memcpy(out, bytes.data(), bytes.size()); size = bytes.size(); return companion::BlobRead::Ok;
    }
    bool write(const std::uint8_t* data, std::size_t size) override { ++writes; bytes.assign(data, data + size); exists = true; return true; }
};
DisplayCapabilities lcd() { return {Support::Supported, 135, 240, PixelFormat::Rgb565, Support::Supported}; }
Packet packet(const Bytes& f, const Clock& clock, int rssi = -50) {
    Packet p{};
    p.meta = meta(clock.at, rssi);
    std::memcpy(p.bytes.data(), f.b.data(), f.n);
    p.size = static_cast<std::uint16_t>(f.n);
    return p;
}
Network network(const Mac& bssid, const std::string& name) {
    Network n{}; n.bssid = bssid; n.ssid_size = static_cast<std::uint8_t>(name.size()); std::memcpy(n.ssid.data(), name.data(), name.size()); return n;
}
void pick(Companion& c, const Network& n, Action confirm) {
    if (c.presenter().screen() != Screen::Picker) c.input(Action::SecondaryLong);
    for (int i = 0; i < 20; ++i) {
        const auto& v = c.presenter().picker();
        if (v.count && v.entries[v.cursor].network == n) break;
        c.input(Action::Primary);
    }
    c.input(confirm);
}
bool has(const companion::Frame& f, const char* needle) {
    for (std::uint8_t i = 0; i < f.count; ++i) if (std::strstr(f.lines[i].text.data(), needle)) return true;
    return false;
}
std::string joined(const companion::Frame& f) {
    std::string out;
    for (std::uint8_t i = 0; i < f.count; ++i) { if (!out.empty()) out += ' '; out += f.lines[i].text.data(); }
    return out;
}
bool printable(const char* s) {
    for (; *s; ++s) if (static_cast<unsigned char>(*s) < 0x20 || static_cast<unsigned char>(*s) > 0x7e) return false;
    return true;
}
// A companion whose owner picked "home" (kHome), fed its beacon every 100 ms.
struct Home {
    Clock clock{};
    Monitor monitor{clock, profiles::all_2g4_channels(), Origin::LiveRadio};
    MemoryBlob blob{};
    companion::EncodedSelectionStore store{blob};
    Companion companion{clock, monitor, store, lcd(), Origin::LiveRadio};
};

} // namespace

// =========================================================================================
// Parser facts the shapes read
// =========================================================================================
GUARDIAN_CASE(parser_reports_the_duration_field_and_a_synthetic_pmkid) {
    Rig r;
    Disc d{}; d.reason = 7; d.duration = 0x013a;
    const auto p = r.parse(disconnect(kHome, kPhone, kHome, d), meta(1000));
    CHECK(p.header_valid);
    CHECK_EQ(p.duration, 0x013au);
    CHECK_EQ(r.parse(disconnect(kHome, kPhone, kHome), meta(1000)).duration, 0u);

    const auto keyed = r.parse(eapol(kNeighbour, kPhone, false, 1, 1), meta(1000));
    CHECK_EQ(keyed.eapol.state, ElementState::Valid);
    CHECK(keyed.eapol.pmkid_present);
    CHECK(!keyed.eapol.pmkid_synthetic);               // a keyed-hash-looking value is never called a template
    const auto zero = r.parse(eapol(kNeighbour, kPhone, false, 1, 2), meta(1000));
    CHECK(zero.eapol.pmkid_present);
    CHECK(zero.eapol.pmkid_synthetic);                 // 16 equal bytes
    const auto ramp = r.parse(eapol(kNeighbour, kPhone, false, 1, 3), meta(1000));
    CHECK(ramp.eapol.pmkid_present);
    CHECK(ramp.eapol.pmkid_synthetic);                 // 11 22 33 ... : a constant step
    CHECK(!r.parse(eapol(kNeighbour, kPhone, false, 1, 0), meta(1000)).eapol.pmkid_synthetic);
}

// =========================================================================================
// Shape helpers
// =========================================================================================
GUARDIAN_CASE(disconnect_frame_shapes_read_only_readable_reasons) {
    Rig r;
    CHECK_EQ(disconnect_frame_shapes(r.parse(disconnect(kHome, kPhone, kHome, kToolDeauth), meta(1))), shape::DisconnectFixedSequence);
    Disc other = kToolDeauth; other.seq = 0x123;
    CHECK_EQ(disconnect_frame_shapes(r.parse(disconnect(kHome, kPhone, kHome, other), meta(1))), 0u);
    Disc reason3 = kToolDeauth; reason3.reason = 3;
    CHECK_EQ(disconnect_frame_shapes(r.parse(disconnect(kHome, kPhone, kHome, reason3), meta(1))), 0u);
    Disc aire{}; aire.reason = 7; aire.duration = 0x013a; aire.seq = 40;
    CHECK_EQ(disconnect_frame_shapes(r.parse(disconnect(kHome, kPhone, kHome, aire), meta(1))), shape::DisconnectFixedDuration);
    aire.duration = 0;
    CHECK_EQ(disconnect_frame_shapes(r.parse(disconnect(kHome, kPhone, kHome, aire), meta(1))), 0u);
    // A Protected frame's body is unreadable: its reason is never read, so it never shows a per-frame shape.
    Disc prot = kToolDeauth; prot.protected_frame = true;
    CHECK_EQ(disconnect_frame_shapes(r.parse(disconnect(kHome, kPhone, kHome, prot), meta(1))), 0u);
    // Not a disconnect frame.
    CHECK_EQ(disconnect_frame_shapes(r.parse(beacon(kHome, "home"), meta(1))), 0u);
}

GUARDIAN_CASE(rising_run_needs_one_destination_and_alternation_needs_changes) {
    Rig r;
    DisconnectRuns runs;
    std::uint16_t got = 0;
    // Six frames to ONE station, sequence +1 each: the run holds on the sixth.
    for (std::uint32_t i = 0; i < 6; ++i) {
        Disc d{}; d.seq = 100 + i;
        got = runs.observe(r.parse(disconnect(kNeighbour, kPhone, kNeighbour, d), meta(1000 + i * 20)), 1000 + i * 20, 6, 10000);
        if (i < 5) CHECK_EQ(got, 0u);
    }
    CHECK_EQ(got, shape::RisingSequence);
    // An AP saying goodbye to eight DIFFERENT stations with consecutive sequence numbers never makes a run.
    runs.clear();
    for (std::uint32_t i = 0; i < 8; ++i) {
        Disc d{}; d.seq = 500 + i;
        CHECK_EQ(runs.observe(r.parse(disconnect(kNeighbour, mac(0x3c, i), kNeighbour, d), meta(2000 + i * 5)), 2000 + i * 5, 6, 10000), 0u);
    }
    // The sequence wraps at 4096: 0xFFE, 0xFFF, 0x000 ... still rises by one.
    runs.clear(); got = 0;
    for (std::uint32_t i = 0; i < 6; ++i) {
        Disc d{}; d.seq = (0xffe + i) & 0xfff;
        got = runs.observe(r.parse(disconnect(kNeighbour, kPhone, kNeighbour, d), meta(3000 + i * 20)), 3000 + i * 20, 6, 10000);
    }
    CHECK_EQ(got, shape::RisingSequence);
    // Alternating deauthentication / disassociation: six changes.
    runs.clear(); got = 0;
    for (std::uint32_t i = 0; i < 7; ++i) {
        Disc d{}; d.seq = 7 * i + 3; d.disassoc = (i % 2) == 1;
        got = runs.observe(r.parse(disconnect(kNeighbour, kPhone, kNeighbour, d), meta(4000 + i * 20)), 4000 + i * 20, 6, 10000);
        if (i < 6) CHECK_EQ(got, 0u);
    }
    CHECK_EQ(got, shape::KindAlternation);
    // One deauthentication then one disassociation (an ordinary goodbye) is not an alternation run.
    runs.clear();
    Disc a{}; a.seq = 9; Disc b{}; b.seq = 30; b.disassoc = true;
    CHECK_EQ(runs.observe(r.parse(disconnect(kNeighbour, kPhone, kNeighbour, a), meta(5000)), 5000, 6, 10000), 0u);
    CHECK_EQ(runs.observe(r.parse(disconnect(kNeighbour, kPhone, kNeighbour, b), meta(5010)), 5010, 6, 10000), 0u);
    // A run not continued within the window starts over.
    runs.clear(); got = 0;
    for (std::uint32_t i = 0; i < 6; ++i) {
        Disc d{}; d.seq = 100 + i;
        const Millis at = 10000 + i * 20 + (i >= 3 ? 20000 : 0);
        got = runs.observe(r.parse(disconnect(kNeighbour, kPhone, kNeighbour, d), meta(at)), at, 6, 10000);
    }
    CHECK_EQ(got, 0u);
    // run == 0 disables the check.
    runs.clear();
    for (std::uint32_t i = 0; i < 12; ++i) {
        Disc d{}; d.seq = 100 + i;
        CHECK_EQ(runs.observe(r.parse(disconnect(kNeighbour, kPhone, kNeighbour, d), meta(50000 + i)), 50000 + i, 0, 10000), 0u);
    }
}

GUARDIAN_CASE(vendor_table_and_template_address) {
    CHECK(board_vendor(board_mac(1)));                                   // AC:27:6E (this StickS3's own block)
    CHECK(board_vendor(Mac{0x24, 0x0a, 0xc4, 1, 2, 3}));
    CHECK(board_vendor(Mac{0x34, 0x85, 0x18, 1, 2, 3}));
    CHECK(!board_vendor(kHome));
    CHECK(!board_vendor(random_mac(4)));                                 // a randomized address has no vendor
    CHECK(!board_vendor(Mac{0xac, 0x27, 0x6f, 1, 2, 3}));
    CHECK(template_address(kTemplate));
    CHECK(!template_address(kHome));
    CHECK_EQ(halved(20), 10u); CHECK_EQ(halved(5), 3u); CHECK_EQ(halved(1), 1u); CHECK_EQ(halved(0), 1u);
}

// =========================================================================================
// Disconnect frames on the selected network
// =========================================================================================
GUARDIAN_CASE(shaped_disconnects_halve_the_red_burst_threshold_once_per_cooldown) {
    Rig r; DisconnectDetector d(r.scope, DetectorLimits{});
    CHECK(d.configured());
    Millis t = 10000;
    // 2 frames a second for 100 s: reason 2 with sequence control 0xFFF0, as the AP to broadcast.
    for (int i = 0; i < 200; ++i, t += 500) r.feed(d, disconnect(kHome, kBroadcast, kHome, kToolDeauth), meta(t));
    CHECK_EQ(count_kind(r.sink, IncidentKind::DisconnectBurst), 3u);   // at frame 10, then after each 45 s cooldown
    const auto& o = r.sink.got[0];
    CHECK_EQ(o.threshold, 10u);
    CHECK_EQ(o.count, 10u);
    CHECK((o.shapes & shape::DisconnectFixedSequence) != 0);
    CHECK(o.tool_shape());
    CHECK_EQ(o.acquired.at, 10000u + 9 * 500);                       // on the closing frame
    CHECK(r.sink.got[1].acquired.at - o.acquired.at >= 45000u);
}

GUARDIAN_CASE(unshaped_disconnects_keep_the_full_threshold) {
    Rig r; DisconnectDetector d(r.scope, DetectorLimits{});
    Millis t = 10000;
    // 12 ordinary frames in 6 s: different stations, unrelated sequence numbers, reason 3.
    for (std::uint32_t i = 0; i < 12; ++i, t += 500) {
        Disc x{}; x.seq = 17 * i + 5;
        r.feed(d, disconnect(kHome, mac(0x3c, i), kHome, x), meta(t));
    }
    CHECK_EQ(r.sink.count, 0u);
    // An AP reboot: goodbye to 12 different stations back to back, consecutive sequence numbers.
    d.reset(); t = 100000;
    for (std::uint32_t i = 0; i < 12; ++i, t += 3) {
        Disc x{}; x.seq = 900 + i;
        r.feed(d, disconnect(kHome, mac(0x3c, i), kHome, x), meta(t));
    }
    CHECK_EQ(r.sink.count, 0u);
    // Two frames with the fixed sequence are not enough (shape_frames = 3), and 9 shaped frames stay below 10.
    d.reset(); t = 200000;
    for (int i = 0; i < 2; ++i, t += 500) r.feed(d, disconnect(kHome, kBroadcast, kHome, kToolDeauth), meta(t));
    for (std::uint32_t i = 0; i < 10; ++i, t += 500) { Disc x{}; x.seq = 31 * i + 2; r.feed(d, disconnect(kHome, mac(0x3c, i), kHome, x), meta(t)); }
    CHECK_EQ(r.sink.count, 0u);
    d.reset(); t = 300000;
    for (int i = 0; i < 9; ++i, t += 500) r.feed(d, disconnect(kHome, kBroadcast, kHome, kToolDeauth), meta(t));
    CHECK_EQ(r.sink.count, 0u);
    // 20 unshaped frames still report, with the full threshold and no shape.
    d.reset(); t = 400000;
    for (std::uint32_t i = 0; i < 20; ++i, t += 400) { Disc x{}; x.seq = 31 * i + 2; r.feed(d, disconnect(kHome, mac(0x3c, i), kHome, x), meta(t)); }
    CHECK_EQ(r.sink.count, 1u);
    CHECK_EQ(r.sink.got[0].threshold, 20u);
    CHECK_EQ(r.sink.got[0].shapes, 0u);
}

GUARDIAN_CASE(rising_and_alternating_disconnect_runs_halve_the_red_threshold) {
    Rig r; DisconnectDetector d(r.scope, DetectorLimits{});
    Millis t = 10000;
    // 10 frames, one station, the sender's own counter: sequence +1 each (reason 1, nothing fixed).
    for (std::uint32_t i = 0; i < 10; ++i, t += 300) { Disc x{}; x.seq = 200 + i; x.reason = 1; r.feed(d, disconnect(kHome, kPhone, kHome, x), meta(t)); }
    CHECK_EQ(r.sink.count, 1u);
    CHECK((r.sink.got[0].shapes & shape::RisingSequence) != 0);
    CHECK_EQ(r.sink.got[0].threshold, 10u);
    // 10 frames alternating deauthentication / disassociation with unrelated sequence numbers.
    Rig r2; DisconnectDetector d2(r2.scope, DetectorLimits{});
    t = 10000;
    for (std::uint32_t i = 0; i < 10; ++i, t += 300) { Disc x{}; x.seq = 23 * i + 1; x.disassoc = (i % 2) == 1; r2.feed(d2, disconnect(kHome, kPhone, kHome, x), meta(t)); }
    CHECK_EQ(r2.sink.count, 1u);
    CHECK((r2.sink.got[0].shapes & shape::KindAlternation) != 0);
    // shape_run = 0 and shape_frames = 0 switch the halving off.
    Rig r3; DetectorLimits off{}; off.shape_run = 0; off.shape_frames = 0;
    DisconnectDetector d3(r3.scope, off);
    t = 10000;
    for (std::uint32_t i = 0; i < 19; ++i, t += 300) r3.feed(d3, disconnect(kHome, kBroadcast, kHome, kToolDeauth), meta(t));
    CHECK_EQ(r3.sink.count, 0u);
}

GUARDIAN_CASE(reason_7_with_the_fixed_duration_halves_the_red_threshold_and_plain_reason_7_does_not) {
    Rig r; DisconnectDetector d(r.scope, DetectorLimits{});
    Millis t = 10000;
    // 2 frames a second for 100 s to changing stations: reason 7 with Duration 0x013A, unrelated sequence numbers.
    for (std::uint32_t i = 0; i < 200; ++i, t += 500) {
        Disc x{}; x.reason = 7; x.duration = 0x013a; x.seq = 29 * i + 3;
        r.feed(d, disconnect(kHome, mac(0x3c, i % 9), kHome, x), meta(t));
    }
    CHECK_EQ(count_kind(r.sink, IncidentKind::DisconnectBurst), 3u);
    CHECK_EQ(r.sink.got[0].threshold, 10u);
    CHECK((r.sink.got[0].shapes & shape::DisconnectFixedDuration) != 0);
    CHECK_EQ(r.sink.got[0].acquired.at, 10000u + 9 * 500);
    // The same ten frames with an ordinary Duration: reason 7 alone is what a real AP sends too.
    Rig q; DisconnectDetector dq(q.scope, DetectorLimits{});
    t = 10000;
    for (std::uint32_t i = 0; i < 10; ++i, t += 500) {
        Disc x{}; x.reason = 7; x.seq = 29 * i + 3;
        q.feed(dq, disconnect(kHome, mac(0x3c, i % 9), kHome, x), meta(t));
    }
    CHECK_EQ(q.sink.count, 0u);
}

// Baseline (expected green from the start: DisconnectDetector already counts disassociation).
GUARDIAN_CASE(disassociation_reason_8_burst_is_red_once_per_cooldown_and_roaming_never) {
    Rig r; DisconnectDetector d(r.scope, DetectorLimits{});
    Millis t = 10000;
    for (std::uint32_t i = 0; i < 400; ++i, t += 250) {   // 100 s, spoofed as each of 40 stations leaving
        Disc x{}; x.seq = 41 * i + 7; x.reason = 8; x.disassoc = true;
        r.feed(d, disconnect(mac(0x3c, i % 40), kHome, kHome, x), meta(t));
    }
    CHECK_EQ(count_kind(r.sink, IncidentKind::DisconnectBurst), 3u);
    CHECK_EQ(r.sink.got[0].threshold, 20u);
    CHECK_EQ(r.sink.got[0].shapes, 0u);
    // Ordinary roaming: one station leaving (reason 8) every 30 s for ten minutes.
    Rig quiet; DisconnectDetector q(quiet.scope, DetectorLimits{});
    t = 10000;
    for (std::uint32_t i = 0; i < 20; ++i, t += 30000) {
        Disc x{}; x.seq = 41 * i + 7; x.reason = 8; x.disassoc = true;
        quiet.feed(q, disconnect(mac(0x3c, i), kHome, kHome, x), meta(t));
    }
    CHECK_EQ(quiet.sink.count, 0u);
}

GUARDIAN_CASE(targeted_pair_on_the_selected_network_is_red_once_per_cooldown) {
    Rig r; AreaDisconnectDetector d(r.scope);
    Millis t = 10000;
    // 12 frames in under a second from the AP's address to ONE station, then the same every 2 s for 100 s.
    for (int burst = 0; burst < 50; ++burst, t += 2000)
        for (std::uint32_t i = 0; i < 12; ++i) { Disc x{}; x.seq = 37 * (static_cast<std::uint32_t>(burst) * 12 + i) + 1; r.feed(d, disconnect(kHome, kPhone, kHome, x), meta(t + i * 50)); }
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthPair), 3u);
    const auto& o = r.sink.got[0];
    CHECK_EQ(o.scope, IncidentScope::Network);
    CHECK_EQ(o.kind, IncidentKind::NetworkPattern);
    CHECK(o.affected == home_network());
    CHECK_EQ(o.bssid, kHome);
    CHECK_EQ(o.count, 12u);
    CHECK_EQ(o.threshold, 12u);
    CHECK_EQ(o.window_ms, 1000u);
    CHECK_EQ(o.acquired.at, 10000u + 11 * 50);
    // In-scope frames never feed the AREA rules (source / broadcast): those stay the red burst's.
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthSource), 0u);
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthBroadcast), 0u);
}

GUARDIAN_CASE(pair_rule_benign_twins_and_the_shaped_half) {
    // 11 frames in a second to one station: below the rule.
    Rig r; AreaDisconnectDetector d(r.scope);
    for (std::uint32_t i = 0; i < 11; ++i) { Disc x{}; x.seq = 37 * i + 1; r.feed(d, disconnect(kHome, kPhone, kHome, x), meta(10000 + i * 50)); }
    CHECK_EQ(r.sink.count, 0u);
    // One frame and eleven Retry copies of it: one observation.
    Rig r2; AreaDisconnectDetector d2(r2.scope);
    for (std::uint32_t i = 0; i < 12; ++i) { Disc x{}; x.seq = 77; x.retry = i > 0; r2.feed(d2, disconnect(kHome, kPhone, kHome, x), meta(10000 + i * 5)); }
    CHECK_EQ(r2.sink.count, 0u);
    // 12 frames in a second to 12 different stations (an AP restart): no pair.
    Rig r3; AreaDisconnectDetector d3(r3.scope);
    for (std::uint32_t i = 0; i < 12; ++i) { Disc x{}; x.seq = 300 + i; r3.feed(d3, disconnect(kHome, mac(0x3c, i), kHome, x), meta(10000 + i * 50)); }
    CHECK_EQ(r3.sink.count, 0u);
    // Six frames with the fixed sequence to one station: the halved pair rule, marked as a tool shape.
    Rig r4; AreaDisconnectDetector d4(r4.scope);
    for (std::uint32_t i = 0; i < 6; ++i) r4.feed(d4, disconnect(kHome, kPhone, kHome, kToolDeauth), meta(10000 + i * 100));
    CHECK_EQ(count_pattern(r4.sink, Pattern::DeauthPair), 1u);
    CHECK_EQ(r4.sink.got[0].threshold, 6u);
    CHECK((r4.sink.got[0].shapes & shape::DisconnectFixedSequence) != 0);
    CHECK_EQ(r4.sink.got[0].scope, IncidentScope::Network);
    // Six ordinary frames: nothing.
    Rig r5; AreaDisconnectDetector d5(r5.scope);
    for (std::uint32_t i = 0; i < 6; ++i) { Disc x{}; x.seq = 37 * i + 1; r5.feed(d5, disconnect(kHome, kPhone, kHome, x), meta(10000 + i * 100)); }
    CHECK_EQ(r5.sink.count, 0u);
}

GUARDIAN_CASE(area_disconnects_with_a_tool_shape_report_at_half_the_count) {
    // A neighbour's network: 10 alternating frames from one address in 5 s (the area rule needs 20 without a shape).
    Rig r; AreaDisconnectDetector d(r.scope);
    Millis t = 10000;
    for (std::uint32_t i = 0; i < 10; ++i, t += 500) { Disc x{}; x.seq = 23 * i + 1; x.disassoc = (i % 2) == 1; r.feed(d, disconnect(kNeighbour, mac(0x3c, i), kNeighbour, x), meta(t)); }
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthSource), 1u);
    CHECK_EQ(r.sink.got[0].scope, IncidentScope::Area);
    CHECK_EQ(r.sink.got[0].threshold, 10u);
    CHECK((r.sink.got[0].shapes & shape::KindAlternation) != 0);
    // The same ten frames, all deauthentication, unrelated sequence numbers: nothing.
    Rig q; AreaDisconnectDetector dq(q.scope);
    t = 10000;
    for (std::uint32_t i = 0; i < 10; ++i, t += 500) { Disc x{}; x.seq = 23 * i + 1; q.feed(dq, disconnect(kNeighbour, mac(0x3c, i), kNeighbour, x), meta(t)); }
    CHECK_EQ(q.sink.count, 0u);
    // Five broadcast frames with the fixed sequence (the broadcast rule needs 10 without a shape).
    Rig b; AreaDisconnectDetector db(b.scope);
    t = 10000;
    for (std::uint32_t i = 0; i < 5; ++i, t += 500) b.feed(db, disconnect(kNeighbour, kBroadcast, kNeighbour, kToolDeauth), meta(t));
    CHECK_EQ(count_pattern(b.sink, Pattern::DeauthBroadcast), 1u);
    CHECK_EQ(b.sink.got[0].threshold, 5u);
    CHECK((b.sink.got[0].shapes & shape::DisconnectFixedSequence) != 0);
}

// =========================================================================================
// A device asks for a name, then a never-seen BSSID answers it
// =========================================================================================
namespace {
// 40 s of an ordinary neighbourhood on this channel (the learn time): two APs beaconing.
void neighbourhood(Rig& r, FrameDetector& d, Millis from, Millis until) {
    std::uint64_t tsf = 5000000;
    for (Millis t = from; t < until; t += 100, tsf += 102400) {
        BeaconOptions o{}; o.tsf = tsf;
        r.feed(d, beacon(kHome, "home", o), meta(t));
        r.feed(d, beacon(kNeighbour, "cafe", o), meta(t + 7));
    }
}
} // namespace

GUARDIAN_CASE(probe_then_a_new_bssid_answering_is_amber_once_per_cooldown) {
    Rig r; ResponderDetector d(r.scope);
    neighbourhood(r, d, 1000, 41000);
    CHECK_EQ(r.sink.count, 0u);
    Millis t = 41000;
    // Every 15 s for two minutes: the phone asks for a remembered name; 1.5 s later a BSSID never heard
    // before (a new random address each time) answers and beacons that name.
    for (std::uint32_t round = 0; round < 8; ++round, t += 15000) {
        const std::string name = "OfficeWiFi" + std::to_string(round);
        r.feed(d, probe_request(kPhone, name), meta(t));
        const Mac fresh = random_mac(100 + round);
        r.feed(d, probe_response(fresh, name, kPhone), meta(t + 1500));
        for (int i = 0; i < 5; ++i) r.feed(d, beacon(fresh, name), meta(t + 1600 + i * 100));
    }
    CHECK_EQ(count_pattern(r.sink, Pattern::KarmaAnswer), 3u);   // rounds 0, 3 and 6: one per 45 s cooldown
    const auto& o = r.sink.got[0];
    CHECK_EQ(o.scope, IncidentScope::Area);
    CHECK_EQ(o.family, DetectorFamily::Responder);
    CHECK_EQ(o.bssid, random_mac(100));
    CHECK_EQ(o.threshold, 2u);
    CHECK(o.count >= 2u);
    CHECK_EQ(o.window_ms, 10000u);
    CHECK(o.sources_random);
    CHECK_EQ(o.acquired.at, 41000u + 1600);                       // the second frame carrying the name closes it
    CHECK_EQ(count_pattern(r.sink, Pattern::ManyNames), 0u);      // one name per transmitter: the many-names rule is blind to it
}

GUARDIAN_CASE(probe_then_answer_benign_twins_never_fire) {
    // (a) The AP was beaconing before the phone asked: an ordinary reply.
    { Rig r; ResponderDetector d(r.scope);
      neighbourhood(r, d, 1000, 41000);
      r.feed(d, probe_request(kPhone, "cafe"), meta(41000));
      for (int i = 0; i < 5; ++i) r.feed(d, probe_response(kNeighbour, "cafe", kPhone), meta(41020 + i * 100));
      CHECK_EQ(r.sink.count, 0u); }
    // (b) The new BSSID shows up 15 s after the ask: outside the answer window.
    { Rig r; ResponderDetector d(r.scope);
      neighbourhood(r, d, 1000, 41000);
      r.feed(d, probe_request(kPhone, "OfficeWiFi"), meta(41000));
      for (int i = 0; i < 5; ++i) r.feed(d, beacon(random_mac(7), "OfficeWiFi"), meta(56000 + i * 100));
      CHECK_EQ(r.sink.count, 0u); }
    // (c) Listening began 5 s ago: "never seen" means nothing yet.
    { Rig r; ResponderDetector d(r.scope);
      neighbourhood(r, d, 1000, 6000);
      r.feed(d, probe_request(kPhone, "OfficeWiFi"), meta(6000));
      for (int i = 0; i < 5; ++i) r.feed(d, beacon(random_mac(7), "OfficeWiFi"), meta(6500 + i * 100));
      CHECK_EQ(r.sink.count, 0u); }
    // (d) The answering BSSID is one the owner approved (a mesh node switched on).
    { Rig r; ResponderDetector d(r.scope);
      ApprovedAp node{}; node.network = home_network(); node.network.bssid = mac(0x00, 77);
      CHECK(r.scope.approve(node));
      neighbourhood(r, d, 1000, 41000);
      r.feed(d, probe_request(kPhone, "home"), meta(41000));
      for (int i = 0; i < 5; ++i) r.feed(d, beacon(node.network.bssid, "home"), meta(41500 + i * 100));
      CHECK_EQ(r.sink.count, 0u); }
    // (e) The name is already advertised by an AP heard before the ask (a second AP of that network appears).
    { Rig r; ResponderDetector d(r.scope);
      neighbourhood(r, d, 1000, 41000);
      r.feed(d, probe_request(kPhone, "cafe"), meta(41000));
      for (int i = 0; i < 5; ++i) r.feed(d, beacon(mac(0x00, 88), "cafe"), meta(41500 + i * 100));
      CHECK_EQ(r.sink.count, 0u); }
    // (f) A wildcard probe asks for no name; a new network appearing after it is just a new network.
    { Rig r; ResponderDetector d(r.scope);
      neighbourhood(r, d, 1000, 41000);
      r.feed(d, probe_request(kPhone, ""), meta(41000));
      for (int i = 0; i < 5; ++i) r.feed(d, beacon(random_mac(7), "OfficeWiFi"), meta(41500 + i * 100));
      CHECK_EQ(r.sink.count, 0u); }
    // (g) One stray frame from the new BSSID is not enough (karma_answers = 2).
    { Rig r; ResponderDetector d(r.scope);
      neighbourhood(r, d, 1000, 41000);
      r.feed(d, probe_request(kPhone, "OfficeWiFi"), meta(41000));
      r.feed(d, beacon(random_mac(7), "OfficeWiFi"), meta(41500));
      CHECK_EQ(r.sink.count, 0u); }
}

GUARDIAN_CASE(template_transmitter_halves_the_many_names_rule) {
    Rig r; ResponderDetector d(r.scope);
    // The placeholder address answering for two names (the rule needs four from an ordinary transmitter).
    Bytes a = beacon(kTemplate, "alpha", {}, 5, kPhone), b = beacon(kTemplate, "bravo", {}, 5, kPhone);
    r.feed(d, a, meta(10000)); r.feed(d, b, meta(10100));
    CHECK_EQ(count_pattern(r.sink, Pattern::ManyNames), 1u);
    CHECK_EQ(r.sink.got[0].threshold, 2u);
    CHECK((r.sink.got[0].shapes & shape::TemplateAddress) != 0);
    Rig q; ResponderDetector dq(q.scope);
    q.feed(dq, beacon(kNeighbour, "alpha", {}, 5, kPhone), meta(10000)); q.feed(dq, beacon(kNeighbour, "bravo", {}, 5, kPhone), meta(10100));
    CHECK_EQ(q.sink.count, 0u);
}

// =========================================================================================
// Channel switch, probes, beacons
// =========================================================================================
GUARDIAN_CASE(switch_count_255_is_marked_as_a_tool_shape) {
    Rig r; ChannelSwitchDetector d(r.scope);
    BeaconOptions ff{}; ff.csa_count = 255;
    r.feed(d, beacon(kNeighbour, "cafe", ff), meta(10000));
    CHECK_EQ(count_pattern(r.sink, Pattern::ChannelSwitch), 1u);
    CHECK((r.sink.got[0].shapes & shape::SwitchCount255) != 0);
    Rig q; ChannelSwitchDetector dq(q.scope);
    BeaconOptions big{}; big.csa_count = 60;
    q.feed(dq, beacon(kNeighbour, "cafe", big), meta(10000));
    CHECK_EQ(count_pattern(q.sink, Pattern::ChannelSwitch), 1u);
    CHECK_EQ(q.sink.got[0].shapes, 0u);
    Rig n; ChannelSwitchDetector dn(n.scope);
    BeaconOptions real{}; real.csa_count = 3;                          // an ordinary announcement
    for (int i = 0; i < 20; ++i) { real.csa_count = 3; n.feed(dn, beacon(kNeighbour, "cafe", real), meta(10000 + i * 100)); }
    CHECK_EQ(n.sink.count, 0u);
}

GUARDIAN_CASE(probe_defaults_are_the_values_measured_on_one_channel) {
    const ThreatLimits l{};
    CHECK_EQ(l.probe_flood, 16u); CHECK_EQ(l.probe_flood_sources, 12u); CHECK_EQ(l.probe_window_ms, 10000u);
    // What one channel hears of a tool that hops on every probe: about 2.5 probes a second, a new random address each.
    Rig r; ProbeFloodDetector d(r.scope);
    Millis t = 10000;
    for (std::uint32_t i = 0; i < 250; ++i, t += 400) r.feed(d, probe_request(random_mac(i), ""), meta(t));
    CHECK_EQ(count_pattern(r.sink, Pattern::ProbeFloodRandom), 3u);
    CHECK_EQ(r.sink.got[0].threshold, 16u);
    CHECK_EQ(r.sink.got[0].window_ms, 10000u);
    CHECK_EQ(r.sink.got[0].shapes, 0u);
    // The benign ceiling of the soak: 15 probes in 10 s, from the home's three phones.
    Rig q; ProbeFloodDetector dq(q.scope);
    t = 10000;
    for (int round = 0; round < 60; ++round, t += 10000)
        for (std::uint32_t i = 0; i < 15; ++i) q.feed(dq, probe_request(mac(0x3c, i % 3), i % 2 ? "home" : ""), meta(t + i * 600));
    CHECK_EQ(q.sink.count, 0u);
}

GUARDIAN_CASE(probes_with_the_fixed_sequence_halve_the_flood_thresholds) {
    // Sequence control 0x0001 (sequence 0, fragment 1): 8 probes from 6 addresses in 4 s.
    Rig r; ProbeFloodDetector d(r.scope);
    Millis t = 10000;
    for (std::uint32_t i = 0; i < 8; ++i, t += 500) r.feed(d, probe_request(random_mac(i % 6), "anything", 0x0001), meta(t));
    CHECK_EQ(count_pattern(r.sink, Pattern::ProbeFloodRandom), 1u);
    CHECK_EQ(r.sink.got[0].threshold, 8u);
    CHECK((r.sink.got[0].shapes & shape::ProbeFixedSequence) != 0);
    // Eight ordinary probes from six addresses: nothing.
    Rig q; ProbeFloodDetector dq(q.scope);
    t = 10000;
    for (std::uint32_t i = 0; i < 8; ++i, t += 500) q.feed(dq, probe_request(random_mac(i % 6), "anything", (i + 5) << 4), meta(t));
    CHECK_EQ(q.sink.count, 0u);
}

GUARDIAN_CASE(beacons_with_a_static_timestamp_or_interval_1000_halve_the_flood_threshold) {
    // 20 strong BSSIDs, each repeating ONE timestamp over six beacons across a second (the rule needs 40 unshaped).
    Rig r; BeaconFloodDetector d(r.scope);
    for (int pass = 0; pass < 6; ++pass)
        for (std::uint32_t i = 0; i < 20; ++i) {
            BeaconOptions o{}; o.tsf = 0x0000000f8ff75183ull;
            r.feed(d, beacon(random_mac(i), "net" + std::to_string(i), o), meta(10000 + static_cast<Millis>(pass) * 200 + i * 5));
        }
    CHECK_EQ(count_pattern(r.sink, Pattern::BeaconFlood), 1u);
    CHECK_EQ(r.sink.got[0].threshold, 20u);
    CHECK((r.sink.got[0].shapes & shape::StaticTimestamp) != 0);
    CHECK(r.sink.got[0].distinct_sources >= 20u);
    // A dense but ordinary neighbourhood: 30 strong BSSIDs whose timestamps advance. Nothing.
    Rig q; BeaconFloodDetector dq(q.scope);
    for (std::uint32_t pass = 0; pass < 60; ++pass)
        for (std::uint32_t i = 0; i < 30; ++i) {
            BeaconOptions o{}; o.tsf = 900000000ull + pass * 102400ull + i * 977ull;
            q.feed(dq, beacon(mac(0x00, 500 + i), "ap" + std::to_string(i), o), meta(10000 + pass * 100 + i * 3));
        }
    CHECK_EQ(q.sink.count, 0u);
    // 20 BSSIDs with a beacon interval of exactly 1000 TU.
    Rig b; BeaconFloodDetector db(b.scope);
    for (std::uint32_t i = 0; i < 20; ++i) {
        BeaconOptions o{}; o.tsf = 900000000ull + i * 977ull; o.interval = 1000;
        b.feed(db, beacon(random_mac(i), "net" + std::to_string(i), o), meta(10000 + i * 5));
    }
    CHECK_EQ(count_pattern(b.sink, Pattern::BeaconFlood), 1u);
    CHECK((b.sink.got[0].shapes & shape::BeaconInterval1000) != 0);
    // Weak ones never count, shaped or not.
    Rig w; BeaconFloodDetector dw(w.scope);
    for (std::uint32_t i = 0; i < 60; ++i) { BeaconOptions o{}; o.interval = 1000; w.feed(dw, beacon(random_mac(i), "far", o), meta(10000 + i * 5, -80)); }
    // An ordinary transmitter whose six beacons carry advancing timestamps is not shaped.
    Rig m; BeaconFloodDetector dm(m.scope);
    for (std::uint32_t i = 0; i < 25; ++i) for (int k = 0; k < 6; ++k) m.feed(dm, beacon(mac(0x00, 700 + i), "ok" + std::to_string(i)), meta(10000 + static_cast<Millis>(k) * 200 + i * 5));
    CHECK_EQ(m.sink.count, 0u);
    CHECK_EQ(w.sink.count, 0u);
}

GUARDIAN_CASE(rotation_from_the_template_address_reports_at_half) {
    Rig r; NameRotationDetector d(r.scope);
    for (std::uint32_t i = 0; i < 6; ++i) r.feed(d, beacon(kTemplate, "name" + std::to_string(i)), meta(10000 + i * 100));
    CHECK_EQ(count_pattern(r.sink, Pattern::NameRotation), 1u);
    CHECK_EQ(r.sink.got[0].threshold, 6u);
    CHECK((r.sink.got[0].shapes & shape::TemplateAddress) != 0);
    Rig q; NameRotationDetector dq(q.scope);
    for (std::uint32_t i = 0; i < 6; ++i) q.feed(dq, beacon(kNeighbour, "name" + std::to_string(i)), meta(10000 + i * 100));
    CHECK_EQ(q.sink.count, 0u);
}

GUARDIAN_CASE(open_lure_name_from_a_board_vendor_address_is_amber_once_per_cooldown) {
    Rig r; NameRotationDetector d(r.scope);
    BeaconOptions open{}; open.privacy = false;
    Millis t = 10000;
    std::uint64_t tsf = 777000;
    for (int i = 0; i < 1000; ++i, t += 100, tsf += 102400) { open.tsf = tsf; r.feed(d, beacon(board_mac(9), "Free WiFi", open), meta(t)); }
    CHECK_EQ(count_pattern(r.sink, Pattern::LurePortal), 3u);          // 100 s: at the third beacon, then per cooldown
    const auto& o = r.sink.got[0];
    CHECK_EQ(o.scope, IncidentScope::Area);
    CHECK_EQ(o.bssid, board_mac(9));
    CHECK_EQ(o.threshold, 3u);
    CHECK((o.shapes & shape::BoardVendorLure) != 0);
    CHECK_EQ(o.acquired.at, 10200u);
    // Benign twins: the same board with a protected "Guest" network; an open lure name from another vendor
    // (a real cafe); the board's own setup network without a lure word.
    Rig q; NameRotationDetector dq(q.scope);
    t = 10000;
    for (int i = 0; i < 300; ++i, t += 100) {
        BeaconOptions adv{}; adv.tsf = 777000ull + static_cast<std::uint64_t>(i) * 102400ull;
        q.feed(dq, beacon(board_mac(10), "Guest", adv), meta(t));
        adv.privacy = false;
        q.feed(dq, beacon(kNeighbour, "Free WiFi", adv), meta(t + 3));
        q.feed(dq, beacon(board_mac(11), "ESP_1A2B3C", adv), meta(t + 6));
    }
    CHECK_EQ(q.sink.count, 0u);
}

// =========================================================================================
// Handshake shapes
// =========================================================================================
GUARDIAN_CASE(synthetic_pmkid_and_replay_range_are_handshake_shapes) {
    // A handshake start carrying a template PMKID (all zero): reported like the empty-nonce start, marked.
    Rig r; HandshakeDetector d(r.scope);
    r.feed(d, eapol(kNeighbour, kPhone, false, 1, 2), meta(10000));
    CHECK_EQ(count_pattern(r.sink, Pattern::FakeM1), 1u);
    CHECK((r.sink.got[0].shapes & shape::SyntheticPmkid) != 0);
    CHECK_EQ(r.sink.got[0].scope, IncidentScope::Area);
    // On the selected network it is the red network pattern.
    Rig h; HandshakeDetector dh(h.scope);
    h.feed(dh, eapol(kHome, kPhone, false, 1, 3), meta(10000));
    CHECK_EQ(count_pattern(h.sink, Pattern::FakeM1), 1u);
    CHECK_EQ(h.sink.got[0].scope, IncidentScope::Network);
    // An ordinary start with a keyed-hash-looking PMKID: nothing.
    Rig q; HandshakeDetector dq(q.scope);
    q.feed(dq, eapol(kNeighbour, kPhone, false, 1, 1), meta(10000));
    q.feed(dq, eapol(kNeighbour, kPhone, true, 1), meta(10050));
    dq.on_tick(Instant{epoch(), 20000, true}, q.sink);
    CHECK_EQ(q.sink.count, 0u);
    // Unanswered starts from TWO APs with replay counters in 0xF000..0xFFFE: the harvest rule at half (it needs three).
    Rig v; HandshakeDetector dv(v.scope);
    v.feed(dv, eapol(mac(0x00, 1), kPhone, false, 0xf123, 1), meta(10000));
    v.feed(dv, eapol(mac(0x00, 2), kPhone, false, 0xf124, 1), meta(10100));
    dv.on_tick(Instant{epoch(), 12000, true}, v.sink);
    CHECK_EQ(count_pattern(v.sink, Pattern::PmkidHarvest), 1u);
    CHECK_EQ(v.sink.got[0].threshold, 2u);
    CHECK((v.sink.got[0].shapes & shape::ReplayCounterRange) != 0);
    // Two unanswered starts with ordinary replay counters: nothing.
    Rig u; HandshakeDetector du(u.scope);
    u.feed(du, eapol(mac(0x00, 1), kPhone, false, 1, 1), meta(10000));
    u.feed(du, eapol(mac(0x00, 2), kPhone, false, 2, 1), meta(10100));
    du.on_tick(Instant{epoch(), 12000, true}, u.sink);
    CHECK_EQ(u.sink.count, 0u);
}

GUARDIAN_CASE(handshake_inside_the_bait_window_after_shaped_disconnects) {
    // Three frames with the fixed sequence push one station off the selected network; its handshake follows 20 s later.
    Rig r; HandshakeDetector d(r.scope);
    for (std::uint32_t i = 0; i < 3; ++i) r.feed(d, disconnect(kHome, kPhone, kHome, kToolDeauth), meta(10000 + i * 100));
    r.feed(d, eapol(kHome, kPhone, false, 1), meta(30000));
    r.feed(d, eapol(kHome, kPhone, true, 1), meta(30020));
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthHandshake), 1u);
    const auto& o = r.sink.got[0];
    CHECK_EQ(o.scope, IncidentScope::Network);
    CHECK_EQ(o.threshold, 3u);
    CHECK((o.shapes & shape::DisconnectFixedSequence) != 0);
    CHECK((o.shapes & shape::HandshakeAfterForgery) != 0);
    // Three ordinary disconnect frames, handshake 20 s later: nothing (below 5, and outside the 8 s rule).
    Rig q; HandshakeDetector dq(q.scope);
    for (std::uint32_t i = 0; i < 3; ++i) { Disc x{}; x.seq = 41 * i + 3; q.feed(dq, disconnect(kHome, kPhone, kHome, x), meta(10000 + i * 100)); }
    q.feed(dq, eapol(kHome, kPhone, false, 1), meta(30000)); q.feed(dq, eapol(kHome, kPhone, true, 1), meta(30020));
    CHECK_EQ(q.sink.count, 0u);
    // Five ordinary frames, handshake 20 s later: still outside the unshaped 8 s rule.
    Rig u; HandshakeDetector du(u.scope);
    for (std::uint32_t i = 0; i < 5; ++i) { Disc x{}; x.seq = 41 * i + 3; u.feed(du, disconnect(kHome, kPhone, kHome, x), meta(10000 + i * 100)); }
    u.feed(du, eapol(kHome, kPhone, false, 1), meta(30000)); u.feed(du, eapol(kHome, kPhone, true, 1), meta(30020));
    CHECK_EQ(u.sink.count, 0u);
    // Shaped frames, but the handshake comes 40 s later: outside the bait window.
    Rig w; HandshakeDetector dw(w.scope);
    for (std::uint32_t i = 0; i < 3; ++i) w.feed(dw, disconnect(kHome, kPhone, kHome, kToolDeauth), meta(10000 + i * 100));
    w.feed(dw, eapol(kHome, kPhone, false, 1), meta(50300)); w.feed(dw, eapol(kHome, kPhone, true, 1), meta(50320));
    CHECK_EQ(w.sink.count, 0u);
}

// =========================================================================================
// The same-name watch is on for every picked network; the owner approves their own other APs
// =========================================================================================
GUARDIAN_CASE(picking_a_network_turns_the_same_name_watch_on) {
    Home h;
    h.companion.boot();
    h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    h.companion.tick();
    pick(h.companion, home_network(), Action::Secondary);
    CHECK(h.monitor.scope().has_selection());
    CHECK(h.monitor.scope().selected().watch_impostors);
    CHECK(h.companion.impostor_watch());
    // Another device starts using that name: red, in the ledger's words.
    for (int i = 0; i < 6; ++i) {
        h.clock.at += 100;
        h.companion.receive(packet(beacon(kHome, "home"), h.clock));
        h.companion.receive(packet(beacon(random_mac(55), "home"), h.clock));
    }
    h.companion.tick();
    const auto& v = h.companion.presenter().view();
    CHECK(v.alert);
    CHECK_EQ(v.incident.kind, IncidentKind::UnexpectedAp);
    CHECK_EQ(std::string(v.alert_reason), "Another device is using your network's name");
    // The persisted record carries the watch, so it survives a reboot.
    PersistedSelection stored{};
    CHECK(h.store.load(stored));
    CHECK(stored.selected.watch_impostors);
}

GUARDIAN_CASE(watch_off_keeps_the_previous_behaviour) {
    Home h;
    h.companion.set_impostor_watch(false);
    h.companion.boot();
    h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    h.companion.tick();
    pick(h.companion, home_network(), Action::Secondary);
    CHECK(h.monitor.scope().has_selection());
    CHECK(!h.monitor.scope().selected().watch_impostors);
    for (int i = 0; i < 6; ++i) {
        h.clock.at += 100;
        h.companion.receive(packet(beacon(kHome, "home"), h.clock));
        h.companion.receive(packet(beacon(random_mac(55), "home"), h.clock));
    }
    h.companion.tick();
    CHECK(!h.companion.presenter().view().alert);
    // Turning it on later watches the current selection at once and saves it.
    const unsigned writes = h.blob.writes;
    h.companion.set_impostor_watch(true);
    CHECK(h.monitor.scope().selected().watch_impostors);
    CHECK(h.blob.writes > writes);
}

GUARDIAN_CASE(a_restored_selection_from_before_is_upgraded_to_watched_and_saved) {
    Clock clock; MemoryBlob blob; companion::EncodedSelectionStore store{blob};
    { ApprovedScope old; ApprovedAp home{}; home.network = home_network(); CHECK(old.select(home)); CHECK(store.save(persist(old))); }
    PersistedSelection before{}; CHECK(store.load(before)); CHECK(!before.selected.watch_impostors);
    Monitor monitor{clock, profiles::all_2g4_channels(), Origin::LiveRadio};
    Companion c{clock, monitor, store, lcd(), Origin::LiveRadio};
    CHECK_EQ(c.boot(), companion::StoreState::Restored);
    CHECK(monitor.scope().selected().watch_impostors);
    PersistedSelection after{}; CHECK(store.load(after)); CHECK(after.selected.watch_impostors);
    CHECK(after.selected.network == home_network());
}

GUARDIAN_CASE(approve_this_ap_from_the_picker_feeds_the_approved_set) {
    Home h;
    h.companion.boot();
    const Mac node = mac(0x00, 77);
    h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    h.companion.receive(packet(beacon(node, "home"), h.clock, -60));
    h.companion.receive(packet(beacon(kNeighbour, "cafe"), h.clock, -70));
    h.companion.tick();
    pick(h.companion, home_network(), Action::Secondary);
    // Holding the primary key on another network's row does nothing.
    pick(h.companion, network(kNeighbour, "cafe"), Action::PrimaryLong);
    CHECK_EQ(h.monitor.scope().approved_count(), 0u);
    // Holding it on the same-name row approves that AP (and it is saved).
    const unsigned writes = h.blob.writes;
    pick(h.companion, network(node, "home"), Action::PrimaryLong);
    CHECK_EQ(h.monitor.scope().approved_count(), 1u);
    CHECK(h.monitor.scope().in_scope(node));
    CHECK(h.blob.writes > writes);
    { companion::Frame f{}; companion::Status st{}; st.radio = companion::RadioState::Monitoring;
      h.companion.render(st, f);
      CHECK(has(f, "hold blue: not mine"));        // the highlighted row is now approved: the same key takes it back
      CHECK_EQ(f.overflow, 0u); }
    h.companion.input(Action::SecondaryLong);   // leave the list
    // The approved AP beaconing the name raises nothing.
    for (int i = 0; i < 6; ++i) {
        h.clock.at += 100;
        h.companion.receive(packet(beacon(kHome, "home"), h.clock));
        h.companion.receive(packet(beacon(node, "home"), h.clock, -60));
    }
    h.companion.tick();
    CHECK(!h.companion.presenter().view().alert);
    // Holding it again takes the approval back.
    pick(h.companion, network(node, "home"), Action::PrimaryLong);
    CHECK_EQ(h.monitor.scope().approved_count(), 0u);
}

GUARDIAN_CASE(the_picker_offers_the_approval_only_on_a_same_name_row) {
    Home h;
    h.companion.boot();
    const Mac node = mac(0x00, 77);
    h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    h.companion.receive(packet(beacon(node, "home"), h.clock, -60));
    h.companion.receive(packet(beacon(kNeighbour, "cafe"), h.clock, -70));
    h.companion.tick();
    pick(h.companion, home_network(), Action::Secondary);
    companion::Status st{}; st.radio = companion::RadioState::Monitoring;
    h.companion.input(Action::SecondaryLong);
    for (int i = 0; i < 6; ++i) {
        companion::Frame f{}; h.companion.render(st, f);
        const auto& v = h.companion.presenter().picker();
        const auto& e = v.entries[v.cursor];
        CHECK_EQ(has(f, "hold blue: my AP"), e.approvable && !e.approved);
        CHECK_EQ(f.overflow, 0u);
        h.companion.input(Action::Primary);
    }
}

// =========================================================================================
// Wording: what was seen, never a tool, never a person
// =========================================================================================
GUARDIAN_CASE(tool_shape_wording_never_names_a_tool) {
    CHECK_EQ(std::string(tool_shape_text(0)), "");
    CHECK_EQ(std::string(tool_shape_text(shape::DisconnectFixedSequence)), "looks like a known attack tool");
    CHECK_EQ(std::string(tool_shape_text(shape::TemplateAddress | shape::StaticTimestamp)), "looks like a known attack tool");
    static constexpr const char* names[] = {"marauder", "bruce", "flipper", "pwnagotchi", "evil", "hcx", "aireplay", "mdk", "bettercap",
                                            "ghost", "cardputer", "hacker", "attacker", "cracked"};
    const auto clean = [&](const char* text) {
        std::string lower(text);
        for (auto& c : lower) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        for (const char* n : names) if (lower.find(n) != std::string::npos) return false;
        return true;
    };
    for (unsigned p = 0; p < static_cast<unsigned>(Pattern::Count); ++p) {
        IncidentObservation o{}; o.pattern = static_cast<Pattern>(p); o.scope = IncidentScope::Area;
        CHECK(clean(area_text(o)));
        CHECK(clean(network_pattern_text(o.pattern)));
        CHECK(clean(measurement::pattern_key(o.pattern)));
    }
    for (unsigned k = 0; k < static_cast<unsigned>(IncidentKind::Count); ++k) CHECK(clean(alert_text(static_cast<IncidentKind>(k))));
    // The new patterns have their own words, a unit and a STATUS / JSON key.
    for (Pattern p : {Pattern::KarmaAnswer, Pattern::LurePortal, Pattern::NoiseFloor}) {
        IncidentObservation o{}; o.pattern = p; o.scope = IncidentScope::Area;
        const std::string text = area_text(o);
        CHECK(text.size() > 10);
        CHECK(text.rfind("nearby") == text.size() - 6);
        CHECK(std::strlen(area_unit(o)) > 0);
        CHECK(std::strlen(network_pattern_text(p)) > 10);
        CHECK(std::strcmp(measurement::pattern_key(p), "?") != 0);
        CHECK(std::strcmp(measurement::pattern_key(p), "none") != 0);
    }
    CHECK_EQ(std::string(alert_text(IncidentKind::UnexpectedAp)), "Another device is using your network's name");
}

GUARDIAN_CASE(a_shaped_alert_says_so_on_the_face_and_in_the_details) {
    Home h;
    h.companion.boot();
    h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    h.companion.tick();
    pick(h.companion, home_network(), Action::Secondary);
    for (int i = 0; i < 12; ++i) {
        h.clock.at += 300;
        h.companion.receive(packet(beacon(kHome, "home"), h.clock));
        h.companion.receive(packet(disconnect(kHome, kBroadcast, kHome, kToolDeauth), h.clock));
    }
    h.companion.tick();
    const auto& v = h.companion.presenter().view();
    CHECK(v.alert);
    CHECK_EQ(v.incident.kind, IncidentKind::DisconnectBurst);
    CHECK((v.incident.shapes & shape::DisconnectFixedSequence) != 0);
    CHECK_EQ(v.incident.threshold, 10u);
    companion::Status st{}; st.radio = companion::RadioState::Monitoring;
    companion::Frame face{}; h.companion.render(st, face);
    CHECK(joined(face).find("looks like a known attack tool") != std::string::npos);
    CHECK_EQ(face.overflow, 0u);
    // An unshaped burst never carries the sentence.
    Home q;
    q.companion.boot();
    q.companion.receive(packet(beacon(kHome, "home"), q.clock));
    q.companion.tick();
    pick(q.companion, home_network(), Action::Secondary);
    for (std::uint32_t i = 0; i < 24; ++i) {
        q.clock.at += 300;
        q.companion.receive(packet(beacon(kHome, "home"), q.clock));
        Disc x{}; x.seq = 31 * i + 2;
        q.companion.receive(packet(disconnect(kHome, mac(0x3c, i), kHome, x), q.clock));
    }
    q.companion.tick();
    CHECK(q.companion.presenter().view().alert);
    companion::Frame plain{}; q.companion.render(st, plain);
    CHECK(joined(plain).find("attack tool") == std::string::npos);
}

// =========================================================================================
// Honesty on the glass: the blind spots are printed
// =========================================================================================
namespace {
// The Details page "What it cannot see" of a companion locked on channel 6.
std::string coverage_page(Home& h, companion::HandshakeWatch watch, bool sweep, std::uint8_t* overflow = nullptr) {
    companion::Status st{}; st.radio = companion::RadioState::Monitoring; st.handshake = watch; st.area_sweep = sweep;
    CoverageReport c{}; c.sampled_at = Instant{epoch(), h.clock.at, true}; c.channel = 6; c.window_ms = 1000; c.listened_ms = 1000;
    c.passive_receive = Support::Supported;
    h.monitor.coverage(c);
    h.companion.tick();
    while (h.companion.presenter().screen() != Screen::Details) h.companion.input(Action::Primary);
    for (int i = 0; i < 12 && h.companion.presenter().details().page != DetailsPage::Limits; ++i) h.companion.input(Action::Primary);
    companion::Frame f{}; h.companion.render(st, f);
    if (overflow) *overflow = f.overflow;
    for (std::uint8_t i = 0; i < f.count; ++i) if (std::strlen(f.lines[i].text.data()) > static_cast<std::size_t>(companion::Frame::cols1) && f.lines[i].scale == 1 && overflow) *overflow = 99;
    while (h.companion.presenter().screen() != Screen::Face) h.companion.input(Action::Secondary);
    return joined(f);
}
} // namespace

GUARDIAN_CASE(details_print_what_the_radio_cannot_see) {
    Home h;
    h.companion.boot();
    h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    h.companion.tick();
    pick(h.companion, home_network(), Action::Secondary);
    h.clock.at += 100; h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    std::uint8_t overflow = 0;
    std::string page = coverage_page(h, companion::HandshakeWatch::Off, false, &overflow);
    CHECK(page.find("2.4 GHz, channel 6 only, no 5 GHz, passive") != std::string::npos);
    CHECK(page.find("handshake watch: off") != std::string::npos);
    CHECK(page.find("(load)") == std::string::npos);
    CHECK_EQ(overflow, 0u);
    page = coverage_page(h, companion::HandshakeWatch::OffLoad, false, &overflow);
    CHECK(page.find("handshake watch: off (load)") != std::string::npos);
    CHECK_EQ(overflow, 0u);
    page = coverage_page(h, companion::HandshakeWatch::On, false, &overflow);
    CHECK(page.find("handshake watch: on") != std::string::npos);
    CHECK(page.find("handshake watch: off") == std::string::npos);
    // With the area sweep on, "only" would be untrue.
    page = coverage_page(h, companion::HandshakeWatch::Off, true, &overflow);
    CHECK(page.find("channel 6 only") == std::string::npos);
    CHECK(page.find("2.4 GHz, channel 6 + area sweep, no 5 GHz, passive") != std::string::npos);
    CHECK_EQ(overflow, 0u);
}

// G16N: what guarding with the screen off costs is printed, from the measured drain only.
GUARDIAN_CASE(details_print_the_dark_guard_from_the_measured_drain) {
    Home h;
    h.companion.boot();
    h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    h.companion.tick();
    pick(h.companion, home_network(), Action::Secondary);
    h.clock.at += 100; h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    const auto page_with = [&](companion::DarkGuard g, std::uint16_t h10, std::uint8_t& overflow) {
        companion::Status st{}; st.radio = companion::RadioState::Monitoring; st.dark_guard = g; st.dark_guard_h10 = h10;
        h.companion.tick();
        while (h.companion.presenter().screen() != Screen::Details) h.companion.input(Action::Primary);
        for (int i = 0; i < 12 && h.companion.presenter().details().page != DetailsPage::Limits; ++i) h.companion.input(Action::Primary);
        companion::Frame f{}; h.companion.render(st, f);
        overflow = f.overflow;
        for (std::uint8_t i = 0; i < f.count; ++i) if (std::strlen(f.lines[i].text.data()) > static_cast<std::size_t>(companion::Frame::cols1) && f.lines[i].scale == 1) overflow = 99;
        while (h.companion.presenter().screen() != Screen::Face) h.companion.input(Action::Secondary);
        return joined(f);
    };
    std::uint8_t overflow = 0;
    std::string page = page_with(companion::DarkGuard::Hidden, 0, overflow);
    CHECK(page.find("dark guard") == std::string::npos);          // a host that says nothing prints nothing
    CHECK_EQ(overflow, 0u);
    page = page_with(companion::DarkGuard::Off, 0, overflow);
    CHECK(page.find("dark guard: off") != std::string::npos);
    CHECK_EQ(overflow, 0u);
    page = page_with(companion::DarkGuard::NotMeasured, 55, overflow);
    CHECK(page.find("dark guard: not measured yet") != std::string::npos);
    CHECK(page.find("h left") == std::string::npos);              // never a number without a measurement
    CHECK_EQ(overflow, 0u);
    page = page_with(companion::DarkGuard::Measured, 25, overflow);
    CHECK(page.find("dark guard: about 2 h left") != std::string::npos);   // whole hours, rounded down
    CHECK_EQ(overflow, 0u);
    page = page_with(companion::DarkGuard::Measured, 137, overflow);
    CHECK(page.find("dark guard: about 13 h left") != std::string::npos);
    CHECK_EQ(overflow, 0u);
    page = page_with(companion::DarkGuard::Measured, 9, overflow);
    CHECK(page.find("dark guard: under 1 h left") != std::string::npos);
    CHECK_EQ(overflow, 0u);
    // The rest of the page is still there (nothing was pushed off it).
    CHECK(page.find("handshake watch: off") != std::string::npos);
    CHECK(page.find("It says what it saw, never who sent it.") != std::string::npos);
}

GUARDIAN_CASE(a_noise_observation_prints_its_error_ratio_as_evidence_on_the_nearby_page) {
    Home h;
    h.companion.boot();
    h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    h.companion.tick();
    pick(h.companion, home_network(), Action::Secondary);
    const auto second = [&](int noise, std::uint32_t errors) {
        h.clock.at += 1000;
        ChannelLoadSample s{};
        s.sampled_at = Instant{epoch(), h.clock.at, true}; s.origin = Origin::LiveRadio; s.channel = 6;
        s.window_ms = 1000; s.listened_ms = 1000; s.valid_frames = 40 - errors; s.error_frames = errors; s.fcs_supported = errors > 0;
        s.noise_sum = noise * 40; s.noise_count = 40;
        h.monitor.channel_load(s);
        h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    };
    for (int i = 0; i < 30; ++i) second(-96, 0);
    for (int i = 0; i < 4; ++i) second(-85, 30);
    h.companion.tick();
    CHECK(h.companion.presenter().view().caution);
    CHECK(!h.companion.presenter().view().alert);
    companion::Status st{}; st.radio = companion::RadioState::Monitoring;
    while (h.companion.presenter().screen() != Screen::Details) h.companion.input(Action::Primary);
    for (int i = 0; i < 12 && h.companion.presenter().details().page != DetailsPage::Nearby; ++i) h.companion.input(Action::Primary);
    CHECK(h.companion.presenter().details().page == DetailsPage::Nearby);
    companion::Frame f{}; h.companion.render(st, f);
    const std::string page = joined(f);
    CHECK(page.find("Noise floor jumped on this channel nearby: 11 dB / 3 s") != std::string::npos);
    CHECK(page.find("channel 6: 120 of 160 frames had errors") != std::string::npos);   // evidence, never the rule
    CHECK_EQ(f.overflow, 0u);
    // Without checksum-failed delivery there is no error count to show: the line is absent, not "0 of N".
    Home q;
    q.companion.boot();
    q.companion.receive(packet(beacon(kHome, "home"), q.clock));
    q.companion.tick();
    pick(q.companion, home_network(), Action::Secondary);
    for (int i = 0; i < 34; ++i) {
        q.clock.at += 1000;
        ChannelLoadSample s{};
        s.sampled_at = Instant{epoch(), q.clock.at, true}; s.origin = Origin::LiveRadio; s.channel = 6;
        s.window_ms = 1000; s.listened_ms = 1000; s.valid_frames = 40; s.noise_sum = (i < 30 ? -96 : -85) * 40; s.noise_count = 40;
        q.monitor.channel_load(s);
        q.companion.receive(packet(beacon(kHome, "home"), q.clock));
    }
    q.companion.tick();
    while (q.companion.presenter().screen() != Screen::Details) q.companion.input(Action::Primary);
    for (int i = 0; i < 12 && q.companion.presenter().details().page != DetailsPage::Nearby; ++i) q.companion.input(Action::Primary);
    companion::Frame g{}; q.companion.render(st, g);
    CHECK(joined(g).find("Noise floor jumped") != std::string::npos);
    CHECK(joined(g).find("frames had errors") == std::string::npos);
    CHECK(joined(g).find("channel 6") != std::string::npos);
}

// =========================================================================================
// Hostile network names: never a crash, never a different rating, text clipped
// =========================================================================================
GUARDIAN_CASE(hostile_names_never_crash_never_change_the_rating_and_are_clipped) {
    const std::vector<std::string> names = {
        "%s%s%s%s%n%n%x%p",                                   // format directives
        "%99999999d%s",
        std::string(32, 'A'),                                  // the longest legal name
        std::string("\x1b[2J\x1b[H\r\nG14 STATUS alert=0", 26), // terminal control and a forged console line
        std::string("net\0work\0", 9),                         // NUL bytes inside
        "\xe2\x80\x8f\xe2\x80\xaegnp.exe",                    // right-to-left mark and override
        "\xff\xfe\xfd\xfc\x80\x81",                            // not UTF-8
        "\"}],\"alert\":false,{\"x\":\"",                      // JSON closing sequences
        "$(reboot);`id`|&<>",                                  // shell characters
        "\\x00\\n\\\\",                                        // backslashes
        "<script>alert(1)</script>",
        std::string(1, '\x7f') + "DEL" + std::string(1, '\x01'),
    };
    SecurityFrameParser parser;
    const auto ordinary = beacon(kHome, "home");
    const RxMeta m = meta(1000);
    const auto ordinary_parse = parser.parse(FrameSpan{ordinary.b.data(), static_cast<std::uint16_t>(ordinary.n), false}, m);
    const Mood expected = assess(observe_security(ordinary_parse, m)).mood;
    CHECK(expected != Mood::Unknown);
    for (std::size_t i = 0; i < names.size(); ++i) {
        const auto f = beacon(kHome, names[i]);
        const auto p = parser.parse(FrameSpan{f.b.data(), static_cast<std::uint16_t>(f.n), false}, m);
        CHECK_EQ(p.status, ParseStatus::Complete);
        CHECK_EQ(p.identity.ssid_size, names[i].size());
        CHECK_EQ(assess(observe_security(p, m)).mood, expected);          // the name never moves the rating
        const Label label = ssid_label(p.identity, p.ssid_kind);
        CHECK(label.length <= 32);
        CHECK(printable(label.c_str()));
        CHECK_EQ(std::strlen(label.c_str()), label.length);
        char escaped[160];
        measurement::escaped_ssid(p.identity, escaped, sizeof escaped);
        CHECK(printable(escaped));
        CHECK(std::strchr(escaped, '%') == nullptr || names[i].find('%') != std::string::npos);
    }
    // Every screen with every hostile name selected: printable, inside its row, nothing dropped.
    for (std::size_t i = 0; i < names.size(); ++i) {
        Home h;
        h.companion.boot();
        const Mac bssid = mac(0x00, 200 + static_cast<std::uint32_t>(i));
        h.companion.receive(packet(beacon(bssid, names[i]), h.clock));
        h.companion.receive(packet(beacon(kNeighbour, names[(i + 1) % names.size()]), h.clock, -70));
        h.companion.tick();
        pick(h.companion, network(bssid, names[i]), Action::Secondary);
        CHECK(h.monitor.scope().has_selection());
        h.clock.at += 100; h.companion.receive(packet(beacon(bssid, names[i]), h.clock));
        companion::Status st{}; st.radio = companion::RadioState::Monitoring;
        for (int screen = 0; screen < 8; ++screen) {
            companion::Frame f{}; h.companion.render(st, f);
            CHECK_EQ(f.overflow, 0u);
            for (std::uint8_t k = 0; k < f.count; ++k) {
                CHECK(printable(f.lines[k].text.data()));
                CHECK(std::strlen(f.lines[k].text.data()) <= static_cast<std::size_t>(f.lines[k].scale == 2 ? companion::Frame::cols2 : companion::Frame::cols1));
            }
            if (screen == 6) h.companion.input(Action::SecondaryLong); else h.companion.input(Action::Primary);
        }
        static char json[8192];   // the board's state_line size; G16H: 17 detector records with a hostile name passed 4096
        const auto n = h.monitor.json(json, sizeof json, 0, true, false);
        CHECK(n > 0);
        CHECK(printable(json));
        char status[4096];
        CHECK(h.monitor.status_text(status, sizeof status) > 0);
        CHECK(printable(status));
    }
    // A name element longer than 32 bytes is not a name: never Complete, never rated, never selectable.
    for (std::size_t len : {std::size_t{33}, std::size_t{64}, std::size_t{255}}) {
        Bytes f = header(8, kBroadcast, kHome, kHome);
        f.le64(0).u16(100).u16(0x0011);
        f.u8(0).u8(len); f.fill(len, '%');
        f.u8(3).u8(1).u8(6);
        const auto p = parser.parse(FrameSpan{f.b.data(), static_cast<std::uint16_t>(f.n), false}, m);
        CHECK(p.status != ParseStatus::Complete);
        CHECK_EQ(assess(observe_security(p, m)).mood, Mood::Unknown);
        CHECK(p.identity.ssid_size <= 32);
    }
    // A cut name element (claims 32 bytes, the frame ends after 5): Truncated or Malformed, never rated.
    {
        Bytes f = header(8, kBroadcast, kHome, kHome);
        f.le64(0).u16(100).u16(0x0011).u8(0).u8(32).fill(5, 'A');
        const auto p = parser.parse(FrameSpan{f.b.data(), static_cast<std::uint16_t>(f.n), false}, m);
        CHECK(p.status == ParseStatus::Malformed || p.status == ParseStatus::Truncated);
        CHECK_EQ(assess(observe_security(p, m)).mood, Mood::Unknown);
    }
}

GUARDIAN_CASE(hostile_names_through_every_detector_report_nothing_and_stay_bounded) {
    // 300 beacons and probe traffic with hostile names from ONE ordinary AP and one phone: no detector reports.
    Rig r; ThreatDetectors all(r.scope);
    const std::vector<std::string> names = {"%s%s%n", std::string(32, '%'), "\xe2\x80\xae" "evil", std::string("a\0b", 3), "\x1b[2J"};
    Millis t = 10000;
    std::uint64_t tsf = 4242424;
    for (std::uint32_t i = 0; i < 300; ++i, t += 100, tsf += 102400) {
        BeaconOptions o{}; o.tsf = tsf;
        const auto b = beacon(kNeighbour, names[0], o);
        const auto q = probe_request(kPhone, names[i % names.size()], (i & 0xfff) << 4);
        // The phone probes once every two seconds (an ordinary rate), each time for another hostile name.
        for (std::size_t k = 0; k < ThreatDetectors::count; ++k) { r.feed(*all.at(k), b, meta(t)); if (i % 20 == 0) r.feed(*all.at(k), q, meta(t + 9)); }
    }
    CHECK_EQ(r.sink.count, 0u);
}

// =========================================================================================
// TUNE
// =========================================================================================
GUARDIAN_CASE(new_limits_are_tune_keys_and_the_board_registry_fits) {
    std::vector<std::string> keys;
    for (std::size_t i = 0; i < tune::threat_key_count(); ++i) keys.emplace_back(tune::threat_key(i));
    const auto has_key = [&](const char* k) { for (const auto& x : keys) if (x == k) return true; return false; };
    for (const char* k : {"t.shape_frames", "t.shape_run", "t.tsf_static_beacons", "t.tsf_static_ms", "t.bait_ms", "t.karma_answer_ms",
                          "t.karma_answers", "t.karma_learn_ms", "t.lure_beacons", "t.noise_rise_db", "t.noise_average_ms",
                          "t.noise_hold_ms", "t.noise_min_frames", "t.noise_baseline_samples"})
        CHECK(has_key(k));
    for (const char* k : {"t.loss_errors", "t.loss_pdr_percent", "t.loss_rssi_min", "t.loss_recent_ms", "t.loss_window_ms"}) CHECK(!has_key(k));
    // The StickS3 registers 56 board keys before the t.* keys (the 44 of G16J, the four head.* of
    // G21, ota.auto_s, G16N's power.dark_s and power.dark_floor_pct, G16O's burst.still_dps,
    // burst.still_g, burst.calm_s and burst.max_s, and G16P's power.sleep_check_s;
    // firmware/boards/sticks3/main/measurement_main.cpp):
    // everything must fit. 56 + 68 = 124 of tune::max_params 128 (G16O raised it from 112 to 120;
    // G16H added the seven t.ble_* keys and raised it to 128).
    constexpr std::size_t board_keys = 56;
    CHECK(board_keys + tune::threat_key_count() <= tune::max_params);
    // A changed key reaches exactly its field and the detectors accept the defaults.
    MemoryBlob blob; tune::Registry reg(blob); tune::ThreatKeys tk{};
    CHECK(tune::add_threat_limits(reg, ThreatLimits{}, tk));
    const char* reason = nullptr;
    CHECK(reg.set("t.karma_answer_ms", 5000.0f, reason));
    CHECK(reg.set("t.noise_rise_db", 12.0f, reason));
    const auto l = tune::threat_limits_from(reg, tk, ThreatLimits{});
    CHECK_EQ(l.karma_answer_ms, 5000u);
    CHECK_EQ(l.noise_rise_db, 12u);
    CHECK_EQ(l.shape_run, ThreatLimits{}.shape_run);
    ApprovedScope scope; ThreatDetectors d(scope);
    CHECK(d.configure(l));
    ThreatLimits bad = l; bad.karma_answers = 0;
    CHECK(!d.configure(bad));
    bad = l; bad.noise_rise_db = 0;
    CHECK(!d.configure(bad));
    bad = l; bad.noise_hold_ms = 50;
    CHECK(!d.configure(bad));
    CHECK(d.configure(l));
}

// =========================================================================================
// The optional area sweep (TUNE detect.sweep_ms, default off)
// =========================================================================================
GUARDIAN_CASE(area_sweep_leaves_briefly_and_returns_without_losing_the_lock) {
    Survey s;
    CHECK(s.begin(1, 13, 6, 0));
    s.observed(6, 10);                       // an advertisement of the selected network: locked on 6
    CHECK(s.locked());
    // Off by default: never leaves.
    for (Millis t = 100; t < 4000; t += 50) { s.observed(6, t); CHECK_EQ(s.next(t), 6u); CHECK(!s.away()); }
    s.set_sweep(100, 2000);
    std::array<bool, 14> visited{};
    Millis away_ms = 0, total = 0;
    const Millis start = 4000;
    for (Millis t = start; t < start + 13 * 2000 + 1000; t += 10) {
        const auto ch = s.next(t);
        if (!s.away()) s.observed(6, t);     // the AP is heard whenever the radio is home
        CHECK(s.locked());                   // the excursion never drops the lock
        CHECK(ch >= 1 && ch <= 13);
        if (s.away()) { CHECK(ch != 6); visited[ch] = true; away_ms += 10; }
        else CHECK_EQ(ch, 6u);
        total += 10;
    }
    for (std::uint8_t ch = 1; ch <= 13; ++ch) CHECK_EQ(visited[ch], ch != 6);   // every other channel, round robin
    CHECK(away_ms * 100 >= total * 4 && away_ms * 100 <= total * 6);            // about 100 ms in every 2 s (5 %)
    CHECK_EQ(s.lock_losses(), 0u);
    // If the AP is truly gone, the 5 s silence rule still ends the lock (time away does not count as silence).
    Millis t = start + 13 * 2000 + 1000;
    for (; t < start + 13 * 2000 + 1000 + 9000 && s.locked(); t += 10) s.next(t);
    CHECK(!s.locked());
    CHECK(t - (start + 13 * 2000 + 1000) >= 5000);
    // dwell >= period, or dwell 0, switches it off.
    Survey o; CHECK(o.begin(1, 13, 6, 0)); o.observed(6, 10);
    o.set_sweep(2000, 2000);
    for (Millis k = 100; k < 9000; k += 50) { o.observed(6, k); CHECK_EQ(o.next(k), 6u); CHECK(!o.away()); }
    // Not locked (still searching): the sweep never interferes with discovery hopping.
    Survey d; CHECK(d.begin(1, 13, 1, 0)); d.set_sweep(100, 2000);
    for (Millis k = 0; k < 9000; k += 50) { d.next(k); CHECK(!d.away()); }
}

// =========================================================================================
// G16R: the picked network is its NAME, not one address (TDD: written and run RED first
// against the stub stage of ApprovedScope::hear / in_network; logs in
// $GUARDIAN_STORE/builds/20261118-g16r-tdd/red-coverage_check.log).
// Every name and address below is synthetic. Nothing is configured: what belongs to the
// picked name is learned from the advertisements the scope hears.
// =========================================================================================
namespace {
// What the owner of the scope does with every received frame (Monitor::receive, the lab engine).
bool hear(Rig& r, const Bytes& f, Millis at) { const auto m = meta(at); return r.scope.hear(m, r.parse(f, m)); }
// `frames` broadcast disconnect frames naming the access point `bssid`, 100 ms apart, unrelated sequence numbers.
void burst(Rig& r, FrameDetector& red, FrameDetector& area, const Mac& bssid, Millis from, std::uint32_t frames = 20, bool disassoc = false) {
    for (std::uint32_t i = 0; i < frames; ++i) {
        Disc d{}; d.seq = 41 * i + 3; d.disassoc = disassoc;
        const auto f = disconnect(bssid, kBroadcast, bssid, d);
        r.feed(red, f, meta(from + i * 100));
        r.feed(area, f, meta(from + i * 100));
    }
}
void burst(Monitor& m, Clock& clock, const Mac& bssid, std::uint32_t frames = 20) {
    for (std::uint32_t i = 0; i < frames; ++i) {
        clock.at += 100;
        Disc d{}; d.seq = 41 * i + 3;
        m.receive(packet(disconnect(bssid, kBroadcast, bssid, d), clock));
    }
}
constexpr std::size_t kBurst = static_cast<std::size_t>(IncidentKind::DisconnectBurst);
constexpr std::size_t kUnexpected = static_cast<std::size_t>(IncidentKind::UnexpectedAp);
} // namespace

GUARDIAN_CASE(g16r_a_burst_against_a_second_address_of_the_picked_name_is_a_network_incident) {
    const Mac second = mac(0x00, 77);
    for (const bool disassoc : {false, true}) {
        Rig r; DisconnectDetector red(r.scope, DetectorLimits{}); AreaDisconnectDetector area(r.scope);
        // The stick hears the picked name from the picked address and from a second one. Nobody approved it.
        CHECK(!hear(r, beacon(kHome, "home"), 1000));     // the picked address is the network already: no entry
        CHECK(hear(r, beacon(second, "home"), 1010));
        CHECK(r.scope.same_name(second));
        CHECK(r.scope.in_network(second));
        CHECK(!r.scope.in_scope(second));                 // heard is not approved
        burst(r, red, area, second, 2000, 20, disassoc);
        CHECK_EQ(count_kind(r.sink, IncidentKind::DisconnectBurst), 1u);
        CHECK_EQ(r.sink.count, 1u);                       // red only: nothing amber beside it
        const auto& o = r.sink.got[0];
        CHECK_EQ(o.scope, IncidentScope::Network);
        CHECK(o.affected == home_network());              // about the picked network ...
        CHECK(o.bssid == second);                         // ... the address the frames named is evidence
        CHECK_EQ(o.count, 20u);
        CHECK_EQ(red.stats().in_scope, 20u);
        CHECK_EQ(red.stats().out_of_scope, 0u);
    }
}

GUARDIAN_CASE(g16r_a_burst_against_another_name_stays_nearby) {
    Rig r; DisconnectDetector red(r.scope, DetectorLimits{}); AreaDisconnectDetector area(r.scope);
    CHECK(!hear(r, beacon(kHome, "home"), 1000));
    CHECK(!hear(r, beacon(kNeighbour, "cafe"), 1010));
    CHECK_EQ(r.scope.same_name_count(), 0u);
    CHECK(!r.scope.in_network(kNeighbour));
    burst(r, red, area, kNeighbour, 2000);
    CHECK_EQ(count_kind(r.sink, IncidentKind::DisconnectBurst), 0u);
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthBroadcast), 1u);
    CHECK(r.sink.count >= 1u);
    for (std::size_t i = 0; i < r.sink.count && i < r.sink.got.size(); ++i) CHECK_EQ(r.sink.got[i].scope, IncidentScope::Area);
    CHECK_EQ(red.stats().in_scope, 0u);
    CHECK_EQ(red.stats().out_of_scope, 20u);
    // An address the stick never heard under the picked name is not the network either.
    Rig q; DisconnectDetector qred(q.scope, DetectorLimits{}); AreaDisconnectDetector qarea(q.scope);
    burst(q, qred, qarea, mac(0x00, 80), 2000);
    CHECK_EQ(count_kind(q.sink, IncidentKind::DisconnectBurst), 0u);
    CHECK_EQ(count_pattern(q.sink, Pattern::DeauthBroadcast), 1u);
}

GUARDIAN_CASE(g16r_the_same_name_set_is_learned_only_from_advertisements_of_the_exact_name) {
    Rig r;
    const Mac a = mac(0x00, 81), b = mac(0x00, 82), c = mac(0x00, 83);
    CHECK_EQ(r.scope.same_name_count(), 0u);
    CHECK(hear(r, beacon(a, "home"), 1000));                       // a beacon
    CHECK(hear(r, probe_response(b, "home", kPhone), 1010));      // a probe response
    CHECK_EQ(r.scope.same_name_count(), 2u);
    CHECK(r.scope.same_name(a));
    CHECK(r.scope.same_name(b));
    CHECK(hear(r, beacon(a, "home"), 1100));                       // heard again: the same entry
    CHECK_EQ(r.scope.same_name_count(), 2u);
    // Not learned: a device ASKING for the name, other frame kinds, other names, a hidden name,
    // bytes the receiver did not vouch for, addresses that cannot be an access point.
    CHECK(!hear(r, probe_request(kPhone, "home"), 1200));
    CHECK(!hear(r, disconnect(c, kBroadcast, c), 1210));
    CHECK(!hear(r, beacon(c, "home2"), 1220));
    CHECK(!hear(r, beacon(c, "hom"), 1230));
    CHECK(!hear(r, beacon(c, "Home"), 1240));
    CHECK(!hear(r, beacon(c, ""), 1250));
    { auto m = meta(1260); m.status = RxStatus::FcsError; CHECK(!r.scope.hear(m, r.parse(beacon(c, "home"), m))); }
    { auto m = meta(1270); m.status = RxStatus::Unknown; CHECK(!r.scope.hear(m, r.parse(beacon(c, "home"), m))); }
    CHECK(!hear(r, beacon(Mac{0x01, 0x10, 0, 0, 0, 0x01}, "home"), 1280));   // a group address
    CHECK(!hear(r, beacon(Mac{}, "home"), 1290));                              // all zero
    CHECK_EQ(r.scope.same_name_count(), 2u);
    CHECK(!r.scope.in_network(c));
    CHECK(!r.scope.in_network(kPhone));
    CHECK(!r.scope.in_network(Mac{}));
    // The picked and the approved addresses are the network already and take no entry.
    ApprovedAp node{}; node.network = network(c, "home");
    CHECK(r.scope.approve(node));
    CHECK(!hear(r, beacon(c, "home"), 1300));
    CHECK(!hear(r, beacon(kHome, "home"), 1310));
    CHECK_EQ(r.scope.same_name_count(), 2u);
    CHECK(r.scope.in_network(c));
    CHECK(r.scope.in_network(kHome));
    // Approving a learned address moves it to the approved list (its entry is free again).
    ApprovedAp mine{}; mine.network = network(a, "home");
    CHECK(r.scope.approve(mine));
    CHECK(!r.scope.same_name(a));
    CHECK(r.scope.in_network(a));
    CHECK_EQ(r.scope.same_name_count(), 1u);
    // Taking the approval back: not the network until it is heard under the name again.
    CHECK(r.scope.revoke(a));
    CHECK(!r.scope.in_network(a));
    CHECK(hear(r, beacon(a, "home"), 1400));
    CHECK(r.scope.in_network(a));
    // Without a picked network nothing is learned; a picked hidden network has no name to match.
    ApprovedScope none;
    { const auto m = meta(1500); CHECK(!none.hear(m, r.parse(beacon(a, "home"), m))); }
    CHECK_EQ(none.same_name_count(), 0u);
    CHECK(!none.in_network(a));
    ApprovedScope hidden; ApprovedAp h{}; h.network = network(kHome, "");
    CHECK(hidden.select(h));
    { const auto m = meta(1600); CHECK(!hidden.hear(m, r.parse(beacon(a, ""), m))); }
    CHECK_EQ(hidden.same_name_count(), 0u);
}

GUARDIAN_CASE(g16r_the_same_name_set_holds_eight_replaces_the_one_heard_longest_ago_and_is_cleared_on_a_new_pick) {
    Rig r;
    CHECK_EQ(ApprovedScope::same_name_capacity, 8u);
    for (std::uint32_t i = 0; i < 8; ++i) CHECK(hear(r, beacon(mac(0x00, 100 + i), "home"), 1000 + i));
    CHECK_EQ(r.scope.same_name_count(), 8u);
    CHECK_EQ(r.scope.same_name_evictions(), 0u);
    CHECK(hear(r, beacon(mac(0x00, 100), "home"), 1100));          // the first address is heard again
    CHECK(hear(r, beacon(mac(0x00, 108), "home"), 1200));          // a ninth address
    CHECK_EQ(r.scope.same_name_count(), 8u);
    CHECK_EQ(r.scope.same_name_evictions(), 1u);
    CHECK(r.scope.same_name(mac(0x00, 100)));                      // heard a moment ago: kept
    CHECK(!r.scope.same_name(mac(0x00, 101)));                     // heard longest ago: replaced
    CHECK(r.scope.same_name(mac(0x00, 108)));
    for (std::uint32_t i = 2; i < 8; ++i) CHECK(r.scope.same_name(mac(0x00, 100 + i)));
    std::size_t listed = 0;
    for (std::size_t i = 0; i < ApprovedScope::same_name_capacity; ++i) {
        const Mac* m = r.scope.same_name_at(i);
        if (m) { ++listed; CHECK(r.scope.same_name(*m)); }
    }
    CHECK_EQ(listed, 8u);
    CHECK(r.scope.same_name_at(ApprovedScope::same_name_capacity) == nullptr);
    // Many more addresses under the name never grow it.
    for (std::uint32_t i = 0; i < 100; ++i) hear(r, beacon(random_mac(500 + i), "home"), 2000 + i);
    CHECK_EQ(r.scope.same_name_count(), 8u);
    CHECK_EQ(r.scope.same_name_evictions(), 101u);
    // Approving the baseline or switching the watch re-selects the SAME identity: the set is kept.
    ApprovedAp same = r.scope.selected(); same.watch_impostors = true;
    CHECK(r.scope.select(same));
    CHECK_EQ(r.scope.same_name_count(), 8u);
    // A new pick starts clean: another name ...
    ApprovedAp cafe{}; cafe.network = network(kNeighbour, "cafe");
    CHECK(r.scope.select(cafe));
    CHECK_EQ(r.scope.same_name_count(), 0u);
    CHECK_EQ(r.scope.same_name_evictions(), 0u);
    CHECK(!r.scope.in_network(mac(0x00, 100)));
    CHECK(!hear(r, beacon(mac(0x00, 100), "home"), 3000));         // the old name means nothing now
    CHECK(hear(r, beacon(mac(0x00, 120), "cafe"), 3010));
    CHECK(hear(r, beacon(mac(0x00, 121), "cafe"), 3020));
    CHECK_EQ(r.scope.same_name_count(), 2u);
    // ... another address of the same name ...
    ApprovedAp other{}; other.network = network(mac(0x00, 120), "cafe");
    CHECK(r.scope.select(other));
    CHECK_EQ(r.scope.same_name_count(), 0u);
    // ... and clear().
    CHECK(hear(r, beacon(kNeighbour, "cafe"), 3100));
    r.scope.clear();
    CHECK_EQ(r.scope.same_name_count(), 0u);
    CHECK(!r.scope.in_network(kNeighbour));
}

GUARDIAN_CASE(g16r_the_monitor_learns_from_the_air_alerts_red_and_reports_the_set_in_status) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    ApprovedAp picked{}; picked.network = home_network();       // watch off here: only the burst is under test
    CHECK(m.select(picked));
    const Mac second = mac(0x00, 77);
    for (int i = 0; i < 3; ++i) {
        clock.at += 100;
        m.receive(packet(beacon(kHome, "home"), clock));
        m.receive(packet(beacon(second, "home"), clock));
        m.receive(packet(beacon(kNeighbour, "cafe"), clock));
    }
    CHECK_EQ(m.scope().same_name_count(), 1u);
    CHECK(m.scope().in_network(second));
    CHECK(!m.scope().in_network(kNeighbour));
    char status[2048]{};
    CHECK(m.status_text(status, sizeof status) > 0);
    CHECK(std::string(status).find(" same_name=1 same_name_evicted=0") != std::string::npos);
    CHECK(!m.snapshot().incidents[kBurst]);
    burst(m, clock, second);
    const auto s = m.snapshot();
    CHECK(s.incidents[kBurst]);
    CHECK_EQ(s.evidence[kBurst].count, 20u);
    CHECK(s.evidence[kBurst].bssid == second);
    for (const bool visible : s.area_visible) CHECK(!visible);  // red only
    CHECK(m.view(s).alert);
    CHECK(m.status_text(status, sizeof status) > 0);
    CHECK(std::string(status).find("detectors=disconnect:frames=29,in_window=20,events=20,incidents=1,") != std::string::npos);
    // The same burst against another name: amber, and the red count does not move.
    Monitor n(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    CHECK(n.select(picked));
    for (int i = 0; i < 3; ++i) {
        clock.at += 100;
        n.receive(packet(beacon(kHome, "home"), clock));
        n.receive(packet(beacon(kNeighbour, "cafe"), clock));
    }
    burst(n, clock, kNeighbour);
    const auto t = n.snapshot();
    CHECK(!t.incidents[kBurst]);
    bool amber = false;
    for (const bool visible : t.area_visible) amber = amber || visible;
    CHECK(amber);
    CHECK(!n.view(t).alert);
    CHECK(n.status_text(status, sizeof status) > 0);
    CHECK(std::string(status).find(" same_name=0 same_name_evicted=0") != std::string::npos);
    // Picking another network forgets the old name's addresses.
    CHECK(m.select(network(kNeighbour, "cafe")));
    CHECK_EQ(m.scope().same_name_count(), 0u);
    CHECK(!m.scope().in_network(second));
}

GUARDIAN_CASE(g16r_the_same_name_warning_and_the_red_burst_coexist) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    CHECK(m.select(home_network()));                             // the watch is on, as for every picked network
    const Mac twin = random_mac(55);
    for (int i = 0; i < 6; ++i) {
        clock.at += 100;
        m.receive(packet(beacon(kHome, "home"), clock));
        m.receive(packet(beacon(twin, "home"), clock));
    }
    auto s = m.snapshot();
    CHECK(s.incidents[kUnexpected]);                             // G16J: the warning keeps its own rule
    CHECK(!s.incidents[kBurst]);
    CHECK_EQ(std::string(m.view(s).alert_reason), "Another device is using your network's name");
    CHECK(!m.scope().in_scope(twin));                            // hearing it never approves it
    CHECK(m.scope().in_network(twin));
    burst(m, clock, twin);
    s = m.snapshot();
    CHECK(s.incidents[kUnexpected]);
    CHECK(s.incidents[kBurst]);
    CHECK(s.evidence[kBurst].bssid == twin);
    const auto v = m.view(s);
    CHECK(v.alert);
    CHECK_EQ(v.incident.kind, IncidentKind::DisconnectBurst);
    CHECK_EQ(v.incident.current, 2u);
    // The other address keeps being reported as unapproved for as long as it advertises the name.
    clock.at += 50000;
    for (int i = 0; i < 6; ++i) {
        clock.at += 100;
        m.receive(packet(beacon(kHome, "home"), clock));
        m.receive(packet(beacon(twin, "home"), clock));
    }
    s = m.snapshot();
    CHECK(s.incidents[kUnexpected]);
    CHECK(s.evidence[kUnexpected].acquired.at > clock.at - 1000);
}

GUARDIAN_CASE(g16r_every_network_scope_rule_reads_the_same_name_set) {
    const Mac second = mac(0x00, 77);
    // Many disconnect frames to one device inside a second.
    Rig r; AreaDisconnectDetector area(r.scope);
    CHECK(hear(r, beacon(second, "home"), 1000));
    for (std::uint32_t i = 0; i < 12; ++i) { Disc d{}; d.seq = 41 * i + 3; r.feed(area, disconnect(second, kPhone, second, d), meta(2000 + i * 50)); }
    CHECK_EQ(r.sink.count, 1u);
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthPair), 1u);
    CHECK_EQ(r.sink.got[0].scope, IncidentScope::Network);
    CHECK_EQ(r.sink.got[0].kind, IncidentKind::NetworkPattern);
    CHECK(r.sink.got[0].affected == home_network());
    // A channel-switch order with count 255 in that address's own beacon; the same from another name is nearby.
    BeaconOptions order{}; order.csa_count = 255;
    Rig c; ChannelSwitchDetector cs(c.scope);
    CHECK(hear(c, beacon(second, "home", order), 1000));
    c.feed(cs, beacon(second, "home", order), meta(1000));
    CHECK_EQ(count_pattern(c.sink, Pattern::ChannelSwitch), 1u);
    CHECK_EQ(c.sink.got[0].scope, IncidentScope::Network);
    Rig n; ChannelSwitchDetector ns(n.scope);
    CHECK(!hear(n, beacon(kNeighbour, "cafe", order), 1000));
    n.feed(ns, beacon(kNeighbour, "cafe", order), meta(1000));
    CHECK_EQ(count_pattern(n.sink, Pattern::ChannelSwitch), 1u);
    CHECK_EQ(n.sink.got[0].scope, IncidentScope::Area);
    // Devices pushed off that address, then a fresh handshake with it.
    Rig h; HandshakeDetector hs(h.scope);
    CHECK(hear(h, beacon(second, "home"), 1000));
    for (std::uint32_t i = 0; i < 5; ++i) { Disc x{}; x.seq = 41 * i + 3; h.feed(hs, disconnect(second, kPhone, second, x), meta(10000 + i * 100)); }
    h.feed(hs, eapol(second, kPhone, false, 1), meta(11000));
    h.feed(hs, eapol(second, kPhone, true, 1), meta(11020));
    CHECK_EQ(count_pattern(h.sink, Pattern::DeauthHandshake), 1u);
    CHECK_EQ(h.sink.got[0].scope, IncidentScope::Network);
}

GUARDIAN_CASE(g16r_the_glass_names_the_network_in_red_never_an_address) {
    Home h;
    h.companion.boot();
    h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    h.companion.tick();
    pick(h.companion, home_network(), Action::Secondary);
    const Mac second = mac(0x00, 77);
    for (std::uint32_t i = 0; i < 24; ++i) {
        h.clock.at += 100;
        h.companion.receive(packet(beacon(kHome, "home"), h.clock));
        h.companion.receive(packet(beacon(second, "home"), h.clock));
        Disc d{}; d.seq = 41 * i + 3;
        h.companion.receive(packet(disconnect(second, kBroadcast, second, d), h.clock));
    }
    h.companion.tick();
    const auto& v = h.companion.presenter().view();
    CHECK(v.alert);
    CHECK_EQ(v.incident.kind, IncidentKind::DisconnectBurst);
    CHECK(v.incident.bssid == second);
    char sentence[96]{};
    CHECK(alert_sentence(v, sentence, sizeof sentence) > 0);
    CHECK_EQ(std::string(sentence), "Disconnect burst on home");
    companion::Status st{}; st.radio = companion::RadioState::Monitoring;
    const std::string tail = mac_text(second).c_str() + 12;      // the last two bytes of the address the frames named
    for (int screen = 0; screen < 2; ++screen) {                 // the face, then the details
        companion::Frame f{}; h.companion.render(st, f);
        CHECK(has(f, "Disconnect burst on"));
        bool named = false;
        for (std::uint8_t i = 0; i < f.count; ++i) {
            const std::string text = f.lines[i].text.data();
            if (f.lines[i].color == color::red && text == "home") named = true;
            CHECK(text.find(tail) == std::string::npos);
            if (f.lines[i].color == color::red) CHECK(text.find(':') == std::string::npos);   // no address in red
        }
        CHECK(named);
        CHECK(!has(f, "Disconnect burst detected"));
        CHECK_EQ(f.overflow, 0u);
        h.companion.input(Action::Primary);                      // blue: info
    }
}

// =========================================================================================
// G16S: burst forensics. Who the frames of the last disconnect burst named, per scope:
// receiver / sender / BSSID / channel tuples with counts, in STATUS and on the Details
// screen (TDD: written and run RED first against the stub stage of BurstTrace, burst_text
// and the screens; logs in $GUARDIAN_STORE/builds/20261119-g16s-tdd/).
// Synthetic addresses and names only.
// =========================================================================================
namespace {
bool tuple_is(const BurstTuple& t, const Mac& to, const Mac& from, const Mac& bssid, unsigned channel, std::uint32_t count) {
    return t.receiver == to && t.sender == from && t.bssid == bssid && t.channel == channel && t.count == count;
}
std::string hex(const Mac& m) {
    char text[13]{};
    std::snprintf(text, sizeof text, "%02x%02x%02x%02x%02x%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    return text;
}
std::string tuple_text(const Mac& to, const Mac& from, const Mac& bssid, unsigned channel, unsigned count) {
    return hex(to) + "/" + hex(from) + "/" + hex(bssid) + "/" + std::to_string(channel) + ":" + std::to_string(count);
}
std::string burst_status(const Monitor& m) {
    char text[Monitor::burst_text_max]{};
    return m.burst_text(text, sizeof text) ? std::string(text) : std::string("<refused>");
}
std::string tail(const Mac& m) { return mac_text(m).c_str() + 12; }   // the last two bytes as the glass prints them
Instant instant(Millis at) { return Instant{epoch(), at, true}; }
std::size_t count_of(const std::string& text, char c) { std::size_t n = 0; for (char x : text) n += x == c; return n; }
} // namespace

GUARDIAN_CASE(g16s_the_burst_table_slides_before_a_burst_and_keeps_the_whole_burst_after) {
    constexpr Millis w = 10000;
    const Mac a = mac(0x00, 1), b = mac(0x00, 2), ap = mac(0x00, 3);
    BurstTrace t;
    CHECK(!t.last(1000, w).known);
    CHECK_EQ(t.top(1000, w).count, 0u);
    // Before a burst: the counts of the current window, and old frames leave by themselves.
    t.seen(kBroadcast, a, ap, 6, 1000, w);
    t.seen(kBroadcast, a, ap, 6, 1100, w);
    t.seen(b, a, ap, 6, 1200, w);
    CHECK(tuple_is(t.top(1200, w), kBroadcast, a, ap, 6, 2));
    CHECK(!t.last(1200, w).known);                              // no threshold reached: nothing to report
    CHECK_EQ(t.top(1200 + 2 * w, w).count, 0u);                 // two windows later nothing is left
    t.seen(b, a, ap, 6, 30000, w);
    CHECK(tuple_is(t.top(30000, w), b, a, ap, 6, 1));           // the three old frames are gone
    // A burst: the threshold is reached at 30300. The record holds the frames of the window ...
    t.seen(kBroadcast, a, ap, 6, 30100, w);
    t.seen(kBroadcast, a, ap, 6, 30200, w);
    t.seen(kBroadcast, a, ap, 11, 30300, w);                    // the same addresses on another channel: its own tuple
    t.incident(30300, w, Pattern::DeauthBroadcast);
    auto r = t.last(30300, w);
    CHECK(r.known);
    CHECK(r.open);
    CHECK_EQ(r.incident_at, Millis{30300});
    CHECK_EQ(r.rule, Pattern::DeauthBroadcast);
    CHECK_EQ(r.total, 4u);
    CHECK_EQ(r.unlisted, 0u);
    CHECK_EQ(unsigned(r.tuples), 3u);
    CHECK(tuple_is(r.top[0], kBroadcast, a, ap, 6, 2));
    CHECK(tuple_is(r.top[1], kBroadcast, a, ap, 11, 1));        // equal counts: heard most recently first
    CHECK(tuple_is(r.top[2], b, a, ap, 6, 1));
    CHECK(tuple_is(t.top(30300, w), kBroadcast, a, ap, 6, 2));
    // ... and every frame after it, for as long as the burst lasts (here longer than two windows).
    for (Millis at = 31000; at <= 55000; at += 1000) t.seen(b, a, ap, 6, at, w);   // 25 frames, 1 s apart
    r = t.last(55000, w);
    CHECK(r.open);
    CHECK_EQ(r.total, 29u);
    CHECK(tuple_is(r.top[0], b, a, ap, 6, 26));
    CHECK(tuple_is(r.top[1], kBroadcast, a, ap, 6, 2));         // the first frames did not age out of the record
    CHECK_EQ(r.incident_at, Millis{30300});
    // Reached again inside the same burst (another rule, or after a cooldown): still the one record.
    t.incident(55000, w, Pattern::DeauthSource);
    CHECK_EQ(t.last(55000, w).incident_at, Millis{30300});
    CHECK_EQ(t.last(55000, w).rule, Pattern::DeauthBroadcast);
    // The window closes after a whole window without a counted frame: the record is final ...
    CHECK(t.last(64999, w).open);
    r = t.last(65000, w);
    CHECK(r.known);
    CHECK(!r.open);
    CHECK_EQ(r.total, 29u);
    // ... the table counts the next window from zero, and the record stays until the next burst.
    t.seen(kBroadcast, b, ap, 1, 70000, w);
    CHECK(tuple_is(t.top(70000, w), kBroadcast, b, ap, 1, 1));
    r = t.last(70000, w);
    CHECK(r.known);
    CHECK(!r.open);
    CHECK_EQ(r.total, 29u);
    CHECK_EQ(r.incident_at, Millis{30300});
    t.incident(70000, w, Pattern::None);
    r = t.last(70000, w);
    CHECK(r.open);
    CHECK_EQ(r.total, 1u);
    CHECK_EQ(r.incident_at, Millis{70000});
    CHECK_EQ(r.rule, Pattern::None);
    CHECK_EQ(unsigned(r.tuples), 1u);
    t.clear();
    CHECK(!t.last(70000, w).known);
    CHECK_EQ(t.top(70000, w).count, 0u);
}

GUARDIAN_CASE(g16s_the_burst_table_holds_eight_tuples_and_counts_what_it_could_not_list) {
    constexpr Millis w = 10000;
    const Mac ap = mac(0x00, 3), steady = mac(0x00, 9);
    CHECK_EQ(BurstTrace::capacity, std::size_t{8});
    BurstTrace t;
    Millis at = 1000;
    // A flood that changes its sender on every frame, with one steady sender between them.
    for (std::uint32_t i = 0; i < 40; ++i) {
        t.seen(kBroadcast, random_mac(i), ap, 6, at++, w);
        t.seen(kBroadcast, steady, ap, 6, at++, w);
    }
    t.incident(at, w, Pattern::DeauthSource);
    auto r = t.last(at, w);
    CHECK(r.known);
    CHECK_EQ(r.total, 80u);
    CHECK_EQ(unsigned(r.tuples), 8u);
    CHECK(tuple_is(r.top[0], kBroadcast, steady, ap, 6, 40));   // the steady one is never the one replaced
    for (std::size_t i = 1; i < r.top.size(); ++i) CHECK_EQ(r.top[i].count, 1u);   // the changing ones: one frame each
    CHECK(r.top[1].sender == random_mac(39));                   // ... the newest of them kept
    CHECK_EQ(r.unlisted, 33u);                                  // 80 - 40 - 7: counted, never listed, never made up
    // The same after the threshold: a ninth tuple replaces the one with the fewest frames, heard longest ago.
    t.seen(kPhone, steady, ap, 6, at + 1, w);
    r = t.last(at + 1, w);
    CHECK_EQ(r.total, 81u);
    CHECK_EQ(unsigned(r.tuples), 8u);
    CHECK_EQ(r.unlisted, 34u);
    CHECK(tuple_is(r.top[0], kBroadcast, steady, ap, 6, 40));
    CHECK(tuple_is(r.top[1], kPhone, steady, ap, 6, 1));
    bool oldest_kept = false;
    for (const auto& kept : r.top) oldest_kept = oldest_kept || kept.sender == random_mac(33);
    CHECK(!oldest_kept);
}

GUARDIAN_CASE(g16s_a_mixed_burst_on_the_picked_network_is_listed_by_tuple) {
    const Mac second = mac(0x00, 77);
    Rig r; DisconnectDetector red(r.scope, DetectorLimits{});
    CHECK(hear(r, beacon(second, "home"), 1000));
    CHECK(!red.last_burst(instant(1000)).known);
    // The replay: 20 frames 100 ms apart, 12 broadcast ones naming the picked address and 8 to one
    // device naming the second address of the name.
    std::uint32_t seq = 0;
    const auto frame = [&](bool to_second, Millis at) {
        Disc d{}; d.seq = 41 * seq++ + 3;
        r.feed(red, to_second ? disconnect(second, kPhone, second, d) : disconnect(kHome, kBroadcast, kHome, d), meta(at));
    };
    for (std::uint32_t i = 0; i < 20; ++i) frame(i % 5 >= 3, 2000 + i * 100);
    CHECK_EQ(count_kind(r.sink, IncidentKind::DisconnectBurst), 1u);
    CHECK_EQ(r.sink.got[0].count, 20u);
    CHECK(tuple_is(r.sink.got[0].top, kBroadcast, kHome, kHome, 6, 12));   // the observation carries the most frequent tuple
    auto b = red.last_burst(instant(3900));
    CHECK(b.known);
    CHECK(b.open);
    CHECK(b.age_known);
    CHECK_EQ(b.age_ms, Millis{0});
    CHECK_EQ(b.incident_at, Millis{3900});
    CHECK_EQ(b.rule, Pattern::None);
    CHECK_EQ(b.total, 20u);
    CHECK_EQ(b.unlisted, 0u);
    CHECK_EQ(unsigned(b.tuples), 2u);
    CHECK(tuple_is(b.top[0], kBroadcast, kHome, kHome, 6, 12));
    CHECK(tuple_is(b.top[1], kPhone, second, second, 6, 8));
    // The burst goes on: the record grows with it and the order follows the counts.
    for (std::uint32_t i = 0; i < 5; ++i) frame(true, 4000 + i * 100);
    b = red.last_burst(instant(5000));
    CHECK_EQ(b.total, 25u);
    CHECK_EQ(b.age_ms, Millis{1100});
    CHECK(tuple_is(b.top[0], kPhone, second, second, 6, 13));
    CHECK(tuple_is(b.top[1], kBroadcast, kHome, kHome, 6, 12));
    CHECK_EQ(r.sink.count, 1u);                                 // one report, one record
    // A Retry-bit copy is not a counted frame and adds nothing.
    { Disc d{}; d.seq = 41 * (seq - 1) + 3; d.retry = true; r.feed(red, disconnect(second, kPhone, second, d), meta(4450)); }
    CHECK_EQ(red.last_burst(instant(5000)).total, 25u);
    // The window closes 10 s after the last counted frame; the record stays readable.
    CHECK(red.last_burst(instant(14399)).open);
    b = red.last_burst(instant(14400));
    CHECK(b.known);
    CHECK(!b.open);
    CHECK_EQ(b.total, 25u);
    // A second burst inside the cooldown of the first makes no new report, and is recorded all the same.
    for (std::uint32_t i = 0; i < 20; ++i) frame(true, 20000 + i * 100);
    CHECK_EQ(r.sink.count, 1u);
    CHECK(red.stats().suppressed_by_cooldown >= 1u);
    b = red.last_burst(instant(22000));
    CHECK(b.open);
    CHECK_EQ(b.incident_at, Millis{21900});
    CHECK_EQ(b.total, 20u);
    CHECK_EQ(unsigned(b.tuples), 1u);
    CHECK(tuple_is(b.top[0], kPhone, second, second, 6, 20));
    // Another timebase cannot age the record; reset() forgets it with the other counters.
    TimeEpoch other = epoch(); other.boot_id = 2;
    b = red.last_burst(Instant{other, 22000, true});
    CHECK(b.known);
    CHECK(!b.age_known);
    CHECK(!b.open);
    red.reset();
    CHECK(!red.last_burst(instant(22000)).known);
}

GUARDIAN_CASE(g16s_a_mixed_burst_nearby_is_listed_with_the_rule_it_reached) {
    const Mac other = mac(0x00, 90);
    Rig r; AreaDisconnectDetector area(r.scope);
    CHECK(!area.last_burst(IncidentScope::Area, instant(1000)).known);
    // The replay: a burst against two access points that are not the picked network, 14 broadcast
    // frames naming one and 6 to one device naming the other.
    std::uint32_t seq = 0;
    const auto frame = [&](const Mac& from, const Mac& to, const Mac& bssid, Millis at) {
        Disc d{}; d.seq = 41 * seq++ + 3;
        r.feed(area, disconnect(from, to, bssid, d), meta(at));
    };
    for (std::uint32_t i = 0; i < 20; ++i) {
        if (i % 10 >= 7) frame(other, kPhone, other, 2000 + i * 100);
        else frame(kNeighbour, kBroadcast, kNeighbour, 2000 + i * 100);
    }
    CHECK_EQ(r.sink.count, 1u);                                 // the tenth broadcast frame, at 3200
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthBroadcast), 1u);
    CHECK_EQ(r.sink.got[0].scope, IncidentScope::Area);
    CHECK(tuple_is(r.sink.got[0].top, kBroadcast, kNeighbour, kNeighbour, 6, 10));
    auto b = area.last_burst(IncidentScope::Area, instant(3900));
    CHECK(b.known);
    CHECK(b.open);
    CHECK(b.age_known);
    CHECK_EQ(b.age_ms, Millis{700});
    CHECK_EQ(b.incident_at, Millis{3200});
    CHECK_EQ(b.rule, Pattern::DeauthBroadcast);
    CHECK_EQ(b.total, 20u);
    CHECK_EQ(b.unlisted, 0u);
    CHECK_EQ(unsigned(b.tuples), 2u);
    CHECK(tuple_is(b.top[0], kBroadcast, kNeighbour, kNeighbour, 6, 14));
    CHECK(tuple_is(b.top[1], kPhone, other, other, 6, 6));
    CHECK(!area.last_burst(IncidentScope::Network, instant(3900)).known);   // nothing here was about the picked network
    b = area.last_burst(IncidentScope::Area, instant(13900));               // 10 s after the last frame: closed, kept
    CHECK(b.known);
    CHECK(!b.open);
    CHECK_EQ(b.total, 20u);
    // The picked network's own frames: many to one device inside a second is the pair rule, recorded
    // as the picked network's burst (the red burst itself is the disconnect detector's record).
    const Mac second = mac(0x00, 77);
    CHECK(hear(r, beacon(second, "home"), 20000));
    for (std::uint32_t i = 0; i < 12; ++i) frame(second, kPhone, second, 21000 + i * 50);
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthPair), 1u);
    CHECK_EQ(r.sink.last().scope, IncidentScope::Network);
    CHECK(tuple_is(r.sink.last().top, kPhone, second, second, 6, 12));
    b = area.last_burst(IncidentScope::Network, instant(21600));
    CHECK(b.known);
    CHECK_EQ(b.rule, Pattern::DeauthPair);
    CHECK_EQ(b.incident_at, Millis{21550});
    CHECK_EQ(b.total, 12u);
    CHECK(tuple_is(b.top[0], kPhone, second, second, 6, 12));
    CHECK_EQ(area.last_burst(IncidentScope::Area, instant(21600)).total, 20u);   // the nearby record is untouched
    area.reset();
    CHECK(!area.last_burst(IncidentScope::Area, instant(21600)).known);
    CHECK(!area.last_burst(IncidentScope::Network, instant(21600)).known);
}

GUARDIAN_CASE(g16s_status_prints_the_last_burst_of_each_scope) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    ApprovedAp picked{}; picked.network = home_network();
    CHECK(m.select(picked));
    const Mac second = mac(0x00, 77), other = mac(0x00, 90);
    clock.at = 1900;
    m.receive(packet(beacon(second, "home"), clock));
    CHECK_EQ(burst_status(m), std::string(" last_burst_network=none last_burst_area=none"));
    CHECK(!m.last_burst(IncidentScope::Network).known);
    // The replay through the real parser and detectors: a mixed burst on the picked network (two of
    // its addresses), 2000 .. 3900 ...
    std::uint32_t seq = 0;
    const auto frame = [&](Monitor& to_monitor, const Mac& from, const Mac& to, const Mac& bssid) {
        clock.at += 100;
        Disc d{}; d.seq = 41 * seq++ + 3;
        to_monitor.receive(packet(disconnect(from, to, bssid, d), clock));
    };
    for (std::uint32_t i = 0; i < 20; ++i) {
        if (i % 5 >= 3) frame(m, second, kPhone, second); else frame(m, kHome, kBroadcast, kHome);
    }
    CHECK(m.snapshot().incidents[kBurst]);
    CHECK(tuple_is(m.snapshot().evidence[kBurst].top, kBroadcast, kHome, kHome, 6, 12));
    clock.at = 9900;                                            // read 6 s later: the window is still open
    const std::string network_tuples = tuple_text(kBroadcast, kHome, kHome, 6, 12) + ";" + tuple_text(kPhone, second, second, 6, 8);
    CHECK_EQ(burst_status(m), " last_burst_network=rule:burst,total:20,unlisted:0,tuples:2,age_s:6,open:1,top:" + network_tuples
                                  + " last_burst_area=none");
    // ... then a mixed burst nearby (two other access points), 30100 .. 32000. Each scope keeps its own record.
    clock.at = 30000;
    for (std::uint32_t i = 0; i < 20; ++i) {
        if (i % 10 >= 7) frame(m, other, kPhone, other); else frame(m, kNeighbour, kBroadcast, kNeighbour);
    }
    clock.at = 45000;
    const std::string status = burst_status(m);
    CHECK_EQ(status, " last_burst_network=rule:burst,total:20,unlisted:0,tuples:2,age_s:41,open:0,top:" + network_tuples
                         + " last_burst_area=rule:deauth_broadcast,total:20,unlisted:0,tuples:2,age_s:13,open:0,top:"
                         + tuple_text(kBroadcast, kNeighbour, kNeighbour, 6, 14) + ";" + tuple_text(kPhone, other, other, 6, 6));
    // Tools split STATUS on spaces and then on the first '=': a record holds neither.
    CHECK_EQ(count_of(status, ' '), std::size_t{2});
    CHECK_EQ(count_of(status, '='), std::size_t{2});
    const auto area = m.last_burst(IncidentScope::Area);
    CHECK(area.known);
    CHECK_EQ(area.total, 20u);
    CHECK_EQ(area.age_ms, Millis{13700});
    // At most four tuples are printed, the most frequent first; `tuples` says how many the table holds.
    Monitor n(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    CHECK(n.select(picked));
    for (std::uint32_t sender = 1; sender <= 6; ++sender)
        for (std::uint32_t k = sender; k <= 6; ++k) frame(n, mac(0x00, 200 + sender), kBroadcast, kNeighbour);   // 6, 5, 4, 3, 2, 1 frames
    const std::string many = burst_status(n);
    std::string expected = " last_burst_network=none last_burst_area=rule:deauth_broadcast,total:21,unlisted:0,tuples:6,age_s:1,open:1,top:";
    for (std::uint32_t sender = 1; sender <= 4; ++sender)
        expected += (sender > 1 ? ";" : "") + tuple_text(kBroadcast, mac(0x00, 200 + sender), kNeighbour, 6, 7 - sender);
    CHECK_EQ(many, expected);
    // The longest possible records fit burst_text_max; a buffer that is too small is refused, never cut.
    LastBurst big{}; big.known = true; big.open = true; big.age_known = true; big.age_ms = ~Millis{0};
    big.rule = Pattern::DeauthBroadcast; big.total = big.unlisted = 0xffffffffu; big.tuples = LastBurst::capacity;
    for (auto& t : big.top) { t.receiver = t.sender = t.bssid = kBroadcast; t.channel = 255; t.count = 0xffffffffu; }
    char record[Monitor::burst_text_max]{};
    const std::size_t longest = measurement::burst_record(big, record, sizeof record);
    CHECK(longest > 0u);
    CHECK_EQ(count_of(record, ';'), Monitor::burst_status_tuples - 1);
    CHECK(2 * longest + std::strlen(" last_burst_network= last_burst_area=") < Monitor::burst_text_max);
    char tiny[32]{'#'};
    CHECK_EQ(m.burst_text(tiny, sizeof tiny), std::size_t{0});
    CHECK_EQ(tiny[0], '\0');
    CHECK_EQ(m.burst_text(nullptr, 0), std::size_t{0});
    // A new pick starts the detectors clean: the old network's record is gone with its counters.
    CHECK(m.select(network(kNeighbour, "cafe")));
    CHECK(!m.last_burst(IncidentScope::Network).known);
}

GUARDIAN_CASE(g16s_the_details_screen_shows_the_top_tuple_of_the_burst_in_short_form) {
    companion::Status st{}; st.radio = companion::RadioState::Monitoring;
    const auto fits = [](const companion::Frame& f) {
        if (f.overflow) return false;
        for (std::uint8_t i = 0; i < f.count; ++i)
            if (f.lines[i].scale == 1 && std::strlen(f.lines[i].text.data()) > static_cast<std::size_t>(companion::Frame::cols1)) return false;
        return true;
    };
    // Red: a burst on the picked network, the frames naming a second address of its name.
    Home h;
    h.companion.boot();
    h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    h.companion.tick();
    pick(h.companion, home_network(), Action::Secondary);
    const Mac second = mac(0x00, 77);
    for (std::uint32_t i = 0; i < 24; ++i) {
        h.clock.at += 100;
        h.companion.receive(packet(beacon(kHome, "home"), h.clock));
        h.companion.receive(packet(beacon(second, "home"), h.clock));
        Disc d{}; d.seq = 41 * i + 3;
        h.companion.receive(packet(disconnect(second, kBroadcast, second, d), h.clock));
    }
    h.companion.tick();
    CHECK(h.companion.presenter().view().alert);
    CHECK(tuple_is(h.companion.presenter().view().incident.top, kBroadcast, second, second, 6, 20));
    while (h.companion.presenter().screen() != Screen::Details) h.companion.input(Action::Primary);
    for (int i = 0; i < 12 && h.companion.presenter().details().page != DetailsPage::SignalAndEvidence; ++i) h.companion.input(Action::Primary);
    CHECK(h.companion.presenter().details().page == DetailsPage::SignalAndEvidence);
    companion::Frame f{}; h.companion.render(st, f);
    CHECK(has(f, "Seen 20 (raw 20)"));
    CHECK(has(f, ("to FF:FF from " + tail(second)).c_str()));   // receiver, sender: the last two bytes of each
    CHECK(has(f, ("AP " + tail(second) + " ch6 x20").c_str())); // the access point named, the channel, the frames
    CHECK(fits(f));
    // Amber: a burst nearby, on the page that lists what was seen nearby.
    Home q;
    q.companion.boot();
    q.companion.receive(packet(beacon(kHome, "home"), q.clock));
    q.companion.tick();
    pick(q.companion, home_network(), Action::Secondary);
    for (std::uint32_t i = 0; i < 14; ++i) {
        q.clock.at += 100;
        q.companion.receive(packet(beacon(kHome, "home"), q.clock));
        Disc d{}; d.seq = 41 * i + 3;
        q.companion.receive(packet(disconnect(kNeighbour, kBroadcast, kNeighbour, d), q.clock));
    }
    q.companion.tick();
    CHECK(q.companion.presenter().view().caution);
    CHECK(!q.companion.presenter().view().alert);
    CHECK(tuple_is(q.companion.presenter().view().caution_evidence.top, kBroadcast, kNeighbour, kNeighbour, 6, 10));
    while (q.companion.presenter().screen() != Screen::Details) q.companion.input(Action::Primary);
    for (int i = 0; i < 12 && q.companion.presenter().details().page != DetailsPage::Nearby; ++i) q.companion.input(Action::Primary);
    CHECK(q.companion.presenter().details().page == DetailsPage::Nearby);
    companion::Frame g{}; q.companion.render(st, g);
    CHECK(has(g, ("to FF:FF from " + tail(kNeighbour)).c_str()));
    CHECK(has(g, ("AP " + tail(kNeighbour) + " ch6 x10").c_str()));
    CHECK(fits(g));
    // An observation without a tuple (another family) prints no tuple rows.
    Home p;
    p.companion.boot();
    p.companion.receive(packet(beacon(kHome, "home"), p.clock));
    p.companion.tick();
    pick(p.companion, home_network(), Action::Secondary);
    for (int i = 0; i < 34; ++i) {                              // the noise-floor rise of the G16J case
        p.clock.at += 1000;
        ChannelLoadSample s{};
        s.sampled_at = Instant{epoch(), p.clock.at, true}; s.origin = Origin::LiveRadio; s.channel = 6;
        s.window_ms = 1000; s.listened_ms = 1000; s.valid_frames = 40; s.noise_sum = (i < 30 ? -96 : -85) * 40; s.noise_count = 40;
        p.monitor.channel_load(s);
        p.companion.receive(packet(beacon(kHome, "home"), p.clock));
    }
    p.companion.tick();
    CHECK(p.companion.presenter().view().caution);
    while (p.companion.presenter().screen() != Screen::Details) p.companion.input(Action::Primary);
    for (int i = 0; i < 12 && p.companion.presenter().details().page != DetailsPage::Nearby; ++i) p.companion.input(Action::Primary);
    companion::Frame e{}; p.companion.render(st, e);
    CHECK(has(e, "Noise floor jumped"));
    CHECK(!has(e, "to FF:FF"));
    CHECK(!has(e, "AP "));
}

// =========================================================================================
// G16T: a nearby disconnect burst that also names the picked network is a Network incident
// (red), not an Area one (amber). MEASURED 2026-11-19 on the stick: a burst spread over the
// access points of one channel reached the nearby threshold while the picked network got a
// few frames, below the red burst's own threshold, and the owner saw amber. The rule: when a
// nearby disconnect rule is reached and the same burst holds at least one counted frame that
// names the picked network in Address 1, 2 or 3 (the selected or an approved address, or one
// heard under the picked name), the report is Network scope. No frame there: nearby, as before.
// (TDD: written and run RED first against the stub stage of BurstTrace::own / top_own and the
// unchanged detector, STATUS record and red sentence; logs in
// $GUARDIAN_STORE/builds/20261119-g16t-tdd/.) Synthetic addresses and names only.
// =========================================================================================
namespace {
constexpr std::size_t kPatternKind = static_cast<std::size_t>(IncidentKind::NetworkPattern);
// The replay: 40 broadcast disconnect frames, 100 ms apart, on one channel, spread over seven
// access points. '1'..'4' are other networks with 9, 9, 9 and 8 frames, '5' and '6' other
// networks with one frame each, and 'H' is the address that gets 3 frames (the picked network's
// for the incident, a seventh other network for the twin).
// Early: the first 'H' frame (2400) comes before the tenth frame of the others (3000).
constexpr char kSpreadEarly[] = "1234H12345" "1234H12346" "1234H1234" "1234" "1234" "123";
// Late: the others reach ten frames at 2900, the first 'H' frame comes at 4600.
constexpr char kSpreadLate[] = "1234512346" "1234" "1234" "1234" "1234" "H1234" "H1234" "H123";
static_assert(sizeof kSpreadEarly == 41 && sizeof kSpreadLate == 41, "40 frames");
Mac spread_ap(char c, const Mac& three) { return c == 'H' ? three : mac(0x00, 300 + static_cast<std::uint32_t>(c - '0')); }
Mac other(std::uint32_t i) { return spread_ap(static_cast<char>('0' + i), Mac{}); }
Bytes spread_frame(const char* order, std::uint32_t i, const Mac& three) {
    Disc d{}; d.seq = 41 * i + 3;
    const Mac ap = spread_ap(order[i], three);
    return disconnect(ap, kBroadcast, ap, d);
}
void spread(Rig& r, FrameDetector& red, FrameDetector& area, const char* order, const Mac& three, Millis from = 2000) {
    for (std::uint32_t i = 0; order[i]; ++i) {
        const auto f = spread_frame(order, i, three);
        r.feed(red, f, meta(from + i * 100));
        r.feed(area, f, meta(from + i * 100));
    }
}
void spread(Monitor& m, Clock& clock, const char* order, const Mac& three) {
    for (std::uint32_t i = 0; order[i]; ++i) { clock.at += 100; m.receive(packet(spread_frame(order, i, three), clock)); }
}
// The four most frequent tuples of the replay as STATUS lists them (equal counts: heard most recently first).
std::string spread_top4() {
    return tuple_text(kBroadcast, other(3), other(3), 6, 9) + ";" + tuple_text(kBroadcast, other(2), other(2), 6, 9) + ";"
        + tuple_text(kBroadcast, other(1), other(1), 6, 9) + ";" + tuple_text(kBroadcast, other(4), other(4), 6, 8);
}
} // namespace

GUARDIAN_CASE(g16t_a_nearby_burst_with_three_frames_at_the_picked_network_is_a_network_incident) {
    Rig r; DisconnectDetector red(r.scope, DetectorLimits{}); AreaDisconnectDetector area(r.scope);
    spread(r, red, area, kSpreadEarly, kHome);
    // One report for the whole replay: about the picked network, made by the nearby rule that was reached.
    CHECK_EQ(r.sink.count, 1u);
    const auto& o = r.sink.got[0];
    CHECK_EQ(o.scope, IncidentScope::Network);
    CHECK_EQ(o.kind, IncidentKind::NetworkPattern);
    CHECK_EQ(o.pattern, Pattern::DeauthBroadcast);
    CHECK(o.affected == home_network());
    CHECK_EQ(o.acquired.at, Millis{3000});                      // the tenth broadcast frame of the other networks
    CHECK_EQ(o.count, 10u);
    CHECK_EQ(o.threshold, 10u);
    CHECK_EQ(o.own_frames, 1u);                                 // one frame at the picked network so far (2400)
    CHECK(o.bssid == kHome);                                    // the picked network's address the frames named
    CHECK(tuple_is(o.top, kBroadcast, kHome, kHome, 6, 1));     // the glass shows the tuple that made it red
    CHECK(o.top.own);
    // The red burst keeps its own threshold: three frames are far below it and it reports nothing.
    CHECK_EQ(count_kind(r.sink, IncidentKind::DisconnectBurst), 0u);
    CHECK_EQ(red.stats().in_scope, 3u);
    CHECK_EQ(red.stats().out_of_scope, 37u);
    CHECK_EQ(red.stats().reports, 0u);
    CHECK(!red.last_burst(instant(5900)).known);
    // The burst record keeps every tuple, with the count of frames at the picked network.
    for (const auto scope : {IncidentScope::Area, IncidentScope::Network}) {   // one burst: nearby AND on the picked network
        const auto b = area.last_burst(scope, instant(5900));
        CHECK(b.known);
        CHECK(b.open);
        CHECK_EQ(b.rule, Pattern::DeauthBroadcast);
        CHECK_EQ(b.incident_at, Millis{3000});
        CHECK_EQ(b.total, 40u);
        CHECK_EQ(b.unlisted, 0u);
        CHECK_EQ(b.own, 3u);
        CHECK_EQ(unsigned(b.tuples), 7u);
        CHECK(tuple_is(b.top[0], kBroadcast, other(3), other(3), 6, 9));
        CHECK(tuple_is(b.top[1], kBroadcast, other(2), other(2), 6, 9));
        CHECK(tuple_is(b.top[2], kBroadcast, other(1), other(1), 6, 9));
        CHECK(tuple_is(b.top[3], kBroadcast, other(4), other(4), 6, 8));
        CHECK(tuple_is(b.top[4], kBroadcast, kHome, kHome, 6, 3));              // outside the four most frequent
        CHECK(b.top[4].own);
        CHECK(tuple_is(b.top[5], kBroadcast, other(6), other(6), 6, 1));
        CHECK(tuple_is(b.top[6], kBroadcast, other(5), other(5), 6, 1));
        for (std::size_t i = 0; i < 7; ++i) if (i != 4) CHECK(!b.top[i].own);
    }
    const auto rep = area.report(instant(5900));
    CHECK_EQ(rep.incidents, 1u);
    CHECK_EQ(rep.events_total, 37u);                            // the nearby rules count the other networks' frames only
}

GUARDIAN_CASE(g16t_the_same_burst_with_no_frame_at_the_picked_network_stays_nearby) {
    const Mac seventh = mac(0x00, 307);
    Rig r; DisconnectDetector red(r.scope, DetectorLimits{}); AreaDisconnectDetector area(r.scope);
    spread(r, red, area, kSpreadEarly, seventh);
    CHECK_EQ(r.sink.count, 1u);
    const auto& o = r.sink.got[0];
    CHECK_EQ(o.scope, IncidentScope::Area);
    CHECK_EQ(o.pattern, Pattern::DeauthBroadcast);
    CHECK_EQ(o.acquired.at, Millis{2900});
    CHECK_EQ(o.count, 10u);
    CHECK_EQ(o.own_frames, 0u);
    CHECK(!o.top.own);
    CHECK_EQ(red.stats().in_scope, 0u);
    const auto b = area.last_burst(IncidentScope::Area, instant(5900));
    CHECK(b.known);
    CHECK_EQ(b.total, 40u);
    CHECK_EQ(b.own, 0u);
    CHECK_EQ(unsigned(b.tuples), 7u);
    CHECK(tuple_is(b.top[4], kBroadcast, seventh, seventh, 6, 3));
    for (std::size_t i = 0; i < 7; ++i) CHECK(!b.top[i].own);
    CHECK(!area.last_burst(IncidentScope::Network, instant(5900)).known);      // nothing here was about the picked network
    // Without a picked network nothing can be "its" frames: the replay naming that address is nearby too.
    Rig n; n.scope.clear();
    DisconnectDetector nred(n.scope, DetectorLimits{}); AreaDisconnectDetector narea(n.scope);
    spread(n, nred, narea, kSpreadEarly, kHome);
    CHECK_EQ(n.sink.count, 1u);
    CHECK_EQ(n.sink.got[0].scope, IncidentScope::Area);
    CHECK_EQ(n.sink.got[0].own_frames, 0u);
    CHECK_EQ(narea.last_burst(IncidentScope::Area, instant(5900)).own, 0u);
}

GUARDIAN_CASE(g16t_frames_at_an_address_heard_under_the_picked_name_count_as_the_picked_network) {
    const Mac second = mac(0x00, 77);
    Rig r; DisconnectDetector red(r.scope, DetectorLimits{}); AreaDisconnectDetector area(r.scope);
    CHECK(hear(r, beacon(second, "home"), 1000));               // learned from the air, never approved
    CHECK(!r.scope.in_scope(second));
    spread(r, red, area, kSpreadEarly, second);
    CHECK_EQ(r.sink.count, 1u);
    const auto& o = r.sink.got[0];
    CHECK_EQ(o.scope, IncidentScope::Network);
    CHECK_EQ(o.kind, IncidentKind::NetworkPattern);
    CHECK(o.affected == home_network());                        // about the picked network ...
    CHECK(o.bssid == second);                                   // ... the address the frames named is evidence
    CHECK_EQ(o.own_frames, 1u);
    CHECK(tuple_is(o.top, kBroadcast, second, second, 6, 1));
    const auto b = area.last_burst(IncidentScope::Network, instant(5900));
    CHECK_EQ(b.own, 3u);
    CHECK(tuple_is(b.top[4], kBroadcast, second, second, 6, 3));
    CHECK(b.top[4].own);
    // An approved address of the network counts the same way.
    const Mac node = mac(0x00, 78);
    Rig a; ApprovedAp ap{}; ap.network = network(node, "home");
    CHECK(a.scope.approve(ap));
    DisconnectDetector ared(a.scope, DetectorLimits{}); AreaDisconnectDetector aarea(a.scope);
    spread(a, ared, aarea, kSpreadEarly, node);
    CHECK_EQ(a.sink.count, 1u);
    CHECK_EQ(a.sink.got[0].scope, IncidentScope::Network);
    CHECK(a.sink.got[0].bssid == node);
    CHECK_EQ(aarea.last_burst(IncidentScope::Network, instant(5900)).own, 3u);
    // The same replay at an address that only LOOKS close (never heard under the name): nearby.
    Rig q; DisconnectDetector qred(q.scope, DetectorLimits{}); AreaDisconnectDetector qarea(q.scope);
    spread(q, qred, qarea, kSpreadEarly, second);
    CHECK_EQ(q.sink.count, 1u);
    CHECK_EQ(q.sink.got[0].scope, IncidentScope::Area);
}

GUARDIAN_CASE(g16t_a_frame_at_the_picked_network_after_the_nearby_report_turns_the_burst_red) {
    Rig r; DisconnectDetector red(r.scope, DetectorLimits{}); AreaDisconnectDetector area(r.scope);
    spread(r, red, area, kSpreadLate, kHome);
    // Ten frames of the other networks first: nearby (amber), exactly as before ...
    CHECK_EQ(r.sink.count, 2u);
    CHECK_EQ(r.sink.got[0].scope, IncidentScope::Area);
    CHECK_EQ(r.sink.got[0].pattern, Pattern::DeauthBroadcast);
    CHECK_EQ(r.sink.got[0].acquired.at, Millis{2900});
    CHECK_EQ(r.sink.got[0].own_frames, 0u);
    // ... then the first frame naming the picked network inside the same burst: a Network report.
    const auto& o = r.sink.got[1];
    CHECK_EQ(o.scope, IncidentScope::Network);
    CHECK_EQ(o.kind, IncidentKind::NetworkPattern);
    CHECK_EQ(o.pattern, Pattern::DeauthBroadcast);
    CHECK_EQ(o.acquired.at, Millis{4600});
    CHECK_EQ(o.own_frames, 1u);
    CHECK_EQ(o.threshold, 10u);
    CHECK(o.count >= 10u);
    CHECK(o.bssid == kHome);
    CHECK(tuple_is(o.top, kBroadcast, kHome, kHome, 6, 1));
    const auto b = area.last_burst(IncidentScope::Network, instant(5900));
    CHECK_EQ(b.incident_at, Millis{2900});                      // one burst, one record
    CHECK_EQ(b.total, 40u);
    CHECK_EQ(b.own, 3u);
    CHECK_EQ(area.report(instant(5900)).incidents, 2u);
}

// MEASURED 2026-11-19 13:28 on the stick (supervisor): the glass showed the red "Nearby burst also on"
// line for an 18-frame burst, then a second burst of the same Bruce run with no frame at the picked
// network replaced the nearby record, and STATUS read last_burst_network=none 51 s later. The
// picked network's record stays until the next burst that names the picked network.
GUARDIAN_CASE(g16t_a_later_nearby_burst_without_the_picked_network_keeps_its_red_record) {
    const Mac seventh = mac(0x00, 307);
    Rig r; DisconnectDetector red(r.scope, DetectorLimits{}); AreaDisconnectDetector area(r.scope);
    spread(r, red, area, kSpreadEarly, kHome);                  // red: 3 frames at the picked network, 2000 .. 5900
    spread(r, red, area, kSpreadEarly, seventh, 30000);         // amber: none there, 30000 .. 33900
    CHECK_EQ(r.sink.count, 2u);
    CHECK_EQ(r.sink.got[0].scope, IncidentScope::Network);
    CHECK_EQ(r.sink.got[1].scope, IncidentScope::Area);
    const auto n = area.last_burst(IncidentScope::Network, instant(50000));
    CHECK(n.known);
    CHECK(!n.open);
    CHECK_EQ(n.incident_at, Millis{3000});                      // the red burst, not the later one
    CHECK_EQ(n.total, 40u);
    CHECK_EQ(n.own, 3u);
    CHECK_EQ(unsigned(n.tuples), 7u);
    CHECK(tuple_is(n.top[4], kBroadcast, kHome, kHome, 6, 3));
    CHECK(n.top[4].own);
    CHECK(n.age_known);
    CHECK_EQ(n.age_ms, Millis{47000});
    const auto a = area.last_burst(IncidentScope::Area, instant(50000));    // the nearby record is the latest burst
    CHECK(a.known);
    CHECK_EQ(a.incident_at, Millis{30900});
    CHECK_EQ(a.own, 0u);
    // A third burst that names the picked network again takes its place.
    spread(r, red, area, kSpreadEarly, kHome, 60000);
    const auto t = area.last_burst(IncidentScope::Network, instant(70000));
    CHECK_EQ(t.incident_at, Millis{61000});
    CHECK_EQ(t.own, 3u);
}

GUARDIAN_CASE(g16t_only_frames_inside_the_burst_count_and_the_red_threshold_is_unchanged) {
    const auto others = [](Rig& r, FrameDetector& red, FrameDetector& area) {   // 12 broadcast frames, 2000 .. 3100
        for (std::uint32_t i = 0; i < 12; ++i) {
            Disc d{}; d.seq = 41 * i + 3;
            const auto f = disconnect(other(1 + i % 3), kBroadcast, other(1 + i % 3), d);
            r.feed(red, f, meta(2000 + i * 100)); r.feed(area, f, meta(2000 + i * 100));
        }
    };
    const auto own_frame = [](Rig& r, FrameDetector& red, FrameDetector& area, Millis at, std::uint32_t seq) {
        Disc d{}; d.seq = seq;
        const auto f = disconnect(kHome, kBroadcast, kHome, d);
        r.feed(red, f, meta(at)); r.feed(area, f, meta(at));
    };
    // A frame at the picked network while the nearby burst is still being counted (its window closes
    // 10 s after its newest frame): the burst is on the picked network too.
    Rig r; DisconnectDetector red(r.scope, DetectorLimits{}); AreaDisconnectDetector area(r.scope);
    others(r, red, area);
    CHECK_EQ(r.sink.count, 1u);
    own_frame(r, red, area, 3100 + 9999, 900);
    CHECK_EQ(r.sink.count, 2u);
    CHECK_EQ(r.sink.got[1].scope, IncidentScope::Network);
    CHECK_EQ(r.sink.got[1].own_frames, 1u);
    // The same frame once that window has closed: not part of the burst, nothing new.
    Rig q; DisconnectDetector qred(q.scope, DetectorLimits{}); AreaDisconnectDetector qarea(q.scope);
    others(q, qred, qarea);
    own_frame(q, qred, qarea, 3100 + 10000, 900);
    CHECK_EQ(q.sink.count, 1u);
    CHECK_EQ(q.sink.got[0].scope, IncidentScope::Area);
    CHECK_EQ(qarea.last_burst(IncidentScope::Area, instant(13100)).own, 0u);
    CHECK(!qarea.last_burst(IncidentScope::Network, instant(13100)).known);
    // A frame at the picked network long BEFORE the nearby burst has left the window: nearby.
    Rig e; DisconnectDetector ered(e.scope, DetectorLimits{}); AreaDisconnectDetector earea(e.scope);
    own_frame(e, ered, earea, 2000, 900);
    for (std::uint32_t i = 0; i < 12; ++i) {
        Disc d{}; d.seq = 41 * i + 3;
        const auto f = disconnect(other(1), kBroadcast, other(1), d);
        e.feed(ered, f, meta(30000 + i * 100)); e.feed(earea, f, meta(30000 + i * 100));
    }
    CHECK_EQ(e.sink.count, 1u);
    CHECK_EQ(e.sink.got[0].scope, IncidentScope::Area);
    // Frames at the picked network alone, below the red threshold: no report of any kind (targeted
    // bursts keep the red burst's own threshold and the pair rule).
    Rig t; DisconnectDetector tred(t.scope, DetectorLimits{}); AreaDisconnectDetector tarea(t.scope);
    for (std::uint32_t i = 0; i < 3; ++i) own_frame(t, tred, tarea, 2000 + i * 100, 41 * i + 3);
    CHECK_EQ(t.sink.count, 0u);
    CHECK(!tarea.last_burst(IncidentScope::Area, instant(2300)).known);
    CHECK(!tarea.last_burst(IncidentScope::Network, instant(2300)).known);
    for (std::uint32_t i = 3; i < 20; ++i) own_frame(t, tred, tarea, 2000 + i * 100, 41 * i + 3);
    CHECK_EQ(t.sink.count, 1u);                                 // the twentieth: the red burst, and nothing beside it
    CHECK_EQ(t.sink.got[0].kind, IncidentKind::DisconnectBurst);
    CHECK_EQ(t.sink.got[0].own_frames, 0u);
    CHECK(!tarea.last_burst(IncidentScope::Area, instant(3900)).known);
}

GUARDIAN_CASE(g16t_a_frame_naming_the_picked_network_as_receiver_or_sender_counts_too) {
    // Address 3 names another access point; the picked network's address is the receiver (first rig)
    // or the sender (second rig). Header bytes as received: spoofable, and still frames at the network.
    for (const bool as_receiver : {true, false}) {
        Rig r; DisconnectDetector red(r.scope, DetectorLimits{}); AreaDisconnectDetector area(r.scope);
        Disc first{}; first.seq = 900;
        const auto f = as_receiver ? disconnect(kPhone, kHome, other(1), first) : disconnect(kHome, kPhone, other(1), first);
        r.feed(red, f, meta(1900)); r.feed(area, f, meta(1900));
        CHECK_EQ(r.sink.count, 0u);
        CHECK_EQ(red.stats().in_scope, 0u);                     // the red burst counts by Address 3 only, as before
        for (std::uint32_t i = 0; i < 10; ++i) {
            Disc d{}; d.seq = 41 * i + 3;
            const auto g = disconnect(other(2), kBroadcast, other(2), d);
            r.feed(red, g, meta(2000 + i * 100)); r.feed(area, g, meta(2000 + i * 100));
        }
        CHECK_EQ(r.sink.count, 1u);
        const auto& o = r.sink.got[0];
        CHECK_EQ(o.scope, IncidentScope::Network);
        CHECK_EQ(o.pattern, Pattern::DeauthBroadcast);
        CHECK_EQ(o.own_frames, 1u);
        CHECK(o.bssid == kHome);
        CHECK(o.top.own);
        CHECK(as_receiver ? tuple_is(o.top, kHome, kPhone, other(1), 6, 1) : tuple_is(o.top, kPhone, kHome, other(1), 6, 1));
        CHECK_EQ(area.report(instant(2900)).events_total, 11u);   // Address 3 is another network: a nearby frame as well
    }
}

GUARDIAN_CASE(g16t_the_burst_table_never_drops_a_tuple_of_the_picked_network_for_another) {
    constexpr Millis w = 10000;
    BurstTrace t;
    CHECK_EQ(t.own(1000, w), 0u);
    CHECK_EQ(t.top_own(1000, w).count, 0u);
    CHECK(!t.open(1000, w));
    Millis at = 1000;
    t.seen(kBroadcast, kHome, kHome, 6, at++, w, true);         // one frame at the picked network ...
    for (std::uint32_t i = 0; i < 12; ++i) {                    // ... then twelve other tuples with two frames each
        t.seen(kBroadcast, mac(0x00, 400 + i), mac(0x00, 400 + i), 6, at++, w);
        t.seen(kBroadcast, mac(0x00, 400 + i), mac(0x00, 400 + i), 6, at++, w);
    }
    CHECK_EQ(t.own(at, w), 1u);                                 // the window's count, before any threshold
    CHECK(tuple_is(t.top_own(at, w), kBroadcast, kHome, kHome, 6, 1));
    CHECK(!t.open(at, w));
    t.incident(at, w, Pattern::DeauthBroadcast);
    CHECK(t.open(at, w));
    auto r = t.last(at, w);
    CHECK_EQ(r.total, 25u);
    CHECK_EQ(r.own, 1u);
    CHECK_EQ(unsigned(r.tuples), 8u);
    CHECK_EQ(r.unlisted, 10u);                                  // five replaced tuples of two frames
    CHECK(tuple_is(r.top[7], kBroadcast, kHome, kHome, 6, 1));  // the fewest frames, and still listed
    CHECK(r.top[7].own);
    for (std::size_t i = 0; i < 7; ++i) { CHECK_EQ(r.top[i].count, 2u); CHECK(!r.top[i].own); }
    // The same while the burst is being counted: new tuples replace others, never that one, and
    // the count of frames at the picked network follows the whole burst.
    for (std::uint32_t i = 0; i < 6; ++i) t.seen(kBroadcast, mac(0x00, 500 + i), mac(0x00, 500 + i), 6, at++, w);
    t.seen(kBroadcast, kHome, kHome, 6, at++, w, true);
    t.seen(kPhone, kHome, kHome, 6, at++, w, true);             // a second tuple of the picked network
    r = t.last(at, w);
    CHECK_EQ(r.total, 33u);
    CHECK_EQ(r.own, 3u);
    CHECK_EQ(t.own(at, w), 3u);
    CHECK(tuple_is(t.top_own(at, w), kBroadcast, kHome, kHome, 6, 2));
    std::size_t own_listed = 0;
    for (std::size_t i = 0; i < r.tuples; ++i) own_listed += r.top[i].own;
    CHECK_EQ(own_listed, std::size_t{2});
    // Closed: the next window counts from zero.
    CHECK(!t.open(at + w, w));
    t.seen(kBroadcast, mac(0x00, 600), mac(0x00, 600), 6, at + w, w);
    CHECK_EQ(t.own(at + w, w), 0u);
    CHECK_EQ(t.last(at + w, w).own, 3u);                        // the finished record keeps its count
    // Eight tuples of the picked network: a ninth tuple that is not takes no entry and is counted.
    BurstTrace all;
    for (std::uint32_t i = 0; i < 8; ++i) all.seen(mac(0x00, 700 + i), kHome, kHome, 6, 1000 + i, w, true);
    all.seen(kBroadcast, mac(0x00, 800), mac(0x00, 800), 6, 1010, w);
    all.incident(1010, w, Pattern::DeauthSource);
    r = all.last(1010, w);
    CHECK_EQ(r.total, 9u);
    CHECK_EQ(r.own, 8u);
    CHECK_EQ(r.unlisted, 1u);
    for (std::size_t i = 0; i < 8; ++i) CHECK(r.top[i].own);
    all.seen(kBroadcast, mac(0x00, 801), mac(0x00, 801), 6, 1020, w);
    r = all.last(1020, w);
    CHECK_EQ(r.total, 10u);
    CHECK_EQ(r.unlisted, 2u);
    for (std::size_t i = 0; i < 8; ++i) CHECK(r.top[i].own);
    all.clear();
    CHECK_EQ(all.own(1020, w), 0u);
}

GUARDIAN_CASE(g16t_status_prints_the_picked_networks_tuple_and_its_count_in_the_burst_record) {
    ApprovedAp picked{}; picked.network = home_network();
    // The replay with 3 frames at the picked network, through the real parser, detectors and core.
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    CHECK(m.select(picked));
    clock.at = 1900;
    spread(m, clock, kSpreadEarly, kHome);                      // 2000 .. 5900
    auto s = m.snapshot();
    CHECK(s.incidents[kPatternKind]);                           // red ...
    CHECK(!s.incidents[kBurst]);                                // ... and not by the red burst's own rule
    CHECK_EQ(s.evidence[kPatternKind].pattern, Pattern::DeauthBroadcast);
    CHECK_EQ(s.evidence[kPatternKind].own_frames, 1u);
    CHECK(s.evidence[kPatternKind].bssid == kHome);
    for (const bool visible : s.area_visible) CHECK(!visible);  // nothing amber beside it
    auto v = m.view(s);
    CHECK(v.alert);
    CHECK_EQ(v.incident.kind, IncidentKind::NetworkPattern);
    CHECK_EQ(v.incident.own_frames, 1u);
    CHECK_EQ(std::string(v.alert_reason), "Disconnect burst nearby also on your network");
    char sentence[96]{};
    CHECK(alert_sentence(v, sentence, sizeof sentence) > 0);
    CHECK_EQ(std::string(sentence), "Nearby burst also on home");
    clock.at = 7000;
    // The picked network's tuple is fifth by count: printed after the four most frequent, marked,
    // and `own:` says how many frames of the burst named the picked network.
    const std::string mixed = "rule:deauth_broadcast,total:40,unlisted:0,tuples:7,own:3,age_s:4,open:1,top:" + spread_top4() + ";"
        + tuple_text(kBroadcast, kHome, kHome, 6, 3) + ":own";
    const std::string status = burst_status(m);
    CHECK_EQ(status, " last_burst_network=" + mixed + " last_burst_area=" + mixed);
    CHECK_EQ(count_of(status, ' '), std::size_t{2});
    CHECK_EQ(count_of(status, '='), std::size_t{2});
    CHECK_EQ(m.last_burst(IncidentScope::Network).own, 3u);
    char detectors[2048]{};
    CHECK(m.status_text(detectors, sizeof detectors) > 0);
    CHECK(std::string(detectors).find("detectors=disconnect:frames=40,in_window=3,events=3,incidents=0,") != std::string::npos);
    CHECK(std::string(detectors).find("area_disconnect:frames=40,in_window=37,events=37,incidents=1,") != std::string::npos);
    // The twin with no frame at the picked network: amber, and the record reads as it did before.
    Clock twin_clock; Monitor n(twin_clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    CHECK(n.select(picked));
    twin_clock.at = 1900;
    spread(n, twin_clock, kSpreadEarly, mac(0x00, 307));
    s = n.snapshot();
    CHECK(!s.incidents[kPatternKind]);
    CHECK(!s.incidents[kBurst]);
    bool amber = false;
    for (const bool visible : s.area_visible) amber = amber || visible;
    CHECK(amber);
    CHECK(!n.view(s).alert);
    twin_clock.at = 7000;
    CHECK_EQ(burst_status(n), " last_burst_network=none last_burst_area=rule:deauth_broadcast,total:40,unlisted:0,tuples:7,age_s:4,open:1,top:"
                                  + spread_top4());
    // Every tuple of the picked network is printed, also one inside the four most frequent (once).
    LastBurst b{}; b.known = true; b.open = true; b.age_known = true; b.age_ms = 5000;
    b.rule = Pattern::DeauthSource; b.total = 44; b.tuples = LastBurst::capacity; b.own = 14;
    for (std::size_t i = 0; i < b.top.size(); ++i) {
        auto& t = b.top[i];
        t.receiver = kBroadcast; t.sender = t.bssid = mac(0x00, 600 + static_cast<std::uint32_t>(i)); t.channel = 1;
        t.count = static_cast<std::uint32_t>(9 - i); t.own = i == 1 || i == 5 || i == 7;
    }
    const auto listed = [&](std::size_t i, bool own) {
        return tuple_text(kBroadcast, b.top[i].sender, b.top[i].bssid, 1, 9 - static_cast<unsigned>(i)) + (own ? ":own" : "");
    };
    char record[Monitor::burst_text_max]{};
    CHECK(measurement::burst_record(b, record, sizeof record) > 0);
    CHECK_EQ(std::string(record), "rule:deauth_source,total:44,unlisted:0,tuples:8,own:14,age_s:5,open:1,top:" + listed(0, false) + ";"
                                      + listed(1, true) + ";" + listed(2, false) + ";" + listed(3, false) + ";" + listed(5, true) + ";" + listed(7, true));
    // The longest possible records (every tuple the picked network's) fit burst_text_max.
    LastBurst big{}; big.known = true; big.open = true; big.age_known = true; big.age_ms = ~Millis{0};
    big.rule = Pattern::DeauthBroadcast; big.total = big.unlisted = big.own = 0xffffffffu; big.tuples = LastBurst::capacity;
    for (auto& t : big.top) { t.receiver = t.sender = t.bssid = kBroadcast; t.channel = 255; t.count = 0xffffffffu; t.own = true; }
    const std::size_t longest = measurement::burst_record(big, record, sizeof record);
    CHECK(longest > 0u);
    CHECK_EQ(count_of(record, ';'), LastBurst::capacity - 1);
    CHECK(2 * longest + std::strlen(" last_burst_network= last_burst_area=") < Monitor::burst_text_max);
}

GUARDIAN_CASE(g16t_the_glass_says_the_nearby_burst_is_also_on_the_picked_network) {
    Home h;
    h.companion.boot();
    h.companion.receive(packet(beacon(kHome, "home"), h.clock));
    h.companion.tick();
    pick(h.companion, home_network(), Action::Secondary);
    for (std::uint32_t i = 0; kSpreadEarly[i]; ++i) {
        h.clock.at += 100;
        h.companion.receive(packet(beacon(kHome, "home"), h.clock));
        h.companion.receive(packet(spread_frame(kSpreadEarly, i, kHome), h.clock));
    }
    h.companion.tick();
    const auto& v = h.companion.presenter().view();
    CHECK(v.alert);
    CHECK_EQ(v.incident.kind, IncidentKind::NetworkPattern);
    CHECK_EQ(v.incident.pattern, Pattern::DeauthBroadcast);
    CHECK_EQ(v.incident.own_frames, 1u);
    CHECK(tuple_is(v.incident.top, kBroadcast, kHome, kHome, 6, 1));
    char sentence[96]{};
    CHECK(alert_sentence(v, sentence, sizeof sentence) > 0);
    CHECK_EQ(std::string(sentence), "Nearby burst also on home");
    companion::Status st{}; st.radio = companion::RadioState::Monitoring;
    for (int screen = 0; screen < 2; ++screen) {                 // the face, then the details
        companion::Frame f{}; h.companion.render(st, f);
        CHECK(has(f, "Nearby burst also on"));
        bool named = false;
        for (std::uint8_t i = 0; i < f.count; ++i) {
            const std::string text = f.lines[i].text.data();
            if (f.lines[i].color == color::red && text == "home") named = true;                // the name on its own row
            if (f.lines[i].color == color::red) CHECK(text.find(':') == std::string::npos);   // no address in red
        }
        CHECK(named);
        CHECK(!has(f, "Broadcast disconnects on your network"));
        CHECK_EQ(f.overflow, 0u);
        h.companion.input(Action::Primary);                      // blue: info
    }
    // The evidence page shows the tuple that named the picked network, in white beside the count.
    for (int i = 0; i < 12 && h.companion.presenter().details().page != DetailsPage::SignalAndEvidence; ++i) h.companion.input(Action::Primary);
    CHECK(h.companion.presenter().details().page == DetailsPage::SignalAndEvidence);
    companion::Frame f{}; h.companion.render(st, f);
    CHECK(has(f, "Seen 10 (raw 10)"));
    CHECK(has(f, ("to FF:FF from " + tail(kHome)).c_str()));
    CHECK(has(f, ("AP " + tail(kHome) + " ch6 x1").c_str()));
    CHECK_EQ(f.overflow, 0u);
}

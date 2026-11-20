// G16G passive data-path checks (TDD: written and run RED first against stub
// detectors / prefilter / meter and the pre-G16G parser; logs in
// $GUARDIAN_STORE/builds/20261117-g16g-host/red-*.log).
//
// Hand-built 802.11 data frames carrying EAPOL-Key bodies go through the real
// SecurityFrameParser into HandshakeDetector (or measurement::Monitor end to
// end); per-channel receive counts go into NoiseFloorDetector (G16J). Attack-shaped
// streams must produce exactly one observation per cooldown; benign streams
// (ordinary connects, roaming across a mesh, group re-keys, a single
// disconnect before a reconnect, retransmissions, a quiet or weak channel)
// must produce none. Generated frames are host input, never radio proof.
#include "check.hpp"
#include <algorithm>
#include "measurement.hpp"

#include "guardian/advice.hpp"
#include "guardian/presenter.hpp"
#include "guardian/security_parser.hpp"
#include "guardian/threats.hpp"

#include <array>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>

using namespace guardian;

// ---- allocation ban (same technique as threat_detectors_check) ----------------------------
namespace {
int g_ban_depth = 0;
std::size_t g_banned_allocations = 0;
struct AllocationBan {
    AllocationBan() { ++g_ban_depth; }
    ~AllocationBan() { --g_ban_depth; }
};
} // namespace
void* operator new(std::size_t n) {
    if (g_ban_depth > 0) ++g_banned_allocations;
    if (void* p = std::malloc(n ? n : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

namespace {

TimeEpoch epoch(std::uint64_t boot = 1) { TimeEpoch e{}; e.source_id[0] = 7; e.boot_id = boot; return e; }
class Clock final : public MonotonicClock {
public:
    Millis at{1000};
    Millis now() const override { return at; }
    TimeEpoch epoch() const override { return ::epoch(); }
};

constexpr Mac kBroadcast{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
constexpr Mac kHome{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
constexpr Mac kHome2{0x00, 0x11, 0x22, 0x33, 0x44, 0x56};    // approved mesh node
constexpr Mac kNeighbour{0x00, 0x66, 0x77, 0x88, 0x99, 0xaa};
constexpr Mac kPhone{0x00, 0xa0, 0xb0, 0xc0, 0xd0, 0x01};
constexpr Mac kLaptop{0x00, 0xa0, 0xb0, 0xc0, 0xd0, 0x02};
constexpr Mac kOdd{0x02, 0x99, 0x88, 0x77, 0x66, 0x55};      // a locally administered station address
Mac ap(std::uint32_t i) { return Mac{0x00, 0x24, 0x00, 0x00, static_cast<std::uint8_t>(i >> 8), static_cast<std::uint8_t>(i)}; }

struct Bytes {
    std::array<std::uint8_t, 512> b{};
    std::size_t n{};
    Bytes& u8(std::size_t v) { b[n++] = static_cast<std::uint8_t>(v); return *this; }
    Bytes& le16(std::size_t v) { u8(v & 0xff); return u8((v >> 8) & 0xff); }
    Bytes& be16(std::size_t v) { u8((v >> 8) & 0xff); return u8(v & 0xff); }
    Bytes& be64(std::uint64_t v) { for (int i = 7; i >= 0; --i) u8(static_cast<std::size_t>((v >> (8 * i)) & 0xff)); return *this; }
    Bytes& addr(const Mac& m) { for (auto x : m) u8(x); return *this; }
    Bytes& fill(std::size_t count, std::uint8_t v) { for (std::size_t i = 0; i < count; ++i) u8(v); return *this; }
};

// ---- EAPOL-Key frames ---------------------------------------------------------------------
struct Key {
    EapolMessage msg{EapolMessage::M1};
    std::uint64_t replay{1};
    bool zero_nonce{};
    bool pmkid{};             // M1: PMKID KDE in the key data
    std::size_t mic{16};
    std::uint8_t descriptor{2};
    bool qos{};
    bool order{};             // QoS + Order: 4-byte HT Control
    bool four_address{};
    bool protected_frame{};
    std::uint16_t extra_info{}; // OR-ed into Key Information
    bool group{};             // group-key message (Key Type = 0)
    std::uint16_t seq{};
    std::size_t kdl_override{0xffff}; // != 0xffff: write this key-data length field instead of the real one
    std::uint8_t eapol_type{3};
};
std::uint16_t info_for(const Key& k) {
    std::uint16_t i = 0x0002;   // descriptor version 2 (HMAC-SHA1-128 / AES)
    if (!k.group) i |= key_info::Pairwise;
    switch (k.msg) {
    case EapolMessage::M1: i |= key_info::Ack; break;
    case EapolMessage::M2: i |= key_info::Mic; break;
    case EapolMessage::M3: i |= key_info::Ack | key_info::Mic | key_info::Install | key_info::Secure | key_info::EncryptedKeyData; break;
    case EapolMessage::M4: i |= key_info::Mic | key_info::Secure; break;
    case EapolMessage::Group: i |= key_info::Ack | key_info::Mic | key_info::Secure | key_info::EncryptedKeyData; break;
    case EapolMessage::None: break;
    }
    return static_cast<std::uint16_t>(i | k.extra_info);
}
// The data frame: Ack messages travel AP -> station (FromDS), others station -> AP (ToDS).
Bytes eapol(const Mac& access_point, const Mac& station, const Key& k = {}) {
    const bool ack = (info_for(k) & key_info::Ack) != 0;
    Bytes f;
    std::uint8_t fc1 = ack ? 0x02 : 0x01;
    if (k.four_address) fc1 = 0x03;
    if (k.protected_frame) fc1 = static_cast<std::uint8_t>(fc1 | 0x40);
    if (k.order) fc1 = static_cast<std::uint8_t>(fc1 | 0x80);
    f.u8(k.qos ? 0x88 : 0x08).u8(fc1).le16(0);
    if (ack) f.addr(station).addr(access_point).addr(access_point);
    else f.addr(access_point).addr(station).addr(access_point);
    f.le16(static_cast<std::size_t>((k.seq & 0x0fff) << 4));
    if (k.four_address) f.addr(station);
    if (k.qos) f.le16(0x0007);
    if (k.qos && k.order) f.le16(0).le16(0);
    // key data
    Bytes kd;
    if (k.msg == EapolMessage::M1 && k.pmkid) {   // G16J: a keyed-hash-looking value (16 equal bytes are a tool shape now)
        static constexpr std::uint8_t hash[16] = {0x9c, 0x13, 0xe7, 0x40, 0x2b, 0xd8, 0x55, 0xa1, 0x0e, 0xf6, 0x73, 0x3a, 0xc9, 0x84, 0x1d, 0x62};
        kd.u8(0xdd).u8(20).u8(0x00).u8(0x0f).u8(0xac).u8(0x04);
        for (auto b : hash) kd.u8(b);
    }
    if (k.msg == EapolMessage::M2) { kd.u8(48).u8(20).le16(1).u8(0).u8(0x0f).u8(0xac).u8(4).le16(1).u8(0).u8(0x0f).u8(0xac).u8(4).le16(1).u8(0).u8(0x0f).u8(0xac).u8(2).le16(0); }
    if (k.msg == EapolMessage::M3 || k.msg == EapolMessage::Group) kd.fill(56, 0x33);   // encrypted, opaque
    const std::size_t body = 95 - 16 + k.mic + kd.n;
    f.u8(0xaa).u8(0xaa).u8(0x03).u8(0x00).u8(0x00).u8(0x00).u8(0x88).u8(0x8e);
    f.u8(2).u8(k.eapol_type).be16(body);
    f.u8(k.descriptor).be16(info_for(k)).be16(16).be64(k.replay);
    if (k.zero_nonce || k.msg == EapolMessage::M4) f.fill(32, 0); else f.fill(32, 0x42);
    f.fill(16, 0).fill(8, 0).fill(8, 0);                    // IV, RSC, reserved
    f.fill(k.mic, k.msg == EapolMessage::M1 ? 0 : 0x77);     // MIC
    f.be16(k.kdl_override != 0xffff ? k.kdl_override : kd.n);
    for (std::size_t i = 0; i < kd.n; ++i) f.u8(kd.b[i]);
    return f;
}
Key msg(EapolMessage m, std::uint64_t replay = 1) { Key k; k.msg = m; k.replay = replay; return k; }

// G16J: the sequence number on air is seq * 37 + 11, so consecutive test numbers do not make the
// rising-sequence tool shape (equal numbers stay equal: Retry copies still deduplicate).
Bytes disconnect(const Mac& from, const Mac& to, const Mac& bssid, std::uint32_t seq, bool retry = false, bool disassoc = false) {
    Bytes f; f.u8(disassoc ? 0xa0 : 0xc0).u8(retry ? 0x08 : 0).le16(0).addr(to).addr(from).addr(bssid).le16(((seq * 37 + 11) & 0x0fff) << 4);
    f.le16(7);
    return f;
}
Bytes beacon(const Mac& bssid, const char* name) {
    Bytes f; f.u8(0x80).u8(0).le16(0).addr(kBroadcast).addr(bssid).addr(bssid).le16(0);
    f.fill(8, 0).le16(100).le16(0x0011);
    const auto len = std::strlen(name); f.u8(0).u8(len); for (std::size_t i = 0; i < len; ++i) f.u8(static_cast<std::uint8_t>(name[i]));
    f.u8(3).u8(1).u8(6);
    f.u8(48).u8(20).le16(1).u8(0).u8(0x0f).u8(0xac).u8(4).le16(1).u8(0).u8(0x0f).u8(0xac).u8(4).le16(1).u8(0).u8(0x0f).u8(0xac).u8(2).le16(0);
    return f;
}

RxMeta meta(Millis at, std::uint64_t boot = 1) {
    RxMeta m{};
    m.acquired = Instant{epoch(boot), at, true};
    m.origin = Origin::LiveRadio; m.status = RxStatus::Ok; m.channel = 6;
    m.rssi_dbm = -50; m.rssi_valid = true;
    return m;
}
ParseResult parse(const Bytes& f, bool truncated = false) {
    SecurityFrameParser p;
    return p.parse(FrameSpan{f.b.data(), static_cast<std::uint16_t>(f.n), truncated}, meta(1000));
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

ApprovedAp home_ap() {
    ApprovedAp a{}; a.network.bssid = kHome; a.network.ssid_size = 4; std::memcpy(a.network.ssid.data(), "home", 4); return a;
}
Network home_network() { return home_ap().network; }

struct Rig {
    ApprovedScope scope{};
    Sink sink{};
    SecurityFrameParser parser{};
    std::uint32_t parsed_bad{};
    Rig() {
        scope.select(home_ap());
        ApprovedAp mesh = home_ap(); mesh.network.bssid = kHome2; scope.approve(mesh);
    }
    void feed(FrameDetector& d, const Bytes& f, Millis at) {
        const FrameSpan span{f.b.data(), static_cast<std::uint16_t>(f.n), false};
        const auto m = meta(at);
        const auto p = parser.parse(span, m);
        if (p.status == ParseStatus::Malformed || p.status == ParseStatus::Truncated) ++parsed_bad;
        d.on_frame(span, m, p, sink);
    }
    void tick(FrameDetector& d, Millis at) { d.on_tick(Instant{epoch(), at, true}, sink); }
    // A complete, ordinary 4-way handshake (M1..M4) between `access_point` and `station`.
    void handshake(FrameDetector& d, const Mac& access_point, const Mac& station, Millis at, std::uint64_t replay = 1) {
        feed(d, eapol(access_point, station, msg(EapolMessage::M1, replay)), at);
        feed(d, eapol(access_point, station, msg(EapolMessage::M2, replay)), at + 5);
        feed(d, eapol(access_point, station, msg(EapolMessage::M3, replay + 1)), at + 10);
        feed(d, eapol(access_point, station, msg(EapolMessage::M4, replay + 1)), at + 15);
    }
};

ChannelLoadSample load(Millis at, std::uint8_t channel, std::uint32_t valid, std::uint32_t errors, int rssi = -50, bool fcs = true,
                       Millis listened = 1000, std::uint64_t boot = 1) {
    ChannelLoadSample s{};
    s.sampled_at = Instant{epoch(boot), at, true}; s.origin = Origin::LiveRadio; s.channel = channel;
    s.window_ms = 1000; s.listened_ms = listened; s.valid_frames = valid; s.error_frames = errors;
    s.error_rssi_sum = rssi * static_cast<std::int32_t>(errors); s.error_rssi_count = errors; s.fcs_supported = fcs;
    return s;
}
// G16J: one second on `channel` in which `frames` frames each carried the noise-floor reading `noise` (dBm).
ChannelLoadSample air(Millis at, std::uint8_t channel, int noise, std::uint32_t frames = 40, std::uint32_t errors = 0, bool fcs = false,
                      Millis listened = 1000, std::uint64_t boot = 1) {
    ChannelLoadSample s = load(at, channel, frames - std::min(frames, errors), errors, -50, fcs, listened, boot);
    s.noise_sum = noise * static_cast<std::int32_t>(frames); s.noise_count = frames;
    return s;
}

measurement::Packet packet(const Bytes& f, Millis at) {
    measurement::Packet p{};
    std::memcpy(p.bytes.data(), f.b.data(), f.n);
    p.size = static_cast<std::uint16_t>(f.n);
    p.meta = meta(at);
    return p;
}

} // namespace

// =========================================================================================
// EAPOL-Key decoding (parser)
// =========================================================================================
GUARDIAN_CASE(eapol_m1_with_pmkid_kde_is_decoded) {
    Key k = msg(EapolMessage::M1, 7); k.pmkid = true;
    const auto r = parse(eapol(kHome, kPhone, k));
    CHECK_EQ(r.kind, FrameKind::EapolData);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.eapol.state, ElementState::Valid);
    CHECK_EQ(r.eapol.message, EapolMessage::M1);
    CHECK_EQ(r.eapol.descriptor, 2u);
    CHECK_EQ(r.eapol.version, 2u);
    CHECK_EQ(r.eapol.replay_counter, 7u);
    CHECK_EQ(r.eapol.key_length, 16u);
    CHECK(!r.eapol.nonce_zero);
    CHECK_EQ(r.eapol.mic_size, 16u);
    CHECK(r.eapol.key_data_known);
    CHECK_EQ(r.eapol.key_data_length, 22u);
    CHECK(r.eapol.pmkid_present);
    CHECK(r.eapol.authenticator == kHome);
    CHECK(r.eapol.supplicant == kPhone);
    CHECK(r.header_valid);
}

GUARDIAN_CASE(eapol_m2_m3_m4_and_group_messages_are_classified) {
    const auto m2 = parse(eapol(kHome, kPhone, msg(EapolMessage::M2)));
    CHECK_EQ(m2.status, ParseStatus::Complete);
    CHECK_EQ(m2.eapol.message, EapolMessage::M2);
    CHECK(m2.eapol.authenticator == kHome);   // ToDS: Address 1 is the AP
    CHECK(m2.eapol.supplicant == kPhone);
    CHECK(!m2.eapol.pmkid_present);
    CHECK_EQ(m2.eapol.key_data_length, 22u);
    const auto m3 = parse(eapol(kHome, kPhone, msg(EapolMessage::M3, 2)));
    CHECK_EQ(m3.eapol.message, EapolMessage::M3);
    CHECK(m3.eapol.key_data_encrypted);
    CHECK(!m3.eapol.pmkid_present);
    CHECK_EQ(m3.eapol.replay_counter, 2u);
    const auto m4 = parse(eapol(kHome, kPhone, msg(EapolMessage::M4, 2)));
    CHECK_EQ(m4.eapol.message, EapolMessage::M4);
    CHECK_EQ(m4.eapol.key_data_length, 0u);
    CHECK(m4.eapol.nonce_zero);              // M4 carries no nonce: never a "fake M1"
    Key g = msg(EapolMessage::Group); g.group = true;
    CHECK_EQ(parse(eapol(kHome, kPhone, g)).eapol.message, EapolMessage::Group);
    Key req = msg(EapolMessage::M2); req.extra_info = key_info::Request;
    CHECK_EQ(parse(eapol(kHome, kPhone, req)).eapol.message, EapolMessage::None);
    // WPA1 M4 (descriptor 254) has no Secure bit and no key data: still M4.
    Key wpa = msg(EapolMessage::M2); wpa.descriptor = 254;
    const auto w2 = parse(eapol(kHome, kPhone, wpa));
    CHECK_EQ(w2.eapol.descriptor, 254u);
    CHECK_EQ(w2.eapol.message, EapolMessage::M2);
}

GUARDIAN_CASE(eapol_zero_anonce_and_header_variants) {
    Key z = msg(EapolMessage::M1); z.zero_nonce = true;
    CHECK(parse(eapol(kHome, kPhone, z)).eapol.nonce_zero);
    Key q = msg(EapolMessage::M1); q.qos = true; q.pmkid = true;
    const auto rq = parse(eapol(kHome, kPhone, q));
    CHECK_EQ(rq.eapol.state, ElementState::Valid);
    CHECK(rq.eapol.pmkid_present);
    Key ho = q; ho.order = true;
    CHECK_EQ(parse(eapol(kHome, kPhone, ho)).eapol.message, EapolMessage::M1);
    Key four = msg(EapolMessage::M1); four.four_address = true;
    CHECK_EQ(parse(eapol(kHome, kPhone, four)).eapol.state, ElementState::Valid);
    Key mic24 = msg(EapolMessage::M2); mic24.mic = 24;
    const auto r24 = parse(eapol(kHome, kPhone, mic24));
    CHECK_EQ(r24.eapol.mic_size, 24u);
    CHECK(r24.eapol.key_data_known);
    CHECK_EQ(r24.eapol.key_data_length, 22u);
}

GUARDIAN_CASE(malformed_or_cut_eapol_keys_never_yield_facts) {
    // Body length larger than the bytes present.
    Bytes cut = eapol(kHome, kPhone, msg(EapolMessage::M1)); cut.n -= 10;
    const auto rc = parse(cut);
    CHECK_EQ(rc.status, ParseStatus::Malformed);
    CHECK_EQ(rc.eapol.state, ElementState::Malformed);
    CHECK_EQ(rc.eapol.message, EapolMessage::None);
    CHECK(!rc.eapol.pmkid_present);
    // The same bytes flagged as a truncated copy: Truncated, never Malformed.
    const auto rt = parse(cut, true);
    CHECK_EQ(rt.status, ParseStatus::Truncated);
    CHECK_EQ(rt.eapol.state, ElementState::Truncated);
    // A key body shorter than its fixed fields.
    Bytes tiny;
    tiny.u8(0x08).u8(0x02).le16(0).addr(kPhone).addr(kHome).addr(kHome).le16(0);
    tiny.u8(0xaa).u8(0xaa).u8(0x03).u8(0x00).u8(0x00).u8(0x00).u8(0x88).u8(0x8e).u8(2).u8(3).be16(40).u8(2).be16(0x008a).fill(37, 0);
    const auto rs = parse(tiny);
    CHECK_EQ(rs.status, ParseStatus::Malformed);
    CHECK_EQ(rs.eapol.message, EapolMessage::None);
    // A key-data length that fits no MIC size: fields valid, key data unknown, no PMKID claimed.
    Key bad = msg(EapolMessage::M1); bad.pmkid = true; bad.kdl_override = 200;
    const auto rb = parse(eapol(kHome, kPhone, bad));
    CHECK_EQ(rb.eapol.state, ElementState::Valid);
    CHECK(!rb.eapol.key_data_known);
    CHECK_EQ(rb.eapol.mic_size, 0u);
    CHECK(!rb.eapol.pmkid_present);
    // A PMKID-looking KDE with the wrong length is not a PMKID.
    Bytes odd = eapol(kHome, kPhone, [] { Key k = msg(EapolMessage::M1); k.pmkid = true; return k; }());
    odd.b[odd.n - 21] = 19;   // KDE length byte (was 20)
    CHECK(!parse(odd).eapol.pmkid_present);
    // Encrypted key data is never read.
    Key enc = msg(EapolMessage::M1); enc.pmkid = true; enc.extra_info = key_info::EncryptedKeyData;
    CHECK(!parse(eapol(kHome, kPhone, enc)).eapol.pmkid_present);
    // A non-key EAPOL packet (EAP) is recognised and left undecoded.
    Key eap = msg(EapolMessage::M1); eap.eapol_type = 0;
    const auto re = parse(eapol(kHome, kPhone, eap));
    CHECK_EQ(re.kind, FrameKind::EapolData);
    CHECK_EQ(re.status, ParseStatus::Unsupported);
    CHECK_EQ(re.eapol.state, ElementState::Absent);
    // An unknown descriptor type is not decoded.
    Key d = msg(EapolMessage::M1); d.descriptor = 1;
    CHECK_EQ(parse(eapol(kHome, kPhone, d)).eapol.state, ElementState::Absent);
    // Protected data is never inspected.
    Key p = msg(EapolMessage::M1); p.protected_frame = true;
    const auto rp = parse(eapol(kHome, kPhone, p));
    CHECK_EQ(rp.kind, FrameKind::Data);
    CHECK_EQ(rp.eapol.state, ElementState::Absent);
}

// =========================================================================================
// Receive-callback prefilter and per-channel load meter (adapter, SDK-free)
// =========================================================================================
GUARDIAN_CASE(prefilter_keeps_exactly_what_the_parser_calls_eapol) {
    std::array<Bytes, 10> frames{};
    Key q = msg(EapolMessage::M2); q.qos = true;
    Key ho = q; ho.order = true;
    Key four = msg(EapolMessage::M1); four.four_address = true;
    Key prot = msg(EapolMessage::M1); prot.protected_frame = true;
    frames[0] = eapol(kHome, kPhone, msg(EapolMessage::M1));
    frames[1] = eapol(kHome, kPhone, q);
    frames[2] = eapol(kHome, kPhone, ho);
    frames[3] = eapol(kHome, kPhone, four);
    frames[4] = eapol(kHome, kPhone, prot);
    frames[5] = beacon(kHome, "home");
    frames[6] = disconnect(kHome, kPhone, kHome, 1);
    frames[7] = eapol(kHome, kPhone, msg(EapolMessage::M1)); frames[7].b[30] = 0x08; frames[7].b[31] = 0x00;   // IPv4, not EAPOL
    frames[8] = eapol(kHome, kPhone, msg(EapolMessage::M1)); frames[8].n = 30;                                  // cut inside LLC
    frames[9].u8(0x08).u8(0x02).le16(0);                                                                         // 4 bytes
    std::size_t kept = 0;
    for (const auto& f : frames) {
        const bool pre = measurement::eapol_candidate(f.b.data(), f.n);
        const bool parsed = parse(f).kind == FrameKind::EapolData;
        CHECK_EQ(pre, parsed);
        kept += pre;
    }
    CHECK_EQ(kept, 4u);
    CHECK(!measurement::eapol_candidate(nullptr, 100));
}

GUARDIAN_CASE(load_meter_samples_per_channel_counts_and_listening) {
    static measurement::ChannelLoadMeter m;   // atomics: not copyable, keep it static
    m.tuned(6, 1000);
    for (int i = 0; i < 40; ++i) m.valid(6, -96);
    for (int i = 0; i < 20; ++i) m.error(6, -50, -90);
    m.valid(0, -96); m.error(15, -40, -96); m.valid(200, -96);   // not a 2.4 GHz channel: ignored
    std::array<ChannelLoadSample, 4> out{};
    std::size_t n = m.sample(Instant{epoch(), 2000, true}, Origin::LiveRadio, true, out.data(), out.size());
    CHECK_EQ(n, 1u);
    CHECK_EQ(out[0].channel, 6u);
    CHECK_EQ(out[0].valid_frames, 40u);
    CHECK_EQ(out[0].error_frames, 20u);
    CHECK_EQ(out[0].error_rssi_sum, -1000);
    CHECK_EQ(out[0].error_rssi_count, 20u);
    CHECK_EQ(out[0].noise_count, 60u);                    // G16J: every frame, valid or flagged, carries a noise reading
    CHECK_EQ(out[0].noise_sum, 40 * -96 + 20 * -90);
    CHECK_EQ(out[0].listened_ms, 1000u);
    CHECK_EQ(out[0].window_ms, 1000u);
    CHECK(out[0].fcs_supported);
    CHECK(out[0].sampled_at.valid());
    CHECK_EQ(m.valid_total(), 40u);
    CHECK_EQ(m.error_total(), 20u);
    // Still tuned, nothing received: a listened sample with zero counts.
    n = m.sample(Instant{epoch(), 3000, true}, Origin::LiveRadio, true, out.data(), out.size());
    CHECK_EQ(n, 1u);
    CHECK_EQ(out[0].listened_ms, 1000u);
    CHECK_EQ(out[0].valid_frames + out[0].error_frames, 0u);
    CHECK_EQ(out[0].noise_count, 0u);                     // counts are per interval
    CHECK_EQ(out[0].noise_sum, 0);
    // Hop: 300 ms on 6, then 11 for the rest.
    m.untuned(3300); m.tuned(11, 3300);
    for (int i = 0; i < 3; ++i) m.valid(11, -95);
    n = m.sample(Instant{epoch(), 4000, true}, Origin::LiveRadio, false, out.data(), out.size());
    CHECK_EQ(n, 2u);
    for (std::size_t i = 0; i < n; ++i) {
        CHECK(!out[i].fcs_supported);
        if (out[i].channel == 6) CHECK_EQ(out[i].listened_ms, 300u);
        else { CHECK_EQ(out[i].channel, 11u); CHECK_EQ(out[i].listened_ms, 700u); CHECK_EQ(out[i].valid_frames, 3u); }
    }
    // Not listening and nothing counted: no sample. Capacity bounds the output.
    m.untuned(4000);
    CHECK_EQ(m.sample(Instant{epoch(), 5000, true}, Origin::LiveRadio, true, out.data(), out.size()), 0u);
    m.tuned(1, 5000); m.valid(1, -95); m.valid(2, -95); m.valid(3, -95);
    CHECK_EQ(m.sample(Instant{epoch(), 6000, true}, Origin::LiveRadio, true, out.data(), 2), 2u);
}

// =========================================================================================
// (13) Unanswered handshake starts to one station from many APs
// =========================================================================================
GUARDIAN_CASE(pmkid_harvest_fires_after_the_settle_time_once_per_cooldown) {
    Rig r; HandshakeDetector d(r.scope);
    CHECK(d.configured());
    Key k = msg(EapolMessage::M1); k.pmkid = true;
    r.feed(d, eapol(ap(1), kOdd, k), 10000);
    r.feed(d, eapol(ap(2), kOdd, k), 10100);
    r.feed(d, eapol(ap(3), kOdd, k), 10200);
    CHECK_EQ(r.parsed_bad, 0u);
    r.tick(d, 11650);                       // ap(3) has not settled yet: 2 unanswered
    CHECK_EQ(r.sink.count, 0u);
    r.tick(d, 11750);
    CHECK_EQ(count_pattern(r.sink, Pattern::PmkidHarvest), 1u);
    const auto& o = r.sink.last();
    CHECK_EQ(o.scope, IncidentScope::Area);
    CHECK_EQ(o.family, DetectorFamily::Auth);
    CHECK_EQ(o.count, 3u);
    CHECK_EQ(o.threshold, 3u);
    CHECK_EQ(o.window_ms, 10000u);
    CHECK_EQ(o.corroborating, 3u);           // all three carried a PMKID KDE
    CHECK_EQ(o.distinct_sources, 1u);
    CHECK(o.sources_random);                 // the station address is locally administered
    // More starts inside the cooldown: no second observation.
    for (std::uint32_t i = 4; i < 10; ++i) r.feed(d, eapol(ap(i), kOdd, k), 12000 + i * 100);
    r.tick(d, 15000);
    CHECK_EQ(count_pattern(r.sink, Pattern::PmkidHarvest), 1u);
    // After the cooldown, a new round reports again.
    for (std::uint32_t i = 20; i < 23; ++i) r.feed(d, eapol(ap(i), kOdd, k), 60000 + i * 10);
    r.tick(d, 62000);
    CHECK_EQ(count_pattern(r.sink, Pattern::PmkidHarvest), 2u);
}

GUARDIAN_CASE(answered_starts_and_two_aps_never_fire) {
    Rig r; HandshakeDetector d(r.scope);
    // A phone roaming across three mesh nodes: every M1 is answered by its M2.
    for (std::uint32_t i = 1; i <= 3; ++i) r.handshake(d, ap(i), kPhone, 10000 + i * 500);
    // Starts to another station from only two APs.
    r.feed(d, eapol(ap(7), kLaptop, msg(EapolMessage::M1)), 20000);
    r.feed(d, eapol(ap(8), kLaptop, msg(EapolMessage::M1)), 20100);
    // An AP retrying M1 to an absent station: one AP, many starts.
    for (std::uint64_t i = 0; i < 6; ++i) r.feed(d, eapol(ap(9), kOdd, msg(EapolMessage::M1, i + 1)), 30000 + i * 1000);
    // Three starts spread over more than the window.
    r.feed(d, eapol(ap(11), kLaptop, msg(EapolMessage::M1)), 50000);
    r.feed(d, eapol(ap(12), kLaptop, msg(EapolMessage::M1)), 56000);
    r.feed(d, eapol(ap(13), kLaptop, msg(EapolMessage::M1)), 62000);
    for (Millis t = 10000; t <= 70000; t += 250) r.tick(d, t);
    CHECK_EQ(r.parsed_bad, 0u);
    CHECK_EQ(r.sink.count, 0u);
}

GUARDIAN_CASE(pmkid_harvest_touching_the_selected_network_is_network_scope) {
    Rig r; HandshakeDetector d(r.scope);
    r.feed(d, eapol(kHome, kOdd, msg(EapolMessage::M1)), 10000);
    r.feed(d, eapol(ap(2), kOdd, msg(EapolMessage::M1)), 10100);
    r.feed(d, eapol(ap(3), kOdd, msg(EapolMessage::M1)), 10200);
    r.tick(d, 12000);
    CHECK_EQ(r.sink.count, 1u);
    CHECK_EQ(r.sink.last().scope, IncidentScope::Network);
    CHECK_EQ(r.sink.last().kind, IncidentKind::NetworkPattern);
    CHECK(r.sink.last().affected == home_network());
    CHECK_EQ(r.sink.last().corroborating, 0u);   // no PMKID KDE in these starts
}

// =========================================================================================
// (14) Handshake start with an all-zero ANonce
// =========================================================================================
GUARDIAN_CASE(fake_m1_fires_by_scope_and_ordinary_m1_never) {
    Rig r; HandshakeDetector d(r.scope);
    for (std::uint32_t i = 0; i < 20; ++i) r.handshake(d, ap(i), kPhone, 1000 + i * 3000);
    CHECK_EQ(r.sink.count, 0u);
    Key z = msg(EapolMessage::M1); z.zero_nonce = true;
    r.feed(d, eapol(kNeighbour, kPhone, z), 70000);
    CHECK_EQ(count_pattern(r.sink, Pattern::FakeM1), 1u);
    CHECK_EQ(r.sink.last().scope, IncidentScope::Area);
    CHECK(r.sink.last().bssid == kNeighbour);
    r.feed(d, eapol(kNeighbour, kPhone, z), 71000);   // cooling
    CHECK_EQ(count_pattern(r.sink, Pattern::FakeM1), 1u);
    r.feed(d, eapol(kHome, kPhone, z), 72000);
    CHECK_EQ(count_pattern(r.sink, Pattern::FakeM1), 2u);
    CHECK_EQ(r.sink.last().scope, IncidentScope::Network);
    CHECK(r.sink.last().bssid == kHome);
}

// =========================================================================================
// (15) Disconnect burst on the selected network, then a fresh handshake
// =========================================================================================
GUARDIAN_CASE(deauth_burst_then_handshake_on_the_selected_network_fires_once) {
    Rig r; HandshakeDetector d(r.scope);
    for (std::uint32_t i = 0; i < 6; ++i) r.feed(d, disconnect(kHome, kPhone, kHome, 100 + i), 10000 + i * 100);
    CHECK_EQ(r.sink.count, 0u);                // a burst alone is the DisconnectDetector's
    r.feed(d, eapol(kHome, kPhone, msg(EapolMessage::M1, 9)), 14000);
    CHECK_EQ(r.sink.count, 0u);                // one message is not an exchange
    r.feed(d, eapol(kHome, kPhone, msg(EapolMessage::M2, 9)), 14010);
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthHandshake), 1u);
    const auto& o = r.sink.last();
    CHECK_EQ(o.scope, IncidentScope::Network);
    CHECK_EQ(o.kind, IncidentKind::NetworkPattern);
    CHECK(o.bssid == kHome);
    CHECK_EQ(o.count, 6u);
    CHECK_EQ(o.threshold, 5u);
    CHECK_EQ(o.corroborating, 2u);
    r.feed(d, eapol(kHome, kPhone, msg(EapolMessage::M3, 10)), 14020);
    r.feed(d, eapol(kHome, kPhone, msg(EapolMessage::M4, 10)), 14030);
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthHandshake), 1u);
    // A broadcast burst on the approved mesh node, then any station's exchange.
    for (std::uint32_t i = 0; i < 5; ++i) r.feed(d, disconnect(kHome2, kBroadcast, kHome2, 300 + i, false, true), 20000 + i * 50);
    r.handshake(d, kHome2, kLaptop, 27000);
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthHandshake), 2u);
    CHECK(r.sink.last().bssid == kHome2);
}

// G22 (independent review, finding D1): one disconnect header with the Retry bit, repeated, counted as one
// frame for ever, so the burst before a captured handshake was never a burst.
GUARDIAN_CASE(retry_bit_flood_then_handshake_on_the_selected_network_fires) {
    Rig r; HandshakeDetector d(r.scope);
    for (std::uint32_t i = 0; i < 100; ++i) r.feed(d, disconnect(kHome, kPhone, kHome, 100, true), 10000 + i * 20);   // ONE header, 2 s
    r.feed(d, eapol(kHome, kPhone, msg(EapolMessage::M1, 9)), 14000);
    r.feed(d, eapol(kHome, kPhone, msg(EapolMessage::M2, 9)), 14010);
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthHandshake), 1u);
    CHECK_EQ(r.parsed_bad, 0u);
}

GUARDIAN_CASE(normal_reconnects_never_fire) {
    Rig r; HandshakeDetector d(r.scope);
    // 1. A phone leaves (one disassociation) and comes back.
    r.feed(d, disconnect(kPhone, kHome, kHome, 1, false, true), 1000);
    r.handshake(d, kHome, kPhone, 3000);
    // 2. The AP kicks an idle client once, with six retransmissions of that frame.
    r.feed(d, disconnect(kHome, kLaptop, kHome, 50), 10000);
    for (int i = 0; i < 6; ++i) r.feed(d, disconnect(kHome, kLaptop, kHome, 50, true), 10000 + 20 * (i + 1));
    r.handshake(d, kHome, kLaptop, 12000);
    // 3. Periodic re-keys: pairwise and group handshakes with no disconnects.
    for (std::uint64_t i = 0; i < 10; ++i) {
        r.handshake(d, kHome, kPhone, 20000 + i * 3000, 10 + 2 * i);
        Key g = msg(EapolMessage::Group, 50 + i); g.group = true;
        r.feed(d, eapol(kHome, kPhone, g), 20500 + i * 3000);
    }
    // 4. A burst, then the reconnect more than 8 s after its last frame.
    for (std::uint32_t i = 0; i < 6; ++i) r.feed(d, disconnect(kHome, kPhone, kHome, 200 + i), 60000 + i * 100);
    r.handshake(d, kHome, kPhone, 60500 + 8600);
    // 5. A burst aimed at the phone, then only the laptop re-keys.
    for (std::uint32_t i = 0; i < 6; ++i) r.feed(d, disconnect(kHome, kPhone, kHome, 300 + i), 80000 + i * 100);
    r.handshake(d, kHome, kLaptop, 81000);
    // 6. A burst on a neighbour's AP and its client reconnecting (another task's area rule).
    for (std::uint32_t i = 0; i < 10; ++i) r.feed(d, disconnect(kNeighbour, kPhone, kNeighbour, 400 + i), 100000 + i * 100);
    r.handshake(d, kNeighbour, kPhone, 101500);
    // 7. A burst followed only by group re-keys.
    for (std::uint32_t i = 0; i < 6; ++i) r.feed(d, disconnect(kHome, kBroadcast, kHome, 500 + i), 120000 + i * 100);
    for (std::uint64_t i = 0; i < 3; ++i) { Key g = msg(EapolMessage::Group, 90 + i); g.group = true; r.feed(d, eapol(kHome, kPhone, g), 121000 + i * 100); }
    for (Millis t = 1000; t <= 130000; t += 500) r.tick(d, t);
    CHECK_EQ(r.parsed_bad, 0u);
    CHECK_EQ(r.sink.count, 0u);
}

GUARDIAN_CASE(malformed_keys_never_count) {
    Rig r; HandshakeDetector d(r.scope);
    for (std::uint32_t i = 1; i <= 5; ++i) {
        Bytes cut = eapol(ap(i), kOdd, msg(EapolMessage::M1)); cut.n -= 12;
        r.feed(d, cut, 10000 + i * 100);
        Key z = msg(EapolMessage::M1); z.zero_nonce = true; z.kdl_override = 999;   // fields valid, key data unknown
        Bytes zero = eapol(ap(i), kOdd, z); zero.n -= 3;                               // ... and cut: malformed
        r.feed(d, zero, 10050 + i * 100);
    }
    r.tick(d, 20000);
    CHECK_EQ(r.parsed_bad, 10u);
    CHECK_EQ(r.sink.count, 0u);
    const auto rep = d.report(Instant{epoch(), 20000, true});
    CHECK_EQ(rep.events_total, 0u);
    CHECK_EQ(rep.frames_seen, 10u);
}

GUARDIAN_CASE(unavailable_or_foreign_input_counts_nothing) {
    Rig r; HandshakeDetector d(r.scope);
    d.set_available(false);
    CHECK(!d.report(Instant{epoch(), 1000, true}).configured);
    for (std::uint32_t i = 1; i <= 3; ++i) r.feed(d, eapol(ap(i), kOdd, msg(EapolMessage::M1)), 10000 + i);
    r.tick(d, 20000);
    CHECK_EQ(r.sink.count, 0u);
    d.set_available(true);
    CHECK(d.report(Instant{epoch(), 1000, true}).configured);
    // A tick from another timebase cannot settle anything.
    for (std::uint32_t i = 1; i <= 3; ++i) r.feed(d, eapol(ap(i), kOdd, msg(EapolMessage::M1)), 30000 + i);
    d.on_tick(Instant{epoch(2), 40000, true}, r.sink);
    CHECK_EQ(r.sink.count, 0u);
    r.tick(d, 40000);
    CHECK_EQ(r.sink.count, 1u);
    // Limits are validated.
    ThreatLimits bad{}; bad.harvest_bssids = 0;
    CHECK(!d.accepts(bad));
    bad = ThreatLimits{}; bad.harvest_bssids = HandshakeDetector::start_capacity + 1;
    CHECK(!d.accepts(bad));
    bad = ThreatLimits{}; bad.reconnect_messages = 5;
    CHECK(!d.accepts(bad));
    bad = ThreatLimits{}; bad.noise_rise_db = 0;
    CHECK(!ThreatDetectors(r.scope).configure(bad));
    CHECK(d.accepts(ThreatLimits{}));
}

// =========================================================================================
// (16) G16J: noise floor on a channel (replaces the G16G frame-loss rule)
// =========================================================================================
GUARDIAN_CASE(noise_floor_rise_held_fires_once_per_channel_per_cooldown) {
    ApprovedScope scope; Sink sink; NoiseFloorDetector d(scope);
    CHECK(d.configured());
    Millis t = 10000;
    for (int i = 0; i < 60; ++i, t += 1000) d.sample(air(t, 6, -96 + (i % 3) - 1), sink);   // a quiet minute around -96 dBm
    CHECK_EQ(sink.count, 0u);
    // The floor jumps 10 dB and stays: the first raised second starts the hold, the one 3 s later closes it.
    const Millis rise = t;
    for (int i = 0; i < 100; ++i, t += 1000) d.sample(air(t, 6, -86, 40, 25, true), sink);
    CHECK_EQ(count_pattern(sink, Pattern::NoiseFloor), 3u);        // 100 s: once, then after each 45 s cooldown
    const auto& o = sink.got[0];
    CHECK_EQ(o.scope, IncidentScope::Area);
    CHECK_EQ(o.family, DetectorFamily::Jamming);
    CHECK_EQ(o.channel, 6u);
    CHECK_EQ(o.count, 10u);                 // the rise in dB above the channel's own average
    CHECK_EQ(o.threshold, 8u);
    CHECK_EQ(o.window_ms, 3000u);
    CHECK_EQ(o.acquired.at, rise + 3000);
    CHECK_EQ(o.corroborating, 4u * 25u);    // receive-error frames in the held seconds: evidence text only
    CHECK_EQ(o.raw_frames, 4u * 40u);
    CHECK(o.coverage_known);
    // A long rise never becomes the new normal: after 100 s raised, falling back and rising again still reports.
    for (int i = 0; i < 60; ++i, t += 1000) d.sample(air(t, 6, -96), sink);
    const std::size_t before = count_pattern(sink, Pattern::NoiseFloor);
    for (int i = 0; i < 5; ++i, t += 1000) d.sample(air(t, 6, -85), sink);
    CHECK_EQ(count_pattern(sink, Pattern::NoiseFloor), before + 1);
    // Another channel has its own average and its own observation.
    for (int i = 0; i < 30; ++i, t += 1000) d.sample(air(t, 11, -92), sink);
    for (int i = 0; i < 5; ++i, t += 1000) d.sample(air(t, 11, -80), sink);
    CHECK_EQ(sink.last().channel, 11u);
    CHECK_EQ(sink.last().count, 12u);
    // The rule needs no checksum-failed delivery (data path off): the readings come with ordinary frames.
    CHECK(!air(1, 6, -96).fcs_supported);
}

GUARDIAN_CASE(noise_floor_rule_boundaries_never_fire) {
    ApprovedScope scope; Sink sink; NoiseFloorDetector d(scope);
    Millis t = 10000;
    for (int i = 0; i < 60; ++i, t += 1000) d.sample(air(t, 6, -96), sink);
    for (int i = 0; i < 20; ++i, t += 1000) d.sample(air(t, 6, -89), sink);                 // +7 dB: below the rise
    for (int i = 0; i < 30; ++i, t += 1000) d.sample(air(t, 6, -96), sink);
    for (int i = 0; i < 3; ++i, t += 1000) d.sample(air(t, 6, -80), sink);                  // +16 dB for 2 s (3 samples span 2 s), then gone
    for (int i = 0; i < 30; ++i, t += 1000) d.sample(air(t, 6, -96), sink);
    for (int i = 0; i < 20; ++i, t += 1000) d.sample(air(t, 6, -80, 4), sink);              // 4 frames a second: no usable reading
    for (int i = 0; i < 20; ++i, t += 1000) d.sample(air(t, 6, -80, 40, 0, false, 0), sink); // not listening
    for (int i = 0; i < 20; ++i, t += 1000) d.sample(air(t, 6, -80, 40, 0, false, 1000, 2), sink);   // another timebase
    CHECK_EQ(sink.count, 0u);
    // Slow drift (1 dB every 20 s for 5 min): the average follows it.
    for (int i = 0; i < 300; ++i, t += 1000) d.sample(air(t, 6, -96 + i / 20), sink);
    CHECK_EQ(sink.count, 0u);
    // A channel heard for 5 s only has no average yet.
    for (int i = 0; i < 5; ++i, t += 1000) d.sample(air(t, 3, -96), sink);
    for (int i = 0; i < 5; ++i, t += 1000) d.sample(air(t, 3, -70), sink);
    CHECK_EQ(sink.count, 0u);
    // Exactly at the edges it does fire: +8 dB, held 3 s.
    for (int i = 0; i < 60; ++i, t += 1000) d.sample(air(t, 9, -96), sink);
    for (int i = 0; i < 4; ++i, t += 1000) d.sample(air(t, 9, -88), sink);
    CHECK_EQ(count_pattern(sink, Pattern::NoiseFloor), 1u);
    CHECK_EQ(sink.last().channel, 9u);
    CHECK_EQ(sink.last().count, 8u);
    ThreatLimits bad{}; bad.noise_rise_db = 0;
    CHECK(!d.accepts(bad));
    bad = ThreatLimits{}; bad.noise_average_ms = 2000;       // shorter than the hold
    CHECK(!d.accepts(bad));
    bad = ThreatLimits{}; bad.noise_baseline_samples = NoiseFloorDetector::history + 1;
    CHECK(!d.accepts(bad));
}

// =========================================================================================
// Monitor end to end, wording, allocation, benign stream
// =========================================================================================
GUARDIAN_CASE(monitor_data_path_off_is_honest_and_on_reports_through_core) {
    Clock clock; measurement::Monitor m(clock, profiles::all_2g4_channels());
    CHECK_EQ(m.detectors().size(), 2u + ThreatDetectors::count);
    CHECK(m.detectors().size() < DetectorRegistry::capacity);   // adapters can still add detectors
    CHECK_EQ(m.detectors().refused(), 0u);
    CHECK(!m.data_path());
    auto radar = m.radar();
    // G16J: the noise-floor watch needs no data path (every received frame carries a reading);
    // the handshake watch does, and is not shown as measuring while it is unfed.
    CHECK(radar.families[static_cast<std::size_t>(DetectorFamily::Jamming)].registered);
    {
        char off[2048];
        CHECK(m.status_text(off, sizeof off) > 0u);
        CHECK(std::strstr(off, "handshake:frames=0,in_window=0,events=0,incidents=0,last=none,cooldown=0,unconfigured") != nullptr);
        CHECK(std::strstr(off, "noise_floor:") != nullptr);
        CHECK(std::strstr(off, "noise_floor:frames=0,in_window=0,events=0,incidents=0,last=none,cooldown=0,unconfigured") == nullptr);
    }
    CHECK(m.select(home_network()));
    m.set_data_path(true);
    CHECK(m.data_path());
    // Disconnect burst + reconnect on the selected network: red, with the ledger's wording.
    clock.at = 2000;
    for (std::uint32_t i = 0; i < 6; ++i) { clock.at = 2000 + 100 * i; m.receive(packet(disconnect(kHome, kPhone, kHome, 10 + i), clock.at)); }
    clock.at = 5000; m.receive(packet(eapol(kHome, kPhone, msg(EapolMessage::M1, 3)), clock.at));
    clock.at = 5010; m.receive(packet(eapol(kHome, kPhone, msg(EapolMessage::M2, 3)), clock.at));
    auto s = m.snapshot();
    CHECK(s.incidents[static_cast<std::size_t>(IncidentKind::NetworkPattern)]);
    CHECK_EQ(s.evidence[static_cast<std::size_t>(IncidentKind::NetworkPattern)].pattern, Pattern::DeauthHandshake);
    auto v = m.view(s);
    CHECK(v.alert);
    CHECK_EQ(std::string(v.alert_reason), std::string("Clients were pushed off your network and reconnected (a handshake was exchanged)"));
    CHECK(std::string(v.alert_reason).find("crack") == std::string::npos);
    CHECK(advise(s, ConnectivityResult{}).has(AdviceId::NetworkPatternObserved));
    // Noise floor: amber, about the channel.
    for (Millis t = 6000; t < 40000; t += 1000) { clock.at = t; m.channel_load(air(t, 6, -96)); }
    for (Millis t = 40000; t < 45000; t += 1000) { clock.at = t; m.channel_load(air(t, 6, -84, 40, 30, true)); }
    s = m.snapshot();
    bool loss = false;
    for (std::size_t i = 0; i < area_slots; ++i)
        if (s.area_visible[i] && s.area[i].pattern == Pattern::NoiseFloor) { loss = true; CHECK_EQ(s.area[i].channel, 6u); }
    CHECK(loss);
    v = m.view(s);
    CHECK(v.caution);
    CHECK_EQ(std::string(v.caution_reason), std::string("Noise floor jumped on this channel nearby"));
    radar = m.radar();
    CHECK(radar.families[static_cast<std::size_t>(DetectorFamily::Jamming)].active);
    static char json[8192];
    CHECK(m.json(json, sizeof json, 0, true, false) > 0u);
    CHECK(std::strstr(json, "\"name\":\"handshake\"") != nullptr);
    CHECK(std::strstr(json, "\"name\":\"noise_floor\"") != nullptr);
    CHECK(std::strstr(json, "\"pattern\":\"noise_floor\"") != nullptr);
    CHECK(std::strstr(json, "\"network_pattern_name\":\"deauth_handshake\"") != nullptr);
    char status[2048];
    CHECK(m.status_text(status, sizeof status) > 0u);
    CHECK(std::strstr(status, "noise_floor:") != nullptr);
    CHECK(std::strstr(status, "frame_loss:") == nullptr);
    // Turning the data path off again: the unfed handshake detector is not shown as measuring.
    m.set_data_path(false);
    CHECK(m.status_text(status, sizeof status) > 0u);
    CHECK(std::strstr(status, ",unconfigured;noise_floor:") != nullptr);
}

GUARDIAN_CASE(g16g_patterns_have_wording_keys_and_never_overclaim) {
    const Pattern all[] = {Pattern::PmkidHarvest, Pattern::FakeM1, Pattern::DeauthHandshake, Pattern::NoiseFloor};
    for (auto p : all) {
        IncidentObservation o{}; o.pattern = p; o.scope = IncidentScope::Area;
        const std::string area = area_text(o), network = network_pattern_text(p);
        CHECK(area.find("nearby") != std::string::npos);
        CHECK(network.find("your network") != std::string::npos);
        CHECK(std::string(measurement::pattern_key(p)) != "?");
        CHECK(std::strlen(area_unit(o)) > 0u);
        for (const char* banned : {"crack", "attack", "hacker", "stolen", "captured", "password"}) {
            CHECK(area.find(banned) == std::string::npos);
            CHECK(network.find(banned) == std::string::npos);
        }
    }
    CHECK_EQ(std::string(measurement::family_key(DetectorFamily::Jamming)), std::string("jamming"));
    CHECK(std::strlen(area_text(DetectorFamily::Jamming)) > 0u);
    CHECK(std::strlen(family_text(DetectorFamily::Jamming)) > 0u);
}

GUARDIAN_CASE(data_path_detectors_never_allocate_while_running) {
    Rig r; HandshakeDetector d(r.scope); NoiseFloorDetector f(r.scope);
    AllocationBan ban;
    for (std::uint32_t i = 0; i < 400; ++i) {
        Key k = msg(EapolMessage::M1, i); k.pmkid = (i % 2) != 0; k.zero_nonce = (i % 7) == 0;
        r.feed(d, eapol(ap(i), Mac{0x02, 0, 0, 0, static_cast<std::uint8_t>(i >> 8), static_cast<std::uint8_t>(i)}, k), 1000 + i * 30);
        r.feed(d, disconnect(kHome, kPhone, kHome, i), 1000 + i * 30 + 5);
        if (i % 10 == 0) r.tick(d, 1000 + i * 30 + 10);
        f.sample(air(1000 + i * 30, static_cast<std::uint8_t>(1 + i % 13), -96 + static_cast<int>(i % 20)), r.sink);
    }
    CHECK_EQ(g_banned_allocations, 0u);
}

GUARDIAN_CASE(benign_home_stream_of_ten_minutes_reports_nothing) {
    // A home evening on the host: beacons, two clients re-keying every minute,
    // a phone that leaves and rejoins every 3 minutes (one disassociation),
    // a neighbour's AP kicking its clients, and a busy channel with a few
    // checksum errors every second (normal noise). Zero incidents.
    Clock clock; measurement::Monitor m(clock, profiles::all_2g4_channels());
    CHECK(m.select(home_network()));
    m.set_data_path(true);
    std::uint32_t seq = 0;
    for (Millis t = 1000; t < 601000; t += 100) {
        clock.at = t;
        m.receive(packet(beacon(kHome, "home"), t));
        if (t % 1000 == 0) m.channel_load(load(t, 6, 250 + static_cast<std::uint32_t>(t % 7000) / 100, 2 + static_cast<std::uint32_t>(t % 3000) / 1000, -60));
        if (t % 60000 == 5000) {
            for (const auto& sta : {kPhone, kLaptop}) {
                m.receive(packet(eapol(kHome, sta, msg(EapolMessage::M1, t)), t));
                m.receive(packet(eapol(kHome, sta, msg(EapolMessage::M2, t)), t));
            }
            Key g = msg(EapolMessage::Group, t); g.group = true;
            m.receive(packet(eapol(kHome, kPhone, g), t));
        }
        if (t % 180000 == 20000) {
            m.receive(packet(disconnect(kPhone, kHome, kHome, ++seq, false, true), t));
            m.receive(packet(eapol(kHome, kPhone, msg(EapolMessage::M1, t)), t + 0));
        }
        if (t % 180000 == 20500) {
            m.receive(packet(eapol(kHome, kPhone, msg(EapolMessage::M2, t)), t));
            m.receive(packet(eapol(kHome, kPhone, msg(EapolMessage::M3, t + 1)), t));
            m.receive(packet(eapol(kHome, kPhone, msg(EapolMessage::M4, t + 1)), t));
        }
        if (t % 240000 == 30000) {
            for (std::uint32_t i = 0; i < 3; ++i) m.receive(packet(disconnect(kNeighbour, kLaptop, kNeighbour, ++seq), t));
        }
        if (t % 5000 == 0) {
            const auto s = m.snapshot();
            for (bool b : s.incidents) CHECK(!b);
            for (bool b : s.area_visible) CHECK(!b);
        }
    }
    for (std::size_t i = 0; i < m.detectors().size(); ++i) CHECK_EQ(m.detectors().at(i)->report(Instant{epoch(), clock.at, true}).incidents, 0u);
}


// G16F passive management-frame pattern detectors (TDD: written and run RED
// first against stub detectors that counted nothing; logs in
// $GUARDIAN_STORE/builds/20261117-g16f-host/red-*.log).
//
// Every case feeds hand-built 802.11 management frames through the real
// SecurityFrameParser into the detector under test (or through
// measurement::Monitor end to end). Attack streams must produce exactly one
// observation per cooldown; benign streams (phones probing, a mesh system, an
// AP reboot, a Multiple-BSSID AP, hidden names, ordinary roaming disconnects)
// must produce none. Generated frames are host input, never radio proof.
#include "check.hpp"
#include "measurement.hpp"

#include "guardian/presenter.hpp"
#include "guardian/security_parser.hpp"
#include "guardian/threats.hpp"

#include <array>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>

using namespace guardian;

// ---- allocation ban (same technique as detector_check / threat_check) -------------------
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

// ---- time, addresses, frames ----------------------------------------------------------
TimeEpoch epoch(std::uint64_t boot = 1) { TimeEpoch e{}; e.source_id[0] = 7; e.boot_id = boot; return e; }
class Clock final : public MonotonicClock {
public:
    Millis at{1000};
    Millis now() const override { return at; }
    TimeEpoch epoch() const override { return ::epoch(); }
};

constexpr Mac kBroadcast{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
constexpr Mac kHomeBssid{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
constexpr Mac kNeighbour{0x00, 0x66, 0x77, 0x88, 0x99, 0xaa};
constexpr Mac kMarker{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad};
Mac mac(std::uint8_t a, std::uint32_t i, bool local = false) {
    return Mac{static_cast<std::uint8_t>(local ? (a | 0x02) & 0xfe : a & 0xfc), 0x10, static_cast<std::uint8_t>(i >> 16),
               static_cast<std::uint8_t>(i >> 8), static_cast<std::uint8_t>(i), 0x01};
}
Mac random_mac(std::uint32_t i) { return mac(0x5a, i, true); }

struct Bytes {
    std::array<std::uint8_t, 400> b{};
    std::size_t n{};
    Bytes& u8(std::size_t v) { b[n++] = static_cast<std::uint8_t>(v); return *this; }
    Bytes& u16(std::size_t v) { u8(v & 0xff); return u8((v >> 8) & 0xff); }
    Bytes& addr(const Mac& m) { for (auto x : m) u8(x); return *this; }
    Bytes& raw(const char* s, std::size_t len) { for (std::size_t i = 0; i < len; ++i) u8(static_cast<std::uint8_t>(s[i])); return *this; }
    Bytes& ssid(const char* s) { const auto len = std::strlen(s); u8(0); u8(len); return raw(s, len); }
};
Bytes header(std::uint32_t subtype, const Mac& a1, const Mac& a2, const Mac& a3, std::uint32_t seq = 0, std::uint32_t fc1 = 0) {
    Bytes f; f.u8(subtype << 4).u8(fc1).u16(0).addr(a1).addr(a2).addr(a3).u16((seq & 0x0fff) << 4);
    return f;
}

struct BeaconOptions {
    bool privacy{true};
    bool rsn_psk{true};     // WPA2-PSK CCMP RSNE (when privacy)
    bool rsn_owe{};         // OWE AKM RSNE instead
    int csa_count{-1};      // >= 0: Channel Switch Announcement with this count
    int quiet_tu{-1};       // >= 0: Quiet element with this duration
    bool multi_bssid{};
    bool element222{};
    bool owe_partner{};     // OWE Transition Mode element
    Mac partner{};
    const char* partner_ssid{""};
    bool hidden_nul{};      // SSID of NUL bytes of the name's length
    bool hidden{};          // zero-length SSID
};
void beacon_body(Bytes& f, const char* name, const BeaconOptions& o) {
    // G16J: a real AP's timestamp advances with every beacon (a constant one is a tool shape now).
    static std::uint64_t tsf = 3600000000ull;
    tsf += 102400;
    for (int i = 0; i < 8; ++i) f.u8(static_cast<std::size_t>((tsf >> (8 * i)) & 0xff));
    f.u16(100).u16(o.privacy ? 0x0011 : 0x0001);
    if (o.hidden) { f.u8(0).u8(0); }
    else if (o.hidden_nul) { const auto len = std::strlen(name); f.u8(0).u8(len); for (std::size_t i = 0; i < len; ++i) f.u8(0); }
    else f.ssid(name);
    f.u8(3).u8(1).u8(6);
    if (o.privacy && o.rsn_owe) f.u8(48).u8(20).u16(1).u8(0).u8(0x0f).u8(0xac).u8(4).u16(1).u8(0).u8(0x0f).u8(0xac).u8(4)
                                .u16(1).u8(0).u8(0x0f).u8(0xac).u8(18).u16(0x00c0);
    else if (o.privacy && o.rsn_psk) f.u8(48).u8(20).u16(1).u8(0).u8(0x0f).u8(0xac).u8(4).u16(1).u8(0).u8(0x0f).u8(0xac).u8(4)
                                     .u16(1).u8(0).u8(0x0f).u8(0xac).u8(2).u16(0x0000);
    if (o.csa_count >= 0) f.u8(37).u8(3).u8(1).u8(11).u8(static_cast<std::uint32_t>(o.csa_count));
    if (o.quiet_tu >= 0) f.u8(40).u8(6).u8(1).u8(1).u16(static_cast<std::uint32_t>(o.quiet_tu)).u16(0);
    if (o.multi_bssid) f.u8(71).u8(1).u8(3);
    if (o.element222) f.u8(222).u8(4).u8(0x7b).u8(0x22).u8(0x7d).u8(0x00);
    if (o.owe_partner) {
        const auto len = std::strlen(o.partner_ssid);
        f.u8(221).u8(4 + 7 + len).u8(0x50).u8(0x6f).u8(0x9a).u8(28).addr(o.partner).u8(len).raw(o.partner_ssid, len);
    }
}
Bytes beacon(const Mac& bssid, const char* name, const BeaconOptions& o = {}, const Mac* transmitter = nullptr) {
    Bytes f = header(8, kBroadcast, transmitter ? *transmitter : bssid, bssid);
    beacon_body(f, name, o);
    return f;
}
Bytes probe_response(const Mac& bssid, const char* name, const Mac& to, const BeaconOptions& o = {}) {
    Bytes f = header(5, to, bssid, bssid);
    beacon_body(f, name, o);
    return f;
}
Bytes probe_request(const Mac& from, const char* name /* "" = wildcard */) {
    Bytes f = header(4, kBroadcast, from, kBroadcast);
    f.ssid(name).u8(1).u8(4).u8(0x82).u8(0x84).u8(0x8b).u8(0x96);
    return f;
}
Bytes authentication(const Mac& from, const Mac& bssid, std::uint32_t algorithm, std::uint32_t transaction, std::uint32_t seq = 0) {
    Bytes f = header(11, bssid, from, bssid, seq);
    f.u16(algorithm).u16(transaction).u16(0);
    if (algorithm == 3) f.u16(19);   // SAE: group id; scalar/element not decoded
    return f;
}
Bytes association(const Mac& from, const Mac& bssid, bool power_management, bool reassociation = false) {
    Bytes f = header(reassociation ? 2 : 0, bssid, from, bssid, 0, power_management ? 0x10 : 0);
    f.u16(0x0011).u16(10);
    if (reassociation) f.addr(bssid);
    f.ssid("home");
    return f;
}
// G16J: the sequence number on air is seq * 37 + 11, so consecutive test numbers do not make the
// rising-sequence tool shape (equal numbers stay equal: Retry copies still deduplicate).
Bytes disconnect(const Mac& from, const Mac& to, const Mac& bssid, std::uint32_t seq, bool retry = false, bool disassoc = false) {
    Bytes f = header(disassoc ? 10 : 12, to, from, bssid, seq * 37 + 11, retry ? 0x08 : 0);
    f.u16(7);
    return f;
}

RxMeta meta(Millis at, int rssi = -50, bool rssi_valid = true, std::uint64_t boot = 1) {
    RxMeta m{};
    m.acquired = Instant{epoch(boot), at, true};
    m.origin = Origin::LiveRadio; m.status = RxStatus::Ok; m.channel = 6;
    m.rssi_dbm = static_cast<std::int8_t>(rssi); m.rssi_valid = rssi_valid;
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

// One detector + its scope + a sink; feeds bytes through the real parser.
struct Rig {
    ApprovedScope scope{};
    Sink sink{};
    SecurityFrameParser parser{};
    std::uint32_t parsed_bad{};
    Rig() {
        ApprovedAp home{}; home.network.bssid = kHomeBssid; home.network.ssid_size = 4;
        std::memcpy(home.network.ssid.data(), "home", 4);
        scope.select(home);
    }
    void feed(FrameDetector& d, const Bytes& f, const RxMeta& m) {
        const FrameSpan span{f.b.data(), static_cast<std::uint16_t>(f.n), false};
        const auto p = parser.parse(span, m);
        if (p.status == ParseStatus::Malformed || p.status == ParseStatus::Truncated) ++parsed_bad;
        d.on_frame(span, m, p, sink);
    }
};
Network home_network() {
    Network n{}; n.bssid = kHomeBssid; n.ssid_size = 4; std::memcpy(n.ssid.data(), "home", 4); return n;
}
// G16J changed the probe DEFAULTS to the values measured on one channel (16 / 12 / 10 s). The G16F
// probe cases below were written for the AntiHunter-described hypothesis and keep it explicitly.
ThreatLimits described_probe_limits() { ThreatLimits l{}; l.probe_window_ms = 5000; l.probe_flood = 80; l.probe_flood_sources = 60; return l; }
std::size_t count_pattern(const Sink& s, Pattern p) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < s.count && i < s.got.size(); ++i) n += s.got[i].pattern == p;
    return n;
}

} // namespace

// =========================================================================================
// (1) Probe requests
// =========================================================================================
GUARDIAN_CASE(probe_random_flood_fires_once_per_cooldown) {
    Rig r; ProbeFloodDetector d(r.scope, described_probe_limits());
    CHECK(d.configured());
    Millis t = 10000;
    // 25 probes/s from a new randomized address each, for 100 s.
    for (std::uint32_t i = 0; i < 2500; ++i, t += 40) r.feed(d, probe_request(random_mac(i), ""), meta(t));
    CHECK_EQ(r.parsed_bad, 0u);
    CHECK_EQ(count_pattern(r.sink, Pattern::ProbeFloodRandom), 3u);   // 100 s of flood: at ~13.2 s, then after each 45 s cooldown (~58.2 s, ~103.2 s)
    const auto& o = r.sink.got[0];
    CHECK_EQ(o.scope, IncidentScope::Area);
    CHECK_EQ(o.family, DetectorFamily::Probe);
    CHECK_EQ(o.pattern, Pattern::ProbeFloodRandom);
    CHECK(o.count >= 80u);
    CHECK(o.distinct_sources >= 60u);
    CHECK(o.sources_random);
    CHECK_EQ(o.window_ms, 5000u);
    CHECK_EQ(o.threshold, 80u);
    CHECK_EQ(o.origin, Origin::LiveRadio);
    CHECK(o.acquired.valid());
    // Emitted on the closing frame itself (latency 0 on the acquisition timebase).
    CHECK(o.acquired.at >= 10000 + 79 * 40);
    CHECK(o.acquired.at <= 10000 + 5000);
    CHECK(r.sink.got[1].acquired.at - o.acquired.at >= 45000u);
}

GUARDIAN_CASE(probe_single_source_flood_needs_two_windows) {
    Rig r; ProbeFloodDetector d(r.scope, described_probe_limits());
    const Mac one = mac(0x3c, 77);
    Millis t = 1000;
    // 15 probes/s from one address: a single 5 s window over 60 is not enough.
    for (int i = 0; i < 75; ++i, t += 66) r.feed(d, probe_request(one, "cafe"), meta(t));
    CHECK_EQ(r.sink.count, 0u);
    for (int i = 0; i < 90; ++i, t += 66) r.feed(d, probe_request(one, "cafe"), meta(t));
    CHECK_EQ(count_pattern(r.sink, Pattern::ProbeFloodSource), 1u);
    CHECK_EQ(r.sink.got[0].bssid, one);
    CHECK_EQ(r.sink.got[0].distinct_sources, 1u);
    CHECK(!r.sink.got[0].sources_random);
    CHECK_EQ(r.sink.got[0].threshold, 60u);
    // Continuing inside the cooldown adds nothing.
    for (int i = 0; i < 300; ++i, t += 66) r.feed(d, probe_request(one, "cafe"), meta(t));
    CHECK_EQ(r.sink.count, 1u);
}

GUARDIAN_CASE(probe_name_flood_counts_distinct_askers_of_one_name) {
    Rig r; ProbeFloodDetector d(r.scope, described_probe_limits());
    Millis t = 1000;
    for (std::uint32_t i = 0; i < 45; ++i, t += 80) r.feed(d, probe_request(random_mac(i), "Airport Lounge"), meta(t));
    CHECK_EQ(count_pattern(r.sink, Pattern::ProbeFloodName), 1u);
    CHECK_EQ(count_pattern(r.sink, Pattern::ProbeFloodRandom), 0u);   // 45 probes < 80
    CHECK(r.sink.got[0].distinct_sources >= 40u);
    CHECK_EQ(r.sink.got[0].threshold, 40u);
    // Wildcard probes never count for a name.
    Rig w; ProbeFloodDetector e(w.scope, described_probe_limits());
    t = 1000;
    for (std::uint32_t i = 0; i < 70; ++i, t += 60) w.feed(e, probe_request(random_mac(i), ""), meta(t));
    CHECK_EQ(w.sink.count, 0u);
}

GUARDIAN_CASE(probe_benign_phones_never_fire) {
    Rig r; ProbeFloodDetector d(r.scope);
    // Eight phones, each scanning every 20-35 s with a fresh randomized address:
    // a burst of 14 probes (wildcard + 3 remembered names) over ~1.4 s. Ten minutes.
    const char* names[] = {"", "home", "work", "gym"};
    std::uint32_t serial = 0;
    std::array<std::uint32_t, 8> left{};
    std::array<Mac, 8> address{};
    for (Millis t = 0; t < 600000; t += 100) {
        for (std::uint32_t phone = 0; phone < 8; ++phone) {
            const Millis period = 20000 + 2000 * phone;
            if ((t + 3700 * phone) % period == 0) { left[phone] = 14; address[phone] = random_mac(1000 + serial++); }
            if (left[phone] == 0) continue;
            r.feed(d, probe_request(address[phone], names[left[phone] % 4]), meta(t + phone));
            --left[phone];
        }
    }
    CHECK(serial > 100u);
    CHECK_EQ(r.sink.count, 0u);
    CHECK_EQ(r.parsed_bad, 0u);
    CHECK(d.report(Instant{epoch(), 10000000, true}).events_total > 1000u);   // the stream was parsed and counted, just never enough
}

// =========================================================================================
// (2) Beacon flood
// =========================================================================================
GUARDIAN_CASE(beacon_flood_fires_once_for_many_strong_bssids) {
    Rig r; BeaconFloodDetector d(r.scope);
    Millis t = 1000;
    // 60 fake BSSIDs, each beaconing every 100 ms at -48 dBm, for 50 s.
    for (int round = 0; round < 500; ++round)
        for (std::uint32_t i = 0; i < 60; ++i) r.feed(d, beacon(random_mac(5000 + i), "FREE"), meta(t + static_cast<Millis>(round) * 100 + i, -48));
    CHECK_EQ(r.sink.count, 2u);   // once at ~1 s, once more after the 45 s cooldown
    const auto& o = r.sink.got[0];
    CHECK_EQ(o.pattern, Pattern::BeaconFlood);
    CHECK_EQ(o.family, DetectorFamily::Beacon);
    CHECK_EQ(o.scope, IncidentScope::Area);
    CHECK_EQ(o.distinct_sources, 40u);
    CHECK_EQ(o.threshold, 40u);
    CHECK_EQ(o.window_ms, 10000u);
    CHECK(o.acquired.at < 1000 + 100);
}

GUARDIAN_CASE(beacon_flood_ignores_mesh_far_networks_and_unknown_rssi) {
    Rig r; BeaconFloodDetector d(r.scope);
    // A mesh system: 3 nodes x 8 BSSIDs (two bands' worth of SSIDs heard on 2.4), strong, 2 min.
    for (Millis t = 0; t < 120000; t += 100)
        for (std::uint32_t i = 0; i < 24; ++i) r.feed(d, beacon(mac(0x00, 0x700 + i), i % 2 ? "home" : "home-iot"), meta(t + i, -40));
    CHECK_EQ(r.sink.count, 0u);
    CHECK_EQ(r.parsed_bad, 0u);
    const auto mesh_events = d.report(Instant{epoch(), 10000000, true}).events_total;
    CHECK_EQ(mesh_events, 24u * 1200u);   // every strong mesh beacon was counted
    // 80 far-away BSSIDs below the -65 dBm gate.
    for (Millis t = 200000; t < 230000; t += 100)
        for (std::uint32_t i = 0; i < 80; ++i) r.feed(d, beacon(mac(0x04, 0x900 + i), "far"), meta(t + i, -80));
    CHECK_EQ(r.sink.count, 0u);
    // 80 BSSIDs without an RSSI reading.
    for (Millis t = 300000; t < 310000; t += 100)
        for (std::uint32_t i = 0; i < 80; ++i) r.feed(d, beacon(mac(0x08, 0x900 + i), "x"), meta(t + i, -40, false));
    CHECK_EQ(r.sink.count, 0u);
    CHECK_EQ(d.report(Instant{epoch(), 10000000, true}).events_total, mesh_events);   // gated beacons never entered the count
}

// =========================================================================================
// (3) One transmitter answering for many names
// =========================================================================================
GUARDIAN_CASE(responder_many_names_from_one_transmitter) {
    Rig r; ResponderDetector d(r.scope);
    const Mac tx = mac(0x2c, 9);
    const char* names[] = {"cafe", "Hotel Guest", "airport", "linksys", "netgear"};
    Millis t = 1000;
    for (int k = 0; k < 30; ++k, t += 400) r.feed(d, probe_response(tx, names[k % 5], random_mac(static_cast<std::uint32_t>(k))), meta(t));
    CHECK_EQ(count_pattern(r.sink, Pattern::ManyNames), 1u);
    const auto& o = r.sink.got[0];
    CHECK_EQ(o.family, DetectorFamily::Responder);
    CHECK_EQ(o.scope, IncidentScope::Area);
    CHECK_EQ(o.bssid, tx);
    CHECK_EQ(o.count, 4u);
    CHECK_EQ(o.threshold, 4u);
    CHECK_EQ(o.window_ms, 60000u);
    CHECK_EQ(o.corroborating, 0u);
}

GUARDIAN_CASE(responder_answering_names_just_asked_for_is_enough) {
    Rig r; ResponderDetector d(r.scope);
    const Mac tx = mac(0x2c, 10);
    r.feed(d, probe_request(random_mac(1), "Grandma"), meta(1000));
    r.feed(d, probe_response(tx, "Grandma", random_mac(1)), meta(1010));
    CHECK_EQ(r.sink.count, 0u);
    r.feed(d, probe_request(random_mac(2), "Office-5G"), meta(3000));
    r.feed(d, probe_response(tx, "Office-5G", random_mac(2)), meta(3012));
    CHECK_EQ(count_pattern(r.sink, Pattern::ManyNames), 1u);
    CHECK_EQ(r.sink.got[0].corroborating, 2u);
    CHECK_EQ(r.sink.got[0].count, 2u);
}

GUARDIAN_CASE(responder_benign_ap_reboot_hidden_and_multi_bssid) {
    Rig r; ResponderDetector d(r.scope);
    const Mac ap = mac(0x00, 0x123);
    BeaconOptions hidden; hidden.hidden = true;
    BeaconOptions nul; nul.hidden_nul = true;
    for (Millis t = 0; t < 120000; t += 100) {
        r.feed(d, beacon(ap, "home", (t / 100) % 2 ? hidden : nul), meta(t));   // hidden beacons
        if (t % 1000 == 0) r.feed(d, probe_response(ap, "home", random_mac(static_cast<std::uint32_t>(t))), meta(t + 3));   // real name on request
    }
    // AP reboot: silence, then the same BSSID and name again.
    for (Millis t = 200000; t < 260000; t += 100) r.feed(d, beacon(ap, "home"), meta(t));
    CHECK_EQ(r.sink.count, 0u);
    // A Multiple-BSSID transmitter advertising many names.
    BeaconOptions multi; multi.multi_bssid = true;
    const Mac mb = mac(0x00, 0x456);
    const char* names[] = {"corp", "corp-guest", "corp-iot", "corp-voice", "corp-lab", "corp-av"};
    for (Millis t = 300000; t < 330000; t += 100) r.feed(d, beacon(mb, names[(t / 100) % 6], multi), meta(t));
    CHECK_EQ(r.sink.count, 0u);
    CHECK_EQ(r.parsed_bad, 0u);
    CHECK_EQ(d.report(Instant{epoch(), 10000000, true}).events_total, 120u + 600u);   // named answers + reboot beacons counted; hidden and Multiple-BSSID not
}

// =========================================================================================
// (4)-(6) Join floods
// =========================================================================================
GUARDIAN_CASE(auth_flood_area_and_network_scope) {
    Rig r; AuthFloodDetector d(r.scope);
    Millis t = 1000;
    for (std::uint32_t i = 0; i < 70; ++i, t += 50) r.feed(d, authentication(random_mac(i % 20), kNeighbour, 0, 1, i), meta(t));
    CHECK_EQ(count_pattern(r.sink, Pattern::AuthFlood), 1u);
    const auto a = r.sink.got[0];
    CHECK_EQ(a.scope, IncidentScope::Area);
    CHECK_EQ(a.family, DetectorFamily::Auth);
    CHECK_EQ(a.bssid, kNeighbour);
    CHECK(a.count >= 60u);
    CHECK_EQ(a.distinct_sources, 20u);
    CHECK_EQ(a.threshold, 60u);
    // The same against the selected BSSID: a network observation for Core's red path.
    for (std::uint32_t i = 0; i < 70; ++i, t += 50) r.feed(d, authentication(random_mac(100 + i % 20), kHomeBssid, 0, 1, i), meta(t));
    CHECK_EQ(r.sink.count, 2u);
    const auto n = r.sink.got[1];
    CHECK_EQ(n.scope, IncidentScope::Network);
    CHECK_EQ(n.kind, IncidentKind::NetworkPattern);
    CHECK_EQ(n.pattern, Pattern::AuthFlood);
    CHECK(n.affected == home_network());
    CHECK_EQ(n.bssid, kHomeBssid);
}

GUARDIAN_CASE(auth_flood_benign_clients_ap_replies_and_one_source) {
    Rig r; AuthFloodDetector d(r.scope);
    Millis t = 1000;
    // Ten clients joining (request + retry) and the AP answering (transaction 2, from the BSSID).
    for (std::uint32_t c = 0; c < 10; ++c, t += 300) {
        r.feed(d, authentication(random_mac(c), kHomeBssid, 0, 1, c), meta(t));
        r.feed(d, authentication(random_mac(c), kHomeBssid, 0, 1, c), meta(t + 5));
        r.feed(d, authentication(kHomeBssid, kHomeBssid, 0, 2, c), meta(t + 8));
    }
    // One address hammering: count reached, sources not.
    for (std::uint32_t i = 0; i < 200; ++i, t += 20) r.feed(d, authentication(mac(0x3c, 1), kNeighbour, 0, 1, i), meta(t));
    CHECK_EQ(r.sink.count, 0u);
    CHECK_EQ(r.parsed_bad, 0u);
    CHECK_EQ(d.report(Instant{epoch(), 10000000, true}).events_total, 220u);   // 20 client requests + 200 from one address; AP replies excluded
}

GUARDIAN_CASE(sae_commit_flood_counts_commits_without_confirms) {
    Rig r; SaeCommitDetector d(r.scope);
    Millis t = 1000;
    for (std::uint32_t i = 0; i < 12; ++i, t += 100) r.feed(d, authentication(random_mac(i), kNeighbour, 3, 1, i), meta(t));
    CHECK_EQ(count_pattern(r.sink, Pattern::SaeCommitFlood), 1u);
    CHECK_EQ(r.sink.got[0].count, 10u);
    CHECK_EQ(r.sink.got[0].threshold, 10u);
    CHECK_EQ(r.sink.got[0].family, DetectorFamily::Auth);
    // Benign WPA3 joins: commit + confirm per client, and the AP's own commits / confirms.
    Rig b; SaeCommitDetector e(b.scope);
    t = 1000;
    for (std::uint32_t c = 0; c < 30; ++c, t += 150) {
        b.feed(e, authentication(random_mac(c), kHomeBssid, 3, 1, c), meta(t));
        b.feed(e, authentication(kHomeBssid, kHomeBssid, 3, 1, c), meta(t + 2));
        b.feed(e, authentication(random_mac(c), kHomeBssid, 3, 2, c), meta(t + 4));
        b.feed(e, authentication(kHomeBssid, kHomeBssid, 3, 2, c), meta(t + 6));
    }
    CHECK_EQ(b.sink.count, 0u);
    CHECK_EQ(b.parsed_bad, 0u);
    CHECK_EQ(e.report(Instant{epoch(), 10000000, true}).events_total, 30u);   // one client commit each; the AP's own frames excluded
}

GUARDIAN_CASE(assoc_sleep_by_count_or_by_sources) {
    Rig r; AssocSleepDetector d(r.scope);
    for (std::uint32_t i = 0; i < 8; ++i) r.feed(d, association(mac(0x3c, 2), kNeighbour, true, i % 2 == 1), meta(1000 + 100 * i));
    CHECK_EQ(count_pattern(r.sink, Pattern::AssocSleep), 1u);
    CHECK_EQ(r.sink.got[0].count, 8u);
    Rig s; AssocSleepDetector e(s.scope);
    for (std::uint32_t i = 0; i < 4; ++i) s.feed(e, association(random_mac(i), kHomeBssid, true), meta(1000 + 100 * i));
    CHECK_EQ(s.sink.count, 1u);
    CHECK_EQ(s.sink.got[0].distinct_sources, 4u);
    CHECK_EQ(s.sink.got[0].scope, IncidentScope::Network);
    // Benign: ordinary joins without the power-management bit, and three sleepy joins.
    Rig b; AssocSleepDetector f(b.scope);
    for (std::uint32_t i = 0; i < 40; ++i) b.feed(f, association(random_mac(i), kHomeBssid, false, i % 3 == 0), meta(1000 + 100 * i));
    for (std::uint32_t i = 0; i < 3; ++i) b.feed(f, association(random_mac(100 + i), kHomeBssid, true), meta(6000 + 100 * i));
    CHECK_EQ(b.sink.count, 0u);
    CHECK_EQ(b.parsed_bad, 0u);
    CHECK_EQ(f.report(Instant{epoch(), 10000000, true}).events_total, 3u);   // only the power-management joins count
}

// =========================================================================================
// (7) Channel switch / quiet
// =========================================================================================
GUARDIAN_CASE(channel_switch_large_count_and_long_quiet_per_bssid_cooldown) {
    Rig r; ChannelSwitchDetector d(r.scope);
    BeaconOptions csa; csa.csa_count = 60;
    for (Millis t = 1000; t < 41000; t += 100) r.feed(d, beacon(kNeighbour, "cafe", csa), meta(t));
    CHECK_EQ(count_pattern(r.sink, Pattern::ChannelSwitch), 2u);   // t = 1 s and t = 31 s (30 s per BSSID)
    CHECK_EQ(r.sink.got[0].scope, IncidentScope::Area);
    CHECK_EQ(r.sink.got[0].family, DetectorFamily::ChannelSwitch);
    CHECK_EQ(r.sink.got[0].threshold, 50u);
    CHECK_EQ(r.sink.got[0].acquired.at, 1000u);
    CHECK_EQ(r.sink.got[1].acquired.at, 31000u);
    BeaconOptions quiet; quiet.quiet_tu = 2000;
    r.feed(d, beacon(mac(0x00, 0x777), "lab", quiet), meta(50000));
    CHECK_EQ(count_pattern(r.sink, Pattern::QuietOrder), 1u);
    CHECK_EQ(r.sink.last().threshold, 1000u);
}

GUARDIAN_CASE(channel_switch_the_selected_ap_never_announced) {
    Rig r; ChannelSwitchDetector d(r.scope);
    BeaconOptions csa; csa.csa_count = 3;
    // The real AP keeps beaconing without a switch; forged beacons with a switch interleave.
    for (Millis t = 1000; t < 5000; t += 100) {
        r.feed(d, beacon(kHomeBssid, "home"), meta(t));
        if (t % 300 == 0) r.feed(d, beacon(kHomeBssid, "home", csa), meta(t + 20));
    }
    CHECK_EQ(r.parsed_bad, 0u);
    CHECK_EQ(count_pattern(r.sink, Pattern::ChannelSwitch), 1u);
    const auto& o = r.sink.got[0];
    CHECK_EQ(o.scope, IncidentScope::Network);
    CHECK_EQ(o.kind, IncidentKind::NetworkPattern);
    CHECK(o.affected == home_network());
    CHECK(o.corroborating >= 2u);
}

GUARDIAN_CASE(channel_switch_benign_real_announcement_and_ordinary_values) {
    Rig r; ChannelSwitchDetector d(r.scope);
    // The selected AP announces a real switch: normal beacons, then every beacon counts down, then it is gone.
    for (Millis t = 1000; t < 3000; t += 100) r.feed(d, beacon(kHomeBssid, "home"), meta(t));
    for (int k = 10; k >= 1; --k) { BeaconOptions o; o.csa_count = k; r.feed(d, beacon(kHomeBssid, "home", o), meta(3000 + static_cast<Millis>(10 - k) * 100)); }
    // A neighbour with an ordinary count and a short quiet period.
    BeaconOptions small; small.csa_count = 5;
    BeaconOptions shortq; shortq.quiet_tu = 100;
    for (Millis t = 10000; t < 20000; t += 100) { r.feed(d, beacon(kNeighbour, "cafe", small), meta(t)); r.feed(d, beacon(mac(0x00, 0x5), "q", shortq), meta(t + 1)); }
    CHECK_EQ(r.sink.count, 0u);
    CHECK_EQ(r.parsed_bad, 0u);
    CHECK_EQ(d.report(Instant{epoch(), 10000000, true}).events_total, 0u);
}

// =========================================================================================
// (8) SSID confusion indicator
// =========================================================================================
GUARDIAN_CASE(name_mismatch_between_beacon_and_probe_response) {
    Rig r; NameMismatchDetector d(r.scope);
    for (Millis t = 1000; t < 3000; t += 100) r.feed(d, beacon(kNeighbour, "cafe"), meta(t));
    r.feed(d, probe_response(kNeighbour, "bank", random_mac(1)), meta(3010));
    CHECK_EQ(r.sink.count, 0u);   // one response is not enough
    r.feed(d, probe_response(kNeighbour, "bank", random_mac(2)), meta(3500));
    CHECK_EQ(count_pattern(r.sink, Pattern::NameMismatch), 1u);
    CHECK_EQ(r.sink.got[0].family, DetectorFamily::Identity);
    CHECK_EQ(r.sink.got[0].scope, IncidentScope::Area);
    CHECK_EQ(r.sink.got[0].bssid, kNeighbour);
    CHECK_EQ(r.sink.got[0].count, 2u);
    // Under the selected BSSID it is about the owner's network.
    for (Millis t = 4000; t < 5000; t += 100) r.feed(d, beacon(kHomeBssid, "home"), meta(t));
    r.feed(d, probe_response(kHomeBssid, "home-guest", random_mac(3)), meta(5010));
    r.feed(d, probe_response(kHomeBssid, "home-guest", random_mac(4)), meta(5020));
    CHECK_EQ(r.sink.count, 2u);
    CHECK_EQ(r.sink.got[1].scope, IncidentScope::Network);
    CHECK_EQ(r.sink.got[1].kind, IncidentKind::NetworkPattern);
}

GUARDIAN_CASE(name_mismatch_benign_hidden_and_rename) {
    Rig r; NameMismatchDetector d(r.scope);
    BeaconOptions hidden; hidden.hidden = true;
    BeaconOptions nul; nul.hidden_nul = true;
    for (Millis t = 1000; t < 20000; t += 100) {
        r.feed(d, beacon(kNeighbour, "secret", hidden), meta(t));
        r.feed(d, beacon(mac(0x00, 0x99), "secret2", nul), meta(t + 1));
        if (t % 500 == 0) { r.feed(d, probe_response(kNeighbour, "secret", random_mac(1)), meta(t + 2)); r.feed(d, probe_response(mac(0x00, 0x99), "secret2", random_mac(1)), meta(t + 3)); }
    }
    // Rename: old beacons, one response with the new name in between, then the new beacons.
    for (Millis t = 30000; t < 31000; t += 100) r.feed(d, beacon(kHomeBssid, "home"), meta(t));
    r.feed(d, probe_response(kHomeBssid, "home2", random_mac(5)), meta(31010));
    for (Millis t = 31100; t < 40000; t += 100) { r.feed(d, beacon(kHomeBssid, "home2"), meta(t)); if (t % 700 == 0) r.feed(d, probe_response(kHomeBssid, "home2", random_mac(6)), meta(t + 2)); }
    CHECK_EQ(r.sink.count, 0u);
    CHECK_EQ(r.parsed_bad, 0u);
    CHECK_EQ(d.report(Instant{epoch(), 10000000, true}).events_total, 1u);   // the single response between rename and new beacon
}

// =========================================================================================
// (9) Marked beacons
// =========================================================================================
GUARDIAN_CASE(marked_beacon_once_per_bssid_per_30_s) {
    Rig r; MarkedBeaconDetector d(r.scope);
    BeaconOptions marked; marked.element222 = true;
    const Mac pet = mac(0x0c, 0x42);
    for (Millis t = 1000; t < 61500; t += 1000) r.feed(d, beacon(pet, "pet", marked), meta(t));
    CHECK_EQ(count_pattern(r.sink, Pattern::MarkedBeacon), 3u);   // 1 s, 31 s, 61 s
    CHECK_EQ(r.sink.got[0].family, DetectorFamily::Beacon);
    CHECK_EQ(r.sink.got[0].bssid, pet);
    r.feed(d, beacon(kMarker, "x"), meta(62000));
    CHECK_EQ(r.sink.count, 4u);
    // Benign beacons never fire.
    Rig b; MarkedBeaconDetector e(b.scope);
    for (Millis t = 0; t < 60000; t += 100) { e.on_tick(Instant{epoch(), t, true}, b.sink); b.feed(e, beacon(kHomeBssid, "home"), meta(t)); }
    CHECK_EQ(b.sink.count, 0u);
}

// =========================================================================================
// (10) OWE transition twin
// =========================================================================================
GUARDIAN_CASE(owe_open_twin_not_the_declared_partner) {
    Rig r; OweTwinDetector d(r.scope);
    const Mac owe = mac(0x00, 0xa1), open = mac(0x00, 0xa2), twin = mac(0x0c, 0xa3);
    BeaconOptions owe_side; owe_side.rsn_owe = true; owe_side.hidden = true; owe_side.owe_partner = true; owe_side.partner = open; owe_side.partner_ssid = "CafeFree";
    BeaconOptions open_side; open_side.privacy = false; open_side.owe_partner = true; open_side.partner = owe; open_side.partner_ssid = "";
    BeaconOptions plain_open; plain_open.privacy = false;
    for (Millis t = 1000; t < 10000; t += 100) { r.feed(d, beacon(owe, "", owe_side), meta(t)); r.feed(d, beacon(open, "CafeFree", open_side), meta(t + 1)); }
    CHECK_EQ(r.sink.count, 0u);
    r.feed(d, beacon(twin, "CafeFree", plain_open), meta(10010));
    r.feed(d, beacon(twin, "CafeFree", plain_open), meta(10110));
    CHECK_EQ(count_pattern(r.sink, Pattern::OpenTwin), 1u);
    CHECK_EQ(r.sink.got[0].family, DetectorFamily::Identity);
    CHECK_EQ(r.sink.got[0].bssid, twin);
    CHECK_EQ(r.sink.got[0].scope, IncidentScope::Area);
    // Benign: an open network with a name no OWE pair declared.
    Rig b; OweTwinDetector e(b.scope);
    for (Millis t = 1000; t < 10000; t += 100) b.feed(e, beacon(twin, "Library", plain_open), meta(t));
    CHECK_EQ(b.sink.count, 0u);
    CHECK_EQ(r.parsed_bad, 0u);
    CHECK_EQ(b.parsed_bad, 0u);
}

// =========================================================================================
// (11) Disconnect frames nearby
// =========================================================================================
GUARDIAN_CASE(area_disconnect_per_source_pair_and_broadcast) {
    Rig r; AreaDisconnectDetector d(r.scope);
    const Mac src = mac(0x00, 0xb1);
    std::uint32_t seq = 0;
    for (std::uint32_t i = 0; i < 25; ++i) r.feed(d, disconnect(src, random_mac(i), kNeighbour, seq++), meta(1000 + 300 * i));
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthSource), 1u);
    CHECK_EQ(r.sink.got[0].bssid, src);
    CHECK_EQ(r.sink.got[0].threshold, 20u);
    CHECK_EQ(r.sink.got[0].family, DetectorFamily::Disconnect);
    CHECK_EQ(r.sink.got[0].scope, IncidentScope::Area);
    Rig p; AreaDisconnectDetector e(p.scope);
    const Mac victim = random_mac(900);
    // Both kinds count (six deauthentications, then seven disassociations: one change, not an alternation run).
    for (std::uint32_t i = 0; i < 13; ++i) p.feed(e, disconnect(src, victim, kNeighbour, seq++, false, i >= 6), meta(1000 + 60 * i));
    CHECK_EQ(count_pattern(p.sink, Pattern::DeauthPair), 1u);
    CHECK_EQ(p.sink.got[0].threshold, 12u);
    Rig b; AreaDisconnectDetector f(b.scope);
    for (std::uint32_t i = 0; i < 12; ++i) b.feed(f, disconnect(mac(0x00, 0xc0 + i), kBroadcast, mac(0x00, 0xc0 + i), seq++), meta(1000 + 400 * i));
    CHECK_EQ(count_pattern(b.sink, Pattern::DeauthBroadcast), 1u);
    CHECK_EQ(b.sink.got[0].threshold, 10u);
}

GUARDIAN_CASE(area_disconnect_retries_selected_network_and_roaming_never_fire) {
    Rig r; AreaDisconnectDetector d(r.scope);
    const Mac src = mac(0x00, 0xb1), dst = random_mac(7);
    // A frame and its retry chain (retry_copies_max Retry copies): one observation. G22: this case fed 40
    // copies before; more copies than a retry chain has are counted now (see the retry-bit flood case below).
    r.feed(d, disconnect(src, dst, kNeighbour, 5), meta(1000));
    for (int i = 0; i < retry_copies_max; ++i) r.feed(d, disconnect(src, dst, kNeighbour, 5, true), meta(1001 + static_cast<Millis>(i) * 10));
    // A burst under the selected BSSID belongs to DisconnectDetector (red), not here.
    for (std::uint32_t i = 0; i < 40; ++i) r.feed(d, disconnect(kHomeBssid, random_mac(i), kHomeBssid, 100 + i), meta(2000 + 20 * i));
    CHECK_EQ(d.report(Instant{epoch(), 2900, true}).events_total, 1u);   // the 40 retries and the selected-network frames were not counted
    // Roaming: thirty clients each leaving once over five minutes.
    for (std::uint32_t i = 0; i < 30; ++i) r.feed(d, disconnect(random_mac(300 + i), kNeighbour, kNeighbour, i), meta(10000 + 10000 * i));
    CHECK_EQ(r.sink.count, 0u);
}

// G22 (independent review, finding D1): one header with the Retry bit set, repeated, was one observation
// for ever (each copy moved the dedupe time forward). A retry chain is bounded; a flood is counted.
GUARDIAN_CASE(area_disconnect_retry_bit_flood_with_one_sequence_number_is_counted) {
    Rig r; AreaDisconnectDetector d(r.scope);
    const Mac src = mac(0x00, 0xb1);
    for (std::uint32_t i = 0; i < 500; ++i) r.feed(d, disconnect(src, kBroadcast, kNeighbour, 5, true), meta(1000 + 20 * i));   // 50 a second, 10 s
    CHECK_EQ(d.report(Instant{epoch(), 11000, true}).events_total, 63u);   // every 8th frame
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthBroadcast), 1u);
    CHECK_EQ(count_pattern(r.sink, Pattern::DeauthSource), 1u);
    // 41 frames of one header (the old "40 copies" case): six observations, still far from any rule.
    Rig q; AreaDisconnectDetector e(q.scope);
    const Mac dst = random_mac(7);
    q.feed(e, disconnect(src, dst, kNeighbour, 5), meta(1000));
    for (int i = 0; i < 40; ++i) q.feed(e, disconnect(src, dst, kNeighbour, 5, true), meta(1001 + static_cast<Millis>(i) * 10));
    CHECK_EQ(e.report(Instant{epoch(), 2900, true}).events_total, 6u);
    CHECK_EQ(q.sink.count, 0u);
}

// =========================================================================================
// (12) Name rotation / open lure
// =========================================================================================
GUARDIAN_CASE(name_rotation_and_open_lure) {
    Rig r; NameRotationDetector d(r.scope);
    const Mac tx = mac(0x0c, 0xd1);
    char name[8] = "spam-00";
    for (std::uint32_t i = 0; i < 13; ++i) { name[5] = static_cast<char>('0' + i / 10); name[6] = static_cast<char>('0' + i % 10); r.feed(d, beacon(tx, name), meta(1000 + 300 * i)); }
    CHECK_EQ(count_pattern(r.sink, Pattern::NameRotation), 1u);
    CHECK_EQ(r.sink.got[0].count, 12u);
    CHECK_EQ(r.sink.got[0].family, DetectorFamily::Beacon);
    CHECK_EQ(r.sink.got[0].bssid, tx);
    Rig l; NameRotationDetector e(l.scope);
    BeaconOptions open; open.privacy = false;
    l.feed(e, beacon(tx, "Free Airport WiFi", open), meta(900));
    for (std::uint32_t i = 0; i < 12; ++i) { name[5] = static_cast<char>('0' + i / 10); name[6] = static_cast<char>('0' + i % 10); l.feed(e, beacon(tx, name), meta(1000 + 300 * i)); }
    CHECK_EQ(count_pattern(l.sink, Pattern::OpenLure), 1u);
    CHECK_EQ(l.sink.got[0].corroborating, 1u);
    CHECK(lure_name(reinterpret_cast<const std::uint8_t*>("HOTEL guest"), 11));
    CHECK(!lure_name(reinterpret_cast<const std::uint8_t*>("home"), 4));
}

GUARDIAN_CASE(name_rotation_benign_multi_bssid_and_mesh) {
    Rig r; NameRotationDetector d(r.scope);
    BeaconOptions multi; multi.multi_bssid = true;
    const Mac tx = mac(0x00, 0xe1);
    char name[8] = "corp-00";
    for (Millis t = 1000; t < 20000; t += 100) { const auto i = static_cast<std::uint32_t>((t / 100) % 16); name[5] = static_cast<char>('0' + i / 10); name[6] = static_cast<char>('0' + i % 10); r.feed(d, beacon(tx, name, multi), meta(t)); }
    for (Millis t = 30000; t < 60000; t += 100)
        for (std::uint32_t i = 0; i < 24; ++i) r.feed(d, beacon(mac(0x00, 0x700 + i), i % 2 ? "home" : "home-iot"), meta(t + i));
    CHECK_EQ(r.sink.count, 0u);
    CHECK_EQ(r.parsed_bad, 0u);
    CHECK_EQ(d.report(Instant{epoch(), 10000000, true}).events_total, 24u * 300u);   // multi-BSSID beacons excluded, mesh beacons counted
}

// =========================================================================================
// Shared rules
// =========================================================================================
GUARDIAN_CASE(unverified_foreign_epoch_and_foreign_origin_frames_never_count) {
    Rig r; AuthFloodDetector d(r.scope);
    Millis t = 1000;
    for (std::uint32_t i = 0; i < 40; ++i, t += 50) {
        auto bad = meta(t); bad.status = RxStatus::FcsError;
        r.feed(d, authentication(random_mac(i), kNeighbour, 0, 1, i), bad);
        auto unknown = meta(t); unknown.acquired.known = false;
        r.feed(d, authentication(random_mac(i), kNeighbour, 0, 1, i), unknown);
    }
    r.feed(d, authentication(random_mac(1), kNeighbour, 0, 1, 1), meta(t));   // binds epoch 1 / LiveRadio
    for (std::uint32_t i = 0; i < 80; ++i, t += 50) {
        r.feed(d, authentication(random_mac(i), kNeighbour, 0, 1, i), meta(t, -50, true, 2));   // another boot
        auto demo = meta(t); demo.origin = Origin::Demo;
        r.feed(d, authentication(random_mac(i), kNeighbour, 0, 1, i), demo);
    }
    CHECK_EQ(r.sink.count, 0u);
    CHECK_EQ(d.report(Instant{epoch(), t, true}).events_total, 1u);
    d.reset();
    CHECK_EQ(d.report(Instant{epoch(), t, true}).frames_seen, 0u);
}

GUARDIAN_CASE(configure_validates_limits_and_reports_are_honest) {
    ApprovedScope scope; ThreatLimits bad{};
    bad.probe_flood_sources = ProbeFloodDetector::source_capacity + 1;   // unreachable threshold
    ProbeFloodDetector p(scope, bad);
    CHECK(!p.configured());
    CHECK(!p.report(Instant{epoch(), 1, true}).configured);
    ThreatLimits zero{}; zero.beacon_window_ms = 0;
    BeaconFloodDetector b(scope, zero);
    CHECK(!b.configured());
    CHECK(b.configure(ThreatLimits{}));
    CHECK(b.configured());
    ThreatDetectors all(scope);
    for (std::size_t i = 0; i < ThreatDetectors::count; ++i) {
        const auto rep = all.at(i)->report(Instant{epoch(), 1, true});
        CHECK(rep.configured);
        CHECK(std::strlen(rep.name) > 0);
        CHECK_EQ(rep.scope, IncidentScope::Area);
        for (std::size_t j = 0; j < i; ++j) CHECK(std::strcmp(rep.name, all.at(j)->report(Instant{epoch(), 1, true}).name) != 0);
    }
    CHECK(all.at(ThreatDetectors::count) == nullptr);
    ThreatLimits refused{}; refused.auth_flood_sources = 0;
    CHECK(!all.configure(refused));
    CHECK(all.auth.configured());   // all-or-nothing: nothing changed
    // Report counters follow what was counted.
    Rig r; ProbeFloodDetector d(r.scope, described_probe_limits());
    for (std::uint32_t i = 0; i < 100; ++i) r.feed(d, probe_request(random_mac(i), ""), meta(1000 + 40 * i));
    const auto rep = d.report(Instant{epoch(), 1000 + 40 * 99, true});
    CHECK_EQ(rep.frames_seen, 100u);
    CHECK_EQ(rep.events_total, 100u);
    CHECK(rep.events_in_window >= 80u);
    CHECK_EQ(rep.incidents, 1u);
    CHECK(rep.cooldown_remaining_ms > 40000u);
    CHECK(rep.last_incident_known);
    CHECK_EQ(rep.family, DetectorFamily::Probe);
    CHECK_EQ(rep.window_ms, 5000u);
}

GUARDIAN_CASE(saturation_is_flagged_as_a_lower_bound) {
    ApprovedScope scope; ThreatLimits l = described_probe_limits();
    l.probe_flood = 150; l.probe_flood_sources = 60;
    ProbeFloodDetector d(scope, l);
    CHECK(d.configured());
    Rig r;
    for (std::uint32_t i = 0; i < 150; ++i) r.feed(d, probe_request(random_mac(i), ""), meta(1000 + 25 * i));
    CHECK_EQ(r.sink.count, 1u);
    CHECK(r.sink.got[0].saturated);
    CHECK_EQ(r.sink.got[0].distinct_sources, static_cast<std::uint32_t>(ProbeFloodDetector::source_capacity));
    // Below the bound nothing is saturated.
    Rig s; ProbeFloodDetector e(s.scope, described_probe_limits());
    for (std::uint32_t i = 0; i < 62; ++i) s.feed(e, probe_request(random_mac(i), ""), meta(1000 + 40 * i));
    CHECK_EQ(s.sink.count, 0u);   // 62 probes < 80
    for (std::uint32_t i = 0; i < 20; ++i) s.feed(e, probe_request(random_mac(i), ""), meta(3500 + 40 * i));   // repeat addresses: no eviction
    CHECK_EQ(s.sink.count, 1u);
    CHECK(!s.sink.got[0].saturated);
}

GUARDIAN_CASE(coverage_report_travels_with_the_observation) {
    Rig r; SaeCommitDetector d(r.scope);
    CoverageReport c{}; c.sampled_at = Instant{epoch(), 1500, true}; c.channel = 6; c.window_ms = 5000; c.listened_ms = 4200; c.hopping = true;
    d.coverage(c);
    for (std::uint32_t i = 0; i < 10; ++i) r.feed(d, authentication(random_mac(i), kNeighbour, 3, 1, i), meta(1000 + 100 * i));
    CHECK_EQ(r.sink.count, 1u);
    CHECK(r.sink.got[0].coverage_known);
    CHECK_EQ(r.sink.got[0].listened_ms, 4200u);
    CHECK(r.sink.got[0].hopping);
}

GUARDIAN_CASE(detectors_never_allocate_while_running) {
    Rig r; ThreatDetectors all(r.scope);
    BeaconOptions csa; csa.csa_count = 60;
    BeaconOptions marked; marked.element222 = true;
    // Build every frame before the ban: Bytes is a fixed array, the parser and detectors must not allocate.
    const Bytes frames[] = {probe_request(random_mac(1), "x"), beacon(random_mac(2), "y"), probe_response(mac(0x2c, 3), "z", random_mac(4)),
                            authentication(random_mac(5), kNeighbour, 0, 1), authentication(random_mac(6), kNeighbour, 3, 1),
                            association(random_mac(7), kNeighbour, true), beacon(kNeighbour, "c", csa), beacon(mac(0x0c, 8), "m", marked),
                            disconnect(mac(0x00, 9), random_mac(10), kNeighbour, 1)};
    g_banned_allocations = 0;
    {
        AllocationBan ban;
        for (std::uint32_t round = 0; round < 3000; ++round)
            for (std::size_t k = 0; k < sizeof frames / sizeof frames[0]; ++k) {
                Bytes f = frames[k];
                f.b[10] = static_cast<std::uint8_t>(round); f.b[11] = static_cast<std::uint8_t>(round >> 8);   // new transmitter each round
                for (std::size_t i = 0; i < ThreatDetectors::count; ++i) r.feed(*all.at(i), f, meta(1000 + round * 5 + k));
            }
        for (std::size_t i = 0; i < ThreatDetectors::count; ++i) { all.at(i)->on_tick(Instant{epoch(), 20000, true}, r.sink); (void)all.at(i)->report(Instant{epoch(), 20000, true}); }
    }
    CHECK_EQ(g_banned_allocations, 0u);
    CHECK(r.sink.count > 0u);   // the stream did trip patterns, so the emitting paths ran under the ban too
}

// =========================================================================================
// End to end: Monitor -> Core -> presenter
// =========================================================================================
measurement::Packet packet(const Bytes& f, Millis at) {
    measurement::Packet p{};
    std::memcpy(p.bytes.data(), f.b.data(), f.n); p.size = static_cast<std::uint16_t>(f.n);
    p.meta = meta(at);
    return p;
}

GUARDIAN_CASE(monitor_registers_every_detector_and_shows_an_area_observation) {
    Clock clock; measurement::Monitor m(clock, profiles::all_2g4_channels());
    CHECK_EQ(m.detectors().size(), 2u + ThreatDetectors::count);
    CHECK_EQ(m.detectors().refused(), 0u);
    for (std::uint32_t i = 0; i < 100; ++i) { clock.at = 2000 + 40 * i; m.receive(packet(probe_request(random_mac(i), ""), clock.at)); }
    const auto s = m.snapshot();
    bool probe = false;
    for (std::size_t i = 0; i < area_slots; ++i)
        if (s.area_visible[i] && s.area[i].family == DetectorFamily::Probe) { probe = true; CHECK_EQ(s.area[i].pattern, Pattern::ProbeFloodRandom); }
    CHECK(probe);
    const auto v = m.view(s);
    CHECK(v.caution);
    CHECK(!v.alert);
    CHECK_EQ(std::string(v.caution_reason), std::string("Probe flood nearby"));
    CHECK_EQ(std::string(area_text(v.caution_evidence)), std::string("Probe flood nearby"));
    CHECK_EQ(std::string(area_unit(v.caution_evidence)), std::string("probes"));
    static char json[8192];
    CHECK(m.json(json, sizeof json, 0, true, false) > 0u);
    CHECK(std::strstr(json, "\"name\":\"probe_flood\"") != nullptr);
    CHECK(std::strstr(json, "\"pattern\":\"probe_flood_random\"") != nullptr);
    char status[2048];
    CHECK(m.status_text(status, sizeof status) > 0u);
    CHECK(std::strstr(status, "rotation:") != nullptr);
}

GUARDIAN_CASE(monitor_raises_the_red_alert_for_a_pattern_on_the_selected_network) {
    Clock clock; measurement::Monitor m(clock, profiles::all_2g4_channels());
    CHECK(m.select(home_network()));
    clock.at = 2000;
    for (std::uint32_t i = 0; i < 70; ++i) { clock.at = 2000 + 50 * i; m.receive(packet(authentication(random_mac(i % 20), kHomeBssid, 0, 1, i), clock.at)); }
    const auto s = m.snapshot();
    CHECK(s.incidents[static_cast<std::size_t>(IncidentKind::NetworkPattern)]);
    CHECK_EQ(s.evidence[static_cast<std::size_t>(IncidentKind::NetworkPattern)].pattern, Pattern::AuthFlood);
    const auto v = m.view(s);
    CHECK(v.alert);
    CHECK_EQ(std::string(v.alert_reason), std::string("Join flood on your network"));
    CHECK_EQ(v.incident.item, AdviceId::NetworkPatternObserved);
    const auto a = advise(s, ConnectivityResult{});
    CHECK(a.has(AdviceId::NetworkPatternObserved));
    CHECK_EQ(a.next_step, NextStep::CheckNetworkPattern);
    CHECK(std::strlen(advice_text(AdviceId::NetworkPatternObserved)) > 0u);
    CHECK(std::strlen(advice_text(NextStep::CheckNetworkPattern)) > 0u);
}

// G22 (independent review, finding H5): firmware/README says the burst records are cleared by a new pick.
// The pattern detectors kept theirs, so a record about the previous network could be read as the new one's.
GUARDIAN_CASE(monitor_a_new_pick_clears_the_nearby_burst_record_and_the_pattern_counters) {
    Clock clock; measurement::Monitor m(clock, profiles::all_2g4_channels());
    CHECK(m.select(home_network()));
    const Mac src = mac(0x00, 0xb1);
    for (std::uint32_t i = 0; i < 25; ++i) { clock.at = 2000 + 100 * i; m.receive(packet(disconnect(src, random_mac(i), kNeighbour, i), clock.at)); }
    CHECK(m.last_burst(IncidentScope::Area).known);
    const auto nearby_events = [&] {   // the nearby disconnect detector's counter, through the registry
        for (std::size_t i = 0; i < m.detectors().size(); ++i) {
            const auto report = m.detectors().at(i)->report(Instant{epoch(), clock.at, true});
            if (std::string(report.name) == "area_disconnect") return report.events_total;
        }
        return ~std::uint32_t{0};
    };
    CHECK_EQ(nearby_events(), 25u);
    Network other = home_network(); other.bssid = kNeighbour; other.ssid[0] = 'x';
    clock.at = 6000;
    CHECK(m.select(other));                                 // another network picked
    CHECK(!m.last_burst(IncidentScope::Area).known);
    CHECK(!m.last_burst(IncidentScope::Network).known);
    CHECK_EQ(nearby_events(), 0u);
    // Picking the SAME network again (baseline approval, the watch switch) keeps what was counted.
    for (std::uint32_t i = 0; i < 25; ++i) { clock.at = 7000 + 100 * i; m.receive(packet(disconnect(src, random_mac(i), kHomeBssid, 100 + i), clock.at)); }
    CHECK(m.last_burst(IncidentScope::Area).known);
    ApprovedAp same{}; same.network = other; same.watch_impostors = true;
    CHECK(m.select(same));
    CHECK(m.last_burst(IncidentScope::Area).known);
}

GUARDIAN_CASE(every_pattern_has_area_and_network_wording) {
    for (std::size_t i = 1; i < static_cast<std::size_t>(Pattern::Count); ++i) {
        IncidentObservation o{}; o.pattern = static_cast<Pattern>(i);
        o.scope = IncidentScope::Area;
        const std::string area = area_text(o);
        CHECK(area.find("nearby") != std::string::npos);
        CHECK(std::strlen(area_unit(o)) > 0u);
        CHECK(std::strlen(measurement::pattern_key(o.pattern)) > 0u);
        CHECK(std::strlen(network_pattern_text(o.pattern)) > 0u);
        CHECK(std::string(network_pattern_text(o.pattern)).find("your network") != std::string::npos);
    }
    IncidentObservation g06{}; g06.family = DetectorFamily::Probe;
    CHECK_EQ(std::string(area_text(g06)), std::string(area_text(DetectorFamily::Probe)));
}

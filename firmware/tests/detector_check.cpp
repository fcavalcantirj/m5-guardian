// G06 detector checks (TDD: written and run RED against a stub detectors.cpp
// first; see docs/G06-detectors.md for the recorded run).
//
// Every frame here is a hand-assembled Origin::Imported fixture (or a fixture
// with its header bytes patched in this file: sequence number, Retry bit,
// addresses) and the clock is a fake. Nothing here is radio proof; a passing
// burst case says the counting policy behaves as documented on replayed bytes,
// not that a real deauthentication flood is detected on hardware (G13/L02).
// The cases are the ledger's calibration list: benign reconnects, roaming,
// AP reboot, retries, sequence wrap, protected/malformed frames, bursts,
// coverage gaps, scope, bounded state, explicit baselines, unexpected APs.
#include "check.hpp"
#include "fixtures.hpp"

#include "guardian/detectors.hpp"
#include "guardian/presenter.hpp"
#include "guardian/rating.hpp"
#include "guardian/security_parser.hpp"

#include <cstdlib>
#include <string>
#include <vector>

using namespace guardian;
using guardian::fixtures::Fixture;

namespace {

// ---- allocation guard: the detectors must not allocate after construction ---------------------
bool g_forbid_allocation = false;
struct AllocationBan {
    AllocationBan() { g_forbid_allocation = true; }
    ~AllocationBan() { g_forbid_allocation = false; }
};

const SecurityFrameParser parser{};

TimeEpoch epoch_of(std::uint8_t source, std::uint64_t boot) {
    TimeEpoch e{};
    e.source_id[0] = source;
    e.boot_id = boot;
    return e;
}

class FakeClock final : public MonotonicClock {
public:
    explicit FakeClock(Millis start = 0, TimeEpoch epoch = epoch_of(1, 1)) : now_(start), epoch_(epoch) {}
    Millis now() const override { return now_; }
    TimeEpoch epoch() const override { return epoch_; }
    void set(Millis t) { now_ = t; }
    void advance(Millis ms) { now_ += ms; }
    void reboot() { ++epoch_.boot_id; now_ = 0; }
private:
    Millis now_;
    TimeEpoch epoch_;
};

const Mac kHome{0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
const Mac kExtender{0x02, 0x11, 0x22, 0x33, 0x44, 0x56};
const Mac kOther{0x02, 0x11, 0x22, 0x33, 0x44, 0x66};
const Mac kNeighbour{0x02, 0x11, 0x22, 0x33, 0x44, 0x77};
const Mac kStation{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
const Mac kBroadcast{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

Network named(const Mac& bssid, const char* name = "home") {
    Network n{};
    n.bssid = bssid;
    std::uint8_t i = 0;
    for (; name[i] && i < 32; ++i) n.ssid[i] = static_cast<std::uint8_t>(name[i]);
    n.ssid_size = i;
    return n;
}

RxMeta meta_at(const FakeClock& clock, Millis at, Origin origin = Origin::Imported, std::uint8_t channel = 6) {
    RxMeta m{};
    m.acquired = Instant{clock.epoch(), at, true};
    m.status = RxStatus::Ok;
    m.origin = origin;
    m.band = Band::Ghz2_4;
    m.channel = channel;
    m.rssi_dbm = -55;
    m.rssi_valid = true;
    return m;
}

bool load(check::Case& c_, const char* name, std::vector<std::uint8_t>& out) {
    Fixture f;
    std::string err;
    if (!fixtures::load(name, f, err)) { CHECK_FAIL(err); return false; }
    out = f.bytes;
    return true;
}

// Header patches on a loaded management frame (IEEE 802.11-2020 9.2.4). Spoofable bytes, like the real thing.
void set_sequence(std::vector<std::uint8_t>& b, std::uint16_t seq, std::uint8_t frag = 0) {
    const std::uint16_t ctrl = static_cast<std::uint16_t>((seq & 0x0fffu) << 4 | (frag & 0x0fu));
    b[22] = static_cast<std::uint8_t>(ctrl & 0xffu);
    b[23] = static_cast<std::uint8_t>(ctrl >> 8);
}
void set_retry(std::vector<std::uint8_t>& b, bool on) { b[1] = static_cast<std::uint8_t>(on ? (b[1] | 0x08u) : (b[1] & ~0x08u)); }
void set_addr(std::vector<std::uint8_t>& b, std::size_t offset, const Mac& m) { for (std::size_t i = 0; i < 6; ++i) b[offset + i] = m[i]; }
void set_bssid_and_transmitter(std::vector<std::uint8_t>& b, const Mac& m) { set_addr(b, 10, m); set_addr(b, 16, m); }

// Unprotected EAPOL data frame (FromDS, LLC/SNAP 88-8E), as parser_check builds it; BSSID = Address 2.
std::vector<std::uint8_t> eapol_frame(const Mac& bssid, const Mac& station, std::uint16_t seq) {
    std::vector<std::uint8_t> b{0x08, 0x02, 0x00, 0x00};
    for (auto x : station) b.push_back(x);
    for (auto x : bssid) b.push_back(x);
    for (auto x : bssid) b.push_back(x);
    b.push_back(0); b.push_back(0);
    set_sequence(b, seq);
    for (auto x : {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e, 0x02, 0x03, 0x00, 0x5f}) b.push_back(static_cast<std::uint8_t>(x));
    return b;
}

// Allocation-free sink: fixed storage, counts what Core would receive.
class RecordingSink final : public ObservationSink {
public:
    void security(const SecurityObservation&) override { ++securities; }
    void incident(const IncidentObservation& i) override {
        if (count < incidents.size()) incidents[count] = i; // the first 64 in order
        latest = i;                                          // and always the newest
        ++count;
    }
    const IncidentObservation& last() const { return latest; }
    std::array<IncidentObservation, 64> incidents{};
    IncidentObservation latest{};
    std::size_t count{};
    std::size_t securities{};
};

SettingsFingerprint fingerprint_of(check::Case& c_, const char* fixture) {
    std::vector<std::uint8_t> b;
    if (!load(c_, fixture, b)) return SettingsFingerprint{};
    FakeClock clock;
    const ParseResult p = parser.parse(FrameSpan{b.data(), static_cast<std::uint16_t>(b.size()), false}, meta_at(clock, 0));
    if (p.status != ParseStatus::Complete) CHECK_FAIL(std::string(fixture) + ": baseline fixture did not parse Complete");
    return SettingsFingerprint::of(p.settings);
}

// The owner's approval of the home AP: WPA3 fingerprint (from the fixture, as a picker would show it) and channel 6.
ApprovedAp home_baseline(check::Case& c_, bool settings_known = true, bool channel_known = true) {
    ApprovedAp a{};
    a.network = named(kHome);
    a.settings_known = settings_known;
    if (settings_known) a.settings = fingerprint_of(c_, "beacon_wpa3_sae_pmf_required");
    a.channel_known = channel_known;
    a.band = Band::Ghz2_4;
    a.channel = 6;
    a.watch_impostors = true; // these cases exercise impostor detection (owner opt-in, G14)
    return a;
}

// G16J: these G06 cases pin the UNSHAPED rule. Their generated frames (one destination, consecutive
// sequence numbers) would otherwise match the rising-sequence tool shape that halves the threshold;
// the shapes have their own attack and benign cases in tests/coverage_check.cpp.
DetectorLimits unshaped() { DetectorLimits l{}; l.shape_frames = 0; l.shape_run = 0; return l; }

struct Rig {
    FakeClock clock{};
    ApprovedScope scope{};
    DetectorLimits limits{};
    RecordingSink sink{};
    explicit Rig(DetectorLimits l = unshaped()) : limits(l) {}
    // Parses and feeds one frame to a detector at acquisition time `at`.
    ParseResult feed(FrameDetector& d, const std::vector<std::uint8_t>& bytes, Millis at, Origin origin = Origin::Imported,
                     RxStatus status = RxStatus::Ok, ObservationSink* sink_override = nullptr) {
        RxMeta m = meta_at(clock, at, origin);
        m.status = status;
        const FrameSpan span{bytes.data(), static_cast<std::uint16_t>(bytes.size()), false};
        const ParseResult p = parser.parse(span, m);
        AllocationBan ban;
        d.on_frame(span, m, p, sink_override ? *sink_override : sink);
        return p;
    }
    void tick(FrameDetector& d, Millis at) {
        AllocationBan ban;
        d.on_tick(Instant{clock.epoch(), at, true}, sink);
    }
    Instant at(Millis t) const { return Instant{clock.epoch(), t, true}; }
};

// `n` distinct unprotected deauthentications (sequence numbers from `first_seq`) for `bssid`, `spacing_ms` apart from `start`.
void burst(check::Case& c_, Rig& r, FrameDetector& d, std::uint32_t n, Millis start, Millis spacing_ms = 100,
           const Mac& bssid = kHome, std::uint16_t first_seq = 1, ObservationSink* sink_override = nullptr) {
    std::vector<std::uint8_t> b;
    if (!load(c_, "deauth_reason7", b)) return;
    set_bssid_and_transmitter(b, bssid);
    for (std::uint32_t i = 0; i < n; ++i) {
        set_sequence(b, static_cast<std::uint16_t>((first_seq + i) & 0x0fffu));
        r.feed(d, b, start + spacing_ms * i, Origin::Imported, RxStatus::Ok, sink_override);
    }
}

CoverageReport listening(const FakeClock& clock, Millis at, std::uint8_t channel = 6, Millis listened = 10000, bool hopping = false) {
    CoverageReport c{};
    c.sampled_at = Instant{clock.epoch(), at, true};
    c.band = Band::Ghz2_4;
    c.channel = channel;
    c.hopping = hopping;
    c.window_ms = 10000;
    c.listened_ms = listened;
    c.passive_receive = Support::Unsupported;
    return c;
}

} // namespace

// Replaced allocator: the detectors and the scope must never allocate while a ban is active.
void* operator new(std::size_t n) {
    if (g_forbid_allocation) std::abort();
    void* p = std::malloc(n ? n : 1);
    if (!p) std::abort();
    return p;
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

// ---- bounded resources ---------------------------------------------------------------------
static_assert(DisconnectDetector::capacity == 128 && BaselineDetector::capacity == 32 && ApprovedScope::capacity == 16,
              "documented fixed capacities (docs/G06-detectors.md)");
static_assert(sizeof(DisconnectDetector) <= 6 * 1024, "disconnect detector state stays within a few KiB of internal RAM");
// G25: + one router track per approved AP (17 tracks: the newest, the differing and an accepted fingerprint,
// the channel compared with, a pending change); 3,328 B measured. The Monitor lives in PSRAM on the StickS3.
static_assert(sizeof(BaselineDetector) <= 4 * 1024, "baseline detector state stays small");
static_assert(sizeof(ApprovedScope) <= 4 * 1024, "approved scope stays small");
static_assert(std::is_trivially_copyable_v<IncidentObservation> && std::is_trivially_copyable_v<ApprovedAp>
              && std::is_trivially_copyable_v<SettingsFingerprint>, "evidence records are plain values");

// ---- configuration ---------------------------------------------------------------------------
GUARDIAN_CASE(defaults_are_configured_and_limits_that_cannot_be_honoured_are_refused_visibly) {
    Rig r;
    CHECK(r.scope.configured());
    CHECK(DisconnectDetector(r.scope, DetectorLimits{}).configured());
    CHECK(BaselineDetector(r.scope, DetectorLimits{}).configured());
    DetectorLimits l{};
    l.burst_threshold = 0;
    CHECK(!DisconnectDetector(r.scope, l).configured());
    l = DetectorLimits{};
    l.window_ms = 0;
    CHECK(!DisconnectDetector(r.scope, l).configured());
    CHECK(!BaselineDetector(r.scope, l).configured());
    l = DetectorLimits{};
    l.max_window_events = static_cast<std::uint16_t>(DisconnectDetector::capacity + 1); // more than the fixed storage
    CHECK(!DisconnectDetector(r.scope, l).configured());
    l = DetectorLimits{};
    l.burst_threshold = 200; // can never be reached inside 128 entries
    CHECK(!DisconnectDetector(r.scope, l).configured());
    l = DetectorLimits{};
    l.change_threshold = 0;
    CHECK(!BaselineDetector(r.scope, l).configured());
    l = DetectorLimits{};
    l.change_threshold = static_cast<std::uint32_t>(BaselineDetector::capacity + 1);
    CHECK(!BaselineDetector(r.scope, l).configured());
    ApprovedScope too_many(static_cast<std::uint16_t>(ApprovedScope::capacity + 1));
    CHECK(!too_many.configured());
    CHECK(!DisconnectDetector(too_many, DetectorLimits{}).configured());
    // A misconfigured detector counts nothing and reports nothing: the failure is visible, never silent growth.
    l = DetectorLimits{};
    l.burst_threshold = 0;
    DisconnectDetector dead(r.scope, l);
    r.scope.select(home_baseline(c_));
    burst(c_, r, dead, 30, 0);
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(dead.stats().in_scope, 0u);
    CHECK_EQ(dead.in_window(r.at(3000)), 0u);
}

// ---- disconnect bursts: counts, windows, thresholds ---------------------------------------------
GUARDIAN_CASE(nineteen_distinct_disconnects_in_ten_seconds_are_no_burst_the_twentieth_is) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    burst(c_, r, d, 19, 0, 500); // 0 .. 9000 ms
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.in_window(r.at(9000)), 19u);
    CHECK_EQ(d.stats().counted, 19u);
    std::vector<std::uint8_t> b;
    if (!load(c_, "deauth_reason7", b)) return;
    set_sequence(b, 20);
    r.feed(d, b, 9500);
    CHECK_EQ(r.sink.count, std::size_t{1});
    const IncidentObservation& i = r.sink.last();
    CHECK_EQ(i.kind, IncidentKind::DisconnectBurst);
    CHECK(i.affected == named(kHome));
    CHECK_EQ(i.bssid, kHome);
    CHECK_EQ(i.count, 20u);
    CHECK_EQ(i.window_ms, 10000u);
    CHECK_EQ(i.threshold, 20u);
    CHECK_EQ(i.raw_frames, 20u);
    CHECK_EQ(i.retries_deduped, 0u);
    CHECK_EQ(i.protected_frames, 0u);
    CHECK_EQ(i.eapol_frames, 0u);
    CHECK_EQ(i.changes, 0);
    CHECK(!i.saturated);
    CHECK(!i.coverage_known); // no coverage report was given: the record says so instead of guessing
    CHECK_EQ(i.acquired.at, Millis{9500}); // the acquisition instant of the frame that closed the window
    CHECK(i.acquired.epoch == r.clock.epoch());
    CHECK_EQ(i.origin, Origin::Imported);
    CHECK_EQ(d.stats().reports, 1u);
}

GUARDIAN_CASE(twenty_disconnects_spread_over_more_than_the_window_are_no_burst) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    burst(c_, r, d, 20, 0, 600); // 0 .. 11400 ms: never 20 inside any 10 s window
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.in_window(r.at(11400)), 17u); // frames at 1800 .. 11400
    CHECK_EQ(d.stats().counted, 20u);
    // Tunable: the same traffic with a 12 s window is a burst (documented heuristic, not a signature).
    Rig wide;
    wide.limits.window_ms = 12000;
    wide.scope.select(home_baseline(c_));
    DisconnectDetector dw(wide.scope, wide.limits);
    burst(c_, wide, dw, 20, 0, 600);
    CHECK_EQ(wide.sink.count, std::size_t{1});
    CHECK_EQ(wide.sink.last().window_ms, 12000u);
}

GUARDIAN_CASE(retry_copies_inside_the_dedupe_gap_are_retransmissions_not_new_observations) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> b;
    if (!load(c_, "deauth_reason7", b)) return;
    for (std::uint16_t s = 1; s <= 13; ++s) { // 13 originals, each retransmitted 20 ms later with the Retry bit
        set_sequence(b, s);
        set_retry(b, false);
        r.feed(d, b, Millis{s} * 100);
        set_retry(b, true);
        r.feed(d, b, Millis{s} * 100 + 20);
    }
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.in_window(r.at(1320)), 13u);
    CHECK_EQ(d.stats().counted, 13u);
    CHECK_EQ(d.stats().retries_deduped, 13u);
    set_retry(b, false);
    for (std::uint16_t s = 14; s <= 20; ++s) { set_sequence(b, s); r.feed(d, b, Millis{s} * 100); }
    CHECK_EQ(r.sink.count, std::size_t{1});
    CHECK_EQ(r.sink.last().count, 20u);
    CHECK_EQ(r.sink.last().raw_frames, 33u);
    CHECK_EQ(r.sink.last().retries_deduped, 13u);
}

GUARDIAN_CASE(a_retry_without_a_seen_original_or_outside_the_gap_counts_and_the_bit_alone_drops_nothing) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> b;
    if (!load(c_, "disassoc_retry_reason8", b)) return; // Retry bit set, sequence 4: the original was not received
    r.feed(d, b, 1000);
    CHECK_EQ(d.stats().counted, 1u); // we may have missed the original; the copy is still observed disconnect traffic
    CHECK_EQ(d.stats().retries_deduped, 0u);
    r.feed(d, b, 1010); // a second copy of the same header inside dedupe_ms: now a retransmission of what we saw
    CHECK_EQ(d.stats().counted, 1u);
    CHECK_EQ(d.stats().retries_deduped, 1u);
    r.feed(d, b, 1000 + r.limits.dedupe_ms + 1); // same header, Retry bit, but outside the gap: a new observation
    CHECK_EQ(d.stats().counted, 2u);
    // The same sequence number WITHOUT the Retry bit inside the gap is a new observation: sequence numbers are
    // not identities (they wrap and can be spoofed), so equality never drops a frame on its own.
    std::vector<std::uint8_t> plain;
    if (!load(c_, "deauth_reason7", plain)) return; // sequence 4 as well, different subtype
    r.feed(d, plain, 1020);
    r.feed(d, plain, 1030);
    CHECK_EQ(d.stats().counted, 4u);
    CHECK_EQ(d.stats().retries_deduped, 1u);
    // Dedupe is per full header: a Retry copy with another receiver address is not a copy of the first.
    std::vector<std::uint8_t> other_station = b;
    set_addr(other_station, 4, kBroadcast);
    r.feed(d, other_station, 1040);
    CHECK_EQ(d.stats().counted, 5u);
}

// G22 (independent review, finding D1): the Retry bit is not a way to hide a flood. retry_copies_max
// copies of one counted header are its retransmissions; every further copy is disconnect traffic again.
GUARDIAN_CASE(one_frame_and_its_retry_limit_of_copies_is_one_observation_and_the_next_copy_counts) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> b;
    if (!load(c_, "deauth_reason7", b)) return;
    set_sequence(b, 9);
    set_retry(b, false);
    r.feed(d, b, 1000);
    set_retry(b, true);
    for (std::uint32_t i = 1; i <= retry_copies_max; ++i) r.feed(d, b, 1000 + Millis{i} * 10);
    CHECK_EQ(d.stats().counted, 1u);                       // one transmission and its whole retry chain
    CHECK_EQ(d.stats().retries_deduped, std::uint32_t{retry_copies_max});
    r.feed(d, b, 1000 + Millis{retry_copies_max + 1u} * 10); // one copy more than a retry chain has
    CHECK_EQ(d.stats().counted, 2u);
    CHECK_EQ(d.stats().retries_deduped, std::uint32_t{retry_copies_max});
    CHECK_EQ(r.sink.count, std::size_t{0});
}

GUARDIAN_CASE(a_retry_bit_flood_with_one_sequence_number_is_still_a_burst) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> b;
    if (!load(c_, "deauth_reason7", b)) return;
    set_addr(b, 4, kBroadcast);
    set_sequence(b, 100);
    set_retry(b, true);
    for (std::uint32_t i = 0; i < 500; ++i) r.feed(d, b, 1000 + Millis{i} * 20); // 50 a second for 10 s, ONE header
    CHECK_EQ(r.sink.count, std::size_t{1});                // reported (once: the cooldown), not hidden
    if (r.sink.count != 1) return;
    const IncidentObservation& i = r.sink.incidents[0];
    CHECK_EQ(i.kind, IncidentKind::DisconnectBurst);
    CHECK_EQ(i.count, 20u);                                // every 8th frame counts: the 20th is frame 153
    CHECK_EQ(i.raw_frames, 153u);
    CHECK_EQ(i.retries_deduped, 133u);                     // 19 counted frames with 7 copies each
    CHECK_EQ(i.acquired.at, Millis{1000 + 152 * 20});
    CHECK(!i.saturated);                                   // copies no longer take ring entries from counted frames
    CHECK_EQ(d.stats().counted, 63u);
    CHECK_EQ(d.stats().retries_deduped, 437u);
    CHECK_EQ(d.stats().evicted_in_window, 0u);
}

GUARDIAN_CASE(sequence_numbers_wrap_and_are_counted_as_distinct_observations) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> b;
    if (!load(c_, "deauth_reason7", b)) return;
    Millis t = 0;
    for (int s : {4090, 4091, 4092, 4093, 4094, 4095, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}) {
        set_sequence(b, static_cast<std::uint16_t>(s));
        r.feed(d, b, t);
        t += 100;
    }
    CHECK_EQ(r.sink.count, std::size_t{1});
    CHECK_EQ(r.sink.last().count, 20u);
    CHECK_EQ(r.sink.last().retries_deduped, 0u);
}

GUARDIAN_CASE(protected_and_malformed_disconnects_count_from_their_header_and_no_reason_is_ever_read) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> prot, mme, bad;
    if (!load(c_, "deauth_protected_unicast", prot) || !load(c_, "deauth_group_mme", mme)) return;
    bad = mme;
    bad[27] = 0x0f; // MME length 15: structurally invalid (must be 16 or 24) -> Malformed, header still valid
    for (std::uint16_t s = 1; s <= 10; ++s) { set_sequence(prot, s); const ParseResult p = r.feed(d, prot, Millis{s} * 100);
        CHECK(p.protected_frame); CHECK(!p.reason_readable); CHECK_EQ(p.status, ParseStatus::Unsupported); }
    for (std::uint16_t s = 11; s <= 15; ++s) { set_sequence(mme, s); const ParseResult p = r.feed(d, mme, Millis{s} * 100);
        CHECK(p.reason_readable); CHECK_EQ(p.status, ParseStatus::Complete); }
    for (std::uint16_t s = 16; s <= 20; ++s) { set_sequence(bad, s); const ParseResult p = r.feed(d, bad, Millis{s} * 100);
        CHECK_EQ(p.status, ParseStatus::Malformed); CHECK(p.header_valid); CHECK(!p.reason_readable); }
    CHECK_EQ(r.sink.count, std::size_t{1});
    const IncidentObservation& i = r.sink.last();
    CHECK_EQ(i.count, 20u);
    CHECK_EQ(i.protected_frames, 10u); // header-only observations, named as such
    CHECK_EQ(d.stats().protected_frames, 10u);
    // Nothing in the record claims a reason, a MIC check or a transmitter identity.
    CHECK_EQ(i.changes, 0);
    CHECK_EQ(i.bssid, kHome);
}

GUARDIAN_CASE(frames_for_another_bssid_without_a_valid_header_or_of_other_kinds_are_not_our_evidence) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    burst(c_, r, d, 25, 0, 100, kOther); // a neighbour's clients being deauthenticated is not evidence about home
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.stats().out_of_scope, 25u);
    CHECK_EQ(d.stats().in_scope, 0u);
    std::vector<std::uint8_t> short_hdr, beacon;
    if (!load(c_, "mgmt_header_short_23", short_hdr) || !load(c_, "beacon_wpa3_sae_pmf_required", beacon)) return;
    for (int k = 0; k < 25; ++k) r.feed(d, short_hdr, 3000 + static_cast<Millis>(k));
    for (int k = 0; k < 25; ++k) r.feed(d, beacon, 4000 + static_cast<Millis>(k));
    CHECK_EQ(d.stats().header_invalid, 25u);
    CHECK_EQ(d.stats().other_frames, 25u);
    CHECK_EQ(d.stats().counted, 0u);
    CHECK_EQ(d.in_window(r.at(5000)), 0u);
    CHECK_EQ(r.sink.count, std::size_t{0});
    // Without a selection nothing is in scope.
    Rig none;
    DisconnectDetector dn(none.scope, none.limits);
    burst(c_, none, dn, 25, 0);
    CHECK_EQ(none.sink.count, std::size_t{0});
    CHECK_EQ(dn.stats().out_of_scope, 25u);
}

GUARDIAN_CASE(an_approved_extender_is_in_scope_and_its_burst_is_reported_under_the_selected_network) {
    Rig r;
    r.scope.select(home_baseline(c_));
    ApprovedAp ext{};
    ext.network = named(kExtender);
    CHECK(r.scope.approve(ext));
    DisconnectDetector d(r.scope, r.limits);
    burst(c_, r, d, 20, 0, 100, kExtender);
    CHECK_EQ(r.sink.count, std::size_t{1});
    CHECK(r.sink.last().affected == named(kHome)); // Core's scope is the selected network
    CHECK_EQ(r.sink.last().bssid, kExtender);     // the evidence names the AP it was observed under
    CHECK_EQ(d.stats().in_scope, 20u);
    // Revoked: the same traffic is out of scope again.
    CHECK(r.scope.revoke(kExtender));
    d.reset();
    r.sink.count = 0;
    burst(c_, r, d, 20, 20000, 100, kExtender);
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.stats().out_of_scope, 20u);
}

GUARDIAN_CASE(benign_reconnects_roaming_retries_and_an_ap_reboot_do_not_report) {
    // Two minutes of ordinary life: a client leaves, a phone roams to the approved extender, the AP reboots and
    // deauthenticates its clients with retransmissions, clients reconnect (EAPOL). No burst.
    Rig r;
    r.scope.select(home_baseline(c_));
    ApprovedAp ext{};
    ext.network = named(kExtender);
    r.scope.approve(ext);
    DisconnectDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> deauth, disassoc, bcast;
    if (!load(c_, "deauth_reason7", deauth) || !load(c_, "disassoc_retry_reason8", disassoc) || !load(c_, "deauth_group_mme", bcast)) return;
    set_sequence(disassoc, 300);
    r.feed(d, disassoc, 1000);                    // client leaving (disassociation, retried)
    r.feed(d, disassoc, 1030);
    set_sequence(deauth, 301);
    r.feed(d, deauth, 15000);                     // class-3 deauth to a stale client
    std::vector<std::uint8_t> roam = disassoc;
    set_bssid_and_transmitter(roam, kExtender);
    set_sequence(roam, 7);
    set_retry(roam, false);
    r.feed(d, roam, 30000);                       // roaming: the extender drops the phone
    r.feed(d, eapol_frame(kHome, kStation, 8), 30400); // the phone re-keys with home
    for (std::uint16_t s = 0; s < 3; ++s) {       // AP reboot at 60 s: broadcast deauth x3, each retried twice
        set_sequence(bcast, static_cast<std::uint16_t>(500 + s));
        set_retry(bcast, false);
        r.feed(d, bcast, 60000 + Millis{s} * 100);
        set_retry(bcast, true);
        r.feed(d, bcast, 60000 + Millis{s} * 100 + 15);
        r.feed(d, bcast, 60000 + Millis{s} * 100 + 40);
    }
    for (std::uint16_t s = 0; s < 4; ++s) r.feed(d, eapol_frame(kHome, kStation, static_cast<std::uint16_t>(600 + s)), 75000 + Millis{s} * 200);
    r.tick(d, 120000);
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.stats().counted, 6u);           // 2 + 1 + 1 + 3 (retries deduped, EAPOL not counted)
    CHECK_EQ(d.stats().retries_deduped, 7u);
    CHECK_EQ(d.stats().eapol_frames, 5u);
    CHECK_EQ(d.stats().reports, 0u);
    CHECK_EQ(d.in_window(r.at(120000)), 0u);
}

GUARDIAN_CASE(a_sustained_burst_reports_once_per_cooldown_with_the_current_count) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    burst(c_, r, d, 701, 0, 100); // 10 frames/s for 70 s, sequence numbers wrapping naturally
    CHECK_EQ(r.sink.count, std::size_t{2});
    CHECK_EQ(r.sink.incidents[0].count, 20u);
    CHECK_EQ(r.sink.incidents[0].acquired.at, Millis{1900});
    CHECK_EQ(r.sink.incidents[1].acquired.at, Millis{1900} + DetectorLimits{}.cooldown_ms); // cooldown_ms after the first report
    CHECK_EQ(r.sink.incidents[1].count, 100u);                      // what the window holds now, not a running total
    CHECK_EQ(r.sink.incidents[1].raw_frames, 100u);
    CHECK(!r.sink.incidents[1].saturated);
    CHECK(d.stats().suppressed_by_cooldown > 500u);
    CHECK_EQ(d.stats().reports, 2u);
    // Tunable: cooldown 0 reports at every frame once the threshold holds.
    Rig eager;
    eager.limits.cooldown_ms = 0;
    eager.scope.select(home_baseline(c_));
    DisconnectDetector de(eager.scope, eager.limits);
    burst(c_, eager, de, 25, 0, 100);
    CHECK_EQ(eager.sink.count, std::size_t{6});
    CHECK_EQ(eager.sink.last().count, 25u);
}

GUARDIAN_CASE(bounded_state_saturates_and_says_so_instead_of_growing) {
    Rig r;
    r.limits.cooldown_ms = 0;
    r.limits.max_window_events = 32; // the adapter budgets 32 entries of the 128 available
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    burst(c_, r, d, 300, 0, 10); // 300 distinct frames in 3 s
    CHECK_EQ(r.sink.count, std::size_t{281}); // every frame from the 20th on
    const IncidentObservation& i = r.sink.last();
    CHECK_EQ(i.count, 32u); // a lower bound, bounded by the configured entries
    CHECK(i.saturated);
    CHECK(d.stats().evicted_in_window > 0u);
    CHECK(!r.sink.incidents[0].saturated); // the first report, at 20 entries, was exact
    // The whole run above executed under the allocation ban (Rig::feed); the ring never grew.
    // A detector using all 128 entries saturates at 128.
    Rig full;
    full.limits.cooldown_ms = 0;
    full.scope.select(home_baseline(c_));
    DisconnectDetector df(full.scope, full.limits);
    burst(c_, full, df, 300, 0, 10);
    CHECK_EQ(full.sink.last().count, 128u);
    CHECK(full.sink.last().saturated);
    // After the window drains the saturation note is gone.
    full.tick(df, 3000 + 10000);
    burst(c_, full, df, 20, 20000, 10, kHome, 1000);
    CHECK(!full.sink.last().saturated);
    CHECK_EQ(full.sink.last().count, 20u);
}

GUARDIAN_CASE(coverage_facts_ride_with_the_report_and_never_change_the_count) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    { AllocationBan ban; d.coverage(listening(r.clock, 5000, 6, 4000, true)); } // hopping: listened 4 of 10 s
    burst(c_, r, d, 20, 5000, 100);
    CHECK_EQ(r.sink.count, std::size_t{1});
    const IncidentObservation& i = r.sink.last();
    CHECK_EQ(i.count, 20u);
    CHECK(i.coverage_known);
    CHECK_EQ(i.listened_ms, Millis{4000});
    CHECK_EQ(i.coverage_window_ms, Millis{10000});
    CHECK(i.hopping);
    // A gap (not tuned) is reported as listened 0, the frames before and after it still count.
    Rig gap;
    gap.limits.cooldown_ms = 0;
    gap.scope.select(home_baseline(c_));
    DisconnectDetector dg(gap.scope, gap.limits);
    burst(c_, gap, dg, 10, 0, 100);
    { AllocationBan ban; dg.coverage(listening(gap.clock, 2000, 0, 0)); } // channel 0: not listening
    burst(c_, gap, dg, 10, 4000, 100, kHome, 100);
    CHECK_EQ(gap.sink.last().count, 20u);
    CHECK(gap.sink.last().coverage_known);
    CHECK_EQ(gap.sink.last().listened_ms, Millis{0});
    // A report older than the window, from another epoch, or with an invalid instant is not knowledge about this window.
    Rig stale;
    stale.scope.select(home_baseline(c_));
    DisconnectDetector ds(stale.scope, stale.limits);
    { AllocationBan ban; ds.coverage(listening(stale.clock, 1000)); }
    burst(c_, stale, ds, 20, 20000, 100);
    CHECK(!stale.sink.last().coverage_known);
    Rig foreign;
    foreign.scope.select(home_baseline(c_));
    DisconnectDetector dfo(foreign.scope, foreign.limits);
    CoverageReport other = listening(foreign.clock, 0);
    other.sampled_at.epoch = epoch_of(1, 9);
    CoverageReport unknown = listening(foreign.clock, 0);
    unknown.sampled_at.known = false;
    { AllocationBan ban; dfo.coverage(other); dfo.coverage(unknown); }
    burst(c_, foreign, dfo, 20, 0, 100);
    CHECK(!foreign.sink.last().coverage_known);
}

GUARDIAN_CASE(foreign_epochs_and_invalid_instants_cannot_count_expire_or_renew_the_window) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    burst(c_, r, d, 19, 0, 100);
    std::vector<std::uint8_t> b;
    if (!load(c_, "deauth_reason7", b)) return;
    set_sequence(b, 900);
    RxMeta foreign = meta_at(r.clock, 1900);
    foreign.acquired.epoch = epoch_of(1, 2); // another boot of this device
    const FrameSpan span{b.data(), static_cast<std::uint16_t>(b.size()), false};
    { AllocationBan ban; d.on_frame(span, foreign, parser.parse(span, foreign), r.sink); }
    RxMeta unknown = meta_at(r.clock, 1900);
    unknown.acquired.known = false;
    { AllocationBan ban; d.on_frame(span, unknown, parser.parse(span, unknown), r.sink); }
    { AllocationBan ban; d.on_tick(Instant{epoch_of(1, 2), 999999, true}, r.sink); } // a foreign tick expires nothing
    { AllocationBan ban; d.on_tick(Instant{}, r.sink); }
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.stats().foreign_epoch, 2u);
    CHECK_EQ(d.stats().invalid_time, 2u); // the unknown-time frame and the invalid tick
    CHECK_EQ(d.in_window(r.at(1800)), 19u);
    CHECK_EQ(d.in_window(Instant{epoch_of(1, 2), 1800, true}), 0u);
    set_sequence(b, 20);
    r.feed(d, b, 1900);
    CHECK_EQ(r.sink.count, std::size_t{1}); // the 20th live frame closes the window
    // reset() clears state, counters and the epoch: the next epoch starts clean.
    d.reset();
    CHECK_EQ(d.in_window(r.at(1900)), 0u);
    CHECK_EQ(d.stats().counted, 0u);
    CHECK_EQ(d.stats().reports, 0u);
    r.clock.reboot();
    burst(c_, r, d, 20, 100, 10);
    CHECK_EQ(r.sink.count, std::size_t{2});
    CHECK(r.sink.last().acquired.epoch == r.clock.epoch());
}

GUARDIAN_CASE(ticks_expire_the_window_without_traffic) {
    Rig r;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    burst(c_, r, d, 19, 0, 100);
    CHECK_EQ(d.in_window(r.at(1800)), 19u);
    r.tick(d, 11801);
    CHECK_EQ(d.in_window(r.at(11801)), 0u);
    std::vector<std::uint8_t> b;
    if (!load(c_, "deauth_reason7", b)) return;
    set_sequence(b, 50);
    r.feed(d, b, 11900);
    CHECK_EQ(d.in_window(r.at(11900)), 1u);
    CHECK_EQ(r.sink.count, std::size_t{0});
    // A delayed frame (acquired before the newest one, drained later) still lands in the window by its own instant.
    set_sequence(b, 51);
    r.feed(d, b, 11850);
    CHECK_EQ(d.in_window(r.at(11900)), 2u);
    // DECISION (docs/G06-detectors.md section 3): the window never looks back further than window_ms before the
    // newest instant the detector has seen, ticks included. 19 frames, then the clock moves on 15 s, then the 20th
    // frame of that old second is drained late: it cannot by itself re-open a window the clock has passed.
    Rig late;
    late.scope.select(home_baseline(c_));
    DisconnectDetector dl(late.scope, late.limits);
    burst(c_, late, dl, 19, 0, 100);
    late.tick(dl, 15000);
    std::vector<std::uint8_t> old;
    if (!load(c_, "deauth_reason7", old)) return;
    set_sequence(old, 20);
    late.feed(dl, old, 1900);
    CHECK_EQ(late.sink.count, std::size_t{0});
    CHECK_EQ(dl.stats().counted, 20u);        // still observed and counted in the statistics
    CHECK_EQ(dl.in_window(late.at(1900)), 1u); // the 19 older entries were pruned by the tick: only the late frame is held
    CHECK_EQ(dl.in_window(late.at(15000)), 0u);
}

GUARDIAN_CASE(eapol_after_disconnects_is_context_in_the_report_never_a_verdict) {
    Rig r;
    r.limits.cooldown_ms = 0;
    r.scope.select(home_baseline(c_));
    DisconnectDetector d(r.scope, r.limits);
    burst(c_, r, d, 20, 0, 100);
    CHECK_EQ(r.sink.last().eapol_frames, 0u);
    for (std::uint16_t s = 0; s < 3; ++s) r.feed(d, eapol_frame(kHome, kStation, s), 2000 + Millis{s} * 50);
    r.feed(d, eapol_frame(kOther, kStation, 9), 2200); // another BSS re-keying is not our context
    std::vector<std::uint8_t> protected_data = eapol_frame(kHome, kStation, 10);
    protected_data[1] = static_cast<std::uint8_t>(protected_data[1] | 0x40); // Protected: the parser never inspects it for EAPOL
    r.feed(d, protected_data, 2250);
    CHECK_EQ(d.stats().eapol_frames, 3u);
    CHECK_EQ(d.stats().other_frames, 2u);
    std::vector<std::uint8_t> b;
    if (!load(c_, "deauth_reason7", b)) return;
    set_sequence(b, 21);
    r.feed(d, b, 2300);
    const IncidentObservation& i = r.sink.last();
    CHECK_EQ(i.count, 21u);          // EAPOL never counts toward the burst
    CHECK_EQ(i.eapol_frames, 3u);    // but the window says it was there
    CHECK_EQ(i.kind, IncidentKind::DisconnectBurst);
}

// ---- disconnect burst through Core and the presenter ----------------------------------------
GUARDIAN_CASE(a_burst_reaches_core_and_stays_visible_over_a_very_good_rating_without_celebration) {
    Rig r;
    r.scope.select(home_baseline(c_));
    Core core(r.clock, profiles::all_2g4_channels(), Origin::Imported);
    CHECK(core.select(named(kHome)));
    std::vector<std::uint8_t> beacon;
    if (!load(c_, "beacon_wpa3_sae_pmf_required", beacon)) return;
    r.clock.set(1000);
    const RxMeta bm = meta_at(r.clock, 1000);
    core.security(observe_security(parser.parse(FrameSpan{beacon.data(), static_cast<std::uint16_t>(beacon.size()), false}, bm), bm));
    CHECK_EQ(core.snapshot().settings.mood, Mood::VeryGood);
    CHECK(!present(core.snapshot()).incident_visible); // (an Imported core never celebrates anyway: presenter policy)
    CHECK_EQ(present(core.snapshot()).overlay, Overlay::None);
    DisconnectDetector d(r.scope, r.limits);
    r.clock.set(2900);
    burst(c_, r, d, 20, 1000, 100, kHome, 1, &core);
    const Snapshot s = core.snapshot();
    CHECK(s.incidents[static_cast<std::size_t>(IncidentKind::DisconnectBurst)]);
    const IncidentObservation& e = s.evidence[static_cast<std::size_t>(IncidentKind::DisconnectBurst)];
    CHECK_EQ(e.count, 20u);
    CHECK_EQ(e.window_ms, 10000u);
    CHECK_EQ(e.threshold, 20u);
    CHECK_EQ(e.acquired.at, Millis{2900});
    CHECK_EQ(s.settings.mood, Mood::VeryGood);       // the grade stays
    const ViewModel v = present(s);
    CHECK(v.incident_visible);
    CHECK_EQ(v.overlay, Overlay::Incident);          // the incident is the status
    CHECK_EQ(v.face, Mood::VeryGood);
    CHECK(!v.celebrate);                             // never the cigar alone while a burst is current
    CHECK_EQ(s.rejected.origin, 0u);
    // Lost coverage during the incident: both facts stay visible, no grade.
    core.coverage(listening(r.clock, 2900, 0, 0));
    const ViewModel degraded = present(core.snapshot());
    CHECK(degraded.incident_visible);
    CHECK_EQ(degraded.overlay, Overlay::CoverageDegraded);
    CHECK(!degraded.celebrate);
    // Core's visibility window (60 s from the evidence instant) and freshness expire independently.
    r.clock.set(2900 + Core::incident_ms);
    CHECK(!core.snapshot().incidents[0]);
    CHECK_EQ(core.snapshot().coverage, Coverage::Stale);
    // Origin isolation: an Imported detector cannot raise an incident in a live core.
    Core live(r.clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    live.select(named(kHome));
    DisconnectDetector dl(r.scope, r.limits);
    burst(c_, r, dl, 20, 70000, 10, kHome, 1, &live);
    CHECK(!live.snapshot().incidents[0]);
    CHECK_EQ(live.snapshot().rejected.origin, 1u);
}

// ---- baselines: explicit approval, settings and channel changes --------------------------------
GUARDIAN_CASE(settings_fingerprint_is_over_valid_fields_only_and_names_what_differs) {
    const SettingsFingerprint wpa3 = fingerprint_of(c_, "beacon_wpa3_sae_pmf_required");
    const SettingsFingerprint wpa2 = fingerprint_of(c_, "beacon_wpa2_ccmp_pmf_optional");
    const SettingsFingerprint open = fingerprint_of(c_, "beacon_open");
    const SettingsFingerprint wpa1 = fingerprint_of(c_, "beacon_wpa1_tkip_vendor");
    const SettingsFingerprint owe = fingerprint_of(c_, "beacon_owe_transition");
    const SettingsFingerprint ch11 = fingerprint_of(c_, "beacon_wpa3_channel_11");
    const SettingsFingerprint hidden = fingerprint_of(c_, "beacon_hidden_ssid_wpa2");
    CHECK(wpa3 == wpa3);
    CHECK(wpa3 == ch11);                                   // the channel is not part of the settings fingerprint
    CHECK(wpa2 == hidden);                                 // SSID presentation is not a setting
    CHECK_EQ(wpa3.diff(wpa2), static_cast<std::uint8_t>(change::Rsn | change::Pmf));
    CHECK_EQ(wpa2.diff(wpa3), wpa3.diff(wpa2));
    CHECK_EQ(wpa3.diff(open), static_cast<std::uint8_t>(change::Privacy | change::Rsn | change::Pmf));
    CHECK_EQ(wpa3.diff(wpa1) & change::Wpa, change::Wpa);
    CHECK_EQ(wpa3.diff(wpa1) & change::Rsn, change::Rsn);
    CHECK_EQ(wpa3.diff(owe) & change::OweTransition, change::OweTransition);
    CHECK_EQ(wpa3.diff(owe) & change::Rsn, change::Rsn);
    CHECK_EQ(wpa3.diff(owe) & change::Pmf, 0);            // both advertise PMF required
    CHECK(wpa3.rsn_state == ElementState::Valid && wpa3.pmf == Pmf::Required && wpa3.privacy_bit);
    CHECK_EQ(wpa3.rsn_akms, akm::Sae);
    CHECK_EQ(wpa2.pmf, Pmf::Optional);
    CHECK_EQ(open.rsn_state, ElementState::Absent);
    CHECK_EQ(open.pmf, Pmf::Unknown);
    // Vendor churn: an extra vendor element at the end changes nothing.
    std::vector<std::uint8_t> b;
    if (!load(c_, "beacon_wpa3_sae_pmf_required", b)) return;
    for (auto x : {0xdd, 0x05, 0x00, 0x11, 0x22, 0x01, 0x02}) b.push_back(static_cast<std::uint8_t>(x));
    FakeClock clock;
    const ParseResult p = parser.parse(FrameSpan{b.data(), static_cast<std::uint16_t>(b.size()), false}, meta_at(clock, 0));
    CHECK_EQ(p.status, ParseStatus::Complete);
    CHECK(SettingsFingerprint::of(p.settings) == wpa3);
    // A Truncated RSNE is a different (non-Valid) state, not zeroed-into-equality with a Valid one; callers compare
    // Complete parses only (the detector enforces that), the fingerprint itself never hides the difference.
    std::vector<std::uint8_t> cut;
    if (!load(c_, "beacon_rsn_truncated_ie", cut)) return;
    const ParseResult pc = parser.parse(FrameSpan{cut.data(), static_cast<std::uint16_t>(cut.size()), false}, meta_at(clock, 0));
    CHECK_EQ(pc.status, ParseStatus::Truncated);
    const SettingsFingerprint fc = SettingsFingerprint::of(pc.settings);
    CHECK_EQ(fc.rsn_state, ElementState::Truncated);
    CHECK_EQ(fc.rsn_akms, 0);
    CHECK_EQ(fc.diff(wpa3) & change::Rsn, change::Rsn);
    // Defense in depth: fields of a non-Valid element never enter the fingerprint even if a parser left them set.
    AdvertisedSettings hand{};
    hand.privacy_valid = true;
    hand.privacy_bit = true;
    hand.rsn.state = ElementState::Malformed;
    hand.rsn.akms.kinds = akm::Sae;
    hand.rsn.pairwise.kinds = cipher::Ccmp128;
    hand.rsn.group.kind = cipher::Ccmp128;
    hand.rsn.group_management.kind = cipher::BipCmac128;
    hand.rsn.pmf = Pmf::Required;
    hand.wpa.state = ElementState::Conflicting;
    hand.wpa.akms.kinds = akm::Wpa1Psk;
    const SettingsFingerprint fh = SettingsFingerprint::of(hand);
    CHECK_EQ(fh.rsn_state, ElementState::Malformed);
    CHECK_EQ(fh.rsn_akms, 0);
    CHECK_EQ(fh.rsn_pairwise, 0);
    CHECK_EQ(fh.rsn_group, 0);
    CHECK_EQ(fh.rsn_group_management, 0);
    CHECK_EQ(fh.pmf, Pmf::Unknown);
    CHECK_EQ(fh.wpa_state, ElementState::Conflicting);
    CHECK_EQ(fh.wpa_akms, 0);
    CHECK(fh.privacy_bit);
}

GUARDIAN_CASE(approval_is_explicit_bounded_and_never_learned_from_traffic) {
    ApprovedScope scope; // default max_approved_aps = 8
    CHECK(!scope.has_selection());
    ApprovedAp bad{};
    bad.network = named(kHome);
    bad.network.bssid[0] = 0x03; // group address
    CHECK(!scope.select(bad));
    bad.network.bssid = Mac{};   // zero
    CHECK(!scope.select(bad));
    bad.network = named(kHome);
    bad.network.ssid_size = 33;
    CHECK(!scope.select(bad));
    CHECK(!scope.has_selection());
    ApprovedAp home{};
    home.network = named(kHome);
    CHECK(scope.select(home));
    CHECK(scope.has_selection());
    CHECK(scope.in_scope(kHome));
    CHECK(!scope.selected().settings_known && !scope.selected().channel_known); // no baseline facts unless approved
    CHECK(!scope.approve(home)); // the selected BSSID is not a "related" AP
    for (std::uint8_t k = 0; k < 8; ++k) {
        ApprovedAp a{};
        a.network = named(Mac{0x02, 0x11, 0x22, 0x33, 0x55, k});
        CHECK(scope.approve(a));
    }
    CHECK_EQ(scope.approved_count(), std::size_t{8});
    ApprovedAp ninth{};
    ninth.network = named(kOther);
    CHECK(!scope.approve(ninth)); // full: refused, nothing silently dropped
    CHECK_EQ(scope.approved_count(), std::size_t{8});
    CHECK(!scope.in_scope(kOther));
    ApprovedAp again{};
    again.network = named(Mac{0x02, 0x11, 0x22, 0x33, 0x55, 3});
    again.channel_known = true;
    again.channel = 11;
    CHECK(scope.approve(again)); // same BSSID: replaced in place
    CHECK_EQ(scope.approved_count(), std::size_t{8});
    CHECK(scope.find(again.network.bssid) != nullptr && scope.find(again.network.bssid)->channel == 11);
    CHECK(scope.revoke(again.network.bssid));
    CHECK(!scope.revoke(again.network.bssid));
    CHECK_EQ(scope.approved_count(), std::size_t{7});
    CHECK(scope.approve(ninth));
    // Traffic never adds anything: 100 beacons of the home SSID from an unknown BSSID leave the scope as it is.
    Rig r;
    r.limits.cooldown_ms = 0;
    r.scope.select(home_baseline(c_));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> b;
    if (!load(c_, "beacon_same_ssid_other_bssid_wpa2", b)) return;
    for (int k = 0; k < 100; ++k) r.feed(d, b, 100 * static_cast<Millis>(k));
    CHECK_EQ(r.scope.approved_count(), std::size_t{0});
    CHECK(r.scope.find(kOther) == nullptr);
    CHECK_EQ(d.stats().unexpected, 100u);
    CHECK(r.sink.count > 0);
    // The owner approves it: from then on it is handled normally and raises nothing.
    ApprovedAp other{};
    other.network = named(kOther);
    CHECK(r.scope.approve(other));
    const std::size_t reports = r.sink.count;
    for (int k = 100; k < 110; ++k) r.feed(d, b, 100 * static_cast<Millis>(k));
    CHECK_EQ(d.stats().unexpected, 100u);
    CHECK_EQ(d.stats().no_baseline, 10u); // in scope, but no approved settings/channel for it: nothing to compare
    CHECK_EQ(r.sink.count, reports);
    // clear() drops everything.
    r.scope.clear();
    CHECK(!r.scope.has_selection());
    CHECK_EQ(r.scope.approved_count(), std::size_t{0});
}

GUARDIAN_CASE(no_approved_baseline_means_no_comparison_and_no_report) {
    Rig r;
    r.scope.select(home_baseline(c_, false, false)); // selected, but the owner approved no settings or channel
    BaselineDetector d(r.scope, r.limits);
    for (const char* f : {"beacon_wpa3_sae_pmf_required", "beacon_wpa2_ccmp_pmf_optional", "beacon_wpa3_channel_11", "beacon_open"}) {
        std::vector<std::uint8_t> b;
        if (!load(c_, f, b)) continue;
        for (int k = 0; k < 3; ++k) r.feed(d, b, 100 * static_cast<Millis>(k));
    }
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.stats().in_scope, 12u);
    CHECK_EQ(d.stats().no_baseline, 12u);
    CHECK_EQ(d.stats().changed, 0u);
}

GUARDIAN_CASE(the_selected_ap_advertising_other_settings_is_a_settings_change_naming_the_fields) {
    Rig r;
    r.scope.select(home_baseline(c_));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> wpa2;
    if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", wpa2)) return;
    r.feed(d, wpa2, 1000);
    CHECK_EQ(r.sink.count, std::size_t{0}); // one differing beacon is not yet a change (change_threshold 2)
    CHECK_EQ(d.stats().changed, 1u);
    r.feed(d, wpa2, 1100);
    // G25: the owner's router changing its own security is a pending RouterChange, never an incident.
    CHECK_EQ(r.sink.count, std::size_t{0});
    const RouterChange& i = d.router().change;
    CHECK(i.pending);
    CHECK_EQ(i.bssid, kHome);
    CHECK_EQ(i.changes, static_cast<std::uint8_t>(change::Rsn | change::Pmf)); // SAE -> PSK, PMF required -> optional
    CHECK_EQ(i.count, 2u);
    CHECK_EQ(i.first.at, Millis{1100});
    CHECK(i.from == home_baseline(c_).settings);
    CHECK(i.to == fingerprint_of(c_, "beacon_wpa2_ccmp_pmf_optional"));
    CHECK(i.downgrade);
    // Channel only: same settings on channel 11 against the approved channel 6.
    Rig ch;
    ch.scope.select(home_baseline(c_));
    BaselineDetector dc(ch.scope, ch.limits);
    std::vector<std::uint8_t> c11;
    if (!load(c_, "beacon_wpa3_channel_11", c11)) return;
    ch.feed(dc, c11, 0);
    ch.feed(dc, c11, 100);
    CHECK_EQ(ch.sink.count, std::size_t{0});   // G25: a channel move is re-baselined, never an incident
    CHECK_EQ(dc.router().moves, 1u);
    CHECK(!dc.router().change.pending);
    // Without an approved channel the same beacons are unchanged (settings match).
    Rig noch;
    noch.scope.select(home_baseline(c_, true, false));
    BaselineDetector dn(noch.scope, noch.limits);
    noch.feed(dn, c11, 0);
    noch.feed(dn, c11, 100);
    CHECK_EQ(noch.sink.count, std::size_t{0});
    CHECK_EQ(dn.stats().unchanged, 2u);
    // Open and WPA1 variants from the home BSSID name their fields too.
    Rig open;
    open.limits.cooldown_ms = 0;
    open.scope.select(home_baseline(c_));
    BaselineDetector dopen(open.scope, open.limits);
    std::vector<std::uint8_t> o, w1;
    if (!load(c_, "beacon_open", o) || !load(c_, "beacon_wpa1_tkip_vendor", w1)) return;
    open.feed(dopen, o, 0);
    open.feed(dopen, o, 100);
    CHECK_EQ(dopen.router().change.changes, static_cast<std::uint8_t>(change::Privacy | change::Rsn | change::Pmf));
    CHECK(dopen.router().change.downgrade);   // anything -> open
    open.tick(dopen, 20000); // window drained
    open.feed(dopen, w1, 20000);
    open.feed(dopen, w1, 20100);
    // Still the same pending change (never re-reported); the fields seen differing accumulate.
    CHECK_EQ(dopen.router().change.changes & (change::Wpa | change::Rsn), change::Wpa | change::Rsn);
    CHECK_EQ(dopen.router().change.changes & change::Channel, 0);
    CHECK_EQ(open.sink.count, std::size_t{0});
}

GUARDIAN_CASE(the_same_settings_from_the_selected_ap_are_unchanged_and_report_nothing) {
    Rig r;
    r.scope.select(home_baseline(c_));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> b;
    if (!load(c_, "beacon_wpa3_sae_pmf_required", b)) return;
    for (int k = 0; k < 600; ++k) r.feed(d, b, 100 * static_cast<Millis>(k)); // a minute of beacons
    r.tick(d, 61000);
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.stats().unchanged, 600u);
    CHECK_EQ(d.stats().changed, 0u);
    CHECK_EQ(d.stats().in_scope, 600u);
    CHECK_EQ(d.stats().reports, 0u);
}

GUARDIAN_CASE(incomplete_or_unverified_advertisements_prove_nothing_about_a_change) {
    Rig r;
    r.scope.select(home_baseline(c_));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> cut, bad, wpa2;
    if (!load(c_, "beacon_rsn_truncated_ie", cut) || !load(c_, "beacon_rsn_pmf_inconsistent", bad) || !load(c_, "beacon_wpa2_ccmp_pmf_optional", wpa2)) return;
    for (int k = 0; k < 5; ++k) {
        CHECK_EQ(r.feed(d, cut, 100 * static_cast<Millis>(k)).status, ParseStatus::Truncated);
        CHECK_EQ(r.feed(d, bad, 100 * static_cast<Millis>(k) + 50).status, ParseStatus::Malformed);
        r.feed(d, wpa2, 100 * static_cast<Millis>(k) + 70, Origin::Imported, RxStatus::Unknown); // the adapter cannot vouch for the bytes
    }
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.stats().skipped_incomplete, 10u);
    CHECK_EQ(d.stats().skipped_unverified, 5u);
    CHECK_EQ(d.stats().changed, 0u);
    // Two verified, Complete differing beacons: a change (G25: a pending router change, not an incident).
    CHECK(!d.router().change.pending);
    r.feed(d, wpa2, 1000);
    r.feed(d, wpa2, 1100);
    CHECK(d.router().change.pending); CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.stats().advertisements, 17u);
}

// Owner rule (2026-11-15): impostor (same name, other BSSID) observations only
// for a network the owner put on the watch list; a phone hotspot that restarts
// with a new random BSSID must not raise a big ALERT.
GUARDIAN_CASE(an_unwatched_selection_never_reports_same_name_aps) {
    Rig r;
    r.limits.cooldown_ms = 0;
    auto home = home_baseline(c_); home.watch_impostors = false;
    r.scope.select(home);
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> other;
    if (!load(c_, "beacon_same_ssid_other_bssid_wpa2", other)) return;
    for (Millis t = 1000; t < 3000; t += 100) r.feed(d, other, t);
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.stats().unexpected, 0u);
    CHECK(d.stats().same_name_unwatched >= 20u);
}

GUARDIAN_CASE(the_selected_ssid_from_an_unapproved_bssid_is_an_unexpected_ap_observation_not_an_evil_twin_verdict) {
    Rig r;
    r.limits.cooldown_ms = 0;
    r.scope.select(home_baseline(c_));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> other, ext;
    if (!load(c_, "beacon_same_ssid_other_bssid_wpa2", other) || !load(c_, "beacon_wpa3_extender_bssid_56", ext)) return;
    r.feed(d, other, 1000);
    CHECK_EQ(r.sink.count, std::size_t{0}); // one beacon is not yet reported
    r.feed(d, other, 1100);
    CHECK_EQ(r.sink.count, std::size_t{1});
    const IncidentObservation first = r.sink.last();
    CHECK_EQ(first.kind, IncidentKind::UnexpectedAp);
    CHECK(first.affected == named(kHome));
    CHECK_EQ(first.bssid, kOther);
    CHECK_EQ(first.count, 1u);      // distinct unapproved BSSIDs in the window
    CHECK_EQ(first.raw_frames, 2u); // advertisements
    CHECK_EQ(first.threshold, 2u);
    CHECK_EQ(first.changes, static_cast<std::uint8_t>(change::Bssid | change::Rsn | change::Pmf)); // weaker settings than the approved home baseline
    CHECK_EQ(first.changes & change::Channel, 0); // same channel 6
    // A second unapproved BSSID with identical settings (not yet approved extender): distinct count 2, Bssid only for it.
    r.feed(d, ext, 1200);
    const IncidentObservation second = r.sink.last();
    CHECK_EQ(second.count, 2u);
    CHECK_EQ(second.bssid, kExtender);
    CHECK_EQ(second.raw_frames, 3u);
    CHECK_EQ(second.changes & change::Bssid, change::Bssid);
    CHECK_EQ(d.stats().unexpected, 3u);
    CHECK_EQ(d.stats().in_scope, 0u);
    // Nothing in the record is an identity claim: the BSSID is the observed Address 3, the changes are field differences.
    CHECK_EQ(second.protected_frames, 0u);
    CHECK_EQ(second.retries_deduped, 0u);
}

GUARDIAN_CASE(a_related_ap_never_carries_the_watch_flag) {
    Rig r;
    r.scope.select(home_baseline(c_));
    ApprovedAp ext = home_baseline(c_);
    ext.network = named(kExtender);
    CHECK(r.scope.approve(ext));                    // template copied from the watched selection
    const auto* stored = r.scope.find(kExtender);
    CHECK(stored && !stored->watch_impostors);      // stored unwatched: one meaning only
    CHECK(r.scope.selected().watch_impostors);
}

GUARDIAN_CASE(an_approved_extender_with_the_same_ssid_is_handled_like_the_selected_ap) {
    Rig r;
    r.scope.select(home_baseline(c_));
    ApprovedAp ext = home_baseline(c_);
    ext.network = named(kExtender);
    ext.watch_impostors = false; // watch is a property of the selection only
    CHECK(r.scope.approve(ext));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> b;
    if (!load(c_, "beacon_wpa3_extender_bssid_56", b)) return;
    for (int k = 0; k < 10; ++k) r.feed(d, b, 100 * static_cast<Millis>(k));
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.stats().unexpected, 0u);
    CHECK_EQ(d.stats().unchanged, 10u);
    CHECK_EQ(d.stats().in_scope, 10u);
    // Its own baseline applies: approved on channel 11, the channel-6 beacons are a change of the extender.
    ext.channel = 11;
    CHECK(r.scope.approve(ext));
    d.reset();   // the owner changed the scope (Monitor::approve resets the detector)
    r.feed(d, b, 2000);
    r.feed(d, b, 2100);
    CHECK_EQ(r.sink.count, std::size_t{0});   // G25: the extender moved channel: re-baselined, no incident
    CHECK_EQ(d.router().moves, 1u);
    CHECK_EQ(d.router().last_move.bssid, kExtender);
    CHECK_EQ(unsigned(d.router().last_move.from), 11u);
    CHECK_EQ(unsigned(d.router().last_move.to), 6u);
    // An approved related AP with no baseline facts is simply in scope.
    ApprovedAp plain{};
    plain.network = named(kExtender);
    CHECK(r.scope.approve(plain));
    r.feed(d, b, 3000);
    CHECK_EQ(d.stats().no_baseline, 1u);
}

GUARDIAN_CASE(neighbours_with_other_or_hidden_ssids_are_ignored) {
    Rig r;
    r.scope.select(home_baseline(c_));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> hidden, binary, named_other;
    if (!load(c_, "beacon_hidden_ssid_wpa2", hidden) || !load(c_, "beacon_ssid_non_utf8", binary) || !load(c_, "beacon_same_ssid_other_bssid_wpa2", named_other)) return;
    set_bssid_and_transmitter(hidden, kNeighbour); // a hidden network next door: says nothing about the name
    set_bssid_and_transmitter(binary, kNeighbour); // another SSID entirely
    named_other[38] = 'H'; // "Home": a different byte sequence is a different name (byte identity, no case folding)
    for (int k = 0; k < 5; ++k) {
        r.feed(d, hidden, 100 * static_cast<Millis>(k));
        r.feed(d, binary, 100 * static_cast<Millis>(k) + 30);
        r.feed(d, named_other, 100 * static_cast<Millis>(k) + 60);
    }
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.stats().neighbours, 15u);
    CHECK_EQ(d.stats().unexpected, 0u);
    CHECK_EQ(d.stats().in_scope, 0u);
    // A hidden selection (zero-length SSID identity) matches no name either: hidden beacons from unknown BSSIDs are neighbours.
    Rig h;
    ApprovedAp hid = home_baseline(c_);
    hid.network.ssid_size = 0;
    h.scope.select(hid);
    BaselineDetector dh(h.scope, h.limits);
    h.feed(dh, hidden, 0);
    h.feed(dh, hidden, 100);
    CHECK_EQ(h.sink.count, std::size_t{0});
    CHECK_EQ(dh.stats().neighbours, 2u);
}

GUARDIAN_CASE(baseline_reports_follow_the_window_cooldown_and_bound_like_bursts) {
    Rig r;
    r.scope.select(home_baseline(c_));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> wpa2;
    if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", wpa2)) return;
    r.feed(d, wpa2, 0);
    r.feed(d, wpa2, 15000); // 15 s apart: never two inside one window
    CHECK(!d.router().change.pending);
    r.feed(d, wpa2, 15100);
    CHECK(d.router().change.pending);
    CHECK_EQ(d.router().change_seq, 1u);
    for (int k = 2; k < 100; ++k) r.feed(d, wpa2, 15000 + 100 * static_cast<Millis>(k)); // keeps differing for 10 s
    r.feed(d, wpa2, 15100 + DetectorLimits{}.cooldown_ms);
    r.feed(d, wpa2, 15200 + DetectorLimits{}.cooldown_ms);
    // G25: confirmed once, never re-fired by the cooldown while the router keeps the new settings.
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(d.router().change_seq, 1u);
    CHECK_EQ(d.stats().reports, 1u);
    CHECK_EQ(d.router().change.count, 102u);   // 2 at the confirmation + 98 + 2
    // Foreign epochs and invalid instants are ignored and counted; reset clears.
    std::vector<std::uint8_t> b = wpa2;
    RxMeta foreign = meta_at(r.clock, 80000);
    foreign.acquired.epoch = epoch_of(1, 2);
    const FrameSpan span{b.data(), static_cast<std::uint16_t>(b.size()), false};
    { AllocationBan ban; d.on_frame(span, foreign, parser.parse(span, foreign), r.sink); }
    RxMeta unknown = meta_at(r.clock, 80000);
    unknown.acquired.known = false;
    { AllocationBan ban; d.on_frame(span, unknown, parser.parse(span, unknown), r.sink); }
    CHECK_EQ(d.stats().foreign_epoch, 1u);
    CHECK_EQ(d.stats().invalid_time, 1u);
    d.reset();
    CHECK_EQ(d.stats().changed, 0u);
    CHECK_EQ(d.stats().reports, 0u);
    // Bound: 40 distinct unapproved BSSIDs in one window saturate the 32-entry ring and say so.
    Rig many;
    many.limits.cooldown_ms = 0;
    many.scope.select(home_baseline(c_));
    BaselineDetector dm(many.scope, many.limits);
    std::vector<std::uint8_t> other;
    if (!load(c_, "beacon_same_ssid_other_bssid_wpa2", other)) return;
    for (std::uint8_t k = 0; k < 40; ++k) {
        set_bssid_and_transmitter(other, Mac{0x02, 0x44, 0x44, 0x44, 0x44, k});
        many.feed(dm, other, 10 * static_cast<Millis>(k));
    }
    CHECK(many.sink.last().saturated);
    CHECK_EQ(many.sink.last().count, 32u); // distinct BSSIDs still held: a lower bound
    CHECK(dm.stats().evicted_in_window > 0u);
}

GUARDIAN_CASE(an_unexpected_ap_reaches_core_with_its_evidence_and_the_grade_stays) {
    Rig r;
    r.scope.select(home_baseline(c_));
    Core core(r.clock, profiles::all_2g4_channels(), Origin::Imported);
    core.select(named(kHome));
    std::vector<std::uint8_t> beacon, other;
    if (!load(c_, "beacon_wpa3_sae_pmf_required", beacon) || !load(c_, "beacon_same_ssid_other_bssid_wpa2", other)) return;
    r.clock.set(1000);
    const RxMeta bm = meta_at(r.clock, 1000);
    core.security(observe_security(parser.parse(FrameSpan{beacon.data(), static_cast<std::uint16_t>(beacon.size()), false}, bm), bm));
    BaselineDetector d(r.scope, r.limits);
    r.clock.set(1200);
    r.feed(d, other, 1100, Origin::Imported, RxStatus::Ok, &core);
    r.feed(d, other, 1200, Origin::Imported, RxStatus::Ok, &core);
    const Snapshot s = core.snapshot();
    CHECK(s.incidents[static_cast<std::size_t>(IncidentKind::UnexpectedAp)]);
    CHECK(!s.incidents[static_cast<std::size_t>(IncidentKind::SettingsChanged)]);
    const IncidentObservation& e = s.evidence[static_cast<std::size_t>(IncidentKind::UnexpectedAp)];
    CHECK_EQ(e.bssid, kOther);
    CHECK_EQ(e.changes & change::Bssid, change::Bssid);
    CHECK_EQ(e.count, 1u);
    CHECK_EQ(s.settings.mood, Mood::VeryGood); // home's own fresh evidence is untouched
    const ViewModel v = present(s);
    CHECK(v.incident_visible);
    CHECK_EQ(v.overlay, Overlay::Incident);
    CHECK(!v.celebrate);
    CHECK_EQ(s.rejected.network, 0u); // the incident is scoped to the selected network, not to the other BSSID
}

GUARDIAN_CASE(mixed_replay_over_every_fixture_allocates_nothing_and_reports_only_the_documented_cases) {
    Rig r;
    r.limits.cooldown_ms = 0;
    r.scope.select(home_baseline(c_));
    DisconnectDetector dd(r.scope, r.limits);
    BaselineDetector db(r.scope, r.limits);
    const auto names = fixtures::list();
    CHECK(names.size() >= 28);
    Millis t = 0;
    for (int pass = 0; pass < 3; ++pass) {
        for (const auto& name : names) {
            std::vector<std::uint8_t> b;
            if (!load(c_, name.c_str(), b)) continue;
            r.feed(dd, b, t);
            r.feed(db, b, t);
            t += 50;
        }
        r.tick(dd, t);
        r.tick(db, t);
    }
    // Disconnect fixtures: 4 distinct headers per pass, identical across passes but far outside dedupe_ms -> counted each pass.
    CHECK_EQ(dd.stats().counted, 12u);
    CHECK_EQ(dd.stats().reports, 0u);
    // Baseline: the home BSSID advertises several different configurations across the fixtures -> a pending
    // router change (G25: never an incident); the two unapproved same-SSID fixtures -> UnexpectedAp;
    // neighbours/hidden ignored.
    CHECK(db.stats().changed > 0u);
    CHECK(db.stats().unexpected == 6u);
    CHECK(db.stats().skipped_incomplete > 0u);
    bool saw_settings = false, saw_unexpected = false, saw_burst = false;
    for (std::size_t i = 0; i < r.sink.count && i < r.sink.incidents.size(); ++i) {
        saw_settings |= r.sink.incidents[i].kind == IncidentKind::SettingsChanged;
        saw_unexpected |= r.sink.incidents[i].kind == IncidentKind::UnexpectedAp;
        saw_burst |= r.sink.incidents[i].kind == IncidentKind::DisconnectBurst;
    }
    CHECK(!saw_settings);
    CHECK(db.router().change.pending);
    CHECK(saw_unexpected);
    CHECK(!saw_burst);
}


GUARDIAN_CASE(review_disconnect_cannot_relabel_imported_counts_as_live) {
    Rig r; CHECK(r.scope.select(home_baseline(c_)));
    DetectorLimits l; l.burst_threshold = 2;
    DisconnectDetector d(r.scope, l);
    std::vector<std::uint8_t> b; if (!load(c_, "deauth_reason7", b)) return;
    r.feed(d, b, 100, Origin::Imported);
    set_sequence(b, 2); r.feed(d, b, 101, Origin::LiveRadio);
    CHECK_EQ(r.sink.count, std::size_t{0});
    set_sequence(b, 3); r.feed(d, b, 102, Origin::Imported);
    CHECK_EQ(r.sink.count, std::size_t{1});
    CHECK_EQ(r.sink.last().origin, Origin::Imported);
    CHECK_EQ(r.sink.last().count, 2u);
    d.reset(); r.sink.count = 0;
    r.feed(d, b, 103, Origin::LiveRadio);
    set_sequence(b, 4); r.feed(d, b, 104, Origin::LiveRadio);
    CHECK_EQ(r.sink.count, std::size_t{1});
    CHECK_EQ(r.sink.last().origin, Origin::LiveRadio);
}
GUARDIAN_CASE(review_baseline_cannot_relabel_imported_counts_as_live) {
    Rig r; CHECK(r.scope.select(home_baseline(c_)));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> b; if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", b)) return;
    r.feed(d, b, 100, Origin::Imported);
    r.feed(d, b, 101, Origin::LiveRadio);
    CHECK(!d.router().change.pending);   // the live frame was refused: one counted advertisement
    r.feed(d, b, 102, Origin::Imported);
    CHECK(d.router().change.pending); CHECK_EQ(d.router().change.count, 2u);
    CHECK_EQ(d.stats().foreign_origin, 1u);
}
GUARDIAN_CASE(review_unverified_disconnect_bytes_do_not_create_a_burst) {
    Rig r; CHECK(r.scope.select(home_baseline(c_)));
    DetectorLimits l; l.burst_threshold = 2;
    DisconnectDetector d(r.scope, l);
    std::vector<std::uint8_t> b; if (!load(c_, "deauth_reason7", b)) return;
    r.feed(d, b, 100, Origin::Imported, RxStatus::Unknown);
    set_sequence(b, 2); r.feed(d, b, 101);
    CHECK_EQ(r.sink.count, std::size_t{0});
    set_sequence(b, 3); r.feed(d, b, 102);
    CHECK_EQ(r.sink.count, std::size_t{1});
    CHECK_EQ(r.sink.last().count, 2u);
}


GUARDIAN_CASE(g09_delayed_burst_retains_acquisition_time) {
    Rig r; CHECK(r.scope.select(home_baseline(c_)));
    DetectorLimits limits; limits.burst_threshold = 2;
    DisconnectDetector d(r.scope, limits);
    std::vector<std::uint8_t> b; if (!load(c_, "deauth_reason7", b)) return;
    r.feed(d, b, 100); r.tick(d, 5000);
    set_sequence(b, 2); r.feed(d, b, 101);
    CHECK_EQ(r.sink.count, std::size_t{1});
    CHECK_EQ(r.sink.last().acquired.at, Millis{101});
}
GUARDIAN_CASE(g09_delayed_baseline_retains_acquisition_time) {
    Rig r; CHECK(r.scope.select(home_baseline(c_)));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> b; if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", b)) return;
    r.feed(d, b, 100); r.tick(d, 5000); r.feed(d, b, 101);
    CHECK(d.router().change.pending);   // G25: a pending router change, not an incident
    CHECK_EQ(d.router().change.first.at, Millis{101});
}
GUARDIAN_CASE(g09_settings_threshold_is_per_ap) {
    Rig r; CHECK(r.scope.select(home_baseline(c_)));
    auto ext = home_baseline(c_); ext.network.bssid = kExtender; CHECK(r.scope.approve(ext));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> b; if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", b)) return;
    r.feed(d, b, 100); set_bssid_and_transmitter(b, kExtender); r.feed(d, b, 101);
    CHECK(!d.router().change.pending);
    r.feed(d, b, 102); CHECK(d.router().change.pending); CHECK_EQ(unsigned(d.router().pending), 1u);
    CHECK(d.router().change.bssid == kExtender); CHECK_EQ(d.router().change.count, 2u);
    CHECK_EQ(r.sink.count, std::size_t{0});
}

GUARDIAN_CASE(g09_settings_cooldowns_are_per_ap) {
    Rig r; CHECK(r.scope.select(home_baseline(c_)));
    auto ext=home_baseline(c_);ext.network.bssid=kExtender;CHECK(r.scope.approve(ext));
    BaselineDetector d(r.scope,r.limits);std::vector<std::uint8_t> b;
    if(!load(c_,"beacon_wpa2_ccmp_pmf_optional",b))return;
    r.feed(d,b,100);r.feed(d,b,101);CHECK_EQ(unsigned(d.router().pending),1u);
    set_bssid_and_transmitter(b,kExtender);r.feed(d,b,102);r.feed(d,b,103);
    // G25: one pending change per AP; the newest is shown first.
    CHECK_EQ(unsigned(d.router().pending),2u);CHECK(d.router().change.bssid==kExtender);CHECK_EQ(d.router().change_seq,2u);
    CHECK_EQ(r.sink.count,std::size_t{0});
}
GUARDIAN_CASE(g09_expired_delayed_frame_cannot_trigger_current_burst) {
    Rig r;CHECK(r.scope.select(home_baseline(c_)));DetectorLimits l;l.burst_threshold=2;l.cooldown_ms=1;
    DisconnectDetector d(r.scope,l);std::vector<std::uint8_t> b;if(!load(c_,"deauth_reason7",b))return;
    r.feed(d,b,10000);set_sequence(b,2);r.feed(d,b,10001);CHECK_EQ(r.sink.count,std::size_t{1});
    r.tick(d,10002);set_sequence(b,3);r.feed(d,b,1);CHECK_EQ(r.sink.count,std::size_t{1});
}

// ---- G25: the owner's router changing its own channel or settings is not an attack (TDD, red first) ----
// Evidence (owner STATUS 2026-11-21 ~20:50): after the router restarted, baseline events=110 incidents=1 kept
// re-firing a red "Advertised settings changed". Now: a channel move is re-baselined silently and counted;
// a security change is a pending RouterChange the presenter colours by the owner's setting.
namespace {
std::vector<std::uint8_t> beacon_on(check::Case& c_, const char* fixture, std::uint8_t ds_channel) {
    std::vector<std::uint8_t> b;
    if (!load(c_, fixture, b)) return b;
    // The DS Parameter Set element (id 3, length 1) after the fixed fields (24-byte header + 12).
    for (std::size_t i = 36; i + 2 < b.size(); i += 2u + b[i + 1]) {
        if (b[i] == 3 && b[i + 1] == 1) { b[i + 2] = ds_channel; return b; }
    }
    CHECK_FAIL(std::string(fixture) + ": no DS Parameter Set element");
    return b;
}
} // namespace

GUARDIAN_CASE(g25_a_channel_move_is_rebaselined_silently_counted_and_never_an_incident) {
    Rig r; CHECK(r.scope.select(home_baseline(c_)));   // approved: WPA3, channel 6
    Core core(r.clock, profiles::all_2g4_channels(), Origin::Imported); core.select(named(kHome));
    BaselineDetector d(r.scope, r.limits);
    const auto ch6 = beacon_on(c_, "beacon_wpa3_sae_pmf_required", 6), ch11 = beacon_on(c_, "beacon_wpa3_sae_pmf_required", 11);
    r.clock.set(100000);
    r.feed(d, ch6, 1000, Origin::Imported, RxStatus::Ok, &core);
    // One odd advertisement on another channel is not a move (change_threshold 2) ...
    r.feed(d, ch11, 1100, Origin::Imported, RxStatus::Ok, &core);
    CHECK_EQ(d.router().moves, 0u);
    // ... and an advertisement on the baseline channel in between starts the count again.
    r.feed(d, ch6, 1200, Origin::Imported, RxStatus::Ok, &core);
    r.feed(d, ch11, 1300, Origin::Imported, RxStatus::Ok, &core);
    CHECK_EQ(d.router().moves, 0u);
    r.feed(d, ch11, 1400, Origin::Imported, RxStatus::Ok, &core);
    CHECK_EQ(d.router().moves, 1u);
    const ChannelMove m = d.router().last_move;
    CHECK(m.known); CHECK_EQ(m.bssid, kHome); CHECK_EQ(unsigned(m.from), 6u); CHECK_EQ(unsigned(m.to), 11u);
    CHECK_EQ(m.at.at, Millis{1400}); CHECK(m.band == Band::Ghz2_4);
    CHECK_EQ(d.stats().channel_moves, 1u);
    // Handed once to the scope's owner for re-baselining.
    ChannelMove taken{};
    CHECK(d.take_move(taken)); CHECK_EQ(unsigned(taken.to), 11u); CHECK(!d.take_move(taken));
    // A minute of beacons on the new channel: nothing more (the detector compares with channel 11 now),
    // even before the owner of the scope re-baselines it.
    for (int k = 0; k < 600; ++k) r.feed(d, ch11, 1500 + 100 * static_cast<Millis>(k), Origin::Imported, RxStatus::Ok, &core);
    CHECK_EQ(d.router().moves, 1u);
    CHECK(!d.router().change.pending);
    CHECK_EQ(r.sink.count, std::size_t{0});
    const Snapshot s = core.snapshot();
    CHECK_EQ(s.incident_seq, 0u);   // nothing reached Core: no ALERT, no lit dark screen
    for (bool on : s.incidents) CHECK(!on);
    // It moves back: a second move, counted and named.
    r.feed(d, ch6, 70000); r.feed(d, ch6, 70100);
    CHECK_EQ(d.router().moves, 2u); CHECK_EQ(unsigned(d.router().last_move.from), 11u); CHECK_EQ(unsigned(d.router().last_move.to), 6u);
    // STATUS facts: the last thing the baseline detector recorded.
    CHECK(d.last().known); CHECK_EQ(d.last().bssid, kHome); CHECK_EQ(d.last().changes, change::Channel);
    CHECK_EQ(d.last().count, 2u); CHECK_EQ(d.last().at.at, Millis{70100});
    // The report keeps "incidents" for what was reported: no move is an incident.
    CHECK_EQ(d.report(r.at(70100)).incidents, 0u);
    // reset() (the owner changed the scope) forgets moves and the channel moved to.
    d.reset(); CHECK_EQ(d.router().moves, 0u); CHECK(!d.last().known);
}

GUARDIAN_CASE(g25_a_security_change_is_one_pending_router_change_with_old_and_new_never_a_red_incident) {
    Rig r; CHECK(r.scope.select(home_baseline(c_)));
    Core core(r.clock, profiles::all_2g4_channels(), Origin::Imported); core.select(named(kHome));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> wpa2;
    if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", wpa2)) return;
    r.clock.set(200000);
    for (int k = 0; k < 110; ++k) r.feed(d, wpa2, 1000 + 1000 * static_cast<Millis>(k), Origin::Imported, RxStatus::Ok, &core);
    const RouterState st = d.router();
    CHECK(st.change.pending); CHECK_EQ(unsigned(st.pending), 1u); CHECK_EQ(st.change_seq, 1u);   // once, never re-fired
    CHECK_EQ(st.change.bssid, kHome);
    CHECK_EQ(st.change.changes, static_cast<std::uint8_t>(change::Rsn | change::Pmf));
    CHECK(st.change.from == home_baseline(c_).settings);
    CHECK(st.change.to == fingerprint_of(c_, "beacon_wpa2_ccmp_pmf_optional"));
    CHECK(st.change.downgrade);
    CHECK_EQ(st.change.first.at, Millis{2000}); CHECK_EQ(st.change.last.at, Millis{110000});
    CHECK_EQ(st.change.count, 110u);
    CHECK_EQ(r.sink.count, std::size_t{0});
    CHECK_EQ(core.snapshot().incident_seq, 0u);
    CHECK(!core.snapshot().incidents[static_cast<std::size_t>(IncidentKind::SettingsChanged)]);
    CHECK_EQ(d.report(r.at(110000)).incidents, 1u);   // STATUS: one router change confirmed
    CHECK(d.last().known); CHECK_EQ(d.last().changes, static_cast<std::uint8_t>(change::Rsn | change::Pmf)); CHECK_EQ(d.last().count, 110u);
    // Reverting does not end it: the owner decides.
    std::vector<std::uint8_t> wpa3;
    if (!load(c_, "beacon_wpa3_sae_pmf_required", wpa3)) return;
    r.feed(d, wpa3, 120000); r.feed(d, wpa3, 120100);
    CHECK(d.router().change.pending); CHECK_EQ(d.router().change_seq, 1u);
    // A further field changing grows the record (seq + 1, so a dark screen may light once more).
    std::vector<std::uint8_t> open;
    if (!load(c_, "beacon_open", open)) return;
    r.feed(d, open, 130000); r.feed(d, open, 130100);
    CHECK_EQ(d.router().change_seq, 2u);
    CHECK_EQ(d.router().change.changes & change::Privacy, change::Privacy);
    CHECK(d.router().change.to == fingerprint_of(c_, "beacon_open"));
}

GUARDIAN_CASE(g25_accept_ends_the_change_hands_the_new_baseline_and_nothing_refires) {
    Rig r; CHECK(r.scope.select(home_baseline(c_)));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> wpa2;
    if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", wpa2)) return;
    r.feed(d, wpa2, 1000); r.feed(d, wpa2, 1100);
    SettingsFingerprint seen{};
    CHECK(!d.accept(kExtender, seen));   // nothing pending for another AP
    CHECK(d.accept(kHome, seen));
    CHECK(seen == fingerprint_of(c_, "beacon_wpa2_ccmp_pmf_optional"));
    CHECK(!d.router().change.pending); CHECK_EQ(unsigned(d.router().pending), 0u);
    CHECK(!d.accept(kHome, seen));
    // The scope's owner stores the new baseline (Monitor::accept_router_change); the router keeps advertising it.
    ApprovedAp now = home_baseline(c_); now.settings = seen; CHECK(r.scope.select(now));
    for (int k = 0; k < 120; ++k) r.feed(d, wpa2, 2000 + 1000 * static_cast<Millis>(k));
    CHECK(!d.router().change.pending); CHECK_EQ(d.router().change_seq, 1u); CHECK_EQ(r.sink.count, std::size_t{0});
    // Even before the owner stores it, the accepted settings do not re-fire.
    Rig q; CHECK(q.scope.select(home_baseline(c_)));
    BaselineDetector e(q.scope, q.limits);
    q.feed(e, wpa2, 1000); q.feed(e, wpa2, 1100); CHECK(e.accept(kHome, seen));
    for (int k = 0; k < 60; ++k) q.feed(e, wpa2, 2000 + 1000 * static_cast<Millis>(k));
    CHECK(!e.router().change.pending); CHECK_EQ(e.router().change_seq, 1u);
    // ... but a different change after the accept is a new one.
    std::vector<std::uint8_t> open;
    if (!load(c_, "beacon_open", open)) return;
    q.feed(e, open, 70000); q.feed(e, open, 70100);
    CHECK(e.router().change.pending); CHECK_EQ(e.router().change_seq, 2u);
}

GUARDIAN_CASE(g25_downgrade_and_summary_follow_the_owner_list) {
    const auto f = [&](const char* name) { return fingerprint_of(c_, name); };
    const auto wpa3 = f("beacon_wpa3_sae_pmf_required"), wpa2 = f("beacon_wpa2_ccmp_pmf_optional"), open = f("beacon_open"),
               wpa1 = f("beacon_wpa1_tkip_vendor"), mixed = f("beacon_wpa2_mixed_tkip");
    CHECK(summarize(wpa3).mode == Mode::Wpa3Personal); CHECK(summarize(wpa3).pmf == Pmf::Required); CHECK(summarize(wpa3).pairwise == Cipher::Ccmp);
    CHECK(summarize(wpa2).mode == Mode::Wpa2Personal); CHECK(summarize(wpa2).pmf == Pmf::Optional);
    CHECK(summarize(open).mode == Mode::Open); CHECK(summarize(open).pairwise == Cipher::None);
    CHECK(summarize(wpa1).mode == Mode::Wpa1); CHECK(summarize(wpa1).pairwise == Cipher::Tkip); CHECK(summarize(wpa1).pmf == Pmf::Disabled);
    CHECK(summarize(mixed).pairwise == Cipher::Tkip);   // weakest advertised
    CHECK(security_downgrade(wpa3, wpa2));    // WPA3 -> WPA2, PMF required -> optional
    CHECK(!security_downgrade(wpa2, wpa3));   // an upgrade
    CHECK(security_downgrade(wpa2, open));    // anything -> open
    CHECK(security_downgrade(wpa2, wpa1));    // WPA2 -> WPA, CCMP -> TKIP
    CHECK(security_downgrade(wpa2, mixed));   // CCMP -> TKIP alone
    CHECK(!security_downgrade(open, wpa2));
    CHECK(!security_downgrade(wpa2, wpa2));
    // PMF required -> optional alone (same mode and cipher).
    auto pmf_opt = wpa3; pmf_opt.pmf = Pmf::Optional;
    CHECK(security_downgrade(wpa3, pmf_opt)); CHECK(!security_downgrade(pmf_opt, wpa3));
    auto pmf_off = wpa3; pmf_off.pmf = Pmf::Disabled; CHECK(security_downgrade(wpa3, pmf_off));
}

GUARDIAN_CASE(g25_an_unexpected_ap_stays_a_red_incident_and_is_the_last_baseline_record) {
    Rig r; CHECK(r.scope.select(home_baseline(c_)));
    BaselineDetector d(r.scope, r.limits);
    std::vector<std::uint8_t> other;
    if (!load(c_, "beacon_same_ssid_other_bssid_wpa2", other)) return;
    r.feed(d, other, 1000); r.feed(d, other, 1100);
    CHECK_EQ(r.sink.count, std::size_t{1});
    CHECK_EQ(r.sink.last().kind, IncidentKind::UnexpectedAp);   // red stays: another BSSID using the name
    CHECK_EQ(r.sink.last().scope, IncidentScope::Network);
    CHECK(d.last().known); CHECK_EQ(d.last().bssid, kOther);
    CHECK_EQ(d.last().changes & change::Bssid, change::Bssid); CHECK_EQ(d.last().count, 1u); CHECK_EQ(d.last().at.at, Millis{1100});
    CHECK(!d.router().change.pending); CHECK_EQ(d.router().moves, 0u);
    // Its cooldown still holds (scope-wide), as before G25.
    r.feed(d, other, 2000); r.feed(d, other, 2100); CHECK_EQ(r.sink.count, std::size_t{1});
    r.feed(d, other, 1100 + DetectorLimits{}.cooldown_ms); r.feed(d, other, 1200 + DetectorLimits{}.cooldown_ms);
    CHECK_EQ(r.sink.count, std::size_t{2});
}

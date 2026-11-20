// G16E detection platform checks (TDD, run RED first against the G16D library;
// logs: $GUARDIAN_STORE/builds/20261117-g16e-host/red-*.log):
//   * IncidentScope: AREA incidents are about the air around the stick. They
//     need no selection, never change the security rating or the network
//     incidents, have their own visibility window and bounded storage.
//   * Every detector reports what it saw (frames, counted events, events in its
//     window, last incident, cooldown remaining) for STATUS and the G13 JSON.
//   * The bounded detector registry (fixed array, no allocation) drives the
//     detectors from Monitor::receive.
//   * The air meter: probes / beacons per 60 s and distinct transmitters,
//     bounded, saturation flagged.
// Generated frames are Imported/LiveRadio-stamped host input, never radio proof.
#include "check.hpp"
#include "fixtures.hpp"
#include "measurement.hpp"

#include "guardian/air.hpp"
#include "guardian/rating.hpp"
#include "guardian/registry.hpp"

#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <vector>

using namespace guardian;
using namespace guardian::measurement;

// ---- allocation ban (same technique as detector_check) -------------------------------
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
class Clock final : public MonotonicClock {
public:
    Millis at{100};
    std::uint32_t boot{1};
    Millis now() const override { return at; }
    TimeEpoch epoch() const override { TimeEpoch e{}; e.source_id[0] = 1; e.boot_id = boot; return e; }
};
const Mac kHome{0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
Network home() {
    Network n{}; n.bssid = kHome; n.ssid_size = 4;
    n.ssid[0] = 'h'; n.ssid[1] = 'o'; n.ssid[2] = 'm'; n.ssid[3] = 'e';
    return n;
}
Instant at(const Clock& c, Millis t) { return Instant{c.epoch(), t, true}; }

IncidentObservation area_obs(const Clock& c, Millis t, DetectorFamily family, std::uint32_t count = 312) {
    IncidentObservation o{};
    o.scope = IncidentScope::Area; o.family = family; o.origin = Origin::LiveRadio;
    o.acquired = at(c, t); o.count = count; o.window_ms = 5000; o.threshold = 80;
    o.distinct_sources = 214; o.sources_random = true;
    return o;
}

bool fixture(check::Case& c_, const char* name, std::vector<std::uint8_t>& out) {
    fixtures::Fixture f; std::string err;
    if (!fixtures::load(name, f, err)) { CHECK_FAIL(err); return false; }
    out = f.bytes; return true;
}
Packet packet(const Clock& clock, const std::vector<std::uint8_t>& b, Origin origin = Origin::LiveRadio) {
    Packet p{}; std::memcpy(p.bytes.data(), b.data(), b.size()); p.size = static_cast<std::uint16_t>(b.size());
    p.meta.acquired = {clock.epoch(), clock.now(), true}; p.meta.origin = origin; p.meta.status = RxStatus::Ok;
    p.meta.channel = 6; p.meta.rssi_dbm = -50; p.meta.rssi_valid = true;
    return p;
}
SecurityObservation fresh_wpa3(check::Case& c_, const Clock& clock) {
    std::vector<std::uint8_t> b; if (!fixture(c_, "beacon_wpa3_sae_pmf_required", b)) return {};
    const auto p = packet(clock, b);
    const auto r = SecurityFrameParser{}.parse(p.span(), p.meta);
    return observe_security(r, p.meta);
}
void set_bssid_and_transmitter(std::vector<std::uint8_t>& b, const Mac& m) {
    for (std::size_t i = 0; i < 6; ++i) { b[10 + i] = m[i]; b[16 + i] = m[i]; }
}
void set_sequence(std::vector<std::uint8_t>& b, std::uint16_t seq) {
    b[22] = static_cast<std::uint8_t>((seq << 4) & 0xff); b[23] = static_cast<std::uint8_t>(seq >> 4);
}

// A test-only AREA detector: emits one Area observation per `every` frames it
// sees. Stands in for the G16F detectors so the platform is tested on its own.
class FakeAreaDetector final : public FrameDetector {
public:
    explicit FakeAreaDetector(std::uint32_t every = 3) : every_(every) {}
    void on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult&, ObservationSink& out) override {
        ++frames; last_ = meta.acquired;
        if (++since_ < every_) return;
        since_ = 0;
        IncidentObservation o{}; o.scope = IncidentScope::Area; o.family = DetectorFamily::Probe; o.origin = meta.origin;
        o.acquired = meta.acquired; o.count = 312; o.window_ms = 5000; o.distinct_sources = 214; o.sources_random = true;
        ++emitted; out.incident(o);
    }
    void on_tick(Instant, ObservationSink&) override { ++ticks; }
    void reset() override { ++resets; since_ = 0; }
    void coverage(const CoverageReport&) override { ++coverages; }
    DetectorReport report(Instant) const override {
        DetectorReport r{}; r.name = "fake"; r.family = DetectorFamily::Probe; r.scope = IncidentScope::Area;
        r.configured = true; r.frames_seen = frames; r.events_total = frames; r.incidents = emitted; return r;
    }
    std::uint32_t frames{}, ticks{}, resets{}, coverages{}, emitted{};
private:
    std::uint32_t every_, since_{};
    Instant last_{};
};
class NullSink final : public ObservationSink {
public:
    void security(const SecurityObservation&) override {}
    void incident(const IncidentObservation&) override { ++incidents; }
    std::uint32_t incidents{};
};
} // namespace

// ---- IncidentScope in Core ---------------------------------------------------------------
GUARDIAN_CASE(area_incident_never_changes_the_rating_or_the_network_incidents) {
    Clock clock; Core core(clock, profiles::all_2g4_channels());
    CHECK(core.select(home()));
    core.security(fresh_wpa3(c_, clock));
    clock.at = 1000;
    const Snapshot before = core.snapshot();
    CHECK_EQ(before.settings.mood, Mood::VeryGood);
    core.incident(area_obs(clock, 900, DetectorFamily::Probe));
    const Snapshot after = core.snapshot();
    CHECK_EQ(after.settings.mood, before.settings.mood);
    CHECK_EQ(after.settings.reason, before.settings.reason);
    CHECK_EQ(after.settings.unrated, before.settings.unrated);
    CHECK_EQ(after.coverage, before.coverage);
    for (std::size_t k = 0; k < after.incidents.size(); ++k) CHECK(!after.incidents[k]);
    CHECK(after.area_visible[0]);
    CHECK_EQ(after.area[0].count, 312u);
    CHECK_EQ(after.area[0].family, DetectorFamily::Probe);
    CHECK_EQ(after.area[0].scope, IncidentScope::Area);
    CHECK_EQ(after.area_visible_ms, Core::area_incident_ms);
}

GUARDIAN_CASE(area_incident_needs_no_selection_but_a_network_incident_does) {
    Clock clock; Core core(clock, profiles::all_2g4_channels());
    clock.at = 2000;
    core.incident(area_obs(clock, 1500, DetectorFamily::Beacon));
    IncidentObservation net{}; net.scope = IncidentScope::Network; net.affected = home();
    net.acquired = at(clock, 1500); net.kind = IncidentKind::DisconnectBurst; net.count = 20;
    core.incident(net);
    const auto s = core.snapshot();
    CHECK(s.area_visible[0]);
    CHECK(!s.incidents[0]);
    CHECK_EQ(s.rejected.not_selected, 1u);
    // A Network observation for another network is still rejected (G06 scope unchanged).
    CHECK(core.select(home()));
    Network other = home(); other.bssid[5] = 0x66; net.affected = other;
    core.incident(net);
    CHECK(!core.snapshot().incidents[0]);
    CHECK_EQ(core.snapshot().rejected.network, 1u);
}

GUARDIAN_CASE(area_visibility_has_its_own_tunable_window) {
    Clock clock; Core core(clock, profiles::all_2g4_channels());
    clock.at = 1000; core.incident(area_obs(clock, 1000, DetectorFamily::Auth));
    clock.at = 1000 + Core::area_incident_ms - 1; CHECK(core.snapshot().area_visible[0]);
    clock.at = 1000 + Core::area_incident_ms; CHECK(!core.snapshot().area_visible[0]);
    CHECK(!core.set_area_visibility(0));                      // refused: nothing would ever show
    CHECK(core.set_area_visibility(5000));
    clock.at = 10000; core.incident(area_obs(clock, 10000, DetectorFamily::Auth));
    clock.at = 14999; CHECK(core.snapshot().area_visible[0]);
    clock.at = 15000; CHECK(!core.snapshot().area_visible[0]);
    CHECK_EQ(core.snapshot().area_visible_ms, 5000u);
}

GUARDIAN_CASE(area_storage_is_bounded_same_family_replaces_oldest_is_evicted) {
    Clock clock; Core core(clock, profiles::all_2g4_channels());
    clock.at = 100000;
    const DetectorFamily f[] = {DetectorFamily::Probe, DetectorFamily::Beacon, DetectorFamily::Auth, DetectorFamily::ChannelSwitch, DetectorFamily::Identity};
    for (int i = 0; i < 4; ++i) core.incident(area_obs(clock, 99000 + static_cast<Millis>(i), f[i], 10u + static_cast<std::uint32_t>(i)));
    auto s = core.snapshot();
    std::size_t shown = 0; for (bool v : s.area_visible) shown += v;
    CHECK_EQ(shown, area_slots);
    CHECK_EQ(s.area_evicted, 0u);
    core.incident(area_obs(clock, 99500, DetectorFamily::Probe, 99));   // same family: replaces, nothing evicted
    s = core.snapshot();
    CHECK_EQ(s.area_evicted, 0u);
    std::size_t probes = 0; for (std::size_t i = 0; i < area_slots; ++i) if (s.area_visible[i] && s.area[i].family == DetectorFamily::Probe) { ++probes; CHECK_EQ(s.area[i].count, 99u); }
    CHECK_EQ(probes, 1u);
    core.incident(area_obs(clock, 99600, f[4]));                        // fifth family: the oldest (Beacon @99001) goes
    s = core.snapshot();
    CHECK_EQ(s.area_evicted, 1u);
    bool beacon = false, identity = false;
    for (std::size_t i = 0; i < area_slots; ++i) { beacon |= s.area_visible[i] && s.area[i].family == DetectorFamily::Beacon; identity |= s.area_visible[i] && s.area[i].family == DetectorFamily::Identity; }
    CHECK(!beacon); CHECK(identity);
    core.incident(area_obs(clock, 99200, DetectorFamily::Probe, 5));    // older than the held Probe reading
    CHECK_EQ(core.snapshot().rejected.older, 1u);
    // An expired observation's slot is reused without counting an eviction.
    clock.at = 99600 + Core::area_incident_ms + 1;
    core.incident(area_obs(clock, clock.at, DetectorFamily::Beacon));
    CHECK_EQ(core.snapshot().area_evicted, 1u);
}

GUARDIAN_CASE(area_incidents_keep_origin_and_epoch_rules_and_survive_reselection) {
    Clock clock; Core core(clock, profiles::all_2g4_channels());
    clock.at = 5000;
    auto demo = area_obs(clock, 4000, DetectorFamily::Probe); demo.origin = Origin::Demo;
    core.incident(demo);
    CHECK_EQ(core.snapshot().rejected.origin, 1u);
    auto foreign = area_obs(clock, 4000, DetectorFamily::Probe); foreign.acquired.epoch.boot_id = 9;
    core.incident(foreign);
    CHECK_EQ(core.snapshot().rejected.foreign_epoch, 1u);
    auto future = area_obs(clock, 6000, DetectorFamily::Probe);
    core.incident(future);
    CHECK_EQ(core.snapshot().rejected.future, 1u);
    core.incident(area_obs(clock, 4000, DetectorFamily::Probe));
    CHECK(core.snapshot().area_visible[0]);
    CHECK(core.select(home()));                                        // about the air, not the network
    CHECK(core.snapshot().area_visible[0]);
}

// ---- detector reports ---------------------------------------------------------------------
GUARDIAN_CASE(disconnect_detector_reports_frames_events_window_incident_and_cooldown) {
    Clock clock; ApprovedScope scope; ApprovedAp ap{}; ap.network = home(); CHECK(scope.select(ap));
    DetectorLimits plain{}; plain.shape_frames = 0; plain.shape_run = 0;   // G16J: the unshaped rule (shapes: coverage_check.cpp)
    DisconnectDetector d(scope, plain);
    NullSink sink; SecurityFrameParser parser;
    std::vector<std::uint8_t> b; if (!fixture(c_, "deauth_reason7", b)) return;
    set_bssid_and_transmitter(b, kHome);
    for (std::uint16_t i = 0; i < 20; ++i) {
        set_sequence(b, static_cast<std::uint16_t>(i + 1));
        RxMeta m{}; m.status = RxStatus::Ok; m.origin = Origin::LiveRadio; m.channel = 6; m.acquired = at(clock, 1000 + 100u * i);
        const FrameSpan span{b.data(), static_cast<std::uint16_t>(b.size()), false};
        AllocationBan ban; d.on_frame(span, m, parser.parse(span, m), sink);
    }
    CHECK_EQ(sink.incidents, 1u);
    auto r = d.report(at(clock, 3000));
    CHECK_EQ(std::string(r.name), std::string("disconnect"));
    CHECK_EQ(r.family, DetectorFamily::Disconnect);
    CHECK_EQ(r.scope, IncidentScope::Network);
    CHECK(r.configured);
    CHECK_EQ(r.frames_seen, 20u);
    CHECK_EQ(r.events_total, 20u);
    CHECK_EQ(r.events_in_window, 20u);
    CHECK_EQ(r.window_ms, 10000u);
    CHECK_EQ(r.incidents, 1u);
    CHECK(r.last_event_known); CHECK_EQ(r.last_event_age_ms, 100u);   // newest counted event at 2900
    CHECK(r.last_incident_known); CHECK_EQ(r.last_incident_age_ms, 100u);
    CHECK_EQ(r.cooldown_remaining_ms, 45000u - 100u);
    r = d.report(at(clock, 13000));
    CHECK_EQ(r.events_in_window, 0u);
    CHECK_EQ(r.cooldown_remaining_ms, 45000u - 10100u);
    r = d.report(at(clock, 60000));
    CHECK_EQ(r.cooldown_remaining_ms, 0u);
    CHECK_EQ(r.events_total, 20u);
    // Another timebase: no age is invented.
    Instant foreign = at(clock, 3000); foreign.epoch.boot_id = 7;
    r = d.report(foreign);
    CHECK(!r.last_event_known); CHECK(!r.last_incident_known); CHECK_EQ(r.events_in_window, 0u);
}

GUARDIAN_CASE(baseline_detector_reports_and_incidents_carry_scope_and_family) {
    Clock clock; ApprovedScope scope; ApprovedAp ap{}; ap.network = home(); ap.watch_impostors = true; CHECK(scope.select(ap));
    BaselineDetector d(scope, DetectorLimits{});
    struct Sink final : ObservationSink {
        void security(const SecurityObservation&) override {}
        void incident(const IncidentObservation& o) override { last = o; ++n; }
        IncidentObservation last{}; int n{};
    } sink;
    SecurityFrameParser parser;
    std::vector<std::uint8_t> b; if (!fixture(c_, "beacon_same_ssid_other_bssid_wpa2", b)) return;
    for (int i = 0; i < 2; ++i) {
        RxMeta m{}; m.status = RxStatus::Ok; m.origin = Origin::LiveRadio; m.channel = 6; m.acquired = at(clock, 1000 + 100u * static_cast<Millis>(i));
        const FrameSpan span{b.data(), static_cast<std::uint16_t>(b.size()), false};
        d.on_frame(span, m, parser.parse(span, m), sink);
    }
    CHECK_EQ(sink.n, 1);
    CHECK_EQ(sink.last.kind, IncidentKind::UnexpectedAp);
    CHECK_EQ(sink.last.scope, IncidentScope::Network);
    CHECK_EQ(sink.last.family, DetectorFamily::Baseline);
    const auto r = d.report(at(clock, 1100));
    CHECK_EQ(std::string(r.name), std::string("baseline"));
    CHECK_EQ(r.family, DetectorFamily::Baseline);
    CHECK_EQ(r.frames_seen, 2u);
    CHECK_EQ(r.events_total, 2u);
    CHECK_EQ(r.events_in_window, 2u);
    CHECK_EQ(r.incidents, 1u);
    CHECK_EQ(r.cooldown_remaining_ms, 45000u);
}

GUARDIAN_CASE(detectors_reconfigure_from_tunable_limits_and_refuse_bad_ones) {
    ApprovedScope scope; DisconnectDetector d(scope, DetectorLimits{}); BaselineDetector b(scope, DetectorLimits{});
    DetectorLimits l{}; l.burst_threshold = 5; l.window_ms = 2000; l.cooldown_ms = 9000; l.change_threshold = 3;
    CHECK(d.configure(l)); CHECK(b.configure(l));
    CHECK_EQ(d.limits().burst_threshold, 5u); CHECK_EQ(b.limits().change_threshold, 3u);
    DetectorLimits bad = l; bad.burst_threshold = 0;
    CHECK(!d.configure(bad));
    CHECK(!d.configured());
    CHECK(!d.report(Instant{}).configured);
    CHECK(d.configure(l)); CHECK(d.configured());
}

// ---- registry --------------------------------------------------------------------------------
GUARDIAN_CASE(registry_is_bounded_and_refuses_duplicates) {
    DetectorRegistry r;
    std::vector<FakeAreaDetector> fakes(DetectorRegistry::capacity + 1);
    for (std::size_t i = 0; i < DetectorRegistry::capacity; ++i) CHECK(r.add(fakes[i]));
    CHECK_EQ(r.size(), DetectorRegistry::capacity);
    CHECK(!r.add(fakes[DetectorRegistry::capacity]));
    CHECK_EQ(r.refused(), 1u);
    DetectorRegistry two; CHECK(two.add(fakes[0])); CHECK(!two.add(fakes[0]));
    CHECK_EQ(two.size(), 1u);
    CHECK(two.at(0) == &fakes[0]); CHECK(two.at(1) == nullptr);
}

GUARDIAN_CASE(registry_forwards_every_call_without_allocating) {
    Clock clock; DetectorRegistry r; FakeAreaDetector a(1), b(100); NullSink sink;
    CHECK(r.add(a)); CHECK(r.add(b));
    std::vector<std::uint8_t> bytes(30, 0); RxMeta m{}; m.acquired = at(clock, 100);
    const FrameSpan span{bytes.data(), 30, false}; const ParseResult p{};
    {
        AllocationBan ban;
        r.on_frame(span, m, p, sink); r.on_tick(at(clock, 200), sink); r.coverage(CoverageReport{}); r.reset();
    }
    CHECK_EQ(g_banned_allocations, 0u);
    CHECK_EQ(a.frames, 1u); CHECK_EQ(b.frames, 1u);
    CHECK_EQ(a.ticks, 1u); CHECK_EQ(b.coverages, 1u); CHECK_EQ(a.resets, 1u);
    CHECK_EQ(sink.incidents, 1u);
    std::array<DetectorReport, 4> out{};
    CHECK_EQ(r.reports(at(clock, 300), out.data(), out.size()), 2u);
    CHECK_EQ(std::string(out[0].name), std::string("fake"));
    CHECK_EQ(r.reports(at(clock, 300), out.data(), 1), 1u);   // bounded by the caller's capacity
}

// ---- air meter ---------------------------------------------------------------------------------
GUARDIAN_CASE(air_meter_counts_probes_beacons_and_distinct_transmitters_per_minute) {
    Clock clock; AirMeter air; SecurityFrameParser parser;
    std::vector<std::uint8_t> probe, beacon; if (!fixture(c_, "probereq_wildcard_random", probe) || !fixture(c_, "beacon_wpa3_sae_pmf_required", beacon)) return;
    const auto feed = [&](std::vector<std::uint8_t>& b, Millis t, RxStatus st = RxStatus::Ok) {
        RxMeta m{}; m.status = st; m.origin = Origin::LiveRadio; m.channel = 6; m.acquired = at(clock, t);
        const FrameSpan span{b.data(), static_cast<std::uint16_t>(b.size()), false};
        AllocationBan ban; air.on_frame(parser.parse(span, m), m);
    };
    CHECK(!air.rates(at(clock, 0)).known);
    for (int i = 0; i < 10; ++i) { probe[15] = static_cast<std::uint8_t>(i); feed(probe, 1000 + 100u * static_cast<Millis>(i)); }
    for (int i = 0; i < 5; ++i) feed(beacon, 1000 + 1000u * static_cast<Millis>(i));
    feed(beacon, 5500, RxStatus::DriverError);                       // unverified bytes are not counted
    auto r = air.rates(at(clock, 6000));
    CHECK(r.known);
    CHECK_EQ(r.probes, 10u);
    CHECK_EQ(r.beacons, 5u);
    CHECK_EQ(r.transmitters, 11u);                                  // 10 probe sources + the AP
    CHECK(!r.transmitters_saturated);
    CHECK_EQ(r.window_ms, 5000u);                                    // listened since the first frame, not a full minute yet
    r = air.rates(at(clock, 1000 + AirMeter::window_ms + 1000));     // the probes at 1.0-1.9 s are now older than 60 s
    CHECK_EQ(r.probes, 0u);
    CHECK_EQ(r.beacons, 3u);                                         // 60 one-second buckets ending at now: 3, 4, 5 s
    CHECK_EQ(r.window_ms, AirMeter::window_ms);
    Instant foreign = at(clock, 6000); foreign.epoch.boot_id = 3;
    CHECK(!air.rates(foreign).known);
    CHECK_EQ(g_banned_allocations, 0u);
}

GUARDIAN_CASE(air_meter_transmitter_table_is_bounded_and_flags_saturation) {
    Clock clock; AirMeter air; SecurityFrameParser parser;
    std::vector<std::uint8_t> probe; if (!fixture(c_, "probereq_wildcard_random", probe)) return;
    for (std::size_t i = 0; i < AirMeter::max_transmitters + 40; ++i) {
        probe[14] = static_cast<std::uint8_t>(i >> 8); probe[15] = static_cast<std::uint8_t>(i);
        RxMeta m{}; m.status = RxStatus::Ok; m.origin = Origin::LiveRadio; m.channel = 6; m.acquired = at(clock, 1000);
        const FrameSpan span{probe.data(), static_cast<std::uint16_t>(probe.size()), false};
        air.on_frame(parser.parse(span, m), m);
    }
    const auto r = air.rates(at(clock, 2000));
    CHECK_EQ(r.transmitters, AirMeter::max_transmitters);
    CHECK(r.transmitters_saturated);
    CHECK_EQ(r.probes, AirMeter::max_transmitters + 40);
}

// ---- Monitor: registry, area path, STATUS, JSON, limits -----------------------------------------
GUARDIAN_CASE(monitor_drives_registered_detectors_and_area_incidents_reach_the_snapshot) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    CHECK(m.select(home()));
    CHECK_EQ(m.detectors().size(), 2u + ThreatDetectors::count);   // G16F: the passive pattern detectors follow the two G06 ones
    FakeAreaDetector fake(2); CHECK(m.detectors().add(fake));
    std::vector<std::uint8_t> b; if (!fixture(c_, "beacon_wpa3_sae_pmf_required", b)) return;
    clock.at = 1000; m.receive(packet(clock, b));
    clock.at = 1100; m.receive(packet(clock, b));
    CHECK_EQ(fake.frames, 2u);
    const auto s = m.snapshot();
    CHECK_EQ(fake.ticks, 1u);
    CHECK_EQ(s.settings.mood, Mood::VeryGood);
    CHECK(s.area_visible[0]);
    const auto v = m.view(s);
    CHECK(!v.alert);
    CHECK_EQ(v.face, Mood::VeryGood);
}

GUARDIAN_CASE(monitor_status_and_json_report_every_detector_and_the_air) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    CHECK(m.select(home()));
    std::vector<std::uint8_t> b, probe; if (!fixture(c_, "beacon_wpa3_sae_pmf_required", b) || !fixture(c_, "probereq_wildcard_random", probe)) return;
    clock.at = 1000; m.receive(packet(clock, b)); m.receive(packet(clock, probe));
    char status[2048]{};   // G16F: 14 detectors (the board's STATUS fragment buffer is 2048 too)
    const auto n = m.status_text(status, sizeof status);
    CHECK(n > 0);
    const std::string st(status);
    CHECK(st.find("detectors=disconnect:frames=2,in_window=0,events=0,incidents=0,last=none,cooldown=0") != std::string::npos);
    CHECK(st.find(";baseline:frames=2,") != std::string::npos);
    CHECK(st.find(" air=probes:1,beacons:1,tx:2,window_s:0") != std::string::npos);
    CHECK(st.find(" area_visible=0") != std::string::npos);
    char json[8192]{};     // G16F: 14 detector records (the board's state_line is 8192 too)
    CHECK(m.json(json, sizeof json, 0, true, false) > 0);
    const std::string js(json);
    CHECK(js.find("\"detectors\":[{\"name\":\"disconnect\",\"family\":\"disconnect\",\"scope\":\"network\",\"frames\":2,") != std::string::npos);
    CHECK(js.find("{\"name\":\"baseline\",\"family\":\"baseline\"") != std::string::npos);
    CHECK(js.find("\"air\":{\"known\":true,\"probes\":1,\"beacons\":1,\"transmitters\":2,\"saturated\":false,\"window_ms\":0}") != std::string::npos);
    CHECK(js.find("\"area\":[]") != std::string::npos);
    CHECK(js.back() == '}');
    // Too small a buffer is refused, never cut.
    char tiny[16]; CHECK_EQ(m.status_text(tiny, sizeof tiny), 0u);
}

GUARDIAN_CASE(monitor_limits_are_tunable_validated_and_unchanged_limits_keep_windows) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    CHECK(m.select(home()));
    std::vector<std::uint8_t> d; if (!fixture(c_, "deauth_reason7", d)) return;
    set_bssid_and_transmitter(d, kHome);
    for (std::uint16_t i = 0; i < 3; ++i) { set_sequence(d, static_cast<std::uint16_t>(i + 1)); clock.at = 1000 + i; m.receive(packet(clock, d)); }
    std::array<DetectorReport, 4> out{};
    m.detectors().reports(at(clock, clock.at), out.data(), out.size());
    CHECK_EQ(out[0].events_in_window, 3u);
    CHECK(m.set_limits(DetectorLimits{}));                            // same values: nothing reset
    m.detectors().reports(at(clock, clock.at), out.data(), out.size());
    CHECK_EQ(out[0].events_in_window, 3u);
    DetectorLimits l{}; l.burst_threshold = 4;
    CHECK(m.set_limits(l));
    CHECK_EQ(m.limits().burst_threshold, 4u);
    m.detectors().reports(at(clock, clock.at), out.data(), out.size());
    CHECK_EQ(out[0].events_in_window, 0u);                           // new limits start a new window
    DetectorLimits bad = l; bad.window_ms = 0;
    CHECK(!m.set_limits(bad));
    CHECK_EQ(m.limits().burst_threshold, 4u);                        // refused: the previous limits stay
    CHECK(!m.set_area_visibility(0));
    CHECK(m.set_area_visibility(30000));
    CHECK_EQ(m.snapshot().area_visible_ms, 30000u);
}

GUARDIAN_CASE(monitor_radar_lists_registered_families_and_pulses_only_on_counted_events) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    CHECK(m.select(home()));
    clock.at = 500;
    auto r = m.radar();
    CHECK(r.known);
    CHECK(r.families[static_cast<std::size_t>(DetectorFamily::Disconnect)].registered);
    CHECK(r.families[static_cast<std::size_t>(DetectorFamily::Baseline)].registered);
    CHECK(r.families[static_cast<std::size_t>(DetectorFamily::Probe)].registered);   // G16F registered the probe detector
    CHECK(!r.families[static_cast<std::size_t>(DetectorFamily::Probe)].pulse);       // ... and nothing was counted yet
    CHECK(!r.families[static_cast<std::size_t>(DetectorFamily::Disconnect)].pulse);
    std::vector<std::uint8_t> d; if (!fixture(c_, "deauth_reason7", d)) return;
    set_bssid_and_transmitter(d, kHome);
    clock.at = 1000; m.receive(packet(clock, d));
    clock.at = 1000 + Radar::pulse_ms - 1;
    r = m.radar();
    CHECK(r.families[static_cast<std::size_t>(DetectorFamily::Disconnect)].pulse);
    CHECK_EQ(r.families[static_cast<std::size_t>(DetectorFamily::Disconnect)].events, 1u);
    clock.at = 1000 + Radar::pulse_ms;
    CHECK(!m.radar().families[static_cast<std::size_t>(DetectorFamily::Disconnect)].pulse);
    FakeAreaDetector fake(1); CHECK(m.detectors().add(fake));
    clock.at = 3000; m.receive(packet(clock, d));
    r = m.radar();
    CHECK(r.families[static_cast<std::size_t>(DetectorFamily::Probe)].registered);
    CHECK(r.families[static_cast<std::size_t>(DetectorFamily::Probe)].active);      // its Area observation is visible
    CHECK_EQ(r.families[static_cast<std::size_t>(DetectorFamily::Probe)].scope, IncidentScope::Area);
}

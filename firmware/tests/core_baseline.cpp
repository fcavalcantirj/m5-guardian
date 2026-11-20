// BASELINE of the draft Core (G03), migrated to the G05 Core API.
//
// core.cpp predated the TDD rule; G03 recorded how it behaved. G05 replaced the
// time model (injected MonotonicClock, epoch-qualified acquisition Instants,
// capability-driven channels, CoverageReport input), so the G03 cases that still
// describe intended behavior were ported to the new API and kept here as
// regression checks. The former KNOWN_LIMIT_* cases (hardcoded 1-14 channels,
// future-timestamp poisoning, unenforced acquisition Instant) were turned into
// their intended behavior in tests/core_check.cpp (red first, then green). The
// former assess_* table cases moved to tests/rating_check.cpp, where they are
// written against AdvertisedSettings instead of the removed mode/cipher summary
// fields. Not TDD for the ported cases: they document, they do not endorse.
#include "check.hpp"

#include "guardian/core.hpp"

using namespace guardian;

namespace {

TimeEpoch test_epoch() {
    TimeEpoch e{};
    e.source_id[0] = 1;
    e.boot_id = 1;
    return e;
}

class FakeClock final : public MonotonicClock {
public:
    Millis now() const override { return now_; }
    TimeEpoch epoch() const override { return epoch_; }
    void set(Millis t) { now_ = t; }
private:
    Millis now_{0};
    TimeEpoch epoch_{test_epoch()};
};

Network home(std::uint8_t last = 0x55) {
    Network n{};
    n.bssid = {0x02, 0x11, 0x22, 0x33, 0x44, last};
    const char* s = "home";
    for (std::uint8_t i = 0; i < 4; ++i) n.ssid[i] = static_cast<std::uint8_t>(s[i]);
    n.ssid_size = 4;
    return n;
}

// A complete WPA3-SAE/CCMP/PMF-required reading (VeryGood when fresh).
SecurityObservation wpa3(const Network& n, Millis at, Origin origin = Origin::LiveRadio) {
    SecurityObservation s{};
    s.network = n;
    s.ssid_kind = SsidKind::Present;
    s.acquired = Instant{test_epoch(), at, true};
    s.origin = origin;
    s.channel = 6;
    s.rssi = -50;
    s.rssi_valid = true;
    s.rx_status = RxStatus::Ok;
    s.kind = FrameKind::Beacon;
    s.parse = Parse::Complete;
    s.settings_present = true;
    s.settings_complete = true;
    s.settings.privacy_valid = true;
    s.settings.privacy_bit = true;
    s.settings.rsn.state = ElementState::Valid;
    s.settings.rsn.akms = SuiteList{{0x000fac08}, 1, akm::Sae};
    s.settings.rsn.pairwise = SuiteList{{0x000fac04}, 1, cipher::Ccmp128};
    s.settings.rsn.group = SuiteSelector{0x000fac04, cipher::Ccmp128, true};
    s.settings.rsn.group_management = SuiteSelector{0x000fac06, cipher::BipCmac128, false};
    s.settings.rsn.pmf = Pmf::Required;
    return s;
}

SecurityObservation open(const Network& n, Millis at) {
    SecurityObservation s = wpa3(n, at);
    s.settings = AdvertisedSettings{};
    s.settings.privacy_valid = true;
    s.settings.privacy_bit = false;
    return s;
}

IncidentObservation burst(const Network& n, Millis at, IncidentKind kind = IncidentKind::DisconnectBurst,
                          Origin origin = Origin::LiveRadio) {
    IncidentObservation i{};
    i.affected = n;
    i.acquired = Instant{test_epoch(), at, true};
    i.origin = origin;
    i.kind = kind;
    i.count = 25;
    i.window_ms = 10000;
    return i;
}

struct Rig {
    FakeClock clock{};
    Core core{clock, profiles::all_2g4_channels(), Origin::LiveRadio};
};

} // namespace

// ---- Core::select ------------------------------------------------------------------
GUARDIAN_CASE(select_rejects_multicast_zero_and_oversized_identities) {
    Rig r;
    Network n = home();
    n.bssid[0] = 0x03; // group bit set
    CHECK(!r.core.select(n));
    n = home();
    n.bssid = {0, 0, 0, 0, 0, 0};
    CHECK(!r.core.select(n));
    n = home();
    n.ssid_size = 33;
    CHECK(!r.core.select(n));
    CHECK(r.core.select(home()));
    CHECK(r.core.snapshot().selected == home());
}

GUARDIAN_CASE(select_clears_previous_security_and_incident_state) {
    Rig r;
    CHECK(r.core.select(home()));
    r.clock.set(1000);
    r.core.security(wpa3(home(), 1000));
    r.core.incident(burst(home(), 1000));
    r.clock.set(2000);
    Snapshot before = r.core.snapshot();
    CHECK(before.has_security);
    CHECK(before.incidents[0]);
    CHECK(r.core.select(home(0x56)));
    Snapshot after = r.core.snapshot();
    CHECK(!after.has_security);
    CHECK_EQ(after.coverage, Coverage::Checking);
    CHECK(!after.incidents[0]);
}

// ---- Core::security scoping and freshness ------------------------------------------
GUARDIAN_CASE(security_ignored_before_selection) {
    Rig r;
    r.clock.set(1000);
    r.core.security(wpa3(home(), 1000));
    CHECK(!r.core.snapshot().has_security);
}

GUARDIAN_CASE(security_ignored_for_wrong_bssid_even_with_same_ssid) {
    Rig r;
    r.core.select(home());
    r.clock.set(1000);
    r.core.security(wpa3(home(0x56), 1000)); // same SSID "home", other AP
    CHECK(!r.core.snapshot().has_security);
}

GUARDIAN_CASE(security_ignored_when_origin_differs_from_core_origin) {
    FakeClock clock;
    clock.set(1000);
    Core live(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    live.select(home());
    live.security(wpa3(home(), 1000, Origin::Demo));
    live.security(wpa3(home(), 1000, Origin::Imported));
    CHECK(!live.snapshot().has_security);
    Core demo(clock, profiles::all_2g4_channels(), Origin::Demo);
    demo.select(home());
    demo.security(wpa3(home(), 1000, Origin::LiveRadio));
    CHECK(!demo.snapshot().has_security);
    demo.security(wpa3(home(), 1000, Origin::Demo));
    CHECK(demo.snapshot().has_security);
    CHECK_EQ(demo.snapshot().origin, Origin::Demo);
}

GUARDIAN_CASE(security_fresh_under_30s_then_stale_and_ungraded) {
    Rig r;
    r.core.select(home());
    r.clock.set(1000);
    r.core.security(wpa3(home(), 1000));
    r.clock.set(1000 + Core::fresh_ms - 1);
    Snapshot fresh = r.core.snapshot();
    CHECK_EQ(fresh.coverage, Coverage::Fresh);
    CHECK_EQ(fresh.settings.mood, Mood::VeryGood);
    CHECK_EQ(fresh.age_ms, Core::fresh_ms - 1);
    r.clock.set(1000 + Core::fresh_ms);
    Snapshot stale = r.core.snapshot();
    CHECK_EQ(stale.coverage, Coverage::Stale);
    CHECK_EQ(stale.settings.mood, Mood::Unknown); // stale evidence never shows a happy grade
    CHECK(stale.has_security);                     // but the historical record is still there
    CHECK_EQ(stale.age_ms, Core::fresh_ms);
}

GUARDIAN_CASE(security_older_sample_does_not_replace_newer) {
    Rig r;
    r.core.select(home());
    r.clock.set(5000);
    r.core.security(wpa3(home(), 5000));
    r.core.security(open(home(), 4000));
    CHECK_EQ(r.core.snapshot().settings.mood, Mood::VeryGood);
    CHECK_EQ(r.core.snapshot().last_security.acquired.at, Millis{5000});
}

GUARDIAN_CASE(security_newer_malformed_sample_invalidates_prior_grade) {
    Rig r;
    r.core.select(home());
    r.clock.set(1000);
    r.core.security(wpa3(home(), 1000));
    r.clock.set(2000);
    SecurityObservation bad = wpa3(home(), 2000);
    bad.parse = Parse::Malformed;
    bad.settings_complete = false;
    r.core.security(bad);
    Snapshot s = r.core.snapshot();
    CHECK_EQ(s.coverage, Coverage::Fresh);
    CHECK_EQ(s.settings.mood, Mood::Unknown); // fresh but ungraded, never the old VeryGood
}

// ---- incidents ------------------------------------------------------------------------
GUARDIAN_CASE(incident_scoped_to_selected_network_and_origin) {
    Rig r;
    r.core.select(home());
    r.clock.set(1000);
    r.core.incident(burst(home(0x56), 1000));              // other AP
    r.core.incident(burst(home(), 1000, IncidentKind::DisconnectBurst, Origin::Demo)); // other origin
    CHECK(!r.core.snapshot().incidents[0]);
    r.core.incident(burst(home(), 1000));
    Snapshot s = r.core.snapshot();
    CHECK(s.incidents[0]);
    CHECK_EQ(s.evidence[0].count, 25u);
    CHECK_EQ(s.evidence[0].window_ms, 10000u);
}

GUARDIAN_CASE(incident_visible_for_60s_then_expires) {
    Rig r;
    r.core.select(home());
    r.clock.set(1000);
    r.core.incident(burst(home(), 1000));
    r.clock.set(1000 + Core::incident_ms - 1);
    CHECK(r.core.snapshot().incidents[0]);
    r.clock.set(1000 + Core::incident_ms);
    CHECK(!r.core.snapshot().incidents[0]);
}

GUARDIAN_CASE(incident_kinds_are_independent_and_out_of_range_kind_is_ignored) {
    Rig r;
    r.core.select(home());
    r.clock.set(1000);
    r.core.incident(burst(home(), 1000, IncidentKind::SettingsChanged));
    Snapshot s = r.core.snapshot();
    CHECK(!s.incidents[static_cast<std::size_t>(IncidentKind::DisconnectBurst)]);
    CHECK(!s.incidents[static_cast<std::size_t>(IncidentKind::UnexpectedAp)]);
    CHECK(s.incidents[static_cast<std::size_t>(IncidentKind::SettingsChanged)]);
    r.core.incident(burst(home(), 1000, IncidentKind::Count)); // invalid kind: no write
    s = r.core.snapshot();
    for (std::size_t k = 0; k < s.incidents.size(); ++k)
        CHECK_EQ(s.incidents[k], k == static_cast<std::size_t>(IncidentKind::SettingsChanged));
}

GUARDIAN_CASE(incident_older_report_does_not_replace_newer) {
    Rig r;
    r.core.select(home());
    r.clock.set(5000);
    r.core.incident(burst(home(), 5000));
    IncidentObservation older = burst(home(), 4000);
    older.count = 99;
    r.core.incident(older);
    CHECK_EQ(r.core.snapshot().evidence[0].count, 25u);
}

// G05 Core evidence-freshness and isolation checks (TDD: written and run RED
// against the mechanically ported pre-G05 Core first; see
// docs/G05-rating-freshness.md for the recorded run).
//
// Every reading here is Origin::Imported or hand-built; the clock is a fake.
// Nothing is radio proof. The cases are the ledger's isolation list: wrong
// BSSID, same SSID on another AP, binary/hidden SSIDs, delayed/future samples,
// reboot/timebase changes, expired evidence, malformed newer samples, queue
// drops, origin separation, and raw RSSI/activity that must not renew security.
#include "check.hpp"
#include "fixtures.hpp"

#include "guardian/rating.hpp"
#include "guardian/security_parser.hpp"

#include <string>

using namespace guardian;
using guardian::fixtures::Fixture;

namespace {

const SecurityFrameParser parser{};

TimeEpoch epoch_of(std::uint8_t source, std::uint64_t boot) {
    TimeEpoch e{};
    e.source_id[0] = source;
    e.boot_id = boot;
    return e;
}

class FakeClock final : public MonotonicClock {
public:
    explicit FakeClock(Millis start = 1000, TimeEpoch epoch = epoch_of(1, 1)) : now_(start), epoch_(epoch) {}
    Millis now() const override { return now_; }
    TimeEpoch epoch() const override { return epoch_; }
    void set(Millis t) { now_ = t; }
    void advance(Millis ms) { now_ += ms; }
    void reboot() { ++epoch_.boot_id; now_ = 0; } // new timebase: old Millis are not comparable
private:
    Millis now_;
    TimeEpoch epoch_;
};

Network home(std::uint8_t last = 0x55) {
    Network n{};
    n.bssid = {0x02, 0x11, 0x22, 0x33, 0x44, last};
    const char* s = "home";
    for (std::uint8_t i = 0; i < 4; ++i) n.ssid[i] = static_cast<std::uint8_t>(s[i]);
    n.ssid_size = 4;
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

// Real parser over a fixture, reduced to the reading Core takes.
bool reading(check::Case& c_, const char* name, const RxMeta& m, SecurityObservation& out) {
    Fixture f;
    std::string err;
    if (!fixtures::load(name, f, err)) { CHECK_FAIL(err); return false; }
    out = observe_security(parser.parse(FrameSpan{f.bytes.data(), static_cast<std::uint16_t>(f.bytes.size()), false}, m), m);
    return true;
}
bool signal_reading(check::Case& c_, const char* name, const RxMeta& m, SignalObservation& out) {
    Fixture f;
    std::string err;
    if (!fixtures::load(name, f, err)) { CHECK_FAIL(err); return false; }
    out = observe_signal(parser.parse(FrameSpan{f.bytes.data(), static_cast<std::uint16_t>(f.bytes.size()), false}, m), m);
    return true;
}
// Shorthand: the WPA3 fixture (VeryGood when fresh) acquired at `at` in the clock's epoch.
bool wpa3(check::Case& c_, const FakeClock& clock, Millis at, SecurityObservation& out, Origin origin = Origin::Imported) {
    return reading(c_, "beacon_wpa3_sae_pmf_required", meta_at(clock, at, origin), out);
}

CoverageReport listening(const FakeClock& clock, Millis at, std::uint8_t channel = 6, std::uint32_t drops = 0) {
    CoverageReport c{};
    c.sampled_at = Instant{clock.epoch(), at, true};
    c.band = Band::Ghz2_4;
    c.channel = channel;
    c.window_ms = 10000;
    c.listened_ms = 10000;
    c.dropped_in_window = drops;
    c.passive_receive = Support::Unsupported; // replay: no physical radio
    return c;
}

struct Rig {
    FakeClock clock{};
    Core core{clock, profiles::all_2g4_channels(), Origin::Imported};
    Rig() { core.select(home()); }
};

} // namespace

// ---- startup, freshness and expiry -------------------------------------------------------
GUARDIAN_CASE(startup_shows_checking_then_no_fresh_data_after_30s_without_a_sample) {
    Rig r;
    CHECK_EQ(r.core.snapshot().coverage, Coverage::Checking);
    r.clock.advance(Core::fresh_ms - 1);
    CHECK_EQ(r.core.snapshot().coverage, Coverage::Checking);
    r.clock.advance(1);
    Snapshot s = r.core.snapshot();
    CHECK_EQ(s.coverage, Coverage::Stale); // "No fresh data"
    CHECK(!s.has_security);
    CHECK_EQ(s.settings.mood, Mood::Unknown);
}

GUARDIAN_CASE(nothing_selected_stays_checking_and_counts_the_input) {
    FakeClock clock;
    Core core(clock, profiles::all_2g4_channels(), Origin::Imported);
    SecurityObservation s;
    if (!wpa3(c_, clock, 1000, s)) return;
    core.security(s);
    clock.advance(60000);
    const Snapshot snap = core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Checking);
    CHECK(!snap.has_security);
    CHECK_EQ(snap.rejected.not_selected, 1u);
}

GUARDIAN_CASE(live_sample_is_fresh_and_graded_under_30s_then_stale_and_ungraded) {
    Rig r;
    SecurityObservation s;
    if (!wpa3(c_, r.clock, 1000, s)) return;
    r.core.security(s);
    r.clock.set(1000 + Core::fresh_ms - 1);
    Snapshot fresh = r.core.snapshot();
    CHECK_EQ(fresh.coverage, Coverage::Fresh);
    CHECK_EQ(fresh.settings.mood, Mood::VeryGood);
    CHECK_EQ(fresh.settings.unrated, Unrated::None);
    CHECK_EQ(fresh.age_ms, Core::fresh_ms - 1);
    CHECK(!fresh.security_historical);
    r.clock.advance(1);
    Snapshot stale = r.core.snapshot();
    CHECK_EQ(stale.coverage, Coverage::Stale);
    CHECK_EQ(stale.settings.mood, Mood::Unknown); // never a stale happy rating
    CHECK(stale.has_security);                     // the record itself stays readable
    CHECK_EQ(stale.age_ms, Core::fresh_ms);
    CHECK_EQ(stale.last_security.channel, 6);
    CHECK_EQ(stale.last_security.origin, Origin::Imported);
}

GUARDIAN_CASE(delayed_sample_counts_from_acquisition_not_from_arrival) {
    // Acquired at 1 s, drained at 40 s: it is 39 s old on arrival (docs/contracts.md section 4).
    Rig r;
    r.clock.set(40000);
    SecurityObservation s;
    if (!wpa3(c_, r.clock, 1000, s)) return;
    r.core.security(s);
    Snapshot snap = r.core.snapshot();
    CHECK(snap.has_security);
    CHECK_EQ(snap.age_ms, Millis{39000});
    CHECK_EQ(snap.coverage, Coverage::Stale);
    CHECK_EQ(snap.settings.mood, Mood::Unknown);
    CHECK_EQ(snap.rejected.older, 0u);
}

GUARDIAN_CASE(older_sample_arriving_after_a_newer_one_is_rejected) {
    Rig r;
    SecurityObservation newer, older;
    if (!wpa3(c_, r.clock, 5000, newer)) return;
    if (!reading(c_, "beacon_open", meta_at(r.clock, 4000), older)) return;
    r.clock.set(5000);
    r.core.security(newer);
    r.core.security(older);
    Snapshot s = r.core.snapshot();
    CHECK_EQ(s.settings.mood, Mood::VeryGood);
    CHECK_EQ(s.last_security.acquired.at, Millis{5000});
    CHECK_EQ(s.rejected.older, 1u);
    // An equal timestamp replaces (two frames in the same millisecond: the later drained one wins).
    SecurityObservation same;
    if (!reading(c_, "beacon_wpa2_ccmp_pmf_optional", meta_at(r.clock, 5000), same)) return;
    r.core.security(same);
    CHECK_EQ(r.core.snapshot().settings.mood, Mood::Medium);
}

GUARDIAN_CASE(newer_malformed_or_truncated_sample_removes_the_grade_but_is_not_stale) {
    Rig r;
    SecurityObservation good, bad;
    if (!wpa3(c_, r.clock, 1000, good)) return;
    r.core.security(good);
    r.clock.set(2000);
    if (!reading(c_, "beacon_rsn_pmf_inconsistent", meta_at(r.clock, 2000), bad)) return;
    r.core.security(bad);
    Snapshot s = r.core.snapshot();
    CHECK_EQ(s.coverage, Coverage::Fresh);
    CHECK_EQ(s.settings.mood, Mood::Unknown);
    CHECK_EQ(s.settings.unrated, Unrated::Incomplete);
    CHECK_EQ(s.last_security.parse, ParseStatus::Malformed);
    r.clock.set(3000);
    SecurityObservation cut;
    if (!reading(c_, "beacon_rsn_truncated_ie", meta_at(r.clock, 3000), cut)) return;
    r.core.security(cut);
    s = r.core.snapshot();
    CHECK_EQ(s.coverage, Coverage::Fresh);
    CHECK_EQ(s.settings.mood, Mood::Unknown);
    CHECK_EQ(s.last_security.parse, ParseStatus::Truncated);
}

GUARDIAN_CASE(newer_sample_with_unverified_receive_status_is_fresh_but_unrated) {
    Rig r;
    RxMeta m = meta_at(r.clock, 1000);
    m.status = RxStatus::Unknown;
    SecurityObservation s;
    if (!reading(c_, "beacon_wpa3_sae_pmf_required", m, s)) return;
    r.core.security(s);
    Snapshot snap = r.core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Fresh);
    CHECK_EQ(snap.settings.mood, Mood::Unknown);
    CHECK_EQ(snap.settings.unrated, Unrated::ReceiveUnverified);
}

// ---- identity isolation -----------------------------------------------------------------
GUARDIAN_CASE(wrong_bssid_with_the_same_ssid_is_rejected) {
    Rig r;
    SecurityObservation s;
    if (!wpa3(c_, r.clock, 1000, s)) return;
    s.network.bssid[5] = 0x56; // another AP advertising "home"
    r.core.security(s);
    Snapshot snap = r.core.snapshot();
    CHECK(!snap.has_security);
    CHECK_EQ(snap.rejected.network, 1u);
    CHECK_EQ(snap.coverage, Coverage::Checking);
}

GUARDIAN_CASE(same_bssid_with_different_ssid_bytes_is_rejected_hidden_and_binary_included) {
    Rig r;
    SecurityObservation hidden, binary, home_frame;
    if (!reading(c_, "beacon_hidden_ssid_wpa2", meta_at(r.clock, 1000), hidden)) return;
    if (!reading(c_, "beacon_ssid_non_utf8", meta_at(r.clock, 1000), binary)) return;
    if (!wpa3(c_, r.clock, 1000, home_frame)) return;
    CHECK_EQ(hidden.ssid_kind, SsidKind::Hidden);
    r.core.security(hidden); // same BSSID, zero-length SSID: a different identity
    r.core.security(binary); // same BSSID, bytes ff fe 78 01
    CHECK(!r.core.snapshot().has_security);
    CHECK_EQ(r.core.snapshot().rejected.network, 2u);
    r.core.security(home_frame);
    CHECK(r.core.snapshot().has_security);
}

GUARDIAN_CASE(selecting_a_hidden_identity_accepts_hidden_beacons_only) {
    FakeClock clock;
    Core core(clock, profiles::all_2g4_channels(), Origin::Imported);
    Network hidden_id = home();
    hidden_id.ssid_size = 0; // identity as the hidden beacon carries it
    CHECK(core.select(hidden_id));
    SecurityObservation hidden, named;
    if (!reading(c_, "beacon_hidden_ssid_wpa2", meta_at(clock, 1000), hidden)) return;
    if (!reading(c_, "probe_response_wpa2", meta_at(clock, 1000), named)) return;
    core.security(hidden);
    CHECK(core.snapshot().has_security);
    CHECK_EQ(core.snapshot().settings.mood, Mood::Medium);
    core.security(named); // the probe response names the SSID: another identity under byte equality
    CHECK_EQ(core.snapshot().rejected.network, 1u);
}

GUARDIAN_CASE(binary_ssid_identity_is_exact_bytes) {
    FakeClock clock;
    Core core(clock, profiles::all_2g4_channels(), Origin::Imported);
    Network bin{};
    bin.bssid = home().bssid;
    bin.ssid = {0xff, 0xfe, 0x78, 0x01};
    bin.ssid_size = 4;
    CHECK(core.select(bin));
    SecurityObservation s;
    if (!reading(c_, "beacon_ssid_non_utf8", meta_at(clock, 1000), s)) return;
    core.security(s);
    CHECK(core.snapshot().has_security);
    CHECK_EQ(core.snapshot().settings.mood, Mood::Medium);
    Network off = bin;
    off.ssid[3] = 0x02;
    CHECK(core.select(off));
    core.security(s);
    CHECK(!core.snapshot().has_security);
    CHECK_EQ(core.snapshot().rejected.network, 1u);
}

GUARDIAN_CASE(origin_separation_demo_imported_live) {
    FakeClock clock;
    for (Origin mine : {Origin::LiveRadio, Origin::Imported, Origin::Demo}) {
        Core core(clock, profiles::all_2g4_channels(), mine);
        core.select(home());
        for (Origin theirs : {Origin::LiveRadio, Origin::Imported, Origin::Demo}) {
            SecurityObservation s;
            if (!wpa3(c_, clock, 1000, s, theirs)) return;
            core.security(s);
        }
        Snapshot snap = core.snapshot();
        CHECK(snap.has_security);
        CHECK_EQ(snap.last_security.origin, mine);
        CHECK_EQ(snap.origin, mine);
        CHECK_EQ(snap.rejected.origin, 2u);
    }
}

GUARDIAN_CASE(unrelated_frames_from_the_selected_bssid_are_never_security_evidence) {
    Rig r;
    SecurityObservation good, deauth;
    if (!wpa3(c_, r.clock, 1000, good)) return;
    r.core.security(good);
    r.clock.set(2000);
    if (!reading(c_, "deauth_reason7", meta_at(r.clock, 2000), deauth)) return;
    deauth.network = home(); // even if an adapter copied the selected identity onto it
    r.core.security(deauth);
    Snapshot s = r.core.snapshot();
    CHECK_EQ(s.settings.mood, Mood::VeryGood);
    CHECK_EQ(s.last_security.acquired.at, Millis{1000});
    CHECK_EQ(s.rejected.unrelated, 1u);
}

// ---- time: epochs, future, reboot, restore ----------------------------------------------
GUARDIAN_CASE(invalid_acquisition_instant_is_rejected) {
    Rig r;
    SecurityObservation s;
    if (!wpa3(c_, r.clock, 1000, s)) return;
    s.acquired.known = false;
    r.core.security(s);
    s.acquired.known = true;
    s.acquired.epoch = TimeEpoch{}; // zero source: not a timebase
    r.core.security(s);
    Snapshot snap = r.core.snapshot();
    CHECK(!snap.has_security);
    CHECK_EQ(snap.rejected.invalid_time, 2u);
}

GUARDIAN_CASE(future_sample_is_rejected_and_does_not_poison_later_live_samples) {
    Rig r;
    SecurityObservation future, now;
    if (!reading(c_, "beacon_open", meta_at(r.clock, 1000000000), future)) return;
    r.core.security(future);
    Snapshot s = r.core.snapshot();
    CHECK(!s.has_security);
    CHECK_EQ(s.rejected.future, 1u);
    r.clock.set(5000);
    if (!wpa3(c_, r.clock, 5000, now)) return;
    r.core.security(now);
    s = r.core.snapshot();
    CHECK(s.has_security);
    CHECK_EQ(s.last_security.acquired.at, Millis{5000});
    CHECK_EQ(s.coverage, Coverage::Fresh);
    CHECK_EQ(s.settings.mood, Mood::VeryGood);
    CHECK_EQ(s.age_ms, Millis{0});
    // One millisecond ahead of the clock is still the future; exactly now is fine.
    SecurityObservation edge;
    if (!wpa3(c_, r.clock, 5001, edge)) return;
    r.core.security(edge);
    CHECK_EQ(r.core.snapshot().rejected.future, 2u);
}

GUARDIAN_CASE(reboot_demotes_live_evidence_to_historical_and_never_grades_it) {
    Rig r;
    SecurityObservation s;
    if (!wpa3(c_, r.clock, 1000, s)) return;
    r.core.security(s);
    CHECK_EQ(r.core.snapshot().settings.mood, Mood::VeryGood);
    r.clock.reboot(); // boot_id changes, Millis restart at 0
    Snapshot snap = r.core.snapshot();
    CHECK(snap.has_security);
    CHECK(snap.security_historical);
    CHECK_EQ(snap.settings.mood, Mood::Unknown);
    CHECK_EQ(snap.coverage, Coverage::Stale);
    CHECK_EQ(snap.age_ms, Millis{0}); // age across timebases is unknown, never computed
    r.clock.set(25000); // a Millis that would look "fresh" against the old 1000 is still not comparable
    snap = r.core.snapshot();
    CHECK(snap.security_historical);
    CHECK_EQ(snap.settings.mood, Mood::Unknown);
    CHECK(snap.coverage != Coverage::Fresh);
}

GUARDIAN_CASE(restored_record_from_a_previous_boot_is_historical_until_observed_again) {
    FakeClock clock(500, epoch_of(1, 7));
    Core core(clock, profiles::all_2g4_channels(), Origin::Imported);
    core.select(home());
    SecurityObservation cached;
    if (!wpa3(c_, clock, 90000, cached)) return;
    cached.acquired.epoch = epoch_of(1, 6); // previous boot of the same device
    core.security(cached);
    Snapshot s = core.snapshot();
    CHECK(s.has_security);
    CHECK(s.security_historical);
    CHECK_EQ(s.coverage, Coverage::Checking); // startup: checking, with the last known record available
    CHECK_EQ(s.settings.mood, Mood::Unknown);
    CHECK_EQ(s.last_security.acquired.epoch.boot_id, 6u);
    CHECK_EQ(s.rejected.foreign_epoch, 0u);
    clock.set(500 + Core::fresh_ms);
    CHECK_EQ(core.snapshot().coverage, Coverage::Stale); // "No fresh data", still historical
    CHECK(core.snapshot().security_historical);
    // A second restored record cannot replace the first: there is no order across timebases.
    SecurityObservation cached2;
    if (!reading(c_, "beacon_open", meta_at(clock, 1), cached2)) return;
    cached2.acquired.epoch = epoch_of(1, 5);
    core.security(cached2);
    CHECK_EQ(core.snapshot().rejected.foreign_epoch, 1u);
    CHECK_EQ(core.snapshot().last_security.acquired.epoch.boot_id, 6u);
    // Observed again in this boot: live, fresh, graded.
    SecurityObservation live;
    if (!wpa3(c_, clock, 500 + Core::fresh_ms, live)) return;
    core.security(live);
    s = core.snapshot();
    CHECK(!s.security_historical);
    CHECK_EQ(s.coverage, Coverage::Fresh);
    CHECK_EQ(s.settings.mood, Mood::VeryGood);
    // Once live evidence exists, a foreign-epoch reading never displaces it.
    core.security(cached);
    CHECK_EQ(core.snapshot().rejected.foreign_epoch, 2u);
    CHECK(!core.snapshot().security_historical);
}

GUARDIAN_CASE(another_devices_epoch_is_foreign_even_with_the_same_boot_counter) {
    Rig r;
    SecurityObservation live, other;
    if (!wpa3(c_, r.clock, 1000, live)) return;
    r.core.security(live);
    if (!reading(c_, "beacon_open", meta_at(r.clock, 2000), other)) return;
    other.acquired.epoch = epoch_of(2, 1); // another source, same boot_id
    r.clock.set(2000);
    r.core.security(other);
    Snapshot s = r.core.snapshot();
    CHECK_EQ(s.settings.mood, Mood::VeryGood);
    CHECK_EQ(s.rejected.foreign_epoch, 1u);
}

// ---- channel capability -----------------------------------------------------------------
GUARDIAN_CASE(channel_outside_the_configured_radio_capability_is_rejected) {
    Rig r;
    SecurityObservation s;
    for (std::uint8_t ch : {std::uint8_t{0}, std::uint8_t{15}, std::uint8_t{36}}) {
        if (!reading(c_, "beacon_wpa3_sae_pmf_required", meta_at(r.clock, 1000, Origin::Imported, ch), s)) return;
        r.core.security(s);
    }
    Snapshot snap = r.core.snapshot();
    CHECK(!snap.has_security);
    CHECK_EQ(snap.rejected.channel, 3u);
    if (!reading(c_, "beacon_wpa3_sae_pmf_required", meta_at(r.clock, 1000, Origin::Imported, 14), s)) return;
    r.core.security(s);
    CHECK(r.core.snapshot().has_security);
}

GUARDIAN_CASE(a_5ghz_capable_radio_accepts_channel_36_and_bands_do_not_alias) {
    FakeClock clock;
    ChannelSet set{};
    set.set(Band::Ghz5, 36);
    Core core(clock, set, Origin::Imported);
    core.select(home());
    RxMeta m = meta_at(clock, 1000, Origin::Imported, 36);
    m.band = Band::Ghz5;
    SecurityObservation s;
    if (!reading(c_, "beacon_wpa3_sae_pmf_required", m, s)) return;
    core.security(s);
    CHECK(core.snapshot().has_security);
    CHECK_EQ(core.snapshot().last_security.band, Band::Ghz5);
    m.band = Band::Ghz2_4; // channel 36 on the 2.4 GHz band is not a capability this radio has
    if (!reading(c_, "beacon_wpa3_sae_pmf_required", m, s)) return;
    core.security(s);
    CHECK_EQ(core.snapshot().rejected.channel, 1u);
}

GUARDIAN_CASE(unknown_channel_capability_rejects_every_reading) {
    FakeClock clock;
    Core core(clock, ChannelSet{}, Origin::Imported); // adapter has not established its channels
    core.select(home());
    SecurityObservation s;
    if (!wpa3(c_, clock, 1000, s)) return;
    core.security(s);
    CHECK(!core.snapshot().has_security);
    CHECK_EQ(core.snapshot().rejected.channel, 1u);
}

// ---- RSSI/activity and coverage never renew security evidence -----------------------------
GUARDIAN_CASE(signal_readings_do_not_refresh_expired_security_evidence) {
    Rig r;
    SecurityObservation s;
    if (!wpa3(c_, r.clock, 1000, s)) return;
    r.core.security(s);
    for (Millis t : {Millis{20000}, Millis{40000}, Millis{60000}}) {
        r.clock.set(t);
        SignalObservation sig;
        if (!signal_reading(c_, "deauth_reason7", meta_at(r.clock, t), sig)) return;
        r.core.signal(sig);
    }
    Snapshot snap = r.core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Stale);
    CHECK_EQ(snap.settings.mood, Mood::Unknown);
    CHECK_EQ(snap.age_ms, Millis{59000});
    CHECK(snap.has_signal);
    CHECK_EQ(snap.signal_age_ms, Millis{0});
    CHECK_EQ(snap.last_signal.rssi, -55);
    CHECK_EQ(snap.last_signal.kind, FrameKind::Deauthentication);
}

GUARDIAN_CASE(signal_is_scoped_by_bssid_and_follows_the_same_time_rules) {
    Rig r;
    SignalObservation sig;
    if (!signal_reading(c_, "deauth_reason7", meta_at(r.clock, 1000), sig)) return;
    SignalObservation other = sig;
    other.bssid[5] = 0x56;
    r.core.signal(other);
    SignalObservation future = sig;
    future.acquired.at = 999999;
    r.core.signal(future);
    SignalObservation foreign = sig;
    foreign.acquired.epoch = epoch_of(1, 2);
    r.core.signal(foreign);
    SignalObservation elsewhere = sig;
    elsewhere.channel = 40;
    r.core.signal(elsewhere);
    SignalObservation imported_as_live = sig;
    imported_as_live.origin = Origin::LiveRadio;
    r.core.signal(imported_as_live);
    Snapshot snap = r.core.snapshot();
    CHECK(!snap.has_signal);
    CHECK_EQ(snap.rejected.network, 1u);
    CHECK_EQ(snap.rejected.future, 1u);
    CHECK_EQ(snap.rejected.foreign_epoch, 1u);
    CHECK_EQ(snap.rejected.channel, 1u);
    CHECK_EQ(snap.rejected.origin, 1u);
    r.core.signal(sig);
    CHECK(r.core.snapshot().has_signal);
    SignalObservation older = sig;
    older.acquired.at = 500;
    r.core.signal(older);
    CHECK_EQ(r.core.snapshot().last_signal.acquired.at, Millis{1000});
    CHECK_EQ(r.core.snapshot().rejected.older, 1u);
    CHECK(!r.core.snapshot().has_security); // a signal is never security evidence
}

GUARDIAN_CASE(coverage_report_never_refreshes_security_but_degrades_when_not_listening_or_dropping) {
    Rig r;
    SecurityObservation s;
    if (!wpa3(c_, r.clock, 1000, s)) return;
    r.core.security(s);
    r.core.coverage(listening(r.clock, 1000));
    Snapshot snap = r.core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Fresh);
    CHECK(snap.has_coverage);
    CHECK_EQ(snap.coverage_age_ms, Millis{0});
    r.clock.set(2000);
    r.core.coverage(listening(r.clock, 2000, 0)); // channel 0: not listening
    snap = r.core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Degraded);
    CHECK_EQ(snap.settings.mood, Mood::Unknown); // a grade is not shown over degraded coverage
    CHECK(snap.has_security);                    // the record stays
    r.clock.set(3000);
    r.core.coverage(listening(r.clock, 3000, 6, 4)); // queue drops in the window
    snap = r.core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Degraded);
    CHECK_EQ(snap.last_coverage.dropped_in_window, 4u);
    // Review 2026-11-17: degraded is held through a brief clean blip (anti-flap under a deauth storm);
    // a single clean window no longer flips straight back to Fresh.
    r.clock.set(4000);
    r.core.coverage(listening(r.clock, 4000));
    snap = r.core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Degraded);
    r.clock.set(4000 + Core::coverage_recover_ms);
    r.core.coverage(listening(r.clock, 4000 + Core::coverage_recover_ms));   // sustained clean clears it
    snap = r.core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Fresh);
    CHECK_EQ(snap.settings.mood, Mood::VeryGood);
    // Clean coverage reports keep arriving, security evidence does not: stale, not fresh.
    for (Millis t : {Millis{20000}, Millis{31000}, Millis{40000}}) {
        r.clock.set(t);
        r.core.coverage(listening(r.clock, t));
    }
    snap = r.core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Stale);
    CHECK_EQ(snap.settings.mood, Mood::Unknown);
    CHECK_EQ(snap.coverage_age_ms, Millis{0});
}

// G14 board finding (2026-11-15): with the AP off the companion hops channels and
// keeps reporting fresh "not listening" coverage. Old evidence must still become
// No fresh data; degraded listening only qualifies evidence that is still fresh.
GUARDIAN_CASE(stale_evidence_wins_over_fresh_degraded_coverage) {
    Rig r;
    SecurityObservation s;
    if (!wpa3(c_, r.clock, 1000, s)) return;
    r.core.security(s);
    for (Millis t = 2000; t < 1000 + Core::fresh_ms; t += 1000) {
        r.clock.set(t);
        r.core.coverage(listening(r.clock, t, 0)); // hopping/not on the AP channel
    }
    Snapshot snap = r.core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Degraded);   // still fresh evidence: degraded, ungraded
    CHECK_EQ(snap.settings.mood, Mood::Unknown);
    r.clock.set(1000 + Core::fresh_ms);
    r.core.coverage(listening(r.clock, r.clock.now(), 0));
    snap = r.core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Stale);      // evidence expired: No fresh data
    CHECK_EQ(snap.age_ms, Core::fresh_ms);
    CHECK_EQ(snap.settings.mood, Mood::Unknown);
    CHECK(snap.has_coverage);                      // the listening report is still visible
    CHECK_EQ(snap.coverage_age_ms, Millis{0});
}

GUARDIAN_CASE(stale_foreign_or_future_coverage_reports_do_not_degrade) {
    Rig r;
    SecurityObservation s;
    if (!wpa3(c_, r.clock, 1000, s)) return;
    r.core.security(s);
    CoverageReport old = listening(r.clock, 1000, 0);
    r.clock.set(1000 + Core::fresh_ms); // the not-listening report is 30 s old: unknown, not degraded
    r.core.coverage(old);
    r.core.security(s);
    SecurityObservation renew;
    if (!wpa3(c_, r.clock, r.clock.now(), renew)) return;
    r.core.security(renew);
    Snapshot snap = r.core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Fresh);
    CHECK(snap.has_coverage);
    CHECK_EQ(snap.coverage_age_ms, Core::fresh_ms);
    CoverageReport foreign = listening(r.clock, r.clock.now(), 0);
    foreign.sampled_at.epoch = epoch_of(1, 9);
    r.core.coverage(foreign);
    CoverageReport future = listening(r.clock, r.clock.now() + 1, 0);
    r.core.coverage(future);
    CoverageReport unknown = listening(r.clock, r.clock.now(), 0);
    unknown.sampled_at.known = false;
    r.core.coverage(unknown);
    snap = r.core.snapshot();
    CHECK_EQ(snap.coverage, Coverage::Fresh);
    CHECK_EQ(snap.rejected.foreign_epoch, 1u);
    CHECK_EQ(snap.rejected.future, 1u);
    CHECK_EQ(snap.rejected.invalid_time, 1u);
}

GUARDIAN_CASE(a_live_core_whose_radio_cannot_receive_passively_is_degraded_an_imported_one_is_not) {
    FakeClock clock;
    Core live(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    live.select(home());
    SecurityObservation s;
    if (!wpa3(c_, clock, 1000, s, Origin::LiveRadio)) return;
    live.security(s);
    CoverageReport c = listening(clock, 1000);
    c.passive_receive = Support::Unknown; // adapter never established passive reception
    live.coverage(c);
    CHECK_EQ(live.snapshot().coverage, Coverage::Degraded);
    c.passive_receive = Support::Supported;
    live.coverage(c);   // condition fixed, but degraded is held until sustained clean (review 2026-11-17)
    CHECK_EQ(live.snapshot().coverage, Coverage::Degraded);
    clock.set(1000 + Core::coverage_recover_ms);
    { CoverageReport ok = listening(clock, 1000 + Core::coverage_recover_ms); ok.passive_receive = Support::Supported; live.coverage(ok); }
    CHECK_EQ(live.snapshot().coverage, Coverage::Fresh);
    Rig replay; // Imported: fixture input is not RF; Unsupported passive receive is expected there
    SecurityObservation i;
    if (!wpa3(c_, replay.clock, 1000, i)) return;
    replay.core.security(i);
    replay.core.coverage(listening(replay.clock, 1000));
    CHECK_EQ(replay.core.snapshot().coverage, Coverage::Fresh);
}

// ---- incidents follow the same epoch rules ------------------------------------------------
GUARDIAN_CASE(incident_uses_the_acquisition_instant_and_rejects_foreign_or_future_time) {
    Rig r;
    IncidentObservation i{};
    i.affected = home();
    i.origin = Origin::Imported;
    i.acquired = Instant{r.clock.epoch(), 1000, true};
    i.kind = IncidentKind::DisconnectBurst;
    i.count = 25;
    i.window_ms = 10000;
    r.core.incident(i);
    CHECK(r.core.snapshot().incidents[0]);
    r.clock.set(1000 + Core::incident_ms - 1);
    CHECK(r.core.snapshot().incidents[0]);
    r.clock.advance(1);
    CHECK(!r.core.snapshot().incidents[0]);
    IncidentObservation future = i;
    future.acquired.at = r.clock.now() + 1;
    r.core.incident(future);
    IncidentObservation foreign = i;
    foreign.acquired.at = r.clock.now();
    foreign.acquired.epoch = epoch_of(1, 2);
    r.core.incident(foreign);
    IncidentObservation unknown = i;
    unknown.acquired = Instant{};
    r.core.incident(unknown);
    Snapshot s = r.core.snapshot();
    CHECK(!s.incidents[0]);
    CHECK_EQ(s.rejected.future, 1u);
    CHECK_EQ(s.rejected.foreign_epoch, 1u);
    CHECK_EQ(s.rejected.invalid_time, 1u);
    r.clock.reboot();
    r.clock.set(1000);
    IncidentObservation again = i;
    again.acquired = Instant{r.clock.epoch(), 1000, true};
    r.core.incident(again);
    CHECK(r.core.snapshot().incidents[0]); // the new epoch's evidence is current
}

// ---- G16N: every accepted incident report counts, so a dark screen can be lit for each ------
GUARDIAN_CASE(incident_seq_counts_every_accepted_network_and_area_report_and_never_goes_back) {
    Rig r;
    CHECK_EQ(r.core.snapshot().incident_seq, 0u);
    IncidentObservation i{};
    i.affected = home();
    i.origin = Origin::Imported;
    i.acquired = Instant{r.clock.epoch(), 1000, true};
    i.kind = IncidentKind::DisconnectBurst;
    r.core.incident(i);
    CHECK_EQ(r.core.snapshot().incident_seq, 1u);
    // A second report of the SAME kind while the first is still current is a new report.
    r.clock.set(20000);
    i.acquired.at = 20000;
    r.core.incident(i);
    Snapshot s = r.core.snapshot();
    CHECK(s.incidents[0]);
    CHECK_EQ(s.incident_seq, 2u);
    // Another kind, and an area (amber) observation, count too.
    IncidentObservation changed = i; changed.kind = IncidentKind::SettingsChanged;
    r.core.incident(changed);
    IncidentObservation area{};
    area.scope = IncidentScope::Area; area.family = DetectorFamily::Probe; area.origin = Origin::Imported;
    area.acquired = Instant{r.clock.epoch(), 20000, true};
    r.core.incident(area);
    s = r.core.snapshot();
    CHECK(s.area_visible[0]);
    CHECK_EQ(s.incident_seq, 4u);
    // Reading the snapshot, time passing and the incidents expiring never change it.
    r.clock.advance(Core::incident_ms + Core::area_incident_ms);
    s = r.core.snapshot();
    CHECK(!s.incidents[0]); CHECK(!s.area_visible[0]);
    CHECK_EQ(s.incident_seq, 4u);
    // Refused reports are not incidents: wrong network, wrong origin, the future, another
    // timebase, an unknown instant, older than the held one, an area family out of range.
    IncidentObservation other = i; other.affected = home(0x66); other.acquired.at = r.clock.now();
    r.core.incident(other);
    IncidentObservation demo = i; demo.origin = Origin::Demo; demo.acquired.at = r.clock.now();
    r.core.incident(demo);
    IncidentObservation future = i; future.acquired.at = r.clock.now() + 1;
    r.core.incident(future);
    IncidentObservation foreign = i; foreign.acquired = Instant{epoch_of(1, 2), 5, true};
    r.core.incident(foreign);
    IncidentObservation unknown = i; unknown.acquired = Instant{};
    r.core.incident(unknown);
    IncidentObservation older = i; older.acquired.at = 19999;
    r.core.incident(older);
    IncidentObservation bad_area = area; bad_area.family = DetectorFamily::Count; bad_area.acquired.at = r.clock.now();
    r.core.incident(bad_area);
    IncidentObservation old_area = area; old_area.acquired.at = 19999;
    r.core.incident(old_area);
    IncidentObservation demo_area = area; demo_area.origin = Origin::Demo; demo_area.acquired.at = r.clock.now();
    r.core.incident(demo_area);
    CHECK_EQ(r.core.snapshot().incident_seq, 4u);
    // A new selection clears the held incidents but the count keeps going up (never back to an old value).
    r.core.select(home(0x66));
    CHECK_EQ(r.core.snapshot().incident_seq, 4u);
    IncidentObservation next = i; next.affected = home(0x66); next.acquired.at = r.clock.now();
    r.core.incident(next);
    CHECK_EQ(r.core.snapshot().incident_seq, 5u);
    // With nothing selected a network report is refused; an area report needs no selection.
    FakeClock clock;
    Core bare{clock, profiles::all_2g4_channels(), Origin::Imported};
    IncidentObservation n = i; n.acquired = Instant{clock.epoch(), clock.now(), true};
    bare.incident(n);
    CHECK_EQ(bare.snapshot().incident_seq, 0u);
    IncidentObservation a = area; a.acquired = Instant{clock.epoch(), clock.now(), true};
    bare.incident(a);
    CHECK_EQ(bare.snapshot().incident_seq, 1u);
}

// ---- select resets everything ----------------------------------------------------------
GUARDIAN_CASE(select_resets_evidence_signal_coverage_counters_and_the_checking_window) {
    Rig r;
    SecurityObservation s;
    if (!wpa3(c_, r.clock, 1000, s)) return;
    r.core.security(s);
    SignalObservation sig;
    if (!signal_reading(c_, "deauth_reason7", meta_at(r.clock, 1000), sig)) return;
    r.core.signal(sig);
    r.core.coverage(listening(r.clock, 1000, 0));
    s.network.bssid[5] = 0x56;
    r.core.security(s);
    r.clock.set(1000 + Core::fresh_ms);
    Snapshot before = r.core.snapshot();
    CHECK(before.has_security);
    CHECK(before.has_signal);
    CHECK(before.has_coverage);
    CHECK_EQ(before.rejected.network, 1u);
    CHECK(r.core.select(home(0x56)));
    Snapshot after = r.core.snapshot();
    CHECK(!after.has_security);
    CHECK(!after.has_signal);
    CHECK(!after.has_coverage);
    CHECK_EQ(after.rejected.network, 0u);
    CHECK_EQ(after.coverage, Coverage::Checking); // the 30 s checking window restarts at selection
    CHECK(after.selected == home(0x56));
}

// ---- the whole imported pipeline -------------------------------------------------------
GUARDIAN_CASE(imported_pipeline_parser_to_snapshot_rates_each_fixture_mood) {
    struct Row { const char* fixture; Mood mood; } rows[] = {
        {"beacon_wpa3_sae_pmf_required", Mood::VeryGood},
        {"beacon_wpa2_ccmp_pmf_optional", Mood::Medium},
        {"beacon_wpa2_mixed_tkip", Mood::Bad},
        {"beacon_wpa1_tkip_vendor", Mood::Bad},
        {"beacon_open", Mood::Horrible},
        {"beacon_owe_transition", Mood::Unknown},
        {"beacon_rsn_unknown_akm", Mood::Unknown},
    };
    Millis t = 1000;
    Rig r;
    for (const Row& row : rows) {
        r.clock.set(t);
        SecurityObservation s;
        if (!reading(c_, row.fixture, meta_at(r.clock, t), s)) continue;
        r.core.security(s);
        const Snapshot snap = r.core.snapshot();
        if (snap.coverage != Coverage::Fresh) CHECK_FAIL(std::string(row.fixture) + ": not fresh");
        if (snap.settings.mood != row.mood) CHECK_FAIL(std::string(row.fixture) + ": unexpected mood");
        CHECK_EQ(snap.origin, Origin::Imported);
        t += 1000;
    }
}

// Review 2026-11-17 (device: a deauth flood flapped the "listening coverage degraded" overlay):
// degraded warns on the first bad window but clears only after coverage is clean for the recover
// hold, so brief clean windows inside a storm never flip it back to Fresh.
GUARDIAN_CASE(degraded_coverage_holds_through_clean_blips_and_warns_immediately) {
    Rig r;
    SecurityObservation s;
    if (!wpa3(c_, r.clock, 1000, s)) return;
    r.core.security(s);
    r.core.coverage(listening(r.clock, 1000));
    CHECK_EQ(r.core.snapshot().coverage, Coverage::Fresh);
    r.clock.set(2000); r.core.coverage(listening(r.clock, 2000, 6, 3));   // drops: warn at once
    CHECK_EQ(r.core.snapshot().coverage, Coverage::Degraded);
    r.clock.set(2500); r.core.coverage(listening(r.clock, 2500));         // one clean blip: still degraded
    CHECK_EQ(r.core.snapshot().coverage, Coverage::Degraded);
    r.clock.set(3000); r.core.coverage(listening(r.clock, 3000, 6, 7));   // bad again: clean timer resets
    CHECK_EQ(r.core.snapshot().coverage, Coverage::Degraded);
    r.clock.set(3500); r.core.coverage(listening(r.clock, 3500));         // clean begins here
    CHECK_EQ(r.core.snapshot().coverage, Coverage::Degraded);
    r.clock.set(3500 + Core::coverage_recover_ms);
    r.core.coverage(listening(r.clock, 3500 + Core::coverage_recover_ms));   // sustained clean: recovers
    CHECK_EQ(r.core.snapshot().coverage, Coverage::Fresh);
}

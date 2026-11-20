// G07 advice checks (TDD: written and run RED against a stub advise() first;
// see docs/G07-advice.md for the recorded run).
//
// Two kinds of case: through the real pipeline (fixture bytes -> the G04
// SecurityFrameParser -> observe_security()/observe_signal() -> the G05 Core
// -> Snapshot -> advise()) and hand-built Snapshots for rows the fixtures do
// not carry. Every input is Origin::Imported or hand-built; the clock is a
// fake. Nothing here is radio proof and no advice here is a claim about a
// real network. The reviewer's acceptance line is executable here: good RSSI
// cannot improve a grade; lost Internet, absent sensor data or an unsuccessful
// password test cannot imply an RF attack or password strength.
#include "check.hpp"
#include "fixtures.hpp"

#include "guardian/advice.hpp"
#include "guardian/presenter.hpp"
#include "guardian/rating.hpp"
#include "guardian/security_parser.hpp"

#include <cstring>
#include <set>
#include <string>
#include <type_traits>

using namespace guardian;
using guardian::fixtures::Fixture;

static_assert(std::is_trivially_copyable_v<Advice> && std::is_trivially_copyable_v<SignalView>
              && std::is_trivially_copyable_v<ConnectivityProbePlan> && std::is_trivially_copyable_v<ConnectivityResult>,
              "advice outputs are plain values");
static_assert(sizeof(Advice) <= 512, "advice fits a small board stack frame");
static_assert(static_cast<std::size_t>(OwnerCheckId::Count) == 7, "seven owner checks (ledger list)");

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
    explicit FakeClock(Millis start = 1000, TimeEpoch epoch = epoch_of(7, 1)) : now_(start), epoch_(epoch) {}
    Millis now() const override { return now_; }
    TimeEpoch epoch() const override { return epoch_; }
    void set(Millis t) { now_ = t; }
    void advance(Millis ms) { now_ += ms; }
    void reboot() { ++epoch_.boot_id; now_ = 0; }
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
Network hidden_home() {
    Network n = home();
    n.ssid = {};
    n.ssid_size = 0;
    return n;
}

RxMeta meta_at(const FakeClock& clock, Millis at, std::int8_t rssi = -55, std::uint8_t channel = 6) {
    RxMeta m{};
    m.acquired = Instant{clock.epoch(), at, true};
    m.status = RxStatus::Ok;
    m.origin = Origin::Imported;
    m.band = Band::Ghz2_4;
    m.channel = channel;
    m.rssi_dbm = rssi;
    m.rssi_valid = true;
    return m;
}

bool load(check::Case& c_, const char* name, Fixture& f) {
    std::string err;
    if (fixtures::load(name, f, err)) return true;
    CHECK_FAIL(err);
    return false;
}

struct Rig {
    FakeClock clock{};
    Core core{clock, profiles::all_2g4_channels(), Origin::Imported};
    explicit Rig(const Network& n = home()) { core.select(n); }
    // Real parser over a fixture; both reductions go to the core (as the application loop does).
    bool feed(check::Case& c_, const char* name, const RxMeta& m) {
        Fixture f;
        if (!load(c_, name, f)) return false;
        const ParseResult p = parser.parse(FrameSpan{f.bytes.data(), static_cast<std::uint16_t>(f.bytes.size()), false}, m);
        core.security(observe_security(p, m));
        core.signal(observe_signal(p, m));
        return true;
    }
    Advice advice(const ConnectivityResult& conn = ConnectivityResult{}) const { return advise(core.snapshot(), conn); }
};

// Hand-built fresh graded snapshot, as Core would produce it.
Snapshot fresh(Mood mood, Finding reason, Unrated unrated = Unrated::None, Mode mode = Mode::Unknown) {
    Snapshot s{};
    s.selected = home();
    s.origin = Origin::Imported;
    s.coverage = Coverage::Fresh;
    s.has_security = true;
    s.settings.mood = mood;
    s.settings.reason = reason;
    s.settings.unrated = unrated;
    s.settings.mode = mode;
    s.last_security.network = home();
    s.last_security.ssid_kind = SsidKind::Present;
    s.last_security.parse = ParseStatus::Complete;
    s.last_security.rx_status = RxStatus::Ok;
    s.age_ms = 1200;
    return s;
}

bool no_incident_items(const Advice& a) {
    return !a.has(AdviceId::DisconnectTrafficObserved) && !a.has(AdviceId::UnexpectedApObserved)
        && !a.has(AdviceId::SettingsChangeObserved);
}
bool no_grade_items(const Advice& a) {
    return !a.has(AdviceId::OpenUnencrypted) && !a.has(AdviceId::WepIsBroken) && !a.has(AdviceId::Wpa3Strong)
        && !a.has(AdviceId::Wpa2AesPmfRequired) && !a.has(AdviceId::TransitionIsCompatibility);
}
std::size_t text_len(const char* t) { return t ? std::strlen(t) : 0; }

} // namespace

// ---- texts ----------------------------------------------------------------------------------
GUARDIAN_CASE(every_id_has_a_short_distinct_simple_language_text_and_none_count_are_empty) {
    std::set<std::string> seen;
    for (std::uint8_t i = 1; i < static_cast<std::uint8_t>(AdviceId::Count); ++i) {
        const char* t = advice_text(static_cast<AdviceId>(i));
        if (text_len(t) == 0) CHECK_FAIL("AdviceId " + std::to_string(i) + " has no text");
        if (text_len(t) > 200) CHECK_FAIL("AdviceId " + std::to_string(i) + " text longer than 200 chars");
        if (!seen.insert(t).second) CHECK_FAIL("AdviceId " + std::to_string(i) + " repeats another text");
    }
    for (std::uint8_t i = 1; i < static_cast<std::uint8_t>(NextStep::Count); ++i) {
        const char* t = advice_text(static_cast<NextStep>(i));
        if (text_len(t) == 0) CHECK_FAIL("NextStep " + std::to_string(i) + " has no text");
        if (text_len(t) > 120) CHECK_FAIL("NextStep " + std::to_string(i) + " text longer than 120 chars");
        if (!seen.insert(t).second) CHECK_FAIL("NextStep " + std::to_string(i) + " repeats another text");
    }
    for (std::uint8_t i = 0; i < static_cast<std::uint8_t>(OwnerCheckId::Count); ++i) {
        const char* t = advice_text(static_cast<OwnerCheckId>(i));
        if (text_len(t) == 0) CHECK_FAIL("OwnerCheckId " + std::to_string(i) + " has no text");
        if (!seen.insert(t).second) CHECK_FAIL("OwnerCheckId " + std::to_string(i) + " repeats another text");
    }
    CHECK(text_len(advice_text(Verification::NotMeasured)) > 0);
    CHECK(text_len(advice_text(Verification::Unverified)) > 0);
    CHECK(text_len(advice_text(Verification::Observed)) > 0);
    CHECK_EQ(text_len(advice_text(AdviceId::None)), std::size_t{0});
    CHECK_EQ(text_len(advice_text(AdviceId::Count)), std::size_t{0});
    CHECK_EQ(text_len(advice_text(NextStep::None)), std::size_t{0});
    CHECK_EQ(text_len(advice_text(NextStep::Count)), std::size_t{0});
    CHECK_EQ(text_len(advice_text(OwnerCheckId::Count)), std::size_t{0});
    CHECK_EQ(seen.size(), std::size_t{(static_cast<std::size_t>(AdviceId::Count) - 1) + (static_cast<std::size_t>(NextStep::Count) - 1)
                                       + static_cast<std::size_t>(OwnerCheckId::Count)});
}

GUARDIAN_CASE(texts_never_claim_an_attacker_safety_or_a_password_verdict) {
    // Words the product must not use about what it cannot see (docs/research/wifi-audit.md,
    // "What each display claim must mean"). Case-sensitive on purpose: these are the exact tokens.
    const char* banned[] = {"attacker", "hacker", "safe", "unhackable", "secure network", "evil twin", "sniffer",
                            "password is", "strong password", "weak password", "Internet is down", "no Internet"};
    auto scan = [&](const char* t, const std::string& who) {
        for (const char* b : banned)
            if (t && std::strstr(t, b)) CHECK_FAIL(who + " says '" + b + "'");
    };
    for (std::uint8_t i = 1; i < static_cast<std::uint8_t>(AdviceId::Count); ++i)
        scan(advice_text(static_cast<AdviceId>(i)), "AdviceId " + std::to_string(i));
    for (std::uint8_t i = 1; i < static_cast<std::uint8_t>(NextStep::Count); ++i)
        scan(advice_text(static_cast<NextStep>(i)), "NextStep " + std::to_string(i));
    for (std::uint8_t i = 0; i < static_cast<std::uint8_t>(OwnerCheckId::Count); ++i)
        scan(advice_text(static_cast<OwnerCheckId>(i)), "OwnerCheckId " + std::to_string(i));
    // The disconnect text must carry its uncertainty in words.
    const char* burst = advice_text(AdviceId::DisconnectTrafficObserved);
    CHECK(std::strstr(burst, "not proof") != nullptr);
    CHECK(std::strstr(advice_text(AdviceId::SignalIsLocalOnly), "this device") != nullptr);
    CHECK(std::strstr(advice_text(AdviceId::TransitionIsCompatibility), "compatibility") != nullptr);
    CHECK(std::strstr(advice_text(AdviceId::OweNotPlainOpen), "not") != nullptr);
}

// ---- the mood is copied, never recomputed ---------------------------------------------------
GUARDIAN_CASE(advice_copies_mood_reason_unrated_coverage_and_age_without_change) {
    for (Mood m : {Mood::Unknown, Mood::VeryGood, Mood::Good, Mood::Medium, Mood::Bad, Mood::Horrible}) {
        Snapshot s = fresh(m, Finding::Legacy);
        s.age_ms = 777;
        const Advice a = advise(s);
        CHECK_EQ(a.mood, m);
        CHECK_EQ(a.reason, Finding::Legacy);
        CHECK_EQ(a.coverage, Coverage::Fresh);
        CHECK_EQ(a.age_ms, Millis{777});
        CHECK(!a.historical);
    }
    Snapshot u = fresh(Mood::Unknown, Finding::Unknown, Unrated::Enterprise);
    CHECK_EQ(advise(u).unrated, Unrated::Enterprise);
}

GUARDIAN_CASE(good_rssi_cannot_improve_the_grade_and_bad_rssi_cannot_lower_it) {
    // The same Medium advertisement at -30 dBm and at -92 dBm, through the real core.
    for (std::int8_t rssi : {std::int8_t{-30}, std::int8_t{-92}}) {
        Rig r;
        if (!r.feed(c_, "beacon_wpa2_ccmp_pmf_optional", meta_at(r.clock, 1000, rssi))) return;
        r.clock.set(1500);
        const Advice a = r.advice();
        CHECK_EQ(a.mood, Mood::Medium);
        CHECK_EQ(a.reason, Finding::PmfNotRequired);
        CHECK(a.signal.available);
        CHECK(a.signal.rssi_valid);
        CHECK_EQ(a.signal.rssi_dbm, rssi);
        CHECK(a.has(AdviceId::SignalIsLocalOnly));
        CHECK_EQ(a.connection_health, Verification::NotMeasured); // a strong signal is not Internet access
        CHECK(a.has(AdviceId::PmfNotRequired));
        CHECK_EQ(a.next_step, NextStep::RequirePmfOrEnableWpa3);
    }
    // And the Horrible open network at -30 dBm stays Horrible.
    Rig strong;
    if (!strong.feed(c_, "beacon_open", meta_at(strong.clock, 1000, -30))) return;
    strong.clock.set(1200);
    const Advice a = strong.advice();
    CHECK_EQ(a.mood, Mood::Horrible);
    CHECK_EQ(a.signal.rssi_dbm, -30);
    CHECK(a.has(AdviceId::OpenUnencrypted));
    CHECK_EQ(a.next_step, NextStep::EnableWpa2AesOrWpa3);
}

// ---- signal at this device ------------------------------------------------------------------
GUARDIAN_CASE(signal_view_shows_rssi_age_channel_and_the_sampling_interval_at_this_device) {
    Rig r;
    // One sample: available, interval unknown.
    if (!r.feed(c_, "beacon_wpa3_sae_pmf_required", meta_at(r.clock, 1000, -51))) return;
    r.clock.set(1400);
    Advice a = r.advice();
    CHECK(a.signal.available);
    CHECK_EQ(a.signal.rssi_dbm, -51);
    CHECK_EQ(a.signal.age_ms, Millis{400});
    CHECK_EQ(a.signal.channel, 6);
    CHECK_EQ(a.signal.band, Band::Ghz2_4);
    CHECK(!a.signal.interval_known);
    CHECK_EQ(a.signal.interval_ms, Millis{0});
    // Second sample 2.5 s later (a deauth counts as a signal reading too), drained 500 ms late:
    // the interval is between the two ACQUISITION instants, never from the drain time.
    r.clock.set(4000);
    if (!r.feed(c_, "deauth_reason7", meta_at(r.clock, 3500, -60))) return;
    a = r.advice();
    CHECK(a.signal.available);
    CHECK_EQ(a.signal.rssi_dbm, -60);
    CHECK_EQ(a.signal.age_ms, Millis{500});
    CHECK(a.signal.interval_known);
    CHECK_EQ(a.signal.interval_ms, Millis{2500});
    // The deauth did not renew security evidence: still the beacon's age.
    CHECK_EQ(a.age_ms, Millis{3000});
    CHECK_EQ(a.mood, Mood::VeryGood);
    // Third sample 1 s later: interval is between the LAST two.
    r.clock.set(4500);
    if (!r.feed(c_, "deauth_reason7", meta_at(r.clock, 4500, -58))) return;
    a = r.advice();
    CHECK(a.signal.interval_known);
    CHECK_EQ(a.signal.interval_ms, Millis{1000});
    // Re-select: everything about the signal is forgotten.
    r.core.select(home());
    a = r.advice();
    CHECK(!a.signal.available);
    CHECK(!a.signal.interval_known);
    CHECK_EQ(a.signal.interval_ms, Millis{0});
    CHECK(!a.has(AdviceId::SignalIsLocalOnly));
}

GUARDIAN_CASE(signal_without_a_valid_rssi_is_shown_as_unavailable_strength) {
    Rig r;
    RxMeta m = meta_at(r.clock, 1000, -51);
    m.rssi_valid = false;
    m.rssi_dbm = -51; // the adapter said "do not trust this"
    if (!r.feed(c_, "beacon_wpa3_sae_pmf_required", m)) return;
    const Advice a = r.advice();
    CHECK(a.signal.available);
    CHECK(!a.signal.rssi_valid);
    CHECK_EQ(a.signal.rssi_dbm, 0);
    CHECK_EQ(a.mood, Mood::VeryGood); // RSSI validity is not a security fact
}

GUARDIAN_CASE(signal_interval_survives_a_rejected_older_sample_and_resets_across_a_reboot) {
    Rig r;
    if (!r.feed(c_, "deauth_reason7", meta_at(r.clock, 1000))) return;
    r.clock.set(3000);
    if (!r.feed(c_, "deauth_reason7", meta_at(r.clock, 3000))) return;
    if (!r.feed(c_, "deauth_reason7", meta_at(r.clock, 2000))) return; // queue reordering: rejected as older
    Advice a = r.advice();
    CHECK(a.signal.interval_known);
    CHECK_EQ(a.signal.interval_ms, Millis{2000});
    CHECK_EQ(r.core.snapshot().rejected.older, std::uint32_t{1});
    r.clock.reboot();
    r.clock.set(500);
    a = r.advice();
    CHECK(!a.signal.available); // another timebase: no live signal
    CHECK(!a.signal.interval_known);
    if (!r.feed(c_, "deauth_reason7", meta_at(r.clock, 500))) return;
    a = r.advice();
    CHECK(a.signal.available);
    CHECK(!a.signal.interval_known); // the pre-reboot sample is not comparable
}

// ---- evidence state first, one next step ---------------------------------------------------
GUARDIAN_CASE(checking_says_no_sample_yet_keep_listening_and_claims_nothing) {
    Rig r;
    const Advice a = r.advice();
    CHECK_EQ(a.coverage, Coverage::Checking);
    CHECK_EQ(a.mood, Mood::Unknown);
    CHECK(a.count >= 1);
    CHECK_EQ(a.items[0], AdviceId::NoSampleYet);
    CHECK_EQ(a.next_step, NextStep::KeepListening);
    CHECK(no_incident_items(a));
    CHECK(no_grade_items(a));
    CHECK(!a.signal.available);
}

GUARDIAN_CASE(stale_says_no_fresh_data_and_points_at_this_device_not_the_network) {
    Rig r;
    if (!r.feed(c_, "beacon_wpa3_sae_pmf_required", meta_at(r.clock, 1000))) return;
    r.clock.set(31000);
    const Advice a = r.advice();
    CHECK_EQ(a.coverage, Coverage::Stale);
    CHECK_EQ(a.mood, Mood::Unknown); // the old VeryGood is not current
    CHECK_EQ(a.items[0], AdviceId::NoFreshData);
    CHECK(!a.has(AdviceId::Wpa3Strong));
    CHECK_EQ(a.next_step, NextStep::CheckDeviceListening);
    CHECK(no_incident_items(a));
    CHECK_EQ(a.age_ms, Millis{30000});
}

GUARDIAN_CASE(a_snapshot_that_still_carries_a_grade_while_not_fresh_shows_no_grade) {
    // Core blanks the Assessment when stale/degraded; a hand-assembled or future Snapshot might not.
    for (Coverage c : {Coverage::Checking, Coverage::Stale, Coverage::Degraded}) {
        Snapshot s = fresh(Mood::VeryGood, Finding::StrongSettings);
        s.coverage = c;
        s.age_ms = 45000;
        const Advice a = advise(s);
        CHECK_EQ(a.mood, Mood::Unknown);
        CHECK_EQ(a.reason, Finding::Unknown);
        CHECK(!a.has(AdviceId::Wpa3Strong));
        CHECK(!a.has(AdviceId::PasswordStrengthNotMeasured));
        CHECK(a.next_step == NextStep::KeepListening || a.next_step == NextStep::CheckDeviceListening);
        Snapshot u = fresh(Mood::Unknown, Finding::Legacy, Unrated::UnknownOption, Mode::Wpa1);
        u.settings.legacy_risk = true;
        u.coverage = c;
        const Advice b = advise(u);
        CHECK_EQ(b.unrated, Unrated::None);
        CHECK(!b.has(AdviceId::LegacyWpaTkip)); // not fresh: nothing about the settings is said
        CHECK(!b.has(AdviceId::UnknownOptionAdvertised));
    }
}

GUARDIAN_CASE(degraded_listening_is_a_fact_about_this_device) {
    Rig r;
    if (!r.feed(c_, "beacon_wpa3_sae_pmf_required", meta_at(r.clock, 1000))) return;
    CoverageReport c{};
    c.sampled_at = Instant{r.clock.epoch(), 1000, true};
    c.channel = 6;
    c.window_ms = 10000;
    c.listened_ms = 10000;
    c.dropped_in_window = 3;
    c.passive_receive = Support::Unsupported;
    r.core.coverage(c);
    r.clock.set(1500);
    const Advice a = r.advice();
    CHECK_EQ(a.coverage, Coverage::Degraded);
    CHECK_EQ(a.mood, Mood::Unknown);
    CHECK_EQ(a.items[0], AdviceId::ListeningDegraded);
    CHECK_EQ(a.next_step, NextStep::CheckDeviceListening);
    CHECK(no_incident_items(a));
    CHECK(no_grade_items(a));
}

GUARDIAN_CASE(historical_record_is_last_known_from_an_earlier_boot_and_waits_for_a_live_sample) {
    Rig r;
    if (!r.feed(c_, "beacon_wpa3_sae_pmf_required", meta_at(r.clock, 1000))) return;
    r.clock.reboot();
    r.core.select(home()); // the application re-selects after boot (G05 decision)
    // Re-inject the pre-reboot record as the restored "last known" reading.
    FakeClock old_clock{1000, epoch_of(7, 1)};
    Fixture f;
    if (!load(c_, "beacon_wpa3_sae_pmf_required", f)) return;
    const RxMeta m = meta_at(old_clock, 1000);
    r.core.security(observe_security(parser.parse(FrameSpan{f.bytes.data(), static_cast<std::uint16_t>(f.bytes.size()), false}, m), m));
    r.clock.set(2000);
    const Advice a = r.advice();
    CHECK(a.historical);
    CHECK_EQ(a.mood, Mood::Unknown);
    CHECK_EQ(a.age_ms, Millis{0}); // unknown across timebases, by design
    CHECK(a.has(AdviceId::LastKnownFromEarlierBoot));
    CHECK_EQ(a.next_step, NextStep::WaitForLiveSample);
    CHECK(no_grade_items(a));
}

// ---- what the advertised settings mean ----------------------------------------------------
GUARDIAN_CASE(each_rated_fixture_gets_its_explanation_and_exactly_one_next_step) {
    struct Row { const char* fixture; Mood mood; AdviceId item; NextStep step; } rows[] = {
        {"beacon_wpa3_sae_pmf_required", Mood::VeryGood, AdviceId::Wpa3Strong, NextStep::KeepRouterUpdated},
        {"beacon_rsn_pmkid_group_mgmt", Mood::VeryGood, AdviceId::Wpa3Strong, NextStep::KeepRouterUpdated},
        {"beacon_wpa2_ccmp_pmf_optional", Mood::Medium, AdviceId::PmfNotRequired, NextStep::RequirePmfOrEnableWpa3},
        {"probe_response_wpa2", Mood::Medium, AdviceId::PmfNotRequired, NextStep::RequirePmfOrEnableWpa3},
        {"beacon_wpa2_mixed_tkip", Mood::Bad, AdviceId::LegacyWpaTkip, NextStep::RemoveWpaTkip},
        {"beacon_wpa1_tkip_vendor", Mood::Bad, AdviceId::LegacyWpaTkip, NextStep::RemoveWpaTkip},
        {"beacon_wpa_and_rsn_mixed", Mood::Bad, AdviceId::LegacyWpaTkip, NextStep::RemoveWpaTkip},
        {"beacon_open", Mood::Horrible, AdviceId::OpenUnencrypted, NextStep::EnableWpa2AesOrWpa3},
    };
    for (const Row& row : rows) {
        Rig r;
        if (!r.feed(c_, row.fixture, meta_at(r.clock, 1000))) continue;
        r.clock.set(1500);
        const Advice a = r.advice();
        const std::string who = row.fixture;
        if (a.coverage != Coverage::Fresh) CHECK_FAIL(who + ": not fresh");
        if (a.mood != row.mood) CHECK_FAIL(who + ": unexpected mood " + std::to_string(static_cast<int>(a.mood)));
        if (!a.has(row.item)) CHECK_FAIL(who + ": missing explanation item " + std::to_string(static_cast<int>(row.item)));
        if (a.next_step != row.step) CHECK_FAIL(who + ": next step " + std::to_string(static_cast<int>(a.next_step)));
        if (a.next_step == NextStep::None) CHECK_FAIL(who + ": no next step");
        if (a.count > Advice::max_items) CHECK_FAIL(who + ": too many items");
        if (a.has(AdviceId::NoSampleYet) || a.has(AdviceId::NoFreshData) || a.has(AdviceId::ListeningDegraded))
            CHECK_FAIL(who + ": fresh evidence carries a no-data item");
        // every rated advertisement is reminded that the signal is local and the password is unseen
        if (!a.has(AdviceId::PasswordStrengthNotMeasured)) CHECK_FAIL(who + ": password-not-measured missing");
        CHECK_EQ(a.password_strength, Verification::NotMeasured);
    }
}

GUARDIAN_CASE(hand_built_rows_good_transition_wep_and_sae_pmf_optional_are_explained) {
    Advice a = advise(fresh(Mood::Good, Finding::Wpa2PmfRequired, Unrated::None, Mode::Wpa2Personal));
    CHECK(a.has(AdviceId::Wpa2AesPmfRequired));
    CHECK_EQ(a.next_step, NextStep::ConsiderWpa3);
    a = advise(fresh(Mood::Medium, Finding::CompatibilityMode, Unrated::None, Mode::Transition));
    CHECK(a.has(AdviceId::TransitionIsCompatibility));
    CHECK(!a.has(AdviceId::LegacyWpaTkip)); // transition is not broken
    CHECK_EQ(a.next_step, NextStep::MoveToWpa3OnlyWhenReady);
    a = advise(fresh(Mood::Horrible, Finding::Legacy, Unrated::None, Mode::Wep));
    CHECK(a.has(AdviceId::WepIsBroken));
    CHECK(!a.has(AdviceId::OpenUnencrypted));
    CHECK_EQ(a.next_step, NextStep::ReplaceWep);
    // SAE-only with PMF optional: unrated Unspecified with the PMF limitation named (G05 row).
    Snapshot s = fresh(Mood::Unknown, Finding::PmfNotRequired, Unrated::Unspecified, Mode::Wpa3Personal);
    s.settings.pmf = Pmf::Optional;
    a = advise(s);
    CHECK(a.has(AdviceId::OutsideDocumentedRows));
    CHECK(a.has(AdviceId::PmfNotRequired));
    CHECK_EQ(a.next_step, NextStep::NotRatedByPolicy);
    CHECK_EQ(a.mood, Mood::Unknown);
}

GUARDIAN_CASE(unrated_reasons_are_explained_and_never_read_as_open_or_wep) {
    struct Row { const char* fixture; Unrated unrated; AdviceId item; NextStep step; } rows[] = {
        {"beacon_owe_transition", Unrated::Owe, AdviceId::OweNotPlainOpen, NextStep::NotRatedByPolicy},
        {"beacon_rsn_minimal_version_only", Unrated::Enterprise, AdviceId::EnterpriseNotRated, NextStep::NotRatedByPolicy},
        {"beacon_rsn_unknown_akm", Unrated::UnknownOption, AdviceId::UnknownOptionAdvertised, NextStep::NotRatedByPolicy},
        {"beacon_rsn_truncated_ie", Unrated::Incomplete, AdviceId::IncompleteAdvertisement, NextStep::WaitForAnotherSample},
        {"beacon_rsn_pmf_inconsistent", Unrated::Incomplete, AdviceId::IncompleteAdvertisement, NextStep::WaitForAnotherSample},
        {"beacon_rsn_duplicate_conflict", Unrated::Incomplete, AdviceId::IncompleteAdvertisement, NextStep::WaitForAnotherSample},
    };
    for (const Row& row : rows) {
        Rig r;
        if (!r.feed(c_, row.fixture, meta_at(r.clock, 1000))) continue;
        r.clock.set(1500);
        const Advice a = r.advice();
        const std::string who = row.fixture;
        if (a.coverage != Coverage::Fresh) CHECK_FAIL(who + ": not fresh");
        if (a.mood != Mood::Unknown) CHECK_FAIL(who + ": graded");
        if (a.unrated != row.unrated) CHECK_FAIL(who + ": unexpected unrated reason " + std::to_string(static_cast<int>(a.unrated)));
        if (!a.has(row.item)) CHECK_FAIL(who + ": missing item " + std::to_string(static_cast<int>(row.item)));
        if (a.next_step != row.step) CHECK_FAIL(who + ": next step " + std::to_string(static_cast<int>(a.next_step)));
        if (a.has(AdviceId::OpenUnencrypted) || a.has(AdviceId::WepIsBroken)) CHECK_FAIL(who + ": read as open/WEP");
        if (a.has(AdviceId::Wpa3Strong)) CHECK_FAIL(who + ": read as strong");
    }
    // Receive-unverified: the adapter could not vouch for the bytes.
    Rig r;
    RxMeta m = meta_at(r.clock, 1000);
    m.status = RxStatus::Unknown;
    if (!r.feed(c_, "beacon_wpa3_sae_pmf_required", m)) return;
    const Advice a = r.advice();
    CHECK_EQ(a.unrated, Unrated::ReceiveUnverified);
    CHECK(a.has(AdviceId::ReceiveUnverified));
    CHECK(!a.has(AdviceId::Wpa3Strong));
    CHECK_EQ(a.next_step, NextStep::WaitForAnotherSample);
    // Inconsistent (hand-built, as the G05 policy reports SAE without PMF capability).
    const Advice b = advise(fresh(Mood::Unknown, Finding::Unknown, Unrated::Inconsistent, Mode::Wpa3Personal));
    CHECK(b.has(AdviceId::ContradictoryAdvertisement));
    CHECK_EQ(b.next_step, NextStep::WaitForAnotherSample);
}

GUARDIAN_CASE(a_confirmed_legacy_risk_is_kept_even_when_no_grade_is_possible) {
    // G05: legacy_risk survives an unknown/malformed sibling. The advice keeps the finding visible.
    Snapshot s = fresh(Mood::Unknown, Finding::Legacy, Unrated::UnknownOption, Mode::Wpa1);
    s.settings.legacy_risk = true;
    const Advice a = advise(s);
    CHECK(a.has(AdviceId::UnknownOptionAdvertised));
    CHECK(a.has(AdviceId::LegacyWpaTkip));
    CHECK_EQ(a.mood, Mood::Unknown);
    CHECK_EQ(a.next_step, NextStep::RemoveWpaTkip); // the one thing the owner can act on from this evidence
    // Without the confirmed risk, nothing legacy is said.
    s.settings.legacy_risk = false;
    s.settings.reason = Finding::Unknown;
    s.settings.mode = Mode::Unknown;
    CHECK(!advise(s).has(AdviceId::LegacyWpaTkip));
}

GUARDIAN_CASE(hidden_ssid_gets_no_credit_and_rates_the_same_as_the_visible_network) {
    Rig visible;
    if (!visible.feed(c_, "beacon_wpa2_ccmp_pmf_optional", meta_at(visible.clock, 1000))) return;
    Rig hidden{hidden_home()};
    if (!hidden.feed(c_, "beacon_hidden_ssid_wpa2", meta_at(hidden.clock, 1000))) return;
    const Advice v = visible.advice();
    const Advice h = hidden.advice();
    CHECK_EQ(h.coverage, Coverage::Fresh);
    CHECK_EQ(h.mood, v.mood);
    CHECK_EQ(h.mood, Mood::Medium);
    CHECK_EQ(h.reason, v.reason);
    CHECK_EQ(h.next_step, v.next_step);
    CHECK(h.has(AdviceId::HiddenSsidOrMacFilteringNoCredit));
    CHECK(!v.has(AdviceId::HiddenSsidOrMacFilteringNoCredit));
    CHECK(h.has(AdviceId::PmfNotRequired));
}

// ---- owner checks, password, connection --------------------------------------------------
GUARDIAN_CASE(owner_checks_are_the_seven_ledger_items_all_unverified_and_never_change_the_mood) {
    const OwnerCheckId order[] = {OwnerCheckId::LongUniqueWifiPassword, OwnerCheckId::UniqueRouterAdminCredentials,
                                  OwnerCheckId::SupportedFirmwareWithUpdates, OwnerCheckId::WpsOffUnlessNeeded,
                                  OwnerCheckId::RemoteAdministrationOff, OwnerCheckId::UpnpOffUnlessNeeded,
                                  OwnerCheckId::GuestAndIotSeparation};
    for (Mood m : {Mood::Unknown, Mood::VeryGood, Mood::Horrible}) {
        const Advice a = advise(fresh(m, Finding::Unknown));
        CHECK_EQ(a.mood, m);
        for (std::size_t i = 0; i < a.owner_checks.size(); ++i) {
            CHECK_EQ(a.owner_checks[i].id, order[i]);
            CHECK_EQ(a.owner_checks[i].status, Verification::Unverified);
        }
        CHECK_EQ(a.password_strength, Verification::NotMeasured);
        CHECK_EQ(a.transmitter_identity, Verification::NotMeasured);
    }
    // The texts say what cannot be proven from the air.
    CHECK(std::strstr(advice_text(OwnerCheckId::GuestAndIotSeparation), "guest") != nullptr);
    CHECK(std::strstr(advice_text(OwnerCheckId::WpsOffUnlessNeeded), "WPS") != nullptr);
    // Even an empty Snapshot lists them, unverified.
    const Advice e = advise(Snapshot{});
    CHECK_EQ(e.owner_checks[0].status, Verification::Unverified);
    CHECK_EQ(e.owner_checks[6].id, OwnerCheckId::GuestAndIotSeparation);
}

GUARDIAN_CASE(connection_health_is_not_measured_in_passive_v1_and_a_failed_endpoint_is_not_an_attack) {
    Rig r;
    if (!r.feed(c_, "beacon_wpa3_sae_pmf_required", meta_at(r.clock, 1000))) return;
    r.clock.set(1500);
    const Advice passive = r.advice();
    CHECK_EQ(passive.connection_health, Verification::NotMeasured);
    CHECK(passive.has(AdviceId::ConnectionNotMeasured));
    CHECK(!passive.has(AdviceId::EndpointFailureIsNotWifiFailure));
    CHECK_EQ(passive.connection.measured, Support::Unsupported);
    // A later probe adapter reports every endpoint failed: a fact about those endpoints.
    ConnectivityResult failed{};
    failed.measured = Support::Supported;
    failed.sampled_at = Instant{r.clock.epoch(), 1400, true};
    failed.gateway = EndpointState::Failed;
    failed.dns = EndpointState::TimedOut;
    failed.https = EndpointState::Failed;
    const Advice probed = r.advice(failed);
    CHECK_EQ(probed.connection_health, Verification::Observed);
    CHECK(probed.has(AdviceId::EndpointFailureIsNotWifiFailure));
    CHECK(!probed.has(AdviceId::ConnectionNotMeasured));
    CHECK_EQ(probed.mood, passive.mood);               // VeryGood stays VeryGood
    CHECK_EQ(probed.next_step, passive.next_step);     // the step is about settings, not the endpoints
    CHECK(no_incident_items(probed));
    CHECK_EQ(probed.connection.gateway, EndpointState::Failed);
    // Reached endpoints add no security credit either.
    failed.gateway = failed.dns = failed.https = EndpointState::Reached;
    const Advice reached = r.advice(failed);
    CHECK_EQ(reached.mood, passive.mood);
    CHECK(!reached.has(AdviceId::EndpointFailureIsNotWifiFailure));
    // "measured" claimed but nothing sampled: still not measured.
    ConnectivityResult half{};
    half.measured = Support::Supported;
    CHECK_EQ(r.advice(half).connection_health, Verification::NotMeasured);
    ConnectivityResult unknown{};
    unknown.measured = Support::Unknown;
    unknown.gateway = EndpointState::Failed;
    CHECK_EQ(r.advice(unknown).connection_health, Verification::NotMeasured); // Unknown is never Observed
}

GUARDIAN_CASE(absent_sensor_data_or_lost_internet_cannot_imply_an_rf_attack_or_password_strength) {
    ConnectivityResult lost{};
    lost.measured = Support::Supported;
    lost.sampled_at = Instant{epoch_of(7, 1), 1400, true};
    lost.gateway = EndpointState::Reached;
    lost.dns = EndpointState::Failed;
    lost.https = EndpointState::TimedOut;
    // Nothing selected, nothing received, Internet gone.
    FakeClock clock;
    Core core{clock, profiles::all_2g4_channels(), Origin::Imported};
    Advice a = advise(core.snapshot(), lost);
    CHECK_EQ(a.mood, Mood::Unknown);
    CHECK(no_incident_items(a));
    CHECK(a.has(AdviceId::EndpointFailureIsNotWifiFailure));
    CHECK_EQ(a.password_strength, Verification::NotMeasured);
    CHECK_EQ(a.transmitter_identity, Verification::NotMeasured);
    // Stale evidence plus Internet gone: still no incident and no mood.
    Rig r;
    if (!r.feed(c_, "beacon_wpa3_sae_pmf_required", meta_at(r.clock, 1000))) return;
    r.clock.set(45000);
    a = r.advice(lost);
    CHECK_EQ(a.coverage, Coverage::Stale);
    CHECK_EQ(a.mood, Mood::Unknown);
    CHECK_EQ(a.items[0], AdviceId::NoFreshData);
    CHECK(a.has(AdviceId::EndpointFailureIsNotWifiFailure));
    CHECK(no_incident_items(a));
    CHECK_EQ(a.next_step, NextStep::CheckDeviceListening);
    // Degraded listening plus Internet gone: the same. Degraded qualifies fresh
    // evidence only (stale evidence is always No fresh data), so renew it first.
    if (!r.feed(c_, "beacon_wpa3_sae_pmf_required", meta_at(r.clock, 45000))) return;
    CoverageReport c{};
    c.sampled_at = Instant{r.clock.epoch(), 45000, true};
    c.channel = 0; // not tuned
    c.window_ms = 10000;
    c.passive_receive = Support::Unsupported;
    r.core.coverage(c);
    a = r.advice(lost);
    CHECK_EQ(a.coverage, Coverage::Degraded);
    CHECK(no_incident_items(a));
    CHECK_EQ(a.mood, Mood::Unknown);
}

// ---- incidents: observations with uncertainty ------------------------------------------------
GUARDIAN_CASE(incidents_are_reported_as_observed_traffic_with_uncertainty_and_take_the_next_step) {
    struct Row { IncidentKind kind; AdviceId item; NextStep step; } rows[] = {
        {IncidentKind::DisconnectBurst, AdviceId::DisconnectTrafficObserved, NextStep::CheckWhetherDevicesDropped},
        {IncidentKind::UnexpectedAp, AdviceId::UnexpectedApObserved, NextStep::CheckUnapprovedAp},
        {IncidentKind::SettingsChanged, AdviceId::SettingsChangeObserved, NextStep::CheckRouterSettings},
    };
    for (const Row& row : rows) {
        Rig r;
        if (!r.feed(c_, "beacon_wpa3_sae_pmf_required", meta_at(r.clock, 1000))) continue;
        IncidentObservation i{};
        i.affected = home();
        i.acquired = Instant{r.clock.epoch(), 1200, true};
        i.origin = Origin::Imported;
        i.kind = row.kind;
        i.count = 20;
        i.window_ms = 10000;
        i.threshold = 20;
        r.clock.set(1200); // Core rejects an incident acquired after its clock's now (G05)
        r.core.incident(i);
        r.clock.set(1500);
        const Advice a = r.advice();
        const std::string who = std::to_string(static_cast<int>(row.kind));
        if (a.mood != Mood::VeryGood) CHECK_FAIL("kind " + who + ": an incident changed the grade");
        if (!a.has(row.item)) CHECK_FAIL("kind " + who + ": incident item missing");
        if (a.next_step != row.step) CHECK_FAIL("kind " + who + ": next step " + std::to_string(static_cast<int>(a.next_step)));
        if (a.items[0] != row.item) CHECK_FAIL("kind " + who + ": a current incident is not the first item");
        CHECK_EQ(a.transmitter_identity, Verification::NotMeasured); // never "who sent it"
        CHECK(a.has(AdviceId::Wpa3Strong));                           // the settings explanation stays
        // 60 s later the incident is no longer current: the settings step returns.
        r.clock.set(1200 + Core::incident_ms);
        const Advice later = r.advice();
        if (later.has(row.item)) CHECK_FAIL("kind " + who + ": expired incident still advised");
        if (later.coverage == Coverage::Fresh) CHECK_FAIL("kind " + who + ": evidence should be stale by now");
    }
}

GUARDIAN_CASE(two_current_incidents_are_both_listed_and_the_disconnect_step_comes_first) {
    Rig r;
    if (!r.feed(c_, "beacon_wpa2_ccmp_pmf_optional", meta_at(r.clock, 1000))) return;
    r.clock.set(1200);
    for (IncidentKind k : {IncidentKind::SettingsChanged, IncidentKind::DisconnectBurst}) {
        IncidentObservation i{};
        i.affected = home();
        i.acquired = Instant{r.clock.epoch(), 1200, true};
        i.origin = Origin::Imported;
        i.kind = k;
        i.count = 2;
        i.window_ms = 10000;
        i.threshold = 2;
        r.core.incident(i);
    }
    r.clock.set(1500);
    const Advice a = r.advice();
    CHECK(a.has(AdviceId::DisconnectTrafficObserved));
    CHECK(a.has(AdviceId::SettingsChangeObserved));
    CHECK_EQ(a.next_step, NextStep::CheckWhetherDevicesDropped);
    CHECK_EQ(a.mood, Mood::Medium);
    CHECK(a.has(AdviceId::PmfNotRequired));
    CHECK(a.count <= Advice::max_items);
    // No duplicates in the list.
    for (std::uint8_t i = 0; i < a.count; ++i)
        for (std::uint8_t j = static_cast<std::uint8_t>(i + 1); j < a.count; ++j)
            if (a.items[i] == a.items[j]) CHECK_FAIL("duplicate item " + std::to_string(static_cast<int>(a.items[i])));
}

GUARDIAN_CASE(items_are_bounded_ordered_and_free_of_duplicates_on_the_busiest_snapshot) {
    // Everything at once: hidden network, legacy risk under an unknown option, three incidents, failed probes.
    Snapshot s = fresh(Mood::Unknown, Finding::Legacy, Unrated::UnknownOption, Mode::Wpa1);
    s.selected = hidden_home();
    s.last_security.network = hidden_home();
    s.last_security.ssid_kind = SsidKind::Hidden;
    s.settings.legacy_risk = true;
    s.has_signal = true;
    s.last_signal.rssi_valid = true;
    s.last_signal.rssi = -40;
    s.signal_age_ms = 300;
    for (auto& flag : s.incidents) flag = true;
    ConnectivityResult failed{};
    failed.measured = Support::Supported;
    failed.sampled_at = Instant{epoch_of(7, 1), 1400, true};
    failed.gateway = EndpointState::Failed;
    const Advice a = advise(s, failed);
    CHECK(a.count <= Advice::max_items);
    CHECK(a.count >= 6);
    for (std::uint8_t i = 0; i < a.count; ++i) {
        if (a.items[i] == AdviceId::None || a.items[i] == AdviceId::Count) CHECK_FAIL("placeholder id in the list");
        for (std::uint8_t j = static_cast<std::uint8_t>(i + 1); j < a.count; ++j)
            if (a.items[i] == a.items[j]) CHECK_FAIL("duplicate item " + std::to_string(static_cast<int>(a.items[i])));
    }
    for (std::uint8_t i = a.count; i < Advice::max_items; ++i) CHECK_EQ(a.items[i], AdviceId::None);
    // Current incidents lead, then why there is no grade, then the kept legacy risk.
    CHECK_EQ(a.items[0], AdviceId::DisconnectTrafficObserved);
    CHECK(a.has(AdviceId::UnknownOptionAdvertised));
    CHECK(a.has(AdviceId::LegacyWpaTkip));
    CHECK(a.has(AdviceId::HiddenSsidOrMacFilteringNoCredit));
    CHECK_EQ(a.next_step, NextStep::CheckWhetherDevicesDropped);
    CHECK_EQ(a.mood, Mood::Unknown);
    CHECK_EQ(a.signal.rssi_dbm, -40);
}

GUARDIAN_CASE(demo_and_imported_origins_are_advised_like_live_but_never_hide_their_origin) {
    // advise() does not label origin (the presenter does); it must not refuse or alter policy by origin.
    for (Origin o : {Origin::LiveRadio, Origin::Imported, Origin::Demo}) {
        Snapshot s = fresh(Mood::Good, Finding::Wpa2PmfRequired, Unrated::None, Mode::Wpa2Personal);
        s.origin = o;
        const Advice a = advise(s);
        CHECK_EQ(a.mood, Mood::Good);
        CHECK(a.has(AdviceId::Wpa2AesPmfRequired));
        CHECK_EQ(a.next_step, NextStep::ConsiderWpa3);
    }
}


GUARDIAN_CASE(review_open_wifi_advice_preserves_application_encryption_caveat) {
    const std::string text = advice_text(AdviceId::OpenUnencrypted);
    CHECK(text.find("HTTPS") != std::string::npos);
    CHECK(text.find("Anyone nearby can read this traffic") == std::string::npos);
}


GUARDIAN_CASE(g09_absent_ssid_does_not_alias_hidden_selection) {
    Rig r(hidden_home()); Fixture f;
    if (!load(c_, "beacon_wpa3_sae_pmf_required", f)) return;
    CHECK_EQ(f.bytes[36], 0u);
    f.bytes.erase(f.bytes.begin()+36, f.bytes.begin()+38+f.bytes[37]);
    const auto m=meta_at(r.clock,1000);const auto p=parser.parse({f.bytes.data(),static_cast<std::uint16_t>(f.bytes.size()),false},m);
    CHECK_EQ(p.ssid_kind,SsidKind::Absent); r.core.security(observe_security(p,m));
    CHECK(!r.core.snapshot().has_security);
    Candidate candidate;CHECK(!candidate_from(p,m,candidate));
}
GUARDIAN_CASE(g09_valid_wep_cipher_survives_malformed_sibling_into_advice) {
    Rig r; Fixture f;if (!load(c_,"beacon_wpa3_sae_pmf_required",f)) return;
    for (std::size_t pos=36;pos+2<=f.bytes.size();pos+=2+f.bytes[pos+1]) {
        if(f.bytes[pos]==48){f.bytes[pos+7]=1;break;}
    }
    f.bytes.insert(f.bytes.end(),{221,5,0,0x50,0xf2,1,0});
    const auto m=meta_at(r.clock,1000);const auto p=parser.parse({f.bytes.data(),static_cast<std::uint16_t>(f.bytes.size()),false},m);
    CHECK_EQ(p.status,ParseStatus::Malformed);r.core.security(observe_security(p,m));
    const auto a=r.advice();CHECK(a.has(AdviceId::WepIsBroken));CHECK_EQ(a.next_step,NextStep::ReplaceWep);
}
GUARDIAN_CASE(g09_open_owe_side_does_not_claim_encryption) {
    Rig r;Fixture f;if(!load(c_,"beacon_owe_transition",f))return;
    f.bytes[34] &= static_cast<std::uint8_t>(~0x10u);
    for(std::size_t pos=36;pos+2<=f.bytes.size();pos+=2+f.bytes[pos+1]) {
        if(f.bytes[pos]==48){const auto end=pos+2+f.bytes[pos+1];f.bytes.erase(f.bytes.begin()+static_cast<std::ptrdiff_t>(pos),f.bytes.begin()+static_cast<std::ptrdiff_t>(end));break;}
    }
    const auto m=meta_at(r.clock,1000);const auto p=parser.parse({f.bytes.data(),static_cast<std::uint16_t>(f.bytes.size()),false},m);
    CHECK_EQ(p.status,ParseStatus::Complete);r.core.security(observe_security(p,m));
    const auto a=r.advice();bool describes_open=false;
    for(std::size_t i=0;i<a.count;++i){const std::string text=advice_text(a.items[i]);if(text.find("open side")!=std::string::npos)describes_open=true;}
    CHECK(describes_open);
}

GUARDIAN_CASE(g09_privacy_set_transition_without_rsn_does_not_prove_owe) {
    Rig r;Fixture f;if(!load(c_,"beacon_owe_transition",f))return;
    for(std::size_t pos=36;pos+2<=f.bytes.size();pos+=2+f.bytes[pos+1]) {
        if(f.bytes[pos]==48){const auto end=pos+2+f.bytes[pos+1];f.bytes.erase(f.bytes.begin()+static_cast<std::ptrdiff_t>(pos),f.bytes.begin()+static_cast<std::ptrdiff_t>(end));break;}
    }
    const auto m=meta_at(r.clock,1000);const auto p=parser.parse({f.bytes.data(),static_cast<std::uint16_t>(f.bytes.size()),false},m);
    CHECK_EQ(p.status,ParseStatus::Complete);r.core.security(observe_security(p,m));
    CHECK_EQ(r.core.snapshot().settings.unrated,Unrated::Inconsistent);
    CHECK(!r.advice().has(AdviceId::OweNotPlainOpen));
}

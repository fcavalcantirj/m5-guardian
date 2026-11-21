// G08: headless interaction and fixture-source checks. Fixtures remain Imported.
#include "check.hpp"
#include "fixtures.hpp"
#include "guardian/presenter.hpp"
#include "guardian/rating.hpp"
#include "guardian/security_parser.hpp"
#include <cstring>
#include <string>
#include <vector>

using namespace guardian;
namespace {
Instant at(Millis ms = 1000, std::uint64_t boot = 1) {
    TimeEpoch e{}; e.source_id[0] = 7; e.boot_id = boot;
    return {e, ms, true};
}
Network home(std::uint8_t tail = 0x55) {
    Network n{}; n.bssid = {2, 0x11, 0x22, 0x33, 0x44, tail};
    n.ssid_size = 4; n.ssid = {'h','o','m','e'}; return n;
}
Snapshot fresh() {
    Snapshot s{}; s.selected = home(); s.coverage = Coverage::Fresh;
    s.has_security = true; s.last_security.network = home();
    s.last_security.acquired = at(); s.last_security.ssid_kind = SsidKind::Present;
    s.settings = {Mood::VeryGood, Finding::StrongSettings}; return s;
}
Candidate candidate(std::uint8_t tail = 0x55) {
    Candidate c{}; c.network = home(tail); c.seen = at();
    c.ssid_kind = SsidKind::Present; c.channel = 6; c.settings_complete = true;
    c.ds_channel_present = true; c.ds_channel = 11; return c;
}
DisplayCapabilities display() {
    return {Support::Supported, 240, 32, PixelFormat::Rgb565, Support::Supported};
}
ParseResult fixture(check::Case& c_, const char* name, RxMeta& meta) {
    fixtures::Fixture f; std::string error;
    if (!fixtures::load(name, f, error)) { CHECK_FAIL(error); return {}; }
    meta.acquired = at(); meta.origin = Origin::Imported; meta.channel = 6;
    meta.status = RxStatus::Ok; meta.rssi_dbm = -55; meta.rssi_valid = true;
    return SecurityFrameParser{}.parse({f.bytes.data(), static_cast<std::uint16_t>(f.bytes.size()), false}, meta);
}
class FakeStore final : public SelectionStore {
public:
    PersistedSelection record{}; bool exists{}, fail{};
    bool load(PersistedSelection& out) const override { if (!exists) return false; out = record; return true; }
    bool save(const PersistedSelection& in) override { if (fail || !in.valid()) return false; record = in; exists = true; return true; }
};
}

GUARDIAN_CASE(labels_preserve_identity_and_bound_untrusted_lengths) {
    auto n = home(); n.ssid = {'a',0,0x1b,0xff,'?'}; n.ssid_size = 5;
    const auto original = n;
    auto label = ssid_label(n);
    CHECK_EQ(std::string(label.c_str()), "a????"); CHECK(label.altered); CHECK(!label.exact);
    CHECK(n == original);
    n.ssid_size = 255; label = ssid_label(n);
    CHECK(label.invalid); CHECK_EQ(label.length, 32); CHECK_EQ(label.text[32], '\0');
    n.ssid_size = 0;
    CHECK(ssid_label(n).hidden); CHECK(ssid_label(n, SsidKind::Absent).absent);
    CHECK_EQ(std::string(mac_text(home().bssid).c_str()), "02:11:22:33:44:55");
    n.ssid.fill('z'); n.ssid_size = 32; CHECK(ssid_label(n).exact);
}

GUARDIAN_CASE(all_static_texts_are_defined) {
    for (auto m : {Mood::Unknown, Mood::VeryGood, Mood::Good, Mood::Medium, Mood::Bad, Mood::Horrible}) CHECK(std::strlen(mood_text(m)) > 0);
    CHECK_EQ(std::string(mood_text(Mood::Unknown)), "Not rated");
    CHECK_EQ(std::string(view_mode_text(ViewMode::Demo)), "DEMO");
    CHECK(std::strlen(mode_text(Mode::Enterprise)) > 0);
    CHECK(std::strlen(cipher_text(Cipher::Gcmp)) > 0);
    CHECK(std::strlen(pmf_text(Pmf::Required)) > 0);
    CHECK(std::strlen(coverage_text(Coverage::Degraded)) > 0);
    CHECK(std::strlen(overlay_text(Overlay::Unsupported)) > 0);
    CHECK(std::strlen(screen_text(Screen::Picker)) > 0);
    CHECK(std::strlen(incident_text(IncidentKind::UnexpectedAp)) > 0);
}

GUARDIAN_CASE(face_details_actions_and_headless_pages) {
    Presenter p({}); p.update(fresh(), at(2500));
    CHECK_EQ(p.view().face, Mood::VeryGood); CHECK(!p.view().animate);
    CHECK(p.handle(Action::Primary, at(2500))); CHECK_EQ(p.screen(), Screen::Details);
    CHECK_EQ(p.details().page, DetailsPage::Settings);
    CHECK(p.handle(Action::Primary, at(2500))); CHECK_EQ(p.details().page, DetailsPage::Explanation);
    CHECK_EQ(p.details().item_count, p.details().advice.count);
    CHECK(p.handle(Action::Primary, at(2500))); CHECK_EQ(p.details().page, DetailsPage::SignalAndEvidence);
    CHECK(p.handle(Action::Primary, at(2500))); CHECK_EQ(p.details().page, DetailsPage::OwnerChecks);
    CHECK(p.handle(Action::Primary, at(2500))); CHECK_EQ(p.details().page, DetailsPage::Limits);   // G16J: what it cannot see
    CHECK_EQ(std::string(p.details().title), std::string("What it cannot see"));
    CHECK(p.handle(Action::Primary, at(2500))); CHECK_EQ(p.screen(), Screen::Face);
    CHECK(!p.handle(Action::None, at(2500))); CHECK(!p.handle(Action::Secondary, at(2500)));
    p.handle(Action::Primary, at(2500)); p.handle(Action::Back, at(2500)); CHECK_EQ(p.screen(), Screen::Face);
    p.handle(Action::Primary, at(2500)); p.handle(Action::Secondary, at(2500)); CHECK_EQ(p.screen(), Screen::Face);
}

GUARDIAN_CASE(explanation_pagination_covers_every_item_and_clamps_when_advice_shrinks) {
    Presenter p(display()); auto s = fresh(); p.update(s, at());
    p.handle(Action::Primary, at()); p.handle(Action::Primary, at());
    CHECK_EQ(p.details().rows, 4); CHECK_EQ(p.details().columns, 40);
    std::size_t count = 0;
    while (p.details().page == DetailsPage::Explanation && count < 100) {
        CHECK_EQ(p.details().first_item, count);
        CHECK(p.details().item_count > 0); count += p.details().item_count;
        p.handle(Action::Primary, at());
    }
    CHECK_EQ(count, p.details().advice.count);
    CHECK_EQ(p.details().page, DetailsPage::SignalAndEvidence);
    p.handle(Action::SecondaryLong, at()); CHECK_EQ(p.screen(), Screen::Picker);
    p.handle(Action::SecondaryLong, at()); CHECK_EQ(p.screen(), Screen::Face);
}

GUARDIAN_CASE(picker_duplicate_names_select_exact_identity_and_explicit_baseline) {
    Presenter p({}); p.update(fresh(), at());
    CHECK(p.offer(candidate())); CHECK(p.offer(candidate(0x66)));
    p.handle(Action::SecondaryLong, at());
    CHECK_EQ(p.picker().count, 2); CHECK(p.picker().entries[0].duplicate_name);
    CHECK(p.picker().entries[0].selected); CHECK(p.picker().entries[1].approvable);
    CHECK(std::strlen(p.picker().entries[1].disambiguator.data()) > 0);
    p.handle(Action::Primary, at()); CHECK_EQ(p.picker().cursor, 1);
    p.handle(Action::Secondary, at()); CHECK_EQ(p.screen(), Screen::Face);
    CHECK(p.has_request()); const auto r = p.take_request(); CHECK(!p.has_request());
    CHECK_EQ(r.kind, RequestKind::Select); CHECK(r.ap.network == home(0x66));
    CHECK(r.ap.settings_known); CHECK(r.ap.channel_known); CHECK_EQ(r.ap.channel, 11);
    CHECK_EQ(r.requested_at.at, Millis{1000});
    CHECK_EQ(p.take_request().kind, RequestKind::None);
    CHECK_EQ(std::string(p.view().selected_bssid.c_str()), "02:11:22:33:44:55"); // request is not applied silently
}

// G14 board finding (2026-11-15): in a dense neighbourhood more than 16 BSSIDs
// stay fresh, so a first-come table never admitted the owner's own hotspot.
Candidate other(std::uint8_t n, int rssi) {
    Candidate c{}; c.network.bssid = {2, 0x77, 0, 0, 0, n}; c.network.ssid_size = 2;
    c.network.ssid = {'n', static_cast<std::uint8_t>('a' + n % 26)}; c.seen = at();
    c.ssid_kind = SsidKind::Present; c.channel = 1; c.rssi = static_cast<std::int8_t>(rssi); c.rssi_valid = true; return c;
}
bool listed(const Presenter& p, const Network& n) {
    for (std::uint8_t i = 0; i < p.picker().count; ++i) if (p.picker().entries[i].network == n) return true;
    return false;
}
GUARDIAN_CASE(full_picker_admits_a_stronger_newcomer_and_keeps_the_selection) {
    Presenter p({}); p.update(fresh(), at());
    auto mine = candidate(); mine.rssi = -90; mine.rssi_valid = true; CHECK(p.offer(mine)); // selected, weakest
    for (std::uint8_t i = 0; i < PickerView::capacity - 1; ++i) CHECK(p.offer(other(i, -80 + i)));
    CHECK_EQ(p.picker().count, PickerView::capacity);
    const auto dropped = p.picker().dropped;
    CHECK(!p.offer(other(40, -85)));                      // weaker than every evictable entry: dropped
    CHECK(!listed(p, other(40, -85).network)); CHECK_EQ(p.picker().dropped, dropped + 1);
    auto hotspot = candidate(0x66); hotspot.rssi = -35; hotspot.rssi_valid = true;
    CHECK(p.offer(hotspot));                               // the owner's strong AP gets in
    CHECK(listed(p, hotspot.network));
    CHECK(listed(p, mine.network));                        // the selected network is never evicted
    CHECK(!listed(p, other(0, -80).network));              // the weakest unprotected entry left
    CHECK_EQ(p.picker().count, PickerView::capacity);
}
GUARDIAN_CASE(opening_the_picker_lists_strongest_first_and_keeps_order_while_open) {
    Presenter p({}); p.update(fresh(), at());
    CHECK(p.offer(other(1, -70))); CHECK(p.offer(other(2, -40))); CHECK(p.offer(other(3, -60)));
    p.handle(Action::SecondaryLong, at()); CHECK_EQ(p.screen(), Screen::Picker);
    CHECK(p.picker().entries[0].network == other(2, -40).network);
    CHECK(p.picker().entries[1].network == other(3, -60).network);
    CHECK(p.picker().entries[2].network == other(1, -70).network);
    CHECK_EQ(p.picker().cursor, 0);
    CHECK(p.offer(other(4, -30)));                         // arrives while open: appended, rows do not jump
    CHECK(p.picker().entries[0].network == other(2, -40).network);
    CHECK(p.picker().entries[3].network == other(4, -30).network);
}

GUARDIAN_CASE(approval_revocation_pending_request_and_scope_mismatch) {
    ApprovedScope scope; CHECK(scope.select({home()}));
    Presenter p({}); p.update(fresh(), at(), &scope); CHECK(p.offer(candidate(0x66)));
    p.handle(Action::SecondaryLong, at()); p.handle(Action::PrimaryLong, at());
    CHECK_EQ(p.screen(), Screen::Picker); CHECK(p.has_request());
    p.handle(Action::Secondary, at()); // may not overwrite unconsumed approval
    auto r = p.take_request(); CHECK_EQ(r.kind, RequestKind::Approve); CHECK(scope.approve(r.ap));
    p.update(fresh(), at(), &scope); CHECK(p.picker().entries[0].approved);
    p.handle(Action::PrimaryLong, at()); CHECK_EQ(p.take_request().kind, RequestKind::Revoke);
    auto wrong = fresh(); wrong.selected.ssid[0] = 'x'; p.update(wrong, at(), &scope);
    CHECK(!p.picker().entries[0].approvable); CHECK(!p.picker().entries[0].approved);
    p.handle(Action::PrimaryLong, at()); CHECK(!p.has_request());
}

GUARDIAN_CASE(display_label_collisions_do_not_approve_other_ssid_bytes) {
    Presenter p({}); auto s = fresh(); s.selected.ssid[0] = 0; p.update(s, at());
    auto c = candidate(0x66); c.network.ssid[0] = 0xff; CHECK(p.offer(c));
    CHECK_EQ(std::string(p.view().selected_label.c_str()), std::string(p.picker().entries[0].label.c_str()));
    CHECK(!p.picker().entries[0].approvable);
    p.handle(Action::SecondaryLong, at()); p.handle(Action::PrimaryLong, at()); CHECK(!p.has_request());
}

GUARDIAN_CASE(picker_rejects_origin_time_identity_and_expires_at_boundary) {
    Presenter p({}); p.update(fresh(), at()); auto c = candidate();
    c.origin = Origin::Demo; CHECK(!p.offer(c)); c.origin = Origin::Imported; CHECK(!p.offer(c));
    CHECK_EQ(p.picker().rejected_origin, 2u);
    c = candidate(); c.seen = at(1000, 2); CHECK(!p.offer(c));
    c.seen = {}; CHECK(!p.offer(c)); c.seen = at(1001); CHECK(!p.offer(c));
    CHECK_EQ(p.picker().rejected_time, 3u);
    c = candidate(); c.network.ssid_size = 33; CHECK(!p.offer(c));
    c = candidate(); c.network.bssid[0] = 1; CHECK(!p.offer(c));
    CHECK(p.offer(candidate())); p.handle(Action::Tick, at(60999)); CHECK_EQ(p.picker().count, 1);
    p.handle(Action::Tick, at(61000)); CHECK_EQ(p.picker().count, 0);
    CHECK(!p.offer(candidate())); // already expired
    CHECK_EQ(p.picker().rejected_time, 4u);
}

GUARDIAN_CASE(picker_capacity_does_not_evict_and_updates_do_not_rewind) {
    Presenter p({}); p.update(fresh(), at(2000));
    for (std::uint8_t i = 1; i <= 16; ++i) CHECK(p.offer(candidate(i)));
    CHECK(!p.offer(candidate(17))); CHECK_EQ(p.picker().dropped, 1u);
    auto c = candidate(1); c.seen = at(2000); c.channel = 11; CHECK(p.offer(c));
    CHECK(!p.offer(candidate(1))); CHECK_EQ(p.picker().entries[0].channel, 11);
    p.handle(Action::SecondaryLong, at(2000));
    for (int i = 0; i < 16; ++i) p.handle(Action::Primary, at(2000));
    CHECK_EQ(p.picker().cursor, 0);
}

GUARDIAN_CASE(empty_picker_and_cancel_never_emit_a_request) {
    Presenter p({}); p.update({}, at()); p.handle(Action::SecondaryLong, at());
    CHECK_EQ(p.screen(), Screen::Picker);
    CHECK(!p.handle(Action::Primary, at())); CHECK(!p.handle(Action::Secondary, at()));
    CHECK(!p.handle(Action::PrimaryLong, at())); CHECK(!p.has_request());
    p.handle(Action::Back, at()); CHECK_EQ(p.screen(), Screen::Face);
}

GUARDIAN_CASE(demo_cycles_five_moods_isolates_requests_and_live_incident_breaks_through) {
    Presenter p(display()); p.update(fresh(), at()); CHECK(p.offer(candidate()));
    CHECK(p.set_demo(true)); CHECK_EQ(p.mode(), ViewMode::Demo);   // G24 retry: the direct method (no key enters DEMO)
    const Mood moods[] = {Mood::VeryGood, Mood::Good, Mood::Medium, Mood::Bad, Mood::Horrible};
    for (auto mood : moods) {
        CHECK(p.view().demo); CHECK_EQ(p.view().face, mood); CHECK(p.view().animate);
        CHECK_EQ(p.view().celebrate, mood == Mood::VeryGood);
        CHECK(!p.handle(Action::SecondaryLong, at())); CHECK_EQ(p.picker().count, 0);
        CHECK(!p.has_request()); p.handle(Action::Secondary, at());
    }
    CHECK_EQ(p.view().face, Mood::VeryGood);
    p.handle(Action::Primary, at()); CHECK(p.details().demo);
    auto s = fresh(); s.incidents[2] = true; s.evidence[2].acquired = at(); s.evidence[2].count = 5;
    p.update(s, at(2500)); CHECK_EQ(p.mode(), ViewMode::Live); CHECK_EQ(p.screen(), Screen::Face);
    CHECK(!p.view().demo); CHECK(p.view().incident.visible); CHECK(!p.view().celebrate);
    CHECK(!p.set_demo(true)); CHECK_EQ(p.mode(), ViewMode::Live);   // refused while the live incident shows
}

GUARDIAN_CASE(demo_toggle_preserves_live_selection_and_does_not_swallow_pending_request) {
    Presenter p({}); p.update(fresh(), at()); p.offer(candidate(0x66));
    p.handle(Action::SecondaryLong, at()); p.handle(Action::Secondary, at());
    CHECK(!p.set_demo(true)); CHECK(p.has_request()); p.take_request();
    CHECK(p.set_demo(true)); CHECK(p.view().demo); CHECK(!p.set_demo(true));
    p.handle(Action::PrimaryLong, at()); CHECK(!p.view().demo);   // G24 retry: hold FRONT in DEMO returns to LIVE
    CHECK_EQ(std::string(p.view().selected_label.c_str()), "home"); CHECK_EQ(p.picker().count, 1);
    auto alien = fresh(); alien.origin = Origin::Demo; alien.selected = home(0x77);
    p.update(alien, at()); CHECK_EQ(std::string(p.view().selected_bssid.c_str()), "02:11:22:33:44:55");
}

GUARDIAN_CASE(incident_priority_and_coverage_coexist_with_full_uncertainty) {
    Presenter p(display()); auto s = fresh(); s.coverage = Coverage::Degraded;
    for (std::size_t i = 0; i < 3; ++i) {
        s.incidents[i] = true; auto& e = s.evidence[i]; e.acquired = at();
        e.count = static_cast<std::uint32_t>(12 + i); e.window_ms = 10000;
        e.threshold = 10; e.raw_frames = 15; e.retries_deduped = 3; e.protected_frames = 2;
        e.saturated = true; e.coverage_known = true; e.listened_ms = 4000; e.coverage_window_ms = 10000;
        e.hopping = true; e.bssid = home().bssid; e.changes = change::Pmf;
    }
    p.update(s, at(2500)); const auto b = p.view().incident;
    CHECK_EQ(b.kind, IncidentKind::DisconnectBurst); CHECK_EQ(b.current, 3);
    CHECK_EQ(b.count, 12u); CHECK_EQ(b.threshold, 10u); CHECK_EQ(b.raw_frames, 15u);
    CHECK_EQ(b.retries_deduped, 3u); CHECK_EQ(b.protected_frames, 2u); CHECK(b.saturated);
    CHECK_EQ(b.window_ms, 10000u); CHECK_EQ(b.listened_ms, Millis{4000}); CHECK(b.hopping);
    CHECK_EQ(b.coverage_window_ms, Millis{10000}); CHECK(b.coverage_known);
    CHECK(b.age_known); CHECK_EQ(b.age_ms, Millis{1500}); CHECK_EQ(b.changes, change::Pmf);
    CHECK_EQ(b.item, AdviceId::DisconnectTrafficObserved);
    CHECK_EQ(p.view().overlay, Overlay::CoverageDegraded); CHECK(p.view().muted); CHECK(!p.view().animate);
    CHECK_EQ(p.details().incident.count, b.count); CHECK(p.details().advice.has(AdviceId::ListeningDegraded));
    s.incidents[0] = false; p.update(s, at(2500)); CHECK_EQ(p.view().incident.kind, IncidentKind::UnexpectedAp);
    s.incidents[1] = false; p.update(s, at(2500)); CHECK_EQ(p.view().incident.kind, IncidentKind::SettingsChanged);
}

GUARDIAN_CASE(fixture_pipeline_exposes_reason_age_coverage_signal_and_stale_state) {
    RxMeta meta; const auto parsed = fixture(c_, "beacon_wpa3_sae_pmf_required", meta);
    struct Clock final : MonotonicClock { Millis t{1000}; Millis now() const override { return t; } TimeEpoch epoch() const override { return at().epoch; } } clock;
    Core core(clock, profiles::all_2g4_channels(), Origin::Imported);
    CHECK(core.select(parsed.identity)); const auto o = observe_security(parsed, meta); core.security(o);
    const auto signal = observe_signal(parsed, meta); core.signal(signal);
    Presenter p({}, Origin::Imported); clock.t = 2500; p.update(core.snapshot(), at(2500));
    CHECK_EQ(p.view().face, Mood::VeryGood); CHECK(p.view().historical); CHECK(p.view().muted); CHECK(!p.view().celebrate);
    CHECK_EQ(p.view().explanation, Finding::StrongSettings); CHECK(p.view().last_seen_known);
    CHECK_EQ(p.view().last_seen_ms, Millis{1500}); CHECK_EQ(p.details().age_ms, Millis{1500});
    CHECK_EQ(std::string(p.details().coverage_label), "Fresh"); CHECK(p.details().advice.signal.available);
    CHECK_EQ(p.details().advice.signal.rssi_dbm, -55); CHECK(p.details().advice.has(AdviceId::Wpa3Strong));
    Candidate c; CHECK(candidate_from(parsed, meta, c)); CHECK(p.offer(c));
    CHECK_EQ(p.picker().entries[0].age_ms, Millis{1500});
    clock.t = 31000; p.update(core.snapshot(), at(31000));
    CHECK_EQ(p.view().face, Mood::Unknown); CHECK_EQ(p.view().overlay, Overlay::NoFreshData);
    CHECK_EQ(p.details().age_ms, Millis{30000}); CHECK(p.details().advice.has(AdviceId::NoFreshData));
}

GUARDIAN_CASE(fixture_candidates_hidden_malformed_and_unverified_baselines) {
    for (const char* name : {"beacon_hidden_ssid_wpa2", "beacon_ssid_non_utf8", "beacon_rsn_truncated_ie"}) {
        RxMeta meta; const auto r = fixture(c_, name, meta); Candidate c;
        CHECK(candidate_from(r, meta, c)); Presenter p({}, Origin::Imported); Snapshot s; s.origin = Origin::Imported;
        p.update(s, at()); CHECK(p.offer(c)); CHECK_EQ(p.picker().count, 1);
        if (r.ssid_kind == SsidKind::Hidden) CHECK(p.picker().entries[0].hidden);
        if (std::string(name) == "beacon_ssid_non_utf8") CHECK(p.picker().entries[0].label.altered);
        if (r.status != ParseStatus::Complete) CHECK(!c.settings_complete);
    }
    RxMeta meta; auto r = fixture(c_, "beacon_wpa3_sae_pmf_required", meta); Candidate c;
    meta.status = RxStatus::Unknown; CHECK(candidate_from(r, meta, c)); CHECK(!c.settings_complete);
    CHECK(!c.ds_channel_present);
    r.kind = FrameKind::Deauthentication; CHECK(!candidate_from(r, meta, c));
    r.kind = FrameKind::Beacon; r.header_valid = false; CHECK(!candidate_from(r, meta, c));
}

GUARDIAN_CASE(persistence_roundtrip_and_atomic_invalid_restore) {
    ApprovedScope scope; CHECK(scope.select({home()})); ApprovedAp related{home(0x66)};
    related.settings_known = true; related.settings.pmf = Pmf::Required; CHECK(scope.approve(related));
    const auto record = persist(scope); CHECK(record.valid()); CHECK_EQ(record.approved_count, 1);
    FakeStore store; PersistedSelection loaded; CHECK(!store.load(loaded)); CHECK(store.save(record)); CHECK(store.load(loaded));
    ApprovedScope restored; CHECK(restore(loaded, restored)); CHECK(restored.selected().network == home());
    CHECK(restored.find(home(0x66).bssid)); CHECK(restored.find(home(0x66).bssid)->settings == related.settings);
    auto bad = record; bad.version++; CHECK(!restore(bad, restored)); CHECK(restored.selected().network == home());
    bad = record; bad.selected.network.ssid_size = 33; CHECK(!bad.valid());
    bad = record; bad.approved_count = 255; CHECK(!bad.valid());
    bad = record; bad.approved[0].network = home(); CHECK(!bad.valid());
    bad = record; bad.approved_count = 2; bad.approved[1] = bad.approved[0]; CHECK(!bad.valid());
    bad = record; bad.has_selection = false; CHECK(!bad.valid());
    ApprovedScope limited(0); CHECK(limited.select({home(0x77)})); CHECK(!restore(record, limited));
    CHECK(limited.selected().network == home(0x77));
    store.fail = true; CHECK(!store.save(record));
    PersistedSelection empty; CHECK(restore(empty, restored)); CHECK(!restored.has_selection()); CHECK_EQ(restored.approved_count(), 0u);
}

GUARDIAN_CASE(persistence_retains_all_supported_approvals_and_rejects_foreign_names) {
    ApprovedScope scope(16); CHECK(scope.select({home()}));
    for (std::uint8_t i = 1; i <= 16; ++i) CHECK(scope.approve({home(i)}));
    auto record = persist(scope); CHECK(record.valid()); CHECK_EQ(record.approved_count, 16);
    ApprovedScope restored(16); CHECK(restore(record, restored)); CHECK_EQ(restored.approved_count(), 16u);
    record.approved[0].network.ssid[0] = 'x'; CHECK(!record.valid());
    record = persist(scope); record.selected.channel_known = true; record.selected.channel = 0; CHECK(!record.valid());
}

GUARDIAN_CASE(details_expose_source_and_listening_measurements_without_an_incident) {
    Presenter p({}, Origin::Imported); auto s = fresh(); s.origin = Origin::Imported;
    s.has_coverage = true; auto& cov = s.last_coverage; cov.sampled_at = at();
    cov.channel = 6; cov.window_ms = 10000; cov.listened_ms = 4200;
    cov.dropped_in_window = 2; cov.passive_receive = Support::Unsupported; cov.hopping = true;
    s.coverage = Coverage::Degraded; p.update(s, at(2000));
    CHECK_EQ(p.view().origin, Origin::Imported); CHECK_EQ(std::string(p.view().source_label), "IMPORTED");
    CHECK_EQ(p.details().origin, Origin::Imported); CHECK_EQ(std::string(p.details().source_label), "IMPORTED");
    CHECK(p.details().has_coverage); CHECK_EQ(p.details().coverage.listened_ms, Millis{4200});
    CHECK_EQ(p.details().coverage.window_ms, Millis{10000}); CHECK_EQ(p.details().coverage.dropped_in_window, 2u);
    CHECK_EQ(p.details().coverage_age_ms, Millis{1000}); CHECK(p.details().coverage.hopping);
    CHECK_EQ(p.details().coverage.passive_receive, Support::Unsupported);
    p.set_demo(true);
    CHECK_EQ(std::string(p.view().source_label), "DEMO"); CHECK_EQ(p.details().origin, Origin::Demo);
    CHECK(!p.details().has_coverage);
}

GUARDIAN_CASE(persisted_fingerprint_rejects_invalid_enums_and_reserved_bits) {
    PersistedSelection r; r.has_selection = true; r.selected.network = home(); r.selected.settings_known = true;
    auto invalid = r; invalid.selected.settings.pmf = static_cast<Pmf>(255); CHECK(!invalid.valid());
    invalid = r; invalid.selected.settings.rsn_state = static_cast<ElementState>(255); CHECK(!invalid.valid());
    invalid = r; invalid.selected.settings.wpa_state = static_cast<ElementState>(255); CHECK(!invalid.valid());
    invalid = r; invalid.selected.settings.owe_transition = static_cast<ElementState>(255); CHECK(!invalid.valid());
    invalid = r; invalid.selected.settings.rsn_pairwise = 1u << 14; CHECK(!invalid.valid());
    invalid = r; invalid.selected.settings.wpa_akms = 1u << 14; CHECK(!invalid.valid());
    ApprovedScope scope; CHECK(scope.select({home(0x77)})); CHECK(!restore(invalid, scope));
    CHECK(scope.selected().network == home(0x77));
    CHECK(scope.approved_at(0) == nullptr); CHECK(scope.approved_at(100) == nullptr);
}

GUARDIAN_CASE(ticks_age_evidence_expire_incidents_and_reboot_invalidates_requests) {
    Presenter p(display()); auto s = fresh(); s.incidents[0] = true; s.evidence[0].acquired = at();
    p.update(s, at()); CHECK(!p.view().celebrate);
    // Evidence at 1000 ms expires exactly Core::fresh_ms later (29 s since G13).
    p.handle(Action::Tick, at(1000 + Core::fresh_ms - 1)); CHECK_EQ(p.view().face, Mood::VeryGood);
    p.handle(Action::Tick, at(1000 + Core::fresh_ms)); CHECK_EQ(p.view().face, Mood::Unknown);
    CHECK(p.view().muted); CHECK_EQ(p.view().overlay, Overlay::NoFreshData);
    CHECK(p.view().incident.visible); CHECK_EQ(p.details().age_ms, Core::fresh_ms);
    p.handle(Action::Tick, at(61000)); CHECK(!p.view().incident.visible);
    p.update(fresh(), at(1000, 2)); CHECK(p.view().historical); CHECK(!p.view().last_seen_known);
    auto c = candidate(); c.seen = at(1000, 2); CHECK(p.offer(c));
    p.handle(Action::SecondaryLong, at(1000, 2)); p.handle(Action::Secondary, at(1000, 2)); CHECK(p.has_request());
    p.handle(Action::Tick, at(0, 3)); CHECK(!p.has_request()); CHECK_EQ(p.picker().count, 0);
    CHECK_EQ(p.screen(), Screen::Face); CHECK(!p.handle(Action::Primary, {}));
}

GUARDIAN_CASE(expiration_during_selection_never_substitutes_another_entry) {
    Presenter p({}); p.update(fresh(), at()); CHECK(p.offer(candidate()));
    p.update(fresh(), at(2000)); auto newer = candidate(0x66); newer.seen = at(2000); CHECK(p.offer(newer));
    p.handle(Action::SecondaryLong, at(2000));
    p.handle(Action::Secondary, at(61000)); // highlighted oldest expired, second still fresh
    CHECK(!p.has_request()); CHECK_EQ(p.picker().count, 1); CHECK_EQ(p.screen(), Screen::Picker);
    p.handle(Action::Secondary, at(61000)); CHECK(p.take_request().ap.network == newer.network);
}

GUARDIAN_CASE(pagination_clamps_after_shrinking_advice_and_small_displays_are_bounded) {
    DisplayCapabilities small{Support::Supported, 6, 8, PixelFormat::Mono1, Support::Unknown};
    Presenter p(small); auto s = fresh(); s.settings.unrated = Unrated::Incomplete;
    s.settings.mood = Mood::Unknown; s.incidents.fill(true);
    for (auto& e : s.evidence) e.acquired = at();
    p.update(s, at()); p.handle(Action::Primary, at()); p.handle(Action::Primary, at());
    CHECK_EQ(p.details().items_per_page, 1); CHECK(!p.view().animate);
    while (p.details().first_item + p.details().item_count < p.details().advice.count) p.handle(Action::Primary, at());
    p.update(fresh(), at()); CHECK(p.details().first_item < p.details().advice.count);
    CHECK_EQ(p.details().item_count, 1); p.handle(Action::Primary, at()); CHECK_EQ(p.details().page, DetailsPage::SignalAndEvidence);
}

GUARDIAN_CASE(demo_fixture_moods_match_real_rating_policy) {
    for (std::uint8_t i = 0; i < demo_steps; ++i) {
        const auto s = demo_snapshot(i); CHECK_EQ(s.origin, Origin::Demo);
        CHECK_EQ(assess(s.last_security).mood, s.settings.mood);
        CHECK_EQ(assess(s.last_security).reason, s.settings.reason);
    }
    CHECK_EQ(demo_snapshot(255).settings.mood, Mood::VeryGood);
}


GUARDIAN_CASE(review_reused_slot_cannot_move_highlight_to_a_new_ap) {
    Presenter p({}); p.update(fresh(), at()); CHECK(p.offer(candidate()));
    p.update(fresh(), at(2000)); auto b = candidate(0x66); b.seen = at(2000); CHECK(p.offer(b));
    p.handle(Action::SecondaryLong, at(2000)); p.handle(Action::Primary, at(2000));
    CHECK(p.picker().entries[p.picker().cursor].network == b.network);
    p.handle(Action::Tick, at(61000)); // old first slot expires; highlighted B survives
    CHECK_EQ(p.picker().count, 1);
    CHECK(p.picker().entries[p.picker().cursor].network == b.network);
    auto c = candidate(0x77); c.seen = at(61000); CHECK(p.offer(c)); // reuses storage before B
    CHECK_EQ(p.picker().count, 2);
    CHECK(p.picker().entries[p.picker().cursor].network == b.network);
    p.handle(Action::Secondary, at(61000));
    CHECK_EQ(p.take_request().ap.network, b.network);
}

GUARDIAN_CASE(review_pending_approval_is_invalidated_when_selection_changes) {
    ApprovedScope scope; CHECK(scope.select({home()}));
    Presenter p({}); p.update(fresh(), at(), &scope); CHECK(p.offer(candidate(0x66)));
    p.handle(Action::SecondaryLong, at()); p.handle(Action::PrimaryLong, at());
    CHECK(p.has_request());
    p.update(fresh(), at(1001), &scope); CHECK(p.has_request()); // same context survives
    auto replacement = fresh(); replacement.selected = home(0x77);
    replacement.last_security.network = replacement.selected;
    CHECK(scope.select({replacement.selected}));
    p.update(replacement, at(1002), &scope);
    CHECK(!p.has_request());
    CHECK_EQ(p.take_request().kind, RequestKind::None);
}

// G14 owner requirement (2026-11-14): a current incident on the selected /
// approved network turns the face into a red ALERT overlay, independent of the
// security grade, with an evidence-based reason; it never celebrates, never
// hides stale/degraded coverage and disappears with its evidence (no all-clear).
GUARDIAN_CASE(g14_alert_overlay_trigger_expiry_and_stale_coexistence) {
    Presenter p(display()); p.update(fresh(), at());
    CHECK(!p.view().alert); CHECK_EQ(std::string(p.view().alert_reason), "");
    CHECK(p.view().celebrate);
    auto s = fresh(); s.incidents[0] = true; auto& e = s.evidence[0];
    e.acquired = at(); e.count = 24; e.window_ms = 10000; e.bssid = home().bssid;
    p.update(s, at(1500));
    CHECK(p.view().alert); CHECK_EQ(std::string(p.view().alert_reason), "Disconnect burst detected");
    CHECK_EQ(p.view().face, Mood::VeryGood);      // grade unchanged, alert is an overlay
    CHECK(!p.view().celebrate); CHECK(!p.view().animate);
    CHECK_EQ(p.view().overlay, Overlay::None);
    // Stale evidence and the alert are both visible.
    p.handle(Action::Tick, at(1000 + Core::fresh_ms));
    CHECK(p.view().alert); CHECK_EQ(p.view().overlay, Overlay::NoFreshData);
    CHECK_EQ(p.view().face, Mood::Unknown); CHECK(p.view().muted);
    // Expiry returns to the evidence state, never to a celebration or all-clear.
    p.handle(Action::Tick, at(1000 + Core::incident_ms));
    CHECK(!p.view().alert); CHECK_EQ(std::string(p.view().alert_reason), "");
    CHECK_EQ(p.view().overlay, Overlay::NoFreshData); CHECK(!p.view().celebrate);
    // Other kinds have their own non-accusatory reason; priority follows the banner.
    for (std::size_t k = 0; k < 3; ++k) {
        const char* text = alert_text(static_cast<IncidentKind>(k));
        CHECK(std::strlen(text) > 0);
        CHECK(std::strstr(text, "attack") == nullptr); CHECK(std::strstr(text, "hacker") == nullptr);
    }
    auto u = fresh(); u.incidents[1] = true; u.evidence[1].acquired = at(2000);
    Presenter q(display()); q.update(u, at(2000));
    CHECK(q.view().alert); CHECK_EQ(std::string(q.view().alert_reason), alert_text(IncidentKind::UnexpectedAp));
    // DEMO fixtures never raise an alert; a live alert breaks through DEMO.
    Presenter d(display()); d.update(fresh(), at()); d.set_demo(true);
    for (int i = 0; i < 5; ++i) { CHECK(!d.view().alert); d.handle(Action::Secondary, at()); }
    d.update(s, at(1500)); CHECK(d.view().alert); CHECK(!d.view().demo);
}

// ---- G16N: the view carries the live incident count (a dark screen is lit when it changes) ----
GUARDIAN_CASE(view_incident_seq_follows_the_live_snapshot_also_in_demo) {
    Presenter p(display()); p.update(fresh(), at());
    CHECK_EQ(p.view().incident_seq, 0u);
    CHECK_EQ(present(fresh()).incident_seq, 0u);
    // A red incident: the count and the ALERT arrive together.
    auto s = fresh(); s.incident_seq = 3; s.incidents[0] = true; s.evidence[0].acquired = at(1400); s.evidence[0].count = 24;
    CHECK_EQ(present(s).incident_seq, 3u);
    p.update(s, at(1500));
    CHECK(p.view().alert); CHECK_EQ(p.view().incident_seq, 3u);
    // A second report of the same kind while the banner is up: the ALERT flag cannot say so, the count does.
    s.incident_seq = 4; s.evidence[0].acquired = at(2400);
    p.update(s, at(2500));
    CHECK(p.view().alert); CHECK_EQ(p.view().incident_seq, 4u);
    // Ticks, aging and the banner's expiry never change it (no false "new incident").
    p.handle(Action::Tick, at(2400 + Core::incident_ms));
    CHECK(!p.view().alert); CHECK_EQ(p.view().incident_seq, 4u);
    // An amber (area) observation: no ALERT at all, the count still moves.
    auto a = fresh(); a.incident_seq = 5; a.area_visible[0] = true; a.area_visible_ms = 60000;
    a.area[0].scope = IncidentScope::Area; a.area[0].family = DetectorFamily::Probe; a.area[0].acquired = at(70000);
    p.update(a, at(70100));
    CHECK(!p.view().alert); CHECK(p.view().caution); CHECK_EQ(p.view().incident_seq, 5u);
    // DEMO shows fixtures, and an amber observation does not leave DEMO: the LIVE count is still in the view.
    Presenter d(display()); d.update(fresh(), at());
    CHECK(d.set_demo(true)); CHECK_EQ(d.mode(), ViewMode::Demo);
    CHECK_EQ(d.view().incident_seq, 0u);
    auto live = fresh(); live.incident_seq = 9; live.area_visible[0] = true; live.area_visible_ms = 60000;
    live.area[0].scope = IncidentScope::Area; live.area[0].family = DetectorFamily::Beacon; live.area[0].acquired = at(1400);
    d.update(live, at(1500));
    CHECK_EQ(d.mode(), ViewMode::Demo); CHECK(d.view().demo);
    CHECK_EQ(d.view().incident_seq, 9u);
    d.handle(Action::Secondary, at(1600));                   // the next DEMO face: still the live count
    CHECK_EQ(d.view().incident_seq, 9u);
    // A snapshot of another origin is ignored whole, its count included.
    auto foreign = fresh(); foreign.origin = Origin::Demo; foreign.incident_seq = 99;
    d.update(foreign, at(1700));
    CHECK_EQ(d.view().incident_seq, 9u);
}

// ---- G16C: pagination by wrapped rows ------------------------------------------
namespace {
// Rows of `t` wrapped at `cols`, computed independently of wrap_take (reference model).
std::size_t ref_rows(const char* t, std::size_t cols) {
    std::size_t n = std::strlen(t), at = 0, rows = 0;
    while (at < n) {
        std::size_t take = std::min(cols, n - at);
        if (at + take < n) { std::size_t sp = take; while (sp > 0 && t[at + sp] != ' ') --sp; if (sp > 0) take = sp; }
        at += take; while (at < n && t[at] == ' ') ++at; ++rows;
    }
    return rows;
}
}

GUARDIAN_CASE(wrap_helpers_break_at_words_and_count_rows) {
    const char* t = "Internet access or coverage elsewhere.";
    const auto n = std::strlen(t);
    CHECK_EQ(wrap_take(t, n, 0, 22), std::size_t{18});                 // "Internet access or"
    CHECK_EQ(wrap_next(t, n, 0, 22), std::size_t{19});
    CHECK_EQ(wrapped_rows(t, 22), std::size_t{2});
    CHECK_EQ(wrapped_rows("", 22), std::size_t{0});
    CHECK_EQ(wrapped_rows("abcdefghijklmnopqrstuvwxyz", 22), std::size_t{2});   // an over-long word is split
    for (const char* s : {"a b c d e f g h i j k l m n o p q r s t u v w x y z", "Weak signal, Internet loss or a dictionary test never change it.",
                          "x", "exactly twenty-two chr", "exactly twenty-two chr and more"})
        for (std::size_t cols : {std::size_t{5}, std::size_t{11}, std::size_t{22}}) CHECK_EQ(wrapped_rows(s, cols), ref_rows(s, cols));
}

GUARDIAN_CASE(row_budget_pages_fit_cover_every_item_and_end_reachable) {
    // Many advice sets (rated, unrated, every incident): with a row budget,
    // every Explanation and OwnerChecks sub-page fits its rows, every item is
    // shown exactly once in order, and Primary walks to the last page.
    const TextBudget budget{22, 9, 8};
    std::vector<Snapshot> cases;
    cases.push_back(fresh());
    { auto s = fresh(); s.settings.unrated = Unrated::Incomplete; s.settings.mood = Mood::Unknown; s.incidents.fill(true);
      for (auto& e : s.evidence) e.acquired = at(); cases.push_back(s); }
    { auto s = fresh(); s.incidents.fill(true); for (auto& e : s.evidence) e.acquired = at(); cases.push_back(s); }
    unsigned planned_pages = 0;
    for (const auto& s : cases) {
        Presenter p(display()); p.set_text_budget(budget); p.update(s, at());
        p.handle(Action::Primary, at()); p.handle(Action::Primary, at());
        CHECK_EQ(p.details().page, DetailsPage::Explanation);
        std::size_t shown = 0; std::uint8_t index = 0;
        const auto pages = p.details().page_count;
        CHECK(pages >= 1);
        while (p.details().page == DetailsPage::Explanation && index < 20) {
            const auto& d = p.details();
            CHECK_EQ(d.page_index, index); CHECK_EQ(d.page_count, pages); CHECK_EQ(d.first_item, shown);
            std::size_t rows = index == 0 ? wrapped_rows(advice_text(d.advice.next_step), budget.columns) : 0;
            for (std::uint8_t i = 0; i < d.item_count; ++i) rows += ref_rows(advice_text(d.advice.items[d.first_item + i]), budget.columns);
            CHECK(rows <= budget.explanation_rows);
            // Only the first sub-page may hold just the next step, when the next item cannot fit beside it.
            CHECK(d.item_count > 0 || d.advice.count == 0
                  || (index == 0 && rows + ref_rows(advice_text(d.advice.items[0]), budget.columns) > budget.explanation_rows));
            shown += d.item_count; ++index; ++planned_pages;
            p.handle(Action::Primary, at());
        }
        CHECK_EQ(shown, p.details().advice.count); CHECK_EQ(index, pages);
        CHECK_EQ(p.details().page, DetailsPage::SignalAndEvidence);
        p.handle(Action::Primary, at()); CHECK_EQ(p.details().page, DetailsPage::OwnerChecks);
        std::size_t checks = 0; index = 0;
        const auto owner_pages = p.details().page_count;
        while (p.screen() == Screen::Details && p.details().page == DetailsPage::OwnerChecks && index < 20) {
            const auto& d = p.details();
            CHECK_EQ(d.page_index, index); CHECK_EQ(d.first_check, checks); CHECK(d.check_count > 0);
            std::size_t rows = 0;
            for (std::uint8_t i = 0; i < d.check_count; ++i) rows += ref_rows(advice_text(d.advice.owner_checks[d.first_check + i].id), budget.columns);
            CHECK(rows <= budget.owner_rows);
            checks += d.check_count; ++index;
            p.handle(Action::Primary, at());
        }
        CHECK_EQ(checks, static_cast<std::size_t>(OwnerCheckId::Count)); CHECK_EQ(index, owner_pages);
        CHECK(owner_pages > 1);                                               // 8 rows cannot hold all owner checks
        CHECK_EQ(p.details().page, DetailsPage::Limits);                      // G16J: then the limits page, then the face
        p.handle(Action::Primary, at());
        CHECK_EQ(p.screen(), Screen::Face);
    }
    CHECK(planned_pages > cases.size());                                      // the budget really splits pages
}

GUARDIAN_CASE(details_expose_the_settings_behind_the_labels) {
    Presenter p(display()); auto s = fresh();
    s.settings.mode = Mode::Wpa3Personal; s.settings.pairwise = Cipher::Ccmp; s.settings.pmf = Pmf::Required;
    p.update(s, at());
    CHECK_EQ(p.details().mode, Mode::Wpa3Personal);
    CHECK_EQ(p.details().mode, s.settings.mode); CHECK_EQ(p.details().pairwise, s.settings.pairwise);
    CHECK_EQ(p.details().pmf, s.settings.pmf);
    CHECK_EQ(std::string(p.details().mode_label), std::string(mode_text(s.settings.mode)));
}

// G16R (TDD, run RED first against the stub alert_sentence; log
// $GUARDIAN_STORE/builds/20261118-g16r-tdd/red-presenter_check.log): the picked
// network is its name. The red sentence of a disconnect burst names that network; the address the
// frames named stays evidence (IncidentBanner::bssid) and is never part of the red text.
GUARDIAN_CASE(g16r_the_red_sentence_names_the_picked_network_never_an_address) {
    auto s = fresh(); s.incidents[0] = true; auto& e = s.evidence[0];
    e.acquired = at(); e.count = 24; e.window_ms = 10000;
    e.bssid = home(0x77).bssid;                              // the frames named ANOTHER address of the name
    Presenter p(display()); p.update(s, at(1500));
    const auto& v = p.view();
    CHECK(v.alert);
    CHECK(v.incident.bssid == home(0x77).bssid);             // the evidence keeps the address
    char text[96]{};
    CHECK_EQ(alert_sentence(v, text, sizeof text), std::strlen("Disconnect burst on home"));
    CHECK_EQ(std::string(text), "Disconnect burst on home");
    for (const auto& address : {mac_text(home().bssid), mac_text(home(0x77).bssid)}) {
        CHECK(std::string(text).find(address.c_str()) == std::string::npos);
        CHECK(std::string(text).find(address.c_str() + 12) == std::string::npos);
    }
    CHECK(std::string(text).find(':') == std::string::npos);
    // The pure reducer gives the same sentence.
    char pure[96]{};
    CHECK(alert_sentence(present(s), pure, sizeof pure) > 0);
    CHECK_EQ(std::string(pure), std::string(text));
    // A name longer than the row is shortened with a visible '~', never cut silently.
    auto l = fresh(); l.selected.ssid_size = 32; l.selected.ssid.fill(std::uint8_t{'x'}); l.last_security.network = l.selected;
    l.incidents[0] = true; l.evidence[0].acquired = at(); l.evidence[0].count = 24; l.evidence[0].window_ms = 10000;
    Presenter q(display()); q.update(l, at(1500));
    CHECK(alert_sentence(q.view(), text, sizeof text, 22) > 0);
    CHECK_EQ(std::string(text), "Disconnect burst on " + std::string(21, 'x') + "~");
    CHECK(alert_sentence(q.view(), text, sizeof text) > 0);
    CHECK_EQ(std::string(text), "Disconnect burst on " + std::string(32, 'x'));
    // A picked network that hides its name has no name to print.
    auto h = fresh(); h.selected.ssid_size = 0; h.last_security.network = h.selected; h.last_security.ssid_kind = SsidKind::Hidden;
    h.incidents[0] = true; h.evidence[0].acquired = at(); h.evidence[0].count = 24; h.evidence[0].window_ms = 10000;
    Presenter hp(display()); hp.update(h, at(1500));
    CHECK(alert_sentence(hp.view(), text, sizeof text) > 0);
    CHECK_EQ(std::string(text), "Disconnect burst on your network");
    // The other kinds keep their sentence (they speak of "your network" already).
    auto u = fresh(); u.incidents[1] = true; u.evidence[1].acquired = at(); u.evidence[1].bssid = home(0x77).bssid;
    Presenter up(display()); up.update(u, at(1500));
    CHECK(alert_sentence(up.view(), text, sizeof text) > 0);
    CHECK_EQ(std::string(text), "Another device is using your network's name");
    // No alert: nothing. A buffer that is too small is refused, never cut.
    Presenter n(display()); n.update(fresh(), at());
    CHECK_EQ(alert_sentence(n.view(), text, sizeof text), 0u);
    CHECK_EQ(std::string(text), "");
    char tiny[8]{'#'};
    CHECK_EQ(alert_sentence(v, tiny, sizeof tiny), 0u);
    CHECK_EQ(tiny[0], '\0');
    CHECK_EQ(alert_sentence(v, nullptr, 0), 0u);
}

// G16S: the incident banner carries the most frequent (receiver, sender, BSSID, channel) tuple of a
// disconnect burst as the detector reported it, for the Details screen (RED first: the banner had no tuple).
GUARDIAN_CASE(g16s_the_banner_carries_the_top_tuple_of_a_disconnect_burst) {
    auto s = fresh(); s.incidents[0] = true; auto& e = s.evidence[0];
    e.acquired = at(); e.count = 24; e.window_ms = 10000;
    e.top.receiver = Mac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    e.top.sender = home(0x77).bssid; e.top.bssid = home(0x77).bssid; e.top.channel = 6; e.top.count = 17;
    const auto same = [&](const BurstTuple& t) {
        return t.receiver == e.top.receiver && t.sender == e.top.sender && t.bssid == e.top.bssid && t.channel == 6 && t.count == 17u;
    };
    Presenter p(display()); p.update(s, at(1500));
    CHECK(same(p.view().incident.top));
    CHECK(same(p.details().incident.top));
    CHECK(same(present(s).incident.top));
    // The red sentence still names the network, never an address (G16R).
    char text[96]{};
    CHECK(alert_sentence(p.view(), text, sizeof text) > 0);
    CHECK_EQ(std::string(text), "Disconnect burst on home");
    // An incident without a tuple leaves it empty.
    auto u = fresh(); u.incidents[1] = true; u.evidence[1].acquired = at();
    CHECK_EQ(present(u).incident.top.count, 0u);
}

// G16T (TDD, run RED first against the unchanged alert_sentence and banner; log
// $GUARDIAN_STORE/builds/20261119-g16t-tdd/red-presenter_check.log): a nearby
// disconnect burst that also named the picked network (IncidentObservation::own_frames > 0) is a
// Network incident with its own red sentence: it names the picked network and says the burst is
// nearby as well. Its first row fits one glass row, so the name starts the second.
GUARDIAN_CASE(g16t_a_nearby_burst_on_the_picked_network_has_its_own_red_sentence) {
    constexpr std::size_t k = static_cast<std::size_t>(IncidentKind::NetworkPattern);
    const auto mixed = [&](Pattern rule, std::uint32_t own) {
        auto s = fresh(); s.incidents[k] = true; auto& e = s.evidence[k];
        e.kind = IncidentKind::NetworkPattern; e.acquired = at(); e.count = 10; e.threshold = 10; e.window_ms = 10000;
        e.pattern = rule; e.own_frames = own; e.bssid = home().bssid;
        return s;
    };
    const auto s = mixed(Pattern::DeauthBroadcast, 3);
    Presenter p(display()); p.update(s, at(1500));
    const auto& v = p.view();
    CHECK(v.alert);
    CHECK_EQ(v.incident.kind, IncidentKind::NetworkPattern);
    CHECK_EQ(v.incident.own_frames, 3u);                       // the banner carries why it is red
    CHECK_EQ(p.details().incident.own_frames, 3u);
    CHECK_EQ(present(s).incident.own_frames, 3u);
    CHECK_EQ(std::string(v.alert_reason), "Disconnect burst nearby also on your network");
    CHECK_EQ(std::string(present(s).alert_reason), "Disconnect burst nearby also on your network");
    char text[96]{};
    CHECK_EQ(alert_sentence(v, text, sizeof text), std::strlen("Nearby burst also on home"));
    CHECK_EQ(std::string(text), "Nearby burst also on home");
    CHECK(std::strlen("Nearby burst also on") <= 22u);         // one 22-glyph row, then the name
    CHECK(std::string(text).find(mac_text(home().bssid).c_str() + 12) == std::string::npos);
    CHECK(std::string(text).find(':') == std::string::npos);
    char pure[96]{};
    CHECK(alert_sentence(present(s), pure, sizeof pure) > 0);
    CHECK_EQ(std::string(pure), std::string(text));
    // Whichever nearby disconnect rule was reached.
    for (const Pattern rule : {Pattern::DeauthSource, Pattern::DeauthPair, Pattern::DeauthBroadcast}) {
        Presenter r(display()); r.update(mixed(rule, 1), at(1500));
        CHECK(alert_sentence(r.view(), text, sizeof text) > 0);
        CHECK_EQ(std::string(text), "Nearby burst also on home");
    }
    // A long name is shortened with a visible '~'; a hidden one has no name to print.
    auto l = mixed(Pattern::DeauthBroadcast, 3); l.selected.ssid_size = 32; l.selected.ssid.fill(std::uint8_t{'x'});
    l.last_security.network = l.selected; l.evidence[k].affected = l.selected;
    Presenter q(display()); q.update(l, at(1500));
    CHECK(alert_sentence(q.view(), text, sizeof text, 22) > 0);
    CHECK_EQ(std::string(text), "Nearby burst also on " + std::string(21, 'x') + "~");
    auto h = mixed(Pattern::DeauthBroadcast, 3); h.selected.ssid_size = 0; h.last_security.network = h.selected;
    h.last_security.ssid_kind = SsidKind::Hidden;
    Presenter hp(display()); hp.update(h, at(1500));
    CHECK(alert_sentence(hp.view(), text, sizeof text) > 0);
    CHECK_EQ(std::string(text), "Nearby burst also on your network");
    // The same rule reached on the picked network alone (no nearby burst) keeps its G16F sentence.
    const auto alone = mixed(Pattern::DeauthPair, 0);
    Presenter a(display()); a.update(alone, at(1500));
    CHECK_EQ(a.view().incident.own_frames, 0u);
    CHECK_EQ(std::string(a.view().alert_reason), "Disconnects aimed at one device on your network");
    CHECK(alert_sentence(a.view(), text, sizeof text) > 0);
    CHECK_EQ(std::string(text), "Disconnects aimed at one device on your network");
    char tiny[8]{'#'};
    CHECK_EQ(alert_sentence(v, tiny, sizeof tiny), 0u);
    CHECK_EQ(tiny[0], '\0');
}

// ---- G24: the device settings screen, its entry (hold FRONT) and the alert-first face (TDD, red first) ----
namespace {
DeviceChoices choice(GuardCycle g, std::uint8_t pct) { DeviceChoices c; c.guard = g; c.bright_pct = pct; return c; }
// G24 retry (owner 2026-11-21: "like side opens net list, blue opens settings"): hold FRONT on the face opens Settings.
void open_settings(Presenter& p, Instant now) { p.handle(Action::PrimaryLong, now); }
Snapshot red_alert(Millis acquired) {
    auto s = fresh(); s.incidents[0] = true; auto& e = s.evidence[0];
    e.acquired = at(acquired); e.count = 24; e.window_ms = 10000; e.bssid = home().bssid; s.incident_seq = 1; return s;
}
} // namespace

GUARDIAN_CASE(g24_device_choices_defaults_and_set_device) {
    Presenter p(display()); p.update(fresh(), at());
    CHECK(p.device() == DeviceChoices{}); CHECK(p.device().guard == GuardCycle::Always); CHECK_EQ(unsigned(p.device().bright_pct), 60u);
    CHECK_EQ(unsigned(p.lit_brightness_pct()), 60u);
    CHECK(p.set_device(choice(GuardCycle::EveryMinute, 30))); CHECK(p.device() == choice(GuardCycle::EveryMinute, 30));
    CHECK_EQ(unsigned(p.lit_brightness_pct()), 30u);
    CHECK(!p.set_device(choice(GuardCycle::Always, 45))); CHECK(p.device() == choice(GuardCycle::EveryMinute, 30));   // refused
    CHECK(!p.set_device(choice(static_cast<GuardCycle>(7), 60))); CHECK(p.device() == choice(GuardCycle::EveryMinute, 30));
    CHECK(!p.settings().open); CHECK(!p.has_settings_save());
}

GUARDIAN_CASE(g24_hold_front_opens_settings_from_the_face_and_from_details_never_demo) {
    // From the face.
    Presenter p(display()); p.update(fresh(), at());
    p.set_device(choice(GuardCycle::Every30s, 80));
    CHECK(p.handle(Action::PrimaryLong, at())); CHECK_EQ(p.screen(), Screen::Settings); CHECK_EQ(p.view().screen, Screen::Settings);
    CHECK_EQ(p.mode(), ViewMode::Live); CHECK(!p.view().demo);
    CHECK(p.settings().open); CHECK(p.settings().page == SettingsPage::Guard); CHECK_EQ(unsigned(p.settings().number), 1u);
    CHECK(p.settings().shown == choice(GuardCycle::Every30s, 80)); CHECK(p.settings().saved == choice(GuardCycle::Every30s, 80));
    CHECK(p.settings().plate == SavePlate::None);
    // From every details page, Nearby included.
    auto a = fresh(); a.area_visible[0] = true; a.area_visible_ms = 60000;
    a.area[0].scope = IncidentScope::Area; a.area[0].family = DetectorFamily::Probe; a.area[0].acquired = at(); a.area[0].count = 9;
    for (const auto page : {DetailsPage::Settings, DetailsPage::Explanation, DetailsPage::SignalAndEvidence, DetailsPage::OwnerChecks,
                            DetailsPage::Limits, DetailsPage::Nearby}) {
        Presenter q(display()); q.update(a, at()); q.handle(Action::Primary, at());
        for (int i = 0; i < 20 && q.screen() == Screen::Details && q.details().page != page; ++i) q.handle(Action::Primary, at());
        CHECK_EQ(q.screen(), Screen::Details); CHECK_EQ(q.details().page, page);
        CHECK(q.handle(Action::PrimaryLong, at())); CHECK_EQ(q.screen(), Screen::Settings); CHECK_EQ(q.mode(), ViewMode::Live);
        CHECK(q.settings().page == SettingsPage::Guard);
        q.handle(Action::Secondary, at()); CHECK_EQ(q.screen(), Screen::Face);   // SIDE leaves to the face
    }
    // Hold FRONT never enters DEMO, however often; a hold of FRONT on the Settings screen is a save, not a toggle.
    Presenter r(display()); r.update(fresh(), at());
    for (int i = 0; i < 4; ++i) {
        r.handle(Action::PrimaryLong, at()); CHECK_EQ(r.mode(), ViewMode::Live); CHECK(!r.view().demo);
        if (r.has_settings_save()) { r.take_settings_save(); r.settings_saved(true); }
    }
    // Somehow in DEMO (the direct method): hold FRONT returns to LIVE, on the face and on a details page.
    Presenter d(display()); d.update(fresh(), at()); CHECK(d.set_demo(true)); CHECK_EQ(d.mode(), ViewMode::Demo);
    CHECK(d.handle(Action::PrimaryLong, at())); CHECK_EQ(d.mode(), ViewMode::Live); CHECK_EQ(d.screen(), Screen::Face); CHECK(!d.settings().open);
    CHECK(d.set_demo(true)); d.handle(Action::Primary, at()); CHECK_EQ(d.screen(), Screen::Details); CHECK(d.details().demo);
    CHECK(d.handle(Action::PrimaryLong, at())); CHECK_EQ(d.mode(), ViewMode::Live); CHECK_EQ(d.screen(), Screen::Face);
    // The direct method both ways; a second call that changes nothing says so.
    CHECK(d.set_demo(true)); CHECK(!d.set_demo(true)); CHECK(d.set_demo(false)); CHECK(!d.set_demo(false)); CHECK_EQ(d.mode(), ViewMode::Live);
    // Hold SIDE keeps opening the network list from the face and from details.
    Presenter n(display()); n.update(fresh(), at()); CHECK(n.handle(Action::SecondaryLong, at())); CHECK_EQ(n.screen(), Screen::Picker);
    n.handle(Action::Back, at()); n.handle(Action::Primary, at()); CHECK(n.handle(Action::SecondaryLong, at())); CHECK_EQ(n.screen(), Screen::Picker);
}

GUARDIAN_CASE(g24_details_order_is_as_before_g24_and_side_always_goes_back) {
    // Face: FRONT -> Advertised Wi-Fi settings first; then Explanation, Signal, Owner checks, Limits, (Nearby), Face.
    Presenter p(display()); p.update(fresh(), at());
    CHECK(p.handle(Action::Primary, at())); CHECK_EQ(p.screen(), Screen::Details); CHECK_EQ(p.details().page, DetailsPage::Settings);
    CHECK_EQ(std::string(p.details().title), std::string("Advertised Wi-Fi settings"));
    const DetailsPage order[] = {DetailsPage::Explanation, DetailsPage::SignalAndEvidence, DetailsPage::OwnerChecks, DetailsPage::Limits};
    for (const auto page : order) {
        for (int i = 0; i < 20 && p.details().page != page && p.screen() == Screen::Details; ++i) {
            const auto before = p.details().page; p.handle(Action::Primary, at());
            CHECK(p.details().page == before || p.details().page == page);   // nothing in between (paginated pages repeat)
        }
        CHECK_EQ(p.details().page, page);
    }
    p.handle(Action::Primary, at()); CHECK_EQ(p.screen(), Screen::Face);
    // With something nearby: Limits, Nearby, then the face.
    auto a = fresh(); a.area_visible[0] = true; a.area_visible_ms = 60000;
    a.area[0].scope = IncidentScope::Area; a.area[0].family = DetectorFamily::Probe; a.area[0].acquired = at(); a.area[0].count = 9;
    Presenter n(display()); n.update(a, at()); n.handle(Action::Primary, at());
    for (int i = 0; i < 20 && n.details().page != DetailsPage::Limits; ++i) n.handle(Action::Primary, at());
    n.handle(Action::Primary, at()); CHECK_EQ(n.details().page, DetailsPage::Nearby);
    n.handle(Action::Primary, at()); CHECK_EQ(n.screen(), Screen::Face);
    // SIDE (and the abstract Back) from every page goes to the face; no page opens anything else.
    for (const auto page : {DetailsPage::Settings, DetailsPage::Explanation, DetailsPage::SignalAndEvidence, DetailsPage::OwnerChecks,
                            DetailsPage::Limits, DetailsPage::Nearby}) {
        for (const auto key : {Action::Secondary, Action::Back}) {
            Presenter q(display()); q.update(a, at()); q.handle(Action::Primary, at());
            for (int i = 0; i < 20 && q.details().page != page; ++i) q.handle(Action::Primary, at());
            CHECK_EQ(q.details().page, page); q.handle(key, at()); CHECK_EQ(q.screen(), Screen::Face);
        }
    }
    // The page count is back to six kinds (no DEVICE SETTINGS page).
    CHECK_EQ(static_cast<unsigned>(DetailsPage::Count), 6u);
}

GUARDIAN_CASE(g24_front_cycles_values_and_wraps_side_leaves_without_saving) {
    Presenter p(display()); p.update(fresh(), at());
    open_settings(p, at());
    CHECK(p.settings().shown.guard == GuardCycle::Always);
    CHECK(p.handle(Action::Primary, at())); CHECK(p.settings().shown.guard == GuardCycle::Every30s);
    CHECK(p.handle(Action::Primary, at())); CHECK(p.settings().shown.guard == GuardCycle::EveryMinute);
    CHECK(p.handle(Action::Primary, at())); CHECK(p.settings().shown.guard == GuardCycle::Always);   // wraps
    p.handle(Action::Primary, at()); CHECK(p.settings().shown.guard == GuardCycle::Every30s);
    CHECK(p.device() == DeviceChoices{}); CHECK(!p.has_settings_save());                          // a draft only
    CHECK_EQ(p.screen(), Screen::Settings);
    CHECK(p.handle(Action::Secondary, at())); CHECK_EQ(p.screen(), Screen::Face); CHECK(!p.settings().open);
    CHECK(p.device() == DeviceChoices{}); CHECK(!p.has_settings_save());
    // Opened again: the draft starts from the values in effect.
    open_settings(p, at()); CHECK(p.settings().shown.guard == GuardCycle::Always);
    // A hold of SIDE leaves too (never the network list from here).
    CHECK(p.handle(Action::SecondaryLong, at())); CHECK_EQ(p.screen(), Screen::Face);
    open_settings(p, at()); p.handle(Action::Back, at()); CHECK_EQ(p.screen(), Screen::Face);
}

GUARDIAN_CASE(g24_hold_front_saves_this_page_shows_saved_then_next_page_then_face) {
    Presenter p(display()); p.update(fresh(), at(1000));
    p.set_device(choice(GuardCycle::Always, 60));
    open_settings(p, at(1000));
    p.handle(Action::Primary, at(1000)); p.handle(Action::Primary, at(1000));                       // EVERY MINUTE
    CHECK(p.handle(Action::PrimaryLong, at(1000))); CHECK(p.has_settings_save());
    const auto save = p.take_settings_save(); CHECK(!p.has_settings_save());
    CHECK(save == choice(GuardCycle::EveryMinute, 60));                                             // this page only
    p.settings_saved(true);
    CHECK(p.settings().plate == SavePlate::Saved); CHECK(p.settings().page == SettingsPage::Guard);
    CHECK(p.device() == choice(GuardCycle::EveryMinute, 60)); CHECK(p.settings().saved == choice(GuardCycle::EveryMinute, 60));
    // FRONT during the plate does nothing; the plate stays for settings_plate_ms.
    CHECK(!p.handle(Action::Primary, at(1000 + Presenter::settings_plate_ms - 1)) || p.settings().shown.guard == GuardCycle::EveryMinute);
    CHECK(p.settings().shown.guard == GuardCycle::EveryMinute); CHECK(p.settings().plate == SavePlate::Saved);
    p.handle(Action::PrimaryLong, at(1000 + Presenter::settings_plate_ms - 1)); CHECK(!p.has_settings_save());
    p.update(fresh(), at(1000 + Presenter::settings_plate_ms));                                    // the plate's time is over
    CHECK(p.settings().plate == SavePlate::None); CHECK(p.settings().page == SettingsPage::Brightness);
    CHECK_EQ(unsigned(p.settings().number), 2u); CHECK_EQ(unsigned(p.settings().shown.bright_pct), 60u);
    // Brightness: 60 -> 80 -> 100 -> 10 (wraps) -> 30, previewed at once, saved by a hold.
    const Instant t = at(3000);
    p.handle(Action::Primary, t); CHECK_EQ(unsigned(p.settings().shown.bright_pct), 80u); CHECK_EQ(unsigned(p.lit_brightness_pct()), 80u);
    p.handle(Action::Primary, t); CHECK_EQ(unsigned(p.settings().shown.bright_pct), 100u);
    p.handle(Action::Primary, t); CHECK_EQ(unsigned(p.settings().shown.bright_pct), 10u); CHECK_EQ(unsigned(p.lit_brightness_pct()), 10u);
    p.handle(Action::Primary, t); CHECK_EQ(unsigned(p.settings().shown.bright_pct), 30u);
    CHECK_EQ(unsigned(p.device().bright_pct), 60u);
    p.handle(Action::PrimaryLong, t); CHECK(p.take_settings_save() == choice(GuardCycle::EveryMinute, 30)); p.settings_saved(true);
    CHECK(p.settings().plate == SavePlate::Saved); CHECK_EQ(p.screen(), Screen::Settings);
    p.handle(Action::Tick, at(3000 + Presenter::settings_plate_ms));                                // after the last page: Face
    CHECK_EQ(p.screen(), Screen::Face); CHECK(!p.settings().open); CHECK(p.device() == choice(GuardCycle::EveryMinute, 30));
    CHECK_EQ(unsigned(p.lit_brightness_pct()), 30u);
}

GUARDIAN_CASE(g24_a_failed_save_shows_save_failed_keeps_the_value_and_stays) {
    Presenter p(display()); p.update(fresh(), at(1000));
    open_settings(p, at(1000));
    p.handle(Action::Primary, at(1000));                                                             // EVERY 30 S
    p.handle(Action::PrimaryLong, at(1000)); CHECK(p.take_settings_save() == choice(GuardCycle::Every30s, 60));
    p.settings_saved(false);
    CHECK(p.settings().plate == SavePlate::Failed); CHECK(p.device() == DeviceChoices{});
    p.handle(Action::Tick, at(1000 + Presenter::settings_plate_ms));
    CHECK_EQ(p.screen(), Screen::Settings); CHECK(p.settings().page == SettingsPage::Guard); CHECK(p.settings().plate == SavePlate::None);
    CHECK(p.settings().shown.guard == GuardCycle::Every30s);                                       // the draft stays: try again
    // Without a report no plate shows; a second hold does not stack a second request.
    p.handle(Action::PrimaryLong, at(2500)); CHECK(p.has_settings_save());
    p.handle(Action::PrimaryLong, at(2500)); p.take_settings_save(); CHECK(!p.has_settings_save());
    CHECK(p.settings().plate == SavePlate::None);
    p.settings_saved(false); CHECK(p.settings().plate == SavePlate::Failed); CHECK(p.device() == DeviceChoices{});
    // A report with nothing taken changes nothing.
    Presenter q(display()); q.update(fresh(), at(1000)); q.settings_saved(true);
    CHECK(q.settings().plate == SavePlate::None); CHECK(q.device() == DeviceChoices{}); CHECK_EQ(q.screen(), Screen::Face);
    open_settings(q, at(1000)); q.handle(Action::Primary, at(1000)); q.settings_saved(true);
    CHECK(q.settings().plate == SavePlate::None); CHECK(q.device() == DeviceChoices{});
}

GUARDIAN_CASE(g24_the_brightness_preview_ends_when_leaving_and_the_side_leaves_during_a_plate) {
    Presenter p(display()); p.update(fresh(), at(1000)); p.set_device(choice(GuardCycle::Always, 60));
    open_settings(p, at(1000));
    p.handle(Action::PrimaryLong, at(1000)); p.take_settings_save(); p.settings_saved(true);       // guard saved as it was
    p.handle(Action::Tick, at(1000 + Presenter::settings_plate_ms));
    p.handle(Action::Primary, at(2500)); CHECK_EQ(unsigned(p.lit_brightness_pct()), 80u);           // previewed
    p.handle(Action::Secondary, at(2500)); CHECK_EQ(p.screen(), Screen::Face);
    CHECK_EQ(unsigned(p.lit_brightness_pct()), 60u);                                                // back to the value in effect
    // SIDE during a SAVED plate leaves at once (the save already happened).
    open_settings(p, at(3000)); p.handle(Action::Primary, at(3000));
    p.handle(Action::PrimaryLong, at(3000)); p.take_settings_save(); p.settings_saved(true);
    p.handle(Action::Secondary, at(3100)); CHECK_EQ(p.screen(), Screen::Face); CHECK(p.device().guard == GuardCycle::Every30s);
    CHECK(p.settings().plate == SavePlate::None);
}

GUARDIAN_CASE(g24_alert_first_a_new_red_alert_returns_to_the_face_amber_does_not) {
    // On a details page, the network list or the settings screen: a NEW red ALERT goes to the face.
    for (int where = 0; where < 3; ++where) {
        Presenter p(display()); p.update(fresh(), at(1000));
        if (where == 0) { p.handle(Action::Primary, at(1000)); p.handle(Action::Primary, at(1000)); CHECK_EQ(p.screen(), Screen::Details); }
        if (where == 1) { p.handle(Action::SecondaryLong, at(1000)); CHECK_EQ(p.screen(), Screen::Picker); }
        if (where == 2) { open_settings(p, at(1000)); p.handle(Action::Primary, at(1000)); CHECK_EQ(p.screen(), Screen::Settings); }
        p.update(red_alert(1500), at(1500));
        CHECK(p.view().alert); CHECK_EQ(p.screen(), Screen::Face); CHECK_EQ(p.view().screen, Screen::Face);
        CHECK(!p.settings().open); CHECK(!p.has_settings_save()); CHECK(p.device() == DeviceChoices{});   // the draft is dropped, nothing saved
        // While it lasts the owner may still look at the details (keys keep working) ...
        p.handle(Action::Primary, at(1600)); CHECK_EQ(p.screen(), Screen::Details);
        // ... and the same alert's next report (still on) does not pull the screen again.
        auto again = red_alert(1700); again.evidence[0].count = 40; again.incident_seq = 2;
        p.update(again, at(1700)); CHECK(p.view().alert); CHECK_EQ(p.screen(), Screen::Details);
        // Once it ended, a new red ALERT returns to the face again.
        p.handle(Action::Tick, at(1700 + Core::incident_ms)); CHECK(!p.view().alert); CHECK_EQ(p.screen(), Screen::Details);
        auto later = red_alert(1800 + Core::incident_ms); later.incident_seq = 3;
        p.update(later, at(1800 + Core::incident_ms)); CHECK(p.view().alert); CHECK_EQ(p.screen(), Screen::Face);
    }
    // Amber (a nearby observation) keeps today's behaviour: the open page stays.
    Presenter a(display()); a.update(fresh(), at(1000)); a.handle(Action::Primary, at(1000)); a.handle(Action::Primary, at(1000));
    auto amber = fresh(); amber.incident_seq = 4; amber.area_visible[0] = true; amber.area_visible_ms = 60000;
    amber.area[0].scope = IncidentScope::Area; amber.area[0].family = DetectorFamily::Probe; amber.area[0].acquired = at(1500); amber.area[0].count = 9;
    a.update(amber, at(1500)); CHECK(a.view().caution); CHECK(!a.view().alert); CHECK_EQ(a.screen(), Screen::Details);
    // Idle on the face: an alert keeps the face (nothing else changes).
    Presenter f(display()); f.update(fresh(), at(1000)); f.update(red_alert(1500), at(1500));
    CHECK_EQ(f.screen(), Screen::Face); CHECK(f.view().alert);
}

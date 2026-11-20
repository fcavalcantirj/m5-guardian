// BASELINE of the pre-existing presenter policy (G03). Not TDD.
//
// present() predates the TDD rule; these cases record its current policy so
// G08 changes are deliberate. The product rules they pin: stale/degraded
// evidence never shows a face, an incident beats celebration, imported and demo
// evidence are labelled and never celebrated.
#include "check.hpp"

#include "guardian/presenter.hpp"

using namespace guardian;

namespace {
Snapshot fresh(Mood mood, Finding reason = Finding::StrongSettings) {
    Snapshot s{};
    s.coverage = Coverage::Fresh;
    s.has_security = true;
    s.settings = {mood, reason};
    s.age_ms = 1200;
    return s;
}
} // namespace

GUARDIAN_CASE(checking_shows_checking_overlay_and_no_face) {
    const ViewModel v = present(Snapshot{});
    CHECK_EQ(v.overlay, Overlay::Checking);
    CHECK_EQ(v.face, Mood::Unknown);
    CHECK(!v.celebrate);
    CHECK(!v.incident_visible);
}

GUARDIAN_CASE(stale_shows_no_fresh_data_and_hides_the_old_grade) {
    Snapshot s = fresh(Mood::VeryGood);
    s.coverage = Coverage::Stale;
    s.age_ms = 45000;
    const ViewModel v = present(s);
    CHECK_EQ(v.overlay, Overlay::NoFreshData);
    CHECK_EQ(v.face, Mood::Unknown);  // a stale happy rating never looks current
    CHECK(!v.celebrate);
    CHECK_EQ(v.age_ms, Millis{45000});
}

GUARDIAN_CASE(degraded_shows_coverage_degraded_and_no_face) {
    Snapshot s = fresh(Mood::Good);
    s.coverage = Coverage::Degraded;
    const ViewModel v = present(s);
    CHECK_EQ(v.overlay, Overlay::CoverageDegraded);
    CHECK_EQ(v.face, Mood::Unknown);
    CHECK(!v.celebrate);
}

GUARDIAN_CASE(fresh_graded_shows_face_and_explanation) {
    for (Mood m : {Mood::VeryGood, Mood::Good, Mood::Medium, Mood::Bad, Mood::Horrible}) {
        const ViewModel v = present(fresh(m, Finding::Legacy));
        CHECK_EQ(v.face, m);
        CHECK_EQ(v.explanation, Finding::Legacy);
        CHECK_EQ(v.overlay, Overlay::None);
        CHECK_EQ(v.celebrate, m == Mood::VeryGood); // only the top mood celebrates
    }
}

GUARDIAN_CASE(fresh_but_ungraded_shows_unsupported_overlay) {
    const ViewModel v = present(fresh(Mood::Unknown, Finding::Unknown));
    CHECK_EQ(v.overlay, Overlay::Unsupported);
    CHECK_EQ(v.face, Mood::Unknown);
    CHECK(!v.celebrate);
}

GUARDIAN_CASE(incident_overlay_beats_celebration_and_keeps_the_face) {
    Snapshot s = fresh(Mood::VeryGood);
    s.incidents[static_cast<std::size_t>(IncidentKind::DisconnectBurst)] = true;
    const ViewModel v = present(s);
    CHECK(v.incident_visible);
    CHECK_EQ(v.overlay, Overlay::Incident);
    CHECK_EQ(v.face, Mood::VeryGood); // the grade stays visible, the cigar does not
    CHECK(!v.celebrate);
}

GUARDIAN_CASE(incident_flag_is_visible_even_while_checking_or_stale) {
    Snapshot s{};
    s.incidents[static_cast<std::size_t>(IncidentKind::UnexpectedAp)] = true;
    CHECK(present(s).incident_visible);
    s = fresh(Mood::Good);
    s.coverage = Coverage::Stale;
    s.incidents[static_cast<std::size_t>(IncidentKind::SettingsChanged)] = true;
    CHECK(present(s).incident_visible);
    CHECK_EQ(present(s).overlay, Overlay::NoFreshData); // coverage overlay wins the slot today
}

GUARDIAN_CASE(imported_origin_is_historical_and_never_celebrates) {
    Snapshot s = fresh(Mood::VeryGood);
    s.origin = Origin::Imported;
    const ViewModel v = present(s);
    CHECK(v.historical);
    CHECK(!v.demo);
    CHECK_EQ(v.face, Mood::VeryGood);
    CHECK(!v.celebrate);
}

GUARDIAN_CASE(demo_origin_is_flagged) {
    Snapshot s = fresh(Mood::VeryGood);
    s.origin = Origin::Demo;
    const ViewModel v = present(s);
    CHECK(v.demo);
    CHECK(!v.historical);
}

GUARDIAN_CASE(KNOWN_LIMIT_demo_origin_still_celebrates) {
    // present() suppresses celebration for Imported but not for Demo. G08 decides
    // the DEMO/live separation policy; this pins today's behavior.
    Snapshot s = fresh(Mood::VeryGood);
    s.origin = Origin::Demo;
    CHECK(present(s).celebrate);
}

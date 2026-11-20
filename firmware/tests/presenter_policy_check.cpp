// G08 behavioral RED against the pre-existing present() reducer.
#include "check.hpp"
#include "guardian/presenter.hpp"
using namespace guardian;

GUARDIAN_CASE(stale_art_is_explicitly_muted_with_reason_and_incident_evidence) {
    Snapshot s{};
    s.coverage = Coverage::Stale;
    s.settings.reason = Finding::Legacy;
    s.incidents[0] = true;
    s.evidence[0].count = 23;
    s.evidence[0].coverage_known = true;
    s.evidence[0].listened_ms = 4000;
    s.evidence[0].coverage_window_ms = 10000;
    const auto v = present(s);
    CHECK(v.muted);
    CHECK_EQ(v.explanation, Finding::Legacy);
    CHECK(v.incident.visible);
    CHECK_EQ(v.incident.count, 23u);
    CHECK_EQ(v.incident.listened_ms, Millis{4000});
    CHECK_EQ(v.overlay, Overlay::NoFreshData);
    CHECK(!v.celebrate);
}

GUARDIAN_CASE(historical_and_unrated_views_are_muted) {
    Snapshot s{};
    s.coverage = Coverage::Fresh;
    s.settings.mood = Mood::VeryGood;
    s.origin = Origin::Imported;
    CHECK(present(s).muted);
    s.origin = Origin::LiveRadio;
    s.security_historical = true;
    CHECK(present(s).historical);
    CHECK_EQ(present(s).face, Mood::Unknown);
    CHECK(!present(s).celebrate);
    s.security_historical = false;
    s.settings.mood = Mood::Unknown;
    s.settings.unrated = Unrated::Incomplete;
    CHECK(present(s).muted);
    CHECK_EQ(present(s).unrated, Unrated::Incomplete);
}

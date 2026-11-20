// G16C rework (2): console writes never block the companion's observation loop
// and dropout causes are counted (boards/sticks3/main/link_health.hpp).
#include "check.hpp"
#include "link_health.hpp"
#include <cstring>
#include <string>

using namespace sticks3;
using guardian::Overlay;

GUARDIAN_CASE(companion_console_never_waits_and_never_counts_as_a_lost_frame) {
    constexpr auto c = write_policy(ConsoleOwner::Companion);
    CHECK_EQ(c.timeout_ms, 0u); CHECK(!c.counts_as_frame_drop);
    constexpr auto lab = write_policy(ConsoleOwner::Lab);   // G13 lab stream: accepted policy unchanged
    CHECK_EQ(lab.timeout_ms, 5u); CHECK(lab.counts_as_frame_drop);
}
GUARDIAN_CASE(console_writes_and_stalls_are_counted) {
    LinkHealth h;
    h.console_write(true, 120); h.console_write(false, 5300); h.console_write(true, -4);
    CHECK_EQ(h.write_drops(), 1u); CHECK_EQ(h.stall_us(), std::uint64_t{5420}); CHECK_EQ(h.stall_max_us(), 5300u);
    h.log_line(true); h.log_line(false); h.log_line(false);
    CHECK_EQ(h.log_drops(), 2u);
    char text[256]; h.status_text(text, sizeof text);
    const std::string s(text);
    CHECK(s.find("console_writes=3 console_drops=1 console_stall_ms=5.4/5.3") != std::string::npos);
    CHECK(s.find("log_lines=3 log_drops=2") != std::string::npos);
}
GUARDIAN_CASE(overlay_transitions_count_entries_not_durations) {
    LinkHealth h;
    h.overlay(Overlay::Checking); h.overlay(Overlay::None);
    for (int i = 0; i < 50; ++i) h.overlay(Overlay::CoverageDegraded);   // one 5 s episode at 100 ms ticks
    CHECK_EQ(h.degraded_transitions(), 1u);
    h.overlay(Overlay::None); h.overlay(Overlay::CoverageDegraded); h.overlay(Overlay::NoFreshData); h.overlay(Overlay::NoFreshData);
    CHECK_EQ(h.degraded_transitions(), 2u); CHECK_EQ(h.no_data_transitions(), 1u);
    h.overlay(Overlay::Incident); h.overlay(Overlay::NoFreshData);
    CHECK_EQ(h.no_data_transitions(), 2u);
    LinkHealth boot; boot.overlay(Overlay::NoFreshData);   // the first sample at boot is a state too
    CHECK_EQ(boot.no_data_transitions(), 1u);
    char text[256]; h.status_text(text, sizeof text);
    CHECK(std::strstr(text, "degraded_transitions=2 nodata_transitions=2") != nullptr);
}

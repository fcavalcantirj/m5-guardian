// G24: the guard listen cycle on battery (components/guardian_core/guard_cycle.cpp), host TDD red first.
// Rules (guardian-tasks.json G24): off only on battery + Dark; listen first from the instant the screen went
// dark; immediate resume on any wake (screen lit, USB); the update poll is not delayed and gets the radio;
// Always is exactly today (radio on, no lever, whatever the power source and screen).
#include "check.hpp"
#include "guardian/guard_cycle.hpp"
#include <cstring>

using namespace guardian;

namespace {
CycleInput dark_on_battery(GuardCycle c, Millis since, Millis now) {
    CycleInput in; in.choice = c; in.on_battery = true; in.dark = true; in.dark_since = since; in.now = now; return in;
}
bool today(const CyclePlan& p) { return p.radio_on && !p.levers && !p.light_sleep && p.phase_left_ms == 0; }
} // namespace

GUARDIAN_CASE(timings_names_and_stored_values) {
    CHECK_EQ(cycle_timing(GuardCycle::Always).listen_ms, Millis{0}); CHECK_EQ(cycle_timing(GuardCycle::Always).off_ms, Millis{0});
    CHECK_EQ(cycle_timing(GuardCycle::Every30s).listen_ms, Millis{10000}); CHECK_EQ(cycle_timing(GuardCycle::Every30s).off_ms, Millis{20000});
    CHECK_EQ(cycle_timing(GuardCycle::EveryMinute).listen_ms, Millis{10000}); CHECK_EQ(cycle_timing(GuardCycle::EveryMinute).off_ms, Millis{50000});
    CHECK(std::strcmp(guard_cycle_name(GuardCycle::Always), "always") == 0);
    CHECK(std::strcmp(guard_cycle_name(GuardCycle::Every30s), "every_30s") == 0);
    CHECK(std::strcmp(guard_cycle_name(GuardCycle::EveryMinute), "every_minute") == 0);
    CHECK(std::strcmp(guard_cycle_name(static_cast<GuardCycle>(9)), "?") == 0);
    GuardCycle g = GuardCycle::EveryMinute;
    CHECK(guard_cycle_from(0, g)); CHECK(g == GuardCycle::Always);
    CHECK(guard_cycle_from(1, g)); CHECK(g == GuardCycle::Every30s);
    CHECK(guard_cycle_from(2, g)); CHECK(g == GuardCycle::EveryMinute);
    CHECK(!guard_cycle_from(3, g)); CHECK(g == GuardCycle::EveryMinute);   // untouched
    CHECK(!guard_cycle_from(255, g)); CHECK(g == GuardCycle::EveryMinute);
    CHECK_EQ(unsigned(guard_cycle_count), 3u);
}

GUARDIAN_CASE(always_is_today_in_every_state) {
    for (const bool battery : {false, true}) for (const bool dark : {false, true}) for (const bool upd : {false, true})
        for (const Millis now : {Millis{0}, Millis{15000}, Millis{59999}, Millis{3600000}}) {
            CycleInput in; in.choice = GuardCycle::Always; in.on_battery = battery; in.dark = dark; in.updating = upd; in.now = now;
            CHECK(today(guard_cycle_plan(in)));
        }
}

GUARDIAN_CASE(cycled_choices_act_only_on_battery_while_dark) {
    for (const auto c : {GuardCycle::Every30s, GuardCycle::EveryMinute}) {
        // On USB (or unknown power), lit or dim: today's plan at every instant of what would be an off period.
        for (const bool battery : {false, true}) for (const bool dark : {false, true}) {
            if (battery && dark) continue;
            for (const Millis now : {Millis{1000}, Millis{25000}, Millis{40000}}) {
                CycleInput in = dark_on_battery(c, 0, now); in.on_battery = battery; in.dark = dark;
                CHECK(today(guard_cycle_plan(in)));
            }
        }
        // On battery and dark: armed (levers) at once, listening first.
        const auto p = guard_cycle_plan(dark_on_battery(c, 1000, 1000));
        CHECK(p.levers); CHECK(p.radio_on); CHECK(!p.light_sleep); CHECK_EQ(p.phase_left_ms, Millis{10000});
    }
}

GUARDIAN_CASE(every_minute_listens_10_s_then_off_50_s_from_the_dark_start) {
    const Millis t0 = 123456;
    struct Row { Millis at; bool radio; Millis left; };
    const Row rows[] = {
        {0, true, 10000}, {9999, true, 1}, {10000, false, 50000}, {35000, false, 25000}, {59999, false, 1},
        {60000, true, 10000}, {69999, true, 1}, {70000, false, 50000}, {120000, true, 10000}, {3600000 + 5000, true, 5000},
    };
    for (const auto& r : rows) {
        const auto p = guard_cycle_plan(dark_on_battery(GuardCycle::EveryMinute, t0, t0 + r.at));
        CHECK(p.levers); CHECK_EQ(p.radio_on, r.radio); CHECK_EQ(p.light_sleep, !r.radio); CHECK_EQ(p.phase_left_ms, r.left);
    }
    // Over one hour: listening 10 of every 60 s.
    Millis listening = 0;
    for (Millis t = 0; t < 3600000; t += 100) if (guard_cycle_plan(dark_on_battery(GuardCycle::EveryMinute, t0, t0 + t)).radio_on) listening += 100;
    CHECK_EQ(listening, Millis{600000});
}

GUARDIAN_CASE(every_30_s_listens_10_s_then_off_20_s) {
    const Millis t0 = 5000;
    struct Row { Millis at; bool radio; Millis left; };
    const Row rows[] = {{0, true, 10000}, {10000, false, 20000}, {29999, false, 1}, {30000, true, 10000}, {40000, false, 20000}, {60000, true, 10000}};
    for (const auto& r : rows) {
        const auto p = guard_cycle_plan(dark_on_battery(GuardCycle::Every30s, t0, t0 + r.at));
        CHECK(p.levers); CHECK_EQ(p.radio_on, r.radio); CHECK_EQ(p.light_sleep, !r.radio); CHECK_EQ(p.phase_left_ms, r.left);
    }
    Millis listening = 0;
    for (Millis t = 0; t < 600000; t += 100) if (guard_cycle_plan(dark_on_battery(GuardCycle::Every30s, t0, t0 + t)).radio_on) listening += 100;
    CHECK_EQ(listening, Millis{200000});   // 10 of every 30 s
}

GUARDIAN_CASE(any_wake_resumes_at_once_without_waiting_for_the_cycle) {
    // In the middle of an off period (35 s into a dark spell): a key, motion, a counted burst or USB.
    const auto off = guard_cycle_plan(dark_on_battery(GuardCycle::EveryMinute, 0, 35000));
    CHECK(!off.radio_on); CHECK(off.levers);
    CycleInput lit = dark_on_battery(GuardCycle::EveryMinute, 0, 35000); lit.dark = false;   // the screen lit
    CHECK(today(guard_cycle_plan(lit)));
    CycleInput usb = dark_on_battery(GuardCycle::EveryMinute, 0, 35000); usb.on_battery = false;   // plugged in
    CHECK(today(guard_cycle_plan(usb)));
    // Dark again later: the new dark spell listens first (its own origin), never inherits the old phase.
    const auto again = guard_cycle_plan(dark_on_battery(GuardCycle::EveryMinute, 90000, 90000));
    CHECK(again.radio_on); CHECK(again.levers); CHECK_EQ(again.phase_left_ms, Millis{10000});
    // A clock that reads before the dark start (never expected) listens rather than going blind.
    const auto early = guard_cycle_plan(dark_on_battery(GuardCycle::EveryMinute, 50000, 40000));
    CHECK(early.radio_on); CHECK(!early.light_sleep);
}

GUARDIAN_CASE(the_update_poll_gets_the_radio_and_is_not_delayed) {
    // Due in an off period: the radio is on for its join and light sleep is off; the levers stay as they are.
    CycleInput in = dark_on_battery(GuardCycle::EveryMinute, 0, 30000); in.updating = true;
    const auto p = guard_cycle_plan(in);
    CHECK(p.radio_on); CHECK(!p.light_sleep); CHECK(p.levers);
    // The plan never says when a poll may run: same plan for the listen part whatever `updating` says.
    CycleInput listen = dark_on_battery(GuardCycle::EveryMinute, 0, 5000), listen_upd = listen; listen_upd.updating = true;
    CHECK_EQ(guard_cycle_plan(listen).radio_on, guard_cycle_plan(listen_upd).radio_on);
    CHECK_EQ(guard_cycle_plan(listen).phase_left_ms, guard_cycle_plan(listen_upd).phase_left_ms);
}

GUARDIAN_CASE(stats_count_cycles_failures_and_relock) {
    CycleStats s;
    CHECK_EQ(s.cycles(), 0u); CHECK_EQ(s.resume_fail(), 0u); CHECK_EQ(s.relock_ms_avg(), 0u); CHECK(!s.waiting_lock());
    s.stopped(10000); s.resumed(60000, true); CHECK(s.waiting_lock());
    s.locked(63000); CHECK(!s.waiting_lock());
    s.locked(64000);                                    // a second lock of the same restart is not counted
    CHECK_EQ(s.cycles(), 1u); CHECK_EQ(s.relocks(), 1u); CHECK_EQ(s.relock_ms_avg(), 3000u);
    s.stopped(70000); s.resumed(120000, true); s.locked(125000);
    CHECK_EQ(s.cycles(), 2u); CHECK_EQ(s.relock_ms_avg(), 4000u);
    s.stopped(130000); s.resumed(180000, false);        // the restart failed
    CHECK_EQ(s.cycles(), 3u); CHECK_EQ(s.resume_fail(), 1u); CHECK(!s.waiting_lock());
    s.failed(); CHECK_EQ(s.resume_fail(), 2u);
    s.resumed(190000, true); CHECK_EQ(s.cycles(), 3u); CHECK(!s.waiting_lock());   // a resume without a stop is no cycle
    s.locked(191000); CHECK_EQ(s.relocks(), 2u);                                   // ... and no relock time
    // A restart that never relocked before the next stop: no relock time, the average is unchanged.
    s.stopped(200000); s.resumed(250000, true); s.stopped(260000);
    CHECK_EQ(s.cycles(), 4u); CHECK_EQ(s.relocks(), 2u); CHECK_EQ(s.relock_ms_avg(), 4000u);
}

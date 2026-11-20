// G16H: the Wi-Fi/BLE coexistence spike instrument (adapters/coex/coex_spike.*):
// duty validity, the interleaved OFF/ON phase plan, raw beacon classification,
// the phase recorder (settle, deltas, faults, abort), the verdict rule and the
// console lines. Host, SDK-free. The radio measurement itself is on the device.
#include "check.hpp"
#include "coex_spike.hpp"
#include <cmath>
#include <cstring>
#include <string>
#include <vector>

using namespace guardian::coex;

namespace {
const Mac ap{{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
const Mac other{{0x02, 0x99, 0x88, 0x77, 0x66, 0x55}};

std::vector<std::uint8_t> beacon(const Mac& bssid, std::uint16_t interval_tu = 100, std::uint8_t fc0 = 0x80, std::uint8_t fc1 = 0x00) {
    std::vector<std::uint8_t> f(24 + 12 + 2, 0);
    f[0] = fc0; f[1] = fc1;
    for (std::size_t i = 0; i < 6; ++i) { f[4 + i] = 0xff; f[10 + i] = bssid[i]; f[16 + i] = bssid[i]; }
    f[32] = static_cast<std::uint8_t>(interval_tu & 0xff);
    f[33] = static_cast<std::uint8_t>(interval_tu >> 8);
    return f;
}

Plan small_plan() {   // 2 levels, 10 s phases, 1 s settle, 2 rounds = 9 phases
    Plan p;
    p.levels[0] = {30, 300};
    p.levels[1] = {150, 300};
    p.level_count = 2;
    p.phase_ms = 10000;
    p.settle_ms = 1000;
    p.rounds = 2;
    return p;
}

Sample locked(std::uint8_t channel = 6, std::uint32_t heap = 60000) {
    Sample s;
    s.heap_internal_free = heap; s.vbat_ok = true; s.vbat_mv = 4000; s.monitoring = true; s.channel = channel;
    return s;
}

// A result as the recorder would produce it (for the verdict cases).
PhaseResult phase(int level, const Duty& duty, std::uint32_t ms, std::uint32_t beacons, std::uint32_t frames = 0,
                  std::uint32_t queue_full = 0, std::uint32_t heap = 60000, PhaseFault fault = PhaseFault::None) {
    PhaseResult r;
    r.level = static_cast<std::int8_t>(level); r.duty = duty; r.fault = fault; r.channel = 6;
    r.measured_ms = ms; r.beacons = beacons; r.beacon_interval_tu = 100;
    r.frames = frames ? frames : beacons * 4; r.queue_full = queue_full; r.heap_min = heap;
    r.monitoring_at_end = fault != PhaseFault::NotMonitoring;
    return r;
}

// Builds a full run for `plan` where the OFF rate is `off_per_s` beacons and level i keeps ratio[i] of them.
std::vector<PhaseResult> run_of(const Plan& plan, double off_per_s, const std::vector<double>& ratio) {
    std::vector<PhaseResult> out;
    const auto ms = plan.phase_ms - plan.settle_ms;
    for (std::size_t i = 0; i < phase_count(plan); ++i) {
        const int level = phase_level(plan, i);
        const double keep = level < 0 ? 1.0 : ratio[static_cast<std::size_t>(level)];
        out.push_back(phase(level, phase_duty(plan, i), ms, static_cast<std::uint32_t>(std::lround(off_per_s * keep * ms / 1000.0))));
    }
    return out;
}
} // namespace

GUARDIAN_CASE(duty_validity_and_units) {
    CHECK(valid(Duty{}));                       // off
    CHECK(!Duty{}.on());
    CHECK_EQ(Duty{}.permille(), 0u);
    CHECK(valid(Duty{30, 300}));
    CHECK_EQ((Duty{30, 300}.permille()), 100u);
    CHECK_EQ((Duty{30, 1000}.permille()), 30u);
    CHECK_EQ((Duty{300, 300}.permille()), 1000u);
    CHECK(!valid(Duty{301, 300}));              // window longer than the interval
    CHECK(!valid(Duty{2, 300}));                // below 2.5 ms
    CHECK(valid(Duty{3, 3}));
    CHECK(!valid(Duty{30, 10241}));             // above 10.24 s
    CHECK(valid(Duty{30, 10240}));
    CHECK_EQ(ble_units(30), 48u);
    CHECK_EQ(ble_units(300), 480u);
    CHECK_EQ(ble_units(10240), 16384u);
}

GUARDIAN_CASE(default_plan_interleaves_off_around_every_scan) {
    const Plan p = default_plan();
    CHECK(valid(p));
    CHECK_EQ(p.level_count, 4u);
    CHECK_EQ(p.rounds, 2u);
    CHECK_EQ(p.phase_ms, 60000u);
    CHECK_EQ(p.settle_ms, 3000u);
    CHECK_EQ((p.levels[0].permille()), 30u);
    CHECK_EQ((p.levels[1].permille()), 100u);
    CHECK_EQ((p.levels[2].permille()), 250u);
    CHECK_EQ((p.levels[3].permille()), 500u);
    CHECK_EQ(phase_count(p), 17u);
    const int expected[17] = {-1, 0, -1, 1, -1, 2, -1, 3, -1, 0, -1, 1, -1, 2, -1, 3, -1};
    for (std::size_t i = 0; i < 17; ++i) CHECK_EQ(phase_level(p, i), expected[i]);
    for (std::size_t i = 0; i < 17; ++i) {
        if (phase_level(p, i) < 0) { CHECK(!phase_duty(p, i).on()); continue; }
        CHECK(phase_duty(p, i).on());
        CHECK(i > 0 && i + 1 < 17);
        CHECK_EQ(phase_level(p, i - 1), -1);
        CHECK_EQ(phase_level(p, i + 1), -1);
    }
    CHECK_EQ(phase_level(p, 17), -1);           // past the end: off
    CHECK(!phase_duty(p, 17).on());
}

GUARDIAN_CASE(invalid_plans_are_refused) {
    Plan p = small_plan();
    CHECK(valid(p));
    CHECK_EQ(phase_count(p), 9u);
    Plan q = p; q.level_count = 0; CHECK(!valid(q)); CHECK_EQ(phase_count(q), 0u);
    q = p; q.level_count = 7; CHECK(!valid(q));
    q = p; q.rounds = 0; CHECK(!valid(q));
    q = p; q.rounds = 5; CHECK(!valid(q));
    q = p; q.settle_ms = q.phase_ms; CHECK(!valid(q));
    q = p; q.levels[1] = Duty{}; CHECK(!valid(q));             // a scanning level must scan
    q = p; q.levels[1] = Duty{400, 300}; CHECK(!valid(q));
    q = p; q.phase_ms = 999; q.settle_ms = 0; CHECK(!valid(q)); // below 1 s
    // Largest plan fits the fixed table.
    q = p; q.level_count = max_levels; q.rounds = max_rounds;
    for (auto& l : q.levels) l = Duty{30, 300};
    CHECK(valid(q));
    CHECK_EQ(phase_count(q), max_phases);
}

GUARDIAN_CASE(classify_counts_only_selected_beacons) {
    auto b = beacon(ap, 100);
    auto s = classify(b.data(), b.size(), ap);
    CHECK(s.from_selected);
    CHECK_EQ(s.interval_tu, 100u);
    b = beacon(ap, 0x0190);
    CHECK_EQ(classify(b.data(), b.size(), ap).interval_tu, 400u);
    b = beacon(other);
    CHECK(!classify(b.data(), b.size(), ap).from_selected);
    b = beacon(ap, 100, 0x50);                  // probe response
    CHECK(!classify(b.data(), b.size(), ap).from_selected);
    b = beacon(ap, 100, 0x80, 0x01);            // ToDS set: not a beacon
    CHECK(!classify(b.data(), b.size(), ap).from_selected);
    b = beacon(ap, 100, 0x81);                  // protocol version 1
    CHECK(!classify(b.data(), b.size(), ap).from_selected);
    b = beacon(ap);
    CHECK(!classify(b.data(), 35, ap).from_selected);   // fixed fields cut
    CHECK(classify(b.data(), 36, ap).from_selected);
    CHECK(!classify(nullptr, 64, ap).from_selected);
    b = beacon(ap, 100, 0x80, 0x08);            // retry flag: still a beacon of the AP
    CHECK(classify(b.data(), b.size(), ap).from_selected);
}

GUARDIAN_CASE(start_is_refused_when_running_or_unscoped) {
    Spike s;
    Spike::Step first;
    CHECK(!s.start(small_plan(), Mac{}, 0, first));        // no selected AP
    Plan bad = small_plan(); bad.rounds = 0;
    CHECK(!s.start(bad, ap, 0, first));
    CHECK(!s.running());
    CHECK(s.start(small_plan(), ap, 1000, first));
    CHECK(first.apply);
    CHECK(!first.duty.on());                                 // phase 0 is OFF
    CHECK(s.running());
    CHECK(!s.start(small_plan(), ap, 1000, first));          // already running
    CHECK_EQ(s.phase(), 0u);
}

GUARDIAN_CASE(run_records_every_phase_with_settle_and_deltas) {
    const Plan p = small_plan();
    Spike s;
    Spike::Step st;
    CHECK(s.start(p, ap, 0, st));
    Counters c;
    const auto b = beacon(ap, 100);
    const auto x = beacon(other, 100);
    std::vector<Duty> applied;
    std::size_t done = 0;
    bool finished = false;
    // 100 ms loop (the board's order: service, then the frames that arrived): 1 beacon of the AP
    // and 1 of a neighbour each tick, 3 callbacks, 1 display frame; during level 1 every second
    // AP beacon is lost (no callback either).
    for (std::uint64_t t = 0; t <= 9 * 10000 + 100 && !finished; t += 100) {
        st = s.tick(t, c, locked(6, 60000 - static_cast<std::uint32_t>(t / 100)));
        if (st.apply) applied.push_back(st.duty);
        if (st.phase_done) ++done;
        finished = st.finished;
        if (finished) break;
        const bool lossy = phase_level(p, s.phase()) == 1 && (t / 100) % 2 == 1;
        if (!lossy) { s.frame(b.data(), b.size(), t); c.frames += 1; }
        s.frame(x.data(), x.size(), t);
        c.frames += 2; c.display_frames += 1;
        if (phase_duty(p, s.phase()).on()) c.adv_reports += 5;
    }
    CHECK(finished);
    CHECK(s.finished());
    CHECK(!s.running());
    CHECK_EQ(s.completed(), 9u);
    CHECK_EQ(done, 9u);
    // Every boundary applied the next phase's duty, and the end switched scanning off.
    CHECK_EQ(applied.size(), 9u);
    for (std::size_t i = 0; i + 1 < applied.size(); ++i) CHECK_EQ(applied[i].window_ms, phase_duty(p, i + 1).window_ms);
    CHECK(!applied.back().on());
    for (std::size_t i = 0; i < 9; ++i) {
        const auto& r = s.result(i);
        CHECK(r.valid());
        CHECK_EQ(r.level, phase_level(p, i));
        CHECK_EQ(r.channel, 6u);
        CHECK_EQ(r.measured_ms, 9000u);                // phase minus settle
        CHECK_EQ(r.beacon_interval_tu, 100u);
        CHECK_EQ(r.display_frames, 90u);
        if (r.level == 1) { CHECK_EQ(r.beacons, 45u); CHECK_EQ(r.frames, 225u); }
        else { CHECK_EQ(r.beacons, 90u); CHECK_EQ(r.frames, 270u); }
        CHECK_EQ(r.adv_reports, r.duty.on() ? 450u : 0u);
        CHECK(r.vbat_ok);
        CHECK_EQ(r.vbat_start_mv, 4000u);
        CHECK(r.heap_min < 60000u - static_cast<std::uint32_t>(i * 100));   // the lowest value of the phase
    }
    // After the run nothing more is counted or applied.
    st = s.tick(200000, c, locked());
    CHECK(!st.apply);
    CHECK_EQ(s.completed(), 9u);
}

GUARDIAN_CASE(frames_outside_the_measured_window_are_ignored) {
    Plan p = small_plan();
    Spike s;
    Spike::Step st;
    CHECK(s.start(p, ap, 0, st));
    const auto b = beacon(ap);
    Counters c;
    s.frame(b.data(), b.size(), 500);            // settle: ignored
    st = s.tick(1000, c, locked());              // measuring from 1000
    s.frame(b.data(), b.size(), 999);            // acquired before the window, delivered late: ignored
    s.frame(b.data(), b.size(), 1000);           // counted
    s.frame(b.data(), b.size(), 9999);           // counted
    st = s.tick(10000, c, locked());
    CHECK(st.phase_done);
    s.frame(b.data(), b.size(), 10000);          // next phase's settle: not added to phase 0
    CHECK_EQ(s.result(0).beacons, 2u);
    CHECK_EQ(s.result(0).measured_ms, 9000u);
}

GUARDIAN_CASE(channel_change_unlock_and_abort_mark_the_phase) {
    Plan p = small_plan();
    Spike s;
    Spike::Step st;
    Counters c;
    CHECK(s.start(p, ap, 0, st));
    st = s.tick(1000, c, locked(6));
    st = s.tick(4000, c, locked(11));            // the survey moved to another channel
    st = s.tick(10000, c, locked(6));
    CHECK(st.phase_done);
    CHECK_EQ(s.result(0).fault, PhaseFault::ChannelChanged);
    Sample lost = locked(6); lost.monitoring = false;
    st = s.tick(12000, c, lost);                 // rediscovery during phase 1
    st = s.tick(20000, c, locked(6));
    CHECK_EQ(s.result(1).fault, PhaseFault::NotMonitoring);
    st = s.tick(25000, c, locked(6));
    st = s.abort();
    CHECK(st.apply);
    CHECK(!st.duty.on());                        // scanning off
    CHECK(!s.running());
    CHECK(!s.finished());                        // aborted, not completed
    CHECK_EQ(s.completed(), 3u);
    CHECK_EQ(s.result(2).fault, PhaseFault::Aborted);
    st = s.abort();                              // idempotent
    CHECK(!st.apply);
    CHECK_EQ(s.completed(), 3u);
    // A stalled loop that never measured the window: too short.
    Spike t;
    CHECK(t.start(p, ap, 0, st));
    st = t.tick(9999, c, locked());              // first sample after settle, then the phase ends
    st = t.tick(10000, c, locked());
    CHECK_EQ(t.result(0).fault, PhaseFault::TooShort);
    CHECK_EQ(std::string(fault_text(PhaseFault::TooShort)), std::string("too_short"));
    CHECK_EQ(std::string(fault_text(PhaseFault::None)), std::string("ok"));
}

GUARDIAN_CASE(verdict_picks_the_highest_acceptable_duty) {
    const Plan p = small_plan();
    const auto run = run_of(p, 9.766, {0.99, 0.80});
    Criteria k; k.min_expected_beacons = 100;
    const Report r = evaluate(p, run.data(), run.size(), k);
    CHECK_EQ(r.level_count, 2u);
    CHECK_EQ(r.phases, 9u);
    CHECK_EQ(r.valid_phases, 9u);
    CHECK_EQ(r.levels[0].verdict, Verdict::Acceptable);
    CHECK_EQ(std::string(r.levels[0].reason), std::string("ok"));
    CHECK_EQ(r.levels[0].pairs, 2u);
    CHECK(r.levels[0].beacon_ratio > 0.985 && r.levels[0].beacon_ratio < 0.995);
    CHECK_EQ(r.levels[1].verdict, Verdict::Unacceptable);
    CHECK_EQ(std::string(r.levels[1].reason), std::string("beacon_loss"));
    CHECK(r.levels[1].beacon_ratio > 0.79 && r.levels[1].beacon_ratio < 0.81);
    CHECK_EQ(r.overall, Verdict::Acceptable);
    CHECK_EQ(r.best_level, 0);
    CHECK(r.reference_delivery > 0.99 && r.reference_delivery < 1.01);   // 9.766 beacons/s at 100 TU
    // Both fine: the higher duty is the best.
    const auto both = run_of(p, 9.766, {1.0, 0.97});
    CHECK_EQ(evaluate(p, both.data(), both.size(), k).best_level, 1);
}

GUARDIAN_CASE(verdict_unacceptable_only_when_every_level_fails) {
    const Plan p = small_plan();
    Criteria k; k.min_expected_beacons = 100;
    const auto bad = run_of(p, 9.766, {0.90, 0.50});
    Report r = evaluate(p, bad.data(), bad.size(), k);
    CHECK_EQ(r.overall, Verdict::Unacceptable);
    CHECK_EQ(r.best_level, -1);
    // One level unacceptable, the other without enough pairs: inconclusive, not a stop.
    auto mixed = run_of(p, 9.766, {0.90, 0.50});
    mixed[7].fault = PhaseFault::ChannelChanged;                  // level 1 second round: only 1 pair left
    r = evaluate(p, mixed.data(), mixed.size(), k);
    CHECK_EQ(r.levels[1].verdict, Verdict::Inconclusive);
    CHECK_EQ(std::string(r.levels[1].reason), std::string("too_few_pairs"));
    CHECK_EQ(r.overall, Verdict::Inconclusive);
    CHECK_EQ(r.valid_phases, 8u);
}

GUARDIAN_CASE(verdict_inconclusive_reasons) {
    const Plan p = small_plan();
    Criteria k; k.min_expected_beacons = 100;
    // An invalid OFF phase removes both triples that share it (phase 2 sits between L1 and L2 of round 1).
    auto run = run_of(p, 9.766, {1.0, 1.0});
    run[2].fault = PhaseFault::NotMonitoring;
    Report r = evaluate(p, run.data(), run.size(), k);
    CHECK_EQ(r.levels[0].pairs, 1u);
    CHECK_EQ(r.levels[1].pairs, 1u);
    CHECK_EQ(r.levels[0].verdict, Verdict::Inconclusive);
    CHECK_EQ(r.levels[1].verdict, Verdict::Inconclusive);
    CHECK_EQ(r.overall, Verdict::Inconclusive);
    // The closing OFF phase only serves the last scanning phase.
    run = run_of(p, 9.766, {1.0, 1.0});
    run[8].fault = PhaseFault::TooShort;
    r = evaluate(p, run.data(), run.size(), k);
    CHECK_EQ(r.levels[0].pairs, 2u);
    CHECK_EQ(r.levels[1].pairs, 1u);
    CHECK_EQ(r.levels[0].verdict, Verdict::Acceptable);
    CHECK_EQ(r.levels[1].verdict, Verdict::Inconclusive);
    CHECK_EQ(r.overall, Verdict::Acceptable);
    // Weak reference: the OFF phases hear a third of the announced beacons.
    run = run_of(p, 3.2, {1.0, 1.0});
    r = evaluate(p, run.data(), run.size(), k);
    CHECK_EQ(std::string(r.levels[0].reason), std::string("weak_reference"));
    CHECK_EQ(r.overall, Verdict::Inconclusive);
    // Not enough beacons for the resolution (default 500 per level; 2 x 9 s x 9.8 = 176).
    run = run_of(p, 9.766, {1.0, 1.0});
    r = evaluate(p, run.data(), run.size());
    CHECK_EQ(std::string(r.levels[0].reason), std::string("too_few_beacons"));
    CHECK_EQ(r.levels[0].verdict, Verdict::Inconclusive);
    // Unknown beacon interval: no reference, inconclusive.
    run = run_of(p, 9.766, {1.0, 1.0});
    for (auto& x : run) x.beacon_interval_tu = 0;
    r = evaluate(p, run.data(), run.size(), k);
    CHECK_EQ(std::string(r.levels[0].reason), std::string("weak_reference"));
    // Partial run (aborted after phase 3): what exists is evaluated, nothing invented.
    run = run_of(p, 9.766, {1.0, 1.0});
    r = evaluate(p, run.data(), 4, k);
    CHECK_EQ(r.phases, 4u);
    CHECK_EQ(r.levels[0].pairs, 1u);
    CHECK_EQ(r.levels[1].pairs, 0u);
    CHECK_EQ(std::string(r.levels[1].reason), std::string("no_data"));
    CHECK_EQ(r.overall, Verdict::Inconclusive);
    r = evaluate(p, run.data(), 0, k);
    CHECK_EQ(r.overall, Verdict::Inconclusive);
}

GUARDIAN_CASE(heap_floor_and_queue_drops_fail_a_level) {
    const Plan p = small_plan();
    Criteria k; k.min_expected_beacons = 100;
    auto run = run_of(p, 9.766, {1.0, 1.0});
    run[3].heap_min = 18000;                                   // level 1, round 1
    run[3].fault = PhaseFault::ChannelChanged;                 // heap is heap, even in an invalid phase
    Report r = evaluate(p, run.data(), run.size(), k);
    CHECK_EQ(r.levels[1].verdict, Verdict::Unacceptable);
    CHECK_EQ(std::string(r.levels[1].reason), std::string("heap_floor"));
    CHECK_EQ(r.levels[1].heap_min, 18000u);
    run = run_of(p, 9.766, {1.0, 1.0});
    run[1].queue_full = 3; run[5].queue_full = 2;              // level 0: 5 drops in 18 s of scanning
    run[0].queue_full = 1;                                     // some drops while off too
    r = evaluate(p, run.data(), run.size(), k);
    CHECK_EQ(r.levels[0].verdict, Verdict::Unacceptable);
    CHECK_EQ(std::string(r.levels[0].reason), std::string("queue_drops"));
    CHECK(r.levels[0].extra_queue_full_per_min > 1.0);
    CHECK_EQ(r.levels[1].verdict, Verdict::Acceptable);
}

GUARDIAN_CASE(console_lines) {
    const Plan p = small_plan();
    auto run = run_of(p, 9.766, {0.99, 0.80});
    run[1].adv_reports = 900; run[1].vbat_ok = true; run[1].vbat_start_mv = 4010; run[1].vbat_end_mv = 4002;
    char line[400];
    const auto n = phase_text(line, sizeof line, p, 1, run[1]);
    CHECK(n > 0);
    CHECK_EQ(std::strlen(line), n);
    const std::string s(line);
    CHECK(s.rfind("G16H SPIKE PHASE index=2/9 level=1 window_ms=30 interval_ms=300 duty_permille=100 state=ok ", 0) == 0);
    CHECK(s.find(" beacons=") != std::string::npos);
    CHECK(s.find(" adv=900 ") != std::string::npos);
    CHECK(s.find(" vbat_mv=4010..4002") != std::string::npos);
    CHECK(s.back() == '\n');
    CHECK_EQ(phase_text(line, 40, p, 1, run[1]), 0u);           // never cut
    Criteria k; k.min_expected_beacons = 100;
    const Report r = evaluate(p, run.data(), run.size(), k);
    CHECK(level_text(line, sizeof line, r.levels[1]) > 0);
    const std::string l(line);
    CHECK(l.rfind("G16H SPIKE LEVEL window_ms=150 interval_ms=300 duty_permille=500 verdict=unacceptable reason=beacon_loss pairs=2 ", 0) == 0);
    CHECK(l.find(" beacon_ratio=0.795 ") != std::string::npos);   // 70 of 88 expected
    CHECK(verdict_text(line, sizeof line, r, p, k) > 0);
    const std::string v(line);
    CHECK(v.rfind("G16H SPIKE VERDICT overall=acceptable best_window_ms=30 best_interval_ms=300 ", 0) == 0);
    CHECK(v.find(" max_beacon_loss=0.050 ") != std::string::npos);
    CHECK(v.find(" min_heap=20480 ") != std::string::npos);
    CHECK_EQ(std::string(verdict_text(Verdict::Inconclusive)), std::string("inconclusive"));
}

GUARDIAN_CASE(lock_loss_while_scanning_fails_the_level) {
    // Recorder: the survey's lock-loss total is sampled every loop; the phase keeps its delta.
    const Plan p = small_plan();
    Spike s;
    Spike::Step st;
    Counters c;
    CHECK(s.start(p, ap, 0, st));
    Sample a = locked();
    a.lock_losses = 7;                           // losses before the run do not count
    st = s.tick(0, c, a);
    st = s.tick(10000, c, a);                    // phase 0 closes clean
    CHECK_EQ(s.result(0).lock_losses, 0u);
    st = s.tick(12000, c, a);
    Sample lost = a; lost.lock_losses = 8; lost.monitoring = false;   // silence_5s while scanning
    st = s.tick(16000, c, lost);
    st = s.tick(20000, c, lost);
    CHECK_EQ(s.result(1).lock_losses, 1u);
    CHECK_EQ(s.result(1).fault, PhaseFault::NotMonitoring);
    // Verdict: a scanning phase that lost the lock while both OFF neighbours kept it fails its level,
    // even though the phase itself cannot be measured.
    Criteria k; k.min_expected_beacons = 100;
    auto run = run_of(p, 9.766, {1.0, 1.0});
    run[3].lock_losses = 1; run[3].fault = PhaseFault::NotMonitoring;
    Report r = evaluate(p, run.data(), run.size(), k);
    CHECK_EQ(r.levels[1].verdict, Verdict::Unacceptable);
    CHECK_EQ(std::string(r.levels[1].reason), std::string("lock_lost"));
    CHECK_EQ(r.levels[0].verdict, Verdict::Acceptable);
    // The AP itself went quiet (an OFF neighbour lost the lock too): not blamed on scanning.
    run = run_of(p, 9.766, {1.0, 1.0});
    run[3].lock_losses = 1; run[3].fault = PhaseFault::NotMonitoring;
    run[4].lock_losses = 1; run[4].fault = PhaseFault::NotMonitoring;
    r = evaluate(p, run.data(), run.size(), k);
    CHECK_EQ(r.levels[1].verdict, Verdict::Inconclusive);
    // Collateral: scanning starved the radio, so the next OFF phase starts unlocked (invalid)
    // but relocks without a loss of its own: the AP was alive, the loss is the scan's.
    run = run_of(p, 9.766, {1.0, 1.0});
    run[3].lock_losses = 1; run[3].fault = PhaseFault::NotMonitoring; run[3].monitoring_at_end = false;
    run[4].fault = PhaseFault::NotMonitoring; run[4].monitoring_at_end = true;
    r = evaluate(p, run.data(), run.size(), k);
    CHECK_EQ(r.levels[1].verdict, Verdict::Unacceptable);
    CHECK_EQ(std::string(r.levels[1].reason), std::string("lock_lost"));
    // ... but if the next OFF phase never hears the AP again, nothing is blamed.
    run[4].monitoring_at_end = false;
    r = evaluate(p, run.data(), run.size(), k);
    CHECK_EQ(r.levels[1].verdict, Verdict::Inconclusive);
    // Recorder keeps whether the phase ended locked.
    {
        Spike t;
        Counters c2;
        CHECK(t.start(p, ap, 0, st));
        Sample un = locked(); un.monitoring = false;
        st = t.tick(1000, c2, un);
        st = t.tick(10000, c2, locked());
        CHECK(t.result(0).monitoring_at_end);
        CHECK_EQ(t.result(0).fault, PhaseFault::NotMonitoring);
        st = t.tick(20000, c2, un);
        CHECK(!t.result(1).monitoring_at_end);
    }
    char line[400];
    CHECK(phase_text(line, sizeof line, p, 3, run[3]) > 0);
    CHECK(std::string(line).find(" lock_losses=1 ") != std::string::npos);
}

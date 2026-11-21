// G24: the guard listen cycle on battery (see guard_cycle.hpp). Pure functions and plain counters: no clock,
// no SDK, no storage. The board applies the plan (radio stop/start, LCD rail, IMU mode, light sleep).
#include "guardian/guard_cycle.hpp"

namespace guardian {

CycleTiming cycle_timing(GuardCycle c) {
    switch (c) {
    case GuardCycle::Always: return {};
    case GuardCycle::Every30s: return {10000, 20000};
    case GuardCycle::EveryMinute: return {10000, 50000};
    }
    return {};
}

const char* guard_cycle_name(GuardCycle c) {
    switch (c) {
    case GuardCycle::Always: return "always";
    case GuardCycle::Every30s: return "every_30s";
    case GuardCycle::EveryMinute: return "every_minute";
    }
    return "?";
}

bool guard_cycle_from(std::uint8_t raw, GuardCycle& out) {
    if (raw >= guard_cycle_count) return false;
    out = static_cast<GuardCycle>(raw);
    return true;
}

CyclePlan guard_cycle_plan(const CycleInput& in) {
    CyclePlan plan;
    const auto t = cycle_timing(in.choice);
    // Today's plan unless a cycled choice is armed: battery AND Dark. Anything that lights the screen or
    // brings USB power gives this plan at once (no wait for the cycle).
    if (t.off_ms == 0 || t.listen_ms == 0 || !in.on_battery || !in.dark) return plan;
    plan.levers = true;
    if (in.now < in.dark_since) return plan;   // a clock before the dark start: listen, never blind
    const Millis period = t.listen_ms + t.off_ms;
    const Millis phase = (in.now - in.dark_since) % period;   // listen first, from the dark start
    const bool listen = phase < t.listen_ms;
    plan.phase_left_ms = listen ? t.listen_ms - phase : period - phase;
    // The update poll keeps its own period: while it owns the radio (join, fetch) the radio is on and the
    // CPU is not put to light sleep; the levers stay as they are.
    plan.radio_on = listen || in.updating;
    plan.light_sleep = !plan.radio_on;
    return plan;
}

void CycleStats::stopped(Millis) {
    off_ = true;
    waiting_ = false;   // a restart that never relocked before the next stop gives no relock time
}
void CycleStats::resumed(Millis now, bool ok) {
    if (!off_) return;   // a resume without a stop (a wake while listening) is not a cycle
    off_ = false;
    if (cycles_ != 0xffffffffu) ++cycles_;
    if (!ok) { if (resume_fail_ != 0xffffffffu) ++resume_fail_; waiting_ = false; return; }
    waiting_ = true;
    resumed_at_ = now;
}
void CycleStats::locked(Millis now) {
    if (!waiting_) return;
    waiting_ = false;
    if (now < resumed_at_) return;
    relock_sum_ms_ += now - resumed_at_;
    if (relocks_ != 0xffffffffu) ++relocks_;
}
void CycleStats::failed() { if (resume_fail_ != 0xffffffffu) ++resume_fail_; }
std::uint32_t CycleStats::relock_ms_avg() const {
    if (!relocks_) return 0;
    const auto avg = relock_sum_ms_ / relocks_;
    return avg > 0xffffffffull ? 0xffffffffu : static_cast<std::uint32_t>(avg);
}

} // namespace guardian

// G16H Wi-Fi/BLE coexistence spike instrument (see coex_spike.hpp).
#include "coex_spike.hpp"
#include <cstdarg>
#include <cstdio>

namespace guardian::coex {
namespace {
constexpr std::uint16_t min_scan_ms = 3;       // 2.5 ms rounded up to whole milliseconds
constexpr std::uint16_t max_scan_ms = 10240;   // 16384 x 0.625 ms
constexpr double tu_ms = 1.024;

__attribute__((format(printf, 3, 4)))
std::size_t emit(char* out, std::size_t size, const char* format, ...) {
    if (!out || !size) return 0;
    va_list args;
    va_start(args, format);
    const int n = std::vsnprintf(out, size, format, args);
    va_end(args);
    if (n < 0 || static_cast<std::size_t>(n) >= size) { out[0] = 0; return 0; }   // never a cut line
    return static_cast<std::size_t>(n);
}
} // namespace

std::uint16_t Duty::permille() const {
    if (!on() || !interval_ms) return 0;
    return static_cast<std::uint16_t>(static_cast<std::uint32_t>(window_ms) * 1000u / interval_ms);
}
bool valid(const Duty& d) {
    if (!d.on()) return d.interval_ms == 0 || d.interval_ms >= min_scan_ms;
    return d.window_ms >= min_scan_ms && d.window_ms <= d.interval_ms && d.interval_ms <= max_scan_ms;
}
std::uint16_t ble_units(std::uint16_t ms) { return static_cast<std::uint16_t>(static_cast<std::uint32_t>(ms) * 8u / 5u); }

Plan default_plan() {
    Plan p;
    p.levels[0] = {30, 1000};   // 3 %
    p.levels[1] = {30, 300};    // 10 %
    p.levels[2] = {75, 300};    // 25 %
    p.levels[3] = {150, 300};   // 50 %
    p.level_count = 4;
    p.phase_ms = 60000;
    p.settle_ms = 3000;
    p.rounds = 2;
    return p;
}
bool valid(const Plan& p) {
    if (p.level_count == 0 || p.level_count > max_levels) return false;
    if (p.rounds == 0 || p.rounds > max_rounds) return false;
    if (p.phase_ms < 1000 || p.settle_ms >= p.phase_ms) return false;
    for (std::size_t i = 0; i < p.level_count; ++i)
        if (!p.levels[i].on() || !valid(p.levels[i])) return false;
    return true;
}
std::size_t phase_count(const Plan& p) {
    return valid(p) ? static_cast<std::size_t>(p.rounds) * 2u * p.level_count + 1u : 0u;
}
int phase_level(const Plan& p, std::size_t i) {
    if (i >= phase_count(p) || i % 2 == 0) return -1;
    return static_cast<int>((i / 2) % p.level_count);
}
Duty phase_duty(const Plan& p, std::size_t i) {
    const int level = phase_level(p, i);
    return level < 0 ? Duty{} : p.levels[static_cast<std::size_t>(level)];
}

BeaconSample classify(const std::uint8_t* f, std::size_t size, const Mac& bssid) {
    BeaconSample s;
    // FC: version 0, type management, subtype 8 (beacon); ToDS = FromDS = 0.
    // 24-byte header + timestamp (8) + beacon interval (2) + capability (2).
    if (!f || size < 36 || f[0] != 0x80 || (f[1] & 0x03) != 0) return s;
    for (std::size_t i = 0; i < 6; ++i) if (f[16 + i] != bssid[i]) return s;
    s.from_selected = true;
    s.interval_tu = static_cast<std::uint16_t>(f[32] | (f[33] << 8));
    return s;
}

const char* fault_text(PhaseFault f) {
    switch (f) {
    case PhaseFault::None: return "ok";
    case PhaseFault::NotMonitoring: return "not_monitoring";
    case PhaseFault::ChannelChanged: return "channel_changed";
    case PhaseFault::TooShort: return "too_short";
    case PhaseFault::Aborted: return "aborted";
    }
    return "aborted";
}

bool Spike::start(const Plan& plan, const Mac& bssid, std::uint64_t now_ms, Step& first) {
    first = {};
    if (running_ || !valid(plan)) return false;
    bool any = false;
    for (auto b : bssid) any |= b != 0;
    if (!any) return false;
    plan_ = plan;
    bssid_ = bssid;
    running_ = true;
    finished_ = false;
    phase_ = completed_ = 0;
    total_ = phase_count(plan);
    results_ = {};
    begin_phase(now_ms);
    first.apply = true;
    first.duty = phase_duty(plan_, 0);
    return true;
}

void Spike::begin_phase(std::uint64_t now_ms) {
    phase_start_ = now_ms;
    measuring_ = false;
    measure_start_ = 0;
    channel_seen_ = false;
    lock_marked_ = false;
    current_ = {};
    current_.level = static_cast<std::int8_t>(phase_level(plan_, phase_));
    current_.duty = phase_duty(plan_, phase_);
    current_.heap_min = UINT32_MAX;
}

void Spike::close_phase(std::uint64_t now_ms, const Counters& c, const Sample& s, PhaseFault forced) {
    PhaseResult r = current_;
    if (measuring_) {
        r.measured_ms = static_cast<std::uint32_t>(now_ms - measure_start_);
        r.frames = c.frames - at_measure_.frames;
        r.queue_full = c.queue_full - at_measure_.queue_full;
        r.adv_reports = c.adv_reports - at_measure_.adv_reports;
        r.display_frames = c.display_frames - at_measure_.display_frames;
        r.vbat_end_mv = s.vbat_mv;
        r.vbat_ok = r.vbat_ok && s.vbat_ok;
    } else {
        r.vbat_ok = false;
    }
    if (r.heap_min == UINT32_MAX) r.heap_min = s.heap_internal_free;
    r.monitoring_at_end = s.monitoring;
    if (forced != PhaseFault::None) r.fault = forced;
    else if (r.fault == PhaseFault::None && 2ull * r.measured_ms < plan_.phase_ms - plan_.settle_ms) r.fault = PhaseFault::TooShort;
    if (completed_ < max_phases) results_[completed_++] = r;
}

Spike::Step Spike::tick(std::uint64_t now_ms, const Counters& c, const Sample& s) {
    Step st;
    if (!running_) return st;
    if (!lock_marked_) { lock_marked_ = true; lock_mark_ = s.lock_losses; }
    current_.lock_losses = s.lock_losses - lock_mark_;
    // Whole-phase conditions (settle included): the radio must stay locked on one channel.
    if (current_.fault == PhaseFault::None) {
        if (!s.monitoring) current_.fault = PhaseFault::NotMonitoring;
        else if (!channel_seen_) { channel_seen_ = true; current_.channel = s.channel; }
        else if (s.channel != current_.channel) current_.fault = PhaseFault::ChannelChanged;
    }
    if (s.heap_internal_free < current_.heap_min) current_.heap_min = s.heap_internal_free;
    const std::uint64_t end = phase_start_ + plan_.phase_ms;
    if (!measuring_ && now_ms >= phase_start_ + plan_.settle_ms && now_ms < end) {
        measuring_ = true;
        measure_start_ = now_ms;
        at_measure_ = c;
        current_.vbat_ok = s.vbat_ok;
        current_.vbat_start_mv = s.vbat_mv;
    }
    if (now_ms < end) return st;
    close_phase(now_ms, c, s, PhaseFault::None);
    st.phase_done = true;
    ++phase_;
    st.apply = true;
    if (phase_ >= total_) {
        running_ = false;
        finished_ = true;
        st.finished = true;
        st.duty = Duty{};
        return st;
    }
    begin_phase(now_ms);
    lock_marked_ = true;
    lock_mark_ = s.lock_losses;   // a loss after this close belongs to the next phase
    st.duty = current_.duty;
    return st;
}

void Spike::frame(const std::uint8_t* bytes, std::size_t size, std::uint64_t acquired_ms) {
    if (!running_ || !measuring_ || acquired_ms < measure_start_ || acquired_ms >= phase_start_ + plan_.phase_ms) return;
    const auto b = classify(bytes, size, bssid_);
    if (!b.from_selected) return;
    ++current_.beacons;
    if (b.interval_tu) current_.beacon_interval_tu = b.interval_tu;
}

Spike::Step Spike::abort() {
    Step st;
    if (!running_) return st;
    Counters c = at_measure_;   // no fresh counters: the aborted phase is not evaluated anyway
    Sample s;
    s.heap_internal_free = current_.heap_min == UINT32_MAX ? 0 : current_.heap_min;
    close_phase(measuring_ ? measure_start_ : phase_start_, c, s, PhaseFault::Aborted);
    running_ = false;
    finished_ = false;
    st.apply = true;
    st.duty = Duty{};
    st.phase_done = true;
    return st;
}

const char* verdict_text(Verdict v) {
    switch (v) {
    case Verdict::Acceptable: return "acceptable";
    case Verdict::Unacceptable: return "unacceptable";
    case Verdict::Inconclusive: return "inconclusive";
    }
    return "inconclusive";
}

Report evaluate(const Plan& plan, const PhaseResult* phases, std::size_t count, const Criteria& k) {
    Report r;
    r.level_count = valid(plan) ? plan.level_count : 0;
    if (!phases) count = 0;
    r.phases = static_cast<std::uint32_t>(count);
    // Reference: every valid OFF phase with a known beacon interval.
    double off_beacons = 0, off_expected = 0;
    for (std::size_t i = 0; i < count; ++i) {
        const auto& p = phases[i];
        if (p.valid()) ++r.valid_phases;
        if (!p.valid() || p.level >= 0 || !p.beacon_interval_tu) continue;
        off_beacons += p.beacons;
        off_expected += p.measured_ms / (p.beacon_interval_tu * tu_ms);
    }
    r.reference_delivery = off_expected > 0 ? off_beacons / off_expected : 0;
    bool any_acceptable = false, any_inconclusive = false;
    for (std::size_t level = 0; level < r.level_count; ++level) {
        LevelReport& lr = r.levels[level];
        lr.duty = plan.levels[level];
        lr.heap_min = UINT32_MAX;
        bool seen = false, lock_lost = false;
        double expected = 0, frames_expected = 0, qf_expected = 0, on_ms = 0, ref_beacons = 0, ref_announced = 0;
        std::uint32_t frames_on = 0, qf_on = 0, adv_on = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const auto& on = phases[i];
            if (on.level != static_cast<int>(level)) continue;
            seen = true;
            if (on.heap_min < lr.heap_min) lr.heap_min = on.heap_min;
            if (i == 0 || i + 1 >= count) continue;
            const auto& a = phases[i - 1];
            const auto& b = phases[i + 1];
            // The scan made the Guardian deaf: the OFF phase before was clean, and the OFF phase after
            // lost no lock of its own and heard the AP again (it may start unlocked: collateral).
            if (on.lock_losses && a.valid() && !a.lock_losses && !b.lock_losses && b.monitoring_at_end) lock_lost = true;
            if (!on.valid() || !a.valid() || !b.valid() || a.level >= 0 || b.level >= 0) continue;
            const double off_ms = static_cast<double>(a.measured_ms) + b.measured_ms;
            if (off_ms <= 0 || on.measured_ms == 0) continue;
            ++lr.pairs;
            const double scale = on.measured_ms / off_ms;
            expected += (static_cast<double>(a.beacons) + b.beacons) * scale;
            frames_expected += (static_cast<double>(a.frames) + b.frames) * scale;
            qf_expected += (static_cast<double>(a.queue_full) + b.queue_full) * scale;
            lr.beacons_on += on.beacons;
            frames_on += on.frames;
            qf_on += on.queue_full;
            adv_on += on.adv_reports;
            on_ms += on.measured_ms;
            ref_beacons += static_cast<double>(a.beacons) + b.beacons;
            const std::uint16_t tu = a.beacon_interval_tu ? a.beacon_interval_tu : b.beacon_interval_tu;
            if (tu) ref_announced += off_ms / (tu * tu_ms);
        }
        if (lr.heap_min == UINT32_MAX) lr.heap_min = 0;
        lr.expected_on = expected;
        lr.beacon_ratio = expected > 0 ? lr.beacons_on / expected : 0;
        lr.frame_ratio = frames_expected > 0 ? frames_on / frames_expected : 0;
        lr.adv_per_s = on_ms > 0 ? adv_on * 1000.0 / on_ms : 0;
        lr.extra_queue_full_per_min = on_ms > 0 ? (qf_on - qf_expected) * 60000.0 / on_ms : 0;
        if (!seen) { lr.verdict = Verdict::Inconclusive; lr.reason = "no_data"; }
        else if (lr.heap_min < k.min_heap_bytes) { lr.verdict = Verdict::Unacceptable; lr.reason = "heap_floor"; }
        else if (lock_lost) { lr.verdict = Verdict::Unacceptable; lr.reason = "lock_lost"; }
        else if (lr.pairs < k.min_pairs) { lr.verdict = Verdict::Inconclusive; lr.reason = lr.pairs ? "too_few_pairs" : "no_data"; }
        else if (ref_announced <= 0 || ref_beacons / ref_announced < k.min_reference_delivery) { lr.verdict = Verdict::Inconclusive; lr.reason = "weak_reference"; }
        else if (expected < k.min_expected_beacons) { lr.verdict = Verdict::Inconclusive; lr.reason = "too_few_beacons"; }
        else if (1.0 - lr.beacon_ratio > k.max_beacon_loss) { lr.verdict = Verdict::Unacceptable; lr.reason = "beacon_loss"; }
        else if (lr.extra_queue_full_per_min > k.max_extra_queue_full_per_min) { lr.verdict = Verdict::Unacceptable; lr.reason = "queue_drops"; }
        else { lr.verdict = Verdict::Acceptable; lr.reason = "ok"; }
        if (lr.verdict == Verdict::Acceptable) {
            any_acceptable = true;
            if (r.best_level < 0 || lr.duty.permille() > r.levels[static_cast<std::size_t>(r.best_level)].duty.permille())
                r.best_level = static_cast<int>(level);
        }
        if (lr.verdict == Verdict::Inconclusive) any_inconclusive = true;
    }
    r.overall = any_acceptable ? Verdict::Acceptable
              : (any_inconclusive || r.level_count == 0) ? Verdict::Inconclusive : Verdict::Unacceptable;
    return r;
}

std::size_t phase_text(char* out, std::size_t size, const Plan& plan, std::size_t index, const PhaseResult& p) {
    return emit(out, size,
        "G16H SPIKE PHASE index=%u/%u level=%d window_ms=%u interval_ms=%u duty_permille=%u state=%s channel=%u ms=%u "
        "beacons=%u beacon_interval_tu=%u frames=%u queue_full=%u adv=%u display_frames=%u heap_min=%u lock_losses=%u vbat_mv=%s%u..%u\n",
        unsigned(index + 1), unsigned(phase_count(plan)), p.level < 0 ? 0 : p.level + 1, unsigned(p.duty.window_ms),
        unsigned(p.duty.interval_ms), unsigned(p.duty.permille()), fault_text(p.fault), unsigned(p.channel),
        unsigned(p.measured_ms), unsigned(p.beacons), unsigned(p.beacon_interval_tu), unsigned(p.frames),
        unsigned(p.queue_full), unsigned(p.adv_reports), unsigned(p.display_frames), unsigned(p.heap_min), unsigned(p.lock_losses),
        p.vbat_ok ? "" : "usb_or_unknown:", unsigned(p.vbat_start_mv), unsigned(p.vbat_end_mv));
}

std::size_t level_text(char* out, std::size_t size, const LevelReport& l) {
    return emit(out, size,
        "G16H SPIKE LEVEL window_ms=%u interval_ms=%u duty_permille=%u verdict=%s reason=%s pairs=%u beacons=%u "
        "expected=%.1f beacon_ratio=%.3f frame_ratio=%.3f adv_per_s=%.1f extra_queue_full_per_min=%.2f heap_min=%u\n",
        unsigned(l.duty.window_ms), unsigned(l.duty.interval_ms), unsigned(l.duty.permille()), verdict_text(l.verdict),
        l.reason, unsigned(l.pairs), unsigned(l.beacons_on), l.expected_on, l.beacon_ratio, l.frame_ratio, l.adv_per_s,
        l.extra_queue_full_per_min, unsigned(l.heap_min));
}

std::size_t verdict_text(char* out, std::size_t size, const Report& r, const Plan& plan, const Criteria& k) {
    unsigned bw = 0, bi = 0;
    if (r.best_level >= 0 && static_cast<std::size_t>(r.best_level) < max_levels) {
        bw = plan.levels[static_cast<std::size_t>(r.best_level)].window_ms;
        bi = plan.levels[static_cast<std::size_t>(r.best_level)].interval_ms;
    }
    return emit(out, size,
        "G16H SPIKE VERDICT overall=%s best_window_ms=%u best_interval_ms=%u reference_delivery=%.3f phases=%u valid=%u "
        "max_beacon_loss=%.3f min_heap=%u max_extra_queue_full_per_min=%.2f min_reference_delivery=%.2f "
        "min_expected_beacons=%u min_pairs=%u\n",
        verdict_text(r.overall), bw, bi, r.reference_delivery, unsigned(r.phases), unsigned(r.valid_phases),
        k.max_beacon_loss, unsigned(k.min_heap_bytes), k.max_extra_queue_full_per_min, k.min_reference_delivery,
        unsigned(k.min_expected_beacons), unsigned(k.min_pairs));
}

} // namespace guardian::coex

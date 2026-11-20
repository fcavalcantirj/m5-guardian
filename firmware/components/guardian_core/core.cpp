// Portable defense core (G05): selected-network scope, epoch-qualified evidence
// freshness, capability-driven channel validation and the snapshot. Policy text:
// docs/G05-rating-freshness.md; behavior checks: tests/core_check.cpp (RED first)
// and tests/core_baseline.cpp (ported G03 baseline).
#include "guardian/core.hpp"
#include "guardian/rating.hpp"
#include <algorithm>

namespace guardian {
bool Network::operator==(const Network& other) const {
    return ssid_size <= ssid.size() && other.ssid_size <= other.ssid.size()
        && bssid == other.bssid && ssid_size == other.ssid_size
        && std::equal(ssid.begin(), ssid.begin() + ssid_size, other.ssid.begin());
}

Core::TimeCheck Core::check_time(const Instant& at) const {
    if (!at.valid()) return TimeCheck::Invalid;
    if (at.epoch != clock_.epoch()) return TimeCheck::Foreign;
    if (at.at > clock_.now()) return TimeCheck::Future;
    return TimeCheck::Live;
}

bool Core::select(const Network& n) {
    if (n.ssid_size > n.ssid.size() || (n.bssid[0] & 1)
        || std::all_of(n.bssid.begin(), n.bssid.end(), [](auto b) { return b == 0; }))
        return false;
    selected_ = n;
    selected_valid_ = true;
    selected_at_ = Instant{clock_.epoch(), clock_.now(), true}; // the fresh_ms "Checking" window starts here
    has_security_ = false;
    security_ = SecurityObservation{};
    has_signal_ = false;
    signal_ = SignalObservation{};
    signal_interval_known_ = false;
    signal_interval_ms_ = 0;
    has_coverage_ = false;
    coverage_ = CoverageReport{};
    rejected_ = Rejections{};
    present_.fill(false);
    return true;
}

void Core::security(const SecurityObservation& s) {
    if (!selected_valid_) { ++rejected_.not_selected; return; }
    if (s.origin != origin_) { ++rejected_.origin; return; }
    if (s.parse == Parse::Unrelated) { ++rejected_.unrelated; return; }
    if (s.ssid_kind == SsidKind::Absent || !(s.network == selected_)) { ++rejected_.network; return; } // activity, not an advertisement
    if (!listenable_.contains(s.band, s.channel)) { ++rejected_.channel; return; }
    switch (check_time(s.acquired)) {
    case TimeCheck::Invalid: ++rejected_.invalid_time; return;
    case TimeCheck::Future: ++rejected_.future; return;
    case TimeCheck::Foreign:
        // A reading from another timebase (restored after a reboot, or another
        // device) is kept as the historical "last known" record only while
        // nothing else is held. It never displaces evidence and is never graded.
        if (has_security_) { ++rejected_.foreign_epoch; return; }
        security_ = s;
        has_security_ = true;
        return;
    case TimeCheck::Live: break;
    }
    if (has_security_ && security_.acquired.epoch == clock_.epoch() && s.acquired.at < security_.acquired.at) {
        ++rejected_.older; // queue reordering: an older sample never replaces a newer one
        return;
    }
    security_ = s;
    has_security_ = true;
}

void Core::signal(const SignalObservation& sig) {
    if (!selected_valid_) { ++rejected_.not_selected; return; }
    if (sig.origin != origin_) { ++rejected_.origin; return; }
    if (sig.bssid != selected_.bssid) { ++rejected_.network; return; }
    if (!listenable_.contains(sig.band, sig.channel)) { ++rejected_.channel; return; }
    switch (check_time(sig.acquired)) {
    case TimeCheck::Invalid: ++rejected_.invalid_time; return;
    case TimeCheck::Future: ++rejected_.future; return;
    case TimeCheck::Foreign: ++rejected_.foreign_epoch; return; // a signal is never historical evidence
    case TimeCheck::Live: break;
    }
    if (has_signal_ && signal_.acquired.epoch == clock_.epoch() && sig.acquired.at < signal_.acquired.at) {
        ++rejected_.older;
        return;
    }
    // G07: the sampling interval at this device is the gap between the last two
    // accepted live samples of the same epoch. It is a fact about this receiver,
    // not about the air, and it never touches security evidence.
    if (has_signal_ && signal_.acquired.epoch == sig.acquired.epoch) {
        signal_interval_ms_ = sig.acquired.at - signal_.acquired.at;
        signal_interval_known_ = true;
    } else {
        signal_interval_known_ = false;
        signal_interval_ms_ = 0;
    }
    signal_ = sig;
    has_signal_ = true;
}

void Core::coverage(const CoverageReport& c) {
    switch (check_time(c.sampled_at)) {
    case TimeCheck::Invalid: ++rejected_.invalid_time; return;
    case TimeCheck::Future: ++rejected_.future; return;
    case TimeCheck::Foreign: ++rejected_.foreign_epoch; return;
    case TimeCheck::Live: break;
    }
    if (has_coverage_ && coverage_.sampled_at.epoch == clock_.epoch() && c.sampled_at.at < coverage_.sampled_at.at) {
        ++rejected_.older;
        return;
    }
    coverage_ = c;
    has_coverage_ = true;
    // Hysteresis (review 2026-11-17): warn immediately, recover only after sustained clean coverage.
    const bool bad = c.channel == 0
        || c.dropped_in_window > 0
        || (origin_ == Origin::LiveRadio && c.passive_receive != Support::Supported);
    if (bad) {
        coverage_degraded_ = true;
        coverage_clean_since_ = Instant{};
    } else if (coverage_degraded_) {
        if (!coverage_clean_since_.valid()) {
            coverage_clean_since_ = c.sampled_at;
        } else if (c.sampled_at.epoch == coverage_clean_since_.epoch
                   && c.sampled_at.at - coverage_clean_since_.at >= coverage_recover_ms) {
            coverage_degraded_ = false;
        }
    }
}

void Core::incident(const IncidentObservation& i) {
    if (i.scope == IncidentScope::Area) { area_incident(i); return; }   // G16E: about the air, never the rating
    if (!selected_valid_) { ++rejected_.not_selected; return; }
    if (i.origin != origin_) { ++rejected_.origin; return; }
    if (!(i.affected == selected_)) { ++rejected_.network; return; }
    const auto k = static_cast<std::size_t>(i.kind);
    if (k >= incidents_.size()) return;
    switch (check_time(i.acquired)) {
    case TimeCheck::Invalid: ++rejected_.invalid_time; return;
    case TimeCheck::Future: ++rejected_.future; return;
    case TimeCheck::Foreign: ++rejected_.foreign_epoch; return; // another epoch cannot open or renew a window
    case TimeCheck::Live: break;
    }
    if (present_[k] && incidents_[k].acquired.epoch == clock_.epoch() && i.acquired.at < incidents_[k].acquired.at) {
        ++rejected_.older;
        return;
    }
    incidents_[k] = i;
    present_[k] = true;
    ++incident_seq_;   // G16N: an accepted report is a new incident, also while this kind is still shown
}

bool Core::set_area_visibility(Millis ms) {
    if (ms == 0) return false;
    area_ms_ = ms;
    return true;
}

// G16E Area path: about the air around this device. No selection is needed and
// `affected` is ignored; origin and time rules are the same as for Network
// incidents. One slot per family (newest wins); a new family takes a free slot
// or evicts the oldest held observation (counted). Never touches incidents_.
void Core::area_incident(const IncidentObservation& i) {
    if (i.origin != origin_) { ++rejected_.origin; return; }
    if (i.family >= DetectorFamily::Count) return;
    switch (check_time(i.acquired)) {
    case TimeCheck::Invalid: ++rejected_.invalid_time; return;
    case TimeCheck::Future: ++rejected_.future; return;
    case TimeCheck::Foreign: ++rejected_.foreign_epoch; return;
    case TimeCheck::Live: break;
    }
    const TimeEpoch epoch = clock_.epoch();
    std::size_t target = area_.size();
    for (std::size_t k = 0; k < area_.size(); ++k) {
        if (area_held_[k] && area_[k].family == i.family && area_[k].acquired.epoch == epoch) {
            if (i.acquired.at < area_[k].acquired.at) { ++rejected_.older; return; }
            target = k;
            break;
        }
    }
    if (target == area_.size()) {   // a free slot, or one no longer visible (expired or another timebase)
        const Millis now = clock_.now();
        for (std::size_t k = 0; k < area_.size(); ++k) {
            const bool gone = !area_held_[k] || area_[k].acquired.epoch != epoch
                || now < area_[k].acquired.at || now - area_[k].acquired.at >= area_ms_;
            if (gone) { target = k; break; }
        }
    }
    if (target == area_.size()) {
        target = 0;
        for (std::size_t k = 1; k < area_.size(); ++k) if (area_[k].acquired.at < area_[target].acquired.at) target = k;
        ++area_evicted_;
    }
    area_[target] = i;
    area_held_[target] = true;
    ++incident_seq_;   // G16N: amber counts too (owner: "any deauth")
}

Snapshot Core::snapshot() const {
    const Millis now = clock_.now();
    const TimeEpoch epoch = clock_.epoch();
    Snapshot s{};
    s.selected = selected_;
    s.origin = origin_;
    s.rejected = rejected_;
    s.has_security = has_security_;
    if (has_security_) s.last_security = security_;
    // Live evidence: same timebase as the clock. Anything else held is historical.
    const bool live = has_security_ && security_.acquired.epoch == epoch && now >= security_.acquired.at;
    s.security_historical = has_security_ && !live;
    if (!selected_valid_) {
        s.coverage = Coverage::Checking;
    } else if (live) {
        s.age_ms = now - security_.acquired.at;
        s.coverage = s.age_ms < fresh_ms ? Coverage::Fresh : Coverage::Stale;
        if (s.coverage == Coverage::Fresh) s.settings = assess(security_); // only fresh live evidence is graded
    } else {
        // No usable sample yet: "Checking" for fresh_ms after selection in this
        // timebase, then "No fresh data". A historical record stays readable.
        const bool since_known = selected_at_.valid() && selected_at_.epoch == epoch && now >= selected_at_.at;
        s.coverage = since_known && now - selected_at_.at < fresh_ms ? Coverage::Checking : Coverage::Stale;
    }
    // Listening coverage: reported with its age. A fresh report degrades the view
    // only while the evidence itself is not stale: expired evidence is always
    // No fresh data, however the radio is currently listening (G14 board finding).
    if (has_coverage_ && coverage_.sampled_at.epoch == epoch && now >= coverage_.sampled_at.at) {
        s.has_coverage = true;
        s.last_coverage = coverage_;
        s.coverage_age_ms = now - coverage_.sampled_at.at;
        if (selected_valid_ && s.coverage_age_ms < fresh_ms && s.coverage != Coverage::Stale) {
            // The latched state (Core::coverage(), coverage_recover_ms): a bad window warns at once,
            // clean must persist before it clears. The honest grade is still blanked while degraded.
            if (coverage_degraded_) {
                s.coverage = Coverage::Degraded;
                s.settings = Assessment{}; // no grade over degraded listening
            }
        }
    }
    if (has_signal_ && signal_.acquired.epoch == epoch && now >= signal_.acquired.at) {
        s.has_signal = true;
        s.last_signal = signal_;
        s.signal_age_ms = now - signal_.acquired.at;
        s.signal_interval_known = signal_interval_known_;
        s.signal_interval_ms = signal_interval_known_ ? signal_interval_ms_ : 0;
    }
    for (std::size_t k = 0; k < incidents_.size(); ++k) {
        s.evidence[k] = incidents_[k];
        s.incidents[k] = present_[k] && incidents_[k].acquired.epoch == epoch && now >= incidents_[k].acquired.at
            && now - incidents_[k].acquired.at < incident_ms;
    }
    // G16E: area observations, visible on their own window; never part of the grade above.
    for (std::size_t k = 0; k < area_.size(); ++k) {
        s.area[k] = area_[k];
        s.area_visible[k] = area_held_[k] && area_[k].acquired.epoch == epoch && now >= area_[k].acquired.at
            && now - area_[k].acquired.at < area_ms_;
    }
    s.area_visible_ms = area_ms_;
    s.area_evicted = area_evicted_;
    s.incident_seq = incident_seq_;
    return s;
}
} // namespace guardian

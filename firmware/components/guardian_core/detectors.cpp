// G06 detectors: disconnect-burst counting and approved-baseline comparison.
// Policy text: docs/G06-detectors.md; behavior checks: tests/detector_check.cpp
// (written and run RED first against a stub of this file).
//
// Independent implementation under the G01 contracts. Standard C++ only; no
// allocation after construction; no pointer kept into a frame; every number is
// a tunable heuristic from DetectorLimits (one exception, G22: retry_copies_max,
// the length of a retry chain, guardian/detector.hpp). Nothing here reads a reason code,
// verifies a MIC, names a tool or attributes a frame to a transmitter.
#include "guardian/detectors.hpp"
#include <algorithm>

namespace guardian {

namespace {

constexpr Millis kNoTime = 0;

bool same_bytes(const Mac& a, const Mac& b) { return a == b; }

// Saturating add on the monotonic millisecond scale (Millis is 64-bit; guard anyway).
Millis add_ms(Millis a, Millis b) { return a > ~Millis{0} - b ? ~Millis{0} : a + b; }

// Fields of a SecurityElement that enter the fingerprint, zero unless Valid.
void take_element(const SecurityElement& e, ElementState& state, std::uint16_t& akms, std::uint16_t& pairwise,
                  std::uint16_t& group) {
    state = e.state;
    if (e.state != ElementState::Valid) { akms = pairwise = group = 0; return; }
    akms = e.akms.kinds;
    pairwise = e.pairwise.kinds;
    group = e.group.kind;
}

} // namespace

// ---- SettingsFingerprint ----------------------------------------------------------------------
SettingsFingerprint SettingsFingerprint::of(const AdvertisedSettings& adv) {
    SettingsFingerprint f{};
    f.privacy_bit = adv.privacy_valid && adv.privacy_bit;
    take_element(adv.wpa, f.wpa_state, f.wpa_akms, f.wpa_pairwise, f.wpa_group);
    take_element(adv.rsn, f.rsn_state, f.rsn_akms, f.rsn_pairwise, f.rsn_group);
    if (adv.rsn.state == ElementState::Valid) {
        f.rsn_group_management = adv.rsn.group_management.kind;
        f.pmf = adv.rsn.pmf;
    } else {
        f.rsn_group_management = 0;
        f.pmf = Pmf::Unknown;
    }
    f.owe_transition = adv.owe_transition;
    return f;
}

std::uint8_t SettingsFingerprint::diff(const SettingsFingerprint& o) const {
    std::uint8_t bits = 0;
    if (privacy_bit != o.privacy_bit) bits |= change::Privacy;
    if (wpa_state != o.wpa_state || wpa_akms != o.wpa_akms || wpa_pairwise != o.wpa_pairwise || wpa_group != o.wpa_group)
        bits |= change::Wpa;
    if (rsn_state != o.rsn_state || rsn_akms != o.rsn_akms || rsn_pairwise != o.rsn_pairwise || rsn_group != o.rsn_group
        || rsn_group_management != o.rsn_group_management)
        bits |= change::Rsn;
    if (pmf != o.pmf) bits |= change::Pmf;
    if (owe_transition != o.owe_transition) bits |= change::OweTransition;
    return bits;
}

// ---- ApprovedScope --------------------------------------------------------------------------
bool ApprovedScope::valid_identity(const Network& n) {
    return n.ssid_size <= n.ssid.size() && !(n.bssid[0] & 1)
        && !std::all_of(n.bssid.begin(), n.bssid.end(), [](auto b) { return b == 0; });
}

bool ApprovedScope::select(const ApprovedAp& s) {
    if (!valid_identity(s.network)) return false;
    // G16R: a new pick (another name or another BSSID) forgets what was heard under the old one.
    const bool same_identity = selected_valid_ && selected_.network == s.network;
    selected_ = s;
    selected_valid_ = true;
    revoke(s.network.bssid); // the selected AP is never also a "related" entry
    if (!same_identity) forget_same_name();
    return true;
}

bool ApprovedScope::approve(const ApprovedAp& related) {
    ApprovedAp ap = related; ap.watch_impostors = false; // watch applies to the selection only
    if (!configured() || !valid_identity(ap.network)) return false;
    if (selected_valid_ && ap.network.bssid == selected_.network.bssid) return false;
    for (std::size_t i = 0; i < count_; ++i) {
        if (aps_[i].network.bssid == ap.network.bssid) { aps_[i] = ap; return true; }
    }
    if (count_ >= max_approved_ || count_ >= capacity) return false;
    aps_[count_++] = ap;
    drop_same_name(ap.network.bssid);   // G16R: approved now, its learned entry is free again
    return true;
}

bool ApprovedScope::revoke(const Mac& bssid) {
    for (std::size_t i = 0; i < count_; ++i) {
        if (aps_[i].network.bssid == bssid) {
            for (std::size_t j = i + 1; j < count_; ++j) aps_[j - 1] = aps_[j];
            aps_[--count_] = ApprovedAp{};
            return true;
        }
    }
    return false;
}

void ApprovedScope::clear() {
    selected_ = ApprovedAp{};
    selected_valid_ = false;
    aps_.fill(ApprovedAp{});
    count_ = 0;
    forget_same_name();
}

const ApprovedAp* ApprovedScope::find(const Mac& bssid) const {
    if (selected_valid_ && selected_.network.bssid == bssid) return &selected_;
    for (std::size_t i = 0; i < count_; ++i) if (aps_[i].network.bssid == bssid) return &aps_[i];
    return nullptr;
}

// ---- G16R: the same-name set ------------------------------------------------------------------
// Rules: guardian/detectors.hpp (ApprovedScope). Checks: tests/coverage_check.cpp, cases g16r_*.
void ApprovedScope::forget_same_name() {
    same_.fill(SameName{});
    same_count_ = 0;
    same_clock_ = 0;
    same_evictions_ = 0;
}

void ApprovedScope::drop_same_name(const Mac& bssid) {
    for (auto& e : same_) {
        if (e.used && e.bssid == bssid) { e = SameName{}; --same_count_; return; }
    }
}

bool ApprovedScope::same_name(const Mac& bssid) const {
    for (const auto& e : same_) if (e.used && e.bssid == bssid) return true;
    return false;
}

const Mac* ApprovedScope::same_name_at(std::size_t index) const {
    for (const auto& e : same_) {
        if (!e.used) continue;
        if (index == 0) return &e.bssid;
        --index;
    }
    return nullptr;
}

bool ApprovedScope::hear(const RxMeta& meta, const ParseResult& p) {
    if (!selected_valid_ || meta.status != RxStatus::Ok || !p.header_valid) return false;
    if (p.kind != FrameKind::Beacon && p.kind != FrameKind::ProbeResponse) return false;   // only an AP's own advertisement
    if (p.status == ParseStatus::Malformed || p.status == ParseStatus::Truncated) return false;
    const Network& picked = selected_.network;
    if (p.ssid_kind != SsidKind::Present || picked.ssid_size == 0 || p.identity.ssid_size != picked.ssid_size
        || !std::equal(picked.ssid.begin(), picked.ssid.begin() + picked.ssid_size, p.identity.ssid.begin()))
        return false;                                   // another name, a hidden name, or a hidden selection
    const Mac& bssid = p.identity.bssid;
    if ((bssid[0] & 1) || std::all_of(bssid.begin(), bssid.end(), [](auto b) { return b == 0; })) return false;
    if (find(bssid)) return false;                      // selected / approved: the network already
    ++same_clock_;
    SameName* free_slot = nullptr;
    SameName* oldest = nullptr;
    for (auto& e : same_) {
        if (!e.used) { if (!free_slot) free_slot = &e; continue; }
        if (e.bssid == bssid) { e.heard = same_clock_; return true; }
        if (!oldest || e.heard < oldest->heard) oldest = &e;
    }
    SameName* slot = free_slot;
    if (slot) ++same_count_;
    else {                                              // full: the one heard longest ago makes room
        slot = oldest;
        if (same_evictions_ < ~std::uint32_t{0}) ++same_evictions_;
    }
    *slot = SameName{bssid, same_clock_, true};
    return true;
}

// ---- DisconnectDetector -----------------------------------------------------------------------
DisconnectDetector::DisconnectDetector(const ApprovedScope& scope, DetectorLimits limits)
    : scope_(scope), limits_(limits) {
    configured_ = scope.configured() && limits.window_ms > 0 && limits.burst_threshold > 0
        && limits.max_window_events > 0 && limits.max_window_events <= capacity
        && limits.burst_threshold <= limits.max_window_events;
}

// The first valid instant fixes the epoch of this state. A later instant from
// another epoch is ignored and counted; it can neither count nor expire anything.
bool DisconnectDetector::adopt_epoch(const Instant& at) {
    if (!at.valid()) { ++stats_.invalid_time; return false; }
    if (!epoch_set_) { epoch_ = at.epoch; epoch_set_ = true; return true; }
    if (at.epoch != epoch_) { ++stats_.foreign_epoch; return false; }
    return true;
}

bool DisconnectDetector::same_header(const Entry& e, const Entry& c) const {
    return e.kind == c.kind && e.sequence == c.sequence && e.fragment == c.fragment
        && same_bytes(e.addr1, c.addr1) && same_bytes(e.addr2, c.addr2) && same_bytes(e.bssid, c.bssid);
}

void DisconnectDetector::push(const Entry& e) {
    const std::size_t cap = limits_.max_window_events;
    if (size_ == cap) {
        // Bound reached: drop the oldest. If it was still inside the window the
        // count becomes a lower bound until the window has moved past this point.
        const Entry& oldest = ring_[head_];
        if (has_latest_ && latest_ >= oldest.at && latest_ - oldest.at < limits_.window_ms && oldest.counted) {
            ++stats_.evicted_in_window;
            saturated_until_ = add_ms(latest_, limits_.window_ms);
        }
        head_ = (head_ + 1) % cap;
        --size_;
    }
    ring_[(head_ + size_) % cap] = e;
    ++size_;
}

// Drops entries that can no longer count or deduplicate anything, from the
// oldest end. Entries are in drain order, which is acquisition order up to
// queue reordering; a slightly out-of-order survivor is harmless.
void DisconnectDetector::prune(Millis anchor) {
    const std::size_t cap = limits_.max_window_events;
    const Millis horizon = add_ms(limits_.window_ms, limits_.dedupe_ms);
    while (size_ > 0) {
        const Entry& oldest = ring_[head_];
        if (anchor >= oldest.at && anchor - oldest.at >= horizon) {
            head_ = (head_ + 1) % cap;
            --size_;
        } else {
            break;
        }
    }
}

DisconnectDetector::WindowStats DisconnectDetector::window(Millis anchor) const {
    WindowStats w{};
    const std::size_t cap = limits_.max_window_events;
    Millis newest_counted = kNoTime;
    for (std::size_t i = 0; i < size_; ++i) {
        const Entry& e = ring_[(head_ + i) % cap];
        if (anchor < e.at || anchor - e.at >= limits_.window_ms) continue;
        if (e.eapol) { ++w.eapol; continue; }
        ++w.raw;
        if (!e.counted) { ++w.retries; continue; }
        ++w.counted;
        w.raw += e.copies;        // G22: its Retry copies are a number on the counted entry, not ring entries
        w.retries += e.copies;
        if (e.protected_body) ++w.protected_body;
        if (!w.any || e.at >= newest_counted) { w.bssid = e.bssid; newest_counted = e.at; w.any = true; }
    }
    return w;
}

void DisconnectDetector::maybe_report(Millis anchor, Millis acquired, Origin origin, ObservationSink& out) {
    const WindowStats w = window(anchor);
    // G16J: a tool shape inside the window halves the count that makes a burst.
    const std::uint16_t shapes = shapes_.current(anchor, limits_.window_ms, limits_.shape_frames);
    const std::uint32_t threshold = shapes ? halved(limits_.burst_threshold) : limits_.burst_threshold;
    if (w.counted < threshold) return;
    // G16S: the burst is recorded whether or not a report follows (a second burst inside the
    // cooldown of the first must not hide behind it). A new record starts with the counted
    // frames of this window; a record that is still open already has them.
    if (!burst_.live()) {
        burst_.begin(acquired, Pattern::None);
        const std::size_t cap = limits_.max_window_events;
        for (std::size_t k = 0; k < size_; ++k) {
            const Entry& e = ring_[(head_ + k) % cap];
            if (e.eapol || !e.counted || anchor < e.at || anchor - e.at >= limits_.window_ms) continue;
            burst_.add(e.addr1, e.addr2, e.bssid, e.channel, e.at);
        }
    }
    if (reported_ && anchor < add_ms(last_report_, limits_.cooldown_ms)) { ++stats_.suppressed_by_cooldown; return; }
    IncidentObservation i{};
    i.affected = scope_.selected().network;
    i.acquired = Instant{epoch_, acquired, true};
    i.origin = origin;
    i.top = burst_.top();
    i.kind = IncidentKind::DisconnectBurst;
    i.scope = IncidentScope::Network;     // G16E
    i.family = DetectorFamily::Disconnect;
    i.count = w.counted;
    i.window_ms = limits_.window_ms;
    i.bssid = w.bssid;
    i.threshold = threshold;
    i.shapes = shapes;
    i.raw_frames = w.raw;
    i.retries_deduped = w.retries;
    i.protected_frames = w.protected_body;
    i.eapol_frames = w.eapol;
    i.saturated = anchor < saturated_until_;
    if (has_coverage_ && coverage_.sampled_at.valid() && coverage_.sampled_at.epoch == epoch_
        && anchor >= coverage_.sampled_at.at && anchor - coverage_.sampled_at.at < limits_.window_ms) {
        i.coverage_known = true;
        i.listened_ms = coverage_.listened_ms;
        i.coverage_window_ms = coverage_.window_ms;
        i.hopping = coverage_.hopping;
    }
    i.changes = 0;
    reported_ = true;
    last_report_ = anchor;
    ++stats_.reports;
    out.incident(i);
}

void DisconnectDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    ++frames_seen_;   // G16E report: every frame offered
    if (!configured_) return;
    const bool disconnect = p.kind == FrameKind::Deauthentication || p.kind == FrameKind::Disassociation;
    const bool eapol = p.kind == FrameKind::EapolData && !p.protected_frame;
    if (!p.header_valid) { ++stats_.header_invalid; return; } // addresses/sequence unusable: never counted
    if (!disconnect && !eapol) { ++stats_.other_frames; return; }
    const bool in_scope = scope_.has_selection() && scope_.in_network(p.identity.bssid);   // G16R: the name, not one address
    if (!in_scope) {
        if (disconnect) ++stats_.out_of_scope; else ++stats_.other_frames;
        return;
    }
    if (meta.status != RxStatus::Ok) { ++stats_.skipped_unverified; return; }
    if (origin_set_ && origin_ != meta.origin) { ++stats_.foreign_origin; return; }
    if (!adopt_epoch(meta.acquired)) return;
    origin_ = meta.origin;
    origin_set_ = true;
    if (disconnect) ++stats_.in_scope;
    const Millis at = meta.acquired.at;
    if (!has_latest_ || at > latest_) { latest_ = at; has_latest_ = true; }
    prune(latest_);

    Entry e{};
    e.at = at;
    e.addr1 = p.addr1;
    e.addr2 = p.addr2;
    e.bssid = p.identity.bssid;
    e.sequence = p.sequence;
    e.fragment = p.fragment;
    e.kind = static_cast<std::uint8_t>(p.kind);
    e.retry = p.retry;
    e.protected_body = p.protected_frame;
    e.eapol = eapol;
    e.channel = meta.channel;
    if (eapol) {
        ++stats_.eapol_frames;
        push(e); // context in the window; never counted, never evaluated
        return;
    }
    // Retry deduplication: a Retry-bit copy of a header seen inside dedupe_ms is
    // a retransmission. Without the bit, or outside the gap, equality of the
    // sequence number proves nothing (wrap, spoofing) and the frame counts. The
    // gap is measured from the COUNTED observation, never from an earlier copy,
    // so a chain of copies cannot stretch the gap indefinitely.
    // G22 (independent review D1): a counted frame absorbs at most retry_copies_max
    // copies (a retry chain is bounded); a further copy is counted, so setting the
    // Retry bit on a flood with one sequence number hides nothing. A copy is a
    // number on its counted entry and takes no ring entry (copies used to fill the
    // ring and push the counted entries out of the window).
    bool duplicate = false;
    if (p.retry) {
        const std::size_t cap = limits_.max_window_events;
        for (std::size_t i = 0; i < size_ && !duplicate; ++i) {
            Entry& seen = ring_[(head_ + i) % cap];
            if (seen.eapol || !seen.counted || seen.copies >= retry_copies_max || !same_header(seen, e)) continue;
            const Millis gap = seen.at > at ? seen.at - at : at - seen.at;
            if (gap <= limits_.dedupe_ms) { duplicate = true; ++seen.copies; }
        }
    }
    if (duplicate) { ++stats_.retries_deduped; return; }
    e.counted = true;
    ++stats_.counted;
    if (e.protected_body) ++stats_.protected_frames;
    if (!has_event_ || at > last_event_) last_event_ = at;   // G16E: radar pulse source
    has_event_ = true;
    // G16J: shapes of counted frames only (a Retry copy adds nothing).
    shapes_.add(limits_.shape_frames ? disconnect_frame_shapes(p) : std::uint16_t{0},
                runs_.observe(p, at, limits_.shape_run, limits_.window_ms), at, limits_.window_ms);
    // G16S: a burst that is being recorded counts this frame; its window closes after window_ms without one.
    if (burst_.live() && !burst_.settle(at, limits_.window_ms)) burst_.add(p.addr1, p.addr2, p.identity.bssid, meta.channel, at);
    push(e);
    if (latest_ - at < limits_.window_ms) maybe_report(latest_, at, meta.origin, out);
}

void DisconnectDetector::on_tick(Instant now, ObservationSink&) {
    if (!configured_ || !adopt_epoch(now)) return;
    if (!has_latest_ || now.at > latest_) { latest_ = now.at; has_latest_ = true; }
    prune(latest_);
}

void DisconnectDetector::reset() {
    origin_set_ = false;
    origin_ = Origin::LiveRadio;
    epoch_set_ = false;
    epoch_ = TimeEpoch{};
    latest_ = 0;
    has_latest_ = false;
    head_ = size_ = 0;
    saturated_until_ = 0;
    reported_ = false;
    last_report_ = 0;
    has_coverage_ = false;
    coverage_ = CoverageReport{};
    stats_ = DisconnectStats{};
    frames_seen_ = 0;
    has_event_ = false;
    last_event_ = 0;
    shapes_.clear();
    runs_.clear();
    burst_.clear();
}

void DisconnectDetector::coverage(const CoverageReport& report) {   // FrameDetector::coverage (G16E)
    if (!configured_) return;
    if (!report.sampled_at.valid()) { ++stats_.invalid_time; return; }
    if (epoch_set_ && report.sampled_at.epoch != epoch_) { ++stats_.foreign_epoch; return; }
    if (!epoch_set_) { epoch_ = report.sampled_at.epoch; epoch_set_ = true; }
    if (has_coverage_ && report.sampled_at.at < coverage_.sampled_at.at) return; // keep the newer report
    coverage_ = report;
    has_coverage_ = true;
}

std::uint32_t DisconnectDetector::in_window(Instant now) const {
    if (!configured_ || !now.valid() || !epoch_set_ || now.epoch != epoch_) return 0;
    return window(now.at).counted;
}

LastBurst DisconnectDetector::last_burst(Instant now) const {   // G16S
    const bool same = configured_ && now.valid() && epoch_set_ && now.epoch == epoch_;
    // Another timebase cannot say whether the window is still open: read as closed, age unknown.
    LastBurst b = burst_.read(same ? now.at : ~Millis{0}, limits_.window_ms);
    b.age_known = b.known && same && now.at >= b.incident_at;
    b.age_ms = b.age_known ? now.at - b.incident_at : 0;
    return b;
}

// ---- BaselineDetector -------------------------------------------------------------------------
BaselineDetector::BaselineDetector(const ApprovedScope& scope, DetectorLimits limits)
    : scope_(scope), limits_(limits) {
    configured_ = scope.configured() && limits.window_ms > 0 && limits.change_threshold > 0
        && limits.change_threshold <= capacity;
}

bool BaselineDetector::adopt_epoch(const Instant& at) {
    if (!at.valid()) { ++stats_.invalid_time; return false; }
    if (!epoch_set_) { epoch_ = at.epoch; epoch_set_ = true; return true; }
    if (at.epoch != epoch_) { ++stats_.foreign_epoch; return false; }
    return true;
}

void BaselineDetector::push(const Entry& e) {
    ++events_;   // G16E report: every differing / unexpected advertisement entering the window
    if (!has_event_ || e.at > last_event_) last_event_ = e.at;
    has_event_ = true;
    if (size_ == capacity) {
        const Entry& oldest = ring_[head_];
        if (has_latest_ && latest_ >= oldest.at && latest_ - oldest.at < limits_.window_ms) {
            ++stats_.evicted_in_window;
            saturated_until_ = add_ms(latest_, limits_.window_ms);
        }
        head_ = (head_ + 1) % capacity;
        --size_;
    }
    ring_[(head_ + size_) % capacity] = e;
    ++size_;
}

void BaselineDetector::prune(Millis anchor) {
    while (size_ > 0) {
        const Entry& oldest = ring_[head_];
        if (anchor >= oldest.at && anchor - oldest.at >= limits_.window_ms) {
            head_ = (head_ + 1) % capacity;
            --size_;
        } else {
            break;
        }
    }
}

void BaselineDetector::maybe_report(bool unexpected, Millis anchor, Millis acquired, const Mac& trigger, Origin origin, ObservationSink& out) {
    // Window reduction for one kind: advertisements (raw), distinct BSSIDs
    // (UnexpectedAp count), the union of differing fields, the newest BSSID.
    std::uint32_t raw = 0, distinct = 0;
    std::uint8_t changes = 0;
    Mac newest_bssid{};
    Millis newest = kNoTime;
    bool any = false;
    for (std::size_t i = 0; i < size_; ++i) {
        const Entry& e = ring_[(head_ + i) % capacity];
        if ((!unexpected && e.bssid != trigger) || e.unexpected != unexpected || anchor < e.at || anchor - e.at >= limits_.window_ms) continue;
        ++raw;
        changes = static_cast<std::uint8_t>(changes | e.changes);
        if (!any || e.at >= newest) { newest_bssid = e.bssid; newest = e.at; any = true; }
        bool seen = false;
        for (std::size_t j = 0; j < i && !seen; ++j) {
            const Entry& earlier = ring_[(head_ + j) % capacity];
            seen = earlier.unexpected == unexpected && !(anchor < earlier.at || anchor - earlier.at >= limits_.window_ms)
                && same_bytes(earlier.bssid, e.bssid);
        }
        if (!seen) ++distinct;
    }
    if (raw < limits_.change_threshold) return;
    // Slot zero is scope-wide unexpected APs; settings cooldowns are per AP.
    std::size_t k = unexpected ? 0 : 1;
    if (!unexpected && trigger != scope_.selected().network.bssid) {
        for (std::size_t n = 0; n < scope_.approved_count(); ++n)
            if (scope_.approved_at(n)->network.bssid == trigger) { k = n + 2; break; }
    }
    if (reported_[k] && anchor < add_ms(last_report_[k], limits_.cooldown_ms)) { ++stats_.suppressed_by_cooldown; return; }
    IncidentObservation i{};
    i.affected = scope_.selected().network;
    i.acquired = Instant{epoch_, acquired, true};
    i.origin = origin;
    i.kind = unexpected ? IncidentKind::UnexpectedAp : IncidentKind::SettingsChanged;
    i.scope = IncidentScope::Network;     // G16E
    i.family = DetectorFamily::Baseline;
    i.count = unexpected ? distinct : raw;
    i.window_ms = limits_.window_ms;
    i.bssid = newest_bssid;
    i.threshold = limits_.change_threshold;
    i.raw_frames = raw;
    i.saturated = anchor < saturated_until_;
    i.changes = changes;
    reported_[k] = true;
    last_report_[k] = anchor;
    ++stats_.reports;
    out.incident(i);
}

void BaselineDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    ++frames_seen_;   // G16E report
    if (!configured_) return;
    const bool advertisement = p.kind == FrameKind::Beacon || p.kind == FrameKind::ProbeResponse;
    if (!advertisement || !p.header_valid) { ++stats_.other_frames; return; }
    ++stats_.advertisements;
    if (meta.status != RxStatus::Ok) { ++stats_.skipped_unverified; return; }            // bytes not vouched for
    if (p.status != ParseStatus::Complete || !p.settings.privacy_valid) { ++stats_.skipped_incomplete; return; } // proves nothing
    if (origin_set_ && origin_ != meta.origin) { ++stats_.foreign_origin; return; }
    if (!adopt_epoch(meta.acquired)) return;
    origin_ = meta.origin;
    origin_set_ = true;
    const Millis at = meta.acquired.at;
    if (!has_latest_ || at > latest_) { latest_ = at; has_latest_ = true; }
    prune(latest_);

    const SettingsFingerprint seen = SettingsFingerprint::of(p.settings);
    const ApprovedAp* ap = scope_.find(p.identity.bssid);
    if (ap) {
        ++stats_.in_scope;
        std::uint8_t changes = 0;
        bool compared = false;
        if (ap->settings_known) { compared = true; changes = static_cast<std::uint8_t>(changes | ap->settings.diff(seen)); }
        if (ap->channel_known && p.settings.ds_channel_present) {
            compared = true;
            if (p.settings.ds_channel != ap->channel || meta.band != ap->band) changes = static_cast<std::uint8_t>(changes | change::Channel);
        }
        if (!compared) { ++stats_.no_baseline; return; }
        if (changes == 0) { ++stats_.unchanged; return; }
        ++stats_.changed;
        Entry e{};
        e.at = at;
        e.bssid = p.identity.bssid;
        e.changes = changes;
        e.unexpected = false;
        push(e);
        if (latest_ - at < limits_.window_ms) maybe_report(false, latest_, at, p.identity.bssid, meta.origin, out);
        return;
    }
    // Not approved: only the selected SSID's exact bytes matter. Hidden/absent
    // SSIDs and other names are neighbours; a hidden selection matches no name.
    const Network& sel = scope_.selected().network;
    const bool same_name = scope_.has_selection() && p.ssid_kind == SsidKind::Present && sel.ssid_size > 0
        && p.identity.ssid_size == sel.ssid_size
        && std::equal(sel.ssid.begin(), sel.ssid.begin() + sel.ssid_size, p.identity.ssid.begin());
    if (!same_name) { ++stats_.neighbours; return; }
    if (!scope_.selected().watch_impostors) { ++stats_.same_name_unwatched; return; }
    ++stats_.unexpected;
    std::uint8_t changes = change::Bssid;
    const ApprovedAp& home = scope_.selected();
    if (home.settings_known) changes = static_cast<std::uint8_t>(changes | home.settings.diff(seen));
    if (home.channel_known && p.settings.ds_channel_present && (p.settings.ds_channel != home.channel || meta.band != home.band))
        changes = static_cast<std::uint8_t>(changes | change::Channel);
    Entry e{};
    e.at = at;
    e.bssid = p.identity.bssid;
    e.changes = changes;
    e.unexpected = true;
    push(e);
    if (latest_ - at < limits_.window_ms) maybe_report(true, latest_, at, p.identity.bssid, meta.origin, out);
}

void BaselineDetector::on_tick(Instant now, ObservationSink&) {
    if (!configured_ || !adopt_epoch(now)) return;
    if (!has_latest_ || now.at > latest_) { latest_ = now.at; has_latest_ = true; }
    prune(latest_);
}

void BaselineDetector::reset() {
    origin_set_ = false;
    origin_ = Origin::LiveRadio;
    epoch_set_ = false;
    epoch_ = TimeEpoch{};
    latest_ = 0;
    has_latest_ = false;
    head_ = size_ = 0;
    saturated_until_ = 0;
    reported_.fill(false);
    last_report_.fill(0);
    stats_ = BaselineStats{};
    frames_seen_ = 0;
    events_ = 0;
    has_event_ = false;
    last_event_ = 0;
}

// ---- G16E: tunable limits and reports ---------------------------------------------------------
namespace {
bool disconnect_limits_ok(const ApprovedScope& scope, const DetectorLimits& l) {
    return scope.configured() && l.window_ms > 0 && l.burst_threshold > 0
        && l.max_window_events > 0 && l.max_window_events <= DisconnectDetector::capacity
        && l.burst_threshold <= l.max_window_events;
}
bool baseline_limits_ok(const ApprovedScope& scope, const DetectorLimits& l) {
    return scope.configured() && l.window_ms > 0 && l.change_threshold > 0 && l.change_threshold <= BaselineDetector::capacity;
}
// Age of `then` at `now` inside one epoch; false for another timebase or a future instant.
bool age_at(const Instant& now, const TimeEpoch& epoch, Millis then, Millis& age) {
    if (!now.valid() || now.epoch != epoch || now.at < then) return false;
    age = now.at - then;
    return true;
}
} // namespace

bool DisconnectDetector::configure(const DetectorLimits& limits) {
    limits_ = limits;
    configured_ = disconnect_limits_ok(scope_, limits);
    reset();
    return configured_;
}

DetectorReport DisconnectDetector::report(Instant now) const {
    DetectorReport r{};
    r.name = "disconnect";
    r.family = DetectorFamily::Disconnect;
    r.scope = IncidentScope::Network;
    r.configured = configured_;
    r.frames_seen = frames_seen_;
    r.events_total = stats_.counted;
    r.events_in_window = in_window(now);
    r.window_ms = limits_.window_ms;
    r.incidents = stats_.reports;
    if (epoch_set_) {
        r.last_event_known = has_event_ && age_at(now, epoch_, last_event_, r.last_event_age_ms);
        r.last_incident_known = reported_ && age_at(now, epoch_, last_report_, r.last_incident_age_ms);
        if (r.last_incident_known && r.last_incident_age_ms < limits_.cooldown_ms)
            r.cooldown_remaining_ms = limits_.cooldown_ms - r.last_incident_age_ms;
    }
    return r;
}

bool BaselineDetector::configure(const DetectorLimits& limits) {
    limits_ = limits;
    configured_ = baseline_limits_ok(scope_, limits);
    reset();
    return configured_;
}

DetectorReport BaselineDetector::report(Instant now) const {
    DetectorReport r{};
    r.name = "baseline";
    r.family = DetectorFamily::Baseline;
    r.scope = IncidentScope::Network;
    r.configured = configured_;
    r.frames_seen = frames_seen_;
    r.events_total = events_;
    r.window_ms = limits_.window_ms;
    r.incidents = stats_.reports;
    if (!configured_ || !epoch_set_ || !now.valid() || now.epoch != epoch_) return r;
    for (std::size_t i = 0; i < size_; ++i) {
        const Entry& e = ring_[(head_ + i) % capacity];
        if (now.at >= e.at && now.at - e.at < limits_.window_ms) ++r.events_in_window;
    }
    r.last_event_known = has_event_ && age_at(now, epoch_, last_event_, r.last_event_age_ms);
    for (std::size_t k = 0; k < reported_.size(); ++k) {
        Millis age{};
        if (!reported_[k] || !age_at(now, epoch_, last_report_[k], age)) continue;
        if (!r.last_incident_known || age < r.last_incident_age_ms) { r.last_incident_known = true; r.last_incident_age_ms = age; }
        if (age < limits_.cooldown_ms) r.cooldown_remaining_ms = std::max<Millis>(r.cooldown_remaining_ms, limits_.cooldown_ms - age);
    }
    return r;
}
} // namespace guardian

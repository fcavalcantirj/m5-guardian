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

// ---- G25: the weakest-advertised summary of a fingerprint, and what counts as a downgrade --------
namespace {
constexpr std::uint16_t kEnterpriseAkms = akm::Wpa1Eap | akm::Eap | akm::EapSha256 | akm::FtEap | akm::EapSuiteB | akm::EapSuiteB192;
constexpr std::uint16_t kSaeAkms = akm::Sae | akm::FtSae | akm::SaeExt;
constexpr std::uint16_t kPersonalAkms = akm::Psk | akm::PskSha256 | akm::FtPsk;
Cipher weakest_cipher(std::uint16_t kinds) {
    if (kinds & (cipher::Wep40 | cipher::Wep104)) return Cipher::Wep;
    if (kinds & cipher::Tkip) return Cipher::Tkip;
    if (kinds & (cipher::Ccmp128 | cipher::Ccmp256)) return Cipher::Ccmp;
    if (kinds & (cipher::Gcmp128 | cipher::Gcmp256)) return Cipher::Gcmp;
    return Cipher::Unknown;
}
// Higher = stronger; -1 = outside the owner's order (OWE, Enterprise, Unknown).
int mode_rank(Mode m) {
    switch (m) {
    case Mode::Open: return 0; case Mode::Wep: return 1; case Mode::Wpa1: return 2; case Mode::Wpa2Personal: return 3;
    case Mode::Transition: return 4; case Mode::Wpa3Personal: return 5;
    case Mode::Owe: case Mode::Enterprise: case Mode::Unknown: return -1;
    }
    return -1;
}
int cipher_rank(Cipher c) {
    switch (c) {
    case Cipher::None: return 0; case Cipher::Wep: return 1; case Cipher::Tkip: return 2; case Cipher::Ccmp: case Cipher::Gcmp: return 3;
    case Cipher::Unknown: return -1;
    }
    return -1;
}
int pmf_rank(Pmf p) {
    switch (p) {
    case Pmf::Disabled: return 0; case Pmf::Optional: return 1; case Pmf::Required: return 2; case Pmf::Unknown: return -1;
    }
    return -1;
}
bool weaker(int from, int to) { return from >= 0 && to >= 0 && to < from; }
} // namespace

SecuritySummary summarize(const SettingsFingerprint& f) {
    // The G05 reduction (rating.cpp assess) over the fingerprint's Valid fields.
    SecuritySummary s{};
    const bool rsn = f.rsn_state == ElementState::Valid, wpa = f.wpa_state == ElementState::Valid;
    std::uint16_t akms = 0, pairwise = 0;
    if (rsn) { akms |= f.rsn_akms; pairwise |= f.rsn_pairwise; }
    if (wpa) { akms |= f.wpa_akms; pairwise |= f.wpa_pairwise; }
    if (!rsn && !wpa) {
        if (f.owe_transition == ElementState::Valid) s.mode = Mode::Owe;
        else if (!f.privacy_bit) { s.mode = Mode::Open; s.pairwise = Cipher::None; }
        else { s.mode = Mode::Wep; s.pairwise = Cipher::Wep; }
        s.pmf = Pmf::Disabled;
        return s;
    }
    if (akms & akm::Unknown) s.mode = Mode::Unknown;
    else if (akms & akm::Owe) s.mode = Mode::Owe;
    else if (akms & kEnterpriseAkms) s.mode = Mode::Enterprise;
    else if (wpa) s.mode = Mode::Wpa1;
    else {
        const bool sae = (akms & kSaeAkms) != 0, psk = (akms & kPersonalAkms) != 0;
        s.mode = sae && psk ? Mode::Transition : sae ? Mode::Wpa3Personal : psk ? Mode::Wpa2Personal : Mode::Unknown;
    }
    if (!(pairwise & cipher::Unknown)) s.pairwise = weakest_cipher(pairwise);
    s.pmf = rsn ? f.pmf : Pmf::Disabled;
    return s;
}

bool security_downgrade(const SettingsFingerprint& from, const SettingsFingerprint& to) {
    const SecuritySummary a = summarize(from), b = summarize(to);
    if (b.mode == Mode::Open && a.mode != Mode::Open) return true;   // anything -> open
    return weaker(mode_rank(a.mode), mode_rank(b.mode)) || weaker(cipher_rank(a.pairwise), cipher_rank(b.pairwise))
        || weaker(pmf_rank(a.pmf), pmf_rank(b.pmf));
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
        if (!unexpected && e.changes == 0) continue;   // G25: belonged to a change the owner accepted
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
    if (!unexpected) {   // G25: the router's own security change, never an incident
        const ApprovedAp* ap = scope_.find(trigger);
        Track* t = ap ? track(*ap) : nullptr;
        if (t && (t->pending || raw >= limits_.change_threshold)) confirm(*t, changes, raw, acquired);
        return;
    }
    if (raw < limits_.change_threshold) return;
    if (unexpected_reported_ && anchor < add_ms(unexpected_last_, limits_.cooldown_ms)) { ++stats_.suppressed_by_cooldown; return; }
    IncidentObservation i{};
    i.affected = scope_.selected().network;
    i.acquired = Instant{epoch_, acquired, true};
    i.origin = origin;
    i.kind = IncidentKind::UnexpectedAp;
    i.scope = IncidentScope::Network;     // G16E
    i.family = DetectorFamily::Baseline;
    i.count = distinct;
    i.window_ms = limits_.window_ms;
    i.bssid = newest_bssid;
    i.threshold = limits_.change_threshold;
    i.raw_frames = raw;
    i.saturated = anchor < saturated_until_;
    i.changes = changes;
    unexpected_reported_ = true;
    unexpected_last_ = anchor;
    ++stats_.reports;
    last_ = BaselineLast{true, newest_bssid, changes, distinct, i.acquired};   // G25 STATUS baseline_last
    out.incident(i);
}

// ---- G25: router tracks ---------------------------------------------------------------------
BaselineDetector::Track* BaselineDetector::track(const ApprovedAp& ap) {
    Track* found = nullptr;
    Track* free = nullptr;
    for (auto& t : tracks_) {
        if (t.used && t.bssid == ap.network.bssid) { found = &t; break; }
        if (!t.used && !free) free = &t;
    }
    if (!found) {
        if (!free) return nullptr;   // more APs than the scope can hold: cannot happen (capacity + 1 tracks)
        *free = Track{};
        free->used = true;
        free->bssid = ap.network.bssid;
        found = free;
        found->scope_channel_known = !ap.channel_known;   // forces the read below
    }
    // The scope's channel until a move is confirmed; when the scope itself changes (the owner, or the scope's
    // owner storing a move), its facts are read again.
    if (found->scope_channel_known != ap.channel_known || found->scope_band != ap.band || found->scope_channel != ap.channel) {
        found->scope_channel_known = ap.channel_known; found->scope_band = ap.band; found->scope_channel = ap.channel;
        found->channel_known = ap.channel_known; found->band = ap.band; found->channel = ap.channel; found->cand_hits = 0;
    }
    return found;
}

void BaselineDetector::confirm(Track& t, std::uint8_t changes, std::uint32_t raw, Millis at) {
    const ApprovedAp* ap = scope_.find(t.bssid);
    const SettingsFingerprint from = ap ? baseline_of(&t, *ap) : SettingsFingerprint{};
    bool news = false;
    if (!t.pending) {
        t.pending = true; t.changes = changes; t.first = at; t.count = raw;
        ++stats_.reports;   // STATUS "incidents": one router change confirmed (no incident reaches Core)
        news = true;
    } else {
        ++t.count;
        if ((t.changes | changes) != t.changes) { t.changes = static_cast<std::uint8_t>(t.changes | changes); news = true; }
    }
    t.to = t.seen;
    t.last = at;
    t.downgrade = security_downgrade(from, t.to);
    if (news) ++change_seq_;
    last_ = BaselineLast{true, t.bssid, t.changes, t.count, Instant{epoch_, at, true}};
}

RouterState BaselineDetector::router() const {
    RouterState r{};
    r.change_seq = change_seq_;
    r.moves = moves_;
    r.last_move = last_move_;
    const Track* newest = nullptr;
    for (const auto& t : tracks_) {
        if (!t.used || !t.pending) continue;
        ++r.pending;
        if (!newest || t.first > newest->first) newest = &t;
    }
    if (newest) {
        auto& c = r.change;
        c.pending = true;
        c.bssid = newest->bssid;
        c.changes = newest->changes;
        const ApprovedAp* ap = scope_.find(newest->bssid);
        if (ap) c.from = baseline_of(newest, *ap);
        c.to = newest->to;
        c.downgrade = newest->downgrade;
        c.first = Instant{epoch_, newest->first, true};
        c.last = Instant{epoch_, newest->last, true};
        c.count = newest->count;
    }
    return r;
}

bool BaselineDetector::take_move(ChannelMove& out) {
    if (!move_waiting_) return false;
    move_waiting_ = false;
    out = last_move_;
    return true;
}

bool BaselineDetector::accept(const Mac& bssid, SettingsFingerprint& seen) {
    for (auto& t : tracks_) {
        if (!t.used || t.bssid != bssid || !t.pending) continue;
        seen = t.seen_known ? t.seen : t.to;
        t.pending = false; t.changes = 0; t.count = 0; t.downgrade = false;
        t.accepted_known = true; t.accepted = seen;   // compared with until the scope's owner stores it
        // The differing advertisements in the window belong to the accepted change.
        for (std::size_t i = 0; i < size_; ++i) {
            Entry& e = ring_[(head_ + i) % capacity];
            if (!e.unexpected && e.bssid == bssid) e.changes = 0;
        }
        return true;
    }
    return false;
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
        Track* t = track(*ap);
        if (t) { t->seen = seen; t->seen_known = true; }
        bool compared = false;
        // G25: the channel. A move of the router is re-baselined (no incident) after change_threshold
        // advertisements on the new channel inside window_ms; one on the baseline channel restarts the count.
        bool moved = false;
        const bool channel_known = t ? t->channel_known : ap->channel_known;
        if (channel_known && p.settings.ds_channel_present) {
            compared = true;
            const std::uint8_t base = t ? t->channel : ap->channel;
            const Band base_band = t ? t->band : ap->band;
            const bool differs = p.settings.ds_channel != base || meta.band != base_band;
            moved = differs;
            if (t && !differs) t->cand_hits = 0;
            if (t && differs) {
                if (t->cand_hits == 0 || t->cand_channel != p.settings.ds_channel || t->cand_band != meta.band
                    || at < t->cand_first || at - t->cand_first >= limits_.window_ms) {
                    t->cand_channel = p.settings.ds_channel; t->cand_band = meta.band; t->cand_first = at; t->cand_hits = 0;
                }
                if (t->cand_hits < 0xff) ++t->cand_hits;
                if (t->cand_hits >= limits_.change_threshold) {
                    last_move_ = ChannelMove{true, t->bssid, meta.band, base, p.settings.ds_channel, Instant{epoch_, at, true}};
                    last_ = BaselineLast{true, t->bssid, change::Channel, t->cand_hits, last_move_.at};
                    t->channel = p.settings.ds_channel; t->band = meta.band; t->cand_hits = 0;
                    ++moves_; ++stats_.channel_moves; move_waiting_ = true;
                }
            }
        }
        // Security: compared with the approved baseline (or, after an accept, with the accepted settings
        // until the scope's owner stores them).
        std::uint8_t changes = 0;
        if (ap->settings_known) {
            compared = true;
            if (t && t->accepted_known && ap->settings == t->accepted) t->accepted_known = false;   // stored: the scope says it now
            changes = baseline_of(t, *ap).diff(seen);
        }
        if (!compared) { ++stats_.no_baseline; return; }
        if (changes == 0) {
            if (moved) ++stats_.changed; else ++stats_.unchanged;
            return;
        }
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
    unexpected_reported_ = false; unexpected_last_ = 0; tracks_.fill(Track{}); change_seq_ = moves_ = 0;   // G25
    last_move_ = ChannelMove{}; move_waiting_ = false; last_ = BaselineLast{};
    origin_set_ = false;
    origin_ = Origin::LiveRadio;
    epoch_set_ = false;
    epoch_ = TimeEpoch{};
    latest_ = 0;
    has_latest_ = false;
    head_ = size_ = 0;
    saturated_until_ = 0;
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
    Millis age{};
    if (unexpected_reported_ && age_at(now, epoch_, unexpected_last_, age)) {
        r.last_incident_known = true; r.last_incident_age_ms = age;
        if (age < limits_.cooldown_ms) r.cooldown_remaining_ms = limits_.cooldown_ms - age;
    }
    // G25: a confirmed router change counts as the detector's last report (never cooled down: never re-fired).
    for (const auto& t : tracks_) {
        if (!t.used || !t.pending || !age_at(now, epoch_, t.first, age)) continue;
        if (!r.last_incident_known || age < r.last_incident_age_ms) { r.last_incident_known = true; r.last_incident_age_ms = age; }
    }
    return r;
}
} // namespace guardian

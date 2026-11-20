// G16F passive management-frame pattern detectors. Policy and limits:
// guardian/threats.hpp; behaviour checks: tests/threat_detectors_check.cpp
// (written and run RED first against stub detectors).
//
// Independent implementation: the behaviours follow the G16F ledger text
// (which describes AntiHunter c6ef921, AGPL-3.0-only, as the starting
// hypothesis); no AntiHunter code was read into or copied here. Standard C++
// only; no allocation; no pointer kept into a frame; no clock read. Nothing
// here reads a reason code, verifies a MIC, transmits, names a tool or
// attributes a frame to a person: header addresses are spoofable bytes.
#include "guardian/threats.hpp"

#include <algorithm>
#include <limits>

namespace guardian {

namespace {

constexpr Mac kBroadcastMac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
constexpr Mac kMarkerMac{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad};
constexpr Millis kMinWindowMs = 100;   // slot = window / 5 >= 20 ms

bool local_mac(const Mac& m) { return (m[0] & 0x02u) != 0; }
bool inside(Millis last, Millis at, Millis window) { return last + window > at; }   // also true for a newer `last`
void bump(std::uint32_t& n) { if (n < std::numeric_limits<std::uint32_t>::max()) ++n; }

// A slot for a new entry: a free one, else the oldest. Evicting an entry still
// inside `window` makes counts a lower bound until it would have left anyway.
template <class E, std::size_t N>
E& take(std::array<E, N>& table, Millis window, Millis& saturated_until) {
    E* oldest = nullptr;
    for (auto& e : table) {
        if (!e.used) { e = E{}; e.used = true; return e; }
        if (!oldest || e.last < oldest->last) oldest = &e;
    }
    saturated_until = std::max(saturated_until, oldest->last + window);
    *oldest = E{};
    oldest->used = true;
    return *oldest;
}
template <class E, std::size_t N, class Match>
E* find(std::array<E, N>& table, Match match) {
    for (auto& e : table) if (e.used && match(e)) return &e;
    return nullptr;
}

std::uint64_t cooldown_key(IncidentScope scope, Pattern pattern, const Mac& key) {
    std::uint64_t k = 0;
    for (auto b : key) k = (k << 8) | b;
    return k | (static_cast<std::uint64_t>(pattern) << 48) | (static_cast<std::uint64_t>(scope) << 56);
}

bool open_settings(const ParseResult& p) {
    const auto& s = p.settings;
    return s.privacy_valid && !s.privacy_bit && s.rsn.state == ElementState::Absent && s.wpa.state == ElementState::Absent;
}

IncidentObservation observation(const RxMeta& meta, Pattern pattern, IncidentScope scope, std::uint32_t count, Millis window,
                                std::uint32_t threshold, const Mac& bssid) {
    IncidentObservation o{};
    o.acquired = meta.acquired;
    o.pattern = pattern;
    o.scope = scope;
    o.count = count;
    o.window_ms = static_cast<std::uint32_t>(std::min<Millis>(window, std::numeric_limits<std::uint32_t>::max()));
    o.threshold = threshold;
    o.raw_frames = count;
    o.bssid = bssid;
    return o;
}

} // namespace

// ---- helpers ------------------------------------------------------------------------------
std::uint32_t name_key(const std::uint8_t* ssid, std::size_t size) {
    std::uint32_t h = 2166136261u;   // FNV-1a, 32 bit
    for (std::size_t i = 0; i < size; ++i) { h ^= ssid[i]; h *= 16777619u; }
    h ^= static_cast<std::uint32_t>(size) + 0x9e3779b9u;
    h *= 16777619u;
    return h;
}

bool lure_name(const std::uint8_t* ssid, std::size_t size) {
    static constexpr const char* words[] = {"free", "guest", "public", "open", "hotspot", "airport", "hotel"};
    for (const char* w : words) {
        std::size_t len = 0;
        while (w[len]) ++len;
        for (std::size_t i = 0; i + len <= size; ++i) {
            std::size_t k = 0;
            while (k < len) {
                std::uint8_t c = ssid[i + k];
                if (c >= 'A' && c <= 'Z') c = static_cast<std::uint8_t>(c - 'A' + 'a');
                if (c != static_cast<std::uint8_t>(w[k])) break;
                ++k;
            }
            if (k == len) return true;
        }
    }
    return false;
}

// ---- ThreatDetector -----------------------------------------------------------------------
ThreatDetector::ThreatDetector(const char* name, DetectorFamily family, const ApprovedScope& scope, const ThreatLimits& limits)
    : scope_(scope), limits_(limits), name_(name), family_(family) {}

void ThreatDetector::init(const ThreatLimits& limits) {
    limits_ = limits;
    configured_ = scope_.configured() && limits.cooldown_ms > 0 && limits.bssid_cooldown_ms > 0 && valid(limits);
    reset();
}

bool ThreatDetector::configure(const ThreatLimits& limits) {
    init(limits);
    return configured_;
}

void ThreatDetector::reset() {
    origin_set_ = epoch_set_ = false;
    origin_ = Origin::LiveRadio;
    epoch_ = TimeEpoch{};
    cooldowns_.fill(Cooldown{});
    has_coverage_ = false;
    coverage_ = CoverageReport{};
    frames_seen_ = events_ = incidents_ = 0;
    has_event_ = has_incident_ = false;
    last_event_ = last_incident_ = 0;
    clear_state();
}

void ThreatDetector::on_tick(Instant, ObservationSink&) {
    // Windows age on read (report / next frame); observations are emitted on
    // the frame that closes a threshold, so a tick has nothing to emit.
}

void ThreatDetector::coverage(const CoverageReport& report) {
    if (!report.sampled_at.valid()) return;
    if (epoch_set_ && report.sampled_at.epoch != epoch_) return;
    if (has_coverage_ && report.sampled_at.epoch == coverage_.sampled_at.epoch && report.sampled_at.at < coverage_.sampled_at.at) return;
    coverage_ = report;
    has_coverage_ = true;
}

bool ThreatDetector::admit(const RxMeta& meta, const ParseResult& parsed) {
    bump(frames_seen_);
    if (!configured_ || !available_) return false;
    if (meta.status != RxStatus::Ok || !parsed.header_valid) return false;
    return admit_input(meta.origin, meta.acquired);
}

bool ThreatDetector::admit_input(Origin origin, const Instant& at) {
    if (!configured_ || !available_ || !at.valid()) return false;
    if (!origin_set_) {
        origin_ = origin; origin_set_ = true;
        epoch_ = at.epoch; epoch_set_ = true;
        return true;
    }
    return origin == origin_ && at.epoch == epoch_;
}

void ThreatDetector::offered() { bump(frames_seen_); }

void ThreatDetector::counted(Millis at) {
    bump(events_);
    if (!has_event_ || at > last_event_) last_event_ = at;
    has_event_ = true;
}

bool ThreatDetector::emit(IncidentObservation o, const Mac& key, Millis cooldown, ObservationSink& out) {
    const std::uint64_t k = cooldown_key(o.scope, o.pattern, key);
    const Millis at = o.acquired.at;
    Cooldown* slot = nullptr;
    for (auto& c : cooldowns_) {
        if (!c.used || c.key != k) continue;
        if (at < c.at || at - c.at < c.length) return false;   // still cooling (or an older frame)
        slot = &c;
        break;
    }
    if (!slot) {
        for (auto& c : cooldowns_) if (!c.used || c.at + c.length <= at) { slot = &c; break; }
    }
    if (!slot) {   // every slot is cooling another key: replace the one that ends first
        slot = &cooldowns_[0];
        for (auto& c : cooldowns_) if (c.at + c.length < slot->at + slot->length) slot = &c;
    }
    *slot = Cooldown{k, at, cooldown, true};

    o.origin = origin_;
    o.family = family_;
    if (o.scope == IncidentScope::Network) {
        o.kind = IncidentKind::NetworkPattern;
        o.affected = scope_.selected().network;
    }
    if (has_coverage_ && coverage_.sampled_at.epoch == o.acquired.epoch && coverage_.sampled_at.at <= at
        && at - coverage_.sampled_at.at <= o.window_ms) {
        o.coverage_known = true;
        o.listened_ms = coverage_.listened_ms;
        o.coverage_window_ms = coverage_.window_ms;
        o.hopping = coverage_.hopping;
    }
    bump(incidents_);
    if (!has_incident_ || at > last_incident_) last_incident_ = at;
    has_incident_ = true;
    out.incident(o);
    return true;
}

DetectorReport ThreatDetector::report(Instant now) const {
    DetectorReport r{};
    r.name = name_;
    r.family = family_;
    r.scope = IncidentScope::Area;
    r.configured = configured_ && available_;   // G16G: an unfed detector is not shown as measuring
    r.frames_seen = frames_seen_;
    r.events_total = events_;
    r.incidents = incidents_;
    r.window_ms = static_cast<std::uint32_t>(std::min<Millis>(window_ms(), std::numeric_limits<std::uint32_t>::max()));
    const bool same = now.valid() && epoch_set_ && now.epoch == epoch_;
    if (!same) return r;
    r.events_in_window = in_window(now.at);
    if (has_event_ && now.at >= last_event_) { r.last_event_known = true; r.last_event_age_ms = now.at - last_event_; }
    if (has_incident_ && now.at >= last_incident_) { r.last_incident_known = true; r.last_incident_age_ms = now.at - last_incident_; }
    for (const auto& c : cooldowns_)
        if (c.used && c.at <= now.at && c.at + c.length > now.at) r.cooldown_remaining_ms = std::max(r.cooldown_remaining_ms, c.at + c.length - now.at);
    return r;
}

// Network when the BSSID is the picked network's: the selected or an owner-approved AP or, G16R, a BSSID
// heard advertising the picked network's exact name (and there is a selection to name).
#define SCOPE_OF(bssid) (scope_.has_selection() && in_network(bssid) ? IncidentScope::Network : IncidentScope::Area)
// One observation per cooldown per scope+pattern; network observations per BSSID.
#define COOLDOWN_KEY(scope, bssid) ((scope) == IncidentScope::Network ? (bssid) : Mac{})

// ---- (1) probe requests ------------------------------------------------------------------
ProbeFloodDetector::ProbeFloodDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("probe_flood", DetectorFamily::Probe, scope, limits) { init(limits); }

bool ProbeFloodDetector::valid(const ThreatLimits& l) const {
    return l.probe_window_ms >= kMinWindowMs && l.probe_flood > 0 && l.probe_flood_sources > 0
        && l.probe_flood_sources <= source_capacity && l.probe_source_flood > 0 && l.probe_name_sources > 0
        && l.probe_name_sources <= name_capacity;
}

void ProbeFloodDetector::clear_state() {
    probes_.clear();
    shaped_.clear();
    sources_.fill(Source{});
    rates_.fill(Rate{});
    names_.fill(NamePair{});
    sources_saturated_until_ = names_saturated_until_ = 0;
}

void ProbeFloodDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p) || p.kind != FrameKind::ProbeRequest) return;
    const Millis at = meta.acquired.at, w = limits_.probe_window_ms;
    counted(at);
    probes_.add(at, w);
    // G16J: probe requests carrying sequence control 0x0001 (sequence 0, fragment 1). Enough of
    // them inside the window halve every probe threshold.
    if (p.fragment == 1 && p.sequence == 0) shaped_.add(at, w);
    const std::uint16_t shapes = limits_.shape_frames && shaped_.sum(at, w) >= limits_.shape_frames ? shape::ProbeFixedSequence : std::uint16_t{0};
    const auto need = [&](std::uint32_t threshold) { return shapes ? halved(threshold) : threshold; };

    // Randomized-source flood: many probes from many distinct addresses.
    Source* s = find(sources_, [&](const Source& e) { return e.mac == p.addr2; });
    if (!s) { s = &take(sources_, w, sources_saturated_until_); s->mac = p.addr2; s->local = p.addr2_local; }
    s->last = std::max(s->last, at);
    std::uint32_t distinct = 0, local = 0;
    for (const auto& e : sources_) if (e.used && inside(e.last, at, w)) { ++distinct; local += e.local; }
    const std::uint32_t total = probes_.sum(at, w);
    if (total >= need(limits_.probe_flood) && distinct >= need(limits_.probe_flood_sources)) {
        auto o = observation(meta, Pattern::ProbeFloodRandom, IncidentScope::Area, total, w, need(limits_.probe_flood), Mac{});
        o.shapes = shapes;
        o.distinct_sources = distinct; o.sources_random = local * 2 > distinct; o.saturated = at < sources_saturated_until_;
        emit(o, Mac{}, limits_.cooldown_ms, out);
    }

    // Single-source flood: probe_source_flood per window, two windows in a row (per-address tumbling windows).
    Millis unused = 0;
    Rate* r = find(rates_, [&](const Rate& e) { return e.mac == p.addr2; });
    if (!r) { r = &take(rates_, 2 * w, unused); r->mac = p.addr2; r->start = at; }
    if (at >= r->start + w) {
        r->full_before = r->count >= need(limits_.probe_source_flood) && at < r->start + 2 * w;
        r->start = at;
        r->count = 0;
    }
    bump(r->count);
    r->last = std::max(r->last, at);
    if (r->full_before && r->count >= need(limits_.probe_source_flood)) {
        auto o = observation(meta, Pattern::ProbeFloodSource, IncidentScope::Area, r->count, w, need(limits_.probe_source_flood), p.addr2);
        o.shapes = shapes;
        o.distinct_sources = 1; o.sources_random = p.addr2_local;
        emit(o, Mac{}, limits_.cooldown_ms, out);
    }

    // Many addresses asking for one name (wildcard probes ask for none).
    if (p.ssid_kind != SsidKind::Present) return;
    const std::uint32_t key = name_key(p.identity.ssid.data(), p.identity.ssid_size);
    NamePair* n = find(names_, [&](const NamePair& e) { return e.name == key && e.mac == p.addr2; });
    if (!n) { n = &take(names_, w, names_saturated_until_); n->name = key; n->mac = p.addr2; n->local = p.addr2_local; }
    n->last = std::max(n->last, at);
    std::uint32_t askers = 0, local_askers = 0;
    for (const auto& e : names_) if (e.used && e.name == key && inside(e.last, at, w)) { ++askers; local_askers += e.local; }
    if (askers >= need(limits_.probe_name_sources)) {
        auto o = observation(meta, Pattern::ProbeFloodName, IncidentScope::Area, askers, w, need(limits_.probe_name_sources), Mac{});
        o.shapes = shapes;
        o.distinct_sources = askers; o.sources_random = local_askers * 2 > askers; o.saturated = at < names_saturated_until_;
        emit(o, Mac{}, limits_.cooldown_ms, out);
    }
}

// ---- (2) beacon flood --------------------------------------------------------------------
BeaconFloodDetector::BeaconFloodDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("beacon_flood", DetectorFamily::Beacon, scope, limits) { init(limits); }

bool BeaconFloodDetector::valid(const ThreatLimits& l) const {
    return l.beacon_window_ms >= kMinWindowMs && l.beacon_flood_bssids > 0 && l.beacon_flood_bssids <= capacity;
}
void BeaconFloodDetector::clear_state() { beacons_.clear(); seen_.fill(Seen{}); saturated_until_ = 0; }

void BeaconFloodDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p) || p.kind != FrameKind::Beacon) return;
    if (!meta.rssi_valid || meta.rssi_dbm < limits_.beacon_rssi_min) return;   // far away or unknown: never counts
    const Millis at = meta.acquired.at, w = limits_.beacon_window_ms;
    counted(at);
    beacons_.add(at, w);
    Seen* s = find(seen_, [&](const Seen& e) { return e.bssid == p.addr3; });
    if (!s) { s = &take(seen_, w, saturated_until_); s->bssid = p.addr3; s->local = local_mac(p.addr3); }
    s->last = std::max(s->last, at);
    // G16J: this BSSID's shapes right now (a timestamp that moves again clears the static one).
    std::uint16_t bits = template_address(p.addr2) ? shape::TemplateAddress : std::uint16_t{0};
    if (p.mgmt.timing_valid) {
        if (p.mgmt.beacon_interval_tu == 1000) bits |= shape::BeaconInterval1000;
        if (s->tsf_same > 0 && s->tsf == p.mgmt.tsf) bump(s->tsf_same);
        else { s->tsf = p.mgmt.tsf; s->tsf_same = 1; s->tsf_first = at; }
        if (limits_.tsf_static_beacons && s->tsf_same >= limits_.tsf_static_beacons && at >= s->tsf_first && at - s->tsf_first >= limits_.tsf_static_ms)
            bits |= shape::StaticTimestamp;
    }
    s->shapes = bits;
    std::uint32_t distinct = 0, local = 0, shaped = 0;
    std::uint16_t shapes = 0;
    for (const auto& e : seen_) if (e.used && inside(e.last, at, w)) {
        ++distinct; local += e.local;
        if (e.shapes) { ++shaped; shapes = static_cast<std::uint16_t>(shapes | e.shapes); }
    }
    const std::uint32_t half = halved(limits_.beacon_flood_bssids);
    const bool by_shape = shaped >= half;   // enough BSSIDs that look generated: half the count is a flood
    if (distinct < limits_.beacon_flood_bssids && !by_shape) return;
    auto o = observation(meta, Pattern::BeaconFlood, IncidentScope::Area, beacons_.sum(at, w), w,
                         distinct >= limits_.beacon_flood_bssids ? limits_.beacon_flood_bssids : half, Mac{});
    if (by_shape) o.shapes = shapes;
    o.distinct_sources = distinct; o.sources_random = local * 2 > distinct; o.saturated = at < saturated_until_;
    emit(o, Mac{}, limits_.cooldown_ms, out);
}

// ---- (3) one transmitter answering for many names --------------------------------------------
ResponderDetector::ResponderDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("responder", DetectorFamily::Responder, scope, limits) { init(limits); }

bool ResponderDetector::valid(const ThreatLimits& l) const {
    return l.responder_window_ms >= kMinWindowMs && l.responder_names > 0 && l.responder_names <= pair_capacity
        && l.responder_matched_names > 0 && l.responder_matched_names <= pair_capacity
        && l.karma_answer_ms >= kMinWindowMs && l.karma_answers > 0;
}
void ResponderDetector::clear_state() {
    answers_.clear(); pairs_.fill(Pair{}); asked_.fill(Asked{}); multi_.fill(Multi{}); saturated_until_ = 0;
    known_.fill(Known{}); answers_new_.fill(Answer{}); known_saturated_until_ = 0; started_ = 0; started_set_ = false;
}
// G16J probe-then-answer: a nearby device asked for a name, then a BSSID this detector never heard
// advertising before the ask answered or beaconed exactly that name (the shape of a tool that
// brings up one access point per asked name). Amber, area scope. Refused, so that ordinary life
// stays quiet: before karma_learn_ms of listening; while the known-BSSID table is saturated (an
// evicted AP could look new); the owner's selected / approved APs; a name some AP heard before
// the ask already advertised (a second AP of an existing network); fewer than karma_answers frames.
// Honest limit: a hotspot switched on within the answer window of a device asking for it by name
// looks the same from the air; the observation says what was received, never why.
void ResponderDetector::karma(const RxMeta& meta, const ParseResult& p, std::uint32_t key, bool, ObservationSink& out) {
    const Millis at = meta.acquired.at;
    if (!started_set_ || at < started_ + limits_.karma_learn_ms || at < known_saturated_until_) return;
    const Mac& bssid = p.addr3;
    if (in_scope(bssid)) return;
    const Asked* a = find(asked_, [&](const Asked& e) { return e.name == key && e.last <= at && at - e.last <= limits_.karma_answer_ms; });
    if (!a) return;
    const Known* self = find(known_, [&](const Known& e) { return e.bssid == bssid; });
    if (!self || self->first < a->first) return;   // heard before the device asked: an ordinary reply
    for (const auto& e : known_) if (e.used && e.name == key && !(e.bssid == bssid) && e.first < a->first) return;
    Millis unused = 0;
    Answer* n = find(answers_new_, [&](const Answer& e) { return e.bssid == bssid && e.name == key; });
    if (!n) { n = &take(answers_new_, limits_.karma_answer_ms, unused); n->bssid = bssid; n->name = key; }
    n->last = std::max(n->last, at);
    bump(n->frames);
    if (n->frames < limits_.karma_answers) return;
    auto o = observation(meta, Pattern::KarmaAnswer, IncidentScope::Area, n->frames, limits_.karma_answer_ms, limits_.karma_answers, bssid);
    o.distinct_sources = 1; o.sources_random = local_mac(bssid); o.corroborating = n->frames;
    emit(o, Mac{}, limits_.cooldown_ms, out);
}

void ResponderDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p)) return;
    const Millis at = meta.acquired.at, w = limits_.responder_window_ms;
    if (!started_set_) { started_ = at; started_set_ = true; }
    Millis unused = 0;
    if (p.kind == FrameKind::ProbeRequest) {   // a name a nearby device asked for
        if (p.ssid_kind != SsidKind::Present) return;
        const std::uint32_t key = name_key(p.identity.ssid.data(), p.identity.ssid_size);
        Asked* a = find(asked_, [&](const Asked& e) { return e.name == key; });
        if (!a) { a = &take(asked_, w, unused); a->name = key; a->first = at; }
        else if (!inside(a->last, at, w)) a->first = at;   // G16J: a new asking episode
        a->last = std::max(a->last, at);
        return;
    }
    if (p.kind != FrameKind::ProbeResponse && p.kind != FrameKind::Beacon) return;
    // G16J: every advertiser is "heard", with the name it last advertised (hidden names keep the earlier one).
    const bool named = p.ssid_kind == SsidKind::Present;
    const std::uint32_t key = named ? name_key(p.identity.ssid.data(), p.identity.ssid_size) : 0;
    Known* known = find(known_, [&](const Known& e) { return e.bssid == p.addr3; });
    const bool was_known = known != nullptr;
    if (!known) { known = &take(known_, w, known_saturated_until_); known->bssid = p.addr3; known->first = at; }
    if (named) known->name = key;
    known->last = std::max(known->last, at);
    if (p.mgmt.multi_bssid == ElementState::Valid) {   // Multiple-BSSID transmitter: excluded while it keeps saying so
        Multi* m = find(multi_, [&](const Multi& e) { return e.tx == p.addr2; });
        if (!m) { m = &take(multi_, w, unused); m->tx = p.addr2; }
        m->last = std::max(m->last, at);
        return;
    }
    if (find(multi_, [&](const Multi& e) { return e.tx == p.addr2 && inside(e.last, at, w); })) return;
    if (!named) return;   // hidden / absent names say nothing about answering
    karma(meta, p, key, was_known, out);
    counted(at);
    answers_.add(at, w);
    const bool asked = find(asked_, [&](const Asked& e) { return e.name == key && e.last <= at && inside(e.last, at, w); }) != nullptr;
    Pair* e = find(pairs_, [&](const Pair& x) { return x.tx == p.addr2 && x.name == key; });
    if (!e) { e = &take(pairs_, w, saturated_until_); e->tx = p.addr2; e->name = key; }
    e->matched = e->matched || asked;
    e->last = std::max(e->last, at);
    std::uint32_t names = 0, matched = 0;
    for (const auto& x : pairs_) if (x.used && x.tx == p.addr2 && inside(x.last, at, w)) { ++names; matched += x.matched; }
    // G16J: the placeholder transmitter address halves both counts.
    const std::uint16_t shapes = template_address(p.addr2) ? shape::TemplateAddress : std::uint16_t{0};
    const std::uint32_t need_names = shapes ? halved(limits_.responder_names) : limits_.responder_names;
    const std::uint32_t need_matched = shapes ? halved(limits_.responder_matched_names) : limits_.responder_matched_names;
    const bool by_names = names >= need_names, by_matched = matched >= need_matched;
    if (!by_names && !by_matched) return;
    auto o = observation(meta, Pattern::ManyNames, IncidentScope::Area, names, w, by_names ? need_names : need_matched, p.addr2);
    o.shapes = shapes;
    o.distinct_sources = 1; o.sources_random = p.addr2_local; o.corroborating = matched; o.saturated = at < saturated_until_;
    emit(o, Mac{}, limits_.cooldown_ms, out);
}

// ---- (4)-(6) join floods -------------------------------------------------------------------
namespace {
// Shared per-BSSID bookkeeping of the join-flood detectors: the counter entry
// and the distinct (BSSID, source) pairs inside the window.
template <std::size_t B>
BssidCounter& counter_for(std::array<BssidCounter, B>& table, const Mac& bssid, Millis at, Millis w, Millis& saturated) {
    BssidCounter* b = find(table, [&](const BssidCounter& e) { return e.bssid == bssid; });
    if (!b) { b = &take(table, w, saturated); b->bssid = bssid; }
    b->last = std::max(b->last, at);
    return *b;
}
template <std::size_t P>
void sources_for(std::array<SourcePair, P>& pairs, const Mac& bssid, const Mac& source, Millis at, Millis w, Millis& saturated,
                 std::uint32_t& distinct, std::uint32_t& local) {
    SourcePair* s = find(pairs, [&](const SourcePair& e) { return e.bssid == bssid && e.source == source; });
    if (!s) { s = &take(pairs, w, saturated); s->bssid = bssid; s->source = source; }
    s->last = std::max(s->last, at);
    distinct = local = 0;
    for (const auto& e : pairs) if (e.used && e.bssid == bssid && inside(e.last, at, w)) { ++distinct; local += local_mac(e.source); }
}
} // namespace

AuthFloodDetector::AuthFloodDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("auth_flood", DetectorFamily::Auth, scope, limits) { init(limits); }
bool AuthFloodDetector::valid(const ThreatLimits& l) const {
    return l.auth_window_ms >= kMinWindowMs && l.auth_flood > 0 && l.auth_flood_sources > 0 && l.auth_flood_sources <= pair_capacity;
}
void AuthFloodDetector::clear_state() { total_.clear(); bssids_.fill(BssidCounter{}); pairs_.fill(SourcePair{}); saturated_until_ = 0; }

void AuthFloodDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p) || p.kind != FrameKind::Authentication || !p.mgmt.auth_valid) return;
    if (p.mgmt.auth_algorithm != auth_algorithm::OpenSystem || p.mgmt.auth_transaction != 1) return;   // requests only
    const Mac bssid = p.addr3;
    if (p.addr2 == bssid) return;   // sent by the AP itself
    const Millis at = meta.acquired.at, w = limits_.auth_window_ms;
    counted(at);
    total_.add(at, w);
    auto& b = counter_for(bssids_, bssid, at, w, saturated_until_);
    b.a.add(at, w);
    std::uint32_t distinct = 0, local = 0;
    sources_for(pairs_, bssid, p.addr2, at, w, saturated_until_, distinct, local);
    const std::uint32_t count = b.a.sum(at, w);
    if (count < limits_.auth_flood || distinct < limits_.auth_flood_sources) return;
    const auto scope = SCOPE_OF(bssid);
    auto o = observation(meta, Pattern::AuthFlood, scope, count, w, limits_.auth_flood, bssid);
    o.distinct_sources = distinct; o.sources_random = local * 2 > distinct; o.saturated = at < saturated_until_;
    emit(o, COOLDOWN_KEY(scope, bssid), limits_.cooldown_ms, out);
}

SaeCommitDetector::SaeCommitDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("sae_commit", DetectorFamily::Auth, scope, limits) { init(limits); }
bool SaeCommitDetector::valid(const ThreatLimits& l) const { return l.auth_window_ms >= kMinWindowMs && l.sae_commit_excess > 0; }
void SaeCommitDetector::clear_state() { total_.clear(); bssids_.fill(BssidCounter{}); pairs_.fill(SourcePair{}); saturated_until_ = 0; }

void SaeCommitDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p) || p.kind != FrameKind::Authentication || !p.mgmt.auth_valid) return;
    if (p.mgmt.auth_algorithm != auth_algorithm::Sae) return;
    const bool commit = p.mgmt.auth_transaction == 1, confirm = p.mgmt.auth_transaction == 2;
    if (!commit && !confirm) return;
    const Mac bssid = p.addr3;
    if (p.addr2 == bssid) return;   // the AP's own commit / confirm
    const Millis at = meta.acquired.at, w = limits_.auth_window_ms;
    auto& b = counter_for(bssids_, bssid, at, w, saturated_until_);
    if (confirm) { b.b.add(at, w); return; }
    counted(at);
    total_.add(at, w);
    b.a.add(at, w);
    std::uint32_t distinct = 0, local = 0;
    sources_for(pairs_, bssid, p.addr2, at, w, saturated_until_, distinct, local);
    const std::uint32_t commits = b.a.sum(at, w), confirms = b.b.sum(at, w);
    const std::uint32_t excess = commits - std::min(commits, confirms);
    if (excess < limits_.sae_commit_excess) return;
    const auto scope = SCOPE_OF(bssid);
    auto o = observation(meta, Pattern::SaeCommitFlood, scope, excess, w, limits_.sae_commit_excess, bssid);
    o.raw_frames = commits; o.distinct_sources = distinct; o.sources_random = local * 2 > distinct; o.saturated = at < saturated_until_;
    emit(o, COOLDOWN_KEY(scope, bssid), limits_.cooldown_ms, out);
}

AssocSleepDetector::AssocSleepDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("assoc_sleep", DetectorFamily::Auth, scope, limits) { init(limits); }
bool AssocSleepDetector::valid(const ThreatLimits& l) const {
    return l.auth_window_ms >= kMinWindowMs && l.assoc_sleep > 0 && l.assoc_sleep_sources > 0 && l.assoc_sleep_sources <= pair_capacity;
}
void AssocSleepDetector::clear_state() { total_.clear(); bssids_.fill(BssidCounter{}); pairs_.fill(SourcePair{}); saturated_until_ = 0; }

void AssocSleepDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p) || (p.kind != FrameKind::AssociationRequest && p.kind != FrameKind::ReassociationRequest)) return;
    if (!p.power_management) return;
    const Mac bssid = p.addr3;
    if (p.addr2 == bssid) return;
    const Millis at = meta.acquired.at, w = limits_.auth_window_ms;
    counted(at);
    total_.add(at, w);
    auto& b = counter_for(bssids_, bssid, at, w, saturated_until_);
    b.a.add(at, w);
    std::uint32_t distinct = 0, local = 0;
    sources_for(pairs_, bssid, p.addr2, at, w, saturated_until_, distinct, local);
    const std::uint32_t count = b.a.sum(at, w);
    const bool by_count = count >= limits_.assoc_sleep, by_sources = distinct >= limits_.assoc_sleep_sources;
    if (!by_count && !by_sources) return;
    const auto scope = SCOPE_OF(bssid);
    auto o = observation(meta, Pattern::AssocSleep, scope, count, w, by_count ? limits_.assoc_sleep : limits_.assoc_sleep_sources, bssid);
    o.distinct_sources = distinct; o.sources_random = local * 2 > distinct; o.saturated = at < saturated_until_;
    emit(o, COOLDOWN_KEY(scope, bssid), limits_.cooldown_ms, out);
}

// ---- (7) channel switch / quiet ------------------------------------------------------------
ChannelSwitchDetector::ChannelSwitchDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("channel_switch", DetectorFamily::ChannelSwitch, scope, limits) { init(limits); }
bool ChannelSwitchDetector::valid(const ThreatLimits& l) const {
    return l.csa_count_min > 0 && l.csa_count_min <= 255 && l.quiet_duration_tu > 0 && l.quiet_duration_tu <= 0xffff
        && l.csa_mix_ms > 0 && l.csa_mixed > 0 && l.csa_window_ms >= kMinWindowMs;
}
void ChannelSwitchDetector::clear_state() { frames_.clear(); tracks_.fill(Track{}); }

void ChannelSwitchDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p) || (p.kind != FrameKind::Beacon && p.kind != FrameKind::ProbeResponse)) return;
    const Mac bssid = p.addr3;
    const Millis at = meta.acquired.at, w = limits_.csa_window_ms;
    const bool csa = p.mgmt.csa == ElementState::Valid;
    const auto scope = SCOPE_OF(bssid);
    if (csa && p.mgmt.csa_count >= limits_.csa_count_min) {
        counted(at);
        frames_.add(at, w);
        auto o = observation(meta, Pattern::ChannelSwitch, scope, frames_.sum(at, w), w, limits_.csa_count_min, bssid);
        if (p.mgmt.csa_count == 0xff) o.shapes = shape::SwitchCount255;   // G16J
        emit(o, bssid, limits_.bssid_cooldown_ms, out);
    }
    if (p.mgmt.quiet == ElementState::Valid && p.mgmt.quiet_max_duration_tu >= limits_.quiet_duration_tu) {
        counted(at);
        frames_.add(at, w);
        auto o = observation(meta, Pattern::QuietOrder, scope, frames_.sum(at, w), w, limits_.quiet_duration_tu, bssid);
        emit(o, bssid, limits_.bssid_cooldown_ms, out);
    }
    // The selected / an approved AP: a real announcement stays in every beacon
    // until the switch, so an own beacon WITHOUT it right after one WITH it
    // means the announcement did not come from the AP's own beacon stream.
    if (scope != IncidentScope::Network || p.kind != FrameKind::Beacon) return;
    Millis unused = 0;
    Track* t = find(tracks_, [&](const Track& e) { return e.bssid == bssid; });
    if (!t) { if (!csa) return; t = &take(tracks_, w, unused); t->bssid = bssid; }
    t->last = std::max(t->last, at);
    if (csa) { t->last_csa = std::max(t->last_csa, at); t->has_csa = true; return; }
    if (!t->has_csa || at < t->last_csa || at - t->last_csa > limits_.csa_mix_ms) return;
    counted(at);
    frames_.add(at, w);
    t->mixed.add(at, w);
    const std::uint32_t mixed = t->mixed.sum(at, w);
    if (mixed < limits_.csa_mixed) return;
    auto o = observation(meta, Pattern::ChannelSwitch, scope, mixed, w, limits_.csa_mixed, bssid);
    o.corroborating = mixed;
    emit(o, bssid, limits_.bssid_cooldown_ms, out);
}

// ---- (8) name mismatch -------------------------------------------------------------------
NameMismatchDetector::NameMismatchDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("name_mismatch", DetectorFamily::Identity, scope, limits) { init(limits); }
bool NameMismatchDetector::valid(const ThreatLimits& l) const { return l.mismatch_window_ms >= kMinWindowMs && l.mismatch_responses > 0; }
void NameMismatchDetector::clear_state() { mismatches_.clear(); beacons_.fill(Beacon{}); counters_.fill(BssidCounter{}); }

void NameMismatchDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p)) return;
    const Mac bssid = p.addr3;
    const Millis at = meta.acquired.at, w = limits_.mismatch_window_ms;
    Millis unused = 0;
    if (p.kind == FrameKind::Beacon) {
        const bool hidden = hidden_ssid(p.ssid_kind);
        if (!hidden && p.ssid_kind != SsidKind::Present) return;
        Beacon* b = find(beacons_, [&](const Beacon& e) { return e.bssid == bssid; });
        if (!b) { b = &take(beacons_, w, unused); b->bssid = bssid; }
        if (at < b->last) return;   // an older beacon never overwrites the newest name
        b->hidden = hidden;
        b->name = hidden ? 0 : name_key(p.identity.ssid.data(), p.identity.ssid_size);
        b->last = at;
        return;
    }
    if (p.kind != FrameKind::ProbeResponse || p.ssid_kind != SsidKind::Present) return;
    const Beacon* b = find(beacons_, [&](const Beacon& e) { return e.bssid == bssid && inside(e.last, at, w); });
    if (!b || b->hidden) return;   // no recent beacon name, or a hidden AP answering with its real name
    if (b->name == name_key(p.identity.ssid.data(), p.identity.ssid_size)) return;
    counted(at);
    mismatches_.add(at, w);
    BssidCounter* c = find(counters_, [&](const BssidCounter& e) { return e.bssid == bssid; });
    if (!c) { c = &take(counters_, w, unused); c->bssid = bssid; }
    c->last = std::max(c->last, at);
    c->a.add(at, w);
    const std::uint32_t n = c->a.sum(at, w);
    if (n < limits_.mismatch_responses) return;
    const auto scope = SCOPE_OF(bssid);
    auto o = observation(meta, Pattern::NameMismatch, scope, n, w, limits_.mismatch_responses, bssid);
    emit(o, COOLDOWN_KEY(scope, bssid), limits_.cooldown_ms, out);
}

// ---- (9) marked beacons ------------------------------------------------------------------
MarkedBeaconDetector::MarkedBeaconDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("marked_beacon", DetectorFamily::Beacon, scope, limits) { init(limits); }
bool MarkedBeaconDetector::valid(const ThreatLimits& l) const { return l.bssid_cooldown_ms >= kMinWindowMs; }
void MarkedBeaconDetector::clear_state() { marked_.clear(); }

void MarkedBeaconDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p) || p.kind != FrameKind::Beacon) return;
    const bool marked = p.mgmt.element222_count > 0 || p.addr2 == kMarkerMac || p.addr3 == kMarkerMac;
    if (!marked) return;
    const Millis at = meta.acquired.at, w = limits_.bssid_cooldown_ms;
    counted(at);
    marked_.add(at, w);
    auto o = observation(meta, Pattern::MarkedBeacon, IncidentScope::Area, marked_.sum(at, w), w, 1, p.addr3);
    emit(o, p.addr3, limits_.bssid_cooldown_ms, out);
}

// ---- (10) OWE transition twin ------------------------------------------------------------
OweTwinDetector::OweTwinDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("owe_twin", DetectorFamily::Identity, scope, limits) { init(limits); }
bool OweTwinDetector::valid(const ThreatLimits& l) const {
    return l.owe_memory_ms >= kMinWindowMs && l.owe_window_ms >= kMinWindowMs && l.owe_twin_beacons > 0;
}
void OweTwinDetector::clear_state() { twins_.clear(); declared_.fill(Declared{}); counters_.fill(BssidCounter{}); }

void OweTwinDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p) || (p.kind != FrameKind::Beacon && p.kind != FrameKind::ProbeResponse)) return;
    const Millis at = meta.acquired.at, w = limits_.owe_window_ms, memory = limits_.owe_memory_ms;
    Millis unused = 0;
    const auto declare = [&](std::uint32_t name, const Mac& open) {
        Declared* d = find(declared_, [&](const Declared& e) { return e.name == name && e.open_bssid == open; });
        if (!d) { d = &take(declared_, memory, unused); d->name = name; d->open_bssid = open; }
        d->last = std::max(d->last, at);
    };
    const auto& s = p.settings;
    if (s.owe_transition == ElementState::Valid) {
        const bool owe_side = s.rsn.state == ElementState::Valid && (s.rsn.akms.kinds & akm::Owe) != 0;
        if (owe_side && p.mgmt.owe_partner_ssid_size > 0)
            declare(name_key(p.mgmt.owe_partner_ssid.data(), p.mgmt.owe_partner_ssid_size), p.mgmt.owe_partner_bssid);
        else if (!owe_side && open_settings(p) && p.ssid_kind == SsidKind::Present)
            declare(name_key(p.identity.ssid.data(), p.identity.ssid_size), p.addr3);
        return;
    }
    if (!open_settings(p) || p.ssid_kind != SsidKind::Present || s.owe_transition != ElementState::Absent) return;
    const std::uint32_t key = name_key(p.identity.ssid.data(), p.identity.ssid_size);
    bool known = false;
    for (const auto& e : declared_) {
        if (!e.used || e.name != key || !inside(e.last, at, memory)) continue;
        if (e.open_bssid == p.addr3) return;   // the declared open side itself
        known = true;
    }
    if (!known) return;   // no OWE pair uses this name: an ordinary open network
    counted(at);
    twins_.add(at, w);
    BssidCounter* c = find(counters_, [&](const BssidCounter& e) { return e.bssid == p.addr3; });
    if (!c) { c = &take(counters_, w, unused); c->bssid = p.addr3; }
    c->last = std::max(c->last, at);
    c->a.add(at, w);
    const std::uint32_t n = c->a.sum(at, w);
    if (n < limits_.owe_twin_beacons) return;
    // About the owner's network when the reused name is the selected network's name.
    const auto& sel = scope_.selected().network;
    const auto scope = scope_.has_selection() && name_key(sel.ssid.data(), sel.ssid_size) == key ? IncidentScope::Network : IncidentScope::Area;
    auto o = observation(meta, Pattern::OpenTwin, scope, n, w, limits_.owe_twin_beacons, p.addr3);
    emit(o, COOLDOWN_KEY(scope, p.addr3), limits_.cooldown_ms, out);
}

// ---- (11) disconnect frames nearby -----------------------------------------------------------
AreaDisconnectDetector::AreaDisconnectDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("area_disconnect", DetectorFamily::Disconnect, scope, limits) { init(limits); }
bool AreaDisconnectDetector::valid(const ThreatLimits& l) const {
    return l.deauth_source_window_ms >= kMinWindowMs && l.deauth_pair_window_ms >= kMinWindowMs
        && l.deauth_broadcast_window_ms >= kMinWindowMs && l.deauth_source > 0 && l.deauth_pair > 0 && l.deauth_broadcast > 0;
}
void AreaDisconnectDetector::clear_state() {
    all_.clear(); broadcast_.clear(); sources_.fill(Keyed{}); pairs_.fill(Keyed{}); recent_.fill(Header{});
    recent_next_ = 0; saturated_until_ = 0; broadcast_shapes_.clear(); runs_.clear();
    for (auto& t : traces_) t.clear();
    reached_ = IncidentObservation{};
}

LastBurst AreaDisconnectDetector::last_burst(IncidentScope scope, Instant now) const {   // G16S
    const bool same = bound_to(now);
    // Another timebase cannot say whether the window is still open: read as closed, age unknown.
    const Millis at = same ? now.at : std::numeric_limits<Millis>::max(), ws = limits_.deauth_source_window_ms;
    LastBurst b = traces_[0].last(at, ws);
    if (scope == IncidentScope::Network) {
        // G16T: a nearby burst that named the picked network is the picked network's burst too.
        // It stays the picked network's record after a later nearby burst that named it not
        // (MEASURED 2026-11-19 13:28: the second burst of one Bruce run had cleared it).
        b = traces_[0].last_own(at, ws);
        const LastBurst pair = traces_[1].last(at, ws);
        if (!b.known || (pair.known && pair.incident_at > b.incident_at)) b = pair;
    }
    b.age_known = b.known && same && now.at >= b.incident_at;
    b.age_ms = b.age_known ? now.at - b.incident_at : 0;
    return b;
}

void AreaDisconnectDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p) || (p.kind != FrameKind::Deauthentication && p.kind != FrameKind::Disassociation)) return;
    // The picked network (G16R: by its name, any address heard under it): the source and broadcast
    // counts stay DisconnectDetector's red burst. G16J: the PAIR rule applies there too (many frames
    // to one device inside a second), reported as a network pattern.
    const bool own = in_network(p.addr3);
    if (own && !scope_.has_selection()) return;
    const Millis at = meta.acquired.at;
    const auto kind = static_cast<std::uint8_t>(p.kind);
    // Retry-bit copy of a header seen within dedupe_ms: a retransmission, not a new frame (G06 rule).
    if (p.retry) {
        for (auto& h : recent_) {
            if (h.used && h.kind == kind && h.sequence == p.sequence && h.fragment == p.fragment && h.a1 == p.addr1 && h.a2 == p.addr2
                && h.a3 == p.addr3 && at >= h.at && at - h.at <= limits_.dedupe_ms && h.copies < retry_copies_max) {
                ++h.copies;   // G22: a bounded retry chain, timed from the counted frame (a copy used to move h.at forward for ever)
                return;
            }
        }
    }
    recent_[recent_next_] = Header{p.addr1, p.addr2, p.addr3, p.sequence, p.fragment, kind, at, true, 0};
    recent_next_ = (recent_next_ + 1) % recent_.size();
    const Millis ws = limits_.deauth_source_window_ms;
    // G16J tool shapes of this counted frame (kept for one source window per key).
    const std::uint16_t frame_bits = limits_.shape_frames ? disconnect_frame_shapes(p) : std::uint16_t{0};
    const std::uint16_t run_bits = runs_.observe(p, at, limits_.shape_run, ws);
    // G16S: who this counted frame named. G16T: every counted frame enters the nearby table, marked
    // when it names the picked network in any address field; the picked network's own frames
    // (Address 3) also enter the table of the pair rule, as before.
    const bool names_picked = scope_.has_selection() && (own || in_network(p.addr1) || in_network(p.addr2));
    BurstTrace& nearby = traces_[0];
    nearby.seen(p.addr1, p.addr2, p.addr3, meta.channel, at, ws, names_picked);
    if (own) traces_[1].seen(p.addr1, p.addr2, p.addr3, meta.channel, at, ws);
    rules(meta, p, own, frame_bits, run_bits, out);
    // G16T: a nearby burst that is being counted and holds a frame naming the picked network is a
    // Network incident: at the frame that reaches the nearby rule, or at the first such frame after it.
    if (!scope_.has_selection() || !nearby.open(at, ws)) return;
    const std::uint32_t own_frames = nearby.own(at, ws);
    if (own_frames == 0) return;
    IncidentObservation o = reached_;      // the rule, its count and threshold as last reached in this burst
    o.acquired = meta.acquired;
    o.scope = IncidentScope::Network;
    o.own_frames = own_frames;
    const BurstTuple named = nearby.top_own(at, ws);
    if (named.count) {
        o.top = named;
        o.bssid = in_network(named.bssid) ? named.bssid : in_network(named.receiver) ? named.receiver : named.sender;
    }
    emit(o, Mac{}, limits_.cooldown_ms, out);
}

void AreaDisconnectDetector::rules(const RxMeta& meta, const ParseResult& p, bool own, std::uint16_t frame_bits, std::uint16_t run_bits,
                                   ObservationSink& out) {
    const Millis at = meta.acquired.at;
    const Millis ws = limits_.deauth_source_window_ms, wp = limits_.deauth_pair_window_ms, wb = limits_.deauth_broadcast_window_ms;
    const auto need = [](std::uint16_t shapes, std::uint32_t threshold) { return shapes ? halved(threshold) : threshold; };
    // G16S: a rule that is reached records the burst (also when its report is inside a cooldown) and
    // puts the most frequent tuple into the observation. G16T: a nearby rule reports as Area only
    // while no frame of its burst named the picked network (on_frame makes the Network report).
    BurstTrace& nearby = traces_[0];
    const auto nearby_reached = [&](IncidentObservation& o) {
        nearby.incident(at, ws, o.pattern);
        o.top = nearby.top(at, ws);
        reached_ = o;
        if (nearby.own(at, ws) == 0) emit(o, Mac{}, limits_.cooldown_ms, out);
    };

    if (!own) {
        counted(at);
        all_.add(at, ws);
        Keyed* s = find(sources_, [&](const Keyed& e) { return e.a == p.addr2; });
        if (!s) { s = &take(sources_, ws, saturated_until_); s->a = p.addr2; }
        s->last = std::max(s->last, at);
        s->n.add(at, ws);
        s->shapes.add(frame_bits, run_bits, at, ws);
        const std::uint16_t shapes = s->shapes.current(at, ws, limits_.shape_frames);
        const std::uint32_t by_source = s->n.sum(at, ws);
        if (by_source >= need(shapes, limits_.deauth_source)) {
            auto o = observation(meta, Pattern::DeauthSource, IncidentScope::Area, by_source, ws, need(shapes, limits_.deauth_source), p.addr2);
            o.shapes = shapes;
            o.distinct_sources = 1; o.sources_random = p.addr2_local; o.saturated = at < saturated_until_;
            o.protected_frames = p.protected_frame ? 1u : 0u;
            nearby_reached(o);
        }
        if (p.addr1 == kBroadcastMac) {
            broadcast_.add(at, wb);
            broadcast_shapes_.add(frame_bits, run_bits, at, wb);
            const std::uint16_t bshapes = broadcast_shapes_.current(at, wb, limits_.shape_frames);
            const std::uint32_t n = broadcast_.sum(at, wb);
            if (n >= need(bshapes, limits_.deauth_broadcast)) {
                auto o = observation(meta, Pattern::DeauthBroadcast, IncidentScope::Area, n, wb, need(bshapes, limits_.deauth_broadcast), p.addr2);
                o.shapes = bshapes;
                nearby_reached(o);
            }
            return;
        }
    }
    if (p.addr1 == kBroadcastMac) return;   // own network, broadcast: the red burst counts it
    Keyed* q = find(pairs_, [&](const Keyed& e) { return e.a == p.addr2 && e.b == p.addr1; });
    if (!q) { q = &take(pairs_, wp, saturated_until_); q->a = p.addr2; q->b = p.addr1; }
    q->last = std::max(q->last, at);
    q->n.add(at, wp);
    q->shapes.add(frame_bits, run_bits, at, ws);
    const std::uint16_t shapes = q->shapes.current(at, ws, limits_.shape_frames);
    const std::uint32_t by_pair = q->n.sum(at, wp);
    if (by_pair < need(shapes, limits_.deauth_pair)) return;
    const auto scope = own ? IncidentScope::Network : IncidentScope::Area;
    auto o = observation(meta, Pattern::DeauthPair, scope, by_pair, wp, need(shapes, limits_.deauth_pair), own ? p.addr3 : p.addr2);
    o.shapes = shapes;
    o.distinct_sources = 1; o.sources_random = p.addr2_local; o.saturated = at < saturated_until_;
    if (!own) { nearby_reached(o); return; }
    // The picked network's own pair rule: its record and its report are unchanged.
    traces_[1].incident(at, ws, o.pattern);
    o.top = traces_[1].top(at, ws);
    emit(o, p.addr3, limits_.cooldown_ms, out);
}

// ---- (12) name rotation ------------------------------------------------------------------
NameRotationDetector::NameRotationDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("rotation", DetectorFamily::Beacon, scope, limits) { init(limits); }
bool NameRotationDetector::valid(const ThreatLimits& l) const {
    return l.rotation_window_ms >= kMinWindowMs && l.rotation_names > 0 && l.rotation_names <= pair_capacity && l.tsf_static_ms > 0;
}
void NameRotationDetector::clear_state() {
    names_.clear(); pairs_.fill(Pair{}); multi_.fill(Multi{}); saturated_until_ = 0; stamps_.fill(Stamp{}); lures_.fill(BssidCounter{});
}

void NameRotationDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p) || p.kind != FrameKind::Beacon) return;
    const Millis at = meta.acquired.at, w = limits_.rotation_window_ms;
    Millis unused = 0;
    if (p.mgmt.multi_bssid == ElementState::Valid) {
        Multi* m = find(multi_, [&](const Multi& e) { return e.tx == p.addr2; });
        if (!m) { m = &take(multi_, w, unused); m->tx = p.addr2; }
        m->last = std::max(m->last, at);
        return;
    }
    if (find(multi_, [&](const Multi& e) { return e.tx == p.addr2 && inside(e.last, at, w); })) return;
    if (p.ssid_kind != SsidKind::Present) return;
    const std::uint32_t key = name_key(p.identity.ssid.data(), p.identity.ssid_size);
    const bool lure = open_settings(p) && lure_name(p.identity.ssid.data(), p.identity.ssid_size);
    counted(at);
    names_.add(at, w);
    // G16J: this transmitter's shapes right now (placeholder address, beacon interval 1000, a
    // timestamp that never advances).
    Stamp* st = find(stamps_, [&](const Stamp& x) { return x.tx == p.addr2; });
    if (!st) { st = &take(stamps_, w, unused); st->tx = p.addr2; }
    st->last = std::max(st->last, at);
    std::uint16_t shapes = template_address(p.addr2) ? shape::TemplateAddress : std::uint16_t{0};
    if (p.mgmt.timing_valid) {
        if (p.mgmt.beacon_interval_tu == 1000) shapes |= shape::BeaconInterval1000;
        if (st->same > 0 && st->tsf == p.mgmt.tsf) bump(st->same);
        else { st->tsf = p.mgmt.tsf; st->same = 1; st->first = at; }
        if (limits_.tsf_static_beacons && st->same >= limits_.tsf_static_beacons && at >= st->first && at - st->first >= limits_.tsf_static_ms)
            shapes |= shape::StaticTimestamp;
    }
    st->shapes = shapes;
    // G16J: an open lure-style name beaconed from a development-board vendor address (the shape of a
    // pocket tool's captive portal: ONE name per access point, so the rotation count never sees it).
    if (lure && limits_.lure_beacons && board_vendor(p.addr3)) {
        BssidCounter* c = find(lures_, [&](const BssidCounter& x) { return x.bssid == p.addr3; });
        if (!c) { c = &take(lures_, w, unused); c->bssid = p.addr3; }
        c->last = std::max(c->last, at);
        c->a.add(at, w);
        const std::uint32_t n = c->a.sum(at, w);
        if (n >= limits_.lure_beacons) {
            auto o = observation(meta, Pattern::LurePortal, IncidentScope::Area, n, w, limits_.lure_beacons, p.addr3);
            o.shapes = shape::BoardVendorLure;
            o.distinct_sources = 1; o.sources_random = false;
            emit(o, Mac{}, limits_.cooldown_ms, out);
        }
    }
    Pair* e = find(pairs_, [&](const Pair& x) { return x.tx == p.addr2 && x.name == key; });
    if (!e) { e = &take(pairs_, w, saturated_until_); e->tx = p.addr2; e->name = key; }
    e->lure = e->lure || lure;
    e->last = std::max(e->last, at);
    std::uint32_t names = 0, lures = 0;
    for (const auto& x : pairs_) if (x.used && x.tx == p.addr2 && inside(x.last, at, w)) { ++names; lures += x.lure; }
    const std::uint32_t need = shapes ? halved(limits_.rotation_names) : limits_.rotation_names;
    if (names < need) return;
    auto o = observation(meta, lures ? Pattern::OpenLure : Pattern::NameRotation, IncidentScope::Area, names, w, need, p.addr2);
    o.shapes = shapes;
    o.distinct_sources = 1; o.sources_random = p.addr2_local; o.corroborating = lures; o.saturated = at < saturated_until_;
    emit(o, Mac{}, limits_.cooldown_ms, out);
}

#undef SCOPE_OF
#undef COOLDOWN_KEY

// ---- the set -----------------------------------------------------------------------------
ThreatDetectors::ThreatDetectors(const ApprovedScope& s, const ThreatLimits& l)
    : probe(s, l), beacon(s, l), responder(s, l), auth(s, l), sae(s, l), assoc(s, l), channel_switch(s, l), mismatch(s, l),
      marked(s, l), owe(s, l), deauth(s, l), rotation(s, l), handshake(s, l), noise(s, l), ble(s, l) {}

FrameDetector* ThreatDetectors::at(std::size_t i) {
    FrameDetector* all[count] = {&probe, &beacon, &responder, &auth, &sae, &assoc, &channel_switch, &mismatch, &marked, &owe, &deauth, &rotation,
                                 &handshake, &noise, &ble};
    return i < count ? all[i] : nullptr;
}

bool ThreatDetectors::configure(const ThreatLimits& l) {
    ThreatDetector* all[count] = {&probe, &beacon, &responder, &auth, &sae, &assoc, &channel_switch, &mismatch, &marked, &owe, &deauth, &rotation,
                                  &handshake, &noise, &ble};
    if (l.cooldown_ms == 0 || l.bssid_cooldown_ms == 0) return false;
    for (auto* d : all) if (!d->accepts(l)) return false;
    for (auto* d : all) d->configure(l);
    return true;
}

} // namespace guardian

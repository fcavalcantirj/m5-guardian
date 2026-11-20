// G16G passive data-path detectors. Policy and limits: guardian/threats.hpp;
// behaviour checks: tests/datapath_check.cpp (written and run RED first
// against stub detectors that counted nothing).
//
// Independent implementation of the behaviour described in guardian-tasks.json
// G16G (which takes AntiHunter c6ef921, AGPL-3.0-only, as the starting
// hypothesis); no AntiHunter code was read into or copied here. Standard C++
// only; no allocation; no pointer kept into a frame; no clock read. Nothing
// here verifies a MIC, keeps a PMKID or a nonce, transmits, names a tool or
// attributes a frame to a person: addresses are spoofable bytes.
#include "guardian/threats.hpp"

#include <algorithm>
#include <limits>

namespace guardian {

namespace {

constexpr Mac kBroadcastMac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
constexpr Millis kMinWindowMs = 100;

bool local_mac(const Mac& m) { return (m[0] & 0x02u) != 0; }
bool inside(Millis last, Millis at, Millis window) { return last + window > at; }

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

std::uint8_t message_bit(EapolMessage m) {
    switch (m) {
    case EapolMessage::M1: return 1u << 0;
    case EapolMessage::M2: return 1u << 1;
    case EapolMessage::M3: return 1u << 2;
    case EapolMessage::M4: return 1u << 3;
    case EapolMessage::None:
    case EapolMessage::Group: break;
    }
    return 0;
}
std::uint32_t bits(std::uint8_t v) { std::uint32_t n = 0; for (; v; v &= static_cast<std::uint8_t>(v - 1)) ++n; return n; }

IncidentObservation make(const Instant& at, Pattern pattern, IncidentScope scope, std::uint32_t count, Millis window,
                         std::uint32_t threshold, const Mac& bssid) {
    IncidentObservation o{};
    o.acquired = at;
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

// ---- (13)-(15) handshake patterns ------------------------------------------------------------
HandshakeDetector::HandshakeDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("handshake", DetectorFamily::Auth, scope, limits) { init(limits); }

bool HandshakeDetector::valid(const ThreatLimits& l) const {
    return l.harvest_window_ms >= kMinWindowMs && l.harvest_bssids >= 2 && l.harvest_bssids <= start_capacity
        && l.harvest_settle_ms < l.harvest_window_ms && l.fake_m1 > 0 && l.fake_m1_window_ms >= kMinWindowMs
        && l.reconnect_ms > 0 && l.reconnect_burst_window_ms >= kMinWindowMs && l.reconnect_burst > 0
        && l.reconnect_messages >= 1 && l.reconnect_messages <= 4 && l.dedupe_ms > 0 && l.bait_ms > 0;
}

void HandshakeDetector::clear_state() {
    messages_.clear();
    starts_.fill(Start{});
    fake_.fill(BssidCounter{});
    counters_.fill(Counter{});
    bursts_.fill(Burst{});
    exchanges_.fill(Exchange{});
    recent_.fill(Header{});
    recent_next_ = 0;
    saturated_until_ = 0;
    runs_.clear();
}

void HandshakeDetector::on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    if (!admit(meta, p)) return;
    if (p.kind == FrameKind::Deauthentication || p.kind == FrameKind::Disassociation) disconnect(meta, p, out);
    else if (p.kind == FrameKind::EapolData && p.status == ParseStatus::Complete && p.eapol.state == ElementState::Valid) {
        key(meta, p, out);
        settle(meta.acquired, out);   // also on on_tick: the settle time must pass without frames
    }
}

void HandshakeDetector::on_tick(Instant now, ObservationSink& out) {
    if (!configured() || !available() || !bound_to(now)) return;
    settle(now, out);
}

void HandshakeDetector::disconnect(const RxMeta& meta, const ParseResult& p, ObservationSink&) {
    // Only the picked network's APs (G16R: selected, approved or heard under its name): "clients of
    // your network were pushed off".
    if (!scope_.has_selection() || !in_network(p.addr3)) return;
    const Millis at = meta.acquired.at;
    const auto kind = static_cast<std::uint8_t>(p.kind);
    if (p.retry) {   // a retransmission of a header seen within dedupe_ms is not a new frame (G06 rule)
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
    // The station is the side that is not the AP (Address 1 may be broadcast).
    const Mac ap = p.addr3;
    const Mac station = p.addr2 == ap ? p.addr1 : p.addr2;
    const Millis w = limits_.reconnect_burst_window_ms;
    Counter* c = find(counters_, [&](const Counter& e) { return e.ap == ap && e.station == station; });
    if (!c) { c = &take(counters_, w, saturated_until_); c->ap = ap; c->station = station; }
    c->last = std::max(c->last, at);
    c->n.add(at, w);
    // G16J: disconnect frames showing a tool shape halve the burst (rounded up), and a handshake
    // then counts for bait_ms instead of reconnect_ms (a capture can wait for the client to return).
    c->shapes.add(limits_.shape_frames ? disconnect_frame_shapes(p) : std::uint16_t{0}, runs_.observe(p, at, limits_.shape_run, w), at, w);
    const std::uint16_t shapes = c->shapes.current(at, w, limits_.shape_frames);
    const std::uint32_t n = c->n.sum(at, w);
    if (n < (shapes ? halved(limits_.reconnect_burst) : limits_.reconnect_burst)) return;
    Burst* b = find(bursts_, [&](const Burst& e) {
        return e.ap == ap && e.station == station && at <= e.last + (e.shapes ? std::max(limits_.bait_ms, limits_.reconnect_ms) : limits_.reconnect_ms);
    });
    if (!b) {
        Millis unused = 0;
        b = &take(bursts_, limits_.reconnect_ms, unused);
        b->ap = ap; b->station = station; b->first = at;
    }
    b->last = std::max(b->last, at);
    b->count = std::max(b->count, n);
    b->shapes = static_cast<std::uint16_t>(b->shapes | shapes);
}

void HandshakeDetector::key(const RxMeta& meta, const ParseResult& p, ObservationSink& out) {
    const auto& k = p.eapol;
    const Millis at = meta.acquired.at;
    const Mac& ap = k.authenticator;
    const Mac& station = k.supplicant;
    if (k.message == EapolMessage::None || k.message == EapolMessage::Group) return;
    counted(at);
    messages_.add(at, limits_.harvest_window_ms);

    if (k.message == EapolMessage::M1) {
        // (14) all-zero ANonce, or (G16J) a PMKID that is a template value, not a keyed hash.
        if (k.nonce_zero || k.pmkid_synthetic) {
            const Millis w = limits_.fake_m1_window_ms;
            Millis unused = 0;
            BssidCounter* c = find(fake_, [&](const BssidCounter& e) { return e.bssid == ap; });
            if (!c) { c = &take(fake_, w, unused); c->bssid = ap; }
            c->last = std::max(c->last, at);
            c->a.add(at, w);
            const std::uint32_t n = c->a.sum(at, w);
            if (n >= limits_.fake_m1) {
                const auto scope = scope_.has_selection() && in_network(ap) ? IncidentScope::Network : IncidentScope::Area;
                auto o = make(meta.acquired, Pattern::FakeM1, scope, n, w, limits_.fake_m1, ap);
                if (k.pmkid_synthetic) o.shapes = shape::SyntheticPmkid;
                o.distinct_sources = 1; o.sources_random = local_mac(ap);
                emit(o, scope == IncidentScope::Network ? ap : Mac{}, limits_.cooldown_ms, out);
            }
        }
        // (13) a pending start; a retransmission (same replay counter) keeps its first time.
        Start* s = find(starts_, [&](const Start& e) { return e.ap == ap && e.station == station; });
        if (s && (s->replay != k.replay_counter || !inside(s->at, at, limits_.harvest_window_ms))) s->used = false, s = nullptr;
        if (!s) {
            s = &take(starts_, limits_.harvest_window_ms, saturated_until_);
            s->ap = ap; s->station = station; s->at = at; s->replay = k.replay_counter;
        }
        s->last = std::max(s->last, at);
        s->pmkid = s->pmkid || k.pmkid_present;
        // G16J: shapes of this start (a replay counter in 0xF000..0xFFFE, a template PMKID).
        if (k.replay_counter >= 0xf000u && k.replay_counter <= 0xfffeu) s->shapes |= shape::ReplayCounterRange;
        if (k.pmkid_synthetic) s->shapes |= shape::SyntheticPmkid;
    } else if (k.message == EapolMessage::M2) {
        for (auto& s : starts_) if (s.used && s.ap == ap && s.station == station && at >= s.at) s.answered = true;
    }

    // (15) an exchange after a disconnect burst on that AP for this station (or broadcast).
    const std::uint8_t bit = message_bit(k.message);
    for (const auto& b : bursts_) {
        if (!b.used || !(b.ap == ap) || !(b.station == station || b.station == kBroadcastMac)) continue;
        const Millis reach = b.shapes ? std::max(limits_.bait_ms, limits_.reconnect_ms) : limits_.reconnect_ms;   // G16J
        if (at < b.first || at > b.last + reach) continue;
        Exchange* e = find(exchanges_, [&](const Exchange& x) { return x.ap == ap && x.station == station; });
        if (e && e->burst_first != b.first) e->used = false, e = nullptr;   // an older burst's exchange: start over
        if (!e) {
            Millis unused = 0;
            e = &take(exchanges_, limits_.reconnect_ms, unused);
            e->ap = ap; e->station = station; e->burst_first = b.first;
        }
        e->last = std::max(e->last, at);
        e->messages = static_cast<std::uint8_t>(e->messages | bit);
        e->burst_count = b.count;
        const std::uint32_t seen = bits(e->messages);
        if (seen >= limits_.reconnect_messages) {
            auto o = make(meta.acquired, Pattern::DeauthHandshake, IncidentScope::Network, b.count, limits_.reconnect_burst_window_ms,
                          b.shapes ? halved(limits_.reconnect_burst) : limits_.reconnect_burst, ap);
            if (b.shapes) o.shapes = static_cast<std::uint16_t>(b.shapes | shape::HandshakeAfterForgery);
            o.corroborating = seen;
            o.distinct_sources = 1; o.sources_random = local_mac(station);
            emit(o, ap, limits_.cooldown_ms, out);
        }
        break;
    }
}

void HandshakeDetector::settle(const Instant& now, ObservationSink& out) {
    const Millis at = now.at, w = limits_.harvest_window_ms, settle = limits_.harvest_settle_ms;
    // O(N) pass: settled, unanswered starts inside the window. Most calls stop here.
    std::array<std::uint8_t, start_capacity> c{};
    std::size_t n = 0;
    for (std::size_t i = 0; i < starts_.size(); ++i) {
        const Start& s = starts_[i];
        if (s.used && !s.answered && s.at + settle <= at && inside(s.at, at, w)) c[n++] = static_cast<std::uint8_t>(i);
    }
    // G16J: starts showing a tool shape report at half the AP count, never below two.
    const std::uint32_t shaped_need = std::max<std::uint32_t>(2, halved(limits_.harvest_bssids));
    if (n < std::min(shaped_need, limits_.harvest_bssids)) return;
    // Group by station (bounded: n <= start_capacity; the table holds one start per AP+station).
    std::array<bool, start_capacity> done{};
    for (std::size_t i = 0; i < n; ++i) {
        if (done[i]) continue;
        const Mac station = starts_[c[i]].station;
        std::uint32_t aps = 0, pmkid = 0;
        std::uint16_t shapes = 0;
        bool network = false;
        for (std::size_t j = i; j < n; ++j) {
            const Start& s = starts_[c[j]];
            if (!(s.station == station)) continue;
            done[j] = true;
            ++aps;
            pmkid += s.pmkid;
            shapes = static_cast<std::uint16_t>(shapes | s.shapes);
            network = network || (scope_.has_selection() && in_network(s.ap));
        }
        const std::uint32_t need = shapes ? std::min(shaped_need, limits_.harvest_bssids) : limits_.harvest_bssids;
        if (aps < need) continue;
        const auto scope = network ? IncidentScope::Network : IncidentScope::Area;
        auto o = make(now, Pattern::PmkidHarvest, scope, aps, w, need, network ? scope_.selected().network.bssid : Mac{});
        o.shapes = shapes;
        o.corroborating = pmkid;
        o.distinct_sources = 1;
        o.sources_random = local_mac(station);
        o.saturated = at < saturated_until_;
        emit(o, scope == IncidentScope::Network ? station : Mac{}, limits_.cooldown_ms, out);
    }
}

// ---- (16) noise floor (G16J; replaces the G16G frame-loss rule) -------------------------------
NoiseFloorDetector::NoiseFloorDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("noise_floor", DetectorFamily::Jamming, scope, limits) { init(limits); }

bool NoiseFloorDetector::valid(const ThreatLimits& l) const {
    return l.noise_rise_db > 0 && l.noise_rise_db <= 60 && l.noise_hold_ms >= kMinWindowMs && l.noise_average_ms > l.noise_hold_ms
        && l.noise_min_frames > 0 && l.noise_baseline_samples > 0 && l.noise_baseline_samples <= history;
}

void NoiseFloorDetector::clear_state() {
    raised_.clear();
    channels_.fill(Channel{});
    samples_ = 0;
}

void NoiseFloorDetector::sample(const ChannelLoadSample& s, ObservationSink& out) {
    if (s.listened_ms == 0 || s.channel == 0 || s.channel >= channel_capacity) return;
    if (!admit_input(s.origin, s.sampled_at)) return;
    ++samples_;
    if (s.noise_count < limits_.noise_min_frames) return;   // no usable reading in this interval
    const Millis at = s.sampled_at.at;
    auto& ch = channels_[s.channel];
    // This interval's average reading, rounded to the nearest dB.
    const std::int64_t count = s.noise_count, twice = 2 * std::int64_t{s.noise_sum};
    const std::int64_t now_dbm = (twice >= 0 ? twice + count : twice - count) / (2 * count);
    // The channel's own average: usable, not-raised intervals of the noise_average_ms before `ref`.
    // While a rise lasts, ref stays where the rise began (the average is frozen); a rise older than
    // ten averages is accepted as the channel's new normal.
    bool rising = ch.raised && at >= ch.last_raised && at - ch.last_raised <= limits_.noise_hold_ms;
    if (rising && at - ch.raised_since > 10 * limits_.noise_average_ms) { rising = false; ch.raised = false; ch.size = ch.next = 0; }
    const Millis ref = rising ? ch.raised_since : at;
    std::int64_t sum = 0, n = 0;
    for (std::size_t i = 0; i < ch.size; ++i)
        if (ch.at[i] <= ref && inside(ch.at[i], ref, limits_.noise_average_ms)) { sum += ch.dbm[i]; ++n; }
    const bool judged = n >= static_cast<std::int64_t>(limits_.noise_baseline_samples);
    const std::int64_t rise_n = now_dbm * n - sum;   // (now - average) * n
    if (!judged || rise_n < static_cast<std::int64_t>(limits_.noise_rise_db) * n) {
        // Ordinary: it joins the average, and any rise in progress is over.
        ch.raised = false; ch.errors = ch.frames = 0;
        ch.dbm[ch.next] = static_cast<std::int8_t>(std::max<std::int64_t>(-128, std::min<std::int64_t>(127, now_dbm)));
        ch.at[ch.next] = at;
        ch.next = (ch.next + 1) % history;
        ch.size = std::min(ch.size + 1, history);
        return;
    }
    // Raised: never added to the average (a long rise must not become the new normal).
    if (!ch.raised || at < ch.last_raised || at - ch.last_raised > limits_.noise_hold_ms) {
        ch.raised = true; ch.raised_since = at; ch.errors = ch.frames = 0;
    }
    ch.last_raised = at;
    const std::uint64_t all = std::uint64_t{s.valid_frames} + s.error_frames;
    ch.errors = static_cast<std::uint32_t>(std::min<std::uint64_t>(std::uint64_t{ch.errors} + s.error_frames, std::numeric_limits<std::uint32_t>::max()));
    ch.frames = static_cast<std::uint32_t>(std::min<std::uint64_t>(std::uint64_t{ch.frames} + all, std::numeric_limits<std::uint32_t>::max()));
    counted(at);
    raised_.add(at, limits_.noise_hold_ms);
    if (at - ch.raised_since < limits_.noise_hold_ms) return;
    auto o = make(s.sampled_at, Pattern::NoiseFloor, IncidentScope::Area, static_cast<std::uint32_t>((rise_n + n / 2) / n), limits_.noise_hold_ms,
                  limits_.noise_rise_db, Mac{});
    o.raw_frames = ch.frames;      // every frame received in the held intervals ...
    o.corroborating = ch.errors;   // ... and how many of them the radio flagged (evidence text, never the rule)
    o.channel = s.channel;
    o.coverage_known = true;
    o.listened_ms = s.listened_ms;
    o.coverage_window_ms = s.window_ms;
    Mac key{}; key[5] = s.channel;   // one observation per channel per cooldown
    emit(o, key, limits_.cooldown_ms, out);
}

} // namespace guardian

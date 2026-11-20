// G16J tool-shape helpers. Contract: guardian/shapes.hpp; behaviour checks:
// tests/coverage_check.cpp (written and run RED first against a stub of this file).
//
// Independent implementation of behaviour described for AntiHunter upstream
// (2026-11-17, AGPL-3.0-only): behaviour and constants as hypotheses, no code.
// Standard C++ only; no allocation; no pointer kept into a frame; no clock read.
#include "guardian/shapes.hpp"
#include "guardian/oui_table.hpp"

#include <algorithm>
#include <limits>

namespace guardian {

namespace {
constexpr Mac kTemplateAddress{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
void bump(std::uint32_t& n) { if (n < std::numeric_limits<std::uint32_t>::max()) ++n; }
} // namespace

void SlotCount::add(Millis at, Millis window, std::uint32_t k) {
    const Millis width = window / slots;
    if (width == 0) return;
    const auto s = static_cast<std::uint32_t>(at / width + 1);
    const std::size_t i = static_cast<std::size_t>(s % slots);
    if (id[i] != s) {
        if (id[i] > s) return;   // older than this slot's current tenant: already outside the window
        id[i] = s;
        n[i] = 0;
    }
    n[i] = n[i] > std::numeric_limits<std::uint32_t>::max() - k ? std::numeric_limits<std::uint32_t>::max() : n[i] + k;
}

std::uint32_t SlotCount::sum(Millis at, Millis window) const {
    const Millis width = window / slots;
    if (width == 0) return 0;
    const auto s = static_cast<std::uint32_t>(at / width + 1);
    std::uint64_t total = 0;
    for (std::size_t i = 0; i < slots; ++i) if (id[i] != 0 && id[i] <= s && std::uint64_t{id[i]} + slots > s) total += n[i];
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(total, std::numeric_limits<std::uint32_t>::max()));
}

std::uint16_t disconnect_frame_shapes(const ParseResult& p) {
    if (!p.header_valid || (p.kind != FrameKind::Deauthentication && p.kind != FrameKind::Disassociation)) return 0;
    if (p.protected_frame || !p.reason_readable) return 0;   // an unreadable body shows nothing
    std::uint16_t bits = 0;
    if (p.reason_code == 2 && p.sequence == 0x0fff && p.fragment == 0) bits |= shape::DisconnectFixedSequence;   // sequence control 0xFFF0
    if (p.reason_code == 7 && p.duration == 0x013a) bits |= shape::DisconnectFixedDuration;
    return bits;
}

std::uint16_t DisconnectRuns::observe(const ParseResult& p, Millis at, std::uint32_t run, Millis window) {
    if (run == 0 || !p.header_valid || (p.kind != FrameKind::Deauthentication && p.kind != FrameKind::Disassociation)) return 0;
    const auto kind = static_cast<std::uint8_t>(p.kind);
    Run* r = nullptr;
    Run* oldest = nullptr;
    for (auto& e : runs_) {
        if (e.used && e.tx == p.addr2) { r = &e; break; }
        if (!oldest || !e.used || (oldest->used && e.last < oldest->last)) oldest = &e;
    }
    const bool fresh = !r || at < r->last || at - r->last > window;
    if (!r) r = oldest;
    if (fresh) {
        *r = Run{};
        r->used = true; r->tx = p.addr2; r->to = p.addr1; r->sequence = p.sequence; r->kind = kind; r->rising = 1; r->last = at;
        return 0;
    }
    r->last = at;
    // Rising: the same destination and exactly the next sequence number. A Retry copy (same number) changes nothing.
    if (!(r->to == p.addr1)) { r->to = p.addr1; r->rising = 1; }
    else if (p.sequence == static_cast<std::uint16_t>((r->sequence + 1u) & 0x0fffu)) bump(r->rising);
    else if (p.sequence != r->sequence) r->rising = 1;
    r->sequence = p.sequence;
    if (kind != r->kind) { bump(r->alternations); r->kind = kind; }
    std::uint16_t bits = 0;
    if (r->rising >= run) bits |= shape::RisingSequence;
    if (r->alternations >= run) bits |= shape::KindAlternation;
    return bits;
}

void ShapeWindow::add(std::uint16_t frame_bits, std::uint16_t run, Millis at, Millis window) {
    if (frame_bits) {
        if (frames.sum(at, window) == 0) bits = 0;   // the window had emptied: earlier shapes are history
        frames.add(at, window);
        bits = static_cast<std::uint16_t>(bits | frame_bits);
    }
    if (run) {
        if (run_at + window <= at) run_bits = 0;
        run_bits = static_cast<std::uint16_t>(run_bits | run);
        run_at = at;
    }
}

std::uint16_t ShapeWindow::current(Millis at, Millis window, std::uint32_t min_frames) const {
    std::uint16_t out = 0;
    if (min_frames > 0 && frames.sum(at, window) >= min_frames) out = bits;
    if (run_bits && run_at + window > at) out = static_cast<std::uint16_t>(out | run_bits);
    return out;
}

bool board_vendor(const Mac& m) {
    if (m[0] & 0x02u) return false;   // locally administered: no vendor
    const std::uint32_t prefix = (static_cast<std::uint32_t>(m[0]) << 16) | (static_cast<std::uint32_t>(m[1]) << 8) | m[2];
    return std::binary_search(std::begin(detail::board_vendor_prefixes), std::end(detail::board_vendor_prefixes), prefix);
}

bool template_address(const Mac& m) { return m == kTemplateAddress; }

// ---- G16S: burst forensics -------------------------------------------------------------------
// Rules: guardian/shapes.hpp (LastBurst, BurstRecord, BurstTrace). Checks: tests/coverage_check.cpp,
// cases g16s_* (written and run RED first against a stub of this section).
namespace {
// SlotCount needs a slot of at least 1 ms; a shorter window is counted as the shortest one.
Millis trace_window(Millis window) { return std::max<Millis>(window, SlotCount::slots); }
bool same_tuple(const BurstTuple& t, const Mac& receiver, const Mac& sender, const Mac& bssid, std::uint8_t channel) {
    return t.channel == channel && t.receiver == receiver && t.sender == sender && t.bssid == bssid;
}
std::uint32_t plus(std::uint32_t a, std::uint32_t b) {
    return a > std::numeric_limits<std::uint32_t>::max() - b ? std::numeric_limits<std::uint32_t>::max() : a + b;
}
} // namespace

void BurstRecord::begin(Millis at, Pattern rule) {
    clear();
    known_ = live_ = true;
    incident_at_ = newest_ = at;
    rule_ = rule;
}

void BurstRecord::unlisted(std::uint32_t frames, std::uint32_t own_frames) {
    if (!live_) return;
    total_ = plus(total_, frames);
    own_ = plus(own_, own_frames);
}

void BurstRecord::add(const Mac& receiver, const Mac& sender, const Mac& bssid, std::uint8_t channel, Millis at, std::uint32_t frames, bool own) {
    if (!live_ || frames == 0) return;
    total_ = plus(total_, frames);
    if (own) own_ = plus(own_, frames);
    if (at > newest_) newest_ = at;
    Entry* hit = nullptr;
    Entry* spare = nullptr;
    Entry* fewest = nullptr;       // among the tuples that do not name the picked network
    Entry* fewest_own = nullptr;   // G16T: among those that do
    for (auto& e : entries_) {
        if (e.tuple.count == 0) { if (!spare) spare = &e; continue; }
        if (same_tuple(e.tuple, receiver, sender, bssid, channel)) { hit = &e; break; }
        Entry*& least = e.tuple.own ? fewest_own : fewest;
        if (!least || e.tuple.count < least->tuple.count || (e.tuple.count == least->tuple.count && e.last < least->last)) least = &e;
    }
    if (!hit) {
        // Full: the tuple with the fewest frames makes room (equal: heard longest ago). Its frames
        // stay in the total and show as `unlisted`. G16T: a tuple naming the picked network makes
        // room only for another such tuple, and only when no other tuple is listed.
        hit = spare ? spare : fewest ? fewest : own ? fewest_own : nullptr;
        if (!hit) return;          // counted in the total, not listed
        *hit = Entry{};
        hit->tuple.receiver = receiver; hit->tuple.sender = sender; hit->tuple.bssid = bssid; hit->tuple.channel = channel;
    }
    if (own) hit->tuple.own = true;
    hit->tuple.count = plus(hit->tuple.count, frames);
    if (at > hit->last) hit->last = at;
}

bool BurstRecord::settle(Millis at, Millis window) {
    if (live_ && at >= newest_ && at - newest_ >= window) live_ = false;
    return !live_;
}

BurstTuple BurstRecord::top(bool own_only) const {
    const Entry* best = nullptr;
    for (const auto& e : entries_) {
        if (e.tuple.count == 0 || (own_only && !e.tuple.own)) continue;
        if (!best || e.tuple.count > best->tuple.count || (e.tuple.count == best->tuple.count && e.last > best->last)) best = &e;
    }
    return best ? best->tuple : BurstTuple{};
}

LastBurst BurstRecord::read(Millis now, Millis window) const {
    LastBurst b{};
    if (!known_) return b;
    b.known = true;
    b.open = live_ && (now < newest_ || now - newest_ < window);
    b.incident_at = incident_at_;
    b.rule = rule_;
    b.total = total_;
    b.own = own_;
    std::array<const Entry*, capacity> order{};
    std::size_t n = 0;
    for (const auto& e : entries_) if (e.tuple.count) order[n++] = &e;
    // Most frequent first; equal counts: heard most recently first (insertion sort, at most 8).
    for (std::size_t i = 1; i < n; ++i) {
        const Entry* moving = order[i];
        std::size_t k = i;
        while (k > 0 && (order[k - 1]->tuple.count < moving->tuple.count
                         || (order[k - 1]->tuple.count == moving->tuple.count && order[k - 1]->last < moving->last))) {
            order[k] = order[k - 1];
            --k;
        }
        order[k] = moving;
    }
    std::uint64_t listed = 0;
    for (std::size_t i = 0; i < n; ++i) { b.top[i] = order[i]->tuple; listed += order[i]->tuple.count; }
    b.tuples = static_cast<std::uint8_t>(n);
    b.unlisted = b.total > listed ? static_cast<std::uint32_t>(b.total - listed) : 0u;
    return b;
}

// ---- G16T: frames of a nearby burst that named the picked network -----------------------------
// Rules: guardian/shapes.hpp (BurstTrace, BurstRecord). Checks: tests/coverage_check.cpp, cases g16t_*.
bool BurstTrace::open(Millis at, Millis window) const { return record_.open(at, trace_window(window)); }

std::uint32_t BurstTrace::own(Millis at, Millis window) const {
    const Millis w = trace_window(window);
    return record_.open(at, w) ? record_.own() : own_.sum(at, w);   // the whole burst so far, else the window
}

BurstTuple BurstTrace::top_own(Millis at, Millis window) const {
    const Millis w = trace_window(window);
    if (record_.open(at, w)) return record_.top(true);
    const Entry* best = nullptr;
    std::uint32_t best_frames = 0;
    for (const auto& e : entries_) {
        if (!e.used || !e.tuple.own) continue;
        const std::uint32_t n = e.sliding.sum(at, w);
        if (n == 0) continue;
        if (!best || n > best_frames || (n == best_frames && e.last > best->last)) { best = &e; best_frames = n; }
    }
    if (!best) return {};
    BurstTuple t = best->tuple;
    t.count = best_frames;
    return t;
}

void BurstTrace::seen(const Mac& receiver, const Mac& sender, const Mac& bssid, std::uint8_t channel, Millis at, Millis window, bool own) {
    const Millis w = trace_window(window);
    if (record_.live() && !record_.settle(at, w)) {              // the burst goes on: its record counts the frame
        record_.add(receiver, sender, bssid, channel, at, 1, own);
        keep_own();
        return;
    }
    if (at > newest_) newest_ = at;
    total_.add(at, w);
    if (own) own_.add(at, w);
    Entry* hit = nullptr;
    Entry* spare = nullptr;
    Entry* fewest = nullptr;        // among the tuples that do not name the picked network
    Entry* fewest_own = nullptr;    // G16T: among those that do
    std::uint32_t fewest_frames = 0, fewest_own_frames = 0;
    for (auto& e : entries_) {
        const std::uint32_t n = e.used ? e.sliding.sum(newest_, w) : 0;
        if (e.used && n == 0) e = Entry{};                       // slid out of the window: free again
        if (!e.used) { if (!spare) spare = &e; continue; }
        if (same_tuple(e.tuple, receiver, sender, bssid, channel)) { hit = &e; break; }
        Entry*& least = e.tuple.own ? fewest_own : fewest;
        std::uint32_t& least_frames = e.tuple.own ? fewest_own_frames : fewest_frames;
        if (!least || n < least_frames || (n == least_frames && e.last < least->last)) { least = &e; least_frames = n; }
    }
    if (!hit) {
        hit = spare ? spare : fewest ? fewest : own ? fewest_own : nullptr;   // full: the BurstRecord replacement rule
        if (!hit) return;                                        // counted in the window's total, not listed
        *hit = Entry{};
        hit->used = true;
        hit->tuple.receiver = receiver; hit->tuple.sender = sender; hit->tuple.bssid = bssid; hit->tuple.channel = channel;
    }
    if (own) hit->tuple.own = true;
    hit->sliding.add(at, w);
    if (at > hit->last) hit->last = at;
}

void BurstTrace::incident(Millis at, Millis window, Pattern rule) {
    const Millis w = trace_window(window);
    if (record_.live() && !record_.settle(at, w)) return;        // the same burst reached a threshold again: one record
    record_.begin(at, rule);
    std::uint64_t listed = 0, listed_own = 0;
    for (const auto& e : entries_) {
        if (!e.used) continue;
        const std::uint32_t n = e.sliding.sum(newest_, w);
        record_.add(e.tuple.receiver, e.tuple.sender, e.tuple.bssid, e.tuple.channel, e.last, n, e.tuple.own);
        listed += n;
        if (e.tuple.own) listed_own += n;
    }
    const std::uint32_t all = total_.sum(newest_, w), own_all = own_.sum(newest_, w);
    if (all > listed)                                            // tuples replaced before the threshold
        record_.unlisted(static_cast<std::uint32_t>(all - listed), own_all > listed_own ? static_cast<std::uint32_t>(own_all - listed_own) : 0u);
    entries_.fill(Entry{});                                      // the next window counts from zero
    total_.clear();
    own_.clear();
    keep_own();
}

BurstTuple BurstTrace::top(Millis at, Millis window) const {
    if (record_.live()) return record_.top();
    const Millis w = trace_window(window);
    const Entry* best = nullptr;
    std::uint32_t best_frames = 0;
    for (const auto& e : entries_) {
        if (!e.used) continue;
        const std::uint32_t n = e.sliding.sum(at, w);
        if (n == 0) continue;
        if (!best || n > best_frames || (n == best_frames && e.last > best->last)) { best = &e; best_frames = n; }
    }
    if (!best) return {};
    BurstTuple t = best->tuple;
    t.count = best_frames;
    return t;
}

LastBurst BurstTrace::last(Millis now, Millis window) const { return record_.read(now, trace_window(window)); }
LastBurst BurstTrace::last_own(Millis now, Millis window) const { return own_record_.read(now, trace_window(window)); }

} // namespace guardian

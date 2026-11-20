// G16E detection platform: the bounded detector registry and the air meter.
// Independent implementation (no third-party code). Nothing here allocates,
// keeps a pointer into a frame, or reads a clock: time comes from the frame's
// acquisition Instant or the caller's `now`.
#include "guardian/air.hpp"
#include "guardian/registry.hpp"

#include <algorithm>

namespace guardian {

// ---- registry --------------------------------------------------------------------------
bool DetectorRegistry::add(FrameDetector& detector) {
    for (std::size_t i = 0; i < size_; ++i) if (items_[i] == &detector) { ++refused_; return false; }
    if (size_ >= items_.size()) { ++refused_; return false; }
    items_[size_++] = &detector;
    return true;
}
void DetectorRegistry::on_frame(const FrameSpan& frame, const RxMeta& meta, const ParseResult& parsed, ObservationSink& out) {
    for (std::size_t i = 0; i < size_; ++i) items_[i]->on_frame(frame, meta, parsed, out);
}
void DetectorRegistry::on_tick(Instant now, ObservationSink& out) {
    for (std::size_t i = 0; i < size_; ++i) items_[i]->on_tick(now, out);
}
void DetectorRegistry::coverage(const CoverageReport& report) {
    for (std::size_t i = 0; i < size_; ++i) items_[i]->coverage(report);
}
void DetectorRegistry::reset() {
    for (std::size_t i = 0; i < size_; ++i) items_[i]->reset();
}
std::size_t DetectorRegistry::reports(Instant now, DetectorReport* out, std::size_t capacity) const {
    if (!out) return 0;
    const std::size_t n = std::min(size_, capacity);
    for (std::size_t i = 0; i < n; ++i) out[i] = items_[i]->report(now);
    return n;
}

// ---- air meter -------------------------------------------------------------------------
void AirMeter::reset() {
    epoch_set_ = false; epoch_ = TimeEpoch{}; first_ = 0;
    buckets_.fill(Bucket{}); seen_.fill(Seen{});
    saturated_ = false; saturated_second_ = 0;
}

void AirMeter::on_frame(const ParseResult& p, const RxMeta& meta) {
    if (meta.status != RxStatus::Ok || !p.header_valid || !meta.acquired.valid()) return;
    if (p.kind == FrameKind::Control || p.kind == FrameKind::Unknown) return;
    if (!epoch_set_) { epoch_set_ = true; epoch_ = meta.acquired.epoch; first_ = meta.acquired.at; }
    if (meta.acquired.epoch != epoch_) return;  // another timebase: not this minute
    if (meta.acquired.at < first_) first_ = meta.acquired.at;
    const std::uint64_t second = meta.acquired.at / 1000;
    auto& b = buckets_[static_cast<std::size_t>(second % seconds)];
    if (!b.used || b.second != second) {
        if (b.used && b.second > second) return;  // a frame older than this slot's minute: already outside the window
        b = Bucket{}; b.second = second; b.used = true;
    }
    if (p.kind == FrameKind::ProbeRequest) ++b.probes;
    else if (p.kind == FrameKind::Beacon) ++b.beacons;
    // Distinct transmitters: refresh a known address, else take a free or expired slot.
    Seen* free_slot = nullptr;
    for (auto& s : seen_) {
        if (s.used && s.mac == p.addr2) { s.second = std::max(s.second, second); return; }
        if (!free_slot && (!s.used || s.second + seconds <= second)) free_slot = &s;
    }
    if (free_slot) { free_slot->mac = p.addr2; free_slot->second = second; free_slot->used = true; return; }
    saturated_ = true; saturated_second_ = std::max(saturated_second_, second);  // the count is now a lower bound
}

AirRates AirMeter::rates(Instant now) const {
    AirRates r{};
    if (!epoch_set_ || !now.valid() || now.epoch != epoch_ || now.at < first_) return r;
    r.known = true;
    r.window_ms = std::min<Millis>(window_ms, now.at - first_);
    const std::uint64_t second = now.at / 1000;
    const auto inside = [&](std::uint64_t s) { return s <= second && s + seconds > second; };
    for (const auto& b : buckets_) if (b.used && inside(b.second)) { r.probes += b.probes; r.beacons += b.beacons; }
    for (const auto& s : seen_) if (s.used && inside(s.second)) ++r.transmitters;
    r.transmitters_saturated = saturated_ && inside(saturated_second_);
    return r;
}

} // namespace guardian

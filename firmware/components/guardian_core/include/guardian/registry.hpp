#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "guardian/detector.hpp"

// G16E: the bounded detector registry. A fixed array of borrowed detectors
// (no allocation, no ownership): the application registers each detector once
// at start; Monitor::receive drives every registered detector with the same
// parsed frame instead of naming them. Order is registration order.
namespace guardian {

class DetectorRegistry {
public:
    // G16G: 20. Monitor registers 16 (2 network + 14 pattern detectors); four
    // slots stay free for adapter-added detectors (the G16E contract).
    static constexpr std::size_t capacity = 20;
    // False (and counted in refused()) when full or already registered.
    // The detector must outlive the registry.
    bool add(FrameDetector& detector);
    std::size_t size() const { return size_; }
    FrameDetector* at(std::size_t index) const { return index < size_ ? items_[index] : nullptr; }
    std::uint32_t refused() const { return refused_; }

    void on_frame(const FrameSpan& frame, const RxMeta& meta, const ParseResult& parsed, ObservationSink& out);
    void on_tick(Instant now, ObservationSink& out);
    void coverage(const CoverageReport& report);
    void reset();
    // Writes up to `capacity` reports in registration order; returns how many.
    std::size_t reports(Instant now, DetectorReport* out, std::size_t capacity) const;

private:
    std::array<FrameDetector*, capacity> items_{};
    std::size_t size_{};
    std::uint32_t refused_{};
};

} // namespace guardian

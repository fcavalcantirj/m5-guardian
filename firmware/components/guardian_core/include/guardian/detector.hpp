#pragma once

#include <cstdint>

#include "guardian/core.hpp"
#include "guardian/parser.hpp"
#include "guardian/radio.hpp"

// Detector and coverage contracts.
//
// Detectors are pure consumers of (frame, metadata, parse result) and emit
// typed observations into an ObservationSink (Core implements it). They own
// bounded state sized by DetectorLimits and must not allocate after
// construction. An incident is "observed traffic matching a heuristic", never
// proof of an attacker (G06 semantics).
namespace guardian {

// Explicit bounds the adapter chooses from MemoryCapabilities. The detector
// rejects construction parameters it cannot honour instead of growing.
// Every number here is a tunable heuristic, not a calibrated signature
// (docs/research/reuse-decisions.md section 4; physical calibration is G13/L02).
// G22 (independent review, finding D1): how many Retry-bit copies of ONE counted header are
// still its retransmissions. One transmission is retried a handful of times (IEEE Std
// 802.11-2020, dot11ShortRetryLimit, default 7), so a counted disconnect frame absorbs at most
// this many identical Retry copies inside the dedupe gap; every further copy is counted again.
// Without the cap a transmitter that sets the Retry bit and keeps one sequence number sends any
// number of frames that count as one. A protocol fact, not a tunable threshold: the same value
// for the G06 burst, the nearby rules and the handshake rule.
constexpr std::uint8_t retry_copies_max = 7;

struct DetectorLimits {
    std::uint16_t max_tracked_sources{64}; // transmitter MACs kept for dedupe
    std::uint16_t max_approved_aps{8};     // owner-approved related BSSIDs
    std::uint32_t window_ms{10000};        // counting window (tunable heuristic)
    // Minimum spacing between incident reports. Kept below Core::incident_ms
    // (60 s) with a 15 s re-detection margin so a condition that is still being
    // observed never lapses from the screen (G14 board finding, 2026-11-15).
    std::uint32_t cooldown_ms{45000};
    std::uint32_t burst_threshold{20};     // observations per window before DisconnectBurst
    // G06 additions. A Retry-bit frame whose header (addresses, sequence,
    // fragment, subtype) equals one seen within dedupe_ms is counted as a
    // retransmission, not a new observation; outside that gap, or without the
    // bit, the same sequence number is a new observation (sequence numbers wrap
    // and can be spoofed). change_threshold is how many differing / unapproved
    // advertisements inside window_ms are needed before UnexpectedAp or
    // SettingsChanged is reported (one odd beacon is not a change).
    // max_window_events is the ring capacity the disconnect detector may use;
    // it must be >= burst_threshold and <= DisconnectDetector::capacity.
    std::uint32_t dedupe_ms{1000};
    std::uint32_t change_threshold{2};
    std::uint16_t max_window_events{128};
    // G16J: tool shapes (guardian/core.hpp namespace shape) on the selected /
    // approved AP's disconnect frames. shape_frames frames showing a per-frame
    // shape, or a run of shape_run frames (rising sequence to one destination,
    // deauthentication / disassociation alternation), halve burst_threshold
    // (rounded up) for that window. 0 disables the respective check.
    std::uint32_t shape_frames{3};
    std::uint32_t shape_run{6};
};

// G16E: what one detector saw, for STATUS, the G13 JSON and the threat radar.
// Facts about this device's input since the detector's last reset(); ages are
// relative to the `now` given to report() and are unknown (false) for another
// timebase. Never a verdict about an attacker.
struct DetectorReport {
    const char* name{""};              // stable short name ("disconnect", "baseline", ...)
    DetectorFamily family{DetectorFamily::Disconnect};
    IncidentScope scope{IncidentScope::Network};
    bool configured{};                 // limits accepted; false = counts nothing (visible, not silent)
    std::uint32_t frames_seen{};       // frames offered to the detector
    std::uint32_t events_total{};      // counted events (what the radar pulses on)
    std::uint32_t events_in_window{};  // counted events inside the window ending at `now`
    std::uint32_t window_ms{};
    std::uint32_t incidents{};         // reports emitted
    bool last_event_known{};
    Millis last_event_age_ms{};
    bool last_incident_known{};
    Millis last_incident_age_ms{};
    Millis cooldown_remaining_ms{};    // 0 = the next threshold crossing reports
};

class FrameDetector {
public:
    virtual ~FrameDetector() = default;
    // Called once per drained frame, after FrameParser. `frame` is valid for
    // this call only. Must be O(1) amortised and never block.
    virtual void on_frame(const FrameSpan& frame, const RxMeta& meta, const ParseResult& parsed,
                          ObservationSink& out) = 0;
    // Called by the application task on its own cadence so windows expire
    // without traffic. `now` is injected.
    // A foreign/unknown epoch cannot expire or renew the active epoch's state.
    virtual void on_tick(Instant now, ObservationSink& out) = 0;
    // Scope changes: new selected network / approved list. Clears counters.
    virtual void reset() = 0;
    // G16E: the adapter's listening report (default: ignored).
    virtual void coverage(const CoverageReport&) {}
    // G16E: counters for STATUS / JSON / radar (default: an unconfigured, unnamed report).
    virtual DetectorReport report(Instant) const { return DetectorReport{}; }
};

// CoverageReport (the adapter's epoch-tagged listening report) lives in
// guardian/radio.hpp since G05, where Core consumes it through
// Core::coverage(). CoverageSource is the pull form of the same record.
class CoverageSource {
public:
    virtual ~CoverageSource() = default;
    virtual CoverageReport coverage(Instant now) const = 0;
};

} // namespace guardian

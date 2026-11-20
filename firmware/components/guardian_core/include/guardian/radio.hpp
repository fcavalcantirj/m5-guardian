#pragma once

#include <cstddef>
#include <cstdint>

#include "guardian/capabilities.hpp"
#include "guardian/identity.hpp"
#include "guardian/time.hpp"

// Packet-acquisition contracts: raw receive metadata, bounded frame input and
// the pull interface an application task uses to drain frames.
//
// Byte identity of a frame (binding for every adapter and parser):
//   * FrameSpan::bytes points at the first byte of the IEEE 802.11 MAC header
//     (Frame Control). No radiotap, no driver header, no padding before it.
//   * The 4-byte FCS is NOT part of the span. The adapter strips it when the
//     driver reports lengths that include it (pinned ESP-IDF v5.4
//     esp_wifi_types_native.h documents sig_len as "length of packet
//     including Frame Check Sequence"). Establish the full FCS-free length
//     BEFORE applying a pool/caller capacity limit. Never subtract four from
//     a truncated copy. If the convention is unknown, drop/count that input;
//     it must not be delivered as a FrameSpan. G13 confirms the live convention.
//   * size is the number of bytes actually present and readable. It is never
//     the untrusted length reported by the radio. RxMeta::reported_length keeps
//     that value separately for truncation accounting.
//
// Ownership and lifetime:
//   * Frame storage belongs to the adapter's bounded pool. A FrameSpan is valid
//     only for the duration of the call that receives it (FrameDetector::on_frame,
//     FrameParser::parse). Nothing in the library keeps a pointer into it;
//     results copy what they keep into fixed-size value fields.
//   * Radio driver callbacks never enter the library. The adapter copies at
//     most RadioCapabilities::max_frame_bytes into its pool, stamps RxMeta,
//     enqueues, and counts drops. The application task drains the queue via
//     FrameSource and calls the library. OS queue types stay in the adapter.
namespace guardian {

// Receive status as the ADAPTER establishes it from the driver.
enum class RxStatus : std::uint8_t {
    Ok,          // driver reported no error (ESP-IDF rx_state == 0)
    FcsError,    // driver flagged a checksum failure; bytes are untrusted
    DriverError, // driver reported a non-public error code
    Unknown      // driver exposes no status (RadioCapabilities::rx_error_state != Supported)
};

enum class SecondaryChannel : std::uint8_t { None, Above, Below, Unknown };

// Per-frame metadata. All fields are the adapter's conversion of driver data
// to Guardian units. Validity flags are explicit; consumers must check them
// instead of trusting zero.
struct RxMeta {
    // Acquisition time stamped before queueing, in its source timebase.
    // Preserve across queueing and copying. Never substitute dequeue time.
    // An invalid Instant cannot renew security freshness or incident windows.
    Instant acquired{};
    // Optional diagnostic processing time on the same timebase; NOT evidence age.
    Instant processed{};
    // Radio-side timestamp in microseconds if RadioCapabilities::rx_timestamp
    // is Supported. On ESP-IDF this is rx_ctrl.timestamp, documented as
    // precise only without modem/light sleep; it is a 32-bit wrapping counter.
    std::uint32_t radio_timestamp_us{};
    bool radio_timestamp_valid{};

    Band band{Band::Ghz2_4};
    // IEEE channel number the radio was tuned to when it received the frame.
    // Never derived from the frame body; the DS Parameter Set IE is a separate
    // ParseResult field so a mismatch is observable. Pinned ESP-IDF stores this
    // in a 4-bit field (channel: 4), so an ESP32-S3 adapter can only report
    // 1..14; a dual-band adapter must widen it, which is why this is uint8_t.
    std::uint8_t channel{};
    SecondaryChannel secondary{SecondaryChannel::Unknown};

    std::int8_t rssi_dbm{};
    bool rssi_valid{};
    std::int8_t noise_floor_dbm{};
    bool noise_floor_valid{};

    RxStatus status{RxStatus::Unknown};
    // Length the driver reported for this frame (ESP-IDF sig_len, which
    // includes FCS). Used only to detect truncation; never used to read bytes.
    std::uint16_t reported_length{};
    Origin origin{Origin::LiveRadio};
};

// Bounded, read-only view of one frame. See byte identity above.
struct FrameSpan {
    const std::uint8_t* bytes{};
    std::uint16_t size{};
    // True when reported_length (minus FCS) exceeded the pool slot, so the
    // tail is missing. Parsers must not call a truncated frame malformed or
    // open; they report ParseStatus::Truncated.
    bool truncated{};
};

// Caller-owned storage a FrameSource fills. capacity must be at least
// RadioCapabilities::max_frame_bytes or every longer frame reads truncated.
struct FrameBuffer {
    std::uint8_t* data{};
    std::uint16_t capacity{};
};

// Counters the adapter maintains. Monotonic within a boot; the core's
// coverage logic compares deltas. Drops are facts about this device's
// listening, not about the air.
struct AcquisitionStats {
    TimeEpoch epoch{}; // counters/listening times belong to this source boot
    std::uint32_t received{};           // frames the driver handed to the adapter
    std::uint32_t delivered{};          // frames the application task drained
    std::uint32_t dropped_queue_full{}; // adapter had no free pool slot
    std::uint32_t dropped_filtered{};   // adapter discarded by type filter (e.g. data frames)
    std::uint32_t dropped_bad_input{};  // length/trailer convention cannot be established
    std::uint32_t truncated{};          // delivered with FrameSpan::truncated
    std::uint32_t rx_errors{};          // RxStatus != Ok
    Instant listening_since{};          // invalid if never started
};

// Listening coverage as the ADAPTER knows it, sampled at an epoch-tagged
// instant. This is the input the core needs to say "no fresh data" versus
// "coverage degraded" honestly. Moved here from detector.hpp in G05 so Core can
// consume it (core.hpp -> parser.hpp -> radio.hpp); CoverageSource stays in
// detector.hpp. Invalid, foreign-epoch or stale coverage is not fresh evidence
// and a coverage report never renews security evidence (G05 policy).
struct CoverageReport {
    Instant sampled_at{}; // invalid/foreign/stale coverage is not fresh evidence
    Band band{Band::Ghz2_4};
    std::uint8_t channel{};          // currently tuned channel, 0 if not listening
    bool hopping{};                  // true when dwell is shared across channels
    Millis window_ms{};              // reporting window
    Millis listened_ms{};            // time within window actually tuned to `channel`
    std::uint32_t dropped_in_window{}; // from AcquisitionStats deltas
    Support passive_receive{Support::Unknown}; // mirrors RadioCapabilities at this moment
};

// G16G: one channel's receive counts over one sampling interval (normally one
// second), as the ADAPTER counted them in its receive callback before any
// queue: every frame the driver handed over without an error, and every frame
// it flagged with a receive error (checksum failure when the adapter enabled
// checksum-failed delivery, fcs_supported). A fact about this device's
// reception; a low delivery ratio is never proof of a jammer, and carrier or
// noise jamming that stops the radio from detecting frames at all produces no
// errors here and is not detectable this way.
struct ChannelLoadSample {
    Instant sampled_at{};            // end of the interval (epoch-tagged)
    Origin origin{Origin::LiveRadio};
    Band band{Band::Ghz2_4};
    std::uint8_t channel{};
    Millis window_ms{};              // interval length
    Millis listened_ms{};            // time inside it the radio was tuned to `channel`
    std::uint32_t valid_frames{};    // frames received without an error (all types)
    std::uint32_t error_frames{};    // frames flagged with a receive error
    std::int32_t error_rssi_sum{};   // sum of their RSSI (dBm), for the average
    std::uint32_t error_rssi_count{};
    bool fcs_supported{};            // the adapter asked the driver for checksum-failed frames
    // G16J: the radio's noise-floor estimate (dBm) attached to the frames received in
    // the interval (valid and flagged alike): their sum and how many carried one.
    std::int32_t noise_sum{};
    std::uint32_t noise_count{};
};

// Pull interface the application task uses. Implementations: an ESP-IDF
// adapter draining a FreeRTOS queue; a replay source reading fixtures; a test
// double. No OS type appears here.
class FrameSource {
public:
    virtual ~FrameSource() = default;
    // Copies the next frame into `into` and fills `span`/`meta`. Returns false
    // when nothing is queued (non-blocking). Null/zero-capacity input also
    // returns false without consuming a frame. On true, span.bytes == into.data
    // and span.size <= into.capacity. A truncated copy remains FCS-free.
    virtual bool next(FrameBuffer into, FrameSpan& span, RxMeta& meta) = 0;
    virtual AcquisitionStats stats() const = 0;
    // Current tuning, so coverage can be attributed. channel 0 = not listening.
    virtual Band current_band() const = 0;
    virtual std::uint8_t current_channel() const = 0;
};

} // namespace guardian

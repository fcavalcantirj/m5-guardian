#pragma once

#include <array>
#include <cstdint>

// Time contracts for the portable defense library.
//
// The library never reads a clock. Adapters inject time as values or through
// the MonotonicClock interface. Two distinct notions exist and must not be
// mixed:
//
//   * Millis: milliseconds on the Guardian monotonic clock of the CURRENT boot
//     (TimeEpoch). Used for every evidence timestamp, age and window. Never
//     persisted across a reboot as if comparable.
//   * WallClock: optional civil time for display and persistence labels only.
//     It is never used to order or expire evidence, because a board without
//     NTP has none and a board with it can jump.
namespace guardian {

// Monotonic milliseconds since an arbitrary origin within one TimeEpoch.
// Shared by every adapter in the same boot. Wraps after ~584 million years.
using Millis = std::uint64_t;

// Identifies one monotonic timebase. Two Millis values are comparable only
// when their valid TimeEpoch is equal. source_id identifies the timebase
// owner, not an AP. The application assigns distinct nonzero 128-bit IDs to
// independent devices/import sessions. boot_id must change whenever that
// source's clock restarts. A counter reset requires a new source_id.
// Replay is a separate source and remains Imported even after time mapping.
struct TimeEpoch {
    std::array<std::uint8_t, 16> source_id{};
    std::uint64_t boot_id{};
    bool valid() const {
        for (auto byte : source_id) if (byte != 0) return true;
        return false;
    }
    bool operator==(const TimeEpoch& o) const {
        return source_id == o.source_id && boot_id == o.boot_id;
    }
    bool operator!=(const TimeEpoch& o) const { return !(*this == o); }
};

// A monotonic instant tagged with its epoch. Observations imported from a
// previous boot or another device carry a foreign epoch and are historical
// until the adapter re-observes them in the live epoch.
struct Instant {
    TimeEpoch epoch{};
    Millis at{};
    // false when acquisition time could not be established. Zero is a valid
    // time only when known and epoch.valid(); default construction is unknown.
    bool known{};
    bool valid() const { return known && epoch.valid(); }
};

// Injected clock. The single application task that owns Core reads it; radio
// callbacks may use an adapter-specific, bounded task-safe clock read to stamp
// acquisition before queueing. They never call Core. Implementations: esp_timer
// in the ESP-IDF adapter, a stepping fake in host tests and replay. The epoch
// is immutable while a capture session is active; restart flushes its queue.
class MonotonicClock {
public:
    virtual ~MonotonicClock() = default;
    virtual Millis now() const = 0;
    virtual TimeEpoch epoch() const = 0;
};

// Tri-state used across all capability and availability contracts.
// Unknown means "the adapter could not establish it"; it is never silently
// treated as Supported.
enum class Support : std::uint8_t { Unknown, Unsupported, Supported };

// Optional civil time. unix_ms is meaningful only when support == Supported.
// uncertainty_ms is the adapter's honest bound (e.g. SNTP poll age); 0 means
// "not estimated", not "exact".
struct WallClock {
    Support support{Support::Unknown};
    std::int64_t unix_ms{};
    std::uint32_t uncertainty_ms{};
};

} // namespace guardian

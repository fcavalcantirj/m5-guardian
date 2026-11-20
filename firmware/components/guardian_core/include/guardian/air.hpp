#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "guardian/identity.hpp"
#include "guardian/parser.hpp"
#include "guardian/radio.hpp"
#include "guardian/time.hpp"

// G16E: the air meter behind the threat radar's rates. Counts what this device
// received in the last minute: probe requests, beacons and distinct transmitter
// addresses (Address 2 of verified management frames). Spoofable bytes, never
// people or devices: a randomizing phone counts as many transmitters. Bounded:
// 60 one-second buckets and a fixed transmitter table; when the table is full of
// addresses still inside the minute, the count is a lower bound (saturated).
// Only RxStatus::Ok frames with a valid header count. The first counted frame
// binds the meter to its epoch; another epoch is ignored until reset().
namespace guardian {

struct AirRates {
    bool known{};                  // at least one counted frame in this epoch
    Millis window_ms{};            // time covered: since the first counted frame, at most window_ms
    std::uint32_t probes{};        // probe requests in the window
    std::uint32_t beacons{};       // beacons in the window
    std::uint32_t transmitters{};  // distinct Address 2 values in the window
    bool transmitters_saturated{}; // lower bound: the table was full
};

class AirMeter {
public:
    static constexpr Millis window_ms = 60000;
    static constexpr std::size_t seconds = 60;
    static constexpr std::size_t max_transmitters = 128;

    void on_frame(const ParseResult& parsed, const RxMeta& meta);
    // The 60 one-second buckets ending at now's second.
    AirRates rates(Instant now) const;
    void reset();

private:
    struct Bucket { std::uint64_t second{}; std::uint32_t probes{}, beacons{}; bool used{}; };
    struct Seen { Mac mac{}; std::uint64_t second{}; bool used{}; };
    bool epoch_set_{};
    TimeEpoch epoch_{};
    Millis first_{};
    std::array<Bucket, seconds> buckets_{};
    std::array<Seen, max_transmitters> seen_{};
    std::uint64_t saturated_second_{};
    bool saturated_{};
};

} // namespace guardian

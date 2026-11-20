#pragma once
#include <array>
#include <cstddef>
#include "tune.hpp"
#include "guardian/threats.hpp"

// Supervisor review (2026-11-17): every G16F/G16G threat limit is a live TUNE
// key "t.<field>" (ledger: "every threshold a TUNE parameter"). SDK-free and
// host-tested. Defaults are the ThreatLimits the firmware starts with; the
// detectors still refuse an inconsistent set (ThreatDetector::valid), in which
// case the caller keeps the previous limits.
namespace guardian::tune {

std::size_t threat_key_count();
const char* threat_key(std::size_t i);          // "t.<field>", i < threat_key_count()

struct ThreatKeys {
    std::array<int, 80> index{};                 // registry index per field (68 since G16H)
    std::size_t count{};
};

// Registers one key per field with `defaults` as the default value. All or
// nothing: false (and nothing added) when the registry lacks room or refuses one.
bool add_threat_limits(Registry&, const ThreatLimits& defaults, ThreatKeys&);
// The limits the registry currently holds; fields without a key come from `base`.
ThreatLimits threat_limits_from(const Registry&, const ThreatKeys&, const ThreatLimits& base);
bool threat_limits_equal(const ThreatLimits&, const ThreatLimits&);

} // namespace guardian::tune

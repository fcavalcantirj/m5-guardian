#pragma once

#include <array>
#include <cstdint>

// Identity and provenance value types shared by every layer.
//
// Byte identity: Network keeps the SSID exactly as received (up to the 32
// bytes IEEE 802.11 allows) plus its length. No trimming, no UTF-8 repair, no
// control-character substitution. Two networks are equal only when BSSID,
// length and every SSID byte match. A sanitized display string is never an
// identity (see docs/research/wifi-audit.md on sanitized SSIDs).
namespace guardian {

using Mac = std::array<std::uint8_t, 6>;

struct Network {
    Mac bssid{};
    std::array<std::uint8_t, 32> ssid{};
    std::uint8_t ssid_size{};
    bool operator==(const Network& other) const; // defined in core.cpp
};

// Where an observation came from. Core accepts only observations whose
// origin matches its own; demo/imported evidence never refreshes a live mood.
enum class Origin { LiveRadio, Imported, Demo };

} // namespace guardian

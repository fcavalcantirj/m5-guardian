#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "guardian/identity.hpp"
#include "guardian/time.hpp"

// G16H: Bluetooth LE advertising input for the pairing-popup observations.
//
// What this is: a value type for one received legacy advertising report and a
// bounded classifier that says whether its data is one of the vendor "pairing
// popup" messages (the adverts that make a nearby phone or PC offer to pair or
// set a device up). Facts about received bytes only: nothing here transmits,
// scans, connects, names a tool, or says who sent an advert. Addresses are
// spoofable bytes and are never an identity; nothing links one address to
// another, to a device or to a person.
//
// Formats (public vendor documentation and the Bluetooth assigned numbers;
// sources and the pinned reads are in docs/research/ble-popup-spam.md):
//   Apple       manufacturer data, company 0x004C, then type/length/value
//               records: type 0x07 = proximity pairing (value: status prefix,
//               two device-model bytes, ...), type 0x0F = nearby action
//               (value: flags, action code, ...).
//   Samsung     manufacturer data, company 0x0075, with one of the two fixed
//               "easy setup" prefixes (earbuds / watch) and its model bytes.
//   Microsoft   manufacturer data, company 0x0006, beacon 0x03 (Swift Pair),
//               sub-scenario 0x00..0x02, reserved byte, optional display name.
//   Google      service data for the 16-bit UUID 0xFE2C carrying exactly a
//               3-byte Fast Pair model ID (the discoverable form). The
//               account-data form (longer) is not a popup for strangers and
//               is not classified.
// A real device in pairing mode sends exactly these messages: one advert is
// never a finding. The rules that count them are BlePopupDetector's
// (guardian/threats.hpp).
namespace guardian {

// One advertising report as the ADAPTER received it during a passive scan.
// Trivially copyable (an adapter may queue it); no pointer.
struct BleAdvert {
    static constexpr std::size_t max_data = 31;   // legacy advertising data
    Instant acquired{};             // stamped by the adapter when the report arrived
    Origin origin{Origin::LiveRadio};
    Mac address{};                  // advertiser address, most significant byte first, as received
    bool address_random{};          // the report's address type was "random" (static, resolvable or not)
    std::int8_t rssi_dbm{};
    bool rssi_valid{};
    std::array<std::uint8_t, max_data> data{};   // advertising data (AD structures)
    std::uint8_t size{};            // bytes present in `data` (<= max_data)
    bool truncated{};               // the report carried more than max_data bytes (extended advertising)
};

enum class BlePopupFormat : std::uint8_t {
    None,                   // not one of the popup messages (or unreadable)
    AppleProximityPairing,
    AppleNearbyAction,
    SamsungEasySetup,
    MicrosoftSwiftPair,
    GoogleFastPair,
    Count
};

// What one advert announces. `variant` is the product or action inside the
// format (Apple device model / action code, Samsung model, a hash of the Swift
// Pair name, the Fast Pair model ID): two adverts are "the same message" when
// format and variant are equal.
struct BlePopup {
    BlePopupFormat format{BlePopupFormat::None};
    std::uint32_t variant{};
    // An AD structure's length ran past the data, or a recognised record was too
    // short to hold its fields: nothing is classified from such bytes.
    bool malformed{};
    bool popup() const { return format != BlePopupFormat::None; }
    // One 32-bit key per (format, variant) for bounded tables.
    std::uint32_t key() const { return (static_cast<std::uint32_t>(format) << 24) ^ (variant & 0x00ffffffu) ^ ((variant >> 24) * 0x9e3779u); }
};

// Bounded: reads at most `size` bytes, never past an AD structure, no
// allocation. The first popup message found wins. data may be null when size is 0.
BlePopup parse_ble_popup(const std::uint8_t* data, std::size_t size);
inline BlePopup parse_ble_popup(const BleAdvert& advert) {
    return parse_ble_popup(advert.data.data(), advert.size <= BleAdvert::max_data ? advert.size : BleAdvert::max_data);
}

} // namespace guardian

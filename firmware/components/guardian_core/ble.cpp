// G16H Bluetooth LE pairing-popup observations: the advert classifier of
// guardian/ble.hpp and BlePopupDetector (guardian/threats.hpp). Behaviour
// checks: tests/ble_check.cpp (written and run RED first against a stub).
//
// Independent implementation. The two rules follow the G16H ledger text (which
// gives AntiHunter c6ef921, AGPL-3.0-only, as the source of the idea and of the
// starting numbers); no AntiHunter code was read into or copied here, and none
// of the tools that send such adverts was copied either: the byte layouts are
// the vendors' own formats (docs/research/ble-popup-spam.md lists every source
// and what was read from it). Standard C++ only; no allocation; no clock read;
// nothing is transmitted, scanned or connected to; no address is kept beyond
// the bounded tables, printed, stored or linked to a device or a person.
#include "guardian/ble.hpp"
#include "guardian/threats.hpp"

#include <algorithm>
#include <limits>

namespace guardian {

namespace {

constexpr Millis kMinWindowMs = 100;   // SlotCount: slot = window / 5 >= 20 ms

// AD types (Bluetooth assigned numbers, Generic Access Profile).
constexpr std::uint8_t kServiceData16 = 0x16;
constexpr std::uint8_t kManufacturerData = 0xff;
// Company identifiers (Bluetooth assigned numbers), little-endian on air.
constexpr std::uint16_t kApple = 0x004c, kMicrosoft = 0x0006, kSamsung = 0x0075;
constexpr std::uint16_t kFastPairUuid = 0xfe2c;
// Apple record types inside the manufacturer data.
constexpr std::uint8_t kAppleProximityPairing = 0x07, kAppleNearbyAction = 0x0f;
constexpr std::uint8_t kSwiftPairBeacon = 0x03;
// Samsung "easy setup" prefixes that follow the company identifier.
constexpr std::uint8_t kSamsungWatch[] = {0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0xff, 0x00, 0x00, 0x43};
constexpr std::uint8_t kSamsungBuds[] = {0x42, 0x09, 0x81, 0x02, 0x14, 0x15, 0x03, 0x21, 0x01, 0x09};

bool starts_with(const std::uint8_t* p, std::size_t n, const std::uint8_t* prefix, std::size_t size) {
    return n >= size && std::equal(prefix, prefix + size, p);
}

std::uint32_t hash_bytes(const std::uint8_t* p, std::size_t n, std::uint32_t seed) {
    std::uint32_t h = 2166136261u ^ seed;   // FNV-1a, 32 bit
    for (std::size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 16777619u; }
    h ^= static_cast<std::uint32_t>(n) + 0x9e3779b9u;
    h *= 16777619u;
    return h;
}

// One manufacturer-data payload (after the AD type): company identifier, then the vendor's bytes.
// True when the structure settled the result (a popup message, or a recognised record cut short).
bool manufacturer(const std::uint8_t* p, std::size_t n, BlePopup& out) {
    if (n < 2) return false;
    const std::uint16_t company = static_cast<std::uint16_t>(p[0] | (p[1] << 8));
    p += 2; n -= 2;
    if (company == kApple) {
        // Records: type, length, value. The first proximity-pairing or nearby-action record wins.
        std::size_t i = 0;
        while (i + 2 <= n) {
            const std::uint8_t type = p[i];
            const std::size_t declared = p[i + 1], present = std::min(declared, n - i - 2);
            const std::uint8_t* v = p + i + 2;
            if (type == kAppleProximityPairing) {              // status prefix, two device-model bytes, ...
                if (present < 3) { out.malformed = true; return true; }
                out.format = BlePopupFormat::AppleProximityPairing;
                out.variant = static_cast<std::uint32_t>((v[1] << 8) | v[2]);
                return true;
            }
            if (type == kAppleNearbyAction) {                  // flags, action code, ...
                if (present < 2) { out.malformed = true; return true; }
                out.format = BlePopupFormat::AppleNearbyAction;
                out.variant = v[1];
                return true;
            }
            if (present < declared) return false;              // another record, cut: nothing of ours in it
            i += 2 + declared;
        }
        if (i < n && (p[i] == kAppleProximityPairing || p[i] == kAppleNearbyAction)) { out.malformed = true; return true; }   // a type with no length
        return false;
    }
    if (company == kMicrosoft) {
        if (n < 1 || p[0] != kSwiftPairBeacon) return false;  // other Microsoft beacons are not Swift Pair
        if (n < 3) { out.malformed = true; return true; }      // beacon, sub-scenario, reserved byte
        if (p[1] > 0x02) return false;                         // the three documented sub-scenarios
        out.format = BlePopupFormat::MicrosoftSwiftPair;
        out.variant = hash_bytes(p + 3, n - 3, p[1]);          // what follows (addresses, class, display name)
        return true;
    }
    if (company == kSamsung) {
        if (starts_with(p, n, kSamsungWatch, sizeof kSamsungWatch)) {
            if (n < sizeof kSamsungWatch + 1) { out.malformed = true; return true; }
            out.format = BlePopupFormat::SamsungEasySetup;
            out.variant = 0x01000000u | p[sizeof kSamsungWatch];
            return true;
        }
        if (starts_with(p, n, kSamsungBuds, sizeof kSamsungBuds)) {
            if (n < sizeof kSamsungBuds + 4) { out.malformed = true; return true; }   // model, model, a fixed byte, model
            const std::uint8_t* m = p + sizeof kSamsungBuds;
            out.format = BlePopupFormat::SamsungEasySetup;
            out.variant = 0x02000000u | static_cast<std::uint32_t>((m[0] << 16) | (m[1] << 8) | m[3]);
            return true;
        }
        return false;
    }
    return false;
}

} // namespace

BlePopup parse_ble_popup(const std::uint8_t* data, std::size_t size) {
    BlePopup out{};
    if (!data) return out;
    std::size_t i = 0;
    while (i < size) {
        const std::size_t length = data[i];                    // counts the type byte and the payload
        if (length == 0) break;                                // padding: the significant part is over
        if (i + 1 + length > size) { out.malformed = true; break; }   // the structure runs past the data
        const std::uint8_t type = data[i + 1];
        const std::uint8_t* payload = data + i + 2;
        const std::size_t n = length - 1;
        if (type == kManufacturerData) {
            if (manufacturer(payload, n, out)) break;
        } else if (type == kServiceData16 && n == 2 + 3 && (payload[0] | (payload[1] << 8)) == kFastPairUuid) {
            // Exactly a 3-byte model ID: the discoverable form. Account data is longer and is not a popup.
            out.format = BlePopupFormat::GoogleFastPair;
            out.variant = static_cast<std::uint32_t>((payload[2] << 16) | (payload[3] << 8) | payload[4]);
            break;
        }
        i += 1 + length;
    }
    if (out.popup()) out.malformed = false;                    // a complete message was read before any cut tail
    return out;
}

// ---- (17) pairing-popup messages ------------------------------------------------------------
BlePopupDetector::BlePopupDetector(const ApprovedScope& scope, const ThreatLimits& limits)
    : ThreatDetector("ble_popup", DetectorFamily::Bluetooth, scope, limits) { init(limits); }

bool BlePopupDetector::valid(const ThreatLimits& l) const {
    return l.ble_popup_window_ms >= kMinWindowMs && l.ble_popup_messages > 0 && l.ble_popup_messages <= address_capacity
        && l.ble_popup_sources > 0 && l.ble_popup_sources <= address_capacity
        && l.ble_address_memory_ms >= l.ble_popup_window_ms
        && l.ble_rotation_window_ms >= kMinWindowMs && l.ble_rotation_models >= 2 && l.ble_rotation_models <= model_capacity;
}

void BlePopupDetector::clear_state() {
    popups_.clear();
    addresses_.fill(Address{});
    models_.fill(Model{});
    saturated_until_ = models_saturated_until_ = started_ = last_heard_ = 0;
    started_set_ = false;
    popup_adverts_ = malformed_ = 0;
}

void BlePopupDetector::advert(const BleAdvert& advert, ObservationSink& out) {
    offered();
    if (!admit_input(advert.origin, advert.acquired)) return;
    const Millis at = advert.acquired.at;
    // Listening: any report proves the scan heard something. After a silence longer than the
    // address memory every address is new again, so the room is learned from the start.
    if (!started_set_ || (at > last_heard_ && at - last_heard_ > limits_.ble_address_memory_ms)) { started_ = at; started_set_ = true; }
    last_heard_ = std::max(last_heard_, at);
    const BlePopup popup = parse_ble_popup(advert);
    if (popup.malformed) { if (malformed_ < std::numeric_limits<std::uint32_t>::max()) ++malformed_; return; }
    if (!popup.popup()) return;
    if (popup_adverts_ < std::numeric_limits<std::uint32_t>::max()) ++popup_adverts_;
    counted(at);
    popups_.add(at, limits_.ble_popup_window_ms);
    flood(advert, popup, out);
    if (popup.format == BlePopupFormat::GoogleFastPair) rotation(advert, popup, out);
}

void BlePopupDetector::flood(const BleAdvert& advert, const BlePopup& popup, ObservationSink& out) {
    const Millis at = advert.acquired.at, w = limits_.ble_popup_window_ms, memory = limits_.ble_address_memory_ms;
    // The address: known (refresh), else a free or forgotten slot, else the one heard longest ago.
    Address* entry = nullptr;
    Address* spare = nullptr;
    for (auto& a : addresses_) {
        if (a.used && a.last + memory <= at) a = Address{};    // forgotten
        if (a.used && a.mac == advert.address) { entry = &a; break; }
        if (!a.used) { if (!spare || spare->used) spare = &a; }   // a free slot beats any used one
        else if (!spare || (spare->used && a.last < spare->last)) spare = &a;
    }
    if (!entry) {
        // Dropping an address that is still inside the window makes the counts a lower bound.
        if (spare->used && spare->last + w > at) saturated_until_ = std::max(saturated_until_, spare->last + w);
        *spare = Address{};
        spare->used = true; spare->mac = advert.address; spare->first = at;
        entry = spare;
    }
    entry->last = std::max(entry->last, at);
    entry->message = popup.key();
    entry->format = static_cast<std::uint8_t>(popup.format);
    entry->random = advert.address_random;
    if (at < started_ + limits_.ble_learn_ms) return;          // the room is still being learned

    // Short-lived addresses of this window, and the different messages they carry.
    std::uint32_t sources = 0, random = 0, messages = 0, formats = 0;
    std::uint32_t format_bits = 0;
    for (std::size_t i = 0; i < addresses_.size(); ++i) {
        const auto& a = addresses_[i];
        if (!a.used || a.last + w <= at || a.first + w <= at) continue;   // not heard in the window, or known before it
        ++sources; random += a.random;
        bool repeated = false;
        for (std::size_t k = 0; k < i && !repeated; ++k) {
            const auto& b = addresses_[k];
            repeated = b.used && b.last + w > at && b.first + w > at && b.message == a.message;
        }
        if (!repeated) ++messages;
        format_bits |= 1u << a.format;
    }
    for (; format_bits; format_bits &= format_bits - 1) ++formats;
    if (messages < limits_.ble_popup_messages || sources < limits_.ble_popup_sources) return;
    IncidentObservation o{};
    o.acquired = advert.acquired;
    o.pattern = Pattern::PairingPopupFlood;
    o.scope = IncidentScope::Area;
    o.count = messages;
    o.threshold = limits_.ble_popup_messages;
    o.window_ms = static_cast<std::uint32_t>(std::min<Millis>(w, std::numeric_limits<std::uint32_t>::max()));
    o.raw_frames = popups_.sum(at, w);
    o.distinct_sources = sources;
    o.sources_random = random * 2 > sources;
    o.corroborating = formats;
    o.saturated = at < saturated_until_;
    emit(o, Mac{}, limits_.cooldown_ms, out);
}

void BlePopupDetector::rotation(const BleAdvert& advert, const BlePopup& popup, ObservationSink& out) {
    const Millis at = advert.acquired.at, w = limits_.ble_rotation_window_ms;
    // The (address, model) pair: known (refresh), else a free slot, else the pair heard longest ago
    // under ANOTHER address (this address's own pairs are what the rule is counting), else its own oldest.
    Model* entry = nullptr;
    Model* spare = nullptr;
    Model* own = nullptr;
    for (auto& m : models_) {
        if (m.used && m.last + w <= at) m = Model{};           // outside the window
        if (m.used && m.mac == advert.address && m.model == popup.variant) { entry = &m; break; }
        if (!m.used) { if (!spare || spare->used) spare = &m; }
        else if (m.mac == advert.address) { if (!own || m.last < own->last) own = &m; }
        else if (!spare || (spare->used && m.last < spare->last)) spare = &m;
    }
    if (!entry) {
        if (!spare) spare = own;
        if (spare->used) models_saturated_until_ = std::max(models_saturated_until_, spare->last + w);   // still inside the window
        *spare = Model{};
        spare->used = true; spare->mac = advert.address; spare->model = popup.variant;
        entry = spare;
    }
    entry->last = std::max(entry->last, at);
    std::uint32_t models = 0;
    for (const auto& m : models_) if (m.used && m.mac == advert.address && m.last + w > at) ++models;
    if (models < limits_.ble_rotation_models) return;
    IncidentObservation o{};
    o.acquired = advert.acquired;
    o.pattern = Pattern::FastPairRotation;
    o.scope = IncidentScope::Area;
    o.count = models;
    o.threshold = limits_.ble_rotation_models;
    o.window_ms = static_cast<std::uint32_t>(std::min<Millis>(w, std::numeric_limits<std::uint32_t>::max()));
    o.raw_frames = models;
    o.distinct_sources = 1;
    o.sources_random = advert.address_random;
    o.saturated = at < models_saturated_until_;
    emit(o, Mac{}, limits_.cooldown_ms, out);
}

} // namespace guardian

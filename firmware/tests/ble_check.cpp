// G16H Bluetooth LE pairing-popup checks (TDD: written and run RED first against
// the stub of components/guardian_core/ble.cpp; logs in
// $GUARDIAN_STORE/builds/20261119-g16h-ble-tdd/red-*.log).
//
// Hand-built advertising data in the layouts read from the vendor documents and
// from the pinned source reads recorded in docs/research/ble-popup-spam.md goes
// through the real classifier into BlePopupDetector, and end to end through
// measurement::Monitor, Core and the presenter. Flood-shaped streams must give
// exactly one observation per cooldown; benign streams (earbuds that keep their
// address, phones, beacons, a device in pairing mode) must give none.
// Generated adverts are host input, never radio proof: no BLE scan ran.
#include "check.hpp"
#include "measurement.hpp"

#include "guardian/ble.hpp"
#include "guardian/presenter.hpp"
#include "guardian/threats.hpp"

#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <new>
#include <string>
#include <vector>

using namespace guardian;

// ---- allocation ban (same technique as threat_detectors_check) ----------------------------
namespace {
int g_ban_depth = 0;
std::size_t g_banned_allocations = 0;
struct AllocationBan {
    AllocationBan() { ++g_ban_depth; }
    ~AllocationBan() { --g_ban_depth; }
};
} // namespace
void* operator new(std::size_t n) {
    if (g_ban_depth > 0) ++g_banned_allocations;
    if (void* p = std::malloc(n ? n : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

namespace {

using Bytes = std::vector<std::uint8_t>;

TimeEpoch epoch(std::uint64_t boot = 1) { TimeEpoch e{}; e.source_id[0] = 7; e.boot_id = boot; return e; }
class Clock final : public MonotonicClock {
public:
    Millis at{1000};
    Millis now() const override { return at; }
    TimeEpoch epoch() const override { return ::epoch(); }
};
struct Sink final : ObservationSink {
    std::vector<IncidentObservation> got;
    void security(const SecurityObservation&) override {}
    void incident(const IncidentObservation& o) override { got.push_back(o); }
    std::size_t count(Pattern p) const { std::size_t n = 0; for (const auto& o : got) n += o.pattern == p; return n; }
    const IncidentObservation* first(Pattern p) const { for (const auto& o : got) if (o.pattern == p) return &o; return nullptr; }
    const IncidentObservation* last(Pattern p) const { const IncidentObservation* r = nullptr; for (const auto& o : got) if (o.pattern == p) r = &o; return r; }
};

// ---- advertising data, as transmitted (docs/research/ble-popup-spam.md) --------------------
Bytes flags() { return {0x02, 0x01, 0x06}; }
Bytes join(std::initializer_list<Bytes> parts) { Bytes out; for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end()); return out; }
// Apple proximity pairing, the 31-byte form: type 0x07, length 0x19, prefix, model, status, filler.
Bytes apple_pairing(std::uint16_t model, std::uint8_t prefix = 0x07) {
    Bytes b{0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, prefix, static_cast<std::uint8_t>(model >> 8), static_cast<std::uint8_t>(model), 0x55, 0x11, 0x22, 0x33, 0x00, 0x00};
    for (int i = 0; i < 16; ++i) b.push_back(static_cast<std::uint8_t>(0xa0 + i));
    return b;
}
// The shorter 21-byte form one tool sends: type 0x07 with length 0x0F.
Bytes apple_pairing_short(std::uint16_t model) {
    return {0x14, 0xff, 0x4c, 0x00, 0x07, 0x0f, 0x00, static_cast<std::uint8_t>(model >> 8), static_cast<std::uint8_t>(model),
            0xac, 0x90, 0x85, 0x75, 0x94, 0x65, 1, 2, 3, 4, 5, 0x00};
}
Bytes apple_action(std::uint8_t action) { return {0x0a, 0xff, 0x4c, 0x00, 0x0f, 0x05, 0xc0, action, 0x10, 0x20, 0x30}; }
Bytes samsung_watch(std::uint8_t model) { return {0x0e, 0xff, 0x75, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0xff, 0x00, 0x00, 0x43, model}; }
// Earbuds: 28 bytes plus the cut second structure (declared 0x10, two bytes present) that is on air.
Bytes samsung_buds(std::uint32_t model) {
    return {0x1b, 0xff, 0x75, 0x00, 0x42, 0x09, 0x81, 0x02, 0x14, 0x15, 0x03, 0x21, 0x01, 0x09,
            static_cast<std::uint8_t>(model >> 16), static_cast<std::uint8_t>(model >> 8), 0x01, static_cast<std::uint8_t>(model),
            0x06, 0x3c, 0x94, 0x8e, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x00, 0x10, 0xff, 0x75};
}
Bytes swift_pair(const char* name, std::uint8_t scenario = 0x00) {
    const std::size_t n = std::strlen(name);
    Bytes b{static_cast<std::uint8_t>(6 + n), 0xff, 0x06, 0x00, 0x03, scenario, 0x80};
    b.insert(b.end(), name, name + n);
    return b;
}
Bytes fast_pair(std::uint32_t model) {
    return {0x03, 0x03, 0x2c, 0xfe, 0x06, 0x16, 0x2c, 0xfe, static_cast<std::uint8_t>(model >> 16), static_cast<std::uint8_t>(model >> 8),
            static_cast<std::uint8_t>(model), 0x02, 0x0a, 0xec};
}
// Benign adverts that are NOT popup messages.
Bytes apple_nearby_info() { return join({flags(), {0x07, 0xff, 0x4c, 0x00, 0x10, 0x02, 0x0b, 0x00}}); }
Bytes apple_find_my() { Bytes b{0x1e, 0xff, 0x4c, 0x00, 0x12, 0x19}; b.resize(31, 0x5a); return b; }
Bytes ibeacon() { Bytes b{0x02, 0x01, 0x06, 0x1a, 0xff, 0x4c, 0x00, 0x02, 0x15}; b.resize(30, 0x77); return b; }
Bytes windows_device_beacon() { Bytes b{0x1e, 0xff, 0x06, 0x00, 0x01, 0x09, 0x20, 0x02}; b.resize(31, 0x33); return b; }
// Fast Pair account data (a paired device that is not in pairing mode): version byte, key filter, salt.
Bytes fast_pair_account() { return {0x02, 0x01, 0x06, 0x0c, 0x16, 0x2c, 0xfe, 0x00, 0x40, 0x11, 0x22, 0x33, 0x44, 0x21, 0xc7, 0xc8}; }
Bytes samsung_other() { return {0x0a, 0xff, 0x75, 0x00, 0x02, 0x18, 0x00, 0x11, 0x22, 0x33, 0x44}; }
Bytes name_only() { return {0x02, 0x01, 0x06, 0x05, 0x09, 'L', 'a', 'm', 'p'}; }

BlePopup parse(const Bytes& b) { return parse_ble_popup(b.data(), b.size()); }

Mac mac(std::uint32_t n, std::uint8_t top = 0xc0) {
    return {top, 0x11, static_cast<std::uint8_t>(n >> 24), static_cast<std::uint8_t>(n >> 16), static_cast<std::uint8_t>(n >> 8), static_cast<std::uint8_t>(n)};
}
BleAdvert advert(const Mac& address, const Bytes& data, Millis at, bool random = true) {
    BleAdvert a{};
    a.acquired = Instant{epoch(), at, true};
    a.address = address; a.address_random = random;
    a.rssi_dbm = -60; a.rssi_valid = true;
    a.size = static_cast<std::uint8_t>(data.size() < BleAdvert::max_data ? data.size() : BleAdvert::max_data);
    for (std::size_t i = 0; i < a.size; ++i) a.data[i] = data[i];
    a.truncated = data.size() > BleAdvert::max_data;
    return a;
}

// The messages a mixed flood rotates through (five formats, different products).
Bytes flood_message(std::uint32_t i) {
    switch (i % 6) {
    case 0: return apple_pairing(static_cast<std::uint16_t>(0x0220 + ((i / 6) % 20) * 0x100));
    case 1: return join({flags(), apple_action(static_cast<std::uint8_t>(0x01 + (i / 6) % 15))});
    case 2: return samsung_watch(static_cast<std::uint8_t>(0x01 + (i / 6) % 17));
    case 3: return samsung_buds(0xee7a0c + ((i / 6) % 30) * 0x010000);
    case 4: { char name[12]; std::snprintf(name, sizeof name, "Device %u", static_cast<unsigned>((i / 6) % 50)); return swift_pair(name); }
    default: return fast_pair(0x00b727 + (i / 6) % 80);
    }
}

struct Rig {
    ApprovedScope scope;
    Sink sink;
    BlePopupDetector d;
    std::uint32_t next_address{1};
    explicit Rig(const ThreatLimits& limits = {}) : d(scope, limits) {}
    void feed(const Mac& address, const Bytes& data, Millis at, bool random = true) { d.advert(advert(address, data, at, random), sink); }
    // A quiet room for `ms`: a lamp's name advert and a phone, each under one address.
    void quiet(Millis from, Millis ms) {
        for (Millis t = from; t < from + ms; t += 250) { feed(mac(0xaa01, 0x00), name_only(), t, false); feed(mac(0xaa02), apple_nearby_info(), t + 100); }
    }
    // A flood: every `step` ms one popup message under an address never used before.
    void flood(Millis from, Millis ms, Millis step = 10) {
        std::uint32_t i = 0;
        for (Millis t = from; t < from + ms; t += step, ++i) feed(mac(0x100000 + next_address++), flood_message(i), t);
    }
};

constexpr Millis kLearned = 31000;   // past ThreatLimits{}.ble_learn_ms when listening began at 1000

} // namespace

// =========================================================================================
// Classifier
// =========================================================================================
GUARDIAN_CASE(popup_messages_are_classified_with_their_product) {
    auto p = parse(apple_pairing(0x0e20));
    CHECK_EQ(p.format, BlePopupFormat::AppleProximityPairing); CHECK_EQ(p.variant, 0x0e20u); CHECK(!p.malformed); CHECK(p.popup());
    CHECK_EQ(parse(apple_pairing(0x0e20, 0x01)).variant, 0x0e20u);            // the status prefix is not the product
    p = parse(apple_pairing_short(0x1420));                                   // length 0x0F form
    CHECK_EQ(p.format, BlePopupFormat::AppleProximityPairing); CHECK_EQ(p.variant, 0x1420u);
    p = parse(join({flags(), apple_action(0x13)}));                           // after a Flags structure
    CHECK_EQ(p.format, BlePopupFormat::AppleNearbyAction); CHECK_EQ(p.variant, 0x13u);
    p = parse(samsung_watch(0x1a));
    CHECK_EQ(p.format, BlePopupFormat::SamsungEasySetup);
    const auto watch = p;
    p = parse(samsung_buds(0xee7a0c));                                        // the cut second structure does not spoil the first
    CHECK_EQ(p.format, BlePopupFormat::SamsungEasySetup); CHECK(!p.malformed);
    CHECK(p.key() != watch.key());
    CHECK(parse(samsung_buds(0xee7a0c)).key() != parse(samsung_buds(0x9d1700)).key());
    CHECK(parse(samsung_watch(0x1a)).key() != parse(samsung_watch(0x1b)).key());
    p = parse(swift_pair("Mouse"));
    CHECK_EQ(p.format, BlePopupFormat::MicrosoftSwiftPair);
    CHECK(parse(swift_pair("Mouse")).key() == p.key());
    CHECK(parse(swift_pair("Mousf")).key() != p.key());
    CHECK_EQ(parse(swift_pair("")).format, BlePopupFormat::MicrosoftSwiftPair);   // the name is optional
    CHECK_EQ(parse(swift_pair("Pad", 0x02)).format, BlePopupFormat::MicrosoftSwiftPair);
    p = parse(fast_pair(0x00b727));
    CHECK_EQ(p.format, BlePopupFormat::GoogleFastPair); CHECK_EQ(p.variant, 0x00b727u);
    // An Apple record chain: a nearby-info record first, the action record after it.
    p = parse({0x0e, 0xff, 0x4c, 0x00, 0x10, 0x02, 0x0b, 0x00, 0x0f, 0x05, 0xc0, 0x20, 1, 2, 3});
    CHECK_EQ(p.format, BlePopupFormat::AppleNearbyAction); CHECK_EQ(p.variant, 0x20u);
    // Same format, another product: another message. Another format with the same number: another message.
    CHECK(parse(apple_pairing(0x0e20)).key() != parse(apple_pairing(0x0220)).key());
    CHECK(parse(apple_action(0x13)).key() != parse(samsung_watch(0x13)).key());
    // The BleAdvert overload reads the same bytes.
    CHECK(parse_ble_popup(advert(mac(1), fast_pair(0x123456), 1000)).key() == parse(fast_pair(0x123456)).key());
}

GUARDIAN_CASE(ordinary_adverts_are_not_popup_messages) {
    for (const Bytes& b : {apple_nearby_info(), apple_find_my(), ibeacon(), windows_device_beacon(), fast_pair_account(), samsung_other(),
                           name_only(), flags(), Bytes{}}) {
        const auto p = parse(b);
        CHECK_EQ(p.format, BlePopupFormat::None);
        CHECK(!p.popup());
        CHECK(!p.malformed);
    }
    // A Fast Pair service-data structure that is not exactly a 3-byte model ID is not a popup.
    CHECK_EQ(parse({0x05, 0x16, 0x2c, 0xfe, 0x12, 0x34}).format, BlePopupFormat::None);
    CHECK_EQ(parse({0x07, 0x16, 0x2c, 0xfe, 0x12, 0x34, 0x56, 0x78}).format, BlePopupFormat::None);
    // Service data of another UUID with three bytes is not Fast Pair.
    CHECK_EQ(parse({0x06, 0x16, 0x2d, 0xfe, 0x12, 0x34, 0x56}).format, BlePopupFormat::None);
    // Zero padding ends the data.
    CHECK(!parse({0x02, 0x01, 0x06, 0x00, 0x00, 0x00}).malformed);
    CHECK_EQ(parse_ble_popup(nullptr, 0).format, BlePopupFormat::None);
}

GUARDIAN_CASE(cut_or_hostile_advertising_data_is_never_read_past_its_end) {
    // A structure longer than the data: malformed, nothing classified.
    auto p = parse({0x1e, 0xff, 0x4c, 0x00, 0x07});
    CHECK_EQ(p.format, BlePopupFormat::None); CHECK(p.malformed);
    // A recognised record too short for its fields.
    p = parse({0x06, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07});          // proximity pairing without a model
    CHECK_EQ(p.format, BlePopupFormat::None); CHECK(p.malformed);
    p = parse({0x05, 0xff, 0x4c, 0x00, 0x0f, 0x05});                // nearby action without an action
    CHECK_EQ(p.format, BlePopupFormat::None); CHECK(p.malformed);
    p = parse({0x04, 0xff, 0x06, 0x00, 0x03});                      // Swift Pair without its header
    CHECK_EQ(p.format, BlePopupFormat::None); CHECK(p.malformed);
    p = parse({0x0d, 0xff, 0x75, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0xff, 0x00, 0x00, 0x43});   // watch prefix, no model
    CHECK_EQ(p.format, BlePopupFormat::None); CHECK(p.malformed);
    CHECK(parse({0x01}).malformed);                                 // a length with no type
    CHECK(!parse({0x01, 0xff}).popup());                            // manufacturer data with no company
    // Every prefix of every message, and every single-byte change of it: bounded (run under ASan) and
    // a classified result always came from complete fields.
    for (const Bytes& whole : {apple_pairing(0x0e20), apple_pairing_short(0x0e20), join({flags(), apple_action(0x13)}), samsung_watch(0x1a),
                               samsung_buds(0xee7a0c), swift_pair("Keyboard K380"), fast_pair(0x00b727)}) {
        for (std::size_t n = 0; n <= whole.size(); ++n) {
            Bytes exact(whole.begin(), whole.begin() + static_cast<std::ptrdiff_t>(n));   // heap copy: ASan sees one byte too far
            const auto r = parse_ble_popup(exact.data(), exact.size());
            CHECK(!(r.popup() && r.malformed));
        }
        for (std::size_t i = 0; i < whole.size(); ++i)
            for (unsigned v : {0x00u, 0x01u, 0x1fu, 0xffu}) {
                Bytes changed = whole; changed[i] = static_cast<std::uint8_t>(v);
                const auto r = parse_ble_popup(changed.data(), changed.size());
                CHECK(!(r.popup() && r.malformed));
            }
    }
}

// =========================================================================================
// Flood rule
// =========================================================================================
GUARDIAN_CASE(a_flood_of_different_messages_from_short_lived_addresses_is_one_nearby_observation) {
    Rig r;
    r.quiet(1000, 39000);
    CHECK_EQ(r.sink.got.size(), 0u);
    r.flood(40000, 100000);                                    // 100 s, 100 adverts a second
    CHECK_EQ(r.sink.count(Pattern::PairingPopupFlood), 3u);    // 40 s, then once per 45 s cooldown
    CHECK_EQ(r.sink.got.size(), 3u);
    const auto* o = r.sink.first(Pattern::PairingPopupFlood);
    if (!o) return;
    CHECK_EQ(o->scope, IncidentScope::Area);
    CHECK_EQ(o->family, DetectorFamily::Bluetooth);
    CHECK_EQ(o->acquired.at, Millis{40020});                   // the third message closes the rule
    CHECK_EQ(o->count, 3u); CHECK_EQ(o->threshold, 3u); CHECK_EQ(o->window_ms, 1000u);
    CHECK_EQ(o->distinct_sources, 3u);
    CHECK(o->sources_random);
    CHECK_EQ(o->corroborating, 3u);                            // three vendor formats among the three messages
    CHECK_EQ(o->raw_frames, 3u);
    CHECK(!o->saturated);
    CHECK(!o->coverage_known);                                 // no scan report was given
    CHECK(o->kind != IncidentKind::NetworkPattern);
    // Later observations of the same flood: more addresses than the table holds, said so.
    const auto* later = r.sink.last(Pattern::PairingPopupFlood);
    CHECK(later && later->saturated);
    CHECK(later && later->distinct_sources <= BlePopupDetector::address_capacity);
    CHECK(later && later->count >= 3u);
    const auto rep = r.d.report(Instant{epoch(), 140000, true});
    CHECK_EQ(std::string(rep.name), std::string("ble_popup"));
    CHECK_EQ(rep.family, DetectorFamily::Bluetooth); CHECK_EQ(rep.scope, IncidentScope::Area);
    CHECK(rep.configured); CHECK_EQ(rep.incidents, 3u);
    CHECK(rep.frames_seen >= 10000u); CHECK(rep.events_total >= 10000u);
    CHECK(rep.events_in_window > 0u);
    CHECK(r.d.popup_adverts() >= 10000u);
}

GUARDIAN_CASE(devices_that_keep_their_address_never_make_a_flood) {
    Rig r;
    // Six earbuds / headphones of different products, a watch, a mouse and a headset in pairing mode,
    // two phones doing a setup action: each under ONE address, advertising for ten minutes; one new
    // device joins every 7 s after the learning time.
    struct Device { Mac address; Bytes data; Millis from; };
    std::vector<Device> devices;
    const std::uint16_t models[] = {0x0220, 0x0e20, 0x1420, 0x0a20, 0x0320, 0x0b20};
    Millis from = 1000;
    for (std::uint32_t i = 0; i < 6; ++i, from += 7000) devices.push_back({mac(0x500 + i), apple_pairing(models[i], 0x01), from});
    from = 45000;
    devices.push_back({mac(0x600), samsung_watch(0x1a), from}); from += 7000;
    devices.push_back({mac(0x601), swift_pair("Mouse"), from}); from += 7000;
    devices.push_back({mac(0x602), fast_pair(0x0a1b2c), from}); from += 7000;
    devices.push_back({mac(0x603), join({flags(), apple_action(0x09)}), from}); from += 7000;
    devices.push_back({mac(0x604), samsung_buds(0xee7a0c), from}); from += 7000;
    devices.push_back({mac(0x605), join({flags(), apple_action(0x13)}), from});
    for (Millis t = 1000; t < 601000; t += 100)
        for (const auto& dv : devices) if (t >= dv.from) r.feed(dv.address, dv.data, t + (dv.address[5] % 7));
    CHECK_EQ(r.sink.got.size(), 0u);
    CHECK(r.d.popup_adverts() > 50000u);
}

GUARDIAN_CASE(nothing_is_reported_while_the_room_is_still_being_learned) {
    Rig r;
    // The flood is already running when listening begins: silent for the learning time, then reported.
    r.flood(1000, 29900);
    CHECK_EQ(r.sink.got.size(), 0u);
    r.flood(30900, 1000);
    CHECK_EQ(r.sink.count(Pattern::PairingPopupFlood), 1u);
    const auto* o = r.sink.first(Pattern::PairingPopupFlood);
    CHECK(o && o->acquired.at >= Millis{31000} && o->acquired.at <= Millis{31030});
    // A silence longer than the address memory: every device is new again, so learning starts over.
    Rig again;
    again.quiet(1000, 40000);
    again.flood(41000 + 61000, 20000);                         // 61 s of nothing, then a flood
    CHECK_EQ(again.sink.got.size(), 0u);                       // still learning (30 s)
    again.flood(41000 + 61000 + 30000, 1000);
    CHECK_EQ(again.sink.count(Pattern::PairingPopupFlood), 1u);
}

GUARDIAN_CASE(flood_thresholds_are_the_limits_and_their_documented_gaps_are_real) {
    // Two messages, however many addresses: below ble_popup_messages.
    {   Rig r; r.quiet(1000, kLearned);
        for (std::uint32_t i = 0; i < 400; ++i) r.feed(mac(0x9000 + i), i % 2 ? apple_pairing(0x0e20) : samsung_watch(0x1a), 40000 + i * 10);
        CHECK_EQ(r.sink.got.size(), 0u);
        // ... and with the limit lowered to 2 (TUNE) the same stream is reported.
        ThreatLimits l{}; l.ble_popup_messages = 2;
        Rig low(l); low.quiet(1000, kLearned);
        for (std::uint32_t i = 0; i < 400; ++i) low.feed(mac(0x9000 + i), i % 2 ? apple_pairing(0x0e20) : samsung_watch(0x1a), 40000 + i * 10);
        CHECK_EQ(low.sink.count(Pattern::PairingPopupFlood), 1u);
        CHECK(low.sink.got.size() == 1 && low.sink.got[0].count == 2u && low.sink.got[0].threshold == 2u);
    }
    // Many messages from only two short-lived addresses: below ble_popup_sources.
    {   Rig r; r.quiet(1000, kLearned);
        for (std::uint32_t i = 0; i < 100; ++i) r.feed(mac(0x9100 + i % 2), swift_pair(i % 2 ? "A" : "B"), 40000 + i * 10);
        r.feed(mac(0x9100), samsung_watch(1), 41500); r.feed(mac(0x9101), samsung_watch(2), 41510);
        CHECK_EQ(r.sink.count(Pattern::PairingPopupFlood), 0u);
    }
    // Documented gap 1: ONE product from ever-new addresses (one message) is not the flood rule at the defaults;
    // ble_popup_messages = 1 turns the rule into "short-lived addresses sending popup messages".
    {   Rig r; r.quiet(1000, kLearned);
        for (std::uint32_t i = 0; i < 500; ++i) r.feed(mac(0x9200 + i), fast_pair(0x00b727), 40000 + i * 10);
        CHECK_EQ(r.sink.got.size(), 0u);
        ThreatLimits l{}; l.ble_popup_messages = 1;
        Rig one(l); one.quiet(1000, kLearned);
        for (std::uint32_t i = 0; i < 500; ++i) one.feed(mac(0x9200 + i), fast_pair(0x00b727), 40000 + i * 10);
        CHECK_EQ(one.sink.count(Pattern::PairingPopupFlood), 1u);
        CHECK(one.sink.got.size() == 1 && one.sink.got[0].count == 1u && one.sink.got[0].distinct_sources == 3u && one.sink.got[0].corroborating == 1u);
    }
    // Documented gap 2: a new address and message only once a second never puts three inside one second;
    // a longer window (TUNE) sees it.
    {   Rig r; r.quiet(1000, kLearned);
        for (std::uint32_t i = 0; i < 60; ++i) for (Millis k = 0; k < 1000; k += 60) r.feed(mac(0x9300 + i), apple_action(static_cast<std::uint8_t>(1 + i % 9)), 40000 + i * 1000 + k);
        CHECK_EQ(r.sink.got.size(), 0u);
        ThreatLimits l{}; l.ble_popup_window_ms = 5000;
        Rig wide(l); wide.quiet(1000, kLearned);
        for (std::uint32_t i = 0; i < 60; ++i) for (Millis k = 0; k < 1000; k += 60) wide.feed(mac(0x9300 + i), apple_action(static_cast<std::uint8_t>(1 + i % 9)), 40000 + i * 1000 + k);
        CHECK_EQ(wide.sink.count(Pattern::PairingPopupFlood), 2u);   // 60 s: once, and once after the 45 s cooldown
        CHECK(wide.sink.got.size() == 2 && wide.sink.got[0].window_ms == 5000u);
    }
    // The known false positive, stated: three NEW real devices of different products first heard in the
    // same second (after learning) are indistinguishable from the start of a flood.
    {   Rig r; r.quiet(1000, kLearned);
        r.feed(mac(0x9400), apple_pairing(0x0e20), 40000); r.feed(mac(0x9401), samsung_buds(0xee7a0c), 40300); r.feed(mac(0x9402), fast_pair(0x0a1b2c), 40600);
        CHECK_EQ(r.sink.count(Pattern::PairingPopupFlood), 1u);
        // ... the same three arriving two seconds apart are not.
        Rig apart; apart.quiet(1000, kLearned);
        apart.feed(mac(0x9400), apple_pairing(0x0e20), 40000); apart.feed(mac(0x9401), samsung_buds(0xee7a0c), 42000); apart.feed(mac(0x9402), fast_pair(0x0a1b2c), 44000);
        CHECK_EQ(apart.sink.got.size(), 0u);
    }
}

// =========================================================================================
// Rotation rule
// =========================================================================================
GUARDIAN_CASE(one_address_announcing_several_fast_pair_products_is_one_nearby_observation) {
    Rig r;
    // Also while learning: the rule needs no knowledge of the room.
    r.feed(mac(0x77), fast_pair(0x000001), 1000);
    r.feed(mac(0x77), fast_pair(0x000002), 1200);
    CHECK_EQ(r.sink.got.size(), 0u);                           // two products: below the limit
    r.feed(mac(0x77), fast_pair(0x000002), 1300);              // a repeat is not a third product
    CHECK_EQ(r.sink.got.size(), 0u);
    r.feed(mac(0x77), fast_pair(0x000003), 1400);
    CHECK_EQ(r.sink.count(Pattern::FastPairRotation), 1u);
    const auto* o = r.sink.first(Pattern::FastPairRotation);
    if (!o) return;
    CHECK_EQ(o->scope, IncidentScope::Area); CHECK_EQ(o->family, DetectorFamily::Bluetooth);
    CHECK_EQ(o->count, 3u); CHECK_EQ(o->threshold, 3u); CHECK_EQ(o->window_ms, 5000u);
    CHECK_EQ(o->distinct_sources, 1u); CHECK(o->sources_random);
    CHECK(o->bssid == Mac{});                                  // the address is never carried in the observation
    // It keeps rotating for two minutes: one observation per cooldown.
    for (std::uint32_t i = 0; i < 1200; ++i) r.feed(mac(0x77), fast_pair(0x000010 + i % 40), 1500 + i * 100);
    CHECK_EQ(r.sink.count(Pattern::FastPairRotation), 3u);     // 1.4 s, 46.4 s, 91.4 s
    CHECK_EQ(r.sink.count(Pattern::PairingPopupFlood), 0u);    // one address is never the flood rule
}

GUARDIAN_CASE(rotation_needs_the_products_inside_the_window_and_from_one_address) {
    Rig r;
    // Three products from one address, spread over 12 s: never three inside 5 s.
    r.feed(mac(0x78), fast_pair(1), 1000); r.feed(mac(0x78), fast_pair(2), 7000); r.feed(mac(0x78), fast_pair(3), 13000);
    // Three products, each from its own long-lived address (three real devices in pairing mode).
    for (Millis t = 20000; t < 80000; t += 200) { r.feed(mac(0x81), fast_pair(0x10), t); r.feed(mac(0x82), fast_pair(0x20), t + 50); r.feed(mac(0x83), fast_pair(0x30), t + 90); }
    // One device announcing one product for an hour.
    for (Millis t = 80000; t < 3680000; t += 1000) r.feed(mac(0x84), fast_pair(0x40), t);
    // Other formats changing product under one address are not this rule (ledger: Fast Pair model IDs).
    for (std::uint32_t i = 0; i < 20; ++i) r.feed(mac(0x85), samsung_watch(static_cast<std::uint8_t>(i)), 3700000 + i * 100);
    CHECK_EQ(r.sink.count(Pattern::FastPairRotation), 0u);
    // Twelve addresses rotating in step fill the pair table (24) after two products each: the third is
    // still reported (an address's own pairs are the last to be dropped) and marked as a lower bound.
    Rig many;
    for (std::uint32_t round = 0; round < 3; ++round)
        for (std::uint32_t a = 0; a < 12; ++a) many.feed(mac(0x200 + a), fast_pair(0x1000 + round), 1000 + round * 40 + a);
    CHECK(many.sink.count(Pattern::FastPairRotation) == 1u);
    CHECK(many.sink.got.size() >= 1 && many.sink.got[0].saturated);
}

// =========================================================================================
// Input rules, limits, bounds
// =========================================================================================
GUARDIAN_CASE(unusable_input_counts_nothing_and_bad_limits_are_refused) {
    Rig r; r.quiet(1000, kLearned);
    // Unknown time, another timebase, another origin: offered, never counted.
    for (std::uint32_t i = 0; i < 50; ++i) {
        auto a = advert(mac(0x3000 + i), flood_message(i), 40000 + i * 10); a.acquired.known = false; r.d.advert(a, r.sink);
        a = advert(mac(0x3100 + i), flood_message(i), 40000 + i * 10); a.acquired.epoch = epoch(2); r.d.advert(a, r.sink);
        a = advert(mac(0x3200 + i), flood_message(i), 40000 + i * 10); a.origin = Origin::Demo; r.d.advert(a, r.sink);
    }
    CHECK_EQ(r.sink.got.size(), 0u);
    CHECK_EQ(r.d.popup_adverts(), 0u);
    // Unreadable data is counted as such and is never a message.
    r.feed(mac(0x3300), {0x1e, 0xff, 0x4c, 0x00, 0x07}, 41000);
    CHECK_EQ(r.d.malformed(), 1u); CHECK_EQ(r.d.popup_adverts(), 0u);
    // A size beyond the data array is clamped, never read.
    auto big = advert(mac(0x3301), apple_pairing(0x0e20), 41010); big.size = 200; r.d.advert(big, r.sink);
    CHECK_EQ(r.d.popup_adverts(), 1u);
    // Unfed (no scan): counts nothing, reports configured=false, and comes back clean.
    r.d.set_available(false);
    r.flood(42000, 3000);
    CHECK_EQ(r.sink.got.size(), 0u);
    CHECK(!r.d.report(Instant{epoch(), 45000, true}).configured);
    r.d.set_available(true);
    CHECK(r.d.report(Instant{epoch(), 45000, true}).configured);
    CHECK_EQ(r.d.popup_adverts(), 0u);
    // Limits.
    const auto refused = [&](ThreatLimits l) { ApprovedScope s; BlePopupDetector d(s, l); return !d.configured() && !r.d.accepts(l); };
    ThreatLimits l{};
    CHECK(r.d.accepts(l));
    l = {}; l.ble_popup_window_ms = 99; CHECK(refused(l));
    l = {}; l.ble_popup_messages = 0; CHECK(refused(l));
    l = {}; l.ble_popup_sources = 0; CHECK(refused(l));
    l = {}; l.ble_popup_sources = BlePopupDetector::address_capacity + 1; CHECK(refused(l));
    l = {}; l.ble_popup_messages = BlePopupDetector::address_capacity + 1; CHECK(refused(l));
    l = {}; l.ble_address_memory_ms = 999; CHECK(refused(l));             // shorter than the window
    l = {}; l.ble_rotation_window_ms = 99; CHECK(refused(l));
    l = {}; l.ble_rotation_models = 1; CHECK(refused(l));                 // one product is every real device
    l = {}; l.ble_rotation_models = BlePopupDetector::model_capacity + 1; CHECK(refused(l));
    l = {}; l.ble_learn_ms = 0; CHECK(r.d.accepts(l));                    // no learning time is allowed (a lab bench)
    // A refused set through the whole detector set changes nothing.
    ApprovedScope s; ThreatDetectors all(s);
    l = {}; l.ble_rotation_models = 1;
    CHECK(!all.configure(l));
    CHECK_EQ(all.ble.limits().ble_rotation_models, 3u);
    CHECK(all.at(ThreatDetectors::count - 1) == &all.ble);
}

GUARDIAN_CASE(the_scan_listening_report_travels_with_the_observation_and_wifi_coverage_does_not) {
    Rig r; r.quiet(1000, kLearned);
    CoverageReport wifi{}; wifi.sampled_at = Instant{epoch(), 39900, true}; wifi.channel = 6; wifi.window_ms = 1000; wifi.listened_ms = 1000;
    r.d.coverage(wifi);                                        // the registry hands every detector the Wi-Fi report
    r.flood(40000, 100);
    CHECK(r.sink.got.size() == 1 && !r.sink.got[0].coverage_known);
    Rig scan; scan.quiet(1000, kLearned);
    CoverageReport ble{}; ble.sampled_at = Instant{epoch(), 39900, true}; ble.window_ms = 1000; ble.listened_ms = 250; ble.hopping = true;
    scan.d.scan_coverage(ble);                                 // a 25 % scan duty
    scan.flood(40000, 100);
    CHECK(scan.sink.got.size() == 1 && scan.sink.got[0].coverage_known);
    CHECK(scan.sink.got.size() == 1 && scan.sink.got[0].listened_ms == 250u && scan.sink.got[0].coverage_window_ms == 1000u && scan.sink.got[0].hopping);
}

GUARDIAN_CASE(the_ble_detector_never_allocates_and_stays_small) {
    Rig r; r.quiet(1000, kLearned);
    r.sink.got.reserve(64);
    std::vector<BleAdvert> stream;
    for (std::uint32_t i = 0; i < 5000; ++i) stream.push_back(advert(mac(0x700000 + i), flood_message(i), 40000 + i * 10));
    for (std::uint32_t i = 0; i < 500; ++i) stream.push_back(advert(mac(0x55), fast_pair(i), 90000 + i * 10));
    g_banned_allocations = 0;
    {
        AllocationBan ban;
        for (const auto& a : stream) r.d.advert(a, r.sink);
        (void)r.d.report(Instant{epoch(), 100000, true});
        r.d.on_tick(Instant{epoch(), 100000, true}, r.sink);
    }
    CHECK_EQ(g_banned_allocations, 0u);
    CHECK(r.sink.got.size() >= 2u);
    // MEASURED on the host 2026-11-19: 3,288 B and 88 B (builds/20261119-g16h-ble-tdd/sizes.log).
    CHECK(sizeof(BlePopupDetector) <= 4 * 1024);
    CHECK(sizeof(BleAdvert) <= 96u);
}

// =========================================================================================
// Monitor, Core, presenter: amber "nearby", never the rating, never an ALERT
// =========================================================================================
GUARDIAN_CASE(monitor_ble_scan_off_is_honest_and_on_reports_amber_through_core) {
    Clock clock; measurement::Monitor m(clock, profiles::all_2g4_channels());
    CHECK_EQ(m.detectors().size(), 2u + ThreatDetectors::count);
    CHECK_EQ(m.detectors().refused(), 0u);
    CHECK(!m.ble_scan());
    const auto bt = static_cast<std::size_t>(DetectorFamily::Bluetooth);
    CHECK(!m.radar().families[bt].registered);                 // nothing is shown as measuring
    static char status[4096];
    CHECK(m.status_text(status, sizeof status) > 0u);
    CHECK(std::strstr(status, "ble_popup:frames=0,in_window=0,events=0,incidents=0,last=none,cooldown=0,unconfigured") != nullptr);
    // Off: an advert is refused and changes nothing.
    clock.at = 2000;
    CHECK(!m.ble_advert(advert(mac(1), apple_pairing(0x0e20), 2000)));
    CHECK_EQ(m.ble_adverts, 0u);

    m.set_ble_scan(true);
    CHECK(m.ble_scan());
    CHECK(m.radar().families[bt].registered);
    CHECK_EQ(m.radar().families[bt].scope, IncidentScope::Area);
    // Input checks as for frames: the future, another timebase, another origin, an unknown time.
    auto bad = advert(mac(2), apple_pairing(0x0e20), 9000); CHECK(!m.ble_advert(bad));            // after the clock's now
    bad = advert(mac(2), apple_pairing(0x0e20), 2000); bad.acquired.epoch = epoch(2); CHECK(!m.ble_advert(bad));
    bad = advert(mac(2), apple_pairing(0x0e20), 2000); bad.origin = Origin::Demo; CHECK(!m.ble_advert(bad));
    bad = advert(mac(2), apple_pairing(0x0e20), 2000); bad.acquired.known = false; CHECK(!m.ble_advert(bad));
    CHECK_EQ(m.ble_invalid, 4u); CHECK_EQ(m.ble_adverts, 0u);

    // A quiet room, then a flood, with the scan's listening report.
    for (Millis t = 2000; t < 40000; t += 250) { clock.at = t; CHECK(m.ble_advert(advert(mac(0xaa02), apple_nearby_info(), t))); }
    auto s = m.snapshot();
    for (bool v : s.area_visible) CHECK(!v);
    CoverageReport scan{}; scan.sampled_at = Instant{epoch(), 39990, true}; scan.window_ms = 1000; scan.listened_ms = 500; scan.hopping = true;
    m.ble_coverage(scan);
    for (std::uint32_t i = 0; i < 300; ++i) { clock.at = 40000 + i * 10; CHECK(m.ble_advert(advert(mac(0x100000 + i), flood_message(i), clock.at))); }
    s = m.snapshot();
    const IncidentObservation* seen = nullptr;
    for (std::size_t i = 0; i < area_slots; ++i) if (s.area_visible[i] && s.area[i].pattern == Pattern::PairingPopupFlood) seen = &s.area[i];
    CHECK(seen != nullptr);
    if (!seen) return;
    CHECK_EQ(seen->family, DetectorFamily::Bluetooth);
    CHECK(seen->coverage_known); CHECK_EQ(seen->listened_ms, Millis{500});
    for (bool on : s.incidents) CHECK(!on);                    // never a network incident
    CHECK_EQ(s.settings.mood, Mood::Unknown);                  // nothing selected: an area observation rates nothing
    const auto v = m.view(s);
    CHECK(!v.alert);
    CHECK(v.caution);
    CHECK_EQ(std::string(v.caution_reason), std::string("Pairing-popup spam nearby"));
    CHECK(m.radar().families[bt].active);
    CHECK(m.radar().families[bt].pulse);
    static char json[8192];
    CHECK(m.json(json, sizeof json, 0, true, false) > 0u);
    CHECK(std::strstr(json, "\"name\":\"ble_popup\"") != nullptr);
    CHECK(std::strstr(json, "\"pattern\":\"pairing_popup_flood\"") != nullptr);
    CHECK(std::strstr(json, "\"family\":\"bluetooth\"") != nullptr);
    CHECK(m.status_text(status, sizeof status) > 0u);
    CHECK(std::strstr(status, "ble_popup:frames=452,") != nullptr);          // 152 quiet + 300 flood reports offered
    CHECK(std::strstr(status, "ble_popup:frames=0,in_window=0,events=0,incidents=0,last=none,cooldown=0,unconfigured") == nullptr);
    CHECK_EQ(m.ble_adverts, 452u);
    // A Wi-Fi selection is untouched by any of it.
    CHECK_EQ(m.frames, 0u);
    // Scan off again: the detector is unfed and says so.
    m.set_ble_scan(false);
    CHECK(!m.radar().families[bt].registered);
    CHECK(m.status_text(status, sizeof status) > 0u);
    CHECK(std::strstr(status, "ble_popup:frames=0,in_window=0,events=0,incidents=0,last=none,cooldown=0,unconfigured") != nullptr);
}

GUARDIAN_CASE(ble_patterns_have_wording_keys_and_never_overclaim) {
    struct Want { Pattern p; const char* area; const char* key; const char* unit; };
    const Want all[] = {{Pattern::PairingPopupFlood, "Pairing-popup spam nearby", "pairing_popup_flood", "messages"},
                        {Pattern::FastPairRotation, "One address spamming pairing popups nearby", "fast_pair_rotation", "products"}};
    for (const auto& w : all) {
        IncidentObservation o{}; o.pattern = w.p; o.scope = IncidentScope::Area; o.family = DetectorFamily::Bluetooth;
        const std::string area = area_text(o);
        CHECK_EQ(area, std::string(w.area));
        CHECK_EQ(std::string(area_unit(o)), std::string(w.unit));
        CHECK_EQ(std::string(measurement::pattern_key(w.p)), std::string(w.key));
        CHECK(std::strlen(network_pattern_text(w.p)) > 10u);
        std::string lower = area + " " + network_pattern_text(w.p);
        for (auto& c : lower) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        for (const char* banned : {"attack", "hacker", "hacked", "flipper", "apple", "samsung", "google", "microsoft", "iphone", "android",
                                   "stolen", "compromis", "track"})
            CHECK(lower.find(banned) == std::string::npos);
        // Two 22-glyph rows of the amber status slot hold the text.
        std::size_t rows = 1, column = 0;
        for (std::size_t i = 0; i < area.size();) {
            std::size_t end = area.find(' ', i); if (end == std::string::npos) end = area.size();
            const std::size_t word = end - i;
            if (column && column + 1 + word > 22) { ++rows; column = word; } else column += (column ? 1 : 0) + word;
            i = end + 1;
        }
        CHECK(rows <= 2u);
    }
    CHECK_EQ(std::string(measurement::family_key(DetectorFamily::Bluetooth)), std::string("bluetooth"));
    CHECK_EQ(std::string(area_text(DetectorFamily::Bluetooth)), std::string("Pairing-popup spam nearby"));
    CHECK_EQ(std::string(area_unit(DetectorFamily::Bluetooth)), std::string("messages"));
    CHECK_EQ(std::string(family_text(DetectorFamily::Bluetooth)), std::string("bluetooth"));
}

// Supervisor review (2026-11-17): every G16F/G16G threshold is a live TUNE key
// ("t.<field>"), as the ledger requires; defaults are today's ThreatLimits.
#include "check.hpp"
#include "threat_tune.hpp"
#include <cmath>
#include <cstring>
#include <set>
#include <string>
#include <vector>
using namespace guardian;
using namespace guardian::tune;
namespace {
class MemoryBlob final : public BlobStorage {
public:
    std::vector<std::uint8_t> bytes; bool exists{};
    BlobRead read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const override {
        if (!exists) return BlobRead::Absent;
        if (bytes.size() > capacity) return BlobRead::Error;
        std::memcpy(out, bytes.data(), bytes.size()); size = bytes.size(); return BlobRead::Ok;
    }
    bool write(const std::uint8_t* data, std::size_t size) override { bytes.assign(data, data + size); exists = true; return true; }
};
}

GUARDIAN_CASE(every_threat_limit_is_a_t_key_with_todays_default) {
    MemoryBlob blob; Registry r(blob); ThreatKeys keys;
    const ThreatLimits d{};
    CHECK(add_threat_limits(r, d, keys));
    CHECK_EQ(keys.count, threat_key_count());
    CHECK(threat_key_count() >= 52);                 // one key per ThreatLimits field
    std::set<std::string> seen;
    for (std::size_t i = 0; i < keys.count; ++i) {
        const std::string k = threat_key(i);
        CHECK(k.rfind("t.", 0) == 0); CHECK(k.size() <= max_key); CHECK(seen.insert(k).second);
        CHECK(keys.index[i] >= 0);
    }
    // Read back with nothing changed: exactly today's limits, field by field.
    CHECK(threat_limits_equal(threat_limits_from(r, keys, d), d));
}

GUARDIAN_CASE(a_tune_change_reaches_only_its_own_field) {
    MemoryBlob blob; Registry r(blob); ThreatKeys keys; const ThreatLimits d{};
    CHECK(add_threat_limits(r, d, keys)); r.load();
    const char* reason = nullptr;
    CHECK(r.set("t.probe_flood", 120.0f, reason));
    CHECK(r.set("t.beacon_rssi_min", -70.0f, reason));
    CHECK(r.set("t.owe_memory_ms", 600000.0f, reason));
    const ThreatLimits got = threat_limits_from(r, keys, d);
    CHECK_EQ(got.probe_flood, 120u); CHECK_EQ(int(got.beacon_rssi_min), -70); CHECK_EQ(got.owe_memory_ms, Millis{600000});
    ThreatLimits expect = d; expect.probe_flood = 120; expect.beacon_rssi_min = -70; expect.owe_memory_ms = 600000;
    CHECK(threat_limits_equal(got, expect));
    // Persisted: a fresh registry restores the same values.
    Registry r2(blob); ThreatKeys k2; CHECK(add_threat_limits(r2, d, k2)); CHECK(r2.load() == Store::Restored);
    CHECK(threat_limits_equal(threat_limits_from(r2, k2, d), expect));
}

GUARDIAN_CASE(no_room_means_nothing_is_added) {
    MemoryBlob blob; Registry r(blob); ThreatKeys keys;
    for (std::size_t i = 0; i + threat_key_count() / 2 < max_params; ++i) { char k[16]; std::snprintf(k, sizeof k, "x%zu", i); r.add(k, 0, 1, 0); }
    const std::size_t before = r.count();
    CHECK(!add_threat_limits(r, ThreatLimits{}, keys));
    CHECK_EQ(r.count(), before); CHECK_EQ(keys.count, 0u);
}

GUARDIAN_CASE(the_whole_stick_registry_fits) {
    // StickS3 registers 44 other keys (persona, motion, imu, display, shake, burst, power, detect incl.
    // G16J detect.twin and detect.sweep_ms; firmware/boards/sticks3/main/measurement_main.cpp).
    MemoryBlob blob; Registry r(blob); ThreatKeys keys;
    for (std::size_t i = 0; i < 44; ++i) { char k[16]; std::snprintf(k, sizeof k, "other%zu", i); CHECK(r.add(k, 0, 1, 0) >= 0); }
    CHECK(add_threat_limits(r, ThreatLimits{}, keys));
    CHECK(r.count() <= max_params);
    std::uint8_t blob_bytes[max_blob];
    CHECK(r.encode(blob_bytes, sizeof blob_bytes, 1) > 0);   // the persisted record still fits its bound
}

// G16H: the Bluetooth LE limits are live TUNE keys like every other threat limit, and the
// StickS3's whole registry (56 board keys today) still fits with them.
GUARDIAN_CASE(the_ble_limits_are_t_keys_and_the_stick_registry_still_fits) {
    MemoryBlob blob; Registry r(blob); ThreatKeys keys; const ThreatLimits d{};
    for (std::size_t i = 0; i < 56; ++i) { char k[16]; std::snprintf(k, sizeof k, "board%zu", i); CHECK(r.add(k, 0, 1, 0) >= 0); }
    CHECK(add_threat_limits(r, d, keys)); r.load();
    CHECK(threat_key_count() >= 68);
    CHECK(r.count() <= max_params);
    const char* reason = nullptr;
    CHECK(r.set("t.ble_popup_window_ms", 5000.0f, reason));
    CHECK(r.set("t.ble_popup_messages", 1.0f, reason));
    CHECK(r.set("t.ble_popup_sources", 5.0f, reason));
    CHECK(r.set("t.ble_learn_ms", 0.0f, reason));
    CHECK(r.set("t.ble_address_memory_ms", 120000.0f, reason));
    CHECK(r.set("t.ble_rotation_window_ms", 8000.0f, reason));
    CHECK(r.set("t.ble_rotation_models", 4.0f, reason));
    const ThreatLimits got = threat_limits_from(r, keys, d);
    ThreatLimits expect = d;
    expect.ble_popup_window_ms = 5000; expect.ble_popup_messages = 1; expect.ble_popup_sources = 5; expect.ble_learn_ms = 0;
    expect.ble_address_memory_ms = 120000; expect.ble_rotation_window_ms = 8000; expect.ble_rotation_models = 4;
    CHECK_EQ(got.ble_popup_window_ms, Millis{5000}); CHECK_EQ(got.ble_popup_messages, 1u); CHECK_EQ(got.ble_popup_sources, 5u);
    CHECK_EQ(got.ble_learn_ms, Millis{0}); CHECK_EQ(got.ble_address_memory_ms, Millis{120000});
    CHECK_EQ(got.ble_rotation_window_ms, Millis{8000}); CHECK_EQ(got.ble_rotation_models, 4u);
    CHECK(threat_limits_equal(got, expect));
    CHECK(!threat_limits_equal(got, d));
    std::uint8_t blob_bytes[max_blob];
    CHECK(r.encode(blob_bytes, sizeof blob_bytes, 1) > 0);
}

// G24: the device settings blob, the measured-hours table and the STATUS fragments
// (adapters/companion/device_settings.cpp), host TDD red first.
#include "check.hpp"
#include "device_settings.hpp"
#include <cstring>
#include <string>
#include <vector>

using namespace guardian;
using namespace guardian::companion;

namespace {
class MemoryBlob final : public BlobStorage {
public:
    std::vector<std::uint8_t> bytes; bool exists{}, fail_write{}, fail_read{}; unsigned writes{};
    BlobRead read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const override {
        if (!exists) return BlobRead::Absent;
        if (fail_read || bytes.size() > capacity) return BlobRead::Error;
        std::memcpy(out, bytes.data(), bytes.size()); size = bytes.size(); return BlobRead::Ok;
    }
    bool write(const std::uint8_t* data, std::size_t size) override {
        ++writes; if (fail_write) return false;
        bytes.assign(data, data + size); exists = true; return true;
    }
};
std::string text_of(std::size_t (*f)(const DeviceChoices&, SettingsStore, char*, std::size_t), const DeviceChoices& c, SettingsStore s) {
    char out[settings_status_max]; f(c, s, out, sizeof out); return out;
}
DeviceChoices choices(GuardCycle g, std::uint8_t pct) { DeviceChoices c; c.guard = g; c.bright_pct = pct; return c; }
} // namespace

GUARDIAN_CASE(defaults_and_valid_values) {
    const DeviceChoices d;
    CHECK(d.guard == GuardCycle::Always); CHECK_EQ(unsigned(d.bright_pct), 60u); CHECK(d.valid());
    for (const auto pct : brightness_choices) CHECK(choices(GuardCycle::EveryMinute, pct).valid());
    for (const unsigned pct : {0u, 9u, 11u, 50u, 61u, 99u, 101u, 255u}) CHECK(!choices(GuardCycle::Always, static_cast<std::uint8_t>(pct)).valid());
    CHECK(!choices(static_cast<GuardCycle>(3), 60).valid());
}

GUARDIAN_CASE(record_round_trip_and_rejections) {
    for (const auto g : {GuardCycle::Always, GuardCycle::Every30s, GuardCycle::EveryMinute})
        for (const auto pct : brightness_choices) {
            std::uint8_t buf[settings_record_bytes + 4]{};
            const auto n = encode_settings(choices(g, pct), buf, sizeof buf);
            CHECK_EQ(n, settings_record_bytes);
            CHECK(std::memcmp(buf, "GSET", 4) == 0);
            DeviceChoices out = choices(GuardCycle::Every30s, 10);
            CHECK(decode_settings(buf, n, out)); CHECK(out == choices(g, pct));
        }
    std::uint8_t buf[settings_record_bytes]{};
    CHECK_EQ(encode_settings(choices(GuardCycle::Always, 55), buf, sizeof buf), std::size_t{0});   // invalid value
    CHECK_EQ(encode_settings(choices(GuardCycle::Always, 60), buf, sizeof buf - 1), std::size_t{0}); // no room
    CHECK_EQ(encode_settings(choices(GuardCycle::EveryMinute, 30), buf, sizeof buf), settings_record_bytes);
    const DeviceChoices keep = choices(GuardCycle::Every30s, 80);
    for (std::size_t i = 0; i < settings_record_bytes; ++i) {      // every single flipped bit is refused
        for (int bit = 0; bit < 8; ++bit) {
            std::uint8_t bad[settings_record_bytes]; std::memcpy(bad, buf, sizeof bad);
            bad[i] = static_cast<std::uint8_t>(bad[i] ^ (1u << bit));
            DeviceChoices out = keep; CHECK(!decode_settings(bad, sizeof bad, out)); CHECK(out == keep);
        }
    }
    DeviceChoices out = keep;
    CHECK(!decode_settings(buf, sizeof buf - 1, out)); CHECK(!decode_settings(nullptr, sizeof buf, out)); CHECK(out == keep);
}

GUARDIAN_CASE(store_absent_restored_corrupt_saved_failed) {
    MemoryBlob blob; DeviceSettingsStore store(blob);
    CHECK(store.state() == SettingsStore::Default);
    CHECK(store.load() == DeviceChoices{}); CHECK(store.state() == SettingsStore::Default);   // absent: the defaults
    CHECK(store.save(choices(GuardCycle::EveryMinute, 30))); CHECK(store.state() == SettingsStore::Saved);
    CHECK(store.current() == choices(GuardCycle::EveryMinute, 30)); CHECK_EQ(blob.writes, 1u);
    DeviceSettingsStore again(blob);                                                         // the next boot
    CHECK(again.load() == choices(GuardCycle::EveryMinute, 30)); CHECK(again.state() == SettingsStore::Restored);
    // A failed write: SAVE FAILED, the previous value stays in effect.
    blob.fail_write = true;
    CHECK(!again.save(choices(GuardCycle::Always, 100))); CHECK(again.state() == SettingsStore::Failed);
    CHECK(again.current() == choices(GuardCycle::EveryMinute, 30));
    blob.fail_write = false;
    CHECK(!again.save(choices(GuardCycle::Always, 55))); CHECK(again.state() == SettingsStore::Failed);   // invalid: never written
    CHECK_EQ(blob.writes, 2u); CHECK(again.current() == choices(GuardCycle::EveryMinute, 30));
    // A corrupt record: the defaults, said so, and the record is not erased.
    CHECK_EQ(blob.bytes.size(), settings_record_bytes); if (blob.bytes.size() != settings_record_bytes) return;
    blob.bytes[6] ^= 0x40; const auto stored = blob.bytes;
    DeviceSettingsStore corrupt(blob);
    CHECK(corrupt.load() == DeviceChoices{}); CHECK(corrupt.state() == SettingsStore::Corrupt);
    CHECK(blob.bytes == stored); CHECK_EQ(blob.writes, 2u);
    // An unreadable or oversized one is corrupt too; a foreign record (another magic) as well.
    blob.fail_read = true; DeviceSettingsStore unreadable(blob);
    CHECK(unreadable.load() == DeviceChoices{}); CHECK(unreadable.state() == SettingsStore::Corrupt);
    blob.fail_read = false; blob.bytes.assign(40, 0x11); DeviceSettingsStore big(blob);
    CHECK(big.load() == DeviceChoices{}); CHECK(big.state() == SettingsStore::Corrupt);
    std::uint8_t rec[settings_record_bytes]; encode_settings(choices(GuardCycle::Every30s, 10), rec, sizeof rec); rec[0] = 'X';
    blob.bytes.assign(rec, rec + sizeof rec); DeviceSettingsStore foreign(blob);
    CHECK(foreign.load() == DeviceChoices{}); CHECK(foreign.state() == SettingsStore::Corrupt);
    // A save after a corrupt boot replaces the record.
    CHECK(foreign.save(choices(GuardCycle::Every30s, 10))); DeviceSettingsStore fixed(blob);
    CHECK(fixed.load() == choices(GuardCycle::Every30s, 10)); CHECK(fixed.state() == SettingsStore::Restored);
    CHECK(std::strcmp(settings_store_text(SettingsStore::Default), "default") == 0);
    CHECK(std::strcmp(settings_store_text(SettingsStore::Restored), "restored") == 0);
    CHECK(std::strcmp(settings_store_text(SettingsStore::Corrupt), "corrupt") == 0);
    CHECK(std::strcmp(settings_store_text(SettingsStore::Saved), "saved") == 0);
    CHECK(std::strcmp(settings_store_text(SettingsStore::Failed), "failed") == 0);
}

GUARDIAN_CASE(hours_table_is_the_measured_spike_and_nothing_else) {
    const auto always = guard_hours(GuardCycle::Always), minute = guard_hours(GuardCycle::EveryMinute), half = guard_hours(GuardCycle::Every30s);
    CHECK(always.measured); CHECK_EQ(unsigned(always.minutes), 125u);            // 2 h 05 min (spike log line 38)
    CHECK(minute.measured); CHECK_EQ(unsigned(minute.minutes), 434u);            // 7 h 14 min (spike log line 43)
    CHECK(!half.measured); CHECK_EQ(unsigned(half.minutes), 0u);                 // never interpolated
    CHECK(std::strstr(always.source, "sticks3-G24-spike-20261121.log:38") != nullptr);
    CHECK(std::strstr(minute.source, "sticks3-G24-spike-20261121.log:43") != nullptr);
    CHECK(std::strstr(half.source, "sticks3-G24-spike-20261121.log:56") != nullptr);   // "Not measured: listen 10 s / off 20 s"
    for (const auto pct : brightness_choices) {
        const auto h = brightness_hours(pct);
        CHECK(!h.measured); CHECK(std::strstr(h.source, "sticks3-G24-spike-20261121.log:56") != nullptr);
        CHECK(brightness_extreme(pct) == Extreme::None);                         // nothing measured: no extreme
    }
    CHECK(!brightness_hours(55).measured);
    CHECK(guard_extreme(GuardCycle::Always) == Extreme::Lowest);
    CHECK(guard_extreme(GuardCycle::EveryMinute) == Extreme::Highest);
    CHECK(guard_extreme(GuardCycle::Every30s) == Extreme::None);
    char t[16];
    CHECK_EQ(hours_text(125, t, sizeof t), std::size_t{6}); CHECK(std::strcmp(t, "2h 05m") == 0);
    CHECK_EQ(hours_text(434, t, sizeof t), std::size_t{6}); CHECK(std::strcmp(t, "7h 14m") == 0);
    CHECK(hours_text(60 * 12 + 3, t, sizeof t) > 0); CHECK(std::strcmp(t, "12h 03m") == 0);
    CHECK_EQ(hours_text(125, t, 6), std::size_t{0}); CHECK_EQ(t[0], '\0');      // never cut
}

GUARDIAN_CASE(status_fragments) {
    CHECK(text_of(settings_status, DeviceChoices{}, SettingsStore::Default) == "settings=guard:always,bright:60,store:default");
    CHECK(text_of(settings_status, choices(GuardCycle::EveryMinute, 100), SettingsStore::Restored) == "settings=guard:every_minute,bright:100,store:restored");
    CHECK(text_of(settings_status, choices(GuardCycle::Every30s, 10), SettingsStore::Failed) == "settings=guard:every_30s,bright:10,store:failed");
    CHECK(text_of(settings_status, DeviceChoices{}, SettingsStore::Corrupt) == "settings=guard:always,bright:60,store:corrupt");
    char small[20]; CHECK_EQ(settings_status(DeviceChoices{}, SettingsStore::Default, small, sizeof small), std::size_t{0}); CHECK_EQ(small[0], '\0');

    CycleStats s; char g[guard_cycle_status_max];
    CHECK(guard_cycle_status(GuardCycle::Always, s, g, sizeof g) > 0);
    CHECK(std::string(g) == "guard_cycle=always,listen_ms=0,off_ms=0,cycles=0,resume_fail=0,relock_ms_avg=0");
    s.stopped(0); s.resumed(50000, true); s.locked(52500); s.stopped(60000); s.resumed(110000, false);
    CHECK(guard_cycle_status(GuardCycle::EveryMinute, s, g, sizeof g) > 0);
    CHECK(std::string(g) == "guard_cycle=every_minute,listen_ms=10000,off_ms=50000,cycles=2,resume_fail=1,relock_ms_avg=2500");
    CHECK(guard_cycle_status(GuardCycle::Every30s, CycleStats{}, g, sizeof g) > 0);
    CHECK(std::string(g) == "guard_cycle=every_30s,listen_ms=10000,off_ms=20000,cycles=0,resume_fail=0,relock_ms_avg=0");
    CHECK_EQ(guard_cycle_status(GuardCycle::Always, s, g, 30), std::size_t{0}); CHECK_EQ(g[0], '\0');

    char p[parts_status_max];
    PartsRead off; off.pwr_cfg = 0x07; off.gpio_out = 0x04; off.ir_oe = 1; off.ir_level = 0; off.codec_0d = 0xFC;   // all off
    CHECK(parts_status(off, p, sizeof p) > 0); CHECK(std::string(p) == "parts=led:0,ir:low,boost5v:0,amp:0,codec:down");
    PartsRead before; before.pwr_cfg = 0x17; before.gpio_out = 0x04; before.ir_oe = 0; before.ir_level = 0; before.codec_0d = 0xFC;   // spike S2 values
    CHECK(parts_status(before, p, sizeof p) > 0); CHECK(std::string(p) == "parts=led:1,ir:?,boost5v:0,amp:0,codec:down");
    PartsRead on; on.pwr_cfg = 0x1F; on.gpio_out = 0x0C; on.ir_oe = 1; on.ir_level = 1; on.codec_0d = 0x00;
    CHECK(parts_status(on, p, sizeof p) > 0); CHECK(std::string(p) == "parts=led:1,ir:?,boost5v:1,amp:1,codec:?");
    CHECK(parts_status(PartsRead{}, p, sizeof p) > 0); CHECK(std::string(p) == "parts=led:?,ir:?,boost5v:?,amp:?,codec:?");   // failed reads
    CHECK_EQ(parts_status(off, p, 20), std::size_t{0}); CHECK_EQ(p[0], '\0');
}

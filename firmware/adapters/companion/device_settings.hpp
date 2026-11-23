#pragma once
#include <cstddef>
#include <cstdint>
#include "blob.hpp"
#include "guardian/guard_cycle.hpp"
#include "guardian/presenter.hpp"

// G24 device settings, SDK-free and host-tested:
//  * the settings the owner sets on the Settings screen (guardian::DeviceChoices: the guard listen
//    cycle on battery, the brightness while lit and, G25, ROUTER CHANGES) in their OWN versioned, CRC-checked
//    blob (never TUNE keys): magic "GSET", format, guard, brightness, router, CRC-32. A corrupt, foreign or absent blob reads the
//    defaults (Always, 60 %) and says so (STATUS settings=...,store:corrupt|default);
//  * the MEASURED battery hours of each choice, one constant table, each entry citing its line of
//    firmware/evidence/sticks3-G24-spike-20261121.log; "highest" / "lowest" are computed over the measured
//    entries only (fewer than two measured: neither). Nothing here is an estimate;
//  * the STATUS fragments settings=, guard_cycle= and parts= (from register reads, never from what the
//    code wrote).
namespace guardian::companion {

// ---- storage ----------------------------------------------------------------------------------------
// G25: format 2 = magic, format, guard, brightness, ROUTER CHANGES, CRC-32. A G24 record (format 1, 12 bytes)
// is still read (decode_settings migrates it: guard and brightness kept, ROUTER CHANGES Amber) and is replaced
// by format 2 at the next save; nothing rewrites it at boot.
constexpr std::size_t settings_record_bytes = 4 + 2 + 1 + 1 + 1 + 4;
// 0: invalid values or no room. decode: only an exact-size record with matching magic, format, CRC and
// valid values; on failure `out` is untouched.
std::size_t encode_settings(const DeviceChoices&, std::uint8_t* out, std::size_t capacity);
bool decode_settings(const std::uint8_t* in, std::size_t size, DeviceChoices& out);

// Where the settings in effect came from: Default (nothing stored), Restored (a valid stored record),
// Corrupt (a stored record that could not be read or used: defaults in effect, the record is kept, never
// silently erased), Saved (the owner's latest save was written), Failed (the latest save was NOT written:
// the previous values stay in effect).
enum class SettingsStore : std::uint8_t { Default, Restored, Corrupt, Saved, Failed };
const char* settings_store_text(SettingsStore);   // "default", "restored", "corrupt", "saved", "failed"

class DeviceSettingsStore {
public:
    explicit DeviceSettingsStore(BlobStorage& storage) : storage_(storage) {}
    const DeviceChoices& load();                   // sets current() and state()
    bool save(const DeviceChoices&);               // false: not written (current() unchanged)
    const DeviceChoices& current() const { return current_; }
    SettingsStore state() const { return state_; }
private:
    BlobStorage& storage_;
    DeviceChoices current_{};
    SettingsStore state_{SettingsStore::Default};
};

// ---- measured hours ---------------------------------------------------------------------------------
// Awake minutes from full to the 20 % floor, MEASURED on the StickS3 (the G24 spike's full drains). An
// entry that was not measured has measured=false and is shown as "not measured yet".
struct Hours {
    bool measured{};
    std::uint16_t minutes{};
    const char* source{""};   // the evidence line the number comes from
};
Hours guard_hours(GuardCycle);
Hours brightness_hours(std::uint8_t pct);
enum class Extreme : std::uint8_t { None, Lowest, Highest };
Extreme guard_extreme(GuardCycle);
Extreme brightness_extreme(std::uint8_t pct);
// "2h 05m" (the Settings screen's hours line); 0 with an empty string when it does not fit.
std::size_t hours_text(std::uint16_t minutes, char* out, std::size_t capacity);

// ---- STATUS fragments (each one space-free token) -----------------------------------------------------
// settings=guard:<always|every_30s|every_minute>,bright:<pct>,store:<default|restored|corrupt|saved|failed>,router:<details|amber|strict>
std::size_t settings_status(const DeviceChoices&, SettingsStore, char* out, std::size_t capacity);
// guard_cycle=<choice>,listen_ms=<n>,off_ms=<n>,cycles=<n>,resume_fail=<n>,relock_ms_avg=<n>
// (Always: listen_ms=0,off_ms=0 = no cycle, the radio listens all the time.)
std::size_t guard_cycle_status(GuardCycle, const CycleStats&, char* out, std::size_t capacity);

// The unused parts as READ back from the hardware (-1 = the read failed):
//   pwr_cfg   PM1 PWR_CFG (0x06): bit 4 = green status LED, bit 3 = 5 V boost (Grove/Hat/IR supply)
//   gpio_out  PM1 GPIO_OUT (0x11): bit 3 = speaker amplifier enable
//   ir_oe, ir_level  the IR TX gate G46: output enabled, level (low and held = off)
//   codec_0d  ES8311 register 0x0D (0xFC after the power-down sequence; no answer = -1)
struct PartsRead {
    int pwr_cfg{-1};
    int gpio_out{-1};
    int ir_oe{-1};
    int ir_level{-1};
    int codec_0d{-1};
};
constexpr std::uint8_t pm1_pwr_cfg_led = 1u << 4, pm1_pwr_cfg_boost5v = 1u << 3, pm1_gpio_out_amp = 1u << 3;
constexpr std::uint8_t es8311_0d_powered_down = 0xFC;
// parts=led:<0|1|?>,ir:<low|?>,boost5v:<0|1|?>,amp:<0|1|?>,codec:<down|?>
std::size_t parts_status(const PartsRead&, char* out, std::size_t capacity);
constexpr std::size_t settings_status_max = 96, guard_cycle_status_max = 128, parts_status_max = 64;   // G25: settings 64 -> 96 (router:)

} // namespace guardian::companion

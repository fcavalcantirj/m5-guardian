#pragma once
#include <cstdint>
#include "guardian/time.hpp"

// G24: the guard listen cycle on battery, as a pure function of time, power source and screen state.
//
// The owner picks one of three choices on the Settings screen (default Always = the behaviour before G24):
//   Always       the radio listens all the time; no other lever is ever applied.
//   Every30s     listen 10 s, off 20 s.
//   EveryMinute  listen 10 s, off 50 s (the G24 spike's mode G, MEASURED about 7 h 14 min from full to the
//                20 % floor against 2 h 05 min always listening: firmware/evidence/sticks3-G24-spike-20261121.log).
// The two cycled choices act ONLY on battery while the screen is Dark. Then every lever is applied together
// (the plan's `levers`: LCD rail cut, IMU in its low-power motion mode, ...) and the radio follows the cycle,
// LISTENING FIRST: from `dark_since` the radio listens listen_ms, is off off_ms, listens again, and so on.
// Light sleep (80 MHz) is allowed only while the radio is off. Anything that lights the screen (dark false),
// USB power (on_battery false) or the Always choice gives the plan of today at once: radio on, no lever,
// no wait for the cycle. While the update poll owns the radio (`updating`: its join and fetch) the radio is
// on and light sleep is off; the poll keeps its own period (nothing here delays or skips it).
//
// What a listen period cannot see is in docs/G23-delivery.md section 11.4: an alert can be up to off_ms late,
// and a short burst that falls entirely inside an off period is not counted.
namespace guardian {

enum class GuardCycle : std::uint8_t { Always, Every30s, EveryMinute };
constexpr std::uint8_t guard_cycle_count = 3;

struct CycleTiming {
    Millis listen_ms{};   // 0 with off_ms 0: no cycle (Always)
    Millis off_ms{};
};
CycleTiming cycle_timing(GuardCycle);
// STATUS / settings token: "always", "every_30s", "every_minute" ("?" for a value outside the enum).
const char* guard_cycle_name(GuardCycle);
// A stored byte back to the enum; false (out untouched) for anything else.
bool guard_cycle_from(std::uint8_t raw, GuardCycle& out);

struct CycleInput {
    GuardCycle choice{GuardCycle::Always};
    bool on_battery{};    // the debounced power source is the battery (USB or unknown: false)
    bool dark{};          // the screen is Dark (backlight off, no frames)
    bool updating{};      // the update poll / an owner update owns the radio right now
    Millis now{};
    Millis dark_since{};  // when the screen went Dark: the cycle's phase origin (listen first)
};
struct CyclePlan {
    bool levers{};        // a cycled choice is armed (battery + Dark): rail cut, IMU low power, ...
    bool radio_on{true};
    bool light_sleep{};   // 80 MHz light sleep allowed: armed, radio off and not updating
    Millis phase_left_ms{};   // time left in the current listen or off period (0 when not armed)
};
CyclePlan guard_cycle_plan(const CycleInput&);

// Counters behind STATUS guard_cycle=...: cycles = off periods that ended with a radio restart; resume_fail =
// lever switches that failed (a radio restart reported by resumed(ok=false), or any other lever reported by
// failed(): the radio stop, the LCD rail, power management); relock_ms_avg = mean time from a restart to the
// first lock on the selected network, over the restarts that relocked.
class CycleStats {
public:
    void stopped(Millis now);              // the radio was stopped for an off period
    void resumed(Millis now, bool ok);     // ... and restarted (ok false: the restart failed)
    void locked(Millis now);               // the survey locked again; counted once per restart
    void failed();                         // another lever failed to switch (radio stop, rail, power management)
    std::uint32_t cycles() const { return cycles_; }
    std::uint32_t resume_fail() const { return resume_fail_; }
    std::uint32_t relocks() const { return relocks_; }
    std::uint32_t relock_ms_avg() const;
    bool waiting_lock() const { return waiting_; }
private:
    bool off_{}, waiting_{};
    Millis resumed_at_{};
    std::uint32_t cycles_{}, resume_fail_{}, relocks_{};
    std::uint64_t relock_sum_ms_{};
};

} // namespace guardian

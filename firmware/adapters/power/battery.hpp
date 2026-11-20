#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include "blob.hpp"
#include "guardian/canvas.hpp"

// G16B honest battery state. SDK-free and host-tested; the StickS3 adapter
// reads the M5PM1 registers and passes the raw values here.
//
// Register source (M5Unified 0.2.21, commit 3eaaf82, MIT, pinned in the store
// third-party/M5Unified; see THIRD_PARTY_NOTICES.md):
//   M5PM1_Class.cpp  REG_VBAT_L 0x22: battery millivolts, 16-bit little endian
//                    (getBatteryVoltage); REG_PWR_SRC 0x04 bit0 = 5V VIN valid,
//                    bit1 = 5V VINOUT valid (getPowerSource); REG_GPIO_IN 0x12.
//   Power_Class.cpp  isCharging(), board_M5StickS3: "PM1_G0 is charging status
//                    input pin, low=charging / high=not charging" (PM1 GPIO0 is
//                    set to plain GPIO input for this board);
//                    getBatteryLevel(): level = (mv - 3300) * 100 / (4150 - 3350),
//                    clamped to 0..100. That is a linear VOLTAGE ESTIMATE, not a
//                    coulomb count; while external power is present the cell
//                    voltage reads high, so the level is marked as such.
namespace guardian::battery {

using companion::BlobRead;
using companion::BlobStorage;

struct Raw {
    bool vbat_ok{};            // the VBAT register read succeeded
    std::uint16_t vbat_mv{};
    bool src_ok{};             // PWR_SRC read succeeded
    std::uint8_t pwr_src{};
    bool gpio_ok{};            // GPIO_IN read succeeded
    std::uint8_t gpio_in{};
    // G16D: VIN 0x24/0x25 (M5PM1_Class::getVBUSVoltage, mV little endian), the
    // owner's "never sleep on USB" evidence (VBUS > 4000 mV); see power/idle.hpp.
    bool vin_ok{};
    std::uint16_t vin_mv{};
};

enum class Charging : std::uint8_t { Unknown, No, Yes };
const char* charging_text(Charging);   // "unknown" / "no" / "yes"

struct State {
    bool known{};              // a plausible battery voltage is available
    std::uint16_t mv{};        // filtered cell voltage (0 when unknown)
    int level{-1};             // 0..100 voltage estimate, -1 unknown
    bool external{};           // 5V input present (USB)
    Charging charging{Charging::Unknown};
    bool low{};                // on battery and at/below low_mv (warning)
    bool critical{};           // on battery and at/below critical_mv
};

constexpr std::uint16_t full_mv = 4150, empty_mv = 3300, span_mv = 4150 - 3350;   // vendor formula constants
constexpr std::uint16_t low_mv = 3450;       // warning on the screen
constexpr std::uint16_t critical_mv = 3350;  // "charge now"
constexpr std::uint16_t plausible_min_mv = 2500, plausible_max_mv = 4500;   // outside: no battery / bad read

int level_from_mv(std::uint16_t mv);   // the vendor formula, clamped

// Moving average of the last `window` plausible readings, so a single noisy
// read cannot flip the warning; a failed or implausible read never invents a
// level (the previous filtered value ages out after `window` failures).
class Monitor {
public:
    static constexpr std::size_t window = 8;
    State update(const Raw&);
    const State& state() const { return state_; }
private:
    std::uint16_t samples_[window]{};
    std::size_t count_{}, next_{}, misses_{};
    State state_{};
};

// "batt=3987mV/85% charging=yes power=usb" style STATUS fragment.
void status_text(const State&, char* out, std::size_t n);

// Small indicator in the top-right corner the companion layout reserves
// (x >= 108, y <= 10) plus, when low, a full-width warning bar on the bottom
// row (y 231..239, the second hint row). Never changes or hides a rating.
void draw_indicator(Canvas&, const State&);

// ---- runtime log on battery (NVS key "battrun") ----------------------------
// While running on battery the board saves {start mV, minutes on battery,
// last mV} once a minute, so after the stick dies the owner plugs USB in and
// reads BATTRUN: the previous run is kept until a new run on battery starts.
// G16N: the screen state a battery run is in. The cell's voltage drop is accounted per phase, so
// the cost of guarding with the screen on, dimmed or dark is a measured number (BATTRUN).
enum class Phase : std::uint8_t { Active, Dim, Dark, Count };
const char* phase_text(Phase);     // "active" / "dim" / "dark"
struct Drain {
    std::uint32_t seconds{};       // settled time measured in this phase
    std::int32_t drop_mv{};        // cell voltage drop over that time (negative: it rose)
};
// After a phase change the cell voltage steps with the load and the 8-reading average refills:
// the first drain_settle_ms of every stretch are not measured. A rate is reported only after
// drain_min_s of measured time in that phase (a few mV of noise over a minute is not a rate).
constexpr std::uint32_t drain_settle_ms = 30000;
constexpr std::uint32_t drain_min_s = 300;
// G16P: the timer checks of one deep sleep (power::Wake after the wake that ended it). Each check
// that went back to sleep read the cell once, with the display, the radio and the IMU off: the
// same light load at every check, so first_mv - last_mv is the standby drop between those checks.
struct SleepChecks {
    std::uint16_t count{};         // checks that found no USB power and slept again
    std::uint16_t period_s{};      // TUNE power.sleep_check_s that sleep was armed with
    std::uint16_t first_mv{};      // cell voltage at the first and at the last check (0 = not read)
    std::uint16_t last_mv{};
};
// Microvolts the cell fell per check interval and per hour between the first and the last check
// (negative: it rose). False without two checks, a period and both readings. The deep sleep's own
// standby current is in these numbers: the checks' share shows when two runs with different
// power.sleep_check_s are compared by the hour.
bool check_drop(const SleepChecks&, int& uv_per_check, int& uv_per_hour);

// G23 (battery life in dark guard): the drain of each SETTING. A run is cut into segments; a new
// segment starts with the run and whenever one of these values changes while on battery, so one
// BATTRUN read gives the drain per phase of every setting tried (A, B, A again: three segments).
// The values are the ones in effect, not the TUNE text: poll_s is the update-poll period the board
// runs on battery (0 = off), dark_mhz the CPU frequency it applies while dark (160 when the image
// cannot change it), dim_pct the backlight percent while dimmed.
struct Settings {
    std::uint16_t poll_s{};
    std::uint16_t dark_mhz{};
    std::uint8_t dim_pct{};
};
bool same(const Settings&, const Settings&);
struct Segment {
    std::uint16_t number{};        // 1, 2, ... within the run (0 = unused slot)
    Settings settings{};
    std::uint16_t start_mv{};      // the cell voltage when the segment began
    std::array<Drain, static_cast<std::size_t>(Phase::Count)> drain{};   // measured like Run::drain
};
constexpr std::size_t max_segments = 4;   // the latest four are kept (Run::segments_started counts them all)

struct Run {
    std::uint32_t boot{};          // boot count of the run
    std::uint16_t start_mv{};
    std::uint16_t last_mv{};
    std::uint32_t minutes{};       // awake on battery (active_s / 60)
    bool ended_on_usb{};           // external power came back before the end
    // G16D: a run continues across deep-sleep wakes (format 2).
    std::uint32_t active_s{};      // awake on battery, summed over the run's boots
    std::uint32_t asleep_s{};      // deep sleep, summed (from the RTC sleep record)
    std::uint16_t sleeps{};        // deep sleeps the run woke from
    std::uint16_t sleep_mv{};      // cell voltage just before the latest deep sleep
    std::uint16_t wake_mv{};       // first reading after the latest wake (standby drop = sleep_mv - wake_mv)
    bool slept{};                  // the latest record was written going into deep sleep
    // G16N (format 3): per-phase drain of the whole run (kept across deep sleeps).
    std::array<Drain, static_cast<std::size_t>(Phase::Count)> drain{};
    // G16P (format 4): the deep sleep's timer checks.
    std::uint32_t checks{};        // over the whole run
    SleepChecks last_checks{};     // of the latest deep sleep the run woke from
    // G23 (format 5): the drain per setting. Segment n lives in segments[(n - 1) % max_segments].
    std::uint16_t segments_started{};
    std::array<Segment, max_segments> segments{};
};
// Format 5 (G23 segments); decode() also reads the G16P format 4 (73 bytes), the G16N format 3 (61 bytes), the G16D format 2 (37 bytes)
// and the G16B format 1 (23 bytes) so a run recorded before an update is never lost.
constexpr std::size_t run_bytes_v2 = 4 + 2 + 4 + 2 + 2 + 4 + 1 + 4 + 4 + 2 + 2 + 2 + 4;
constexpr std::size_t run_bytes_v3 = run_bytes_v2 + static_cast<std::size_t>(Phase::Count) * (4 + 4);
constexpr std::size_t run_bytes_v4 = run_bytes_v3 + 4 + 4 * 2;
constexpr std::size_t segment_bytes = 2 + 2 + 2 + 1 + 2 + static_cast<std::size_t>(Phase::Count) * (4 + 4);
constexpr std::size_t run_bytes = run_bytes_v4 + 2 + max_segments * segment_bytes;   // G23 format 5
constexpr std::size_t run_bytes_v1 = 4 + 2 + 4 + 2 + 2 + 4 + 1 + 4;
std::size_t encode(const Run&, std::uint8_t* out, std::size_t capacity);
bool decode(const std::uint8_t* in, std::size_t size, Run& out);

class RunLog {
public:
    explicit RunLog(BlobStorage& storage, std::uint32_t boot) : storage_(storage), boot_(boot) {}
    void load();                                   // the previous run, if any
    // Called about once a second with the current state and uptime. G16N: `phase` is the
    // screen state right now (power::State Active / Dim / Dark), for the per-phase drain.
    // G23: `settings` = the values in effect now (a change while on battery starts a new segment).
    void tick(const State&, std::uint32_t uptime_ms, Phase phase = Phase::Active, const Settings& settings = {});
    // G16D: just before deep sleep (saves the run with sleep_mv, marked slept).
    void sleeping(const State&, std::uint32_t uptime_ms);
    // G16D: at boot after load(), when this boot is a key wake from deep sleep:
    // a run that went to sleep continues (same boot id, start mV and active
    // time) instead of a new one starting; the sleep and its duration count.
    // G16P: `checks` = the timer checks of that sleep (also after a timer wake that found USB power).
    void resume(std::uint32_t asleep_ms, const SleepChecks& checks = {});
    bool has_run() const { return has_; }
    const Run& run() const { return run_; }
    bool active() const { return active_; }
    std::uint32_t saves() const { return saves_; }
    // A stretch of one phase being measured (G16N), for the run and (G23) for the current segment.
    struct Stretch {
        bool open{};
        Phase phase{Phase::Active};
        std::uint32_t start_ms{}, ref_ms{}, last_ms{};
        std::uint16_t ref_mv{};
        Drain base{};
    };
private:
    void store();
    void account(const State&, std::uint32_t uptime_ms, Phase);
    void begin_segment(const State&, const Settings&, std::uint32_t uptime_ms, Phase);   // G23
    Segment* current_segment();
    BlobStorage& storage_;
    std::uint32_t boot_{};
    Run run_{};
    bool has_{}, active_{}, resume_{};
    std::uint32_t base_active_s_{};
    std::uint32_t last_saved_minute_{0xFFFFFFFFu}, saves_{}, start_ms_{};
    Stretch run_stretch_{};        // G16N: the run's per-phase drain
    Stretch seg_stretch_{};        // G23: the current segment's
};
// "BATTRUN boot=.. ... end=running drain_mv_10min=active:31,dim:14,dark:- drain_s=active:900,dim:600,dark:120
//  checks=24 last_checks=12 check_s=300 check_first_mv=3988 check_last_mv=3984 check_drop_uv=364 standby_uv_h=4364
//  segs=3 seg1=poll_s:120,dark_mhz:160,dim_pct:10,start_mv:4100,active:31/900,dim:-/0,dark:60/1200 seg2=... seg3=..."
// G16N: mV the cell fell per 10 minutes in each screen state ("-" until drain_min_s were measured).
// G16P: checks = timer checks over the run; the rest is the latest deep sleep: its checks, their
// period, the cell at the first and the last one, and check_drop() ("-" until it has a number).
// G23: segs = segments started in the run, then each kept segment (oldest first): its setting values,
// the cell at its start, and per phase <mV per 10 min>/<measured seconds> ("-" as for drain_mv_10min).
void run_text(const RunLog&, char* out, std::size_t n);
constexpr std::size_t run_text_max = 1024;   // the board's BATTRUN reply buffer (battery_check proves the longest line fits)

// G16N: mV per 10 minutes the cell fell in `phase` over the run; false until drain_min_s of
// settled time were measured there.
bool drain_rate(const Run&, Phase, int& mv_per_10min);
bool drain_rate(const std::array<Drain, static_cast<std::size_t>(Phase::Count)>&, Phase, int& mv_per_10min);   // G23: a segment's
// The cell voltage of a battery percent by the vendor formula (the inverse of level_from_mv).
std::uint16_t mv_from_level(int percent);
// "dark guard: about N h left": tenths of an hour until the cell reaches the dark floor
// (power.dark_floor_pct) from `mv_now` at the MEASURED Dark rate. False when that rate is not
// measured yet or is not a fall. A voltage estimate (the discharge curve is not a line): "about".
bool dark_hours_left(const Run&, std::uint16_t mv_now, int floor_pct, std::uint16_t& tenths);

} // namespace guardian::battery

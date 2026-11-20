#pragma once
#include <cstddef>
#include <cstdint>

// G16D battery life: Active -> Dim -> deep sleep on battery, button wake.
// G16N guard in the dark: Active -> Dim -> Dark on battery. Dark = the backlight is off and no
// frame is drawn while the radio, the detectors and the IMU keep running; a key, motion or a NEW
// incident lights the screen again. Deep sleep is only the floor (battery percent, TUNE).
// G16P a plugged-in Guardian wakes by itself: deep sleep also arms a TIMER wake (power.sleep_check_s).
// A timer wake reads the PM1 power source before the board touches the display, the radio or the
// IMU: no USB power -> the check is counted in the RTC record and the stick is back in deep sleep
// (timer_check); USB power -> a normal boot. The keys stay the other wake source.
// SDK-free and host-tested (tests/idle_check.cpp); the StickS3 adapter feeds
// it IMU samples, raw key levels, the PM1 power source and the companion's
// state, and executes the sleep sequence through a SleepPort.
//
// Sources (read, cited; nothing here is invented):
//  [IDF] ESP-IDF v5.4 (67c1de1e) docs/en/api-reference/system/sleep_modes.rst:
//        Deep-sleep powers off the CPUs, most RAM and the digital peripherals;
//        "before entering Deep-sleep ... applications must disable Wi-Fi using
//        esp_wifi_stop"; a wakeup restarts the application. On chips other than
//        the ESP32, ext1 can "wake up if any of the selected pins is low
//        (ESP_EXT1_WAKEUP_ANY_LOW)", and ext1 works even with RTC_PERIPH off.
//        docs/en/api-reference/system/system_time.rst: the RTC timer keeps
//        time across deep sleep (any reset except power-on); gettimeofday().
//        G16P, same sleep_modes.rst: "These sources can also be combined so that the
//        chip will wake up when any of the sources are triggered"; Timer: "The RTC
//        controller has a built-in timer which can be used to wake up the chip after
//        a predefined amount of time. Time is specified at microsecond precision"
//        (esp_sleep_enable_timer_wakeup); esp_sleep_get_wakeup_cause() "can be used
//        to check which wakeup source has triggered wakeup". components/
//        esp_hw_support/sleep_modes.c: enabling the timer only sets RTC_TIMER_TRIG_EN
//        and the duration (always ESP_OK); it changes nothing about ext1.
//  [OWNER] ~/dev/m5/sticks3-ai-usage (f2e03c2) firmware/src/hal/sticks3/power.cpp
//        and docs/DEVICES.md, ptt.ino lineage, each write a measured leak fix:
//        ext1 on the keys GPIO11|GPIO12 any-low with pull-up on / pull-down off
//        (ORDER #27: without pulldown_dis the pin wakes instantly); display sleep;
//        LCD rail off (PM1 GPIO2); PA off (PM1 GPIO3); ES8311 low power (I2C 0x18:
//        0x0D<-0xFC, 0x0E<-0x6A, 0x00<-0x00); BMI270 suspend (0x68: 0x7D<-0x00,
//        0x7C<-0x03). NEVER arm the PM1 IRQ wake (PM1 GPIO1 -> ESP GPIO13 conflicts
//        with SDA and hangs PM1 I2C after wake, ORDER #29). NEVER deep-sleep on USB
//        (VBUS > 4000 mV, debounced: 3 consecutive battery readings, any USB
//        reading resets). The owner measured weeks of standby with button wake.
//  Owner decisions for G16D (ledger): dim first, then deep sleep; wake by a key
//  press only (no timer wake, no IMU wake); never sleep on USB, during UPDATE or
//  a TUNE session, while an ALERT is shown, or during onboarding.
//  Owner, G16P (2026-11-18, after plugging a deep-asleep stick into a charger: "have to click
//  button to wake screen. crazy."): the timer wake is added for that one question, "is there USB
//  power now?". Still no IMU wake, and still never the PM1 IRQ line (ORDER #29).
namespace guardian::power {

// ---- power source (USB vs battery), debounced --------------------------------
enum class Source : std::uint8_t { Unknown, Usb, Battery };
const char* source_text(Source);   // "unknown" / "usb" / "battery"

// One PM1 reading: PWR_SRC (0x04, 5V input bits) and VIN (0x24/0x25, mV,
// M5PM1_Class::getVBUSVoltage). Each with its own read result.
struct SourceReading {
    bool src_ok{};
    bool src_external{};       // PWR_SRC says a 5V input is present
    bool vin_ok{};
    std::uint16_t vin_mv{};
};

// Battery only after `battery_samples` consecutive readings in which BOTH
// registers were read and BOTH say no external power. Any USB evidence
// (either register) is Usb at once. Failed reads never count as battery;
// `unknown_after` consecutive failed readings make the source Unknown, which
// is treated like USB (never dims, never sleeps): a false "battery" would cut
// a plugged-in Guardian off, a false "USB" only costs some battery.
class SourceFilter {
public:
    static constexpr std::uint8_t battery_samples = 3;
    static constexpr std::uint8_t unknown_after = 3;
    static constexpr std::uint16_t usb_vin_mv = 4000;
    Source sample(const SourceReading&);
    Source source() const { return source_; }
    std::uint16_t last_vin_mv() const { return vin_mv_; }
private:
    Source source_{Source::Unknown};
    std::uint8_t battery_run_{}, failures_{};
    std::uint16_t vin_mv_{};
};

// ---- IMU activity ---------------------------------------------------------------
// "Moved" when `consecutive` samples in a row exceed either threshold (rotation
// rate above gyro_dps on any axis, or | |acc| - 1 g | above acc_g), so one noisy
// sample on a still table never wakes the screen. Independent of the screen
// axis map (G16C): an unmapped IMU still detects handling.
struct MotionThresholds {
    float gyro_dps{20.0f};     // same defaults as TUNE motion.rest_gyro / motion.rest_acc. 2026-11-18 (device + the nine
    float acc_g{0.15f};        // recorded traces): 4 deg/s / 0.05 g woke the dark screen on sensor noise; 20 / 0.15 stays quiet at rest and still fires on taps, shakes and drops
    std::uint8_t consecutive{4};   // 20 ms at the 200 Hz sample rate
};
class MotionActivity {
public:
    void configure(const MotionThresholds& t) { t_ = t; }
    void sample(const float acc_g[3], const float gyr_dps[3]);
    // True once after motion was seen since the last take().
    bool take();
    std::uint32_t events() const { return events_; }
private:
    MotionThresholds t_{};
    std::uint8_t run_{};
    bool pending_{};
    std::uint32_t events_{};
};

// ---- the idle state machine --------------------------------------------------------
enum class State : std::uint8_t { Active, Dim, Sleep, Dark };   // Dark: G16N (appended, earlier values unchanged)
const char* state_text(State);     // "active" / "dim" / "sleep" / "dark"

// Why the countdown is held (the first applicable reason, for STATUS).
enum class Hold : std::uint8_t { None, Usb, PowerUnknown, Update, Tune, Onboarding, Console, Alert };
const char* hold_text(Hold);       // "none" / "usb" / "power_unknown" / "update" / "tune" / "onboarding" / "console" / "alert"

struct Params {
    std::uint32_t dim_ms{30000};    // TUNE power.dim_s: still this long -> Dim
    std::uint32_t sleep_ms{120000}; // TUNE power.sleep_s: this much more in Dim -> Sleep (only while dark_ms is 0)
    // G16N. TUNE power.dark_s: this much more in Dim -> Dark. 0 = no Dark: Dim -> Sleep after
    // sleep_ms, the G16D behaviour. While it is not 0, sleep_ms is not used.
    std::uint32_t dark_ms{60000};
    // G16N. TUNE power.dark_floor_pct: Dark -> Sleep when the battery percent is known and at or
    // below this. An unknown percent never sleeps (an unknown reading is not "empty").
    std::uint8_t dark_floor_pct{20};
    // G16P. TUNE power.sleep_check_s: the period of the deep sleep's timer wake that looks for USB
    // power (sleep_check_period_s keeps it inside its range). Not used by step().
    std::uint32_t sleep_check_s{300};
};

struct Inputs {
    bool motion{};             // MotionActivity::take()
    bool key{};                // any key is down (raw level)
    bool alert{};              // an ALERT is shown now
    bool update{};             // UPDATE confirmation open or an update running
    bool tune{};               // an owner TUNE session (Wi-Fi) is open
    bool onboarding{};         // welcome pages shown
    bool console{};            // the lab console owns the stick, or a lab tool (EDGE/IMU stream) runs
    Source source{Source::Unknown};
    // G16N: ViewModel::incident_seq. A changed value = a NEW incident report (red or amber), also
    // while an earlier ALERT is still shown: activity, like a key.
    std::uint32_t incident_seq{};
    int batt_pct{-1};          // battery::State::level (0..100 voltage estimate), -1 = unknown
};

// G16N: why the screen came back from Dark (STATUS dark_wakes=key/motion/incident). Hold = a
// hold began (USB plugged in, UPDATE, TUNE session, console); it has no counter in dark_wakes.
enum class DarkWake : std::uint8_t { None, Key, Motion, Incident, Hold };
const char* dark_wake_text(DarkWake);   // "none" / "key" / "motion" / "incident" / "hold"

// Active: normal screens. Dim after dim_ms without motion, a key or a new
// ALERT. Sleep (the board must now enter deep sleep) after sleep_ms more in
// Dim without activity and with no ALERT shown. Motion, a key, a new ALERT or
// any hold returns to Active. Holds (USB or unknown power, UPDATE, TUNE,
// onboarding, lab console) keep it Active and restart the countdown; an ALERT
// that stays shown lets it dim (the dim view keeps the ALERT) but never sleep,
// and the sleep countdown restarts when the ALERT ends.
// G16N (dark_ms > 0, the default): Dim -> Dark after dark_ms more in Dim, with the same ALERT
// rule (a shown ALERT keeps it in Dim, the countdown restarts when the ALERT ends). In Dark the
// board turns the backlight off and draws nothing; step() keeps reading every input. A key,
// motion, a hold or a NEW incident report (incident_seq changed) returns to Active, and that
// counts in every state, so a second incident re-lights a screen that dimmed under the first
// one's banner. Dark -> Sleep ONLY when batt_pct is known and at or below dark_floor_pct.
class Idle {
public:
    explicit Idle(Params p = {}) : p_(p) {}
    void configure(const Params& p) { p_ = p; }
    const Params& params() const { return p_; }
    State step(const Inputs&, std::uint32_t now_ms);
    State state() const { return state_; }
    Hold hold() const { return hold_; }
    std::uint32_t still_ms(std::uint32_t now_ms) const { return now_ms - last_activity_; }
    std::uint32_t dims() const { return dims_; }
    // G16N
    std::uint32_t darks() const { return darks_; }                       // times Dark was entered
    std::uint32_t dark_for_ms(std::uint32_t now_ms) const;               // time in the current Dark (0 when not Dark)
    std::uint32_t dark_total_ms(std::uint32_t now_ms) const;             // all the time spent in Dark, the current one included
    std::uint32_t dark_wakes(DarkWake why) const { return wakes_[static_cast<std::size_t>(why)]; }
    DarkWake last_dark_wake() const { return last_wake_; }
private:
    Params p_{};
    State state_{State::Active};
    Hold hold_{Hold::None};
    bool started_{}, alert_was_{}, held_was_{};
    std::uint32_t last_activity_{}, dim_since_{};
    std::uint32_t dims_{};
    std::uint32_t seq_was_{}, dark_since_{}, dark_total_{}, darks_{};
    std::uint32_t wakes_[5]{};
    DarkWake last_wake_{DarkWake::None};
};

// G16N: what the board does with the panel in each state. Dark never uses display_sleep() (that
// revokes the canvas until reboot): the backlight goes to 0 and no frame is drawn, nothing else.
// For the first dark_notice_ms of a Dark the backlight stays at the dim level and the board shows
// the one-line notice (companion::draw_dark_notice) once.
constexpr std::uint32_t dark_notice_ms = 2000;
struct Glass {
    std::uint8_t backlight_pct{};
    bool frames{};             // the board draws its screens
    bool notice{};             // the "guarding in the dark" line is up
};
Glass glass(State, std::uint32_t dark_for_ms, std::uint8_t active_pct, std::uint8_t dim_pct);
// The key press that brightened Dim or lit Dark is swallowed by the WakeGuard, never a UI action.
bool wake_press(State before, State after, bool key);

// ---- G23: the CPU frequency while dark -------------------------------------------------
// TUNE power.dark_cpu_mhz. The CPU runs at cpu_default_mhz (CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ) in every
// state; while Dark it runs at the TUNE value. Only an image built with CONFIG_GUARDIAN_DARK_CPU
// applies it (esp_pm_configure needs CONFIG_PM_ENABLE and returns ESP_ERR_NOT_SUPPORTED without it,
// ESP-IDF v5.4 components/esp_pm/pm_impl.c); the normal image keeps 160 MHz and says so in STATUS.
// The Wi-Fi driver's own lock (ESP_PM_APB_FREQ_MAX, components/esp_wifi/src/wifi_init.c) keeps the
// modem clock at 80 MHz, so 80 is the floor offered here.
constexpr std::uint16_t cpu_default_mhz = 160;
// Any stored value -> the nearest of 80 / 160 / 240 MHz (a tie, or not a number: 160).
std::uint16_t dark_cpu_mhz(float tune_value);
// The frequency for a state: Dark -> dark_mhz, every other state -> cpu_default_mhz.
std::uint16_t cpu_mhz(State, std::uint16_t dark_mhz);

// ---- the wake-press guard ---------------------------------------------------------
// The press that woke the Guardian from deep sleep, or brightened it from Dim,
// is never a UI action: while armed for a key, that key reads "up" until it has
// been seen released for release_ms in a row (bounce on release cannot leak a
// press). Keys not armed pass through unchanged.
class WakeGuard {
public:
    static constexpr std::uint32_t release_ms = 50;
    // Arms the given keys (after an ext1 wake: both, whatever their level).
    void arm(bool front, bool side, std::uint32_t now_ms);
    // Filters raw levels in place (true = pressed).
    void filter(bool& front, bool& side, std::uint32_t now_ms);
    bool armed() const { return front_.armed || side_.armed; }
    std::uint32_t swallowed() const { return swallowed_; }   // guarded presses seen
private:
    struct K { bool armed{}, up{}, counted{}; std::uint32_t up_since{}; };
    void one(K&, bool& level, std::uint32_t now_ms);
    K front_{}, side_{};
    std::uint32_t swallowed_{};
};

// ---- deep sleep sequence ----------------------------------------------------------
constexpr int key_front_gpio = 11, key_side_gpio = 12;
constexpr std::uint64_t ext1_mask = (1ULL << key_front_gpio) | (1ULL << key_side_gpio);
constexpr std::uint8_t pm1_gpio_lcd_rail = 2, pm1_gpio_pa = 3;
constexpr std::uint8_t es8311_addr = 0x18, bmi270_default_addr = 0x68;
// ES8311 power-down: the owner's measured sequence (reg, value), used at sleep and, since the
// review of 2026-11-17, also at boot (the Guardian never uses audio).
constexpr std::uint8_t es8311_power_down[3][2] = {{0x0D, 0xFC}, {0x0E, 0x6A}, {0x00, 0x00}};

// What the board must do, in order (fakes record the calls in host tests).
class SleepPort {
public:
    virtual ~SleepPort() = default;
    virtual bool radio_off() = 0;                       // esp_wifi_stop (receive already stopped)
    virtual bool imu_stop() = 0;                        // the IMU sampler no longer touches the bus
    virtual bool display_sleep() = 0;                   // backlight 0, panel off and in sleep
    virtual bool pm1_gpio_low(std::uint8_t pin) = 0;    // PM1 GPIO_OUT bit `pin` low
    virtual bool i2c_write(std::uint8_t addr, std::uint8_t reg, std::uint8_t value) = 0;
    virtual bool i2c_present(std::uint8_t addr) = 0;    // address-only probe (ACK), no register access
    virtual bool arm_ext1(std::uint64_t mask) = 0;      // ANY_LOW, pull-up on, pull-down off (clears every other wake source first)
    virtual bool arm_timer(std::uint64_t us) = 0;       // G16P: esp_sleep_enable_timer_wakeup, beside ext1 (so always after arm_ext1)
    virtual void deep_sleep() = 0;                      // esp_deep_sleep_start (no return on the device)
    virtual void restart() = 0;                         // esp_restart
};

// Fault bits of teardown() (one per step), kept across sleep for STATUS.
enum Fault : std::uint32_t {
    FaultRadio = 1u << 0, FaultImuStop = 1u << 1, FaultDisplay = 1u << 2, FaultLcdRail = 1u << 3,
    FaultImuSuspend = 1u << 4, FaultCodec = 1u << 5, FaultPa = 1u << 6, FaultArm = 1u << 7,
    // Review 2026-11-17: information, not a fault. The ES8311 did not answer its address once
    // the LCD rail was off, so there was nothing to power down (no write attempted). The
    // device measured sleep_faults=0x20 on every sleep before this probe existed.
    InfoCodecUnpowered = 1u << 8,
    // G16P: the timer wake could not be armed. The keys still wake it, so it sleeps anyway; a
    // plugged-in charger is then not noticed until a key press, and STATUS says so.
    FaultTimer = 1u << 9,
};
constexpr std::uint32_t FaultMask = 0xFFu | FaultTimer;   // the real fault bits (information bits excluded)

// Radio off, IMU sampler stopped, BMI270 suspend, ES8311 low power (only when it answers its
// address), then display sleep, LCD rail off, PA off, and ext1 armed on both keys (review
// 2026-11-17: I2C writes first, rails after; the codec refused writes after the rail cut). Every step runs even
// if an earlier one failed (a half torn-down Guardian left awake would only
// drain the cell). Returns the fault bits. No PM1 IRQ register is written and
// no IMU wake is armed. G16P: with check_s > 0 the timer wake is armed after ext1 (the board
// passes sleep_check_period_s of TUNE power.sleep_check_s; 0 = keys only, the G16D sequence).
std::uint32_t teardown(SleepPort&, std::uint8_t imu_addr, std::uint32_t check_s = 0);
// Software restart (OTA install, console RESTART). 2026-11-18 (device, MEASURED): esp_restart with the IMU
// sampler mid-transaction left the BMI270 in a state the boot init rejected (imu=init-failed until a hardware
// reset). prepare_restart stops the radio and the sampler, then soft-resets the sensor (CMD 0xB6) so the next
// boot finds it clean; FaultRadio / FaultImuStop / FaultImuSuspend name a failed step. restart() then reboots.
std::uint32_t prepare_restart(SleepPort&, std::uint8_t imu_addr);
void restart(SleepPort&, std::uint8_t imu_addr);
// teardown(), then deep sleep; if ext1 could not be armed nothing could wake
// it, so it restarts instead (an honest cold boot) and never sleeps unarmed.
// `before_sleep(faults)` runs after teardown and before the final call (the
// board records the RTC-retained sleep stats there).
using BeforeSleep = void (*)(std::uint32_t faults, void* ctx);
void enter_deep_sleep(SleepPort&, std::uint8_t imu_addr, BeforeSleep = nullptr, void* ctx = nullptr, std::uint32_t check_s = 0);

// ---- RTC-retained sleep record ------------------------------------------------------
// Lives in RTC slow memory on the board (RTC_DATA_ATTR): survives deep sleep
// and software resets, not a power-on. Garbage on a cold boot is detected by
// magic + CRC and replaced by zeros; nothing in it is Wi-Fi evidence.
enum class WakeCause : std::uint8_t { None, Ext1, Other, Timer };   // None = not a sleep wake (cold boot, reset, OTA reboot); Timer: G16P (appended)
const char* wake_text(WakeCause);   // "none" / "ext1" / "other" / "timer"
enum class WakeKey : std::uint8_t { Unknown, Front, Side, Both };
const char* wake_key_text(WakeKey); // "-" / "front" / "side" / "both"
WakeKey wake_key_from(std::uint64_t ext1_status);   // esp_sleep_get_ext1_wakeup_status()

struct Retained {
    std::uint32_t magic{};
    std::uint32_t sleep_count{};
    std::uint64_t slept_at_us{};       // RTC time when the last sleep started (0: none pending)
    std::uint64_t asleep_total_ms{};
    std::uint32_t last_asleep_ms{};
    std::uint32_t last_faults{};
    // G16P: the timer checks (see timer_check). Counters since power-on, like sleep_count.
    std::uint64_t check_due_us{};        // RTC time at which the armed timer wake is due (0: no timer armed)
    std::uint32_t sleep_checks{};        // checks that found no USB power and went back to sleep
    std::uint32_t check_faults{};        // of those: the PM1 gave no usable reading (it stayed asleep, see timer_check)
    std::uint16_t check_s{};             // the period the current / latest sleep was armed with (0: keys only)
    std::uint16_t sleep_checks_last{};   // checks during the current / latest sleep
    std::uint16_t check_first_mv{};      // cell voltage read at the first and at the latest check of that sleep
    std::uint16_t check_last_mv{};       //   (one raw PM1 reading each, 0 = none)
    std::uint16_t check_awake_ms{};      // the latest check: from the instant its timer was due to the call that sleeps again
    std::uint16_t check_awake_max_ms{};  // the longest one since power-on
    std::uint32_t crc{};
};
constexpr std::uint32_t retained_magic = 0x47534c50u;   // "GSLP"
bool retained_valid(const Retained&);
void retained_seal(Retained&);   // recomputes the CRC

struct Wake {
    WakeCause cause{WakeCause::None};
    WakeKey key{WakeKey::Unknown};
    bool asleep_known{};           // the record had a pending sleep start and the RTC time moved forward
    std::uint32_t asleep_ms{};     // this wake: time spent asleep (G16P: the timer checks in between included)
    // G16P: the timer checks of the sleep this wake ended (for BATTRUN, battery::SleepChecks).
    std::uint16_t checks{};
    std::uint16_t check_s{};
    std::uint16_t check_first_mv{}, check_last_mv{};
};
// At boot: validates (or resets) the record and, after an ext1 wake or (G16P) a timer wake that
// stays up, closes the pending sleep with the time asleep. Returns what STATUS reports.
Wake on_boot(Retained&, WakeCause, WakeKey, std::uint64_t rtc_now_us);
// Just before deep sleep: counts the sleep and stores its start and faults. G16P: `check_s` is
// the timer period teardown() armed (0, or FaultTimer in `faults`: no timer wake is due).
void on_sleep(Retained&, std::uint64_t rtc_now_us, std::uint32_t faults, std::uint32_t check_s = 0);

// ---- G16P: the timer wake that looks for USB power ---------------------------------
// TUNE power.sleep_check_s: seconds between two checks while in deep sleep.
constexpr std::uint32_t sleep_check_min_s = 60, sleep_check_max_s = 3600, sleep_check_default_s = 300;
// Any stored value -> whole seconds inside the range (not a number: the default).
std::uint32_t sleep_check_period_s(float tune_value);
// A check that finds no USB power is asleep again within this, counted from the instant its timer
// was due (the boot before app_main included). The check reads the PM1 once; it reads again (at
// most check_reads_max in all) only after a failed read and only while less than half of the
// budget is used.
constexpr std::uint32_t check_budget_ms = 1000;
constexpr std::uint8_t check_reads_max = 3;
// A cell voltage outside this is not recorded (same limits as battery::plausible_*_mv).
constexpr std::uint16_t check_mv_min = 2500, check_mv_max = 4500;

// All a timer check may touch: the PM1 power registers, the wake sources, the RTC clock. There is
// no display, rail, radio, IMU or codec call to make: those stay exactly as the teardown left them.
class CheckPort {
public:
    virtual ~CheckPort() = default;
    virtual std::uint64_t rtc_now_us() = 0;
    // One reading of PM1 PWR_SRC + VIN (each with its own result) and VBAT (0 = not read).
    virtual void read_power(SourceReading&, std::uint16_t& vbat_mv) = 0;
    virtual bool arm_ext1(std::uint64_t mask) = 0;      // as SleepPort::arm_ext1
    virtual bool arm_timer(std::uint64_t us) = 0;       // as SleepPort::arm_timer
    virtual void deep_sleep() = 0;                      // no return on the device
};
enum class CheckOutcome : std::uint8_t {
    Slept,       // no USB power: counted, both wake sources armed again, deep sleep (host fakes return here)
    Usb,         // USB power: boot normally (on_boot closes the sleep, wake_cause=timer)
    NoRecord,    // no valid record of a pending sleep: boot normally
    Unarmed,     // the keys could not be armed: boot normally (never asleep without the key wake)
};
const char* check_text(CheckOutcome);   // "slept" / "usb" / "no_record" / "unarmed"
struct Check {
    CheckOutcome outcome{CheckOutcome::NoRecord};
    SourceReading reading{};       // the last reading taken (Usb: the board seeds its SourceFilter with it)
    std::uint8_t reads{};
};
// First thing after a TIMER wake. USB evidence in either register (the SourceFilter rule) boots.
// Anything else sleeps again: both registers read and neither shows external power, or (after the
// retries) no usable reading. A failed check stays asleep and is counted in check_faults: a stick
// that boots on a dead PM1 bus holds "power unknown" and never sleeps again (an empty cell), while
// one that stays asleep costs at most one period before the next check, and the keys still wake it.
Check timer_check(CheckPort&, Retained&);

// " power_state=dim power_hold=none power_source=battery vbus_mv=0 still_s=42 dim_s=30 sleep_s=120
//   wake_cause=ext1 wake_key=front asleep_s=120 sleep_count=3 asleep_total_s=360 sleep_faults=0x0 sleep_codec=powered_down wake_swallowed=1
//   dark_s=60 dark_floor_pct=20 darks=2 dark_total_s=840 dark_wakes=1/0/1 dark_last_wake=incident
//   sleep_check_s=300 sleep_checks=41 wake_checks=12 check_faults=0 check_awake_ms=640/655"
// G16N: dark_s / dark_floor_pct are the TUNE values (like dim_s and sleep_s); darks = times Dark
// was entered; dark_total_s = time spent in Dark since boot; dark_wakes = key/motion/incident.
// G16P: sleep_check_s = the TUNE value; sleep_checks / check_faults = RTC-retained counts of the
// timer checks that slept again / could not read the PM1; wake_checks = the checks of the sleep
// this boot woke from; check_awake_ms = latest/longest check (wake_cause=timer|ext1 as before).
void status_text(const Idle&, Source, std::uint16_t vbus_mv, std::uint32_t now_ms, const Wake&, const Retained&,
                 std::uint32_t swallowed, char* out, std::size_t n);

} // namespace guardian::power

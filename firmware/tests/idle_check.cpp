// G16D: battery-life idle state machine, power-source debounce, IMU activity,
// wake-press guard, deep-sleep teardown order against a fake PM1/I2C bus, the
// RTC-retained sleep record and the dim view (host, SDK-free).
#include "check.hpp"
#include "idle.hpp"
#include "companion.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace guardian::power;
namespace companion = guardian::companion;

namespace {
Inputs on_battery() { Inputs in; in.source = Source::Battery; return in; }
// Advances `idle` from `from` to `to` (inclusive) in 100 ms steps with the same inputs.
State run(Idle& idle, const Inputs& in, std::uint32_t from, std::uint32_t to) {
    State s = idle.state();
    for (std::uint32_t t = from; t <= to; t += 100) s = idle.step(in, t);
    return s;
}
// G16N: Dim -> Sleep after sleep_ms is the behaviour with the dark guard off (power.dark_s=0).
Params no_dark(std::uint32_t dim_ms = 30000, std::uint32_t sleep_ms = 120000) { Params p; p.dim_ms = dim_ms; p.sleep_ms = sleep_ms; p.dark_ms = 0; return p; }
// The dark guard on: Dim after dim_ms, Dark after dark_ms more, floor at 20 %.
Params dark(std::uint32_t dim_ms = 1000, std::uint32_t dark_ms = 2000, std::uint32_t sleep_ms = 500) { Params p; p.dim_ms = dim_ms; p.sleep_ms = sleep_ms; p.dark_ms = dark_ms; p.dark_floor_pct = 20; return p; }
Inputs on_battery_at(int pct) { Inputs in = on_battery(); in.batt_pct = pct; return in; }
SourceReading reading(bool external, std::uint16_t vin) { SourceReading r; r.src_ok = r.vin_ok = true; r.src_external = external; r.vin_mv = vin; return r; }

struct FakePort final : SleepPort {
    std::vector<std::string> calls;
    bool fail_radio{}, fail_arm{}, fail_i2c{}, codec_answers{true}, fail_timer{};
    bool radio_off() override { calls.push_back("radio_off"); return !fail_radio; }
    bool imu_stop() override { calls.push_back("imu_stop"); return true; }
    bool display_sleep() override { calls.push_back("display_sleep"); return true; }
    bool pm1_gpio_low(std::uint8_t pin) override { calls.push_back("pm1_gpio" + std::to_string(pin) + "_low"); return true; }
    bool i2c_write(std::uint8_t a, std::uint8_t r, std::uint8_t v) override {
        char t[32]; std::snprintf(t, sizeof t, "i2c %02x %02x=%02x", a, r, v); calls.push_back(t); return !fail_i2c;
    }
    bool i2c_present(std::uint8_t a) override {
        char t[16]; std::snprintf(t, sizeof t, "probe %02x", a); calls.push_back(t); return a != es8311_addr || codec_answers;
    }
    bool arm_ext1(std::uint64_t mask) override { calls.push_back("arm_ext1 " + std::to_string(mask)); return !fail_arm; }
    bool arm_timer(std::uint64_t us) override { calls.push_back("arm_timer " + std::to_string(us)); return !fail_timer; }   // G16P
    void deep_sleep() override { calls.push_back("deep_sleep"); }
    void restart() override { calls.push_back("restart"); }
};
// G16P: all a timer check can reach. The RTC clock advances by `read_cost_us` per PM1 reading;
// the readings are served in order and the last one repeats.
struct FakeCheck final : CheckPort {
    struct Reading { SourceReading source; std::uint16_t vbat_mv; };
    std::vector<std::string> calls;
    std::vector<Reading> readings;
    std::uint64_t now_us{}, read_cost_us{2000}, slept_at_us{};
    std::size_t served{};
    bool fail_arm{}, fail_timer{};
    std::uint64_t rtc_now_us() override { return now_us; }
    void read_power(SourceReading& out, std::uint16_t& vbat_mv) override {
        calls.push_back("read_power"); now_us += read_cost_us;
        const Reading r = readings.empty() ? Reading{} : readings[served < readings.size() ? served : readings.size() - 1];
        ++served; out = r.source; vbat_mv = r.vbat_mv;
    }
    bool arm_ext1(std::uint64_t mask) override { calls.push_back("arm_ext1 " + std::to_string(mask)); return !fail_arm; }
    bool arm_timer(std::uint64_t us) override { calls.push_back("arm_timer " + std::to_string(us)); return !fail_timer; }
    void deep_sleep() override { calls.push_back("deep_sleep"); slept_at_us = now_us; }
};
SourceReading unread() { return SourceReading{}; }   // both PM1 registers failed
// A record with a deep sleep pending since `slept_us`, armed with a timer of `check_s`.
Retained asleep_since(std::uint64_t slept_us, std::uint32_t check_s) {
    Retained r{}; on_boot(r, WakeCause::None, WakeKey::Unknown, 1000);
    on_sleep(r, slept_us, 0, check_s);
    return r;
}
std::uint32_t recorded_faults;
void record(std::uint32_t f, void* ctx) { recorded_faults = f; static_cast<FakePort*>(ctx)->calls.push_back("record"); }
}

// ---- idle state machine --------------------------------------------------------
GUARDIAN_CASE(still_on_battery_dims_after_dim_s_then_sleeps_after_sleep_s_more) {
    Idle idle(no_dark());   // 30 s / 120 s, dark guard off (G16N: the G16D behaviour is power.dark_s=0)
    const auto in = on_battery();
    CHECK_EQ(idle.step(in, 1000), State::Active);
    CHECK_EQ(run(idle, in, 1100, 30900), State::Active);   // 29.9 s still
    CHECK_EQ(idle.step(in, 31000), State::Dim);             // 30 s still
    CHECK_EQ(idle.dims(), 1u);
    CHECK_EQ(run(idle, in, 31100, 150900), State::Dim);     // 119.9 s in Dim
    CHECK_EQ(idle.step(in, 151000), State::Sleep);          // 120 s in Dim
}

GUARDIAN_CASE(timeouts_come_from_tune_params_and_follow_live_changes) {
    Idle idle(no_dark(5000, 10000));
    const auto in = on_battery();
    idle.step(in, 0);
    CHECK_EQ(run(idle, in, 100, 4900), State::Active);
    CHECK_EQ(idle.step(in, 5000), State::Dim);
    idle.configure(no_dark(5000, 2000));                     // TUNE power.sleep_s=2 while dimmed
    CHECK_EQ(run(idle, in, 5100, 6900), State::Dim);
    CHECK_EQ(idle.step(in, 7000), State::Sleep);
}

GUARDIAN_CASE(motion_or_a_key_returns_to_active_and_restarts_the_countdown) {
    Idle idle(Params{1000, 2000});
    auto in = on_battery();
    idle.step(in, 0);
    CHECK_EQ(run(idle, in, 100, 1000), State::Dim);
    auto moved = in; moved.motion = true;
    CHECK_EQ(idle.step(moved, 1500), State::Active);
    CHECK_EQ(run(idle, in, 1600, 2400), State::Active);       // countdown restarted at 1500
    CHECK_EQ(idle.step(in, 2500), State::Dim);
    auto key = in; key.key = true;
    CHECK_EQ(idle.step(key, 2600), State::Active);
    CHECK_EQ(idle.step(key, 3700), State::Active);            // a held key keeps it awake
    CHECK_EQ(run(idle, in, 3800, 4600), State::Active);
    CHECK_EQ(idle.step(in, 4700), State::Dim);
    // motion in Active also restarts the countdown
    Idle b(Params{1000, 2000});
    b.step(in, 0); b.step(in, 900); b.step(moved, 950);
    CHECK_EQ(b.step(in, 1500), State::Active);
    CHECK_EQ(b.step(in, 1950), State::Dim);
}

GUARDIAN_CASE(a_new_alert_wakes_a_shown_alert_may_dim_but_never_sleeps) {
    Idle idle(no_dark(1000, 2000));
    auto in = on_battery();
    idle.step(in, 0);
    CHECK_EQ(run(idle, in, 100, 1000), State::Dim);
    auto alert = in; alert.alert = true;
    CHECK_EQ(idle.step(alert, 1100), State::Active);          // the ALERT onset is activity
    CHECK_EQ(run(idle, alert, 1200, 2000), State::Active);
    CHECK_EQ(idle.step(alert, 2100), State::Dim);             // still shown: dims (view keeps the ALERT)
    CHECK_EQ(run(idle, alert, 2200, 60000), State::Dim);      // never sleeps while shown
    CHECK_EQ(idle.hold(), Hold::Alert);
    CHECK_EQ(run(idle, in, 60100, 61900), State::Dim);        // sleep countdown restarts when it ends
    CHECK_EQ(idle.step(in, 62100), State::Sleep);
}

GUARDIAN_CASE(usb_or_unknown_power_never_dims_or_sleeps) {
    for (const auto src : {Source::Usb, Source::Unknown}) {
        Idle idle(Params{1000, 1000});
        Inputs in; in.source = src;
        CHECK_EQ(run(idle, in, 0, 600000), State::Active);
        CHECK_EQ(idle.hold(), src == Source::Usb ? Hold::Usb : Hold::PowerUnknown);
    }
    // plugging in while dimmed brightens it; unplugging restarts the countdown
    Idle idle(Params{1000, 1000});
    auto bat = on_battery(); Inputs usb; usb.source = Source::Usb;
    idle.step(bat, 0);
    CHECK_EQ(run(idle, bat, 100, 1000), State::Dim);
    CHECK_EQ(idle.step(usb, 1100), State::Active);
    CHECK_EQ(run(idle, usb, 1200, 50000), State::Active);
    CHECK_EQ(run(idle, bat, 50100, 51000), State::Active);
    CHECK_EQ(idle.step(bat, 51100), State::Dim);
}

GUARDIAN_CASE(update_tune_onboarding_and_console_hold_it_active) {
    struct Case { bool Inputs::* field; Hold hold; };
    const Case cases[] = {{&Inputs::update, Hold::Update}, {&Inputs::tune, Hold::Tune},
                          {&Inputs::onboarding, Hold::Onboarding}, {&Inputs::console, Hold::Console}};
    for (const auto& c : cases) {
        Idle idle(Params{1000, 1000});
        auto in = on_battery(); in.*(c.field) = true;
        CHECK_EQ(run(idle, in, 0, 600000), State::Active);
        CHECK_EQ(idle.hold(), c.hold);
        // a hold that starts while dimmed brightens it at once
        Idle d(Params{1000, 1000});
        auto bat = on_battery();
        d.step(bat, 0);
        CHECK_EQ(run(d, bat, 100, 1000), State::Dim);
        CHECK_EQ(d.step(in, 1100), State::Active);
        // and when it ends the full countdown starts again
        CHECK_EQ(run(d, bat, 1200, 2000), State::Active);
        CHECK_EQ(d.step(bat, 2200), State::Dim);
    }
    Idle idle; auto in = on_battery();
    CHECK_EQ(idle.step(in, 0), State::Active); CHECK_EQ(idle.hold(), Hold::None);
}

GUARDIAN_CASE(after_sleep_was_decided_activity_returns_to_active) {
    Idle idle(no_dark(1000, 1000));
    auto in = on_battery();
    idle.step(in, 0);
    run(idle, in, 100, 1000);
    CHECK_EQ(idle.step(in, 2000), State::Sleep);
    auto key = in; key.key = true;   // a key during the "sleeping" message cancels it
    CHECK_EQ(idle.step(key, 2100), State::Active);
    CHECK_EQ(run(idle, in, 2200, 3000), State::Active);
}

GUARDIAN_CASE(state_and_hold_texts) {
    CHECK_EQ(std::string(state_text(State::Active)), std::string("active"));
    CHECK_EQ(std::string(state_text(State::Dim)), std::string("dim"));
    CHECK_EQ(std::string(state_text(State::Sleep)), std::string("sleep"));
    CHECK_EQ(std::string(state_text(State::Dark)), std::string("dark"));
    CHECK_EQ(std::string(dark_wake_text(DarkWake::None)), std::string("none"));
    CHECK_EQ(std::string(dark_wake_text(DarkWake::Key)), std::string("key"));
    CHECK_EQ(std::string(dark_wake_text(DarkWake::Motion)), std::string("motion"));
    CHECK_EQ(std::string(dark_wake_text(DarkWake::Incident)), std::string("incident"));
    CHECK_EQ(std::string(dark_wake_text(DarkWake::Hold)), std::string("hold"));
    CHECK_EQ(std::string(hold_text(Hold::PowerUnknown)), std::string("power_unknown"));
    CHECK_EQ(std::string(hold_text(Hold::None)), std::string("none"));
    CHECK_EQ(std::string(source_text(Source::Battery)), std::string("battery"));
}

// ---- power source ---------------------------------------------------------------
GUARDIAN_CASE(battery_needs_three_consecutive_readable_battery_readings) {
    SourceFilter f;
    CHECK_EQ(f.source(), Source::Unknown);
    CHECK_EQ(f.sample(reading(false, 0)), Source::Unknown);
    CHECK_EQ(f.sample(reading(false, 12)), Source::Unknown);
    CHECK_EQ(f.sample(reading(false, 0)), Source::Battery);
    CHECK_EQ(f.sample(reading(false, 5200)), Source::Usb);       // VIN alone is USB evidence
    CHECK_EQ(f.sample(reading(false, 0)), Source::Usb);          // one battery reading is not enough
    CHECK_EQ(f.sample(reading(false, 0)), Source::Usb);
    CHECK_EQ(f.sample(reading(false, 0)), Source::Battery);
    CHECK_EQ(f.sample(reading(true, 0)), Source::Usb);           // PWR_SRC alone is USB evidence
    CHECK_EQ(f.sample(reading(false, 4000)), Source::Usb);       // 4000 mV is not above the threshold ...
    CHECK_EQ(f.sample(reading(false, 4001)), Source::Usb);       // ... and resets the run
    CHECK_EQ(f.last_vin_mv(), 4001);
}

GUARDIAN_CASE(failed_reads_never_count_as_battery_and_persisting_failures_are_unknown) {
    SourceFilter f;
    SourceReading src_fail = reading(false, 0); src_fail.src_ok = false;
    SourceReading vin_fail = reading(false, 0); vin_fail.vin_ok = false;
    f.sample(reading(false, 0)); f.sample(src_fail); f.sample(reading(false, 0));
    CHECK_EQ(f.source(), Source::Unknown);                       // the failed read broke the run
    f.sample(reading(false, 0)); f.sample(reading(false, 0)); f.sample(reading(false, 0));
    CHECK_EQ(f.source(), Source::Battery);
    CHECK_EQ(f.sample(vin_fail), Source::Battery);               // one glitch keeps the settled source
    CHECK_EQ(f.sample(src_fail), Source::Battery);
    CHECK_EQ(f.sample(vin_fail), Source::Unknown);               // three in a row: unknown (no sleep)
    SourceReading usb_partial = reading(true, 0); usb_partial.vin_ok = false;
    CHECK_EQ(f.sample(usb_partial), Source::Usb);                // USB evidence from one register is enough
}

// ---- IMU activity --------------------------------------------------------------
GUARDIAN_CASE(motion_needs_consecutive_samples_over_threshold) {
    MotionActivity m;
    const float still_acc[3] = {0.0f, 0.0f, 1.0f}, still_gyr[3] = {0.5f, -0.3f, 0.2f};
    const float turn_gyr[3] = {0.0f, 40.0f, 0.0f}, bump_acc[3] = {0.0f, 0.5f, 1.2f};   // over the 2026-11-18 defaults (20 deg/s, 0.15 g)
    for (int i = 0; i < 200; ++i) m.sample(still_acc, still_gyr);
    CHECK(!m.take());
    for (int i = 0; i < 3; ++i) m.sample(still_acc, turn_gyr);   // three noisy samples: not motion
    m.sample(still_acc, still_gyr);
    CHECK(!m.take());
    for (int i = 0; i < 4; ++i) m.sample(still_acc, turn_gyr);
    CHECK(m.take());
    CHECK(!m.take());                                             // reported once
    m.sample(still_acc, turn_gyr);                               // continued handling keeps reporting
    CHECK(m.take());
    m.sample(still_acc, still_gyr);
    for (int i = 0; i < 4; ++i) m.sample(bump_acc, still_gyr);   // acceleration alone
    CHECK(m.take());
    m.sample(still_acc, still_gyr);
    const float neg_gyr[3] = {-30.0f, 0.0f, 0.0f};
    for (int i = 0; i < 4; ++i) m.sample(still_acc, neg_gyr);    // either sign
    CHECK(m.take());
    CHECK_EQ(m.events(), 3u);                                     // one per onset
    MotionThresholds t; t.gyro_dps = 60.0f; m.configure(t);       // TUNE motion.rest_gyro raised above the turn
    for (int i = 0; i < 10; ++i) m.sample(still_acc, turn_gyr);
    CHECK(!m.take());
}

// ---- wake-press guard ------------------------------------------------------------
GUARDIAN_CASE(the_wake_press_is_swallowed_until_released) {
    WakeGuard g;
    g.arm(true, true, 0);                       // ext1 wake: both keys guarded
    bool front = true, side = false;
    g.filter(front, side, 0);
    CHECK(!front); CHECK(!side); CHECK(g.armed());
    for (std::uint32_t t = 10; t < 400; t += 10) { front = true; side = false; g.filter(front, side, t); CHECK(!front); }
    // release with bounce: a short down blip inside release_ms is still swallowed
    front = false; side = false; g.filter(front, side, 400);
    front = true; g.filter(front, side, 420); CHECK(!front);
    front = false; g.filter(front, side, 430);
    front = false; side = false; g.filter(front, side, 470); CHECK(g.armed());
    front = false; side = false; g.filter(front, side, 480); CHECK(!g.armed());   // 50 ms released
    front = true; g.filter(front, side, 500); CHECK(front);                       // the next press is real
    CHECK_EQ(g.swallowed(), 1u);
}

GUARDIAN_CASE(a_key_already_released_at_boot_is_not_counted_and_unguarded_keys_pass) {
    WakeGuard g;
    g.arm(true, true, 0);
    bool front = false, side = false;
    for (std::uint32_t t = 0; t <= 60; t += 10) { front = false; side = false; g.filter(front, side, t); }
    CHECK(!g.armed()); CHECK_EQ(g.swallowed(), 0u);
    // brightening from Dim guards only the key that is down
    g.arm(false, true, 100);
    front = true; side = true; g.filter(front, side, 100);
    CHECK(front); CHECK(!side); CHECK_EQ(g.swallowed(), 1u);
}

// ---- software restart (OTA install, console RESTART) --------------------------------
// 2026-11-18 (device, MEASURED): esp_restart with the IMU sampler mid-transaction left the BMI270 in a state
// the boot init rejected (imu=init-failed, motion=no_imu after the OTA reboot; fine after a USB reset).
GUARDIAN_CASE(a_software_restart_stops_the_imu_and_soft_resets_it_before_rebooting) {
    FakePort p;
    restart(p, 0x68);
    const std::vector<std::string> want = {"radio_off", "imu_stop", "i2c 68 7e=b6", "restart"};
    CHECK_EQ(p.calls.size(), want.size());
    for (std::size_t i = 0; i < want.size() && i < p.calls.size(); ++i) CHECK_EQ(p.calls[i], want[i]);
    FakePort q; restart(q, 0);                                   // unknown address: the default one
    CHECK(q.calls.size() == 4 && q.calls[2] == "i2c 68 7e=b6");
    FakePort f; f.fail_i2c = true; CHECK_EQ(prepare_restart(f, 0x69) & FaultImuSuspend, FaultImuSuspend);
}

// ---- deep sleep sequence ----------------------------------------------------------
GUARDIAN_CASE(teardown_runs_in_order_on_the_fake_bus_and_never_touches_the_pm1_irq) {
    FakePort p;
    recorded_faults = 99;
    enter_deep_sleep(p, 0x68, record, &p);
    const std::vector<std::string> want = {
        // Review 2026-11-17 (device): the ES8311 accepted the power-down at boot (codec_boot=down) but
        // refused it after the LCD rail cut (sleep_codec=failed): the I2C power-downs now run first,
        // with every rail still in its normal state, and the rails are cut after them.
        "radio_off", "imu_stop",
        "i2c 68 7d=00", "i2c 68 7c=03",                               // BMI270 suspend
        "probe 18", "i2c 18 0d=fc", "i2c 18 0e=6a", "i2c 18 00=00",   // ES8311 low power (it answered)
        "display_sleep", "pm1_gpio2_low", "pm1_gpio3_low", "arm_ext1 6144", "record", "deep_sleep"};
    CHECK_EQ(p.calls.size(), want.size());
    for (std::size_t i = 0; i < want.size() && i < p.calls.size(); ++i) CHECK_EQ(p.calls[i], want[i]);
    CHECK_EQ(recorded_faults, 0u);
    CHECK_EQ(ext1_mask, (1ULL << 11) | (1ULL << 12));
    for (const auto& c : p.calls) {               // only GPIO2/GPIO3 on the PM1, never 0x6E directly
        CHECK(c.find("pm1_gpio1") == std::string::npos);
        CHECK(c.find("i2c 6e") == std::string::npos);
    }
}

GUARDIAN_CASE(teardown_uses_the_detected_imu_address_and_keeps_going_after_faults) {
    FakePort p; p.fail_radio = true; p.fail_i2c = true;
    recorded_faults = 0;
    enter_deep_sleep(p, 0x69, record, &p);
    CHECK(!p.calls.empty() && p.calls.back() == "deep_sleep");
    CHECK(std::find(p.calls.begin(), p.calls.end(), "i2c 69 7d=00") != p.calls.end());
    CHECK_EQ(recorded_faults, std::uint32_t(FaultRadio | FaultImuSuspend | FaultCodec));
    FakePort q;
    CHECK_EQ(teardown(q, 0) & FaultImuSuspend, 0u);   // unknown address: the BMI270 default
    CHECK(std::find(q.calls.begin(), q.calls.end(), "i2c 68 7d=00") != q.calls.end());
}

// Review 2026-11-17 (device: sleep_faults=0x20 on every sleep): a codec that does not answer
// its address once the LCD rail is off has nothing to power down. That is recorded as
// information, never as a codec fault, and no write is attempted; a codec that answers but
// refuses the writes is still a fault.
GUARDIAN_CASE(an_unpowered_codec_is_information_not_a_fault) {
    FakePort p; p.codec_answers = false;
    const auto f = teardown(p, 0x68);
    CHECK_EQ(f, std::uint32_t(InfoCodecUnpowered));
    CHECK_EQ(f & FaultMask, 0u);
    for (const auto& c : p.calls) CHECK(c.rfind("i2c 18", 0) != 0);   // no write to 0x18
    CHECK(std::find(p.calls.begin(), p.calls.end(), "probe 18") != p.calls.end());
    CHECK(std::find(p.calls.begin(), p.calls.end(), "pm1_gpio3_low") != p.calls.end());   // the rest still runs
    FakePort q; q.fail_i2c = true;                                                         // answers, refuses writes
    CHECK_EQ(teardown(q, 0x68) & (FaultCodec | InfoCodecUnpowered), std::uint32_t(FaultCodec));
}

GUARDIAN_CASE(an_unarmed_wake_restarts_instead_of_sleeping) {
    FakePort p; p.fail_arm = true;
    recorded_faults = 0;
    enter_deep_sleep(p, 0x68, record, &p);
    CHECK(std::find(p.calls.begin(), p.calls.end(), "deep_sleep") == p.calls.end());
    CHECK(!p.calls.empty() && p.calls.back() == "restart");
    CHECK(recorded_faults & FaultArm);
}

// ---- RTC-retained record ------------------------------------------------------------
GUARDIAN_CASE(retained_record_counts_sleeps_and_time_asleep) {
    Retained r;
    std::memset(&r, 0xA5, sizeof r);                  // cold boot: garbage
    auto w = on_boot(r, WakeCause::None, WakeKey::Unknown, 5'000'000);
    CHECK(retained_valid(r)); CHECK_EQ(r.sleep_count, 0u); CHECK(!w.asleep_known);
    on_sleep(r, 10'000'000, 0);
    CHECK_EQ(r.sleep_count, 1u); CHECK(retained_valid(r));
    w = on_boot(r, WakeCause::Ext1, WakeKey::Front, 130'000'000);
    CHECK_EQ(w.cause, WakeCause::Ext1); CHECK_EQ(w.key, WakeKey::Front);
    CHECK(w.asleep_known); CHECK_EQ(w.asleep_ms, 120000u);
    CHECK_EQ(r.last_asleep_ms, 120000u); CHECK_EQ(r.asleep_total_ms, 120000u); CHECK_EQ(r.slept_at_us, 0u);
    on_sleep(r, 200'000'000, FaultCodec);
    w = on_boot(r, WakeCause::Ext1, WakeKey::Side, 260'000'000);
    CHECK_EQ(r.sleep_count, 2u); CHECK_EQ(w.asleep_ms, 60000u); CHECK_EQ(r.asleep_total_ms, 180000u);
    CHECK_EQ(r.last_faults, std::uint32_t(FaultCodec));
    // a software reset without a pending sleep changes nothing; a backwards clock is unknown
    w = on_boot(r, WakeCause::None, WakeKey::Unknown, 300'000'000);
    CHECK(!w.asleep_known); CHECK_EQ(r.sleep_count, 2u);
    on_sleep(r, 400'000'000, 0);
    w = on_boot(r, WakeCause::Ext1, WakeKey::Both, 1000);
    CHECK(!w.asleep_known); CHECK_EQ(r.asleep_total_ms, 180000u); CHECK_EQ(r.slept_at_us, 0u);
    // a corrupted field is detected
    r.sleep_count = 77;
    CHECK(!retained_valid(r));
}

GUARDIAN_CASE(wake_key_and_texts) {
    CHECK_EQ(wake_key_from(1ULL << 11), WakeKey::Front);
    CHECK_EQ(wake_key_from(1ULL << 12), WakeKey::Side);
    CHECK_EQ(wake_key_from(ext1_mask), WakeKey::Both);
    CHECK_EQ(wake_key_from(0), WakeKey::Unknown);
    CHECK_EQ(std::string(wake_text(WakeCause::Ext1)), std::string("ext1"));
    CHECK_EQ(std::string(wake_text(WakeCause::None)), std::string("none"));
    CHECK_EQ(std::string(wake_text(WakeCause::Timer)), std::string("timer"));   // G16P
    CHECK_EQ(std::string(wake_text(WakeCause::Other)), std::string("other"));
    CHECK_EQ(std::string(wake_key_text(WakeKey::Side)), std::string("side"));
}

GUARDIAN_CASE(status_fragment_reports_state_wake_and_counts) {
    Idle idle; auto in = on_battery();
    idle.step(in, 0); idle.step(in, 42000);
    Retained r{}; on_boot(r, WakeCause::None, WakeKey::Unknown, 0);
    on_sleep(r, 1'000'000, FaultCodec);
    const Wake w = on_boot(r, WakeCause::Ext1, WakeKey::Front, 121'000'000);
    char t[640];   // the board's fragment buffer
    status_text(idle, Source::Battery, 0, 42000, w, r, 1, t, sizeof t);
    CHECK_EQ(std::string(t), std::string(" power_state=dim power_hold=none power_source=battery vbus_mv=0 still_s=42 dim_s=30 sleep_s=120"
        " wake_cause=ext1 wake_key=front asleep_s=120 sleep_count=1 asleep_total_s=120 sleep_faults=0x20 sleep_codec=failed wake_swallowed=1"
        " dark_s=60 dark_floor_pct=20 darks=0 dark_total_s=0 dark_wakes=0/0/0 dark_last_wake=none"
        " sleep_check_s=300 sleep_checks=0 wake_checks=0 check_faults=0 check_awake_ms=0/0"));
    // Review 2026-11-17: the information bit never shows as a fault; the codec outcome is named.
    Retained u{}; on_boot(u, WakeCause::None, WakeKey::Unknown, 0);
    on_sleep(u, 1'000'000, InfoCodecUnpowered);
    const Wake wu = on_boot(u, WakeCause::Ext1, WakeKey::Side, 121'000'000);
    status_text(idle, Source::Battery, 0, 42000, wu, u, 0, t, sizeof t);
    CHECK(std::string(t).find(" sleep_faults=0x0 sleep_codec=unpowered ") != std::string::npos);
    Retained ok{}; on_boot(ok, WakeCause::None, WakeKey::Unknown, 0); on_sleep(ok, 1'000'000, 0);
    status_text(idle, Source::Battery, 0, 42000, wu, ok, 0, t, sizeof t);
    CHECK(std::string(t).find(" sleep_faults=0x0 sleep_codec=powered_down ") != std::string::npos);
    Retained never{}; on_boot(never, WakeCause::None, WakeKey::Unknown, 0);
    status_text(idle, Source::Battery, 0, 42000, wu, never, 0, t, sizeof t);
    CHECK(std::string(t).find(" sleep_faults=0x0 sleep_codec=- ") != std::string::npos);
    Wake cold;
    status_text(idle, Source::Usb, 5200, 42000, cold, r, 0, t, sizeof t);
    CHECK(std::string(t).find("wake_cause=none wake_key=- asleep_s=- ") != std::string::npos);
    // G16N: the dark state, its TUNE values, the time spent dark and why it was left, by cause.
    Idle d(dark(1000, 2000)); auto bat = on_battery_at(80);
    d.step(bat, 0);
    CHECK_EQ(run(d, bat, 100, 3000), State::Dark);                // dark from t = 3000
    auto key = bat; key.key = true;
    CHECK_EQ(d.step(key, 13000), State::Active);                  // 10 s dark, left by a key
    CHECK_EQ(run(d, bat, 13100, 16000), State::Dark);             // dark again from t = 16000
    status_text(d, Source::Battery, 0, 21000, cold, never, 0, t, sizeof t);
    CHECK(std::string(t).find(" power_state=dark power_hold=none ") != std::string::npos);
    CHECK(std::string(t).find(" dark_s=2 dark_floor_pct=20 darks=2 dark_total_s=15 dark_wakes=1/0/0 dark_last_wake=key") != std::string::npos);
    CHECK(std::strlen(t) < 440);                                   // an everyday line (the longest possible one is checked below)
    // G16P: the timer checks of the sleep this boot woke from, the retained counts and the measured check time.
    Retained c = asleep_since(10'000'000, 120);
    FakeCheck port; port.readings = {{reading(false, 0), 3990}};
    for (int i = 0; i < 3; ++i) { port.now_us = c.check_due_us + 640'000; CHECK_EQ(timer_check(port, c).outcome, CheckOutcome::Slept); }
    const Wake wt = on_boot(c, WakeCause::Timer, WakeKey::Unknown, c.check_due_us + 600'000);
    Params tuned; tuned.sleep_check_s = 120; Idle ti(tuned); ti.step(on_battery(), 0);
    status_text(ti, Source::Usb, 5100, 1000, wt, c, 0, t, sizeof t);
    CHECK(std::string(t).find(" wake_cause=timer wake_key=- asleep_s=482 sleep_count=1 ") != std::string::npos);
    CHECK(std::string(t).find(" sleep_check_s=120 sleep_checks=3 wake_checks=3 check_faults=0 check_awake_ms=642/642") != std::string::npos);
    // The longest line the fields allow (largest TUNE values and counters; the dark counters cannot reach ten
    // digits each in a boot, 40 more characters if they did) leaves the board room for the 90 characters it
    // appends (dark_wake_evidence_ms, dark_wake_frame_ms, wake_check) in its 640-byte fragment buffer.
    Retained big = c; big.sleep_count = big.sleep_checks = big.check_faults = 0xFFFFFFFFu; big.asleep_total_ms = ~0ull; big.last_faults = FaultMask;
    big.check_awake_ms = big.check_awake_max_ms = 0xFFFF;
    Wake wb = wt; wb.asleep_ms = 0xFFFFFFFFu; wb.checks = 0xFFFF;
    Params widest; widest.dim_ms = 600000; widest.sleep_ms = 3600000; widest.dark_ms = 3600000; widest.dark_floor_pct = 90; widest.sleep_check_s = 3600;
    Idle wi(widest); wi.step(on_battery(), 0);
    status_text(wi, Source::Battery, 65535, 0xFFFFFFFFu, wb, big, 0xFFFFFFFFu, t, sizeof t);
    CHECK(std::strlen(t) + 40 + 90 < 640);
}

// ---- G16N: guard in the dark ---------------------------------------------------------
// Owner (2026-11-18): "device now has screen pitch black to save battery, BUT it should be
// monitoring, any deauth packets should bring screen UP, alert."
GUARDIAN_CASE(dark_after_dim_on_battery) {
    Idle idle;   // the defaults: dim after 30 s still, dark 60 s later, floor 20 %
    CHECK_EQ(idle.params().dark_ms, 60000u);
    CHECK_EQ(idle.params().dark_floor_pct, 20);
    const auto in = on_battery_at(80);
    CHECK_EQ(idle.step(in, 1000), State::Active);
    CHECK_EQ(idle.step(in, 31000), State::Dim);
    CHECK_EQ(run(idle, in, 31100, 90900), State::Dim);      // 59.9 s in Dim
    CHECK_EQ(idle.darks(), 0u);
    CHECK_EQ(idle.step(in, 91000), State::Dark);            // 60 s in Dim: dark, NOT asleep
    CHECK_EQ(idle.darks(), 1u);
    CHECK_EQ(idle.hold(), Hold::None);
    // The panel in each state: Dark is backlight 0 and no frames, after 2 s of the notice at the dim level.
    const Glass active = glass(State::Active, 0, 60, 10), dim = glass(State::Dim, 0, 60, 10);
    CHECK_EQ(active.backlight_pct, 60); CHECK(active.frames); CHECK(!active.notice);
    CHECK_EQ(dim.backlight_pct, 10); CHECK(dim.frames); CHECK(!dim.notice);
    const Glass notice = glass(State::Dark, 0, 60, 10), still_notice = glass(State::Dark, dark_notice_ms - 1, 60, 10);
    CHECK_EQ(notice.backlight_pct, 10); CHECK(!notice.frames); CHECK(notice.notice);
    CHECK_EQ(still_notice.backlight_pct, 10); CHECK(still_notice.notice);
    const Glass off = glass(State::Dark, dark_notice_ms, 60, 10);
    CHECK_EQ(off.backlight_pct, 0); CHECK(!off.frames); CHECK(!off.notice);
    CHECK_EQ(dark_notice_ms, 2000u);
    const Glass asleep = glass(State::Sleep, 0, 60, 10);    // the "sleeping" message is at full brightness
    CHECK_EQ(asleep.backlight_pct, 60); CHECK(asleep.frames);
    CHECK_EQ(idle.dark_for_ms(91000), 0u);
    CHECK_EQ(idle.dark_for_ms(92500), 1500u);
    // power.dark_s=0 turns it off: Dim -> Sleep after sleep_s, as before G16N.
    Idle off_idle(no_dark(1000, 2000));
    off_idle.step(in, 0);
    CHECK_EQ(run(off_idle, in, 100, 1000), State::Dim);
    CHECK_EQ(run(off_idle, in, 1100, 2900), State::Dim);
    CHECK_EQ(off_idle.step(in, 3000), State::Sleep);
    CHECK_EQ(off_idle.darks(), 0u);
    // A shown ALERT keeps Dim (the dim view keeps the red sign up); the dark countdown restarts when it ends.
    Idle a(dark(1000, 2000));
    auto alert = in; alert.alert = true;
    a.step(in, 0);
    CHECK_EQ(a.step(alert, 100), State::Active);
    CHECK_EQ(a.step(alert, 1100), State::Dim);
    CHECK_EQ(run(a, alert, 1200, 30000), State::Dim);       // never dark while the ALERT shows
    CHECK_EQ(run(a, in, 30100, 31900), State::Dim);
    CHECK_EQ(a.step(in, 32100), State::Dark);               // 2 s after it ended
}

GUARDIAN_CASE(dark_keeps_running_inputs) {
    // Dark is not a sleep: with the battery above the floor it stays Dark for hours, whatever
    // power.sleep_s says, and step() keeps reading every input.
    Idle idle(dark(1000, 2000, 500));                        // sleep_s far below dark_s: still no sleep
    const auto in = on_battery_at(60);
    idle.step(in, 0);
    CHECK_EQ(run(idle, in, 100, 3000), State::Dark);
    CHECK_EQ(run(idle, in, 3100, 3 * 3600 * 1000), State::Dark);          // 3 h
    CHECK_EQ(idle.dark_total_ms(3 * 3600 * 1000), 3u * 3600u * 1000u - 3000u);
    CHECK_EQ(idle.darks(), 1u);
    auto unknown = on_battery(); CHECK_EQ(unknown.batt_pct, -1);          // an unknown percent is never "empty"
    CHECK_EQ(run(idle, unknown, 3 * 3600 * 1000 + 100, 3 * 3600 * 1000 + 60000), State::Dark);
    // Every hold still brightens it at once (USB plugged in, UPDATE, a TUNE session, the console).
    struct Case { bool Inputs::* field; Hold hold; };
    const Case cases[] = {{&Inputs::update, Hold::Update}, {&Inputs::tune, Hold::Tune}, {&Inputs::console, Hold::Console}};
    for (const auto& c : cases) {
        Idle d(dark(1000, 2000)); d.step(in, 0);
        CHECK_EQ(run(d, in, 100, 3000), State::Dark);
        auto held = in; held.*(c.field) = true;
        CHECK_EQ(d.step(held, 5000), State::Active);
        CHECK_EQ(d.hold(), c.hold);
        CHECK_EQ(d.last_dark_wake(), DarkWake::Hold);
        CHECK_EQ(d.dark_wakes(DarkWake::Key) + d.dark_wakes(DarkWake::Motion) + d.dark_wakes(DarkWake::Incident), 0u);
        CHECK_EQ(d.dark_total_ms(9000), 2000u);                           // the clock of the dark time stopped
    }
    Idle u(dark(1000, 2000)); u.step(in, 0);
    CHECK_EQ(run(u, in, 100, 3000), State::Dark);
    Inputs usb; usb.source = Source::Usb; usb.batt_pct = 60;
    CHECK_EQ(u.step(usb, 4000), State::Active);
    CHECK_EQ(u.hold(), Hold::Usb);
    // A TUNE change while dark applies at once (power.dark_s=0 while Dark: back to the sleep rule from Dim).
    Idle t(dark(1000, 2000)); t.step(in, 0);
    CHECK_EQ(run(t, in, 100, 3000), State::Dark);
    t.configure(dark(1000, 5000));
    CHECK_EQ(t.step(in, 3100), State::Dark);                              // a longer power.dark_s does not undo a Dark
    t.configure(no_dark(1000, 2000));                                     // power.dark_s=0: dimmed again, then the sleep rule
    CHECK_EQ(t.step(in, 3200), State::Dim);
    CHECK_EQ(t.dark_total_ms(9000), 200u);
    CHECK_EQ(run(t, in, 3300, 5100), State::Dim);
    CHECK_EQ(t.step(in, 5200), State::Sleep);
}

GUARDIAN_CASE(a_second_incident_relights_from_dark) {
    Idle idle(dark(1000, 2000));
    auto in = on_battery_at(80); in.incident_seq = 7;        // whatever the count was at boot is not news
    CHECK_EQ(idle.step(in, 0), State::Active);
    CHECK_EQ(run(idle, in, 100, 3000), State::Dark);
    // The first incident (an amber one: no ALERT flag at all) lights the screen.
    in.incident_seq = 8;
    CHECK_EQ(idle.step(in, 5000), State::Active);
    CHECK_EQ(idle.dark_wakes(DarkWake::Incident), 1u);
    CHECK_EQ(idle.last_dark_wake(), DarkWake::Incident);
    CHECK_EQ(run(idle, in, 5100, 5900), State::Active);      // the countdown restarted at 5000
    CHECK_EQ(idle.step(in, 6000), State::Dim);
    CHECK_EQ(idle.step(in, 8000), State::Dark);
    // A red one: the ALERT shows, the screen dims under its banner ...
    auto alert = in; alert.alert = true; alert.incident_seq = 9;
    CHECK_EQ(idle.step(alert, 9000), State::Active);
    CHECK_EQ(idle.dark_wakes(DarkWake::Incident), 2u);
    CHECK_EQ(run(idle, alert, 9100, 10000), State::Dim);
    CHECK_EQ(run(idle, alert, 10100, 20000), State::Dim);
    // ... and a SECOND incident while that banner is still up brightens it again (G16D did not:
    // the input was one bool, already true).
    alert.incident_seq = 10;
    CHECK_EQ(idle.step(alert, 20100), State::Active);
    CHECK_EQ(run(idle, alert, 20200, 21000), State::Active);
    CHECK_EQ(idle.step(alert, 21100), State::Dim);
    // The banner ends, the dark countdown runs in full, and a later burst lights it from the dark.
    in.incident_seq = alert.incident_seq;                    // the count stays where it is when a banner expires
    CHECK_EQ(run(idle, in, 21200, 23100), State::Dim);
    CHECK_EQ(idle.step(in, 23300), State::Dark);
    in.incident_seq = 11;
    CHECK_EQ(idle.step(in, 30000), State::Active);
    CHECK_EQ(idle.dark_wakes(DarkWake::Incident), 3u);
    CHECK_EQ(idle.darks(), 3u);
    // The same number again is not news.
    CHECK_EQ(run(idle, in, 30100, 33000), State::Dark);
    CHECK_EQ(run(idle, in, 33100, 60000), State::Dark);
    // With the dark guard off the second incident still brightens a dimmed screen.
    Idle legacy(no_dark(1000, 60000));
    auto l = on_battery_at(80); l.alert = true; l.incident_seq = 1;
    legacy.step(l, 0);
    CHECK_EQ(run(legacy, l, 100, 1000), State::Dim);
    l.incident_seq = 2;
    CHECK_EQ(legacy.step(l, 1500), State::Active);
}

GUARDIAN_CASE(dark_sleeps_at_the_floor) {
    Idle idle(dark(1000, 2000));
    auto in = on_battery_at(21);
    idle.step(in, 0);
    CHECK_EQ(run(idle, in, 100, 3000), State::Dark);
    CHECK_EQ(run(idle, in, 3100, 600000), State::Dark);      // 21 %: above the 20 % floor
    in.batt_pct = 20;
    CHECK_EQ(idle.step(in, 600100), State::Sleep);           // at the floor: deep sleep (keys-only wake)
    CHECK_EQ(idle.dark_total_ms(700000), 597100u);           // the dark time ended with the sleep
    // The owner sets the floor (TUNE power.dark_floor_pct).
    Params p = dark(1000, 2000); p.dark_floor_pct = 50;
    Idle high(p); auto h = on_battery_at(51);
    high.step(h, 0);
    CHECK_EQ(run(high, h, 100, 10000), State::Dark);
    h.batt_pct = 50;
    CHECK_EQ(high.step(h, 10100), State::Sleep);
    // Already under the floor when left alone: dim, dark, then asleep at once (never straight from Dim).
    Idle low(dark(1000, 2000)); auto l = on_battery_at(5);
    low.step(l, 0);
    CHECK_EQ(run(low, l, 100, 1000), State::Dim);
    CHECK_EQ(run(low, l, 1100, 2900), State::Dim);
    CHECK_EQ(low.step(l, 3000), State::Dark);
    CHECK_EQ(low.step(l, 3100), State::Sleep);
    // A key during the "sleeping" message cancels it, as before.
    auto key = l; key.key = true;
    CHECK_EQ(low.step(key, 3200), State::Active);
    // An unknown percent never sleeps; a new incident at the floor still lights the screen first.
    Idle unk(dark(1000, 2000)); auto u = on_battery();
    unk.step(u, 0);
    CHECK_EQ(run(unk, u, 100, 600000), State::Dark);
    Idle inc(dark(1000, 2000)); auto i = on_battery_at(80);
    inc.step(i, 0);
    CHECK_EQ(run(inc, i, 100, 3000), State::Dark);
    i.batt_pct = 10; i.incident_seq = 1;
    CHECK_EQ(inc.step(i, 3100), State::Active);
}

GUARDIAN_CASE(usb_never_darkens) {
    for (const auto src : {Source::Usb, Source::Unknown}) {
        Idle idle(dark(1000, 2000));
        Inputs in; in.source = src; in.batt_pct = 5;         // even "under the floor" (the level reads high or wrong on USB)
        CHECK_EQ(run(idle, in, 0, 3600 * 1000), State::Active);
        CHECK_EQ(idle.darks(), 0u);
        CHECK_EQ(idle.dims(), 0u);
    }
    // Unplugging restarts the whole countdown: dim, then dark.
    Idle idle(dark(1000, 2000));
    Inputs usb; usb.source = Source::Usb; usb.batt_pct = 90;
    const auto bat = on_battery_at(90);
    CHECK_EQ(run(idle, usb, 0, 50000), State::Active);
    CHECK_EQ(run(idle, bat, 50100, 51000), State::Active);
    CHECK_EQ(idle.step(bat, 51100), State::Dim);
    CHECK_EQ(idle.step(bat, 53100), State::Dark);
}

GUARDIAN_CASE(key_and_motion_leave_dark) {
    Idle idle(dark(1000, 2000));
    const auto in = on_battery_at(80);
    idle.step(in, 0);
    CHECK_EQ(run(idle, in, 100, 3000), State::Dark);
    auto key = in; key.key = true;
    CHECK_EQ(idle.step(key, 4000), State::Active);
    CHECK_EQ(idle.dark_wakes(DarkWake::Key), 1u);
    CHECK_EQ(idle.last_dark_wake(), DarkWake::Key);
    // That press only lights the screen: the board arms the WakeGuard for it (as for Dim).
    CHECK(wake_press(State::Dark, State::Active, true));
    CHECK(wake_press(State::Dim, State::Active, true));
    CHECK(!wake_press(State::Dark, State::Active, false));   // lit by motion or an incident: no key to swallow
    CHECK(!wake_press(State::Active, State::Active, true));  // an ordinary press on a bright screen is an action
    CHECK(!wake_press(State::Dark, State::Dark, true));
    WakeGuard g; g.arm(true, false, 4000);
    bool front = true, side = false; g.filter(front, side, 4000);
    CHECK(!front); CHECK_EQ(g.swallowed(), 1u);
    CHECK_EQ(run(idle, in, 4100, 7000), State::Dark);        // released: dim after 1 s, dark 2 s later
    auto moved = in; moved.motion = true;
    CHECK_EQ(idle.step(moved, 8000), State::Active);
    CHECK_EQ(idle.dark_wakes(DarkWake::Motion), 1u);
    CHECK_EQ(idle.dark_wakes(DarkWake::Key), 1u);
    CHECK_EQ(idle.last_dark_wake(), DarkWake::Motion);
    CHECK_EQ(idle.dark_total_ms(8000), 1000u + 1000u);
    CHECK_EQ(run(idle, in, 8100, 11000), State::Dark);
    // An incident together with a key or motion is counted as the incident (the thing to measure).
    auto both = in; both.key = true; both.motion = true; both.incident_seq = 1;
    CHECK_EQ(idle.step(both, 12000), State::Active);
    CHECK_EQ(idle.dark_wakes(DarkWake::Incident), 1u);
    CHECK_EQ(idle.dark_wakes(DarkWake::Key), 1u);
    CHECK_EQ(idle.dark_wakes(DarkWake::Motion), 1u);
}

GUARDIAN_CASE(dark_notice_is_one_grey_sentence_on_black) {
    std::vector<std::uint16_t> px(135 * 240, 0x1234);
    guardian::Canvas c{px.data(), 135, 240, false};
    companion::draw_dark_notice(c);
    int grey = 0, black = 0, other = 0;
    int top = 240, bottom = -1;
    for (int y = 0; y < 240; ++y) for (int x = 0; x < 135; ++x) {
        const auto v = c.get(x, y);
        if (v == guardian::color::grey) { ++grey; top = std::min(top, y); bottom = std::max(bottom, y); }
        else if (v == guardian::color::black) ++black;
        else ++other;
    }
    CHECK_EQ(other, 0);                    // the whole panel is repainted: black and grey only
    CHECK(black > 135 * 240 * 9 / 10);     // dark: almost nothing is lit
    CHECK(grey > 150); CHECK(grey < 900);  // 33 glyphs of the 5x7 font: text, not a block
    CHECK(bottom - top < 24);              // two short rows ("guarding in the dark" / "press to look")
    CHECK(top > 60); CHECK(bottom < 180);  // in the middle of the panel
}

// ---- dim view ---------------------------------------------------------------------
namespace {
struct Panel {
    std::vector<std::uint16_t> px = std::vector<std::uint16_t>(135 * 240);
    guardian::Canvas c{px.data(), 135, 240, false};
};
int count(const guardian::Canvas& c, std::uint16_t col) {
    int n = 0;
    for (int y = 0; y < c.height(); ++y) for (int x = 0; x < c.width(); ++x) n += c.get(x, y) == col;
    return n;
}
}
GUARDIAN_CASE(dim_view_shows_the_rating_glyph_in_its_mood_colour) {
    Panel p; companion::Frame f;
    f.art = companion::FaceArt::Rated; f.face = guardian::Mood::Good; f.face_color = guardian::rgb565(120, 230, 90);
    companion::draw_dim(p.c, f);
    CHECK(count(p.c, f.face_color) > 2000);                    // the glyph block in the mood colour
    CHECK(count(p.c, guardian::color::black) > 135 * 240 / 2);  // mostly dark (low power, low glare)
    CHECK_EQ(count(p.c, guardian::color::red), 0);
}
GUARDIAN_CASE(dim_view_keeps_no_data_and_alert_honest) {
    Panel p; companion::Frame f;
    f.art = companion::FaceArt::NoData; f.face = guardian::Mood::Unknown; f.face_color = guardian::color::grey;
    companion::draw_dim(p.c, f);
    // an empty outline and the words, never a filled rated block
    CHECK(count(p.c, guardian::color::grey) > 0);
    CHECK(count(p.c, guardian::color::grey) < 1500);
    Panel q; companion::Frame a;
    a.art = companion::FaceArt::Alert; a.alert = true; a.face = guardian::Mood::VeryGood; a.face_color = guardian::color::red;
    companion::draw_dim(q.c, a);
    CHECK(count(q.c, guardian::color::red) > 2000);             // the red "!" sign, not a happy face
    // NoData with an alert (no fresh rating) still shows the alert
    Panel r; companion::Frame b;
    b.art = companion::FaceArt::NoData; b.alert = true; b.face_color = guardian::color::red;
    companion::draw_dim(r.c, b);
    CHECK(count(r.c, guardian::color::red) > 100);
}
// Review 2026-11-17 (owner: "medium with a yellow roblox ugly face"): with the portraits on board the
// dim view shows the REAL portrait, still (the backlight is what is dimmed: an LCD's pixels cost no
// power), with the rating word below; never the placeholder block. The block stays only as the
// no-art fallback (tests above).
GUARDIAN_CASE(dim_view_shows_the_still_portrait_when_the_art_is_on_board) {
    std::vector<std::uint8_t> art(companion::persona::art_bytes);
    for (std::size_t i = 0; i < art.size(); i += 2) { art[i] = 0x34; art[i + 1] = 0x12; }   // 0x1234
    companion::persona::ArtSet set;
    for (std::size_t i = 0; i < 5; ++i) { set.rated[i] = art.data(); set.alert[i] = {art.data(), art.data()}; }
    set.no_data = art.data();
    Panel p; companion::Frame f;
    f.persona = true; f.art = companion::FaceArt::Rated; f.face = guardian::Mood::Medium; f.face_color = guardian::rgb565(250, 210, 40);
    companion::draw_dim(p.c, f, &set);
    CHECK(count(p.c, 0x1234) > 135 * 100);                       // the portrait, not a block
    CHECK(count(p.c, f.face_color) > 0);                         // the rating word in its mood colour
    CHECK(count(p.c, f.face_color) < 1500);                      // ... only the word: no filled mood block
    Panel q; companion::draw_dim(q.c, f, &set);
    CHECK(std::equal(p.px.begin(), p.px.end(), q.px.begin()));   // still: the same frame every second
    Panel r; companion::Frame a = f; a.alert = true; a.art = companion::FaceArt::Alert; a.face_color = guardian::color::red;
    companion::draw_dim(r.c, a, &set);
    CHECK(count(r.c, 0x1234) > 135 * 100);                       // the ALERT portrait
    CHECK(count(r.c, guardian::color::red) > 300);               // red edge + "ALERT"
    Panel n; companion::Frame nd; nd.persona = true; nd.art = companion::FaceArt::NoData; nd.face_color = guardian::color::grey;
    companion::draw_dim(n.c, nd, &set);
    CHECK(count(n.c, 0x1234) > 135 * 100);                       // the NoData silhouette
    // A DEMO face never passes for a reading when dimmed: the label says DEMO, in yellow.
    Panel d; companion::Frame demo = f; demo.demo_badge = true;
    companion::draw_dim(d.c, demo, &set);
    CHECK(count(d.c, guardian::color::yellow) > 0);
    CHECK_EQ(count(d.c, f.face_color), 0);                       // not the mood word
    Panel b; companion::Frame noart = f; noart.persona = false;   // art missing on this build: the honest block
    companion::draw_dim(b.c, noart, &set);
    CHECK(count(b.c, f.face_color) > 2000);
}
// Supervisor review (2026-11-17): a nearby (amber) observation stays visible in
// the dim view, never louder than the network ALERT and never instead of it.
GUARDIAN_CASE(dim_view_keeps_a_nearby_observation_amber) {
    Panel p; companion::Frame f;
    f.art = companion::FaceArt::Rated; f.face = guardian::Mood::Good; f.face_color = guardian::rgb565(120, 230, 90);
    f.caution = true;
    companion::draw_dim(p.c, f);
    CHECK(count(p.c, companion::amber) > 100);                  // amber edge + "NEARBY"
    CHECK(count(p.c, f.face_color) > 2000);                     // the rating glyph is still there
    Panel q; companion::Frame a = f; a.alert = true; a.art = companion::FaceArt::Alert; a.face_color = guardian::color::red;
    companion::draw_dim(q.c, a);
    CHECK_EQ(count(q.c, companion::amber), 0);                  // an ALERT is shown alone, in red
    Panel r; companion::Frame plain = f; plain.caution = false;
    companion::draw_dim(r.c, plain);
    CHECK_EQ(count(r.c, companion::amber), 0);
}

// ---- G16P: a plugged-in Guardian wakes by itself ---------------------------------------
// Owner (2026-11-18, after plugging a deep-asleep stick into a charger): "have to click button to
// wake screen. crazy." Deep sleep also arms a timer; a timer wake only asks "is there USB power?".
GUARDIAN_CASE(deep_sleep_arms_the_timer_beside_the_keys) {
    FakePort p;
    recorded_faults = 99;
    enter_deep_sleep(p, 0x68, record, &p, 300);
    const std::vector<std::string> tail = {"pm1_gpio3_low", "arm_ext1 6144", "arm_timer 300000000", "record", "deep_sleep"};
    CHECK(p.calls.size() >= tail.size());
    for (std::size_t i = 0; i < tail.size() && p.calls.size() >= tail.size(); ++i) CHECK_EQ(p.calls[p.calls.size() - tail.size() + i], tail[i]);
    CHECK_EQ(recorded_faults, 0u);
    for (const auto& c : p.calls) CHECK(c.find("pm1_gpio1") == std::string::npos);   // still never the PM1 IRQ line
    // A timer that cannot be armed is a fault on record, never a reason to stay awake: the keys wake it.
    FakePort q; q.fail_timer = true;
    recorded_faults = 0;
    enter_deep_sleep(q, 0x68, record, &q, 300);
    CHECK(!q.calls.empty() && q.calls.back() == "deep_sleep");
    CHECK_EQ(recorded_faults, std::uint32_t(FaultTimer));
    CHECK_EQ(std::uint32_t(FaultTimer) & FaultMask, std::uint32_t(FaultTimer));        // shown in STATUS sleep_faults
    // The record knows when the timer is due, or that none is.
    Retained r{}; on_boot(r, WakeCause::None, WakeKey::Unknown, 1000);
    on_sleep(r, 10'000'000, 0, 300);
    CHECK_EQ(r.check_s, 300); CHECK_EQ(r.check_due_us, 310'000'000u); CHECK(retained_valid(r));
    on_boot(r, WakeCause::Ext1, WakeKey::Front, 20'000'000);
    CHECK_EQ(r.check_due_us, 0u);                                                       // any boot closes it
    on_sleep(r, 30'000'000, FaultTimer, 300);
    CHECK_EQ(r.check_s, 0); CHECK_EQ(r.check_due_us, 0u); CHECK_EQ(r.sleep_count, 2u);
}

GUARDIAN_CASE(timer_wake_with_usb_stays_up_active_with_hold_usb) {
    Retained r = asleep_since(10'000'000, 300);
    FakeCheck port; port.now_us = r.check_due_us + 600'000;        // the app starts 0.6 s after the timer fired
    port.readings = {{reading(true, 5080), 4012}};
    const Retained before = r;
    const Check c = timer_check(port, r);
    CHECK_EQ(c.outcome, CheckOutcome::Usb); CHECK_EQ(c.reads, 1);
    CHECK(port.calls.size() == 1 && port.calls[0] == "read_power");              // nothing armed, no sleep
    CHECK(std::memcmp(&before, &r, sizeof r) == 0);                // the record is left for on_boot
    const Wake w = on_boot(r, WakeCause::Timer, WakeKey::Unknown, port.now_us);
    CHECK_EQ(w.cause, WakeCause::Timer); CHECK_EQ(w.key, WakeKey::Unknown);
    CHECK(w.asleep_known); CHECK_EQ(w.asleep_ms, 300602u);         // the whole sleep, closed like a key wake
    CHECK_EQ(r.sleep_checks, 0u); CHECK_EQ(w.checks, 0); CHECK_EQ(r.slept_at_us, 0u);
    // The reading that decided seeds the board's filter: USB at once, and USB holds the Guardian up.
    SourceFilter f;
    CHECK_EQ(f.sample(c.reading), Source::Usb);
    Idle idle; Inputs in; in.source = f.source();
    CHECK_EQ(idle.step(in, 0), State::Active); CHECK_EQ(idle.hold(), Hold::Usb);
    CHECK_EQ(run(idle, in, 100, 3600 * 1000), State::Active);      // an hour plugged in: never dim, dark or asleep
    CHECK_EQ(idle.hold(), Hold::Usb);
    // VIN alone is USB evidence too (the SourceFilter rule: either register).
    Retained v = asleep_since(10'000'000, 300);
    FakeCheck vin; vin.now_us = v.check_due_us + 600'000; vin.readings = {{reading(false, 4600), 4012}};
    CHECK_EQ(timer_check(vin, v).outcome, CheckOutcome::Usb);
    SourceReading half; half.vin_ok = true; half.vin_mv = 5000;    // PWR_SRC failed, VIN says 5 V
    Retained h = asleep_since(10'000'000, 300);
    FakeCheck hv; hv.now_us = h.check_due_us + 600'000; hv.readings = {{half, 0}};
    CHECK_EQ(timer_check(hv, h).outcome, CheckOutcome::Usb);
}

GUARDIAN_CASE(timer_wake_without_usb_is_counted_and_asleep_again_within_the_budget) {
    Retained r = asleep_since(10'000'000, 300);
    FakeCheck port; port.now_us = r.check_due_us + 640'000;        // boot before app_main: 640 ms
    port.readings = {{reading(false, 0), 3988}};
    const Check c = timer_check(port, r);
    CHECK_EQ(c.outcome, CheckOutcome::Slept); CHECK_EQ(c.reads, 1);
    // Exactly this, in this order: one PM1 reading, the keys, the timer, deep sleep. The port has
    // no display, rail, radio, IMU or codec call: the panel and the rails stay as the teardown left them.
    const std::vector<std::string> want = {"read_power", "arm_ext1 6144", "arm_timer 300000000", "deep_sleep"};
    CHECK_EQ(port.calls.size(), want.size());
    for (std::size_t i = 0; i < want.size() && i < port.calls.size(); ++i) CHECK_EQ(port.calls[i], want[i]);
    CHECK(retained_valid(r));
    CHECK_EQ(r.sleep_checks, 1u); CHECK_EQ(r.sleep_checks_last, 1); CHECK_EQ(r.check_faults, 0u);
    CHECK_EQ(r.check_first_mv, 3988); CHECK_EQ(r.check_last_mv, 3988);
    CHECK_EQ(r.check_awake_ms, 642); CHECK_EQ(r.check_awake_max_ms, 642);
    CHECK(r.check_awake_ms <= check_budget_ms);
    CHECK_EQ(r.sleep_count, 1u); CHECK_EQ(r.slept_at_us, 10'000'000u);        // the same sleep goes on
    CHECK_EQ(r.check_due_us, port.slept_at_us + 300'000'000u);                // the next check
    // The second check, a slower boot, the cell a little lower.
    port.calls.clear(); port.now_us = r.check_due_us + 655'000; port.readings = {{reading(false, 0), 3984}};
    CHECK_EQ(timer_check(port, r).outcome, CheckOutcome::Slept);
    CHECK_EQ(r.sleep_checks, 2u); CHECK_EQ(r.sleep_checks_last, 2);
    CHECK_EQ(r.check_first_mv, 3988); CHECK_EQ(r.check_last_mv, 3984);
    CHECK_EQ(r.check_awake_ms, 657); CHECK_EQ(r.check_awake_max_ms, 657);
    port.now_us = r.check_due_us + 640'000;
    CHECK_EQ(timer_check(port, r).outcome, CheckOutcome::Slept);
    CHECK_EQ(r.check_awake_ms, 642); CHECK_EQ(r.check_awake_max_ms, 657);     // latest / longest
    // A key ends it: one sleep, its whole length, and its three checks for BATTRUN.
    const Wake w = on_boot(r, WakeCause::Ext1, WakeKey::Side, 10'000'000 + 1000'000'000ull);
    CHECK_EQ(w.cause, WakeCause::Ext1); CHECK(w.asleep_known); CHECK_EQ(w.asleep_ms, 1000000u);
    CHECK_EQ(w.checks, 3); CHECK_EQ(w.check_s, 300); CHECK_EQ(w.check_first_mv, 3988); CHECK_EQ(w.check_last_mv, 3984);
    CHECK_EQ(r.sleep_count, 1u); CHECK_EQ(r.sleep_checks, 3u); CHECK_EQ(r.asleep_total_ms, 1000000u);
    // The next sleep starts its own count; the retained total goes on.
    on_sleep(r, 2000'000'000ull, 0, 60);
    CHECK_EQ(r.sleep_checks_last, 0); CHECK_EQ(r.check_first_mv, 0); CHECK_EQ(r.check_last_mv, 0); CHECK_EQ(r.sleep_checks, 3u);
    port.calls.clear(); port.now_us = r.check_due_us + 640'000;
    CHECK_EQ(timer_check(port, r).outcome, CheckOutcome::Slept);
    CHECK(port.calls.size() == 4 && port.calls[2] == "arm_timer 60000000");   // re-armed with this sleep's period
    CHECK_EQ(r.sleep_checks, 4u); CHECK_EQ(r.sleep_checks_last, 1);
    // An implausible cell reading is not recorded; the check itself still counts.
    Retained odd = asleep_since(10'000'000, 300);
    FakeCheck op; op.now_us = odd.check_due_us + 640'000; op.readings = {{reading(false, 0), 0}, {reading(false, 0), 9000}};
    CHECK_EQ(timer_check(op, odd).outcome, CheckOutcome::Slept);
    op.now_us = odd.check_due_us + 640'000;
    CHECK_EQ(timer_check(op, odd).outcome, CheckOutcome::Slept);
    CHECK_EQ(odd.sleep_checks, 2u); CHECK_EQ(odd.check_first_mv, 0); CHECK_EQ(odd.check_last_mv, 0);
}

GUARDIAN_CASE(a_check_that_cannot_read_the_pm1_retries_inside_the_budget_and_stays_asleep) {
    // Slow failing reads (I2C timeouts, 200 ms each) after a 100 ms boot: a second try fits in half
    // the budget, a third does not. It sleeps again inside the budget and the fault is on record.
    Retained r = asleep_since(10'000'000, 300);
    FakeCheck port; port.now_us = r.check_due_us + 100'000; port.read_cost_us = 200'000;
    port.readings = {{unread(), 0}};
    Check c = timer_check(port, r);
    CHECK_EQ(c.outcome, CheckOutcome::Slept); CHECK_EQ(c.reads, 2);
    CHECK(!port.calls.empty() && port.calls.back() == "deep_sleep");
    CHECK_EQ(r.sleep_checks, 1u); CHECK_EQ(r.check_faults, 1u);
    CHECK_EQ(r.check_awake_ms, 500); CHECK(r.check_awake_ms <= check_budget_ms);
    // A boot that already took more than half the budget: the one reading, no retry.
    Retained late = asleep_since(10'000'000, 300);
    FakeCheck lp; lp.now_us = late.check_due_us + 700'000; lp.read_cost_us = 150'000; lp.readings = {{unread(), 0}};
    c = timer_check(lp, late);
    CHECK_EQ(c.outcome, CheckOutcome::Slept); CHECK_EQ(c.reads, 1);
    CHECK_EQ(late.check_awake_ms, 850); CHECK(late.check_awake_ms <= check_budget_ms);
    // Fast failing reads: never more than check_reads_max.
    Retained fast = asleep_since(10'000'000, 300);
    FakeCheck fp; fp.now_us = fast.check_due_us + 100'000; fp.readings = {{unread(), 0}};
    c = timer_check(fp, fast);
    CHECK_EQ(c.outcome, CheckOutcome::Slept); CHECK_EQ(c.reads, check_reads_max); CHECK_EQ(fast.check_faults, 1u);
    // One register alone saying "no external power" is not battery evidence (the SourceFilter rule): retried.
    SourceReading half; half.src_ok = true;
    Retained hr = asleep_since(10'000'000, 300);
    FakeCheck hp; hp.now_us = hr.check_due_us + 100'000; hp.readings = {{half, 3900}};
    c = timer_check(hp, hr);
    CHECK_EQ(c.outcome, CheckOutcome::Slept); CHECK_EQ(c.reads, check_reads_max);
    CHECK_EQ(hr.check_faults, 1u); CHECK_EQ(hr.check_last_mv, 3900);          // the cell reading itself was fine
    // A glitch, then a good reading: one retry settles it, and it is not a fault.
    Retained g = asleep_since(10'000'000, 300);
    FakeCheck gp; gp.now_us = g.check_due_us + 100'000; gp.readings = {{unread(), 0}, {reading(false, 0), 3950}};
    c = timer_check(gp, g);
    CHECK_EQ(c.outcome, CheckOutcome::Slept); CHECK_EQ(c.reads, 2); CHECK_EQ(g.check_faults, 0u); CHECK_EQ(g.check_last_mv, 3950);
    // A glitch, then USB: it boots.
    Retained u = asleep_since(10'000'000, 300);
    FakeCheck up; up.now_us = u.check_due_us + 100'000; up.readings = {{unread(), 0}, {reading(true, 5100), 4100}};
    c = timer_check(up, u);
    CHECK_EQ(c.outcome, CheckOutcome::Usb); CHECK_EQ(c.reads, 2); CHECK_EQ(u.sleep_checks, 0u);
}

GUARDIAN_CASE(a_timer_check_without_a_pending_sleep_or_without_keys_boots_normally) {
    Retained garbage; std::memset(&garbage, 0xA5, sizeof garbage);
    FakeCheck p; p.now_us = 5'000'000; p.readings = {{reading(false, 0), 3900}};
    CHECK_EQ(timer_check(p, garbage).outcome, CheckOutcome::NoRecord);
    CHECK(p.calls.empty());                                         // nothing to go back to: a normal boot decides
    Retained awake{}; on_boot(awake, WakeCause::None, WakeKey::Unknown, 1000);   // valid, no sleep pending
    CHECK_EQ(timer_check(p, awake).outcome, CheckOutcome::NoRecord);
    CHECK(p.calls.empty());
    // The keys cannot be armed: never asleep without the key wake (the G16D rule). It boots; nothing is counted.
    Retained r = asleep_since(10'000'000, 300);
    FakeCheck q; q.fail_arm = true; q.now_us = r.check_due_us + 640'000; q.readings = {{reading(false, 0), 3900}};
    const Retained before = r;
    CHECK_EQ(timer_check(q, r).outcome, CheckOutcome::Unarmed);
    CHECK(std::find(q.calls.begin(), q.calls.end(), "deep_sleep") == q.calls.end());
    CHECK(std::memcmp(&before, &r, sizeof r) == 0);
    // The timer cannot be armed again: it sleeps on the keys alone, and the record says so.
    Retained t = asleep_since(10'000'000, 300);
    FakeCheck tp; tp.fail_timer = true; tp.now_us = t.check_due_us + 640'000; tp.readings = {{reading(false, 0), 3900}};
    CHECK_EQ(timer_check(tp, t).outcome, CheckOutcome::Slept);
    CHECK(!tp.calls.empty() && tp.calls.back() == "deep_sleep");
    CHECK_EQ(t.last_faults & FaultTimer, std::uint32_t(FaultTimer)); CHECK_EQ(t.check_due_us, 0u); CHECK(retained_valid(t));
    // A wake that is not later than the due time (a clock that went backwards): measured from the app start.
    Retained e = asleep_since(10'000'000, 300);
    FakeCheck ep; ep.now_us = e.check_due_us - 5'000'000; ep.readings = {{reading(false, 0), 3900}};
    CHECK_EQ(timer_check(ep, e).outcome, CheckOutcome::Slept);
    CHECK_EQ(e.check_awake_ms, 2);
    CHECK_EQ(std::string(check_text(CheckOutcome::Slept)), std::string("slept"));
    CHECK_EQ(std::string(check_text(CheckOutcome::Usb)), std::string("usb"));
    CHECK_EQ(std::string(check_text(CheckOutcome::NoRecord)), std::string("no_record"));
    CHECK_EQ(std::string(check_text(CheckOutcome::Unarmed)), std::string("unarmed"));
}

GUARDIAN_CASE(the_check_period_stays_inside_its_tune_range) {
    CHECK_EQ(sleep_check_min_s, 60u); CHECK_EQ(sleep_check_max_s, 3600u); CHECK_EQ(sleep_check_default_s, 300u);
    CHECK_EQ(Params{}.sleep_check_s, sleep_check_default_s);
    CHECK_EQ(sleep_check_period_s(300.0f), 300u);
    CHECK_EQ(sleep_check_period_s(60.0f), 60u); CHECK_EQ(sleep_check_period_s(3600.0f), 3600u);
    CHECK_EQ(sleep_check_period_s(0.0f), 60u); CHECK_EQ(sleep_check_period_s(-5.0f), 60u); CHECK_EQ(sleep_check_period_s(59.4f), 60u);
    CHECK_EQ(sleep_check_period_s(99999.0f), 3600u); CHECK_EQ(sleep_check_period_s(1e30f), 3600u);
    CHECK_EQ(sleep_check_period_s(89.6f), 90u);                              // whole seconds, to the nearest
    CHECK_EQ(sleep_check_period_s(std::nanf("")), sleep_check_default_s);    // not a number: the default
    // A record whose period is outside the range (written by other code, or 0) is re-armed inside it.
    Retained r = asleep_since(10'000'000, 300);
    r.check_s = 5; retained_seal(r);
    FakeCheck p; p.now_us = r.check_due_us + 640'000; p.readings = {{reading(false, 0), 3900}};
    CHECK_EQ(timer_check(p, r).outcome, CheckOutcome::Slept);
    CHECK(p.calls.size() == 4 && p.calls[2] == "arm_timer 60000000");
}

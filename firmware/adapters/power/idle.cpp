// G16D idle/sleep policy, G16N guard in the dark, G16P timer-wake USB check (see idle.hpp for the sources and the rules).
#include "idle.hpp"
#include <cinttypes>
#include <cmath>
#include <cstdio>

namespace guardian::power {
namespace {
std::uint32_t crc32_bytes(std::uint32_t c, const std::uint8_t* p, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        c ^= p[i];
        for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return c;
}
std::uint32_t crc_of(const Retained& r) {
    // Field by field, little endian: padding bytes (garbage after a cold boot) never count.
    std::uint8_t b[60]{};
    std::size_t at = 0;
    const auto put = [&](std::uint64_t v, int bytes) { for (int i = 0; i < bytes; ++i) b[at++] = static_cast<std::uint8_t>(v >> (8 * i)); };
    put(r.magic, 4); put(r.sleep_count, 4); put(r.slept_at_us, 8); put(r.asleep_total_ms, 8);
    put(r.last_asleep_ms, 4); put(r.last_faults, 4);
    // G16P (a record sealed by an older image fails this CRC and starts from zero, like a cold boot)
    put(r.check_due_us, 8); put(r.sleep_checks, 4); put(r.check_faults, 4); put(r.check_s, 2); put(r.sleep_checks_last, 2);
    put(r.check_first_mv, 2); put(r.check_last_mv, 2); put(r.check_awake_ms, 2); put(r.check_awake_max_ms, 2);
    return ~crc32_bytes(0xFFFFFFFFu, b, at);
}
// The SourceFilter rule, shared with the G16P timer check: external power in EITHER register.
bool usb_evidence(const SourceReading& r) {
    return (r.src_ok && r.src_external) || (r.vin_ok && r.vin_mv > SourceFilter::usb_vin_mv);
}
std::uint32_t check_period_in_range(std::uint32_t s) {
    return s < sleep_check_min_s ? sleep_check_min_s : s > sleep_check_max_s ? sleep_check_max_s : s;
}
std::uint16_t to_u16(std::uint64_t v) { return v > 0xFFFFu ? std::uint16_t(0xFFFFu) : static_cast<std::uint16_t>(v); }
} // namespace

const char* source_text(Source s) {
    switch (s) {
    case Source::Usb: return "usb";
    case Source::Battery: return "battery";
    case Source::Unknown: break;
    }
    return "unknown";
}

Source SourceFilter::sample(const SourceReading& r) {
    if (r.vin_ok) vin_mv_ = r.vin_mv;
    if (usb_evidence(r)) { source_ = Source::Usb; battery_run_ = 0; failures_ = 0; return source_; }
    if (!r.src_ok || !r.vin_ok) {   // never battery evidence; a lone glitch keeps the settled source
        battery_run_ = 0;
        if (failures_ < 255) ++failures_;
        if (failures_ >= unknown_after) source_ = Source::Unknown;
        return source_;
    }
    failures_ = 0;
    if (battery_run_ < 255) ++battery_run_;
    if (battery_run_ >= battery_samples) source_ = Source::Battery;
    return source_;
}

void MotionActivity::sample(const float acc_g[3], const float gyr_dps[3]) {
    bool over = false;
    for (int i = 0; i < 3; ++i) over |= std::fabs(gyr_dps[i]) > t_.gyro_dps;
    const float mag = std::sqrt(acc_g[0] * acc_g[0] + acc_g[1] * acc_g[1] + acc_g[2] * acc_g[2]);
    over |= std::fabs(mag - 1.0f) > t_.acc_g;
    if (!over) { run_ = 0; return; }
    if (run_ < 255) ++run_;
    if (run_ == t_.consecutive) ++events_;          // one event per onset
    if (run_ >= t_.consecutive) pending_ = true;    // continued handling keeps reporting
}

bool MotionActivity::take() {
    const bool p = pending_;
    pending_ = false;
    return p;
}

const char* state_text(State s) {
    switch (s) {
    case State::Dim: return "dim";
    case State::Sleep: return "sleep";
    case State::Dark: return "dark";
    case State::Active: break;
    }
    return "active";
}

const char* hold_text(Hold h) {
    switch (h) {
    case Hold::Usb: return "usb";
    case Hold::PowerUnknown: return "power_unknown";
    case Hold::Update: return "update";
    case Hold::Tune: return "tune";
    case Hold::Onboarding: return "onboarding";
    case Hold::Console: return "console";
    case Hold::Alert: return "alert";
    case Hold::None: break;
    }
    return "none";
}

State Idle::step(const Inputs& in, std::uint32_t now) {
    if (!started_) { started_ = true; last_activity_ = now; dim_since_ = now; seq_was_ = in.incident_seq; }
    Hold h = Hold::None;
    if (in.source == Source::Usb) h = Hold::Usb;
    else if (in.source != Source::Battery) h = Hold::PowerUnknown;
    else if (in.update) h = Hold::Update;
    else if (in.tune) h = Hold::Tune;
    else if (in.onboarding) h = Hold::Onboarding;
    else if (in.console) h = Hold::Console;
    const bool held = h != Hold::None;
    const bool new_alert = in.alert && !alert_was_;
    const bool alert_ended = !in.alert && alert_was_;
    const bool hold_ended = !held && held_was_;
    // G16N: a changed count is a NEW incident report, also while an earlier ALERT is still shown
    // (the alert flag alone is already true then and cannot say so).
    const bool new_incident = in.incident_seq != seq_was_;
    alert_was_ = in.alert;
    held_was_ = held;
    seq_was_ = in.incident_seq;
    hold_ = held ? h : in.alert ? Hold::Alert : Hold::None;
    if (held || in.motion || in.key || new_alert || new_incident || hold_ended) {
        if (state_ == State::Dark) {   // lit again: why, for STATUS (an incident wins over a key or motion in the same step)
            dark_total_ += now - dark_since_;
            last_wake_ = new_incident || new_alert ? DarkWake::Incident : in.key ? DarkWake::Key
                       : in.motion ? DarkWake::Motion : DarkWake::Hold;
            ++wakes_[static_cast<std::size_t>(last_wake_)];
        }
        last_activity_ = now;
        state_ = State::Active;
        return state_;
    }
    switch (state_) {
    case State::Active:
        if (now - last_activity_ >= p_.dim_ms) { state_ = State::Dim; dim_since_ = now; ++dims_; }
        break;
    case State::Dim:
        if (in.alert || alert_ended) dim_since_ = now;   // never dark or asleep while shown; full countdown after
        else if (p_.dark_ms) {                           // G16N: the screen goes dark, the Guardian keeps guarding
            if (now - dim_since_ >= p_.dark_ms) { state_ = State::Dark; dark_since_ = now; ++darks_; }
        } else if (now - dim_since_ >= p_.sleep_ms) state_ = State::Sleep;
        break;
    case State::Sleep:
        break;   // the board is going to sleep; only activity (above) brings it back
    case State::Dark:
        // Only activity (above) lights it. Deep sleep is the floor: a KNOWN battery percent at or
        // below the owner's limit. power.dark_s set to 0 meanwhile: dimmed again, the G16D rule.
        if (!p_.dark_ms) { dark_total_ += now - dark_since_; state_ = State::Dim; dim_since_ = now; }
        else if (in.batt_pct >= 0 && in.batt_pct <= static_cast<int>(p_.dark_floor_pct)) {
            dark_total_ += now - dark_since_;
            state_ = State::Sleep;
        }
        break;
    }
    return state_;
}

const char* dark_wake_text(DarkWake w) {
    switch (w) {
    case DarkWake::Key: return "key";
    case DarkWake::Motion: return "motion";
    case DarkWake::Incident: return "incident";
    case DarkWake::Hold: return "hold";
    case DarkWake::None: break;
    }
    return "none";
}

std::uint32_t Idle::dark_for_ms(std::uint32_t now) const { return state_ == State::Dark ? now - dark_since_ : 0; }
std::uint32_t Idle::dark_total_ms(std::uint32_t now) const { return dark_total_ + dark_for_ms(now); }

Glass glass(State s, std::uint32_t dark_for_ms, std::uint8_t active_pct, std::uint8_t dim_pct) {
    switch (s) {
    case State::Dim: return {dim_pct, true, false};
    case State::Dark:
        if (dark_for_ms < dark_notice_ms) return {dim_pct, false, true};   // the notice, at the dim level
        return {0, false, false};                                          // backlight off, nothing drawn
    case State::Active:
    case State::Sleep: break;   // Sleep: the "sleeping" message is shown bright before the teardown
    }
    return {active_pct, true, false};
}

bool wake_press(State before, State after, bool key) {
    return key && after == State::Active && (before == State::Dim || before == State::Dark);
}

void WakeGuard::arm(bool front, bool side, std::uint32_t) {
    if (front) front_ = K{true, false, false, 0};
    if (side) side_ = K{true, false, false, 0};
}

void WakeGuard::one(K& k, bool& level, std::uint32_t now) {
    if (!k.armed) return;
    if (level) {
        if (!k.counted) { k.counted = true; ++swallowed_; }
        k.up = false;
        level = false;
        return;
    }
    if (!k.up) { k.up = true; k.up_since = now; }
    if (now - k.up_since >= release_ms) k.armed = false;
}

void WakeGuard::filter(bool& front, bool& side, std::uint32_t now) {
    one(front_, front, now);
    one(side_, side, now);
}

std::uint32_t teardown(SleepPort& p, std::uint8_t imu_addr, std::uint32_t check_s) {
    std::uint32_t f = 0;
    if (!p.radio_off()) f |= FaultRadio;
    if (!p.imu_stop()) f |= FaultImuStop;
    // Review 2026-11-17 (device): the I2C power-downs run before any rail is cut. The ES8311
    // accepted its power-down at boot but refused it after the LCD rail cut (sleep_codec=failed).
    const std::uint8_t imu = imu_addr ? imu_addr : bmi270_default_addr;
    bool ok = p.i2c_write(imu, 0x7D, 0x00);   // BMI270 PWR_CTRL: accel/gyro/temp off
    ok = p.i2c_write(imu, 0x7C, 0x03) && ok;  // PWR_CONF: advanced power save
    if (!ok) f |= FaultImuSuspend;
    if (!p.i2c_present(es8311_addr)) {
        f |= InfoCodecUnpowered;               // nothing powered to put in low power (see idle.hpp)
    } else {
        ok = true;
        for (const auto& rv : es8311_power_down) ok = p.i2c_write(es8311_addr, rv[0], rv[1]) && ok;
        if (!ok) f |= FaultCodec;
    }
    if (!p.display_sleep()) f |= FaultDisplay;
    if (!p.pm1_gpio_low(pm1_gpio_lcd_rail)) f |= FaultLcdRail;
    if (!p.pm1_gpio_low(pm1_gpio_pa)) f |= FaultPa;
    if (!p.arm_ext1(ext1_mask)) f |= FaultArm;
    // G16P: the timer beside the keys, after them (arm_ext1 clears every other wake source first).
    if (check_s && !p.arm_timer(static_cast<std::uint64_t>(check_s) * 1000000u)) f |= FaultTimer;
    return f;
}

std::uint32_t prepare_restart(SleepPort& p, std::uint8_t imu_addr) {
    std::uint32_t f = 0;
    if (!p.radio_off()) f |= FaultRadio;
    if (!p.imu_stop()) f |= FaultImuStop;
    const std::uint8_t imu = imu_addr ? imu_addr : bmi270_default_addr;
    if (!p.i2c_write(imu, 0x7E, 0xB6)) f |= FaultImuSuspend;   // BMI270 CMD soft reset: a clean sensor for the next boot
    return f;
}

void restart(SleepPort& p, std::uint8_t imu_addr) {
    prepare_restart(p, imu_addr);
    p.restart();
}

void enter_deep_sleep(SleepPort& p, std::uint8_t imu_addr, BeforeSleep before, void* ctx, std::uint32_t check_s) {
    const std::uint32_t f = teardown(p, imu_addr, check_s);
    if (before) before(f, ctx);
    if (f & FaultArm) p.restart();   // the keys could not wake it: never sleep unarmed (FaultTimer alone still sleeps)
    else p.deep_sleep();
}

const char* wake_text(WakeCause c) {
    switch (c) {
    case WakeCause::Ext1: return "ext1";
    case WakeCause::Other: return "other";
    case WakeCause::Timer: return "timer";
    case WakeCause::None: break;
    }
    return "none";
}

const char* wake_key_text(WakeKey k) {
    switch (k) {
    case WakeKey::Front: return "front";
    case WakeKey::Side: return "side";
    case WakeKey::Both: return "both";
    case WakeKey::Unknown: break;
    }
    return "-";
}

WakeKey wake_key_from(std::uint64_t status) {
    const bool front = status & (1ULL << key_front_gpio), side = status & (1ULL << key_side_gpio);
    return front && side ? WakeKey::Both : front ? WakeKey::Front : side ? WakeKey::Side : WakeKey::Unknown;
}

bool retained_valid(const Retained& r) { return r.magic == retained_magic && r.crc == crc_of(r); }
void retained_seal(Retained& r) { r.crc = crc_of(r); }

Wake on_boot(Retained& r, WakeCause cause, WakeKey key, std::uint64_t now_us) {
    if (!retained_valid(r)) { r = Retained{}; r.magic = retained_magic; }
    Wake w;
    w.cause = cause;
    w.key = key;
    const bool sleep_wake = cause == WakeCause::Ext1 || cause == WakeCause::Timer;   // G16P: a timer wake that stays up
    if (sleep_wake && r.slept_at_us && now_us > r.slept_at_us) {
        const std::uint64_t ms = (now_us - r.slept_at_us) / 1000;
        w.asleep_known = true;
        w.asleep_ms = ms > 0xFFFFFFFFu ? 0xFFFFFFFFu : static_cast<std::uint32_t>(ms);
        r.last_asleep_ms = w.asleep_ms;
        r.asleep_total_ms += ms;
    }
    if (sleep_wake) {    // G16P: the timer checks of the sleep that just ended
        w.checks = r.sleep_checks_last; w.check_s = r.check_s;
        w.check_first_mv = r.check_first_mv; w.check_last_mv = r.check_last_mv;
    }
    r.slept_at_us = 0;   // any boot closes a pending sleep
    r.check_due_us = 0;  // ... and its timer
    retained_seal(r);
    return w;
}

void on_sleep(Retained& r, std::uint64_t now_us, std::uint32_t faults, std::uint32_t check_s) {
    if (!retained_valid(r)) { r = Retained{}; r.magic = retained_magic; }
    ++r.sleep_count;
    r.slept_at_us = now_us ? now_us : 1;
    r.last_faults = faults;
    // G16P: this sleep's timer (none when it was not asked for or could not be armed) and its own check count.
    if (faults & FaultTimer) check_s = 0;
    r.check_s = to_u16(check_s);
    r.check_due_us = check_s ? r.slept_at_us + static_cast<std::uint64_t>(check_s) * 1000000u : 0;
    r.sleep_checks_last = 0; r.check_first_mv = 0; r.check_last_mv = 0;
    retained_seal(r);
}

std::uint32_t sleep_check_period_s(float v) {
    if (v != v) return sleep_check_default_s;                             // not a number
    if (v <= static_cast<float>(sleep_check_min_s)) return sleep_check_min_s;   // compared as float first: no out-of-range conversion
    if (v >= static_cast<float>(sleep_check_max_s)) return sleep_check_max_s;
    return check_period_in_range(static_cast<std::uint32_t>(std::lround(v)));
}

const char* check_text(CheckOutcome o) {
    switch (o) {
    case CheckOutcome::Slept: return "slept";
    case CheckOutcome::Usb: return "usb";
    case CheckOutcome::Unarmed: return "unarmed";
    case CheckOutcome::NoRecord: break;
    }
    return "no_record";
}

Check timer_check(CheckPort& p, Retained& r) {
    Check c;
    if (!retained_valid(r) || !r.slept_at_us) return c;   // NoRecord: nothing to go back to, the normal boot decides
    const std::uint64_t t0 = p.rtc_now_us();
    // The awake time counts from the instant the timer was due (the boot before app_main included);
    // from the first instruction here when the record has no usable due time.
    const std::uint64_t began = r.check_due_us && t0 >= r.check_due_us ? r.check_due_us : t0;
    bool battery = false;          // both registers read, neither shows external power
    std::uint16_t cell_mv = 0;
    while (c.reads < check_reads_max) {
        std::uint16_t mv = 0;
        c.reading = SourceReading{};
        p.read_power(c.reading, mv);
        ++c.reads;
        if (usb_evidence(c.reading)) { c.outcome = CheckOutcome::Usb; return c; }   // the record is left for on_boot
        if (mv >= check_mv_min && mv <= check_mv_max) cell_mv = mv;
        if (c.reading.src_ok && c.reading.vin_ok) { battery = true; break; }
        if (p.rtc_now_us() - began >= static_cast<std::uint64_t>(check_budget_ms) * 1000u / 2) break;   // no time for another try
    }
    // No USB power (or no usable reading: see idle.hpp). Back to sleep, the keys first.
    if (!p.arm_ext1(ext1_mask)) { c.outcome = CheckOutcome::Unarmed; return c; }
    const std::uint32_t period = check_period_in_range(r.check_s);
    const bool timer = p.arm_timer(static_cast<std::uint64_t>(period) * 1000000u);
    if (r.sleep_checks < 0xFFFFFFFFu) ++r.sleep_checks;
    if (r.sleep_checks_last < 0xFFFFu) ++r.sleep_checks_last;
    if (!battery && r.check_faults < 0xFFFFFFFFu) ++r.check_faults;
    if (cell_mv) { if (!r.check_first_mv) r.check_first_mv = cell_mv; r.check_last_mv = cell_mv; }
    const std::uint64_t t1 = p.rtc_now_us();
    r.check_awake_ms = to_u16(t1 > began ? (t1 - began) / 1000u : 0);
    if (r.check_awake_ms > r.check_awake_max_ms) r.check_awake_max_ms = r.check_awake_ms;
    r.check_s = static_cast<std::uint16_t>(period);
    r.check_due_us = timer ? t1 + static_cast<std::uint64_t>(period) * 1000000u : 0;
    if (!timer) r.last_faults |= FaultTimer;   // asleep on the keys alone from here on; STATUS sleep_faults says so
    retained_seal(r);
    p.deep_sleep();                // no return on the device
    c.outcome = CheckOutcome::Slept;
    return c;
}

void status_text(const Idle& idle, Source src, std::uint16_t vbus_mv, std::uint32_t now_ms, const Wake& w, const Retained& r,
                 std::uint32_t swallowed, char* out, std::size_t n) {
    if (!out || !n) return;
    char asleep[16];
    if (w.asleep_known) std::snprintf(asleep, sizeof asleep, "%u", unsigned(w.asleep_ms / 1000));
    else std::snprintf(asleep, sizeof asleep, "-");
    // Review 2026-11-17: the last sleep's ES8311 step by name (information bits never read as faults).
    const char* codec = !r.sleep_count ? "-" : (r.last_faults & InfoCodecUnpowered) ? "unpowered"
                      : (r.last_faults & FaultCodec) ? "failed" : "powered_down";
    std::snprintf(out, n,
        " power_state=%s power_hold=%s power_source=%s vbus_mv=%u still_s=%u dim_s=%u sleep_s=%u"
        " wake_cause=%s wake_key=%s asleep_s=%s sleep_count=%u asleep_total_s=%" PRIu64 " sleep_faults=0x%x sleep_codec=%s wake_swallowed=%u"
        " dark_s=%u dark_floor_pct=%u darks=%u dark_total_s=%u dark_wakes=%u/%u/%u dark_last_wake=%s"
        " sleep_check_s=%u sleep_checks=%u wake_checks=%u check_faults=%u check_awake_ms=%u/%u",
        state_text(idle.state()), hold_text(idle.hold()), source_text(src), unsigned(vbus_mv),
        unsigned(idle.still_ms(now_ms) / 1000), unsigned(idle.params().dim_ms / 1000), unsigned(idle.params().sleep_ms / 1000),
        wake_text(w.cause), wake_key_text(w.key), asleep, unsigned(r.sleep_count), r.asleep_total_ms / 1000,
        unsigned(r.last_faults & FaultMask), codec, unsigned(swallowed),
        unsigned(idle.params().dark_ms / 1000), unsigned(idle.params().dark_floor_pct), unsigned(idle.darks()),
        unsigned(idle.dark_total_ms(now_ms) / 1000), unsigned(idle.dark_wakes(DarkWake::Key)),
        unsigned(idle.dark_wakes(DarkWake::Motion)), unsigned(idle.dark_wakes(DarkWake::Incident)),
        dark_wake_text(idle.last_dark_wake()),
        unsigned(idle.params().sleep_check_s), unsigned(r.sleep_checks), unsigned(w.checks), unsigned(r.check_faults),
        unsigned(r.check_awake_ms), unsigned(r.check_awake_max_ms));
}

} // namespace guardian::power

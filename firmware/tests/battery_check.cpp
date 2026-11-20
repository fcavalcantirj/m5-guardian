// G16B: honest battery state from raw M5PM1 values, indicator, runtime log (host).
#include "check.hpp"
#include "battery.hpp"
#include <cstring>
#include <string>
#include <vector>

using namespace guardian::battery;

namespace {
class MemoryBlob final : public BlobStorage {
public:
    std::vector<std::uint8_t> bytes; bool exists{}, fail_write{}; unsigned writes{};
    BlobRead read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const override {
        if (!exists) return BlobRead::Absent;
        if (bytes.size() > capacity) return BlobRead::Error;
        std::memcpy(out, bytes.data(), bytes.size()); size = bytes.size(); return BlobRead::Ok;
    }
    bool write(const std::uint8_t* data, std::size_t size) override {
        ++writes; if (fail_write) return false; bytes.assign(data, data + size); exists = true; return true;
    }
};
Raw on_battery(std::uint16_t mv) { Raw r; r.vbat_ok = r.src_ok = r.gpio_ok = true; r.vbat_mv = mv; r.pwr_src = 0x04; r.gpio_in = 0x01; return r; }
Raw on_usb(std::uint16_t mv, bool charging) { Raw r = on_battery(mv); r.pwr_src = 0x05; r.gpio_in = charging ? 0x00 : 0x01; return r; }
State settle(Monitor& m, const Raw& r) { State s; for (std::size_t i = 0; i < Monitor::window; ++i) s = m.update(r); return s; }
std::string status(const State& s) { char t[96]; status_text(s, t, sizeof t); return t; }
}

GUARDIAN_CASE(level_uses_the_vendor_voltage_formula_clamped) {
    CHECK_EQ(level_from_mv(3300), 0);
    CHECK_EQ(level_from_mv(3100), 0);
    CHECK_EQ(level_from_mv(3700), 50);    // (3700-3300)*100/800
    CHECK_EQ(level_from_mv(4100), 100);
    CHECK_EQ(level_from_mv(4300), 100);
    CHECK_EQ(level_from_mv(3460), 20);
}

GUARDIAN_CASE(charging_comes_from_pm1_gpio0_low_and_external_power_from_pwr_src) {
    Monitor m;
    auto s = settle(m, on_usb(4050, true));
    CHECK(s.external); CHECK_EQ(s.charging, Charging::Yes); CHECK(!s.low);
    s = settle(m, on_usb(4150, false));
    CHECK(s.external); CHECK_EQ(s.charging, Charging::No);
    s = settle(m, on_battery(3900));
    CHECK(!s.external); CHECK_EQ(s.charging, Charging::No);
    // GPIO0 low without any 5V input cannot be charging: reported unknown, never "yes"
    Raw odd = on_battery(3900); odd.gpio_in = 0x00; s = m.update(odd);
    CHECK_EQ(s.charging, Charging::Unknown);
    // a failed GPIO or PWR_SRC read is unknown, never a guess
    Raw g = on_usb(4000, true); g.gpio_ok = false; s = m.update(g); CHECK_EQ(s.charging, Charging::Unknown);
    Raw p = on_usb(4000, true); p.src_ok = false; s = m.update(p); CHECK_EQ(s.charging, Charging::Unknown); CHECK(!s.external);
    CHECK_EQ(std::string(charging_text(Charging::Unknown)), std::string("unknown"));
}

GUARDIAN_CASE(failed_or_implausible_reads_never_invent_a_level) {
    Monitor m;
    Raw bad; bad.vbat_ok = false; auto s = m.update(bad);
    CHECK(!s.known); CHECK_EQ(s.level, -1); CHECK_EQ(s.mv, 0); CHECK(!s.low);
    s = m.update(on_battery(0)); CHECK(!s.known);                 // no cell / ADC not ready
    s = m.update(on_battery(6000)); CHECK(!s.known);              // garbage
    s = settle(m, on_battery(3800)); CHECK(s.known); CHECK_EQ(s.mv, 3800);
    // after a run of failed reads the old value ages out instead of staying "fresh"
    for (std::size_t i = 0; i < Monitor::window - 1; ++i) s = m.update(bad);
    CHECK(s.known);
    s = m.update(bad); CHECK(!s.known); CHECK_EQ(s.level, -1);
    CHECK(status(s).find("batt=unknown") != std::string::npos);
}

GUARDIAN_CASE(filter_averages_so_one_noisy_read_cannot_flip_the_warning) {
    Monitor m; auto s = settle(m, on_battery(3600));
    CHECK(!s.low);
    s = m.update(on_battery(3300));      // one sag
    CHECK(!s.low);
    s = settle(m, on_battery(3440));
    CHECK(s.low); CHECK(!s.critical);
    s = settle(m, on_battery(3340));
    CHECK(s.low); CHECK(s.critical);
    s = settle(m, on_usb(3340, true));   // charging: no warning
    CHECK(!s.low); CHECK(!s.critical);
}

GUARDIAN_CASE(status_fragment_is_explicit) {
    Monitor m;
    auto s = settle(m, on_battery(3700));
    CHECK_EQ(status(s), std::string("batt=3700mV/50% charging=no power=battery"));
    s = settle(m, on_usb(4100, true));
    CHECK_EQ(status(s), std::string("batt=4100mV/100%~usb charging=yes power=usb"));   // level read under charge
    s = settle(m, on_battery(3400));
    CHECK_EQ(status(s), std::string("batt=3400mV/12% charging=no power=battery low=1"));
}

GUARDIAN_CASE(indicator_draws_in_its_corner_and_warns_when_low) {
    std::vector<std::uint16_t> px(135 * 240, 0x1234);
    guardian::Canvas c(px.data(), 135, 240, true);
    Monitor m; auto s = settle(m, on_battery(3900));
    draw_indicator(c, s);
    std::size_t changed = 0, outside = 0;
    for (int y = 0; y < 240; ++y) for (int x = 0; x < 135; ++x) if (px[static_cast<std::size_t>(y * 135 + x)] != 0x1234) {
        ++changed; if (x < 108 || y > 11) ++outside;
    }
    CHECK(changed > 0); CHECK_EQ(outside, 0u);
    std::fill(px.begin(), px.end(), 0x1234);
    s = settle(m, on_battery(3400)); draw_indicator(c, s);
    std::size_t bar = 0, middle = 0;     // the low-battery bar sits on the last hint row only
    for (int y = 12; y < 240; ++y) for (int x = 0; x < 135; ++x) if (px[static_cast<std::size_t>(y * 135 + x)] != 0x1234) {
        if (y >= 231) ++bar; else ++middle;
    }
    CHECK(bar > 0); CHECK_EQ(middle, 0u); // face zone and information rows untouched
    std::fill(px.begin(), px.end(), 0x1234);
    Monitor u; Raw bad; bad.vbat_ok = false; draw_indicator(c, u.update(bad));
    std::size_t unknown_px = 0; for (auto p : px) if (p != 0x1234) ++unknown_px;
    CHECK(unknown_px > 0);               // an unknown battery is drawn as unknown, not as empty or full
}

GUARDIAN_CASE(run_log_keeps_the_previous_run_until_a_new_battery_run) {
    MemoryBlob blob;
    Monitor m; auto batt = settle(m, on_battery(4100));
    {
        RunLog log(blob, 7); log.load(); CHECK(!log.has_run());
        log.tick(batt, 1000); CHECK(log.active()); CHECK_EQ(log.run().start_mv, 4100);
        for (std::uint32_t t = 2000; t <= 125000; t += 1000) log.tick(batt, t);
        CHECK_EQ(log.run().minutes, 2u);
        CHECK(log.saves() >= 2u); CHECK(log.saves() <= 4u);        // about once a minute, not every second
    }
    { RunLog after(blob, 8); after.load(); CHECK(after.has_run()); CHECK_EQ(after.run().boot, 7u); CHECK_EQ(after.run().minutes, 2u); }
    // booted on USB to read it: the previous run must survive
    Monitor u; auto usb = settle(u, on_usb(4000, true));
    { RunLog read(blob, 8); read.load(); for (std::uint32_t t = 0; t < 300000; t += 1000) read.tick(usb, t);
      CHECK(!read.active()); CHECK_EQ(read.run().boot, 7u);
      char t[160]; run_text(read, t, sizeof t); CHECK(std::string(t).find("minutes=2") != std::string::npos); }
    // USB comes back during a run: the run ends and is marked
    { RunLog log(blob, 9); log.load(); log.tick(batt, 0); log.tick(batt, 61000); log.tick(usb, 62000);
      CHECK(!log.active()); CHECK(log.run().ended_on_usb); CHECK_EQ(log.run().boot, 9u);
      RunLog r(blob, 10); r.load(); CHECK(r.run().ended_on_usb); }
    // corrupt record: ignored, never rewritten by load
    blob.bytes[2] ^= 1; const auto w = blob.writes; RunLog c(blob, 11); c.load(); CHECK(!c.has_run()); CHECK_EQ(blob.writes, w);
    Run x; std::uint8_t buf[run_bytes]; CHECK_EQ(encode(x, buf, sizeof buf - 1), 0u);
}

// ---- G16D: a battery run continues across deep sleep -----------------------------------
namespace {
std::uint32_t test_crc32(const std::uint8_t* p, std::size_t n) {
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < n; ++i) { c ^= p[i]; for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u))); }
    return ~c;
}
std::string run_line(const RunLog& l) { char t[480]; run_text(l, t, sizeof t); return t; }   // the board's reply buffer
}

GUARDIAN_CASE(a_deep_sleep_wake_continues_the_run_and_reports_the_standby_drop) {
    MemoryBlob blob;
    Monitor m; const auto full = settle(m, on_battery(4100));
    Monitor m2; const auto before = settle(m2, on_battery(3990));
    Monitor m3; const auto after = settle(m3, on_battery(3950));
    {
        RunLog log(blob, 7); log.load();
        for (std::uint32_t t = 0; t <= 150000; t += 1000) log.tick(full, t);
        CHECK_EQ(log.run().active_s, 150u);
        log.sleeping(before, 150500);                 // just before deep sleep
        CHECK(log.run().slept); CHECK_EQ(log.run().sleep_mv, 3990);
    }
    {
        RunLog log(blob, 8); log.load();
        CHECK(log.has_run()); CHECK(log.run().slept);
        CHECK(run_line(log).find("end=asleep") != std::string::npos);   // as found after the cell died asleep
        log.resume(3600000);                          // ext1 wake after one hour asleep
        log.tick(after, 2000);
        CHECK(log.active()); CHECK_EQ(log.run().boot, 7u); CHECK_EQ(log.run().start_mv, 4100);
        CHECK_EQ(log.run().sleeps, 1u); CHECK_EQ(log.run().asleep_s, 3600u); CHECK_EQ(log.run().wake_mv, 3950);
        for (std::uint32_t t = 3000; t <= 62000; t += 1000) log.tick(after, t);
        CHECK_EQ(log.run().active_s, 210u);           // 150 s before + 60 s after the wake
        CHECK_EQ(log.run().minutes, 3u);
        const auto line = run_line(log);
        CHECK(line.find("active_s=210 sleeps=1 asleep_s=3600 sleep_mv=3990 wake_mv=3950 standby_drop_mv=40") != std::string::npos);
        CHECK(line.find("end=running") != std::string::npos);
    }
    // saved about once a minute (and going to sleep): the 3rd minute is on record, never more than the truth
    { RunLog r(blob, 9); r.load(); CHECK_EQ(r.run().active_s, 180u); CHECK_EQ(r.run().sleeps, 1u); CHECK_EQ(r.run().wake_mv, 3950); }
}

GUARDIAN_CASE(a_cold_boot_or_a_wake_on_usb_does_not_continue_the_slept_run) {
    MemoryBlob blob;
    Monitor m; const auto batt = settle(m, on_battery(4000));
    Monitor u; const auto usb = settle(u, on_usb(4100, true));
    { RunLog log(blob, 7); log.load(); log.tick(batt, 0); log.tick(batt, 30000); log.sleeping(batt, 30000); }
    {   // woke, but USB was plugged in meanwhile: the run ends as usb_returned, sleep counted
        RunLog log(blob, 8); log.load(); log.resume(600000); log.tick(usb, 1000);
        CHECK(!log.active()); CHECK(log.run().ended_on_usb); CHECK_EQ(log.run().sleeps, 1u); CHECK_EQ(log.run().boot, 7u);
        CHECK(run_line(log).find("end=usb_returned") != std::string::npos);
    }
    { RunLog log(blob, 9); log.load(); log.tick(batt, 0); log.tick(batt, 30000); log.sleeping(batt, 30000); }
    {   // cold boot (no resume) on battery: a new run, as before G16D
        RunLog log(blob, 10); log.load(); log.tick(batt, 0);
        CHECK_EQ(log.run().boot, 10u); CHECK_EQ(log.run().sleeps, 0u); CHECK(!log.run().slept);
    }
    {   // resume without a slept run continues nothing: a new run starts
        RunLog log(blob, 11); log.load(); log.resume(1000); log.tick(batt, 0);
        CHECK_EQ(log.run().boot, 11u); CHECK_EQ(log.run().sleeps, 0u);
    }
}

GUARDIAN_CASE(a_g16b_format_1_record_still_reads) {
    std::uint8_t v1[23]{};                       // G16B layout: GBRN, format 1, boot, start, last, minutes, usb, crc
    std::memcpy(v1, "GBRN", 4); v1[4] = 1; v1[6] = 5; v1[10] = 0x04; v1[11] = 0x10; v1[12] = 0x48; v1[13] = 0x0D;
    v1[14] = 95; v1[18] = 1;
    const auto c = test_crc32(v1, 19);
    for (int i = 0; i < 4; ++i) v1[19 + i] = static_cast<std::uint8_t>(c >> (8 * i));
    Run r;
    CHECK(decode(v1, sizeof v1, r));
    CHECK_EQ(r.boot, 5u); CHECK_EQ(r.start_mv, 4100); CHECK_EQ(r.last_mv, 3400); CHECK_EQ(r.minutes, 95u);
    CHECK_EQ(r.active_s, 95u * 60u); CHECK(r.ended_on_usb); CHECK(!r.slept);
    // and a format 2 record round-trips every field
    Run w; w.boot = 3; w.start_mv = 4000; w.last_mv = 3800; w.minutes = 2; w.active_s = 150; w.asleep_s = 7200;
    w.sleeps = 4; w.sleep_mv = 3850; w.wake_mv = 3820; w.slept = true;
    std::uint8_t buf[run_bytes]; CHECK_EQ(encode(w, buf, sizeof buf), run_bytes);
    Run back; CHECK(decode(buf, sizeof buf, back));
    CHECK_EQ(back.asleep_s, 7200u); CHECK_EQ(back.sleeps, 4u); CHECK_EQ(back.sleep_mv, 3850); CHECK_EQ(back.wake_mv, 3820);
    CHECK(back.slept); CHECK(!back.ended_on_usb); CHECK_EQ(back.active_s, 150u);
}

// ---- G16N: what guarding costs in each screen state, measured ---------------------------
namespace {
// One reading a second for `seconds`, the cell falling `mv_per_min` per minute from `mv`.
// Returns the voltage and the time it ended at.
struct Clock { std::uint32_t ms{}; double mv{}; };
State exact(double mv) { State s; s.known = true; s.mv = static_cast<std::uint16_t>(mv + 0.5); s.level = level_from_mv(s.mv); return s; }
void spend(RunLog& log, Clock& c, Phase phase, std::uint32_t seconds, double mv_per_min) {
    for (std::uint32_t i = 0; i < seconds; ++i) { c.ms += 1000; c.mv -= mv_per_min / 60.0; log.tick(exact(c.mv), c.ms, phase); }
}
}

GUARDIAN_CASE(drain_is_measured_per_screen_state_after_the_voltage_settled) {
    MemoryBlob blob;
    RunLog log(blob, 7); log.load();
    Clock c{0, 4100.02};   // .02: no reading ever sits on a rounding edge
    log.tick(exact(c.mv), c.ms, Phase::Active);              // the run starts
    int rate = 0;
    CHECK(!drain_rate(log.run(), Phase::Active, rate));
    // Full on: 3 mV a minute. The first 30 s after a phase began are not measured (settling).
    spend(log, c, Phase::Active, 30 + 299, 3.0);
    CHECK(!drain_rate(log.run(), Phase::Active, rate));      // 299 s measured: not a rate yet
    spend(log, c, Phase::Active, 301, 3.0);
    CHECK(drain_rate(log.run(), Phase::Active, rate));
    CHECK_EQ(rate, 30);                                      // mV per 10 minutes
    CHECK_EQ(log.run().drain[0].seconds, 600u);
    CHECK(!drain_rate(log.run(), Phase::Dim, rate));
    CHECK(!drain_rate(log.run(), Phase::Dark, rate));
    // Dimmed: the load falls, the cell voltage REBOUNDS 25 mV at once. That step is not drain:
    // only the fall after the settle time counts.
    c.mv += 25.0;
    spend(log, c, Phase::Dim, 30 + 600, 1.5);
    CHECK(drain_rate(log.run(), Phase::Dim, rate));
    CHECK_EQ(rate, 15);
    CHECK(drain_rate(log.run(), Phase::Active, rate)); CHECK_EQ(rate, 30);   // the other phases are untouched
    // Dark: backlight off, radio on.
    c.mv += 10.0;
    spend(log, c, Phase::Dark, 30 + 900, 1.0);
    CHECK(drain_rate(log.run(), Phase::Dark, rate));
    CHECK_EQ(rate, 10);
    CHECK_EQ(log.run().drain[2].seconds, 900u);
    // An incident lights the screen for a while, then it is dark again: the two dark stretches add
    // up, each after its own settle time; the bright minute in between belongs to Active.
    c.mv -= 20.0;
    spend(log, c, Phase::Active, 30 + 60, 3.0);
    c.mv += 20.0;
    spend(log, c, Phase::Dark, 30 + 300, 1.0);
    CHECK_EQ(log.run().drain[2].seconds, 1200u);
    CHECK(drain_rate(log.run(), Phase::Dark, rate)); CHECK_EQ(rate, 10);
    CHECK_EQ(log.run().drain[0].seconds, 660u);
    CHECK(drain_rate(log.run(), Phase::Active, rate)); CHECK_EQ(rate, 30);
    const auto line = run_line(log);
    CHECK(line.find(" end=running drain_mv_10min=active:30,dim:15,dark:10 drain_s=active:660,dim:600,dark:1200 checks=0 ") != std::string::npos);   // G16P: the timer checks follow
    // "dark guard: about N h left": from the present voltage to the floor's voltage at the dark rate.
    CHECK_EQ(mv_from_level(20), 3460);                       // the inverse of the vendor formula
    CHECK_EQ(mv_from_level(0), 3300); CHECK_EQ(mv_from_level(100), 4100); CHECK_EQ(mv_from_level(250), 4100); CHECK_EQ(mv_from_level(-3), 3300);
    CHECK_EQ(level_from_mv(mv_from_level(20)), 20); CHECK_EQ(level_from_mv(mv_from_level(57)), 57);
    std::uint16_t h10 = 0;
    CHECK(dark_hours_left(log.run(), 4000, 20, h10));
    CHECK_EQ(h10, 90);                                       // 540 mV at 60 mV an hour: 9.0 h
    CHECK(dark_hours_left(log.run(), 3475, 20, h10)); CHECK_EQ(h10, 2);       // 15 mV: a quarter of an hour, 0.2 (rounded down)
    CHECK(dark_hours_left(log.run(), 3460, 20, h10)); CHECK_EQ(h10, 0);       // at the floor
    CHECK(dark_hours_left(log.run(), 3300, 20, h10)); CHECK_EQ(h10, 0);       // under it
    CHECK(dark_hours_left(log.run(), 4000, 50, h10)); CHECK_EQ(h10, 50);      // a higher floor: 300 mV, 5.0 h
    // The record keeps it (saved once a minute): after the stick dies the numbers are still there.
    RunLog after(blob, 8); after.load();
    CHECK(after.has_run());
    CHECK(drain_rate(after.run(), Phase::Dark, rate)); CHECK_EQ(rate, 10);
    CHECK(drain_rate(after.run(), Phase::Dim, rate)); CHECK_EQ(rate, 15);
    CHECK(run_line(after).find("drain_mv_10min=active:30,dim:15,dark:10") != std::string::npos);
}

GUARDIAN_CASE(drain_is_never_a_guess) {
    MemoryBlob blob;
    RunLog log(blob, 7); log.load();
    Clock c{0, 4000.02};
    log.tick(exact(c.mv), c.ms, Phase::Active);
    std::uint16_t h10 = 77; int rate = 77;
    // Nothing measured: no rate, no hours, and the line says "-".
    CHECK(!dark_hours_left(log.run(), 4000, 20, h10));
    CHECK(run_line(log).find(" drain_mv_10min=active:-,dim:-,dark:- drain_s=active:0,dim:0,dark:0 checks=0 ") != std::string::npos);   // G16P: the timer checks follow
    // Short dark stretches (a wake every 20 s) never reach the settle time: still nothing.
    for (int i = 0; i < 60; ++i) { spend(log, c, Phase::Dark, 20, 1.0); spend(log, c, Phase::Active, 5, 3.0); }
    CHECK_EQ(log.run().drain[2].seconds, 0u);
    CHECK(!drain_rate(log.run(), Phase::Dark, rate));
    // A reading that is not known is never logged; a cell that ROSE while dark (warming up,
    // a relaxing cell) is reported as measured, negative, and gives no "hours left".
    State unknown; log.tick(unknown, c.ms + 1000, Phase::Dark);
    spend(log, c, Phase::Dark, 30 + 600, -0.5);
    CHECK(drain_rate(log.run(), Phase::Dark, rate)); CHECK_EQ(rate, -5);
    CHECK(!dark_hours_left(log.run(), 4000, 20, h10));
    CHECK(run_line(log).find("dark:-5 ") != std::string::npos);
    // USB comes back: the run ends; a later battery run starts from zero.
    Monitor u; const auto usb = settle(u, on_usb(4100, true));
    log.tick(usb, c.ms + 2000, Phase::Active);
    CHECK(!log.active());
    CHECK(drain_rate(log.run(), Phase::Dark, rate));         // the ended run keeps its numbers
    log.tick(exact(3900), c.ms + 3000, Phase::Dark);
    CHECK(log.active()); CHECK_EQ(log.run().drain[2].seconds, 0u);
    CHECK(!drain_rate(log.run(), Phase::Dark, rate));
    CHECK_EQ(std::string(phase_text(Phase::Active)), std::string("active"));
    CHECK_EQ(std::string(phase_text(Phase::Dim)), std::string("dim"));
    CHECK_EQ(std::string(phase_text(Phase::Dark)), std::string("dark"));
}

GUARDIAN_CASE(drain_survives_a_deep_sleep_and_older_records_still_read) {
    MemoryBlob blob;
    Clock c{0, 4000.02};
    {
        RunLog log(blob, 7); log.load();
        log.tick(exact(c.mv), c.ms, Phase::Active);
        spend(log, c, Phase::Dark, 30 + 600, 1.0);
        log.sleeping(exact(c.mv), c.ms);                     // the floor: deep sleep
    }
    {
        RunLog log(blob, 8); log.load();
        int rate = 0;
        CHECK(drain_rate(log.run(), Phase::Dark, rate)); CHECK_EQ(rate, 10);
        log.resume(3600000);
        Clock w{0, c.mv - 5.0};                              // woke 5 mV lower: standby, not dark drain
        log.tick(exact(w.mv), w.ms + 1000, Phase::Active);
        w.ms += 1000;
        spend(log, w, Phase::Dark, 30 + 300, 1.0);
        CHECK_EQ(log.run().drain[2].seconds, 900u);
        CHECK(drain_rate(log.run(), Phase::Dark, rate)); CHECK_EQ(rate, 10);
    }
    // A format 3 record round-trips the drain fields (negative drops too) ...
    Run w; w.boot = 3; w.start_mv = 4000; w.last_mv = 3800; w.minutes = 2; w.active_s = 150;
    w.drain[0] = {600, 30}; w.drain[1] = {1200, -4}; w.drain[2] = {86400, 700};
    std::uint8_t buf[run_bytes]; CHECK_EQ(encode(w, buf, sizeof buf), run_bytes);
    CHECK_EQ(run_bytes, 73u);                                  // G16P format 4 (format 3 was 61)
    Run r; CHECK(decode(buf, run_bytes, r));
    CHECK_EQ(r.drain[0].seconds, 600u); CHECK_EQ(r.drain[0].drop_mv, 30);
    CHECK_EQ(r.drain[1].seconds, 1200u); CHECK_EQ(r.drain[1].drop_mv, -4);
    CHECK_EQ(r.drain[2].seconds, 86400u); CHECK_EQ(r.drain[2].drop_mv, 700);
    buf[40] ^= 1; CHECK(!decode(buf, run_bytes, r));          // a damaged drain byte fails the CRC
    // ... and a G16D format 2 record (37 bytes) still reads, with nothing measured.
    std::uint8_t v2[run_bytes_v2]{};
    std::memcpy(v2, "GBRN", 4); v2[4] = 2; v2[6] = 5; v2[10] = 0x04; v2[11] = 0x10; v2[12] = 0x48; v2[13] = 0x0D;
    v2[14] = 95; v2[18] = 2; v2[19] = 0x44; v2[20] = 0x16; v2[27] = 3;
    const auto crc = test_crc32(v2, 33);
    for (int i = 0; i < 4; ++i) v2[33 + i] = static_cast<std::uint8_t>(crc >> (8 * i));
    Run old; CHECK(decode(v2, sizeof v2, old));
    CHECK_EQ(old.boot, 5u); CHECK_EQ(old.start_mv, 4100); CHECK_EQ(old.minutes, 95u); CHECK_EQ(old.active_s, 5700u);
    CHECK_EQ(old.sleeps, 3u); CHECK(old.slept);
    for (const auto& d : old.drain) { CHECK_EQ(d.seconds, 0u); CHECK_EQ(d.drop_mv, 0); }
    MemoryBlob stored; stored.bytes.assign(v2, v2 + sizeof v2); stored.exists = true;
    RunLog read(stored, 9); read.load();
    CHECK(read.has_run()); CHECK_EQ(read.run().boot, 5u);
}

// ---- G16P: what the deep sleep's timer checks cost, measured ------------------------------
GUARDIAN_CASE(timer_checks_show_their_cost_in_battrun) {
    MemoryBlob blob;
    Monitor m; const auto batt = settle(m, on_battery(4000));
    Monitor m2; const auto after = settle(m2, on_battery(3980));
    { RunLog log(blob, 7); log.load(); log.tick(batt, 0); log.tick(batt, 30000);
      CHECK(run_line(log).find(" checks=0 last_checks=0 check_s=0 check_first_mv=0 check_last_mv=0 check_drop_uv=- standby_uv_h=-\n") != std::string::npos);
      log.sleeping(batt, 30000); }
    {   // a key wake after an hour: 12 checks, 300 s apart, the cell 4 mV lower from the first to the last
        RunLog log(blob, 8); log.load();
        log.resume(3600000, SleepChecks{12, 300, 3988, 3984});
        log.tick(after, 1000);
        CHECK(log.active()); CHECK_EQ(log.run().checks, 12u); CHECK_EQ(log.run().last_checks.count, 12);
        // 4000 uV over 11 intervals = 364 uV a check; over 11 x 300 s = 4364 uV an hour (standby current included)
        CHECK(run_line(log).find(" checks=12 last_checks=12 check_s=300 check_first_mv=3988 check_last_mv=3984 check_drop_uv=364 standby_uv_h=4364\n") != std::string::npos);
        CHECK(run_line(log).find("sleeps=1 asleep_s=3600 sleep_mv=4000 wake_mv=3980 standby_drop_mv=20") != std::string::npos);   // as before
        log.sleeping(after, 60000);
    }
    {   // the next sleep of the same run: the run total adds up, the numbers are the latest sleep's
        RunLog log(blob, 9); log.load();
        CHECK_EQ(log.run().checks, 12u); CHECK_EQ(log.run().last_checks.first_mv, 3988);   // stored (format 4)
        log.resume(900000, SleepChecks{3, 300, 3980, 3979});
        log.tick(after, 1000);
        CHECK(run_line(log).find(" checks=15 last_checks=3 check_s=300 check_first_mv=3980 check_last_mv=3979 check_drop_uv=500 standby_uv_h=6000\n") != std::string::npos);
        log.sleeping(after, 60000);
    }
    {   // one check is no interval; a cell that rose reads negative; a missing reading gives no number
        RunLog log(blob, 10); log.load();
        log.resume(400000, SleepChecks{1, 300, 3979, 3979}); log.tick(after, 1000);
        CHECK(run_line(log).find(" checks=16 last_checks=1 check_s=300 check_first_mv=3979 check_last_mv=3979 check_drop_uv=- standby_uv_h=-\n") != std::string::npos);
        int uv = 7, uvh = 7;
        CHECK(!check_drop(SleepChecks{1, 300, 3979, 3979}, uv, uvh));
        CHECK(!check_drop(SleepChecks{5, 300, 0, 3979}, uv, uvh)); CHECK(!check_drop(SleepChecks{5, 300, 3979, 0}, uv, uvh));
        CHECK(!check_drop(SleepChecks{5, 0, 3980, 3979}, uv, uvh));
        CHECK(check_drop(SleepChecks{3, 60, 3979, 3981}, uv, uvh)); CHECK_EQ(uv, -1000); CHECK_EQ(uvh, -60000);
        CHECK(check_drop(SleepChecks{65535, 3600, 4200, 3300}, uv, uvh)); CHECK_EQ(uv, 14); CHECK_EQ(uvh, 14);
        log.sleeping(after, 60000);
    }
    {   // the timer found the charger: the run ends as usb_returned and keeps that sleep's checks
        Monitor u; const auto usb = settle(u, on_usb(4100, true));
        RunLog log(blob, 11); log.load();
        log.resume(1500000, SleepChecks{4, 300, 3978, 3977}); log.tick(usb, 1000);
        CHECK(!log.active()); CHECK(log.run().ended_on_usb); CHECK_EQ(log.run().checks, 20u);
        CHECK(run_line(log).find("end=usb_returned") != std::string::npos);
        CHECK(run_line(log).find(" checks=20 last_checks=4 ") != std::string::npos);
    }
    // The longest line still fits the board's reply buffer (480).
    Run big; big.boot = big.minutes = big.active_s = big.asleep_s = big.checks = 0xFFFFFFFFu;
    big.start_mv = big.last_mv = big.sleep_mv = 0xFFFF; big.wake_mv = 1; big.sleeps = 0xFFFF; big.ended_on_usb = true;
    for (auto& d : big.drain) d = {0xFFFFFFFFu, -2000000000};
    big.last_checks = SleepChecks{0xFFFF, 60, 0xFFFF, 1};
    std::uint8_t enc[run_bytes]; CHECK_EQ(encode(big, enc, sizeof enc), run_bytes);
    MemoryBlob wide; wide.bytes.assign(enc, enc + sizeof enc); wide.exists = true;
    RunLog wl(wide, 1); wl.load();
    const auto longest = run_line(wl);
    CHECK(longest.size() < 479); CHECK(!longest.empty() && longest.back() == '\n');   // whole, not cut
}

GUARDIAN_CASE(a_format_4_record_round_trips_and_a_format_3_record_still_reads) {
    Run w; w.boot = 3; w.start_mv = 4000; w.last_mv = 3800; w.minutes = 2; w.active_s = 150; w.sleeps = 2; w.slept = true;
    w.drain[2] = {86400, 700};
    w.checks = 70000; w.last_checks = SleepChecks{288, 300, 3990, 3962};
    std::uint8_t buf[run_bytes]; CHECK_EQ(encode(w, buf, sizeof buf), run_bytes);
    Run r; CHECK(decode(buf, run_bytes, r));
    CHECK_EQ(r.checks, 70000u); CHECK_EQ(r.last_checks.count, 288); CHECK_EQ(r.last_checks.period_s, 300);
    CHECK_EQ(r.last_checks.first_mv, 3990); CHECK_EQ(r.last_checks.last_mv, 3962);
    CHECK_EQ(r.drain[2].seconds, 86400u); CHECK_EQ(r.sleeps, 2u); CHECK(r.slept);
    buf[sizeof buf - 6] ^= 1; CHECK(!decode(buf, run_bytes, r));   // a damaged check byte (last_mv) fails the CRC
    // A G16N format 3 record (61 bytes), as a stick updated over the air has stored: every field, no checks.
    CHECK_EQ(run_bytes_v3, 61u);
    std::uint8_t v3[run_bytes_v3]{};
    std::memcpy(v3, "GBRN", 4); v3[4] = 3; v3[6] = 5; v3[10] = 0x04; v3[11] = 0x10; v3[12] = 0x48; v3[13] = 0x0D;
    v3[14] = 95; v3[18] = 2; v3[19] = 0x44; v3[20] = 0x16; v3[27] = 3;
    v3[33 + 16] = 0x2C; v3[33 + 17] = 0x01; v3[33 + 20] = 9;   // drain[2] = {300 s, 9 mV}
    const auto crc = test_crc32(v3, 57);
    for (int i = 0; i < 4; ++i) v3[57 + i] = static_cast<std::uint8_t>(crc >> (8 * i));
    Run old; CHECK(decode(v3, sizeof v3, old));
    CHECK_EQ(old.boot, 5u); CHECK_EQ(old.start_mv, 4100); CHECK_EQ(old.active_s, 5700u); CHECK_EQ(old.sleeps, 3u); CHECK(old.slept);
    CHECK_EQ(old.drain[2].seconds, 300u); CHECK_EQ(old.drain[2].drop_mv, 9);
    CHECK_EQ(old.checks, 0u); CHECK_EQ(old.last_checks.count, 0);
    MemoryBlob stored; stored.bytes.assign(v3, v3 + sizeof v3); stored.exists = true;
    RunLog read(stored, 9); read.load();
    CHECK(read.has_run()); CHECK_EQ(read.run().boot, 5u);
    read.resume(60000, SleepChecks{2, 60, 3900, 3899});       // and the run goes on in the new format
    CHECK_EQ(read.run().checks, 2u);
    CHECK_EQ(stored.bytes.size(), run_bytes);
}

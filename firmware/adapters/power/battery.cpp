// G16B honest battery state (see battery.hpp for the register source).
#include "battery.hpp"
#include <cstdio>
#include <cstring>

namespace guardian::battery {
namespace {
std::uint32_t crc32(const std::uint8_t* p, std::size_t n) {
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < n; ++i) {
        c ^= p[i];
        for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}
constexpr std::uint8_t src_vin = 0x01, src_vinout = 0x02;   // PWR_SRC bits (M5PM1_Class.hpp pwr_src_t)
constexpr std::uint8_t gpio0 = 0x01;                        // PM1 GPIO0: StickS3 charge status, low = charging
constexpr std::uint16_t run_format = 5;   // G23 (formats 1, 2, 3 and 4 still decode)
constexpr std::size_t drain_at = 33, crc_at = run_bytes - 4;   // format 3: three drains after the format 2 fields
constexpr std::size_t checks_at = run_bytes_v3 - 4;                // format 4: the timer checks after the drains (where format 3 had its CRC)
constexpr std::size_t segments_at = run_bytes_v4 - 4;               // format 5: the drain segments after the checks (where format 4 had its CRC)
constexpr std::uint16_t cyan = rgb565(0, 200, 220);   // same tone as the companion screens
void put16(std::uint8_t* p, std::uint16_t v) { p[0] = static_cast<std::uint8_t>(v); p[1] = static_cast<std::uint8_t>(v >> 8); }
void put32(std::uint8_t* p, std::uint32_t v) { put16(p, static_cast<std::uint16_t>(v)); put16(p + 2, static_cast<std::uint16_t>(v >> 16)); }
std::uint16_t get16(const std::uint8_t* p) { return static_cast<std::uint16_t>(p[0] | (p[1] << 8)); }
std::uint32_t get32(const std::uint8_t* p) { return get16(p) | (static_cast<std::uint32_t>(get16(p + 2)) << 16); }
}

const char* charging_text(Charging c) {
    switch (c) {
    case Charging::Yes: return "yes";
    case Charging::No: return "no";
    case Charging::Unknown: break;
    }
    return "unknown";
}

int level_from_mv(std::uint16_t mv) {
    const int level = (static_cast<int>(mv) - static_cast<int>(empty_mv)) * 100 / static_cast<int>(span_mv);
    return level < 0 ? 0 : level > 100 ? 100 : level;
}

State Monitor::update(const Raw& raw) {
    const bool plausible = raw.vbat_ok && raw.vbat_mv >= plausible_min_mv && raw.vbat_mv <= plausible_max_mv;
    if (plausible) {
        samples_[next_] = raw.vbat_mv;
        next_ = (next_ + 1) % window;
        if (count_ < window) ++count_;
        misses_ = 0;
    } else if (++misses_ >= window) {
        count_ = 0; next_ = 0;   // the last good value is too old to show as current
    }
    State s;
    if (count_) {
        std::uint32_t sum = 0;
        for (std::size_t i = 0; i < count_; ++i) sum += samples_[i];
        s.known = true;
        s.mv = static_cast<std::uint16_t>(sum / count_);
        s.level = level_from_mv(s.mv);
    }
    s.external = raw.src_ok && (raw.pwr_src & (src_vin | src_vinout));
    if (!raw.src_ok || !raw.gpio_ok) s.charging = Charging::Unknown;
    else if (s.external) s.charging = (raw.gpio_in & gpio0) ? Charging::No : Charging::Yes;
    else s.charging = (raw.gpio_in & gpio0) ? Charging::No : Charging::Unknown;   // "charging" with no input: not trusted
    s.low = s.known && !s.external && s.mv <= low_mv;
    s.critical = s.known && !s.external && s.mv <= critical_mv;
    state_ = s;
    return s;
}

void status_text(const State& s, char* out, std::size_t n) {
    if (!out || !n) return;
    char batt[32];
    if (s.known) std::snprintf(batt, sizeof batt, "%umV/%d%%%s", unsigned(s.mv), s.level, s.external ? "~usb" : "");
    else std::snprintf(batt, sizeof batt, "unknown");
    std::snprintf(out, n, "batt=%s charging=%s power=%s%s%s", batt, charging_text(s.charging),
                  s.external ? "usb" : "battery", s.low ? " low=1" : "", s.critical ? " critical=1" : "");
}

void draw_indicator(Canvas& c, const State& s) {
    constexpr int x = 112, y = 1, w = 20, h = 9;   // body; nub at x+w..x+w+1
    const std::uint16_t frame = s.known ? color::white : color::grey;
    c.fill_rect(x - 1, y - 1, w + 4, h + 2, color::black);   // keeps the icon readable over the art
    c.draw_rect(x, y, w, h, frame);
    c.fill_rect(x + w, y + 3, 2, 3, frame);
    if (!s.known) {
        c.text(x + 7, y + 1, "?", color::grey, 1);
    } else {
        const int fill = (w - 4) * s.level / 100;
        const std::uint16_t col = s.charging == Charging::Yes ? cyan
                                : s.critical ? color::red : s.low ? color::yellow : color::green;
        if (fill > 0) c.fill_rect(x + 2, y + 2, fill, h - 4, col);
        if (s.external) c.fill_rect(x - 4, y + 3, 2, 3, cyan);   // small "plugged" mark left of the icon
    }
    if (s.low) {
        char line[24];
        std::snprintf(line, sizeof line, "%s %u.%02uV", s.critical ? "CHARGE NOW" : "LOW BATTERY",
                      unsigned(s.mv / 1000), unsigned((s.mv % 1000) / 10));
        // Replaces the last hint row (y 232) of the companion screens; never a rating or evidence line.
        c.fill_rect(0, c.height() - 9, c.width(), 9, s.critical ? color::red : color::orange);
        c.text(2, c.height() - 8, line, color::black, 1);
    }
}

std::size_t encode(const Run& r, std::uint8_t* out, std::size_t capacity) {
    if (!out || capacity < run_bytes) return 0;
    std::memcpy(out, "GBRN", 4);
    put16(out + 4, run_format);
    put32(out + 6, r.boot);
    put16(out + 10, r.start_mv);
    put16(out + 12, r.last_mv);
    put32(out + 14, r.minutes);
    out[18] = static_cast<std::uint8_t>((r.ended_on_usb ? 1 : 0) | (r.slept ? 2 : 0));
    put32(out + 19, r.active_s);
    put32(out + 23, r.asleep_s);
    put16(out + 27, r.sleeps);
    put16(out + 29, r.sleep_mv);
    put16(out + 31, r.wake_mv);
    for (std::size_t k = 0; k < r.drain.size(); ++k) {   // G16N
        put32(out + drain_at + 8 * k, r.drain[k].seconds);
        put32(out + drain_at + 8 * k + 4, static_cast<std::uint32_t>(r.drain[k].drop_mv));
    }
    put32(out + checks_at, r.checks);   // G16P
    put16(out + checks_at + 4, r.last_checks.count);
    put16(out + checks_at + 6, r.last_checks.period_s);
    put16(out + checks_at + 8, r.last_checks.first_mv);
    put16(out + checks_at + 10, r.last_checks.last_mv);
    put16(out + segments_at, r.segments_started);   // G23
    for (std::size_t i = 0; i < max_segments; ++i) {
        const Segment& g = r.segments[i];
        std::uint8_t* q = out + segments_at + 2 + i * segment_bytes;
        put16(q, g.number); put16(q + 2, g.settings.poll_s); put16(q + 4, g.settings.dark_mhz); q[6] = g.settings.dim_pct; put16(q + 7, g.start_mv);
        for (std::size_t k = 0; k < g.drain.size(); ++k) { put32(q + 9 + 8 * k, g.drain[k].seconds); put32(q + 13 + 8 * k, static_cast<std::uint32_t>(g.drain[k].drop_mv)); }
    }
    put32(out + crc_at, crc32(out, crc_at));
    return run_bytes;
}
bool decode(const std::uint8_t* in, std::size_t size, Run& out) {
    if (!in || std::memcmp(in, "GBRN", 4)) return false;
    Run r;
    if (size == run_bytes_v1 && get16(in + 4) == 1) {   // G16B record
        if (crc32(in, 19) != get32(in + 19) || in[18] > 1) return false;
        r.minutes = get32(in + 14); r.active_s = r.minutes * 60u;
    } else if ((size == run_bytes_v2 && get16(in + 4) == 2) || (size == run_bytes_v3 && get16(in + 4) == 3)
               || (size == run_bytes_v4 && get16(in + 4) == 4) || (size == run_bytes && get16(in + 4) == run_format)) {
        const std::size_t crc = size - 4;   // G16D format 2: no drain fields (nothing measured); G16N format 3: no timer checks
        if (crc32(in, crc) != get32(in + crc) || in[18] > 3) return false;
        r.minutes = get32(in + 14); r.active_s = get32(in + 19); r.asleep_s = get32(in + 23);
        r.sleeps = get16(in + 27); r.sleep_mv = get16(in + 29); r.wake_mv = get16(in + 31); r.slept = (in[18] & 2) != 0;
        if (size >= run_bytes_v3) {
            for (std::size_t k = 0; k < r.drain.size(); ++k) {
                r.drain[k].seconds = get32(in + drain_at + 8 * k);
                r.drain[k].drop_mv = static_cast<std::int32_t>(get32(in + drain_at + 8 * k + 4));
            }
        }
        if (size >= run_bytes_v4) {   // G16P
            r.checks = get32(in + checks_at);
            r.last_checks.count = get16(in + checks_at + 4); r.last_checks.period_s = get16(in + checks_at + 6);
            r.last_checks.first_mv = get16(in + checks_at + 8); r.last_checks.last_mv = get16(in + checks_at + 10);
        }
        if (size == run_bytes) {   // G23
            r.segments_started = get16(in + segments_at);
            for (std::size_t i = 0; i < max_segments; ++i) {
                Segment& g = r.segments[i];
                const std::uint8_t* q = in + segments_at + 2 + i * segment_bytes;
                g.number = get16(q); g.settings.poll_s = get16(q + 2); g.settings.dark_mhz = get16(q + 4); g.settings.dim_pct = q[6]; g.start_mv = get16(q + 7);
                for (std::size_t k = 0; k < g.drain.size(); ++k) { g.drain[k].seconds = get32(q + 9 + 8 * k); g.drain[k].drop_mv = static_cast<std::int32_t>(get32(q + 13 + 8 * k)); }
            }
        }
    } else {
        return false;
    }
    r.boot = get32(in + 6); r.start_mv = get16(in + 10); r.last_mv = get16(in + 12);
    r.ended_on_usb = (in[18] & 1) != 0;
    out = r;
    return true;
}

void RunLog::load() {
    std::uint8_t buf[run_bytes]; std::size_t n = 0;
    Run r;
    if (storage_.read(buf, sizeof buf, n) == BlobRead::Ok && decode(buf, n, r)) { run_ = r; has_ = true; }
}

void RunLog::store() {
    std::uint8_t buf[run_bytes];
    const std::size_t n = encode(run_, buf, sizeof buf);
    if (n && storage_.write(buf, n)) ++saves_;
}

const char* phase_text(Phase p) {
    switch (p) {
    case Phase::Dim: return "dim";
    case Phase::Dark: return "dark";
    case Phase::Active: case Phase::Count: break;
    }
    return "active";
}

namespace {
using Drains = std::array<Drain, static_cast<std::size_t>(Phase::Count)>;
// G16N: a stretch of one phase begins (at the previous reading, when there is one). Nothing is
// measured until the voltage has settled; the phase's earlier total is kept as the base.
void begin(RunLog::Stretch& t, const Drains& d, Phase phase, std::uint32_t start_ms) {
    t.open = true; t.phase = phase; t.start_ms = start_ms; t.ref_mv = 0;
    const auto k = static_cast<std::size_t>(phase);
    t.base = k < d.size() ? d[k] : Drain{};
}
void measure(RunLog::Stretch& t, Drains& d, const State& s, std::uint32_t uptime_ms, Phase phase) {
    const auto k = static_cast<std::size_t>(phase);
    if (k >= d.size()) return;
    if (!t.open) begin(t, d, phase, uptime_ms);
    else if (phase != t.phase) begin(t, d, phase, t.last_ms);
    t.last_ms = uptime_ms;
    if (!t.ref_mv) {   // settling: the step of the load change and the refill of the average are not drain
        if (uptime_ms - t.start_ms >= drain_settle_ms) { t.ref_mv = s.mv; t.ref_ms = uptime_ms; }
        return;
    }
    d[k].seconds = t.base.seconds + (uptime_ms - t.ref_ms) / 1000u;
    d[k].drop_mv = t.base.drop_mv + (static_cast<std::int32_t>(t.ref_mv) - static_cast<std::int32_t>(s.mv));
}
}

void RunLog::account(const State& s, std::uint32_t uptime_ms, Phase phase) {
    measure(run_stretch_, run_.drain, s, uptime_ms, phase);
}

bool same(const Settings& a, const Settings& b) { return a.poll_s == b.poll_s && a.dark_mhz == b.dark_mhz && a.dim_pct == b.dim_pct; }
Segment* RunLog::current_segment() {
    return run_.segments_started ? &run_.segments[(run_.segments_started - 1u) % max_segments] : nullptr;
}
// G23: a new segment with these values, measured from start_ms (the previous reading when the values changed
// between two readings, like a phase change; the first reading of a run). After 65535 the number stays.
void RunLog::begin_segment(const State& s, const Settings& v, std::uint32_t start_ms, Phase phase) {
    if (run_.segments_started < 0xFFFFu) ++run_.segments_started;
    Segment& g = *current_segment();
    g = Segment{};
    g.number = run_.segments_started; g.settings = v; g.start_mv = s.mv;
    begin(seg_stretch_, g.drain, phase, start_ms); seg_stretch_.last_ms = start_ms;
}

bool drain_rate(const Drains& d, Phase phase, int& mv_per_10min) {
    const auto k = static_cast<std::size_t>(phase);
    if (k >= d.size() || d[k].seconds < drain_min_s) return false;
    const long long s = d[k].seconds, num = static_cast<long long>(d[k].drop_mv) * 600;
    mv_per_10min = static_cast<int>((num >= 0 ? num + s / 2 : num - s / 2) / s);   // to the nearest mV
    return true;
}
bool drain_rate(const Run& r, Phase phase, int& mv_per_10min) { return drain_rate(r.drain, phase, mv_per_10min); }

std::uint16_t mv_from_level(int percent) {
    const int p = percent < 0 ? 0 : percent > 100 ? 100 : percent;
    return static_cast<std::uint16_t>(empty_mv + p * static_cast<int>(span_mv) / 100);
}

bool dark_hours_left(const Run& r, std::uint16_t mv_now, int floor_pct, std::uint16_t& tenths) {
    int rate = 0;
    if (!drain_rate(r, Phase::Dark, rate) || rate <= 0) return false;   // not measured, or not a fall
    const int left_mv = static_cast<int>(mv_now) - static_cast<int>(mv_from_level(floor_pct));
    const long long t = left_mv <= 0 ? 0 : static_cast<long long>(left_mv) * 10 / (static_cast<long long>(rate) * 6);
    tenths = static_cast<std::uint16_t>(t > 9999 ? 9999 : t);
    return true;
}

void RunLog::tick(const State& s, std::uint32_t uptime_ms, Phase phase, const Settings& settings) {
    if (!s.known) return;                     // never log a guess
    const bool on_battery = !s.external;
    if (resume_) {                            // G16D: first reading after a key wake from deep sleep
        resume_ = false;
        if (on_battery) {
            active_ = true;
            base_active_s_ = run_.active_s; start_ms_ = uptime_ms;
            run_.wake_mv = run_.last_mv = s.mv;
            begin(run_stretch_, run_.drain, phase, uptime_ms); run_stretch_.last_ms = uptime_ms;   // G16N: the drain so far is kept, a new stretch starts
            // G23: the same values go on in the same segment (a new stretch); other values (or a record from before G23) start one.
            if (Segment* g = current_segment(); g && same(g->settings, settings)) { begin(seg_stretch_, g->drain, phase, uptime_ms); seg_stretch_.last_ms = uptime_ms; }
            else begin_segment(s, settings, uptime_ms, phase);
            last_saved_minute_ = run_.minutes; store();
        } else {
            run_.ended_on_usb = true; store();   // plugged in while it slept
        }
        return;
    }
    if (on_battery && !active_) {
        run_ = Run{};
        run_.boot = boot_; run_.start_mv = run_.last_mv = s.mv;
        start_ms_ = uptime_ms; base_active_s_ = 0;
        active_ = has_ = true;
        begin(run_stretch_, run_.drain, phase, uptime_ms); run_stretch_.last_ms = uptime_ms;   // G16N
        begin_segment(s, settings, uptime_ms, phase);                                          // G23: segment 1
        last_saved_minute_ = 0; store();
        return;
    }
    if (!active_) return;
    if (on_battery) {
        run_.last_mv = s.mv;
        run_.active_s = base_active_s_ + (uptime_ms - start_ms_) / 1000u;
        run_.minutes = run_.active_s / 60u;
        // G23: values changed since the previous reading: a new segment from that reading (the run's stretch goes on).
        if (Segment* g = current_segment(); !g || !same(g->settings, settings)) begin_segment(s, settings, seg_stretch_.last_ms, phase);
        account(s, uptime_ms, phase);   // G16N: before the save, so the minute's record carries it
        if (Segment* g = current_segment()) measure(seg_stretch_, g->drain, s, uptime_ms, phase);
        if (run_.minutes != last_saved_minute_) { last_saved_minute_ = run_.minutes; store(); }
    } else {
        run_.ended_on_usb = true;
        active_ = false;
        run_stretch_.open = false; seg_stretch_.open = false;
        store();
    }
}

void RunLog::sleeping(const State& s, std::uint32_t uptime_ms) {
    if (!active_) return;                     // only a battery run goes to sleep
    run_.active_s = base_active_s_ + (uptime_ms - start_ms_) / 1000u;
    run_.minutes = run_.active_s / 60u;
    if (s.known && !s.external) run_.last_mv = s.mv;
    run_.sleep_mv = run_.last_mv;
    run_.slept = true;
    store();
}

void RunLog::resume(std::uint32_t asleep_ms, const SleepChecks& checks) {
    if (!has_ || !run_.slept || run_.ended_on_usb) return;
    run_.slept = false;
    if (run_.sleeps < 0xFFFF) ++run_.sleeps;
    run_.asleep_s += asleep_ms / 1000u;
    run_.checks = run_.checks > 0xFFFFFFFFu - checks.count ? 0xFFFFFFFFu : run_.checks + checks.count;   // G16P
    run_.last_checks = checks;
    resume_ = true;
    store();
}

bool check_drop(const SleepChecks& c, int& uv_per_check, int& uv_per_hour) {
    if (c.count < 2 || !c.period_s || !c.first_mv || !c.last_mv) return false;
    const long long drop_uv = (static_cast<long long>(c.first_mv) - static_cast<long long>(c.last_mv)) * 1000;
    const long long intervals = c.count - 1, seconds = intervals * c.period_s;
    const auto nearest = [](long long num, long long den) { return (num >= 0 ? num + den / 2 : num - den / 2) / den; };
    uv_per_check = static_cast<int>(nearest(drop_uv, intervals));
    uv_per_hour = static_cast<int>(nearest(drop_uv * 3600, seconds));
    return true;
}

void run_text(const RunLog& log, char* out, std::size_t n) {
    if (!out || !n) return;
    if (!log.has_run()) { std::snprintf(out, n, "BATTRUN none\n"); return; }
    const auto& r = log.run();
    char drop[32] = "";
    if (r.sleeps && r.sleep_mv && r.wake_mv) std::snprintf(drop, sizeof drop, " standby_drop_mv=%d", int(r.sleep_mv) - int(r.wake_mv));
    char rate[3][12];   // G16N: mV per 10 minutes in each screen state, "-" until measured long enough
    for (std::size_t k = 0; k < 3; ++k) {
        int v = 0;
        if (drain_rate(r, static_cast<Phase>(k), v)) std::snprintf(rate[k], sizeof rate[k], "%d", v);
        else std::snprintf(rate[k], sizeof rate[k], "-");
    }
    char cost[2][16] = {"-", "-"};   // G16P: the latest sleep's drop per check interval and per hour, "-" until it has a number
    int uv = 0, uvh = 0;
    if (check_drop(r.last_checks, uv, uvh)) { std::snprintf(cost[0], sizeof cost[0], "%d", uv); std::snprintf(cost[1], sizeof cost[1], "%d", uvh); }
    int used = std::snprintf(out, n, "BATTRUN boot=%u start=%umV last=%umV minutes=%u active_s=%u sleeps=%u asleep_s=%u sleep_mv=%u wake_mv=%u%s end=%s"
                  " drain_mv_10min=active:%s,dim:%s,dark:%s drain_s=active:%u,dim:%u,dark:%u"
                  " checks=%u last_checks=%u check_s=%u check_first_mv=%u check_last_mv=%u check_drop_uv=%s standby_uv_h=%s segs=%u",
                  unsigned(r.boot), unsigned(r.start_mv), unsigned(r.last_mv), unsigned(r.minutes), unsigned(r.active_s),
                  unsigned(r.sleeps), unsigned(r.asleep_s), unsigned(r.sleep_mv), unsigned(r.wake_mv), drop,
                  log.active() ? "running" : r.ended_on_usb ? "usb_returned" : r.slept ? "asleep" : "stopped_without_usb",
                  rate[0], rate[1], rate[2], unsigned(r.drain[0].seconds), unsigned(r.drain[1].seconds), unsigned(r.drain[2].seconds),
                  unsigned(r.checks), unsigned(r.last_checks.count), unsigned(r.last_checks.period_s), unsigned(r.last_checks.first_mv),
                  unsigned(r.last_checks.last_mv), cost[0], cost[1], unsigned(r.segments_started));
    // G23: each kept segment, oldest first: its values, the cell at its start, per phase <mV per 10 min>/<seconds>.
    const auto left = [&]() { return used < 0 || static_cast<std::size_t>(used) >= n ? std::size_t{0} : n - static_cast<std::size_t>(used); };
    const unsigned started = r.segments_started, first = started > max_segments ? started - (max_segments - 1u) : 1u;
    for (unsigned k = first; started && k <= started && left() > 1; ++k) {
        const Segment& g = r.segments[(k - 1u) % max_segments];
        char ph[3][28];
        for (std::size_t p = 0; p < 3; ++p) {
            int v = 0;
            if (drain_rate(g.drain, static_cast<Phase>(p), v)) std::snprintf(ph[p], sizeof ph[p], "%d/%u", v, unsigned(g.drain[p].seconds));
            else std::snprintf(ph[p], sizeof ph[p], "-/%u", unsigned(g.drain[p].seconds));
        }
        used += std::snprintf(out + used, left(), " seg%u=poll_s:%u,dark_mhz:%u,dim_pct:%u,start_mv:%u,active:%s,dim:%s,dark:%s",
                              unsigned(g.number), unsigned(g.settings.poll_s), unsigned(g.settings.dark_mhz), unsigned(g.settings.dim_pct),
                              unsigned(g.start_mv), ph[0], ph[1], ph[2]);
    }
    if (left() > 1) std::snprintf(out + used, left(), "\n");
}

} // namespace guardian::battery

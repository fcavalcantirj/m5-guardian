// G14 diagnostic screens, G16A upright portrait layout (135x240, StickS3
// standing with USB down), G16C "every screen is the Guardian": a clean
// header (mode tag plate + BSSID tail slot, then the network name alone on
// its own full-width row), the 135x160 portrait of the current rating in the
// face zone (or the expression-free NoData silhouette with a marker), and a
// dense HUD of real evidence below. Pure black everywhere, like the art.
//
// Formatting only: every value comes from the Presenter's ViewModel /
// DetailsView / PickerView and the board Status. A HUD element is composed
// only when its evidence exists (Hud flags, host-tested); decorative motion
// never implies a measurement.
//
// Grid: 1x glyphs advance 6 px (22 per line), 2x glyphs 12 px (11 per line).
#include "companion.hpp"
#include "persona.hpp"
#include <algorithm>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace guardian::companion {
namespace {
constexpr std::uint16_t light_green = rgb565(120, 220, 80);
constexpr std::uint16_t magenta = rgb565(200, 0, 160); // Horrible: never the ALERT red
constexpr std::uint16_t cyan = rgb565(0, 200, 220);
constexpr std::uint16_t gold = rgb565(255, 200, 40);
constexpr std::uint16_t teal_plate = rgb565(0, 52, 66);   // badge plates (text carries the meaning)
constexpr std::uint16_t hud_dim = rgb565(0, 72, 92);       // HUD rules and brackets
constexpr std::uint16_t hud_faint = rgb565(0, 26, 34);     // scanline
constexpr int cols1 = Frame::cols1, cols2 = Frame::cols2;
constexpr int pitch1 = 9;               // 1x row pitch (7 px glyph + 2)
constexpr int pitch2 = 18;              // 2x row pitch (14 px glyph + 4)
constexpr int zone_top = Frame::face_zone_y, zone_bottom = Frame::face_zone_y + Frame::face_zone_h;   // 20..179
constexpr int hud_y = Frame::hud_y;     // 181
constexpr int hud_last = 215;           // last 1x HUD row above the hints
constexpr int hint1_y = 224, hint2_y = 232;
constexpr int settings_hint1_y = 216, settings_hint2_y = 228;   // G24: the Settings screen's own two hint rows
// Details pages: title (2 rows), a reserved status slot (2 rows), then the body.
constexpr int details_title_y = 21, details_status_y = 39, details_body_y = 59, details_body_last = 214;
constexpr int details_body_rows = (details_body_last - details_body_y) / pitch1 + 1;   // 18

#if defined(__GNUC__)
__attribute__((format(printf, 6, 7)))
#endif
Line* add(Frame& f, int x, int y, std::uint16_t color, std::uint8_t scale, const char* format, ...) {
    if (f.count >= f.lines.size()) { ++f.overflow; return nullptr; }
    auto& l = f.lines[f.count++];
    va_list args; va_start(args, format);
    const int w = std::vsnprintf(l.text.data(), l.text.size(), format, args);
    va_end(args);
    if (w < 0 || static_cast<std::size_t>(w) >= l.text.size()) ++f.overflow;   // never cut text silently
    l.x = static_cast<std::int16_t>(x); l.y = static_cast<std::int16_t>(y); l.color = color; l.scale = scale;
    return &l;
}
void plate(Line* l, std::uint16_t c) { if (l) { l->plated = true; l->plate = c; } }
int text_w(const char* s, int scale = 1) { return static_cast<int>(std::strlen(s)) * Canvas::glyph_advance * scale; }
// Greedy word wrap (the Presenter's wrap_take, so planned pages are what is drawn)
// of `text` at x, from y with `pitch`, while y <= max_y. Returns the next free y;
// `cut` (optional) reports unshown text.
int wrap(Frame& f, int y, std::uint16_t color, const char* text, int max_y, std::uint8_t scale = 1,
         int pitch = pitch1, bool* cut = nullptr, int x = 2, bool centre = false) {
    const std::size_t width = static_cast<std::size_t>(scale == 2 ? cols2 : cols1);
    const std::size_t n = std::strlen(text); std::size_t at = 0;
    while (at < n && y <= max_y) {
        const std::size_t take = wrap_take(text, n, at, width);
        const int lx = centre ? (Frame::width - static_cast<int>(take) * Canvas::glyph_advance * scale) / 2 : x;
        add(f, lx, y, color, scale, "%.*s", static_cast<int>(take), text + at);
        at = wrap_next(text, n, at, width);
        y += pitch;
    }
    if (cut) *cut = at < n;
    else if (at < n) ++f.overflow;   // text that does not fit is a layout defect, never silent
    return y;
}
std::uint16_t mood_color(Mood m) {
    switch (m) {
    case Mood::VeryGood: return color::green; case Mood::Good: return light_green;
    case Mood::Medium: return color::yellow; case Mood::Bad: return color::orange;
    case Mood::Horrible: return magenta; case Mood::Unknown: return color::grey;
    }
    return color::grey;
}
const char* radio_text(RadioState r) {   // each fits one 1x row
    switch (r) {
    case RadioState::Off: return "Radio off: no readings";
    case RadioState::Unconfigured: return "Radio off: no country";
    case RadioState::Failed: return "Radio failed: reboot";
    case RadioState::Discovering: return "Searching 2.4 GHz";
    case RadioState::Monitoring: return "Listening 2.4 GHz only";
    }
    return "";
}
// Compact HUD forms of what the presenter labelled (same enums, nothing inferred).
const char* mode_badge(Mode m) {
    switch (m) {
    case Mode::Open: return "OPEN"; case Mode::Wep: return "WEP"; case Mode::Wpa1: return "WPA1";
    case Mode::Wpa2Personal: return "WPA2-P"; case Mode::Wpa3Personal: return "WPA3-P"; case Mode::Transition: return "WPA2/3";
    case Mode::Owe: return "OWE"; case Mode::Enterprise: return "ENT"; case Mode::Unknown: return "MODE ?";
    }
    return "MODE ?";
}
const char* cipher_badge(Cipher c) {
    switch (c) {
    case Cipher::None: return "NONE"; case Cipher::Wep: return "WEP"; case Cipher::Tkip: return "TKIP";
    case Cipher::Ccmp: return "CCMP"; case Cipher::Gcmp: return "GCMP"; case Cipher::Unknown: return "CIPH ?";
    }
    return "CIPH ?";
}
const char* pmf_badge(Pmf p) {
    switch (p) {
    case Pmf::Required: return "PMF REQ"; case Pmf::Optional: return "PMF OPT"; case Pmf::Disabled: return "PMF OFF";
    case Pmf::Unknown: return "PMF ?";
    }
    return "PMF ?";
}
const char* store_short(StoreState s) {
    return s == StoreState::SaveFailed ? "CHOICE NOT SAVED" : s == StoreState::Rejected ? "SAVED RECORD UNUSED" : nullptr;
}
// "35 s ago" / "12 min ago" / "long ago": at most 11 glyphs, so it reads at 2x.
void age_text(char* out, std::size_t n, Millis age_ms) {
    const unsigned s = static_cast<unsigned>(age_ms / 1000);
    if (s < 100) std::snprintf(out, n, "%u s ago", s);
    else if (s / 60 < 1000) std::snprintf(out, n, "%u min ago", s / 60);
    else std::snprintf(out, n, "long ago");
}
// The last five characters of the BSSID text ("4E:5F").
const char* bssid_tail(const ViewModel& v) { return v.selected_bssid.c_str() + 12; }
void hints(Frame& f, const char* first, const char* second) {
    if (first) add(f, 2, hint1_y, cyan, 1, "%s", first);
    if (second) add(f, 2, hint2_y, cyan, 1, "%s", second);
}
// 1x rows from y while y <= last.
struct Rows {
    Frame& f; int y; int last{hud_last};
    void line(std::uint16_t color, const char* text) { y = wrap(f, y, color, text, last); }
};
std::uint8_t bars_for(int dbm) { return dbm >= -55 ? 4 : dbm >= -65 ? 3 : dbm >= -75 ? 2 : dbm >= -85 ? 1 : 0; }

// `text` in at most `width` glyphs: unchanged when it fits, else width - 1
// glyphs and a visible '~' (never a silent cut). `out` holds width + 1 bytes.
void shorten(char* out, std::size_t n, const char* text, int width) {
    const auto len = std::strlen(text);
    if (len <= static_cast<std::size_t>(width)) std::snprintf(out, n, "%s", text);
    else std::snprintf(out, n, "%.*s~", width - 1, text);
}
// ---- G16E: amber observation text and the threat radar row ------------------------------
// "<what> nearby: <count> <unit> / <s> s from <n> random addresses", shortened by
// dropping clauses (never cutting words) until it fits `rows` wrapped rows; the
// Nearby details page always has the full text.
void area_banner(const IncidentObservation& o, char* out, std::size_t n, int rows, int columns) {
    const unsigned seconds = static_cast<unsigned>((o.window_ms + 999) / 1000);
    for (int variant = 0; variant < 3; ++variant) {
        const bool sources = variant < 2 && o.distinct_sources > 0;
        const bool random = variant == 0 && o.sources_random;
        if (sources) std::snprintf(out, n, "%s: %u %s / %u s from %u %saddresses", area_text(o), unsigned(o.count),
                                   area_unit(o), seconds, unsigned(o.distinct_sources), random ? "random " : "");
        else std::snprintf(out, n, "%s: %u %s / %u s", area_text(o), unsigned(o.count), area_unit(o), seconds);
        if (wrapped_rows(out, static_cast<std::size_t>(columns)) <= static_cast<std::size_t>(rows)) return;
    }
}
// Compact rate: up to 3 characters ("12", "340", "12k", "99k+"), with "+" when capped.
// G25: the router's change in the most words that fit `rows` wrapped rows (Full, Short, then Minimal).
void router_banner(const RouterView& r, char* out, std::size_t n, int rows, int columns) {
    for (const auto w : {RouterWording::Full, RouterWording::Short, RouterWording::Minimal}) {
        if (router_sentence(r, w, out, n) && wrapped_rows(out, static_cast<std::size_t>(columns)) <= static_cast<std::size_t>(rows)) return;
    }
    router_sentence(r, RouterWording::Minimal, out, n);
}
void rate_text(char* out, std::size_t n, std::uint32_t v, bool capped = false) {
    if (v < 1000) std::snprintf(out, n, "%u%s", unsigned(v), capped ? "+" : "");
    else if (v < 100000) std::snprintf(out, n, "%uk%s", unsigned(v / 1000), capped ? "+" : "");
    else std::snprintf(out, n, "99k+");
}
// Radar row: glyph slots from x 2 (6 px each, 9 families since G16G), rates text at x 57. Only for real
// (non-DEMO) readings with radar data; nothing is drawn for unregistered families.
// G16H: the Bluetooth family is a tenth slot that exists only while a BLE scan feeds its detector
// (RadarFamily::registered); the rates then start one cell further right (x 63, 12 glyphs). Without
// it the row is exactly the nine-slot row.
constexpr int radar_x0 = 2, radar_cell = 6, rates_x = 57;
bool radar_row(Frame& f, const Status& st, int y) {
    if (!st.radar.known) return false;
    f.hud.radar = true; f.hud.radar_x = radar_x0; f.hud.radar_y = static_cast<std::int16_t>(y);
    for (std::size_t i = 0; i < f.hud.glyphs.size(); ++i) {
        const auto& in = st.radar.families[i]; auto& g = f.hud.glyphs[i];
        g.registered = in.registered; g.pulse = in.registered && in.pulse; g.active = in.registered && in.active; g.scope = in.scope;
    }
    const auto& a = st.radar.air;
    if (a.known) {
        char p[8], b[8], t[8];
        rate_text(p, sizeof p, a.probes); rate_text(b, sizeof b, a.beacons);
        if (a.transmitters > 99 || a.transmitters_saturated) std::snprintf(t, sizeof t, "99+");
        else rate_text(t, sizeof t, a.transmitters);
        // Review 2026-11-17: never wider than the panel. The transmitter count gives way
        // first (it stays on the details page and in STATUS); a value is never cut.
        const int x = rates_x + (st.radar.families[static_cast<std::size_t>(DetectorFamily::Bluetooth)].registered ? radar_cell : 0);
        const int fit = (Frame::width - x + 1) / Canvas::glyph_advance;   // 13 glyphs (12 with the Bluetooth slot)
        char line[32];
        std::snprintf(line, sizeof line, "P%s B%s T%s", p, b, t);
        if (static_cast<int>(std::strlen(line)) > fit) std::snprintf(line, sizeof line, "P%s B%s", p, b);
        if (static_cast<int>(std::strlen(line)) > fit) std::snprintf(line, sizeof line, "P%s", p);
        add(f, x, y, color::white, 1, "%s", line);
    }
    return true;
}

// ---- header: tag plate + BSSID tail slot, then the name on its own row --------
void header(Frame& f, const ViewModel& v) {
    if (v.demo) {
        plate(add(f, 2, Frame::tag_y, color::black, 1, "DEMO %u/5", unsigned(v.demo_step) + 1), color::yellow);
        add(f, 2, Frame::name_y, color::yellow, 1, "not a real reading");
        return;
    }
    if (v.alert) plate(add(f, 2, Frame::tag_y, color::white, 1, "ALERT"), color::red);
    else plate(add(f, 2, Frame::tag_y, color::black, 1, "%s", v.source_label), v.caution || v.router_amber ? amber : cyan);   // G16E: amber = nearby; G25: the router
    if (!v.has_selection) { add(f, 2, Frame::name_y, color::grey, 1, "(no network)"); return; }
    add(f, Frame::bssid_x, Frame::tag_y, color::grey, 1, "..:%s", bssid_tail(v));
    // Up to 22 glyphs; a longer name is shortened with a visible '~', never cut silently.
    char name[cols1 + 1];
    shorten(name, sizeof name, v.selected_label.c_str(), cols1);
    add(f, 2, Frame::name_y, color::white, 1, "%s", name);
}

// ---- face screens ------------------------------------------------------------------
void badges(Frame& f, const DetailsView& d, int y) {
    int x = 2;
    for (const char* b : {mode_badge(d.mode), cipher_badge(d.pairwise), pmf_badge(d.pmf)}) {
        plate(add(f, x, y, color::white, 1, "%s", b), teal_plate);
        x += text_w(b) + 6;
    }
}
// Fresh, valid signal of the selected network (never stale, never invalid, never DEMO).
bool fresh_signal(const ViewModel& v, const DetailsView& d) {
    const auto& s = d.advice.signal;
    return !v.demo && s.available && s.rssi_valid && s.age_ms < Core::fresh_ms;
}
std::uint8_t heard_channel(const DetailsView& d) {
    if (d.has_coverage && d.coverage.channel) return d.coverage.channel;
    return d.advice.signal.available ? d.advice.signal.channel : 0;
}
void listen_flags(Frame& f, const Status& st) {
    f.hud.listening = st.radio == RadioState::Discovering || st.radio == RadioState::Monitoring;
    f.hud.sweeping = st.radio == RadioState::Discovering;
    f.hud.locked = st.radio == RadioState::Monitoring;
}
void listen_row(Frame& f, const Status& st, const DetailsView& d, int y) {
    const auto ch = heard_channel(d);
    switch (st.radio) {
    case RadioState::Monitoring:
        if (ch) add(f, 2, y, cyan, 1, "CH%02u LOCK", unsigned(ch)); else add(f, 2, y, cyan, 1, "LOCK");
        break;
    case RadioState::Discovering: add(f, 2, y, cyan, 1, "SWEEP 2.4G"); break;
    case RadioState::Off: add(f, 2, y, color::orange, 1, "RADIO OFF"); break;
    case RadioState::Unconfigured: add(f, 2, y, color::orange, 1, "NO COUNTRY"); break;
    case RadioState::Failed: add(f, 2, y, color::orange, 1, "RADIO FAIL"); break;
    }
}
const char* overlay_short(Overlay o) {
    switch (o) {
    case Overlay::None: return "ADV ONLY"; case Overlay::Checking: return "CHECKING"; case Overlay::NoFreshData: return "STALE";
    case Overlay::CoverageDegraded: return "DEGRADED"; case Overlay::Unsupported: return "NOT RATED"; case Overlay::Incident: return "INCIDENT";
    }
    return "";
}

void rated_hud(const Presenter& p, const Status& st, Frame& f) {
    const auto& v = p.view(); const auto& d = p.details();
    add(f, 2, hud_y, v.face == Mood::VeryGood ? gold : mood_color(v.face), 2, "%.11s", v.mood_label);
    const char* store = store_short(st.store);
    if (v.router_amber) {   // G25 amber: the rating label stays; the router's change in words below it
        char text[160]; router_banner(v.router, text, sizeof text, 3, cols1);
        wrap(f, 197, amber, text, 215);
        if (store) add(f, 2, hint1_y, color::orange, 1, "%s", store); else add(f, 2, hint1_y, cyan, 1, "blue: info");
        add(f, 2, hint2_y, cyan, 1, "hold side: networks");
        return;
    }
    if (v.caution) {   // G16E amber: the rating label stays; the observation in words below it
        char text[160]; area_banner(v.caution_evidence, text, sizeof text, 3, cols1);
        wrap(f, 197, amber, text, 215);
        if (store) add(f, 2, hint1_y, color::orange, 1, "%s", store); else if (!radar_row(f, st, hint1_y)) add(f, 2, hint1_y, cyan, 1, "blue: info");
        add(f, 2, hint2_y, cyan, 1, "hold side: networks");
        return;
    }
    badges(f, d, 197);
    if (v.last_seen_known) add(f, 2, 207, color::white, 1, "SEEN %us", std::min(999u, unsigned(v.last_seen_ms / 1000)));
    if (fresh_signal(v, d)) {
        f.hud.rssi = true; f.hud.rssi_dbm = d.advice.signal.rssi_dbm; f.hud.bars = bars_for(d.advice.signal.rssi_dbm);
        f.hud.rssi_x = 58; f.hud.rssi_y = 207;
        add(f, 84, 207, color::white, 1, "%ddBm", int(d.advice.signal.rssi_dbm));
    }
    listen_row(f, st, d, 215);
    // The rating is about the advertised settings only (never password, Internet or attacker).
    add(f, 86, 215, color::grey, 1, "%s", overlay_short(v.overlay));
    const bool radar = !store && radar_row(f, st, hint1_y);   // G16E: the radar takes the first hint row
    hints(f, store || radar ? nullptr : "blue: info", "hold side: networks");
    if (store) add(f, 2, hint1_y, color::orange, 1, "%s", store);
}

void demo_hud(const Presenter& p, Frame& f) {
    const auto& v = p.view(); const auto& d = p.details();
    f.demo_badge = true;
    add(f, Frame::badge_x + 2, Frame::badge_y + 2, color::black, 2, "DEMO");   // on the yellow plate drawn by draw()
    add(f, 56, 182, color::yellow, 1, "not a real");
    add(f, 56, 191, color::yellow, 1, "reading %u/5", unsigned(v.demo_step) + 1);
    add(f, 2, 199, v.face == Mood::VeryGood ? gold : mood_color(v.face), 2, "%.11s", v.mood_label);
    badges(f, d, 215);
    hints(f, "side: next face", "hold blue: exit");
}

void alert_hud(const Presenter& p, const Status& st, Frame& f) {
    const auto& v = p.view();
    add(f, 2, 180, color::red, 2, "ALERT");   // the incident, not a rating: no mood label beside it
    Rows rows{f, 196, hint2_y};
    // G16R: the red sentence names the picked network (at most one row of name), never an address.
    char sentence[96];
    alert_sentence(v, sentence, sizeof sentence, static_cast<std::size_t>(cols1));
    rows.line(color::red, sentence);
    if (v.router_alert) {   // G25 STRICT: the router's own change; no burst count, no cause line
        const char* state = v.overlay == Overlay::NoFreshData ? "No fresh data" : v.overlay == Overlay::CoverageDegraded ? "Coverage degraded" : nullptr;
        rows.line(color::white, "accept it on Details");
        if (state && rows.y <= hint2_y) rows.line(color::white, state);
        if (const char* store = store_short(st.store); store && rows.y <= hint2_y) rows.line(color::orange, store);
        if (rows.y <= hint2_y) add(f, 2, rows.y, cyan, 1, "blue: info");
        return;
    }
    const auto& b = v.incident;
    const unsigned seconds = std::min(999u, static_cast<unsigned>((b.window_ms + 999) / 1000));
    const unsigned count = std::min(999u, static_cast<unsigned>(b.count));
    char text[32];
    if (b.age_known) std::snprintf(text, sizeof text, "%u in %us, %us ago", count, seconds, std::min(999u, unsigned(b.age_ms / 1000)));
    else std::snprintf(text, sizeof text, "%u in %us", count, seconds);
    rows.line(color::red, text);
    // During an ALERT the coverage state stays visible (owner requirement).
    const char* state = v.overlay == Overlay::NoFreshData ? "No fresh data"
        : v.overlay == Overlay::CoverageDegraded ? "Coverage degraded"
        : v.overlay == Overlay::Checking ? "Checking"
        : v.overlay == Overlay::Unsupported ? "Not rated" : nullptr;
    // G16J: frames matching a tool shape say so (never which tool); otherwise the cause stays
    // "unknown". The note is shown only when it fits above the coverage state.
    const auto rows_left = [&] { return rows.y > hint2_y ? 0 : (hint2_y - rows.y) / pitch1 + 1; };
    const char* note = b.shapes ? tool_shape_text(b.shapes) : "cause unknown";
    if (static_cast<int>(wrapped_rows(note, static_cast<std::size_t>(cols1))) + (state ? 1 : 0) <= rows_left()) rows.line(color::red, note);
    if (state && rows_left() >= 1) rows.line(color::white, state);
    if (const char* store = store_short(st.store); store && rows.y <= hint2_y) rows.line(color::orange, store);
    if (rows.y <= hint2_y) add(f, 2, rows.y, cyan, 1, "blue: info");
}

// The NoData marker: what is missing, in large text over the silhouette, then the HUD.
void no_data_hud(const Presenter& p, const Status& st, Frame& f) {
    const auto& v = p.view();
    int y = 68;
    if (!v.has_selection && !v.demo) {
        add(f, (Frame::width - text_w("No network", 2)) / 2, y, color::white, 2, "No network");
        add(f, (Frame::width - text_w("selected", 2)) / 2, y + pitch2, color::white, 2, "selected");
        y += 2 * pitch2;
    } else {
        const char* what = v.overlay != Overlay::None ? v.overlay_label : v.mood_label;
        y = wrap(f, y, color::white, what, y + 2 * pitch2, 2, pitch2, nullptr, 2, true);
        char age[16];
        if (v.last_seen_known) { age_text(age, sizeof age, v.last_seen_ms); add(f, (Frame::width - text_w(age, 2)) / 2, y + 4, color::grey, 2, "%s", age); }
        else if (v.has_selection) add(f, (Frame::width - text_w("No reading", 2)) / 2, y + 4, color::grey, 2, "No reading");
        y += 4 + pitch2;
    }
    // G16E: area observations need no selection: amber inside the NoData zone, under the message.
    if ((v.caution || v.router_amber) && !v.alert && !v.demo) {
        const int top = std::max(y + 2, 124), last = 151;
        if (top <= last) {   // G25: the router's change first (it is about your network), else the nearby observation
            char text[160];
            if (v.router_amber) router_banner(v.router, text, sizeof text, (last - top) / pitch1 + 1, cols1);
            else area_banner(v.caution_evidence, text, sizeof text, (last - top) / pitch1 + 1, cols1);
            bool cut = false; wrap(f, top, amber, text, last, 1, pitch1, &cut);
        }
    }
    if (v.alert) { alert_hud(p, st, f); return; }
    Rows rows{f, 183};
    if (!v.has_selection) rows.line(color::white, "hold side: choose a network");
    rows.line(st.radio == RadioState::Monitoring ? color::grey : color::orange, radio_text(st.radio));
    const char* store = store_short(st.store);
    if (store) rows.line(color::orange, store);
    const bool radar = !v.demo && radar_row(f, st, hint1_y);
    hints(f, radar ? nullptr : "blue: info", "hold side: networks");
}

void face_screen(const Presenter& p, const Status& st, Frame& f) {
    const auto& v = p.view();
    const bool rated = v.face != Mood::Unknown && !v.muted;   // a fresh rating (G08: muted = Unknown or historical)
    f.face_shown = true; f.face = v.face; f.muted = v.muted; f.alert = v.alert; f.celebrate = v.celebrate && !v.alert && rated;
    f.caution = (v.caution || v.router_amber) && !v.alert && !v.demo;   // G16E: red owns the face; amber only without an ALERT (G25: the router too)
    f.face_color = v.alert ? color::red : v.muted ? color::grey : mood_color(v.face);
    f.header_color = f.caution ? amber : f.face_color;
    f.art = v.alert ? (rated ? FaceArt::Alert : FaceArt::NoData) : rated ? FaceArt::Rated : FaceArt::NoData;
    f.persona = st.persona_art;
    f.hud.shown = true; f.hud.incident = v.alert;
    listen_flags(f, st);
    header(f, v);
    if (f.art == FaceArt::NoData) no_data_hud(p, st, f);
    else if (v.demo) demo_hud(p, f);
    else if (v.alert) alert_hud(p, st, f);
    else rated_hud(p, st, f);
}

// ---- details pages: same header and HUD language, body planned by the Presenter --------
struct Page {
    Frame& f; int y; bool cut{};
    void line(std::uint16_t color, const char* format, ...)
#if defined(__GNUC__)
        __attribute__((format(printf, 3, 4)))
#endif
    {
        char text[400]; va_list args; va_start(args, format);
        const int w = std::vsnprintf(text, sizeof text, format, args); va_end(args);
        if (w < 0 || static_cast<std::size_t>(w) >= sizeof text) ++f.overflow;   // never cut text silently
        bool c = false; y = wrap(f, y, color, text, details_body_last, 1, pitch1, &c); cut |= c;
        if (c) ++f.overflow;   // every page is planned to fit entirely
    }
    void pair(std::uint16_t color, const char* label, const char* value) {
        if (std::strlen(label) + 1 + std::strlen(value) <= static_cast<std::size_t>(cols1)) line(color, "%s %s", label, value);
        else { line(color, "%s", label); line(color, "  %s", value); }
    }
};

// G16S: the most frequent (receiver, sender, access point, channel) tuple of a disconnect burst,
// two short rows with the last two bytes of each address (the full addresses are in STATUS).
// Header bytes as heard: evidence in white beside the count, never part of the red sentence.
constexpr int tuple_rows = 2;
constexpr char nearby_footer[] = "Seen nearby, not on your network. Never changes the rating.";
void tuple_lines(Page& pg, const BurstTuple& t) {
    const auto to = mac_text(t.receiver), from = mac_text(t.sender), ap = mac_text(t.bssid);
    pg.line(color::white, "to %s from %s", to.c_str() + 12, from.c_str() + 12);
    pg.line(color::white, "AP %s ch%u x%u", ap.c_str() + 12, unsigned(t.channel), unsigned(t.count));
}
// Rows the mandatory lines of one Nearby entry take (its sentence, its sources, its age).
int nearby_rows(const IncidentObservation& o) {
    char text[160];
    std::snprintf(text, sizeof text, "%s: %u %s / %u s", area_text(o), unsigned(o.count), area_unit(o), unsigned((o.window_ms + 999) / 1000));
    return static_cast<int>(wrapped_rows(text, static_cast<std::size_t>(cols1))) + (o.distinct_sources ? 1 : 0) + 1;
}

void details_screen(const Presenter& p, const Status& st, Frame& f) {
    const auto& v = p.view(); const auto& d = p.details();
    f.header_color = v.alert ? color::red : color::yellow;
    f.hud.shown = true; listen_flags(f, st); f.hud.incident = v.alert;
    header(f, v);
    wrap(f, details_title_y, cyan, d.title, details_title_y + pitch1);
    if (v.alert) {   // G16R: the same sentence as the face (the network by its name)
        char sentence[160];
        if (v.router_alert) router_banner(v.router, sentence, sizeof sentence, 2, cols1);   // G25: the words that fit two rows
        else alert_sentence(v, sentence, sizeof sentence, static_cast<std::size_t>(cols1));
        wrap(f, details_status_y, color::red, sentence, details_status_y + pitch1);
    }
    else if (v.demo) add(f, 2, details_status_y, color::yellow, 1, "simulated example");
    else if (v.router_amber) {   // G25: the router's change, in the words that fit the two status rows
        char text[160]; router_banner(v.router, text, sizeof text, 2, cols1);
        wrap(f, details_status_y, amber, text, details_status_y + pitch1);
    }
    else if (v.caution) wrap(f, details_status_y, amber, v.caution_reason, details_status_y + pitch1);   // G16E
    Page pg{f, details_body_y};
    switch (d.page) {
    case DetailsPage::Settings:
        if (v.face == Mood::Unknown) {
            pg.line(color::white, "Rating: Not rated");
            pg.line(color::grey, "(%s)", v.overlay == Overlay::None ? "no grade" : v.overlay_label);
        } else pg.line(mood_color(v.face), "Rating: %s", d.mood_label);
        pg.pair(color::white, "Mode:", d.mode_label);
        pg.line(color::white, "Cipher: %s", d.pairwise_label);
        pg.line(color::white, "Group cipher: %s", d.group_label);
        pg.line(color::white, "PMF: %s", d.pmf_label);
        if (d.age_known) {
            pg.line(color::white, "Evidence age: %u s%s", unsigned(d.age_ms / 1000), d.advice.signal.available ? "," : "");
            if (d.advice.signal.available) pg.line(color::white, "heard on ch %u", unsigned(d.advice.signal.channel));
        } else pg.line(color::white, "Evidence age: none");
        {   // G25: the router's own channel moves, one grey line (re-baselined, never an alert)
            char moved[40];
            if (move_line(v.router, moved, sizeof moved)) pg.line(color::grey, "%s", moved);
        }
        pg.y += 3;
        pg.line(color::grey, "Not measured: password strength, router patch status, 5 GHz, actual client negotiation.");
        pg.line(color::grey, "Weak signal, Internet loss or a dictionary test never change it.");
        break;
    case DetailsPage::Explanation:
        // The Presenter planned this sub-page by wrapped rows (details_text_budget): it fits.
        if (d.page_index == 0) pg.line(color::white, "%s", advice_text(d.advice.next_step));
        for (std::uint8_t i = 0; i < d.item_count; ++i) pg.line(color::grey, "%s", advice_text(d.advice.items[d.first_item + i]));
        break;
    case DetailsPage::SignalAndEvidence: {
        pg.line(color::white, "Evidence: %s", d.coverage_label);
        if (d.has_coverage) {
            const auto& c = d.coverage;
            pg.line(color::white, "Listened %u/%u ms", unsigned(c.listened_ms), unsigned(c.window_ms));
            pg.line(color::white, "Drops in window: %u", unsigned(c.dropped_in_window));
            pg.line(color::white, "Channel %u", unsigned(c.channel));
            if (c.hopping) pg.line(color::white, "hopping (gaps)");
        } else pg.line(color::grey, "No listening report");
        const auto& s = d.advice.signal;
        if (s.available && s.rssi_valid) {
            pg.line(color::white, "Signal here: %d dBm", int(s.rssi_dbm));
            pg.line(color::white, "  measured %u s ago", unsigned(s.age_ms / 1000));
        } else pg.line(color::grey, "Signal: no reading");
        pg.line(color::grey, "Signal never changes the rating.");
        if (d.incident.visible) {
            const auto& b = d.incident;
            pg.line(color::red, "Seen %u (raw %u)", unsigned(b.count), unsigned(b.raw_frames));
            if (b.top.count) {   // G16S: who the frames named, when these rows and the rest of the block fit
                char listened[48]; std::snprintf(listened, sizeof listened, "Listened %u/%u ms", unsigned(b.listened_ms), unsigned(b.coverage_window_ms));
                const int rest = 3 + (b.saturated ? 1 : 0) + (b.shapes ? static_cast<int>(wrapped_rows(tool_shape_text(b.shapes), static_cast<std::size_t>(cols1))) : 0)
                    + (b.coverage_known ? static_cast<int>(wrapped_rows(listened, static_cast<std::size_t>(cols1))) + (b.hopping ? 1 : 0) : 0);
                if (pg.y + (tuple_rows + rest - 1) * pitch1 <= details_body_last) tuple_lines(pg, b.top);
            }
            pg.line(color::red, "Threshold %u", unsigned(b.threshold));
            pg.line(color::red, "Retries %u", unsigned(b.retries_deduped));
            pg.line(color::red, "Protected %u", unsigned(b.protected_frames));
            if (b.saturated) pg.line(color::red, "(lower bound)");
            if (b.shapes) pg.line(color::red, "%s", tool_shape_text(b.shapes));   // G16J
            if (b.coverage_known) {
                pg.line(color::red, "Listened %u/%u ms", unsigned(b.listened_ms), unsigned(b.coverage_window_ms));
                if (b.hopping) pg.line(color::red, "hopping");
            }
        }
        break;
    }
    case DetailsPage::OwnerChecks:
        for (std::uint8_t i = 0; i < d.check_count; ++i) pg.line(color::grey, "%s", advice_text(d.advice.owner_checks[d.first_check + i].id));
        break;
    case DetailsPage::Nearby: {   // G16E: every current area observation with count / window / sources / age
        if (!d.nearby_count) pg.line(color::grey, "Nothing nearby right now.");
        bool tuple_shown = false;   // G16S: once, under the newest disconnect observation (they share one burst)
        for (std::uint8_t i = 0; i < d.nearby_count; ++i) {
            const auto& o = d.nearby[i];
            pg.line(amber, "%s: %u %s / %u s", area_text(o), unsigned(o.count), area_unit(o), unsigned((o.window_ms + 999) / 1000));
            if (o.distinct_sources) pg.line(color::white, "from %u %saddresses%s", unsigned(o.distinct_sources), o.sources_random ? "random " : "", o.saturated ? " (or more)" : "");
            if (o.top.count && !tuple_shown) {
                // Only when the two rows, this entry's age row, every later entry and the footer still fit.
                int rest = 1 + static_cast<int>(wrapped_rows(nearby_footer, static_cast<std::size_t>(cols1)));
                for (std::uint8_t k = static_cast<std::uint8_t>(i + 1); k < d.nearby_count; ++k) rest += nearby_rows(d.nearby[k]);
                if (pg.y + (tuple_rows + rest - 1) * pitch1 <= details_body_last) { tuple_lines(pg, o.top); tuple_shown = true; }
            }
            // G16J noise floor: which channel, and the receive-error share as EVIDENCE (never the rule). The
            // share exists only when the radio delivers checksum-failed frames (handshake watch on).
            if (o.pattern == Pattern::NoiseFloor && o.channel && pg.y + 5 * pitch1 <= details_body_last) {
                if (o.corroborating && o.raw_frames) pg.line(color::white, "channel %u: %u of %u frames had errors", unsigned(o.channel), unsigned(o.corroborating), unsigned(o.raw_frames));
                else pg.line(color::white, "channel %u", unsigned(o.channel));
            }
            pg.line(color::grey, "%u s ago, threshold %u", unsigned(d.nearby_age_ms[i] / 1000), unsigned(o.threshold));
            // G16J: the tool-shape sentence, when its two rows and the footer still fit.
            if (o.shapes && pg.y + 4 * pitch1 <= details_body_last) pg.line(amber, "%s", tool_shape_text(o.shapes));
        }
        pg.line(color::grey, "%s", nearby_footer);
        break;
    }
    case DetailsPage::Limits: {   // G16J: every blind spot, in words
        const std::uint8_t ch = st.radio == RadioState::Monitoring ? heard_channel(d) : 0;
        if (ch && st.area_sweep) pg.line(color::white, "2.4 GHz, channel %u + area sweep, no 5 GHz, passive", unsigned(ch));
        else if (ch) pg.line(color::white, "2.4 GHz, channel %u only, no 5 GHz, passive", unsigned(ch));
        else pg.line(color::white, "2.4 GHz only, no 5 GHz, passive");
        if (st.handshake == HandshakeWatch::On) pg.line(color::white, "handshake watch: on");
        else pg.line(color::orange, "handshake watch: off%s", st.handshake == HandshakeWatch::OffLoad ? " (load)" : "");
        switch (st.dark_guard) {   // G16N: guarding with the screen off, from the measured drain only
        case DarkGuard::Hidden: break;
        case DarkGuard::Off: pg.line(color::grey, "dark guard: off"); break;
        case DarkGuard::NotMeasured: pg.line(color::grey, "dark guard: not measured yet"); break;
        case DarkGuard::Measured:
            if (st.dark_guard_h10 < 10) pg.line(color::white, "dark guard: under 1 h left");
            else pg.line(color::white, "dark guard: about %u h left", unsigned(st.dark_guard_h10 / 10));
            break;
        }
        pg.y += 3;
        pg.line(color::grey, "Never seen: 5 GHz and 6 GHz, other channels while locked, radios that only listen, "
                             "attacks after joining (ARP, DHCP, DNS), Bluetooth.");
        pg.line(color::grey, "It says what it saw, never who sent it.");
        break;
    }
    case DetailsPage::Router: {   // G25: what the router changed, old -> new, and the owner's choice
        const auto& r = v.router;
        const std::uint16_t ink = r.change_tone == Tone::Red ? color::red : r.change_tone == Tone::Amber ? amber : color::white;
        char text[200];
        if (r.change.pending) {
            if (router_sentence(r, RouterWording::Full, text, sizeof text)) pg.line(ink, "%s", text);
            if (r.age_known) pg.line(color::white, "seen %u times, %u s ago", unsigned(r.change.count), unsigned(r.age_ms / 1000));
            else pg.line(color::white, "seen %u times", unsigned(r.change.count));
            const auto ap = mac_text(r.change.bssid);
            pg.line(color::white, "AP ..:%s", ap.c_str() + 12);
            if (r.pending > 1) pg.line(color::white, "%u of your APs changed", unsigned(r.pending));
        }
        if (r.move_unacked && router_sentence(r, RouterWording::Full, text, sizeof text) && !r.change.pending) pg.line(amber, "%s", text);
        pg.y += 3;
        pg.line(color::grey, "Routers change settings after an update or a restart. If nobody did, check the router.");
        break;
    }
    case DetailsPage::Count: break;
    }
    if (d.page == DetailsPage::Router) {   // G25: hold SIDE here accepts the new settings
        add(f, 2, hint1_y, cyan, 1, "blue: next  side: back");
        add(f, 2, hint2_y, cyan, 1, "hold side: accept new");
        return;
    }
    add(f, 2, hint1_y, cyan, 1, "blue: next page");
    if (d.page_count > 1) add(f, 110, hint1_y, color::white, 1, "%u/%u", unsigned(d.page_index) + 1, unsigned(d.page_count));
    add(f, 2, hint2_y, cyan, 1, "side: back");
}

void picker_screen(const Presenter& p, const Status& st, Frame& f) {
    const auto& v = p.picker();
    f.header_color = color::yellow;
    f.hud.shown = true; listen_flags(f, st);
    header(f, p.view());
    add(f, 2, 21, cyan, 1, "NETWORKS");
    if (v.count) add(f, 62, 21, color::grey, 1, "%u heard", unsigned(v.count));
    if (!v.count) {
        add(f, 2, 33, color::white, 2, "Listening");
        add(f, 2, 53, color::grey, 1, "%s", radio_text(st.radio));
    }
    // Two 2x rows per network: the name, then the duplicate-name disambiguator or the signal.
    constexpr std::uint8_t rows = 5;
    constexpr int first_y = 31, pitch = 38;
    const std::uint8_t first = v.cursor >= rows ? static_cast<std::uint8_t>(v.cursor - rows + 1) : 0;
    for (std::uint8_t i = first, shown = 0; i < v.count && shown < rows; ++i, ++shown) {
        const auto& e = v.entries[i];
        const int y = first_y + shown * pitch;
        // Chosen network (and, G16J, the APs the owner approved as theirs): green. Highlighted row:
        // yellow with '>'. No other markers.
        const std::uint16_t c = i == v.cursor ? color::yellow : (e.selected || e.approved) ? color::green : color::white;
        // Header rule (G16C rework): a name longer than the 10-glyph slot ends in a visible '~'.
        char name[cols2 + 1], extra[cols2 + 1];
        shorten(name, sizeof name, e.label.c_str(), cols2 - 1);
        add(f, 2, y, c, 2, "%c%s", i == v.cursor ? '>' : ' ', name);
        shorten(extra, sizeof extra, e.disambiguator.data(), cols2 - 1);
        if (e.duplicate_name) add(f, 2, y + 17, c, 2, " %s", extra);
        else if (e.rssi_valid) add(f, 2, y + 17, c, 2, " %d dBm", int(e.rssi));
    }
    // G16J: on a row with the chosen network's name and another BSSID, holding blue says
    // "this AP is mine too" (or takes it back). Other rows keep the usual hint.
    const PickerEntry* cur = v.count && v.cursor < v.count ? &v.entries[v.cursor] : nullptr;
    hints(f, cur && cur->approvable ? (cur->approved ? "hold blue: not mine" : "hold blue: my AP") : "blue next  side choose", "hold side: back");
}

// ---- drawing helpers ---------------------------------------------------------------
// Decoration, drawn under the text: frame brackets, rules with moving ticks,
// a scanline over empty pixels, the listening indicator, RSSI bars and the
// (the IMU level line was removed 2026-11-17). Nothing here is a measurement except the bars (fresh RSSI)
// and the indicator (the radio's real state); motion is decoration only.
void draw_hud(Canvas& c, const Frame& f, const DrawInput& in) {
    // 2026-11-17: the held pose drives the HUD whenever the IMU is active (no "calm" gate), and the
    // white tap flash is gone (the owner's "white straps" while handling the stick).
    const bool moving = in.imu.active;
    const std::uint16_t rule = hud_dim;
    const int px = moving ? static_cast<int>(std::lround(in.imu.hud_dx)) : 0;
    const int py = moving ? static_cast<int>(std::lround(in.imu.hud_dy)) : 0;
    const int tick = static_cast<int>((in.anim_ms / 120) % 8);
    // Header separator with moving ticks.
    c.fill_rect(0, Frame::header_h - 1, Frame::width, 1, rule);
    for (int x = (tick + px + 64) % 8; x < Frame::width; x += 8) c.put(x, Frame::header_h - 2, rule);
    const bool face = f.face_shown;
    if (face) {
        // Face/HUD rule and brackets around the HUD block (parallax layer).
        c.fill_rect(0, zone_bottom, Frame::width, 1, rule);
        const int bx0 = 1 + std::max(0, px), bx1 = Frame::width - 2 + std::min(0, px), by0 = zone_bottom + 2 + std::max(0, py), by1 = Frame::height - 2;
        for (int k = 0; k < 5; ++k) {
            c.put(bx0 + k, by0, rule); c.put(bx0, by0 + k, rule); c.put(bx1 - k, by0, rule); c.put(bx1, by0 + k, rule);
            c.put(bx0 + k, by1, rule); c.put(bx0, by1 - k, rule); c.put(bx1 - k, by1, rule); c.put(bx1, by1 - k, rule);
        }
        // Scanline sweeping the HUD, over empty pixels only.
        const int sy = zone_bottom + 1 + static_cast<int>((in.anim_ms / 40) % static_cast<Millis>(Frame::height - zone_bottom - 1));
        for (int x = 0; x < Frame::width; ++x) if (c.get(x, sy) == color::black) c.put(x, sy, hud_faint);
    }
    // Listening indicator, bottom-right of the face zone (or above the hints elsewhere).
    if (f.hud.listening) {
        const int ix = 124, iy = face ? zone_bottom - 6 : hint1_y - 6;
        if (f.hud.sweeping) {
            const int lit = static_cast<int>((in.anim_ms / 150) % 3);
            for (int k = 0; k < 3; ++k) c.fill_rect(ix + k * 3, iy, 2, 2, k == lit ? cyan : hud_dim);
        } else if (f.hud.locked) {
            c.fill_rect(ix + 3, iy, 2, 2, cyan);
            if ((in.anim_ms / 500) % 2 == 0) c.draw_rect(ix + 1, iy - 2, 6, 6, hud_dim);
        }
    }
    // G16E threat radar: a 5x5 glyph per registered family. Dim when idle, cyan on a
    // counted event (pulse), amber/red while an incident of that family is visible.
    if (f.hud.radar) {
        static constexpr std::uint32_t shapes[static_cast<std::size_t>(DetectorFamily::Count)] = {
            0x1151151u, // Disconnect: an X (a broken link)
            0x0477d4eu, // Baseline: a house (the approved AP)
            0x0e89804u, // Probe: a question mark
            0x157108eu, // Beacon: a mast with waves
            0x1451554u, // Responder: an echo (two arcs)
            0x0c93c43u, // Auth: a key
            0x0417c44u, // ChannelSwitch: an arrow
            0x1f0fc88u, // Identity: two names that differ (=/)
            0x223888u, // Jamming (G16G): a lightning bolt (frames lost on the channel)
            0x4b32c4u, // Bluetooth (G16H): the rune (a spine with two angled arms)
        };
        for (std::size_t i = 0; i < f.hud.glyphs.size(); ++i) {
            const auto& g = f.hud.glyphs[i];
            if (!g.registered) continue;   // never decorated as measuring
            const std::uint16_t ink = g.active ? (g.scope == IncidentScope::Area ? amber : color::red) : g.pulse ? cyan : hud_dim;
            const int gx = f.hud.radar_x + static_cast<int>(i) * radar_cell, gy = f.hud.radar_y + 1;
            for (int b = 0; b < 25; ++b) if ((shapes[i] >> (24 - b)) & 1u) c.put(gx + b % 5, gy + b / 5, ink);
            if (g.pulse) c.draw_rect(gx - 1, gy - 1, 7, 7, g.active ? ink : hud_dim);
        }
    }
    // RSSI bars from the fresh reading (signal at this device only).
    if (f.hud.rssi) {
        for (int k = 0; k < 4; ++k) {
            const int h = 2 + k * 2 - (k == 3 ? 1 : 0), x = f.hud.rssi_x + k * 5, y = f.hud.rssi_y + 7 - h;
            if (k < f.hud.bars) c.fill_rect(x, y, 3, h, cyan); else c.draw_rect(x, y, 3, h, hud_dim);
        }
    }
}
void draw_placeholder(Canvas& c, const Frame& f) {
    // Placeholder block: drawn on a 64-unit grid, scaled to face_size (no art set on this build).
    const int x0 = Frame::face_x, y0 = Frame::face_y, s = Frame::face_size;
    if (f.art == FaceArt::NoData) { c.draw_rect(x0, y0, s, s, color::grey); return; }   // an empty outline: no rated face
    const auto r = [&](int x, int y, int w, int h, std::uint16_t col) {
        c.fill_rect(x0 + x * s / 64, y0 + y * s / 64, std::max(1, w * s / 64), std::max(1, h * s / 64), col);
    };
    r(0, 0, 64, 64, f.face_color);
    const std::uint16_t ink = color::black;
    if (f.alert) {                         // "!" sign: an alert, not a mood
        r(28, 10, 8, 30, ink); r(28, 46, 8, 8, ink);
        return;
    }
    r(16, 18, 8, 8, ink); r(40, 18, 8, 8, ink);
    switch (f.face) {
    case Mood::VeryGood: r(12, 40, 40, 4, ink); r(10, 34, 4, 8, ink); r(50, 34, 4, 8, ink); break;
    case Mood::Good: r(16, 42, 32, 4, ink); r(14, 38, 4, 6, ink); r(46, 38, 4, 6, ink); break;
    case Mood::Medium: r(16, 42, 32, 4, ink); break;
    case Mood::Bad: r(16, 42, 32, 4, ink); r(14, 44, 4, 6, ink); r(46, 44, 4, 6, ink); break;
    case Mood::Horrible: r(12, 40, 40, 4, ink); r(10, 42, 4, 10, ink); r(50, 42, 4, 10, ink); break;
    case Mood::Unknown: break;
    }
    if (f.celebrate) { r(50, 40, 12, 4, color::white); r(60, 40, 3, 4, color::orange); } // placeholder cigar
}
const std::uint8_t* pick_art(const Frame& f, const persona::ArtSet& a, Millis t) {
    const int i = persona::rated_index(f.face);
    if (f.art == FaceArt::Rated && i >= 0) return a.rated[static_cast<std::size_t>(i)];
    if (f.art == FaceArt::Alert && i >= 0) return a.alert[static_cast<std::size_t>(i)][static_cast<std::size_t>(persona::alert_pulse(t))];
    return a.no_data;   // NoData, or any state without a fresh rating
}
} // namespace

void compose_onboarding(std::uint8_t page, Frame& f) {
    f = Frame{};
    f.header_color = color::yellow;
    switch (page) {
    case 0:
        add(f, 2, 2, color::yellow, 2, "Welcome!");
        wrap(f, 26, color::white, "I check how your Wi-Fi is protected.", 26 + 4 * pitch2, 2, pitch2);
        wrap(f, 26 + 5 * pitch2, color::grey, "Just listening. No password needed.", 26 + 8 * pitch2, 2, pitch2);
        break;
    case 1:
        add(f, 2, 2, color::yellow, 2, "Buttons");      // G16B: clear of the battery corner
        add(f, 2, 26, cyan, 2, "BLUE");      add(f, 2, 44, color::white, 2, "next / info");
        add(f, 2, 68, cyan, 2, "SIDE");      add(f, 2, 86, color::white, 2, "choose");
        add(f, 2, 110, cyan, 2, "HOLD SIDE"); add(f, 2, 128, color::white, 2, "list");
        // G24 retry: hold FRONT opens Settings (no key enters DEMO); G25: the Settings keys (owner 2026-11-23).
        wrap(f, 156, color::grey, "Hold BLUE: settings. There: SIDE next, hold SIDE save, BLUE back.", 200);
        break;
    default:
        add(f, 2, 2, color::yellow, 2, "Start");        // G16B: clear of the battery corner
        add(f, 2, 26, color::white, 2, "1 hold SIDE");
        wrap(f, 44, color::white, "2 BLUE: your Wi-Fi", 44 + pitch2, 2, pitch2);
        wrap(f, 80, color::white, "3 press SIDE", 80 + pitch2, 2, pitch2);
        wrap(f, 124, color::grey, "Red = alert. Grey = no fresh reading.", 200);
        break;
    }
    add(f, 2, hint2_y, cyan, 1, "press any button %u/%u", unsigned(page) + 1, unsigned(Companion::onboarding_pages));
}

// The two hint rows announce a TUNE session instead (any key ends it).
// G24: on the Settings screen its own key hints go too (during a session any key only ends it).
static void session_hints(Frame& f, const Status& st, bool settings) {
    std::uint8_t kept = 0;
    for (std::uint8_t i = 0; i < f.count && i < f.lines.size(); ++i) {
        const int y = f.lines[i].y;
        if (y == hint1_y || y == hint2_y || (settings && (y == settings_hint1_y || y == settings_hint2_y))) continue;
        f.lines[kept++] = f.lines[i];
    }
    f.count = kept;
    add(f, 2, hint1_y, color::yellow, 1, "TUNE WI-FI %us", unsigned(st.tune_session_s));
    add(f, 2, hint2_y, cyan, 1, "any key: end tune");
}

// G24: the Settings screen, exactly the owner-approved look (firmware/evidence/sticks3-G24-settings-look-20261121.png,
// "perfect", 2026-11-21): one big option per page, its MEASURED battery hours (or "not measured yet"), the
// highest / lowest measured marked, the cost in amber, the SAVED / SAVE FAILED plate and the key hints. The
// existing font and colours only; the battery indicator is the board's, as on every screen.
int settings_centred(const char* t, int scale) { return std::max(0, (Frame::width - text_w(t, scale)) / 2); }
void settings_line(Frame& f, int y, int scale, std::uint16_t c, const char* t) { add(f, settings_centred(t, scale), y, c, static_cast<std::uint8_t>(scale), "%s", t); }
// The SAVED / SAVE FAILED plate and the key hints (G25 keys, owner 2026-11-23: "SIDE changes", "hold side to save").
void settings_plate_and_hints(Frame& f, const SettingsView& sv) {
    if (sv.plate == SavePlate::Saved) plate(add(f, settings_centred("   SAVED   ", 2), 196, color::black, 2, "   SAVED   "), color::green);
    else if (sv.plate == SavePlate::Failed) plate(add(f, settings_centred("SAVE FAILED", 2), 196, color::white, 2, "SAVE FAILED"), color::red);
    settings_line(f, settings_hint1_y, 1, color::grey, "SIDE next  BLUE back");
    settings_line(f, settings_hint2_y, 1, color::grey, "hold SIDE = save");
}
void settings_screen(const Presenter& p, Frame& f) {
    const auto& sv = p.settings();
    const bool guard = sv.page == SettingsPage::Guard;
    f.header_color = color::grey;
    plate(add(f, 0, Frame::tag_y, color::black, 1, "SETTINGS %u/%u", unsigned(sv.number), unsigned(settings_pages)), color::grey);
    settings_line(f, 26, 1, color::grey, guard ? "GUARD ON BATTERY" : sv.page == SettingsPage::Router ? "ROUTER CHANGES" : "BRIGHTNESS");
    add(f, 2, 78, color::grey, 2, "<");
    add(f, Frame::width - 14, 78, color::grey, 2, ">");
    if (sv.page == SettingsPage::Router) {   // G25: how the router's own changes are coloured (no hours: costs nothing)
        switch (sv.shown.router) {
        case RouterPolicy::DetailsOnly:
            settings_line(f, 64, 2, color::white, "DETAILS"); settings_line(f, 86, 2, color::white, "ONLY");
            settings_line(f, 166, 1, color::grey, "router changes listed"); settings_line(f, 177, 1, color::grey, "on Details, no colour");
            break;
        case RouterPolicy::Amber:
            settings_line(f, 76, 2, color::white, "AMBER"); settings_line(f, 126, 1, color::grey, "default");
            settings_line(f, 166, 1, amber, "security change: amber"); settings_line(f, 177, 1, color::grey, "channel move: grey");
            break;
        case RouterPolicy::Strict:
            settings_line(f, 76, 2, color::white, "STRICT");
            settings_line(f, 166, 1, color::red, "security change: red"); settings_line(f, 177, 1, amber, "channel move: amber");
            break;
        }
        settings_plate_and_hints(f, sv);
        return;
    }
    Hours hours; Extreme mark = Extreme::None;
    char cost1[40] = "", cost2[40] = "";
    if (guard) {
        const auto g = sv.shown.guard;
        switch (g) {
        case GuardCycle::Always: settings_line(f, 76, 2, color::white, "ALWAYS"); break;
        case GuardCycle::Every30s: settings_line(f, 64, 2, color::white, "EVERY"); settings_line(f, 86, 2, color::white, "30 S"); break;
        case GuardCycle::EveryMinute: settings_line(f, 64, 2, color::white, "EVERY"); settings_line(f, 86, 2, color::white, "MINUTE"); break;
        }
        hours = guard_hours(g); mark = guard_extreme(g);
        const auto t = cycle_timing(g);
        if (t.off_ms == 0) std::snprintf(cost1, sizeof cost1, "never blind");
        else {   // docs/G23-delivery.md section 11.4: up to one off period late, a burst inside it is not counted
            std::snprintf(cost1, sizeof cost1, "alert up to %us late", unsigned(t.off_ms / 1000));
            std::snprintf(cost2, sizeof cost2, "short bursts missed");
        }
    } else {
        char big[16]; std::snprintf(big, sizeof big, "%u%%", unsigned(sv.shown.bright_pct));
        settings_line(f, 76, 3, color::white, big);
        hours = brightness_hours(sv.shown.bright_pct); mark = brightness_extreme(sv.shown.bright_pct);
        std::snprintf(cost1, sizeof cost1, "costs only while lit");
    }
    char h[16] = "";
    if (hours.measured && hours_text(hours.minutes, h, sizeof h)) settings_line(f, 120, 2, color::white, h);
    else settings_line(f, 126, 1, color::grey, "not measured yet");
    if (mark == Extreme::Lowest) settings_line(f, 142, 1, color::grey, "lowest, measured");
    else if (mark == Extreme::Highest) settings_line(f, 142, 1, color::green, "highest, measured");
    if (cost1[0]) settings_line(f, 166, 1, amber, cost1);
    if (cost2[0]) settings_line(f, 177, 1, amber, cost2);
    settings_plate_and_hints(f, sv);
}

void compose(const Presenter& p, const Status& st, Frame& f) {
    f = Frame{};
    switch (p.screen()) {
    case Screen::Face: face_screen(p, st, f); break;
    case Screen::Details: details_screen(p, st, f); break;
    case Screen::Picker: picker_screen(p, st, f); break;
    case Screen::Settings: settings_screen(p, f); break;   // G24
    }
    if (st.tune_session_s) session_hints(f, st, p.screen() == Screen::Settings);
}

void compose_dim(const Presenter& p, const Status& st, Frame& f) {
    f = Frame{};
    face_screen(p, st, f);
}

// G16E wary glance: 4 s period; still for 2.6 s, then 0.4 s ease to 3 px, 0.4 s hold,
// 0.4 s ease back, still; the next period looks the other way.
float glance_dx(Millis t) {
    constexpr float peak = 3.0f;
    const Millis phase = t % 4000;
    const float side = ((t / 4000) % 2) ? -1.0f : 1.0f;
    const auto ease = [](float x) { return x * x * (3.0f - 2.0f * x); };
    if (phase < 2600 || phase >= 3800) return 0.0f;
    if (phase < 3000) return side * peak * ease(static_cast<float>(phase - 2600) / 400.0f);
    if (phase < 3400) return side * peak;
    return side * peak * ease(static_cast<float>(3800 - phase) / 400.0f);
}

TextBudget details_text_budget() {
    return {static_cast<std::uint8_t>(cols1), static_cast<std::uint8_t>(details_body_rows), static_cast<std::uint8_t>(details_body_rows)};
}

namespace {
// Where the portrait goes: the face zone, the IMU pose, the amber glance.
persona::Placement face_placement(const Frame& f, const DrawInput& in) {
    persona::Placement at{zone_top, 0, 0, 0};
    const bool moving = in.imu.active;   // 2026-11-17: a held pose stays applied (no "calm" reset)
    // G16E: red ALERT = a stare (the IMU shift is ignored); amber = a wary glance on top of it.
    if (moving && !f.alert) { at.dx = in.imu.dx; at.dy = in.imu.dy; at.tilt_deg = in.imu.tilt_deg; at.scale = in.imu.scale; }
    if (f.caution && !f.alert) at.dx += glance_dx(in.anim_ms);
    return at;
}
bool has_art(const Frame& f, const DrawInput& in) { return f.persona && in.art && in.art->complete() && f.art != FaceArt::None; }
}

bool burst_allowed(const Frame& f) { return f.face_shown && f.persona && f.art == FaceArt::Rated && !f.alert; }
const std::uint8_t* face_art(const Frame& f, const DrawInput& in) {
    if (!f.face_shown || !has_art(f, in)) return nullptr;
    // G21: the 3D head's frame stands in for the fresh rated portrait only (the rule of the burst):
    // an ALERT pulse, the NoData silhouette and every other screen keep their 2D art.
    if (in.head && burst_allowed(f)) return in.head;
    return pick_art(f, *in.art, in.anim_ms);
}
persona::Pose face_pose(const Frame& f, const DrawInput& in) { return persona::pose_with(in.anim_ms, in.motion, face_placement(f, in)); }

void choose_head(const Frame& f, DrawInput& in, head3d::Head* head, bool hold) {
    in.head = nullptr;
    if (!head || !burst_allowed(f) || !has_art(f, in)) return;
    // The stick's pose from the motion model; without a mapped, running IMU: the front view.
    in.head = head->frame(persona::rated_index(f.face), in.imu.active ? in.imu.yaw_deg : 0.0f, in.imu.active ? in.imu.pitch_deg : 0.0f, hold);
}

void draw(Canvas& c, const Frame& f, const DrawInput& in) {
    c.clear(color::black);   // G16C: pure black everywhere, like the art (no lifted "dark" background)
    // G16I: a running burst is painted only over the fresh rated portrait it was made from; any
    // other frame (ALERT, no fresh data, another rating, another screen, no art) cancels it here.
    const std::uint8_t* shown = face_art(f, in);
    bool particles = false;
    if (in.burst && in.burst->active()) {
        particles = shown && burst_allowed(f) && in.burst->art() == shown;
        if (!particles) in.burst->cancel();
    }
    if (f.face_shown) {
        if (particles) in.burst->paint(c, zone_top);   // no warp, ember, smoke: the particles are the face
        else if (shown) {
            const auto at = face_placement(f, in);
            // G21: the Very good ember and smoke sit on the 2D portrait's cigar tip; a 3D frame has it elsewhere.
            persona::paint_portrait(c, shown, in.anim_ms, at, persona::Layers{}, in.motion,
                                    f.art == FaceArt::Rated && f.celebrate && shown != in.head, in.cache);
        } else draw_placeholder(c, f);
        if (f.art == FaceArt::NoData) {   // marker: a dashed band above and below the message
            for (int x = 0; x < Frame::width; x += 6) { c.fill_rect(x, 60, 3, 1, color::grey); c.fill_rect(x, 160, 3, 1, color::grey); }
        }
    }
    if (f.alert) c.draw_rect(0, 0, c.width(), c.height(), color::red);
    else if (f.caution) {   // G16E: a dashed amber border (3 on, 3 off), never the solid red ALERT frame
        for (int x = 0; x < c.width(); x += 6) { c.fill_rect(x, 0, 3, 1, amber); c.fill_rect(x, c.height() - 1, 3, 1, amber); }
        for (int y = 0; y < c.height(); y += 6) { c.fill_rect(0, y, 1, 3, amber); c.fill_rect(c.width() - 1, y, 1, 3, amber); }
    }
    if (f.demo_badge) c.fill_rect(Frame::badge_x, Frame::badge_y, Frame::badge_w, Frame::badge_h, color::yellow);
    if (f.hud.shown) draw_hud(c, f, in);
    for (std::uint8_t i = 0; i < f.count && i < f.lines.size(); ++i) {
        const auto& l = f.lines[i];
        if (l.plated) c.fill_rect(l.x - 1, l.y - 1, text_w(l.text.data(), l.scale) + 1, 8 * l.scale + 1, l.plate);
    }
    for (std::uint8_t i = 0; i < f.count && i < f.lines.size(); ++i) {
        const auto& l = f.lines[i];
        c.text(l.x, l.y, l.text.data(), l.color, l.scale);
    }
}

} // namespace guardian::companion
namespace guardian::companion {
void compose_edge_test(Frame& f) {
    f = Frame{};
    add(f, 4, 6, color::white, 2, "EDGE TEST");
    add(f, 4, 30, color::red, 2, "TOP red");
    add(f, 4, 52, color::green, 1, "RIGHT green");
    add(f, 4, 63, color::blue, 1, "BOTTOM blue");
    add(f, 4, 74, color::yellow, 1, "LEFT yellow");
    add(f, 4, 124, color::white, 1, "1 px border on every");
    add(f, 4, 133, color::white, 1, "edge. Stand the stick");
    add(f, 4, 142, color::white, 1, "USB down: TOP is up.");
    add(f, 4, 160, color::grey, 1, "Missing colour = an");
    add(f, 4, 169, color::grey, 1, "unwritten panel line.");
    add(f, 4, 222, color::grey, 1, "EDGE 0 or a key: exit");
}
void draw_edge_test(Canvas& c) {
    c.clear(color::black);
    const int w = c.width(), h = c.height();
    c.fill_rect(0, 0, w, 1, color::red);              // top
    c.fill_rect(0, h - 1, w, 1, color::blue);         // bottom
    c.fill_rect(0, 1, 1, h - 2, color::yellow);       // left
    c.fill_rect(w - 1, 1, 1, h - 2, color::green);    // right
    Frame f; compose_edge_test(f);
    for (std::uint8_t i = 0; i < f.count; ++i) c.text(f.lines[i].x, f.lines[i].y, f.lines[i].text.data(), f.lines[i].color, f.lines[i].scale);
}
// G16D: the dim view (see companion.hpp). The placeholder block is the rating
// glyph: mood colour + mouth for a fresh rating, the "!" sign on red for an
// ALERT, an empty grey outline without a fresh rating; nothing else is lit.
void draw_dim(Canvas& c, const Frame& f, const persona::ArtSet* art) {
    c.clear(color::black);
    const bool portrait = f.persona && art && art->complete() && f.art != FaceArt::None;
    int label_y = Frame::face_y + Frame::face_size + 14;
    if (portrait) {   // review 2026-11-17: the owner's portrait, still (t = 0, portrait layer only, no IMU)
        const persona::Placement at{zone_top, 0, 0, 0};
        persona::paint_portrait(c, pick_art(f, *art, 0), 0, at, persona::Layers{true, false, false}, persona::Motion{}, false, nullptr);
        if (f.alert) c.draw_rect(0, 0, c.width(), c.height(), color::red);
        label_y = zone_bottom + 10;
    } else draw_placeholder(c, f);
    // Review 2026-11-17: a DEMO face never passes for a reading while dimmed (the badge is not drawn here).
    const char* label = f.alert ? "ALERT" : f.demo_badge ? "DEMO" : f.art == FaceArt::Rated ? mood_text(f.face) : "NO DATA";
    const std::uint16_t ink = f.alert ? color::red : f.demo_badge ? color::yellow : f.art == FaceArt::Rated ? f.face_color : color::grey;
    const int w = static_cast<int>(std::strlen(label)) * Canvas::glyph_advance * 2 - 2;
    c.text((Frame::width - w) / 2, label_y, label, ink, 2);
    // Review 2026-11-17: a nearby (amber) observation stays visible while dimmed:
    // an amber edge and one word. Never with an ALERT (that is shown alone, red).
    if (f.caution && !f.alert) {
        c.draw_rect(0, 0, Frame::width, Frame::height, amber);
        const char* near = "NEARBY";
        const int nw = static_cast<int>(std::strlen(near)) * Canvas::glyph_advance - 1;
        c.text((Frame::width - nw) / 2, label_y + 26, near, amber, 1);
    }
}

// G16N: black, and one grey sentence on two short rows (22 glyphs fit a row of the 135 px panel).
void draw_dark_notice(Canvas& c) {
    c.clear(color::black);
    constexpr int glyph = 6, row1 = 108, row2 = row1 + 13;
    c.text((c.width() - 20 * glyph) / 2, row1, "guarding in the dark", color::grey, 1);
    c.text((c.width() - 13 * glyph) / 2, row2, "press to look", color::grey, 1);
}

} // namespace guardian::companion

// G16E experience checks (TDD, run RED first; logs in builds/20261117-g16e-host/red-*.log in the store):
//   * red for YOUR network (today's ALERT), amber for NEARBY observations: the
//     amber banner states the observation in words with count / window /
//     sources, never changes the rating label, suppresses the celebration;
//   * a Nearby details page lists every current area observation;
//   * the live threat radar: one glyph slot per detector family, only
//     registered detectors are drawn, a pulse only on a counted event, real
//     rates (probes / beacons per minute, distinct transmitters);
//   * the face reacts per class: amber = a wary glance, red = a stare.
// Golden checks on the composed frame (text, colours, flags) plus a few pixels
// of the real renderer. Host input only, never radio proof.
#include "check.hpp"
#include "companion.hpp"
#include "fixtures.hpp"

#include "guardian/rating.hpp"

#include <cmath>
#include <cstring>
#include <string>
#include <vector>

using namespace guardian;
using namespace guardian::companion;
using guardian::measurement::Monitor;
using guardian::measurement::Packet;
using guardian::measurement::Radar;

namespace {
class Clock final : public MonotonicClock {
public:
    Millis at{100};
    Millis now() const override { return at; }
    TimeEpoch epoch() const override { TimeEpoch e{}; e.source_id[0] = 1; e.boot_id = 1; return e; }
};
class MemoryBlob final : public BlobStorage {
public:
    std::vector<std::uint8_t> bytes; bool exists{};
    BlobRead read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const override {
        if (!exists) return BlobRead::Absent;
        if (bytes.size() > capacity) return BlobRead::Error;
        std::memcpy(out, bytes.data(), bytes.size()); size = bytes.size(); return BlobRead::Ok;
    }
    bool write(const std::uint8_t* data, std::size_t size) override { bytes.assign(data, data + size); exists = true; return true; }
};
const Mac kHome{0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
Network home() {
    Network n{}; n.bssid = kHome; n.ssid_size = 4;
    n.ssid[0] = 'h'; n.ssid[1] = 'o'; n.ssid[2] = 'm'; n.ssid[3] = 'e';
    return n;
}
Instant at(const Clock& c, Millis t) { return Instant{c.epoch(), t, true}; }
DisplayCapabilities lcd() { return {Support::Supported, 135, 240, PixelFormat::Rgb565, Support::Supported}; }

std::vector<std::uint8_t> fixture(check::Case& c_, const char* name) {
    fixtures::Fixture f; std::string err;
    if (!fixtures::load(name, f, err)) CHECK_FAIL(err);
    return f.bytes;
}
Packet packet(const Clock& clock, const std::vector<std::uint8_t>& b) {
    Packet p{}; std::memcpy(p.bytes.data(), b.data(), b.size()); p.size = static_cast<std::uint16_t>(b.size());
    p.meta.acquired = {clock.epoch(), clock.now(), true}; p.meta.origin = Origin::LiveRadio; p.meta.status = RxStatus::Ok;
    p.meta.channel = 6; p.meta.rssi_dbm = -50; p.meta.rssi_valid = true;
    return p;
}
IncidentObservation probe_flood(const Clock& c, Millis t) {
    IncidentObservation o{};
    o.scope = IncidentScope::Area; o.family = DetectorFamily::Probe; o.origin = Origin::LiveRadio;
    o.acquired = at(c, t); o.count = 312; o.window_ms = 5000; o.threshold = 80;
    o.distinct_sources = 214; o.sources_random = true;
    return o;
}
IncidentObservation disconnect_burst(const Clock& c, Millis t) {
    IncidentObservation o{};
    o.scope = IncidentScope::Network; o.family = DetectorFamily::Disconnect; o.kind = IncidentKind::DisconnectBurst;
    o.affected = home(); o.bssid = kHome; o.origin = Origin::LiveRadio;
    o.acquired = at(c, t); o.count = 24; o.window_ms = 10000; o.threshold = 20;
    return o;
}
// A fresh VeryGood selection with optional area / network incidents, through the real Core.
Snapshot scene(check::Case& c_, Clock& clock, bool area, bool network) {
    Core core(clock, profiles::all_2g4_channels());
    core.select(home());
    const auto b = fixture(c_, "beacon_wpa3_sae_pmf_required");
    const auto p = packet(clock, b);
    core.security(observe_security(SecurityFrameParser{}.parse(p.span(), p.meta), p.meta));
    if (area) core.incident(probe_flood(clock, clock.at));
    if (network) core.incident(disconnect_burst(clock, clock.at));
    return core.snapshot();
}
bool has(const Frame& f, const char* needle) {
    for (std::uint8_t i = 0; i < f.count; ++i) if (std::strstr(f.lines[i].text.data(), needle)) return true;
    return false;
}
std::string joined(const Frame& f, std::uint16_t colour) {
    std::string out;
    for (std::uint8_t i = 0; i < f.count; ++i) if (f.lines[i].color == colour) { if (!out.empty()) out += ' '; out += f.lines[i].text.data(); }
    return out;
}
const Line* line_with(const Frame& f, const char* needle) {
    for (std::uint8_t i = 0; i < f.count; ++i) if (std::strstr(f.lines[i].text.data(), needle)) return &f.lines[i];
    return nullptr;
}
int line_w(const Line& l) { return static_cast<int>(std::strlen(l.text.data())) * Canvas::glyph_advance * l.scale; }
bool inside_panel_no_overlap(const Frame& f) {
    if (f.overflow) return false;
    for (std::uint8_t i = 0; i < f.count; ++i) {
        const auto& a = f.lines[i];
        const int ah = (Canvas::glyph_h + 1) * a.scale;
        if (a.x < 0 || a.y < 0 || a.x + line_w(a) > Frame::width || a.y + ah > Frame::height) return false;
        if ((f.art == FaceArt::Rated || f.art == FaceArt::Alert) && a.y < Frame::face_zone_y + Frame::face_zone_h && a.y + ah > Frame::face_zone_y) return false;
        for (std::uint8_t j = i + 1; j < f.count; ++j) {
            const auto& b = f.lines[j]; const int bh = (Canvas::glyph_h + 1) * b.scale;
            if (a.x < b.x + line_w(b) && b.x < a.x + line_w(a) && a.y < b.y + bh && b.y < a.y + ah) return false;
        }
    }
    return true;
}
Radar radar_with_rates() {
    Radar r{}; r.known = true;
    r.families[static_cast<std::size_t>(DetectorFamily::Disconnect)].registered = true;
    r.families[static_cast<std::size_t>(DetectorFamily::Disconnect)].pulse = true;
    r.families[static_cast<std::size_t>(DetectorFamily::Baseline)].registered = true;
    r.air.known = true; r.air.probes = 12; r.air.beacons = 340; r.air.transmitters = 23; r.air.window_ms = 60000;
    return r;
}
} // namespace

// ---- presenter ------------------------------------------------------------------------------
GUARDIAN_CASE(area_observation_is_amber_and_never_changes_the_rating) {
    Clock clock; clock.at = 1000;
    Presenter p(lcd());
    p.update(scene(c_, clock, true, false), at(clock, 1000));
    const auto& v = p.view();
    CHECK(v.caution);
    CHECK(!v.alert);
    CHECK_EQ(v.face, Mood::VeryGood);                    // the rating label stays
    CHECK(!v.celebrate);                                 // but no celebration while a flood is nearby
    CHECK_EQ(v.caution_count, 1);
    CHECK_EQ(std::string(v.caution_reason), std::string("Probe flood nearby"));
    CHECK_EQ(v.caution_evidence.count, 312u);
    CHECK(v.caution_age_known);
    CHECK_EQ(std::string(area_unit(DetectorFamily::Probe)), std::string("probes"));
}

GUARDIAN_CASE(network_incident_is_red_and_wins_over_amber) {
    Clock clock; clock.at = 1000;
    Presenter p(lcd());
    p.update(scene(c_, clock, true, true), at(clock, 1000));
    const auto& v = p.view();
    CHECK(v.alert);
    CHECK(v.caution);
    CHECK_EQ(std::string(v.alert_reason), std::string("Disconnect burst detected"));
    Presenter only_red(lcd());
    only_red.update(scene(c_, clock, false, true), at(clock, 1000));
    CHECK(only_red.view().alert); CHECK(!only_red.view().caution);
}

GUARDIAN_CASE(amber_expires_with_the_area_visibility_and_never_breaks_demo) {
    Clock clock; clock.at = 1000;
    Presenter p(lcd());
    const auto s = scene(c_, clock, true, false);
    p.update(s, at(clock, 1000));
    CHECK(p.view().caution);
    p.handle(Action::Tick, at(clock, 1000 + s.area_visible_ms - 1)); CHECK(p.view().caution);
    p.handle(Action::Tick, at(clock, 1000 + s.area_visible_ms)); CHECK(!p.view().caution);
    Presenter demo(lcd());
    demo.update(scene(c_, clock, false, false), at(clock, 1000));
    CHECK(demo.set_demo(true));   // G24 retry: the direct method (no key enters DEMO)
    demo.update(scene(c_, clock, true, false), at(clock, 1002));
    CHECK_EQ(demo.mode(), ViewMode::Demo);              // a nearby observation is advisory: DEMO stays
    CHECK(!demo.view().caution);
}

GUARDIAN_CASE(nearby_details_page_lists_current_area_observations_only_when_there_are_some) {
    Clock clock; clock.at = 1000;
    Presenter p(lcd());
    p.update(scene(c_, clock, true, false), at(clock, 1000));
    CHECK(p.handle(Action::Primary, at(clock, 1001)));
    bool reached = false;
    for (int i = 0; i < 30 && p.screen() == Screen::Details; ++i) {
        if (p.details().page == DetailsPage::Nearby) {
            reached = true;
            CHECK_EQ(p.details().nearby_count, 1);
            CHECK_EQ(p.details().nearby[0].family, DetectorFamily::Probe);
            CHECK_EQ(std::string(p.details().title), std::string("Nearby observations"));
        }
        p.handle(Action::Primary, at(clock, 1002 + static_cast<Millis>(i)));
    }
    CHECK(reached);
    CHECK_EQ(p.screen(), Screen::Face);
    Presenter quiet(lcd());
    quiet.update(scene(c_, clock, false, false), at(clock, 1000));
    quiet.handle(Action::Primary, at(clock, 1001));
    for (int i = 0; i < 30 && quiet.screen() == Screen::Details; ++i) {
        CHECK(quiet.details().page != DetailsPage::Nearby);
        quiet.handle(Action::Primary, at(clock, 1002 + static_cast<Millis>(i)));
    }
}

// ---- composed frames (golden) ------------------------------------------------------------------
GUARDIAN_CASE(amber_banner_states_the_observation_in_words) {
    Clock clock; clock.at = 1000;
    Presenter p(lcd()); p.set_text_budget(details_text_budget());
    p.update(scene(c_, clock, true, false), at(clock, 1000));
    Frame f; Status st{}; st.radio = RadioState::Monitoring; st.persona_art = true;
    compose(p, st, f);
    CHECK(f.caution);
    CHECK(!f.alert);
    CHECK_EQ(f.art, FaceArt::Rated);
    CHECK(!f.celebrate);
    CHECK_EQ(joined(f, amber), std::string("Probe flood nearby: 312 probes / 5 s from 214 random addresses"));
    CHECK(has(f, "Very good"));                          // the rating label is still shown
    CHECK(!has(f, "ALERT"));
    CHECK(!has(f, "attack")); CHECK(!has(f, "hack"));
    const Line* tag = line_with(f, "LIVE");
    CHECK(tag != nullptr);
    if (tag) { CHECK(tag->plated); CHECK_EQ(tag->plate, amber); }
    CHECK(inside_panel_no_overlap(f));
}

GUARDIAN_CASE(red_alert_frame_is_unchanged_by_a_nearby_observation) {
    Clock clock; clock.at = 1000;
    Presenter p(lcd());
    p.update(scene(c_, clock, true, true), at(clock, 1000));
    Frame f; Status st{}; st.radio = RadioState::Monitoring; st.persona_art = true;
    compose(p, st, f);
    CHECK(f.alert);
    CHECK(!f.caution);                                  // red owns the face; amber is on the Nearby page
    CHECK_EQ(f.art, FaceArt::Alert);
    CHECK(has(f, "ALERT"));
    CHECK(has(f, "Disconnect burst"));
    CHECK(!has(f, "Probe flood"));
    CHECK(inside_panel_no_overlap(f));
}

GUARDIAN_CASE(amber_also_shows_without_a_selected_network) {
    Clock clock; clock.at = 1000;
    Core core(clock, profiles::all_2g4_channels());
    core.incident(probe_flood(clock, 1000));
    Presenter p(lcd());
    p.update(core.snapshot(), at(clock, 1000));
    Frame f; Status st{}; st.radio = RadioState::Discovering; st.persona_art = true;
    compose(p, st, f);
    CHECK(f.caution);
    CHECK_EQ(f.art, FaceArt::NoData);
    CHECK(joined(f, amber).find("Probe flood nearby") != std::string::npos);
    CHECK(inside_panel_no_overlap(f));
}

GUARDIAN_CASE(radar_row_shows_registered_families_pulses_and_real_rates) {
    Clock clock; clock.at = 1000;
    Presenter p(lcd());
    p.update(scene(c_, clock, false, false), at(clock, 1000));
    Frame f; Status st{}; st.radio = RadioState::Monitoring; st.persona_art = true; st.radar = radar_with_rates();
    compose(p, st, f);
    CHECK(f.hud.radar);
    CHECK(f.hud.glyphs[static_cast<std::size_t>(DetectorFamily::Disconnect)].registered);
    CHECK(f.hud.glyphs[static_cast<std::size_t>(DetectorFamily::Disconnect)].pulse);
    CHECK(f.hud.glyphs[static_cast<std::size_t>(DetectorFamily::Baseline)].registered);
    CHECK(!f.hud.glyphs[static_cast<std::size_t>(DetectorFamily::Probe)].registered);
    CHECK(has(f, "P12 B340 T23"));
    CHECK(has(f, "hold side"));                          // the network-list hint survives
    CHECK(inside_panel_no_overlap(f));
    // Bounded text: large / saturated values are capped visibly, never cut.
    st.radar.air.probes = 12345; st.radar.air.beacons = 1000; st.radar.air.transmitters = 128; st.radar.air.transmitters_saturated = true;
    compose(p, st, f);
    CHECK(has(f, "P12k B1k T99+"));
    CHECK(inside_panel_no_overlap(f));
    // Review 2026-11-17: the widest values must still fit the panel (13 glyphs after x 57):
    // the transmitter count gives way (it stays on the details page / STATUS), never a cut text.
    st.radar.air.probes = 150000; st.radar.air.beacons = 150000;
    st.radar.air.transmitters = 150; st.radar.air.transmitters_saturated = true;
    compose(p, st, f);
    CHECK(inside_panel_no_overlap(f));
    CHECK(has(f, "P99k+ B99k+"));
    // No radar data: no radar decoration and no invented rates.
    Status none{}; none.radio = RadioState::Monitoring; none.persona_art = true;
    compose(p, none, f);
    CHECK(!f.hud.radar);
    CHECK(!has(f, "P12"));
    // DEMO is not a reading: no radar there.
    Presenter demo(lcd()); demo.update(scene(c_, clock, false, false), at(clock, 1000));
    demo.set_demo(true);
    compose(demo, st, f);
    CHECK(!f.hud.radar);
}

// G16H: the Bluetooth slot is the tenth glyph. It exists only while a BLE scan feeds its detector;
// the rates then start one cell further right, and without it the row is exactly as before.
GUARDIAN_CASE(radar_row_gains_a_bluetooth_slot_only_while_a_ble_scan_feeds_it) {
    Clock clock; clock.at = 1000;
    Presenter p(lcd());
    p.update(scene(c_, clock, false, false), at(clock, 1000));
    const auto bt = static_cast<std::size_t>(DetectorFamily::Bluetooth);
    Frame f; Status st{}; st.radio = RadioState::Monitoring; st.persona_art = true; st.radar = radar_with_rates();
    compose(p, st, f);
    CHECK(!f.hud.glyphs[bt].registered);
    const Line* rates = line_with(f, "P12 B340 T23");
    CHECK(rates && rates->x == 57);
    std::vector<std::uint16_t> px(static_cast<std::size_t>(Frame::width * Frame::height));
    Canvas canvas(px.data(), Frame::width, Frame::height, false);
    draw(canvas, f);
    const int gy = f.hud.radar_y + 1;
    const auto ink_in_slot = [&](std::uint16_t colour) {
        int n = 0;
        for (int y = gy; y < gy + 5; ++y) for (int x = 56; x <= 60; ++x) n += canvas.get(x, y) == colour;
        return n;
    };
    const int text_ink_at_57 = ink_in_slot(color::white);      // the rate text starts inside these columns today
    // A BLE scan feeds the detector: its glyph is drawn, amber while a nearby observation is visible.
    st.radar.families[bt].registered = true; st.radar.families[bt].scope = IncidentScope::Area; st.radar.families[bt].active = true;
    compose(p, st, f);
    CHECK(f.hud.glyphs[bt].registered); CHECK(f.hud.glyphs[bt].active);
    rates = line_with(f, "P12 B340 T23");
    CHECK(rates && rates->x == 63);
    CHECK(inside_panel_no_overlap(f));
    for (auto& v : px) v = color::black;
    draw(canvas, f);
    CHECK(ink_in_slot(amber) >= 9);                            // the glyph itself
    CHECK_EQ(ink_in_slot(color::white), 0);                    // no rate text under it
    (void)text_ink_at_57;
    // The widest values still fit (12 glyphs after x 63): the transmitter count gives way, nothing is cut.
    st.radar.air.probes = 12345; st.radar.air.beacons = 1000; st.radar.air.transmitters = 128; st.radar.air.transmitters_saturated = true;
    compose(p, st, f);
    CHECK(has(f, "P12k B1k")); CHECK(!has(f, "T99+"));
    CHECK(inside_panel_no_overlap(f));
    st.radar.air.probes = 150000; st.radar.air.beacons = 150000;
    compose(p, st, f);
    CHECK(has(f, "P99k+ B99k+"));
    CHECK(inside_panel_no_overlap(f));
}

GUARDIAN_CASE(face_reacts_amber_glance_red_stare) {
    // The wary glance: still most of the period, a bounded look to one side, alternating sides.
    CHECK_EQ(glance_dx(0), 0.0f);
    CHECK_EQ(glance_dx(2000), 0.0f);
    float peak = 0.0f, low = 0.0f;
    for (Millis t = 0; t < 8000; t += 10) { peak = std::max(peak, glance_dx(t)); low = std::min(low, glance_dx(t)); }
    CHECK(peak > 2.5f); CHECK(peak <= 3.0f);
    CHECK(low < -2.5f); CHECK(low >= -3.0f);
    CHECK(glance_dx(3200) * glance_dx(7200) < 0.0f);
    // Rendered: amber gets a dashed amber border, red keeps the solid red border.
    Clock clock; clock.at = 1000;
    std::vector<std::uint16_t> px(static_cast<std::size_t>(Frame::width * Frame::height));
    Canvas canvas(px.data(), Frame::width, Frame::height, false);
    Presenter amber_p(lcd()); amber_p.update(scene(c_, clock, true, false), at(clock, 1000));
    Frame fa; Status st{}; st.radio = RadioState::Monitoring;
    compose(amber_p, st, fa); draw(canvas, fa);
    CHECK_EQ(canvas.get(0, 96), amber);                  // left edge: 3 px dash ...
    CHECK_EQ(canvas.get(0, 100), color::black);          // ... 3 px gap
    Presenter red_p(lcd()); red_p.update(scene(c_, clock, true, true), at(clock, 1000));
    Frame fr; compose(red_p, st, fr); draw(canvas, fr);
    CHECK_EQ(canvas.get(0, 96), color::red);
    CHECK_EQ(canvas.get(0, 100), color::red);
}

// ---- end to end: Monitor -> Companion -> frame ------------------------------------------------
GUARDIAN_CASE(companion_render_fills_the_radar_from_the_real_monitor) {
    Clock clock; clock.at = 100;
    Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::LiveRadio);
    c.boot();
    const auto probe = fixture(c_, "probereq_wildcard_random");
    const auto b = fixture(c_, "beacon_wpa3_sae_pmf_required");
    clock.at = 1000; c.receive(packet(clock, b)); c.receive(packet(clock, probe));
    c.tick();
    Frame f; Status st{}; st.radio = RadioState::Discovering; st.persona_art = true;
    c.render(st, f);
    CHECK(f.hud.radar);
    CHECK(f.hud.glyphs[static_cast<std::size_t>(DetectorFamily::Disconnect)].registered);
    CHECK(f.hud.glyphs[static_cast<std::size_t>(DetectorFamily::Probe)].registered);   // G16F: the probe detector is registered
    CHECK(has(f, "P1 B1 T2"));
}

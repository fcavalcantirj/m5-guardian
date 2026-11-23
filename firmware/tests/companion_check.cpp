// G14: companion wiring checks (buttons, persistence codec/store, picker ->
// Monitor scope, alert scoping, screen composition). Generated packets are
// Imported test input, never RF evidence.
#include "check.hpp"
#include "companion.hpp"
#include "fixtures.hpp"
#include "head3d.hpp"
#include "head_pack.hpp"
#include "persona.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace guardian;
using namespace guardian::companion;
using guardian::measurement::Monitor;
using guardian::measurement::Packet;

namespace {
class Clock final : public MonotonicClock {
public:
    Millis at{100};
    Millis now() const override { return at; }
    TimeEpoch epoch() const override { TimeEpoch e{}; e.source_id[0] = 1; e.boot_id = 1; return e; }
};
// Beacon: BSSID 02:00:00:00:00:<tail>, SSID bytes, DS channel 6, open.
Packet beacon(const Clock& clock, std::uint8_t tail, const char* ssid = "ap") {
    Packet p{}; const auto n = std::strlen(ssid);
    p.meta.acquired = {clock.epoch(), clock.now(), true};
    p.meta.origin = Origin::Imported; p.meta.status = RxStatus::Ok; p.meta.channel = 6;
    p.meta.rssi_dbm = -50; p.meta.rssi_valid = true;
    p.bytes[0] = 0x80; p.bytes[16] = 2; p.bytes[21] = tail; p.bytes[10] = 2; p.bytes[15] = tail;
    p.bytes[36] = 0; p.bytes[37] = static_cast<std::uint8_t>(n);
    std::memcpy(p.bytes.data() + 38, ssid, n);
    const auto at = 38 + n; p.bytes[at] = 3; p.bytes[at + 1] = 1; p.bytes[at + 2] = 6;
    p.size = static_cast<std::uint16_t>(at + 3); return p;
}
Packet live(Packet p) { p.meta.origin = Origin::LiveRadio; return p; }
Packet deauth(const Clock& clock, std::uint8_t tail) {
    auto p = beacon(clock, tail); p.size = 26; p.bytes[0] = 0xc0; p.bytes[24] = 7; p.bytes[25] = 0; return p;
}
Network net(std::uint8_t tail, const char* ssid = "ap") {
    Network n{}; n.bssid = {2, 0, 0, 0, 0, tail}; n.ssid_size = static_cast<std::uint8_t>(std::strlen(ssid));
    std::memcpy(n.ssid.data(), ssid, n.ssid_size); return n;
}
// G16A: the StickS3 stands upright, USB down: a 135x240 portrait panel.
DisplayCapabilities lcd() { return {Support::Supported, 135, 240, PixelFormat::Rgb565, Support::Supported}; }

class MemoryBlob final : public BlobStorage {
public:
    std::vector<std::uint8_t> bytes; bool exists{}, fail_write{}, fail_read{}; unsigned writes{};
    BlobRead read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const override {
        if (!exists) return BlobRead::Absent;
        if (fail_read || bytes.size() > capacity) return BlobRead::Error;
        std::memcpy(out, bytes.data(), bytes.size()); size = bytes.size(); return BlobRead::Ok;
    }
    bool write(const std::uint8_t* data, std::size_t size) override {
        ++writes; if (fail_write) return false;
        bytes.assign(data, data + size); exists = true; return true;
    }
};
bool has(const Frame& f, const char* needle) {
    for (std::uint8_t i = 0; i < f.count; ++i) if (std::strstr(f.lines[i].text.data(), needle)) return true;
    return false;
}
// Wrapped large text: all line texts joined by single spaces.
std::string joined(const Frame& f) {
    std::string out;
    for (std::uint8_t i = 0; i < f.count; ++i) { if (!out.empty()) out += ' '; out += f.lines[i].text.data(); }
    return out;
}
bool has_words(const Frame& f, const char* words) { return joined(f).find(words) != std::string::npos; }
// Owner legibility requirement (2026-11-15, "too small"): key lines at 2x, all
// lines inside the panel, no two lines overlapping. G16A: the panel is the
// upright 135x240 portrait (22 glyphs per line at 1x, 11 at 2x).
constexpr int panel_w = 135, panel_h = 240;
int line_w(const Line& l) { return static_cast<int>(std::strlen(l.text.data())) * Canvas::glyph_advance * l.scale; }
int line_h(const Line& l) { return (Canvas::glyph_h + 1) * l.scale; }
bool fits_without_overlap(const Frame& f, bool battery_corner = true) {
    if (f.overflow) return false;                       // no line was silently dropped
    for (std::uint8_t i = 0; i < f.count; ++i) {
        const auto& a = f.lines[i];
        if (a.x < 0 || a.y < 0 || a.x + line_w(a) > panel_w || a.y + line_h(a) > panel_h) return false;
        // G16B: the top-right corner belongs to the battery indicator.
        if (battery_corner && a.x + line_w(a) > Frame::battery_x && a.y < Frame::battery_h) return false;
        // G16C: a face (portrait or placeholder) owns the face zone; only the
        // NoData marker may write text over its silhouette.
        if ((f.art == FaceArt::Rated || f.art == FaceArt::Alert) && a.y < Frame::face_zone_y + Frame::face_zone_h
            && a.y + line_h(a) > Frame::face_zone_y) return false;
        for (std::uint8_t j = i + 1; j < f.count; ++j) {
            const auto& b = f.lines[j];
            const bool x = a.x < b.x + line_w(b) && b.x < a.x + line_w(a);
            const bool y = a.y < b.y + line_h(b) && b.y < a.y + line_h(a);
            if (x && y) return false;
        }
    }
    return true;
}
bool has_scaled(const Frame& f, const char* needle, std::uint8_t scale) {
    for (std::uint8_t i = 0; i < f.count; ++i) if (f.lines[i].scale == scale && std::strstr(f.lines[i].text.data(), needle)) return true;
    return false;
}
const Line* line_with(const Frame& f, const char* needle) {
    for (std::uint8_t i = 0; i < f.count; ++i) if (std::strstr(f.lines[i].text.data(), needle)) return &f.lines[i];
    return nullptr;
}
std::uint8_t scale_of(const Frame& f, const char* needle) {
    for (std::uint8_t i = 0; i < f.count; ++i) if (std::strstr(f.lines[i].text.data(), needle)) return f.lines[i].scale;
    return 0;
}
std::uint16_t color_of(const Frame& f, const char* needle) {
    for (std::uint8_t i = 0; i < f.count; ++i) if (std::strstr(f.lines[i].text.data(), needle)) return f.lines[i].color;
    return 0;
}
// Open the picker, move to the entry for `n` and press `confirm`.
void pick(Companion& c, const Network& n, Action confirm) {
    if (c.presenter().screen() != Screen::Picker) c.input(Action::SecondaryLong);
    for (int i = 0; i < 20; ++i) {
        const auto& v = c.presenter().picker();
        if (v.count && v.entries[v.cursor].network == n) break;
        c.input(Action::Primary);
    }
    c.input(confirm);
}
} // namespace

GUARDIAN_CASE(keys_debounce_short_and_long_presses) {
    Key k(Action::Primary, Action::PrimaryLong);
    CHECK_EQ(k.sample(false, 0), Action::None);
    CHECK_EQ(k.sample(true, 10), Action::None);    // bounce shorter than debounce
    CHECK_EQ(k.sample(false, 20), Action::None);
    CHECK_EQ(k.sample(false, 100), Action::None);  // never a press
    CHECK_EQ(k.sample(true, 200), Action::None);
    CHECK_EQ(k.sample(true, 240), Action::None);   // accepted down, no action until release
    CHECK_EQ(k.sample(false, 400), Action::None);
    CHECK_EQ(k.sample(false, 440), Action::Primary); // short press on stable release
    CHECK_EQ(k.sample(false, 600), Action::None);
    CHECK_EQ(k.sample(true, 1000), Action::None);
    CHECK_EQ(k.sample(true, 1030), Action::None);
    CHECK_EQ(k.sample(true, 1829), Action::None);
    CHECK_EQ(k.sample(true, 1830), Action::PrimaryLong); // fires while held, once
    CHECK_EQ(k.sample(true, 3000), Action::None);
    CHECK_EQ(k.sample(false, 3100), Action::None);
    CHECK_EQ(k.sample(false, 3200), Action::None);       // no short after a long
    Key s(Action::Secondary, Action::SecondaryLong);
    CHECK_EQ(s.sample(true, 5), Action::None);           // pressed at boot: ignored until released once
    CHECK_EQ(s.sample(true, 2000), Action::None);
    CHECK_EQ(s.sample(false, 2100), Action::None); CHECK_EQ(s.sample(false, 2200), Action::None);
    CHECK_EQ(s.sample(true, 2300), Action::None); CHECK_EQ(s.sample(true, 2340), Action::None);
    CHECK_EQ(s.sample(false, 2400), Action::None); CHECK_EQ(s.sample(false, 2440), Action::Secondary);
}

GUARDIAN_CASE(codec_roundtrip_rejects_corruption_and_invalid_records) {
    PersistedSelection r; r.has_selection = true; r.selected.network = net(1);
    r.selected.settings_known = true; r.selected.settings.pmf = Pmf::Required; r.selected.settings.rsn_akms = 2;
    r.selected.channel_known = true; r.selected.channel = 6;
    r.approved_count = 1; r.approved[0].network = net(2);
    std::array<std::uint8_t, record_bytes> buf{};
    CHECK_EQ(encode(r, buf.data(), buf.size()), record_bytes);
    CHECK_EQ(encode(r, buf.data(), buf.size() - 1), std::size_t{0});
    PersistedSelection back; CHECK(decode(buf.data(), buf.size(), back));
    CHECK(back.selected.network == r.selected.network); CHECK(back.selected.settings == r.selected.settings);
    CHECK_EQ(back.selected.channel, 6); CHECK_EQ(back.approved_count, 1); CHECK(back.approved[0].network == net(2));
    CHECK(!decode(buf.data(), buf.size() - 1, back));
    for (std::size_t i : {std::size_t{0}, std::size_t{9}, std::size_t{20}, record_bytes - 1}) {
        auto bad = buf; bad[i] ^= 0x40; PersistedSelection out; out.version = 77;
        CHECK(!decode(bad.data(), bad.size(), out)); CHECK_EQ(out.version, 77); // untouched on failure
    }
    auto invalid = r; invalid.approved[0].network = net(2, "other"); // foreign name never restores
    CHECK_EQ(encode(invalid, buf.data(), buf.size()), std::size_t{0});
    PersistedSelection none; CHECK_EQ(encode(none, buf.data(), buf.size()), record_bytes);
    CHECK(decode(buf.data(), buf.size(), back)); CHECK(!back.has_selection);
}

GUARDIAN_CASE(encoded_store_reports_missing_unreadable_and_failed_writes) {
    MemoryBlob blob; EncodedSelectionStore store(blob); PersistedSelection r;
    CHECK(!store.load(r));
    r.has_selection = true; r.selected.network = net(1);
    CHECK(store.save(r)); CHECK(store.load(r)); CHECK(r.selected.network == net(1));
    blob.bytes[30] ^= 1; CHECK(!store.load(r));
    blob.fail_write = true; CHECK(!store.save(r));
    PersistedSelection bad; bad.has_selection = true; // invalid identity: never written
    blob.fail_write = false; const auto writes = blob.writes; CHECK(!store.save(bad)); CHECK_EQ(blob.writes, writes);
}

GUARDIAN_CASE(survey_discovery_hold_hops_without_locking) {
    measurement::Survey s; CHECK(s.begin(1, 13, 6, 0));
    s.observed(6, 10); CHECK(s.locked());
    s.hold_discovery(true); CHECK(!s.locked()); CHECK(!s.monitoring());
    CHECK_EQ(s.next(300), 7); s.observed(7, 310); CHECK(!s.locked());
    CHECK_EQ(s.next(600), 8);
    s.hold_discovery(false); s.observed(8, 700); CHECK(s.locked()); CHECK(s.monitoring());
}

GUARDIAN_CASE(picker_selection_binds_bytes_and_bssid_and_persists) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::Imported);
    MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::Imported);
    CHECK_EQ(c.boot(), StoreState::Empty); c.tick();
    CHECK(c.discovering());                       // no selection: picker discovery
    // Two APs advertise the same name; a third one another name.
    CHECK(!c.receive(beacon(clock, 1))); CHECK(!c.receive(beacon(clock, 2))); CHECK(!c.receive(beacon(clock, 3, "x")));
    c.tick(); c.input(Action::SecondaryLong);
    CHECK_EQ(c.presenter().picker().count, 3);
    CHECK(c.presenter().picker().entries[0].duplicate_name);
    CHECK(!c.presenter().picker().entries[2].duplicate_name);
    pick(c, net(2), Action::Secondary);
    CHECK_EQ(c.store(), StoreState::Saved);
    CHECK(m.scope().selected().network == net(2)); CHECK(m.snapshot().selected == net(2));
    CHECK(m.scope().selected().channel_known); CHECK_EQ(m.scope().selected().channel, 6);
    CHECK_EQ(c.presenter().screen(), Screen::Face); CHECK(!c.discovering());
    CHECK(c.receive(beacon(clock, 2)));          // the selected AP renews evidence
    CHECK(!c.receive(beacon(clock, 1)));         // same name, other BSSID: not trusted
    c.tick(); CHECK_EQ(c.presenter().view().face, Mood::Horrible);
    // Reboot: a new Monitor/Companion restores the exact selection from the blob.
    Clock clock2; Monitor m2(clock2, profiles::all_2g4_channels(), Origin::Imported);
    EncodedSelectionStore store2(blob); Companion c2(clock2, m2, store2, lcd(), Origin::Imported);
    CHECK_EQ(c2.boot(), StoreState::Restored); c2.tick();
    CHECK(m2.snapshot().selected == net(2)); CHECK(c2.presenter().view().has_selection);
    CHECK_EQ(c2.presenter().view().face, Mood::Unknown); // restored identity, no restored evidence
    CHECK(c2.receive(beacon(clock2, 2))); c2.tick(); CHECK_EQ(c2.presenter().view().face, Mood::Horrible);
    // Corrupt storage restores nothing and says so.
    blob.bytes[40] ^= 0x10; Clock clock3; Monitor m3(clock3, profiles::all_2g4_channels(), Origin::Imported);
    EncodedSelectionStore store3(blob); Companion c3(clock3, m3, store3, lcd(), Origin::Imported);
    CHECK_EQ(c3.boot(), StoreState::Rejected); CHECK(!m3.scope().has_selection());
}

// Owner (2026-11-15, "KISS ... no one needs a manual"): on the device the list
// has two actions only, blue = next row, side = choose. Hold blue in the list
// does nothing, no trust/watch markers, and a radio using the chosen network's
// name never raises an ALERT (phone hotspots restart with random BSSIDs).
// Owner (2026-11-15): "more intuitive ... an onboard (shown once) with instructions".
GUARDIAN_CASE(onboarding_is_shown_once_and_any_button_advances) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    MemoryBlob blob; EncodedSelectionStore store(blob); MemoryBlob seen;
    Companion c(clock, m, store, lcd(), Origin::LiveRadio, &seen); c.boot();
    CHECK(c.onboarding());
    Frame f; Status st{}; st.radio = RadioState::Discovering;
    c.render(st, f); CHECK(has_words(f, "Wi-Fi")); CHECK(has(f, "1/3")); CHECK(fits_without_overlap(f));
    CHECK_EQ(scale_of(f, "Welcome"), 2);
    CHECK(!c.input(Action::PrimaryLong)); CHECK(!c.input(Action::SecondaryLong)); CHECK(c.onboarding()); // holds ignored
    CHECK(c.input(Action::Primary)); c.render(st, f);
    CHECK(has(f, "BLUE")); CHECK(has(f, "SIDE")); CHECK(has(f, "2/3")); CHECK(fits_without_overlap(f));
    CHECK(c.input(Action::Secondary)); c.render(st, f);
    CHECK(has(f, "3/3")); CHECK(has_words(f, "hold SIDE")); CHECK(fits_without_overlap(f));
    CHECK(seen.bytes.empty());                              // not saved until finished
    CHECK(c.input(Action::Primary)); CHECK(!c.onboarding());
    CHECK_EQ(seen.bytes.size(), std::size_t{1}); CHECK_EQ(c.presenter().screen(), Screen::Face);
    Companion again(clock, m, store, lcd(), Origin::LiveRadio, &seen); again.boot();
    CHECK(!again.onboarding());                             // shown once
    MemoryBlob broken; broken.exists = true; broken.fail_read = true;
    Companion retry(clock, m, store, lcd(), Origin::LiveRadio, &broken); retry.boot();
    CHECK(retry.onboarding());                              // unreadable flag: show it again (safe)
}

// G16J (owner direction 2026-11-17) supersedes the G14 rule this case pinned ("hold blue does
// nothing in the list; a same-name radio never alerts"): every picked network is now watched for
// its name from another device, and holding blue on a same-name row says "this AP is mine too".
GUARDIAN_CASE(device_list_same_name_row_is_approved_by_hold_and_then_never_alerts) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot();
    c.receive(live(beacon(clock, 1))); c.receive(live(beacon(clock, 2))); c.tick();
    pick(c, net(1), Action::Secondary);
    CHECK_EQ(c.store(), StoreState::Saved); CHECK(m.scope().selected().network == net(1));
    CHECK(m.scope().selected().watch_impostors);                        // G16J: watched from the moment it is picked
    const auto writes = blob.writes;
    c.input(Action::SecondaryLong); CHECK_EQ(c.presenter().screen(), Screen::Picker);
    for (int i = 0; i < 2; ++i) {                                       // hold blue: only the same-name row reacts
        const auto& v = c.presenter().picker();
        const bool same_name_other_radio = v.entries[v.cursor].network == net(2);
        CHECK_EQ(c.input(Action::PrimaryLong), same_name_other_radio);
        c.input(Action::Primary);
    }
    CHECK_EQ(blob.writes, writes + 1); CHECK_EQ(m.scope().approved_count(), 1u);   // approved once, and saved
    CHECK(m.scope().in_scope(net(2).bssid));
    CHECK(m.scope().selected().watch_impostors); CHECK_EQ(c.presenter().screen(), Screen::Picker);
    Frame f; Status st{}; st.radio = RadioState::Monitoring; compose(c.presenter(), st, f);
    CHECK(!has(f, "+")); CHECK(!has(f, "*")); CHECK(!has(f, " W")); CHECK(fits_without_overlap(f));
    bool green = false;                                                 // the chosen network is shown green
    for (std::uint8_t i = 0; i < f.count; ++i)
        if (std::strstr(f.lines[i].text.data(), "ap") && f.lines[i].color == color::green) green = true;
    CHECK(green);
    c.input(Action::SecondaryLong);
    for (int i = 0; i < 6; ++i) { clock.at += 500; c.receive(live(beacon(clock, 1))); c.receive(live(beacon(clock, 2))); }
    c.tick(); CHECK(!c.presenter().view().alert);                       // the approved same-name radio: no ALERT
    blob.fail_write = true; pick(c, net(2), Action::Secondary);         // storage failure is still shown
    CHECK_EQ(c.store(), StoreState::SaveFailed); CHECK(m.scope().selected().network == net(2));
}

GUARDIAN_CASE(alert_is_scoped_to_selection_and_expires_without_all_clear) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::Imported);
    MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::Imported); c.boot();
    c.receive(beacon(clock, 1)); c.receive(beacon(clock, 9, "neighbour")); c.tick();
    pick(c, net(1), Action::Secondary); c.receive(beacon(clock, 1)); c.tick();
    for (int i = 0; i < 40; ++i) c.receive(deauth(clock, 9));   // unrelated BSSID
    c.tick(); CHECK(!c.presenter().view().alert);
    for (int i = 0; i < 20; ++i) c.receive(deauth(clock, 1));   // selected BSSID
    c.tick(); CHECK(c.presenter().view().alert);
    CHECK_EQ(std::string(c.presenter().view().alert_reason), "Disconnect burst detected");
    Frame f; Status st{}; st.radio = RadioState::Monitoring;
    compose(c.presenter(), st, f); CHECK(f.alert); CHECK_EQ(f.face_color, color::red);
    // G16R: the red sentence on the glass names the picked network ("ap" here), not "detected".
    CHECK(has_words(f, "Disconnect burst on ap")); CHECK(has(f, "cause unknown"));
    // G16C: a 2x red ALERT in the HUD; the header tag is an ALERT plate.
    CHECK(has_scaled(f, "ALERT", 2));
    for (std::uint8_t i = 0; i < f.count; ++i) if (f.lines[i].scale == 2 && !std::strcmp(f.lines[i].text.data(), "ALERT")) CHECK_EQ(f.lines[i].color, color::red);
    CHECK(fits_without_overlap(f));
    CHECK(!has(f, "attack"));
    clock.at += Core::fresh_ms; c.tick();                 // stale + alert coexist
    compose(c.presenter(), st, f); CHECK(f.alert); CHECK(has(f, "No fresh data")); CHECK(fits_without_overlap(f));
    clock.at += Core::incident_ms; c.tick();              // evidence expired
    compose(c.presenter(), st, f); CHECK(!f.alert); CHECK(has_words(f, "No fresh data"));
    CHECK(!has(f, "clear")); CHECK(!has(f, "safe")); CHECK(f.face_color != color::red);
}

// G14 board finding (2026-11-15): with a rogue same-name AP present the whole
// time, the ALERT lapsed for a few seconds every minute (report cooldown equal
// to the incident visibility). A condition still being observed stays visible.
GUARDIAN_CASE(a_persisting_unapproved_ap_keeps_the_alert_continuous) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::Imported);
    MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::Imported); c.boot();
    c.receive(beacon(clock, 1)); c.tick(); pick(c, net(1), Action::Secondary);
    CHECK(m.set_watch(true)); c.tick(); // lab/console-level watch: impostor detection exercised below
    bool started = false; unsigned gaps = 0, visible = 0; Millis next_rogue = clock.at;
    for (Millis t = 0; t < 180000; t += 1000) {
        clock.at += 1000;
        c.receive(beacon(clock, 1));                             // the selected AP stays fresh
        // Unapproved BSSID, same name, seen once per board hop cycle (13 x 300 ms).
        if (clock.at >= next_rogue) { c.receive(beacon(clock, 5)); next_rogue += 3900; }
        c.tick();
        const bool alert = c.presenter().view().alert;
        if (alert) { started = true; ++visible; }
        else if (started) ++gaps;
    }
    CHECK(started); CHECK_EQ(gaps, 0u); CHECK(visible > 170u);
    CHECK_EQ(std::string(c.presenter().view().alert_reason), "Another device is using your network's name");   // G16J wording
}

GUARDIAN_CASE(screens_label_settings_state_limits_and_no_data_age) {
    // Generated host input is stamped LiveRadio here ONLY to exercise the live
    // view path (Imported views are muted/historical by G08 policy). Not RF evidence.
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot(); c.tick();
    Frame f; Status st{}; st.radio = RadioState::Discovering;
    compose(c.presenter(), st, f);
    CHECK(has_words(f, "No network selected")); CHECK(has(f, "hold side")); CHECK(!f.face_shown || f.muted);
    CHECK_EQ(scale_of(f, "No network"), 2); CHECK(fits_without_overlap(f));
    c.receive(live(beacon(clock, 1))); c.tick(); pick(c, net(1), Action::Secondary);
    clock.at += 3000; c.receive(live(beacon(clock, 1))); clock.at += 2000; c.tick();
    st.radio = RadioState::Monitoring; compose(c.presenter(), st, f);
    CHECK(f.face_shown); CHECK(!f.muted); CHECK(has(f, "Horrible")); CHECK(has(f, "LIVE"));
    CHECK_EQ(scale_of(f, "Horrible"), 2); CHECK(fits_without_overlap(f));
    CHECK(line_with(f, "LIVE") && line_with(f, "LIVE")->plated && line_with(f, "LIVE")->y == Frame::tag_y);   // G16C: the tag is a plate
    c.input(Action::Primary); compose(c.presenter(), st, f);
    CHECK(has_words(f, "Advertised Wi-Fi settings")); CHECK(has(f, "Mode: Open")); CHECK(fits_without_overlap(f));
    CHECK(has(f, "Cipher: None")); CHECK(has(f, "PMF: Disabled")); CHECK(has(f, "Evidence age: 2 s")); CHECK(has(f, "heard on ch 6"));
    CHECK(has_words(f, "password strength")); CHECK(has_words(f, "router patch")); CHECK(has_words(f, "client negotiation"));
    CHECK(has(f, "5 GHz")); CHECK(has(f, "Internet")); CHECK(has(f, "dictionary"));
    for (int i = 0; i < 12 && c.presenter().screen() == Screen::Details; ++i) c.input(Action::Primary);
    CHECK_EQ(c.presenter().screen(), Screen::Face);
    // Offline sensor: muted no-data overlay with the last observation age, no grade.
    clock.at += Core::fresh_ms + 4000; c.tick(); st.radio = RadioState::Off; compose(c.presenter(), st, f);
    CHECK(f.muted); CHECK(has_words(f, "No fresh data")); CHECK(has(f, "35 s ago"));
    CHECK_EQ(scale_of(f, "No fresh"), 2); CHECK_EQ(scale_of(f, "35 s ago"), 2); CHECK(fits_without_overlap(f));
    CHECK(!has(f, "Horrible")); CHECK(!has(f, "Medium")); CHECK(!has(f, "Bad"));
    CHECK(f.face_color != color::red); CHECK(has(f, "Radio off"));
    // Picker shows the disambiguator for duplicate names.
    c.receive(live(beacon(clock, 2))); c.receive(live(beacon(clock, 1))); c.tick(); c.input(Action::SecondaryLong);
    compose(c.presenter(), st, f); CHECK(has(f, "..:00:01")); CHECK(has(f, "..:00:02"));
    CHECK(has_scaled(f, "..:00:01", 2)); CHECK(fits_without_overlap(f));   // G16C: the header also shows the chosen BSSID tail (1x)
    CHECK_EQ(c.presenter().screen(), Screen::Picker);
    c.input(Action::SecondaryLong); CHECK_EQ(c.presenter().screen(), Screen::Face);
}

GUARDIAN_CASE(demo_mode_is_labelled_and_never_persists_or_changes_selection) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::Imported);
    MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::Imported); c.boot();
    c.receive(beacon(clock, 1)); c.tick(); pick(c, net(1), Action::Secondary);
    const auto writes = blob.writes;
    CHECK(c.set_demo(true)); CHECK(c.presenter().view().demo);   // G24 retry: no key enters DEMO
    Frame f; Status st{}; st.radio = RadioState::Monitoring;
    const Mood moods[] = {Mood::VeryGood, Mood::Good, Mood::Medium, Mood::Bad, Mood::Horrible};
    for (auto mood : moods) {
        compose(c.presenter(), st, f); CHECK(has(f, "DEMO")); CHECK(has(f, "not a real reading"));
        CHECK(has_scaled(f, "DEMO", 2)); CHECK_EQ(scale_of(f, mood_text(mood)), 2); CHECK(fits_without_overlap(f));
        CHECK(has(f, mood_text(mood))); CHECK(!f.alert);
        c.input(Action::SecondaryLong); CHECK_EQ(c.presenter().screen(), Screen::Face);
        c.input(Action::Secondary);
    }
    CHECK_EQ(blob.writes, writes); CHECK(m.scope().selected().network == net(1));
    c.input(Action::PrimaryLong); CHECK(!c.presenter().view().demo);   // hold FRONT in DEMO returns to LIVE
    CHECK_EQ(c.presenter().screen(), Screen::Face);
    CHECK(c.presenter().view().selected_bssid.text[16] == '1');
}

GUARDIAN_CASE(draw_paints_alert_red_and_muted_grey_face) {
    std::array<std::uint16_t, 135 * 240> px{}; Canvas canvas(px.data(), 135, 240, false);
    Frame f; f.face_shown = true; f.face_color = color::red; f.alert = true; f.face = Mood::Good; f.art = FaceArt::Alert;
    f.count = 1; std::strcpy(f.lines[0].text.data(), "ALERT"); f.lines[0].x = 2; f.lines[0].y = 190; f.lines[0].color = color::red;
    draw(canvas, f);                                                                // no art: the honest placeholder block
    CHECK_EQ(canvas.get(Frame::face_x + 2, Frame::face_y + Frame::face_size / 2), color::red);
    CHECK_EQ(canvas.get(0, 120), color::red);                                       // ALERT frames the whole panel in red
    f.alert = false; f.muted = true; f.face_color = color::grey; f.art = FaceArt::NoData; draw(canvas, f);
    CHECK_EQ(canvas.get(Frame::face_x, Frame::face_y + Frame::face_size / 2), color::grey);   // grey outline, no rated face
}

GUARDIAN_CASE(render_refreshes_at_freshness_deadline_without_periodic_tick) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot();
    c.receive(live(beacon(clock, 1))); c.tick(); pick(c, net(1), Action::Secondary);
    c.receive(live(beacon(clock, 1))); c.tick();
    const auto seen = clock.at;
    Frame f; Status st{}; st.radio = RadioState::Monitoring;
    clock.at = seen + Core::fresh_ms - 1; c.tick(); c.render(st, f);
    CHECK(!has(f, "No fresh data"));
    clock.at = seen + Core::fresh_ms;
    // No periodic tick: a deadline-triggered render must refresh the snapshot itself.
    c.render(st, f);
    CHECK(has_words(f, "No fresh data")); CHECK(f.muted);
    CHECK_EQ(c.presenter().view().last_seen_ms, Core::fresh_ms);
}

GUARDIAN_CASE(storage_errors_are_not_reported_as_empty) {
    MemoryBlob blob; EncodedSelectionStore store(blob); PersistedSelection r;
    CHECK(!store.load(r)); CHECK_EQ(store.last_load(), EncodedSelectionStore::Loaded::Absent);
    blob.exists = true; blob.fail_read = true;
    CHECK(!store.load(r)); CHECK_EQ(store.last_load(), EncodedSelectionStore::Loaded::Unreadable);
    blob.fail_read = false; blob.bytes.resize(record_bytes + 1);
    CHECK(!store.load(r)); CHECK_EQ(store.last_load(), EncodedSelectionStore::Loaded::Unreadable);
    // A storage read error at boot is reported as Rejected, never as "No saved network".
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    blob.fail_read = true; Companion c(clock, m, store, lcd(), Origin::LiveRadio);
    CHECK_EQ(c.boot(), StoreState::Rejected);
    CHECK(!m.scope().has_selection());
}

// ---- G16: Very good portrait layout ----------------------------------------
namespace {
// Real-parser fixture (WPA3-Personal SAE only, PMF required) as a live observation.
Packet wpa3_live(const Clock& clock) {
    guardian::fixtures::Fixture fx; std::string error;
    Packet p{};
    if (!guardian::fixtures::load("beacon_wpa3_sae_pmf_required", fx, error)) return p;
    std::memcpy(p.bytes.data(), fx.bytes.data(), fx.bytes.size()); p.size = static_cast<std::uint16_t>(fx.bytes.size());
    p.meta.acquired = {clock.epoch(), clock.now(), true};
    p.meta.origin = Origin::LiveRadio; p.meta.status = RxStatus::Ok; p.meta.channel = 6;
    p.meta.rssi_dbm = -48; p.meta.rssi_valid = true;
    return p;
}
Packet wpa3_deauth(const Clock& clock) {
    auto p = wpa3_live(clock); p.size = 26; p.bytes[0] = 0xc0; p.bytes[24] = 7; p.bytes[25] = 0; return p;
}
// G16A: the art owns the face zone (full width, y < Frame::face_zone_h); text lives below it.
// G16C: header lines live in the header rows, all others below the face zone; none inside it.
bool in_text_column(const Frame& f) {
    if (f.overflow) return false;
    for (std::uint8_t i = 0; i < f.count; ++i) {
        const auto& l = f.lines[i];
        if (l.x < 0 || l.x + line_w(l) > panel_w || l.y + line_h(l) > panel_h) return false;
        const bool header = l.y + line_h(l) <= Frame::header_h;
        const bool below = l.y >= Frame::face_zone_y + Frame::face_zone_h;
        if (!header && !below) return false;
    }
    return true;
}
bool lines_overlap(const Frame& f) {
    for (std::uint8_t i = 0; i < f.count; ++i) for (std::uint8_t j = i + 1; j < f.count; ++j) {
        const auto &a = f.lines[i], &b = f.lines[j];
        if (a.x < b.x + line_w(b) && b.x < a.x + line_w(a) && a.y < b.y + line_h(b) && b.y < a.y + line_h(a)) return true;
    }
    return false;
}
bool forbidden_claim(const Frame& f) {
    const auto text = joined(f);
    for (const char* w : {"unhackable", "100%", "safe", "secure", "strong password", "password is strong", "cannot be", "attack"})
        if (text.find(w) != std::string::npos) return true;
    return false;
}
struct VeryGoodRig {
    Clock clock; Monitor m; MemoryBlob blob; EncodedSelectionStore store; Companion c;
    VeryGoodRig() : m(clock, profiles::all_2g4_channels(), Origin::LiveRadio), store(blob),
        c(clock, m, store, lcd(), Origin::LiveRadio) {
        c.boot(); c.receive(wpa3_live(clock)); c.tick();
        c.input(Action::SecondaryLong); c.input(Action::Secondary);       // choose the one listed network
        c.receive(wpa3_live(clock)); c.tick();
    }
};
}

GUARDIAN_CASE(live_wpa3_pmf_required_shows_the_portrait_layout_with_a_settings_explanation) {
    VeryGoodRig r;
    CHECK_EQ(r.c.presenter().view().face, Mood::VeryGood);
    Frame f; Status st{}; st.radio = RadioState::Monitoring; st.persona_art = true;
    r.c.render(st, f);
    CHECK(f.persona); CHECK(!f.demo_badge); CHECK(!f.muted); CHECK(!f.alert);
    CHECK(f.art == FaceArt::Rated); CHECK(f.face == Mood::VeryGood); CHECK(f.celebrate);
    CHECK(has(f, "LIVE")); CHECK(!has(f, "DEMO"));
    CHECK_EQ(scale_of(f, "Very good"), 2);                                          // the label, big, one row (9 of 11 glyphs)
    CHECK_EQ(color_of(f, "Very good"), rgb565(255, 200, 40));
    // G16C techy badges of the advertised settings, and the honesty marker.
    CHECK(has(f, "WPA3-P")); CHECK(has(f, "PMF REQ")); CHECK(has(f, "ADV ONLY"));
    CHECK(line_with(f, "WPA3-P") && line_with(f, "WPA3-P")->plated);
    CHECK(has(f, "SEEN 0s")); CHECK(has(f, "-48dBm")); CHECK(f.hud.rssi); CHECK_EQ(f.hud.rssi_dbm, -48);
    CHECK(in_text_column(f)); CHECK(!lines_overlap(f)); CHECK(!forbidden_claim(f));
    CHECK(has(f, "hold side"));                                                     // the network-list hint survives
}

GUARDIAN_CASE(portrait_layout_is_opt_in_so_the_diagnostic_screen_is_unchanged) {
    VeryGoodRig r;
    Frame f; Status st{}; st.radio = RadioState::Monitoring;                        // persona_art false
    r.c.render(st, f);
    CHECK(!f.persona); CHECK(has(f, "Very good")); CHECK(fits_without_overlap(f));
}

GUARDIAN_CASE(removing_fresh_evidence_replaces_the_portrait_with_no_data) {
    VeryGoodRig r;
    Frame f; Status st{}; st.radio = RadioState::Monitoring; st.persona_art = true;
    r.clock.at += Core::fresh_ms; r.c.tick(); r.c.render(st, f);
    CHECK(f.art == FaceArt::NoData); CHECK(f.muted); CHECK(has_words(f, "No fresh data"));
    CHECK(!has(f, "Very")); CHECK(!has(f, "good")); CHECK(!has(f, "WPA3")); CHECK(!f.celebrate);
    CHECK(!has(f, "PMF")); CHECK(!has(f, "dBm")); CHECK(!f.hud.rssi);
    CHECK_EQ(f.face_color, color::grey);
    r.c.receive(wpa3_live(r.clock)); r.c.tick(); r.c.render(st, f);               // fresh evidence returns: portrait returns
    CHECK(f.persona); CHECK(f.art == FaceArt::Rated);
}

GUARDIAN_CASE(alert_never_hides_behind_the_portrait) {
    VeryGoodRig r;
    for (int i = 0; i < 20; ++i) r.c.receive(wpa3_deauth(r.clock));
    r.c.tick(); CHECK(r.c.presenter().view().alert);
    Frame f; Status st{}; st.radio = RadioState::Monitoring; st.persona_art = true;
    r.c.render(st, f);
    CHECK(f.art == FaceArt::Alert); CHECK(f.face == Mood::VeryGood);              // the current rating's ALERT pulse pair
    CHECK(f.alert); CHECK(has_words(f, "Disconnect burst on")); CHECK(has(f, "cause unknown"));   // G16R: then the network's name
    CHECK(!f.celebrate); CHECK(!f.demo_badge);                                      // no celebration during an incident
    CHECK(line_with(f, "ALERT") && line_with(f, "ALERT")->plated && line_with(f, "ALERT")->y == Frame::tag_y);
    CHECK(f.hud.incident);
}

GUARDIAN_CASE(demo_very_good_uses_the_portrait_with_an_obvious_demo_badge) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot();
    c.set_demo(true); CHECK(c.presenter().view().demo);                             // DEMO 1/5 (the direct method since G24)
    Frame f; Status st{}; st.radio = RadioState::Monitoring; st.persona_art = true;
    c.render(st, f);
    CHECK_EQ(c.presenter().view().face, Mood::VeryGood);
    CHECK(f.persona); CHECK(f.demo_badge); CHECK(has(f, "DEMO")); CHECK(has_scaled(f, "DEMO", 2));
    CHECK(has(f, "1/5")); CHECK(has(f, "not a real")); CHECK(!has(f, "LIVE")); CHECK(!has(f, "s ago"));
    CHECK_EQ(scale_of(f, "Very good"), 2); CHECK(has(f, "WPA3-P")); CHECK(has(f, "PMF REQ"));
    CHECK(!has(f, "dBm")); CHECK(!f.hud.rssi); CHECK(!has(f, "SEEN"));             // a demo face never shows a signal
    CHECK(in_text_column(f)); CHECK(!lines_overlap(f)); CHECK(!forbidden_claim(f));
    CHECK(has(f, "next"));                                                          // DEMO hint survives
    c.input(Action::Secondary); c.render(st, f);                                    // G16C: Good has its own portrait
    CHECK(f.persona); CHECK(f.art == FaceArt::Rated); CHECK(f.face == Mood::Good); CHECK(has(f, "DEMO")); CHECK(has(f, "Good"));
}

GUARDIAN_CASE(draw_paints_portrait_badge_and_falls_back_without_art) {
    std::vector<std::uint8_t> art(persona::art_bytes);
    for (std::size_t i = 0; i < art.size(); i += 2) { art[i] = 0x34; art[i + 1] = 0x12; }   // 0x1234 little-endian
    persona::ArtSet set; for (std::size_t i = 0; i < 5; ++i) { set.rated[i] = art.data(); set.alert[i] = {art.data(), art.data()}; }
    set.no_data = art.data();
    std::array<std::uint16_t, 135 * 240> px{}; Canvas canvas(px.data(), 135, 240, true);
    Frame f; f.face_shown = true; f.persona = true; f.demo_badge = true; f.face = Mood::VeryGood; f.celebrate = true; f.art = FaceArt::Rated;
    f.count = 1; std::strcpy(f.lines[0].text.data(), "DEMO"); f.lines[0].x = Frame::badge_x + 2; f.lines[0].y = Frame::badge_y + 2;
    f.lines[0].scale = 2; f.lines[0].color = color::black;
    DrawInput in; in.art = &set;
    draw(canvas, f, in);
    CHECK_EQ(canvas.get(60, Frame::face_zone_y + 80), std::uint16_t{0x1234});      // portrait pixel, byte order handled
    CHECK_EQ(canvas.get(Frame::badge_x + 1, Frame::badge_y + 1), color::yellow);   // badge plate behind the DEMO text
    CHECK_EQ(canvas.get(134, 228), color::black);                                   // HUD background is black
    draw(canvas, f, {});                                                            // no art: honest placeholder, never garbage
    CHECK_EQ(canvas.get(Frame::face_x + 2, Frame::face_y + Frame::face_size / 2), f.face_color);
}

// ---- G16A: every screen in the upright 135x240 portrait --------------------
namespace {
// Compose the current screen and record whether it fits; `what` names the state for the failure line.
bool fits_now(const Companion& c, const Status& st, const char* what) {
    Frame f; compose(c.presenter(), st, f);
    const bool ok = fits_without_overlap(f) && f.count > 0;
    if (!ok) std::printf("     portrait layout overflow: %s\n", what);
    return ok;
}
void walk_details(Companion& c, const Status& st, const char* what, unsigned& bad) {
    c.input(Action::Primary);                                            // face -> details
    for (int i = 0; i < 16 && c.presenter().screen() == Screen::Details; ++i) {
        if (!fits_now(c, st, what)) ++bad;
        c.input(Action::Primary);
    }
    if (c.presenter().screen() == Screen::Details) c.input(Action::Secondary);
}
}

GUARDIAN_CASE(long_advice_text_is_wrapped_whole_never_cut_mid_word) {
    VeryGoodRig r; Status st{}; st.radio = RadioState::Monitoring;
    r.c.input(Action::Primary); r.c.input(Action::Primary);                     // details: explanation page
    CHECK(r.c.presenter().details().page == DetailsPage::Explanation);
    Frame f; compose(r.c.presenter(), st, f); CHECK(fits_without_overlap(f));
    CHECK(has_words(f, "Internet access or coverage elsewhere."));
}

GUARDIAN_CASE(every_screen_fits_the_portrait_panel) {
    unsigned bad = 0;
    const RadioState radios[] = {RadioState::Off, RadioState::Unconfigured, RadioState::Failed, RadioState::Discovering, RadioState::Monitoring};
    const StoreState stores[] = {StoreState::Empty, StoreState::Restored, StoreState::Rejected, StoreState::Saved, StoreState::SaveFailed};
    // Onboarding pages.
    for (std::uint8_t page = 0; page < Companion::onboarding_pages; ++page) {
        Frame f; compose_onboarding(page, f); if (!fits_without_overlap(f)) { ++bad; std::printf("     onboarding %u\n", unsigned(page)); }
    }
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot(); c.tick();
    Status st{};
    for (auto r : radios) for (auto s : stores) { st.radio = r; st.store = s; if (!fits_now(c, st, "no selection")) ++bad; }
    st.store = StoreState::Empty;
    // Picker: empty, then full of long and duplicate names.
    c.input(Action::SecondaryLong);
    for (auto r : radios) { st.radio = r; if (!fits_now(c, st, "empty picker")) ++bad; }
    const char* names[] = {"a-very-long-network-name-32bytes", "ap", "ap", "neighbour", "x", "guest wifi 2.4", "z", "y"};
    for (std::uint8_t i = 0; i < 8; ++i) c.receive(live(beacon(clock, static_cast<std::uint8_t>(i + 1), names[i])));
    c.tick();
    for (int i = 0; i < 10; ++i) { if (!fits_now(c, st, "picker")) ++bad; c.input(Action::Primary); }
    c.input(Action::SecondaryLong);
    // Selected open network (Horrible), every radio/store status, then details.
    pick(c, net(1, names[0]), Action::Secondary); c.receive(live(beacon(clock, 1, names[0]))); c.tick();
    for (auto r : radios) for (auto s : stores) { st.radio = r; st.store = s; if (!fits_now(c, st, "rated face")) ++bad; }
    st.radio = RadioState::Monitoring; st.store = StoreState::Saved;
    walk_details(c, st, "details (rated)", bad);
    // Incident (alert) on the selected BSSID, alone and with stale evidence.
    for (int i = 0; i < 20; ++i) c.receive(live(deauth(clock, 1)));
    c.tick(); CHECK(c.presenter().view().alert);
    if (!fits_now(c, st, "alert")) ++bad;
    walk_details(c, st, "details (alert)", bad);
    clock.at += Core::fresh_ms + 1000; c.tick();
    for (auto r : radios) { st.radio = r; if (!fits_now(c, st, "alert + stale")) ++bad; }
    clock.at += Core::incident_ms; c.tick();
    for (auto r : radios) { st.radio = r; if (!fits_now(c, st, "no data")) ++bad; }
    clock.at += 3600000; c.tick();                                       // very old evidence: minutes / long ago
    if (!fits_now(c, st, "no data, old")) ++bad;
    walk_details(c, st, "details (no data)", bad);
    // DEMO: five moods, with and without the portrait art, plus their details.
    c.set_demo(true); CHECK(c.presenter().view().demo);
    for (int i = 0; i < 5; ++i) {
        st.persona_art = false; if (!fits_now(c, st, "demo")) ++bad;
        st.persona_art = true; if (!fits_now(c, st, "demo + art")) ++bad;
        c.input(Action::Secondary);
    }
    walk_details(c, st, "details (demo)", bad);
    c.input(Action::PrimaryLong); CHECK(!c.presenter().view().demo);
    CHECK_EQ(bad, 0u);
    // Live Very good portrait (art) and its fallback.
    VeryGoodRig r; st.radio = RadioState::Monitoring;
    for (bool art : {true, false}) {
        st.persona_art = art; Frame f; r.c.render(st, f);
        CHECK(fits_without_overlap(f)); CHECK_EQ(f.persona, art);
        if (art) CHECK(in_text_column(f));
    }
}

// ---- G16A: EDGE test pattern (serial EDGE command) --------------------------
GUARDIAN_CASE(edge_pattern_marks_each_panel_edge_with_its_own_colour) {
    std::array<std::uint16_t, 135 * 240> px{}; Canvas c(px.data(), 135, 240, true);
    c.clear(color::white);
    draw_edge_test(c);
    int wrong = 0;
    for (int x = 1; x < 134; ++x) { if (c.get(x, 0) != color::red) ++wrong; if (c.get(x, 239) != color::blue) ++wrong; }
    for (int y = 1; y < 239; ++y) { if (c.get(0, y) != color::yellow) ++wrong; if (c.get(134, y) != color::green) ++wrong; }
    CHECK_EQ(wrong, 0);
    // One pixel only: the next ring inside is background, so a missing glass row shows as a missing colour.
    int inner = 0;
    for (int x = 1; x < 134; ++x) { if (c.get(x, 1) != color::black) ++inner; if (c.get(x, 238) != color::black) ++inner; }
    for (int y = 2; y < 238; ++y) { if (c.get(1, y) != color::black && c.get(1, y) != color::white) ++inner; if (c.get(133, y) != color::black) ++inner; }
    CHECK_EQ(inner, 0);
    // Labels name each edge's colour and the expected orientation.
    Frame f; compose_edge_test(f); CHECK(fits_without_overlap(f, false));   // EDGE is drawn without the battery indicator
    CHECK(has(f, "TOP red")); CHECK(has(f, "BOTTOM blue")); CHECK(has(f, "LEFT yellow")); CHECK(has(f, "RIGHT green"));
    CHECK(has(f, "USB down"));
    for (std::uint8_t i = 0; i < f.count; ++i) CHECK(f.lines[i].x >= 3 && f.lines[i].y >= 3 && f.lines[i].y + 8 * f.lines[i].scale <= 237);
}

// ---- G16C: header, black background, every rating's face, HUD honesty, pagination, motion ----
namespace {
// Fake portrait set: every frame a flat, distinct colour, so the face zone shows which frame was chosen.
struct FakeArt {
    std::array<std::vector<std::uint8_t>, 16> frames;
    persona::ArtSet set;
    static std::uint16_t colour(int i) { return static_cast<std::uint16_t>(0x0841 * (i + 1) + 0x20); }
    FakeArt() {
        for (int i = 0; i < 16; ++i) {
            frames[i].resize(persona::art_bytes);
            for (std::size_t b = 0; b < frames[i].size(); b += 2) { frames[i][b] = colour(i) & 0xff; frames[i][b + 1] = colour(i) >> 8; }
        }
        for (int m = 0; m < 5; ++m) { set.rated[m] = frames[m].data(); set.alert[m] = {frames[5 + 2 * m].data(), frames[6 + 2 * m].data()}; }
        set.no_data = frames[15].data();
    }
};
struct Panel {
    std::array<std::uint16_t, 135 * 240> px{}; Canvas c{px.data(), 135, 240, false};
    std::uint16_t at(int x, int y) const { return c.get(x, y); }
    // The face-zone centre pixel (idle breathing off): which frame is shown.
    std::uint16_t face() const { return at(67, Frame::face_zone_y + 80); }
};
DrawInput still_input(const FakeArt& a, Millis t = 0) {
    DrawInput in; in.art = &a.set; in.anim_ms = t; in.motion.tilt_max_deg = 0; in.motion.breath_amount = 0; return in;
}
Status art_status(RadioState r = RadioState::Monitoring) { Status st{}; st.radio = r; st.persona_art = true; return st; }
// Every line on the name row, and the tag-row lines.
std::vector<const Line*> on_row(const Frame& f, int y) {
    std::vector<const Line*> out;
    for (std::uint8_t i = 0; i < f.count; ++i) if (f.lines[i].y == y) out.push_back(&f.lines[i]);
    return out;
}
// Header contract: tag plate on the tag row (left), BSSID tail slot right of it, the
// network name ALONE on its own full-width 1x row, nothing else in the header rows.
bool header_ok(const Frame& f, const char* expect_name, const char* what) {
    bool ok = true;
    const auto tag = on_row(f, Frame::tag_y), name = on_row(f, Frame::name_y);
    if (tag.empty() || !tag[0]->plated || tag[0]->x > 2 || tag[0]->scale != 1) { ok = false; std::printf("     %s: no tag plate\n", what); }
    for (const auto* l : tag) if (l != tag[0] && l->x < Frame::bssid_x) { ok = false; std::printf("     %s: tag row squeezed\n", what); }
    if (name.size() != 1) { ok = false; std::printf("     %s: name row has %zu lines\n", what, name.size()); return ok; }
    const auto& n = *name[0];
    if (n.scale != 1 || n.x > 2 || std::strlen(n.text.data()) > static_cast<std::size_t>(Frame::cols1)) { ok = false; std::printf("     %s: name row not full-width 1x\n", what); }
    if (expect_name && std::strcmp(n.text.data(), expect_name)) { ok = false; std::printf("     %s: name '%s' != '%s'\n", what, n.text.data(), expect_name); }
    for (std::uint8_t i = 0; i < f.count; ++i) {
        const auto& l = f.lines[i];
        if (l.y < Frame::header_h && l.y != Frame::tag_y && l.y != Frame::name_y) { ok = false; std::printf("     %s: stray header line '%s'\n", what, l.text.data()); }
    }
    return ok;
}
// The most frequent pixel value on the panel.
std::uint16_t dominant(const Panel& p) {
    std::vector<std::pair<std::uint16_t, int>> counts;
    for (auto v : p.px) {
        auto it = std::find_if(counts.begin(), counts.end(), [&](const auto& e) { return e.first == v; });
        if (it == counts.end()) counts.push_back({v, 1}); else ++it->second;
    }
    return std::max_element(counts.begin(), counts.end(), [](const auto& a, const auto& b) { return a.second < b.second; })->first;
}
struct NamedRig {
    Clock clock; Monitor m; MemoryBlob blob; EncodedSelectionStore store; Companion c;
    explicit NamedRig(const char* ssid) : m(clock, profiles::all_2g4_channels(), Origin::LiveRadio), store(blob),
        c(clock, m, store, lcd(), Origin::LiveRadio) {
        c.boot(); c.receive(live(beacon(clock, 7, ssid))); c.tick(); pick(c, net(7, ssid), Action::Secondary);
        c.receive(live(beacon(clock, 7, ssid))); c.tick();
    }
};
}

GUARDIAN_CASE(header_gives_the_network_name_its_own_full_width_row_on_every_screen) {
    struct Name { const char* ssid; const char* shown; };
    const Name names[] = {
        {"a-very-long-network-name-32bytes", "a-very-long-network-n~"},   // longer than 22: shortened with a visible marker
        {"exactly-twenty-two-chr", "exactly-twenty-two-chr"},
        {"ap", "ap"},
        {"caf\xc3\xa9 wifi", nullptr},                                    // non-ASCII bytes: never raw on the glass
    };
    unsigned bad = 0;
    for (const auto& n : names) {
        NamedRig r(n.ssid); Status st = art_status();
        const auto& label = r.c.presenter().view().selected_label;
        Frame f;
        const auto check = [&](const char* what) {
            compose(r.c.presenter(), st, f);
            const char* expect = n.shown;
            if (!header_ok(f, expect, what) || !fits_without_overlap(f)) { ++bad; std::printf("     (ssid %s)\n", label.c_str()); }
            const auto name = on_row(f, Frame::name_y);
            if (!name.empty()) for (const char* p = name[0]->text.data(); *p; ++p) if (static_cast<unsigned char>(*p) > 126 || *p < 32) { ++bad; break; }
            const auto tag = on_row(f, Frame::tag_y);
            bool tail = false; for (const auto* l : tag) tail |= std::strcmp(l->text.data(), "..:00:07") == 0 && l->x == Frame::bssid_x;
            if (!tail) { ++bad; std::printf("     %s: BSSID tail slot missing\n", what); }
        };
        check("rated face");
        r.c.input(Action::Primary); for (int i = 0; i < 8 && r.c.presenter().screen() == Screen::Details; ++i) { check("details"); r.c.input(Action::Primary); }
        r.c.input(Action::SecondaryLong); check("picker"); r.c.input(Action::SecondaryLong);
        r.clock.at += Core::fresh_ms + 1000; r.c.tick(); check("no data");
        for (int i = 0; i < 20; ++i) r.c.receive(live(deauth(r.clock, 7)));
        r.c.tick(); CHECK(r.c.presenter().view().alert); check("alert");
    }
    // Hidden network (empty SSID): a visible marker, never an empty row.
    { NamedRig r(""); Frame f; compose(r.c.presenter(), art_status(), f);
      const auto name = on_row(f, Frame::name_y); CHECK_EQ(name.size(), std::size_t{1});
      if (!name.empty()) CHECK(std::strlen(name[0]->text.data()) > 0); CHECK(header_ok(f, nullptr, "hidden")); }
    // No selection and DEMO keep the same header rows.
    { Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob; EncodedSelectionStore store(blob);
      Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot(); c.tick(); Frame f;
      compose(c.presenter(), art_status(), f); if (!header_ok(f, nullptr, "no selection")) ++bad;
      c.set_demo(true); compose(c.presenter(), art_status(), f); if (!header_ok(f, "not a real reading", "demo")) ++bad;
      CHECK_EQ(color_of(f, "DEMO 1/5"), color::black); CHECK(line_with(f, "DEMO 1/5") && line_with(f, "DEMO 1/5")->plate == color::yellow); }
    CHECK_EQ(bad, 0u);
}

// G16C rework (3): the network list applies the header rule. A name longer than
// its 2x row is shortened with a visible '~', never cut silently.
GUARDIAN_CASE(network_list_shortens_long_names_with_a_visible_marker) {
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio);
    MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot();
    const char* names[] = {"a-very-long-network-name-32bytes", "exactly-10", "eleven-char", "ap"};
    for (std::uint8_t i = 0; i < 4; ++i) c.receive(live(beacon(clock, static_cast<std::uint8_t>(i + 1), names[i])));
    c.tick(); c.input(Action::SecondaryLong); CHECK_EQ(c.presenter().screen(), Screen::Picker);
    Frame f; Status st = art_status();
    std::string all;
    for (int i = 0; i < 4; ++i) { compose(c.presenter(), st, f); for (std::uint8_t k = 0; k < f.count; ++k) all += std::string(f.lines[k].text.data()) + "|"; c.input(Action::Primary); }
    CHECK(all.find("a-very-lo~") != std::string::npos);     // 9 glyphs + marker in the 10-glyph name slot
    CHECK(all.find("exactly-10|") != std::string::npos);    // exactly fits: unchanged
    CHECK(all.find("eleven-cha~") == std::string::npos);
    CHECK(all.find("eleven-ch~") != std::string::npos);     // one too long: marker, never a silent cut
    CHECK(all.find("eleven-char") == std::string::npos);
    CHECK(all.find("a-very-long") == std::string::npos);
    CHECK(fits_without_overlap(f));
}

// G16C rework (5): during an owner-confirmed TUNE session over Wi-Fi the glass
// says so (monitoring is paused) and how to end it, on every face/details state.
GUARDIAN_CASE(tune_session_is_announced_with_its_time_and_how_to_end_it) {
    NamedRig r("homenet"); Frame f; Status st = art_status(); st.radio = RadioState::Off; st.tune_session_s = 125;
    compose(r.c.presenter(), st, f);
    CHECK(has(f, "TUNE WI-FI 125s")); CHECK(has(f, "any key: end tune")); CHECK(!has(f, "hold side: networks"));
    CHECK(has(f, "RADIO OFF")); CHECK(fits_without_overlap(f));
    r.c.input(Action::Primary); compose(r.c.presenter(), st, f);   // details page
    CHECK(has(f, "TUNE WI-FI 125s")); CHECK(has(f, "any key: end tune")); CHECK(fits_without_overlap(f));
    r.c.input(Action::PrimaryLong); compose(r.c.presenter(), st, f);   // G24: the Settings screen (hold FRONT) during a TUNE session
    CHECK_EQ(r.c.presenter().screen(), Screen::Settings);
    CHECK(has(f, "TUNE WI-FI 125s")); CHECK(has(f, "any key: end tune")); CHECK(!has(f, "hold FRONT = save"));
    CHECK(!has(f, "FRONT next")); CHECK(fits_without_overlap(f));
    r.c.input(Action::Secondary);
    r.c.set_demo(true); compose(r.c.presenter(), st, f);   // DEMO faces while tuning motion (G24 retry: the direct method)
    CHECK(has(f, "TUNE WI-FI 125s")); CHECK(fits_without_overlap(f));
    st.tune_session_s = 0; compose(r.c.presenter(), st, f); CHECK(!has(f, "TUNE WI-FI"));
}

GUARDIAN_CASE(every_screen_is_pure_black_like_the_art) {
    FakeArt art; Panel p; unsigned bad = 0;
    const auto look = [&](const Frame& f, const char* what) {
        p.c.clear(color::white); draw(p.c, f, still_input(art));
        int dark = 0; for (auto v : p.px) dark += v == color::dark;
        // Outside the face zone (the fake art is a flat colour there), the background is black.
        Panel q = p; for (int y = Frame::face_zone_y; y < Frame::face_zone_y + Frame::face_zone_h; ++y) for (int x = 0; x < 135; ++x) q.px[static_cast<std::size_t>(y * 135 + x)] = color::black;
        int black = 0; for (int y = 0; y < 240; ++y) for (int x = 0; x < 135; ++x) if (y < Frame::face_zone_y || y >= Frame::face_zone_y + Frame::face_zone_h) black += p.at(x, y) == color::black;
        if (dark || dominant(q) != color::black || black < 135 * 80 / 2) { ++bad; std::printf("     %s: background not black (dark px %d)\n", what, dark); }
    };
    for (std::uint8_t page = 0; page < Companion::onboarding_pages; ++page) { Frame f; compose_onboarding(page, f); look(f, "onboarding"); }
    VeryGoodRig r; Frame f; Status st = art_status();
    compose(r.c.presenter(), st, f); look(f, "rated");
    r.c.input(Action::Primary); for (int i = 0; i < 8 && r.c.presenter().screen() == Screen::Details; ++i) { compose(r.c.presenter(), st, f); look(f, "details"); r.c.input(Action::Primary); }
    r.c.input(Action::SecondaryLong); compose(r.c.presenter(), st, f); look(f, "picker"); r.c.input(Action::SecondaryLong);
    r.clock.at += Core::fresh_ms; r.c.tick(); compose(r.c.presenter(), st, f); look(f, "no data");
    st.persona_art = false; compose(r.c.presenter(), st, f); look(f, "no data, no art");
    CHECK_EQ(bad, 0u);
}

GUARDIAN_CASE(every_rating_shows_its_own_portrait_and_alert_pulses) {
    FakeArt art; Panel p;
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot();
    c.set_demo(true);                                                                  // DEMO walks the five ratings
    const Mood moods[] = {Mood::VeryGood, Mood::Good, Mood::Medium, Mood::Bad, Mood::Horrible};
    for (int i = 0; i < 5; ++i) {
        Frame f; c.render(art_status(), f);
        CHECK(f.art == FaceArt::Rated); CHECK(f.face == moods[i]); CHECK(f.persona); CHECK_EQ(f.celebrate, moods[i] == Mood::VeryGood);
        draw(p.c, f, still_input(art)); CHECK_EQ(p.face(), FakeArt::colour(i));
        CHECK(fits_without_overlap(f)); CHECK(in_text_column(f));
        c.input(Action::Secondary);
    }
    c.input(Action::PrimaryLong);
    // Live ALERT on a fresh rating: that rating's two pulse frames alternate; no rated face during the pulse is wrong.
    VeryGoodRig r; for (int i = 0; i < 20; ++i) r.c.receive(wpa3_deauth(r.clock));
    r.c.tick(); Frame f; r.c.render(art_status(), f);
    CHECK(f.art == FaceArt::Alert); CHECK(f.face == Mood::VeryGood);
    draw(p.c, f, still_input(art, 0)); CHECK_EQ(p.face(), FakeArt::colour(5));
    draw(p.c, f, still_input(art, persona::alert_pulse_ms)); CHECK_EQ(p.face(), FakeArt::colour(6));
    CHECK_EQ(p.at(0, 120), color::red);
    // ALERT without a fresh rating: the silhouette, never a rated (or alert-rated) face.
    r.clock.at += Core::fresh_ms + 500; r.c.tick(); CHECK(r.c.presenter().view().alert);
    r.c.render(art_status(), f); CHECK(f.art == FaceArt::NoData);
    draw(p.c, f, still_input(art)); CHECK_EQ(p.face(), FakeArt::colour(15));
}

GUARDIAN_CASE(no_rated_face_is_ever_shown_without_a_fresh_rating) {
    FakeArt art; Panel p;
    // No selection, checking, stale, very old, imported: the NoData silhouette with a marker.
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot(); c.tick();
    Frame f; c.render(art_status(), f);
    CHECK(f.art == FaceArt::NoData); CHECK(has_words(f, "No network selected")); CHECK_EQ(scale_of(f, "No network"), 2);
    draw(p.c, f, still_input(art)); CHECK_EQ(p.at(67, 40), FakeArt::colour(15));
    VeryGoodRig r; r.clock.at += Core::fresh_ms; r.c.tick(); r.c.render(art_status(), f);
    CHECK(f.art == FaceArt::NoData); CHECK(f.muted); CHECK(has_words(f, "No fresh data")); CHECK(has_scaled(f, " s ago", 2));
    CHECK(!f.hud.rssi); CHECK(!has(f, "WPA3")); CHECK(!has(f, "PMF")); CHECK(!has(f, "Very good")); CHECK(!has(f, "SEEN"));
    r.clock.at += 3600000; r.c.tick(); r.c.render(art_status(), f);
    CHECK(f.art == FaceArt::NoData); CHECK(has(f, "min ago") || has(f, "long ago"));
    CHECK(fits_without_overlap(f));
    // Imported (replayed) evidence is historical: muted, never a fresh face.
    Clock ic; Monitor im(ic, profiles::all_2g4_channels(), Origin::Imported); MemoryBlob ib; EncodedSelectionStore is(ib);
    Companion ci(ic, im, is, lcd(), Origin::Imported); ci.boot(); ci.receive(beacon(ic, 1)); ci.tick(); pick(ci, net(1), Action::Secondary);
    ci.receive(beacon(ic, 1)); ci.tick(); ci.render(art_status(), f);
    CHECK(f.art != FaceArt::Rated || !ci.presenter().view().muted);
    if (ci.presenter().view().muted) CHECK(f.art == FaceArt::NoData);
}

GUARDIAN_CASE(hud_draws_each_element_only_with_its_evidence) {
    Status st = art_status(); Frame f;
    VeryGoodRig r; r.c.render(st, f);
    CHECK(f.hud.shown); CHECK(f.hud.rssi); CHECK_EQ(f.hud.bars, 4); CHECK(f.hud.listening); CHECK(!f.hud.incident);
    CHECK(has(f, "CH06")); CHECK(!forbidden_claim(f));
    for (const char* w : {"safe", "hack", "speed", "Mbps", "online", "Internet", "fast"}) CHECK(joined(f).find(w) == std::string::npos);
    // Radio states drive the listening indicator; no channel text without a lock.
    st.radio = RadioState::Discovering; r.c.render(st, f); CHECK(f.hud.listening); CHECK(f.hud.sweeping); CHECK(!f.hud.locked);
    st.radio = RadioState::Off; r.c.render(st, f); CHECK(!f.hud.listening); CHECK(!f.hud.sweeping); CHECK(!f.hud.locked); CHECK(has(f, "RADIO OFF"));
    CHECK(!has(f, "CH06"));
    st.radio = RadioState::Failed; r.c.render(st, f); CHECK(!f.hud.listening); CHECK(has(f, "RADIO FAIL"));
    st.radio = RadioState::Monitoring;
    // Weak but fresh signal: bars follow the dBm.
    { VeryGoodRig w; auto pk = wpa3_live(w.clock); pk.meta.rssi_dbm = -80; w.c.receive(pk); w.c.tick(); w.c.render(st, f);
      CHECK(f.hud.rssi); CHECK_EQ(f.hud.bars, 1); CHECK(has(f, "-80dBm")); }
    // An invalid RSSI is never drawn.
    { VeryGoodRig w; w.clock.at += 1000; auto pk = wpa3_live(w.clock); pk.meta.rssi_valid = false; w.c.receive(pk); w.c.tick(); w.c.render(st, f);
      if (!w.c.presenter().details().advice.signal.rssi_valid) { CHECK(!f.hud.rssi); CHECK(!has(f, "dBm")); } }
    // Stale: no rating, no badges, no signal, no age ticker; the listening state remains.
    r.clock.at += Core::fresh_ms; r.c.tick(); r.c.render(st, f);
    CHECK(!f.hud.rssi); CHECK(!has(f, "dBm")); CHECK(!has(f, "CCMP")); CHECK(!has(f, "SEEN")); CHECK(f.hud.listening);
    // DEMO: no signal, no age, no channel lock claim about the demo network.
    { Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob; EncodedSelectionStore store(blob);
      Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot(); c.set_demo(true);
      for (int i = 0; i < 5; ++i) { c.render(st, f); CHECK(!f.hud.rssi); CHECK(!has(f, "dBm")); CHECK(!has(f, "SEEN")); CHECK(!has(f, "CH0")); c.input(Action::Secondary); } }
    // ALERT: the incident marker and its reason.
    VeryGoodRig a; for (int i = 0; i < 20; ++i) a.c.receive(wpa3_deauth(a.clock));
    a.c.tick(); a.c.render(st, f); CHECK(f.hud.incident); CHECK(has(f, "cause unknown")); CHECK(!has(f, "Very good"));
}

GUARDIAN_CASE(advice_pages_never_end_in_an_unreachable_more) {
    // Open network (many advice items), WPA3 and an incident: every details sub-page fits
    // whole, no page says "more" without a next page, and every advice item is shown once.
    const TextBudget b = details_text_budget();
    CHECK(b.columns == Frame::cols1); CHECK(b.explanation_rows >= 8); CHECK(b.owner_rows >= 8);
    unsigned bad = 0;
    const auto walk = [&](Companion& c, const char* what) {
        Status st = art_status(); c.input(Action::Primary);
        std::string seen;
        for (int i = 0; i < 20 && c.presenter().screen() == Screen::Details; ++i) {
            const auto& d = c.presenter().details(); Frame f; compose(c.presenter(), st, f);
            if (!fits_without_overlap(f)) { ++bad; std::printf("     %s: page %u/%u overflows\n", what, unsigned(d.page_index) + 1, unsigned(d.page_count)); }
            if (has(f, "more")) { ++bad; std::printf("     %s: unreachable 'more'\n", what); }
            if (d.page_count > 1) {
                char tag[8]; std::snprintf(tag, sizeof tag, "%u/%u", unsigned(d.page_index) + 1, unsigned(d.page_count));
                if (!has(f, tag)) { ++bad; std::printf("     %s: no page indicator %s\n", what, tag); }
            }
            if (d.page == DetailsPage::Explanation) seen += joined(f) + " ";
            c.input(Action::Primary);
        }
        const auto& adv = c.presenter().details().advice;   // same evidence
        for (std::uint8_t i = 0; i < adv.count; ++i) {
            std::string words = advice_text(adv.items[i]);
            // wrapped text joined by spaces equals the original (single spaces in the source)
            if (seen.find(words) == std::string::npos) { ++bad; std::printf("     %s: item not shown: %s\n", what, words.c_str()); }
        }
    };
    { NamedRig r("open-net"); walk(r.c, "open"); }
    { VeryGoodRig r; walk(r.c, "wpa3"); }
    { VeryGoodRig r; for (int i = 0; i < 20; ++i) r.c.receive(wpa3_deauth(r.clock)); r.c.tick(); walk(r.c, "alert"); }
    CHECK_EQ(bad, 0u);
}

// 2026-11-17 (owner video: a cyan line rotating across the chin read as a strap against the floating
// face): the IMU "level line" is gone; nothing is drawn in the band above the chin rule.
GUARDIAN_CASE(no_level_line_is_drawn_under_the_chin) {
    FakeArt art;
    for (auto& fr : art.frames) std::fill(fr.begin(), fr.end(), std::uint8_t{0});   // black portrait: nothing hides decoration
    VeryGoodRig r; Frame f; r.c.render(art_status(), f);
    const int bottom = Frame::face_zone_y + Frame::face_zone_h;
    for (int pose = 0; pose < 2; ++pose) {
        DrawInput in = still_input(art, 1000);
        if (pose) { in.imu.active = true; in.imu.dx = 5; in.imu.tilt_deg = -12; }
        Panel p; draw(p.c, f, in);
        int cyan_px = 0;
        for (int y = bottom - 12; y < bottom; ++y) for (int x = 0; x < 118; ++x) cyan_px += p.at(x, y) == rgb565(0, 200, 220);
        CHECK_EQ(cyan_px, 0);
    }
}

GUARDIAN_CASE(imu_motion_moves_face_and_decoration_but_never_the_text) {
    FakeArt art;
    // A real-looking frame (the VeryGood portrait from disk is not needed: a gradient fake shows motion).
    std::vector<std::uint8_t> grad(persona::art_bytes);
    for (int y = 0; y < persona::art_h; ++y) for (int x = 0; x < persona::art_w; ++x) {
        const auto v = rgb565(static_cast<std::uint8_t>(x * 255 / 134), static_cast<std::uint8_t>(y * 255 / 159), 60);
        const auto i = static_cast<std::size_t>(y * persona::art_w + x) * 2; grad[i] = v & 0xff; grad[i + 1] = v >> 8;
    }
    art.set.rated[0] = grad.data();
    VeryGoodRig r; Frame f; r.c.render(art_status(), f);
    Panel a, b, c2;
    DrawInput in = still_input(art, 1000);
    draw(a.c, f, in);
    DrawInput moved = in; moved.imu.active = true; moved.imu.dx = 4; moved.imu.dy = -3; moved.imu.tilt_deg = 4;
    moved.imu.hud_dx = 2.4f;
    draw(b.c, f, moved);
    int face_diff = 0, text_diff = 0;
    for (int y = Frame::face_zone_y; y < Frame::face_zone_y + Frame::face_zone_h; ++y) for (int x = 0; x < 135; ++x) face_diff += a.at(x, y) != b.at(x, y);
    CHECK(face_diff > 1000);
    // Every text glyph pixel is identical: legibility never moves.
    for (std::uint8_t i = 0; i < f.count; ++i) {
        const auto& l = f.lines[i];
        for (int y = l.y; y < l.y + 7 * l.scale; ++y) for (int x = l.x; x < l.x + line_w(l) - l.scale; ++x)
            if (a.at(x, y) == l.color && b.at(x, y) != l.color) ++text_diff;
    }
    CHECK_EQ(text_diff, 0);
    // A centred active pose (stick upright: every output 0, scale 1) draws exactly the still frame.
    DrawInput centred = in; centred.imu.active = true;
    draw(c2.c, f, centred); int centred_diff = 0; for (std::size_t i = 0; i < a.px.size(); ++i) centred_diff += a.px[i] != c2.px[i];
    CHECK_EQ(centred_diff, 0);
    // 2026-11-17: no white flash anywhere (the owner's "white straps" while handling the stick).
    int white_rules = 0;
    for (int x = 0; x < 135; ++x) white_rules += b.at(x, Frame::face_zone_y + Frame::face_zone_h) == color::white;
    CHECK_EQ(white_rules, 0);
}

// ---- G16I: the snow-globe burst in the face band (draw rules) --------------------------------
namespace {
// A portrait a burst can take: a gradient inside the middle of the art (35 x 40 = 1,400 lit blocks,
// like a real face; a full flat frame would be 2,430 blocks, over the capacity), black around it.
std::vector<std::uint8_t> face_like(std::uint8_t blue) {
    std::vector<std::uint8_t> a(persona::art_bytes, 0);
    for (int y = 21; y < 141; ++y) for (int x = 15; x < 120; ++x) {
        const auto v = rgb565(static_cast<std::uint8_t>(40 + x), static_cast<std::uint8_t>(40 + y), blue);
        const auto i = static_cast<std::size_t>(y * persona::art_w + x) * 2; a[i] = v & 0xff; a[i + 1] = v >> 8;
    }
    return a;
}
struct BurstRig {
    FakeArt art; std::vector<std::uint8_t> very_good = face_like(60), good = face_like(200);
    std::unique_ptr<burst::Burst> b{new burst::Burst};
    VeryGoodRig r; Frame f; Millis t{1000};
    BurstRig() { art.set.rated[0] = very_good.data(); art.set.rated[1] = good.data(); r.c.render(art_status(), f); }
    // Still input (no idle motion, no ember or smoke) so a frame is a pure function of the portrait.
    DrawInput in() {
        DrawInput i = still_input(art, t); i.motion.ember_peak = 0; i.motion.smoke_alpha = 0; i.burst = b.get(); return i;
    }
    DrawInput plain() { DrawInput i = in(); i.burst = nullptr; return i; }
    bool begin() { const auto i = in(); return b->begin(face_art(f, i), persona::PixelSource{nullptr, face_art(f, i)}, t, face_pose(f, i), 0, 0, 5); }
    void run(Millis ms) { for (Millis e = 0; e < ms; e += 40) { t += 40; b->step(t, 0, -1, face_pose(f, in())); } }
};
int differing_rows(const Panel& a, const Panel& b, int y0, int y1) {
    int n = 0; for (int y = y0; y < y1; ++y) for (int x = 0; x < 135; ++x) n += a.at(x, y) != b.at(x, y);
    return n;
}
constexpr int band0 = Frame::face_zone_y, band1 = Frame::face_zone_y + Frame::face_zone_h;
}

GUARDIAN_CASE(burst_never_paints_outside_the_band) {
    BurstRig g; CHECK(g.f.art == FaceArt::Rated); CHECK(burst_allowed(g.f)); CHECK(g.begin());
    int outside = 0, frames = 0, band_changed = 0;
    while (g.b->active() && frames++ < 200) {
        g.run(40); if (!g.b->active()) break;
        Panel with, without; draw(with.c, g.f, g.in()); draw(without.c, g.f, g.plain());
        CHECK(g.b->active());                                           // drawing an allowed frame never ends it
        outside += differing_rows(with, without, 0, band0) + differing_rows(with, without, band1, Frame::height);
        band_changed += differing_rows(with, without, band0, band1) > 1000;
    }
    CHECK(frames > 80); CHECK_EQ(outside, 0);
    CHECK(band_changed > 60);                                           // and it really was the particles in the band
}

GUARDIAN_CASE(text_and_hud_untouched_during_burst) {
    BurstRig g; CHECK(g.begin()); g.run(900);
    Panel with, without; draw(with.c, g.f, g.in()); draw(without.c, g.f, g.plain());
    CHECK(g.f.hud.shown); CHECK(g.f.count > 4);
    int text_diff = 0, text_px = 0;
    for (std::uint8_t i = 0; i < g.f.count; ++i) {
        const auto& l = g.f.lines[i];
        for (int y = l.y - 1; y < l.y + 8 * l.scale; ++y) for (int x = l.x - 1; x < l.x + line_w(l); ++x) {
            if (x < 0 || y < 0 || x >= 135 || y >= 240 || (y >= band0 && y < band1)) continue;
            ++text_px; text_diff += with.at(x, y) != without.at(x, y);
        }
    }
    CHECK(text_px > 2000); CHECK_EQ(text_diff, 0);                      // the rating and every HUD word stay put
    CHECK(has(g.f, "Very good"));
    CHECK_EQ(differing_rows(with, without, band1, Frame::height), 0);   // the whole HUD, graphics included
    CHECK_EQ(differing_rows(with, without, 0, band0), 0);               // and the header
}

GUARDIAN_CASE(alert_cancels_burst_and_paints_the_red_stare) {
    BurstRig g; CHECK(g.begin()); g.run(800); CHECK(g.b->active());
    for (int i = 0; i < 20; ++i) g.r.c.receive(wpa3_deauth(g.r.clock));
    g.r.c.tick(); g.r.c.render(art_status(), g.f);
    CHECK(g.f.alert); CHECK(g.f.art == FaceArt::Alert); CHECK(!burst_allowed(g.f));
    Panel with, without; draw(with.c, g.f, g.in());
    CHECK(!g.b->active());                                              // cancelled by the very frame that shows the ALERT
    draw(without.c, g.f, g.plain());
    CHECK_EQ(differing_rows(with, without, 0, Frame::height), 0);       // exactly the ALERT frame: nothing of the burst left
    CHECK_EQ(with.face(), FakeArt::colour(5 + persona::alert_pulse(g.t))); // the red-eye ALERT portrait (pulse pair of Very good)
    CHECK_EQ(with.at(0, 120), color::red); CHECK_EQ(with.at(134, 120), color::red);
    g.run(200); CHECK(!g.b->active());                                  // and it does not come back by itself
}

GUARDIAN_CASE(burst_reforms_to_exact_pixels) {
    BurstRig g; CHECK(g.begin());
    // The HUD decoration animates with time, so every comparison is against the plain frame of the same instant.
    Panel last, still; int frames = 0; bool was_different = false; Millis last_t = g.t;
    while (g.b->active() && frames++ < 200) {
        last_t = g.t; draw(last.c, g.f, g.in());
        if (frames == 20) { draw(still.c, g.f, g.plain()); was_different = differing_rows(last, still, band0, band1) > 1000; }
        g.run(40);
    }
    CHECK(was_different); CHECK(!g.b->active()); CHECK(frames > 80);
    const Millis end_t = g.t; g.t = last_t; draw(still.c, g.f, g.plain()); g.t = end_t;
    CHECK_EQ(differing_rows(last, still, 0, Frame::height), 0);         // the last burst frame is the still frame, whole panel
    Panel after, usual; draw(after.c, g.f, g.in()); draw(usual.c, g.f, g.plain());   // and the next frame is painted the usual way
    CHECK_EQ(differing_rows(after, usual, 0, Frame::height), 0);
}

GUARDIAN_CASE(no_burst_without_a_rated_face) {
    BurstRig g;
    Frame nodata = g.f; nodata.art = FaceArt::NoData; CHECK(!burst_allowed(nodata));
    Frame alert = g.f; alert.alert = true; CHECK(!burst_allowed(alert));
    Frame pulse = g.f; pulse.art = FaceArt::Alert; CHECK(!burst_allowed(pulse));
    Frame no_art = g.f; no_art.persona = false; CHECK(!burst_allowed(no_art));
    Frame other = g.f; other.face_shown = false; CHECK(!burst_allowed(other));   // details, picker, onboarding
    Frame none = g.f; none.art = FaceArt::None; CHECK(!burst_allowed(none));
    CHECK(burst_allowed(g.f));
    Frame demo = g.f; demo.demo_badge = true; CHECK(burst_allowed(demo));         // a labelled DEMO face may play too
    // A burst that is running when such a frame arrives is cancelled, and the frame is painted as usual.
    for (const Frame* f : {&nodata, &no_art, &other}) {
        CHECK(g.begin()); g.run(400); CHECK(g.b->active());
        Panel with, without; draw(with.c, *f, g.in()); CHECK(!g.b->active());
        draw(without.c, *f, g.plain());
        CHECK_EQ(differing_rows(with, without, 0, Frame::height), 0);
    }
    // Evidence going stale mid-burst (the real path): the NoData silhouette replaces it at once.
    CHECK(g.begin()); g.run(400);
    g.r.clock.at += Core::fresh_ms; g.r.c.tick(); g.r.c.render(art_status(), g.f);
    CHECK(g.f.art == FaceArt::NoData);
    Panel stale; draw(stale.c, g.f, g.in()); CHECK(!g.b->active()); CHECK_EQ(stale.at(67, 40), FakeArt::colour(15));
}

GUARDIAN_CASE(a_changed_portrait_cancels_the_burst) {
    BurstRig g; CHECK(g.begin()); g.run(400);
    Frame good = g.f; good.face = Mood::Good; good.celebrate = false;   // the rating changed while the face was in the air
    CHECK(burst_allowed(good));
    Panel with, without; draw(with.c, good, g.in()); CHECK(!g.b->active());
    draw(without.c, good, g.plain());
    CHECK_EQ(differing_rows(with, without, 0, Frame::height), 0);       // the new rating's portrait, never the old face's particles
    // A burst never starts from, or survives, a draw without the art it was made from.
    CHECK(g.begin()); DrawInput no_set = g.in(); no_set.art = nullptr;
    Panel p; draw(p.c, g.f, no_set); CHECK(!g.b->active());
}

GUARDIAN_CASE(caution_border_stays_during_burst) {
    BurstRig g; g.f.caution = true;                                     // an amber nearby observation (G16E)
    CHECK(burst_allowed(g.f)); CHECK(g.begin()); g.run(900);
    Panel with, without; draw(with.c, g.f, g.in()); draw(without.c, g.f, g.plain());
    CHECK(g.b->active());                                               // amber does not cancel
    // The dashed amber edge (3 on, 3 off): every dash is there, over the particles too. (The gaps between
    // the dashes show the band underneath, so only the dashes are compared.)
    int border = 0, dash_same = 0;
    for (int x = 0; x < 135; ++x) for (int y : {0, 239}) { border += with.at(x, y) == amber; dash_same += (with.at(x, y) == amber) == (without.at(x, y) == amber); }
    for (int y = 1; y < 239; ++y) for (int x : {0, 134}) { border += with.at(x, y) == amber; dash_same += (with.at(x, y) == amber) == (without.at(x, y) == amber); }
    CHECK(border > 300); CHECK_EQ(dash_same, 2 * 135 + 2 * 238);
    CHECK(differing_rows(with, without, band0, band1) > 1000);
}

// ---- G21: the 3D head in the face band (draw rules) ------------------------------------------
namespace {
// Very good, fresh, on the face screen, with a 3x3 head set for Very good only. Every frame is a
// face-like gradient whose blue names its place in the grid, so the band shows which frame was used.
struct HeadRig {
    BurstRig g;
    std::vector<std::uint8_t> a = std::vector<std::uint8_t>(persona::art_bytes), b = std::vector<std::uint8_t>(persona::art_bytes);
    std::unique_ptr<head3d::Head> head{new head3d::Head(a.data(), b.data())};
    std::vector<std::uint8_t> pack;
    static std::uint8_t blue(int yi, int pi) { return static_cast<std::uint8_t>(20 + 60 * yi + 15 * pi); }
    static std::vector<std::uint8_t> frame(int yi, int pi) { return face_like(blue(yi, pi)); }
    explicit HeadRig(int corrupt_entry = -1) {
        guardian::fixtures::PackSpec s; s.mood = 0; s.frame = frame;
        pack = guardian::fixtures::make_pack(s);
        if (corrupt_entry >= 0) pack[guardian::fixtures::get32(pack, guardian::fixtures::pack_table_offset(s) + 12 * static_cast<std::size_t>(corrupt_entry))] = 0x07;
        head->add(pack.data(), pack.size());
        head3d::Params p; p.on = true; p.yaw_gain = 1; p.pitch_gain = 1; head->configure(p);
    }
    // What the board does each frame: the pose from the motion model, then the head's frame for it.
    DrawInput in(float yaw = 0, float pitch = 0) {
        DrawInput i = g.in(); i.imu.active = true; i.imu.yaw_deg = yaw; i.imu.pitch_deg = pitch;
        choose_head(g.f, i, head.get(), g.b->active());
        return i;
    }
};
// The face band differs from these art bytes in this many pixels (the HUD's own marks in the band's last rows count too).
int band_differs(const Panel& p, const std::vector<std::uint8_t>& art) {
    int n = 0;
    for (int y = 0; y < persona::art_h; ++y) for (int x = 0; x < persona::art_w; ++x) {
        const auto i = static_cast<std::size_t>(y * persona::art_w + x) * 2;
        n += p.at(x, band0 + y) != static_cast<std::uint16_t>(art[i] | (art[i + 1] << 8));
    }
    return n;
}
// Pixels by which the panel differs from the same frame painted the pre-G21 way with `art` as its 2D
// rated portrait: no head, no burst, no cache, no cigar overlay. 0 = "the 3D frame is just the art".
int differs_from_2d(const HeadRig& h, const Frame& f, DrawInput in, const Panel& p, const std::vector<std::uint8_t>& art) {
    FakeArt as2d = h.g.art; const int m = persona::rated_index(f.face);
    if (m >= 0) as2d.set.rated[static_cast<std::size_t>(m)] = art.data();
    in.art = &as2d.set; in.head = nullptr; in.burst = nullptr; in.cache = nullptr; in.motion.ember_peak = 0; in.motion.smoke_alpha = 0;
    Panel want; draw(want.c, f, in);
    return differing_rows(p, want, 0, Frame::height);
}
}

GUARDIAN_CASE(the_rated_face_shows_the_3d_frame_for_the_pose) {
    HeadRig h; CHECK(h.g.f.art == FaceArt::Rated); CHECK(h.g.f.face == Mood::VeryGood);
    auto in = h.in(0, 0);
    CHECK(in.head != nullptr); CHECK(face_art(h.g.f, in) == in.head);
    Panel p; draw(p.c, h.g.f, in);
    CHECK_EQ(differs_from_2d(h, h.g.f, in, p, HeadRig::frame(1, 1)), 0);   // the middle frame, pixel for pixel
    CHECK(band_differs(p, h.g.very_good) > 1000);                 // and not the 2D portrait
    in = h.in(30, -15); draw(p.c, h.g.f, in);
    CHECK_EQ(differs_from_2d(h, h.g.f, in, p, HeadRig::frame(2, 0)), 0);
    CHECK_EQ(h.head->inflates(), 2u);
    // No IMU (inactive model): the front frame, never a stale angle.
    DrawInput still = h.g.in(); still.imu.yaw_deg = 30; still.imu.pitch_deg = 15;   // inactive: the numbers are not a pose
    choose_head(h.g.f, still, h.head.get(), false); draw(p.c, h.g.f, still);
    CHECK_EQ(differs_from_2d(h, h.g.f, still, p, HeadRig::frame(1, 1)), 0);
    // A labelled DEMO face is a rated face too.
    Frame demo = h.g.f; demo.demo_badge = true; DrawInput d = h.g.in(); choose_head(demo, d, h.head.get(), false);
    CHECK(d.head != nullptr);
}

GUARDIAN_CASE(a_rating_without_a_3d_set_keeps_its_2d_portrait) {
    HeadRig h;
    Frame good = h.g.f; good.face = Mood::Good; good.celebrate = false;
    DrawInput in = h.g.in(); in.imu.active = true; choose_head(good, in, h.head.get(), false);
    CHECK(in.head == nullptr); CHECK(face_art(good, in) == h.g.art.set.rated[1]);
    Panel p; draw(p.c, good, in);
    CHECK_EQ(differs_from_2d(h, good, in, p, h.g.good), 0);
    // No head object at all (no PSRAM for it), or the head switched off: the 2D portrait of every rating.
    DrawInput none = h.g.in(); none.head = h.a.data(); choose_head(h.g.f, none, nullptr, false);
    CHECK(none.head == nullptr); draw(p.c, h.g.f, none); CHECK_EQ(differs_from_2d(h, h.g.f, none, p, h.g.very_good), 0);
    head3d::Params off; off.on = false; h.head->configure(off);
    DrawInput o = h.in(); CHECK(o.head == nullptr); draw(p.c, h.g.f, o); CHECK_EQ(differs_from_2d(h, h.g.f, o, p, h.g.very_good), 0);
    // Without the complete 2D set there is no persona face at all: the head never appears alone.
    DrawInput bare = h.g.in(); bare.art = nullptr; off.on = true; h.head->configure(off);
    choose_head(h.g.f, bare, h.head.get(), false); CHECK(bare.head == nullptr); CHECK(face_art(h.g.f, bare) == nullptr);
}

GUARDIAN_CASE(alert_and_no_data_never_use_the_3d_head) {
    HeadRig h; const auto forced = h.in(0, 0).head; CHECK(forced != nullptr);
    for (int i = 0; i < 20; ++i) h.g.r.c.receive(wpa3_deauth(h.g.r.clock));
    h.g.r.c.tick(); h.g.r.c.render(art_status(), h.g.f);
    CHECK(h.g.f.alert); CHECK(h.g.f.art == FaceArt::Alert);
    DrawInput in = h.in(20, 10); CHECK(in.head == nullptr);
    in.head = forced;                                             // even a caller that sets it by hand: the draw rule holds
    CHECK(face_art(h.g.f, in) != forced);
    Panel p; draw(p.c, h.g.f, in);
    CHECK_EQ(p.face(), FakeArt::colour(5 + persona::alert_pulse(h.g.t)));   // the red-eye ALERT portrait, the stare
    CHECK_EQ(p.at(0, 120), color::red);
    h.g.r.clock.at += Core::fresh_ms + 500; h.g.r.c.tick(); h.g.r.c.render(art_status(), h.g.f);
    CHECK(h.g.f.art == FaceArt::NoData);
    DrawInput stale = h.in(20, 10); CHECK(stale.head == nullptr);
    stale.head = forced; draw(p.c, h.g.f, stale);
    CHECK_EQ(p.face(), FakeArt::colour(15));                      // the expression-free silhouette
    Frame other = h.g.f; other.art = FaceArt::Rated; other.face_shown = false;   // details, list, onboarding
    DrawInput o = h.g.in(); choose_head(other, o, h.head.get(), false); CHECK(o.head == nullptr);
}

GUARDIAN_CASE(the_cigar_overlay_is_painted_on_the_2d_portrait_only) {
    HeadRig h; CHECK(h.g.f.celebrate);
    DrawInput flat = still_input(h.g.art, h.g.t);                 // ember and smoke at their defaults
    Panel p; draw(p.c, h.g.f, flat);
    CHECK(differs_from_2d(h, h.g.f, flat, p, h.g.very_good) > 20);   // 2D Very good: the ember glows on the cigar tip
    DrawInput in = flat; in.imu.active = true; choose_head(h.g.f, in, h.head.get(), false);
    CHECK(in.head != nullptr); draw(p.c, h.g.f, in);
    CHECK_EQ(differs_from_2d(h, h.g.f, in, p, HeadRig::frame(1, 1)), 0);   // 3D: the tip is somewhere else in every frame, so no overlay
}

GUARDIAN_CASE(upright_and_breathing_warp_the_chosen_3d_frame_like_any_portrait) {
    HeadRig h; auto in = h.in(30, 15); in.imu.tilt_deg = 90.0f; in.imu.scale = 0.85f; in.imu.dx = 2.0f;
    Panel with; draw(with.c, h.g.f, in);
    // The same frame handed over as an ordinary 2D portrait draws the same pixels.
    FakeArt as2d = h.g.art; const auto frame = HeadRig::frame(2, 2); as2d.set.rated[0] = frame.data();
    DrawInput plain = in; plain.head = nullptr; plain.art = &as2d.set;
    Panel want; draw(want.c, h.g.f, plain);
    CHECK_EQ(differing_rows(with, want, 0, Frame::height), 0);
    CHECK(band_differs(with, frame) > 1000);                      // and it really was turned
}

GUARDIAN_CASE(a_burst_takes_the_3d_frame_and_holds_it_until_it_lands) {
    HeadRig h; auto in = h.in(0, 0);
    const auto* art = face_art(h.g.f, in); CHECK(art == in.head);
    CHECK(h.g.b->begin(art, persona::PixelSource{nullptr, art}, h.g.t, face_pose(h.g.f, in), 0, 0, 5));
    int frames = 0; bool cancelled = false; Panel last; DrawInput last_in;
    while (h.g.b->active() && frames++ < 200) {
        in = h.in(30, 15);                                        // the shake turns the stick: the frame must not change under the particles
        CHECK(in.head == art);
        last_in = in; draw(last.c, h.g.f, in); cancelled = cancelled || (!h.g.b->active() && frames < 60);
        h.g.t += 40; h.g.b->step(h.g.t, 0, -1, face_pose(h.g.f, in));
    }
    CHECK(!cancelled); CHECK(frames > 80); CHECK(!h.g.b->active());
    CHECK_EQ(h.head->inflates(), 1u);
    CHECK_EQ(differs_from_2d(h, h.g.f, last_in, last, HeadRig::frame(1, 1)), 0);   // it landed as the frame it left from
    in = h.in(30, 15); CHECK(in.head != nullptr && in.head != art);   // then the head follows the stick again
    Panel after; draw(after.c, h.g.f, in);
    CHECK_EQ(differs_from_2d(h, h.g.f, in, after, HeadRig::frame(2, 2)), 0);
}

GUARDIAN_CASE(a_3d_frame_that_fails_paints_the_2d_portrait) {
    HeadRig h(1 * 3 + 2);                                         // the frame at yaw 30, pitch 0 is corrupt
    Panel p; auto in = h.in(0, 0); draw(p.c, h.g.f, in); CHECK_EQ(differs_from_2d(h, h.g.f, in, p, HeadRig::frame(1, 1)), 0);
    in = h.in(30, 0); CHECK(in.head == nullptr); draw(p.c, h.g.f, in);
    CHECK_EQ(differs_from_2d(h, h.g.f, in, p, h.g.very_good), 0);   // never a half-inflated frame
    in = h.in(0, 0); CHECK(in.head == nullptr); draw(p.c, h.g.f, in);
    CHECK_EQ(differs_from_2d(h, h.g.f, in, p, h.g.very_good), 0);   // and the set stays off: one face, not two taking turns
    CHECK_EQ(h.head->failures(), 1u);
}

// G23 (G22 review H2): the dim view is the Guardian's state, whatever screen was left open. Only the
// Face screen fills alert / caution / art, so a stick left on Details or on the network list painted
// the grey outline and "NO DATA" while dimmed: during a red ALERT, and also with a fresh rating.
// render_dim() gives draw_dim() the Face screen's decision; the open screen itself is not changed.
GUARDIAN_CASE(dim_view_shows_the_alert_and_the_rating_whatever_screen_was_left_open) {
    FakeArt art; const Status st = art_status();
    auto red = [](const Panel& p) { int n = 0; for (auto v : p.px) n += v == color::red; return n; };
    {   // a fresh rating, no incident
        VeryGoodRig r; Frame face; r.c.render_dim(st, face);
        CHECK(face.art == FaceArt::Rated); CHECK(face.face == Mood::VeryGood); CHECK(!face.alert);
        Panel on_face; draw_dim(on_face.c, face, &art.set); CHECK_EQ(on_face.face(), FakeArt::colour(0));
        r.c.input(Action::Primary); CHECK_EQ(r.c.presenter().screen(), Screen::Details);
        Frame f; r.c.render_dim(st, f);
        CHECK(f.art == FaceArt::Rated); CHECK(f.face == Mood::VeryGood); CHECK(f.persona);
        Panel on_details; draw_dim(on_details.c, f, &art.set);
        CHECK(on_details.px == on_face.px);                                   // the same dim frame as from the Face screen
        CHECK_EQ(r.c.presenter().screen(), Screen::Details);                  // the open screen is untouched
        Frame lit; r.c.render(st, lit); CHECK(!lit.face_shown); CHECK(lit.art == FaceArt::None);   // and so is its lit frame
    }
    {   // a red ALERT
        VeryGoodRig r;
        for (int i = 0; i < 20; ++i) r.c.receive(wpa3_deauth(r.clock));
        r.c.tick(); CHECK(r.c.presenter().view().alert);
        Frame face; r.c.render_dim(st, face); CHECK(face.alert); CHECK(face.art == FaceArt::Alert);
        Panel on_face; draw_dim(on_face.c, face, &art.set);
        CHECK(red(on_face) > 300);                                            // red edge + "ALERT"
        r.c.input(Action::Primary); CHECK_EQ(r.c.presenter().screen(), Screen::Details);
        CHECK(r.c.presenter().view().alert);
        Frame f; r.c.render_dim(st, f);
        CHECK(f.alert); CHECK(f.art == FaceArt::Alert); CHECK_EQ(f.face_color, color::red);
        Panel on_details; draw_dim(on_details.c, f, &art.set);
        CHECK(red(on_details) > 300); CHECK(on_details.px == on_face.px);     // never the grey "NO DATA"
        r.c.input(Action::SecondaryLong); CHECK_EQ(r.c.presenter().screen(), Screen::Picker);
        CHECK(r.c.presenter().view().alert);
        Frame g; r.c.render_dim(st, g); CHECK(g.alert);
        Panel on_list; draw_dim(on_list.c, g, &art.set);
        CHECK(red(on_list) > 300); CHECK(on_list.px == on_face.px);
        CHECK_EQ(r.c.presenter().screen(), Screen::Picker);
    }
    {   // no art on the build: the placeholder also shows the red sign from Details
        VeryGoodRig r; Status plain{}; plain.radio = RadioState::Monitoring;
        for (int i = 0; i < 20; ++i) r.c.receive(wpa3_deauth(r.clock));
        r.c.tick(); r.c.input(Action::Primary); CHECK_EQ(r.c.presenter().screen(), Screen::Details);
        Frame f; r.c.render_dim(plain, f); Panel p; draw_dim(p.c, f);
        CHECK(f.alert); CHECK(red(p) > 2000);
    }
}

// ---- G24: the device settings through the Companion, and the Settings screen's look (TDD, red first) ----
namespace {
// The owner-approved look (firmware/evidence/sticks3-G24-settings-look-20261121.png, "perfect", 2026-11-21),
// rebuilt line by line from the S6 preview that drew it: compose() must give exactly these lines.
struct LookOption { const char* big; const char* big2; const char* hours; const char* mark; std::uint16_t mark_c; const char* cost1; const char* cost2; };
void look_add(Frame& f, const char* t, int x, int y, int scale, std::uint16_t c, bool plated = false, std::uint16_t plate_c = color::black) {
    Line& l = f.lines[f.count++];
    std::snprintf(l.text.data(), l.text.size(), "%s", t);
    l.x = static_cast<std::int16_t>(x); l.y = static_cast<std::int16_t>(y); l.scale = static_cast<std::uint8_t>(scale); l.color = c;
    l.plated = plated; l.plate = plate_c;
}
int look_centered(const char* t, int scale) { const int w = int(std::strlen(t)) * 6 * scale; return (Frame::width - w) / 2 < 0 ? 0 : (Frame::width - w) / 2; }
void look_center(Frame& f, const char* t, int y, int scale, std::uint16_t c) { look_add(f, t, look_centered(t, scale), y, scale, c); }
Frame look(const char* title, int idx, const LookOption& o, bool saved_flash) {
    Frame f; f.header_color = color::grey;
    char tag[24]; std::snprintf(tag, sizeof tag, "SETTINGS %d/%d", idx, 3);   // G25: a third page
    look_add(f, tag, 0, Frame::tag_y, 1, color::black, true, color::grey);
    look_center(f, title, 26, 1, color::grey);
    look_add(f, "<", 2, 78, 2, color::grey);
    look_add(f, ">", Frame::width - 14, 78, 2, color::grey);
    if (o.big2) { look_center(f, o.big, 64, 2, color::white); look_center(f, o.big2, 86, 2, color::white); }
    else look_center(f, o.big, 76, o.big[0] >= '0' && o.big[0] <= '9' ? 3 : 2, color::white);
    if (o.hours[0] == '-') look_center(f, "not measured yet", 126, 1, color::grey); else look_center(f, o.hours, 120, 2, color::white);
    if (o.mark) look_center(f, o.mark, 142, 1, o.mark_c);
    if (o.cost1) look_center(f, o.cost1, 166, 1, amber);
    if (o.cost2) look_center(f, o.cost2, 177, 1, amber);
    if (saved_flash) look_add(f, "   SAVED   ", look_centered("   SAVED   ", 2), 196, 2, color::black, true, color::green);
    look_center(f, "SIDE next  BLUE back", 216, 1, color::grey);   // G25 keys (owner 2026-11-23)
    look_center(f, "hold SIDE = save", 228, 1, color::grey);
    return f;
}
std::string line_diff(const Frame& got, const Frame& want) {
    std::string out;
    if (got.count != want.count) out += "count " + std::to_string(got.count) + " vs " + std::to_string(want.count) + "; ";
    for (std::uint8_t i = 0; i < std::max(got.count, want.count); ++i) {
        const Line g = i < got.count ? got.lines[i] : Line{}, w = i < want.count ? want.lines[i] : Line{};
        if (std::strcmp(g.text.data(), w.text.data()) || g.x != w.x || g.y != w.y || g.scale != w.scale || g.color != w.color
            || g.plated != w.plated || (g.plated && g.plate != w.plate))
            out += "[" + std::to_string(i) + "] '" + g.text.data() + "'@" + std::to_string(g.x) + "," + std::to_string(g.y) + " vs '" + w.text.data()
                + "'@" + std::to_string(w.x) + "," + std::to_string(w.y) + "; ";
    }
    if (got.overflow) out += "overflow; ";
    if (got.header_color != want.header_color || got.hud.shown || got.face_shown || got.persona) out += "frame flags; ";
    return out;
}
struct SettingsRig {
    Clock clock; Monitor m{clock, profiles::all_2g4_channels(), Origin::LiveRadio};
    MemoryBlob blob, settings_blob; EncodedSelectionStore store{blob}; DeviceSettingsStore settings{settings_blob};
    Companion c{clock, m, store, lcd(), Origin::LiveRadio};
    void boot() { c.attach_settings(settings); c.boot(); }
    void open_settings() { c.input(Action::PrimaryLong); }   // G24 retry: hold FRONT on the face
    Frame frame() { Frame f; Status st{}; st.radio = RadioState::Monitoring; compose(c.presenter(), st, f); return f; }
};
} // namespace

GUARDIAN_CASE(g24_companion_loads_saves_and_reports_device_settings) {
    SettingsRig r;
    std::uint8_t rec[settings_record_bytes]; DeviceChoices stored; stored.guard = GuardCycle::EveryMinute; stored.bright_pct = 80;
    CHECK_EQ(encode_settings(stored, rec, sizeof rec), settings_record_bytes);
    r.settings_blob.bytes.assign(rec, rec + sizeof rec); r.settings_blob.exists = true;
    r.boot();
    CHECK(r.c.device() == stored); CHECK(r.c.settings_store() == SettingsStore::Restored); CHECK_EQ(unsigned(r.c.lit_brightness_pct()), 80u);
    CHECK(r.c.input(Action::PrimaryLong)); CHECK_EQ(r.c.presenter().screen(), Screen::Settings);   // hold FRONT on the face
    r.c.input(Action::Secondary);                                                  // EVERY MINUTE -> ALWAYS (G25: SIDE)
    CHECK(r.c.input(Action::SecondaryLong));                                       // G25: hold SIDE saves
    CHECK(r.c.settings_store() == SettingsStore::Saved); CHECK(r.c.device().guard == GuardCycle::Always);
    DeviceChoices back; CHECK(decode_settings(r.settings_blob.bytes.data(), r.settings_blob.bytes.size(), back));
    CHECK(back.guard == GuardCycle::Always); CHECK_EQ(unsigned(back.bright_pct), 80u);
    CHECK(r.c.presenter().settings().plate == SavePlate::Saved);
    // A failed write: SAVE FAILED on the glass, the value in effect unchanged.
    r.clock.at += Presenter::settings_plate_ms; r.c.tick();
    CHECK(r.c.presenter().settings().page == SettingsPage::Brightness);
    r.settings_blob.fail_write = true;
    r.c.input(Action::Secondary); CHECK_EQ(unsigned(r.c.lit_brightness_pct()), 100u);   // previewed
    r.c.input(Action::SecondaryLong);
    CHECK(r.c.settings_store() == SettingsStore::Failed); CHECK_EQ(unsigned(r.c.device().bright_pct), 80u);
    CHECK(r.c.presenter().settings().plate == SavePlate::Failed);
    const auto f = r.frame(); const Line* plate = line_with(f, "SAVE FAILED");
    CHECK(plate != nullptr); if (plate) { CHECK(plate->plated); CHECK_EQ(plate->y, 196); CHECK_EQ(plate->scale, 2); CHECK_EQ(plate->plate, color::red); }
    CHECK(fits_without_overlap(f));
    // No store attached: the defaults, and every save fails.
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion bare(clock, m, store, lcd(), Origin::LiveRadio); bare.boot();
    CHECK(bare.device() == DeviceChoices{}); CHECK(bare.settings_store() == SettingsStore::Default);
}

GUARDIAN_CASE(g24_a_corrupt_settings_record_boots_the_defaults) {
    SettingsRig r; r.settings_blob.bytes.assign(settings_record_bytes, 0x5A); r.settings_blob.exists = true; r.boot();
    CHECK(r.c.device() == DeviceChoices{}); CHECK(r.c.settings_store() == SettingsStore::Corrupt);
    SettingsRig a; a.boot(); CHECK(a.c.settings_store() == SettingsStore::Default);
}

GUARDIAN_CASE(g24_settings_pages_are_exactly_the_approved_look) {
    SettingsRig r; r.boot(); r.open_settings();
    const LookOption always{"ALWAYS", nullptr, "2h 05m", "lowest, measured", color::grey, "never blind", nullptr};
    const LookOption half{"EVERY", "30 S", "-", nullptr, color::grey, "alert up to 20s late", "short bursts missed"};
    const LookOption minute{"EVERY", "MINUTE", "7h 14m", "highest, measured", color::green, "alert up to 50s late", "short bursts missed"};
    const LookOption b30{"30%", nullptr, "-", nullptr, color::grey, "costs only while lit", nullptr};
    const LookOption b100{"100%", nullptr, "-", nullptr, color::grey, "costs only while lit", nullptr};
    const LookOption b60{"60%", nullptr, "-", nullptr, color::grey, "costs only while lit", nullptr};
    std::string d;
    d = line_diff(r.frame(), look("GUARD ON BATTERY", 1, always, false)); CHECK_EQ(d, std::string());
    r.c.input(Action::Secondary); d = line_diff(r.frame(), look("GUARD ON BATTERY", 1, half, false)); CHECK_EQ(d, std::string());
    r.c.input(Action::Secondary); d = line_diff(r.frame(), look("GUARD ON BATTERY", 1, minute, false)); CHECK_EQ(d, std::string());
    r.c.input(Action::SecondaryLong); d = line_diff(r.frame(), look("GUARD ON BATTERY", 1, minute, true)); CHECK_EQ(d, std::string());
    r.clock.at += Presenter::settings_plate_ms; r.c.tick();
    d = line_diff(r.frame(), look("BRIGHTNESS", 2, b60, false)); CHECK_EQ(d, std::string());
    r.c.input(Action::Secondary); r.c.input(Action::Secondary); r.c.input(Action::Secondary); r.c.input(Action::Secondary);   // 80, 100, 10, 30
    d = line_diff(r.frame(), look("BRIGHTNESS", 2, b30, false)); CHECK_EQ(d, std::string());
    r.c.input(Action::Secondary); r.c.input(Action::Secondary); r.c.input(Action::Secondary);                                // 60, 80, 100
    d = line_diff(r.frame(), look("BRIGHTNESS", 2, b100, false)); CHECK_EQ(d, std::string());
    CHECK(fits_without_overlap(r.frame()));
    CHECK_EQ(scale_of(r.frame(), "100%"), 3);
}

GUARDIAN_CASE(g24_hold_front_opens_settings_and_the_details_pages_are_as_before) {
    // G24 retry (owner 2026-11-21): no DEVICE SETTINGS details page; hold FRONT opens Settings from the face and details.
    SettingsRig r; r.boot();
    r.c.input(Action::Primary); CHECK_EQ(r.c.presenter().screen(), Screen::Details);
    CHECK(has_words(r.frame(), "Advertised Wi-Fi settings"));                       // the first page, as before G24
    for (int i = 0; i < 20 && r.c.presenter().screen() == Screen::Details; ++i) {
        const auto f = r.frame();
        CHECK(!has(f, "DEVICE SETTINGS")); CHECK(!has(f, "SIDE = open")); CHECK(has(f, "side: back"));
        r.c.input(Action::Primary);
    }
    CHECK_EQ(r.c.presenter().screen(), Screen::Face);
    r.c.input(Action::Primary); r.c.input(Action::Primary);
    CHECK(r.c.input(Action::PrimaryLong)); CHECK_EQ(r.c.presenter().screen(), Screen::Settings); CHECK(!r.c.presenter().view().demo);
    CHECK(has(r.frame(), "GUARD ON BATTERY"));
    CHECK(r.c.input(Action::Primary)); CHECK_EQ(r.c.presenter().screen(), Screen::Face);   // G25: BLUE leaves
    r.open_settings(); CHECK_EQ(r.c.presenter().screen(), Screen::Settings); CHECK(!r.c.presenter().view().demo);
    // The Buttons onboarding page tells the new hold: settings, never demo faces.
    Frame b; compose_onboarding(1, b);
    CHECK(has_words(b, "Hold BLUE: settings")); CHECK(!has_words(b, "demo")); CHECK(fits_without_overlap(b));
}

// ---- G25: router changes through the real Monitor, ROUTER CHANGES on the Settings screen, the keys (TDD, red first) ----
namespace {
Packet fixture_live(const Clock& clock, const char* name, std::uint8_t ds_channel = 0) {
    guardian::fixtures::Fixture fx; std::string error;
    Packet p{};
    if (!guardian::fixtures::load(name, fx, error)) return p;
    std::memcpy(p.bytes.data(), fx.bytes.data(), fx.bytes.size()); p.size = static_cast<std::uint16_t>(fx.bytes.size());
    p.meta.acquired = {clock.epoch(), clock.now(), true};
    p.meta.origin = Origin::LiveRadio; p.meta.status = RxStatus::Ok; p.meta.channel = ds_channel ? ds_channel : 6;
    p.meta.rssi_dbm = -48; p.meta.rssi_valid = true;
    if (ds_channel) for (std::size_t i = 36; i + 2 < p.size; i += 2u + p.bytes[i + 1]) if (p.bytes[i] == 3 && p.bytes[i + 1] == 1) { p.bytes[i + 2] = ds_channel; break; }
    return p;
}
// The VeryGoodRig with a settings store and a status buffer: the WPA3 network picked from the list.
struct RouterRig {
    Clock clock; Monitor m{clock, profiles::all_2g4_channels(), Origin::LiveRadio};
    MemoryBlob blob, settings_blob; EncodedSelectionStore store{blob}; DeviceSettingsStore settings{settings_blob};
    Companion c{clock, m, store, lcd(), Origin::LiveRadio};
    RouterRig() {
        c.attach_settings(settings); c.boot(); c.receive(wpa3_live(clock)); c.tick();
        c.input(Action::SecondaryLong); c.input(Action::Secondary);       // choose the one listed network
        c.receive(wpa3_live(clock)); c.tick();
    }
    void feed(const char* name, int n, std::uint8_t ds = 0) {
        for (int i = 0; i < n; ++i) { clock.at += 100; c.receive(fixture_live(clock, name, ds)); }
        c.tick();
    }
    Frame frame() { Frame f; Status st{}; st.radio = RadioState::Monitoring; st.persona_art = true; c.render(st, f); return f; }
    PersistedSelection stored() const { PersistedSelection p{}; decode(blob.bytes.data(), blob.bytes.size(), p); return p; }
    std::string status() const { char t[2048]; return m.status_text(t, sizeof t) ? std::string(t) : std::string("overflow"); }
};
SettingsFingerprint fingerprint_of(const char* name) {
    guardian::fixtures::Fixture fx; std::string error;
    if (!guardian::fixtures::load(name, fx, error)) return {};
    RxMeta meta{}; meta.status = RxStatus::Ok;
    const auto p = SecurityFrameParser{}.parse({fx.bytes.data(), static_cast<std::uint16_t>(fx.bytes.size()), false}, meta);
    return SettingsFingerprint::of(p.settings);
}
} // namespace

GUARDIAN_CASE(g25_the_router_changing_its_security_is_amber_accepted_on_details_and_stored) {
    RouterRig r;
    CHECK(r.m.scope().has_selection()); CHECK(r.m.scope().selected().settings_known);
    CHECK(r.stored().selected.settings == fingerprint_of("beacon_wpa3_sae_pmf_required"));
    const auto writes = r.blob.writes;
    r.feed("beacon_wpa2_ccmp_pmf_optional", 3);
    const auto& v = r.c.presenter().view();
    CHECK(!v.alert); CHECK(v.router_amber); CHECK(v.router.change.pending);
    // The face: amber, the rating's label stays, the router's words (never "attack").
    Frame f = r.frame();
    CHECK(f.caution || f.header_color == amber); CHECK(!f.alert);
    CHECK(has_words(f, "Router changed")); CHECK(!forbidden_claim(f)); CHECK(fits_without_overlap(f));
    // STATUS says what it was, never guesswork.
    const auto st = r.status();
    CHECK(st.find(" baseline_last=bssid:") != std::string::npos);
    CHECK(st.find(",changes:rsn+pmf,count:3,age_s:0") != std::string::npos);
    CHECK(st.find(" channel_moves=0,last:none") != std::string::npos);
    CHECK(st.find("baseline:frames=") != std::string::npos);
    // BLUE: the Router page first, in plain words, with the accept hint.
    r.c.input(Action::Primary); CHECK_EQ(r.c.presenter().details().page, DetailsPage::Router);
    f = r.frame();
    CHECK(has_words(f, "Your router changed")); CHECK(has_words(f, "PMF (required -> optional)")); CHECK(has_words(f, "downgrade"));
    CHECK(has_words(f, "hold side: accept new")); CHECK(!f.overflow); CHECK(fits_without_overlap(f)); CHECK(!forbidden_claim(f));
    // Hold SIDE accepts: the new settings become the baseline and are stored; the amber ends.
    CHECK(r.c.input(Action::SecondaryLong));
    CHECK_EQ(r.c.presenter().screen(), Screen::Face);
    CHECK(!r.c.presenter().view().router_amber);
    CHECK(r.m.scope().selected().settings == fingerprint_of("beacon_wpa2_ccmp_pmf_optional"));
    CHECK(r.blob.writes > writes); CHECK(r.stored().selected.settings == fingerprint_of("beacon_wpa2_ccmp_pmf_optional"));
    // The router keeps the new settings: nothing comes back.
    r.feed("beacon_wpa2_ccmp_pmf_optional", 20);
    CHECK(!r.c.presenter().view().router_amber); CHECK(!r.c.presenter().view().alert);
    CHECK(!r.c.presenter().view().router.change.pending);
}

GUARDIAN_CASE(g25_a_channel_move_is_stored_shown_grey_and_counted_in_status) {
    RouterRig r;
    CHECK(r.m.scope().selected().channel_known); CHECK_EQ(unsigned(r.m.scope().selected().channel), 6u);
    const auto writes = r.blob.writes;
    r.feed("beacon_wpa3_sae_pmf_required", 3, 11);
    CHECK_EQ(unsigned(r.m.scope().selected().channel), 11u);          // re-baselined at once
    CHECK(r.blob.writes > writes); CHECK_EQ(unsigned(r.stored().selected.channel), 11u);   // and stored for the next boot
    const auto& v = r.c.presenter().view();
    CHECK(!v.alert); CHECK(!v.router_amber); CHECK_EQ(v.router.moves, 1u);
    const auto st = r.status();
    CHECK(st.find(" channel_moves=1,last:6->11") != std::string::npos);
    CHECK(st.find(",changes:channel,count:2,") != std::string::npos);
    // The grey line on the Advertised Wi-Fi settings page; the page still fits.
    r.c.input(Action::Primary); CHECK_EQ(r.c.presenter().details().page, DetailsPage::Settings);
    const Frame f = r.frame();
    const Line* l = line_with(f, "Router moved ch 6->11");
    CHECK(l != nullptr); if (l) CHECK_EQ(l->color, color::grey);
    CHECK(!f.overflow); CHECK(fits_without_overlap(f));
    // A second boot restores channel 11: no new move is counted.
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); EncodedSelectionStore store(r.blob);
    Companion again(clock, m, store, lcd(), Origin::LiveRadio); CHECK_EQ(again.boot(), StoreState::Restored);
    for (int i = 0; i < 5; ++i) { clock.at += 100; again.receive(fixture_live(clock, "beacon_wpa3_sae_pmf_required", 11)); }
    again.tick(); CHECK_EQ(m.router().moves, 0u);
}

GUARDIAN_CASE(g25_strict_alert_and_details_only_through_the_companion) {
    RouterRig r;
    // Set through the Settings screen: page 3, SIDE to STRICT, hold SIDE to save.
    r.c.input(Action::PrimaryLong);
    for (int i = 0; i < 2; ++i) { r.c.input(Action::SecondaryLong); r.clock.at += Presenter::settings_plate_ms; r.c.tick(); }
    CHECK(r.c.presenter().settings().page == SettingsPage::Router);
    r.c.input(Action::Secondary); CHECK(r.c.presenter().settings().shown.router == RouterPolicy::Strict);
    r.c.input(Action::SecondaryLong); CHECK(r.c.device().router == RouterPolicy::Strict);
    DeviceChoices back; CHECK(decode_settings(r.settings_blob.bytes.data(), r.settings_blob.bytes.size(), back)); CHECK(back.router == RouterPolicy::Strict);
    r.clock.at += Presenter::settings_plate_ms; r.c.tick(); CHECK_EQ(r.c.presenter().screen(), Screen::Face);
    r.feed("beacon_wpa2_ccmp_pmf_optional", 3);
    CHECK(r.c.presenter().view().alert); CHECK(r.c.presenter().view().router_alert);
    Frame f = r.frame(); CHECK(f.alert); CHECK(has_words(f, "Router changed security")); CHECK(fits_without_overlap(f));
    CHECK(!has_words(f, "0 in 0s"));   // no Core incident behind it: no burst count line
    // Its Details page fits (the red status slot has two rows).
    r.c.input(Action::Primary); CHECK_EQ(r.c.presenter().details().page, DetailsPage::Router);
    f = r.frame(); CHECK(!f.overflow); CHECK(fits_without_overlap(f)); CHECK(has_words(f, "hold side: accept new"));
    // DETAILS ONLY: the same change shows no colour on the face; the Router page still lists it.
    RouterRig q;
    q.c.input(Action::PrimaryLong);
    for (int i = 0; i < 2; ++i) { q.c.input(Action::SecondaryLong); q.clock.at += Presenter::settings_plate_ms; q.c.tick(); }
    q.c.input(Action::Secondary); q.c.input(Action::Secondary); CHECK(q.c.presenter().settings().shown.router == RouterPolicy::DetailsOnly);
    q.c.input(Action::SecondaryLong); q.clock.at += Presenter::settings_plate_ms; q.c.tick();
    q.feed("beacon_wpa2_ccmp_pmf_optional", 3);
    f = q.frame(); CHECK(!f.alert); CHECK(!f.caution); CHECK(f.header_color != amber); CHECK(!has_words(f, "Router changed"));
    q.c.input(Action::Primary); CHECK_EQ(q.c.presenter().details().page, DetailsPage::Router);
    f = q.frame(); CHECK(has_words(f, "Your router changed its security settings")); CHECK(!f.overflow);
}

GUARDIAN_CASE(g25_settings_page_three_router_changes_and_the_new_hints) {
    SettingsRig r; r.boot(); r.open_settings();
    for (int i = 0; i < 2; ++i) { r.c.input(Action::SecondaryLong); r.clock.at += Presenter::settings_plate_ms; r.c.tick(); }
    CHECK(r.c.presenter().settings().page == SettingsPage::Router);
    struct Want { const char* big; const char* big2; const char* note; const char* l1; std::uint16_t c1; const char* l2; std::uint16_t c2; };
    const Want amber_w{"AMBER", nullptr, "default", "security change: amber", amber, "channel move: grey", color::grey};
    const Want strict_w{"STRICT", nullptr, nullptr, "security change: red", color::red, "channel move: amber", amber};
    const Want details_w{"DETAILS", "ONLY", nullptr, "router changes listed", color::grey, "on Details, no colour", color::grey};
    for (const auto* w : {&amber_w, &strict_w, &details_w}) {
        Frame want; want.header_color = color::grey;
        look_add(want, "SETTINGS 3/3", 0, Frame::tag_y, 1, color::black, true, color::grey);
        look_center(want, "ROUTER CHANGES", 26, 1, color::grey);
        look_add(want, "<", 2, 78, 2, color::grey);
        look_add(want, ">", Frame::width - 14, 78, 2, color::grey);
        if (w->big2) { look_center(want, w->big, 64, 2, color::white); look_center(want, w->big2, 86, 2, color::white); }
        else look_center(want, w->big, 76, 2, color::white);
        if (w->note) look_center(want, w->note, 126, 1, color::grey);
        look_center(want, w->l1, 166, 1, w->c1);
        look_center(want, w->l2, 177, 1, w->c2);
        look_center(want, "SIDE next  BLUE back", 216, 1, color::grey);
        look_center(want, "hold SIDE = save", 228, 1, color::grey);
        const auto got = r.frame();
        CHECK_EQ(line_diff(got, want), std::string()); CHECK(fits_without_overlap(got));
        r.c.input(Action::Secondary);
    }
    // The Buttons onboarding page tells the Settings keys.
    Frame b; compose_onboarding(1, b);
    CHECK(has_words(b, "Hold BLUE: settings")); CHECK(has_words(b, "SIDE next")); CHECK(has_words(b, "hold SIDE save"));
    CHECK(has_words(b, "BLUE back")); CHECK(fits_without_overlap(b));
}

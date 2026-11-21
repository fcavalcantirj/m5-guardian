// G16C host preview: renders every companion screen with the REAL composer,
// renderer and embedded portraits into PPM files (one per screen) for the
// evidence sheet. Not a test and not radio evidence: generated packets are
// Imported/LiveRadio-stamped host input only, exactly like companion_check.
//   companion_preview <out dir>
#include "battery.hpp"
#include "companion.hpp"
#include "fixtures.hpp"
#include "persona.hpp"
#include <array>
#include <cstdio>
#include <cmath>
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
Packet beacon(const Clock& clock, std::uint8_t tail, const char* ssid, std::int8_t rssi = -52) {
    Packet p{}; const auto n = std::strlen(ssid);
    p.meta.acquired = {clock.epoch(), clock.now(), true};
    p.meta.origin = Origin::LiveRadio; p.meta.status = RxStatus::Ok; p.meta.channel = 6;
    p.meta.rssi_dbm = rssi; p.meta.rssi_valid = true;
    p.bytes[0] = 0x80; p.bytes[16] = 2; p.bytes[21] = tail; p.bytes[10] = 2; p.bytes[15] = tail;
    p.bytes[36] = 0; p.bytes[37] = static_cast<std::uint8_t>(n);
    std::memcpy(p.bytes.data() + 38, ssid, n);
    const auto at = 38 + n; p.bytes[at] = 3; p.bytes[at + 1] = 1; p.bytes[at + 2] = 6;
    p.size = static_cast<std::uint16_t>(at + 3); return p;
}
Packet wpa3(const Clock& clock) {
    guardian::fixtures::Fixture fx; std::string error; Packet p{};
    if (!guardian::fixtures::load("beacon_wpa3_sae_pmf_required", fx, error)) { std::fprintf(stderr, "fixture: %s\n", error.c_str()); return p; }
    std::memcpy(p.bytes.data(), fx.bytes.data(), fx.bytes.size()); p.size = static_cast<std::uint16_t>(fx.bytes.size());
    p.meta.acquired = {clock.epoch(), clock.now(), true};
    p.meta.origin = Origin::LiveRadio; p.meta.status = RxStatus::Ok; p.meta.channel = 6; p.meta.rssi_dbm = -48; p.meta.rssi_valid = true;
    return p;
}
Packet deauth_of(Packet p) { p.size = 26; p.bytes[0] = 0xc0; p.bytes[24] = 7; p.bytes[25] = 0; return p; }
// G16E: a wildcard probe request from a randomized-looking source `n`.
Packet probe(const Clock& clock, std::uint16_t n) {
    Packet p{}; p.meta.acquired = {clock.epoch(), clock.now(), true};
    p.meta.origin = Origin::LiveRadio; p.meta.status = RxStatus::Ok; p.meta.channel = 6; p.meta.rssi_dbm = -60; p.meta.rssi_valid = true;
    p.bytes[0] = 0x40; for (int i = 4; i < 10; ++i) p.bytes[i] = 0xff;
    p.bytes[10] = 0xda; p.bytes[14] = static_cast<std::uint8_t>(n >> 8); p.bytes[15] = static_cast<std::uint8_t>(n);
    for (int i = 16; i < 22; ++i) p.bytes[i] = 0xff;
    p.bytes[24] = 0; p.bytes[25] = 0; p.size = 26; return p;
}
// PREVIEW ONLY (not a G16F detector, not evidence): emits one Probe-family Area
// observation with fixed illustrative numbers so the amber screens can be drawn.
class PreviewAreaSource final : public FrameDetector {
public:
    bool armed{};
    void on_frame(const FrameSpan&, const RxMeta& meta, const ParseResult& p, ObservationSink& out) override {
        if (p.kind == FrameKind::ProbeRequest) { ++events_; last_ = meta.acquired.at; }
        if (!armed) return;
        armed = false;
        IncidentObservation o{}; o.scope = IncidentScope::Area; o.family = DetectorFamily::Probe; o.origin = meta.origin;
        o.acquired = meta.acquired; o.count = 312; o.window_ms = 5000; o.threshold = 80; o.distinct_sources = 214; o.sources_random = true;
        out.incident(o);
    }
    void on_tick(Instant, ObservationSink&) override {}
    void reset() override {}
    DetectorReport report(Instant now) const override {
        DetectorReport r{}; r.name = "preview"; r.family = DetectorFamily::Probe; r.scope = IncidentScope::Area; r.configured = true;
        r.events_total = events_; r.last_event_known = events_ && now.at >= last_; r.last_event_age_ms = now.at - last_; return r;
    }
private:
    std::uint32_t events_{}; Millis last_{};
};
DisplayCapabilities lcd() { return {Support::Supported, 135, 240, PixelFormat::Rgb565, Support::Supported}; }

std::vector<std::uint8_t> load(const char* dir, const char* name) {
    std::string path = std::string(dir) + "/portrait/" + name + "_portrait.rgb565";
    std::vector<std::uint8_t> out(persona::art_bytes);
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f || std::fread(out.data(), 1, out.size(), f) != out.size()) { std::fprintf(stderr, "missing %s\n", path.c_str()); std::exit(2); }
    std::fclose(f); return out;
}
struct Art {
    std::vector<std::vector<std::uint8_t>> keep; persona::ArtSet set;
    explicit Art(const char* dir) {
        const char* moods[5] = {"VeryGood", "Good", "Medium", "Bad", "Horrible"};
        for (int m = 0; m < 5; ++m) {
            keep.push_back(load(dir, moods[m])); set.rated[m] = keep.back().data();
        }
        for (int m = 0; m < 5; ++m) for (int p = 0; p < 2; ++p) {
            keep.push_back(load(dir, (std::string(moods[m]) + "_ALERT_p" + char('0' + p)).c_str()));
            set.alert[m][p] = keep.back().data();
        }
        keep.push_back(load(dir, "NoData")); set.no_data = keep.back().data();
    }
};
const char* out_dir;
// Review 2026-11-17: `dim` renders the G16D dim view (still portrait + label) instead of the face.
void save(const char* name, const Frame& f, const DrawInput& in, const battery::State* batt = nullptr, bool dim = false) {
    std::array<std::uint16_t, 135 * 240> px{}; Canvas c(px.data(), 135, 240, false);
    if (dim) draw_dim(c, f, in.art); else draw(c, f, in);
    if (batt) battery::draw_indicator(c, *batt);
    std::string path = std::string(out_dir) + "/" + name + ".ppm";
    std::FILE* o = std::fopen(path.c_str(), "wb"); if (!o) { std::perror(path.c_str()); std::exit(3); }
    std::fprintf(o, "P6\n135 240\n255\n");
    for (auto v : px) {
        const unsigned char rgb[3] = {static_cast<unsigned char>(((v >> 11) & 31) * 255 / 31), static_cast<unsigned char>(((v >> 5) & 63) * 255 / 63),
                                      static_cast<unsigned char>((v & 31) * 255 / 31)};
        std::fwrite(rgb, 1, 3, o);
    }
    std::fclose(o);
    std::printf("%s overflow=%u lines=%u art=%d rssi=%d\n", name, unsigned(f.overflow), unsigned(f.count), int(f.art), int(f.hud.rssi));
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 3) { std::fprintf(stderr, "usage: companion_preview <art dir> <out dir>\n"); return 1; }
    out_dir = argv[2];
    Art art(argv[1]);
    battery::State batt; batt.known = true; batt.mv = 3980; batt.level = 79; batt.external = false; batt.charging = battery::Charging::No;
    DrawInput in; in.art = &art.set; in.anim_ms = 1200;
    Status st{}; st.radio = RadioState::Monitoring; st.persona_art = true; st.store = StoreState::Restored;
    Frame f;
    // Onboarding.
    for (std::uint8_t p = 0; p < Companion::onboarding_pages; ++p) { compose_onboarding(p, f); char n[32]; std::snprintf(n, sizeof n, "00-onboarding-%u", unsigned(p) + 1); save(n, f, in); }
    // No selection.
    { Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob; EncodedSelectionStore store(blob);
      Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot(); c.tick(); Status s2 = st; s2.radio = RadioState::Discovering;
      c.render(s2, f); save("01-no-selection", f, in, &batt);
      // DEMO: five ratings (G24 retry: the direct method; no key enters DEMO).
      c.set_demo(true);
      for (int i = 0; i < 5; ++i) { c.render(st, f); char n[32]; std::snprintf(n, sizeof n, "02-demo-%d-%s", i + 1, mood_text(f.face)); for (char* q = n; *q; ++q) if (*q == ' ') *q = '_'; save(n, f, in, &batt);
          n[0] = '2'; n[1] = '0'; save(n, f, in, &batt, true); c.input(Action::Secondary); }   // 20-demo-*: the dim view
      c.input(Action::PrimaryLong); }
    // Live WPA3 (Very good), then details, picker, alert, stale.
    { Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob; EncodedSelectionStore store(blob);
      Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot(); c.receive(wpa3(clock)); c.receive(beacon(clock, 9, "a-very-long-network-name-32bytes", -71));
      c.receive(beacon(clock, 3, "caf\xc3\xa9 wifi", -80)); c.tick();
      c.input(Action::SecondaryLong);
      for (int i = 0; i < 4 && !(c.presenter().picker().entries[c.presenter().picker().cursor].label.c_str()[0] != 'a' && c.presenter().picker().entries[c.presenter().picker().cursor].label.c_str()[0] != 'c'); ++i) c.input(Action::Primary);
      c.render(st, f); save("03-picker", f, in, &batt);
      c.input(Action::Secondary); clock.at += 3000; c.receive(wpa3(clock)); c.tick();
      c.render(st, f); save("04-live-verygood", f, in, &batt);
      DrawInput moved = in; moved.imu.active = true; moved.imu.dx = 3; moved.imu.dy = 1.5f; moved.imu.tilt_deg = -4; moved.imu.hud_dx = 1.8f;
      save("05-live-verygood-imu-tilt", f, moved, &batt);
      // Review 2026-11-17 (owner: IMU "radically weak ... weird on its edges"): strong poses for the edge study.
      // A = today's maximum (4 px, 5 deg); B = strong slide without pull-back (chops the hood);
      // C/D = strong tilt + slide with the pull-back; E = medium with pull-back.
      const struct { const char* n; float dx, dy, tilt, scale; } strong[] = {
          {"22-imu-A-today-max", 4, 0, -5, 1.0f}, {"22-imu-B-slide10-nopull", 10, 0, 0, 1.0f},
          {"22-imu-C-tilt12-pull", 6, 0, -12, 0.90f}, {"22-imu-D-mix-pull", -6, 4, 12, 0.90f},
          {"22-imu-E-medium-pull", 4, 2, -8, 0.94f}};
      for (const auto& s : strong) {
          DrawInput m2 = in; m2.imu.active = true; m2.imu.dx = s.dx; m2.imu.dy = s.dy;
          m2.imu.tilt_deg = s.tilt; m2.imu.scale = s.scale;
          save(s.n, f, m2, &batt);
      }
      // G16I upright: the motion model's own output with the stick held at each roll (USB down = 0),
      // standing 4 s at that angle; fit 1 (the default: the hood never leaves the glass) and fit 0.
      for (const int roll : {30, 45, 90, 135, 180, -90}) for (const int fit : {1, 0}) {
          if (!fit && roll != 45) continue;
          motion::Params mp; mp.bob_px = 0; mp.sway_deg = 0; mp.upright_fit = static_cast<float>(fit);
          motion::Model model; model.configure(motion::AxisMap{1, 2, 3}, mp);
          const float rad = static_cast<float>(roll) * 0.01745329252f; std::int64_t t_us = 0;
          for (int k = 0; k < 800; ++k) {
              motion::Reading rd; t_us += 5000; rd.t_us = t_us; rd.acc_g[0] = -std::sin(rad); rd.acc_g[1] = std::cos(rad);
              model.sample(rd); model.step(t_us);
          }
          DrawInput up = in; up.imu = model.output();
          char n[48]; std::snprintf(n, sizeof n, "23-upright-roll%+04d-fit%d", roll, fit); save(n, f, up, &batt);
      }
      {   // G16I burst: the face standing still, then shaken; and the same with the stick held on its side.
          const auto b = std::make_unique<burst::Burst>();
          const struct { const char* n; Millis at; } shots[] = {{"24-burst-1-explode-0.24s", 240}, {"24-burst-2-drift-1.20s", 1200},
              {"24-burst-3-reform-2.20s", 2200}, {"24-burst-4-reform-3.00s", 3000}, {"24-burst-5-landed-3.52s", 3520}};
          DrawInput bi = in; bi.motion.tilt_max_deg = 0; bi.motion.breath_amount = 0; bi.burst = b.get();
          Millis now = bi.anim_ms;
          if (b->begin(face_art(f, bi), persona::PixelSource{nullptr, face_art(f, bi)}, now, face_pose(f, bi), 0.6f, -0.4f, 20261117u))
              for (const auto& shot : shots) {
                  while (now < in.anim_ms + shot.at) { now += 40; b->step(now, 0.0f, -1.0f, face_pose(f, bi)); }
                  save(shot.n, f, bi, &batt);
              }
          b->cancel();
          motion::Params mp; mp.bob_px = 0; mp.sway_deg = 0;
          motion::Model model; model.configure(motion::AxisMap{1, 2, 3}, mp); std::int64_t t_us = 0;
          for (int k = 0; k < 800; ++k) { motion::Reading rd; t_us += 5000; rd.t_us = t_us; rd.acc_g[0] = -1.0f; model.sample(rd); model.step(t_us); }
          DrawInput side = bi; side.imu = model.output(); now = side.anim_ms;
          if (b->begin(face_art(f, side), persona::PixelSource{nullptr, face_art(f, side)}, now, face_pose(f, side), 0.0f, 0.0f, 7u)) {
              const struct { const char* n; Millis at; } turned[] = {{"25-burst-roll90-1-drift-1.20s", 1200}, {"25-burst-roll90-2-reform-3.00s", 3000}, {"25-burst-roll90-3-landed-3.52s", 3520}};
              for (const auto& shot : turned) {
                  while (now < side.anim_ms + shot.at) { now += 40; b->step(now, side.imu.up_x, side.imu.up_y, face_pose(f, side)); }
                  save(shot.n, f, side, &batt);
              }
              b->cancel(); save("25-burst-roll90-4-after", f, side, &batt);
          }
          // G16O: the stick handled after the shake (swung +-12 degrees at 1 Hz): the particles fall, pile up on
          // the side that is down and follow it when the stick is turned on its right side; held still, the
          // face comes back 2.6 s later.
          b->cancel(); now = bi.anim_ms;
          if (b->begin(face_art(f, bi), persona::PixelSource{nullptr, face_art(f, bi)}, now, face_pose(f, bi), 0.6f, -0.4f, 20261118u)) {
              const struct { const char* n; Millis until; float down_deg; bool still; } pile[] = {
                  {"26-pile-1-falling-1.00s", 1000, 0, false}, {"26-pile-2-standing-4.00s", 4000, 0, false},
                  {"26-pile-3-on-its-side-0.60s", 4600, 90, false}, {"26-pile-4-on-its-side-1.60s", 5600, 90, false}, {"26-pile-5-on-its-side-4.00s", 8000, 90, false},
                  {"26-pile-6-held-still-1.40s", 9400, 90, true}, {"26-pile-7-held-still-2.60s-landed", 10600, 90, true}};
              float down = 0;
              for (const auto& shot : pile) {
                  while (now < bi.anim_ms + shot.until) {
                      now += 40;
                      if (!shot.still) down = (shot.down_deg + 12.0f * std::sin(6.2831853f * static_cast<float>(now % 100000) / 1000.0f)) * 0.01745329252f;
                      b->step(now, -std::sin(down), -std::cos(down), face_pose(f, bi));
                  }
                  save(shot.n, f, bi, &batt);
              }
              b->cancel();
          }
      }
      c.input(Action::Primary);
      for (int i = 0; i < 12 && c.presenter().screen() == Screen::Details; ++i) {
          c.render(st, f); const auto& d = c.presenter().details();
          char n[48]; std::snprintf(n, sizeof n, "07-details-%d-p%u-%u", i + 1, unsigned(d.page_index) + 1, unsigned(d.page_count)); save(n, f, in, &batt);
          c.input(Action::Primary);
      }
      for (int i = 0; i < 20; ++i) c.receive(deauth_of(wpa3(clock)));
      c.tick(); c.render(st, f); save("08-alert-verygood-p0", f, in, &batt);
      save("21-dim-alert", f, in, &batt, true);
      DrawInput p1 = in; p1.anim_ms += persona::alert_pulse_ms; save("09-alert-verygood-p1", f, p1, &batt);
      clock.at += Core::fresh_ms + 2000; c.tick(); c.render(st, f); save("10-alert-stale", f, in, &batt);
      clock.at += Core::incident_ms; c.tick(); Status off = st; off.radio = RadioState::Off; c.render(off, f); save("11-no-fresh-data-radio-off", f, in, &batt);
      battery::State low = batt; low.mv = 3400; low.level = 6; low.low = true; c.render(st, f); save("12-no-fresh-data-low-battery", f, in, &low); }
    // Live open network (Horrible) with a long name, and its explanation pages.
    { Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob; EncodedSelectionStore store(blob);
      Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot(); c.receive(beacon(clock, 9, "a-very-long-network-name-32bytes", -63)); c.tick();
      c.input(Action::SecondaryLong); c.input(Action::Secondary); clock.at += 2000; c.receive(beacon(clock, 9, "a-very-long-network-name-32bytes", -63)); c.tick();
      c.render(st, f); save("13-live-horrible-long-name", f, in, &batt);
      { Status ts = st; ts.radio = RadioState::Off; ts.tune_session_s = 287; c.render(ts, f); save("13b-tune-session-wifi", f, in, &batt); }
      c.input(Action::Primary);
      for (int i = 0; i < 12 && c.presenter().screen() == Screen::Details; ++i) {
          c.render(st, f); const auto& d = c.presenter().details();
          char n[48]; std::snprintf(n, sizeof n, "14-open-details-%d-p%u-%u", i + 1, unsigned(d.page_index) + 1, unsigned(d.page_count)); save(n, f, in, &batt);
          c.input(Action::Primary);
      } }
    // No art (diagnostic fallback) stays honest.
    { Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob; EncodedSelectionStore store(blob);
      Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot(); c.receive(wpa3(clock)); c.tick(); c.input(Action::SecondaryLong); c.input(Action::Secondary);
      c.receive(wpa3(clock)); c.tick(); Status na = st; na.persona_art = false; c.render(na, f); save("15-no-art-fallback", f, DrawInput{}, &batt); }
    // G16E: threat radar, amber (nearby) vs red (your network), the Nearby page, the wary glance.
    { Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob; EncodedSelectionStore store(blob);
      PreviewAreaSource area; m.detectors().add(area);
      Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot();
      for (std::uint16_t i = 0; i < 40; ++i) c.receive(probe(clock, i));
      c.receive(wpa3(clock)); c.tick();
      Status s2 = st; s2.radio = RadioState::Discovering; c.render(s2, f); save("16-radar-no-selection", f, in, &batt);
      area.armed = true; c.receive(probe(clock, 99)); c.tick(); c.render(s2, f); save("17-amber-no-selection", f, in, &batt);
      c.input(Action::SecondaryLong); c.input(Action::Secondary); clock.at += 1000; c.receive(wpa3(clock)); c.tick();
      c.render(st, f); save("18-amber-verygood", f, in, &batt);
      DrawInput glance = in; glance.anim_ms = 3200; save("19-amber-verygood-glance", f, glance, &batt);
      c.input(Action::Primary);
      for (int i = 0; i < 14 && c.presenter().screen() == Screen::Details; ++i) {
          if (c.presenter().details().page == DetailsPage::Nearby) { c.render(st, f); save("20-nearby-details", f, in, &batt); }
          c.input(Action::Primary);
      }
      for (int i = 0; i < 20; ++i) c.receive(deauth_of(wpa3(clock)));
      c.tick(); c.render(st, f); save("21-red-alert-with-amber-nearby", f, in, &batt);
      clock.at += Core::incident_ms + 1000; c.receive(wpa3(clock)); for (std::uint16_t i = 0; i < 5; ++i) c.receive(probe(clock, i));
      c.tick(); c.render(st, f); save("22-radar-verygood-pulse", f, in, &batt); }
    // G24: the Settings screen through the real Companion (hold FRONT on the face opens it, G24 retry), in the order
    // of the owner-approved look (firmware/evidence/sticks3-G24-settings-look-20261121.png;
    // tools/settings_look_compare.py compares 24-settings-1..6 with it pixel by pixel), plus SAVE FAILED.
    { Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob, settings_blob; EncodedSelectionStore store(blob);
      DeviceSettingsStore settings(settings_blob);
      Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.attach_settings(settings); c.boot(); c.receive(wpa3(clock)); c.tick();
      c.input(Action::PrimaryLong);   // hold FRONT on the face
      c.render(st, f); save("24-settings-1-guard-always", f, in, &batt);
      c.input(Action::Primary); c.render(st, f); save("24-settings-2-guard-30s", f, in, &batt);
      c.input(Action::Primary); c.render(st, f); save("24-settings-3-guard-1min", f, in, &batt);
      c.input(Action::PrimaryLong); c.render(st, f); save("24-settings-4-guard-1min-saved", f, in, &batt);
      clock.at += Presenter::settings_plate_ms; c.tick();
      for (int i = 0; i < 4; ++i) c.input(Action::Primary);   // 60 -> 80, 100, 10, 30
      c.render(st, f); save("24-settings-5-brightness-30", f, in, &batt);
      for (int i = 0; i < 3; ++i) c.input(Action::Primary);   // 60, 80, 100
      c.render(st, f); save("24-settings-6-brightness-100", f, in, &batt);
      c.input(Action::Secondary); }
    { Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob; EncodedSelectionStore store(blob);
      struct Refusing final : BlobStorage {
          BlobRead read(std::uint8_t*, std::size_t, std::size_t&) const override { return BlobRead::Absent; }
          bool write(const std::uint8_t*, std::size_t) override { return false; }
      } refusing;
      DeviceSettingsStore settings(refusing);
      Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.attach_settings(settings); c.boot(); c.receive(wpa3(clock)); c.tick();
      c.input(Action::PrimaryLong); c.input(Action::Primary); c.input(Action::PrimaryLong);
      c.render(st, f); save("24-settings-7-save-failed", f, in, &batt); }
    return 0;
}

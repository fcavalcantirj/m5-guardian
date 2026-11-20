// G16C host micro-benchmark of the companion render path (rework 2026-11-16).
// Times, per screen kind, the stages the StickS3 loop runs every animated
// frame: Companion::render (presenter refresh + compose), draw (clear,
// portrait warp, overlays, HUD, text) and the dirty-row planner that decides
// the panel push. Host numbers are RELATIVE (a desktop CPU, not the 160 MHz
// ESP32-S3); they make regressions visible between builds. The device keeps
// its own FRAMES/STATUS timing.
//   render_bench <art dir> [frames] [--check]   prints one line per scenario;
//   --check also fails unless a still pose reuses the warped band (no timing bound).
// G16O: rated-burst-handled is the burst with the stick turned and swung the whole time: the particles lie in
// a pile that keeps sliding (the costliest burst frames; compare its draw_us with rated-moving, a warp per frame).
// G21: rated-3d-rest / rated-3d-turning draw the SHIPPED 3D head packs (GUARDIAN_HEAD_DIR): the head's
// frame choice and the inflate of each newly chosen frame are timed inside draw_us (the StickS3 counts
// them inside render). `3d-cost` prints what one inflate, one frame-to-frame blend (a cross-fade's
// per-frame extra) and one warp cost here, and how much two neighbouring frames differ.
// Not radio evidence: the packets are generated host input, as in companion_check.
#include "companion.hpp"
#include "dirty_rows.hpp"
#include "fixtures.hpp"
#include "head3d.hpp"
#include "persona.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
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
Packet wpa3(const Clock& clock) {
    guardian::fixtures::Fixture fx; std::string error; Packet p{};
    if (!guardian::fixtures::load("beacon_wpa3_sae_pmf_required", fx, error)) { std::fprintf(stderr, "fixture: %s\n", error.c_str()); std::exit(2); }
    std::memcpy(p.bytes.data(), fx.bytes.data(), fx.bytes.size()); p.size = static_cast<std::uint16_t>(fx.bytes.size());
    p.meta.acquired = {clock.epoch(), clock.now(), true};
    p.meta.origin = Origin::LiveRadio; p.meta.status = RxStatus::Ok; p.meta.channel = 6; p.meta.rssi_dbm = -48; p.meta.rssi_valid = true;
    return p;
}
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
        keep.reserve(16);
        const char* moods[5] = {"VeryGood", "Good", "Medium", "Bad", "Horrible"};
        for (int m = 0; m < 5; ++m) { keep.push_back(load(dir, moods[m])); set.rated[m] = keep.back().data(); }
        for (int m = 0; m < 5; ++m) for (int p = 0; p < 2; ++p) {
            keep.push_back(load(dir, (std::string(moods[m]) + "_ALERT_p" + char('0' + p)).c_str()));
            set.alert[m][p] = keep.back().data();
        }
        keep.push_back(load(dir, "NoData")); set.no_data = keep.back().data();
    }
};
DisplayCapabilities lcd() { return {Support::Supported, 135, 240, PixelFormat::Rgb565, Support::Supported}; }
using clk = std::chrono::steady_clock;
double us(clk::time_point a, clk::time_point b) { return std::chrono::duration<double, std::micro>(b - a).count(); }

struct Result { double render{}, draw{}, plan{}, head{}; unsigned rows{}, warps{}, frames{}, particles{}, bursts{}, lying{}, inflates{}, head_frames{}; };
// G21: the shipped head packs, read from disk as the board reads them from flash.
struct HeadPacks {
    std::vector<std::vector<std::uint8_t>> files;
    std::vector<std::uint8_t> a = std::vector<std::uint8_t>(persona::art_bytes), b = std::vector<std::uint8_t>(persona::art_bytes);
    std::unique_ptr<head3d::Head> head{new head3d::Head(a.data(), b.data())};
    explicit HeadPacks(const char* dir) {
        head3d::Params on; on.on = true; head->configure(on);   // the bench measures the 3D path on purpose (off by default since 2026-11-18)
        files.reserve(5);
        for (const char* mood : {"VeryGood", "Good", "Medium", "Bad", "Horrible"}) {
            std::FILE* f = std::fopen((std::string(dir) + "/" + mood + ".bin").c_str(), "rb");
            if (!f) continue;
            std::vector<std::uint8_t> bytes; std::uint8_t buf[65536]; std::size_t n;
            while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) bytes.insert(bytes.end(), buf, buf + n);
            std::fclose(f);
            files.push_back(std::move(bytes));
            const auto e = head->add(files.back().data(), files.back().size());
            if (e != head3d::PackError::Ok) { std::fprintf(stderr, "%s.bin: %s\n", mood, head3d::pack_error_text(e)); std::exit(2); }
        }
    }
};
// One scenario: `frames` animated frames at 40 ms, the stick at rest (moving = false) or handled.
// `burst` (G16I): the face is kept bursting (begun again whenever it has landed); its step and its
// particle paint are timed inside draw_us, as the StickS3 counts them inside render.
// `head` (G21): the rated face is the 3D head; `turning` swings the stick +-30 degrees of yaw every 2 s and
// +-30 of pitch every 6.8 s (the upright face otherwise at rest), so frames change as fast as a hand turns it.
// `handled` (G16O): the stick is turned round once every 8 s and swung +-12 degrees at 1 Hz while the
// face is burst, so the particles pile up and the pile keeps sliding (the costliest burst frames).
Result run(Companion& c, Clock& clock, const Status& st, const persona::ArtSet& art, persona::WarpCache* cache, bool moving, int frames,
           burst::Burst* burst = nullptr, head3d::Head* head = nullptr, bool turning = false, bool handled = false) {
    std::array<std::uint16_t, 135 * 240> px{};
    Canvas canvas(px.data(), 135, 240, true);
    sticks3::DirtyRows dirty;
    Frame f; Result r;
    const unsigned warps_before = cache ? cache->warps : 0, inflates_before = head ? head->inflates() : 0;
    for (int i = 0; i < frames; ++i) {
        clock.at += 40;
        DrawInput in; in.art = &art; in.anim_ms = clock.at; in.cache = cache;
        in.motion.tilt_max_deg = 0.0f;   // the StickS3 default (TUNE persona.sway_deg = 0)
        if (moving) { in.imu.active = true; in.imu.dx = 2.0f * static_cast<float>(i % 7) / 7.0f; in.imu.tilt_deg = -3.0f + 0.1f * static_cast<float>(i % 60); in.imu.hud_dx = 1.0f; }
        const auto t0 = clk::now();
        c.render(st, f);
        const auto t1 = clk::now();
        if (head) {
            if (turning) {
                in.imu.active = true;
                in.imu.yaw_deg = 30.0f * std::sin(6.2831853f * static_cast<float>(i) / 50.0f);
                in.imu.pitch_deg = 30.0f * std::sin(6.2831853f * static_cast<float>(i) / 170.0f);
            }
            const auto h0 = clk::now();
            choose_head(f, in, head, burst && burst->active());
            r.head += us(h0, clk::now()); r.head_frames += in.head != nullptr;
        }
        if (burst) {
            const auto pose = face_pose(f, in); const auto* shown = face_art(f, in);
            if (!burst->active() && shown && burst_allowed(f)) {
                const auto src = cache && cache->art() == shown ? cache->source() : persona::PixelSource{nullptr, shown};
                if (burst->begin(shown, src, clock.at, pose, 0.5f, -0.5f, 0x1234u + static_cast<std::uint32_t>(i))) ++r.bursts;
            }
            if (handled) {
                const float down = (45.0f * static_cast<float>(i) * 0.04f + 12.0f * std::sin(6.2831853f * static_cast<float>(i) * 0.04f)) * 0.01745329252f;
                burst->step(clock.at, -std::sin(down), -std::cos(down), pose, 0.2f * std::sin(static_cast<float>(i)), 0.0f);
            } else burst->step(clock.at, 0.0f, -1.0f, pose);
            in.burst = burst;
            r.particles = std::max(r.particles, static_cast<unsigned>(burst->count()));
            r.lying = std::max(r.lying, static_cast<unsigned>(burst->resting()));
        }
        draw(canvas, f, in);
        const auto t2 = clk::now();
        const auto plan = dirty.plan(px.data(), 135, 240, i == 0);
        const auto t3 = clk::now();
        r.render += us(t0, t1); r.draw += us(t1, t2); r.plan += us(t2, t3);
        for (std::size_t k = 0; k < plan.count; ++k) r.rows += static_cast<unsigned>(plan.runs[k].rows);
        ++r.frames;
    }
    r.warps = cache ? cache->warps - warps_before : 0;
    r.inflates = head ? head->inflates() - inflates_before : 0;
    return r;
}
void print(const char* name, const Result& r) {
    std::printf("%s", "");
    std::printf("%-26s frames=%u render_us=%.1f draw_us=%.1f plan_us=%.1f total_us=%.1f push_rows=%.1f warps=%u", name, r.frames,
                r.render / r.frames, r.draw / r.frames, r.plan / r.frames, (r.render + r.draw + r.plan) / r.frames,
                static_cast<double>(r.rows) / r.frames, r.warps);
    if (r.bursts) std::printf(" particles=%u bursts=%u lying_max=%u", r.particles, r.bursts, r.lying);
    if (r.head_frames) std::printf(" head_frames=%u inflates=%u head_us=%.1f", r.head_frames, r.inflates, r.head / r.frames);
    std::printf("\n");
}
// G21 "cross-fade or snap, decided by measurement" (host, relative): what a cross-fade would add to every
// frame while it fades (one blend of two whole frames, then a warp of the blend instead of a reused band),
// against one inflate per frame CHANGE for a snap, and how far apart two neighbouring frames are.
void head_costs(head3d::Head& head, int mood, int rounds) {
    const auto* set = head.set(mood); if (!set) return;
    head3d::Params plain; plain.on = true; plain.yaw_gain = 1; plain.pitch_gain = 1; head.configure(plain);   // on: off by default since 2026-11-18
    const int mid = set->pitch_count / 2;
    const auto angle = [&](int y) { return static_cast<float>(set->yaw[static_cast<std::size_t>(y)]) * 0.1f; };
    const float pitch = static_cast<float>(set->pitch[static_cast<std::size_t>(mid)]) * 0.1f;
    // Inflate: sweep the yaw row there and back (each step is a frame the other buffer does not hold).
    const unsigned before = head.inflates(); const auto t0 = clk::now();
    for (int r = 0; r < rounds; ++r) for (int y = 0; y < set->yaw_count; ++y) head.frame(mood, angle(r & 1 ? set->yaw_count - 1 - y : y), pitch);
    const double inflate_us = us(t0, clk::now()) / std::max(1u, head.inflates() - before);
    // Two neighbours in the middle of the row, kept as copies.
    std::vector<std::uint8_t> a(persona::art_bytes), b(persona::art_bytes), mix(persona::art_bytes);
    const int y0 = set->yaw_count / 2, y1 = std::min(set->yaw_count - 1, y0 + 1);
    std::memcpy(a.data(), head.frame(mood, angle(y0), pitch), persona::art_bytes);
    std::memcpy(b.data(), head.frame(mood, angle(y1), pitch), persona::art_bytes);
    const auto px = [](const std::vector<std::uint8_t>& v, std::size_t i) { return static_cast<unsigned>(v[2 * i] | (v[2 * i + 1] << 8)); };
    double diff = 0; unsigned changed = 0;
    for (std::size_t i = 0; i < persona::art_pixels; ++i) {
        const unsigned p = px(a, i), q = px(b, i);
        const int dr = int(p >> 11) - int(q >> 11), dg = int((p >> 5) & 63) - int((q >> 5) & 63), db = int(p & 31) - int(q & 31);
        diff += (std::abs(dr) * 8 + std::abs(dg) * 4 + std::abs(db) * 8) / 3.0; changed += p != q;
    }
    // Blend: a + (b - a) * w / 32 per channel, the arithmetic of the portrait warp's bilinear step.
    const auto t1 = clk::now(); unsigned sink = 0;
    for (int r = 0; r < rounds * 8; ++r) {
        const unsigned w = static_cast<unsigned>(r) & 31u;
        for (std::size_t i = 0; i < persona::art_pixels; ++i) {
            const std::uint32_t p = px(a, i), q = px(b, i);
            const std::uint32_t sp = (p | (p << 16)) & 0x07E0F81Fu, sq = (q | (q << 16)) & 0x07E0F81Fu;
            const std::uint32_t m = ((sp * (32u - w) + sq * w) >> 5) & 0x07E0F81Fu; const auto v = static_cast<std::uint16_t>(m | (m >> 16));
            mix[2 * i] = static_cast<std::uint8_t>(v); mix[2 * i + 1] = static_cast<std::uint8_t>(v >> 8);
        }
        sink += mix[1000];
    }
    const double blend_us = us(t1, clk::now()) / (rounds * 8);
    // Warp of one frame at a small tilt (what a fade forces on every frame: the band cannot be reused).
    std::array<std::uint16_t, 135 * 240> panel{}; Canvas canvas(panel.data(), 135, 240, true);
    const auto t2 = clk::now();
    for (int r = 0; r < rounds * 8; ++r) persona::paint_portrait(canvas, a.data(), 0, persona::Placement{20, 0, 0, 1.0f + 0.01f * static_cast<float>(r & 7)}, persona::Layers{true, false, false}, persona::Motion{}, false);
    const double warp_us = us(t2, clk::now()) / (rounds * 8);
    std::printf("3d-cost                    inflate_us=%.1f blend_us=%.1f warp_us=%.1f neighbour_changed_px=%u of %zu neighbour_mean_abs_diff=%.1f of 255 (sink %u)\n",
                inflate_us, blend_us, warp_us, changed, persona::art_pixels, diff / static_cast<double>(persona::art_pixels), sink & 1u);
}
} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: render_bench <art dir> [frames]\n"); return 1; }
    const int frames = argc > 2 ? std::atoi(argv[2]) : 500;
    Art art(argv[1]);
    std::vector<std::uint16_t> source(persona::art_pixels), band(persona::art_pixels);
    persona::WarpCache cache(source.data(), band.data());
    Status st{}; st.radio = RadioState::Monitoring; st.persona_art = true; st.store = StoreState::Restored;
    Clock clock; Monitor m(clock, profiles::all_2g4_channels(), Origin::LiveRadio); MemoryBlob blob; EncodedSelectionStore store(blob);
    Companion c(clock, m, store, lcd(), Origin::LiveRadio); c.boot(); c.receive(wpa3(clock)); c.tick();
    c.input(Action::SecondaryLong); c.input(Action::Secondary);
    // Keep the rating fresh for the whole run (one beacon per simulated 100 ms is not needed: 1 s is plenty).
    const auto keep_fresh = [&]() { c.receive(wpa3(clock)); };
    keep_fresh(); c.tick();
    Result r = run(c, clock, st, art.set, nullptr, false, 1); (void)r;   // warm-up
    keep_fresh(); print("rated-rest-nocache", run(c, clock, st, art.set, nullptr, false, frames / 4));
    keep_fresh(); const auto rest = run(c, clock, st, art.set, &cache, false, frames / 4); print("rated-rest", rest);
    keep_fresh(); const auto moving = run(c, clock, st, art.set, &cache, true, frames / 4); print("rated-moving", moving);
    // G16I: the snow-globe burst of the same face (about 1,370 particles instead of one warp per frame).
    const auto particles = std::make_unique<burst::Burst>();
    keep_fresh(); const auto burst_run = run(c, clock, st, art.set, &cache, true, frames / 4, particles.get()); print("rated-burst", burst_run);
    particles->cancel();
    // G16O: the same burst with the stick handled the whole time (the pile forms and keeps sliding). At least 6 s,
    // so the pile exists even in the short ctest run.
    keep_fresh(); const auto pile_run = run(c, clock, st, art.set, &cache, true, std::max(frames / 4, 150), particles.get(), nullptr, false, true); print("rated-burst-handled", pile_run);
    particles->cancel();
    // G21: the same rated face as the 3D head (the shipped packs), at rest and with the stick turning.
    HeadPacks packs(GUARDIAN_HEAD_DIR);
    Result rest3d{}, turning3d{};
    const std::uint32_t reuses_before_3d = cache.reuses;
    if (packs.head->sets()) {
        keep_fresh(); rest3d = run(c, clock, st, art.set, &cache, false, frames / 4, nullptr, packs.head.get(), false); print("rated-3d-rest", rest3d);
        keep_fresh(); turning3d = run(c, clock, st, art.set, &cache, false, frames / 4, nullptr, packs.head.get(), true); print("rated-3d-turning", turning3d);
        { head3d::Params on; on.on = true; packs.head->configure(on); }   // off by default since 2026-11-18; the cost probe needs frames
        for (int mood = 0; mood < 5; ++mood) if (packs.head->has(mood)) { head_costs(*packs.head, mood, std::max(1, frames / 40)); break; }
        std::printf("head sets=%u frames=%u inflates=%u reuses=%u failures=%u\n", unsigned(packs.head->sets()), unsigned(packs.head->frames()),
                    unsigned(packs.head->inflates()), unsigned(packs.head->reuses()), unsigned(packs.head->failures()));
    } else std::printf("rated-3d: no head pack in %s\n", GUARDIAN_HEAD_DIR);
    const std::uint32_t reuses_3d = cache.reuses - reuses_before_3d;
    clock.at += Core::fresh_ms + 1000; c.tick();
    print("nodata-rest", run(c, clock, st, art.set, &cache, false, frames / 4));
    c.input(Action::PrimaryLong);   // DEMO
    print("demo-rest", run(c, clock, st, art.set, &cache, false, frames / 4));
    std::printf("cache copies=%u warps=%u reuses=%u\n", cache.copies, cache.warps, cache.reuses);
    if (argc > 3 && std::strcmp(argv[3], "--check") == 0) {
        // At rest (breathing only), most frames reuse the band; never every frame re-warped.
        // G16I: a burst frame never warps (the only warps are the one ordinary frame after each burst has
        // landed), and it carries the whole face ("about a thousand" particles).
        // G16O: handled, the particles lie in a pile (most of them at some moment) and still no frame warps.
        const bool burst_ok = burst_run.bursts > 0 && burst_run.warps <= burst_run.bursts && burst_run.particles > 1000 && burst_run.particles <= burst::capacity
            && pile_run.bursts > 0 && pile_run.warps <= pile_run.bursts && pile_run.lying * 2 > pile_run.particles;
        // G21: with the shipped pack every rated frame is the 3D head; at rest one frame is inflated once and the
        // warped band is still reused; turning, frames change (inflates) and nothing fails.
        const bool head_ok = packs.head->sets() > 0 && rest3d.head_frames == rest3d.frames && rest3d.inflates <= 1 && rest3d.warps < rest3d.frames
            && reuses_3d > 0 && turning3d.head_frames == turning3d.frames && turning3d.inflates > 2 && packs.head->failures() == 0;
        const bool ok = rest.frames > 0 && rest.warps < rest.frames && cache.reuses > 0 && burst_ok && head_ok;
        std::printf("RESULT: %s\n", ok ? "PASS" : "FAIL");
        return ok ? 0 : 1;
    }
    return 0;
}

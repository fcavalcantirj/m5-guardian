// G23 measurement tool (not a test, not device evidence): the G16O stillness rule over recorded IMU
// traces, for tuning burst.still_dps / burst.still_g / burst.calm_s from what the stick measured.
//
//   still_trace <trace.txt> [<trace.txt> ...]
//
// A trace is the stick's own console recording (`IMU <seconds>`: one header line
// "G16A IMU STREAM ... fields=t_us,sensortime,ax,ay,az,gx,gy,gz", then "IMU ..." lines; the nine
// G16I recordings are tests/fixtures/imu/*.txt). Each trace runs through the real motion model
// (the stick's axis map 2,-1,3) stepped at 25 frames a second like the face, and every frame is
// judged with the formula of Burst::stirred: "moving" when the up vector turned faster than
// still_dps since the frame before, or the shove across the glass is above still_g.
//
// Printed per trace:
//   - turn (degrees/s) and shove (g) percentiles;
//   - the net turn of the up vector over a window of 0.6 / 1.0 / 1.5 s (a slow tilt adds up, a
//     hand-held wobble does not: the number a displacement rule would need);
//   - for the firmware defaults and a grid of still_dps x calm_s: the share of moving frames, the
//     longest still run and how often the calm time was reached (each time = a reform would start).
// A slow-tilt recording should reach calm 0 times; a hand-held still one at least once.
#include "burst.hpp"
#include "motion.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <vector>

using namespace guardian::companion;

namespace {
constexpr std::int64_t frame_us = 40000;   // 25 frames a second
struct Up { float x{}, y{}, z{}; };
float angle_deg(const Up& a, const Up& b) {
    const float cx = a.y * b.z - a.z * b.y, cy = a.z * b.x - a.x * b.z, cz = a.x * b.y - a.y * b.x;
    return std::atan2(std::sqrt(cx * cx + cy * cy + cz * cz), a.x * b.x + a.y * b.y + a.z * b.z) * 57.29577951f;
}
float percentile(std::vector<float> v, double p) {
    if (v.empty()) return 0.0f;
    std::sort(v.begin(), v.end());
    const auto i = static_cast<std::size_t>(p * static_cast<double>(v.size()));
    return v[std::min(v.size() - 1, i)];
}
struct Run { int moving{}; int longest{}; int calm_starts{}; };
Run judge(const std::vector<float>& rate, const std::vector<float>& shove, float dps, float g, int calm_frames) {
    Run r; int run = 0;
    for (std::size_t i = 0; i < rate.size(); ++i) {
        const bool moving = rate[i] > dps || shove[i] > g;
        r.moving += moving ? 1 : 0;
        if (moving) run = 0;
        else if (++run == calm_frames) ++r.calm_starts;
        r.longest = std::max(r.longest, run);
    }
    return r;
}
int frames_of(float seconds) { return std::max(1, static_cast<int>(std::lround(seconds * 25.0f))); }

bool one(const char* path) {
    std::FILE* f = std::fopen(path, "r");
    if (!f) { std::printf("%s: cannot open\n", path); return false; }
    motion::Model model; model.configure(motion::axis_map_from(2, -1, 3), motion::Params{});
    char line[240]; std::int64_t next = 0; bool have = false; Up before; std::int64_t before_us = 0;
    std::vector<float> rate, shove; std::vector<Up> ups;
    while (std::fgets(line, sizeof line, f)) {
        long long t = 0; unsigned long sensortime = 0; int ax = 0, ay = 0, az = 0, gx = 0, gy = 0, gz = 0;
        if (std::sscanf(line, "IMU %lld %lu %d %d %d %d %d %d", &t, &sensortime, &ax, &ay, &az, &gx, &gy, &gz) != 8) continue;
        motion::Reading r; r.t_us = t;
        r.acc_g[0] = static_cast<float>(ax) / 4096.0f; r.acc_g[1] = static_cast<float>(ay) / 4096.0f; r.acc_g[2] = static_cast<float>(az) / 4096.0f;
        r.gyr_dps[0] = static_cast<float>(gx) / 16.384f; r.gyr_dps[1] = static_cast<float>(gy) / 16.384f; r.gyr_dps[2] = static_cast<float>(gz) / 16.384f;
        model.sample(r);
        if (!next) next = t + frame_us;
        if (t < next) continue;
        next += frame_us;
        const auto& o = model.step(t);
        Up up{o.up_x, o.up_y, 0.0f};
        const float in2 = up.x * up.x + up.y * up.y;
        if (in2 > 1.0f) { const float n = std::sqrt(in2); up.x /= n; up.y /= n; } else up.z = std::sqrt(1.0f - in2);
        if (have && t > before_us) {
            rate.push_back(angle_deg(up, before) / (static_cast<float>(t - before_us) * 1e-6f));
            shove.push_back(std::hypot(o.lin_x, o.lin_y));
        }
        ups.push_back(up); before = up; before_us = t; have = true;
    }
    std::fclose(f);
    if (rate.empty()) { std::printf("%s: no IMU lines\n", path); return false; }
    const float seconds = static_cast<float>(rate.size()) * 0.04f;
    std::printf("%s\n  frames=%zu (%.1f s)  turn dps p50=%.1f p90=%.1f p99=%.1f max=%.1f  shove g p50=%.3f p99=%.3f max=%.3f\n", path, rate.size(), static_cast<double>(seconds),
                static_cast<double>(percentile(rate, .5)), static_cast<double>(percentile(rate, .9)), static_cast<double>(percentile(rate, .99)), static_cast<double>(percentile(rate, 1.0)),
                static_cast<double>(percentile(shove, .5)), static_cast<double>(percentile(shove, .99)), static_cast<double>(percentile(shove, 1.0)));
    for (const float window : {0.6f, 1.0f, 1.5f}) {
        const auto n = static_cast<std::size_t>(frames_of(window)); std::vector<float> net;
        for (std::size_t i = n; i < ups.size(); ++i) net.push_back(angle_deg(ups[i], ups[i - n]));
        std::printf("  net turn over %.1f s: p50=%.1f p90=%.1f p99=%.1f max=%.1f degrees\n", static_cast<double>(window),
                    static_cast<double>(percentile(net, .5)), static_cast<double>(percentile(net, .9)), static_cast<double>(percentile(net, .99)), static_cast<double>(percentile(net, 1.0)));
    }
    const burst::Params d{};
    const Run def = judge(rate, shove, d.still_dps, d.still_g, frames_of(d.calm_s));
    std::printf("  firmware defaults still_dps=%.0f still_g=%.2f calm_s=%.1f: moving %.0f%%, longest still %.2f s, calm reached %d time(s)\n",
                static_cast<double>(d.still_dps), static_cast<double>(d.still_g), static_cast<double>(d.calm_s),
                100.0 * def.moving / static_cast<double>(rate.size()), def.longest * 0.04, def.calm_starts);
    std::printf("  calm reached, times (still_g=%.2f); rows still_dps, columns calm_s 0.6 / 1.0 / 1.5 / 2.0 / 3.0:\n", static_cast<double>(d.still_g));
    for (const float dps : {2.0f, 3.0f, 4.0f, 6.0f, 8.0f, 10.0f, 12.0f, 16.0f, 20.0f}) {
        std::printf("    still_dps=%-4.0f", static_cast<double>(dps));
        for (const float calm : {0.6f, 1.0f, 1.5f, 2.0f, 3.0f}) std::printf(" %3d", judge(rate, shove, dps, d.still_g, frames_of(calm)).calm_starts);
        const Run r = judge(rate, shove, dps, d.still_g, frames_of(d.calm_s));
        std::printf("   moving %3.0f%%, longest still %.2f s\n", 100.0 * r.moving / static_cast<double>(rate.size()), r.longest * 0.04);
    }
    return true;
}
} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { std::printf("usage: still_trace <trace.txt> [<trace.txt> ...]\n"); return 2; }
    bool ok = true;
    for (int i = 1; i < argc; ++i) ok = one(argv[i]) && ok;
    return ok ? 0 : 1;
}

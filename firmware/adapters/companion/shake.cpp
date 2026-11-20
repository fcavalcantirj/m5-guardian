// G16I shake detector: see shake.hpp. Float only; a few operations per 200 Hz sample.
#include "shake.hpp"
#include <algorithm>
#include <cmath>

namespace guardian::companion::shake {
namespace {
float clampf(float v, Range r) { return std::max(r.lo, std::min(r.hi, v)); }
constexpr std::size_t ring = 16;
}

void Detector::configure(const Params& p) {
    Params q;
    q.g = std::isfinite(p.g) ? clampf(p.g, g_range) : Params{}.g;
    q.peaks = static_cast<std::uint8_t>(clampf(static_cast<float>(p.peaks), peaks_range));
    q.window_ms = static_cast<std::uint16_t>(clampf(static_cast<float>(p.window_ms), window_ms_range));
    const bool same = q.g == p_.g && q.peaks == p_.peaks && q.window_ms == p_.window_ms;
    p_ = q;
    if (!same) head_ = count_ = 0;   // alternations counted under the old rule do not carry over
}

void Detector::reset() {
    have_ = pending_ = fired_ = false; sign_ = 0; head_ = count_ = 0;
    last_us_ = peak_us_ = fired_us_ = 0;
}

void Detector::sample(const float acc_g[3], std::int64_t t_us) {
    if (!std::isfinite(acc_g[0]) || !std::isfinite(acc_g[1]) || !std::isfinite(acc_g[2])) return;
    if (!have_) {   // the first sample is the best gravity estimate there is
        for (int k = 0; k < 3; ++k) gravity_[k] = acc_g[k];
        have_ = true; last_us_ = t_us;
        return;
    }
    const float dt = std::max(1e-4f, static_cast<float>(t_us - last_us_) * 1e-6f);
    last_us_ = t_us;
    const float a = dt / (gravity_tau_s + dt);
    float motion = 0;   // the dominant axis, gravity removed (signed)
    for (int k = 0; k < 3; ++k) {
        gravity_[k] += a * (acc_g[k] - gravity_[k]);
        const float hp = acc_g[k] - gravity_[k];
        if (std::fabs(hp) > std::fabs(motion)) motion = hp;
    }
    const int s = motion > p_.g ? 1 : motion < -p_.g ? -1 : 0;
    if (!s || s == sign_) return;
    // A peak of the other sign. It is an alternation unless it follows the previous peak too closely.
    const bool alternation = sign_ != 0 && t_us - peak_us_ >= min_gap_us;
    sign_ = s; peak_us_ = t_us;
    if (!alternation) return;
    if (fired_ && t_us - fired_us_ < refractory_us) return;
    at_[head_] = t_us; head_ = static_cast<std::uint8_t>((head_ + 1) % ring);
    if (count_ < ring) ++count_;
    if (count_ < p_.peaks) return;
    const std::int64_t first = at_[(head_ + ring - p_.peaks) % ring];
    if (t_us - first > static_cast<std::int64_t>(p_.window_ms) * 1000) return;
    pending_ = true; fired_ = true; fired_us_ = t_us; ++events_;
    head_ = count_ = 0;
}

} // namespace guardian::companion::shake

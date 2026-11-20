// Supervisor review (2026-11-17): G16F/G16G threat limits as live TUNE keys (see threat_tune.hpp).
#include "threat_tune.hpp"
#include <cmath>

namespace guardian::tune {
namespace {
enum class Kind : std::uint8_t { Ms, Count, Dbm };
struct Field {
    const char* key;
    Kind kind;
    Millis ThreatLimits::* ms;
    std::uint32_t ThreatLimits::* count;
    std::int8_t ThreatLimits::* dbm;
};
constexpr Field ms(const char* k, Millis ThreatLimits::* m) { return {k, Kind::Ms, m, nullptr, nullptr}; }
constexpr Field n(const char* k, std::uint32_t ThreatLimits::* c) { return {k, Kind::Count, nullptr, c, nullptr}; }
constexpr Field dbm(const char* k, std::int8_t ThreatLimits::* d) { return {k, Kind::Dbm, nullptr, nullptr, d}; }

// One row per ThreatLimits member (guardian/threats.hpp), same order.
constexpr Field fields[] = {
    ms("t.cooldown_ms", &ThreatLimits::cooldown_ms), ms("t.bssid_cooldown_ms", &ThreatLimits::bssid_cooldown_ms),
    ms("t.probe_window_ms", &ThreatLimits::probe_window_ms), n("t.probe_flood", &ThreatLimits::probe_flood),
    n("t.probe_flood_sources", &ThreatLimits::probe_flood_sources), n("t.probe_source_flood", &ThreatLimits::probe_source_flood),
    n("t.probe_name_sources", &ThreatLimits::probe_name_sources),
    ms("t.beacon_window_ms", &ThreatLimits::beacon_window_ms), n("t.beacon_flood_bssids", &ThreatLimits::beacon_flood_bssids),
    dbm("t.beacon_rssi_min", &ThreatLimits::beacon_rssi_min),
    ms("t.responder_window_ms", &ThreatLimits::responder_window_ms), n("t.responder_names", &ThreatLimits::responder_names),
    n("t.responder_matched_names", &ThreatLimits::responder_matched_names),
    ms("t.auth_window_ms", &ThreatLimits::auth_window_ms), n("t.auth_flood", &ThreatLimits::auth_flood),
    n("t.auth_flood_sources", &ThreatLimits::auth_flood_sources), n("t.sae_commit_excess", &ThreatLimits::sae_commit_excess),
    n("t.assoc_sleep", &ThreatLimits::assoc_sleep), n("t.assoc_sleep_sources", &ThreatLimits::assoc_sleep_sources),
    n("t.csa_count_min", &ThreatLimits::csa_count_min), n("t.quiet_duration_tu", &ThreatLimits::quiet_duration_tu),
    ms("t.csa_mix_ms", &ThreatLimits::csa_mix_ms), n("t.csa_mixed", &ThreatLimits::csa_mixed),
    ms("t.csa_window_ms", &ThreatLimits::csa_window_ms),
    ms("t.mismatch_window_ms", &ThreatLimits::mismatch_window_ms), n("t.mismatch_responses", &ThreatLimits::mismatch_responses),
    ms("t.owe_memory_ms", &ThreatLimits::owe_memory_ms), ms("t.owe_window_ms", &ThreatLimits::owe_window_ms),
    n("t.owe_twin_beacons", &ThreatLimits::owe_twin_beacons),
    ms("t.deauth_source_window_ms", &ThreatLimits::deauth_source_window_ms), n("t.deauth_source", &ThreatLimits::deauth_source),
    ms("t.deauth_pair_window_ms", &ThreatLimits::deauth_pair_window_ms), n("t.deauth_pair", &ThreatLimits::deauth_pair),
    ms("t.deauth_broadcast_window_ms", &ThreatLimits::deauth_broadcast_window_ms),
    n("t.deauth_broadcast", &ThreatLimits::deauth_broadcast), ms("t.dedupe_ms", &ThreatLimits::dedupe_ms),
    ms("t.rotation_window_ms", &ThreatLimits::rotation_window_ms), n("t.rotation_names", &ThreatLimits::rotation_names),
    ms("t.harvest_window_ms", &ThreatLimits::harvest_window_ms), n("t.harvest_bssids", &ThreatLimits::harvest_bssids),
    ms("t.harvest_settle_ms", &ThreatLimits::harvest_settle_ms), n("t.fake_m1", &ThreatLimits::fake_m1),
    ms("t.fake_m1_window_ms", &ThreatLimits::fake_m1_window_ms), ms("t.reconnect_ms", &ThreatLimits::reconnect_ms),
    ms("t.reconnect_burst_window_ms", &ThreatLimits::reconnect_burst_window_ms),
    n("t.reconnect_burst", &ThreatLimits::reconnect_burst), n("t.reconnect_messages", &ThreatLimits::reconnect_messages),
    // G16J: the noise-floor rule (replaces the five t.loss_* keys), tool shapes, probe-then-answer, lure portal.
    n("t.noise_rise_db", &ThreatLimits::noise_rise_db), ms("t.noise_average_ms", &ThreatLimits::noise_average_ms),
    ms("t.noise_hold_ms", &ThreatLimits::noise_hold_ms), n("t.noise_min_frames", &ThreatLimits::noise_min_frames),
    n("t.noise_baseline_samples", &ThreatLimits::noise_baseline_samples),
    n("t.shape_frames", &ThreatLimits::shape_frames), n("t.shape_run", &ThreatLimits::shape_run),
    n("t.tsf_static_beacons", &ThreatLimits::tsf_static_beacons), ms("t.tsf_static_ms", &ThreatLimits::tsf_static_ms),
    ms("t.bait_ms", &ThreatLimits::bait_ms),
    ms("t.karma_answer_ms", &ThreatLimits::karma_answer_ms), n("t.karma_answers", &ThreatLimits::karma_answers),
    ms("t.karma_learn_ms", &ThreatLimits::karma_learn_ms), n("t.lure_beacons", &ThreatLimits::lure_beacons),
    // G16H: Bluetooth LE pairing-popup rules (unused while no BLE scan feeds the detector).
    ms("t.ble_popup_window_ms", &ThreatLimits::ble_popup_window_ms), n("t.ble_popup_messages", &ThreatLimits::ble_popup_messages),
    n("t.ble_popup_sources", &ThreatLimits::ble_popup_sources), ms("t.ble_learn_ms", &ThreatLimits::ble_learn_ms),
    ms("t.ble_address_memory_ms", &ThreatLimits::ble_address_memory_ms),
    ms("t.ble_rotation_window_ms", &ThreatLimits::ble_rotation_window_ms), n("t.ble_rotation_models", &ThreatLimits::ble_rotation_models),
};
constexpr std::size_t field_count = sizeof fields / sizeof fields[0];
static_assert(field_count <= ThreatKeys{}.index.size(), "ThreatKeys must hold every field");

// Wide, honest ranges: TUNE refuses only impossible values; the detectors'
// own valid() refuses inconsistent combinations at apply time.
constexpr float ms_max = 3600000.0f, count_max = 65535.0f;   // 1 h; floats are exact below 2^24
float read(const Field& f, const ThreatLimits& l) {
    switch (f.kind) {
    case Kind::Ms: return static_cast<float>(l.*(f.ms));
    case Kind::Count: return static_cast<float>(l.*(f.count));
    case Kind::Dbm: return static_cast<float>(l.*(f.dbm));
    }
    return 0.0f;
}
void write(const Field& f, ThreatLimits& l, float v) {
    switch (f.kind) {
    case Kind::Ms: l.*(f.ms) = static_cast<Millis>(std::lround(v)); break;
    case Kind::Count: l.*(f.count) = static_cast<std::uint32_t>(std::lround(v)); break;
    case Kind::Dbm: l.*(f.dbm) = static_cast<std::int8_t>(std::lround(v)); break;
    }
}
} // namespace

std::size_t threat_key_count() { return field_count; }
const char* threat_key(std::size_t i) { return i < field_count ? fields[i].key : ""; }

bool add_threat_limits(Registry& r, const ThreatLimits& defaults, ThreatKeys& keys) {
    keys = ThreatKeys{};
    if (r.count() + field_count > max_params) return false;   // all or nothing
    for (std::size_t i = 0; i < field_count; ++i) {
        const auto& f = fields[i];
        float lo = 0.0f, hi = count_max;
        if (f.kind == Kind::Ms) hi = ms_max;
        if (f.kind == Kind::Dbm) { lo = -100.0f; hi = -20.0f; }
        const float def = read(f, defaults);
        if (def < lo || def > hi) return false;   // a default outside its range is a programming error
        keys.index[i] = r.add(f.key, lo, hi, def);
        if (keys.index[i] < 0) return false;      // count was checked, so only a duplicate key gets here
    }
    keys.count = field_count;
    return true;
}

ThreatLimits threat_limits_from(const Registry& r, const ThreatKeys& keys, const ThreatLimits& base) {
    ThreatLimits l = base;
    for (std::size_t i = 0; i < keys.count && i < field_count; ++i)
        if (keys.index[i] >= 0) write(fields[i], l, r.get(keys.index[i]));
    return l;
}

bool threat_limits_equal(const ThreatLimits& a, const ThreatLimits& b) {
    for (const auto& f : fields) if (read(f, a) != read(f, b)) return false;
    return true;
}

} // namespace guardian::tune

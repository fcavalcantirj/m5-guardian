#pragma once
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include "guardian/core.hpp"
#include "guardian/air.hpp"
#include "guardian/detectors.hpp"
#include "guardian/registry.hpp"
#include "guardian/security_parser.hpp"
#include "guardian/threats.hpp"
#include "guardian/presenter.hpp"

// SDK-free adapter mechanics. No alternate parser, detector or rating policy.
namespace guardian::measurement {
constexpr std::size_t frame_capacity = 1536;
struct Packet {
    std::array<std::uint8_t, frame_capacity> bytes{};
    RxMeta meta{};
    std::uint16_t size{};
    bool truncated{};
    FrameSpan span() const { return {bytes.data(), size, truncated}; }
};
// accessible is the driver's FCS-free readable length, not the pool capacity.
bool copy_rx(Packet&, const std::uint8_t*, std::size_t accessible,
             std::uint16_t sig_len, std::uint8_t rx_state, RxMeta);
bool deliver(const Packet&, FrameBuffer, FrameSpan&, RxMeta&);
bool decode_network(const char* bssid_hex, const char* ssid_hex, Network&);

// G16G receive-callback prefilter: true only for an unprotected, unfragmented
// data frame whose LLC/SNAP header is EAPOL (AA AA 03 00 00 00 88 8E), using the
// same header-length rule as the parser (4-address +6, QoS +2, QoS+Order +4).
// `size` is the FCS-free readable length. Constant work: no loop over the body.
// Everything else on the data path is dropped before the queue.
bool eapol_candidate(const std::uint8_t* bytes, std::size_t size);

// G16G per-channel receive counters. valid()/error() are called from the radio
// driver's receive callback (single writer, relaxed atomics, no lock, no
// allocation); tuned()/untuned()/sample() from the application task. sample()
// turns the counts since its previous call into one ChannelLoadSample per
// channel that was listened to or counted anything (bounded by `capacity`).
class ChannelLoadMeter {
public:
    static constexpr std::size_t channels = 15;   // index = channel number 1..14
    // G16J: `noise` is the radio's noise-floor estimate for that frame (dBm, rx_ctrl.noise_floor).
    void valid(std::uint8_t channel, std::int8_t noise);
    void error(std::uint8_t channel, std::int8_t rssi, std::int8_t noise);
    void tuned(std::uint8_t channel, Millis now);
    void untuned(Millis now);
    std::size_t sample(const Instant& now, Origin origin, bool fcs_supported, ChannelLoadSample* out, std::size_t capacity);
    std::uint32_t valid_total() const;
    std::uint32_t error_total() const;
private:
    std::array<std::atomic<std::uint32_t>, channels> valid_{}, errors_{}, rssi_n_{}, rssi_sum_{};   // rssi_sum_: two's complement
    std::array<std::atomic<std::uint32_t>, channels> noise_n_{}, noise_sum_{};                      // G16J, two's complement sum
    std::array<std::uint32_t, channels> seen_valid_{}, seen_errors_{}, seen_rssi_n_{}, seen_rssi_sum_{}, seen_noise_n_{}, seen_noise_sum_{};
    std::array<Millis, channels> listened_{};
    std::uint8_t tuned_{};
    Millis segment_{};
    Millis last_sample_{};
    bool sampled_{};
};
void escaped_ssid(const Network&, char* out, std::size_t capacity);

class Survey {
public:
    bool begin(std::uint8_t first, std::uint8_t count, std::uint8_t initial, Millis now, bool fixed = false);
    std::uint8_t next(Millis now);
    void observed(std::uint8_t channel, Millis acquired, std::uint8_t advertised_channel = 0);
    void stop() { lose(Loss::Stopped); active_ = false; hold_ = false; }
    // G14: while held (picker open / nothing selected) the survey keeps hopping
    // and never claims a lock, so coverage stays honestly unknown/degraded.
    void hold_discovery(bool hold) { hold_ = hold; if (hold) lose(Loss::Held); }
    // G16J optional area sweep (TUNE detect.sweep_ms, default 0 = off): while locked,
    // once every `period_ms` the radio leaves the selected network's channel for
    // `dwell_ms` on the next other channel (round robin), then returns. The lock is
    // kept and the silence timer does not run while away. away() tells the adapter
    // its coverage of the selected channel has a gap (report hopping, count listened
    // time honestly). dwell 0 or dwell >= period: off.
    void set_sweep(Millis dwell_ms, Millis period_ms = 2000);
    bool away() const { return away_; }
    Millis sweep_dwell_ms() const { return sweep_dwell_; }
    // G16C rework: why the most recent lock ended, and how many locks ended
    // since boot (a restart keeps the counts). Diagnostics only: the lock
    // behaviour itself is unchanged.
    enum class Loss : std::uint8_t { None, Silence, Followed, Held, Stopped };
    static const char* loss_text(Loss);   // "none", "silence_5s", "followed_channel", "held", "stopped"
    std::uint32_t lock_losses() const { return lock_losses_; }
    Loss last_loss() const { return last_loss_; }
    // G23: the count per reason and its STATUS token
    // "lock_loss_by=silence:<n>,followed:<n>,held:<n>,stopped:<n>" (the four sum to lock_losses()).
    // Returns the length written; 0 with an empty string when it does not fit (never cut).
    static constexpr std::size_t lock_loss_text_max = 96;   // four ten-digit counts: 86 characters and the terminator
    std::uint32_t losses(Loss why) const { return loss_by_[static_cast<std::size_t>(why)]; }
    std::size_t lock_loss_text(char* out, std::size_t capacity) const;
    bool holding() const { return hold_; }
    bool active() const { return active_; }
    bool fixed() const { return active_ && fixed_; }
    bool monitoring() const { return active_ && (locked_ || fixed_); }
    bool locked() const { return locked_; }
    std::uint8_t channel() const { return active_ ? channel_ : 0; }
private:
    std::uint8_t first_{}, count_{}, channel_{};
    void lose(Loss why) { if (locked_) { locked_ = false; ++lock_losses_; ++loss_by_[static_cast<std::size_t>(why)]; last_loss_ = why; } }
    bool active_{}, locked_{}, fixed_{}, hold_{};
    Millis changed_{}, last_seen_{};
    Millis sweep_dwell_{}, sweep_period_{}, sweep_next_{}, away_since_{};   // G16J
    std::uint8_t sweep_channel_{};
    bool away_{};
    std::uint32_t lock_losses_{};
    std::array<std::uint32_t, 5> loss_by_{};   // index = Loss (None stays 0)
    Loss last_loss_{Loss::None};
};

// G16E: the live threat radar's input, one slot per detector family. A slot is
// `registered` only while a registered detector reports that family (nothing
// is decorated as measuring otherwise); `pulse` = one of its detectors counted
// an event within pulse_ms; `active` = an incident of that family is currently
// visible (network or area). `air` carries the real per-minute rates.
struct RadarFamily {
    bool registered{};
    IncidentScope scope{IncidentScope::Network};
    std::uint32_t events{};      // counted events since reset (all detectors of the family)
    bool pulse{};
    bool active{};
};
struct Radar {
    static constexpr Millis pulse_ms = 600;
    bool known{};
    std::array<RadarFamily, static_cast<std::size_t>(DetectorFamily::Count)> families{};
    AirRates air{};
};
const char* family_key(DetectorFamily);   // "disconnect", "baseline", "probe", ... (STATUS / JSON)
const char* scope_key(IncidentScope);     // "network" / "area"
const char* pattern_key(Pattern);         // G16F: "probe_flood_random", ... ("none" for None)
// G16S: one LastBurst as STATUS prints it (format: Monitor::burst_text; `tuples` most frequent
// tuples plus, G16T, every further tuple naming the picked network). Returns the length
// written, 0 with an empty string when it does not fit (never cut).
std::size_t burst_record(const LastBurst&, char* out, std::size_t capacity, std::size_t tuples = 4);

class Monitor {
public:
    Monitor(const MonotonicClock&, ChannelSet, Origin = Origin::LiveRadio);
    bool select(const Network&);
    bool approve_baseline();
    bool watch_ap(const Mac&, bool approve);
    bool receive(const Packet&); // true only for a valid exact-selected advertisement
    // G14: the same, also reducing the parsed advertisement to a picker
    // candidate (candidate_from) when `candidate` is non-null; *offered is set
    // true only for an advertisement that passed the Monitor's input checks.
    bool receive(const Packet&, Candidate* candidate, bool* offered);
    // G14 owner scope from the picker/persistence: exact identity plus the
    // explicitly approved baseline facts. Selecting another network clears
    // related approvals; re-selecting the same identity keeps them and its
    // current evidence, replacing only the baseline facts.
    bool select(const ApprovedAp&);
    bool set_watch(bool watch); // owner watch list for the selection (impostor alerts)
    bool approve(const ApprovedAp&);  // related AP: same SSID bytes, other BSSID
    bool revoke(const Mac&);
    bool restore(const PersistedSelection&); // atomic: false leaves everything unchanged
    const ApprovedScope& scope() const { return scope_; }
    void coverage(const CoverageReport&);
    Snapshot snapshot();
    // Review 2026-11-17 (stack): Core::last_security() without a Snapshot copy or a detector
    // tick (the tick runs with every snapshot(), which the companion takes every 100 ms).
    const SecurityObservation* last_security() const { return core_.last_security(); }
    ViewModel view(const Snapshot&) const;
    std::size_t json(char*, std::size_t, std::uint32_t drops, bool listening, bool hopping);
    // G16E. The registry drives every detector from receive()/snapshot()/
    // coverage(); the built-in disconnect and baseline detectors are entries 0
    // and 1. Adapters may add more (they must outlive the Monitor).
    DetectorRegistry& detectors() { return registry_; }
    const DetectorRegistry& detectors() const { return registry_; }
    // TUNE: validated replacement of the built-in detectors' limits. Equal
    // limits change nothing; new limits restart both detectors' windows; bad
    // limits are refused and the previous ones stay.
    bool set_limits(const DetectorLimits&);
    const DetectorLimits& limits() const { return limits_; }
    bool set_area_visibility(Millis ms) { return core_.set_area_visibility(ms); }
    // G16F/G16G: the passive pattern detectors (registry entries 2..15). Validated,
    // all-or-nothing replacement of their limits; refused limits change nothing.
    bool set_threat_limits(const ThreatLimits& limits) { return threats_.configure(limits); }
    // G16G: whether the adapter delivers EAPOL data frames and per-channel
    // receive-error counts. Off (the default) = the handshake and frame-loss
    // detectors are unfed and report configured=false (never shown as measuring).
    void set_data_path(bool on) { data_path_ = on; threats_.set_data_path(on); }
    bool data_path() const { return data_path_; }
    // G16G/G16J: one interval's receive counts for one channel (NoiseFloorDetector).
    void channel_load(const ChannelLoadSample& sample);
    // G16H: Bluetooth LE advertising reports from a PASSIVE scan the adapter runs (the Monitor
    // never scans). Off (the default) = the BLE detector is unfed and reports configured=false:
    // nothing is shown as measuring and the radar has no Bluetooth slot. ble_advert() applies
    // the same input checks as receive() (origin, epoch, a time not in the future) and returns
    // false for a refused report (counted in ble_invalid) or while the scan is off.
    void set_ble_scan(bool on);
    bool ble_scan() const { return ble_scan_; }
    bool ble_advert(const BleAdvert& advert);
    // The scan's own listening report (window, time actually scanning, reports dropped).
    void ble_coverage(const CoverageReport& report);
    std::uint32_t ble_adverts{}, ble_invalid{};
    const ThreatLimits& threat_limits() const { return threats_.probe.limits(); }
    AirRates air() const;
    Radar radar() const;
    // STATUS fragment: " detectors=<name>:frames=..,in_window=..,events=..,incidents=..,last=<s>s|none,cooldown=<s>;..."
    // " air=probes:..,beacons:..,tx:..[+],window_s:.. area_visible=N same_name=N same_name_evicted=N" (G16R: the
    // addresses heard under the picked name). 0 when it does not fit (never cut).
    std::size_t status_text(char*, std::size_t) const;
    // G16S burst forensics: the last disconnect burst of one scope that reached a
    // detector threshold (guardian/shapes.hpp LastBurst), at the Monitor's clock.
    // Network = the newest of the red burst (DisconnectDetector), the pair rule on the
    // picked network and, G16T, a nearby burst that also named the picked network
    // (AreaDisconnectDetector); Area = the burst counted nearby (G16T: with the picked
    // network's frames inside it, marked).
    LastBurst last_burst(IncidentScope) const;
    // STATUS fragment, its own buffer so that it never shares an overflow with status_text():
    // " last_burst_network=<record> last_burst_area=<record>", <record> = "none" or
    // "rule:<burst|deauth_source|deauth_pair|deauth_broadcast>,total:<frames>,unlisted:<frames>,"
    // "tuples:<kept, at most 8>,age_s:<since the incident>,open:<0|1>,top:<t>[;<t>...]" with up to
    // burst_status_tuples tuples, most frequent first, <t> = "<a1>/<a2>/<bssid>/<ch>:<n>"
    // (receiver / sender / BSSID as 12 hex digits, the tuned channel, counted frames).
    // G16T, a nearby burst that also named the picked network: ",own:<frames>" follows
    // "tuples:" (how many frames of the burst named the picked network in Address 1, 2 or 3;
    // the key is absent when there were none), every tuple naming it ends ":own", and such a
    // tuple is printed also when it ranks below the burst_status_tuples most frequent (so a
    // record prints up to 8 tuples). The same record is then both last_burst_network and
    // last_burst_area: one burst, nearby and on the picked network.
    // No space and no '=' inside a record. 0 when it does not fit (never cut).
    static constexpr std::size_t burst_status_tuples = 4;
    static constexpr std::size_t burst_text_max = 1280;   // both records at their longest (G16T: 8 marked tuples each, 1,199 with the keys), with the terminator
    std::size_t burst_text(char*, std::size_t) const;
    std::uint32_t accepted{}, invalid{}, frames{}, selected_advertisements{}, watched_advertisements{}, association_frames{};
private:
    const MonotonicClock& clock_;
    Origin origin_;
    Core core_;
    ApprovedScope scope_{};
    ApprovedAp selected_{};
    Mac watched_{};
    SecurityFrameParser parser_{};
    DetectorLimits limits_{};
    DisconnectDetector disconnect_;
    BaselineDetector baseline_;
    ThreatDetectors threats_;
    bool data_path_{};
    bool ble_scan_{};
    DetectorRegistry registry_{};
    AirMeter air_{};
};
} // namespace guardian::measurement

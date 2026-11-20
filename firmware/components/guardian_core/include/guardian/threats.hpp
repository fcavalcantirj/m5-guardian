#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "guardian/ble.hpp"
#include "guardian/core.hpp"
#include "guardian/detector.hpp"
#include "guardian/detectors.hpp"
#include "guardian/identity.hpp"
#include "guardian/parser.hpp"
#include "guardian/radio.hpp"
#include "guardian/shapes.hpp"
#include "guardian/time.hpp"

// G16F: passive management-frame pattern detectors behind the FrameDetector
// contract. Each one counts received frames of one pattern inside a bounded
// window and reports an IncidentObservation with its count, window, distinct
// addresses, saturation and the adapter's listening coverage. They never
// transmit, never name a tool and never claim an attacker or a compromise:
// header addresses are spoofable bytes, and every observation says "seen
// nearby" (IncidentScope::Area) unless the frames are about the picked network
// (IncidentScope::Network, IncidentKind::NetworkPattern): the selected or an
// owner-approved BSSID or, G16R, a BSSID heard advertising the picked network's
// exact name (ApprovedScope::in_network).
//
// Provenance: independent implementation. The behaviours and every default
// below start from the observable behaviour described for AntiHunter (commit
// c6ef921, AGPL-3.0-only) in guardian-tasks.json G16F; no AntiHunter code was
// read into or copied here. All numbers are uncalibrated starting hypotheses
// (docs/research/reuse-decisions.md section 4) to be set from the measured home
// rates of the G16F benign soak.
//
// Shared rules (ThreatDetector):
//   * Only RxStatus::Ok frames with a valid header and a valid acquisition
//     Instant count. The first such frame binds the detector to its Origin and
//     epoch until reset(); others are ignored (counted in DetectorReport only
//     as frames).
//   * Windows slide on the frames' acquisition time in 5 sub-slots of
//     window/5, so a count covers between 4/5 and all of its window.
//   * Bounded state: every table has a fixed capacity; when a table must evict
//     an entry that is still inside its window the observation is flagged
//     `saturated` (its count is a lower bound).
//   * Per frame the work is bounded by the table capacities (no history scan,
//     no allocation after construction, no pointer kept into a frame).
//   * Cooldown: one observation per (scope, pattern, key) per cooldown, where
//     key is the BSSID for network-scope and per-BSSID patterns, else none.
//     The cooldown table holds 8 keys; when all 8 are cooling, the one that
//     ends first is dropped and that key may report again early (bounded).
//     Incidents are emitted from on_frame, on the frame that closes the
//     threshold; on_tick only lets windows age.
namespace guardian {

// Every tunable heuristic of the G16F detectors (TUNE). Defaults: the
// AntiHunter-described values as starting hypotheses, except cooldown_ms (45 s,
// kept below Core::area_incident_ms so a continuing pattern never lapses from
// the screen, the G14/G16E finding) and the values marked "Guardian" that the
// ledger left open.
struct ThreatLimits {
    Millis cooldown_ms{45000};              // area/network patterns (AntiHunter: 60 s quiet before re-alert)
    Millis bssid_cooldown_ms{30000};        // channel-switch / quiet and marked beacons: per BSSID
    // (1) Probe requests.
    // G16J, measured on the StickS3 locked to one channel (2026-11-17): a tool that hops
    // channel on every probe leaves about 1/13 of its probes here (10-14 per 5 s against
    // 0-4 when quiet), so the AntiHunter-described 80 / 60 / 5 s never fired. 16 / 12 / 10 s
    // fired on that flood and stayed silent through the benign soak
    // (firmware/evidence/sticks3-G16J-spike-c-benign-ceiling-20261118.log).
    Millis probe_window_ms{10000};
    std::uint32_t probe_flood{16};          // probe requests in the window ...
    std::uint32_t probe_flood_sources{12};  // ... from at least this many distinct addresses
    std::uint32_t probe_source_flood{60};   // one address, per window, for two windows in a row
    std::uint32_t probe_name_sources{40};   // distinct addresses asking for one name in the window
    // (2) Beacon flood.
    Millis beacon_window_ms{10000};
    std::uint32_t beacon_flood_bssids{40};  // distinct BSSIDs received at or above beacon_rssi_min
    std::int8_t beacon_rssi_min{-65};       // dBm gate: far-away networks never count
    // (3) One transmitter answering for many names.
    Millis responder_window_ms{60000};
    std::uint32_t responder_names{4};       // Guardian: ledger "N"; distinct names from one transmitter
    std::uint32_t responder_matched_names{2}; // Guardian: names that a nearby device asked for just before
    // (4)-(6) Join floods, per BSSID.
    Millis auth_window_ms{5000};
    std::uint32_t auth_flood{60};           // open-system authentication requests ...
    std::uint32_t auth_flood_sources{16};   // ... from at least this many distinct addresses
    std::uint32_t sae_commit_excess{10};    // SAE commits minus confirms
    std::uint32_t assoc_sleep{8};           // (re)association requests with the power-management bit ...
    std::uint32_t assoc_sleep_sources{4};   // ... or this many distinct addresses sending them
    // (7) Channel switch / quiet.
    std::uint32_t csa_count_min{50};        // a switch count this large is out of the ordinary
    std::uint32_t quiet_duration_tu{1000};  // a Quiet duration this long (TU = 1024 us)
    Millis csa_mix_ms{2000};                // Guardian: an own beacon WITHOUT the switch this soon after one with it
    std::uint32_t csa_mixed{2};             // Guardian: ... this many times inside csa_window_ms
    Millis csa_window_ms{10000};
    // (8) Probe-response name differs from the same BSSID's beacon name.
    Millis mismatch_window_ms{10000};       // Guardian
    std::uint32_t mismatch_responses{2};    // Guardian: one response right after a rename is not enough
    // (10) Open beacon reusing an OWE transition network's name.
    Millis owe_memory_ms{300000};           // Guardian: how long a declared OWE pair is remembered
    Millis owe_window_ms{10000};            // Guardian
    std::uint32_t owe_twin_beacons{2};      // Guardian
    // (11) Disconnect frames outside the selected/approved BSSIDs.
    Millis deauth_source_window_ms{10000};
    std::uint32_t deauth_source{20};
    Millis deauth_pair_window_ms{1000};
    std::uint32_t deauth_pair{12};
    Millis deauth_broadcast_window_ms{10000}; // Guardian
    std::uint32_t deauth_broadcast{10};       // Guardian
    Millis dedupe_ms{1000};                   // Retry-bit copy of an identical header: not counted (G06 rule)
    // (12) Name rotation from one transmitter.
    Millis rotation_window_ms{5000};
    std::uint32_t rotation_names{12};
    // G16G data path. Ledger G16G values (AntiHunter-described starting
    // hypotheses) unless marked "Guardian"; all uncalibrated.
    // (13) Handshake starts (M1) to one station by many APs, none answered by its M2.
    Millis harvest_window_ms{10000};
    std::uint32_t harvest_bssids{3};
    Millis harvest_settle_ms{1500};         // an M1 counts as unanswered only after this long without an M2
    // (14) Handshake start with an all-zero ANonce.
    std::uint32_t fake_m1{1};
    Millis fake_m1_window_ms{10000};        // Guardian
    // (15) Disconnect burst on the selected / an approved AP, then a fresh handshake.
    Millis reconnect_ms{8000};              // the handshake starts at most this long after the burst's last frame
    Millis reconnect_burst_window_ms{5000}; // Guardian
    std::uint32_t reconnect_burst{5};       // Guardian: deduplicated disconnect frames for one station (or broadcast)
    std::uint32_t reconnect_messages{2};    // Guardian: distinct handshake messages (M1..M4) that make "an exchange"
    // G16J (16) Noise floor on a channel, from the adapter's per-second receive counts.
    // Ledger G16J values: a rise of noise_rise_db above the channel's own
    // noise_average_ms moving average, held for noise_hold_ms.
    std::uint32_t noise_rise_db{8};
    Millis noise_average_ms{60000};
    Millis noise_hold_ms{3000};
    std::uint32_t noise_min_frames{5};      // Guardian: frames with a noise reading needed in an interval
    std::uint32_t noise_baseline_samples{10}; // Guardian: intervals in the average before a rise is judged
    // G16J tool shapes (guardian/core.hpp namespace shape).
    std::uint32_t shape_frames{3};          // Guardian: frames showing a per-frame shape inside the window
    std::uint32_t shape_run{6};             // Guardian: frames in a rising-sequence / alternation run
    std::uint32_t tsf_static_beacons{5};    // Guardian: beacons of one BSSID repeating one timestamp ...
    Millis tsf_static_ms{500};              // Guardian: ... at least this far apart, first to last
    Millis bait_ms{30000};                  // a handshake this long after SHAPED disconnect frames still counts
    // G16J a device asks for a name, then a BSSID never seen before answers / beacons it.
    Millis karma_answer_ms{10000};          // ledger: the answer comes within this long after the ask
    std::uint32_t karma_answers{2};         // Guardian: frames from that BSSID carrying the name
    Millis karma_learn_ms{30000};           // Guardian: listening time before "never seen" means anything
    // G16J an open lure-style name from a development-board vendor address.
    std::uint32_t lure_beacons{3};          // Guardian: such beacons inside rotation_window_ms
    // G16H Bluetooth LE pairing-popup adverts (BlePopupDetector). Ledger G16H values
    // (AntiHunter-described starting hypotheses) unless marked "Guardian"; all
    // uncalibrated until the benign soak with the owner's real earbuds.
    Millis ble_popup_window_ms{1000};
    std::uint32_t ble_popup_messages{3};    // different popup messages inside the window ...
    std::uint32_t ble_popup_sources{3};     // ... carried by at least this many short-lived addresses
    Millis ble_learn_ms{30000};             // Guardian: listening time before a "new" address means anything
    Millis ble_address_memory_ms{60000};    // Guardian: how long a heard address stays known (not "new")
    Millis ble_rotation_window_ms{5000};
    std::uint32_t ble_rotation_models{3};   // different Fast Pair model IDs from one address inside the window
};

// SlotCount, the bounded sliding counter, lives in guardian/shapes.hpp since G16J.

// Shared mechanics of the G16F detectors (origin/epoch binding, cooldowns,
// report counters, coverage, emission). Not a detector by itself.
class ThreatDetector : public FrameDetector {
public:
    bool configured() const { return configured_; }
    const ThreatLimits& limits() const { return limits_; }
    // Validated replacement (TUNE). On success the detector starts clean; on
    // failure it is unconfigured and counts nothing until a valid configure().
    bool configure(const ThreatLimits& limits);
    // G16G: whether the adapter feeds this detector's input at all (data frames,
    // receive-error counts). Unavailable = counts nothing and reports
    // configured=false, so nothing is shown as measuring. Default true.
    void set_available(bool available) { if (available_ != available) { available_ = available; reset(); } }
    bool available() const { return available_; }
    // Whether configure(limits) would succeed (no state change).
    bool accepts(const ThreatLimits& limits) const { return valid(limits); }
    void on_tick(Instant now, ObservationSink& out) override;
    void reset() override;
    void coverage(const CoverageReport& report) override;
    DetectorReport report(Instant now) const override;

protected:
    ThreatDetector(const char* name, DetectorFamily family, const ApprovedScope& scope, const ThreatLimits& limits);
    // The detector's own limit checks (called by the constructor and configure).
    virtual bool valid(const ThreatLimits& limits) const = 0;
    virtual void clear_state() = 0;            // drop every window / table (reset, configure)
    virtual Millis window_ms() const = 0;      // the main window for report()
    virtual std::uint32_t in_window(Millis at) const = 0;  // counted events in the window ending at `at`
    // Frame admission: counts frames_seen, checks status/header/time/origin/epoch.
    bool admit(const RxMeta& meta, const ParseResult& parsed);
    // G16G: the origin/epoch binding alone (for non-frame input such as samples).
    bool admit_input(Origin origin, const Instant& at);
    // G16G: `now` belongs to the bound timebase (for emission from on_tick).
    bool bound_to(const Instant& now) const { return now.valid() && epoch_set_ && now.epoch == epoch_; }
    void counted(Millis at);                   // one counted event (radar pulse)
    bool in_scope(const Mac& bssid) const { return scope_.in_scope(bssid); }       // selected / approved only
    // G16R: the picked network by its name (selected, approved, or heard advertising that name).
    bool in_network(const Mac& bssid) const { return scope_.in_network(bssid); }
    // G16H: one input offered to a detector that takes no frames (DetectorReport::frames_seen).
    void offered();
    // One observation per cooldown per (scope, pattern, key). Returns true when emitted.
    bool emit(IncidentObservation o, const Mac& key, Millis cooldown, ObservationSink& out);
    void init(const ThreatLimits& limits);

    const ApprovedScope& scope_;
    ThreatLimits limits_;
    bool configured_{};
    Origin origin_{Origin::LiveRadio};

private:
    struct Cooldown { std::uint64_t key{}; Millis at{}; Millis length{}; bool used{}; };
    static constexpr std::size_t cooldown_slots = 8;
    const char* name_;
    DetectorFamily family_;
    bool available_{true};
    bool origin_set_{};
    bool epoch_set_{};
    TimeEpoch epoch_{};
    std::array<Cooldown, cooldown_slots> cooldowns_{};
    bool has_coverage_{};
    CoverageReport coverage_{};
    std::uint32_t frames_seen_{};
    std::uint32_t events_{};
    std::uint32_t incidents_{};
    bool has_event_{};
    Millis last_event_{};
    bool has_incident_{};
    Millis last_incident_{};
};

// (1) Probe requests: randomized-source flood, single-source flood (two windows
// in a row, counted in per-address tumbling windows that start at the
// address's first probe) and many addresses asking for one name. Wildcard
// probes never count for a name. With the default 60-address threshold and a
// 64-address table, a randomized flood is usually reported `saturated`
// ("64 or more addresses"). No name is ignored for "looking random": that filter is
// deliberately not applied (a documented rule, not a hidden one).
class ProbeFloodDetector final : public ThreatDetector {
public:
    static constexpr std::size_t source_capacity = 64;   // distinct addresses in the window
    static constexpr std::size_t rate_capacity = 16;     // addresses with a per-address rate
    static constexpr std::size_t name_capacity = 64;     // (name, address) pairs in the window
    ProbeFloodDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
private:
    struct Source { Mac mac{}; Millis last{}; bool used{}; bool local{}; };
    struct Rate { Mac mac{}; Millis last{}; Millis start{}; std::uint32_t count{}; bool full_before{}; bool used{}; };
    struct NamePair { std::uint32_t name{}; Mac mac{}; Millis last{}; bool local{}; bool used{}; };
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.probe_window_ms; }
    std::uint32_t in_window(Millis at) const override { return probes_.sum(at, limits_.probe_window_ms); }
    SlotCount probes_{};
    SlotCount shaped_{};   // G16J: probe requests with sequence control 0x0001
    std::array<Source, source_capacity> sources_{};
    std::array<Rate, rate_capacity> rates_{};
    std::array<NamePair, name_capacity> names_{};
    Millis sources_saturated_until_{};
    Millis names_saturated_until_{};
};

// (2) Many distinct strong BSSIDs beaconing inside the window. Beacons below
// the RSSI gate (or without an RSSI) never count. While a flood observation is
// inside its cooldown nothing more is emitted for it (one observation, not one
// per beacon).
class BeaconFloodDetector final : public ThreatDetector {
public:
    static constexpr std::size_t capacity = 64;
    BeaconFloodDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
private:
    // G16J: the timestamp this BSSID keeps repeating (tsf_same beacons since tsf_first) and its shapes.
    struct Seen { Mac bssid{}; Millis last{}; bool used{}; bool local{}; std::uint64_t tsf{}; std::uint32_t tsf_same{}; Millis tsf_first{}; std::uint16_t shapes{}; };
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.beacon_window_ms; }
    std::uint32_t in_window(Millis at) const override { return beacons_.sum(at, limits_.beacon_window_ms); }
    SlotCount beacons_{};
    std::array<Seen, capacity> seen_{};
    Millis saturated_until_{};
};

// (3) One transmitter (Address 2) answering for many names through probe
// responses or beacons inside the window. Transmitters that advertise a
// Multiple BSSID element are excluded. Names a nearby device asked for (probe
// request) shortly before the answer are corroborating, and reaching
// responder_matched_names of them is enough on its own.
class ResponderDetector final : public ThreatDetector {
public:
    static constexpr std::size_t pair_capacity = 48;     // (transmitter, name) pairs
    static constexpr std::size_t asked_capacity = 32;    // names asked for by probe requests
    static constexpr std::size_t multi_capacity = 16;    // Multiple-BSSID transmitters (excluded)
    static constexpr std::size_t known_capacity = 128;   // G16J: BSSIDs heard advertising (least recently heard is replaced)
    static constexpr std::size_t answer_capacity = 8;    // G16J: new BSSIDs answering an asked name
    ResponderDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
private:
    struct Pair { Mac tx{}; std::uint32_t name{}; Millis last{}; bool matched{}; bool used{}; };
    // `first`: the start of the current asking episode (asks no further apart than the responder window).
    struct Asked { std::uint32_t name{}; Millis first{}; Millis last{}; bool used{}; };
    struct Multi { Mac tx{}; Millis last{}; bool used{}; };
    struct Known { Mac bssid{}; std::uint32_t name{}; Millis first{}; Millis last{}; bool used{}; };
    struct Answer { Mac bssid{}; std::uint32_t name{}; Millis last{}; std::uint32_t frames{}; bool used{}; };
    void karma(const RxMeta&, const ParseResult&, std::uint32_t name, bool was_known, ObservationSink&);
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.responder_window_ms; }
    std::uint32_t in_window(Millis at) const override { return answers_.sum(at, limits_.responder_window_ms); }
    SlotCount answers_{};
    std::array<Pair, pair_capacity> pairs_{};
    std::array<Asked, asked_capacity> asked_{};
    std::array<Multi, multi_capacity> multi_{};
    Millis saturated_until_{};
    // G16J probe-then-answer: BSSIDs heard advertising (never-seen = not here), the
    // new BSSIDs currently answering an asked name, and when listening began.
    std::array<Known, known_capacity> known_{};
    std::array<Answer, answer_capacity> answers_new_{};
    Millis known_saturated_until_{};
    Millis started_{};
    bool started_set_{};
};

// Per-BSSID counters shared by the join-flood detectors (4)-(6).
struct BssidCounter {
    Mac bssid{};
    Millis last{};
    SlotCount a{};   // detector-specific: requests / commits
    SlotCount b{};   // detector-specific: confirms
    bool used{};
};
struct SourcePair {
    Mac bssid{};
    Mac source{};
    Millis last{};
    bool used{};
};

// (4) Open-system authentication requests (transaction 1, not sent by the
// BSSID itself) to one BSSID: count and distinct sources inside the window.
class AuthFloodDetector final : public ThreatDetector {
public:
    static constexpr std::size_t bssid_capacity = 8;
    static constexpr std::size_t pair_capacity = 48;
    AuthFloodDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
private:
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.auth_window_ms; }
    std::uint32_t in_window(Millis at) const override { return total_.sum(at, limits_.auth_window_ms); }
    SlotCount total_{};
    std::array<BssidCounter, bssid_capacity> bssids_{};
    std::array<SourcePair, pair_capacity> pairs_{};
    Millis saturated_until_{};
};

// (5) SAE (algorithm 3) commits minus confirms sent to one BSSID inside the
// window. Frames sent by the BSSID itself never count.
class SaeCommitDetector final : public ThreatDetector {
public:
    static constexpr std::size_t bssid_capacity = 8;
    static constexpr std::size_t pair_capacity = 32;
    SaeCommitDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
private:
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.auth_window_ms; }
    std::uint32_t in_window(Millis at) const override { return total_.sum(at, limits_.auth_window_ms); }
    SlotCount total_{};
    std::array<BssidCounter, bssid_capacity> bssids_{};
    std::array<SourcePair, pair_capacity> pairs_{};
    Millis saturated_until_{};
};

// (6) (Re)association requests carrying the power-management bit to one
// BSSID: count or distinct sources inside the window.
class AssocSleepDetector final : public ThreatDetector {
public:
    static constexpr std::size_t bssid_capacity = 8;
    static constexpr std::size_t pair_capacity = 32;
    AssocSleepDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
private:
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.auth_window_ms; }
    std::uint32_t in_window(Millis at) const override { return total_.sum(at, limits_.auth_window_ms); }
    SlotCount total_{};
    std::array<BssidCounter, bssid_capacity> bssids_{};
    std::array<SourcePair, pair_capacity> pairs_{};
    Millis saturated_until_{};
};

// (7) Channel-switch and quiet announcements in beacons / probe responses:
// a switch count >= csa_count_min, a Quiet duration >= quiet_duration_tu, or,
// for the selected / an approved BSSID, a switch its own beacons do not keep
// announcing (a beacon of that BSSID WITHOUT the element arriving within
// csa_mix_ms after one WITH it, csa_mixed times inside csa_window_ms: a real
// announcement stays in every beacon until the switch). Per BSSID cooldown.
class ChannelSwitchDetector final : public ThreatDetector {
public:
    static constexpr std::size_t capacity = 8;   // in-scope BSSIDs tracked for the mixed rule
    ChannelSwitchDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
private:
    struct Track { Mac bssid{}; Millis last{}; Millis last_csa{}; bool has_csa{}; SlotCount mixed{}; bool used{}; };
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.csa_window_ms; }
    std::uint32_t in_window(Millis at) const override { return frames_.sum(at, limits_.csa_window_ms); }
    SlotCount frames_{};   // announcements counted
    std::array<Track, capacity> tracks_{};
};

// (8) A BSSID's probe response names a different network than its own
// beacons (CVE-2023-52424 "SSID confusion" indicator). Hidden beacons (zero
// length or NUL bytes) never make a mismatch: a hidden AP answers with its
// real name. Compared by a 32-bit hash of the exact bytes plus the length: a
// different hash proves different bytes; a collision can only hide one.
class NameMismatchDetector final : public ThreatDetector {
public:
    static constexpr std::size_t beacon_capacity = 48;
    static constexpr std::size_t counter_capacity = 8;
    NameMismatchDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
private:
    struct Beacon { Mac bssid{}; std::uint32_t name{}; bool hidden{}; Millis last{}; bool used{}; };
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.mismatch_window_ms; }
    std::uint32_t in_window(Millis at) const override { return mismatches_.sum(at, limits_.mismatch_window_ms); }
    SlotCount mismatches_{};
    std::array<Beacon, beacon_capacity> beacons_{};
    std::array<BssidCounter, counter_capacity> counters_{};
};

// (9) Beacons carrying element 222 or sent from / for DE:AD:BE:EF:DE:AD. One
// observation per BSSID per bssid_cooldown_ms. A marker, not an identity.
class MarkedBeaconDetector final : public ThreatDetector {
public:
    MarkedBeaconDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
private:
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.bssid_cooldown_ms; }
    std::uint32_t in_window(Millis at) const override { return marked_.sum(at, limits_.bssid_cooldown_ms); }
    SlotCount marked_{};
};

// (10) An open beacon (Privacy clear, no RSN/WPA, no OWE transition element)
// reusing the open name of an OWE transition pair from a BSSID that pair did
// not declare. Pairs are learned from valid OWE Transition Mode elements: the
// OWE side declares its open partner, and the open side declares itself.
class OweTwinDetector final : public ThreatDetector {
public:
    static constexpr std::size_t pair_capacity = 16;
    static constexpr std::size_t counter_capacity = 8;
    OweTwinDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
private:
    struct Declared { std::uint32_t name{}; Mac open_bssid{}; Millis last{}; bool used{}; };
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.owe_window_ms; }
    std::uint32_t in_window(Millis at) const override { return twins_.sum(at, limits_.owe_window_ms); }
    SlotCount twins_{};
    std::array<Declared, pair_capacity> declared_{};
    std::array<BssidCounter, counter_capacity> counters_{};
};

// (11) Disconnect frames (deauthentication / disassociation) under BSSIDs that
// are not the picked network's (selected, approved or, G16R, heard under its
// name: those stay the red DisconnectBurst's):
// per transmitter, per transmitter+destination pair and broadcast bursts.
// Retry-bit copies of an identical header within dedupe_ms are not counted;
// reason codes are never read.
//
// G16T: a nearby burst that also names the picked network is about the picked
// network. MEASURED 2026-11-19 on the StickS3: a burst spread over the access
// points of one channel reached the nearby threshold while the picked network
// got a few frames, below the red burst's own threshold, and the owner saw
// amber. The rule: when a rule above is reached for frames under other BSSIDs
// and the same burst holds at least one counted disconnect frame that names the
// picked network in Address 1, 2 or 3 (ApprovedScope::in_network: nothing
// configured, the addresses come from the pick and from the air), the report is
// IncidentScope::Network (NetworkPattern, red) instead of Area, with the reached
// rule as its pattern and count, IncidentObservation::own_frames = those frames
// so far, `top` = the most frequent tuple naming the picked network and `bssid`
// = the picked network's address in it. "The same burst": the source window
// before the rule is reached, then every counted frame for as long as the burst
// is being counted (it closes after a whole source window without one), so a
// frame at the picked network AFTER a nearby report turns that burst red at
// that frame. No such frame: Area, exactly as before. One Network report per
// rule per cooldown. The red burst's threshold (DisconnectDetector) and the
// pair rule on the picked network are unchanged: a few frames at the picked
// network with no nearby burst report nothing. Honest limit: one ordinary
// disconnect frame of the picked network inside a neighbour's burst makes that
// burst red too; the frames are header bytes as received, never a sender proven.
class AreaDisconnectDetector final : public ThreatDetector {
public:
    static constexpr std::size_t source_capacity = 16;
    static constexpr std::size_t pair_capacity = 16;
    static constexpr std::size_t dedupe_capacity = 16;
    AreaDisconnectDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
    // G16S: the tuples (receiver, sender, BSSID, channel) of the last burst that reached
    // one of this detector's thresholds (also inside a cooldown), with its total and the
    // incident time. Area: the burst counted nearby. G16T: its record holds EVERY counted
    // disconnect frame of the burst, the picked network's too, each such tuple marked
    // (BurstTuple::own) with LastBurst::own = how many frames named the picked network.
    // Network: the picked network's frames, recorded when the PAIR rule is reached (the
    // red burst itself is DisconnectDetector::last_burst) or, G16T, that nearby record
    // when it holds a frame naming the picked network (it was reported as a Network
    // incident), whichever reached its threshold later; a later nearby burst without such a
    // frame leaves that record in place (BurstTrace::last_own). The window is the source
    // window (window_ms()). Rules: guardian/shapes.hpp (BurstTrace).
    LastBurst last_burst(IncidentScope scope, Instant now) const;
private:
    struct Header { Mac a1{}, a2{}, a3{}; std::uint16_t sequence{}; std::uint8_t fragment{}, kind{}; Millis at{}; bool used{}; std::uint8_t copies{}; };   // copies: G22, Retry copies absorbed (<= retry_copies_max)
    struct Keyed { Mac a{}, b{}; Millis last{}; SlotCount n{}; ShapeWindow shapes{}; bool used{}; };
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.deauth_source_window_ms; }
    std::uint32_t in_window(Millis at) const override { return all_.sum(at, limits_.deauth_source_window_ms); }
    // The three rules for one counted frame (`own`: Address 3 is the picked network's).
    void rules(const RxMeta&, const ParseResult&, bool own, std::uint16_t frame_bits, std::uint16_t run_bits, ObservationSink&);
    SlotCount all_{};
    SlotCount broadcast_{};
    ShapeWindow broadcast_shapes_{};   // G16J
    DisconnectRuns runs_{};            // G16J
    std::array<Keyed, source_capacity> sources_{};
    std::array<Keyed, pair_capacity> pairs_{};
    std::array<Header, dedupe_capacity> recent_{};
    std::size_t recent_next_{};
    Millis saturated_until_{};
    // G16S: [0] the burst counted nearby (G16T: every counted frame, the picked network's marked),
    // [1] the picked network's frames for the pair rule.
    std::array<BurstTrace, 2> traces_{};
    IncidentObservation reached_{};        // G16T: the nearby rule as last reached in the burst being counted
};

// (12) One transmitter beaconing many names inside the window (Multiple-BSSID
// transmitters excluded). When that transmitter also beaconed an open network
// with a lure-style name (case-insensitive "free", "guest", "public", "open",
// "hotspot", "airport" or "hotel"), the observation is OpenLure instead.
class NameRotationDetector final : public ThreatDetector {
public:
    static constexpr std::size_t pair_capacity = 48;
    static constexpr std::size_t multi_capacity = 16;
    NameRotationDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
private:
    struct Pair { Mac tx{}; std::uint32_t name{}; Millis last{}; bool lure{}; bool used{}; };
    struct Multi { Mac tx{}; Millis last{}; bool used{}; };
    // G16J: per transmitter, the timestamp it keeps repeating and its shapes.
    struct Stamp { Mac tx{}; Millis last{}; std::uint64_t tsf{}; std::uint32_t same{}; Millis first{}; std::uint16_t shapes{}; bool used{}; };
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.rotation_window_ms; }
    std::uint32_t in_window(Millis at) const override { return names_.sum(at, limits_.rotation_window_ms); }
    SlotCount names_{};
    std::array<Pair, pair_capacity> pairs_{};
    std::array<Multi, multi_capacity> multi_{};
    Millis saturated_until_{};
    std::array<Stamp, multi_capacity> stamps_{};      // G16J
    std::array<BssidCounter, 8> lures_{};             // G16J: open lure beacons per board-vendor BSSID
};

// (13)-(15) G16G: unprotected EAPOL-Key frames (ParseResult::eapol) plus the
// disconnect frames of the selected / approved APs.
//   PmkidHarvest  one station is sent handshake starts (M1) by >= harvest_bssids
//                 distinct APs inside harvest_window_ms and answers none of them
//                 with its M2 within harvest_settle_ms. Network scope when one of
//                 those APs is the selected / an approved one. Evaluated on every
//                 frame and on on_tick (the settle time must pass).
//   FakeM1        an M1 whose ANonce is all zero (fake_m1 of them per AP inside
//                 fake_m1_window_ms). Scope by the AP.
//   DeauthHandshake  on the selected / an approved AP only: reconnect_burst
//                 deduplicated disconnect frames for one station (or broadcast)
//                 inside reconnect_burst_window_ms, then reconnect_messages
//                 distinct handshake messages for that station starting no later
//                 than reconnect_ms after the burst's last frame. Wording: clients
//                 were pushed off and reconnected (a handshake was exchanged);
//                 never "cracked", never who captured it.
// Missed frames are possible (the station may be out of range while its AP is
// heard), which is why the settle time and the thresholds are TUNE hypotheses.
class HandshakeDetector final : public ThreatDetector {
public:
    static constexpr std::size_t start_capacity = 32;    // (AP, station) handshake starts
    static constexpr std::size_t counter_capacity = 16;  // (AP, station) disconnect counters on in-scope APs
    static constexpr std::size_t burst_capacity = 8;
    static constexpr std::size_t exchange_capacity = 8;
    static constexpr std::size_t dedupe_capacity = 16;
    HandshakeDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override;
    void on_tick(Instant now, ObservationSink& out) override;
private:
    struct Start { Mac ap{}, station{}; Millis at{}, last{}; std::uint64_t replay{}; bool pmkid{}, answered{}, used{}; std::uint16_t shapes{}; };
    struct Counter { Mac ap{}, station{}; Millis last{}; SlotCount n{}; ShapeWindow shapes{}; bool used{}; };
    struct Burst { Mac ap{}, station{}; Millis first{}, last{}; std::uint32_t count{}; bool used{}; std::uint16_t shapes{}; };
    struct Exchange { Mac ap{}, station{}; Millis burst_first{}, last{}; std::uint8_t messages{}; std::uint32_t burst_count{}; bool used{}; };
    struct Header { Mac a1{}, a2{}, a3{}; std::uint16_t sequence{}; std::uint8_t fragment{}, kind{}; Millis at{}; bool used{}; std::uint8_t copies{}; };   // copies: G22, Retry copies absorbed (<= retry_copies_max)
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.harvest_window_ms; }
    std::uint32_t in_window(Millis at) const override { return messages_.sum(at, limits_.harvest_window_ms); }
    void disconnect(const RxMeta&, const ParseResult&, ObservationSink&);
    void key(const RxMeta&, const ParseResult&, ObservationSink&);
    void settle(const Instant& now, ObservationSink&);
    SlotCount messages_{};
    std::array<Start, start_capacity> starts_{};
    std::array<BssidCounter, 8> fake_{};
    std::array<Counter, counter_capacity> counters_{};
    std::array<Burst, burst_capacity> bursts_{};
    std::array<Exchange, exchange_capacity> exchanges_{};
    std::array<Header, dedupe_capacity> recent_{};
    std::size_t recent_next_{};
    Millis saturated_until_{};
    DisconnectRuns runs_{};   // G16J
};

// (16) G16J: a channel's noise floor rising above its own recent average,
// from the adapter's per-interval receive counts (ChannelLoadSample: the
// noise-floor readings the radio attached to the frames it received), never
// from frame bytes. It replaces the G16G packet-delivery-ratio rule (the one
// AntiHunter dropped). An interval has a usable reading when at least
// noise_min_frames frames carried one while the radio listened there. The
// channel's average covers the usable intervals of the last noise_average_ms
// that were not themselves raised and needs noise_baseline_samples of them;
// while a rise lasts the average stays the one from before it began, so a
// long rise does not become the new normal by itself. After ten times
// noise_average_ms of continuous rise the raised level IS taken as the new
// normal (a permanently noisier channel must not report forever). A rise of noise_rise_db or
// more above that average, in consecutive usable intervals spanning
// noise_hold_ms, is one observation per channel per cooldown (Area scope, "on
// this channel nearby"): count = the rise in dB, threshold = noise_rise_db,
// corroborating = receive-error frames in the held intervals, raw_frames =
// every frame in them (the error ratio is evidence text, never the rule).
// Honest limits: the noise figure is the radio's own estimate at the moments
// it received a frame; a jammer strong enough to stop ALL reception leaves no
// frames and so no reading (then the selected network goes "No fresh data").
// A microwave oven or a neighbour's wideband traffic can raise the floor too:
// the observation says the channel got noisy, never why.
class NoiseFloorDetector final : public ThreatDetector {
public:
    static constexpr std::size_t channel_capacity = 15;   // index = channel number 1..14
    static constexpr std::size_t history = 64;            // usable intervals kept per channel
    NoiseFloorDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override {}
    void sample(const ChannelLoadSample& s, ObservationSink& out);
    std::uint32_t samples() const { return samples_; }
private:
    struct Channel {
        std::array<std::int8_t, history> dbm{};
        std::array<Millis, history> at{};
        std::size_t next{}, size{};
        Millis raised_since{}, last_raised{};
        bool raised{};
        std::uint32_t errors{}, frames{};   // inside the current rise
    };
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.noise_hold_ms; }
    std::uint32_t in_window(Millis at) const override { return raised_.sum(at, limits_.noise_hold_ms); }
    SlotCount raised_{};
    std::array<Channel, channel_capacity> channels_{};
    std::uint32_t samples_{};
};

// (17) G16H: Bluetooth LE pairing-popup messages (guardian/ble.hpp), from the
// advertising reports of a PASSIVE scan the adapter runs; never from Wi-Fi
// frames (on_frame does nothing). Two independent rules, both Area scope
// ("nearby", amber) and one observation per rule per cooldown:
//
//   PairingPopupFlood  inside ble_popup_window_ms, at least ble_popup_messages
//       DIFFERENT popup messages (format + product/action) carried by at least
//       ble_popup_sources SHORT-LIVED addresses. Short-lived = first heard
//       inside that same window. A device that keeps its address (real earbuds
//       in use, a phone) is heard under one address for minutes, becomes known
//       after one window and never counts again while it stays in the address
//       memory (ble_address_memory_ms after it was last heard). The ledger rule
//       is ">= 3 message types and >= 3 addresses in 1 s from rotating
//       addresses"; "rotating" is made concrete as short-lived. count = the
//       different messages, distinct_sources = the short-lived addresses,
//       corroborating = the different vendor formats among them, raw_frames =
//       popup adverts received in the window.
//       Nothing is reported during the first ble_learn_ms of listening, nor of
//       listening again after a silence longer than the address memory: until
//       then every device in the room is "new".
//   FastPairRotation   one address announcing at least ble_rotation_models
//       different Fast Pair model IDs inside ble_rotation_window_ms (a real
//       device has one model). count = the models, distinct_sources = 1.
//
// Honest limits (docs/research/ble-popup-spam.md): a sender that keeps ONE
// address and one product, or changes its address slower than the window, is
// not reported; several real devices that all appear for the first time in the
// same second (after the learning time) look like the flood rule and are the
// known false positive to calibrate in the benign soak; with a scan duty below
// 100 % only part of the adverts is heard, so counts are lower bounds and the
// observation carries the scan's own listening report (scan_coverage) when the
// adapter gave one. Tables are bounded: when an address still inside the window
// must be dropped the observation is `saturated`. Addresses are kept in RAM for
// the address memory only, never printed, stored or linked to anything.
class BlePopupDetector final : public ThreatDetector {
public:
    static constexpr std::size_t address_capacity = 48;   // addresses heard sending a popup message
    static constexpr std::size_t model_capacity = 24;     // (address, Fast Pair model) pairs
    BlePopupDetector(const ApprovedScope& scope, const ThreatLimits& limits = {});
    void on_frame(const FrameSpan&, const RxMeta&, const ParseResult&, ObservationSink&) override {}
    // One advertising report. Every report is offered (also the ones that are no
    // popup message: they prove the scan is listening).
    void advert(const BleAdvert& advert, ObservationSink& out);
    // The Wi-Fi radio's listening report says nothing about the BLE scan: ignored.
    void coverage(const CoverageReport&) override {}
    // The BLE scan's own listening report (window, time actually scanning, reports dropped).
    void scan_coverage(const CoverageReport& report) { ThreatDetector::coverage(report); }
    std::uint32_t popup_adverts() const { return popup_adverts_; }   // classified as a popup message since reset
    std::uint32_t malformed() const { return malformed_; }           // unreadable advertising data since reset
private:
    struct Address { Mac mac{}; Millis first{}, last{}; std::uint32_t message{}; std::uint8_t format{}; bool random{}; bool used{}; };
    struct Model { Mac mac{}; std::uint32_t model{}; Millis last{}; bool used{}; };
    bool valid(const ThreatLimits&) const override;
    void clear_state() override;
    Millis window_ms() const override { return limits_.ble_popup_window_ms; }
    std::uint32_t in_window(Millis at) const override { return popups_.sum(at, limits_.ble_popup_window_ms); }
    void flood(const BleAdvert&, const BlePopup&, ObservationSink&);
    void rotation(const BleAdvert&, const BlePopup&, ObservationSink&);
    SlotCount popups_{};
    std::array<Address, address_capacity> addresses_{};
    std::array<Model, model_capacity> models_{};
    Millis saturated_until_{};
    Millis models_saturated_until_{};
    Millis started_{};       // when the current stretch of listening began
    Millis last_heard_{};    // the latest report of any kind
    bool started_set_{};
    std::uint32_t popup_adverts_{};
    std::uint32_t malformed_{};
};

// Exact-bytes name key: FNV-1a over the SSID bytes, mixed with the length.
std::uint32_t name_key(const std::uint8_t* ssid, std::size_t size);
// The documented lure-word rule of NameRotationDetector.
bool lure_name(const std::uint8_t* ssid, std::size_t size);

// The G16F and G16G detectors as one value the application owns and registers.
struct ThreatDetectors {
    ThreatDetectors(const ApprovedScope& scope, const ThreatLimits& limits = {});
    static constexpr std::size_t count = 15;   // G16G: + handshake; G16J: noise replaces frame_loss; G16H: + ble
    ProbeFloodDetector probe;
    BeaconFloodDetector beacon;
    ResponderDetector responder;
    AuthFloodDetector auth;
    SaeCommitDetector sae;
    AssocSleepDetector assoc;
    ChannelSwitchDetector channel_switch;
    NameMismatchDetector mismatch;
    MarkedBeaconDetector marked;
    OweTwinDetector owe;
    AreaDisconnectDetector deauth;
    NameRotationDetector rotation;
    HandshakeDetector handshake;     // G16G
    NoiseFloorDetector noise;        // G16J (replaces the G16G frame_loss rule)
    BlePopupDetector ble;            // G16H (fed by advert(), never by frames)
    FrameDetector* at(std::size_t i);
    // G16G: the adapter delivers unprotected EAPOL data frames (or not). The noise
    // detector needs no data path: every received frame carries a noise reading.
    void set_data_path(bool available) { handshake.set_available(available); }
    // G16H: an adapter runs a passive BLE scan and feeds ble.advert() (or not).
    void set_ble_scan(bool available) { ble.set_available(available); }
    // All-or-nothing: false (nothing changed) when any detector refuses.
    bool configure(const ThreatLimits& limits);
};

} // namespace guardian

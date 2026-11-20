#pragma once
// G16H spike instrument: what passive BLE scanning costs the Wi-Fi capture.
//
// The ESP32-S3 has one 2.4 GHz radio. Wi-Fi and BLE share it by time slices
// (ESP-IDF v5.4 docs/en/api-guides/coexist.rst: "Sniffer RX" with "BLE Scan"
// is rated C1, "supported but the performance is unstable"; with Wi-Fi not
// connected, "RF module is controlled by Bluetooth module"). Whether BLE
// observations are worth that cost is a measurement, not an assumption, so the
// ledger orders this spike before any BLE detector exists.
//
// This file is the portable half of the spike: the interleaved phase plan
// (OFF, L1, OFF, L2, ..., closing OFF, so every scanning phase has a
// non-scanning phase right before and after it, measured on the same AP in
// the same minutes), the per-phase counters, the beacon count of the selected
// AP from raw 802.11 headers, the verdict rule and the console lines. The board
// adapter (boards/sticks3/main/ble_spike.*, spike build variant only) starts
// and stops a PASSIVE scan (no scan requests, no advertising: nothing is
// transmitted) and feeds the counters. Advertising reports are only counted:
// no address, payload or identity is kept (no tracking, ledger out-of-scope).
//
// No allocation, fixed tables, no SDK. Host-tested in tests/coex_spike_check.cpp.
#include <array>
#include <cstddef>
#include <cstdint>

namespace guardian::coex {

using Mac = std::array<std::uint8_t, 6>;

// Passive BLE scan duty: the radio listens for window_ms out of every interval_ms.
// window_ms == 0 means BLE scanning off.
struct Duty {
    std::uint16_t window_ms{};
    std::uint16_t interval_ms{};
    bool on() const { return window_ms != 0; }
    std::uint16_t permille() const;   // window / interval in 1/1000 (0 when off)
};
// Off, or a scan the controller accepts: 2.5 ms <= window <= interval <= 10240 ms
// (HCI LE Set Scan Parameters range, 0.625 ms units).
bool valid(const Duty&);
// Milliseconds to 0.625 ms controller units (rounded down, as the HCI range is checked above).
std::uint16_t ble_units(std::uint16_t ms);

constexpr std::size_t max_levels = 6;
constexpr std::uint8_t max_rounds = 4;
constexpr std::size_t max_phases = 2u * max_levels * max_rounds + 1u;

struct Plan {
    std::array<Duty, max_levels> levels{};   // scanning duty levels, each must be on()
    std::uint8_t level_count{};
    std::uint32_t phase_ms{60000};           // each OFF and ON phase
    std::uint32_t settle_ms{3000};           // ignored at the start of every phase (scan start/stop)
    std::uint8_t rounds{2};
};
// The owner default: 3 %, 10 %, 25 % and 50 % passive duty, 60 s phases, 2 rounds
// (17 phases, 17 minutes).
Plan default_plan();
bool valid(const Plan&);
std::size_t phase_count(const Plan&);          // rounds * 2 * levels + 1 (0 for an invalid plan)
int phase_level(const Plan&, std::size_t i);   // level index of phase i, -1 for an OFF phase
Duty phase_duty(const Plan&, std::size_t i);   // Duty{} for an OFF phase

// Raw 802.11 header check, no parser: a beacon (FC 0x80, ToDS/FromDS 0) whose
// BSSID (address 3) is `bssid`, with its beacon interval (TU) when the fixed
// fields are present. Frames are FCS-free (the adapter strips the 4 bytes).
struct BeaconSample {
    bool from_selected{};
    std::uint16_t interval_tu{};
};
BeaconSample classify(const std::uint8_t* frame, std::size_t size, const Mac& bssid);

// Monotonic totals sampled from the board (unsigned deltas: wrap-safe).
struct Counters {
    std::uint32_t frames{};           // Wi-Fi receive callbacks (every frame the driver delivered)
    std::uint32_t queue_full{};       // frames lost because the 24-deep queue was full
    std::uint32_t adv_reports{};      // BLE advertising reports (counted only)
    std::uint32_t display_frames{};   // frames pushed to the panel
};
// Instantaneous board state, sampled every loop.
struct Sample {
    std::uint32_t heap_internal_free{};
    bool vbat_ok{};
    std::uint16_t vbat_mv{};
    bool monitoring{};                // radio locked on the selected AP's channel (survey.monitoring())
    std::uint8_t channel{};
    std::uint32_t lock_losses{};      // survey locks ended since boot (Survey::lock_losses(), monotonic)
};

enum class PhaseFault : std::uint8_t { None, NotMonitoring, ChannelChanged, TooShort, Aborted };
const char* fault_text(PhaseFault);   // "ok", "not_monitoring", "channel_changed", "too_short", "aborted"

struct PhaseResult {
    std::int8_t level{-1};            // -1 = OFF
    Duty duty{};
    PhaseFault fault{PhaseFault::None};
    bool valid() const { return fault == PhaseFault::None; }
    std::uint8_t channel{};
    std::uint32_t measured_ms{};      // after settle
    std::uint32_t beacons{};          // selected-AP beacons acquired inside the measured window
    std::uint16_t beacon_interval_tu{};
    std::uint32_t frames{}, queue_full{}, adv_reports{}, display_frames{};   // deltas over the measured window
    std::uint32_t heap_min{};         // lowest free internal heap during the whole phase
    std::uint32_t lock_losses{};      // survey locks ended during the whole phase (silence_5s: no frame for 5 s)
    bool monitoring_at_end{};         // locked on the AP's channel when the phase closed
    bool vbat_ok{};
    std::uint16_t vbat_start_mv{}, vbat_end_mv{};
};

class Spike {
public:
    struct Step {
        bool apply{};                 // the board must apply `duty` now (phase boundary or start/stop)
        Duty duty{};
        bool phase_done{};            // result(completed()-1) is new
        bool finished{};              // the plan completed this step (scan is off)
    };
    // False (and nothing changes) when running, the plan is invalid or the BSSID is zero.
    // The first phase (OFF) starts at now; Step tells the board to apply it.
    bool start(const Plan&, const Mac& bssid, std::uint64_t now_ms, Step& first);
    Step tick(std::uint64_t now_ms, const Counters&, const Sample&);
    // A queued Wi-Fi frame, timestamped when the receive callback acquired it.
    void frame(const std::uint8_t* bytes, std::size_t size, std::uint64_t acquired_ms);
    // Ends the run now: the current phase is recorded as Aborted, scanning goes off.
    Step abort();
    bool running() const { return running_; }
    bool finished() const { return finished_; }
    const Plan& plan() const { return plan_; }
    std::size_t phase() const { return phase_; }   // current phase index while running
    std::size_t completed() const { return completed_; }
    const PhaseResult& result(std::size_t i) const { return results_[i < max_phases ? i : 0]; }
    const PhaseResult* results() const { return results_.data(); }

private:
    void begin_phase(std::uint64_t now_ms);
    void close_phase(std::uint64_t now_ms, const Counters&, const Sample&, PhaseFault forced);
    Plan plan_{};
    Mac bssid_{};
    bool running_{}, finished_{};
    std::size_t phase_{}, completed_{}, total_{};
    std::uint64_t phase_start_{}, measure_start_{};
    bool measuring_{};
    Counters at_measure_{};
    PhaseResult current_{};
    bool channel_seen_{};
    bool lock_marked_{};
    std::uint32_t lock_mark_{};       // Sample::lock_losses when the phase began
    std::array<PhaseResult, max_phases> results_{};
};

// Verdict rule (owner/supervisor may change the numbers; they are the proposal
// recorded with the spike, not calibrated facts).
struct Criteria {
    double max_beacon_loss{0.05};          // selected-AP beacons lost while scanning, vs the adjacent OFF phases
    std::uint32_t min_heap_bytes{20480};   // lowest free internal heap allowed during any scanning phase
    double max_extra_queue_full_per_min{1.0};
    double min_reference_delivery{0.5};    // OFF phases must hear >= half the beacons the AP announces
    std::uint32_t min_expected_beacons{500};   // per level, for a loss resolution near 1 %
    std::uint8_t min_pairs{2};             // valid OFF-ON-OFF triples per level
};

enum class Verdict : std::uint8_t { Acceptable, Unacceptable, Inconclusive };
const char* verdict_text(Verdict);   // "acceptable", "unacceptable", "inconclusive"

struct LevelReport {
    Duty duty{};
    Verdict verdict{Verdict::Inconclusive};
    const char* reason{"no_data"};
    std::uint32_t pairs{};
    std::uint32_t beacons_on{};
    double expected_on{};             // beacons the adjacent OFF rates predict for the ON time
    double beacon_ratio{};            // beacons_on / expected_on
    double frame_ratio{};             // same for all received frames (context, not a criterion)
    double adv_per_s{};
    double extra_queue_full_per_min{};
    std::uint32_t heap_min{};
};
struct Report {
    std::array<LevelReport, max_levels> levels{};
    std::uint8_t level_count{};
    Verdict overall{Verdict::Inconclusive};
    int best_level{-1};               // highest-duty acceptable level, -1 when none
    double reference_delivery{};      // OFF beacons / beacons announced (beacon interval), 0 when unknown
    std::uint32_t valid_phases{}, phases{};
};
// Evaluates the phases recorded so far (any prefix of a run).
// A level whose scanning phase lost the survey lock is unacceptable ("lock_lost":
// the Guardian went deaf for >= 5 s) when the OFF phase before was clean and the
// OFF phase after lost no lock of its own and was locked again at its end.
// Acceptable level: >= min_pairs valid triples, enough expected beacons, the
// reference hears the AP, loss <= max_beacon_loss, no extra queue drops beyond
// the limit, heap never below the floor. Overall: acceptable when any level is
// (best = the highest duty that is); unacceptable only when EVERY level was
// measured unacceptable (then the defense keeps Wi-Fi and BLE stays out);
// inconclusive otherwise.
Report evaluate(const Plan&, const PhaseResult* phases, std::size_t count, const Criteria& = Criteria{});

// Console lines (one line each, '\n' terminated). Return the length, 0 when it does not fit.
std::size_t phase_text(char*, std::size_t, const Plan&, std::size_t index, const PhaseResult&);
std::size_t level_text(char*, std::size_t, const LevelReport&);
std::size_t verdict_text(char*, std::size_t, const Report&, const Plan&, const Criteria&);

} // namespace guardian::coex

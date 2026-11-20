// Headless replay example for the portable contracts (G01), wired to the real
// G04 parser, the real G05 policy and (since G06) the real detectors. Built and
// run by the host harness (ctest `headless_replay_runs`), which asserts its
// final line.
//
// Wiring shown:
//   ReplaySource (FrameSource) -> SecurityFrameParser (FrameParser)
//   -> observe_security() -> Core (ObservationSink) -> present() -> StdoutStatus
//   -> DisconnectDetector / BaselineDetector (FrameDetector) -> Core::incident()
//
// Everything above the StdoutStatus is identical on a board. The only
// non-portable code in this file is <cstdio>, inside the output adapter.
// The replayed bytes are the hand-assembled fixture
// tests/fixtures/beacon_wpa3_sae_pmf_required.hex (Origin::Imported, no
// capture); the second frame is the same beacon with its RSN capabilities
// changed to PMF optional, the way a reconfigured AP would advertise it.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "guardian/capabilities.hpp"
#include "guardian/core.hpp"
#include "guardian/detector.hpp"
#include "guardian/detectors.hpp"
#include "guardian/output.hpp"
#include "guardian/parser.hpp"
#include "guardian/presenter.hpp"
#include "guardian/radio.hpp"
#include "guardian/rating.hpp"
#include "guardian/security_parser.hpp"
#include "guardian/time.hpp"

namespace {

using namespace guardian;

// Injected clock. Tests step it; nothing in the library reads time itself.
class FakeClock final : public MonotonicClock {
public:
    Millis now() const override { return now_; }
    TimeEpoch epoch() const override { return epoch_; }
    void advance(Millis ms) { now_ += ms; }
    void reboot() { ++epoch_.boot_id; now_ = 0; } // a new epoch: old Millis are not comparable
private:
    Millis now_{1000};
    TimeEpoch epoch_{{0x52, 0x45, 0x50, 0x4c, 0x41, 0x59}, 7}; // fixture-only identity
};

// One recorded frame: bytes as they would sit in the adapter pool, plus the
// metadata the adapter would have stamped.
struct RecordedFrame {
    std::array<std::uint8_t, 96> bytes{};
    std::uint16_t size{};
    std::uint8_t channel{};
    std::int8_t rssi{};
    Millis offset_ms{};      // when the frame is "received" relative to start
};

// tests/fixtures/beacon_wpa3_sae_pmf_required.hex: 77 bytes, FCS-free.
constexpr std::array<std::uint8_t, 77> kWpa3Beacon{
    0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x30, 0x12, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x64, 0x00, 0x11, 0x00, 0x00, 0x04, 0x68, 0x6f, 0x6d, 0x65, 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96,
    0x0c, 0x12, 0x18, 0x24, 0x03, 0x01, 0x06, 0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01,
    0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x08, 0xc0, 0x00};
constexpr std::size_t kRsnCapabilitiesOffset = 75; // little-endian RSN Capabilities field

// Replay FrameSource. Owns its storage (the "pool"); hands out copies.
class ReplaySource final : public FrameSource {
public:
    ReplaySource(const RecordedFrame* frames, std::size_t count, const MonotonicClock& clock, std::uint8_t channel)
        : frames_(frames), count_(count), clock_(clock), channel_(channel), start_(clock.now()), epoch_(clock.epoch()) {
        stats_.epoch = epoch_;
        stats_.listening_since = Instant{epoch_, start_, true};
    }
    bool next(FrameBuffer into, FrameSpan& span, RxMeta& meta) override {
        if (!into.data || !into.capacity || index_ >= count_ || clock_.epoch() != epoch_) return false;
        const RecordedFrame& f = frames_[index_];
        if (f.offset_ms > UINT64_MAX - start_ || clock_.now() < start_ + f.offset_ms) return false; // not yet "arrived"
        ++index_;
        ++stats_.received;
        const auto available = static_cast<std::uint16_t>(f.size < f.bytes.size() ? f.size : f.bytes.size());
        const std::uint16_t n = available < into.capacity ? available : into.capacity;
        for (std::uint16_t i = 0; i < n; ++i) into.data[i] = f.bytes[i];
        span.bytes = into.data; // span points into the CALLER's buffer
        span.size = n;
        span.truncated = n < f.size;
        if (span.truncated) ++stats_.truncated;
        meta = RxMeta{};
        meta.acquired = Instant{epoch_, start_ + f.offset_ms, true}; // preserve acquisition, including queue delay
        meta.processed = Instant{epoch_, clock_.now(), true};
        meta.band = Band::Ghz2_4;
        meta.channel = f.channel;
        meta.rssi_dbm = f.rssi;
        meta.rssi_valid = true;
        meta.status = RxStatus::Ok;
        meta.reported_length = static_cast<std::uint16_t>(f.size <= UINT16_MAX - 4 ? f.size + 4 : UINT16_MAX); // as a driver would (incl. FCS)
        meta.origin = Origin::Imported; // replay is never live evidence
        ++stats_.delivered;
        return true;
    }
    AcquisitionStats stats() const override { return stats_; }
    Band current_band() const override { return Band::Ghz2_4; }
    std::uint8_t current_channel() const override { return channel_; }
    // The adapter's listening report for Core::coverage(): tuned, no drops.
    CoverageReport coverage() const {
        CoverageReport c{};
        c.sampled_at = Instant{epoch_, clock_.now(), true};
        c.band = Band::Ghz2_4;
        c.channel = channel_;
        c.window_ms = 10000;
        c.listened_ms = 10000;
        c.dropped_in_window = stats_.dropped_queue_full;
        c.passive_receive = Support::Unsupported; // replay is not RF reception
        return c;
    }
private:
    const RecordedFrame* frames_;
    std::size_t count_;
    const MonotonicClock& clock_;
    std::uint8_t channel_;
    std::size_t index_{};
    Millis start_{};
    TimeEpoch epoch_{};
    AcquisitionStats stats_{};
};

// Output adapter: the only place that formats for a human. On a board this is
// the canvas renderer; here it is one printf line.
class StdoutStatus final : public StatusOutput {
public:
    void show(const ViewModel& v, const Snapshot& s, Millis now) override {
        std::printf("t=%llu face=%d overlay=%d finding=%d unrated=%d age=%llu historical=%d record_historical=%d incident=%d "
                    "bssid=%02X:%02X:%02X:%02X:%02X:%02X\n",
                    static_cast<unsigned long long>(now), static_cast<int>(v.face), static_cast<int>(v.overlay),
                    static_cast<int>(v.explanation), static_cast<int>(s.settings.unrated),
                    static_cast<unsigned long long>(v.age_ms), v.historical, s.security_historical, v.incident_visible,
                    s.selected.bssid[0], s.selected.bssid[1], s.selected.bssid[2], s.selected.bssid[3], s.selected.bssid[4], s.selected.bssid[5]);
    }
    const DisplayCapabilities& display() const override { return caps_; }
private:
    DisplayCapabilities caps_{Support::Unsupported, 0, 0, PixelFormat::None, Support::Unsupported};
};

} // namespace

int main() {
    using namespace guardian;
    FakeClock clock;
    const BoardCapabilities caps = profiles::headless(profiles::all_2g4_channels(), 96);

    // Selected network: identity by raw bytes, never by a display string.
    Network home{};
    home.bssid = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const char* name = "home";
    for (std::uint8_t i = 0; i < 4; ++i) home.ssid[i] = static_cast<std::uint8_t>(name[i]);
    home.ssid_size = 4;

    // Two recorded beacons: WPA3-SAE with PMF required, then the same AP
    // reconfigured to PMF optional (RSN Capabilities 0x00c0 -> 0x0080).
    RecordedFrame frames[2]{};
    for (std::size_t i = 0; i < kWpa3Beacon.size(); ++i) frames[0].bytes[i] = kWpa3Beacon[i];
    frames[0].size = static_cast<std::uint16_t>(kWpa3Beacon.size());
    frames[0].channel = 6;
    frames[0].rssi = -51;
    frames[0].offset_ms = 0;
    frames[1] = frames[0];
    frames[1].bytes[kRsnCapabilitiesOffset] = 0x80; // MFPC only
    frames[1].offset_ms = 5000;

    // Replay is Imported evidence; the core is told so and will label it historical.
    Core core(clock, caps.radio.channels, Origin::Imported);
    core.select(home);
    ReplaySource source(frames, 2, clock, 6);
    const SecurityFrameParser parser;
    StdoutStatus out;

    // G06 detectors over the same frames. The owner's explicit baseline is the
    // first beacon's advertised settings on channel 6 (as a picker would offer
    // it for approval); nothing is learned from the replayed traffic itself.
    // This replay has no disconnect frames and only the selected BSSID, so no
    // incident is expected (the ctest pattern asserts incident=0); the PMF
    // change in the second beacon is a SettingsChanged observation only after
    // change_threshold (2) differing advertisements, which one beacon is not.
    ApprovedScope scope;
    {
        ApprovedAp approved{};
        approved.network = home;
        RxMeta first{};
        first.status = RxStatus::Ok;
        const ParseResult baseline = parser.parse(FrameSpan{kWpa3Beacon.data(), static_cast<std::uint16_t>(kWpa3Beacon.size()), false}, first);
        approved.settings_known = baseline.status == ParseStatus::Complete;
        approved.settings = SettingsFingerprint::of(baseline.settings);
        approved.channel_known = true;
        approved.band = Band::Ghz2_4;
        approved.channel = 6;
        scope.select(approved);
    }
    DisconnectDetector disconnects(scope, DetectorLimits{});
    BaselineDetector baselines(scope, DetectorLimits{});
    if (!disconnects.configured() || !baselines.configured()) {
        std::printf("detector configuration refused\n");
        return 2;
    }

    std::array<std::uint8_t, 96> slot{}; // caller-owned FrameBuffer storage, capacity = caps.radio.max_frame_bytes
    for (int step = 0; step < 8; ++step) {
        if (step == 6) {
            clock.reboot(); // timebase change: everything held becomes historical
            disconnects.reset(); // detector windows belong to one epoch
            baselines.reset();
        }
        FrameSpan span{};
        RxMeta meta{};
        while (source.next(FrameBuffer{slot.data(), static_cast<std::uint16_t>(slot.size())}, span, meta)) {
            const ParseResult parsed = parser.parse(span, meta); // span valid only here
            core.security(observe_security(parsed, meta));
            core.signal(observe_signal(parsed, meta));
            disconnects.on_frame(span, meta, parsed, core); // incidents go to Core through ObservationSink
            baselines.on_frame(span, meta, parsed, core);
        }
        const CoverageReport listening = source.coverage();
        core.coverage(listening);
        disconnects.coverage(listening);
        const Instant now{clock.epoch(), clock.now(), true};
        disconnects.on_tick(now, core);
        baselines.on_tick(now, core);
        const Snapshot snap = core.snapshot();
        out.show(present(snap), snap, clock.now());
        clock.advance(10000); // 10 s per step: evidence goes stale after Core::fresh_ms
    }
    return 0;
}

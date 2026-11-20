// G12 qualification of EXISTING behavior, not retrospective TDD or RF evidence.
// The identical checks execute on the host and link into each native IDF probe.
// This file uses no SDK, filesystem, renderer or dynamically allocated fixtures.
#include "guardian/advice.hpp"
#include "guardian/detectors.hpp"
#include "guardian/rating.hpp"
#include "guardian/security_parser.hpp"
#ifdef GUARDIAN_QUALIFY_PRESENTER
#include "guardian/presenter.hpp"
#endif
#include <cstdio>

namespace {
using namespace guardian;
struct Clock final : MonotonicClock {
    Millis at{1000};
    Millis now() const override { return at; }
    TimeEpoch epoch() const override { return {{1}, 1}; }
};
struct Checks {
    unsigned count{}, failed{};
    void expect(bool ok, const char* expression, int line) {
        ++count;
        if (!ok) { ++failed; std::printf("FAIL line=%d %s\n", line, expression); }
    }
};
#define EXPECT(expr) checks.expect((expr), #expr, __LINE__)

// Exact bytes of tests/fixtures/beacon_wpa3_sae_pmf_required.hex: original,
// hand-assembled synthetic beacon; no capture and no third-party implementation.
constexpr std::uint8_t beacon[]{
    0x80,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,2,0x11,0x22,0x33,0x44,0x55,
    2,0x11,0x22,0x33,0x44,0x55,0x30,0x12,0x33,0x22,0x11,0,0,0,0,0,
    0x64,0,0x11,0,0,4,0x68,0x6f,0x6d,0x65,1,8,0x82,0x84,0x8b,0x96,
    0x0c,0x12,0x18,0x24,3,1,6,0x30,0x14,1,0,0,0x0f,0xac,4,1,0,0,
    0x0f,0xac,4,1,0,0,0x0f,0xac,8,0xc0,0
};

void exercise(Checks& checks, unsigned profile) {
    auto caps = profiles::headless(profiles::all_2g4_channels(), 512);
    caps.board_name = "synthetic-headless";
    if (profile == 1) {
        caps.board_name = "synthetic-display-no-psram";
        caps.memory.internal_ram_bytes = 320 * 1024;
        caps.display = {Support::Supported, 240, 32, PixelFormat::Rgb565, Support::Unsupported};
    } else if (profile == 2) {
        caps.board_name = "synthetic-dual-band";
        caps.radio.channels.set(Band::Ghz5, 36);
    }
    EXPECT(caps.memory.external_ram_bytes == 0);
    EXPECT(caps.radio.passive_receive == Support::Unsupported);
    EXPECT(caps.radio.channels.any(Band::Ghz5) == (profile == 2));
    EXPECT(!caps.radio.channels.any(Band::Ghz6));
    Clock clock;
    RxMeta meta{};
    meta.origin = Origin::Imported;
    meta.status = RxStatus::Ok;
    meta.acquired = {clock.epoch(), clock.now(), true};
    meta.band = Band::Ghz2_4;
    meta.channel = 6;
    SecurityFrameParser parser;
    const auto parsed = parser.parse({beacon, sizeof beacon, false}, meta);
    EXPECT(parsed.status == ParseStatus::Complete);
    Core core(clock, caps.radio.channels, Origin::Imported);
    EXPECT(core.select(parsed.identity));
    EXPECT(core.snapshot().settings.mood == Mood::Unknown);
    core.security(observe_security(parsed, meta));
    EXPECT(core.snapshot().settings.mood == Mood::VeryGood);
    EXPECT(advise(core.snapshot()).password_strength == Verification::NotMeasured);

    // Synthetic tuned-channel metadata, not a 5 GHz capture. The DS IE remains
    // channel 6; Core validates the receiver's band/channel, not that IE.
    auto reading = observe_security(parsed, meta);
    reading.band = Band::Ghz5;
    reading.channel = 36;
    EXPECT(core.select(parsed.identity));
    core.security(reading);
    EXPECT(core.snapshot().has_security == (profile == 2));
    EXPECT(core.snapshot().rejected.channel == (profile == 2 ? 0u : 1u));
    reading.band = Band::Ghz2_4; // channel 36 must not alias across bands
    core.security(reading);
    EXPECT(core.snapshot().rejected.channel == (profile == 2 ? 1u : 2u));
    EXPECT(core.select(parsed.identity));
    core.security(observe_security(parsed, meta));

    // Scope and disconnect behavior exercise the detector object file too.
    ApprovedScope scope;
    ApprovedAp approved{};
    approved.network = parsed.identity;
    EXPECT(scope.select(approved));
    DetectorLimits limits{};
    limits.burst_threshold = 2;
    DisconnectDetector detector(scope, limits);
    std::uint8_t disconnect[]{0xc0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,
        2,0x11,0x22,0x33,0x44,0x55,2,0x11,0x22,0x33,0x44,0x55,0,0,7,0};
    for (unsigned i = 0; i != 2; ++i) {
        disconnect[22] = static_cast<std::uint8_t>(i * 16);
        FrameSpan frame{disconnect, sizeof disconnect, false};
        detector.on_frame(frame, meta, parser.parse(frame, meta), core);
    }
    EXPECT(core.snapshot().incidents[static_cast<unsigned>(IncidentKind::DisconnectBurst)]);

#ifdef GUARDIAN_QUALIFY_PRESENTER
    Presenter presenter(caps.display, Origin::Imported);
    presenter.update(core.snapshot(), meta.acquired, &scope);
    EXPECT(presenter.view().historical);
    EXPECT(!presenter.view().animate);
    EXPECT(presenter.view().incident_visible);
    EXPECT(presenter.handle(Action::Primary, meta.acquired));
    EXPECT(presenter.details().rows == (profile == 1 ? 4 : 0));
    EXPECT(presenter.handle(Action::Primary, meta.acquired));
    if (profile != 1) EXPECT(presenter.details().item_count == presenter.details().advice.count);
#endif
    clock.at += Core::fresh_ms;
    EXPECT(core.snapshot().settings.mood == Mood::Unknown);
    EXPECT(core.snapshot().coverage == Coverage::Stale);
#ifdef GUARDIAN_QUALIFY_PRESENTER
    presenter.update(core.snapshot(), {clock.epoch(), clock.now(), true}, &scope);
    EXPECT(presenter.view().face == Mood::Unknown);
    EXPECT(!presenter.view().celebrate);
#endif
    std::printf("PROFILE %s checks=%u failures=%u origin=imported rf=unverified\n",
                caps.board_name, checks.count, checks.failed);
}
} // namespace

int guardian_profile_checks() {
    Checks checks;
    for (unsigned profile = 0; profile != 3; ++profile) exercise(checks, profile);
    std::printf("G12 RESULT checks=%u failures=%u\n", checks.count, checks.failed);
    return checks.count > 0 && checks.failed == 0 ? 0 : 1;
}

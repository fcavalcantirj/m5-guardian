// G01 contract checks (G03 target `guardian_contracts`).
//
// These exercise the documented contracts of the portable headers with
// counterexamples: what MUST be rejected or stay Unknown, not only what passes.
// They are value-type checks on headers; they do not claim parser, detector or
// radio behavior (G04-G08, L02). Every public core/presenter header is included
// so a dependency on an SDK header would fail this build on the host.
#include "check.hpp"

#include "guardian/capabilities.hpp"
#include "guardian/core.hpp"
#include "guardian/detector.hpp"
#include "guardian/identity.hpp"
#include "guardian/output.hpp"
#include "guardian/parser.hpp"
#include "guardian/presenter.hpp"
#include "guardian/radio.hpp"
#include "guardian/rating.hpp"
#include "guardian/time.hpp"

#include <type_traits>

using namespace guardian;

// ---- compile-time contracts -------------------------------------------------
static_assert(std::is_same_v<Millis, std::uint64_t>, "Millis is 64-bit so windows never wrap in practice");
static_assert(std::is_same_v<Parse, ParseStatus>, "legacy alias must point at the typed ParseStatus");
static_assert(SuiteList::capacity == 16, "docs/contracts.md section 7: 16 selectors per list");
static_assert(sizeof(Mac) == 6 && std::tuple_size_v<decltype(Network::ssid)> == 32, "identity sizes");
static_assert(static_cast<std::size_t>(Band::Count) == 3 && ChannelSet::words_per_band == 4, "3 bands x 256 bits");
static_assert((akm::Unknown & (akm::Sae | akm::Psk | akm::Owe)) == 0, "Unknown is a distinct bit");
static_assert((cipher::Unknown & (cipher::Tkip | cipher::Ccmp128 | cipher::Gcmp128)) == 0, "Unknown is a distinct bit");
static_assert(Support::Unknown != Support::Supported && Support::Unsupported != Support::Supported, "tri-state");
static_assert(std::is_trivially_copyable_v<RxMeta> && std::is_trivially_copyable_v<ParseResult>
              && std::is_trivially_copyable_v<SecurityObservation> && std::is_trivially_copyable_v<Snapshot>,
              "results are plain values with no pointers into frames");
static_assert(std::is_abstract_v<FrameSource> && std::is_abstract_v<FrameParser> && std::is_abstract_v<FrameDetector>
              && std::is_abstract_v<MonotonicClock> && std::is_abstract_v<StatusOutput> && std::is_abstract_v<CoverageSource>,
              "adapter boundaries are interfaces");
static_assert(std::is_final_v<Core> && std::is_base_of_v<ObservationSink, Core>, "Core is the single sink");
// Wire selector encoding: OUI in the upper 24 bits, suite type in the low 8.
static_assert((0x000fac04u >> 8) == 0x000fac && (0x000fac04u & 0xff) == 4, "selector encoding example");

// ---- time -------------------------------------------------------------------
GUARDIAN_CASE(time_epoch_default_is_invalid_and_nonzero_source_is_valid) {
    TimeEpoch none{};
    CHECK(!none.valid());
    TimeEpoch only_boot{};
    only_boot.boot_id = 5;
    CHECK(!only_boot.valid()); // boot counter alone does not identify a timebase
    TimeEpoch src{};
    src.source_id[15] = 1;
    CHECK(src.valid());
}

GUARDIAN_CASE(time_epoch_equality_needs_same_source_and_boot) {
    TimeEpoch a{};
    a.source_id[0] = 7;
    a.boot_id = 1;
    TimeEpoch b = a;
    CHECK(a == b);
    b.boot_id = 2; // reboot: Millis no longer comparable
    CHECK(a != b);
    TimeEpoch c = a;
    c.source_id[1] = 1; // other device, same boot counter
    CHECK(a != c);
}

GUARDIAN_CASE(instant_valid_only_when_known_and_epoch_valid) {
    Instant unknown{};
    CHECK(!unknown.valid());
    TimeEpoch e{};
    e.source_id[0] = 1;
    Instant known_bad_epoch{TimeEpoch{}, 100, true};
    CHECK(!known_bad_epoch.valid());
    Instant unknown_good_epoch{e, 100, false};
    CHECK(!unknown_good_epoch.valid());
    Instant zero_time{e, 0, true};
    CHECK(zero_time.valid()); // zero is a legal instant when explicitly known
}

GUARDIAN_CASE(wall_clock_defaults_to_unknown_support) {
    WallClock w{};
    CHECK_EQ(w.support, Support::Unknown);
    CHECK_EQ(w.uncertainty_ms, 0u); // 0 means "not estimated", not exact
}

// ---- capabilities -----------------------------------------------------------
GUARDIAN_CASE(channel_set_tracks_channels_per_band_without_aliasing) {
    ChannelSet s{};
    CHECK(s.empty());
    s.set(Band::Ghz5, 36);
    CHECK(s.contains(Band::Ghz5, 36));
    CHECK(!s.contains(Band::Ghz2_4, 36));
    CHECK(!s.contains(Band::Ghz6, 36));
    CHECK(s.any(Band::Ghz5));
    CHECK(!s.any(Band::Ghz2_4));
    CHECK(!s.empty());
    s.set(Band::Ghz6, 233); // highest 6 GHz number, lives in the 4th word
    CHECK(s.contains(Band::Ghz6, 233));
    s.set(Band::Ghz2_4, 255); // top of uint8 range stays in bounds
    CHECK(s.contains(Band::Ghz2_4, 255));
    CHECK(!s.contains(Band::Count, 1));  // out-of-range band is false, not UB
    s.set(Band::Count, 1);                 // ignored, no write out of bounds
    CHECK(!s.contains(Band::Count, 1));
}

GUARDIAN_CASE(all_2g4_channels_is_exactly_1_to_14) {
    const ChannelSet s = profiles::all_2g4_channels();
    for (std::uint8_t ch = 1; ch <= 14; ++ch) CHECK(s.contains(Band::Ghz2_4, ch));
    CHECK(!s.contains(Band::Ghz2_4, 0));
    CHECK(!s.contains(Band::Ghz2_4, 15));
    CHECK(!s.any(Band::Ghz5));
    CHECK(!s.any(Band::Ghz6));
}

GUARDIAN_CASE(headless_profile_reports_no_physical_radio_display_or_input) {
    ChannelSet ch{};
    ch.set(Band::Ghz2_4, 6);
    const BoardCapabilities c = profiles::headless(ch, 512);
    CHECK_EQ(c.radio.passive_receive, Support::Unsupported); // replay is not RF reception
    CHECK_EQ(c.radio.channel_hop, Support::Unsupported);
    CHECK_EQ(c.radio.max_frame_bytes, 512);
    CHECK(c.radio.channels.contains(Band::Ghz2_4, 6));
    CHECK(!c.radio.channels.contains(Band::Ghz2_4, 1));
    CHECK_EQ(c.radio.rx_timestamp, Support::Unsupported);
    CHECK_EQ(c.radio.fcs_error_delivery, Support::Unsupported);
    CHECK_EQ(c.display.present, Support::Unsupported);
    CHECK_EQ(c.display.animation, Support::Unsupported);
    for (auto s : c.input.controls) CHECK_EQ(s, Support::Unsupported);
    CHECK_EQ(c.input.touch, Support::Unsupported);
    CHECK_EQ(c.ble.present, Support::Unsupported);
    CHECK_EQ(c.storage.key_value, Support::Unsupported);
    CHECK_EQ(c.storage.removable_media, Support::Unsupported);
    CHECK_EQ(c.memory.external_ram_bytes, 0u); // PSRAM never assumed
}

GUARDIAN_CASE(default_capabilities_are_unknown_not_supported) {
    const BoardCapabilities c{};
    CHECK_EQ(c.radio.passive_receive, Support::Unknown);
    CHECK_EQ(c.display.present, Support::Unknown);
    CHECK_EQ(c.ble.observer, Support::Unknown);
    CHECK(c.radio.channels.empty());
    CHECK_EQ(c.radio.max_frame_bytes, 0);
}

// ---- identity ---------------------------------------------------------------
namespace {
Network make_network(const char* ssid, std::uint8_t last_bssid_byte = 0x55) {
    Network n{};
    n.bssid = {0x02, 0x11, 0x22, 0x33, 0x44, last_bssid_byte};
    std::uint8_t i = 0;
    for (; ssid[i] && i < 32; ++i) n.ssid[i] = static_cast<std::uint8_t>(ssid[i]);
    n.ssid_size = i;
    return n;
}
} // namespace

GUARDIAN_CASE(network_equality_is_byte_identity) {
    const Network a = make_network("home");
    CHECK(a == a);
    CHECK(a == make_network("home"));
    CHECK(!(a == make_network("Home")));          // one byte differs
    CHECK(!(a == make_network("hom")));           // shorter, shared prefix
    CHECK(!(a == make_network("home", 0x56)));    // same SSID bytes, other BSSID
    Network trailing = a;
    trailing.ssid[10] = 0xAA;                     // bytes beyond ssid_size are not identity
    CHECK(a == trailing);
    Network binary = a;
    binary.ssid[0] = 0x00;                        // control/zero byte is still identity, not trimmed
    CHECK(!(a == binary));
    Network longer = a;
    longer.ssid_size = 5;                         // same first 4 bytes and a zero 5th byte in BOTH arrays:
    CHECK(!(a == longer));                        // length alone is identity (mutant check: dropping the
    CHECK(!(longer == a));                        // ssid_size comparison must fail here, in both directions)
}

GUARDIAN_CASE(network_equality_rejects_oversized_length_instead_of_overreading) {
    Network a = make_network("home");
    Network b = a;
    a.ssid_size = 33;
    b.ssid_size = 33;
    CHECK(!(a == b)); // never compares 33 bytes of a 32-byte array
}

// ---- parser result semantics --------------------------------------------------
GUARDIAN_CASE(parse_result_default_is_unrelated_with_nothing_trusted) {
    const ParseResult r{};
    CHECK_EQ(r.status, ParseStatus::Unrelated);
    CHECK_EQ(r.error, ParseError::None);
    CHECK(!r.header_valid);
    CHECK(!r.settings_present);
    CHECK(!r.settings_complete);
    CHECK(!r.reason_readable);
    CHECK_EQ(r.ssid_kind, SsidKind::Absent);
    CHECK_EQ(r.settings.rsn.state, ElementState::Absent);
    CHECK_EQ(r.settings.wpa.state, ElementState::Absent);
    CHECK_EQ(r.settings.rsn.pmf, Pmf::Unknown);
    CHECK(!r.settings.privacy_valid);
}

GUARDIAN_CASE(suite_list_marks_unknown_without_dropping_known_bits) {
    SuiteList l{};
    l.selectors[0] = 0x000fac04; // CCMP-128
    l.selectors[1] = 0x00123401; // vendor selector nobody maps
    l.count = 2;
    l.kinds = cipher::Ccmp128 | cipher::Unknown;
    CHECK((l.kinds & cipher::Ccmp128) != 0);
    CHECK((l.kinds & cipher::Unknown) != 0);
    CHECK(l.count <= SuiteList::capacity);
    CHECK_EQ(l.selectors[1] >> 8, 0x001234u);
    CHECK_EQ(l.selectors[1] & 0xffu, 1u);
}

// ---- observations and core policy on unknown input ----------------------------
GUARDIAN_CASE(default_security_observation_cannot_grade) {
    const SecurityObservation s{};
    CHECK_EQ(s.parse, Parse::Unsupported);
    CHECK(!s.acquired.valid());
    CHECK(!s.settings_present);
    CHECK(!s.settings_complete);
    CHECK_EQ(s.rx_status, RxStatus::Unknown);
    const Assessment a = assess(s);
    CHECK_EQ(a.mood, Mood::Unknown);
    CHECK_EQ(a.reason, Finding::Unknown);
    CHECK_EQ(a.unrated, Unrated::Incomplete);
    CHECK_EQ(a.mode, Mode::Unknown);
}

GUARDIAN_CASE(incomplete_parse_never_grades_even_with_strong_fields) {
    SecurityObservation s{};
    s.kind = FrameKind::Beacon;
    s.rx_status = RxStatus::Ok;
    s.settings_present = true;
    s.settings_complete = true;
    s.settings.privacy_valid = true;
    s.settings.privacy_bit = true;
    s.settings.rsn.state = ElementState::Valid;
    s.settings.rsn.akms = SuiteList{{0x000fac08}, 1, akm::Sae};
    s.settings.rsn.pairwise = SuiteList{{0x000fac04}, 1, cipher::Ccmp128};
    s.settings.rsn.group = SuiteSelector{0x000fac04, cipher::Ccmp128, true};
    s.settings.rsn.group_management = SuiteSelector{0x000fac06, cipher::BipCmac128, false};
    s.settings.rsn.pmf = Pmf::Required;
    for (Parse p : {Parse::Unsupported, Parse::Malformed, Parse::Truncated, Parse::Unrelated}) {
        s.parse = p;
        CHECK_EQ(assess(s).mood, Mood::Unknown);
        CHECK_EQ(assess(s).unrated, Unrated::Incomplete);
    }
    s.parse = Parse::Complete;
    CHECK_EQ(assess(s).mood, Mood::VeryGood); // the same fields grade once Complete
    CHECK_EQ(assess(s).unrated, Unrated::None);
}

GUARDIAN_CASE(snapshot_default_is_checking_with_no_incidents) {
    const Snapshot s{};
    CHECK_EQ(s.coverage, Coverage::Checking);
    CHECK(!s.has_security);
    CHECK(!s.security_historical);
    CHECK(!s.has_signal);
    CHECK(!s.has_coverage);
    CHECK_EQ(s.rejected.future, 0u);
    CHECK_EQ(s.settings.mood, Mood::Unknown);
    for (bool b : s.incidents) CHECK(!b);
    CHECK_EQ(s.incidents.size(), static_cast<std::size_t>(IncidentKind::Count));
}

// ---- radio / detector value contracts ------------------------------------------
GUARDIAN_CASE(rx_meta_defaults_are_unknown_and_invalid) {
    const RxMeta m{};
    CHECK(!m.acquired.valid());
    CHECK(!m.rssi_valid);
    CHECK(!m.noise_floor_valid);
    CHECK(!m.radio_timestamp_valid);
    CHECK_EQ(m.status, RxStatus::Unknown);
    CHECK_EQ(m.secondary, SecondaryChannel::Unknown);
    CHECK_EQ(m.origin, Origin::LiveRadio);
    const FrameSpan f{};
    CHECK(f.bytes == nullptr);
    CHECK_EQ(f.size, 0);
    CHECK(!f.truncated);
}

GUARDIAN_CASE(detector_limits_carry_the_documented_uncalibrated_defaults) {
    const DetectorLimits d{};
    CHECK_EQ(d.max_tracked_sources, 64);
    CHECK_EQ(d.max_approved_aps, 8);
    CHECK_EQ(d.window_ms, 10000u);
    CHECK_EQ(d.cooldown_ms, 45000u);
    // A persisting condition is re-reported before its incident stops being shown:
    // 15 s margin for re-detection while hopping channels (G14 board finding).
    CHECK(Millis{d.cooldown_ms} + 15000 <= Core::incident_ms);
    CHECK_EQ(d.burst_threshold, 20u);
    const CoverageReport c{};
    CHECK(!c.sampled_at.valid());
    CHECK_EQ(c.passive_receive, Support::Unknown);
    CHECK_EQ(c.channel, 0); // 0 = not listening
}

GUARDIAN_CASE(core_fresh_and_incident_windows_match_documented_policy) {
    // G13 owner requirement (2026-11-15): the SCREEN must show "No fresh data" within
    // 30 s of the AP turning off. Expiry counts from the last advertisement (at or
    // before AP off); 29 s leaves ~1 s for the deadline redraw and scheduling.
    CHECK_EQ(Core::fresh_ms, Millis{29000});
    CHECK_EQ(Core::incident_ms, Millis{60000});
}

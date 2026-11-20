// G05 rating policy checks (TDD: written and run RED against a stub assess()
// first; see docs/G05-rating-freshness.md for the recorded run).
//
// Two kinds of case: fixture-driven (the real SecurityFrameParser decodes a
// hand-assembled Origin::Imported fixture, observe_security() reduces it, and
// assess() rates it) and hand-built AdvertisedSettings combinations for rows the
// fixtures do not carry. Nothing here is radio proof and no mood here is a
// claim about a real network.
#include "check.hpp"
#include "fixtures.hpp"

#include "guardian/rating.hpp"
#include "guardian/security_parser.hpp"

#include <string>

using namespace guardian;
using guardian::fixtures::Fixture;

namespace {

const SecurityFrameParser parser{};

TimeEpoch test_epoch() {
    TimeEpoch e{};
    e.source_id = {0x47, 0x30, 0x35, 0x2d, 0x74, 0x65, 0x73, 0x74}; // "G05-test", fixture-only identity
    e.boot_id = 1;
    return e;
}

RxMeta ok_meta(Millis at = 1000) {
    RxMeta m{};
    m.acquired = Instant{test_epoch(), at, true};
    m.status = RxStatus::Ok;
    m.origin = Origin::Imported;
    m.band = Band::Ghz2_4;
    m.channel = 6;
    m.rssi_dbm = -51;
    m.rssi_valid = true;
    return m;
}

bool load(check::Case& c_, const char* name, Fixture& f) {
    std::string err;
    if (fixtures::load(name, f, err)) return true;
    CHECK_FAIL(err);
    return false;
}

// Parse a fixture with the real parser and reduce it. `meta` lets a case vary the adapter metadata.
bool observe(check::Case& c_, const char* name, SecurityObservation& out, RxMeta meta = ok_meta()) {
    Fixture f;
    if (!load(c_, name, f)) return false;
    const FrameSpan span{f.bytes.data(), static_cast<std::uint16_t>(f.bytes.size()), false};
    out = observe_security(parser.parse(span, meta), meta);
    return true;
}

// ---- hand-built settings -----------------------------------------------------------------
SuiteList list(std::uint16_t kinds, std::uint8_t count = 1) {
    SuiteList l{};
    l.count = count;
    l.kinds = kinds;
    for (std::uint8_t i = 0; i < count; ++i) l.selectors[i] = 0x000fac00u | i; // raw values irrelevant to policy
    return l;
}
SuiteSelector sel(std::uint16_t kind, bool present = true) { return SuiteSelector{0x000fac04u, kind, present}; }

SecurityElement rsn(std::uint16_t akms, std::uint16_t pairwise, std::uint16_t group, Pmf pmf,
                    std::uint16_t group_mgmt = cipher::BipCmac128) {
    SecurityElement e{};
    e.state = ElementState::Valid;
    e.akms = list(akms);
    e.pairwise = list(pairwise);
    e.group = sel(group);
    e.group_management = sel(group_mgmt, false);
    e.pmf = pmf;
    return e;
}
SecurityElement wpa(std::uint16_t akms = akm::Wpa1Psk, std::uint16_t pairwise = cipher::Tkip, std::uint16_t group = cipher::Tkip) {
    SecurityElement e{};
    e.state = ElementState::Valid;
    e.akms = list(akms);
    e.pairwise = list(pairwise);
    e.group = sel(group);
    e.pmf = Pmf::Unknown; // never attributed to WPA by the parser
    return e;
}

SecurityObservation complete(const AdvertisedSettings& a, bool privacy = true) {
    SecurityObservation s{};
    s.network.bssid = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    s.ssid_kind = SsidKind::Present;
    s.acquired = Instant{test_epoch(), 1000, true};
    s.origin = Origin::Imported;
    s.channel = 6;
    s.rx_status = RxStatus::Ok;
    s.kind = FrameKind::Beacon;
    s.parse = ParseStatus::Complete;
    s.settings_present = true;
    s.settings_complete = true;
    s.settings = a;
    s.settings.privacy_valid = true;
    s.settings.privacy_bit = privacy;
    return s;
}
SecurityObservation with_rsn(const SecurityElement& e, bool privacy = true) {
    AdvertisedSettings a{};
    a.rsn = e;
    return complete(a, privacy);
}

void expect_rated(check::Case& c_, const Assessment& a, Mood mood, Finding reason) {
    CHECK_EQ(a.mood, mood);
    CHECK_EQ(a.reason, reason);
    CHECK_EQ(a.unrated, Unrated::None);
}
void expect_unrated(check::Case& c_, const Assessment& a, Unrated why) {
    CHECK_EQ(a.mood, Mood::Unknown);
    CHECK_EQ(a.unrated, why);
}

} // namespace

// ---- the five moods through the real parser ---------------------------------------------
GUARDIAN_CASE(fixture_wpa3_sae_pmf_required_is_very_good) {
    SecurityObservation s;
    if (!observe(c_, "beacon_wpa3_sae_pmf_required", s)) return;
    CHECK_EQ(s.parse, ParseStatus::Complete);
    CHECK(s.settings_complete);
    const Assessment a = assess(s);
    expect_rated(c_, a, Mood::VeryGood, Finding::StrongSettings);
    CHECK(!a.legacy_risk);
    CHECK_EQ(a.mode, Mode::Wpa3Personal);
    CHECK_EQ(a.pairwise, Cipher::Ccmp);
    CHECK_EQ(a.group, Cipher::Ccmp);
    CHECK_EQ(a.pmf, Pmf::Required);
}

GUARDIAN_CASE(fixture_wpa3_with_pmkid_and_group_management_is_very_good) {
    SecurityObservation s;
    if (!observe(c_, "beacon_rsn_pmkid_group_mgmt", s)) return;
    expect_rated(c_, assess(s), Mood::VeryGood, Finding::StrongSettings);
}

GUARDIAN_CASE(fixture_wpa2_ccmp_pmf_optional_is_medium_with_pmf_finding) {
    SecurityObservation s;
    if (!observe(c_, "beacon_wpa2_ccmp_pmf_optional", s)) return;
    const Assessment a = assess(s);
    expect_rated(c_, a, Mood::Medium, Finding::PmfNotRequired);
    CHECK(!a.legacy_risk);
    CHECK_EQ(a.mode, Mode::Wpa2Personal);
    CHECK_EQ(a.pmf, Pmf::Optional);
}

GUARDIAN_CASE(fixture_probe_response_hidden_ssid_ht_control_and_later_empty_ie_all_rate_medium) {
    // The rating depends on the advertised settings only: frame subtype, SSID
    // visibility, header length and unrelated elements change nothing.
    for (const char* name : {"probe_response_wpa2", "beacon_hidden_ssid_wpa2",
                             "beacon_later_empty_ie_then_rsn", "beacon_ssid_non_utf8"}) {
        SecurityObservation s;
        if (!observe(c_, name, s)) continue;
        const Assessment a = assess(s);
        if (a.mood != Mood::Medium) CHECK_FAIL(std::string(name) + ": expected Medium");
        CHECK_EQ(a.reason, Finding::PmfNotRequired);
    }
}

GUARDIAN_CASE(review_ht_control_fixture_preserves_privacy_and_rating) {
    SecurityObservation s;
    if (!observe(c_, "beacon_ht_control_order_bit", s)) return;
    CHECK_EQ(s.parse, ParseStatus::Complete);
    CHECK(s.settings.privacy_valid);
    CHECK(s.settings.privacy_bit);
    CHECK_EQ(s.settings.rsn.state, ElementState::Valid);
    expect_rated(c_, assess(s), Mood::Medium, Finding::PmfNotRequired);
}

GUARDIAN_CASE(fixture_wpa2_mixed_tkip_is_bad_legacy_not_medium) {
    SecurityObservation s;
    if (!observe(c_, "beacon_wpa2_mixed_tkip", s)) return;
    const Assessment a = assess(s);
    expect_rated(c_, a, Mood::Bad, Finding::Legacy);
    CHECK(a.legacy_risk);
    CHECK_EQ(a.mode, Mode::Wpa2Personal);
    CHECK_EQ(a.pairwise, Cipher::Tkip); // weakest advertised pairwise option, not the CCMP one
    CHECK_EQ(a.group, Cipher::Tkip);
    CHECK_EQ(a.pmf, Pmf::Disabled);
}

GUARDIAN_CASE(fixture_wpa1_tkip_vendor_is_bad_legacy) {
    SecurityObservation s;
    if (!observe(c_, "beacon_wpa1_tkip_vendor", s)) return;
    const Assessment a = assess(s);
    expect_rated(c_, a, Mood::Bad, Finding::Legacy);
    CHECK(a.legacy_risk);
    CHECK_EQ(a.mode, Mode::Wpa1);
    CHECK_EQ(a.pairwise, Cipher::Tkip);
    CHECK_EQ(a.group, Cipher::Tkip);
    CHECK_EQ(a.pmf, Pmf::Disabled); // original WPA has no PMF at all
}

GUARDIAN_CASE(fixture_wpa_and_rsn_mixed_is_bad_by_the_weakest_advertised_rule) {
    // RSN alone would be Medium (CCMP, PMF optional); the WPA/TKIP fallback caps it.
    SecurityObservation s;
    if (!observe(c_, "beacon_wpa_and_rsn_mixed", s)) return;
    const Assessment a = assess(s);
    expect_rated(c_, a, Mood::Bad, Finding::Legacy);
    CHECK(a.legacy_risk);
    CHECK_EQ(a.mode, Mode::Wpa1);
    CHECK_EQ(a.pairwise, Cipher::Tkip);
    CHECK_EQ(a.group, Cipher::Tkip);
    CHECK_EQ(a.pmf, Pmf::Optional); // the RSN's PMF fact stays visible
    CHECK_EQ(s.settings.rsn.group.kind, cipher::Ccmp128); // and the full record travels with the reading
}

GUARDIAN_CASE(fixture_open_is_horrible_unencrypted) {
    SecurityObservation s;
    if (!observe(c_, "beacon_open", s)) return;
    const Assessment a = assess(s);
    expect_rated(c_, a, Mood::Horrible, Finding::Unencrypted);
    CHECK(!a.legacy_risk);
    CHECK_EQ(a.mode, Mode::Open);
    CHECK_EQ(a.pairwise, Cipher::None);
    CHECK_EQ(a.group, Cipher::None);
}

// ---- unsupported / unknown overlays through the real parser ------------------------------
GUARDIAN_CASE(fixture_owe_transition_is_unrated_owe_not_open) {
    SecurityObservation s;
    if (!observe(c_, "beacon_owe_transition", s)) return;
    CHECK_EQ(s.parse, ParseStatus::Complete);
    const Assessment a = assess(s);
    expect_unrated(c_, a, Unrated::Owe);
    CHECK_EQ(a.mode, Mode::Owe);
    CHECK(!a.legacy_risk);
}

GUARDIAN_CASE(fixture_rsn_version_only_defaults_to_enterprise_and_is_unrated) {
    // Absent AKM list = 802.1X by the standard's default; G05 treats the default like an advertised AKM.
    SecurityObservation s;
    if (!observe(c_, "beacon_rsn_minimal_version_only", s)) return;
    CHECK(s.settings_complete);
    const Assessment a = assess(s);
    expect_unrated(c_, a, Unrated::Enterprise);
    CHECK_EQ(a.mode, Mode::Enterprise);
}

GUARDIAN_CASE(fixture_unknown_akm_is_unrated_unknown_option) {
    SecurityObservation s;
    if (!observe(c_, "beacon_rsn_unknown_akm", s)) return;
    CHECK_EQ(s.parse, ParseStatus::Complete);
    CHECK(!s.settings_complete); // the parser already says "not understood"
    const Assessment a = assess(s);
    expect_unrated(c_, a, Unrated::UnknownOption);
    CHECK(!a.legacy_risk); // PSK/CCMP next to the unknown AKM is not legacy
}

GUARDIAN_CASE(fixture_malformed_truncated_and_conflicting_frames_are_incomplete_never_open) {
    for (const char* name : {"beacon_rsn_pmf_inconsistent", "beacon_rsn_truncated_ie", "beacon_rsn_duplicate_conflict",
                             "beacon_rsn_pairwise_count_256", "mgmt_header_short_23"}) {
        SecurityObservation s;
        if (!observe(c_, name, s)) continue;
        const Assessment a = assess(s);
        if (a.mood != Mood::Unknown) CHECK_FAIL(std::string(name) + ": graded a non-Complete frame");
        if (a.unrated != Unrated::Incomplete) CHECK_FAIL(std::string(name) + ": expected Incomplete");
        if (a.mode == Mode::Open || a.mode == Mode::Wep) CHECK_FAIL(std::string(name) + ": parse failure became open/WEP");
        CHECK(s.parse != ParseStatus::Complete); // the parser, not the policy, refused these
        CHECK_EQ(a.pairwise, Cipher::Unknown);
    }
}

GUARDIAN_CASE(fixture_deauth_is_unrelated_and_can_never_be_security_evidence) {
    SecurityObservation s;
    if (!observe(c_, "deauth_reason7", s)) return;
    CHECK_EQ(s.parse, ParseStatus::Unrelated);
    CHECK_EQ(s.kind, FrameKind::Deauthentication);
    CHECK(!s.settings_present);
    CHECK(!s.settings_complete);
    expect_unrated(c_, assess(s), Unrated::Incomplete);
    // The same frame yields a signal reading: BSSID and RSSI only.
    Fixture f;
    if (!load(c_, "deauth_reason7", f)) return;
    const RxMeta m = ok_meta(2000);
    const SignalObservation sig = observe_signal(parser.parse(FrameSpan{f.bytes.data(), static_cast<std::uint16_t>(f.bytes.size()), false}, m), m);
    CHECK_EQ(sig.bssid[5], 0x55);
    CHECK_EQ(sig.rssi, -51);
    CHECK(sig.rssi_valid);
    CHECK_EQ(sig.acquired.at, Millis{2000});
    CHECK_EQ(sig.kind, FrameKind::Deauthentication);
}

// Supervisor review (2026-11-17): "signal here" is the AP's signal at this
// device, so only frames the AP transmitted (addr2 == BSSID) may feed it.
// Client frames to the AP (auth, association, client data/EAPOL with the data
// path on) carry the AP's BSSID too, but their RSSI is the client's.
GUARDIAN_CASE(signal_reading_comes_only_from_frames_the_ap_transmitted) {
    const RxMeta m = ok_meta(3000);
    for (const char* name : {"auth_open_seq1", "assoc_request_pm"}) {   // client -> AP
        Fixture f;
        if (!load(c_, name, f)) return;
        const SignalObservation sig = observe_signal(parser.parse(FrameSpan{f.bytes.data(), static_cast<std::uint16_t>(f.bytes.size()), false}, m), m);
        CHECK(sig.bssid == Mac{});   // no BSSID: Core rejects it as another network
    }
    for (const char* name : {"beacon_wpa3_sae_pmf_required", "deauth_reason7"}) {   // AP -> air
        Fixture f;
        if (!load(c_, name, f)) return;
        const SignalObservation sig = observe_signal(parser.parse(FrameSpan{f.bytes.data(), static_cast<std::uint16_t>(f.bytes.size()), false}, m), m);
        CHECK_EQ(sig.bssid[5], 0x55);
    }
}

GUARDIAN_CASE(fixture_rx_status_not_ok_blocks_the_grade_as_receive_unverified) {
    SecurityObservation s;
    RxMeta m = ok_meta();
    m.status = RxStatus::Unknown; // adapter cannot vouch for the checksum
    if (!observe(c_, "beacon_wpa3_sae_pmf_required", s, m)) return;
    CHECK_EQ(s.parse, ParseStatus::Complete);
    CHECK_EQ(s.rx_status, RxStatus::Unknown);
    expect_unrated(c_, assess(s), Unrated::ReceiveUnverified);
    m.status = RxStatus::FcsError; // rejected by the parser itself
    if (!observe(c_, "beacon_wpa3_sae_pmf_required", s, m)) return;
    expect_unrated(c_, assess(s), Unrated::Incomplete);
}

GUARDIAN_CASE(observe_security_keeps_source_identity_time_channel_and_status) {
    SecurityObservation s;
    RxMeta m = ok_meta(4242);
    m.channel = 11;
    m.rssi_dbm = -70;
    if (!observe(c_, "beacon_ssid_non_utf8", s, m)) return;
    CHECK_EQ(s.origin, Origin::Imported);
    CHECK_EQ(s.network.bssid[0], 0x02);
    CHECK_EQ(s.network.bssid[5], 0x55);
    CHECK_EQ(s.network.ssid_size, 4);
    CHECK_EQ(s.network.ssid[0], 0xff); // raw bytes, nothing substituted
    CHECK_EQ(s.network.ssid[3], 0x01);
    CHECK_EQ(s.ssid_kind, SsidKind::Present);
    CHECK(s.acquired.valid());
    CHECK_EQ(s.acquired.at, Millis{4242});
    CHECK(s.acquired.epoch == test_epoch());
    CHECK_EQ(s.channel, 11); // tuned channel from the adapter, not the DS element (6)
    CHECK_EQ(s.settings.ds_channel, 6);
    CHECK_EQ(s.rssi, -70);
    CHECK(s.rssi_valid);
    CHECK_EQ(s.kind, FrameKind::Beacon);
    CHECK_EQ(s.parse, ParseStatus::Complete);
    CHECK_EQ(s.rx_status, RxStatus::Ok);
}

// ---- hand-built rows and counterexamples -------------------------------------------------
GUARDIAN_CASE(wpa2_ccmp_pmf_required_is_good) {
    const Assessment a = assess(with_rsn(rsn(akm::Psk, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required)));
    expect_rated(c_, a, Mood::Good, Finding::Wpa2PmfRequired);
    CHECK_EQ(a.mode, Mode::Wpa2Personal);
    CHECK_EQ(a.pmf, Pmf::Required);
}

GUARDIAN_CASE(wpa2_personal_family_includes_psk_sha256_and_ft_psk) {
    const Assessment a = assess(with_rsn(rsn(akm::Psk | akm::PskSha256 | akm::FtPsk, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required)));
    expect_rated(c_, a, Mood::Good, Finding::Wpa2PmfRequired);
    CHECK_EQ(a.mode, Mode::Wpa2Personal);
}

GUARDIAN_CASE(wpa2_ccmp_pmf_disabled_is_medium) {
    const Assessment a = assess(with_rsn(rsn(akm::Psk, cipher::Ccmp128, cipher::Ccmp128, Pmf::Disabled)));
    expect_rated(c_, a, Mood::Medium, Finding::PmfNotRequired);
    CHECK_EQ(a.pmf, Pmf::Disabled);
}

GUARDIAN_CASE(wpa2_with_gcmp_or_ccmp256_is_unspecified_not_graded) {
    // The documented Good/Medium rows say CCMP; other strong ciphers under WPA2-Personal are a
    // deliberate "not specified yet", never silently promoted or demoted.
    for (std::uint16_t pw : {cipher::Gcmp128, cipher::Gcmp256, cipher::Ccmp256}) {
        const Assessment a = assess(with_rsn(rsn(akm::Psk, pw, cipher::Ccmp128, Pmf::Required)));
        expect_unrated(c_, a, Unrated::Unspecified);
        CHECK_EQ(a.mode, Mode::Wpa2Personal);
        CHECK(!a.legacy_risk);
    }
}

GUARDIAN_CASE(wpa3_sae_family_with_gcmp_is_very_good) {
    for (std::uint16_t akms : {akm::Sae, static_cast<std::uint16_t>(akm::Sae | akm::FtSae), static_cast<std::uint16_t>(akm::Sae | akm::SaeExt), akm::FtSae}) {
        const Assessment a = assess(with_rsn(rsn(akms, cipher::Gcmp256, cipher::Gcmp256, Pmf::Required, cipher::BipGmac256)));
        expect_rated(c_, a, Mood::VeryGood, Finding::StrongSettings);
        CHECK_EQ(a.mode, Mode::Wpa3Personal);
        CHECK_EQ(a.pairwise, Cipher::Gcmp);
        CHECK_EQ(a.group, Cipher::Gcmp);
    }
    const Assessment mixed = assess(with_rsn(rsn(akm::Sae, cipher::Ccmp128 | cipher::Gcmp256, cipher::Ccmp128, Pmf::Required)));
    expect_rated(c_, mixed, Mood::VeryGood, Finding::StrongSettings);
    CHECK_EQ(mixed.pairwise, Cipher::Ccmp); // weakest of the strong options is still strong
}

GUARDIAN_CASE(wpa3_sae_only_with_pmf_optional_is_unspecified_with_the_pmf_limitation_named) {
    const Assessment a = assess(with_rsn(rsn(akm::Sae, cipher::Ccmp128, cipher::Ccmp128, Pmf::Optional)));
    expect_unrated(c_, a, Unrated::Unspecified);
    CHECK_EQ(a.reason, Finding::PmfNotRequired);
    CHECK_EQ(a.mode, Mode::Wpa3Personal);
    CHECK_EQ(a.pmf, Pmf::Optional);
}

GUARDIAN_CASE(sae_without_pmf_capability_is_inconsistent) {
    expect_unrated(c_, assess(with_rsn(rsn(akm::Sae, cipher::Ccmp128, cipher::Ccmp128, Pmf::Disabled))), Unrated::Inconsistent);
    expect_unrated(c_, assess(with_rsn(rsn(akm::Sae | akm::Psk, cipher::Ccmp128, cipher::Ccmp128, Pmf::Disabled))), Unrated::Inconsistent);
}

GUARDIAN_CASE(transition_psk_and_sae_with_strong_ciphers_is_medium_compatibility) {
    for (Pmf pmf : {Pmf::Optional, Pmf::Required}) {
        const Assessment a = assess(with_rsn(rsn(akm::Psk | akm::Sae, cipher::Ccmp128, cipher::Ccmp128, pmf)));
        expect_rated(c_, a, Mood::Medium, Finding::CompatibilityMode);
        CHECK_EQ(a.mode, Mode::Transition);
        CHECK(!a.legacy_risk);
        CHECK_EQ(a.pmf, pmf);
    }
    const Assessment gcmp = assess(with_rsn(rsn(akm::PskSha256 | akm::FtSae, cipher::Gcmp128, cipher::Ccmp128, Pmf::Optional)));
    expect_rated(c_, gcmp, Mood::Medium, Finding::CompatibilityMode);
}

GUARDIAN_CASE(transition_with_a_tkip_option_is_bad) {
    const Assessment a = assess(with_rsn(rsn(akm::Psk | akm::Sae, cipher::Ccmp128 | cipher::Tkip, cipher::Ccmp128, Pmf::Optional)));
    expect_rated(c_, a, Mood::Bad, Finding::Legacy);
    CHECK(a.legacy_risk);
    CHECK_EQ(a.mode, Mode::Transition);
    CHECK_EQ(a.pairwise, Cipher::Tkip);
    const Assessment g = assess(with_rsn(rsn(akm::Psk | akm::Sae, cipher::Ccmp128, cipher::Tkip, Pmf::Optional)));
    expect_rated(c_, g, Mood::Bad, Finding::Legacy);
    CHECK_EQ(g.group, Cipher::Tkip);
}

GUARDIAN_CASE(any_wep_selector_is_horrible_legacy) {
    const Assessment a = assess(with_rsn(rsn(akm::Psk, cipher::Ccmp128, cipher::Wep40, Pmf::Disabled)));
    expect_rated(c_, a, Mood::Horrible, Finding::Legacy);
    CHECK(a.legacy_risk);
    CHECK_EQ(a.group, Cipher::Wep);
    CHECK_EQ(a.mode, Mode::Wpa2Personal); // the AKM is still named; the cipher decides the mood
    const Assessment w = assess(with_rsn(rsn(akm::Psk, cipher::Wep104 | cipher::Ccmp128, cipher::Ccmp128, Pmf::Required)));
    expect_rated(c_, w, Mood::Horrible, Finding::Legacy);
    CHECK_EQ(w.pairwise, Cipher::Wep);
}

GUARDIAN_CASE(privacy_set_with_no_security_element_is_wep_only_when_the_decode_is_complete) {
    AdvertisedSettings a{};
    const Assessment wep = assess(complete(a, true));
    expect_rated(c_, wep, Mood::Horrible, Finding::Legacy);
    CHECK(wep.legacy_risk);
    CHECK_EQ(wep.mode, Mode::Wep);
    CHECK_EQ(wep.pairwise, Cipher::Wep);
    CHECK_EQ(wep.group, Cipher::Wep);
    SecurityObservation cut = complete(a, true);
    cut.parse = ParseStatus::Truncated; // a parse failure never becomes WEP
    cut.settings_complete = false;
    const Assessment t = assess(cut);
    expect_unrated(c_, t, Unrated::Incomplete);
    CHECK(t.mode != Mode::Wep);
    CHECK(!t.legacy_risk);
}

GUARDIAN_CASE(privacy_clear_with_owe_transition_element_is_owe_not_unencrypted) {
    AdvertisedSettings a{};
    a.owe_transition = ElementState::Valid; // the open side of an OWE transition pair
    const Assessment o = assess(complete(a, false));
    expect_unrated(c_, o, Unrated::Owe);
    CHECK(o.mode != Mode::Open);
    AdvertisedSettings plain{};
    expect_rated(c_, assess(complete(plain, false)), Mood::Horrible, Finding::Unencrypted);
}

GUARDIAN_CASE(use_group_pairwise_takes_the_group_cipher) {
    const Assessment bad = assess(with_rsn(rsn(akm::Psk, cipher::UseGroup, cipher::Tkip, Pmf::Disabled)));
    expect_rated(c_, bad, Mood::Bad, Finding::Legacy);
    CHECK_EQ(bad.pairwise, Cipher::Tkip);
    const Assessment good = assess(with_rsn(rsn(akm::Psk, cipher::UseGroup, cipher::Ccmp128, Pmf::Required)));
    expect_rated(c_, good, Mood::Good, Finding::Wpa2PmfRequired);
    CHECK_EQ(good.pairwise, Cipher::Ccmp);
}

GUARDIAN_CASE(enterprise_akms_are_unrated_even_next_to_psk_and_keep_a_legacy_finding) {
    for (std::uint16_t e : {akm::Eap, akm::EapSha256, akm::FtEap, akm::EapSuiteB, akm::EapSuiteB192}) {
        const Assessment a = assess(with_rsn(rsn(e, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required)));
        expect_unrated(c_, a, Unrated::Enterprise);
        CHECK_EQ(a.mode, Mode::Enterprise);
    }
    const Assessment mixed = assess(with_rsn(rsn(akm::Eap | akm::Psk, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required)));
    expect_unrated(c_, mixed, Unrated::Enterprise); // an unsupported option blocks the grade
    const Assessment tkip = assess(with_rsn(rsn(akm::Eap | akm::Psk, cipher::Ccmp128 | cipher::Tkip, cipher::Tkip, Pmf::Disabled)));
    expect_unrated(c_, tkip, Unrated::Enterprise);
    CHECK(tkip.legacy_risk); // but the confirmed TKIP option stays visible
    CHECK_EQ(tkip.reason, Finding::Legacy);
    AdvertisedSettings w{};
    w.wpa = wpa(akm::Wpa1Eap, cipher::Tkip, cipher::Tkip);
    const Assessment wpa_eap = assess(complete(w));
    expect_unrated(c_, wpa_eap, Unrated::Enterprise);
    CHECK(wpa_eap.legacy_risk);
}

GUARDIAN_CASE(original_wpa_with_ccmp_only_is_still_bad_and_a_legacy_finding) {
    // Found by the mutation check: without TKIP anywhere, a Valid WPA vendor element (WPA v1 with
    // AES) must still be Bad/Legacy because original WPA itself is the legacy mode (ledger row).
    AdvertisedSettings a{};
    a.wpa = wpa(akm::Wpa1Psk, cipher::Ccmp128, cipher::Ccmp128);
    const Assessment w = assess(complete(a));
    expect_rated(c_, w, Mood::Bad, Finding::Legacy);
    CHECK(w.legacy_risk);
    CHECK_EQ(w.mode, Mode::Wpa1);
    CHECK_EQ(w.pairwise, Cipher::Ccmp);
    CHECK_EQ(w.group, Cipher::Ccmp);
    CHECK_EQ(w.pmf, Pmf::Disabled);
    // Next to a WPA2 RSNE that alone would be Good, the WPA/AES fallback still caps the grade.
    a.rsn = rsn(akm::Psk, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required);
    const Assessment mixed = assess(complete(a));
    expect_rated(c_, mixed, Mood::Bad, Finding::Legacy);
    CHECK(mixed.legacy_risk);
    CHECK_EQ(mixed.pmf, Pmf::Required);
    // And as partial evidence next to a Malformed RSNE: no grade, legacy risk confirmed.
    SecurityObservation partial = complete(a);
    partial.parse = ParseStatus::Malformed;
    partial.settings_complete = false;
    partial.settings.rsn = SecurityElement{};
    partial.settings.rsn.state = ElementState::Malformed;
    const Assessment p = assess(partial);
    expect_unrated(c_, p, Unrated::Incomplete);
    CHECK(p.legacy_risk);
    CHECK_EQ(p.reason, Finding::Legacy);
}

GUARDIAN_CASE(owe_akm_is_unrated_owe) {
    const Assessment a = assess(with_rsn(rsn(akm::Owe, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required)));
    expect_unrated(c_, a, Unrated::Owe);
    CHECK_EQ(a.mode, Mode::Owe);
    expect_unrated(c_, assess(with_rsn(rsn(akm::Owe | akm::Psk, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required))), Unrated::Owe);
}

GUARDIAN_CASE(security_element_with_privacy_clear_is_inconsistent) {
    expect_unrated(c_, assess(with_rsn(rsn(akm::Sae, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required), false)), Unrated::Inconsistent);
    AdvertisedSettings w{};
    w.wpa = wpa();
    const Assessment a = assess(complete(w, false));
    expect_unrated(c_, a, Unrated::Inconsistent);
    CHECK(a.legacy_risk); // the Valid WPA element is still a confirmed legacy fact
}

GUARDIAN_CASE(owe_transition_element_on_a_non_owe_bss_is_inconsistent) {
    AdvertisedSettings a{};
    a.rsn = rsn(akm::Sae, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required);
    a.owe_transition = ElementState::Valid;
    expect_unrated(c_, assess(complete(a)), Unrated::Inconsistent);
}

GUARDIAN_CASE(unknown_cipher_or_akm_blocks_the_grade_but_keeps_confirmed_legacy_risk) {
    const Assessment a = assess(with_rsn(rsn(akm::Psk, cipher::Tkip | cipher::Unknown, cipher::Ccmp128, Pmf::Disabled)));
    expect_unrated(c_, a, Unrated::UnknownOption);
    CHECK(a.legacy_risk);
    CHECK_EQ(a.reason, Finding::Legacy);
    const Assessment g = assess(with_rsn(rsn(akm::Psk, cipher::Ccmp128, cipher::Unknown, Pmf::Required)));
    expect_unrated(c_, g, Unrated::UnknownOption);
    CHECK(!g.legacy_risk);
    const Assessment k = assess(with_rsn(rsn(akm::Sae | akm::Unknown, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required)));
    expect_unrated(c_, k, Unrated::UnknownOption); // never "SAE-only" by ignoring the unknown AKM
    const Assessment gm = assess(with_rsn(rsn(akm::Sae, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required, cipher::Unknown)));
    expect_unrated(c_, gm, Unrated::UnknownOption); // group management cipher counts too
}

GUARDIAN_CASE(bip_as_a_data_cipher_is_inconsistent) {
    expect_unrated(c_, assess(with_rsn(rsn(akm::Psk, cipher::BipCmac128, cipher::Ccmp128, Pmf::Required))), Unrated::Inconsistent);
    expect_unrated(c_, assess(with_rsn(rsn(akm::Psk, cipher::Ccmp128, cipher::BipGmac128, Pmf::Required))), Unrated::Inconsistent);
}

GUARDIAN_CASE(legacy_risk_survives_a_malformed_rsn_sibling_without_a_grade) {
    // docs/contracts.md section 6: a Valid WPA/TKIP element next to a Malformed RSNE is partial
    // legacy-risk evidence; the decode cannot earn a complete grade.
    SecurityObservation s = complete(AdvertisedSettings{});
    s.parse = ParseStatus::Malformed;
    s.settings_present = true;
    s.settings_complete = false;
    s.settings.wpa = wpa();
    s.settings.rsn.state = ElementState::Malformed;
    const Assessment a = assess(s);
    expect_unrated(c_, a, Unrated::Incomplete);
    CHECK(a.legacy_risk);
    CHECK_EQ(a.reason, Finding::Legacy);
    // Only a VALID element confirms anything: zeroed fields of a Malformed element never do.
    SecurityObservation z = complete(AdvertisedSettings{});
    z.parse = ParseStatus::Malformed;
    z.settings_complete = false;
    z.settings.rsn.state = ElementState::Malformed;
    z.settings.wpa.state = ElementState::Truncated;
    CHECK(!assess(z).legacy_risk);
}

GUARDIAN_CASE(no_parse_status_other_than_complete_grades_strong_settings) {
    SecurityObservation s = with_rsn(rsn(akm::Sae, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required));
    for (ParseStatus p : {ParseStatus::Unsupported, ParseStatus::Malformed, ParseStatus::Truncated, ParseStatus::Unrelated}) {
        s.parse = p;
        expect_unrated(c_, assess(s), Unrated::Incomplete);
    }
    s.parse = ParseStatus::Complete;
    s.settings_complete = false;
    expect_unrated(c_, assess(s), Unrated::Incomplete);
    s.settings_complete = true;
    s.settings_present = false;
    expect_unrated(c_, assess(s), Unrated::Incomplete);
    s.settings_present = true;
    s.kind = FrameKind::Deauthentication; // not an advertisement
    expect_unrated(c_, assess(s), Unrated::Incomplete);
    s.kind = FrameKind::ProbeResponse;
    expect_rated(c_, assess(s), Mood::VeryGood, Finding::StrongSettings);
}

GUARDIAN_CASE(default_observation_is_unrated_incomplete) {
    const Assessment a = assess(SecurityObservation{});
    expect_unrated(c_, a, Unrated::Incomplete);
    CHECK_EQ(a.reason, Finding::Unknown);
    CHECK(!a.legacy_risk);
    CHECK_EQ(a.mode, Mode::Unknown);
}

GUARDIAN_CASE(fixture_four_strong_pairwise_options_with_sae_is_very_good_and_weakest_is_ccmp) {
    SecurityObservation s;
    if (!observe(c_, "beacon_rsn_four_pairwise", s)) return;
    CHECK_EQ(s.settings.rsn.pairwise.count, 4);
    const Assessment a = assess(s);
    expect_rated(c_, a, Mood::VeryGood, Finding::StrongSettings);
    CHECK_EQ(a.pairwise, Cipher::Ccmp); // CCMP-128 is the weakest of the four advertised strong options
    CHECK_EQ(a.group, Cipher::Ccmp);
}


GUARDIAN_CASE(review_typed_management_cipher_must_not_be_a_data_cipher) {
    for (auto bad : {cipher::Tkip, cipher::Ccmp128, cipher::UseGroup}) {
        expect_unrated(c_, assess(with_rsn(rsn(akm::Sae, cipher::Ccmp128, cipher::Ccmp128, Pmf::Required, bad))), Unrated::Inconsistent);
    }
}


GUARDIAN_CASE(review_unverified_bytes_do_not_establish_confirmed_legacy_risk) {
    auto s = with_rsn(rsn(akm::Psk, cipher::Tkip, cipher::Tkip, Pmf::Disabled));
    s.rx_status = RxStatus::Unknown;
    const auto a = assess(s);
    expect_unrated(c_, a, Unrated::ReceiveUnverified);
    CHECK(!a.legacy_risk);
    CHECK_EQ(a.reason, Finding::Unknown);
}

// G04 SecurityFrameParser behavior checks (TDD: this file was written and run
// RED against a stub parser first; see docs/G04-parser.md for the recorded run).
//
// Fixtures come from firmware/tests/fixtures (hand-assembled, Origin::Imported,
// FCS-free). Counterexamples that the generator does not carry are built here
// by mutating loaded fixtures or assembling frames with the helpers below, so
// every malformed rule has a byte-exact witness. Nothing here is radio proof.
#include "check.hpp"
#include "fixtures.hpp"

#include "guardian/security_parser.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <vector>

using namespace guardian;
using guardian::fixtures::Fixture;

namespace {

const SecurityFrameParser parser{};

RxMeta ok_meta() {
    RxMeta m{};
    m.status = RxStatus::Ok;
    m.origin = Origin::Imported;
    m.band = Band::Ghz2_4;
    m.channel = 6;
    return m;
}

FrameSpan span_of(const std::vector<std::uint8_t>& bytes, bool truncated = false) {
    return FrameSpan{bytes.data(), static_cast<std::uint16_t>(bytes.size()), truncated};
}

ParseResult parse(const std::vector<std::uint8_t>& bytes, bool truncated = false) {
    return parser.parse(span_of(bytes, truncated), ok_meta());
}

// Loads a fixture or records a named failure; returns false when unavailable.
bool load(check::Case& c_, const char* name, Fixture& f) {
    std::string err;
    if (fixtures::load(name, f, err)) return true;
    CHECK_FAIL(err);
    return false;
}

constexpr std::uint32_t RSN_CCMP128 = make_selector(oui::Ieee8021, 4);
constexpr std::uint32_t RSN_TKIP = make_selector(oui::Ieee8021, 2);
constexpr std::uint32_t RSN_AKM_PSK = make_selector(oui::Ieee8021, 2);
constexpr std::uint32_t RSN_AKM_SAE = make_selector(oui::Ieee8021, 8);
constexpr std::uint32_t RSN_AKM_EAP = make_selector(oui::Ieee8021, 1);
constexpr std::uint32_t RSN_AKM_OWE = make_selector(oui::Ieee8021, 18);
constexpr std::uint32_t RSN_BIP_CMAC128 = make_selector(oui::Ieee8021, 6);
constexpr std::uint32_t RSN_BIP_GMAC256 = make_selector(oui::Ieee8021, 12);
constexpr std::uint32_t WPA_TKIP = make_selector(oui::Microsoft, 2);
constexpr std::uint32_t WPA_AKM_PSK = make_selector(oui::Microsoft, 2);

const std::vector<std::uint8_t> BSSID{0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
const std::vector<std::uint8_t> STATION{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
const std::vector<std::uint8_t> BROADCAST{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// ---- small frame builder for synthetic counterexamples -------------------------------
struct Frame {
    std::vector<std::uint8_t> b;
    Frame& raw(const std::vector<std::uint8_t>& v) { b.insert(b.end(), v.begin(), v.end()); return *this; }
    Frame& u8(std::uint8_t v) { b.push_back(v); return *this; }
    Frame& le16(std::uint16_t v) { b.push_back(static_cast<std::uint8_t>(v & 0xff)); b.push_back(static_cast<std::uint8_t>(v >> 8)); return *this; }
    Frame& sel(std::uint32_t selector) { // wire order: OUI big-endian then type
        b.push_back(static_cast<std::uint8_t>(selector >> 24)); b.push_back(static_cast<std::uint8_t>(selector >> 16));
        b.push_back(static_cast<std::uint8_t>(selector >> 8)); b.push_back(static_cast<std::uint8_t>(selector)); return *this;
    }
    Frame& ie(std::uint8_t id, const std::vector<std::uint8_t>& body) { u8(id); u8(static_cast<std::uint8_t>(body.size())); return raw(body); }
};

Frame mgmt_header(std::uint8_t fc0, std::uint8_t fc1, const std::vector<std::uint8_t>& a1,
                  const std::vector<std::uint8_t>& a2, const std::vector<std::uint8_t>& a3, std::uint16_t seq) {
    Frame f;
    f.u8(fc0).u8(fc1).le16(0).raw(a1).raw(a2).raw(a3).le16(static_cast<std::uint16_t>(seq << 4));
    return f;
}

Frame beacon_head(std::uint16_t capability, std::uint8_t fc0 = 0x80, std::uint8_t fc1 = 0x00) {
    Frame f = mgmt_header(fc0, fc1, BROADCAST, BSSID, BSSID, 0x123);
    for (int i = 0; i < 8; ++i) f.u8(0);        // timestamp
    f.le16(100);                                 // beacon interval
    f.le16(capability);
    f.ie(0, {'h', 'o', 'm', 'e'});
    f.ie(3, {6});
    return f;
}

// RSNE body builder: fields are appended in wire order; stop wherever the test wants.
std::vector<std::uint8_t> rsn(std::uint32_t group, const std::vector<std::uint32_t>& pairwise,
                              const std::vector<std::uint32_t>& akms, int caps = -1,
                              int pairwise_count = -1, int akm_count = -1) {
    Frame f;
    f.le16(1).sel(group);
    f.le16(static_cast<std::uint16_t>(pairwise_count < 0 ? pairwise.size() : static_cast<std::size_t>(pairwise_count)));
    for (auto s : pairwise) f.sel(s);
    f.le16(static_cast<std::uint16_t>(akm_count < 0 ? akms.size() : static_cast<std::size_t>(akm_count)));
    for (auto s : akms) f.sel(s);
    if (caps >= 0) f.le16(static_cast<std::uint16_t>(caps));
    return f.b;
}

std::vector<std::uint8_t> wpa(std::uint32_t group, const std::vector<std::uint32_t>& pairwise,
                              const std::vector<std::uint32_t>& akms, int pairwise_count = -1) {
    Frame f;
    f.raw({0x00, 0x50, 0xf2, 0x01}).le16(1).sel(group);
    f.le16(static_cast<std::uint16_t>(pairwise_count < 0 ? pairwise.size() : static_cast<std::size_t>(pairwise_count)));
    for (auto s : pairwise) f.sel(s);
    f.le16(static_cast<std::uint16_t>(akms.size()));
    for (auto s : akms) f.sel(s);
    return f.b;
}

bool zeroed(const SuiteList& l) { 
    if (l.count != 0 || l.kinds != 0) return false;
    for (auto s : l.selectors) if (s) return false;
    return true;
}
bool zeroed(const SuiteSelector& s) { return s.selector == 0 && s.kind == 0 && !s.present; }
bool element_zeroed(const SecurityElement& e) {
    return zeroed(e.akms) && zeroed(e.pairwise) && zeroed(e.group) && zeroed(e.group_management) && e.pmf == Pmf::Unknown;
}

// Invariants every result must satisfy regardless of input (used by the sweeps).
void check_invariants(check::Case& c_, const ParseResult& r, const char* what) {
    const bool ok_complete = (r.status == ParseStatus::Complete) || !r.settings_complete;
    if (!ok_complete) CHECK_FAIL(std::string(what) + ": settings_complete without Complete status");
    if (r.settings.rsn.akms.count > SuiteList::capacity || r.settings.rsn.pairwise.count > SuiteList::capacity
        || r.settings.wpa.akms.count > SuiteList::capacity || r.settings.wpa.pairwise.count > SuiteList::capacity)
        CHECK_FAIL(std::string(what) + ": suite count above capacity");
    if (r.identity.ssid_size > 32) CHECK_FAIL(std::string(what) + ": ssid_size above 32");
    for (const SecurityElement* e : {&r.settings.rsn, &r.settings.wpa}) {
        if (e->state != ElementState::Valid && !element_zeroed(*e))
            CHECK_FAIL(std::string(what) + ": non-Valid element carries fields");
    }
    if (r.settings_complete && !r.settings_present) CHECK_FAIL(std::string(what) + ": complete but not present");
    if (!r.header_valid && (r.settings_present || r.reason_readable))
        CHECK_FAIL(std::string(what) + ": fields without a valid header");
    CHECK(true); // the sweep made at least one assertion even when everything held
}

} // namespace

// ---- input rejection before any byte is read --------------------------------------------
GUARDIAN_CASE(fcs_error_input_is_rejected_before_parsing) {
    Fixture f;
    if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", f)) return;
    RxMeta m = ok_meta();
    m.status = RxStatus::FcsError;
    const ParseResult r = parser.parse(span_of(f.bytes), m);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::FcsFailed);
    CHECK(!r.header_valid);
    CHECK(!r.settings_present);
    CHECK(!r.settings_complete);
    CHECK_EQ(r.kind, FrameKind::Unknown);
    CHECK_EQ(r.settings.rsn.state, ElementState::Absent);
}

GUARDIAN_CASE(driver_error_input_is_rejected_before_parsing) {
    Fixture f;
    if (!load(c_, "deauth_reason7", f)) return;
    RxMeta m = ok_meta();
    m.status = RxStatus::DriverError;
    const ParseResult r = parser.parse(span_of(f.bytes), m);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::ReceiveFailed);
    CHECK(!r.header_valid);
    CHECK(!r.reason_readable);
}

GUARDIAN_CASE(unknown_rx_status_is_parsed_structurally_not_rejected) {
    // RxStatus::Unknown means "driver exposes no status"; the parser decodes the
    // bytes and the policy layer keeps the checksum uncertainty from RxMeta.
    Fixture f;
    if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", f)) return;
    RxMeta m = ok_meta();
    m.status = RxStatus::Unknown;
    const ParseResult r = parser.parse(span_of(f.bytes), m);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
}

GUARDIAN_CASE(null_or_tiny_span_is_malformed_short_header) {
    const ParseResult r0 = parser.parse(FrameSpan{}, ok_meta());
    CHECK_EQ(r0.status, ParseStatus::Malformed);
    CHECK_EQ(r0.error, ParseError::ShortMacHeader);
    CHECK(!r0.header_valid);
    const std::vector<std::uint8_t> one{0x80};
    const ParseResult r1 = parse(one);
    CHECK_EQ(r1.status, ParseStatus::Malformed);
    CHECK_EQ(r1.error, ParseError::ShortMacHeader);
    const ParseResult r2 = parser.parse(FrameSpan{nullptr, 4, false}, ok_meta()); // null pointer with a size: never read
    CHECK_EQ(r2.status, ParseStatus::Malformed);
    CHECK_EQ(r2.error, ParseError::ShortMacHeader);
}

GUARDIAN_CASE(mgmt_header_short_23_fixture_is_short_mac_header) {
    Fixture f;
    if (!load(c_, "mgmt_header_short_23", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::ShortMacHeader);
    CHECK_EQ(r.kind, FrameKind::Beacon); // the kind is known from frame control; the header is not usable
    CHECK(!r.header_valid);
    CHECK(!r.settings_present);
    CHECK(!r.settings_complete);
    // A 23-byte prefix flagged truncated by the adapter is Truncated, not Malformed.
    const ParseResult t = parse(f.bytes, true);
    CHECK_EQ(t.status, ParseStatus::Truncated);
    CHECK_EQ(t.error, ParseError::ShortMacHeader);
    CHECK(!t.header_valid);
}

GUARDIAN_CASE(frame_control_protocol_version_not_zero_is_unsupported) {
    Fixture f;
    if (!load(c_, "beacon_open", f)) return;
    std::vector<std::uint8_t> b = f.bytes;
    b[0] = static_cast<std::uint8_t>(b[0] | 0x01); // version 1
    const ParseResult r = parse(b);
    CHECK_EQ(r.status, ParseStatus::Unsupported);
    CHECK_EQ(r.error, ParseError::UnsupportedVersion);
    CHECK(!r.header_valid);
    CHECK(!r.settings_present);
}

// ---- complete valid beacons: identity, header and advertised settings --------------------
GUARDIAN_CASE(open_beacon_fixture_decodes_header_identity_and_clear_privacy) {
    Fixture f;
    if (!load(c_, "beacon_open", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.error, ParseError::None);
    CHECK_EQ(r.kind, FrameKind::Beacon);
    CHECK(r.header_valid);
    CHECK(std::equal(r.addr1.begin(), r.addr1.end(), BROADCAST.begin()));
    CHECK(std::equal(r.addr2.begin(), r.addr2.end(), BSSID.begin()));
    CHECK(std::equal(r.addr3.begin(), r.addr3.end(), BSSID.begin()));
    CHECK(std::equal(r.identity.bssid.begin(), r.identity.bssid.end(), BSSID.begin()));
    CHECK_EQ(r.sequence, 0x123);
    CHECK_EQ(r.fragment, 0);
    CHECK(!r.protected_frame);
    CHECK(!r.retry);
    CHECK_EQ(r.ssid_kind, SsidKind::Present);
    CHECK(r.ssid_utf8);
    CHECK_EQ(r.identity.ssid_size, 4);
    CHECK_EQ(std::string(r.identity.ssid.begin(), r.identity.ssid.begin() + 4), std::string("home"));
    CHECK(r.settings.privacy_valid);
    CHECK(!r.settings.privacy_bit);
    CHECK_EQ(r.settings.rsn.state, ElementState::Absent);
    CHECK_EQ(r.settings.wpa.state, ElementState::Absent);
    CHECK_EQ(r.settings.owe_transition, ElementState::Absent);
    CHECK(r.settings.ds_channel_present);
    CHECK_EQ(r.settings.ds_channel, 6);
    CHECK(r.settings_present);
    CHECK(r.settings_complete); // structurally complete; "open" is G05's call, not a parser output
    CHECK(!r.reason_readable);
}

GUARDIAN_CASE(wpa2_ccmp_pmf_optional_fixture_decodes_rsn) {
    Fixture f;
    if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK(r.settings.privacy_bit);
    const SecurityElement& e = r.settings.rsn;
    CHECK_EQ(e.state, ElementState::Valid);
    CHECK_EQ(e.akms.count, 1);
    CHECK_EQ(e.akms.selectors[0], RSN_AKM_PSK);
    CHECK_EQ(e.akms.kinds, akm::Psk);
    CHECK_EQ(e.pairwise.count, 1);
    CHECK_EQ(e.pairwise.selectors[0], RSN_CCMP128);
    CHECK_EQ(e.pairwise.kinds, cipher::Ccmp128);
    CHECK(e.group.present);
    CHECK_EQ(e.group.selector, RSN_CCMP128);
    CHECK_EQ(e.group.kind, cipher::Ccmp128);
    CHECK_EQ(e.pmf, Pmf::Optional);
    CHECK(!e.group_management.present); // absent: documented default reported, flagged as not present
    CHECK_EQ(e.group_management.selector, RSN_BIP_CMAC128);
    CHECK_EQ(e.group_management.kind, cipher::BipCmac128);
    CHECK_EQ(r.settings.wpa.state, ElementState::Absent);
    CHECK(r.settings_present);
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(wpa3_sae_fixture_reports_sae_and_pmf_required) {
    Fixture f;
    if (!load(c_, "beacon_wpa3_sae_pmf_required", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK_EQ(r.settings.rsn.akms.kinds, akm::Sae);
    CHECK_EQ(r.settings.rsn.akms.selectors[0], RSN_AKM_SAE);
    CHECK_EQ(r.settings.rsn.pmf, Pmf::Required);
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(hidden_ssid_fixture_is_hidden_and_the_following_rsn_is_still_read) {
    Fixture f;
    if (!load(c_, "beacon_hidden_ssid_wpa2", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.ssid_kind, SsidKind::Hidden);
    CHECK_EQ(r.identity.ssid_size, 0);
    CHECK(!r.ssid_utf8);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK_EQ(r.settings.rsn.pmf, Pmf::Optional);
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(later_zero_length_element_does_not_stop_the_walk) {
    // The G02 libwifi iterator stops at a later empty element and keeps WEP; Guardian must not.
    Fixture f;
    if (!load(c_, "beacon_later_empty_ie_then_rsn", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK_EQ(r.settings.rsn.akms.kinds, akm::Psk);
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(mixed_tkip_fixture_keeps_both_pairwise_options_in_wire_order) {
    Fixture f;
    if (!load(c_, "beacon_wpa2_mixed_tkip", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    const SecurityElement& e = r.settings.rsn;
    CHECK_EQ(e.state, ElementState::Valid);
    CHECK_EQ(e.pairwise.count, 2);
    CHECK_EQ(e.pairwise.selectors[0], RSN_CCMP128);
    CHECK_EQ(e.pairwise.selectors[1], RSN_TKIP);
    CHECK_EQ(e.pairwise.kinds, static_cast<std::uint16_t>(cipher::Ccmp128 | cipher::Tkip));
    CHECK_EQ(e.group.kind, cipher::Tkip);
    CHECK_EQ(e.pmf, Pmf::Disabled); // caps present, MFPC clear
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(four_pairwise_suites_are_all_kept) {
    Fixture f;
    if (!load(c_, "beacon_rsn_four_pairwise", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    const SuiteList& p = r.settings.rsn.pairwise;
    CHECK_EQ(p.count, 4);
    CHECK_EQ(p.selectors[0], RSN_CCMP128);
    CHECK_EQ(p.selectors[1], make_selector(oui::Ieee8021, 8));
    CHECK_EQ(p.selectors[2], make_selector(oui::Ieee8021, 9));
    CHECK_EQ(p.selectors[3], make_selector(oui::Ieee8021, 10));
    CHECK_EQ(p.kinds, static_cast<std::uint16_t>(cipher::Ccmp128 | cipher::Gcmp128 | cipher::Gcmp256 | cipher::Ccmp256));
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(unknown_akm_selector_is_preserved_and_blocks_completeness) {
    Fixture f;
    if (!load(c_, "beacon_rsn_unknown_akm", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete); // structurally fine
    const SuiteList& a = r.settings.rsn.akms;
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK_EQ(a.count, 2);
    CHECK_EQ(a.selectors[0], make_selector(oui::Ieee8021, 200));
    CHECK_EQ(a.selectors[1], RSN_AKM_PSK);
    CHECK_EQ(a.kinds, static_cast<std::uint16_t>(akm::Unknown | akm::Psk));
    CHECK(r.settings_present);
    CHECK(!r.settings_complete); // not understood -> no complete grade
}

GUARDIAN_CASE(owe_fixture_reports_owe_akm_and_valid_transition_element) {
    Fixture f;
    if (!load(c_, "beacon_owe_transition", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK_EQ(r.settings.rsn.akms.kinds, akm::Owe);
    CHECK_EQ(r.settings.rsn.akms.selectors[0], RSN_AKM_OWE);
    CHECK_EQ(r.settings.rsn.pmf, Pmf::Required);
    CHECK_EQ(r.settings.owe_transition, ElementState::Valid);
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(owe_transition_element_with_band_and_channel_is_valid_and_with_bad_ssid_length_is_not) {
    Frame good = beacon_head(0x0011);
    good.ie(221, {0x50, 0x6f, 0x9a, 0x1c, 0x02, 0x11, 0x22, 0x33, 0x44, 0x56, 0x03, 'a', 'b', 'c', 0x51, 0x06});
    const ParseResult rg = parse(good.b);
    CHECK_EQ(rg.status, ParseStatus::Complete);
    CHECK_EQ(rg.settings.owe_transition, ElementState::Valid);

    Frame bad = beacon_head(0x0011);
    bad.ie(221, {0x50, 0x6f, 0x9a, 0x1c, 0x02, 0x11, 0x22, 0x33, 0x44, 0x56, 40, 'a', 'b', 'c'}); // SSID length 40 > 32
    const ParseResult rb = parse(bad.b);
    CHECK_EQ(rb.status, ParseStatus::Malformed);
    CHECK_EQ(rb.error, ParseError::BadElementLength);
    CHECK_EQ(rb.settings.owe_transition, ElementState::Malformed);
    CHECK(!rb.settings_complete);
    CHECK(rb.settings.privacy_valid); // independent fields survive

    Frame odd = beacon_head(0x0011); // one dangling byte after the SSID: neither 0 nor 2 optional bytes
    odd.ie(221, {0x50, 0x6f, 0x9a, 0x1c, 0x02, 0x11, 0x22, 0x33, 0x44, 0x56, 0x01, 'a', 0x51});
    const ParseResult ro = parse(odd.b);
    CHECK_EQ(ro.status, ParseStatus::Malformed);
    CHECK_EQ(ro.settings.owe_transition, ElementState::Malformed);
}

GUARDIAN_CASE(probe_response_fixture_is_parsed_like_a_beacon) {
    Fixture f;
    if (!load(c_, "probe_response_wpa2", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.kind, FrameKind::ProbeResponse);
    CHECK(std::equal(r.addr1.begin(), r.addr1.end(), STATION.begin()));
    CHECK(std::equal(r.identity.bssid.begin(), r.identity.bssid.end(), BSSID.begin()));
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(order_bit_means_a_28_byte_header_with_ht_control) {
    Fixture f;
    if (!load(c_, "beacon_ht_control_order_bit", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK(r.header_valid);
    CHECK_EQ(r.sequence, 0x123);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK(r.settings.ds_channel_present);
    CHECK_EQ(r.settings.ds_channel, 6);
    CHECK(r.settings_complete);
    // 27 bytes with the Order bit set is one short of that header.
    std::vector<std::uint8_t> short27(f.bytes.begin(), f.bytes.begin() + 27);
    const ParseResult s = parse(short27);
    CHECK_EQ(s.status, ParseStatus::Malformed);
    CHECK_EQ(s.error, ParseError::ShortMacHeader);
    CHECK(!s.header_valid);
}

// ---- SSID identity rules -------------------------------------------------------------------
GUARDIAN_CASE(non_utf8_ssid_bytes_are_preserved_exactly_and_flagged) {
    Fixture f;
    if (!load(c_, "beacon_ssid_non_utf8", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.ssid_kind, SsidKind::Present);
    CHECK(!r.ssid_utf8);
    CHECK_EQ(r.identity.ssid_size, 4);
    CHECK_EQ(r.identity.ssid[0], 0xff);
    CHECK_EQ(r.identity.ssid[1], 0xfe);
    CHECK_EQ(r.identity.ssid[2], 0x78);
    CHECK_EQ(r.identity.ssid[3], 0x01); // control byte kept, nothing substituted
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
}

GUARDIAN_CASE(ssid_utf8_flag_follows_encoding_validity_only) {
    Frame f = mgmt_header(0x80, 0x00, BROADCAST, BSSID, BSSID, 1);
    for (int i = 0; i < 8; ++i) f.u8(0);
    f.le16(100).le16(0x0001);
    f.ie(0, {0xc3, 0xa9, 0x01, 'x'}); // U+00E9 then a control byte: valid UTF-8
    f.ie(3, {1});
    const ParseResult ok = parse(f.b);
    CHECK_EQ(ok.ssid_kind, SsidKind::Present);
    CHECK(ok.ssid_utf8);
    CHECK_EQ(ok.identity.ssid[2], 0x01);

    Frame g = mgmt_header(0x80, 0x00, BROADCAST, BSSID, BSSID, 1);
    for (int i = 0; i < 8; ++i) g.u8(0);
    g.le16(100).le16(0x0001);
    g.ie(0, {0xc0, 0x80}); // overlong encoding of NUL: invalid
    const ParseResult overlong = parse(g.b);
    CHECK_EQ(overlong.ssid_kind, SsidKind::Present);
    CHECK(!overlong.ssid_utf8);

    Frame h = mgmt_header(0x80, 0x00, BROADCAST, BSSID, BSSID, 1);
    for (int i = 0; i < 8; ++i) h.u8(0);
    h.le16(100).le16(0x0001);
    h.ie(0, {0xed, 0xa0, 0x80}); // UTF-16 surrogate U+D800: invalid in UTF-8
    CHECK(!parse(h.b).ssid_utf8);

    Frame k = mgmt_header(0x80, 0x00, BROADCAST, BSSID, BSSID, 1);
    for (int i = 0; i < 8; ++i) k.u8(0);
    k.le16(100).le16(0x0001);
    k.ie(0, {0xf0, 0x9f, 0x98, 0x80}); // U+1F600, 4-byte sequence: valid
    CHECK(parse(k.b).ssid_utf8);
}

// G16E contract change: N NUL bytes are their own SsidKind (HiddenNul), still a
// hidden name (hidden_ssid), never a different name. Was SsidKind::Hidden (G04).
GUARDIAN_CASE(all_zero_ssid_of_nonzero_length_is_hidden_but_keeps_its_length) {
    Frame g = mgmt_header(0x80, 0x00, BROADCAST, BSSID, BSSID, 1);
    for (int i = 0; i < 8; ++i) g.u8(0);
    g.le16(100).le16(0x0011);
    g.ie(0, {0, 0, 0, 0, 0, 0, 0, 0});
    g.ie(3, {6});
    const ParseResult r = parse(g.b);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.ssid_kind, SsidKind::HiddenNul);
    CHECK(hidden_ssid(r.ssid_kind));
    CHECK_EQ(r.identity.ssid_size, 8); // length is identity; the distinction from a zero-length SSID is kept
    CHECK(!r.ssid_utf8);
    for (int i = 0; i < 8; ++i) CHECK_EQ(r.identity.ssid[static_cast<std::size_t>(i)], 0);
}

GUARDIAN_CASE(absent_ssid_element_is_absent_not_hidden) {
    Frame g = mgmt_header(0x80, 0x00, BROADCAST, BSSID, BSSID, 1);
    for (int i = 0; i < 8; ++i) g.u8(0);
    g.le16(100).le16(0x0001);
    g.ie(3, {6});
    const ParseResult r = parse(g.b);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.ssid_kind, SsidKind::Absent);
    CHECK_EQ(r.identity.ssid_size, 0);
}

GUARDIAN_CASE(oversized_ssid_element_is_rejected_not_truncated_to_32) {
    Frame g = mgmt_header(0x80, 0x00, BROADCAST, BSSID, BSSID, 1);
    for (int i = 0; i < 8; ++i) g.u8(0);
    g.le16(100).le16(0x0001);
    std::vector<std::uint8_t> ssid(33, 'a');
    g.ie(0, ssid);
    g.ie(3, {6});
    const ParseResult r = parse(g.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::BadElementLength);
    CHECK_EQ(r.ssid_kind, SsidKind::Absent);
    CHECK_EQ(r.identity.ssid_size, 0);
    CHECK(r.settings.ds_channel_present); // later independent element still read
    CHECK(!r.settings_complete);
}

GUARDIAN_CASE(conflicting_duplicate_ssid_elements_invalidate_the_identity) {
    Frame g = beacon_head(0x0001);
    g.ie(0, {'h', 'o', 'm', 'E'});
    const ParseResult r = parse(g.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::DuplicateConflict);
    CHECK_EQ(r.ssid_kind, SsidKind::Absent);
    CHECK_EQ(r.identity.ssid_size, 0);
    CHECK(r.header_valid); // BSSID identity from the header remains usable
    // An identical duplicate is tolerated.
    Frame same = beacon_head(0x0001);
    same.ie(0, {'h', 'o', 'm', 'e'});
    const ParseResult s = parse(same.b);
    CHECK_EQ(s.status, ParseStatus::Complete);
    CHECK_EQ(s.ssid_kind, SsidKind::Present);
}

GUARDIAN_CASE(ds_parameter_set_must_be_one_byte) {
    Frame g = mgmt_header(0x80, 0x00, BROADCAST, BSSID, BSSID, 1);
    for (int i = 0; i < 8; ++i) g.u8(0);
    g.le16(100).le16(0x0001);
    g.ie(0, {'h'});
    g.ie(3, {6, 7});
    const ParseResult r = parse(g.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::BadElementLength);
    CHECK(!r.settings.ds_channel_present);
    CHECK_EQ(r.settings.ds_channel, 0);
    CHECK_EQ(r.ssid_kind, SsidKind::Present); // independent field survives
    Frame dup = beacon_head(0x0001);
    dup.ie(3, {11});
    const ParseResult d = parse(dup.b);
    CHECK_EQ(d.status, ParseStatus::Malformed);
    CHECK_EQ(d.error, ParseError::DuplicateConflict);
    CHECK(!d.settings.ds_channel_present);
}

// ---- fixed body and truncation ------------------------------------------------------------
GUARDIAN_CASE(short_fixed_body_has_valid_header_but_no_settings) {
    Fixture f;
    if (!load(c_, "beacon_open", f)) return;
    std::vector<std::uint8_t> b(f.bytes.begin(), f.bytes.begin() + 24 + 11); // one byte short of Capability
    const ParseResult r = parse(b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::ShortFixedBody);
    CHECK(r.header_valid);
    CHECK(std::equal(r.identity.bssid.begin(), r.identity.bssid.end(), BSSID.begin()));
    CHECK(!r.settings.privacy_valid);
    CHECK(!r.settings_present);
    CHECK(!r.settings_complete);
    const ParseResult t = parse(b, true);
    CHECK_EQ(t.status, ParseStatus::Truncated);
    CHECK_EQ(t.error, ParseError::ShortFixedBody);
    // Exactly the fixed body and no elements is structurally complete (no SSID element: Absent).
    std::vector<std::uint8_t> fixed_only(f.bytes.begin(), f.bytes.begin() + 36);
    const ParseResult e = parse(fixed_only);
    CHECK_EQ(e.status, ParseStatus::Complete);
    CHECK(e.settings.privacy_valid);
    CHECK_EQ(e.ssid_kind, SsidKind::Absent);
}

GUARDIAN_CASE(truncated_rsn_fixture_is_truncated_with_ie_overrun_and_no_rsn_fields) {
    Fixture f;
    if (!load(c_, "beacon_rsn_truncated_ie", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Truncated);
    CHECK_EQ(r.error, ParseError::IeOverrun);
    CHECK(r.header_valid);
    CHECK_EQ(r.settings.rsn.state, ElementState::Truncated);
    CHECK(element_zeroed(r.settings.rsn));
    CHECK(r.settings.privacy_valid);
    CHECK(r.settings.privacy_bit);
    CHECK_EQ(r.ssid_kind, SsidKind::Present);
    CHECK(r.settings_present);    // privacy bit, SSID and DS channel are valid independent facts
    CHECK(!r.settings_complete);  // never a complete grade, never "open"
}

GUARDIAN_CASE(adapter_truncation_flag_demotes_a_clean_decode_to_truncated) {
    Fixture f;
    if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", f)) return;
    const ParseResult r = parse(f.bytes, true);
    CHECK_EQ(r.status, ParseStatus::Truncated);
    CHECK_EQ(r.error, ParseError::None);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid); // what was fully read stays as partial evidence
    CHECK_EQ(r.settings.rsn.pmf, Pmf::Optional);
    CHECK(r.settings_present);
    CHECK(!r.settings_complete);
}

GUARDIAN_CASE(dangling_single_byte_after_elements_is_truncated) {
    Fixture f;
    if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", f)) return;
    std::vector<std::uint8_t> b = f.bytes;
    b.push_back(0xdd);
    const ParseResult r = parse(b);
    CHECK_EQ(r.status, ParseStatus::Truncated);
    CHECK_EQ(r.error, ParseError::IeOverrun);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK(!r.settings_complete);
}

// ---- RSN element rules -------------------------------------------------------------------------
GUARDIAN_CASE(pairwise_count_256_fixture_is_suite_count_overflow) {
    Fixture f;
    if (!load(c_, "beacon_rsn_pairwise_count_256", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::SuiteCountOverflow);
    CHECK_EQ(r.settings.rsn.state, ElementState::Malformed);
    CHECK(element_zeroed(r.settings.rsn)); // no low-byte misread into "0 suites, success"
    CHECK(r.settings.privacy_valid);
    CHECK(r.settings_present);
    CHECK(!r.settings_complete);
}

GUARDIAN_CASE(zero_suite_counts_are_rejected_not_defaulted) {
    Frame p = beacon_head(0x0011);
    p.ie(48, rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_PSK}, 0x0080, /*pairwise_count=*/0));
    const ParseResult rp = parse(p.b);
    CHECK_EQ(rp.status, ParseStatus::Malformed);
    CHECK_EQ(rp.error, ParseError::SuiteCountZero);
    CHECK_EQ(rp.settings.rsn.state, ElementState::Malformed);
    CHECK(element_zeroed(rp.settings.rsn));
    Frame a = beacon_head(0x0011);
    a.ie(48, rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_PSK}, 0x0080, -1, /*akm_count=*/0));
    const ParseResult ra = parse(a.b);
    CHECK_EQ(ra.status, ParseStatus::Malformed);
    CHECK_EQ(ra.error, ParseError::SuiteCountZero);
    CHECK(element_zeroed(ra.settings.rsn));
}

GUARDIAN_CASE(count_above_capacity_rejects_the_element_instead_of_keeping_a_prefix) {
    std::vector<std::uint32_t> seventeen(17, RSN_CCMP128);
    Frame f = beacon_head(0x0011);
    f.ie(48, rsn(RSN_CCMP128, seventeen, {RSN_AKM_PSK}, 0x0080)); // 2+4+2+68+2+4+2 = 84 bytes, fits in one element
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::SuiteCountOverflow);
    CHECK_EQ(r.settings.rsn.state, ElementState::Malformed);
    CHECK_EQ(r.settings.rsn.pairwise.count, 0);
    CHECK(element_zeroed(r.settings.rsn));
    // Exactly the capacity (16) is accepted.
    std::vector<std::uint32_t> sixteen(16, RSN_CCMP128);
    Frame g = beacon_head(0x0011);
    g.ie(48, rsn(RSN_CCMP128, sixteen, {RSN_AKM_PSK}, 0x0080));
    const ParseResult s = parse(g.b);
    CHECK_EQ(s.status, ParseStatus::Complete);
    CHECK_EQ(s.settings.rsn.pairwise.count, 16);
}

GUARDIAN_CASE(count_larger_than_remaining_bytes_is_overflow_even_when_below_capacity) {
    // Declared 4 pairwise suites (16 bytes) with 12 bytes left in the element.
    Frame f = beacon_head(0x0011);
    f.ie(48, rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_PSK}, 0x0080, /*pairwise_count=*/4));
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::SuiteCountOverflow);
    CHECK_EQ(r.settings.rsn.state, ElementState::Malformed);
    CHECK(element_zeroed(r.settings.rsn));
    // Declared 3 with exactly 12 bytes left is structurally plausible: the AKM count
    // and PSK bytes are consumed as two selectors nobody maps. It stays Complete but
    // not understood; a wrong count is indistinguishable from unknown vendor suites.
    Frame g = beacon_head(0x0011);
    g.ie(48, rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_PSK}, 0x0080, /*pairwise_count=*/3));
    const ParseResult s = parse(g.b);
    CHECK_EQ(s.status, ParseStatus::Complete);
    CHECK_EQ(s.settings.rsn.pairwise.count, 3);
    CHECK((s.settings.rsn.pairwise.kinds & cipher::Unknown) != 0);
    CHECK(!s.settings_complete);
}

GUARDIAN_CASE(minimal_rsn_gets_documented_defaults) {
    Fixture f;
    if (!load(c_, "beacon_rsn_minimal_version_only", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    const SecurityElement& e = r.settings.rsn;
    CHECK_EQ(e.state, ElementState::Valid);
    CHECK(!e.group.present);
    CHECK_EQ(e.group.selector, RSN_CCMP128);
    CHECK_EQ(e.group.kind, cipher::Ccmp128);
    CHECK_EQ(e.pairwise.count, 1);
    CHECK_EQ(e.pairwise.selectors[0], RSN_CCMP128);
    CHECK_EQ(e.pairwise.kinds, cipher::Ccmp128);
    CHECK_EQ(e.akms.count, 1);
    CHECK_EQ(e.akms.selectors[0], RSN_AKM_EAP);
    CHECK_EQ(e.akms.kinds, akm::Eap);
    CHECK_EQ(e.pmf, Pmf::Disabled);
    CHECK(!e.group_management.present);
    CHECK_EQ(e.group_management.kind, cipher::BipCmac128);
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(rsn_without_capabilities_defaults_pmf_disabled_and_is_complete) {
    Frame f = beacon_head(0x0011);
    f.ie(48, rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_PSK})); // ends after the AKM list (libwifi over-reads here)
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK_EQ(r.settings.rsn.pmf, Pmf::Disabled);
    CHECK_EQ(r.settings.rsn.akms.kinds, akm::Psk);
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(rsn_with_pmkid_and_group_management_fixture_is_complete) {
    Fixture f;
    if (!load(c_, "beacon_rsn_pmkid_group_mgmt", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    const SecurityElement& e = r.settings.rsn;
    CHECK_EQ(e.state, ElementState::Valid);
    CHECK_EQ(e.pmf, Pmf::Required);
    CHECK(e.group_management.present);
    CHECK_EQ(e.group_management.selector, RSN_BIP_GMAC256);
    CHECK_EQ(e.group_management.kind, cipher::BipGmac256);
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(pmkid_count_beyond_the_element_is_rejected) {
    Frame f = beacon_head(0x0011);
    std::vector<std::uint8_t> body = rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_SAE}, 0x00c0);
    body.push_back(0x02); body.push_back(0x00);              // PMKID count 2
    for (int i = 0; i < 16; ++i) body.push_back(0x11);      // only one PMKID present
    f.ie(48, body);
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::BadElementLength);
    CHECK_EQ(r.settings.rsn.state, ElementState::Malformed);
    CHECK(element_zeroed(r.settings.rsn));
}

GUARDIAN_CASE(group_management_cipher_cut_inside_is_bad_element_length) {
    // caps + PMKID count 0, then 1..3 bytes of a 4-byte group management cipher (m9 mutant witness).
    for (std::size_t partial : {std::size_t{1}, std::size_t{2}, std::size_t{3}}) {
        std::vector<std::uint8_t> body = rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_SAE}, 0x00c0);
        body.push_back(0x00); body.push_back(0x00);                         // PMKID count 0
        for (std::size_t i = 0; i < partial; ++i) body.push_back(0x00);     // cut selector
        Frame f = beacon_head(0x0011);
        f.ie(48, body);
        const ParseResult r = parse(f.b);
        CHECK_EQ(r.status, ParseStatus::Malformed);
        CHECK_EQ(r.error, ParseError::BadElementLength);
        CHECK_EQ(r.settings.rsn.state, ElementState::Malformed);
        CHECK(element_zeroed(r.settings.rsn));
    }
    // PMKID count 0 and no group management cipher is a clean stop: Valid with the default.
    std::vector<std::uint8_t> body = rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_SAE}, 0x00c0);
    body.push_back(0x00); body.push_back(0x00);
    Frame g = beacon_head(0x0011);
    g.ie(48, body);
    const ParseResult s = parse(g.b);
    CHECK_EQ(s.status, ParseStatus::Complete);
    CHECK_EQ(s.settings.rsn.state, ElementState::Valid);
    CHECK(!s.settings.rsn.group_management.present);
    CHECK_EQ(s.settings.rsn.group_management.kind, cipher::BipCmac128);
}

GUARDIAN_CASE(pmf_required_without_capable_is_inconsistent) {
    Fixture f;
    if (!load(c_, "beacon_rsn_pmf_inconsistent", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::PmfInconsistent);
    CHECK_EQ(r.settings.rsn.state, ElementState::Malformed);
    CHECK_EQ(r.settings.rsn.pmf, Pmf::Unknown);
    CHECK(element_zeroed(r.settings.rsn));
    CHECK(r.settings.privacy_valid);
    CHECK(!r.settings_complete);
}

GUARDIAN_CASE(rsn_version_other_than_one_is_unsupported_version) {
    Frame f = beacon_head(0x0011);
    std::vector<std::uint8_t> body = rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_PSK}, 0x0080);
    body[0] = 2; // version 2
    f.ie(48, body);
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::UnsupportedVersion);
    CHECK_EQ(r.settings.rsn.state, ElementState::Malformed);
    CHECK(element_zeroed(r.settings.rsn));
    Frame g = beacon_head(0x0011);
    g.ie(48, {0x01}); // one byte: not even a version
    const ParseResult s = parse(g.b);
    CHECK_EQ(s.status, ParseStatus::Malformed);
    CHECK_EQ(s.error, ParseError::BadElementLength);
}

GUARDIAN_CASE(field_cut_inside_the_rsn_element_is_bad_element_length) {
    for (std::size_t cut : {std::size_t{3}, std::size_t{5}, std::size_t{7}, std::size_t{9}, std::size_t{13}, std::size_t{17}, std::size_t{19}}) {
        std::vector<std::uint8_t> body = rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_PSK}, 0x0080); // 20 bytes
        body.resize(cut); // cut inside group (3,5), inside pairwise count (7), inside pairwise (9), inside AKM count (13), inside AKM (17), inside caps (19)
        Frame f = beacon_head(0x0011);
        f.ie(48, body);
        const ParseResult r = parse(f.b);
        CHECK_EQ(r.status, ParseStatus::Malformed);
        // A cut inside a suite LIST is "count larger than bytes remaining" (contract: SuiteCountOverflow);
        // a cut inside a fixed-size field is BadElementLength.
        const bool inside_list = cut == 9 || cut == 17;
        CHECK_EQ(r.error, inside_list ? ParseError::SuiteCountOverflow : ParseError::BadElementLength);
        CHECK_EQ(r.settings.rsn.state, ElementState::Malformed);
        CHECK(element_zeroed(r.settings.rsn));
    }
    // Clean boundaries are the documented optional-field stops and stay Valid.
    for (std::size_t stop : {std::size_t{2}, std::size_t{6}, std::size_t{12}, std::size_t{18}, std::size_t{20}}) {
        std::vector<std::uint8_t> body = rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_PSK}, 0x0080);
        body.resize(stop);
        Frame f = beacon_head(0x0011);
        f.ie(48, body);
        const ParseResult r = parse(f.b);
        CHECK_EQ(r.status, ParseStatus::Complete);
        CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    }
}

GUARDIAN_CASE(trailing_bytes_after_the_last_rsn_field_are_rejected) {
    Fixture f;
    if (!load(c_, "beacon_rsn_pmkid_group_mgmt", f)) return;
    Frame g = beacon_head(0x0011);
    const auto off = static_cast<std::ptrdiff_t>(std::strtoul(f.meta.at("rsn_offset").c_str(), nullptr, 10));
    std::vector<std::uint8_t> body(f.bytes.begin() + off + 2, f.bytes.end()); // the fixture's full RSNE body
    body.push_back(0x00);
    g.ie(48, body);
    const ParseResult r = parse(g.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::BadElementLength);
    CHECK_EQ(r.settings.rsn.state, ElementState::Malformed);
    CHECK(element_zeroed(r.settings.rsn));
}

GUARDIAN_CASE(use_group_selector_as_group_cipher_is_unknown_but_valid_in_pairwise) {
    Frame f = beacon_head(0x0011);
    f.ie(48, rsn(make_selector(oui::Ieee8021, 0), {make_selector(oui::Ieee8021, 0)}, {RSN_AKM_PSK}, 0x0080));
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK_EQ(r.settings.rsn.group.kind, cipher::Unknown);     // "use group" has no meaning as the group cipher
    CHECK_EQ(r.settings.rsn.pairwise.kinds, cipher::UseGroup);
    CHECK(!r.settings_complete);                              // Unknown anywhere blocks completeness
}

GUARDIAN_CASE(duplicate_rsn_identical_is_tolerated_conflicting_is_rejected) {
    Fixture f;
    if (!load(c_, "beacon_rsn_duplicate_conflict", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::DuplicateConflict);
    CHECK_EQ(r.settings.rsn.state, ElementState::Conflicting);
    CHECK(element_zeroed(r.settings.rsn)); // never a union of PSK and SAE
    CHECK(r.settings.privacy_valid);
    CHECK(r.settings_present);
    CHECK(!r.settings_complete);
    Frame same = beacon_head(0x0011);
    const std::vector<std::uint8_t> body = rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_PSK}, 0x0080);
    same.ie(48, body);
    same.ie(48, body);
    const ParseResult s = parse(same.b);
    CHECK_EQ(s.status, ParseStatus::Complete);
    CHECK_EQ(s.settings.rsn.state, ElementState::Valid);
    CHECK_EQ(s.settings.rsn.akms.count, 1);
}

// ---- WPA vendor element ----------------------------------------------------------------------
GUARDIAN_CASE(wpa1_vendor_fixture_decodes_a_separate_wpa_record) {
    Fixture f;
    if (!load(c_, "beacon_wpa1_tkip_vendor", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    const SecurityElement& w = r.settings.wpa;
    CHECK_EQ(w.state, ElementState::Valid);
    CHECK_EQ(w.akms.count, 1);
    CHECK_EQ(w.akms.selectors[0], WPA_AKM_PSK);
    CHECK_EQ(w.akms.kinds, akm::Wpa1Psk);
    CHECK_EQ(w.pairwise.count, 1);
    CHECK_EQ(w.pairwise.selectors[0], WPA_TKIP);
    CHECK_EQ(w.pairwise.kinds, cipher::Tkip);
    CHECK(w.group.present);
    CHECK_EQ(w.group.kind, cipher::Tkip);
    CHECK_EQ(w.pmf, Pmf::Unknown);          // PMF is never attributed to WPA
    CHECK(!w.group_management.present);
    CHECK_EQ(w.group_management.selector, 0u);
    CHECK_EQ(r.settings.rsn.state, ElementState::Absent);
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(wpa_and_rsn_fixture_keeps_two_independent_records) {
    Fixture f;
    if (!load(c_, "beacon_wpa_and_rsn_mixed", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.settings.wpa.state, ElementState::Valid);
    CHECK_EQ(r.settings.wpa.group.kind, cipher::Tkip);
    CHECK_EQ(r.settings.wpa.akms.kinds, akm::Wpa1Psk);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK_EQ(r.settings.rsn.group.kind, cipher::Ccmp128);
    CHECK_EQ(r.settings.rsn.akms.kinds, akm::Psk);
    CHECK_EQ(r.settings.rsn.pmf, Pmf::Optional);
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(malformed_wpa_does_not_erase_a_valid_rsn_sibling) {
    Frame f = beacon_head(0x0011);
    f.ie(221, wpa(WPA_TKIP, {WPA_TKIP}, {WPA_AKM_PSK}, /*pairwise_count=*/9));
    f.ie(48, rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_PSK}, 0x0080));
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::SuiteCountOverflow);
    CHECK_EQ(r.settings.wpa.state, ElementState::Malformed);
    CHECK(element_zeroed(r.settings.wpa));
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid); // partial evidence survives
    CHECK_EQ(r.settings.rsn.pmf, Pmf::Optional);
    CHECK(r.settings_present);
    CHECK(!r.settings_complete);
}

GUARDIAN_CASE(malformed_rsn_does_not_erase_a_valid_wpa_sibling) {
    Frame f = beacon_head(0x0011);
    f.ie(221, wpa(WPA_TKIP, {WPA_TKIP}, {WPA_AKM_PSK}));
    f.ie(48, rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_PSK}, 0x0040)); // MFPR without MFPC
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::PmfInconsistent);
    CHECK_EQ(r.settings.rsn.state, ElementState::Malformed);
    CHECK_EQ(r.settings.wpa.state, ElementState::Valid); // legacy-risk evidence G05 may report
    CHECK_EQ(r.settings.wpa.pairwise.kinds, cipher::Tkip);
    CHECK(!r.settings_complete);
}

GUARDIAN_CASE(wpa_minimal_version_only_gets_wpa_defaults) {
    Frame f = beacon_head(0x0011);
    f.ie(221, {0x00, 0x50, 0xf2, 0x01, 0x01, 0x00});
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Complete);
    const SecurityElement& w = r.settings.wpa;
    CHECK_EQ(w.state, ElementState::Valid);
    CHECK(!w.group.present);
    CHECK_EQ(w.group.kind, cipher::Tkip);
    CHECK_EQ(w.pairwise.count, 1);
    CHECK_EQ(w.pairwise.kinds, cipher::Tkip);
    CHECK_EQ(w.akms.count, 1);
    CHECK_EQ(w.akms.kinds, akm::Wpa1Eap);
    CHECK_EQ(w.akms.selectors[0], make_selector(oui::Microsoft, 1));
    Frame g = beacon_head(0x0011);
    g.ie(221, {0x00, 0x50, 0xf2, 0x01, 0x02, 0x00}); // WPA version 2 does not exist
    const ParseResult s = parse(g.b);
    CHECK_EQ(s.status, ParseStatus::Malformed);
    CHECK_EQ(s.error, ParseError::UnsupportedVersion);
    CHECK_EQ(s.settings.wpa.state, ElementState::Malformed);
}

GUARDIAN_CASE(wpa_unknown_selectors_and_capabilities_are_handled) {
    Frame f = beacon_head(0x0011);
    std::vector<std::uint8_t> body = wpa(WPA_TKIP, {make_selector(oui::Microsoft, 4), make_selector(oui::Microsoft, 9)}, {WPA_AKM_PSK});
    body.push_back(0x00); body.push_back(0x00); // WPA capabilities (optional, ignored)
    f.ie(221, body);
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.settings.wpa.state, ElementState::Valid);
    CHECK_EQ(r.settings.wpa.pairwise.kinds, static_cast<std::uint16_t>(cipher::Ccmp128 | cipher::Unknown));
    CHECK_EQ(r.settings.wpa.pairwise.selectors[1], make_selector(oui::Microsoft, 9));
    CHECK(!r.settings_complete);
    Frame g = beacon_head(0x0011);
    body.push_back(0x00); // one trailing byte after capabilities
    g.ie(221, body);
    const ParseResult s = parse(g.b);
    CHECK_EQ(s.status, ParseStatus::Malformed);
    CHECK_EQ(s.error, ParseError::BadElementLength);
}

GUARDIAN_CASE(conflicting_duplicate_wpa_is_conflicting) {
    Frame f = beacon_head(0x0011);
    f.ie(221, wpa(WPA_TKIP, {WPA_TKIP}, {WPA_AKM_PSK}));
    f.ie(221, wpa(WPA_TKIP, {make_selector(oui::Microsoft, 4)}, {WPA_AKM_PSK}));
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::DuplicateConflict);
    CHECK_EQ(r.settings.wpa.state, ElementState::Conflicting);
    CHECK(element_zeroed(r.settings.wpa));
}

// ---- vendor and unknown elements --------------------------------------------------------------
GUARDIAN_CASE(vendor_element_shorter_than_its_oui_is_bad_vendor_oui) {
    Frame f = beacon_head(0x0011);
    f.ie(221, {0x00, 0x50});
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::BadVendorOui);
    CHECK(r.settings.privacy_valid);
    CHECK(!r.settings_complete);
}

GUARDIAN_CASE(unknown_vendor_and_unknown_elements_are_skipped_by_length) {
    Frame f = beacon_head(0x0011);
    f.ie(221, {0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x80, 0x00}); // WMM (00-50-F2 type 2): not security, skipped
    f.ie(221, {0x00, 0x50, 0xf2});                               // OUI only, no type: skipped
    f.ie(221, {0x50, 0x6f, 0x9a, 0x09, 0x30, 0x14});             // WFA P2P (type 9) whose body happens to look like an RSNE header: skipped, not an RSNE
    f.ie(45, std::vector<std::uint8_t>(26, 0x30));              // HT Capabilities full of 0x30 bytes: skipped by length
    f.ie(48, rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_SAE}, 0x00c0));
    f.ie(0xdd, {0x00, 0x11, 0x22, 0x33});                       // unknown vendor after the RSNE
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK_EQ(r.settings.rsn.akms.kinds, akm::Sae);
    CHECK_EQ(r.settings.wpa.state, ElementState::Absent);
    CHECK(r.settings_complete);
}

GUARDIAN_CASE(protected_bit_on_a_beacon_is_malformed) {
    Fixture f;
    if (!load(c_, "beacon_wpa2_ccmp_pmf_optional", f)) return;
    std::vector<std::uint8_t> b = f.bytes;
    b[1] = static_cast<std::uint8_t>(b[1] | 0x40);
    const ParseResult r = parse(b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK(r.protected_frame);
    CHECK(r.header_valid);
    CHECK(!r.settings_present);
    CHECK(!r.settings_complete);
}

// ---- disconnect frames -------------------------------------------------------------------------
GUARDIAN_CASE(deauth_fixture_reason_is_readable) {
    Fixture f;
    if (!load(c_, "deauth_reason7", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.kind, FrameKind::Deauthentication);
    CHECK(r.header_valid);
    CHECK(std::equal(r.addr1.begin(), r.addr1.end(), STATION.begin()));
    CHECK(std::equal(r.identity.bssid.begin(), r.identity.bssid.end(), BSSID.begin()));
    CHECK_EQ(r.sequence, 4);
    CHECK(!r.protected_frame);
    CHECK(!r.retry);
    CHECK(r.reason_readable);
    CHECK_EQ(r.reason_code, 7);
    CHECK(!r.settings_present); // no advertised settings in a disconnect frame
    CHECK(!r.settings_complete);
    CHECK_EQ(r.ssid_kind, SsidKind::Absent);
}

GUARDIAN_CASE(disassoc_fixture_reports_retry_and_reason) {
    Fixture f;
    if (!load(c_, "disassoc_retry_reason8", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.kind, FrameKind::Disassociation);
    CHECK(r.retry);
    CHECK(r.reason_readable);
    CHECK_EQ(r.reason_code, 8);
    CHECK_EQ(r.sequence, 4);
}

GUARDIAN_CASE(protected_unicast_deauth_is_unsupported_with_unreadable_reason) {
    Fixture f;
    if (!load(c_, "deauth_protected_unicast", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Unsupported);
    CHECK_EQ(r.error, ParseError::None);
    CHECK_EQ(r.kind, FrameKind::Deauthentication);
    CHECK(r.header_valid);
    CHECK(r.protected_frame);
    CHECK(!r.reason_readable);
    CHECK_EQ(r.reason_code, 0);
}

GUARDIAN_CASE(group_deauth_with_mme_is_structurally_readable_but_not_verified) {
    Fixture f;
    if (!load(c_, "deauth_group_mme", f)) return;
    const ParseResult r = parse(f.bytes);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.kind, FrameKind::Deauthentication);
    CHECK(!r.protected_frame);
    CHECK(r.reason_readable);
    CHECK_EQ(r.reason_code, 1);
    // An MME of the wrong length is malformed and makes the reason untrusted.
    std::vector<std::uint8_t> b = f.bytes;
    b[27] = 5; b.resize(26 + 2 + 5);
    const ParseResult s = parse(b);
    CHECK_EQ(s.status, ParseStatus::Malformed);
    CHECK_EQ(s.error, ParseError::BadElementLength);
    CHECK(!s.reason_readable);
    CHECK(s.header_valid);
}

GUARDIAN_CASE(deauth_body_shorter_than_the_reason_code_is_short_fixed_body) {
    Fixture f;
    if (!load(c_, "deauth_reason7", f)) return;
    std::vector<std::uint8_t> b(f.bytes.begin(), f.bytes.begin() + 25);
    const ParseResult r = parse(b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::ShortFixedBody);
    CHECK(r.header_valid);
    CHECK(!r.reason_readable);
    const ParseResult t = parse(b, true);
    CHECK_EQ(t.status, ParseStatus::Truncated);
    CHECK(!t.reason_readable);
}

GUARDIAN_CASE(deauth_trailing_element_overrun_is_truncated_but_the_reason_stays_readable) {
    Fixture f;
    if (!load(c_, "deauth_reason7", f)) return;
    std::vector<std::uint8_t> b = f.bytes;
    b.push_back(0xdd); b.push_back(0x10); b.push_back(0x00); // vendor element claiming 16 bytes, 1 present
    const ParseResult r = parse(b);
    CHECK_EQ(r.status, ParseStatus::Truncated);
    CHECK_EQ(r.error, ParseError::IeOverrun);
    CHECK(r.reason_readable); // the fixed field was complete; the tail was cut
    CHECK_EQ(r.reason_code, 7);
    // A complete vendor element after the reason is allowed (9.3.3.12) and stays Complete.
    std::vector<std::uint8_t> v = f.bytes;
    v.push_back(0xdd); v.push_back(0x04); v.push_back(0x00); v.push_back(0x11); v.push_back(0x22); v.push_back(0x01);
    const ParseResult s = parse(v);
    CHECK_EQ(s.status, ParseStatus::Complete);
    CHECK(s.reason_readable);
}

// ---- other frame types -----------------------------------------------------------------------
// G16E contract change: (re)association request/response (0..3), probe request (4) and
// authentication (11) bodies are now decoded (tests/mgmt_parser_check.cpp); they are
// Complete here and still never settings. Action (13) and other subtypes stay Unsupported.
GUARDIAN_CASE(other_management_subtypes_have_valid_headers_and_unsupported_bodies) {
    for (std::uint8_t subtype : {std::uint8_t{0}, std::uint8_t{1}, std::uint8_t{11}, std::uint8_t{13}, std::uint8_t{4}, std::uint8_t{6}}) {
        Frame f = mgmt_header(static_cast<std::uint8_t>(subtype << 4), 0x00, BSSID, STATION, BSSID, 9);
        f.le16(0).le16(0).le16(0);
        const ParseResult r = parse(f.b);
        const bool decoded = subtype == 0 || subtype == 1 || subtype == 11 || subtype == 4;
        CHECK_EQ(r.status, decoded ? ParseStatus::Complete : ParseStatus::Unsupported);
        CHECK(r.header_valid);
        CHECK(!r.settings_present);
        CHECK(!r.reason_readable);
        const FrameKind expected = subtype == 0 ? FrameKind::AssociationRequest
                                 : subtype == 1 ? FrameKind::AssociationResponse
                                 : subtype == 11 ? FrameKind::Authentication
                                 : subtype == 13 ? FrameKind::Action
                                 : subtype == 4 ? FrameKind::ProbeRequest : FrameKind::OtherManagement;
        CHECK_EQ(r.kind, expected);
    }
}

GUARDIAN_CASE(control_frames_are_unrelated_without_header_claims) {
    const std::vector<std::uint8_t> ack{0xd4, 0x00, 0x00, 0x00, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55}; // ACK: 10 bytes
    const ParseResult r = parse(ack);
    CHECK_EQ(r.status, ParseStatus::Unrelated);
    CHECK_EQ(r.kind, FrameKind::Control);
    CHECK(!r.header_valid);
    CHECK(!r.settings_present);
}

GUARDIAN_CASE(data_frames_are_unrelated_but_carry_header_identity) {
    Frame f;
    f.u8(0x08).u8(0x02).le16(0).raw(STATION).raw(BSSID).raw(BSSID).le16(0x0050); // FromDS: addr2 is the BSSID
    f.raw({0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45});
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Unrelated);
    CHECK_EQ(r.kind, FrameKind::Data);
    CHECK(r.header_valid);
    CHECK(std::equal(r.identity.bssid.begin(), r.identity.bssid.end(), BSSID.begin()));
    CHECK_EQ(r.sequence, 5);
    CHECK(!r.settings_present);
    Frame s; // 20 bytes: shorter than a data header
    s.u8(0x08).u8(0x00).le16(0).raw(STATION).raw(BSSID).raw({0, 0, 0, 0});
    const ParseResult rs = parse(s.b);
    CHECK_EQ(rs.status, ParseStatus::Unrelated);
    CHECK(!rs.header_valid);
}

GUARDIAN_CASE(eapol_data_is_recognized_by_llc_snap_and_a_cut_key_body_is_malformed) {
    // G16G (intended expectation change): EAPOL-Key bodies are now decoded
    // (datapath_check). This header claims a 95-byte key body that is absent,
    // so the frame is Malformed with no key facts; it is still EapolData.
    Frame f;
    f.u8(0x08).u8(0x02).le16(0).raw(STATION).raw(BSSID).raw(BSSID).le16(0x0060);
    f.raw({0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e, 0x02, 0x03, 0x00, 0x5f});
    const ParseResult r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.eapol.state, ElementState::Malformed);
    CHECK_EQ(r.eapol.message, EapolMessage::None);
    CHECK_EQ(r.kind, FrameKind::EapolData);
    CHECK(r.header_valid);
    // QoS data (subtype 8) adds a 2-byte QoS Control field before the LLC header.
    Frame q;
    q.u8(0x88).u8(0x02).le16(0).raw(STATION).raw(BSSID).raw(BSSID).le16(0x0060).le16(0x0006);
    q.raw({0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e, 0x02});
    const ParseResult rq = parse(q.b);
    CHECK_EQ(rq.kind, FrameKind::EapolData);
    // Protected data is never inspected for EAPOL.
    Frame p;
    p.u8(0x08).u8(0x42).le16(0).raw(STATION).raw(BSSID).raw(BSSID).le16(0x0060);
    p.raw({0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e});
    const ParseResult rp = parse(p.b);
    CHECK_EQ(rp.kind, FrameKind::Data);
    CHECK_EQ(rp.status, ParseStatus::Unrelated);
    CHECK(rp.protected_frame);
}

// ---- allocation, pointers and whole-fixture sweeps ----------------------------------------
namespace {
bool g_forbid_allocation = false;
}
void* operator new(std::size_t n) {
    if (g_forbid_allocation) std::abort(); // the parser must not allocate; this is the "allocator failure" case
    void* p = std::malloc(n ? n : 1);
    if (!p) throw std::bad_alloc();
    return p;
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

GUARDIAN_CASE(parser_allocates_nothing_even_when_the_allocator_would_fail) {
    const auto names = fixtures::list();
    CHECK(names.size() >= 25);
    std::vector<Fixture> loaded(names.size());
    for (std::size_t i = 0; i < names.size(); ++i) {
        std::string err;
        if (!fixtures::load(names[i], loaded[i], err)) { CHECK_FAIL(err); return; }
    }
    std::vector<ParseResult> results(loaded.size()); // allocated before the window
    g_forbid_allocation = true;
    for (std::size_t i = 0; i < loaded.size(); ++i) results[i] = parse(loaded[i].bytes); // abort() here = failure
    g_forbid_allocation = false;
    std::size_t complete = 0;
    for (const auto& r : results) if (r.status == ParseStatus::Complete) ++complete;
    CHECK(complete >= 15);
}

GUARDIAN_CASE(every_fixture_parses_with_a_valid_header_and_consistent_flags) {
    for (const auto& name : fixtures::list()) {
        Fixture f;
        std::string err;
        if (!fixtures::load(name, f, err)) { CHECK_FAIL(err); continue; }
        const ParseResult r = parse(f.bytes);
        check_invariants(c_, r, name.c_str());
        if (name != "mgmt_header_short_23" && !r.header_valid) CHECK_FAIL(name + ": header should be valid");
        if (name.rfind("beacon_", 0) == 0 || name.rfind("probe_", 0) == 0) {
            if (!r.settings.privacy_valid) CHECK_FAIL(name + ": privacy should be valid");
        }
    }
}

GUARDIAN_CASE(byte_mutation_sweep_never_breaks_invariants) {
    // Deterministic sweep: every byte of several fixtures replaced by a few values,
    // plus every prefix length. Sanitizers (reviewer run) make over-reads fatal.
    const char* names[] = {"beacon_wpa_and_rsn_mixed", "beacon_rsn_pmkid_group_mgmt", "beacon_owe_transition",
                           "beacon_rsn_four_pairwise", "deauth_group_mme", "beacon_ht_control_order_bit"};
    const std::uint8_t values[] = {0x00, 0x01, 0x10, 0x30, 0x7f, 0x80, 0xdd, 0xff};
    std::size_t parses = 0;
    for (const char* name : names) {
        Fixture f;
        if (!load(c_, name, f)) continue;
        for (std::size_t i = 0; i < f.bytes.size(); ++i) {
            for (std::uint8_t v : values) {
                std::vector<std::uint8_t> b = f.bytes;
                b[i] = v;
                check_invariants(c_, parse(b), name);
                check_invariants(c_, parse(b, true), name);
                ++parses;
            }
        }
        for (std::size_t n = 0; n <= f.bytes.size(); ++n) {
            std::vector<std::uint8_t> b(f.bytes.begin(), f.bytes.begin() + static_cast<std::ptrdiff_t>(n));
            check_invariants(c_, parse(b), name);
            ++parses;
        }
    }
    CHECK(parses > 3000);
}


GUARDIAN_CASE(review_cipher_namespaces_do_not_cross_wpa_and_rsn) {
    const auto wrong_rsn = make_selector(oui::Microsoft, 4);
    Frame f = beacon_head(0x0011);
    f.ie(48, rsn(wrong_rsn, {wrong_rsn}, {RSN_AKM_SAE}, 0x00c0));
    const auto a = parse(f.b);
    CHECK_EQ(a.settings.rsn.group.selector, wrong_rsn);
    CHECK_EQ(a.settings.rsn.group.kind, cipher::Unknown);
    CHECK_EQ(a.settings.rsn.pairwise.kinds, cipher::Unknown);
    CHECK(!a.settings_complete);
    Frame w = beacon_head(0x0011);
    w.ie(221, wpa(RSN_CCMP128, {RSN_CCMP128}, {WPA_AKM_PSK}));
    const auto b = parse(w.b);
    CHECK_EQ(b.settings.wpa.group.kind, cipher::Unknown);
    CHECK_EQ(b.settings.wpa.pairwise.kinds, cipher::Unknown);
    CHECK(!b.settings_complete);
}
GUARDIAN_CASE(review_management_protection_requires_a_management_cipher) {
    for (auto bad : {RSN_TKIP, RSN_CCMP128, make_selector(oui::Microsoft, 4)}) {
        Frame body;
        body.raw(rsn(RSN_CCMP128, {RSN_CCMP128}, {RSN_AKM_SAE}, 0x00c0)).le16(0).sel(bad);
        Frame f = beacon_head(0x0011); f.ie(48, body.b);
        const auto a = parse(f.b);
        CHECK_EQ(a.settings.rsn.group_management.selector, bad);
        CHECK_EQ(a.settings.rsn.group_management.kind, cipher::Unknown);
        CHECK(!a.settings_complete);
    }
}
GUARDIAN_CASE(review_fragmented_advertisements_are_not_complete_settings) {
    for (bool first : {false, true}) {
        Fixture f;
        if (!load(c_, "beacon_wpa3_sae_pmf_required", f)) return;
        if (first) f.bytes[1] |= 0x04; // More Fragments, first fragment
        else f.bytes[22] |= 0x01;     // continuation fragment with plausible body bytes
        const auto a = parse(f.bytes);
        CHECK(a.header_valid);
        CHECK_EQ(a.status, ParseStatus::Unsupported);
        CHECK(!a.settings_complete);
        CHECK(!a.settings_present);
    }
}


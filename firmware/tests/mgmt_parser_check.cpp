// G16E parser platform checks: the management frames and fields the passive
// detectors need (probe requests, (re)association, authentication bodies, the
// Power Management bit, the locally administered source bit, beacon timing,
// CSA / Quiet / Multiple BSSID / element 222 and the OWE transition partner),
// and the hidden NUL-byte SSID as its own SsidKind.
//
// TDD: written and run RED against the G16D parser (new fields absent / stub
// values) before the implementation; logs: $GUARDIAN_STORE/
// builds/20261117-g16e-host/red-*.log. Fixtures come from tests/fixtures/make_fixtures.py
// (hand-assembled from IEEE 802.11-2020, Origin::Imported, never radio proof).
// Malformed and truncated bodies must stay explicit statuses, never guesses.
#include "check.hpp"
#include "fixtures.hpp"

#include "guardian/rating.hpp"
#include "guardian/security_parser.hpp"

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

ParseResult parse(const std::vector<std::uint8_t>& bytes, bool truncated = false) {
    return parser.parse(FrameSpan{bytes.data(), static_cast<std::uint16_t>(bytes.size()), truncated}, ok_meta());
}

bool load(check::Case& c_, const char* name, std::vector<std::uint8_t>& out) {
    Fixture f; std::string err;
    if (!fixtures::load(name, f, err)) { CHECK_FAIL(err); return false; }
    out = f.bytes; return true;
}

const Mac kBssid{0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
const Mac kRandom{0xda, 0xa1, 0x19, 0x00, 0x00, 0x01};

struct Frame {
    std::vector<std::uint8_t> b;
    Frame& raw(const std::vector<std::uint8_t>& v) { b.insert(b.end(), v.begin(), v.end()); return *this; }
    Frame& u8(std::uint8_t v) { b.push_back(v); return *this; }
    Frame& le16(std::uint16_t v) { b.push_back(static_cast<std::uint8_t>(v & 0xff)); b.push_back(static_cast<std::uint8_t>(v >> 8)); return *this; }
    Frame& ie(std::uint8_t id, const std::vector<std::uint8_t>& body) { u8(id); u8(static_cast<std::uint8_t>(body.size())); return raw(body); }
};
Frame header(std::uint8_t fc0, std::uint8_t fc1 = 0) {
    Frame f; f.u8(fc0).u8(fc1).le16(0);
    f.raw({0x02, 0x11, 0x22, 0x33, 0x44, 0x55}).raw({0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}).raw({0x02, 0x11, 0x22, 0x33, 0x44, 0x55});
    f.le16(0x10 << 4);
    return f;
}
Frame beacon_body() {
    Frame f = header(0x80);
    for (int i = 0; i < 8; ++i) f.u8(0);
    f.le16(100).le16(0x0011);
    f.ie(0, {'h', 'o', 'm', 'e'}).ie(3, {6});
    return f;
}

} // namespace

// ---- probe requests -------------------------------------------------------------------
GUARDIAN_CASE(wildcard_probe_request_from_a_random_source) {
    std::vector<std::uint8_t> b; if (!load(c_, "probereq_wildcard_random", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.kind, FrameKind::ProbeRequest);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK(r.header_valid);
    CHECK_EQ(r.ssid_kind, SsidKind::Wildcard);
    CHECK_EQ(r.identity.ssid_size, 0);
    CHECK(r.addr2 == kRandom);
    CHECK(r.addr2_local);
    CHECK_EQ(r.sequence, 0x0a1);
    CHECK(!r.settings_present);
}

GUARDIAN_CASE(directed_probe_request_keeps_the_requested_name_and_a_universal_source) {
    std::vector<std::uint8_t> b; if (!load(c_, "probereq_named", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.kind, FrameKind::ProbeRequest);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.ssid_kind, SsidKind::Present);
    CHECK_EQ(r.identity.ssid_size, 4);
    CHECK_EQ(r.identity.ssid[0], 'h'); CHECK_EQ(r.identity.ssid[3], 'e');
    CHECK(r.ssid_utf8);
    CHECK(!r.addr2_local);
    // A probe request is never security evidence and never a picker candidate.
    CHECK_EQ(observe_security(r, ok_meta()).parse, ParseStatus::Unrelated);
}

GUARDIAN_CASE(truncated_probe_request_never_guesses_the_name) {
    std::vector<std::uint8_t> b; if (!load(c_, "probereq_truncated_ssid", b)) return;
    const auto cut = parse(b, true);
    CHECK_EQ(cut.status, ParseStatus::Truncated);
    CHECK_EQ(cut.error, ParseError::IeOverrun);
    CHECK_EQ(cut.ssid_kind, SsidKind::Absent);
    CHECK_EQ(cut.identity.ssid_size, 0);
    const auto bad = parse(b, false); // same bytes, but the receiver says the frame was whole
    CHECK_EQ(bad.status, ParseStatus::Truncated);
    CHECK_EQ(bad.ssid_kind, SsidKind::Absent);
}

GUARDIAN_CASE(probe_request_nul_and_empty_names_are_kinds_not_names) {
    Frame p = header(0x40); p.ie(0, {0, 0, 0});
    const auto r = parse(p.b);
    CHECK_EQ(r.kind, FrameKind::ProbeRequest);
    CHECK_EQ(r.ssid_kind, SsidKind::HiddenNul);
    Frame q = header(0x40); q.ie(1, {0x82});           // no SSID element at all
    const auto a = parse(q.b);
    CHECK_EQ(a.status, ParseStatus::Complete);
    CHECK_EQ(a.ssid_kind, SsidKind::Absent);
}

// ---- authentication ------------------------------------------------------------------
GUARDIAN_CASE(open_system_authentication_fixed_fields) {
    std::vector<std::uint8_t> b; if (!load(c_, "auth_open_seq1", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.kind, FrameKind::Authentication);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK(r.mgmt.auth_valid);
    CHECK_EQ(r.mgmt.auth_algorithm, auth_algorithm::OpenSystem);
    CHECK_EQ(r.mgmt.auth_transaction, 1);
    CHECK(r.mgmt.status_valid);
    CHECK_EQ(r.mgmt.status_code, 0);
    CHECK(r.identity.bssid == kBssid);
}

GUARDIAN_CASE(sae_commit_is_algorithm_3_transaction_1_and_its_body_is_not_parsed_as_elements) {
    std::vector<std::uint8_t> b; if (!load(c_, "auth_sae_commit", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK(r.mgmt.auth_valid);
    CHECK_EQ(r.mgmt.auth_algorithm, auth_algorithm::Sae);
    CHECK_EQ(r.mgmt.auth_transaction, 1);
    CHECK(r.addr2_local);
    // SAE Confirm is transaction 2 on the same algorithm.
    Frame confirm = header(0xb0); confirm.le16(3).le16(2).le16(0).le16(0).raw(std::vector<std::uint8_t>(32, 0x5a));
    const auto c2 = parse(confirm.b);
    CHECK_EQ(c2.mgmt.auth_transaction, 2);
    CHECK_EQ(c2.status, ParseStatus::Complete);
}

GUARDIAN_CASE(short_authentication_body_is_malformed_or_truncated_never_read) {
    std::vector<std::uint8_t> b; if (!load(c_, "auth_short_body", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::ShortFixedBody);
    CHECK(!r.mgmt.auth_valid);
    CHECK_EQ(r.mgmt.auth_algorithm, 0);
    const auto t = parse(b, true);
    CHECK_EQ(t.status, ParseStatus::Truncated);
    CHECK(!t.mgmt.auth_valid);
}

GUARDIAN_CASE(protected_authentication_body_is_unsupported) {
    Frame f = header(0xb0, 0x40); f.raw(std::vector<std::uint8_t>(16, 0x77)); // shared-key seq 3: encrypted
    const auto r = parse(f.b);
    CHECK_EQ(r.kind, FrameKind::Authentication);
    CHECK_EQ(r.status, ParseStatus::Unsupported);
    CHECK(r.header_valid);
    CHECK(!r.mgmt.auth_valid);
}

// ---- (re)association -------------------------------------------------------------------
GUARDIAN_CASE(association_request_power_management_bit_and_requested_name) {
    std::vector<std::uint8_t> b; if (!load(c_, "assoc_request_pm", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.kind, FrameKind::AssociationRequest);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK(r.power_management);
    CHECK(r.mgmt.listen_interval_valid);
    CHECK_EQ(r.mgmt.listen_interval, 10);
    CHECK_EQ(r.ssid_kind, SsidKind::Present);
    CHECK_EQ(r.identity.ssid_size, 4);
    // The client's RSNE is not the AP's advertisement.
    CHECK(!r.settings_present);
    CHECK_EQ(r.settings.rsn.state, ElementState::Absent);
    CHECK_EQ(observe_security(r, ok_meta()).parse, ParseStatus::Unrelated);
}

GUARDIAN_CASE(reassociation_request_kind_current_ap_and_power_management) {
    std::vector<std::uint8_t> b; if (!load(c_, "reassoc_request_pm", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.kind, FrameKind::ReassociationRequest);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK(r.power_management);
    CHECK(r.addr2_local);
    CHECK_EQ(r.mgmt.listen_interval, 3);
    const Mac current{0x02, 0x11, 0x22, 0x33, 0x44, 0x56};
    CHECK(r.mgmt.current_ap == current);
    CHECK_EQ(r.ssid_kind, SsidKind::Present);
}

GUARDIAN_CASE(reassociation_response_status_code) {
    std::vector<std::uint8_t> b; if (!load(c_, "reassoc_response_success", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.kind, FrameKind::ReassociationResponse);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK(r.mgmt.status_valid);
    CHECK_EQ(r.mgmt.status_code, 0);
    CHECK(!r.power_management);
    // Association response (subtype 1) reads the same fixed fields.
    Frame a = header(0x10); a.le16(0x0011).le16(17).le16(0xc002);
    const auto ar = parse(a.b);
    CHECK_EQ(ar.kind, FrameKind::AssociationResponse);
    CHECK(ar.mgmt.status_valid);
    CHECK_EQ(ar.mgmt.status_code, 17);
}

GUARDIAN_CASE(short_association_bodies_are_malformed) {
    Frame req = header(0x00); req.le16(0x0011).u8(1);           // listen interval cut
    const auto r = parse(req.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::ShortFixedBody);
    CHECK(!r.mgmt.listen_interval_valid);
    Frame re = header(0x20); re.le16(0x0011).le16(3).raw({1, 2, 3}); // current AP cut
    const auto rr = parse(re.b, true);
    CHECK_EQ(rr.status, ParseStatus::Truncated);
    CHECK(!rr.mgmt.listen_interval_valid);
    Frame resp = header(0x30); resp.le16(0x0011).le16(0);         // AID missing
    const auto rs = parse(resp.b);
    CHECK_EQ(rs.status, ParseStatus::Malformed);
    CHECK(!rs.mgmt.status_valid);
}

GUARDIAN_CASE(power_management_bit_is_read_from_frame_control_only) {
    std::vector<std::uint8_t> b; if (!load(c_, "beacon_wpa3_sae_pmf_required", b)) return;
    CHECK(!parse(b).power_management);
    b[1] = static_cast<std::uint8_t>(b[1] | 0x10);
    CHECK(parse(b).power_management);
}

// ---- beacon / probe response extras -----------------------------------------------------
GUARDIAN_CASE(beacon_timing_csa_quiet_and_multiple_bssid) {
    std::vector<std::uint8_t> b; if (!load(c_, "beacon_csa_quiet_mbssid", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK(r.mgmt.timing_valid);
    CHECK_EQ(r.mgmt.tsf, 0x112233u);
    CHECK_EQ(r.mgmt.beacon_interval_tu, 100);
    CHECK_EQ(r.mgmt.csa, ElementState::Valid);
    CHECK_EQ(r.mgmt.csa_mode, 1);
    CHECK_EQ(r.mgmt.csa_new_channel, 11);
    CHECK_EQ(r.mgmt.csa_count, 5);
    CHECK_EQ(r.mgmt.quiet, ElementState::Valid);
    CHECK_EQ(r.mgmt.quiet_elements, 2);
    CHECK_EQ(r.mgmt.quiet_max_duration_tu, 1500);
    CHECK_EQ(r.mgmt.multi_bssid, ElementState::Valid);
    // The rating input is unchanged by these elements.
    CHECK(r.settings_complete);
    CHECK_EQ(r.settings.rsn.state, ElementState::Valid);
    CHECK_EQ(r.settings.rsn.akms.kinds, akm::Sae);
}

GUARDIAN_CASE(probe_response_carries_the_same_timing_fields) {
    std::vector<std::uint8_t> b; if (!load(c_, "probe_response_wpa2", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.kind, FrameKind::ProbeResponse);
    CHECK(r.mgmt.timing_valid);
    CHECK_EQ(r.mgmt.beacon_interval_tu, 100);
    CHECK_EQ(r.mgmt.csa, ElementState::Absent);
    CHECK_EQ(r.mgmt.multi_bssid, ElementState::Absent);
}

GUARDIAN_CASE(csa_with_a_bad_length_is_malformed_with_zero_fields) {
    std::vector<std::uint8_t> b; if (!load(c_, "beacon_csa_bad_length", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::BadElementLength);
    CHECK_EQ(r.mgmt.csa, ElementState::Malformed);
    CHECK_EQ(r.mgmt.csa_new_channel, 0);
    CHECK_EQ(r.mgmt.csa_count, 0);
    CHECK(!r.settings_complete);
}

GUARDIAN_CASE(conflicting_csa_copies_are_conflicting_never_merged) {
    Frame f = beacon_body(); f.ie(37, {1, 11, 5}).ie(37, {0, 1, 200});
    const auto r = parse(f.b);
    CHECK_EQ(r.status, ParseStatus::Malformed);
    CHECK_EQ(r.error, ParseError::DuplicateConflict);
    CHECK_EQ(r.mgmt.csa, ElementState::Conflicting);
    CHECK_EQ(r.mgmt.csa_count, 0);
    Frame same = beacon_body(); same.ie(37, {1, 11, 5}).ie(37, {1, 11, 5});
    const auto s = parse(same.b);
    CHECK_EQ(s.status, ParseStatus::Complete);
    CHECK_EQ(s.mgmt.csa, ElementState::Valid);
}

GUARDIAN_CASE(quiet_and_multiple_bssid_length_rules) {
    Frame q = beacon_body(); q.ie(40, {1, 0, 0x10, 0x00, 0x00});      // 5 bytes, must be 6
    const auto rq = parse(q.b);
    CHECK_EQ(rq.status, ParseStatus::Malformed);
    CHECK_EQ(rq.mgmt.quiet, ElementState::Malformed);
    CHECK_EQ(rq.mgmt.quiet_max_duration_tu, 0);
    Frame m = beacon_body(); m.ie(71, {});                           // MaxBSSID Indicator missing
    const auto rm = parse(m.b);
    CHECK_EQ(rm.status, ParseStatus::Malformed);
    CHECK_EQ(rm.mgmt.multi_bssid, ElementState::Malformed);
}

GUARDIAN_CASE(element_222_payload_is_bounded) {
    std::vector<std::uint8_t> b; if (!load(c_, "beacon_element222", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.mgmt.element222_count, 1);
    CHECK_EQ(r.mgmt.element222_bytes, 40);
    CHECK_EQ(r.mgmt.element222_head_size, ManagementFacts::element222_head_capacity);
    CHECK_EQ(r.mgmt.element222_head[0], '{');
    const Mac marked{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad};
    CHECK(r.identity.bssid == marked);
    // Two elements (255 + 100 bytes): counted and summed, the head is still bounded.
    Frame f = beacon_body(); f.ie(222, std::vector<std::uint8_t>(255, 'a')).ie(222, std::vector<std::uint8_t>(100, 'b'));
    const auto two = parse(f.b);
    CHECK_EQ(two.status, ParseStatus::Complete);
    CHECK_EQ(two.mgmt.element222_count, 2);
    CHECK_EQ(two.mgmt.element222_bytes, 355);
    CHECK_EQ(two.mgmt.element222_head_size, ManagementFacts::element222_head_capacity);
    CHECK_EQ(two.mgmt.element222_head[0], 'a');
    // An empty element 222 is counted with zero bytes.
    Frame e = beacon_body(); e.ie(222, {});
    const auto empty = parse(e.b);
    CHECK_EQ(empty.mgmt.element222_count, 1);
    CHECK_EQ(empty.mgmt.element222_head_size, 0);
}

GUARDIAN_CASE(hidden_nul_ssid_is_its_own_kind_and_zero_length_stays_hidden) {
    std::vector<std::uint8_t> b; if (!load(c_, "beacon_hidden_nul_ssid", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.status, ParseStatus::Complete);
    CHECK_EQ(r.ssid_kind, SsidKind::HiddenNul);
    CHECK_EQ(r.identity.ssid_size, 4);
    CHECK(!r.ssid_utf8);
    CHECK(hidden_ssid(r.ssid_kind));
    CHECK(r.settings_complete);
    std::vector<std::uint8_t> h; if (!load(c_, "beacon_hidden_ssid_wpa2", h)) return;
    CHECK_EQ(parse(h).ssid_kind, SsidKind::Hidden);
    CHECK(hidden_ssid(SsidKind::Hidden));
    CHECK(!hidden_ssid(SsidKind::Present));
    CHECK(!hidden_ssid(SsidKind::Wildcard));
}

GUARDIAN_CASE(owe_transition_partner_bssid_and_name) {
    std::vector<std::uint8_t> b; if (!load(c_, "beacon_owe_transition", b)) return;
    const auto r = parse(b);
    CHECK_EQ(r.settings.owe_transition, ElementState::Valid);
    const Mac partner{0x02, 0x11, 0x22, 0x33, 0x44, 0x56};
    CHECK(r.mgmt.owe_partner_bssid == partner);
    CHECK_EQ(r.mgmt.owe_partner_ssid_size, 9);
    CHECK_EQ(r.mgmt.owe_partner_ssid[0], 'h');
    CHECK_EQ(r.mgmt.owe_partner_ssid[8], 'n');
    // A malformed transition element exposes no partner.
    Frame f = beacon_body(); f.ie(221, {0x50, 0x6f, 0x9a, 0x1c, 0x02, 0x11, 0x22, 0x33, 0x44, 0x56, 40, 'x'});
    const auto bad = parse(f.b);
    CHECK_EQ(bad.settings.owe_transition, ElementState::Malformed);
    CHECK_EQ(bad.mgmt.owe_partner_ssid_size, 0);
    CHECK(bad.mgmt.owe_partner_bssid == Mac{});
}

GUARDIAN_CASE(new_subtypes_map_to_their_own_kinds) {
    CHECK_EQ(parse(header(0x20).le16(0x11).le16(1).raw({2, 0x11, 0x22, 0x33, 0x44, 0x56}).b).kind, FrameKind::ReassociationRequest);
    CHECK_EQ(parse(header(0x30).le16(0x11).le16(0).le16(1).b).kind, FrameKind::ReassociationResponse);
    CHECK_EQ(parse(header(0x40).b).kind, FrameKind::ProbeRequest);
    CHECK_EQ(parse(header(0x60).b).kind, FrameKind::OtherManagement); // subtype 6 (timing advertisement) stays other
}

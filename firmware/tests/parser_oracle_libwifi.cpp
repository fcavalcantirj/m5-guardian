// G04 differential check against an INDEPENDENT decoder: libwifi (Apache-2.0,
// pinned c38dbc8 in the store; docs/research/reuse-decisions.md). Host-only, opt-in via
// -DGUARDIAN_LIBWIFI_DIR; never linked into guardian_core or firmware.
//
// libwifi is a secondary reference, not an oracle of record (G02 measured
// defects: low-byte suite counts, silent 6-suite clamp, over-read when RSN
// capabilities are absent, iterator stops at a later zero-length element).
// So this file compares only VETTED valid fixtures that none of those defects
// can touch (counts <= 6, RSN capabilities present, no empty element before the
// RSNE) and pins the documented disagreement for the zero-length-element case.
// Expected values come from Guardian's own reading of the standard (fixtures)
// and are confirmed here by a second, unrelated implementation.
#include "check.hpp"
#include "fixtures.hpp"

#include "guardian/security_parser.hpp"

extern "C" {
#include "libwifi/core/frame/frame.h"
#include "libwifi/core/frame/management/common.h"
#include "libwifi/core/misc/security.h"
#include "libwifi/parse/management/beacon.h"
#include "libwifi/parse/management/probe_response.h"
}

#include <cstring>
#include <string>
#include <vector>

using namespace guardian;
using guardian::fixtures::Fixture;

namespace {

const SecurityFrameParser parser{};

struct Oracle {
    libwifi_frame frame{};
    libwifi_bss bss{};
    int frame_rc{-1};
    int parse_rc{-1};
    ~Oracle() { libwifi_free_bss(&bss); libwifi_free_wifi_frame(&frame); }
};

// Runs libwifi on FCS-free bytes (radiotap = 0). Beacon or probe response by subtype.
void run_oracle(const std::vector<std::uint8_t>& bytes, Oracle& o) {
    o.frame_rc = libwifi_get_wifi_frame(&o.frame, bytes.data(), bytes.size(), 0);
    if (o.frame_rc != 0) return;
    const std::uint8_t subtype = static_cast<std::uint8_t>(bytes[0] >> 4);
    o.parse_rc = subtype == 5 ? libwifi_parse_probe_resp(&o.bss, &o.frame) : libwifi_parse_beacon(&o.bss, &o.frame);
}

ParseResult run_guardian(const std::vector<std::uint8_t>& bytes) {
    RxMeta m{};
    m.status = RxStatus::Ok;
    m.origin = Origin::Imported;
    return parser.parse(FrameSpan{bytes.data(), static_cast<std::uint16_t>(bytes.size()), false}, m);
}

std::uint32_t selector_of(const libwifi_cipher_suite& s) {
    return make_selector((static_cast<std::uint32_t>(s.oui[0]) << 16) | (static_cast<std::uint32_t>(s.oui[1]) << 8) | s.oui[2], s.suite_type);
}

// Compares one Guardian SecurityElement with libwifi's rsn_info/wpa_info fields.
template <class Info>
void compare_suites(check::Case& c_, const std::string& name, const SecurityElement& e, const Info& info,
                    const libwifi_cipher_suite& group, int pairwise_n, const libwifi_cipher_suite* pairwise,
                    int akm_n, const libwifi_cipher_suite* akms) {
    (void)info;
    CHECK_EQ(e.state, ElementState::Valid);
    CHECK(e.group.present);
    if (e.group.selector != selector_of(group)) CHECK_FAIL(name + ": group selector differs from libwifi");
    CHECK_EQ(static_cast<int>(e.pairwise.count), pairwise_n);
    for (int i = 0; i < pairwise_n && i < static_cast<int>(e.pairwise.count); ++i)
        if (e.pairwise.selectors[static_cast<std::size_t>(i)] != selector_of(pairwise[i])) CHECK_FAIL(name + ": pairwise selector differs");
    CHECK_EQ(static_cast<int>(e.akms.count), akm_n);
    for (int i = 0; i < akm_n && i < static_cast<int>(e.akms.count); ++i)
        if (e.akms.selectors[static_cast<std::size_t>(i)] != selector_of(akms[i])) CHECK_FAIL(name + ": AKM selector differs");
}

// Fixtures whose RSNE/WPA elements libwifi decodes without hitting a known defect.
const char* const VETTED[] = {
    "beacon_open", "beacon_wpa2_ccmp_pmf_optional", "beacon_wpa3_sae_pmf_required", "beacon_hidden_ssid_wpa2",
    "beacon_wpa2_mixed_tkip", "beacon_owe_transition", "beacon_wpa1_tkip_vendor", "beacon_wpa_and_rsn_mixed",
    "beacon_rsn_pmkid_group_mgmt", "beacon_rsn_four_pairwise", "beacon_rsn_unknown_akm", "probe_response_wpa2",
    "beacon_ht_control_order_bit", "beacon_ssid_non_utf8",
};

} // namespace

GUARDIAN_CASE(libwifi_oracle_is_the_pinned_checkout) {
    // The build points at the checkout; record which. The reviewer verifies the hash in the store.
    const std::string dir = GUARDIAN_LIBWIFI_DIR;
    CHECK(dir.find("libwifi") != std::string::npos);
    std::printf("     libwifi dir: %s\n", dir.c_str());
}

GUARDIAN_CASE(vetted_fixtures_agree_with_libwifi_on_identity_channel_and_suites) {
    for (const char* name : VETTED) {
        Fixture f;
        std::string err;
        if (!fixtures::load(name, f, err)) { CHECK_FAIL(err); continue; }
        const std::string n = name;
        Oracle o;
        run_oracle(f.bytes, o);
        if (o.frame_rc != 0 || o.parse_rc != 0) { CHECK_FAIL(n + ": libwifi failed to parse a vetted fixture"); continue; }
        const ParseResult g = run_guardian(f.bytes);
        CHECK_EQ(g.status, ParseStatus::Complete);
        // Header identity.
        if (std::memcmp(g.identity.bssid.data(), o.bss.bssid, 6) != 0) CHECK_FAIL(n + ": BSSID differs");
        if (g.kind == FrameKind::Beacon) { // libwifi_parse_probe_resp fills only the BSSID (SOURCE: probe_response.c)
            if (std::memcmp(g.addr2.data(), o.bss.transmitter, 6) != 0) CHECK_FAIL(n + ": transmitter differs");
            if (std::memcmp(g.addr1.data(), o.bss.receiver, 6) != 0) CHECK_FAIL(n + ": receiver differs");
        }
        // SSID bytes (libwifi copies up to 32 raw bytes into char[33]) and hidden flag.
        if (std::memcmp(g.identity.ssid.data(), o.bss.ssid, g.identity.ssid_size) != 0) CHECK_FAIL(n + ": SSID bytes differ");
        CHECK_EQ(hidden_ssid(g.ssid_kind), o.bss.hidden != 0); // G16E: Hidden or HiddenNul
        // DS channel.
        CHECK(g.settings.ds_channel_present);
        CHECK_EQ(static_cast<int>(g.settings.ds_channel), static_cast<int>(o.bss.channel));
        // Encryption summary: libwifi sets WEP from the Privacy bit and clears it when it finds RSN/WPA.
        const bool lw_wep = (o.bss.encryption_info & WEP) != 0;
        const bool lw_wpa = (o.bss.encryption_info & WPA) != 0;
        const bool lw_rsn = (o.bss.encryption_info & (WPA2 | WPA3)) != 0;
        const bool g_rsn = g.settings.rsn.state == ElementState::Valid;
        const bool g_wpa = g.settings.wpa.state == ElementState::Valid;
        CHECK_EQ(g_wpa, lw_wpa);
        if (g_rsn != lw_rsn && n != "beacon_rsn_unknown_akm") CHECK_FAIL(n + ": RSN presence differs"); // libwifi maps unknown AKMs to neither WPA2 nor WPA3
        CHECK_EQ(g.settings.privacy_bit && !g_rsn && !g_wpa, lw_wep);
        if (g_rsn) {
            compare_suites(c_, n, g.settings.rsn, o.bss.rsn_info, o.bss.rsn_info.group_cipher_suite,
                           o.bss.rsn_info.num_pairwise_cipher_suites, o.bss.rsn_info.pairwise_cipher_suites,
                           o.bss.rsn_info.num_auth_key_mgmt_suites, o.bss.rsn_info.auth_key_mgmt_suites);
            CHECK_EQ(static_cast<int>(o.bss.rsn_info.rsn_version), 1);
            const bool mfpc = (o.bss.rsn_info.rsn_capabilities & 0x0080) != 0;
            const bool mfpr = (o.bss.rsn_info.rsn_capabilities & 0x0040) != 0;
            const Pmf expected = mfpc ? (mfpr ? Pmf::Required : Pmf::Optional) : Pmf::Disabled;
            CHECK_EQ(g.settings.rsn.pmf, expected);
        }
        if (g_wpa) {
            compare_suites(c_, n, g.settings.wpa, o.bss.wpa_info, o.bss.wpa_info.multicast_cipher_suite,
                           static_cast<int>(o.bss.wpa_info.num_unicast_cipher_suites), o.bss.wpa_info.unicast_cipher_suites,
                           static_cast<int>(o.bss.wpa_info.num_auth_key_mgmt_suites), o.bss.wpa_info.auth_key_mgmt_suites);
            CHECK_EQ(static_cast<int>(o.bss.wpa_info.wpa_version), 1);
        }
    }
}

GUARDIAN_CASE(libwifi_known_defect_later_zero_length_element_is_pinned_as_a_disagreement) {
    // G02 MEASURED (direct tag-parser spike): libwifi's iterator stops when advancing to a
    // zero-length element, so an RSNE after it is never read. Guardian reads it. Through the
    // full libwifi_parse_beacon path (MEASURED here, G04) the result is: success, no WPA2,
    // RSN record untouched. The WEP flag the G02 spike pre-set by hand is NOT set by
    // libwifi_parse_beacon for this fixture either (its Privacy-bit test did not flag it;
    // see docs/G04-parser.md), so the pin below records the full-path values only.
    Fixture f;
    std::string err;
    if (!fixtures::load("beacon_later_empty_ie_then_rsn", f, err)) { CHECK_FAIL(err); return; }
    Oracle o;
    run_oracle(f.bytes, o);
    const ParseResult g = run_guardian(f.bytes);
    CHECK_EQ(g.status, ParseStatus::Complete);
    CHECK_EQ(g.settings.rsn.state, ElementState::Valid);
    CHECK_EQ(g.settings.rsn.akms.kinds, akm::Psk);
    CHECK_EQ(o.frame_rc, 0);
    CHECK_EQ(o.parse_rc, 0);                        // libwifi reports success...
    CHECK((o.bss.encryption_info & (WPA2 | WPA3)) == 0); // ...without the RSNE
    CHECK_EQ(o.bss.rsn_info.num_auth_key_mgmt_suites, 0);
    CHECK_EQ(static_cast<int>(o.bss.rsn_info.rsn_version), 0); // never read
    CHECK_EQ(static_cast<int>(o.bss.channel), 6);   // elements before the empty one were read
    // If a future libwifi pin fixes this, the pinned expectation above fails and the
    // documentation must change with it; that is the point of pinning it.
}

GUARDIAN_CASE(malformed_fixtures_are_not_handed_to_the_oracle) {
    // Documented exclusion, not a comparison: the G02 spikes showed these inputs make
    // libwifi over-read (ASan abort) or return incorrect success. Guardian's own
    // contract checks (parser_check) cover them; the oracle would add nothing truthful.
    const char* const excluded[] = {"beacon_rsn_truncated_ie", "beacon_rsn_pairwise_count_256",
                                    "beacon_rsn_pmf_inconsistent", "beacon_rsn_duplicate_conflict", "mgmt_header_short_23"};
    for (const char* name : excluded) {
        Fixture f;
        std::string err;
        if (!fixtures::load(name, f, err)) { CHECK_FAIL(err); continue; }
        const ParseResult g = run_guardian(f.bytes);
        CHECK(!g.settings_complete); // every excluded malformed fixture is one Guardian refuses to grade
    }
    // beacon_rsn_minimal_version_only is VALID for Guardian (documented defaults) but excluded from
    // the oracle because libwifi_get_rsn_info reads the group cipher and capabilities unconditionally
    // (G02 "short"/"nocaps": heap over-read). Its expected values rest on 9.4.2.24.1 alone.
    Fixture m;
    std::string err;
    if (!fixtures::load("beacon_rsn_minimal_version_only", m, err)) { CHECK_FAIL(err); return; }
    CHECK(run_guardian(m.bytes).settings_complete);
}

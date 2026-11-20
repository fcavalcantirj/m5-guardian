// G04 SecurityFrameParser: independent, bounded IEEE 802.11 security-frame
// decoding behind the G01 FrameParser contract. See security_parser.hpp for
// the status rules and docs/G04-parser.md for the evidence.
//
// Clause references are to IEEE Std 802.11-2020 unless noted. Nothing here
// allocates, keeps a pointer past the call, or reads a byte before checking
// that it is inside the span. Arithmetic on lengths uses std::size_t with
// explicit remaining-byte checks, never pointer comparison after an add.
#include "guardian/security_parser.hpp"

#include <cstddef>
#include <cstdint>

namespace guardian {
namespace {

// ---- byte helpers -----------------------------------------------------------------------
std::uint16_t le16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] | (static_cast<std::uint16_t>(p[1]) << 8));
}

// Selector on the wire: OUI (3 bytes, network order) then suite type (9.4.2.24.2).
std::uint32_t read_selector(const std::uint8_t* p) {
    return make_selector((static_cast<std::uint32_t>(p[0]) << 16) | (static_cast<std::uint32_t>(p[1]) << 8) | p[2], p[3]);
}

std::uint32_t selector_oui(std::uint32_t selector) { return selector >> 8; }
std::uint8_t selector_type(std::uint32_t selector) { return static_cast<std::uint8_t>(selector & 0xffu); }

bool same_bytes(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) if (a[i] != b[i]) return false;
    return true;
}

Mac read_mac(const std::uint8_t* p) {
    Mac m{};
    for (std::size_t i = 0; i < m.size(); ++i) m[i] = p[i];
    return m;
}

// Strict UTF-8 (RFC 3629): no overlongs, no surrogates, nothing above U+10FFFF.
bool valid_utf8(const std::uint8_t* s, std::size_t n) {
    std::size_t i = 0;
    while (i < n) {
        const std::uint8_t c = s[i];
        if (c < 0x80) { ++i; continue; }
        std::size_t len;
        std::uint32_t cp;
        if (c >= 0xc2 && c <= 0xdf) { len = 2; cp = c & 0x1fu; }
        else if (c >= 0xe0 && c <= 0xef) { len = 3; cp = c & 0x0fu; }
        else if (c >= 0xf0 && c <= 0xf4) { len = 4; cp = c & 0x07u; }
        else return false; // 0x80..0xc1 continuation/overlong lead, 0xf5..0xff invalid
        if (n - i < len) return false;
        for (std::size_t k = 1; k < len; ++k) {
            const std::uint8_t cc = s[i + k];
            if ((cc & 0xc0u) != 0x80u) return false;
            cp = (cp << 6) | (cc & 0x3fu);
        }
        if (len == 3 && cp < 0x800u) return false;
        if (len == 4 && (cp < 0x10000u || cp > 0x10ffffu)) return false;
        if (cp >= 0xd800u && cp <= 0xdfffu) return false;
        i += len;
    }
    return true;
}

// ---- selector mapping (Table 9-149 cipher suites, Table 9-151 AKM suites) -------------------
enum class CipherRole { Group, Pairwise, GroupManagement };

std::uint16_t map_cipher(std::uint32_t selector, CipherRole role, bool wpa_element = false) {
    // A known cipher number in another protocol namespace is still unknown.
    if (selector_oui(selector) != (wpa_element ? oui::Microsoft : oui::Ieee8021))
        return cipher::Unknown;
    if (role == CipherRole::GroupManagement) {
        if (wpa_element) return cipher::Unknown;
        switch (selector_type(selector)) {
        case 6: return cipher::BipCmac128;
        case 11: return cipher::BipGmac128;
        case 12: return cipher::BipGmac256;
        case 13: return cipher::BipCmac256;
        default: return cipher::Unknown;
        }
    }
    if (selector_oui(selector) == oui::Ieee8021) {
        switch (selector_type(selector)) {
        case 0: return role == CipherRole::Pairwise ? cipher::UseGroup : cipher::Unknown; // "Use group cipher suite" is pairwise-only
        case 1: return cipher::Wep40;
        case 2: return cipher::Tkip;
        case 4: return cipher::Ccmp128;
        case 5: return cipher::Wep104;
        case 6: return cipher::BipCmac128;
        case 8: return cipher::Gcmp128;
        case 9: return cipher::Gcmp256;
        case 10: return cipher::Ccmp256;
        case 11: return cipher::BipGmac128;
        case 12: return cipher::BipGmac256;
        case 13: return cipher::BipCmac256;
        default: return cipher::Unknown; // 3 reserved, 7 "group addressed traffic not allowed", 14+ unassigned
        }
    }
    if (selector_oui(selector) == oui::Microsoft) { // WPA v1 selectors share the WPA OUI
        switch (selector_type(selector)) {
        case 0: return role == CipherRole::Pairwise ? cipher::UseGroup : cipher::Unknown;
        case 1: return cipher::Wep40;
        case 2: return cipher::Tkip;
        case 4: return cipher::Ccmp128;
        case 5: return cipher::Wep104;
        default: return cipher::Unknown;
        }
    }
    return cipher::Unknown;
}

std::uint16_t map_akm(std::uint32_t selector, bool wpa_element) {
    if (wpa_element) {
        if (selector_oui(selector) == oui::Microsoft) {
            switch (selector_type(selector)) {
            case 1: return akm::Wpa1Eap;
            case 2: return akm::Wpa1Psk;
            default: return akm::Unknown;
            }
        }
        return akm::Unknown;
    }
    if (selector_oui(selector) == oui::Ieee8021) {
        switch (selector_type(selector)) {
        case 1: return akm::Eap;
        case 2: return akm::Psk;
        case 3: return akm::FtEap;
        case 4: return akm::FtPsk;
        case 5: return akm::EapSha256;
        case 6: return akm::PskSha256;
        case 8: return akm::Sae;
        case 9: return akm::FtSae;
        case 11: return akm::EapSuiteB;
        case 12: return akm::EapSuiteB192;
        case 18: return akm::Owe;
        case 24: return akm::SaeExt;
        default: return akm::Unknown;
        }
    }
    return akm::Unknown;
}

// ---- RSN / WPA element decoding ----------------------------------------------------------
// A cursor over one element body; every read checks `left()` first.
struct Cursor {
    const std::uint8_t* p;
    std::size_t len;
    std::size_t pos{};
    std::size_t left() const { return len - pos; }
    const std::uint8_t* at() const { return p + pos; }
    void skip(std::size_t n) { pos += n; }
};

// Reads "count (LE16) + count selectors". Returns ParseError::None on success.
ParseError read_suite_list(Cursor& c, SuiteList& out, bool wpa_element, bool akm_list) {
    if (c.left() < 2) return ParseError::BadElementLength;
    const std::uint16_t count = le16(c.at());
    c.skip(2);
    if (count == 0) return ParseError::SuiteCountZero;
    if (count > SuiteList::capacity) return ParseError::SuiteCountOverflow;        // bound before arithmetic
    if (c.left() < static_cast<std::size_t>(count) * 4u) return ParseError::SuiteCountOverflow;
    for (std::uint16_t i = 0; i < count; ++i) {
        const std::uint32_t sel = read_selector(c.at());
        c.skip(4);
        out.selectors[i] = sel;
        out.kinds = static_cast<std::uint16_t>(out.kinds | (akm_list ? map_akm(sel, wpa_element) : map_cipher(sel, CipherRole::Pairwise, wpa_element)));
    }
    out.count = static_cast<std::uint8_t>(count);
    return ParseError::None;
}

void set_default_selector(SuiteSelector& s, std::uint32_t selector, CipherRole role, bool wpa_element = false) {
    s.selector = selector;
    s.kind = map_cipher(selector, role, wpa_element);
    s.present = false;
}

void set_default_list(SuiteList& l, std::uint32_t selector, bool wpa_element, bool akm_list) {
    l = SuiteList{};
    l.selectors[0] = selector;
    l.count = 1;
    l.kinds = akm_list ? map_akm(selector, wpa_element) : map_cipher(selector, CipherRole::Pairwise, wpa_element);
}

// RSNE body (9.4.2.24): Version | Group Data Cipher | Pairwise Count+List |
// AKM Count+List | RSN Capabilities | PMKID Count+List | Group Management Cipher.
// All fields after Version are optional; once one is absent no later one is present
// (9.4.2.24.1). Absent fields take the documented defaults. A field cut in the
// middle, a zero/oversized count or trailing bytes reject the element.
ParseError decode_rsn(const std::uint8_t* body, std::size_t len, SecurityElement& e) {
    e = SecurityElement{};
    Cursor c{body, len};
    if (c.left() < 2) return ParseError::BadElementLength;
    if (le16(c.at()) != 1) return ParseError::UnsupportedVersion;
    c.skip(2);
    const std::uint32_t ccmp = make_selector(oui::Ieee8021, 4);
    set_default_selector(e.group, ccmp, CipherRole::Group);
    set_default_list(e.pairwise, ccmp, false, false);
    set_default_list(e.akms, make_selector(oui::Ieee8021, 1), false, true);
    e.pmf = Pmf::Disabled; // capabilities default 0 (9.4.2.24.1)
    set_default_selector(e.group_management, make_selector(oui::Ieee8021, 6), CipherRole::GroupManagement);

    if (c.left() == 0) return ParseError::None;
    if (c.left() < 4) return ParseError::BadElementLength;
    e.group.selector = read_selector(c.at());
    e.group.kind = map_cipher(e.group.selector, CipherRole::Group);
    e.group.present = true;
    c.skip(4);

    if (c.left() == 0) return ParseError::None;
    e.pairwise = SuiteList{};
    if (const ParseError err = read_suite_list(c, e.pairwise, false, false); err != ParseError::None) return err;

    if (c.left() == 0) return ParseError::None;
    e.akms = SuiteList{};
    if (const ParseError err = read_suite_list(c, e.akms, false, true); err != ParseError::None) return err;

    if (c.left() == 0) return ParseError::None;
    if (c.left() < 2) return ParseError::BadElementLength;
    const std::uint16_t caps = le16(c.at());
    c.skip(2);
    const bool mfpr = (caps & 0x0040u) != 0; // bit 6 (9.4.2.24.4)
    const bool mfpc = (caps & 0x0080u) != 0; // bit 7
    if (mfpr && !mfpc) return ParseError::PmfInconsistent;
    e.pmf = mfpc ? (mfpr ? Pmf::Required : Pmf::Optional) : Pmf::Disabled;

    if (c.left() == 0) return ParseError::None;
    if (c.left() < 2) return ParseError::BadElementLength;
    const std::uint16_t pmkid_count = le16(c.at());
    c.skip(2);
    if (c.left() < static_cast<std::size_t>(pmkid_count) * 16u) return ParseError::BadElementLength; // 65535*16 fits size_t
    c.skip(static_cast<std::size_t>(pmkid_count) * 16u); // PMKIDs are not evidence; not stored

    if (c.left() == 0) return ParseError::None;
    if (c.left() < 4) return ParseError::BadElementLength;
    e.group_management.selector = read_selector(c.at());
    e.group_management.kind = map_cipher(e.group_management.selector, CipherRole::GroupManagement);
    e.group_management.present = true;
    c.skip(4);

    if (c.left() != 0) return ParseError::BadElementLength; // nothing is defined after the group management cipher
    return ParseError::None;
}

// WPA vendor element body after OUI+type (WPA v1 specification section 2.1):
// Version(=1) | Multicast Cipher | Unicast Count+List | AKM Count+List | Capabilities.
// Defaults when absent: TKIP / TKIP / 802.1X. No PMF, no group management cipher.
ParseError decode_wpa(const std::uint8_t* body, std::size_t len, SecurityElement& e) {
    e = SecurityElement{};
    Cursor c{body, len};
    if (c.left() < 2) return ParseError::BadElementLength;
    if (le16(c.at()) != 1) return ParseError::UnsupportedVersion;
    c.skip(2);
    const std::uint32_t tkip = make_selector(oui::Microsoft, 2);
    set_default_selector(e.group, tkip, CipherRole::Group, true);
    set_default_list(e.pairwise, tkip, true, false);
    set_default_list(e.akms, make_selector(oui::Microsoft, 1), true, true);
    e.pmf = Pmf::Unknown; // WPA has no PMF; never attributed

    if (c.left() == 0) return ParseError::None;
    if (c.left() < 4) return ParseError::BadElementLength;
    e.group.selector = read_selector(c.at());
    e.group.kind = map_cipher(e.group.selector, CipherRole::Group, true);
    e.group.present = true;
    c.skip(4);

    if (c.left() == 0) return ParseError::None;
    e.pairwise = SuiteList{};
    if (const ParseError err = read_suite_list(c, e.pairwise, true, false); err != ParseError::None) return err;

    if (c.left() == 0) return ParseError::None;
    e.akms = SuiteList{};
    if (const ParseError err = read_suite_list(c, e.akms, true, true); err != ParseError::None) return err;

    if (c.left() == 0) return ParseError::None;
    if (c.left() != 2) return ParseError::BadElementLength; // WPA capabilities are the last field
    return ParseError::None;
}

// WFA OWE Transition Mode element body after OUI+type (WFA OWE Specification v1.1,
// 2.3.1): BSSID(6) | SSID Length(1) | SSID(n <= 32) | optional Band Info(1) + Channel(1).
bool owe_transition_valid(const std::uint8_t* body, std::size_t len) {
    if (len < 7) return false;
    const std::uint8_t ssid_len = body[6];
    if (ssid_len > 32) return false;
    const std::size_t rest = len - 7;
    if (rest < ssid_len) return false;
    const std::size_t optional = rest - ssid_len;
    return optional == 0 || optional == 2;
}

bool has_unknown(const SecurityElement& e) {
    if (e.state != ElementState::Valid) return false;
    return (e.akms.kinds & akm::Unknown) || (e.pairwise.kinds & cipher::Unknown)
        || e.group.kind == cipher::Unknown || e.group_management.kind == cipher::Unknown;
}

// ---- per-frame decoding state -------------------------------------------------------------
struct Decoder {
    const FrameSpan& frame;
    ParseResult& r;

    // First-copy locations for duplicate detection (valid only during this call).
    const std::uint8_t* first_ssid{}; std::size_t first_ssid_len{}; bool ssid_conflict{};
    const std::uint8_t* first_ds{}; bool ds_conflict{};
    const std::uint8_t* first_rsn{}; std::size_t first_rsn_len{};
    const std::uint8_t* first_wpa{}; std::size_t first_wpa_len{};
    const std::uint8_t* first_owe{}; std::size_t first_owe_len{};
    const std::uint8_t* first_csa{}; bool csa_conflict{};

    void fail(ParseError e) {
        r.status = ParseStatus::Malformed;
        if (r.error == ParseError::None) r.error = e;
    }
    void cut(ParseError e) { // the span ended before the structure did
        if (r.status != ParseStatus::Malformed) r.status = ParseStatus::Truncated;
        if (r.error == ParseError::None) r.error = e;
    }

    void ssid(const std::uint8_t* body, std::size_t len) {
        if (ssid_conflict) return;
        if (first_ssid) {
            if (first_ssid_len == len && same_bytes(first_ssid, body, len)) return; // identical duplicate
            ssid_conflict = true;
            r.identity.ssid = {};
            r.identity.ssid_size = 0;
            r.ssid_kind = SsidKind::Absent;
            r.ssid_utf8 = false;
            fail(ParseError::DuplicateConflict);
            return;
        }
        first_ssid = body;
        first_ssid_len = len;
        if (len > r.identity.ssid.size()) { fail(ParseError::BadElementLength); ssid_conflict = true; return; } // oversized: never trimmed to 32
        bool all_zero = true;
        for (std::size_t i = 0; i < len; ++i) { r.identity.ssid[i] = body[i]; if (body[i]) all_zero = false; }
        r.identity.ssid_size = static_cast<std::uint8_t>(len);
        // G16E: zero length = Hidden (a probe request's empty SSID = Wildcard);
        // N NUL bytes = HiddenNul, a distinct fact that keeps its length.
        r.ssid_kind = len == 0 ? (r.kind == FrameKind::ProbeRequest ? SsidKind::Wildcard : SsidKind::Hidden)
                    : all_zero ? SsidKind::HiddenNul : SsidKind::Present;
        r.ssid_utf8 = r.ssid_kind == SsidKind::Present && valid_utf8(body, len);
    }

    void ds_parameter(const std::uint8_t* body, std::size_t len) {
        if (ds_conflict) return;
        if (len != 1) { fail(ParseError::BadElementLength); r.settings.ds_channel_present = false; r.settings.ds_channel = 0; ds_conflict = true; return; }
        if (first_ds) {
            if (*first_ds == body[0]) return;
            ds_conflict = true;
            r.settings.ds_channel_present = false;
            r.settings.ds_channel = 0;
            fail(ParseError::DuplicateConflict);
            return;
        }
        first_ds = body;
        r.settings.ds_channel = body[0];
        r.settings.ds_channel_present = true;
    }

    // Shared duplicate/decode handling for RSN and WPA records.
    void security_element(SecurityElement& e, const std::uint8_t*& first, std::size_t& first_len,
                          const std::uint8_t* body, std::size_t len, bool wpa) {
        if (e.state == ElementState::Conflicting || e.state == ElementState::Malformed) return; // already rejected
        if (first) {
            if (first_len == len && same_bytes(first, body, len)) return; // identical duplicate
            e = SecurityElement{};
            e.state = ElementState::Conflicting;
            fail(ParseError::DuplicateConflict);
            return;
        }
        first = body;
        first_len = len;
        const ParseError err = wpa ? decode_wpa(body, len, e) : decode_rsn(body, len, e);
        if (err != ParseError::None) {
            e = SecurityElement{};
            e.state = ElementState::Malformed;
            fail(err);
            return;
        }
        e.state = ElementState::Valid;
    }

    void vendor(const std::uint8_t* body, std::size_t len) {
        if (len < 3) { fail(ParseError::BadVendorOui); return; }
        if (len < 4) return; // OUI without a type byte: vendor-private, nothing to read
        const std::uint32_t oui24 = (static_cast<std::uint32_t>(body[0]) << 16) | (static_cast<std::uint32_t>(body[1]) << 8) | body[2];
        const std::uint8_t type = body[3];
        if (oui24 == oui::Microsoft && type == 1) {
            security_element(r.settings.wpa, first_wpa, first_wpa_len, body + 4, len - 4, true);
        } else if (oui24 == oui::Wfa && type == 28) {
            if (r.settings.owe_transition == ElementState::Conflicting || r.settings.owe_transition == ElementState::Malformed) return;
            if (first_owe) {
                if (first_owe_len == len && same_bytes(first_owe, body, len)) return;
                r.settings.owe_transition = ElementState::Conflicting;
                fail(ParseError::DuplicateConflict);
                return;
            }
            first_owe = body;
            first_owe_len = len;
            if (!owe_transition_valid(body + 4, len - 4)) { r.settings.owe_transition = ElementState::Malformed; fail(ParseError::BadElementLength); return; }
            r.settings.owe_transition = ElementState::Valid;
            // G16E: the declared partner (BSSID + SSID bytes), already length-checked above.
            const std::uint8_t* t = body + 4;
            r.mgmt.owe_partner_bssid = read_mac(t);
            r.mgmt.owe_partner_ssid_size = t[6];
            for (std::size_t i = 0; i < t[6]; ++i) r.mgmt.owe_partner_ssid[i] = t[7 + i];
        }
        // Every other vendor element (WMM, WPS, P2P, ...) is skipped by its length.
    }

    // G16E elements of beacons / probe responses (9.4.2.18, 9.4.2.22, 9.4.2.45, id 222).
    void csa(const std::uint8_t* body, std::size_t len) {
        if (csa_conflict) return;
        if (len != 3) { clear_csa(ElementState::Malformed); fail(ParseError::BadElementLength); return; }
        if (first_csa) {
            if (same_bytes(first_csa, body, 3)) return;          // identical duplicate
            clear_csa(ElementState::Conflicting); fail(ParseError::DuplicateConflict); return;
        }
        first_csa = body;
        r.mgmt.csa = ElementState::Valid;
        r.mgmt.csa_mode = body[0];
        r.mgmt.csa_new_channel = body[1];
        r.mgmt.csa_count = body[2];
    }
    void clear_csa(ElementState why) {
        csa_conflict = true;
        r.mgmt.csa = why; r.mgmt.csa_mode = r.mgmt.csa_new_channel = r.mgmt.csa_count = 0;
    }
    void quiet(const std::uint8_t* body, std::size_t len) {
        if (r.mgmt.quiet == ElementState::Malformed) return;
        if (len != 6) {   // Count(1) Period(1) Duration(2) Offset(2)
            r.mgmt.quiet = ElementState::Malformed; r.mgmt.quiet_elements = 0; r.mgmt.quiet_max_duration_tu = 0;
            fail(ParseError::BadElementLength); return;
        }
        r.mgmt.quiet = ElementState::Valid;
        if (r.mgmt.quiet_elements < 255) ++r.mgmt.quiet_elements;
        const std::uint16_t duration = le16(body + 2);
        if (duration > r.mgmt.quiet_max_duration_tu) r.mgmt.quiet_max_duration_tu = duration;
    }
    void multi_bssid(std::size_t len) {
        if (r.mgmt.multi_bssid == ElementState::Malformed) return;
        if (len < 1) { r.mgmt.multi_bssid = ElementState::Malformed; fail(ParseError::BadElementLength); return; }
        r.mgmt.multi_bssid = ElementState::Valid;   // subelements (nontransmitted profiles) are not decoded
    }
    void element222(const std::uint8_t* body, std::size_t len) {
        if (r.mgmt.element222_count < 255) ++r.mgmt.element222_count;
        const std::size_t total = static_cast<std::size_t>(r.mgmt.element222_bytes) + len;
        r.mgmt.element222_bytes = static_cast<std::uint16_t>(total > 0xffffu ? 0xffffu : total);
        while (r.mgmt.element222_head_size < ManagementFacts::element222_head_capacity && len > 0) {
            r.mgmt.element222_head[r.mgmt.element222_head_size++] = *body++;
            --len;
        }
    }

    // Walks elements from `pos` to the end of the span. Returns false when the walk
    // was cut short (overrun); earlier elements keep whatever state they earned.
    // G16E: elements of probe / (re)association requests and responses: the SSID
    // (requested name) and structural rules only. A client's RSNE is never AP evidence.
    bool walk_request_elements(std::size_t pos) {
        const std::uint8_t* b = frame.bytes;
        const std::size_t end = frame.size;
        while (pos < end) {
            if (end - pos < 2) { cut(ParseError::IeOverrun); return false; }
            const std::uint8_t id = b[pos];
            const std::size_t len = b[pos + 1];
            if (end - pos - 2 < len) { cut(ParseError::IeOverrun); return false; }
            if (id == 0) ssid(b + pos + 2, len);
            else if (id == 221 && len < 3) fail(ParseError::BadVendorOui);
            pos += 2 + len;
        }
        return true;
    }

    bool walk_elements(std::size_t pos, bool security_frame) {
        const std::uint8_t* b = frame.bytes;
        const std::size_t end = frame.size;
        while (pos < end) {
            if (end - pos < 2) { cut(ParseError::IeOverrun); return false; } // dangling byte: element header is 2 bytes
            const std::uint8_t id = b[pos];
            const std::size_t len = b[pos + 1];
            if (end - pos - 2 < len) {
                if (id == 48 && security_frame && r.settings.rsn.state == ElementState::Absent) r.settings.rsn.state = ElementState::Truncated;
                cut(ParseError::IeOverrun);
                return false;
            }
            const std::uint8_t* body = b + pos + 2;
            if (security_frame) {
                switch (id) {
                case 0: ssid(body, len); break;
                case 3: ds_parameter(body, len); break;
                case 48: security_element(r.settings.rsn, first_rsn, first_rsn_len, body, len, false); break;
                case 221: vendor(body, len); break;
                case 37: csa(body, len); break;
                case 40: quiet(body, len); break;
                case 71: multi_bssid(len); break;
                case 222: element222(body, len); break;
                default: break; // skipped by length, including zero-length elements
                }
            } else if (id == 76) {
                // Management MIC element (9.4.2.55): 16 bytes (8-byte MIC) or 24 bytes (16-byte MIC).
                if (len != 16 && len != 24) fail(ParseError::BadElementLength);
            } else if (id == 221) {
                if (len < 3) fail(ParseError::BadVendorOui);
            }
            pos += 2 + len;
        }
        return true;
    }

    void beacon_like(std::size_t body_pos) {
        const std::size_t body_len = frame.size - body_pos;
        if (r.protected_frame) { fail(ParseError::Other); return; } // beacons/probe responses are never protected
        if (body_len < 12) { // Timestamp(8) Beacon Interval(2) Capability(2) (9.3.3.3 / 9.3.3.11)
            if (frame.truncated) cut(ParseError::ShortFixedBody); else fail(ParseError::ShortFixedBody);
            return;
        }
        const std::uint16_t capability = le16(frame.bytes + body_pos + 10);
        r.mgmt.timing_valid = true;   // G16E: Timestamp (8, LE) and Beacon Interval (2)
        for (int i = 7; i >= 0; --i) r.mgmt.tsf = (r.mgmt.tsf << 8) | frame.bytes[body_pos + static_cast<std::size_t>(i)];
        r.mgmt.beacon_interval_tu = le16(frame.bytes + body_pos + 8);
        r.settings.privacy_valid = true;
        r.settings.privacy_bit = (capability & 0x0010u) != 0; // bit 4 (9.4.1.4)
        walk_elements(body_pos + 12, true);
        if (frame.truncated && r.status == ParseStatus::Complete) r.status = ParseStatus::Truncated;
        r.settings_present = r.settings.privacy_valid || r.settings.rsn.state == ElementState::Valid
                          || r.settings.wpa.state == ElementState::Valid || r.settings.ds_channel_present;
        r.settings_complete = r.status == ParseStatus::Complete && !has_unknown(r.settings.rsn) && !has_unknown(r.settings.wpa)
                           && (r.settings.owe_transition == ElementState::Absent || r.settings.owe_transition == ElementState::Valid);
    }

    // A fixed body shorter than `need`: Truncated when the receiver cut the frame, else Malformed.
    bool fixed(std::size_t body_pos, std::size_t need) {
        if (frame.size - body_pos >= need) return true;
        if (frame.truncated) cut(ParseError::ShortFixedBody); else fail(ParseError::ShortFixedBody);
        return false;
    }
    void finish() { if (frame.truncated && r.status == ParseStatus::Complete) r.status = ParseStatus::Truncated; }

    // Authentication (9.3.3.11): Algorithm | Transaction | Status, then
    // algorithm-specific fields that are not decoded (SAE scalar/element are not elements).
    void authentication(std::size_t body_pos) {
        if (r.protected_frame) { r.status = ParseStatus::Unsupported; return; } // shared-key transaction 3: encrypted
        if (!fixed(body_pos, 6)) return;
        const std::uint8_t* f = frame.bytes + body_pos;
        r.mgmt.auth_valid = true;
        r.mgmt.auth_algorithm = le16(f);
        r.mgmt.auth_transaction = le16(f + 2);
        r.mgmt.status_valid = true;
        r.mgmt.status_code = le16(f + 4);
        finish();
    }
    // Probe Request (9.3.3.10): elements only.
    void probe_request(std::size_t body_pos) {
        if (r.protected_frame) { fail(ParseError::Other); return; }
        walk_request_elements(body_pos);
        finish();
    }
    // (Re)Association Request: Capability | Listen Interval [| Current AP] then elements.
    void association_request(std::size_t body_pos, bool reassociation) {
        if (r.protected_frame) { fail(ParseError::Other); return; }
        const std::size_t need = reassociation ? 10u : 4u;
        if (!fixed(body_pos, need)) return;
        r.mgmt.listen_interval_valid = true;
        r.mgmt.listen_interval = le16(frame.bytes + body_pos + 2);
        if (reassociation) r.mgmt.current_ap = read_mac(frame.bytes + body_pos + 4);
        walk_request_elements(body_pos + need);
        finish();
    }
    // (Re)Association Response: Capability | Status | AID then elements.
    void association_response(std::size_t body_pos) {
        if (r.protected_frame) { fail(ParseError::Other); return; }
        if (!fixed(body_pos, 6)) return;
        r.mgmt.status_valid = true;
        r.mgmt.status_code = le16(frame.bytes + body_pos + 2);
        walk_request_elements(body_pos + 6);
        finish();
    }

    void disconnect(std::size_t body_pos) {
        if (r.protected_frame) { r.status = ParseStatus::Unsupported; return; } // encrypted unicast body: nothing readable
        const std::size_t body_len = frame.size - body_pos;
        if (body_len < 2) { // Reason Code (9.3.3.5 / 9.3.3.12)
            if (frame.truncated) cut(ParseError::ShortFixedBody); else fail(ParseError::ShortFixedBody);
            return;
        }
        r.reason_code = le16(frame.bytes + body_pos);
        walk_elements(body_pos + 2, false); // vendor elements and a BIP MME may follow
        if (frame.truncated && r.status == ParseStatus::Complete) r.status = ParseStatus::Truncated;
        // Readable = structurally decoded from an unprotected or integrity-only body; never MIC-verified.
        r.reason_readable = r.status != ParseStatus::Malformed;
        if (!r.reason_readable) r.reason_code = 0;
    }
};

FrameKind management_kind(std::uint8_t subtype) {
    switch (subtype) {
    case 0: return FrameKind::AssociationRequest;
    case 1: return FrameKind::AssociationResponse;
    case 2: return FrameKind::ReassociationRequest;   // G16E
    case 3: return FrameKind::ReassociationResponse;  // G16E
    case 4: return FrameKind::ProbeRequest;           // G16E
    case 5: return FrameKind::ProbeResponse;
    case 8: return FrameKind::Beacon;
    case 10: return FrameKind::Disassociation;
    case 11: return FrameKind::Authentication;
    case 12: return FrameKind::Deauthentication;
    case 13: return FrameKind::Action;
    default: return FrameKind::OtherManagement;
    }
}

// G16G: bounded EAPOL-Key decode (IEEE 802.1X-2020 11.3 EAPOL header; IEEE
// 802.11-2020 12.7.2 EAPOL-Key frame). `p` points at the EAPOL header (after
// LLC/SNAP), `n` bytes are readable. Fills r.eapol and r.status; never keeps a
// pointer, never reads past `n`, keeps no nonce, MIC or PMKID bytes.
std::uint16_t be16(const std::uint8_t* p) { return static_cast<std::uint16_t>((p[0] << 8) | p[1]); }

void eapol_key(const std::uint8_t* p, std::size_t n, bool truncated, ParseResult& r) {
    // EAPOL header: Protocol Version (1), Packet Type (1), Packet Body Length (2, big endian).
    if (n < 4) return;                                      // recognised by LLC/SNAP, nothing more to read
    if (p[1] != 3) return;                                  // not EAPOL-Key (EAP, Start, Logoff, ...): left undecoded
    auto& k = r.eapol;
    const auto fail = [&](ParseError e) {
        k = EapolKeyFacts{};
        k.state = truncated ? ElementState::Truncated : ElementState::Malformed;
        r.status = truncated ? ParseStatus::Truncated : ParseStatus::Malformed;
        r.error = e;
    };
    const std::size_t body = be16(p + 2);
    const std::uint8_t* b = p + 4;
    if (body > n - 4) { fail(ParseError::IeOverrun); return; }   // the frame is shorter than its EAPOL length
    // Descriptor Type (1) | Key Information (2) | Key Length (2) | Replay Counter (8) |
    // Key Nonce (32) | EAPOL-Key IV (16) | Key RSC (8) | Reserved (8) = 77 bytes before the MIC.
    const std::uint8_t descriptor = body >= 1 ? b[0] : 0;
    if (body >= 1 && descriptor != 2 && descriptor != 254) return;   // unknown descriptor: left undecoded
    if (body < 77) { fail(ParseError::ShortFixedBody); return; }
    k = EapolKeyFacts{};
    k.version = p[0];
    k.descriptor = descriptor;
    k.key_info = be16(b + 1);
    k.key_length = be16(b + 3);
    for (std::size_t i = 0; i < 8; ++i) k.replay_counter = (k.replay_counter << 8) | b[5 + i];
    k.nonce_zero = true;
    for (std::size_t i = 0; i < 32; ++i) if (b[13 + i] != 0) { k.nonce_zero = false; break; }
    // The MIC size depends on the AKM, which this frame does not name: place the
    // Key Data Length field for each known size and accept exactly one fit.
    static constexpr std::uint8_t mic_sizes[] = {16, 24, 32};
    for (auto m : mic_sizes) {
        const std::size_t at = 77u + m;
        if (body < at + 2) continue;
        const std::size_t kdl = be16(b + at);
        if (at + 2 + kdl != body) continue;
        if (k.mic_size) { k.mic_size = 0; k.key_data_known = false; break; }   // two fits: ambiguous, report neither
        k.mic_size = m; k.key_data_known = true; k.key_data_length = static_cast<std::uint16_t>(kdl);
    }
    k.key_data_encrypted = (k.key_info & key_info::EncryptedKeyData) != 0;
    if (k.key_data_known && !k.key_data_encrypted) {
        // Walk the key data elements / KDEs (bounded by key_data_length); stop at padding (DD 00) or a cut element.
        const std::uint8_t* d = b + 77 + k.mic_size + 2;
        std::size_t i = 0;
        while (i + 2 <= k.key_data_length) {
            const std::uint8_t id = d[i], len = d[i + 1];
            if (i + 2u + len > k.key_data_length) break;
            if (id == 0xdd && len == 0) break;
            if (id == 0xdd && len == 20 && d[i + 2] == 0x00 && d[i + 3] == 0x0f && d[i + 4] == 0xac && d[i + 5] == 0x04) {
                k.pmkid_present = true;
                // G16J: a template value (one repeated byte, or a constant non-zero step over the first 15 bytes).
                const std::uint8_t* v = d + i + 6;
                const std::uint8_t step = static_cast<std::uint8_t>(v[1] - v[0]);
                bool equal = true, ramp = step != 0;
                for (std::size_t n = 1; n < 16; ++n) {
                    equal = equal && v[n] == v[0];
                    if (n < 15) ramp = ramp && static_cast<std::uint8_t>(v[n] - v[n - 1]) == step;
                }
                k.pmkid_synthetic = k.pmkid_synthetic || equal || ramp;
            }
            i += 2u + len;
        }
    }
    // Message from the Key Information bits.
    const std::uint16_t ki = k.key_info;
    const bool ack = (ki & key_info::Ack) != 0, mic = (ki & key_info::Mic) != 0, secure = (ki & key_info::Secure) != 0;
    if (!(ki & key_info::Pairwise)) k.message = EapolMessage::Group;
    else if (ki & key_info::Request) k.message = EapolMessage::None;
    else if (ack && !mic) k.message = EapolMessage::M1;
    else if (ack && mic) k.message = EapolMessage::M3;
    else if (mic) {
        if (secure) k.message = EapolMessage::M4;
        else if (k.key_data_known) k.message = k.key_data_length > 0 ? EapolMessage::M2 : EapolMessage::M4;
        else k.message = k.nonce_zero ? EapolMessage::M4 : EapolMessage::M2;
    } else k.message = EapolMessage::None;
    // Roles: Ack messages are sent by the authenticator (Address 2) to the supplicant (Address 1).
    k.authenticator = ack ? r.addr2 : r.addr1;
    k.supplicant = ack ? r.addr1 : r.addr2;
    k.state = ElementState::Valid;
    r.status = ParseStatus::Complete;
}

void read_header(const std::uint8_t* b, ParseResult& r) {
    r.addr1 = read_mac(b + 4);
    r.addr2 = read_mac(b + 10);
    r.addr3 = read_mac(b + 16);
    const std::uint16_t seq_ctrl = le16(b + 22); // 9.2.4.4: fragment bits 0..3, sequence bits 4..15
    r.fragment = static_cast<std::uint8_t>(seq_ctrl & 0x0fu);
    r.sequence = static_cast<std::uint16_t>(seq_ctrl >> 4);
    r.power_management = (b[1] & 0x10u) != 0;  // G16E: Frame Control Power Management (9.2.4.1.7)
    r.duration = le16(b + 2);                  // G16J: Duration/ID as received (9.2.4.2)
    r.addr2_local = (r.addr2[0] & 0x02u) != 0; // G16E: locally administered bit of Address 2
    r.header_valid = true;
}

} // namespace

ParseResult SecurityFrameParser::parse(const FrameSpan& frame, const RxMeta& meta) const {
    ParseResult r{};
    if (meta.status == RxStatus::FcsError) { r.status = ParseStatus::Malformed; r.error = ParseError::FcsFailed; return r; }
    if (meta.status == RxStatus::DriverError) { r.status = ParseStatus::Malformed; r.error = ParseError::ReceiveFailed; return r; }
    if (!frame.bytes || frame.size < 2) {
        r.status = frame.truncated ? ParseStatus::Truncated : ParseStatus::Malformed;
        r.error = ParseError::ShortMacHeader;
        return r;
    }
    const std::uint8_t* b = frame.bytes;
    const std::uint8_t fc0 = b[0], fc1 = b[1];
    if ((fc0 & 0x03u) != 0) { r.status = ParseStatus::Unsupported; r.error = ParseError::UnsupportedVersion; return r; }
    const std::uint8_t type = static_cast<std::uint8_t>((fc0 >> 2) & 0x03u);
    const std::uint8_t subtype = static_cast<std::uint8_t>(fc0 >> 4);
    r.protected_frame = (fc1 & 0x40u) != 0; // 9.2.4.1.9
    r.retry = (fc1 & 0x08u) != 0;           // 9.2.4.1.6
    const bool order = (fc1 & 0x80u) != 0;  // 9.2.4.1.10: HT Control present in management/QoS data frames

    if (type == 1) { r.kind = FrameKind::Control; r.status = ParseStatus::Unrelated; return r; }
    if (type == 3) { r.kind = FrameKind::Unknown; r.status = ParseStatus::Unrelated; return r; } // extension frames

    if (type == 2) {
        r.kind = FrameKind::Data;
        r.status = ParseStatus::Unrelated;
        const bool to_ds = (fc1 & 0x01u) != 0, from_ds = (fc1 & 0x02u) != 0, qos = (subtype & 0x08u) != 0;
        const std::size_t header_len = 24u + (to_ds && from_ds ? 6u : 0u) + (qos ? 2u : 0u) + (qos && order ? 4u : 0u);
        if (frame.size < 24) return r; // not usable; data frames are not Guardian's evidence anyway
        read_header(b, r);
        if (!to_ds && !from_ds) r.identity.bssid = r.addr3;
        else if (to_ds && !from_ds) r.identity.bssid = r.addr1;
        else if (!to_ds && from_ds) r.identity.bssid = r.addr2;
        // both set (4-address): BSSID not defined by the header; identity stays zero
        if (frame.size < header_len) { r.header_valid = false; return r; }
        // LLC/SNAP EAPOL (AA AA 03 00 00 00 88 8E) in an unprotected data body: recognised;
        // G16G decodes an EAPOL-Key body (other EAPOL packet types stay Unsupported).
        static constexpr std::uint8_t eapol[8] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e};
        if (!r.protected_frame && frame.size - header_len >= 8 && same_bytes(b + header_len, eapol, 8)) {
            r.kind = FrameKind::EapolData;
            r.status = ParseStatus::Unsupported;
            eapol_key(b + header_len + 8, frame.size - header_len - 8, frame.truncated, r);
        }
        return r;
    }

    // Management frame: 24-byte header plus 4-byte HT Control when Order is set (9.3.3.2).
    r.kind = management_kind(subtype);
    const std::size_t header_len = order ? 28u : 24u;
    if (frame.size < header_len) {
        r.status = frame.truncated ? ParseStatus::Truncated : ParseStatus::Malformed;
        r.error = ParseError::ShortMacHeader;
        return r;
    }
    read_header(b, r);
    r.identity.bssid = r.addr3; // Address 3 is the BSSID for these management frames (Table 9-30)
    // No fragment reassembly in this parser. A plausible prefix is not a
    // complete advertisement; retain only the observable header for counters.
    if ((fc1 & 0x04u) != 0 || r.fragment != 0) {
        r.status = ParseStatus::Unsupported;
        return r;
    }
    r.status = ParseStatus::Complete; // demoted below as rules fail
    Decoder d{frame, r};
    switch (r.kind) {
    case FrameKind::Beacon:
    case FrameKind::ProbeResponse:
        d.beacon_like(header_len);
        break;
    case FrameKind::Deauthentication:
    case FrameKind::Disassociation:
        d.disconnect(header_len);
        break;
    // G16E: the bodies the passive detectors need.
    case FrameKind::Authentication: d.authentication(header_len); break;
    case FrameKind::ProbeRequest: d.probe_request(header_len); break;
    case FrameKind::AssociationRequest: d.association_request(header_len, false); break;
    case FrameKind::ReassociationRequest: d.association_request(header_len, true); break;
    case FrameKind::AssociationResponse:
    case FrameKind::ReassociationResponse: d.association_response(header_len); break;
    default:
        r.status = ParseStatus::Unsupported; // valid header; body kinds not decoded by Guardian
        break;
    }
    return r;
}

} // namespace guardian

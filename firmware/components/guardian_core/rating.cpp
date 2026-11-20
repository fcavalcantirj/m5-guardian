// G05: the documented v1 rating of advertised Wi-Fi configuration and the
// parser-to-observation reduction. Policy table and every decision:
// guardian/rating.hpp (summary) and docs/G05-rating-freshness.md (full text).
// Executable form: firmware/tests/rating_check.cpp (written RED first).
//
// Standard C++ only, no allocation, no time: freshness is Core's job.
#include "guardian/rating.hpp"

#include <cstdint>

namespace guardian {
namespace {

constexpr std::uint16_t kSaeFamily = akm::Sae | akm::FtSae | akm::SaeExt;          // WPA3-Personal
constexpr std::uint16_t kWpa2Personal = akm::Psk | akm::PskSha256 | akm::FtPsk;     // WPA2-Personal
constexpr std::uint16_t kEnterprise = akm::Eap | akm::EapSha256 | akm::FtEap | akm::EapSuiteB | akm::EapSuiteB192 | akm::Wpa1Eap;
constexpr std::uint16_t kWep = cipher::Wep40 | cipher::Wep104;
constexpr std::uint16_t kLegacyCipher = kWep | cipher::Tkip;
constexpr std::uint16_t kStrong = cipher::Ccmp128 | cipher::Ccmp256 | cipher::Gcmp128 | cipher::Gcmp256;
constexpr std::uint16_t kBip = cipher::BipCmac128 | cipher::BipGmac128 | cipher::BipGmac256 | cipher::BipCmac256;

bool valid(const SecurityElement& e) { return e.state == ElementState::Valid; }

// Every kind bit a Valid element advertises for data confidentiality: pairwise
// list plus group cipher; a pairwise "Use group cipher" selector means the
// group cipher is the pairwise option, so it is resolved and dropped.
std::uint16_t pairwise_kinds(const SecurityElement& e) {
    std::uint16_t k = e.pairwise.kinds;
    if (k & cipher::UseGroup) k = static_cast<std::uint16_t>((k & ~cipher::UseGroup) | e.group.kind);
    return k;
}

bool has_unknown(const SecurityElement& e) {
    return (e.akms.kinds & akm::Unknown) || (e.pairwise.kinds & cipher::Unknown) || (e.group.kind & cipher::Unknown)
        || (e.group_management.present && (e.group_management.kind & cipher::Unknown))
        || (!e.group_management.present && e.group_management.kind != 0 && (e.group_management.kind & cipher::Unknown));
}

// Weakest cipher named by a mask of data-cipher kinds (Unknown already excluded by the caller).
Cipher weakest(std::uint16_t kinds) {
    if (kinds & kWep) return Cipher::Wep;
    if (kinds & cipher::Tkip) return Cipher::Tkip;
    if (kinds & (cipher::Ccmp128 | cipher::Ccmp256)) return Cipher::Ccmp;
    if (kinds & (cipher::Gcmp128 | cipher::Gcmp256)) return Cipher::Gcmp;
    return Cipher::Unknown;
}

} // namespace

Assessment assess(const SecurityObservation& s) {
    Assessment a{};
    const AdvertisedSettings& adv = s.settings;
    const bool rsn_valid = valid(adv.rsn);
    const bool wpa_valid = valid(adv.wpa);

    // Separately confirmed legacy risk: a Valid original-WPA element, or a
    // TKIP/WEP option in a Valid element. Independent of the overall status, so
    // receive-verified elements survive a malformed or unknown sibling (docs/contracts.md section 6).
    if (s.rx_status == RxStatus::Ok) {
        if (wpa_valid) a.legacy_risk = true;
        if (rsn_valid && ((pairwise_kinds(adv.rsn) | adv.rsn.group.kind) & kLegacyCipher)) a.legacy_risk = true;
        if (wpa_valid && ((pairwise_kinds(adv.wpa) | adv.wpa.group.kind) & kLegacyCipher)) a.legacy_risk = true;
    }
    // Keep specifically confirmed weak ciphers even if another element later
    // prevents a complete rating. Missing/malformed elements infer nothing.
    if (s.rx_status == RxStatus::Ok) {
        std::uint16_t known_pairwise = 0, known_group = 0;
        if (rsn_valid) { known_pairwise |= pairwise_kinds(adv.rsn); known_group |= adv.rsn.group.kind; }
        if (wpa_valid) { known_pairwise |= pairwise_kinds(adv.wpa); known_group |= adv.wpa.group.kind; }
        if (known_pairwise & kLegacyCipher) a.pairwise = weakest(known_pairwise & kLegacyCipher);
        if (known_group & kLegacyCipher) a.group = weakest(known_group & kLegacyCipher);
    }
    if (a.legacy_risk) a.reason = Finding::Legacy;

    // Gate 1: only a Complete advertisement with validated settings is rated.
    const bool advertisement = s.kind == FrameKind::Beacon || s.kind == FrameKind::ProbeResponse;
    if (s.parse != ParseStatus::Complete || !advertisement || !s.settings_present || !adv.privacy_valid) {
        a.unrated = Unrated::Incomplete;
        return a;
    }
    // Gate 2: the adapter must vouch for the bytes (checksum / driver state).
    if (s.rx_status != RxStatus::Ok) {
        a.unrated = Unrated::ReceiveUnverified;
        return a;
    }

    // Weakest-advertised summary from the Valid elements.
    std::uint16_t akms = 0, pairwise = 0, group = 0;
    if (rsn_valid) { akms |= adv.rsn.akms.kinds; pairwise |= pairwise_kinds(adv.rsn); group |= adv.rsn.group.kind; }
    if (wpa_valid) { akms |= adv.wpa.akms.kinds; pairwise |= pairwise_kinds(adv.wpa); group |= adv.wpa.group.kind; }
    const bool any_element = rsn_valid || wpa_valid;
    const bool unknown_option = (rsn_valid && has_unknown(adv.rsn)) || (wpa_valid && has_unknown(adv.wpa));

    if (!any_element) {
        if (adv.owe_transition == ElementState::Valid) a.mode = Mode::Owe; // open side of an OWE transition pair
        else if (!adv.privacy_bit) { a.mode = Mode::Open; a.pairwise = Cipher::None; a.group = Cipher::None; }
        else { a.mode = Mode::Wep; a.pairwise = Cipher::Wep; a.group = Cipher::Wep; }
        a.pmf = Pmf::Disabled; // no RSNE: PMF cannot be offered
    } else {
        if (akms & akm::Unknown) a.mode = Mode::Unknown;
        else if (akms & akm::Owe) a.mode = Mode::Owe;
        else if (akms & kEnterprise) a.mode = Mode::Enterprise;
        else if (wpa_valid) a.mode = Mode::Wpa1; // original WPA advertised: the weakest mode, whatever the RSNE adds
        else {
            const bool sae = (akms & kSaeFamily) != 0;
            const bool psk = (akms & kWpa2Personal) != 0;
            a.mode = sae && psk ? Mode::Transition : sae ? Mode::Wpa3Personal : psk ? Mode::Wpa2Personal : Mode::Unknown;
        }
        if (!(pairwise & cipher::Unknown)) a.pairwise = weakest(pairwise);
        if (!(group & cipher::Unknown)) a.group = weakest(group);
        a.pmf = rsn_valid ? adv.rsn.pmf : Pmf::Disabled; // original WPA has no PMF
    }

    // Gate 3: unknown options block a complete grade; the summary above keeps the known weaker ones visible.
    if (unknown_option) { a.unrated = Unrated::UnknownOption; return a; }
    if (!s.settings_complete) { a.unrated = Unrated::Incomplete; return a; }

    // Gate 4: contradictions are not graded.
    const bool sae_present = (akms & kSaeFamily) != 0;
    const bool invalid_management_cipher = rsn_valid
        && (adv.rsn.group_management.kind == 0 || (adv.rsn.group_management.kind & ~kBip) != 0);
    if ((!any_element && adv.privacy_bit && adv.owe_transition == ElementState::Valid)
        || invalid_management_cipher || (any_element && !adv.privacy_bit)                                         // RSN/WPA advertised with Privacy clear
        || (any_element && adv.owe_transition == ElementState::Valid && !(akms & akm::Owe)) // transition element on a non-OWE BSS
        || ((pairwise | group) & kBip)                                              // management-only cipher offered for data
        || (sae_present && a.pmf == Pmf::Disabled)) {                               // SAE requires PMF capability
        a.unrated = Unrated::Inconsistent;
        return a;
    }

    // Gate 5: deliberately unspecified policies.
    if (a.mode == Mode::Owe) { a.unrated = Unrated::Owe; return a; }
    if (a.mode == Mode::Enterprise) { a.unrated = Unrated::Enterprise; return a; }

    // The five rows, weakest advertised option first.
    if (a.mode == Mode::Open) { a.mood = Mood::Horrible; a.reason = Finding::Unencrypted; return a; }
    if (a.mode == Mode::Wep || ((pairwise | group) & kWep)) {
        a.legacy_risk = true;
        a.mood = Mood::Horrible;
        a.reason = Finding::Legacy;
        return a;
    }
    if (wpa_valid || ((pairwise | group) & cipher::Tkip)) {
        a.legacy_risk = true;
        a.mood = Mood::Bad;
        a.reason = Finding::Legacy;
        return a;
    }
    const bool strong = pairwise != 0 && (pairwise & ~kStrong) == 0 && group != 0 && (group & ~kStrong) == 0;
    if (!strong || a.pmf == Pmf::Unknown) { a.unrated = Unrated::Unspecified; return a; }
    switch (a.mode) {
    case Mode::Wpa3Personal:
        if (a.pmf == Pmf::Required) { a.mood = Mood::VeryGood; a.reason = Finding::StrongSettings; return a; }
        a.unrated = Unrated::Unspecified; // SAE-only without PMF required is outside the documented rows
        a.reason = Finding::PmfNotRequired;
        return a;
    case Mode::Wpa2Personal:
        if (pairwise != cipher::Ccmp128 || group != cipher::Ccmp128) { a.unrated = Unrated::Unspecified; return a; }
        if (a.pmf == Pmf::Required) { a.mood = Mood::Good; a.reason = Finding::Wpa2PmfRequired; return a; }
        a.mood = Mood::Medium;
        a.reason = Finding::PmfNotRequired;
        return a;
    case Mode::Transition:
        a.mood = Mood::Medium;
        a.reason = Finding::CompatibilityMode;
        return a;
    default:
        a.unrated = Unrated::Unspecified;
        return a;
    }
}

SecurityObservation observe_security(const ParseResult& p, const RxMeta& m) {
    SecurityObservation s{};
    s.network = p.identity;
    s.ssid_kind = p.ssid_kind;
    s.acquired = m.acquired;
    s.origin = m.origin;
    s.band = m.band;
    s.channel = m.channel;
    s.rssi = m.rssi_valid ? m.rssi_dbm : 0;
    s.rssi_valid = m.rssi_valid;
    s.rx_status = m.status;
    s.kind = p.kind;
    const bool advertisement = p.kind == FrameKind::Beacon || p.kind == FrameKind::ProbeResponse;
    if (!advertisement || !p.header_valid) {
        s.parse = ParseStatus::Unrelated; // never security evidence, whatever else the frame is
        return s;
    }
    s.parse = p.status;
    s.settings_present = p.settings_present;
    s.settings_complete = p.settings_complete;
    s.settings = p.settings;
    return s;
}

SignalObservation observe_signal(const ParseResult& p, const RxMeta& m) {
    SignalObservation s{};
    // Only frames the AP itself transmitted (addr2 == BSSID) measure the AP's
    // signal here; a client's frame to the AP carries the BSSID too, but its
    // RSSI is the client's (supervisor review 2026-11-17).
    if (p.header_valid && p.addr2 == p.identity.bssid) s.bssid = p.identity.bssid;
    s.acquired = m.acquired;
    s.origin = m.origin;
    s.band = m.band;
    s.channel = m.channel;
    s.rssi = m.rssi_valid ? m.rssi_dbm : 0;
    s.rssi_valid = m.rssi_valid;
    s.kind = p.kind;
    return s;
}

} // namespace guardian

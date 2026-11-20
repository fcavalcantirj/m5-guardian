#pragma once

#include <cstdint>

#include "guardian/parser.hpp"
#include "guardian/radio.hpp"

// G04: the portable security-frame parser behind the G01 FrameParser contract.
//
// Independent implementation (docs/research/reuse-decisions.md, G02): no
// libwifi, SDK or AntiHunter code. Format knowledge comes from IEEE 802.11-2020
// (clauses cited in parser.cpp). Standard C++ only, no allocation, no pointer
// kept into the frame; every output is a ParseResult value.
//
// Input contract (guardian/radio.hpp): the span starts at Frame Control and
// EXCLUDES the FCS. ESP-IDF sig_len/FCS adaptation is the acquisition
// adapter's job and never happens here. RxStatus::FcsError / DriverError are
// rejected before any byte is read. RxStatus::Unknown is parsed structurally;
// it is not a claim that the checksum was verified, and the metadata keeps
// that uncertainty for the policy layer.
//
// Status rules (binding, tested in firmware/tests/parser_check.cpp):
//   * Complete: header, fixed body and every element were validated to the end
//     of the span and the span was not truncated by the adapter.
//   * Truncated: FrameSpan::truncated, or an element/field claims more bytes
//     than remain (ParseError::IeOverrun). Elements fully validated before the
//     cut stay Valid as partial evidence; settings_complete is false.
//   * Malformed: a structural rule failed (bad length, count, version, PMF
//     flags, conflicting duplicate, bad vendor OUI). Malformed wins over
//     Truncated. Only independently valid elements keep their fields; every
//     invalid element is zeroed with its ElementState set.
//   * Unsupported: valid frame of a kind/option not decoded here (protected
//     disconnect bodies, Action/Authentication/Association bodies, EAPOL body,
//     protocol version != 0).
//   * Unrelated: Control frames, non-EAPOL Data frames, extension frames.
//   The parser never emits an open/WEP classification; G05 derives grades and
//   must require status == Complete && settings_complete for a full grade.
//
// Optional RSN/WPA fields absent at the END of an otherwise valid element get
// the documented defaults (IEEE 802.11-2020 9.4.2.24.1: CCMP-128 / CCMP-128 /
// 802.1X / capabilities 0 / BIP-CMAC-128; WPA v1: TKIP / TKIP / 802.1X). A
// defaulted selector is reported with SuiteSelector::present == false; a
// defaulted list has count 1. A field cut in the middle, a zero or oversized
// count, or trailing bytes after the last defined field reject the element.
//
// Hidden/empty/non-UTF-8 SSIDs: Network keeps the exact bytes and length;
// SsidKind and ssid_utf8 are flags. Nothing is substituted or injected.
namespace guardian {

// Wire selector encoding shared with SuiteList: OUI in the upper 24 bits,
// suite type in the low 8 (docs/contracts.md section 6).
constexpr std::uint32_t make_selector(std::uint32_t oui24, std::uint8_t type) {
    return ((oui24 & 0xffffffu) << 8) | type;
}

namespace oui {
constexpr std::uint32_t Ieee8021 = 0x000fac; // RSN selectors (00-0F-AC)
constexpr std::uint32_t Microsoft = 0x0050f2; // WPA vendor element and selectors (00-50-F2)
constexpr std::uint32_t Wfa = 0x506f9a;       // Wi-Fi Alliance vendor elements (50-6F-9A)
} // namespace oui

class SecurityFrameParser final : public FrameParser {
public:
    ParseResult parse(const FrameSpan& frame, const RxMeta& meta) const override;
};

} // namespace guardian

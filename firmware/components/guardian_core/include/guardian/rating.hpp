#pragma once

#include "guardian/core.hpp"
#include "guardian/parser.hpp"
#include "guardian/radio.hpp"

// G05: the documented v1 rating of ADVERTISED Wi-Fi configuration and the
// reduction from a parsed frame to the observations Core stores.
//
// This is Guardian's product policy, not a standard certification and not a
// probability of being hacked. It rates what the selected AP advertises in
// beacons/probe responses; it cannot see which options a client negotiated,
// whether the password is strong, or who really transmitted a frame. The exact
// table and every deliberate decision are in docs/G05-rating-freshness.md;
// firmware/tests/rating_check.cpp is the executable form of that table.
//
// Weakest-advertised rule: every AKM and every pairwise/group cipher in both
// the WPA vendor element and the RSNE counts; a legacy fallback caps the grade.
//
//   Very good  SAE-family AKMs only (SAE, FT-SAE, SAE-EXT-KEY), pairwise and
//              group among CCMP-128/256, GCMP-128/256, PMF Required, no WPA element
//   Good       WPA2-Personal AKMs only (PSK, PSK-SHA256, FT-PSK), CCMP-128
//              pairwise and group, PMF Required
//   Medium     WPA2-Personal, CCMP-128, PMF Optional or Disabled (the PMF
//              limitation is the finding, not "broken"); or WPA2/WPA3 transition
//              (PSK-family and SAE-family together) with strong ciphers and PMF
//              Optional or Required (a valid compatibility choice)
//   Bad        a Valid original-WPA vendor element, or any TKIP option anywhere
//   Horrible   Complete beacon with Privacy clear and no RSN/WPA/OWE-transition
//              element (unencrypted open access); Privacy set with no RSN/WPA
//              element (WEP); or any WEP-40/104 selector
//
// Not rated (Assessment::unrated names the reason; mood stays Unknown):
//   Incomplete (parse not Complete / settings incomplete / not an advertisement),
//   ReceiveUnverified (RxStatus not Ok), UnknownOption (unmapped selector),
//   Owe (OWE AKM or the open side of an OWE transition pair), Enterprise (any
//   802.1X/Suite B AKM, including the RSNE default when the AKM list is absent),
//   Inconsistent (RSN/WPA with Privacy clear, SAE without PMF capability, BIP as
//   a data cipher, OWE transition element on a non-OWE BSS), Unspecified (valid
//   and understood but outside the rows above, e.g. SAE-only with PMF Optional
//   or WPA2-Personal with GCMP). A separately confirmed legacy risk (Valid WPA
//   element, TKIP or WEP option in a Valid element) is reported through
//   Assessment::legacy_risk and Finding::Legacy even when the grade is blocked.
namespace guardian {

// Rates one reading. Pure; no time or freshness here (Core applies freshness
// before calling it). Never returns a mood for a reading whose parse is not
// Complete with present+complete settings and RxStatus::Ok.
Assessment assess(const SecurityObservation&);

// Reduction from the parser's output and the adapter's metadata to the
// reading Core stores. Copies identity bytes, acquisition Instant, origin,
// band/channel, RSSI validity, RX status, parse status and the settings record.
// A frame that is not a Beacon/ProbeResponse yields parse == Unrelated with no
// settings, so it can never become security evidence.
SecurityObservation observe_security(const ParseResult&, const RxMeta&);

// Signal/activity reading for any frame with a valid header: BSSID from the
// parse result, RSSI and acquisition Instant from the metadata. Core::signal()
// matches it by BSSID only. It never carries settings.
SignalObservation observe_signal(const ParseResult&, const RxMeta&);

} // namespace guardian

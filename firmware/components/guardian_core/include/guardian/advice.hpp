#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "guardian/capabilities.hpp"
#include "guardian/core.hpp"
#include "guardian/time.hpp"

// G07: evidence-based advice over a Core Snapshot, without overstating Wi-Fi
// health. Portable policy, standard C++ only, no allocation, no time read: the
// Snapshot already carries ages, and advise() is a pure reduction of it.
//
// What this layer says, and only from what the Snapshot holds:
//   * what the ADVERTISED settings mean in simple words (WPA3 preference,
//     transition-mode compatibility, legacy WPA/TKIP/WEP risk, PMF limits), as
//     AdviceId codes a renderer turns into text with advice_text();
//   * exactly one relevant next step for the current evidence (NextStep);
//   * the received signal AT THIS DEVICE with its age and sampling interval,
//     kept apart from the security mood (SignalView);
//   * owner checks the sensor cannot verify by listening, always marked
//     Unverified in v1 (OwnerCheck);
//   * what is NOT measured in passive-only v1: connection health, password
//     strength, transmitter identity (Verification::NotMeasured).
//
// What it never does: change the mood (Advice::mood is copied from the
// Snapshot, never recomputed), give credit for a hidden SSID or MAC filtering,
// infer speed, congestion, Internet access, interference or whole-home coverage
// from RSSI or AP counts, turn missing data, a lost Internet connection or a
// failed probe into an RF attack, or ask for the home password. A disconnect
// burst is reported as observed disconnect traffic with its uncertainty, not as
// an attacker.
//
// Primary references (docs/research/wifi-audit.md): Apple router guidance
// (support.apple.com/en-us/102766: WPA3 preferred, WPA2/WPA3 transition as a
// compatibility choice, WPA2 AES where needed, hidden SSID / MAC filtering give
// no security credit), Espressif Wi-Fi security guide (PMF required/optional/
// disabled, OWE is not plain open), FTC home Wi-Fi guidance (unique passwords,
// router admin credentials, updates, remote administration/WPS/UPnP, guest
// separation). Policy text: docs/G07-advice.md; executable form:
// firmware/tests/advice_check.cpp (written and run RED first).
namespace guardian {

// How a statement in the advice was established. Unknown is never Observed.
enum class Verification : std::uint8_t {
    NotMeasured, // v1 has no instrument for it (connection health, password strength, transmitter identity)
    Unverified,  // an owner check: the sensor cannot confirm it by listening
    Observed     // derived from received frames held in the Snapshot
};

// Simple-language explanation items. Each has one text in advice_text().
// Ordered roughly from "state of the evidence" to "what the settings mean".
enum class AdviceId : std::uint8_t {
    None,
    // evidence state
    NoSampleYet,              // Checking: nothing received from the selected network in this timebase yet
    NoFreshData,              // Stale: last sample at least Core::fresh_ms (29 s) old; the old grade is not current
    ListeningDegraded,        // Degraded: gaps/drops at this device; the view is incomplete, not the network
    LastKnownFromEarlierBoot, // historical record only: age unknown across timebases
    ReceiveUnverified,        // adapter could not vouch for the bytes (checksum state unknown)
    // why there is no grade
    IncompleteAdvertisement,  // parse not Complete / settings incomplete: no grade, not "open"
    UnknownOptionAdvertised,  // an option the policy does not know: no grade; known weaker options still shown
    ContradictoryAdvertisement, // settings contradict each other: wait for another sample / check the router
    OweNotPlainOpen,          // OWE: encrypted without a password; not rated, not "unencrypted"
    EnterpriseNotRated,       // 802.1X / Suite B: outside the personal-network policy
    OutsideDocumentedRows,    // valid, understood, but no documented row (e.g. SAE-only with PMF optional)
    // what the advertised settings mean
    Wpa3Strong,               // SAE only, strong ciphers, PMF required: the preferred setting
    Wpa2AesPmfRequired,       // WPA2-Personal AES with PMF required: good; WPA3 is the stronger option
    PmfNotRequired,           // PMF optional/disabled: management frames of clients that skip it are unprotected
    TransitionIsCompatibility,// WPA2/WPA3 transition: a valid compatibility choice, not broken
    LegacyWpaTkip,            // original WPA or TKIP advertised: deprecated, weak; remove it
    WepIsBroken,              // WEP: broken; replace
    OpenUnencrypted,          // Privacy clear, no RSN/WPA/OWE: anyone nearby can read the traffic
    // what gives no credit, what is not measured
    HiddenSsidOrMacFilteringNoCredit, // a hidden network name or MAC filtering is not a security measure; rated the same
    SignalIsLocalOnly,        // RSSI = received at this device; says nothing about speed, congestion, Internet or coverage
    ConnectionNotMeasured,    // passive v1 measures no gateway/DNS/HTTPS health
    EndpointFailureIsNotWifiFailure, // a failed probe endpoint is not by itself a Wi-Fi failure or an attack
    PasswordStrengthNotMeasured, // the sensor cannot see the password; never asks for it
    // incidents, with uncertainty
    DisconnectTrafficObserved,// observed disconnect frames: may be a reboot, roaming, interference or a flood
    UnexpectedApObserved,     // the selected name from an unapproved AP: could be an extender you did not approve
    SettingsChangeObserved,   // the AP advertises other settings than approved: check the router
    OweOpenTransition,
    OweUnverified,       // OWE information present; encryption on this BSS is not established
    // G16F (appended): a passive pattern (join flood, unannounced channel switch,
    // name mismatch, open twin) received under the selected or an approved BSSID.
    NetworkPatternObserved,
    Count
};

// One next step for the current evidence; the renderer shows it on its own line.
enum class NextStep : std::uint8_t {
    None,
    KeepListening,            // no sample yet: keep the device near the router and wait
    CheckDeviceListening,     // degraded/stale: check this device's listening (position, power), not the network
    WaitForLiveSample,        // historical record: wait for a sample in this boot
    WaitForAnotherSample,     // contradictory/incomplete/unverified: wait for another advertisement
    NotRatedByPolicy,         // OWE/Enterprise/unknown option/outside rows: nothing to change from here
    EnableWpa2AesOrWpa3,      // open: turn encryption on
    ReplaceWep,               // WEP: move to WPA2 AES or WPA3
    RemoveWpaTkip,            // WPA/TKIP: WPA2 AES or WPA3 only
    RequirePmfOrEnableWpa3,   // WPA2 AES with PMF optional/disabled
    MoveToWpa3OnlyWhenReady,  // transition mode: WPA3-only once every device supports it
    ConsiderWpa3,             // WPA2 AES PMF required: WPA3 if router and devices support it
    KeepRouterUpdated,        // WPA3 strong: nothing to change in settings; the owner checks remain
    CheckWhetherDevicesDropped, // disconnect traffic observed
    CheckUnapprovedAp,        // unexpected AP observed
    CheckRouterSettings,      // settings change observed
    CheckNetworkPattern,      // G16F: a passive pattern on the owner's network observed
    Count
};

// Owner checks the sensor cannot verify by listening (FTC guidance). Each is
// Unverified in v1; a later authorized router integration could mark one
// Observed. Nothing here is awarded mood points.
enum class OwnerCheckId : std::uint8_t {
    LongUniqueWifiPassword,
    UniqueRouterAdminCredentials,
    SupportedFirmwareWithUpdates,
    WpsOffUnlessNeeded,         // WPS IE presence/absence proves neither exploitable nor disabled
    RemoteAdministrationOff,
    UpnpOffUnlessNeeded,
    GuestAndIotSeparation,      // a guest SSID alone cannot prove isolation
    Count
};

struct OwnerCheck {
    OwnerCheckId id{OwnerCheckId::LongUniqueWifiPassword};
    Verification status{Verification::Unverified};
};

// Received signal AT THIS DEVICE for the selected BSSID. Facts about this
// receiver's samples: strength, age, and the interval between the last two
// accepted samples. No field here describes speed, congestion, Internet access,
// interference or coverage elsewhere, and none of it feeds the mood.
struct SignalView {
    bool available{};         // a same-epoch reading exists (Snapshot::has_signal)
    bool rssi_valid{};        // the adapter marked the RSSI valid
    std::int8_t rssi_dbm{};
    Millis age_ms{};          // Snapshot::signal_age_ms
    bool interval_known{};    // two accepted samples exist in this epoch
    Millis interval_ms{};     // time between the last two accepted samples
    Band band{Band::Ghz2_4};
    std::uint8_t channel{};   // channel the radio was tuned to for the last sample
};

// ---- later associated probes: contract only, no implementation in v1 ---------------------
//
// A later version may ASSOCIATE to the selected network and time a gateway
// ping, a DNS lookup and an HTTPS fetch. That is active behavior, kept apart
// from passive monitoring. Before any implementation these must be fixed:
//   * credentials: the owner enters them in the picker and they are stored by
//     the board's key-value adapter; the passive path never reads them and no
//     mood is awarded for having them (CredentialSource::OwnerEntered);
//   * destinations: the DHCP gateway, one DNS name, one HTTPS host, named here,
//     never a list learned from traffic;
//   * timeouts: per step, bounded, so a hung probe cannot stall the display;
//   * channel-sharing gap: while associated the radio is not listening
//     passively; the gap is reported through CoverageReport (channel 0 /
//     listened_ms) and never hidden;
//   * user-visible opt-in: off by default; the detail screen says "connection
//     check ON" while it runs.
// A failed endpoint is a fact about that endpoint from this device; it is not
// by itself a Wi-Fi failure, a security finding or an attack (see
// ConnectivityResult and AdviceId::EndpointFailureIsNotWifiFailure).
enum class CredentialSource : std::uint8_t { None, OwnerEntered };

struct ConnectivityProbePlan {
    bool opt_in{};                                  // user-visible switch; false = never associate
    CredentialSource credentials{CredentialSource::None};
    std::array<char, 64> dns_name{};                // one DNS name to resolve
    std::array<char, 64> https_host{};              // one HTTPS host to fetch from
    bool gateway_from_dhcp{true};                   // the gateway is whatever DHCP assigns, never typed
    Millis step_timeout_ms{3000};                   // per gateway / DNS / HTTPS step
    Millis probe_interval_ms{600000};               // how often; the passive gap repeats this often
    Millis max_channel_gap_ms{15000};               // longest allowed interruption of passive listening
};

enum class EndpointState : std::uint8_t { NotMeasured, Reached, Failed, TimedOut };

struct ConnectivityResult {
    Support measured{Support::Unsupported};  // v1: Unsupported; a later probe adapter sets Supported
    Instant sampled_at{};
    EndpointState gateway{EndpointState::NotMeasured};
    EndpointState dns{EndpointState::NotMeasured};
    EndpointState https{EndpointState::NotMeasured};
    Millis gateway_rtt_ms{};
    Millis dns_ms{};
    Millis https_ms{};
};

// The advice for one Snapshot. Value type, fixed size.
struct Advice {
    static constexpr std::size_t max_items = 12;

    // Copied from the Snapshot. advise() never recomputes or adjusts them.
    Mood mood{Mood::Unknown};
    Finding reason{Finding::Unknown};
    Unrated unrated{Unrated::None};
    Coverage coverage{Coverage::Checking};
    Millis age_ms{};
    bool historical{};

    // Simple-language items in display order; `items[0..count)` are set.
    std::array<AdviceId, max_items> items{};
    std::uint8_t count{};
    NextStep next_step{NextStep::None};

    SignalView signal{};

    // Separately labelled things v1 cannot establish.
    Verification connection_health{Verification::NotMeasured};
    Verification password_strength{Verification::NotMeasured};
    Verification transmitter_identity{Verification::NotMeasured};
    ConnectivityResult connection{};  // echoed input; never changes mood or incidents

    std::array<OwnerCheck, static_cast<std::size_t>(OwnerCheckId::Count)> owner_checks{};

    bool has(AdviceId id) const {
        for (std::uint8_t i = 0; i < count && i < max_items; ++i) if (items[i] == id) return true;
        return false;
    }
};

// Pure reduction. `connection` defaults to "not measured" (v1).
Advice advise(const Snapshot&, const ConnectivityResult& connection = ConnectivityResult{});

// Static-storage simple-language texts (string literals; never allocated). The
// renderer wraps them. Every id has a non-empty text; None/Count give "".
const char* advice_text(AdviceId);
const char* advice_text(NextStep);
const char* advice_text(OwnerCheckId);
const char* advice_text(Verification);

} // namespace guardian

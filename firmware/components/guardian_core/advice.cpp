// G07: evidence-based advice over a Core Snapshot. Policy text and every
// decision: guardian/advice.hpp (summary) and docs/G07-advice.md (full text).
// Executable form: firmware/tests/advice_check.cpp (written RED first).
//
// Standard C++ only, no allocation, no time read. advise() is a pure function
// of the Snapshot (plus an optional, v1-unsupported connectivity result). The
// mood is copied, never recomputed: nothing here can raise or lower a grade.
#include "guardian/advice.hpp"

#include <cstdint>

namespace guardian {
namespace {

// Append without duplicates, bounded by Advice::max_items. Order of calls is
// the display order: current incidents, state of the evidence, why there is no
// grade, what the settings mean, what gives no credit, what is not measured.
void push(Advice& a, AdviceId id) {
    if (id == AdviceId::None || id == AdviceId::Count) return;
    if (a.has(id)) return;
    if (a.count >= Advice::max_items) return;
    a.items[a.count++] = id;
}

bool current(const Snapshot& s, IncidentKind k) {
    const auto i = static_cast<std::size_t>(k);
    return i < s.incidents.size() && s.incidents[i];
}

// WEP is named only when the weakest-advertised summary says so; everything
// else legacy is original WPA / TKIP.
bool wep_advertised(const Assessment& a) {
    return a.mode == Mode::Wep || a.pairwise == Cipher::Wep || a.group == Cipher::Wep;
}

bool sampled(EndpointState e) { return e != EndpointState::NotMeasured; }
bool failed(EndpointState e) { return e == EndpointState::Failed || e == EndpointState::TimedOut; }

} // namespace

Advice advise(const Snapshot& s, const ConnectivityResult& connection) {
    Advice a{};
    // Copied facts. The grade is the G05 policy's and stays exactly as given,
    // and it is reported only over Fresh evidence: Core already blanks the
    // Assessment when stale/degraded; this layer refuses to show a grade a
    // hand-assembled Snapshot might still carry (stale data is never a fresh
    // positive grade).
    const bool fresh = s.coverage == Coverage::Fresh;
    a.mood = fresh ? s.settings.mood : Mood::Unknown;
    a.reason = fresh ? s.settings.reason : Finding::Unknown;
    a.unrated = fresh ? s.settings.unrated : Unrated::None;
    a.coverage = s.coverage;
    a.age_ms = s.age_ms;
    a.historical = s.security_historical;

    // Owner checks: always listed, always Unverified in passive v1.
    for (std::size_t i = 0; i < a.owner_checks.size(); ++i) {
        a.owner_checks[i].id = static_cast<OwnerCheckId>(i);
        a.owner_checks[i].status = Verification::Unverified;
    }

    // Received signal at this device, as Core holds it. Never an input to anything below.
    if (s.has_signal) {
        a.signal.available = true;
        a.signal.rssi_valid = s.last_signal.rssi_valid;
        a.signal.rssi_dbm = s.last_signal.rssi_valid ? s.last_signal.rssi : static_cast<std::int8_t>(0);
        a.signal.age_ms = s.signal_age_ms;
        a.signal.interval_known = s.signal_interval_known;
        a.signal.interval_ms = s.signal_interval_known ? s.signal_interval_ms : 0;
        a.signal.band = s.last_signal.band;
        a.signal.channel = s.last_signal.channel;
    }

    // Connection health: a later active probe's result, echoed and labelled. Unknown is never Observed.
    a.connection = connection;
    const bool probed = connection.measured == Support::Supported
        && (sampled(connection.gateway) || sampled(connection.dns) || sampled(connection.https));
    a.connection_health = probed ? Verification::Observed : Verification::NotMeasured;
    const bool endpoint_failed = probed && (failed(connection.gateway) || failed(connection.dns) || failed(connection.https));

    // 1. Current incidents lead. They are observations with their uncertainty, never a transmitter identity.
    const bool burst = current(s, IncidentKind::DisconnectBurst);
    const bool unexpected = current(s, IncidentKind::UnexpectedAp);
    const bool changed = current(s, IncidentKind::SettingsChanged);
    if (burst) push(a, AdviceId::DisconnectTrafficObserved);
    if (unexpected) push(a, AdviceId::UnexpectedApObserved);
    if (changed) push(a, AdviceId::SettingsChangeObserved);
    const bool pattern = current(s, IncidentKind::NetworkPattern);   // G16F
    if (pattern) push(a, AdviceId::NetworkPatternObserved);

    // 2. State of the evidence.
    if (a.historical) push(a, AdviceId::LastKnownFromEarlierBoot);
    switch (s.coverage) {
    case Coverage::Checking: push(a, AdviceId::NoSampleYet); break;
    case Coverage::Stale: push(a, AdviceId::NoFreshData); break;
    case Coverage::Degraded: push(a, AdviceId::ListeningDegraded); break;
    case Coverage::Fresh: break;
    }

    // 3./4. Why there is no grade, or what the advertised settings mean. Fresh evidence only.
    bool legacy_named = false;
    if (fresh) {
        switch (s.settings.unrated) {
        case Unrated::None: break;
        case Unrated::Incomplete: push(a, AdviceId::IncompleteAdvertisement); break;
        case Unrated::ReceiveUnverified: push(a, AdviceId::ReceiveUnverified); break;
        case Unrated::UnknownOption: push(a, AdviceId::UnknownOptionAdvertised); break;
        case Unrated::Owe: {
            const auto& settings = s.last_security.settings;
            const bool open_side = s.has_security && settings.privacy_valid && !settings.privacy_bit
                && settings.rsn.state == ElementState::Absent && settings.wpa.state == ElementState::Absent
                && settings.owe_transition == ElementState::Valid;
            const bool owe_akm = settings.rsn.state == ElementState::Valid && (settings.rsn.akms.kinds & akm::Owe);
            push(a, open_side ? AdviceId::OweOpenTransition : owe_akm ? AdviceId::OweNotPlainOpen : AdviceId::OweUnverified);
            break;
        }
        case Unrated::Enterprise: push(a, AdviceId::EnterpriseNotRated); break;
        case Unrated::Inconsistent: push(a, AdviceId::ContradictoryAdvertisement); break;
        case Unrated::Unspecified:
            push(a, AdviceId::OutsideDocumentedRows);
            if (s.settings.reason == Finding::PmfNotRequired) push(a, AdviceId::PmfNotRequired); // SAE-only, PMF optional
            break;
        }
        switch (s.settings.mood) {
        case Mood::Unknown: break;
        case Mood::VeryGood: push(a, AdviceId::Wpa3Strong); break;
        case Mood::Good: push(a, AdviceId::Wpa2AesPmfRequired); break;
        case Mood::Medium:
            if (s.settings.reason == Finding::CompatibilityMode) push(a, AdviceId::TransitionIsCompatibility);
            else push(a, AdviceId::PmfNotRequired);
            break;
        case Mood::Bad:
            push(a, AdviceId::LegacyWpaTkip);
            legacy_named = true;
            break;
        case Mood::Horrible:
            if (s.settings.reason == Finding::Unencrypted) push(a, AdviceId::OpenUnencrypted);
            else if (wep_advertised(s.settings)) push(a, AdviceId::WepIsBroken);
            else push(a, AdviceId::LegacyWpaTkip);
            legacy_named = true;
            break;
        }
        // A separately confirmed legacy risk survives a blocked grade (G05); it stays visible here.
        if (s.settings.legacy_risk && !legacy_named) {
            push(a, wep_advertised(s.settings) ? AdviceId::WepIsBroken : AdviceId::LegacyWpaTkip);
            legacy_named = true;
        }
        // 5. No credit for hiding the name (or MAC filtering, which cannot be seen at all).
        if (s.has_security && hidden_ssid(s.last_security.ssid_kind)) push(a, AdviceId::HiddenSsidOrMacFilteringNoCredit);
    }

    // 6. What is local and what is not measured.
    if (a.signal.available) push(a, AdviceId::SignalIsLocalOnly);
    if (endpoint_failed) push(a, AdviceId::EndpointFailureIsNotWifiFailure);
    else if (!probed) push(a, AdviceId::ConnectionNotMeasured);
    if (fresh) push(a, AdviceId::PasswordStrengthNotMeasured);

    // One next step, from the most current evidence down.
    if (burst) a.next_step = NextStep::CheckWhetherDevicesDropped;
    else if (unexpected) a.next_step = NextStep::CheckUnapprovedAp;
    else if (changed) a.next_step = NextStep::CheckRouterSettings;
    else if (pattern) a.next_step = NextStep::CheckNetworkPattern;
    else if (a.historical) a.next_step = NextStep::WaitForLiveSample;
    else if (s.coverage == Coverage::Checking) a.next_step = NextStep::KeepListening;
    else if (!fresh) a.next_step = NextStep::CheckDeviceListening; // Stale or Degraded: this device's listening
    else if (s.settings.unrated != Unrated::None) {
        if (s.settings.legacy_risk) a.next_step = wep_advertised(s.settings) ? NextStep::ReplaceWep : NextStep::RemoveWpaTkip;
        else switch (s.settings.unrated) {
        case Unrated::Incomplete:
        case Unrated::ReceiveUnverified:
        case Unrated::Inconsistent: a.next_step = NextStep::WaitForAnotherSample; break;
        default: a.next_step = NextStep::NotRatedByPolicy; break; // UnknownOption, Owe, Enterprise, Unspecified
        }
    } else switch (s.settings.mood) {
    case Mood::VeryGood: a.next_step = NextStep::KeepRouterUpdated; break;
    case Mood::Good: a.next_step = NextStep::ConsiderWpa3; break;
    case Mood::Medium:
        a.next_step = s.settings.reason == Finding::CompatibilityMode ? NextStep::MoveToWpa3OnlyWhenReady
                                                                      : NextStep::RequirePmfOrEnableWpa3;
        break;
    case Mood::Bad: a.next_step = NextStep::RemoveWpaTkip; break;
    case Mood::Horrible:
        a.next_step = s.settings.reason == Finding::Unencrypted ? NextStep::EnableWpa2AesOrWpa3
                    : wep_advertised(s.settings)                ? NextStep::ReplaceWep
                                                                : NextStep::RemoveWpaTkip;
        break;
    case Mood::Unknown: a.next_step = NextStep::WaitForAnotherSample; break; // fresh, no grade, no reason: not a Core state
    }
    return a;
}

// Simple language, short lines; the renderer wraps. No claim beyond the evidence.
const char* advice_text(AdviceId id) {
    switch (id) {
    case AdviceId::NoSampleYet: return "Nothing received from your network yet in this session.";
    case AdviceId::NoFreshData: return "No fresh data: no new reading for 29 seconds. The old rating is not current.";
    case AdviceId::ListeningDegraded: return "This device had listening gaps or dropped frames. The view is incomplete; the network is not judged.";
    case AdviceId::LastKnownFromEarlierBoot: return "Last known from an earlier session. Its age is unknown and it is not rated.";
    case AdviceId::ReceiveUnverified: return "The receiver could not confirm these bytes arrived intact. Not rated.";
    case AdviceId::IncompleteAdvertisement: return "The advertisement could not be fully read. Not rated; this does not mean the network is open.";
    case AdviceId::UnknownOptionAdvertised: return "The router advertises an option this device does not know. Not rated; known weaker options are still shown.";
    case AdviceId::ContradictoryAdvertisement: return "The advertised settings contradict each other. Not rated.";
    case AdviceId::OweOpenTransition: return "This is the open side of an OWE transition pair. It advertises an encrypted counterpart, but that counterpart and the client connection are not verified. Not rated.";
    case AdviceId::OweUnverified: return "OWE information is present, but encryption on this access point is not established. Not rated.";
    case AdviceId::NetworkPatternObserved: return "Unusual management or handshake frames were received for your access point. Addresses can be forged; it is not proof of an attack.";
    case AdviceId::OweNotPlainOpen: return "This access point advertises OWE encryption without a password. The client connection is not verified. Not rated.";
    case AdviceId::EnterpriseNotRated: return "Enterprise (802.1X) login. Outside this home-network rating.";
    case AdviceId::OutsideDocumentedRows: return "Valid settings this rating has no row for. Not rated.";
    case AdviceId::Wpa3Strong: return "WPA3-Personal only, strong ciphers, protected management frames required. This is the preferred setting.";
    case AdviceId::Wpa2AesPmfRequired: return "WPA2-Personal with AES and protected management frames required. Good; WPA3 is the stronger option.";
    case AdviceId::PmfNotRequired: return "Protected management frames are optional or off. Devices that skip them can be disconnected by forged frames.";
    case AdviceId::TransitionIsCompatibility: return "WPA2/WPA3 mixed mode: a reasonable compatibility choice while older devices need WPA2. Not broken.";
    case AdviceId::LegacyWpaTkip: return "Original WPA or TKIP is advertised. These are deprecated and weak; remove them when every device allows it.";
    case AdviceId::WepIsBroken: return "WEP is advertised. WEP is broken and should be replaced.";
    case AdviceId::OpenUnencrypted: return "No Wi-Fi encryption is advertised. Nearby listeners can read unencrypted traffic; HTTPS still protects its content.";
    case AdviceId::HiddenSsidOrMacFilteringNoCredit: return "A hidden network name or MAC filtering adds no security. The rating is the same.";
    case AdviceId::SignalIsLocalOnly: return "Signal is what this device receives here. It says nothing about speed, congestion, Internet access or coverage elsewhere.";
    case AdviceId::ConnectionNotMeasured: return "Connection health is not measured: this device only listens.";
    case AdviceId::EndpointFailureIsNotWifiFailure: return "A connection check failed. That is a fact about that endpoint, not by itself a Wi-Fi problem or an attack.";
    case AdviceId::PasswordStrengthNotMeasured: return "Password strength cannot be seen from the air and is never asked for.";
    case AdviceId::DisconnectTrafficObserved: return "Many disconnect frames were received for your network. A router reboot, roaming or interference can cause this; it is not proof of an attack.";
    case AdviceId::UnexpectedApObserved: return "Your network name was advertised by an access point you did not approve. It could be an extender or a neighbour's router.";
    case AdviceId::SettingsChangeObserved: return "Your access point advertises settings or a channel different from the approved ones.";
    case AdviceId::None:
    case AdviceId::Count: break;
    }
    return "";
}

const char* advice_text(NextStep step) {
    switch (step) {
    case NextStep::KeepListening: return "Keep this device near the router and wait for a reading.";
    case NextStep::CheckDeviceListening: return "Check this device's position and power; the network is not being judged.";
    case NextStep::WaitForLiveSample: return "Wait for a fresh reading in this session.";
    case NextStep::WaitForAnotherSample: return "Wait for another advertisement before acting.";
    case NextStep::NotRatedByPolicy: return "Nothing to change from this reading.";
    case NextStep::EnableWpa2AesOrWpa3: return "Turn on WPA3, or WPA2 with AES, in the router.";
    case NextStep::ReplaceWep: return "Replace WEP with WPA3, or WPA2 with AES.";
    case NextStep::RemoveWpaTkip: return "Set the router to WPA2 AES or WPA3 only; remove WPA/TKIP.";
    case NextStep::RequirePmfOrEnableWpa3: return "If every device supports it, require protected management frames or enable WPA3.";
    case NextStep::MoveToWpa3OnlyWhenReady: return "Move to WPA3 only once every device supports it.";
    case NextStep::ConsiderWpa3: return "Consider WPA3 if the router and your devices support it.";
    case NextStep::KeepRouterUpdated: return "Settings are strong as advertised. Keep the router updated (owner check).";
    case NextStep::CheckWhetherDevicesDropped: return "Check whether your devices dropped off and whether the router restarted.";
    case NextStep::CheckUnapprovedAp: return "If this is your extender, approve it; otherwise check who uses your network name.";
    case NextStep::CheckRouterSettings: return "Check the router's security and channel settings against what you approved.";
    case NextStep::CheckNetworkPattern: return "Check whether your devices still connect normally, and keep the Guardian listening.";
    case NextStep::None:
    case NextStep::Count: break;
    }
    return "";
}

const char* advice_text(OwnerCheckId id) {
    switch (id) {
    case OwnerCheckId::LongUniqueWifiPassword: return "Long, unique Wi-Fi passphrase (not reused anywhere).";
    case OwnerCheckId::UniqueRouterAdminCredentials: return "Unique router admin user and passphrase, not the factory default.";
    case OwnerCheckId::SupportedFirmwareWithUpdates: return "Router firmware still supported and updated.";
    case OwnerCheckId::WpsOffUnlessNeeded: return "WPS off unless needed. Seeing WPS advertised proves nothing either way.";
    case OwnerCheckId::RemoteAdministrationOff: return "Remote administration off.";
    case OwnerCheckId::UpnpOffUnlessNeeded: return "UPnP off unless something needs it.";
    case OwnerCheckId::GuestAndIotSeparation: return "Guest and smart-home devices on a separate network. A guest name alone does not prove isolation.";
    case OwnerCheckId::Count: break;
    }
    return "";
}

const char* advice_text(Verification v) {
    switch (v) {
    case Verification::NotMeasured: return "not measured";
    case Verification::Unverified: return "unverified";
    case Verification::Observed: return "observed";
    }
    return "";
}

} // namespace guardian

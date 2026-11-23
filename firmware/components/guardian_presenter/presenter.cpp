#include "guardian/presenter.hpp"
#include <algorithm>
#include <cstring>
#include <limits>

namespace guardian {
namespace {
bool valid_identity(const Network& n) {
    return n.ssid_size <= n.ssid.size() && !(n.bssid[0] & 1)
        && std::any_of(n.bssid.begin(), n.bssid.end(), [](auto b) { return b != 0; });
}
bool same_ssid(const Network& a, const Network& b) {
    return a.ssid_size <= a.ssid.size() && b.ssid_size == a.ssid_size
        && std::equal(a.ssid.begin(), a.ssid.begin() + a.ssid_size, b.ssid.begin());
}
bool age_of(Instant seen, Instant now, Millis& age) {
    if (!seen.valid() || !now.valid() || seen.epoch != now.epoch || seen.at > now.at) return false;
    age = now.at - seen.at;
    return true;
}
void increment(std::uint32_t& n) { if (n < std::numeric_limits<std::uint32_t>::max()) ++n; }
Overlay evidence_overlay(const Snapshot& s) {
    if (s.security_historical) return Overlay::NoFreshData;
    switch (s.coverage) {
    case Coverage::Checking: return Overlay::Checking;
    case Coverage::Stale: return Overlay::NoFreshData;
    case Coverage::Degraded: return Overlay::CoverageDegraded;
    case Coverage::Fresh: return s.settings.mood == Mood::Unknown ? Overlay::Unsupported : Overlay::None;
    }
    return Overlay::Unsupported;
}
IncidentBanner incident_banner(const Snapshot& s) {
    IncidentBanner b{};
    for (std::size_t i = 0; i < s.incidents.size(); ++i) {
        if (!s.incidents[i]) continue;
        ++b.current;
        if (b.visible) continue;
        b.visible = true; b.kind = static_cast<IncidentKind>(i);
        const auto& e = s.evidence[i];
        b.count = e.count; b.window_ms = e.window_ms; b.threshold = e.threshold;
        b.raw_frames = e.raw_frames; b.retries_deduped = e.retries_deduped;
        b.protected_frames = e.protected_frames; b.eapol_frames = e.eapol_frames;
        b.saturated = e.saturated; b.coverage_known = e.coverage_known;
        b.listened_ms = e.listened_ms; b.coverage_window_ms = e.coverage_window_ms;
        b.hopping = e.hopping; b.changes = e.changes; b.bssid = e.bssid; b.bssid_text = mac_text(e.bssid);
        b.pattern = e.pattern; b.distinct_sources = e.distinct_sources;   // G16F
        b.shapes = e.shapes;                                               // G16J
        b.top = e.top;                                                     // G16S
        b.own_frames = e.own_frames;                                       // G16T
        switch (b.kind) {
        case IncidentKind::DisconnectBurst: b.item = AdviceId::DisconnectTrafficObserved; break;
        case IncidentKind::UnexpectedAp: b.item = AdviceId::UnexpectedApObserved; break;
        case IncidentKind::SettingsChanged: b.item = AdviceId::SettingsChangeObserved; break;
        case IncidentKind::NetworkPattern: b.item = AdviceId::NetworkPatternObserved; break;
        case IncidentKind::Count: break;
        }
    }
    return b;
}
ApprovedAp approval(const Candidate& c) {
    ApprovedAp ap{}; ap.network = c.network; ap.settings_known = c.settings_complete;
    if (ap.settings_known) ap.settings = c.settings;
    ap.channel_known = c.settings_complete && c.ds_channel_present && c.ds_channel != 0;
    ap.band = c.band; if (ap.channel_known) ap.channel = c.ds_channel;
    return ap;
}
bool valid_ap(const ApprovedAp& ap) {
    if (ap.settings_known) {
        const auto& f = ap.settings;
        const auto state_valid = [](ElementState s) { return static_cast<unsigned>(s) <= static_cast<unsigned>(ElementState::Conflicting); };
        if (!state_valid(f.wpa_state) || !state_valid(f.rsn_state) || !state_valid(f.owe_transition)
            || static_cast<unsigned>(f.pmf) > static_cast<unsigned>(Pmf::Required)) return false;
        // Bits reserved by the current portable parser cannot be decoded as known facts.
        if (((f.wpa_akms | f.rsn_akms) & 0x4000u)
            || ((f.wpa_pairwise | f.wpa_group | f.rsn_pairwise | f.rsn_group | f.rsn_group_management) & 0x7000u)) return false;
    }
    return valid_identity(ap.network) && static_cast<unsigned>(ap.band) < static_cast<unsigned>(Band::Count)
        && (!ap.channel_known || (ap.channel != 0 && (ap.band != Band::Ghz2_4 || ap.channel <= 14)));
}
} // namespace

Label ssid_label(const Network& n) {
    const auto end = n.ssid.begin() + std::min<std::size_t>(n.ssid_size, n.ssid.size());
    const bool hidden = std::all_of(n.ssid.begin(), end, [](auto byte) { return byte == 0; });
    return ssid_label(n, hidden && n.ssid_size <= n.ssid.size() ? SsidKind::Hidden : SsidKind::Present);
}
Label ssid_label(const Network& n, SsidKind kind) {
    Label l{}; l.invalid = n.ssid_size > n.ssid.size();
    l.hidden = hidden_ssid(kind); l.absent = kind == SsidKind::Absent; // G16E: NUL-byte names are hidden too
    if ((l.hidden || l.absent) && !l.invalid) {
        const char* marker = l.hidden ? "(hidden)" : "(no name)";
        l.length = static_cast<std::uint8_t>(std::strlen(marker));
        std::copy_n(marker, l.length, l.text.begin());
        return l;
    }
    l.length = static_cast<std::uint8_t>(std::min<std::size_t>(n.ssid_size, n.ssid.size()));
    for (std::size_t i = 0; i < l.length; ++i) {
        const auto byte = n.ssid[i]; const bool printable = byte >= 0x20 && byte <= 0x7e;
        l.text[i] = printable ? static_cast<char>(byte) : '?'; l.altered |= !printable;
    }
    l.exact = !l.invalid && !l.altered;
    return l;
}
MacText mac_text(const Mac& mac) {
    constexpr char hex[] = "0123456789ABCDEF";
    MacText out{};
    for (std::size_t i = 0; i < mac.size(); ++i) {
        out.text[3 * i] = hex[mac[i] >> 4]; out.text[3 * i + 1] = hex[mac[i] & 15];
        if (i < mac.size() - 1) out.text[3 * i + 2] = ':';
    }
    return out;
}
const char* mood_text(Mood m) {
    switch (m) {
    case Mood::VeryGood: return "Very good"; case Mood::Good: return "Good";
    case Mood::Medium: return "Medium"; case Mood::Bad: return "Bad";
    case Mood::Horrible: return "Horrible"; case Mood::Unknown: return "Not rated";
    }
    return "Not rated";
}
const char* overlay_text(Overlay o) {
    switch (o) {
    case Overlay::None: return ""; case Overlay::Checking: return "Checking";
    case Overlay::NoFreshData: return "No fresh data"; case Overlay::CoverageDegraded: return "Listening coverage degraded";
    case Overlay::Unsupported: return "Not rated"; case Overlay::Incident: return "Observed incident";
    }
    return "Not rated";
}
const char* mode_text(Mode m) {
    switch (m) {
    case Mode::Open: return "Open"; case Mode::Wep: return "WEP"; case Mode::Wpa1: return "WPA";
    case Mode::Wpa2Personal: return "WPA2-Personal"; case Mode::Wpa3Personal: return "WPA3-Personal";
    case Mode::Transition: return "WPA2/WPA3 transition"; case Mode::Owe: return "OWE";
    case Mode::Enterprise: return "Enterprise"; case Mode::Unknown: return "Unknown";
    }
    return "Unknown";
}
const char* cipher_text(Cipher c) {
    switch (c) {
    case Cipher::None: return "None"; case Cipher::Wep: return "WEP"; case Cipher::Tkip: return "TKIP";
    case Cipher::Ccmp: return "CCMP"; case Cipher::Gcmp: return "GCMP"; case Cipher::Unknown: return "Unknown";
    }
    return "Unknown";
}
const char* pmf_text(Pmf p) {
    switch (p) {
    case Pmf::Required: return "Required"; case Pmf::Optional: return "Optional";
    case Pmf::Disabled: return "Disabled"; case Pmf::Unknown: return "Unknown";
    }
    return "Unknown";
}
const char* coverage_text(Coverage c) {
    switch (c) {
    case Coverage::Fresh: return "Fresh"; case Coverage::Checking: return "Checking";
    case Coverage::Stale: return "Stale"; case Coverage::Degraded: return "Degraded";
    }
    return "Unknown";
}
const char* incident_text(IncidentKind k) {
    switch (k) {
    case IncidentKind::DisconnectBurst: return "Disconnect traffic observed";
    case IncidentKind::UnexpectedAp: return "Unapproved AP observed";
    case IncidentKind::SettingsChanged: return "Advertised settings changed";
    case IncidentKind::NetworkPattern: return "Management-frame pattern observed";
    case IncidentKind::Count: return "";
    }
    return "";
}
const char* screen_text(Screen s) {
    switch (s) { case Screen::Face: return "Face"; case Screen::Details: return "Details"; case Screen::Picker: return "Networks"; case Screen::Settings: return "Settings"; }
    return "";
}
const char* view_mode_text(ViewMode m) { return m == ViewMode::Demo ? "DEMO" : "LIVE"; }
const char* alert_text(IncidentKind k) {
    switch (k) {
    case IncidentKind::DisconnectBurst: return "Disconnect burst detected";
    case IncidentKind::UnexpectedAp: return "Another device is using your network's name";   // G16J (owner wording)
    case IncidentKind::SettingsChanged: return "Advertised settings changed";
    case IncidentKind::NetworkPattern: return "Frame pattern on your network";
    case IncidentKind::Count: return "";
    }
    return "";
}
// G16F: one wording table per Pattern: what was received, never who sent it.
namespace {
struct PatternWords { const char* area; const char* network; const char* unit; };
PatternWords pattern_words(Pattern p) {
    switch (p) {
    case Pattern::ProbeFloodRandom: return {"Probe flood nearby", "Probe flood on your network", "probes"};
    case Pattern::ProbeFloodSource: return {"One address probing nonstop nearby", "One address probing nonstop on your network", "probes"};
    case Pattern::ProbeFloodName: return {"Many devices asking for one name nearby", "Many devices asking for your network", "askers"};
    case Pattern::BeaconFlood: return {"Beacon flood nearby", "Beacon flood on your network", "beacons"};
    case Pattern::ManyNames: return {"One radio answering for many names nearby", "One radio answering for many names on your network", "names"};
    case Pattern::AuthFlood: return {"Join flood nearby", "Join flood on your network", "requests"};
    case Pattern::SaeCommitFlood: return {"WPA3 handshake flood nearby", "WPA3 handshake flood on your network", "unanswered"};
    case Pattern::AssocSleep: return {"Sleeping-join flood nearby", "Sleeping-join flood on your network", "requests"};
    case Pattern::ChannelSwitch: return {"Unusual channel-switch order nearby", "Channel switch your AP never announced on your network", "frames"};
    case Pattern::QuietOrder: return {"Long quiet order nearby", "Long quiet order on your network", "frames"};
    case Pattern::NameMismatch: return {"Network name mismatch nearby", "Network name mismatch on your network", "replies"};
    case Pattern::MarkedBeacon: return {"Marked beacon nearby", "Marked beacon on your network", "beacons"};
    case Pattern::OpenTwin: return {"Open copy of an OWE network nearby", "Open copy of your network name on your network", "beacons"};
    case Pattern::DeauthSource: return {"Disconnects from one address nearby", "Disconnects from one address on your network", "frames"};
    case Pattern::DeauthPair: return {"Disconnects aimed at one device nearby", "Disconnects aimed at one device on your network", "frames"};
    case Pattern::DeauthBroadcast: return {"Broadcast disconnects nearby", "Broadcast disconnects on your network", "frames"};
    case Pattern::NameRotation: return {"One radio rotating names nearby", "One radio rotating names on your network", "names"};
    case Pattern::OpenLure: return {"Rotating names with open lures nearby", "Rotating names with open lures on your network", "names"};
    // G16G: handshake and frame-loss observations. Never "cracked", never who captured anything.
    case Pattern::PmkidHarvest: return {"Unanswered handshakes to one device nearby", "Unanswered handshakes to one device on your network", "APs"};
    case Pattern::FakeM1: return {"Forged-looking handshake start nearby", "Forged-looking handshake start on your network", "frames"};
    case Pattern::DeauthHandshake: return {"Clients pushed off, then reconnected nearby",
                                           "Clients were pushed off your network and reconnected (a handshake was exchanged)", "frames"};
    case Pattern::FrameLoss: return {"Heavy frame loss on this channel nearby", "Heavy frame loss on your network's channel", "errors"};
    // G16J. Each area text wraps into the two 22-glyph rows of the amber status slot.
    case Pattern::KarmaAnswer: return {"New radio answering an asked name nearby", "New radio answering an asked name on your network", "frames"};
    case Pattern::LurePortal: return {"Open lure network from a maker board nearby", "Open lure network from a maker board on your network", "beacons"};
    case Pattern::NoiseFloor: return {"Noise floor jumped on this channel nearby", "Noise floor jumped on your network's channel", "dB"};
    // G16H Bluetooth LE. What was received, never a vendor, a tool or a sender; never Network scope
    // (the second text exists only because every pattern has one).
    case Pattern::PairingPopupFlood: return {"Pairing-popup spam nearby", "Pairing-popup spam near your network", "messages"};
    case Pattern::FastPairRotation: return {"One address spamming pairing popups nearby", "One address spamming pairing popups near your network", "products"};
    case Pattern::None:
    case Pattern::Count: break;
    }
    return {"", "", ""};
}
} // namespace
const char* area_text(const IncidentObservation& o) { return o.pattern == Pattern::None ? area_text(o.family) : pattern_words(o.pattern).area; }
const char* area_unit(const IncidentObservation& o) { return o.pattern == Pattern::None ? area_unit(o.family) : pattern_words(o.pattern).unit; }
const char* network_pattern_text(Pattern p) { return pattern_words(p).network; }
namespace {
// G16T: a nearby disconnect burst that also named the picked network (IncidentBanner::own_frames).
constexpr char kNearbyAlsoReason[] = "Disconnect burst nearby also on your network";
constexpr char kNearbyAlsoLead[] = "Nearby burst also on ";   // one 22-glyph glass row, then the network's name
constexpr char kRouterAlertReason[] = "Your router changed its security settings";   // G25 STRICT
// The red reason of a current NetworkPattern incident (G16F wording, G16T for the nearby burst).
const char* pattern_reason(const IncidentBanner& b) {
    return b.own_frames ? kNearbyAlsoReason : network_pattern_text(b.pattern);
}
} // namespace
const char* tool_shape_text(std::uint16_t shapes) { return shapes ? "looks like a known attack tool" : ""; }

// G16E: what was seen nearby (observations, never a tool or an attacker).
const char* area_text(DetectorFamily f) {
    switch (f) {
    case DetectorFamily::Disconnect: return "Disconnects nearby";
    case DetectorFamily::Baseline: return "AP changes nearby";
    case DetectorFamily::Probe: return "Probe flood nearby";
    case DetectorFamily::Beacon: return "Beacon flood nearby";
    case DetectorFamily::Responder: return "Name answering nearby";
    case DetectorFamily::Auth: return "Join flood nearby";
    case DetectorFamily::ChannelSwitch: return "Channel orders nearby";
    case DetectorFamily::Identity: return "Name mismatch nearby";
    case DetectorFamily::Jamming: return "Frame loss nearby";
    case DetectorFamily::Bluetooth: return "Pairing-popup spam nearby";   // G16H
    case DetectorFamily::Count: break;
    }
    return "";
}
const char* area_unit(DetectorFamily f) {
    switch (f) {
    case DetectorFamily::Disconnect: return "frames";
    case DetectorFamily::Baseline: return "beacons";
    case DetectorFamily::Probe: return "probes";
    case DetectorFamily::Beacon: return "beacons";
    case DetectorFamily::Responder: return "names";
    case DetectorFamily::Auth: return "requests";
    case DetectorFamily::ChannelSwitch: return "frames";
    case DetectorFamily::Identity: return "frames";
    case DetectorFamily::Jamming: return "errors";
    case DetectorFamily::Bluetooth: return "messages";   // G16H
    case DetectorFamily::Count: break;
    }
    return "";
}
const char* family_text(DetectorFamily f) {
    switch (f) {
    case DetectorFamily::Disconnect: return "disconnect";
    case DetectorFamily::Baseline: return "AP baseline";
    case DetectorFamily::Probe: return "probe";
    case DetectorFamily::Beacon: return "beacon";
    case DetectorFamily::Responder: return "responder";
    case DetectorFamily::Auth: return "join";
    case DetectorFamily::ChannelSwitch: return "channel switch";
    case DetectorFamily::Identity: return "name";
    case DetectorFamily::Jamming: return "frame loss";
    case DetectorFamily::Bluetooth: return "bluetooth";   // G16H
    case DetectorFamily::Count: break;
    }
    return "";
}
namespace {
// G16E: the current area observations of a snapshot, newest first (bounded by area_slots).
std::uint8_t current_area(const Snapshot& s, std::array<std::size_t, area_slots>& order) {
    std::uint8_t n = 0;
    for (std::size_t i = 0; i < area_slots; ++i) if (s.area_visible[i]) order[n++] = i;
    std::sort(order.begin(), order.begin() + n, [&](std::size_t a, std::size_t b) { return s.area[a].acquired.at > s.area[b].acquired.at; });
    return n;
}
} // namespace

ViewModel present(const Snapshot& s) {
    ViewModel v{};
    v.demo = s.origin == Origin::Demo; v.mode = v.demo ? ViewMode::Demo : ViewMode::Live;
    v.origin = s.origin; v.source_label = v.demo ? "DEMO" : s.origin == Origin::Imported ? "IMPORTED" : "LIVE";
    v.historical = s.origin == Origin::Imported || s.security_historical;
    v.age_ms = s.age_ms; v.explanation = s.settings.reason; v.unrated = s.settings.unrated;
    v.incident = incident_banner(s); v.incident_visible = v.incident.visible;
    v.incident_seq = s.incident_seq;   // G16N
    v.has_selection = valid_identity(s.selected);
    if (v.has_selection) {
        v.selected_label = s.has_security && s.last_security.network == s.selected
            ? ssid_label(s.selected, s.last_security.ssid_kind) : ssid_label(s.selected);
        v.selected_bssid = mac_text(s.selected.bssid);
    }
    v.overlay = evidence_overlay(s);
    if (s.coverage == Coverage::Fresh && !s.security_historical) v.face = s.settings.mood;
    v.muted = v.face == Mood::Unknown || v.historical;
    if (s.coverage == Coverage::Fresh && v.incident_visible && !s.security_historical) v.overlay = Overlay::Incident;
    v.celebrate = v.face == Mood::VeryGood && !v.incident_visible && !v.historical;
    v.mood_label = mood_text(v.face); v.overlay_label = overlay_text(v.overlay);
    v.alert = v.incident_visible; v.alert_reason = v.alert ? alert_text(v.incident.kind) : "";
    if (v.alert && v.incident.kind == IncidentKind::NetworkPattern && v.incident.pattern != Pattern::None)   // G16F
        v.alert_reason = pattern_reason(v.incident);
    // G16E amber: area observations never touch face/rating/alert; they only end the celebration.
    std::array<std::size_t, area_slots> order{};
    v.caution_count = current_area(s, order);
    v.caution = v.caution_count > 0;
    if (v.caution) { v.caution_evidence = s.area[order[0]]; v.caution_reason = area_text(v.caution_evidence); }
    v.celebrate = v.celebrate && !v.caution;
    return v;
}

bool candidate_from(const ParseResult& p, const RxMeta& m, Candidate& out) {
    out = Candidate{};
    if (!p.header_valid || p.ssid_kind == SsidKind::Absent || (p.kind != FrameKind::Beacon && p.kind != FrameKind::ProbeResponse)
        || !valid_identity(p.identity)) return false;
    out.network = p.identity; out.ssid_kind = p.ssid_kind; out.ssid_utf8 = p.ssid_utf8;
    out.origin = m.origin; out.seen = m.acquired; out.band = m.band; out.channel = m.channel;
    out.rssi = m.rssi_dbm; out.rssi_valid = m.rssi_valid;
    out.settings_complete = p.status == ParseStatus::Complete && p.settings_complete && m.status == RxStatus::Ok;
    if (out.settings_complete) {
        out.settings = SettingsFingerprint::of(p.settings);
        out.ds_channel_present = p.settings.ds_channel_present; out.ds_channel = p.settings.ds_channel;
    }
    return true;
}

bool PersistedSelection::valid() const {
    if (version != current_version || approved_count > approved.size()) return false;
    if (!has_selection) return approved_count == 0;
    if (!valid_ap(selected)) return false;
    for (std::size_t i = 0; i < approved_count; ++i) {
        const auto& ap = approved[i];
        if (!valid_ap(ap) || !same_ssid(ap.network, selected.network) || ap.network.bssid == selected.network.bssid) return false;
        for (std::size_t j = 0; j < i; ++j) if (approved[j].network.bssid == ap.network.bssid) return false;
    }
    return true;
}
PersistedSelection persist(const ApprovedScope& scope) {
    PersistedSelection r{}; r.has_selection = scope.has_selection();
    if (r.has_selection) r.selected = scope.selected();
    r.approved_count = static_cast<std::uint8_t>(scope.approved_count());
    for (std::size_t i = 0; i < scope.approved_count() && i < r.approved.size(); ++i) r.approved[i] = *scope.approved_at(i);
    if (!scope.configured()) r.version = 0;
    return r;
}
bool restore(const PersistedSelection& r, ApprovedScope& scope) {
    if (!r.valid() || !scope.configured()) return false;
    ApprovedScope next(scope.max_approved_aps());
    if (r.has_selection && !next.select(r.selected)) return false;
    for (std::size_t i = 0; i < r.approved_count; ++i) if (!next.approve(r.approved[i])) return false;
    scope = next;
    return true;
}

Snapshot demo_snapshot(std::uint8_t step) {
    Snapshot s{}; s.origin = Origin::Demo; s.coverage = Coverage::Fresh; s.has_security = true;
    s.selected.bssid = {2,0,0,0,0,1}; s.selected.ssid = {'D','E','M','O'}; s.selected.ssid_size = 4;
    auto& o = s.last_security; o.network = s.selected; o.origin = Origin::Demo; o.ssid_kind = SsidKind::Present;
    o.kind = FrameKind::Beacon; o.parse = ParseStatus::Complete; o.rx_status = RxStatus::Ok;
    o.settings_present = o.settings_complete = true; o.settings.privacy_valid = true;
    constexpr Mood moods[] = {Mood::VeryGood, Mood::Good, Mood::Medium, Mood::Bad, Mood::Horrible};
    constexpr Finding reasons[] = {Finding::StrongSettings, Finding::Wpa2PmfRequired, Finding::PmfNotRequired, Finding::Legacy, Finding::Unencrypted};
    const auto i = step % demo_steps; auto& a = s.settings; a.mood = moods[i]; a.reason = reasons[i];
    a.mode = i == 0 ? Mode::Wpa3Personal : i < 3 ? Mode::Wpa2Personal : i == 3 ? Mode::Wpa1 : Mode::Open;
    a.pairwise = a.group = i < 3 ? Cipher::Ccmp : i == 3 ? Cipher::Tkip : Cipher::None;
    a.pmf = i < 2 ? Pmf::Required : i == 2 ? Pmf::Optional : Pmf::Disabled; a.legacy_risk = i == 3;
    o.settings.privacy_bit = i != 4;
    if (i < 3) {
        auto& r = o.settings.rsn; r.state = ElementState::Valid; r.pmf = a.pmf;
        r.akms.kinds = i == 0 ? akm::Sae : akm::Psk;
        r.akms.count = r.pairwise.count = 1;
        r.akms.selectors[0] = i == 0 ? 0x000fac08 : 0x000fac02;
        r.pairwise.selectors[0] = 0x000fac04; r.group.selector = 0x000fac04;
        // Parser supplies the default BIP-CMAC-128 when the RSNE omits it.
        r.group_management.kind = cipher::BipCmac128; r.group_management.selector = 0x000fac06;
        r.pairwise.kinds = cipher::Ccmp128; r.group.kind = cipher::Ccmp128; r.group.present = true;
    } else if (i == 3) {
        auto& w = o.settings.wpa; w.state = ElementState::Valid; w.akms.kinds = akm::Wpa1Psk;
        w.akms.count = w.pairwise.count = 1; w.akms.selectors[0] = 0x0050f202;
        w.pairwise.selectors[0] = 0x0050f202; w.group.selector = 0x0050f202;
        w.pairwise.kinds = cipher::Tkip; w.group.kind = cipher::Tkip; w.group.present = true;
    }
    return s;
}

Presenter::Presenter(DisplayCapabilities display, Origin live_origin) : display_(display), live_origin_(live_origin) {
    live_.origin = live_origin_; demo_ = demo_snapshot(0); rebuild();
}
const Snapshot& Presenter::shown() const { return mode_ == ViewMode::Demo ? demo_ : live_; }
void Presenter::update(const Snapshot& live, Instant now, const ApprovedScope* scope, const RouterState* router) {
    if (live.origin != live_origin_ || live.origin == Origin::Demo) return;
    if (have_now_ && now.valid() && now.epoch == now_.epoch && now.at < now_.at) return;
    if (router) {   // G25: new router events count as dark-screen wakes when the setting colours them
        if (router->change_seq >= router_seen_seq_ && router->moves >= router_seen_moves_) {
            if (device_.router != RouterPolicy::DetailsOnly) router_wakes_ += router->change_seq - router_seen_seq_;
            if (device_.router == RouterPolicy::Strict) router_wakes_ += router->moves - router_seen_moves_;
        }
        router_seen_seq_ = router->change_seq; router_seen_moves_ = router->moves;   // a reset detector starts again from 0
        router_ = *router;
    }
    // A request was made in the previous selection context. Do not apply it
    // to a different selected network after an external selection update.
    if (!(live.selected == live_.selected) || !now.valid()
        || (have_now_ && now.epoch != now_.epoch)) request_ = {};
    const bool was_alert = view_.alert;
    live_ = live; scope_ = scope; now_ = now; have_now_ = now.valid();
    expire(now);
    if (mode_ == ViewMode::Demo && incident_banner(live_).visible) { mode_ = ViewMode::Live; to_face(); }
    tick_plate();
    rebuild();
    // G24 alert-first (owner, G23 run): a NEW red ALERT shows on the face, whatever page was open; it stays
    // there unless the owner opens another page. Amber (caution) keeps the open page, as before.
    if (view_.alert && !was_alert && screen_ != Screen::Face) { to_face(); rebuild(); }
}
void Presenter::expire(Instant now) {
    Network cursor_identity{}; const bool cursor_known = cursor_ < picker_.count;
    if (cursor_known) cursor_identity = picker_.entries[cursor_].network;
    for (auto& slot : slots_) {
        Millis age{};
        if (slot.used && (!age_of(slot.c.seen, now, age) || age >= candidate_ttl_ms)) slot = Slot{};
    }
    if (cursor_known) {
        std::uint8_t index = 0;
        for (const auto& slot : slots_) if (slot.used) {
            if (slot.c.network == cursor_identity) { cursor_ = index; break; }
            ++index;
        }
    }
    // Conservative aging between Core updates. Never reassess or promote a grade.
    Millis age{};
    if (live_.has_security) {
        if (age_of(live_.last_security.acquired, now, age) && !live_.security_historical) {
            live_.age_ms = age;
            if (age >= Core::fresh_ms && live_.coverage == Coverage::Fresh) live_.coverage = Coverage::Stale;
        } else {
            live_.security_historical = true; live_.age_ms = 0; live_.coverage = Coverage::Stale;
        }
    }
    if (live_.coverage != Coverage::Fresh) live_.settings.mood = Mood::Unknown;
    if (live_.has_signal) {
        if (age_of(live_.last_signal.acquired, now, age)) live_.signal_age_ms = age;
        else live_.has_signal = false;
    }
    if (live_.has_coverage) {
        if (age_of(live_.last_coverage.sampled_at, now, age)) live_.coverage_age_ms = age;
        else live_.has_coverage = false;
    }
    for (std::size_t i = 0; i < live_.incidents.size(); ++i) {
        if (live_.incidents[i] && (!age_of(live_.evidence[i].acquired, now, age) || age >= Core::incident_ms)) live_.incidents[i] = false;
    }
    for (std::size_t i = 0; i < area_slots; ++i) {   // G16E: area observations expire on their own window
        if (live_.area_visible[i] && (!age_of(live_.area[i].acquired, now, age) || age >= live_.area_visible_ms)) live_.area_visible[i] = false;
    }
}
IncidentBanner Presenter::banner_from(const Snapshot& s) const {
    auto b = incident_banner(s);
    if (b.visible) b.age_known = age_of(s.evidence[static_cast<std::size_t>(b.kind)].acquired, now_, b.age_ms);
    return b;
}
// G16R: the red sentence names the picked network, never an address (rules: presenter.hpp).
std::size_t alert_sentence(const ViewModel& v, char* out, std::size_t capacity, std::size_t name_glyphs) {
    if (!out || !capacity) return 0;
    out[0] = 0;
    if (!v.alert) return 0;
    // Plain copies: the portable presenter uses no formatted output (tests/portability_check.cmake).
    constexpr std::size_t all = std::numeric_limits<std::size_t>::max();
    std::size_t used = 0;
    bool fits = true;
    const auto put = [&](const char* text, std::size_t limit) {
        for (std::size_t i = 0; fits && i < limit && text[i]; ++i) {
            if (used + 1 >= capacity) fits = false;
            else out[used++] = text[i];
        }
    };
    // The picked network by its name, shortened with a visible '~'; "your network" when it has none to print.
    const auto network = [&] {
        const Label& name = v.selected_label;
        const bool printable = v.has_selection && name.length > 0 && !name.hidden && !name.absent && !name.invalid;
        if (!printable) put("your network", all);
        else if (name.length <= name_glyphs) put(name.c_str(), all);
        else { put(name.c_str(), name_glyphs ? name_glyphs - 1 : 0); put("~", all); }
    };
    if (v.router_alert) {   // G25: the router's own security change (STRICT), never "on <name>"
        char router[96];
        if (!router_sentence(v.router, RouterWording::Short, router, sizeof router)) router_sentence(v.router, RouterWording::Minimal, router, sizeof router);
        put(router, all);
    } else if (v.incident.kind == IncidentKind::DisconnectBurst) {
        put("Disconnect burst on ", all);
        network();
    } else if (v.incident.kind == IncidentKind::NetworkPattern && v.incident.own_frames > 0) {   // G16T
        put(kNearbyAlsoLead, all);
        network();
    } else {
        put(v.alert_reason, all);
    }
    if (!fits) { out[0] = 0; return 0; }
    out[used] = 0;
    return used;
}
void Presenter::rebuild_face(const Snapshot& s) {
    view_ = present(s); view_.screen = screen_; view_.mode = mode_; view_.demo_step = demo_step_;
    view_.incident_seq = live_.incident_seq;   // G16N: the LIVE count, whatever is shown (DEMO fixtures have none)
    view_.overlay = evidence_overlay(s); view_.overlay_label = overlay_text(view_.overlay);
    view_.incident = banner_from(s); view_.incident_visible = view_.incident.visible;
    // G14: the alert follows the presenter's own (expiring) incident view.
    view_.alert = view_.incident_visible; view_.alert_reason = view_.alert ? alert_text(view_.incident.kind) : "";
    if (view_.alert && view_.incident.kind == IncidentKind::NetworkPattern && view_.incident.pattern != Pattern::None)   // G16F
        view_.alert_reason = pattern_reason(view_.incident);
    // G25: the router's own changes, coloured by the owner's ROUTER CHANGES setting. A Core incident keeps the
    // red ALERT and its words; STRICT makes a security change the ALERT when none is shown; amber otherwise.
    rebuild_router();
    if (mode_ == ViewMode::Live && !view_.alert && view_.router.change_tone == Tone::Red) {
        view_.alert = true; view_.router_alert = true; view_.alert_reason = kRouterAlertReason;
    }
    view_.router_amber = mode_ == ViewMode::Live && !view_.alert
        && (view_.router.change_tone == Tone::Amber || view_.router.move_tone == Tone::Amber);
    view_.incident_seq = live_.incident_seq + router_wakes_;
    view_.celebrate = view_.celebrate && !view_.alert && !view_.caution && !view_.router_amber;
    if (view_.caution) view_.caution_age_known = age_of(view_.caution_evidence.acquired, now_, view_.caution_age_ms);
    view_.animate = display_.present == Support::Supported && display_.animation == Support::Supported
        && !view_.muted && !view_.incident_visible && !view_.router_alert;
    view_.last_seen_known = s.has_security && !s.security_historical
        && age_of(s.last_security.acquired, now_, view_.last_seen_ms);
}
std::uint8_t Presenter::explanation_pages() const {
    if (explanation_planned_) return explanation_planned_;
    const auto count = details_.advice.count, per_page = details_.items_per_page;
    return per_page == 0 ? 1 : static_cast<std::uint8_t>(std::max(1, (count + per_page - 1) / per_page));
}
void Presenter::rebuild_details(const Snapshot& s) {
    if (page_ == DetailsPage::Router && !view_.router.page) page_ = DetailsPage::Settings;   // G25: nothing to show there now
    details_ = {}; details_.advice = advise(s); details_.page = page_;
    details_.mood_label = mood_text(view_.face); details_.mode_label = mode_text(s.settings.mode);
    details_.pairwise_label = cipher_text(s.settings.pairwise); details_.group_label = cipher_text(s.settings.group);
    details_.pmf_label = pmf_text(s.settings.pmf); details_.coverage_label = coverage_text(s.coverage);
    details_.historical = view_.historical; details_.demo = view_.demo; details_.incident = view_.incident;
    details_.origin = view_.origin; details_.source_label = view_.source_label;
    details_.has_coverage = s.has_coverage;
    if (s.has_coverage) { details_.coverage = s.last_coverage; details_.coverage_age_ms = s.coverage_age_ms; }
    details_.age_known = view_.last_seen_known; details_.age_ms = view_.last_seen_ms;
    if (display_.present == Support::Supported) {
        details_.rows = static_cast<std::uint8_t>(std::min<unsigned>(display_.height / 8, 255));
        details_.columns = static_cast<std::uint8_t>(std::min<unsigned>(display_.width / 6, 255));
        details_.items_per_page = static_cast<std::uint8_t>(std::max(1, static_cast<int>(details_.rows) - 2));
    }
    details_.mode = s.settings.mode; details_.pairwise = s.settings.pairwise; details_.pmf = s.settings.pmf;
    plan_pages();
    explanation_page_ = std::min<std::uint8_t>(explanation_page_, explanation_pages() - 1);
    if (explanation_planned_) {
        details_.first_item = explanation_starts_[explanation_page_];
        details_.item_count = static_cast<std::uint8_t>(explanation_starts_[explanation_page_ + 1u] - details_.first_item);
    } else {
        details_.first_item = static_cast<std::uint8_t>(explanation_page_ * details_.items_per_page);
        const auto remaining = static_cast<std::uint8_t>(details_.advice.count - details_.first_item);
        details_.item_count = details_.items_per_page == 0 ? remaining : std::min(remaining, details_.items_per_page);
    }
    owner_page_ = std::min<std::uint8_t>(owner_page_, owner_pages() - 1);
    if (owner_planned_) {
        details_.first_check = owner_starts_[owner_page_];
        details_.check_count = static_cast<std::uint8_t>(owner_starts_[owner_page_ + 1u] - details_.first_check);
    } else details_.check_count = static_cast<std::uint8_t>(details_.advice.owner_checks.size());
    if (page_ == DetailsPage::Explanation) { details_.page_index = explanation_page_; details_.page_count = explanation_pages(); }
    else if (page_ == DetailsPage::OwnerChecks) { details_.page_index = owner_page_; details_.page_count = owner_pages(); }
    switch (page_) {
    case DetailsPage::Settings: details_.title = "Advertised Wi-Fi settings"; break;
    case DetailsPage::Explanation: details_.title = "Evidence and explanation"; break;
    case DetailsPage::SignalAndEvidence: details_.title = "Signal and listening coverage"; break;
    case DetailsPage::OwnerChecks: details_.title = "Owner checks: unverified"; break;
    case DetailsPage::Nearby: details_.title = "Nearby observations"; break;
    case DetailsPage::Limits: details_.title = "What it cannot see"; break;
    case DetailsPage::Router: details_.title = "Your router changed"; break;   // G25
    case DetailsPage::Count: break;
    }
    // G16E Nearby page: every current area observation, newest first.
    std::array<std::size_t, area_slots> order{};
    details_.nearby_count = current_area(s, order);
    for (std::uint8_t i = 0; i < details_.nearby_count; ++i) {
        details_.nearby[i] = s.area[order[i]];
        Millis age{};
        details_.nearby_age_ms[i] = age_of(s.area[order[i]].acquired, now_, age) ? age : 0;
    }
}
void Presenter::rebuild_picker() {
    picker_ = {}; picker_.dropped = dropped_; picker_.rejected_origin = rejected_origin_; picker_.rejected_time = rejected_time_;
    if (mode_ == ViewMode::Demo) return;
    picker_.open = screen_ == Screen::Picker;
    const bool selection = valid_identity(live_.selected);
    const bool matching_scope = scope_ && scope_->has_selection() && scope_->selected().network == live_.selected;
    for (const auto& slot : slots_) {
        if (!slot.used) continue;
        const auto& c = slot.c; auto& e = picker_.entries[picker_.count++];
        e.network = c.network; e.label = ssid_label(c.network, c.ssid_kind); e.hidden = e.label.hidden;
        e.bssid_text = mac_text(c.network.bssid); e.ssid_utf8 = c.ssid_utf8; e.band = c.band; e.channel = c.channel;
        e.rssi = c.rssi; e.rssi_valid = c.rssi_valid; e.age_known = age_of(c.seen, now_, e.age_ms);
        e.selected = selection && c.network == live_.selected;
        e.approvable = selection && same_ssid(c.network, live_.selected) && c.network.bssid != live_.selected.bssid;
        const auto* approved = matching_scope ? scope_->find(c.network.bssid) : nullptr;
        e.approved = e.approvable && approved && approved->network == c.network;
    }
    for (std::size_t i = 0; i < picker_.count; ++i) {
        auto& e = picker_.entries[i];
        for (std::size_t j = 0; j < picker_.count; ++j) if (i != j && same_ssid(e.network, picker_.entries[j].network)) e.duplicate_name = true;
        if (e.duplicate_name) {
            // Short suffix is a visual aid; the full BSSID is always available.
            std::copy_n("..:", 3, e.disambiguator.begin());
            std::copy_n(e.bssid_text.text.begin() + 12, 5, e.disambiguator.begin() + 3);
        }
    }
    cursor_ = picker_.count == 0 ? 0 : std::min<std::uint8_t>(cursor_, picker_.count - 1);
    picker_.cursor = cursor_;
}
void Presenter::rebuild() { const auto& s = shown(); rebuild_face(s); rebuild_details(s); rebuild_picker(); rebuild_settings(); }
bool Presenter::evictable(const Slot& slot) const {
    if (valid_identity(live_.selected) && slot.c.network == live_.selected) return false;
    if (scope_ && scope_->find(slot.c.network.bssid)) return false;
    if (screen_ == Screen::Picker && cursor_ < picker_.count && picker_.entries[cursor_].network == slot.c.network) return false;
    return true;
}
void Presenter::order_strongest_first() {
    std::stable_sort(slots_.begin(), slots_.end(), [](const Slot& a, const Slot& b) {
        if (a.used != b.used) return a.used;
        if (!a.used) return false;
        if (a.c.rssi_valid != b.c.rssi_valid) return a.c.rssi_valid;
        return a.c.rssi_valid && a.c.rssi > b.c.rssi;
    });
    cursor_ = 0; rebuild_picker();
}
bool Presenter::offer(const Candidate& c) {
    if (c.origin == Origin::Demo || c.origin != live_origin_) { increment(rejected_origin_); rebuild_picker(); return false; }
    Millis age{};
    if (!have_now_ || !age_of(c.seen, now_, age) || age >= candidate_ttl_ms) {
        increment(rejected_time_); rebuild_picker(); return false;
    }
    if (!valid_identity(c.network)) return false;
    Slot* free = nullptr;
    for (auto& slot : slots_) {
        if (!slot.used) { if (!free) free = &slot; continue; }
        if (slot.c.network == c.network) {
            if (slot.c.seen.at > c.seen.at) { increment(rejected_time_); rebuild_picker(); return false; }
            slot.c = c; rebuild_picker(); return true;
        }
    }
    if (!free) {
        // Full: a stronger newcomer replaces the weakest evictable entry, so the
        // owner's nearby AP is never locked out by distant networks that keep
        // re-advertising. Selected, approved and highlighted rows are kept.
        auto weaker = [](const Candidate& a, const Candidate& b) {
            if (a.rssi_valid != b.rssi_valid) return !a.rssi_valid;
            if (a.rssi_valid && a.rssi != b.rssi) return a.rssi < b.rssi;
            return a.seen.at < b.seen.at;
        };
        Slot* victim = nullptr;
        for (auto& slot : slots_) if (slot.used && evictable(slot) && (!victim || weaker(slot.c, victim->c))) victim = &slot;
        if (!victim || !weaker(victim->c, c)) { increment(dropped_); rebuild_picker(); return false; }
        *victim = Slot{}; free = victim; increment(dropped_);
    }
    // A freed storage slot can precede the current highlighted entry. Keep
    // the owner's highlight by identity rather than by the rebuilt row number.
    const bool had_cursor = picker_.count > 0;
    const Network highlighted = had_cursor ? picker_.entries[cursor_].network : Network{};
    free->c = c; free->used = true; rebuild_picker();
    if (had_cursor) {
        for (std::uint8_t i = 0; i < picker_.count; ++i) {
            if (picker_.entries[i].network == highlighted) {
                cursor_ = i; picker_.cursor = i; break;
            }
        }
    }
    return true;
}
bool Presenter::toggle_mode() {
    if (has_request() || (mode_ == ViewMode::Live && incident_banner(live_).visible)) return false;
    mode_ = mode_ == ViewMode::Live ? ViewMode::Demo : ViewMode::Live;
    demo_step_ = 0; demo_ = demo_snapshot(0); to_face();
    return true;
}
bool Presenter::set_demo(bool on) {
    if (on == (mode_ == ViewMode::Demo) || !toggle_mode()) return false;
    rebuild(); return true;
}
bool Presenter::handle(Action action, Instant now) {
    if (!now.valid() || !have_now_ || (now.epoch == now_.epoch && now.at < now_.at)) return false;
    const bool had_cursor = picker_.count > 0;
    const Network highlighted = had_cursor ? picker_.entries[cursor_].network : Network{};
    const bool time_changed = now.epoch != now_.epoch || now.at != now_.at;
    if (now.epoch != now_.epoch) request_ = {};
    now_ = now; expire(now); tick_plate(); rebuild();
    bool changed = false;
    if (screen_ == Screen::Settings) changed = settings_key(action);   // G24: its own single-key rules
    else if (screen_ == Screen::Picker) {
        if (action == Action::Back || action == Action::SecondaryLong) { screen_ = Screen::Face; changed = true; }
        else if (action == Action::Primary && picker_.count) { cursor_ = static_cast<std::uint8_t>((cursor_ + 1) % picker_.count); changed = true; }
        else if ((action == Action::Secondary || action == Action::PrimaryLong) && !has_request() && picker_.count
                 && had_cursor && picker_.entries[cursor_].network == highlighted) {
            const auto& entry = picker_.entries[cursor_];
            if (action == Action::Secondary || entry.approvable) {
                for (const auto& slot : slots_) if (slot.used && slot.c.network == entry.network) {
                    request_.kind = action == Action::Secondary ? RequestKind::Select : entry.approved ? RequestKind::Revoke : RequestKind::Approve;
                    request_.ap = approval(slot.c); request_.requested_at = now;
                    // G16J: every network the owner picks is watched for the same name from another device.
                    if (request_.kind == RequestKind::Select) request_.ap.watch_impostors = impostor_watch_;
                    if (action == Action::Secondary) screen_ = Screen::Face;
                    changed = true; break;
                }
            }
        }
    } else if (action == Action::PrimaryLong) {
        // G24 retry (owner 2026-11-21: "like side opens net list, blue opens settings"): hold FRONT on the face or a
        // details page opens the Settings screen. No key enters DEMO; somehow in DEMO, hold FRONT returns to LIVE.
        if (mode_ == ViewMode::Demo) changed = toggle_mode();
        else { open_settings(); changed = true; }
    } else if (action == Action::SecondaryLong && screen_ == Screen::Details && page_ == DetailsPage::Router && mode_ == ViewMode::Live) {
        changed = router_key(action);   // G25: hold SIDE on the Router page = accept the new settings
    } else if (action == Action::SecondaryLong && mode_ == ViewMode::Live) { screen_ = Screen::Picker; order_strongest_first(); changed = true; }
    else if (screen_ == Screen::Face) {
        if (action == Action::Primary) {
            screen_ = Screen::Details; explanation_page_ = 0; owner_page_ = 0; changed = true;
            page_ = view_.router.page ? DetailsPage::Router : DetailsPage::Settings;   // G25: the router's change first
        }
        else if (action == Action::Secondary && mode_ == ViewMode::Demo) {
            demo_step_ = static_cast<std::uint8_t>((demo_step_ + 1) % demo_steps); demo_ = demo_snapshot(demo_step_); changed = true;
        }
    } else if (screen_ == Screen::Details) {
        if (action == Action::Back || action == Action::Secondary) { screen_ = Screen::Face; changed = true; }
        else if (action == Action::Primary) {
            if (page_ == DetailsPage::Explanation && explanation_page_ + 1 < explanation_pages()) ++explanation_page_;
            else if (page_ == DetailsPage::OwnerChecks && owner_page_ + 1 < owner_pages()) ++owner_page_;
            else if (page_ == DetailsPage::OwnerChecks) { page_ = DetailsPage::Limits; owner_page_ = 0; }                    // G16J
            else if (page_ == DetailsPage::Limits && view_.caution) page_ = DetailsPage::Nearby;                               // G16E
            else if (page_ == DetailsPage::Limits || page_ == DetailsPage::Nearby) { screen_ = Screen::Face; page_ = DetailsPage::Settings; owner_page_ = 0; }
            else if (page_ == DetailsPage::Router) page_ = DetailsPage::Settings;                                               // G25
            else { page_ = static_cast<DetailsPage>(static_cast<unsigned>(page_) + 1); explanation_page_ = 0; owner_page_ = 0; }
            changed = true;
        }
    }
    rebuild(); return changed || time_changed;
}
OwnerRequest Presenter::take_request() { const auto r = request_; request_ = {}; return r; }
} // namespace guardian
// ---- G16C: row-based pagination ------------------------------------------------
namespace guardian {
std::size_t wrap_take(const char* text, std::size_t n, std::size_t at, std::size_t columns) {
    if (!text || at >= n || columns == 0) return 0;
    std::size_t take = std::min(columns, n - at);
    if (at + take < n) {                       // break at the last space that fits
        std::size_t space = take;
        while (space > 0 && text[at + space] != ' ') --space;
        if (space > 0) take = space;           // otherwise an over-long word is split
    }
    return take;
}
std::size_t wrap_next(const char* text, std::size_t n, std::size_t at, std::size_t columns) {
    if (!text || columns == 0) return n;
    at += wrap_take(text, n, at, columns);
    while (at < n && text[at] == ' ') ++at;
    return at;
}
std::size_t wrapped_rows(const char* text, std::size_t columns) {
    if (!text || columns == 0) return 0;
    const std::size_t n = std::strlen(text);
    std::size_t rows = 0;
    for (std::size_t at = 0; at < n; at = wrap_next(text, n, at, columns)) ++rows;
    return rows;
}
void Presenter::set_text_budget(const TextBudget& b) { budget_ = b; rebuild(); }
std::uint8_t Presenter::owner_pages() const { return owner_planned_ ? owner_planned_ : 1; }
namespace {
// Greedy page plan: an item that does not fit on a page that already shows
// something starts the next page; `first_used` rows are taken on page 0.
template <typename Rows, std::size_t N>
std::uint8_t plan(std::array<std::uint8_t, N>& starts, std::size_t count, std::size_t rows, std::size_t first_used, Rows rows_of) {
    std::uint8_t pages = 1; starts[0] = 0;
    std::size_t used = first_used; bool any = false;
    for (std::size_t i = 0; i < count && pages + 1 < N; ++i) {
        const auto r = rows_of(i);
        if (used + r > rows && (any || used > 0)) { starts[pages++] = static_cast<std::uint8_t>(i); used = 0; any = false; }
        used += r; any = true;
    }
    starts[pages] = static_cast<std::uint8_t>(count);
    return pages;
}
}
void Presenter::plan_pages() {
    explanation_planned_ = owner_planned_ = 0;
    const std::size_t cols = budget_.columns;
    if (!cols) return;
    const auto& a = details_.advice;
    if (budget_.explanation_rows)
        explanation_planned_ = plan(explanation_starts_, std::min<std::size_t>(a.count, Advice::max_items), budget_.explanation_rows,
            wrapped_rows(advice_text(a.next_step), cols), [&](std::size_t i) { return wrapped_rows(advice_text(a.items[i]), cols); });
    if (budget_.owner_rows)
        owner_planned_ = plan(owner_starts_, a.owner_checks.size(), budget_.owner_rows, 0,
            [&](std::size_t i) { return wrapped_rows(advice_text(a.owner_checks[i].id), cols); });
}
} // namespace guardian

// ---- G24 device settings ------------------------------------------------------------------------
namespace guardian {
bool DeviceChoices::valid() const {
    if (static_cast<std::uint8_t>(guard) >= guard_cycle_count) return false;
    if (static_cast<std::uint8_t>(router) >= router_policy_count) return false;   // G25
    for (const auto pct : brightness_choices) if (pct == bright_pct) return true;
    return false;
}
bool Presenter::set_device(const DeviceChoices& c) {
    if (!c.valid()) return false;
    device_ = c;
    if (screen_ != Screen::Settings) draft_ = c;
    rebuild();
    return true;
}
DeviceChoices Presenter::merged() const {
    DeviceChoices v = device_;
    switch (settings_page_) {
    case SettingsPage::Guard: v.guard = draft_.guard; break;
    case SettingsPage::Brightness: v.bright_pct = draft_.bright_pct; break;
    case SettingsPage::Router: v.router = draft_.router; break;   // G25
    }
    return v;
}
void Presenter::open_settings() {
    screen_ = Screen::Settings; settings_page_ = SettingsPage::Guard; draft_ = device_;
    save_pending_ = report_due_ = false; plate_ = SavePlate::None;
}
void Presenter::to_face() {
    screen_ = Screen::Face; page_ = DetailsPage::Settings; explanation_page_ = 0; owner_page_ = 0;
    settings_page_ = SettingsPage::Guard; draft_ = device_; save_pending_ = false; plate_ = SavePlate::None;
}
DeviceChoices Presenter::take_settings_save() {
    const DeviceChoices v = pending_;
    if (save_pending_) { save_pending_ = false; report_due_ = true; }
    return v;
}
void Presenter::settings_saved(bool ok) {
    if (!report_due_) return;   // nothing was taken: nothing to report
    report_due_ = false;
    if (ok) device_ = pending_;
    if (screen_ == Screen::Settings) { plate_ = ok ? SavePlate::Saved : SavePlate::Failed; plate_at_ = now_.at; }
    rebuild();
}
std::uint8_t Presenter::lit_brightness_pct() const {
    return screen_ == Screen::Settings && settings_page_ == SettingsPage::Brightness ? draft_.bright_pct : device_.bright_pct;
}
void Presenter::rebuild_settings() {
    settings_view_ = {};
    settings_view_.open = screen_ == Screen::Settings;
    settings_view_.page = settings_page_;
    settings_view_.number = static_cast<std::uint8_t>(static_cast<unsigned>(settings_page_) + 1u);
    settings_view_.shown = merged();
    settings_view_.saved = device_;
    settings_view_.plate = settings_view_.open ? plate_ : SavePlate::None;
}
void Presenter::tick_plate() {
    if (screen_ == Screen::Settings && plate_ != SavePlate::None && have_now_ && now_.at >= plate_at_ + settings_plate_ms) settings_advance();
}
void Presenter::settings_advance() {
    const bool saved = plate_ == SavePlate::Saved;
    plate_ = SavePlate::None;
    if (!saved) return;                                   // SAVE FAILED: stay on the page, the draft kept
    if (settings_page_ == SettingsPage::Guard) { settings_page_ = SettingsPage::Brightness; draft_ = device_; }
    else if (settings_page_ == SettingsPage::Brightness) { settings_page_ = SettingsPage::Router; draft_ = device_; }   // G25
    else to_face();                                       // after the last page: the face
}
// G25 keys (owner 2026-11-23: "SIDE changes, BLUE saves" then "or hold side to save"): SIDE = next value,
// hold SIDE = save, BLUE (or a hold of BLUE, or Back) = leave without saving.
bool Presenter::settings_key(Action a) {
    if (a == Action::Primary || a == Action::PrimaryLong || a == Action::Back) { to_face(); return true; }
    if (plate_ != SavePlate::None) return false;          // the plate shows: SIDE waits for it
    if (a == Action::Secondary) {
        switch (settings_page_) {
        case SettingsPage::Guard:
            draft_.guard = static_cast<GuardCycle>((static_cast<unsigned>(draft_.guard) + 1u) % guard_cycle_count);
            break;
        case SettingsPage::Brightness: {
            std::size_t i = 0;
            while (i < brightness_choices.size() && brightness_choices[i] != draft_.bright_pct) ++i;
            draft_.bright_pct = brightness_choices[i < brightness_choices.size() ? (i + 1) % brightness_choices.size() : 0];
            break;
        }
        case SettingsPage::Router:
            draft_.router = static_cast<RouterPolicy>((static_cast<unsigned>(draft_.router) + 1u) % router_policy_count);
            break;
        }
        return true;
    }
    if (a == Action::SecondaryLong) {
        if (save_pending_ || report_due_) return false;   // one save at a time
        pending_ = merged(); save_pending_ = true;
        return true;
    }
    return false;
}
} // namespace guardian


// ---- G25: the router's own changes ---------------------------------------------------------------
namespace guardian {
const char* router_policy_text(RouterPolicy p) {
    switch (p) { case RouterPolicy::DetailsOnly: return "details"; case RouterPolicy::Amber: return "amber"; case RouterPolicy::Strict: return "strict"; }
    return "?";
}
const char* router_mode_text(Mode m) {
    switch (m) {
    case Mode::Wpa3Personal: return "WPA3"; case Mode::Transition: return "WPA2/WPA3"; case Mode::Wpa2Personal: return "WPA2";
    case Mode::Wpa1: return "WPA"; case Mode::Wep: return "WEP"; case Mode::Open: return "open"; case Mode::Owe: return "OWE";
    case Mode::Enterprise: return "Enterprise"; case Mode::Unknown: return "unknown";
    }
    return "unknown";
}
const char* router_cipher_text(Cipher c) {
    switch (c) {
    case Cipher::Gcmp: return "GCMP"; case Cipher::Ccmp: return "CCMP"; case Cipher::Tkip: return "TKIP"; case Cipher::Wep: return "WEP";
    case Cipher::None: return "none"; case Cipher::Unknown: return "unknown";
    }
    return "unknown";
}
const char* router_pmf_text(Pmf p) {
    switch (p) { case Pmf::Required: return "required"; case Pmf::Optional: return "optional"; case Pmf::Disabled: return "off"; case Pmf::Unknown: return "unknown"; }
    return "unknown";
}
namespace {
// Plain character copies (the portable presenter has no formatted output).
struct Text {
    char* out; std::size_t capacity; std::size_t used{}; bool fits{true};
    void put(const char* t) { for (std::size_t i = 0; fits && t[i]; ++i) { if (used + 1 >= capacity) fits = false; else out[used++] = t[i]; } }
    void number(std::uint32_t n) {
        char digits[11]; std::size_t k = 0;
        do { digits[k++] = static_cast<char>('0' + n % 10); n /= 10; } while (n && k < sizeof digits);
        char t[12]; for (std::size_t i = 0; i < k; ++i) t[i] = digits[k - 1 - i];
        t[k] = 0; put(t);
    }
    std::size_t end() { if (!fits || !used) { if (capacity) out[0] = 0; return 0; } out[used] = 0; return used; }
};
} // namespace
std::size_t router_sentence(const RouterView& v, RouterWording w, char* out, std::size_t capacity) {
    if (!out || !capacity) return 0;
    Text t{out, capacity};
    if (v.change.pending) {
        if (w == RouterWording::Minimal) { t.put("Router changed its security settings"); return t.end(); }
        t.put(w == RouterWording::Full ? "Your router changed its security settings: " : "Router changed security: ");
        const SecuritySummary a = summarize(v.change.from), b = summarize(v.change.to);
        bool any = false;
        const auto item = [&](const char* name, const char* from, const char* to) {
            if (any) t.put(", ");
            any = true; t.put(name);
            if (w == RouterWording::Full) { t.put(" ("); t.put(from); t.put(" -> "); t.put(to); t.put(")"); }
        };
        if (a.mode != b.mode) item("mode", router_mode_text(a.mode), router_mode_text(b.mode));
        if (a.pairwise != b.pairwise) item("cipher", router_cipher_text(a.pairwise), router_cipher_text(b.pairwise));
        if (a.pmf != b.pmf) item("PMF", router_pmf_text(a.pmf), router_pmf_text(b.pmf));
        if (!any) t.put("other options");
        if (v.change.downgrade) t.put(", a downgrade");
        return t.end();
    }
    if (v.move_unacked && v.last_move.known) {
        if (w == RouterWording::Full) { t.put("Your router moved to channel "); t.number(v.last_move.to); t.put(" (from "); t.number(v.last_move.from); t.put(")"); }
        else { t.put("Router moved to ch "); t.number(v.last_move.to); }
        return t.end();
    }
    return t.end();
}
std::size_t move_line(const RouterView& v, char* out, std::size_t capacity) {
    if (!out || !capacity) return 0;
    Text t{out, capacity};
    if (!v.moves || !v.last_move.known) return t.end();
    if (v.moves == 1) t.put("Router moved ch ");
    else { t.put("Router moved "); t.number(v.moves); t.put("x, "); }
    t.number(v.last_move.from); t.put("->"); t.number(v.last_move.to);
    return t.end();
}
void Presenter::rebuild_router() {
    // Moves seen while the setting was not STRICT are not turned amber later; a reset detector starts again.
    if (device_.router != RouterPolicy::Strict || router_.moves < moves_acked_) moves_acked_ = router_.moves;
    RouterView r{};
    r.policy = device_.router;
    if (mode_ == ViewMode::Live) {
        r.change = router_.change; r.pending = router_.pending; r.moves = router_.moves; r.last_move = router_.last_move;
        if (r.change.pending)
            r.change_tone = r.policy == RouterPolicy::DetailsOnly ? Tone::Grey : r.policy == RouterPolicy::Amber ? Tone::Amber : Tone::Red;
        r.move_unacked = r.policy == RouterPolicy::Strict && r.moves > moves_acked_;
        if (r.moves) r.move_tone = r.move_unacked ? Tone::Amber : Tone::Grey;
        r.page = r.change.pending || r.move_unacked;
        if (r.change.pending) r.age_known = age_of(r.change.first, now_, r.age_ms);
    }
    view_.router = r;
    view_.router_alert = false; view_.router_amber = false;
}
bool Presenter::router_key(Action) {
    if (has_request() || !view_.router.page) return false;
    if (view_.router.change.pending) {
        request_ = {}; request_.kind = RequestKind::AcceptChange;
        request_.ap.network = live_.selected; request_.ap.network.bssid = view_.router.change.bssid;
        request_.requested_at = now_;
    }
    if (view_.router.move_unacked) moves_acked_ = router_.moves;   // acknowledged; nothing for the application to do
    to_face();
    return true;
}
} // namespace guardian

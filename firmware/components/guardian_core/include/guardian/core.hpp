#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "guardian/capabilities.hpp"
#include "guardian/identity.hpp"
#include "guardian/parser.hpp"
#include "guardian/radio.hpp"
#include "guardian/time.hpp"

// Portable defense core: selected-network scope, evidence freshness and the
// snapshot the presenter reads. Standard C++ only. Time is injected through a
// MonotonicClock; observations are injected as values. Nothing here reads a
// radio, a pin or a wall clock.
//
// G05 made the acquisition Instant normative. Every reading keeps its source
// (Origin), raw SSID bytes and BSSID (Network), epoch-tagged monotonic
// acquisition time, band/channel and parsing status. Core accepts a reading as
// LIVE evidence only when its epoch equals the injected clock's epoch, it is
// not in the future, it is not older than the reading already held, its origin
// matches the core's origin, its identity is byte-equal to the selection and its
// band/channel is one the configured radio can listen on. A reading from
// another epoch (a restored record from a previous boot) is kept as HISTORICAL
// only while no live reading exists; it is never graded and never displaces
// live evidence. Everything rejected is counted in Snapshot::rejected so a
// test or a diagnostics screen can see why nothing is shown.
//
// Shared value types (Millis, Mac, Network, Origin, Pmf, AdvertisedSettings)
// live in guardian/time.hpp, identity.hpp and parser.hpp since G01; this header
// re-exports them through its includes. The rating policy (assess) and the
// parser-to-observation reduction live in guardian/rating.hpp.
namespace guardian {

// Compatibility alias for the pre-G01 draft name. Only Complete can produce a grade.
using Parse = ParseStatus;

// Advertised mode after the weakest-advertised reduction (guardian/rating.hpp).
enum class Mode { Unknown, Open, Wep, Wpa1, Wpa2Personal, Wpa3Personal, Transition, Owe, Enterprise };
enum class Cipher { Unknown, None, Wep, Tkip, Ccmp, Gcmp };
// The five rated moods. Unknown is "not rated": an observation overlay
// (Assessment::unrated says why), never a sixth mood.
enum class Mood { Unknown, VeryGood, Good, Medium, Bad, Horrible };
enum class Finding { Unknown, StrongSettings, Wpa2PmfRequired, PmfNotRequired, CompatibilityMode, Legacy, Unencrypted };
// Why an observation carries no complete grade (G05). None when rated.
enum class Unrated : std::uint8_t {
    None,
    Incomplete,        // parse not Complete, settings not present/complete, or not an advertisement
    ReceiveUnverified, // RxStatus not Ok: the adapter could not vouch for the bytes
    UnknownOption,     // an AKM/cipher selector the policy does not know; weaker known options stay visible
    Owe,               // OWE or the open side of an OWE transition pair: policy deliberately unspecified
    Enterprise,        // any 802.1X / Suite B AKM (including the RSNE default): policy deliberately unspecified
    Inconsistent,      // settings contradict each other (RSN without Privacy, SAE without PMF capability, ...)
    Unspecified        // valid, understood, but outside the five documented rows (e.g. SAE-only with PMF optional)
};
enum class Coverage { Checking, Fresh, Stale, Degraded };
// G16F appended NetworkPattern: a passive management-frame pattern (join flood,
// unannounced channel switch, name mismatch, open twin, ...) observed under the
// selected or an owner-approved BSSID. IncidentObservation::pattern names which.
enum class IncidentKind { DisconnectBurst, UnexpectedAp, SettingsChanged, NetworkPattern, Count };

// G16E: what an incident is about.
//   Network  the selected network (or an owner-approved related AP): today's
//            G06/G14 rule; a current one is the red ALERT.
//   Area     the air around this device ("seen nearby"): needs no selection,
//            never changes the security rating or the network incidents, has
//            its own visibility window (Core::set_area_visibility) and bounded
//            storage (area_slots). Shown amber, never as an ALERT.
enum class IncidentScope : std::uint8_t { Network, Area };

// G16E: detector families. One radar glyph per family; a family is "measured"
// only while at least one registered detector reports it. Network kinds map to
// Disconnect (DisconnectBurst) and Baseline (UnexpectedAp, SettingsChanged).
// The other families are filled by the passive detectors of later tasks; the
// names describe observations, never a tool or an attacker.
enum class DetectorFamily : std::uint8_t {
    Disconnect,    // deauthentication / disassociation traffic
    Baseline,      // owner-approved AP baseline changes, same-name APs
    Probe,         // probe requests
    Beacon,        // beacon floods, rotating or marked beacons
    Responder,     // one transmitter answering for many names
    Auth,          // authentication / SAE / (re)association request floods
    ChannelSwitch, // channel-switch and quiet announcements
    Identity,      // name / transition-partner mismatches
    // G16G (appended): frame loss on a channel (checksum-failed frames while the
    // channel's valid traffic collapses). Handshake (EAPOL-Key) patterns report
    // under Auth: they are the key exchange of a join.
    Jamming,
    // G16H (appended): Bluetooth LE advertising (pairing-popup messages). Registered
    // only while an adapter feeds a passive BLE scan (Monitor::set_ble_scan).
    Bluetooth,
    Count
};

// G16F: which passive pattern an observation matched, finer than its family.
// None for the G06 detectors (their IncidentKind already says it). Names
// describe received frames only: never a tool, an attacker or a compromise.
enum class Pattern : std::uint8_t {
    None,
    ProbeFloodRandom,  // many probe requests from many (mostly randomized-looking) addresses
    ProbeFloodSource,  // one address probing at flood rate for two windows in a row
    ProbeFloodName,    // many addresses asking for the same network name
    BeaconFlood,       // many distinct strong BSSIDs beaconing at once
    ManyNames,         // one transmitter answering (probe responses / beacons) for many names
    AuthFlood,         // open-system authentication requests from many addresses to one BSSID
    SaeCommitFlood,    // SAE commits without matching confirms to one BSSID
    AssocSleep,        // (re)association requests with the power-management bit to one BSSID
    ChannelSwitch,     // channel-switch announcement out of the ordinary (count, or unannounced by the AP's own beacons)
    QuietOrder,        // Quiet element with a long duration
    NameMismatch,      // a BSSID's probe response names another network than its beacons
    MarkedBeacon,      // beacon carrying element 222 or the DE:AD:BE:EF:DE:AD address
    OpenTwin,          // an open beacon reusing an OWE transition network's name, not its declared partner
    DeauthSource,      // many disconnect frames from one transmitter address
    DeauthPair,        // many disconnect frames between one transmitter and one destination
    DeauthBroadcast,   // many broadcast disconnect frames
    NameRotation,      // one transmitter beaconing many names in a short window
    OpenLure,          // a name-rotating transmitter that also beacons open lure-style names
    // G16G (appended), from unprotected EAPOL-Key frames and per-channel receive counts:
    PmkidHarvest,      // one station sent handshake starts (M1) by >= 3 APs and answered none of them
    FakeM1,            // a handshake start (M1) whose ANonce is all zero bytes
    DeauthHandshake,   // disconnect burst on the selected network, then a fresh handshake for that station
    FrameLoss,         // a channel's packet-delivery ratio collapsed with strong checksum-failed frames (G16J: no longer emitted)
    // G16J (appended):
    KarmaAnswer,       // a device asked for a name, then a BSSID never seen before answered or beaconed that name
    LurePortal,        // an open network with a lure-style name from a development-board vendor address
    NoiseFloor,        // a channel's noise floor rose well above its own recent average and stayed there
    // G16H (appended), from Bluetooth LE advertising reports (guardian/ble.hpp):
    PairingPopupFlood, // several different pairing-popup messages from several short-lived addresses at once
    FastPairRotation,  // one address announcing several different Fast Pair products in a short window
    Count
};

// G16J: frame shapes that widely used attack tools are known to send (fixed
// sequence numbers, fixed durations, counters that never move, template
// addresses). A shape is a fact about received bytes. It never names a tool
// and never identifies a sender: the wording is only "looks like a known
// attack tool". A matched shape halves the pattern's count threshold
// (IncidentObservation::threshold carries the halved value) and is listed in
// IncidentObservation::shapes. Values start from the behaviour described for
// AntiHunter upstream (2026-11-17, AGPL-3.0: behaviour only, no code) and are
// uncalibrated hypotheses (docs/attack-coverage.md).
namespace shape {
constexpr std::uint16_t DisconnectFixedSequence = 1u << 0;  // disconnect, reason 2, sequence control 0xFFF0
constexpr std::uint16_t DisconnectFixedDuration = 1u << 1;  // disconnect, reason 7, Duration 0x013A
constexpr std::uint16_t RisingSequence          = 1u << 2;  // one transmitter, one destination, sequence +1 every frame
constexpr std::uint16_t KindAlternation         = 1u << 3;  // one transmitter alternating deauthentication / disassociation
constexpr std::uint16_t SwitchCount255          = 1u << 4;  // channel-switch count 0xFF
constexpr std::uint16_t ProbeFixedSequence      = 1u << 5;  // probe request, sequence control 0x0001
constexpr std::uint16_t StaticTimestamp         = 1u << 6;  // beacons whose timestamp never advances
constexpr std::uint16_t BeaconInterval1000      = 1u << 7;  // beacon interval of exactly 1000 TU
constexpr std::uint16_t TemplateAddress         = 1u << 8;  // transmitter 12:34:56:78:9A:BC
constexpr std::uint16_t ReplayCounterRange      = 1u << 9;  // handshake start with a replay counter in 0xF000..0xFFFE
constexpr std::uint16_t SyntheticPmkid          = 1u << 10; // PMKID made of one repeated byte or a constant-step byte ramp
constexpr std::uint16_t HandshakeAfterForgery   = 1u << 11; // handshake within the bait window after shaped disconnect frames
constexpr std::uint16_t BoardVendorLure         = 1u << 12; // open lure-style name from a development-board vendor address
} // namespace shape

// Area incidents held at once (newest per family; the oldest is evicted).
constexpr std::size_t area_slots = 4;

// One advertised-settings reading (beacon or probe response) as the policy
// layer receives it: raw facts, no verdict. Built from a ParseResult and its
// RxMeta by observe_security() (guardian/rating.hpp). The AdvertisedSettings
// record travels with it so weaker advertised options stay visible after the
// weakest-advertised reduction. Trivially copyable, no pointers.
struct SecurityObservation {
    Network network{};              // identity by raw bytes: BSSID + SSID bytes + length
    SsidKind ssid_kind{SsidKind::Absent};
    Instant acquired{};             // normative acquisition epoch/time (stamped before queueing)
    Origin origin{Origin::LiveRadio};
    Band band{Band::Ghz2_4};
    std::uint8_t channel{};         // the channel the radio was tuned to, never the DS element
    std::int8_t rssi{};
    bool rssi_valid{};
    RxStatus rx_status{RxStatus::Unknown}; // checksum/driver confidence from the adapter
    FrameKind kind{FrameKind::Unknown};    // Beacon or ProbeResponse for an advertisement
    Parse parse{Parse::Unsupported};
    bool settings_present{};
    bool settings_complete{};
    AdvertisedSettings settings{};
};

// Raw received-signal / activity reading for the selected BSSID. Separate from
// SecurityObservation on purpose: a frame's RSSI or mere activity (a data frame,
// a deauthentication) never renews security evidence (G05 policy). Matched by
// BSSID only, because non-advertisement frames carry no SSID.
struct SignalObservation {
    Mac bssid{};
    Instant acquired{};
    Origin origin{Origin::LiveRadio};
    Band band{Band::Ghz2_4};
    std::uint8_t channel{};
    std::int8_t rssi{};
    bool rssi_valid{};
    FrameKind kind{FrameKind::Unknown};
};

// Which approved-baseline fact an advertisement differed in (G06). A bit set,
// because one beacon can differ in several. Each bit is an observation about
// received bytes; none of them confirms an evil twin or names a tool.
namespace change {
constexpr std::uint8_t Bssid         = 1u << 0; // the selected SSID bytes advertised by a BSSID that is neither selected nor approved
constexpr std::uint8_t Channel       = 1u << 1; // DS Parameter channel differs from the approved channel
constexpr std::uint8_t Privacy       = 1u << 2; // Privacy capability bit differs
constexpr std::uint8_t Wpa           = 1u << 3; // WPA vendor element state / AKMs / ciphers differ
constexpr std::uint8_t Rsn           = 1u << 4; // RSNE state / AKMs / ciphers / group management differ
constexpr std::uint8_t Pmf           = 1u << 5; // RSN PMF capability differs
constexpr std::uint8_t OweTransition = 1u << 6; // OWE transition element state differs
} // namespace change

// G16S burst forensics: one (receiver, sender, BSSID, channel) combination of
// disconnect frames and how many counted frames carried it. Header bytes as
// received and the channel the radio was tuned to: spoofable bytes, never a
// device or a person proven. count 0 = no tuple.
struct BurstTuple {
    Mac receiver{};           // Address 1: who the frames were addressed to
    Mac sender{};             // Address 2: the transmitter address the frames carried
    Mac bssid{};              // Address 3: the access point the frames named
    std::uint8_t channel{};   // RxMeta::channel of the frames (0 = the adapter did not report one)
    // G16T: one of the three addresses was the picked network's (the selected or an approved
    // address, or one heard under the picked name) when the frames were counted. Set only in
    // the record of a NEARBY burst (AreaDisconnectDetector); the red burst and the pair rule
    // count the picked network's frames from the start and leave it false.
    bool own{};
    std::uint32_t count{};    // counted frames with exactly these four values
};

// Canonical output from a detector, not a verdict that an attacker exists.
// `affected` is always the selected network (Core's scope); `bssid` names the
// AP the evidence was observed under. `acquired` is the acquisition instant of
// the evidence that closed the window (G06 preserves it through detector
// emission); Core validates its epoch. The counters after `window_ms` are the
// G06 uncertainty record: what this device received, how much of it was a
// retransmission or an unreadable protected body, and how much of the window
// the radio was actually listening. A burst is observed disconnect traffic,
// not proof that clients were disconnected or that anyone sent it.
struct IncidentObservation {
    Network affected{};
    Instant acquired{};
    Origin origin{Origin::LiveRadio};
    IncidentKind kind{IncidentKind::DisconnectBurst};
    std::uint32_t count{};      // DisconnectBurst: deduplicated observations in the window; UnexpectedAp: distinct
                                // unapproved BSSIDs in the window; SettingsChanged: differing advertisements in the window
    std::uint32_t window_ms{};  // the counting window the count refers to
    Mac bssid{};                // in-scope AP for bursts/changes; the unapproved BSSID for UnexpectedAp (latest seen)
    std::uint32_t threshold{};  // the tunable heuristic that was reached (DetectorLimits)
    std::uint32_t raw_frames{}; // frames in the window before deduplication / distinct reduction
    std::uint32_t retries_deduped{};  // Retry-bit copies matched to an earlier identical header inside dedupe_ms; not counted
    std::uint32_t protected_frames{}; // counted observations whose body was protected: header read, reason never read
    std::uint32_t eapol_frames{};     // unprotected EAPOL data frames in scope inside the window (context only, never a verdict)
    bool saturated{};           // detector state reached its bound inside this window: count is a lower bound
    bool coverage_known{};      // a same-epoch coverage report sampled inside the window described the listening
    Millis listened_ms{};       // from that report: time actually tuned within coverage_window_ms
    Millis coverage_window_ms{};
    bool hopping{};             // from that report: dwell shared across channels (gaps expected)
    std::uint8_t changes{};     // change:: bits (UnexpectedAp, SettingsChanged); 0 for bursts
    // G16E. Network observations keep today's rules (affected must be the
    // selection). Area observations ignore `affected` and `kind`; `family`
    // names what was observed. distinct_sources / sources_random describe the
    // transmitter addresses inside the window (spoofable bytes, never people).
    IncidentScope scope{IncidentScope::Network};
    DetectorFamily family{DetectorFamily::Disconnect};
    std::uint32_t distinct_sources{};
    bool sources_random{};      // most of those addresses are locally administered (randomized-looking)
    // G16F: the passive pattern (None for the G06 detectors) and the number of
    // independent supporting facts inside the window (ManyNames: answered names
    // a nearby device had just asked for; OpenLure: open lure-style names;
    // ChannelSwitch: own beacons without the announcement after it;
    // G16G PmkidHarvest: unanswered starts carrying a PMKID KDE;
    // DeauthHandshake: distinct handshake messages seen after the burst;
    // FrameLoss: valid frames in that second; G16J KarmaAnswer: answering frames
    // from the new BSSID; NoiseFloor: receive-error frames in the held interval,
    // with raw_frames = all frames in it, count = the rise in dB and threshold
    // = the rise that was required; G16H PairingPopupFlood: the different vendor
    // formats among the counted messages). 0 = none.
    Pattern pattern{Pattern::None};
    std::uint32_t corroborating{};
    // G16G: the channel a FrameLoss / NoiseFloor observation is about (0 = not channel-specific).
    std::uint8_t channel{};
    // G16J: shape:: bits matched inside the window (0 = none). See namespace shape.
    std::uint16_t shapes{};
    bool tool_shape() const { return shapes != 0; }
    // G16S: disconnect observations only. The most frequent tuple of the detector's
    // window at this report (guardian/shapes.hpp BurstTrace); count 0 = none. The
    // whole burst (up to 8 tuples, its total) is the detector's last_burst().
    BurstTuple top{};
    // G16T: > 0 only on a Network observation that AreaDisconnectDetector made from a NEARBY
    // burst: the counted disconnect frames of that burst, so far, that named the picked
    // network in Address 1, 2 or 3. `pattern`, `count`, `threshold` and `window_ms` are then
    // the nearby rule that was reached, `top` is the most frequent tuple naming the picked
    // network and `bssid` the picked network's address in it. 0 on every other observation.
    std::uint32_t own_frames{};
};

class ObservationSink {
public:
    virtual ~ObservationSink() = default;
    virtual void security(const SecurityObservation&) = 0;
    virtual void incident(const IncidentObservation&) = 0;
};

// Result of the G05 rating (guardian/rating.hpp). mood/reason are the product
// policy; unrated says why there is no grade; legacy_risk is the separately
// confirmed finding (a Valid WPA element or a TKIP/WEP option) that survives
// even when another element blocks a complete grade; mode/pairwise/group/pmf are
// the weakest-advertised summary for display, derived from the settings record.
struct Assessment {
    Mood mood{Mood::Unknown};
    Finding reason{Finding::Unknown};
    Unrated unrated{Unrated::None};
    bool legacy_risk{};
    Mode mode{Mode::Unknown};
    Cipher pairwise{Cipher::Unknown}; // weakest advertised pairwise option
    Cipher group{Cipher::Unknown};    // weakest advertised group cipher
    Pmf pmf{Pmf::Unknown};
};

// Why inputs were not taken as live evidence since the last select(). Facts
// about this device's input, for tests and diagnostics; never shown as an attack.
struct Rejections {
    std::uint32_t not_selected{};   // nothing selected yet
    std::uint32_t origin{};         // demo/imported/live mismatch with the core's origin
    std::uint32_t network{};        // BSSID or SSID bytes differ from the selection
    std::uint32_t unrelated{};      // not an advertisement (no settings can come from it)
    std::uint32_t invalid_time{};   // acquisition Instant unknown or epoch invalid
    std::uint32_t foreign_epoch{};  // another timebase while live evidence exists
    std::uint32_t future{};         // acquired after the clock's now
    std::uint32_t older{};          // older than the reading already held (queue reordering)
    std::uint32_t channel{};        // band/channel outside the configured radio capability
};

struct Snapshot {
    Network selected{};
    Origin origin{Origin::LiveRadio};
    Coverage coverage{Coverage::Checking};
    Assessment settings{};
    SecurityObservation last_security{};
    bool has_security{};
    bool security_historical{}; // last_security is from another epoch: shown as "last known", never graded
    Millis age_ms{};            // age of live security evidence; 0 when none or historical
    bool has_signal{};
    SignalObservation last_signal{};
    Millis signal_age_ms{};
    bool signal_interval_known{}; // G07: two accepted live signal samples exist in this epoch
    Millis signal_interval_ms{};  // G07: time between the last two accepted signal samples (sampling interval at this device)
    bool has_coverage{};
    CoverageReport last_coverage{};
    Millis coverage_age_ms{};
    Rejections rejected{};
    std::array<bool, static_cast<std::size_t>(IncidentKind::Count)> incidents{};
    std::array<IncidentObservation, static_cast<std::size_t>(IncidentKind::Count)> evidence{};
    // G16E: Area observations (never graded, never an ALERT). area_visible[i]
    // is true while area[i] is younger than area_visible_ms in this epoch.
    std::array<IncidentObservation, area_slots> area{};
    std::array<bool, area_slots> area_visible{};
    Millis area_visible_ms{};
    std::uint32_t area_evicted{};  // a newer family displaced the oldest held area observation
    // G16N: counts every incident report this Core accepted (Network or Area) since it was built.
    // It only ever goes up (a new selection does not reset it), so "the number changed" means a
    // NEW report arrived, also while an earlier one of the same kind is still shown. A rejected
    // report (wrong network, another timebase, the future, older than the held one) never counts.
    std::uint32_t incident_seq{};
};

// Single application-task owner. No Arduino, ESP-IDF, renderer, allocations,
// network requests or storage. The clock is borrowed and must outlive the Core;
// its epoch defines "live". `listenable` is RadioCapabilities::channels (or the
// replay source's declared channels): a reading on a band/channel outside it is
// rejected, and an empty set (capability Unknown) rejects every reading, because
// Unknown is never Supported. UI receives Snapshot by value.
class Core final : public ObservationSink {
public:
    Core(const MonotonicClock& clock, ChannelSet listenable, Origin origin = Origin::LiveRadio)
        : clock_(clock), listenable_(listenable), origin_(origin) {}
    bool select(const Network&);
    void security(const SecurityObservation&) override;
    void incident(const IncidentObservation&) override;
    void signal(const SignalObservation&);
    void coverage(const CoverageReport&);
    Snapshot snapshot() const;
    // Review 2026-11-17 (stack): the held security observation without building a
    // ~2 KB Snapshot (the StickS3 asks for it on every accepted frame); nullptr when none.
    // Same value as snapshot().last_security when non-null.
    const SecurityObservation* last_security() const { return has_security_ ? &security_ : nullptr; }
    // "No fresh data" after 29 s without a usable sample. Counted from the last
    // advertisement (at or before the AP stops), so the screen reaches No fresh
    // data within 30 s of the AP turning off, with ~1 s for redraw/scheduling (G13).
    static constexpr Millis fresh_ms = 29000;
    // Review 2026-11-17: listening coverage uses hysteresis. A bad coverage window (not tuned,
    // or frames dropped at this device) warns at once, but degraded clears only after coverage
    // has been clean this long, so a deauth storm's brief clean windows do not flap the overlay.
    static constexpr Millis coverage_recover_ms = 3000;
    static constexpr Millis incident_ms = 60000;
    // G16E: default Area visibility. Starting hypothesis: AntiHunter's 60 s quiet
    // period before a re-alert (c6ef921, uncalibrated; TUNE detect.area_ms).
    static constexpr Millis area_incident_ms = 60000;
    // False for 0 (nothing would ever show); the value applies to held observations too.
    bool set_area_visibility(Millis ms);
    Millis area_visibility() const { return area_ms_; }
private:
    // Classification of an acquisition Instant against the injected clock.
    enum class TimeCheck : std::uint8_t { Live, Invalid, Foreign, Future };
    TimeCheck check_time(const Instant&) const;
    const MonotonicClock& clock_;
    ChannelSet listenable_;
    Origin origin_;
    Network selected_{};
    bool selected_valid_{};
    Instant selected_at_{};
    bool has_security_{};
    SecurityObservation security_{};
    bool has_signal_{};
    SignalObservation signal_{};
    bool signal_interval_known_{};
    Millis signal_interval_ms_{};
    bool has_coverage_{};
    CoverageReport coverage_{};
    bool coverage_degraded_{};          // hysteresis latch (see coverage_recover_ms)
    Instant coverage_clean_since_{};    // when clean coverage began while latched; invalid after a bad window
    Rejections rejected_{};
    std::array<bool, static_cast<std::size_t>(IncidentKind::Count)> present_{};
    std::array<IncidentObservation, static_cast<std::size_t>(IncidentKind::Count)> incidents_{};
    void area_incident(const IncidentObservation&);
    std::array<IncidentObservation, area_slots> area_{};
    std::array<bool, area_slots> area_held_{};
    Millis area_ms_{area_incident_ms};
    std::uint32_t area_evicted_{};
    std::uint32_t incident_seq_{};      // G16N: accepted incident reports (see Snapshot::incident_seq)
};
} // namespace guardian

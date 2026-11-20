#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "guardian/core.hpp"
#include "guardian/detector.hpp"
#include "guardian/identity.hpp"
#include "guardian/parser.hpp"
#include "guardian/radio.hpp"
#include "guardian/shapes.hpp"
#include "guardian/time.hpp"

// G06: the portable disconnect-burst and baseline-change detectors behind the
// G01 FrameDetector contract (guardian/detector.hpp).
//
// What they are: bounded counters over frames this device received, scoped to
// the owner-approved APs, with every threshold a tunable heuristic
// (DetectorLimits) and every report carrying its count, window, deduplication
// and listening-coverage facts (IncidentObservation). What they are not: proof
// that clients were disconnected, that a transmitter is who the header says, or
// that an evil twin, a named attack tool or a passive sniffer exists. Header
// addresses are spoofable bytes. Policy text: docs/G06-detectors.md; behavior
// checks: firmware/tests/detector_check.cpp (written and run RED first).
//
// Source isolation: the first eligible, receive-verified frame binds the
// detector to its Origin until reset(). Other origins are counted as rejected
// and cannot enter windows, cooldowns or dedupe state. Reset when switching
// live/demo/imported input; use a separate instance for simultaneous streams.
// Clock ticks and coverage must belong to that same adapter pipeline.
//
// Independent implementation (docs/research/reuse-decisions.md section 4): the
// two-tier window/cooldown idea and the "typed fingerprint, not an IE hash"
// decision are kept; no AntiHunter code, no blanket Retry-bit discard, no tool
// fingerprinting, no self-clone evil-twin rule. Standard C++ only, no
// allocation after construction, no pointer kept into a frame.
namespace guardian {

// The comparable record of what an AP advertises, derived from VALID elements
// of an AdvertisedSettings only. Two beacons with the same fingerprint advertise
// the same security configuration as far as the policy layer can see; vendor
// element churn and element order never enter it. Unknown selectors compare by
// their Unknown kind bit, so two different unmapped selectors read as equal here
// (the G05 policy already refuses to grade them).
struct SettingsFingerprint {
    bool privacy_bit{};
    ElementState wpa_state{ElementState::Absent};
    std::uint16_t wpa_akms{};
    std::uint16_t wpa_pairwise{};
    std::uint16_t wpa_group{};
    ElementState rsn_state{ElementState::Absent};
    std::uint16_t rsn_akms{};
    std::uint16_t rsn_pairwise{};
    std::uint16_t rsn_group{};
    std::uint16_t rsn_group_management{};
    Pmf pmf{Pmf::Unknown};
    ElementState owe_transition{ElementState::Absent};

    // Reduction from a parsed advertisement. Fields of non-Valid elements are
    // left zero so a Malformed/Truncated sibling cannot invent a difference;
    // callers compare Complete parses only (BaselineDetector enforces this).
    static SettingsFingerprint of(const AdvertisedSettings&);
    // change:: bits (guardian/core.hpp) that differ between the two records.
    std::uint8_t diff(const SettingsFingerprint& other) const;
    bool operator==(const SettingsFingerprint& o) const { return diff(o) == 0; }
    bool operator!=(const SettingsFingerprint& o) const { return diff(o) != 0; }
};

// One owner-approved AP: the selected network itself or a related AP (mesh
// node, extender) the owner names explicitly. Baseline facts are optional and
// explicit: settings_known/channel_known false means "no baseline for this
// field", and the detector then reports nothing about that field. Nothing here
// is ever filled from received frames (the G16R same-name set of ApprovedScope
// is separate state and never makes an ApprovedAp).
struct ApprovedAp {
    Network network{};        // BSSID + exact SSID bytes (identity.hpp byte identity)
    bool settings_known{};
    SettingsFingerprint settings{};
    bool channel_known{};
    Band band{Band::Ghz2_4};
    std::uint8_t channel{};   // approved operating channel, compared with the DS Parameter element
    // Selected network only: the owner put it on the watch list, so the same SSID
    // from another BSSID is reported (UnexpectedAp). Off by default: a phone
    // hotspot restarting with a random BSSID must not raise an ALERT (owner, G14).
    bool watch_impostors{};
};

// The owner-approved scope both detectors read: the selected network plus up
// to max_approved_aps related APs. Fixed storage; approve() refuses when full
// instead of growing. The application task owns it, fills it from the owner's
// explicit choices (picker/persistence, G08/G14) and keeps it alive while the
// detectors exist. Detectors borrow it read-only.
class ApprovedScope {
public:
    static constexpr std::size_t capacity = 16;
    explicit ApprovedScope(std::uint16_t max_approved_aps = DetectorLimits{}.max_approved_aps)
        : max_approved_(max_approved_aps) {}
    // The configured limit fits the fixed storage. False means the adapter asked
    // for more approved APs than this build can hold; approve() will refuse.
    bool configured() const { return max_approved_ <= capacity; }

    // Selected network (same identity rules as Core::select: unicast, nonzero
    // BSSID, SSID length <= 32). Replaces any previous selection and drops its
    // baseline facts; approved related APs are kept.
    bool select(const ApprovedAp& selected);
    bool has_selection() const { return selected_valid_; }
    const ApprovedAp& selected() const { return selected_; }

    // Adds or replaces (same BSSID) a related AP. False when the identity is
    // invalid, when it is the selected BSSID (use select), or when the list is
    // full (max_approved_aps or capacity), in which case nothing changes.
    bool approve(const ApprovedAp& ap);
    bool revoke(const Mac& bssid);
    void clear(); // selection and approvals
    std::size_t approved_count() const { return count_; }
    // Bounded read-only enumeration for configuration persistence (G08).
    const ApprovedAp* approved_at(std::size_t index) const {
        return index < count_ ? &aps_[index] : nullptr;
    }
    std::uint16_t max_approved_aps() const { return max_approved_; }

    // Selected or approved entry for this BSSID; nullptr when out of scope.
    const ApprovedAp* find(const Mac& bssid) const;
    bool in_scope(const Mac& bssid) const { return find(bssid) != nullptr; }

    // G16R: the picked network is its NAME, not one address. A router may answer to
    // one name from several addresses, and a tool that targets "the network" targets
    // them all. The same-name set holds the BSSIDs this scope HEARD advertising the
    // picked network's exact SSID bytes since it was picked:
    //   * learned only by hear(): a Beacon or Probe Response the receiver vouched for
    //     (RxStatus::Ok, valid header, parse not Malformed / Truncated) whose SSID is
    //     Present and byte-equal to the selected one, from a unicast non-zero BSSID.
    //     A probe REQUEST carries the name too and teaches nothing (a device asking is
    //     not the network). A hidden selection has no name to match. Nothing is
    //     configured or hard-coded: no names, no addresses, no vendor lists.
    //   * the selected and the approved BSSIDs are the network already and take no
    //     entry; approving a learned BSSID removes its entry.
    //   * bounded: same_name_capacity entries. A new BSSID when all are used replaces
    //     the one heard longest ago (an AP that keeps beaconing is never the one
    //     replaced) and counts in same_name_evictions().
    //   * forgotten whenever the selection's identity changes (another name or another
    //     BSSID picked) and on clear(). Re-selecting the SAME identity (baseline
    //     approval, the watch switch) keeps it.
    // Heard is not approved: find() / in_scope() never see these BSSIDs, so the
    // baseline detector keeps reporting an unapproved same-name BSSID (UnexpectedAp,
    // "another device is using your network's name") exactly as before. What the set
    // widens is in_network(): which BSSIDs make a frame pattern "about the picked
    // network" (IncidentScope::Network) instead of "seen nearby".
    // The owner of the scope calls hear() for every received frame before its
    // detectors see it (measurement::Monitor::receive, lab/live/engine.cpp). Header
    // addresses and names are spoofable bytes: membership says what was received
    // under the name, never that the transmitter belongs to the owner.
    static constexpr std::size_t same_name_capacity = 8;
    // True when the frame was such an advertisement and its BSSID is in the set after the call.
    bool hear(const RxMeta& meta, const ParseResult& parsed);
    bool same_name(const Mac& bssid) const;
    std::size_t same_name_count() const { return same_count_; }
    // Bounded enumeration (diagnostics): the index-th entry, nullptr past the count.
    const Mac* same_name_at(std::size_t index) const;
    std::uint32_t same_name_evictions() const { return same_evictions_; }
    // Network scope: the selected BSSID, the approved list and the same-name set.
    bool in_network(const Mac& bssid) const { return find(bssid) != nullptr || same_name(bssid); }

private:
    struct SameName { Mac bssid{}; std::uint64_t heard{}; bool used{}; };
    static bool valid_identity(const Network&);
    void forget_same_name();
    void drop_same_name(const Mac& bssid);
    std::uint16_t max_approved_;
    ApprovedAp selected_{};
    bool selected_valid_{};
    std::array<ApprovedAp, capacity> aps_{};
    std::size_t count_{};
    std::array<SameName, same_name_capacity> same_{};
    std::size_t same_count_{};
    std::uint64_t same_clock_{};      // orders "heard longest ago" without reading a clock
    std::uint32_t same_evictions_{};
};

// Counters a test or diagnostics screen reads. Facts about this device's
// input since reset(); never shown as an attack.
struct DisconnectStats {
    std::uint32_t in_scope{};          // deauth/disassoc with the BSSID selected, approved or (G16R) heard under the picked name
    std::uint32_t out_of_scope{};      // deauth/disassoc for another BSSID (neighbours are not our evidence)
    std::uint32_t skipped_unverified{}; // bytes not vouched for by the receiver
    std::uint32_t header_invalid{};    // addresses/sequence unusable: never counted
    std::uint32_t other_frames{};      // frames of kinds this detector does not count
    std::uint32_t invalid_time{};      // acquisition Instant unknown or epoch invalid
    std::uint32_t foreign_origin{}; // a different live/imported/demo source: ignored until reset
    std::uint32_t foreign_epoch{};     // another timebase than the one this state belongs to
    std::uint32_t counted{};           // observations that entered the window count
    std::uint32_t retries_deduped{};   // Retry-bit copies matched inside dedupe_ms
    std::uint32_t protected_frames{};  // counted observations with a protected body (header only)
    std::uint32_t eapol_frames{};      // in-scope unprotected EAPOL data frames (context)
    std::uint32_t evicted_in_window{}; // bound reached: an in-window entry was dropped (count became a lower bound)
    std::uint32_t reports{};           // IncidentObservation emissions
    std::uint32_t suppressed_by_cooldown{}; // threshold reached again inside cooldown_ms: no new report
};

// G16J: when the counted frames inside the window show a tool shape (namespace
// shape in guardian/core.hpp: reason 2 with sequence control 0xFFF0, reason 7
// with Duration 0x013A, a rising-sequence run to one destination, a
// deauthentication / disassociation alternation run), the report is made at
// half the burst_threshold (rounded up) and lists the shapes. The reason of a
// Protected frame is still never read. Shapes never name a tool.
//
// Disconnect-burst detector. Counts deauthentication/disassociation frames whose
// BSSID (Address 3) belongs to the picked network (ApprovedScope::in_network:
// the selected or an approved AP, or, G16R, a BSSID heard advertising the picked
// network's exact name), all in ONE window, inside a sliding window
// anchored at the newest acquisition instant seen, after Retry-bit
// deduplication (DetectorLimits::dedupe_ms; G22: at most retry_copies_max
// copies per counted frame, so a Retry-bit flood with one sequence number is
// counted and a copy never takes a ring entry). When the deduplicated count
// reaches burst_threshold and no report was made inside cooldown_ms, it emits
// IncidentKind::DisconnectBurst with the full evidence record. Protected
// disconnect frames are counted from their header; their body is never read.
// Reason codes are never read (an unreadable or spoofable reason adds nothing
// a defensive count needs). Unprotected EAPOL data frames in scope are counted
// as context only.
//
// Bounded state: a ring of at most `capacity` entries (DetectorLimits::
// max_window_events of them used). When the ring is full and the evicted entry
// is still inside the window, the report says `saturated` (lower bound).
// Time: the first valid instant fixes the epoch this state belongs to; frames,
// ticks and coverage from another epoch are ignored and counted; reset() (on
// select / scope change / clock epoch change) clears everything.
class DisconnectDetector final : public FrameDetector {
public:
    static constexpr std::size_t capacity = 128;
    DisconnectDetector(const ApprovedScope& scope, DetectorLimits limits);
    // False when the limits cannot be honoured (window or threshold 0,
    // threshold > max_window_events, max_window_events > capacity, or the
    // scope itself is misconfigured). A misconfigured detector counts nothing
    // and reports nothing, so the failure is visible instead of silent growth.
    bool configured() const { return configured_; }
    const DetectorLimits& limits() const { return limits_; }

    void on_frame(const FrameSpan& frame, const RxMeta& meta, const ParseResult& parsed,
                  ObservationSink& out) override;
    void on_tick(Instant now, ObservationSink& out) override;
    void reset() override;
    // Latest adapter listening report; copied into the next report when it is
    // from this epoch and sampled inside the window. Never changes the count.
    void coverage(const CoverageReport& report) override;
    // G16E: replace the limits (TUNE). Validated like the constructor; on
    // success the detector starts clean (reset()), on failure it is
    // unconfigured and counts nothing until a valid configure().
    bool configure(const DetectorLimits& limits);
    DetectorReport report(Instant now) const override;

    const DisconnectStats& stats() const { return stats_; }
    // Deduplicated in-scope observations inside the window ending at `now`
    // (0 for a foreign/invalid instant). Diagnostics; the report carries the
    // same number at emission time.
    std::uint32_t in_window(Instant now) const;
    // G16S: the tuples (receiver, sender, BSSID, channel) of the last burst about the
    // picked network that reached the threshold (also inside a cooldown: a second
    // burst shortly after the first is not hidden behind it), with its total and the
    // incident time. At the threshold the record takes the counted frames of the
    // window from the ring below, then every further counted frame until a whole
    // window_ms passes without one. Rules: guardian/shapes.hpp (BurstRecord). Cleared
    // by reset() like every other counter here. age_known is false for another timebase.
    LastBurst last_burst(Instant now) const;

private:
    struct Entry {
        Millis at{};
        Mac addr1{};
        Mac addr2{};
        Mac bssid{};
        std::uint16_t sequence{};
        std::uint8_t fragment{};
        std::uint8_t kind{};   // FrameKind as uint8
        bool counted{};        // a deduplicated observation (not a retry copy, not EAPOL)
        bool retry{};
        bool protected_body{};
        bool eapol{};
        std::uint8_t channel{};   // G16S: RxMeta::channel of the frame
        std::uint8_t copies{};    // G22: Retry copies this counted entry absorbed (at most retry_copies_max)
    };
    struct WindowStats {
        std::uint32_t counted{}, raw{}, retries{}, protected_body{}, eapol{};
        Mac bssid{};
        bool any{};
    };
    bool adopt_epoch(const Instant& at);
    bool same_header(const Entry& e, const Entry& candidate) const;
    void push(const Entry& e);
    void prune(Millis anchor);
    WindowStats window(Millis anchor) const;
    void maybe_report(Millis anchor, Millis acquired, Origin origin, ObservationSink& out);

    const ApprovedScope& scope_;
    DetectorLimits limits_;
    bool configured_{};
    bool origin_set_{};
    Origin origin_{Origin::LiveRadio};
    bool epoch_set_{};
    TimeEpoch epoch_{};
    Millis latest_{};           // newest acquisition instant seen (window anchor)
    bool has_latest_{};
    std::array<Entry, capacity> ring_{};
    std::size_t head_{};        // index of the oldest entry
    std::size_t size_{};
    Millis saturated_until_{};  // an eviction inside the window happened: reports before this are lower bounds
    bool reported_{};
    Millis last_report_{};
    bool has_coverage_{};
    CoverageReport coverage_{};
    DisconnectStats stats_{};
    std::uint32_t frames_seen_{};   // G16E report: every on_frame call since reset
    bool has_event_{};
    Millis last_event_{};           // newest counted observation (epoch_)
    // G16J: tool shapes of the counted frames inside the window (DetectorLimits::shape_*).
    ShapeWindow shapes_{};
    DisconnectRuns runs_{};
    BurstRecord burst_{};           // G16S: the burst being counted / the last finished one
};

struct BaselineStats {
    std::uint32_t advertisements{};     // Beacon/ProbeResponse with a valid header
    std::uint32_t skipped_incomplete{}; // parse not Complete: proves nothing about a change
    std::uint32_t skipped_unverified{}; // RxStatus not Ok: bytes not vouched for
    std::uint32_t other_frames{};
    std::uint32_t invalid_time{};
    std::uint32_t foreign_origin{}; // a different live/imported/demo source: ignored until reset
    std::uint32_t foreign_epoch{};
    std::uint32_t in_scope{};           // from the selected or an approved BSSID
    std::uint32_t no_baseline{};        // in scope but no approved settings/channel to compare with
    std::uint32_t unchanged{};          // in scope, every approved fact matched
    std::uint32_t changed{};            // in scope, some approved fact differed
    std::uint32_t unexpected{};         // the selected SSID bytes from an unapproved BSSID (watched selection)
    std::uint32_t same_name_unwatched{};// same SSID from another BSSID while the selection is not watched: ignored
    std::uint32_t neighbours{};         // other SSIDs or hidden SSIDs from unapproved BSSIDs: ignored
    std::uint32_t evicted_in_window{};
    std::uint32_t reports{};
    std::uint32_t suppressed_by_cooldown{};
};

// Baseline-change detector. Compares Complete, receive-verified advertisements
// against the owner's explicit baseline (ApprovedScope) and reports two kinds
// of observation after change_threshold such advertisements inside window_ms:
//   UnexpectedAp    the selected SSID bytes advertised by a BSSID that is
//                   neither selected nor approved (count = distinct BSSIDs;
//                   changes = Bssid, plus Channel/settings bits when the
//                   selected AP has an approved channel/settings to compare)
//   SettingsChanged the selected or an approved AP advertising a fingerprint
//                   or DS channel different from its approved baseline
//                   (changes names the fields)
// Approved mesh/extender APs with the same SSID are in scope and compared
// against their own baseline like the selected AP; they never raise
// UnexpectedAp. Hidden-SSID advertisements from unknown BSSIDs are ignored:
// a hidden beacon says nothing about the name. Nothing is learned from
// traffic: without an approved baseline fact there is no comparison.
class BaselineDetector final : public FrameDetector {
public:
    static constexpr std::size_t capacity = 32; // window entries (advertisements that differed / were unexpected)
    BaselineDetector(const ApprovedScope& scope, DetectorLimits limits);
    bool configured() const { return configured_; }
    const DetectorLimits& limits() const { return limits_; }

    void on_frame(const FrameSpan& frame, const RxMeta& meta, const ParseResult& parsed,
                  ObservationSink& out) override;
    void on_tick(Instant now, ObservationSink& out) override;
    void reset() override;
    bool configure(const DetectorLimits& limits); // G16E, same rules as DisconnectDetector::configure
    DetectorReport report(Instant now) const override;

    const BaselineStats& stats() const { return stats_; }

private:
    struct Entry {
        Millis at{};
        Mac bssid{};
        std::uint8_t changes{};
        bool unexpected{}; // true: UnexpectedAp entry; false: SettingsChanged entry
    };
    bool adopt_epoch(const Instant& at);
    void push(const Entry& e);
    void prune(Millis anchor);
    void maybe_report(bool unexpected, Millis anchor, Millis acquired, const Mac& trigger, Origin origin, ObservationSink& out);

    const ApprovedScope& scope_;
    DetectorLimits limits_;
    bool configured_{};
    bool origin_set_{};
    Origin origin_{Origin::LiveRadio};
    bool epoch_set_{};
    TimeEpoch epoch_{};
    Millis latest_{};
    bool has_latest_{};
    std::array<Entry, capacity> ring_{};
    std::size_t head_{};
    std::size_t size_{};
    Millis saturated_until_{};
    std::array<bool, ApprovedScope::capacity + 2> reported_{};
    std::array<Millis, ApprovedScope::capacity + 2> last_report_{};
    BaselineStats stats_{};
    std::uint32_t frames_seen_{};   // G16E report
    std::uint32_t events_{};        // differing / unexpected advertisements counted
    bool has_event_{};
    Millis last_event_{};
};

} // namespace guardian

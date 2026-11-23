#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "guardian/advice.hpp"
#include "guardian/capabilities.hpp"
#include "guardian/core.hpp"
#include "guardian/detectors.hpp"
#include "guardian/guard_cycle.hpp"
#include "guardian/identity.hpp"
#include "guardian/parser.hpp"
#include "guardian/radio.hpp"
#include "guardian/time.hpp"

// G08: portable presentation and interaction state, before any board paints.
//
// Inputs: Core Snapshots (values), typed input Actions (the board maps its
// physical keys to them; the presenter never reads a pin), picker Candidates
// (the application reduces each received advertisement with candidate_from()),
// the owner-approved scope (read-only) and the static DisplayCapabilities of
// the output. Outputs: the face ViewModel, a DetailsView and a PickerView,
// plus OwnerRequests (select / approve / revoke) the application applies to
// Core, ApprovedScope and the SelectionStore. Nothing here draws, allocates,
// reads a clock or writes storage; a renderer chooses sprites and fonts from
// these values and a board adapter owns button reads and NVS (G14).
//
// Policy fixed here (docs/G08-presenter.md, executable in
// firmware/tests/presenter_check.cpp and presenter_policy_check.cpp):
//   * five rated moods and nothing else on the face; Mood::Unknown is "Not
//     rated" with an explaining overlay, never a sixth expression;
//   * the evidence overlay (Checking / NoFreshData / CoverageDegraded /
//     Unsupported) is distinct from the incident banner: both are visible at
//     once, so stale evidence never hides an incident and an incident never
//     hides staleness (closes the G06 one-overlay-slot limit);
//   * stale, degraded and checking views hide the mood face; historical views
//     are also MUTED, with a replay grade labelled historical, never celebrated;
//   * celebration (the grin and cigar animation) only for VeryGood, never
//     during a visible incident, never over a historical record;
//   * selection is by exact SSID bytes AND BSSID; a display Label is never an
//     identity; candidates sharing SSID bytes get a BSSID disambiguator;
//   * DEMO is a separate mode over built-in fixtures (Origin::Demo): it cycles
//     the five expressions with the demo flag set, never offers a candidate,
//     never emits a request, never opens the picker, and a LIVE incident
//     still breaks through it;
//   * incident priority when several are current: DisconnectBurst, then
//     UnexpectedAp, then SettingsChanged (the G07 next-step order).
namespace guardian {

// Evidence overlay on the face. Incident is kept for the legacy present()
// reducer (fresh evidence + incident); the Presenter reports incidents through
// ViewModel::incident so an incident and a coverage overlay coexist.
enum class Overlay { None, Checking, NoFreshData, CoverageDegraded, Unsupported, Incident };

// G24: Settings = the device settings screen (one big option per page), opened by holding FRONT on the face or details.
enum class Screen : std::uint8_t { Face, Details, Picker, Settings };
enum class ViewMode : std::uint8_t { Live, Demo };

// Abstract input. The board maps physical keys (StickS3: front key -> Primary,
// side key -> Secondary; a long press is the board's debounce/hold decision).
// Documented transitions (handle()):
//   Face:    Primary -> Details; PrimaryLong -> Settings screen (G24 retry; in DEMO: back to Live);
//            Secondary -> (DEMO) next expression, (Live) nothing;
//            SecondaryLong -> Picker (Live only; ignored in DEMO)
//   Details: Primary -> next page (Settings, Explanation, Signal, Owner checks, What it cannot see, then Nearby
//            while something is nearby; after the last page: Face); Secondary/Back -> Face;
//            PrimaryLong -> Settings screen (in DEMO: back to Live, Face); SecondaryLong -> Picker (Live only)
//   No key enters DEMO (owner 2026-11-21, "is for development, ditch"): set_demo() is the direct method.
//   Settings (G25 keys, owner 2026-11-23 "SIDE changes, BLUE saves" then "or hold side to save"; single key,
//            the owner is one-handed): Secondary -> next value of this page (wraps); SecondaryLong -> save
//            this page (SettingsSave request; the SAVED / SAVE FAILED plate shows for settings_plate_ms, then
//            the next page, after the last page Face; a failed save stays on the page); Primary /
//            PrimaryLong / Back -> Face (nothing more saved; the draft is dropped)
//   Details, Router page (G25, first while a router change waits): SecondaryLong -> accept the new settings
//            (OwnerRequest AcceptChange; a STRICT channel move is acknowledged here) and Face; every other key
//            as on the other details pages
//   Any screen: a NEW red ALERT (view().alert turning on) returns to Face (alert-first, G24); amber does not.
//   Picker:  Primary -> move the cursor (wraps); Secondary -> select the highlighted
//            network (OwnerRequest::Select, then Face); PrimaryLong -> approve or revoke
//            the highlighted network as a related AP of the selection (same SSID bytes,
//            another BSSID); SecondaryLong/Back -> cancel (Face)
//   Tick / None never change the screen; Tick expires old candidates.
enum class Action : std::uint8_t { None, Tick, Primary, PrimaryLong, Secondary, SecondaryLong, Back };

// ---- G25: the owner's router changing its own settings ----------------------------------------------
// ROUTER CHANGES (Settings page 3): how the router's own changes (guardian/detectors.hpp RouterState) are
// coloured. DetailsOnly: recorded on the Details Router page, no colour, never lights the dark screen.
// Amber (default): a security change is amber until the owner accepts it; a channel move is one grey line.
// Strict: a security change is the red ALERT until accepted; a channel move is amber until acknowledged.
enum class RouterPolicy : std::uint8_t { DetailsOnly, Amber, Strict };
constexpr std::uint8_t router_policy_count = 3;
const char* router_policy_text(RouterPolicy);   // STATUS: "details", "amber", "strict"
enum class Tone : std::uint8_t { None, Grey, Amber, Red };
struct RouterView {
    RouterPolicy policy{RouterPolicy::Amber};
    RouterChange change{};           // change.pending: a security change waiting for the owner
    std::uint8_t pending{};          // approved APs with a pending change (the newest is `change`)
    Tone change_tone{Tone::None};    // pending: Grey (DetailsOnly), Amber, Red (Strict)
    std::uint32_t moves{};           // channel moves since the scope was set
    ChannelMove last_move{};
    bool move_unacked{};             // Strict: a channel move the owner has not acknowledged
    Tone move_tone{Tone::None};      // moves: Grey, or Amber while move_unacked
    bool page{};                     // the Details Router page is offered (change pending or move_unacked)
    bool age_known{};                // change.first's age at the presenter's instant (same epoch)
    Millis age_ms{};
};
// Short display labels of the summary values ("WPA3", "WPA2/WPA3", "WPA2", "WPA", "WEP", "open", "OWE",
// "Enterprise", "unknown"; "GCMP", "CCMP", "TKIP", "WEP", "none"; "required", "optional", "off").
const char* router_mode_text(Mode);
const char* router_cipher_text(Cipher);
const char* router_pmf_text(Pmf);
// The router's change in plain words (owner wording), copied by hand (no formatted output here):
//   Full    "Your router changed its security settings: PMF (required -> optional), a downgrade"
//           (every differing item of mode / cipher / PMF, or "other options" when only finer fields
//           differ; ", a downgrade" when security_downgrade());
//   Short   "Router changed security: PMF, a downgrade" (the items' names only);
//   Minimal "Router changed its security settings".
// Without a pending change but with a move the owner has not acknowledged (Strict):
//   Full "Your router moved to channel 11 (from 6)", Short/Minimal "Router moved to ch 11".
// Returns the length written; 0 with an empty string when there is nothing to say or it does not fit.
enum class RouterWording : std::uint8_t { Full, Short, Minimal };
std::size_t router_sentence(const RouterView&, RouterWording, char* out, std::size_t capacity);
// The grey channel-move line: "Router moved ch 6->11", or "Router moved 3x, 6->11" after several
// moves; 0 with an empty string without a move.
std::size_t move_line(const RouterView&, char* out, std::size_t capacity);

// Display text derived from SSID bytes. NEVER an identity (identity.hpp): two
// different byte strings may share a label; selection always carries the bytes.
// Printable ASCII (0x20..0x7E) is kept; every other byte becomes '?' and sets
// `altered` (the 5x7 renderer font has no other glyphs, and nothing is
// injected into a log or a screen from the air). Hidden shows "(hidden)",
// absent "(no name)"; an impossible length (> 32) is clamped and `invalid`.
struct Label {
    static constexpr std::size_t capacity = 40; // 32 glyphs + NUL, or a fixed marker text
    std::array<char, capacity> text{};
    std::uint8_t length{};
    bool exact{};    // every SSID byte is shown as received
    bool altered{};  // at least one byte replaced by '?'
    bool hidden{};
    bool absent{};
    bool invalid{};  // ssid_size > 32 on the input record
    const char* c_str() const { return text.data(); }
};
Label ssid_label(const Network&);
// The same, with the parser's flags (Hidden/Absent come from SsidKind).
Label ssid_label(const Network&, SsidKind);

// "02:11:22:33:44:55", upper-case hex, NUL-terminated.
struct MacText {
    std::array<char, 18> text{};
    const char* c_str() const { return text.data(); }
};
MacText mac_text(const Mac&);

// Static-storage display texts (string literals; the renderer wraps).
const char* mood_text(Mood);          // Unknown -> "Not rated"
const char* overlay_text(Overlay);
const char* mode_text(Mode);
const char* cipher_text(Cipher);
const char* pmf_text(Pmf);
const char* coverage_text(Coverage);
const char* incident_text(IncidentKind);
const char* screen_text(Screen);
const char* view_mode_text(ViewMode); // "LIVE" / "DEMO"
// G14 ALERT reason for a current incident kind: what was observed, never who
// did it or why ("Disconnect burst detected", ...). Count gives "".
const char* alert_text(IncidentKind);
// G16E amber wording for an AREA observation of a family: what was seen
// nearby, never who did it ("Probe flood nearby"), and the counted unit
// ("probes"). family_text: a one-word family name ("probe").
const char* area_text(DetectorFamily);
const char* area_unit(DetectorFamily);
const char* family_text(DetectorFamily);
// G16F: the same wording for one observation: its Pattern when it has one
// ("Join flood nearby", unit "requests"), else its family's (G16E text).
const char* area_text(const IncidentObservation&);
const char* area_unit(const IncidentObservation&);
// G16F red wording for a NetworkPattern incident ("Join flood on your network").
const char* network_pattern_text(Pattern);
// G16J: the one sentence shown beside an observation whose frames matched a tool
// shape (IncidentObservation::shapes): "looks like a known attack tool". It never
// names the tool and is "" for 0.
const char* tool_shape_text(std::uint16_t shapes);

// The most important current incident, with the G06 evidence record the
// renderer must show next to it (count, window, listening coverage, bounds).
// Facts about received frames; never a verdict about an attacker.
struct IncidentBanner {
    bool visible{};
    IncidentKind kind{IncidentKind::DisconnectBurst};
    std::uint8_t current{};        // how many incident kinds are current
    std::uint32_t count{};
    std::uint32_t window_ms{};
    std::uint32_t threshold{};
    std::uint32_t raw_frames{};
    std::uint32_t retries_deduped{};
    std::uint32_t protected_frames{};
    std::uint32_t eapol_frames{};   // context only, never a verdict
    bool saturated{};
    bool coverage_known{};
    Millis listened_ms{};
    Millis coverage_window_ms{};
    bool hopping{};
    std::uint8_t changes{};        // change:: bits
    Pattern pattern{Pattern::None}; // G16F: which passive pattern (NetworkPattern incidents)
    std::uint16_t shapes{};         // G16J: shape:: bits of the evidence (0 = none)
    std::uint32_t distinct_sources{};
    Mac bssid{};
    MacText bssid_text{};
    BurstTuple top{};               // G16S: the most frequent tuple of a disconnect burst at its report (count 0 = none)
    std::uint32_t own_frames{};     // G16T: IncidentObservation::own_frames (> 0: a nearby burst that also named the picked network)
    bool age_known{};              // filled by the Presenter (needs now); false from present()
    Millis age_ms{};
    AdviceId item{AdviceId::None}; // the G07 text id for this banner
};

// Face view. Rendering code chooses sprites/fonts from these values.
struct ViewModel {
    Mood face{Mood::Unknown};
    Overlay overlay{Overlay::Checking};
    Finding explanation{Finding::Unknown};
    bool demo{};
    bool historical{};
    bool celebrate{};
    bool incident_visible{};
    Millis age_ms{};
    // G08 additions
    Screen screen{Screen::Face};
    ViewMode mode{ViewMode::Live};
    Origin origin{Origin::LiveRadio};
    const char* source_label{"LIVE"}; // LIVE / IMPORTED / DEMO, independent of navigation mode
    bool muted{};                 // dim the art: no fresh graded evidence behind this face
    bool animate{};               // the output can animate (DisplayCapabilities::animation Supported)
    bool has_selection{};
    Label selected_label{};
    MacText selected_bssid{};
    bool last_seen_known{};       // comparable observation age in this source epoch
    Millis last_seen_ms{};
    Unrated unrated{Unrated::None};
    IncidentBanner incident{};
    const char* mood_label{""};
    const char* overlay_label{""};
    std::uint8_t demo_step{};     // 0..4 in DEMO
    // G14 owner requirement: a current incident on the selected/approved scope
    // is a red ALERT overlay on the face, independent of the security grade.
    // It suppresses celebration, coexists with stale/degraded overlays, and
    // clears only when its evidence expires (never an "all clear").
    bool alert{};
    const char* alert_reason{""}; // alert_text(incident.kind) while alert (G16F: the pattern's sentence; G16T: the nearby-burst one); the glass shows alert_sentence() (G16R)
    // G16E: a current AREA observation (seen nearby). Amber, never an ALERT:
    // it never changes `face`, the rating or `alert`; it suppresses the
    // celebration. caution_evidence is the newest current area observation.
    bool caution{};
    std::uint8_t caution_count{};          // current area observations
    IncidentObservation caution_evidence{};
    bool caution_age_known{};
    Millis caution_age_ms{};
    const char* caution_reason{""};        // area_text(caution_evidence.family)
    // G16N: Snapshot::incident_seq of the LIVE snapshot (also while DEMO is shown): it changes
    // with every new incident report, red or amber, so a dark screen can be lit for each one.
    // G25: plus every router change or channel move shown in colour (amber or red) under the owner's
    // ROUTER CHANGES setting; a DetailsOnly or grey one never changes it.
    std::uint32_t incident_seq{};
    // G25: the router's own changes and how they are coloured. router_amber: amber on the face from the
    // router (never while a red ALERT shows; it ends the celebration). router_alert: the red ALERT is the
    // router's security change (Strict) and no Core incident is shown (a Core incident keeps the alert's words).
    RouterView router{};
    bool router_amber{};
    bool router_alert{};
};
// Pure reducer of one Snapshot to the face view (pre-G08 API, kept; G08 fills
// the additional fields that need no clock or interaction state).
ViewModel present(const Snapshot&);

// G16R: the red sentence of an ALERT as the glass shows it. The picked network is its
// name, not one address: a disconnect burst reads "Disconnect burst on <name>" with
// the picked network's label (selected_label), whichever address under that name the
// frames named; a name longer than `name_glyphs` is shortened to name_glyphs - 1
// glyphs and a visible '~'. A picked network without a printable name reads
// "Disconnect burst on your network". G16T: a nearby disconnect burst that also
// named the picked network (a NetworkPattern incident with own_frames > 0) reads
// "Nearby burst also on <name>" by the same name rules; its alert_reason is
// "Disconnect burst nearby also on your network". Every other kind keeps alert_reason (those
// sentences say "your network" already). An address is never part of the sentence:
// IncidentBanner::bssid stays evidence for STATUS / JSON. Returns the length written;
// 0 with an empty string when there is no alert or the text does not fit (never cut).
std::size_t alert_sentence(const ViewModel&, char* out, std::size_t capacity, std::size_t name_glyphs = Label::capacity - 1);

// Details screen pages. The presenter paginates the explanation items by the
// display's text rows (DetailsView::rows); a headless output has zero rows and
// receives every item on one page.
// G16E: Nearby is shown only while an area observation is current.
// G16J: Limits ("What it cannot see") follows OwnerChecks, always; then Nearby when current.
// (Appended so the earlier values stay stable.)
// G25: Router ("Your router changed") is the FIRST page while RouterView::page; hold SIDE there accepts.
enum class DetailsPage : std::uint8_t { Settings, Explanation, SignalAndEvidence, OwnerChecks, Nearby, Limits, Router, Count };

// ---- G24 device settings ------------------------------------------------------------------------
// Two settings the owner sets on the stick: the guard listen cycle on battery (guard_cycle.hpp) and the
// screen brightness while lit (backlight percent; the dim level stays its own TUNE key). The application
// owns their storage (a versioned, CRC-checked blob on StickS3) and tells the Presenter what is in effect.
constexpr std::uint8_t brightness_default_pct = 60;
constexpr std::array<std::uint8_t, 5> brightness_choices{{10, 30, 60, 80, 100}};
struct DeviceChoices {
    GuardCycle guard{GuardCycle::Always};
    std::uint8_t bright_pct{brightness_default_pct};
    RouterPolicy router{RouterPolicy::Amber};   // G25
    bool valid() const;               // a known guard choice, one of brightness_choices and a known router policy
    bool operator==(const DeviceChoices& o) const { return guard == o.guard && bright_pct == o.bright_pct && router == o.router; }
};
enum class SettingsPage : std::uint8_t { Guard, Brightness, Router };
constexpr std::uint8_t settings_pages = 3;
enum class SavePlate : std::uint8_t { None, Saved, Failed };
struct SettingsView {
    bool open{};                      // the Settings screen is shown
    SettingsPage page{SettingsPage::Guard};
    std::uint8_t number{1};           // 1-based page number of settings_pages
    DeviceChoices shown{};            // the in-effect values with this page's draft applied
    DeviceChoices saved{};            // the values in effect (set_device / a successful save)
    SavePlate plate{SavePlate::None}; // shown after a save for settings_plate_ms
};

struct DetailsView {
    DetailsPage page{DetailsPage::Settings};
    const char* title{""};               // "Advertised Wi-Fi settings"
    Advice advice{};                     // G07 reduction of the shown snapshot
    const char* mood_label{""};
    const char* mode_label{""};
    const char* pairwise_label{""};
    const char* group_label{""};
    const char* pmf_label{""};
    const char* coverage_label{""};
    bool age_known{};
    Millis age_ms{};
    bool historical{};
    bool demo{};
    IncidentBanner incident{};
    Origin origin{Origin::LiveRadio};
    const char* source_label{"LIVE"};
    bool has_coverage{};
    CoverageReport coverage{};           // actual listening/drops/support, separate from the grade
    Millis coverage_age_ms{};
    // Explanation pagination: items[first_item .. first_item + item_count) of advice.items.
    std::uint8_t first_item{};
    std::uint8_t item_count{};
    std::uint8_t items_per_page{};      // 0 = unlimited (headless)
    std::uint8_t rows{};                // text rows the display offers (height / 8)
    std::uint8_t columns{};             // text columns (width / 6)
    // G16C: the advertised settings behind the labels above, for compact
    // renderer badges (same snapshot, nothing recomputed).
    Mode mode{Mode::Unknown};
    Cipher pairwise{Cipher::Unknown};
    Pmf pmf{Pmf::Unknown};
    // G16C: owner-check pagination (OwnerChecks page) and the position of the
    // current Explanation/OwnerChecks sub-page (page_index of page_count; 0/1
    // on the other pages). With a TextBudget set, pages are planned by WRAPPED
    // ROWS, so every planned page fits and the last page is always reachable.
    std::uint8_t first_check{};
    std::uint8_t check_count{};
    std::uint8_t page_index{};
    std::uint8_t page_count{1};
    // G16E Nearby page: every current area observation, newest first, with its age.
    std::array<IncidentObservation, area_slots> nearby{};
    std::array<Millis, area_slots> nearby_age_ms{};
    std::uint8_t nearby_count{};
};

// G16C: greedy word wrap shared by the Presenter's row-based pagination and
// renderers, so a page the Presenter plans is exactly what the renderer draws.
// wrap_take: glyphs of `text` (length n) shown on the row starting at `at`
// for `columns` glyphs per row (breaks at the last space that fits; a word
// longer than a row is split). wrap_next: start of the following row (skips
// the separating spaces). wrapped_rows: rows needed for the whole text.
std::size_t wrap_take(const char* text, std::size_t n, std::size_t at, std::size_t columns);
std::size_t wrap_next(const char* text, std::size_t n, std::size_t at, std::size_t columns);
std::size_t wrapped_rows(const char* text, std::size_t columns);
// Rows a renderer offers for the body of the Explanation page (the next step
// on the first sub-page plus the items) and of the OwnerChecks page. Unset
// (rows 0): the earlier item-count pagination (headless and small displays).
struct TextBudget {
    std::uint8_t columns{};
    std::uint8_t explanation_rows{};
    std::uint8_t owner_rows{};
};

// One observed network the owner may select or approve. Reduced from a parsed
// advertisement by candidate_from(); the baseline facts (fingerprint, DS
// channel) are what a picker offers for explicit approval, never learned
// silently by a detector.
struct Candidate {
    Network network{};
    SsidKind ssid_kind{SsidKind::Absent};
    bool ssid_utf8{};
    Origin origin{Origin::LiveRadio};
    Instant seen{};                      // acquisition instant of the latest advertisement
    Band band{Band::Ghz2_4};
    std::uint8_t channel{};              // tuned channel
    std::int8_t rssi{};
    bool rssi_valid{};
    bool settings_complete{};            // Complete parse with complete settings
    SettingsFingerprint settings{};
    bool ds_channel_present{};
    std::uint8_t ds_channel{};
};
// True only for a Beacon/ProbeResponse with a valid header; copies identity
// bytes, flags, acquisition instant, tuned channel, RSSI and the baseline facts.
bool candidate_from(const ParseResult&, const RxMeta&, Candidate& out);

struct PickerEntry {
    Network network{};
    Label label{};
    MacText bssid_text{};
    bool duplicate_name{};               // another entry has the same SSID bytes
    std::array<char, 16> disambiguator{}; // "..:44:66"; full BSSID and channel also available
    bool selected{};                     // the current live selection (Snapshot::selected)
    bool approved{};                     // an approved related AP (ApprovedScope)
    bool approvable{};                   // same SSID bytes as the selection, another BSSID
    bool hidden{};
    bool ssid_utf8{};
    Band band{Band::Ghz2_4};
    std::uint8_t channel{};
    std::int8_t rssi{};
    bool rssi_valid{};
    bool age_known{};
    Millis age_ms{};
};

struct PickerView {
    static constexpr std::size_t capacity = 16;
    bool open{};
    std::uint8_t count{};
    std::uint8_t cursor{};
    std::array<PickerEntry, capacity> entries{};
    std::uint32_t dropped{};             // candidates refused: list full
    std::uint32_t rejected_origin{};     // Demo / foreign-origin candidates refused
    std::uint32_t rejected_time{};       // invalid or foreign-epoch acquisition instant
};

// What the owner asked for through the picker. The application applies it
// (Core::select, ApprovedScope::select/approve/revoke, SelectionStore::save)
// and the presenter learns the outcome from the next Snapshot/scope. Never
// emitted in DEMO.
// G25 AcceptChange: the owner accepted the router's new settings (ap.network.bssid names the AP); the
// application re-baselines it (Monitor::accept_router_change) and stores the selection.
enum class RequestKind : std::uint8_t { None, Select, Approve, Revoke, AcceptChange };
struct OwnerRequest {
    RequestKind kind{RequestKind::None};
    ApprovedAp ap{};                      // identity bytes + the offered baseline facts
    Instant requested_at{};
};

// Persistence record and adapter contract. The board's key-value adapter
// implements SelectionStore (NVS on StickS3, G14); the host uses a fake. The
// record is a fixed-size value validated before use: a corrupt or foreign
// record restores nothing. DEMO never produces one.
struct PersistedSelection {
    static constexpr std::uint16_t current_version = 1;
    static constexpr std::size_t max_approved = ApprovedScope::capacity;
    std::uint16_t version{current_version};
    bool has_selection{};
    ApprovedAp selected{};
    std::uint8_t approved_count{};
    std::array<ApprovedAp, max_approved> approved{};
    bool valid() const;                   // version, identity rules, bounds
};
class SelectionStore {
public:
    virtual ~SelectionStore() = default;
    virtual bool load(PersistedSelection& out) const = 0; // false: nothing stored / unreadable
    virtual bool save(const PersistedSelection&) = 0;     // false: the write failed (adapter reports it)
};
// The record for the current scope (selection + approved related APs).
PersistedSelection persist(const ApprovedScope&);
// Fills `scope` from a valid record (clear, select, approve...). False and
// an untouched scope when the record is invalid or the scope refuses it.
bool restore(const PersistedSelection&, ApprovedScope& scope);

// Five built-in DEMO fixtures (Origin::Demo), one per rated mood, in face order
// VeryGood, Good, Medium, Bad, Horrible. Fresh, complete, hand-built the way
// Core would produce them; selected network "DEMO". step wraps modulo 5.
Snapshot demo_snapshot(std::uint8_t step);
constexpr std::uint8_t demo_steps = 5;

// Interaction state. One per application; the application task owns it.
class Presenter {
public:
    static constexpr Millis candidate_ttl_ms = 60000; // a network not heard for this long leaves the picker
    // `live_origin` is the Core's origin; candidates of another origin are refused.
    explicit Presenter(DisplayCapabilities display, Origin live_origin = Origin::LiveRadio);

    // New live evidence and the current instant (the clock the application reads).
    // `scope` may be null; otherwise borrowed until next update(), must outlive
    // use. Mismatched-origin snapshots are ignored. Refresh from Core regularly.
    // G25 `router`: the baseline detector's router state (Monitor::router()); null = none (kept as is).
    void update(const Snapshot& live, Instant now, const ApprovedScope* scope = nullptr, const RouterState* router = nullptr);
    // One input action at `now`. Returns true when the view changed.
    bool handle(Action, Instant now);
    // A received advertisement reduced by candidate_from(). Refused (and
    // counted) for foreign/Demo origin, invalid/foreign/future/expired/older time
    // or full capacity. Invalid identities are refused without a counter. A new
    // arrival preserves any existing highlighted identity even when reusing a slot.
    bool offer(const Candidate&);

    const ViewModel& view() const { return view_; }
    const DetailsView& details() const { return details_; }
    const PickerView& picker() const { return picker_; }
    // G16C: plan Explanation/OwnerChecks pages by wrapped rows (see TextBudget).
    void set_text_budget(const TextBudget&);
    // G16J: the same-name watch is ON for every network the owner picks (default):
    // a Select request carries ApprovedAp::watch_impostors, so the selected name
    // advertised by a BSSID that is neither selected nor approved is reported
    // (UnexpectedAp, red). The owner's own other APs (mesh node, extender) are
    // approved from the picker (hold the primary key on a same-name row).
    void set_impostor_watch(bool on) { impostor_watch_ = on; }
    bool impostor_watch() const { return impostor_watch_; }
    ViewMode mode() const { return mode_; }
    // G24 retry (owner 2026-11-21: DEMO "is for development, ditch"): no key enters DEMO any more. The capability
    // stays behind this direct method for tests and tools: true = the mode changed (refused, false, while an owner
    // request is pending or, to enter, while a live incident shows; asking for the mode already in effect is false).
    bool set_demo(bool on);
    Screen screen() const { return screen_; }

    // The pending owner request, cleared by take_request(), selection changes or
    // invalid/changed clock epochs. At most one request belongs to this selection.
    bool has_request() const { return request_.kind != RequestKind::None; }
    OwnerRequest take_request();

    // G24 device settings. set_device: the values in effect (after the application loaded them); an invalid
    // value is refused (false, nothing changes). A hold of FRONT on the Settings screen leaves ONE pending
    // save: take_settings_save() hands the values to store (the in-effect values with this page's draft);
    // the application stores them and reports the outcome with settings_saved() (at the instant of the last
    // handle/update). Without a report no plate shows and the page stays.
    static constexpr Millis settings_plate_ms = 1000;
    bool set_device(const DeviceChoices&);
    const DeviceChoices& device() const { return device_; }
    const SettingsView& settings() const { return settings_view_; }
    bool has_settings_save() const { return save_pending_; }
    DeviceChoices take_settings_save();
    void settings_saved(bool ok);
    // The backlight percent while lit: the brightness page's draft while it is shown (a preview at once),
    // otherwise the brightness in effect.
    std::uint8_t lit_brightness_pct() const;

private:
    struct Slot {
        Candidate c{};
        bool used{};
    };
    void rebuild();
    void rebuild_face(const Snapshot& shown);
    void rebuild_details(const Snapshot& shown);
    void rebuild_picker();
    // Picker table maintenance (G14 board finding: dense neighbourhoods).
    bool evictable(const Slot&) const;   // not selected, not approved, not highlighted
    void order_strongest_first();        // when the picker opens; stable while open
    IncidentBanner banner_from(const Snapshot& live) const;
    void expire(Instant now);
    const Snapshot& shown() const;
    std::uint8_t explanation_pages() const;
    bool toggle_mode();
    void rebuild_settings();
    void settings_advance();          // after a plate: next page, or Face after the last
    bool settings_key(Action);
    void open_settings();
    void to_face();                   // Face, details reset, any settings draft / plate dropped
    void tick_plate();                // the plate's time over: settings_advance()
    DeviceChoices merged() const;     // device_ with this page's draft
    void rebuild_router();            // G25: view_.router and the face colours from router_ and the policy
    bool router_key(Action);          // G25: hold SIDE on the Router page

    DisplayCapabilities display_;
    Origin live_origin_;
    Snapshot live_{};
    Snapshot demo_{};
    Instant now_{};
    bool have_now_{};
    const ApprovedScope* scope_{nullptr};
    ViewMode mode_{ViewMode::Live};
    Screen screen_{Screen::Face};
    std::uint8_t demo_step_{};
    DetailsPage page_{DetailsPage::Settings};
    std::uint8_t explanation_page_{};
    std::uint8_t owner_page_{};
    TextBudget budget_{};
    bool impostor_watch_{true};   // G16J
    // G16C: first item / owner check of each planned sub-page (+ end marker).
    std::array<std::uint8_t, Advice::max_items + 2> explanation_starts_{};
    std::uint8_t explanation_planned_{};   // planned sub-pages (0: item-count pagination)
    std::array<std::uint8_t, static_cast<std::size_t>(OwnerCheckId::Count) + 2> owner_starts_{};
    std::uint8_t owner_planned_{};
    std::uint8_t owner_pages() const;
    void plan_pages();
    std::uint8_t cursor_{};
    std::array<Slot, PickerView::capacity> slots_{};
    std::uint32_t dropped_{};
    std::uint32_t rejected_origin_{};
    std::uint32_t rejected_time_{};
    OwnerRequest request_{};
    // G24
    DeviceChoices device_{};
    SettingsPage settings_page_{SettingsPage::Guard};
    DeviceChoices draft_{};
    bool save_pending_{};
    bool report_due_{};               // a save was taken; settings_saved() reports its outcome
    DeviceChoices pending_{};
    SavePlate plate_{SavePlate::None};
    Millis plate_at_{};
    SettingsView settings_view_{};
    // G25
    RouterState router_{};
    std::uint32_t router_seen_seq_{}, router_seen_moves_{};   // last change_seq / moves taken into account
    std::uint32_t router_wakes_{};    // coloured router events (added to incident_seq)
    std::uint32_t moves_acked_{};     // Strict: channel moves the owner acknowledged
    ViewModel view_{};
    DetailsView details_{};
    PickerView picker_{};
};

} // namespace guardian

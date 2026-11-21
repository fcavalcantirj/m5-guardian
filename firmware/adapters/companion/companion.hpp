#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include "guardian/canvas.hpp"
#include "blob.hpp"
#include "device_settings.hpp"
#include "persona.hpp"
#include "motion.hpp"
#include "burst.hpp"
#include "head3d.hpp"
#include "guardian/presenter.hpp"
#include "measurement.hpp"

// G14 companion wiring, SDK-free and host-tested. It connects the accepted
// G08 Presenter to the real G13 measurement Monitor: picker candidates come
// from the same parsed advertisements the Monitor receives, owner requests
// change the Monitor's approved scope, and the scope is persisted through a
// SelectionStore. No rating, freshness or incident policy lives here; the
// screen composer only formats presenter output. Board code (StickS3) supplies
// raw key levels, an NVS BlobStorage and the panel.
namespace guardian::companion {

// ---- buttons -------------------------------------------------------------
// One physical key. Raw levels are debounced; a press is reported as the
// short action on release, or as the long action once while held for
// long_ms. A key already held when sampling starts is ignored until it has
// been seen released (no action from a key pressed during boot).
struct ButtonTiming {
    Millis debounce_ms{30};
    Millis long_ms{800};
};
class Key {
public:
    Key(Action short_press, Action long_press, ButtonTiming timing = {})
        : short_(short_press), long_(long_press), timing_(timing) {}
    Action sample(bool down, Millis now);
private:
    Action short_, long_;
    ButtonTiming timing_;
    bool started_{}, raw_{}, known_{}, stable_{}, armed_{}, pressing_{}, fired_{};
    Millis raw_since_{}, pressed_at_{};
};

// ---- persistence -----------------------------------------------------------
// Fixed-size, explicitly serialized record: magic "GSEL", format, the
// PersistedSelection fields, CRC-32. decode() accepts only an exact-size
// record with matching magic/format/CRC whose content passes
// PersistedSelection::valid(); on failure `out` is untouched.
constexpr std::size_t ap_record_bytes = 61; // 6 BSSID + 32 SSID + len + flags + band + channel + 19 fingerprint
constexpr std::size_t record_bytes = 4 + 2 + 2 + 1 + 1 + ap_record_bytes * (1 + PersistedSelection::max_approved) + 4;
std::size_t encode(const PersistedSelection&, std::uint8_t* out, std::size_t capacity); // 0: invalid or no room
bool decode(const std::uint8_t* in, std::size_t size, PersistedSelection& out);

// BlobStorage / BlobRead: blob.hpp (G16A: shared with the TUNE store).
class EncodedSelectionStore final : public SelectionStore {
public:
    enum class Loaded : std::uint8_t { Absent, Valid, Unreadable };
    explicit EncodedSelectionStore(BlobStorage& storage) : storage_(storage) {}
    bool load(PersistedSelection& out) const override;
    bool save(const PersistedSelection&) override;
    // Outcome of the latest load(): nothing stored vs a stored record that was
    // corrupt, foreign or invalid (never used, never silently erased).
    Loaded last_load() const { return last_load_; }
private:
    BlobStorage& storage_;
    mutable Loaded last_load_{Loaded::Absent};
};

// What happened to the persisted selection most recently.
enum class StoreState : std::uint8_t { Empty, Restored, Rejected, Saved, SaveFailed };
const char* store_text(StoreState);

struct Status;
struct Frame;

// ---- controller ------------------------------------------------------------
class Companion {
public:
    static constexpr std::size_t pending_capacity = 24;
    // `monitor` uses the same clock; `origin` is the Monitor's origin.
    // `onboarding_seen`: optional 1-byte flag storage; when given, the welcome
    // pages are shown until finished once (owner request, 2026-11-15).
    Companion(const MonotonicClock&, measurement::Monitor&, EncodedSelectionStore&,
              DisplayCapabilities, Origin = Origin::LiveRadio, BlobStorage* onboarding_seen = nullptr);
    static constexpr std::uint8_t onboarding_pages = 3;
    bool onboarding() const { return onboarding_page_ < onboarding_pages; }
    std::uint8_t onboarding_page() const { return onboarding_page_; }
    // Restores the owner's persisted selection (identity + approved baseline
    // facts + approved related APs), never evidence. Then refreshes the view.
    StoreState boot();
    // One received frame through the real Monitor. Advertisements become
    // picker candidates (offered at the next tick()). True only for a valid
    // advertisement of the exact selected network (survey lock evidence).
    bool receive(const measurement::Packet&);
    // Presenter refresh from the Monitor at the current clock instant.
    void tick();
    // Refresh evidence at draw time, not at the previous periodic UI tick.
    void render(const Status&, Frame&);
    // G23 (G22 review H2): the frame for the dim view. Always the Face screen's decision (ALERT,
    // nearby, the fresh rating or NoData), whatever screen is open, so a stick left on Details or on
    // the network list does not dim to a grey "NO DATA" during an incident. The open screen and its
    // lit frame are not changed. The welcome pages keep their own frame, as before.
    void render_dim(const Status&, Frame&);
    // One input action; applies any owner request immediately. True when the view changed.
    bool input(Action);
    // Survey should hop channels: the picker is open or nothing is selected.
    bool discovering() const;
    const Presenter& presenter() const { return presenter_; }
    // G16J: the same-name (impostor) watch for the selected network. On by default:
    // every picked network and a restored selection are watched (a restored record
    // from before G16J is upgraded and saved). Off = the pre-G16J behaviour.
    void set_impostor_watch(bool on);
    bool impostor_watch() const { return presenter_.impostor_watch(); }
    StoreState store() const { return store_; }
    std::uint32_t pending_dropped() const { return pending_dropped_; }
    // G24 device settings: the store is attached before boot(), which loads it (the defaults and
    // SettingsStore::Default without one). A save from the Settings screen is written through it at once
    // and its outcome shown (SAVED / SAVE FAILED); without a store every save fails.
    void attach_settings(DeviceSettingsStore& store) { settings_ = &store; }
    const DeviceChoices& device() const { return presenter_.device(); }
    SettingsStore settings_store() const { return settings_ ? settings_->state() : SettingsStore::Default; }
    // The backlight percent while lit (the brightness page's draft while it is shown).
    std::uint8_t lit_brightness_pct() const { return presenter_.lit_brightness_pct(); }
    // G24 retry: DEMO only through this direct method (tests, tools); no key enters it. See Presenter::set_demo.
    bool set_demo(bool on) { return presenter_.set_demo(on); }
private:
    Instant now() const;
    void apply(const OwnerRequest&);
    void save();
    const MonotonicClock& clock_;
    measurement::Monitor& monitor_;
    EncodedSelectionStore& store_ref_;
    Presenter presenter_;
    StoreState store_{StoreState::Empty};
    std::array<Candidate, pending_capacity> pending_{};
    std::size_t pending_count_{};
    std::uint32_t pending_dropped_{};
    BlobStorage* onboarding_seen_{};
    std::uint8_t onboarding_page_{onboarding_pages}; // == pages: not showing
    DeviceSettingsStore* settings_{};                 // G24
};

// ---- screen composition (diagnostic visuals until art is accepted) ---------
// G16E: amber = an observation NEARBY (area scope); red stays YOUR network's ALERT.
constexpr std::uint16_t amber = rgb565(255, 176, 0);
enum class RadioState : std::uint8_t { Off, Unconfigured, Failed, Discovering, Monitoring };
// G16J: whether the handshake watch (the data path: EAPOL frames) is fed. Off is
// printed on the Details page; OffLoad = turned off because the measured load
// was too high on this device.
enum class HandshakeWatch : std::uint8_t { Off, OffLoad, On };
// G16N: the Details line about guarding with the screen off on battery. Hidden: no line (hosts
// and tests that say nothing). Off: power.dark_s is 0. NotMeasured: on, but the Dark drain has
// not been measured long enough. Measured: "dark guard: about N h left" (dark_guard_h10 tenths
// of an hour until the battery floor, from the measured drain; a voltage estimate).
enum class DarkGuard : std::uint8_t { Hidden, Off, NotMeasured, Measured };
struct Status {
    DarkGuard dark_guard{DarkGuard::Hidden};
    std::uint16_t dark_guard_h10{};
    HandshakeWatch handshake{HandshakeWatch::Off};
    // G16J: the optional area sweep is on (the radio leaves the locked channel briefly).
    bool area_sweep{};
    RadioState radio{RadioState::Off};
    StoreState store{StoreState::Empty};
    // The board has the complete G16C portrait set (persona::ArtSet::complete):
    // every rating, both ALERT pulses of each and the NoData silhouette. Without
    // it the composer keeps the honest placeholder block.
    bool persona_art{};
    // G16C rework: seconds left in an owner-confirmed TUNE session over Wi-Fi
    // (0 = none). Monitoring is paused meanwhile; the bottom rows say so.
    std::uint16_t tune_session_s{};
    // G16E: the live threat radar (Companion::render fills it from the Monitor;
    // known=false: no radar decoration and no rates are shown).
    measurement::Radar radar{};
};
struct Line {
    std::array<char, 41> text{};
    std::uint16_t color{color::white};
    std::int16_t x{};
    std::int16_t y{};
    std::uint8_t scale{1};
    bool plated{};               // G16C: a filled plate behind the text (tags, badges)
    std::uint16_t plate{color::black};
};
// G16C: what the face zone shows. Rated only for a fresh rating (never for
// Unknown, stale, historical or imported evidence); Alert = that rating's
// ALERT pulse pair; NoData = the expression-free silhouette with a marker.
enum class FaceArt : std::uint8_t { None, Rated, Alert, NoData };
// G16C techy HUD: graphic elements, each set ONLY when its evidence exists
// (host-tested). Text items of the HUD are ordinary Lines.
struct Hud {
    bool shown{};                // HUD frame, separator and decorative motion on this screen
    bool rssi{};                 // a fresh, valid received-signal reading of the selected network
    std::int8_t rssi_dbm{};
    std::uint8_t bars{};         // 0..4 from rssi_dbm (signal here only; never Internet or speed)
    bool listening{};            // the radio is receiving (passive)
    bool sweeping{};             // ... hopping channels to find the network
    bool locked{};               // ... on the selected network's channel
    bool incident{};             // a current incident (ALERT)
    std::int16_t rssi_x{}, rssi_y{};
    // G16E threat radar: one glyph slot per DetectorFamily on the radar row.
    // Only registered families are drawn; a glyph pulses only on a counted
    // event (Radar::pulse_ms) and turns amber/red while an incident of its
    // family is visible. The rates beside it are an ordinary Line.
    struct Glyph { bool registered{}, pulse{}, active{}; IncidentScope scope{IncidentScope::Network}; };
    bool radar{};
    std::int16_t radar_x{}, radar_y{};
    std::array<Glyph, static_cast<std::size_t>(DetectorFamily::Count)> glyphs{};
};
// G16A/G16C: composed for the upright 135x240 portrait panel (StickS3 standing,
// USB down): at most 22 glyphs per line at 1x and 11 at 2x, pure black.
//   header  y 0..18: mode tag (plate) + BSSID tail slot on row 1, the network
//                    name alone on its own full-width row, a separator
//   face    y 20..179: the 135x160 portrait (or the NoData silhouette + marker)
//   HUD     y 181..239: rating, badges, signal/age, listening, hints
struct Frame {
    static constexpr int width = 135, height = 240;
    static constexpr std::size_t capacity = 40;
    static constexpr int cols1 = 22, cols2 = 11;
    static constexpr int tag_y = 1, name_y = 11, header_h = 19;   // header rows 0..18
    static constexpr int bssid_x = 56;                            // "..:4E:5F" slot on the tag row
    static constexpr int face_zone_y = 20, face_zone_h = 160;     // portrait band 20..179
    static constexpr int hud_y = 181;
    static constexpr int face_x = 27, face_y = 60, face_size = 80; // placeholder block (no art)
    static constexpr int badge_x = 0, badge_y = 180, badge_w = 52, badge_h = 18;   // DEMO plate, top-left of the HUD
    // G16B: reserved for the battery indicator (x >= battery_x, y < battery_h); no text goes there.
    static constexpr int battery_x = 106, battery_h = 11;
    std::array<Line, capacity> lines{};
    std::uint8_t count{};
    std::uint8_t overflow{};     // lines that did not fit in `lines` (a layout defect, never silent)
    bool face_shown{};
    bool muted{};
    bool alert{};
    bool celebrate{};
    bool persona{};              // the art set is used for the face zone
    bool demo_badge{};           // yellow plate behind a 2x "DEMO" line
    bool caution{};              // G16E: amber nearby observation shown (never while alert)
    FaceArt art{FaceArt::None};
    Mood face{Mood::Unknown};
    std::uint16_t face_color{color::grey};
    std::uint16_t header_color{color::grey};
    Hud hud{};
};
// Formats only what the presenter decided: face/details/picker for its screen.
void compose(const Presenter&, const Status&, Frame&);
// G23: the Face screen's frame whatever Presenter::screen() is (the dim view's input; see Companion::render_dim).
void compose_dim(const Presenter&, const Status&, Frame&);
// Welcome page `page` (0-based) of Companion::onboarding_pages.
void compose_onboarding(std::uint8_t page, Frame&);
// G16C: the rows the details pages offer, for the Presenter's row-based
// pagination (the Companion installs it), so a page never ends in "more".
TextBudget details_text_budget();
// G16A EDGE command: a 1-pixel border, one colour per edge (top red, right
// green, bottom blue, left yellow) on black, so a reviewer can confirm on the
// glass that every edge row/column is written and the frame is upright.
void compose_edge_test(Frame&);   // the labels
void draw_edge_test(Canvas&);     // background, border and labels
// Paints a composed frame (portable Canvas); the board then presents it.
// `art`: the embedded portraits (nullptr or incomplete: placeholder block).
// `anim_ms`: monotonic ms (idle breathing, ember/smoke, ALERT pulse, HUD
// decoration). `motion`: the live-tunable idle motion (TUNE persona.*).
// `imu`: the motion model output (the floating face's shift/rotation/pull-back and the HUD
// parallax; see motion.hpp); inactive = still.
// `cache`: optional fast-RAM portrait copy + warped band (G16C rework; see
// persona::WarpCache). Same pixels with or without it.
// `burst` (G16I): optional, board-owned like `cache`. While it is active AND burst_allowed(frame) AND
// it was started from the portrait this frame shows, its particles are painted instead of the
// portrait (no warp, ember, smoke or glance); otherwise draw() CANCELS it and paints the frame as
// usual. So an ALERT, lost evidence, a changed rating or another screen ends a burst at once, and
// the red stare is never hidden. Header, HUD, borders and text are painted exactly as without it.
struct DrawInput {
    const persona::ArtSet* art{};
    Millis anim_ms{};
    persona::Motion motion{};
    motion::Output imu{};
    persona::WarpCache* cache{};
    burst::Burst* burst{};
    // G21: the 3D head's frame for THIS draw (persona::art_bytes, from choose_head), or nullptr = the 2D
    // portrait. draw() uses it for a fresh rated face only (the rule of burst_allowed): never for an
    // ALERT pulse, the NoData silhouette or another screen, whatever the caller put here.
    const std::uint8_t* head{};
};
void draw(Canvas&, const Frame&, const DrawInput& = {});
// G21: sets in.head for this frame: the head's frame for the frame's rating at the motion model's
// yaw / pitch (in.imu; an inactive model is the front view), or nullptr when the frame is not a fresh
// rated face, the 2D set is incomplete, there is no head, or the head has no usable set for this
// rating (then the 2D portrait is painted, as before G21). `hold`: a burst is running, keep the frame
// its particles were made from. The chosen frame is just the art: the upright rotation, the breathing,
// the amber glance and the burst apply to it as to a 2D portrait; the Very good ember and smoke do
// not (the cigar tip is at another place in every frame).
void choose_head(const Frame&, DrawInput&, head3d::Head*, bool hold);
// G16I: a burst may only replace a fresh rated portrait: the face is shown from the art set, the
// art is a Rated face (never NoData, never an ALERT pulse) and no ALERT shows. An amber nearby
// observation does not forbid it (its dashed border and HUD stay).
bool burst_allowed(const Frame&);
// G16I: the portrait this frame shows (what draw() paints), or nullptr without a complete art set.
const std::uint8_t* face_art(const Frame&, const DrawInput&);
// G16I: the pose draw() gives that portrait (idle breathing + IMU placement + amber glance), so the
// board can start a burst from where the face is.
persona::Pose face_pose(const Frame&, const DrawInput&);
// G16E face reaction for an amber (nearby) observation: a wary glance, the
// portrait's horizontal offset in px at `anim_ms` (still most of a 4 s
// period, then a bounded look to one side, alternating sides). Red ALERT is a
// stare instead: the portrait ignores the IMU shift while the ALERT shows.
float glance_dx(Millis anim_ms);
// G16D dim view (battery, left still): the backlight is dimmed by the caller. With the portraits
// on board (review 2026-11-17, owner): the real portrait, STILL (no breath, ember, smoke or IMU
// motion; the same frame every second), the ALERT portrait with a red edge, or the NoData
// silhouette, and one short label in the mood colour below. Without art: the placeholder glyph
// (mood block, red "!" for an ALERT, empty NoData outline). Paints only what the composed frame
// already decided; never a fresher or better state.
void draw_dim(Canvas&, const Frame&, const persona::ArtSet* art = nullptr);
// G16N: shown once, for power::dark_notice_ms at the dim backlight, when the screen is about to go
// dark on battery: black, and one grey sentence on two short rows, "guarding in the dark" /
// "press to look". No rating, no evidence, no colour: it says only that the Guardian still listens.
void draw_dark_notice(Canvas&);

} // namespace guardian::companion

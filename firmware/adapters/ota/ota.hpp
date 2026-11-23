#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include "blob.hpp"

// G16B owner-initiated, signed over-the-air update. SDK-free and host-tested.
//
// The board adapter (StickS3: Wi-Fi station + esp_http_client + esp_ota_ops)
// implements Transport and Slot; everything that decides whether an image is
// accepted lives here and runs against fakes on the host:
//   join -> fetch manifest -> its version newer than the running one (G22A) ->
//   size within the slot -> stream the image into the inactive slot while
//   hashing it -> the version inside the image newer too -> exact length -> sha256 equal to the
//   manifest -> Slot::finish() (ESP-IDF image + RSA-3072 signature check) ->
//   Slot::activate() (the slot switch) -> the caller reboots.
// Any failure aborts the slot, leaves the network and reports one Reason; the
// running image is untouched and the caller resumes passive monitoring.
// A boot record (persisted before the reboot) lets the next boot report the
// outcome, including an automatic rollback.
namespace guardian::ota {

using companion::BlobRead;
using companion::BlobStorage;

// ---- SHA-256 (FIPS 180-4), portable, streaming ------------------------------
class Sha256 {
public:
    Sha256() { reset(); }
    void reset();
    void update(const std::uint8_t* data, std::size_t n);
    void finish(std::uint8_t out[32]);
private:
    void block(const std::uint8_t* p);
    std::uint32_t h_[8]{};
    std::uint8_t buf_[64]{};
    std::size_t used_{};
    std::uint64_t bits_{};
};

// ---- manifest (served by tools/ota-serve.py) --------------------------------
//   GUARDIAN-OTA 1
//   version=<1..31 chars [A-Za-z0-9._-]>
//   size=<decimal bytes, 1..16 MiB>
//   sha256=<64 lowercase hex: the exact bytes of /image>
//   signature=rsa3072-sbv2
//   end
// Every field exactly once, in any order between the header and "end".
constexpr std::size_t max_manifest = 512;
constexpr std::size_t max_version = 31;
struct Manifest {
    std::array<char, max_version + 1> version{};
    std::uint32_t size{};
    std::array<std::uint8_t, 32> sha256{};
};
enum class ManifestError : std::uint8_t { None, Header, Field, Duplicate, Missing, Version, Size, Hash, Scheme, End };
const char* manifest_error_text(ManifestError);
// `out` is written only on success.
ManifestError parse_manifest(const char* text, std::size_t n, Manifest& out);

// ---- outcome ----------------------------------------------------------------
enum class Reason : std::uint8_t {
    None,              // success
    NotProvisioned,    // no Wi-Fi credentials / server URL in NVS
    JoinFailed,        // could not join the owner network
    ManifestFetch,     // manifest request failed
    ManifestInvalid,   // manifest did not parse
    TooLarge,          // image larger than the update slot
    NoSlot,            // no inactive slot / slot begin failed
    Download,          // network error during the image transfer
    Truncated,         // image ended before the manifest size
    Oversize,          // image longer than the manifest size
    LengthMismatch,    // HTTP Content-Length differs from the manifest size
    ShaMismatch,       // received bytes do not match the manifest sha256
    SignatureInvalid,  // unsigned or wrongly signed (ESP-IDF sbv2 check)
    ImageInvalid,      // ESP-IDF image validation failed for another reason
    WriteFailed,       // flash write into the slot failed
    SwitchFailed,      // could not select the new slot for the next boot
    Cancelled,         // owner cancelled / confirmation timed out
    SelfTest,          // the new image failed its boot self-test (rollback)
    CrashBeforeSelfTest, // the new image reset before validating (bootloader rollback)
    NotNewer,          // G22A: the offered version is not newer than the running one (appended: the record stores the number)
};
const char* reason_text(Reason);     // short token for STATUS ("signature", "sha256", ...)
const char* reason_line(Reason);     // <= 22 glyph owner explanation for the screen

// ---- adapters the board implements -----------------------------------------
class Transport {
public:
    virtual ~Transport() = default;
    virtual bool join() = 0;                       // owner-configured network only
    virtual void leave() = 0;                      // always called after join() was attempted
    // GET <server URL>/<path>; content_length = -1 when the server did not say.
    // close() follows every successful open(); a failed open() cleans up itself.
    virtual bool open(const char* path, std::int32_t& content_length) = 0;
    // >0 bytes read, 0 end of body, <0 error.
    virtual int read(std::uint8_t* out, std::size_t capacity) = 0;
    virtual void close() = 0;
};
enum class Finish : std::uint8_t { Ok, SignatureInvalid, ImageInvalid, Failed };
class Slot {
public:
    virtual ~Slot() = default;
    virtual std::uint32_t capacity() const = 0;    // bytes of the inactive slot (0: none)
    virtual bool begin(std::uint32_t size) = 0;
    virtual bool write(const std::uint8_t* data, std::size_t n) = 0;
    virtual void abort() = 0;                      // only between begin() and finish()
    virtual Finish finish() = 0;                   // validates image + signature; ends the session either way
    virtual bool activate() = 0;                   // the slot switch (boot partition)
};
enum class Phase : std::uint8_t { Joining, Manifest, Download, Verify, Switch };
class Observer {
public:
    virtual ~Observer() = default;
    virtual void phase(Phase, std::uint32_t done, std::uint32_t total) = 0;
};

struct Outcome {
    Reason reason{Reason::None};
    Manifest manifest{};          // valid once the manifest parsed
    std::uint32_t received{};
};
// ---- version order (G22A) ----------------------------------------------------
// Build versions are "guardian-<YYYYMMDD>-<HHMMSS>" with an optional "-<suffix>"
// (boards/sticks3/tools/build_support.py default_app_version). The stamp is the
// 14 digits; false: `version` is not in that format.
bool version_stamp(const char* version, std::uint64_t& stamp);
// True only when `offered` is in the format and its stamp is later than `running`'s.
// A running version outside the format (a hand-named build) counts as older than
// every stamped one, so such a stick can still be brought onto stamped builds.
bool newer(const char* offered, const char* running);
// The version an ESP-IDF app image carries in its own descriptor (esp_app_desc_t,
// magic 0xABCD5432 at byte 32, version at bytes 48..79): covered by the image
// signature, unlike the manifest's text. False: `n` < 80 or no descriptor.
constexpr std::size_t app_desc_bytes = 80;
bool image_version(const std::uint8_t* image, std::size_t n, std::array<char, max_version + 1>& out);

// One complete attempt. Success means the new slot is selected for the next
// boot; the caller persists a Pending record and reboots.
// G22A: `running_version` is the running image's version. The manifest's version
// must be newer (refused before any download) and so must the version inside the
// image itself (the manifest is plain text from the network; the image's own
// descriptor is what the signature check at Slot::finish() covers).
Outcome run(Transport&, Slot&, const char* running_version, Observer* = nullptr);

// ---- the unattended self-fetch poll (TUNE ota.auto_s) -------------------------
// G22A: decides when the board may leave monitoring for one poll. A due poll waits
// while something else owns the radio or the glass (`busy`: a session, a
// confirmation, the setup). While a red ALERT is active a due poll is DEFERRED:
// the incident stays on the glass, the deferral is counted once per due poll, and
// the poll runs at the first sample after the alert has ended.
class AutoPoll {
public:
    enum class Decision : std::uint8_t { Wait, Deferred, Run };
    // period_ms 0 = the poll is off. Run is returned once per period.
    Decision sample(std::uint64_t now_ms, std::uint64_t period_ms, bool busy, bool alert);
    std::uint32_t checks() const { return checks_; }         // polls run
    std::uint32_t deferrals() const { return deferrals_; }   // due polls held back by an ALERT
    bool deferred() const { return deferred_; }              // one is being held back now
private:
    std::uint64_t last_{};
    std::uint32_t checks_{}, deferrals_{};
    bool deferred_{};
};
// G23 battery life: the poll period the board runs. TUNE ota.auto_s is the period on USB and, by
// default, on battery too. TUNE ota.auto_batt_s at 0 or more replaces it while the stick runs on
// battery (0 = no poll on battery); below 0 (the default, follow_auto_s) the battery period follows
// ota.auto_s, the behaviour before G23. Seconds become milliseconds as the board did before
// (truncated); a value that is not a number, or 0 or less, is 0 (the poll is off).
constexpr float follow_auto_s = -1.0f;
std::uint64_t poll_period_ms(float auto_s, float auto_batt_s, bool on_battery);
// G26 public image: the automatic poll (and the TUNE offer fetch it carries) runs only while an update
// server is stored (`server_stored`: Provisioner::provisioned(), a network AND a server URL). Without one the
// poll is off whatever ota.auto_s says (NoServer, STATUS ota_auto=off:no_server): no join, no failure record,
// nothing on the glass. The owner's gesture still runs and says "No update server". `period_ms` is
// poll_period_ms() for the power source now; 0 there is Off (gesture only).
enum class AutoMode : std::uint8_t { On, Off, NoServer };
AutoMode auto_mode(bool server_stored, std::uint64_t period_ms);
const char* auto_mode_text(AutoMode);                         // "on", "off", "off:no_server"
std::uint64_t auto_period_ms(AutoMode, std::uint64_t period_ms);   // the period AutoPoll::sample gets (0 = off)

// ---- boot record (NVS key "ota") --------------------------------------------
// Fixed record: magic "GOTA", format, state, reason, from/target slot,
// version, CRC-32. A corrupt record is ignored, never erased.
enum class State : std::uint8_t { None, Pending, Succeeded, Failed, RolledBack };
struct Record {
    State state{State::None};
    Reason reason{Reason::None};
    std::uint8_t from_slot{};
    std::uint8_t target_slot{};
    std::array<char, max_version + 1> version{};
};
constexpr std::size_t record_bytes = 4 + 2 + 1 + 1 + 1 + 1 + (max_version + 1) + 4;
std::size_t encode(const Record&, std::uint8_t* out, std::size_t capacity);
bool decode(const std::uint8_t* in, std::size_t size, Record& out);
bool load(const BlobStorage&, Record& out);   // false: absent or unusable (out untouched)
bool save(BlobStorage&, const Record&);
// "none", "pending:<v>", "ok:<v>", "failed:<reason>", "rolled_back:<reason>"
void result_text(const Record&, char* out, std::size_t n);

// ---- boot self-test and rollback decision ----------------------------------
struct SelfTest {
    bool display{};   // panel initialised and the first frame presented
    bool store{};     // NVS usable and the companion selection not rejected
    bool radio{};     // passive receive initialised and tuned
    bool imu{};       // optional: reported, never required
    bool forced_fail{}; // reviewer test image (CONFIG_GUARDIAN_OTA_SELFTEST_FAIL)
    bool passed() const { return display && store && radio && !forced_fail; }
};
struct BootFacts {
    std::uint8_t running_slot{};
    bool pending_verify{};   // this image is on probation (bootloader rollback armed)
};
enum class BootAction : std::uint8_t { None, MarkValid, Rollback };
// Decides what this boot must do and updates `record` (save it when changed is
// true). A rollback record is saved BEFORE the board triggers the rollback.
struct BootDecision { BootAction action{BootAction::None}; bool changed{}; };
BootDecision decide_boot(Record& record, const BootFacts&, const SelfTest&);

// ---- owner gesture and confirmation ------------------------------------------
// UPDATE mode starts only from a deliberate gesture: both keys held together
// for hold_ms, then an on-screen confirmation (front = yes, side = no,
// confirm_ms timeout = no). While both keys are involved their ordinary
// actions are suppressed until both are released.
class Gesture {
public:
    static constexpr std::uint32_t hold_ms = 3000;
    // True once per hold, when both keys have been down for hold_ms.
    bool sample(bool front_down, bool side_down, std::uint32_t now_ms);
    // Ordinary key actions must be ignored while this is true.
    bool involved() const { return involved_; }
private:
    bool both_{}, fired_{}, involved_{};
    std::uint32_t since_{};
};

// Owner request (2026-11-16, one-handed use): the FRONT key pressed three times
// fast also arms UPDATE. Feed each completed short press of that key. The first
// tap is delivered as an ordinary action; a second within gap_ms is held back;
// a third within gap_ms fires. A held tap with no third is delivered by expire().
class TripleTap {
public:
    static constexpr std::uint32_t gap_ms = 450;   // max time between taps
    enum class Tap : std::uint8_t { Deliver, Hold, Fire };
    Tap tap(std::uint32_t now_ms);
    // True once when a held tap must now be delivered (no third tap in time).
    bool expire(std::uint32_t now_ms);
private:
    std::uint8_t count_{};
    bool held_{};
    std::uint32_t last_{};
};

enum class Answer : std::uint8_t { Pending, Yes, No };
class Confirmation {
public:
    static constexpr std::uint32_t confirm_ms = 15000;
    static constexpr std::uint32_t arm_ms = 800;   // a yes this soon is part of the opening tap burst: ignored
    void open(std::uint32_t now_ms) { open_ = true; opened_ = now_ms; deadline_ = now_ms + confirm_ms; }
    bool is_open() const { return open_; }
    // front/side: a completed short press of that key in this sample.
    Answer sample(bool front_pressed, bool side_pressed, std::uint32_t now_ms);
    std::uint32_t remaining_ms(std::uint32_t now_ms) const;
private:
    bool open_{};
    std::uint32_t opened_{}, deadline_{};
};

// ---- provisioning over USB serial (NVS key "otacfg") ------------------------
// Console lines (never echoed, values never printed back):
//   OTA SSID <hex 1..32 bytes>   OTA PASS <hex 0 or 8..63 bytes, "-" = open>
//   OTA URL <http://host[:port][/path], printable, no spaces, <= 120>
//   OTA SAVE   OTA CLEAR   OTA?
constexpr std::size_t max_ssid = 32, max_pass = 63, max_url = 120;
struct Credentials {
    std::array<std::uint8_t, max_ssid> ssid{};
    std::uint8_t ssid_len{};
    std::array<char, max_pass + 1> pass{};
    std::uint8_t pass_len{};
    std::array<char, max_url + 1> url{};
    bool complete() const { return ssid_len > 0 && url[0] != 0; }
    // G16M: enough to join the network (phone setup stores no server URL unless the owner gives one).
    bool wifi() const { return ssid_len > 0; }
};
constexpr std::size_t credentials_bytes = 4 + 2 + 1 + max_ssid + 1 + (max_pass + 1) + (max_url + 1) + 4;
std::size_t encode(const Credentials&, std::uint8_t* out, std::size_t capacity);
bool decode(const std::uint8_t* in, std::size_t size, Credentials& out);
bool valid_url(const char* url);

class Provisioner {
public:
    explicit Provisioner(BlobStorage& storage) : storage_(storage) {}
    void load();                                  // restores the saved credentials (if any)
    bool provisioned() const { return saved_.complete(); }
    // G16M: a network name (and its password) is stored; UPDATE / TUNE also need the server URL (provisioned()).
    bool wifi_provisioned() const { return saved_.wifi(); }
    // G16M phone setup: replaces the stored record with `c` (a network name is required; the URL may
    // be empty). False: not committed, the previous record stays in use.
    bool store(const Credentials& c);
    const Credentials& credentials() const { return saved_; }
    // false: not an OTA console line (nothing written). Otherwise one reply
    // line "OTA ..." / "OTA ERROR <reason>" that never contains a value.
    bool command(const char* line, char* out, std::size_t n);
private:
    BlobStorage& storage_;
    Credentials saved_{}, staged_{};
    bool ssid_set_{}, pass_set_{}, url_set_{};
};

} // namespace guardian::ota

// ---- UPDATE screens (portable composition + paint) ----------------------------
#include "guardian/canvas.hpp"
namespace guardian::ota {
enum class Stage : std::uint8_t { Confirm, Working, Installed, Failed };
struct View {
    Stage stage{Stage::Confirm};
    Phase phase{Phase::Joining};
    std::uint32_t done{}, total{};       // download bytes
    Reason reason{Reason::None};
    std::uint32_t remaining_ms{};        // confirmation countdown
    const char* running_version{""};
    const char* new_version{""};
};
// Composed for the 135x240 portrait: <= 22 glyphs per 1x line, 11 per 2x line.
struct ScreenLine { std::array<char, 23> text{}; std::uint16_t color{}; std::uint8_t scale{1}; std::int16_t y{}; };
struct Screen {
    static constexpr std::size_t capacity = 16;
    std::array<ScreenLine, capacity> lines{};
    std::uint8_t count{};
    std::uint8_t overflow{};             // lines/glyphs that did not fit: a layout defect, never silent
    bool progress{};                     // draw the download bar
    std::uint8_t percent{};
};
void compose(const View&, Screen&);
void draw(Canvas&, const View&);
} // namespace guardian::ota

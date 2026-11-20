#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include "ota.hpp"

// G16M product setup: the owner gives the stick the home Wi-Fi password from a
// phone. No cable, no Mac, no app. SDK-free and host-tested; the board adapter
// (StickS3: SoftAP + esp_http_server + a DNS answerer) implements Port.
//
//   gesture (hold SIDE 3 s on a network in the list, or FRONT x3 while no Wi-Fi
//   is stored) -> the stick stops listening and raises "Guardian-xxxx", a WPA
//   access point whose one-time password is printed on the glass -> the phone
//   joins it and gets ONE page that asks for the password of the picked network
//   (its name comes from the list, it is never typed) -> the access point goes
//   down -> the stick joins the home network once to check the password ->
//   only a password that joined is stored -> passive listening resumes and the
//   glass says what happened.
//
// The access point lives at most open_ms, ends on any key, and is never opened
// while an ALERT is shown. The stick transmits only inside this owner-started
// session. The home password is never put in a log, a STATUS line or a screen.
// The stored record is the G16B one (ota::Credentials through ota::Provisioner),
// so UPDATE, the automatic update poll and TUNE over Wi-Fi use it unchanged;
// tools/ota_provision.py over USB stays the lab path.
namespace guardian::setup {

using companion::BlobRead;
using companion::BlobStorage;

constexpr std::uint32_t open_ms = 5u * 60u * 1000u;   // the access point's whole life
constexpr std::uint32_t result_ms = 8000;              // SAVED / NOT SAVED stays this long (a key ends it)
constexpr std::uint32_t notice_ms = 5000;              // "pick your network first"
constexpr std::size_t ap_name_bytes = 14;              // "Guardian-XXXX" + NUL
constexpr std::size_t ap_pass_len = 10;
constexpr char page_host[] = "192.168.4.1";            // the ESP-IDF SoftAP default address

// "Guardian-" + the last two bytes of the device MAC in upper-case hex.
void ap_name(const std::uint8_t mac[6], char out[ap_name_bytes]);
// The access point's one-time password: 10 characters from 29 symbols without
// look-alikes on the 5x7 font (a..z without g, i, l, o, q; 2..9), one per
// random byte: 48.6 bits (min-entropy 48.3: 256 is not a multiple of 29, so 24
// symbols come up 9 times in 256 and 5 come up 8 times). G23: was 8 characters
// (38.9 bits); a recorded join of the setup access point can be tried offline
// and the page then carries the home password, so the longer one. 10 glyphs at
// 2x still fit a row of the glass (11). Lower case and digits, so a phone
// keyboard types it without shift.
void ap_pass(const std::uint8_t random[ap_pass_len], char out[ap_pass_len + 1]);
// Overwrites a secret copy; the compiler cannot drop it.
void wipe(void* p, std::size_t n);

// The network the password is for: the exact SSID bytes from the list, whether
// it advertises no protection, and a printable label (never an identity).
struct Target {
    std::array<std::uint8_t, ota::max_ssid> ssid{};
    std::uint8_t ssid_len{};
    bool open{};
    std::array<char, ota::max_ssid + 1> label{};
    bool valid() const { return ssid_len > 0 && ssid_len <= ota::max_ssid; }
};
// A hidden (empty) or oversize name gives an invalid Target. Label: printable ASCII kept, other bytes '?'.
Target target_of(const std::uint8_t* ssid, std::size_t len, bool open);

// ---- gestures ----------------------------------------------------------------
// SIDE alone held for hold_ms. `eligible` is sampled when the press begins (the
// device list is open on a named network); FRONT down at any moment cancels the
// hold, so both keys together stay the UPDATE gesture. True once per hold.
class SideHold {
public:
    static constexpr std::uint32_t hold_ms = 3000;
    bool sample(bool side_down, bool front_down, bool eligible, std::uint32_t now_ms);
    // The press began eligible and is still held (the board keeps the target it captured).
    bool holding() const { return down_ && armed_; }
private:
    bool down_{}, armed_{}, fired_{};
    std::uint32_t since_{};
};
// FRONT x3 fast: SETUP while no Wi-Fi credential is stored (an UPDATE could not
// join anything), the G16B UPDATE question otherwise.
enum class Triple : std::uint8_t { Update, Setup };
constexpr Triple triple_tap(bool wifi_provisioned) { return wifi_provisioned ? Triple::Update : Triple::Setup; }

// ---- the page's form ------------------------------------------------------------
// POST /save, application/x-www-form-urlencoded: p=<password>[&u=<update server URL>].
// Unknown fields are ignored; a repeated p or u is refused.
constexpr std::size_t max_body = 512;
enum class FormError : std::uint8_t { None, Malformed, TooLong, PasswordMissing, PasswordLength, PasswordChars, Url };
const char* form_error_text(FormError);   // one sentence for the page; never contains a value
struct Form {
    std::array<char, ota::max_pass + 1> pass{};
    std::uint8_t pass_len{};
    std::array<char, ota::max_url + 1> url{};
    bool has_url{};
    void wipe();
};
// Password: 8..63 printable ASCII (the G16B rule); empty only for an open
// network. URL: optional, ota::valid_url. `out` is written only on success.
FormError parse_form(const char* body, std::size_t n, bool open_network, Form& out);

// The one page (no script, no external resource) and the answer to a good save.
// Return the length written (NUL-terminated), 0 when `capacity` is too small.
// The network label is HTML-escaped; no stored value is ever put in a page.
constexpr std::size_t page_bytes = 3072;
std::size_t render_form(char* out, std::size_t capacity, const Target&, bool url_stored, FormError shown);
std::size_t render_received(char* out, std::size_t capacity, const Target&);

// The access point's name service: every A question is answered with the page's
// address, so the phone's "sign in to network" sheet opens the page by itself.
// Returns the reply length (0: not a query this answers; nothing is sent).
// Bounded: one question, a name of at most 255 bytes inside the datagram, no
// compression pointers followed. Other question types get an empty answer.
constexpr std::size_t dns_max = 512;
std::size_t dns_answer(const std::uint8_t* query, std::size_t n, const std::uint8_t ip[4], std::uint8_t* out, std::size_t capacity);

// ---- what the board provides -----------------------------------------------------
enum class Join : std::uint8_t { Joined, Password, NotFound, Failed };
class Port {
public:
    virtual ~Port() = default;
    // Passive listening stops, the access point and the page come up. False: nothing is up.
    virtual bool open(const char* ap_name, const char* ap_pass, const Target&, bool url_stored) = 0;
    virtual void close() = 0;                     // access point and page down (idempotent)
    virtual bool take(Form& out) = 0;             // one accepted form submission, at most once
    virtual Join join(const ota::Credentials&) = 0;   // one bounded join of the home network, then leave
    virtual void resume() = 0;                    // passive listening again
};

// ---- where the credential lives --------------------------------------------------
// Plain = the G16B record in the default NVS (not encrypted). Encrypted = the
// same record in the encrypted vault. Error = a vault exists but cannot be
// used: nothing is stored anywhere until the owner repairs it (never a silent
// fall back to plain text).
enum class StoreKind : std::uint8_t { None, Plain, Encrypted, Error };
const char* store_text(StoreKind);   // "none", "plain", "encrypted", "error"
enum class VaultState : std::uint8_t { Absent, Ready, Error };
struct Choice {
    BlobStorage* storage{};
    StoreKind kind{StoreKind::None};
    bool migrated{};         // a plain record was copied into the vault and read back equal
    bool legacy_cleared{};   // the plain record was overwritten with the empty record
};
// Picks the storage for ota::Provisioner at boot and moves a plain credential
// into a ready vault (copy, read back, then overwrite the plain record).
Choice choose_store(BlobStorage& legacy, BlobStorage* vault, VaultState);

// ---- the session -------------------------------------------------------------------
enum class State : std::uint8_t { Idle, Open, Checking, Saved, Failed, Notice };
enum class Entry : std::uint8_t { PickerHold, TripleTap };
enum class Refusal : std::uint8_t { None, Alert, Busy, NoNetwork, Active };
enum class End : std::uint8_t { None, Saved, Timeout, Key, Alert, Password, NotFound, JoinFailed, StoreFailed, AccessPoint };
const char* state_text(State);   // "idle", "open", "checking", "saved", "failed", "notice"
const char* end_text(End);       // "none", "saved", "timeout", "key", "alert", "password", "not_found", "join_failed", "store_failed", "access_point"
struct Facts {
    bool alert{};   // an ALERT is on the glass
    bool busy{};    // UPDATE question / update / TUNE session / console measurement owns the radio or the glass
};
struct View {
    State state{State::Idle};
    End end{End::None};
    const char* ap_name{""};
    const char* ap_pass{""};
    const char* label{""};
    std::uint32_t remaining_ms{};
    StoreKind store{StoreKind::None};
    bool update_server{};   // a server URL is stored (UPDATE / TUNE can reach the Mac)
};

class Session {
public:
    Session(Port& port, ota::Provisioner& provisioner) : port_(port), provisioner_(provisioner) {}
    void set_identity(const std::uint8_t mac[6]) { ap_name(mac, name_.data()); }
    void set_store(StoreKind kind) { store_ = kind; }
    // The owner's gesture. Refused (nothing opened, nothing transmitted) while an
    // ALERT is shown, while something else owns the radio, without a named
    // network, or while a session is open. `random`: ap_pass_len fresh random bytes.
    Refusal request(Entry, const Target&, const Facts&, const std::uint8_t random[ap_pass_len], std::uint32_t now_ms);
    // A completed key press: cancels an open session, dismisses a result or notice.
    void key(std::uint32_t now_ms);
    // Main loop. One step per call, so the board can paint CHECKING before the
    // (blocking, bounded) join runs in the next call.
    void tick(std::uint32_t now_ms, bool alert);
    State state() const { return state_; }
    bool active() const { return state_ == State::Open || state_ == State::Checking; }   // the radio is not listening
    bool visible() const { return state_ != State::Idle; }                                // a setup screen owns the glass
    View view(std::uint32_t now_ms) const;
    std::uint32_t opened() const { return opened_; }
    std::uint32_t saved() const { return saved_; }
    std::uint32_t refused() const { return refused_; }
    End last() const { return last_; }
    // " setup=<state> setup_count=<n> setup_saved=<n> setup_refused=<n> setup_last=<end>" (values never appear)
    bool status_text(char* out, std::size_t n) const;
private:
    void finish(State, End);
    Port& port_;
    ota::Provisioner& provisioner_;
    State state_{State::Idle};
    End end_{End::None}, last_{End::None};
    StoreKind store_{StoreKind::None};
    Target target_{};
    Form form_{};
    std::array<char, ap_name_bytes> name_{};
    std::array<char, ap_pass_len + 1> pass_{};
    std::uint32_t deadline_{}, shown_until_{}, opened_{}, saved_{}, refused_{};
    bool shown_pending_{};
};

// ---- the glass (135x240 portrait: <= 22 glyphs per 1x line, 11 per 2x line) ---------
void compose(const View&, ota::Screen&);
void draw(Canvas&, const View&);

} // namespace guardian::setup

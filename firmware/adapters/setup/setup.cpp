// G16M product setup from the phone (see setup.hpp). SDK-free.
#include "setup.hpp"
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace guardian::setup {
namespace {
bool printable(unsigned char c) { return c >= 32 && c <= 126; }
int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
// True once `deadline` is reached; correct across the 32-bit millisecond wrap.
bool reached(std::uint32_t now, std::uint32_t deadline) { return static_cast<std::int32_t>(now - deadline) >= 0; }
// a..z without i, l, o (0 / 1 look-alikes) and without g, q (both read as 9 on the 5x7 font), and 2..9.
constexpr char kSymbols[] = "abcdefhjkmnprstuvwxyz23456789";
constexpr unsigned kSymbolCount = sizeof kSymbols - 1;
} // namespace

void wipe(void* p, std::size_t n) {
    auto* v = static_cast<volatile std::uint8_t*>(p);
    while (n--) *v++ = 0;
}

void ap_name(const std::uint8_t mac[6], char out[ap_name_bytes]) {
    std::snprintf(out, ap_name_bytes, "Guardian-%02X%02X", unsigned(mac[4]), unsigned(mac[5]));
}

void ap_pass(const std::uint8_t random[ap_pass_len], char out[ap_pass_len + 1]) {
    for (std::size_t i = 0; i < ap_pass_len; ++i) out[i] = kSymbols[random[i] % kSymbolCount];
    out[ap_pass_len] = 0;
}

Target target_of(const std::uint8_t* ssid, std::size_t len, bool open) {
    Target t;
    if (!ssid || !len || len > ota::max_ssid) return t;
    std::memcpy(t.ssid.data(), ssid, len);
    t.ssid_len = static_cast<std::uint8_t>(len);
    t.open = open;
    for (std::size_t i = 0; i < len; ++i) t.label[i] = printable(ssid[i]) ? static_cast<char>(ssid[i]) : '?';
    return t;
}

// ---- gestures ----------------------------------------------------------------
bool SideHold::sample(bool side_down, bool front_down, bool eligible, std::uint32_t now_ms) {
    if (!side_down) { down_ = armed_ = fired_ = false; return false; }
    if (!down_) { down_ = true; armed_ = eligible && !front_down; fired_ = false; since_ = now_ms; }
    if (front_down) armed_ = false;   // both keys: the UPDATE gesture, never this one
    if (armed_ && !fired_ && now_ms - since_ >= hold_ms) { fired_ = true; return true; }
    return false;
}

// ---- the form --------------------------------------------------------------------
const char* form_error_text(FormError e) {
    switch (e) {
    case FormError::None: return "";
    case FormError::Malformed: return "The page sent something unexpected. Please try again.";
    case FormError::TooLong: return "That was too long. Please try again.";
    case FormError::PasswordMissing: return "Type the Wi-Fi password of this network.";
    case FormError::PasswordLength: return "A Wi-Fi password has 8 to 63 characters.";
    case FormError::PasswordChars: return "Only plain letters, digits and symbols are supported in the password.";
    case FormError::Url: return "The update server must look like http://192.168.1.10:8070 (at most 120 characters).";
    }
    return "";
}

void Form::wipe() {
    setup::wipe(pass.data(), pass.size());
    setup::wipe(url.data(), url.size());
    pass_len = 0; has_url = false;
}

namespace {
// Decodes one urlencoded value [from, to) into out (capacity includes the NUL).
// 0 = ok, 1 = malformed escape or NUL, 2 = does not fit.
int decode_value(const char* from, const char* to, char* out, std::size_t capacity, std::size_t& len) {
    len = 0;
    for (const char* p = from; p < to; ++p) {
        char c = *p;
        if (c == '+') c = ' ';
        else if (c == '%') {
            if (to - p < 3) return 1;
            const int hi = hex_value(p[1]), lo = hex_value(p[2]);
            if (hi < 0 || lo < 0) return 1;
            c = static_cast<char>(hi * 16 + lo); p += 2;
        }
        if (c == 0) return 1;
        if (len + 1 >= capacity) return 2;
        out[len++] = c;
    }
    out[len] = 0;
    return 0;
}
} // namespace

FormError parse_form(const char* body, std::size_t n, bool open_network, Form& out) {
    if (!body && n) return FormError::Malformed;
    if (n > max_body) return FormError::TooLong;
    Form f;
    // One byte more than the limits, so "too long" is a length error and not a cut value.
    char pass[ota::max_pass + 2]{}; std::size_t pass_len = 0; bool have_pass = false;
    char url[ota::max_url + 2]{}; std::size_t url_len = 0; bool have_url = false;
    FormError result = FormError::None;
    const char* const end = body + n;
    for (const char* at = body; at < end && result == FormError::None;) {
        const char* stop = at; while (stop < end && *stop != '&') ++stop;
        const char* eq = at; while (eq < stop && *eq != '=') ++eq;
        const std::size_t key = static_cast<std::size_t>(eq - at);
        const char* value = eq < stop ? eq + 1 : stop;
        if (key == 1 && *at == 'p') {
            if (have_pass) result = FormError::Malformed;
            else {
                have_pass = true;
                const int r = decode_value(value, stop, pass, sizeof pass, pass_len);
                if (r == 1) result = FormError::Malformed; else if (r == 2) result = FormError::PasswordLength;
            }
        } else if (key == 1 && *at == 'u') {
            if (have_url) result = FormError::Malformed;
            else {
                have_url = true;
                const int r = decode_value(value, stop, url, sizeof url, url_len);
                if (r == 1) result = FormError::Malformed; else if (r == 2) result = FormError::Url;
            }
        }
        at = stop < end ? stop + 1 : stop;
    }
    if (result == FormError::None) {
        if (!pass_len) { if (!open_network) result = FormError::PasswordMissing; }
        else if (pass_len < 8 || pass_len > ota::max_pass) result = FormError::PasswordLength;
        else for (std::size_t i = 0; i < pass_len; ++i) if (!printable(static_cast<unsigned char>(pass[i]))) { result = FormError::PasswordChars; break; }
    }
    if (result == FormError::None && url_len && (url_len > ota::max_url || !ota::valid_url(url))) result = FormError::Url;
    if (result == FormError::None) {
        std::memcpy(f.pass.data(), pass, pass_len); f.pass_len = static_cast<std::uint8_t>(pass_len);
        if (url_len) { std::memcpy(f.url.data(), url, url_len); f.has_url = true; }
        out = f;
    }
    wipe(pass, sizeof pass); wipe(url, sizeof url); f.wipe();
    return result;
}

// ---- the page ------------------------------------------------------------------------
namespace {
class Page {
public:
    Page(char* out, std::size_t capacity) : out_(out), capacity_(capacity) { if (capacity_) out_[0] = 0; }
    void raw(const char* s) { const auto n = std::strlen(s); if (room(n)) { std::memcpy(out_ + at_, s, n); at_ += n; out_[at_] = 0; } }
    void escaped(const char* s) {
        for (; *s; ++s) {
            switch (*s) {
            case '&': raw("&amp;"); break; case '<': raw("&lt;"); break; case '>': raw("&gt;"); break;
            case '"': raw("&quot;"); break; case '\'': raw("&#39;"); break;
            default: { const char one[2] = {*s, 0}; raw(one); }
            }
        }
    }
    std::size_t done() { if (bad_ && capacity_) out_[0] = 0; return bad_ ? 0 : at_; }
private:
    bool room(std::size_t n) { if (bad_ || at_ + n + 1 > capacity_) bad_ = true; return !bad_; }
    char* out_; std::size_t capacity_, at_{}; bool bad_{};
};
constexpr char kHead[] =
    "<!doctype html><html lang=en><meta charset=utf-8>"
    "<meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Guardian setup</title>"
    "<style>body{font:17px system-ui,sans-serif;background:#000;color:#eee;margin:0;padding:22px;max-width:30em}"
    "h1{font-size:21px}b{color:#fff;font-size:19px;word-break:break-all}"
    "input{font:inherit;width:100%;box-sizing:border-box;padding:12px;margin:6px 0 14px;border:1px solid #666;"
    "border-radius:8px;background:#111;color:#fff}"
    "button{font:inherit;font-weight:700;width:100%;padding:14px;margin-top:8px;border:0;border-radius:8px;background:#2a7;color:#000}"
    ".e{color:#f66}.s{color:#999;font-size:14px}</style><h1>Guardian setup</h1>";
} // namespace

std::size_t render_form(char* out, std::size_t capacity, const Target& t, bool url_stored, FormError shown) {
    if (!out) return 0;
    Page p(out, capacity);
    p.raw(kHead);
    p.raw("<p>Wi-Fi network:<br><b>"); p.escaped(t.label.data()); p.raw("</b></p>");
    if (shown != FormError::None) { p.raw("<p class=e>"); p.escaped(form_error_text(shown)); p.raw("</p>"); }
    p.raw("<form method=post action=/save>");
    if (t.open) p.raw("<p>This network is open: no password is needed.</p>");
    else p.raw("<label>Its password<input name=p type=password minlength=8 maxlength=63 required autofocus "
               "autocomplete=off autocapitalize=none autocorrect=off spellcheck=false></label>");
    p.raw("<details><summary class=s>Advanced</summary><label class=s>Update server on your Mac (optional");
    if (url_stored) p.raw("; one is stored, leave empty to keep it");
    p.raw(")<input name=u type=url maxlength=120 placeholder=\"http://192.168.1.10:8070\" autocomplete=off autocapitalize=none "
          "autocorrect=off spellcheck=false></label></details>"
          "<button>Save</button></form>"
          "<p class=s>The Guardian closes this access point, joins the network once to check the password, stores it "
          "on the stick only if it worked, and goes back to listening. Watch its screen.</p>");
    return p.done();
}

std::size_t render_received(char* out, std::size_t capacity, const Target& t) {
    if (!out) return 0;
    Page p(out, capacity);
    p.raw(kHead);
    p.raw("<p>Received. This access point is closing now.</p><p>The Guardian is joining<br><b>");
    p.escaped(t.label.data());
    p.raw("</b><br>to check. Watch its screen: it says SAVED or NOT SAVED in about 20 seconds.</p>"
          "<p class=s>Your phone goes back to its usual network by itself.</p>");
    return p.done();
}

// ---- the access point's name service -------------------------------------------------------
std::size_t dns_answer(const std::uint8_t* query, std::size_t n, const std::uint8_t ip[4], std::uint8_t* out, std::size_t capacity) {
    constexpr std::size_t header = 12, answer = 16;
    if (!query || !out || !ip || n < header + 5 || n > dns_max) return 0;
    if (query[2] & 0x80) return 0;                                   // a response, not a query
    if ((query[2] & 0x78) != 0) return 0;                            // only the standard query opcode
    if (query[4] != 0 || query[5] != 1) return 0;                    // exactly one question
    std::size_t at = header, name = 0;
    for (;;) {                                                       // the name: plain labels only
        if (at >= n) return 0;
        const std::uint8_t len = query[at];
        if (len == 0) { ++at; break; }
        if (len > 63) return 0;                                      // a compression pointer or a reserved form
        name += static_cast<std::size_t>(len) + 1;
        if (name > 255 || at + 1 + len > n) return 0;
        at += static_cast<std::size_t>(len) + 1;
    }
    if (at + 4 > n) return 0;                                        // type + class
    const bool address = query[at] == 0 && query[at + 1] == 1 && query[at + 2] == 0 && query[at + 3] == 1;   // A, IN
    const std::size_t question_end = at + 4;
    const std::size_t total = question_end + (address ? answer : 0);
    if (total > capacity) return 0;
    std::memcpy(out, query, question_end);                           // id, question (anything after it is dropped)
    out[2] = static_cast<std::uint8_t>(0x80 | (query[2] & 0x01));    // response, recursion-desired echoed
    out[3] = 0x80;                                                   // recursion available, no error
    out[4] = 0; out[5] = 1; out[6] = 0; out[7] = address ? 1 : 0;
    out[8] = out[9] = out[10] = out[11] = 0;
    if (address) {
        std::uint8_t* a = out + question_end;
        a[0] = 0xC0; a[1] = 0x0C;                                    // the question's name
        a[2] = 0; a[3] = 1; a[4] = 0; a[5] = 1;                      // A, IN
        a[6] = 0; a[7] = 0; a[8] = 0; a[9] = 10;                     // 10 s: forgotten right after setup
        a[10] = 0; a[11] = 4;
        std::memcpy(a + 12, ip, 4);
    }
    return total;
}

// ---- where the credential lives --------------------------------------------------------
const char* store_text(StoreKind k) {
    switch (k) {
    case StoreKind::None: return "none"; case StoreKind::Plain: return "plain";
    case StoreKind::Encrypted: return "encrypted"; case StoreKind::Error: return "error";
    }
    return "?";
}

namespace {
class RefusingStore final : public BlobStorage {
public:
    BlobRead read(std::uint8_t*, std::size_t, std::size_t&) const override { return BlobRead::Error; }
    bool write(const std::uint8_t*, std::size_t) override { return false; }
};
RefusingStore refusing;
// The stored record, if it is a usable Wi-Fi credential.
bool read_credential(const BlobStorage& s, std::uint8_t* buf, std::size_t& n) {
    ota::Credentials c;
    const bool ok = s.read(buf, ota::credentials_bytes, n) == BlobRead::Ok && ota::decode(buf, n, c) && c.wifi();
    wipe(&c, sizeof c);
    return ok;
}
bool clear(BlobStorage& s) {
    std::uint8_t buf[ota::credentials_bytes];
    const auto n = ota::encode(ota::Credentials{}, buf, sizeof buf);
    return n && s.write(buf, n);
}
} // namespace

Choice choose_store(BlobStorage& legacy, BlobStorage* vault, VaultState state) {
    Choice c;
    if (state == VaultState::Error) { c.storage = &refusing; c.kind = StoreKind::Error; return c; }
    if (state == VaultState::Absent || !vault) { c.storage = &legacy; c.kind = StoreKind::Plain; return c; }
    std::uint8_t plain[ota::credentials_bytes], check[ota::credentials_bytes];
    std::size_t plain_n = 0, check_n = 0;
    const bool in_legacy = read_credential(legacy, plain, plain_n);
    const bool in_vault = read_credential(*vault, check, check_n);
    c.storage = vault; c.kind = StoreKind::Encrypted;
    if (in_legacy && !in_vault) {
        // Copy, read back, compare; only then is the plain record overwritten.
        const bool moved = vault->write(plain, plain_n) && vault->read(check, sizeof check, check_n) == BlobRead::Ok
                           && check_n == plain_n && std::memcmp(check, plain, plain_n) == 0;
        if (moved) { c.migrated = true; c.legacy_cleared = clear(legacy); }
        else { c.storage = &legacy; c.kind = StoreKind::Plain; }   // keep what works; STATUS says plain
    } else if (in_legacy) {
        c.legacy_cleared = clear(legacy);
    }
    wipe(plain, sizeof plain); wipe(check, sizeof check);
    return c;
}

// ---- the session -------------------------------------------------------------------------
const char* state_text(State s) {
    switch (s) {
    case State::Idle: return "idle"; case State::Open: return "open"; case State::Checking: return "checking";
    case State::Saved: return "saved"; case State::Failed: return "failed"; case State::Notice: return "notice";
    }
    return "?";
}
const char* end_text(End e) {
    switch (e) {
    case End::None: return "none"; case End::Saved: return "saved"; case End::Timeout: return "timeout"; case End::Key: return "key";
    case End::Alert: return "alert"; case End::Password: return "password"; case End::NotFound: return "not_found";
    case End::JoinFailed: return "join_failed"; case End::StoreFailed: return "store_failed"; case End::AccessPoint: return "access_point";
    }
    return "?";
}

void Session::finish(State next, End why) {
    form_.wipe();
    wipe(pass_.data(), pass_.size());
    state_ = next; end_ = why;
    if (why != End::None) last_ = why;
    shown_pending_ = next == State::Saved || next == State::Failed;
}

Refusal Session::request(Entry, const Target& target, const Facts& facts, const std::uint8_t random[ap_pass_len], std::uint32_t now_ms) {
    if (active()) return Refusal::Active;
    // An ALERT keeps the glass and the radio keeps listening: no screen, no access point.
    if (facts.alert) { if (refused_ != 0xffffffffu) ++refused_; return Refusal::Alert; }
    if (facts.busy) { if (refused_ != 0xffffffffu) ++refused_; return Refusal::Busy; }
    if (!target.valid()) {
        state_ = State::Notice; end_ = End::None; shown_pending_ = false; shown_until_ = now_ms + notice_ms;
        return Refusal::NoNetwork;
    }
    target_ = target;
    form_.wipe();
    ap_pass(random, pass_.data());
    if (opened_ != 0xffffffffu) ++opened_;
    if (!port_.open(name_.data(), pass_.data(), target_, provisioner_.credentials().url[0] != 0)) {
        port_.close(); port_.resume();
        finish(State::Failed, End::AccessPoint);
        return Refusal::None;
    }
    state_ = State::Open; end_ = End::None; deadline_ = now_ms + open_ms;
    return Refusal::None;
}

void Session::key(std::uint32_t) {
    switch (state_) {
    case State::Open: port_.close(); port_.resume(); finish(State::Idle, End::Key); break;
    case State::Saved: case State::Failed: case State::Notice: state_ = State::Idle; shown_pending_ = false; break;
    case State::Checking: case State::Idle: break;   // the join is bounded; nothing to cancel
    }
}

void Session::tick(std::uint32_t now_ms, bool alert) {
    switch (state_) {
    case State::Idle: break;
    case State::Open:
        if (alert) { port_.close(); port_.resume(); finish(State::Idle, End::Alert); }
        else if (reached(now_ms, deadline_)) { port_.close(); port_.resume(); finish(State::Idle, End::Timeout); }
        else if (port_.take(form_)) state_ = State::Checking;
        break;
    case State::Checking: {
        port_.close();
        ota::Credentials c;
        c.ssid = target_.ssid; c.ssid_len = target_.ssid_len;
        c.pass = form_.pass; c.pass_len = form_.pass_len;
        c.url = form_.has_url ? form_.url : provisioner_.credentials().url;
        End why = End::JoinFailed;
        switch (port_.join(c)) {
        case Join::Joined: why = provisioner_.store(c) ? End::Saved : End::StoreFailed; break;
        case Join::Password: why = End::Password; break;
        case Join::NotFound: why = End::NotFound; break;
        case Join::Failed: why = End::JoinFailed; break;
        }
        wipe(&c, sizeof c);
        port_.resume();
        if (why == End::Saved && saved_ != 0xffffffffu) ++saved_;
        finish(why == End::Saved ? State::Saved : State::Failed, why);
        break;
    }
    case State::Saved: case State::Failed: case State::Notice:
        // The join blocked for up to its timeout: the result's time starts at the first tick after it.
        if (shown_pending_) { shown_pending_ = false; shown_until_ = now_ms + result_ms; }
        if (alert || reached(now_ms, shown_until_)) state_ = State::Idle;   // an ALERT always gets the glass
        break;
    }
}

View Session::view(std::uint32_t now_ms) const {
    View v;
    v.state = state_; v.end = end_;
    v.ap_name = name_.data(); v.ap_pass = pass_.data(); v.label = target_.label.data();
    v.remaining_ms = state_ == State::Open && !reached(now_ms, deadline_) ? deadline_ - now_ms : 0;
    v.store = store_;
    v.update_server = provisioner_.credentials().url[0] != 0;
    return v;
}

bool Session::status_text(char* out, std::size_t n) const {
    if (!out || !n) return false;
    const int w = std::snprintf(out, n, " setup=%s setup_count=%u setup_saved=%u setup_refused=%u setup_last=%s", state_text(state_),
                                unsigned(opened_), unsigned(saved_), unsigned(refused_), end_text(last_));
    if (w > 0 && static_cast<std::size_t>(w) < n) return true;
    out[0] = 0;
    return false;
}

// ---- the glass -------------------------------------------------------------------------------
namespace {
constexpr std::uint16_t cyan = rgb565(0, 200, 220);
#if defined(__GNUC__)
__attribute__((format(printf, 5, 6)))
#endif
void line(ota::Screen& s, int y, std::uint16_t color, std::uint8_t scale, const char* format, ...) {
    if (s.count >= s.lines.size()) { ++s.overflow; return; }
    auto& l = s.lines[s.count++];
    char wide[64];
    va_list args; va_start(args, format);
    const int w = std::vsnprintf(wide, sizeof wide, format, args);
    va_end(args);
    const std::size_t limit = scale == 2 ? 11u : 22u;
    if (w < 0 || static_cast<std::size_t>(w) > limit) ++s.overflow;   // never cut silently
    std::snprintf(l.text.data(), l.text.size(), "%.*s", static_cast<int>(limit), wide);
    l.y = static_cast<std::int16_t>(y); l.color = color; l.scale = scale;
}
// A network label (<= 32 glyphs) on one or two 1x lines, never cut.
int label_lines(ota::Screen& s, int y, const char* label) {
    const auto n = std::strlen(label);
    line(s, y, color::white, 1, "%.22s", n ? label : "(no name)"); y += 10;
    if (n > 22) { line(s, y, color::white, 1, "%.22s", label + 22); y += 10; }
    return y;
}
const char* failure_line(End e) {   // <= 22 glyphs
    switch (e) {
    case End::Password: return "Password not accepted";
    case End::NotFound: return "Network not in range";
    case End::JoinFailed: return "Could not join it";
    case End::StoreFailed: return "Storage refused it";
    case End::AccessPoint: return "Access point failed";
    default: return "Setup did not finish";
    }
}
} // namespace

void compose(const View& v, ota::Screen& s) {
    s = ota::Screen{};
    switch (v.state) {
    case State::Idle: break;
    case State::Open: {
        line(s, 6, cyan, 2, "SETUP");
        int y = 28;
        line(s, y, color::white, 1, "On your phone, join"); y += 10;
        line(s, y, color::white, 1, "this Wi-Fi:"); y += 12;
        line(s, y, color::yellow, 1, "%s", v.ap_name); y += 12;
        line(s, y, color::grey, 1, "its password:"); y += 11;
        line(s, y, color::green, 2, "%s", v.ap_pass); y += 22;
        line(s, y, color::white, 1, "A page opens. If not:"); y += 10;
        line(s, y, color::yellow, 1, "http://%s", page_host); y += 14;
        line(s, y, color::grey, 1, "It asks the password"); y += 10;
        line(s, y, color::grey, 1, "of:"); y += 10;
        y = label_lines(s, y, v.label) + 4;
        line(s, y, color::grey, 1, "Monitoring is paused."); y += 12;
        line(s, y, color::red, 1, "Any key = cancel"); y += 10;
        const unsigned left = unsigned((v.remaining_ms + 999) / 1000);
        line(s, y, color::grey, 1, "closes in %u:%02u", left / 60, left % 60);
        break;
    }
    case State::Checking: {
        line(s, 6, cyan, 2, "CHECKING");
        int y = 34;
        line(s, y, color::white, 1, "Access point closed."); y += 14;
        line(s, y, color::white, 1, "Joining:"); y += 10;
        y = label_lines(s, y, v.label) + 4;
        line(s, y, color::grey, 1, "once, to check the"); y += 10;
        line(s, y, color::grey, 1, "password. Up to 20 s."); y += 14;
        line(s, y, color::grey, 1, "Stored only if it"); y += 10;
        line(s, y, color::grey, 1, "joins.");
        break;
    }
    case State::Saved: {
        line(s, 6, color::green, 2, "SAVED");
        int y = 34;
        line(s, y, color::white, 1, "Joined:"); y += 10;
        y = label_lines(s, y, v.label) + 4;
        if (v.store == StoreKind::Encrypted) {
            line(s, y, color::white, 1, "Password stored on"); y += 10;
            line(s, y, color::green, 1, "the stick, encrypted.");
        } else {   // never called encrypted when it is not (no vault on this stick yet)
            line(s, y, color::white, 1, "Password stored,"); y += 10;
            line(s, y, color::yellow, 1, "NOT encrypted.");
        }
        y += 14;
        if (!v.update_server) {
            line(s, y, color::yellow, 1, "No update server yet:"); y += 10;
            line(s, y, color::grey, 1, "setup > Advanced."); y += 14;
        }
        line(s, y, color::green, 1, "Listening again.");
        break;
    }
    case State::Failed: {
        line(s, 6, color::red, 2, "NOT SAVED");
        int y = 34;
        line(s, y, color::white, 1, "%s", failure_line(v.end)); y += 14;
        if (v.end != End::AccessPoint) { y = label_lines(s, y, v.label) + 4; }
        line(s, y, color::green, 1, "Nothing was changed."); y += 10;
        line(s, y, color::grey, 1, "Listening again."); y += 14;
        line(s, y, color::grey, 1, "Do the gesture again"); y += 10;
        line(s, y, color::grey, 1, "to retry.");
        break;
    }
    case State::Notice: {
        line(s, 6, cyan, 2, "SETUP");
        int y = 34;
        line(s, y, color::white, 1, "Pick your network"); y += 10;
        line(s, y, color::white, 1, "first:"); y += 14;
        line(s, y, color::grey, 1, "open the list, go to"); y += 10;
        line(s, y, color::grey, 1, "your Wi-Fi name, then"); y += 10;
        line(s, y, color::grey, 1, "hold SIDE for 3 s.");
        break;
    }
    }
}

void draw(Canvas& c, const View& v) {
    ota::Screen s; compose(v, s);
    c.clear(color::black);
    for (std::uint8_t i = 0; i < s.count; ++i) c.text(2, s.lines[i].y, s.lines[i].text.data(), s.lines[i].color, s.lines[i].scale);
}

} // namespace guardian::setup

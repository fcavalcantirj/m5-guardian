// G16M: phone setup (adapters/setup/setup.hpp) against a fake provisioning port:
// the gestures, the page's form, the session (enter, page served, password
// checked and saved, 5 min timeout, cancel by key, never while an ALERT shows),
// the glass texts, the STATUS fields and where the credential is stored.
#include "check.hpp"
#include "setup.hpp"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace guardian::setup;
namespace ota = guardian::ota;

namespace {
constexpr char kHomePass[] = "correct horse 42!";   // the home password used by every case below

class MemoryBlob final : public BlobStorage {
public:
    std::vector<std::uint8_t> bytes; bool exists{}, fail_write{}, fail_read{}; unsigned writes{};
    BlobRead read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const override {
        if (fail_read) return BlobRead::Error;
        if (!exists) return BlobRead::Absent;
        if (bytes.size() > capacity) return BlobRead::Error;
        std::memcpy(out, bytes.data(), bytes.size()); size = bytes.size(); return BlobRead::Ok;
    }
    bool write(const std::uint8_t* data, std::size_t size) override {
        ++writes; if (fail_write) return false; bytes.assign(data, data + size); exists = true; return true;
    }
    bool holds(const char* text) const {
        const std::string all(bytes.begin(), bytes.end());
        return all.find(text) != std::string::npos;
    }
};

ota::Credentials creds(const char* ssid, const char* pass, const char* url) {
    ota::Credentials c;
    c.ssid_len = static_cast<std::uint8_t>(std::strlen(ssid)); std::memcpy(c.ssid.data(), ssid, c.ssid_len);
    c.pass_len = static_cast<std::uint8_t>(std::strlen(pass)); std::memcpy(c.pass.data(), pass, c.pass_len);
    std::memcpy(c.url.data(), url, std::strlen(url));
    return c;
}
void put(MemoryBlob& blob, const ota::Credentials& c) {
    std::uint8_t buf[ota::credentials_bytes];
    const auto n = ota::encode(c, buf, sizeof buf);
    blob.bytes.assign(buf, buf + n); blob.exists = true;
}
bool get(const MemoryBlob& blob, ota::Credentials& c) {
    return blob.exists && ota::decode(blob.bytes.data(), blob.bytes.size(), c);
}

class FakePort final : public Port {
public:
    std::vector<std::string> calls;      // the order of everything the session asked of the board
    bool open_ok{true}, up{}, listening{true}, pending{}, url_stored_seen{};
    std::string name, pass, target_label;
    Form form{};
    Join answer{Join::Joined};
    ota::Credentials joined_with{};
    bool up_during_join{};
    bool open(const char* ap, const char* ap_pass, const Target& t, bool url_stored) override {
        calls.push_back("open"); listening = false;
        if (!open_ok) return false;
        up = true; name = ap; pass = ap_pass; target_label = t.label.data(); url_stored_seen = url_stored;
        return true;
    }
    void close() override { calls.push_back("close"); up = false; }
    bool take(Form& out) override { if (!pending) return false; pending = false; out = form; return true; }
    Join join(const ota::Credentials& c) override { calls.push_back("join"); joined_with = c; up_during_join = up; return answer; }
    void resume() override { calls.push_back("resume"); listening = true; }
    void submit(const char* body, bool open_network = false) {
        Form f; if (parse_form(body, std::strlen(body), open_network, f) == FormError::None) { form = f; pending = true; }
    }
    unsigned count(const char* what) const { unsigned n = 0; for (const auto& c : calls) n += c == what; return n; }
};

const std::uint8_t kMac[6] = {0xAC, 0x27, 0x6E, 0xD3, 0x51, 0xF4};
const std::uint8_t kRandom[ap_pass_len] = {0, 1, 31, 32, 63, 200, 255, 7};
Target home(bool open = false) { return target_of(reinterpret_cast<const std::uint8_t*>("Casa <5G>"), 9, open); }

struct Rig {
    MemoryBlob blob; ota::Provisioner prov{blob}; FakePort port; Session session{port, prov};
    Rig() { prov.load(); session.set_identity(kMac); session.set_store(StoreKind::Encrypted); }
    Refusal enter(std::uint32_t now, Facts facts = {}, Entry how = Entry::PickerHold) { return session.request(how, home(), facts, kRandom, now); }
};

std::string all_text(const View& v) {
    ota::Screen s; compose(v, s);
    std::string out;
    for (std::uint8_t i = 0; i < s.count; ++i) { out += s.lines[i].text.data(); out += '\n'; }
    return out;
}
bool fits(const View& v) {
    ota::Screen s; compose(v, s);
    if (s.overflow || !s.count) return false;
    for (std::uint8_t i = 0; i < s.count; ++i) {
        const auto n = std::strlen(s.lines[i].text.data());
        if (n > (s.lines[i].scale == 2 ? 11u : 22u)) return false;
        if (s.lines[i].y < 0 || s.lines[i].y + 8 * s.lines[i].scale > 240) return false;
        if (i && s.lines[i].y < s.lines[i - 1].y + 8 * s.lines[i - 1].scale) return false;   // no line over another
    }
    return true;
}
} // namespace

// G23 (G22 review carry-over): the one-time password of the setup access point is 10 symbols, not 8.
// 8 symbols of 29 are 38.9 bits: a recorded join can be tried offline, and the page then carries the
// home password. 10 symbols are 48.6 bits (min-entropy 48.3 with the byte-to-symbol mapping).
GUARDIAN_CASE(one_time_password_is_ten_symbols_and_fits_the_glass) {
    CHECK_EQ(ap_pass_len, std::size_t{10});
    const std::uint8_t random[16] = {250, 3, 77, 28, 29, 131, 9, 255, 64, 17, 1, 2, 3, 4, 5, 6};
    char pass[17] = {};
    ap_pass(random, pass);
    CHECK_EQ(std::strlen(pass), std::size_t{10});
    Rig r; CHECK(r.enter(0) == Refusal::None);
    CHECK_EQ(r.port.pass.size(), std::size_t{10});                            // what the access point is opened with
    const View v = r.session.view(0);
    CHECK_EQ(std::strlen(v.ap_pass), std::size_t{10});                        // and what the glass prints
    CHECK(fits(v));
    const Target wide = target_of(reinterpret_cast<const std::uint8_t*>("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"), 32, false);
    View w; w.state = State::Open; w.label = wide.label.data(); w.ap_name = "Guardian-51F4"; w.ap_pass = "abcdefhjkm"; w.remaining_ms = open_ms; w.store = StoreKind::Plain;
    CHECK(fits(w));                                                           // 10 glyphs at 2x beside the longest network name
    ota::Screen s; compose(w, s); bool big = false;
    for (std::uint8_t i = 0; i < s.count; ++i) if (!std::strcmp(s.lines[i].text.data(), "abcdefhjkm")) big = s.lines[i].scale == 2;
    CHECK(big);                                                               // still the large line
}
GUARDIAN_CASE(access_point_name_and_one_time_password) {
    char name[ap_name_bytes];
    ap_name(kMac, name);
    CHECK_EQ(std::string(name), std::string("Guardian-51F4"));
    char a[ap_pass_len + 1], b[ap_pass_len + 1];
    ap_pass(kRandom, a);
    CHECK_EQ(std::strlen(a), ap_pass_len);                      // WPA2 needs at least 8 (G23: 10)
    for (const char* p = a; *p; ++p) {
        CHECK((*p >= 'a' && *p <= 'z') || (*p >= '2' && *p <= '9'));
        CHECK(*p != 'o' && *p != 'l' && *p != 'i');             // no look-alikes on the 5x7 font
        CHECK(*p != 'g' && *p != 'q');                          // ... both read as 9 on the glass (setup-screens.png)
    }
    const std::uint8_t other[ap_pass_len] = {9, 8, 7, 6, 5, 4, 3, 2};
    ap_pass(other, b);
    CHECK(std::strcmp(a, b) != 0);
    // Every one of the 29 symbols is reachable and distinct, and none is g or q.
    std::string seen;
    for (unsigned v = 0; v < 29; ++v) {
        std::uint8_t r[ap_pass_len] = {}; r[0] = static_cast<std::uint8_t>(v); char p[ap_pass_len + 1]; ap_pass(r, p);
        CHECK(seen.find(p[0]) == std::string::npos); seen += p[0];
    }
    CHECK_EQ(seen.size(), std::size_t{29});
    CHECK(seen.find('g') == std::string::npos && seen.find('q') == std::string::npos && seen.find('9') != std::string::npos);
}

GUARDIAN_CASE(target_carries_the_exact_name_and_a_safe_label) {
    const std::uint8_t raw[] = {'C', 'a', 0xC3, 0xA9, '<', 7};
    const Target t = target_of(raw, sizeof raw, false);
    CHECK(t.valid()); CHECK_EQ(t.ssid_len, 6); CHECK(std::memcmp(t.ssid.data(), raw, 6) == 0);
    CHECK_EQ(std::string(t.label.data()), std::string("Ca?\?<?"));
    CHECK(!target_of(raw, 0, false).valid());                    // hidden name: nothing to join
    std::uint8_t big[40] = {}; std::memset(big, 'a', sizeof big);
    CHECK(!target_of(big, 33, false).valid());
    CHECK(target_of(big, 32, true).valid()); CHECK(target_of(big, 32, true).open);
}

GUARDIAN_CASE(side_hold_fires_once_after_three_seconds_on_the_list) {
    SideHold h;
    CHECK(!h.sample(false, false, true, 0));
    CHECK(!h.sample(true, false, true, 100)); CHECK(h.holding());
    CHECK(!h.sample(true, false, false, 2000));                  // the list closed at 0.8 s (hold SIDE = back): still this press
    CHECK(!h.sample(true, false, false, 3099));
    CHECK(h.sample(true, false, false, 3100));
    CHECK(!h.sample(true, false, false, 9000));                  // once per hold
    CHECK(!h.sample(false, false, true, 9100)); CHECK(!h.holding());
    // A press that began outside the list never fires, however long.
    CHECK(!h.sample(true, false, false, 10000)); CHECK(!h.holding());
    CHECK(!h.sample(true, false, true, 14000));
    CHECK(!h.sample(false, false, true, 14100));
    // Released early: nothing. Then a fresh full hold works.
    CHECK(!h.sample(true, false, true, 15000));
    CHECK(!h.sample(false, false, true, 17900));
    CHECK(!h.sample(true, false, true, 18000));
    CHECK(h.sample(true, false, true, 21000));
    CHECK(!h.sample(false, false, true, 21100));
    // FRONT at any moment cancels (both keys together stay the UPDATE gesture).
    CHECK(!h.sample(true, false, true, 30000));
    CHECK(!h.sample(true, true, true, 31000));
    CHECK(!h.sample(true, false, true, 34000));
    CHECK(!h.sample(false, false, true, 34100));
    CHECK(!h.sample(true, true, true, 40000));                   // began with both keys
    CHECK(!h.sample(true, false, true, 44000));
}

GUARDIAN_CASE(front_triple_tap_is_setup_only_while_no_wifi_is_stored) {
    CHECK(triple_tap(false) == Triple::Setup);
    CHECK(triple_tap(true) == Triple::Update);
}

GUARDIAN_CASE(form_accepts_one_valid_password_and_an_optional_server) {
    Form f;
    CHECK(parse_form("p=correct+horse+42%21", 21, false, f) == FormError::None);
    CHECK_EQ(std::string(f.pass.data()), std::string(kHomePass)); CHECK_EQ(f.pass_len, 17); CHECK(!f.has_url);
    const char with_url[] = "u=http%3A%2F%2F192.168.1.10%3A8070&p=abcdefgh&x=ignored";
    CHECK(parse_form(with_url, std::strlen(with_url), false, f) == FormError::None);
    CHECK(f.has_url); CHECK_EQ(std::string(f.url.data()), std::string("http://192.168.1.10:8070")); CHECK_EQ(f.pass_len, 8);
    CHECK(parse_form("p=abcdefgh&u=", 12, false, f) == FormError::None); CHECK(!f.has_url);   // the empty optional field
    const std::string max63 = "p=" + std::string(63, 'k');
    CHECK(parse_form(max63.data(), max63.size(), false, f) == FormError::None); CHECK_EQ(f.pass_len, 63);
    CHECK(parse_form("p=%2B%26%3D%25+%7E", 18, false, f) == FormError::PasswordLength);          // "+&=% ~" decodes, 6 chars
    CHECK(parse_form("p=%2B%26%3D%25+%7Eab", 20, false, f) == FormError::None);
    CHECK_EQ(std::string(f.pass.data()), std::string("+&=% ~ab"));
    // An open network needs no password; a protected one does.
    CHECK(parse_form("", 0, true, f) == FormError::None); CHECK_EQ(f.pass_len, 0);
    CHECK(parse_form("p=", 2, true, f) == FormError::None); CHECK_EQ(f.pass_len, 0);
}

GUARDIAN_CASE(form_refuses_everything_else_and_leaves_the_output_alone) {
    Form keep; keep.pass_len = 3; std::memcpy(keep.pass.data(), "old", 3);
    const auto refused = [&](const std::string& body, FormError want, bool open = false) {
        const auto got = parse_form(body.data(), body.size(), open, keep);
        return got == want && keep.pass_len == 3 && !std::strcmp(keep.pass.data(), "old");
    };
    CHECK(refused("", FormError::PasswordMissing));
    CHECK(refused("p=", FormError::PasswordMissing));
    CHECK(refused("u=http%3A%2F%2Fa", FormError::PasswordMissing));
    CHECK(refused("p=short", FormError::PasswordLength));
    CHECK(refused("p=short", FormError::PasswordLength, true));              // a typed password is checked even for an "open" label
    CHECK(refused("p=" + std::string(64, 'k'), FormError::PasswordLength));
    CHECK(refused("p=abcdefg%07h", FormError::PasswordChars));               // a control byte
    CHECK(refused("p=abcdefg%C3%A9", FormError::PasswordChars));             // not ASCII (the G16B rule)
    CHECK(refused("p=abcdefgh%0Ax", FormError::PasswordChars));
    CHECK(refused("p=abcdefgh&p=abcdefgh", FormError::Malformed));           // one password
    CHECK(refused("p=abcdefgh&u=http%3A%2F%2Fa&u=http%3A%2F%2Fb", FormError::Malformed));
    CHECK(refused("p=abcdefg%4", FormError::Malformed));                     // cut escape
    CHECK(refused("p=abcdefg%zz", FormError::Malformed));
    CHECK(refused("p=abcdefg%00h", FormError::Malformed));                   // a NUL never shortens the password
    CHECK(refused("p=abcdefgh&u=ftp%3A%2F%2Fmac", FormError::Url));
    CHECK(refused("p=abcdefgh&u=http%3A%2F%2F", FormError::Url));
    CHECK(refused("p=abcdefgh&u=http%3A%2F%2F" + std::string(130, 'a'), FormError::Url));
    CHECK(refused("p=" + std::string(max_body, 'k'), FormError::TooLong));
    CHECK(parse_form(nullptr, 5, false, keep) == FormError::Malformed);
    for (const auto e : {FormError::Malformed, FormError::TooLong, FormError::PasswordMissing, FormError::PasswordLength,
                         FormError::PasswordChars, FormError::Url})
        CHECK(std::strlen(form_error_text(e)) > 10);
    CHECK_EQ(std::strlen(form_error_text(FormError::None)), std::size_t{0});
}

GUARDIAN_CASE(page_asks_only_for_the_password_of_the_named_network) {
    std::vector<char> page(page_bytes);
    const auto n = render_form(page.data(), page.size(), home(), false, FormError::None);
    CHECK(n > 0 && n < page_bytes); CHECK_EQ(std::strlen(page.data()), n);
    const std::string html(page.data());
    CHECK(html.find("Casa &lt;5G&gt;") != std::string::npos);   // the name from the list, escaped
    CHECK(html.find("<5G>") == std::string::npos);
    CHECK(html.find("name=p") != std::string::npos && html.find("type=password") != std::string::npos);
    CHECK(html.find("action=/save") != std::string::npos && html.find("method=post") != std::string::npos);
    CHECK(html.find("name=ssid") == std::string::npos && html.find("name=s ") == std::string::npos);   // the name is never typed
    CHECK(html.find("name=u") != std::string::npos);            // optional update server, under "Advanced"
    CHECK(html.find("<details>") != std::string::npos);
    CHECK(html.find("<script") == std::string::npos && html.find("src=") == std::string::npos && html.find("href=") == std::string::npos);
    std::size_t inputs = 0; for (std::size_t at = 0; (at = html.find("<input", at)) != std::string::npos; ++at) ++inputs;
    CHECK_EQ(inputs, std::size_t{2});
    // An error is one sentence above the form; a stored server is said, never shown.
    const auto m = render_form(page.data(), page.size(), home(), true, FormError::PasswordLength);
    CHECK(m > n);
    const std::string again(page.data());
    CHECK(again.find(form_error_text(FormError::PasswordLength)) != std::string::npos);
    CHECK(again.find("one is stored") != std::string::npos);
    CHECK(html.find("one is stored") == std::string::npos);
    // An open network: no password field at all.
    render_form(page.data(), page.size(), home(true), false, FormError::None);
    const std::string open_page(page.data());
    CHECK(open_page.find("type=password") == std::string::npos && open_page.find("no password") != std::string::npos);
    // The answer to a good save names the network and tells the owner to watch the stick.
    const auto r = render_received(page.data(), page.size(), home());
    CHECK(r > 0); const std::string got(page.data());
    CHECK(got.find("Casa &lt;5G&gt;") != std::string::npos && got.find("screen") != std::string::npos && got.find("<form") == std::string::npos);
    // Hostile label characters and a short buffer.
    const Target hostile = target_of(reinterpret_cast<const std::uint8_t*>("\"'&<>"), 5, false);
    render_form(page.data(), page.size(), hostile, false, FormError::None);
    CHECK(std::string(page.data()).find("&quot;&#39;&amp;&lt;&gt;") != std::string::npos);
    char tiny[64]; CHECK_EQ(render_form(tiny, sizeof tiny, home(), false, FormError::None), std::size_t{0});
    CHECK_EQ(render_received(tiny, sizeof tiny, home()), std::size_t{0});
}

GUARDIAN_CASE(gesture_opens_the_access_point_and_a_good_password_is_checked_then_saved) {
    Rig r;
    put(r.blob, creds("OldNet", "oldpassword", "http://192.168.1.10:8070")); r.prov.load();
    CHECK(r.enter(1000) == Refusal::None);
    CHECK(r.session.state() == State::Open); CHECK(r.session.active()); CHECK(r.session.visible());
    CHECK(r.port.up && !r.port.listening);
    CHECK_EQ(r.port.name, std::string("Guardian-51F4")); CHECK_EQ(r.port.pass.size(), ap_pass_len);
    CHECK_EQ(r.port.target_label, std::string("Casa <5G>")); CHECK(r.port.url_stored_seen);
    CHECK_EQ(r.session.opened(), 1u);
    r.session.tick(2000, false);
    CHECK(r.session.state() == State::Open);                    // nothing submitted yet
    r.port.submit("p=correct+horse+42%21");
    r.session.tick(3000, false);
    CHECK(r.session.state() == State::Checking);                // one step: the glass can say CHECKING first
    CHECK_EQ(r.port.count("join"), 0u); CHECK(r.session.active());
    r.session.tick(3100, false);
    CHECK(r.session.state() == State::Saved); CHECK(!r.session.active()); CHECK(r.session.visible());
    // Order: access point down, one join, listening again.
    const std::vector<std::string> want = {"open", "close", "join", "resume"};
    CHECK(r.port.calls == want); CHECK(!r.port.up_during_join); CHECK(r.port.listening);
    // Joined with the picked name, the typed password and the stored server.
    CHECK_EQ(r.port.joined_with.ssid_len, 9); CHECK(std::memcmp(r.port.joined_with.ssid.data(), "Casa <5G>", 9) == 0);
    CHECK_EQ(std::string(r.port.joined_with.pass.data()), std::string(kHomePass));
    // Stored: the same record the OTA/TUNE transport reads.
    ota::Credentials stored; CHECK(get(r.blob, stored));
    CHECK_EQ(stored.ssid_len, 9); CHECK_EQ(std::string(stored.pass.data()), std::string(kHomePass));
    CHECK_EQ(std::string(stored.url.data()), std::string("http://192.168.1.10:8070"));
    CHECK(r.prov.wifi_provisioned() && r.prov.provisioned());
    CHECK_EQ(std::string(r.prov.credentials().pass.data()), std::string(kHomePass));
    CHECK_EQ(r.session.saved(), 1u); CHECK(r.session.last() == End::Saved);
    // The result stays result_ms from the first tick AFTER the (long) join, then the face returns.
    r.session.tick(30000, false); CHECK(r.session.state() == State::Saved);
    r.session.tick(30000 + result_ms - 1, false); CHECK(r.session.state() == State::Saved);
    r.session.tick(30000 + result_ms, false); CHECK(r.session.state() == State::Idle);
    CHECK(!r.session.visible()); CHECK(r.session.last() == End::Saved);
    CHECK_EQ(r.port.count("resume"), 1u);
}

GUARDIAN_CASE(a_typed_server_replaces_the_stored_one_and_none_leaves_wifi_only) {
    Rig r;
    CHECK(r.enter(0, {}, Entry::TripleTap) == Refusal::None);
    CHECK(!r.port.url_stored_seen);
    r.port.submit("p=correct+horse+42%21");
    r.session.tick(10, false); r.session.tick(20, false);
    CHECK(r.session.state() == State::Saved);
    CHECK(r.prov.wifi_provisioned()); CHECK(!r.prov.provisioned());   // no server URL: UPDATE/TUNE not possible yet, and said so
    CHECK(!r.session.view(30).update_server);
    r.session.key(40); CHECK(r.session.state() == State::Idle);       // a key dismisses the result
    CHECK(r.enter(100) == Refusal::None);
    r.port.submit("p=correct+horse+42%21&u=http%3A%2F%2F10.0.0.7%3A8070");
    r.session.tick(110, false); r.session.tick(120, false);
    CHECK(r.session.state() == State::Saved); CHECK(r.prov.provisioned());
    CHECK_EQ(std::string(r.prov.credentials().url.data()), std::string("http://10.0.0.7:8070"));
    CHECK(r.session.view(130).update_server);
    CHECK_EQ(r.session.opened(), 2u); CHECK_EQ(r.session.saved(), 2u);
}

GUARDIAN_CASE(an_open_network_is_joined_without_a_password) {
    Rig r;
    CHECK(r.session.request(Entry::PickerHold, home(true), {}, kRandom, 0) == Refusal::None);
    r.port.submit("", true);
    r.session.tick(10, false); r.session.tick(20, false);
    CHECK(r.session.state() == State::Saved);
    CHECK_EQ(r.port.joined_with.pass_len, 0); CHECK(r.prov.wifi_provisioned());
}

GUARDIAN_CASE(access_point_closes_after_five_minutes_with_nothing_changed) {
    Rig r;
    put(r.blob, creds("OldNet", "oldpassword", "http://192.168.1.10:8070")); r.prov.load();
    const auto before = r.blob.bytes;
    CHECK(r.enter(1000) == Refusal::None);
    CHECK_EQ(r.session.view(1000).remaining_ms, open_ms);
    r.session.tick(1000 + open_ms - 1, false);
    CHECK(r.session.state() == State::Open); CHECK_EQ(r.session.view(1000 + open_ms - 1).remaining_ms, 1u);
    r.session.tick(1000 + open_ms, false);
    CHECK(r.session.state() == State::Idle); CHECK(r.session.last() == End::Timeout);
    const std::vector<std::string> want = {"open", "close", "resume"};
    CHECK(r.port.calls == want); CHECK(r.port.listening && !r.port.up);
    CHECK(r.blob.bytes == before); CHECK_EQ(r.blob.writes, 0u); CHECK_EQ(r.session.saved(), 0u);
    // A submission that arrives with the deadline is not used.
    Rig late; CHECK(late.enter(0) == Refusal::None);
    late.port.submit("p=correct+horse+42%21");
    late.session.tick(open_ms, false);
    CHECK(late.session.state() == State::Idle); CHECK_EQ(late.port.count("join"), 0u); CHECK(!late.prov.wifi_provisioned());
    // The clock wrapping during the five minutes changes nothing.
    Rig wrap; CHECK(wrap.enter(0xFFFFF000u) == Refusal::None);
    wrap.session.tick(0xFFFFF000u + open_ms - 1, false); CHECK(wrap.session.state() == State::Open);
    wrap.session.tick(0xFFFFF000u + open_ms, false); CHECK(wrap.session.state() == State::Idle);
}

GUARDIAN_CASE(any_key_cancels_an_open_session) {
    Rig r;
    CHECK(r.enter(0) == Refusal::None);
    r.port.submit("p=correct+horse+42%21");                     // typed on the phone, but the key comes first
    r.session.key(5000);
    CHECK(r.session.state() == State::Idle); CHECK(r.session.last() == End::Key);
    const std::vector<std::string> want = {"open", "close", "resume"};
    CHECK(r.port.calls == want); CHECK(r.port.listening);
    r.session.tick(5100, false);
    CHECK(r.session.state() == State::Idle); CHECK_EQ(r.port.count("join"), 0u); CHECK(!r.prov.wifi_provisioned());
    r.session.key(5200);                                        // a key with nothing open does nothing
    CHECK(r.port.calls == want);
}

GUARDIAN_CASE(never_opened_while_an_alert_is_shown_or_the_radio_is_busy) {
    Rig r;
    Facts alert; alert.alert = true;
    CHECK(r.enter(0, alert) == Refusal::Alert);
    CHECK(r.session.state() == State::Idle); CHECK(!r.session.visible());   // the ALERT keeps the glass
    CHECK(r.port.calls.empty()); CHECK(r.port.listening);
    Facts busy; busy.busy = true;
    CHECK(r.enter(10, busy) == Refusal::Busy);
    CHECK(r.session.state() == State::Idle); CHECK(r.port.calls.empty());
    CHECK_EQ(r.session.refused(), 2u); CHECK_EQ(r.session.opened(), 0u);
    // Without a named network there is nothing to ask a password for: a notice, no access point.
    CHECK(r.session.request(Entry::TripleTap, Target{}, {}, kRandom, 20) == Refusal::NoNetwork);
    CHECK(r.session.state() == State::Notice); CHECK(r.session.visible()); CHECK(!r.session.active());
    CHECK(r.port.calls.empty());
    r.session.tick(20 + notice_ms - 1, false); CHECK(r.session.state() == State::Notice);
    r.session.tick(20 + notice_ms, false); CHECK(r.session.state() == State::Idle);
    CHECK(r.session.request(Entry::TripleTap, Target{}, {}, kRandom, 9000) == Refusal::NoNetwork);
    r.session.tick(9100, true); CHECK(!r.session.visible());    // an ALERT takes the glass back at once
    // A second gesture while one is open changes nothing.
    CHECK(r.enter(10000) == Refusal::None);
    CHECK(r.enter(10100) == Refusal::Active);
    CHECK_EQ(r.port.count("open"), 1u); CHECK(r.session.state() == State::Open);
    // Should an ALERT ever show while the access point is up, it goes down at once.
    r.session.tick(10200, true);
    CHECK(r.session.state() == State::Idle); CHECK(r.session.last() == End::Alert);
    CHECK(r.port.listening && !r.port.up); CHECK(!r.prov.wifi_provisioned());
    // ... and a result screen never covers an ALERT.
    Rig s; CHECK(s.enter(0) == Refusal::None);
    s.port.submit("p=correct+horse+42%21"); s.session.tick(1, false); s.session.tick(2, false);
    CHECK(s.session.state() == State::Saved);
    s.session.tick(3, true); CHECK(!s.session.visible()); CHECK(s.session.last() == End::Saved);
}

GUARDIAN_CASE(a_password_that_does_not_join_is_not_stored) {
    struct Row { Join answer; End end; };
    for (const Row row : {Row{Join::Password, End::Password}, Row{Join::NotFound, End::NotFound}, Row{Join::Failed, End::JoinFailed}}) {
        Rig r;
        put(r.blob, creds("OldNet", "oldpassword", "http://192.168.1.10:8070")); r.prov.load();
        const auto before = r.blob.bytes;
        r.port.answer = row.answer;
        CHECK(r.enter(0) == Refusal::None);
        r.port.submit("p=wrong+password");
        r.session.tick(10, false); r.session.tick(20, false);
        CHECK(r.session.state() == State::Failed); CHECK(r.session.last() == row.end); CHECK(r.session.view(30).end == row.end);
        CHECK(r.blob.bytes == before); CHECK_EQ(r.blob.writes, 0u);
        CHECK_EQ(std::string(r.prov.credentials().pass.data()), std::string("oldpassword"));   // the old one still works
        CHECK(r.port.listening); CHECK_EQ(r.port.count("resume"), 1u); CHECK_EQ(r.session.saved(), 0u);
        r.session.tick(40, false); r.session.tick(40 + result_ms, false);
        CHECK(r.session.state() == State::Idle);
    }
    // The storage refusing the record is NOT SAVED too, and the old record stays in use.
    Rig r; put(r.blob, creds("OldNet", "oldpassword", "")); r.prov.load(); r.blob.fail_write = true;
    CHECK(r.enter(0) == Refusal::None);
    r.port.submit("p=correct+horse+42%21"); r.session.tick(10, false); r.session.tick(20, false);
    CHECK(r.session.state() == State::Failed); CHECK(r.session.last() == End::StoreFailed);
    CHECK_EQ(std::string(r.prov.credentials().pass.data()), std::string("oldpassword"));
    // The access point failing to start: listening resumes, nothing else happens.
    Rig ap; ap.port.open_ok = false;
    CHECK(ap.enter(0) == Refusal::None);
    CHECK(ap.session.state() == State::Failed); CHECK(ap.session.last() == End::AccessPoint); CHECK(!ap.session.active());
    const std::vector<std::string> want = {"open", "close", "resume"};
    CHECK(ap.port.calls == want); CHECK(ap.port.listening);
}

GUARDIAN_CASE(glass_texts_fit_and_say_what_happened_without_the_home_password) {
    Rig r;
    CHECK(r.enter(0) == Refusal::None);
    View open = r.session.view(1000);
    CHECK(open.state == State::Open); CHECK(fits(open));
    std::string text = all_text(open);
    CHECK(text.find("SETUP") != std::string::npos);
    CHECK(text.find("Guardian-51F4") != std::string::npos);     // what to join
    CHECK(text.find(r.port.pass) != std::string::npos);         // the access point's one-time password
    CHECK(text.find("192.168.4.1") != std::string::npos);
    CHECK(text.find("Casa <5G>") != std::string::npos);         // whose password the page asks
    CHECK(text.find("4:59") != std::string::npos);
    CHECK(text.find("cancel") != std::string::npos);
    r.port.submit("p=correct+horse+42%21");
    r.session.tick(2000, false);
    View checking = r.session.view(2000);
    CHECK(checking.state == State::Checking); CHECK(fits(checking));
    text = all_text(checking);
    CHECK(text.find("CHECKING") != std::string::npos && text.find("Casa <5G>") != std::string::npos);
    CHECK(text.find(r.port.pass) == std::string::npos);         // the access point is gone
    r.session.tick(2100, false);
    View saved = r.session.view(2200);
    CHECK(saved.state == State::Saved); CHECK(fits(saved));
    text = all_text(saved);
    CHECK(text.find("SAVED") != std::string::npos && text.find("NOT SAVED") == std::string::npos);
    CHECK(text.find("encrypted") != std::string::npos && text.find("NOT encrypted") == std::string::npos);
    CHECK(text.find("Listening again") != std::string::npos);   // passive listening is back, and said
    CHECK(text.find("No update server") != std::string::npos);
    saved.store = StoreKind::Plain; CHECK(fits(saved));
    CHECK(all_text(saved).find("NOT encrypted") != std::string::npos);   // never called encrypted when it is not
    saved.update_server = true; CHECK(fits(saved)); CHECK(all_text(saved).find("No update server") == std::string::npos);
    for (const View v : {open, checking, saved}) CHECK(all_text(v).find("horse") == std::string::npos);
    // Every failure names its reason and says nothing changed; the longest label still fits.
    const Target wide = target_of(reinterpret_cast<const std::uint8_t*>("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"), 32, false);
    for (const End e : {End::Password, End::NotFound, End::JoinFailed, End::StoreFailed, End::AccessPoint}) {
        View v; v.state = State::Failed; v.end = e; v.label = wide.label.data();
        CHECK(fits(v));
        const std::string t = all_text(v);
        CHECK(t.find("NOT SAVED") != std::string::npos && t.find("Nothing was changed") != std::string::npos);
    }
    View f; f.state = State::Failed; f.label = "x";
    f.end = End::Password; CHECK(all_text(f).find("Password not accepted") != std::string::npos);
    f.end = End::NotFound; CHECK(all_text(f).find("not in range") != std::string::npos);
    for (const State s : {State::Open, State::Checking, State::Saved}) {
        View v; v.state = s; v.label = wide.label.data(); v.ap_name = "Guardian-51F4"; v.ap_pass = "abcdefhjkm"; v.remaining_ms = open_ms; v.store = StoreKind::Plain;
        CHECK(fits(v));
        CHECK(all_text(v).find("WWWWWWWWWW") != std::string::npos);
    }
    View notice; notice.state = State::Notice; CHECK(fits(notice));
    CHECK(all_text(notice).find("network") != std::string::npos);
    // draw() paints the composed lines.
    std::vector<std::uint16_t> px(135 * 240, 0x1234);
    guardian::Canvas canvas(px.data(), 135, 240, false);
    draw(canvas, open);
    std::size_t black = 0, lit = 0; for (const auto p : px) { black += p == guardian::color::black; lit += p != guardian::color::black; }
    CHECK(black > 20000); CHECK(lit > 500);
}

GUARDIAN_CASE(status_fields_follow_the_session_and_never_hold_a_secret) {
    Rig r; char line[160];
    CHECK(r.session.status_text(line, sizeof line));
    CHECK_EQ(std::string(line), std::string(" setup=idle setup_count=0 setup_saved=0 setup_refused=0 setup_last=none"));
    Facts alert; alert.alert = true; r.enter(0, alert);
    CHECK(r.enter(10) == Refusal::None);
    CHECK(r.session.status_text(line, sizeof line));
    CHECK_EQ(std::string(line), std::string(" setup=open setup_count=1 setup_saved=0 setup_refused=1 setup_last=none"));
    CHECK(std::string(line).find(r.port.pass) == std::string::npos);   // not even the one-time password
    r.port.submit("p=correct+horse+42%21"); r.session.tick(20, false);
    CHECK(r.session.status_text(line, sizeof line)); CHECK(std::string(line).find(" setup=checking ") != std::string::npos);
    r.session.tick(30, false);
    CHECK(r.session.status_text(line, sizeof line));
    CHECK_EQ(std::string(line), std::string(" setup=saved setup_count=1 setup_saved=1 setup_refused=1 setup_last=saved"));
    CHECK(std::string(line).find("horse") == std::string::npos && std::string(line).find("Casa") == std::string::npos);
    r.session.key(40);
    CHECK(r.session.status_text(line, sizeof line));
    CHECK_EQ(std::string(line), std::string(" setup=idle setup_count=1 setup_saved=1 setup_refused=1 setup_last=saved"));
    char small[20]; CHECK(!r.session.status_text(small, sizeof small));
    for (const End e : {End::None, End::Saved, End::Timeout, End::Key, End::Alert, End::Password, End::NotFound, End::JoinFailed,
                        End::StoreFailed, End::AccessPoint})
        for (const char* p = end_text(e); *p; ++p) CHECK((*p >= 'a' && *p <= 'z') || *p == '_');
    CHECK_EQ(std::string(store_text(StoreKind::Encrypted)), std::string("encrypted"));
    CHECK_EQ(std::string(store_text(StoreKind::Plain)), std::string("plain"));
    CHECK_EQ(std::string(store_text(StoreKind::Error)), std::string("error"));
    CHECK_EQ(std::string(store_text(StoreKind::None)), std::string("none"));
}

GUARDIAN_CASE(the_session_keeps_no_copy_of_the_password_after_it_ends) {
    // The Session object is examined byte by byte: the typed password is gone
    // once the attempt ended, whatever the outcome.
    for (const Join answer : {Join::Joined, Join::Password}) {
        Rig r; r.port.answer = answer;
        CHECK(r.enter(0) == Refusal::None);
        r.port.submit("p=correct+horse+42%21"); r.session.tick(10, false);
        const auto* raw = reinterpret_cast<const char*>(&r.session);
        const std::string during(raw, sizeof r.session);
        CHECK(during.find(kHomePass) != std::string::npos);     // held only while CHECKING
        r.session.tick(20, false);
        const std::string after(raw, sizeof r.session);
        CHECK(after.find("horse") == std::string::npos);
    }
    Rig r; CHECK(r.enter(0) == Refusal::None);
    Form f; std::memcpy(f.pass.data(), "secretsecret", 12); f.pass_len = 12; std::memcpy(f.url.data(), "http://a", 8); f.has_url = true;
    f.wipe();
    CHECK_EQ(f.pass_len, 0); CHECK(!f.has_url);
    for (const char c : f.pass) CHECK_EQ(c, 0);
    for (const char c : f.url) CHECK_EQ(c, 0);
}

GUARDIAN_CASE(credential_goes_to_the_encrypted_vault_when_there_is_one) {
    const auto home_creds = creds("Casa", kHomePass, "http://192.168.1.10:8070");
    {   // No vault (old partition table or no key): the G16B record, said to be plain.
        MemoryBlob legacy; put(legacy, home_creds);
        const Choice c = choose_store(legacy, nullptr, VaultState::Absent);
        CHECK(c.storage == &legacy); CHECK(c.kind == StoreKind::Plain); CHECK(!c.migrated && !c.legacy_cleared);
        CHECK_EQ(legacy.writes, 0u);
    }
    {   // A ready, empty vault: the plain record moves in and the plain copy is overwritten.
        MemoryBlob legacy, vault; put(legacy, home_creds);
        const Choice c = choose_store(legacy, &vault, VaultState::Ready);
        CHECK(c.storage == &vault); CHECK(c.kind == StoreKind::Encrypted); CHECK(c.migrated && c.legacy_cleared);
        ota::Credentials moved; CHECK(get(vault, moved));
        CHECK_EQ(std::string(moved.pass.data()), std::string(kHomePass)); CHECK_EQ(std::string(moved.url.data()), std::string("http://192.168.1.10:8070"));
        CHECK(!legacy.holds("horse"));                          // the live plain record no longer holds it
        ota::Credentials left; CHECK(get(legacy, left)); CHECK(!left.wifi());
        ota::Provisioner prov(*c.storage); prov.load(); CHECK(prov.provisioned());
    }
    {   // The vault refusing the write: the plain record stays in use, untouched, and is called plain.
        MemoryBlob legacy, vault; put(legacy, home_creds); vault.fail_write = true;
        const auto before = legacy.bytes;
        const Choice c = choose_store(legacy, &vault, VaultState::Ready);
        CHECK(c.storage == &legacy); CHECK(c.kind == StoreKind::Plain); CHECK(!c.migrated && !c.legacy_cleared);
        CHECK(legacy.bytes == before); CHECK_EQ(legacy.writes, 0u);
    }
    {   // The vault already holds a credential: it wins, and a stale plain copy is overwritten.
        MemoryBlob legacy, vault; put(legacy, creds("Old", "oldpassword", "")); put(vault, home_creds);
        const auto before = vault.bytes;
        const Choice c = choose_store(legacy, &vault, VaultState::Ready);
        CHECK(c.storage == &vault); CHECK(c.kind == StoreKind::Encrypted); CHECK(!c.migrated && c.legacy_cleared);
        CHECK(vault.bytes == before); CHECK(!legacy.holds("oldpassword"));
    }
    {   // Nothing stored anywhere: the vault is used, nothing is written.
        MemoryBlob legacy, vault;
        const Choice c = choose_store(legacy, &vault, VaultState::Ready);
        CHECK(c.storage == &vault); CHECK(c.kind == StoreKind::Encrypted); CHECK(!c.migrated && !c.legacy_cleared);
        CHECK_EQ(legacy.writes + vault.writes, 0u);
    }
    {   // A cleared plain record (OTA CLEAR) is not a credential to move.
        MemoryBlob legacy, vault; put(legacy, ota::Credentials{});
        const Choice c = choose_store(legacy, &vault, VaultState::Ready);
        CHECK(c.kind == StoreKind::Encrypted); CHECK(!c.migrated && !c.legacy_cleared); CHECK_EQ(legacy.writes + vault.writes, 0u);
    }
    {   // A vault that exists but cannot be used: nothing is stored, never a silent fall back to plain text.
        MemoryBlob legacy; put(legacy, home_creds);
        const auto before = legacy.bytes;
        const Choice c = choose_store(legacy, nullptr, VaultState::Error);
        CHECK(c.kind == StoreKind::Error); CHECK(c.storage != nullptr && c.storage != &legacy);
        CHECK(legacy.bytes == before);
        ota::Provisioner prov(*c.storage); prov.load(); CHECK(!prov.wifi_provisioned());
        CHECK(!prov.store(home_creds));
        FakePort port; Session session(port, prov); session.set_identity(kMac); session.set_store(c.kind);
        CHECK(session.request(Entry::PickerHold, home(), {}, kRandom, 0) == Refusal::None);
        port.submit("p=correct+horse+42%21"); session.tick(10, false); session.tick(20, false);
        CHECK(session.state() == State::Failed); CHECK(session.last() == End::StoreFailed);
    }
}

GUARDIAN_CASE(provisioner_stores_a_phone_credential_and_the_usb_path_is_unchanged) {
    MemoryBlob blob; ota::Provisioner prov(blob); prov.load();
    CHECK(!prov.wifi_provisioned() && !prov.provisioned());
    CHECK(!prov.store(ota::Credentials{}));                     // a name is required
    CHECK_EQ(blob.writes, 0u);
    CHECK(prov.store(creds("Casa", kHomePass, "")));
    CHECK(prov.wifi_provisioned() && !prov.provisioned());
    char reply[160];
    CHECK(prov.command("OTA?", reply, sizeof reply));
    CHECK_EQ(std::string(reply), std::string("OTA provisioned=no staged_ssid=set staged_pass=set staged_url=unset\n"));
    CHECK(std::string(reply).find("horse") == std::string::npos);
    // The lab path completes it with the server only (name and password stay staged from the phone setup).
    CHECK(prov.command("OTA URL http://192.168.1.10:8070", reply, sizeof reply));
    CHECK(prov.command("OTA SAVE", reply, sizeof reply)); CHECK_EQ(std::string(reply), std::string("OTA SAVED provisioned=yes\n"));
    CHECK(prov.provisioned()); CHECK_EQ(std::string(prov.credentials().pass.data()), std::string(kHomePass));
    // A reload sees the same record; a refused write keeps the previous one.
    ota::Provisioner again(blob); again.load(); CHECK(again.provisioned());
    blob.fail_write = true;
    CHECK(!again.store(creds("Other", "otherpassword", "")));
    CHECK_EQ(std::string(again.credentials().pass.data()), std::string(kHomePass));
    blob.fail_write = false;
    CHECK(again.command("OTA CLEAR", reply, sizeof reply));
    CHECK(!again.wifi_provisioned()); CHECK(triple_tap(again.wifi_provisioned()) == Triple::Setup);
}

GUARDIAN_CASE(name_service_answers_every_address_question_with_the_page) {
    const std::uint8_t ip[4] = {192, 168, 4, 1};
    const auto query = [](const char* dotted, std::uint16_t type, std::uint16_t questions = 1) {
        std::vector<std::uint8_t> q = {0xAB, 0xCD, 0x01, 0x00, static_cast<std::uint8_t>(questions >> 8), static_cast<std::uint8_t>(questions), 0, 0, 0, 0, 0, 0};
        const std::string name(dotted); std::size_t at = 0;
        while (at <= name.size()) {
            auto dot = name.find('.', at); if (dot == std::string::npos) dot = name.size();
            q.push_back(static_cast<std::uint8_t>(dot - at)); q.insert(q.end(), name.begin() + static_cast<long>(at), name.begin() + static_cast<long>(dot));
            at = dot + 1;
        }
        q.push_back(0); q.push_back(static_cast<std::uint8_t>(type >> 8)); q.push_back(static_cast<std::uint8_t>(type)); q.push_back(0); q.push_back(1);
        return q;
    };
    std::uint8_t out[dns_max];
    const auto q = query("captive.apple.com", 1);
    const auto n = dns_answer(q.data(), q.size(), ip, out, sizeof out);
    CHECK_EQ(n, q.size() + 16);
    CHECK_EQ(out[0], 0xAB); CHECK_EQ(out[1], 0xCD);             // the same id
    CHECK_EQ(out[2] & 0x80, 0x80); CHECK_EQ(out[3] & 0x0F, 0);   // a response, no error
    CHECK_EQ(out[5], 1); CHECK_EQ(out[7], 1);                    // one question, one answer
    CHECK(std::memcmp(out + 12, q.data() + 12, q.size() - 12) == 0);   // the question echoed
    const std::uint8_t* a = out + q.size();
    CHECK_EQ(a[0], 0xC0); CHECK_EQ(a[1], 0x0C);                  // the name: a pointer to the question
    CHECK_EQ(a[3], 1); CHECK_EQ(a[5], 1); CHECK_EQ(a[11], 4);    // A, IN, 4 bytes
    CHECK(std::memcmp(a + 12, ip, 4) == 0);
    CHECK(a[6] == 0 && a[7] == 0 && a[8] == 0 && a[9] <= 60);    // a short life: the phone forgets it after setup
    // Another type (AAAA): the question echoed, no answer, no error.
    const auto v6 = query("connectivitycheck.gstatic.com", 28);
    const auto m = dns_answer(v6.data(), v6.size(), ip, out, sizeof out);
    CHECK_EQ(m, v6.size()); CHECK_EQ(out[7], 0); CHECK_EQ(out[3] & 0x0F, 0);
    // Refused without a reply: responses, several questions, cut or oversize datagrams, pointers, a short output.
    auto resp = q; resp[2] = 0x81;
    CHECK_EQ(dns_answer(resp.data(), resp.size(), ip, out, sizeof out), std::size_t{0});
    const auto two = query("a.b", 1, 2);
    CHECK_EQ(dns_answer(two.data(), two.size(), ip, out, sizeof out), std::size_t{0});
    for (std::size_t cut = 0; cut < q.size(); ++cut) CHECK_EQ(dns_answer(q.data(), cut, ip, out, sizeof out), std::size_t{0});
    auto pointer = q; pointer[12] = 0xC0;
    CHECK_EQ(dns_answer(pointer.data(), pointer.size(), ip, out, sizeof out), std::size_t{0});
    auto overrun = q; overrun[12] = 63;                          // a label longer than the datagram
    CHECK_EQ(dns_answer(overrun.data(), overrun.size(), ip, out, sizeof out), std::size_t{0});
    std::vector<std::uint8_t> big(dns_max + 1, 1);
    CHECK_EQ(dns_answer(big.data(), big.size(), ip, out, sizeof out), std::size_t{0});
    CHECK_EQ(dns_answer(q.data(), q.size(), ip, out, q.size() + 15), std::size_t{0});
    CHECK_EQ(dns_answer(nullptr, 20, ip, out, sizeof out), std::size_t{0});
    // Every byte pattern is safe (the sanitizer build watches the bounds).
    std::uint32_t seed = 7;
    for (int round = 0; round < 4000; ++round) {
        std::uint8_t fuzz[80]; const std::size_t len = 1 + (seed >> 8) % sizeof fuzz;
        for (auto& b : fuzz) { seed = seed * 1664525u + 1013904223u; b = static_cast<std::uint8_t>(seed >> 24); }
        if (round & 1) { fuzz[2] &= 0x07; fuzz[4] = 0; fuzz[5] = 1; }   // looks like a one-question query
        const auto r = dns_answer(fuzz, len, ip, out, sizeof out);
        CHECK(r == 0 || (r >= 17 && r <= len + 16));   // header + the shortest question; bytes after the question are dropped
    }
}

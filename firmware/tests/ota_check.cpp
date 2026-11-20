// G16B: OTA state machine over a fake transport and slot, boot record,
// rollback decision, owner gesture/confirmation and USB provisioning (host).
#include "check.hpp"
#include "ota.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace guardian::ota;

namespace {
std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef"; std::string s;
    for (std::size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
std::string sha_hex(const std::vector<std::uint8_t>& v) {
    Sha256 h; h.update(v.data(), v.size()); std::uint8_t out[32]; h.finish(out); return hex(out, 32);
}
std::string sha_hex(const char* s) { return sha_hex(std::vector<std::uint8_t>(s, s + std::strlen(s))); }

class MemoryBlob final : public BlobStorage {
public:
    std::vector<std::uint8_t> bytes; bool exists{}, fail_write{}; unsigned writes{};
    BlobRead read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const override {
        if (!exists) return BlobRead::Absent;
        if (bytes.size() > capacity) return BlobRead::Error;
        std::memcpy(out, bytes.data(), bytes.size()); size = bytes.size(); return BlobRead::Ok;
    }
    bool write(const std::uint8_t* data, std::size_t size) override {
        ++writes; if (fail_write) return false; bytes.assign(data, data + size); exists = true; return true;
    }
};

// G22A: build versions are date-time stamps; the rig's stick runs kRunning and is offered kOffered.
const char* kRunning = "guardian-20261116-120000";
const char* kOffered = "guardian-20261116-120001";
// An image with an ESP-IDF app descriptor (magic at 32, version at 48..79) carrying `version`.
std::vector<std::uint8_t> image(std::size_t n, const char* version = kOffered) {
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::uint8_t>((i * 131u + 7u) & 0xFF);
    if (version && n >= 80) {
        v[0] = 0xE9; v[32] = 0x32; v[33] = 0x54; v[34] = 0xCD; v[35] = 0xAB;
        for (std::size_t i = 48; i < 80; ++i) v[i] = 0;
        std::memcpy(v.data() + 48, version, std::min<std::size_t>(std::strlen(version), 31));
    }
    return v;
}
std::string manifest_for(const std::vector<std::uint8_t>& img, const char* version = kOffered) {
    char m[400];
    std::snprintf(m, sizeof m, "GUARDIAN-OTA 1\nversion=%s\nsize=%zu\nsha256=%s\nsignature=rsa3072-sbv2\nend\n",
                  version, img.size(), sha_hex(img).c_str());
    return m;
}

// Fake HTTP server + Wi-Fi.
class FakeTransport final : public Transport {
public:
    std::string manifest; std::vector<std::uint8_t> body;
    bool join_ok{true}, manifest_ok{true}, image_ok{true};
    std::int32_t content_length_override{-2};   // -2: use the real size
    long fail_after{-1};                         // network error after this many image bytes
    std::size_t truncate_to{0};                  // >0: body ends early
    std::size_t chunk{700};
    unsigned joins{}, leaves{}, opens{}, closes{}, image_opens{};
    bool joined{};
    std::string current; std::size_t at{};
    bool join() override { ++joins; joined = join_ok; return join_ok; }
    void leave() override { ++leaves; joined = false; }
    bool open(const char* path, std::int32_t& length) override {
        // opens counts only successful opens: a failed open() cleans up after
        // itself in the adapter and is never followed by close().
        current = path; at = 0;
        if (!joined) return false;
        if (current == "manifest") { if (!manifest_ok) return false; length = static_cast<std::int32_t>(manifest.size()); ++opens; return true; }
        if (current == "image") {
            ++image_opens;   // every request for the image, served or not
            if (!image_ok) return false;
            length = content_length_override != -2 ? content_length_override : static_cast<std::int32_t>(body.size());
            ++opens; return true;
        }
        return false;
    }
    int read(std::uint8_t* out, std::size_t capacity) override {
        const std::vector<std::uint8_t> m(manifest.begin(), manifest.end());
        const auto& src = current == "manifest" ? m : body;
        std::size_t end = src.size();
        if (current == "image" && truncate_to) end = truncate_to;
        if (current == "image" && fail_after >= 0 && at >= static_cast<std::size_t>(fail_after)) return -1;
        if (at >= end) return 0;
        std::size_t n = std::min({capacity, chunk, end - at});
        if (current == "image" && fail_after >= 0) n = std::min(n, static_cast<std::size_t>(fail_after) - at);
        std::memcpy(out, src.data() + at, n); at += n; return static_cast<int>(n);
    }
    void close() override { ++closes; }
};

class FakeSlot final : public Slot {
public:
    std::uint32_t cap{3u * 1024u * 1024u};
    bool begin_ok{true}, write_ok{true}, activate_ok{true};
    Finish finish_result{Finish::Ok};
    std::vector<std::uint8_t> written;
    bool begun{}, finished{}, aborted{}, activated{};
    std::uint32_t declared{};
    std::uint32_t capacity() const override { return cap; }
    bool begin(std::uint32_t size) override { declared = size; begun = begin_ok; return begin_ok; }
    bool write(const std::uint8_t* d, std::size_t n) override { if (!write_ok) return false; written.insert(written.end(), d, d + n); return true; }
    void abort() override { aborted = true; }
    Finish finish() override { finished = true; return finish_result; }
    bool activate() override { activated = activate_ok; return activate_ok; }
};

class Recorder final : public Observer {
public:
    std::vector<Phase> phases; std::uint32_t last_done{}, last_total{};
    void phase(Phase p, std::uint32_t done, std::uint32_t total) override {
        if (phases.empty() || phases.back() != p) phases.push_back(p);
        last_done = done; last_total = total;
    }
};

struct Rig {
    std::vector<std::uint8_t> img = image(10000);
    FakeTransport net; FakeSlot slot; Recorder seen;
    Rig() { net.body = img; net.manifest = manifest_for(img); }
    const char* running = kRunning;
    Outcome go() { return run(net, slot, running, &seen); }
    // Serves an image whose own descriptor says `inside` under a manifest that says `listed`.
    void serve(const char* listed, const char* inside) { img = image(10000, inside); net.body = img; net.manifest = manifest_for(img, listed); }
};
// After any attempt: the network was left, and an unfinished slot session was aborted.
void cleanup_invariants(guardian::check::Case& c_, const Rig& r) {
    auto& c = c_;
    c.expect_eq(r.net.leaves, r.net.joins, "leaves", "joins", __FILE__, __LINE__);
    c.expect_eq(r.net.closes, r.net.opens, "closes", "opens", __FILE__, __LINE__);
    if (r.slot.begun && !r.slot.finished) c.expect(r.slot.aborted, "aborted unfinished slot", __FILE__, __LINE__);
}
} // namespace

GUARDIAN_CASE(sha256_matches_fips_vectors) {
    CHECK_EQ(sha_hex(""), std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(sha_hex("abc"), std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(sha_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
             std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    // one million 'a', fed in odd-sized pieces across block boundaries
    Sha256 h; std::vector<std::uint8_t> a(997, 'a'); std::size_t left = 1000000;
    while (left) { const auto n = std::min(left, a.size()); h.update(a.data(), n); left -= n; }
    std::uint8_t out[32]; h.finish(out);
    CHECK_EQ(hex(out, 32), std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

GUARDIAN_CASE(manifest_parses_only_complete_well_formed_text) {
    const auto img = image(1234);
    Manifest m; const auto text = manifest_for(img, "g16b-20261116-1");
    CHECK_EQ(parse_manifest(text.data(), text.size(), m), ManifestError::None);
    CHECK_EQ(std::string(m.version.data()), std::string("g16b-20261116-1"));
    CHECK_EQ(m.size, 1234u);
    CHECK_EQ(hex(m.sha256.data(), 32), sha_hex(img));
    const auto bad = [&](const std::string& t) { Manifest x; x.size = 77; const auto e = parse_manifest(t.data(), t.size(), x); return std::make_pair(e, x.size); };
    const std::string h = "GUARDIAN-OTA 1\n", sha = "sha256=" + sha_hex(img) + "\n";
    CHECK_EQ(bad("GUARDIAN-OTA 2\nversion=a\nsize=1\n" + sha + "signature=rsa3072-sbv2\nend\n").first, ManifestError::Header);
    CHECK_EQ(bad(h + "version=a\nsize=1\n" + sha + "signature=rsa3072-sbv2\n").first, ManifestError::End);
    CHECK_EQ(bad(h + "version=a\nsize=1\n" + sha + "end\n").first, ManifestError::Missing);
    CHECK_EQ(bad(h + "version=a\nversion=b\nsize=1\n" + sha + "signature=rsa3072-sbv2\nend\n").first, ManifestError::Duplicate);
    CHECK_EQ(bad(h + "version=has space\nsize=1\n" + sha + "signature=rsa3072-sbv2\nend\n").first, ManifestError::Version);
    CHECK_EQ(bad(h + "version=\nsize=1\n" + sha + "signature=rsa3072-sbv2\nend\n").first, ManifestError::Version);
    CHECK_EQ(bad(h + "version=a\nsize=0\n" + sha + "signature=rsa3072-sbv2\nend\n").first, ManifestError::Size);
    CHECK_EQ(bad(h + "version=a\nsize=12x\n" + sha + "signature=rsa3072-sbv2\nend\n").first, ManifestError::Size);
    CHECK_EQ(bad(h + "version=a\nsize=99999999999\n" + sha + "signature=rsa3072-sbv2\nend\n").first, ManifestError::Size);
    CHECK_EQ(bad(h + "version=a\nsize=1\nsha256=ABCD\nsignature=rsa3072-sbv2\nend\n").first, ManifestError::Hash);
    CHECK_EQ(bad(h + "version=a\nsize=1\n" + sha + "signature=none\nend\n").first, ManifestError::Scheme);
    CHECK_EQ(bad(h + "version=a\nsize=1\n" + sha + "colour=red\nsignature=rsa3072-sbv2\nend\n").first, ManifestError::Field);
    CHECK_EQ(bad(h + "version=a\nsize=1\n" + sha + "signature=rsa3072-sbv2\nend\n").second, 1u);   // control: valid
    CHECK_EQ(bad(h + "version=a\nsize=0\n" + sha + "signature=rsa3072-sbv2\nend\n").second, 77u);  // untouched on failure
    CHECK(std::strlen(manifest_error_text(ManifestError::Hash)) > 0);
}

GUARDIAN_CASE(good_image_is_written_verified_and_switched) {
    Rig r; const auto o = r.go();
    CHECK_EQ(o.reason, Reason::None);
    CHECK_EQ(o.received, 10000u);
    CHECK(r.slot.written == r.img);
    CHECK_EQ(r.slot.declared, 10000u);
    CHECK(r.slot.finished); CHECK(r.slot.activated); CHECK(!r.slot.aborted);
    CHECK_EQ(std::string(o.manifest.version.data()), std::string(kOffered));
    const std::vector<Phase> want{Phase::Joining, Phase::Manifest, Phase::Download, Phase::Verify, Phase::Switch};
    CHECK(r.seen.phases == want);
    cleanup_invariants(c_, r);
}

GUARDIAN_CASE(bad_signature_is_refused_before_the_slot_switch) {
    Rig r; r.slot.finish_result = Finish::SignatureInvalid;
    const auto o = r.go();
    CHECK_EQ(o.reason, Reason::SignatureInvalid);
    CHECK(!r.slot.activated);
    cleanup_invariants(c_, r);
    Rig q; q.slot.finish_result = Finish::ImageInvalid;
    CHECK_EQ(q.go().reason, Reason::ImageInvalid); CHECK(!q.slot.activated);
}

GUARDIAN_CASE(wrong_sha256_is_refused_and_never_validated_or_switched) {
    Rig r; r.net.body[5000] ^= 0x01;   // one flipped bit in transit
    const auto o = r.go();
    CHECK_EQ(o.reason, Reason::ShaMismatch);
    CHECK(!r.slot.finished); CHECK(r.slot.aborted); CHECK(!r.slot.activated);
    cleanup_invariants(c_, r);
}

GUARDIAN_CASE(truncated_and_oversized_downloads_are_refused) {
    Rig r; r.net.truncate_to = 9000; r.net.content_length_override = -1;
    CHECK_EQ(r.go().reason, Reason::Truncated);
    CHECK(r.slot.aborted); CHECK(!r.slot.activated); cleanup_invariants(c_, r);
    Rig o; o.net.body.push_back(0x55); o.net.content_length_override = -1;   // server sends one byte too many
    CHECK_EQ(o.go().reason, Reason::Oversize);
    CHECK(o.slot.aborted); CHECK(!o.slot.activated); cleanup_invariants(c_, o);
    Rig l; l.net.content_length_override = 9999;                             // header disagrees with the manifest
    CHECK_EQ(l.go().reason, Reason::LengthMismatch);
    CHECK(!l.slot.begun); CHECK(!l.slot.activated); cleanup_invariants(c_, l);
}

GUARDIAN_CASE(network_failures_leave_the_running_image_alone) {
    Rig j; j.net.join_ok = false;
    CHECK_EQ(j.go().reason, Reason::JoinFailed); CHECK(!j.slot.begun); cleanup_invariants(c_, j);
    Rig m; m.net.manifest_ok = false;
    CHECK_EQ(m.go().reason, Reason::ManifestFetch); CHECK(!m.slot.begun); cleanup_invariants(c_, m);
    Rig g; g.net.manifest = "garbage\n";
    CHECK_EQ(g.go().reason, Reason::ManifestInvalid); CHECK(!g.slot.begun); cleanup_invariants(c_, g);
    Rig i; i.net.image_ok = false;
    CHECK_EQ(i.go().reason, Reason::Download); CHECK(!i.slot.begun); cleanup_invariants(c_, i);
    Rig d; d.net.fail_after = 4096;
    const auto o = d.go();
    CHECK_EQ(o.reason, Reason::Download); CHECK_EQ(o.received, 4096u);
    CHECK(d.slot.aborted); CHECK(!d.slot.activated); cleanup_invariants(c_, d);
}

GUARDIAN_CASE(slot_limits_and_flash_errors_are_reported) {
    Rig t; t.slot.cap = 9999;
    CHECK_EQ(t.go().reason, Reason::TooLarge); CHECK(!t.slot.begun); cleanup_invariants(c_, t);
    Rig n; n.slot.cap = 0;
    CHECK_EQ(n.go().reason, Reason::NoSlot); cleanup_invariants(c_, n);
    Rig b; b.slot.begin_ok = false;
    CHECK_EQ(b.go().reason, Reason::NoSlot); CHECK(!b.slot.aborted); cleanup_invariants(c_, b);
    Rig w; w.slot.write_ok = false;
    CHECK_EQ(w.go().reason, Reason::WriteFailed); CHECK(w.slot.aborted); cleanup_invariants(c_, w);
    Rig f; f.slot.finish_result = Finish::Failed;
    CHECK_EQ(f.go().reason, Reason::ImageInvalid); CHECK(!f.slot.activated);
    Rig s; s.slot.activate_ok = false;
    CHECK_EQ(s.go().reason, Reason::SwitchFailed); cleanup_invariants(c_, s);
}

GUARDIAN_CASE(download_progress_is_reported_against_the_manifest_size) {
    Rig r; r.go();
    CHECK_EQ(r.seen.last_total, 0u);   // the Switch phase has no byte count
    Rig p; p.slot.activate_ok = false;
    struct Last final : Observer { std::uint32_t done{}, total{}; unsigned downloads{};
        void phase(Phase ph, std::uint32_t d, std::uint32_t t) override { if (ph == Phase::Download) { done = d; total = t; ++downloads; } } } last;
    run(p.net, p.slot, kRunning, &last);
    CHECK_EQ(last.done, 10000u); CHECK_EQ(last.total, 10000u); CHECK(last.downloads > 1);
}

GUARDIAN_CASE(boot_record_round_trips_and_rejects_corruption) {
    Record r; r.state = State::Pending; r.reason = Reason::None; r.from_slot = 0; r.target_slot = 1;
    std::snprintf(r.version.data(), r.version.size(), "%s", "g16b-abc");
    std::uint8_t buf[record_bytes]; CHECK_EQ(encode(r, buf, sizeof buf), record_bytes);
    CHECK_EQ(encode(r, buf, sizeof buf - 1), 0u);
    Record back; CHECK(decode(buf, sizeof buf, back));
    CHECK_EQ(back.state, State::Pending); CHECK_EQ(back.target_slot, 1); CHECK_EQ(std::string(back.version.data()), std::string("g16b-abc"));
    for (std::size_t i = 0; i < sizeof buf; ++i) {   // any single flipped byte is refused
        std::uint8_t copy[record_bytes]; std::memcpy(copy, buf, sizeof buf); copy[i] ^= 0x40;
        Record x; x.from_slot = 9; CHECK(!decode(copy, sizeof copy, x)); CHECK_EQ(x.from_slot, 9);
    }
    CHECK(!decode(buf, sizeof buf - 1, back));
    MemoryBlob blob; Record none; CHECK(!load(blob, none));
    CHECK(save(blob, r)); Record loaded; CHECK(load(blob, loaded)); CHECK_EQ(loaded.state, State::Pending);
    blob.bytes[3] ^= 1; Record kept; kept.target_slot = 7; CHECK(!load(blob, kept)); CHECK_EQ(kept.target_slot, 7);
    CHECK_EQ(blob.writes, 1u);   // a corrupt record is never rewritten by load()
}

GUARDIAN_CASE(result_text_names_every_outcome) {
    char t[64]; Record r;
    result_text(r, t, sizeof t); CHECK_EQ(std::string(t), std::string("none"));
    std::snprintf(r.version.data(), r.version.size(), "%s", "v7");
    r.state = State::Pending; result_text(r, t, sizeof t); CHECK_EQ(std::string(t), std::string("pending:v7"));
    r.state = State::Succeeded; result_text(r, t, sizeof t); CHECK_EQ(std::string(t), std::string("ok:v7"));
    r.state = State::Failed; r.reason = Reason::SignatureInvalid; result_text(r, t, sizeof t); CHECK_EQ(std::string(t), std::string("failed:signature"));
    r.state = State::RolledBack; r.reason = Reason::SelfTest; result_text(r, t, sizeof t); CHECK_EQ(std::string(t), std::string("rolled_back:selftest"));
    for (int i = 0; i <= static_cast<int>(Reason::NotNewer); ++i) {
        const auto why = static_cast<Reason>(i);
        const std::string token = reason_text(why), line = reason_line(why);
        CHECK(!token.empty()); CHECK(token.find(' ') == std::string::npos);
        CHECK(!line.empty()); CHECK(line.size() <= 22);   // one 1x row on the 135 px portrait
    }
}

GUARDIAN_CASE(new_image_marks_valid_only_after_the_self_test) {
    SelfTest ok; ok.display = ok.store = ok.radio = true;
    CHECK(ok.passed());
    SelfTest no_imu = ok; no_imu.imu = false; CHECK(no_imu.passed());   // IMU optional
    Record r; r.state = State::Pending; r.from_slot = 0; r.target_slot = 1;
    auto d = decide_boot(r, {1, true}, ok);
    CHECK_EQ(d.action, BootAction::MarkValid); CHECK(d.changed); CHECK_EQ(r.state, State::Succeeded);
    // the next boot of the same image: nothing more to do
    d = decide_boot(r, {1, false}, ok);
    CHECK_EQ(d.action, BootAction::None); CHECK(!d.changed);
}

GUARDIAN_CASE(self_test_failure_rolls_back_and_says_why) {
    for (int failing = 0; failing < 4; ++failing) {
        SelfTest t; t.display = failing != 0; t.store = failing != 1; t.radio = failing != 2; t.forced_fail = failing == 3; t.imu = true;
        CHECK(!t.passed());
        Record r; r.state = State::Pending; r.from_slot = 0; r.target_slot = 1;
        const auto d = decide_boot(r, {1, true}, t);
        CHECK_EQ(d.action, BootAction::Rollback); CHECK(d.changed);
        CHECK_EQ(r.state, State::RolledBack); CHECK_EQ(r.reason, Reason::SelfTest);
        // after the bootloader returned to slot 0 the record is already final
        const auto after = decide_boot(r, {0, false}, SelfTest{true, true, true});
        CHECK_EQ(after.action, BootAction::None); CHECK(!after.changed); CHECK_EQ(r.state, State::RolledBack);
    }
}

GUARDIAN_CASE(crash_before_self_test_is_reported_as_bootloader_rollback) {
    Record r; r.state = State::Pending; r.from_slot = 0; r.target_slot = 1;
    // the new image reset before validating: the bootloader booted the old slot
    const auto d = decide_boot(r, {0, false}, SelfTest{true, true, true});
    CHECK_EQ(d.action, BootAction::None); CHECK(d.changed);
    CHECK_EQ(r.state, State::RolledBack); CHECK_EQ(r.reason, Reason::CrashBeforeSelfTest);
    // a pending-verify image without a record (e.g. flashed by USB as a
    // probation image) still validates itself only after a passing self-test
    Record none; const auto u = decide_boot(none, {1, true}, SelfTest{true, true, true});
    CHECK_EQ(u.action, BootAction::MarkValid);
    Record none2; const auto f = decide_boot(none2, {1, true}, SelfTest{true, false, true});
    CHECK_EQ(f.action, BootAction::Rollback);
    // ordinary boots never touch a final record
    Record ok; ok.state = State::Failed; ok.reason = Reason::JoinFailed;
    CHECK(!decide_boot(ok, {0, false}, SelfTest{}).changed); CHECK_EQ(ok.state, State::Failed);
}

GUARDIAN_CASE(both_keys_for_three_seconds_arm_update_once) {
    Gesture g;
    CHECK(!g.sample(true, false, 0)); CHECK(!g.involved());          // one key alone: ordinary
    CHECK(!g.sample(true, true, 100)); CHECK(g.involved());
    CHECK(!g.sample(true, true, 3099));
    CHECK(g.sample(true, true, 3100));                                 // 3 s of both
    CHECK(!g.sample(true, true, 9000));                                // once per hold
    CHECK(!g.sample(true, false, 9100)); CHECK(g.involved());         // still suppressing until both are up
    CHECK(!g.sample(false, false, 9200)); CHECK(!g.involved());
    // a release in between restarts the hold
    CHECK(!g.sample(true, true, 10000)); CHECK(!g.sample(true, false, 12000));
    CHECK(!g.sample(true, true, 12100)); CHECK(!g.sample(true, true, 15000));
    CHECK(g.sample(true, true, 15100));
}

// Owner request (2026-11-16): one-handed use, so a single key pressed three
// times fast also arms UPDATE. The first tap acts normally; a quick second tap
// is held back; a third fires the gesture; a held tap is delivered late if no
// third tap follows within the window.
GUARDIAN_CASE(triple_tap_of_one_key_arms_update) {
    TripleTap t;
    CHECK(t.tap(1000) == TripleTap::Tap::Deliver);                     // first tap: ordinary action
    CHECK(t.tap(1000 + TripleTap::gap_ms) == TripleTap::Tap::Hold);    // quick second: held back
    CHECK(!t.expire(1000 + TripleTap::gap_ms + 10));
    CHECK(t.tap(1000 + 2 * TripleTap::gap_ms) == TripleTap::Tap::Fire); // quick third: arm UPDATE
    CHECK(!t.expire(99999));                                           // nothing left held
    // a slow sequence never fires
    CHECK(t.tap(20000) == TripleTap::Tap::Deliver);
    CHECK(t.tap(20000 + TripleTap::gap_ms + 1) == TripleTap::Tap::Deliver);
    CHECK(t.tap(20000 + 2 * TripleTap::gap_ms + 1) == TripleTap::Tap::Hold);   // quick after the 2nd
    // ...and a held tap without a third is delivered once the window passes
    CHECK(!t.expire(20000 + 3 * TripleTap::gap_ms + 1));
    CHECK(t.expire(20000 + 3 * TripleTap::gap_ms + 2));
    CHECK(!t.expire(20000 + 3 * TripleTap::gap_ms + 3));
    // after a fire the count restarts
    CHECK(t.tap(40000) == TripleTap::Tap::Deliver);
    CHECK(t.tap(40100) == TripleTap::Tap::Hold);
    CHECK(t.tap(40200) == TripleTap::Tap::Fire);
    CHECK(t.tap(40300) == TripleTap::Tap::Deliver);
}

GUARDIAN_CASE(confirmation_ignores_a_yes_from_the_same_tap_burst) {
    Confirmation c;
    c.open(1000);
    CHECK_EQ(c.sample(true, false, 1000 + Confirmation::arm_ms - 1), Answer::Pending);   // a 4th fast tap is not a yes
    CHECK(c.is_open());
    CHECK_EQ(c.sample(true, false, 1000 + Confirmation::arm_ms), Answer::Yes);
    c.open(0); CHECK_EQ(c.sample(false, true, 1), Answer::No);          // no is always accepted
}

GUARDIAN_CASE(confirmation_needs_an_explicit_yes) {
    Confirmation c; CHECK(!c.is_open());
    CHECK_EQ(c.sample(true, false, 0), Answer::Pending);               // closed: ignores keys
    c.open(1000); CHECK(c.is_open()); CHECK_EQ(c.remaining_ms(1000), Confirmation::confirm_ms);
    CHECK_EQ(c.sample(false, false, 2000), Answer::Pending);
    CHECK_EQ(c.sample(true, false, 2100), Answer::Yes); CHECK(!c.is_open());
    c.open(0); CHECK_EQ(c.sample(false, true, 10), Answer::No); CHECK(!c.is_open());
    c.open(0); CHECK_EQ(c.sample(true, true, 10), Answer::No);          // ambiguous: no
    c.open(0); CHECK_EQ(c.sample(false, false, Confirmation::confirm_ms), Answer::No);   // timeout: no
    CHECK_EQ(c.remaining_ms(99999), 0u);
}

GUARDIAN_CASE(provisioning_stores_credentials_and_never_echoes_them) {
    MemoryBlob blob; Provisioner p(blob); p.load();
    CHECK(!p.provisioned());
    char out[200];
    CHECK(!p.command("STATUS", out, sizeof out));
    CHECK(!p.command("OTAX", out, sizeof out));
    // "MyLab 5G" / "hunter2hunter2" / server URL
    CHECK(p.command("OTA SSID 4d794c6162203547", out, sizeof out)); CHECK(std::string(out).find("OTA ERROR") == std::string::npos);
    CHECK(std::string(out).find("MyLab") == std::string::npos); CHECK(std::string(out).find("4d794c") == std::string::npos);
    CHECK(p.command("OTA PASS 68756e74657232068756e746572", out, sizeof out)); CHECK(std::string(out).find("OTA ERROR") == 0);   // odd hex
    CHECK(p.command("OTA PASS 68756e74657232", out, sizeof out)); CHECK(std::string(out).find("OTA ERROR") == 0);   // 7 bytes: WPA2 needs 8..63
    CHECK(p.command("OTA PASS 68756e7465723268756e74657232", out, sizeof out)); CHECK(std::string(out).find("OTA ERROR") == std::string::npos);
    CHECK(std::string(out).find("hunter") == std::string::npos);
    CHECK(p.command("OTA URL ftp://10.0.0.2/", out, sizeof out)); CHECK(std::string(out).find("OTA ERROR") == 0);
    CHECK(p.command("OTA SAVE", out, sizeof out)); CHECK(std::string(out).find("OTA ERROR") == 0);   // URL missing
    CHECK_EQ(blob.writes, 0u);
    CHECK(p.command("OTA URL http://192.168.1.20:8070/guardian", out, sizeof out)); CHECK(std::string(out).find("OTA ERROR") == std::string::npos);
    CHECK(std::string(out).find("192.168") == std::string::npos);
    CHECK(p.command("OTA SAVE", out, sizeof out)); CHECK(std::string(out).find("OTA SAVED") == 0);
    CHECK(p.provisioned()); CHECK_EQ(blob.writes, 1u);
    CHECK_EQ(p.credentials().ssid_len, 8); CHECK_EQ(std::string(p.credentials().pass.data()), std::string("hunter2hunter2"));
    CHECK_EQ(std::string(p.credentials().url.data()), std::string("http://192.168.1.20:8070/guardian"));
    CHECK(p.command("OTA?", out, sizeof out));
    const std::string q = out;
    CHECK(q.find("provisioned=yes") != std::string::npos);
    CHECK(q.find("hunter") == std::string::npos); CHECK(q.find("MyLab") == std::string::npos); CHECK(q.find("192.168") == std::string::npos);
    // a fresh boot restores it
    Provisioner again(blob); again.load(); CHECK(again.provisioned());
    CHECK_EQ(std::string(again.credentials().pass.data()), std::string("hunter2hunter2"));
    // open network ("-") and CLEAR
    CHECK(again.command("OTA PASS -", out, sizeof out)); CHECK(std::string(out).find("OTA ERROR") == std::string::npos);
    CHECK(again.command("OTA CLEAR", out, sizeof out)); CHECK(!again.provisioned());
    Provisioner third(blob); third.load(); CHECK(!third.provisioned());
    // corrupt storage: not provisioned, never rewritten by load
    blob.bytes[10] ^= 1; const auto w = blob.writes; Provisioner fourth(blob); fourth.load();
    CHECK(!fourth.provisioned()); CHECK_EQ(blob.writes, w);
    // failed write: not provisioned, reported
    MemoryBlob broken; broken.fail_write = true; Provisioner b(broken);
    b.command("OTA SSID 41", out, sizeof out); b.command("OTA PASS -", out, sizeof out); b.command("OTA URL http://10.0.0.2/", out, sizeof out);
    CHECK(b.command("OTA SAVE", out, sizeof out)); CHECK(std::string(out).find("OTA ERROR") == 0); CHECK(!b.provisioned());
}

GUARDIAN_CASE(url_validation_is_strict) {
    CHECK(valid_url("http://192.168.1.20:8070/"));
    CHECK(valid_url("http://mac.local:8070"));
    CHECK(!valid_url("https://x/"));          // the device does not hold a CA bundle; integrity is the signature
    CHECK(!valid_url("http://"));
    CHECK(!valid_url("http://a b/"));
    CHECK(!valid_url("http://a/\x7f"));
    std::string long_url = "http://" + std::string(200, 'a'); CHECK(!valid_url(long_url.c_str()));
}

GUARDIAN_CASE(credentials_codec_round_trips) {
    Credentials c; c.ssid_len = 3; c.ssid[0] = 'a'; c.ssid[1] = 0; c.ssid[2] = 'z';   // SSIDs are bytes
    std::snprintf(c.url.data(), c.url.size(), "%s", "http://10.0.0.2/");
    std::uint8_t buf[credentials_bytes]; CHECK_EQ(encode(c, buf, sizeof buf), credentials_bytes);
    Credentials back; CHECK(decode(buf, sizeof buf, back));
    CHECK_EQ(back.ssid_len, 3); CHECK_EQ(back.ssid[1], 0); CHECK_EQ(back.ssid[2], 'z'); CHECK_EQ(back.pass_len, 0);
    buf[sizeof buf - 1] ^= 1; Credentials x; CHECK(!decode(buf, sizeof buf, x));
}

GUARDIAN_CASE(update_screens_fit_the_portrait_and_say_what_happens) {
    const char* long_version = "g16b-20261116-201500-selftest-f";   // 31 chars, the manifest maximum
    std::vector<View> views;
    View confirm; confirm.stage = Stage::Confirm; confirm.remaining_ms = 11001; confirm.running_version = long_version; views.push_back(confirm);
    for (int p = 0; p <= static_cast<int>(Phase::Switch); ++p) {
        View w; w.stage = Stage::Working; w.phase = static_cast<Phase>(p); w.done = 450000; w.total = 1000000;
        w.running_version = "g16b-a"; w.new_version = long_version; views.push_back(w);
    }
    View done; done.stage = Stage::Installed; done.new_version = long_version; views.push_back(done);
    for (int r = 1; r <= static_cast<int>(Reason::NotNewer); ++r) {
        View f; f.stage = Stage::Failed; f.reason = static_cast<Reason>(r); views.push_back(f);
    }
    for (const auto& v : views) {
        Screen s; compose(v, s);
        CHECK(s.count >= 3); CHECK_EQ(s.overflow, 0);
        for (std::uint8_t i = 0; i < s.count; ++i) {
            const auto& l = s.lines[i];
            CHECK(std::strlen(l.text.data()) <= (l.scale == 2 ? 11u : 22u));
            CHECK(l.y >= 0); CHECK(l.y + 7 * l.scale <= 240);
        }
    }
    const auto joined = [](const View& v) { Screen s; compose(v, s); std::string all; for (std::uint8_t i = 0; i < s.count; ++i) { all += s.lines[i].text.data(); all += '\n'; } return all; };
    const auto c = joined(confirm);
    CHECK(c.find("FRONT") != std::string::npos); CHECK(c.find("SIDE") != std::string::npos); CHECK(c.find("12 s") != std::string::npos);
    std::string flat; for (char ch : c) if (ch != '\n') flat += ch;
    CHECK(flat.find(long_version) != std::string::npos);   // a long version wraps, never cut
    View dl; dl.stage = Stage::Working; dl.phase = Phase::Download; dl.done = 450000; dl.total = 1000000;
    Screen s; compose(dl, s); CHECK(s.progress); CHECK_EQ(s.percent, 45);
    CHECK(joined(dl).find("45%") != std::string::npos);
    View bad; bad.stage = Stage::Failed; bad.reason = Reason::SignatureInvalid;
    const auto b = joined(bad);
    CHECK(b.find("Signature refused") != std::string::npos); CHECK(b.find("kept") != std::string::npos);
    std::vector<std::uint16_t> px(135 * 240, 0);
    guardian::Canvas canvas(px.data(), 135, 240, true);
    draw(canvas, dl);
    std::size_t lit = 0; for (auto p : px) if (p) ++lit;
    CHECK(lit > 0);
}

// ---- G22A: only a newer image is installed; the poll never runs over an ALERT -------------------

GUARDIAN_CASE(version_order_is_the_build_stamp) {
    std::uint64_t a = 0;
    CHECK(version_stamp("guardian-20261119-214200", a)); CHECK_EQ(a, 20261119214200ull);
    CHECK(version_stamp("guardian-20261119-214200-bench", a)); CHECK_EQ(a, 20261119214200ull);   // variants keep the stamp
    CHECK(version_stamp("guardian-20261119-214200-bench-badsig", a));
    std::uint64_t keep = 7;
    for (const char* bad : {"", "guardian", "guardian-", "g16b-test-2", "guardian-2026119-214200", "guardian-20261119-21420",
                            "guardian-20261119214200", "guardian-20261119-214200x", "guardian-20261119-2142000", "guardian-2026111a-214200",
                            "Guardian-20261119-214200", "guardian-20261119-214200-", "guardian-20261119_214200", " guardian-20261119-214200"}) {
        if (version_stamp(bad, keep)) { std::printf("     accepted as a stamp: '%s'\n", bad); CHECK(false); }
    }
    CHECK(!version_stamp(nullptr, keep)); CHECK_EQ(keep, 7ull);
    CHECK(newer("guardian-20261119-214201", "guardian-20261119-214200"));
    CHECK(newer("guardian-20261120-000000", "guardian-20261119-235959"));
    CHECK(newer("guardian-20270101-000000-bench", "guardian-20261231-235959"));
    CHECK(!newer("guardian-20261119-214200", "guardian-20261119-214200"));           // the same build is not newer
    CHECK(!newer("guardian-20261119-214200-bench", "guardian-20261119-214200"));    // nor its variant
    CHECK(!newer("guardian-20261119-214159", "guardian-20261119-214200"));
    CHECK(!newer("guardian-20261118-235959", "guardian-20261119-000000-bench"));
    // An offered version outside the format is never newer; nothing is assumed about it.
    CHECK(!newer("g16b-test-2", "guardian-20261119-214200")); CHECK(!newer("", "guardian-20261119-214200"));
    CHECK(!newer(nullptr, "guardian-20261119-214200")); CHECK(!newer("zzzz", "aaaa"));
    // A hand-named running build is older than every stamped one (so it can be brought onto stamped builds).
    CHECK(newer("guardian-20200101-000000", "g16b-test-2")); CHECK(newer("guardian-20200101-000000", ""));
    CHECK(newer("guardian-20200101-000000", nullptr));
}

GUARDIAN_CASE(image_version_is_read_from_the_app_descriptor) {
    std::array<char, max_version + 1> v{};
    const auto img = image(200, "guardian-20261119-214200-bench");
    CHECK(image_version(img.data(), img.size(), v)); CHECK_EQ(std::string(v.data()), std::string("guardian-20261119-214200-bench"));
    CHECK(image_version(img.data(), 80, v));
    std::array<char, max_version + 1> keep{}; keep[0] = 'k';
    CHECK(!image_version(img.data(), 79, keep));
    auto no_magic = img; no_magic[33] ^= 1; CHECK(!image_version(no_magic.data(), no_magic.size(), keep));
    auto no_header = img; no_header[0] = 0; CHECK(!image_version(no_header.data(), no_header.size(), keep));
    CHECK(!image_version(nullptr, 200, keep)); CHECK_EQ(keep[0], 'k');
    // 32 bytes without a terminator: read as 31 characters, never past the field.
    auto full = img; for (std::size_t i = 48; i < 80; ++i) full[i] = 'v';
    CHECK(image_version(full.data(), full.size(), v)); CHECK_EQ(std::strlen(v.data()), std::size_t{31});
}

GUARDIAN_CASE(newer_image_is_installed) {
    Rig r; r.serve("guardian-20261116-120001", "guardian-20261116-120001");
    CHECK_EQ(r.go().reason, Reason::None); CHECK(r.slot.activated); cleanup_invariants(c_, r);
    Rig hand; hand.running = "g16b-test-2";   // a hand-named running build
    CHECK_EQ(hand.go().reason, Reason::None); CHECK(hand.slot.activated);
}

GUARDIAN_CASE(older_or_same_version_is_refused_before_any_download) {
    for (const char* listed : {"guardian-20261116-115959", "guardian-20261116-120000", "guardian-20261116-120000-bench",
                               "guardian-20251231-235959", "g16b-test-2"}) {
        Rig r; r.serve(listed, listed);
        const auto o = r.go();
        if (o.reason != Reason::NotNewer) { std::printf("     %s: %s\n", listed, reason_text(o.reason)); CHECK(false); }
        CHECK(!r.slot.begun); CHECK(!r.slot.activated); CHECK_EQ(o.received, 0u);
        CHECK_EQ(r.net.image_opens, 0u);   // the image was never asked for
        cleanup_invariants(c_, r);
    }
    CHECK_EQ(std::string(reason_text(Reason::NotNewer)), std::string("not_newer"));
    CHECK(std::strlen(reason_line(Reason::NotNewer)) <= 22);
}

GUARDIAN_CASE(old_image_under_a_newer_manifest_is_refused) {
    // The manifest is plain text from the network: it may claim any version for a validly signed old image.
    // The version inside the image is what the signature covers, so that one decides.
    for (const char* inside : {"guardian-20261116-115959", "guardian-20261116-120000", "g16b-test-2"}) {
        Rig r; r.serve("guardian-20991231-235959", inside);
        const auto o = r.go();
        if (o.reason != Reason::NotNewer) { std::printf("     inside=%s: %s\n", inside, reason_text(o.reason)); CHECK(false); }
        CHECK(r.slot.begun); CHECK(r.slot.aborted); CHECK(!r.slot.finished); CHECK(!r.slot.activated);
        CHECK(o.received < 10000u);   // stopped at the descriptor, not after the whole download
        cleanup_invariants(c_, r);
    }
    // An image with no descriptor at all is not an app image.
    Rig none; none.img = image(10000, nullptr); none.net.body = none.img; none.net.manifest = manifest_for(none.img);
    CHECK_EQ(none.go().reason, Reason::ImageInvalid); CHECK(!none.slot.activated); CHECK(none.slot.aborted); cleanup_invariants(c_, none);
    Rig tiny; tiny.img = image(60, nullptr); tiny.net.body = tiny.img; tiny.net.manifest = manifest_for(tiny.img);
    CHECK_EQ(tiny.go().reason, Reason::ImageInvalid); CHECK(!tiny.slot.activated); cleanup_invariants(c_, tiny);
    // The descriptor split over small reads is still read whole.
    Rig slow; slow.net.chunk = 7; slow.serve("guardian-20991231-235959", "guardian-20261116-115959");
    CHECK_EQ(slow.go().reason, Reason::NotNewer); CHECK(!slow.slot.activated);
    Rig slow_ok; slow_ok.net.chunk = 7;
    CHECK_EQ(slow_ok.go().reason, Reason::None); CHECK(slow_ok.slot.activated);
    // A variant of a newer build under a manifest with a test suffix (tools/ota_serve.py --bad-signature-test) still reaches the signature check.
    Rig bad; bad.serve("guardian-20261116-120001-badsig", "guardian-20261116-120001"); bad.slot.finish_result = Finish::SignatureInvalid;
    CHECK_EQ(bad.go().reason, Reason::SignatureInvalid);
}

GUARDIAN_CASE(auto_poll_runs_once_per_period) {
    AutoPoll p; using D = AutoPoll::Decision;
    CHECK(p.sample(0, 120000, false, false) == D::Wait);
    CHECK(p.sample(119999, 120000, false, false) == D::Wait);
    CHECK(p.sample(120000, 120000, false, false) == D::Run); CHECK_EQ(p.checks(), 1u);
    CHECK(p.sample(120001, 120000, false, false) == D::Wait);
    CHECK(p.sample(239999, 120000, false, false) == D::Wait);
    CHECK(p.sample(240500, 120000, false, false) == D::Run); CHECK_EQ(p.checks(), 2u);
    CHECK(p.sample(360499, 120000, false, false) == D::Wait);   // the period runs from the poll, not from a grid
    CHECK(p.sample(999999, 0, false, false) == D::Wait); CHECK_EQ(p.checks(), 2u);   // 0 = off
    // Busy (a session, the confirmation, the setup): the due poll waits, uncounted, and runs when free.
    CHECK(p.sample(999999, 120000, true, false) == D::Wait); CHECK_EQ(p.deferrals(), 0u);
    CHECK(p.sample(1000000, 120000, false, false) == D::Run); CHECK_EQ(p.checks(), 3u);
}

GUARDIAN_CASE(auto_poll_is_deferred_while_an_alert_is_active) {
    AutoPoll p; using D = AutoPoll::Decision;
    // Not due: an alert changes nothing and nothing is counted.
    CHECK(p.sample(1000, 120000, false, true) == D::Wait); CHECK_EQ(p.deferrals(), 0u); CHECK(!p.deferred());
    // Due while the ALERT is on the glass: deferred, never run, counted once however often the loop asks.
    CHECK(p.sample(120000, 120000, false, true) == D::Deferred); CHECK_EQ(p.deferrals(), 1u); CHECK(p.deferred());
    for (std::uint64_t t = 120001; t < 180000; t += 997) CHECK(p.sample(t, 120000, false, true) == D::Deferred);
    CHECK_EQ(p.deferrals(), 1u); CHECK_EQ(p.checks(), 0u);
    // The alert outlasts another whole period: still one held poll, still not run.
    CHECK(p.sample(400000, 120000, false, true) == D::Deferred); CHECK_EQ(p.deferrals(), 1u); CHECK_EQ(p.checks(), 0u);
    // The alert has ended: the held poll runs at the first sample, then the period starts again.
    CHECK(p.sample(400010, 120000, false, false) == D::Run); CHECK_EQ(p.checks(), 1u); CHECK(!p.deferred());
    CHECK(p.sample(400020, 120000, false, false) == D::Wait);
    CHECK(p.sample(520009, 120000, false, true) == D::Wait); CHECK_EQ(p.deferrals(), 1u);
    CHECK(p.sample(520010, 120000, false, true) == D::Deferred); CHECK_EQ(p.deferrals(), 2u);   // the next due poll is a new deferral
    // An alert and a busy radio together: the alert is what STATUS reports.
    CHECK(p.sample(520020, 120000, true, true) == D::Deferred); CHECK_EQ(p.deferrals(), 2u);
    // Turned off while deferred: nothing is held any more.
    CHECK(p.sample(520030, 0, false, true) == D::Wait); CHECK(!p.deferred());
    CHECK(p.sample(520040, 120000, false, false) == D::Run);
}

// G23 battery life: a separate update-poll period on battery, today's behaviour by default.
GUARDIAN_CASE(poll_period_on_battery_follows_ota_auto_s_unless_set) {
    CHECK(follow_auto_s < 0.0f);
    CHECK_EQ(poll_period_ms(120.0f, follow_auto_s, false), 120000u);
    CHECK_EQ(poll_period_ms(120.0f, follow_auto_s, true), 120000u);    // the default: as before G23
    CHECK_EQ(poll_period_ms(300.0f, -0.5f, true), 300000u);            // any value below 0 follows ota.auto_s
    CHECK_EQ(poll_period_ms(120.0f, 600.0f, true), 600000u);           // set: it replaces ota.auto_s on battery ...
    CHECK_EQ(poll_period_ms(120.0f, 600.0f, false), 120000u);          // ... and never on USB
    CHECK_EQ(poll_period_ms(120.0f, 0.0f, true), 0u);                  // 0: no poll on battery
    CHECK_EQ(poll_period_ms(120.0f, 0.0f, false), 120000u);
    CHECK_EQ(poll_period_ms(0.0f, follow_auto_s, true), 0u);           // ota.auto_s 0 (gesture only) stays off
    CHECK_EQ(poll_period_ms(0.0f, 900.0f, true), 900000u);
    CHECK_EQ(poll_period_ms(2.5f, follow_auto_s, false), 2500u);       // seconds to ms as the board did
    CHECK_EQ(poll_period_ms(-5.0f, follow_auto_s, true), 0u);
    CHECK_EQ(poll_period_ms(std::nanf(""), follow_auto_s, false), 0u);
    CHECK_EQ(poll_period_ms(120.0f, std::nanf(""), true), 120000u);    // not a number: not a battery period, follow
}

// G16C rework (5): TUNE/STATUS over the owner's Wi-Fi inside a bounded session
// (adapters/tune/session.hpp). The stick is only ever an HTTP client of the
// owner's Mac tool (tools/tune_session.py); it never listens.
// G22A: an offer is a signed envelope. The shape, nonce, expiry and allowlist rules are
// checked here with a stand-in verifier (the bytes it is shown are part of the check);
// the real RSA-3072 check with a generated key pair is tests/tune_offer_check.cpp.
#include "check.hpp"
#include "session.hpp"
#include <cstring>
#include <string>

using namespace guardian::tune::wifi;

namespace {
const char* kNonceA = "000102030405060708090a0b0c0d0e0f";
const std::string kSig(2 * kSignatureBytes, 'a');
// Says yes or no as told and records exactly what it was asked to check.
struct Stand final : SignatureVerifier {
    bool answer{true};
    mutable std::string message; mutable std::size_t signature_n{}; mutable unsigned calls{};
    bool verify(const std::uint8_t* m, std::size_t n, const std::uint8_t* sig, std::size_t sn) const override {
        ++calls; message.assign(reinterpret_cast<const char*>(m), n); signature_n = sn;
        return answer && sn == kSignatureBytes && sig[0] == 0xaa;
    }
};
Nonce nonce_a(std::uint32_t at = 1000) {
    std::uint8_t r[kNonceBytes]; for (std::size_t i = 0; i < kNonceBytes; ++i) r[i] = static_cast<std::uint8_t>(i);
    return make_nonce(r, at);
}
std::string body(const std::string& commands = "cmd=STATUS\n", const char* nonce = kNonceA, const char* expires = "60") {
    return std::string("GUARDIAN-TUNE 2\nnonce=") + nonce + "\nexpires=" + expires + "\n" + commands + "end\n";
}
std::string signed_offer(const std::string& signed_part) { return signed_part + "sig=" + kSig + "\n"; }
Refusal check(const std::string& text, Offer& o, const SignatureVerifier* key, std::uint32_t now = 2000, const Nonce* n = nullptr) {
    const Nonce mine = nonce_a();
    return verify_offer(text.data(), text.size(), n ? *n : mine, now, key, o);
}
}

GUARDIAN_CASE(nonce_is_the_sticks_own_and_names_the_request) {
    const Nonce n = nonce_a(777);
    CHECK(n.valid); CHECK_EQ(std::string(n.hex.data()), std::string(kNonceA)); CHECK_EQ(n.issued_ms, 777u);
    char path[64];
    CHECK(offer_path(n, path, sizeof path)); CHECK_EQ(std::string(path), std::string("tune/offer?nonce=") + kNonceA);
    CHECK(!offer_path(n, path, 20));
    CHECK(!offer_path(Nonce{}, path, sizeof path));   // no nonce drawn: no request
}

GUARDIAN_CASE(signed_offer_opens_with_its_command_list) {
    Stand key; Offer o;
    const std::string text = signed_offer(body("cmd=TUNE detect.burst=6\ncmd=TUNE save\ncmd=STATUS\n", kNonceA, "300"));
    CHECK(check(text, o, &key) == Refusal::None);
    CHECK_EQ(std::string(o.session.data()), std::string(kNonceA)); CHECK_EQ(o.seconds, 300u);
    CHECK_EQ(int(o.command_count), 3);
    if (o.command_count == 3) {
        CHECK_EQ(std::string(o.commands[0].data()), std::string("TUNE detect.burst=6"));
        CHECK_EQ(std::string(o.commands[1].data()), std::string("TUNE save"));
        CHECK_EQ(std::string(o.commands[2].data()), std::string("STATUS"));
    }
    // The verifier saw every byte from the header through "end\n", and nothing of the sig line.
    CHECK_EQ(key.calls, 1u); CHECK_EQ(key.message, body("cmd=TUNE detect.burst=6\ncmd=TUNE save\ncmd=STATUS\n", kNonceA, "300"));
    CHECK_EQ(key.signature_n, kSignatureBytes);
    CHECK(check(signed_offer(body()) .substr(0, signed_offer(body()).size() - 1), o, &key) == Refusal::None);   // final newline optional
    std::string eight; for (int i = 0; i < 8; ++i) eight += "cmd=TUNE " + std::string(kMaxCommand - 5, 'x') + "\n";
    const std::string largest = signed_offer(body(eight, kNonceA, "1800"));
    CHECK(largest.size() <= kMaxOffer); CHECK(check(largest, o, &key) == Refusal::None); CHECK_EQ(int(o.command_count), 8);
}

GUARDIAN_CASE(unsigned_offers_are_refused) {
    Stand key; Offer keep; keep.seconds = 77;
    // The offer of every tool before G22A: no signature at all.
    CHECK(check("GUARDIAN-TUNE 1\nsession=0123456789abcdef\nseconds=300\nend\n", keep, &key) == Refusal::Unsigned);
    CHECK(check(body(), keep, &key) == Refusal::Unsigned);                 // the new shape without its sig line
    CHECK(check(body() + "sig=\n", keep, &key) == Refusal::Unsigned);      // an empty one
    CHECK_EQ(key.calls, 0u); CHECK_EQ(keep.seconds, 77u);
}

GUARDIAN_CASE(a_signature_that_does_not_verify_is_refused) {
    Stand key; key.answer = false; Offer keep; keep.seconds = 77;
    CHECK(check(signed_offer(body()), keep, &key) == Refusal::Signature); CHECK_EQ(key.calls, 1u);
    Stand yes;
    CHECK(check(body() + "sig=" + std::string(766, 'a') + "\n", keep, &yes) == Refusal::Signature);    // too short
    CHECK(check(body() + "sig=" + std::string(770, 'a') + "\n", keep, &yes) == Refusal::Signature);    // too long
    CHECK(check(body() + "sig=" + std::string(767, 'a') + "G\n", keep, &yes) == Refusal::Signature);   // not hex
    CHECK(check(body() + "sig=" + std::string(768, 'A') + "\n", keep, &yes) == Refusal::Signature);    // lowercase only
    CHECK_EQ(yes.calls, 0u);
    CHECK(check(signed_offer(body()), keep, nullptr) == Refusal::NoKey);   // no public key on the stick: nothing opens
    CHECK_EQ(keep.seconds, 77u);
}

GUARDIAN_CASE(another_nonce_is_a_replay_and_is_refused) {
    Stand key; Offer keep; keep.seconds = 77;
    const std::string recorded = signed_offer(body("cmd=STATUS\n", "ffffffffffffffffffffffffffffffff"));   // well signed, for an earlier poll
    CHECK(check(recorded, keep, &key) == Refusal::Nonce);
    const Nonce none{};   // the stick drew no nonce: nothing can match it, not even an all-zero one
    CHECK(check(signed_offer(body("cmd=STATUS\n", "00000000000000000000000000000000")), keep, &key, 2000, &none) == Refusal::Nonce);
    CHECK_EQ(keep.seconds, 77u);
}

GUARDIAN_CASE(an_offer_past_its_expiry_is_refused) {
    Stand key; Offer o;
    const std::string text = signed_offer(body("cmd=STATUS\n", kNonceA, "30"));   // the nonce was drawn at 1000 ms
    CHECK(check(text, o, &key, 30999) == Refusal::None);
    Offer keep; keep.seconds = 77;
    CHECK(check(text, keep, &key, 31000) == Refusal::Expired);
    CHECK(check(text, keep, &key, 4000000) == Refusal::Expired);
    CHECK_EQ(keep.seconds, 77u);
    // The clock is 32 bits of milliseconds: an offer made just before the wrap is still judged by elapsed time.
    const Nonce late = nonce_a(0xFFFFFF00u);
    CHECK(verify_offer(text.data(), text.size(), late, 0x00000100u, &key, o) == Refusal::None);
    CHECK(verify_offer(text.data(), text.size(), late, 0xFFFFFF00u + 30000u, &key, keep) == Refusal::Expired);
}

GUARDIAN_CASE(a_signed_offer_cannot_widen_the_allowlist) {
    Stand key; Offer keep; keep.seconds = 77;
    for (const char* cmd : {"OTA SSID 41", "start 6 10", "select 1 2 BR", "IMU 3", "STATUS ", "TUNE", ""}) {
        const auto r = check(signed_offer(body(std::string("cmd=STATUS\ncmd=") + cmd + "\n")), keep, &key);
        if (r != Refusal::Command) { std::printf("     not refused as command: '%s' (%s)\n", cmd, refusal_text(r)); CHECK(false); }
    }
    CHECK(check(signed_offer(body("cmd=STATUS\r\n")), keep, &key) == Refusal::Command);
    CHECK(check(signed_offer(body("cmd=" + std::string(kMaxCommand + 1, 'x') + "\n")), keep, &key) == Refusal::Format);
    CHECK_EQ(keep.seconds, 77u);
}

GUARDIAN_CASE(offer_shape_is_strict_and_bounded) {
    Stand key; Offer keep; keep.seconds = 77;
    const char* n = kNonceA;
    const std::string bad[] = {
        "", "END\n", "GUARDIAN-OTA 1\nversion=x\nend\n", "GUARDIAN-TUNE 3\nnonce=" + std::string(n) + "\nexpires=60\ncmd=STATUS\nend\n",
        signed_offer(body("")),                                                             // no command
        signed_offer(std::string("GUARDIAN-TUNE 2\nexpires=60\nnonce=") + n + "\ncmd=STATUS\nend\n"),   // fixed order
        signed_offer(std::string("GUARDIAN-TUNE 2\nnonce=") + n + "\ncmd=STATUS\nend\n"),               // no expiry
        signed_offer(std::string("GUARDIAN-TUNE 2\nnonce=") + n + "\nexpires=60\nexpires=60\ncmd=STATUS\nend\n"),
        signed_offer(std::string("GUARDIAN-TUNE 2\nnonce=") + n + "\nexpires=60\ncmd=STATUS\nport=1\nend\n"),
        signed_offer(body("cmd=STATUS\n", "000102030405060708090A0B0C0D0E0F")),             // lowercase hex only
        signed_offer(body("cmd=STATUS\n", "0001")),
        signed_offer(body("cmd=STATUS\n", n, "29")), signed_offer(body("cmd=STATUS\n", n, "1801")),
        signed_offer(body("cmd=STATUS\n", n, "6x")), signed_offer(body("cmd=STATUS\n", n, "")), signed_offer(body("cmd=STATUS\n", n, "000060")),
        signed_offer(body("cmd=STATUS\ncmd=STATUS\ncmd=STATUS\ncmd=STATUS\ncmd=STATUS\ncmd=STATUS\ncmd=STATUS\ncmd=STATUS\ncmd=STATUS\n")),   // nine
        signed_offer(body()) + "more\n", signed_offer(body()) + "sig=" + kSig + "\n",       // nothing may follow the signature
        body() + "x\nsig=" + kSig + "\n",                                                   // nothing between "end" and the signature
    };
    for (const auto& text : bad) {
        const auto r = check(text, keep, &key);
        if (r != Refusal::Format) { std::printf("     not refused as format (%s): %.60s\n", refusal_text(r), text.c_str()); CHECK(false); }
    }
    CHECK_EQ(key.calls, 0u);   // nothing malformed reaches the signature check
    const std::string huge = signed_offer(body()) + std::string(kMaxOffer, '\n');
    CHECK(check(huge, keep, &key) == Refusal::Format);
    CHECK(verify_offer(nullptr, 5, nonce_a(), 2000, &key, keep) == Refusal::Format);
    CHECK_EQ(keep.seconds, 77u);
    CHECK(check(signed_offer(body()), keep, &key) == Refusal::None);   // control: the same helpers make a valid one
}

GUARDIAN_CASE(refusals_are_counted_with_their_reason_for_status) {
    OfferCounts c; char line[256];
    CHECK(c.status(line, sizeof line));
    CHECK_EQ(std::string(line), std::string("tune_offers_ok=0 tune_offers_refused=0 tune_offers_refused_last=none"
        " tune_offers_refused_by=unsigned:0,format:0,nokey:0,signature:0,nonce:0,expired:0,command:0"));
    c.note(Refusal::Unsigned); c.note(Refusal::Signature); c.note(Refusal::Signature); c.note(Refusal::None); c.note(Refusal::Nonce);
    c.note(Refusal::Expired); c.note(Refusal::Command); c.note(Refusal::Format); c.note(Refusal::NoKey); c.note(Refusal::Unsigned);
    CHECK_EQ(c.accepted, 1u); CHECK_EQ(c.refused, 9u); CHECK(c.last == Refusal::Unsigned);
    CHECK(c.status(line, sizeof line));
    CHECK_EQ(std::string(line), std::string("tune_offers_ok=1 tune_offers_refused=9 tune_offers_refused_last=unsigned"
        " tune_offers_refused_by=unsigned:2,format:1,nokey:1,signature:2,nonce:1,expired:1,command:1"));
    CHECK(std::string(line).find(' ') != std::string::npos && std::string(line).find("  ") == std::string::npos);
    CHECK(!c.status(line, 40));
    const char* names[] = {"none", "unsigned", "format", "nokey", "signature", "nonce", "expired", "command"};
    for (std::size_t i = 0; i < kRefusals; ++i) CHECK_EQ(std::string(refusal_text(static_cast<Refusal>(i))), std::string(names[i]));
}

GUARDIAN_CASE(only_tune_status_and_frame_statistics_are_accepted) {
    CHECK(allowed("STATUS")); CHECK(allowed("FRAMES")); CHECK(allowed("FRAMES 0"));
    CHECK(allowed("TUNE?")); CHECK(allowed("TUNE motion.damping=9")); CHECK(allowed("TUNE save"));
    CHECK(allowed("TUNE? t.probe"));   // review 2026-11-17: one group of the larger registry
    CHECK(allowed("IMU POSE"));        // review 2026-11-17: one still-pose reading (IMU calibration standing, no cable)
    CHECK(allowed("BATTRUN"));         // review 2026-11-17: the battery run log (read-only) without the cable
    // Radio, measurement, OTA provisioning, the raw IMU stream and anything else stay USB-only.
    const char* refused[] = {"", "TUNEX", "TUNE", "STATUS ", "status", "start 6 10", "select 1 2 BR", "OTA SSID 41", "OTA?", "IMU 3",
                             "IMU", "IMU POSE ", "IMU POSE 3", "imu pose", "IMU 0",
                             "EDGE", "BATTRUN ", "BATTRUN 0", "battrun", "SNAPSHOT", "DROP 24", "FRAMES 1", "TUNE motion.damping=9\nSTATUS", "TUNE \x01", "TUNE? ", "TUNE?x"};
    for (const char* r : refused) if (allowed(r)) { std::printf("     accepted: %s\n", r); CHECK(false); }
}

GUARDIAN_CASE(g16h_spike_verbs_reach_the_wifi_session) {
    // Supervisor 2026-11-19: the stick's USB is only its charger now, so the coexistence spike
    // (spike image only; the normal image answers "TUNE ERROR unsupported") is armed and read over Wi-Fi.
    CHECK(allowed("BLESPIKE")); CHECK(allowed("BLESPIKE report")); CHECK(allowed("BLESPIKE phases"));
    CHECK(allowed("BLESPIKE stop")); CHECK(allowed("BLESPIKE start")); CHECK(allowed("BLESPIKE start 60 2"));
    CHECK(allowed("BLESPIKE start 600 4"));
    const char* refused[] = {"BLESPIKE ", "BLESPIKEX", "blespike", "BLESPIKE start ", "BLESPIKE start 60", "BLESPIKE start 60 ",
                             "BLESPIKE start 60 2 1", "BLESPIKE start a b", "BLESPIKE start 60  2", "BLESPIKE start 6000 2",
                             "BLESPIKE start 60 22", "BLESPIKE start -1 2", "BLESPIKE report ", "BLESPIKE phases 1", "BLESPIKE go"};
    for (const char* r : refused) if (allowed(r)) { std::printf("     accepted: %s\n", r); CHECK(false); }
}

GUARDIAN_CASE(session_is_bounded_by_its_expiry_keys_the_list_and_the_network) {
    Stand key; Offer o; CHECK(check(signed_offer(body()), o, &key) == Refusal::None);   // expires=60
    Session s; CHECK(!s.active());
    // The expiry runs from the moment the nonce was drawn (1000 ms), not from when the offer arrived.
    s.begin(o, 1000); CHECK(s.active()); CHECK_EQ(s.remaining_ms(1000), 60000u); CHECK_EQ(s.remaining_ms(31000), 30000u);
    s.tick(60999); CHECK(s.active());
    s.tick(61000); CHECK(!s.active()); CHECK(s.end() == End::Timeout); CHECK_EQ(s.remaining_ms(61000), 0u);
    s.begin(o, 0); s.key(10); CHECK(!s.active()); CHECK(s.end() == End::Key);
    s.begin(o, 0); s.done(); CHECK(s.end() == End::Done);
    s.begin(o, 0);
    s.network(false, 1); s.network(false, 2); CHECK(s.active());
    s.network(true, 3); s.network(false, 4); s.network(false, 5); CHECK(s.active());   // only consecutive failures end it
    s.network(false, 6); CHECK(!s.active()); CHECK(s.end() == End::Network);
    // Ended sessions stay ended; the record of the end is kept for STATUS.
    s.key(7); CHECK(s.end() == End::Network);
    CHECK(std::strcmp(end_text(End::Timeout), "timeout") == 0); CHECK(std::strcmp(end_text(End::Key), "key") == 0);
    CHECK(std::strcmp(end_text(End::Done), "done") == 0);
    // Commands: counted; refused ones never executed.
    s.begin(o, 0); s.command(true); s.command(false); s.command(true);
    CHECK_EQ(s.commands(), 2u); CHECK_EQ(s.refused(), 1u);
}

GUARDIAN_CASE(paths_carry_the_nonce_as_the_session) {
    Stand key; Offer o; CHECK(check(signed_offer(body()), o, &key) == Refusal::None);
    char path[96];
    CHECK(reply_path(o, path, sizeof path)); CHECK_EQ(std::string(path), std::string("tune/reply?s=") + kNonceA);
    CHECK(end_path(o, End::Key, path, sizeof path)); CHECK_EQ(std::string(path), std::string("tune/end?s=") + kNonceA + "&why=key");
    CHECK(!reply_path(o, path, 10));
}

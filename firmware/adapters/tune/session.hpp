#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

// G16C rework (5): TUNE and STATUS over the owner's Wi-Fi, so the standing
// stick can be tuned without its USB cable. SDK-free and host-tested.
//
// G22A (2026-11-19): SIGNED OFFERS ONLY. The session can open with no gesture (the
// board's self-fetch poll, TUNE ota.auto_s, runs the UPDATE path by itself), so the
// offer is the whole authorization and carries its own proof of origin:
//   GET <url>/tune/offer?nonce=<32 hex>     the nonce is the stick's own, fresh per request
//   ->  GUARDIAN-TUNE 2
//       nonce=<the same 32 hex>
//       expires=<30..1800>                  seconds, counted by the stick from the nonce
//       cmd=<one console line>              1..8 lines, each inside the allowlist below
//       end
//       sig=<768 hex>                       RSA-3072 PKCS#1 v1.5 SHA-256 over every byte
//                                           from "GUARDIAN-TUNE 2" through "end\n"
// The signature is made on the Mac with the OTA signing key (tools/tune_session.py)
// and checked with the public key the stick verifies update images with. An unsigned
// offer (the old "GUARDIAN-TUNE 1" or no sig line), a bad signature, another nonce
// (a replay), an expired offer or a command outside the allowlist is refused, counted
// (OfferCounts, STATUS tune_offers_refused*) and opens nothing: the poll goes on to the
// update check and monitoring resumes as if nothing had been offered.
// The commands are the signed list, nothing else: the stick asks for no further command.
// During the session the stick is an HTTP client only (it never listens):
//   POST <url>/tune/reply?s=<nonce>   <- one command's reply lines, in the order of the list
//   GET  <url>/tune/end?s=<nonce>&why=<reason>   (best effort, at the end)
// Accepted commands: STATUS, FRAMES, FRAMES 0, TUNE?, TUNE? <group>, TUNE <args> and
// IMU POSE (review 2026-11-17: the IMU calibration in the stick's real, cable-less pose) and
// BATTRUN (the read-only battery run log), and the G16H spike verbs BLESPIKE, BLESPIKE start [<phase_s> <rounds>],
// BLESPIKE stop, BLESPIKE report and BLESPIKE phases (acted on by the spike image only).
// Radio, measurement, OTA provisioning, the raw IMU stream and everything else stay USB-only.
// The session ends when the list is done, on its expiry, on any key press or after three
// consecutive network failures; then the stick leaves the network and passive
// monitoring resumes. Monitoring is paused for the whole session (the radio is
// a Wi-Fi station on the owner's network meanwhile), and the screen says so.
namespace guardian::tune::wifi {

constexpr std::size_t kMaxCommand = 159;    // the USB console's line limit
constexpr std::size_t kMaxCommands = 8;     // commands in one signed offer
constexpr std::size_t kNonceBytes = 16, kNonceHex = 2 * kNonceBytes;
constexpr std::size_t kSignatureBytes = 384;   // RSA-3072
// header + nonce + expires + 8 full commands + end + sig line = 2,158 bytes at most.
constexpr std::size_t kMaxOffer = 2304;
// G16S: one STATUS line is about 3.7 kB (measured 2026-11-19) and grows by the burst records (up to 0.7 kB),
// so 4096 would cut its tail without a word. 8192 is what tools/tune_session.py reads of one reply.
constexpr std::size_t kMaxReply = 8192;
constexpr std::uint32_t kMinSeconds = 30, kMaxSeconds = 1800;
constexpr unsigned kNetworkFailures = 3;

// The stick's own challenge: 16 random bytes as lowercase hex and the moment they were drawn.
// One nonce serves one offer request and is forgotten after it, whatever came back.
struct Nonce {
    std::array<char, kNonceHex + 1> hex{};
    std::uint32_t issued_ms{};
    bool valid{};
};
Nonce make_nonce(const std::uint8_t random[kNonceBytes], std::uint32_t now_ms);
// "tune/offer?nonce=<hex>" (false: no nonce or it does not fit `n`).
bool offer_path(const Nonce&, char* out, std::size_t n);

// A verified offer. `session` is the nonce: it also names the session in the reply paths.
struct Offer {
    std::array<char, kNonceHex + 1> session{};
    std::uint32_t seconds{};          // expiry, counted from Nonce::issued_ms
    std::uint8_t command_count{};
    std::array<std::array<char, kMaxCommand + 1>, kMaxCommands> commands{};
};

// The public half of the OTA signing key. RSA-3072, PKCS#1 v1.5, SHA-256 of `message`.
class SignatureVerifier {
public:
    virtual ~SignatureVerifier() = default;
    virtual bool verify(const std::uint8_t* message, std::size_t n, const std::uint8_t* signature, std::size_t signature_n) const = 0;
};

enum class Refusal : std::uint8_t { None, Unsigned, Format, NoKey, Signature, Nonce, Expired, Command };
constexpr std::size_t kRefusals = 8;
const char* refusal_text(Refusal);   // "none", "unsigned", "format", "nokey", "signature", "nonce", "expired", "command"
// The one way an offer becomes a session. Checks, in this order: the shape, the signature over the
// exact bytes received, the nonce, the expiry on the stick's own clock, every command against
// allowed(). `out` is written only when the answer is Refusal::None.
Refusal verify_offer(const char* text, std::size_t n, const Nonce& nonce, std::uint32_t now_ms,
                     const SignatureVerifier* key, Offer& out);

// What STATUS reports about offers since boot.
struct OfferCounts {
    std::uint32_t accepted{}, refused{};
    std::array<std::uint32_t, kRefusals> by{};
    Refusal last{Refusal::None};
    void note(Refusal r);
    // "tune_offers_ok=<n> tune_offers_refused=<n> tune_offers_refused_last=<reason>
    //  tune_offers_refused_by=unsigned:<n>,format:<n>,nokey:<n>,signature:<n>,nonce:<n>,expired:<n>,command:<n>"
    // (one line, space separated; false: does not fit `n`).
    bool status(char* out, std::size_t n) const;
};

// One console line accepted inside a session (exact verbs, printable ASCII).
bool allowed(const char* line);

enum class End : std::uint8_t { None, Timeout, Key, Done, Network };
const char* end_text(End);   // "none", "timeout", "key", "done", "network"

class Session {
public:
    // `issued_ms`: when the offer's nonce was drawn; the session ends `seconds` after that instant at the latest.
    void begin(const Offer& o, std::uint32_t issued_ms) {
        offer_ = o; started_ = issued_ms; deadline_ = issued_ms + o.seconds * 1000u; active_ = true; end_ = End::None;
        failures_ = 0; commands_ = 0; refused_ = 0;
    }
    bool active() const { return active_; }
    End end() const { return end_; }
    const Offer& offer() const { return offer_; }
    std::uint32_t remaining_ms(std::uint32_t now_ms) const {
        return active_ && static_cast<std::int32_t>(deadline_ - now_ms) > 0 ? deadline_ - now_ms : 0;
    }
    void tick(std::uint32_t now_ms) { if (active_ && static_cast<std::int32_t>(now_ms - deadline_) >= 0) finish(End::Timeout); }
    void key(std::uint32_t) { finish(End::Key); }
    void done() { finish(End::Done); }   // every command of the signed list was answered
    // One network exchange (a reply post): three consecutive failures end the session.
    void network(bool ok, std::uint32_t) {
        if (!active_) return;
        failures_ = ok ? 0u : failures_ + 1u;
        if (failures_ >= kNetworkFailures) finish(End::Network);
    }
    // One command received: executed (true) or refused (false).
    void command(bool executed) { if (executed) ++commands_; else ++refused_; }
    std::uint32_t commands() const { return commands_; }
    std::uint32_t refused() const { return refused_; }
private:
    void finish(End why) { if (active_) { active_ = false; end_ = why; } }
    Offer offer_{};
    std::uint32_t started_{}, deadline_{}, commands_{}, refused_{};
    unsigned failures_{};
    bool active_{};
    End end_{End::None};
};

// Request paths below the provisioned URL (false: does not fit `n`).
bool reply_path(const Offer&, char* out, std::size_t n);
bool end_path(const Offer&, End, char* out, std::size_t n);

} // namespace guardian::tune::wifi

// G22A host tool (not a test by itself): the stick's own offer check as a command, so
// tools/tests/test_tune_session.py can prove that an offer signed by the Mac tool
// (openssl, throwaway key) is accepted by the code the board compiles, and that a
// tampered one is refused.
//   tune_offer_verify <modulus: 768 hex, most significant byte first> <exponent> <nonce: 32 hex> <issued_ms> <now_ms> < offer
//   tune_offer_verify block:<file> 0 <nonce> <issued_ms> <now_ms> < offer
// The second form takes the key the way the stick does: from a Secure Boot V2 signature block (the
// 1216 bytes at the start of a signed image's last 4096-byte sector); "key=block" or "key=none" is printed first.
// Prints "refusal=<reason>" and, when accepted, the session, the expiry and the commands.
// Exit: 0 accepted, 1 refused, 2 usage.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "offer_rsa.hpp"

using namespace guardian::tune::wifi;

namespace {
bool unhex(const char* text, std::vector<std::uint8_t>& out) {
    const std::size_t n = std::strlen(text);
    if (n % 2) return false;
    out.clear();
    for (std::size_t i = 0; i < n; i += 2) {
        unsigned v = 0;
        for (std::size_t k = 0; k < 2; ++k) {
            const char c = text[i + k];
            if (c >= '0' && c <= '9') v = v * 16u + static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') v = v * 16u + static_cast<unsigned>(c - 'a' + 10);
            else return false;
        }
        out.push_back(static_cast<std::uint8_t>(v));
    }
    return true;
}
}

int main(int argc, char** argv) {
    std::vector<std::uint8_t> modulus, random;
    const bool from_block = argc == 6 && std::strncmp(argv[1], "block:", 6) == 0;
    if (argc != 6 || (!from_block && !unhex(argv[1], modulus)) || !unhex(argv[3], random) || random.size() != kNonceBytes) {
        std::fprintf(stderr, "usage: tune_offer_verify <modulus hex> <exponent> <nonce hex> <issued_ms> <now_ms> < offer\n");
        return 2;
    }
    RsaKey key;
    bool loaded = false;
    if (from_block) {
        std::vector<std::uint8_t> block(kSignatureBlockBytes);
        std::FILE* f = std::fopen(argv[1] + 6, "rb");
        const std::size_t got = f ? std::fread(block.data(), 1, block.size(), f) : 0;
        if (f) std::fclose(f);
        loaded = key.load_signature_block(block.data(), got);
        std::printf("key=%s\n", loaded ? "block" : "none");
    } else {
        loaded = key.load(modulus.data(), modulus.size(), static_cast<std::uint32_t>(std::strtoul(argv[2], nullptr, 10)));
    }
    const Nonce nonce = make_nonce(random.data(), static_cast<std::uint32_t>(std::strtoul(argv[4], nullptr, 10)));
    std::string text;
    char buffer[1024];
    for (std::size_t got; (got = std::fread(buffer, 1, sizeof buffer, stdin)) > 0;) text.append(buffer, got);
    Offer offer;
    const Refusal r = verify_offer(text.data(), text.size(), nonce, static_cast<std::uint32_t>(std::strtoul(argv[5], nullptr, 10)),
                                   loaded ? &key : nullptr, offer);
    std::printf("refusal=%s\n", refusal_text(r));
    if (r != Refusal::None) return 1;
    std::printf("session=%s expires=%u commands=%u\n", offer.session.data(), static_cast<unsigned>(offer.seconds), static_cast<unsigned>(offer.command_count));
    for (std::size_t i = 0; i < offer.command_count; ++i) std::printf("cmd=%s\n", offer.commands[i].data());
    return 0;
}

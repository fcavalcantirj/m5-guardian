#pragma once
// G22A: the signature check of a TUNE offer (session.hpp), RSA-3072 PKCS#1 v1.5 over
// SHA-256, done by mbedtls: the library ESP-IDF checks update images with. The same
// source runs on the board (ESP-IDF's mbedtls) and in the host check (the same
// mbedtls sources, built for the host by firmware/CMakeLists.txt). The key is the
// PUBLIC half only: on the board, the one in the running image's signature block.
#include <array>
#include <cstddef>
#include <cstdint>
#include "session.hpp"

namespace guardian::tune::wifi {

class RsaKey final : public SignatureVerifier {
public:
    // The modulus as 384 bytes, most significant first, and the public exponent.
    // False (and no key loaded): another size, an even or tiny modulus, an exponent below 3 or even.
    bool load(const std::uint8_t* modulus_be, std::size_t n, std::uint32_t exponent);
    // The same from a Secure Boot V2 signature block, which stores the modulus least significant first.
    bool load_le(const std::uint8_t* modulus_le, std::size_t n, std::uint32_t exponent);
    // The key of one Secure Boot V2 signature block, as ESP-IDF's espsecure appends it to a signed app
    // image (1216 bytes: magic 0xE7, version 2 = RSA, image digest, the public key, the image signature,
    // a CRC-32 of the first 1196 bytes). The same validity rule as ESP-IDF's own reader
    // (bootloader_support secure_boot_signatures_app.c validate_signature_block). False: no key loaded.
    bool load_signature_block(const std::uint8_t* block, std::size_t n);
    bool loaded() const { return loaded_; }
    bool verify(const std::uint8_t* message, std::size_t n, const std::uint8_t* signature, std::size_t signature_n) const override;
private:
    std::array<std::uint8_t, kSignatureBytes> modulus_{};
    std::uint32_t exponent_{};
    bool loaded_{};
};

constexpr std::size_t kSignatureBlockBytes = 1216;
// CRC-32 as zlib and esp_rom_crc32_le(0, ...) compute it (reflected 0xEDB88320, initial and final inversion).
std::uint32_t crc32(const std::uint8_t* data, std::size_t n);

} // namespace guardian::tune::wifi

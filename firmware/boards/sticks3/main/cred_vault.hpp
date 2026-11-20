#pragma once
// G16M: the encrypted home of the Wi-Fi credential. A separate small NVS
// partition ("nvs_cred") opened with NVS encryption (XTS-AES); its keys are
// derived at boot by the chip's HMAC peripheral from a key in one eFuse block
// (ESP-IDF "HMAC-based" NVS key protection, the only scheme the ESP32-S3
// offers without flash encryption). The default NVS partition (selection,
// TUNE values, boot counter, update record) is untouched and stays readable
// by every earlier image, so an update rollback loses nothing.
//
// This code only READS the key: it never generates or burns one. The owner
// burns it once over USB with espefuse (firmware/README.md, "Credential
// vault"); until the partition and the key exist the vault is Absent and the
// credential stays in the G16B plain record, reported as cred_store=plain.
// A vault that exists but cannot be opened is an Error: nothing is erased and
// nothing falls back to plain text.
#include "companion.hpp"
#include "setup.hpp"
namespace sticks3::vault {
constexpr const char* partition_label = "nvs_cred";
// Once, after the default NVS is initialised. Never erases, never writes an eFuse.
guardian::setup::VaultState init();
// "ready", "no_partition", "no_key", "scheme_failed", "key_derivation_failed", "open_failed" (STATUS cred_vault=)
const char* state_text();
class Blob final : public guardian::companion::BlobStorage {
public:
    explicit Blob(const char* key) : key_(key) {}
    guardian::companion::BlobRead read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const override;
    bool write(const std::uint8_t* data, std::size_t size) override;
private:
    const char* key_;
};
} // namespace sticks3::vault

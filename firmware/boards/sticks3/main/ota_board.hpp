#pragma once
// G16B ESP-IDF adapters for the portable OTA decisions (adapters/ota/ota.hpp).
// Only used inside the owner-confirmed UPDATE mode; outside it the Guardian
// never joins a network.
#include "ota.hpp"
#include "offer_rsa.hpp"
#include <cstdint>

namespace sticks3::ota {

// Wi-Fi station on the owner network + plain HTTP GET of <url>/<path>. The
// radio driver is already initialised by the passive receiver (country set,
// 802.11d off); join() switches it from NULL mode to STA and leave() returns
// it to NULL mode, ready for MeasurementRadio::tune() to resume listening.
// Credentials and URL are never logged.
class WifiTransport final : public guardian::ota::Transport {
public:
    explicit WifiTransport(const guardian::ota::Credentials& c) : creds_(c) {}
    // Idempotent: true at once while already joined (G16C: the TUNE offer probe
    // joins first, then the update path reuses the connection).
    bool join() override;
    void leave() override;
    bool open(const char* path, std::int32_t& content_length) override;
    int read(std::uint8_t* out, std::size_t capacity) override;
    void close() override;
    // G16C TUNE session: a whole small GET body (false: not 200, too long or a
    // network error) and a POST of `body`. `timeout_ms` bounds each request.
    bool fetch(const char* path, char* out, std::size_t capacity, std::size_t& n, int timeout_ms);
    bool post(const char* path, const char* body, std::size_t n, int timeout_ms);
    bool joined() const { return joined_; }
private:
    bool url_for(const char* path, char* out, std::size_t n) const;
    const guardian::ota::Credentials& creds_;
    void* client_{};   // esp_http_client_handle_t
    bool joined_{};
};

// The inactive OTA slot through esp_ota_ops. finish() = esp_ota_end(), which
// with CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT verifies the image and its
// RSA-3072 signature against the running app's signing key; on failure the
// signature is re-checked alone to name the reason. activate() =
// esp_ota_set_boot_partition() (the slot switch).
class OtaSlot final : public guardian::ota::Slot {
public:
    OtaSlot();
    std::uint32_t capacity() const override;
    bool begin(std::uint32_t size) override;
    bool write(const std::uint8_t* data, std::size_t n) override;
    void abort() override;
    guardian::ota::Finish finish() override;
    bool activate() override;
    std::uint8_t slot_index() const;
private:
    const void* target_{};   // const esp_partition_t*
    std::uint32_t handle_{};
    bool open_{};
};

// G16M: the station side's one-time network set-up (esp_netif, the station interface, the join
// events); shared with the setup access point. The reason code of the latest failed join
// (wifi_err_reason_t, 0 = none seen), so the setup can tell a refused password from an absent network.
bool net_init();
std::uint8_t last_disconnect_reason();

// G22A: the RSA-3072 public key of the running image's Secure Boot V2 signature block, the key
// esp_ota_end() checks update images against (CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT). A TUNE
// offer must be signed with the same key. False (no key loaded): the running image carries no valid
// signature block, so no offer can be accepted. Only the public key is ever on the stick.
bool signing_key(guardian::tune::wifi::RsaKey& out);

// Running slot (0/1, 0xFF unknown) and whether this image is on probation.
guardian::ota::BootFacts boot_facts();
const char* slot_text(std::uint8_t slot);   // "ota_0", "ota_1", "unknown"
const char* running_version();
bool mark_valid();                          // esp_ota_mark_app_valid_cancel_rollback()
[[noreturn]] void rollback_and_reboot();    // esp_ota_mark_app_invalid_rollback_and_reboot()

} // namespace sticks3::ota

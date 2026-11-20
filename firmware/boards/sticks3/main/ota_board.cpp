// G16B ESP-IDF adapters for the owner-initiated signed OTA (see ota_board.hpp).
#include "ota_board.hpp"
#include <cstdio>
#include <cstring>
#include "esp_app_desc.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_image_format.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_secure_boot.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

namespace sticks3::ota {
namespace {
using guardian::ota::Finish;
constexpr EventBits_t got_ip = BIT0, failed = BIT1;
constexpr int join_timeout_ms = 20000, connect_attempts = 3;
EventGroupHandle_t events;
bool netif_ready;
int attempts_left;
std::uint8_t last_reason;   // G16M: why the latest join attempt was disconnected (0: no disconnect seen)
// Overwrites credential copies; volatile so the compiler cannot drop it.
void wipe(void* p, std::size_t n) { auto* v = static_cast<volatile std::uint8_t*>(p); while (n--) *v++ = 0; }
void on_event(void*, esp_event_base_t base, std::int32_t id, void* data) {
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) { xEventGroupSetBits(events, got_ip); return; }
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (data && attempts_left > 0) last_reason = static_cast<const wifi_event_sta_disconnected_t*>(data)->reason;
        if (--attempts_left > 0 && esp_wifi_connect() == ESP_OK) return;
        xEventGroupSetBits(events, failed);
    }
}
} // namespace

bool net_init() {
    if (netif_ready) return true;
    events = xEventGroupCreate();
    if (!events || esp_netif_init() != ESP_OK || !esp_netif_create_default_wifi_sta()) return false;
    if (esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, on_event, nullptr) != ESP_OK
        || esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, nullptr) != ESP_OK) return false;
    netif_ready = true;
    return true;
}
std::uint8_t last_disconnect_reason() { return last_reason; }

bool WifiTransport::join() {
    if (joined_) return true;
    if (!net_init()) return false;
    // G16M: a name is enough to join (the phone setup checks a password before any server URL exists);
    // run_update() still requires the complete record before it calls this.
    if (!creds_.wifi()) return false;
    last_reason = 0;
    esp_wifi_set_promiscuous(false);
    if (esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK) return false;
    wifi_config_t cfg{};
    std::memcpy(cfg.sta.ssid, creds_.ssid.data(), creds_.ssid_len);
    std::memcpy(cfg.sta.password, creds_.pass.data(), creds_.pass_len);
    cfg.sta.threshold.authmode = creds_.pass_len ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    cfg.sta.pmf_cfg.capable = true;
    const bool configured = esp_wifi_set_config(WIFI_IF_STA, &cfg) == ESP_OK;
    wipe(&cfg, sizeof cfg);
    if (!configured) return false;
    xEventGroupClearBits(events, got_ip | failed);
    attempts_left = connect_attempts;
    if (esp_wifi_connect() != ESP_OK) return false;
    const auto bits = xEventGroupWaitBits(events, got_ip | failed, pdFALSE, pdFALSE, pdMS_TO_TICKS(join_timeout_ms));
    joined_ = (bits & got_ip) != 0;
    return joined_;
}

void WifiTransport::leave() {
    close();
    joined_ = false;
    attempts_left = 0;   // a disconnect event must not reconnect
    esp_wifi_disconnect();
    wifi_config_t empty{};
    esp_wifi_set_config(WIFI_IF_STA, &empty);   // drop the credentials from the driver (storage is RAM only)
    esp_wifi_set_mode(WIFI_MODE_NULL);           // back to the passive receiver's mode
}

bool WifiTransport::url_for(const char* path, char* url, std::size_t n) const {
    std::size_t base = std::strlen(creds_.url.data());
    while (base && creds_.url[base - 1] == '/') --base;
    const int w = std::snprintf(url, n, "%.*s/%s", static_cast<int>(base), creds_.url.data(), path);
    return w > 0 && static_cast<std::size_t>(w) < n;
}

bool WifiTransport::open(const char* path, std::int32_t& content_length) {
    close();
    char url[guardian::ota::max_url + 32];
    if (!url_for(path, url, sizeof url)) return false;
    esp_http_client_config_t cfg{};
    cfg.url = url;
    cfg.timeout_ms = 10000;
    cfg.buffer_size = 2048;
    cfg.disable_auto_redirect = true;
    auto client = esp_http_client_init(&cfg);
    wipe(url, sizeof url);
    if (!client) return false;
    if (esp_http_client_open(client, 0) != ESP_OK) { esp_http_client_cleanup(client); return false; }
    const std::int64_t length = esp_http_client_fetch_headers(client);
    if (esp_http_client_get_status_code(client) != 200) { esp_http_client_close(client); esp_http_client_cleanup(client); return false; }
    content_length = length > 0 && length <= INT32_MAX ? static_cast<std::int32_t>(length) : -1;
    client_ = client;
    return true;
}

int WifiTransport::read(std::uint8_t* out, std::size_t capacity) {
    if (!client_) return -1;
    const int n = esp_http_client_read(static_cast<esp_http_client_handle_t>(client_), reinterpret_cast<char*>(out),
                                       static_cast<int>(capacity > 4096 ? 4096 : capacity));
    return n < 0 ? -1 : n;   // 0 = end of body; the core decides truncated vs complete by size
}

bool WifiTransport::fetch(const char* path, char* out, std::size_t capacity, std::size_t& n, int timeout_ms) {
    n = 0;
    if (!joined_ || !capacity) return false;
    char url[guardian::ota::max_url + 64];
    if (!url_for(path, url, sizeof url)) return false;
    esp_http_client_config_t cfg{};
    cfg.url = url; cfg.timeout_ms = timeout_ms; cfg.buffer_size = 1024; cfg.disable_auto_redirect = true;
    auto client = esp_http_client_init(&cfg);
    wipe(url, sizeof url);
    if (!client) return false;
    bool ok = false;
    if (esp_http_client_open(client, 0) == ESP_OK) {
        const std::int64_t length = esp_http_client_fetch_headers(client);
        if (esp_http_client_get_status_code(client) == 200 && length < static_cast<std::int64_t>(capacity)) {
            ok = true;
            for (;;) {
                if (n + 1 >= capacity) { ok = false; break; }   // longer than the caller allows
                const int r = esp_http_client_read(client, out + n, static_cast<int>(capacity - 1 - n));
                if (r < 0) { ok = false; break; }
                if (r == 0) break;
                n += static_cast<std::size_t>(r);
            }
        }
    }
    out[n < capacity ? n : capacity - 1] = 0;
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return ok;
}

bool WifiTransport::post(const char* path, const char* body, std::size_t n, int timeout_ms) {
    if (!joined_) return false;
    char url[guardian::ota::max_url + 64];
    if (!url_for(path, url, sizeof url)) return false;
    esp_http_client_config_t cfg{};
    cfg.url = url; cfg.timeout_ms = timeout_ms; cfg.buffer_size = 1024; cfg.disable_auto_redirect = true;
    cfg.method = HTTP_METHOD_POST;
    auto client = esp_http_client_init(&cfg);
    wipe(url, sizeof url);
    if (!client) return false;
    esp_http_client_set_header(client, "Content-Type", "text/plain");
    esp_http_client_set_post_field(client, body, static_cast<int>(n));
    const bool ok = esp_http_client_perform(client) == ESP_OK && esp_http_client_get_status_code(client) == 200;
    esp_http_client_cleanup(client);
    return ok;
}

void WifiTransport::close() {
    if (!client_) return;
    auto client = static_cast<esp_http_client_handle_t>(client_);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    client_ = nullptr;
}

OtaSlot::OtaSlot() : target_(esp_ota_get_next_update_partition(nullptr)) {}
std::uint32_t OtaSlot::capacity() const { return target_ ? static_cast<const esp_partition_t*>(target_)->size : 0; }
bool OtaSlot::begin(std::uint32_t size) {
    if (!target_ || open_) return false;
    esp_ota_handle_t h{};
    if (esp_ota_begin(static_cast<const esp_partition_t*>(target_), size, &h) != ESP_OK) return false;
    handle_ = h; open_ = true;
    return true;
}
bool OtaSlot::write(const std::uint8_t* data, std::size_t n) {
    return open_ && esp_ota_write(handle_, data, n) == ESP_OK;
}
void OtaSlot::abort() {
    if (open_) esp_ota_abort(handle_);
    open_ = false;
}
Finish OtaSlot::finish() {
    if (!open_) return Finish::Failed;
    open_ = false;
    const esp_err_t err = esp_ota_end(handle_);   // image + signature verification; frees the handle either way
    if (err == ESP_OK) return Finish::Ok;
    if (err != ESP_ERR_OTA_VALIDATE_FAILED) return Finish::Failed;
    // Name the reason: a structurally loadable image whose sbv2 signature does
    // not verify against the running app's key is a signature refusal.
    const auto* part = static_cast<const esp_partition_t*>(target_);
    const esp_partition_pos_t pos{part->address, part->size};
    esp_image_metadata_t meta{};
    if (esp_image_get_metadata(&pos, &meta) == ESP_OK && esp_secure_boot_verify_signature(part->address, meta.image_len) != ESP_OK)
        return Finish::SignatureInvalid;
    return Finish::ImageInvalid;
}
bool OtaSlot::activate() {
    return target_ && esp_ota_set_boot_partition(static_cast<const esp_partition_t*>(target_)) == ESP_OK;
}
std::uint8_t OtaSlot::slot_index() const {
    if (!target_) return 0xFF;
    const auto sub = static_cast<const esp_partition_t*>(target_)->subtype;
    return sub >= ESP_PARTITION_SUBTYPE_APP_OTA_MIN && sub < ESP_PARTITION_SUBTYPE_APP_OTA_MAX
        ? static_cast<std::uint8_t>(sub - ESP_PARTITION_SUBTYPE_APP_OTA_MIN) : 0xFF;
}

// G22A. Where ESP-IDF itself looks (bootloader_support secure_boot_signatures_app.c,
// calculate_image_public_key_digests): the first signature block starts at the next 4096-byte
// boundary after the running image.
bool signing_key(guardian::tune::wifi::RsaKey& out) {
    const esp_partition_t* running = esp_ota_get_running_partition();
    if (!running) return false;
    const esp_partition_pos_t pos{running->address, running->size};
    esp_image_metadata_t meta{};
    if (esp_image_get_metadata(&pos, &meta) != ESP_OK) return false;
    const std::uint32_t at = (meta.image_len + 4095u) & ~4095u;   // offset inside the partition
    if (at + sizeof(ets_secure_boot_sig_block_t) > running->size) return false;
    static_assert(sizeof(ets_secure_boot_sig_block_t) == guardian::tune::wifi::kSignatureBlockBytes, "signature block layout");
    auto* block = static_cast<std::uint8_t*>(heap_caps_malloc(guardian::tune::wifi::kSignatureBlockBytes, MALLOC_CAP_DEFAULT));
    if (!block) return false;
    // The block's own rule (magic, scheme, CRC) and its key are read by the portable, host-tested RsaKey.
    const bool ok = esp_partition_read(running, at, block, guardian::tune::wifi::kSignatureBlockBytes) == ESP_OK
        && out.load_signature_block(block, guardian::tune::wifi::kSignatureBlockBytes);
    heap_caps_free(block);
    return ok;
}

guardian::ota::BootFacts boot_facts() {
    guardian::ota::BootFacts f;
    f.running_slot = 0xFF;
    const esp_partition_t* running = esp_ota_get_running_partition();
    if (!running) return f;
    if (running->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MIN && running->subtype < ESP_PARTITION_SUBTYPE_APP_OTA_MAX)
        f.running_slot = static_cast<std::uint8_t>(running->subtype - ESP_PARTITION_SUBTYPE_APP_OTA_MIN);
    esp_ota_img_states_t state{};
    f.pending_verify = esp_ota_get_state_partition(running, &state) == ESP_OK && state == ESP_OTA_IMG_PENDING_VERIFY;
    return f;
}
const char* slot_text(std::uint8_t slot) { return slot == 0 ? "ota_0" : slot == 1 ? "ota_1" : "unknown"; }
const char* running_version() { return esp_app_get_description()->version; }
bool mark_valid() { return esp_ota_mark_app_valid_cancel_rollback() == ESP_OK; }
void rollback_and_reboot() {
    esp_ota_mark_app_invalid_rollback_and_reboot();
    esp_restart();   // only reached when no previous valid slot exists; the bootloader decides
}

} // namespace sticks3::ota

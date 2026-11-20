// G16M: encrypted credential vault on the "nvs_cred" partition (see cred_vault.hpp).
#include "cred_vault.hpp"
#include "sdkconfig.h"
#include "esp_efuse.h"
#include "esp_hmac.h"
#include "esp_partition.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "nvs_sec_provider.h"

namespace sticks3::vault {
namespace {
using guardian::companion::BlobRead;
using guardian::setup::VaultState;
constexpr const char* ns = "guardian";
const char* state = "no_partition";
}

VaultState init() {
    if (!esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, partition_label)) { state = "no_partition"; return VaultState::Absent; }
    // The key must already be in the eFuse block, with the HMAC purpose. Checked here, before any
    // NVS security call, so no path of this firmware can ever create or burn one.
    const auto block = static_cast<esp_efuse_block_t>(EFUSE_BLK_KEY0 + CONFIG_GUARDIAN_CRED_HMAC_KEY_ID);
    if (esp_efuse_get_key_purpose(block) != ESP_EFUSE_KEY_PURPOSE_HMAC_UP) { state = "no_key"; return VaultState::Absent; }
    nvs_sec_config_hmac_t scheme_cfg{};
    scheme_cfg.hmac_key_id = static_cast<hmac_key_id_t>(CONFIG_GUARDIAN_CRED_HMAC_KEY_ID);
    nvs_sec_scheme_t* scheme = nullptr;
    if (nvs_sec_provider_register_hmac(&scheme_cfg, &scheme) != ESP_OK || !scheme) { state = "scheme_failed"; return VaultState::Error; }
    nvs_sec_cfg_t keys{};
    const esp_err_t derived = nvs_flash_read_security_cfg_v2(scheme, &keys);   // read only: derives, never generates
    if (derived != ESP_OK) { guardian::setup::wipe(&keys, sizeof keys); state = "key_derivation_failed"; return VaultState::Error; }
    const esp_err_t opened = nvs_flash_secure_init_partition(partition_label, &keys);
    guardian::setup::wipe(&keys, sizeof keys);
    if (opened != ESP_OK) { state = "open_failed"; return VaultState::Error; }   // never erased here: the owner decides (README)
    state = "ready";
    return VaultState::Ready;
}
const char* state_text() { return state; }

BlobRead Blob::read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const {
    if (!out) return BlobRead::Error;
    nvs_handle_t h{};
    const esp_err_t opened = nvs_open_from_partition(partition_label, ns, NVS_READONLY, &h);
    if (opened == ESP_ERR_NVS_NOT_FOUND) return BlobRead::Absent;
    if (opened != ESP_OK) return BlobRead::Error;
    std::size_t length = 0;
    const esp_err_t probed = nvs_get_blob(h, key_, nullptr, &length);
    BlobRead result = BlobRead::Error;
    if (probed == ESP_ERR_NVS_NOT_FOUND) result = BlobRead::Absent;
    else if (probed == ESP_OK && length <= capacity && nvs_get_blob(h, key_, out, &length) == ESP_OK) { size = length; result = BlobRead::Ok; }
    nvs_close(h);
    return result;
}
bool Blob::write(const std::uint8_t* data, std::size_t size) {
    nvs_handle_t h{};
    if (!data || nvs_open_from_partition(partition_label, ns, NVS_READWRITE, &h) != ESP_OK) return false;
    const bool ok = nvs_set_blob(h, key_, data, size) == ESP_OK && nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}
} // namespace sticks3::vault

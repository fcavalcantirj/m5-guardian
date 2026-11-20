#include "nvs_blob.hpp"
#include "nvs.h"
namespace sticks3 {
namespace { constexpr const char* ns = "guardian"; }
using guardian::companion::BlobRead;
// ESP_ERR_NVS_NOT_FOUND (namespace or key never written) is Absent; any other
// failure, or a stored blob larger than the record, is Error (never "nothing saved").
BlobRead NvsBlob::read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const {
    if (!out) return BlobRead::Error;
    nvs_handle_t h{};
    const esp_err_t opened = nvs_open(ns, NVS_READONLY, &h);
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
bool NvsBlob::write(const std::uint8_t* data, std::size_t size) {
    nvs_handle_t h{};
    if (!data || nvs_open(ns, NVS_READWRITE, &h) != ESP_OK) return false;
    const bool ok = nvs_set_blob(h, key_, data, size) == ESP_OK && nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}
}

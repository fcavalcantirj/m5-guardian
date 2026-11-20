#pragma once
// G14: NVS-backed BlobStorage for the owner's persisted network selection.
// Namespace "guardian" (shared with the G11 boot counter), key "selection".
// Never erases or re-initializes NVS; a missing/unreadable record restores nothing.
#include "companion.hpp"
namespace sticks3 {
class NvsBlob final : public guardian::companion::BlobStorage {
public:
    explicit NvsBlob(const char* key = "selection") : key_(key) {}
    guardian::companion::BlobRead read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const override;
    bool write(const std::uint8_t* data, std::size_t size) override;
private:
    const char* key_;
};
}

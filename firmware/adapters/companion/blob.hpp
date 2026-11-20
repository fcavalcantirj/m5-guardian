#pragma once
#include <cstddef>
#include <cstdint>

// Raw key-value blob the board provides (NVS on StickS3). SDK-free.
namespace guardian::companion {
// Absent (never written) and Error (present but not readable, or larger than
// the record) stay distinct so a storage fault is never shown as "nothing saved".
enum class BlobRead : std::uint8_t { Absent, Ok, Error };
class BlobStorage {
public:
    virtual ~BlobStorage() = default;
    virtual BlobRead read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const = 0; // size valid only on Ok
    virtual bool write(const std::uint8_t* data, std::size_t size) = 0;                      // false: not committed
};
} // namespace guardian::companion

#pragma once
// Review 2026-11-17 (memory): one boot-time placement rule for the StickS3's large,
// CPU-only objects and buffers. Measured on the device (guardian-20261117-052123):
// heap_internal_min fell from 86-96 KB (G16C) to 41 KB, and to 19 KB while the
// Wi-Fi TUNE session was joined; the internal DRAM is what the Wi-Fi driver needs.
//
// Rule (same as the G16F Monitor and the G16C portrait cache): allocate once at boot in
// PSRAM, internal DRAM only as a fallback, never freed. Never for task stacks, DMA
// buffers or anything an ISR or a flash-cache-disabled path touches:
//   ESP-IDF v5.4 docs/en/api-guides/external-ram.rst: "When flash cache is disabled
//   (for example, if the flash is being written to), the external RAM also becomes
//   inaccessible" and task stacks stay internal. The promiscuous callback runs in the
//   Wi-Fi task (not an ISR), which is suspended like every non-IRAM task while the
//   cache is off; NVS/esp_flash copy non-DRAM buffers through an internal bounce
//   buffer (components/spi_flash/esp_flash_api.c, direct_read/direct_write).
#include <cstddef>
#include <new>
#include <utility>
#include "esp_heap_caps.h"

namespace sticks3::psram {

enum class Where : unsigned char { None, Psram, Internal };
inline const char* where_text(Where w) {
    return w == Where::Psram ? "psram" : w == Where::Internal ? "internal" : "none";
}

// `size` bytes aligned to `align`: PSRAM first, internal DRAM as the fallback; nullptr
// (where = None) when neither has room. Never freed.
inline void* alloc(std::size_t size, std::size_t align, Where& where) {
    void* mem = heap_caps_aligned_alloc(align, size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    where = Where::Psram;
    if (!mem) { mem = heap_caps_aligned_alloc(align, size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT); where = Where::Internal; }
    if (!mem) where = Where::None;
    return mem;
}

// Constructs one T in place (see alloc). nullptr when there is no room anywhere.
template <class T, class... Args>
T* make(Where& where, Args&&... args) {
    void* mem = alloc(sizeof(T), alignof(T), where);
    return mem ? new (mem) T(std::forward<Args>(args)...) : nullptr;
}

} // namespace sticks3::psram

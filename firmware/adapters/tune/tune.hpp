#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include "blob.hpp"

// G16A live tuning. SDK-free and host-tested. Named, bounded float parameters
// that the serial console reads and changes ("TUNE?" / "TUNE key=value").
// A change is applied immediately and persisted as one versioned, CRC-checked
// blob (same style as the companion selection store): magic "GTUN", format,
// revision, entries keyed by name, CRC-32. Unknown keys and out-of-range
// values are rejected with a reason and change nothing. A stored blob that is
// corrupt, foreign or from another format is never used and never erased;
// stored entries whose key is no longer registered, or whose value is out of
// the current range, are ignored (the default stays). Art and physics tasks
// register their parameters here at boot, before load().
namespace guardian::tune {

using companion::BlobRead;
using companion::BlobStorage;

constexpr std::size_t max_params = 128;  // G16H: 56 board keys + 68 t.* keys = 124 (was 120). G16J: 44 board keys + 61 t.* keys (one per threat limit) = 105; G21: + 4 head.* keys = 109;
                                         // ota.auto_s and G16N's two power.dark* keys = 112 (the old size); G16O: + 4 burst.* keys = 116;
                                         // G16P: + power.sleep_check_s = 117
constexpr std::size_t max_key = 31;          // [a-z0-9._], not empty (stored blobs with shorter keys still load)
constexpr std::uint16_t format = 1;
constexpr std::size_t max_blob = 4 + 2 + 2 + 4 + max_params * (1 + max_key + 4) + 4;

struct Param {
    std::array<char, max_key + 1> key{};
    float min{}, max{}, def{}, value{};
};

enum class Store : std::uint8_t { Defaults, Restored, Rejected, Saved, SaveFailed };
const char* store_text(Store);

class Registry {
public:
    explicit Registry(BlobStorage& storage) : storage_(storage) {}
    // Registers a parameter; -1 on a bad key, duplicate, min > max, default
    // outside [min, max], non-finite bound or a full registry.
    int add(const char* key, float min, float max, float def);
    // Restores stored values (see header comment). Returns the resulting state.
    Store load();
    int find(const char* key) const;
    float get(int index) const { return index >= 0 && static_cast<std::size_t>(index) < count_ ? params_[index].value : 0.0f; }
    std::size_t count() const { return count_; }
    const Param& param(std::size_t i) const { return params_[i]; }
    Store store() const { return store_; }
    std::uint32_t revision() const { return revision_; }   // successful saves, persisted
    // "1.<revision>": format and persisted revision, as shown by STATUS tune_version=.
    void version(char* out, std::size_t n) const;
    // One console line. Returns false when `line` is not a TUNE command
    // (nothing written). Otherwise writes one or more '\n'-terminated reply
    // lines ("TUNE ..." / "TUNE ERROR <reason>") into out.
    bool command(const char* line, char* out, std::size_t n);
    // Programmatic set with the same rules; reason is static text on failure.
    bool set(const char* key, float value, const char*& reason);

    // Codec, exposed for tests.
    std::size_t encode(std::uint8_t* out, std::size_t capacity, std::uint32_t revision) const;

private:
    bool save();
    BlobStorage& storage_;
    std::array<Param, max_params> params_{};
    // Review 2026-11-17 (memory): the load/save working memory is part of the
    // Registry (one blob shared by load and save, which never overlap), so it
    // lives wherever the owner places the Registry (the StickS3 puts it in PSRAM)
    // instead of in internal .bss or on the task stack.
    struct Entry { char key[max_key + 1]; float value; };
    std::array<std::uint8_t, max_blob> blob_{};
    std::array<Entry, max_params> parsed_{};
    std::size_t count_{};
    Store store_{Store::Defaults};
    std::uint32_t revision_{};
};

} // namespace guardian::tune

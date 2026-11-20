// G16A: live-tuning registry, console parser and NVS-style persistence (host).
#include "check.hpp"
#include "tune.hpp"
#include <cmath>
#include <cstring>
#include <string>
#include <vector>

using namespace guardian::tune;

namespace {
class MemoryBlob final : public BlobStorage {
public:
    std::vector<std::uint8_t> bytes; bool exists{}, fail_write{}, fail_read{}; unsigned writes{};
    BlobRead read(std::uint8_t* out, std::size_t capacity, std::size_t& size) const override {
        if (!exists) return BlobRead::Absent;
        if (fail_read || bytes.size() > capacity) return BlobRead::Error;
        std::memcpy(out, bytes.data(), bytes.size()); size = bytes.size(); return BlobRead::Ok;
    }
    bool write(const std::uint8_t* data, std::size_t size) override {
        ++writes; if (fail_write) return false;
        bytes.assign(data, data + size); exists = true; return true;
    }
};
void standard(Registry& r) {
    r.add("persona.tilt_deg", 0.0f, 3.0f, 1.2f);
    r.add("persona.smoke", 0.0f, 1.0f, 0.62f);
}
std::string run(Registry& r, const char* line) {
    char out[1024] = "<untouched>";
    if (!r.command(line, out, sizeof out)) return "<not tune>";
    return out;
}
bool has(const std::string& s, const char* needle) { return s.find(needle) != std::string::npos; }
}

GUARDIAN_CASE(registry_accepts_only_well_formed_bounded_parameters) {
    MemoryBlob blob; Registry r(blob);
    CHECK_EQ(r.add("persona.tilt_deg", 0.0f, 3.0f, 1.2f), 0);
    CHECK_EQ(r.add("persona.tilt_deg", 0.0f, 3.0f, 1.2f), -1);          // duplicate
    CHECK_EQ(r.add("Bad Key", 0.0f, 1.0f, 0.5f), -1);                    // charset
    CHECK_EQ(r.add("", 0.0f, 1.0f, 0.5f), -1);
    CHECK_EQ(r.add("a.very.long.key.over.31.chars.xy", 0.0f, 1.0f, 0.5f), -1);  // 32 chars
    CHECK(r.add("t.deauth_broadcast_window_ms", 0.0f, 1.0f, 0.5f) >= 0);   // 28 chars: threat limits fit
    CHECK_EQ(r.add("x", 1.0f, 0.0f, 0.5f), -1);                          // min > max
    CHECK_EQ(r.add("x", 0.0f, 1.0f, 2.0f), -1);                          // default outside
    CHECK_EQ(r.add("x", 0.0f, NAN, 0.5f), -1);
    CHECK_EQ(r.add("x", 0.0f, 1.0f, 0.5f), 2);
    CHECK_EQ(r.find("x"), 2); CHECK_EQ(r.find("y"), -1);
    CHECK(std::fabs(r.get(0) - 1.2f) < 1e-6f);
    for (std::size_t i = r.count(); i < max_params; ++i) {
        char key[8]; std::snprintf(key, sizeof key, "k%zu", i); CHECK(r.add(key, 0, 1, 0) >= 0);
    }
    CHECK_EQ(r.add("overflow", 0, 1, 0), -1);
}

GUARDIAN_CASE(non_tune_lines_are_left_alone) {
    MemoryBlob blob; Registry r(blob); standard(r);
    CHECK_EQ(run(r, "STATUS"), std::string("<not tune>"));
    CHECK_EQ(run(r, "TUNER x=1"), std::string("<not tune>"));
    CHECK_EQ(run(r, "select 001122334455 ap BR"), std::string("<not tune>"));
}

GUARDIAN_CASE(query_lists_every_parameter_with_bounds_and_version) {
    MemoryBlob blob; Registry r(blob); standard(r); CHECK(r.load() == Store::Defaults);
    const auto out = run(r, "TUNE?");
    CHECK(has(out, "TUNE persona.tilt_deg=1.2 min=0 max=3 default=1.2\n"));
    CHECK(has(out, "TUNE persona.smoke=0.62 min=0 max=1 default=0.62\n"));
    CHECK(has(out, "TUNE OK params=2 version=1.0 store=defaults\n"));
    CHECK_EQ(blob.writes, 0u);
}

GUARDIAN_CASE(set_applies_immediately_and_persists_a_new_revision) {
    MemoryBlob blob; Registry r(blob); standard(r); r.load();
    const auto out = run(r, "TUNE persona.tilt_deg=2.5");
    CHECK_EQ(out, std::string("TUNE OK persona.tilt_deg=2.5 version=1.1 saved\n"));
    CHECK(std::fabs(r.get(r.find("persona.tilt_deg")) - 2.5f) < 1e-6f);
    CHECK_EQ(blob.writes, 1u); CHECK(r.store() == Store::Saved); CHECK_EQ(r.revision(), 1u);
    CHECK(has(run(r, "TUNE persona.smoke = 0.25"), "TUNE OK persona.smoke=0.25 version=1.2"));   // spaces around '='
    // A fresh boot restores both values and the revision.
    Registry again(blob); standard(again);
    CHECK(again.load() == Store::Restored);
    CHECK(std::fabs(again.get(0) - 2.5f) < 1e-6f); CHECK(std::fabs(again.get(1) - 0.25f) < 1e-6f);
    char v[16]; again.version(v, sizeof v); CHECK_EQ(std::string(v), std::string("1.2"));
    CHECK_EQ(blob.writes, 2u);                                                       // load never writes
}

GUARDIAN_CASE(invalid_requests_are_rejected_with_a_reason_and_change_nothing) {
    MemoryBlob blob; Registry r(blob); standard(r); r.load();
    const struct { const char* line; const char* reason; } cases[] = {
        {"TUNE nope=1", "TUNE ERROR unknown key nope\n"},
        {"TUNE persona.tilt_deg=3.5", "TUNE ERROR out of range persona.tilt_deg [0, 3]\n"},
        {"TUNE persona.tilt_deg=-0.1", "TUNE ERROR out of range persona.tilt_deg [0, 3]\n"},
        {"TUNE persona.tilt_deg=abc", "TUNE ERROR not a number\n"},
        {"TUNE persona.tilt_deg=1.0x", "TUNE ERROR not a number\n"},
        {"TUNE persona.tilt_deg=nan", "TUNE ERROR not a number\n"},
        {"TUNE persona.tilt_deg=inf", "TUNE ERROR not a number\n"},
        {"TUNE persona.tilt_deg=", "TUNE ERROR not a number\n"},
        {"TUNE persona.tilt_deg", "TUNE ERROR use TUNE key=value or TUNE?\n"},
        {"TUNE", "TUNE ERROR use TUNE key=value or TUNE?\n"},
        {"TUNE =1", "TUNE ERROR use TUNE key=value or TUNE?\n"},
    };
    for (const auto& c : cases) CHECK_EQ(run(r, c.line), std::string(c.reason));
    CHECK(std::fabs(r.get(0) - 1.2f) < 1e-6f); CHECK_EQ(blob.writes, 0u); CHECK_EQ(r.revision(), 0u);
}

GUARDIAN_CASE(storage_failure_is_reported_and_the_value_is_live_until_reboot) {
    MemoryBlob blob; Registry r(blob); standard(r); r.load();
    blob.fail_write = true;
    CHECK_EQ(run(r, "TUNE persona.smoke=0.5"), std::string("TUNE ERROR not saved (storage); persona.smoke=0.5 applied until reboot\n"));
    CHECK(std::fabs(r.get(1) - 0.5f) < 1e-6f); CHECK(r.store() == Store::SaveFailed); CHECK_EQ(r.revision(), 0u);
}

GUARDIAN_CASE(corrupt_foreign_or_unreadable_blobs_are_never_used_or_erased) {
    MemoryBlob good; { Registry r(good); standard(r); r.load(); run(r, "TUNE persona.tilt_deg=2"); }
    const auto pristine = good.bytes;
    const auto check_rejected = [&](MemoryBlob& blob) {
        Registry r(blob); standard(r);
        CHECK(r.load() == Store::Rejected); CHECK(std::fabs(r.get(0) - 1.2f) < 1e-6f); CHECK_EQ(r.revision(), 0u);
        CHECK_EQ(blob.writes, 0u);
        char v[16]; r.version(v, sizeof v); CHECK_EQ(std::string(v), std::string("1.0"));
    };
    { MemoryBlob b; b.exists = true; b.bytes = pristine; b.bytes[b.bytes.size() - 1] ^= 1; check_rejected(b); }   // CRC
    { MemoryBlob b; b.exists = true; b.bytes = pristine; b.bytes[0] = 'X'; check_rejected(b); }                   // magic
    { MemoryBlob b; b.exists = true; b.bytes = pristine; b.bytes[4] = 9; check_rejected(b); }                     // format
    { MemoryBlob b; b.exists = true; b.bytes = pristine; b.bytes.pop_back(); check_rejected(b); }                 // truncated
    { MemoryBlob b; b.exists = true; b.fail_read = true; check_rejected(b); }                                     // unreadable
    const auto out = [&] { MemoryBlob b; b.exists = true; b.fail_read = true; Registry r(b); standard(r); r.load(); return run(r, "TUNE?"); }();
    CHECK(has(out, "store=rejected"));
}

GUARDIAN_CASE(stored_entries_for_unknown_keys_or_out_of_range_values_are_ignored) {
    // An older/newer build stored different parameters and bounds.
    MemoryBlob blob;
    { Registry wide(blob); wide.add("persona.tilt_deg", 0, 10, 1.2f); wide.add("retired.key", 0, 1, 0.5f);
      wide.add("persona.smoke", 0, 1, 0.62f); wide.load();
      run(wide, "TUNE persona.tilt_deg=7"); run(wide, "TUNE retired.key=0.9"); run(wide, "TUNE persona.smoke=0.1"); }
    Registry r(blob); standard(r);
    CHECK(r.load() == Store::Restored);
    CHECK(std::fabs(r.get(0) - 1.2f) < 1e-6f);     // 7 is outside today's [0, 3]: default kept
    CHECK(std::fabs(r.get(1) - 0.1f) < 1e-6f);     // still valid: restored
    CHECK_EQ(r.revision(), 3u);
}

GUARDIAN_CASE(encoded_blob_fits_the_declared_bound) {
    MemoryBlob blob; Registry r(blob);
    for (std::size_t i = 0; i < max_params; ++i) {
        char key[max_key + 1]; std::snprintf(key, sizeof key, "param.number.%010zu", i); CHECK(r.add(key, 0, 1, 0.5f) >= 0);
    }
    std::uint8_t out[max_blob]; CHECK(r.encode(out, sizeof out, 7) > 0); CHECK(r.encode(out, sizeof out, 7) <= max_blob);
    CHECK_EQ(r.encode(out, 10, 7), std::size_t{0});
}

// Supervisor review (2026-11-17): G16F/G16G thresholds become TUNE keys (t.*),
// so the registry grows; a listing must be filterable and never cut silently.
GUARDIAN_CASE(query_with_a_prefix_lists_only_that_group) {
    MemoryBlob blob; Registry r(blob); standard(r);
    r.add("t.probe_flood", 1.0f, 1000.0f, 80.0f);
    r.add("t.probe_window_ms", 0.0f, 600000.0f, 5000.0f);
    r.load();
    const std::string out = run(r, "TUNE? t.probe");
    CHECK(has(out, "TUNE t.probe_flood=80 ")); CHECK(has(out, "TUNE t.probe_window_ms=5000 "));
    CHECK(!has(out, "persona.")); CHECK(has(out, "TUNE OK params=2 of 4 prefix=t.probe "));
    CHECK(has(run(r, "TUNE? nothing.here"), "TUNE OK params=0 of 4 prefix=nothing.here "));
    CHECK_EQ(run(r, "TUNE?x"), std::string("TUNE ERROR use TUNE key=value or TUNE?\n"));
}

GUARDIAN_CASE(a_listing_that_does_not_fit_ends_with_a_visible_more_line) {
    MemoryBlob blob; Registry r(blob);
    for (std::size_t i = 0; i < 40; ++i) { char key[24]; std::snprintf(key, sizeof key, "t.key_number_%02zu", i); r.add(key, 0, 1000, 500); }
    r.load();
    char out[600];
    CHECK(r.command("TUNE?", out, sizeof out));
    const std::string s(out);
    CHECK(has(s, "TUNE MORE "));                       // the reader is told the list continues
    CHECK(s.size() < sizeof out); CHECK(!s.empty() && s.back() == '\n');   // never a cut line
    std::size_t lines = 0; for (char c : s) lines += c == '\n';
    CHECK(lines >= 3);
}

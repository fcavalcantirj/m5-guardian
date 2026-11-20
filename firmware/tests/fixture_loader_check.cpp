// Fixture scaffolding checks (G03). These test the loader and the fixture
// files' self-consistency; they do NOT parse 802.11 (that is G04). Every
// fixture declares expect.* metadata that make_fixtures.py computed from the
// same bytes; a hand edit that breaks the frame will fail here first.
#include "check.hpp"
#include "fixtures.hpp"

#include "guardian/radio.hpp"

#include <cstdlib>

using namespace guardian;
using guardian::fixtures::Fixture;

GUARDIAN_CASE(parse_hex_text_accepts_comments_whitespace_and_metadata) {
    Fixture f;
    std::string err;
    CHECK(fixtures::parse_hex_text("# expect.length: 3\n# expect.name : x y \n  80 00\n\tc0 # trailing\n", f, err));
    CHECK_EQ(f.bytes.size(), std::size_t{3});
    CHECK_EQ(f.bytes[0], 0x80);
    CHECK_EQ(f.bytes[2], 0xC0);
    CHECK_EQ(f.meta.at("length"), std::string("3"));
    CHECK_EQ(f.meta.at("name"), std::string("x y"));
    CHECK(err.empty());
    CHECK(fixtures::parse_hex_text("", f, err));
    CHECK(f.bytes.empty());
}

GUARDIAN_CASE(parse_hex_text_rejects_malformed_tokens_instead_of_shortening) {
    Fixture f;
    std::string err;
    CHECK(!fixtures::parse_hex_text("80 0\n", f, err));   // odd nibble
    CHECK(!err.empty());
    CHECK(!fixtures::parse_hex_text("80 zz\n", f, err));  // not hex
    CHECK(!fixtures::parse_hex_text("8000\n", f, err));   // run-together bytes are refused too
    CHECK(!fixtures::parse_hex_text("# expect.broken 7\n", f, err)); // metadata without ':'
    std::vector<std::uint8_t> b;
    CHECK(fixtures::hex_to_bytes("021122334455", b));
    CHECK_EQ(b.size(), std::size_t{6});
    CHECK_EQ(b[5], 0x55);
    CHECK(!fixtures::hex_to_bytes("0211223344", b) || b.size() == 5);
    CHECK(!fixtures::hex_to_bytes("02112233445", b));
    CHECK(!fixtures::hex_to_bytes("0211223344gg", b));
}

GUARDIAN_CASE(load_reports_a_missing_fixture_as_an_error) {
    Fixture f;
    std::string err;
    CHECK(!fixtures::load("does_not_exist_" __DATE__, f, err));
    CHECK(err.find("cannot open") != std::string::npos);
}

GUARDIAN_CASE(fixture_directory_has_the_scaffolding_set) {
    const auto names = fixtures::list();
    CHECK(names.size() >= 10); // the G03 set; G04 adds more, never fewer
    bool have_open = false, have_wpa3 = false, have_truncated = false, have_deauth = false, have_short = false;
    for (const auto& n : names) {
        have_open |= n == "beacon_open";
        have_wpa3 |= n == "beacon_wpa3_sae_pmf_required";
        have_truncated |= n == "beacon_rsn_truncated_ie";
        have_deauth |= n == "deauth_reason7";
        have_short |= n == "mgmt_header_short_23";
    }
    CHECK(have_open);
    CHECK(have_wpa3);
    CHECK(have_truncated);
    CHECK(have_deauth);
    CHECK(have_short);
}

GUARDIAN_CASE(every_fixture_matches_its_declared_metadata) {
    const auto names = fixtures::list();
    CHECK(!names.empty());
    for (const auto& name : names) {
        Fixture f;
        std::string err;
        if (!fixtures::load(name, f, err)) {
            CHECK_FAIL(err);
            continue;
        }
        // Declared length and first byte must match the bytes exactly.
        if (!f.meta.count("length") || !f.meta.count("fc0")) {
            CHECK_FAIL(name + ": missing expect.length / expect.fc0");
            continue;
        }
        CHECK_EQ(f.bytes.size(), static_cast<std::size_t>(std::strtoul(f.meta.at("length").c_str(), nullptr, 10)));
        CHECK(!f.bytes.empty());
        CHECK_EQ(f.bytes[0], static_cast<std::uint8_t>(std::strtoul(f.meta.at("fc0").c_str(), nullptr, 16)));
        // Frame Control byte 0: protocol version bits 0..1 must be 0 and type
        // bits 2..3 must be Management (00) for every G03 fixture.
        CHECK_EQ(f.bytes[0] & 0x0F, 0);
        // Fixtures with a declared BSSID are full management frames.
        if (f.meta.count("bssid")) {
            std::vector<std::uint8_t> bssid;
            CHECK(fixtures::hex_to_bytes(f.meta.at("bssid"), bssid));
            CHECK_EQ(bssid.size(), std::size_t{6});
            CHECK(f.bytes.size() >= 24);
            if (f.bytes.size() >= 24 && bssid.size() == 6)
                for (std::size_t i = 0; i < 6; ++i) CHECK_EQ(f.bytes[16 + i], bssid[i]);
            CHECK_EQ(bssid[0] & 1, 0); // fixture BSSID is unicast
        }
        // Declared RSN offset must land on element id 48 with a length that fits
        // or, for the truncated counterexample, deliberately does not.
        if (f.meta.count("rsn_offset")) {
            const std::size_t off = std::strtoul(f.meta.at("rsn_offset").c_str(), nullptr, 10);
            CHECK(off + 2 <= f.bytes.size());
            if (off + 2 <= f.bytes.size()) {
                CHECK_EQ(f.bytes[off], 48);
                const bool fits = off + 2 + f.bytes[off + 1] <= f.bytes.size();
                CHECK_EQ(fits, name != "beacon_rsn_truncated_ie");
            }
        }
        if (f.meta.count("reason")) {
            CHECK(f.bytes.size() >= 26); // header + reason; G04 adds a BIP fixture with a trailing MME
            const unsigned reason = static_cast<unsigned>(f.bytes[24]) | (static_cast<unsigned>(f.bytes[25]) << 8);
            CHECK_EQ(reason, static_cast<unsigned>(std::strtoul(f.meta.at("reason").c_str(), nullptr, 10)));
        }
        if (f.meta.count("retry")) CHECK_EQ((f.bytes[1] >> 3) & 1, 1);
    }
}

GUARDIAN_CASE(fixture_bytes_fit_the_frame_span_contract) {
    // A fixture becomes a FrameSpan over caller-owned storage: FCS-free, size =
    // bytes present. This shows the intended wiring for G04 without parsing.
    Fixture f;
    std::string err;
    if (!fixtures::load("beacon_wpa2_ccmp_pmf_optional", f, err)) { CHECK_FAIL(err); return; }
    FrameSpan span{f.bytes.data(), static_cast<std::uint16_t>(f.bytes.size()), false};
    CHECK_EQ(span.size, 77);
    CHECK_EQ(span.bytes[0], 0x80);          // beacon
    CHECK_EQ(span.bytes[34] & 0x10, 0x10);  // Privacy bit in Capability Information
    RxMeta meta{};
    meta.reported_length = static_cast<std::uint16_t>(span.size + 4); // as a driver reporting FCS would
    meta.origin = Origin::Imported;          // fixtures are never live evidence
    CHECK_EQ(meta.reported_length - 4, span.size);
}

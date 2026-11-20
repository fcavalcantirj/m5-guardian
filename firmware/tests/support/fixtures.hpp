#pragma once
// Host-only fixture loader for firmware/tests/fixtures/*.hex (G03 scaffolding).
//
// Format (written by make_fixtures.py): `#` starts a comment to end of line;
// `# expect.<key>: <value>` comment lines are metadata; everything else is hex
// digit pairs separated by whitespace. Loading is strict: an odd number of
// digits or any non-hex token is an error, never a silently shorter frame.
//
// The loader returns bytes that are ALREADY FCS-free (the fixtures are written
// without an FCS), matching the FrameSpan byte identity in guardian/radio.hpp.
// Fixture bytes are Origin::Imported evidence; nothing here is radio proof.
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace guardian::fixtures {

struct Fixture {
    std::string name;                         // file stem
    std::vector<std::uint8_t> bytes;          // decoded frame, FCS-free
    std::map<std::string, std::string> meta;  // expect.<key> -> value
};

// Parses fixture text. On failure returns false and sets `error`.
bool parse_hex_text(const std::string& text, Fixture& out, std::string& error);

// Directory compiled in by CMake (GUARDIAN_FIXTURE_DIR), i.e. the source tree.
std::string directory();

// Loads <directory()>/<name>.hex. On failure returns false and sets `error`.
bool load(const std::string& name, Fixture& out, std::string& error);

// Stems of every *.hex file in directory(), sorted. Empty if unreadable.
std::vector<std::string> list();

// Decodes a hex string ("021122334455") into bytes; false on malformed input.
bool hex_to_bytes(const std::string& hex, std::vector<std::uint8_t>& out);

} // namespace guardian::fixtures

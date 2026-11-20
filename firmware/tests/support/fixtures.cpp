#include "fixtures.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifndef GUARDIAN_FIXTURE_DIR
#error "GUARDIAN_FIXTURE_DIR must be defined by the build (see firmware/CMakeLists.txt)"
#endif

namespace guardian::fixtures {

namespace {

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string trim(const std::string& s) {
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

} // namespace

bool hex_to_bytes(const std::string& hex, std::vector<std::uint8_t>& out) {
    out.clear();
    if (hex.size() % 2 != 0) return false;
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = hex_value(hex[i]);
        const int lo = hex_value(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<std::uint8_t>(hi * 16 + lo));
    }
    return true;
}

bool parse_hex_text(const std::string& text, Fixture& out, std::string& error) {
    out.bytes.clear();
    out.meta.clear();
    std::istringstream lines(text);
    std::string line;
    int line_no = 0;
    while (std::getline(lines, line)) {
        ++line_no;
        const std::size_t hash = line.find('#');
        if (hash != std::string::npos) {
            const std::string comment = trim(line.substr(hash + 1));
            const std::string key = "expect.";
            if (comment.compare(0, key.size(), key) == 0) {
                const std::size_t colon = comment.find(':');
                if (colon == std::string::npos) {
                    error = "line " + std::to_string(line_no) + ": expect metadata without ':'";
                    return false;
                }
                out.meta[trim(comment.substr(key.size(), colon - key.size()))] = trim(comment.substr(colon + 1));
            }
            line = line.substr(0, hash);
        }
        std::istringstream tokens(line);
        std::string tok;
        while (tokens >> tok) {
            if (tok.size() != 2) {
                error = "line " + std::to_string(line_no) + ": token '" + tok + "' is not a hex byte";
                return false;
            }
            const int hi = hex_value(tok[0]);
            const int lo = hex_value(tok[1]);
            if (hi < 0 || lo < 0) {
                error = "line " + std::to_string(line_no) + ": token '" + tok + "' is not a hex byte";
                return false;
            }
            out.bytes.push_back(static_cast<std::uint8_t>(hi * 16 + lo));
        }
    }
    error.clear();
    return true;
}

std::string directory() { return GUARDIAN_FIXTURE_DIR; }

bool load(const std::string& name, Fixture& out, std::string& error) {
    const std::string path = directory() + "/" + name + ".hex";
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot open " + path;
        return false;
    }
    std::stringstream buf;
    buf << in.rdbuf();
    out.name = name;
    if (!parse_hex_text(buf.str(), out, error)) {
        error = path + ": " + error;
        return false;
    }
    return true;
}

std::vector<std::string> list() {
    std::vector<std::string> names;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(directory(), ec)) {
        if (ec) return {};
        const auto& p = entry.path();
        // Skip macOS AppleDouble shadows ("._name.hex") that an SMB checkout can carry.
        if (p.extension() == ".hex" && p.filename().string().rfind("._", 0) != 0) names.push_back(p.stem().string());
    }
    std::sort(names.begin(), names.end());
    return names;
}

} // namespace guardian::fixtures

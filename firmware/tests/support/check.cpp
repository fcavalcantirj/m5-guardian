#include "check.hpp"

#include <cstring>

namespace guardian::check {
namespace {

struct Entry {
    const char* name;
    CaseFn fn;
};

std::vector<Entry>& registry() {
    static std::vector<Entry> r;
    return r;
}

} // namespace

Registrar::Registrar(const char* name, CaseFn fn) { registry().push_back({name, fn}); }

int run(int argc, char** argv) {
    bool list = false;
    std::vector<const char*> only;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--list") == 0) list = true;
        else only.push_back(argv[i]);
    }
    const auto& cases = registry();
    if (list) {
        for (const auto& e : cases) std::printf("%s\n", e.name);
        return 0;
    }
    // A typo must not silently shrink a requested check set.
    for (const char* requested : only) {
        bool found = false;
        for (const auto& e : cases) if (std::strcmp(requested, e.name) == 0) found = true;
        if (!found) {
            std::printf("RESULT: FAIL (unknown case: %s)\n", requested);
            return 3;
        }
    }
    std::size_t ran = 0, assertions = 0, failed_cases = 0, failed_assertions = 0;
    for (const auto& e : cases) {
        if (!only.empty()) {
            bool selected = false;
            for (const char* n : only) if (std::strcmp(n, e.name) == 0) selected = true;
            if (!selected) continue;
        }
        Case c(e.name);
        e.fn(c);
        if (c.assertions() == 0) c.fail("case executed no assertions", __FILE__, __LINE__);
        ++ran;
        assertions += c.assertions();
        if (c.failures().empty()) {
            std::printf("ok   %s (%zu assertions)\n", e.name, c.assertions());
        } else {
            ++failed_cases;
            failed_assertions += c.failures().size();
            std::printf("FAIL %s (%zu of %zu assertions failed)\n", e.name, c.failures().size(), c.assertions());
            for (const auto& f : c.failures()) std::printf("     %s:%d: %s\n", f.file, f.line, f.text.c_str());
        }
    }
    std::printf("summary: %zu cases run, %zu registered, %zu assertions, %zu failed cases, %zu failed assertions\n",
                ran, cases.size(), assertions, failed_cases, failed_assertions);
    if (ran == 0) { std::printf("RESULT: FAIL (no case ran; a harness with no cases is not a pass)\n"); return 3; }
    if (assertions == 0) { std::printf("RESULT: FAIL (no assertion ran; a vacuous harness is not a pass)\n"); return 4; }
    if (failed_cases) { std::printf("RESULT: FAIL\n"); return 1; }
    std::printf("RESULT: PASS\n");
    return 0;
}

} // namespace guardian::check

int main(int argc, char** argv) { return guardian::check::run(argc, argv); }

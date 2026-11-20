#pragma once
// Minimal host check framework for the Guardian host harness (G03).
//
// Deliberately tiny and dependency-free: no download, no license to carry, and
// nothing a reviewer must trust blindly. Each test executable links
// guardian_test_support, which supplies main(). A run prints one line per case
// and a summary, and exits non-zero on any failed assertion, on zero registered
// cases, unknown requested cases, or any case with zero assertions. `--list` prints case names; a case name argument runs that case only.
//
// This is host test support, not library code: it may use the C++ standard
// library freely (vector/string/printf). Nothing under components/ includes it.
#include <cstdint>
#include <cstdio>
#include <string>
#include <type_traits>
#include <vector>

namespace guardian::check {

struct Failure {
    std::string text;
    const char* file;
    int line;
};

class Case {
public:
    explicit Case(const char* name) : name_(name) {}
    const char* name() const { return name_; }
    std::size_t assertions() const { return assertions_; }
    const std::vector<Failure>& failures() const { return failures_; }

    bool expect(bool ok, const char* expr, const char* file, int line) {
        ++assertions_;
        if (!ok) failures_.push_back({std::string("CHECK(") + expr + ")", file, line});
        return ok;
    }

    template <class A, class B>
    bool expect_eq(const A& a, const B& b, const char* ea, const char* eb, const char* file, int line) {
        ++assertions_;
        const bool ok = (a == b);
        if (!ok) {
            failures_.push_back({std::string("CHECK_EQ(") + ea + ", " + eb + ") got " + show(a) + " vs " + show(b), file, line});
        }
        return ok;
    }

    // Explicit, named failure for a case that could not even start (e.g. missing fixture).
    void fail(const std::string& why, const char* file, int line) {
        ++assertions_;
        failures_.push_back({why, file, line});
    }

private:
    template <class T>
    static std::string show(const T& v) {
        if constexpr (std::is_enum_v<T>) {
            return std::to_string(static_cast<long long>(static_cast<std::underlying_type_t<T>>(v)));
        } else if constexpr (std::is_same_v<T, bool>) {
            return v ? "true" : "false";
        } else if constexpr (std::is_integral_v<T>) {
            return std::to_string(static_cast<long long>(v));
        } else if constexpr (std::is_convertible_v<T, std::string>) {
            return std::string(v);
        } else {
            return "<value>";
        }
    }

    const char* name_;
    std::size_t assertions_{};
    std::vector<Failure> failures_;
};

using CaseFn = void (*)(Case&);

struct Registrar {
    Registrar(const char* name, CaseFn fn);
};

// Runs every registered case (or the ones named in argv). Returns the process
// exit code: 0 only when every requested case exists, every executed case
// made at least one assertion, at least one case ran, and nothing failed.
int run(int argc, char** argv);

} // namespace guardian::check

#define GUARDIAN_CASE(name)                                                        \
    static void name(::guardian::check::Case& c_);                                 \
    static ::guardian::check::Registrar name##_registrar(#name, &name);            \
    static void name(::guardian::check::Case& c_)

#define CHECK(expr) c_.expect(static_cast<bool>(expr), #expr, __FILE__, __LINE__)
#define CHECK_EQ(a, b) c_.expect_eq((a), (b), #a, #b, __FILE__, __LINE__)
#define CHECK_FAIL(why) c_.fail((why), __FILE__, __LINE__)

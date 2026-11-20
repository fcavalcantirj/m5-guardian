// Deliberate child cases for checking the host test framework itself.
// CTest uses expect_process.cmake to assert their exact expected exit statuses.
#include "check.hpp"
GUARDIAN_CASE(one_check) { CHECK(true); }
GUARDIAN_CASE(empty_case) { (void)c_; }
GUARDIAN_CASE(failing_case) { CHECK(false); }

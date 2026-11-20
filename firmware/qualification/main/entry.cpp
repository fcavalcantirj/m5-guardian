// Native app entry only; no radio, board peripherals or PSRAM initialization.
// Linking this is NOT evidence that app_main or the tests executed on a board.
#include <cstdio>
int guardian_profile_checks();
extern "C" void app_main() {
    const int result = guardian_profile_checks();
    std::printf("G12 native result=%d (imported fixtures only)\n", result);
}

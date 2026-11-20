#pragma once
// Measurement screen redraw schedule. The normal cadence is 250 ms, but while the
// selected AP is fresh the screen is also redrawn exactly when its evidence
// expires, so "No fresh data" never waits for the next cadence tick (G13).
#include "guardian/time.hpp"
namespace sticks3 {
struct RedrawSchedule {
    static constexpr guardian::Millis default_cadence_ms = 250;
    // G16C: animated face screens set a shorter cadence (TUNE display.frame_ms).
    guardian::Millis cadence_ms = default_cadence_ms;
    guardian::Millis last = 0, stale_due = 0;
    bool drawn_once = false, has_due = false;
    bool due(guardian::Millis now) const {
        return !drawn_once || now - last >= cadence_ms || (has_due && now >= stale_due);
    }
    void drawn(guardian::Millis now, bool has_security, guardian::Millis age_ms, guardian::Millis fresh_ms) {
        last = now; drawn_once = true;
        has_due = has_security && age_ms < fresh_ms;
        stale_due = has_due ? now + (fresh_ms - age_ms) : 0;
    }
};
}

#pragma once

#include "guardian/capabilities.hpp"
#include "guardian/presenter.hpp"

// Presentation output boundary. The presenter produces a ViewModel; whatever
// shows it implements StatusOutput. A board renderer paints pixels from it, a
// headless adapter prints a line, a test records it. Nothing below this
// interface is portable and nothing above it may draw.
namespace guardian {

class StatusOutput {
public:
    virtual ~StatusOutput() = default;
    // Called by the application task after each presenter step. `snapshot` is
    // supplied so an output can show evidence detail (BSSID, age, counts)
    // without the presenter widening ViewModel. Both are values owned by the
    // caller for the duration of the call.
    virtual void show(const ViewModel& view, const Snapshot& snapshot, Millis now) = 0;
    // What this output can do; the presenter (G08) consults it to choose
    // static vs animated expressions and whether text advice fits.
    virtual const DisplayCapabilities& display() const = 0;
};

} // namespace guardian

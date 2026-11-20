// G16H coexistence spike: passive BLE scanning on the StickS3 (spike build variant only).
// NimBLE usage follows the pinned ESP-IDF v5.4 examples/bluetooth/nimble/blecent
// (nimble_port_init, ble_hs_cfg.sync_cb, nimble_port_freertos_init, ble_gap_disc
// with passive = 1); see ble_spike.hpp for what this never does.
#include "ble_spike.hpp"
#if CONFIG_GUARDIAN_BLE_SPIKE
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include <atomic>

namespace sticks3::ble {
namespace {
using guardian::coex::Duty;
std::atomic<State> state_{State::Off};
std::atomic<std::uint32_t> reports_{0}, errors_{0};
std::atomic<int> last_error_{0};
std::atomic<std::uint32_t> wanted_{0};   // window_ms << 16 | interval_ms
std::uint32_t pack(const Duty& d) { return static_cast<std::uint32_t>(d.window_ms) << 16 | d.interval_ms; }
Duty unpack(std::uint32_t v) { return {static_cast<std::uint16_t>(v >> 16), static_cast<std::uint16_t>(v & 0xffffu)}; }

// Host task context. Counted, never stored: the event's address and data are not read.
int on_gap(ble_gap_event* event, void*) {
    if (event && event->type == BLE_GAP_EVENT_DISC) reports_.fetch_add(1, std::memory_order_relaxed);
    return 0;
}
int set_scan(const Duty& d) {
    if (ble_gap_disc_active()) {
        const int rc = ble_gap_disc_cancel();
        if (rc != 0 && rc != BLE_HS_EALREADY) return rc;
    }
    if (!d.on()) return 0;
    ble_gap_disc_params p{};
    p.itvl = guardian::coex::ble_units(d.interval_ms);
    p.window = guardian::coex::ble_units(d.window_ms);
    p.filter_policy = 0;
    p.limited = 0;
    p.passive = 1;              // never a scan request: receive only
    p.filter_duplicates = 0;    // every report reaches the count (flood rates need them all)
    return ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &p, on_gap, nullptr);
}
void record(int rc) { if (rc != 0) { errors_.fetch_add(1); last_error_ = rc; } }
void on_sync() { state_ = State::Ready; record(set_scan(unpack(wanted_.load()))); }
void on_reset(int reason) { state_ = State::Starting; errors_.fetch_add(1); last_error_ = reason; }
void host_task(void*) {
    nimble_port_run();   // returns only after nimble_port_stop()
    nimble_port_freertos_deinit();
}
} // namespace

const char* state_text(State s) {
    switch (s) {
    case State::Off: return "off";
    case State::Starting: return "starting";
    case State::Ready: return "ready";
    case State::Failed: return "failed";
    }
    return "failed";
}
bool init() {
    State expected = State::Off;
    if (!state_.compare_exchange_strong(expected, State::Starting)) return state_.load() != State::Failed;
    if (nimble_port_init() != ESP_OK) { state_ = State::Failed; return false; }
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.reset_cb = on_reset;
    nimble_port_freertos_init(host_task);
    return true;
}
State state() { return state_.load(); }
bool apply(const Duty& d) {
    if (!guardian::coex::valid(d)) return false;
    wanted_ = pack(d);
    const State s = state_.load();
    if (s == State::Failed) return false;
    if (s != State::Ready) return !d.on() || s == State::Starting;   // applied on sync
    const int rc = set_scan(d);
    record(rc);
    return rc == 0;
}
std::uint32_t adv_reports() { return reports_.load(std::memory_order_relaxed); }
std::uint32_t errors() { return errors_.load(); }
int last_error() { return last_error_.load(); }
bool scanning() { return state_.load() == State::Ready && ble_gap_disc_active(); }
} // namespace sticks3::ble
#endif

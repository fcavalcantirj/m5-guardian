#pragma once
// G16C rework (2): console output never blocks observation, and every cause of
// a rating dropout on the glass is counted so STATUS can name it.
// SDK-free so the host can check it (tests/link_health_check.cpp).
//
// Console write policy. The USB-Serial-JTAG TX buffer only drains while a host
// reads the port; with the cable plugged in and the port closed, a write waits
// for its timeout. In the companion the console carries replies and notices,
// never observations, so its writes never wait (timeout 0) and a lost line is a
// console drop, not a lost radio frame. The G13 lab console streams the
// observations themselves (GRX1 records), so it keeps its accepted policy: a
// short wait, and a write that still fails counts in the G13 drop accounting.
//
// Dropout causes (since boot): console writes that failed and the time spent
// inside console writes, log lines dropped by the non-blocking ESP_LOG sink,
// and transitions of the presenter overlay into "Listening coverage degraded"
// and "No fresh data". The radio queue and survey-lock counters live with the
// radio and the Survey and are reported beside these.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include "guardian/presenter.hpp"

namespace sticks3 {

enum class ConsoleOwner : std::uint8_t { Companion, Lab };
struct WritePolicy {
    std::uint32_t timeout_ms;   // longest wait for room in the TX buffer
    bool counts_as_frame_drop;  // a failed write is a lost observation (G13 drop accounting)
};
constexpr WritePolicy write_policy(ConsoleOwner o) {
    return o == ConsoleOwner::Lab ? WritePolicy{5, true} : WritePolicy{0, false};
}

class LinkHealth {
public:
    // One console write: whether it went out whole and how long it took.
    void console_write(bool ok, std::int64_t elapsed_us) {
        ++writes_; if (!ok) ++write_drops_;
        const auto us = elapsed_us < 0 ? 0u : elapsed_us > 0x7fffffff ? 0x7fffffffu : static_cast<std::uint32_t>(elapsed_us);
        stall_us_ += us; if (us > stall_max_us_) stall_max_us_ = us;
    }
    // One ESP_LOG line through the non-blocking sink: written, or dropped.
    // Called from any task (the Wi-Fi driver logs from its own), hence atomic.
    void log_line(bool ok) { log_lines_.fetch_add(1); if (!ok) log_drops_.fetch_add(1); }
    // The presenter overlay now (sampled at every UI tick): counts entries into
    // the degraded / no-data states, never a state that merely continues.
    void overlay(guardian::Overlay o) {
        if (have_overlay_ && o == overlay_) return;
        if (have_overlay_ || o != guardian::Overlay::None) {
            if (o == guardian::Overlay::CoverageDegraded) ++degraded_;
            if (o == guardian::Overlay::NoFreshData) ++no_data_;
        }
        overlay_ = o; have_overlay_ = true;
    }
    std::uint32_t write_drops() const { return write_drops_; }
    std::uint32_t log_drops() const { return log_drops_.load(); }
    std::uint32_t degraded_transitions() const { return degraded_; }
    std::uint32_t no_data_transitions() const { return no_data_; }
    std::uint64_t stall_us() const { return stall_us_; }
    std::uint32_t stall_max_us() const { return stall_max_us_; }
    // " console_writes=.. console_drops=.. console_stall_ms=a/max log_lines=.. log_drops=.. degraded_transitions=.. nodata_transitions=.."
    void status_text(char* out, std::size_t n) const {
        std::snprintf(out, n, "console_writes=%u console_drops=%u console_stall_ms=%u.%u/%u.%u log_lines=%u log_drops=%u degraded_transitions=%u nodata_transitions=%u",
                      unsigned(writes_), unsigned(write_drops_), unsigned(stall_us_ / 1000), unsigned(stall_us_ / 100 % 10),
                      unsigned(stall_max_us_ / 1000), unsigned(stall_max_us_ / 100 % 10), unsigned(log_lines_.load()), unsigned(log_drops_.load()),
                      unsigned(degraded_), unsigned(no_data_));
    }
private:
    std::uint32_t writes_{}, write_drops_{}, stall_max_us_{}, degraded_{}, no_data_{};
    std::atomic<std::uint32_t> log_lines_{0}, log_drops_{0};
    std::uint64_t stall_us_{};
    guardian::Overlay overlay_{guardian::Overlay::None};
    bool have_overlay_{};
};

} // namespace sticks3

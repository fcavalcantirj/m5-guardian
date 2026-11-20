// ESP-IDF adapter SKETCH for the G01 contracts. NOT BUILT, NOT FLASHED.
//
// Shows where the SDK lives (only here), how the promiscuous callback stays
// tiny, and the exact wifi_pkt_rx_ctrl_t -> RxMeta mapping against the pinned
// ESP-IDF v5.4 header (components/esp_wifi/include/local/esp_wifi_types_native.h,
// commit 67c1de1e, read 2026-11-13). G10/G13 turn this into boards/sticks3 code
// with tests and a real capture.
#include <atomic>
#include <cstdint>
#include <cstring>

#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include "guardian/capabilities.hpp"
#include "guardian/radio.hpp"
#include "guardian/time.hpp"

namespace sticks3 {

using guardian::Band;
using guardian::Millis;
using guardian::Support;

class EspTimerClock final : public guardian::MonotonicClock {
public:
    explicit EspTimerClock(guardian::TimeEpoch epoch) : epoch_(epoch) {}
    Millis now() const override { return static_cast<Millis>(esp_timer_get_time() / 1000); }
    guardian::TimeEpoch epoch() const override { return epoch_; }
private:
    guardian::TimeEpoch epoch_; // source UUID + durable boot generation; no AP identity
};

// Bounded pool + queue. Slot size is the RadioCapabilities::max_frame_bytes
// this adapter publishes. Chosen from measured free heap in G13, not here.
class PromiscuousSource final : public guardian::FrameSource {
public:
    static constexpr std::uint16_t slot_bytes = 1024;
    static constexpr std::size_t slots = 16;

    // Static application-lifetime instance; stop/restart synchronization is
    // deliberately not implemented in this sketch. Never destroy while active.
    bool start(std::uint8_t channel, guardian::TimeEpoch epoch) {
        bool enabled = false;
        if (self_ || !epoch.valid() || channel < 1 || channel > 14 ||
            esp_wifi_get_promiscuous(&enabled) != ESP_OK || enabled) return false;
        epoch_ = epoch;
        free_ = xQueueCreate(slots, sizeof(std::uint8_t));
        ready_ = xQueueCreate(slots, sizeof(std::uint8_t));
        if (!free_ || !ready_) { release_queues(); return false; }
        for (std::uint8_t i = 0; i < slots; ++i) {
            if (xQueueSend(free_, &i, 0) != pdTRUE) { release_queues(); return false; }
        }
        // Publish only after initialization; reception is still disabled.
        self_ = this;
        wifi_promiscuous_filter_t filter{};
        filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT; // DATA added later for EAPOL (G06)
        // FCSFAIL deliberately not set: capability fcs_error_delivery = Supported, policy off.
        if (esp_wifi_set_promiscuous_filter(&filter) != ESP_OK ||
            esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) != ESP_OK ||
            esp_wifi_set_promiscuous_rx_cb(&PromiscuousSource::rx_cb) != ESP_OK) {
            // No capture was enabled. Null self makes a retained callback inert.
            self_ = nullptr;
            release_queues();
            return false;
        }
        channel_ = channel;
        stats_.epoch = epoch_;
        stats_.listening_since = guardian::Instant{epoch_, static_cast<Millis>(esp_timer_get_time() / 1000), true};
        if (esp_wifi_set_promiscuous(true) != ESP_OK) {
            // Keep the bounded queues/instance alive on uncertain driver state;
            // no freeing a pool potentially still referenced by a callback.
            // Production G13 adds a synchronized stop and restart path.
            stats_.listening_since.known = false;
            channel_ = 0;
            return false;
        }
        return true;
    }

    // Application task side.
    bool next(guardian::FrameBuffer into, guardian::FrameSpan& span, guardian::RxMeta& meta) override {
        if (!into.data || !into.capacity || !ready_) return false;
        std::uint8_t idx{};
        if (xQueueReceive(ready_, &idx, 0) != pdTRUE) return false;
        Slot& s = pool_[idx];
        const std::uint16_t n = s.size < into.capacity ? s.size : into.capacity;
        std::memcpy(into.data, s.bytes, n);
        span.bytes = into.data;
        span.size = n;
        span.truncated = s.truncated || n < s.size;
        meta = s.meta;
        meta.processed = guardian::Instant{epoch_, static_cast<Millis>(esp_timer_get_time() / 1000), true}; // diagnostics only
        // span now lives in the caller's buffer. Return failure is an internal
        // pool invariant violation; count it rather than blocking driver work.
        if (xQueueSend(free_, &idx, 0) != pdTRUE) dropped_.fetch_add(1, std::memory_order_relaxed);
        ++stats_.delivered;
        if (span.truncated) ++stats_.truncated;
        if (meta.status != guardian::RxStatus::Ok) ++stats_.rx_errors;
        return true;
    }
    guardian::AcquisitionStats stats() const override {
        guardian::AcquisitionStats s = stats_;
        s.received = received_.load();
        s.dropped_queue_full = dropped_.load();
        s.dropped_bad_input = bad_input_.load();
        s.dropped_filtered = filtered_.load();
        return s;
    }
    Band current_band() const override { return Band::Ghz2_4; }
    std::uint8_t current_channel() const override { return channel_; }

private:
    void release_queues() {
        if (free_) vQueueDelete(free_);
        if (ready_) vQueueDelete(ready_);
        free_ = ready_ = nullptr;
    }

    struct Slot {
        guardian::RxMeta meta{};
        std::uint16_t size{};
        bool truncated{};
        std::uint8_t bytes[slot_bytes];
    };

    // Runs in the Wi-Fi driver task. Copy, stamp, enqueue. No parsing, no
    // drawing, no library call, no blocking.
    static void rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
        PromiscuousSource* self = self_;
        if (!self || !buf) return;
        self->received_.fetch_add(1, std::memory_order_relaxed);
        if (type != WIFI_PKT_MGMT) {
            self->filtered_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
        const wifi_pkt_rx_ctrl_t& rc = pkt->rx_ctrl;
        const guardian::Instant acquired{self->epoch_, static_cast<Millis>(esp_timer_get_time() / 1000), true};
        // Pinned driver contract: full reported length includes a 4-byte FCS.
        // Subtract before pool truncation. Unknown conventions are not accepted.
        const std::uint16_t reported = static_cast<std::uint16_t>(rc.sig_len);
        if (reported < 4) { self->bad_input_.fetch_add(1, std::memory_order_relaxed); return; }
        std::uint8_t idx{};
        if (xQueueReceive(self->free_, &idx, 0) != pdTRUE) { // Wi-Fi driver TASK; never ISR APIs
            self->dropped_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        Slot& s = self->pool_[idx];
        // sig_len is documented as "length of packet including FCS". Strip 4.
        // G13 confirms on a real capture that this pinned convention holds.
        const std::uint16_t body = static_cast<std::uint16_t>(reported - 4);
        s.size = body < slot_bytes ? body : slot_bytes;
        s.truncated = body > slot_bytes;
        std::memcpy(s.bytes, pkt->payload, s.size);
        guardian::RxMeta& m = s.meta;
        m = guardian::RxMeta{};
        m.acquired = acquired; // immutable during queueing; preserves epoch
        m.radio_timestamp_us = rc.timestamp;        // 32-bit µs, imprecise with modem/light sleep
        m.radio_timestamp_valid = true;
        m.band = Band::Ghz2_4;
        m.channel = static_cast<std::uint8_t>(rc.channel); // 4-bit field: 1..14 only on this chip
        m.secondary = rc.secondary_channel == 0 ? guardian::SecondaryChannel::None
                    : rc.secondary_channel == 1 ? guardian::SecondaryChannel::Above
                    : rc.secondary_channel == 2 ? guardian::SecondaryChannel::Below
                                                : guardian::SecondaryChannel::Unknown;
        m.rssi_dbm = static_cast<std::int8_t>(rc.rssi);
        m.rssi_valid = true;
        m.noise_floor_dbm = static_cast<std::int8_t>(rc.noise_floor); // present on ESP32-S3 in the pinned header
        m.noise_floor_valid = true;
        m.status = rc.rx_state == 0 ? guardian::RxStatus::Ok : guardian::RxStatus::DriverError;
        m.reported_length = reported;
        m.origin = guardian::Origin::LiveRadio;
        if (xQueueSend(self->ready_, &idx, 0) != pdTRUE) {
            self->dropped_.fetch_add(1, std::memory_order_relaxed);
            if (xQueueSend(self->free_, &idx, 0) != pdTRUE)
                self->bad_input_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    static PromiscuousSource* self_;
    Slot pool_[slots]{};
    QueueHandle_t free_{};
    QueueHandle_t ready_{};
    std::uint8_t channel_{};
    std::atomic<std::uint32_t> received_{0};
    std::atomic<std::uint32_t> dropped_{0};
    std::atomic<std::uint32_t> bad_input_{0};
    std::atomic<std::uint32_t> filtered_{0};
    guardian::TimeEpoch epoch_{};
    guardian::AcquisitionStats stats_{};
};
PromiscuousSource* PromiscuousSource::self_ = nullptr;

// Static capability publication, not evidence of current operation. Board
// facts come from source/identity records; fields needing runtime support stay
// Unknown. CoverageReport separately reports whether reception is running.
// These SDK/source capabilities do not claim a successful G11/G13 boot.
inline guardian::BoardCapabilities sticks3_capabilities(std::uint32_t internal_ram, std::uint32_t psram,
                                                        std::uint32_t assets_bytes, bool nvs_ok) {
    using namespace guardian;
    BoardCapabilities c{};
    c.board_name = "M5StickS3";
    c.radio.passive_receive = Support::Unknown;     // G13 sets Supported after a real capture
    c.radio.channels = profiles::all_2g4_channels(); // narrow by esp_wifi_get_country() at start
    c.radio.channel_hop = Support::Unknown;         // G13 decides fixed-channel vs hop
    c.radio.max_frame_bytes = PromiscuousSource::slot_bytes;
    c.radio.rx_timestamp = Support::Supported;      // field exists; precision caveat in RxMeta
    c.radio.noise_floor = Support::Supported;       // field exists for ESP32-S3 in pinned header
    c.radio.fcs_error_delivery = Support::Supported; // WIFI_PROMIS_FILTER_MASK_FCSFAIL exists; kept off
    c.radio.rx_error_state = Support::Supported;    // rx_state field
    c.display.present = Support::Supported;          // ST7789 135x240, landscape 240x135 (G11 proves pixels)
    c.display.width = 240;
    c.display.height = 135;
    c.display.format = PixelFormat::Rgb565;
    c.display.animation = Support::Unknown;          // G21 measures frame budget
    c.input.controls[static_cast<std::size_t>(InputControl::Primary)] = Support::Supported;   // front key G11
    c.input.controls[static_cast<std::size_t>(InputControl::Secondary)] = Support::Supported; // side key G12
    c.input.controls[static_cast<std::size_t>(InputControl::Back)] = Support::Unsupported;
    c.input.touch = Support::Unsupported;
    c.input.motion = Support::Unknown;               // BMI270 present per board docs, not probed
    c.ble.present = Support::Supported;              // ESP32-S3 has BLE; observer/peripheral unprobed
    c.ble.observer = Support::Unknown;
    c.ble.peripheral = Support::Unknown;
    c.memory.internal_ram_bytes = internal_ram;      // measured at boot
    c.memory.external_ram_bytes = psram;             // measured: 8 MB octal, or 0 if the test failed
    c.memory.frame_pool_bytes = 0; // G13 budgets full Slot metadata, queue overhead and bytes
    c.storage.key_value = nvs_ok ? Support::Supported : Support::Unsupported;
    c.storage.asset_bytes = assets_bytes;
    c.storage.removable_media = Support::Unsupported; // no SD slot by design
    return c;
}

} // namespace sticks3

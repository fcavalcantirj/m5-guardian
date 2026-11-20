#pragma once
#include "measurement.hpp"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include <atomic>
namespace sticks3 {
class MeasurementRadio final : public guardian::FrameSource {
public:
    bool init(const guardian::TimeEpoch&, const char* country);
    bool tune(std::uint8_t channel);
    bool stop();
    // G16D: before deep sleep: stop() then esp_wifi_stop (sleep_modes.rst).
    bool shutdown();
    bool next(guardian::FrameBuffer, guardian::FrameSpan&, guardian::RxMeta&) override;
    guardian::AcquisitionStats stats() const override;
    guardian::Band current_band() const override { return guardian::Band::Ghz2_4; }
    std::uint8_t current_channel() const override { return listening() ? channel_ : 0; }
    std::uint32_t drops() const { return drops_.load()+discarded_.load()+bad_.load(); }
    std::uint32_t received() const { return received_.load(); }
    std::uint32_t bad() const { return bad_.load(); }
    std::uint32_t queue_drops() const { return drops_.load()+discarded_.load(); }
    // G16C rework diagnostics: frames lost because the 24-deep queue was full,
    // and frames flushed on purpose when listening stopped (channel hop, update).
    std::uint32_t queue_full() const { return drops_.load(); }
    std::uint32_t discarded() const { return discarded_.load(); }
    bool listening() const { return listening_.load(); }
    // G14 console takeover: restart counters while reception is stopped.
    void reset_counters() { if (!listening()) { drops_=0;bad_=0;received_=0;delivered_=0;truncated_=0;rx_errors_=0;filtered_=0;discarded_=0; } }
    // G16G data path: promiscuous DATA + checksum-failed delivery behind a
    // callback prefilter (EAPOL only reaches the queue; errors are counted per
    // channel and never queued). Off = management frames only (the G13/G16C
    // configuration). Applied immediately when the radio is initialised.
    bool set_data_path(bool on);
    bool data_path() const { return data_path_.load(); }
    // Per-channel receive counts since the previous call (application task).
    std::size_t sample_load(const guardian::Instant& now, guardian::ChannelLoadSample* out, std::size_t capacity);
    // Callback cost and data-path counters. *_window values are exchanged to 0
    // by take_callback_window() (once a second); the totals are since boot.
    struct CallbackWindow { std::uint32_t calls{}, cycles{}, max_cycles{}; };
    CallbackWindow take_callback_window();
    std::uint32_t data_frames() const { return data_frames_.load(); }   // data frames seen by the callback (data path on)
    std::uint32_t eapol_kept() const { return eapol_kept_.load(); }     // ... of which queued as EAPOL
    std::uint32_t rx_errors() const { return rx_errors_.load(); }       // receive-error frames (counted, never queued)
    const guardian::measurement::ChannelLoadMeter& load() const { return load_; }
    std::uint8_t first() const { return country_.schan; }
    const char* queue_ram() const { return storage_ram_; }   // STATUS radio_ram=: psram / internal / none
    std::uint8_t count() const { return country_.nchan; }
private:
    static void receive(void*,wifi_promiscuous_pkt_type_t);
    static MeasurementRadio* instance_;
    guardian::TimeEpoch epoch_{};
    wifi_country_t country_{};
    QueueHandle_t queue_{};
    StaticQueue_t queue_control_{};
    // Review 2026-11-17 (memory): the 24-slot queue storage (~39 KB) is placed at init in
    // PSRAM, internal DRAM only as a fallback (psram.hpp), not in internal .bss.
    std::uint8_t* storage_{};
    const char* storage_ram_{"none"};
    std::atomic<std::uint32_t> drops_{0}, bad_{0}, received_{0};
    std::atomic<bool> listening_{false};
    std::atomic<std::uint32_t> delivered_{0}, truncated_{0}, rx_errors_{0}, filtered_{0}, discarded_{0};
    guardian::measurement::Packet dequeued_{};
    bool apply_filter();
    guardian::measurement::ChannelLoadMeter load_{};
    std::atomic<bool> data_path_{false};
    std::atomic<std::uint32_t> data_frames_{0}, eapol_kept_{0};
    std::atomic<std::uint32_t> cb_calls_{0}, cb_cycles_{0}, cb_max_{0};
    guardian::Instant listening_since_{};
    std::uint8_t channel_{};
    bool initialized_{};
};
}

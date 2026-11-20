#include "measurement_radio.hpp"
#include "psram.hpp"
#include "esp_event.h"
#include "esp_timer.h"
#include "esp_cpu.h"
#include <cstring>
namespace sticks3 {
MeasurementRadio* MeasurementRadio::instance_=nullptr;
bool MeasurementRadio::init(const guardian::TimeEpoch& epoch,const char* country) {
    if(initialized_ || !epoch.valid() || !country || std::strlen(country)!=2)return false;
    epoch_=epoch;instance_=this;
    if(!storage_) {   // once per boot, never freed (psram.hpp)
        psram::Where where{};
        storage_=static_cast<std::uint8_t*>(psram::alloc(24*sizeof(guardian::measurement::Packet),4,where));
        storage_ram_=psram::where_text(where);
        if(!storage_)return false;
    }
    queue_=xQueueCreateStatic(24,sizeof(guardian::measurement::Packet),storage_,&queue_control_);
    if(!queue_)return false;
    if(esp_event_loop_create_default()!=ESP_OK)return false;
    wifi_init_config_t cfg=WIFI_INIT_CONFIG_DEFAULT();cfg.nvs_enable=0;
    if(esp_wifi_init(&cfg)!=ESP_OK || esp_wifi_set_storage(WIFI_STORAGE_RAM)!=ESP_OK
       || esp_wifi_set_mode(WIFI_MODE_NULL)!=ESP_OK
       || esp_wifi_set_country_code(country,false)!=ESP_OK
       || esp_wifi_get_country(&country_)!=ESP_OK)return false;
    // The adapter deliberately supports only 2.4 GHz channels 1..13, intersected
    // with the SDK's explicitly configured country. No 802.11d auto-adoption.
    if(!country_.schan || !country_.nchan || unsigned(country_.schan)+country_.nchan>14)return false;
    if(esp_wifi_start()!=ESP_OK || esp_wifi_set_ps(WIFI_PS_NONE)!=ESP_OK)return false;
    if(esp_wifi_set_promiscuous_rx_cb(receive)!=ESP_OK)return false;
    initialized_=true;
    if(!apply_filter()){initialized_=false;return false;}
    return true;
}
// G16G: management only, or management + data + checksum-failed frames.
bool MeasurementRadio::apply_filter() {
    if(!initialized_)return true;
    wifi_promiscuous_filter_t filter{};
    filter.filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|(data_path_.load()?(WIFI_PROMIS_FILTER_MASK_DATA|WIFI_PROMIS_FILTER_MASK_FCSFAIL):0);
    return esp_wifi_set_promiscuous_filter(&filter)==ESP_OK;
}
bool MeasurementRadio::set_data_path(bool on) {
    const bool before=data_path_.exchange(on);
    if(apply_filter())return true;
    data_path_=before;apply_filter();return false;
}
std::size_t MeasurementRadio::sample_load(const guardian::Instant& now,guardian::ChannelLoadSample* out,std::size_t capacity) {
    return load_.sample(now,guardian::Origin::LiveRadio,data_path_.load(),out,capacity);
}
MeasurementRadio::CallbackWindow MeasurementRadio::take_callback_window() {
    CallbackWindow w;w.calls=cb_calls_.exchange(0);w.cycles=cb_cycles_.exchange(0);w.max_cycles=cb_max_.exchange(0);return w;
}
bool MeasurementRadio::shutdown() {
    const bool stopped=stop();
    return (!initialized_ || esp_wifi_stop()==ESP_OK) && stopped;
}
bool MeasurementRadio::stop() {
    listening_=false;
    load_.untuned(static_cast<guardian::Millis>(esp_timer_get_time()/1000));
    if(initialized_ && esp_wifi_set_promiscuous(false)!=ESP_OK)return false;
    // Persistent scratch: never share the callback's stack or payload pointer.
    static guardian::measurement::Packet discarded;
    if(queue_)while(xQueueReceive(queue_,&discarded,0)==pdTRUE)++discarded_;
    return true;
}
bool MeasurementRadio::tune(std::uint8_t channel) {
    if(!initialized_ || channel<first() || unsigned(channel)>=unsigned(first())+count())return false;
    if(!stop() || esp_wifi_set_channel(channel,WIFI_SECOND_CHAN_NONE)!=ESP_OK)return false;
    channel_=channel;
    listening_since_={epoch_,static_cast<guardian::Millis>(esp_timer_get_time()/1000),true};
    load_.tuned(channel,listening_since_.at);
    listening_=true;
    if(esp_wifi_set_promiscuous(true)!=ESP_OK){listening_=false;return false;}
    return true;
}
bool MeasurementRadio::next(guardian::FrameBuffer into,guardian::FrameSpan& span,guardian::RxMeta& meta) {
    if(!queue_ || !into.data || !into.capacity || xQueueReceive(queue_,&dequeued_,0)!=pdTRUE)return false;
    if(!guardian::measurement::deliver(dequeued_,into,span,meta)){++bad_;return false;}
    ++delivered_;if(span.truncated)++truncated_;return true;
}
guardian::AcquisitionStats MeasurementRadio::stats() const {
    guardian::AcquisitionStats s{};s.epoch=epoch_;s.received=received_;s.delivered=delivered_;
    s.dropped_queue_full=drops_;s.dropped_bad_input=bad_;s.dropped_filtered=filtered_.load()+discarded_.load();
    s.truncated=truncated_;s.rx_errors=rx_errors_;s.listening_since=listening_since_;return s;
}
namespace {
// G16G: cycles spent in the receive callback (per call, window maximum).
struct CallbackCost {
    std::atomic<std::uint32_t>& calls; std::atomic<std::uint32_t>& cycles; std::atomic<std::uint32_t>& max;
    const std::uint32_t start=esp_cpu_get_cycle_count();
    ~CallbackCost() {
        const std::uint32_t c=esp_cpu_get_cycle_count()-start;
        calls.fetch_add(1,std::memory_order_relaxed);cycles.fetch_add(c,std::memory_order_relaxed);
        std::uint32_t m=max.load(std::memory_order_relaxed);
        while(c>m && !max.compare_exchange_weak(m,c,std::memory_order_relaxed)){}
    }
};
}
void MeasurementRadio::receive(void* buffer,wifi_promiscuous_pkt_type_t type) {
    auto* self=instance_;
    if(!self || !self->listening_)return;
    CallbackCost cost{self->cb_calls_,self->cb_cycles_,self->cb_max_};
    ++self->received_;
    if(!buffer){++self->bad_;return;}
    const auto* rx=static_cast<const wifi_promiscuous_pkt_t*>(buffer);
    const auto length=static_cast<std::uint16_t>(rx->rx_ctrl.sig_len);
    const auto rx_channel=static_cast<std::uint8_t>(rx->rx_ctrl.channel);
    // G16G: a frame the driver flagged (checksum failure when FCSFAIL delivery is on)
    // is counted per channel with its RSSI and never queued: its bytes are untrusted.
    // G16J: every frame, valid or flagged, carries the radio's noise-floor estimate (the noise-floor rule).
    const auto noise=static_cast<std::int8_t>(rx->rx_ctrl.noise_floor);
    if(rx->rx_ctrl.rx_state){++self->rx_errors_;self->load_.error(rx_channel,static_cast<std::int8_t>(rx->rx_ctrl.rssi),noise);return;}
    self->load_.valid(rx_channel,noise);
    if(type==WIFI_PKT_DATA && self->data_path_.load(std::memory_order_relaxed)) {
        ++self->data_frames_;
        // Prefilter before any copy: only unprotected EAPOL reaches the queue.
        if(length<4 || !guardian::measurement::eapol_candidate(rx->payload,length-4u)){++self->filtered_;return;}
        ++self->eapol_kept_;
    } else if(type!=WIFI_PKT_MGMT){++self->filtered_;return;}
    guardian::RxMeta meta{};
    meta.acquired={self->epoch_,static_cast<guardian::Millis>(esp_timer_get_time()/1000),true};
    meta.radio_timestamp_us=rx->rx_ctrl.timestamp;meta.radio_timestamp_valid=true;
    meta.channel=rx->rx_ctrl.channel;
    meta.secondary=rx->rx_ctrl.secondary_channel==0?guardian::SecondaryChannel::None:
        rx->rx_ctrl.secondary_channel==1?guardian::SecondaryChannel::Above:
        rx->rx_ctrl.secondary_channel==2?guardian::SecondaryChannel::Below:guardian::SecondaryChannel::Unknown;
    meta.rssi_dbm=rx->rx_ctrl.rssi;meta.rssi_valid=true;
    meta.noise_floor_dbm=rx->rx_ctrl.noise_floor;meta.noise_floor_valid=true;
    guardian::measurement::Packet packet;
    if(!guardian::measurement::copy_rx(packet,rx->payload,length>=4?length-4:0,length,rx->rx_ctrl.rx_state,meta)) {++self->bad_;return;}
    // Driver TASK callback, not ISR. Never parse, render, log, allocate or wait.
    if(xQueueSend(self->queue_,&packet,0)!=pdTRUE)++self->drops_;
}
}

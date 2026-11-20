// G16C rework (5): TUNE session network task (see tune_link.hpp).
#include "tune_link.hpp"
#include <cstring>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"

namespace sticks3 {
namespace {
constexpr int request_timeout_ms = 4000;   // each reply / end request
constexpr std::uint32_t reply_wait_ms = 5000;
}
using namespace guardian::tune::wifi;

bool TuneLink::start(ota::WifiTransport& net, const Offer& offer) {
    if (running_.load()) return false;
    if (!reply_) reply_ = static_cast<char*>(heap_caps_malloc(kMaxReply, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (!reply_) return false;
    net_ = &net; offer_ = offer;
    stop_ = false; command_ready_ = false; reply_ready_ = false; done_ = false; why_ = 0;
    ok_ = 0; failed_ = 0; reply_len_ = 0;
    running_ = true; started_ = true;
    // Core 0 beside the Wi-Fi stack, below its priority; the HTTP client needs a few KiB of stack.
    if (xTaskCreatePinnedToCore(entry, "tune_link", 6144, this, 4, nullptr, 0) != pdPASS) { running_ = false; started_ = false; return false; }
    return true;
}

void TuneLink::entry(void* self) { static_cast<TuneLink*>(self)->loop(); vTaskDelete(nullptr); }

void TuneLink::loop() {
    char path[96], body[16];
    // G22A: the commands are the offer's signed list, in order. Nothing is fetched from the network here.
    for (std::size_t i = 0; i < offer_.command_count && !stop_.load(); ++i) {
        std::memcpy(command_, offer_.commands[i].data(), sizeof command_);
        reply_ready_ = false; command_ready_ = true;
        std::uint32_t waited = 0;
        while (!reply_ready_.load() && !stop_.load() && waited < reply_wait_ms) { vTaskDelay(pdMS_TO_TICKS(10)); waited += 10; }
        if (!reply_ready_.load()) { command_ready_ = false; static const char none[] = "TUNE ERROR no reply\n"; std::memcpy(reply_, none, sizeof none); reply_len_ = sizeof none - 1; }
        reply_ready_ = false;
        if (reply_path(offer_, path, sizeof path) && net_->post(path, reply_, reply_len_, request_timeout_ms)) ++ok_; else ++failed_;
    }
    if (!stop_.load()) done_ = true;
    // Best-effort end report; the session already ended on this side either way.
    const auto why = stop_.load() ? static_cast<End>(why_.load()) : End::Done;
    std::size_t n = 0;
    if (end_path(offer_, why, path, sizeof path)) net_->fetch(path, body, sizeof body, n, request_timeout_ms);
    running_ = false;
}

bool TuneLink::take_command(char* out, std::size_t capacity) {
    if (!command_ready_.load() || !capacity) return false;
    std::strncpy(out, command_, capacity - 1); out[capacity - 1] = 0;
    command_ready_ = false;
    return true;
}

void TuneLink::give_reply(std::size_t n) {
    reply_len_ = n > kMaxReply ? kMaxReply : n;
    reply_ready_ = true;
}

TuneLink::Events TuneLink::events() {
    Events e;
    e.ok = ok_.exchange(0); e.failed = failed_.exchange(0);
    e.done = done_.exchange(false);
    return e;
}

} // namespace sticks3

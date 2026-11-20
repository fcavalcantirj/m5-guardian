#pragma once
// G16M ESP-IDF adapter for the phone setup (adapters/setup/setup.hpp): a WPA2/WPA3
// access point with a one-time password, esp_http_server with the one page, and a
// name service that sends every lookup to the page (so the phone opens it by
// itself). Only used inside an owner-started setup session; outside it the
// Guardian never raises an access point and never listens on a port.
//
// The radio driver is already initialised by the passive receiver. open() takes
// it from the companion (stop hook), switches NULL -> AP; close() returns it to
// NULL; resume() hands it back (resume hook = passive listening again).
// The home password exists here only between the page's POST and take(); it is
// never logged, and every copy is overwritten.
#include <atomic>
#include <cstdint>
#include "setup.hpp"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

namespace sticks3 {

class SetupPort final : public guardian::setup::Port {
public:
    // `stop`: passive listening off (false: the radio could not be taken). `resume`: listening again.
    void hooks(bool (*stop)(), void (*resume)()) { stop_ = stop; resume_ = resume; }
    bool open(const char* ap_name, const char* ap_pass, const guardian::setup::Target&, bool url_stored) override;
    void close() override;
    bool take(guardian::setup::Form& out) override;
    guardian::setup::Join join(const guardian::ota::Credentials&) override;
    void resume() override;
    // STATUS: pages served and forms refused since boot; why the last open() failed ("none" ...).
    std::uint32_t pages() const { return pages_.load(); }
    std::uint32_t refused() const { return refused_.load(); }
    const char* open_error() const { return open_error_; }
    // Used by the HTTP handlers and the name-service task (this file only).
    struct Impl;
private:
    friend struct Impl;
    bool (*stop_)(){};
    void (*resume_)(){};
    void* server_{};              // httpd_handle_t
    void* ap_netif_{};            // esp_netif_t*, created at the first setup and kept
    char* page_{};                // page_bytes in PSRAM while the access point is up
    SemaphoreHandle_t lock_{};    // guards form_/pending_
    guardian::setup::Form form_{};
    guardian::setup::Target target_{};
    bool pending_{}, url_stored_{}, up_{};
    std::atomic<bool> dns_stop_{false}, dns_running_{false};
    std::atomic<std::uint32_t> pages_{0}, refused_{0};
    const char* open_error_{"none"};
};

} // namespace sticks3

// G16M ESP-IDF adapter for the phone setup (see setup_board.hpp).
#include "setup_board.hpp"
#include <cstdio>
#include <cstring>
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "ota_board.hpp"

namespace sticks3 {
namespace {
using guardian::setup::Form;
using guardian::setup::FormError;
using guardian::setup::Join;
constexpr std::uint8_t ap_channel = 6;
constexpr std::uint8_t page_ip[4] = {192, 168, 4, 1};   // guardian::setup::page_host (checked in open())
constexpr char redirect_to[] = "http://192.168.4.1/";
}

struct SetupPort::Impl {
    static esp_err_t send_page(httpd_req_t* req, SetupPort& p, std::size_t n) {
        httpd_resp_set_type(req, "text/html; charset=utf-8");
        httpd_resp_set_hdr(req, "Cache-Control", "no-store");
        return n ? httpd_resp_send(req, p.page_, static_cast<ssize_t>(n)) : httpd_resp_send_500(req);
    }
    static esp_err_t root(httpd_req_t* req) {
        auto& p = *static_cast<SetupPort*>(req->user_ctx);
        ++p.pages_;
        return send_page(req, p, guardian::setup::render_form(p.page_, guardian::setup::page_bytes, p.target_, p.url_stored_, FormError::None));
    }
    // Every other address (the phones' connectivity probes): to the page. iOS wants a body, not only the redirect.
    static esp_err_t elsewhere(httpd_req_t* req) {
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", redirect_to);
        httpd_resp_set_hdr(req, "Cache-Control", "no-store");
        return httpd_resp_send(req, "Guardian setup: open http://192.168.4.1/", HTTPD_RESP_USE_STRLEN);
    }
    static esp_err_t save(httpd_req_t* req) {
        auto& p = *static_cast<SetupPort*>(req->user_ctx);
        char body[guardian::setup::max_body + 1];
        Form form;
        FormError error = FormError::None;
        std::size_t got = 0;
        if (req->content_len > guardian::setup::max_body) error = FormError::TooLong;
        else {
            for (int timeouts = 0; got < req->content_len;) {
                const int r = httpd_req_recv(req, body + got, req->content_len - got);
                if (r == HTTPD_SOCK_ERR_TIMEOUT && ++timeouts < 3) continue;   // a stalled phone never holds the server
                if (r <= 0) { error = FormError::Malformed; break; }
                got += static_cast<std::size_t>(r);
            }
        }
        if (error == FormError::None) error = guardian::setup::parse_form(body, got, p.target_.open, form);
        guardian::setup::wipe(body, sizeof body);   // the typed password is never kept in this buffer
        if (error != FormError::None) {
            ++p.refused_;
            return send_page(req, p, guardian::setup::render_form(p.page_, guardian::setup::page_bytes, p.target_, p.url_stored_, error));
        }
        xSemaphoreTake(p.lock_, portMAX_DELAY);
        p.form_ = form; p.pending_ = true;
        xSemaphoreGive(p.lock_);
        form.wipe();
        return send_page(req, p, guardian::setup::render_received(p.page_, guardian::setup::page_bytes, p.target_));
    }
    // Answers every A question with the page's address until the access point closes.
    static void dns(void* arg) {
        auto& p = *static_cast<SetupPort*>(arg);
        const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock >= 0) {
            sockaddr_in local{}; local.sin_family = AF_INET; local.sin_port = htons(53); local.sin_addr.s_addr = htonl(INADDR_ANY);
            timeval wait{}; wait.tv_usec = 250000;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
            if (bind(sock, reinterpret_cast<sockaddr*>(&local), sizeof local) == 0) {
                static std::uint8_t query[guardian::setup::dns_max], reply[guardian::setup::dns_max];   // one task at a time
                while (!p.dns_stop_.load()) {
                    sockaddr_in from{}; socklen_t from_len = sizeof from;
                    const int n = recvfrom(sock, query, sizeof query, 0, reinterpret_cast<sockaddr*>(&from), &from_len);
                    if (n <= 0) continue;
                    const auto m = guardian::setup::dns_answer(query, static_cast<std::size_t>(n), page_ip, reply, sizeof reply);
                    if (m) sendto(sock, reply, m, 0, reinterpret_cast<sockaddr*>(&from), from_len);
                }
            }
            closesocket(sock);
        }
        p.dns_running_.store(false);
        vTaskDelete(nullptr);
    }
};

bool SetupPort::open(const char* ap_name, const char* ap_pass, const guardian::setup::Target& target, bool url_stored) {
    open_error_ = "none";
    const auto fail = [&](const char* why) { open_error_ = why; return false; };
    if (up_) return fail("already_open");
    if (!stop_ || !stop_()) return fail("radio_busy");
    if (!lock_ && !(lock_ = xSemaphoreCreateMutex())) return fail("no_memory");
    if (!ota::net_init()) return fail("netif");
    if (!ap_netif_ && !(ap_netif_ = esp_netif_create_default_wifi_ap())) return fail("ap_netif");
    esp_netif_ip_info_t ip{};
    if (esp_netif_get_ip_info(static_cast<esp_netif_t*>(ap_netif_), &ip) != ESP_OK || ip.ip.addr != ipaddr_addr(guardian::setup::page_host))
        return fail("ap_address");   // the glass prints page_host: never a different address
    if (!page_ && !(page_ = static_cast<char*>(heap_caps_malloc(guardian::setup::page_bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)))
        && !(page_ = static_cast<char*>(heap_caps_malloc(guardian::setup::page_bytes, MALLOC_CAP_8BIT)))) return fail("no_memory");
    target_ = target; url_stored_ = url_stored; pending_ = false; form_.wipe();
    up_ = true;   // from here close() undoes whatever came up
    if (esp_wifi_set_mode(WIFI_MODE_AP) != ESP_OK) return fail("ap_mode");
    wifi_config_t cfg{};
    const std::size_t name_len = std::strlen(ap_name), pass_len = std::strlen(ap_pass);
    if (name_len > sizeof cfg.ap.ssid || pass_len < 8 || pass_len >= sizeof cfg.ap.password) return fail("ap_config");
    std::memcpy(cfg.ap.ssid, ap_name, name_len); cfg.ap.ssid_len = static_cast<std::uint8_t>(name_len);
    std::memcpy(cfg.ap.password, ap_pass, pass_len);
    cfg.ap.channel = ap_channel;
    cfg.ap.authmode = WIFI_AUTH_WPA2_WPA3_PSK;   // WPA3-SAE for phones that have it, WPA2 for the rest
    cfg.ap.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
    cfg.ap.pmf_cfg.capable = true;
    cfg.ap.max_connection = 2;                   // the owner's phone (and its reconnect)
    const bool configured = esp_wifi_set_config(WIFI_IF_AP, &cfg) == ESP_OK;
    guardian::setup::wipe(&cfg, sizeof cfg);
    if (!configured) return fail("ap_config");
    {   // DHCP option 114 (RFC 8910): tells the phone where the page is. Best effort; the name service does the rest.
        auto* netif = static_cast<esp_netif_t*>(ap_netif_);
        static char uri[] = "http://192.168.4.1/";
        esp_netif_dhcps_stop(netif);
        esp_netif_dhcps_option(netif, ESP_NETIF_OP_SET, ESP_NETIF_CAPTIVEPORTAL_URI, uri, sizeof uri - 1);
        esp_netif_dhcps_start(netif);
    }
    httpd_config_t http = HTTPD_DEFAULT_CONFIG();
    http.stack_size = 8192;
    http.max_open_sockets = 4;
    http.lru_purge_enable = true;                // phones open several probe connections
    http.uri_match_fn = httpd_uri_match_wildcard;
    httpd_handle_t server = nullptr;
    if (httpd_start(&server, &http) != ESP_OK) return fail("http_server");
    server_ = server;
    httpd_uri_t root{}; root.uri = "/"; root.method = HTTP_GET; root.handler = Impl::root; root.user_ctx = this;
    httpd_uri_t save{}; save.uri = "/save"; save.method = HTTP_POST; save.handler = Impl::save; save.user_ctx = this;
    httpd_uri_t other{}; other.uri = "/*"; other.method = HTTP_GET; other.handler = Impl::elsewhere; other.user_ctx = this;
    if (httpd_register_uri_handler(server, &root) != ESP_OK || httpd_register_uri_handler(server, &save) != ESP_OK
        || httpd_register_uri_handler(server, &other) != ESP_OK) return fail("http_handlers");
    dns_stop_.store(false); dns_running_.store(true);
    if (xTaskCreatePinnedToCore(Impl::dns, "setup_dns", 3072, this, tskIDLE_PRIORITY + 3, nullptr, 0) != pdPASS) {
        dns_running_.store(false);
        return fail("dns_task");
    }
    return true;
}

void SetupPort::close() {
    if (!up_) return;
    up_ = false;
    dns_stop_.store(true);
    for (int i = 0; i < 40 && dns_running_.load(); ++i) vTaskDelay(pdMS_TO_TICKS(50));   // its receive wakes every 250 ms
    if (server_) { httpd_stop(static_cast<httpd_handle_t>(server_)); server_ = nullptr; }
    wifi_config_t empty{};
    esp_wifi_set_config(WIFI_IF_AP, &empty);     // the one-time password leaves the driver (storage is RAM only)
    esp_wifi_set_mode(WIFI_MODE_NULL);           // back to the passive receiver's mode
    if (page_) { guardian::setup::wipe(page_, guardian::setup::page_bytes); heap_caps_free(page_); page_ = nullptr; }
    if (lock_) {
        xSemaphoreTake(lock_, portMAX_DELAY);
        form_.wipe(); pending_ = false;
        xSemaphoreGive(lock_);
    }
}

bool SetupPort::take(Form& out) {
    if (!lock_) return false;
    bool got = false;
    xSemaphoreTake(lock_, portMAX_DELAY);
    if (pending_) { out = form_; form_.wipe(); pending_ = false; got = true; }
    xSemaphoreGive(lock_);
    return got;
}

Join SetupPort::join(const guardian::ota::Credentials& c) {
    ota::WifiTransport net(c);
    const bool joined = net.join();
    const auto reason = ota::last_disconnect_reason();
    net.leave();
    if (joined) return Join::Joined;
    switch (reason) {
    case WIFI_REASON_AUTH_FAIL: case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT: case WIFI_REASON_HANDSHAKE_TIMEOUT: case WIFI_REASON_MIC_FAILURE:
        return Join::Password;
    case WIFI_REASON_NO_AP_FOUND: case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY: case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD:
    case WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD:
        return Join::NotFound;
    default: return Join::Failed;
    }
}

void SetupPort::resume() { if (resume_) resume_(); }

} // namespace sticks3

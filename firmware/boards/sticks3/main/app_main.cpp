// M5 Guardian retained StickS3 bring-up spike, reconciled with G09 contracts.
//
// Intended measurements on the real board (not proof until a saved boot log): ESP-IDF boot without Arduino, board identification
// through the M5PM1, flash and PSRAM sizes, a working ST7789 screen, both
// buttons, NVS settings and no SD card. The portable core and presenter are
// linked and exercised with an empty snapshot so the device shows the honest
// "checking" state; no radio adapter exists yet, so no mood is claimed.
#include <cinttypes>
#include <cstdio>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "guardian/capabilities.hpp"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "guardian/canvas.hpp"
#include "guardian/core.hpp"
#include "guardian/presenter.hpp"
#include "sticks3_board.hpp"

namespace {
constexpr const char* TAG = "guardian";
constexpr const char* kFirmware = "guardian-sticks3 bringup-0.3";

const char* mood_name(guardian::Mood m) {
    switch (m) {
        case guardian::Mood::VeryGood: return "Very good";
        case guardian::Mood::Good: return "Good";
        case guardian::Mood::Medium: return "Medium";
        case guardian::Mood::Bad: return "Bad";
        case guardian::Mood::Horrible: return "Horrible";
        default: return "Unknown";
    }
}

std::uint16_t mood_color(guardian::Mood m) {
    using namespace guardian::color;
    switch (m) {
        case guardian::Mood::VeryGood: return green;
        case guardian::Mood::Good: return guardian::rgb565(120, 220, 80);
        case guardian::Mood::Medium: return yellow;
        case guardian::Mood::Bad: return orange;
        case guardian::Mood::Horrible: return red;
        default: return grey;
    }
}

const char* overlay_name(guardian::Overlay o) {
    switch (o) {
        case guardian::Overlay::None: return "none";
        case guardian::Overlay::Checking: return "checking";
        case guardian::Overlay::NoFreshData: return "no fresh data";
        case guardian::Overlay::CoverageDegraded: return "coverage degraded";
        case guardian::Overlay::Unsupported: return "unsupported";
        case guardian::Overlay::Incident: return "incident";
    }
    return "?";
}

struct Buttons {
    bool front{}, side{};
    std::uint32_t front_presses{}, side_presses{};
};

class Clock final : public guardian::MonotonicClock {
public:
    Clock(){esp_fill_random(epoch_.source_id.data(),epoch_.source_id.size());epoch_.source_id[0]|=1;epoch_.boot_id=1;}
    guardian::Millis now()const override{return static_cast<guardian::Millis>(esp_timer_get_time()/1000);}
    guardian::TimeEpoch epoch()const override{return epoch_;}
private: guardian::TimeEpoch epoch_{};
};
void log_board(const sticks3::BoardInfo& b,bool transfer_ok) {
    ESP_LOGI(TAG,"BOARD profile=StickS3 identity=owner-selected pm1_response=%d pm1_id_raw=0x%08" PRIx32
        " pm1_config=%d panel_setup=%d transfer_complete=%d visible_pixels=unverified buttons_setup=%d"
        " flash=%" PRIu32 " psram=%u psram_test=%d heap=%u nvs=%d boot_count=%" PRIu32 " sd=none fw=%s",
        b.pm1_present,b.pm1_device_id,b.pm1_config_ok,b.panel_setup_ok,transfer_ok,b.buttons_ok,b.flash_bytes,
        unsigned(b.psram_bytes),b.psram_test_ok,unsigned(b.heap_free),b.nvs_ok,b.boot_count,kFirmware);
}

bool draw(sticks3::Board& board, const sticks3::BoardInfo& b, const guardian::ViewModel& vm,
          const Buttons& keys, std::uint32_t uptime_s) {
    using namespace guardian::color;
    auto* frame=board.canvas();if(!frame)return false;
    auto& c=*frame;
    c.clear(dark);
    // Header
    c.fill_rect(0, 0, c.width(), 14, mood_color(vm.face));
    c.text(3, 3, "GUARDIAN  StickS3 bring-up", black, 1);
    // Status (what the presenter says, truthfully "checking" without radio)
    char line[64];
    std::snprintf(line, sizeof line, "face: %s", mood_name(vm.face));
    c.text(3, 18, line, white, 1);
    std::snprintf(line, sizeof line, "overlay: %s", overlay_name(vm.overlay));
    c.text(3, 27, line, white, 1);
    // Hardware facts measured this boot
    std::snprintf(line, sizeof line, "profile StickS3 pm1 0x%08" PRIx32, b.pm1_device_id);
    c.text(3, 40, line, b.pm1_present ? green : red, 1);
    std::snprintf(line, sizeof line, "%s r%d  flash %" PRIu32 "K", b.chip_model, b.chip_revision, b.flash_bytes / 1024);
    c.text(3, 49, line, white, 1);
    std::snprintf(line, sizeof line, "psram %uK %s  heap %uK", static_cast<unsigned>(b.psram_bytes / 1024),
                  b.psram_test_ok ? "ok" : "FAIL", static_cast<unsigned>(b.heap_free / 1024));
    c.text(3, 58, line, b.psram_test_ok ? green : red, 1);
    std::snprintf(line, sizeof line, "nvs %s boot #%" PRIu32 "  assets %" PRIu32 "K  sd none", b.nvs_ok ? "ok" : "FAIL",
                  b.boot_count, b.assets_partition_bytes / 1024);
    c.text(3, 67, line, white, 1);
    // Buttons
    std::snprintf(line, sizeof line, "KEY front(G11) %s x%" PRIu32, keys.front ? "DOWN" : "up", keys.front_presses);
    c.text(3, 80, line, keys.front ? yellow : white, 1);
    std::snprintf(line, sizeof line, "KEY side (G12) %s x%" PRIu32, keys.side ? "DOWN" : "up", keys.side_presses);
    c.text(3, 89, line, keys.side ? yellow : white, 1);
    // Colour and orientation check for the photograph: R G B, five mood swatches.
    c.fill_rect(3, 102, 24, 12, red);
    c.text(6, 104, "R", white, 1);
    c.fill_rect(29, 102, 24, 12, green);
    c.text(32, 104, "G", black, 1);
    c.fill_rect(55, 102, 24, 12, blue);
    c.text(58, 104, "B", white, 1);
    const guardian::Mood moods[] = {guardian::Mood::VeryGood, guardian::Mood::Good, guardian::Mood::Medium,
                                    guardian::Mood::Bad, guardian::Mood::Horrible};
    for (int i = 0; i < 5; ++i) c.fill_rect(100 + i * 26, 102, 24, 12, mood_color(moods[i]));
    std::snprintf(line, sizeof line, "up %" PRIu32 "s  USB-powered, no SD, no Pi", uptime_s);
    c.text(3, 120, line, grey, 1);
    c.draw_rect(0, 0, c.width(), c.height(), white); // frame edge: confirms the 240x135 window
    return board.present();
}
} // namespace

extern "C" void guardian_bringup_main() {
    static sticks3::Board board;
    sticks3::BoardInfo info{};
    bool transfer_ok = false;
    const bool display_ready=board.init(info);
    log_board(info,transfer_ok);

    Clock clock;
    guardian::Core core(clock,guardian::profiles::all_2g4_channels(),guardian::Origin::LiveRadio);
    Buttons keys{};
    bool prev_front = false, prev_side = false;
    std::int64_t last_log_us = 0;

    for (;;) {
        const std::int64_t now_us = esp_timer_get_time();
        keys.front = info.buttons_ok && board.key_front_down();
        keys.side = info.buttons_ok && board.key_side_down();
        if (keys.front && !prev_front) {
            ++keys.front_presses;
            ESP_LOGI(TAG, "BTN gpio=11 front pressed count=%" PRIu32, keys.front_presses);
        }
        if (keys.side && !prev_side) {
            ++keys.side_presses;
            ESP_LOGI(TAG, "BTN gpio=12 side pressed count=%" PRIu32, keys.side_presses);
        }
        prev_front = keys.front;
        prev_side = keys.side;

        const guardian::Snapshot snap = core.snapshot();
        const guardian::ViewModel vm = guardian::present(snap);
        if(display_ready) transfer_ok=draw(board,info,vm,keys,static_cast<std::uint32_t>(now_us/1000000));

        if (now_us - last_log_us > 5 * 1000000) { // repeat for a late-attached monitor
            last_log_us = now_us;
            log_board(info, transfer_ok);
            ESP_LOGI(TAG, "VIEW face=%s overlay=%s age_ms=%" PRIu64 " front_down=%d side_down=%d",
                     mood_name(vm.face), overlay_name(vm.overlay), static_cast<std::uint64_t>(vm.age_ms),
                     keys.front, keys.side);
        }
        vTaskDelay(pdMS_TO_TICKS(40));
    }
}

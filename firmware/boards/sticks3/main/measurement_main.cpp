// G13 native receive -> existing portable library -> diagnostic outputs.
// G14: boots as the companion (face / details / network picker on the
// buttons, owner selection persisted in NVS) and starts PASSIVE, receive-only
// 2.4 GHz listening in CONFIG_GUARDIAN_COUNTRY. No transmit, association, scan
// request or password. The first scoped console command (select/start/listen/
// stop/...) hands the radio and screen to the G13 measurement protocol until
// reboot, unchanged for the lab harness; console selections are never persisted.
// G16A: upright portrait (USB down), EDGE / IMU / TUNE console commands that
// never take the radio, the BMI270 sampled on core 1, TUNE values in NVS.
// G16B: owner-initiated signed OTA (both keys ~3 s + on-screen yes), boot
// self-test that validates or rolls back a new image, OTA provisioning over
// USB (values never printed), honest PM1 battery state, BATTRUN runtime log.
// G16C: every rating's portrait (16 embedded frames), the HUD, the IMU motion
// model (axis map from a recorded trace via TUNE imu.*), animated face screens
// at the TUNE display.frame_ms cadence, frame-time / fps / IMU-to-glass stats
// in STATUS and the FRAMES console command.
// G16C rework: the portrait warp runs from a PSRAM copy and is skipped while the
// pose is still; only changed rows go to the panel; console output never blocks
// observation (companion writes never wait, ESP_LOG through a non-blocking sink,
// everything below WARN off after boot) and dropout causes are counted in STATUS;
// TUNE/STATUS also over the owner's Wi-Fi inside an owner-confirmed session.
// G16M: phone setup (hold SIDE 3 s on a network of the list, or FRONT x3 while no Wi-Fi is stored): a short-lived
// WPA access point with one page that asks the picked network's password; the credential goes to the encrypted
// vault when the stick has one (cred_vault.hpp). The stick transmits only inside that owner-started session.
// G16D: on battery the Guardian dims when left still (TUNE power.dim_s), then
// deep-sleeps (power.sleep_s) with only the two keys armed (ext1); a key press
// boots it and is swallowed. Policy, teardown order and the RTC sleep record are
// host-tested in adapters/power/idle.{hpp,cpp}; this file only wires them.
// G16N: guard in the dark. On battery Dim is followed by Dark (TUNE power.dark_s, 0 = off): the backlight
// is 0 and no frame is drawn, while the radio, the detectors, the IMU and this loop keep running. A key
// (swallowed), motion or a NEW incident report (ViewModel::incident_seq changed, red or amber) lights the
// screen again at 60 % with a full redraw. Deep sleep is only the floor (power.dark_floor_pct). The panel is
// never put to sleep for Dark (display_sleep() revokes the canvas until reboot): set_backlight(0) only.
// G16E: detector limits and the area visibility are TUNE parameters (detect.*,
// AntiHunter c6ef921 values as documented starting hypotheses); STATUS reports
// every registered detector and the air meter (Monitor::status_text).
#include <algorithm>
#include "measurement.hpp"
#include "companion.hpp"
#include "persona.hpp"
#include "motion.hpp"
#include "shake.hpp"
#include "burst.hpp"
#include "head3d.hpp"
#include "frame_stats.hpp"
#include "nvs_blob.hpp"
#include "measurement_radio.hpp"
#include "psram.hpp"
#include "pose.hpp"
#include "measurement_display.hpp"
#include "redraw.hpp"
#include "wire.hpp"
#include "orientation.hpp"
#include "imu_task.hpp"
#include "tune.hpp"
#include "threat_tune.hpp"
#include "ota.hpp"
#include "ota_board.hpp"
#include "battery.hpp"
#include "dirty_rows.hpp"
#include "link_health.hpp"
#include "session.hpp"
#include "tune_link.hpp"
#include "offer_rsa.hpp"
#include "esp_random.h"
#include "setup.hpp"
#include "setup_board.hpp"
#include "cred_vault.hpp"
#include "esp_random.h"
#include "idle.hpp"
#include "ble_spike.hpp"   // G16H: empty unless CONFIG_GUARDIAN_BLE_SPIKE (spike build variant)
#include "art_bench.hpp"   // G16Q: used only under CONFIG_GUARDIAN_ART_BENCH (art bench build variant)
#include "esp_sleep.h"
#include "esp_attr.h"
#if CONFIG_GUARDIAN_DARK_CPU
#include "esp_pm.h"        // G23: the CPU frequency while dark (dark-cpu build variant only; needs CONFIG_PM_ENABLE)
#endif
#include "driver/rtc_io.h"
#include <sys/time.h>
#include "sdkconfig.h"
#include "esp_log.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "freertos/semphr.h"
#include <cstdarg>
#include "esp_system.h"
#include "driver/usb_serial_jtag.h"
#include "esp_mac.h"
#include "esp_app_desc.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "freertos/task.h"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <cstdlib>
#include <new>
static_assert(CONFIG_APP_RETRIEVE_LEN_ELF_SHA == 64, "Live qualification requires the full ELF SHA-256");
// G16C: the 16 upright 135x160 portraits (every rating, both ALERT pulses of
// each, the NoData silhouette), embedded by EMBED_FILES (little-endian RGB565,
// persona::art_bytes = 43,200 bytes each; sizes checked at build and run time).
#define GUARDIAN_PORTRAIT(sym) \
    extern const std::uint8_t sym##_start[] asm("_binary_" #sym "_portrait_rgb565_start"); \
    extern const std::uint8_t sym##_end[] asm("_binary_" #sym "_portrait_rgb565_end");
GUARDIAN_PORTRAIT(VeryGood) GUARDIAN_PORTRAIT(Good) GUARDIAN_PORTRAIT(Medium) GUARDIAN_PORTRAIT(Bad) GUARDIAN_PORTRAIT(Horrible)
GUARDIAN_PORTRAIT(VeryGood_ALERT_p0) GUARDIAN_PORTRAIT(VeryGood_ALERT_p1) GUARDIAN_PORTRAIT(Good_ALERT_p0) GUARDIAN_PORTRAIT(Good_ALERT_p1)
GUARDIAN_PORTRAIT(Medium_ALERT_p0) GUARDIAN_PORTRAIT(Medium_ALERT_p1) GUARDIAN_PORTRAIT(Bad_ALERT_p0) GUARDIAN_PORTRAIT(Bad_ALERT_p1)
GUARDIAN_PORTRAIT(Horrible_ALERT_p0) GUARDIAN_PORTRAIT(Horrible_ALERT_p1) GUARDIAN_PORTRAIT(NoData)
#undef GUARDIAN_PORTRAIT
// G21: the 3D head's frame sets (art/persona/v3/frames/<Mood>.bin, built by tools/face3d/pack_frames.py),
// embedded like the portraits. main/CMakeLists.txt embeds each file that exists and defines
// GUARDIAN_HEAD3D_<Mood>; a rating without a set shows its 2D portrait.
#define GUARDIAN_HEAD3D(sym) \
    extern const std::uint8_t head3d_##sym##_start[] asm("_binary_" #sym "_bin_start"); \
    extern const std::uint8_t head3d_##sym##_end[] asm("_binary_" #sym "_bin_end");
#ifdef GUARDIAN_HEAD3D_VeryGood
GUARDIAN_HEAD3D(VeryGood)
#endif
#ifdef GUARDIAN_HEAD3D_Good
GUARDIAN_HEAD3D(Good)
#endif
#ifdef GUARDIAN_HEAD3D_Medium
GUARDIAN_HEAD3D(Medium)
#endif
#ifdef GUARDIAN_HEAD3D_Bad
GUARDIAN_HEAD3D(Bad)
#endif
#ifdef GUARDIAN_HEAD3D_Horrible
GUARDIAN_HEAD3D(Horrible)
#endif
#undef GUARDIAN_HEAD3D
#if CONFIG_GUARDIAN_ART_BENCH
// G16Q: the art bench's 16 candidate frames (art/bench/*.rgb565, 135x240 little-endian RGB565, 64,800 B each,
// built and pinned by tools/art/candidates.py), embedded only in the bench image (main/CMakeLists.txt).
#define GUARDIAN_BENCH_FRAME(sym) \
    extern const std::uint8_t bench_##sym##_start[] asm("_binary_" #sym "_rgb565_start"); \
    extern const std::uint8_t bench_##sym##_end[] asm("_binary_" #sym "_rgb565_end");
GUARDIAN_BENCH_FRAME(A_VeryGood) GUARDIAN_BENCH_FRAME(A_Horrible) GUARDIAN_BENCH_FRAME(A_Medium)
GUARDIAN_BENCH_FRAME(B_VeryGood) GUARDIAN_BENCH_FRAME(B_Horrible) GUARDIAN_BENCH_FRAME(B_Medium)
GUARDIAN_BENCH_FRAME(C_VeryGood) GUARDIAN_BENCH_FRAME(C_Horrible) GUARDIAN_BENCH_FRAME(C_Medium)
GUARDIAN_BENCH_FRAME(D_VeryGood) GUARDIAN_BENCH_FRAME(D_Horrible) GUARDIAN_BENCH_FRAME(D_Medium)
GUARDIAN_BENCH_FRAME(E_VeryGood) GUARDIAN_BENCH_FRAME(E_Horrible) GUARDIAN_BENCH_FRAME(E_Medium)
GUARDIAN_BENCH_FRAME(ramp)
#undef GUARDIAN_BENCH_FRAME
#endif
namespace {
using namespace guardian;
class Clock final:public MonotonicClock {
    TimeEpoch id_{};
public:
    Clock(){esp_fill_random(id_.source_id.data(),id_.source_id.size());id_.source_id[0]|=1;esp_fill_random(&id_.boot_id,sizeof id_.boot_id);if(!id_.boot_id)id_.boot_id=1;}
    Millis now()const override{return static_cast<Millis>(esp_timer_get_time()/1000);}
    TimeEpoch epoch()const override{return id_;}
};
Clock* clock_ptr;
sticks3::MeasurementRadio radio;
measurement::Survey survey;
measurement::Monitor* monitor;
Network selected{};
bool configured{},radio_initialized{};
char configured_country[3]{};
Millis deadline{},last_cover{},stable_since{};
std::uint32_t sequence{},output_drops{},deliberate_drops{},drop_budget{},previous_drops{};
std::uint64_t boot;
std::uint8_t channel{},mac[6]{};
measurement::Packet packet;
grx::Record record;
// Review 2026-11-17 (memory): the large record/reply buffers (~33 KB) are placed once at
// boot in PSRAM, internal DRAM only as a fallback (psram.hpp), instead of internal .bss.
struct TextBuffers {
    std::uint8_t binary[grx::max_packet];
    char wire_line[grx::max_packet*2+7];
    char state_line[8192];      // G16F: 14 detector records in the G13 JSON
    char snapshot_line[8256];   // one USB write keeps state prefix/body together
    char status_line[7456];     // G16E: + detector fragment (G16F: 14 detectors; G16G: 16 + data-path numbers); G16S: + burst records (the compiler's worst case was 5674); G16T: the burst buffer grew by 576; G23: + lock_loss_by (96); G23 battery: + energy (160)
    char detect[2048];          // G16E/G16F: per-detector counters (14), air meter, area observations
    char bursts[measurement::Monitor::burst_text_max];   // G16S: last_burst_network= / last_burst_area= (its own buffer: never lost with `detect`)
    char frames_reply[1024];
    char tune_reply[4096];      // G16E: up to tune::max_params lines (longer listings end "TUNE MORE")
};
TextBuffers* bufs{};
const char* text_ram="none";const char* app_ram="none";const char* tune_ram="none";   // STATUS: psram / internal
// Review 2026-11-17: why this boot happened (esp_reset_reason), so "did it deep-sleep or
// restart?" is read from STATUS (reset= and uptime_s=), never guessed.
const char* reset_text="unknown";
const char* codec_boot="-";   // ES8311 address probe at boot: ack / nack (STATUS codec_boot=)
const char* reset_reason_text(esp_reset_reason_t r) {
    switch(r) {
    case ESP_RST_POWERON:return "poweron";case ESP_RST_EXT:return "ext";case ESP_RST_SW:return "sw";
    case ESP_RST_PANIC:return "panic";case ESP_RST_INT_WDT:return "int_wdt";case ESP_RST_TASK_WDT:return "task_wdt";
    case ESP_RST_WDT:return "wdt";case ESP_RST_DEEPSLEEP:return "deepsleep";case ESP_RST_BROWNOUT:return "brownout";
    case ESP_RST_SDIO:return "sdio";case ESP_RST_USB:return "usb";case ESP_RST_JTAG:return "jtag";case ESP_RST_EFUSE:return "efuse";
    case ESP_RST_PWR_GLITCH:return "pwr_glitch";case ESP_RST_CPU_LOCKUP:return "cpu_lockup";default:return "unknown";
    }
}
std::uint32_t drops(){return radio.drops()+output_drops+deliberate_drops;}
// ---- G14 companion state --------------------------------------------------
enum class Control:std::uint8_t{Companion,Console};
Control control=Control::Companion;
companion::Companion* app;
companion::RadioState companion_radio=companion::RadioState::Unconfigured;
sticks3::Board* board_ptr;
bool buttons_ok{};
// ---- G16A console tools ------------------------------------------------------
tune::Registry* tuning;
int tune_sway=-1,tune_breath=-1,tune_ember=-1,tune_smoke=-1;
// ---- G16C art, motion, frame stats ---------------------------------------------
companion::persona::ArtSet art_set;
bool art_ok{};
companion::motion::Model motion_model;
int tune_imu_right=-1,tune_imu_up=-1,tune_imu_out=-1,tune_frame_ms=-1;
struct MotionKey { const char* key; float lo, hi; float companion::motion::Params::* field; int index; };
MotionKey motion_keys[]={
    // 2026-11-17: the face floats in water inside the stick (adapters/companion/motion.hpp); ranges single-sourced there.
    {"motion.roll_gain",companion::motion::roll_gain_range.lo,companion::motion::roll_gain_range.hi,&companion::motion::Params::roll_gain,-1},
    {"motion.max_roll",companion::motion::max_roll_range.lo,companion::motion::max_roll_range.hi,&companion::motion::Params::max_roll_deg,-1},
    {"motion.drift",companion::motion::drift_gain_range.lo,companion::motion::drift_gain_range.hi,&companion::motion::Params::drift_px_per_deg,-1},
    {"motion.max_x",companion::motion::max_x_range.lo,companion::motion::max_x_range.hi,&companion::motion::Params::max_x_px,-1},
    {"motion.pitch_gain",companion::motion::pitch_gain_range.lo,companion::motion::pitch_gain_range.hi,&companion::motion::Params::pitch_px_per_deg,-1},
    {"motion.max_y",companion::motion::max_y_range.lo,companion::motion::max_y_range.hi,&companion::motion::Params::max_y_px,-1},
    {"motion.yaw_gain",companion::motion::yaw_gain_range.lo,companion::motion::yaw_gain_range.hi,&companion::motion::Params::yaw_px_per_deg,-1},
    {"motion.yaw_return",companion::motion::yaw_return_range.lo,companion::motion::yaw_return_range.hi,&companion::motion::Params::yaw_return_s,-1},
    {"motion.inertia",companion::motion::inertia_range.lo,companion::motion::inertia_range.hi,&companion::motion::Params::inertia_px_per_g,-1},
    {"motion.float_hz",companion::motion::float_hz_range.lo,companion::motion::float_hz_range.hi,&companion::motion::Params::float_hz,-1},
    {"motion.water",companion::motion::water_damping_range.lo,companion::motion::water_damping_range.hi,&companion::motion::Params::water_damping,-1},
    {"motion.bob",companion::motion::bob_px_range.lo,companion::motion::bob_px_range.hi,&companion::motion::Params::bob_px,-1},
    {"motion.sway",companion::motion::sway_deg_range.lo,companion::motion::sway_deg_range.hi,&companion::motion::Params::sway_deg,-1},
    {"motion.fusion_tau",companion::motion::fusion_tau_range.lo,companion::motion::fusion_tau_range.hi,&companion::motion::Params::fusion_tau_s,-1},
    {"motion.pull_back",companion::motion::pull_back_range.lo,companion::motion::pull_back_range.hi,&companion::motion::Params::pull_back,-1},
    {"motion.parallax",companion::motion::parallax_range.lo,companion::motion::parallax_range.hi,&companion::motion::Params::parallax,-1},
    // G16I: 1 = Fawkes always stands upright by gravity (continuous counter-rotation); fit 1 = the hood never leaves the glass.
    {"motion.upright",companion::motion::upright_range.lo,companion::motion::upright_range.hi,&companion::motion::Params::upright,-1},
    {"motion.upright_fit",companion::motion::upright_fit_range.lo,companion::motion::upright_fit_range.hi,&companion::motion::Params::upright_fit,-1},
};
int tune_rest_gyro=-1,tune_rest_acc=-1;   // G16D handling detection (was in the old motion Params)
// ---- G16I: shake -> snow-globe burst of the face ----------------------------------------
companion::shake::Detector shake_detector;   // fed every IMU sample (drain_imu); STATUS shakes=
companion::burst::Burst* face_burst;         // 16 KB of particles, placed by psram.hpp (nullptr: no room, the face never bursts)
const char* burst_ram="none";
int tune_shake_g=-1,tune_shake_peaks=-1,tune_shake_window=-1,tune_burst_s=-1;
int tune_burst_still_dps=-1,tune_burst_still_g=-1,tune_burst_calm=-1,tune_burst_max=-1;   // G16O: the reform waits for a still stick
// The burst's TUNE values (a key that is not registered keeps its default).
companion::burst::Params burst_params(const guardian::tune::Registry& r) {
    companion::burst::Params p;
    if(tune_burst_s>=0)p.total_s=r.get(tune_burst_s);
    if(tune_burst_still_dps>=0)p.still_dps=r.get(tune_burst_still_dps);
    if(tune_burst_still_g>=0)p.still_g=r.get(tune_burst_still_g);
    if(tune_burst_calm>=0)p.calm_s=r.get(tune_burst_calm);
    if(tune_burst_max>=0)p.max_s=r.get(tune_burst_max);
    return p;
}
bool shake_waiting{};                        // a shake was detected and waits for the next face frame ...
Millis shake_at{};
constexpr Millis shake_fresh_ms=250;         // ... but never longer than this: an old shake starts nothing later
std::uint32_t burst_seed{};
void burst_stop(){shake_waiting=false;if(face_burst && face_burst->active())face_burst->cancel();}
// ---- G21: the 3D head (pre-rendered angle frames chosen by the stick's yaw / pitch) ---------
companion::head3d::Head* face_head;          // nullptr: no PSRAM for it, every rated face stays the 2D portrait
const char* head_ram="none";
std::uint32_t head_ram_bytes{};
std::uint8_t head_packs{},head_refused{};    // frame sets embedded in this image / refused at boot (damaged pack)
const char* head_refusal="none";
int tune_head_on=-1,tune_head_yaw=-1,tune_head_pitch=-1,tune_head_hyst=-1;
// What choosing a frame costs (one inflate of 43,200 B when the frame changes), inside render.
std::uint32_t head_changes{},head_change_us_max{};
std::uint64_t head_change_us_total{};
void configure_head() {
    if(!face_head || !tuning || tune_head_on<0)return;
    companion::head3d::Params p;
    p.on=tuning->get(tune_head_on)>=0.5f;p.yaw_gain=tuning->get(tune_head_yaw);p.pitch_gain=tuning->get(tune_head_pitch);
    p.hysteresis=tuning->get(tune_head_hyst);
    face_head->configure(p);
}
sticks3::FrameStats frame_stats;
std::int64_t last_present_us{};
Millis edge_until{};                    // EDGE test pattern shown until this instant (0: off)
guardian::imu::PoseMeter imu_pose;   // review 2026-11-17: IMU POSE (USB and Wi-Fi), adapters/imu/pose.hpp
Millis imu_stream_until{};              // IMU raw stream active until this instant (0: off)
std::uint32_t imu_streamed{},imu_output_drops{};
// ---- G16B OTA + battery ------------------------------------------------------
guardian::ota::Provisioner* provisioner;
companion::BlobStorage* ota_blob;
guardian::ota::Record ota_record;          // last update outcome (NVS "ota")
guardian::ota::SelfTest self_test;
guardian::ota::Gesture update_gesture;
guardian::ota::Confirmation update_confirm;
guardian::ota::TripleTap update_taps;   // FRONT x3 fast = UPDATE (owner, one-handed)
bool update_requested{};
// ---- G16M phone setup ---------------------------------------------------------
sticks3::SetupPort setup_port;
guardian::setup::Session* setup_session;        // created with the provisioner (boot)
guardian::setup::SideHold setup_hold;
guardian::setup::Target setup_hold_target;      // the list row under the cursor when SIDE went down
guardian::setup::StoreKind cred_store=guardian::setup::StoreKind::None;
bool cred_migrated{},cred_legacy_cleared{};
bool setup_visible(){return setup_session && setup_session->visible();}
// 2026-11-18 (owner: "from here on you got OTA"): the stick asks the Mac for a signed image by itself every
// ota.auto_s seconds (TUNE, 0 = off) through the same owner-confirmed path, quietly when nothing is offered.
// G22A: the poll is deferred while a red ALERT is active (guardian::ota::AutoPoll: the incident stays on the glass),
// and an offered image is installed only when its version is newer than the running one (ota_not_newer counts refusals).
int tune_ota_auto=-1;guardian::ota::AutoPoll auto_poll;unsigned ota_not_newer{};bool update_quiet{};const char* auto_last_text="none";
guardian::battery::Monitor battery_monitor;
guardian::battery::State battery_state;
guardian::battery::RunLog* battery_log;
// ---- G16C rework: fast render, dropout diagnostics, TUNE over Wi-Fi ----------------
sticks3::LinkHealth health;
sticks3::DirtyRows dirty;
companion::persona::WarpCache* warp_cache;   // PSRAM portrait copy + warped band (nullptr: from flash, no reuse)
const char* art_ram="none";
const char* monitor_ram="none";   // G16F: where the Monitor (Core + all detectors) lives: psram / internal
std::uint32_t art_ram_bytes{};
std::uint64_t push_rows_total{};
std::uint32_t push_frames{},full_pushes{};
Millis last_full_push{};
constexpr Millis full_push_ms=1000;   // heals any row a hash collision left stale
guardian::tune::wifi::Session tune_session;
// G22A: a TUNE offer opens a session only when it is signed with the OTA signing key. tune_key is the public key of
// the running image's own signature block (the key update images are checked against), read at the first offer.
guardian::tune::wifi::OfferCounts tune_offers;
guardian::tune::wifi::RsaKey tune_key;
bool tune_key_read{};
sticks3::TuneLink tune_link;
sticks3::ota::WifiTransport* tune_net;
bool tune_stopping{};
char* capture_buf{};std::size_t capture_len{},capture_cap{};   // text() goes here while a TUNE command runs
SemaphoreHandle_t log_lock;
// ---- G16D battery life: dim, deep sleep, button wake ------------------------------
namespace gp=guardian::power;
gp::Idle idle;
gp::SourceFilter power_source;
gp::MotionActivity activity;
gp::WakeGuard wake_guard;
gp::Wake wake_info;
RTC_DATA_ATTR gp::Retained retained;   // RTC slow memory: kept across deep sleep (validated by magic + CRC)
int tune_dim_s=-1,tune_sleep_s=-1,tune_dim_pct=-1;
// ---- G16P a plugged-in Guardian wakes by itself -------------------------------------
int tune_sleep_check=-1;              // TUNE power.sleep_check_s: the deep sleep's timer wake period
gp::Check check_info;                 // this boot's timer check (outcome NoRecord when the boot was not a timer wake)
bool check_ran{},check_pm1_open{};    // a timer wake ran the check; the PM1 bus could be opened for it
// ---- G16N guard in the dark --------------------------------------------------------
int tune_dark_s=-1,tune_dark_floor=-1;
// ---- G23 battery life in dark guard: the means to measure and reduce the drain (defaults = before G23) ----
int tune_ota_auto_batt=-1;            // TUNE ota.auto_batt_s: the update-poll period on battery (-1 = follow ota.auto_s)
int tune_dark_cpu=-1;                 // TUNE power.dark_cpu_mhz: the CPU frequency while dark (dark-cpu image only)
static_assert(CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ==gp::cpu_default_mhz,"the dark CPU policy assumes the sdkconfig CPU frequency");
std::uint16_t cpu_applied_mhz=gp::cpu_default_mhz;   // what esp_pm_configure last accepted (the boot frequency until then)
unsigned cpu_set_fail{};              // esp_pm_configure refusals
unsigned cpu_switches{};              // esp_pm_configure changes accepted (two per dark stretch at a non-160 value)
#if CONFIG_GUARDIAN_DARK_CPU
constexpr bool dark_cpu_built=true;   // undefined (not 0) in a normal image: the option depends on CONFIG_PM_ENABLE
#else
constexpr bool dark_cpu_built=false;
#endif
int backlight_applied=-1;   // the percent last written to the backlight (-1: the board's init value)
// S2 of the device spike: from the evidence instant of the incident that lit the screen to the backlight
// command (dark_wake_evidence_ms) and to the first frame pushed after it (dark_wake_frame_ms). -1 = none yet.
int dark_wake_evidence_ms=-1,dark_wake_frame_ms=-1;
bool dark_frame_pending{};Millis dark_wake_evidence_at{};
// ---- G16E detector tuning ----------------------------------------------------------
int tune_det_window=-1,tune_det_burst=-1,tune_det_cooldown=-1,tune_det_dedupe=-1,tune_det_change=-1,tune_det_area=-1;
// ---- G16G data path: EAPOL + per-channel receive errors, load measured each second ----------
int tune_det_datapath=-1;
// ---- G16J: the same-name watch (on by default), the optional area sweep (off until spike (b)) ----
int tune_det_twin=-1,tune_det_sweep=-1;
// Spike (a) (data-path load on this stick, firmware/evidence/) decides the detect.datapath default.
// Until it is recorded the default stays 0 and Details prints "handshake watch: off". Set this to
// true only when the spike measured a load that forces it off: Details then prints "off (load)".
constexpr bool datapath_off_for_load=false;
constexpr Millis sweep_period_ms=2000;       // ledger G16J: a 100 ms dwell every 2 s
bool sweeping{};Millis sweep_left{},sweep_away_in_window{};   // excursion bookkeeping for the coverage report
guardian::tune::ThreatKeys threat_keys;   // review 2026-11-17: t.* = every G16F/G16G threat limit
sticks3::MeasurementRadio::CallbackWindow cb_last{};   // the callback's last full second
std::uint32_t loss_samples{};
Millis last_load{};
void text(const char* s);
void configure_detectors() {
    if(!tuning || !monitor)return;
    DetectorLimits l=monitor->limits();
    // t.*: the wanted pattern limits (applied below); G16J: the red burst reads the two shape counts too.
    const auto wanted=threat_keys.count?guardian::tune::threat_limits_from(*tuning,threat_keys,monitor->threat_limits()):monitor->threat_limits();
    l.shape_frames=wanted.shape_frames;l.shape_run=wanted.shape_run;
    l.window_ms=static_cast<std::uint32_t>(tuning->get(tune_det_window));
    l.burst_threshold=static_cast<std::uint32_t>(tuning->get(tune_det_burst));
    l.cooldown_ms=static_cast<std::uint32_t>(tuning->get(tune_det_cooldown));
    l.dedupe_ms=static_cast<std::uint32_t>(tuning->get(tune_det_dedupe));
    l.change_threshold=static_cast<std::uint32_t>(tuning->get(tune_det_change));
    if(!monitor->set_limits(l))text("G16E TUNE detect limits refused; previous limits kept\n");
    if(!monitor->set_area_visibility(static_cast<Millis>(tuning->get(tune_det_area))))text("G16E TUNE detect.area_ms refused\n");
    if(threat_keys.count) {   // t.*: the detectors refuse an inconsistent set; the previous limits then stay
        if(!guardian::tune::threat_limits_equal(wanted,monitor->threat_limits()) && !monitor->set_threat_limits(wanted))
            text("TUNE t.* limits refused by the detectors (inconsistent set); previous limits kept\n");
    }
    // G16G: the data path is off until the owner turns it on (TUNE detect.datapath=1) after
    // the on-device load spike; the handshake / frame-loss detectors stay unfed (not shown) while off.
    if(tune_det_datapath>=0) {
        const bool on=tuning->get(tune_det_datapath)>=0.5f;
        if(radio.set_data_path(on))monitor->set_data_path(on);
        else {monitor->set_data_path(false);text("G16G TUNE detect.datapath refused by the driver; data path off\n");}
    }
    // G16J: the same-name watch follows TUNE detect.twin (default on); the area sweep follows
    // detect.sweep_ms (default 0 = off: the radio never leaves the selected network's channel).
    if(app && tune_det_twin>=0)app->set_impostor_watch(tuning->get(tune_det_twin)>=0.5f);
    if(tune_det_sweep>=0)survey.set_sweep(static_cast<Millis>(tuning->get(tune_det_sweep)),sweep_period_ms);
}
// G16J: what the Details page prints about the radio's limits.
void fill_limits(companion::Status& st) {
    st.handshake=monitor && monitor->data_path()?companion::HandshakeWatch::On
        :datapath_off_for_load?companion::HandshakeWatch::OffLoad:companion::HandshakeWatch::Off;
    st.area_sweep=survey.sweep_dwell_ms()>0;
    // G16N "dark guard: about N h left": from the measured Dark drain of the battery run (BATTRUN), never a guess.
    if(tuning && tune_dark_s>=0) {
        std::uint16_t h10=0;
        if(!idle.params().dark_ms)st.dark_guard=companion::DarkGuard::Off;   // the value the idle policy runs with (whole seconds)
        else if(battery_log && battery_log->has_run() && battery_state.known
                && guardian::battery::dark_hours_left(battery_log->run(),battery_state.mv,int(std::lround(tuning->get(tune_dark_floor))),h10))
            {st.dark_guard=companion::DarkGuard::Measured;st.dark_guard_h10=h10;}
        else st.dark_guard=companion::DarkGuard::NotMeasured;
    }
}
// G16G: once a second, the per-channel receive counts go to the frame-loss
// detector, and the callback-cost window is kept for STATUS.
void load_tick(Millis now) {
    static std::array<ChannelLoadSample,measurement::ChannelLoadMeter::channels> samples;
    const auto n=radio.sample_load({clock_ptr->epoch(),now,true},samples.data(),samples.size());
    for(std::size_t i=0;i<n;++i)monitor->channel_load(samples[i]);
    loss_samples+=static_cast<std::uint32_t>(n);
    cb_last=radio.take_callback_window();
}
constexpr Millis dim_cadence_ms=1000;   // the dim view is static: one frame a second (evidence deadlines still redraw)
// G16N: the only writer of the backlight after boot (the deep-sleep teardown aside), so the loop can tell
// what is on the glass and restore it after anything that lit the screen for a message.
void apply_backlight(std::uint8_t pct) {
    if(int(pct)==backlight_applied || !board_ptr)return;
    board_ptr->set_backlight(pct);backlight_applied=pct;
}
std::uint8_t dim_backlight_pct(){return tuning && tune_dim_pct>=0?static_cast<std::uint8_t>(tuning->get(tune_dim_pct)):std::uint8_t(10);}
// G23: the update-poll period the loop runs now (USB / unknown power: ota.auto_s; battery: ota.auto_batt_s when >= 0).
std::uint64_t poll_period_ms(bool on_battery) {
    if(!tuning || tune_ota_auto<0)return 0;
    return guardian::ota::poll_period_ms(tuning->get(tune_ota_auto),tune_ota_auto_batt>=0?tuning->get(tune_ota_auto_batt):guardian::ota::follow_auto_s,on_battery);
}
// G23: the CPU frequency this image runs while dark: the TUNE value in the dark-cpu image, 160 MHz otherwise.
std::uint16_t dark_mhz() {
#if CONFIG_GUARDIAN_DARK_CPU
    if(tuning && tune_dark_cpu>=0)return gp::dark_cpu_mhz(tuning->get(tune_dark_cpu));
#endif
    return gp::cpu_default_mhz;
}
#if CONFIG_GUARDIAN_DARK_CPU
// G23: esp_pm_configure with max = min (no frequency scaling inside a state, no light sleep). The Wi-Fi driver's
// ESP_PM_APB_FREQ_MAX lock keeps the modem clock; esp_pm_configure refuses what the chip cannot run (counted).
void apply_cpu(std::uint16_t mhz) {
    if(mhz==cpu_applied_mhz)return;
    esp_pm_config_t c{};c.max_freq_mhz=mhz;c.min_freq_mhz=mhz;c.light_sleep_enable=false;
    if(esp_pm_configure(&c)==ESP_OK){cpu_applied_mhz=mhz;++cpu_switches;}else ++cpu_set_fail;
}
#endif
guardian::battery::Phase battery_phase();
// G23: the setting values in effect, for BATTRUN's drain segments (a change on battery starts a new segment).
guardian::battery::Settings battery_settings() {
    guardian::battery::Settings v;
    v.poll_s=static_cast<std::uint16_t>(poll_period_ms(true)/1000u);v.dark_mhz=dark_mhz();v.dim_pct=dim_backlight_pct();
    return v;
}
guardian::battery::Phase battery_phase() {   // BATTRUN per-state drain: which screen state this second belongs to
    switch(idle.state()) {
    case gp::State::Dim: return guardian::battery::Phase::Dim;
    case gp::State::Dark: return guardian::battery::Phase::Dark;
    case gp::State::Active: case gp::State::Sleep: break;
    }
    return guardian::battery::Phase::Active;
}
bool g_front{},g_side{};   // this loop's key levels after the wake-press guard
gp::WakeCause wake_cause_now() {
    switch(esp_sleep_get_wakeup_cause()) {
    case ESP_SLEEP_WAKEUP_EXT1: return gp::WakeCause::Ext1;
    case ESP_SLEEP_WAKEUP_TIMER: return gp::WakeCause::Timer;   // G16P: the USB check
    case ESP_SLEEP_WAKEUP_UNDEFINED: return gp::WakeCause::None;   // cold boot, reset, OTA reboot
    default: return gp::WakeCause::Other;
    }
}
// RTC-backed system time: keeps counting through deep sleep (system_time.rst).
std::uint64_t rtc_now_us() {
    timeval tv{};gettimeofday(&tv,nullptr);
    return static_cast<std::uint64_t>(tv.tv_sec)*1000000u+static_cast<std::uint64_t>(tv.tv_usec);
}
companion::persona::Motion motion() {
    companion::persona::Motion m;
    if(tuning){m.tilt_max_deg=tuning->get(tune_sway);m.breath_amount=tuning->get(tune_breath);
        m.ember_peak=tuning->get(tune_ember);m.smoke_alpha=tuning->get(tune_smoke);}
    return m;
}
// G16C: the motion model follows TUNE live (a changed axis map resets it).
void configure_motion() {
    if(!tuning)return;
    companion::motion::Params p;
    for(const auto& k:motion_keys)if(k.index>=0)p.*(k.field)=tuning->get(k.index);
    motion_model.configure(companion::motion::axis_map_from(tuning->get(tune_imu_right),tuning->get(tune_imu_up),tuning->get(tune_imu_out)),p);
    {   // G16I: shake rule and burst length (an unchanged rule keeps the detector's state)
        companion::shake::Params sp;
        if(tune_shake_g>=0)sp.g=tuning->get(tune_shake_g);
        if(tune_shake_peaks>=0)sp.peaks=static_cast<std::uint8_t>(std::lround(tuning->get(tune_shake_peaks)));
        if(tune_shake_window>=0)sp.window_ms=static_cast<std::uint16_t>(std::lround(tuning->get(tune_shake_window)));
        shake_detector.configure(sp);
        if(face_burst)face_burst->configure(burst_params(*tuning));
    }
    configure_head();   // G21
    // G16D: idle timeouts from TUNE power.*; "moved" uses the same rest thresholds as the face.
    gp::MotionThresholds t;
    if(tune_rest_gyro>=0)t.gyro_dps=tuning->get(tune_rest_gyro);
    if(tune_rest_acc>=0)t.acc_g=tuning->get(tune_rest_acc);
    activity.configure(t);
    gp::Params ip;
    if(tune_dim_s>=0)ip.dim_ms=static_cast<std::uint32_t>(tuning->get(tune_dim_s)*1000.0f);
    if(tune_sleep_s>=0)ip.sleep_ms=static_cast<std::uint32_t>(tuning->get(tune_sleep_s)*1000.0f);
    // G16N: whole seconds (0 = off, never a fraction of a second of Dim); the floor in whole percent.
    if(tune_dark_s>=0)ip.dark_ms=static_cast<std::uint32_t>(std::lround(tuning->get(tune_dark_s)))*1000u;
    if(tune_dark_floor>=0)ip.dark_floor_pct=static_cast<std::uint8_t>(std::lround(tuning->get(tune_dark_floor)));
    if(tune_sleep_check>=0)ip.sleep_check_s=gp::sleep_check_period_s(tuning->get(tune_sleep_check));   // G16P: whole seconds inside 60..3600
    idle.configure(ip);
}
const char* motion_text() {
    const auto imu=sticks3::imu::status().state;
    if(imu!=guardian::imu::State::Running)return "no_imu";
    if(!tuning || !companion::motion::axis_map_from(tuning->get(tune_imu_right),tuning->get(tune_imu_up),tuning->get(tune_imu_out)).valid())return "unmapped";
    const auto& o=motion_model.output();
    return o.active?"following":"waiting";
}
bool next_packet() {
    FrameSpan span{};
    if(!radio.next({packet.bytes.data(),static_cast<std::uint16_t>(packet.bytes.size())},span,packet.meta))return false;
    packet.size=span.size;packet.truncated=span.truncated;return true;
}
// G16C rework: the companion's console writes never wait (a closed host port
// cannot stall observation) and a lost line is a console drop, not a lost frame;
// the G13 lab console keeps its accepted policy (link_health.hpp).
void text(const char* s) {
    const auto n=std::strlen(s);
    if(capture_buf) {   // reply of a TUNE-session command: collected, sent over Wi-Fi
        const std::size_t room=capture_cap-1-capture_len,k=n<room?n:room;
        std::memcpy(capture_buf+capture_len,s,k);capture_len+=k;capture_buf[capture_len]=0;return;
    }
    const auto policy=sticks3::write_policy(control==Control::Console?sticks3::ConsoleOwner::Lab:sticks3::ConsoleOwner::Companion);
    const std::int64_t t0=esp_timer_get_time();
    const bool ok=usb_serial_jtag_write_bytes(s,n,pdMS_TO_TICKS(policy.timeout_ms))==static_cast<int>(n);
    health.console_write(ok,esp_timer_get_time()-t0);
    if(!ok && policy.counts_as_frame_drop)++output_drops;
}
// ESP_LOG sink (every task, including the Wi-Fi driver's): formats into one
// buffer under a try-lock and writes with no wait; anything else is a counted drop.
int log_vprintf(const char* format,va_list args) {
    static char line[256];
    if(!log_lock || xSemaphoreTake(log_lock,0)!=pdTRUE){health.log_line(false);return 0;}
    const int w=std::vsnprintf(line,sizeof line,format,args);
    const int n=w<0?0:w>=static_cast<int>(sizeof line)?static_cast<int>(sizeof line)-1:w;
    const bool ok=!n || usb_serial_jtag_write_bytes(line,static_cast<std::size_t>(n),0)==n;
    xSemaphoreGive(log_lock);
    health.log_line(ok);
    return n;
}
// IMU stream lines never wait for the host (timeout 0) and have their own drop
// counter, so a closed monitor cannot slow the loop or touch G13 drop accounting.
void text_imu(const char* s) {
    const auto n=std::strlen(s);
    if(usb_serial_jtag_write_bytes(s,n,0)!=static_cast<int>(n))++imu_output_drops;
}
void send_record() {
    record.boot=boot;record.sequence=sequence++;record.received=radio.received();
    record.drops=radio.queue_drops()+output_drops;record.bad=radio.bad();
    auto& binary=bufs->binary;auto& wire_line=bufs->wire_line;
    const auto n=grx::encode(record,binary,sizeof binary);
    if(!n){++output_drops;return;}
    std::memcpy(wire_line,"GRX1 ",5);const char* hex="0123456789abcdef";
    for(std::size_t i=0;i<n;++i){wire_line[5+2*i]=hex[binary[i]>>4];wire_line[6+2*i]=hex[binary[i]&15];}
    wire_line[5+2*n]='\n';wire_line[6+2*n]=0;text(wire_line);
}
void status(std::uint8_t kind) {
    record={};record.kind=kind;record.channel=channel;
    record.flags=radio.listening() && survey.monitoring()?1:0;
    record.acquired_us=static_cast<std::uint64_t>(esp_timer_get_time());send_record();
}
void cover() {
    const auto now=clock_ptr->now();const auto total=drops();
    CoverageReport c{};c.sampled_at={clock_ptr->epoch(),now,true};
    const bool stable=radio.listening() && survey.monitoring() && stable_since<=last_cover;
    // G16J: a sweep excursion is a planned gap, reported honestly: the selected channel stays the
    // reported one, the window is marked hopping and the time away is taken off listened_ms.
    Millis away=sweep_away_in_window;
    if(sweeping && now>sweep_left){away+=now-sweep_left;sweep_left=now;}
    sweep_away_in_window=0;
    c.channel=stable?survey.channel():0;c.hopping=radio.listening() && (!survey.monitoring() || away>0);
    c.window_ms=now>last_cover?now-last_cover:1;c.listened_ms=stable?c.window_ms-std::min<Millis>(c.window_ms,away):0;
    c.dropped_in_window=total-previous_drops;c.passive_receive=stable?Support::Supported:Support::Unknown;
    monitor->coverage(c);previous_drops=total;last_cover=now;
}
void snapshot() {
    char prefix[40];std::snprintf(prefix,sizeof prefix,"G13 %016" PRIx64 " ",boot);
    auto& state_line=bufs->state_line;
    if(monitor->json(state_line,sizeof state_line,drops(),radio.listening(),radio.listening() && !survey.monitoring())) {
        const auto used=std::strlen(state_line);
        const int metrics=std::snprintf(state_line+used-1,sizeof(state_line)-used+1,
            ",\"heap_internal\":%u,\"heap_internal_min\":%u,\"task_stack_free\":%u}",
            unsigned(heap_caps_get_free_size(MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT)),
            unsigned(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT)),
            unsigned(uxTaskGetStackHighWaterMark(nullptr)));
        if(metrics<0 || static_cast<std::size_t>(metrics)>=sizeof(state_line)-used+1){++output_drops;return;}
        // One USB write keeps state prefix/body together; bounded scratch (TextBuffers).
        auto& line=bufs->snapshot_line;const auto crc=grx::crc32(reinterpret_cast<const std::uint8_t*>(state_line),std::strlen(state_line));
        std::snprintf(line,sizeof line,"%s%08" PRIx32 " %s\n",prefix,crc,state_line);text(line);
    } else ++output_drops;
}
void stop() {
    survey.stop();deadline=0;drop_budget=0;stable_since=clock_ptr->now();
    if(!radio.stop()) {text("GRX1 ERROR receive stop failed; reboot required\n");abort();}
    cover();status(4);snapshot();
}
// The lab console takes the radio from the companion once, before its first
// scoped command. Counters restart so the G13 harness sees only its own session.
void take_console() {
    if(control==Control::Console)return;
    control=Control::Console;survey.stop();survey.hold_discovery(false);deadline=0;drop_budget=0;
    if(radio.listening() && !radio.stop()){text("GRX1 ERROR receive stop failed; reboot required\n");abort();}
    radio.reset_counters();output_drops=deliberate_drops=previous_drops=0;
    stable_since=last_cover=clock_ptr->now();
}
companion::RadioState radio_state();
// Review 2026-11-17 (stack): the console (G13) screen takes its ~2 KB Snapshot in its own
// frame, so app_main's frame no longer reserves it under every companion call.
__attribute__((noinline)) void draw_console(sticks3::Board& board,sticks3::RedrawSchedule& redraw,Millis draw_now) {
    const auto shown=monitor->snapshot();
    sticks3::draw_measurement(board,shown,monitor->accepted,monitor->invalid,drops(),radio.listening(),survey.monitoring(),channel,draw_now);
    redraw.drawn(draw_now,shown.has_security,shown.age_ms,Core::fresh_ms);
}
#if CONFIG_GUARDIAN_ART_BENCH
// ---- G16Q art bench (build variant only; catalogue, keys and drawing are in art_bench.hpp, host-tested) ----
namespace ab=sticks3::artbench;
ab::Bench bench;
ab::Frames bench_frames;
bool bench_frames_ok{};
int bench_gamma_applied{0};            // 0: the panel's power-on gamma (Board::init sends none), 1: the M5GFX table
unsigned bench_gamma_errors{};         // panel calls of a gamma change that failed
bool bench_drawn{};std::size_t bench_drawn_index{};bool bench_label_shown{};Millis bench_last_draw{};
constexpr Millis bench_still_cadence_ms=250;   // a still candidate is repainted this often (heals the glass after an update screen)
void bench_frames_init() {
    const auto take=[](const std::uint8_t* b,const std::uint8_t* e){return static_cast<std::size_t>(e-b)==ab::frame_bytes?b:nullptr;};
#define GUARDIAN_BENCH_ROW(row,letter) \
    bench_frames.art[row]={take(bench_##letter##_VeryGood_start,bench_##letter##_VeryGood_end), \
        take(bench_##letter##_Horrible_start,bench_##letter##_Horrible_end),take(bench_##letter##_Medium_start,bench_##letter##_Medium_end)};
    GUARDIAN_BENCH_ROW(0,A) GUARDIAN_BENCH_ROW(1,B) GUARDIAN_BENCH_ROW(2,C) GUARDIAN_BENCH_ROW(3,D) GUARDIAN_BENCH_ROW(4,E)
#undef GUARDIAN_BENCH_ROW
    bench_frames.ramp=take(bench_ramp_start,bench_ramp_end);
    bench_frames_ok=bench_frames.complete();
}
// " bench=<name> ... bench_gamma_errors=<n>" in place of the newline that ends `line` (nothing when it does not fit).
void bench_status_append(char* line,std::size_t cap) {
    char frag[208];std::size_t f=bench.status(frag,sizeof frag-32,bench_frames_ok);
    if(!f)return;
    f+=static_cast<std::size_t>(std::snprintf(frag+f,sizeof frag-f," bench_gamma_errors=%u",bench_gamma_errors));
    const std::size_t n=std::strlen(line);
    if(!n || line[n-1]!='\n' || n+f+1>cap)return;
    std::memcpy(line+n-1,frag,f);line[n-1+f]='\n';line[n+f]=0;
}
void bench_line(const char* what) {
    char line[272];std::snprintf(line,sizeof line,"G16Q BENCH %s\n",what);
    bench_status_append(line,sizeof line);text(line);
}
// BENCH, BENCH NEXT, BENCH PREV, BENCH GO <name>, BENCH BL <60|80|100>, BENCH LIST (USB console).
bool bench_command(const char* input) {
    if(std::strncmp(input,"BENCH",5) || (input[5] && input[5]!=' '))return false;
    const auto now=static_cast<std::uint32_t>(clock_ptr->now());
    const char* arg=input[5]?input+6:"";
    if(!*arg){bench_line("status");return true;}
    if(!std::strcmp(arg,"NEXT")){bench.next(now);bench_line("candidate");return true;}
    if(!std::strcmp(arg,"PREV")){bench.prev(now);bench_line("candidate");return true;}
    if(!std::strncmp(arg,"GO ",3)) {
        if(bench.go(arg+3,now))bench_line("candidate");else text("G16Q BENCH ERROR no such candidate (BENCH LIST)\n");
        return true;
    }
    if(!std::strncmp(arg,"BL ",3)) {
        char* end=nullptr;const long v=std::strtol(arg+3,&end,10);
        if(end!=arg+3 && !*end && v>=0 && v<=100 && bench.set_backlight(static_cast<int>(v),now))bench_line("backlight");
        else text("G16Q BENCH ERROR use BENCH BL 60, BENCH BL 80 or BENCH BL 100\n");
        return true;
    }
    if(!std::strcmp(arg,"LIST")) {
        char line[320];std::size_t used=0;
        for(std::size_t i=0;i<ab::entry_count;++i) {
            if(!used)used=static_cast<std::size_t>(std::snprintf(line,sizeof line,"G16Q BENCH LIST"));
            used+=static_cast<std::size_t>(std::snprintf(line+used,sizeof line-used," %s",ab::entry(i).name));
            if(i%9==8 || i+1==ab::entry_count){std::snprintf(line+used,sizeof line-used,"\n");text(line);used=0;}
        }
        return true;
    }
    text("G16Q BENCH ERROR use BENCH, BENCH NEXT, BENCH PREV, BENCH GO <name>, BENCH BL <60|80|100> or BENCH LIST\n");
    return true;
}
// One loop of the bench: keys, the candidate's panel state (gamma table, backlight), the frame.
// It replaces the idle policy and the companion screens: the bench never dims, sleeps or captures.
void bench_step(Millis now,bool display) {
    const auto now32=static_cast<std::uint32_t>(now);
    bool changed=false;
    if(buttons_ok) {
        const auto c=bench.keys(board_ptr->key_front_down(),board_ptr->key_side_down(),now32);
        if(c.entry)bench_line("candidate");else if(c.backlight)bench_line("backlight");
        changed=c.any();
    }
    if(int(bench.gamma())!=bench_gamma_applied) {
        // Dark while the panel is written: taking the table away is a panel reset, and the glass shows
        // undefined memory until the next full frame.
        apply_backlight(0);
        if(!board_ptr->set_panel_gamma(bench.gamma(),ab::m5gfx_gamma[0].data.data(),ab::m5gfx_gamma[1].data.data()))++bench_gamma_errors;
        bench_gamma_applied=bench.gamma()?1:0;dirty.invalidate();changed=true;
        char line[96];std::snprintf(line,sizeof line,"G16Q BENCH panel gamma=%d errors=%u\n",bench_gamma_applied,bench_gamma_errors);text(line);
    }
    const bool label=bench.label_visible(now32);
    const Millis cadence=bench.animated() && tuning && tune_frame_ms>=0?static_cast<Millis>(tuning->get(tune_frame_ms)):bench_still_cadence_ms;
    if(display && (changed || !bench_drawn || bench.index()!=bench_drawn_index || label!=bench_label_shown || now-bench_last_draw>=cadence)) {
        if(auto* canvas=board_ptr->canvas()) {
            ab::draw(*canvas,bench,bench_frames,now32,warp_cache);
            const bool force=now-last_full_push>=full_push_ms;
            const auto plan=dirty.plan(canvas->pixels(),canvas->width(),canvas->height(),force);
            if(plan.full){last_full_push=now;++full_pushes;}
            if(!board_ptr->present_rows(plan))dirty.invalidate();
            for(std::size_t r=0;r<plan.count;++r)push_rows_total+=static_cast<std::uint64_t>(plan.runs[r].rows);
            ++push_frames;
        }
        bench_drawn=true;bench_drawn_index=bench.index();bench_label_shown=label;bench_last_draw=now;
    }
    apply_backlight(bench.backlight_pct());
}
#endif
void companion_status() {
    if(control==Control::Companion)app->tick();
    const auto& v=app->presenter().view();auto& line=bufs->status_line;
    const auto imu=sticks3::imu::status();char imu_text[96];
    if(imu.state==guardian::imu::State::Running)std::snprintf(imu_text,sizeof imu_text,"running@0x%02x",imu.address);
    else if(imu.failure && *imu.failure) {   // 2026-11-18: the failing init step is part of STATUS (imu=init-failed:why_it_failed)
        std::snprintf(imu_text,sizeof imu_text,"%s:%s",guardian::imu::state_text(imu.state),imu.failure);
        for(char* c=imu_text;*c;++c)if(*c==' '||*c=='(' || *c==')')*c='_';
    } else std::snprintf(imu_text,sizeof imu_text,"%s",guardian::imu::state_text(imu.state));
    char tune_version[16];if(tuning)tuning->version(tune_version,sizeof tune_version);else std::snprintf(tune_version,sizeof tune_version,"none");
    char update_text[48];guardian::ota::result_text(ota_record,update_text,sizeof update_text);
    char batt[96];guardian::battery::status_text(battery_state,batt,sizeof batt);
    char frames[160];frame_stats.status_text(frames,sizeof frames);
    char link[240];health.status_text(link,sizeof link);
    char lock_by[measurement::Survey::lock_loss_text_max];   // G23: lock_loss_by=silence:<n>,followed:<n>,held:<n>,stopped:<n>
    if(!survey.lock_loss_text(lock_by,sizeof lock_by))std::snprintf(lock_by,sizeof lock_by,"lock_loss_by=status_overflow");
    char energy[160];   // G23: the battery-life settings in effect (the poll period now, the CPU now and while dark)
    {   const float batt_s=tuning && tune_ota_auto_batt>=0?tuning->get(tune_ota_auto_batt):guardian::ota::follow_auto_s;
        std::snprintf(energy,sizeof energy," ota_auto_batt_s=%d poll_s=%u cpu_mhz=%u dark_cpu_mhz=%u dark_cpu=%s cpu_set_fail=%u cpu_switches=%u",
            batt_s<0.0f?-1:int(std::lround(batt_s)),unsigned(poll_period_ms(power_source.source()==gp::Source::Battery)/1000u),
            unsigned(cpu_applied_mhz),unsigned(dark_mhz()),dark_cpu_built?"built":"unbuilt",cpu_set_fail,cpu_switches);}
    char power[640];gp::status_text(idle,power_source.source(),power_source.last_vin_mv(),static_cast<std::uint32_t>(clock_ptr->now()),
        wake_info,retained,wake_guard.swallowed(),power,sizeof power);
    {   // G16N: the last incident wake's latency (ms from the evidence instant; -1 = none since boot)
        const auto used=std::strlen(power);
        std::snprintf(power+used,sizeof power-used," dark_wake_evidence_ms=%d dark_wake_frame_ms=%d wake_check=%s",dark_wake_evidence_ms,dark_wake_frame_ms,
            !check_ran?"-":!check_pm1_open?"pm1_bus_failed":gp::check_text(check_info.outcome));   // G16P: this boot's timer check (640 B: idle_check proves the longest fragment fits)
    }
    auto& detect=bufs->detect;   // off the task stack (TextBuffers)
    if(!monitor->status_text(detect,sizeof detect))std::snprintf(detect,sizeof detect," detectors=status_overflow");
    // G16S: who the frames of the last disconnect burst named, per scope (receiver/sender/BSSID/channel:count).
    auto& bursts=bufs->bursts;
    if(!monitor->burst_text(bursts,sizeof bursts))std::snprintf(bursts,sizeof bursts," last_burst_network=status_overflow last_burst_area=status_overflow");
    // G16G spike numbers: data path state, callback calls / CPU per mille / worst call in the last
    // full second (CPU cycles), data frames seen, EAPOL queued, receive errors (never queued).
    char datapath[260];   // G16J: + twin (same-name watch on the selection), sweep_ms (area sweep dwell, 0 = off)
    std::snprintf(datapath,sizeof datapath," datapath=%s cb_calls_s=%u cb_cpu_permille=%u cb_max_cycles=%u rx_data=%u rx_eapol=%u rx_errors=%u rx_valid=%u loss_samples=%u twin=%d sweep_ms=%u",
        radio.data_path()?"on":"off",unsigned(cb_last.calls),unsigned(cb_last.cycles/(CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ*1000u)),unsigned(cb_last.max_cycles),
        unsigned(radio.data_frames()),unsigned(radio.eapol_kept()),unsigned(radio.rx_errors()),unsigned(radio.load().valid_total()),unsigned(loss_samples),
        int(monitor->scope().has_selection() && monitor->scope().selected().watch_impostors),unsigned(survey.sweep_dwell_ms()));
    char setup_text[300];   // G16M: the session, the page counters and where the credential lives (never a value)
    {   char session[120];if(!setup_session || !setup_session->status_text(session,sizeof session))std::snprintf(session,sizeof session," setup=none");
        std::snprintf(setup_text,sizeof setup_text,"%s setup_pages=%u setup_form_refused=%u setup_ap_error=%s wifi_provisioned=%s cred_store=%s cred_vault=%s cred_migrated=%d cred_plain_cleared=%d",
            session,unsigned(setup_port.pages()),unsigned(setup_port.refused()),setup_port.open_error(),provisioner && provisioner->wifi_provisioned()?"yes":"no",
            guardian::setup::store_text(cred_store),sticks3::vault::state_text(),int(cred_migrated),int(cred_legacy_cleared));}
    char offers[288];   // G22A (worst case 245 characters with ten-digit counts): offers accepted / refused, the last reason and the count per reason
    if(!tune_offers.status(offers,sizeof offers))std::snprintf(offers,sizeof offers,"tune_offers=status_overflow");
    char tune_wifi[48];
    if(tune_session.active())std::snprintf(tune_wifi,sizeof tune_wifi,"active:%us",unsigned(tune_session.remaining_ms(static_cast<std::uint32_t>(clock_ptr->now()))/1000));
    else std::snprintf(tune_wifi,sizeof tune_wifi,"%s",tune_link.running()?"ending":"off");
    std::snprintf(line,sizeof line,"G14 STATUS control=%s onboarding=%u screen=%s mode=%s selected=%s radio=%d store=%d alert=%d face=%d overlay=%d picker=%u picker_dropped=%u heap_internal_min=%u task_stack_free=%u"
        " imu=%s imu_samples=%u imu_drops=%u orient=%s tune_version=%s tune_store=%s edge=%d"
        " ota_slot=%s app_version=%s last_update_result=%s ota_provisioned=%s ota_auto_checks=%u ota_auto_last=%s ota_auto_deferred=%u ota_not_newer=%u selftest=display:%d,store:%d,radio:%d,imu:%d %s"
        " art=%s motion=%s imu_map=%d,%d,%d pose=%d,%d,%d %s"
        " art_ram=%s art_ram_bytes=%u monitor_ram=%s radio_ram=%s text_ram=%s app_ram=%s tune_ram=%s reset=%s uptime_s=%u codec_boot=%s warps=%u warp_reuses=%u art_copies=%u push_rows_avg=%u full_pushes=%u"
        " shakes=%u bursts=%u burst_ram=%s burst_ram_bytes=%u"
        " head=%s head_sets=%u/%u head_frames=%u head_refused=%s head_at=%d:%d,%d head_inflates=%u head_reuses=%u head_fail=%u:%s head_ms=%u.%u/%u.%u head_ram=%s head_ram_bytes=%u"
        " rx_received=%u rx_queue_full=%u rx_discarded=%u rx_bad=%u lock_losses=%u last_lock_loss=%s %s %s"
        " tune_wifi=%s tune_wifi_last_end=%s tune_wifi_commands=%u tune_wifi_refused=%u %s tune_key=%s%s%s%s%s%s%s\n",
        control==Control::Console?"console":"companion",unsigned(app->onboarding()?app->onboarding_page()+1:0),screen_text(v.screen),view_mode_text(v.mode),v.has_selection?v.selected_bssid.c_str():"none",
        int(radio_state()),int(app->store()),int(v.alert),int(v.face),int(v.overlay),unsigned(app->presenter().picker().count),unsigned(app->presenter().picker().dropped),
        unsigned(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT)),unsigned(uxTaskGetStackHighWaterMark(nullptr)),
        imu_text,unsigned(imu.samples),unsigned(imu.ring_drops),sticks3::orientation::display_name,tune_version,
        tuning?tune::store_text(tuning->store()):"none",edge_until?1:0,
        sticks3::ota::slot_text(sticks3::ota::boot_facts().running_slot),sticks3::ota::running_version(),update_text,
        provisioner && provisioner->provisioned()?"yes":"no",unsigned(auto_poll.checks()),auto_last_text,unsigned(auto_poll.deferrals()),ota_not_newer,int(self_test.display),int(self_test.store),int(self_test.radio),int(self_test.imu),batt,
        art_ok?"16":"missing",motion_text(),tuning?int(tuning->get(tune_imu_right)):0,tuning?int(tuning->get(tune_imu_up)):0,tuning?int(tuning->get(tune_imu_out)):0,
        int(std::lround(motion_model.output().roll_deg)),int(std::lround(motion_model.output().pitch_deg)),int(std::lround(motion_model.output().yaw_deg)),frames,
        art_ram,unsigned(art_ram_bytes),monitor_ram,radio.queue_ram(),text_ram,app_ram,tune_ram,reset_text,unsigned(esp_timer_get_time()/1000000),codec_boot,warp_cache?unsigned(warp_cache->warps):0u,warp_cache?unsigned(warp_cache->reuses):0u,warp_cache?unsigned(warp_cache->copies):0u,
        push_frames?unsigned(push_rows_total/push_frames):0u,unsigned(full_pushes),
        unsigned(shake_detector.events()),face_burst?unsigned(face_burst->started()):0u,burst_ram,face_burst?unsigned(sizeof(companion::burst::Burst)):0u,
        !face_head?"none":!face_head->params().on?"off":face_head->sets()?"on":"no_sets",face_head?unsigned(face_head->sets()):0u,unsigned(head_packs),face_head?unsigned(face_head->frames()):0u,
        head_refused?head_refusal:"none",face_head?face_head->shown_mood():-1,face_head?face_head->yaw_index():-1,face_head?face_head->pitch_index():-1,
        face_head?unsigned(face_head->inflates()):0u,face_head?unsigned(face_head->reuses()):0u,face_head?unsigned(face_head->failures()):0u,
        !face_head||!face_head->failures()?"none":face_head->last_failure_was_check()?"check":companion::inflate::result_text(face_head->last_failure()),
        head_changes?unsigned(head_change_us_total/head_changes/1000):0u,head_changes?unsigned(head_change_us_total/head_changes%1000/100):0u,
        unsigned(head_change_us_max/1000),unsigned(head_change_us_max%1000/100),head_ram,unsigned(head_ram_bytes),
        unsigned(radio.received()),unsigned(radio.queue_full()),unsigned(radio.discarded()),unsigned(radio.bad()),
        unsigned(survey.lock_losses()),measurement::Survey::loss_text(survey.last_loss()),lock_by,link,
        tune_wifi,guardian::tune::wifi::end_text(tune_session.end()),unsigned(tune_session.commands()),unsigned(tune_session.refused()),
        offers,tune_key.loaded()?"ota":tune_key_read?"none":"unread",power,energy,detect,bursts,datapath,setup_text);
#if CONFIG_GUARDIAN_ART_BENCH
    bench_status_append(line,sizeof line);   // G16Q: " bench=<name> ..." before the line's newline
#endif
    text(line);
    if(imu.state==guardian::imu::State::Absent || imu.state==guardian::imu::State::InitFailed || imu.state==guardian::imu::State::Faulted) {
        std::snprintf(line,sizeof line,"G16A IMU state=%s reason=%s bus_errors=%u\n",guardian::imu::state_text(imu.state),imu.failure,unsigned(imu.bus_errors));
        text(line);
    }
}
void info() {
    char elf[65]{};esp_app_get_elf_sha256(elf,sizeof elf);
    char line[300];std::snprintf(line,sizeof line,"GRX1 INFO guardian-sticks3/1.0 mac=%02x:%02x:%02x:%02x:%02x:%02x boot=%016" PRIx64 " max=1536 fcs=unavailable logical-length-minus4 country=%s elf=%s\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],boot,configured?configured_country:"unset",elf);text(line);
}
// Parses "<verb>", "<verb> 0" or "<verb> <seconds>" (1..max). -1: malformed.
long seconds_arg(const char* rest,long fallback,long max) {
    if(!*rest)return fallback;
    if(*rest!=' ')return -1;
    char* end=nullptr;const long v=std::strtol(rest+1,&end,10);
    if(end==rest+1 || *end || v<0 || v>max)return -1;
    return v;
}
void board_restart(const char* why);   // 2026-11-18: IMU stopped and soft-reset before any software restart (idle.hpp)
bool console_tool(const char* input) {
    char line[160];
    if(!std::strcmp(input,"RESTART")) {   // USB only (not in the Wi-Fi allowlist): reproduces the post-OTA boot with the port open
        text("G16I RESTART software reset, IMU stopped and reset first\n");board_restart("console");return true;
    }
    if(!std::strncmp(input,"EDGE",4) && (input[4]==0 || input[4]==' ')) {
        const long s=seconds_arg(input+4,60,600);
        if(s<0){text("GRX1 ERROR use EDGE, EDGE <1..600 s> or EDGE 0\n");return true;}
        edge_until=s?clock_ptr->now()+static_cast<Millis>(s)*1000:0;
        std::snprintf(line,sizeof line,s?"G16A ACK edge %lds\n":"G16A ACK edge off\n",s);text(line);return true;
    }
    if(!std::strcmp(input,"BATTRUN")) {   // read-only; console_tool so the Wi-Fi session reaches it (review 2026-11-17)
        // G16N: + per-state drain; G16P: + the timer checks (480 B: battery_check proves the longest line fits).
        // G16P also restores the `else` that a comment had swallowed here (reply was unset without a run log).
        // G23: + the drain segments per setting (run_text_max; battery_check proves the longest line fits). Off the stack.
        static char reply[guardian::battery::run_text_max];
        if(battery_log)guardian::battery::run_text(*battery_log,reply,sizeof reply);
        else std::snprintf(reply,sizeof reply,"BATTRUN none\n");
        text(reply);return true;
    }
    if(!std::strcmp(input,"IMU POSE")) {   // review 2026-11-17: latest 2 s still-pose block (calibration over Wi-Fi)
        const bool running=sticks3::imu::status().state==guardian::imu::State::Running;
        if(!guardian::imu::pose_text(imu_pose,running,esp_timer_get_time(),line,sizeof line))std::snprintf(line,sizeof line,"G16C IMU POSE none reason=overflow\n");
        text(line);return true;
    }
    if(!std::strncmp(input,"IMU",3) && (input[3]==0 || input[3]==' ')) {
        const long s=seconds_arg(input+3,10,600);
        if(s<0){text("GRX1 ERROR use IMU, IMU <1..600 s> or IMU 0\n");return true;}
        const auto imu=sticks3::imu::status();
        if(!s){imu_stream_until=0;std::snprintf(line,sizeof line,"G16A IMU END samples=%u ring_drops=%u output_drops=%u\n",unsigned(imu_streamed),unsigned(imu.ring_drops),unsigned(imu_output_drops));text(line);return true;}
        if(imu.state!=guardian::imu::State::Running){
            std::snprintf(line,sizeof line,"G16A IMU ERROR state=%s reason=%s\n",guardian::imu::state_text(imu.state),imu.failure);text(line);return true;}
        imu_streamed=0;imu_output_drops=0;imu_stream_until=clock_ptr->now()+static_cast<Millis>(s)*1000;
        std::snprintf(line,sizeof line,"G16A IMU STREAM addr=0x%02x rate_hz=%u acc_lsb_per_g=%.0f gyr_lsb_per_dps=%.3f seconds=%ld fields=t_us,sensortime,ax,ay,az,gx,gy,gz\n",
            imu.address,unsigned(guardian::imu::sample_hz),double(guardian::imu::acc_lsb_per_g),double(guardian::imu::gyr_lsb_per_dps),s);
        text(line);return true;
    }
    if(!std::strcmp(input,"FRAMES")) {   // G16C: per-screen frame time and fps since boot (or the last FRAMES 0)
        auto& reply=bufs->frames_reply;frame_stats.table(reply,sizeof reply);text(reply);return true;
    }
    if(!std::strcmp(input,"FRAMES 0")){frame_stats.reset();text("G16C ACK frames_reset\n");return true;}
    if(tuning) {
        auto& reply=bufs->tune_reply;
        if(tuning->command(input,reply,sizeof reply)){text(reply);configure_motion();configure_detectors();return true;}
    }
    return false;
}
// Drains the IMU ring every loop; prints raw samples while a stream is active.
void drain_imu(Millis now) {
    if(imu_stream_until && now>=imu_stream_until) {
        imu_stream_until=0;const auto imu=sticks3::imu::status();char line[128];
        std::snprintf(line,sizeof line,"G16A IMU END samples=%u ring_drops=%u output_drops=%u\n",unsigned(imu_streamed),unsigned(imu.ring_drops),unsigned(imu_output_drops));text(line);
    }
    guardian::imu::Sample s;
    const bool imu_running=sticks3::imu::status().state==guardian::imu::State::Running;
    if(!imu_running){motion_model.reset();imu_pose.reset_partial();shake_detector.reset();}   // absent or faulted: static, still correct screens
    for(unsigned i=0;i<64 && sticks3::imu::ring().pop(s);++i) {
        if(imu_running) {   // G16C: raw LSB -> g and deg/s for the motion model
            companion::motion::Reading r;r.t_us=s.t_us;
            for(int k=0;k<3;++k){r.acc_g[k]=float(s.acc[k])/guardian::imu::acc_lsb_per_g;r.gyr_dps[k]=float(s.gyr[k])/guardian::imu::gyr_lsb_per_dps;}
            motion_model.sample(r);
            activity.sample(r.acc_g,r.gyr_dps);   // G16D: handling keeps the screen bright
            shake_detector.sample(r.acc_g,s.t_us);   // G16I: raw IMU axes (the rule needs no axis map)
            imu_pose.add(s);
        }
        if(!imu_stream_until)continue;
        char line[112];
        std::snprintf(line,sizeof line,"IMU %" PRId64 " %" PRIu32 " %d %d %d %d %d %d\n",s.t_us,s.sensor_time,
            int(s.acc[0]),int(s.acc[1]),int(s.acc[2]),int(s.gyr[0]),int(s.gyr[1]),int(s.gyr[2]));
        text_imu(line);++imu_streamed;
    }
}
#if CONFIG_GUARDIAN_BLE_SPIKE
// ---- G16H Wi-Fi/BLE coexistence spike (spike build variant only) -------------------
// BLESPIKE start [phase_s rounds]: interleaved OFF/ON phases of PASSIVE BLE scanning
// while the companion keeps monitoring the selected AP; per phase the selected AP's
// beacons, every received frame, queue-full drops, advertising reports, display frames,
// the lowest internal heap and the battery voltage; then one verdict per duty level
// (adapters/coex/coex_spike.*, host-tested). Nothing is transmitted.
namespace coex=guardian::coex;
coex::Spike spike;
const coex::Criteria spike_criteria{};
std::uint32_t spike_heap_before_ble{},spike_heap_after_ble{};
const char* spike_end="none";   // why the last run ended: completed / stop / console / tune / update / scan_refused
// Supervisor 2026-11-19: the stick's USB is only its charger, so the run is armed over the Wi-Fi TUNE session and
// starts after that session ends (a session takes the radio and would end the run), once the Guardian monitors the
// selected AP again; it gives up after spike_arm_wait_ms (spike_end=not_monitoring). The self-fetch poll and the
// dim/sleep policy wait while a run is armed or running.
bool spike_armed=false;
coex::Plan spike_armed_plan{};
Millis spike_armed_since=0;   // 0 = the TUNE session that armed it is still open
constexpr Millis spike_arm_wait_ms=180000;
coex::Sample spike_sample() {
    coex::Sample s;
    s.heap_internal_free=static_cast<std::uint32_t>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    s.vbat_ok=battery_state.known && !battery_state.external;   // a voltage trend means something only on battery
    s.vbat_mv=battery_state.mv;
    s.monitoring=control==Control::Companion && radio.listening() && survey.monitoring();
    s.channel=channel;
    s.lock_losses=survey.lock_losses();
    return s;
}
coex::Counters spike_counters() {
    coex::Counters c;
    c.frames=radio.received();c.queue_full=radio.queue_full();c.adv_reports=sticks3::ble::adv_reports();c.display_frames=push_frames;
    return c;
}
void spike_phases() {
    char line[400];
    for(std::size_t i=0;i<spike.completed();++i)if(coex::phase_text(line,sizeof line,spike.plan(),i,spike.result(i)))text(line);
}
void spike_report() {
    char line[400];
    const auto r=coex::evaluate(spike.plan(),spike.results(),spike.completed(),spike_criteria);
    for(std::size_t i=0;i<r.level_count;++i)if(coex::level_text(line,sizeof line,r.levels[i]))text(line);
    if(coex::verdict_text(line,sizeof line,r,spike.plan(),spike_criteria))text(line);
    std::snprintf(line,sizeof line,"G16H SPIKE END why=%s ble_errors=%u ble_last_error=%d heap_before_ble=%u heap_after_ble=%u heap_internal_min=%u\n",
        spike_end,unsigned(sticks3::ble::errors()),sticks3::ble::last_error(),unsigned(spike_heap_before_ble),unsigned(spike_heap_after_ble),
        unsigned(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL)));
    text(line);
}
void spike_phase_line() {
    if(!spike.completed())return;
    char line[400];const auto i=spike.completed()-1;
    if(coex::phase_text(line,sizeof line,spike.plan(),i,spike.result(i)))text(line);
}
void spike_abort(const char* why) {
    if(!spike.running())return;
    spike_end=why;
    const auto st=spike.abort();
    if(st.apply)sticks3::ble::apply(st.duty);
    spike_phase_line();spike_report();
}
// Every loop: phase boundaries apply the next duty; anything that takes the radio ends the run.
void spike_service(Millis now) {
    if(!spike.running())return;
    if(control!=Control::Companion){spike_abort("console");return;}
    if(tune_session.active() || tune_link.running()){spike_abort("tune");return;}
    if(update_requested || update_confirm.is_open()){spike_abort("update");return;}
    if(setup_visible()){spike_abort("setup");return;}
    const auto st=spike.tick(now,spike_counters(),spike_sample());
    if(st.phase_done)spike_phase_line();
    if(st.apply && !sticks3::ble::apply(st.duty)) {
        if(!st.finished){spike_abort("scan_refused");return;}
    }
    if(st.finished){spike_end="completed";spike_report();}
}
void spike_begin(const coex::Plan& plan);
// Supervisor 2026-11-19: an armed run starts once the arming TUNE session is over and the companion owns the radio
// and monitors the selected AP again; a key-opened update/setup or a new session in between does not count as over.
void spike_arm_service(Millis now) {
    if(!spike_armed || spike.running())return;
    if(control!=Control::Companion || tune_session.active() || tune_link.running() || update_requested || update_confirm.is_open() || setup_visible())
        {spike_armed_since=0;return;}
    if(!spike_armed_since)spike_armed_since=now?now:1;
    if(monitor->scope().has_selection() && radio.listening() && survey.monitoring()){spike_armed=false;spike_begin(spike_armed_plan);return;}
    if(now-spike_armed_since>=spike_arm_wait_ms){spike_armed=false;spike_end="not_monitoring";text("G16H SPIKE ERROR armed run gave up: the Guardian did not monitor the selected AP\n");}
}
// "BLESPIKE", "BLESPIKE start", "BLESPIKE start <phase_s 20..600> <rounds 1..4>", "BLESPIKE stop", "BLESPIKE report", "BLESPIKE phases".
// Over Wi-Fi (wifi=true, tune_execute) "start" arms the run instead of starting it.
bool spike_command(const char* input,bool wifi=false) {
    if(std::strncmp(input,"BLESPIKE",8) || (input[8] && input[8]!=' '))return false;
    const char* arg=input[8]?input+9:"";
    char line[300];
    if(!*arg) {
        std::snprintf(line,sizeof line,"G16H SPIKE STATUS run=%s armed=%d phase=%u/%u ble=%s scanning=%d adv=%u ble_errors=%u last_end=%s heap_before_ble=%u heap_after_ble=%u heap_internal=%u\n",
            spike.running()?"running":spike.finished()?"finished":"idle",spike_armed?1:0,unsigned(spike.running()?spike.phase()+1:spike.completed()),unsigned(coex::phase_count(spike.plan())),
            sticks3::ble::state_text(sticks3::ble::state()),sticks3::ble::scanning()?1:0,unsigned(sticks3::ble::adv_reports()),unsigned(sticks3::ble::errors()),spike_end,
            unsigned(spike_heap_before_ble),unsigned(spike_heap_after_ble),unsigned(heap_caps_get_free_size(MALLOC_CAP_INTERNAL)));
        text(line);return true;
    }
    if(!std::strcmp(arg,"stop")) {
        if(spike_armed){spike_armed=false;spike_end="disarmed";text("G16H SPIKE ACK disarmed\n");}
        else if(spike.running())spike_abort("stop");else text("G16H SPIKE ERROR not running\n");
        return true;
    }
    if(!std::strcmp(arg,"phases")){if(spike.completed())spike_phases();else text("G16H SPIKE ERROR no phases recorded\n");return true;}
    if(!std::strcmp(arg,"report")){if(spike.completed())spike_report();else text("G16H SPIKE ERROR no phases recorded\n");return true;}
    if(std::strncmp(arg,"start",5) || (arg[5] && arg[5]!=' ')){text("G16H SPIKE ERROR use BLESPIKE, BLESPIKE start [phase_s rounds], BLESPIKE stop or BLESPIKE report\n");return true;}
    coex::Plan plan=coex::default_plan();
    if(arg[5]) {
        unsigned phase_s=0,rounds=0;char extra;
        if(std::sscanf(arg+6,"%u %u %c",&phase_s,&rounds,&extra)!=2 || phase_s<20 || phase_s>600 || rounds<1 || rounds>coex::max_rounds)
            {text("G16H SPIKE ERROR use BLESPIKE start <phase_s 20..600> <rounds 1..4>\n");return true;}
        plan.phase_ms=phase_s*1000u;plan.rounds=static_cast<std::uint8_t>(rounds);
    }
    if(spike.running()){text("G16H SPIKE ERROR already running\n");return true;}
    if(wifi) {   // supervisor 2026-11-19: armed now, started by spike_arm_service() after this session
        spike_armed=true;spike_armed_plan=plan;spike_armed_since=0;spike_end="armed";
        std::snprintf(line,sizeof line,"G16H SPIKE ARMED phases=%u phase_s=%u rounds=%u minutes=%u starts after this session ends, once the Guardian monitors the selected AP (gives up after %u s); no key, TUNE session or update until it ends\n",
            unsigned(coex::phase_count(plan)),unsigned(plan.phase_ms/1000),unsigned(plan.rounds),unsigned(coex::phase_count(plan)*plan.phase_ms/60000),unsigned(spike_arm_wait_ms/1000));
        text(line);return true;
    }
    spike_begin(plan);return true;
}
// Starts a run now (console start, or an armed run once the radio is the companion's again). Every outcome is a line.
void spike_begin(const coex::Plan& plan) {
    char line[300];
    if(control!=Control::Companion || tune_session.active() || tune_link.running() || update_confirm.is_open() || setup_visible())
        {spike_end="radio_busy";text("G16H SPIKE ERROR the companion must own the radio (no console run, TUNE session or update)\n");return;}
    if(!monitor->scope().has_selection() || !radio.listening() || !survey.monitoring())
        {spike_end="not_monitoring";text("G16H SPIKE ERROR select your AP and wait until the Guardian monitors its channel\n");return;}
    if(sticks3::ble::state()==sticks3::ble::State::Off) {
        spike_heap_before_ble=static_cast<std::uint32_t>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        const bool ok=sticks3::ble::init();
        spike_heap_after_ble=static_cast<std::uint32_t>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        if(!ok){spike_end="ble_init_failed";text("G16H SPIKE ERROR BLE controller/host init failed\n");return;}
    }
    if(sticks3::ble::state()==sticks3::ble::State::Failed){spike_end="ble_failed";text("G16H SPIKE ERROR BLE failed; reboot\n");return;}
    coex::Spike::Step first;
    const auto& bssid=monitor->scope().selected().network.bssid;
    if(!spike.start(plan,coex::Mac{bssid},clock_ptr->now(),first)){spike_end="plan_refused";text("G16H SPIKE ERROR plan refused\n");return;}
    sticks3::ble::apply(first.duty);
    spike_end="running";
    std::snprintf(line,sizeof line,"G16H SPIKE START phases=%u phase_s=%u settle_s=%u rounds=%u levels=%u bssid=%02x%02x%02x%02x%02x%02x channel=%u minutes=%u heap_before_ble=%u heap_after_ble=%u\n",
        unsigned(coex::phase_count(plan)),unsigned(plan.phase_ms/1000),unsigned(plan.settle_ms/1000),unsigned(plan.rounds),unsigned(plan.level_count),
        bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],unsigned(channel),unsigned(coex::phase_count(plan)*plan.phase_ms/60000),
        unsigned(spike_heap_before_ble),unsigned(spike_heap_after_ble));
    text(line);
}
#endif
void command(const char* input) {
    const bool fixed=!std::strncmp(input,"listen ",7);
    char request[160]{};
    if(fixed)std::snprintf(request,sizeof request,"start %s",input+7);
    const auto c=grx::parse_command(fixed?request:input);
    if(c.verb==grx::Verb::Info){info();return;}
    if(c.verb==grx::Verb::Sync){char reply[128];std::snprintf(reply,sizeof reply,"GRX1 SYNC nonce=%u boot=%016" PRIx64 " us=%" PRIu64 "\n",unsigned(c.nonce),boot,static_cast<std::uint64_t>(esp_timer_get_time()));text(reply);return;}
    if(!std::strcmp(input,"STATUS")){companion_status();return;}
#if CONFIG_GUARDIAN_BLE_SPIKE
    if(spike_command(input))return;   // G16H: never takes the radio from the companion
#endif
#if CONFIG_GUARDIAN_ART_BENCH
    if(bench_command(input))return;   // G16Q: BENCH ...
#endif
    if(console_tool(input))return;   // G16A EDGE / IMU / TUNE: never take the radio
    // G16B: OTA provisioning (values never echoed) and the battery run log; never take the radio.
    if(provisioner) {char reply[160];if(provisioner->command(input,reply,sizeof reply)){text(reply);return;}}
#if CONFIG_GUARDIAN_ART_BENCH
    // G16Q: the bench never captures, so the lab console's select / start / listen verbs are refused here.
    text("GRX1 ERROR art bench image: no radio capture (use BENCH, STATUS, TUNE, BATTRUN, RESTART)\n");return;
#endif
    // G16C: the radio is a Wi-Fi station on the owner's network during a TUNE session.
    if(tune_link.running()){text("GRX1 ERROR tune session active; press a key on the stick to end it\n");return;}
    // G16M: the radio is the setup access point (or is joining once to check the password).
    if(setup_session && setup_session->active()){text("GRX1 ERROR setup session open; press a key on the stick to end it\n");return;}
    take_console();
    if(c.verb==grx::Verb::Stop){stop();return;}
    if(!std::strncmp(input,"select ",7)) {
        char bssid[13]{},ssid[65]{},country[3]{},extra;
        if(radio.listening() || std::sscanf(input+7,"%12s %64s %2s %c",bssid,ssid,country,&extra)!=3
           || country[0]<'A' || country[0]>'Z' || country[1]<'A' || country[1]>'Z'
           || !measurement::decode_network(bssid,ssid,selected)) {text("GRX1 ERROR invalid selection; stop first\n");return;}
        if(radio_initialized && std::strcmp(country,configured_country)){text("GRX1 ERROR country change requires reboot\n");return;}
        if(!radio_initialized) {
            if(!radio.init(clock_ptr->epoch(),country)){text("GRX1 ERROR radio initialization; reboot required\n");abort();}
            radio_initialized=true;std::memcpy(configured_country,country,3);
        }
        if(!monitor->select(selected)){text("GRX1 ERROR selected scope rejected\n");return;}
        configured=true;text("G13 ACK selected\n");return;
    }
    if(c.verb==grx::Verb::Start) {
        if(!configured || radio.listening() || !survey.begin(radio.first(),radio.count(),static_cast<std::uint8_t>(c.channel),clock_ptr->now(),fixed)) {text("GRX1 ERROR unavailable start scope/channel\n");return;}
        channel=survey.channel();stable_since=clock_ptr->now();
        if(!radio.tune(channel)){survey.stop();text("GRX1 ERROR tune failed\n");return;}
        deadline=clock_ptr->now()+static_cast<Millis>(c.seconds)*1000;cover();status(2);return;
    }
    if(!std::strcmp(input,"SNAPSHOT")){snapshot();return;}
    if(!std::strcmp(input,"BASELINE")){text(monitor->approve_baseline()?"G13 ACK baseline_approved\n":"GRX1 ERROR no fresh complete baseline\n");return;}
    if(!std::strcmp(input,"DROP 24") && radio.listening()){drop_budget=24;text("G13 ACK deliberate_drop_24\n");return;}
    const bool approve=!std::strncmp(input,"APPROVE_AP ",11),watch=!std::strncmp(input,"WATCH_AP ",9);
    if(approve || watch) {
        Network net{};
        if(!measurement::decode_network(input+(approve?11:9),"-",net) || !monitor->watch_ap(net.bssid,approve)){text("GRX1 ERROR related AP scope\n");return;}
        text("G13 ACK ap_scope_configured\n");return;
    }
    text("GRX1 ERROR unsupported command\n");
}
}
namespace {
// G16C: one command received over Wi-Fi: only the accepted verbs, reply captured and sent back.
void tune_execute(const char* cmd) {
    char* reply=tune_link.reply_buffer();
    if(!reply)return;
    capture_buf=reply;capture_len=0;capture_cap=guardian::tune::wifi::kMaxReply;reply[0]=0;
    const bool ok=guardian::tune::wifi::allowed(cmd);
    if(!ok)text("TUNE ERROR not accepted over Wi-Fi\n");
    else if(!std::strcmp(cmd,"STATUS"))companion_status();
#if CONFIG_GUARDIAN_BLE_SPIKE
    else if(spike_command(cmd,true)){}   // supervisor 2026-11-19: arm and read the G16H spike without the cable
#endif
    else if(!console_tool(cmd))text("TUNE ERROR unsupported\n");
    capture_buf=nullptr;
    tune_session.command(ok);
    tune_link.give_reply(capture_len);
}
}
namespace {
// Receive-only start of the companion: explicit country (802.11d off), then
// passive discovery over that country's 2.4 GHz channels 1..13.
void companion_radio_start() {
    const char* country=CONFIG_GUARDIAN_COUNTRY;
    if(std::strlen(country)!=2 || country[0]<'A' || country[0]>'Z' || country[1]<'A' || country[1]>'Z') {
        companion_radio=companion::RadioState::Unconfigured;return;
    }
    if(!radio.init(clock_ptr->epoch(),country)){companion_radio=companion::RadioState::Failed;return;}
    radio_initialized=true;std::memcpy(configured_country,country,3);
#if CONFIG_GUARDIAN_ART_BENCH
    // G16Q: the Wi-Fi driver is up for the self-fetch poll only. No survey, no tune: promiscuous
    // listening is never switched on (MeasurementRadio enables it in tune()), so nothing is captured.
    companion_radio=companion::RadioState::Off;return;
#endif
    const auto now=clock_ptr->now();
    if(!survey.begin(radio.first(),radio.count(),radio.first(),now) || !radio.tune(survey.channel())) {
        survey.stop();companion_radio=companion::RadioState::Failed;return;
    }
    companion_radio=companion::RadioState::Discovering;
    channel=survey.channel();stable_since=last_cover=now;
}
companion::RadioState radio_state() {
    if(companion_radio==companion::RadioState::Unconfigured || companion_radio==companion::RadioState::Failed)return companion_radio;
    if(!radio.listening() || !survey.active())return companion::RadioState::Off;
    return survey.monitoring()?companion::RadioState::Monitoring:companion::RadioState::Discovering;
}
companion::Key front_key(Action::Primary,Action::PrimaryLong);
companion::Key side_key(Action::Secondary,Action::SecondaryLong);
companion::Frame frame;
// Returns true when an input changed the view (redraw now).
// Up to 24 queued frames through the companion (the radio queue holds 24).
// ---- G16M phone setup: the gestures' request ----------------------------------
void companion_radio_resume();
bool setup_radio_stop() {   // the same hand-over as UPDATE: passive listening off, the driver stays
    if(!radio_initialized)return false;
    survey.stop();
    if(radio.listening() && !radio.stop())return false;
    companion_radio=companion::RadioState::Off;
    return true;
}
bool network_is_open(const guardian::SettingsFingerprint& f) {
    return !f.privacy_bit && f.rsn_state==guardian::ElementState::Absent && f.wpa_state==guardian::ElementState::Absent;
}
// The network the Guardian watches (FRONT x3 path), or an invalid target without a selection.
guardian::setup::Target setup_target_selected() {
    const auto& scope=monitor->scope();
    if(!scope.has_selection())return {};
    const auto& ap=scope.selected();
    return guardian::setup::target_of(ap.network.ssid.data(),ap.network.ssid_size,ap.settings_known && network_is_open(ap.settings));
}
// The list row under the cursor. Its advertised settings are known only when it is the watched network;
// any other row is treated as protected (the page asks its password).
guardian::setup::Target setup_target_cursor() {
    const auto& pv=app->presenter().picker();
    if(app->presenter().screen()!=Screen::Picker || !pv.count || pv.cursor>=pv.count)return {};
    const auto& n=pv.entries[pv.cursor].network;
    const auto& scope=monitor->scope();
    const bool watched=scope.has_selection() && scope.selected().network.ssid_size==n.ssid_size
        && !std::memcmp(scope.selected().network.ssid.data(),n.ssid.data(),n.ssid_size);
    return guardian::setup::target_of(n.ssid.data(),n.ssid_size,watched && scope.selected().settings_known && network_is_open(scope.selected().settings));
}
void setup_request(guardian::setup::Entry how,const guardian::setup::Target& target,Millis now) {
    if(!setup_session)return;
    guardian::setup::Facts facts;
    facts.alert=app->presenter().view().alert;
    facts.busy=control!=Control::Companion || !radio_initialized || update_confirm.is_open() || update_requested || tune_session.active() || tune_link.running();
    std::uint8_t random[guardian::setup::ap_pass_len];esp_fill_random(random,sizeof random);   // the radio driver is running: hardware entropy
    const auto refusal=setup_session->request(how,target,facts,random,static_cast<std::uint32_t>(now));
    guardian::setup::wipe(random,sizeof random);
    static const char* refusals[]={"none","alert","busy","no_network","active"};
    char line[128];std::snprintf(line,sizeof line,"G16M SETUP request gesture=%s refusal=%s state=%s ap_error=%s\n",how==guardian::setup::Entry::PickerHold?"side_hold":"triple_tap",
        refusals[int(refusal)],guardian::setup::state_text(setup_session->state()),setup_port.open_error());text(line);
}
void companion_drain() {
    for(unsigned i=0;i<24 && next_packet();++i) {
#if CONFIG_GUARDIAN_BLE_SPIKE
        spike.frame(packet.bytes.data(),packet.size,packet.meta.acquired.at);   // G16H: selected-AP beacon count
#endif
        if(app->receive(packet)) {
            const auto* observation=monitor->last_security();   // no Snapshot copy on the main stack
            const auto advertised=observation && observation->settings.ds_channel_present?observation->settings.ds_channel:0;
            const bool locked=survey.locked();survey.observed(packet.meta.channel,packet.meta.acquired.at,advertised);
            if(!locked && survey.locked())stable_since=clock_ptr->now();
        }
    }
}
// `front`/`side`: raw key levels after the G16D wake-press guard.
bool companion_step(Millis now,bool front,bool side) {
    companion_drain();
    bool changed=false;
    if(buttons_ok && setup_visible()) {
        // G16M: while a setup screen shows, a key only cancels the session or dismisses the result.
        const Action a=front_key.sample(front,now),b=side_key.sample(side,now);
        setup_hold.sample(side,front,false,static_cast<std::uint32_t>(now));
        if(a!=Action::None || b!=Action::None){setup_session->key(static_cast<std::uint32_t>(now));changed=true;}
    } else if(buttons_ok && (tune_session.active() || tune_link.running())) {
        // G16C: during a TUNE session any key ends it; nothing else acts on keys.
        const Action a=front_key.sample(front,now),b=side_key.sample(side,now);
        if(tune_session.active() && (a!=Action::None || b!=Action::None)){tune_session.key(static_cast<std::uint32_t>(now));changed=true;}
    } else if(buttons_ok) {
        const auto now32=static_cast<std::uint32_t>(now);
        // G16B: both keys ~3 s open the UPDATE confirmation. Ordinary actions are
        // dropped while both keys are involved (including the releasing sample).
        bool suppress=update_gesture.involved();
        if(update_gesture.sample(front,side,now32) && !update_confirm.is_open()) {
            update_confirm.open(now32);edge_until=0;changed=true;
            text("G16B UPDATE confirm_open\n");
        }
        suppress|=update_gesture.involved();
        {   // G16M: SIDE alone held 3 s on a named network of the list opens the phone setup for that network.
            // Sampled before the keys act, so the row is the one under the cursor when the press began
            // (hold SIDE = back still closes the list at 0.8 s; keep holding).
            const bool was_holding=setup_hold.holding();
            const auto on_row=setup_target_cursor();
            const bool fired=setup_hold.sample(side,front,on_row.valid() && !app->onboarding() && !update_confirm.is_open(),now32);
            if(setup_hold.holding() && !was_holding)setup_hold_target=on_row;
            if(fired){setup_request(guardian::setup::Entry::PickerHold,setup_hold_target,now);edge_until=0;changed=true;}
        }
        const Action actions[2]={front_key.sample(front,now),side_key.sample(side,now)};
        bool yes=false,no=false;
        const auto deliver=[&](Action a){
            if(edge_until){edge_until=0;changed=true;return;}   // a key ends the EDGE pattern
            changed|=app->input(a);
        };
        for(const auto a:actions) {
            if(a==Action::None || suppress)continue;
            if(update_confirm.is_open()){yes|=a==Action::Primary;no|=a==Action::Secondary || a==Action::SecondaryLong || a==Action::PrimaryLong;continue;}
            if(a==Action::Primary) {   // owner one-handed gesture: FRONT pressed three times fast
                const auto t=update_taps.tap(now32);
                if(t==guardian::ota::TripleTap::Tap::Hold)continue;
                if(t==guardian::ota::TripleTap::Tap::Fire) {
                    // G16M: with no Wi-Fi stored an UPDATE could not join anything: the same gesture is SETUP.
                    if(guardian::setup::triple_tap(provisioner && provisioner->wifi_provisioned())==guardian::setup::Triple::Setup) {
                        setup_request(guardian::setup::Entry::TripleTap,setup_target_selected(),now);edge_until=0;changed=true;continue;
                    }
                    update_confirm.open(now32);edge_until=0;changed=true;
                    text("G16B UPDATE confirm_open gesture=triple_tap\n");continue;
                }
            }
            deliver(a);
        }
        if(update_taps.expire(now32) && !update_confirm.is_open())deliver(Action::Primary);   // a held tap with no third
        if(update_confirm.is_open()) {
            const auto answer=update_confirm.sample(yes,no,now32);
            if(answer==guardian::ota::Answer::Yes){update_requested=true;changed=true;}
            else if(answer==guardian::ota::Answer::No){text("G16B UPDATE declined\n");changed=true;}
        }
    }
    survey.hold_discovery(app->discovering());
    return changed;
}
}
namespace {
// ---- G16B UPDATE mode ---------------------------------------------------------
void show_update(const guardian::ota::View& v) {
    if(auto* canvas=board_ptr?board_ptr->canvas():nullptr){guardian::ota::draw(*canvas,v);board_ptr->present();dirty.invalidate();}
}
class UpdateScreen final:public guardian::ota::Observer {
public:
    explicit UpdateScreen(const char* running){view_.stage=guardian::ota::Stage::Working;view_.running_version=running;}
    void phase(guardian::ota::Phase p,std::uint32_t done,std::uint32_t total) override {
        const unsigned pct=total?unsigned(std::uint64_t(done)*100u/total):0;
        if(p==view_.phase && p==guardian::ota::Phase::Download && pct<last_pct_+2 && done!=total && started_)return;   // ~50 repaints max
        started_=true;view_.phase=p;view_.done=done;view_.total=total;last_pct_=pct;show_update(view_);
        static const char* names[]={"join","manifest","download","verify","switch"};
        char line[96];std::snprintf(line,sizeof line,"G16B UPDATE phase=%s done=%u total=%u\n",names[int(p)],unsigned(done),unsigned(total));text(line);
    }
    void set_new_version(const char* v){view_.new_version=v;}
private:
    guardian::ota::View view_{};
    unsigned last_pct_{};
    bool started_{};
};
// Resumes passive receive-only listening after an UPDATE attempt that did not reboot.
void companion_radio_resume() {
    if(!radio_initialized){companion_radio_start();return;}
#if CONFIG_GUARDIAN_ART_BENCH
    return;   // G16Q: no capture to resume after an update check
#endif
    const auto now=clock_ptr->now();
    if(!survey.begin(radio.first(),radio.count(),radio.first(),now) || !radio.tune(survey.channel())) {
        survey.stop();companion_radio=companion::RadioState::Failed;return;
    }
    companion_radio=companion::RadioState::Discovering;channel=survey.channel();stable_since=last_cover=now;
}
void companion_radio_resume();
void update_failed(guardian::ota::Reason why) {
    if(why==guardian::ota::Reason::NotNewer)++ota_not_newer;   // G22A: counted whoever asked (the poll or the owner's gesture)
    if(update_quiet && (why==guardian::ota::Reason::JoinFailed || why==guardian::ota::Reason::ManifestFetch || why==guardian::ota::Reason::NotNewer)) {
        auto_last_text=guardian::ota::reason_text(why);   // the Mac is not serving, or serves nothing newer: the poll stays silent
        char line[96];std::snprintf(line,sizeof line,"G16B AUTO no update (%s)\n",auto_last_text);text(line);return;
    }
    ota_record=guardian::ota::Record{};ota_record.state=guardian::ota::State::Failed;ota_record.reason=why;
    const bool saved=guardian::ota::save(*ota_blob,ota_record);
    char line[96];std::snprintf(line,sizeof line,"G16B UPDATE failed reason=%s record=%s\n",guardian::ota::reason_text(why),saved?"saved":"unsaved");text(line);
    apply_backlight(sticks3::Board::backlight_active_pct);   // G16N: a failed update is shown even when the screen was dark (the loop restores it)
    guardian::ota::View v;v.stage=guardian::ota::Stage::Failed;v.reason=why;show_update(v);
    vTaskDelay(pdMS_TO_TICKS(5000));
}
// Owner-confirmed update: pause monitoring, join, fetch, verify, switch, reboot.
// Any failure keeps the running image and resumes passive monitoring.
void run_update() {
    update_requested=false;
    text("G16B UPDATE start\n");
    if(!provisioner || !provisioner->provisioned()){update_failed(guardian::ota::Reason::NotProvisioned);return;}
    if(!radio_initialized){update_failed(guardian::ota::Reason::JoinFailed);return;}   // no radio driver (country unset)
    survey.stop();
    if(radio.listening() && !radio.stop()){text("GRX1 ERROR receive stop failed; reboot required\n");abort();}
    companion_radio=companion::RadioState::Off;
    const auto from=sticks3::ota::boot_facts().running_slot;
    UpdateScreen screen(sticks3::ota::running_version());
    static sticks3::ota::WifiTransport net(provisioner->credentials());tune_net=&net;
    // G16C: join first and ask the Mac for a TUNE offer (tools/tune_session.py).
    // No offer (tools/ota_serve.py answers 404) = the signed update, unchanged.
    screen.phase(guardian::ota::Phase::Joining,0,0);
    if(!net.join()){net.leave();update_failed(guardian::ota::Reason::JoinFailed);companion_radio_resume();return;}
#if !CONFIG_GUARDIAN_ART_BENCH   // G16Q: the bench has no TUNE session over Wi-Fi (USB console only); the update check runs
    {
        // G22A: signed offers only. The stick draws a fresh nonce for this one request; what comes back opens a
        // session only when verify_offer says so (signature by the OTA key over this nonce, an expiry and the
        // command list). A refusal is counted (STATUS tune_offers_refused*), opens nothing, and the update check
        // below runs as if nothing had been offered.
        namespace tw=guardian::tune::wifi;
        static char body[tw::kMaxOffer+1];static tw::Offer offer;   // 2.3 kB + 1.3 kB: off the task stack
        std::size_t n=0;char path[64];
        std::uint8_t random[tw::kNonceBytes];esp_fill_random(random,sizeof random);   // the radio is on: hardware entropy
        const tw::Nonce nonce=tw::make_nonce(random,static_cast<std::uint32_t>(clock_ptr->now()));
        if(tw::offer_path(nonce,path,sizeof path) && net.fetch(path,body,sizeof body,n,4000)) {
            if(!tune_key_read){tune_key_read=true;sticks3::ota::signing_key(tune_key);}
            const auto refusal=tw::verify_offer(body,n,nonce,static_cast<std::uint32_t>(clock_ptr->now()),tune_key.loaded()?&tune_key:nullptr,offer);
            tune_offers.note(refusal);
            if(refusal==tw::Refusal::None) {
                if(tune_link.start(net,offer)) {
                    tune_session.begin(offer,nonce.issued_ms);tune_stopping=false;dirty.invalidate();
                    char line[96];std::snprintf(line,sizeof line,"G22A TUNE session start signed=ota commands=%u expires=%u\n",unsigned(offer.command_count),unsigned(offer.seconds));text(line);
                    return;   // monitoring stays paused until the session ends (tune_service)
                }
                text("G16C TUNE ERROR session task\n");net.leave();companion_radio_resume();return;
            }
            char line[96];std::snprintf(line,sizeof line,"G22A TUNE offer refused reason=%s\n",tw::refusal_text(refusal));text(line);
        }
    }
#endif
    sticks3::ota::OtaSlot slot;
    const auto outcome=guardian::ota::run(net,slot,sticks3::ota::running_version(),&screen);   // G22A: only a newer version
    if(outcome.reason==guardian::ota::Reason::None) {
        ota_record=guardian::ota::Record{};ota_record.state=guardian::ota::State::Pending;
        ota_record.from_slot=from;ota_record.target_slot=slot.slot_index();ota_record.version=outcome.manifest.version;
        const bool saved=guardian::ota::save(*ota_blob,ota_record);
        char line[128];std::snprintf(line,sizeof line,"G16B UPDATE installed version=%s slot=%s record=%s rebooting\n",
            outcome.manifest.version.data(),sticks3::ota::slot_text(slot.slot_index()),saved?"saved":"unsaved");text(line);
        apply_backlight(sticks3::Board::backlight_active_pct);   // G16N: shown even when the screen was dark
        guardian::ota::View v;v.stage=guardian::ota::Stage::Installed;v.new_version=outcome.manifest.version.data();show_update(v);
        vTaskDelay(pdMS_TO_TICKS(2000));
        board_restart("update");
    }
    update_failed(outcome.reason);
    companion_radio_resume();
}
// ---- G16M phone setup: the screen and the session's steps ---------------------
void show_setup(Millis now) {
    if(auto* canvas=board_ptr?board_ptr->canvas():nullptr) {
        guardian::setup::draw(*canvas,setup_session->view(static_cast<std::uint32_t>(now)));board_ptr->present();dirty.invalidate();
    }
}
// One step per loop. True when the setup screen appeared, changed or went away (redraw now). CHECKING is
// painted here before the next loop's step runs the bounded join, which blocks like UPDATE's join does.
bool setup_service(Millis now) {
    if(!setup_visible())return false;
    const auto before=setup_session->state();
    setup_session->tick(static_cast<std::uint32_t>(now),app->presenter().view().alert);
    const auto after=setup_session->state();
    if(after==before)return false;
    char line[128];std::snprintf(line,sizeof line,"G16M SETUP state=%s last=%s store=%s\n",guardian::setup::state_text(after),
        guardian::setup::end_text(setup_session->last()),guardian::setup::store_text(cred_store));text(line);
    if(after!=guardian::setup::State::Idle)show_setup(clock_ptr->now());
    return true;
}
// G16C: drives an open TUNE session from the main loop (never blocks on the network).
void tune_service(Millis now) {
    namespace tw=guardian::tune::wifi;
    const auto now32=static_cast<std::uint32_t>(now);
    if(tune_session.active()) {
        const auto e=tune_link.events();
        for(std::uint32_t i=0;i<e.ok;++i)tune_session.network(true,now32);
        for(std::uint32_t i=0;i<e.failed;++i)tune_session.network(false,now32);
        if(e.done || !tune_link.running())tune_session.done();   // G22A: the signed list is the whole session
        tune_session.tick(now32);
        char cmd[tw::kMaxCommand+1];
        if(tune_session.active() && tune_link.take_command(cmd,sizeof cmd))tune_execute(cmd);
    }
    if(!tune_session.active() && tune_link.running() && !tune_stopping){tune_link.stop(tune_session.end());tune_stopping=true;}
    if(tune_link.done()) {   // the task is gone: leave the owner network, resume passive listening
        tune_link.reset();tune_stopping=false;
        if(tune_net)tune_net->leave();
        char line[128];std::snprintf(line,sizeof line,"G16C TUNE session end why=%s commands=%u refused=%u\n",
            tw::end_text(tune_session.end()),unsigned(tune_session.commands()),unsigned(tune_session.refused()));text(line);
        companion_radio_resume();dirty.invalidate();
    }
}
// ---- G16D deep sleep -------------------------------------------------------------
// The keys as the ext1 wake source (owner ORDER #27: pull-up on, pull-down off), every other source cleared
// first; never the IMU, never the PM1 IRQ line (GPIO13, owner ORDER #29). G16P: the timer is armed after it.
bool arm_key_wake(std::uint64_t mask) {
    esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_ALL);
    bool ok=true;
    for(const int pin:{gp::key_front_gpio,gp::key_side_gpio}) {
        ok=rtc_gpio_pullup_en(static_cast<gpio_num_t>(pin))==ESP_OK && ok;
        ok=rtc_gpio_pulldown_dis(static_cast<gpio_num_t>(pin))==ESP_OK && ok;
    }
    return esp_sleep_enable_ext1_wakeup_io(mask,ESP_EXT1_WAKEUP_ANY_LOW)==ESP_OK && ok;
}
// G16P: the RTC timer beside ext1 (IDF v5.4 sleep_modes.rst: sources combine, any one wakes the chip).
bool arm_timer_wake(std::uint64_t us) {return esp_sleep_enable_timer_wakeup(us)==ESP_OK;}
std::uint64_t rtc_clock_us() {return rtc_now_us();}
// One PM1 reading as the power-source evidence of idle.hpp (PWR_SRC bit0 = 5V VIN, bit1 = 5V VINOUT).
gp::SourceReading source_reading(const guardian::battery::Raw& raw) {
    gp::SourceReading sr;sr.src_ok=raw.src_ok;sr.src_external=raw.pwr_src&0x03;sr.vin_ok=raw.vin_ok;sr.vin_mv=raw.vin_mv;
    return sr;
}
// The SleepPort of adapters/power/idle.hpp on the StickS3 (sequence host-tested there).
class BoardSleepPort final:public gp::SleepPort {
public:
    bool radio_off() override {return radio.shutdown();}
    bool imu_stop() override {return sticks3::imu::stop(100);}
    bool display_sleep() override {return board_ptr->display_sleep();}
    bool pm1_gpio_low(std::uint8_t pin) override {return board_ptr->pm1_gpio_low(pin);}
    bool i2c_write(std::uint8_t a,std::uint8_t r,std::uint8_t v) override {return board_ptr->i2c_write(a,r,v);}
    bool i2c_present(std::uint8_t a) override {return board_ptr->i2c_present(a);}
    bool arm_ext1(std::uint64_t mask) override {return arm_key_wake(mask);}
    bool arm_timer(std::uint64_t us) override {return arm_timer_wake(us);}
    void deep_sleep() override {esp_deep_sleep_start();}
    void restart() override {esp_restart();}
};
// ---- G16P: the timer wake's USB check ----------------------------------------------
// The CheckPort of adapters/power/idle.hpp (the decision and its order are host-tested there). It runs first
// thing in app_main after a TIMER wake, before Board::init(): the PM1 power registers through QuickPower,
// the two wake sources and the RTC clock, nothing else.
class BoardCheckPort final:public gp::CheckPort {
public:
    explicit BoardCheckPort(sticks3::QuickPower& pm1):pm1_(pm1){}
    std::uint64_t rtc_now_us() override {return rtc_clock_us();}
    void read_power(gp::SourceReading& out,std::uint16_t& vbat_mv) override {
        guardian::battery::Raw raw;pm1_.read(raw);
        out=source_reading(raw);vbat_mv=raw.vbat_ok?raw.vbat_mv:0;
    }
    bool arm_ext1(std::uint64_t mask) override {return arm_key_wake(mask);}
    bool arm_timer(std::uint64_t us) override {return arm_timer_wake(us);}
    void deep_sleep() override {pm1_.close();esp_deep_sleep_start();}   // the bus is released first; no return
private:
    sticks3::QuickPower& pm1_;
};
// Returns only when this boot must go on (USB power found, or one of the refusals of gp::timer_check);
// otherwise the stick is in deep sleep again. A PM1 bus that cannot even be opened reads as "no usable
// reading": counted in check_faults, asleep again (idle.hpp says why a failed check never boots).
void timer_wake_check() {
    check_ran=true;
    sticks3::QuickPower pm1;check_pm1_open=pm1.open();
    BoardCheckPort port(pm1);
    check_info=gp::timer_check(port,retained);
}
// 2026-11-18 (device, MEASURED): after the OTA's esp_restart the BMI270 answered but its init failed
// (imu=init-failed, motion=no_imu) until a hardware reset. Every software restart now runs the host-tested
// sequence of idle.hpp first: radio off, sampler stopped, sensor soft reset, then esp_restart.
void board_restart(const char* why) {
    static BoardSleepPort port;
    const auto imu=sticks3::imu::status();
    const std::uint32_t f=gp::prepare_restart(port,imu.state==guardian::imu::State::Running?imu.address:0);
    char line[96];std::snprintf(line,sizeof line,"G16I RESTART reason=%s faults=0x%x\n",why,unsigned(f));text(line);
    vTaskDelay(pdMS_TO_TICKS(20));   // let the line leave the console and the sensor finish its reset (>= 2 ms)
    port.restart();
}
void record_sleep(std::uint32_t faults,void*) {
    gp::on_sleep(retained,rtc_now_us(),faults,idle.params().sleep_check_s);   // G16P: when the timer check is due
    char line[128];std::snprintf(line,sizeof line,"G16D SLEEP enter faults=0x%x sleep_count=%u check_s=%u\n",unsigned(faults),unsigned(retained.sleep_count),unsigned(retained.check_s));text(line);
}
void draw_sleeping() {
    auto* c=board_ptr?board_ptr->canvas():nullptr;
    if(!c)return;
    c->clear(color::black);
    c->text(19,100,"sleeping",color::white,2);
    c->text(29,130,"press to wake",color::grey,1);
    guardian::battery::draw_indicator(*c,battery_state);
    board_ptr->present();dirty.invalidate();
}
// G16N: the one grey sentence shown at the dim backlight for gp::dark_notice_ms before the screen goes dark.
void draw_dark_notice() {
    auto* c=board_ptr?board_ptr->canvas():nullptr;
    if(!c)return;
    companion::draw_dark_notice(*c);
    guardian::battery::draw_indicator(*c,battery_state);
    board_ptr->present();dirty.invalidate();
}
// G16N: milliseconds since the evidence instant of the newest shown incident (red or amber); -1 = none shown.
int incident_evidence_age_ms() {
    const auto& v=app->presenter().view();
    long best=-1;
    if(v.alert && v.incident.age_known)best=static_cast<long>(v.incident.age_ms);
    if(v.caution && v.caution_age_known && (best<0 || static_cast<long>(v.caution_age_ms)<best))best=static_cast<long>(v.caution_age_ms);
    return best<0?-1:best>600000?600000:static_cast<int>(best);
}
// Shows "sleeping - press to wake" for about 1 s; a key in that second cancels
// (returns false, the key is activity). Otherwise never returns: deep sleep, or
// a restart if the keys could not be armed as the wake source.
bool sleep_now() {
    char line[96];std::snprintf(line,sizeof line,"G16D SLEEP start still_s=%u\n",unsigned(idle.still_ms(static_cast<std::uint32_t>(clock_ptr->now()))/1000));text(line);
    apply_backlight(sticks3::Board::backlight_active_pct);
    draw_sleeping();
    for(int i=0;i<100;++i) {
        vTaskDelay(pdMS_TO_TICKS(10));
        if(buttons_ok && (board_ptr->key_front_down() || board_ptr->key_side_down())){text("G16D SLEEP cancelled key\n");return false;}
    }
    battery_log->sleeping(battery_state,static_cast<std::uint32_t>(clock_ptr->now()));   // BATTRUN: sleep_mv, slept
    survey.stop();companion_radio=companion::RadioState::Off;
    const auto imu=sticks3::imu::status();
    static BoardSleepPort port;
    // G16P: the timer wake is armed beside the keys (power.sleep_check_s), so a charger plugged in later is noticed.
    gp::enter_deep_sleep(port,imu.state==guardian::imu::State::Running?imu.address:0,record_sleep,nullptr,idle.params().sleep_check_s);
    return false;   // not reached on the device
}
// Boot self-test of a (possibly new) image; validates or rolls back.
void boot_check(bool display_ok,bool nvs_ok) {
    self_test.display=display_ok;
    self_test.store=nvs_ok && app->store()!=companion::StoreState::Rejected;
    self_test.radio=companion_radio==companion::RadioState::Discovering || companion_radio==companion::RadioState::Monitoring;
    self_test.imu=sticks3::imu::status().state==guardian::imu::State::Running;
#if CONFIG_GUARDIAN_ART_BENCH
    // G16Q: the bench does not listen. Its radio criterion is the Wi-Fi driver being up, which is what the
    // next self-fetch needs; display, store and IMU are judged as in the Guardian.
    self_test.radio=radio_initialized;
#endif
#if CONFIG_GUARDIAN_OTA_SELFTEST_FAIL
    self_test.forced_fail=true;   // reviewer test image only
#endif
    const auto facts=sticks3::ota::boot_facts();
    const auto decision=guardian::ota::decide_boot(ota_record,facts,self_test);
    bool saved=true;
    if(decision.changed)saved=guardian::ota::save(*ota_blob,ota_record);
    char result[48];guardian::ota::result_text(ota_record,result,sizeof result);
    char line[200];std::snprintf(line,sizeof line,"G16B BOOT slot=%s version=%s pending_verify=%d selftest=%s display=%d store=%d radio=%d imu=%d forced_fail=%d result=%s record=%s\n",
        sticks3::ota::slot_text(facts.running_slot),sticks3::ota::running_version(),int(facts.pending_verify),self_test.passed()?"pass":"fail",
        int(self_test.display),int(self_test.store),int(self_test.radio),int(self_test.imu),int(self_test.forced_fail),result,saved?"ok":"unsaved");
    text(line);
    if(decision.action==guardian::ota::BootAction::MarkValid) {
        text(sticks3::ota::mark_valid()?"G16B BOOT marked_valid\n":"G16B BOOT mark_valid_failed\n");
    } else if(decision.action==guardian::ota::BootAction::Rollback) {
        guardian::ota::View v;v.stage=guardian::ota::Stage::Failed;v.reason=guardian::ota::Reason::SelfTest;show_update(v);
        text("G16B BOOT rollback\n");vTaskDelay(pdMS_TO_TICKS(3000));
        sticks3::ota::rollback_and_reboot();
    }
}
}
extern "C" void app_main() {
    // G16P: a TIMER wake first asks the PM1 whether USB power is there, before anything else is brought up
    // (no display, no rail, no radio, no IMU, no NVS). Without USB power this call does not return.
    if(wake_cause_now()==gp::WakeCause::Timer)timer_wake_check();
    reset_text=reset_reason_text(esp_reset_reason());
    {   // Review 2026-11-17 (memory): record/reply buffers, before anything can print a record.
        sticks3::psram::Where w{};bufs=sticks3::psram::make<TextBuffers>(w);text_ram=sticks3::psram::where_text(w);
        if(!bufs){std::printf("GRX1 ERROR text buffer allocation failed (%u bytes)\n",unsigned(sizeof(TextBuffers)));abort();}
    }
    // G16D: why this boot happened, before anything else (RTC sleep record, wake key).
    {   const auto cause=wake_cause_now();
        const auto key=cause==gp::WakeCause::Ext1?gp::wake_key_from(esp_sleep_get_ext1_wakeup_status()):gp::WakeKey::Unknown;
        wake_info=gp::on_boot(retained,cause,key,rtc_now_us());
        if(cause==gp::WakeCause::Ext1)wake_guard.arm(true,true,0);   // the waking press is never a UI action
        // G16P: the timer check saw USB power; its reading settles the source at once (USB is immediate in the
        // filter), so the first loop already holds the Guardian up on USB instead of "power unknown".
        if(check_ran && check_info.outcome==gp::CheckOutcome::Usb)power_source.sample(check_info.reading);
    }
    static sticks3::Board board;sticks3::BoardInfo info_board{};const bool display=board.init(info_board);
    board_ptr=&board;buttons_ok=info_board.buttons_ok;
    static Clock clock;clock_ptr=&clock;boot=clock.epoch().boot_id;
    {   // G16F: the Monitor (Core, the G06 and the twelve G16F detectors: ~45 KB of bounded tables)
        // is placed once at boot in PSRAM, internal DRAM only as a fallback, never in .bss, so the
        // tables do not take the internal heap the Wi-Fi driver needs. One allocation, never freed.
        constexpr auto align=alignof(measurement::Monitor);constexpr auto size=sizeof(measurement::Monitor);
        void* mem=heap_caps_aligned_alloc(align,size,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);monitor_ram="psram";
        if(!mem){mem=heap_caps_aligned_alloc(align,size,MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);monitor_ram="internal";}
        if(!mem){std::printf("GRX1 ERROR monitor allocation failed (%u bytes)\n",unsigned(size));abort();}
        monitor=new(mem) measurement::Monitor(clock,profiles::all_2g4_channels());
    }
    // G16A: live-tunable parameters (NVS key "tune"), registered before load.
    static sticks3::NvsBlob tune_blob("tune");
    tune::Registry* registry_mem;   // review 2026-11-17 (memory): ~12 KB with its load/save buffers, placed by psram.hpp
    {sticks3::psram::Where w{};registry_mem=sticks3::psram::make<tune::Registry>(w,tune_blob);tune_ram=sticks3::psram::where_text(w);}
    if(!registry_mem){std::printf("GRX1 ERROR tune registry allocation failed (%u bytes)\n",unsigned(sizeof(tune::Registry)));abort();}
    auto& registry=*registry_mem;tuning=registry_mem;
    {const companion::persona::Motion d;
     // G16C: at rest the Guardian is calm (idle breathing only): the idle sway defaults to 0
     // (new key, so a persisted G16A persona.tilt_deg cannot bring the sway back); tilt now comes from the IMU.
     tune_sway=registry.add("persona.sway_deg",0.0f,3.0f,0.0f);
     tune_breath=registry.add("persona.breath",0.0f,0.02f,d.breath_amount);
     tune_ember=registry.add("persona.ember",0.0f,0.6f,d.ember_peak);
     tune_smoke=registry.add("persona.smoke",0.0f,1.0f,d.smoke_alpha);}
    {   // G16C motion model and the IMU axis map (signed axis 1..3 per screen axis, 0 = unset: derive it
        // from a recorded serial IMU trace with tools/imu_axis_map.py, never assume it).
        const companion::motion::Params d;
        for(auto& k:motion_keys)k.index=registry.add(k.key,k.lo,k.hi,d.*(k.field));
        {const gp::MotionThresholds h;   // G16D: what counts as "handled" (keeps the screen bright)
         tune_rest_gyro=registry.add("motion.rest_gyro",0.5f,30.0f,h.gyro_dps);
         tune_rest_acc=registry.add("motion.rest_acc",0.01f,0.3f,h.acc_g);}
        tune_imu_right=registry.add("imu.right",-3.0f,3.0f,0.0f);
        tune_imu_up=registry.add("imu.up",-3.0f,3.0f,0.0f);
        tune_imu_out=registry.add("imu.out",-3.0f,3.0f,0.0f);
        tune_frame_ms=registry.add("display.frame_ms",20.0f,250.0f,40.0f);   // animated face cadence (>= 20 fps at <= 50)
        {   // G16I: the shake rule (MEASURED defaults, shake.hpp) and the burst length. These four and the two
            // motion.upright* rows bring the board keys to 42 (G16J adds detect.twin and detect.sweep_ms: 44; with the 61 t.* keys: 105 of 112).
            const companion::shake::Params sd;
            tune_shake_g=registry.add("shake.g",companion::shake::g_range.lo,companion::shake::g_range.hi,sd.g);
            tune_shake_peaks=registry.add("shake.peaks",companion::shake::peaks_range.lo,companion::shake::peaks_range.hi,float(sd.peaks));
            tune_shake_window=registry.add("shake.window_ms",companion::shake::window_ms_range.lo,companion::shake::window_ms_range.hi,float(sd.window_ms));
            tune_burst_s=registry.add("burst.s",companion::burst::total_s_range.lo,companion::burst::total_s_range.hi,companion::burst::default_total_s);
            // G16O: the particles keep falling while the stick is handled; the reform waits for stillness (burst.hpp).
            // Four keys: 55 board keys + 61 t.* keys = 116 of tune::max_params 120.
            const companion::burst::Params bd;
            tune_burst_still_dps=registry.add("burst.still_dps",companion::burst::still_dps_range.lo,companion::burst::still_dps_range.hi,bd.still_dps);
            tune_burst_still_g=registry.add("burst.still_g",companion::burst::still_g_range.lo,companion::burst::still_g_range.hi,bd.still_g);
            tune_burst_calm=registry.add("burst.calm_s",companion::burst::calm_s_range.lo,companion::burst::calm_s_range.hi,bd.calm_s);
            tune_burst_max=registry.add("burst.max_s",companion::burst::max_s_range.lo,companion::burst::max_s_range.hi,bd.max_s);
        }
        {   // G21: the 3D head. on 0 = the 2D portraits; gains map the stick's yaw / pitch to the frame angles (a negative
            // gain mirrors an axis, 0 holds it in the middle); hyst = how far past a boundary before the frame changes.
            // Four keys: 48 board keys + 61 t.* keys = 109 of tune::max_params 112.
            const companion::head3d::Params hd;
            tune_head_on=registry.add("head.on",0.0f,1.0f,hd.on?1.0f:0.0f);
            tune_head_yaw=registry.add("head.yaw_gain",companion::head3d::gain_range.lo,companion::head3d::gain_range.hi,hd.yaw_gain);
            tune_head_pitch=registry.add("head.pitch_gain",companion::head3d::gain_range.lo,companion::head3d::gain_range.hi,hd.pitch_gain);
            tune_head_hyst=registry.add("head.hyst",companion::head3d::hysteresis_range.lo,companion::head3d::hysteresis_range.hi,hd.hysteresis);
        }
    }
    // G16D battery life (owner defaults: dim after 30 s still, deep sleep 120 s later).
    tune_ota_auto=registry.add("ota.auto_s",0.0f,3600.0f,120.0f);   // self-fetch period; 0 = gesture only
    // G23 battery life: the self-fetch period on battery (-1 = follow ota.auto_s, the behaviour before G23; 0 = no poll on
    // battery), and the CPU frequency while dark (160 = before G23; applied only by the dark-cpu image). Two keys:
    // 40 literal + 18 motion.* = 58 board keys, + 68 t.* keys = 126 of tune::max_params 128 (counted 2026-11-20).
    tune_ota_auto_batt=registry.add("ota.auto_batt_s",-1.0f,3600.0f,guardian::ota::follow_auto_s);
    tune_dark_cpu=registry.add("power.dark_cpu_mhz",80.0f,240.0f,float(gp::cpu_default_mhz));
    tune_dim_s=registry.add("power.dim_s",5.0f,600.0f,30.0f);
    tune_sleep_s=registry.add("power.sleep_s",10.0f,3600.0f,120.0f);
    tune_dim_pct=registry.add("power.dim_pct",1.0f,60.0f,10.0f);   // backlight percent while dimmed
    // G16P: seconds between the deep sleep's timer wakes that look for USB power (a plugged-in Guardian lights
    // by itself within this). One key: 56 board keys + 61 t.* keys = 117 of tune::max_params 120.
    tune_sleep_check=registry.add("power.sleep_check_s",float(gp::sleep_check_min_s),float(gp::sleep_check_max_s),float(gp::sleep_check_default_s));
    // G16N guard in the dark: seconds of Dim before the screen goes dark (0 = off: Dim -> deep sleep after
    // power.sleep_s, as before), and the battery percent at or below which Dark ends in deep sleep.
    // Two keys: 51 board keys + 61 t.* keys = 112 (G16O adds four burst.* keys above: 116 of tune::max_params 120).
    {const gp::Params pd;
     tune_dark_s=registry.add("power.dark_s",0.0f,3600.0f,float(pd.dark_ms/1000u));
     tune_dark_floor=registry.add("power.dark_floor_pct",5.0f,90.0f,float(pd.dark_floor_pct));}
    // G16E detector limits. Defaults = today's accepted values; the AntiHunter (c6ef921, AGPL-3.0,
    // values only, no code; docs/research/reuse-decisions.md sections 4 and 10) starting hypotheses:
    // deauth flood 20 in 10 s, 60 s alert cooldown (Guardian keeps 45 s: an ALERT must not lapse
    // under Core::incident_ms, G14 finding), 60 s quiet before an area re-alert.
    tune_det_window=registry.add("detect.window_ms",1000.0f,60000.0f,10000.0f);
    tune_det_burst=registry.add("detect.burst",2.0f,128.0f,20.0f);
    tune_det_cooldown=registry.add("detect.cooldown_ms",5000.0f,300000.0f,45000.0f);
    tune_det_dedupe=registry.add("detect.dedupe_ms",0.0f,5000.0f,1000.0f);
    tune_det_change=registry.add("detect.change_n",1.0f,32.0f,2.0f);
    tune_det_area=registry.add("detect.area_ms",5000.0f,600000.0f,60000.0f);
    tune_det_datapath=registry.add("detect.datapath",0.0f,1.0f,0.0f);   // G16G: 1 = DATA + FCS-fail promiscuous (spike first)
    // G16J: the same-name watch is ON for every picked network (0 = the pre-G16J behaviour); the area
    // sweep dwell in ms every 2 s (0 = off, the default until spike (b) shows the red path keeps its frames).
    // 44 board keys + 61 t.* keys = 105 of tune::max_params 112.
    tune_det_twin=registry.add("detect.twin",0.0f,1.0f,1.0f);
    tune_det_sweep=registry.add("detect.sweep_ms",0.0f,500.0f,0.0f);
    if(!guardian::tune::add_threat_limits(registry,monitor->threat_limits(),threat_keys))text("TUNE t.* keys not registered (registry full)\n");
    registry.load();configure_motion();configure_detectors();
    {   // G16C: the 16 portraits, each exactly persona::art_bytes; any mismatch = placeholder screens.
        const auto ok=[](const std::uint8_t* b,const std::uint8_t* e){return static_cast<std::size_t>(e-b)==companion::persona::art_bytes;};
        art_set.rated={VeryGood_start,Good_start,Medium_start,Bad_start,Horrible_start};
        art_set.alert={{{VeryGood_ALERT_p0_start,VeryGood_ALERT_p1_start},{Good_ALERT_p0_start,Good_ALERT_p1_start},
            {Medium_ALERT_p0_start,Medium_ALERT_p1_start},{Bad_ALERT_p0_start,Bad_ALERT_p1_start},{Horrible_ALERT_p0_start,Horrible_ALERT_p1_start}}};
        art_set.no_data=NoData_start;
        art_ok=ok(VeryGood_start,VeryGood_end)&&ok(Good_start,Good_end)&&ok(Medium_start,Medium_end)&&ok(Bad_start,Bad_end)&&ok(Horrible_start,Horrible_end)
            &&ok(VeryGood_ALERT_p0_start,VeryGood_ALERT_p0_end)&&ok(VeryGood_ALERT_p1_start,VeryGood_ALERT_p1_end)
            &&ok(Good_ALERT_p0_start,Good_ALERT_p0_end)&&ok(Good_ALERT_p1_start,Good_ALERT_p1_end)
            &&ok(Medium_ALERT_p0_start,Medium_ALERT_p0_end)&&ok(Medium_ALERT_p1_start,Medium_ALERT_p1_end)
            &&ok(Bad_ALERT_p0_start,Bad_ALERT_p0_end)&&ok(Bad_ALERT_p1_start,Bad_ALERT_p1_end)
            &&ok(Horrible_ALERT_p0_start,Horrible_ALERT_p0_end)&&ok(Horrible_ALERT_p1_start,Horrible_ALERT_p1_end)
            &&ok(NoData_start,NoData_end)&&art_set.complete();
    }
    if(art_ok) {   // G16C rework: the warp works from a PSRAM copy of the current portrait (0 B internal heap)
        auto* src=static_cast<std::uint16_t*>(heap_caps_malloc(companion::persona::art_bytes,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));
        auto* band=static_cast<std::uint16_t*>(heap_caps_malloc(companion::persona::art_bytes,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));
        if(src && band){static companion::persona::WarpCache cache(src,band);warp_cache=&cache;art_ram="psram";art_ram_bytes=2*companion::persona::art_bytes;}
        else {heap_caps_free(src);heap_caps_free(band);art_ram="flash";}
        // G16I: the burst's particles (16 KB), once at boot like the portrait copy. Without room the face simply never bursts.
        sticks3::psram::Where w{};face_burst=sticks3::psram::make<companion::burst::Burst>(w);burst_ram=sticks3::psram::where_text(w);
        if(face_burst)face_burst->configure(burst_params(registry));
        // G21: the head's two frame buffers (2 x 43,200 B) and its object (sets, inflater tables), PSRAM only, once at
        // boot, never freed. No internal-heap fallback: the Wi-Fi driver needs that memory (psram.hpp), and without
        // PSRAM the 2D portraits are the face, as before G21. Nothing is allocated in the frame path.
        auto* head_a=static_cast<std::uint8_t*>(heap_caps_malloc(companion::persona::art_bytes,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));
        auto* head_b=static_cast<std::uint8_t*>(heap_caps_malloc(companion::persona::art_bytes,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));
        void* head_mem=heap_caps_aligned_alloc(alignof(companion::head3d::Head),sizeof(companion::head3d::Head),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
        if(head_a && head_b && head_mem) {
            face_head=new(head_mem)companion::head3d::Head(head_a,head_b);
            head_ram="psram";head_ram_bytes=static_cast<std::uint32_t>(2*companion::persona::art_bytes+sizeof(companion::head3d::Head));
            const auto add=[](const std::uint8_t* b,const std::uint8_t* e) {
                ++head_packs;
                const auto r=face_head->add(b,static_cast<std::size_t>(e-b));
                if(r!=companion::head3d::PackError::Ok){++head_refused;head_refusal=companion::head3d::pack_error_text(r);}
            };
            (void)add;   // an image without any frame set still builds
#ifdef GUARDIAN_HEAD3D_VeryGood
            add(head3d_VeryGood_start,head3d_VeryGood_end);
#endif
#ifdef GUARDIAN_HEAD3D_Good
            add(head3d_Good_start,head3d_Good_end);
#endif
#ifdef GUARDIAN_HEAD3D_Medium
            add(head3d_Medium_start,head3d_Medium_end);
#endif
#ifdef GUARDIAN_HEAD3D_Bad
            add(head3d_Bad_start,head3d_Bad_end);
#endif
#ifdef GUARDIAN_HEAD3D_Horrible
            add(head3d_Horrible_start,head3d_Horrible_end);
#endif
            configure_head();
        } else {heap_caps_free(head_a);heap_caps_free(head_b);heap_caps_free(head_mem);}
    }
    // G16A: BMI270 on the board's internal I2C bus, sampled on core 1.
    // Review 2026-11-17: does the ES8311 answer with the LCD rail on? (Read-only address probe,
    // before the IMU sampler shares the bus.) With sleep_codec= after a sleep this tells whether
    // the codec is unpowered at sleep because the rail cut powers it down, or never powered.
    // Review 2026-11-17 (device: sleep_codec=failed, codec_boot=ack): the Guardian never uses audio,
    // so the ES8311 is powered down here, at boot, in a known-good bus state; the exact error and
    // register are reported if a write fails (codec_boot=down | nack | write_err:<esp_err>@<reg>).
    if(!board.i2c_present(gp::es8311_addr))codec_boot="nack";
    else {
        static char why[48];codec_boot="down";
        for(const auto& rv:gp::es8311_power_down) {
            const int e=board.i2c_write_err(gp::es8311_addr,rv[0],rv[1]);
            if(e!=ESP_OK){std::snprintf(why,sizeof why,"write_err:%s@0x%02x",esp_err_to_name(e),unsigned(rv[0]));codec_boot=why;break;}
        }
    }
    sticks3::imu::start(board.i2c_bus());
    ESP_ERROR_CHECK(esp_read_mac(mac,ESP_MAC_WIFI_STA));
    usb_serial_jtag_driver_config_t usb{};usb.tx_buffer_size=16384;usb.rx_buffer_size=512;
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&usb));
    // G16C rework: ESP_LOG never blocks a task on the USB port (non-blocking sink,
    // counted drops), stdio goes through the same driver, and only WARN and above
    // are formatted after boot (no wifi:ic_enable_sniffer chatter on every hop).
    log_lock=xSemaphoreCreateMutex();
    usb_serial_jtag_vfs_use_driver();
    esp_log_set_vprintf(log_vprintf);
    esp_log_level_set("*",ESP_LOG_WARN);
    // G14: owner selection from NVS (identity + approved baseline only), then passive listening.
    static sticks3::NvsBlob blob;static companion::EncodedSelectionStore store(blob);
    static sticks3::NvsBlob onboarded("onboarded");   // shown-once welcome pages
    // G16B: OTA boot record, provisioning (Wi-Fi + Mac URL), battery run log.
    static sticks3::NvsBlob ota_store("ota");ota_blob=&ota_store;guardian::ota::load(ota_store,ota_record);
    // G16M: the Wi-Fi credential lives in the encrypted vault when this stick has one (the "nvs_cred" partition and
    // the owner-burnt eFuse key; cred_vault.hpp); otherwise in the G16B plain record, and STATUS says cred_store=plain.
    static sticks3::NvsBlob ota_cfg("otacfg");static sticks3::vault::Blob vault_cfg("otacfg");
    const auto vault_state=info_board.nvs_ok?sticks3::vault::init():guardian::setup::VaultState::Absent;
    const auto cred_choice=guardian::setup::choose_store(ota_cfg,vault_state==guardian::setup::VaultState::Ready?&vault_cfg:nullptr,vault_state);
    cred_store=cred_choice.kind;cred_migrated=cred_choice.migrated;cred_legacy_cleared=cred_choice.legacy_cleared;
    static guardian::ota::Provisioner prov(*cred_choice.storage);prov.load();provisioner=&prov;
    static guardian::setup::Session setup(setup_port,prov);setup.set_identity(mac);setup.set_store(cred_store);setup_session=&setup;
    setup_port.hooks(setup_radio_stop,companion_radio_resume);
    {   char line[128];std::snprintf(line,sizeof line,"G16M CRED store=%s vault=%s migrated=%d plain_cleared=%d wifi_provisioned=%s\n",guardian::setup::store_text(cred_store),
            sticks3::vault::state_text(),int(cred_migrated),int(cred_legacy_cleared),prov.wifi_provisioned()?"yes":"no");text(line);}
    static sticks3::NvsBlob battrun("battrun");static guardian::battery::RunLog run_log(battrun,info_board.boot_count);run_log.load();battery_log=&run_log;
    // G16D: a key wake continues the battery run that went to sleep (active time, sleeps, standby drop).
    // G16P: so does a timer wake that found USB power (the run then ends as usb_returned); both carry the
    // sleep's timer checks (count, period, cell voltage at the first and the last) into BATTRUN.
    if(wake_info.cause==gp::WakeCause::Ext1 || wake_info.cause==gp::WakeCause::Timer)
        run_log.resume(wake_info.asleep_known?wake_info.asleep_ms:0,
            guardian::battery::SleepChecks{wake_info.checks,wake_info.check_s,wake_info.check_first_mv,wake_info.check_last_mv});
    {   // Review 2026-11-17 (memory): the companion (presenter, picker, views: ~14 KB), placed by psram.hpp.
        sticks3::psram::Where w{};
        app=sticks3::psram::make<companion::Companion>(w,clock,*monitor,store,
            DisplayCapabilities{Support::Supported,sticks3::Board::width,sticks3::Board::height,PixelFormat::Rgb565,Support::Supported},
            Origin::LiveRadio,static_cast<companion::BlobStorage*>(&onboarded));
        app_ram=sticks3::psram::where_text(w);
        if(!app){std::printf("GRX1 ERROR companion allocation failed (%u bytes)\n",unsigned(sizeof(companion::Companion)));abort();}
    }
    if(tuning && tune_det_twin>=0)app->set_impostor_watch(tuning->get(tune_det_twin)>=0.5f);   // G16J: before the restore
    app->boot();companion_radio_start();
    {   // G16B: first frame (display self-test), then validate or roll back this image.
        guardian::battery::Raw raw;board.read_power(raw);battery_state=battery_monitor.update(raw);
        bool display_ok=false;
        if(display) {
            companion::Status st{};st.radio=radio_state();st.store=app->store();fill_limits(st);
            st.persona_art=art_ok;app->render(st,frame);
            companion::DrawInput in;in.art=art_ok?&art_set:nullptr;in.anim_ms=clock.now();in.motion=motion();
            if(auto* canvas=board.canvas()){companion::draw(*canvas,frame,in);
                guardian::battery::draw_indicator(*canvas,battery_state);display_ok=board.present();dirty.invalidate();}
        }
        boot_check(display_ok,info_board.nvs_ok);
    }
#if CONFIG_GUARDIAN_ART_BENCH
    bench_frames_init();
    bench.go(ab::entry(0).name,static_cast<std::uint32_t>(clock.now()));   // the first candidate's 2 s label starts now, not at time 0
    bench_line(bench_frames_ok?"start":"start frames_missing");
#endif
    info();char input[160]{};std::size_t used=0;bool overflow=false;
    {   char line[240];std::snprintf(line,sizeof line,"G16D WAKE cause=%s key=%s asleep_s=%d sleep_count=%u wake_checks=%u sleep_checks=%u check_faults=%u check_awake_ms=%u/%u wake_check=%s\n",
            gp::wake_text(wake_info.cause),gp::wake_key_text(wake_info.key),wake_info.asleep_known?int(wake_info.asleep_ms/1000):-1,unsigned(retained.sleep_count),
            unsigned(wake_info.checks),unsigned(retained.sleep_checks),unsigned(retained.check_faults),unsigned(retained.check_awake_ms),unsigned(retained.check_awake_max_ms),
            !check_ran?"-":!check_pm1_open?"pm1_bus_failed":gp::check_text(check_info.outcome));text(line);}
    Millis last_status=0,last_tick=0,last_power=0,last_confirm_draw=0;sticks3::RedrawSchedule redraw;
    for(;;) {
        char bytes[64];const int n=usb_serial_jtag_read_bytes(bytes,sizeof bytes,0);
        for(int i=0;i<n;++i) {
            if(bytes[i]=='\n') {if(overflow)text("GRX1 ERROR oversized command\n");else {input[used]=0;command(input);}used=0;overflow=false;}
            else if(bytes[i]!='\r' && !overflow) {if(bytes[i]<32 || bytes[i]>126 || used==sizeof(input)-1)overflow=true;else input[used++]=bytes[i];}
        }
        const auto now=clock.now();
        drain_imu(now);
        // G16I: a shake is taken at once (so it can never fire late) and offered to the next face frame only.
        if(shake_detector.take()){shake_waiting=true;shake_at=now;}
        if(shake_waiting && now-shake_at>shake_fresh_ms)shake_waiting=false;
        if(now-last_load>=1000){load_tick(now);last_load=now;}
#if CONFIG_GUARDIAN_BLE_SPIKE
        spike_arm_service(now);spike_service(now);
#endif
        if(now-last_power>=1000) {   // G16B: PM1 battery once a second, run log once a minute
            guardian::battery::Raw raw;board.read_power(raw);battery_state=battery_monitor.update(raw);
            battery_log->tick(battery_state,static_cast<std::uint32_t>(now),battery_phase(),battery_settings());last_power=now;   // G16N: drain per screen state; G23: per setting
            power_source.sample(source_reading(raw));   // G16D: debounced USB vs battery (never sleeps on USB or unknown)
        }
        if(update_requested){burst_stop();run_update();redraw=sticks3::RedrawSchedule{};continue;}
        bool spike_busy=false;
#if CONFIG_GUARDIAN_BLE_SPIKE
        spike_busy=spike_armed || spike.running();   // supervisor 2026-11-19: the poll's join would take the radio mid-phase
#endif
        if(!spike_busy && tune_ota_auto>=0 && control==Control::Companion) {
            // G22A: alert first. While a red ALERT is active a due poll is deferred (counted, STATUS ota_auto_deferred):
            // the incident stays on the glass and the radio keeps listening; the poll runs once the alert has ended.
            const bool busy=tune_session.active() || tune_link.running() || update_confirm.is_open() || setup_visible();
            const auto period_ms=poll_period_ms(power_source.source()==gp::Source::Battery);   // G23: ota.auto_batt_s on battery
            if(auto_poll.sample(now,period_ms,busy,app && app->presenter().view().alert)==guardian::ota::AutoPoll::Decision::Run) {
                burst_stop();update_quiet=true;run_update();update_quiet=false;
                redraw=sticks3::RedrawSchedule{};continue;
            }
        }
#if CONFIG_GUARDIAN_ART_BENCH
        // G16Q: the bench owns the keys and the glass from here. The console, the IMU drain, the battery
        // reading and the self-fetch poll above stay; the idle policy and the companion below do not run.
        bench_step(now,display);vTaskDelay(pdMS_TO_TICKS(1));continue;
#endif
        if(edge_until && now>=edge_until)edge_until=0;
        bool force_draw=false,glass_frames=true;   // G16N: glass_frames false = Dark, nothing is drawn
        {   // G16D: idle policy before any key reaches the UI.
            bool front=false,side=false;
            if(buttons_ok){front=board.key_front_down();side=board.key_side_down();}
            const auto now32=static_cast<std::uint32_t>(now);
            gp::Inputs pin;pin.motion=activity.take();pin.key=front || side;pin.alert=app->presenter().view().alert;
            // G16N: every new incident report (red or amber) is activity; the floor reads the filtered battery percent.
            pin.incident_seq=app->presenter().view().incident_seq;pin.batt_pct=battery_state.known?battery_state.level:-1;
            pin.update=update_confirm.is_open() || update_requested || setup_visible();pin.tune=tune_session.active() || tune_link.running();
            pin.onboarding=app->onboarding();pin.console=control==Control::Console || edge_until || imu_stream_until;
#if CONFIG_GUARDIAN_BLE_SPIKE
            pin.console=pin.console || spike.running() || spike_armed;   // G16H: no dim/sleep in the middle of a spike run (or while armed)
#endif
            pin.source=power_source.source();
            const auto before=idle.state();
            auto after=idle.step(pin,now32);
            bool sleep_cancelled=false;
            if(after==gp::State::Sleep && !sleep_now()) {   // cancelled by a key during the message
                pin.key=true;after=idle.step(pin,now32);front=board.key_front_down();side=board.key_side_down();
                wake_guard.arm(front,side,now32);sleep_cancelled=true;
            }
            if(gp::wake_press(before,after,pin.key))wake_guard.arm(front,side,now32);   // the press that brightened Dim or lit Dark is not an action
            // G16N: the backlight follows the state every loop (Dark: the dim level for the 2 s notice, then 0),
            // so nothing that lit the screen for a message can leave it lit, or dark, by mistake.
            const auto glass=gp::glass(after,idle.dark_for_ms(now32),sticks3::Board::backlight_active_pct,dim_backlight_pct());
            apply_backlight(glass.backlight_pct);glass_frames=glass.frames;
#if CONFIG_GUARDIAN_DARK_CPU
            apply_cpu(gp::cpu_mhz(after,dark_mhz()));   // G23: the dark-cpu image only (STATUS cpu_mhz, cpu_set_fail)
#endif
            if(after!=before) {
                redraw=sticks3::RedrawSchedule{};dirty.invalidate();force_draw=true;   // leaving Dark: a full redraw at 60 %
                char line[96];std::snprintf(line,sizeof line,"G16D POWER %s hold=%s\n",gp::state_text(after),gp::hold_text(idle.hold()));text(line);
                if(after==gp::State::Dark && display)draw_dark_notice();   // "guarding in the dark, press to look", once
                if(before==gp::State::Dark && !sleep_cancelled) {   // lit from the dark (a cancelled floor sleep is logged by sleep_now)
                    const auto why=idle.last_dark_wake();
                    int age=-1;
                    if(why==gp::DarkWake::Incident && control==Control::Companion) {   // S2: evidence instant -> backlight on
                        app->tick();age=incident_evidence_age_ms();
                        dark_wake_evidence_ms=age;dark_wake_frame_ms=-1;dark_frame_pending=age>=0;
                        if(age>=0)dark_wake_evidence_at=clock.now()-static_cast<Millis>(age);
                    }
                    std::snprintf(line,sizeof line,"G16N DARK wake cause=%s evidence_ms=%d dark_total_s=%u\n",gp::dark_wake_text(why),age,unsigned(idle.dark_total_ms(now32)/1000));text(line);
                }
            }
            wake_guard.filter(front,side,now32);
            g_front=front;g_side=side;
        }
        if(control==Control::Companion) {
            force_draw|=companion_step(now,g_front,g_side);
        } else {
        if(deadline && now>=deadline)stop();
        // Bound work per loop so no traffic rate can starve expiry/stop/display.
        for(unsigned i=0;i<24 && next_packet();++i) {
            record={};record.kind=1;record.flags=1|(packet.truncated?2:0);record.channel=packet.meta.channel;
            record.acquired_us=packet.meta.acquired.at*1000;record.radio_us=packet.meta.radio_timestamp_us;
            record.reported=packet.meta.reported_length;record.size=packet.size;record.rssi=packet.meta.rssi_dbm;record.noise=packet.meta.noise_floor_dbm;
            record.rx_state=packet.meta.status==RxStatus::Ok?0:1;std::memcpy(record.payload,packet.bytes.data(),packet.size);
            if(drop_budget){--drop_budget;++deliberate_drops;if(!drop_budget){cover();snapshot();text("G13 ACK drop_completed_24\n");}}
            else if(monitor->receive(packet)) {
                const auto* observation=monitor->last_security();
                const auto advertised=observation && observation->settings.ds_channel_present?observation->settings.ds_channel:0;
                const bool locked=survey.locked();survey.observed(packet.meta.channel,packet.meta.acquired.at,advertised);
                if(!locked && survey.locked())stable_since=clock.now();
            }
            send_record();
        }
        }
        const auto next=survey.next(clock.now());
        if(next && next!=channel) {
            // G16J: an area-sweep excursion (and the return from it) keeps the lock and the coverage
            // window; any other retune is a real channel change and restarts both.
            const bool leaving=survey.away(),returning=sweeping && !leaving;
            channel=next;
            if(!leaving && !returning)stable_since=clock.now();
            if(!radio.tune(channel)){
                if(control==Control::Console){stop();text("GRX1 ERROR rediscovery tune failed\n");}
                else {survey.stop();radio.stop();companion_radio=companion::RadioState::Failed;}
            }
            const auto tuned_at=clock.now();
            if(leaving){sweeping=true;sweep_left=tuned_at;}
            else if(returning){sweeping=false;if(tuned_at>sweep_left)sweep_away_in_window+=tuned_at-sweep_left;}
            else {sweeping=false;sweep_away_in_window=0;cover();}
        }
        if(control==Control::Console) {
            burst_stop();   // G16I: the lab console owns the screen
            if(now-last_status>=1000){cover();status(2);snapshot();last_status=now;}
            const auto draw_now=clock.now();
            if(display && edge_until) {
                if(redraw.due(draw_now)){if(auto* canvas=board.canvas()){companion::draw_edge_test(*canvas);board.present();dirty.invalidate();}redraw.drawn(draw_now,false,0,Core::fresh_ms);}
            } else if(display && redraw.due(draw_now)) {
                draw_console(board,redraw,draw_now);dirty.invalidate();
            }
        } else {
            if(now-last_status>=1000){if(radio.listening())cover();last_status=now;}
            if(force_draw || now-last_tick>=100){app->tick();last_tick=now;health.overlay(app->presenter().view().overlay);}
            tune_service(now);
            if(setup_service(now)){force_draw=true;redraw=sticks3::RedrawSchedule{};}   // G16M
            const auto draw_now=clock.now();
            // G16I: only the bright face screen may show a burst; the update question, the EDGE pattern and the dim view end it.
            if(!display || update_confirm.is_open() || edge_until || idle.state()!=gp::State::Active || setup_visible())burst_stop();
            if(display && setup_visible()) {   // G16M: the setup screen owns the panel (countdown once a second is enough: 250 ms)
                if(force_draw || draw_now-last_confirm_draw>=250){show_setup(draw_now);last_confirm_draw=draw_now;}
            } else if(display && update_confirm.is_open()) {   // G16B: the on-screen confirmation owns the panel
                if(force_draw || draw_now-last_confirm_draw>=250) {
                    guardian::ota::View v;v.stage=guardian::ota::Stage::Confirm;v.running_version=sticks3::ota::running_version();
                    v.remaining_ms=update_confirm.remaining_ms(static_cast<std::uint32_t>(draw_now));show_update(v);last_confirm_draw=draw_now;
                }
                if(force_draw)redraw=sticks3::RedrawSchedule{};
            } else if(display && edge_until) {
                if(force_draw || redraw.due(draw_now)){if(auto* canvas=board.canvas()){companion::draw_edge_test(*canvas);board.present();dirty.invalidate();}redraw.drawn(draw_now,false,0,Core::fresh_ms);}
            } else if(display && !glass_frames) {
                // G16N: no frame is drawn while dark (the notice was painted once on entering); monitoring continues.
            } else if(display && idle.state()==gp::State::Dim && (force_draw || redraw.due(draw_now))) {
                // G16D: the dim view, one frame a second; passive monitoring continues underneath.
                companion::Status st{};st.radio=radio_state();st.store=app->store();st.persona_art=art_ok;fill_limits(st);
                app->render_dim(st,frame);   // G23: the Face screen's decision, whatever screen was left open
                redraw.cadence_ms=dim_cadence_ms;
                if(auto* canvas=board.canvas()) {
                    companion::draw_dim(*canvas,frame,art_ok?&art_set:nullptr);guardian::battery::draw_indicator(*canvas,battery_state);
                    const auto plan=dirty.plan(canvas->pixels(),canvas->width(),canvas->height(),true);
                    if(!board.present_rows(plan))dirty.invalidate();
                }
                const auto& v=app->presenter().view();
                redraw.drawn(draw_now,v.last_seen_known,v.last_seen_ms,Core::fresh_ms);
            } else if(display && (force_draw || redraw.due(draw_now))) {
                const std::int64_t t0=esp_timer_get_time();
                companion::Status st{};st.radio=radio_state();st.store=app->store();fill_limits(st);
                // The portraits only when all 16 embedded frames have exactly the expected size; otherwise placeholders.
                st.persona_art=art_ok;
                if(tune_session.active()){const auto left=(tune_session.remaining_ms(static_cast<std::uint32_t>(draw_now))+999)/1000;st.tune_session_s=static_cast<std::uint16_t>(left?left:1);}
                app->render(st,frame);
                const auto& v=app->presenter().view();
                // G16C: face screens animate at display.frame_ms; other screens keep the 250 ms cadence.
                const bool animated=frame.face_shown && app->presenter().screen()==Screen::Face;
                redraw.cadence_ms=animated && tuning?static_cast<Millis>(tuning->get(tune_frame_ms)):sticks3::RedrawSchedule::default_cadence_ms;
                companion::DrawInput in;in.art=art_ok?&art_set:nullptr;in.anim_ms=draw_now;in.motion=motion();
                in.imu=motion_model.step(t0);in.cache=warp_cache;
                if(face_head) {   // G21: the rated face's 3D frame for this pose (a running burst keeps the frame it was made from)
                    const auto before=face_head->inflates()+face_head->failures();
                    const std::int64_t h0=esp_timer_get_time();
                    companion::choose_head(frame,in,face_head,face_burst && face_burst->active());
                    if(face_head->inflates()+face_head->failures()!=before) {
                        const auto took=static_cast<std::uint32_t>(esp_timer_get_time()-h0);
                        ++head_changes;head_change_us_total+=took;if(took>head_change_us_max)head_change_us_max=took;
                    }
                }
                if(face_burst) {   // G16I: a real shake bursts the fresh rated face; draw() cancels it for an ALERT or any other face
                    const auto pose=companion::face_pose(frame,in);
                    if(shake_waiting) {
                        shake_waiting=false;
                        // Never while a TUNE session is being used (the update question is excluded by the branch above).
                        if(animated && companion::burst_allowed(frame) && !tune_session.active() && !tune_link.running()) {
                            burst_seed=burst_seed*1664525u+1013904223u+static_cast<std::uint32_t>(t0);
                            if(face_burst->active())face_burst->kick(draw_now,in.imu.lin_x,in.imu.lin_y,burst_seed);   // shaken again: re-scatter
                            else if(const auto* art=companion::face_art(frame,in)) {
                                const auto src=warp_cache && warp_cache->art()==art?warp_cache->source():companion::persona::PixelSource{nullptr,art};
                                face_burst->begin(art,src,draw_now,pose,in.imu.lin_x,in.imu.lin_y,burst_seed);
                            }
                        }
                    }
                    // G16O: gravity is the motion model's up vector; its shove feeds the stillness rule (no IMU: standing and still).
                    face_burst->step(draw_now,in.imu.active?in.imu.up_x:0.0f,in.imu.active?in.imu.up_y:-1.0f,pose,
                                     in.imu.active?in.imu.lin_x:0.0f,in.imu.active?in.imu.lin_y:0.0f);
                    in.burst=face_burst;
                }
                if(auto* canvas=board.canvas()){
                    companion::draw(*canvas,frame,in);guardian::battery::draw_indicator(*canvas,battery_state);
                    const std::int64_t t1=esp_timer_get_time();
                    companion_drain();   // keep the radio queue short while the panel transfer runs
                    const std::int64_t t2=esp_timer_get_time();
                    // G16C rework: only the rows that changed, the whole frame once a second.
                    const bool force=draw_now-last_full_push>=full_push_ms;
                    const auto plan=dirty.plan(canvas->pixels(),canvas->width(),canvas->height(),force);
                    if(plan.full){last_full_push=draw_now;++full_pushes;}
                    if(!board.present_rows(plan))dirty.invalidate();
                    for(std::size_t r=0;r<plan.count;++r)push_rows_total+=static_cast<std::uint64_t>(plan.runs[r].rows);
                    ++push_frames;
                    const std::int64_t t3=esp_timer_get_time();
                    if(dark_frame_pending){dark_frame_pending=false;dark_wake_frame_ms=static_cast<int>(clock.now()-dark_wake_evidence_at);}   // G16N S2: first frame after the wake
                    frame_stats.add(sticks3::frame_category(frame,face_burst && face_burst->active()),t1-t0,t3-t2,last_present_us?t3-last_present_us:0,
                                    in.imu.active?t3-in.imu.newest_us:-1);
                    last_present_us=t3;
                }
                // Redraw exactly at the evidence deadline (G13 timing rule) as well as the cadence.
                redraw.drawn(draw_now,v.last_seen_known,v.last_seen_ms,Core::fresh_ms);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

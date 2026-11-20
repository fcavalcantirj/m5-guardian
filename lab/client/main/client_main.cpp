// Ordinary STA client used only in explicitly launched owner-scoped lab checks.
// No raw frame injection, AP mode, automatic reconnect or persisted credentials.
#include "command.hpp"
#include <atomic>
#include <cstdio>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include "driver/usb_serial_jtag.h"
#include "esp_app_desc.h"
#include "esp_event.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
namespace {
std::atomic<bool> connected{false},got_ip{false};
std::atomic<unsigned> connects{0},disconnects{0},reason{0};
bool started=false;std::uint64_t deadline=0;std::uint8_t mac[6]{};
// Random per-boot nonce: lets the host prove a stop happened without a reset.
char boot[17]{};unsigned deadline_stops=0,command_stops=0;std::int64_t last_join_us=-1,last_stop_us=-1;
void text(const char* s){usb_serial_jtag_write_bytes(s,std::strlen(s),pdMS_TO_TICKS(30));}
void status(){
 char out[256];std::snprintf(out,sizeof out,"GCLIENT STATE us=%" PRIi64 " boot=%s active=%d connected=%d ip=%d connects=%u disconnects=%u reason=%u deadline_stops=%u command_stops=%u last_join_us=%" PRIi64 " last_stop_us=%" PRIi64 "\n",esp_timer_get_time(),boot,started,connected.load(),got_ip.load(),connects.load(),disconnects.load(),reason.load(),deadline_stops,command_stops,last_join_us,last_stop_us);text(out);
}
void event(void*,esp_event_base_t base,int32_t id,void* data){
 if(base==WIFI_EVENT&&id==WIFI_EVENT_STA_CONNECTED){connected=true;++connects;}
 if(base==WIFI_EVENT&&id==WIFI_EVENT_STA_DISCONNECTED){connected=false;got_ip=false;++disconnects;reason=static_cast<wifi_event_sta_disconnected_t*>(data)->reason;}
 if(base==IP_EVENT&&id==IP_EVENT_STA_GOT_IP)got_ip=true;
}
void stop(bool expired=false){
 if(started){esp_wifi_disconnect();ESP_ERROR_CHECK(esp_wifi_stop());started=false;last_stop_us=esp_timer_get_time();if(expired)++deadline_stops;else ++command_stops;}
 deadline=0;connected=false;got_ip=false;
 wifi_config_t clear{};ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA,&clear));
 text(expired?"GCLIENT STOPPED deadline\n":"GCLIENT STOPPED\n");
}
void command(const char* s){
 auto c=gclient::parse(s);
 if(c.verb==gclient::Verb::Info){char out[256],sha[65];esp_app_get_elf_sha256(sha,sizeof sha);std::snprintf(out,sizeof out,"GCLIENT INFO guardian-client/1.1 mac=%02x:%02x:%02x:%02x:%02x:%02x boot=%s elf=%s\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],boot,sha);text(out);status();return;}
 if(c.verb==gclient::Verb::Stop){stop();return;}
 if(c.verb!=gclient::Verb::Join){text("GCLIENT ERROR invalid command\n");return;}
 if(started){gclient::wipe(&c,sizeof c);text("GCLIENT ERROR stop first\n");return;}
 wifi_config_t cfg{};std::memcpy(cfg.sta.ssid,c.ssid,32);std::memcpy(cfg.sta.password,c.password,64);
 cfg.sta.bssid_set=true;std::memcpy(cfg.sta.bssid,c.bssid,6);cfg.sta.channel=c.channel;
 cfg.sta.threshold.authmode=WIFI_AUTH_WPA2_PSK;cfg.sta.pmf_cfg.capable=true;
 cfg.sta.scan_method=WIFI_FAST_SCAN;cfg.sta.failure_retry_cnt=0;
 auto err=esp_wifi_set_config(WIFI_IF_STA,&cfg);gclient::wipe(&cfg,sizeof cfg);
 auto seconds=c.seconds;gclient::wipe(&c,sizeof c);
 if(err!=ESP_OK){text("GCLIENT ERROR config\n");stop();return;}
 err=esp_wifi_start();if(err!=ESP_OK){text("GCLIENT ERROR start\n");stop();return;}
 started=true;last_join_us=esp_timer_get_time();deadline=last_join_us+static_cast<std::uint64_t>(seconds)*1000000;
 ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
 if(esp_wifi_connect()!=ESP_OK){text("GCLIENT ERROR connect\n");stop();return;}
 text("GCLIENT JOINING\n");
}
}
extern "C" void app_main(){
 usb_serial_jtag_driver_config_t usb={.tx_buffer_size=4096,.rx_buffer_size=512};ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&usb));
 ESP_ERROR_CHECK(esp_read_mac(mac,ESP_MAC_WIFI_STA));
 std::uint8_t nonce[8];esp_fill_random(nonce,sizeof nonce);for(unsigned i=0;i<8;++i)std::snprintf(boot+2*i,3,"%02x",nonce[i]);
 // This test image is dedicated to the owner-designated Cardputer only.
 const std::uint8_t allowed[]={0x70,0xaf,0x09,0xdf,0xb4,0xfc};if(std::memcmp(mac,allowed,6)){text("GCLIENT ERROR wrong device\n");for(;;)vTaskDelay(pdMS_TO_TICKS(1000));}
 ESP_ERROR_CHECK(esp_netif_init());ESP_ERROR_CHECK(esp_event_loop_create_default());
 if(!esp_netif_create_default_wifi_sta())abort();
 wifi_init_config_t cfg=WIFI_INIT_CONFIG_DEFAULT();cfg.nvs_enable=0;ESP_ERROR_CHECK(esp_wifi_init(&cfg));
 ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
 wifi_country_t country={};std::memcpy(country.cc,"BR",3);country.schan=1;country.nchan=13;country.policy=WIFI_COUNTRY_POLICY_MANUAL;ESP_ERROR_CHECK(esp_wifi_set_country(&country));
 ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,ESP_EVENT_ANY_ID,event,nullptr));
 ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT,IP_EVENT_STA_GOT_IP,event,nullptr));
 char input[256]{};unsigned used=0;bool overflow=false;std::int64_t last=0;
 for(;;){
  char bytes[64];int n=usb_serial_jtag_read_bytes(bytes,sizeof bytes,0);
  for(int i=0;i<n;++i){
   if(bytes[i]=='\n'){if(overflow)text("GCLIENT ERROR too long\n");else{input[used]=0;command(input);}gclient::wipe(input,sizeof input);used=0;overflow=false;}
   else if(bytes[i]!='\r'&&!overflow){if(used==sizeof(input)-1)overflow=true;else input[used++]=bytes[i];}
  }
  gclient::wipe(bytes,sizeof bytes);
  auto now=esp_timer_get_time();if(started&&static_cast<std::uint64_t>(now)>=deadline)stop(true);
  if(now-last>=1000000){status();last=now;}
  vTaskDelay(pdMS_TO_TICKS(10));
 }
}

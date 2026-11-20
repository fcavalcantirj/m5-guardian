// Lab acquisition bridge only. No Guardian policy, UI, active scanning or TX API.
#include "wire.hpp"
#include <atomic>
#include <algorithm>
#include <cinttypes>
#include "driver/usb_serial_jtag.h"
#include "esp_event.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
namespace {
using grx::Record;
QueueHandle_t queue;
std::atomic<std::uint32_t> received{0},drops{0},bad{0};
std::atomic<bool> listening{false};
std::uint64_t boot_id{},deadline{},run_start{};
std::uint32_t sequence{};
std::uint8_t channel{},mac[6]{};
// Static scratch avoids large app-task stack use; callback has separate storage.
Record outgoing{};
std::uint8_t binary[grx::max_packet];
char line[grx::max_packet*2+7];
void text(const char* p){usb_serial_jtag_write_bytes(p,std::strlen(p),pdMS_TO_TICKS(20));}
void send(Record& r){
 r.boot=boot_id;r.sequence=sequence++;r.received=received.load();r.drops=drops.load();r.bad=bad.load();
 auto n=grx::encode(r,binary,sizeof binary);if(!n)return;
 std::memcpy(line,"GRX1 ",5);const char* h="0123456789abcdef";
 for(std::size_t i=0;i<n;++i){line[5+2*i]=h[binary[i]>>4];line[6+2*i]=h[binary[i]&15];}
 line[5+2*n]='\n';const auto length=6+2*n;
 if(usb_serial_jtag_write_bytes(line,length,pdMS_TO_TICKS(20))!=static_cast<int>(length))++drops;
}
void status(std::uint8_t kind){
 outgoing={};outgoing.kind=kind;outgoing.channel=channel;outgoing.flags=listening?1:0;outgoing.acquired_us=esp_timer_get_time();send(outgoing);
}
void stop(){
 listening=false;ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
 // Discard pending frames explicitly; never present pre-stop queued frames as new.
 while(xQueueReceive(queue,&outgoing,0)==pdTRUE)++drops;
 deadline=0;status(4);
}
void info(){
 char msg[180];std::snprintf(msg,sizeof msg,"GRX1 INFO guardian-rx/1.2 chip=esp32s3 mac=%02x:%02x:%02x:%02x:%02x:%02x idf=v5.4 boot=%016" PRIx64 " max=1536 fcs=unavailable logical-length-minus4\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],boot_id);text(msg);
}
void receive(void* buffer,wifi_promiscuous_pkt_type_t type){
 if(!listening||type!=WIFI_PKT_MGMT)return;
 ++received;
 const auto* p=static_cast<const wifi_promiscuous_pkt_t*>(buffer);
 const auto length=p->rx_ctrl.sig_len;
 if(length<4){++bad;return;}
 Record r{};r.kind=1;r.flags=1;r.channel=p->rx_ctrl.channel;r.rx_state=p->rx_ctrl.rx_state;
 r.acquired_us=esp_timer_get_time();r.radio_us=p->rx_ctrl.timestamp;r.reported=length;r.rssi=p->rx_ctrl.rssi;r.noise=p->rx_ctrl.noise_floor;
 r.size=std::min<std::uint16_t>(length-4,grx::max_frame);if(r.size<length-4)r.flags|=2;
 std::memcpy(r.payload,p->payload,r.size);
 // sig_len includes logical FCS, but trailing storage is not a verified FCS.
 // Never read beyond the logical FCS-free bytes. flags bit 2 remains false.
 // Wi-Fi callback runs in the driver task, not an ISR. Bounded, no USB/policy here.
 if(xQueueSend(queue,&r,0)!=pdTRUE)++drops;
}
void command(const char* s){
 const auto c=grx::parse_command(s);
 if(c.verb==grx::Verb::Sync){
  char reply[128];const auto now=static_cast<std::uint64_t>(esp_timer_get_time());
  std::snprintf(reply,sizeof reply,"GRX1 SYNC nonce=%" PRIu32 " boot=%016" PRIx64 " us=%" PRIu64 "\n",c.nonce,boot_id,now);text(reply);return;
 }
 if(c.verb==grx::Verb::Info){info();return;}
 if(c.verb==grx::Verb::Stop){stop();return;}
 if(c.verb!=grx::Verb::Start){text("GRX1 ERROR command: info | start CHANNEL SECONDS | stop\n");return;}
 if(listening){text("GRX1 ERROR already listening; stop first\n");return;}
 if(esp_wifi_set_channel(c.channel,WIFI_SECOND_CHAN_NONE)!=ESP_OK){text("GRX1 ERROR channel unavailable\n");return;}
 channel=static_cast<std::uint8_t>(c.channel);run_start=esp_timer_get_time();deadline=run_start+static_cast<std::uint64_t>(c.seconds)*1000000;
 listening=true;
 if(esp_wifi_set_promiscuous(true)!=ESP_OK){listening=false;deadline=0;text("GRX1 ERROR receive start failed\n");return;}
 status(2);
}
}
extern "C" void app_main(){
 usb_serial_jtag_driver_config_t usb={.tx_buffer_size=8192,.rx_buffer_size=256};ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&usb));
 ESP_ERROR_CHECK(esp_read_mac(mac,ESP_MAC_WIFI_STA));esp_fill_random(&boot_id,sizeof boot_id);if(!boot_id)boot_id=1;
 queue=xQueueCreate(24,sizeof(Record));if(!queue)abort();
 ESP_ERROR_CHECK(esp_event_loop_create_default());
 wifi_init_config_t cfg=WIFI_INIT_CONFIG_DEFAULT();cfg.nvs_enable=0;ESP_ERROR_CHECK(esp_wifi_init(&cfg));
 ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
 // Explicit Brazil regulatory channel set, no active scan or association.
 wifi_country_t country={};std::memcpy(country.cc,"BR",3);country.schan=1;country.nchan=13;country.policy=WIFI_COUNTRY_POLICY_MANUAL;
 ESP_ERROR_CHECK(esp_wifi_set_country(&country));
 ESP_ERROR_CHECK(esp_wifi_start());ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
 wifi_promiscuous_filter_t filter={};filter.filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT;
 ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(receive));
 char input[64]{};std::size_t used=0;bool overflow=false;std::uint64_t last_status=0;
 for(;;){
  char bytes[32];int count=usb_serial_jtag_read_bytes(bytes,sizeof bytes,0);
  for(int i=0;i<count;++i){
   if(bytes[i]=='\n'){
    if(overflow)text("GRX1 ERROR command too long\n");else{input[used]=0;command(input);}
    used=0;overflow=false;
   }else if(bytes[i]!='\r'&&!overflow){if(used==sizeof(input)-1)overflow=true;else input[used++]=bytes[i];}
  }
  auto now=static_cast<std::uint64_t>(esp_timer_get_time());
  if(listening&&now>=deadline)stop();
  if(listening&&xQueueReceive(queue,&outgoing,0)==pdTRUE){
   if(outgoing.acquired_us<run_start)++drops;else send(outgoing);
  }
  if(now-last_status>=1000000){status(2);last_status=now;}
  vTaskDelay(pdMS_TO_TICKS(1));
 }
}

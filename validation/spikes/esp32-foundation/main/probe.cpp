// No radio, display, storage or network initialization. Imported fixture checks.
#include <cstdio>
#include <cstring>
#include "esp_heap_caps.h"
#include "esp_psram.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "guardian/core.hpp"
#include "guardian/security_parser.hpp"
#include "guardian/rating.hpp"
#include "guardian/detectors.hpp"
#include "guardian/presenter.hpp"
#include "fixtures.hpp"
using namespace guardian;
namespace {
struct Clock final:MonotonicClock {
    Millis at{1000};Millis now()const override{return at;}
    TimeEpoch epoch()const override{return {{1,2,3,4,5,6},1};}
};
struct Sink final:ObservationSink {
    IncidentObservation last{};unsigned count{};
    void security(const SecurityObservation&)override{}
    void incident(const IncidentObservation&i)override{last=i;++count;}
};
unsigned checks=0,failures=0;
void check(bool ok,const char*name){++checks;if(!ok)++failures;std::printf("GPROBE CHECK %s %s\n",name,ok?"PASS":"FAIL");}
}
extern "C" void app_main(){
    vTaskDelay(pdMS_TO_TICKS(1500));
    Clock clock;SecurityFrameParser parser;RxMeta m{};
    m.origin=Origin::Imported;m.status=RxStatus::Ok;m.acquired={clock.epoch(),clock.now(),true};m.band=Band::Ghz2_4;m.channel=6;
    auto parse=[&](const std::uint8_t*b,std::size_t n){return parser.parse({b,static_cast<std::uint16_t>(n),false},m);};
    const auto p=parse(beacon_wpa3_sae_pmf_required,sizeof beacon_wpa3_sae_pmf_required);
    check(p.status==ParseStatus::Complete,"sae_parse");
    Core core(clock,profiles::all_2g4_channels(),Origin::Imported);check(core.select(p.identity),"select");
    core.security(observe_security(p,m));const auto fresh=core.snapshot();
    check(fresh.settings.mood==Mood::VeryGood,"sae_policy");
    check(present(fresh).historical,"imported_is_historical");
    clock.at+=31000;check(core.snapshot().settings.mood==Mood::Unknown,"freshness_expires");
    const auto open=parse(beacon_open,sizeof beacon_open);check(assess(observe_security(open,m)).mood==Mood::Horrible,"open_policy");
    auto bad=p;bad.ssid_kind=SsidKind::Absent;bad.identity.ssid_size=0;bad.identity.ssid={};
    Core hidden(clock,profiles::all_2g4_channels(),Origin::Imported);check(hidden.select(bad.identity),"hidden_select");
    m.acquired.at=clock.at;hidden.security(observe_security(bad,m));check(!hidden.snapshot().has_security,"absent_not_hidden");
    ApprovedScope scope;ApprovedAp approved{};approved.network=p.identity;check(scope.select(approved),"scope");
    DetectorLimits limits;limits.burst_threshold=2;DisconnectDetector detector(scope,limits);Sink sink;
    std::uint8_t frame[sizeof deauth_reason7];std::memcpy(frame,deauth_reason7,sizeof frame);
    m.acquired.at=100;auto d=parse(frame,sizeof frame);detector.on_frame({frame,sizeof frame,false},m,d,sink);
    detector.on_tick({clock.epoch(),5000,true},sink);frame[22]=0x40;m.acquired.at=101;d=parse(frame,sizeof frame);
    detector.on_frame({frame,sizeof frame,false},m,d,sink);
    check(sink.count==1&&sink.last.acquired.at==101,"delayed_burst_acquisition");
    std::printf("GPROBE SIZES core=%u parser=%u disconnect=%u baseline=%u presenter=%u\n",unsigned(sizeof(Core)),unsigned(sizeof(SecurityFrameParser)),unsigned(sizeof(DisconnectDetector)),unsigned(sizeof(BaselineDetector)),unsigned(sizeof(Presenter)));
    for(;;){std::printf("GPROBE RESULT checks=%u failures=%u origin=imported rf=off psram=%u heap_internal=%u stack_free=%u\n",checks,failures,unsigned(esp_psram_is_initialized()?esp_psram_get_size():0),unsigned(heap_caps_get_free_size(MALLOC_CAP_INTERNAL)),unsigned(uxTaskGetStackHighWaterMark(nullptr)));std::fflush(stdout);vTaskDelay(pdMS_TO_TICKS(3000));}
}

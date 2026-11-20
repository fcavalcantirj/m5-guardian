// Host adapter over the SAME parser/detector/Core/presenter libraries as firmware.
#include "guardian/core.hpp"
#include "guardian/detectors.hpp"
#include "guardian/threats.hpp"
#include "guardian/rating.hpp"
#include "guardian/security_parser.hpp"
#include "guardian/presenter.hpp"
#include <array>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <time.h>
#include <unistd.h>
using namespace guardian;
namespace {
std::size_t unhex(const std::string& s,std::uint8_t* p,std::size_t cap){
 if(s.size()%2||s.size()/2>cap)throw std::runtime_error("invalid hex size");
 auto n=[](char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
 for(std::size_t i=0;i<s.size()/2;++i){int a=n(s[2*i]),b=n(s[2*i+1]);if(a<0||b<0)throw std::runtime_error("invalid hex digit");p[i]=static_cast<std::uint8_t>((a<<4)|b);}
 return s.size()/2;
}
class HostClock final:public MonotonicClock {
 TimeEpoch id_;
public:
 explicit HostClock(const std::string& id){if(unhex(id,id_.source_id.data(),16)!=16||!id_.valid())throw std::runtime_error("epoch required");id_.boot_id=1;}
 Millis now()const override{timespec t{};if(clock_gettime(CLOCK_MONOTONIC,&t))std::abort();return static_cast<Millis>(t.tv_sec)*1000+static_cast<Millis>(t.tv_nsec)/1000000;}
 TimeEpoch epoch()const override{return id_;}
};
class InputSource final:public FrameSource {
 std::array<std::uint8_t,1536> data_{};RxMeta meta_{};std::uint16_t size_{};bool truncated_{},pending_{};AcquisitionStats stats_{};
public:
 void offer(const std::string& hex,const RxMeta& meta,bool truncated){if(pending_)throw std::runtime_error("undrained frame");size_=static_cast<std::uint16_t>(unhex(hex,data_.data(),data_.size()));meta_=meta;truncated_=truncated;pending_=true;++stats_.received;stats_.epoch=meta.acquired.epoch;}
 bool next(FrameBuffer into,FrameSpan& span,RxMeta& meta)override{
  if(!pending_||!into.data||into.capacity<size_)return false;
  std::memcpy(into.data,data_.data(),size_);span={into.data,size_,truncated_};meta=meta_;pending_=false;++stats_.delivered;return true;
 }
 AcquisitionStats stats()const override{return stats_;}Band current_band()const override{return Band::Ghz2_4;}std::uint8_t current_channel()const override{return meta_.channel;}
};
}
int main(int argc,char**argv){
 try{
  if(argc!=5||(std::strcmp(argv[1],"--live")&&std::strcmp(argv[1],"--imported")))throw std::runtime_error("usage: engine --live|--imported BSSID_HEX SSID_HEX EPOCH_HEX");
  const auto origin=std::strcmp(argv[1],"--live")==0?Origin::LiveRadio:Origin::Imported;
  HostClock clock(argv[4]);Network net{};if(unhex(argv[2],net.bssid.data(),6)!=6)throw std::runtime_error("BSSID length");net.ssid_size=static_cast<std::uint8_t>(unhex(argv[3],net.ssid.data(),32));
  const auto caps=profiles::headless(profiles::all_2g4_channels(),1536);
  Core core(clock,caps.radio.channels,origin);if(!core.select(net))throw std::runtime_error("invalid selected network");
  ApprovedScope scope;ApprovedAp selected{};selected.network=net;selected.watch_impostors=true; // lab scope: full monitoring
  if(!scope.select(selected))throw std::runtime_error("invalid scope");
  SecurityFrameParser parser;DisconnectDetector disconnect(scope,DetectorLimits{});BaselineDetector baseline(scope,DetectorLimits{});ThreatDetectors threats(scope);Presenter presenter(caps.display,origin);InputSource source;
  std::array<std::uint8_t,1536> slot{};std::uint64_t parsed_count=0,selected_advertisements=0,association_frames=0,watched_advertisements=0;Mac watched_ap{};bool running=true;std::string pending;Millis last_output=0;
  auto snapshot=[&]{
   const Instant now{clock.epoch(),clock.now(),true};disconnect.on_tick(now,core);baseline.on_tick(now,core);for(std::size_t i=0;i<ThreatDetectors::count;++i)threats.at(i)->on_tick(now,core);
   const auto s=core.snapshot();presenter.update(s,now,&scope);const auto& v=presenter.view();
   std::cout<<"{\"event\":\"state\",\"now_ms\":"<<now.at<<",\"origin\":\""<<(origin==Origin::LiveRadio?"live":"imported")<<"\",\"frames\":"<<parsed_count<<",\"has_security\":"<<(s.has_security?"true":"false")<<",\"coverage\":"<<static_cast<int>(s.coverage)<<",\"mood\":"<<static_cast<int>(v.face)<<",\"overlay\":"<<static_cast<int>(v.overlay)<<",\"historical\":"<<(v.historical?"true":"false")<<",\"age_ms\":"<<s.age_ms<<",\"burst\":"<<(s.incidents[static_cast<std::size_t>(IncidentKind::DisconnectBurst)]?"true":"false")<<",\"burst_count\":"<<s.evidence[static_cast<std::size_t>(IncidentKind::DisconnectBurst)].count<<",\"burst_threshold\":"<<(s.incidents[static_cast<std::size_t>(IncidentKind::DisconnectBurst)]?s.evidence[static_cast<std::size_t>(IncidentKind::DisconnectBurst)].threshold:0)<<",\"burst_shapes\":"<<(s.incidents[static_cast<std::size_t>(IncidentKind::DisconnectBurst)]?s.evidence[static_cast<std::size_t>(IncidentKind::DisconnectBurst)].shapes:0)<<",\"unexpected_ap\":"<<(s.incidents[static_cast<std::size_t>(IncidentKind::UnexpectedAp)]?"true":"false")<<",\"settings_changed\":"<<(s.incidents[static_cast<std::size_t>(IncidentKind::SettingsChanged)]?"true":"false")<<",\"incident_visible\":"<<(v.incident_visible?"true":"false")<<",\"incident_kind\":"<<static_cast<int>(v.incident.kind)<<",\"coverage_drops\":"<<s.last_coverage.dropped_in_window<<",\"mode\":"<<static_cast<int>(s.settings.mode)<<",\"pmf\":"<<static_cast<int>(s.settings.pmf)<<",\"selected_advertisements\":"<<selected_advertisements<<",\"watched_advertisements\":"<<watched_advertisements<<",\"association_frames\":"<<association_frames<<",\"burst_acquired_ms\":"<<s.evidence[static_cast<std::size_t>(IncidentKind::DisconnectBurst)].acquired.at<<",\"channel\":"<<unsigned(s.last_security.channel)<<",\"advertised_channel\":"<<(s.last_security.settings.ds_channel_present?unsigned(s.last_security.settings.ds_channel):0)<<",\"in_window\":"<<disconnect.in_window(now)<<",\"area\":[";
   for(std::size_t i=0,n=0;i<s.area.size();++i){if(!s.area[i].count)continue;std::cout<<(n++?",":"")<<"{\"family\":"<<static_cast<int>(s.area[i].family)<<",\"count\":"<<s.area[i].count<<",\"visible\":"<<(s.area_visible[i]?"true":"false")<<"}";}
   std::cout<<"]}"<<std::endl;
  };
  auto process=[&](const std::string& line){
   std::istringstream in(line);std::string op,extra;in>>op;
   if(op=="QUIT"){running=false;return;}
   if(op=="SNAPSHOT"){snapshot();return;}
   if(op=="WATCH_AP"||op=="APPROVE_AP"){
    std::string mac;if(!(in>>mac)||in>>extra||unhex(mac,watched_ap.data(),6)!=6||watched_ap[0]&1||std::all_of(watched_ap.begin(),watched_ap.end(),[](std::uint8_t x){return x==0;}))throw std::runtime_error("invalid AP identity");
    if(op=="APPROVE_AP"){ApprovedAp related{};related.network=net;related.network.bssid=watched_ap;if(!scope.approve(related))throw std::runtime_error("AP approval rejected");}
    std::cout<<"{\"event\":\"ap_scope_configured\"}"<<std::endl;return;
   }
   if(op=="BASELINE"){
    const auto s=core.snapshot();if(!s.has_security||s.security_historical||s.age_ms>=Core::fresh_ms||!s.last_security.settings_complete)throw std::runtime_error("no fresh complete baseline");
    selected.settings_known=true;selected.settings=SettingsFingerprint::of(s.last_security.settings);selected.channel_known=s.last_security.settings.ds_channel_present;selected.channel=s.last_security.settings.ds_channel;selected.band=s.last_security.band;
    scope.select(selected);baseline.reset();std::cout<<"{\"event\":\"baseline_approved\"}"<<std::endl;return;
   }
   if(op=="FRAME"){
    std::uint64_t acquired;int ch,rssi,state,trunc,reported;std::string hex;
    if(!(in>>acquired>>ch>>rssi>>state>>trunc>>reported>>hex)||in>>extra||ch<1||ch>13||rssi< -128||rssi>127||state<0||state>255||trunc<0||trunc>1||reported<4||reported>4095)throw std::runtime_error("invalid FRAME");
    if(hex.size()/2!=std::min<std::size_t>(static_cast<std::size_t>(reported-4),1536)||bool(trunc)!=(reported-4>1536))throw std::runtime_error("inconsistent frame lengths");
    if(acquired>clock.now()+100)throw std::runtime_error("future acquisition");
    RxMeta meta{};meta.acquired={clock.epoch(),acquired,true};meta.processed={clock.epoch(),clock.now(),true};meta.channel=static_cast<std::uint8_t>(ch);meta.rssi_dbm=static_cast<std::int8_t>(rssi);meta.rssi_valid=true;meta.status=state?RxStatus::DriverError:RxStatus::Ok;meta.reported_length=static_cast<std::uint16_t>(reported);meta.origin=origin;
    source.offer(hex,meta,trunc!=0);FrameSpan span{};RxMeta delivered{};if(!source.next({slot.data(),static_cast<std::uint16_t>(slot.size())},span,delivered))throw std::runtime_error("frame delivery failed");
    auto parsed=parser.parse(span,delivered);++parsed_count;
    if(delivered.status==RxStatus::Ok&&parsed.header_valid){
     if(parsed.status==ParseStatus::Complete&&parsed.identity.bssid==watched_ap&&(parsed.kind==FrameKind::Beacon||parsed.kind==FrameKind::ProbeResponse))++watched_advertisements;
     if(parsed.status==ParseStatus::Complete&&parsed.identity==net&&(parsed.kind==FrameKind::Beacon||parsed.kind==FrameKind::ProbeResponse))++selected_advertisements;
     if(parsed.identity.bssid==net.bssid&&(parsed.kind==FrameKind::Authentication||parsed.kind==FrameKind::AssociationRequest||parsed.kind==FrameKind::AssociationResponse))++association_frames;
    }
    core.security(observe_security(parsed,delivered));core.signal(observe_signal(parsed,delivered));scope.hear(delivered,parsed); /* G16R: the picked name's addresses, as Monitor::receive does */ disconnect.on_frame(span,delivered,parsed,core);baseline.on_frame(span,delivered,parsed,core);for(std::size_t i=0;i<ThreatDetectors::count;++i)threats.at(i)->on_frame(span,delivered,parsed,core);return;
   }
   if(op=="COVER"){
    std::uint64_t acquired,window,listened;unsigned channel,drops,supported;
    if(!(in>>acquired>>channel>>window>>listened>>drops>>supported)||in>>extra||channel>13||!window||window>300000||listened>window||supported>1)throw std::runtime_error("invalid COVER");
    CoverageReport c{};c.sampled_at={clock.epoch(),acquired,true};c.channel=static_cast<std::uint8_t>(channel);c.window_ms=window;c.listened_ms=listened;c.dropped_in_window=drops;c.passive_receive=supported?Support::Supported:Support::Unknown;core.coverage(c);disconnect.coverage(c);for(std::size_t i=0;i<ThreatDetectors::count;++i)threats.at(i)->coverage(c);return;
   }
   throw std::runtime_error("unknown command");
  };
  std::cout<<"{\"event\":\"ready\",\"clock_ms\":"<<clock.now()<<"}"<<std::endl;
  while(running){
   pollfd fd{STDIN_FILENO,POLLIN,0};int ready=poll(&fd,1,100);if(ready<0&&errno!=EINTR)throw std::runtime_error("poll failed");
   if(ready>0&&(fd.revents&(POLLIN|POLLHUP))){char buf[4096];ssize_t n=read(STDIN_FILENO,buf,sizeof buf);if(n==0)break;if(n<0){if(errno!=EINTR)throw std::runtime_error("read failed");}else for(ssize_t i=0;i<n;++i){if(buf[i]=='\n'){process(pending);pending.clear();if(!running)break;}else{if(pending.size()>=3300)throw std::runtime_error("oversized command");pending+=buf[i];}}}
   if(clock.now()-last_output>=1000){snapshot();last_output=clock.now();}
  }
  snapshot();return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}
}

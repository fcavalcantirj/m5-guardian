// G13 lab-console diagnostics screen, G16A upright portrait (135x240): every
// line at most 22 glyphs at 1x.
#include "measurement_display.hpp"
#include <cstdio>
#include <cinttypes>
#include <cstring>
#include <algorithm>
namespace sticks3 {
bool draw_measurement(Board& board,const guardian::Snapshot& s,std::uint32_t accepted,
    std::uint32_t invalid,std::uint32_t dropped,bool listening,bool locked,std::uint8_t tuned,guardian::Millis now) {
    auto* c=board.canvas();if(!c)return false;
    using namespace guardian;using namespace guardian::color;
    c->clear(dark);char line[64];char label[129];measurement::escaped_ssid(s.selected,label,sizeof label);
    int y=2;const auto put=[&](const char* text,std::uint16_t color){std::snprintf(line,sizeof line,"%.22s",text);c->text(2,y,line,color);y+=10;};
    const bool stale=s.has_security && s.age_ms>=Core::fresh_ms;
    const char* status=stale||s.coverage==Coverage::Stale?"No fresh data":!listening?"Radio stopped":!locked?"Discovery: gaps":s.coverage==Coverage::Degraded?"Coverage degraded":"Listening: 1 channel";
    put(s.origin==Origin::LiveRadio?"GUARDIAN live diag":"DEMO/Imported diag",yellow);
    put(status,white);
    const auto& b=s.selected.bssid;
    const bool selected=std::any_of(b.begin(),b.end(),[](auto byte){return byte!=0;});
    char text[64];
    if(selected){std::snprintf(text,sizeof text,"%02x:%02x:%02x:%02x:%02x:%02x",b[0],b[1],b[2],b[3],b[4],b[5]);put(text,white);
        std::snprintf(text,sizeof text,"tuned channel %u",tuned);put(text,white);}
    else {put("No selected BSSID",white);y+=10;}
    // Rotate long escaped labels in 22-glyph chunks. Raw bytes are always complete in JSON.
    const std::size_t len=std::strlen(label);
    const std::size_t pages=std::max<std::size_t>(1,(len+21)/22);
    const std::size_t offset=static_cast<std::size_t>((now/2000)%pages)*22;
    put(selected?label+offset:"Select via console",white);
    if(s.has_security){std::snprintf(text,sizeof text,"SSID bytes %u kind %d",s.selected.ssid_size,int(s.last_security.ssid_kind));put(text,grey);
        std::snprintf(text,sizeof text,"parse %d",int(s.last_security.parse));put(text,grey);}
    else if(selected){std::snprintf(text,sizeof text,"SSID bytes %u",s.selected.ssid_size);put(text,grey);put("no frame yet",grey);}
    else {put("No selection;",grey);put("no received fields",grey);}
    if(s.has_security){std::snprintf(text,sizeof text,"ch %u RSSI %d",s.last_security.channel,s.last_security.rssi);put(text,white);
        std::snprintf(text,sizeof text,"age %" PRIu64 " ms",static_cast<std::uint64_t>(s.age_ms));put(text,white);}
    else {put("ch -- RSSI --",white);put("age --",white);}
    std::snprintf(text,sizeof text,"ok %u invalid %u",unsigned(accepted),unsigned(invalid));put(text,white);
    std::snprintf(text,sizeof text,"drop %u",unsigned(dropped));put(text,white);
    const auto& a=s.last_security.settings;
    if(s.has_security) {
        std::snprintf(text,sizeof text,"Privacy %d WPA %d",a.privacy_valid?int(a.privacy_bit):-1,int(a.wpa.state));put(text,white);
        std::snprintf(text,sizeof text,"RSN %d PMF %d",int(a.rsn.state),int(a.rsn.pmf));put(text,white);
        std::snprintf(text,sizeof text,"RSN AKM %04x ci %04x",a.rsn.akms.kinds,a.rsn.pairwise.kinds);put(text,white);
        std::snprintf(text,sizeof text,"WPA AKM %04x ci %04x",a.wpa.akms.kinds,a.wpa.pairwise.kinds);put(text,white);
        std::snprintf(text,sizeof text,"OWE transition %d",int(a.owe_transition));put(text,white);
    } else {put("Security fields:",grey);put("not observed",grey);}
    const auto v=present(s);
    y=std::max(y,200);
    if(v.incident_visible){put("Observed incident;",red);put("cause unknown",red);}
    else {put("Advertised settings;",grey);put("2.4 GHz only",grey);}
    put("No password/identity",grey);put("assessment",grey);
    return board.present();
}
}

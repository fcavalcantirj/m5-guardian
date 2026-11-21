#include "check.hpp"
#include "measurement.hpp"
#include <algorithm>
#include <cstring>
#include <string>
using namespace guardian;
using namespace guardian::measurement;
GUARDIAN_CASE(fcs_before_capacity_and_rx_status) {
    std::array<std::uint8_t,1600> bytes{}; bytes[1535]=0x91;
    Packet p; RxMeta meta{};meta.acquired.epoch.source_id[0]=1;meta.acquired.known=true;meta.acquired.at=42;meta.channel=6;
    CHECK(copy_rx(p,bytes.data(),bytes.size(),1604,0,meta));
    CHECK_EQ(p.size,1536); CHECK(p.truncated); CHECK_EQ(p.bytes[1535],0x91);
    CHECK_EQ(p.meta.acquired.at,42ull); CHECK_EQ(p.meta.status,RxStatus::Ok);
    CHECK(copy_rx(p,bytes.data(),24,28,9,meta)); CHECK_EQ(p.meta.status,RxStatus::DriverError);
    CHECK_EQ(p.size,24); CHECK(!p.truncated);
    CHECK(!copy_rx(p,bytes.data(),24,29,0,meta));
    CHECK(!copy_rx(p,bytes.data(),24,3,0,meta));
    CHECK(!copy_rx(p,nullptr,24,28,0,meta));
}
GUARDIAN_CASE(raw_identity_and_escaped_label) {
    Network n{};CHECK(decode_network("021122334455","41001bff5c",n));
    CHECK_EQ(n.ssid_size,5);char label[129]{};escaped_ssid(n,label,sizeof label);
    CHECK_EQ(std::string(label),std::string("A\\x00\\x1b\\xff\\x5c"));
    CHECK(!decode_network("031122334455","41",n));
    CHECK(!decode_network("000000000000","41",n));
    CHECK(!decode_network("021122334455","0z",n));
    CHECK(decode_network("021122334455","-",n));CHECK_EQ(n.ssid_size,0);
    escaped_ssid(n,label,sizeof label);CHECK_EQ(std::string(label),std::string("<empty>"));
    CHECK(decode_network("021122334455","00",n));CHECK_EQ(n.ssid_size,1);
    char tiny[3]={'x','x','x'};escaped_ssid(n,tiny,sizeof tiny);CHECK_EQ(tiny[2],0);
}
GUARDIAN_CASE(passive_discovery_lock_loss_and_regulatory_bounds) {
    Survey s;CHECK(!s.begin(1,14,1,0));CHECK(!s.begin(1,11,13,0));
    CHECK(s.begin(1,13,6,0));CHECK_EQ(s.next(299),6);CHECK_EQ(s.next(300),7);
    s.observed(6,301);CHECK(!s.locked());
    s.observed(7,301);CHECK(s.locked());CHECK_EQ(s.next(1000),7);
    CHECK_EQ(s.next(5301),8);CHECK(!s.locked());
    s.stop();CHECK_EQ(s.next(5500),0);
    CHECK(s.begin(1,11,11,0xffffffffull));CHECK_EQ(s.next(0x10000012bull),1);
}

namespace {
class Clock final : public MonotonicClock {
public:
    Millis at{100};
    Millis now()const override{return at;}
    TimeEpoch epoch()const override{TimeEpoch e{};e.source_id[0]=1;e.boot_id=1;return e;}
};
Packet advertisement(Clock& clock) {
    // Deliberately generated Imported input, not RF evidence.
    Packet p{};p.size=43;p.meta.acquired={clock.epoch(),clock.now(),true};
    p.meta.origin=Origin::Imported;p.meta.status=RxStatus::Ok;p.meta.channel=6;
    p.bytes[0]=0x80;p.bytes[16]=2;p.bytes[21]=1;
    p.bytes[36]=0;p.bytes[37]=2;p.bytes[38]='a';p.bytes[39]='p';
    p.bytes[40]=3;p.bytes[41]=1;p.bytes[42]=6;return p;
}
}
GUARDIAN_CASE(real_library_pipeline_age_scope_and_degradation) {
    Clock clock;Monitor m(clock,profiles::all_2g4_channels(),Origin::Imported);
    Network n{};CHECK(decode_network("020000000001","6170",n));CHECK(m.select(n));
    CHECK(!m.approve_baseline());
    auto p=advertisement(clock);CHECK(m.receive(p));CHECK(m.snapshot().has_security);
    CHECK_EQ(m.snapshot().settings.mode,Mode::Open);CHECK(m.approve_baseline());
    p.meta.origin=Origin::Demo;CHECK(!m.receive(p));
    p.meta.origin=Origin::Imported;p.bytes[21]=2;CHECK(!m.receive(p));
    CoverageReport cov{};cov.sampled_at={clock.epoch(),clock.now(),true};cov.channel=6;
    cov.passive_receive=Support::Supported;cov.window_ms=100;cov.listened_ms=100;cov.dropped_in_window=1;
    m.coverage(cov);CHECK_EQ(m.snapshot().coverage,Coverage::Degraded);
    CHECK_EQ(m.snapshot().settings.mood,Mood::Unknown);
    clock.at=30100;CHECK_EQ(m.snapshot().coverage,Coverage::Stale);
    CHECK_EQ(m.snapshot().settings.mood,Mood::Unknown);
    // malformed selected advertisement must not be interpreted as open
    p=advertisement(clock);p.bytes[41]=9;CHECK(!m.receive(p));CHECK(m.invalid>0);
    CHECK_EQ(m.snapshot().settings.mood,Mood::Unknown);
    char output[4096]{};CHECK(m.json(output,sizeof output,3,false,false)>0);
    CHECK(std::strstr(output,"\"origin\":\"imported\"")!=nullptr);
    CHECK(std::strstr(output,"\"dropped\":3")!=nullptr);
}
GUARDIAN_CASE(selection_starts_a_new_explicit_approval_scope) {
    Clock clock;Monitor m(clock,profiles::all_2g4_channels(),Origin::Imported);
    Network n{};CHECK(decode_network("020000000001","6170",n));CHECK(m.select(n));
    Mac related{2,0,0,0,0,2};CHECK(m.watch_ap(related,true));
    auto p=advertisement(clock);p.bytes[21]=2;
    m.receive(p);m.receive(p);CHECK(!m.snapshot().incidents[1]);
    CHECK(m.select(n));m.receive(p);m.receive(p);CHECK(m.snapshot().incidents[1]);
}
GUARDIAN_CASE(adapter_pipeline_runs_the_same_disconnect_detector) {
    Clock clock;Monitor m(clock,profiles::all_2g4_channels(),Origin::Imported);
    Network n{};CHECK(decode_network("020000000001","6170",n));CHECK(m.select(n));
    auto p=advertisement(clock);p.size=26;p.bytes[0]=0xc0;p.bytes[24]=7;
    for(int i=0;i<19;++i)m.receive(p);
    CHECK(!m.snapshot().incidents[0]);
    // G16N: the count before the red report. (Found when this went green: the pattern detectors already
    // reported these frames as a NEARBY observation below the red threshold, and amber counts too.)
    const auto before_red=m.snapshot().incident_seq;
    m.receive(p);CHECK(m.snapshot().incidents[0]);
    CHECK_EQ(m.snapshot().evidence[0].count,20u);
    CHECK(m.view(m.snapshot()).incident_visible);
    // The disconnect detector's report went through the Monitor's Core: exactly one new incident, also in the view.
    CHECK_EQ(m.snapshot().incident_seq,before_red+1u);
    CHECK_EQ(m.view(m.snapshot()).incident_seq,before_red+1u);
    clock.at+=Core::incident_ms;CHECK(!m.snapshot().incidents[0]);
    CHECK_EQ(m.snapshot().incident_seq,before_red+1u);   // expiry is not a new incident
    // A second burst after the first banner ended is reported again: the count moves again.
    for(int i=0;i<20;++i){clock.at+=10;p.meta.acquired.at=clock.at;p.bytes[22]=static_cast<std::uint8_t>(i<<4);m.receive(p);}
    CHECK(m.snapshot().incidents[0]);
    CHECK(m.snapshot().incident_seq>before_red+1u);
    Monitor quiet(clock,profiles::all_2g4_channels(),Origin::Imported);
    CHECK_EQ(quiet.snapshot().incident_seq,0u);          // nothing received: nothing counted
}

GUARDIAN_CASE(frame_source_delivery_retains_fcs_free_bytes_and_acquisition) {
    Packet p{};p.size=100;p.bytes[15]=0xab;p.meta.reported_length=104;p.meta.acquired.at=19;
    std::array<std::uint8_t,16> small{};FrameSpan span{};RxMeta meta{};
    CHECK(!deliver(p,{nullptr,16},span,meta));CHECK(!deliver(p,{small.data(),0},span,meta));
    CHECK(deliver(p,{small.data(),16},span,meta));CHECK_EQ(span.size,16);CHECK(span.truncated);
    CHECK_EQ(small[15],0xab);CHECK_EQ(meta.reported_length,104);CHECK_EQ(meta.acquired.at,19ull);
    p.size=12;p.truncated=true;CHECK(deliver(p,{small.data(),16},span,meta));CHECK_EQ(span.size,12);CHECK(span.truncated);
    p.size=1600;CHECK(!deliver(p,{small.data(),16},span,meta));
}

GUARDIAN_CASE(fixed_channel_bootstrap_is_listening_without_invented_ap_lock) {
    Survey s;CHECK(s.begin(1,13,13,0,true));
    CHECK(s.fixed());CHECK(s.monitoring());CHECK(!s.locked());
    CHECK_EQ(s.next(1000),13);CHECK_EQ(s.next(6000),13);
    s.observed(13,6001);CHECK(s.locked());CHECK_EQ(s.next(15000),13);
    s.stop();CHECK(!s.monitoring());CHECK(!s.fixed());
    CHECK(s.begin(1,13,6,20000));CHECK(!s.fixed());
    CHECK_EQ(s.next(20300),7);CHECK(!s.monitoring());
}
// G16C rework (2): every lock loss is counted with its reason so a dropout on
// the glass can be traced to its cause from STATUS. Lock behaviour unchanged.
GUARDIAN_CASE(survey_counts_lock_losses_with_the_last_reason) {
    Survey s;CHECK(s.begin(1,13,6,0));
    CHECK_EQ(s.lock_losses(),0u);CHECK(s.last_loss()==Survey::Loss::None);
    s.observed(6,100);CHECK(s.locked());
    CHECK_EQ(s.next(5099),6);CHECK(s.locked());CHECK_EQ(s.lock_losses(),0u);
    CHECK_EQ(s.next(5100),7);CHECK(!s.locked());                       // 5 s without a verified advertisement
    CHECK_EQ(s.lock_losses(),1u);CHECK(s.last_loss()==Survey::Loss::Silence);
    CHECK_EQ(s.next(5200),7);CHECK_EQ(s.lock_losses(),1u);              // hopping is not another loss
    s.observed(7,5300);CHECK(s.locked());
    s.observed(7,5310,9);CHECK(!s.locked());CHECK_EQ(s.next(5311),9);   // followed the advertised channel
    CHECK_EQ(s.lock_losses(),2u);CHECK(s.last_loss()==Survey::Loss::Followed);
    s.observed(9,5400);CHECK(s.locked());
    s.hold_discovery(true);CHECK(!s.locked());                          // picker opened
    CHECK_EQ(s.lock_losses(),3u);CHECK(s.last_loss()==Survey::Loss::Held);
    s.hold_discovery(true);CHECK_EQ(s.lock_losses(),3u);                // not locked: nothing lost
    s.hold_discovery(false);s.observed(9,5500);CHECK(s.locked());
    s.stop();CHECK_EQ(s.lock_losses(),4u);CHECK(s.last_loss()==Survey::Loss::Stopped);
    CHECK(s.begin(1,13,6,6000));CHECK_EQ(s.lock_losses(),4u);          // counters survive a restart (since boot)
    CHECK(std::strcmp(Survey::loss_text(Survey::Loss::Silence),"silence_5s")==0);
    CHECK(std::strcmp(Survey::loss_text(Survey::Loss::None),"none")==0);
}
// G23 (channel-lock losses exceed update polls on the stick): the count per reason, so STATUS
// shows which cause produces the losses. Diagnostics only: the lock behaviour is unchanged.
GUARDIAN_CASE(survey_counts_lock_losses_per_reason_and_prints_them) {
    const char* zero="lock_loss_by=silence:0,followed:0,held:0,stopped:0";
    Survey s;char t[Survey::lock_loss_text_max];
    CHECK_EQ(s.lock_loss_text(t,sizeof t),std::strlen(zero));CHECK_EQ(std::string(t),std::string(zero));
    CHECK(s.begin(1,13,6,0));
    s.observed(6,100);CHECK_EQ(s.next(5100),7);                         // 5 s of silence
    s.observed(7,5300);CHECK_EQ(s.next(10299),7);CHECK_EQ(s.next(10300),8);   // and again
    CHECK_EQ(s.losses(Survey::Loss::Silence),2u);CHECK_EQ(s.losses(Survey::Loss::Followed),0u);
    s.observed(8,10400);s.observed(8,10410,3);CHECK_EQ(s.next(10411),3);       // followed the advertised channel
    s.observed(3,10500);s.hold_discovery(true);s.hold_discovery(true);         // picker opened (the second call loses nothing)
    s.hold_discovery(false);s.observed(3,10600);s.stop();                      // stopped while locked
    s.stop();                                                                  // not locked: nothing lost
    CHECK(s.begin(1,13,6,11000));s.observed(6,11100);CHECK(s.locked());
    CHECK(s.begin(1,13,6,12000));                                              // a restart while locked ends that lock
    CHECK_EQ(s.losses(Survey::Loss::Silence),2u);CHECK_EQ(s.losses(Survey::Loss::Followed),1u);
    CHECK_EQ(s.losses(Survey::Loss::Held),1u);CHECK_EQ(s.losses(Survey::Loss::Stopped),2u);
    CHECK_EQ(s.losses(Survey::Loss::None),0u);
    CHECK_EQ(s.lock_losses(),6u);                                              // the total is the sum of the reasons
    CHECK_EQ(s.lock_losses(),s.losses(Survey::Loss::Silence)+s.losses(Survey::Loss::Followed)+s.losses(Survey::Loss::Held)+s.losses(Survey::Loss::Stopped));
    CHECK(s.last_loss()==Survey::Loss::Stopped);
    const char* want="lock_loss_by=silence:2,followed:1,held:1,stopped:2";     // one STATUS token: no space, one '='
    CHECK_EQ(s.lock_loss_text(t,sizeof t),std::strlen(want));CHECK_EQ(std::string(t),std::string(want));
    char cut[64];std::memset(cut,'x',sizeof cut);                              // one byte short of the text: empty, never cut
    CHECK(std::strlen(want)<sizeof cut);                                       // the stated capacity stays inside the buffer
    CHECK_EQ(s.lock_loss_text(cut,std::strlen(want)),0u);CHECK_EQ(cut[0],0);
    CHECK_EQ(cut[std::strlen(want)],'x');                                      // nothing written past the stated capacity
    CHECK_EQ(s.lock_loss_text(nullptr,0),0u);
    char exact[64];CHECK_EQ(s.lock_loss_text(exact,std::strlen(want)+1),std::strlen(want));
    // four ten-digit counts and the terminator fit the documented size
    CHECK(Survey::lock_loss_text_max>=std::strlen("lock_loss_by=silence:4294967295,followed:4294967295,held:4294967295,stopped:4294967295")+1);
}
// G23 silence log (the silence lock losses are independent of the update poll; cause not known):
// a diagnostic record of the last 8 silence losses, so a deaf radio and a quiet network can be
// told apart. Diagnostics only: the lock behaviour is unchanged (the cases above are untouched).
GUARDIAN_CASE(survey_logs_a_silence_loss_with_its_context) {
    Survey s;char t[Survey::silence_log_text_max];
    const char* none="silence_log=none";
    CHECK_EQ(s.silence_count(),0u);
    CHECK_EQ(s.silence_log_text(t,sizeof t),std::strlen(none));CHECK_EQ(std::string(t),std::string(none));
    CHECK(s.begin(1,13,6,0));
    s.heard(6);s.observed(6,100,0,-61);CHECK(s.locked());          // the lock begins at 100 ms (a frame heard before it is not counted)
    s.heard(6);s.observed(6,1000,0,-58);                            // the last accepted frame: 1000 ms, -58 dBm
    s.heard(6);s.heard(6);s.heard(6);s.heard(7);                    // three other frames on the locked channel; one elsewhere is not counted
    CHECK_EQ(s.next(5999),6);CHECK(s.locked());
    CHECK_EQ(s.next(6000),7);CHECK(!s.locked());                    // silence: unchanged behaviour
    CHECK_EQ(s.silence_count(),1u);
    if(s.silence_count()==1u) {
        const auto& e=s.silence(0);
        CHECK_EQ(e.uptime_s,6u);CHECK_EQ(e.channel,6);CHECK_EQ(e.gap_ms,5000u);CHECK_EQ(e.age_s,5u);
        CHECK_EQ(e.other,3u);CHECK_EQ(e.rssi_dbm,-58);CHECK_EQ(e.sweeps,0u);CHECK(e.power==Survey::Power::Awake);
    }
    const char* one="silence_log=6:ch6:gap5000:age5:other3:rssi-58:sweep0:awake";
    CHECK_EQ(s.silence_log_text(t,sizeof t),std::strlen(one));CHECK_EQ(std::string(t),std::string(one));
    // the other reasons are counted (lock_loss_by) but not logged here
    s.heard(7);s.observed(7,6200,0,-75);CHECK(s.locked());
    s.observed(7,6300,9);CHECK(!s.locked());                        // followed
    s.observed(9,6400,0,-66);s.hold_discovery(true);                 // held
    s.hold_discovery(false);s.observed(9,6500,0,-66);s.stop();       // stopped
    CHECK(s.begin(1,13,6,7000));s.observed(6,7100);CHECK(s.begin(1,13,6,8000));   // restart while locked
    CHECK_EQ(s.losses(Survey::Loss::Silence),1u);CHECK_EQ(s.lock_losses(),5u);
    CHECK_EQ(s.silence_count(),1u);                                  // and the log survives a restart (since boot)
    CHECK_EQ(s.silence_log_text(t,sizeof t),std::strlen(one));CHECK_EQ(std::string(t),std::string(one));
}
GUARDIAN_CASE(silence_log_counts_sweep_excursions_and_the_power_state) {
    Survey s;CHECK(s.begin(1,13,6,10000));s.set_sweep(200,2000);
    s.power(Survey::Power::Dark);
    s.observed(6,10000,0,-70);CHECK(s.locked());
    CHECK_EQ(s.next(10000),6);                                       // the first excursion is due at 11800
    CHECK_EQ(s.next(11800),7);CHECK(s.away());                       // excursion 1
    s.heard(7);s.heard(6);                                           // a late frame of the locked channel counts; channel 7 does not
    CHECK_EQ(s.next(12000),6);
    CHECK_EQ(s.next(13800),8);CHECK_EQ(s.next(14000),6);             // excursion 2
    CHECK_EQ(s.next(15399),6);CHECK(s.locked());                     // time away is not silence (unchanged)
    CHECK_EQ(s.next(15400),7);CHECK(!s.locked());
    const char* want="silence_log=15:ch6:gap5400:age5:other1:rssi-70:sweep2:dark";   // gap: since the last accepted frame, time away included
    char t[Survey::silence_log_text_max];
    CHECK_EQ(s.silence_log_text(t,sizeof t),std::strlen(want));CHECK_EQ(std::string(t),std::string(want));
    CHECK(std::strcmp(Survey::power_text(Survey::Power::Awake),"awake")==0);
    CHECK(std::strcmp(Survey::power_text(Survey::Power::Dim),"dim")==0);
    CHECK(std::strcmp(Survey::power_text(Survey::Power::Dark),"dark")==0);
    // a new accepted frame starts a new gap: the counts are per gap, not per lock
    s.power(Survey::Power::Dim);s.observed(7,15500,0,-50);s.heard(7);s.observed(7,16000,0,-52);s.heard(7);s.heard(7);
    CHECK_EQ(s.next(21000),8);CHECK_EQ(s.silence_count(),2u);
    if(s.silence_count()==2u) {
        const auto& e=s.silence(1);
        CHECK_EQ(e.uptime_s,21u);CHECK_EQ(e.channel,7);CHECK_EQ(e.gap_ms,5000u);CHECK_EQ(e.age_s,5u);
        CHECK_EQ(e.other,2u);CHECK_EQ(e.rssi_dbm,-52);CHECK_EQ(e.sweeps,0u);CHECK(e.power==Survey::Power::Dim);
    }
}
GUARDIAN_CASE(silence_log_keeps_eight_and_prints_the_last_four_oldest_first) {
    Survey s;CHECK(s.begin(1,13,6,0,true));                          // fixed channel: no hop between the losses
    for(unsigned i=0;i<10;++i) {
        const Millis base=Millis{i}*10000;
        s.observed(6,base+100,0,static_cast<std::int8_t>(-50-int(i)));CHECK(s.locked());
        CHECK_EQ(s.next(base+5100),6);CHECK(!s.locked());
    }
    CHECK_EQ(s.losses(Survey::Loss::Silence),10u);
    CHECK_EQ(s.silence_count(),Survey::silence_kept);CHECK_EQ(Survey::silence_kept,8u);
    if(s.silence_count()==8u){CHECK_EQ(s.silence(0).uptime_s,25u);CHECK_EQ(s.silence(7).uptime_s,95u);CHECK_EQ(s.silence(7).rssi_dbm,-59);}
    const char* want="silence_log=65:ch6:gap5000:age5:other0:rssi-56:sweep0:awake;75:ch6:gap5000:age5:other0:rssi-57:sweep0:awake;"
                     "85:ch6:gap5000:age5:other0:rssi-58:sweep0:awake;95:ch6:gap5000:age5:other0:rssi-59:sweep0:awake";
    char t[Survey::silence_log_text_max];
    CHECK_EQ(s.silence_log_text(t,sizeof t),std::strlen(want));CHECK_EQ(std::string(t),std::string(want));
    // never cut: one byte short of the text gives an empty string, nothing past the stated capacity
    char cut[512];std::memset(cut,'x',sizeof cut);CHECK(std::strlen(want)<sizeof cut);
    CHECK_EQ(s.silence_log_text(cut,std::strlen(want)),0u);CHECK_EQ(cut[0],0);CHECK_EQ(cut[std::strlen(want)],'x');
    CHECK_EQ(s.silence_log_text(nullptr,0),0u);
    CHECK_EQ(s.silence_log_text(cut,std::strlen(want)+1),std::strlen(want));
}
GUARDIAN_CASE(silence_log_worst_case_line_fits_its_buffer_as_one_status_token) {
    Survey::SilenceLoss w{};
    w.uptime_s=4294967295u;w.gap_ms=4294967295u;w.age_s=4294967295u;w.other=4294967295u;w.sweeps=4294967295u;
    w.rssi_dbm=-128;w.channel=255;w.power=Survey::Power::Awake;   // every field at its widest
    const Survey::SilenceLoss four[4]={w,w,w,w};
    const std::string entry="4294967295:ch255:gap4294967295:age4294967295:other4294967295:rssi-128:sweep4294967295:awake";
    const std::string want="silence_log="+entry+";"+entry+";"+entry+";"+entry;
    char big[1024];
    const auto n=Survey::silence_log_format(four,4,big,sizeof big);
    CHECK_EQ(n,want.size());CHECK_EQ(std::string(big),want);
    CHECK(want.size()+1<=Survey::silence_log_text_max);              // the measured worst case fits the documented size
    CHECK(want.find(' ')==std::string::npos);                        // one STATUS token: no space, one '='
    CHECK_EQ(std::count(want.begin(),want.end(),'='),1);
    CHECK_EQ(Survey::silence_log_format(four,4,big,want.size()),0u);CHECK_EQ(big[0],0);   // never cut
    // the line is wider than any real one: uptime saturates rather than wraps
    Survey s;CHECK(s.begin(1,13,6,0,true));
    const Millis late=Millis{5000000000ull}*1000;                    // 5e9 s of uptime
    s.observed(6,late,0,-60);CHECK_EQ(s.next(late+5000),6);
    CHECK_EQ(s.silence_count(),1u);
    if(s.silence_count()==1u)CHECK_EQ(s.silence(0).uptime_s,4294967295u);
}
GUARDIAN_CASE(out_of_order_advertisement_does_not_regress_survey_freshness) {
    Survey s;CHECK(s.begin(1,13,6,0));
    s.observed(6,4000);s.observed(6,1000);
    CHECK_EQ(s.next(6500),6);CHECK(s.locked());
}

GUARDIAN_CASE(adjacent_channel_reception_is_not_a_settings_change) {
    Clock clock;Monitor m(clock,profiles::all_2g4_channels(),Origin::Imported);
    Network n{};CHECK(decode_network("020000000001","6170",n));CHECK(m.select(n));
    auto p=advertisement(clock);p.bytes[42]=5; // AP advertises 5; receiver is tuned to 6.
    CHECK(m.receive(p));
    CoverageReport c{};c.sampled_at={clock.epoch(),clock.now(),true};c.channel=6;
    c.passive_receive=Support::Supported;c.window_ms=100;c.listened_ms=100;m.coverage(c);
    CHECK(m.approve_baseline());
    for(unsigned i=0;i<25;++i){++clock.at;p.meta.acquired.at=clock.at;CHECK(m.receive(p));}
    CHECK(!m.snapshot().incidents[2]);
    // A real advertised-channel change must still be detected.
    p.bytes[42]=7;
    for(unsigned i=0;i<25;++i){++clock.at;p.meta.acquired.at=clock.at;CHECK(m.receive(p));}
    CHECK(m.snapshot().incidents[2]);
}
GUARDIAN_CASE(survey_follows_valid_advertised_channel_without_claiming_lock) {
    Survey s;CHECK(s.begin(1,13,6,0));
    s.observed(6,100,5);CHECK_EQ(s.next(101),5);CHECK(!s.locked());
    s.observed(5,110,5);CHECK(s.locked());
    s.observed(5,120,14);CHECK_EQ(s.next(121),5); // outside configured country
    CHECK(s.begin(1,13,13,200,true));s.observed(13,210,5);CHECK_EQ(s.next(211),13);
}

#include "measurement.hpp"
#include "guardian/rating.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cinttypes>
namespace guardian::measurement {
bool copy_rx(Packet& out, const std::uint8_t* bytes, std::size_t accessible,
             std::uint16_t length, std::uint8_t state, RxMeta meta) {
    if (!bytes || length < 4 || length > 4095 || accessible < std::size_t(length - 4)
        || !meta.acquired.valid() || meta.channel < 1 || meta.channel > 13) return false;
    const auto full = static_cast<std::uint16_t>(length - 4);
    out.size = static_cast<std::uint16_t>(std::min<std::size_t>(full, frame_capacity));
    out.truncated = full > out.size;
    meta.reported_length = length;
    meta.status = state ? RxStatus::DriverError : RxStatus::Ok;
    out.meta = meta;
    std::memcpy(out.bytes.data(), bytes, out.size);
    return true;
}
bool deliver(const Packet& packet, FrameBuffer into, FrameSpan& span, RxMeta& meta) {
    if(!into.data || !into.capacity || packet.size>packet.bytes.size())return false;
    const auto copied=std::min(packet.size,into.capacity);
    std::memcpy(into.data,packet.bytes.data(),copied);
    span={into.data,copied,packet.truncated || copied<packet.size};meta=packet.meta;return true;
}
// ---- G16G data path ------------------------------------------------------------------------
bool eapol_candidate(const std::uint8_t* b, std::size_t size) {
    if (!b || size < 24) return false;
    const std::uint8_t fc0 = b[0], fc1 = b[1];
    if ((fc0 & 0x03u) != 0 || ((fc0 >> 2) & 0x03u) != 2 || (fc1 & 0x40u) != 0) return false;   // version 0, data, unprotected
    const bool to_ds = (fc1 & 0x01u) != 0, from_ds = (fc1 & 0x02u) != 0, qos = (fc0 & 0x80u) != 0, order = (fc1 & 0x80u) != 0;
    const std::size_t h = 24u + (to_ds && from_ds ? 6u : 0u) + (qos ? 2u : 0u) + (qos && order ? 4u : 0u);
    static constexpr std::uint8_t llc[8] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e};
    return size >= h + 8 && std::memcmp(b + h, llc, 8) == 0;
}
void ChannelLoadMeter::valid(std::uint8_t ch, std::int8_t noise) {
    if (ch == 0 || ch >= channels) return;
    valid_[ch].fetch_add(1, std::memory_order_relaxed);
    noise_n_[ch].fetch_add(1, std::memory_order_relaxed);   // G16J
    noise_sum_[ch].fetch_add(static_cast<std::uint32_t>(static_cast<std::int32_t>(noise)), std::memory_order_relaxed);   // two's complement
}
void ChannelLoadMeter::error(std::uint8_t ch, std::int8_t rssi, std::int8_t noise) {
    if (ch == 0 || ch >= channels) return;
    noise_n_[ch].fetch_add(1, std::memory_order_relaxed);
    noise_sum_[ch].fetch_add(static_cast<std::uint32_t>(static_cast<std::int32_t>(noise)), std::memory_order_relaxed);
    errors_[ch].fetch_add(1, std::memory_order_relaxed);
    rssi_n_[ch].fetch_add(1, std::memory_order_relaxed);
    rssi_sum_[ch].fetch_add(static_cast<std::uint32_t>(static_cast<std::int32_t>(rssi)), std::memory_order_relaxed);   // two's complement
}
void ChannelLoadMeter::tuned(std::uint8_t ch, Millis now) {
    untuned(now);
    if (ch == 0 || ch >= channels) return;
    tuned_ = ch; segment_ = now;
}
void ChannelLoadMeter::untuned(Millis now) {
    if (tuned_ && now > segment_) listened_[tuned_] += now - segment_;
    tuned_ = 0; segment_ = now;
}
std::size_t ChannelLoadMeter::sample(const Instant& now, Origin origin, bool fcs, ChannelLoadSample* out, std::size_t cap) {
    if (tuned_ && now.at > segment_) { listened_[tuned_] += now.at - segment_; segment_ = now.at; }
    const Millis window = sampled_ && now.at > last_sample_ ? now.at - last_sample_ : 0;
    std::size_t n = 0;
    for (std::size_t ch = 1; ch < channels; ++ch) {
        const std::uint32_t v = valid_[ch].load(std::memory_order_relaxed), e = errors_[ch].load(std::memory_order_relaxed);
        const std::uint32_t rn = rssi_n_[ch].load(std::memory_order_relaxed), rs = rssi_sum_[ch].load(std::memory_order_relaxed);
        const std::uint32_t dv = v - seen_valid_[ch], de = e - seen_errors_[ch], drn = rn - seen_rssi_n_[ch], drs = rs - seen_rssi_sum_[ch];
        const std::uint32_t nn = noise_n_[ch].load(std::memory_order_relaxed), ns = noise_sum_[ch].load(std::memory_order_relaxed);
        const std::uint32_t dnn = nn - seen_noise_n_[ch], dns = ns - seen_noise_sum_[ch];
        const Millis heard = listened_[ch];
        if (!heard && !dv && !de) continue;
        if (n >= cap || !out) break;   // the rest stays counted for the next call
        seen_valid_[ch] = v; seen_errors_[ch] = e; seen_rssi_n_[ch] = rn; seen_rssi_sum_[ch] = rs; listened_[ch] = 0;
        seen_noise_n_[ch] = nn; seen_noise_sum_[ch] = ns;
        ChannelLoadSample s{};
        s.sampled_at = now; s.origin = origin; s.band = Band::Ghz2_4; s.channel = static_cast<std::uint8_t>(ch);
        s.window_ms = window ? window : heard; s.listened_ms = heard;
        s.valid_frames = dv; s.error_frames = de;
        s.error_rssi_sum = static_cast<std::int32_t>(drs); s.error_rssi_count = drn; s.fcs_supported = fcs;
        s.noise_sum = static_cast<std::int32_t>(dns); s.noise_count = dnn;
        out[n++] = s;
    }
    last_sample_ = now.at; sampled_ = true;
    return n;
}
std::uint32_t ChannelLoadMeter::valid_total() const {
    std::uint32_t t = 0; for (const auto& v : valid_) t += v.load(std::memory_order_relaxed); return t;
}
std::uint32_t ChannelLoadMeter::error_total() const {
    std::uint32_t t = 0; for (const auto& v : errors_) t += v.load(std::memory_order_relaxed); return t;
}
namespace {
int nibble(char c) {
    if(c>='0' && c<='9')return c-'0';
    if(c>='a' && c<='f')return c-'a'+10;
    if(c>='A' && c<='F')return c-'A'+10;
    return -1;
}
bool hex(const char* s, std::uint8_t* dst, std::size_t n) {
    for(std::size_t i=0;i<n;++i) {
        const int a=nibble(s[2*i]), b=nibble(s[2*i+1]);
        if(a<0 || b<0)return false;
        dst[i]=static_cast<std::uint8_t>((a<<4)|b);
    }
    return true;
}
}
bool decode_network(const char* bssid, const char* ssid, Network& out) {
    if(!bssid || !ssid || std::strlen(bssid)!=12)return false;
    Network n{};const auto length=std::strcmp(ssid,"-")==0?0:std::strlen(ssid);
    if(length>64 || length%2 || !hex(bssid,n.bssid.data(),6)
       || n.bssid[0]&1 || std::all_of(n.bssid.begin(),n.bssid.end(),[](auto b){return b==0;})
       || !hex(ssid,n.ssid.data(),length/2))return false;
    n.ssid_size=static_cast<std::uint8_t>(length/2);out=n;return true;
}
void escaped_ssid(const Network& n, char* out, std::size_t cap) {
    if(!out || !cap)return;
    std::memset(out,0,cap);
    if(!n.ssid_size){std::snprintf(out,cap,"<empty>");return;}
    std::size_t used=0;
    for(std::size_t i=0;i<std::min<std::size_t>(n.ssid_size,n.ssid.size());++i) {
        const auto b=n.ssid[i];const bool literal=b>=32 && b<=126 && b!='\\';
        if(used+(literal?1:4)>=cap)break;
        if(literal)out[used++]=static_cast<char>(b);
        else {std::snprintf(out+used,cap-used,"\\x%02x",b);used+=4;}
    }
}
bool Survey::begin(std::uint8_t first, std::uint8_t count, std::uint8_t initial, Millis now, bool fixed) {
    if(!first || !count || unsigned(first)+count>14 || initial<first || initial>=unsigned(first)+count)return false;
    lose(Loss::Stopped);   // a restart while locked ends that lock (normally stop() already did)
    first_=first;count_=count;channel_=initial;active_=true;locked_=false;fixed_=fixed;changed_=now;last_seen_=now;
    away_=false;sweep_next_=0;sweep_channel_=0;return true;
}
void Survey::set_sweep(Millis dwell_ms, Millis period_ms) {
    const bool on = dwell_ms > 0 && period_ms > 0 && dwell_ms < period_ms;
    sweep_dwell_ = on ? dwell_ms : 0; sweep_period_ = on ? period_ms : 0;
    sweep_next_ = 0;   // the first excursion is scheduled by the next next()
    if (!on) away_ = false;
}
const char* Survey::loss_text(Loss l) {
    switch(l){
    case Loss::None:return "none";case Loss::Silence:return "silence_5s";case Loss::Followed:return "followed_channel";
    case Loss::Held:return "held";case Loss::Stopped:return "stopped";
    }
    return "?";
}
std::size_t Survey::lock_loss_text(char* out, std::size_t capacity) const {
    if(!out || !capacity)return 0;
    const int n=std::snprintf(out,capacity,"lock_loss_by=silence:%u,followed:%u,held:%u,stopped:%u",
        unsigned(losses(Loss::Silence)),unsigned(losses(Loss::Followed)),unsigned(losses(Loss::Held)),unsigned(losses(Loss::Stopped)));
    if(n<0 || static_cast<std::size_t>(n)>=capacity){out[0]=0;return 0;}   // never cut
    return static_cast<std::size_t>(n);
}
std::uint8_t Survey::next(Millis now) {
    if(!active_)return 0;
    // G16J area sweep: a bounded excursion off the locked channel. Time away is not silence.
    if(away_) {
        if(locked_ && sweep_dwell_ && now>=away_since_ && now-away_since_<sweep_dwell_)return sweep_channel_;
        away_=false;
        if(now>away_since_)last_seen_+=now-away_since_;
    }
    if(locked_ && now-last_seen_>=5000){lose(Loss::Silence);changed_=now-300;}
    if(!fixed_ && !locked_ && now-changed_>=300){channel_=static_cast<std::uint8_t>(first_+(channel_-first_+1)%count_);changed_=now;}
    if(locked_ && !fixed_ && !hold_ && sweep_dwell_ && count_>1) {
        if(!sweep_next_)sweep_next_=now+sweep_period_-sweep_dwell_;
        else if(now>=sweep_next_) {
            std::uint8_t c=sweep_channel_?sweep_channel_:channel_;
            do { c=static_cast<std::uint8_t>(first_+(c-first_+1)%count_); } while(c==channel_);
            sweep_channel_=c;away_=true;away_since_=now;sweep_next_=now+sweep_period_;
            return sweep_channel_;
        }
    } else if(!locked_)sweep_next_=0;
    return channel_;
}
void Survey::observed(std::uint8_t channel, Millis acquired, std::uint8_t advertised_channel) {
    if(!active_ || hold_ || channel!=channel_ || acquired<changed_)return;
    // Strong adjacent-channel advertisements can be decoded while tuned away
    // from the AP. Follow its bounded advertised channel, then require a new
    // verified advertisement there before claiming lock.
    if(!fixed_ && advertised_channel>=first_ && unsigned(advertised_channel)<unsigned(first_)+count_
       && advertised_channel!=channel_) {
        channel_=advertised_channel;changed_=acquired;lose(Loss::Followed);return;
    }
    locked_=true;last_seen_=std::max(last_seen_,acquired);
}
Monitor::Monitor(const MonotonicClock& clock, ChannelSet channels, Origin origin)
    : clock_(clock), origin_(origin), core_(clock,channels,origin),
      disconnect_(scope_,limits_), baseline_(scope_,limits_), threats_(scope_) {
    // G16E: the built-in network detectors are registry entries 0 and 1.
    registry_.add(disconnect_);registry_.add(baseline_);
    // G16F/G16G: the passive pattern detectors follow (2..15).
    for(std::size_t i=0;i<ThreatDetectors::count;++i)registry_.add(*threats_.at(i));
    threats_.set_data_path(false);   // G16G: unfed until the adapter says otherwise
    threats_.set_ble_scan(false);    // G16H: no BLE scan feeds the detector until the adapter says so
}
void Monitor::channel_load(const ChannelLoadSample& sample) { threats_.noise.sample(sample,core_); }
// G16H: Bluetooth LE advertising reports from the adapter's passive scan. The same input checks as
// receive(): this Monitor's origin and timebase, a known time that is not in the future.
void Monitor::set_ble_scan(bool on) { ble_scan_=on;threats_.set_ble_scan(on); }
bool Monitor::ble_advert(const BleAdvert& advert) {
    if(!ble_scan_)return false;
    if(advert.origin!=origin_ || !advert.acquired.valid() || advert.acquired.epoch!=clock_.epoch()
       || advert.acquired.at>clock_.now()){++ble_invalid;return false;}
    ++ble_adverts;threats_.ble.advert(advert,core_);return true;
}
void Monitor::ble_coverage(const CoverageReport& report) { if(ble_scan_)threats_.ble.scan_coverage(report); }

bool Monitor::select(const Network& net) {
    // Console (lab harness) selection: explicitly scoped lab run, full monitoring incl. impostors.
    ApprovedAp candidate{};candidate.network=net;candidate.watch_impostors=true;
    if(!core_.select(net))return false;
    scope_.clear();
    if(!scope_.select(candidate))return false;
    // G22 (independent review H5): every registered detector, not only the two network ones. The pattern
    // detectors kept their burst records, counters and cooldowns across a pick (README: a new pick clears them).
    selected_=candidate;watched_={};registry_.reset();
    accepted=invalid=frames=selected_advertisements=watched_advertisements=association_frames=0;
    return true;
}
bool Monitor::select(const ApprovedAp& ap) {
    ApprovedScope check{};
    if(!check.select(ap))return false;
    if(scope_.has_selection() && scope_.selected().network==ap.network) {
        if(!scope_.select(ap))return false;
        selected_=ap;baseline_.reset();return true;
    }
    if(!select(ap.network) || !scope_.select(ap))return false;
    selected_=ap;return true;
}
bool Monitor::set_watch(bool watch) {
    if(!scope_.has_selection())return false;
    ApprovedAp ap=scope_.selected();ap.watch_impostors=watch;
    if(!scope_.select(ap))return false;
    selected_=ap;baseline_.reset();return true;
}
bool Monitor::approve(const ApprovedAp& ap) {
    if(!scope_.has_selection() || ap.network.ssid_size!=selected_.network.ssid_size
       || !std::equal(ap.network.ssid.begin(),ap.network.ssid.begin()+ap.network.ssid_size,selected_.network.ssid.begin())
       || !scope_.approve(ap))return false;
    baseline_.reset();return true;
}
bool Monitor::revoke(const Mac& bssid) {
    if(!scope_.revoke(bssid))return false;
    if(watched_==bssid)watched_={};
    baseline_.reset();return true;
}
bool Monitor::restore(const PersistedSelection& record) {
    ApprovedScope check(scope_.max_approved_aps());
    if(!guardian::restore(record,check))return false;
    if(!record.has_selection)return true;
    if(!select(record.selected))return false;
    for(std::size_t i=0;i<record.approved_count;++i)if(!approve(record.approved[i]))return false;
    return true;
}
bool Monitor::approve_baseline() {
    const auto s=core_.snapshot();
    if(!s.has_security || s.security_historical || s.age_ms>=Core::fresh_ms
       || s.coverage!=Coverage::Fresh || !s.last_security.settings_complete
       || s.last_security.parse!=ParseStatus::Complete || s.last_security.rx_status!=RxStatus::Ok)return false;
    selected_.settings_known=true;selected_.settings=SettingsFingerprint::of(s.last_security.settings);
    // ApprovedAp.channel is the advertised operating channel, not the
    // receiver's tuned channel. Never compare these different quantities.
    selected_.channel_known=s.last_security.settings.ds_channel_present;
    selected_.channel=s.last_security.settings.ds_channel;
    selected_.band=s.last_security.band;
    if(!scope_.select(selected_))return false;
    baseline_.reset();return true;
}
bool Monitor::watch_ap(const Mac& mac, bool approve) {
    if(mac[0]&1 || std::all_of(mac.begin(),mac.end(),[](auto b){return b==0;}))return false;
    if(approve){ApprovedAp related{};related.network=selected_.network;related.network.bssid=mac;if(!scope_.approve(related))return false;}
    watched_=mac;return true;
}
bool Monitor::receive(const Packet& packet) { return receive(packet,nullptr,nullptr); }
bool Monitor::receive(const Packet& packet, Candidate* candidate, bool* offered) {
    if(offered)*offered=false;
    ++frames;
    auto meta=packet.meta;
    if(meta.origin!=origin_ || meta.acquired.epoch!=clock_.epoch() || !meta.acquired.valid()
       || meta.acquired.at>clock_.now()){++invalid;return false;}
    meta.processed={clock_.epoch(),clock_.now(),true};
    const auto frame=packet.span();const auto p=parser_.parse(frame,meta);
    if(candidate && offered)*offered=candidate_from(p,meta,*candidate);
    const bool good=meta.status==RxStatus::Ok && p.status==ParseStatus::Complete;
    if(good)++accepted;
    else if(meta.status!=RxStatus::Ok || p.status==ParseStatus::Malformed || p.status==ParseStatus::Truncated)++invalid;
    const bool advert=p.kind==FrameKind::Beacon || p.kind==FrameKind::ProbeResponse;
    const bool selected=good && advert && p.identity==selected_.network;
    if(selected)++selected_advertisements;
    if(good && advert && p.identity.bssid==watched_)++watched_advertisements;
    if(meta.status==RxStatus::Ok && p.header_valid && p.identity.bssid==selected_.network.bssid
       && (p.kind==FrameKind::Authentication || p.kind==FrameKind::AssociationRequest || p.kind==FrameKind::AssociationResponse))++association_frames;
    core_.security(observe_security(p,meta));core_.signal(observe_signal(p,meta));
    scope_.hear(meta,p);                       // G16R: which addresses advertise the picked name (before the detectors)
    registry_.on_frame(frame,meta,p,core_);   // G16E: every registered detector, same parse
    air_.on_frame(p,meta);
    return selected;
}
void Monitor::coverage(const CoverageReport& c) { core_.coverage(c);registry_.coverage(c); }
Snapshot Monitor::snapshot() {
    const Instant now{clock_.epoch(),clock_.now(),true};
    registry_.on_tick(now,core_);return core_.snapshot();
}
ViewModel Monitor::view(const Snapshot& s) const { return present(s); }
std::size_t Monitor::json(char* out,std::size_t cap,std::uint32_t drops,bool listening,bool hopping) {
    const auto s=snapshot();const auto v=view(s);const auto& a=s.last_security.settings;
    const auto& burst=s.evidence[static_cast<std::size_t>(IncidentKind::DisconnectBurst)];
    char ssid[65]{};for(unsigned i=0;i<s.selected.ssid_size;++i)std::snprintf(ssid+2*i,3,"%02x",s.selected.ssid[i]);
    const auto& b=s.selected.bssid;
    const int n=std::snprintf(out,cap,
      "{\"event\":\"state\",\"now_ms\":%" PRIu64 ",\"origin\":\"%s\",\"frames\":%u,"
      "\"has_security\":%s,\"coverage\":%d,\"mood\":%d,\"overlay\":%d,\"historical\":%s,\"age_ms\":%" PRIu64 ","
      "\"burst\":%s,\"burst_count\":%u,\"unexpected_ap\":%s,\"settings_changed\":%s,\"incident_visible\":%s,\"incident_kind\":%d,"
      "\"coverage_drops\":%u,\"mode\":%d,\"pmf\":%d,\"selected_advertisements\":%u,\"watched_advertisements\":%u,"
      "\"association_frames\":%u,\"burst_acquired_ms\":%" PRIu64 ",\"in_window\":%u,"
      "\"accepted\":%u,\"invalid\":%u,\"dropped\":%u,\"listening\":%s,\"hopping\":%s,"
      "\"bssid\":\"%02x%02x%02x%02x%02x%02x\",\"ssid_hex\":\"%s\",\"ssid_kind\":%d,\"channel\":%u,\"rssi\":%d,"
      "\"parse\":%d,\"privacy_valid\":%s,\"privacy\":%s,\"wpa_state\":%d,\"rsn_state\":%d,"
      "\"wpa_akms\":%u,\"wpa_ciphers\":%u,\"rsn_akms\":%u,\"rsn_ciphers\":%u,\"owe_transition\":%d}",
      static_cast<std::uint64_t>(clock_.now()),origin_==Origin::LiveRadio?"live":origin_==Origin::Demo?"demo":"imported",unsigned(frames),
      s.has_security?"true":"false",int(s.coverage),int(v.face),int(v.overlay),s.security_historical?"true":"false",static_cast<std::uint64_t>(s.age_ms),
      s.incidents[0]?"true":"false",unsigned(burst.count),s.incidents[1]?"true":"false",s.incidents[2]?"true":"false",v.incident_visible?"true":"false",int(v.incident.kind),
      unsigned(s.last_coverage.dropped_in_window),int(s.settings.mode),int(s.settings.pmf),unsigned(selected_advertisements),unsigned(watched_advertisements),unsigned(association_frames),
      static_cast<std::uint64_t>(burst.acquired.at),unsigned(disconnect_.in_window({clock_.epoch(),clock_.now(),true})),
      unsigned(accepted),unsigned(invalid),unsigned(drops),listening?"true":"false",hopping?"true":"false",b[0],b[1],b[2],b[3],b[4],b[5],ssid,int(s.last_security.ssid_kind),s.last_security.channel,s.last_security.rssi,
      int(s.last_security.parse),a.privacy_valid?"true":"false",a.privacy_bit?"true":"false",int(a.wpa.state),int(a.rsn.state),a.wpa.akms.kinds,a.wpa.pairwise.kinds,a.rsn.akms.kinds,a.rsn.pairwise.kinds,int(a.owe_transition));
    if(n<0 || std::size_t(n)>=cap)return 0;
    // G16E: per-detector counters, the air meter and the current area observations.
    std::size_t used=static_cast<std::size_t>(n)-1;   // overwrite the closing brace
    const auto put=[&](const char* format,auto... args)->bool{
        if(used>=cap)return false;
        const int w=std::snprintf(out+used,cap-used,format,args...);
        if(w<0 || std::size_t(w)>=cap-used)return false;
        used+=static_cast<std::size_t>(w);return true;
    };
    const Instant now{clock_.epoch(),clock_.now(),true};
    bool ok=put("%s",",\"detectors\":[");
    for(std::size_t i=0;ok && i<registry_.size();++i) {
        const auto r=registry_.at(i)->report(now);
        ok=put("%s{\"name\":\"%s\",\"family\":\"%s\",\"scope\":\"%s\",\"frames\":%u,\"in_window\":%u,\"events\":%u,\"incidents\":%u,"
               "\"configured\":%s,\"window_ms\":%u,\"last_incident_ms\":%lld,\"cooldown_ms\":%u}",
               i?",":"",r.name,family_key(r.family),scope_key(r.scope),unsigned(r.frames_seen),unsigned(r.events_in_window),unsigned(r.events_total),
               unsigned(r.incidents),r.configured?"true":"false",unsigned(r.window_ms),
               r.last_incident_known?static_cast<long long>(r.last_incident_age_ms):-1LL,unsigned(r.cooldown_remaining_ms));
    }
    const auto rates=air_.rates(now);
    ok=ok && put("],\"air\":{\"known\":%s,\"probes\":%u,\"beacons\":%u,\"transmitters\":%u,\"saturated\":%s,\"window_ms\":%u},\"area\":[",
                 rates.known?"true":"false",unsigned(rates.probes),unsigned(rates.beacons),unsigned(rates.transmitters),
                 rates.transmitters_saturated?"true":"false",unsigned(rates.window_ms));
    bool first=true;
    for(std::size_t i=0;ok && i<area_slots;++i) {
        if(!s.area_visible[i])continue;
        const auto& o=s.area[i];
        ok=put("%s{\"family\":\"%s\",\"pattern\":\"%s\",\"count\":%u,\"window_ms\":%u,\"threshold\":%u,\"sources\":%u,\"random\":%s,\"saturated\":%s,\"shapes\":%u,\"age_ms\":%llu}",
               first?"":",",family_key(o.family),pattern_key(o.pattern),unsigned(o.count),unsigned(o.window_ms),unsigned(o.threshold),unsigned(o.distinct_sources),
               o.sources_random?"true":"false",o.saturated?"true":"false",unsigned(o.shapes),static_cast<unsigned long long>(clock_.now()-o.acquired.at));
        first=false;
    }
    // G16F: the current network-scope pattern (red), if any.
    const auto& np=s.evidence[static_cast<std::size_t>(IncidentKind::NetworkPattern)];
    const bool np_on=s.incidents[static_cast<std::size_t>(IncidentKind::NetworkPattern)];
    ok=ok && put("],\"area_visible_ms\":%u,\"network_pattern\":%s,\"network_pattern_name\":\"%s\",\"network_pattern_count\":%u,"
                 "\"network_pattern_shapes\":%u,\"burst_shapes\":%u,\"burst_threshold\":%u}",
                 unsigned(s.area_visible_ms),np_on?"true":"false",pattern_key(np_on?np.pattern:Pattern::None),unsigned(np_on?np.count:0),
                 unsigned(np_on?np.shapes:0),unsigned(s.incidents[0]?burst.shapes:0),unsigned(s.incidents[0]?burst.threshold:0));
    return ok?used:0;
}
// ---- G16E -------------------------------------------------------------------------------
const char* family_key(DetectorFamily f) {
    switch(f){
    case DetectorFamily::Disconnect:return "disconnect";case DetectorFamily::Baseline:return "baseline";
    case DetectorFamily::Probe:return "probe";case DetectorFamily::Beacon:return "beacon";
    case DetectorFamily::Responder:return "responder";case DetectorFamily::Auth:return "auth";
    case DetectorFamily::ChannelSwitch:return "channel_switch";case DetectorFamily::Identity:return "identity";
    case DetectorFamily::Jamming:return "jamming";
    case DetectorFamily::Bluetooth:return "bluetooth";
    case DetectorFamily::Count:break;
    }
    return "?";
}
const char* scope_key(IncidentScope s) { return s==IncidentScope::Area?"area":"network"; }
const char* pattern_key(Pattern p) {
    switch(p){
    case Pattern::None:return "none";
    case Pattern::ProbeFloodRandom:return "probe_flood_random";case Pattern::ProbeFloodSource:return "probe_flood_source";
    case Pattern::ProbeFloodName:return "probe_flood_name";case Pattern::BeaconFlood:return "beacon_flood";
    case Pattern::ManyNames:return "many_names";case Pattern::AuthFlood:return "auth_flood";
    case Pattern::SaeCommitFlood:return "sae_commit_flood";case Pattern::AssocSleep:return "assoc_sleep";
    case Pattern::ChannelSwitch:return "channel_switch";case Pattern::QuietOrder:return "quiet_order";
    case Pattern::NameMismatch:return "name_mismatch";case Pattern::MarkedBeacon:return "marked_beacon";
    case Pattern::OpenTwin:return "open_twin";case Pattern::DeauthSource:return "deauth_source";
    case Pattern::DeauthPair:return "deauth_pair";case Pattern::DeauthBroadcast:return "deauth_broadcast";
    case Pattern::NameRotation:return "name_rotation";case Pattern::OpenLure:return "open_lure";
    case Pattern::PmkidHarvest:return "pmkid_harvest";case Pattern::FakeM1:return "fake_m1";
    case Pattern::DeauthHandshake:return "deauth_handshake";case Pattern::FrameLoss:return "frame_loss";
    case Pattern::KarmaAnswer:return "karma_answer";case Pattern::LurePortal:return "lure_portal";
    case Pattern::NoiseFloor:return "noise_floor";
    case Pattern::PairingPopupFlood:return "pairing_popup_flood";case Pattern::FastPairRotation:return "fast_pair_rotation";
    case Pattern::Count:break;
    }
    return "?";
}
bool Monitor::set_limits(const DetectorLimits& l) {
    const auto same=l.max_tracked_sources==limits_.max_tracked_sources && l.max_approved_aps==limits_.max_approved_aps
        && l.window_ms==limits_.window_ms && l.cooldown_ms==limits_.cooldown_ms && l.burst_threshold==limits_.burst_threshold
        && l.dedupe_ms==limits_.dedupe_ms && l.change_threshold==limits_.change_threshold && l.max_window_events==limits_.max_window_events
        && l.shape_frames==limits_.shape_frames && l.shape_run==limits_.shape_run;
    if(same)return disconnect_.configured() && baseline_.configured();
    // Validate on scratch detectors first so a refused value never leaves the live ones unconfigured.
    DisconnectDetector d(scope_,l);BaselineDetector b(scope_,l);
    if(!d.configured() || !b.configured())return false;
    limits_=l;disconnect_.configure(l);baseline_.configure(l);return true;
}
AirRates Monitor::air() const { return air_.rates({clock_.epoch(),clock_.now(),true}); }
Radar Monitor::radar() const {
    Radar r{};r.known=true;
    const Instant now{clock_.epoch(),clock_.now(),true};
    for(std::size_t i=0;i<registry_.size();++i) {
        const auto rep=registry_.at(i)->report(now);
        if(!rep.configured || rep.family>=DetectorFamily::Count)continue;
        auto& f=r.families[static_cast<std::size_t>(rep.family)];
        if(!f.registered)f.scope=rep.scope;
        f.registered=true;f.events+=rep.events_total;
        f.pulse=f.pulse || (rep.last_event_known && rep.last_event_age_ms<Radar::pulse_ms);
    }
    const auto s=core_.snapshot();
    for(std::size_t k=0;k<s.incidents.size();++k) if(s.incidents[k]) {
        const auto kind=static_cast<IncidentKind>(k);
        const auto fam=kind==IncidentKind::NetworkPattern?s.evidence[k].family   // G16F: the pattern's own family
            :kind==IncidentKind::DisconnectBurst?DetectorFamily::Disconnect:DetectorFamily::Baseline;
        if(fam>=DetectorFamily::Count)continue;
        r.families[static_cast<std::size_t>(fam)].active=true;
    }
    for(std::size_t i=0;i<area_slots;++i) if(s.area_visible[i] && s.area[i].family<DetectorFamily::Count)
        r.families[static_cast<std::size_t>(s.area[i].family)].active=true;
    r.air=air_.rates(now);
    return r;
}
std::size_t Monitor::status_text(char* out, std::size_t cap) const {
    if(!out || !cap)return 0;
    std::size_t used=0;
    const auto put=[&](const char* format,auto... args)->bool{
        const int w=std::snprintf(out+used,cap-used,format,args...);
        if(w<0 || std::size_t(w)>=cap-used)return false;
        used+=static_cast<std::size_t>(w);return true;
    };
    const Instant now{clock_.epoch(),clock_.now(),true};
    bool ok=put("%s"," detectors=");
    for(std::size_t i=0;ok && i<registry_.size();++i) {
        const auto r=registry_.at(i)->report(now);
        char last[16];
        if(r.last_incident_known)std::snprintf(last,sizeof last,"%us",unsigned(r.last_incident_age_ms/1000));else std::snprintf(last,sizeof last,"none");
        ok=put("%s%s:frames=%u,in_window=%u,events=%u,incidents=%u,last=%s,cooldown=%u%s",i?";":"",r.name,unsigned(r.frames_seen),
               unsigned(r.events_in_window),unsigned(r.events_total),unsigned(r.incidents),last,unsigned((r.cooldown_remaining_ms+999)/1000),
               r.configured?"":",unconfigured");
    }
    const auto a=air_.rates(now);
    std::size_t visible=0;const auto s=core_.snapshot();for(bool v:s.area_visible)visible+=v;
    if(a.known)ok=ok && put(" air=probes:%u,beacons:%u,tx:%u%s,window_s:%u",unsigned(a.probes),unsigned(a.beacons),unsigned(a.transmitters),
                           a.transmitters_saturated?"+":"",unsigned(a.window_ms/1000));
    else ok=ok && put("%s"," air=none");
    ok=ok && put(" area_visible=%u",unsigned(visible));
    // G16R: addresses heard advertising the picked name besides the selected / approved ones (bounded set).
    ok=ok && put(" same_name=%u same_name_evicted=%u",unsigned(scope_.same_name_count()),unsigned(scope_.same_name_evictions()));
    if(!ok){out[0]=0;return 0;}
    return used;
}
// ---- G16S -------------------------------------------------------------------------------
LastBurst Monitor::last_burst(IncidentScope scope) const {
    const Instant now{clock_.epoch(),clock_.now(),true};
    if(scope==IncidentScope::Area)return threats_.deauth.last_burst(IncidentScope::Area,now);
    const LastBurst burst=disconnect_.last_burst(now),pair=threats_.deauth.last_burst(IncidentScope::Network,now);
    return pair.known && (!burst.known || pair.incident_at>burst.incident_at)?pair:burst;
}
std::size_t burst_record(const LastBurst& b, char* out, std::size_t cap, std::size_t tuples) {
    if(!out || !cap)return 0;
    std::size_t used=0;
    const auto put=[&](const char* format,auto... args)->bool{
        const int w=std::snprintf(out+used,cap-used,format,args...);
        if(w<0 || std::size_t(w)>=cap-used)return false;
        used+=static_cast<std::size_t>(w);return true;
    };
    bool ok=true;
    if(!b.known)ok=put("%s","none");
    else {
        // The G06 burst has no Pattern; the pattern rules print their STATUS / JSON key.
        ok=put("rule:%s,total:%u,unlisted:%u,tuples:%u,",b.rule==Pattern::None?"burst":pattern_key(b.rule),unsigned(b.total),unsigned(b.unlisted),unsigned(b.tuples));
        if(b.own)ok=ok && put("own:%u,",unsigned(b.own));   // G16T: frames of a nearby burst that named the picked network
        if(b.age_known)ok=ok && put("age_s:%llu,",static_cast<unsigned long long>(b.age_ms/1000));
        else ok=ok && put("%s","age_s:unknown,");
        ok=ok && put("open:%d,top:",b.open?1:0);
        const std::size_t held=std::min<std::size_t>(b.tuples,b.top.size());
        std::size_t printed=0;
        for(std::size_t i=0;ok && i<held;++i) {
            const auto& t=b.top[i];const auto& r=t.receiver;const auto& s=t.sender;const auto& a=t.bssid;
            if(i>=tuples && !t.own)continue;   // G16T: a tuple naming the picked network is printed wherever it ranks
            ok=put("%s%02x%02x%02x%02x%02x%02x/%02x%02x%02x%02x%02x%02x/%02x%02x%02x%02x%02x%02x/%u:%u%s",printed?";":"",
                   r[0],r[1],r[2],r[3],r[4],r[5],s[0],s[1],s[2],s[3],s[4],s[5],a[0],a[1],a[2],a[3],a[4],a[5],unsigned(t.channel),unsigned(t.count),
                   t.own?":own":"");
            ++printed;
        }
        if(ok && !printed)ok=put("%s","-");
    }
    if(!ok){out[0]=0;return 0;}
    return used;
}
std::size_t Monitor::burst_text(char* out, std::size_t cap) const {
    if(!out || !cap)return 0;
    out[0]=0;
    std::size_t used=0;
    const auto part=[&](const char* key,IncidentScope scope)->bool{
        const int w=std::snprintf(out+used,cap-used," %s=",key);
        if(w<0 || std::size_t(w)>=cap-used)return false;
        used+=static_cast<std::size_t>(w);
        const std::size_t n=burst_record(last_burst(scope),out+used,cap-used,burst_status_tuples);
        used+=n;return n>0;
    };
    if(!part("last_burst_network",IncidentScope::Network) || !part("last_burst_area",IncidentScope::Area)){out[0]=0;return 0;}
    return used;
}
} // namespace guardian::measurement

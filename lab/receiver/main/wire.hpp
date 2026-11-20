#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
namespace grx {
constexpr std::size_t max_frame=1536,header_size=56,max_packet=header_size+max_frame+4;
struct Record {
 std::uint8_t kind{},flags{},channel{},rx_state{};
 std::uint64_t boot{},acquired_us{};
 std::uint32_t sequence{},radio_us{},received{},drops{},bad{},fcs{};
 std::uint16_t reported{},size{};
 std::int8_t rssi{},noise{};
 std::uint8_t payload[max_frame]{};
};
inline std::uint32_t crc32(const std::uint8_t* p,std::size_t n){
 std::uint32_t c=0xffffffff;
 for(std::size_t i=0;i<n;++i){c^=p[i];for(int j=0;j<8;++j)c=(c>>1)^((0u-(c&1u))&0xedb88320u);}
 return ~c;
}
inline void put(std::uint8_t* p,std::uint64_t v,std::size_t n){for(std::size_t i=0;i<n;++i)p[i]=static_cast<std::uint8_t>(v>>(i*8));}
inline std::size_t encode(const Record& r,std::uint8_t* p,std::size_t capacity){
 if(r.size>max_frame||capacity<header_size+r.size+4)return 0;
 std::memset(p,0,header_size);std::memcpy(p,"GRX1",4);p[4]=1;p[5]=r.kind;p[6]=r.flags;p[7]=r.channel;
 put(p+8,r.boot,8);put(p+16,r.sequence,4);put(p+20,r.acquired_us,8);put(p+28,r.radio_us,4);
 put(p+32,r.reported,2);put(p+34,r.size,2);p[36]=static_cast<std::uint8_t>(r.rssi);p[37]=static_cast<std::uint8_t>(r.noise);p[38]=r.rx_state;
 put(p+40,r.received,4);put(p+44,r.drops,4);put(p+48,r.bad,4);put(p+52,r.fcs,4);std::memcpy(p+header_size,r.payload,r.size);
 const auto n=header_size+r.size;put(p+n,crc32(p,n),4);return n+4;
}
enum class Verb { Invalid,Info,Start,Stop,Sync };
struct Command {Verb verb{Verb::Invalid};int channel{},seconds{};std::uint32_t nonce{};};
inline Command parse_command(const char* s){
 if(!std::strncmp(s,"sync ",5)){
  const char* p=s+5;std::uint32_t nonce=0;int digits=0;
  while(*p>='0'&&*p<='9'){if(++digits>9)return {};nonce=nonce*10+static_cast<unsigned>(*p++-'0');}
  if(!digits||*p)return {};
  return {Verb::Sync,0,0,nonce};
 }
 if(!std::strcmp(s,"info"))return {Verb::Info,0,0};
 if(!std::strcmp(s,"stop"))return {Verb::Stop,0,0};
 // Bounded decimal parse: do not pass attacker-controlled huge integers to scanf.
 if(std::strncmp(s,"start ",6))return {};
 const char* p=s+6;int values[2]{};
 for(int i=0;i<2;++i){
  int digits=0;
  while(*p>='0'&&*p<='9'){if(++digits>3)return {};values[i]=values[i]*10+(*p++-'0');}
  if(!digits)return {};
  if(i==0){if(*p++!=' ')return {};}
 }
 if(*p||values[0]<1||values[0]>14||values[1]<1||values[1]>300)return {};
 return {Verb::Start,values[0],values[1]};
}
}

// Qualification decoder linked to the real Guardian parser. Input is imported
// capture evidence; this program does not assert live detector/core acceptance.
#include "guardian/security_parser.hpp"
#include <array>
#include <iostream>
#include <sstream>
#include <string>
int main(){
 guardian::SecurityFrameParser parser;char line[3400];
 while(std::cin.getline(line,sizeof line)){
  unsigned reported,channel,state,truncated;std::string hex,extra;std::istringstream in(line);
  if(!(in>>reported>>channel>>state>>truncated>>hex)||in>>extra||reported>4095||channel<1||channel>14||state>255||truncated>1||hex.size()>3072||hex.size()%2)return 2;
  std::array<std::uint8_t,1536> data{};
  auto nibble=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;};
  for(std::size_t i=0;i<hex.size()/2;++i){int a=nibble(hex[2*i]),b=nibble(hex[2*i+1]);if(a<0||b<0)return 2;data[i]=static_cast<std::uint8_t>((a<<4)|b);}
  guardian::RxMeta meta{};meta.origin=guardian::Origin::Imported;meta.channel=static_cast<std::uint8_t>(channel);meta.reported_length=static_cast<std::uint16_t>(reported);meta.status=state?guardian::RxStatus::DriverError:guardian::RxStatus::Ok;
  auto r=parser.parse({data.data(),static_cast<std::uint16_t>(hex.size()/2),truncated!=0},meta);
  std::cout<<"{\"advertised_channel\":"<<static_cast<unsigned>(r.settings.ds_channel)<<",\"advertised_channel_known\":"<<(r.settings.ds_channel_present?"true":"false")<<",\"kind\":"<<static_cast<unsigned>(r.kind)<<",\"status\":"<<static_cast<unsigned>(r.status)<<",\"error\":"<<static_cast<unsigned>(r.error)<<",\"header_valid\":"<<(r.header_valid?"true":"false")<<",\"settings_complete\":"<<(r.settings_complete?"true":"false")<<",\"origin\":\"imported\",\"bssid_hex\":\"";
  const char* digits="0123456789abcdef";for(auto byte:r.identity.bssid)std::cout<<digits[byte>>4]<<digits[byte&15];
  std::cout<<"\",\"ssid_hex\":\"";for(std::size_t i=0;i<r.identity.ssid_size;++i){auto byte=r.identity.ssid[i];std::cout<<digits[byte>>4]<<digits[byte&15];}std::cout<<"\"}\n";
 }
 return std::cin.eof()?0:2;
}

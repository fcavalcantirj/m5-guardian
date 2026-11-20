#pragma once
#include <cstdint>
#include <cstring>
namespace gclient {
enum class Verb { Invalid, Info, Stop, Join };
struct Command { Verb verb{Verb::Invalid}; std::uint8_t bssid[6]{},ssid[33]{},password[64]{}; unsigned channel{},seconds{}; };
inline int nibble(char c) { if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1; }
inline unsigned hex(const char* p,std::uint8_t* out,unsigned cap) {
 auto n=std::strlen(p);if(!n||n%2||n>2*cap)return 0;
 for(unsigned i=0;i<n/2;++i){int a=nibble(p[2*i]),b=nibble(p[2*i+1]);if(a<0||b<0)return 0;out[i]=static_cast<std::uint8_t>(a*16+b);}return n/2;
}
inline unsigned number(const char* p,unsigned cap){unsigned n=0;if(!*p)return 0;for(;*p;++p){if(*p<'0'||*p>'9')return 0;unsigned d=*p-'0';if(n>(cap-d)/10)return 0;n=n*10+d;if(n>cap)return 0;}return n;}
inline void wipe(void* p,unsigned n){auto v=static_cast<volatile unsigned char*>(p);while(n--)*v++=0;}
inline Command parse(const char* s) {
 Command out{};if(!s)return out;
 if(std::strcmp(s,"info")==0){out.verb=Verb::Info;return out;}
 if(std::strcmp(s,"stop")==0){out.verb=Verb::Stop;return out;}
 if(std::strncmp(s,"join ",5)!=0||std::strlen(s)>=256)return out;
 char tmp[256]{};std::strcpy(tmp,s+5);char* words[5]{};char* p=tmp;bool valid=true;
 for(unsigned i=0;i<5;++i){words[i]=p;char* space=std::strchr(p,' ');if(i<4){if(!space||space==p){valid=false;break;}*space=0;p=space+1;}else if(space||!*p)valid=false;}
 if(valid){
  auto m=hex(words[0],out.bssid,6);auto n=hex(words[2],out.ssid,32);auto k=hex(words[3],out.password,63);
  out.channel=number(words[1],13);out.seconds=number(words[4],90);
  bool nonzero=false;for(auto v:out.bssid)nonzero|=v!=0;
  valid=m==6&&nonzero&&!(out.bssid[0]&1)&&n>0&&k>=8&&out.channel>0&&out.seconds>0;
  // This lab adapter accepts printable passphrases; SSID remains exact bytes.
  for(unsigned i=0;i<k;++i)if(out.password[i]<32||out.password[i]>126)valid=false;
  // SDK STA config uses a NUL-terminated SSID below 32 bytes; reject embedded NUL.
  for(unsigned i=0;i<n;++i)if(!out.ssid[i])valid=false;
 }
 wipe(tmp,sizeof tmp);if(!valid){wipe(&out,sizeof out);return {};}
 out.verb=Verb::Join;return out;
}
}

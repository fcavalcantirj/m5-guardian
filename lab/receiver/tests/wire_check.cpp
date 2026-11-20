#include "wire.hpp"
#include <cassert>
#include <iostream>
int main(){
 using namespace grx;
 assert(crc32(reinterpret_cast<const std::uint8_t*>("123456789"),9)==0xcbf43926);
 assert(parse_command("start 6 20").verb==Verb::Start);
 for(const char* s:{"start 0 20","start 6 301","start 6 20 x","start 6 20\n","start 999999999999999999999999 1","start 1","start  1 2","start -1 2","start 1 0","start 1 1.5"})assert(parse_command(s).verb==Verb::Invalid);
 assert(parse_command("sync 42").verb==Verb::Sync);assert(parse_command("sync 42").nonce==42);assert(parse_command("sync 1000000000").verb==Verb::Invalid);assert(parse_command("sync 42 x").verb==Verb::Invalid);
 assert(parse_command("stop").verb==Verb::Stop);assert(parse_command("info").verb==Verb::Info);
 Record r{};r.kind=1;r.flags=5;r.channel=6;r.boot=123;r.sequence=7;r.acquired_us=900000;r.radio_us=4000;r.reported=28;r.size=24;r.rssi=-40;r.noise=-95;r.received=9;r.drops=1;r.payload[0]=0x80;r.fcs=crc32(r.payload,r.size);
 std::uint8_t b[max_packet+1]{};b[max_packet]=0x55;
 assert(encode(r,b,10)==0);auto n=encode(r,b,max_packet);assert(n==84);assert(b[max_packet]==0x55);
 std::cout<<"GRX1 ";const char* h="0123456789abcdef";for(std::size_t i=0;i<n;++i)std::cout<<h[b[i]>>4]<<h[b[i]&15];std::cout<<'\n';
 r.size=1537;assert(encode(r,b,max_packet)==0);
}

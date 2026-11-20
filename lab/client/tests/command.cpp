#include "command.hpp"
#include <cassert>
#include <string>
#include <iostream>
int main(){
 using namespace gclient;
 assert(parse("info").verb==Verb::Info);
 assert(parse("stop").verb==Verb::Stop);
 const std::string base="join 02aabbccddee 13 4c6162 7465737431323334 ";
 auto c=parse((base+"60").c_str());
 assert(c.verb==Verb::Join && c.channel==13 && c.seconds==60);
 assert(c.bssid[0]==2 && std::strcmp((char*)c.ssid,"Lab")==0);
 assert(std::strcmp((char*)c.password,"test1234")==0);
 for(const char* t:{"0","91","-1","1junk","999999999999999999999","60 extra"})assert(parse((base+t).c_str()).verb==Verb::Invalid);
 for(const char* t:{"info extra","stop extra","join 01aabbccddee 1 41 7465737431323334 5","join 000000000000 1 41 7465737431323334 5","join 02aabbccddee 14 41 7465737431323334 5","join 02aabbccddee 0 41 7465737431323334 5","join 02aabbccddee 1 4 7465737431323334 5","join 02aabbccddee 1 41 00 5","join 02aabbccddee 1 41 7465737431323300 5","join 02aabbccddee 1 zz 7465737431323334 5",""," join 02aabbccddee 1 41 7465737431323334 5"})assert(parse(t).verb==Verb::Invalid);
 assert(parse(("join 02aabbccddee 1 "+std::string(66,'4')+" 7465737431323334 5").c_str()).verb==Verb::Invalid);
 std::cout<<"bounded client command checks passed\n";
}

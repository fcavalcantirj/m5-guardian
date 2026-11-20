#include "transfer.hpp"
#include <cassert>
int main(){
 sticks3::Transfer t;unsigned submitted=0,waited=0;
 assert(t.writable());
 assert(t.present([&](){++submitted;assert(!t.writable());return true;},[&](){++waited;assert(!t.writable());return true;}));
 assert(t.writable()&&submitted==1&&waited==1);
 assert(!t.present([](){return true;},[](){return false;}));assert(!t.writable());
 assert(!t.present([&](){++submitted;return true;},[](){return true;}));assert(submitted==1);
 sticks3::Transfer failed;assert(!failed.present([](){return false;},[&](){++waited;return true;}));assert(waited==1&&!failed.writable());
}

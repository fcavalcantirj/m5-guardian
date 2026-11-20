// Host check for the measurement screen redraw schedule (G13 stale-on-screen timing).
// Build: c++ -std=c++17 -fsanitize=address,undefined -I boards/sticks3/main -I components/guardian_core/include boards/sticks3/tests/redraw_check.cpp
#include "redraw.hpp"
#include <cassert>
#include <cstdio>
int main(){
 using sticks3::RedrawSchedule;using guardian::Millis;
 constexpr Millis fresh=29000;
 RedrawSchedule r;
 assert(r.due(0));                                   // first frame immediately
 r.drawn(1000,true,100,fresh);                       // fresh sample, 100 ms old
 assert(!r.due(1001)&&!r.due(1249));
 assert(r.due(1250));                                // normal 250 ms cadence
 r.drawn(29800,true,28800,fresh);                    // stale due at 29800+200 = 30000
 assert(!r.due(29999));
 assert(r.due(30000));                               // exactly at the deadline, not up to 250 ms later
 r.drawn(30000,true,29000,fresh);                    // drawn stale: no extra deadline
 assert(!r.due(30001)&&r.due(30250));
 r.drawn(40000,false,0,fresh);                       // no security yet: cadence only
 assert(!r.due(40249)&&r.due(40250));
 r.drawn(50000,true,0,fresh);                        // brand-new sample: deadline = now + fresh
 assert(r.due(50250));r.drawn(50250,true,250,fresh);assert(r.due(79000)||r.due(50500));
 RedrawSchedule e;e.drawn(100,true,28999,fresh);assert(!e.due(100)&&e.due(101)); // 1 ms before expiry
 std::puts("redraw schedule checks passed");
}

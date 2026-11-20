#pragma once
namespace sticks3 {
// Application-task ownership. An ISR only signals the external wait primitive.
// A failed/uncertain submission or timeout retains the buffer until reboot.
class Transfer {
 enum class State {Writable,Pending,Fault};State state_{State::Writable};
public:
 bool writable()const{return state_==State::Writable;}
 template<class Submit,class Wait>bool present(Submit submit,Wait wait){
  if(!writable())return false;
  state_=State::Pending;
  if(!submit() || !wait()){state_=State::Fault;return false;}
  state_=State::Writable;return true;
 }
};
}

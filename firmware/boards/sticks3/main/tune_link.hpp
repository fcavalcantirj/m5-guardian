#pragma once
// G16C rework (5): the network side of a TUNE session over Wi-Fi. A small task
// on core 0 hands the commands of the verified, signed offer (G22A: the list is
// inside the signature; nothing else is fetched) one at a time to the main loop
// (which owns TUNE, STATUS and the screen) and posts each reply back. The main loop never blocks on the network: it polls take_command() and
// events. Policy (what is accepted, when the session ends) is the portable
// guardian::tune::wifi::Session in the main loop; this file only moves bytes.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include "session.hpp"
#include "ota_board.hpp"

namespace sticks3 {

class TuneLink {
public:
    // Starts the task on an already joined transport. False: task not created.
    bool start(ota::WifiTransport& net, const guardian::tune::wifi::Offer& offer);
    bool running() const { return running_.load(); }
    // Main loop: a pending command (copied into out), at most once per command.
    bool take_command(char* out, std::size_t capacity);
    // Main loop: the reply to the command last taken is written into
    // reply_buffer() (kMaxReply bytes, PSRAM) and handed over with give_reply(n).
    char* reply_buffer() { return reply_; }
    void give_reply(std::size_t n);
    // Network results since the last call: successful and failed reply posts, and the list finished.
    struct Events { std::uint32_t ok{}, failed{}; bool done{}; };
    Events events();
    // Ask the task to send the end report and exit (non-blocking).
    void stop(guardian::tune::wifi::End why) { why_.store(static_cast<std::uint8_t>(why)); stop_.store(true); }
    // The task has exited; the transport is free again (the caller leaves the network).
    bool done() const { return started_ && !running_.load(); }
    void reset() { started_ = false; }
private:
    static void entry(void*);
    void loop();
    ota::WifiTransport* net_{};
    guardian::tune::wifi::Offer offer_{};
    std::atomic<bool> running_{false}, stop_{false}, command_ready_{false}, reply_ready_{false}, done_{false};
    std::atomic<std::uint8_t> why_{0};
    std::atomic<std::uint32_t> ok_{0}, failed_{0};
    bool started_{};
    char command_[guardian::tune::wifi::kMaxCommand + 1]{};
    char* reply_{};   // kMaxReply bytes in PSRAM, allocated at the first session (never the internal heap)
    std::size_t reply_len_{};
};

} // namespace sticks3

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "guardian/core.hpp"
#include "guardian/identity.hpp"
#include "guardian/parser.hpp"
#include "guardian/time.hpp"

// G16J: bounded helpers shared by the detectors for the tool shapes of
// guardian/core.hpp (namespace shape) and for sliding counts. Facts about
// received bytes only: nothing here names a tool or a sender, reads a clock,
// allocates or keeps a pointer into a frame.
//
// Provenance: independent implementation of behaviour described for AntiHunter
// upstream (2026-11-17, AGPL-3.0-only; behaviour and constants as hypotheses,
// no code). The vendor prefix table is generated from the public IEEE registry
// (firmware/tools/make_oui_table.py).
namespace guardian {

// Bounded sliding counter: `slots` sub-windows of window/slots each. Slot
// numbers are 32-bit: with the minimum 100 ms window (20 ms slots) they wrap
// after ~2.7 years of one boot's monotonic time.
struct SlotCount {
    static constexpr std::size_t slots = 5;
    std::array<std::uint32_t, slots> id{};   // slot number + 1 (0 = unused)
    std::array<std::uint32_t, slots> n{};
    void add(Millis at, Millis window, std::uint32_t k = 1);
    std::uint32_t sum(Millis at, Millis window) const;
    void clear() { id.fill(0); n.fill(0); }
};

// Half of a count threshold, rounded up, never below 1 (the "shape matched" threshold).
constexpr std::uint32_t halved(std::uint32_t threshold) { return threshold <= 1 ? 1 : (threshold + 1) / 2; }

// Per-frame shapes of one deauthentication / disassociation frame:
// DisconnectFixedSequence (reason 2 with sequence control 0xFFF0) and
// DisconnectFixedDuration (reason 7 with Duration 0x013A). The reason is read
// only when the parser marked it readable on an unprotected frame; a Protected
// frame never shows a per-frame shape. 0 for every other frame kind.
std::uint16_t disconnect_frame_shapes(const ParseResult&);

// Run shapes of disconnect frames, per transmitter (Address 2), bounded:
//   RisingSequence   `run` frames in a row from one transmitter to ONE
//                    destination whose sequence numbers each rise by exactly 1
//                    (an AP telling each of its clients goodbye once has a
//                    different destination every frame and never makes a run);
//   KindAlternation  `run` changes between deauthentication and disassociation
//                    from one transmitter.
// A run not continued within `window` starts over. When all `capacity`
// transmitters are in use the one heard longest ago is replaced.
class DisconnectRuns {
public:
    static constexpr std::size_t capacity = 4;
    // The run shapes that hold at this frame (0 when none, or run == 0).
    std::uint16_t observe(const ParseResult& p, Millis at, std::uint32_t run, Millis window);
    void clear() { runs_.fill(Run{}); }
private:
    struct Run {
        Mac tx{}, to{};
        std::uint16_t sequence{};
        std::uint8_t kind{};
        std::uint32_t rising{};        // frames in the current +1 run (1 = just started)
        std::uint32_t alternations{};  // kind changes in the current run
        Millis last{};
        bool used{};
    };
    std::array<Run, capacity> runs_{};
};

// Which shapes are current for one counted key (a BSSID, a transmitter, a
// pair): per-frame shapes need `min_frames` shaped frames inside the window,
// run shapes hold for one window after the frame that showed them.
struct ShapeWindow {
    SlotCount frames{};         // frames that showed a per-frame shape
    std::uint16_t bits{};       // which per-frame shapes (reset when the window has emptied)
    std::uint16_t run_bits{};
    Millis run_at{};
    void add(std::uint16_t frame_bits, std::uint16_t run, Millis at, Millis window);
    std::uint16_t current(Millis at, Millis window, std::uint32_t min_frames) const;
    void clear() { *this = ShapeWindow{}; }
};

// True when the address's first three bytes are a block the public IEEE
// registry assigns to Espressif (ESP32 / ESP8266 radio modules, the hardware
// of most pocket Wi-Fi tools and of very many ordinary home devices). Says who
// was assigned the block, never who is transmitting.
bool board_vendor(const Mac&);
// 12:34:56:78:9A:BC, a placeholder address some tool firmware transmits from.
bool template_address(const Mac&);

// ---- G16S: burst forensics ----------------------------------------------------------------
// What the last disconnect burst of one scope looked like: the tuples its frames
// carried, most frequent first. Every address is a header byte string as received
// (spoofable); the record says what was heard, never who sent it or who was hit
// for certain.
struct LastBurst {
    static constexpr std::size_t capacity = 8;
    bool known{};               // a burst reached its detector's threshold since the detector was reset
    bool open{};                // its window had not closed at the read: the numbers can still grow
    Millis incident_at{};       // acquisition time of the frame that first reached the threshold in this burst
    bool age_known{};           // filled by the detector for the instant it was asked at
    Millis age_ms{};
    Pattern rule{Pattern::None}; // which rule that was (None = the G06 disconnect burst)
    std::uint32_t total{};      // counted frames: those inside the window at incident_at plus every one until the window closed
    std::uint32_t unlisted{};   // of them, frames whose tuple has no entry (more than `capacity` tuples): the listed tuples are the most frequent kept
    // G16T: of `total`, the frames that named the picked network in Address 1, 2 or 3 (BurstTuple::own).
    // Counted only in the record of a NEARBY burst: > 0 says why that burst was reported as a Network
    // incident. The red burst and the pair rule are the picked network's from the start and leave it 0.
    std::uint32_t own{};
    std::uint8_t tuples{};      // entries used in `top`
    std::array<BurstTuple, capacity> top{};   // most frequent first; equal counts: heard most recently first
};

// The record behind LastBurst: the burst being counted, then the last finished one.
//   * begin(): a detector threshold was reached. The previous record is dropped.
//   * add(): counted disconnect frames of one tuple (after the detector's own
//     Retry-bit deduplication). The detector first adds the frames of its window
//     at the threshold, then every further counted frame for as long as the
//     burst lasts: the counts of a record never slide.
//   * settle(): the burst's window closes when a whole `window` passes without a
//     counted frame. The record is then final and stays readable until the next
//     begin().
//   * Bounded: `capacity` tuples. A new tuple when all are in use replaces the
//     one with the fewest frames (equal: the one heard longest ago); the
//     replaced frames stay in `total` and are reported as `unlisted`. A flood
//     that changes an address on every frame therefore shows as many unlisted
//     frames and tuples of one frame each, never as a made-up top address.
//   * G16T: a tuple that names the picked network (`own`) is never the one
//     replaced while a tuple that does not is listed, so a few frames at the
//     picked network stay listed inside a large nearby burst. When every listed
//     tuple names the picked network, a new tuple that does not is counted in
//     `total` / `unlisted` and takes no entry.
// No allocation, no clock read: time is the frames' acquisition time.
class BurstRecord {
public:
    static constexpr std::size_t capacity = LastBurst::capacity;
    bool live() const { return live_; }
    void begin(Millis at, Pattern rule);
    void add(const Mac& receiver, const Mac& sender, const Mac& bssid, std::uint8_t channel, Millis at, std::uint32_t frames = 1,
             bool own = false);
    // Counted frames whose tuple is not known any more; `own_frames` of them named the picked network.
    void unlisted(std::uint32_t frames, std::uint32_t own_frames = 0);
    // True when the record is final: a whole window has passed since its newest frame.
    bool settle(Millis at, Millis window);
    // G16T: the burst is still being counted at `at` (settle() without the state change).
    bool open(Millis at, Millis window) const { return live_ && (at < newest_ || at - newest_ < window); }
    std::uint32_t own() const { return own_; }   // G16T: counted frames that named the picked network
    // The most frequent tuple (count 0 = none). own_only: among the tuples naming the picked network.
    BurstTuple top(bool own_only = false) const;
    LastBurst read(Millis now, Millis window) const;   // known = false before the first begin()
    void clear() { *this = BurstRecord{}; }
private:
    struct Entry { BurstTuple tuple{}; Millis last{}; };   // tuple.count 0 = free
    std::array<Entry, capacity> entries_{};
    std::uint32_t total_{};
    std::uint32_t own_{};
    Millis incident_at_{};
    Millis newest_{};
    Pattern rule_{Pattern::None};
    bool known_{};
    bool live_{};
};

// A detector without a per-frame window of its own (AreaDisconnectDetector) keeps
// the tuples of its current window here, one table per scope:
//   * seen(): one counted disconnect frame. Before a burst the counts slide with
//     the window, in the same 5 sub-slots as SlotCount (a count covers between
//     4/5 and all of the window), so old frames leave by themselves. The table
//     holds `capacity` tuples with the replacement rule of BurstRecord.
//   * incident(): the threshold was reached at this frame. The window's tuples
//     become a BurstRecord, the table is cleared, and every further counted
//     frame goes to the record until its window closes. Called again inside the
//     same burst (another rule, a report after the cooldown) it changes nothing.
//     The detectors call it also when the report itself is suppressed by a
//     cooldown, so a second burst shortly after the first is not hidden.
//   * G16T: `own` marks a frame that named the picked network in Address 1, 2 or
//     3. own() is how many such frames the current window holds or, while a burst
//     is being counted, the whole burst so far (that count never slides).
class BurstTrace {
public:
    static constexpr std::size_t capacity = LastBurst::capacity;
    void seen(const Mac& receiver, const Mac& sender, const Mac& bssid, std::uint8_t channel, Millis at, Millis window, bool own = false);
    void incident(Millis at, Millis window, Pattern rule);
    // The most frequent tuple of the current window / burst (count 0 when there is none).
    BurstTuple top(Millis at, Millis window) const;
    // G16T: a burst that reached a threshold is still being counted at `at`.
    bool open(Millis at, Millis window) const;
    // G16T: counted frames naming the picked network, in the burst being counted at `at`, else in the current window.
    std::uint32_t own(Millis at, Millis window) const;
    // G16T: the most frequent tuple naming the picked network, of that burst / window (count 0 = none).
    BurstTuple top_own(Millis at, Millis window) const;
    // The burst still being counted, else the last finished one (known = false: none yet).
    LastBurst last(Millis now, Millis window) const;
    // G16T: the last burst that held a frame naming the picked network (known = false: none yet).
    // A later burst without such a frame replaces last() but not this one; the next burst that
    // names the picked network does.
    LastBurst last_own(Millis now, Millis window) const;
    void clear() { *this = BurstTrace{}; }
private:
    struct Entry { BurstTuple tuple{}; SlotCount sliding{}; Millis last{}; bool used{}; };
    std::array<Entry, capacity> entries_{};
    SlotCount total_{};             // every counted frame of the window
    SlotCount own_{};               // G16T: of them, the frames naming the picked network
    Millis newest_{};               // newest counted frame seen
    BurstRecord record_{};
    BurstRecord own_record_{};      // G16T: copy of record_ while that burst holds a frame naming the picked network
    void keep_own() { if (record_.live() && record_.own() > 0) own_record_ = record_; }
};

} // namespace guardian

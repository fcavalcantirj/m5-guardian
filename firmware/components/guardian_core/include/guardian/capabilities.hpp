#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "guardian/time.hpp"

// Board and radio capability contracts.
//
// Capability DATA, not board-name conditionals, tells the defense library and
// the presenter what the running hardware can do. The core never assumes a
// band, channel range, display, PSRAM or button. A headless adapter fills the
// same structure with Unsupported display/input and runs identical logic.
//
// Every optional feature is a Support tri-state. Unknown is a legal answer
// from an adapter that has not probed yet; consumers must treat Unknown as
// "cannot rely on it", never as Supported.
//
// Only standard C++ here: no SDK, pins or driver handles.
namespace guardian {

enum class Band : std::uint8_t { Ghz2_4, Ghz5, Ghz6, Count };

// A set of channel numbers per band, 256 bits per band. Channel numbers are
// the IEEE numbers (2.4 GHz 1..14, 5 GHz up to 177, 6 GHz up to 233). The
// ESP-IDF adapter derives this from the chip's country/regulatory settings at
// start; the headless/replay adapter from the fixture metadata. Header-only
// so this task adds no build units.
struct ChannelSet {
    static constexpr std::size_t words_per_band = 4;
    std::array<std::array<std::uint64_t, words_per_band>, static_cast<std::size_t>(Band::Count)> bits{};

    constexpr bool contains(Band band, std::uint8_t channel) const {
        const auto b = static_cast<std::size_t>(band);
        if (b >= bits.size()) return false;
        return (bits[b][channel / 64] >> (channel % 64)) & 1u;
    }
    constexpr void set(Band band, std::uint8_t channel) {
        const auto b = static_cast<std::size_t>(band);
        if (b < bits.size()) bits[b][channel / 64] |= (std::uint64_t{1} << (channel % 64));
    }
    constexpr bool any(Band band) const {
        const auto b = static_cast<std::size_t>(band);
        if (b >= bits.size()) return false;
        for (auto w : bits[b]) if (w) return true;
        return false;
    }
    constexpr bool empty() const {
        for (std::size_t b = 0; b < bits.size(); ++b) if (any(static_cast<Band>(b))) return false;
        return true;
    }
};

struct RadioCapabilities {
    // Physical radio capability only. Replay input is described separately;
    // accepting fixture frames never establishes passive RF reception.
    // Passive (promiscuous / monitor) reception of management frames. Without
    // Supported, Guardian cannot observe anything and must say so; it must
    // not fall back to active scanning silently (G13 decides whether a
    // scan-only mode exists and how it is labelled).
    Support passive_receive{Support::Unknown};
    // Channels this radio can listen on. Empty while Unknown.
    ChannelSet channels{};
    // Whether the adapter can retune while listening (channel hopping).
    // Hopping trades breadth for coverage gaps; CoverageReport records them.
    Support channel_hop{Support::Unknown};
    // Largest MPDU the acquisition path delivers to a FrameSpan, excluding FCS.
    // Frames longer than this arrive truncated (FrameSpan::truncated = true).
    // 0 while Unknown.
    std::uint16_t max_frame_bytes{};
    // Radio-side receive timestamp (RxMeta::radio_timestamp_us).
    Support rx_timestamp{Support::Unknown};
    // Per-frame noise floor (RxMeta::noise_floor_dbm).
    Support noise_floor{Support::Unknown};
    // Whether frames that failed FCS can be delivered at all (RxStatus::FcsError).
    // Default policy is to never enable it; the capability only states if the
    // driver could.
    Support fcs_error_delivery{Support::Unknown};
    // Whether the driver exposes an RX error state distinct from FCS.
    Support rx_error_state{Support::Unknown};
};

enum class PixelFormat : std::uint8_t { None, Rgb565, Mono1 };

struct DisplayCapabilities {
    Support present{Support::Unknown};
    std::uint16_t width{};  // logical pixels after the board's rotation
    std::uint16_t height{};
    PixelFormat format{PixelFormat::None};
    // Whether the renderer can present full frames fast enough for animation.
    // The presenter degrades to static expressions when Unsupported (G08/G21).
    Support animation{Support::Unknown};
};

enum class InputControl : std::uint8_t { Primary, Secondary, Back, Count };

struct InputCapabilities {
    // Which abstract controls exist. The board maps its physical keys to these
    // (StickS3: front key -> Primary, side key -> Secondary; no Back).
    std::array<Support, static_cast<std::size_t>(InputControl::Count)> controls{};
    Support touch{Support::Unknown};
    Support motion{Support::Unknown}; // IMU, for wake/orientation only; never evidence
};

struct BleCapabilities {
    Support present{Support::Unknown};
    Support observer{Support::Unknown};   // passive BLE scanning
    Support peripheral{Support::Unknown}; // advertising/GATT for a companion app
};

struct MemoryCapabilities {
    std::uint32_t internal_ram_bytes{};  // total internal SRAM the adapter may budget
    std::uint32_t external_ram_bytes{};  // PSRAM; 0 means none, never assumed
    // Bytes the adapter reserves for the bounded frame pool/queue. The library
    // sizes nothing itself; it only reports drops the adapter counts.
    std::uint32_t frame_pool_bytes{};
};

struct StorageCapabilities {
    Support key_value{Support::Unknown};       // settings (selected network, approved APs)
    std::uint32_t asset_bytes{};               // read-only asset region for art, 0 if none
    Support removable_media{Support::Unknown}; // SD card etc.; StickS3 reports Unsupported
};

struct BoardCapabilities {
    // Static-storage string owned by the adapter (string literal or
    // adapter-lifetime buffer). Used for logs and the about screen only;
    // business logic never branches on it.
    const char* board_name{"unknown"};
    RadioCapabilities radio{};
    DisplayCapabilities display{};
    InputCapabilities input{};
    BleCapabilities ble{};
    MemoryCapabilities memory{};
    StorageCapabilities storage{};
};

namespace profiles {

// A headless host/replay profile: no display, no input, no BLE, no storage,
// passive receive Unsupported: fixture input is not physical RF. Channels are
// whatever the replay source declares; callers set them from the fixture.
inline BoardCapabilities headless(ChannelSet channels, std::uint16_t max_frame_bytes) {
    BoardCapabilities c{};
    c.board_name = "headless";
    c.radio.passive_receive = Support::Unsupported;
    c.radio.channels = channels;
    c.radio.channel_hop = Support::Unsupported;
    c.radio.max_frame_bytes = max_frame_bytes;
    c.radio.rx_timestamp = Support::Unsupported;
    c.radio.noise_floor = Support::Unsupported;
    c.radio.fcs_error_delivery = Support::Unsupported;
    c.radio.rx_error_state = Support::Unsupported;
    c.display.present = Support::Unsupported;
    c.display.animation = Support::Unsupported;
    for (auto& s : c.input.controls) s = Support::Unsupported;
    c.input.touch = Support::Unsupported;
    c.input.motion = Support::Unsupported;
    c.ble.present = Support::Unsupported;
    c.ble.observer = Support::Unsupported;
    c.ble.peripheral = Support::Unsupported;
    c.storage.key_value = Support::Unsupported;
    c.storage.removable_media = Support::Unsupported;
    return c;
}

// Convenience: the fourteen 2.4 GHz channel numbers. Regulatory availability
// is the adapter's job; this is only the IEEE numbering.
inline ChannelSet all_2g4_channels() {
    ChannelSet s{};
    for (std::uint8_t ch = 1; ch <= 14; ++ch) s.set(Band::Ghz2_4, ch);
    return s;
}

} // namespace profiles
} // namespace guardian

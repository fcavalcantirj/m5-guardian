#pragma once
#include "measurement.hpp"
#include "sticks3_board.hpp"
namespace sticks3 {
bool draw_measurement(Board&, const guardian::Snapshot&, std::uint32_t accepted,
    std::uint32_t invalid, std::uint32_t dropped, bool listening, bool locked, std::uint8_t tuned, guardian::Millis now);
}

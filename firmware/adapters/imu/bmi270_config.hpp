#pragma once
#include <cstddef>
#include <cstdint>

// Bosch BMI270 configuration blob (BSD-3-Clause, see bmi270_config.cpp and
// THIRD_PARTY_NOTICES.md). Uploaded to INIT_DATA at every power-up.
namespace guardian::imu {
constexpr std::size_t bmi270_config_bytes = 8192;
constexpr std::uint32_t bmi270_config_crc32 = 0x229a1189u;   // from the generator (sha256 2d75e68e...178db)
extern const std::uint8_t bmi270_config_file[bmi270_config_bytes];
}

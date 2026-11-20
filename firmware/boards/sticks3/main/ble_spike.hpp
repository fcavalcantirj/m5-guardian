#pragma once
// G16H coexistence spike, board half: a PASSIVE BLE scanner on the StickS3.
// Compiled only in the spike build variant (CONFIG_GUARDIAN_BLE_SPIKE, made by
// `tools/build.sh build-ble-spike`); the normal Guardian image has no BLE stack.
//
// NimBLE runs without the broadcaster and peripheral roles (compiled out in
// sdkconfig.ble-spike; central is compiled in only because NimBLE does not build
// observer-only, and is never used), and every scan is passive: no scan request,
// no advertising, no connection. Nothing is transmitted. Advertising
// reports are counted and discarded; no address or payload is kept.
#include "sdkconfig.h"
#include "coex_spike.hpp"
#include <cstdint>

namespace sticks3::ble {
#if CONFIG_GUARDIAN_BLE_SPIKE
enum class State : std::uint8_t { Off, Starting, Ready, Failed };
const char* state_text(State);   // "off", "starting", "ready", "failed"
// Starts the controller and the NimBLE host once (first BLESPIKE start, never at boot).
bool init();
State state();
// Requests a passive scan duty (Duty{} = no scanning). Before the host has synced
// the request is kept and applied on sync. False when the controller refused it.
bool apply(const guardian::coex::Duty&);
std::uint32_t adv_reports();     // advertising reports since init (counted only)
std::uint32_t errors();          // refused scan commands and host resets
int last_error();
bool scanning();                 // ble_gap_disc_active()
#endif
} // namespace sticks3::ble

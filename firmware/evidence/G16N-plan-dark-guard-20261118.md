# Guard in the dark: screen off on battery, radio and detectors on, any new incident lights it up — "G16N"

## Context
Owner (2026-11-18 13:30): "device now has screen pitch black to save battery... BUT it should be monitoring, any deauth
packets should bring screen UP, alert. Spike this, let's do it. Otherwise the screen has to be on to guard."
Today (MEASURED in code): Active → Dim (10 % backlight, one frame a second, radio and detectors still running) → deep
sleep after `power.sleep_s` (CPU, Wi-Fi and IMU off, keys-only wake, boots like cold). So on battery the Guardian stops
guarding two minutes after it is left alone. A first ALERT brightens a dimmed screen, but a second incident while the
banner is still up does not (the idle input is one bool, `idle.cpp:102`).

## Facts (cites under firmware/)
- States Active/Dim/Sleep, holds, TUNE power.dim_s 30 / sleep_s 120 / dim_pct 10 (`adapters/power/idle.hpp:92-101`,
  `boards/sticks3/main/measurement_main.cpp:1170-1172`, applied :380-382). Step rule: any hold, motion, key or NEW alert
  = activity (`idle.cpp:108-111`); Dim→Sleep after sleep_ms, never during an ALERT (:118-119); Sleep terminal (:122).
- Monitoring runs regardless of idle state: `companion_drain`, survey retune, `load_tick`, `app->tick()`
  (`measurement_main.cpp:1365, 1384-1399, 1318, 1411`).
- Backlight: LEDC 8-bit, Active 60 %, Dim `power.dim_pct` (`measurement_main.cpp:1356-1358`, `sticks3_board.cpp:255-259`).
  `display_sleep()` revokes the canvas until reboot (`sticks3_board.cpp:318-327`): NOT usable for a dark state.
- Deep sleep teardown and keys-only ext1 wake (`idle.cpp:149-171`, `measurement_main.cpp:1020-1029`); BATTRUN logs mV once
  a minute on battery (`adapters/power/battery.cpp:173-177, 204-214`); battery 250 mAh (`docs/research/research.md:83`);
  no current draw ever measured (`README.md:321-323`).
- ALERT path: `Presenter::update` sets `view_.alert` from the first visible incident (`presenter.cpp:445-457`); the board
  reads `view().alert` (`measurement_main.cpp:1342`). No incident sequence number exists.

## Design (decided)
1. **New idle state `Dark`** (`adapters/power/idle.{hpp,cpp}`): Dim → Dark after `power.dark_s` (TUNE, default 60 s of Dim)
   when on battery. Dark = backlight 0, no frames drawn (dirty rows skipped), radio, detectors, IMU and the loop all
   running. Dark → Sleep (deep sleep, as today) only when `batt_pct <= power.dark_floor_pct` (TUNE, default 20 %) or when
   `power.sleep_s` is set to a value below `dark_s` (owner wants the old behaviour). On USB nothing changes (Hold::Usb,
   always on). Exits from Dark: a key (swallowed, like Dim), motion above the existing rest threshold, a new incident.
   Reason: the owner's ask is literal ("screen off, still guarding"); deep sleep remains the floor so an empty battery is
   not the price of guarding.
2. **Every new incident wakes the screen, not only the first.** The Snapshot/view gains an `incident_seq` (incremented by
   the Monitor on every new Network or Area incident); `gp::Inputs` gains `incident_seq`; `Idle::step` treats a changed
   seq as activity. Dark → Active → the ALERT (red) or caution (amber) paints at full brightness; the normal Dim/Dark
   countdown restarts after the banner ends (existing rule). Deauth nearby (amber) counts: the owner said "any deauth".
3. **Backlight path:** `set_backlight(0)` only (reversible). On exit, 60 % and a forced full redraw.
4. **STATUS/BATTRUN:** `power_state=dark`, `dark_s=` time in Dark, `dark_wakes=` by cause (key/motion/incident);
   BATTRUN gains a per-state drain estimate (mV per 10 min in active / dim / dark) so the trade-off is on the glass:
   Details line "dark guard: ~N h left" from the measured drain.
5. **Honesty on the glass:** entering Dark prints one dim line for 2 s "guarding in the dark, press to look"; the dim
   view's red "!" rule stays for Dim.

## Spike FIRST (recorded, firmware/evidence/sticks3-G16N-spike-<date>.log; the plan's defaults come from it)
- S1 drain: on battery, 20 min each at full-on (face, 60 %), Dim (10 %, 1 fps), Dark (backlight 0, radio on), Sleep;
  BATTRUN mV deltas → mA estimate per state and hours of guarding on 250 mAh. The Dark build is the feature itself
  behind TUNE (`power.dark_s`), so the spike runs on the first image; `tools/threat_watch.py` cannot be used on battery
  (USB resets): read BATTRUN over the self-fetch TUNE poll.
- S2 wake latency: owner's Bruce deauth against the home network while Dark; measure first-frame latency from the
  incident timestamp (STATUS `last=`) to the backlight-on log line; target ≤ 1.5 s plus the detector window.
- S3 the second incident: with the red banner up, a second deauth burst after the first banner ends must re-light.
- GO = guarding in the dark costs ≤ 150 mA (≥ 1.5 h on a full battery) and S2/S3 pass; else the plan's default is
  `power.dark_s=0` (off) with the numbers on the glass.

## Files
- Change: adapters/power/idle.{hpp,cpp} (Dark state, inputs incident_seq/batt_pct, status text), tests/idle_check.cpp
  (dark_after_dim_on_battery, dark_keeps_monitoring_inputs, a_second_incident_relights_from_dark, dark_sleeps_at_the_floor,
  usb_never_darkens, key_and_motion_leave_dark), components/guardian_core (incident_seq in Snapshot) + core tests,
  guardian_presenter (view.incident_seq), boards/sticks3/main/measurement_main.cpp (apply Dark: backlight 0, skip
  draws, forced redraw on exit, 3 TUNE keys power.dark_s / dark_floor_pct, STATUS/BATTRUN fields), firmware/README.md.
- Ledger: row G16N after G16M (HOST_BATCH), owner-approved text from this plan; G23 carry-overs unchanged.

## Verification
- Host: idle_check cases above green, core/presenter tests for incident_seq, host-check plain + ASan.
- Device (owner's kit, my hands over the self-fetch poll): the three spikes with numbers in the evidence log; the
  image lands by auto-OTA; STATUS shows `power_state=dark` while the detectors' `frames=` keep counting; a Bruce deauth
  lights the red stare from the dark within the target; the battery floor sends it to deep sleep.

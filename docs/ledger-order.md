# Guardian ledger order

Current review: G01–G08 accepted for documented host scope. See
[G08 validation](G08-validation.md). L01/L02 are accepted for the
[measured live scope](L02-live-validation.md). G09 is accepted after corrections and independent Codex approval; see
[G09 validation](G09-validation.md). G10 source/build and G11 physical bring-up are accepted; see
[G11 evidence](G11-device-validation.md). G12 is accepted; see [validation](G12-validation.md). G13 is next; order is unchanged.

The array order is the execution order. Stable IDs identify requirements. Ralph checks dependency order/readiness; G04–G08 may use pending implementation handoffs within their host batch after G01–G03 acceptance. The dependency order below puts the host live gate before new board integration.

1. Contracts and reuse decisions; identify candidate live-test equipment.
2. Host build, baseline and red/green TDD for parsing, evidence, detection and presentation.
3. Qualify live-test equipment, then **automated real RF testing from the CLI with the actual library on the host.**
4. Independent foundation review, then board integration and repeat live validation.
5. Physical UI/art, performance and final acceptance.

## Tasks

1. **G01** — Define the portable defense-library contracts and boundaries
2. **G02** — Choose reusable parsers and detector components with provenance
3. **G03** — Make the portable host build and reviewer validation harness complete
4. **G04** — Implement bounded portable Wi-Fi security-frame parsing
5. **G05** — Implement evidence freshness and the five advertised-settings ratings
6. **G06** — Implement portable disconnect and baseline-change detectors
7. **G07** — Implement evidence-based advice without overstating Wi-Fi health
8. **G08** — Implement portable presentation and interaction state before board painting
9. **L01** — Qualify host live capture and automated offensive control before writing the harness
10. **L02** — Automate live RF scenarios against the real library running on the host
11. **G09** — Review the portable foundation before proceeding to hardware
12. **G10** — Repair and integrate the existing StickS3 adapter; preserve the earlier spike
13. **G11** — Accept StickS3 bring-up on the real device after the library is ready
14. **G12** — Qualify the reviewed library across host and ESP32 target profiles
15. **G13** — Repeat the accepted host live scenarios through the real ESP32 adapter
16. **G14** — Connect the network picker, buttons and persistence to real observations
17. **G15** — Create an original, iconic Guy Fawkes-inspired 3D Guardian persona designed for the StickS3 screen
18. **G16** — Very good shows the Guardian's best possible expression: an enormous confident smile and cigar
19. **G16A** — Upright portrait platform for the standing StickS3 (USB down): clean panel edges, portrait layouts, native BMI270 IMU and live-tunable parameters
20. **G16B** — Signed over-the-air updates from the owner's Mac with automatic rollback, plus honest battery state, so the Guardian runs and updates unplugged
21. **G16C** — Every screen is the Guardian: the v2 face for every rating on top, a dense techy HUD of the real evidence below, a clean full-width header, and face and HUD that react to the IMU
22. **G16D** — Battery life: on battery the Guardian dims when left still, then deep-sleeps, and a button press wakes it
23. **G16E** — Detection platform: the parser decodes every management frame the passive detectors need, nearby threats get their own scope, and the Guardian shows them as a live threat radar
24. **G16F** — Passive management-frame threat detectors: probe floods, beacon floods, karma/MANA responders, auth/SAE/assoc floods, channel-switch abuse, SSID confusion, pwnagotchi, OWE abuse and stronger deauth detection
25. **G16G** — Passive data-path detectors: handshake-harvesting signs (PMKID harvest, fake M1, deauth followed by a fresh handshake) and frame-loss jamming, after a measured device load spike
26. **G17** — Good shows a clearly smiling, reassuring Guardian
27. **G18** — Medium shows a neutral Guardian with no smile
28. **G19** — Bad shows a concerned Guardian and a clear warning about legacy Wi-Fi settings
29. **G20** — Horrible shows the most alarmed Guardian for open or WEP configuration
30. **G16I** — Fawkes always stands upright by gravity and a real shake bursts the face into particles that reform (added 2026-11-17)
31. **G16J** — Attack coverage: every attack the owner's kit can send on 2.4 GHz proven live, evil twin on, data path on after a load spike, measured thresholds, blind spots on the glass (added 2026-11-18; see docs/attack-coverage.md)
32. **G21** — The 3D Guardian head: pre-rendered angle frames of the owner-accepted Meshy head with the original master projected on it, under 1.9 MB, chosen by the IMU (rewritten 2026-11-17)
33. **G16M** — Product setup: join the home Wi-Fi from the phone, no cable, no Mac (added 2026-11-18)
34. **G16N** — Guard in the dark: screen off on battery, radio and detectors on, every new incident lights the alert (added 2026-11-18)
35. **G16O** — Shake particles obey gravity: fall while tilting, reform only when still (added 2026-11-18)
36. **G16P** — A plugged-in Guardian wakes by itself: timer wake with a USB check (added 2026-11-18)
37. **G16R** — Your network is its name, not one address: deauth against any same-name access point is RED (added 2026-11-18)
38. **G16S** — Burst forensics: STATUS and the glass show the addresses of the last disconnect burst (added 2026-11-19)
39. **G16T** — BUG: a nearby disconnect burst that also touches the owner's network is RED (added 2026-11-19, from the G16S record)
40. **G16Q** — The approved art on the glass as close to the master as the panel allows: art bench, then the winning knobs in the Guardian (added 2026-11-18)
41. **G16H** — Deferred candidate (moved here 2026-11-17; needs the owner-run Wi-Fi/BLE coexistence spike): BLE threat observations
42. **G22** — Complete own review and independent Claude review of the integrated product
43. **G22A** — Self-fetch lane hardening: signed TUNE offers, alert-first poll, version check (from the G22 review, added 2026-11-19)
44. **G23** — Deliver a tested StickS3 Guardian with five expressive moods and honest evidence of what works

## Preserved reordering history (historical snapshot)

The original task-1 StickS3 build and flash backup stay intact as early spike evidence. G10/G11 own its repair and physical acceptance. No board was flashed by this reorganization.

G01 can be accepted only after its reviewed correction package is installed and its hashes match. Its acceptance is for contracts, not tested detector behavior. All other tasks remain false. G03 builds the missing host harness; G04-G08 provide actual TDD evidence; L02 provides automated live RF evidence. See [G01 validation](G01-validation.md).

The existing awaiting_review receipt still identifies G01 by content hash. The correction changes only G01's passes field, so the normal next invocation `./ralph-claude.sh 1` selects G02 after installation. No receipt reset or retry is needed. All prior logs remain intact.

See [roadmap](roadmap.md), [live lab plan](live-lab.md) and [Ralph rules](ralph.md). Library TDD and explicit live scenario automation are required; Ralph's own automatic verifier and auto-acceptance remain absent.

Current acceptance is in guardian-tasks.json, not the historical snapshot above.
G04–G08 now support bounded implementation batching; read [Ralph rules](ralph.md).
The runner leaves passes unchanged and stops for batch review before later phases.
45. **G16U** — DEFERRED IDEA: radio guard toggle, Wi-Fi (default) or Bluetooth, one at a time (owner thinking out loud 2026-11-19; built only on his word)

# G16H: Bluetooth LE pairing-popup spam — sources, formats, rules and limits

Status 2026-11-19: **host library only.** The classifier and the two rules are implemented and host-tested
(`firmware/components/guardian_core/ble.cpp`, `tests/ble_check.cpp`). **No BLE scan runs on the StickS3 or on any
board**: the ledger gates that on the owner-run Wi-Fi/BLE coexistence spike (`tools/build.sh build-ble-spike`,
`BLESPIKE start`), which has not been run. Nothing here is radio proof.

## 1. What the thing is

A "pairing popup" is what a phone or PC shows when a nearby accessory advertises that it wants to be paired or set up.
Tools flood those adverts so every phone in range keeps showing popups. The adverts are ordinary vendor formats; a
single one is what a real device in pairing mode sends. Only the pattern over time is unusual.

The Guardian only receives. It never transmits, scans actively or connects, never names a vendor, a tool or a sender
on the glass, and keeps no address beyond a bounded table in RAM (60 s by default). No address is linked to another,
to a device or to a person; tracker hunting is out of scope (ledger G16H).

## 2. Sources and what was read from each

| Source | Pinned | Read for | How |
|---|---|---|---|
| Google, *Fast Pair: Provider advertising* (developers.google.com/nearby/fast-pair/specifications/service/provider) | page as of 2026-11-19 | service-data UUID 0xFE2C; discoverable = 3-byte model ID; account data = version byte, key filter, salt; "the BLE address shall not rotate" while discoverable | page text |
| Microsoft, *Bluetooth Swift Pair* (learn.microsoft.com/.../bluetooth-swift-pair) | page commit `c1f3764`, dated 2022-06-09 | vendor ID 0x0006, sub-scenarios 0x00/0x01/0x02, reserved byte 0x80, optional display name at the end; no address rotation during a session; do not beacon forever | page text. The beacon ID value (0x03) and the byte offsets are in figures that were not read; 0x03 comes from the two tools below |
| Bluetooth SIG assigned numbers | — | AD types 0xFF (manufacturer data), 0x16 (service data, 16-bit UUID); company IDs Apple 0x004C, Microsoft 0x0006, Samsung 0x0075 | general knowledge, not re-fetched |
| ESP32 Marauder `esp32_marauder/WiFiScan.cpp` (GPL family; a tool in the owner's kit) | file commit `2a87164`, 2026-11-19 | the bytes it puts on air per mode, address policy, timing | partial read (three windows of the file); the "all" mode loop and the random-address generator were not read |
| Bruce `src/modules/ble/ble_spam.cpp` (AGPL-3.0; a tool in the owner's kit) | path commit `ec014ad`, 2026-11-06 (raw file not verified against that commit) | the same | read to about 85 % of the file |
| Evil-M5Project README | page as of 2026-11-19 | whether it lists popup spam | README only: it lists "BLENameFlood" and sniffing features, no popup spam by name |
| AntiHunter `c6ef921` (AGPL-3.0-only) | local checkout | **nothing**: its BLE code was not opened. Only the ledger's one-line description of its rule was used | — |

No code was copied from any of them. The byte layouts are the vendors' formats; the tools were read only to learn
which variant of each format is actually sent and how fast the address changes. Apple publishes no Continuity
specification: the record types 0x07 (proximity pairing) and 0x0F (nearby action) are as both tools use them.

## 3. Formats the classifier recognises (`parse_ble_popup`)

AD structure = length, type, payload. Offsets below are inside the payload after the company ID or UUID.

| Format | Recognised by | Product ("variant") | Seen from the tools |
|---|---|---|---|
| Apple proximity pairing | manufacturer data, company `4C 00`, record type `07`, at least 3 value bytes | value bytes 1-2 (device model) | Bruce: length 0x19, 31 bytes, 27 models. Marauder: length 0x0F, 21 bytes, 15 models |
| Apple nearby action | same, record type `0F`, at least 2 value bytes | value byte 1 (action code) | both: `0F 05 <flags> <action> + 3 random`; 15 / 9 actions |
| Samsung easy setup | company `75 00` + prefix `01 00 02 00 01 01 FF 00 00 43` (watch) or `42 09 81 02 14 15 03 21 01 09` (earbuds) | watch: next byte; earbuds: bytes 10, 11, 13 | Bruce both (48 / 30 models); Marauder watch only (17). The earbuds advert ends in a cut second structure; the first one is classified |
| Microsoft Swift Pair | company `06 00`, beacon `03`, sub-scenario 0..2, reserved byte | hash of everything after those three bytes (the name) | both: `03 00 80 <name>` |
| Google Fast Pair | service data, UUID `2C FE`, exactly 3 more bytes | the 24-bit model ID | Bruce: 82 models; Marauder: one fixed model `00B727` |

Deliberately not popup messages: Apple nearby-info (0x10), Find My (0x12), iBeacon (0x02) and every other Apple
record; Microsoft device beacons other than 0x03; Fast Pair account data (a paired device that is not in pairing
mode); other Samsung data. A structure that runs past the data, or a recognised record too short for its fields, is
counted as malformed and classifies nothing.

## 4. The two rules (`BlePopupDetector`) and their numbers

Both are Area scope (amber, "nearby"), one observation per rule per 45 s cooldown, every number a `t.ble_*` TUNE key.
The numbers are the ledger's (AntiHunter-described) or the Guardian's own and are **uncalibrated hypotheses**.

1. **Pairing-popup spam nearby** (`pairing_popup_flood`): inside `ble_popup_window_ms` (1 s), at least
   `ble_popup_messages` (3) different messages (format + product) from at least `ble_popup_sources` (3) short-lived
   addresses. Short-lived = first heard inside that window. A device that keeps its address is heard under it for
   minutes and never counts after its first second; it stays known for `ble_address_memory_ms` (60 s) after it was
   last heard. Nothing is reported during the first `ble_learn_ms` (30 s) of listening, or of listening again after a
   silence longer than the address memory.
   The ledger says "from rotating addresses: >= 3 message types and >= 3 addresses in 1 s"; "rotating" was made
   concrete as short-lived, and "message type" as format + product (so a one-vendor mode with many products counts).
2. **One address spamming pairing popups nearby** (`fast_pair_rotation`): one address announcing at least
   `ble_rotation_models` (3) different Fast Pair model IDs inside `ble_rotation_window_ms` (5 s).

What the tools' measured-from-source behaviour means for those numbers (not measured on air):

| Sender behaviour | Source | Rule 1 at defaults | Rule 2 |
|---|---|---|---|
| new random address every advert, about 100 adverts/s, mixed or one-vendor mode with many products | Bruce defaults | reported (host test) | no |
| new address per advert, Swift Pair random names / Samsung watch models | Marauder | reported | no |
| new address per advert, ONE Fast Pair model | Marauder Google mode | **not reported** (one message); `t.ble_popup_messages 1` reports it (host test) | no (one model) |
| address and payload change about once a second | Marauder Apple mode | **not reported** (never three inside 1 s); `t.ble_popup_window_ms 5000` reports it (host test) | no |
| one fixed address, many Fast Pair models | Bruce with address rotation off | no | reported |
| one fixed address, many products of another format | Bruce with rotation off, non-Google modes | **not reported** | **not reported** (the ledger's rule is Fast Pair only) |

Suggestion for the owner/supervisor, not implemented: extend rule 2 to every format ("one address announcing three
different products in 5 s"); a real device announces one product, so it adds no known false positive.

## 5. Known false positives and other honest limits

- **Several new real devices in the same second.** Three devices of different products first heard within one second
  after the learning time are indistinguishable from the start of a flood (host test states it). Earbud cases opened
  together, or the first second after a long BLE silence shorter than the address memory, can do it. This is the
  ledger's "real earbuds" case and is what the benign soak must count.
- **Address changes of real devices.** A phone or earbud changes its private address every several minutes; that is
  one new address, not three.
- **Scan duty.** With a scan window below 100 % only part of the adverts is heard, so every count is a lower bound and
  a 1 s window may never see three. The observation carries the scan's own listening report when the adapter gives one.
- **Extended advertising** is not scanned (legacy reports only, 31 bytes).
- **Tables are bounded**: 48 addresses, 24 (address, model) pairs. A flood larger than the table is reported
  `saturated`. More than about 12 addresses rotating Fast Pair models in step can evade rule 2.
- **Popup adverts are not an intrusion.** They annoy and can crash old phone software; the Guardian says "nearby",
  amber, never an ALERT, and never changes the network's rating.

## 6. What is not done, and why

- **No BLE scan on the stick.** Ledger order: spike first; "report and stop if the defense loses Wi-Fi coverage".
  ESP-IDF's coexistence guide rates sniffer receive with BLE scan as supported with unstable performance (read by the
  2026-11-17 attempt), so the gate is real. The spike image, its phase plan and its verdict rules exist since
  2026-11-17 and were not run. Until the verdict the detector is unfed on the stick: STATUS prints
  `ble_popup:...,unconfigured`, the radar shows no Bluetooth slot, and the "What it cannot see" page stays as it is.
- **The adapter that feeds it**: a passive NimBLE scan handing each report to `Monitor::ble_advert()` and the scan
  duty to `Monitor::ble_coverage()`, then `Monitor::set_ble_scan(true)`. On the stick this follows the spike verdict;
  on the C5 node it follows its own S-4 number ([c5-node.md](../c5-node.md)).
- **Calibration**: the benign soak with the owner's real earbuds and phones (count of observations per day at the
  defaults), and one live run per tool mode of the table in section 4.

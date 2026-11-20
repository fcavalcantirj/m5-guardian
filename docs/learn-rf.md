# Learn RF with the Guardian

A defensive learning track for the owner. Each lesson explains one idea, says what the Guardian
(ESP32-S3) can and cannot see, and ends with a lab exercise on the owner's own gear (StickS3
Guardian, Evil Cardputer, Cardputer receiver, Pi-attached ESP32 emitter, LilyGO). Attacks are run
only against the owner's own network and devices. Facts marked *datasheet* come from the vendor
documents listed at the end; check them there before relying on a number.

## 1. What a radio actually sends: modulation

A carrier is a sine wave at a fixed frequency (for example 2.437 GHz = Wi-Fi channel 6). Data is
put on it by changing one property of that wave:

| Modulation | What changes | Where you meet it |
|---|---|---|
| ASK / OOK | amplitude (on/off) | 433/868 MHz garage remotes, cheap sensors (sub-GHz, CC1101) |
| FSK / **GFSK** | frequency, shifted up/down; "G" = Gaussian-smoothed so it stays narrow | **BLE**, **nRF24**, many keyboards/mice/toys |
| PSK (BPSK, QPSK) | phase | 802.11b (DSSS), Zigbee (O-QPSK) |
| QAM (16/64/256) | phase **and** amplitude together, many bits per symbol | Wi-Fi g/n/ac/ax data |
| **OFDM** | splits one channel into many narrow sub-carriers, each QAM-modulated | Wi-Fi 802.11g/n/ac/ax |
| DSSS | spreads each bit over a long chip sequence | 802.11b, Zigbee |
| CSS (chirp) | frequency sweeps | LoRa |

Key idea: **two radios only understand each other if modulation, data rate, channel, packet format
(preamble, sync word or address, whitening, CRC) all match.** Same band (2.4 GHz) is not enough.

*Exercise:* on the Cardputer, compare the Wi-Fi scan and a BLE scan — same 2.4 GHz band, different
radios/protocols, different lists.

## 2. The 2.4 GHz neighbourhood

- **Wi-Fi:** channels 1–13 in Brazil, 20 MHz wide, centres 5 MHz apart → only 1, 6, 11 do not overlap.
  The home AP is on channel 11.
- **BLE:** 40 channels of 2 MHz; advertising lives on 37/38/39 (2402, 2426, 2480 MHz).
- **nRF24:** 126 channels of 1 MHz (2.400–2.525 GHz), *datasheet*.
- Microwave ovens leak around 2.45 GHz (and their metal box blocks it — the Guardian's no-data test).

*Exercise:* run `STATUS` on the stick and note `channel`, then move the stick into the (off)
microwave: the rating must turn into "No fresh data" within 30 s.

## 3. Wi-Fi frames (what the Guardian reads)

802.11 frames have a type: **management** (beacons, probe requests/responses, auth, association,
deauthentication), **control** (ACK, RTS/CTS) and **data** (your traffic; EAPOL handshakes ride here).
Management frames are **unencrypted** unless PMF (802.11w) protects some of them — that is why
anyone can forge a deauth against a network with PMF off, and why WPA3 (PMF required) resists it.

The Guardian listens in promiscuous mode, today to management frames only, and never transmits.

*Exercise:* `IMU`/`STATUS` aside, use the lab console (`lab/live/deauth_truth.py`) to list every
deauth the stick hears, by sender, target and BSSID.

## 4. The attacks and what a passive guard can prove

| Attack | What goes on the air | Can a listener see it? | Guardian task |
|---|---|---|---|
| Deauth / disassoc flood | forged management frames "you are disconnected" | yes (count, burst) | G06 today; G16F per source |
| Handshake capture | deauth, then the client's 4-way EAPOL handshake | deauth + fresh handshake yes; **who** recorded it, no | G16G |
| PMKID harvest | association attempts that make APs send message 1 only | yes (M1 without M2 across many APs) | G16G |
| Evil twin | an AP copying your network name | yes (same SSID, new BSSID) | G06 today |
| Karma / MANA | an AP answering "yes, I'm X" to every probe | yes (one transmitter, many SSIDs) | G16F |
| Probe / beacon flood | thousands of fake probes or networks | yes (rates, distinct addresses) | G16F |
| Pure sniffing | nothing (receive only) | **never**, by physics | — |
| Carrier jamming | a constant tone or noise | only as loss of frames or a raised noise floor | G16G / G16J (honest limit) |
| Channel-switch / Quiet abuse | a forged beacon telling clients to move channel or go silent | yes (CSA count, Quiet duration, a flap on your AP) | G16F |
| SAE commit flood (WPA3) | hundreds of half-finished WPA3 logins | yes (commits without confirms) | G16F |
| Assoc-sleep | association requests with the "I'm asleep" bit, spoofed as a client | yes (many per AP, many sources) | G16F |
| Forged M1 ("Bad Msg") | a fake handshake message 1 sent to clients | yes, with the data path on (all-zero ANonce) | G16G / G16J |
| Clone with your name + deauth (evil portal) | an open AP named like yours, plus deauths | yes (same name, new BSSID: the watch must be ON) | G16J |
| BLE pairing-popup spam | floods of advertising packets | yes, with a BLE radio listening | C5 node (G16K) |
| Anything on 5 GHz | the same attacks on the other band | **not from the stick**: 2.4 GHz radio | C5 node (G16K) |

The full kit-by-kit matrix, what is proven on the stick and what it cannot see, lives in
[attack-coverage.md](attack-coverage.md).

## 4b. EAPOL and the WPA2 four-way handshake (why "handshake capture" matters)

**EAPOL** (EAP over LAN) is the protocol that carries the key-exchange messages; in WPA2-Personal
they are four **EAPOL-Key** frames, sent as *data* frames right after a device associates:

| Msg | Direction | Carries |
|---|---|---|
| M1 | AP → phone | ANonce (AP random); often a **PMKID** |
| M2 | phone → AP | SNonce (phone random) + **MIC** |
| M3 | AP → phone | group key (encrypted) + MIC |
| M4 | phone → AP | acknowledgement + MIC |

The password never travels. Both sides derive the **PMK** from passphrase + SSID (PBKDF2-SHA1,
4096 rounds), then the session key **PTK** from PMK + both nonces + both MAC addresses; the MIC
proves each side knows the PTK. An eavesdropper who records **M1+M2** (or M2+M3) of the same
exchange can **guess passwords offline**: for each guess compute PMK → PTK → MIC and compare. The
**PMKID** in M1 allows the same offline guessing with no client at all. One EAPOL frame is not a
usable capture; a "valid handshake" means a matching pair from one exchange.

Defence (what actually protects the home): a **long random passphrase** (offline guessing becomes
hopeless), **WPA3-SAE** (no offline dictionary from the exchange) and **PMF** (forged deauths are
ignored, so attackers cannot force reconnects). The home AP today is WPA2-Personal with PMF off —
the reason the Guardian rates it **Medium**.

What the Guardian can see: the **deauth burst** that forces a reconnect (today) and, after G16G,
"deauth then a fresh handshake on your network" and PMKID-harvest patterns. It can never see a
device that only **listens** — that is why a passive "Handshake Master" leaves no trace.

*Exercise:* with the owner's own pcap from Bruce/Evil Cardputer, open it in Wireshark with the
filter `eapol` and identify M1–M4 by their key-info flags and the matching replay counter.

## 5. nRF24 versus the ESP32

The **nRF24L01+** (Nordic) is a tiny 2.4 GHz transceiver used by wireless mice, keyboards, toys,
drones and DIY links. *Datasheet* facts:
- **GFSK** at 250 kbps, 1 Mbps or 2 Mbps; channels 0–125 (1 MHz steps).
- **Enhanced ShockBurst (ESB)** packet: preamble (1 byte), **address 3–5 bytes**, a 9-bit packet
  control field (payload length, packet ID, no-ack flag), payload **0–32 bytes**, CRC 1–2 bytes;
  automatic ACK and retransmit; up to 6 receive "pipes".
- A test mode transmits a constant carrier — the basis of cheap 2.4 GHz jammers.

Known research (defensive context): Travis Goodspeed (2011) showed a **promiscuous-sniffing trick**
(very short address matching preamble-like bits); Bastille's **MouseJack** (2016) showed that many
wireless mice/keyboards accepted unencrypted injected keystrokes.

**Why the ESP32-S3 cannot speak nRF24:** its Wi-Fi radio only exposes 802.11 (DSSS/OFDM) frames,
and its Bluetooth controller only BLE packets (GFSK 1M/2M/Coded, BLE access address, whitening,
BLE CRC). ESB uses GFSK too, but a different preamble/address/packet/CRC, and the ESP32 exposes no
raw-GFSK mode to match it. Radios with a raw packet mode (an nRF24 itself, nRF52, CC2500/CC1101 for
their bands) can; that is why "nRF24 modules" are added to ESP32 tools like Bruce/Marauder.
For the Guardian this means: nRF24 traffic is invisible except as **noise/frame loss** on overlapping
Wi-Fi channels.

*Exercise (with an nRF24 module on the LilyGO or Cardputer, later):* scan the 126 channels for
activity while a wireless mouse moves; then show on the stick that Wi-Fi channel 11 sees nothing of it.

## 6. BLE in one page

Advertising packets on 37/38/39 carry a device address (often random/rotating) and manufacturer
data. Pairing-popup spam (Apple/Samsung/Microsoft/Google formats) floods these. A passive BLE scan
shares the ESP32 radio with Wi-Fi, so it costs Wi-Fi capture time — G16H measures that first.

## 7. Sub-GHz (outside the Guardian's radio)

433/868/915 MHz devices (remotes, weather stations, LoRa) need a sub-GHz radio (CC1101, SX127x).
The ESP32 cannot receive them. Rolling codes vs fixed codes is the security lesson there.

## Sources to check numbers against

- Nordic Semiconductor, *nRF24L01+ Product Specification* v1.0 (channels, GFSK rates, ESB packet).
- Bluetooth SIG, *Core Specification* (BLE PHYs, advertising channels).
- IEEE 802.11-2020 (frame types, PMF/802.11w), Wi-Fi Alliance WPA3 specification.
- Espressif, *ESP32-S3 Technical Reference Manual* and ESP-IDF Wi-Fi/BLE guides (what the radio exposes).
- Goodspeed, "Promiscuity is the nRF24L01+'s Duty" (2011); Bastille Networks, "MouseJack" (2016).
- `docs/research/reuse-decisions.md` §10 for the AntiHunter detector map.

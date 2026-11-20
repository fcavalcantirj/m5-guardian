#!/usr/bin/env python3
"""Generate the Guardian host test fixtures (G03 scaffolding).

Every fixture is hand-assembled here from the IEEE 802.11-2020 frame formats
(clause references in the field comments below). Nothing is captured from the
air and nothing is copied from a third-party parser or pcap. Rerun with

    python3 -I firmware/tests/fixtures/make_fixtures.py

from the repository root; output is deterministic and byte-identical, so a
`git diff` after regeneration must be empty. The `.hex` text format is read by
`firmware/tests/support/fixtures.cpp`: `#` starts a comment, hex digit pairs are
separated by whitespace, and `# expect.<key>: <value>` lines carry metadata the
loader check asserts against the bytes (length, first byte, BSSID offset 16,
RSN IE offset). These fixtures do not test a parser; G04 adds that behavior.

Valid-looking fixtures are structurally complete to the best of the author's
reading of the standard. They have NOT been cross-checked by an independent
decoder on this machine (tshark and scapy are not installed); that comparison
is the G04 reviewer's acceptance step and must be recorded then.
"""
from __future__ import annotations

import os
import struct
import sys
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))

BSSID = bytes.fromhex("021122334455")      # locally administered, unicast
STATION = bytes.fromhex("02aabbccddee")    # fixture station address
BROADCAST = bytes.fromhex("ffffffffffff")

# Frame Control (9.2.4.1): protocol version 0, type Management (00),
# subtype in bits 4..7. byte0 = subtype << 4 | type << 2 | version.
FC_BEACON = bytes([0x80, 0x00])            # subtype 8
FC_DEAUTH = bytes([0xC0, 0x00])            # subtype 12
FC_DISASSOC = bytes([0xA0, 0x00])          # subtype 10
FC_PROBE_RESP = bytes([0x50, 0x00])        # subtype 5
# G16E additions (same rule: byte0 = subtype << 4).
FC_ASSOC_REQ = bytes([0x00, 0x00])         # subtype 0
FC_REASSOC_REQ = bytes([0x20, 0x00])       # subtype 2
FC_REASSOC_RESP = bytes([0x30, 0x00])      # subtype 3
FC_PROBE_REQ = bytes([0x40, 0x00])         # subtype 4
FC_AUTH = bytes([0xB0, 0x00])              # subtype 11

# Capability Information (9.4.1.4): bit0 ESS, bit4 Privacy.
CAP_ESS = 0x0001
CAP_PRIVACY = 0x0010

RSN_SUITE_CCMP128 = bytes.fromhex("000fac04")
RSN_SUITE_TKIP = bytes.fromhex("000fac02")
RSN_SUITE_GCMP128 = bytes.fromhex("000fac08")
RSN_SUITE_GCMP256 = bytes.fromhex("000fac09")
RSN_SUITE_CCMP256 = bytes.fromhex("000fac0a")
RSN_SUITE_BIP_GMAC256 = bytes.fromhex("000fac0c")
RSN_AKM_PSK = bytes.fromhex("000fac02")
RSN_AKM_SAE = bytes.fromhex("000fac08")
RSN_AKM_OWE = bytes.fromhex("000fac12")     # 00-0F-AC:18
RSN_AKM_UNKNOWN_200 = bytes.fromhex("000facc8")  # 00-0F-AC:200, not assigned in 802.11-2020 Table 9-151
# WPA (Microsoft OUI 00-50-F2) vendor element: type 1; selectors share the OUI (WPA v1 spec, Table 4/5).
WPA_OUI_TYPE = bytes.fromhex("0050f201")
WPA_SUITE_TKIP = bytes.fromhex("0050f202")
WPA_AKM_PSK = bytes.fromhex("0050f202")
# Wi-Fi Alliance OWE Transition Mode element: OUI 50-6F-9A, type 28 (0x1c).
OWE_TRANSITION_OUI_TYPE = bytes.fromhex("506f9a1c")
# RSN Capabilities (9.4.2.24.4): bit6 MFPR, bit7 MFPC.
RSN_CAP_MFPC = 0x0080
RSN_CAP_MFPR = 0x0040


def mac_header(fc: bytes, addr1: bytes, addr2: bytes, addr3: bytes, seq: int, frag: int = 0) -> list[tuple[bytes, str]]:
    """Management MAC header (9.3.3.2): FC, Duration, A1, A2, A3, Sequence Control."""
    assert 0 <= seq < 4096 and 0 <= frag < 16
    seq_ctrl = struct.pack("<H", (seq << 4) | frag)  # 9.2.4.4: fragment bits 0..3, sequence bits 4..15
    return [
        (fc, "Frame Control"),
        (b"\x00\x00", "Duration"),
        (addr1, "Address 1"),
        (addr2, "Address 2"),
        (addr3, "Address 3 (BSSID for these management frames)"),
        (seq_ctrl, f"Sequence Control: fragment {frag}, sequence {seq}"),
    ]


def beacon_fixed(capability: int, interval_tu: int = 100) -> list[tuple[bytes, str]]:
    """Beacon frame body fixed fields (9.3.3.3): Timestamp, Beacon Interval, Capability."""
    return [
        (struct.pack("<Q", 0x0000000000112233), "Timestamp (TSF, little-endian)"),
        (struct.pack("<H", interval_tu), f"Beacon Interval {interval_tu} TU"),
        (struct.pack("<H", capability), f"Capability Information 0x{capability:04x}"),
    ]


def ie(element_id: int, body: bytes, note: str, claimed_len: int | None = None) -> tuple[bytes, str]:
    length = len(body) if claimed_len is None else claimed_len
    assert 0 <= length <= 255
    return (bytes([element_id, length]) + body, note)


def rsn_body(group: bytes, pairwise: list[bytes], akms: list[bytes], caps: int | None,
             pairwise_count: int | None = None, akm_count: int | None = None,
             pmkids: list[bytes] | None = None, group_mgmt: bytes | None = None) -> bytes:
    """RSNE body (9.4.2.24): Version(2) Group(4) PairwiseCount(2) Pairwise(4n) AKMCount(2) AKM(4n)
    [RSNCaps(2)] [PMKIDCount(2) PMKIDs(16n)] [GroupMgmtCipher(4)]. Every field after Version is
    optional; once one is absent none of the later ones is present (9.4.2.24.1)."""
    pc = len(pairwise) if pairwise_count is None else pairwise_count
    ac = len(akms) if akm_count is None else akm_count
    out = struct.pack("<H", 1) + group + struct.pack("<H", pc) + b"".join(pairwise) + struct.pack("<H", ac) + b"".join(akms)
    if caps is not None:
        out += struct.pack("<H", caps)
        if pmkids is not None:
            out += struct.pack("<H", len(pmkids)) + b"".join(pmkids)
            if group_mgmt is not None:
                out += group_mgmt
    return out


def wpa_body(group: bytes, pairwise: list[bytes], akms: list[bytes]) -> bytes:
    """WPA vendor element body (WPA v1 spec section 2.1): OUI 00-50-F2 type 1, Version(2)=1,
    Multicast(4), UnicastCount(2) Unicast(4n), AKMCount(2) AKM(4n); capabilities omitted (optional)."""
    return (WPA_OUI_TYPE + struct.pack("<H", 1) + group + struct.pack("<H", len(pairwise)) + b"".join(pairwise)
            + struct.pack("<H", len(akms)) + b"".join(akms))


def owe_transition_body(pair_bssid: bytes, pair_ssid: bytes, band_channel: tuple[int, int] | None = None) -> bytes:
    """WFA OWE Transition Mode element: OUI 50-6F-9A type 28, BSSID(6), SSID length(1), SSID(n),
    optional Band Info(1) + Channel(1) (WFA OWE Specification v1.1, section 2.3.1)."""
    out = OWE_TRANSITION_OUI_TYPE + pair_bssid + bytes([len(pair_ssid)]) + pair_ssid
    if band_channel is not None:
        out += bytes(band_channel)
    return out


@dataclass
class Fixture:
    name: str
    kind: str
    provenance: str
    parts: list[tuple[bytes, str]]
    meta: dict[str, str] = field(default_factory=dict)
    truncate_to: int | None = None

    def bytes(self) -> bytes:
        raw = b"".join(p for p, _ in self.parts)
        return raw if self.truncate_to is None else raw[: self.truncate_to]

    def render(self) -> str:
        raw = self.bytes()
        lines = [
            f"# name: {self.name}",
            f"# kind: {self.kind}",
            f"# provenance: {self.provenance}",
            "# generator: firmware/tests/fixtures/make_fixtures.py (hand-assembled from IEEE 802.11-2020; no capture, no third-party decoder)",
            f"# expect.length: {len(raw)}",
            f"# expect.fc0: {raw[0]:02x}",
        ]
        for k, v in self.meta.items():
            lines.append(f"# expect.{k}: {v}")
        lines.append("#")
        offset = 0
        for part, note in self.parts:
            if self.truncate_to is not None and offset >= self.truncate_to:
                lines.append(f"# [{offset:3d}] (cut) {note}")
                offset += len(part)
                continue
            chunk = part
            cut = ""
            if self.truncate_to is not None and offset + len(part) > self.truncate_to:
                chunk = part[: self.truncate_to - offset]
                cut = f" (cut after {len(chunk)} of {len(part)} bytes)"
            lines.append(f"# [{offset:3d}] {note}{cut}")
            for i in range(0, len(chunk), 16):
                lines.append("  " + " ".join(f"{b:02x}" for b in chunk[i : i + 16]))
            offset += len(part)
        return "\n".join(lines) + "\n"


def beacon(name: str, capability: int, ssid: bytes | None, extra: list[tuple[bytes, str]], provenance: str,
           meta: dict[str, str] | None = None, seq: int = 0x123, truncate_to: int | None = None,
           fc: bytes = FC_BEACON, addr1: bytes = BROADCAST,
           between: list[tuple[bytes, str]] | None = None,
           bssid: bytes = BSSID, ds_channel: int = 6) -> Fixture:
    # G06 added `bssid` and `ds_channel` with the previous constants as defaults;
    # every earlier fixture regenerates byte-identically (checked by git diff).
    parts = mac_header(fc, addr1, bssid, bssid, seq)
    if fc[1] & 0x80:
        parts.append((b"\x00\x00\x00\x00", "HT Control (9.2.4.6a): present because the Order bit is set in a management frame"))
    parts += beacon_fixed(capability)
    if ssid is not None:
        parts.append(ie(0, ssid, f"SSID element (9.4.2.2), {len(ssid)} bytes" + (" = hidden/zero-length" if not ssid else "")))
    parts.append(ie(1, bytes.fromhex("82848b960c121824"), "Supported Rates (9.4.2.3): 1 2 5.5 11 basic, 6 9 12 18"))
    parts.append(ie(3, bytes([ds_channel]), f"DS Parameter Set (9.4.2.4): channel {ds_channel}"))
    if between:
        parts.extend(between)
    m = {"bssid": bssid.hex()}
    if meta:
        m.update(meta)
    f = Fixture(name, "beacon", provenance, parts + extra, m, truncate_to)
    return f


def rsn_offset(f: Fixture) -> int:
    """Offset of the RSNE, found by its field note (not by scanning for byte 0x30,
    which also appears in the Sequence Control of these fixtures)."""
    off = 0
    for part, note in f.parts:
        if note.startswith("RSNE"):
            assert part[0] == 48
            return off
        off += len(part)
    raise AssertionError("no RSN element in fixture " + f.name)


def main() -> int:
    fixtures: list[Fixture] = []

    fixtures.append(beacon(
        "beacon_open", CAP_ESS, b"home", [],
        "Open AP beacon: Privacy bit clear, no RSNE/WPA/OWE elements. Expected G04 reading: privacy_bit=false, rsn Absent.",
    ))

    rsn_wpa2 = ie(48, rsn_body(RSN_SUITE_CCMP128, [RSN_SUITE_CCMP128], [RSN_AKM_PSK], RSN_CAP_MFPC),
                  "RSNE (9.4.2.24): v1, group CCMP-128, 1 pairwise CCMP-128, 1 AKM PSK (00-0F-AC:2), caps MFPC only (PMF optional)")
    f = beacon("beacon_wpa2_ccmp_pmf_optional", CAP_ESS | CAP_PRIVACY, b"home", [rsn_wpa2],
               "WPA2-Personal CCMP, PMF optional (MFPC=1, MFPR=0). Expected G04 reading: rsn Valid, akms Psk, pairwise Ccmp128, pmf Optional.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    rsn_wpa3 = ie(48, rsn_body(RSN_SUITE_CCMP128, [RSN_SUITE_CCMP128], [RSN_AKM_SAE], RSN_CAP_MFPC | RSN_CAP_MFPR),
                  "RSNE: v1, group CCMP-128, 1 pairwise CCMP-128, 1 AKM SAE (00-0F-AC:8), caps MFPC|MFPR (PMF required)")
    f = beacon("beacon_wpa3_sae_pmf_required", CAP_ESS | CAP_PRIVACY, b"home", [rsn_wpa3],
               "WPA3-Personal SAE only, PMF required. Expected G04 reading: rsn Valid, akms Sae, pmf Required.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    f = beacon("beacon_hidden_ssid_wpa2", CAP_ESS | CAP_PRIVACY, b"", [rsn_wpa2],
               "Same RSNE as beacon_wpa2_ccmp_pmf_optional with a zero-length SSID element (hidden). Expected G04 reading: ssid_kind Hidden, settings still Valid; the element after the empty SSID must still be read (G02 showed the initial empty SSID succeeds; its iterator defect concerns a later zero-length IE).")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    # Counterexample: RSNE length claims 20 bytes but the frame ends after the AKM count.
    full = beacon("beacon_rsn_truncated_ie", CAP_ESS | CAP_PRIVACY, b"home", [rsn_wpa2],
                  "Counterexample for G04: RSNE claims length 20 but the frame ends 6 bytes early (after the AKM suite count). Expected G04 reading: ParseStatus Truncated or Malformed with IeOverrun, never Open and never a complete grade.")
    off = rsn_offset(full)
    full.truncate_to = off + 2 + 2 + 4 + 2 + 4 + 2  # id,len + version + group + pairwise count + pairwise + akm count
    full.meta["rsn_offset"] = str(off)
    fixtures.append(full)

    # Counterexample: pairwise count 0x0100 little-endian (256) while one suite is present.
    rsn_count = ie(48, rsn_body(RSN_SUITE_CCMP128, [RSN_SUITE_CCMP128], [RSN_AKM_PSK], RSN_CAP_MFPC, pairwise_count=0x0100),
                   "RSNE with pairwise count bytes 00 01 = 256 (little-endian) but one suite present: malformed; a low-byte-only reader sees 0")
    f = beacon("beacon_rsn_pairwise_count_256", CAP_ESS | CAP_PRIVACY, b"home", [rsn_count],
               "Counterexample for G04 (from the G02 libwifi finding): declared pairwise count 256 with one suite. Expected G04 reading: SuiteCountOverflow, rsn not Valid, no grade.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    # Counterexample: WPA2 that also advertises TKIP pairwise. Weakest-advertised rule (G05) must see TKIP.
    rsn_mixed = ie(48, rsn_body(RSN_SUITE_TKIP, [RSN_SUITE_CCMP128, RSN_SUITE_TKIP], [RSN_AKM_PSK], 0),
                   "RSNE: group TKIP, 2 pairwise (CCMP-128, TKIP), 1 AKM PSK, caps 0 (no PMF)")
    f = beacon("beacon_wpa2_mixed_tkip", CAP_ESS | CAP_PRIVACY, b"home", [rsn_mixed],
               "WPA2 with TKIP group and TKIP among pairwise options. Expected G04 reading: pairwise kinds Ccmp128|Tkip, group Tkip, pmf Disabled; G05 must grade Bad (legacy option advertised), not Medium.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    # ---- G04 parser fixtures (added with the parser; same hand-assembly rules) ----

    rsn_owe = ie(48, rsn_body(RSN_SUITE_CCMP128, [RSN_SUITE_CCMP128], [RSN_AKM_OWE], RSN_CAP_MFPC | RSN_CAP_MFPR),
                 "RSNE: v1, group CCMP-128, 1 pairwise CCMP-128, 1 AKM OWE (00-0F-AC:18), caps MFPC|MFPR")
    owe_tr = ie(221, owe_transition_body(bytes.fromhex("021122334456"), b"home-open"),
                "Vendor Specific (9.4.2.26) OWE Transition Mode: OUI 50-6F-9A type 28, paired open BSSID 02:11:22:33:44:56, SSID 'home-open', no band/channel")
    f = beacon("beacon_owe_transition", CAP_ESS | CAP_PRIVACY, b"home", [rsn_owe, owe_tr],
               "OWE BSS with an OWE Transition Mode element. Expected G04 reading: rsn Valid, akms Owe, pmf Required, owe_transition Valid, settings complete.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    wpa1 = ie(221, wpa_body(WPA_SUITE_TKIP, [WPA_SUITE_TKIP], [WPA_AKM_PSK]),
              "Vendor Specific WPA (00-50-F2 type 1): v1, multicast TKIP, 1 unicast TKIP, 1 AKM PSK (00-50-F2:2), no capabilities")
    f = beacon("beacon_wpa1_tkip_vendor", CAP_ESS | CAP_PRIVACY, b"home", [wpa1],
               "Original WPA (vendor element only, no RSNE). Expected G04 reading: wpa Valid (akms Wpa1Psk, pairwise Tkip, group Tkip, pmf Unknown), rsn Absent, settings complete.")
    fixtures.append(f)

    f = beacon("beacon_wpa_and_rsn_mixed", CAP_ESS | CAP_PRIVACY, b"home", [wpa1, rsn_wpa2],
               "WPA/WPA2 mixed mode: WPA vendor element (TKIP) and RSNE (CCMP, PMF optional) together. Expected G04 reading: both elements Valid with separate records (wpa group Tkip, rsn group Ccmp128), settings complete.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    rsn_min = ie(48, struct.pack("<H", 1), "RSNE: v1 only; every later field absent (9.4.2.24.1 defaults: CCMP-128 / CCMP-128 / 802.1X / caps 0)")
    f = beacon("beacon_rsn_minimal_version_only", CAP_ESS | CAP_PRIVACY, b"home", [rsn_min],
               "RSNE with only the Version field. Expected G04 reading: rsn Valid with documented defaults (group Ccmp128 present=false, pairwise {Ccmp128}, akms {Eap}, pmf Disabled), settings complete.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    rsn_full = ie(48, rsn_body(RSN_SUITE_CCMP128, [RSN_SUITE_CCMP128], [RSN_AKM_SAE], RSN_CAP_MFPC | RSN_CAP_MFPR,
                               pmkids=[bytes(range(16))], group_mgmt=RSN_SUITE_BIP_GMAC256),
                  "RSNE: v1, group CCMP-128, 1 pairwise CCMP-128, 1 AKM SAE, caps MFPC|MFPR, PMKID count 1 + one 16-byte PMKID, group management BIP-GMAC-256 (00-0F-AC:12)")
    f = beacon("beacon_rsn_pmkid_group_mgmt", CAP_ESS | CAP_PRIVACY, b"home", [rsn_full],
               "RSNE with every optional field present. Expected G04 reading: rsn Valid, pmf Required, group_management present kind BipGmac256, settings complete.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    rsn_bad_pmf = ie(48, rsn_body(RSN_SUITE_CCMP128, [RSN_SUITE_CCMP128], [RSN_AKM_PSK], RSN_CAP_MFPR),
                     "RSNE: caps MFPR=1 with MFPC=0, an invalid combination (9.4.2.24.4)")
    f = beacon("beacon_rsn_pmf_inconsistent", CAP_ESS | CAP_PRIVACY, b"home", [rsn_bad_pmf],
               "Counterexample for G04: MFPR set without MFPC. Expected G04 reading: ParseError PmfInconsistent, rsn Malformed and zeroed, pmf Unknown, no complete settings.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    rsn_four = ie(48, rsn_body(RSN_SUITE_CCMP128, [RSN_SUITE_CCMP128, RSN_SUITE_GCMP128, RSN_SUITE_GCMP256, RSN_SUITE_CCMP256],
                               [RSN_AKM_SAE], RSN_CAP_MFPC | RSN_CAP_MFPR),
                  "RSNE: 4 pairwise suites (CCMP-128, GCMP-128, GCMP-256, CCMP-256), more than libwifi's 3-suite model")
    f = beacon("beacon_rsn_four_pairwise", CAP_ESS | CAP_PRIVACY, b"home", [rsn_four],
               "RSNE advertising four pairwise ciphers. Expected G04 reading: pairwise count 4, kinds Ccmp128|Gcmp128|Gcmp256|Ccmp256 in wire order, settings complete.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    rsn_unknown = ie(48, rsn_body(RSN_SUITE_CCMP128, [RSN_SUITE_CCMP128], [RSN_AKM_UNKNOWN_200, RSN_AKM_PSK], RSN_CAP_MFPC),
                     "RSNE: 2 AKMs, 00-0F-AC:200 (unassigned) then PSK")
    f = beacon("beacon_rsn_unknown_akm", CAP_ESS | CAP_PRIVACY, b"home", [rsn_unknown],
               "RSNE with an unassigned AKM selector before PSK. Expected G04 reading: rsn Valid, akms kinds Unknown|Psk with the raw selector 0x000facc8 preserved, settings_complete false (not understood).")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    f = beacon("beacon_rsn_duplicate_conflict", CAP_ESS | CAP_PRIVACY, b"home", [rsn_wpa2, rsn_wpa3],
               "Counterexample for G04: two RSNEs with different content (PSK/MFPC then SAE/MFPC|MFPR). Expected G04 reading: ParseError DuplicateConflict, rsn Conflicting and zeroed (never a union of the copies), privacy still valid.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    f = beacon("beacon_later_empty_ie_then_rsn", CAP_ESS | CAP_PRIVACY, b"home", [rsn_wpa2],
               "SSID, rates, DS, then a zero-length Extended Supported Rates element (id 50) BEFORE the RSNE: the G02 libwifi iterator defect stops here and keeps WEP. Expected G04 reading: rsn Valid, settings complete.",
               between=[ie(50, b"", "Extended Supported Rates (9.4.2.13) with zero length: legal element header, empty body")])
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    f = beacon("probe_response_wpa2", CAP_ESS | CAP_PRIVACY, b"home", [rsn_wpa2],
               "Probe Response (9.3.3.11) to one station with the WPA2 RSNE; same body layout as a beacon. Expected G04 reading: kind ProbeResponse, rsn Valid, settings complete.",
               fc=FC_PROBE_RESP, addr1=STATION)
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    f = beacon("beacon_ht_control_order_bit", CAP_ESS | CAP_PRIVACY, b"home", [rsn_wpa2],
               "Beacon with the Order bit set (FC byte 1 bit 7): a 4-byte HT Control field follows the sequence control, so the MAC header is 28 bytes (9.2.4.1.10, 9.3.3.2). Expected G04 reading: header_valid, rsn Valid at the shifted offset, settings complete.",
               fc=bytes([FC_BEACON[0], FC_BEACON[1] | 0x80]))
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    f = beacon("beacon_ssid_non_utf8", CAP_ESS | CAP_PRIVACY, bytes.fromhex("ff fe 78 01"), [rsn_wpa2],
               "SSID bytes ff fe 78 01: not valid UTF-8 (lone 0xff/0xfe), contains a control byte. Expected G04 reading: ssid_kind Present, ssid_utf8 false, the four bytes preserved exactly, rsn Valid.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    # Group-addressed deauthentication with a Management MIC element (BIP, 12.5.4): reason + MME id 76,
    # length 16 (KeyID 2, IPN 6, MIC 8). The MIC is not verifiable without the IGTK.
    mme = ie(76, struct.pack("<H", 4) + bytes.fromhex("010000000000") + bytes(8),
             "Management MIC element (9.4.2.55): Key ID 4, IPN 1, 8-byte MIC (unverifiable here)")
    parts = mac_header(FC_DEAUTH, BROADCAST, BSSID, BSSID, seq=5) + [(struct.pack("<H", 1), "Reason Code 1 (unspecified)")] + [mme]
    fixtures.append(Fixture("deauth_group_mme", "deauth",
                            "Broadcast deauthentication protected by BIP: Protected Frame bit clear, reason in the clear, MME appended. Expected G04 reading: kind Deauthentication, reason_readable true (structurally; MIC unverified), reason_code 1.",
                            parts, {"bssid": BSSID.hex(), "reason": "1"}))

    # Unicast deauthentication with the Protected Frame bit set (CCMP, 12.5.3): the body is an 8-byte CCMP header
    # followed by encrypted data and an 8-byte MIC. The bytes below are placeholders, not a real ciphertext.
    fc_prot = bytes([FC_DEAUTH[0], FC_DEAUTH[1] | 0x40])
    parts = mac_header(fc_prot, STATION, BSSID, BSSID, seq=6) + [
        (bytes.fromhex("0100002000000000"), "CCMP header: PN0 PN1, reserved, KeyID/ExtIV byte 0x20, PN2..PN5"),
        (bytes.fromhex("5a5a"), "encrypted Reason Code (placeholder bytes)"),
        (bytes(8), "CCMP MIC (placeholder)"),
    ]
    fixtures.append(Fixture("deauth_protected_unicast", "deauth",
                            "Unicast deauthentication with the Protected Frame bit set. Expected G04 reading: kind Deauthentication, protected_frame true, status Unsupported, reason_readable false, header_valid true.",
                            parts, {"bssid": BSSID.hex()}))

    # Deauthentication (9.3.3.12): header + Reason Code (9.4.1.7). Reason 7 = class 3 frame from nonassociated STA.
    parts = mac_header(FC_DEAUTH, STATION, BSSID, BSSID, seq=4) + [(struct.pack("<H", 7), "Reason Code 7 (little-endian)")]
    fixtures.append(Fixture("deauth_reason7", "deauth",
                            "Unprotected deauthentication from the fixture BSSID to one station, reason 7. Expected G04 reading: kind Deauthentication, reason_readable true, reason_code 7, protected_frame false.",
                            parts, {"bssid": BSSID.hex(), "reason": "7"}))

    # Disassociation (9.3.3.5) with the Retry bit set (FC byte1 bit3) and reason 8 (STA leaving).
    fc_retry = bytes([FC_DISASSOC[0], FC_DISASSOC[1] | 0x08])
    parts = mac_header(fc_retry, STATION, BSSID, BSSID, seq=4) + [(struct.pack("<H", 8), "Reason Code 8")]
    fixtures.append(Fixture("disassoc_retry_reason8", "disassoc",
                            "Disassociation with Retry bit set, same sequence number 4 as deauth_reason7. Scaffolding for G06 dedupe cases: the Retry bit alone must not cause a silent drop (docs/research/reuse-decisions.md).",
                            parts, {"bssid": BSSID.hex(), "reason": "8", "retry": "1"}))

    # ---- G06 detector fixtures (baseline-change cases; same hand-assembly rules) ----

    # The selected AP's exact WPA3 advertisement on another channel: with an approved channel of 6 this is a
    # SettingsChanged(Channel) observation; without an approved channel it is nothing.
    f = beacon("beacon_wpa3_channel_11", CAP_ESS | CAP_PRIVACY, b"home", [rsn_wpa3],
               "Same AP and RSNE as beacon_wpa3_sae_pmf_required with DS Parameter channel 11. Expected G06 reading: fingerprint equal to the WPA3 baseline, channel differs (change::Channel) only when a channel was approved.",
               ds_channel=11)
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    # An owner-approved extender: another BSSID advertising the same SSID bytes and settings. In scope once
    # approved (handled like the selected AP, never UnexpectedAp); the UnexpectedAp counterexample until then.
    f = beacon("beacon_wpa3_extender_bssid_56", CAP_ESS | CAP_PRIVACY, b"home", [rsn_wpa3],
               "Same SSID bytes and RSNE as beacon_wpa3_sae_pmf_required from BSSID 02:11:22:33:44:56 (an approved mesh/extender node in the G06 roaming cases; an unapproved AP with the selected SSID otherwise).",
               bssid=bytes.fromhex("021122334456"))
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    # The selected SSID bytes from an unapproved BSSID with weaker advertised settings (WPA2, PMF optional).
    f = beacon("beacon_same_ssid_other_bssid_wpa2", CAP_ESS | CAP_PRIVACY, b"home", [rsn_wpa2],
               "SSID bytes of the selected network from BSSID 02:11:22:33:44:66 with the WPA2 PMF-optional RSNE. Expected G06 reading: UnexpectedAp (change::Bssid, plus Rsn/Pmf against a WPA3 baseline); never a confirmed evil twin.",
               bssid=bytes.fromhex("021122334466"))
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    # ---- G16E management-frame fixtures (parser platform for the passive detectors) ----
    # Same hand-assembly rules: IEEE 802.11-2020 clause references, no capture, no third-party
    # decoder, no code or bytes from any other project. Addresses are fixture values.
    RANDOM_SOURCE = bytes.fromhex("daa119000001")   # locally administered (bit 1 of byte 0), unicast
    UNIVERSAL_SOURCE = bytes.fromhex("001a2b3c4d5e")  # universally administered, unicast
    rates = ie(1, bytes.fromhex("82848b960c121824"), "Supported Rates (9.4.2.3): 1 2 5.5 11 basic, 6 9 12 18")

    # Probe Request (9.3.3.10): header, then elements only (SSID first). Subtype 4.
    parts = mac_header(FC_PROBE_REQ, BROADCAST, RANDOM_SOURCE, BROADCAST, seq=0x0A1) + [
        ie(0, b"", "SSID element (9.4.2.2), 0 bytes = wildcard (any network)"), rates]
    fixtures.append(Fixture("probereq_wildcard_random", "probe_request",
                            "Wildcard probe request from a locally administered (randomized-looking) source address. Expected G16E reading: kind ProbeRequest, status Complete, ssid_kind Wildcard (not Hidden), addr2_local true, sequence 0x0a1, no advertised settings.",
                            parts, {}))  # Address 3 is the wildcard BSSID: no AP identity

    parts = mac_header(FC_PROBE_REQ, BROADCAST, UNIVERSAL_SOURCE, BROADCAST, seq=0x0A2) + [
        ie(0, b"home", "SSID element (9.4.2.2), 4 bytes 'home' (directed probe)"), rates]
    probe_named = Fixture("probereq_named", "probe_request",
                          "Directed probe request for 'home' from a universally administered source. Expected G16E reading: kind ProbeRequest, ssid_kind Present with the 4 bytes, addr2_local false; never security evidence.",
                          parts, {})  # wildcard BSSID: no AP identity
    fixtures.append(probe_named)

    # Counterexample: the same probe request cut inside its SSID element.
    cut = Fixture("probereq_truncated_ssid", "probe_request",
                  "Counterexample for G16E: probereq_named cut 2 bytes into the SSID element body (element claims 4). Expected G16E reading: Truncated or Malformed with IeOverrun, ssid_kind Absent (never a guessed name).",
                  list(probe_named.parts), {}, truncate_to=24 + 2 + 2)
    fixtures.append(cut)

    # Authentication (9.3.3.11): Algorithm(2) Transaction(2) Status(2) [algorithm-specific fields]. Subtype 11.
    parts = mac_header(FC_AUTH, BSSID, STATION, BSSID, seq=0x010) + [
        (struct.pack("<H", 0), "Authentication Algorithm Number 0 (Open System, 9.4.1.1)"),
        (struct.pack("<H", 1), "Authentication Transaction Sequence Number 1 (9.4.1.2)"),
        (struct.pack("<H", 0), "Status Code 0 (9.4.1.9; reserved in request frames)")]
    fixtures.append(Fixture("auth_open_seq1", "auth",
                            "Open System authentication request (transaction 1) from the fixture station to the fixture BSSID. Expected G16E reading: kind Authentication, status Complete, auth_valid, algorithm 0, transaction 1, status code 0.",
                            parts, {"bssid": BSSID.hex()}))

    parts = mac_header(FC_AUTH, BSSID, RANDOM_SOURCE, BSSID, seq=0x011) + [
        (struct.pack("<H", 3), "Authentication Algorithm Number 3 (SAE, 9.4.1.1)"),
        (struct.pack("<H", 1), "Authentication Transaction Sequence Number 1 (SAE Commit, 12.4.7.4)"),
        (struct.pack("<H", 0), "Status Code 0"),
        (struct.pack("<H", 19), "Finite Cyclic Group 19 (9.4.1.42)"),
        (bytes(32), "Scalar (32 bytes, placeholder zeros: not a valid commit, never decoded)"),
        (bytes(64), "Element (64 bytes, placeholder zeros: not a curve point, never decoded)")]
    fixtures.append(Fixture("auth_sae_commit", "auth",
                            "SAE Commit (algorithm 3, transaction 1) from a locally administered source. The scalar/element are placeholders. Expected G16E reading: auth_valid, algorithm 3, transaction 1, status Complete; the SAE body after the fixed fields is not decoded and is not parsed as elements.",
                            parts, {"bssid": BSSID.hex()}))

    parts = mac_header(FC_AUTH, BSSID, STATION, BSSID, seq=0x012) + [
        (struct.pack("<H", 0), "Authentication Algorithm Number 0"),
        (struct.pack("<H", 1), "Transaction 1; the 2-byte Status Code is missing")]
    fixtures.append(Fixture("auth_short_body", "auth",
                            "Counterexample for G16E: authentication body of 4 bytes (Status Code missing). Expected G16E reading: Malformed, ShortFixedBody, auth_valid false (no algorithm reported).",
                            parts, {"bssid": BSSID.hex()}))

    rsn_client = ie(48, rsn_body(RSN_SUITE_CCMP128, [RSN_SUITE_CCMP128], [RSN_AKM_PSK], RSN_CAP_MFPC),
                    "RSNE chosen by the client (9.4.2.24): never an advertisement of the AP")
    # (Re)Association Request with the Power Management bit (FC byte 1 bit 4, 9.2.4.1.7) set.
    parts = mac_header(bytes([FC_ASSOC_REQ[0], FC_ASSOC_REQ[1] | 0x10]), BSSID, STATION, BSSID, seq=0x013) + [
        (struct.pack("<H", CAP_ESS | CAP_PRIVACY), "Capability Information 0x0011 (9.4.1.4)"),
        (struct.pack("<H", 10), "Listen Interval 10 (9.4.1.6)"),
        ie(0, b"home", "SSID element, 'home'"), rates, rsn_client]
    fixtures.append(Fixture("assoc_request_pm", "assoc_request",
                            "Association request (9.3.3.6) with the Power Management bit set in Frame Control. Expected G16E reading: kind AssociationRequest, power_management true, listen interval 10, SSID 'home', status Complete, settings_present false (a client's RSNE is never AP evidence).",
                            parts, {"bssid": BSSID.hex()}))

    parts = mac_header(bytes([FC_REASSOC_REQ[0], FC_REASSOC_REQ[1] | 0x10]), BSSID, RANDOM_SOURCE, BSSID, seq=0x014) + [
        (struct.pack("<H", CAP_ESS | CAP_PRIVACY), "Capability Information 0x0011"),
        (struct.pack("<H", 3), "Listen Interval 3"),
        (bytes.fromhex("021122334456"), "Current AP Address 02:11:22:33:44:56 (9.4.1.12)"),
        ie(0, b"home", "SSID element, 'home'"), rates]
    fixtures.append(Fixture("reassoc_request_pm", "reassoc_request",
                            "Reassociation request (9.3.3.8) with the Power Management bit set, from a locally administered source. Expected G16E reading: kind ReassociationRequest, power_management true, addr2_local true, listen interval 3, current AP 02:11:22:33:44:56, SSID 'home'.",
                            parts, {"bssid": BSSID.hex()}))

    parts = mac_header(FC_REASSOC_RESP, STATION, BSSID, BSSID, seq=0x015) + [
        (struct.pack("<H", CAP_ESS | CAP_PRIVACY), "Capability Information 0x0011"),
        (struct.pack("<H", 0), "Status Code 0 (success)"),
        (struct.pack("<H", 0xC001), "AID 1 with bits 14-15 set (9.4.1.8)"), rates]
    fixtures.append(Fixture("reassoc_response_success", "reassoc_response",
                            "Reassociation response (9.3.3.9) with status 0. Expected G16E reading: kind ReassociationResponse, status_valid, status code 0, status Complete.",
                            parts, {"bssid": BSSID.hex()}))

    # Beacon with Channel Switch Announcement (9.4.2.18), two Quiet elements (9.4.2.22) and a
    # Multiple BSSID element (9.4.2.45). The RSNE is the WPA3 one: the rating must be unaffected.
    csa = ie(37, bytes([1, 11, 5]), "Channel Switch Announcement (9.4.2.18): mode 1 (stop transmitting), new channel 11, count 5")
    quiet_a = ie(40, bytes([1, 0]) + struct.pack("<H", 100) + struct.pack("<H", 0), "Quiet (9.4.2.22): count 1, period 0, duration 100 TU, offset 0")
    quiet_b = ie(40, bytes([2, 0]) + struct.pack("<H", 1500) + struct.pack("<H", 10), "Quiet (9.4.2.22): count 2, period 0, duration 1500 TU, offset 10 (a second quiet interval is legal)")
    mbssid = ie(71, bytes([3]), "Multiple BSSID (9.4.2.45): MaxBSSID Indicator 3, no subelements")
    f = beacon("beacon_csa_quiet_mbssid", CAP_ESS | CAP_PRIVACY, b"home", [rsn_wpa3, csa, quiet_a, quiet_b, mbssid],
               "WPA3 beacon that also announces a channel switch, two quiet intervals and a Multiple BSSID set. Expected G16E reading: timing TSF 0x112233 interval 100 TU, csa Valid (mode 1, channel 11, count 5), quiet Valid (2 elements, longest 1500 TU), multi_bssid Valid; rsn Valid and settings complete exactly as without these elements.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    f = beacon("beacon_csa_bad_length", CAP_ESS | CAP_PRIVACY, b"home",
               [rsn_wpa3, ie(37, bytes([1, 11]), "Channel Switch Announcement with length 2 (must be 3): malformed")],
               "Counterexample for G16E: CSA element of length 2. Expected G16E reading: Malformed, BadElementLength, csa Malformed with zero fields, settings_complete false (never a guessed channel or count).")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    payload = b'{"name":"lab-unit","face":"(o_o)","epoch":12345}'[:40]
    f = beacon("beacon_element222", CAP_ESS, b"", [ie(222, payload, f"Element ID 222 (not assigned by IEEE 802.11-2020 Table 9-92 to a public element; some community devices carry a JSON status here), {len(payload)} bytes")],
               "Open, hidden beacon carrying a 40-byte payload in element 222 from BSSID de:ad:be:ef:de:ad. Expected G16E reading: element222 count 1, 40 bytes, a bounded 32-byte head copy; status Complete.",
               bssid=bytes.fromhex("deadbeefdead"))
    fixtures.append(f)

    f = beacon("beacon_hidden_nul_ssid", CAP_ESS | CAP_PRIVACY, bytes(4), [rsn_wpa2],
               "Hidden network that keeps its name length: SSID element of 4 NUL bytes. Expected G16E reading: ssid_kind HiddenNul (distinct from the zero-length Hidden), identity length 4, ssid_utf8 false, rsn Valid.")
    f.meta["rsn_offset"] = str(rsn_offset(f))
    fixtures.append(f)

    # Counterexample: header too short for a management frame (23 bytes).
    short = Fixture("mgmt_header_short_23", "beacon",
                    "Counterexample for G04: 23 bytes, one short of a management MAC header. Expected G04 reading: ParseError ShortMacHeader, header_valid false.",
                    mac_header(FC_BEACON, BROADCAST, BSSID, BSSID, seq=1), {}, truncate_to=23)
    fixtures.append(short)

    written = []
    for f in fixtures:
        path = os.path.join(HERE, f.name + ".hex")
        text = f.render()
        with open(path, "w", encoding="ascii", newline="\n") as fh:
            fh.write(text)
        written.append((f.name, len(f.bytes())))
    for name, n in written:
        print(f"{n:4d} bytes  {name}.hex")
    return 0


if __name__ == "__main__":
    sys.exit(main())

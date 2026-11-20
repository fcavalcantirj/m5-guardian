#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "guardian/identity.hpp"
#include "guardian/radio.hpp"

// Parser contracts: what a security-frame parser must produce from one
// bounded frame, and the normalized advertised-settings record derived from
// beacons / probe responses.
//
// These are CONTRACTS. The parser implementation is chosen in G02 and built in
// G04 behind FrameParser. Nothing here allocates or keeps pointers into the
// frame; every result is a fixed-size value the caller may store or discard.
//
// Error and unknown semantics (binding):
//   * A frame that cannot be fully validated is never reported as open, WEP or
//     any complete grade. Independent, structurally validated WPA/RSN elements
//     may remain as partial evidence, with settings_complete == false. Invalid
//     elements never expose trusted suites. G05 may report a confirmed legacy
//     risk from a valid element even when another element blocks a full grade.
//   * Unknown AKMs/ciphers are preserved as the Unknown bit of the set; they
//     block a complete grade in G05 but do not erase the known weaker options.
//   * Hidden, empty and non-UTF-8 SSIDs are distinct facts carried as raw
//     bytes plus flags. No control characters are injected; display code
//     sanitizes at the presentation layer, never here.
namespace guardian {

enum class FrameKind : std::uint8_t {
    Unknown,
    Beacon,
    ProbeResponse,
    Deauthentication,
    Disassociation,
    Authentication,
    AssociationRequest,
    AssociationResponse,
    Action,
    OtherManagement,
    Control,
    Data,
    EapolData, // recognized LLC/SNAP EAPOL EtherType; G16G: an EAPOL-Key body is decoded into ParseResult::eapol
    // G16E (appended so recorded integer values stay stable):
    ProbeRequest,          // subtype 4: requested SSID (or wildcard), source address
    ReassociationRequest,  // subtype 2
    ReassociationResponse  // subtype 3
};

enum class ParseStatus : std::uint8_t {
    Complete,    // every field the parser emits was validated
    Unsupported, // valid frame of a kind or option this parser does not decode
    Malformed,   // structural failure; only explicitly valid independent fields survive
    Truncated,   // input shorter than the frame claims (FrameSpan::truncated or short IE tail)
    Unrelated    // not a frame kind Guardian looks at (e.g. most data/control)
};

// Where validation stopped. Documented so fixtures can assert the exact rule.
enum class ParseError : std::uint8_t {
    None,
    ShortMacHeader,
    ShortFixedBody,
    IeOverrun,            // an IE length exceeded the remaining body
    SuiteCountOverflow,   // RSN/WPA count larger than bytes remaining or > bound
    DuplicateConflict,    // two copies of an element with different content
    PmfInconsistent,      // MFPR set without MFPC
    BadVendorOui,         // vendor element shorter than its 3-byte OUI
    UnsupportedVersion,   // frame-control protocol version != 0, or RSN/WPA version != 1
    FcsFailed,            // RxStatus::FcsError: bytes rejected before parsing
    ReceiveFailed,        // RxStatus::DriverError: no trusted parse
    // Added in G04 so fixtures can name the exact rule (parser.hpp is the
    // contract; these are additional documented outcomes, not new semantics):
    SuiteCountZero,       // RSN/WPA pairwise or AKM count of 0: an empty list is not an advertisement
                          // (the pinned SDK supplicant parser rejects it as well); never defaulted
    BadElementLength,     // element length invalid for its type: field cut inside the element,
                          // oversized SSID, DS Parameter != 1 byte, MME not 16/24, trailing bytes
    Other
};

enum class SsidKind : std::uint8_t {
    Absent, // no SSID element
    Hidden, // zero length (an AP that hides its name)
    Present,
    // G16E (appended): a hidden network that keeps its name length by sending
    // N NUL bytes. A distinct fact, never a different name: detectors comparing
    // names (SSID confusion) must not count it as a mismatch.
    HiddenNul,
    // G16E: a zero-length SSID in a probe request = "any network" (wildcard),
    // not a hidden network.
    Wildcard
};
// Either form of a hidden advertised name (zero length or NUL bytes).
constexpr bool hidden_ssid(SsidKind k) { return k == SsidKind::Hidden || k == SsidKind::HiddenNul; }

// Authentication Algorithm Number (9.4.1.1). Values the passive detectors read.
namespace auth_algorithm {
constexpr std::uint16_t OpenSystem = 0;
constexpr std::uint16_t SharedKey = 1;
constexpr std::uint16_t FastBssTransition = 2;
constexpr std::uint16_t Sae = 3;           // SAE: transaction 1 = Commit, 2 = Confirm
constexpr std::uint16_t FilsSk = 4;
constexpr std::uint16_t FilsSkPfs = 5;
constexpr std::uint16_t FilsPk = 6;
constexpr std::uint16_t Pasn = 7;
} // namespace auth_algorithm

// Bit sets. Multiple options may be advertised at once; the policy layer
// (G05) reduces them with the weakest-advertised rule. Unknown is set when an
// OUI/type the parser does not recognise appears; it is never dropped.
namespace akm {
constexpr std::uint16_t Wpa1Psk      = 1u << 0;  // WPA vendor IE, PSK
constexpr std::uint16_t Wpa1Eap      = 1u << 1;  // WPA vendor IE, 802.1X
constexpr std::uint16_t Psk          = 1u << 2;  // RSN 00-0F-AC:2
constexpr std::uint16_t PskSha256    = 1u << 3;  // RSN 00-0F-AC:6
constexpr std::uint16_t FtPsk        = 1u << 4;  // RSN 00-0F-AC:4
constexpr std::uint16_t Sae          = 1u << 5;  // RSN 00-0F-AC:8
constexpr std::uint16_t FtSae        = 1u << 6;  // RSN 00-0F-AC:9
constexpr std::uint16_t SaeExt       = 1u << 7;  // RSN 00-0F-AC:24
constexpr std::uint16_t Owe          = 1u << 8;  // RSN 00-0F-AC:18
constexpr std::uint16_t Eap          = 1u << 9;  // RSN 00-0F-AC:1
constexpr std::uint16_t EapSha256    = 1u << 10; // RSN 00-0F-AC:5
constexpr std::uint16_t FtEap        = 1u << 11; // RSN 00-0F-AC:3
constexpr std::uint16_t EapSuiteB    = 1u << 12; // RSN 00-0F-AC:11
constexpr std::uint16_t EapSuiteB192 = 1u << 13; // RSN 00-0F-AC:12
constexpr std::uint16_t Unknown      = 1u << 15;
} // namespace akm

namespace cipher {
constexpr std::uint16_t UseGroup  = 1u << 0;  // 00-0F-AC:0 (pairwise only)
constexpr std::uint16_t Wep40     = 1u << 1;
constexpr std::uint16_t Tkip      = 1u << 2;
constexpr std::uint16_t Ccmp128   = 1u << 3;
constexpr std::uint16_t Wep104    = 1u << 4;
constexpr std::uint16_t BipCmac128 = 1u << 5; // group management only
constexpr std::uint16_t Gcmp128   = 1u << 6;
constexpr std::uint16_t Gcmp256   = 1u << 7;
constexpr std::uint16_t Ccmp256   = 1u << 8;
constexpr std::uint16_t BipGmac128 = 1u << 9;
constexpr std::uint16_t BipGmac256 = 1u << 10;
constexpr std::uint16_t BipCmac256 = 1u << 11;
constexpr std::uint16_t Unknown   = 1u << 15;
} // namespace cipher

enum class Pmf { Unknown, Disabled, Optional, Required };

// Validity is per element, so unknown options or a malformed sibling cannot
// erase independently validated legacy evidence. Conflicting duplicate IEs
// invalidate that entire protocol element; never union competing copies.
enum class ElementState : std::uint8_t { Absent, Valid, Malformed, Truncated, Conflicting };

// Wire selectors encoded OUI in the upper 24 bits, suite type in the low 8.
// Preserve unknown selectors instead of discarding their provenance. The
// parser validates the complete list before publishing it. Overflow rejects
// the element; it must not silently keep the first capacity entries.
struct SuiteList {
    static constexpr std::size_t capacity = 16;
    std::array<std::uint32_t, capacity> selectors{};
    std::uint8_t count{};
    std::uint16_t kinds{}; // akm:: or cipher:: mask; includes Unknown if any
};

struct SuiteSelector {
    std::uint32_t selector{};
    std::uint16_t kind{}; // exactly one mapped bit or Unknown
    bool present{};       // false for a genuinely absent optional field
};

// One protocol's complete structural decode. WPA and RSN never share a group
// cipher, pairwise list or AKM list. Fields are trusted only when state=Valid.
// Unknown selectors are structurally Valid but block a complete policy grade.
struct SecurityElement {
    ElementState state{ElementState::Absent};
    SuiteList akms{};
    SuiteList pairwise{};
    SuiteSelector group{};
    SuiteSelector group_management{}; // RSN only; absent for WPA
    Pmf pmf{Pmf::Unknown};            // RSN only, never attributed to WPA
};

struct AdvertisedSettings {
    bool privacy_valid{};            // fixed header was validated
    bool privacy_bit{};
    SecurityElement wpa{};           // vendor WPA IE, OUI 00-50-F2 type 1
    SecurityElement rsn{};           // RSN IE id 48
    ElementState owe_transition{ElementState::Absent}; // WFA OUI 50-6F-9A type 28
    bool ds_channel_present{};
    std::uint8_t ds_channel{};        // independently validated DS Parameter IE
};

// G16E: management-body facts the passive detectors need. Each group is
// trusted only when its own flag / ElementState says so; a malformed or cut
// field leaves its group zeroed (never a guessed value). These facts never
// enter AdvertisedSettings: they cannot change the security rating.
struct ManagementFacts {
    // Authentication (9.3.3.11) fixed fields. Algorithm-specific bodies (SAE
    // scalar/element, FILS, challenge text) are not decoded.
    bool auth_valid{};
    std::uint16_t auth_algorithm{};      // auth_algorithm::
    std::uint16_t auth_transaction{};    // Authentication Transaction Sequence Number
    // Status Code (9.4.1.9): Authentication and (Re)Association Response.
    bool status_valid{};
    std::uint16_t status_code{};
    // (Re)Association Request fixed fields (9.3.3.6 / 9.3.3.8).
    bool listen_interval_valid{};
    std::uint16_t listen_interval{};
    Mac current_ap{};                    // Reassociation Request only
    // Beacon / Probe Response fixed fields (9.3.3.3 / 9.3.3.11).
    bool timing_valid{};
    std::uint64_t tsf{};                 // Timestamp (TSF, microseconds)
    std::uint16_t beacon_interval_tu{};  // Beacon Interval (TU = 1024 us)
    // Channel Switch Announcement element 37 (9.4.2.18): exactly 3 bytes.
    ElementState csa{ElementState::Absent};
    std::uint8_t csa_mode{};             // 1: transmissions must stop until the switch
    std::uint8_t csa_new_channel{};
    std::uint8_t csa_count{};            // target beacon transmission times until the switch
    // Quiet element 40 (9.4.2.22): exactly 6 bytes each; several are legal.
    ElementState quiet{ElementState::Absent};
    std::uint8_t quiet_elements{};
    std::uint16_t quiet_max_duration_tu{}; // longest Quiet Duration among the valid elements
    // Multiple BSSID element 71 (9.4.2.45): presence (at least the MaxBSSID Indicator).
    ElementState multi_bssid{ElementState::Absent};
    // Element ID 222: not a public IEEE 802.11-2020 element; some community
    // devices carry a status payload there. Counted, summed and a bounded head
    // copy only; never interpreted here.
    static constexpr std::size_t element222_head_capacity = 32;
    std::uint8_t element222_count{};
    std::uint16_t element222_bytes{};
    std::array<std::uint8_t, element222_head_capacity> element222_head{};
    std::uint8_t element222_head_size{};
    // OWE Transition Mode partner (valid only when settings.owe_transition is Valid).
    Mac owe_partner_bssid{};
    std::array<std::uint8_t, 32> owe_partner_ssid{};
    std::uint8_t owe_partner_ssid_size{};
};

// G16G: which 4-way-handshake message an EAPOL-Key frame is, read from its Key
// Information bits only (IEEE 802.11-2020 12.7.2 / 12.7.6). A reading of the
// bytes, never a statement about who sent them or whether a MIC is correct.
enum class EapolMessage : std::uint8_t {
    None,   // not a pairwise handshake message (request, or an unknown bit combination)
    M1,     // pairwise, Key Ack, no Key MIC: authenticator -> supplicant, carries the ANonce
    M2,     // pairwise, no Ack, Key MIC, not Secure, key data present: supplicant -> authenticator
    M3,     // pairwise, Key Ack, Key MIC: authenticator -> supplicant
    M4,     // pairwise, no Ack, Key MIC, Secure (or no key data): supplicant -> authenticator
    Group   // group-key handshake (Key Type = group)
};

// G16G: the bounded EAPOL-Key decode of an unprotected EAPOL data frame. Valid
// only when state == Valid (ParseResult::status Complete); every other state
// leaves the fields zeroed. Nothing is verified (no keys): a MIC is never
// checked and a nonce is never judged except "all zero". The PMKID value
// itself is never kept, only that a PMKID KDE was present.
struct EapolKeyFacts {
    ElementState state{ElementState::Absent};
    std::uint8_t version{};        // EAPOL protocol version (1, 2 or 3 seen in the field)
    std::uint8_t descriptor{};     // 2 = IEEE 802.11 (RSN), 254 = WPA
    std::uint16_t key_info{};      // Key Information, host order
    std::uint16_t key_length{};
    std::uint64_t replay_counter{};
    bool nonce_zero{};             // Key Nonce is 32 zero bytes
    // Key MIC size located from the body length (16, 24 or 32); 0 when the
    // key-data length could not be placed unambiguously (then key_data_known
    // is false and no key-data fact is reported).
    std::uint8_t mic_size{};
    bool key_data_known{};
    std::uint16_t key_data_length{};
    bool key_data_encrypted{};     // Key Information bit 12: key data not readable
    bool pmkid_present{};          // a PMKID KDE (DD, 00-0F-AC type 4, 16 bytes) in readable key data
    // G16J: that PMKID is 16 equal bytes (all zero included) or its first 15
    // bytes are a constant non-zero step ramp (11 22 33 ...). A real PMKID is
    // a keyed-hash output; such a value is a template. The value is not kept.
    bool pmkid_synthetic{};
    EapolMessage message{EapolMessage::None};
    // Roles from the Key Ack bit: Ack messages travel authenticator -> supplicant
    // (Address 2 -> Address 1), the others supplicant -> authenticator. Spoofable bytes.
    Mac authenticator{};
    Mac supplicant{};
};
namespace key_info {
constexpr std::uint16_t Pairwise = 1u << 3;
constexpr std::uint16_t Install = 1u << 6;
constexpr std::uint16_t Ack = 1u << 7;
constexpr std::uint16_t Mic = 1u << 8;
constexpr std::uint16_t Secure = 1u << 9;
constexpr std::uint16_t Error = 1u << 10;
constexpr std::uint16_t Request = 1u << 11;
constexpr std::uint16_t EncryptedKeyData = 1u << 12;
} // namespace key_info

// Result of parsing one frame. Value type, no pointers into the frame.
struct ParseResult {
    ParseStatus status{ParseStatus::Unrelated};
    ParseError error{ParseError::None};
    FrameKind kind{FrameKind::Unknown};

    bool header_valid{}; // false means addresses/sequence must not feed detectors

    // Header addresses as transmitted. For management frames addr3 is the
    // BSSID; identity.bssid is filled from it. Spoofable: these are facts
    // about the bytes received, not about who sent them.
    Mac addr1{};
    Mac addr2{};
    Mac addr3{};
    bool protected_frame{};      // Protected Frame bit; not proof the body is encrypted
    bool retry{};                // Retry bit; detectors dedupe with care (G06)
    std::uint16_t sequence{};    // 12-bit sequence number
    std::uint8_t fragment{};     // 4-bit fragment number
    // G16E header facts (valid with header_valid). Both are bytes as received.
    bool power_management{};     // Frame Control Power Management bit (9.2.4.1.7): "the transmitter will sleep"
    bool addr2_local{};          // Address 2 locally administered bit: randomized-looking, never an identity
    // G16J: the Duration/ID field as received (9.2.4.2), valid with header_valid.
    std::uint16_t duration{};

    // Beacon/probe response identity and settings.
    Network identity{};
    SsidKind ssid_kind{SsidKind::Absent};
    bool ssid_utf8{};            // bytes form valid UTF-8 (false for Hidden/Absent)
    // settings_present means at least one explicitly valid field is available.
    // A full grade additionally needs status=Complete AND settings_complete.
    // Invalid/truncated/conflicting elements have zeroed payload fields. Valid
    // independent elements may survive for separate legacy-risk findings.
    bool settings_present{};
    bool settings_complete{};
    AdvertisedSettings settings{};

    // Deauthentication/Disassociation reason. Readable only when the frame is
    // unprotected or a supported integrity-only group-management format has
    // been structurally decoded. Protected unicast bodies remain unreadable;
    // unsupported protected formats also keep this false. Readable is not
    // authenticated: never claim MIC verification without keys.
    std::uint16_t reason_code{};
    bool reason_readable{};

    // G16E: probe/auth/(re)association bodies and beacon extras.
    ManagementFacts mgmt{};

    // G16G: EAPOL-Key body of an unprotected EAPOL data frame (kind EapolData).
    EapolKeyFacts eapol{};
};

// Stateless parser boundary. Implementations are the G02 choice (libwifi port,
// SDK supplicant parser or independent) and may not allocate. The span is
// valid only during the call.
class FrameParser {
public:
    virtual ~FrameParser() = default;
    virtual ParseResult parse(const FrameSpan& frame, const RxMeta& meta) const = 0;
};

} // namespace guardian

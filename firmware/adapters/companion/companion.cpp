#include "companion.hpp"
#include <algorithm>
#include <cstring>

namespace guardian::companion {

// ---- buttons ---------------------------------------------------------------
Action Key::sample(bool down, Millis now) {
    if (!started_) { started_ = true; raw_ = down; raw_since_ = now; }
    if (down != raw_) { raw_ = down; raw_since_ = now; }
    Action out = Action::None;
    const bool settled = now >= raw_since_ && now - raw_since_ >= timing_.debounce_ms;
    if (settled && (!known_ || stable_ != raw_)) {
        known_ = true; stable_ = raw_;
        if (!stable_) {
            if (pressing_ && !fired_) out = short_;
            pressing_ = false; armed_ = true;
        } else if (armed_) {
            pressing_ = true; fired_ = false; pressed_at_ = now;
        }
    }
    if (pressing_ && stable_ && !fired_ && now >= pressed_at_ && now - pressed_at_ >= timing_.long_ms) {
        fired_ = true; out = long_;
    }
    return out;
}

// ---- persistence codec --------------------------------------------------------
namespace {
constexpr std::uint8_t magic[4] = {'G', 'S', 'E', 'L'};
constexpr std::uint16_t format = 1;

std::uint32_t crc32(const std::uint8_t* p, std::size_t n) {
    std::uint32_t c = 0xffffffffu;
    for (std::size_t i = 0; i < n; ++i) {
        c ^= p[i];
        for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
    }
    return ~c;
}

class Writer {
public:
    explicit Writer(std::uint8_t* p) : p_(p) {}
    void u8(std::uint8_t v) { p_[n_++] = v; }
    void u16(std::uint16_t v) { u8(static_cast<std::uint8_t>(v)); u8(static_cast<std::uint8_t>(v >> 8)); }
    void u32(std::uint32_t v) { u16(static_cast<std::uint16_t>(v)); u16(static_cast<std::uint16_t>(v >> 16)); }
    void bytes(const std::uint8_t* b, std::size_t n) { std::memcpy(p_ + n_, b, n); n_ += n; }
    std::size_t size() const { return n_; }
private:
    std::uint8_t* p_;
    std::size_t n_{};
};

class Reader {
public:
    explicit Reader(const std::uint8_t* p) : p_(p) {}
    std::uint8_t u8() { return p_[n_++]; }
    std::uint16_t u16() { const auto lo = u8(); return static_cast<std::uint16_t>(lo | (u8() << 8)); }
    std::uint32_t u32() { const auto lo = u16(); return lo | (static_cast<std::uint32_t>(u16()) << 16); }
    void bytes(std::uint8_t* b, std::size_t n) { std::memcpy(b, p_ + n_, n); n_ += n; }
    bool boolean(bool& ok) { const auto v = u8(); ok &= v <= 1; return v == 1; }
private:
    const std::uint8_t* p_;
    std::size_t n_{};
};

void put(Writer& w, const ApprovedAp& ap) {
    w.bytes(ap.network.bssid.data(), 6); w.bytes(ap.network.ssid.data(), 32); w.u8(ap.network.ssid_size);
    w.u8(static_cast<std::uint8_t>((ap.settings_known ? 1u : 0u) | (ap.channel_known ? 2u : 0u) | (ap.watch_impostors ? 4u : 0u)));
    w.u8(static_cast<std::uint8_t>(ap.band)); w.u8(ap.channel);
    const auto& f = ap.settings;
    w.u8(f.privacy_bit ? 1 : 0); w.u8(static_cast<std::uint8_t>(f.wpa_state));
    w.u16(f.wpa_akms); w.u16(f.wpa_pairwise); w.u16(f.wpa_group);
    w.u8(static_cast<std::uint8_t>(f.rsn_state));
    w.u16(f.rsn_akms); w.u16(f.rsn_pairwise); w.u16(f.rsn_group); w.u16(f.rsn_group_management);
    w.u8(static_cast<std::uint8_t>(f.pmf)); w.u8(static_cast<std::uint8_t>(f.owe_transition));
}

bool get(Reader& r, ApprovedAp& ap) {
    bool ok = true;
    r.bytes(ap.network.bssid.data(), 6); r.bytes(ap.network.ssid.data(), 32); ap.network.ssid_size = r.u8();
    const auto flags = r.u8(); ok &= (flags & ~7u) == 0;
    ap.settings_known = flags & 1u; ap.channel_known = flags & 2u; ap.watch_impostors = flags & 4u;
    const auto band = r.u8(); ok &= band < static_cast<unsigned>(Band::Count); ap.band = static_cast<Band>(band);
    ap.channel = r.u8();
    auto& f = ap.settings;
    f.privacy_bit = r.boolean(ok); f.wpa_state = static_cast<ElementState>(r.u8());
    f.wpa_akms = r.u16(); f.wpa_pairwise = r.u16(); f.wpa_group = r.u16();
    f.rsn_state = static_cast<ElementState>(r.u8());
    f.rsn_akms = r.u16(); f.rsn_pairwise = r.u16(); f.rsn_group = r.u16(); f.rsn_group_management = r.u16();
    f.pmf = static_cast<Pmf>(r.u8()); f.owe_transition = static_cast<ElementState>(r.u8());
    // Enum ranges and reserved bits are then checked by PersistedSelection::valid().
    // Unused fields must be zero so one stored value has one meaning.
    if (!ap.settings_known) ok &= f == SettingsFingerprint{} && !f.privacy_bit;
    if (!ap.channel_known) ok &= ap.channel == 0;
    // Bytes after the SSID length are not part of the identity: require zeros.
    for (std::size_t i = std::min<std::size_t>(ap.network.ssid_size, 32); i < 32; ++i) ok &= ap.network.ssid[i] == 0;
    return ok;
}

// Normalize a record so equal selections encode identically (unused fields zero).
ApprovedAp normalized(ApprovedAp ap) {
    if (!ap.settings_known) ap.settings = {};
    if (!ap.channel_known) ap.channel = 0;
    for (std::size_t i = std::min<std::size_t>(ap.network.ssid_size, 32); i < 32; ++i) ap.network.ssid[i] = 0;
    return ap;
}
} // namespace

std::size_t encode(const PersistedSelection& r, std::uint8_t* out, std::size_t capacity) {
    if (!out || capacity < record_bytes || !r.valid()) return 0;
    std::memset(out, 0, record_bytes);
    Writer w(out);
    w.bytes(magic, 4); w.u16(format); w.u16(r.version);
    w.u8(r.has_selection ? 1 : 0); w.u8(r.approved_count);
    put(w, r.has_selection ? normalized(r.selected) : ApprovedAp{});
    for (std::size_t i = 0; i < PersistedSelection::max_approved; ++i)
        put(w, i < r.approved_count ? normalized(r.approved[i]) : ApprovedAp{});
    w.u32(crc32(out, w.size()));
    return w.size() == record_bytes ? record_bytes : 0;
}

bool decode(const std::uint8_t* in, std::size_t size, PersistedSelection& out) {
    if (!in || size != record_bytes || std::memcmp(in, magic, 4) != 0) return false;
    Reader crc_reader(in + record_bytes - 4);
    if (crc_reader.u32() != crc32(in, record_bytes - 4)) return false;
    Reader r(in + 4);
    if (r.u16() != format) return false;
    PersistedSelection p{}; bool ok = true;
    p.version = r.u16(); p.has_selection = r.boolean(ok); p.approved_count = r.u8();
    ApprovedAp unused{};
    ok &= get(r, p.has_selection ? p.selected : unused);
    for (std::size_t i = 0; i < PersistedSelection::max_approved; ++i) {
        ApprovedAp ap{}; ok &= get(r, ap);
        ok &= !ap.watch_impostors; // watch applies to the selection only
        if (i < p.approved_count && i < p.approved.size()) p.approved[i] = ap;
        else ok &= ap.network.ssid_size == 0 && ap.network.bssid == Mac{};
    }
    if (!p.has_selection) ok &= unused.network.ssid_size == 0 && unused.network.bssid == Mac{};
    if (!ok || !p.valid()) return false;
    out = p;
    return true;
}

bool EncodedSelectionStore::load(PersistedSelection& out) const {
    std::array<std::uint8_t, record_bytes> buf{}; std::size_t size = 0;
    switch (storage_.read(buf.data(), buf.size(), size)) {
    case BlobRead::Absent: last_load_ = Loaded::Absent; return false;
    case BlobRead::Error: last_load_ = Loaded::Unreadable; return false;
    case BlobRead::Ok: break;
    }
    const bool ok = size <= buf.size() && decode(buf.data(), size, out);
    last_load_ = ok ? Loaded::Valid : Loaded::Unreadable;
    return ok;
}
bool EncodedSelectionStore::save(const PersistedSelection& r) {
    std::array<std::uint8_t, record_bytes> buf{};
    const auto n = encode(r, buf.data(), buf.size());
    return n != 0 && storage_.write(buf.data(), n);
}

const char* store_text(StoreState s) {
    switch (s) {
    case StoreState::Empty: return "No saved network";
    case StoreState::Restored: return "Saved network restored";
    case StoreState::Rejected: return "Saved record unreadable; not used";
    case StoreState::Saved: return "Choice saved";
    case StoreState::SaveFailed: return "Choice NOT saved (storage)";
    }
    return "";
}

// ---- controller ------------------------------------------------------------
Companion::Companion(const MonotonicClock& clock, measurement::Monitor& monitor, EncodedSelectionStore& store,
                     DisplayCapabilities display, Origin origin, BlobStorage* onboarding_seen)
    : clock_(clock), monitor_(monitor), store_ref_(store), presenter_(display, origin), onboarding_seen_(onboarding_seen) {
    presenter_.set_text_budget(details_text_budget());   // G16C: details pages planned by wrapped rows
}

Instant Companion::now() const { return {clock_.epoch(), clock_.now(), true}; }

StoreState Companion::boot() {
    if (onboarding_seen_) {
        std::uint8_t flag = 0; std::size_t size = 0;
        const bool seen = onboarding_seen_->read(&flag, 1, size) == BlobRead::Ok && size == 1 && flag == 1;
        onboarding_page_ = seen ? onboarding_pages : 0; // absent or unreadable: show it (safe)
    }
    PersistedSelection record{};
    if (!store_ref_.load(record))
        store_ = store_ref_.last_load() == EncodedSelectionStore::Loaded::Unreadable ? StoreState::Rejected : StoreState::Empty;
    else store_ = monitor_.restore(record) ? (record.has_selection ? StoreState::Restored : StoreState::Empty)
                                           : StoreState::Rejected;
    // G16J: a selection saved before the same-name watch existed is upgraded once (and saved).
    if (store_ == StoreState::Restored && presenter_.impostor_watch() && !monitor_.scope().selected().watch_impostors
        && monitor_.set_watch(true) && !store_ref_.save(persist(monitor_.scope()))) store_ = StoreState::SaveFailed;
    if (settings_) presenter_.set_device(settings_->load());   // G24: corrupt or absent = the defaults (said in STATUS)
    saved_revision_ = monitor_.scope_revision();                // G25: what boot restored is what is stored
    tick();
    return store_;
}

bool Companion::receive(const measurement::Packet& packet) {
    Candidate c{}; bool offered = false;
    const bool selected = monitor_.receive(packet, &c, &offered);
    if (!offered) return selected;
    for (std::size_t i = 0; i < pending_count_; ++i) {
        if (pending_[i].network == c.network) { if (c.seen.at >= pending_[i].seen.at) pending_[i] = c; return selected; }
    }
    if (pending_count_ < pending_.size()) pending_[pending_count_++] = c;
    else if (pending_dropped_ != 0xffffffffu) ++pending_dropped_;
    return selected;
}

void Companion::tick() {
    // G25: the Monitor re-baselined a channel move (or an accept) without an owner request: store the scope.
    if (monitor_.scope_revision() != saved_revision_) save();
    const RouterState router = monitor_.router();
    presenter_.update(monitor_.snapshot(), now(), &monitor_.scope(), &router);
    for (std::size_t i = 0; i < pending_count_; ++i) presenter_.offer(pending_[i]);
    pending_count_ = 0;
}

bool Companion::input(Action action) {
    if (onboarding()) {
        // Any short press moves on; holds are ignored so a long press never skips by accident.
        if (action != Action::Primary && action != Action::Secondary) return false;
        if (++onboarding_page_ >= onboarding_pages) {
            const std::uint8_t done = 1;
            if (onboarding_seen_) onboarding_seen_->write(&done, 1); // failure: shown again next boot
        }
        return true;
    }
    // Device list (owner, KISS): blue = next row, side = choose, hold side = back.
    // G16J: hold blue on a row with the selected network's NAME and another BSSID says "this
    // AP is mine too" (or takes that back): it feeds the approved set, so the owner's own mesh
    // node or extender never raises the same-name ALERT. On every other row it does nothing.
    if (action == Action::PrimaryLong && presenter_.screen() == Screen::Picker) {
        const auto& v = presenter_.picker();
        if (!v.count || v.cursor >= v.count || !v.entries[v.cursor].approvable) return false;
    }
    const bool changed = presenter_.handle(action, now());
    if (presenter_.has_request()) { apply(presenter_.take_request()); tick(); return true; }
    if (presenter_.has_settings_save()) {   // G24: a hold of FRONT on the Settings screen, written at once
        const DeviceChoices v = presenter_.take_settings_save();
        presenter_.settings_saved(settings_ && settings_->save(v));
        return true;
    }
    return changed;
}

bool Companion::discovering() const {
    return presenter_.screen() == Screen::Picker || !monitor_.scope().has_selection();
}

void Companion::apply(const OwnerRequest& r) {
    bool ok = false;
    switch (r.kind) {
    case RequestKind::Select: ok = monitor_.select(r.ap); break;
    case RequestKind::Approve: ok = monitor_.approve(r.ap); break;
    case RequestKind::Revoke: ok = monitor_.revoke(r.ap.network.bssid); break;
    case RequestKind::AcceptChange: ok = monitor_.accept_router_change(r.ap.network.bssid); break;   // G25
    case RequestKind::None: return;
    }
    if (ok) save();
}

void Companion::set_impostor_watch(bool on) {
    presenter_.set_impostor_watch(on);
    const auto& scope = monitor_.scope();
    if (scope.has_selection() && scope.selected().watch_impostors != on && monitor_.set_watch(on)) save();
}

void Companion::save() {
    store_ = store_ref_.save(persist(monitor_.scope())) ? StoreState::Saved : StoreState::SaveFailed;
    saved_revision_ = monitor_.scope_revision();   // G25: a failed write is shown (StoreState), not retried every tick
}

} // namespace guardian::companion

namespace guardian::companion {
void Companion::render(const Status& status, Frame& frame) {
    tick();
    if (onboarding()) { compose_onboarding(onboarding_page_, frame); return; }
    Status with_radar = status;                 // G16E: the threat radar from the real Monitor
    with_radar.radar = monitor_.radar();
    compose(presenter_, with_radar, frame);
}
void Companion::render_dim(const Status& status, Frame& frame) {
    tick();
    if (onboarding()) { compose_onboarding(onboarding_page_, frame); return; }
    Status with_radar = status;
    with_radar.radar = monitor_.radar();
    compose_dim(presenter_, with_radar, frame);
}
}

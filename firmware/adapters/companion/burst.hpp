#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include "guardian/canvas.hpp"
#include "guardian/time.hpp"
#include "persona.hpp"

// G16I: the snow-globe burst; G16O: the particles obey gravity (pile, slide, reform when still). Owner 2026-11-17: "if we shake it: THOUSAND PARTICLES LIKE SNOW GLOBE,
// slowly reforming face". SDK-free, host-tested. Decoration only: it replaces the portrait in the
// face band for a few seconds and never touches the header, the HUD or any text; the composer
// cancels it the moment an ALERT shows (screens.cpp draw()).
//
//  * One particle per LIT 3x3 block of the current portrait (grid 45 x 54; the last row is 1 px tall):
//    1,357..1,391 particles per rated face (MEASURED 2026-11-17). Colours are not stored: a particle
//    paints its own home pixels, read through a persona::PixelSource, so the face keeps its colours.
//  * 10 bytes a particle, capacity 1600 = 16,000 B, plus the 424 B pile map (the board places the object in PSRAM).
//    begin() refuses an art with more lit blocks (the NoData silhouette, 1,575, never bursts anyway):
//    never a partial face.
//  * Phases (G16O, owner 2026-11-18: "when shake, particles should assume physics, fall... if one
//    keeps tilting to sides, particles should fall (gravity)... it only comes back with no or very few
//    tilting... if one shakes and keeps shaking, particles keep falling on gravity"):
//      explode  - thrown outward from the middle of the mask at 120..300 px/s, plus the shove, for
//                 0.5 s (as a fraction of `total_s`, TUNE burst.s, default 3.5 s);
//      drift    - falls under gravity (250 px/s^2 along the given up vector, so it follows the stick)
//                 with drag, bouncing off the edges of the band, and SETTLES against the edge that is
//                 down: a block that reaches the floor or a lying block stays there (no bounce, like
//                 snow), in a 3 px cell of its own (the pile map below), so the blocks stack in rows
//                 and never overlap. For AS LONG AS THE STICK IS HANDLED the pile follows the down
//                 of the moment: a lying block whose next cell toward down is free falls again, one
//                 with a free cell diagonally below topples into it (no towers), layer by layer;
//      reform   - every block eases (smoothstep) from where it lay or flew to its home in 2.0 s (the
//                 rest of `total_s`). The last frame has every block exactly on its home: at the
//                 identity pose the band then equals the still portrait pixel for pixel.
//    The reform is gated by STILLNESS, not by a timer. The stick is "moving" in a frame when the up
//    vector turned faster than `still_dps` since the frame before, or the shove is above `still_g`
//    (TUNE burst.still_dps 10, burst.still_g 0.10; MEASURED on the nine recorded traces at 25 fps:
//    hand-held still or lying = moving in 0..2 % of the frames, handling, FRONT x3 and the gentlest
//    shake in 92..98 %). The reform starts once the stick has been still for `calm_s` (burst.calm_s,
//    1.0 s), never earlier than explode + drift after the last shake (1.5 s: a shake on a stick that
//    is then left alone is the 3.5 s show of G16I), and never later than `max_s` after the last shake
//    (burst.max_s, 20 s: a stick carried about does not stay a pile forever). Once it started it runs
//    to the end; only a new shake (kick) interrupts it. Lying flat (less than 0.2 of gravity across
//    the glass) there is no down: nothing settles or slides.
//  * The pile map: one bit per 3 px cell, 45 x 53 cells standing on the band's bottom edge (the top
//    pixel row of the band is outside it). Flying blocks pass through each other and only meet lying
//    ones, so a frame costs one pass over the particles (no particle-against-particle search).
//  * Homes follow the face's live pose (upright rotation, fit scale, shift): the cloud leaves from
//    where the face is drawn and reforms where it will be drawn, never as a sideways face.
//    Blocks stay axis-aligned and show their pixels turned by the nearest quarter turn: on its side or
//    upside down the landed face is the turned portrait; in between it is a 3x3 mosaic until the warp
//    takes over on the next frame.
//  * No warp and no allocation while a burst runs. Positions are 1/64 px, velocities 1/64 px/s.
namespace guardian::companion::burst {

constexpr int block = 3;
constexpr int grid_w = persona::art_w / block;                    // 45
constexpr int grid_h = (persona::art_h + block - 1) / block;      // 54
constexpr std::size_t capacity = 1600;
struct Range { float lo, hi; };
constexpr Range total_s_range{1.5f, 10.0f};                       // TUNE burst.s
constexpr float default_total_s = 3.5f;
constexpr float explode_part = 0.5f / 3.5f, drift_part = 1.0f / 3.5f;   // the rest reforms
constexpr int pile_w = grid_w, pile_h = persona::art_h / block;    // 45 x 53 whole 3 px cells
// G16O: the reform waits for a still stick (TUNE burst.still_dps, burst.still_g, burst.calm_s, burst.max_s).
constexpr Range still_dps_range{2.0f, 60.0f}, still_g_range{0.02f, 1.0f}, calm_s_range{0.2f, 5.0f}, max_s_range{5.0f, 120.0f};
struct Params {
    float total_s{default_total_s};   // explode 1/7 of it, the shortest fall 2/7, the reform 4/7
    // G24 carry-over (G23 owner run, firmware/evidence/sticks3-G23-20261121.log step 11, still_trace on the slow-tilt
    // recording and the recorded still / setdown / walk traces): 10 and 1.0 s (from 12 and 0.6 s): the slow tilt
    // reaches calm 0 times (2 at the old values); hand-held 4, set down 1, lying still 1.
    float still_dps{10.0f};           // the up vector turning faster than this between two frames: the stick is moving
    float still_g{0.10f};             // ... or a shove above this
    float calm_s{1.0f};               // still for this long: the reform starts
    float max_s{20.0f};               // after the last shake the reform starts at the latest now
};

struct Particle { std::int16_t x, y, vx, vy; std::uint16_t home; };   // home: grid cell in the low 12 bits; bit 15 = lying in the pile
static_assert(sizeof(Particle) == 10, "10 bytes a particle");
enum class Phase : std::uint8_t { Idle, Explode, Drift, Reform };
struct Point { float x{}, y{}; };

class Burst {
public:
    void configure(float total_s);                                // clamped to total_s_range; the other values stay
    void configure(const Params&);                                // every value clamped to its range (not finite: its default)
    const Params& params() const { return params_; }
    float total_s() const { return params_.total_s; }
    // Starts a burst of `art` (art_bytes; identity only) whose pixels `src` holds, at the face's
    // current `pose`. lin_x/lin_y: the stick's linear acceleration in g, screen axes (+y down);
    // the particles are thrown the other way. False (and nothing changes) without pixels or when the
    // art has more than `capacity` lit blocks.
    bool begin(const std::uint8_t* art, persona::PixelSource src, Millis now, const persona::Pose& pose,
               float lin_x, float lin_y, std::uint32_t seed);
    // A shake while a burst runs: every particle is thrown again from where it is (a lying one away
    // from the floor it lay on), and the stillness and maximum clocks start again. False when idle.
    bool kick(Millis now, float lin_x, float lin_y, std::uint32_t seed);
    // Advances to `now`. up_x/up_y: the world's up in screen axes (motion::Output; standing = 0,-1;
    // 0,0 = no gravity across the glass). `pose`: where the face is drawn now (the homes follow it).
    // lin_x/lin_y: the stick's linear acceleration in g (motion::Output), for the stillness rule only.
    void step(Millis now, float up_x, float up_y, const persona::Pose& pose = {}, float lin_x = 0.0f, float lin_y = 0.0f);
    std::size_t resting() const { return active() ? resting_ : 0; }   // particles lying in the pile
    bool resting(std::size_t i) const;
    void cancel() { phase_ = Phase::Idle; landed_ = false; }
    bool active() const { return phase_ != Phase::Idle; }
    Phase phase() const { return phase_; }
    const std::uint8_t* art() const { return active() ? art_ : nullptr; }
    std::size_t count() const { return active() ? count_ : 0; }
    std::uint32_t started() const { return started_; }           // bursts since boot (STATUS bursts=)
    // Paints the particles into rows [origin_y, origin_y + art_h), columns < art_w. Black is not
    // painted (the composer cleared the band). Nothing when idle.
    void paint(Canvas&, int origin_y) const;
    // Host checks: where particle i is painted (top-left, band px) and its home block in the art.
    Point position(std::size_t i) const;
    Point home(std::size_t i) const;
private:
    struct Px { std::int32_t x, y; };
    Px target(const Particle&) const;      // posed home, 1/64 px, inside the band
    Px now_at(const Particle&) const;      // current position, 1/64 px
    void set_pose(const persona::Pose&);
    void scatter(float lin_x, float lin_y, std::uint32_t seed);
    bool stirred(Millis now, float ux, float uy, float lin_x, float lin_y);   // the stillness rule for this frame
    void wake();                           // nothing lies any more (reform, kick, begin)
    bool taken(int c, int r) const { return (pile_[static_cast<std::size_t>(r)] >> c) & 1u; }
    bool free_cell(int c, int r) const { return c >= 0 && c < pile_w && r >= 0 && r < pile_h && !taken(c, r); }
    void lay(Particle&, int c, int r);     // the particle lies in this free cell
    void lift(Particle&, int c, int r);    // ... and leaves it
    bool try_rest(Particle&, std::int32_t x, std::int32_t y);
    void slide(float gx, float gy);        // one pass over the lying blocks: fall or topple toward down
    std::array<Particle, capacity> p_{};
    std::array<std::uint64_t, pile_h> pile_{};   // bit c of row r: a block lies in that cell
    persona::PixelSource src_{};
    const std::uint8_t* art_{};
    std::uint16_t count_{}, resting_{};
    Phase phase_{Phase::Idle};
    bool landed_{}, have_up_{};
    std::int8_t down_x_{}, down_y_{};      // down across the glass as a grid step (0,0: lying flat or exploding)
    Params params_{};
    Millis t0_{}, last_{}, still_since_{}, reform_at_{}, up_at_{};
    float up_[3]{};                        // the up vector of the frame before (unit, out of the glass in [2])
    std::int32_t slide_ms_{};              // time owed to the pile passes
    std::uint32_t passes_{};
    std::int32_t reform_q16_{};            // reform progress after smoothstep, 0..65536
    std::int32_t cos_q14_{16384}, sin_q14_{}, tx_{}, ty_{};   // the face pose: scale*cos, scale*sin, pivot (1/64 px)
    std::uint8_t quarter_{};               // ... and its nearest quarter turn (0..3, clockwise)
    std::uint32_t started_{};
};

} // namespace guardian::companion::burst

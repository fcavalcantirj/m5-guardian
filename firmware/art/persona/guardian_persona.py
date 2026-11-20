"""Guardian persona: original masked-guardian 3D source for the StickS3 screen (G15).

Run with Blender (tested 5.2.2 LTS, EEVEE), never with a system Python:

  blender -b -P guardian_persona.py -- build  --blend OUT.blend
  blender -b -P guardian_persona.py -- render --blend IN.blend --outdir DIR [--scale 4]

Everything is generated here from numbers (no imported mesh, texture or image),
so this file IS the editable source; the .blend it writes is the same model for
interactive editing.  Controls live on the empty GUARDIAN_CONTROLS:

  mood   0 Very good | 1 Good | 2 Medium | 3 Bad | 4 Horrible   (fractions blend)
  alert  0..1  red alert treatment, overlays any mood (NOT a sixth rating)
  pulse  0..1  alert pulse phase (halo scale and glow)

Face = a sculpted height-field mask (carved eye/mouth cavities, cheekbones,
brow ridge, nose, chin, embossed gold markings) with five relative shape keys;
brows, moustache and goatee are tapered tube meshes with the same five keys;
the cigar is a fifth-key-only mesh.  Eye/mouth/teeth/iris paint masks are baked
per mood into colour attributes and blended in the shader with the same weights.
"""
import math
import os
import sys

import bpy
import numpy as np

# ------------------------------------------------------------------ layout
FRAME_W, FRAME_H = 240, 135          # StickS3 ST7789 window
PERSONA_CX_PX = 74                   # subject centre; right ~90 px stay free for text
CAM_DIST = 14.3
CAM_Z = 0.36
YAW_DEG = 9.0                        # slight turn: depth without hiding either eye

MOODS = ["VeryGood", "Good", "Medium", "Bad", "Horrible"]
ACCENT = [(0.0, 0.85, 0.30), (0.47, 0.86, 0.31), (0.95, 0.78, 0.08),
          (1.00, 0.48, 0.04), (0.78, 0.00, 0.63)]      # companion mood colours (rim/glow only)
ALERT_RED = (1.0, 0.04, 0.03)

W_FACE, H_UP, H_DN = 0.80, 1.0, 1.12
GRID = 240

# ------------------------------------------------------------------ expressions
# eye: ucr/lcr = upper/lower lid arch height, su/sl = inner-corner slant of the lids,
#      iris radius and gaze.  brow: inner/peak/outer z + thickness per side (L,R as the viewer sees them).
# mouth: centre z, half width, corner lift c (smile +), opening h, crooked slope k,
#      teeth fraction of the opening (upper part), grit lines.  mus: moustache heading/curl.
EXPR = {
    "VeryGood": dict(
        eye=dict(ucr=.140, lcr=.050, su=0.0, sl=0.0, ir=0.0, gx=0.0, gz=0.0),
        brow=dict(L=(.47, .58, .48), R=(.47, .58, .48), t=.050),
        mouth=dict(m0=-.50, mw=.37, c=.13, h=.17, k=0.0, teeth=.62, grit=0),
        mus=dict(th0=-6, tot=215, L=.60, zc=-.285, r=.062),
        cheek=.075, tint=0.0),
    "Good": dict(
        eye=dict(ucr=.115, lcr=-.050, su=.01, sl=0.0, ir=.062, gx=0.0, gz=.01),
        brow=dict(L=(.44, .53, .44), R=(.44, .53, .44), t=.048),
        mouth=dict(m0=-.485, mw=.28, c=.075, h=.055, k=0.0, teeth=0.0, grit=0),
        mus=dict(th0=-10, tot=165, L=.58, zc=-.285, r=.060),
        cheek=.04, tint=0.0),
    "Medium": dict(
        eye=dict(ucr=.070, lcr=-.065, su=-.020, sl=0.0, ir=.055, gx=.06, gz=0.0),
        brow=dict(L=(.40, .46, .39), R=(.45, .60, .46), t=.048),
        mouth=dict(m0=-.470, mw=.23, c=0.0, h=.050, k=.035, teeth=0.0, grit=0),
        mus=dict(th0=-15, tot=105, L=.57, zc=-.285, r=.060),
        cheek=0.0, tint=0.0),
    "Bad": dict(
        eye=dict(ucr=.125, lcr=-.095, su=.085, sl=0.0, ir=.060, gx=0.0, gz=-.03),
        brow=dict(L=(.58, .59, .33), R=(.58, .59, .33), t=.050),
        mouth=dict(m0=-.475, mw=.26, c=-.10, h=.055, k=0.0, teeth=0.0, grit=0),
        mus=dict(th0=-34, tot=-35, L=.58, zc=-.29, r=.060),
        cheek=-.02, tint=0.0),
    "Horrible": dict(
        eye=dict(ucr=.090, lcr=-.075, su=-.105, sl=.030, ir=.046, gx=0.0, gz=0.0),
        brow=dict(L=(.33, .46, .55), R=(.33, .46, .55), t=.060),
        mouth=dict(m0=-.490, mw=.33, c=-.070, h=.140, k=0.0, teeth=1.0, grit=1),
        mus=dict(th0=-24, tot=45, L=.58, zc=-.29, r=.068),
        cheek=.012, tint=0.0),
}
EYE_CX, EYE_CZ, EYE_A = .34, .20, .19
CARVE = float(os.environ.get("GP_CARVE", "0.035"))           # how far the eye/mouth cavity floors sit behind the mask
EPS = 0.011            # soft edge width of every painted/carved region (model units)


# ------------------------------------------------------------------ small maths
def smooth(t):
    t = np.clip(t, 0.0, 1.0)
    return t * t * (3 - 2 * t)


def softedge(margin, eps=EPS):
    return smooth(margin / eps)


def gauss(x, z, cx, cz, sx, sz):
    return np.exp(-(((x - cx) / sx) ** 2 + ((z - cz) / sz) ** 2))


def face_width(v):
    vv = np.clip(v, -1, 1)
    return np.where(vv < 0, W_FACE * (1 - 0.50 * (-vv) ** 1.5), W_FACE * (1 - 0.14 * vv ** 2))


def uv_from_xz(x, z):
    v = np.where(z >= 0, z / H_UP, z / H_DN)
    u = x / face_width(v)
    return u, v


def xz_from_uv(u, v):
    return u * face_width(v), np.where(v >= 0, v * H_UP, v * H_DN)


# ------------------------------------------------------------------ paint/carve masks per expression
def eye_masks(x, z, e):
    """Soft eye-opening mask, iris mask (both eyes) for expression params e['eye']."""
    p = e["eye"]
    ax = np.abs(x)
    i = (EYE_CX - ax) / EYE_A                       # +1 inner (nose side) .. -1 outer
    zc = z - EYE_CZ
    arch = 1 - i ** 2
    upper = p["ucr"] * arch + p["su"] * i
    lower = p["lcr"] * arch + p["sl"] * i
    m = np.minimum(np.minimum(upper - zc, zc - lower), (1 - np.abs(i)) * EYE_A * .55)
    opening = softedge(m)
    iz = zc - (0.5 * (upper + lower)) - p["gz"]
    # gaze: positive gx looks to the viewer's right for both eyes
    ixs = (x - np.sign(x) * EYE_CX) - p["gx"]
    r = np.sqrt(ixs ** 2 + iz ** 2)
    iris = opening * softedge(p["ir"] - r, 0.006) if p["ir"] > 0 else np.zeros_like(x)
    return opening, iris


def mouth_masks(x, z, e):
    p = e["mouth"]
    q = x / p["mw"]
    zu = p["m0"] + p["c"] * q ** 2 + p["k"] * x
    hh = max(p["h"], 0.05) * np.clip(1 - q ** 2, 0, 1) ** 0.7
    zl = zu - hh
    m = np.minimum(np.minimum(zu - z, z - zl), (p["mw"] - np.abs(x)) * .55)
    opening = softedge(m)
    if p["teeth"] > 0:
        tz = zu - p["teeth"] * (zu - zl)
        teeth = opening * softedge(z - tz + 0.004, 0.006)
        if p["grit"]:
            teeth *= 1 - (np.abs(np.sin(x * 40)) > .965) * .85
            teeth *= 1 - softedge(0.006 - np.abs(z - (zu + zl) * .5), 0.004) * .8
    else:
        teeth = np.zeros_like(x)
    return opening, teeth


def marking_mask(x, z):
    """Original gold markings: forehead signal-arc crest + ascending signal bars on each cheek."""
    ax = np.abs(x)
    m = np.zeros_like(x)
    cx, cz = 0.0, 0.50
    rr = np.sqrt((x - cx) ** 2 + (z - cz) ** 2)
    ang = np.degrees(np.arctan2(x - cx, z - cz))      # 0 = straight up
    for rad in (0.11, 0.19, 0.27):
        arc = softedge(0.024 - np.abs(rr - rad), 0.006) * softedge(52 - np.abs(ang), 2.0) * (z > cz - .02)
        m = np.maximum(m, arc)
    m = np.maximum(m, softedge(0.036 - rr, 0.006))   # emitter dot
    for k, h in enumerate((0.07, 0.125, 0.18)):      # signal bars, long on the outside
        bx = 0.575 + k * 0.075
        bar = softedge(0.021 - np.abs(ax - bx), 0.005) * softedge(h * .5 - np.abs(z - (-0.19 + h * .5 - .0)), 0.005)
        m = np.maximum(m, bar)
    return np.clip(m, 0, 1)


def blush_mask(x, z, e):
    ax = np.abs(x)
    return gauss(ax, z, 0.47, -0.17 + e["cheek"], 0.15, 0.11)


# ------------------------------------------------------------------ surface
def surface_y(x, z, e, carve=True):
    """Mask surface y (viewer is at -y). Positive features come toward the viewer."""
    u, v = uv_from_xz(x, z)
    r2 = np.clip(u * u + v * v, 0, 1)
    dome = np.sqrt(1 - r2)
    y = -0.46 * dome ** 0.82
    ax = np.abs(x)
    f = 0.0
    f = f + 0.040 * gauss(x, z, 0, .62, .45, .26)                                  # forehead
    ridge_z = 0.40 + 0.10 * np.cos(np.clip(ax / 0.7, 0, 1.4) * 1.1) - 0.10 * (ax > 0.7)
    f = f + 0.045 * np.exp(-((z - (0.395 + 0.07 * (1 - np.clip(ax / .65, 0, 1)) ** 1)) / .06) ** 2) \
        * np.exp(-((ax - .33) / .30) ** 2)                                         # brow ridge
    f = f - 0.050 * gauss(ax, z, EYE_CX, EYE_CZ, .21, .15)                         # eye sockets
    f = f + 0.050 * gauss(x, z, 0, .05, .055, .30)                                 # nose bridge
    f = f + 0.095 * gauss(x, z, 0, -.115, .085, .085)                              # nose tip
    f = f + 0.040 * gauss(ax, z, .13, -.17, .06, .045)                             # nostril wings
    f = f + (0.085 + 0.30 * max(e["cheek"], 0) * .2) * gauss(ax, z, .47, -.11 + e["cheek"], .17, .14)  # cheekbones
    f = f - 0.035 * gauss(ax, z, .40, -.46, .13, .15)                              # cheek hollows
    f = f + 0.075 * gauss(x, z, 0, -.80, .20, .13)                                 # chin
    f = f + 0.018 * marking_mask(x, z)                                             # embossed gold
    y = y - f
    if carve:
        eo, _ = eye_masks(x, z, e)
        mo, _ = mouth_masks(x, z, e)
        y = y + CARVE * np.maximum(eo, mo)
    return y


# ------------------------------------------------------------------ tubes (brows, moustache, goatee)
def tube(P, rin, rdep, nseg=10):
    P = np.asarray(P, float)
    n = len(P)
    T = np.gradient(P, axis=0)
    T /= np.linalg.norm(T, axis=1)[:, None]
    up = np.array([0.0, 1.0, 0.0])
    N = np.cross(T, up)
    N /= np.linalg.norm(N, axis=1)[:, None]
    ang = np.linspace(0, 2 * np.pi, nseg, endpoint=False)
    V = P[:, None, :] + rin[:, None, None] * np.cos(ang)[None, :, None] * N[:, None, :] \
        + rdep[:, None, None] * np.sin(ang)[None, :, None] * up[None, None, :]
    return V.reshape(-1, 3)


def tube_faces(n, nseg=10, base=0):
    F = []
    for i in range(n - 1):
        for j in range(nseg):
            a = base + i * nseg + j
            b = base + i * nseg + (j + 1) % nseg
            c = base + (i + 1) * nseg + (j + 1) % nseg
            d = base + (i + 1) * nseg + j
            F.append((a, b, c, d))
    F.append(tuple(base + j for j in reversed(range(nseg))))
    F.append(tuple(base + (n - 1) * nseg + j for j in range(nseg)))
    return F


NSEG = 10
BROW_N = 26


def brow_geometry(e, side):
    zi, zp, zo = e["brow"][side]
    P0 = np.array([.07, zi]); P2 = np.array([.63, zo])
    P1 = np.array([.30, 2 * zp - 0.5 * (P0[1] + P2[1])])
    P1[0] = .30
    s = np.linspace(0, 1, BROW_N)
    xz = ((1 - s) ** 2)[:, None] * P0 + (2 * s * (1 - s))[:, None] * P1 + (s ** 2)[:, None] * P2
    t = e["brow"]["t"]
    cap0 = np.sqrt(np.clip((s + .03) / .10, 0, 1))
    capn = np.sqrt(np.clip((1 - s) / .08, 0, 1))
    rin = t * (1.0 - .72 * s ** 1.25) * cap0 * capn + 1e-4
    rdep = 0.052 * (1 - .35 * s) * cap0 * capn + 1e-4
    x = xz[:, 0] * (1 if side == "R" else -1)
    ey = surface_y(x, xz[:, 1], e, carve=False) - 0.030
    return tube(np.stack([x, ey, xz[:, 1]], 1), rin, rdep, NSEG)


MUS_N = 40


def mus_spine(e, sign):
    m = e["mus"]
    s = np.linspace(0, 1, MUS_N)
    th = math.radians(m["th0"]) + math.radians(m["tot"]) * s ** 2.1
    ds = m["L"] / (MUS_N - 1)
    x = np.zeros(MUS_N); z = np.zeros(MUS_N)
    for i in range(1, MUS_N):
        x[i] = x[i - 1] + math.cos(th[i]) * ds
        z[i] = z[i - 1] + math.sin(th[i]) * ds
    return s, x, z + m["zc"]


def mus_geometry(e, sign):
    s, x, z = mus_spine(e, sign)
    r0 = e["mus"]["r"]
    cap0 = np.sqrt(np.clip((s + .02) / .08, 0, 1))
    capn = np.sqrt(np.clip((1 - s) / .05, 0, 1))
    rin = r0 * (1 - .82 * s ** 1.3) * cap0 * capn + 1e-4
    rdep = r0 * .95 * (1 - .6 * s) * cap0 * capn + 1e-4
    xs = x * sign
    ey = surface_y(xs, z, e, carve=False) - 0.055 - 0.02 * s
    ey = np.minimum(ey, surface_y(0 * xs, z * 0 - .20, e, carve=False) - 0.03)  # keep base ahead of the nose volume
    return tube(np.stack([xs, ey, z], 1), rin, rdep, NSEG)


GOAT_N = 22


def goatee_geometry(e):
    s = np.linspace(0, 1, GOAT_N)
    z = -0.60 - 0.58 * s
    x = np.zeros_like(s)
    prof = np.clip(4 * s * (1 - s) ** .9, 0, 1) ** .62 * (s > 0.0) + np.clip(s * 12, 0, 1) * 0.0
    prof = prof * np.sqrt(np.clip(s / .06, 0, 1))
    rin = 0.135 * prof + 1e-4
    rdep = 0.060 * prof + 1e-4
    ey = surface_y(x, z, e, carve=False) - 0.045 - 0.03 * s
    ey = np.minimum(ey, -0.40 - 0.35 * s * .0)
    ang = np.linspace(0, 2 * np.pi, NSEG, endpoint=False)
    V = np.zeros((GOAT_N, NSEG, 3))
    for i in range(GOAT_N):
        V[i, :, 0] = x[i] + rin[i] * np.cos(ang)
        V[i, :, 1] = ey[i] + rdep[i] * np.sin(ang)
        V[i, :, 2] = z[i] + 0 * ang
    return V.reshape(-1, 3)


# ------------------------------------------------------------------ mesh helpers
def new_mesh_obj(name, V, F, coll, mats=()):
    me = bpy.data.meshes.new(name)
    me.from_pydata([tuple(map(float, v)) for v in V], [], F)
    me.update()
    me.shade_smooth()
    ob = bpy.data.objects.new(name, me)
    coll.objects.link(ob)
    for m in mats:
        me.materials.append(m)
    return ob


def add_shape_keys(ob, per_mood_V, basis="Medium", extra_is=None):
    ob.shape_key_add(name="Basis")  # = Medium
    keys = {}
    for mood in MOODS:
        if mood == basis:
            continue
        k = ob.shape_key_add(name=mood, from_mix=False)
        k.data.foreach_set("co", np.asarray(per_mood_V[mood], np.float32).ravel())
        k.slider_min, k.slider_max = 0.0, 1.0
        keys[mood] = k
    return keys


# ------------------------------------------------------------------ materials
def mat_principled(name, color, rough=0.5, metal=0.0, emis=None, emis_strength=0.0, spec=0.5, coat=0.0):
    m = bpy.data.materials.new(name)
    m.use_nodes = True
    b = m.node_tree.nodes["Principled BSDF"]
    b.inputs["Base Color"].default_value = (*color, 1)
    b.inputs["Roughness"].default_value = rough
    b.inputs["Metallic"].default_value = metal
    b.inputs["Specular IOR Level"].default_value = spec
    b.inputs["Coat Weight"].default_value = coat
    if emis is not None:
        b.inputs["Emission Color"].default_value = (*emis, 1)
        b.inputs["Emission Strength"].default_value = emis_strength
    return m


def drive(owner_id, data_path, expr, ctrl, props, index=-1):
    fc = owner_id.driver_add(data_path, index) if index >= 0 else owner_id.driver_add(data_path)
    d = fc.driver
    d.type = "SCRIPTED"
    d.expression = expr
    for pname in props:
        v = d.variables.new()
        v.name = pname
        v.type = "SINGLE_PROP"
        v.targets[0].id = ctrl
        v.targets[0].data_path = f'["{pname}"]'
    return fc


def build_mask_material(ctrl):
    m = bpy.data.materials.new("GuardianMask")
    m.use_nodes = True
    nt = m.node_tree
    nodes, links = nt.nodes, nt.links
    for n in list(nodes):
        if n.type != "OUTPUT_MATERIAL":
            nodes.remove(n)
    out = nodes["Material Output"]
    out.location = (1500, 0)
    bsdf = nodes.new("ShaderNodeBsdfPrincipled")
    bsdf.location = (1200, 0)
    links.new(bsdf.outputs["BSDF"], out.inputs["Surface"])

    def val(name, x, y):
        n = nodes.new("ShaderNodeValue"); n.name = n.label = name; n.location = (x, y); return n

    # per-mood weights W0..W4 driven by ctrl.mood (linear blend between neighbours)
    W = []
    for i in range(5):
        w = val(f"W{i}", -1400, 600 - i * 140)
        drive(nt, f'nodes["W{i}"].outputs[0].default_value', f"max(0,1-abs(mood-{i}))", ctrl, ["mood"])
        W.append(w)
    al = val("ALERT", -1400, -200)
    drive(nt, 'nodes["ALERT"].outputs[0].default_value', "alert", ctrl, ["alert"])

    def math_(op, a, b, x, y, clamp=False):
        n = nodes.new("ShaderNodeMath"); n.operation = op; n.location = (x, y); n.use_clamp = clamp
        if isinstance(a, (int, float)): n.inputs[0].default_value = a
        else: links.new(a, n.inputs[0])
        if isinstance(b, (int, float)): n.inputs[1].default_value = b
        else: links.new(b, n.inputs[1])
        return n.outputs[0]

    # weighted sum of the five baked colour attributes: R cavity, G teeth, B iris
    acc = None
    for i, mood in enumerate(MOODS):
        a = nodes.new("ShaderNodeAttribute"); a.attribute_name = f"ex_{mood}"; a.location = (-1100, 700 - i * 160)
        sc = nodes.new("ShaderNodeVectorMath"); sc.operation = "SCALE"; sc.location = (-850, 700 - i * 160)
        links.new(a.outputs["Color"], sc.inputs[0])
        links.new(W[i].outputs[0], sc.inputs["Scale"])
        if acc is None:
            acc = sc.outputs["Vector"]
        else:
            ad = nodes.new("ShaderNodeVectorMath"); ad.operation = "ADD"; ad.location = (-600, 700 - i * 160)
            links.new(acc, ad.inputs[0]); links.new(sc.outputs["Vector"], ad.inputs[1])
            acc = ad.outputs["Vector"]
    sep = nodes.new("ShaderNodeSeparateXYZ"); sep.location = (-350, 400)
    links.new(acc, sep.inputs[0])
    cav, teeth, iris = sep.outputs[0], sep.outputs[1], sep.outputs[2]

    stat = nodes.new("ShaderNodeAttribute"); stat.attribute_name = "paint_static"; stat.location = (-1100, -100)
    sep2 = nodes.new("ShaderNodeSeparateXYZ"); sep2.location = (-850, -100)
    links.new(stat.outputs["Color"], sep2.inputs[0])
    mark, blush = sep2.outputs[0], sep2.outputs[1]

    def rgb(c, x, y):
        n = nodes.new("ShaderNodeRGB"); n.outputs[0].default_value = (*c, 1); n.location = (x, y); return n.outputs[0]

    def mix(fac, a, b, x, y):
        n = nodes.new("ShaderNodeMix"); n.data_type = "RGBA"; n.location = (x, y)
        if isinstance(fac, (int, float)): n.inputs[0].default_value = fac
        else: links.new(fac, n.inputs[0])
        links.new(a, n.inputs[6]); links.new(b, n.inputs[7])
        return n.outputs[2]

    ivory = rgb((0.90, 0.83, 0.69), -300, 200)
    rose = rgb((0.86, 0.38, 0.30), -300, 100)
    gold = rgb((1.00, 0.70, 0.16), -300, 0)
    ink = rgb((0.008, 0.010, 0.016), -300, -100)
    tooth = rgb((0.95, 0.93, 0.86), -300, -200)
    red = rgb(ALERT_RED, -300, -300)
    # alert: mask tint toward hot rose, so the same face reads "emergency"
    ivory_a = mix(math_("MULTIPLY", al.outputs[0], 0.45, -100, 250), ivory, rgb((1.0, 0.45, 0.38), -300, 300), -50, 250)
    c = mix(math_("MULTIPLY", blush, 0.65, -100, 150), ivory_a, rose, 100, 150)
    c = mix(mark, c, gold, 250, 100)
    c = mix(cav, c, ink, 400, 50)
    c = mix(teeth, c, tooth, 550, 0)
    links.new(c, bsdf.inputs["Base Color"])
    # roughness: porcelain smooth, cavities rough
    rg = math_("ADD", 0.34, math_("MULTIPLY", cav, 0.5, 700, -300), 850, -300)
    links.new(rg, bsdf.inputs["Roughness"])
    bsdf.inputs["Coat Weight"].default_value = 0.25
    bsdf.inputs["Coat Roughness"].default_value = 0.25
    bsdf.inputs["Specular IOR Level"].default_value = 0.5
    # emission: iris glints warm white; alert turns them hot red; gold markings glow faintly
    iris_c = mix(al.outputs[0], rgb((1.0, 0.86, 0.55), 700, -420), red, 900, -420)
    emis = mix(mark, iris_c, mix(al.outputs[0], gold, red, 900, -480), 1000, -420)
    links.new(emis, bsdf.inputs["Emission Color"])
    strength = math_("ADD", math_("MULTIPLY", iris, 9.0, 1000, -520), math_("MULTIPLY", mark, 0.35, 1000, -580), 1100, -520)
    strength = math_("ADD", strength, math_("MULTIPLY", teeth, 0.12, 1000, -640), 1200, -520)
    links.new(strength, bsdf.inputs["Emission Strength"])
    return m


def build_backdrop_material(ctrl, name="GuardianGlow", ring=False):
    """Emission-only backdrop: soft round mood glow (calm) / spiked red ring (alert)."""
    m = bpy.data.materials.new(name)
    m.use_nodes = True
    nt = m.node_tree
    nodes, links = nt.nodes, nt.links
    for n in list(nodes):
        if n.type != "OUTPUT_MATERIAL":
            nodes.remove(n)
    out = nodes["Material Output"]
    em = nodes.new("ShaderNodeEmission")
    links.new(em.outputs[0], out.inputs["Surface"])
    W = []
    for i in range(5):
        w = nodes.new("ShaderNodeValue"); w.name = w.label = f"W{i}"
        drive(nt, f'nodes["W{i}"].outputs[0].default_value', f"max(0,1-abs(mood-{i}))", ctrl, ["mood"])
        W.append(w)
    al = nodes.new("ShaderNodeValue"); al.name = al.label = "ALERT"
    drive(nt, 'nodes["ALERT"].outputs[0].default_value', "alert", ctrl, ["alert"])
    pu = nodes.new("ShaderNodeValue"); pu.name = pu.label = "PULSE"
    drive(nt, 'nodes["PULSE"].outputs[0].default_value', "pulse", ctrl, ["pulse"])
    acc = None
    for i in range(5):
        sc = nodes.new("ShaderNodeVectorMath"); sc.operation = "SCALE"; sc.inputs[0].default_value = ACCENT[i]
        links.new(W[i].outputs[0], sc.inputs["Scale"])
        if acc is None: acc = sc.outputs[0]
        else:
            ad = nodes.new("ShaderNodeVectorMath"); ad.operation = "ADD"
            links.new(acc, ad.inputs[0]); links.new(sc.outputs[0], ad.inputs[1]); acc = ad.outputs[0]
    mx = nodes.new("ShaderNodeMix"); mx.data_type = "RGBA"
    links.new(al.outputs[0], mx.inputs[0]); links.new(acc, mx.inputs[6]); mx.inputs[7].default_value = (*ALERT_RED, 1)
    # radial falloff from texture coordinate
    tc = nodes.new("ShaderNodeTexCoord")
    vm = nodes.new("ShaderNodeVectorMath"); vm.operation = "LENGTH"
    sub = nodes.new("ShaderNodeVectorMath"); sub.operation = "SUBTRACT"; sub.inputs[1].default_value = (0.5, 0.5, 0)
    links.new(tc.outputs["UV"], sub.inputs[0]); links.new(sub.outputs[0], vm.inputs[0])
    fall = nodes.new("ShaderNodeMapRange"); fall.inputs[1].default_value = 0.0; fall.inputs[2].default_value = 0.30
    fall.inputs[3].default_value = 1.0; fall.inputs[4].default_value = 0.0; fall.clamp = True
    links.new(vm.outputs["Value"], fall.inputs[0])
    sq = nodes.new("ShaderNodeMath"); sq.operation = "POWER"; sq.inputs[1].default_value = 2.2
    links.new(fall.outputs[0], sq.inputs[0])
    st = nodes.new("ShaderNodeMath"); st.operation = "MULTIPLY"; st.inputs[1].default_value = 0.55
    links.new(sq.outputs[0], st.inputs[0])
    # calm glow dims when alert is on (the ring takes over)
    dim = nodes.new("ShaderNodeMath"); dim.operation = "MULTIPLY_ADD"; dim.inputs[1].default_value = -0.55
    links.new(al.outputs[0], dim.inputs[0]); dim.inputs[2].default_value = 1.0
    st2 = nodes.new("ShaderNodeMath"); st2.operation = "MULTIPLY"
    links.new(st.outputs[0], st2.inputs[0]); links.new(dim.outputs[0], st2.inputs[1])
    links.new(mx.outputs[2], em.inputs["Color"])
    links.new(st2.outputs[0], em.inputs["Strength"])
    return m


def build_ring_material(ctrl):
    m = bpy.data.materials.new("GuardianAlertRing")
    m.use_nodes = True
    nt = m.node_tree
    nodes, links = nt.nodes, nt.links
    for n in list(nodes):
        if n.type != "OUTPUT_MATERIAL":
            nodes.remove(n)
    out = nodes["Material Output"]
    em = nodes.new("ShaderNodeEmission")
    em.inputs["Color"].default_value = (1.0, 0.05, 0.03, 1)
    links.new(em.outputs[0], out.inputs["Surface"])
    pu = nodes.new("ShaderNodeValue"); pu.name = pu.label = "PULSE"
    drive(nt, 'nodes["PULSE"].outputs[0].default_value', "pulse", ctrl, ["pulse"])
    ma = nodes.new("ShaderNodeMath"); ma.operation = "MULTIPLY_ADD"; ma.inputs[1].default_value = 0.7; ma.inputs[2].default_value = 1.05
    links.new(pu.outputs[0], ma.inputs[0])
    links.new(ma.outputs[0], em.inputs["Strength"])
    return m


# ------------------------------------------------------------------ build
def clear_scene():
    bpy.ops.wm.read_factory_settings(use_empty=True)


def build(blend_path):
    clear_scene()
    sc = bpy.context.scene
    coll = bpy.data.collections.new("GUARDIAN_PERSONA")
    sc.collection.children.link(coll)
    rig = bpy.data.objects.new("GUARDIAN_RIG", None)   # whole character: yaw lives here
    coll.objects.link(rig)
    rig.rotation_euler = (0, 0, math.radians(YAW_DEG))

    ctrl = bpy.data.objects.new("GUARDIAN_CONTROLS", None)
    ctrl.empty_display_type = "PLAIN_AXES"
    coll.objects.link(ctrl)
    for k, v, lo, hi, doc in (("mood", 2.0, 0.0, 4.0, "0 VeryGood 1 Good 2 Medium 3 Bad 4 Horrible (fractions blend)"),
                              ("alert", 0.0, 0.0, 1.0, "red alert treatment; overlays any mood, not a rating"),
                              ("pulse", 0.0, 0.0, 1.0, "alert pulse phase")):
        ctrl[k] = v
        ctrl.id_properties_ui(k).update(min=lo, max=hi, description=doc)

    # ----- mask mesh
    N = GRID
    s = np.linspace(-1, 1, N + 1)
    S, T = np.meshgrid(s, s, indexing="xy")
    U = S * np.sqrt(1 - T ** 2 / 2)
    Vv = T * np.sqrt(1 - S ** 2 / 2)
    X, Z = xz_from_uv(U, Vv)
    X = X.ravel(); Z = Z.ravel()
    faces = []
    for j in range(N):
        for i in range(N):
            a = j * (N + 1) + i
            faces.append((a, a + 1, a + N + 2, a + N + 1))
    per = {}
    for mood in MOODS:
        e = EXPR[mood]
        Y = surface_y(X, Z, e)
        per[mood] = np.stack([X, Y, Z], 1)
    mats = {}
    mats["mask"] = build_mask_material(ctrl)
    mask = new_mesh_obj("GuardianMask", per["Medium"], faces, coll, [mats["mask"]])
    mask.parent = rig
    me = mask.data
    # baked paint attributes
    for mood in MOODS:
        e = EXPR[mood]
        eo, iris = eye_masks(X, Z, e)
        mo, teeth = mouth_masks(X, Z, e)
        cav = np.maximum(eo, mo)
        att = me.color_attributes.new(f"ex_{mood}", "FLOAT_COLOR", "POINT")
        col = np.stack([cav, teeth, iris, np.ones_like(cav)], 1).astype(np.float32)
        att.data.foreach_set("color", col.ravel())
    att = me.color_attributes.new("paint_static", "FLOAT_COLOR", "POINT")
    mk = marking_mask(X, Z)
    bl = blush_mask(X, Z, EXPR["Medium"])
    att.data.foreach_set("color", np.stack([mk, bl, np.zeros_like(mk), np.ones_like(mk)], 1).astype(np.float32).ravel())
    add_shape_keys(mask, per)
    # a thin back shell so the rim is solid
    sol = mask.modifiers.new("Shell", "SOLIDIFY")
    sol.thickness = 0.05
    sol.offset = -1.0   # shell goes BEHIND the mask; +1 would grow an outer skin over the carved openings
    sol.use_rim = True

    # hair meshes
    hair = bpy.data.materials.new("GuardianInk")
    hair.use_nodes = True
    hb = hair.node_tree.nodes["Principled BSDF"]
    hb.inputs["Base Color"].default_value = (0.012, 0.012, 0.018, 1)
    hb.inputs["Roughness"].default_value = 0.22
    hb.inputs["Specular IOR Level"].default_value = 0.9
    hb.inputs["Coat Weight"].default_value = 0.35

    def hair_obj(name, geo_fn, faces_fn):
        pm = {m: geo_fn(EXPR[m]) for m in MOODS}
        ob = new_mesh_obj(name, pm["Medium"], faces_fn, coll, [hair])
        ob.parent = rig
        add_shape_keys(ob, pm)
        return ob

    brow_V = lambda e: np.concatenate([brow_geometry(e, "L"), brow_geometry(e, "R")])
    bf = tube_faces(BROW_N, NSEG) + tube_faces(BROW_N, NSEG, base=BROW_N * NSEG)
    hair_obj("GuardianBrows", brow_V, bf)
    mus_V = lambda e: np.concatenate([mus_geometry(e, -1), mus_geometry(e, +1)])
    mf = tube_faces(MUS_N, NSEG) + tube_faces(MUS_N, NSEG, base=MUS_N * NSEG)
    hair_obj("GuardianMoustache", mus_V, mf)
    hair_obj("GuardianGoatee", goatee_geometry, tube_faces(GOAT_N, NSEG))

    build_static_parts(coll, rig, ctrl, mats)
    wire_shape_key_drivers(ctrl)
    build_lights_camera(coll, ctrl, sc)
    os.makedirs(os.path.dirname(os.path.abspath(blend_path)), exist_ok=True)
    bpy.ops.wm.save_as_mainfile(filepath=blend_path, compress=True)
    print("SAVED", blend_path)


def wire_shape_key_drivers(ctrl):
    for ob in bpy.data.objects:
        if ob.type == "MESH" and ob.data.shape_keys:
            kb = ob.data.shape_keys
            for mood in MOODS:
                if mood in kb.key_blocks:
                    i = MOODS.index(mood)
                    drive(kb, f'key_blocks["{mood}"].value', f"max(0,1-abs(mood-{i}))", ctrl, ["mood"])
    # cigar: Very good only
    cg = bpy.data.objects.get("GuardianCigar")
    if cg:
        drive(cg.data.shape_keys, 'key_blocks["Lit"].value', "max(0,1-abs(mood))", ctrl, ["mood"])


def ellipsoid(name, rx, ry, rz, loc, coll, mat, seg=48, ring=32):
    import bmesh
    bm = bmesh.new()
    bmesh.ops.create_uvsphere(bm, u_segments=seg, v_segments=ring, radius=1.0)
    for v in bm.verts:
        v.co.x *= rx; v.co.y *= ry; v.co.z *= rz
    me = bpy.data.meshes.new(name)
    bm.to_mesh(me); bm.free()
    me.shade_smooth()
    ob = bpy.data.objects.new(name, me)
    ob.location = loc
    me.materials.append(mat)
    coll.objects.link(ob)
    return ob


def build_static_parts(coll, rig, ctrl, mats):
    import bmesh
    cloth = mat_principled("GuardianCloth", (0.018, 0.055, 0.068), rough=0.72, spec=0.25)
    cloth2 = mat_principled("GuardianClothDeep", (0.010, 0.030, 0.040), rough=0.75, spec=0.2)
    goldm = mat_principled("GuardianGold", (1.0, 0.68, 0.14), rough=0.3, spec=0.6, emis=(1.0, 0.62, 0.1), emis_strength=0.45)
    # ---- hood: smooth cowl lofted around the mask outline (polar grid in the same u,v warp)
    prof = [(1.10, -0.10), (1.17, -0.03), (1.28, 0.12), (1.36, 0.32), (1.34, 0.56), (1.16, 0.80), (0.80, 0.94), (0.40, 1.00), (0.0, 1.02)]
    NTH = 72
    V = []
    for rho, yy in prof:
        for j in range(NTH):
            th = 2 * math.pi * j / NTH
            xh, zh = xz_from_uv(np.array([rho * math.cos(th)]), np.array([rho * math.sin(th)]))
            V.append((float(xh[0]), yy, float(zh[0]) + (0.10 if zh[0] > 0 else 0.0) * min(rho, 1.2)))
    F = []
    for k in range(len(prof) - 1):
        for j in range(NTH):
            j2 = (j + 1) % NTH
            F.append((k * NTH + j, k * NTH + j2, (k + 1) * NTH + j2, (k + 1) * NTH + j))
    hood = new_mesh_obj("GuardianHood", V, F, coll, [cloth]); hood.parent = rig
    ss = hood.modifiers.new("Smooth", "SUBSURF"); ss.levels = 2; ss.render_levels = 2
    so = hood.modifiers.new("Thick", "SOLIDIFY"); so.thickness = 0.05; so.offset = -1.0
    # ---- gold trim along the face outline
    th = np.linspace(0, 2 * np.pi, 120, endpoint=False)
    U_, V_ = np.cos(th) * 1.0, np.sin(th) * 1.0
    xo, zo = xz_from_uv(U_, V_)
    yo = surface_y(xo, zo, EXPR["Medium"], carve=False) - 0.01
    P = np.stack([xo * 1.06, yo - 0.02, zo * 1.04], 1)
    ring = tube_loop(P, 0.032, 0.026, 8)
    trim = new_mesh_obj("GuardianTrim", ring[0], ring[1], coll, [goldm]); trim.parent = rig
    # ---- hood peak: curled tapered horn (silhouette)
    s = np.linspace(0, 1, 34)
    cp = np.array([[0.0, 0.15, 1.20], [0.05, 0.20, 1.62], [0.38, 0.10, 1.78], [0.62, -0.05, 1.42]])
    t = s[:, None]
    B = ((1 - t) ** 3) * cp[0] + 3 * ((1 - t) ** 2) * t * cp[1] + 3 * (1 - t) * t ** 2 * cp[2] + t ** 3 * cp[3]
    rad = 0.50 * (1 - s) ** 0.85 + 0.014
    horn_V = tube3(B, rad, rad * 0.9, 14)
    horn = new_mesh_obj("GuardianHoodPeak", horn_V, tube_faces(len(s), 14), coll, [cloth]); horn.parent = rig
    # gold band at the peak base + three signal arcs (original silhouette marker)
    # ---- collar: stand collar + shoulder cape + two pointed wings
    bm = bmesh.new()
    bmesh.ops.create_cone(bm, cap_ends=False, cap_tris=False, segments=48, radius1=1.05, radius2=0.62, depth=0.75)
    for v in bm.verts:
        v.co.z -= 1.28
        v.co.y += 0.22
    me = bpy.data.meshes.new("GuardianCollar"); bm.to_mesh(me); bm.free(); me.shade_smooth(); me.materials.append(cloth2)
    col = bpy.data.objects.new("GuardianCollar", me); coll.objects.link(col); col.parent = rig
    so = col.modifiers.new("Thick", "SOLIDIFY"); so.thickness = 0.05
    cape = ellipsoid("GuardianCape", 1.55, 0.78, 0.62, (0, 0.30, -1.62), coll, cloth2); cape.parent = rig
    for sgn in (-1, 1):
        wing = ellipsoid(f"GuardianWing{'L' if sgn < 0 else 'R'}", 0.95, 0.20, 0.30, (sgn * 0.98, 0.0, -1.0), coll, cloth)
        wing.rotation_euler = (0, math.radians(sgn * 22), 0)
        wing.parent = rig
        # gold edge on the wing tip
    # ---- cigar: the Very good prop (shape-key only)
    build_cigar(coll, rig, goldm)
    # ---- backdrop: calm mood glow + alert spiked ring
    glow_m = build_backdrop_material(ctrl)
    bm = bmesh.new()
    bmesh.ops.create_grid(bm, x_segments=1, y_segments=1, size=1.0)
    uv = bm.loops.layers.uv.new("UVMap")
    for f in bm.faces:
        for l in f.loops:
            l[uv].uv = (l.vert.co.x * .5 + .5, l.vert.co.y * .5 + .5)
    me = bpy.data.meshes.new("GuardianGlow"); bm.to_mesh(me); bm.free(); me.materials.append(glow_m)
    glow = bpy.data.objects.new("GuardianGlow", me); coll.objects.link(glow)
    glow.location = (0, 2.2, 0.34); glow.rotation_euler = (math.radians(90), 0, 0); glow.scale = (4.8, 4.8, 4.8)
    ringm = build_ring_material(ctrl)
    nspike = 20
    V = []; F = []
    for i in range(nspike):
        a0 = 2 * math.pi * i / nspike
        a1 = 2 * math.pi * (i + .5) / nspike
        a2 = 2 * math.pi * (i + 1) / nspike
        rin_, rout = 1.30, 1.72
        b0 = len(V)
        V += [(rin_ * math.cos(a0), 0, rin_ * math.sin(a0)), (rout * math.cos(a1), 0, rout * math.sin(a1)),
              (rin_ * math.cos(a2), 0, rin_ * math.sin(a2)),
              (1.16 * math.cos(a0), 0, 1.16 * math.sin(a0)), (1.16 * math.cos(a2), 0, 1.16 * math.sin(a2))]
        F += [(b0, b0 + 1, b0 + 2), (b0 + 3, b0, b0 + 2, b0 + 4)]
    me = bpy.data.meshes.new("GuardianAlertRing"); me.from_pydata(V, [], F); me.update(); me.materials.append(ringm)
    rg = bpy.data.objects.new("GuardianAlertRing", me); coll.objects.link(rg)
    rg.location = (0, 1.6, 0.34)   # ring already lies in the x-z plane, facing the camera
    # visible only with alert, pulse scales it
    drive(rg, "scale", "0.001+alert*(0.97+0.09*pulse)", ctrl, ["alert", "pulse"], index=0)
    drive(rg, "scale", "0.001+alert*(0.97+0.09*pulse)", ctrl, ["alert", "pulse"], index=1)
    drive(rg, "scale", "0.001+alert*(0.97+0.09*pulse)", ctrl, ["alert", "pulse"], index=2)


def tube_loop(P, rin, rdep, nseg):
    """Closed tube around a loop path in xz (gold trim)."""
    n = len(P)
    T = np.roll(P, -1, 0) - np.roll(P, 1, 0)
    T /= np.linalg.norm(T, axis=1)[:, None]
    up = np.array([0.0, 1.0, 0.0])
    N = np.cross(T, up); N /= np.linalg.norm(N, axis=1)[:, None]
    ang = np.linspace(0, 2 * np.pi, nseg, endpoint=False)
    V = P[:, None, :] + rin * np.cos(ang)[None, :, None] * N[:, None, :] + rdep * np.sin(ang)[None, :, None] * up
    F = []
    for i in range(n):
        i2 = (i + 1) % n
        for j in range(nseg):
            j2 = (j + 1) % nseg
            F.append((i * nseg + j, i * nseg + j2, i2 * nseg + j2, i2 * nseg + j))
    return V.reshape(-1, 3), F


def tube3(P, rin, rdep, nseg):
    """Round-ish tube along a 3D path with a parallel-transported frame."""
    P = np.asarray(P, float)
    n = len(P)
    T = np.gradient(P, axis=0); T /= np.linalg.norm(T, axis=1)[:, None]
    ref = np.array([0.0, 1.0, 0.0])
    N0 = np.cross(T[0], ref); N0 /= np.linalg.norm(N0)
    Ns = [N0]
    for i in range(1, n):
        Ni = Ns[-1] - np.dot(Ns[-1], T[i]) * T[i]
        Ni /= np.linalg.norm(Ni)
        Ns.append(Ni)
    Ns = np.array(Ns)
    Bs = np.cross(T, Ns)
    ang = np.linspace(0, 2 * np.pi, nseg, endpoint=False)
    V = P[:, None, :] + rin[:, None, None] * np.cos(ang)[None, :, None] * Ns[:, None, :] \
        + rdep[:, None, None] * np.sin(ang)[None, :, None] * Bs[:, None, :]
    return V.reshape(-1, 3)


def build_cigar(coll, rig, goldm):
    import bmesh
    body = mat_principled("CigarLeaf", (0.30, 0.13, 0.05), rough=0.7, spec=0.3)
    ash = mat_principled("CigarAsh", (0.55, 0.55, 0.52), rough=0.9)
    ember = mat_principled("CigarEmber", (1.0, 0.25, 0.03), rough=0.6, emis=(1.0, 0.30, 0.03), emis_strength=2.6)
    # corner of the Very good grin; the cigar leaves up and to the viewer's right
    corner = np.array([0.30, surface_y(np.array([0.30]), np.array([-0.50 + 0.13 * (0.30 / 0.37) ** 2]), EXPR["VeryGood"])[0] - 0.05,
                       -0.50 + 0.13 * (0.30 / 0.37) ** 2])
    d = np.array([math.cos(math.radians(24)), -0.18, math.sin(math.radians(24))])
    d /= np.linalg.norm(d)
    L = 0.92
    s = np.linspace(0, 1, 9)
    prof = np.array([0.062, 0.074, 0.076, 0.082, 0.078, 0.076, 0.076, 0.070, 0.0])   # last ring = closing cap
    # materials by ring band: leaf (0-4), band(4-5), leaf, ash cap (7), ember (8)
    P = corner[None, :] + s[:, None] * L * d[None, :]
    V = tube3(P, prof, prof, 12)
    F = tube_faces(len(s), 12)
    # collapsed basis: all rings at the corner, tiny
    Vb = np.tile(corner, (len(V), 1)) + (V - np.repeat(P, 12, axis=0)) * 0.02
    me = bpy.data.meshes.new("GuardianCigar")
    me.from_pydata([tuple(map(float, v)) for v in Vb], [], F)
    me.update(); me.shade_smooth()
    for m in (body, goldm, ash, ember):
        me.materials.append(m)
    # material index by ring band
    band = {0: 0, 1: 0, 2: 1, 3: 0, 4: 0, 5: 0, 6: 2, 7: 3}
    for pi, poly in enumerate(me.polygons):
        if pi < (len(s) - 1) * 12:
            ring_i = pi // 12
            poly.material_index = band.get(ring_i, 0)
        else:
            poly.material_index = 0 if pi == (len(s) - 1) * 12 else 3
    ob = bpy.data.objects.new("GuardianCigar", me)
    coll.objects.link(ob); ob.parent = rig
    ob.shape_key_add(name="Basis")
    k = ob.shape_key_add(name="Lit")
    k.data.foreach_set("co", V.astype(np.float32).ravel())


def build_lights_camera(coll, ctrl, sc):
    # world: near-black, slightly cool
    w = bpy.data.worlds.new("GuardianWorld")
    w.use_nodes = True
    bg = w.node_tree.nodes["Background"]
    bg.inputs["Color"].default_value = (0.006, 0.008, 0.012, 1)
    bg.inputs["Strength"].default_value = 1.0
    sc.world = w

    def light(name, kind, loc, rot, energy, color, size):
        l = bpy.data.lights.new(name, kind)
        l.energy = energy; l.color = color
        if kind == "AREA": l.size = size
        ob = bpy.data.objects.new(name, l)
        coll.objects.link(ob)
        ob.location = loc; ob.rotation_euler = tuple(math.radians(a) for a in rot)
        return ob, l

    key, kl = light("KeyWarm", "AREA", (-4.6, -6.0, 4.6), (64, 0, -38), 900, (1.0, 0.92, 0.80), 3.5)
    fill, fl = light("FillCool", "AREA", (4.5, -6.5, 1.0), (84, 0, 34), 70, (0.72, 0.85, 1.0), 4.5)
    rim1, r1 = light("RimLeft", "AREA", (-4.2, 4.0, 2.2), (-100, 0, -122), 650, (0.85, 0.95, 1.0), 2.5)
    rim2, r2 = light("RimRight", "AREA", (4.2, 4.0, 2.2), (-100, 0, 122), 650, (1.0, 0.85, 0.65), 2.5)
    # alert: key and fill swing red; rims go hot red (lighting treatment, same face)
    for l, base in ((kl, (1.0, 0.92, 0.80)), (fl, (0.72, 0.85, 1.0)), (r1, (0.85, 0.95, 1.0)), (r2, (1.0, 0.85, 0.65))):
        for ch in range(3):
            drive(l, "color", f"{base[ch]}*(1-alert)+{ALERT_RED[ch]}*alert", ctrl, ["alert"], index=ch)
    drive(kl, "energy", "900*(1+0.25*alert*(0.5+pulse))", ctrl, ["alert", "pulse"])
    cam = bpy.data.cameras.new("GuardianCam")
    cam.lens = 85
    cam.sensor_fit = "HORIZONTAL"
    cam.sensor_width = 36
    cam.shift_x = (FRAME_W / 2 - PERSONA_CX_PX) / FRAME_W
    co = bpy.data.objects.new("GuardianCam", cam)
    coll.objects.link(co)
    co.location = (0, -CAM_DIST, CAM_Z)
    co.rotation_euler = (math.radians(90), 0, 0)
    sc.camera = co
    r = sc.render
    r.engine = "BLENDER_EEVEE"
    r.resolution_x, r.resolution_y, r.resolution_percentage = FRAME_W * 4, FRAME_H * 4, 100
    r.film_transparent = False
    try:
        sc.view_settings.view_transform = "Standard"
    except Exception as ex:
        print("view transform", ex)
    sc.eevee.taa_render_samples = 96
    try:
        sc.eevee.use_raytracing = False
    except Exception:
        pass


def set_controls(mood, alert=0.0, pulse=0.0):
    c = bpy.data.objects["GUARDIAN_CONTROLS"]
    c["mood"], c["alert"], c["pulse"] = float(mood), float(alert), float(pulse)
    c.update_tag()
    bpy.context.scene.frame_set(bpy.context.scene.frame_current)   # forces driver evaluation in background mode
    bpy.context.view_layer.update()


def project_bboxes(sc, names):
    """Projected pixel bounding boxes (display px) of objects at the current control state."""
    from bpy_extras.object_utils import world_to_camera_view
    dg = bpy.context.evaluated_depsgraph_get()
    out = {}
    for n in names:
        ob = bpy.data.objects.get(n)
        if ob is None:
            continue
        ev = ob.evaluated_get(dg)
        me = ev.to_mesh()
        pts = [world_to_camera_view(sc, sc.camera, ev.matrix_world @ v.co) for v in me.vertices]
        ev.to_mesh_clear()
        xs = [p.x * FRAME_W for p in pts]
        ys = [(1 - p.y) * FRAME_H for p in pts]
        out[n] = [round(min(xs), 1), round(min(ys), 1), round(max(xs), 1), round(max(ys), 1)]
    return out


def render_states(blend, outdir, scale, states=None):
    import json
    bpy.ops.wm.open_mainfile(filepath=blend)
    sc = bpy.context.scene
    sc.render.resolution_x, sc.render.resolution_y = FRAME_W * scale, FRAME_H * scale
    os.makedirs(outdir, exist_ok=True)
    if states is None:
        states = [(i, 0, 0, MOODS[i]) for i in range(5)]
        for i in range(5):
            for p in (0, 1):
                states.append((i, 1, p, f"{MOODS[i]}_ALERT_p{p}"))
    report = {}
    for mood, alert, pulse, name in states:
        set_controls(mood, alert, pulse)
        sc.render.filepath = os.path.join(outdir, f"{name}.png")
        bpy.ops.render.render(write_still=True)
        report[name] = project_bboxes(sc, ["GuardianMask", "GuardianBrows", "GuardianMoustache", "GuardianGoatee",
                                           "GuardianCigar", "GuardianHood", "GuardianHoodPeak", "GuardianAlertRing"])
        print("RENDERED", sc.render.filepath)
    with open(os.path.join(outdir, "bboxes.json"), "w") as f:
        json.dump(report, f, indent=1)


def main():
    argv = sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else []
    if not argv:
        print(__doc__); return
    cmd = argv[0]
    opt = {argv[i]: argv[i + 1] for i in range(1, len(argv) - 1, 2)}
    if cmd == "build":
        build(opt["--blend"])
    elif cmd == "render":
        only = opt.get("--only")
        states = None
        if only:
            states = []
            for tok in only.split(","):
                mood, alert, pulse = tok.split(":")
                states.append((float(mood), float(alert), float(pulse), f"{MOODS[int(float(mood))]}{'_ALERT_p'+pulse if float(alert) else ''}"))
        render_states(opt["--blend"], opt["--outdir"], int(opt.get("--scale", 4)), states)
    else:
        print("unknown command", cmd)


if __name__ == "__main__":
    main()

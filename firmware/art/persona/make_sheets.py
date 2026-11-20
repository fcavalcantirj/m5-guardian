#!/usr/bin/env python3
"""Turn the 4x Blender renders into display-size StickS3 frames and contact sheets (G15).

  python3 make_sheets.py --render DIR4X --out EXPORTDIR [--blend persona.blend]

Pillow only.  Never reads the board; pure file conversion.
Outputs in EXPORTDIR:
  frames/<state>.png          240x135 downsampled (Lanczos) RGB
  rgb565/<state>.rgb565       raw 64,800-byte little-endian frames, what the ST7789 window takes
  preview565/<state>.png      the same frames expanded from RGB565 (what the glass can show)
  sheet-moods-1x.png          five rated moods at the real 240x135 size + layout-guide tile
  sheet-moods-3x.png          same, 3x nearest-neighbour for inspection on a monitor
  sheet-alert-1x.png          ALERT overlay on all five moods, pulse phase 0 and 1
  sheet-mock-labels-1x.png    review-only mock of the text zone (mood label, network, ALERT reason)
  manifest.json               sha256 of every output and of the source files
"""
import argparse
import hashlib
import json
import os

from PIL import Image, ImageDraw, ImageFont

W, H = 240, 135
MOODS = ["VeryGood", "Good", "Medium", "Bad", "Horrible"]
LABEL = {"VeryGood": "Very good", "Good": "Good", "Medium": "Medium", "Bad": "Bad", "Horrible": "Horrible"}
ACCENT = {"VeryGood": (0, 220, 76), "Good": (120, 220, 80), "Medium": (240, 200, 20),
          "Bad": (255, 122, 10), "Horrible": (200, 0, 160)}
TEXT_X = 152          # persona zone ends here; the renderer owns everything to the right


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def to565(im):
    px = im.convert("RGB").load()
    raw = bytearray()
    prev = Image.new("RGB", im.size)
    pp = prev.load()
    for y in range(im.height):
        for x in range(im.width):
            r, g, b = px[x, y]
            r5, g6, b5 = round(r * 31 / 255), round(g * 63 / 255), round(b * 31 / 255)
            v = (r5 << 11) | (g6 << 5) | b5
            raw += v.to_bytes(2, "little")
            pp[x, y] = ((r5 << 3) | (r5 >> 2), (g6 << 2) | (g6 >> 4), (b5 << 3) | (b5 >> 2))
    return bytes(raw), prev


def font(size):
    return ImageFont.load_default(size=size)


def tile_sheet(tiles, cols, gap=6, bg=(40, 40, 46), caption=None):
    rows = (len(tiles) + cols - 1) // cols
    cap_h = 14 if caption else 0
    sheet = Image.new("RGB", (cols * W + (cols + 1) * gap, rows * (H + cap_h) + (rows + 1) * gap), bg)
    d = ImageDraw.Draw(sheet)
    for i, (im, cap) in enumerate(tiles):
        x = gap + (i % cols) * (W + gap)
        y = gap + (i // cols) * (H + cap_h + gap)
        sheet.paste(im, (x, y + cap_h))
        if caption and cap:
            d.text((x, y), cap, fill=(200, 200, 210), font=font(10))
    return sheet


def mock_labels(im, state):
    """Review-only mock of the text zone. The product renders its own text; this checks the space."""
    out = im.copy()
    d = ImageDraw.Draw(out)
    mood = state.split("_")[0]
    alert = "ALERT" in state
    d.text((TEXT_X + 4, 6), "LIVE HomeNet", fill=(255, 255, 255) if not alert else (255, 80, 70), font=font(11))
    if alert:
        d.text((TEXT_X + 4, 34), "ALERT", fill=(255, 60, 50), font=font(24))
        d.text((TEXT_X + 4, 66), "Disconnect", fill=(255, 255, 255), font=font(13))
        d.text((TEXT_X + 4, 82), "burst detected", fill=(255, 255, 255), font=font(13))
        d.text((TEXT_X + 4, 108), "Rated: " + LABEL[mood], fill=(200, 200, 200), font=font(11))
    else:
        d.text((TEXT_X + 4, 40), LABEL[mood], fill=ACCENT[mood], font=font(20))
        d.text((TEXT_X + 4, 70), "Seen 4 s ago", fill=(255, 255, 255), font=font(12))
        d.text((TEXT_X + 4, 112), "blue: info", fill=(160, 160, 160), font=font(10))
    return out


def guide_tile():
    g = Image.new("RGB", (W, H), (10, 10, 14))
    d = ImageDraw.Draw(g)
    d.rectangle((0, 0, TEXT_X - 1, H - 1), outline=(0, 200, 220))
    d.rectangle((TEXT_X, 0, W - 1, H - 1), outline=(220, 200, 0))
    d.text((6, 6), "persona zone\n0..151 x 0..134\nfull height,\nno text", fill=(0, 200, 220), font=font(11))
    d.text((TEXT_X + 4, 6), "text zone\n152..239\nlabel/network\nowned by the\nrenderer", fill=(220, 200, 0), font=font(10))
    return g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--render", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--blend")
    ap.add_argument("--script", action="append", default=[])
    a = ap.parse_args()
    for sub in ("frames", "rgb565", "preview565"):
        os.makedirs(os.path.join(a.out, sub), exist_ok=True)
    states = [n[:-4] for n in sorted(os.listdir(a.render)) if n.endswith(".png") and not n.startswith(("sheet", "._"))]
    manifest = {"frame": [W, H], "text_zone_x": TEXT_X, "files": {}, "sources": {}}
    prev = {}
    for st in states:
        im4 = Image.open(os.path.join(a.render, st + ".png")).convert("RGB")
        assert im4.size[0] % W == 0 and im4.size[1] % H == 0 and im4.size[0] // W == im4.size[1] // H, (st, im4.size)
        im = im4.resize((W, H), Image.LANCZOS)
        im.save(os.path.join(a.out, "frames", st + ".png"))
        raw, pv = to565(im)
        assert len(raw) == W * H * 2
        with open(os.path.join(a.out, "rgb565", st + ".rgb565"), "wb") as f:
            f.write(raw)
        pv.save(os.path.join(a.out, "preview565", st + ".png"))
        prev[st] = pv
    moods = [(prev[m], LABEL[m]) for m in MOODS if m in prev] + [(guide_tile(), "layout guide")]
    s1 = tile_sheet(moods, 3, caption=True)
    s1.save(os.path.join(a.out, "sheet-moods-1x.png"))
    s1.resize((s1.width * 3, s1.height * 3), Image.NEAREST).save(os.path.join(a.out, "sheet-moods-3x.png"))
    alert = []
    for p in (0, 1):
        for m in MOODS:
            k = f"{m}_ALERT_p{p}"
            if k in prev:
                alert.append((prev[k], f"{LABEL[m]} + ALERT pulse {p}"))
    if alert:
        tile_sheet(alert, 5, caption=True).save(os.path.join(a.out, "sheet-alert-1x.png"))
    mocks = [(mock_labels(prev[m], m), LABEL[m]) for m in MOODS if m in prev]
    mocks += [(mock_labels(prev[f"{m}_ALERT_p1"], f"{m}_ALERT_p1"), f"{LABEL[m]} + ALERT") for m in ("VeryGood", "Horrible") if f"{m}_ALERT_p1" in prev]
    if mocks:
        tile_sheet(mocks, 3, caption=True).save(os.path.join(a.out, "sheet-mock-labels-1x.png"))
    for root, _, files in os.walk(a.out):
        for fn in sorted(files):
            if fn.startswith("._"):
                continue        # AppleDouble litter from the SMB share
            p = os.path.join(root, fn)
            if fn != "manifest.json":
                manifest["files"][os.path.relpath(p, a.out)] = sha(p)
    for p in ([a.blend] if a.blend else []) + a.script:
        manifest["sources"][os.path.basename(p)] = sha(p)
    bb = os.path.join(a.render, "bboxes.json")
    if os.path.exists(bb):
        manifest["bboxes_display_px"] = json.load(open(bb))
    with open(os.path.join(a.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)
    print("OK", len(states), "states ->", a.out)


if __name__ == "__main__":
    main()

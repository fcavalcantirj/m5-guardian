#!/usr/bin/env python3
"""Build the README hero images from the shipped portrait previews.

  python3 tools/art/readme_hero.py [--out docs/img]

Pillow only. Pure file conversion: decodes the shipped, pinned portraits
firmware/art/persona/v2/portrait/<Mood>_portrait.rgb565 (135x160 little-endian RGB565, pipeline D,
the bytes the StickS3 glass shows), scales them 2x nearest-neighbour on black and adds a label
strip. Draws nothing new on the faces. PNGs carry no metadata chunks. Writes:
  guardian-moods.png   one row: the five moods, an ALERT frame and No fresh data
  guardian-faces.webp   a loop: the five moods, the ALERT pulse (3x), No fresh data (lossless WebP, under 200 KB)
The output is deterministic: a re-run over the same previews gives the same bytes.
"""
import argparse
import os

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
PORTRAIT = os.path.join(REPO, "firmware", "art", "persona", "v2", "portrait")
PW, PH = 135, 160

SCALE = 2
FACE_W, FACE_H = 135 * SCALE, 160 * SCALE
STRIP = 56
GAP = 16
BG = (0, 0, 0)

# (portrait file stem, label, label colour)
VERY_GOOD = ("VeryGood", "Very good", (61, 220, 132))
GOOD = ("Good", "Good", (155, 225, 93))
MEDIUM = ("Medium", "Medium", (242, 201, 76))
BAD = ("Bad", "Bad", (242, 153, 74))
HORRIBLE = ("Horrible", "Horrible", (235, 87, 87))
ALERT_P0 = ("Horrible_ALERT_p0", "ALERT", (255, 59, 48))
ALERT_P1 = ("Horrible_ALERT_p1", "ALERT", (255, 59, 48))
NO_DATA = ("NoData", "No fresh data", (138, 143, 152))

SHEET = [VERY_GOOD, GOOD, MEDIUM, BAD, HORRIBLE, ALERT_P0, NO_DATA]
# (tile, milliseconds)
LOOP = ([(t, 1200) for t in (VERY_GOOD, GOOD, MEDIUM, BAD, HORRIBLE)]
        + [(t, 400) for _ in range(3) for t in (ALERT_P0, ALERT_P1)]
        + [(NO_DATA, 1200)])


def font(size):
    return ImageFont.load_default(size=size)


def decode565(path):
    raw = open(path, "rb").read()
    if len(raw) != PW * PH * 2:
        raise SystemExit(f"{path}: expected {PW * PH * 2} bytes, got {len(raw)}")
    px = bytearray()
    for i in range(0, len(raw), 2):
        v = raw[i] | (raw[i + 1] << 8)
        r, g, b = (v >> 11) & 31, (v >> 5) & 63, v & 31
        px += bytes(((r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2)))
    return Image.frombytes("RGB", (PW, PH), bytes(px))


def tile(spec):
    stem, label, colour = spec
    face = decode565(os.path.join(PORTRAIT, f"{stem}_portrait.rgb565"))
    out = Image.new("RGB", (FACE_W, FACE_H + STRIP), BG)
    out.paste(face.resize((FACE_W, FACE_H), Image.NEAREST), (0, 0))
    draw = ImageDraw.Draw(out)
    f = font(30)
    w = draw.textlength(label, font=f)
    draw.text(((FACE_W - w) / 2, FACE_H + 10), label, font=f, fill=colour)
    return out


def sheet(path):
    tiles = [tile(s) for s in SHEET]
    w = len(tiles) * FACE_W + (len(tiles) + 1) * GAP
    h = FACE_H + STRIP + 2 * GAP
    img = Image.new("RGB", (w, h), BG)
    for i, t in enumerate(tiles):
        img.paste(t, (GAP + i * (FACE_W + GAP), GAP))
    img.save(path, optimize=True)


def loop(path):
    cache = {}
    frames, durations = [], []
    for spec, ms in LOOP:
        if spec[0] not in cache:
            cache[spec[0]] = tile(spec)
        frames.append(cache[spec[0]])
        durations.append(ms)
    # Lossless animated WebP: the exact glass pixels in every frame (a GIF palette loses Very good's
    # green eyes) and about 135 KB.
    frames[0].save(path, "WEBP", save_all=True, append_images=frames[1:], duration=durations, loop=0,
                   lossless=True, method=6)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=os.path.join(REPO, "docs", "img"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    sheet(os.path.join(a.out, "guardian-moods.png"))
    loop(os.path.join(a.out, "guardian-faces.webp"))
    for n in ("guardian-moods.png", "guardian-faces.webp"):
        p = os.path.join(a.out, n)
        print(p, os.path.getsize(p))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""ALERT frames v3: the rated face with BLOOD-RED glowing eyes, nothing else (owner, 2026-11-17:
"red eyes alive, blood eyes"; the v2 corona and its stray red hood block were rejected).

  python3 alert_eyes.py <v2 masters_png dir> <out masters_png dir> [--review SHEET.png]

Reads the five accepted mood masters (512x512 RGBA, sha256-pinned in build_assets.py) and writes:
  <Mood>.png            the rating face: Good/Medium/Bad copied unchanged (cyan eyes); the two extremes
                        get their own eye colour (RATING_EYES: Very good GREEN, Horrible RED; owner's
                        row B, 2026-11-17)
  <Mood>_ALERT_p0/p1    red eyes on the ORIGINAL cyan master: p0 = full glow, p1 = PULSE_DIM, so the
                        450 ms alert pulse still breathes (Horrible_ALERT = Horrible + the pulse + the red
                        frame; the G15 "Horrible distinct from ALERT" rule is amended by the owner)
Only the two eye glows are touched (the two largest wide cyan blobs in the eye band, one each side of
the nose line); alpha, hood, circuit lines and mouth are byte-identical to the mood master. The eye
boxes and parameters go to alert_eyes.json in the output dir, so the result is reproducible.
"""
import hashlib, json, pathlib, shutil, sys
from collections import deque

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

MOODS = ['VeryGood', 'Good', 'Medium', 'Bad', 'Horrible']
BAND = (140, 150, 380, 280)          # x0, y0, x1, y1: where the eyes live in every v2 master
NOSE_X = 256                         # the two blobs must sit on opposite sides of the face line
PULSE_DIM = 0.6                      # p1 glow relative to p0
RATING_EYES = {'VeryGood': 'green', 'Horrible': 'red'}   # rating faces with their own eye colour; others stay cyan
CORE_GAMMA, HALO_NEAR, HALO_FAR = 1.4, 9, 22


def cyan_mask(a):
    r, g, b = a[..., 0], a[..., 1], a[..., 2]
    return (b > 70) & (g > 60) & (r < 0.8 * np.minimum(g, b))


def components(mask):
    """Connected components (4-neighbour) of a boolean mask; returns a list of pixel-index arrays."""
    seen = np.zeros_like(mask, bool); out = []
    ys, xs = np.nonzero(mask)
    for y0, x0 in zip(ys, xs):
        if seen[y0, x0]: continue
        q = deque([(y0, x0)]); seen[y0, x0] = True; pix = []
        while q:
            y, x = q.popleft(); pix.append((y, x))
            for ny, nx in ((y - 1, x), (y + 1, x), (y, x - 1), (y, x + 1)):
                if 0 <= ny < mask.shape[0] and 0 <= nx < mask.shape[1] and mask[ny, nx] and not seen[ny, nx]:
                    seen[ny, nx] = True; q.append((ny, nx))
        out.append(np.array(pix))
    return out


def find_eyes(a):
    """The two eye glows: largest cyan blobs inside BAND, one left and one right of NOSE_X."""
    x0, y0, x1, y1 = BAND
    m = np.zeros(a.shape[:2], bool); m[y0:y1, x0:x1] = cyan_mask(a)[y0:y1, x0:x1]
    # an eye glow is a wide blob; the thin vertical nose/circuit lines are taller than wide
    blobs = [b for b in sorted(components(m), key=len, reverse=True)
             if np.ptp(b[:, 1]) + 1 >= np.ptp(b[:, 0]) + 1]
    left = next((b for b in blobs if b[:, 1].mean() < NOSE_X), None)
    right = next((b for b in blobs if b[:, 1].mean() >= NOSE_X), None)
    if left is None or right is None or min(len(left), len(right)) < 80:
        raise SystemExit(f'eye glows not found (left {0 if left is None else len(left)}, right {0 if right is None else len(right)} px)')
    eyes = np.zeros(a.shape[:2], bool)
    for b in (left, right): eyes[b[:, 0], b[:, 1]] = True
    eyes = np.asarray(Image.fromarray(eyes.astype(np.uint8) * 255).filter(ImageFilter.MaxFilter(5))) > 0
    boxes = [[int(b[:, 1].min()), int(b[:, 0].min()), int(b[:, 1].max()) + 1, int(b[:, 0].max()) + 1] for b in (left, right)]
    return eyes, boxes


# Glow colours: (core base, core per-channel gain, halo per-channel gain). red = blood eyes (owner-approved).
COLOURS = {'red': ((0.55, 0.0, 0.0), (0.45, 0.75, 0.70), (0.9, 0.08, 0.10)),
           'green': ((0.0, 0.55, 0.0), (0.75, 0.45, 0.70), (0.10, 0.9, 0.12))}


def blood_eyes(master, strength, colour='red'):
    """RGBA master -> RGBA with glowing eyes of COLOURS[colour]; alpha untouched; strength 1.0 = p0."""
    base, gain, halo_gain = COLOURS[colour]
    a = np.asarray(master.convert('RGBA')).astype(np.float32)
    rgb = a[..., :3]; alpha = a[..., 3:]
    eyes, boxes = find_eyes(rgb)
    g, b = rgb[..., 1], rgb[..., 2]
    lvl = np.clip(np.maximum(g, b) / 255.0, 0, 1) * strength
    core = lvl ** CORE_GAMMA
    out = rgb.copy()
    for c in range(3):   # the dominant channel carries the glow level, the others only its hot core
        out[..., c][eyes] = 255 * np.clip(base[c] + gain[c] * (core[eyes] if base[c] else core[eyes] ** 3), 0, 1)
    glow = np.zeros(rgb.shape[:2], np.float32); glow[eyes] = lvl[eyes]
    def blur(k): return np.asarray(Image.fromarray((glow * 255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(k))).astype(np.float32) / 255
    halo = (1.1 * blur(HALO_NEAR) + 0.6 * blur(HALO_FAR)) * (~eyes)
    for c in range(3): out[..., c] += 255 * halo * halo_gain[c]
    res = np.concatenate([np.clip(np.rint(out), 0, 255), alpha], axis=2).astype(np.uint8)
    return Image.fromarray(res), boxes


def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def build(src, dst, review=None):
    src, dst = pathlib.Path(src), pathlib.Path(dst); dst.mkdir(parents=True, exist_ok=True)
    rec = {'from': str(src), 'rating_eyes': RATING_EYES, 'band': BAND, 'nose_x': NOSE_X, 'pulse_dim': PULSE_DIM, 'core_gamma': CORE_GAMMA,
           'halo_blur': [HALO_NEAR, HALO_FAR], 'moods': {}, 'files': {}}
    tiles = []
    for mood in MOODS:
        m = src / f'{mood}.png'; im = Image.open(m); assert im.size == (512, 512), m
        if mood in RATING_EYES:
            rating, boxes = blood_eyes(im, 1.0, RATING_EYES[mood]); rating.save(dst / f'{mood}.png', optimize=False)
        else:
            shutil.copyfile(m, dst / f'{mood}.png'); rating = im
        rec['files'][f'{mood}.png'] = sha(dst / f'{mood}.png')
        for phase, strength in (('p0', 1.0), ('p1', PULSE_DIM)):
            out, boxes = blood_eyes(im, strength)
            name = f'{mood}_ALERT_{phase}.png'; out.save(dst / name, optimize=False)
            rec['files'][name] = sha(dst / name); rec['moods'][mood] = {'eye_boxes': boxes}
            if phase == 'p0': tiles.append((mood, rating, out))
    (dst / 'alert_eyes.json').write_text(json.dumps(rec, indent=1) + '\n')
    if review:
        sheet = Image.new('RGB', (len(tiles) * 522 + 10, 2 * 522 + 30), (30, 30, 30)); d = ImageDraw.Draw(sheet)
        for i, (mood, im, out) in enumerate(tiles):
            for row, (img, lab) in enumerate(((im, f'{mood} (rating)'), (out, f'{mood}_ALERT_p0 (red eyes)'))):
                k = Image.new('RGBA', (512, 512), (0, 0, 0, 255)); k.alpha_composite(img.convert('RGBA'))
                sheet.paste(k.convert('RGB'), (10 + i * 522, 22 + row * 522)); d.text((10 + i * 522, 4 + row * 522), lab, fill='white')
        sheet.save(review)
    for n, h in rec['files'].items(): print(h, n)
    return rec


if __name__ == '__main__':
    argv = sys.argv[1:]
    review = argv[argv.index('--review') + 1] if '--review' in argv else None
    pos = [a for i, a in enumerate(argv) if a != '--review' and (i == 0 or argv[i - 1] != '--review')]
    if len(pos) != 2: raise SystemExit(__doc__)
    build(pos[0], pos[1], review)

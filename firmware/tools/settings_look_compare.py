#!/usr/bin/env python3
"""G24: compare the Settings screen the firmware composes with the owner-approved look.

The approved look (firmware/evidence/sticks3-G24-settings-look-20261121.png, owner "perfect", 2026-11-21)
is six 135x240 pages drawn at 2x, one every 280 px. firmware/tests/companion_preview.cpp renders the same
six pages through the real Companion, composer and renderer as 24-settings-1..6 (PPM). This prints, per
page, how many pixels differ (0 = identical) and exits 1 when any page differs or is missing.

  ~/miniconda3/bin/python3 -I firmware/tools/settings_look_compare.py <companion_preview out dir> [look.png] [--allow-rows=A-B,...]

G25: every differing pixel is also counted by panel row band (tag 0-10, body 11-215, hints 216-239). With
--allow-rows (inclusive page-pixel row ranges, e.g. the two G25 hint rows 216-235) a page whose differing
pixels all lie in those rows counts as an expected change (exit 0); any other difference still fails.

Needs Pillow (the pinned art toolchain's python, see firmware/README.md). Reads files only.
"""
import sys
from pathlib import Path

from PIL import Image

PAGES = ['24-settings-1-guard-always', '24-settings-2-guard-30s', '24-settings-3-guard-1min',
         '24-settings-4-guard-1min-saved', '24-settings-5-brightness-30', '24-settings-6-brightness-100']
W, H, SCALE, PITCH = 135, 240, 2, 280


BANDS = (('tag', 0, 10), ('body', 11, 215), ('hints', 216, 239))


def parse_rows(spec):
    rows = []
    for part in spec.split(','):
        a, _, b = part.partition('-')
        rows.append((int(a), int(b or a)))
    return rows


def main(argv):
    allow = [a for a in argv[1:] if a.startswith('--allow-rows=')]
    argv = [argv[0]] + [a for a in argv[1:] if not a.startswith('--allow-rows=')]
    allowed = parse_rows(allow[-1].split('=', 1)[1]) if allow else []
    if len(argv) not in (2, 3):
        print(next(l.strip() for l in __doc__.splitlines() if 'settings_look_compare.py <' in l))
        return 2
    out = Path(argv[1])
    look_path = Path(argv[2]) if len(argv) == 3 else Path(__file__).resolve().parents[1] / 'evidence' / 'sticks3-G24-settings-look-20261121.png'
    look = Image.open(look_path).convert('RGB')
    if look.size != (PITCH * len(PAGES), H * SCALE):
        print(f'look {look_path}: size {look.size}, expected {(PITCH * len(PAGES), H * SCALE)}')
        return 1
    lp = look.load()
    worst = 0
    for i, name in enumerate(PAGES):
        path = out / f'{name}.ppm'
        if not path.exists():
            print(f'{name}: MISSING ({path})')
            worst = max(worst, 1)
            continue
        page = Image.open(path).convert('RGB')
        if page.size != (W, H):
            print(f'{name}: size {page.size}, expected {(W, H)}')
            worst = max(worst, 1)
            continue
        pp = page.load()
        diff = 0
        first = None
        bands = {b[0]: 0 for b in BANDS}
        outside = 0
        for y in range(H):
            for x in range(W):
                # every pixel of a 2x2 block in the look must equal the page pixel
                want = pp[x, y]
                block = [lp[i * PITCH + SCALE * x + dx, SCALE * y + dy] for dx in range(SCALE) for dy in range(SCALE)]
                if any(b != want for b in block):
                    diff += 1
                    bands[next(n for n, a, b in BANDS if a <= y <= b)] += 1
                    if not any(a <= y <= b for a, b in allowed):
                        outside += 1
                    if first is None:
                        first = (x, y, want, block[0])
        detail = ', '.join(f'{n} {c}' for n, c in bands.items())
        print(f'{name}: {diff} of {W * H} pixels differ ({detail}; outside the allowed rows {outside})'
              + (f' (first at {first[0]},{first[1]}: page {first[2]} look {first[3]})' if first else ''))
        if outside:
            worst = max(worst, 1)
    verdict = 'DIFFERENT' if worst else ('IDENTICAL' if not allowed else 'ONLY THE ALLOWED ROWS DIFFER (or nothing)')
    print('settings_look_compare: ' + verdict)
    return worst


if __name__ == '__main__':
    sys.exit(main(sys.argv))

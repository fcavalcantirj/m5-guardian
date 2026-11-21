#!/usr/bin/env python3
"""G24: compare the Settings screen the firmware composes with the owner-approved look.

The approved look (firmware/evidence/sticks3-G24-settings-look-20261121.png, owner "perfect", 2026-11-21)
is six 135x240 pages drawn at 2x, one every 280 px. firmware/tests/companion_preview.cpp renders the same
six pages through the real Companion, composer and renderer as 24-settings-1..6 (PPM). This prints, per
page, how many pixels differ (0 = identical) and exits 1 when any page differs or is missing.

  ~/miniconda3/bin/python3 -I firmware/tools/settings_look_compare.py <companion_preview out dir> [look.png]

Needs Pillow (the pinned art toolchain's python, see firmware/README.md). Reads files only.
"""
import sys
from pathlib import Path

from PIL import Image

PAGES = ['24-settings-1-guard-always', '24-settings-2-guard-30s', '24-settings-3-guard-1min',
         '24-settings-4-guard-1min-saved', '24-settings-5-brightness-30', '24-settings-6-brightness-100']
W, H, SCALE, PITCH = 135, 240, 2, 280


def main(argv):
    if len(argv) not in (2, 3):
        print(__doc__.strip().splitlines()[-3].strip())
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
        for y in range(H):
            for x in range(W):
                # every pixel of a 2x2 block in the look must equal the page pixel
                want = pp[x, y]
                block = [lp[i * PITCH + SCALE * x + dx, SCALE * y + dy] for dx in range(SCALE) for dy in range(SCALE)]
                if any(b != want for b in block):
                    diff += 1
                    if first is None:
                        first = (x, y, want, block[0])
        print(f'{name}: {diff} of {W * H} pixels differ' + (f' (first at {first[0]},{first[1]}: page {first[2]} look {first[3]})' if first else ''))
        if diff:
            worst = max(worst, 1)
    print('settings_look_compare: ' + ('IDENTICAL' if worst == 0 else 'DIFFERENT'))
    return worst


if __name__ == '__main__':
    sys.exit(main(sys.argv))

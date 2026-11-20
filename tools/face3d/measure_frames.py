#!/usr/bin/env python3
"""Measure what a rendered angle grid would cost in flash on the StickS3.
  python3 measure_frames.py VIEWS_DIR [--full YAWxPITCH] [--sheet OUT.png]
Each view PNG (any size, 135:160 aspect) is downscaled to the portrait size 135x160 (LANCZOS, black matte),
converted to little-endian RGB565 (43,200 B raw) and deflated (zlib level 9, the ESP32-S3 ROM has an inflater).
Prints per-frame raw/deflate sizes, the total for this grid, and the extrapolated total for a --full grid,
against the frame budget (G21: pack_frames.default_budget(), what the OTA slot leaves beside the app; the earlier
1.9 MB was the size of the unused assets partition). --sheet writes a contact sheet of the downscaled frames at 3x.
Quick sizing only: pack_frames.py builds the real sets."""
import glob, os, struct, sys, zlib
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pack_frames import default_budget

BUDGET = default_budget()
W, H = 135, 160


def rgb565le(im):
    out = bytearray()
    for r, g, b in im.convert('RGB').getdata():
        out += struct.pack('<H', ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3))
    return bytes(out)


def main(argv):
    views = argv[0]
    full = argv[argv.index('--full') + 1] if '--full' in argv else None
    sheet = argv[argv.index('--sheet') + 1] if '--sheet' in argv else None
    files = sorted(glob.glob(os.path.join(views, 'yaw*.png')))
    if not files: raise SystemExit(f'no yaw*.png in {views}')
    rows = []; frames = []
    for f in files:
        im = Image.open(f).convert('RGB').resize((W, H), Image.LANCZOS)
        raw = rgb565le(im); z = zlib.compress(raw, 9)
        rows.append((os.path.basename(f)[:-4], len(raw), len(z))); frames.append((os.path.basename(f)[:-4], im))
    tot_raw = sum(r[1] for r in rows); tot_z = sum(r[2] for r in rows)
    for name, raw, z in rows: print(f'{name:24} raw {raw:6d}  deflate {z:6d}  ({100 * z / raw:4.1f} %)')
    print(f'{len(rows)} frames: raw {tot_raw:,} B, deflate {tot_z:,} B (avg {tot_z // len(rows):,} B/frame); budget {BUDGET:,} B')
    if full:
        ny, npit = (int(v) for v in full.lower().split('x')); n = ny * npit
        est = tot_z // len(rows) * n
        print(f'full grid {ny} yaw x {npit} pitch = {n} frames: deflate about {est:,} B = {100 * est / BUDGET:.0f} % of budget; '
              f'max frames inside budget at this average: {BUDGET // (tot_z // len(rows))}')
    if sheet:
        k = 3; yaws = sorted({n.split('_')[0] for n, _ in frames}); pits = sorted({n.split('_')[1] for n, _ in frames})
        out = Image.new('RGB', (len(yaws) * (W * k + 4) + 4, len(pits) * (H * k + 4) + 4), (30, 30, 30))
        for n, im in frames:
            y, p = n.split('_'); out.paste(im.resize((W * k, H * k), Image.NEAREST), (4 + yaws.index(y) * (W * k + 4), 4 + pits.index(p) * (H * k + 4)))
        out.save(sheet); print('sheet', sheet)


if __name__ == '__main__':
    main(sys.argv[1:])

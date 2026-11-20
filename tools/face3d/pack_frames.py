#!/usr/bin/env python3
"""Pack rendered angle grids of the 3D Guardian head into the frame sets the StickS3 firmware embeds (G21).

  python3 tools/face3d/pack_frames.py pack --out firmware/art/persona/v3/frames [--budget BYTES] MOOD=VIEWS_DIR ...
  python3 tools/face3d/pack_frames.py verify firmware/art/persona/v3/frames

MOOD is VeryGood, Good, Medium, Bad or Horrible. VIEWS_DIR holds the PNGs project_views.py renders, one per angle,
named yaw<+-DD.D>_pitch<+-DD.D>.png: a full yaw x pitch grid (at most 32 x 16), any size with the 135:160 aspect.

Each view is put on black, downscaled to 135x160 (LANCZOS), converted to little-endian RGB565 (43,200 B, the same
bytes as a 2D portrait file) and deflated on its own (zlib level 9, RAW deflate: no zlib header, the firmware's
inflater reads RFC 1951 only). One mood = one <MOOD>.bin (layout in firmware/adapters/companion/head3d.hpp, whose
parse() is the only reader on the device) + one manifest.json for the whole pack: the grid, and per frame the
offset, size, adler32, the sha256 of the 43,200 inflated bytes and the sha256 of the view it came from.

A run always writes the WHOLE pack: a mood that is not named loses its <MOOD>.bin (the firmware then shows that
rating's 2D portrait). A pack above the budget is refused before anything is written. The same views give the
same bytes. Moods without a set, a frame that fails its check on the device: the 2D portrait, never a broken face.

Budget (MEASURED 2026-11-18, G21): the sets are embedded in the app image, and the app must fit one OTA slot.
  OTA slot (boards/sticks3/partitions.csv, ota_0 = ota_1)  3,145,728 B
  signed app without any frame set (APP_BYTES_WITHOUT_FRAMES below)
  reserve for code growth (RESERVE_BYTES)                     150,000 B
The ledger's "under 1.9 MB" came from the size of the unused `assets` partition; an app with 1.9 MB of frames
would be about 3.9 MB and cannot be installed over the air. build.sh's archive step checks the real image again.
"""
import hashlib, json, os, re, struct, sys, zlib
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
MOODS = ('VeryGood', 'Good', 'Medium', 'Bad', 'Horrible')
W, H = 135, 160
FRAME_BYTES = W * H * 2
MAX_YAW, MAX_PITCH = 32, 16
FORMAT = 1
BURST_CAPACITY = 1600            # firmware/adapters/companion/burst.hpp: a face with more lit 3x3 blocks never bursts
# MEASURED 2026-11-18 (G21): $GUARDIAN_STORE/builds/20261118-023215-26731-sticks3/guardian_sticks3-signed.bin = 2,887,680 B with
# its two frame sets of 907,351 B, so 1,980,329 B without them (the G16J image without G21 code was 1,970,176 B).
# Re-measure when the app grows: signed app size minus COMPLETE.json head3d.set_bytes.
APP_BYTES_WITHOUT_FRAMES = 1_980_329
RESERVE_BYTES = 150_000
VIEW_NAME = re.compile(r'^yaw([+-]\d+(?:\.\d)?)_pitch([+-]\d+(?:\.\d)?)\.png$')


def ota_slot_bytes(partitions=ROOT / 'firmware/boards/sticks3/partitions.csv'):
    sizes = {}
    for line in Path(partitions).read_text().splitlines():
        cells = [c.strip() for c in line.split('#')[0].split(',')]
        if len(cells) >= 5 and cells[0] in ('ota_0', 'ota_1'): sizes[cells[0]] = int(cells[4], 0)
    if set(sizes) != {'ota_0', 'ota_1'} or sizes['ota_0'] != sizes['ota_1']:
        raise SystemExit(f'{partitions}: expected two equal OTA slots, found {sizes}')
    return sizes['ota_0']


def default_budget():
    return ota_slot_bytes() - APP_BYTES_WITHOUT_FRAMES - RESERVE_BYTES


def view_name(yaw_tenths, pitch_tenths):
    return f'yaw{yaw_tenths / 10:+05.1f}_pitch{pitch_tenths / 10:+05.1f}'


def load_views(folder):
    """{(yaw tenths, pitch tenths): path} for a full grid, plus the two sorted angle lists."""
    folder = Path(folder)
    if not folder.is_dir(): raise SystemExit(f'{folder}: not a directory of views')
    found = {}
    for p in sorted(folder.iterdir()):
        m = VIEW_NAME.match(p.name)          # AppleDouble "._*" files on the share do not match
        if not m: continue
        key = (round(float(m.group(1)) * 10), round(float(m.group(2)) * 10))
        if key in found: raise SystemExit(f'{folder}: two views for {view_name(*key)}')
        found[key] = p
    if not found: raise SystemExit(f'{folder}: no yaw<+-DD.D>_pitch<+-DD.D>.png views')
    yaws = sorted({k[0] for k in found}); pitches = sorted({k[1] for k in found})
    if len(yaws) > MAX_YAW or len(pitches) > MAX_PITCH:
        raise SystemExit(f'{folder}: {len(yaws)} yaw x {len(pitches)} pitch angles; the firmware takes at most {MAX_YAW} x {MAX_PITCH}')
    missing = [view_name(y, p) for p in pitches for y in yaws if (y, p) not in found]
    if missing: raise SystemExit(f'{folder}: not a full grid, missing {", ".join(missing[:6])}{" ..." if len(missing) > 6 else ""}')
    if any(abs(a) > 3276 for a in yaws + pitches): raise SystemExit(f'{folder}: an angle beyond +-327.6 degrees')
    return found, yaws, pitches


def frame_bytes(path):
    """The view as the device paints it: on black, 135x160, little-endian RGB565."""
    im = Image.open(path)
    if im.size[0] * H != im.size[1] * W: raise SystemExit(f'{path}: {im.size[0]}x{im.size[1]} is not the 135:160 portrait aspect')
    if im.mode in ('RGBA', 'LA', 'P'):
        rgba = im.convert('RGBA'); black = Image.new('RGBA', rgba.size, (0, 0, 0, 255)); black.alpha_composite(rgba); im = black
    im = im.convert('RGB')
    if im.size != (W, H): im = im.resize((W, H), Image.Resampling.LANCZOS)
    raw = im.tobytes(); out = bytearray(FRAME_BYTES)
    for i in range(W * H):
        r, g, b = raw[3 * i], raw[3 * i + 1], raw[3 * i + 2]
        v = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
        out[2 * i] = v & 0xff; out[2 * i + 1] = v >> 8
    return bytes(out)


def deflate_raw(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    out = c.compress(data) + c.flush()
    if zlib.decompress(out, -15) != data: raise SystemExit('deflate round trip failed')
    return out


def lit_stats(frame):
    """Lit 3x3 blocks as the burst counts them (any non-black pixel), and the lit bounding box."""
    blocks = 0; x0, y0, x1, y1 = W, H, -1, -1
    rows = [frame[2 * W * y: 2 * W * (y + 1)] for y in range(H)]
    for y, row in enumerate(rows):
        xs = [x for x in range(W) if row[2 * x] or row[2 * x + 1]]
        if xs: x0 = min(x0, xs[0]); x1 = max(x1, xs[-1]); y0 = min(y0, y); y1 = max(y1, y)
    for gy in range(0, H, 3):
        for gx in range(0, W, 3):
            if any(rows[y][2 * x] or rows[y][2 * x + 1] for y in range(gy, min(gy + 3, H)) for x in range(gx, gx + 3)): blocks += 1
    return blocks, (x0, y0, x1 + 1, y1 + 1) if x1 >= 0 else (0, 0, 0, 0)


def build_set(mood, folder):
    """One mood's pack bytes and its manifest record."""
    found, yaws, pitches = load_views(folder)
    table = 24 + 2 * (len(yaws) + len(pitches)); first = table + 12 * len(found)
    streams = []; frames = []; at = first; lit_max = 0; box = [W, H, 0, 0]
    for p in pitches:
        for y in yaws:
            path = found[(y, p)]; raw = frame_bytes(path); z = deflate_raw(raw); adler = zlib.adler32(raw)
            blocks, b = lit_stats(raw); lit_max = max(lit_max, blocks)
            if b[2]: box = [min(box[0], b[0]), min(box[1], b[1]), max(box[2], b[2]), max(box[3], b[3])]
            frames.append({'yaw_deg': y / 10, 'pitch_deg': p / 10, 'offset': at, 'size': len(z), 'adler32': f'{adler:08x}',
                           'frame_sha256': hashlib.sha256(raw).hexdigest(), 'lit_blocks': blocks,
                           'view': path.name, 'view_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
            streams.append((at, len(z), adler, z)); at += len(z)
    head = struct.pack('<4sHBBHHBBHII', b'GH3D', FORMAT, MOODS.index(mood), 0, W, H, len(yaws), len(pitches), 0, at, first)
    head += struct.pack(f'<{len(yaws)}h', *yaws) + struct.pack(f'<{len(pitches)}h', *pitches)
    data = head + b''.join(struct.pack('<III', o, s, a) for o, s, a, _ in streams) + b''.join(z for _, _, _, z in streams)
    assert len(head) == table and len(data) == at
    record = {'file': f'{mood}.bin', 'file_sha256': hashlib.sha256(data).hexdigest(), 'mood_index': MOODS.index(mood), 'bytes': len(data),
              'yaw_deg': [y / 10 for y in yaws], 'pitch_deg': [p / 10 for p in pitches], 'views_dir': Path(folder).name,
              'lit_blocks_max': lit_max, 'lit_box': box if box[2] else [0, 0, 0, 0], 'frames': frames}
    return data, record


def pack(sets, out, budget=None):
    """Writes the whole pack into `out` and returns the manifest. Refuses (SystemExit) before writing anything."""
    out = Path(out); budget = default_budget() if budget is None else int(budget)
    if not sets: raise SystemExit('no MOOD=VIEWS_DIR given')
    unknown = [m for m in sets if m not in MOODS]
    if unknown: raise SystemExit(f'unknown mood {unknown[0]}: one of {", ".join(MOODS)}')
    built = {m: build_set(m, sets[m]) for m in MOODS if m in sets}
    total = sum(len(data) for data, _ in built.values())
    for m, (data, rec) in built.items():
        n = len(rec['frames'])
        print(f'{m:9} {len(rec["yaw_deg"])} yaw x {len(rec["pitch_deg"])} pitch = {n} frames, {len(data):,} B (avg {len(data) // n:,} B/frame), '
              f'lit blocks up to {rec["lit_blocks_max"]}, lit box {rec["lit_box"]}')
        if rec['lit_blocks_max'] > BURST_CAPACITY:
            print(f'{"":9} note: above {BURST_CAPACITY} lit blocks the snow-globe burst does not fire for that frame (burst.hpp capacity)')
    print(f'total {total:,} B of the budget {budget:,} B ({100 * total / budget:.1f} %)' if budget > 0 else f'total {total:,} B, budget {budget:,} B')
    if total > budget:
        raise SystemExit(f'refused: the pack is {total:,} B, above the budget of {budget:,} B (fewer angles, or fewer moods; nothing was written)')
    manifest = {'format': FORMAT, 'tool': 'tools/face3d/pack_frames.py',
                'frame': {'width': W, 'height': H, 'pixel': 'rgb565 little-endian', 'bytes': FRAME_BYTES, 'resample': 'LANCZOS', 'matte': 'black',
                          'deflate': 'raw (RFC 1951), zlib level 9, window 15', 'zlib': zlib.ZLIB_RUNTIME_VERSION},
                'budget_bytes': budget, 'total_bytes': total, 'sets': {m: rec for m, (_, rec) in built.items()}}
    out.mkdir(parents=True, exist_ok=True)
    for m, (data, _) in built.items():
        tmp = out / f'.{m}.bin.tmp'; tmp.write_bytes(data); os.replace(tmp, out / f'{m}.bin')
    for m in MOODS:
        stale = out / f'{m}.bin'
        if m not in built and stale.exists(): stale.unlink(); print(f'removed {stale.name}: {m} is not in this pack (its 2D portrait is shown)')
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=1) + '\n')
    problems = verify(out)
    if problems: raise SystemExit('written pack does not verify: ' + '; '.join(problems))
    print(f'wrote {out} ({len(built)} set{"s" if len(built) != 1 else ""}); verified')
    return manifest


def verify(out):
    """Problems with the pack in `out` against its own manifest ([] = every file and every frame is the pinned one)."""
    out = Path(out); problems = []
    try: manifest = json.loads((out / 'manifest.json').read_text())
    except (OSError, ValueError) as e: return [f'manifest.json: {e}']
    total = 0
    for mood, rec in manifest.get('sets', {}).items():
        path = out / rec['file']
        if rec['file'] != f'{mood}.bin' or mood not in MOODS: problems.append(f'{rec["file"]}: not the file name of mood {mood}'); continue
        if not path.is_file(): problems.append(f'{rec["file"]}: missing'); continue
        data = path.read_bytes(); total += len(data)
        if hashlib.sha256(data).hexdigest() != rec['file_sha256']: problems.append(f'{rec["file"]}: sha256 differs from the manifest'); continue
        for f in rec['frames']:
            try: raw = zlib.decompress(data[f['offset']: f['offset'] + f['size']], -15)
            except zlib.error as e: problems.append(f'{rec["file"]} {f["view"]}: {e}'); continue
            if len(raw) != FRAME_BYTES or hashlib.sha256(raw).hexdigest() != f['frame_sha256'] or f'{zlib.adler32(raw):08x}' != f['adler32']:
                problems.append(f'{rec["file"]} {f["view"]}: inflated frame differs from the manifest')
    for mood in MOODS:
        if mood not in manifest.get('sets', {}) and (out / f'{mood}.bin').exists(): problems.append(f'{mood}.bin: not in the manifest (the build would embed it)')
    if total != manifest.get('total_bytes'): problems.append(f'total {total} B differs from the manifest ({manifest.get("total_bytes")})')
    if total > manifest.get('budget_bytes', 0): problems.append(f'total {total} B is above the budget {manifest.get("budget_bytes")}')
    return problems


def main(argv):
    if len(argv) >= 2 and argv[0] == 'verify':
        problems = verify(argv[1])
        for p in problems: print('PROBLEM', p)
        if not problems: print(f'{argv[1]}: every set and frame matches the manifest')
        return 1 if problems else 0
    if len(argv) >= 4 and argv[0] == 'pack' and '--out' in argv:
        args = argv[1:]; out = args[args.index('--out') + 1]; budget = int(args[args.index('--budget') + 1]) if '--budget' in args else None
        skip = {args.index('--out'), args.index('--out') + 1} | ({args.index('--budget'), args.index('--budget') + 1} if '--budget' in args else set())
        sets = {}
        for i, a in enumerate(args):
            if i in skip: continue
            if '=' not in a: raise SystemExit(f'expected MOOD=VIEWS_DIR, got {a}')
            mood, folder = a.split('=', 1); sets[mood] = folder
        pack(sets, out, budget)
        return 0
    print(__doc__); return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

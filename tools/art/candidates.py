#!/usr/bin/env python3
"""G16Q art bench candidates: the approved v4 portraits as 135x240 RGB565 frames, one per pipeline
knob, for the StickS3 art bench (firmware/boards/sticks3/main/art_bench.*). The owner compares them
on the real glass; the winning knobs later become the Guardian's portrait pipeline.

  python3 tools/art/candidates.py build <masters_png dir> [--out DIR] [--previews DIR]
  python3 tools/art/candidates.py verify [DIR]

masters: $GUARDIAN_STORE/art-exports/G15/20261117-v4/masters_png/ (VeryGood, Horrible, Medium; 512x512 RGBA,
sha256-pinned below, the same files the shipped portraits were built from).
writes (default firmware/art/bench/): <A..E>_<Mood>.rgb565, ramp.rgb565 (135x240 little-endian
RGB565, 64,800 B each) and manifest.json with every sha256 and the knobs. --previews writes PNGs of
what each frame holds plus the master crops (large files: give it a folder in the store).

Candidates (frames A..D hold the 135x160 portrait in rows 20..179, the Guardian's face zone, on black):
  A  the pre-G16Q pipeline: crop (40,0,472,512), LANCZOS in sRGB, black matte, unsharp 1.0/90/2, rounded
     to 565. Since G16Q part 2 (owner's pick, 2026-11-18) the shipped portraits are D, not A.
  B  the same crop resized in linear light (sRGB decoded, premultiplied by alpha, LANCZOS, encoded),
     no unsharp, rounded to 565.
  C  B + unsharp 0.6/120/1.
  D  C + Floyd-Steinberg dither to 565 (instead of rounding).
  E  D's steps over the full 240 rows: master crop (112,0,400,512) scaled to 135x240, so the hood's
     sides are cut (measured per master in the manifest).
F, G and H are not frames: the bench shows D's frame with the panel gamma table (F), with it at
100 % backlight (G), and still versus breathing through the Guardian's painter (H).
ramp: five grey bands (0, 25, 50, 75, 100 %), top to bottom, for the camera.

Deterministic: fixed boxes, Pillow LANCZOS / UnsharpMask, the dither in plain IEEE double arithmetic.
The bytes are pinned for the Pillow and numpy versions recorded in the manifest; another version
that renders differently fails the pin instead of silently changing the art.
"""
import argparse, hashlib, json, platform, sys
from pathlib import Path

try:
    import numpy as np
    import PIL
    from PIL import Image, ImageFilter
except ImportError as missing:   # `verify` only hashes files and runs without them (build.sh calls it)
    np = PIL = Image = ImageFilter = None
    IMAGING_ERROR = missing

ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = ROOT / 'firmware' / 'art' / 'bench'

FRAME = (135, 240)                 # the StickS3 glass, upright
FACE = (135, 160)                  # the Guardian's face zone
FACE_ROW = 20                      # its first row (companion layout: rows 20..179)
FRAME_BYTES = FRAME[0] * FRAME[1] * 2
CROP = (40, 0, 472, 512)           # today's crop (art/persona/v2/build_assets.py PORTRAIT_CROP)
FULL_CROP = (112, 0, 400, 512)     # 288x512 = 135:240, centred on the same column as CROP
MOODS = ('VeryGood', 'Horrible', 'Medium')
LETTERS = ('A', 'B', 'C', 'D', 'E')
SHARPEN_TODAY = (1.0, 90, 2)       # the pre-G16Q build_assets.py PORTRAIT_SHARPEN (radius, percent, threshold)
SHARPEN_TUNED = (0.6, 120, 1)
RAMP_LEVELS = (0, 64, 128, 191, 255)
# The v4 masters (build_assets.py PORTRAIT_MASTERS_SHA256; tools/tests/test_art_candidates.py keeps them equal).
MASTERS_SHA256 = {
    'VeryGood': '234557de1c9209d3826b67fa4ec5868adfb6896f6e22f6b08e0d78a554751eb5',
    'Horrible': 'b6efb06b4eb3cf2295deda11a53ffe7235f3d506cfc854132667b5bedddb64c8',
    'Medium': '803cb9b9161d8ade7b970c7a7922c238d5da76208d84882d93028de27258d6a1',
}
MASTERS_AT = '$GUARDIAN_STORE/art-exports/G15/20261117-v4/masters_png/'


def open_master(path, mood):
    """The pinned 512x512 RGBA master of a mood; anything else is refused."""
    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != MASTERS_SHA256[mood]:
        raise ValueError(f'unexpected master {path}: sha256 {digest} (expected {MASTERS_SHA256[mood]})')
    im = Image.open(path).convert('RGBA')
    if im.size != (512, 512): raise ValueError(f'{path}: {im.size}, expected 512x512')
    return im


# ---- resize -----------------------------------------------------------------------------------
def today_resize(master):
    """The pre-G16Q resize (build_assets.crop_portrait before part 2, without its unsharp): CROP, LANCZOS on the sRGB
    codes, black matte. Returns RGB 135x160."""
    art = master.convert('RGBA').crop(CROP).resize(FACE, Image.Resampling.LANCZOS)
    lay = Image.new('RGBA', FACE, (0, 0, 0, 255)); lay.alpha_composite(art)
    return lay.convert('RGB')


def _decode_table():
    c = np.arange(256, dtype=np.float64) / 255.0
    return np.where(c <= 0.04045, c / 12.92, ((c + 0.055) / 1.055) ** 2.4)


def linear_resize(master, box, size):
    """`box` of the master resized to `size` in linear light: sRGB decoded, premultiplied by alpha
    (= matted on black), LANCZOS per channel in float, encoded back to sRGB codes. Returns RGB."""
    rgba = np.asarray(master.convert('RGBA').crop(box), dtype=np.uint8)
    alpha = rgba[..., 3].astype(np.float64) / 255.0
    table = _decode_table()
    out = np.empty((size[1], size[0], 3), dtype=np.float64)
    for c in range(3):
        light = (table[rgba[..., c]] * alpha).astype(np.float32)
        out[..., c] = np.asarray(Image.fromarray(light).resize(size, Image.Resampling.LANCZOS), dtype=np.float64)
    out = np.clip(out, 0.0, 1.0)
    code = np.where(out <= 0.0031308, out * 12.92, 1.055 * np.power(out, 1.0 / 2.4) - 0.055)
    return Image.fromarray(np.clip(np.rint(code * 255.0), 0, 255).astype(np.uint8))


def unsharp(im, params):
    radius, percent, threshold = params
    return im.convert('RGB').filter(ImageFilter.UnsharpMask(radius=radius, percent=percent, threshold=threshold))


# ---- RGB565 -----------------------------------------------------------------------------------
def round565(im):
    """Nearest 565 level per channel (art/persona/v2/make_sheets.to565), little-endian words."""
    px = im.convert('RGB').load()
    raw = bytearray()
    for y in range(im.height):
        for x in range(im.width):
            r, g, b = px[x, y]
            v = (round(r * 31 / 255) << 11) | (round(g * 63 / 255) << 5) | round(b * 31 / 255)
            raw += v.to_bytes(2, 'little')
    return bytes(raw)


def dither565(im):
    """Floyd-Steinberg error diffusion to 565, left to right, top to bottom, per channel on the sRGB
    codes. A level is worth index * 255 / 31 (or / 63); the error of each pixel goes 7/16 right,
    3/16 down-left, 5/16 down, 1/16 down-right. Colours that are exact 565 levels pass unchanged."""
    w, h = im.size
    src = np.asarray(im.convert('RGB'), dtype=np.float64)
    index = np.zeros((h, w, 3), dtype=np.int64)
    for c, top in enumerate((31, 63, 31)):
        step = 255.0 / top
        cur = [float(v) for v in src[0, :, c]]
        for y in range(h):
            nxt = [float(v) for v in src[y + 1, :, c]] if y + 1 < h else [0.0] * w
            for x in range(w):
                want = cur[x]
                q = int(want / step + 0.5)
                q = 0 if q < 0 else top if q > top else q
                index[y, x, c] = q
                err = want - q * step
                if err:
                    if x + 1 < w: cur[x + 1] += err * 7.0 / 16.0
                    if x > 0: nxt[x - 1] += err * 3.0 / 16.0
                    nxt[x] += err * 5.0 / 16.0
                    if x + 1 < w: nxt[x + 1] += err * 1.0 / 16.0
            cur = nxt
    words = (index[..., 0] << 11) | (index[..., 1] << 5) | index[..., 2]
    return words.astype('<u2').tobytes()


def expand565(raw, size):
    """What a frame holds, as an RGB image (each level at index * 255 / top, rounded)."""
    w = np.frombuffer(raw, dtype='<u2').astype(np.uint32).reshape(size[1], size[0])
    r = np.rint((w >> 11) * 255.0 / 31.0); g = np.rint(((w >> 5) & 63) * 255.0 / 63.0); b = np.rint((w & 31) * 255.0 / 31.0)
    return Image.fromarray(np.stack([r, g, b], axis=-1).astype(np.uint8))


def place(face):
    """A 135x160 face band in rows 20..179 of a black 135x240 frame."""
    if len(face) != FACE[0] * FACE[1] * 2: raise ValueError(f'face band is {len(face)} B, expected {FACE[0] * FACE[1] * 2}')
    return bytes(FACE_ROW * FRAME[0] * 2) + bytes(face) + bytes((FRAME[1] - FACE_ROW - FACE[1]) * FRAME[0] * 2)


# ---- candidates -------------------------------------------------------------------------------
def candidate(letter, master):
    """One candidate frame (FRAME_BYTES) of a 512x512 RGBA master."""
    if letter == 'A': return place(round565(unsharp(today_resize(master), SHARPEN_TODAY)))
    if letter == 'B': return place(round565(linear_resize(master, CROP, FACE)))
    if letter == 'C': return place(round565(unsharp(linear_resize(master, CROP, FACE), SHARPEN_TUNED)))
    if letter == 'D': return place(dither565(unsharp(linear_resize(master, CROP, FACE), SHARPEN_TUNED)))
    if letter == 'E': return dither565(unsharp(linear_resize(master, FULL_CROP, FRAME), SHARPEN_TUNED))
    raise ValueError(f'no candidate frame {letter!r} (F, G and H show D)')


def ramp():
    """Five grey bands of 48 rows, RAMP_LEVELS top to bottom, by the shipped rounding."""
    band = FRAME[1] // len(RAMP_LEVELS)
    im = Image.new('RGB', FRAME)
    for i, level in enumerate(RAMP_LEVELS):
        im.paste((level, level, level), (0, i * band, FRAME[0], (i + 1) * band))
    return round565(im)


def hood_cut(master):
    """How much of the hood (the master's alpha box) the full-height crop cuts, each side."""
    x0, _, x1, _ = master.getchannel('A').getbbox()
    scale = FRAME[1] / 512.0
    left, right = max(0, FULL_CROP[0] - x0), max(0, x1 - FULL_CROP[2])
    return {'alpha_box_x': [x0, x1], 'cut_master_px': [left, right], 'cut_glass_px': [round(left * scale, 1), round(right * scale, 1)]}


def _sha(data): return hashlib.sha256(data).hexdigest()


def build(masters_dir, out_dir, previews=None):
    if Image is None: raise ValueError(f'build needs numpy and Pillow ({IMAGING_ERROR})')
    masters_dir, out_dir = Path(masters_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files, cuts, frames = {}, {}, {}
    for mood in MOODS:
        master = open_master(masters_dir / f'{mood}.png', mood)
        cuts[mood] = hood_cut(master)
        for letter in LETTERS:
            frames[f'{letter}_{mood}.rgb565'] = candidate(letter, master)
        if previews:
            Path(previews).mkdir(parents=True, exist_ok=True)
            for name, box in (('today-crop', CROP), ('full-height-crop', FULL_CROP)):
                lay = Image.new('RGBA', (box[2] - box[0], box[3] - box[1]), (0, 0, 0, 255)); lay.alpha_composite(master.crop(box))
                lay.convert('RGB').save(Path(previews) / f'master_{mood}_{name}.png')
    frames['ramp.rgb565'] = ramp()
    for name, data in frames.items():
        if len(data) != FRAME_BYTES: raise ValueError(f'{name}: {len(data)} B, expected {FRAME_BYTES}')
        (out_dir / name).write_bytes(data)
        files[name] = _sha(data)
        if previews: expand565(data, FRAME).save(Path(previews) / (name[:-7] + '.png'))
    manifest = {
        'task': 'G16Q art bench candidates',
        'tool': 'tools/art/candidates.py build',
        'frame': list(FRAME), 'frame_bytes': FRAME_BYTES, 'rgb565_byte_order': 'little-endian',
        'face_band': {'rows': [FACE_ROW, FACE_ROW + FACE[1] - 1], 'size': list(FACE)},
        'masters_at': MASTERS_AT, 'masters': dict(MASTERS_SHA256),
        'candidates': {
            'A': {'crop': list(CROP), 'resize': 'LANCZOS on sRGB codes', 'unsharp': list(SHARPEN_TODAY), 'to565': 'round',
                  'note': "today's pipeline; the face band equals art/persona/v2/portrait/<Mood>_portrait.rgb565"},
            'B': {'crop': list(CROP), 'resize': 'LANCZOS in linear light, premultiplied alpha', 'unsharp': None, 'to565': 'round'},
            'C': {'crop': list(CROP), 'resize': 'LANCZOS in linear light, premultiplied alpha', 'unsharp': list(SHARPEN_TUNED), 'to565': 'round'},
            'D': {'crop': list(CROP), 'resize': 'LANCZOS in linear light, premultiplied alpha', 'unsharp': list(SHARPEN_TUNED), 'to565': 'Floyd-Steinberg'},
            'E': {'crop': list(FULL_CROP), 'size': list(FRAME), 'resize': 'LANCZOS in linear light, premultiplied alpha',
                  'unsharp': list(SHARPEN_TUNED), 'to565': 'Floyd-Steinberg', 'hood_cut': cuts},
            'F': 'D + the ST7789 gamma table (bench panel state, no frame)',
            'G': 'F at 100 % backlight (bench panel state, no frame)',
            'H': "D through the Guardian's portrait painter: still (breath 0) and breathing (bench, no frame)",
        },
        'ramp': {'levels_srgb': list(RAMP_LEVELS), 'rows_per_band': FRAME[1] // len(RAMP_LEVELS), 'order': 'top to bottom',
                 'rgb565': ['0x%04X' % int.from_bytes(frames['ramp.rgb565'][i * 48 * FRAME[0] * 2:][:2], 'little') for i in range(len(RAMP_LEVELS))]},
        'rendered_with': {'python': platform.python_version(), 'Pillow': PIL.__version__, 'numpy': np.__version__},
        'files': files,
    }
    (out_dir / 'manifest.json').write_text(json.dumps(manifest, indent=1) + '\n')
    return manifest


def verify(out_dir=None):
    """Every pinned frame is there with its size and sha256, and no other frame is in the folder."""
    out_dir = Path(out_dir or BENCH_DIR)
    manifest = json.loads((out_dir / 'manifest.json').read_text())
    want = sorted([f'{l}_{m}.rgb565' for l in LETTERS for m in MOODS] + ['ramp.rgb565'])
    if sorted(manifest['files']) != want: raise ValueError('manifest does not list exactly the bench frames')
    if sorted(p.name for p in out_dir.glob('*.rgb565')) != want: raise ValueError(f'{out_dir} does not hold exactly the pinned frames')
    for name, digest in manifest['files'].items():
        data = (out_dir / name).read_bytes()
        if len(data) != FRAME_BYTES: raise ValueError(f'{name}: {len(data)} B, expected {FRAME_BYTES}')
        if _sha(data) != digest: raise ValueError(f'{name} differs from its pin')
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='action', required=True)
    b = sub.add_parser('build'); b.add_argument('masters'); b.add_argument('--out', default=str(BENCH_DIR)); b.add_argument('--previews')
    v = sub.add_parser('verify'); v.add_argument('dir', nargs='?', default=str(BENCH_DIR))
    a = parser.parse_args(argv)
    if a.action == 'build':
        manifest = build(a.masters, a.out, a.previews)
        for name, digest in manifest['files'].items(): print(digest, name)
    else:
        print('OK', len(verify(a.dir)['files']), 'frames')


if __name__ == '__main__':
    try: main()
    except ValueError as e: sys.exit(f'candidates.py: {e}')

"""G16Q art bench candidates (tools/art/candidates.py): 135x240 RGB565 frames of the approved v4
portraits by candidate pipelines. Checks the frame layout, that candidate D (the owner's pick,
2026-11-18) is the shipped portrait byte for byte, that the linear-light resize averages light (not sRGB codes) and never
leaks the colour of transparent pixels, that the Floyd-Steinberg dither is deterministic, keeps
the average and leaves exact colours alone, the full-height crop, the grey ramp, the pins of the
committed frames, and that a rebuild from the pinned masters reproduces them byte for byte.

The two tests that read the v4 masters need the artifact store (GUARDIAN_STORE, environment or
~/.config/m5-guardian/local.conf). With a store configured they FAIL (not skip) when a master is
missing, because "byte-exact" is not shown by a test that did not run; only a checkout with no store
configured at all (a public clone) skips them, and says so."""
import hashlib, importlib.util, json, re, sys, tempfile, unittest
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / 'tools' / 'art' / 'candidates.py'
BENCH = ROOT / 'firmware' / 'art' / 'bench'
PORTRAITS = ROOT / 'firmware' / 'art' / 'persona' / 'v2' / 'portrait'
sys.path.insert(0, str(ROOT / 'tools'))
import guardian_local  # noqa: E402
MASTERS_REL = 'art-exports/G15/20261117-v4/masters_png'
try:
    MASTERS = guardian_local.store(check=False) / MASTERS_REL
except guardian_local.Missing:
    MASTERS = None   # no store configured: the two master tests skip (a public clone)
LETTERS = 'ABCDE'
MOODS = ('VeryGood', 'Horrible', 'Medium')


def load():
    spec = importlib.util.spec_from_file_location('candidates', TOOL)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def words(raw):
    return np.frombuffer(raw, dtype='<u2')


def expand(raw, size):
    """RGB565 words back to the 8-bit levels the panel shows (level * 255 / 31 or / 63)."""
    w = words(raw).astype(np.float64).reshape(size[1], size[0])
    r = np.floor(w / 2048); g = np.floor(w / 32) % 64; b = w % 32
    return np.stack([r * 255 / 31, g * 255 / 63, b * 255 / 31], axis=-1)


def opaque(rgb):
    """A 512x512 opaque master from an (512,512,3) uint8 array."""
    a = np.full((512, 512, 1), 255, dtype=np.uint8)
    return Image.fromarray(np.concatenate([rgb, a], axis=-1))


class Layout(unittest.TestCase):
    def setUp(self):
        self.m = load()

    def test_geometry_constants(self):
        m = self.m
        self.assertEqual(m.FRAME, (135, 240)); self.assertEqual(m.FACE, (135, 160)); self.assertEqual(m.FACE_ROW, 20)
        self.assertEqual(m.FRAME_BYTES, 64800)
        self.assertEqual(m.CROP, (40, 0, 472, 512))                 # today's crop (build_assets.PORTRAIT_CROP)
        x0, y0, x1, y1 = m.FULL_CROP                                # full height, 135:240, centred like today's crop
        self.assertEqual((y0, y1), (0, 512))
        self.assertEqual((x1 - x0) * 240, (y1 - y0) * 135)
        self.assertEqual(x0 + x1, m.CROP[0] + m.CROP[2])
        self.assertEqual(m.MOODS, MOODS)

    def test_place_puts_the_face_band_in_rows_20_to_179_on_black(self):
        face = bytes((i * 7 + 1) % 251 + 1 for i in range(135 * 160 * 2))
        frame = self.m.place(face)
        self.assertEqual(len(frame), 64800)
        self.assertEqual(frame[:20 * 135 * 2], bytes(20 * 135 * 2))
        self.assertEqual(frame[20 * 135 * 2:180 * 135 * 2], face)
        self.assertEqual(frame[180 * 135 * 2:], bytes(60 * 135 * 2))
        with self.assertRaises(ValueError): self.m.place(face[:-2])

    def test_round565_is_the_shipped_rounding_little_endian(self):
        im = Image.new('RGB', (2, 1)); im.putpixel((0, 0), (255, 0, 0)); im.putpixel((1, 0), (100, 150, 200))
        raw = self.m.round565(im)
        self.assertEqual(raw[:2], bytes([0x00, 0xF8]))              # 0xF800 little-endian
        r5, g6, b5 = round(100 * 31 / 255), round(150 * 63 / 255), round(200 * 31 / 255)
        self.assertEqual(int.from_bytes(raw[2:4], 'little'), (r5 << 11) | (g6 << 5) | b5)


class LinearLight(unittest.TestCase):
    def setUp(self):
        self.m = load()

    def stripes(self):
        rgb = np.zeros((512, 512, 3), dtype=np.uint8); rgb[:, ::2, :] = 255   # 1 px black / white columns
        return opaque(rgb)

    def test_fine_black_and_white_stripes_average_to_half_the_light(self):
        m = self.m
        lin = np.asarray(m.linear_resize(self.stripes(), m.CROP, m.FACE)).astype(np.float64)[40:120, 30:105]
        srgb = np.asarray(m.today_resize(self.stripes())).astype(np.float64)[40:120, 30:105]
        # half the light is sRGB code 188; averaging the codes gives 128 (too dark: what today's resize does)
        self.assertLess(abs(lin.mean() - 188), 4, lin.mean())
        self.assertLess(abs(srgb.mean() - 128), 4, srgb.mean())

    def test_flat_colours_survive_the_round_trip(self):
        m = self.m
        for colour in ((0, 0, 0), (255, 255, 255), (37, 190, 91), (128, 128, 128), (5, 3, 250)):
            rgb = np.empty((512, 512, 3), dtype=np.uint8); rgb[:] = colour
            out = np.asarray(m.linear_resize(opaque(rgb), m.CROP, m.FACE))
            self.assertEqual({tuple(int(v) for v in p) for p in out.reshape(-1, 3)}, {colour})

    def test_transparent_pixels_never_leak_their_colour(self):
        m = self.m
        rgba = np.zeros((512, 512, 4), dtype=np.uint8); rgba[..., 1] = 255      # transparent pure green everywhere
        yy, xx = np.mgrid[0:512, 0:512]
        disc = (xx - 256) ** 2 + (yy - 256) ** 2 < 150 ** 2
        rgba[disc] = (255, 0, 0, 255)                                           # an opaque red disc
        out = np.asarray(m.linear_resize(Image.fromarray(rgba), m.CROP, m.FACE)).astype(int)
        self.assertEqual(int(out[..., 1].max()), 0)                             # no green anywhere
        self.assertEqual(tuple(out[0, 0]), (0, 0, 0))                           # the matte is black
        self.assertEqual(tuple(out[80, 67]), (255, 0, 0))

    def test_output_size_follows_the_request(self):
        m = self.m
        out = m.linear_resize(self.stripes(), m.FULL_CROP, m.FRAME)
        self.assertEqual(out.size, (135, 240)); self.assertEqual(out.mode, 'RGB')


class Dither(unittest.TestCase):
    def setUp(self):
        self.m = load()

    def test_it_is_deterministic(self):
        rng = np.random.RandomState(7)
        im = Image.fromarray(rng.randint(0, 256, (48, 37, 3)).astype(np.uint8))
        self.assertEqual(self.m.dither565(im), self.m.dither565(im))

    def test_flat_in_between_grey_keeps_its_average_where_rounding_shifts_it(self):
        m = self.m
        im = Image.new('RGB', (64, 64), (100, 100, 100))            # between 5-bit levels 12 (98.7) and 13 (106.9)
        d = expand(m.dither565(im), (64, 64)); r = expand(m.round565(im), (64, 64))
        for c in range(3):
            self.assertLess(abs(d[..., c].mean() - 100), 0.25, (c, d[..., c].mean()))
        self.assertGreater(abs(r[..., 0].mean() - 100), 1.0)        # rounding alone is off by more than a code
        red = {int(v) >> 11 for v in words(m.dither565(im))}
        self.assertEqual(red, {12, 13})                             # only the two neighbouring levels

    def test_exact_565_colours_are_left_alone(self):
        # Only codes 0 and 255 are exact 565 levels (a level is index * 255 / 31 or / 63): the matte
        # and saturated primaries get no dither noise at all.
        m = self.m
        px = np.zeros((16, 32, 3), dtype=np.uint8)
        for x in range(32):
            px[:, x] = (255 * (x & 1), 255 * ((x >> 1) & 1), 255 * ((x >> 2) & 1))
        im = Image.fromarray(px)
        self.assertEqual(m.dither565(im), m.round565(im))
        black = Image.new('RGB', (9, 9), (0, 0, 0)); white = Image.new('RGB', (9, 9), (255, 255, 255))
        self.assertEqual(m.dither565(black), bytes(9 * 9 * 2))
        self.assertEqual(m.dither565(white), b'\xff' * (9 * 9 * 2))

    def test_smooth_gradient_keeps_its_local_average(self):
        m = self.m
        px = np.zeros((40, 128, 3), dtype=np.uint8)
        for x in range(128): px[:, x] = (60 + x // 4, 60 + x // 4, 60 + x // 4)
        im = Image.fromarray(px)
        d = expand(m.dither565(im), (128, 40))
        for x0 in range(0, 128, 16):                                # every 16 px wide block, each channel
            want = px[:, x0:x0 + 16].astype(np.float64).mean(axis=(0, 1))
            got = d[:, x0:x0 + 16].mean(axis=(0, 1))
            self.assertLess(np.abs(got - want).max(), 0.6, (x0, got, want))


class FullHeight(unittest.TestCase):
    def test_candidate_e_uses_all_240_rows_and_cuts_the_sides(self):
        m = load()
        rgb = np.zeros((512, 512, 3), dtype=np.uint8)
        rgb[:, :, 2] = 90                                           # blue body
        rgb[0:6, :, :] = (255, 0, 0); rgb[506:512, :, :] = (0, 255, 0)   # red top edge, green bottom edge
        rgb[:, 0:m.FULL_CROP[0] - 8, :] = (255, 255, 255)           # white only OUTSIDE the full-height crop
        rgb[:, m.FULL_CROP[2] + 8:, :] = (255, 255, 255)
        frame = m.candidate('E', opaque(rgb))
        self.assertEqual(len(frame), 64800)
        px = expand(frame, (135, 240))
        self.assertGreater(px[0, 60, 0], 200); self.assertLess(px[0, 60, 1], 40)        # red on the first row
        self.assertGreater(px[239, 60, 1], 200); self.assertLess(px[239, 60, 0], 40)    # green on the last row
        mid = px[20:220]
        self.assertLess(mid[..., 0].max(), 40)                      # none of the white sides is in the frame
        self.assertGreater(mid[..., 2].min(), 60)                   # every column and row is art, no matte


class Ramp(unittest.TestCase):
    def test_five_grey_bands_black_to_white(self):
        m = load()
        raw = m.ramp()
        self.assertEqual(len(raw), 64800)
        w = words(raw).reshape(240, 135)
        want = [0x0000, 0x4208, 0x8410, 0xBDF7, 0xFFFF]             # 0, 64, 128, 191, 255 by the shipped rounding
        self.assertEqual(m.RAMP_LEVELS, (0, 64, 128, 191, 255))
        for band, value in enumerate(want):
            self.assertEqual({int(v) for v in w[band * 48:(band + 1) * 48].reshape(-1)}, {value})


class Pins(unittest.TestCase):
    """The committed frames are exactly what the manifest pins and what a rebuild produces."""
    def setUp(self):
        self.m = load()
        self.manifest = json.loads((BENCH / 'manifest.json').read_text())

    def test_committed_frames_match_the_manifest(self):
        names = [f'{l}_{mood}.rgb565' for l in LETTERS for mood in MOODS] + ['ramp.rgb565']
        self.assertEqual(sorted(self.manifest['files']), sorted(names))
        for name in names:
            data = (BENCH / name).read_bytes()
            self.assertEqual(len(data), 64800, name)
            self.assertEqual(hashlib.sha256(data).hexdigest(), self.manifest['files'][name], name)
        self.assertEqual(sorted(p.name for p in BENCH.glob('*.rgb565')), sorted(names))   # nothing unpinned is embedded
        self.m.verify(BENCH)

    def test_masters_are_the_ones_the_shipped_portraits_were_built_from(self):
        text = (ROOT / 'firmware/art/persona/v2/build_assets.py').read_text()
        for mood in MOODS:
            pin = re.search(r"'%s':'([0-9a-f]{64})'" % mood, text).group(1)
            self.assertEqual(self.m.MASTERS_SHA256[mood], pin)
            self.assertEqual(self.manifest['masters'][mood], pin)

    def test_verify_refuses_a_changed_frame(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            for p in BENCH.iterdir():
                if p.is_file(): (d / p.name).write_bytes(p.read_bytes())
            self.m.verify(d)
            data = bytearray((d / 'D_Medium.rgb565').read_bytes()); data[40000] ^= 1
            (d / 'D_Medium.rgb565').write_bytes(bytes(data))
            with self.assertRaises(ValueError): self.m.verify(d)

    def need_masters(self):
        if MASTERS is None:
            self.skipTest(f'no artifact store configured (GUARDIAN_STORE); the v4 masters live in <store>/{MASTERS_REL}')
        for mood in MOODS:
            if not (MASTERS / f'{mood}.png').is_file():
                self.fail(f'v4 master missing: {MASTERS}/{mood}.png (is the store mounted?)')

    def test_candidate_d_is_the_shipped_portrait_byte_for_byte(self):
        # G16Q part 2: the owner picked D on the glass (2026-11-18, "its the difuser. perfect",
        # firmware/evidence/sticks3-G16Q-artbench-20261118.log); build_assets.py now renders the portraits with it.
        self.need_masters()
        for mood in MOODS:
            frame = self.m.candidate('D', self.m.open_master(MASTERS / f'{mood}.png', mood))
            shipped = (PORTRAITS / f'{mood}_portrait.rgb565').read_bytes()
            self.assertEqual(frame[20 * 135 * 2:180 * 135 * 2], shipped, mood)
            self.assertEqual(frame, (BENCH / f'D_{mood}.rgb565').read_bytes(), mood)
            # A stays the pre-G16Q pipeline the bench compared against.
            self.assertEqual(self.m.candidate('A', self.m.open_master(MASTERS / f'{mood}.png', mood)),
                             (BENCH / f'A_{mood}.rgb565').read_bytes(), mood)

    def test_rebuild_from_the_pinned_masters_is_byte_exact(self):
        self.need_masters()
        with tempfile.TemporaryDirectory() as d:
            built = self.m.build(MASTERS, Path(d))
            self.assertEqual(built['files'], self.manifest['files'])
            for name, digest in self.manifest['files'].items():
                self.assertEqual(hashlib.sha256((Path(d) / name).read_bytes()).hexdigest(), digest, name)
            self.assertEqual(json.loads((Path(d) / 'manifest.json').read_text()), self.manifest)

    def test_open_master_refuses_an_unpinned_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'VeryGood.png'
            Image.new('RGBA', (512, 512), (1, 2, 3, 255)).save(p)
            with self.assertRaises(ValueError): self.m.open_master(p, 'VeryGood')

    def test_every_knob_changes_the_frame(self):
        frames = {l: (BENCH / f'{l}_VeryGood.rgb565').read_bytes() for l in LETTERS}
        self.assertEqual(len(set(frames.values())), 5)              # A, B, C, D and E all differ


if __name__ == '__main__':
    unittest.main()

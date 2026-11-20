"""G21: the 3D head frame packer (tools/face3d/pack_frames.py), host only. Synthetic view PNGs stand in
for the Blender renders; nothing here calls Blender or Meshy. The byte-exact round trip through the
DEVICE's inflater is firmware/tests/head3d_check.cpp (it reads the shipped pack and this tool's manifest);
here the streams are checked with zlib, the format with an independent reader."""
import hashlib, importlib.util, io, json, struct, tempfile, unittest, zlib
from contextlib import redirect_stdout
from pathlib import Path

from PIL import Image

HERE = Path(__file__).resolve().parents[1]
W, H = 135, 160


def load():
    spec = importlib.util.spec_from_file_location('face3d_pack', HERE / 'face3d' / 'pack_frames.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def view(path, yaw, pitch, scale=4, mode='RGB', seed=0):
    """A deterministic picture that differs per angle: a gradient plus a bright block that moves with yaw and pitch."""
    im = Image.new(mode, (W * scale, H * scale), (0, 0, 0) if mode == 'RGB' else (0, 0, 0, 0))
    px = im.load()
    for y in range(40 * scale, 120 * scale):
        for x in range(30 * scale, 100 * scale):
            c = ((x // scale + seed) % 256, (y // scale) % 256, int(128 + yaw + pitch) % 256)
            px[x, y] = c if mode == 'RGB' else c + (255,)
    bx, by = int((60 + yaw) * scale), int((70 + pitch) * scale)
    for y in range(by, by + 8 * scale):
        for x in range(bx, bx + 8 * scale): px[x, y] = (255, 255, 255) if mode == 'RGB' else (255, 255, 255, 255)
    im.save(path)


def views(folder, yaws=(-30.0, 0.0, 30.0), pitches=(-15.0, 15.0), **kw):
    folder.mkdir(parents=True)
    for p in pitches:
        for y in yaws: view(folder / f'yaw{y:+05.1f}_pitch{p:+05.1f}.png', y, p, **kw)
    return folder


def rgb565le(path):
    """Independent of the tool: the documented conversion, written out long-hand."""
    im = Image.open(path)
    if im.mode == 'RGBA':
        black = Image.new('RGBA', im.size, (0, 0, 0, 255)); black.alpha_composite(im); im = black
    im = im.convert('RGB')
    if im.size != (W, H): im = im.resize((W, H), Image.Resampling.LANCZOS)
    out = bytearray()
    for r, g, b in im.getdata(): out += struct.pack('<H', ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3))
    return bytes(out)


def read_pack(data):
    """Independent reader of the layout in firmware/adapters/companion/head3d.hpp."""
    magic, fmt, mood, zero, w, h, ny, npitch, zero2, size, first = struct.unpack_from('<4sHBBHHBBHII', data, 0)
    yaw = struct.unpack_from(f'<{ny}h', data, 24); pitch = struct.unpack_from(f'<{npitch}h', data, 24 + 2 * ny)
    table = 24 + 2 * (ny + npitch)
    entries = [struct.unpack_from('<III', data, table + 12 * i) for i in range(ny * npitch)]
    return dict(magic=magic, format=fmt, mood=mood, zero=(zero, zero2), w=w, h=h, yaw=yaw, pitch=pitch, size=size, first=first,
                table=table, entries=entries)


class Face3dPack(unittest.TestCase):
    def setUp(self):
        self.m = load(); self.tmp = Path(tempfile.mkdtemp()); self.out = self.tmp / 'frames'

    def pack(self, sets, **kw):
        with redirect_stdout(io.StringIO()) as log: manifest = self.m.pack(sets, self.out, **kw)
        self.log = log.getvalue(); return manifest

    def test_pack_layout_is_the_one_the_firmware_parses(self):
        v = views(self.tmp / 'Medium-views')
        self.pack({'Medium': v})
        data = (self.out / 'Medium.bin').read_bytes(); p = read_pack(data)
        self.assertEqual((p['magic'], p['format'], p['mood'], p['zero'], p['w'], p['h']), (b'GH3D', 1, 2, (0, 0), 135, 160))
        self.assertEqual(p['yaw'], (-300, 0, 300)); self.assertEqual(p['pitch'], (-150, 150))
        self.assertEqual(p['size'], len(data)); self.assertEqual(p['first'], p['table'] + 12 * 6)
        at = p['first']
        for offset, size, adler in p['entries']:                 # back to back, to the end of the file
            self.assertEqual(offset, at); self.assertGreater(size, 0); at += size
        self.assertEqual(at, len(data))

    def test_every_frame_round_trips_byte_exact_and_is_pinned(self):
        v = views(self.tmp / 'v')
        manifest = self.pack({'VeryGood': v})
        data = (self.out / 'VeryGood.bin').read_bytes(); p = read_pack(data); rec = manifest['sets']['VeryGood']
        self.assertEqual(rec['file'], 'VeryGood.bin'); self.assertEqual(rec['mood_index'], 0)
        self.assertEqual(rec['file_sha256'], hashlib.sha256(data).hexdigest()); self.assertEqual(rec['bytes'], len(data))
        self.assertEqual(rec['yaw_deg'], [-30.0, 0.0, 30.0]); self.assertEqual(rec['pitch_deg'], [-15.0, 15.0])
        self.assertEqual(len(rec['frames']), 6)
        i = 0
        for pitch in (-15.0, 15.0):                              # pitch-major, as the table
            for yaw in (-30.0, 0.0, 30.0):
                f = rec['frames'][i]; offset, size, adler = p['entries'][i]; i += 1
                name = f'yaw{yaw:+05.1f}_pitch{pitch:+05.1f}.png'
                want = rgb565le(v / name)
                got = zlib.decompress(data[offset:offset + size], -15)   # raw deflate, no wrapper
                self.assertEqual(got, want, name); self.assertEqual(len(got), 43200)
                self.assertEqual(adler, zlib.adler32(want)); self.assertEqual(f['adler32'], f'{adler:08x}')
                self.assertEqual(f['frame_sha256'], hashlib.sha256(want).hexdigest())
                self.assertEqual((f['yaw_deg'], f['pitch_deg'], f['offset'], f['size'], f['view']), (yaw, pitch, offset, size, name))
                self.assertEqual(f['view_sha256'], hashlib.sha256((v / name).read_bytes()).hexdigest())
        self.assertEqual(manifest['total_bytes'], len(data))
        self.assertEqual(json.loads((self.out / 'manifest.json').read_text()), manifest)

    def test_views_at_the_panel_size_are_used_as_they_are_and_alpha_goes_on_black(self):
        small = views(self.tmp / 'small', scale=1); self.pack({'Good': small})
        p = read_pack((self.out / 'Good.bin').read_bytes()); offset, size, _ = p['entries'][0]
        self.assertEqual(zlib.decompress((self.out / 'Good.bin').read_bytes()[offset:offset + size], -15), rgb565le(small / 'yaw-30.0_pitch-15.0.png'))
        alpha = views(self.tmp / 'alpha', mode='RGBA'); out2 = self.tmp / 'frames2'
        with redirect_stdout(io.StringIO()): self.m.pack({'Bad': alpha}, out2)
        data = (out2 / 'Bad.bin').read_bytes(); offset, size, _ = read_pack(data)['entries'][0]
        got = zlib.decompress(data[offset:offset + size], -15)
        self.assertEqual(got, rgb565le(alpha / 'yaw-30.0_pitch-15.0.png')); self.assertEqual(got[:2], b'\x00\x00')   # transparent = black

    def test_the_same_views_always_give_the_same_bytes(self):
        v = views(self.tmp / 'v'); self.pack({'Medium': v})
        first = {p.name: p.read_bytes() for p in self.out.iterdir()}
        out2 = self.tmp / 'again'
        with redirect_stdout(io.StringIO()): self.m.pack({'Medium': v}, out2)
        self.assertEqual({p.name: p.read_bytes() for p in out2.iterdir()}, first)
        self.assertNotIn(str(self.tmp), (self.out / 'manifest.json').read_text())   # no machine paths in the repository

    def test_a_pack_above_the_budget_is_refused_and_nothing_is_written(self):
        v = views(self.tmp / 'v')
        manifest = self.pack({'Medium': v}); size = manifest['total_bytes']
        before = {p.name: p.read_bytes() for p in self.out.iterdir()}
        other = views(self.tmp / 'other', seed=5)
        with redirect_stdout(io.StringIO()): other_size = self.m.pack({'Medium': other}, self.tmp / 'probe')['total_bytes']
        with self.assertRaises(SystemExit) as e:
            self.pack({'Medium': other}, budget=other_size - 1)   # one byte over
        self.assertIn('budget', str(e.exception))
        self.assertEqual({p.name: p.read_bytes() for p in self.out.iterdir()}, before)   # the previous pack is untouched
        fresh = self.tmp / 'fresh'
        with self.assertRaises(SystemExit), redirect_stdout(io.StringIO()): self.m.pack({'Medium': v}, fresh, budget=100)
        self.assertFalse(fresh.exists() and any(fresh.iterdir()))
        # Exactly at the budget is allowed, and the manifest records the budget it was checked against.
        with redirect_stdout(io.StringIO()): m2 = self.m.pack({'Medium': v}, self.tmp / 'exact', budget=size)
        self.assertEqual(m2['budget_bytes'], size)

    def test_the_default_budget_is_what_the_ota_slot_leaves(self):
        slot = self.m.ota_slot_bytes()
        self.assertEqual(slot, 0x300000)                         # boards/sticks3/partitions.csv, ota_0 == ota_1
        self.assertEqual(self.m.default_budget(), slot - self.m.APP_BYTES_WITHOUT_FRAMES - self.m.RESERVE_BYTES)
        self.assertGreater(self.m.default_budget(), 0); self.assertLess(self.m.default_budget(), 1_900_000)
        v = views(self.tmp / 'v'); manifest = self.pack({'Medium': v})
        self.assertEqual(manifest['budget_bytes'], self.m.default_budget())

    def test_an_incomplete_or_odd_grid_is_refused(self):
        v = views(self.tmp / 'hole'); (v / 'yaw+00.0_pitch+15.0.png').unlink()
        with self.assertRaises(SystemExit) as e: self.pack({'Medium': v})
        self.assertIn('yaw+00.0_pitch+15.0', str(e.exception))
        empty = self.tmp / 'empty'; empty.mkdir()
        with self.assertRaises(SystemExit): self.pack({'Medium': empty})
        with self.assertRaises(SystemExit): self.pack({'Medium': self.tmp / 'missing'})
        wide = views(self.tmp / 'wide'); Image.new('RGB', (540, 600)).save(wide / 'yaw+00.0_pitch+15.0.png')
        with self.assertRaises(SystemExit) as e: self.pack({'Medium': wide})
        self.assertIn('135:160', str(e.exception))
        many = self.tmp / 'many'; many.mkdir()
        for i in range(33): view(many / f'yaw{i - 16.0:+05.1f}_pitch+00.0.png', i, 0, scale=1)
        with self.assertRaises(SystemExit) as e: self.pack({'Medium': many})
        self.assertIn('32', str(e.exception))
        with self.assertRaises(SystemExit): self.pack({'Fine': views(self.tmp / 'x')})          # not one of the five ratings
        with self.assertRaises(SystemExit): self.pack({})
        self.assertFalse(self.out.exists() and any(self.out.iterdir()))

    def test_a_rerun_replaces_the_whole_pack(self):
        self.pack({'Medium': views(self.tmp / 'a'), 'VeryGood': views(self.tmp / 'b', seed=9)})
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ['Medium.bin', 'VeryGood.bin', 'manifest.json'])
        (self.out / 'README-kept.txt').write_text('not the tool\'s file')
        manifest = self.pack({'Good': views(self.tmp / 'c', seed=3)})
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ['Good.bin', 'README-kept.txt', 'manifest.json'])
        self.assertEqual(list(manifest['sets']), ['Good'])
        self.assertIn('removed', self.log)                       # it says which sets it dropped

    def test_sets_are_written_in_rating_order_with_the_keys_the_host_check_reads(self):
        self.pack({'Medium': views(self.tmp / 'a'), 'VeryGood': views(self.tmp / 'b', seed=9)})
        text = (self.out / 'manifest.json').read_text()
        self.assertLess(text.index('"file": "VeryGood.bin"'), text.index('"file": "Medium.bin"'))
        self.assertEqual(text.count('"frame_sha256": "'), 12); self.assertEqual(text.count('"file_sha256": "'), 2)
        self.assertRegex(text, r'"budget_bytes": \d+'); self.assertRegex(text, r'"total_bytes": \d+')
        first_set = text[text.index('"file": "VeryGood.bin"'):text.index('"file": "Medium.bin"')]
        self.assertEqual(first_set.count('"frame_sha256": "'), 6)   # each set's frames follow its file key

    def test_verify_finds_a_changed_missing_or_stray_file(self):
        self.pack({'Medium': views(self.tmp / 'a'), 'VeryGood': views(self.tmp / 'b', seed=9)})
        self.assertEqual(self.m.verify(self.out), [])
        data = bytearray((self.out / 'Medium.bin').read_bytes()); data[-3] ^= 1; (self.out / 'Medium.bin').write_bytes(bytes(data))
        self.assertTrue(any('Medium.bin' in p for p in self.m.verify(self.out)))
        (self.out / 'Medium.bin').unlink()
        self.assertTrue(any('Medium.bin' in p and 'missing' in p for p in self.m.verify(self.out)))
        (self.out / 'Horrible.bin').write_bytes(b'stray')
        self.assertTrue(any('Horrible.bin' in p for p in self.m.verify(self.out)))
        self.assertTrue(self.m.verify(self.tmp / 'nowhere'))

    def test_command_line_packs_and_verifies(self):
        v = views(self.tmp / 'v')
        with redirect_stdout(io.StringIO()) as log:
            self.assertEqual(self.m.main(['pack', '--out', str(self.out), f'Medium={v}']), 0)
            self.assertEqual(self.m.main(['verify', str(self.out)]), 0)
        self.assertIn('Medium', log.getvalue()); self.assertIn('budget', log.getvalue())
        (self.out / 'Medium.bin').write_bytes(b'x')
        with redirect_stdout(io.StringIO()): self.assertEqual(self.m.main(['verify', str(self.out)]), 1)
        with self.assertRaises(SystemExit), redirect_stdout(io.StringIO()): self.m.main(['pack', '--out', str(self.out), '--budget', '10', f'Medium={v}'])


if __name__ == '__main__':
    unittest.main()

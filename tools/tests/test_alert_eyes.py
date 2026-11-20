"""v3 ALERT frames (firmware/art/persona/v2/alert_eyes.py): blood-red glowing eyes on a synthetic
512x512 master. Checks the two eye glows are found, only they (plus their halo) change, alpha and
far-away cyan pixels (hood rim, circuit line) are untouched, and p1 is dimmer than p0."""
import importlib.util, json, tempfile, unittest
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parents[2] / 'firmware' / 'art' / 'persona' / 'v2'


def load():
    spec = importlib.util.spec_from_file_location('alert_eyes', HERE / 'alert_eyes.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def synthetic_master():
    """A pale face disc with two cyan eye glows, a cyan hood rim far from the eyes and a thin cyan nose line."""
    im = Image.new('RGBA', (512, 512), (0, 0, 0, 0)); d = ImageDraw.Draw(im)
    d.ellipse((96, 60, 416, 470), fill=(190, 170, 150, 255))              # the mask
    d.rectangle((100, 60, 130, 470), fill=(0, 200, 230, 255))             # cyan hood rim (outside BAND x)
    d.line((256, 150, 256, 300), fill=(0, 220, 240, 255), width=3)        # nose line: thin, must not be an eye
    d.ellipse((175, 195, 230, 225), fill=(40, 230, 255, 255))             # left eye glow
    d.ellipse((290, 195, 345, 225), fill=(40, 230, 255, 255))             # right eye glow
    return im


class AlertEyes(unittest.TestCase):
    def setUp(self):
        self.m = load(); self.master = synthetic_master()

    def test_finds_the_two_eye_glows_and_not_the_nose_line_or_hood(self):
        rgb = np.asarray(self.master.convert('RGBA')).astype(np.float32)[..., :3]
        eyes, boxes = self.m.find_eyes(rgb)
        self.assertEqual(len(boxes), 2)
        (lx0, ly0, lx1, ly1), (rx0, ry0, rx1, ry1) = boxes
        self.assertTrue(lx0 >= 170 and lx1 <= 236 and ly0 >= 190 and ly1 <= 231, boxes)
        self.assertTrue(rx0 >= 285 and rx1 <= 351 and ry0 >= 190 and ry1 <= 231, boxes)
        self.assertFalse(eyes[200:300, 100:131].any(), 'hood rim must not be an eye')
        self.assertFalse(eyes[250:300, 254:259].any(), 'nose line below the eyes must not be an eye')

    def test_only_eyes_and_halo_change_alpha_untouched(self):
        out, _ = self.m.blood_eyes(self.master, 1.0)
        a = np.asarray(self.master).astype(int); b = np.asarray(out).astype(int)
        self.assertTrue((a[..., 3] == b[..., 3]).all(), 'alpha must be byte-identical')
        rim = np.abs(a[60:471, 100:131, :3] - b[60:471, 100:131, :3])    # 45+ px from the eye: only the faint far halo
        self.assertLessEqual(rim.max(), 8, 'hood rim gets at most a faint halo'); self.assertTrue((b[60:471, 100:131, 2] > b[60:471, 100:131, 0]).all(), 'hood rim stays cyan')
        self.assertTrue((a[380:470, :, :3] == b[380:470, :, :3]).all(), 'mouth/chin region untouched')
        eye = b[205:215, 190:215]                                        # inside the left glow
        self.assertTrue((eye[..., 0] > 200).all() and (eye[..., 0] > eye[..., 2] + 60).all(), 'eyes must be red')
        skin_near = b[232:238, 190:215]; skin_far = a[232:238, 190:215]   # just below the eye: red halo on the skin
        self.assertGreater(skin_near[..., 0].mean(), skin_far[..., 0].mean() + 10)

    def test_p1_is_dimmer_than_p0(self):
        p0, _ = self.m.blood_eyes(self.master, 1.0); p1, _ = self.m.blood_eyes(self.master, self.m.PULSE_DIM)
        r0 = np.asarray(p0).astype(int)[205:215, 190:215, 0].mean(); r1 = np.asarray(p1).astype(int)[205:215, 190:215, 0].mean()
        self.assertGreater(r0, r1 + 15)

    def test_build_writes_fifteen_masters_a_record_recolours_the_extremes_and_copies_the_rest(self):
        tmp = Path(tempfile.mkdtemp()); src = tmp / 'src'; src.mkdir()
        for mood in self.m.MOODS: self.master.save(src / f'{mood}.png')
        rec = self.m.build(src, tmp / 'out', review=str(tmp / 'review.png'))
        self.assertEqual(len(rec['files']), 15)
        self.assertEqual((tmp / 'out' / 'Good.png').read_bytes(), (src / 'Good.png').read_bytes())
        vg = np.asarray(Image.open(tmp / 'out' / 'VeryGood.png')).astype(int)[205:215, 190:215]
        self.assertTrue((vg[..., 1] > 200).all() and (vg[..., 1] > vg[..., 0] + 60).all(), 'Very good rating eyes are green')
        ho = np.asarray(Image.open(tmp / 'out' / 'Horrible.png')).astype(int)[205:215, 190:215]
        self.assertTrue((ho[..., 0] > 200).all() and (ho[..., 0] > ho[..., 2] + 60).all(), 'Horrible rating eyes are red')
        self.assertEqual(saved_alpha := np.asarray(Image.open(tmp / 'out' / 'VeryGood.png'))[..., 3].tolist(), np.asarray(self.master)[..., 3].tolist())
        saved = json.loads((tmp / 'out' / 'alert_eyes.json').read_text())
        self.assertEqual(saved['files'], rec['files']); self.assertEqual(len(saved['moods']['Bad']['eye_boxes']), 2)
        self.assertTrue((tmp / 'review.png').is_file())

    def test_missing_eye_glow_is_refused(self):
        im = synthetic_master(); ImageDraw.Draw(im).ellipse((290, 195, 345, 225), fill=(190, 170, 150, 255))   # erase the right eye
        with self.assertRaises(SystemExit): self.m.blood_eyes(im, 1.0)


if __name__ == '__main__':
    unittest.main()

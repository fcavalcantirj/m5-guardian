"""G16C: the IMU axis map is DERIVED from recorded serial IMU traces (never assumed).

Synthetic traces in the device's exact 'IMU <t_us> <sensortime> ax ay az gx gy gz' format
exercise the derivation and every refusal. Nothing here is a hardware measurement.
"""
import importlib.util, math, subprocess, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


def load():
    spec = importlib.util.spec_from_file_location('imu_axis_map', HERE / 'imu_axis_map.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def trace(acc_g, n=400, gyro_dps=(0.2, -0.1, 0.3), noise_g=0.004, lsb=4096.0, header=True, extra=''):
    lines = []
    if header:
        lines.append('G16A IMU STREAM addr=0x68 rate_hz=200 acc_lsb_per_g=%.0f gyr_lsb_per_dps=16.384 seconds=3 fields=t_us,sensortime,ax,ay,az,gx,gy,gz' % lsb)
    for i in range(n):
        a = [acc_g[k] + noise_g * math.sin(0.37 * i + k) for k in range(3)]
        g = [gyro_dps[k] + 0.2 * math.cos(0.11 * i + k) for k in range(3)]
        lines.append('IMU %d %d %d %d %d %d %d %d' % (1000000 + 5000 * i, 128 * i, *[round(v * lsb) for v in a], *[round(v * 16.384) for v in g]))
        if i == 7: lines.append('G14 STATUS control=companion ...')   # interleaved console lines are ignored
    return '\n'.join(lines) + '\n' + extra


class AxisMapTests(unittest.TestCase):
    def setUp(self):
        self.m = load(); self.tmp = tempfile.TemporaryDirectory(); self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        p = self.dir / name; p.write_text(text); return p

    def test_standing_and_lying_traces_give_a_right_handed_signed_map(self):
        # Standing USB-down: +1 g on +y; lying screen-up: +1 g on -z  ->  up=+2, out=-3, right=up x out=-1.
        r = self.m.derive(self.write('stand.log', trace((0.02, 0.99, -0.05))), self.write('lie.log', trace((0.01, 0.26, -0.96))))
        self.assertEqual((r['right'], r['up'], r['out']), (-1, 2, -3))
        self.assertEqual(self.m.tune_lines(r), ['TUNE imu.right=-1', 'TUNE imu.up=2', 'TUNE imu.out=-3'])
        self.assertGreaterEqual(r['standing']['samples'], 400)

    def test_other_orientations(self):
        r = self.m.derive(self.write('s.log', trace((-0.98, 0.05, 0.1))), self.write('l.log', trace((0.0, 0.97, 0.12))))
        self.assertEqual((r['up'], r['out']), (-1, 2))
        self.assertEqual(r['right'], -3)          # (-x) x (+y) = -z

    def test_optional_side_trace_cross_checks_the_right_axis(self):
        stand, lie = self.write('s.log', trace((0, 1, 0))), self.write('l.log', trace((0, 0, -1)))
        ok = self.write('side.log', trace((1.0, 0, 0)))      # lying on its right edge: world-up = screen LEFT = -right = +x
        self.assertEqual(self.m.derive(stand, lie, ok)['right'], -1)
        bad = self.write('bad.log', trace((-1.0, 0, 0)))
        with self.assertRaisesRegex(self.m.TraceError, 'right-edge trace'):
            self.m.derive(stand, lie, bad)

    def test_refusals(self):
        good = self.write('g.log', trace((0, 1, 0)))
        cases = {
            'samples': trace((0, 0, -1), n=50),
            'moving': trace((0, 0, -1), gyro_dps=(25, 0, 0)),
            'magnitude': trace((0, 0, -1.4)),
            'dominant': trace((0, 0.7, -0.7)),
        }
        for why, text in cases.items():
            with self.subTest(why=why), self.assertRaises(self.m.TraceError):
                self.m.derive(good, self.write(why + '.log', text))
        with self.assertRaisesRegex(self.m.TraceError, 'same axis'):
            self.m.derive(good, self.write('same.log', trace((0, -1, 0))))
        with self.assertRaisesRegex(self.m.TraceError, 'no IMU samples'):
            self.m.derive(good, self.write('empty.log', 'G14 STATUS only\n'))

    # Review 2026-11-17: the Wi-Fi "IMU POSE" line (adapters/imu/pose.hpp) carries the same two
    # numbers read_trace derives from a raw stream, so the stick can be calibrated cable-less.
    @staticmethod
    def pose(acc_g, gyro_dps=0.31, samples=400, lsb=4096):
        a = ','.join('%.1f' % (v * lsb) for v in acc_g)
        return 'TUNE ok\nG16C IMU POSE samples=%d age_ms=812 acc_mean=%s gyro_dps=%.2f acc_lsb_per_g=%d\n' % (samples, a, gyro_dps, lsb)

    def test_pose_lines_give_the_same_map_as_streams(self):
        r = self.m.derive(self.write('s.txt', self.pose((0.02, 0.99, -0.05))), self.write('l.txt', self.pose((0.01, 0.26, -0.96))))
        self.assertEqual((r['right'], r['up'], r['out']), (-1, 2, -3))
        self.assertEqual(r['standing']['samples'], 400)
        self.assertAlmostEqual(r['standing']['gyro_dps'], 0.31, places=2)

    def test_the_last_pose_line_is_used_and_moving_or_partial_poses_are_refused(self):
        moved = self.pose((1, 0, 0), gyro_dps=9.0) + self.pose((0, 1, 0))      # settled after the gesture
        self.assertEqual(self.m.dominant_axis('standing', self.m.read_trace(self.write('m.txt', moved))), 2)
        with self.assertRaisesRegex(self.m.TraceError, 'moving'):
            self.m.dominant_axis('standing', self.m.read_trace(self.write('mv.txt', self.pose((0, 1, 0), gyro_dps=9.0))))
        with self.assertRaisesRegex(self.m.TraceError, 'samples'):
            self.m.dominant_axis('standing', self.m.read_trace(self.write('p.txt', self.pose((0, 1, 0), samples=120))))
        with self.assertRaisesRegex(self.m.TraceError, 'no IMU samples'):
            self.m.read_trace(self.write('n.txt', 'G16C IMU POSE none reason=no_block_yet\n'))

    def test_stream_header_scale_is_used(self):
        r = self.m.derive(self.write('s.log', trace((0, 1, 0), lsb=2048)), self.write('l.log', trace((0, 0, -1), lsb=2048)))
        self.assertAlmostEqual(r['standing']['mean_g'][1], 1.0, places=2)

    def test_cli_prints_tune_lines_and_fails_closed(self):
        stand, lie = self.write('s.log', trace((0, 1, 0))), self.write('l.log', trace((0, 0, -1)))
        out = subprocess.run([sys.executable, str(HERE / 'imu_axis_map.py'), '--standing', str(stand), '--lying', str(lie)],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('TUNE imu.right=-1\nTUNE imu.up=2\nTUNE imu.out=-3', out.stdout)
        bad = subprocess.run([sys.executable, str(HERE / 'imu_axis_map.py'), '--standing', str(stand), '--lying', str(stand)],
                             capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0); self.assertNotIn('TUNE', bad.stdout)


if __name__ == '__main__':
    unittest.main()

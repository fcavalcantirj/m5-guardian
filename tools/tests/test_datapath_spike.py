"""G16J spike (a) runner (tools/datapath_spike.py), host only: a fake StickS3 on a fake serial port."""
import os as _os
_os.environ['GUARDIAN_LAB_STICK_MAC'] = '02:00:00:00:0b:01'   # synthetic stick under test; the environment wins over local.conf
import importlib.util, json, os, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


INFO = 'GRX1 INFO guardian-sticks3/1.0 mac=02:00:00:00:0b:01 boot=63017900d8a33748 max=1536\n'


class Clock:
    def __init__(self, step=0.05):
        self.t, self.step = 500.0, step

    def __call__(self):
        self.t += self.step
        return self.t


class FakeStick:
    """Keeps detect.datapath; STATUS numbers depend on it through `load(on)` -> (fps, queue_growth_per_status, heap)."""
    def __init__(self, load, start=0.0, refuse=False):
        self.load, self.value, self.refuse = load, start, refuse
        self.buffer, self.sent, self.queue_full, self.uptime = b'', [], 7, 100

    def write(self, data):
        line = data.decode().strip()
        self.sent.append(line)
        if line == 'STATUS':
            on = self.value >= 0.5
            fps, growth, heap = self.load(on)
            self.queue_full += growth
            self.uptime += 1
            self.buffer += (f'G14 STATUS control=companion heap_internal_min={heap} task_stack_free=6400 fps={fps} rx_queue_full={self.queue_full} '
                            f'reset=usb uptime_s={self.uptime} detectors=disconnect:frames=1,in_window=0,events=0,incidents=0,last=none,cooldown=0 '
                            f'air=none area_visible=0 datapath={"on" if on else "off"} cb_calls_s={900 if on else 300} cb_cpu_permille={9 if on else 3} '
                            f'cb_max_cycles=4000 rx_data={500 if on else 0} rx_eapol=0 rx_errors=0 rx_valid=10 loss_samples=5\n').encode()
        elif line == 'TUNE? detect.datapath':
            self.buffer += f'TUNE detect.datapath={self.value:g} min=0 max=1 default=0\nTUNE OK params=1 of 105 prefix=detect.datapath version=1.22 store=restored\n'.encode()
        elif line.startswith('TUNE detect.datapath='):
            if self.refuse:
                self.buffer += b'TUNE ERROR not saved (storage); detect.datapath=1 applied until reboot\n'
            else:
                self.value = float(line.split('=')[1])
                self.buffer += f'TUNE OK detect.datapath={self.value:g} version=1.23 saved\n'.encode()

    def read(self, n):
        out, self.buffer = self.buffer[:n], self.buffer[n:]
        return out


class DatapathSpike(unittest.TestCase):
    def setUp(self):
        self.m = load('datapath_spike')
        self.tmp = tempfile.TemporaryDirectory()
        self.raw = os.path.join(self.tmp.name, 'raw.jsonl')
        self.out = os.path.join(self.tmp.name, 'spike.log')

    def tearDown(self):
        self.tmp.cleanup()

    def run_spike(self, stick, **kw):
        clock = Clock()
        return self.m.run(stick, self.raw, self.out, seconds=5.0, interval=0.1, now=clock, sleep=lambda s: None, boot_text=INFO,
                          say=lambda s: None, wall='test', **kw)

    def test_a_light_load_says_on_and_the_setting_is_put_back(self):
        stick = FakeStick(lambda on: ('24.1' if on else '24.8', 0, 121000 if on else 123000))
        r = self.run_spike(stick)
        self.assertEqual(r['verdict'], 'on')
        self.assertEqual(stick.value, 0.0)                               # restored to what it was
        tunes = [s for s in stick.sent if s.startswith('TUNE')]
        self.assertEqual(tunes, ['TUNE? detect.datapath', 'TUNE detect.datapath=0', 'TUNE detect.datapath=1', 'TUNE detect.datapath=0'])
        self.assertEqual(r['off']['rx_queue_full_growth'], 0)
        self.assertEqual(r['on']['fps_min'], 24.1)
        self.assertEqual(r['on']['heap_internal_min'], 121000)
        self.assertEqual(r['on']['cb_cpu_permille_max'], 9)
        text = open(self.out).read()
        self.assertIn('VERDICT on', text)
        self.assertIn('fps_min=24.1', text)
        kinds = [json.loads(line)['type'] for line in open(self.raw)]
        self.assertEqual(kinds.count('phase'), 2)

    def test_slow_frames_or_queue_drops_say_off_for_load(self):
        r = self.run_spike(FakeStick(lambda on: ('17.9' if on else '24.8', 0, 120000)))
        self.assertEqual(r['verdict'], 'off (load)')
        self.assertTrue(any('fps' in reason for reason in r['reasons']))
        os.remove(self.raw); os.remove(self.out)
        r = self.run_spike(FakeStick(lambda on: ('24.0', 3 if on else 0, 120000)))
        self.assertEqual(r['verdict'], 'off (load)')
        self.assertTrue(any('rx_queue_full' in reason for reason in r['reasons']))
        os.remove(self.raw); os.remove(self.out)
        # Drops that were already there with the data path OFF are the home's baseline, not the data path's load.
        r = self.run_spike(FakeStick(lambda on: ('24.0', 1, 120000)))
        self.assertEqual(r['verdict'], 'on')

    def test_it_restores_a_setting_that_was_on_and_refuses_another_board(self):
        stick = FakeStick(lambda on: ('24.0', 0, 120000), start=1.0)
        self.run_spike(stick)
        self.assertEqual(stick.value, 1.0)
        os.remove(self.raw); os.remove(self.out)
        other = INFO.replace('02:00:00:00:0b:01', '02:00:00:00:0b:03')
        clock = Clock()
        with self.assertRaises(self.m.tw.WatchError):
            self.m.run(FakeStick(lambda on: ('24', 0, 1)), self.raw, self.out, seconds=1.0, now=clock, sleep=lambda s: None, boot_text=other,
                       say=lambda s: None)
        self.assertFalse(os.path.exists(self.raw))

    def test_a_refused_tune_stops_the_spike_without_a_verdict(self):
        stick = FakeStick(lambda on: ('24.0', 0, 120000), refuse=True)
        with self.assertRaises(self.m.SpikeError):
            self.run_spike(stick)
        self.assertFalse(os.path.exists(self.out))


if __name__ == '__main__':
    unittest.main()

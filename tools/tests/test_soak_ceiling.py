"""G16J spike (c): the benign ceiling per detector from a threat_watch soak file (tools/soak_ceiling.py).
Host only; the records are built here, no device."""
import os as _os
_os.environ['GUARDIAN_LAB_STICK_MAC'] = '02:00:00:00:0b:01'   # synthetic stick under test; the environment wins over local.conf
import importlib.util, io, json, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def det(name, in_window=0, events=0, incidents=0, extra=''):
    return f'{name}:frames=230,in_window={in_window},events={events},incidents={incidents},last=none,cooldown=0{extra}'


def status(t, uptime, probe=(0, 0, 0), deauth=(0, 0, 0), heap=120000, queue_full=0, fps='24.0', air=(3, 2500, 40)):
    dets = ';'.join([det('probe_flood', *probe), det('area_disconnect', *deauth), det('handshake', extra=',unconfigured')])
    line = (f'G14 STATUS control=companion heap_internal_min={heap} task_stack_free=6600 fps={fps} rx_queue_full={queue_full} '
            f'reset=usb uptime_s={uptime} detectors={dets} air=probes:{air[0]},beacons:{air[1]},tx:{air[2]},window_s:60 area_visible=0 datapath=off')
    return json.dumps({'type': 'status', 't': t, 'line': line})


class SoakCeiling(unittest.TestCase):
    def setUp(self):
        self.m = load('soak_ceiling')

    def test_ceiling_is_the_largest_window_count_and_the_event_rate(self):
        lines = [json.dumps({'type': 'start', 't': 0.0, 'mac': '02:00:00:00:0b:01', 'wall': '2026-11-17T23:22:12-0300'}),
                 status(10.0, 10, probe=(2, 10, 0)), status(70.0, 70, probe=(9, 40, 0), heap=110000, queue_full=3),
                 status(130.0, 130, probe=(4, 50, 0), deauth=(1, 3, 0), fps='19.5', air=(12, 2796, 44))]
        r = self.m.analyse(io.StringIO('\n'.join(lines) + '\n'))
        self.assertEqual(r['statuses'], 3)
        self.assertEqual(r['duration_s'], 120)
        p = r['detectors']['probe_flood']
        self.assertEqual((p['in_window_max'], p['events'], p['incidents']), (9, 50, 0))
        self.assertAlmostEqual(p['events_per_min_max'], 30.0)          # 30 events between t=10 and t=70
        self.assertEqual(r['detectors']['area_disconnect']['in_window_max'], 1)
        self.assertTrue(r['detectors']['handshake']['unconfigured'])
        self.assertEqual(r['heap_internal_min'], 110000)
        self.assertEqual(r['rx_queue_full'], {'first': 0, 'last': 0, 'max': 3})
        self.assertEqual(r['fps_min'], 19.5)
        self.assertEqual(r['air_max'], {'probes': 12, 'beacons': 2796, 'tx': 44})
        self.assertEqual(r['incidents_total'], 0)

    def test_a_reboot_restarts_the_counters_and_is_counted(self):
        lines = [status(10.0, 100, probe=(1, 500, 1)), status(20.0, 3, probe=(0, 2, 0)), status(80.0, 63, probe=(3, 12, 0))]
        r = self.m.analyse(io.StringIO('\n'.join(lines) + '\n'))
        self.assertEqual(r['reboots'], 1)
        p = r['detectors']['probe_flood']
        self.assertEqual(p['events'], 512)       # 500 before the reboot + 12 after
        self.assertEqual(p['incidents'], 1)
        self.assertEqual(r['incidents_total'], 1)

    def test_a_cut_last_line_is_skipped_not_fatal(self):
        text = status(10.0, 10) + '\n' + status(20.0, 20)[:80]
        r = self.m.analyse(io.StringIO(text))
        self.assertEqual((r['statuses'], r['skipped']), (1, 1))

    def test_report_names_every_detector_and_the_verdict(self):
        r = self.m.analyse(io.StringIO(status(10.0, 10, probe=(2, 10, 0)) + '\n' + status(70.0, 70, probe=(9, 40, 0)) + '\n'))
        text = self.m.report(r, 'soak.jsonl')
        self.assertIn('probe_flood', text)
        self.assertIn('in_window_max=9', text)
        self.assertIn('incidents_total=0', text)
        self.assertIn('handshake', text)
        self.assertIn('unconfigured', text)


if __name__ == '__main__':
    unittest.main()

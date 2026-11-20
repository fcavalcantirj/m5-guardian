"""Review 2026-11-17: read-only STATUS recorder for the G16F/G16G live proofs and the benign soak
(tools/threat_watch.py), host only. A fake serial port stands in for the StickS3."""
import os as _os
_os.environ['GUARDIAN_LAB_STICK_MAC'] = '02:00:00:00:0b:01'   # synthetic stick under test; the environment wins over local.conf
import importlib.util, io, json, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def det(name, incidents=0, events=0, last='none', extra=''):
    return f'{name}:frames=230,in_window=0,events={events},incidents={incidents},last={last},cooldown=0{extra}'


def status(uptime=60, heap=114375, stack=7160, queue_full=0, probe=0, deauth=0, reset='poweron', visible=0):
    dets = ';'.join([det('disconnect'), det('probe_flood', probe, 90, '2s' if probe else 'none'),
                     det('area_disconnect', deauth), det('handshake', extra=',unconfigured')])
    return (f'G14 STATUS control=companion screen=Face heap_internal_min={heap} task_stack_free={stack} imu=running@0x68 '
            f'rx_received=42623 rx_queue_full={queue_full} lock_losses=1 reset={reset} uptime_s={uptime} '
            f'power_source=battery detectors={dets} air=probes:14,beacons:2539,tx:44,window_s:58 area_visible={visible} '
            f'datapath=off cb_calls_s=0\n')


INFO = 'GRX1 INFO guardian-sticks3/1.0 mac=02:00:00:00:0b:01 boot=63017900d8a33748 max=1536\n'


class FakePort:
    def __init__(self, replies):
        self.replies, self.written, self.buffer = list(replies), [], b''

    def write(self, data):
        self.written.append(data)
        if data == b'STATUS\n' and self.replies:
            self.buffer += self.replies.pop(0).encode()

    def read(self, n):
        out, self.buffer = self.buffer[:n], self.buffer[n:]
        return out


class ThreatWatchTests(unittest.TestCase):
    def setUp(self):
        self.m = load('threat_watch')

    def test_status_line_is_parsed_into_fields_and_detectors(self):
        s = self.m.parse_status(status(probe=2, deauth=1, visible=1))
        self.assertEqual(s['heap_internal_min'], 114375); self.assertEqual(s['task_stack_free'], 7160)
        self.assertEqual(s['uptime_s'], 60); self.assertEqual(s['reset'], 'poweron'); self.assertEqual(s['area_visible'], 1)
        self.assertEqual(s['detectors']['probe_flood']['incidents'], 2)
        self.assertEqual(s['detectors']['probe_flood']['last'], '2s')
        self.assertEqual(s['detectors']['area_disconnect']['incidents'], 1)
        self.assertTrue(s['detectors']['handshake']['unconfigured'])
        self.assertEqual(s['air'], {'probes': 14, 'beacons': 2539, 'tx': 44, 'window_s': 58})

    def test_non_status_lines_are_not_parsed(self):
        self.assertIsNone(self.m.parse_status(INFO))
        self.assertIsNone(self.m.parse_status('G14 STATUS truncated without detectors\n'))

    def test_identity_comes_from_the_info_line(self):
        self.assertEqual(self.m.mac_from_info(INFO), '02:00:00:00:0b:01')
        self.assertIsNone(self.m.mac_from_info('G14 STATUS ...'))

    def test_new_incidents_and_reboots_are_reported_once(self):
        w = self.m.Watch()
        self.assertEqual(w.update(self.m.parse_status(status(uptime=10)), 0.0), [])
        ev = w.update(self.m.parse_status(status(uptime=11, probe=1)), 1.0)
        self.assertEqual(ev, [{'t': 1.0, 'kind': 'incident', 'detector': 'probe_flood', 'count': 1, 'new': 1}])
        self.assertEqual(w.update(self.m.parse_status(status(uptime=12, probe=1)), 2.0), [])   # no change, no event
        ev = w.update(self.m.parse_status(status(uptime=3, reset='panic')), 3.0)                 # uptime went back
        self.assertEqual(ev, [{'t': 3.0, 'kind': 'reboot', 'reset': 'panic', 'uptime_s': 3}])
        # Counters restart with the reboot: a later incident counts from the new baseline, not as negative.
        ev = w.update(self.m.parse_status(status(uptime=4, probe=1, reset='panic')), 4.0)
        self.assertEqual(ev, [{'t': 4.0, 'kind': 'incident', 'detector': 'probe_flood', 'count': 1, 'new': 1}])

    def test_summary_keeps_the_worst_values_and_totals(self):
        w = self.m.Watch()
        w.update(self.m.parse_status(status(uptime=10, heap=120000, stack=7500)), 0.0)
        w.update(self.m.parse_status(status(uptime=11, heap=99000, stack=6900, queue_full=3, deauth=2)), 1.0)
        w.update(self.m.parse_status(status(uptime=12, heap=110000, stack=7200, queue_full=3, deauth=2)), 2.0)
        s = w.summary()
        self.assertEqual(s['heap_internal_min'], 99000); self.assertEqual(s['task_stack_free_min'], 6900)
        self.assertEqual(s['rx_queue_full_max'], 3); self.assertEqual(s['reboots'], 0)
        self.assertEqual(s['incidents'], {'area_disconnect': 2}); self.assertEqual(s['statuses'], 3)

    def test_marks_give_latency_from_the_owner_start(self):
        w = self.m.Watch()
        w.update(self.m.parse_status(status(uptime=10)), 0.0)
        w.mark(5.0, 'probe flood started')
        ev = w.update(self.m.parse_status(status(uptime=17, probe=1)), 7.25)
        self.assertEqual(ev[0]['since_mark_s'], 2.25); self.assertEqual(ev[0]['mark'], 'probe flood started')

    def test_poll_sends_only_status_and_logs_every_reply(self):
        port = FakePort([status(uptime=10), status(uptime=11, probe=1)])
        log = io.StringIO(); clock = iter([0.0, 0.5, 1.0, 1.5, 2.0, 2.5])
        w = self.m.Watch()
        events = []
        for _ in range(2):
            events += self.m.poll_once(port, w, log, now=lambda: next(clock), wait_s=0.0)
        self.assertEqual(set(port.written), {b'STATUS\n'})                    # read-only: nothing else is ever sent
        rows = [json.loads(l) for l in log.getvalue().splitlines()]
        self.assertEqual([r['type'] for r in rows], ['status', 'status', 'event'])
        self.assertEqual(events[0]['detector'], 'probe_flood')

    def test_closed_stdin_never_produces_marks(self):
        # Review 2026-11-17: run with stdin closed (/dev/null, background), select() reports it readable
        # forever and readline() returns ''. That is end-of-input, never an owner mark.
        marks = self.m.MarkReader(io.StringIO(''))
        self.assertIsNone(marks.poll(ready=True)); self.assertTrue(marks.closed)
        self.assertIsNone(marks.poll(ready=True))
        typed = self.m.MarkReader(io.StringIO('probe flood started\n\n'))
        self.assertEqual(typed.poll(ready=True), 'probe flood started')
        self.assertEqual(typed.poll(ready=True), 'mark')                    # a bare Enter is a plain mark
        self.assertIsNone(typed.poll(ready=True)); self.assertTrue(typed.closed)

    def test_refuses_a_board_that_is_not_the_stick(self):
        with self.assertRaisesRegex(self.m.WatchError, 'not the StickS3'):
            self.m.check_identity('GRX1 INFO cardputer/1.2 mac=02:00:00:00:0b:03\n', '02:00:00:00:0b:01')
        with self.assertRaisesRegex(self.m.WatchError, 'no GRX1 INFO'):
            self.m.check_identity('noise\n', '02:00:00:00:0b:01')
        self.assertEqual(self.m.check_identity(INFO, '02:00:00:00:0B:01'), '02:00:00:00:0b:01')


if __name__ == '__main__':
    unittest.main()

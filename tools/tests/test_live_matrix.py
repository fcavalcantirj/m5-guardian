"""G16J live matrix runner (tools/live_matrix.py), host only. A fake serial port stands in for the
StickS3 and a scripted clock for time; nothing here talks to a device or starts an attack."""
import os as _os
_os.environ['GUARDIAN_LAB_STICK_MAC'] = '02:00:00:00:0b:01'   # synthetic stick under test; the environment wins over local.conf
import importlib.util, json, os, tempfile, unittest
from unittest import mock
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


INFO = 'GRX1 INFO guardian-sticks3/1.0 mac=02:00:00:00:0b:01 boot=63017900d8a33748 max=1536\n'


def status(uptime, **incidents):
    names = ['disconnect', 'baseline', 'probe_flood', 'beacon_flood', 'responder', 'area_disconnect', 'handshake']
    dets = ';'.join(f'{n}:frames=10,in_window=0,events=0,incidents={incidents.get(n, 0)},last=none,cooldown=0' for n in names)
    return (f'G14 STATUS control=companion selected=02:00:00:00:00:01 heap_internal_min=120000 task_stack_free=6600 fps=24.5 '
            f'app_version=guardian-test tune_version=1.22 rx_queue_full=0 reset=usb uptime_s={uptime} detectors={dets} '
            f'air=probes:3,beacons:2500,tx:40,window_s:60 area_visible=0 datapath=off\n')


class Clock:
    """Monotonic seconds that advance a little every time they are read."""
    def __init__(self, step=0.05):
        self.t, self.step = 1000.0, step

    def __call__(self):
        self.t += self.step
        return self.t


class FakeStick:
    """Answers STATUS from a function of the fake time; `plan(t)` returns the incident counters."""
    def __init__(self, clock, plan, reboot_at=None):
        self.clock, self.plan, self.buffer, self.writes, self.reboot_at = clock, plan, b'', 0, reboot_at

    def write(self, data):
        self.writes += 1
        if data == b'STATUS\n':
            t = self.clock.t
            uptime = int(t - 900) if not (self.reboot_at and t >= self.reboot_at) else int(t - self.reboot_at)
            self.buffer += status(uptime, **self.plan(t)).encode()

    def read(self, n):
        out, self.buffer = self.buffer[:n], self.buffer[n:]
        return out


class LiveMatrix(unittest.TestCase):
    def setUp(self):
        self.m = load('live_matrix')
        self.tmp = tempfile.TemporaryDirectory()
        self.raw = os.path.join(self.tmp.name, 'raw.jsonl')
        self.evidence = os.path.join(self.tmp.name, 'evidence.log')

    def tearDown(self):
        self.tmp.cleanup()

    def run_row(self, row, plan, reboot_at=None, **kw):
        clock = Clock()
        marks, said = [], []
        stick = FakeStick(clock, lambda t: plan(t, marks), reboot_at)

        def ask(prompt):
            marks.append(clock.t)
            return ''
        result = self.m.run_row(stick, row, self.raw, self.evidence, seconds=6.0, quiet_seconds=2.0, interval=0.1,
                                ask=ask, say=said.append, now=clock, sleep=lambda s: None, boot_text=INFO, wall='test', **kw)
        return result, said, marks

    def test_deauth_row_passes_with_time_to_alert_and_a_silent_twin(self):
        # The red burst fires 0.8 s after the owner's mark; nothing else happens.
        def plan(t, marks):
            return {'disconnect': 1} if marks and t >= marks[0] + 0.8 else {}
        result, said, marks = self.run_row('bruce-deauth', plan)
        self.assertTrue(result['pass'], result)
        self.assertEqual(list(result['fired']), ['disconnect'])
        self.assertGreaterEqual(result['time_to_alert_from_mark_s'], 0.8)
        self.assertLess(result['time_to_alert_from_mark_s'], 1.3)
        text = open(self.evidence).read()
        self.assertIn('VERDICT PASS', text)
        self.assertIn('row=bruce-deauth', text)
        self.assertIn('app_version=guardian-test', text)
        self.assertIn('UPPER bound', text)
        kinds = [json.loads(line)['type'] for line in open(self.raw)]
        self.assertEqual(kinds[0], 'start')
        self.assertEqual(kinds.count('phase'), 3)
        self.assertEqual(kinds[-1], 'result')
        self.assertTrue(any('proven' in s for s in said))

    def test_a_miss_a_late_alert_and_a_false_alarm_fail(self):
        result, _, _ = self.run_row('bruce-deauth', lambda t, marks: {})
        self.assertFalse(result['pass'])
        self.assertIn('no expected detector fired', result['reasons'][0])
        os.remove(self.raw); os.remove(self.evidence)
        result, _, _ = self.run_row('bruce-deauth', lambda t, marks: {'disconnect': 1} if marks and t >= marks[0] + 3.0 else {})
        self.assertFalse(result['pass'])
        self.assertIn('limit', result['reasons'][0])
        os.remove(self.raw); os.remove(self.evidence)

        def twin_false_alarm(t, marks):
            n = 1 if marks and t >= marks[0] + 0.5 else 0
            if len(marks) > 1 and t >= marks[1] + 2.0:
                n += 1
            return {'disconnect': n}
        result, _, _ = self.run_row('bruce-deauth', twin_false_alarm)
        self.assertFalse(result['pass'])
        self.assertTrue(any('benign' in r for r in result['reasons']))
        self.assertIn('unproven', self.m.doc_line(result, 'x.log'))

    def test_only_an_expected_detector_proves_a_row(self):
        # The probe detector firing does not prove the deauth row.
        result, _, _ = self.run_row('bruce-deauth', lambda t, marks: {'probe_flood': 1} if marks and t >= marks[0] + 0.5 else {})
        self.assertFalse(result['pass'])
        self.assertEqual(result['fired'], {})

    def test_noise_before_the_attack_and_a_reboot_void_the_row(self):
        result, _, _ = self.run_row('bruce-deauth', lambda t, marks: {'disconnect': 1 if t > 1001.0 else 0, 'beacon_flood': 1 if t > 1001.0 else 0})
        self.assertFalse(result['pass'])
        self.assertTrue(any('quiet phase' in r for r in result['reasons']))
        os.remove(self.raw); os.remove(self.evidence)
        result, _, _ = self.run_row('bruce-deauth', lambda t, marks: {'disconnect': 1} if marks and t >= marks[0] + 0.5 and t < 1006.0 else {},
                                    reboot_at=1006.0)
        self.assertFalse(result['pass'])
        self.assertTrue(any('rebooted' in r for r in result['reasons']))

    def test_a_silent_row_passes_only_without_incidents(self):
        result, _, _ = self.run_row('pi-hostile-ssid', lambda t, marks: {})
        self.assertTrue(result['pass'])
        self.assertIn('silent', self.m.doc_line(result, 'x.log'))
        os.remove(self.raw); os.remove(self.evidence)
        result, _, _ = self.run_row('pi-hostile-ssid', lambda t, marks: {'baseline': 1} if marks and t >= marks[0] + 1.0 else {})
        self.assertFalse(result['pass'])

    def test_wrong_board_unknown_row_and_existing_files_are_refused(self):
        clock = Clock()
        with self.assertRaises(self.m.MatrixError):
            self.m.run_row(FakeStick(clock, lambda t: {}), 'no-such-row', self.raw, self.evidence, boot_text=INFO)
        other = INFO.replace('02:00:00:00:0b:01', '02:00:00:00:0b:03')
        with self.assertRaises(self.m.tw.WatchError):
            self.m.run_row(FakeStick(clock, lambda t: {}), 'bruce-deauth', self.raw, self.evidence, boot_text=other,
                           ask=lambda p: '', say=lambda s: None, now=clock, sleep=lambda s: None)
        self.assertFalse(os.path.exists(self.raw))
        open(self.raw, 'w').close()
        with self.assertRaises(FileExistsError):
            self.m.run_row(FakeStick(clock, lambda t: {}), 'bruce-deauth', self.raw, self.evidence, seconds=1.0, quiet_seconds=0.5,
                           boot_text=INFO, ask=lambda p: '', say=lambda s: None, now=clock, sleep=lambda s: None)

    def test_it_only_ever_sends_status(self):
        clock = Clock()
        sent = []

        class Spy(FakeStick):
            def write(self, data):
                sent.append(data); super().write(data)
        self.m.run_row(Spy(clock, lambda t: {}), 'evilm5-probe-flood', self.raw, self.evidence, seconds=1.0, quiet_seconds=0.5, interval=0.1,
                       ask=lambda p: '', say=lambda s: None, now=clock, sleep=lambda s: None, boot_text=INFO)
        self.assertTrue(sent)
        self.assertEqual(set(sent), {b'STATUS\n'})

    def test_every_ledger_row_is_listed_with_known_detectors(self):
        known = {'disconnect', 'baseline', 'probe_flood', 'beacon_flood', 'responder', 'auth_flood', 'sae_commit', 'assoc_sleep',
                 'channel_switch', 'name_mismatch', 'marked_beacon', 'owe_twin', 'area_disconnect', 'rotation', 'handshake', 'noise_floor'}
        for key, (tool, attack, expected, colour, start, twin) in self.m.ROWS.items():
            self.assertTrue(set(expected) <= known, key)
            self.assertIn(colour, ('red', 'amber', 'none'))
            self.assertTrue(key.startswith(tool))
        for needed in ('bruce-deauth', 'bruce-targeted', 'bruce-beacon-spam', 'bruce-evil-portal', 'bruce-karma', 'bruce-pwngrid',
                       'evilm5-beacon-spam', 'evilm5-probe-flood', 'evilm5-karma-spear', 'evilm5-csa', 'evilm5-sae', 'evilm5-pwngrid',
                       'marauder-ap-clone', 'marauder-assoc-sleep', 'marauder-bad-msg', 'marauder-csa', 'marauder-quiet', 'marauder-sae',
                       'pi-disassoc', 'pi-targeted-pair', 'pi-auth-flood', 'pi-pmkid-orphan', 'pi-fake-m1', 'pi-csa-ff', 'pi-quiet',
                       'pi-hostile-ssid'):
            self.assertIn(needed, self.m.ROWS)

    def test_raw_evidence_is_refused_when_the_store_is_not_mounted(self):
        with self.assertRaises(self.m.MatrixError):
            self.m.require_store(os.path.join(self.tmp.name, 'missing'))
        self.m.require_store(self.tmp.name)
        store = os.path.join(self.tmp.name, 'store')
        os.makedirs(os.path.join(store, 'evidence-raw'))
        settings = {'GUARDIAN_STORE': store, 'GUARDIAN_LOCAL_CONF': os.path.join(self.tmp.name, 'absent.conf')}
        with mock.patch.dict(os.environ, settings):
            with self.assertRaisesRegex(self.m.MatrixError, 'guardian-store-root'):   # inside the store, no sentinel
                self.m.require_store(os.path.join(store, 'evidence-raw'))
            open(os.path.join(store, '.guardian-store-root'), 'w').close()
            self.m.require_store(os.path.join(store, 'evidence-raw'))
            self.assertEqual(self.m.default_raw_dir(), os.path.realpath(os.path.join(store, 'evidence-raw')))
        with mock.patch.dict(os.environ, {'GUARDIAN_LOCAL_CONF': os.path.join(self.tmp.name, 'absent.conf')}):
            for name in [k for k in os.environ if k.startswith('GUARDIAN_') and k != 'GUARDIAN_LOCAL_CONF']:
                os.environ.pop(name, None)
            with self.assertRaisesRegex(self.m.MatrixError, 'GUARDIAN_STORE'):
                self.m.default_raw_dir()


if __name__ == '__main__':
    unittest.main()

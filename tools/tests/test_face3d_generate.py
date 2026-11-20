"""G21-3d: Meshy candidate generator (tools/face3d/generate.py), host only. A fake `meshy` on PATH
answers in the CLI's v1 envelope and records every call; no real credits are ever spent here."""
import hashlib, importlib.util, io, json, os, stat, sys, tempfile, unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]

FAKE = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ['FAKE_MESHY_CALLS'], 'a') as f:
    f.write(json.dumps(args) + '\n')
def out(result, ok=True, code=0, error=None, warnings=()):
    print(json.dumps({'schema_version': 'meshy.cli/v1', 'ok': ok, 'result': result, 'error': error,
                      'warnings': list(warnings)}))
    sys.exit(code)
if args[0] == 'balance':
    out({'balance': int(os.environ.get('FAKE_BALANCE', '1470'))})
if args[1] == 'create':
    op = args[args.index('--operation-id') + 1]
    if os.environ.get('FAKE_FAIL_OP') and op.endswith(os.environ['FAKE_FAIL_OP']):
        out({'submission': {'state': 'unknown', 'operation_id': op, 'task_id': None}}, ok=False, code=7,
            error={'message': 'network dropped'})
    tid = 'task-' + op.rsplit('-', 1)[1]
    out({'task': None, 'submission': {'state': 'accepted', 'operation_id': op, 'task_id': tid}, 'task_id': tid})
if args[1] == 'get':
    tid = args[2]
    thumb = os.environ['FAKE_THUMB']
    out({'task': {'task_id': tid, 'status': 'SUCCEEDED', 'consumed_credits': 20,
                  'raw': {'id': tid, 'status': 'SUCCEEDED', 'consumed_credits': 20, 'expires_at': 1795210966209,
                          'thumbnail_url': 'file://' + thumb}}})
sys.exit(99)
'''


def load():
    spec = importlib.util.spec_from_file_location('face3d_generate', HERE / 'face3d' / 'generate.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


class Face3dGenerate(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        bin_ = self.tmp / 'bin'; bin_.mkdir()
        fake = bin_ / 'meshy'; fake.write_text(FAKE.replace('/usr/bin/env python3', sys.executable))
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        self.calls = self.tmp / 'calls.jsonl'; self.calls.touch()
        thumb = self.tmp / 'thumb.png'; thumb.write_bytes(b'\x89PNG fake')
        self.env = {'PATH': f'{bin_}:{os.environ["PATH"]}', 'FAKE_MESHY_CALLS': str(self.calls),
                    'FAKE_THUMB': str(thumb)}
        self.old_env = {k: os.environ.get(k) for k in [*self.env, 'FAKE_BALANCE', 'FAKE_FAIL_OP']}
        os.environ.update(self.env)
        self.g = load()
        # a store with its sentinel, a master and a manifest that pins it
        self.store = self.tmp / 'store'; (self.store / self.g.MASTERS).mkdir(parents=True)
        (self.store / self.g.SENTINEL).touch()
        png = b'\x89PNG medium master'
        (self.store / self.g.MASTERS / 'Medium.png').write_bytes(png)
        man = self.tmp / 'manifest.json'
        man.write_text(json.dumps({'sources': {'masters_png/Medium.png': hashlib.sha256(png).hexdigest()}}))   # the real manifest's key
        self.g.MANIFEST = man

    def tearDown(self):
        for k, v in self.old_env.items():
            if v is None: os.environ.pop(k, None)
            else: os.environ[k] = v

    def batch(self, cands):
        p = self.tmp / f'batch-{len(list(self.tmp.glob("batch-*")))}.json'
        p.write_text(json.dumps({'candidates': cands}))
        return str(p)

    def run_main(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                rc = self.g.main(list(argv))
            except SystemExit as e:
                rc = e.code
        return rc, buf.getvalue()

    def creates(self):
        return [json.loads(l) for l in self.calls.read_text().splitlines() if json.loads(l)[1:2] == ['create']]

    def log(self, stamp='s1'):
        p = self.store / self.g.RUNS / stamp / 'spend.jsonl'
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    TWO = [{'id': 'i1', 'kind': 'image-to-3d', 'master': 'Medium', 'should_texture': False},
           {'id': 't1', 'kind': 'text-to-3d-preview', 'prompt': 'hooded mask bust'}]

    def test_plan_prices_batch_without_calling_meshy(self):
        rc, out = self.run_main('plan', '--batch', self.batch(self.TWO))
        self.assertEqual(rc, 0)
        self.assertIn('TOTAL 40 credits', out)
        self.assertEqual(self.calls.read_text(), '')

    def test_submit_above_cap_sends_nothing(self):
        rc, _ = self.run_main('submit', '--batch', self.batch(self.TWO), '--cap', '39', '--store', str(self.store), '--stamp', 's1')
        self.assertIn('above the cap', str(rc))
        self.assertEqual(self.creates(), [])
        self.assertEqual(self.log(), [])

    def test_submit_refuses_when_balance_is_short(self):
        os.environ['FAKE_BALANCE'] = '30'
        rc, _ = self.run_main('submit', '--batch', self.batch(self.TWO), '--cap', '100', '--store', str(self.store), '--stamp', 's1')
        self.assertIn('balance 30', str(rc))
        self.assertEqual(self.creates(), [])

    def test_submit_refuses_master_with_wrong_hash(self):
        (self.store / self.g.MASTERS / 'Medium.png').write_bytes(b'tampered')
        rc, _ = self.run_main('submit', '--batch', self.batch(self.TWO), '--cap', '100', '--store', str(self.store), '--stamp', 's1')
        self.assertIn('sha256', str(rc))
        self.assertEqual(self.creates(), [])

    def test_submit_refuses_store_without_sentinel(self):
        (self.store / self.g.SENTINEL).unlink()
        rc, _ = self.run_main('submit', '--batch', self.batch(self.TWO), '--cap', '100', '--store', str(self.store), '--stamp', 's1')
        self.assertIn(self.g.SENTINEL, str(rc))
        self.assertEqual(self.creates(), [])

    def test_unpriced_option_needs_an_explicit_estimate(self):
        c = [{'id': 'i1', 'kind': 'image-to-3d', 'master': 'Medium', 'options': {'--geometry-resolution': '2k'}}]
        rc, _ = self.run_main('plan', '--batch', self.batch(c))
        self.assertIn('estimate_credits', str(rc))
        c[0]['estimate_credits'] = 45
        rc, out = self.run_main('plan', '--batch', self.batch(c))
        self.assertIn('TOTAL 45 credits', out)

    def test_forbidden_options_are_refused(self):
        c = [{'id': 'i1', 'kind': 'image-to-3d', 'master': 'Medium', 'options': {'--api-key': 'x'}}]
        rc, _ = self.run_main('submit', '--batch', self.batch(c), '--cap', '100', '--store', str(self.store), '--stamp', 's1')
        self.assertIn('not allowed', str(rc))
        self.assertEqual(self.creates(), [])

    def test_submit_logs_intent_before_and_outcome_after_each_task(self):
        rc, out = self.run_main('submit', '--batch', self.batch(self.TWO), '--cap', '40', '--store', str(self.store), '--stamp', 's1')
        self.assertEqual(rc, 0, out)
        creates = self.creates()
        self.assertEqual(len(creates), 2)
        for argv in creates:
            self.assertIn('--async', argv)
            self.assertIn('--output-schema', argv)
        self.assertEqual(creates[0][creates[0].index('--should-texture') + 1], 'false')
        self.assertEqual(creates[0][creates[0].index('--operation-id') + 1], 'guardian-face3d-s1-i1')
        events = [(r['event'], r.get('candidate')) for r in self.log()]
        self.assertEqual(events, [('batch', None), ('intent', 'i1'), ('submitted', 'i1'), ('intent', 't1'), ('submitted', 't1')])
        sub = [r for r in self.log() if r['event'] == 'submitted']
        self.assertEqual([r['task_id'] for r in sub], ['task-i1', 'task-t1'])
        intent = self.log()[1]
        self.assertEqual(len(intent['image_sha256']), 64)
        self.assertTrue((self.store / self.g.RUNS / 's1' / 'batch.json').is_file())

    def test_same_run_is_never_submitted_again(self):
        b = self.batch(self.TWO)
        self.run_main('submit', '--batch', b, '--cap', '40', '--store', str(self.store), '--stamp', 's1')
        rc, _ = self.run_main('submit', '--batch', b, '--cap', '40', '--store', str(self.store), '--stamp', 's1')
        self.assertIn('never re-submitted', str(rc))
        self.assertEqual(len(self.creates()), 2)

    def test_failed_submission_stops_the_batch(self):
        os.environ['FAKE_FAIL_OP'] = '-i1'
        rc, out = self.run_main('submit', '--batch', self.batch(self.TWO), '--cap', '40', '--store', str(self.store), '--stamp', 's1')
        self.assertEqual(rc, 2)
        self.assertEqual(len(self.creates()), 1)
        last = self.log()[-1]
        self.assertEqual((last['event'], last['state'], last['error']), ('failed', 'unknown', 'network dropped'))

    def test_retexture_uses_the_master_as_style_image_and_keeps_the_uv(self):
        c = [{'id': 'r1', 'kind': 'retexture', 'input_task_id': 'task-i1', 'master': 'Medium'}]
        rc, out = self.run_main('plan', '--batch', self.batch(c))
        self.assertEqual(rc, 0, out); self.assertIn('TOTAL 10 credits', out)
        rc, out = self.run_main('submit', '--batch', self.batch(c), '--cap', '10', '--store', str(self.store), '--stamp', 's1')
        self.assertEqual(rc, 0, out)
        argv = self.creates()[0]
        self.assertEqual(argv[:2], ['retexture', 'create'])
        self.assertEqual(argv[argv.index('--input-task-id') + 1], 'task-i1')
        self.assertTrue(argv[argv.index('--image-style-url') + 1].endswith('Medium.png'))
        self.assertEqual(argv[argv.index('--enable-original-uv') + 1], 'true')
        self.assertNotIn('--text-style-prompt', argv)
        self.assertEqual([r['resource'] for r in self.log() if r['event'] == 'submitted'], ['retexture'])

    def test_retexture_without_input_task_is_refused(self):
        c = [{'id': 'r1', 'kind': 'retexture', 'master': 'Medium'}]
        rc, _ = self.run_main('submit', '--batch', self.batch(c), '--cap', '10', '--store', str(self.store), '--stamp', 's1')
        self.assertIn('input_task_id', str(rc)); self.assertEqual(self.creates(), [])

    def test_status_records_real_credits_and_saves_thumbnails(self):
        self.run_main('submit', '--batch', self.batch(self.TWO), '--cap', '40', '--store', str(self.store), '--stamp', 's1')
        run = self.store / self.g.RUNS / 's1'
        rc, out = self.run_main('status', '--dir', str(run))
        self.assertEqual(rc, 0, out)
        self.assertIn('MEASURED credits consumed so far: 40', out)
        self.assertIn('task-i1', out)
        self.assertEqual((run / 'i1.thumb.png').read_bytes(), b'\x89PNG fake')
        st = [r for r in self.log() if r['event'] == 'status']
        self.assertEqual([r['consumed_credits'] for r in st], [20, 20])
        self.assertEqual(json.loads((run / 't1.task.json').read_text())['id'], 'task-t1')


if __name__ == '__main__':
    unittest.main()

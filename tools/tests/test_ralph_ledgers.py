"""Two Ralph ledgers in one checkout: guardian-tasks.json (firmware, the default) and website-tasks.json.

Unit checks import the runner; the end-to-end checks run a copy of the runner in a throwaway git
checkout with a fake `claude` on PATH (a shell script that prints READY FOR REVIEW). No real worker,
model or Ralph loop is ever started here.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import ralph_runner  # noqa: E402

ABSENT = {'GUARDIAN_LOCAL_CONF': '/nonexistent/guardian-test-local.conf'}
FIRMWARE, WEBSITE = 'guardian-tasks.json', 'website-tasks.json'


def task(task_id, deps=(), passes=False):
    return {'id': task_id, 'category': 'c', 'description': f'{task_id} description',
            'depends_on': list(deps), 'steps': ['s'], 'passes': passes}


FIRMWARE_TASKS = [task('G01')]
WEBSITE_TASKS = [task('W01'), task('W02', ['W01'])]

FAKE_CLAUDE = r'''#!/bin/sh
cat > /dev/null
if [ -n "${FAKE_COUNT:-}" ]; then echo run >> "$FAKE_COUNT"; fi
if [ -n "${FAKE_STARTED:-}" ]; then : > "$FAKE_STARTED"; fi
if [ -n "${FAKE_HOLD:-}" ]; then
    i=0
    while [ ! -e "$FAKE_HOLD" ] && [ "$i" -lt 300 ]; do sleep 0.1; i=$((i+1)); done
fi
if [ -n "${FAKE_MUTATE:-}" ]; then printf ' ' >> "$FAKE_MUTATE"; fi
echo "READY FOR REVIEW"
'''


class Selection(unittest.TestCase):
    def test_default_is_the_firmware_ledger(self):
        self.assertEqual(ralph_runner.ledger_name({}), FIRMWARE)
        self.assertEqual(ralph_runner.ledger_name({'RALPH_LEDGER': ''}), FIRMWARE)
        lane = ralph_runner.select_lane({})
        self.assertEqual(lane.name, FIRMWARE)
        self.assertEqual(lane.path, ROOT / FIRMWARE)
        self.assertEqual(lane.batch, ralph_runner.HOST_BATCH)
        self.assertEqual(lane.prompt, ROOT / 'tools/prompts/guardian-worker.md')

    def test_website_selection(self):
        lane = ralph_runner.select_lane({'RALPH_LEDGER': WEBSITE})
        self.assertEqual(lane.name, WEBSITE)
        self.assertEqual(lane.path, ROOT / WEBSITE)
        self.assertEqual(lane.batch, frozenset())
        self.assertEqual(lane.prompt, ROOT / 'tools/prompts/website-worker.md')

    def test_invalid_values_are_a_named_refusal(self):
        for value in ('other.json', '../guardian-tasks.json', '/tmp/website-tasks.json', 'tools/../website-tasks.json'):
            with self.subTest(value=value), self.assertRaises(ValueError) as caught:
                ralph_runner.select_lane({'RALPH_LEDGER': value})
            self.assertIn(value, str(caught.exception))
            self.assertIn(FIRMWARE, str(caught.exception))
            self.assertIn(WEBSITE, str(caught.exception))

    def test_a_missing_ledger_file_names_the_selected_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / FIRMWARE).write_text('[]\n')
            with self.assertRaisesRegex(ValueError, 'website-tasks.json'):
                ralph_runner.select_lane({'RALPH_LEDGER': WEBSITE}, root=Path(tmp))

    def test_ledger_diagnostics_name_the_selected_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / WEBSITE).write_text('{}\n')
            lane = ralph_runner.select_lane({'RALPH_LEDGER': WEBSITE}, root=Path(tmp))
            with self.assertRaisesRegex(ValueError, 'website-tasks.json must be an array'):
                ralph_runner.read_ledger(lane)


class DataRootPerLane(unittest.TestCase):
    def test_each_lane_has_its_own_store_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp).resolve()
            self.assertEqual(ralph_runner.data_root(dict(ABSENT, GUARDIAN_STORE=tmp)), store / 'ralph')
            self.assertEqual(ralph_runner.data_root(dict(ABSENT, GUARDIAN_STORE=tmp, RALPH_LEDGER=WEBSITE)),
                             store / 'ralph-website')

    def test_ralph_data_root_overrides_both_lanes(self):
        with tempfile.TemporaryDirectory() as tmp:
            for ledger in (FIRMWARE, WEBSITE):
                env = dict(ABSENT, GUARDIAN_STORE='/elsewhere', RALPH_DATA_ROOT=tmp, RALPH_LEDGER=ledger)
                self.assertEqual(ralph_runner.data_root(env), Path(tmp).resolve())


class Identity(unittest.TestCase):
    def lanes(self):
        return ralph_runner.select_lane({}), ralph_runner.select_lane({'RALPH_LEDGER': WEBSITE})

    def test_first_use_writes_the_identity_and_a_mismatch_is_refused(self):
        firmware, website = self.lanes()
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            ralph_runner.bind_data(data, website, write=True)
            self.assertEqual(json.loads((data / ralph_runner.IDENTITY).read_text()), {'ledger': WEBSITE})
            ralph_runner.bind_data(data, website)                     # same lane: fine
            with self.assertRaises(ValueError) as caught:
                ralph_runner.bind_data(data, firmware)
            self.assertIn(WEBSITE, str(caught.exception))
            self.assertIn(FIRMWARE, str(caught.exception))

    def test_a_read_only_check_writes_nothing(self):
        firmware, _ = self.lanes()
        with tempfile.TemporaryDirectory() as tmp:
            ralph_runner.bind_data(Path(tmp), firmware)
            self.assertFalse((Path(tmp) / ralph_runner.IDENTITY).exists())

    def test_a_legacy_queue_without_identity_belongs_to_the_firmware_ledger(self):
        firmware, website = self.lanes()
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            (data / 'handoffs.json').write_text('{}\n')
            with self.assertRaisesRegex(ValueError, 'guardian-tasks.json'):
                ralph_runner.bind_data(data, website, write=True)
            self.assertFalse((data / ralph_runner.IDENTITY).exists())
            ralph_runner.bind_data(data, firmware, write=True)
            self.assertEqual(json.loads((data / ralph_runner.IDENTITY).read_text()), {'ledger': FIRMWARE})


class Prompts(unittest.TestCase):
    def render(self, lane, data, extra=None):
        env = dict(ABSENT, GUARDIAN_STORE=str(data.parent), **(extra or {}))
        with mock.patch.dict(os.environ, env, clear=False):
            if 'RALPH_WEBSITE_SOURCE' not in (extra or {}):
                os.environ.pop('RALPH_WEBSITE_SOURCE', None)
            os.environ.pop('GUARDIAN_BROW_ROOT', None)
            selected = WEBSITE_TASKS[0] if lane.name == WEBSITE else FIRMWARE_TASKS[0]
            return ralph_runner.prompt_for(0, selected, data, data / 'attempt', lane)

    def test_the_website_prompt_renders_the_task_journal_run_and_source(self):
        _, website = self.lanes()
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp).resolve() / 'ralph-website'
            text = self.render(website, data, {'RALPH_WEBSITE_SOURCE': '/source/export-dir'})
            self.assertIn(json.dumps(WEBSITE_TASKS[0], indent=2), text)
            self.assertIn(str(data / 'progress.txt'), text)
            self.assertIn(str(data / 'attempt'), text)
            self.assertIn('/source/export-dir', text)
            self.assertIn(WEBSITE, text)
            for rule in ('READY FOR REVIEW', 'BLOCKED', 'website/', 'LICENSE', 'deploy'):
                self.assertIn(rule, text)
            self.assertNotRegex(text, r'\$\{?[A-Za-z_]')

    def test_the_website_source_is_empty_when_unset(self):
        _, website = self.lanes()
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp).resolve() / 'ralph-website'
            text = self.render(website, data)
            self.assertNotRegex(text, r'\$\{?[A-Za-z_]')
            self.assertIn('Owner source export: \n', text)

    def test_the_firmware_prompt_is_the_guardian_worker_template(self):
        firmware, _ = self.lanes()
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp).resolve() / 'ralph'
            text = self.render(firmware, data, {'RALPH_WEBSITE_SOURCE': '/source/export-dir'})
            self.assertIn('Do not edit guardian-tasks.json', text)
            self.assertNotIn('/source/export-dir', text)
            self.assertNotRegex(text, r'\$\{?[A-Za-z_]')

    lanes = Identity.lanes


class NonBatchWebsite(unittest.TestCase):
    def test_the_website_lane_ignores_host_batch(self):
        tasks = [dict(t) for t in WEBSITE_TASKS]
        with mock.patch.object(ralph_runner, 'HOST_BATCH', frozenset(('W01', 'W02'))):
            lane = ralph_runner.select_lane({'RALPH_LEDGER': WEBSITE})
            self.assertEqual(lane.batch, frozenset())
            key = ralph_runner.key(tasks[0])
            work = {'W01': {'key': key, 'status': 'awaiting_review', 'attempt': 'a1', 'inputs': {}}}
            pending, reason = ralph_runner.select_next(tasks, work, lane.batch)
            # W01's handoff does not unlock W02: the selection stays on W01 for review.
            self.assertEqual(pending[1]['id'], 'W01')
            self.assertFalse(ralph_runner.ready(tasks[0], tasks, work, lane.batch))
            # Under the patched set the firmware batch rules (and their FOUNDATION gate) would apply instead.
            self.assertEqual(ralph_runner.select_next(tasks, work, frozenset(('W01', 'W02'))),
                             (None, 'Foundation acceptance required: G01, G02, G03'))


class CheckoutLockPath(unittest.TestCase):
    def test_lock_lives_in_the_git_directory_of_a_checkout_or_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'main/.git').mkdir(parents=True)
            self.assertEqual(ralph_runner.checkout_lock_path(root / 'main'), root / 'main/.git' / ralph_runner.CHECKOUT_LOCK)
            gitdir = root / 'main/.git/worktrees/side'
            gitdir.mkdir(parents=True)
            (root / 'side').mkdir()
            (root / 'side/.git').write_text(f'gitdir: {gitdir}\n')
            self.assertEqual(ralph_runner.checkout_lock_path(root / 'side'), gitdir / ralph_runner.CHECKOUT_LOCK)
            with self.assertRaisesRegex(ValueError, 'git'):
                ralph_runner.checkout_lock_path(root)


@unittest.skipUnless(shutil.which('git'), 'git is needed for a throwaway checkout')
class EndToEnd(unittest.TestCase):
    """A copy of the runner in a throwaway checkout, a fake claude on PATH, receipts in temp dirs."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / 'repo'
        (self.repo / 'tools/prompts').mkdir(parents=True)
        for name in ('ralph_runner.py', 'guardian_local.py'):
            shutil.copy2(ROOT / 'tools' / name, self.repo / 'tools' / name)
        for prompt in (ROOT / 'tools/prompts').glob('*.md'):
            shutil.copy2(prompt, self.repo / 'tools/prompts' / prompt.name)
        (self.repo / FIRMWARE).write_text(json.dumps(FIRMWARE_TASKS, indent=2) + '\n')
        (self.repo / WEBSITE).write_text(json.dumps(WEBSITE_TASKS, indent=2) + '\n')
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir()
        fake = bin_dir / 'claude'
        fake.write_text(FAKE_CLAUDE)
        fake.chmod(0o755)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(('RALPH_', 'FAKE_', 'GUARDIAN_')) and k != 'CLAUDE_CONFIG_DIR'}
        self.env.update(ABSENT, PATH=f'{bin_dir}{os.pathsep}{os.environ.get("PATH", "")}',
                        PYTHONDONTWRITEBYTECODE='1')

    def lane_env(self, ledger, data, **extra):
        env = dict(self.env, RALPH_DATA_ROOT=str(data), **extra)
        if ledger:
            env['RALPH_LEDGER'] = ledger
        return env

    def args(self, *more):
        return [sys.executable, str(self.repo / 'tools/ralph_runner.py'), *more]

    def run_runner(self, env, *more):
        return subprocess.run(self.args(*more), env=env, cwd=self.repo, capture_output=True, text=True, timeout=60)

    def state(self, data):
        return json.loads((data / 'state.json').read_text())

    def test_status_names_the_missing_selected_ledger(self):
        (self.repo / WEBSITE).unlink()
        result = self.run_runner(self.lane_env(WEBSITE, self.tmp / 'web'), '--status')
        self.assertEqual(result.returncode, 1)
        self.assertIn(WEBSITE, result.stderr)

    def test_an_invalid_ledger_value_is_refused_before_anything_runs(self):
        count = self.tmp / 'count'
        result = self.run_runner(self.lane_env('../guardian-tasks.json', self.tmp / 'x', FAKE_COUNT=str(count)), '1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('../guardian-tasks.json', result.stderr)
        self.assertFalse(count.exists())

    def test_one_website_task_per_invocation_and_the_identity_is_written(self):
        data, count = self.tmp / 'web', self.tmp / 'count'
        result = self.run_runner(self.lane_env(WEBSITE, data, FAKE_COUNT=str(count)), '3')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(count.read_text().splitlines(), ['run'])
        self.assertEqual(self.state(data)['task_id'], 'W01')
        self.assertEqual(self.state(data)['status'], 'awaiting_review')
        self.assertEqual(json.loads((data / ralph_runner.IDENTITY).read_text()), {'ledger': WEBSITE})
        self.assertIn(WEBSITE, self.run_runner(self.lane_env(WEBSITE, data), '--status').stdout)

    def test_a_shared_data_root_is_refused_for_the_other_ledger(self):
        data, count = self.tmp / 'shared', self.tmp / 'count'
        self.assertEqual(self.run_runner(self.lane_env(WEBSITE, data), '1').returncode, 0)
        for more in (('1',), ('--status',), ('--dry-run',)):
            with self.subTest(more=more):
                result = self.run_runner(self.lane_env(None, data, FAKE_COUNT=str(count)), *more)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(WEBSITE, result.stderr)
                self.assertIn(FIRMWARE, result.stderr)
        self.assertFalse(count.exists())
        self.assertEqual(self.state(data)['task_id'], 'W01')

    def test_the_checkout_lock_excludes_a_second_runner_of_either_lane(self):
        started, release = self.tmp / 'started', self.tmp / 'release'
        first = subprocess.Popen(self.args('1'), cwd=self.repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 env=self.lane_env(None, self.tmp / 'fw', FAKE_STARTED=str(started), FAKE_HOLD=str(release)))
        try:
            deadline = time.monotonic() + 30
            while not started.exists() and time.monotonic() < deadline and first.poll() is None:
                time.sleep(0.05)
            self.assertTrue(started.exists(), 'the first runner never reached its worker')
            count = self.tmp / 'count'
            for ledger, data in ((WEBSITE, self.tmp / 'web'), (None, self.tmp / 'fw2')):
                with self.subTest(ledger=ledger):
                    second = self.run_runner(self.lane_env(ledger, data, FAKE_COUNT=str(count)), '1')
                    self.assertEqual(second.returncode, 1, second.stdout)
                    self.assertIn('checkout', second.stderr)
            self.assertFalse(count.exists())
        finally:
            release.write_text('')
            out, err = first.communicate(timeout=60)
        self.assertEqual(first.returncode, 0, out + err)
        self.assertEqual(self.state(self.tmp / 'fw')['status'], 'awaiting_review')
        # Released: the website lane now runs.
        self.assertEqual(self.run_runner(self.lane_env(WEBSITE, self.tmp / 'web'), '1').returncode, 0)

    def test_a_change_to_either_ledger_stops_either_lane(self):
        cases = ((None, WEBSITE), (None, FIRMWARE), (WEBSITE, FIRMWARE), (WEBSITE, WEBSITE))
        for n, (ledger, mutated) in enumerate(cases):
            with self.subTest(lane=ledger or FIRMWARE, mutated=mutated):
                data = self.tmp / f'data-{n}'
                target = self.repo / mutated
                original = target.read_bytes()
                result = self.run_runner(self.lane_env(ledger, data, FAKE_MUTATE=str(target)), '1')
                target.write_bytes(original)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(self.state(data)['status'], 'ledger_changed')
                self.assertIn(mutated, result.stdout)


if __name__ == '__main__':
    unittest.main()

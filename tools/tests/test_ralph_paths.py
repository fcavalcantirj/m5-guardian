"""The Ralph runner's data root and work-profile refusal come from owner-local settings (import only;
the loop is never started here)."""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import guardian_local  # noqa: E402
import ralph_runner  # noqa: E402

ABSENT = {'GUARDIAN_LOCAL_CONF': '/nonexistent/guardian-test-local.conf'}


class DataRoot(unittest.TestCase):
    def test_ralph_data_root_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(ABSENT, RALPH_DATA_ROOT=tmp, GUARDIAN_STORE='/elsewhere')
            self.assertEqual(ralph_runner.data_root(env), Path(tmp).resolve())

    def test_store_ralph_folder_from_the_environment_or_local_conf(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(ralph_runner.data_root(dict(ABSENT, GUARDIAN_STORE=tmp)), Path(tmp).resolve() / 'ralph')
            conf = Path(tmp) / 'local.conf'
            conf.write_text(f'GUARDIAN_STORE={tmp}\n')
            self.assertEqual(ralph_runner.data_root({'GUARDIAN_LOCAL_CONF': str(conf)}), Path(tmp).resolve() / 'ralph')

    def test_no_store_is_a_named_refusal(self):
        with self.assertRaisesRegex(guardian_local.Missing, 'GUARDIAN_STORE'):
            ralph_runner.data_root(dict(ABSENT))

    def test_checked_store_needs_its_sentinel(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(guardian_local.Missing, 'guardian-store-root'):
                ralph_runner.data_root(dict(ABSENT, GUARDIAN_STORE=tmp), check=True)
            (Path(tmp) / '.guardian-store-root').write_text('')
            self.assertEqual(ralph_runner.data_root(dict(ABSENT, GUARDIAN_STORE=tmp), check=True), Path(tmp).resolve() / 'ralph')


class Profile(unittest.TestCase):
    def test_the_configured_work_profile_is_refused_and_nothing_else(self):
        env = dict(ABSENT, GUARDIAN_FORBIDDEN_CLAUDE_CONFIG='work-profile')
        self.assertTrue(ralph_runner.forbidden_profile(dict(env, CLAUDE_CONFIG_DIR='/tmp/.claude-WORK-PROFILE')))
        self.assertFalse(ralph_runner.forbidden_profile(dict(env, CLAUDE_CONFIG_DIR='/tmp/.claude')))
        self.assertFalse(ralph_runner.forbidden_profile(dict(ABSENT, CLAUDE_CONFIG_DIR='/tmp/.claude-work-profile')))

    def test_the_runner_source_names_no_machine_or_employer(self):
        text = (ROOT / 'tools/ralph_runner.py').read_text()
        for word in ('/Volumes/', '/Users/'):
            self.assertNotIn(word, text)


class WorkerPrompt(unittest.TestCase):
    """The real template must render: a start of the loop fails on any placeholder the runner does not fill."""
    TASK = {'id': 'G99', 'category': 'core', 'description': 'd', 'depends_on': [], 'steps': ['s'], 'passes': False}

    def render(self, env_store, data):
        import os
        from unittest import mock
        env = dict(ABSENT, **({'GUARDIAN_STORE': env_store} if env_store else {}))
        with mock.patch.dict(os.environ, env, clear=False):
            for name in ('GUARDIAN_BROW_ROOT',) + (() if env_store else ('GUARDIAN_STORE',)):
                os.environ.pop(name, None)
            return ralph_runner.prompt_for(0, self.TASK, data, data / 'attempt')

    def test_the_prompt_renders_and_names_the_configured_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp).resolve() / 'store'
            store.mkdir()
            text = self.render(str(store), store / 'ralph')
            self.assertIn(str(store), text)
            self.assertIn(str(store / 'ralph' / 'attempt'), text)
            self.assertNotRegex(text, r'\$\{?[A-Za-z_]')       # no placeholder is left for the worker to guess

    def test_the_worker_process_gets_the_store_exported(self):
        # Ledger rows and docs write $GUARDIAN_STORE/...; an unset variable in the worker's shell would expand to nothing.
        import os
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp).resolve() / 'store'
            store.mkdir()
            conf = Path(tmp) / 'local.conf'
            conf.write_text(f'GUARDIAN_STORE={store}\n')
            with mock.patch.dict(os.environ, {'GUARDIAN_LOCAL_CONF': str(conf)}, clear=False):
                for name in ('GUARDIAN_STORE', 'GUARDIAN_BROW_ROOT'):
                    os.environ.pop(name, None)
                env = ralph_runner.worker_env(store / 'ralph')
                self.assertEqual(env['GUARDIAN_STORE'], str(store))
                self.assertEqual(env['GUARDIAN_LOCAL_CONF'], str(conf))     # the rest of the environment is passed on

    def test_without_a_configured_store_the_prompt_names_the_folder_beside_the_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp).resolve() / 'elsewhere' / 'ralph'      # RALPH_DATA_ROOT with no store configured
            text = self.render(None, data)
            self.assertIn(str(data.parent), text)
            self.assertNotRegex(text, r'\$\{?[A-Za-z_]')


if __name__ == '__main__':
    unittest.main()

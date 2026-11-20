"""Owner-local settings: environment first, then ~/.config/m5-guardian/local.conf, else a named refusal."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import guardian_local as gl  # noqa: E402


class ConfFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def conf(self, text):
        path = self.dir / 'local.conf'
        path.write_text(text)
        return path

    def test_reads_key_value_lines_comments_and_quotes(self):
        path = self.conf('# lab settings\n\nGUARDIAN_STORE = /srv/store\nGUARDIAN_LAB_PI_SSH="lab@pi-host"\nX=\'a b\'\n')
        self.assertEqual(gl.read_conf(path), {'GUARDIAN_STORE': '/srv/store', 'GUARDIAN_LAB_PI_SSH': 'lab@pi-host', 'X': 'a b'})

    def test_a_missing_file_is_empty(self):
        self.assertEqual(gl.read_conf(self.dir / 'absent.conf'), {})

    def test_a_malformed_line_names_its_number(self):
        path = self.conf('GUARDIAN_STORE=/srv/store\nnot a setting\n')
        with self.assertRaisesRegex(ValueError, r'local\.conf:2'):
            gl.read_conf(path)

    def test_environment_wins_then_conf_then_aliases(self):
        conf = {'GUARDIAN_STORE': '/from/conf', 'GUARDIAN_BROW_ROOT': '/alias/conf'}
        self.assertEqual(gl.get('GUARDIAN_STORE', 'GUARDIAN_BROW_ROOT', env={'GUARDIAN_STORE': '/from/env'}, conf=conf), '/from/env')
        self.assertEqual(gl.get('GUARDIAN_STORE', 'GUARDIAN_BROW_ROOT', env={'GUARDIAN_BROW_ROOT': '/alias/env'}, conf=conf), '/alias/env')
        self.assertEqual(gl.get('GUARDIAN_STORE', 'GUARDIAN_BROW_ROOT', env={}, conf=conf), '/from/conf')
        self.assertEqual(gl.get('GUARDIAN_STORE', 'GUARDIAN_BROW_ROOT', env={}, conf={'GUARDIAN_BROW_ROOT': '/alias/conf'}), '/alias/conf')
        self.assertIsNone(gl.get('GUARDIAN_STORE', env={}, conf={}))
        self.assertIsNone(gl.get('GUARDIAN_STORE', env={'GUARDIAN_STORE': ''}, conf={}))

    def test_require_names_the_key_the_file_and_the_template(self):
        with self.assertRaises(gl.Missing) as raised:
            gl.require('GUARDIAN_LAB_PI_SSH', purpose='the lab Pi ssh target', env={}, conf={})
        text = str(raised.exception)
        for part in ('GUARDIAN_LAB_PI_SSH', 'the lab Pi ssh target', 'local.conf', 'lab/local.conf.example'):
            self.assertIn(part, text)

    def test_conf_path_follows_its_environment_variable(self):
        self.assertEqual(gl.conf_path({'GUARDIAN_LOCAL_CONF': str(self.dir / 'x.conf')}), self.dir / 'x.conf')
        self.assertEqual(gl.conf_path({}), Path('~/.config/m5-guardian/local.conf').expanduser())

    def test_load_reads_the_file_named_by_the_environment(self):
        path = self.conf('GUARDIAN_STORE=/srv/store\n')
        self.assertEqual(gl.load({'GUARDIAN_LOCAL_CONF': str(path)}), {'GUARDIAN_STORE': '/srv/store'})


class Store(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Path(self.tmp.name) / 'store'
        self.store.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_refuses_without_a_store(self):
        with self.assertRaisesRegex(gl.Missing, 'GUARDIAN_STORE'):
            gl.store(env={}, conf={})

    def test_refuses_without_the_sentinel(self):
        with self.assertRaisesRegex(gl.Missing, r'\.guardian-store-root'):
            gl.store(env={'GUARDIAN_STORE': str(self.store)}, conf={})

    def test_a_store_with_its_sentinel_and_no_mount_setting(self):
        (self.store / gl.SENTINEL).write_text('')
        self.assertEqual(gl.store(env={'GUARDIAN_STORE': str(self.store)}, conf={}), self.store.resolve())

    def test_the_old_name_is_an_alias(self):
        (self.store / gl.SENTINEL).write_text('')
        self.assertEqual(gl.store(env={}, conf={'GUARDIAN_BROW_ROOT': str(self.store)}), self.store.resolve())

    def test_a_named_mount_must_be_a_mounted_share(self):
        (self.store / gl.SENTINEL).write_text('')
        settings = {'GUARDIAN_STORE': str(self.store), 'GUARDIAN_STORE_MOUNT': '/mnt/share'}
        with mock.patch.object(gl, 'mount_table', return_value='//u@host/Share on /mnt/share (apfs, local)\n'):
            with self.assertRaisesRegex(gl.Missing, 'not mounted as smbfs'):
                gl.store(env=settings, conf={})
        with mock.patch.object(gl, 'mount_table', return_value='//u@host/Share on /mnt/share (smbfs, nodev)\n'):
            self.assertEqual(gl.store(env=settings, conf={}), self.store.resolve())

    def test_unchecked_store_only_resolves_the_path(self):
        self.assertEqual(gl.store(env={'GUARDIAN_STORE': str(self.store)}, conf={}, check=False), self.store.resolve())


class ShellResolver(unittest.TestCase):
    """tools/guardian-local.sh gives the shell scripts the same answers."""

    def run_sh(self, script, env):
        base = {k: v for k, v in os.environ.items() if not k.startswith('GUARDIAN_')}
        base.update(env)
        return subprocess.run(['/bin/sh', '-c', f'. "{ROOT}/tools/guardian-local.sh"; {script}'],
                              capture_output=True, text=True, env=base)

    def test_shell_reads_environment_then_conf(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / 'local.conf'
            conf.write_text('# x\nGUARDIAN_LAB_PI_SSH = "lab@pi-host"\nGUARDIAN_BROW_ROOT=/alias\n')
            env = {'GUARDIAN_LOCAL_CONF': str(conf)}
            self.assertEqual(self.run_sh('guardian_conf GUARDIAN_LAB_PI_SSH', env).stdout, 'lab@pi-host\n')
            self.assertEqual(self.run_sh('guardian_conf GUARDIAN_STORE GUARDIAN_BROW_ROOT', env).stdout, '/alias\n')
            self.assertEqual(self.run_sh('guardian_conf GUARDIAN_LAB_PI_SSH', dict(env, GUARDIAN_LAB_PI_SSH='env@pi')).stdout, 'env@pi\n')
            self.assertEqual(self.run_sh('guardian_conf GUARDIAN_NOPE; echo rc=$?', env).stdout, 'rc=1\n')

    def test_shell_store_refuses_with_the_named_message_and_accepts_a_sentinel(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {'GUARDIAN_LOCAL_CONF': str(Path(tmp) / 'absent.conf')}
            run = self.run_sh('guardian_store', env)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('GUARDIAN_STORE', run.stderr)
            self.assertIn('lab/local.conf.example', run.stderr)
            store = Path(tmp) / 'store'
            store.mkdir()
            run = self.run_sh('guardian_store', dict(env, GUARDIAN_STORE=str(store)))
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('.guardian-store-root', run.stderr)
            (store / '.guardian-store-root').write_text('')
            run = self.run_sh('guardian_store', dict(env, GUARDIAN_STORE=str(store)))
            self.assertEqual((run.returncode, run.stdout), (0, f'{store}\n'))
            run = self.run_sh('guardian_store', dict(env, GUARDIAN_STORE=str(store), GUARDIAN_STORE_MOUNT=str(Path(tmp) / 'not-a-mount')))
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('not mounted as smbfs', run.stderr)


if __name__ == '__main__':
    unittest.main()

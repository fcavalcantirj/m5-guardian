"""Public-readiness guard: the tree may hold no personal or machine-specific value.

Every planted value below is assembled at run time, so this source file itself stays clean.
"""
import importlib.util, json, os, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
SEP = ':'


def load():
    spec = importlib.util.spec_from_file_location('public_check', HERE / 'public_check.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def mac(*octets):
    return SEP.join(f'{o:02X}' for o in octets)


REAL_MAC = mac(0xAC, 0x27, 0x6E, 0x01, 0x02, 0x03)          # universally administered, made up
LOCAL_MAC = mac(0x02, 0x11, 0x22, 0x33, 0x44, 0x55)         # locally administered: synthetic
GROUP_MAC = mac(0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB)         # group address: nobody's device
HOME = '/' + 'Users' + '/' + 'somebody'
VOLUME = '/' + 'Volumes' + '/' + 'DISK'


class Tree:
    """A throwaway tree with the required license files; no git, so every file is listed."""
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.write('LICENSE', 'MIT License\n')
        self.write('firmware/art/LICENSE', 'All rights reserved.\n')
        self.write('THIRD_PARTY_NOTICES.md', '# notices\n')
        self.write('src/ok.py', f'ADDRESS = "{LOCAL_MAC}"\nGROUP = "{GROUP_MAC}"\nALL = "FF:FF:FF:FF:FF:FF"\n')

    def write(self, rel, data):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return path

    def close(self):
        self.tmp.cleanup()


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.pc = load()
        self.tree = Tree()
        self.addCleanup(self.tree.close)

    def run_check(self, map_path=None):
        return self.pc.check(self.tree.root, map_path=map_path)

    def rules(self, findings):
        return sorted({f.rule for f in findings})

    def test_clean_tree_has_no_findings(self):
        self.assertEqual(self.run_check(), [])

    def test_real_radio_address_is_found_with_file_and_line(self):
        self.tree.write('docs/a.md', f'line one\nreceiver {REAL_MAC.lower()} here\n')
        found = self.run_check()
        self.assertEqual(self.rules(found), ['radio-address'])
        self.assertEqual((found[0].path, found[0].line), ('docs/a.md', 2))

    def test_dash_form_is_found_and_longer_hex_runs_are_not(self):
        self.tree.write('a.txt', REAL_MAC.replace(SEP, '-') + '\n')
        self.tree.write('b.txt', 'fingerprint ' + SEP.join(['AC'] * 20) + '\n')
        found = self.run_check()
        self.assertEqual([(f.rule, f.path) for f in found], [('radio-address', 'a.txt')])

    def test_home_and_volume_paths_are_found_but_patterns_are_not(self):
        self.tree.write('tools/x.sh', f'cd {HOME}/dev\ncp a {VOLUME}/store\n')
        self.tree.write('tools/y.sh', 'case "$p" in /' + 'Volumes' + '/*) exit 1;; esac\necho /' + 'Users' + '/<owner>\n')
        found = self.run_check()
        self.assertEqual(sorted((f.rule, f.path) for f in found), [('home-path', 'tools/x.sh'), ('volume-path', 'tools/x.sh')])

    def test_local_hostname_in_a_login_or_url_is_found(self):
        self.tree.write('lab/run.py', 'target = "user@' + 'mybox' + '.local"\nu = "http://' + 'mybox' + '.local:8070"\nimport threading\nt = threading.local()\n')
        found = self.run_check()
        self.assertEqual([(f.rule, f.line) for f in found], [('local-hostname', 1), ('local-hostname', 2)])

    def test_private_network_address_is_found_and_the_setup_page_is_allowed(self):
        self.tree.write('a.md', 'open http://192.168.4.1/ on the phone\n')
        self.tree.write('b.md', 'the Mac is at 192.168.' + '0.77\n')
        self.assertEqual([(f.rule, f.path) for f in self.run_check()], [('private-ip', 'b.md')])

    def test_mail_address_is_found_and_the_git_remote_form_is_not(self):
        self.tree.write('a.md', 'clone git@github.com:someone/repo.git\n')
        self.tree.write('c.patch', '\n'.join(['+@contextlib.contextmanager', '-@functools.wraps', '']))   # decorators on diff lines
        self.tree.write('b.md', 'write to some.one@' + 'mailhost.example.org\n')
        self.assertEqual([(f.rule, f.path) for f in self.run_check()], [('mail-address', 'b.md')])

    def test_key_and_local_config_files_are_refused_by_name(self):
        self.tree.write('keys/signing.pem', 'x')
        self.tree.write('lab/local.conf', 'A=1\n')
        self.tree.write('lab/local.conf.example', 'A=\n')
        self.assertEqual(sorted(f.path for f in self.run_check() if f.rule == 'forbidden-file'), ['keys/signing.pem', 'lab/local.conf'])

    def test_missing_license_is_a_finding(self):
        (self.tree.root / 'firmware/art/LICENSE').unlink()
        self.assertEqual([(f.rule, f.path) for f in self.run_check()], [('required-file', 'firmware/art/LICENSE')])

    def test_allow_file_silences_one_rule_for_one_path_and_needs_a_reason(self):
        self.tree.write('tests/t.py', 'URL = "http://10.' + '0.0.5:8070"\n')
        self.assertEqual(self.rules(self.run_check()), ['private-ip'])
        self.tree.write('tools/public_check.allow', 'private-ip | tests/*.py | 10.' + '0.0.5 | synthetic server address in a test\n')
        self.assertEqual(self.run_check(), [])
        self.tree.write('tools/public_check.allow', 'private-ip | tests/*.py | 10.' + '0.0.5 |\n')
        with self.assertRaises(ValueError):
            self.run_check()

    def write_map(self, entries):
        path = Path(self.tree.tmp.name + '-map.json')
        path.write_text(json.dumps({'version': 1, 'entries': entries}))
        self.addCleanup(lambda: path.exists() and path.unlink())
        return path

    def test_private_map_finds_every_form_of_an_address_and_never_prints_it(self):
        secret = mac(0x02, 0xAB, 0xCD, 0xEF, 0x10, 0x20)   # locally administered: only the map can find it
        bare = secret.replace(SEP, '').lower()
        raw = bytes.fromhex(bare)
        self.tree.write('a.log', f'sel={secret}\n')
        self.tree.write('b.log', f'frame 80000000{bare}0000\n')
        self.tree.write('c.bin', b'\x00\x01' + raw + b'\xff')
        self.tree.write('d.bin', b'\x00\x01' + raw[::-1] + b'\xff')
        self.tree.write(f'shots/stick-{bare.upper()}.jpg', b'\xff\xd8')
        found = self.run_check(self.write_map([{'real': secret, 'placeholder': 'LAB-STICK-1', 'kind': 'mac'}]))
        self.assertEqual(sorted(f.path for f in found), ['a.log', 'b.log', 'c.bin', 'd.bin', f'shots/stick-{bare.upper()}.jpg'])
        self.assertTrue(all(f.rule == 'private-map' for f in found))
        text = '\n'.join(self.pc.render(f) for f in found)
        self.assertIn('LAB-STICK-1', text)
        for form in (secret, secret.lower(), bare, bare.upper()):
            self.assertNotIn(form, text.replace(f'shots/stick-{bare.upper()}.jpg', ''))

    def test_private_map_finds_text_in_plain_hex_and_url_forms(self):
        name = 'My' + '&' + 'Net'
        self.tree.write('a.md', 'network ' + name.upper() + '\n')
        self.tree.write('b.log', 'ssid=' + name.encode().hex() + '\n')
        self.tree.write('c.log', 'q=My%26Net\n')
        found = self.run_check(self.write_map([{'real': name, 'placeholder': 'OWNER-NETWORK', 'kind': 'text'}]))
        self.assertEqual(sorted(f.path for f in found), ['a.md', 'b.log', 'c.log'])

    def test_map_with_a_bad_entry_is_refused(self):
        for bad in ({'real': '', 'placeholder': 'X', 'kind': 'text'}, {'real': 'zz', 'placeholder': 'X', 'kind': 'mac'},
                    {'real': 'abc', 'placeholder': '', 'kind': 'text'}, {'real': 'abc', 'placeholder': 'X', 'kind': 'other'}):
            with self.assertRaises(ValueError):
                self.run_check(self.write_map([bad]))

    def test_main_exit_codes_and_summary(self):
        self.assertEqual(self.pc.main(['--root', str(self.tree.root), '--map', os.devnull + '-absent']), 0)
        self.tree.write('a.md', REAL_MAC + '\n')
        self.assertEqual(self.pc.main(['--root', str(self.tree.root), '--map', os.devnull + '-absent']), 1)


if __name__ == '__main__':
    unittest.main()

"""tools/redact.py: the private map applied to text files, never by hand. Synthetic values only."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import redact  # noqa: E402

DEV = {'real': '0a1b2c3d4e5f', 'placeholder': 'LAB-DEV-1', 'kind': 'mac', 'synthetic': '020000000b01'}
NET = {'real': 'Some Net&Co', 'placeholder': 'LAB-NET', 'kind': 'text'}
HOST = {'real': 'labhost.lan-x', 'placeholder': 'LAB-HOST', 'kind': 'text'}
HOST_SHORT = {'real': 'labhost', 'placeholder': 'LAB-HOST-2', 'kind': 'text'}
ENTRIES = [DEV, NET, HOST_SHORT, HOST]


class Text(unittest.TestCase):
    def test_placeholder_mode_names_every_address_form(self):
        text = 'bssid 0A:1B:2C:3D:4E:5F, dash 0a-1b-2c-3d-4e-5f, bare 0a1b2c3d4e5f.'
        out, counts = redact.redact_text(text, ENTRIES, synthetic=False)
        self.assertEqual(out, 'bssid LAB-DEV-1, dash LAB-DEV-1, bare LAB-DEV-1.')
        self.assertEqual(counts, {'LAB-DEV-1': 3})

    def test_synthetic_mode_keeps_the_format_so_code_still_parses_it(self):
        text = "MAC='0A:1B:2C:3D:4E:5F'; m='0a-1b-2c-3d-4e-5f'; raw=bytes.fromhex('0a1b2c3d4e5f')"
        out, _ = redact.redact_text(text, ENTRIES, synthetic=True)
        self.assertEqual(out, "MAC='02:00:00:00:0B:01'; m='02-00-00-00-0b-01'; raw=bytes.fromhex('020000000b01')")

    def test_an_address_inside_a_hex_string_gets_a_same_length_synthetic_address(self):
        frame = 'c0003a01ffffffffffff' + '0a1b2c3d4e5f' + '0a1b2c3d4e5f' + '1000'
        out, _ = redact.redact_text(f'frame_hex={frame}\n', ENTRIES, synthetic=False)
        self.assertEqual(out, 'frame_hex=c0003a01ffffffffffff020000000b01020000000b011000\n')
        self.assertEqual(len(out), len(f'frame_hex={frame}\n'))

    def test_text_entries_cover_case_hex_and_url_encoded_forms_longest_first(self):
        text = 'ssh u@labhost.lan-x; host labhost; name Some Net&Co / some net&co; hex ' + 'Some Net&Co'.encode().hex() + '; url Some%20Net%26Co'
        out, counts = redact.redact_text(text, ENTRIES, synthetic=False)
        self.assertEqual(out, 'ssh u@LAB-HOST; host LAB-HOST-2; name LAB-NET / LAB-NET; hex ' + 'LAB-NET'.encode().hex() + '; url LAB-NET')
        self.assertEqual(counts, {'LAB-HOST': 1, 'LAB-HOST-2': 1, 'LAB-NET': 4})

    def test_path_rules_rewrite_the_repository_and_the_store(self):
        rules = redact.path_rules(repo='/srv/owner/guardian', store='/mnt/share/guardian', mount='/mnt/share')
        text = 'see /srv/owner/guardian/docs/x.md and /srv/owner/guardian; logs /mnt/share/guardian/builds/1; share /mnt/share.'
        out, counts = redact.redact_text(text, [], synthetic=False, rules=rules)
        self.assertEqual(out, 'see docs/x.md and .; logs $GUARDIAN_STORE/builds/1; share $GUARDIAN_STORE_MOUNT.')
        self.assertEqual(sum(counts.values()), 4)

    def test_untouched_text_is_returned_identical(self):
        text = 'nothing private here: 02:00:00:00:00:01, ff:ff:ff:ff:ff:ff\n'
        self.assertEqual(redact.redact_text(text, ENTRIES, synthetic=False), (text, {}))


class Map(unittest.TestCase):
    def test_a_mac_entry_needs_a_locally_administered_synthetic_of_twelve_hex(self):
        for bad in ('001b2c3d4e5f', '030000000001', '02000000', 'zz0000000001', None):   # universal, group, short, not hex, absent
            entry = dict(DEV, synthetic=bad)
            with self.assertRaises(ValueError):
                redact.check_entries([entry])
        redact.check_entries(ENTRIES)

    def test_the_map_must_live_outside_the_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'map.json'
            path.write_text(json.dumps({'version': 1, 'entries': ENTRIES}))
            self.assertEqual(len(redact.load_map(path, root=ROOT)), 4)
            with self.assertRaises(ValueError):
                redact.load_map(path, root=Path(tmp))


class Cli(unittest.TestCase):
    def test_files_are_rewritten_counts_name_placeholders_and_binaries_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as tree:
            mp = Path(tmp) / 'map.json'
            mp.write_text(json.dumps({'version': 1, 'entries': ENTRIES}))
            doc, code, blob = Path(tree) / 'notes.md', Path(tree) / 'tool.py', Path(tree) / 'image.bin'
            doc.write_text('router 0A:1B:2C:3D:4E:5F\n')
            code.write_text("MAC='0A:1B:2C:3D:4E:5F'\n")
            blob.write_bytes(b'\0\0' + bytes.fromhex('0a1b2c3d4e5f'))
            env = {k: v for k, v in os.environ.items() if not k.startswith('GUARDIAN_')}
            env['GUARDIAN_LOCAL_CONF'] = str(Path(tmp) / 'absent.conf')
            run = subprocess.run([sys.executable, '-I', str(ROOT / 'tools/redact.py'), '--map', str(mp), '--root', tree,
                                  str(doc), str(code), str(blob)], capture_output=True, text=True, env=env)
            self.assertEqual(run.returncode, 1, run.stderr)          # 1: a binary still holds a value
            self.assertEqual(doc.read_text(), 'router LAB-DEV-1\n')
            self.assertEqual(code.read_text(), "MAC='02:00:00:00:0B:01'\n")
            self.assertIn('image.bin', run.stdout + run.stderr)
            self.assertNotIn('0a1b2c3d4e5f', (run.stdout + run.stderr).lower().replace(':', ''))


if __name__ == '__main__':
    unittest.main()

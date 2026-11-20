"""G16B Mac-side OTA tools: archive verification, manifest, one-update server, provisioning lines."""
import hashlib, importlib.util, json, os, tempfile, threading, unittest, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def app_image(version, tail=b''):
    head = bytes([0xE9]) + bytes(31)
    desc = (0xABCD5432).to_bytes(4, 'little') + bytes(12) + version.encode().ljust(32, b'\0')
    return head + desc + bytes(4000) + tail


class ServeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ['GUARDIAN_STORE'] = self.tmp.name
        self.serve = load('ota_serve')
        self.archive = Path(self.tmp.name) / 'builds' / '20261116-200000-1-sticks3'
        self.archive.mkdir(parents=True)
        self.version = 'g16b-20261116-200000'
        unsigned = app_image(self.version); signed = app_image(self.version, b'SIG')
        (self.archive / 'guardian_sticks3.bin').write_bytes(unsigned)
        (self.archive / 'guardian_sticks3-signed.bin').write_bytes(signed)
        (self.archive / 'signing.json').write_text(json.dumps({'scheme': 'rsa3072-sbv2', 'signed_sha256': hashlib.sha256(signed).hexdigest(), 'app_version': self.version}))
        (self.archive / 'COMPLETE.json').write_text(json.dumps({'complete': True, 'signed_app': 'guardian_sticks3-signed.bin', 'app_version': self.version, 'selftest_fail_test_image': False}))
        self.rehash()

    def rehash(self):
        names = ['guardian_sticks3.bin', 'guardian_sticks3-signed.bin', 'signing.json']
        (self.archive / 'SHA256SUMS').write_text(''.join(hashlib.sha256((self.archive / n).read_bytes()).hexdigest() + '  ' + n + '\n' for n in names))

    def tearDown(self):
        os.environ.pop('GUARDIAN_STORE', None); self.tmp.cleanup()

    def test_manifest_names_the_signed_image_exactly(self):
        version, image, _ = self.serve.load_archive(self.archive)
        self.assertEqual(version, self.version)
        text = self.serve.manifest(version, image).decode()
        self.assertEqual(text, f'GUARDIAN-OTA 1\nversion={self.version}\nsize={len(image)}\nsha256={hashlib.sha256(image).hexdigest()}\nsignature=rsa3072-sbv2\nend\n')

    def test_ble_spike_image_is_reported_to_the_owner(self):   # G16H
        self.assertFalse(self.serve.load_archive(self.archive)[2]['ble_spike_image'])
        complete = json.loads((self.archive / 'COMPLETE.json').read_text()); complete['ble_spike_image'] = True
        (self.archive / 'COMPLETE.json').write_text(json.dumps(complete))
        self.assertTrue(self.serve.load_archive(self.archive)[2]['ble_spike_image'])

    def test_art_bench_image_is_reported_to_the_owner(self):   # G16Q
        self.assertFalse(self.serve.load_archive(self.archive)[2]['art_bench_image'])
        complete = json.loads((self.archive / 'COMPLETE.json').read_text()); complete['art_bench_image'] = True
        (self.archive / 'COMPLETE.json').write_text(json.dumps(complete))
        self.assertTrue(self.serve.load_archive(self.archive)[2]['art_bench_image'])

    def test_tampered_or_incomplete_archives_are_refused(self):
        (self.archive / 'guardian_sticks3-signed.bin').write_bytes(app_image(self.version, b'EVIL'))
        with self.assertRaises(ValueError): self.serve.load_archive(self.archive)     # SHA256SUMS mismatch
        self.rehash()
        with self.assertRaises(ValueError): self.serve.load_archive(self.archive)     # signing record mismatch
        other = Path(self.tmp.name) / 'elsewhere'; other.mkdir()
        with self.assertRaises(ValueError): self.serve.load_archive(other)            # not under $GUARDIAN_STORE/builds/
        (self.archive / 'COMPLETE.json').write_text(json.dumps({'complete': False}))
        with self.assertRaises(ValueError): self.serve.load_archive(self.archive)

    def test_version_mismatch_is_refused(self):
        signed = app_image('g16b-other', b'SIG')
        (self.archive / 'guardian_sticks3-signed.bin').write_bytes(signed)
        (self.archive / 'signing.json').write_text(json.dumps({'scheme': 'rsa3072-sbv2', 'signed_sha256': hashlib.sha256(signed).hexdigest(), 'app_version': self.version}))
        self.rehash()
        with self.assertRaises(ValueError): self.serve.load_archive(self.archive)

    def test_serves_manifest_and_image_once_then_stops(self):
        version, image, _ = self.serve.load_archive(self.archive)
        logs = []
        server = self.serve.OneUpdateServer(('127.0.0.1', 0), self.serve.manifest(version, image), image, log=logs.append)
        port = server.server_address[1]
        result = {}
        t = threading.Thread(target=lambda: result.setdefault('done', self.serve.serve(server, 10))); t.start()
        base = f'http://127.0.0.1:{port}'
        self.assertIn(b'GUARDIAN-OTA 1', urllib.request.urlopen(base + '/manifest', timeout=5).read())
        with self.assertRaises(urllib.error.HTTPError): urllib.request.urlopen(base + '/etc/passwd', timeout=5)
        got = urllib.request.urlopen(base + '/image', timeout=5)
        self.assertEqual(got.headers['Content-Length'], str(len(image)))
        self.assertEqual(got.read(), image)
        t.join(15)
        self.assertTrue(result.get('done'))
        with self.assertRaises(OSError): urllib.request.urlopen(base + '/manifest', timeout=2)   # stopped after one update

    def test_timeout_without_a_transfer_reports_failure(self):
        server = self.serve.OneUpdateServer(('127.0.0.1', 0), b'm', b'i', log=lambda *_: None)
        self.assertFalse(self.serve.serve(server, 0.2))


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.prov = load('ota_provision')

    def test_lines_are_hex_encoded_and_validated(self):
        lines = self.prov.commands('MyLab 5G', 'hunter2hunter2', 'http://192.168.1.20:8070')
        self.assertEqual(lines[0], 'OTA SSID ' + 'MyLab 5G'.encode().hex())
        self.assertEqual(lines[1], 'OTA PASS ' + 'hunter2hunter2'.encode().hex())
        self.assertEqual(lines[2:], ['OTA URL http://192.168.1.20:8070', 'OTA SAVE', 'OTA?'])
        self.assertTrue(all(len(l) < 160 for l in self.prov.commands('x' * 32, 'p' * 63, 'http://' + 'h' * 113)))   # device line limit
        self.assertEqual(self.prov.commands('open', '', 'http://10.0.0.2')[1], 'OTA PASS -')
        for bad in [('', 'hunter2hunter2', 'http://a'), ('x' * 33, '', 'http://a'), ('s', 'short', 'http://a'),
                    ('s', 'hunter2hunter2', 'https://a'), ('s', 'hunter2hunter2', 'http://a b')]:
            with self.assertRaises(ValueError): self.prov.commands(*bad)


if __name__ == '__main__':
    unittest.main()

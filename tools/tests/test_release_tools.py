"""G26 release tooling, offline: tools/release_support.py (reproducibility check, package, manifest), and the
owner-run scripts tools/release_keygen.sh and tools/release_publish.sh with a THROWAWAY key made in a temp
directory, a fake gh that logs every call, a fake espsecure for the OTA-key check and a local HTTP server
standing in for GitHub (the API's releases/latest and releases/download/<tag>/). The real keys, the real
repository and the network are never touched."""
import hashlib, http.server, importlib.util, json, os, shutil, subprocess, tempfile, threading, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parent
spec = importlib.util.spec_from_file_location('release_support', HERE / 'release_support.py')
rs = importlib.util.module_from_spec(spec); spec.loader.exec_module(rs)
COMMIT = 'a' * 40


def app_image(version, tail=b''):
    head = bytes([0xE9]) + bytes(31)
    desc = (0xABCD5432).to_bytes(4, 'little') + bytes(12) + version.encode().ljust(32, b'\0')
    return head + desc + bytes(4000) + tail


def fake_archive(path, version='guardian-20261123-180000-rel', app_tail=b'APP', release=True, country='01', sig=b'SIGBLOCK-1'):
    path = Path(path); path.mkdir(parents=True)
    files = {'bootloader/bootloader.bin': b'BOOT' * 100, 'partition_table/partition-table.bin': b'PART' * 50,
             'ota_data_initial.bin': b'\xff' * 64, 'guardian_sticks3.elf': b'ELF-never-shipped',
             'guardian_sticks3.map': b'MAP-never-shipped', 'source.tar.gz': b'SRC-never-shipped',
             'sdk-inputs/libnet80211.a': b'SDK-never-shipped', 'toolchain.txt': b'ESP-IDF 67c1de1\nPython 3.10\n'}
    for name, data in files.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True); (path / name).write_bytes(data)
    unsigned = app_image(version, app_tail); signed = unsigned + sig
    (path / 'guardian_sticks3.bin').write_bytes(unsigned); (path / rs.APP).write_bytes(signed)
    (path / 'signing.json').write_text(json.dumps({'scheme': 'rsa3072-sbv2', 'unsigned_sha256': hashlib.sha256(unsigned).hexdigest(),
                                                   'signed_sha256': hashlib.sha256(signed).hexdigest(), 'app_version': version}))
    (path / 'COMPLETE.json').write_text(json.dumps({'complete': True, 'app_version': version, 'release_image': release,
                                                    'radio_country': country, 'radio_80211d': release, 'selftest_fail_test_image': False,
                                                    'ble_spike_image': False, 'art_bench_image': False, 'dark_cpu_image': False}))
    return path


def package(tmp, version='1.0.0', build=1, tree='clean', name='a', **kw):
    a = fake_archive(Path(tmp) / f'{name}-1', **kw); b = fake_archive(Path(tmp) / f'{name}-2', **{**kw, 'sig': b'SIGBLOCK-2'})
    sums = rs.compare_builds(a, b)
    return rs.make_package(a, Path(tmp) / 'releases', version, build, COMMIT, tree, sums, 'ESP-IDF 67c1de1\n')


class SupportTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(); self.tmp = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def test_release_number_file_is_strict_and_the_repository_one_reads(self):
        version, build = rs.read_release_number()
        self.assertRegex(version, r'^\d+\.\d+\.\d+$'); self.assertGreaterEqual(build, 1)
        for text in ('version=1.0\nbuild=1\n', 'version=1.0.0\nbuild=0\n', 'version=1.0.0\n', 'version=1.0.0\nbuild=1\nextra=2\n', 'version 1.0.0\nbuild=1\n'):
            p = self.tmp / 'v.txt'; p.write_text(text)
            with self.assertRaises(ValueError, msg=text): rs.read_release_number(p)
        p = self.tmp / 'v.txt'; p.write_text('# comment\nversion = 2.3.4  # trailing\nbuild=17\n')
        self.assertEqual(rs.read_release_number(p), ('2.3.4', 17))

    def test_commit_stamp_is_the_commit_time_on_the_local_clock_and_fits_the_ota_order(self):
        import datetime
        self.assertEqual(rs.commit_stamp(0, datetime.timezone.utc), 'guardian-19700101-000000')
        self.assertEqual(rs.commit_stamp(0, datetime.timezone(datetime.timedelta(hours=-3))), 'guardian-19691231-210000')
        self.assertEqual(rs.commit_stamp(1795464927), 'guardian-' + datetime.datetime.fromtimestamp(1795464927).strftime('%Y%m%d-%H%M%S'))
        stamp = rs.commit_stamp(1795464927)
        self.assertRegex(stamp, r'^guardian-\d{8}-\d{6}$'); self.assertLessEqual(len(stamp + '-rel'), 31)

    def test_two_builds_must_agree_on_the_unsigned_parts(self):
        a = fake_archive(self.tmp / 'a'); b = fake_archive(self.tmp / 'b', sig=b'OTHER-SALT')
        sums = rs.compare_builds(a, b)   # the signature blocks differ (RSA-PSS salt): allowed
        self.assertEqual(set(sums), set(rs.REPRODUCED))
        c = fake_archive(self.tmp / 'c', app_tail=b'APX')
        with self.assertRaisesRegex(ValueError, 'not reproducible: guardian_sticks3.bin'): rs.compare_builds(a, c)
        d = fake_archive(self.tmp / 'd'); (d / 'bootloader/bootloader.bin').write_bytes(b'BOOT' * 99 + b'BOOX')
        with self.assertRaisesRegex(ValueError, 'bootloader'): rs.compare_builds(a, d)
        e = fake_archive(self.tmp / 'e', version='guardian-20261123-180001-rel')
        with self.assertRaisesRegex(ValueError, 'different versions'): rs.compare_builds(a, e)

    def test_only_a_world_safe_release_archive_is_packaged(self):
        lab = fake_archive(self.tmp / 'lab', release=False, country='BR')
        with self.assertRaisesRegex(ValueError, 'not a release image'): rs.check_release_archive(lab)
        br = fake_archive(self.tmp / 'br', country='BR')
        with self.assertRaisesRegex(ValueError, 'world safe'): rs.check_release_archive(br)
        bad = fake_archive(self.tmp / 'bad'); (bad / rs.APP).write_bytes(b'not the unsigned app' + b'SIG')
        with self.assertRaisesRegex(ValueError, 'signature block'): rs.check_release_archive(bad)
        spike = fake_archive(self.tmp / 'spike'); done = json.loads((spike / 'COMPLETE.json').read_text()); done['ble_spike_image'] = True
        (spike / 'COMPLETE.json').write_text(json.dumps(done))
        with self.assertRaisesRegex(ValueError, 'ble_spike_image'): rs.check_release_archive(spike)

    def test_package_holds_only_the_four_flash_files_and_names_the_shipped_app(self):
        pkg = package(self.tmp)
        self.assertEqual({p.name for p in pkg.iterdir()}, rs.PACKAGE_FILES)   # never the ELF, map, sources or SDK inputs
        facts = rs.check_package(pkg)
        app_sha = hashlib.sha256((pkg / rs.APP).read_bytes()).hexdigest()
        self.assertEqual(facts['tag'], f'guardian-1.0.0-b1-{app_sha[:12]}'); self.assertEqual(pkg.name, facts['tag'])
        self.assertEqual([(p['file'], p['offset']) for p in facts['parts']],
                         [('bootloader.bin', 0), ('partition-table.bin', 0x8000), ('ota_data_initial.bin', 0x10000), (rs.APP, 0x20000)])
        self.assertEqual((pkg / rs.APP).read_bytes(), (self.tmp / 'a-1' / rs.APP).read_bytes())   # build 1's signed app
        info = (pkg / 'BUILD_INFO.txt').read_text()
        for want in ('tree: clean', f'git commit: {COMMIT}', 'radio country: 01 (802.11d adoption: on)', 'reproducible: two clean builds', 'app_version: guardian-20261123-180000-rel'):
            self.assertIn(want, info)
        self.assertNotIn(str(self.tmp), info)   # no local paths in what travels with the package
        with self.assertRaisesRegex(ValueError, 'already exists'): rs.make_package(self.tmp / 'a-1', self.tmp / 'releases', '1.0.0', 1, COMMIT, 'clean', rs.compare_builds(self.tmp / 'a-1', self.tmp / 'a-2'))

    def test_a_changed_or_extra_file_fails_the_package_check(self):
        pkg = package(self.tmp)
        (pkg / 'guardian_sticks3.elf').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'never published'): rs.check_package(pkg)
        (pkg / 'guardian_sticks3.elf').unlink()
        data = bytearray((pkg / 'partition-table.bin').read_bytes()); data[0] ^= 1; (pkg / 'partition-table.bin').write_bytes(bytes(data))
        with self.assertRaisesRegex(ValueError, 'partition-table.bin does not match'): rs.check_package(pkg)
        other = package(self.tmp, name='b', app_tail=b'APQ')
        renamed = other.parent / 'guardian-1.0.0-b1-000000000000'; other.rename(renamed)
        with self.assertRaisesRegex(ValueError, 'package name'): rs.check_package(renamed)

    def test_manifest_has_the_website_shape_and_its_rules_refuse_everything_else(self):
        pkg = package(self.tmp)
        facts = rs.check_package(pkg)
        data = rs.manifest_bytes(facts, '2026-11-23', 'First public release.')
        m = json.loads(data)
        self.assertEqual(list(m), ['tag', 'version', 'build', 'date', 'notes', 'parts'])
        self.assertEqual(m['parts'][3], {'file': rs.APP, 'offset': 0x20000, 'sha256': hashlib.sha256((pkg / rs.APP).read_bytes()).hexdigest(), 'size': (pkg / rs.APP).stat().st_size})
        self.assertEqual(rs.parse_manifest(data)['tag'], facts['tag'])
        def broken(change):
            x = json.loads(data); change(x); return json.dumps(x).encode()
        for name, change in [('extra key', lambda x: x.update(url='https://example.com')),
                             ('moved part', lambda x: x['parts'][1].update(offset=0x9000)),
                             ('swapped parts', lambda x: x['parts'].reverse()),
                             ('fifth part', lambda x: x['parts'].append(dict(x['parts'][0]))),
                             ('build mismatch', lambda x: x.update(build=2)),
                             ('version mismatch', lambda x: x.update(version='1.0.1')),
                             ('app not named by the tag', lambda x: x['parts'][3].update(sha256='f' * 64)),
                             ('bad size', lambda x: x['parts'][0].update(size=0))]:
            with self.subTest(name), self.assertRaises(ValueError): rs.parse_manifest(broken(change))
        with self.assertRaises(ValueError): rs.manifest_bytes(facts, '23/11/2026', 'x')
        with self.assertRaises(ValueError): rs.manifest_bytes(facts, '2026-11-23', '   ')


class FakeGitHub:
    """GET /api/latest -> {"tag_name": <latest>} or 404; GET /download/<tag>/<file> from <root>/<tag>/<file>."""
    def __init__(self, root):
        self.root = Path(root); self.latest = None
        outer = self
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_GET(self):
                if self.path == '/api/latest':
                    if not outer.latest: return self.send_error(404)
                    body = json.dumps({'tag_name': outer.latest}).encode()
                elif self.path.startswith('/download/'):
                    f = outer.root / self.path[len('/download/'):]
                    if '..' in self.path or not f.is_file(): return self.send_error(404)
                    body = f.read_bytes()
                else: return self.send_error(404)
                self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f'http://127.0.0.1:{self.server.server_port}'

    def close(self):
        self.server.shutdown(); self.server.server_close()


class ScriptTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(); self.tmp = Path(self._t.name)
        self.keydir = self.tmp / 'home' / '.config' / 'm5-guardian'; self.public = self.tmp / 'release-public-key.json'
        self.github = FakeGitHub(self.tmp / 'served'); (self.tmp / 'served').mkdir()
        self.bin = self.tmp / 'bin'; self.bin.mkdir()
        (self.bin / 'gh').write_text('''#!/usr/bin/env bash
line=""; for a in "$@"; do line+="${line:+ }${a//$'\\n'/\\\\n}"; done
printf '%s\\n' "$line" >> "$GH_LOG"
case "${1:-} ${2:-}" in
  "api user") echo "${FAKE_GH_ACTIVE:-home-account}"; exit 0 ;;
  "auth switch") [[ "${FAKE_GH_SWITCH_FAIL:-}" == "${4:-}" ]] && exit 1; exit 0 ;;
  "release create")
    [[ -z "${FAKE_GH_CREATE_FAIL:-}" ]] || exit 1
    mkdir -p "$SERVED/$3"; for a in "$@"; do [[ -f "$a" ]] && cp "$a" "$SERVED/$3/"; done
    printf '%s' "$3" > "$SERVED/.latest"; exit 0 ;;
esac
exit 3
''')
        (self.bin / 'espsecure-python').write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$ESPSECURE_LOG"\n[[ -z "${FAKE_OTA_BAD:-}" ]] || { echo "Signature is not valid"; exit 1; }\necho "Signature is valid"\n')
        for f in ('gh', 'espsecure-python'): os.chmod(self.bin / f, 0o755)
        self.ota_key = self.tmp / 'ota-key.pem'; self.ota_key.write_text('throwaway OTA key stand-in')
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'GH_LOG': str(self.tmp / 'gh.log'),
                    'ESPSECURE_LOG': str(self.tmp / 'espsecure.log'), 'SERVED': str(self.tmp / 'served'),
                    'GUARDIAN_RELEASE_KEY_DIR': str(self.keydir), 'GUARDIAN_RELEASE_PUBLIC_KEY': str(self.public),
                    'GUARDIAN_RELEASE_API_URL': self.github.url + '/api/latest', 'GUARDIAN_RELEASE_DOWNLOAD_URL': self.github.url + '/download',
                    'GUARDIAN_RELEASE_ROUNDTRIP_TRIES': '3', 'GUARDIAN_RELEASE_ROUNDTRIP_WAIT': '0',
                    'GUARDIAN_IDF_PYTHON': str(self.bin / 'espsecure-python'), 'GUARDIAN_OTA_SIGNING_KEY': str(self.ota_key), 'TMPDIR': str(self.tmp)}

    def tearDown(self):
        self.github.close(); self._t.cleanup()

    def run_script(self, name, *args, **env):
        return subprocess.run(['bash', str(HERE / name), *args], env={**self.env, **env}, text=True, capture_output=True, timeout=120)

    def keygen(self):
        r = self.run_script('release_keygen.sh'); self.assertEqual(r.returncode, 0, r.stdout + r.stderr); return r

    def gh_calls(self):
        p = self.tmp / 'gh.log'; return p.read_text().splitlines() if p.exists() else []

    def sync_latest(self):   # the fake gh records the created tag; the fake API serves it
        p = self.tmp / 'served' / '.latest'
        if p.exists(): self.github.latest = p.read_text()

    def test_keygen_makes_a_600_key_outside_the_tree_writes_only_the_public_half_and_never_overwrites(self):
        r = self.keygen()
        key = self.keydir / 'release-signing-p256.pem'
        self.assertEqual(oct(key.stat().st_mode & 0o777), '0o600'); self.assertEqual(oct(self.keydir.stat().st_mode & 0o777), '0o700')
        pub = json.loads(self.public.read_text())
        self.assertIn('BEGIN PUBLIC KEY', pub['spki_pem']); self.assertNotIn('PRIVATE', self.public.read_text())
        self.assertRegex(pub['spki_der_sha256'], r'^[0-9a-f]{64}$'); self.assertNotIn('PRIVATE', r.stdout)
        before = key.read_bytes()
        again = self.run_script('release_keygen.sh')
        self.assertNotEqual(again.returncode, 0); self.assertIn('never overwritten', again.stdout); self.assertEqual(key.read_bytes(), before)

    def test_committed_public_key_file_is_not_key_material_by_name(self):
        self.assertFalse(str(rs.ROOT / 'release' / 'release-public-key.json').endswith(('.pem', '.key')))   # tools/public_check.py FORBIDDEN names

    def test_dry_run_writes_a_signed_manifest_and_never_calls_gh(self):
        self.keygen(); pkg = package(self.tmp)
        r = self.run_script('release_publish.sh', str(pkg), '--notes', 'First public release.')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('OK latest: none published yet', r.stdout); self.assertIn('OK dry run: nothing uploaded', r.stdout)
        self.assertEqual(self.gh_calls(), [])
        pub = json.loads(self.public.read_text()); (self.tmp / 'pub.pem').write_text(pub['spki_pem'])
        ok = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(self.tmp / 'pub.pem'), '-signature', str(pkg / 'manifest.sig'), str(pkg / 'manifest.json')], capture_output=True)
        self.assertEqual(ok.returncode, 0)
        self.assertEqual(rs.parse_manifest((pkg / 'manifest.json').read_bytes())['tag'], pkg.name)
        self.assertIn(f'--keyfile {self.ota_key}', (self.tmp / 'espsecure.log').read_text())   # the OTA-key check ran on the app
        self.assertIn(f'--target {COMMIT}', r.stdout)

    def test_refusals_before_anything_is_signed_or_uploaded(self):
        self.keygen()
        dirty = package(self.tmp, tree='dirty', name='d', app_tail=b'APD')
        r = self.run_script('release_publish.sh', str(dirty), '--notes', 'x')
        self.assertNotEqual(r.returncode, 0); self.assertIn('dirty tree', r.stdout)
        pkg = package(self.tmp)
        r = self.run_script('release_publish.sh', str(pkg), '--notes', 'x', FAKE_OTA_BAD='1')
        self.assertNotEqual(r.returncode, 0); self.assertIn("does not verify with the owner's OTA key", r.stdout)
        os.chmod(self.keydir / 'release-signing-p256.pem', 0o644)
        r = self.run_script('release_publish.sh', str(pkg), '--notes', 'x')
        self.assertNotEqual(r.returncode, 0); self.assertIn('expected 600', r.stdout)
        os.chmod(self.keydir / 'release-signing-p256.pem', 0o600)
        other = self.tmp / 'other.json'; shutil.copy(self.public, other)
        (self.keydir / 'release-signing-p256.pem').unlink(); self.keygen()           # a NEW key: no longer the committed public key
        r = self.run_script('release_publish.sh', str(pkg), '--notes', 'x', GUARDIAN_RELEASE_PUBLIC_KEY=str(other))
        self.assertNotEqual(r.returncode, 0); self.assertIn('is not the pair of the committed public key', r.stdout)
        self.assertFalse((pkg / 'manifest.sig').exists())
        self.assertEqual(self.gh_calls(), [])

    def test_publish_creates_the_release_with_six_assets_switches_back_and_round_trips(self):
        self.keygen(); pkg = package(self.tmp)
        # The fake API turns to the new tag once gh has created it (polled by the round trip).
        stop = threading.Event()
        def follow():
            while not stop.is_set(): self.sync_latest(); stop.wait(0.05)
        t = threading.Thread(target=follow, daemon=True); t.start()
        try:
            r = self.run_script('release_publish.sh', str(pkg), '--notes', 'First public release.', '--publish')
        finally:
            stop.set(); t.join()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        calls = self.gh_calls()
        self.assertEqual(calls[:2], ['api user --jq .login', 'auth switch --user fcavalcantirj']); self.assertEqual(calls[-1], 'auth switch --user home-account')
        create = calls[2]
        self.assertTrue(create.startswith(f'release create {pkg.name} --repo fcavalcantirj/m5-guardian --target {COMMIT} '), create)
        self.assertTrue(create.endswith(' --latest bootloader.bin partition-table.bin ota_data_initial.bin guardian_sticks3-signed.bin manifest.json manifest.sig'), create)
        self.assertEqual(sorted(p.name for p in (self.tmp / 'served' / pkg.name).iterdir()),
                         sorted(['bootloader.bin', 'partition-table.bin', 'ota_data_initial.bin', rs.APP, 'manifest.json', 'manifest.sig']))
        self.assertIn('OK round trip', r.stdout); self.assertIn(f'OK published: {pkg.name}', r.stdout)
        # The next release must carry a higher build; the same build is refused against what is published.
        same = package(self.tmp, name='n', app_tail=b'APZ')
        r = self.run_script('release_publish.sh', str(same), '--notes', 'x')
        self.assertNotEqual(r.returncode, 0); self.assertIn('is not higher than the published build 1', r.stdout)
        higher = package(self.tmp, build=2, name='h', app_tail=b'APY')
        r = self.run_script('release_publish.sh', str(higher), '--notes', 'Second.')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr); self.assertIn(f'OK latest: {pkg.name} build 1, signature valid', r.stdout)

    def test_a_failed_create_still_switches_gh_back(self):
        self.keygen(); pkg = package(self.tmp)
        r = self.run_script('release_publish.sh', str(pkg), '--notes', 'x', '--publish', FAKE_GH_CREATE_FAIL='1')
        self.assertNotEqual(r.returncode, 0); self.assertIn('gh release create', r.stdout)
        self.assertEqual(self.gh_calls()[-1], 'auth switch --user home-account')   # the account that was active before

    def test_a_latest_release_not_signed_with_the_release_key_is_refused(self):
        self.keygen(); pkg = package(self.tmp)
        foreign = self.tmp / 'served' / 'guardian-0.9.0-b1-000000000000'; foreign.mkdir()
        (foreign / 'manifest.json').write_text('{}'); (foreign / 'manifest.sig').write_bytes(b'not a signature')
        self.github.latest = foreign.name
        r = self.run_script('release_publish.sh', str(pkg), '--notes', 'x')
        self.assertNotEqual(r.returncode, 0); self.assertIn('NOT signed with the release key', r.stdout)


if __name__ == '__main__':
    unittest.main()

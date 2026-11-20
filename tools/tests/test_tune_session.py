"""G16C / G22A: Mac-side TUNE tool (tools/tune_session.py), host only.

The stick is an HTTP client of this tool; these checks drive the tool's real HTTP server from a
fake stick on 127.0.0.1. Offers are signed with a THROWAWAY RSA-3072 key generated here in a
temporary directory (never the owner's key) and checked with openssl's own verify. When
GUARDIAN_OFFER_VERIFY names the host-built firmware check (<build dir>/tune_offer_verify), the
same offers are also put through the code the stick compiles.
"""
import importlib.util, os, re, stat, subprocess, tempfile, threading, unittest, urllib.error, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
OPENSSL = os.environ.get('GUARDIAN_OPENSSL', '/usr/bin/openssl')
VERIFY = os.environ.get('GUARDIAN_OFFER_VERIFY', '')
IDF_PYTHON = os.environ.get('GUARDIAN_IDF_PYTHON', str(Path.home() / '.espressif/python_env/idf5.4_py3.10_env/bin/python'))
NONCE = '000102030405060708090a0b0c0d0e0f'


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def make_key(directory, name, bits=3072, mode=0o600):
    key = Path(directory) / name
    subprocess.run([OPENSSL, 'genrsa', '-out', str(key), str(bits)], check=True, capture_output=True)
    key.chmod(mode)
    return key


class Keys(unittest.TestCase):
    """One throwaway key pair for the whole file (generation takes about a second)."""
    @classmethod
    def setUpClass(cls):
        cls.t = load('tune_session')
        cls.tmp = tempfile.TemporaryDirectory()
        cls.key = make_key(cls.tmp.name, 'throwaway-rsa3072.pem')
        cls.public = Path(cls.tmp.name) / 'public.pem'
        subprocess.run([OPENSSL, 'rsa', '-in', str(cls.key), '-pubout', '-out', str(cls.public)], check=True, capture_output=True)
        out = subprocess.run([OPENSSL, 'rsa', '-in', str(cls.key), '-noout', '-modulus'], check=True, capture_output=True).stdout.decode()
        cls.modulus = out.strip().split('=', 1)[1].lower().rjust(768, '0')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def openssl_verifies(self, offer):
        """True when the sig line is a PKCS#1 v1.5 SHA-256 signature of everything before it, by the throwaway key."""
        body, sig = offer.rsplit(b'sig=', 1)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'sig').write_bytes(bytes.fromhex(sig.strip().decode()))
            run = subprocess.run([OPENSSL, 'dgst', '-sha256', '-verify', str(self.public), '-signature', str(Path(d) / 'sig')],
                                 input=body, capture_output=True)
        return run.returncode == 0


class TuneSessionTests(Keys):
    def setUp(self):
        self.lines = []
        self.server = self.t.TuneServer(('127.0.0.1', 0), key_path=self.key, seconds=60, log=self.lines.append)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_address[1]}'

    def tearDown(self):
        self.server.shutdown(); self.server.server_close()

    def get(self, path, raw=False):
        body = urllib.request.urlopen(self.base + path, timeout=5).read()
        return body if raw else body.decode()

    def post(self, path, body):
        return urllib.request.urlopen(urllib.request.Request(self.base + path, data=body.encode(), method='POST'), timeout=5).status

    def code(self, path, post=None):
        try:
            self.post(path, post) if post is not None else self.get(path)
        except urllib.error.HTTPError as e:
            return e.code
        return 200

    def test_offer_is_a_signed_envelope_for_the_sticks_nonce(self):
        self.assertTrue(self.server.queue('TUNE detect.burst=6')); self.assertTrue(self.server.queue('STATUS'))
        offer = self.get(f'/tune/offer?nonce={NONCE}', raw=True)
        self.assertRegex(offer.decode(), r'\AGUARDIAN-TUNE 2\nnonce=' + NONCE + r'\nexpires=60\ncmd=TUNE detect\.burst=6\ncmd=STATUS\nend\nsig=[0-9a-f]{768}\n\Z')
        self.assertTrue(self.openssl_verifies(offer))
        self.assertLessEqual(len(offer), 2304)   # the device's kMaxOffer
        # One changed byte of the signed part and the signature no longer fits.
        self.assertFalse(self.openssl_verifies(offer.replace(b'detect.burst=6', b'detect.burst=9')))
        self.assertFalse(self.openssl_verifies(offer.replace(b'expires=60', b'expires=90')))
        self.assertFalse(self.openssl_verifies(offer.replace(NONCE.encode(), b'f' * 32)))

    def test_the_largest_offer_fits_the_device_limit(self):
        for _ in range(8):
            self.assertTrue(self.server.queue('TUNE ' + 'x' * 154))
        self.server.seconds = 1800
        offer = self.get(f'/tune/offer?nonce={NONCE}', raw=True)
        self.assertLessEqual(len(offer), 2304); self.assertTrue(self.openssl_verifies(offer))

    def test_no_offer_without_a_nonce_or_without_commands(self):
        self.assertEqual(self.code(f'/tune/offer?nonce={NONCE}'), 404)            # nothing queued: the stick goes on to the update check
        self.server.queue('STATUS')
        for bad in ('/tune/offer', '/tune/offer?nonce=', '/tune/offer?nonce=0123', f'/tune/offer?nonce={NONCE.upper()}',
                    f'/tune/offer?nonce={NONCE}00', '/tune/offer?nonce=' + 'g' * 32):
            self.assertEqual(self.code(bad), 400, bad)
        self.assertEqual(self.server.offers, 0)                                    # nothing was signed for them
        self.assertIn('cmd=STATUS', self.get(f'/tune/offer?nonce={NONCE}'))

    def test_a_command_leaves_once_and_every_offer_is_bound_to_its_nonce(self):
        self.server.queue('STATUS')
        first = self.get(f'/tune/offer?nonce={NONCE}', raw=True)
        self.assertEqual(self.code('/tune/offer?nonce=' + 'a' * 32), 404)          # already handed out: not signed again for another nonce
        self.server.queue('TUNE?')
        second = self.get('/tune/offer?nonce=' + 'a' * 32, raw=True)
        self.assertIn(b'nonce=' + b'a' * 32, second); self.assertNotIn(b'cmd=STATUS', second)
        self.assertNotEqual(first.rsplit(b'sig=', 1)[1], second.rsplit(b'sig=', 1)[1])
        self.assertTrue(self.openssl_verifies(second))
        self.assertTrue(any('without 1 replies' in l and 'STATUS' in l for l in self.lines))   # the unanswered one is reported

    def test_more_than_eight_commands_go_out_in_two_offers(self):
        for i in range(10):
            self.server.queue(f'TUNE a.b={i}')
        first = self.get(f'/tune/offer?nonce={NONCE}')
        self.assertEqual(first.count('cmd='), 8)
        for i in range(8):
            self.assertEqual(self.post(f'/tune/reply?s={NONCE}', f'TUNE a.b={i}\n'), 200)
        self.assertEqual(self.get('/tune/offer?nonce=' + 'b' * 32).count('cmd='), 2)
        self.assertEqual(self.server.lost, 0)

    def test_replies_and_the_end_belong_to_the_offered_session(self):
        self.assertEqual(self.code(f'/tune/reply?s={NONCE}', post='x'), 403)       # no offer yet: no session
        self.assertEqual(self.code(f'/tune/end?s={NONCE}&why=done'), 403)
        self.server.queue('TUNE?'); self.get(f'/tune/offer?nonce={NONCE}')
        self.assertEqual(self.code('/tune/reply?s=' + 'f' * 32, post='x'), 403)
        self.assertEqual(self.code('/tune/reply?s=', post='x'), 403)
        self.assertFalse(self.server.idle())
        self.assertEqual(self.post(f'/tune/reply?s={NONCE}', 'TUNE motion.damping=9\n'), 200)
        self.assertTrue(any('TUNE motion.damping=9' in l for l in self.lines))
        self.assertTrue(self.server.idle()); self.assertFalse(self.server.ended.is_set())
        self.get(f'/tune/end?s={NONCE}&why=done')
        self.assertTrue(self.server.ended.wait(2))
        self.assertTrue(any('ended: done' in l for l in self.lines))

    def test_update_and_old_session_paths_are_not_served(self):
        for path in ('/manifest', '/image', '/etc/passwd', '/tune/next', f'/tune/next?s={NONCE}'):
            self.assertEqual(self.code(path), 404, path)

    def test_only_device_accepted_commands_are_queued(self):
        for ok in ('STATUS', 'FRAMES', 'FRAMES 0', 'TUNE?', 'TUNE? t.probe', 'TUNE motion.damping=9', 'IMU POSE', 'BATTRUN'):
            self.assertTrue(self.server.queue(ok), ok)
        for bad in ('', 'TUNE', 'TUNEX', 'start 6 10', 'OTA SSID 41', 'IMU 3', 'IMU', 'IMU POSE ', 'IMU POSE 3', 'imu pose', 'BATTRUN 0', 'EDGE', 'status', 'TUNE a=1\nSTATUS', 'TUNE? ', 'TUNE?x', 'x' * 160):
            self.assertFalse(self.server.queue(bad), bad)
        with self.assertRaises(ValueError): self.t.envelope(NONCE, 60, ['OTA SSID 41'])
        with self.assertRaises(ValueError): self.t.envelope(NONCE, 60, [])
        with self.assertRaises(ValueError): self.t.envelope(NONCE, 60, ['STATUS'] * 9)
        with self.assertRaises(ValueError): self.t.envelope(NONCE, 29, ['STATUS'])
        with self.assertRaises(ValueError): self.t.envelope(NONCE, 1801, ['STATUS'])
        with self.assertRaises(ValueError): self.t.envelope(NONCE[:-1], 60, ['STATUS'])

    def test_g16h_spike_verbs_match_the_device_rule(self):
        # Supervisor 2026-11-19: the coexistence spike is armed and read over Wi-Fi (same cases as tune_session_check.cpp).
        for ok in ('BLESPIKE', 'BLESPIKE report', 'BLESPIKE phases', 'BLESPIKE stop', 'BLESPIKE start', 'BLESPIKE start 60 2',
                   'BLESPIKE start 600 4'):
            self.assertTrue(self.server.queue(ok), ok)
        for bad in ('BLESPIKE ', 'BLESPIKEX', 'blespike', 'BLESPIKE start ', 'BLESPIKE start 60', 'BLESPIKE start 60 ',
                    'BLESPIKE start 60 2 1', 'BLESPIKE start a b', 'BLESPIKE start 60  2', 'BLESPIKE start 6000 2',
                    'BLESPIKE start 60 22', 'BLESPIKE start -1 2', 'BLESPIKE report ', 'BLESPIKE phases 1', 'BLESPIKE go'):
            self.assertFalse(self.server.queue(bad), bad)

    def test_the_key_never_appears_in_offers_or_in_the_log(self):
        self.server.queue('STATUS')
        offer = self.get(f'/tune/offer?nonce={NONCE}')
        self.get(f'/tune/end?s={NONCE}&why=key')
        secret = [l for l in self.key.read_text().splitlines() if l and not l.startswith('-----')]
        self.assertGreater(len(secret), 20)
        shown = offer + '\n'.join(self.lines)
        for line in secret:
            self.assertNotIn(line, shown)
        self.assertNotIn('PRIVATE KEY', shown)

    @unittest.skipUnless(VERIFY, 'GUARDIAN_OFFER_VERIFY not set: the cross-check against the firmware verifier did not run')
    def test_the_firmware_verifier_accepts_what_this_tool_signs(self):
        def stick(offer, nonce=NONCE, now=2000):
            run = subprocess.run([VERIFY, self.modulus, '65537', nonce, '1000', str(now)], input=offer, capture_output=True)
            return run.returncode, run.stdout.decode()
        self.server.queue('TUNE detect.burst=6'); self.server.queue('STATUS')
        offer = self.get(f'/tune/offer?nonce={NONCE}', raw=True)
        code, out = stick(offer)
        self.assertEqual((code, out), (0, f'refusal=none\nsession={NONCE} expires=60 commands=2\ncmd=TUNE detect.burst=6\ncmd=STATUS\n'))
        self.assertEqual(stick(offer.replace(b'detect.burst=6', b'detect.burst=9')), (1, 'refusal=signature\n'))
        self.assertEqual(stick(offer, nonce='f' * 32), (1, 'refusal=nonce\n'))                 # a replay at a later poll
        self.assertEqual(stick(offer, now=61000), (1, 'refusal=expired\n'))
        self.assertEqual(stick(offer.rsplit(b'sig=', 1)[0]), (1, 'refusal=unsigned\n'))
        self.assertEqual(stick(b'GUARDIAN-TUNE 1\nsession=0123456789abcdef\nseconds=300\nend\n'), (1, 'refusal=unsigned\n'))
        other = make_key(self.tmp.name, 'other-rsa3072.pem')
        forged = self.t.signed_offer(other, NONCE, 60, ['TUNE detect.burst=128'])
        self.assertEqual(stick(forged), (1, 'refusal=signature\n'))


class RefusalTestModes(Keys):
    """--unsigned-test and --bad-signature-test: offers the stick must refuse, made without the owner's key."""
    def stick(self, offer, modulus=None):
        run = subprocess.run([VERIFY, modulus or self.modulus, '65537', NONCE, '1000', '2000'], input=offer, capture_output=True)
        return run.returncode, run.stdout.decode()

    def test_unsigned_mode_needs_no_key_and_sends_no_signature(self):
        server = self.t.TuneServer(('127.0.0.1', 0), key_path=Path(self.tmp.name) / 'absent.pem', seconds=60, log=lambda l: None, unsigned=True)
        try:
            server.queue('STATUS')
            offer = server.offer(NONCE)
            self.assertEqual(offer, f'GUARDIAN-TUNE 2\nnonce={NONCE}\nexpires=60\ncmd=STATUS\nend\n'.encode())
            if VERIFY: self.assertEqual(self.stick(offer), (1, 'refusal=unsigned\n'))
        finally:
            server.server_close()

    def test_bad_signature_mode_uses_a_throwaway_key(self):
        with tempfile.TemporaryDirectory() as d:
            key = self.t.throwaway_key(d)
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            self.assertNotEqual(key.read_bytes(), self.key.read_bytes())
            offer = self.t.signed_offer(key, NONCE, 60, ['STATUS'])
            self.assertRegex(offer.decode(), r'end\nsig=[0-9a-f]{768}\n\Z')
            self.assertFalse(self.openssl_verifies(offer))            # not the key the "stick" (self.public) trusts
            if VERIFY: self.assertEqual(self.stick(offer), (1, 'refusal=signature\n'))

    def test_refusal_test_passes_only_when_the_offer_was_fetched_and_not_answered(self):
        quiet = lambda l: None
        server = self.t.TuneServer(('127.0.0.1', 0), seconds=60, log=quiet, unsigned=True)
        try:
            server.queue('STATUS')
            self.assertEqual(self.t.refusal_test(server, wait=0.3, log=quiet, settle=0.1), 2)   # never fetched
            server.offer(NONCE)
            self.assertEqual(self.t.refusal_test(server, wait=0.3, log=quiet, settle=0.1), 0)   # fetched, refused
            server.replies = 1
            self.assertEqual(self.t.refusal_test(server, wait=0.3, log=quiet, settle=0.1), 2)   # the stick answered: a failure
        finally:
            server.server_close()

    def test_one_refusal_test_at_a_time(self):
        import contextlib, io
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.t.main(['--port', '0', '--unsigned-test', '--bad-signature-test'])


class KeyChainTests(unittest.TestCase):
    """The whole chain with a throwaway key made the way build.sh keygen makes the owner's: espsecure writes the
    key file and signs an image with it; the stick's key is what that image's signature block holds; the Mac tool
    signs an offer with the same key file through openssl; the firmware check accepts it with the block's key."""
    @unittest.skipUnless(VERIFY and Path(IDF_PYTHON).exists(), 'needs GUARDIAN_OFFER_VERIFY and the ESP-IDF Python (espsecure): the key chain check did not run')
    def test_offer_signed_with_an_espsecure_key_verifies_with_that_keys_signature_block(self):
        t = load('tune_session')
        with tempfile.TemporaryDirectory() as d:
            d = Path(d); key, image, signed = d / 'throwaway-sbv2.pem', d / 'app.bin', d / 'app-signed.bin'
            espsecure = lambda *a: subprocess.run([IDF_PYTHON, '-m', 'espsecure', *a], check=True, capture_output=True)
            espsecure('generate_signing_key', '--version', '2', '--scheme', 'rsa3072', str(key)); key.chmod(0o600)
            image.write_bytes(bytes([0xE9]) + bytes(4095))
            espsecure('sign_data', '--version', '2', '--keyfile', str(key), '--output', str(signed), str(image))
            data = signed.read_bytes()
            self.assertEqual(len(data), 8192)                      # the image, then one 4096-byte signature sector
            block = d / 'block.bin'; block.write_bytes(data[4096:4096 + 1216])
            stick = lambda offer, b=block: (lambda r: (r.returncode, r.stdout.decode()))(
                subprocess.run([VERIFY, f'block:{b}', '0', NONCE, '1000', '2000'], input=offer, capture_output=True))
            offer = t.signed_offer(t.check_key(key), NONCE, 60, ['TUNE detect.burst=6', 'STATUS'])
            self.assertEqual(stick(offer), (0, f'key=block\nrefusal=none\nsession={NONCE} expires=60 commands=2\ncmd=TUNE detect.burst=6\ncmd=STATUS\n'))
            other = make_key(d, 'other.pem')
            self.assertEqual(stick(t.signed_offer(other, NONCE, 60, ['STATUS'])), (1, 'key=block\nrefusal=signature\n'))
            # A stick whose image has no signature block (erased flash there) accepts nothing.
            blank = d / 'blank.bin'; blank.write_bytes(b'\xff' * 1216)
            self.assertEqual(stick(offer, blank), (1, 'key=none\nrefusal=nokey\n'))


class CommandLineTests(Keys):
    """The whole tool as the supervisor runs it: --command ... --no-prompt against a stick that polls."""
    def run_tool(self, argv, stick):
        import contextlib, io, socket
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
        old = os.environ.get('GUARDIAN_OTA_SIGNING_KEY'); os.environ['GUARDIAN_OTA_SIGNING_KEY'] = str(self.key)
        out, result = io.StringIO(), {}
        def tool():
            with contextlib.redirect_stdout(out):
                result['code'] = self.t.main(['--bind', '127.0.0.1', '--port', str(port)] + argv)
        thread = threading.Thread(target=tool, daemon=True); thread.start()
        try:
            stick(f'http://127.0.0.1:{port}')
            thread.join(20)
        finally:
            os.environ.pop('GUARDIAN_OTA_SIGNING_KEY', None)
            if old is not None: os.environ['GUARDIAN_OTA_SIGNING_KEY'] = old
        self.assertFalse(thread.is_alive(), 'the tool did not exit')
        return result.get('code'), out.getvalue()

    @staticmethod
    def fetch(url, data=None):
        import time
        for _ in range(100):   # the tool's server may not be listening yet
            try:
                return urllib.request.urlopen(urllib.request.Request(url, data=data, method='POST' if data is not None else 'GET'), timeout=5).read()
            except urllib.error.HTTPError:
                raise
            except OSError:
                time.sleep(0.05)
        raise AssertionError('tool server never answered')

    def test_commands_are_offered_signed_answered_and_the_tool_exits_zero(self):
        seen = {}
        def stick(base):
            offer = self.fetch(f'{base}/tune/offer?nonce={NONCE}')
            seen['offer'] = offer
            self.fetch(f'{base}/tune/reply?s={NONCE}', b'TUNE detect.burst=6\n')
            self.fetch(f'{base}/tune/reply?s={NONCE}', b'G14 STATUS control=companion tune_offers_ok=1\n')
            self.fetch(f'{base}/tune/end?s={NONCE}&why=done')
        code, out = self.run_tool(['--seconds', '60', '--wait', '5', '--command', 'TUNE detect.burst=6', '--command', 'STATUS', '--no-prompt'], stick)
        self.assertEqual(code, 0, out)
        self.assertTrue(self.openssl_verifies(seen['offer']))
        self.assertIn('G14 STATUS control=companion tune_offers_ok=1', out)
        self.assertIn('session ended: done', out)
        self.assertIn('offers=1 replies=2 sessions_ended=1 unanswered=0', out)
        self.assertNotIn(str(self.key), out)   # not even the key's path is printed in a normal run

    def test_unfetched_or_unanswered_commands_keep_the_tool_from_reporting_success(self):
        # main() returns 0 only when idle() and a session end were seen; a whole expiry (30 s at least) is too long
        # to wait for here, so the rule is checked on the server object.
        server = self.t.TuneServer(('127.0.0.1', 0), key_path=self.key, seconds=30, log=lambda l: None)
        try:
            server.queue('STATUS'); self.assertFalse(server.idle())            # queued, never fetched
            server.offer(NONCE); self.assertFalse(server.idle())               # fetched, never answered
            self.assertFalse(server.ended.is_set())
        finally:
            server.server_close()

    def test_no_prompt_needs_a_command(self):
        import contextlib, io
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.t.main(['--port', '0', '--no-prompt'])


class KeyPolicyTests(Keys):
    def test_key_must_exist_be_private_and_live_outside_the_repository(self):
        with self.assertRaises(ValueError) as e: self.t.check_key(Path(self.tmp.name) / 'absent.pem')
        self.assertIn('missing', str(e.exception))
        loose = make_key(self.tmp.name, 'loose.pem', mode=0o644)
        with self.assertRaises(ValueError) as e: self.t.check_key(loose)
        self.assertIn('600', str(e.exception))
        self.assertEqual(self.t.check_key(self.key), self.key.resolve())
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        inside = self.t.REPO_ROOT
        try:
            self.t.REPO_ROOT = Path(self.tmp.name).resolve()   # as if the key had been put in the repository
            with self.assertRaises(ValueError) as e: self.t.check_key(self.key)
            self.assertIn('outside the repository', str(e.exception))
        finally:
            self.t.REPO_ROOT = inside

    def test_default_key_path_is_the_one_build_sh_uses(self):
        build = (HERE.parent / 'firmware/boards/sticks3/tools/build.sh').read_text()
        self.assertIn('SIGNING_KEY="${GUARDIAN_OTA_SIGNING_KEY:-$HOME/.config/m5-guardian/ota-signing-rsa3072.pem}"', build)
        old = os.environ.pop('GUARDIAN_OTA_SIGNING_KEY', None)
        try:
            self.assertEqual(self.t.signing_key_path(), Path.home() / '.config/m5-guardian/ota-signing-rsa3072.pem')
            os.environ['GUARDIAN_OTA_SIGNING_KEY'] = '/somewhere/else.pem'
            self.assertEqual(self.t.signing_key_path(), Path('/somewhere/else.pem'))
        finally:
            os.environ.pop('GUARDIAN_OTA_SIGNING_KEY', None)
            if old is not None: os.environ['GUARDIAN_OTA_SIGNING_KEY'] = old

    def test_a_key_that_is_not_rsa_3072_is_refused_at_start(self):
        short = make_key(self.tmp.name, 'rsa2048.pem', bits=2048)
        with self.assertRaises(ValueError) as e: self.t.TuneServer(('127.0.0.1', 0), key_path=short)
        self.assertIn('not RSA-3072', str(e.exception))
        junk = Path(self.tmp.name) / 'junk.pem'; junk.write_text('not a key\n'); junk.chmod(0o600)
        with self.assertRaises(ValueError) as e: self.t.TuneServer(('127.0.0.1', 0), key_path=junk)
        self.assertIn('could not sign', str(e.exception)); self.assertNotIn('not a key', str(e.exception))

    def test_signature_is_pkcs1_v15_sha256_of_exactly_the_given_bytes(self):
        data = b'GUARDIAN-TUNE 2\nnonce=' + NONCE.encode() + b'\nexpires=60\ncmd=STATUS\nend\n'
        sig = self.t.sign(self.key, data)
        self.assertEqual(len(sig), 384)
        self.assertEqual(sig, self.t.sign(self.key, data))            # v1.5 is deterministic (PSS, the image scheme, is not)
        self.assertTrue(self.openssl_verifies(data + b'sig=' + sig.hex().encode() + b'\n'))
        self.assertEqual(self.t.signed_offer(self.key, NONCE, 60, ['STATUS']), data + b'sig=' + sig.hex().encode() + b'\n')

    def test_tool_stops_without_a_usable_key(self):
        old = os.environ.get('GUARDIAN_OTA_SIGNING_KEY')
        os.environ['GUARDIAN_OTA_SIGNING_KEY'] = str(Path(self.tmp.name) / 'absent.pem')
        try:
            self.assertEqual(self.t.main(['--port', '0', '--command', 'STATUS', '--no-prompt']), 1)
        finally:
            os.environ.pop('GUARDIAN_OTA_SIGNING_KEY', None)
            if old is not None: os.environ['GUARDIAN_OTA_SIGNING_KEY'] = old


if __name__ == '__main__':
    unittest.main()

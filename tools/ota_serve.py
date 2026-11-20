#!/usr/bin/env python3
"""G16B: serve ONE archived, signed StickS3 build to the Guardian for one OTA update.

    tools/ota_serve.py $GUARDIAN_STORE/builds/<stamp>-sticks3 [--port 8070]

Serves exactly two paths on the owner's LAN, then exits:
  GET /manifest  "GUARDIAN-OTA 1" text: version, size, sha256 of /image, signature scheme
  GET /image     the archived guardian_sticks3-signed.bin (Content-Length = size)
The archive must be COMPLETE (build.sh), its SHA256SUMS must re-verify, the signing
record must match the image and the image's own app version must equal the archive's.
The server stops after one complete /image transfer or after --timeout seconds.

--bad-signature-test (reviewer acceptance only): re-signs the archive's UNSIGNED image
with a throwaway RSA-3072 key generated in a temporary directory and serves that, so the
device must refuse it at the signature check before any slot switch. The throwaway key is
deleted on exit. Nothing here touches the owner's signing key or flashes a device.
"""
import argparse, hashlib, http.server, json, os, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guardian_local  # noqa: E402  GUARDIAN_STORE: environment, else local.conf


def store_builds():
    return guardian_local.store(check=False) / 'builds'
SIGNED = 'guardian_sticks3-signed.bin'
UNSIGNED = 'guardian_sticks3.bin'
IDF_PYTHON = os.environ.get('GUARDIAN_IDF_PYTHON', str(Path.home() / '.espressif/python_env/idf5.4_py3.10_env/bin/python'))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def app_version(image):
    """esp_app_desc_t.version (same reader as boards/sticks3/tools/build_support.py)."""
    if len(image) < 80 or image[0] != 0xE9 or int.from_bytes(image[32:36], 'little') != 0xABCD5432:
        raise ValueError('not an ESP-IDF app image with an app descriptor')
    return image[48:80].split(b'\0', 1)[0].decode('ascii')


def load_archive(archive):
    """Returns (version, signed image bytes, archive facts) after re-verifying the archive."""
    archive = Path(archive).resolve()
    builds = store_builds()
    if not archive.is_relative_to(builds):
        raise ValueError(f'archive must be under {builds}')
    complete = json.loads((archive / 'COMPLETE.json').read_text())
    if complete.get('complete') is not True or complete.get('signed_app') != SIGNED:
        raise ValueError('archive is not a complete signed G16B build')
    sums = {}
    for line in (archive / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1)
        sums[name] = digest
    for name in (SIGNED, UNSIGNED, 'signing.json'):
        if sums.get(name) != sha256((archive / name).read_bytes()):
            raise ValueError(f'{name} does not match SHA256SUMS')
    image = (archive / SIGNED).read_bytes()
    record = json.loads((archive / 'signing.json').read_text())
    if record.get('scheme') != 'rsa3072-sbv2' or record.get('signed_sha256') != sha256(image):
        raise ValueError('signing record does not match the signed image')
    version = app_version(image)
    if version != complete.get('app_version') or version != record.get('app_version'):
        raise ValueError('image app version differs from the archive record')
    return version, image, {'selftest_fail_test_image': complete.get('selftest_fail_test_image', False),
                            'ble_spike_image': complete.get('ble_spike_image', False),   # G16H
                            'art_bench_image': complete.get('art_bench_image', False)}   # G16Q


def manifest(version, image):
    if not (1 <= len(version) <= 31) or any(not (c.isalnum() or c in '._-') for c in version):
        raise ValueError('version must be 1..31 chars of [A-Za-z0-9._-]')
    return (f'GUARDIAN-OTA 1\nversion={version}\nsize={len(image)}\nsha256={sha256(image)}\n'
            'signature=rsa3072-sbv2\nend\n').encode()


def bad_signature_image(archive, workdir):
    """The archive's unsigned image signed by a throwaway key (never the owner key)."""
    key = Path(workdir) / 'throwaway-rsa3072.pem'
    out = Path(workdir) / 'bad-signature.bin'
    run = lambda *a: subprocess.run([IDF_PYTHON, '-m', 'espsecure', *a], check=True, capture_output=True)
    run('generate_signing_key', '--version', '2', '--scheme', 'rsa3072', str(key))
    run('sign_data', '--version', '2', '--keyfile', str(key), '--output', str(out), str(Path(archive) / UNSIGNED))
    return out.read_bytes()


class OneUpdateServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, manifest_bytes, image_bytes, log=print):
        self.manifest_bytes, self.image_bytes, self.log = manifest_bytes, image_bytes, log
        self.image_sent = threading.Event()
        super().__init__(address, Handler)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'GuardianOTA/1'

    def log_message(self, fmt, *args):
        self.server.log(f'{self.client_address[0]} {fmt % args}')

    def do_GET(self):
        body = {'/manifest': self.server.manifest_bytes, '/image': self.server.image_bytes}.get(self.path)
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream' if self.path == '/image' else 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            for at in range(0, len(body), 16384):
                self.wfile.write(body[at:at + 16384])
        except (BrokenPipeError, ConnectionResetError):
            self.server.log(f'{self.path}: client closed the connection early')
            return
        if self.path == '/image':
            self.server.log(f'/image: sent {len(body)} bytes')
            self.server.image_sent.set()


def serve(server, timeout_s):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    finished = server.image_sent.wait(timeout_s)
    time.sleep(0.5)   # let the final response flush
    server.shutdown()
    server.server_close()
    return finished


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('archive')
    p.add_argument('--port', type=int, default=8070)
    p.add_argument('--bind', default='0.0.0.0')
    p.add_argument('--timeout', type=int, default=900, help='seconds before giving up (default 900)')
    p.add_argument('--bad-signature-test', action='store_true', help='reviewer test: serve the image signed by a throwaway key')
    a = p.parse_args(argv)
    try:
        version, image, facts = load_archive(a.archive)
    except (OSError, ValueError) as e:   # includes guardian_local.Missing (no GUARDIAN_STORE)
        print(f'ota_serve: refused: {e}', file=sys.stderr)
        return 2
    workdir = tempfile.mkdtemp(prefix='guardian-ota-')
    try:
        if a.bad_signature_test:
            image = bad_signature_image(a.archive, workdir)
            version = (version + '-badsig')[:31]
        body = manifest(version, image)
        server = OneUpdateServer((a.bind, a.port), body, image)
        print(f'serving version={version} size={len(image)} sha256={sha256(image)}'
              f'{" [BAD-SIGNATURE TEST]" if a.bad_signature_test else ""}'
              f'{" [SELF-TEST-FAIL TEST IMAGE]" if facts["selftest_fail_test_image"] else ""}'
              f'{" [BLE COEXISTENCE SPIKE IMAGE]" if facts["ble_spike_image"] else ""}'
              f'{" [ART BENCH IMAGE]" if facts["art_bench_image"] else ""}'
              f' on {a.bind}:{server.server_address[1]} for one update (timeout {a.timeout}s)', flush=True)
        done = serve(server, a.timeout)
        print('one update served; server stopped' if done else 'timeout: no complete /image transfer; server stopped', flush=True)
        return 0 if done else 2
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())

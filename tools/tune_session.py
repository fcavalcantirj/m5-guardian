#!/usr/bin/env python3
"""G16C / G22A: tune the standing Guardian over the owner's Wi-Fi with SIGNED offers (no USB cable).

    tools/tune_session.py [--port 8070] [--seconds 300] --command 'TUNE?' [--command STATUS ...] [--no-prompt]

Run it on the Mac whose URL the stick was provisioned with (tools/ota_provision.py),
on the same port, instead of tools/ota_serve.py. The stick asks for an offer by itself
at every self-fetch poll (TUNE ota.auto_s, 120 s by default) and after FRONT x3 fast
+ FRONT=yes. Since G22A the stick opens a session only for an offer SIGNED WITH THE OTA
SIGNING KEY: the key file tools of this repository already use to sign images
(boards/sticks3/tools/build.sh: $GUARDIAN_OTA_SIGNING_KEY, default
~/.config/m5-guardian/ota-signing-rsa3072.pem). This tool passes the key's PATH to
openssl and never reads, prints or copies the key itself. Without that key no offer can
be made, on this Mac or any other host.

One offer carries up to 8 commands, the stick's own fresh nonce and an expiry:
    GUARDIAN-TUNE 2 / nonce=<32 hex> / expires=<seconds> / cmd=<line> ... / end / sig=<768 hex>
(RSA-3072 PKCS#1 v1.5 SHA-256 over every byte from the header through "end"). The stick
runs the commands in order and posts each reply; nothing else can be sent into a session.
Monitoring is paused for the session; the glass shows "TUNE WI-FI <s>" and any key ends it.

Commands (one per --command, or one per line at the prompt; they leave with the stick's
next request): STATUS, FRAMES, FRAMES 0, TUNE?, TUNE key=value, TUNE save ... (the
device's own TUNE syntax), IMU POSE, BATTRUN. Every other command (radio, measurement,
OTA provisioning, the raw IMU stream) stays USB-only and is refused here and on the device.

The stick is only an HTTP client of this tool; it never listens. Served paths:
  GET  /tune/offer?nonce=<32 hex>  the signed offer for that nonce (404 while nothing is queued)
  POST /tune/reply?s=<nonce>       one command's reply lines (printed here)
  GET  /tune/end?s=<nonce>&why=<r> the device ended the session
Anything else, including the update paths /manifest and /image, is 404; a wrong
session is 403. Nothing here flashes, updates or reboots the device.

Reviewer acceptance only (the stick must REFUSE both; neither touches the owner's key):
  --unsigned-test        the offer goes out without its sig line   -> STATUS tune_offers_refused_by=unsigned:+1
  --bad-signature-test   the offer is signed with a throwaway RSA-3072 key made in a temporary directory and
                         deleted on exit                           -> STATUS tune_offers_refused_by=signature:+1
Each serves one offer, waits a few seconds for a reply that must not come, and exits 0 when none came
(read the counter afterwards with a normal signed STATUS), 2 when the stick answered or never asked.
"""
import argparse, http.server, os, re, shutil, stat, subprocess, sys, tempfile, threading, time, urllib.parse
from pathlib import Path

MIN_SECONDS, MAX_SECONDS, MAX_COMMAND, MAX_COMMANDS = 30, 1800, 159, 8
SIGNATURE_BYTES = 384   # RSA-3072
REPO_ROOT = Path(__file__).resolve().parents[1]
OPENSSL = os.environ.get('GUARDIAN_OPENSSL', '/usr/bin/openssl')
_EXACT = {'STATUS', 'FRAMES', 'FRAMES 0', 'TUNE?', 'IMU POSE', 'BATTRUN'}   # IMU POSE, BATTRUN: review 2026-11-17
_EXACT |= {'BLESPIKE', 'BLESPIKE report', 'BLESPIKE phases', 'BLESPIKE stop', 'BLESPIKE start'}   # G16H spike, supervisor 2026-11-19
_NONCE = re.compile(r'[0-9a-f]{32}')


def allowed(line):
    """Same rule as the device (adapters/tune/session.cpp allowed())."""
    if not line or len(line) > MAX_COMMAND or any(not (' ' <= c <= '~') for c in line):
        return False
    if line.startswith('TUNE? '):   # one registry group, e.g. 'TUNE? t.probe' (review 2026-11-17)
        rest = line[6:]
        return bool(rest) and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789._' for c in rest)
    if re.fullmatch(r'BLESPIKE start [0-9]{1,3} [0-9]', line):   # G16H spike (supervisor 2026-11-19), spike image only
        return True
    return line in _EXACT or (line.startswith('TUNE ') and len(line) > 5)


def signing_key_path():
    """The key file build.sh signs images with (same variable, same default)."""
    return Path(os.environ.get('GUARDIAN_OTA_SIGNING_KEY') or Path.home() / '.config/m5-guardian/ota-signing-rsa3072.pem')


def check_key(path):
    """build.sh require_key: the key exists, lives outside the repository and outside external volumes, mode 600.

    Only the path and its permissions are looked at; the file is not opened here."""
    path = Path(path)
    if not path.is_file():
        raise ValueError(f'OTA signing key missing at {path} (build.sh keygen creates it once)')
    real = path.resolve()
    if real.is_relative_to(REPO_ROOT) or real.is_relative_to('/Volumes'):
        raise ValueError('the signing key must live outside the repository and outside the store/external volumes')
    if stat.S_IMODE(real.stat().st_mode) != 0o600:
        raise ValueError(f'signing key permissions must be 600: {real}')
    return real


def sign(key_path, data):
    """RSA PKCS#1 v1.5 SHA-256 signature of `data` by openssl; the key goes in as a path only."""
    try:
        run = subprocess.run([OPENSSL, 'dgst', '-sha256', '-sign', str(key_path)], input=data, capture_output=True)
    except OSError as e:
        raise ValueError(f'cannot run {OPENSSL}: {e.strerror}') from None
    if run.returncode != 0:
        raise ValueError(f'openssl could not sign with the key at {key_path} (exit {run.returncode})')   # its stderr is not echoed
    if len(run.stdout) != SIGNATURE_BYTES:
        raise ValueError(f'the key at {key_path} is not RSA-3072 (signature of {len(run.stdout)} bytes)')
    return run.stdout


def envelope(nonce, seconds, commands):
    """The signed part of an offer: every byte from the header through "end\n"."""
    if not _NONCE.fullmatch(nonce):
        raise ValueError('nonce must be 32 lowercase hex digits')
    if not MIN_SECONDS <= seconds <= MAX_SECONDS:
        raise ValueError(f'seconds must be {MIN_SECONDS}..{MAX_SECONDS}')
    if not 1 <= len(commands) <= MAX_COMMANDS or not all(allowed(c) for c in commands):
        raise ValueError(f'an offer carries 1..{MAX_COMMANDS} commands the device accepts over Wi-Fi')
    return (f'GUARDIAN-TUNE 2\nnonce={nonce}\nexpires={seconds}\n' + ''.join(f'cmd={c}\n' for c in commands) + 'end\n').encode('ascii')


def signed_offer(key_path, nonce, seconds, commands):
    body = envelope(nonce, seconds, commands)
    return body + b'sig=' + sign(key_path, body).hex().encode('ascii') + b'\n'


class TuneServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, key_path=None, seconds=300, log=print, unsigned=False):
        if not MIN_SECONDS <= seconds <= MAX_SECONDS:
            raise ValueError(f'seconds must be {MIN_SECONDS}..{MAX_SECONDS}')
        self.unsigned = unsigned   # reviewer test: no sig line, and no key is looked at
        if not unsigned:
            self.key_path = check_key(key_path or signing_key_path())
            sign(self.key_path, b'GUARDIAN-TUNE key-check\n')   # fails now, not at the stick's poll, when the key cannot sign
        self.seconds, self.log = seconds, log
        self.lock = threading.Lock()
        self.pending = []                     # accepted commands not yet in an offer
        self.session = None                   # nonce of the offer handed out last
        self.batch, self.answered = [], 0     # its commands and how many replies came back
        self.offers = self.sessions_ended = self.replies = self.lost = 0
        self.ended = threading.Event()        # the device reported the end of a session
        self.replied = threading.Event()      # at least one reply arrived since the last queue()
        super().__init__(address, Handler)

    def queue(self, line):
        if not allowed(line):
            return False
        with self.lock:
            self.pending.append(line)
        self.replied.clear(); self.ended.clear()
        return True

    def idle(self):
        """Nothing queued and every command handed out was answered or its session ended."""
        with self.lock:
            return not self.pending and (self.session is None or self.answered >= len(self.batch))

    def offer(self, nonce):
        """The signed offer for the stick's nonce, or None while nothing is queued. A command leaves once:
        commands of an earlier offer that were never answered are reported, not sent again."""
        with self.lock:
            if not self.pending:
                return None
            if self.session is not None and self.answered < len(self.batch):
                missing = self.batch[self.answered:]
                self.lost += len(missing)
                self.log(f'earlier session ended without {len(missing)} replies (not sent again): {missing!r}')
            batch, self.pending = self.pending[:MAX_COMMANDS], self.pending[MAX_COMMANDS:]
            body = envelope(nonce, self.seconds, batch) if self.unsigned else signed_offer(self.key_path, nonce, self.seconds, batch)
            self.session, self.batch, self.answered = nonce, batch, 0
            self.offers += 1
        self.log(f'{"UNSIGNED" if self.unsigned else "signed"} offer {self.offers}: {len(batch)} command(s), expires in {self.seconds}s')
        return body


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'GuardianTune/2'

    def log_message(self, fmt, *args):
        pass   # request lines are noise at the prompt; replies and ends are printed

    def _send(self, code, body=b''):
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _route(self):
        url = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(url.query)
        return url.path, q.get('s', [''])[0], q

    def do_GET(self):
        s = self.server
        path, sid, q = self._route()
        if path == '/tune/offer':
            nonce = q.get('nonce', [''])[0]
            if not _NONCE.fullmatch(nonce):
                self._send(400); return   # no nonce, nothing to sign: an offer is made for one request of the stick only
            try:
                body = s.offer(nonce)
            except ValueError as e:
                s.log(f'offer not signed: {e}'); self._send(500); return
            self._send(200, body) if body else self._send(404)
            return
        if path != '/tune/end':
            self._send(404); return
        if not sid or sid != s.session:
            self._send(403); return
        why = re.sub(r'[^a-z]', '', q.get('why', ['?'])[0])[:16]
        s.log(f'session ended: {why}')
        with s.lock:
            s.sessions_ended += 1
        self._send(200); s.ended.set()

    def do_POST(self):
        s = self.server
        path, sid, _ = self._route()
        if path != '/tune/reply':
            self._send(404); return
        if not sid or sid != s.session:
            self._send(403); return
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(min(n, 8192)).decode('ascii', 'replace') if n > 0 else ''
        for line in body.splitlines():
            s.log(line)
        with s.lock:
            s.answered += 1; s.replies += 1
        s.replied.set()
        self._send(200)


def throwaway_key(workdir):
    """A new RSA-3072 key in `workdir` (never the owner's key), for --bad-signature-test."""
    key = Path(workdir) / 'throwaway-rsa3072.pem'
    try:
        run = subprocess.run([OPENSSL, 'genrsa', '-out', str(key), '3072'], capture_output=True)
    except OSError as e:
        raise ValueError(f'cannot run {OPENSSL}: {e.strerror}') from None
    if run.returncode != 0:
        raise ValueError('openssl could not make the throwaway key')
    key.chmod(0o600)
    return key


def refusal_test(server, wait, log=print, settle=8.0):
    """Reviewer run: one offer the stick must refuse. 0: fetched and not answered; 2: answered, or never fetched."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline and not server.offers:
        time.sleep(0.2)
    if not server.offers:
        log('refusal test: the stick never asked for the offer'); return 2
    time.sleep(settle)   # a stick that accepted it would post its first reply well inside this
    if server.replies or server.ended.is_set():
        log('refusal test FAILED: the stick opened a session for an offer it must refuse'); return 2
    log('refusal test: the offer was fetched and not answered; read tune_offers_refused_by in a signed STATUS'); return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--port', type=int, default=8070)
    p.add_argument('--bind', default='0.0.0.0')
    p.add_argument('--seconds', type=int, default=300, help=f'expiry of each offer and of its session on the stick ({MIN_SECONDS}..{MAX_SECONDS})')
    p.add_argument('--wait', type=int, default=180, help='with --no-prompt: seconds to wait for the stick to fetch the offer (its poll period plus the join; default 180)')
    p.add_argument('--command', action='append', default=[], help='queue these first (repeatable); with --no-prompt, exit once they are answered')
    p.add_argument('--no-prompt', action='store_true', help='do not read commands from stdin')
    p.add_argument('--unsigned-test', action='store_true', help='reviewer test: serve the offer without its signature (the stick must refuse it)')
    p.add_argument('--bad-signature-test', action='store_true', help='reviewer test: sign the offer with a throwaway key (the stick must refuse it)')
    a = p.parse_args(argv)
    testing = a.unsigned_test or a.bad_signature_test
    if a.unsigned_test and a.bad_signature_test:
        p.error('one refusal test at a time')
    if testing and not a.command:
        a.command = ['STATUS']
    for c in a.command:
        if not allowed(c):
            p.error(f'not accepted over Wi-Fi: {c!r}')
    if a.no_prompt and not a.command:
        p.error('--no-prompt needs at least one --command')
    workdir = tempfile.mkdtemp(prefix='guardian-tune-') if a.bad_signature_test else None
    try:
        server = TuneServer((a.bind, a.port), key_path=throwaway_key(workdir) if workdir else None, seconds=a.seconds,
                            log=lambda l: print(l, flush=True), unsigned=a.unsigned_test)
    except ValueError as e:
        if workdir: shutil.rmtree(workdir, ignore_errors=True)
        print(f'tune_session.py: {e}', file=sys.stderr); return 1
    threading.Thread(target=server.serve_forever, daemon=True).start()
    for c in a.command:
        server.queue(c)
    if testing:
        print(f'[{"UNSIGNED" if a.unsigned_test else "BAD-SIGNATURE"} TEST] one offer on {a.bind}:{server.server_address[1]} that the stick must refuse; '
              f'waiting up to {a.wait}s for its poll.', flush=True)
        try:
            return refusal_test(server, a.wait, log=lambda l: print(l, flush=True))
        finally:
            server.shutdown(); server.server_close()
            if workdir: shutil.rmtree(workdir, ignore_errors=True)
    print(f'Signed TUNE offers on {a.bind}:{server.server_address[1]} (expiry {a.seconds}s, {len(a.command)} command(s) queued). '
          'The stick fetches them at its next poll (TUNE ota.auto_s) or after FRONT x3 fast + FRONT=yes.', flush=True)
    try:
        if a.no_prompt:
            deadline = time.monotonic() + a.wait + a.seconds
            while time.monotonic() < deadline and not (server.idle() and server.ended.is_set()):
                time.sleep(0.2)
        else:
            while True:
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.strip()
                if line in ('quit', 'exit'):
                    break
                if line and not server.queue(line):
                    print(f'refused (not accepted over Wi-Fi): {line!r}', flush=True)
            deadline = time.monotonic() + 30   # let a session in flight report its end
            while time.monotonic() < deadline and not (server.idle() and (server.ended.is_set() or not server.offers)):
                time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown(); server.server_close()
    done = server.idle() and server.lost == 0 and (server.offers == 0 or server.ended.is_set())
    print(f'offers={server.offers} replies={server.replies} sessions_ended={server.sessions_ended} unanswered={server.lost + len(server.pending) + max(0, len(server.batch) - server.answered)}', flush=True)
    return 0 if done and (server.replies or not a.command) else 2


if __name__ == '__main__':
    sys.exit(main())

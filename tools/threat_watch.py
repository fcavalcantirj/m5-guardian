#!/usr/bin/env python3
"""Review 2026-11-17: read-only STATUS recorder for the G16F/G16G live proofs and the benign soak.

    tools/threat_watch.py --port /dev/cu.usbmodemXXXX --out <evidence.jsonl> [--seconds 600] [--interval 0.5]

The StickS3 under test stays on USB (it never sleeps on USB power). This tool asks it for
"STATUS" every --interval seconds and nothing else (read-only), writes every reply with the
host time to --out (JSON lines), and prints one line per change worth seeing:
  - a detector's incident counter going up (detector, count, seconds since the last mark),
  - a reboot (uptime_s going backwards; the stick's own reset= reason is printed).
Type a note and Enter while it runs to MARK the moment an attack starts ("probe flood
started"); incidents after it carry since_mark_s. Ctrl-C or --seconds ends it with a
summary: incidents per detector, reboots, worst heap_internal_min / task_stack_free,
worst rx_queue_full.

Honest limits: STATUS is polled, so latency is known to about one --interval, and it is
measured from the owner's mark, not from the attack's closing frame on air (that needs a
second receiver). Opening the USB port resets the stick once (USB Serial/JTAG), so the
first STATUS comes ~10 s after boot; identity is checked from the boot INFO line (MAC)
before anything is recorded, and any other board (the Cardputer) is refused.
"""
import argparse, json, re, select, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guardian_local  # noqa: E402

# The stick under test: --mac, else GUARDIAN_LAB_STICK_MAC (environment or local.conf).
STICK_MAC = guardian_local.get('GUARDIAN_LAB_STICK_MAC') or ''
_FIELD = re.compile(r'(?:^| )([a-z_]+)=(\S+)')
_INFO_MAC = re.compile(r'GRX1 INFO \S+ mac=([0-9a-fA-F:]{17})')
_INT = re.compile(r'-?\d+')


class WatchError(Exception):
    pass


def mac_from_info(line):
    m = _INFO_MAC.search(line)
    return m.group(1).lower() if m else None


def check_identity(text, expected):
    for line in text.splitlines():
        mac = mac_from_info(line)
        if mac:
            if mac != expected.lower():
                raise WatchError(f'board {mac} is not the StickS3 {expected.lower()}; refusing')
            return mac
    raise WatchError('no GRX1 INFO line from the board (identity unknown); refusing')


def _num(v):
    return int(v) if _INT.fullmatch(v) else v


def parse_status(line):
    """One 'G14 STATUS ...' line -> dict (None for anything else or a line without detectors)."""
    line = line.strip()
    if not line.startswith('G14 STATUS ') or ' detectors=' not in line:
        return None
    out = {}
    for k, v in _FIELD.findall(line):
        if k == 'detectors':
            dets = {}
            for rec in v.split(';'):
                name, _, body = rec.partition(':')
                d = {}
                for part in body.split(','):
                    key, eq, val = part.partition('=')
                    d[key] = _num(val) if eq else True        # bare flag, e.g. "unconfigured"
                dets[name] = d
            out['detectors'] = dets
        elif k == 'air' and v != 'none':
            out['air'] = {a: _num(b.rstrip('+')) for a, _, b in (p.partition(':') for p in v.split(','))}
        else:
            out.setdefault(k, _num(v))
    return out


class Watch:
    def __init__(self):
        self.prev, self.marked = None, None
        self.statuses = self.reboots = 0
        self.incidents = {}
        self.heap_min = self.stack_min = None
        self.queue_full_max = 0

    def mark(self, t, note):
        self.marked = (t, note)

    def update(self, s, t):
        events = []
        self.statuses += 1
        for key, attr in (('heap_internal_min', 'heap_min'), ('task_stack_free', 'stack_min')):
            v = s.get(key)
            if isinstance(v, int) and (getattr(self, attr) is None or v < getattr(self, attr)):
                setattr(self, attr, v)
        if isinstance(s.get('rx_queue_full'), int):
            self.queue_full_max = max(self.queue_full_max, s['rx_queue_full'])
        prev = self.prev
        if prev is not None and isinstance(s.get('uptime_s'), int) and isinstance(prev.get('uptime_s'), int) \
                and s['uptime_s'] < prev['uptime_s']:
            self.reboots += 1
            events.append({'t': t, 'kind': 'reboot', 'reset': s.get('reset'), 'uptime_s': s['uptime_s']})
            prev = None                                      # counters restart with the stick
        for name, d in s.get('detectors', {}).items():
            now_n = d.get('incidents', 0)
            before = (prev or {}).get('detectors', {}).get(name, {}).get('incidents', 0) if prev is not None else 0
            if self.prev is None:
                before = now_n                               # the first STATUS is the baseline
            if isinstance(now_n, int) and now_n > before:
                e = {'t': t, 'kind': 'incident', 'detector': name, 'count': now_n, 'new': now_n - before}
                if self.marked:
                    e['since_mark_s'] = round(t - self.marked[0], 3); e['mark'] = self.marked[1]
                events.append(e)
                self.incidents[name] = self.incidents.get(name, 0) + now_n - before
        self.prev = s
        return events

    def summary(self):
        return {'statuses': self.statuses, 'reboots': self.reboots, 'incidents': dict(self.incidents),
                'heap_internal_min': self.heap_min, 'task_stack_free_min': self.stack_min,
                'rx_queue_full_max': self.queue_full_max}


class MarkReader:
    """Owner marks typed on stdin. End of input (closed or /dev/null stdin) is never a mark
    (review 2026-11-17: a background run once logged a mark every poll)."""
    def __init__(self, stream):
        self.stream, self.closed = stream, False

    def poll(self, ready):
        if self.closed or not ready:
            return None
        line = self.stream.readline()
        if line == '':
            self.closed = True
            return None
        return line.strip() or 'mark'


def _read_lines(port, wait_s, now):
    """Bytes the port yields within wait_s, split into complete lines."""
    end, buf = now() + wait_s, b''
    while True:
        chunk = port.read(4096)
        if chunk:
            buf += chunk
        if b'G14 STATUS' in buf and buf.endswith(b'\n'):
            break
        if now() >= end:
            break
    return buf.decode('ascii', 'replace').splitlines()


def poll_once(port, watch, log, now=time.monotonic, wait_s=1.0):
    port.write(b'STATUS\n')
    events = []
    for line in _read_lines(port, wait_s, now):
        s = parse_status(line)
        if s is None:
            continue
        t = now()
        log.write(json.dumps({'type': 'status', 't': t, 'line': line}) + '\n')
        for e in watch.update(s, t):
            log.write(json.dumps({'type': 'event', **e}) + '\n'); events.append(e)
    log.flush()
    return events


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--port', required=True)
    ap.add_argument('--out', required=True, help='JSON-lines evidence file (created; refused if it exists)')
    ap.add_argument('--seconds', type=float, default=600.0)
    ap.add_argument('--interval', type=float, default=0.5)
    ap.add_argument('--mac', default=STICK_MAC)
    a = ap.parse_args(argv)
    if not a.mac:
        ap.error('name the stick: --mac <address> or GUARDIAN_LAB_STICK_MAC (lab/local.conf.example)')
    import serial                                             # pyserial, only for the live run
    port = serial.Serial(); port.port = a.port; port.baudrate = 115200; port.dtr = False; port.rts = False; port.timeout = 0.05
    port.open()
    with open(a.out, 'x') as log:
        boot, end = b'', time.monotonic() + 15
        while time.monotonic() < end and b'GRX1 INFO' not in boot:
            boot += port.read(4096)
        try:
            mac = check_identity(boot.decode('ascii', 'replace'), a.mac)
        except WatchError as e:
            print(f'threat_watch: REFUSED: {e}', file=sys.stderr); return 2
        log.write(json.dumps({'type': 'start', 't': time.monotonic(), 'mac': mac, 'wall': time.strftime('%Y-%m-%dT%H:%M:%S%z')}) + '\n')
        print(f'watching {mac}; type a note + Enter to mark an attack start, Ctrl-C to stop', flush=True)
        watch, stop, marks = Watch(), time.monotonic() + a.seconds, MarkReader(sys.stdin)
        try:
            while time.monotonic() < stop:
                note = marks.poll(not marks.closed and bool(select.select([sys.stdin], [], [], 0)[0]))
                if note:
                    t = time.monotonic(); watch.mark(t, note)
                    log.write(json.dumps({'type': 'mark', 't': t, 'note': note}) + '\n'); print(f'MARK {note}', flush=True)
                for e in poll_once(port, watch, log):
                    print(json.dumps(e), flush=True)
                time.sleep(max(0.0, a.interval))
        except KeyboardInterrupt:
            pass
        s = watch.summary()
        log.write(json.dumps({'type': 'summary', 't': time.monotonic(), **s}) + '\n')
    print(json.dumps(s, indent=1), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())

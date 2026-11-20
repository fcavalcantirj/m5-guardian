#!/usr/bin/env python3
"""G16J spike (a): the data-path load on the StickS3, measured, with a verdict.

    tools/datapath_spike.py --port /dev/cu.usbmodemXXXX [--seconds 600]

Owner-launched (it CHANGES one setting on the stick for the length of the run, then puts it back):
over USB it reads `TUNE? detect.datapath`, sets it to 0 and records STATUS for --seconds, sets it
to 1 and records again, then restores the value it found. Nothing is transmitted on air; the data
path only widens what the radio RECEIVES (data frames and checksum-failed frames, EAPOL kept).

It writes the raw STATUS stream to the store (evidence-raw/) and the numbers to
firmware/evidence/sticks3-G16J-spike-a-datapath-<date>.log:
  fps (min / median), rx_queue_full growth, heap_internal_min, task_stack_free, callback CPU.

Verdict (ledger G16J): "on" when, with the data path on, fps stays >= 20 and rx_queue_full grows
no faster than it did with the data path off; otherwise "off (load)". The verdict is a
recommendation for the detect.datapath default; this tool never changes a default.

Honest limits: STATUS fps is the display loop's rate at the moment of each poll; ten minutes in
one home at one hour is not every load. Run it while the house is busy, and not during a soak
(opening the USB port resets the stick once).
"""
import argparse, json, os, statistics, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import threat_watch as tw   # noqa: E402

import live_matrix  # noqa: E402  require_store / default_raw_dir, one definition
REPO = Path(__file__).resolve().parents[1]
KEY = 'detect.datapath'
FPS_MIN = 20.0


class SpikeError(Exception):
    pass


def _lines(port, wait_s, now, done):
    """Decoded lines the port yields until `done(text)` or the wait is over."""
    end, buf = now() + wait_s, b''
    while True:
        chunk = port.read(4096)
        if chunk:
            buf += chunk
        text = buf.decode('ascii', 'replace')
        if done(text) or now() >= end:
            return text.splitlines()


def tune_get(port, now):
    port.write(('TUNE? %s\n' % KEY).encode())
    for line in _lines(port, 2.0, now, lambda t: 'TUNE OK' in t or 'TUNE ERROR' in t):
        if line.startswith('TUNE %s=' % KEY):
            return float(line.split('=', 1)[1].split()[0])
    raise SpikeError('the stick did not answer TUNE? %s' % KEY)


def tune_set(port, value, now):
    port.write(('TUNE %s=%g\n' % (KEY, value)).encode())
    for line in _lines(port, 3.0, now, lambda t: 'TUNE OK %s=' % KEY in t or 'TUNE ERROR' in t):
        if line.startswith('TUNE OK %s=' % KEY):
            return
        if line.startswith('TUNE ERROR'):
            raise SpikeError('the stick refused %s=%g: %s' % (KEY, value, line))
    raise SpikeError('no reply to TUNE %s=%g' % (KEY, value))


def record(port, log, name, seconds, interval, now, sleep):
    fps, heap, stack, cpu, queue = [], None, None, 0, []
    statuses = 0
    start = now()
    log.write(json.dumps({'type': 'phase', 't': start, 'name': name, 'seconds': seconds}) + '\n')
    while now() < start + seconds:
        port.write(b'STATUS\n')
        for line in tw._read_lines(port, max(interval, 0.05), now):
            s = tw.parse_status(line)
            if s is None:
                continue
            statuses += 1
            log.write(json.dumps({'type': 'status', 't': now(), 'line': line}) + '\n')
            try:
                fps.append(float(s.get('fps')))
            except (TypeError, ValueError):
                pass
            for key in ('heap_internal_min', 'task_stack_free'):
                v = s.get(key)
                if isinstance(v, int):
                    if key == 'heap_internal_min':
                        heap = v if heap is None else min(heap, v)
                    else:
                        stack = v if stack is None else min(stack, v)
            if isinstance(s.get('cb_cpu_permille'), int):
                cpu = max(cpu, s['cb_cpu_permille'])
            if isinstance(s.get('rx_queue_full'), int):
                queue.append(s['rx_queue_full'])
        log.flush()
        sleep(0)
    if not statuses or not fps or not queue:
        raise SpikeError('phase %s recorded no usable STATUS' % name)
    return {'phase': name, 'statuses': statuses, 'fps_min': min(fps), 'fps_median': statistics.median(fps),
            'rx_queue_full_growth': queue[-1] - queue[0], 'heap_internal_min': heap, 'task_stack_free_min': stack,
            'cb_cpu_permille_max': cpu}


def judge(off, on):
    reasons = []
    if on['fps_min'] < FPS_MIN:
        reasons.append('fps fell to %.1f with the data path on (needs >= %.0f)' % (on['fps_min'], FPS_MIN))
    # Per-status growth, so phases of slightly different length compare fairly.
    off_rate = off['rx_queue_full_growth'] / max(off['statuses'], 1)
    on_rate = on['rx_queue_full_growth'] / max(on['statuses'], 1)
    if on_rate > off_rate:
        reasons.append('rx_queue_full grew %d with the data path on against %d with it off' % (on['rx_queue_full_growth'], off['rx_queue_full_growth']))
    return ('off (load)' if reasons else 'on'), reasons


def report(result, header):
    lines = ['# G16J spike (a): data-path load on the StickS3, recorded by tools/datapath_spike.py (STATUS over USB).',
             '# The verdict recommends the detect.datapath default; it changes nothing by itself.']
    lines += ['%s=%s' % kv for kv in header.items()]
    for phase in (result['off'], result['on']):
        lines.append(' '.join('%s=%s' % kv for kv in phase.items()))
    lines.append('VERDICT %s%s' % (result['verdict'], (' ' + '; '.join(result['reasons'])) if result['reasons'] else ''))
    return '\n'.join(lines) + '\n'


def run(port, raw_path, out_path, seconds=600.0, interval=1.0, now=time.monotonic, sleep=time.sleep, boot_text=None,
        mac=tw.STICK_MAC, say=print, wall=None):
    identity = tw.check_identity(boot_text, mac) if boot_text is not None else mac
    before = tune_get(port, now)
    with open(raw_path, 'x') as log:
        log.write(json.dumps({'type': 'start', 't': now(), 'mac': identity, 'wall': wall, 'found': before}) + '\n')
        try:
            tune_set(port, 0, now)
            say('data path OFF: recording %d s' % int(seconds))
            off = record(port, log, 'off', seconds, interval, now, sleep)
            tune_set(port, 1, now)
            say('data path ON: recording %d s' % int(seconds))
            on = record(port, log, 'on', seconds, interval, now, sleep)
        finally:
            try:
                tune_set(port, before, now)   # always put the owner's setting back
            except SpikeError as e:
                say('WARNING: could not restore %s=%g: %s' % (KEY, before, e))
        verdict, reasons = judge(off, on)
        result = {'off': off, 'on': on, 'verdict': verdict, 'reasons': reasons, 'restored': before}
        log.write(json.dumps({'type': 'result', **result}) + '\n')
    with open(out_path, 'x') as f:
        f.write(report(result, {'mac': identity, 'wall_start': wall, 'raw': raw_path, 'seconds_per_phase': seconds, 'found_setting': before}))
    say('VERDICT %s' % verdict)
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--port', required=True)
    ap.add_argument('--seconds', type=float, default=600.0, help='per phase (ledger: 10 min off, then 10 min on)')
    ap.add_argument('--interval', type=float, default=1.0)
    ap.add_argument('--raw-dir', help='default: <GUARDIAN_STORE>/evidence-raw')
    ap.add_argument('--evidence-dir', default=str(REPO / 'firmware' / 'evidence'))
    ap.add_argument('--mac', default=tw.STICK_MAC)
    a = ap.parse_args(argv)
    if not a.mac:
        print('datapath_spike: REFUSED: name the stick: --mac or GUARDIAN_LAB_STICK_MAC', file=sys.stderr)
        return 2
    try:
        a.raw_dir = a.raw_dir or live_matrix.default_raw_dir()
        live_matrix.require_store(a.raw_dir)
    except live_matrix.MatrixError as e:
        print(f'datapath_spike: REFUSED: {e}', file=sys.stderr)
        return 2
    stamp = time.strftime('%Y%m%d-%H%M%S')
    raw_path = os.path.join(a.raw_dir, 'spike-a-datapath-%s.jsonl' % stamp)
    out_path = os.path.join(a.evidence_dir, 'sticks3-G16J-spike-a-datapath-%s.log' % stamp[:8])
    import serial                                              # pyserial, only for the live run
    port = serial.Serial(); port.port = a.port; port.baudrate = 115200; port.dtr = False; port.rts = False; port.timeout = 0.05
    port.open()
    boot, end = b'', time.monotonic() + 15
    while time.monotonic() < end and b'GRX1 INFO' not in boot:
        boot += port.read(4096)
    try:
        run(port, raw_path, out_path, a.seconds, a.interval, boot_text=boot.decode('ascii', 'replace'), mac=a.mac,
            wall=time.strftime('%Y-%m-%dT%H:%M:%S%z'))
    except (tw.WatchError, SpikeError) as e:
        print('datapath_spike: REFUSED: %s' % e, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""G16J live matrix: one row of docs/attack-coverage.md proven (or not) on the StickS3.

    tools/live_matrix.py --list
    tools/live_matrix.py --port /dev/cu.usbmodemXXXX --row bruce-deauth [--seconds 60]

The OWNER runs every attack; this tool only LISTENS. It asks the stick for "STATUS" over USB
(read-only, the same recorder as tools/threat_watch.py, MAC-gated to the StickS3) and walks one
row through three phases:

  quiet    10 s    nothing is started; any new incident here voids the row (the air was not quiet)
  attack   60 s    the owner starts the row's attack on the SELECTED network's channel and presses
                   Enter at that moment (the mark); the first incident of an expected detector
                   gives time-to-alert
  benign   60 s    the owner stops the attack, presses Enter, then does the row's benign twin;
                   any new incident here is a false alarm

It writes the raw STATUS stream to the store (evidence-raw/) and the result to
firmware/evidence/sticks3-G16J-<tool>-<attack>-<date>.log, and prints the line to paste into
the docs/attack-coverage.md row. Nothing is transmitted and no setting is changed.

Honest limits. Time-to-alert is measured from the owner's key press to the first STATUS that
shows the incident: it includes the owner's reaction, the tool's own start-up, the frames needed
to reach the threshold and one polling interval (0.25 s by default). It is an UPPER bound on
"alert after the closing frame"; the closing frame's own time needs a second receiver (the Pi or
the Mac capture). A row PASSES when an expected detector fired in the attack phase within
--limit seconds of the mark and the benign phase stayed silent. A slow owner or a tool with a
long start-up can fail the limit without the Guardian being slow: read first_incident_s.
"""
import argparse, json, os, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import threat_watch as tw   # noqa: E402

import guardian_local  # noqa: E402  the artifact store (GUARDIAN_STORE) and its fail-closed check
REPO = Path(__file__).resolve().parents[1]

# key: (tool, attack, detectors any of which proves the row, colour, what the owner starts, the benign twin)
ROWS = {
    'bruce-deauth': ('bruce', 'deauth', ('disconnect',), 'red',
                     'Bruce: WiFi > deauth flood on YOUR network', 'toggle Wi-Fi off/on on a phone joined to your network, twice'),
    'bruce-targeted': ('bruce', 'targeted-deauth', ('disconnect', 'area_disconnect', 'handshake'), 'red',
                       'Bruce: deauth ONE client of your network', 'toggle Wi-Fi off/on on that client, twice'),
    'bruce-beacon-spam': ('bruce', 'beacon-spam', ('beacon_flood', 'rotation'), 'amber',
                          'Bruce: beacon spam (any list) on your channel', 'leave everything idle'),
    'bruce-evil-portal': ('bruce', 'evil-portal-clone', ('baseline', 'rotation'), 'red',
                          'Bruce: evil portal cloning YOUR network name', 'switch a phone hotspot with a DIFFERENT name on, then off'),
    'bruce-karma': ('bruce', 'karma', ('responder',), 'amber',
                    'Bruce: karma, with a phone nearby probing a remembered name', 'toggle Wi-Fi off/on on that phone, twice'),
    'bruce-pwngrid': ('bruce', 'pwngrid', ('marked_beacon',), 'amber',
                      'Bruce: Brucegotchi / pwngrid beacons on your channel', 'leave everything idle'),
    'evilm5-beacon-spam': ('evilm5', 'beacon-spam', ('beacon_flood', 'rotation'), 'amber',
                           'Evil-M5: beacon attack on your channel', 'leave everything idle'),
    'evilm5-probe-flood': ('evilm5', 'probe-flood', ('probe_flood',), 'amber',
                           'Evil-M5: probe attack', 'toggle Wi-Fi off/on on two phones'),
    'evilm5-karma-spear': ('evilm5', 'karma-spear', ('responder',), 'amber',
                           'Evil-M5: Karma Spear (needs /evil/KarmaList.txt) with a phone probing a listed name',
                           'toggle Wi-Fi off/on on that phone, twice'),
    'evilm5-csa': ('evilm5', 'csa', ('channel_switch',), 'red',
                   'Evil-M5: channel-switch attack against YOUR network', 'leave everything idle'),
    'evilm5-sae': ('evilm5', 'sae-flood', ('sae_commit',), 'red',
                   'Evil-M5: SAE flood against YOUR network (the router must run WPA3)', 'join the network once with a WPA3 phone'),
    'evilm5-pwngrid': ('evilm5', 'pwngrid', ('marked_beacon',), 'amber',
                       'Evil-M5: pwngrid spam on your channel', 'leave everything idle'),
    'marauder-ap-clone': ('marauder', 'ap-clone-spam', ('baseline', 'beacon_flood', 'rotation'), 'red',
                          'Marauder: AP clone spam including YOUR network name', 'leave everything idle'),
    'marauder-assoc-sleep': ('marauder', 'assoc-sleep', ('assoc_sleep',), 'red',
                             'Marauder: association sleep attack on YOUR network', 'join the network once with a phone'),
    'marauder-bad-msg': ('marauder', 'bad-msg', ('handshake',), 'red',
                         'Marauder: Bad Msg (forged handshake start) on YOUR network; needs handshake watch: on',
                         'join the network once with a phone'),
    'marauder-csa': ('marauder', 'csa', ('channel_switch',), 'red',
                     'Marauder: channel-switch attack on YOUR network', 'leave everything idle'),
    'marauder-quiet': ('marauder', 'quiet', ('channel_switch',), 'red',
                       'Marauder: Quiet element attack on YOUR network', 'leave everything idle'),
    'marauder-sae': ('marauder', 'sae-flood', ('sae_commit',), 'red',
                     'Marauder: SAE commit flood on YOUR network (the router must run WPA3)', 'join the network once with a WPA3 phone'),
    'pi-disassoc': ('pi', 'disassoc', ('disconnect',), 'red', 'Pi emitter scenario "disassoc" (lab/live)', 'leave everything idle'),
    'pi-targeted-pair': ('pi', 'targeted-pair', ('area_disconnect', 'disconnect'), 'red', 'Pi emitter scenario "pair" (lab/live)', 'leave everything idle'),
    'pi-auth-flood': ('pi', 'auth-flood', ('auth_flood',), 'red', 'Pi emitter scenario "auth-flood" (lab/live)', 'join the network once with a phone'),
    'pi-pmkid-orphan': ('pi', 'pmkid-orphan', ('handshake',), 'red', 'Pi emitter scenario "pmkid-orphan" (lab/live); needs handshake watch: on', 'join the network once with a phone'),
    'pi-fake-m1': ('pi', 'fake-m1', ('handshake',), 'red', 'Pi emitter scenario "fake-m1" (lab/live); needs handshake watch: on', 'join the network once with a phone'),
    'pi-csa-ff': ('pi', 'csa-ff', ('channel_switch',), 'red', 'Pi emitter scenario "csa-ff" (lab/live)', 'leave everything idle'),
    'pi-quiet': ('pi', 'quiet', ('channel_switch',), 'red', 'Pi emitter scenario "quiet" (lab/live)', 'leave everything idle'),
    'pi-hostile-ssid': ('pi', 'hostile-ssid', (), 'none', 'Pi emitter scenario "hostile-ssid" (lab/live): the stick must stay up and silent', 'leave everything idle'),
}


class MatrixError(Exception):
    pass


def detector_counts(status):
    return {name: d.get('incidents', 0) for name, d in status.get('detectors', {}).items() if isinstance(d.get('incidents', 0), int)}


class Phase:
    """One phase's STATUS stream: new incidents per detector and the first time each appeared."""
    def __init__(self, name, started):
        self.name, self.started = name, started
        self.base, self.last = None, None
        self.new, self.first = {}, {}
        self.statuses = self.reboots = 0
        self.heap_min = self.stack_min = self.fps_min = None
        self.queue_first = self.queue_last = None

    def update(self, status, t):
        self.statuses += 1
        counts = detector_counts(status)
        if self.last is not None and isinstance(status.get('uptime_s'), int) and isinstance(self.last.get('uptime_s'), int) \
                and status['uptime_s'] < self.last['uptime_s']:
            self.reboots += 1
            self.base = {k: 0 for k in counts}          # counters restarted with the stick
        if self.base is None:
            self.base = counts
        for name, n in counts.items():
            delta = n - self.base.get(name, 0)
            if delta > self.new.get(name, 0):
                self.new[name] = delta
                self.first.setdefault(name, round(t - self.started, 3))
        for key, attr in (('heap_internal_min', 'heap_min'), ('task_stack_free', 'stack_min')):
            v = status.get(key)
            if isinstance(v, int) and (getattr(self, attr) is None or v < getattr(self, attr)):
                setattr(self, attr, v)
        try:
            fps = float(status.get('fps'))
            self.fps_min = fps if self.fps_min is None else min(self.fps_min, fps)
        except (TypeError, ValueError):
            pass
        q = status.get('rx_queue_full')
        if isinstance(q, int):
            self.queue_first = q if self.queue_first is None else self.queue_first
            self.queue_last = q
        self.last = status

    def record(self):
        return {'phase': self.name, 'statuses': self.statuses, 'reboots': self.reboots, 'new_incidents': dict(self.new),
                'first_incident_s': dict(self.first), 'heap_internal_min': self.heap_min, 'task_stack_free_min': self.stack_min,
                'fps_min': self.fps_min, 'rx_queue_full_first': self.queue_first, 'rx_queue_full_last': self.queue_last}


def verdict(row_key, quiet, attack, benign, limit_s):
    """PASS / FAIL with the reasons, from the three phase records."""
    tool, attack_name, expected, colour, _, _ = ROWS[row_key]
    reasons = []
    if quiet['statuses'] == 0 or attack['statuses'] == 0 or benign['statuses'] == 0:
        reasons.append('a phase recorded no STATUS (stick silent)')
    if quiet['reboots'] or attack['reboots'] or benign['reboots']:
        reasons.append('the stick rebooted during the row')
    if quiet['new_incidents']:
        reasons.append('incident during the quiet phase: the air was not quiet (%s)' % ','.join(sorted(quiet['new_incidents'])))
    hits = {d: attack['first_incident_s'][d] for d in expected if d in attack['first_incident_s']}
    tta = min(hits.values()) if hits else None
    if expected:
        if not hits:
            reasons.append('no expected detector fired in the attack phase (expected one of %s)' % ','.join(expected))
        elif tta > limit_s:
            reasons.append('first incident %.2f s after the mark, limit %.2f s' % (tta, limit_s))
    elif attack['new_incidents']:
        reasons.append('incident on a row that must stay silent (%s)' % ','.join(sorted(attack['new_incidents'])))
    if benign['new_incidents']:
        reasons.append('false incident in the benign phase (%s)' % ','.join(sorted(benign['new_incidents'])))
    return {'row': row_key, 'tool': tool, 'attack': attack_name, 'colour': colour, 'expected': list(expected), 'fired': hits,
            'time_to_alert_from_mark_s': tta, 'limit_s': limit_s, 'pass': not reasons, 'reasons': reasons}


def run_phase(port, log, name, seconds, interval, now=time.monotonic, sleep=time.sleep):
    phase = Phase(name, now())
    log.write(json.dumps({'type': 'phase', 't': phase.started, 'name': name, 'seconds': seconds}) + '\n')
    end = phase.started + seconds
    while now() < end:
        port.write(b'STATUS\n')
        for line in tw._read_lines(port, max(interval, 0.05), now):
            s = tw.parse_status(line)
            if s is None:
                continue
            t = now()
            log.write(json.dumps({'type': 'status', 't': t, 'line': line}) + '\n')
            phase.update(s, t)
        log.flush()
        sleep(0)
    return phase


def evidence_text(result, phases, header):
    lines = ['# G16J live matrix row, recorded by tools/live_matrix.py (read-only STATUS over USB; the owner ran the attack).',
             '# time_to_alert_from_mark_s is an UPPER bound: owner key press -> first STATUS showing the incident.']
    lines += ['%s=%s' % kv for kv in header.items()]
    for p in phases:
        lines.append(json.dumps(p, sort_keys=True))
    lines.append(json.dumps(result, sort_keys=True))
    lines.append('VERDICT %s %s' % ('PASS' if result['pass'] else 'FAIL', '; '.join(result['reasons']) if result['reasons'] else 'ok'))
    return '\n'.join(lines) + '\n'


def doc_line(result, evidence_name):
    if not result['pass']:
        return 'unproven (%s, %s)' % ('; '.join(result['reasons']), evidence_name)
    if result['time_to_alert_from_mark_s'] is None:
        return '**proven** silent, benign twin 0 incidents (`%s`)' % evidence_name
    fired = ', '.join('`%s` %.2f s' % kv for kv in sorted(result['fired'].items()))
    return '**proven** %s after the mark, benign twin 0 incidents (`%s`)' % (fired, evidence_name)


def default_raw_dir():
    """<GUARDIAN_STORE>/evidence-raw (environment or local.conf); a named refusal when no store is set."""
    try:
        return str(guardian_local.store(check=False) / 'evidence-raw')
    except guardian_local.Missing as e:
        raise MatrixError('no --raw-dir and %s' % e)


def require_store(raw_dir):
    """Fail closed: raw evidence inside the configured store only after the store's own check (sentinel,
    mounted share), never into an empty mount point."""
    try:
        root = guardian_local.store(check=False)
    except guardian_local.Missing:
        root = None
    if root is not None and Path(os.path.abspath(raw_dir)).resolve().is_relative_to(root):
        try:
            guardian_local.store()
        except guardian_local.Missing as e:
            raise MatrixError('store check failed (%s); refusing to write raw evidence' % e)
    if not os.path.isdir(raw_dir):
        raise MatrixError('raw evidence folder %s does not exist' % raw_dir)


def run_row(port, row_key, raw_path, evidence_path, seconds=60.0, quiet_seconds=10.0, interval=0.25, limit_s=1.75,
            ask=input, say=print, now=time.monotonic, sleep=time.sleep, boot_text=None, mac=tw.STICK_MAC, wall=None):
    if row_key not in ROWS:
        raise MatrixError('unknown row %s (see --list)' % row_key)
    tool, attack_name, expected, colour, start_text, twin_text = ROWS[row_key]
    identity = tw.check_identity(boot_text, mac) if boot_text is not None else mac
    with open(raw_path, 'x') as log:
        log.write(json.dumps({'type': 'start', 't': now(), 'mac': identity, 'row': row_key, 'wall': wall}) + '\n')
        say('ROW %s: %s. Keep everything idle for %d s.' % (row_key, start_text, int(quiet_seconds)))
        quiet = run_phase(port, log, 'quiet', quiet_seconds, interval, now, sleep)
        ask('START NOW: %s. Press Enter at the moment it starts. ' % start_text)
        attack = run_phase(port, log, 'attack', seconds, interval, now, sleep)
        ask('STOP the attack. Press Enter when it has stopped; then, for %d s: %s. ' % (int(seconds), twin_text))
        benign = run_phase(port, log, 'benign', seconds, interval, now, sleep)
        phases = [quiet.record(), attack.record(), benign.record()]
        result = verdict(row_key, phases[0], phases[1], phases[2], limit_s)
        log.write(json.dumps({'type': 'result', **result}) + '\n')
    last = attack.last or quiet.last or {}
    header = {'row': row_key, 'tool': tool, 'attack': attack_name, 'mac': identity, 'wall_start': wall,
              'app_version': last.get('app_version'), 'selected': last.get('selected'), 'datapath': last.get('datapath'),
              'tune_version': last.get('tune_version'), 'raw': raw_path, 'poll_interval_s': interval,
              'attack_seconds': seconds, 'benign_seconds': seconds}
    with open(evidence_path, 'x') as f:
        f.write(evidence_text(result, phases, header))
    say('VERDICT %s' % ('PASS' if result['pass'] else 'FAIL: ' + '; '.join(result['reasons'])))
    say('docs/attack-coverage.md status cell: ' + doc_line(result, os.path.basename(evidence_path)))
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--list', action='store_true', help='print the rows and what the owner starts for each')
    ap.add_argument('--port')
    ap.add_argument('--row')
    ap.add_argument('--seconds', type=float, default=60.0)
    ap.add_argument('--limit', type=float, default=1.75, help='seconds from the mark to the first incident (1.5 s + one poll)')
    ap.add_argument('--interval', type=float, default=0.25)
    ap.add_argument('--raw-dir', help='default: <GUARDIAN_STORE>/evidence-raw')
    ap.add_argument('--evidence-dir', default=str(REPO / 'firmware' / 'evidence'))
    ap.add_argument('--mac', default=tw.STICK_MAC)
    a = ap.parse_args(argv)
    if a.list:
        for key, (tool, attack, expected, colour, start_text, twin_text) in ROWS.items():
            print('%-22s %-5s expects %-36s start: %s | twin: %s' % (key, colour, ','.join(expected) or '(silence)', start_text, twin_text))
        return 0
    if not a.port or not a.row:
        ap.error('--port and --row are required (or --list)')
    if a.row not in ROWS:
        print('live_matrix: unknown row %s (see --list)' % a.row, file=sys.stderr)
        return 2
    if not a.mac:
        print('live_matrix: REFUSED: name the stick: --mac or GUARDIAN_LAB_STICK_MAC', file=sys.stderr)
        return 2
    try:
        a.raw_dir = a.raw_dir or default_raw_dir()
        require_store(a.raw_dir)
    except MatrixError as e:
        print('live_matrix: REFUSED: %s' % e, file=sys.stderr)
        return 2
    stamp = time.strftime('%Y%m%d-%H%M%S')
    tool, attack = ROWS[a.row][0], ROWS[a.row][1]
    raw_path = os.path.join(a.raw_dir, 'matrix-%s-%s-%s.jsonl' % (tool, attack, stamp))
    evidence_path = os.path.join(a.evidence_dir, 'sticks3-G16J-%s-%s-%s.log' % (tool, attack, stamp[:8]))
    if os.path.exists(evidence_path):
        evidence_path = evidence_path[:-4] + '-' + stamp[9:] + '.log'
    import serial                                              # pyserial, only for the live run
    port = serial.Serial(); port.port = a.port; port.baudrate = 115200; port.dtr = False; port.rts = False; port.timeout = 0.05
    port.open()
    boot, end = b'', time.monotonic() + 15
    while time.monotonic() < end and b'GRX1 INFO' not in boot:
        boot += port.read(4096)
    try:
        result = run_row(port, a.row, raw_path, evidence_path, a.seconds, 10.0, a.interval, a.limit,
                         boot_text=boot.decode('ascii', 'replace'), mac=a.mac, wall=time.strftime('%Y-%m-%dT%H:%M:%S%z'))
    except (tw.WatchError, MatrixError) as e:
        print('live_matrix: REFUSED: %s' % e, file=sys.stderr)
        return 2
    return 0 if result['pass'] else 1


if __name__ == '__main__':
    sys.exit(main())

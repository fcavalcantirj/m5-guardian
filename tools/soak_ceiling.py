#!/usr/bin/env python3
"""G16J spike (c): the benign ceiling per detector, read from a threat_watch soak file.

    tools/soak_ceiling.py <soak.jsonl> [--out <report.log>]

Read-only: it opens the JSON-lines file tools/threat_watch.py wrote (one STATUS per second from
the StickS3) and prints, per detector, the largest in_window count ever sampled, the counted
events, the busiest minute and the incidents; plus the air meter maxima, the worst heap, the
receive-queue drops, the slowest fps and the reboots. Nothing is sent to any device.

Honest limits: in_window is each detector's MAIN window counter (probe_flood: probe requests in
its window, not distinct addresses; responder: answers; rotation: named beacons), sampled once
per STATUS, so a peak shorter than the polling interval can be missed (the windows are 5 s or
longer, the poll 1 s). A soak says what was normal in THIS home on THIS channel on that night;
it is a floor for thresholds, never a proof that a threshold is safe elsewhere.
"""
import argparse, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from threat_watch import parse_status   # noqa: E402  (the same STATUS parser the recorder uses)


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def analyse(stream):
    """Reduce a threat_watch JSON-lines stream to the ceiling record (see module text)."""
    r = {'statuses': 0, 'skipped': 0, 'reboots': 0, 'duration_s': 0, 'detectors': {}, 'heap_internal_min': None,
         'task_stack_free_min': None, 'rx_queue_full': {'first': None, 'last': None, 'max': 0}, 'fps_min': None,
         'air_max': {'probes': 0, 'beacons': 0, 'tx': 0}, 'incidents_total': 0, 'wall': None}
    first_t = last_t = None
    prev = None
    base = {}        # counters carried over a reboot: name -> [events, incidents]
    minute = {}      # name -> (t, events) at the start of the current one-minute bucket
    for raw in stream:
        try:
            rec = json.loads(raw)
        except ValueError:
            r['skipped'] += 1
            continue
        if rec.get('type') == 'start':
            r['wall'] = rec.get('wall')
        if rec.get('type') != 'status':
            continue
        s = parse_status(rec.get('line', ''))
        if s is None:
            r['skipped'] += 1
            continue
        t = rec.get('t', 0.0)
        r['statuses'] += 1
        first_t = t if first_t is None else first_t
        last_t = t
        rebooted = prev is not None and isinstance(s.get('uptime_s'), int) and isinstance(prev.get('uptime_s'), int) \
            and s['uptime_s'] < prev['uptime_s']
        if rebooted:
            r['reboots'] += 1
            for name, d in prev.get('detectors', {}).items():
                b = base.setdefault(name, [0, 0])
                b[0] += d.get('events', 0); b[1] += d.get('incidents', 0)
            minute = {}
        for key, out in (('heap_internal_min', 'heap_internal_min'), ('task_stack_free', 'task_stack_free_min')):
            v = s.get(key)
            if isinstance(v, int) and (r[out] is None or v < r[out]):
                r[out] = v
        q = s.get('rx_queue_full')
        if isinstance(q, int):
            if r['rx_queue_full']['first'] is None:
                r['rx_queue_full']['first'] = q
            r['rx_queue_full']['last'] = q
            r['rx_queue_full']['max'] = max(r['rx_queue_full']['max'], q)
        fps = _f(s.get('fps'))
        if fps is not None and (r['fps_min'] is None or fps < r['fps_min']):
            r['fps_min'] = fps
        for k in r['air_max']:
            v = s.get('air', {}).get(k) if isinstance(s.get('air'), dict) else None
            if isinstance(v, int):
                r['air_max'][k] = max(r['air_max'][k], v)
        for name, d in s.get('detectors', {}).items():
            e = r['detectors'].setdefault(name, {'in_window_max': 0, 'events': 0, 'incidents': 0, 'events_per_min_max': 0.0,
                                                 'unconfigured': False})
            b = base.get(name, [0, 0])
            e['in_window_max'] = max(e['in_window_max'], d.get('in_window', 0))
            e['events'] = b[0] + d.get('events', 0)
            e['incidents'] = b[1] + d.get('incidents', 0)
            e['unconfigured'] = bool(d.get('unconfigured'))
            start = minute.get(name)
            if start is None:
                minute[name] = (t, d.get('events', 0))
            elif t - start[0] >= 60.0:
                rate = (d.get('events', 0) - start[1]) * 60.0 / (t - start[0])
                e['events_per_min_max'] = max(e['events_per_min_max'], rate)
                minute[name] = (t, d.get('events', 0))
        prev = s
    if first_t is not None:
        r['duration_s'] = int(round(last_t - first_t))
    if r['rx_queue_full']['first'] is None:
        r['rx_queue_full'] = {'first': 0, 'last': 0, 'max': 0}
    r['incidents_total'] = sum(d['incidents'] for d in r['detectors'].values())
    return r


def report(r, source):
    lines = [f'G16J spike (c) benign ceiling: source={source}',
             f'wall_start={r["wall"]} statuses={r["statuses"]} skipped={r["skipped"]} duration_s={r["duration_s"]} reboots={r["reboots"]}',
             f'heap_internal_min={r["heap_internal_min"]} task_stack_free_min={r["task_stack_free_min"]} fps_min={r["fps_min"]} '
             f'rx_queue_full_first={r["rx_queue_full"]["first"]} rx_queue_full_last={r["rx_queue_full"]["last"]} rx_queue_full_max={r["rx_queue_full"]["max"]}',
             f'air_max probes_per_min={r["air_max"]["probes"]} beacons_per_min={r["air_max"]["beacons"]} transmitters={r["air_max"]["tx"]}',
             'detector in_window_max events events_per_min_max incidents']
    for name, d in r['detectors'].items():
        lines.append(f'  {name} in_window_max={d["in_window_max"]} events={d["events"]} events_per_min_max={d["events_per_min_max"]:.1f} '
                     f'incidents={d["incidents"]}{" unconfigured" if d["unconfigured"] else ""}')
    lines.append(f'incidents_total={r["incidents_total"]}')
    return '\n'.join(lines) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('soak')
    ap.add_argument('--out', help='also write the report here (created; refused if it exists)')
    a = ap.parse_args(argv)
    with open(a.soak) as f:
        text = report(analyse(f), a.soak)
    if a.out:
        with open(a.out, 'x') as f:
            f.write(text)
    sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())

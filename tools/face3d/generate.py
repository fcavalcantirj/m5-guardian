#!/usr/bin/env python3
"""Guardian 3D head candidates from Meshy, behind a credit cap and a spend log (G21-3d).

  generate.py plan   --batch BATCH.json                       no spend: candidates, estimates, total
  generate.py submit --batch BATCH.json --cap CREDITS [--stamp S] [--store DIR]
  generate.py status --dir RUN_DIR                            free: task state, real credits, thumbnails

A batch file lists candidates; each one is one Meshy task:
  {"candidates": [
    {"id": "i1", "kind": "image-to-3d", "master": "Medium", "should_texture": false},
    {"id": "i2", "kind": "image-to-3d", "master": "Medium", "should_texture": true, "texture_prompt": "..."},
    {"id": "t1", "kind": "text-to-3d-preview", "prompt": "..."},
    {"id": "t1r", "kind": "text-to-3d-refine", "preview_task_id": "<id>", "texture_prompt": "..."}]}
Optional per candidate: "options" (extra meshy flags, e.g. {"--geometry-resolution": "2k"}) and
"estimate_credits" (required when the built-in table cannot price the request).

Rules: the whole batch is priced before anything is sent and refused above --cap or the balance;
masters are checked against the v2 manifest sha256; every task gets --operation-id
guardian-face3d-<stamp>-<id>, an intent line is appended to spend.jsonl BEFORE the call and its
outcome after; a run directory that already has a spend log is never submitted again; the batch stops
at the first failed or uncertain submission. The API key never passes through this script.
Run output lives in the artifact store: <GUARDIAN_STORE>/art-exports/G21-3d/<stamp>/.
"""
import argparse, datetime as dt, hashlib, json, os, shutil, subprocess, sys, urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tools'))
import guardian_local  # noqa: E402  GUARDIAN_STORE / GUARDIAN_STORE_MOUNT (lab/local.conf.example)
SENTINEL = '.guardian-store-root'
MASTERS = 'art-exports/G15/20261117-v4/masters_png'   # the set pinned by firmware/art/persona/v2/manifest.json "sources"
MANIFEST = REPO / 'firmware/art/persona/v2/manifest.json'
RUNS = 'art-exports/G21-3d'
HERMES_MESHY = Path.home() / '.hermes/node/bin/meshy'

# Credits per task. MEASURED: image-to-3d standard + texture = 30 (task 01a1eb75, consumed_credits).
# From `meshy make --dry-run` (CLI estimate): text-to-3d preview 20, refine 10, image-to-3d textured 30.
# image-to-3d untextured 20 is INFERRED from Meshy's price list; status records the real charge.
# retexture 10 is INFERRED from Meshy's price list (the CLI gives no estimate for it); status records the real charge.
PRICES = {('image-to-3d', True): 30, ('image-to-3d', False): 20,
          ('text-to-3d-preview', None): 20, ('text-to-3d-refine', None): 10, ('retexture', None): 10}
# Flags whose cost the table does not know: the candidate must carry estimate_credits.
UNPRICED = {'--geometry-resolution', '--ultra-mode', '--model-type', '--ai-model', '--texture-resolution'}


class Refused(SystemExit):
    def __init__(self, why):
        super().__init__(f'REFUSED: {why}')


def meshy_bin():
    found = shutil.which('meshy')
    return found or str(HERMES_MESHY)


def meshy(*args):
    """Run the CLI with the stable v1 envelope; returns (exit code, parsed JSON or None, stderr)."""
    r = subprocess.run([meshy_bin(), *args, '--output-schema', 'v1', '--format', 'json', '--no-update-check'],
                       capture_output=True, text=True)
    try:
        body = json.loads(r.stdout) if r.stdout.strip() else None
    except json.JSONDecodeError:
        body = None
    return r.returncode, body, r.stderr


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def check_store(store):
    if store is None:
        try:
            return guardian_local.store()
        except guardian_local.Missing as e:
            raise Refused(f'{e}; nothing written')
    store = Path(store)
    if not (store / SENTINEL).is_file():
        raise Refused(f'{store}/{SENTINEL} is missing (share offline or wrong store); nothing written')
    return store


def load_batch(path):
    batch = json.loads(Path(path).read_text())
    cands = batch.get('candidates') or []
    if not cands:
        raise Refused('batch has no candidates')
    ids = [c.get('id') for c in cands]
    if any(not i or not str(i).replace('-', '').replace('_', '').isalnum() for i in ids) or len(set(ids)) != len(ids):
        raise Refused(f'candidate ids must be unique and alphanumeric: {ids}')
    return cands


def estimate(c):
    if 'estimate_credits' in c:
        return int(c['estimate_credits'])
    kind = c.get('kind')
    unpriced = sorted(UNPRICED & set(c.get('options') or {}))
    if unpriced:
        raise Refused(f'candidate {c["id"]}: {unpriced} changes the price; add "estimate_credits"')
    key = (kind, bool(c.get('should_texture'))) if kind == 'image-to-3d' else (kind, None)
    if key not in PRICES:
        raise Refused(f'candidate {c["id"]}: unknown kind {kind!r}')
    return PRICES[key]


def master_image(c, store):
    """The v2 master by name, verified against the manifest; or an explicit image with its sha256."""
    if 'master' in c:
        name = f'{c["master"]}.png'
        man = json.loads(MANIFEST.read_text())   # the v2 manifest pins the masters under "sources"
        want = man.get('sources', {}).get(f'masters_png/{name}') or man.get('files', {}).get(f'masters_png/{name}')
        if not want:
            raise Refused(f'candidate {c["id"]}: master {name} is not in {MANIFEST.name}')
        path = Path(store) / MASTERS / name
    else:
        path, want = Path(c.get('image', '')), c.get('image_sha256')
        if not want:
            raise Refused(f'candidate {c["id"]}: an explicit "image" needs "image_sha256"')
    if not path.is_file():
        raise Refused(f'candidate {c["id"]}: {path} not found')
    got = sha256(path)
    if got != want:
        raise Refused(f'candidate {c["id"]}: {path.name} sha256 {got[:12]} != expected {want[:12]}')
    return path, got


def command(c, op_id, image=None):
    kind = c['kind']
    if kind == 'image-to-3d':
        args = ['image-to-3d', 'create', '--image-url', str(image),
                '--should-texture', 'true' if c.get('should_texture') else 'false']
        if c.get('texture_prompt'):
            args += ['--texture-prompt', c['texture_prompt']]
    elif kind == 'text-to-3d-preview':
        if not c.get('prompt'):
            raise Refused(f'candidate {c["id"]}: text-to-3d-preview needs "prompt"')
        args = ['text-to-3d', 'create', '--mode', 'preview', '--prompt', c['prompt']]
    elif kind == 'retexture':
        if not c.get('input_task_id'):
            raise Refused(f'candidate {c["id"]}: retexture needs "input_task_id"')
        if not image and not c.get('text_style_prompt'):
            raise Refused(f'candidate {c["id"]}: retexture needs a "master" (style image) or "text_style_prompt"')
        args = ['retexture', 'create', '--input-task-id', c['input_task_id'],
                '--enable-original-uv', 'true' if c.get('original_uv', True) else 'false']
        args += ['--image-style-url', str(image)] if image else ['--text-style-prompt', c['text_style_prompt']]
    elif kind == 'text-to-3d-refine':
        if not c.get('preview_task_id'):
            raise Refused(f'candidate {c["id"]}: text-to-3d-refine needs "preview_task_id"')
        args = ['text-to-3d', 'create', '--mode', 'refine', '--preview-task-id', c['preview_task_id']]
        if c.get('texture_prompt'):
            args += ['--texture-prompt', c['texture_prompt']]
    else:
        raise Refused(f'candidate {c["id"]}: unknown kind {kind!r}')
    for k, v in (c.get('options') or {}).items():
        if not str(k).startswith('--') or k in ('--api-key', '--api-key-file', '--async', '--operation-id'):
            raise Refused(f'candidate {c["id"]}: option {k} is not allowed')
        args += [k, str(v)]
    return args + ['--target-formats', 'glb', '--async', '--operation-id', op_id]


def resource(kind):
    return kind if kind in ('image-to-3d', 'retexture') else 'text-to-3d'


def cmd_plan(a):
    cands = load_batch(a.batch)
    total = 0
    for c in cands:
        e = estimate(c)
        total += e
        what = c.get('master') or c.get('prompt', '')[:60] or c.get('preview_task_id', '') or c.get('input_task_id', '')
        if c['kind'] == 'retexture': what = f'{c.get("input_task_id")} style={c.get("master") or "text"}'
        print(f'{c["id"]:<8} {c["kind"]:<20} texture={bool(c.get("should_texture")) if c["kind"] == "image-to-3d" else "-"!s:<5} '
              f'{e:>4} credits  {what}')
    print(f'TOTAL {total} credits (estimate; nothing sent)')
    return total


def append(log, rec):
    with open(log, 'a') as f:
        f.write(json.dumps(rec, ensure_ascii=False) + '\n')


def cmd_submit(a):
    cands = load_batch(a.batch)
    store = check_store(a.store)
    total = sum(estimate(c) for c in cands)
    if total > a.cap:
        raise Refused(f'batch estimate {total} credits is above the cap {a.cap}; nothing sent')
    images = {c['id']: master_image(c, store) for c in cands if c['kind'] == 'image-to-3d' or (c['kind'] == 'retexture' and 'master' in c)}
    stamp = a.stamp or dt.datetime.now().strftime('%Y%m%d-%H%M%S')
    run = store / RUNS / stamp
    log = run / 'spend.jsonl'
    if log.exists():
        raise Refused(f'{log} exists: this batch was already submitted; never re-submitted. Use a new --stamp')
    rc, body, err = meshy('balance')
    balance = ((body or {}).get('result') or body or {}).get('balance')
    if rc != 0 or not isinstance(balance, int):
        raise Refused(f'could not read the Meshy balance (exit {rc}): {err.strip()[:200]}')
    if balance < total:
        raise Refused(f'balance {balance} < batch estimate {total}; nothing sent')
    run.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(a.batch, run / 'batch.json')
    append(log, {'ts': now(), 'event': 'batch', 'stamp': stamp, 'cap': a.cap, 'estimate_total': total,
                 'balance_before': balance, 'candidates': [c['id'] for c in cands]})
    for c in cands:
        op = f'guardian-face3d-{stamp}-{c["id"]}'
        image, image_sha = images.get(c['id'], (None, None))
        args = command(c, op, image)
        base = {'candidate': c['id'], 'operation_id': op, 'kind': c['kind'], 'resource': resource(c['kind']),
                'estimate_credits': estimate(c)}
        append(log, {'ts': now(), 'event': 'intent', **base, 'args': args[2:],
                     **({'image': str(image), 'image_sha256': image_sha} if image else {})})
        rc, body, err = meshy(*args)
        res = (body or {}).get('result') or {}
        sub = res.get('submission') or {}
        task_id = sub.get('task_id') or res.get('task_id')
        state = sub.get('state') or ('accepted' if rc == 0 and task_id else 'unknown')
        replayed = any(w.get('code') == 'operation_replayed' for w in (body or {}).get('warnings') or [])
        append(log, {'ts': now(), 'event': 'submitted' if rc == 0 and task_id else 'failed', **base,
                     'task_id': task_id, 'state': state, 'exit': rc, 'replayed': replayed,
                     **({'error': ((body or {}).get('error') or {}).get('message') or err.strip()[:300]} if rc else {})})
        if rc != 0 or not task_id:
            print(f'{c["id"]}: FAILED ({state}, exit {rc}); batch stopped, later candidates not sent. Log: {log}')
            return 2
        if replayed:
            print(f'{c["id"]}: operation {op} was already accepted earlier; no new request was sent')
        print(f'{c["id"]:<8} {c["kind"]:<20} task {task_id}  est {base["estimate_credits"]} credits')
    print(f'submitted {len(cands)} tasks, estimate {total} credits. Run: {run}\nnext: generate.py status --dir {run}')
    return 0


def submitted_tasks(log):
    out = {}
    for line in Path(log).read_text().splitlines():
        r = json.loads(line)
        if r.get('event') == 'submitted':
            out[r['candidate']] = r
    return out


def cmd_status(a):
    run = Path(a.dir)
    log = run / 'spend.jsonl'
    if not log.is_file():
        raise Refused(f'{log} not found')
    tasks = submitted_tasks(log)
    rows, spent, done = [], 0, True
    for cid, r in tasks.items():
        rc, body, err = meshy(r['resource'], 'get', r['task_id'], '--include-raw')
        task = ((body or {}).get('result') or {}).get('task') or {}
        raw = task.get('raw') or {}
        status, credits = task.get('status') or f'unknown(exit {rc})', task.get('consumed_credits')
        done &= status in ('SUCCEEDED', 'FAILED', 'CANCELED', 'EXPIRED')
        spent += credits or 0
        (run / f'{cid}.task.json').write_text(json.dumps(raw or task, indent=1) + '\n')
        thumb = ''
        if status == 'SUCCEEDED' and raw.get('thumbnail_url'):
            dest = run / f'{cid}.thumb.png'
            if not dest.exists():
                with urllib.request.urlopen(raw['thumbnail_url'], timeout=60) as src:
                    dest.write_bytes(src.read())
            thumb = str(dest)
        append(log, {'ts': now(), 'event': 'status', 'candidate': cid, 'task_id': r['task_id'], 'status': status,
                     'consumed_credits': credits, 'expires_at': raw.get('expires_at') or task.get('expires_at')})
        rows.append((cid, r['kind'], r['task_id'], status, credits, thumb))
    print(f'{"cand":<8} {"kind":<20} {"task id":<38} {"status":<12} {"credits":>7}  thumbnail')
    for cid, kind, tid, status, credits, thumb in rows:
        print(f'{cid:<8} {kind:<20} {tid:<38} {status:<12} {credits if credits is not None else "?":>7}  {thumb}')
    print(f'MEASURED credits consumed so far: {spent}' + ('' if done else ' (some tasks still running)'))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sp = p.add_subparsers(dest='cmd', required=True)
    s = sp.add_parser('plan'); s.add_argument('--batch', required=True)
    s = sp.add_parser('submit'); s.add_argument('--batch', required=True)
    s.add_argument('--cap', type=int, required=True, help='credit cap for this batch (set by Felipe)')
    s.add_argument('--stamp'); s.add_argument('--store', help='default: GUARDIAN_STORE (environment or local.conf)')
    s = sp.add_parser('status'); s.add_argument('--dir', required=True)
    a = p.parse_args(argv)
    if a.cmd == 'plan':
        cmd_plan(a); return 0
    return {'submit': cmd_submit, 'status': cmd_status}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())

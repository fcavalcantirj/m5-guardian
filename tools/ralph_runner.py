#!/usr/bin/env python3
"""One Guardian ledger task per agent session. Acceptance belongs to the reviewer."""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from string import Template
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guardian_local  # noqa: E402  owner-local settings (lab/local.conf.example)

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / 'guardian-tasks.json'
# Tasks that run back to back, each handed off for later supervisor review (owner, 2026-11-17:
# "remove the Ralph gate; you can validate all tomorrow"). A changed earlier task still
# invalidates every later handoff (input tokens), so a fix upstream re-runs the chain.
HOST_BATCH = frozenset(('G04', 'G05', 'G06', 'G07', 'G08', 'G16D', 'G16E', 'G16F', 'G16G', 'G16H', 'G16I', 'G16J', 'G21', 'G16M', 'G16N', 'G16O', 'G16P', 'G16R', 'G16S', 'G16T', 'G16Q', 'G22', 'G22A', 'G23'))
FOUNDATION = ('G01', 'G02', 'G03')

def data_root(env=None, check=False):
    """RALPH_DATA_ROOT, else <GUARDIAN_STORE>/ralph (local.conf); check = the store's fail-closed check."""
    env = os.environ if env is None else env
    if env.get('RALPH_DATA_ROOT'):
        return Path(env['RALPH_DATA_ROOT']).expanduser().resolve()
    return guardian_local.store(env=env, check=check) / 'ralph'

def forbidden_profile(env=None):
    """True when CLAUDE_CONFIG_DIR contains the owner's GUARDIAN_FORBIDDEN_CLAUDE_CONFIG pattern."""
    env = os.environ if env is None else env
    pattern = guardian_local.get('GUARDIAN_FORBIDDEN_CLAUDE_CONFIG', env=env)
    return bool(pattern) and pattern.lower() in env.get('CLAUDE_CONFIG_DIR', '').lower()

def say(text):
    print(text, flush=True)

def read_ledger():
    tasks = json.loads(LEDGER.read_text())
    if not isinstance(tasks, list):
        raise ValueError('guardian-tasks.json must be an array')
    ids = set()
    for n, task in enumerate(tasks, 1):
        if not isinstance(task, dict) or type(task.get('passes')) is not bool:
            raise ValueError(f'Task {n} needs a boolean passes field')
        if not isinstance(task.get('description'), str) or not isinstance(task.get('steps'), list):
            raise ValueError(f'Task {n} needs a description and steps')
        task_id = task.get('id')
        if not isinstance(task_id, str) or not task_id or task_id in ids:
            raise ValueError(f'Task {n} needs a unique stable id')
        deps = task.get('depends_on')
        if not isinstance(deps, list) or any(d not in ids for d in deps):
            raise ValueError(f'Task {task_id} dependencies must name earlier ledger entries')
        ids.add(task_id)
    return tasks

def key(task):
    content = {k: v for k, v in task.items() if k != 'passes'}
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()

def save(path, value):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.replace(path)

def journal(data, text):
    with (data / 'progress.txt').open('a') as stream:
        stream.write(f'{dt.datetime.now().isoformat(timespec="seconds")} {text}\n')

def read_work(data):
    path = data / 'handoffs.json'
    work = json.loads(path.read_text()) if path.is_file() else {}
    if not isinstance(work, dict) or any(not isinstance(v, dict) for v in work.values()):
        raise ValueError('Invalid implementation receipts; inspect handoffs.json')
    return work

def read_state(data):
    path = data / 'state.json'
    state = json.loads(path.read_text()) if path.is_file() else None
    if state is not None and not isinstance(state, dict):
        raise ValueError('Invalid last-run receipt')
    return state

def input_tokens(task, tasks, work):
    by_id = {t['id']: t for t in tasks}
    return {dep: {'key': key(by_id[dep]), 'attempt': work.get(dep, {}).get('attempt')}
            for dep in task['depends_on']}

def ready(task, tasks, work):
    """Implementation handoff only. Never independent validation/acceptance."""
    if task['passes']:
        return True
    if task['id'] not in HOST_BATCH:
        return False
    record = work.get(task['id'], {})
    if (record.get('key') != key(task) or record.get('status') != 'awaiting_review'
            or not record.get('attempt') or record.get('inputs') != input_tokens(task, tasks, work)):
        return False
    by_id = {t['id']: t for t in tasks}
    return all(ready(by_id[dep], tasks, work) for dep in task['depends_on'])

def select_next(tasks, work):
    for i, task in enumerate(tasks):
        if task['passes'] or ready(task, tasks, work):
            continue
        earlier = [t['id'] for t in tasks[:i] if not t['passes']]
        if task['id'] not in HOST_BATCH and earlier:
            return None, 'Batch implementation handed off; review needed: ' + ', '.join(earlier)
        by_id = {t['id']: t for t in tasks}
        required = list(task['depends_on'])
        if task['id'] in HOST_BATCH:
            missing = [dep for dep in FOUNDATION if dep not in by_id or not by_id[dep]['passes']]
            if missing:
                return None, 'Foundation acceptance required: ' + ', '.join(missing)
        missing = [dep for dep in required if not (ready(by_id[dep], tasks, work)
                   if task['id'] in HOST_BATCH else by_id[dep]['passes'])]
        if missing:
            return None, 'Dependency acceptance/handoff required: ' + ', '.join(missing)
        return (i, task), None
    pending = [t['id'] for t in tasks if not t['passes']]
    return None, ('Batch implementation handed off; review needed: ' + ', '.join(pending)
                  if pending else 'All ledger tasks accepted by reviewer.')

def select_retry(tasks, work, state):
    # A retry is deliberate, not evidence of successful implementation.
    failed_index = state.get('task', 0) - 1 if state else -1
    if (state and state.get('status') != 'awaiting_review' and
            0 <= failed_index < len(tasks) and not tasks[failed_index]['passes']):
        pending = (failed_index, tasks[failed_index])
    else:
        pending = next(((i,t) for i,t in enumerate(tasks) if not t['passes']), None)
    if pending:
        i, task = pending
        if any(not ready(x, tasks, work) for x in tasks[:i]):
            raise ValueError('Earlier task must be implemented/reviewed before this retry')
        if task['id'] not in HOST_BATCH and any(not x['passes'] for x in tasks[:i]):
            raise ValueError('Review the preceding batch before retrying a later phase')
        by_id = {x['id']: x for x in tasks}
        if task['id'] in HOST_BATCH and any(dep not in by_id or not by_id[dep]['passes'] for dep in FOUNDATION):
            raise ValueError('Foundation acceptance is required before the host batch')
    return pending, None

def last_record(index, task, work, state):
    if task['id'] in work:
        return work[task['id']]
    if state and state.get('task') == index + 1 and state.get('task_id', task['id']) == task['id']:
        return state
    return None

def final_marker(path):
    # This is the worker's completion signal, not a test or acceptance verdict.
    last = ''
    if path.is_file():
        with path.open(errors='replace') as stream:
            for line in stream:
                if line.strip():
                    last = line.strip()
    return last if last in ('READY FOR REVIEW', 'BLOCKED') else None

def report_pending(tasks, work):
    ids = [t['id'] for t in tasks if not t['passes'] and ready(t, tasks, work)]
    if ids:
        say('Implementation handed off, NOT independently accepted: ' + ', '.join(ids))


def command(engine, data):
    if engine == 'claude':
        if forbidden_profile():
            raise ValueError('Use normal claude, not the profile named by GUARDIAN_FORBIDDEN_CLAUDE_CONFIG')
        return ['claude', '-p', '--model', os.environ.get('CLAUDE_MODEL', 'claude-fable-5-1'),
                '--effort', os.environ.get('CLAUDE_EFFORT', 'high'),
                '--no-session-persistence', '--add-dir', str(data)]
    args = ['codex', 'exec', '--sandbox', 'workspace-write', '--ephemeral',
            '-C', str(ROOT), '--add-dir', str(data)]
    if os.environ.get('CODEX_MODEL'):
        args += ['-m', os.environ['CODEX_MODEL']]
    if os.environ.get('CODEX_EFFORT'):
        args += ['-c', 'model_reasoning_effort=' + json.dumps(os.environ['CODEX_EFFORT'])]
    return args + ['-']

def prompt_for(index, task, data, run):
    template_path = ROOT / 'tools/prompts/guardian-worker.md'
    task_id = task.get('id', str(index + 1))
    if task_id == 'G02':
        task_brief = (
            'G02 is a source, architecture and license review. Read the existing research '
            'and relevant open-source components; pin revisions and compare their defensive '
            'parsing/detection APIs, memory bounds, native C++ compatibility and licenses. '
            'Produce a source-linked reuse decision table and adapter plan. Downloads of '
            'source code belong in the store. This task does not implement or run radio tests, '
            'operate Bruce, recover passwords, collect credentials, or contact any access '
            'point. Do not edit firmware to satisfy a later task. Distinguish source findings '
            'from experiments that have actually run.'
        )
    else:
        task_brief = (
            'Implement only the selected ledger entry below. Its listed dependencies '
            'are context, and later roadmap entries are not instructions to execute now. '
            'Preserve explicit lab-scope and reviewer-acceptance requirements.'
        )
    return Template(template_path.read_text()).substitute(
        project_root=str(ROOT), task_number=index + 1, task_id=task_id,
        task_brief=task_brief, selected_task=json.dumps(task, indent=2),
        journal_path=str(data / 'progress.txt'), run_path=str(run),
        GUARDIAN_STORE=str(worker_store(data)),
    )

def worker_store(data):
    """The store the worker is told about: the configured one; with RALPH_DATA_ROOT and no store
    configured, the folder beside the queue."""
    try:
        return guardian_local.store(check=False)
    except guardian_local.Missing:
        return data.parent

def worker_env(data):
    """The worker's environment: ours plus GUARDIAN_STORE, because ledger rows and docs write
    $GUARDIAN_STORE/... and an unset variable in the worker's shell would expand to nothing."""
    return dict(os.environ, GUARDIAN_STORE=str(worker_store(data)))

def run_task(engine, index, task, data, tasks, work):
    run = data / (dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f') + f'-task-{index+1}')
    run.mkdir()
    before = LEDGER.read_bytes()
    (run / 'ledger-before.json').write_bytes(before)
    prompt = prompt_for(index, task, data, run)
    (run / 'prompt.txt').write_text(prompt)
    args = command(engine, data)
    state = dict(task=index+1, task_id=task['id'], key=key(task), engine=engine,
                 status='running', log=str(run/'engine.log'), attempt=run.name,
                 inputs=input_tokens(task, tasks, work))
    work[task['id']] = dict(state)
    save(data/'handoffs.json', work)
    save(data/'state.json', state)
    save(run/'command.json', args)
    journal(data, f'START task {index+1}: {task["description"]} [{engine}]')
    say(f'\nTask {index+1} · {task["description"]}\nEngine: {engine}\nLog: {run / "engine.log"}\n')
    process = None
    code = 1
    try:
        with (run/'engine.log').open('w') as log, (run/'prompt.txt').open() as source:
            process = subprocess.Popen(args, stdin=source, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, errors='replace', cwd=ROOT,
                                       env=worker_env(data), start_new_session=True)
            for line in process.stdout:
                print(line, end='', flush=True)
                log.write(line)
                log.flush()
            code = process.wait()
    except KeyboardInterrupt:
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        code = 130
    except OSError as error:
        say(str(error))
        journal(data, f'ERROR task {index+1}: {error}')
    # This checks ledger ownership only; it does not validate the implementation.
    if not LEDGER.exists() or LEDGER.read_bytes() != before:
        state['status'] = 'ledger_changed'
        code = code or 2
        say('Ledger changed during the worker run. Stopping for reviewer inspection; no automatic restore.')
    else:
        marker = final_marker(run / 'engine.log')
        if code == 0 and marker != 'READY FOR REVIEW':
            state['status'] = 'blocked' if marker == 'BLOCKED' else 'incomplete_handoff'
            code = 3
            say('No completed handoff. Stopping; inspect the log before --retry.')
        else:
            state['status'] = 'awaiting_review' if code == 0 else 'interrupted' if code == 130 else 'error'
    state['exit_code'] = code
    work[task['id']] = dict(state)
    save(data/'handoffs.json', work)
    save(data/'state.json', state)
    save(run/'result.json', state)
    journal(data, f'{state["status"].upper()} task {index+1}; exit={code}; log={state["log"]}')
    say(f'\n{state["status"]} · task {index+1}. Ledger passes remains reviewer-owned.')
    return code

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('iterations', nargs='?', type=int, default=1,
                        help='Maximum fresh worker sessions, including in continuous mode (default 1)')
    parser.add_argument('--engine', choices=('claude','codex'), default=os.environ.get('ENGINE','claude'))
    parser.add_argument('--continuous', action='store_true', help='Wait at review boundaries within the session limit')
    parser.add_argument('--interval', type=float, default=10, help='Seconds between review checks')
    parser.add_argument('--retry', action='store_true', help='Explicitly retry failed work, or rework the earliest unaccepted task')
    parser.add_argument('--status', action='store_true', help='Show acceptance, implementation handoffs and last receipt')
    parser.add_argument('--dry-run', action='store_true', help='Show next implementation or review boundary without an agent')
    args = parser.parse_args()
    if args.iterations < 1 or not 0 < args.interval < float('inf'):
        parser.error('iterations and interval must be finite positive values')
    data = data_root()
    tasks = read_ledger()
    work, state = read_work(data), read_state(data)
    if args.status or args.dry_run:
        say(f'Ledger: {LEDGER}\nIndependently accepted: {sum(t["passes"] for t in tasks)}/{len(tasks)}')
        report_pending(tasks, work)
        pending, reason = select_retry(tasks, work, state) if args.retry else select_next(tasks, work)
        if pending:
            i, task = pending
            record = last_record(i, task, work, state)
            if record and not args.retry:
                reason = ('Awaiting review: ' if record.get('status') == 'awaiting_review' else 'Previous attempt requires inspection: ') + task['id']
                # A stale downstream success must be reimplemented after its input changed.
                if (task['id'] in HOST_BATCH and record.get('status') == 'awaiting_review'
                        and record.get('inputs') is not None and record.get('key') == key(task)):
                    reason = None
                if record.get('key') != key(task):
                    reason = 'Task content changed; inspect before --retry: ' + task['id']
            if reason:
                say(reason)
            else:
                say(f'Next implementation: {task["id"]} · {task["description"]}')
                if args.dry_run:
                    say('Command: ' + json.dumps(command(args.engine, data)))
        else:
            say(reason)
        if state:
            say('Last receipt: ' + json.dumps(state, indent=2))
        return 0
    if all(t['passes'] for t in tasks):
        say('All ledger tasks accepted by reviewer. Nothing to execute.')
        return 0
    if 'RALPH_DATA_ROOT' not in os.environ:
        data_root(check=True)   # the store's fail-closed check; no local-storage fallback
    command(args.engine, data)
    data.mkdir(parents=True, exist_ok=True)
    with (data/'runner.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another Guardian Ralph runner holds this queue')
        completed, notice = 0, None
        while completed < args.iterations:
            tasks = read_ledger()
            work, state = read_work(data), read_state(data)
            pending, reason = select_next(tasks, work)
            retrying = args.retry
            if retrying:
                pending, reason = select_retry(tasks, work, state)
            if not pending:
                if reason != notice:
                    say(reason or 'Nothing to execute.'); notice = reason
                if (not args.continuous or all(t['passes'] for t in tasks) or
                        (reason and reason.startswith('Batch implementation handed off'))):
                    break
                time.sleep(args.interval)
                continue
            index, task = pending
            if completed and task['id'] not in HOST_BATCH:
                say('Phase boundary before ' + task['id'] + '. Start it explicitly after review.')
                break
            record = last_record(index, task, work, state)
            if record and not retrying:
                if record.get('key') != key(task):
                    raise ValueError('Task content changed since its attempt. Inspect it, then use --retry.')
                if record.get('status') != 'awaiting_review':
                    raise ValueError('Previous attempt is ' + str(record.get('status')) + '; inspect the log before --retry.')
                if task['id'] not in HOST_BATCH or record.get('inputs') is None:
                    message = 'Awaiting supervising review: ' + task['id']
                    if message != notice:
                        say(message); notice = message
                    if not args.continuous:
                        break
                    time.sleep(args.interval)
                    continue
            args.retry = False
            code = run_task(args.engine, index, task, data, tasks, work)
            completed += 1
            if code:
                report_pending(read_ledger(), read_work(data))
                return code
        say(f'Worker sessions this invocation: {completed}/{args.iterations}. No acceptance flags changed by Ralph.')
        report_pending(read_ledger(), read_work(data))
    return 0

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\nRunner stopped.', file=sys.stderr)
        sys.exit(130)
    except (OSError, ValueError, KeyError) as error:
        print(f'ralph: {error}', file=sys.stderr)
        sys.exit(1)

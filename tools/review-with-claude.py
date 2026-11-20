#!/usr/bin/env python3
"""Independent Claude ledger/foundation/integrated review; evidence only in the store."""
from pathlib import Path
import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import guardian_local  # noqa: E402  owner-local settings (lab/local.conf.example)


def forbidden_profile(environ):
    pattern = guardian_local.get('GUARDIAN_FORBIDDEN_CLAUDE_CONFIG', env=environ)
    return bool(pattern) and pattern.lower() in environ.get('CLAUDE_CONFIG_DIR', '').lower()
MODEL = 'claude-fable-5-1'
# G22 (ledger pin, 2026-11-19): the final integrated review asks for this model.
INTEGRATED_MODEL = 'claude-fable-5-2'
FILES = [
    'AGENTS.md', 'CLAUDE.md', 'README.md', 'guardian-tasks.json',
    'docs/roadmap.md', 'docs/live-lab.md', 'docs/ledger-order.md',
    'docs/contracts.md', 'docs/G01-validation.md', 'docs/review-status.md',
]

def default_model(scope):
    return INTEGRATED_MODEL if scope == 'integrated' else MODEL

def integrated_files():
    """G22: ledger, product documents, device evidence and the shipped source.

    Left out on purpose: docs/review-status.md (the worker's own conclusions; the
    reviewer gets the code and the records, not a verdict to confirm), the test
    sources (1.2 MB; the prompt says so), art/IMU/power/spike code, vendor blobs.
    """
    paths = ['AGENTS.md', 'CLAUDE.md', 'README.md', 'THIRD_PARTY_NOTICES.md', 'guardian-tasks.json',
             'docs/roadmap.md', 'docs/attack-coverage.md', 'docs/contracts.md', 'docs/architecture.md',
             'firmware/README.md', 'firmware/CMakeLists.txt', 'firmware/tools/host-check.sh',
             'firmware/boards/sticks3/partitions.csv', 'firmware/boards/sticks3/sdkconfig.defaults',
             'firmware/evidence/README.md',
             'firmware/adapters/companion/companion.hpp', 'firmware/adapters/companion/companion.cpp',
             'firmware/adapters/companion/screens.cpp', 'firmware/adapters/companion/inflate.hpp',
             'firmware/adapters/companion/inflate.cpp']
    for folder, suffixes in [('firmware/components/guardian_core', ('.cpp', '.hpp')),
                             ('firmware/components/guardian_presenter', ('.cpp', '.hpp')),
                             ('firmware/adapters/measurement', ('.cpp', '.hpp')),
                             ('firmware/adapters/ota', ('.cpp', '.hpp')),
                             ('firmware/adapters/setup', ('.cpp', '.hpp')),
                             ('firmware/adapters/tune', ('.cpp', '.hpp'))]:
        paths.extend(str(p.relative_to(ROOT)) for p in sorted((ROOT/folder).rglob('*'))
                     if p.is_file() and p.suffix in suffixes)
    board = ROOT/'firmware/boards/sticks3/main'
    left_out = ('art_bench', 'ble_spike', 'imu_task')
    paths.extend(str(p.relative_to(ROOT)) for p in sorted(board.iterdir())
                 if p.is_file() and p.suffix in ('.cpp', '.hpp') and not p.name.startswith(left_out))
    evidence = ROOT/'firmware/evidence'
    paths.extend(str(p.relative_to(ROOT)) for p in sorted(evidence.glob('sticks3-G16*-202611*.log'))
                 if p.stat().st_size <= 16384)
    return sorted(set(paths))

def input_files(scope):
    if scope == 'ledger':
        return FILES
    if scope == 'integrated':
        return integrated_files()
    paths = ['AGENTS.md', 'CLAUDE.md', 'THIRD_PARTY_NOTICES.md',
             'docs/contracts.md', 'docs/architecture.md', 'docs/G09-validation.md',
             'docs/G05-rating-freshness.md', 'docs/G06-detectors.md',
             'docs/G08-validation.md', 'docs/L02-live-validation.md',
             'firmware/CMakeLists.txt', 'lab/live/CMakeLists.txt',
             'lab/receiver/receiver.py']
    for folder, suffixes in [('firmware/components/guardian_core', ('.cpp','.hpp')),
                             ('firmware/components/guardian_presenter', ('.cpp','.hpp')),
                             ('firmware/tests', ('.cpp','.hpp','.cmake')),
                             ('lab/live', ('.py','.cpp'))]:
        paths.extend(str(p.relative_to(ROOT)) for p in sorted((ROOT/folder).rglob('*'))
                     if p.is_file() and p.suffix in suffixes and '__pycache__' not in p.parts)
    return sorted(set(paths))

INTEGRATED_PROMPT = """Independently review the integrated M5 Guardian product (ledger row G22, final integrated review).
M5 Guardian is defensive Wi-Fi monitoring firmware for the owner's own home network: a portable C++ library that
parses received management frames, tracks evidence freshness and reports possible disconnect bursts or changes from
an approved baseline, plus adapters and one board (M5Stack StickS3, native ESP-IDF). It never transmits attacks.
This is a read-only critical review. Tools are disabled. Do not run, edit, flash or operate anything, and do not
propose radio operations. You are given the ledger, the product documents, the device evidence logs and the shipped
source (portable core, presenter, the measurement / OTA / setup / TUNE adapters, the companion screens and inflater,
and the StickS3 board code). The test sources are not supplied (1.2 MB): the build file names them; treat every test
count in the documents as a claim you could not check. The worker's own review notes are withheld on purpose, so
that your findings are your own.

Review, in this order of importance:
1. Defensive honesty: can the product show a fresh, good or calm state on stale, missing or paused evidence? Is every
   stated blind spot real and is any real blind spot unstated (on the glass, in STATUS, in the documents)?
2. Security of the device itself: memory and bounds safety of everything that parses untrusted bytes (802.11 frames,
   EAPOL, BLE adverts, the setup page's HTTP form and name service, OTA manifest and image, TUNE offer and commands,
   the inflater); who can change detector settings, pause monitoring, install an image or read the Wi-Fi password,
   and with what authentication.
3. Detector correctness: false positives on ordinary networks, false negatives a nearby transmitter can force,
   state bounded under floods, scope (the owner's network versus nearby), cooldown and eviction behaviour.
4. Evidence against acceptance: rows marked passes=true whose own Verify step is not met by the recorded evidence;
   contradictions between the ledger, README, firmware/README and the evidence logs; carried-over checks that the
   final delivery row (G23) does not list; claims of device proof that the logs do not show.
5. Portability and licensing: SDK or board code leaking into the portable components; third-party obligations.

For each substantive finding give: severity (critical / high / medium / low), the exact file and function or ledger
row, a concrete counterexample or the exact contradicting sentences, and the smallest fix. Separate what you read in
the source from what you infer. Say plainly what you could not check. Do not praise; a statement that the design is
good is not evidence. Preserve the owner's requirements: five expressions of the persona, portable core, host TDD
before live validation before board integration. At most 3500 words. Requested model claude-fable-5-2 at high
effort; no other model or account. End with exactly one final line: APPROVE INTEGRATED or REVISE INTEGRATED.
A verdict is not acceptance of any ledger row.
"""

def review_prompt(scope, contents, requested_model=MODEL):
    if scope == 'integrated':
        prompt = INTEGRATED_PROMPT.replace(INTEGRATED_MODEL, requested_model)
        for name, content in contents.items():
            prompt += '\nFILE: ' + name + '\n' + content
        return prompt
    if scope == 'foundation':
        prompt = """Independently review the implemented M5 Guardian defensive monitoring foundation (G09).
Review the supplied source, contracts, tests and measured evidence. Read-only review; tools are disabled.
The C++ library parses received Wi-Fi frames, tracks freshness and displays uncertain defensive observations.
A separate explicitly launched owner-scoped lab fixture generated the recorded validation stimuli.
No radio operations, credential recovery, new attack implementation or hardware work are requested.

Focus on parser memory/bounds safety; exact network identity; freshness/epoch/origin separation;
detector false positives and limits; UI state/persistence; host process cleanup and truthful evidence;
source provenance/licenses and portable board isolation. Distinguish documented limitations from bugs.
For each substantive finding give severity, exact file/function, a concrete counterexample and minimal fix.
Do not treat a test count or a plausible design as proof that you executed it. Identify any missing evidence.
Read the supervisor's dispositions critically. Board adapters and physical rendering are later tasks.
End with APPROVE FOUNDATION or REVISE FOUNDATION, within 3000 words. Requested model
claude-fable-5-1, effort high; no alternate account/model. A verdict is not automatic acceptance.
"""
    else:
        prompt = """Independently review the M5 Guardian implementation ledger and planning documents.
Read-only architecture review; no tools, edits, tests, radio operations or execution.
Critique dependency order, finite acceptance criteria, evidence truthfulness, licensing,
portable boundaries, stale-data safety and TDD. Preserve host TDD -> real host-library
RF validation -> independent review -> board integration -> art. No Arduino or website.
Give prioritized findings with task IDs and exact amendments. End with APPROVE LEDGER
or REVISE LEDGER, within 1800 words. Requested model claude-fable-5-1, high effort.
"""
    prompt = prompt.replace(MODEL, requested_model)
    for name, content in contents.items():
        prompt += '\nFILE: ' + name + '\n' + content
    return prompt

def classify_response(response, returncode, scope='ledger', requested_model=MODEL):
    """Classify transport/model/outcome separately; a refusal is never a review."""
    models = list(response.get('modelUsage', {})) if isinstance(response.get('modelUsage'), dict) else []
    model_verified = bool(models) and all(m == requested_model or m.startswith(requested_model + '-') for m in models)
    body = response.get('result', '')
    body = body if isinstance(body, str) else ''
    refused = (response.get('stop_reason') == 'refusal' or
               bool(response.get('safety_stops')) or 'safeguards flagged this message' in body)
    if refused:
        outcome, message = 'provider_refused', 'Provider refused the request; no review completed.'
    elif returncode or response.get('is_error') or response.get('terminal_reason') == 'api_error':
        outcome, message = 'provider_error', 'Provider/CLI error; no completed review.'
    elif not model_verified:
        outcome, message = 'model_unverified', 'Response received, but requested model is unverified.'
    elif not body.strip():
        outcome, message = 'empty_response', 'No review text returned.'
    elif not body.rstrip().endswith(('APPROVE '+scope.upper(), 'REVISE '+scope.upper())):
        outcome, message = 'incomplete_review', 'Response lacks the requested final scope verdict; review incomplete.'
    else:
        outcome, message = 'review_received', 'Review received; findings require supervising assessment and fixes.'
    return dict(outcome=outcome, message=message, models_reported=models,
                requested_model_verified=model_verified, stop_reason=response.get('stop_reason'),
                cli_returncode=returncode, response_complete_requested_model=outcome == 'review_received',
                requested_model=requested_model, effort_requested='high', findings_disposition='no automatic acceptance')

def cli_args(binary, requested_model, scope):
    """The reviewer call. No tools, no MCP, no fallback model, nothing persisted."""
    args = [binary, '-p', '--model', requested_model, '--effort', 'high',
            '--no-session-persistence', '--tools', '', '--strict-mcp-config']
    if scope == 'integrated':
        # Only the supplied context: no user-level instructions, hooks, plugins or skills (the call runs
        # in its evidence folder, which has no project settings either), and the stream keeps the
        # session's own init record (model, tools, MCP servers, CLI version) beside the result.
        return args + ['--setting-sources', 'project', '--disable-slash-commands',
                       '--output-format', 'stream-json', '--verbose']
    return args + ['--output-format', 'json']

def child_env(environ):
    """A plain terminal's environment: a parent Claude Code session's model/effort/session variables
    must not reach the reviewer. Another account's configuration is refused, never switched to."""
    if forbidden_profile(environ):
        raise ValueError('Use normal Claude configuration; no account switch will be performed.')
    return {k: v for k, v in environ.items() if not k.startswith(('CLAUDE', 'ANTHROPIC_'))}

def read_stream(text):
    """(final result object or None, init facts) from --output-format stream-json output."""
    response, facts = None, {}
    for line in text.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        if message.get('type') == 'system' and message.get('subtype') == 'init':
            facts = {k: message[k] for k in ('model', 'tools', 'mcp_servers', 'claude_code_version', 'apiKeySource', 'skills')
                     if k in message}
        elif message.get('type') == 'result':
            response = message
    return response, facts

def report_existing(directory):
    directory = Path(directory)
    response = json.loads((directory / 'response.json').read_text())
    if not isinstance(response, dict):
        raise ValueError('Structured response is not an object.')
    # Legacy evidence did not save the CLI exit code. Do not invent it.
    request = json.loads((directory/'request.json').read_text()) if (directory/'request.json').exists() else {}
    status = classify_response(response, request.get('cli_returncode'), request.get('scope', 'ledger'), request.get('model', MODEL))
    print(json.dumps(status, indent=2))
    print(f'Evidence: {directory}\nRead-only report: no provider call, edits or retry.')
    return 0 if status['response_complete_requested_model'] else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', metavar='EVIDENCE_DIR', help='classify saved response without contacting Claude or editing evidence')
    parser.add_argument('--scope', choices=['ledger','foundation','integrated'], default='ledger')
    parser.add_argument('--model', choices=[MODEL, INTEGRATED_MODEL, 'claude-opus-5-5'], default=None,
                        help='Explicit owner-selected model; never an automatic fallback (default: the scope\'s pinned model)')
    args = parser.parse_args()
    scope = args.scope
    requested_model = args.model or default_model(scope)
    if args.report:
        return report_existing(args.report)
    if forbidden_profile(os.environ):
        raise ValueError('Use normal Claude configuration; no account switch will be performed.')
    binary = shutil.which('claude')
    if not binary:
        raise ValueError('Normal claude executable not found in PATH.')
    store = guardian_local.store()   # fail-closed store check; no local output fallback
    contents = {name: (ROOT / name).read_text() for name in input_files(scope)}
    prompt = review_prompt(scope, contents, requested_model)
    output = store / 'reviews' / (
        dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '-'+scope+'-independent')
    output.mkdir(parents=True)
    args = cli_args(binary, requested_model, scope)
    integrated = scope == 'integrated'
    request = {'scope':scope, 'model': requested_model, 'effort': 'high', 'tools': [],
               'source_hashes': {name: hashlib.sha256(content.encode()).hexdigest()
                                 for name, content in contents.items()}, 'argv': args}
    (output / 'request.json').write_text(json.dumps(request, indent=2) + '\n')
    (output / 'prompt.txt').write_text(prompt)
    print(f'Read-only independent {scope} review: {requested_model}, high effort.\nEvidence: {output}', flush=True)
    print('No ledger edits or lab actions. Waiting for the reviewer response...', flush=True)
    if integrated:
        result = subprocess.run(args, input=prompt, text=True, capture_output=True, cwd=output, env=child_env(os.environ))
        (output / 'stream.jsonl').write_text(result.stdout)
        final, facts = read_stream(result.stdout)
        (output / 'session.json').write_text(json.dumps(facts, indent=2) + '\n')
        stdout = json.dumps(final, indent=2) + '\n' if final is not None else ''
    else:
        result = subprocess.run(args, input=prompt, text=True, capture_output=True, cwd=ROOT)
        stdout = result.stdout
    (output / 'response.json').write_text(stdout)
    (output / 'stderr.txt').write_text(result.stderr)
    request['cli_returncode'] = result.returncode
    (output/'request.json').write_text(json.dumps(request, indent=2)+'\n')
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    try:
        response = json.loads(stdout)
        if not isinstance(response, dict):
            raise ValueError('Structured response is not an object.')
    except (json.JSONDecodeError, ValueError) as error:
        status = dict(outcome='invalid_response', message=str(error), cli_returncode=result.returncode,
                      response_complete_requested_model=False, requested_model_verified=False,
                      findings_disposition='no automatic acceptance')
    else:
        print(response.get('result', 'No review text returned.'))
        status = classify_response(response, result.returncode, scope, requested_model)
        if integrated:
            # The CLI's result does not echo the effort level: it is known only as the argument sent.
            status['effort_evidence'] = 'argv only (--effort high); not echoed by the CLI result'
            status['session'] = facts
            if facts.get('tools') or facts.get('mcp_servers') or facts.get('model') != requested_model:
                status.update(outcome='session_unverified', response_complete_requested_model=False,
                              message='Session init does not show the requested model with no tools and no MCP servers.')
    changed = [name for name, content in contents.items()
               if not (ROOT / name).is_file() or (ROOT / name).read_text() != content]
    status['source_changed_during_review'] = changed
    (output / 'review-status.json').write_text(json.dumps(status, indent=2) + '\n')
    print(f'\nEvidence: {output}')
    print(status['message'])
    if not status['response_complete_requested_model']:
        print('No automatic retry or model/account fallback. Ledger unchanged.', file=sys.stderr)
        return 1
    if changed:
        print('Source changed during review; review applies to its saved snapshot: ' + ', '.join(changed))
    print('Requested model response received. Findings still need supervising assessment and fixes.')
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print('Review stopped: ' + str(error), file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Apply the owner's private redaction map to text files: the one rerunnable redaction step.

The map lives OUTSIDE the tree (GUARDIAN_REDACT_MAP, default ~/.config/m5-guardian/redact-map.json),
in the format tools/public_check.py reads, plus one field per address entry:
  {"version": 1, "entries": [
     {"real": "...", "placeholder": "LAB-STICK-1", "kind": "mac", "synthetic": "020000000b01"},
     {"real": "...", "placeholder": "LAB-PI-HOST", "kind": "text"}]}
The search forms of every entry come from public_check.variants(), so the redaction and the guard agree.

Replacement:
  documents        an address becomes its placeholder word; text becomes its placeholder
  code and tests   an address becomes its synthetic locally administered address in the same format
  (*.py, *.sh,     (separator and letter case kept), so the code still parses it
   *.c/h/cpp/hpp,
   CMake, tests/)
  inside a hex     an address embedded in a longer hex string becomes the same-length synthetic hex,
  string           in any file, so a frame or fixture keeps its length (re-derive checksums with the
                   project's own encoder afterwards, never by hand)
  text forms       hex form -> hex of the placeholder; URL-encoded form -> the placeholder
  path rules       the repository's absolute path -> relative; the artifact store (GUARDIAN_STORE) ->
                   $GUARDIAN_STORE; its mount point (GUARDIAN_STORE_MOUNT) -> $GUARDIAN_STORE_MOUNT

Binary files are never edited: a binary that still holds a value is reported and the exit code is 1.
Reports name placeholders and counts only, never a real value.

  python3 tools/redact.py FILE...            rewrite in place
  python3 tools/redact.py --dry-run FILE...  counts only
"""
import argparse
import fnmatch
import json
import os
import re
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
from public_check import variants  # noqa: E402
import guardian_local  # noqa: E402

CODE = ('*.py', '*.sh', '*.c', '*.h', '*.cpp', '*.hpp', '*.cmake', 'CMakeLists.txt', '*.hex')
_HEX = re.compile(r'[0-9A-Fa-f]')


def check_entries(entries):
    for entry in entries:
        variants(entry)   # the guard's own validation of real / placeholder / kind
        if entry['kind'] == 'mac':
            syn = entry.get('synthetic')
            if not isinstance(syn, str) or not re.fullmatch(r'[0-9a-f]{12}', syn) or not int(syn[:2], 16) & 0x02 or int(syn[:2], 16) & 0x01:
                raise ValueError(f"private map: {entry['placeholder']}: a mac entry needs 'synthetic', 12 lowercase hex, "
                                 'locally administered and unicast')
    return entries


def load_map(path, root=ROOT):
    path = Path(path).expanduser().resolve()
    if Path(root).resolve() in path.parents:
        raise ValueError('the private map must live outside the tree')
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('entries'), list):
        raise ValueError('private map: expected {"version": 1, "entries": [...]}')
    return check_entries(data['entries'])


def path_rules(repo=None, store=None, mount=None):
    """(literal, replacement) pairs, longest first."""
    rules = []
    if repo:
        rules += [(str(repo).rstrip('/') + '/', ''), (str(repo).rstrip('/'), '.')]
    if store:
        rules.append((str(store).rstrip('/'), '$GUARDIAN_STORE'))
    if mount:
        rules.append((str(mount).rstrip('/'), '$GUARDIAN_STORE_MOUNT'))
    return sorted(rules, key=lambda r: -len(r[0]))


def _formatted(synthetic, sample):
    """The synthetic address written like the matched sample (separator, letter case)."""
    sep = ':' if ':' in sample else '-' if '-' in sample else ''
    text = sep.join(synthetic[i:i + 2] for i in range(0, 12, 2))
    return text.upper() if any(c.isupper() for c in sample) else text


def redact_text(text, entries, synthetic=False, rules=()):
    """(new text, {placeholder or rule replacement: count})."""
    counts = {}

    def bump(name, n=1):
        counts[name] = counts.get(name, 0) + n

    for literal, replacement in rules:
        n = text.count(literal)
        if n:
            text = text.replace(literal, replacement)
            bump(replacement, n)
    ordered = sorted(entries, key=lambda e: -len(e['real']))
    for entry in ordered:
        placeholder = entry['placeholder']
        for form, pattern in variants(entry):
            if form.startswith('raw'):
                continue
            regex = re.compile(pattern.pattern.decode(), pattern.flags & re.IGNORECASE)

            def replace(match, form=form):
                found = match.group(0)
                bump(placeholder)
                if entry['kind'] == 'mac':
                    before = text[match.start() - 1:match.start()]
                    after = text[match.end():match.end() + 1]
                    embedded = ':' not in found and '-' not in found and (_HEX.match(before or ' ') or _HEX.match(after or ' '))
                    if embedded or synthetic:
                        return _formatted(entry['synthetic'], found)
                    return placeholder
                if form == 'hex':
                    hexed = placeholder.encode().hex()
                    return hexed.upper() if found.isupper() else hexed
                return placeholder

            text = regex.sub(replace, text)
    return text, counts


def is_code(rel):
    name = Path(rel).name
    return any(fnmatch.fnmatch(name, p) for p in CODE) or '/tests/' in f'/{rel}'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('files', nargs='+')
    ap.add_argument('--map', default=os.environ.get('GUARDIAN_REDACT_MAP', '~/.config/m5-guardian/redact-map.json'))
    ap.add_argument('--root', default=str(ROOT), help='the tree the files belong to (default: this repository)')
    ap.add_argument('--dry-run', action='store_true')
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()
    try:
        entries = load_map(a.map, root)
    except (OSError, ValueError) as e:
        print(f'redact: {e}', file=sys.stderr)
        return 2
    store = guardian_local.get('GUARDIAN_STORE')
    rules = path_rules(repo=root, store=store, mount=guardian_local.get('GUARDIAN_STORE_MOUNT'))
    leftovers, total = [], {}
    for name in a.files:
        path = Path(name).resolve()
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else path.name
        data = path.read_bytes()
        if b'\0' in data[:8192]:
            hits = [e['placeholder'] for e in entries for form, p in variants(e) if p.search(data)]
            if hits:
                leftovers.append(rel)
                print(f'BINARY {rel}: still holds {", ".join(sorted(set(hits)))} (not edited)')
            continue
        text = data.decode('utf-8')
        new, counts = redact_text(text, entries, synthetic=is_code(rel), rules=rules)
        if counts:
            print(f'{rel}: ' + ', '.join(f'{k} x{v}' for k, v in sorted(counts.items())) + (' (dry run)' if a.dry_run else ''))
            for k, v in counts.items():
                total[k] = total.get(k, 0) + v
        if new != text and not a.dry_run:
            tmp = path.with_name(path.name + '.redact-tmp')
            tmp.write_text(new)
            os.chmod(tmp, path.stat().st_mode & 0o7777)   # keep the executable bit of scripts
            os.replace(tmp, path)
    print('redact: ' + (', '.join(f'{k} x{v}' for k, v in sorted(total.items())) or 'nothing to replace'))
    return 1 if leftovers else 0


if __name__ == '__main__':
    sys.exit(main())

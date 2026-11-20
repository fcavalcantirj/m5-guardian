#!/usr/bin/env python3
"""Public-readiness guard: fail when the tree holds a personal or machine-specific value.

Scans exactly the files git would take (tracked plus untracked-and-not-ignored; every file when the
directory is not a git checkout) and reports:

  radio-address   a full universally administered radio address (synthetic locally administered
                  ones, group addresses and all-zero are fine)
  home-path       a named home directory
  volume-path     a named mounted volume
  local-hostname  a .local host in a login or a URL
  private-ip      a private-range IPv4 address (the stick's own setup page is the one built-in exception)
  mail-address    an e-mail address
  forbidden-file  key material or a local configuration file, by name
  required-file   a license file that must exist
  private-map     any form of a value listed in the owner's private map (never printed: the report
                  names the placeholder instead)

The private map lives OUTSIDE the tree (GUARDIAN_REDACT_MAP, default
~/.config/m5-guardian/redact-map.json):
  {"version": 1, "entries": [{"real": "...", "placeholder": "LAB-STICK-1", "kind": "mac" | "text"}]}
Without it only the generic rules run, and the summary says so.

False positives are silenced one by one in tools/public_check.allow:
  rule | path-glob | literal (or *) | reason
A reason is mandatory. private-map, forbidden-file and required-file cannot be allowed.

Exit code 0 = no findings, 1 = findings, 2 = usage or configuration error.
"""
import argparse, fnmatch, json, os, re, subprocess, sys, urllib.parse
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOW_FILE = 'tools/public_check.allow'
REQUIRED = ('LICENSE', 'firmware/art/LICENSE', 'THIRD_PARTY_NOTICES.md')
FORBIDDEN = ('*.pem', '*.key', '*.p12', '*.keystore', '.env', '.env.*', 'local.conf',
             'redact-map*.json', 'lab-credentials*.json')
WALK_SKIP = {'.git', 'build', '__pycache__', 'managed_components', '.venv', '.pytest_cache'}
ALLOWABLE = ('radio-address', 'home-path', 'volume-path', 'local-hostname', 'private-ip', 'mail-address')
SETUP_PAGE = b'192.168.4.1'          # the ESP-IDF SoftAP default the product's setup page is served on
MAIL_OK = (b'git@github.com', b'noreply@anthropic.com')
NOT_A_DOMAIN = (b'.local', b'.png', b'.jpg', b'.jpeg', b'.gif', b'.svg', b'.webp')

HEX = b'[0-9A-Fa-f]'
RULES = (
    ('radio-address', re.compile(rb'(?<![0-9A-Fa-f:\-])' + HEX + b'{2}([:\\-])(?:' + HEX + b'{2}\\1){4}' + HEX + b'{2}(?![0-9A-Fa-f:\\-])')),
    ('home-path', re.compile(rb'(?<![\w.])/(?:Users|home)/[A-Za-z0-9._-]+')),
    ('volume-path', re.compile(rb'(?<![\w.])/Volumes/[A-Za-z0-9._-]+')),
    ('local-hostname', re.compile(rb'(?:@|//)[A-Za-z0-9][A-Za-z0-9-]*\.local(?![\w(])')),
    ('private-ip', re.compile(rb'(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}'
                              rb'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])')),
    ('mail-address', re.compile(rb'(?<![A-Za-z0-9._%+-])[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])')),
)
GENERIC_HOME = (b'/home/user', b'/home/pi', b'/home/runner', b'/Users/Shared')


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int      # 0 = not a text position (binary content or the file name)
    what: str


def render(finding):
    return f'{finding.rule}: {finding.path}:{finding.line}: {finding.what}'


def list_files(root):
    """The exact list `git add -A` would take; every file when root is not a git checkout."""
    if (root / '.git').exists():
        out = subprocess.run(['git', '-C', str(root), 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                             check=True, capture_output=True).stdout
        return sorted(p for p in out.decode().split('\0') if p and (root / p).is_file())
    found = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in WALK_SKIP]
        found += [str((Path(base) / f).relative_to(root)) for f in files]
    return sorted(found)


def keep_generic(rule, text):
    """False for a match the rule deliberately lets through."""
    if rule == 'radio-address':
        first = int(text[:2], 16)
        return not (first & 0x01 or first & 0x02 or set(text.lower()) <= set(b'0:-'))
    if rule == 'home-path':
        return text not in GENERIC_HOME
    if rule == 'private-ip':
        return text != SETUP_PAGE
    if rule == 'mail-address':
        low = text.lower()
        return low not in MAIL_OK and not low.endswith(NOT_A_DOMAIN)
    return True


def read_allow(root):
    path = root / ALLOW_FILE
    rows = []
    if not path.is_file():
        return rows
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = [p.strip() for p in line.split('|')]
        if len(parts) != 4 or not all(parts[:3]) or not parts[3]:
            raise ValueError(f'{ALLOW_FILE}:{number}: expected "rule | path-glob | literal | reason" with a reason')
        if parts[0] not in ALLOWABLE:
            raise ValueError(f'{ALLOW_FILE}:{number}: rule {parts[0]!r} cannot be allowed')
        rows.append((parts[0], parts[1], parts[2].lower()))
    return rows


def allowed(rows, rule, path, text):
    low = text.decode(errors='replace').lower()
    return any(r == rule and fnmatch.fnmatch(path, glob) and literal in ('*', low) for r, glob, literal in rows)


def variants(entry):
    """Search forms of one private-map entry: [(form name, compiled bytes pattern)].

    Shared with tools/redact.py so the redaction and the guard agree on what a value looks like.
    """
    real, placeholder, kind = entry.get('real'), entry.get('placeholder'), entry.get('kind')
    if not isinstance(real, str) or not isinstance(placeholder, str) or not placeholder.strip():
        raise ValueError('private map: every entry needs a real value and a placeholder')
    if kind == 'mac':
        bare = re.sub(r'[:\-\s]', '', real).lower()
        if not re.fullmatch(r'[0-9a-f]{12}', bare):
            raise ValueError(f'private map: {placeholder}: a mac entry needs 12 hex digits')
        pairs = [bare[i:i + 2] for i in range(0, 12, 2)]
        raw = bytes.fromhex(bare)
        return [('address', re.compile('[:\\-]?'.join(pairs).encode(), re.IGNORECASE)),
                ('raw bytes', re.compile(re.escape(raw))),
                ('raw bytes reversed', re.compile(re.escape(raw[::-1])))]
    if kind == 'text':
        if len(real.strip()) < 3:
            raise ValueError(f'private map: {placeholder}: a text entry needs at least 3 characters')
        forms = [('text', re.compile(re.escape(real.encode()), re.IGNORECASE)),
                 ('hex', re.compile(real.encode().hex().encode(), re.IGNORECASE))]
        quoted = urllib.parse.quote(real, safe='')
        if quoted != real:
            forms.append(('url-encoded', re.compile(re.escape(quoted.encode()), re.IGNORECASE)))
        return forms
    raise ValueError(f'private map: {placeholder}: kind must be "mac" or "text"')


def read_map(map_path, root):
    if map_path is None:
        return []
    path = Path(map_path).expanduser().resolve()
    if root.resolve() in path.parents:
        raise ValueError('the private map must live outside the tree')
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('entries'), list):
        raise ValueError('private map: expected {"version": 1, "entries": [...]}')
    return [(entry['placeholder'], variants(entry)) for entry in data['entries']]


def line_of(data, offset, binary):
    return 0 if binary else data.count(b'\n', 0, offset) + 1


def check(root, map_path=None):
    """All findings for the tree at root, sorted. map_path None = generic rules only."""
    root = Path(root)
    allow, private = read_allow(root), read_map(map_path, root)
    files, findings = list_files(root), []
    for required in REQUIRED:
        if not (root / required).is_file():
            findings.append(Finding('required-file', required, 0, 'missing'))
    for rel in files:
        name = Path(rel).name
        if not name.endswith('.example') and any(fnmatch.fnmatch(name, pattern) for pattern in FORBIDDEN):
            findings.append(Finding('forbidden-file', rel, 0, 'this file name must not be in the tree'))
        data = (root / rel).read_bytes()
        binary = b'\0' in data[:8192]
        if rel != ALLOW_FILE:
            for rule, pattern in RULES:
                for match in pattern.finditer(data):
                    text = match.group(0)
                    if rule == 'local-hostname':
                        text = text.lstrip(b'@/')
                    if keep_generic(rule, text) and not allowed(allow, rule, rel, text):
                        findings.append(Finding(rule, rel, line_of(data, match.start(), binary), text.decode(errors='replace')))
        for placeholder, forms in private:
            for form, pattern in forms:
                for match in pattern.finditer(data):
                    findings.append(Finding('private-map', rel, line_of(data, match.start(), binary), f'{placeholder} ({form})'))
                if not form.startswith('raw') and pattern.search(rel.encode()):
                    findings.append(Finding('private-map', rel, 0, f'{placeholder} ({form}, in the file name)'))
    return sorted(set(findings), key=lambda f: (f.path, f.line, f.rule, f.what))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--root', default=str(ROOT), help='tree to check (default: this repository)')
    parser.add_argument('--map', default=os.environ.get('GUARDIAN_REDACT_MAP', '~/.config/m5-guardian/redact-map.json'),
                        help='private map outside the tree')
    parser.add_argument('--require-map', action='store_true', help='fail when the private map is absent')
    args = parser.parse_args(argv)
    root, map_path = Path(args.root), Path(args.map).expanduser()
    have_map = map_path.is_file()
    if args.require_map and not have_map:
        print(f'public_check: private map absent at {map_path}', file=sys.stderr)
        return 2
    try:
        findings = check(root, map_path if have_map else None)
    except (ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f'public_check: {error}', file=sys.stderr)
        return 2
    for finding in findings:
        print(render(finding))
    counts = {}
    for finding in findings:
        counts[finding.rule] = counts.get(finding.rule, 0) + 1
    summary = ', '.join(f'{rule}={count}' for rule, count in sorted(counts.items())) or 'none'
    print(f'public_check: {len(list_files(root))} files, findings: {summary}')
    print('public_check: private map applied' if have_map else
          'public_check: private map ABSENT: generic rules only, this is not the full check')
    return 1 if findings else 0


if __name__ == '__main__':
    sys.exit(main())

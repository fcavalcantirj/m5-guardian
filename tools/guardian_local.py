"""Owner-local settings for the lab tools: nothing about one owner's machine lives in the tree.

Each value comes from the environment first, then from one untracked file,
~/.config/m5-guardian/local.conf (or the file named by GUARDIAN_LOCAL_CONF), as KEY=VALUE lines.
A value that is needed and absent is a named refusal (Missing), never a guess. The tracked template
lab/local.conf.example lists every key. The shell twin is tools/guardian-local.sh.

The artifact store (GUARDIAN_STORE) is fail-closed: it must hold the sentinel file
.guardian-store-root, and when GUARDIAN_STORE_MOUNT names
a mount point, that mount point must be a mounted smbfs share, so nothing is ever written into an
empty mount point.
"""
import os
import re
import subprocess
from pathlib import Path

CONF_ENV = 'GUARDIAN_LOCAL_CONF'
DEFAULT_CONF = '~/.config/m5-guardian/local.conf'
TEMPLATE = 'lab/local.conf.example'
SENTINEL = '.guardian-store-root'
_LINE = re.compile(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*')


class Missing(ValueError):
    """A needed owner-local value is absent or the store failed its fail-closed check."""


def conf_path(env=None):
    env = os.environ if env is None else env
    return Path(env.get(CONF_ENV) or DEFAULT_CONF).expanduser()


def read_conf(path):
    path = Path(path)
    if not path.is_file():
        return {}
    values = {}
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        match = _LINE.fullmatch(raw)
        if not match:
            raise ValueError(f'{path.name}:{number}: expected KEY=VALUE')
        value = match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        values[match.group(1)] = value
    return values


def load(env=None):
    return read_conf(conf_path(env))


def get(key, *aliases, env=None, conf=None):
    """The first non-empty value of key or an alias: environment first, then local.conf."""
    env = os.environ if env is None else env
    conf = load(env) if conf is None else conf
    for source in (env, conf):
        for name in (key, *aliases):
            if source.get(name):
                return source[name]
    return None


def require(key, *aliases, purpose='', env=None, conf=None):
    value = get(key, *aliases, env=env, conf=conf)
    if value is None:
        what = f' ({purpose})' if purpose else ''
        raise Missing(f'{key}{what} is not set: export {key}=... or add it to {conf_path(env)} '
                      f'(every key is listed in {TEMPLATE})')
    return value


def mount_table():
    return subprocess.run(['mount'], capture_output=True, text=True).stdout


def store(env=None, conf=None, check=True):
    """The artifact store as a resolved Path; with check, refuse unless it passes the fail-closed check."""
    root = Path(require('GUARDIAN_STORE', 'GUARDIAN_BROW_ROOT', purpose='the artifact store', env=env, conf=conf)).expanduser()
    if check:
        mount = get('GUARDIAN_STORE_MOUNT', env=env, conf=conf)
        if mount and not any(f' on {mount} (smbfs' in line for line in mount_table().splitlines()):
            raise Missing(f'{mount} (GUARDIAN_STORE_MOUNT) is not mounted as smbfs; nothing is read or written')
        if not (root / SENTINEL).is_file():
            raise Missing(f'{root} has no {SENTINEL} sentinel; refusing to use it as the artifact store')
    return root.resolve()

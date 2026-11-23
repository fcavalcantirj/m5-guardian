#!/usr/bin/env python3
"""G26 public release: the steps tools/release_package.sh and tools/release_publish.sh run.

A release is the four files a browser flasher writes (the owner's W07 spike, 2026-11-23):

    0x0      bootloader.bin                 the ESP-IDF second stage bootloader
    0x8000   partition-table.bin            partitions.csv (nvs, otadata, phy, nvs_cred, ota_0, ota_1)
    0x10000  ota_data_initial.bin           boots ota_0
    0x20000  guardian_sticks3-signed.bin    the app, signed with the owner's OTA key (RSA-3072, Secure Boot V2 scheme)

Nothing else ships: never the ELF, the map, the source tarball or the SDK inputs (they stay in the build
archive on the store). The app is built twice from a clean tree (build.sh build-release) and the two
builds must give the same bytes. The signature block is NOT compared: espsecure signs with RSA-PSS, whose
salt is random, so two signings of one image differ (the unsigned app, which the signature covers, is what
is compared, and the shipped app must be that unsigned app plus its signature block).

The manifest the website reads (tools/release_publish.sh signs it with the separate ECDSA P-256 release key):
    {"tag": "guardian-<version>-b<build>-<sha12>", "version": "<x.y.z>", "build": <n>, "date": "YYYY-MM-DD",
     "notes": "<text>", "parts": [{"file", "offset", "sha256", "size"} x 4, in flash order]}
<sha12> is the first 12 hex digits of the shipped (signed) app's sha256.
"""
import argparse, datetime, hashlib, json, re, shutil, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / 'release' / 'version.txt'
APP = 'guardian_sticks3-signed.bin'
# (offset, file in the package and on the release, file in the build archive)
PARTS = ((0x0, 'bootloader.bin', 'bootloader/bootloader.bin'),
         (0x8000, 'partition-table.bin', 'partition_table/partition-table.bin'),
         (0x10000, 'ota_data_initial.bin', 'ota_data_initial.bin'),
         (0x20000, APP, APP))
# What the two builds must agree on: the three plain parts and the UNSIGNED app.
REPRODUCED = ('bootloader/bootloader.bin', 'partition_table/partition-table.bin', 'ota_data_initial.bin', 'guardian_sticks3.bin')
PACKAGE_FILES = {name for _, name, _ in PARTS} | {'BUILD_INFO.txt', 'SHA256SUMS'}
PUBLISHED_EXTRA = {'manifest.json', 'manifest.sig'}
TAG_RE = re.compile(r'^guardian-(\d+\.\d+\.\d+)-b([1-9]\d{0,8})-([0-9a-f]{12})$')
VERSION_RE = re.compile(r'^\d+\.\d+\.\d+$')
NOTES_MAX = 1000
MANIFEST_MAX = 4096


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_release_number(path=VERSION_FILE):
    """release/version.txt: `version=x.y.z` and `build=<n>` (comments start with #). The build number is
    what tools/release_publish.sh compares with the published release (it must be higher)."""
    values = {}
    for line in Path(path).read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        if '=' not in line:
            raise ValueError(f'{path}: expected key=value, got {line!r}')
        key, value = (x.strip() for x in line.split('=', 1))
        values[key] = value
    if set(values) != {'version', 'build'}:
        raise ValueError(f'{path}: needs exactly version= and build=')
    if not VERSION_RE.match(values['version']):
        raise ValueError(f'{path}: version must be x.y.z, got {values["version"]!r}')
    if not re.fullmatch(r'[1-9]\d{0,8}', values['build']):
        raise ValueError(f'{path}: build must be a whole number from 1, got {values["build"]!r}')
    return values['version'], int(values['build'])


def commit_stamp(epoch_seconds, tz=None):
    """The app version of a release build: the commit's time as the build stamp the stick's OTA order reads
    (guardian-YYYYMMDD-HHMMSS; build.sh adds -rel), on the local clock like every other build stamp
    (build_support.py default_app_version), so a release never looks newer than the owner's later dev builds.
    Both builds of one commit get the same stamp."""
    at = datetime.datetime.fromtimestamp(int(epoch_seconds), tz)
    return 'guardian-' + at.strftime('%Y%m%d-%H%M%S')


def _complete(archive):
    path = Path(archive) / 'COMPLETE.json'
    if not path.is_file():
        raise ValueError(f'{archive}: not a complete build archive (COMPLETE.json missing)')
    return json.loads(path.read_text())


def check_release_archive(archive):
    done = _complete(archive)
    if not done.get('complete') or not done.get('release_image'):
        raise ValueError(f'{archive}: not a release image (build.sh build-release)')
    if done.get('radio_country') != '01' or not done.get('radio_80211d'):
        raise ValueError(f'{archive}: release image without the world safe country "01" and 802.11d adoption')
    for flag in ('selftest_fail_test_image', 'ble_spike_image', 'art_bench_image', 'dark_cpu_image'):
        if done.get(flag):
            raise ValueError(f'{archive}: {flag} is not a public image')
    archive = Path(archive)
    unsigned, signed = (archive / 'guardian_sticks3.bin').read_bytes(), (archive / APP).read_bytes()
    if not signed.startswith(unsigned) or len(signed) <= len(unsigned):
        raise ValueError(f'{archive}: the signed app is not the unsigned app plus a signature block')
    signing = json.loads((archive / 'signing.json').read_text())
    if signing.get('scheme') != 'rsa3072-sbv2' or signing.get('signed_sha256') != hashlib.sha256(signed).hexdigest() \
            or signing.get('unsigned_sha256') != hashlib.sha256(unsigned).hexdigest():
        raise ValueError(f'{archive}: signing.json does not match the images')
    return done


def compare_builds(first, second):
    """The two clean builds of one tree: the same app version and the same bytes for the three plain parts and
    the unsigned app. Returns {archive file: sha256}."""
    a, b = check_release_archive(first), check_release_archive(second)
    if a.get('app_version') != b.get('app_version'):
        raise ValueError(f'the two builds carry different versions: {a.get("app_version")} / {b.get("app_version")}')
    sums = {}
    for name in REPRODUCED:
        x, y = sha256(Path(first) / name), sha256(Path(second) / name)
        if x != y:
            raise ValueError(f'not reproducible: {name} differs between the two clean builds ({x} / {y})')
        sums[name] = x
    return sums


def make_package(archive, parent, version, build, commit, tree, reproduced, toolchain=''):
    """Copy the four flash files out of a checked release archive into <parent>/<tag>/ with BUILD_INFO.txt and
    SHA256SUMS. Returns the package directory. Never copies anything else from the archive."""
    if not VERSION_RE.match(version) or not (isinstance(build, int) and build >= 1):
        raise ValueError('bad release number')
    if tree not in ('clean', 'dirty'):
        raise ValueError('tree must be clean or dirty')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('commit must be a full git sha')
    done = check_release_archive(archive)
    archive = Path(archive)
    if sha256(archive / 'guardian_sticks3.bin') != reproduced.get('guardian_sticks3.bin'):
        raise ValueError('the archive is not the build that was reproduced')
    app_sha = sha256(archive / APP)
    tag = f'guardian-{version}-b{build}-{app_sha[:12]}'
    out = Path(parent) / tag
    if out.exists():
        raise ValueError(f'package already exists: {out}')
    out.mkdir(parents=True)
    lines = []
    for offset, name, source in PARTS:
        before = sha256(archive / source)
        shutil.copyfile(archive / source, out / name)
        if sha256(out / name) != before:
            raise ValueError(f'copy readback failed: {name}')
    for offset, name, _ in PARTS:
        lines.append(f'part: {name} offset=0x{offset:x} size={(out / name).stat().st_size} sha256={sha256(out / name)}')
    info = [
        'product: M5 Guardian (M5Stack StickS3), public release image',
        f'version: {version}',
        f'build: {build}',
        f'tag: {tag}',
        f'app_version: {done["app_version"]}',
        f'git commit: {commit}',
        f'tree: {tree}',
        f'radio country: {done["radio_country"]} (802.11d adoption: {"on" if done["radio_80211d"] else "off"})',
        'reproducible: two clean builds, same sha256 for ' + ', '.join(f'{n} {h}' for n, h in sorted(reproduced.items())),
        'app signature: RSA-3072 (Secure Boot V2 scheme, the owner OTA key); the signature block alone differs between signings (RSA-PSS)',
        f'build archive: {archive.name} (ELF, map, sources and SDK inputs stay there; they are not published)',
        *lines,
        *([f'toolchain: {t}' for t in toolchain.splitlines() if t.strip()]),
    ]
    (out / 'BUILD_INFO.txt').write_text('\n'.join(info) + '\n')
    names = sorted(PACKAGE_FILES - {'SHA256SUMS'})
    (out / 'SHA256SUMS').write_text(''.join(f'{sha256(out / n)}  {n}\n' for n in names))
    remove_appledouble(out)
    check_package(out)
    return out


def remove_appledouble(directory):
    """The SMB share (the store) leaves a '._<name>' AppleDouble file beside every file written there. Only those
    beside our own files are removed; nothing of them is ever published (uploads go by name)."""
    for name in PACKAGE_FILES | PUBLISHED_EXTRA:
        junk = Path(directory) / ('._' + name)
        if junk.is_file() and junk.stat().st_size <= 4096:
            junk.unlink()


def _info(pkg):
    values = {}
    for line in (Path(pkg) / 'BUILD_INFO.txt').read_text().splitlines():
        if ': ' in line and not line.startswith('part: ') and not line.startswith('toolchain: '):
            key, value = line.split(': ', 1)
            values.setdefault(key, value)
    return values


def check_package(pkg, allow_published=False):
    """A package tools/release_package.sh made: exactly its files, each one matching SHA256SUMS, the name equal to
    the tag, the tag naming the version, build and the shipped app. Returns the facts tools/release_publish.sh needs."""
    pkg = Path(pkg)
    if not pkg.is_dir():
        raise ValueError(f'no package directory {pkg}')
    present = {p.name for p in pkg.iterdir() if not p.name.startswith('._')}
    allowed = PACKAGE_FILES | (PUBLISHED_EXTRA if allow_published else set())
    if present - allowed:
        raise ValueError('package holds files that are never published: ' + ', '.join(sorted(present - allowed)))
    if PACKAGE_FILES - present:
        raise ValueError('package lacks: ' + ', '.join(sorted(PACKAGE_FILES - present)))
    sums = {}
    for line in (pkg / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1)
        sums[name] = digest
    if set(sums) != PACKAGE_FILES - {'SHA256SUMS'}:
        raise ValueError('SHA256SUMS does not list exactly the four parts and BUILD_INFO.txt')
    for name, digest in sums.items():
        if sha256(pkg / name) != digest:
            raise ValueError(f'{name} does not match SHA256SUMS')
    info = _info(pkg)
    tag = info.get('tag', '')
    match = TAG_RE.match(tag)
    if not match:
        raise ValueError(f'BUILD_INFO.txt tag {tag!r} is not guardian-<x.y.z>-b<n>-<sha12>')
    if pkg.name != tag:
        raise ValueError(f'package name {pkg.name} is not its tag {tag}')
    if match.group(1) != info.get('version') or match.group(2) != info.get('build'):
        raise ValueError('BUILD_INFO.txt version/build differ from the tag')
    if match.group(3) != sums[APP][:12]:
        raise ValueError('the tag does not name the shipped app (sha256 prefix)')
    app = (pkg / APP).read_bytes()
    if len(app) < 80 or app[0] != 0xE9 or int.from_bytes(app[32:36], 'little') != 0xABCD5432:
        raise ValueError(f'{APP} is not an ESP-IDF app image')
    app_version = app[48:80].split(b'\0', 1)[0].decode('ascii')
    if app_version != info.get('app_version') or not app_version.endswith('-rel'):
        raise ValueError(f'the app carries version {app_version!r}, BUILD_INFO.txt says {info.get("app_version")!r} (a release build ends in -rel)')
    parts = [{'file': name, 'offset': offset, 'sha256': sums[name], 'size': (pkg / name).stat().st_size} for offset, name, _ in PARTS]
    return {'tag': tag, 'version': info['version'], 'build': int(info['build']), 'tree': info.get('tree'),
            'commit': info.get('git commit', ''), 'app_version': app_version, 'parts': parts}


def manifest_bytes(facts, date, notes):
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', date):
        raise ValueError('date must be YYYY-MM-DD')
    if not notes.strip() or len(notes) > NOTES_MAX:
        raise ValueError(f'notes must be 1 to {NOTES_MAX} characters')
    data = json.dumps({'tag': facts['tag'], 'version': facts['version'], 'build': facts['build'], 'date': date,
                       'notes': notes, 'parts': facts['parts']}, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    parse_manifest(data)
    return data


def parse_manifest(data):
    """The rules the website applies to a manifest (W07): the exact shape, the four parts at their offsets, a tag
    that names the version, the build and the app's sha256."""
    if len(data) > MANIFEST_MAX:
        raise ValueError('manifest larger than 4 KiB')
    m = json.loads(data.decode('utf-8'))
    if not isinstance(m, dict) or set(m) != {'tag', 'version', 'build', 'date', 'notes', 'parts'}:
        raise ValueError('manifest keys must be tag, version, build, date, notes, parts')
    match = TAG_RE.match(m['tag']) if isinstance(m['tag'], str) else None
    if not match or match.group(1) != m['version'] or not isinstance(m['build'], int) or match.group(2) != str(m['build']):
        raise ValueError('manifest tag, version and build disagree')
    if not isinstance(m['parts'], list) or len(m['parts']) != len(PARTS):
        raise ValueError('manifest must list the four parts')
    for part, (offset, name, _) in zip(m['parts'], PARTS):
        if not isinstance(part, dict) or set(part) != {'file', 'offset', 'sha256', 'size'} or part['file'] != name or part['offset'] != offset:
            raise ValueError(f'manifest part {part!r} is not {name} at 0x{offset:x}')
        if not re.fullmatch(r'[0-9a-f]{64}', str(part['sha256'])) or not isinstance(part['size'], int) or part['size'] <= 0:
            raise ValueError(f'manifest part {name}: bad sha256 or size')
    if m['parts'][-1]['sha256'][:12] != match.group(3):
        raise ValueError('manifest tag does not name the app part')
    return m


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('number')
    s = sub.add_parser('stamp'); s.add_argument('epoch')
    s = sub.add_parser('compare'); s.add_argument('first'); s.add_argument('second'); s.add_argument('--record')
    s = sub.add_parser('package'); s.add_argument('archive'); s.add_argument('parent'); s.add_argument('--record', required=True)
    s.add_argument('--commit', required=True); s.add_argument('--tree', required=True); s.add_argument('--toolchain', default='')
    s = sub.add_parser('check'); s.add_argument('pkg'); s.add_argument('--published', action='store_true')
    s = sub.add_parser('manifest'); s.add_argument('pkg'); s.add_argument('--date', required=True); s.add_argument('--notes', required=True)
    s = sub.add_parser('parse-manifest'); s.add_argument('file')
    a = p.parse_args(argv)
    try:
        if a.cmd == 'number':
            version, build = read_release_number(); print(f'version={version}\nbuild={build}')
        elif a.cmd == 'stamp':
            print(commit_stamp(a.epoch))
        elif a.cmd == 'compare':
            sums = compare_builds(a.first, a.second)
            if a.record: Path(a.record).write_text(json.dumps(sums, indent=2) + '\n')
            for name, digest in sums.items(): print(f'{digest}  {name}')
        elif a.cmd == 'package':
            version, build = read_release_number()
            toolchain = Path(a.toolchain).read_text() if a.toolchain else ''
            print(make_package(a.archive, a.parent, version, build, a.commit, a.tree, json.loads(Path(a.record).read_text()), toolchain))
        elif a.cmd == 'check':
            facts = check_package(a.pkg, a.published)
            for key in ('tag', 'version', 'build', 'tree', 'commit', 'app_version'): print(f'{key}={facts[key]}')
            for part in facts['parts']: print(f'part={part["file"]}@0x{part["offset"]:x}:{part["size"]}:{part["sha256"]}')
        elif a.cmd == 'manifest':
            facts = check_package(a.pkg, True)
            (Path(a.pkg) / 'manifest.json').write_bytes(manifest_bytes(facts, a.date, a.notes))
            remove_appledouble(a.pkg)
            print(Path(a.pkg) / 'manifest.json')
        elif a.cmd == 'parse-manifest':
            m = parse_manifest(Path(a.file).read_bytes())
            print(f'tag={m["tag"]}\nversion={m["version"]}\nbuild={m["build"]}')
    except (ValueError, OSError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f'release_support: {e}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

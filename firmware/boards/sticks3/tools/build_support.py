#!/usr/bin/env python3
"""Guard owned scratch directories and archive complete, relocatable images."""
import os,re,argparse,hashlib,json,shlex,shutil,tarfile,tempfile,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
PROJECT=ROOT/'firmware/boards/sticks3'
MARKER='.guardian-build-owner.json'

def checked_path(path):
    path=Path(path)
    if path.is_symlink():raise ValueError('symlink build directory refused')
    p=path.resolve()
    bases=[Path('/private/tmp').resolve(),Path(tempfile.gettempdir()).resolve()]
    store=os.environ.get('GUARDIAN_STORE')   # build.sh exports the resolved store
    if store:bases.append((Path(store)/'build-cache').resolve())
    if not any(p!=b and p.is_relative_to(b) for b in bases):raise ValueError('build directory must be a dedicated scratch/cache child')
    if p==ROOT or p.is_relative_to(ROOT) or ROOT.is_relative_to(p):raise ValueError('source directory refused')
    return p

def initialize(path):
    p=checked_path(path)
    if p.exists() and any(p.iterdir()) and not (p/MARKER).is_file():raise ValueError('nonempty unowned build directory refused')
    p.mkdir(parents=True,exist_ok=True)
    if (p/MARKER).exists() and json.loads((p/MARKER).read_text())!={'project':str(PROJECT)}:raise ValueError('wrong build owner')
    (p/MARKER).write_text(json.dumps({'project':str(PROJECT)})+'\n')
    return p

def clean(path):
    p=checked_path(path)
    if not (p/MARKER).is_file() or json.loads((p/MARKER).read_text())!={'project':str(PROJECT)}:raise ValueError('refusing to clean without matching owner marker')
    shutil.rmtree(p)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def verified_copy(source,target):
    before=digest(source)
    target=Path(target);target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source,target)
    if digest(target)!=before or digest(source)!=before:
        raise ValueError('copy/input integrity failed: '+str(source))
    return before

def qualify_sdk(sdk):
    sdk=Path(sdk)
    def git(path,*args):
        return subprocess.check_output(['git','-C',str(path),*args],text=True)
    if git(sdk,'rev-parse','HEAD').strip()!='67c1de1eebe095d554d281952fde63c16ee2dca0':
        raise ValueError('wrong SDK revision')
    submodules=git(sdk,'submodule','status','--recursive').splitlines()
    # Every SDK input is the vendor original at the pinned revision: any change, untracked file or moved
    # submodule is refused. (Until 2026-11-20 one modified esp32s3/libnet80211.a was allowed; the
    # vendor original was restored that day, see THIRD_PARTY_NOTICES.md.)
    def check_status(path):
        for line in git(path,'status','--porcelain','--untracked-files=all').splitlines():
            raise ValueError('unarchived SDK change: '+str(path)+' '+line)
    check_status(sdk)
    for line in submodules:
        if not line.startswith(' '):raise ValueError('unqualified SDK submodule: '+line)
        check_status(sdk/line[1:].split()[1])
    return {'head':git(sdk,'rev-parse','HEAD').strip(),'submodules':submodules}

APP_DESC_MAGIC=0xABCD5432
SIGNED_APP='guardian_sticks3-signed.bin'
def app_version(image):
    """esp_app_desc_t.version of an ESP-IDF app image (header 24 B + first segment header 8 B, version at +16)."""
    if len(image)<80 or image[0]!=0xE9 or int.from_bytes(image[32:36],'little')!=APP_DESC_MAGIC:raise ValueError('not an ESP-IDF app image with an app descriptor')
    return image[48:80].split(b'\0',1)[0].decode('ascii')

# G16B: an existing build directory keeps its old sdkconfig values, so the
# archive refuses any build that did not actually enable signing + rollback.
REQUIRED_OTA_CONFIG=['CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT','CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME',
                     'CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT','CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE']
# Review 2026-11-17: the same staleness applies to every value in sdkconfig.defaults (a new
# main task stack size never reached the image otherwise): each must be in the built sdkconfig.
DEFAULTS=Path(__file__).resolve().parents[1]/'sdkconfig.defaults'
def defaults_config():
    out=[]
    for line in DEFAULTS.read_text().splitlines():
        line=line.strip()
        if line.startswith('CONFIG_') and '=' in line:k,v=line.split('=',1);out.append((k,v))
    return out
def built_line(key,value):
    return '# '+key+' is not set' if value=='n' else key+'='+value
def check_config(build,version):
    lines=set((build/'sdkconfig').read_text().splitlines())
    for key in REQUIRED_OTA_CONFIG:
        if key+'=y' not in lines:raise ValueError('build lacks '+key+'=y (stale sdkconfig in the build directory?)')
    for key,value in defaults_config():
        if built_line(key,value) not in lines:raise ValueError('build sdkconfig differs from sdkconfig.defaults: '+built_line(key,value)+' (stale sdkconfig in the build directory?)')
    forced='CONFIG_GUARDIAN_OTA_SELFTEST_FAIL=y' in lines
    if forced!=version.endswith('-stfail'):raise ValueError('self-test-fail test image must be built by build-selftest-fail and carry the -stfail version suffix')
    # G16H: the BLE coexistence spike image is never mistaken for (or installed as) a normal build.
    spike='CONFIG_GUARDIAN_BLE_SPIKE=y' in lines
    if spike!=version.endswith('-blespk'):raise ValueError('BLE spike image must be built by build-ble-spike and carry the -blespk version suffix')
    # G16Q: the art bench image (candidate portraits, no radio capture) is never mistaken for a Guardian build.
    bench='CONFIG_GUARDIAN_ART_BENCH=y' in lines
    if bench!=version.endswith('-bench'):raise ValueError('art bench image must be built by build-art-bench and carry the -bench version suffix')
    return forced,spike,bench

def check_signing(build):
    """G16B: the archived flash image is the owner-signed app; its record and version agree."""
    version=(build/'guardian_app_version.txt').read_text().strip()
    unsigned=(build/'guardian_sticks3.bin').read_bytes();signed=(build/SIGNED_APP).read_bytes()
    record=json.loads((build/'signing.json').read_text())
    if record.get('scheme')!='rsa3072-sbv2':raise ValueError('unexpected signature scheme')
    if record.get('unsigned_sha256')!=hashlib.sha256(unsigned).hexdigest() or record.get('signed_sha256')!=hashlib.sha256(signed).hexdigest():raise ValueError('signing record does not match the images')
    if record.get('public_key_sha256')!=digest(build/'ota-signing-public.pem'):raise ValueError('signing record does not match the public key')
    if not signed.startswith(unsigned) or len(signed)<=len(unsigned):raise ValueError('signed image is not the unsigned image plus a signature block')
    if app_version(unsigned)!=version or app_version(signed)!=version or record.get('app_version')!=version:raise ValueError('app image version differs from the requested version')
    return version

# G21: the shipped artifact is the product. The 3D head's frame sets are embedded in the app, so the archive
# refuses an image that does not hold, byte for byte and exactly once, every set the manifest pins by sha256
# (firmware/art/persona/v3/frames/manifest.json, written by tools/face3d/pack_frames.py), a source folder with a
# set the manifest does not list (CMake would embed it), and a signed app that does not fit one OTA slot.
HEAD3D_DIR=ROOT/'firmware/art/persona/v3/frames'
HEAD3D_MOODS=('VeryGood','Good','Medium','Bad','Horrible')
PARTITIONS=PROJECT/'partitions.csv'
def ota_slot_bytes(partitions=None):
    sizes={}
    for line in Path(partitions or PARTITIONS).read_text().splitlines():
        cells=[c.strip() for c in line.split('#')[0].split(',')]
        if len(cells)>=5 and cells[0] in ('ota_0','ota_1'):sizes[cells[0]]=int(cells[4],0)
    if set(sizes)!={'ota_0','ota_1'} or sizes['ota_0']!=sizes['ota_1']:raise ValueError('partition table without two equal OTA slots')
    return sizes['ota_0']
def check_head3d(build,head_dir=None,expected=True):
    """expected=False (G16Q art bench image, built without the 3D head to make room for its frames): no pinned
    set may be in the image; the record lists what was left out."""
    build=Path(build);head_dir=Path(head_dir or HEAD3D_DIR)
    unsigned=(build/'guardian_sticks3.bin').read_bytes();signed=(build/SIGNED_APP).read_bytes()
    manifest=json.loads((head_dir/'manifest.json').read_text()) if (head_dir/'manifest.json').is_file() else {'sets':{}}
    sets=manifest.get('sets',{})
    for mood in HEAD3D_MOODS:
        if mood not in sets and (head_dir/(mood+'.bin')).exists():raise ValueError('3D head set '+mood+'.bin is not in the manifest')
    record={}
    for mood,rec in sets.items():
        if mood not in HEAD3D_MOODS or rec.get('file')!=mood+'.bin':raise ValueError('3D head manifest names an unknown set: '+str(mood))
        path=head_dir/rec['file']
        if not path.is_file():raise ValueError('3D head set missing: '+rec['file'])
        data=path.read_bytes()
        if hashlib.sha256(data).hexdigest()!=rec.get('file_sha256') or len(data)!=rec.get('bytes'):raise ValueError('3D head set differs from its manifest: '+rec['file'])
        for name,image in (('guardian_sticks3.bin',unsigned),(SIGNED_APP,signed)):
            if image.count(data)!=(1 if expected else 0):raise ValueError('3D head set '+rec['file']+' is in '+name+' '+str(image.count(data))+' times, expected '+('once' if expected else 'none (art bench image)'))
        if not expected:continue
        record[mood]={'file':rec['file'],'sha256':rec['file_sha256'],'bytes':len(data),'frames':len(rec.get('frames',[])),'offset_in_app':unsigned.find(data)}
    slot=ota_slot_bytes()
    if len(signed)>slot:raise ValueError('signed app is '+str(len(signed))+' B, larger than the OTA slot of '+str(slot)+' B')
    out={'sets':record,'set_bytes':sum(r['bytes'] for r in record.values()),'signed_app_bytes':len(signed),'ota_slot_bytes':slot,'ota_slot_free_bytes':slot-len(signed)}
    if not expected:out['left_out']=sorted(rec['file'] for rec in sets.values())
    return out

# G16Q: the art bench image embeds the candidate frames pinned in firmware/art/bench/manifest.json (written by
# tools/art/candidates.py). The archive refuses a bench image that does not hold each of them byte for byte and
# exactly once, a frame on disk that differs from its pin, and a normal image that holds any of them.
BENCH_DIR=ROOT/'firmware/art/bench'
def check_bench(build,bench,bench_dir=None):
    build=Path(build);bench_dir=Path(bench_dir or BENCH_DIR)
    unsigned=(build/'guardian_sticks3.bin').read_bytes();signed=(build/SIGNED_APP).read_bytes()
    manifest=json.loads((bench_dir/'manifest.json').read_text()) if (bench_dir/'manifest.json').is_file() else {'files':{}}
    files=manifest.get('files',{})
    if bench and not files:raise ValueError('art bench image, but '+str(bench_dir)+' has no pinned frames')
    record={}
    for name,pin in sorted(files.items()):
        path=bench_dir/name
        if Path(name).name!=name or not name.endswith('.rgb565'):raise ValueError('bench manifest names an unexpected file: '+name)
        if not path.is_file():raise ValueError('bench frame missing: '+name)
        data=path.read_bytes()
        if hashlib.sha256(data).hexdigest()!=pin or len(data)!=manifest.get('frame_bytes'):raise ValueError('bench frame '+name+' differs from its pin')
        for label,image in (('guardian_sticks3.bin',unsigned),(SIGNED_APP,signed)):
            if image.count(data)!=(1 if bench else 0):raise ValueError('bench frame '+name+' is in '+label+' '+str(image.count(data))+' times, expected '+('once' if bench else 'none (not the art bench image)'))
        record[name]={'sha256':pin,'bytes':len(data),'offset_in_app':unsigned.find(data)}
    if not bench:return None
    return {'frames':record,'frame_bytes':sum(r['bytes'] for r in record.values())}

def archive(build,out):
    build=Path(build).resolve();out=Path(out)
    if out.exists():raise ValueError('archive destination already exists')
    required=['guardian_sticks3.bin','guardian_sticks3.elf','guardian_sticks3.map','sdkconfig','flasher_args.json','toolchain.txt','sdk-worktree.txt','sdk-submodules.txt','size.txt','sdk-inputs/qualification.json','sdk-inputs/libnet80211.a','sdk-inputs/LICENSE',
              SIGNED_APP,'signing.json','ota-signing-public.pem','guardian_app_version.txt']
    config=json.loads((build/'flasher_args.json').read_text());flash=config.get('flash_files',{})
    # G16B OTA layout (partitions.csv): otadata 0x10000, ota_0 0x20000.
    expected={0:'bootloader/bootloader.bin',0x8000:'partition_table/partition-table.bin',0x10000:'ota_data_initial.bin',0x20000:'guardian_sticks3.bin'}
    numeric={int(k,0):v for k,v in flash.items()}
    if len(numeric)!=len(flash) or numeric!=expected:raise ValueError('incomplete/wrong StickS3 flash map')
    for name in flash.values():
        p=Path(name)
        if p.is_absolute() or '..' in p.parts or not (build/p).resolve().is_relative_to(build):raise ValueError('escaping flash path refused')
        required.append(name)
    required += [str(p.relative_to(build)) for p in (build/'sdk-inputs').rglob('*') if p.is_file()]
    for name in required:
        if not (build/name).is_file():raise ValueError('missing required output: '+name)
    version=check_signing(build)
    selftest_fail,ble_spike,art_bench_image=check_config(build,version)
    head3d=check_head3d(build,expected=not art_bench_image)   # G21: before anything is written (G16Q: the bench leaves the head out)
    art_bench=check_bench(build,art_bench_image)
    out.mkdir(parents=True)
    inputs={}
    for name in sorted(set(required)):inputs[name]=verified_copy(build/name,out/name)
    args=list(config.get('write_flash_args',[]))
    for offset,name in flash.items():args.extend([offset,SIGNED_APP if name=='guardian_sticks3.bin' else name])   # only the signed app is ever flashed
    (out/'flash_args').write_text(shlex.join(args)+'\n')
    for name in ['CMakeCache.txt','project_description.json']:
        if (build/name).is_file():inputs[name]=verified_copy(build/name,out/name)
    sources=[p for p in (ROOT/'firmware').rglob('*') if p.is_file() and p.suffix in ('.cpp','.hpp','.h','.csv','.py','.sh','.txt','.defaults','.md') and '__pycache__' not in p.parts and 'build' not in p.parts]
    # G21: the frame sets and their manifest are build inputs (binary, so not matched by the suffix list), and the pipeline that made them.
    if Path(HEAD3D_DIR).resolve().is_relative_to(ROOT):sources += [p for p in Path(HEAD3D_DIR).glob('*') if p.is_file() and (p.suffix=='.bin' or p.name=='manifest.json')]
    sources += [p for p in (ROOT/'tools/face3d').glob('*.py')]
    # G16Q: the bench frames, their manifest and the tool that made them.
    if Path(BENCH_DIR).resolve().is_relative_to(ROOT):sources += [p for p in Path(BENCH_DIR).glob('*') if p.is_file() and (p.suffix=='.rgb565' or p.name=='manifest.json')]
    sources += [p for p in (ROOT/'tools/art').glob('*.py')]
    sources += [p for p in ROOT.iterdir() if p.is_file() and (p.name.startswith(('LICENSE','COPYING','NOTICE')) or p.name=='THIRD_PARTY_NOTICES.md')]
    sources += list((ROOT/'docs').rglob('*.md'))
    # G13 reuses the lab receiver wire format; keep this native build input.
    sources += [ROOT/'lab/receiver/main/wire.hpp']
    sources=sorted(set(sources))
    source_hashes={str(p.relative_to(ROOT)):digest(p) for p in sources}
    (out/'source-sha256.json').write_text(json.dumps(source_hashes,indent=2)+'\n')
    with tarfile.open(out/'source.tar.gz','w:gz') as tar:
        for p in sources:tar.add(p,arcname=str(p.relative_to(ROOT)))
    with tarfile.open(out/'source.tar.gz') as tar:
        for name,h in source_hashes.items():
            if hashlib.sha256(tar.extractfile(name).read()).hexdigest()!=h or digest(ROOT/name)!=h:
                raise ValueError('source archive mismatch: '+name)
    (out/'input-sha256.json').write_text(json.dumps(inputs,indent=2)+'\n')
    hashes={str(p.relative_to(out)):digest(p) for p in out.rglob('*') if p.is_file() and not p.name.startswith('._')}
    for name,h in hashes.items():
        if digest(out/name)!=h:raise ValueError('archive readback failed: '+name)
    (out/'SHA256SUMS').write_text(''.join(h+'  '+n+'\n' for n,h in sorted(hashes.items())))
    (out/'COMPLETE.json').write_text(json.dumps({'complete':True,'app_version':version,'signed_app':SIGNED_APP,'selftest_fail_test_image':selftest_fail,'ble_spike_image':ble_spike,'art_bench_image':art_bench_image,'art_bench':art_bench,'head3d':head3d,'sha256':hashes,'hardware_verified':False},indent=2)+'\n')
    return out

# G16C rework: the default version names the build (date-time), never a task, so
# STATUS and the OTA manifest show which build runs. <= 31 chars with -stfail.
def default_app_version(at=None,suffix=''):
    import datetime
    v='guardian-'+(at or datetime.datetime.now()).strftime('%Y%m%d-%H%M%S')+suffix
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,31}',v):raise ValueError('bad app version: '+v)
    return v

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['init','clean','archive','sdk','resolve','version-stamp']);parser.add_argument('path');parser.add_argument('destination',nargs='?');a=parser.parse_args()
    if a.action=='version-stamp':print(default_app_version(suffix={'none':'','stfail':'-stfail','blespk':'-blespk','bench':'-bench'}[a.path]))
    elif a.action=='resolve':print(checked_path(a.path))
    elif a.action=='sdk':print(json.dumps(qualify_sdk(a.path),indent=2))
    elif a.action=='init':print(initialize(a.path))
    elif a.action=='clean':clean(a.path)
    else:
        if not a.destination:parser.error('archive needs destination')
        print(archive(a.path,a.destination))
if __name__=='__main__':main()

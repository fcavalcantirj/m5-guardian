#!/usr/bin/env python3
"""Exercise the actual qualification wrapper using isolated simulated builds.
No library behavior, native runtime or radio evidence is claimed by this check.
The wrapper itself requires the artifact store (GUARDIAN_STORE: mounted share and sentinel) before writing outputs.
"""
from pathlib import Path
import tempfile,subprocess,os,json,shutil,sys
r=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(r/'tools'))
import guardian_local
try:guardian_store=guardian_local.store()
except guardian_local.Missing as e:raise SystemExit(f'Artifact store required: {e}')
store=Path(os.environ.get('GUARDIAN_G12_TEST_PARENT',str(guardian_store/'builds'))).resolve();results=[]
if not store.is_relative_to(guardian_store):
 raise SystemExit('Test output must stay below the artifact store')
for mutate in (False,True):
 with tempfile.TemporaryDirectory(prefix='guardian-g12-guard-') as d:
  root=Path(d);fw=root/'firmware';(fw/'tools').mkdir(parents=True);(fw/'components/guardian_core').mkdir(parents=True);(fw/'CMakeLists.txt').write_text('# fixture\n');source=fw/'components/guardian_core/core.cpp';source.write_text('// original\n')
  script=fw/'tools/qualify-targets.sh';shutil.copyfile(r/'firmware/tools/qualify-targets.sh',script)
  guard=fw/'boards/sticks3/tools/build_support.py';guard.parent.mkdir(parents=True);guard.write_text('# simulated SDK guard input\n')
  bin=root/'bin';bin.mkdir()
  for name in ('cmake','ctest','c++','ninja'):
   p=bin/name;p.write_text('#!/bin/sh\nif [ "$1" = "--build" ] && [ "${G12_MUTATE:-}" = 1 ]; then echo "// changed during build" >> "$G12_SOURCE"; fi\nexit 0\n' if name=='cmake' else '#!/bin/sh\nexit 0\n');p.chmod(0o755)
  parent=store/'wrapper-fixtures';parent.mkdir(exist_ok=True)
  env=dict(os.environ,PATH=str(bin)+':'+os.environ['PATH'],GUARDIAN_QUALIFICATION_PARENT=str(parent),G12_SOURCE=str(source),G12_MUTATE='1' if mutate else '0')
  p=subprocess.run(['bash',str(script),'host'],env=env,text=True,capture_output=True)
  results.append({'modified_source':mutate,'exit':p.returncode,'expected':1 if mutate else 0,'output':p.stdout.strip()})
print(json.dumps(results,indent=2));raise SystemExit(0 if all((x['exit']!=0)==x['modified_source'] for x in results) else 1)

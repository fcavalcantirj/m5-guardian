import importlib.util,json,tempfile,unittest,tarfile,os,sys,subprocess
from unittest.mock import patch
from pathlib import Path
s=importlib.util.spec_from_file_location('build_support',Path(__file__).resolve().parents[1]/'tools/build_support.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class BuildSupportTests(unittest.TestCase):
 # G21: archive() checks the image against the 3D head frame sets. The tests use their own small pack
 # (the check reads files and hashes; it does not parse frames) instead of the repository's 0.9 MB one.
 HEAD_SET=b'GH3D'+bytes(range(256))*4
 def setUp(self):
  import hashlib
  self._head=tempfile.TemporaryDirectory();self.head=Path(self._head.name)
  (self.head/'Medium.bin').write_bytes(self.HEAD_SET)
  (self.head/'manifest.json').write_text(json.dumps({'sets':{'Medium':{'file':'Medium.bin','file_sha256':hashlib.sha256(self.HEAD_SET).hexdigest(),'bytes':len(self.HEAD_SET),'frames':[{},{}]}}}))
  self._saved=m.HEAD3D_DIR;m.HEAD3D_DIR=self.head
  # G16Q: the art bench image is checked against its pinned frames the same way (own small pack).
  self._bench=tempfile.TemporaryDirectory();self.bench=Path(self._bench.name)
  for name,data in self.BENCH_FRAMES.items():(self.bench/name).write_bytes(data)
  (self.bench/'manifest.json').write_text(json.dumps({'frame_bytes':len(self.BENCH_FRAMES['ramp.rgb565']),'files':{n:hashlib.sha256(d).hexdigest() for n,d in self.BENCH_FRAMES.items()}}))
  self._saved_bench=m.BENCH_DIR;m.BENCH_DIR=self.bench
 BENCH_FRAMES={'A_VeryGood.rgb565':b'BNCH-A'+bytes(range(250))*3,'ramp.rgb565':b'BNCH-R'+bytes(reversed(range(250)))*3}
 BENCH_TAIL=BENCH_FRAMES['A_VeryGood.rgb565']+b'..'+BENCH_FRAMES['ramp.rgb565']
 def tearDown(self):
  m.HEAD3D_DIR=self._saved;self._head.cleanup()
  m.BENCH_DIR=self._saved_bench;self._bench.cleanup()
 def test_clean_refuses_unowned_or_source_paths(self):
  with self.assertRaises(ValueError):m.clean(m.ROOT)
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'unowned';p.mkdir();(p/'keep').write_text('mine')
   with self.assertRaises(ValueError):m.clean(p)
   self.assertTrue((p/'keep').exists())
 def test_owned_directory_can_be_cleaned(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'build';m.initialize(p);m.clean(p);self.assertFalse(p.exists())
 def test_symlink_is_not_a_clean_target(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'build';m.initialize(p);alias=Path(d)/'alias';alias.symlink_to(p)
   with self.assertRaises(ValueError):m.clean(alias)
   self.assertTrue(p.exists())
 @staticmethod
 def app_image(version,tail=b''):
  # ESP image header (magic 0xE9) + first segment header, then esp_app_desc_t
  # (magic 0xABCD5432, secure_version, reserv1[2], version[32] at byte 48).
  head=bytes([0xE9])+bytes(31)
  desc=(0xABCD5432).to_bytes(4,'little')+bytes(12)+version.encode().ljust(32,b'\0')
  return head+desc+bytes(64)+tail
 def seed(self,p,version='g16b-20261116-200000'):
  (p).mkdir(parents=True,exist_ok=True)
  (p/'sdkconfig').write_text(''.join(m.built_line(k,v)+'\n' for k,v in m.defaults_config())+''.join(k+'=y\n' for k in m.REQUIRED_OTA_CONFIG)+('CONFIG_GUARDIAN_OTA_SELFTEST_FAIL=y\n' if version.endswith('-stfail') else '# CONFIG_GUARDIAN_OTA_SELFTEST_FAIL is not set\n')+('CONFIG_GUARDIAN_BLE_SPIKE=y\n' if version.endswith('-blespk') else '# CONFIG_GUARDIAN_BLE_SPIKE is not set\n')+('CONFIG_GUARDIAN_ART_BENCH=y\n' if version.endswith('-bench') else '# CONFIG_GUARDIAN_ART_BENCH is not set\n')+('CONFIG_PM_ENABLE=y\nCONFIG_GUARDIAN_DARK_CPU=y\n' if version.endswith('-dcpu') else ''))
  for name in ['guardian_sticks3.elf','guardian_sticks3.map','toolchain.txt','sdk-worktree.txt','sdk-submodules.txt','size.txt','sdk-inputs/qualification.json','sdk-inputs/libnet80211.a','sdk-inputs/LICENSE','bootloader/bootloader.bin','partition_table/partition-table.bin','ota_data_initial.bin','ota-signing-public.pem']:
   f=p/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(name)
  tail=self.BENCH_TAIL if version.endswith('-bench') else self.HEAD_SET   # G21: the frame set is in the image; G16Q: the bench image holds its frames instead
  unsigned=self.app_image(version,tail);signed=self.app_image(version,tail+b'SIGBLOCK')
  (p/'guardian_sticks3.bin').write_bytes(unsigned);(p/'guardian_sticks3-signed.bin').write_bytes(signed)
  (p/'guardian_app_version.txt').write_text(version+'\n')
  import hashlib
  (p/'signing.json').write_text(json.dumps({'scheme':'rsa3072-sbv2','unsigned_sha256':hashlib.sha256(unsigned).hexdigest(),'signed_sha256':hashlib.sha256(signed).hexdigest(),'public_key_sha256':hashlib.sha256(b'ota-signing-public.pem').hexdigest(),'app_version':version}))
  (p/'flasher_args.json').write_text(json.dumps(dict(flash_files={'0x0':'bootloader/bootloader.bin','0x8000':'partition_table/partition-table.bin','0x10000':'ota_data_initial.bin','0x20000':'guardian_sticks3.bin'},write_flash_args=['--flash_size','8MB'])))
 # ---- G21: the shipped image holds every pinned 3D head frame set and fits the OTA slot ----
 def resign(self,b,unsigned,version='g16b-20261116-200000'):
  import hashlib
  signed=unsigned+b'SIGBLOCK';(b/'guardian_sticks3.bin').write_bytes(unsigned);(b/'guardian_sticks3-signed.bin').write_bytes(signed)
  rec=json.loads((b/'signing.json').read_text());rec['unsigned_sha256']=hashlib.sha256(unsigned).hexdigest();rec['signed_sha256']=hashlib.sha256(signed).hexdigest()
  (b/'signing.json').write_text(json.dumps(rec))
 def test_archive_records_the_frame_sets_found_in_the_image_and_the_slot_room(self):
  import hashlib
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);m.archive(b,o)
   h=json.loads((o/'COMPLETE.json').read_text())['head3d']
   self.assertEqual(h['sets']['Medium'],{'file':'Medium.bin','sha256':hashlib.sha256(self.HEAD_SET).hexdigest(),'bytes':len(self.HEAD_SET),'frames':2,
                                         'offset_in_app':(b/'guardian_sticks3.bin').read_bytes().find(self.HEAD_SET)})
   self.assertEqual(h['ota_slot_bytes'],0x300000);self.assertEqual(h['signed_app_bytes'],(o/'guardian_sticks3-signed.bin').stat().st_size)
   self.assertEqual(h['ota_slot_free_bytes'],0x300000-h['signed_app_bytes']);self.assertEqual(h['set_bytes'],len(self.HEAD_SET))
 def test_image_without_a_pinned_frame_set_cannot_complete(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);self.resign(b,self.app_image('g16b-20261116-200000',self.HEAD_SET[:-1]+b'X'))   # one byte differs
   with self.assertRaisesRegex(ValueError,'Medium.bin'):m.archive(b,o)
   self.assertFalse(o.exists())
  with tempfile.TemporaryDirectory() as d:   # embedded twice: one copy too many
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);self.resign(b,self.app_image('g16b-20261116-200000',self.HEAD_SET+b'--'+self.HEAD_SET))
   with self.assertRaisesRegex(ValueError,'2 times'):m.archive(b,o)
 def test_frame_set_that_differs_from_its_manifest_cannot_complete(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);(self.head/'Medium.bin').write_bytes(self.HEAD_SET[:-1]+b'X')
   with self.assertRaisesRegex(ValueError,'differs from its manifest'):m.archive(b,o)
  (self.head/'Medium.bin').unlink()
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b)
   with self.assertRaisesRegex(ValueError,'missing'):m.archive(b,o)
 def test_frame_set_the_manifest_does_not_list_cannot_complete(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);(self.head/'Horrible.bin').write_bytes(b'stray')
   with self.assertRaisesRegex(ValueError,'Horrible.bin is not in the manifest'):m.archive(b,o)
   self.assertFalse(o.exists())
 def test_image_without_any_frame_set_is_allowed_when_none_is_pinned(self):
  (self.head/'Medium.bin').unlink();(self.head/'manifest.json').unlink()
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);m.archive(b,o)
   self.assertEqual(json.loads((o/'COMPLETE.json').read_text())['head3d']['sets'],{})
 def test_app_larger_than_the_ota_slot_cannot_complete(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b)
   self.resign(b,self.app_image('g16b-20261116-200000',self.HEAD_SET+bytes(0x300000-len(self.app_image('g16b-20261116-200000',self.HEAD_SET))-len(b'SIGBLOCK'))))
   m.archive(b,o)                                           # exactly the slot: allowed
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b)
   self.resign(b,self.app_image('g16b-20261116-200000',self.HEAD_SET+bytes(0x300000-len(self.app_image('g16b-20261116-200000',self.HEAD_SET))-len(b'SIGBLOCK')+1)))
   with self.assertRaisesRegex(ValueError,'larger than the OTA slot'):m.archive(b,o)
   self.assertFalse(o.exists())
 def test_the_repository_pack_is_what_its_manifest_pins(self):
  # The real folder (not the test pack): every listed set is there with its sha256, nothing unlisted.
  import hashlib
  real=self._saved;manifest=json.loads((real/'manifest.json').read_text())
  self.assertTrue(manifest['sets'])
  for mood,rec in manifest['sets'].items():
   self.assertEqual(hashlib.sha256((real/rec['file']).read_bytes()).hexdigest(),rec['file_sha256'],mood)
  self.assertEqual(sorted(p.name for p in real.glob('*.bin')),sorted(r['file'] for r in manifest['sets'].values()))
 # ---- G16B: signed OTA images -------------------------------------------------
 # G23 review 2026-11-20: the archive's source copy holds every build input, including the Kconfig menu and the
 # sdkconfig variant files (they decide which image a build makes), and nothing git ignores (caches, sdkconfig.old).
 def test_source_copy_holds_the_kconfig_menu_and_every_sdkconfig_variant(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);m.archive(b,o)
   with tarfile.open(o/'source.tar.gz') as tar:names=set(tar.getnames())
  board=m.PROJECT.relative_to(m.ROOT)
  want={str(board/'main/Kconfig.projbuild')}|{str(board/p.name) for p in m.PROJECT.glob('sdkconfig.*') if p.name!='sdkconfig.old'}
  self.assertTrue({str(board/n) for n in ['sdkconfig.defaults','sdkconfig.art-bench','sdkconfig.ble-spike','sdkconfig.selftest-fail','sdkconfig.dark-cpu']}<=want)
  self.assertEqual(want-names,set())
  self.assertEqual(sorted(n for n in names if Path(n).name=='sdkconfig.old' or {'.pytest_cache','__pycache__','build'}&set(Path(n).parts)),[])
 def test_source_selection_takes_the_git_file_list_and_falls_back_to_the_tree(self):
  keep={'firmware/a.cpp','firmware/boards/sticks3/main/Kconfig.projbuild','firmware/boards/sticks3/sdkconfig.defaults','firmware/boards/sticks3/sdkconfig.dark-cpu'}
  junk=['firmware/boards/sticks3/sdkconfig.old','firmware/t/.pytest_cache/README.md','firmware/t/__pycache__/x.py','firmware/build/gen.cpp','firmware/notes.bin']
  with tempfile.TemporaryDirectory() as d:
   r=Path(d)
   for f in sorted(keep)+junk+['firmware/local.cpp']:(r/f).parent.mkdir(parents=True,exist_ok=True);(r/f).write_text('x')
   (r/'.gitignore').write_text('firmware/local.cpp\n')
   rel=lambda ps:{str(p.relative_to(r)) for p in ps}
   self.assertEqual(rel(m.firmware_sources(r)),keep|{'firmware/local.cpp'})   # not a git checkout: every file, filtered
   subprocess.run(['git','init','-q',str(r)],check=True,capture_output=True)
   self.assertEqual(rel(m.firmware_sources(r)),keep)                          # a checkout: what git does not ignore
 def test_flash_args_install_the_signed_image_at_ota_0(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);m.archive(b,o)
   args=(o/'flash_args').read_text().split()
   self.assertIn('0x20000',args);self.assertEqual(args[args.index('0x20000')+1],'guardian_sticks3-signed.bin')
   self.assertEqual(args[args.index('0x10000')+1],'ota_data_initial.bin')
   self.assertNotIn('guardian_sticks3.bin',args)
   for name in ['guardian_sticks3-signed.bin','guardian_sticks3.bin','signing.json','ota-signing-public.pem','guardian_app_version.txt']:self.assertTrue((o/name).is_file(),name)
   self.assertEqual(json.loads((o/'COMPLETE.json').read_text())['app_version'],'g16b-20261116-200000')
 def test_unsigned_build_cannot_complete(self):
  for missing in ['guardian_sticks3-signed.bin','signing.json','ota-signing-public.pem','guardian_app_version.txt']:
   with tempfile.TemporaryDirectory() as d:
    b=Path(d)/'b';o=Path(d)/'o';self.seed(b);(b/missing).unlink()
    with self.assertRaises((ValueError,OSError)):m.archive(b,o)
    self.assertFalse((o/'COMPLETE.json').exists())
 def test_signing_record_must_match_the_images(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);(b/'guardian_sticks3-signed.bin').write_bytes(self.app_image('g16b-20261116-200000',b'OTHER'))
   with self.assertRaises(ValueError):m.archive(b,o)
   self.assertFalse((o/'COMPLETE.json').exists())
 def test_image_must_carry_the_requested_version(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);(b/'guardian_app_version.txt').write_text('g16b-other\n')
   with self.assertRaises(ValueError):m.archive(b,o)
 def test_factory_flash_map_is_refused(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b)
   (b/'flasher_args.json').write_text(json.dumps(dict(flash_files={'0x0':'bootloader/bootloader.bin','0x8000':'partition_table/partition-table.bin','0x10000':'guardian_sticks3.bin'},write_flash_args=[])))
   with self.assertRaises(ValueError):m.archive(b,o)
 def test_build_without_signing_or_rollback_config_cannot_complete(self):
  for drop in ['CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT','CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT','CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE','CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME']:
   with tempfile.TemporaryDirectory() as d:
    b=Path(d)/'b';o=Path(d)/'o';self.seed(b)
    (b/'sdkconfig').write_text((b/'sdkconfig').read_text().replace(drop+'=y','# '+drop+' is not set'))
    with self.assertRaises(ValueError):m.archive(b,o)
    self.assertFalse((o/'COMPLETE.json').exists())
 def test_stale_build_config_that_differs_from_the_defaults_cannot_complete(self):
  # Review 2026-11-17: an existing build directory keeps its old sdkconfig, so a value changed
  # in sdkconfig.defaults (here the main task stack) would silently not reach the image.
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b)
   want=dict(m.defaults_config())['CONFIG_ESP_MAIN_TASK_STACK_SIZE']
   (b/'sdkconfig').write_text((b/'sdkconfig').read_text().replace('CONFIG_ESP_MAIN_TASK_STACK_SIZE='+want,'CONFIG_ESP_MAIN_TASK_STACK_SIZE=4096'))
   with self.assertRaisesRegex(ValueError,'CONFIG_ESP_MAIN_TASK_STACK_SIZE'):m.archive(b,o)
   self.assertFalse(o.exists())
 def test_defaults_n_matches_not_set(self):
  self.assertEqual(m.built_line('CONFIG_X','n'),'# CONFIG_X is not set')
  self.assertEqual(m.built_line('CONFIG_X','12'),'CONFIG_X=12')
 def test_selftest_fail_image_is_labelled_and_never_a_normal_build(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,'g16b-20261116-200000-stfail');m.archive(b,o)
   self.assertTrue(json.loads((o/'COMPLETE.json').read_text())['selftest_fail_test_image'])
  with tempfile.TemporaryDirectory() as d:   # forced failure without the -stfail label
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);(b/'sdkconfig').write_text((b/'sdkconfig').read_text().replace('# CONFIG_GUARDIAN_OTA_SELFTEST_FAIL is not set','CONFIG_GUARDIAN_OTA_SELFTEST_FAIL=y'))
   with self.assertRaises(ValueError):m.archive(b,o)
  with tempfile.TemporaryDirectory() as d:   # -stfail label on a normal image
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,'g16b-20261116-200000-stfail');(b/'sdkconfig').write_text((b/'sdkconfig').read_text().replace('CONFIG_GUARDIAN_OTA_SELFTEST_FAIL=y','# CONFIG_GUARDIAN_OTA_SELFTEST_FAIL is not set'))
   with self.assertRaises(ValueError):m.archive(b,o)
 # ---- G16H: the Wi-Fi/BLE coexistence spike image ---------------------------------
 def test_ble_spike_image_is_labelled_and_never_a_normal_build(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,'guardian-20261117-050000-blespk');m.archive(b,o)
   self.assertTrue(json.loads((o/'COMPLETE.json').read_text())['ble_spike_image'])
  with tempfile.TemporaryDirectory() as d:   # a normal build records that it is not the spike image
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);m.archive(b,o)
   self.assertFalse(json.loads((o/'COMPLETE.json').read_text())['ble_spike_image'])
  with tempfile.TemporaryDirectory() as d:   # BLE spike config without the -blespk label
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);(b/'sdkconfig').write_text((b/'sdkconfig').read_text().replace('# CONFIG_GUARDIAN_BLE_SPIKE is not set','CONFIG_GUARDIAN_BLE_SPIKE=y'))
   with self.assertRaises(ValueError):m.archive(b,o)
  with tempfile.TemporaryDirectory() as d:   # -blespk label on a normal image
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,'guardian-20261117-050000-blespk');(b/'sdkconfig').write_text((b/'sdkconfig').read_text().replace('CONFIG_GUARDIAN_BLE_SPIKE=y','# CONFIG_GUARDIAN_BLE_SPIKE is not set'))
   with self.assertRaises(ValueError):m.archive(b,o)
 def test_ble_spike_version_stamp_fits(self):
  out=subprocess.run([sys.executable,str(m.PROJECT/'tools/build_support.py'),'version-stamp','blespk'],text=True,capture_output=True)
  self.assertEqual(out.returncode,0,out.stderr)
  self.assertRegex(out.stdout.strip(),r'^guardian-[0-9]{8}-[0-9]{6}-blespk$')
  self.assertLessEqual(len(out.stdout.strip()),31)
  script=(m.PROJECT/'tools/build.sh').read_text()
  self.assertIn('build-ble-spike)',script)
  self.assertIn('sdkconfig.ble-spike',script)
 # ---- G23: the battery-life image (CPU frequency while dark; power management compiled in) ----
 DCPU_VERSION='guardian-20261120-090000-dcpu'
 def test_dark_cpu_image_is_labelled_and_never_a_normal_build(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,self.DCPU_VERSION);m.archive(b,o)
   self.assertTrue(json.loads((o/'COMPLETE.json').read_text())['dark_cpu_image'])
  with tempfile.TemporaryDirectory() as d:   # a normal build records that it is not the dark-cpu image
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);m.archive(b,o)
   self.assertFalse(json.loads((o/'COMPLETE.json').read_text())['dark_cpu_image'])
  with tempfile.TemporaryDirectory() as d:   # the dark-cpu config without the -dcpu label
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);(b/'sdkconfig').write_text((b/'sdkconfig').read_text()+'CONFIG_PM_ENABLE=y\nCONFIG_GUARDIAN_DARK_CPU=y\n')
   with self.assertRaisesRegex(ValueError,'dcpu'):m.archive(b,o)
  with tempfile.TemporaryDirectory() as d:   # -dcpu label on a normal image
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,self.DCPU_VERSION);(b/'sdkconfig').write_text((b/'sdkconfig').read_text().replace('CONFIG_GUARDIAN_DARK_CPU=y\n',''))
   with self.assertRaisesRegex(ValueError,'dcpu'):m.archive(b,o)
  with tempfile.TemporaryDirectory() as d:   # labelled, but power management is not compiled in
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,self.DCPU_VERSION);(b/'sdkconfig').write_text((b/'sdkconfig').read_text().replace('CONFIG_PM_ENABLE=y\n',''))
   with self.assertRaisesRegex(ValueError,'PM_ENABLE'):m.archive(b,o)
 def test_dark_cpu_version_stamp_fits_and_the_variant_is_default_off(self):
  out=subprocess.run([sys.executable,str(m.PROJECT/'tools/build_support.py'),'version-stamp','dcpu'],text=True,capture_output=True)
  self.assertEqual(out.returncode,0,out.stderr)
  self.assertRegex(out.stdout.strip(),r'^guardian-[0-9]{8}-[0-9]{6}-dcpu$')
  self.assertLessEqual(len(out.stdout.strip()),31)
  script=(m.PROJECT/'tools/build.sh').read_text()
  self.assertIn('build-dark-cpu)',script)
  self.assertIn('sdkconfig.dark-cpu',script)
  overlay=(m.PROJECT/'sdkconfig.dark-cpu').read_text()
  self.assertIn('CONFIG_PM_ENABLE=y',overlay);self.assertIn('CONFIG_GUARDIAN_DARK_CPU=y',overlay)
  self.assertNotIn('CONFIG_PM_DFS_INIT_AUTO=y',overlay)   # boots at the sdkconfig frequency, scaling only while dark
  defaults=(m.PROJECT/'sdkconfig.defaults').read_text()
  self.assertNotIn('CONFIG_PM_ENABLE=y',defaults);self.assertNotIn('CONFIG_GUARDIAN_DARK_CPU=y',defaults)   # the normal image is unchanged
  kconfig=(m.PROJECT/'main/Kconfig.projbuild').read_text()
  block=kconfig[kconfig.index('config GUARDIAN_DARK_CPU'):]
  block=block[:block.index('\nconfig ',1)]
  self.assertIn('depends on PM_ENABLE',block);self.assertIn('default n',block)
 # ---- G16Q: the art bench image -----------------------------------------------------
 BENCH_VERSION='guardian-20261118-220000-bench'
 def test_art_bench_image_is_labelled_and_never_a_normal_build(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,self.BENCH_VERSION);m.archive(b,o)
   self.assertTrue(json.loads((o/'COMPLETE.json').read_text())['art_bench_image'])
  with tempfile.TemporaryDirectory() as d:   # a normal build records that it is not the bench image
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);m.archive(b,o)
   done=json.loads((o/'COMPLETE.json').read_text());self.assertFalse(done['art_bench_image']);self.assertIsNone(done['art_bench'])
  with tempfile.TemporaryDirectory() as d:   # bench config without the -bench label
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);(b/'sdkconfig').write_text((b/'sdkconfig').read_text().replace('# CONFIG_GUARDIAN_ART_BENCH is not set','CONFIG_GUARDIAN_ART_BENCH=y'))
   with self.assertRaisesRegex(ValueError,'-bench'):m.archive(b,o)
  with tempfile.TemporaryDirectory() as d:   # -bench label on a normal image
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,self.BENCH_VERSION);(b/'sdkconfig').write_text((b/'sdkconfig').read_text().replace('CONFIG_GUARDIAN_ART_BENCH=y','# CONFIG_GUARDIAN_ART_BENCH is not set'))
   with self.assertRaisesRegex(ValueError,'-bench'):m.archive(b,o)
 def test_art_bench_image_holds_every_pinned_frame_once_and_no_head_set(self):
  import hashlib
  v=self.BENCH_VERSION
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,v);m.archive(b,o)
   done=json.loads((o/'COMPLETE.json').read_text());image=(b/'guardian_sticks3.bin').read_bytes()
   self.assertEqual(done['art_bench']['frames'],{n:{'sha256':hashlib.sha256(f).hexdigest(),'bytes':len(f),'offset_in_app':image.find(f)} for n,f in self.BENCH_FRAMES.items()})
   self.assertEqual(done['art_bench']['frame_bytes'],sum(len(f) for f in self.BENCH_FRAMES.values()))
   self.assertEqual(done['head3d']['sets'],{});self.assertEqual(done['head3d']['left_out'],['Medium.bin'])   # the bench has no 3D head
   self.assertEqual(done['head3d']['ota_slot_free_bytes'],0x300000-(o/'guardian_sticks3-signed.bin').stat().st_size)
   with tarfile.open(o/'source.tar.gz') as tar:names=tar.getnames()
   self.assertTrue(any(n.endswith('tools/art/candidates.py') for n in names))   # the pipeline that made the frames is archived
  with tempfile.TemporaryDirectory() as d:   # one frame is not in the image (one byte differs)
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,v);self.resign(b,self.app_image(v,self.BENCH_TAIL[:-1]+b'X'),v)
   with self.assertRaisesRegex(ValueError,'ramp.rgb565'):m.archive(b,o)
   self.assertFalse(o.exists())
  with tempfile.TemporaryDirectory() as d:   # a frame embedded twice
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,v);self.resign(b,self.app_image(v,self.BENCH_TAIL+self.BENCH_FRAMES['ramp.rgb565']),v)
   with self.assertRaisesRegex(ValueError,'2 times'):m.archive(b,o)
  with tempfile.TemporaryDirectory() as d:   # a 3D head set in the bench image: it was meant to be left out
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,v);self.resign(b,self.app_image(v,self.BENCH_TAIL+self.HEAD_SET),v)
   with self.assertRaisesRegex(ValueError,'Medium.bin'):m.archive(b,o)
 def test_normal_image_must_not_hold_a_bench_frame(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);self.resign(b,self.app_image('g16b-20261116-200000',self.HEAD_SET+self.BENCH_FRAMES['ramp.rgb565']))
   with self.assertRaisesRegex(ValueError,'ramp.rgb565'):m.archive(b,o)
   self.assertFalse(o.exists())
 def test_bench_frame_that_differs_from_its_pin_cannot_complete(self):
  v=self.BENCH_VERSION
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,v);(self.bench/'ramp.rgb565').write_bytes(self.BENCH_FRAMES['ramp.rgb565'][:-1]+b'X')
   with self.assertRaisesRegex(ValueError,'differs from its pin'):m.archive(b,o)
  (self.bench/'ramp.rgb565').unlink()
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,v)
   with self.assertRaisesRegex(ValueError,'missing'):m.archive(b,o)
  (self.bench/'manifest.json').unlink()
  with tempfile.TemporaryDirectory() as d:   # a bench image without any pinned frame is not a bench
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b,v)
   with self.assertRaisesRegex(ValueError,'no pinned frames'):m.archive(b,o)
 def test_art_bench_version_stamp_fits(self):
  out=subprocess.run([sys.executable,str(m.PROJECT/'tools/build_support.py'),'version-stamp','bench'],text=True,capture_output=True)
  self.assertEqual(out.returncode,0,out.stderr)
  self.assertRegex(out.stdout.strip(),r'^guardian-[0-9]{8}-[0-9]{6}-bench$')
  self.assertLessEqual(len(out.stdout.strip()),31)
  script=(m.PROJECT/'tools/build.sh').read_text()
  self.assertIn('build-art-bench)',script)
  self.assertIn('sdkconfig.art-bench',script)
  self.assertIn('CONFIG_GUARDIAN_ART_BENCH=y',(m.PROJECT/'sdkconfig.art-bench').read_text())
 def test_the_repository_bench_frames_are_what_their_manifest_pins(self):
  import hashlib
  real=self._saved_bench;manifest=json.loads((real/'manifest.json').read_text())
  self.assertEqual(len(manifest['files']),16)
  for name,pin in manifest['files'].items():
   data=(real/name).read_bytes();self.assertEqual(len(data),manifest['frame_bytes'],name);self.assertEqual(hashlib.sha256(data).hexdigest(),pin,name)
  self.assertEqual(sorted(p.name for p in real.glob('*.rgb565')),sorted(manifest['files']))
 def test_app_version_reader(self):
  self.assertEqual(m.app_version(self.app_image('g16b-x')),'g16b-x')
  with self.assertRaises(ValueError):m.app_version(b'\0'*100)
 def test_archive_is_self_contained_and_verified(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'build';out=Path(d)/'out';self.seed(b);m.archive(b,out)
   self.assertTrue((out/'COMPLETE.json').exists())
   for name in json.loads((out/'flasher_args.json').read_text())['flash_files'].values():self.assertTrue((out/name).is_file())
   self.assertIn('bootloader/bootloader.bin',(out/'flash_args').read_text())
   with tarfile.open(out/'source.tar.gz') as archive:
    self.assertIn('lab/receiver/main/wire.hpp',archive.getnames())
 def test_missing_output_cannot_claim_complete(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'build';out=Path(d)/'out';self.seed(b);(b/'guardian_sticks3.elf').unlink()
   with self.assertRaises((ValueError,OSError)):m.archive(b,out)
   self.assertFalse((out/'COMPLETE.json').exists())
 def test_escaping_flash_path_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'build';out=Path(d)/'out';self.seed(b);(b/'flasher_args.json').write_text(json.dumps(dict(flash_files={'0':'../outside'},write_flash_args=[])))
   with self.assertRaises(ValueError):m.archive(b,out)
 def test_source_bundle_has_derived_code_notice(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b);m.archive(b,o)
   with tarfile.open(o/'source.tar.gz') as t:self.assertIn('THIRD_PARTY_NOTICES.md',t.getnames())
   self.assertIn('THIRD_PARTY_NOTICES.md',json.loads((o/'source-sha256.json').read_text()))
 def test_corrupt_copy_cannot_complete(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b)
   def corrupt(src,dst):Path(dst).write_bytes(b'corrupt')
   with patch.object(m.shutil,'copyfile',side_effect=corrupt):
    with self.assertRaises(ValueError):m.archive(b,o)
   self.assertFalse((o/'COMPLETE.json').exists())
 def test_incomplete_flash_map_cannot_complete(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b';o=Path(d)/'o';self.seed(b)
   (b/'flasher_args.json').write_text(json.dumps({'flash_files':{'0x10000':'guardian_sticks3.bin'}}))
   with self.assertRaises(ValueError):m.archive(b,o)
   self.assertFalse((o/'COMPLETE.json').exists())
 def test_sdk_refuses_a_modified_radio_library_like_any_other_change(self):
  # 2026-11-20: the vendor original was restored; a modified libnet80211.a is no longer an allowed input.
  for lib,top,named in [(' M esp32s3/libnet80211.a\n',' M components/esp_wifi/lib\n','components/esp_wifi/lib'),(' M esp32s3/libnet80211.a\n','','esp32s3/libnet80211.a'),('M  esp32s3/libnet80211.a\n','','esp32s3/libnet80211.a')]:
   def git(argv,**kw):
    args=argv[3:];path=argv[2]
    if args==['rev-parse','HEAD']:return '67c1de1eebe095d554d281952fde63c16ee2dca0'
    if args==['submodule','status','--recursive']:return ' a29b11 components/esp_wifi/lib (v)\n'
    return lib if path.endswith('/lib') else top
   with patch.object(m.subprocess,'check_output',side_effect=git):
    with self.assertRaisesRegex(ValueError,'unarchived SDK change: .*'+named):m.qualify_sdk('/sdk')
 def test_clean_sdk_qualifies_with_no_modified_input(self):
  def git(argv,**kw):
   args=argv[3:]
   if args==['rev-parse','HEAD']:return '67c1de1eebe095d554d281952fde63c16ee2dca0'
   if args==['submodule','status','--recursive']:return ' a29b11 components/esp_wifi/lib (v)\n'
   return ''
  with patch.object(m.subprocess,'check_output',side_effect=git):q=m.qualify_sdk('/sdk')
  self.assertEqual(q['head'],'67c1de1eebe095d554d281952fde63c16ee2dca0')
  self.assertNotIn('allowed_modified_input',q)
 def test_sdk_refuses_other_dirty_inputs(self):
  for dirty in [' M components/esp_lcd/driver.c\n','?? local.c\n']:
   def git(argv,**kw):
    if argv[3:]==['rev-parse','HEAD']:return '67c1de1eebe095d554d281952fde63c16ee2dca0'
    if argv[3:]==['submodule','status','--recursive']:return ''
    return dirty
   with patch.object(m.subprocess,'check_output',side_effect=git):
    with self.assertRaises(ValueError):m.qualify_sdk('/sdk')
 def test_sdk_refuses_moved_or_missing_submodules(self):
  for prefix in ['+','-','U']:
   def git(argv,**kw):
    if argv[3:]==['rev-parse','HEAD']:return '67c1de1eebe095d554d281952fde63c16ee2dca0'
    if argv[3:]==['submodule','status','--recursive']:return prefix+'bad components/x (v)\n'
    return ''
   with patch.object(m.subprocess,'check_output',side_effect=git):
    with self.assertRaises(ValueError):m.qualify_sdk('/sdk')
 def test_staged_gitlink_is_not_pinned_sdk(self):
  def git(argv,**kw):
   if argv[3:]==['rev-parse','HEAD']:return '67c1de1eebe095d554d281952fde63c16ee2dca0'
   if argv[3:]==['submodule','status','--recursive']:return ' changed components/esp_wifi/lib (v)\n'
   return 'M  components/esp_wifi/lib\n' if argv[2]=='/sdk' else ''
  with patch.object(m.subprocess,'check_output',side_effect=git):
   with self.assertRaises(ValueError):m.qualify_sdk('/sdk')
 def test_size_normalizes_relative_build_before_cd(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);bindir=root/'bin';bindir.mkdir();sdk=root/'sdk';sdk.mkdir()
   git=bindir/'git';git.write_text('#!/bin/sh\ncase "$*" in *rev-parse*) echo 67c1de1eebe095d554d281952fde63c16ee2dca0;; esac\n');git.chmod(0o755)
   idf=bindir/'idf.py';idf.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n');idf.chmod(0o755)
   (sdk/'export.sh').write_text('export PATH="'+str(bindir)+':$PATH"\n')
   env=dict(os.environ,PATH=str(bindir)+':'+os.environ['PATH'],IDF_PATH_PINNED=str(sdk),GUARDIAN_IDF_PYTHON=sys.executable,GUARDIAN_BUILD_DIR='relative-build')
   result=subprocess.run(['/bin/bash',str(m.PROJECT/'tools/build.sh'),'size'],cwd=root,env=env,text=True,capture_output=True)
   self.assertEqual(result.returncode,0,result.stderr)
   self.assertIn(str((root/'relative-build').resolve()),result.stdout)
 # ---- G16C rework (4): the build stamp names the build, not a task ------------
 def test_default_app_version_is_task_neutral_and_fits(self):
  import datetime,re
  at=datetime.datetime(2026,11,16,22,5,9)
  self.assertEqual(m.default_app_version(at),'guardian-20261116-220509')
  self.assertEqual(m.default_app_version(at,'-stfail'),'guardian-20261116-220509-stfail')
  for v in (m.default_app_version(at),m.default_app_version(at,'-stfail')):
   self.assertRegex(v,r'^[A-Za-z0-9._-]{1,31}$')
   self.assertNotRegex(v,r'(?i)g1[0-9][a-z]?-')
  script=(m.PROJECT/'tools/build.sh').read_text()
  self.assertNotIn('g16b-',script)
  self.assertIn('version-stamp',script)
 def test_version_stamp_command_prints_one_valid_version(self):
  out=subprocess.run([sys.executable,str(m.PROJECT/'tools/build_support.py'),'version-stamp','stfail'],text=True,capture_output=True)
  self.assertEqual(out.returncode,0,out.stderr)
  self.assertRegex(out.stdout.strip(),r'^guardian-[0-9]{8}-[0-9]{6}-stfail$')
  out=subprocess.run([sys.executable,str(m.PROJECT/'tools/build_support.py'),'version-stamp','none'],text=True,capture_output=True)
  self.assertRegex(out.stdout.strip(),r'^guardian-[0-9]{8}-[0-9]{6}$')
if __name__=='__main__':unittest.main()

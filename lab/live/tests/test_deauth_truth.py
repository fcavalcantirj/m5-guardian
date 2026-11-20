import os,subprocess,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
# Redaction 2026-11-19: the owner's network is never in the tree; the target comes from the command line or the environment.
from deauth_truth import target
AP='02:00:00:00:00:01'   # synthetic, locally administered
class DeauthTruthTargetTests(unittest.TestCase):
 def test_arguments_name_the_target(self):
  self.assertEqual(target(['--ap',AP,'--ssid','Lab Net'],{}),('020000000001','Lab Net'.encode().hex()))
 def test_environment_names_the_target(self):
  env={'GUARDIAN_LAB_AP':'02-00-00-00-00-01','GUARDIAN_LAB_SSID':'Lab Net'}
  self.assertEqual(target([],env),('020000000001','Lab Net'.encode().hex()))
 def test_arguments_win_over_the_environment(self):
  env={'GUARDIAN_LAB_AP':'02:00:00:00:00:09','GUARDIAN_LAB_SSID':'Other'}
  self.assertEqual(target(['--ap',AP,'--ssid','Lab Net'],env)[0],'020000000001')
 def test_refuses_without_a_target(self):
  for argv,env in [([],{}),(['--ap',AP],{}),(['--ssid','Lab Net'],{})]:
   with self.assertRaises(ValueError):target(argv,env)
 def test_refuses_a_malformed_address_or_name(self):
  for ap,ssid in [('02:00:00:00:00','Lab'),('zz:00:00:00:00:01','Lab'),(AP,''),(AP,'x'*33)]:
   with self.assertRaises(ValueError):target(['--ap',ap,'--ssid',ssid],{})
 def test_script_refuses_before_opening_any_port(self):
  env={k:v for k,v in os.environ.items() if not k.startswith('GUARDIAN_LAB_')}
  run=subprocess.run([sys.executable,'-I',str(HERE/'deauth_truth.py'),'/dev/null-port','1','/dev/null'],capture_output=True,text=True,env=env)
  self.assertEqual(run.returncode,2)
  self.assertIn('GUARDIAN_LAB_AP',run.stderr)
 def test_source_has_no_path_of_this_machine(self):
  self.assertNotIn('/Users/',(HERE/'deauth_truth.py').read_text())
if __name__=='__main__':unittest.main()

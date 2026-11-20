import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from control import RadioWitness
B='02:11:22:33:44:55'
F='c0003a01ffffffffffff021122334455021122334455f0ff0200'
class WitnessTests(unittest.TestCase):
 def test_match_requires_exact_scope_and_template(self):
  w=RadioWitness(B);w.observe(1000,bytes.fromhex(F),0,False);self.assertEqual(w.count,1)
  for bad in [F[:20]+'001122334455'+F[32:],F[:-4]+'0300',F[:2]+'08'+F[4:]]:w.observe(1100,bytes.fromhex(bad),0,False)
  w.observe(1200,bytes.fromhex(F),1,False);w.observe(1200,bytes.fromhex(F),0,True);self.assertEqual(w.count,1)
 def test_driver_duration_rewrite_from_live_capture(self):
  w=RadioWitness('5a:1a:f4:41:9a:56');w.observe(1000,bytes.fromhex('c0000000ffffffffffff5a1af4419a565a1af4419a56f0ff0200'),0,False);self.assertEqual(w.count,1)
 def test_post_stop_requires_observation_window(self):
  w=RadioWitness(B);w.observe(1000,bytes.fromhex(F),0,False)
  self.assertFalse(w.stop_proven(2000,2500,100,1))
  self.assertTrue(w.stop_proven(2000,5000000,100,1,post_stop_listening=True))
 def test_late_frame_rejects_stop(self):
  w=RadioWitness(B);w.observe(3000,bytes.fromhex(F),0,False)
  self.assertFalse(w.stop_proven(2000,5000000,100,1,post_stop_listening=True))
 def test_no_emission_is_not_pass(self):
  self.assertFalse(RadioWitness(B).stop_proven(2000,5000000,100,1,post_stop_listening=True))
if __name__=='__main__':unittest.main()

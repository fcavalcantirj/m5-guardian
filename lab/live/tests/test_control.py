import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from control import validate_scope,BatchState,ClockMap
BASE={'bssid':'02:11:22:33:44:55','channel':6,'groups':8,'deadline_s':4,'ssid_hex':'477561726469616e4c6162'}
class ControlTests(unittest.TestCase):
 def test_scope(self):self.assertEqual(validate_scope(BASE)['bssid'],'02:11:22:33:44:55')
 def test_reject_scope(self):
  for key,value in [('bssid','ff:ff:ff:ff:ff:ff'),('bssid','00:00:00:00:00:00'),('channel',0),('channel',14),('groups',9),('deadline_s',30),('ssid_hex','gg')]:
   with self.assertRaises(ValueError):validate_scope(dict(BASE,**{key:value}))
 def test_start_is_not_completion(self):
  b=BatchState();b.begin(0);self.assertFalse(b.line('OK deauth start bssid=02:11:22:33:44:55 channel=6 count=1'));self.assertTrue(b.pending);self.assertTrue(b.line('OK deauth done 1'));self.assertFalse(b.pending)
 def test_bad_count(self):
  b=BatchState();b.begin(0)
  with self.assertRaises(ValueError):b.line('OK deauth done 20')
 def test_no_concurrent_batch(self):
  b=BatchState();b.begin(0)
  with self.assertRaises(ValueError):b.begin(.1)
 def test_timeout(self):
  b=BatchState();b.begin(0);self.assertFalse(b.expired(.9));self.assertTrue(b.expired(1.01))
 def test_stop_blocks_new_batches(self):
  b=BatchState();b.stop()
  with self.assertRaises(ValueError):b.begin(0)
 def test_unsolicited_done(self):
  with self.assertRaises(ValueError):BatchState().line('OK deauth done 1')
 def test_sync_preserves_age(self):
  m=ClockMap();m.sample(1000000,1010000,500000);self.assertEqual(m.map(490000),990000);self.assertEqual(m.uncertainty_us,10000)
 def test_sync_no_future_refresh(self):
  m=ClockMap();m.sample(1000000,1010000,500000);m.sample(2000000,2030000,1500000);self.assertEqual(m.map(490000),990000)
 def test_bad_sync(self):
  m=ClockMap()
  with self.assertRaises(ValueError):m.map(1)
  with self.assertRaises(ValueError):m.sample(100,90,10)
  with self.assertRaises(ValueError):m.sample(100,300000,10)
if __name__=='__main__':unittest.main()

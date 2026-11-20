import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ap_control import ap_command,ap_channel_command,start_test_ap
class APControlTests(unittest.TestCase):
 def test_channel_command_stays_in_the_qualified_domain(self):
  self.assertEqual(ap_channel_command(6),b'apchannel 6\n')
  for value in [0,14,-1,True,'6',999999]:
   with self.assertRaises(ValueError):ap_channel_command(value)
 def test_start_validates_before_write_and_retunes_only_fixture(self):
  from unittest.mock import Mock,patch,call
  port=Mock()
  with patch('ap_control.await_line') as wait:
   start_test_ap(port,'61',2,60,5)
   self.assertEqual(port.write.call_args_list,[call(b'ap 2 60 61\n'),call(b'apchannel 5\n')])
   self.assertEqual(wait.call_count,2)
  port.reset_mock()
  with self.assertRaises(ValueError):start_test_ap(port,'61',2,60,14)
  port.write.assert_not_called()
 def test_explicit_bounded_command(self):self.assertEqual(ap_command('4c41422d50492d32',3,60),b'ap 3 60 4c41422d50492d32\n')
 def test_invalid(self):
  for ssid,mode,seconds in [('00',3,60),('61',0,60),('61',3,121),('61',3,0),('gg',3,60),('61'*33,3,60),('0a',3,60),('61',True,60),('61',3,True)]:
   with self.assertRaises(ValueError):ap_command(ssid,mode,seconds)
if __name__=='__main__':unittest.main()

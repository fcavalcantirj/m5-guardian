import os as _os
_os.environ.update({'GUARDIAN_LOCAL_CONF':'/nonexistent/guardian-test-local.conf','GUARDIAN_LAB_STICK_MAC':'02:00:00:00:0b:01','GUARDIAN_LAB_CARDPUTER_MAC':'02:00:00:00:0b:03','GUARDIAN_LAB_EMITTER_MAC':'02:00:00:00:0b:04','GUARDIAN_LAB_PI_SSH':'lab@lab-pi','GUARDIAN_LAB_PI_PYTHON':'/opt/lab/bin/python','GUARDIAN_LAB_PI_TOOLS':'/opt/lab/tools'})   # synthetic lab bench, never this owner's (lab/local.conf.example)
import sys,unittest,time
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import run
class ReceiverStopTests(unittest.TestCase):
 def check_status(self,records):
  class Port:
   def __init__(self):self.reset=False;self.commands=[]
   def reset_input_buffer(self):self.reset=True
   def write(self,b):self.commands.append(b)
   def read(self,n):return b'GRX1 fixture\n' if records else b''
  s=run.Session.__new__(run.Session);s.serial=Port();s.boot='one';s.previous=dict(sequence=10,acquired_us=100)
  def decode(_):return records.pop(0)
  # deterministic advancing deadline; no wall-clock delay or USB.
  times=iter([i*.1 for i in range(100)])
  with patch.object(run,'decode',side_effect=decode),patch.object(run.time,'monotonic',side_effect=lambda:next(times)):
   receipt=s.confirm_receiver_stop()
  self.assertTrue(s.serial.reset);self.assertEqual(s.serial.commands,[b'stop\n'])
  return receipt
 def status(self,**kw):return dict(dict(kind=4,flags=0,boot='one',sequence=11,acquired_us=101),**kw)
 def test_requires_fresh_stopped_matching_boot(self):
  self.assertTrue(self.check_status([self.status()])['receiver_stop_confirmed'])
  for key,value in [('kind',2),('flags',1),('boot','other'),('sequence',9),('sequence',10),('acquired_us',99)]:
   with self.subTest(key=key,value=value):self.assertFalse(self.check_status([self.status(**{key:value})])['receiver_stop_confirmed'])
 def test_absent_ack_is_explicitly_unconfirmed(self):
  receipt=self.check_status([]);self.assertTrue(receipt['receiver_stop_sent']);self.assertFalse(receipt['receiver_stop_confirmed'])
if __name__=='__main__':unittest.main()

import sys,unittest,io
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cleanup import cleanup
class Serial:
 def __init__(self,fail=False):self.fail=fail;self.closed=False;self.writes=[]
 def write(self,b):
  if self.fail:raise OSError('USB removed')
  self.writes.append(b)
 def close(self):self.closed=True
class Process:
 def __init__(self):self.stdin=io.StringIO();self.code=None;self.sent=''
 def poll(self):return self.code
 def wait(self,timeout):self.sent=self.stdin.getvalue() if not self.stdin.closed else 'EOF';self.code=0;return 0
class Log:
 def __init__(self):self.closed=False
 def close(self):self.closed=True
class CleanupTests(unittest.TestCase):
 def test_usb_failure_still_closes_everything(self):
  serial=Serial(True);engine=Process();log=Log();result=cleanup(serial,engine,None,[log]);self.assertTrue(serial.closed);self.assertEqual(engine.code,0);self.assertTrue(log.closed);self.assertFalse(result['ok'])
 def test_reader_drained_before_logs_close(self):
  class Reader:
   def __init__(self):self.joined=False
   def join(self,timeout):self.joined=True
   def is_alive(self):return not self.joined
  reader=Reader();result=cleanup(Serial(),Process(),None,[Log()],threads=[reader],confirm_receiver_stop=lambda:dict(receiver_stop_confirmed=True));self.assertTrue(reader.joined);self.assertTrue(result['ok'])
 def test_normal(self):
  serial=Serial();engine=Process();log=Log();result=cleanup(serial,engine,None,[log],confirm_receiver_stop=lambda:(serial.write(b'stop\n'),dict(receiver_stop_confirmed=True))[1]);self.assertTrue(result['ok']);self.assertIn(b'stop\n',serial.writes);self.assertEqual(engine.sent,'QUIT\n')
if __name__=='__main__':unittest.main()

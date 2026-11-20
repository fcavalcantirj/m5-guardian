import sys,unittest,time,threading,io
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from evidence import AsyncLog
class Slow(io.StringIO):
 def __init__(self):super().__init__();self.enter=threading.Event();self.release=threading.Event()
 def write(self,s):self.enter.set();self.release.wait(2);return super().write(s)
 def close(self):pass
class LoggingTests(unittest.TestCase):
 def test_receiver_not_blocked_by_disk(self):
  sink=Slow();log=AsyncLog(sink,capacity=4);start=time.monotonic();log.write('first\n');self.assertLess(time.monotonic()-start,.1);self.assertTrue(sink.enter.wait(1));log.write('second\n');sink.release.set();log.close();self.assertEqual(sink.getvalue(),'first\nsecond\n')
 def test_full_queue_fails_visibly(self):
  sink=Slow();log=AsyncLog(sink,capacity=1);log.write('a');self.assertTrue(sink.enter.wait(1));log.write('b')
  with self.assertRaises(RuntimeError):log.write('c')
  sink.release.set();log.close()
if __name__=='__main__':unittest.main()

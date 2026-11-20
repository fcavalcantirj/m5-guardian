import os,sys,subprocess,threading,unittest,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cleanup import cleanup
class BoundedTests(unittest.TestCase):
 def test_full_pipe_cannot_block_cleanup(self):
  p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],stdin=subprocess.PIPE,text=True)
  fd=p.stdin.fileno();os.set_blocking(fd,False)
  try:
   while True:os.write(fd,b'x'*4096)
  except BlockingIOError:pass
  os.set_blocking(fd,True);results=[]
  t=threading.Thread(target=lambda:results.append(cleanup(None,p,None,[])),daemon=True);t.start()
  try:t.join(4);self.assertFalse(t.is_alive(),'cleanup blocked on a full stdin pipe');self.assertFalse(results[0]['ok'])
  finally:
   if p.poll() is None:p.kill()
   p.wait();t.join(2);p.stdin.close()
if __name__=='__main__':unittest.main()

import sys,unittest,io
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from control import RadioWitness
from cleanup import cleanup
class ReviewControls(unittest.TestCase):
 def test_elapsed_time_without_listening_is_not_stop_proof(self):
  w=RadioWitness('02:11:22:33:44:55');w.observe(1000,w.template,0,False)
  self.assertFalse(w.stop_proven(2000,5000000,100,1))
 def test_receiver_write_is_not_confirmed_stop(self):
  class Port:
   def write(self,b):pass
   def close(self):pass
  r=cleanup(Port(),None,None,[])
  self.assertFalse(r['ok'])
if __name__=='__main__':unittest.main()

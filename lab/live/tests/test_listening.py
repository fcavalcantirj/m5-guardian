import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from control import ListeningWitness
class ListeningTests(unittest.TestCase):
 def records(self):return [dict(kind=2,flags=1,channel=6,boot='one',sequence=i,acquired_us=i*1000000,queue_drops=0,bad_input=0) for i in range(7)]
 def feed(self,rs):
  w=ListeningWitness(6)
  for r in rs:w.observe(r,r['acquired_us'])
  return w
 def test_continuous_scoped_window_covers_clock_envelope(self):
  w=self.feed(self.records());self.assertTrue(w.covers_after(2000000,20000));self.assertFalse(w.covers_after(4000000,20000))
 def test_no_heartbeat_wrong_channel_stopped_or_missing_record_refuses(self):
  rs=self.records();self.assertFalse(self.feed(rs[:3]).covers_after(2000000,20000))
  for key,value in [('flags',0),('channel',11),('boot','other'),('queue_drops',1),('bad_input',1),('sequence',100),('acquired_us',100000)]:
   rs=self.records();rs[3][key]=value
   with self.subTest(key=key):self.assertFalse(self.feed(rs).covers_after(2000000,20000))
  rs=self.records();del rs[3];self.assertFalse(self.feed(rs).covers_after(2000000,20000))
 def test_frame_sequence_and_counter_loss_break_coverage(self):
  rs=self.records();rs[3]['kind']=1;rs[3]['queue_drops']=1
  self.assertFalse(self.feed(rs).covers_after(2000000,20000))
 def test_old_interval_not_extended_over_stopped_gap(self):
  rs=self.records();rs[3]['flags']=0
  w=self.feed(rs);self.assertFalse(w.covers_after(2000000,0));self.assertFalse(w.covers_after(None,0))
if __name__=='__main__':unittest.main()

import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from assessment import assess
from control import RadioWitness
B='02:11:22:33:44:55';F=bytes.fromhex('c0000000ffffffffffff021122334455021122334455f0ff0200')
def quiet_states():return [dict(now_ms=1000+i*1000,origin='live',coverage=1,has_security=True,age_ms=50,mood=3,burst=False,unexpected_ap=False,settings_changed=False) for i in range(8)]
def witness(n):
 w=RadioWitness(B)
 for i in range(n):w.observe(10000000+i*20000,F,0,False)
 return w
class AssessmentTests(unittest.TestCase):
 def check(self,scenario,states,w=None,emitter=None,ack=11000000,end=15000000,ap_stopped=False):return assess(scenario,states,w or RadioWitness(B),emitter,ack,end,20000,8,ap_stop_observed=ap_stopped,post_stop_listening=True)
 def test_quiet_needs_real_fresh_window(self):
  self.assertTrue(self.check('quiet',quiet_states())['pass']);self.assertFalse(self.check('quiet',quiet_states()[:2])['pass'])
 def test_imported_never_live_pass(self):
  s=quiet_states()
  for x in s:x['origin']='imported'
  self.assertFalse(self.check('quiet',s)['pass'])
 def test_burst_requires_witness_and_latency(self):
  s=quiet_states()+[dict(quiet_states()[-1],now_ms=10800,burst=True,burst_count=20,burst_acquired_ms=10380,incident_visible=True)]
  e={'completed_groups':8,'stop_requested':False}
  self.assertTrue(self.check('burst',s,witness(24),e)['pass']);self.assertFalse(self.check('burst',s,witness(0),e)['pass'])
  s[-1]['now_ms']=13000;self.assertFalse(self.check('burst',s,witness(24),e)['pass'])
 def test_recovery_requires_new_fresh_evidence(self):
  s=quiet_states()+[dict(quiet_states()[-1],now_ms=10800,burst=True,burst_count=20,burst_acquired_ms=10380,incident_visible=True),dict(quiet_states()[-1],now_ms=75000)]
  e={'completed_groups':8};self.assertTrue(self.check('recovery',s,witness(24),e,end=80000000)['pass']);s[-1]['coverage']=3;self.assertFalse(self.check('recovery',s,witness(24),e,end=80000000)['pass'])
 def test_stop_not_vacuous(self):
  self.assertTrue(self.check('stop',quiet_states(),witness(3),{'completed_groups':1,'stop_requested':True})['pass'])
  self.assertFalse(self.check('stop',quiet_states(),witness(0),{'completed_groups':1,'stop_requested':True})['pass'])
 def test_reconnect_requires_observed_association(self):
  s=quiet_states();s[-1]['association_frames']=0;self.assertFalse(self.check('reconnect',s)['pass']);s[-1]['association_frames']=4;self.assertTrue(self.check('reconnect',s)['pass'])
 def test_settings_requires_real_mode_sequence_and_stop(self):
  s=[dict(x,mode=4,pmf=2) for x in quiet_states()]
  s += [dict(x,now_ms=x['now_ms']+10000,mode=5,pmf=3,settings_changed=True,incident_visible=True) for x in quiet_states()]
  s += [dict(x,now_ms=x['now_ms']+20000,mode=4,pmf=2) for x in quiet_states()]
  e={'role':'test_ap','completed_groups':0,'stop_requested':True}
  self.assertTrue(self.check('settings',s,emitter=e,ap_stopped=True)['pass']);self.assertFalse(self.check('settings',s,emitter=e)['pass'])
  red=[dict(x,alert=True) if x.get('settings_changed') else x for x in s]   # G25: a security change is amber, never the red ALERT
  self.assertFalse(self.check('settings',red,emitter=e,ap_stopped=True)['pass'])
  for x in s:x['mode']=4
  self.assertFalse(self.check('settings',s,emitter=e,ap_stopped=True)['pass'])
 def test_channel_change_requires_full_sequence_gap_and_stopped_ap(self):
  states=[dict(x,channel=13) for x in quiet_states()]
  states += [dict(quiet_states()[0],now_ms=10000,coverage=3,mood=0)]
  states += [dict(x,now_ms=x['now_ms']+15000,channel=6) for x in quiet_states()]   # G25: followed silently, no incident
  states += [dict(quiet_states()[0],now_ms=30000,coverage=3,mood=0)]
  states += [dict(x,now_ms=x['now_ms']+35000,channel=13) for x in quiet_states()]
  emitter={'role':'test_ap','completed_groups':0}
  self.assertTrue(self.check('channel',states,emitter=emitter,ap_stopped=True)['pass'])
  self.assertFalse(self.check('channel',states,emitter=emitter)['pass'])
  flagged=[dict(x,settings_changed=True) if x.get('channel')==6 else x for x in states]
  self.assertFalse(self.check('channel',flagged,emitter=emitter,ap_stopped=True)['pass'])   # a channel move must not be an incident
  no_gap=[s for s in states if s['coverage']==1]
  self.assertFalse(self.check('channel',no_gap,emitter=emitter,ap_stopped=True)['pass'])
  startup_only=[dict(quiet_states()[0],now_ms=0,coverage=3,mood=0)]+no_gap
  self.assertFalse(self.check('channel',startup_only,emitter=emitter,ap_stopped=True)['pass'])
  for s in states:s['channel']=13
  self.assertFalse(self.check('channel',states,emitter=emitter,ap_stopped=True)['pass'])
 def test_related_needs_observed_ap_and_correct_approval(self):
  s=[dict(x,watched_advertisements=40) for x in quiet_states()];e={'role':'test_ap','completed_groups':0}
  self.assertTrue(self.check('related-approved',s,emitter=e,ap_stopped=True)['pass']);self.assertFalse(self.check('related-unapproved',s,emitter=e,ap_stopped=True)['pass'])
  s[-1]['unexpected_ap']=True;s[-1]['incident_visible']=True
  self.assertTrue(self.check('related-unapproved',s,emitter=e,ap_stopped=True)['pass']);self.assertFalse(self.check('related-approved',s,emitter=e,ap_stopped=True)['pass'])
 def test_mid_batch_stop_requires_partial_rf_not_full_batch(self):
  e={'completed_groups':0,'submitted_groups':1,'stop_requested':True,'interrupted_inflight':True}
  self.assertTrue(self.check('stop-inflight',quiet_states(),witness(1),e)['pass']);self.assertFalse(self.check('stop-inflight',quiet_states(),witness(3),e)['pass'])
 def test_live_adapter_drop_needs_degradation_then_recovery(self):
  s=quiet_states()+[dict(quiet_states()[-1],now_ms=9000,coverage=3,mood=0,coverage_drops=10),dict(quiet_states()[-1],now_ms=11000)]
  self.assertTrue(self.check('drop',s)['pass']);s[-1]['coverage']=3;self.assertFalse(self.check('drop',s)['pass'])
 def test_stale_needs_unknown_after_fresh(self):
  s=quiet_states()+[dict(quiet_states()[-1],now_ms=42000,age_ms=31000,mood=0,coverage=3)]
  self.assertTrue(self.check('stale',s)['pass']);s[-1]['mood']=3;self.assertFalse(self.check('stale',s)['pass'])
if __name__=='__main__':unittest.main()

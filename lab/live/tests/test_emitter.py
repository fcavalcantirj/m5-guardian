import os as _os
_os.environ.update({'GUARDIAN_LOCAL_CONF':'/nonexistent/guardian-test-local.conf','GUARDIAN_LAB_STICK_MAC':'02:00:00:00:0b:01','GUARDIAN_LAB_CARDPUTER_MAC':'02:00:00:00:0b:03','GUARDIAN_LAB_EMITTER_MAC':'02:00:00:00:0b:04','GUARDIAN_LAB_PI_SSH':'lab@lab-pi','GUARDIAN_LAB_PI_PYTHON':'/opt/lab/bin/python','GUARDIAN_LAB_PI_TOOLS':'/opt/lab/tools'})   # synthetic lab bench, never this owner's (lab/local.conf.example)
import contextlib,io,json,sys,unittest,threading
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import emitter
class Port:
 def __init__(self,stop_after=None,complete=True):self.writes=[];self.lines=[];self.stop_after=stop_after;self.complete=complete
 def __enter__(self):return self
 def __exit__(self,*_):pass
 def write(self,b):
  self.writes.append(b)
  if b==b'stop\n':self.lines.append(b'OK stop\n')
  if b.startswith(b'arm '):self.lines.append(b'OK armed\n')
  if b.startswith(b'deauth '):
   self.lines.append(b'OK deauth start count=1\n')
   if self.complete:self.lines.append(b'OK deauth done 1\n')
   if self.stop_after is not None and sum(x.startswith(b'deauth ') for x in self.writes)>=self.stop_after:emitter.stop_event.set()
 def readline(self,_):return self.lines.pop(0) if self.lines else b''
class DummyThread:
 def __init__(self,*a,**k):pass
 def start(self):pass
class EmitterTests(unittest.TestCase):
 def run_controller(self,port,backend='native',interrupt=False):
  emitter.stop_event.clear();scope={'bssid':'02:11:22:33:44:55','channel':6,'groups':8,'deadline_s':4,'ssid_hex':'686f6d65'}
  with patch.object(sys,'argv',['emitter','--emit']+(['--interrupt-batch'] if interrupt else [])),patch.object(sys,'stdin',io.StringIO(json.dumps(scope)+'\nGO\n')),patch.object(emitter.Path,'exists',return_value=True),patch.object(emitter,'open_port',return_value=port),patch.object(emitter,'identify',return_value=backend),patch.object(emitter.signal,'signal'),patch.object(emitter.threading,'Thread',DummyThread),patch.object(emitter.stop_event,'wait',side_effect=lambda _:emitter.stop_event.is_set()),contextlib.redirect_stdout(io.StringIO()) as out:
   emitter.main()
  return [json.loads(l) for l in out.getvalue().splitlines()]
 def test_only_one_count_per_command(self):
  port=Port();events=self.run_controller(port);tx=[x for x in port.writes if x.startswith(b'deauth ')];self.assertEqual(len(tx),8);self.assertTrue(all(x.endswith(b' 1\n') for x in tx));self.assertEqual(events[-1]['event'],'stopped')
 def test_stop_prevents_next_batch(self):
  port=Port(stop_after=1);events=self.run_controller(port);self.assertEqual(sum(x.startswith(b'deauth ') for x in port.writes),1);self.assertTrue(events[-1]['stop_requested'])
 def test_brownout_rejected(self):
  port=Port();port.lines=[b'E BOD: Brownout detector was triggered\n']
  with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(RuntimeError):emitter.read_line(port)
 def test_timeout_uses_reset_without_retry(self):
  port=Port(complete=False)
  with patch.object(emitter.BatchState,'expired',return_value=True),patch.object(emitter,'bootloader_stop') as reset,self.assertRaises(RuntimeError):self.run_controller(port)
  reset.assert_called_once_with(port);self.assertEqual(sum(x.startswith(b'deauth ') for x in port.writes),1)
 def test_failed_reset_never_claims_stopped(self):
  port=Port(complete=False);events=[]
  with patch.object(emitter.BatchState,'expired',return_value=True),patch.object(emitter,'bootloader_stop',side_effect=RuntimeError('reset failed')),patch.object(emitter,'emit',side_effect=lambda event,**kw:events.append(dict(event=event,**kw))),self.assertRaises(RuntimeError):self.run_controller(port)
  self.assertFalse(any(e.get('left_in_bootloader') for e in events));self.assertTrue(any(e['event']=='stop_unconfirmed' for e in events))
 def test_control_eof_requests_stop(self):
  emitter.stop_event.clear()
  with patch.object(sys,'stdin',io.StringIO('')):emitter.watch_stdin()
  self.assertTrue(emitter.stop_event.is_set())
 def test_native_arms_before_batch(self):
  port=Port();self.run_controller(port,'native');arm=next(i for i,x in enumerate(port.writes) if x.startswith(b'arm '));tx=next(i for i,x in enumerate(port.writes) if x.startswith(b'deauth '));self.assertLess(arm,tx)
 def test_error_before_ack_is_not_success(self):
  port=Port();port.lines=[b'ERR wifi_stop code=1\n',b'OK stop\n']
  with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(RuntimeError):emitter.await_line(port,'OK stop',1)
 def test_native_mid_batch_cancel_requests_stop(self):
  port=Port();events=self.run_controller(port,'native',True);self.assertEqual(sum(x.startswith(b'deauth ') for x in port.writes),1);self.assertTrue(events[-1]['interrupted_inflight']);self.assertEqual(events[-1]['submitted_groups'],1)
 def test_go_required(self):
  port=Port();emitter.stop_event.clear()
  scope={'bssid':'02:11:22:33:44:55','channel':6,'groups':1,'deadline_s':4,'ssid_hex':'686f6d65'}
  with patch.object(sys,'argv',['emitter','--emit']),patch.object(sys,'stdin',io.StringIO(json.dumps(scope)+'\nNO\n')),patch.object(emitter.Path,'exists',return_value=True),patch.object(emitter,'open_port',return_value=port),patch.object(emitter,'identify',return_value='legacy'),patch.object(emitter.signal,'signal'),contextlib.redirect_stdout(io.StringIO()),self.assertRaises(RuntimeError):emitter.main()
  self.assertFalse(any(x.startswith(b'deauth ') for x in port.writes))
 def test_legacy_or_missing_identity_never_arms_or_transmits(self):
  for backend in ('legacy',None,'unknown'):
   port=Port()
   with self.assertRaisesRegex(RuntimeError,'qualified native'):self.run_controller(port,backend)
   self.assertFalse(any(x.startswith((b'arm ',b'deauth ')) for x in port.writes))
if __name__=='__main__':unittest.main()


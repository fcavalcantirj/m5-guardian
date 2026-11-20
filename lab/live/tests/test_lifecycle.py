import os as _os
_os.environ.update({'GUARDIAN_LOCAL_CONF':'/nonexistent/guardian-test-local.conf','GUARDIAN_LAB_STICK_MAC':'02:00:00:00:0b:01','GUARDIAN_LAB_CARDPUTER_MAC':'02:00:00:00:0b:03','GUARDIAN_LAB_EMITTER_MAC':'02:00:00:00:0b:04','GUARDIAN_LAB_PI_SSH':'lab@lab-pi','GUARDIAN_LAB_PI_PYTHON':'/opt/lab/bin/python','GUARDIAN_LAB_PI_TOOLS':'/opt/lab/tools'})   # synthetic lab bench, never this owner's (lab/local.conf.example)
import importlib.util,io,os,signal,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(os.environ.get('GUARDIAN_TEST_ROOT',str(Path(__file__).resolve().parents[3])))
sys.path.insert(0,str(ROOT/'lab/live'))
spec=importlib.util.spec_from_file_location('guardian_live_run',ROOT/'lab/live/run.py');run=importlib.util.module_from_spec(spec);spec.loader.exec_module(run)
from cleanup import cleanup
class LifecycleTests(unittest.TestCase):
 def test_nonzero_engine_exit_is_not_success(self):
  class Failed:
   def poll(self):return 2
  result=cleanup(None,Failed(),None,[])
  self.assertFalse(result['ok']);self.assertEqual(result['engine_exit'],2)
 def test_sigterm_enters_finally_and_restores_handlers(self):
  # Real POSIX signal in a subprocess, no radio/device/subprocess fixture.
  source=f'''import sys,signal,os
sys.path.insert(0,{str(ROOT/'lab/live')!r})
import run
old=signal.getsignal(signal.SIGTERM)
try:
 with run.interruptible():
  try: os.kill(os.getpid(),signal.SIGTERM)
  finally:
   os.kill(os.getpid(),signal.SIGTERM)
   print("CLEANED",flush=True)
except run.RunInterrupted as exc:
 assert exc.signum==signal.SIGTERM
assert signal.getsignal(signal.SIGTERM)==old
print("RESTORED",flush=True)
'''
  p=subprocess.run([sys.executable,'-c',source],capture_output=True,text=True,timeout=5)
  self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(p.stdout.splitlines(),['CLEANED','RESTORED'])
 def test_serial_open_failure_closes_open_logs(self):
  from types import SimpleNamespace
  s=run.Session.__new__(run.Session);s.engine=s.emitter=s.serial=None;s.threads=[]
  s.args=SimpleNamespace(scenario='quiet');s.frames=0;s.state={};s.save=lambda *args:None
  class Log(io.StringIO):
   def close(self):self.was_closed=True;super().close()
  logs=[]
  def log(sink):sink.close();x=Log();x.was_closed=False;logs.append(x);return x
  with tempfile.TemporaryDirectory() as d:
   s.root=Path(d)
   with patch('serial.tools.list_ports.comports',return_value=[SimpleNamespace(serial_number=run.SERIAL,device='unused')]),patch.object(run,'open_port',side_effect=OSError('open failure')),patch.object(run,'AsyncLog',side_effect=log):
    with self.assertRaises(OSError):s.run()
  self.assertTrue(logs);self.assertTrue(all(x.was_closed for x in logs))
 def test_real_signals_run_session_cleanup(self):
  from types import SimpleNamespace
  for signum in (signal.SIGINT,signal.SIGTERM):
   class Port:
    timeout=0
    def __init__(self):self.commands=[];self.closed=False
    def write(self,data):self.commands.append(data)
    def read(self,size):os.kill(os.getpid(),signum);return b''
    def close(self):self.closed=True
   port=Port();s=run.Session.__new__(run.Session)
   s.engine=s.emitter=s.serial=None;s.threads=[];s.frames=0;s.state={}
   s.args=SimpleNamespace(scenario='quiet');s.stream=run.LineBuffer();s.confirm_receiver_stop=lambda: (port.write(b'stop\n'),dict(receiver_stop_sent=True,receiver_stop_confirmed=True))[1]
   with tempfile.TemporaryDirectory() as d:
    s.root=Path(d)
    with patch('serial.tools.list_ports.comports',return_value=[SimpleNamespace(serial_number=run.SERIAL,device='unused')]),patch.object(run,'open_port',return_value=port):
     with self.assertRaises(run.RunInterrupted),run.interruptible():s.run()
    import json
    self.assertTrue(json.loads((s.root/'cleanup.json').read_text())['ok'])
    self.assertTrue((s.root/'failure.json').exists())
   self.assertIn(b'stop\n',port.commands);self.assertTrue(port.closed)
 def test_first_signal_during_cleanup_cannot_skip_remaining_steps(self):
  from types import SimpleNamespace
  class Port:
   def __init__(self):self.commands=[];self.closed=False
   def write(self,data):self.commands.append(data)
   def close(self):self.closed=True
  port=Port();s=run.Session.__new__(run.Session)
  s.engine=s.emitter=s.serial=None;s.threads=[];s.frames=0;s.state={};s.args=SimpleNamespace(scenario='quiet')
  original=run.cleanup
  def signal_in_cleanup(*args,**kwargs):
   os.kill(os.getpid(),signal.SIGTERM)
   return original(*args,**kwargs)
  with tempfile.TemporaryDirectory() as d:
   s.root=Path(d)
   with patch('serial.tools.list_ports.comports',return_value=[SimpleNamespace(serial_number=run.SERIAL,device='unused')]),patch.object(run,'open_port',side_effect=OSError('open failure')),patch.object(run,'cleanup',side_effect=signal_in_cleanup):
    with self.assertRaises(run.RunInterrupted),run.interruptible():s.run()
   import json
   self.assertTrue(json.loads((s.root/'cleanup.json').read_text())['ok'])
 def test_deferred_signals_preserve_cleanup_and_exit_status(self):
  for sig in (signal.SIGINT,signal.SIGTERM):
   for failure in (False,True):
    events=[]
    with self.assertRaises(run.RunInterrupted) as caught,run.interruptible():
     try:
      if failure:raise OSError('original failure')
     finally:
      with run.finishing_cleanup():
       os.kill(os.getpid(),sig);events.append('receiver closed')
       os.kill(os.getpid(),sig);events.append('receipt saved')
    self.assertEqual(events,['receiver closed','receipt saved']);self.assertEqual(caught.exception.signum,sig)
 def test_first_signal_during_cleanup_context_entry_is_deferred(self):
  events=[]
  def enter():
   os.kill(os.getpid(),signal.SIGTERM)
   return run.finishing_cleanup()
  with self.assertRaises(run.RunInterrupted),run.interruptible():
   try:pass
   finally:
    with enter():events.append('cleaned')
  self.assertEqual(events,['cleaned'])
 def test_initial_signal_survives_cleanup_error_and_different_second_signal(self):
  with self.assertRaises(run.RunInterrupted) as caught:
   with run.interruptible():
    try:os.kill(os.getpid(),signal.SIGINT)
    finally:
     with run.finishing_cleanup():
      os.kill(os.getpid(),signal.SIGTERM)
      raise RuntimeError('cleanup failed and receipt saved')
  self.assertEqual(caught.exception.signum,signal.SIGINT)
if __name__=='__main__':unittest.main()

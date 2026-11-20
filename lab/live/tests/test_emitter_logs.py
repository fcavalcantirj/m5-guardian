"""start_emitter must not create files on the evidence share inside the reception loop.
Measured 2026-11-15: the store SMB open() took 560-640 ms each; two opens stalled board
telemetry >1 s (settings-video-01)."""
import os as _os
_os.environ.update({'GUARDIAN_LOCAL_CONF':'/nonexistent/guardian-test-local.conf','GUARDIAN_LAB_STICK_MAC':'02:00:00:00:0b:01','GUARDIAN_LAB_CARDPUTER_MAC':'02:00:00:00:0b:03','GUARDIAN_LAB_EMITTER_MAC':'02:00:00:00:0b:04','GUARDIAN_LAB_PI_SSH':'lab@lab-pi','GUARDIAN_LAB_PI_PYTHON':'/opt/lab/bin/python','GUARDIAN_LAB_PI_TOOLS':'/opt/lab/tools'})   # synthetic lab bench, never this owner's (lab/local.conf.example)
import io,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import run
class EmitterLogs(unittest.TestCase):
    def session(self,scenario):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        s=run.Session.__new__(run.Session);s.root=Path(tmp.name);s.args=SimpleNamespace(scenario=scenario)
        s.logs=[];s.threads=[];s.emitter_events=Mock();s.scope={'bssid':'02:11:22:33:44:55'}
        def close_fixture():
            for thread in s.threads:
                thread.join(timeout=2);self.assertFalse(thread.is_alive())
            for log in s.logs:log.close()
        self.addCleanup(close_fixture)
        return s
    def test_logs_prepared_before_reception_then_no_open_in_loop(self):
        s=self.session('settings');s.prepare_emitter_logs()
        self.assertTrue((s.root/'emitter.jsonl').exists() and (s.root/'emitter.stderr').exists())
        proc=Mock();proc.stdin=io.StringIO();proc.stdout=io.StringIO('')
        with patch('pathlib.Path.open',side_effect=AssertionError('file opened in reception loop')),patch('run.subprocess.Popen',return_value=proc):
            s.start_emitter()
        self.assertIs(s.emitter,proc)
    def test_no_logs_for_scenarios_without_emitter(self):
        s=self.session('reconnect');s.prepare_emitter_logs()
        self.assertFalse((s.root/'emitter.jsonl').exists())
if __name__=='__main__':unittest.main()

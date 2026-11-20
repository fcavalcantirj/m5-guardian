"""End-to-end controller dry run: simulated client + simulated observer process."""
import os as _os
_os.environ.update({'GUARDIAN_LOCAL_CONF':'/nonexistent/guardian-test-local.conf','GUARDIAN_LAB_STICK_MAC':'02:00:00:00:0b:01','GUARDIAN_LAB_CARDPUTER_MAC':'02:00:00:00:0b:03','GUARDIAN_LAB_EMITTER_MAC':'02:00:00:00:0b:04','GUARDIAN_LAB_PI_SSH':'lab@lab-pi','GUARDIAN_LAB_PI_PYTHON':'/opt/lab/bin/python','GUARDIAN_LAB_PI_TOOLS':'/opt/lab/tools'})   # synthetic lab bench, never this owner's (lab/local.conf.example)
import importlib.util,io,json,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reconnect',HERE.parent/'reconnect.py')
rc=importlib.util.module_from_spec(spec);spec.loader.exec_module(rc)
spec2=importlib.util.spec_from_file_location('test_client_fake',HERE/'test_client_fake.py')
fake=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(fake)
CFG={'bssid':'02:00:00:00:0b:08','channel':13,'ssid_hex':'4c41422d50492d32'}
class Run(unittest.TestCase):
    def go(self,mode):
        d=Path(tempfile.mkdtemp())/'run';devs=[]
        def factory(elf,log):
            dev=fake.FakeDevice();devs.append(dev);return rc.Client(fake.ELF,log,port=dev)
        observer=[sys.executable,'-u',str(HERE/'fake_observer.py'),str(d/'guardian'),mode]
        try:code=rc.run(CFG,'password1',fake.ELF,d,observer,factory)
        except RuntimeError as e:code=str(e)
        result=json.loads((d/'controller-result.json').read_text())
        return code,result,d,devs[0]
    def test_observer_pipe_closed_without_resource_warning(self):
        import gc,warnings
        for mode in ('pass','early-exit'):
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter('always',ResourceWarning)
                self.go(mode);gc.collect()
            self.assertEqual([str(x.message) for x in w if issubclass(x.category,ResourceWarning)],[],mode)
    def test_two_cycles_pass(self):
        code,r,d,dev=self.go('pass')
        self.assertEqual(code,0,r);self.assertEqual(r['checks']['cycle_requests'][0]>0 and r['checks']['cycle_requests'][1]>0,True)
        self.assertEqual([a['action'] for a in r['actions']],['initial_join','disconnect','rejoin','disconnect','rejoin'])
        self.assertEqual([a['observer_elapsed_s']>=b for a,b in zip([x for x in r['actions'] if x['action']=='disconnect'],(15,40))],[True,True])
        self.assertTrue(r['cleanup']['client_stopped'] and r['cleanup']['console_reader_joined'] and r['cleanup']['guardian_cleanup_ok'])
        self.assertNotIn('password1',(d/'client.jsonl').read_text()+(d/'controller-result.json').read_text())
        self.assertEqual(dev.writes[-1],b'stop\n')
    def test_no_association_fails(self):
        code,r,_,_=self.go('no-assoc');self.assertEqual(code,2);self.assertEqual(r['checks']['cycle_requests'],[0,0]);self.assertFalse(r['pass'])
    def test_observer_early_exit_fails_and_cleans_up(self):
        code,r,_,dev=self.go('early-exit')
        self.assertIn('ended before reconnect',code);self.assertFalse(r['pass']);self.assertTrue(r['cleanup']['client_stopped']);self.assertEqual(dev.writes[-1],b'stop\n')
if __name__=='__main__':unittest.main()

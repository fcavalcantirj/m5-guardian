"""Client protocol checks against a simulated lab-client device (no hardware)."""
import os as _os
_os.environ.update({'GUARDIAN_LOCAL_CONF':'/nonexistent/guardian-test-local.conf','GUARDIAN_LAB_STICK_MAC':'02:00:00:00:0b:01','GUARDIAN_LAB_CARDPUTER_MAC':'02:00:00:00:0b:03','GUARDIAN_LAB_EMITTER_MAC':'02:00:00:00:0b:04','GUARDIAN_LAB_PI_SSH':'lab@lab-pi','GUARDIAN_LAB_PI_PYTHON':'/opt/lab/bin/python','GUARDIAN_LAB_PI_TOOLS':'/opt/lab/tools'})   # synthetic lab bench, never this owner's (lab/local.conf.example)
import importlib.util,io,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reconnect',HERE.parent/'reconnect.py')
rc=importlib.util.module_from_spec(spec);spec.loader.exec_module(rc)
ELF='ab'*32

class FakeDevice:
    """Answers like client_main.cpp: INFO/STATE/STOPPED/ERROR lines."""
    def __init__(self,boot='0123456789abcdef',elf=ELF):
        self.boot=boot;self.elf=elf;self.us=1000;self.out=bytearray();self.active=0;self.connected=0;self.ip=0;self.connects=0;self.disconnects=0;self.reason=0;self.writes=[];self.reboot_next=False;self.fail_joins=0;self.join_mode=None
    def state(self):
        self.us+=1000
        self.out+=f'GCLIENT STATE us={self.us} boot={self.boot} active={self.active} connected={self.connected} ip={self.ip} connects={self.connects} disconnects={self.disconnects} reason={self.reason} deadline_stops=0 command_stops=0 last_join_us=-1 last_stop_us=-1\n'.encode()
    def write(self,data):
        self.writes.append(data)
        for line in data.decode().splitlines():
            if self.reboot_next:self.boot='fedcba9876543210';self.us=10
            if line=='info':self.out+=f'GCLIENT INFO guardian-client/1.1 mac=02:00:00:00:0b:03 boot={self.boot} elf={self.elf}\n'.encode();self.state()
            elif line=='stop':self.active=self.connected=self.ip=0;self.out+=b'GCLIENT STOPPED\n';self.state()
            elif line.startswith('join '):
                self.active=1;self.out+=b'GCLIENT JOINING\n'
                if self.join_mode=='silent':self.join_mode=None;self.state()             # no event: attempt times out
                elif self.join_mode=='reboot':self.boot='fedcba9876543210';self.us=10;self.state()
                elif self.join_mode=='error':self.out+=b'GCLIENT ERROR config\n'
                elif self.fail_joins:self.fail_joins-=1;self.disconnects+=1;self.reason=2;self.state()   # AUTH_EXPIRE, no retry
                else:self.connected=self.ip=1;self.connects+=1;self.state()
            else:self.out+=b'GCLIENT ERROR invalid command\n'
    def read(self,n):
        if not self.out:self.state()
        b=bytes(self.out[:n]);del self.out[:n];return b
    def close(self):pass

CFG={'bssid':'02:00:00:00:0b:08','channel':13,'ssid_hex':'4c41422d50492d32'}
class ClientProtocol(unittest.TestCase):
    def test_identity_join_stop(self):
        dev=FakeDevice();log=io.StringIO();c=rc.Client(ELF,log,port=dev)
        self.assertEqual(c.boot,'0123456789abcdef')
        j=c.join(CFG,'password1',10);self.assertEqual(j['state']['connects'],1)
        self.assertTrue(dev.writes[-1].endswith(b' 10\n'))
        c.stop();self.assertEqual(c.state['active'],0)
    def test_password_never_logged(self):
        dev=FakeDevice();log=io.StringIO();c=rc.Client(ELF,log,port=dev);c.join(CFG,'password1');c.stop()
        self.assertNotIn('password1',log.getvalue());self.assertNotIn('password1'.encode().hex(),log.getvalue())
    def test_wrong_elf_rejected(self):
        dev=FakeDevice(elf='cd'*32)
        with self.assertRaises(RuntimeError):rc.Client(ELF,io.StringIO(),port=dev)
    def test_reboot_detected_by_boot_nonce(self):
        dev=FakeDevice();c=rc.Client(ELF,io.StringIO(),port=dev);dev.reboot_next=True
        with self.assertRaisesRegex(RuntimeError,'rebooted'):c.stop()
    def test_error_raises_unless_collected(self):
        dev=FakeDevice();c=rc.Client(ELF,io.StringIO(),port=dev)
        dev.write(b'bogus\n')
        with self.assertRaisesRegex(RuntimeError,'invalid command'):c.read()
        c.errors=[];dev.write(b'bogus\n');c.read();self.assertEqual(c.errors,['GCLIENT ERROR invalid command'])
    def test_deadline_stop_line_counted(self):
        dev=FakeDevice();c=rc.Client(ELF,io.StringIO(),port=dev);dev.out+=b'GCLIENT STOPPED deadline\n';c.read();self.assertEqual(c.stops,1)

class JoinRetry(unittest.TestCase):
    def test_failed_attempt_is_stopped_and_retried(self):
        dev=FakeDevice();c=rc.Client(ELF,io.StringIO(),port=dev);dev.fail_joins=2
        j=c.join(CFG,'password1',attempt_gap_s=0.05)
        self.assertEqual(len(j['attempts']),3);self.assertEqual([a['result'] for a in j['attempts']],['failed','failed','connected'])
        self.assertEqual(j['state']['connected'],1);self.assertEqual(j['join_sent_us'],j['attempts'][0]['join_sent_us'])
        joins=[w for w in dev.writes if w.startswith(b'join ')];self.assertEqual(len(joins),3)
        pos=[i for i,w in enumerate(dev.writes) if w.startswith(b'join ')];self.assertEqual([dev.writes[i-1] for i in pos[1:]],[b'stop\n',b'stop\n'])
    def test_retries_are_bounded(self):
        dev=FakeDevice();c=rc.Client(ELF,io.StringIO(),port=dev);dev.fail_joins=5
        with self.assertRaisesRegex(RuntimeError,'3 attempts'):c.join(CFG,'password1',attempt_gap_s=0.05)
        self.assertEqual(len([w for w in dev.writes if w.startswith(b'join ')]),3)
class TypedRetry(unittest.TestCase):
    def client(self,mode):
        dev=FakeDevice();c=rc.Client(ELF,io.StringIO(),port=dev);dev.join_mode=mode;return dev,c
    def joins(self,dev):return len([w for w in dev.writes if w.startswith(b'join ')])
    def test_ordinary_timeout_is_retried(self):
        dev,c=self.client('silent');j=c.join(CFG,'password1',attempt_timeout_s=0.3,attempt_gap_s=0.05)
        self.assertEqual([a['result'] for a in j['attempts']],['failed','connected']);self.assertEqual(self.joins(dev),2)
    def test_reboot_during_join_is_not_retried(self):
        dev,c=self.client('reboot')
        with self.assertRaisesRegex(RuntimeError,'rebooted'):c.join(CFG,'password1',attempt_timeout_s=0.3,attempt_gap_s=0.05)
        self.assertEqual(self.joins(dev),1)
    def test_protocol_error_during_join_is_not_retried(self):
        dev,c=self.client('error')
        with self.assertRaisesRegex(RuntimeError,'GCLIENT ERROR config'):c.join(CFG,'password1',attempt_timeout_s=0.3,attempt_gap_s=0.05)
        self.assertEqual(self.joins(dev),1)
    def test_timeout_type(self):
        self.assertTrue(issubclass(rc.ClientTimeout,RuntimeError))
if __name__=='__main__':unittest.main()

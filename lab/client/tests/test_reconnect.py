"""Host checks for the Cardputer reconnect controller's pure helpers.

Run with the IDF Python (has pyserial):
  $IDF_PYTHON -m unittest discover -s lab/client/tests -p 'test_*.py'
"""
import importlib.util,json,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reconnect',HERE.parent/'reconnect.py')
reconnect=importlib.util.module_from_spec(spec);spec.loader.exec_module(reconnect)

AP=bytes.fromhex('020000000b08');STA=bytes.fromhex('020000000b03');OTHER=bytes.fromhex('02aabbccddee')
def mgmt(fc0,a1,a2,a3,body=b''):return bytes([fc0,0])+b'\x00\x00'+a1+a2+a3+b'\x10\x00'+body
REQ=b'\x11\x04\x0a\x00';REASSOC=REQ+AP
def rec(frame,ms,rx_state=0,truncated=False,kind=1):
    return {'kind':kind,'frame_hex':frame.hex(),'mapped_acquired_ms':ms,'rx_state':rx_state,'truncated':truncated,'host_received_us':ms*1000+5000}

class Progress(unittest.TestCase):
    def test_reads_run_report_elapsed(self):
        self.assertEqual(reconnect.progress_elapsed('reconnect: 15s | frames 10 | age 40 ms | burst False | sync envelope 1.0 ms'),15)
        self.assertEqual(reconnect.progress_elapsed('reconnect: 0s | frames 0 | age ? ms | burst False | sync envelope 0.4 ms\n'),0)
    def test_ignores_other_lines(self):
        for line in ('quiet: 15s | frames 1','{"scenario": "reconnect"}','reconnect: xs |',''):
            self.assertIsNone(reconnect.progress_elapsed(line))

class State(unittest.TestCase):
    def test_parses_boot_nonce_and_counters(self):
        s=reconnect.parse_state('GCLIENT STATE us=12 boot=0123456789abcdef active=1 connected=1 ip=1 connects=2 disconnects=1 reason=8 deadline_stops=0 command_stops=1 last_join_us=10 last_stop_us=5')
        self.assertEqual(s['boot'],'0123456789abcdef');self.assertEqual(s['connects'],2);self.assertEqual(s['last_stop_us'],5)
    def test_rejects_malformed_boot(self):
        with self.assertRaises(ValueError):reconnect.parse_state('GCLIENT STATE us=1 boot=zz active=0')

class Witness(unittest.TestCase):
    def setUp(self):
        self.cycles=[(10_000_000,30_000_000),(30_000_000,50_000_000)]
    def run_w(self,records,uncertainty=2000):
        return reconnect.cycle_witnesses(records,AP,STA,self.cycles,uncertainty)
    def test_counts_assoc_and_reassoc_requests_per_cycle(self):
        r=[rec(mgmt(0x00,AP,STA,AP,REQ),12_000),rec(mgmt(0x20,AP,STA,AP,REASSOC),31_000)]
        w=self.run_w(r);self.assertEqual([len(c['requests']) for c in w],[1,1])
    def test_rejects_wrong_direction_other_sta_or_bssid(self):
        r=[rec(mgmt(0x00,STA,AP,AP,REQ),12_000),rec(mgmt(0x00,AP,OTHER,AP,REQ),12_000),rec(mgmt(0x00,AP,STA,OTHER,REQ),12_000),rec(mgmt(0x40,AP,STA,AP,REQ),12_000)]
        self.assertEqual([len(c['requests']) for c in self.run_w(r)],[0,0])
    def test_rejects_unclean_frames(self):
        r=[rec(mgmt(0x00,AP,STA,AP,REQ),12_000,rx_state=1),rec(mgmt(0x00,AP,STA,AP,REQ),12_000,truncated=True),rec(mgmt(0x00,AP,STA,AP)[:20],12_000),{'event':'clock_sync'}]
        self.assertEqual([len(c['requests']) for c in self.run_w(r)],[0,0])
    def test_boundary_ambiguous_frames_not_counted(self):
        # mapped time is a lower bound; true time lies within [ms*1000, ms*1000+999+uncertainty].
        before=rec(mgmt(0x00,AP,STA,AP,REQ),9_999)          # starts before cycle 1
        straddle=rec(mgmt(0x00,AP,STA,AP,REQ),29_998)       # could fall after cycle-1 end
        w=self.run_w([before,straddle],uncertainty=2000)
        self.assertEqual([len(c['requests']) for c in w],[0,0])
        inside=rec(mgmt(0x00,AP,STA,AP,REQ),27_000)
        self.assertEqual(len(self.run_w([inside])[0]['requests']),1)
    def test_records_successful_association_response(self):
        resp=mgmt(0x10,STA,AP,AP,b'\x11\x04\x00\x00\x01\xc0')
        fail=mgmt(0x10,STA,AP,AP,b'\x11\x04\x01\x00\x01\xc0')
        w=self.run_w([rec(resp,12_000),rec(fail,13_000)])
        self.assertEqual(len(w[0]['success_responses']),1)
    def test_requires_uncertainty(self):
        with self.assertRaises(ValueError):reconnect.cycle_witnesses([],AP,STA,self.cycles,None)

class Review12288(unittest.TestCase):
    cycles=[(10_000_000,30_000_000)]
    def count(self,frame,**kw):return len(reconnect.cycle_witnesses([rec(frame,12_000,**kw)],AP,STA,self.cycles,1000)[0]['requests'])
    def test_assoc_request_needs_fixed_fields(self):
        self.assertEqual(self.count(mgmt(0x00,AP,STA,AP)),0)                 # 24-byte header only
        self.assertEqual(self.count(mgmt(0x00,AP,STA,AP,b'\x11\x04\x0a\x00')),1)
    def test_reassoc_request_needs_current_ap(self):
        self.assertEqual(self.count(mgmt(0x20,AP,STA,AP,b'\x11\x04\x0a\x00')),0)
        self.assertEqual(self.count(mgmt(0x20,AP,STA,AP,b'\x11\x04\x0a\x00'+AP)),1)
    def test_protected_or_fragmented_rejected(self):
        body=b'\x11\x04\x0a\x00'
        f=bytearray(mgmt(0x00,AP,STA,AP,body));f[1]|=0x40;self.assertEqual(self.count(bytes(f)),0)
        f=bytearray(mgmt(0x00,AP,STA,AP,body));f[1]|=0x04;self.assertEqual(self.count(bytes(f)),0)
        f=bytearray(mgmt(0x00,AP,STA,AP,body));f[22]=0x11;self.assertEqual(self.count(bytes(f)),0)
    def test_pass_requires_reader_join_and_no_forced_kill(self):
        good={'client_stopped':True,'guardian_cleanup_ok':True,'console_reader_joined':True}
        self.assertTrue(reconnect.final_pass(True,good))
        self.assertFalse(reconnect.final_pass(True,{**good,'console_reader_joined':False}))
        self.assertFalse(reconnect.final_pass(True,{k:v for k,v in good.items() if k!='console_reader_joined'}))
        self.assertFalse(reconnect.final_pass(True,{**good,'guardian_forced_kill':True}))
        self.assertFalse(reconnect.final_pass(False,good))
    def test_progress_freshness_uses_event_receipt_time(self):
        t=reconnect.ProgressTracker(begin_us=0,startup_s=30,stale_s=10)
        t.feed(1_000_000,0);t.feed(5_000_000,5)
        with self.assertRaisesRegex(RuntimeError,'stale'):t.check(16_000_000)   # drained late, but last event was at 5 s
    def test_progress_must_increase(self):
        t=reconnect.ProgressTracker(begin_us=0,startup_s=30,stale_s=10);t.feed(1_000_000,5)
        with self.assertRaisesRegex(RuntimeError,'increase'):t.feed(2_000_000,5)
    def test_progress_startup_limit(self):
        t=reconnect.ProgressTracker(begin_us=0,startup_s=30,stale_s=10);t.check(29_000_000)
        with self.assertRaisesRegex(RuntimeError,'no progress'):t.check(31_000_000)

class Clock(unittest.TestCase):
    def test_host_clock_is_harness_monotonic_domain(self):
        import time
        a=time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000;b=reconnect.host_us();c=time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000
        self.assertTrue(a<=b<=c)

if __name__=='__main__':unittest.main()

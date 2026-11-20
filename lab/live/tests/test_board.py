"""Synthetic transport checks only; never a board/RF acceptance claim."""
import os as _os
_os.environ.update({'GUARDIAN_LOCAL_CONF':'/nonexistent/guardian-test-local.conf','GUARDIAN_LAB_STICK_MAC':'02:00:00:00:0b:01','GUARDIAN_LAB_CARDPUTER_MAC':'02:00:00:00:0b:03','GUARDIAN_LAB_EMITTER_MAC':'02:00:00:00:0b:04','GUARDIAN_LAB_PI_SSH':'lab@lab-pi','GUARDIAN_LAB_PI_PYTHON':'/opt/lab/bin/python','GUARDIAN_LAB_PI_TOOLS':'/opt/lab/tools'})   # synthetic lab bench, never this owner's (lab/local.conf.example)
import json,sys,unittest,zlib
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from board import BoardSession
class Mapping:
    def map(self,t):return t+1000000
class BoardOutputTests(unittest.TestCase):
    def session(self):
        s=BoardSession.__new__(BoardSession);s.boot='0123456789abcdef';s.mapping=Mapping()
        s.scope={'bssid':'02:11:22:33:44:55','ssid_hex':'6170'};s.states=[];s.state={};s.board_ready=True
        import io
        s.engine_log=io.StringIO();return s
    def state(self,**kw):
        e=dict(event='state',origin='live',bssid='021122334455',ssid_hex='6170',now_ms=1000,age_ms=10,burst_acquired_ms=900,burst_count=20)
        e.update(kw);payload=json.dumps(e).encode();return b'G13 0123456789abcdef '+f'{zlib.crc32(payload):08x} '.encode()+payload
    @patch('board.micros',return_value=2010000)
    def test_maps_board_acquisition_and_uses_actual_receipt_for_latency(self,_):
        s=self.session();s.process(self.state())
        self.assertEqual(s.state['now_ms'],2010);self.assertEqual(s.state['age_ms'],20)
        self.assertEqual(s.state['burst_acquired_ms'],1900);self.assertEqual(s.state['execution_target'],'sticks3')
    @patch('board.micros',return_value=2010000)
    def test_rejects_wrong_scope_demo_and_boot(self,_):
        for change in ({'origin':'demo'},{'bssid':'021122334466'},{'ssid_hex':'62'}):
            with self.assertRaises(RuntimeError):self.session().process(self.state(**change))
        with self.assertRaises(RuntimeError):self.session().process(self.state().replace(b'0123456789abcdef',b'9999999999999999'))
    @patch('board.micros',return_value=2400000)
    def test_stalled_telemetry_is_not_timely_detection(self,_):
        with self.assertRaises(RuntimeError):self.session().process(self.state())
    @patch('board.micros',return_value=2010000)
    def test_telemetry_crc_covers_the_actual_state(self,_):
        with self.assertRaises(RuntimeError):self.session().process(self.state().replace(b'6170',b'6171'))
    def test_identity_requires_the_reviewed_elf_and_exact_board_mac(self):
        s=self.session();s.expected_elf='a'*64
        banner=b'GRX1 INFO guardian-sticks3/1.0 mac=02:00:00:00:0b:01 elf='+b'a'*64
        self.assertTrue(s.identify_receiver(banner))
        with self.assertRaises(RuntimeError):s.identify_receiver(banner.replace(b'elf=aaaa',b'elf=bbbb'))
        with self.assertRaises(RuntimeError):s.identify_receiver(banner.replace(b'0b:01',b'0b:02'))
    def test_radio_frame_input_cannot_be_injected_over_console(self):
        s=self.session();s.serial=type('Serial',(),{'write':lambda self,x:(_ for _ in ()).throw(AssertionError('unexpected write'))})()
        s.send_engine('FRAME 1000 6 -40 0 0 4 00');s.send_engine('COVER 1000 6 1 1 0 1')
    def test_settings_bootstrap_requests_bounded_fixed_channel_listening(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        s=self.session();s.args=SimpleNamespace(scenario='settings',seconds=70)
        s.scope['channel']=13;s.serial=Mock()
        s.start_receiver()
        s.serial.write.assert_called_once_with(b'listen 13 75\n')
    def test_channel_bootstrap_releases_to_bounded_real_discovery(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        s=self.session();s.args=SimpleNamespace(scenario='channel',seconds=95)
        s.scope['channel']=13;s.serial=Mock();s.start_receiver()
        s.serial.write.assert_called_once_with(b'listen 13 100\n')
        s.serial.reset_mock();s.release_fixed_channel(80)
        s.serial.write.assert_called_once_with(b'stop\nstart 13 85\n')
        for seconds in [0,296,301,True]:
            with self.assertRaises(ValueError):s.release_fixed_channel(seconds)
    def test_controller_go_rejects_a_hotspot_that_moved_channels(self):
        import io,queue
        from types import SimpleNamespace
        from unittest.mock import Mock
        from run import Session
        s=Session.__new__(Session);s.serial=Mock();s.serial.read.return_value=b''
        s.stream=Mock();s.stream.feed.return_value=[];s.engine_events=queue.Queue();s.emitter_events=queue.Queue()
        s.args=SimpleNamespace(scenario='related-approved');s.scope={'channel':5}
        s.state={'has_security':True,'age_ms':50,'channel':11};s.emitter=SimpleNamespace(stdin=io.StringIO())
        s.emitter_events.put({'event':'ready','role':'test_ap'})
        with self.assertRaises(RuntimeError):s.drain()
        self.assertEqual(s.emitter.stdin.getvalue(),'')
        s.state['channel']=5;s.emitter_events.put({'event':'ready','role':'test_ap'});s.drain()
        self.assertEqual(s.emitter.stdin.getvalue(),'GO\n')
    def test_channel_admission_preserves_legacy_fixed_receiver_and_prefers_advertisement(self):
        from run import Session
        s=Session.__new__(Session);s.state={};s.heartbeat={'flags':1,'channel':6}
        self.assertEqual(s.observed_scope_channel(),6)
        s.heartbeat['flags']=0;self.assertIsNone(s.observed_scope_channel())
        s.state={'channel':6,'advertised_channel':5};self.assertEqual(s.observed_scope_channel(),5)
    def test_ordinary_capture_keeps_passive_discovery(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        s=self.session();s.args=SimpleNamespace(scenario='quiet',seconds=30)
        s.scope['channel']=6;s.serial=Mock()
        s.start_receiver()
        s.serial.write.assert_called_once_with(b'start 6 35\n')
    def test_board_deadline_is_a_backstop_after_the_host_window(self):
        # reconnect-02 (2026-11-15): a board deadline equal to the host window
        # stopped reception inside the final drain and counted a queued discard.
        from types import SimpleNamespace
        from unittest.mock import Mock
        s=self.session();s.scope['channel']=1;s.serial=Mock()
        s.args=SimpleNamespace(scenario='reconnect',seconds=75);s.start_receiver()
        s.serial.write.assert_called_once_with(b'start 1 80\n')
        s.serial.reset_mock();s.args=SimpleNamespace(scenario='reconnect',seconds=296)
        with self.assertRaises(ValueError):s.start_receiver()
        s.serial.write.assert_not_called()
    def test_board_window_bounds_295_valid_296_rejected_before_device_or_output(self):
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import Mock
        s=self.session();s.scope['channel']=1;s.serial=Mock();s.args=SimpleNamespace(scenario='reconnect',seconds=295);s.start_receiver()
        s.serial.write.assert_called_once_with(b'start 1 300\n')
        d=Path(tempfile.mkdtemp());cfg=d/'scope.json'
        cfg.write_text(json.dumps({'country':'BR','firmware_elf_sha256':'ab'*32}))
        with patch('serial.tools.list_ports.comports') as ports, self.assertRaisesRegex(ValueError,'295'):
            BoardSession(SimpleNamespace(config=str(cfg),out=str(d/'out'),scenario='reconnect',seconds=296))
        ports.assert_not_called();self.assertFalse((d/'out').exists())
    def test_post_window_stop_discard_is_reported_separately(self):
        from run import window_and_stop_drops
        r=window_and_stop_drops({'receiver_drops':0},{'receiver_stop_status':{'queue_drops':1,'bad_input':0}})
        self.assertEqual(r,{'observation_receiver_drops':0,'post_window_stop_discards':1})
        r=window_and_stop_drops({'receiver_drops':2},{'receiver_stop_status':{'queue_drops':2,'bad_input':1}})
        self.assertEqual(r,{'observation_receiver_drops':2,'post_window_stop_discards':1})
        self.assertEqual(window_and_stop_drops({'receiver_drops':0},{}),{'observation_receiver_drops':0,'post_window_stop_discards':None})
if __name__=='__main__':unittest.main()

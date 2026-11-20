import os,json,subprocess,time,unittest
from pathlib import Path
ENGINE=os.environ.get('GUARDIAN_ENGINE','/private/tmp/guardian-live-build/guardian_live_engine')
FIX=Path(os.environ.get('GUARDIAN_ROOT',str(Path(__file__).resolve().parents[3])))/'firmware/tests/fixtures'
def fixture(name):return bytes.fromhex(' '.join(l.split('#')[0] for l in (FIX/(name+'.hex')).read_text().splitlines()))
def frame(b,ago=0,reported=None):
 now=time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000000
 return f'FRAME {now-ago} 6 -45 0 0 {len(b)+4 if reported is None else reported} {b.hex()}\n'
def run(lines):
 p=subprocess.run([ENGINE,'--imported','021122334455','686f6d65','01020304050607080910111213141516'],input=lines+'SNAPSHOT\nQUIT\n',text=True,capture_output=True,timeout=4)
 return p,[json.loads(l) for l in p.stdout.splitlines() if l.startswith('{')]
class EngineTests(unittest.TestCase):
 def test_same_library_beacon(self):
  p,rows=run(frame(fixture('beacon_wpa3_sae_pmf_required')));self.assertEqual(p.returncode,0,p.stderr);s=rows[-1];self.assertTrue(s['has_security']);self.assertTrue(s['historical']);self.assertEqual(s['origin'],'imported');self.assertEqual(s['mode'],5);self.assertEqual(s['pmf'],3);self.assertEqual(s['selected_advertisements'],1)
 def test_advertised_and_receiver_channels_are_distinct(self):
  b=bytearray(fixture('beacon_wpa3_sae_pmf_required'));i=36
  while i+2<=len(b):
   tag,n=b[i:i+2];i+=2
   if tag==3:b[i]=5
   i+=n
  p,rows=run(frame(b)+'BASELINE\n'+frame(b)+frame(b))
  self.assertEqual(p.returncode,0,p.stderr);self.assertFalse(rows[-1]['settings_changed'])
  self.assertEqual(rows[-1]['channel'],6);self.assertEqual(rows[-1]['advertised_channel'],5)
 def test_scope(self):
  b=bytearray(fixture('beacon_wpa3_sae_pmf_required'));b[21]=0x56;p,rows=run(frame(b));self.assertEqual(p.returncode,0,p.stderr);self.assertFalse(rows[-1]['has_security'])
 def test_threshold(self):
  b=fixture('deauth_reason7');p,rows=run(''.join(frame(b) for _ in range(20)));self.assertEqual(p.returncode,0,p.stderr);self.assertTrue(rows[-1]['burst']);self.assertEqual(rows[-1]['burst_count'],20);self.assertTrue(rows[-1]['incident_visible']);self.assertGreater(rows[-1]['burst_acquired_ms'],0);self.assertLessEqual(rows[-1]['burst_acquired_ms'],rows[-1]['now_ms'])
 # G16J: the Pi emitter's own template (reason 2, sequence control 0xFFF0, Duration 0x013A, as the AP to
 # broadcast) is a known tool shape: the red burst is reported at half the count and says so.
 def test_emitter_template_is_a_shaped_burst_at_half_the_threshold(self):
  t=bytes.fromhex('c0003a01ffffffffffff021122334455021122334455f0ff0200')
  p,rows=run(''.join(frame(t) for _ in range(10)));self.assertEqual(p.returncode,0,p.stderr)
  self.assertTrue(rows[-1]['burst']);self.assertEqual(rows[-1]['burst_count'],10);self.assertEqual(rows[-1]['burst_threshold'],10)
  self.assertEqual(rows[-1]['burst_shapes']&1,1);self.assertTrue(rows[-1]['incident_visible'])
  p,rows=run(''.join(frame(t) for _ in range(9)));self.assertEqual(p.returncode,0,p.stderr);self.assertFalse(rows[-1]['burst'])
  self.assertEqual(rows[-1]['burst_shapes'],0)
 # G16R: the picked network is its name. A burst naming a second address that was heard beaconing the picked
 # name is the red burst; the same burst without that address ever advertising the name is not.
 def test_g16r_burst_on_a_second_address_of_the_picked_name_is_red(self):
  b=bytearray(fixture('beacon_wpa3_sae_pmf_required'));b[15]=0x56;b[21]=0x56
  d=bytearray(fixture('deauth_reason7'));d[15]=0x56;d[21]=0x56
  p,rows=run(frame(b)+''.join(frame(d) for _ in range(20)));self.assertEqual(p.returncode,0,p.stderr)
  self.assertTrue(rows[-1]['burst']);self.assertEqual(rows[-1]['burst_count'],20);self.assertTrue(rows[-1]['incident_visible'])
  p,rows=run(''.join(frame(d) for _ in range(20)));self.assertEqual(p.returncode,0,p.stderr);self.assertFalse(rows[-1]['burst'])
 def test_below_threshold(self):
  p,rows=run(''.join(frame(fixture('deauth_reason7')) for _ in range(19)));self.assertEqual(p.returncode,0);self.assertFalse(rows[-1]['burst'])
 def test_related_ap_observed_and_unapproved(self):
  b=bytearray(fixture('beacon_wpa3_sae_pmf_required'));b[15]=0x56;b[21]=0x56;p,rows=run('WATCH_AP 021122334456\n'+frame(b)+frame(b));self.assertEqual(p.returncode,0,p.stderr);self.assertTrue(rows[-1]['unexpected_ap']);self.assertEqual(rows[-1]['watched_advertisements'],2)
 def test_approved_related_ap_has_no_unexpected_alert(self):
  b=bytearray(fixture('beacon_wpa3_sae_pmf_required'));b[15]=0x56;b[21]=0x56;p,rows=run('APPROVE_AP 021122334456\n'+frame(b)+frame(b));self.assertEqual(p.returncode,0,p.stderr);self.assertFalse(rows[-1]['unexpected_ap']);self.assertEqual(rows[-1]['watched_advertisements'],2)
 def test_bad_length_rejected(self):
  p,_=run(frame(fixture('deauth_reason7'),reported=100));self.assertNotEqual(p.returncode,0)
 def test_future_rejected(self):
  p,_=run(frame(fixture('deauth_reason7'),ago=-1000));self.assertNotEqual(p.returncode,0)
 def test_stale_not_fresh(self):
  p,rows=run(frame(fixture('beacon_wpa3_sae_pmf_required'),ago=31000));self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(rows[-1]['mood'],0)
 def test_oversize(self):
  p,_=run('x'*4000+'\n');self.assertNotEqual(p.returncode,0)
 # Supervisor review 2026-11-17: the lab engine runs the SAME G16F/G16G threat
 # detectors as the firmware, so owner Evil-Cardputer runs can be asserted live.
 def test_probe_flood_from_random_sources_is_a_nearby_incident(self):
  b=bytearray(fixture('probereq_wildcard_random'))
  lines=''
  for i in range(100):
   b[10:16]=bytes([0x02|0x40,0x10,0x20,0x30,i>>8,i&0xff]);b[22:24]=((i<<4)&0xfff0).to_bytes(2,'little')
   lines+=frame(b,ago=2000-i*20)
  p,rows=run(lines)
  self.assertEqual(p.returncode,0,p.stderr)
  area=rows[-1]['area']
  probe=[a for a in area if a['family']==2]
  # G16J: the probe defaults are the values measured on one channel (16 probes / 12 addresses / 10 s, was 80 / 60 / 5 s).
  self.assertTrue(probe,area);self.assertGreaterEqual(probe[0]['count'],16);self.assertTrue(probe[0]['visible'])
  self.assertFalse(rows[-1]['incident_visible'])   # nearby (amber) is never the network ALERT
if __name__=='__main__':unittest.main()

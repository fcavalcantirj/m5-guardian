import unittest,struct,zlib,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from receiver import decode,command,LineBuffer

def packet(kind=1,payload=b'\x80'+bytes(23),channel=6,flags=5,reported=None):
 h=struct.pack('<4sBBBBQIQIHHbbBBIIII',b'GRX1',1,kind,flags,channel,123,7,900000,4000,len(payload)+4 if reported is None else reported,len(payload),-40,-95,0,0,9,1,0,zlib.crc32(payload))
 b=h+payload;return b'GRX1 '+(b+struct.pack('<I',zlib.crc32(b))).hex().encode()+b'\n'

class ProtocolTests(unittest.TestCase):
 def test_frame(self):
  r=decode(packet());self.assertEqual(r['frame_hex'],'80'+'00'*23);self.assertEqual(r['acquired_us'],900000);self.assertEqual(r['rssi'],-40);self.assertTrue(r['fcs_matches'])
 def test_fcs_unavailable_stays_unknown(self):
  self.assertIsNone(decode(packet(flags=1))['fcs_matches'])
 def test_crc_covers_metadata(self):
  b=bytearray.fromhex(packet()[5:].decode());b[7]=11
  with self.assertRaises(ValueError):decode(b'GRX1 '+b.hex().encode())
 def test_short(self):
  with self.assertRaises(ValueError):decode(b'GRX1 01')
 def test_corrupt_length(self):
  with self.assertRaises(ValueError):decode(packet(reported=3))
 def test_unknown_kind(self):
  with self.assertRaises(ValueError):decode(packet(kind=9))
 def test_truncation(self):
  self.assertTrue(decode(packet(payload=bytes(1536),flags=3,reported=2400))['truncated'])
  with self.assertRaises(ValueError):decode(packet(flags=1,reported=2400))
 def test_cap(self):
  with self.assertRaises(ValueError):decode(packet(payload=bytes(1537)))
 def test_channel(self):
  with self.assertRaises(ValueError):decode(packet(channel=0))
 def test_reserved(self):
  with self.assertRaises(ValueError):decode(packet(flags=128))
 def test_command(self):
  self.assertEqual(command(6,20),b'start 6 20\n')
  for c,d in [(0,20),(15,20),(6,0),(6,301),(6,1.5)]:
   with self.assertRaises(ValueError):command(c,d)
 def test_stream_split_and_resync(self):
  f=LineBuffer();p=packet();self.assertEqual(f.feed(p[:10]),[]);self.assertEqual(f.feed(p[10:]),[p.rstrip(b'\n')]);self.assertEqual(f.feed(b'x'*4000+b'\n'+p),[p.rstrip(b'\n')]);self.assertEqual(f.oversized,1)
 def test_unknown_text(self):
  with self.assertRaises(ValueError):decode(b'boot log')
if __name__=='__main__':unittest.main()

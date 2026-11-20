# Ground truth for "deauth not detected": console-mode capture on the StickS3, fixed channel 11,
# every management frame recorded, then decoded. Read-only for the AP; the stick only listens.
#   python3 deauth_truth.py <port> <seconds> <out.log> --ap <bssid> --ssid <network name>
# or GUARDIAN_LAB_AP / GUARDIAN_LAB_SSID in the environment. The owner's network is never written in this
# repository (redaction 2026-11-19); without a target the script refuses before it opens any port.
import argparse, os, re, sys, time, json, collections
from pathlib import Path

def target(argv, env):
    """(bssid as 12 lowercase hex, network name as hex) from --ap/--ssid, else GUARDIAN_LAB_AP/GUARDIAN_LAB_SSID."""
    a = argparse.ArgumentParser(add_help=False); a.add_argument('--ap'); a.add_argument('--ssid')
    known, _ = a.parse_known_args(argv)
    ap = known.ap if known.ap is not None else env.get('GUARDIAN_LAB_AP')
    ssid = known.ssid if known.ssid is not None else env.get('GUARDIAN_LAB_SSID')
    if not ap or ssid is None:
        raise ValueError('name the target network: --ap <bssid> --ssid <name>, or GUARDIAN_LAB_AP and GUARDIAN_LAB_SSID')
    hexap = re.sub(r'[:\-]', '', ap).lower()
    if not re.fullmatch(r'[0-9a-f]{12}', hexap): raise ValueError('GUARDIAN_LAB_AP / --ap: six bytes, e.g. 02:00:00:00:00:01')
    raw = ssid.encode()
    if not 1 <= len(raw) <= 32: raise ValueError('GUARDIAN_LAB_SSID / --ssid: 1 to 32 bytes')
    return hexap, raw.hex()

if __name__ == '__main__':
    try:
        AP, SSID = target(sys.argv[1:], os.environ)
    except ValueError as e:
        print(f'deauth_truth: {e}', file=sys.stderr); sys.exit(2)
    a = argparse.ArgumentParser(); a.add_argument('port'); a.add_argument('secs', type=int); a.add_argument('out')
    a.add_argument('--ap'); a.add_argument('--ssid')
    args = a.parse_args()
    port, secs, out = args.port, args.secs, args.out
    sys.path.insert(0, os.environ.get('GUARDIAN_RX_MODULE', str(Path(__file__).resolve().parents[1] / 'receiver')))
    from receiver import decode
    import serial
    p = serial.Serial(); p.port = port; p.baudrate = 115200; p.timeout = 0.2; p.dtr = False; p.rts = False; p.open()
    time.sleep(4); p.reset_input_buffer()
    log = open(out, 'w'); buf = b''
    def pump(t):
        global buf
        end = time.time() + t
        while time.time() < end:
            buf += p.read(65536)
            while b'\n' in buf:
                line, buf = buf.split(b'\n', 1); log.write(line.decode(errors='replace') + '\n')
    p.write(b'INFO\n'); pump(1)
    p.write(f'select {AP} {SSID} BR\n'.encode()); pump(1)
    p.write(f'listen 11 {secs}\n'.encode())
    print(f'LISTENING on channel 11 for {secs} s — start the deauther now', flush=True)
    t0 = time.time()
    while time.time() - t0 < secs + 3:
        pump(5); p.write(b'SNAPSHOT\n')
    log.close(); p.close()
    kinds = collections.Counter(); deauth = collections.Counter(); first = None; acks = []
    for line in open(out):
        if line.startswith(('G13 ACK', 'GRX1 ERROR', 'GRX1 INFO')): acks.append(line.strip()[:160])
        if not line.startswith('GRX1 ') or line.startswith(('GRX1 INFO', 'GRX1 ERROR', 'GRX1 SYNC')): continue
        try: r = decode(line.strip().encode())
        except Exception: continue
        if r.get('kind') != 1: continue
        b = bytes.fromhex(r['frame_hex'])
        if len(b) < 24: continue
        st = (b[0] >> 4) & 0xF; kinds[st] += 1
        if st in (10, 12):
            key = ('deauth' if st == 12 else 'disassoc', b[4:10].hex(), b[10:16].hex(), b[16:22].hex(), r['channel'])
            deauth[key] += 1
    print('ACKS:', *acks[:6], sep='\n  ')
    print('mgmt subtypes seen:', dict(sorted(kinds.items())), '(12=deauth, 10=disassoc, 8=beacon, 4=probe req)')
    print('deauth/disassoc by (kind, addr1, addr2, addr3=bssid, ch):')
    for k, n in deauth.most_common(12): print('  ', n, k, 'IN-SCOPE' if k[3] == AP else 'other bssid')
    snaps = [l for l in open(out) if l.startswith('G13 ') and 'incident' in l]
    print('last snapshot:', snaps[-1][:900] if snaps else 'none')

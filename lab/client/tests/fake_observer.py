"""Stand-in for run_board.py in host tests: paced progress, receiver records, results."""
import json,sys,time
from pathlib import Path
out=Path(sys.argv[1]);mode=sys.argv[2] if len(sys.argv)>2 else 'pass';out.mkdir(parents=True)
AP='020000000b08';STA='020000000b03'
def us():return time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000
frame=bytes.fromhex('0000'+'0000'+AP+STA+AP+'1000'+'11040a00').hex()
with (out/'receiver.jsonl').open('w') as raw:
    raw.write(json.dumps({'event':'clock_sync','uncertainty_us':1000})+'\n')
    for e in range(0,80,5):
        if mode=='early-exit' and e==20:break
        print(f'reconnect: {e}s | frames 1 | age 10 ms | burst False | sync envelope 1.0 ms',flush=True)
        t=time.monotonic()+0.4
        while time.monotonic()<t:
            if mode!='no-assoc':raw.write(json.dumps({'kind':1,'frame_hex':frame,'mapped_acquired_ms':us()//1000-3,'rx_state':0,'truncated':False})+'\n')
            time.sleep(.05)
(out/'result.json').write_text(json.dumps({'run_complete_pass':mode!='early-exit','checks':{'association_frames_after_baseline':2}}))
(out/'cleanup.json').write_text(json.dumps({'ok':True}))
sys.exit(0 if mode!='early-exit' else 2)

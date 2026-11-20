#!/usr/bin/env python3
"""Receive-only GRX1 qualification tools; no flash or offensive commands."""
import argparse,json,struct,time,zlib
from pathlib import Path
HEADER=struct.Struct('<4sBBBBQIQIHHbbBBIIII')
MAX_FRAME=1536
MAX_LINE=6+2*(HEADER.size+MAX_FRAME+4)

def decode(line):
    if len(line)>MAX_LINE or not line.startswith(b'GRX1 '):raise ValueError('not a bounded GRX1 record')
    try:b=bytes.fromhex(line[5:].decode('ascii').strip())
    except (ValueError,UnicodeError) as e:raise ValueError('invalid hex') from e
    if len(b)<HEADER.size+4:raise ValueError('short record')
    if zlib.crc32(b[:-4])!=int.from_bytes(b[-4:],'little'):raise ValueError('transport CRC mismatch')
    magic,version,kind,flags,channel,boot,sequence,acquired,radio,reported,size,rssi,noise,state,reserved,received,drops,bad,fcs=HEADER.unpack_from(b)
    if magic!=b'GRX1' or version!=1 or kind not in (1,2,3,4) or flags&~7 or reserved or not boot:raise ValueError('unsupported record')
    if size>MAX_FRAME or len(b)!=HEADER.size+size+4:raise ValueError('length mismatch')
    if kind==1:
        if not 1<=channel<=14 or reported<4 or size!=min(reported-4,MAX_FRAME) or bool(flags&2)!=(reported-4>size) or not flags&1:raise ValueError('invalid frame metadata')
    elif size!=0 or reported!=0 or flags&6 or channel>14:raise ValueError('invalid status metadata')
    return dict(kind=kind,flags=flags,channel=channel,boot=f'{boot:016x}',sequence=sequence,acquired_us=acquired,radio_us=radio,reported_length=reported,rssi=rssi,noise=noise,rx_state=state,received=received,queue_drops=drops,bad_input=bad,truncated=bool(flags&2),frame_hex=b[HEADER.size:-4].hex(),fcs_le=fcs,fcs_available=bool(flags&4),fcs_matches=(zlib.crc32(b[HEADER.size:-4])==fcs if kind==1 and flags&4 and not flags&2 else None))

def command(channel,seconds):
    if type(channel) is not int or type(seconds) is not int or not 1<=channel<=14 or not 1<=seconds<=300:raise ValueError('channel 1..14 and duration 1..300 seconds required')
    return f'start {channel} {seconds}\n'.encode()

class LineBuffer:
    def __init__(self):self.buf=bytearray();self.discard=False;self.oversized=0
    def feed(self,data):
        lines=[]
        for c in data:
            if c==10:
                if not self.discard:lines.append(bytes(self.buf))
                self.buf.clear();self.discard=False
            elif not self.discard:
                if len(self.buf)>=MAX_LINE:self.buf.clear();self.discard=True;self.oversized+=1
                else:self.buf.append(c)
        return lines

def open_port(port):
    import serial
    s=serial.Serial(port=None,baudrate=115200,timeout=.1,write_timeout=1,exclusive=True)
    s.dtr=False;s.rts=False;s.port=port;s.open();return s

def capture(args):
    # Capture duration is bounded on both receiver and host. Raw data is evidence,
    # not a guarantee of valid FCS or transport latency, and is never a grade.
    import sys
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
    import guardian_local
    store=guardian_local.store()   # fail-closed: mounted share + sentinel (GUARDIAN_STORE, lab/local.conf.example)
    out=Path(args.out).resolve()
    if not out.is_relative_to(store):raise ValueError('output must be inside the artifact store (GUARDIAN_STORE)')
    out.parent.mkdir(parents=True,exist_ok=True)
    cmd=command(args.channel,args.seconds);stream=LineBuffer();valid=frames=errors=0;boot=None;lastseq=None;gaps=0;lasttime=None;stopped=False
    with out.open('x') as log,open_port(args.port) as s:
        def record(r):log.write(json.dumps(r)+'\n');log.flush()
        deadline=time.monotonic()+8;identified=False;next_info=0.0
        while time.monotonic()<deadline and not identified:
            if time.monotonic()>=next_info:
                s.write(b'info\n');next_info=time.monotonic()+.5
            for line in stream.feed(s.read(512)):
                if line.startswith(b'GRX1 INFO ') and b'guardian-rx/1' in line:
                    record({'identity':line.decode('ascii'),'live':True});identified=True
        s.reset_input_buffer();stream=LineBuffer()
        if not identified:raise ValueError('receiver identity not confirmed; nothing started')
        try:
            s.write(cmd);deadline=time.monotonic()+args.seconds+4
            while time.monotonic()<deadline and not stopped:
                for line in stream.feed(s.read(4096)):
                    if not line.startswith(b'GRX1 '):continue
                    if line.startswith((b'GRX1 INFO ',b'GRX1 ERROR ')):
                        record({'device_text':line.decode('ascii','replace')})
                        if line.startswith(b'GRX1 ERROR '):raise ValueError('receiver rejected command')
                        continue
                    try:r=decode(line)
                    except ValueError:errors+=1;continue
                    if boot is not None and boot!=r['boot']:raise ValueError('receiver rebooted during capture')
                    if lasttime is not None and r['acquired_us']<lasttime and r['kind']!=1:raise ValueError('receiver clock moved backwards')
                    if lastseq is not None:gaps+=(r['sequence']-lastseq-1)&0xffffffff
                    boot=r['boot'];lastseq=r['sequence'];lasttime=r['acquired_us'];valid+=1;frames+=r['kind']==1
                    record(dict(r,host_received_monotonic_ns=time.monotonic_ns(),live=True,qualification_only=True))
                    if r['kind']==4:stopped=True
        finally:s.write(b'stop\n')
        record({'summary':True,'frames':frames,'records':valid,'transport_errors':errors,'sequence_gaps':gaps,'oversized_lines':stream.oversized,'device_stop_seen':stopped,'live_validation_pass':False})
    print(f'{frames} frames recorded → {out}; qualification only, not live acceptance')
    return 0 if frames and stopped and not errors and not gaps else 2

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    sub.add_parser('ports',help='list USB serial identities without opening devices')
    c=sub.add_parser('capture',help='bounded passive reception; requires prepared receiver firmware')
    c.add_argument('--port',required=True);c.add_argument('--channel',required=True,type=int);c.add_argument('--seconds',type=int,default=30);c.add_argument('--out',required=True)
    a=p.parse_args()
    if a.action=='ports':
        from serial.tools import list_ports
        for d in list_ports.comports():print(f'{d.device}\tVID={d.vid!s} PID={d.pid!s}\tserial={d.serial_number}\t{d.description}')
        return 0
    return capture(a)
if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError) as e:raise SystemExit(str(e))

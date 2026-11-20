"""Pure admission, stop-state and conservative clock-mapping rules for lab tools."""
import re

def validate_scope(config):
    c=dict(config);mac=c.get('bssid','')
    if not isinstance(mac,str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',mac):raise ValueError('exact BSSID required')
    raw=bytes.fromhex(mac.replace(':',''))
    if not any(raw) or raw[0]&1:raise ValueError('unicast nonzero BSSID required')
    for key,low,high in [('channel',1,13),('groups',1,8),('deadline_s',1,4)]:
        if type(c.get(key)) is not int or not low<=c[key]<=high:raise ValueError(f'invalid {key}')
    try:ssid=bytes.fromhex(c.get('ssid_hex',''))
    except (TypeError,ValueError) as e:raise ValueError('SSID must be exact hex bytes') from e
    if not 1<=len(ssid)<=32:raise ValueError('visible SSID of 1..32 bytes required for this lab adapter')
    c['bssid']=mac.lower();c['ssid_hex']=ssid.hex();return c

class BatchState:
    def __init__(self):self.pending=False;self.stopped=False;self.started=0.0;self.completed=0
    def begin(self,now):
        if self.pending or self.stopped:raise ValueError('batch refused: pending or stopped')
        self.pending=True;self.started=now
    def line(self,text):
        if text.startswith('ERR'):raise ValueError(text)
        if text.startswith('OK deauth done'):
            if not self.pending or text.strip()!='OK deauth done 1':raise ValueError('unexpected completion')
            self.pending=False;self.completed+=1;return True
        return False
    def expired(self,now):return self.pending and now-self.started>=1.0
    def stop(self):self.stopped=True

class ClockMap:
    """Map receiver acquisition onto CLOCK_MONOTONIC, never receipt time.

    Each request/response brackets offset. Use the smallest observed lower
    bound (conservative aging), and expose the full observed interval width.
    This is an observed synchronization envelope, not a hard oscillator/jitter
    guarantee. Re-sample during each bounded run; reject >100 ms uncertainty.
    """
    def __init__(self):self.low=None;self.high=None;self.last_device=None
    @property
    def uncertainty_us(self):return None if self.low is None else self.high-self.low
    def sample(self,start,end,device):
        if not 0<=start<=end or end-start>100000 or device<0:raise ValueError('invalid or slow clock sample')
        if self.last_device is not None and device<=self.last_device:raise ValueError('receiver clock reset/stale sync')
        lo=start-device;hi=end-device
        newlow=lo if self.low is None else min(self.low,lo);newhigh=hi if self.high is None else max(self.high,hi)
        if newhigh-newlow>100000:raise ValueError('clock uncertainty exceeds 100 ms')
        self.low,self.high,self.last_device=newlow,newhigh,device
    def map(self,device):
        if self.low is None:raise ValueError('clock not synchronized')
        value=device+self.low
        if value<0:raise ValueError('acquisition predates host clock')
        return value

class RadioWitness:
    """Recognize the inspected stimulus template, not an authenticated sender.

    A forged frame cannot identify its physical transmitter. This correlation
    is meaningful only alongside isolated, explicitly timed lab control logs.
    """
    def __init__(self,bssid):
        mac=bytes.fromhex(bssid.replace(':',''));self.template=bytes.fromhex('c0003a01ffffffffffff')+mac+mac+bytes.fromhex('f0ff0200');self.times=[]
    @property
    def count(self):return len(self.times)
    def observe(self,acquired_us,frame,rx_state,truncated):
        # Live SDK rewrites Duration (bytes 2..3). Match FC, addresses, sequence
        # and reason exactly; Duration is not a stimulus identity field.
        if not rx_state and not truncated and len(frame)==len(self.template) and frame[:2]==self.template[:2] and frame[4:]==self.template[4:]:self.times.append(acquired_us)
    def stop_proven(self,ack_host_us,end_host_us,uncertainty_us,groups,post_stop_listening=False):
        return bool(post_stop_listening and ack_host_us is not None and 0<self.count<=3*groups and end_host_us-ack_host_us>=3000000 and not any(t>ack_host_us+uncertainty_us for t in self.times))


class ListeningWitness:
    """Conservative bounded intervals of scoped receiver coverage (1 s heartbeat).

    No inference across a missing record, clock/boot reset, loss counter change,
    wrong channel, stopped status, or a heartbeat gap above 1.5 s.
    """
    def __init__(self,channel):
        self.channel=channel;self.previous=None;self.status=None;self.intervals=[]
    def observe(self,r,mapped_us):
        p=self.previous
        broken=p is not None and (r['boot']!=p['boot'] or (r['sequence']-p['sequence'])&0xffffffff != 1
            or r['queue_drops']!=p['queue_drops'] or r['bad_input']!=p['bad_input'])
        self.previous=r
        if broken:self.status=None
        if r['kind'] not in (2,4):return
        good=bool(r['flags']&1 and r['channel']==self.channel)
        old=self.status
        if good and old is not None:
            start=old
            if 0<mapped_us-start<=1500000:
                if self.intervals and self.intervals[-1][1]==start:self.intervals[-1][1]=mapped_us
                else:self.intervals.append([start,mapped_us])
                self.intervals=self.intervals[-512:]
        self.status=mapped_us if good else None
    def covers_after(self,ack_us,uncertainty_us):
        if ack_us is None or uncertainty_us is None or not 0<=uncertainty_us<=100000:return False
        return any(a<=ack_us-uncertainty_us and b>=ack_us+3000000+uncertainty_us for a,b in self.intervals)

#!/usr/bin/env python3
"""Explicit ordinary-client test; never launches a raw-frame emitter.

Timestamps use CLOCK_MONOTONIC, the same domain as lab/live/run.py micros() and
its ClockMap-mapped receiver acquisition times, so client actions and witnessed
frames can be ordered. Reconnect cycles are scheduled from the observer's own
flushed progress reports, after its 10 s association baseline.
"""
import argparse,hashlib,json,queue,re,signal,subprocess,sys,threading,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
import guardian_local  # owner-local settings: environment, else ~/.config/m5-guardian/local.conf (lab/local.conf.example)
SERIAL=(guardian_local.get('GUARDIAN_LAB_CARDPUTER_MAC') or '').upper()   # the client board's USB serial number
CLIENT_VERSION='guardian-client/1.1'
RUN_SECONDS=75
CYCLE_AT=(15,40)       # observer-reported elapsed seconds; its baseline is taken at 10 s
PROGRESS_STALE_S=10    # reports arrive every 5 s
STARTUP_S=30           # identity + sync + selection before the first report

def host_us():return time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000

PROGRESS=re.compile(r'reconnect: (\d+)s \|')
def progress_elapsed(line):
    m=PROGRESS.match(line.strip()) if line else None
    return int(m[1]) if m else None

def parse_state(s):
    fields=dict(item.split('=',1) for item in s.split()[2:])
    boot=fields.pop('boot',None)
    if boot is not None and not re.fullmatch('[0-9a-f]{16}',boot):raise ValueError('invalid client boot nonce')
    state={k:int(v) for k,v in fields.items()}
    if boot is not None:state['boot']=boot
    return state

def cycle_witnesses(records,ap,sta,cycles,uncertainty_us):
    """Per cycle (start_us,end_us): clean, unprotected, unfragmented assoc
    (>=28 bytes) / reassoc (>=34 bytes) requests sta->ap and successful
    responses ap->sta whose possible acquisition interval lies entirely inside
    the cycle. mapped_acquired_ms is the floor of ClockMap's lower-bound mapping;
    relative to ClockMap's OBSERVED synchronization envelope (not a hard
    oscillator/jitter guarantee) the acquisition falls in
    [ms*1000, ms*1000+999+uncertainty_us]."""
    if not isinstance(uncertainty_us,int) or uncertainty_us<0:raise ValueError('clock uncertainty required')
    out=[{'start_us':a,'end_us':b,'requests':[],'success_responses':[]} for a,b in cycles]
    for r in records:
        if r.get('kind')!=1 or 'frame_hex' not in r or r.get('rx_state') or r.get('truncated'):continue
        b=bytes.fromhex(r['frame_hex'])
        # Management frame without ToDS/FromDS, More Fragments or Protected; fragment 0.
        if len(b)<24 or b[1]&0x47 or b[22]&0x0f:continue
        lo=r['mapped_acquired_ms']*1000;hi=lo+999+uncertainty_us
        item={'subtype':b[0]>>4,'mapped_acquired_ms':r['mapped_acquired_ms'],'host_received_us':r.get('host_received_us'),'frame_hex':b.hex()}
        for c in out:
            if not (c['start_us']<=lo and hi<=c['end_us']):continue
            if ((b[0]==0x00 and len(b)>=28) or (b[0]==0x20 and len(b)>=34)) and b[4:10]==ap and b[10:16]==sta and b[16:22]==ap:c['requests'].append(item)
            elif b[0] in (0x10,0x30) and b[4:10]==sta and b[10:16]==ap and b[16:22]==ap and len(b)>=30 and b[26:28]==b'\x00\x00':c['success_responses'].append(item)
    return out

def load_password(cfg):
    """Owner-approved private local file; never copied into evidence or logs."""
    ssid=bytes.fromhex(cfg['ssid_hex']).decode('utf-8')
    credentials=Path.home()/'.config/m5-guardian/lab-credentials.json'
    if credentials.stat().st_mode&0o077 or credentials.parent.stat().st_mode&0o077:raise RuntimeError('credential config must be private (dir 0700, file 0600)')
    return json.loads(credentials.read_text())[ssid]['password']

def final_pass(ok,cleanup):
    return bool(ok and cleanup.get('client_stopped') is True and cleanup.get('guardian_cleanup_ok') is True
                and cleanup.get('console_reader_joined') is True and not cleanup.get('guardian_forced_kill'))

class ProgressTracker:
    """Observer progress freshness, judged by each report's receipt time (CLOCK_MONOTONIC us)."""
    def __init__(self,begin_us,startup_s=STARTUP_S,stale_s=PROGRESS_STALE_S):
        self.begin_us=begin_us;self.startup_us=startup_s*1_000_000;self.stale_us=stale_s*1_000_000;self.last_us=None;self.elapsed=-1
    def feed(self,received_us,elapsed):
        if elapsed<=self.elapsed:raise RuntimeError('observer progress did not increase')
        self.last_us=received_us;self.elapsed=elapsed
    def check(self,now_us):
        if self.last_us is None:
            if now_us-self.begin_us>self.startup_us:raise RuntimeError('observer produced no progress report')
        elif now_us-self.last_us>self.stale_us:raise RuntimeError('observer progress stale')

class ClientTimeout(RuntimeError):
    """No matching client response before the deadline; the only retryable join outcome."""

class Client:
    def __init__(self,elf,log,port=None):
        if port is None:
            import serial
            from serial.tools import list_ports
            if not SERIAL:raise RuntimeError('GUARDIAN_LAB_CARDPUTER_MAC not set (lab/local.conf.example)')
            ports=[p for p in list_ports.comports() if p.serial_number==SERIAL]
            if len(ports)!=1:raise RuntimeError('Connect designated Cardputer '+SERIAL)
            port=serial.Serial(port=None,baudrate=115200,timeout=.1,write_timeout=1,exclusive=True)
            # Measured 2026-11-15 (open-reset-probe-01): DTR=0/RTS=0 open reset the board 1 of 2 times; DTR=1/RTS=0 0 of 4.
            port.dtr=True;port.rts=False;port.port=ports[0].device;port.open()
        self.s=port
        self.buf=bytearray();self.log=log;self.state={};self.info='';self.stops=0;self.last_us=-1;self.boot=None
        self.errors=None  # qualification may collect expected ERROR lines instead of failing
        try:
            self.s.write(b'info\n');self.wait(lambda:CLIENT_VERSION in self.info and f'elf={elf}' in self.info and f'mac={SERIAL.lower()}' in self.info and self.boot,5)
        except BaseException:self.s.close();raise
    def read(self):
        self.buf.extend(self.s.read(4096))
        if len(self.buf)>16384:raise RuntimeError('oversized client response')
        while b'\n' in self.buf:
            b,_,tail=self.buf.partition(b'\n');self.buf=bytearray(tail);s=b.decode('ascii',errors='replace').strip()
            if not s.startswith('GCLIENT '):continue
            self.log.write(json.dumps({'host_us':host_us(),'response':s})+'\n');self.log.flush()
            if s.startswith('GCLIENT INFO '):self.info=s
            elif s.startswith('GCLIENT STATE '):
                state=parse_state(s)
                if self.boot is None:self.boot=state.get('boot')
                if state.get('boot')!=self.boot or state['us']<self.last_us:raise RuntimeError('Client rebooted during test')
                self.last_us=state['us'];self.state=state
            elif s.startswith('GCLIENT STOPPED'):self.stops+=1
            elif s.startswith('GCLIENT ERROR'):
                if self.errors is None:raise RuntimeError(s)
                self.errors.append(s)
    def wait(self,predicate,seconds):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            self.read()
            if predicate():return
        raise ClientTimeout('Client response deadline exceeded')
    def stop(self):
        old=self.stops;sent=host_us();self.s.write(b'stop\n');self.wait(lambda:self.stops>old,5)
        self.state={}  # require a STATE line emitted after STOPPED
        self.wait(lambda:self.state.get('active')==0 and self.state.get('connected')==0,3)
        return sent
    def join(self,cfg,password,seconds=90,attempts=3,attempt_timeout_s=8,attempt_gap_s=1):
        """Ordinary bounded join: one SDK connection per attempt (firmware never
        retries). A failed attempt (disconnect without connection, or no
        connection+DHCP within attempt_timeout_s) is stopped and retried after
        attempt_gap_s, at most `attempts` times. Measured need: the phone hotspot
        sometimes ignores a fresh auth (reconnect-04 cycle 2)."""
        # Credentials go only to RAM over the local USB cable. Never log command text.
        p=password.encode('ascii');ssid=bytes.fromhex(cfg['ssid_hex'])
        if not 8<=len(p)<=63 or not 1<=len(ssid)<=32:raise ValueError('invalid lab credentials')
        tried=[]
        for n in range(attempts):
            if n:
                self.stop();end=time.monotonic()+attempt_gap_s
                while time.monotonic()<end:self.read()
            old=self.state.get('connects',0);old_disc=self.state.get('disconnects',0);sent=host_us()
            self.s.write(f"join {cfg['bssid'].replace(':','')} {cfg['channel']} {cfg['ssid_hex']} {p.hex()} {int(seconds)}\n".encode())
            ok=lambda:self.state.get('connects',0)>old and self.state.get('connected')==1 and self.state.get('ip')==1
            failed=lambda:self.state.get('disconnects',0)>old_disc and self.state.get('connected')==0 and self.state.get('connects',0)==old
            try:self.wait(lambda:ok() or failed(),attempt_timeout_s)
            except ClientTimeout:pass  # reboot/protocol/identity errors propagate into cleanup
            result='connected' if ok() else 'failed'
            tried.append({'join_sent_us':sent,'result':result,'state':dict(self.state)})
            if result=='connected':
                return {'join_sent_us':tried[0]['join_sent_us'],'confirmed_us':host_us(),'state':dict(self.state),'attempts':tried}
        raise RuntimeError(f'join failed after {attempts} attempts')

def pump(proc,console,events):
    for line in proc.stdout:
        console.write(line);console.flush()
        e=progress_elapsed(line)
        if e is not None:events.put((host_us(),e))
    events.put(None)

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--config',required=True);a.add_argument('--client-elf',required=True);a.add_argument('--out',required=True);args=a.parse_args()
    out=Path(args.out).resolve();store=guardian_local.store()   # fail-closed: mounted share + sentinel
    if not out.is_relative_to(store):raise RuntimeError('evidence must go inside the artifact store (GUARDIAN_STORE)')
    cfg=json.loads(Path(args.config).read_text());password=load_password(cfg)
    elf=hashlib.sha256(Path(args.client_elf).read_bytes()).hexdigest()
    observer=[sys.executable,'-u',str(Path(__file__).resolve().parents[1]/'live/run_board.py'),'--config',str(args.config),'--out',str(out/'guardian'),'--scenario','reconnect','--seconds',str(RUN_SECONDS)]
    return run(cfg,password,elf,out,observer,Client)

def run(cfg,password,elf,out,observer,client_factory):
    out.mkdir(parents=True,exist_ok=False);(out/'config.json').write_text(json.dumps(cfg,indent=2))
    def interrupted(signum,frame):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    proc=None;client=None;pumper=None;ok=False;cleanup={};actions=[];cycles=[];checks={}
    with (out/'client.jsonl').open('w') as log,(out/'guardian-console.log').open('w') as console:
        try:
            client=client_factory(elf,log);client.stop()
            actions.append({'action':'initial_join',**client.join(cfg,password)})
            print('Cardputer joined lab hotspot; DHCP confirmed.',flush=True)
            proc=subprocess.Popen(observer,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
            events=queue.Queue();pumper=threading.Thread(target=pump,args=(proc,console,events),daemon=True);pumper.start()
            tracker=ProgressTracker(host_us());eof=False
            def poll():
                nonlocal eof
                client.read()
                while True:
                    try:e=events.get_nowait()
                    except queue.Empty:break
                    if e is None:eof=True
                    else:tracker.feed(*e)
                if not eof:tracker.check(host_us())
            for at in CYCLE_AT:
                while tracker.elapsed<at:
                    poll()
                    if eof:raise RuntimeError(f'Guardian test ended before reconnect at {at}s')
                if eof:raise RuntimeError(f'Guardian test ended before reconnect at {at}s')
                stop_sent=client.stop();actions.append({'action':'disconnect','observer_elapsed_s':tracker.elapsed,'stop_sent_us':stop_sent,'stopped_state':dict(client.state)})
                end=time.monotonic()+2
                while time.monotonic()<end:poll()
                joined=client.join(cfg,password);actions.append({'action':'rejoin','observer_elapsed_s':tracker.elapsed,**joined})
                cycles.append([joined['join_sent_us'],None])
                if len(cycles)>1:cycles[-2][1]=stop_sent
            deadline=time.monotonic()+RUN_SECONDS+30
            while not eof:
                if time.monotonic()>deadline:raise RuntimeError('Guardian test exceeded deadline')
                poll()
            proc.wait(timeout=15);final_state=dict(client.state)
            cycles[-1][1]=host_us()
            result=json.loads((out/'guardian/result.json').read_text())
            records=[json.loads(l) for l in (out/'guardian/receiver.jsonl').read_text().splitlines() if l.strip()]
            uncertainty=max((r['uncertainty_us'] for r in records if r.get('event')=='clock_sync'),default=None)
            # Cycle 1 ends at the second stop request; cycle 2 at observer exit.
            w=cycle_witnesses(records,bytes.fromhex(cfg['bssid'].replace(':','')),bytes.fromhex(SERIAL.replace(':','')),[tuple(c) for c in cycles],uncertainty)
            (out/'client-witness.json').write_text(json.dumps({'clock_uncertainty_us':uncertainty,'cycles':w},indent=2))
            rejoins=[x for x in actions if x['action']=='rejoin']
            checks={'guardian_exit':proc.returncode,'run_complete_pass':result.get('run_complete_pass'),
                    'association_frames_after_baseline':result.get('checks',{}).get('association_frames_after_baseline'),
                    'cycles':len(rejoins),'cycle_requests':[len(c['requests']) for c in w],'cycle_success_responses':[len(c['success_responses']) for c in w],
                    'connects_increased':all(rejoins[i]['state']['connects']>(actions[2*i]['state']['connects'] if i==0 else rejoins[i-1]['state']['connects']) for i in range(len(rejoins))),
                    'final_connected_dhcp':final_state.get('connected')==1 and final_state.get('ip')==1,'client_boot':client.boot}
            ok=(proc.returncode==0 and result.get('run_complete_pass') is True and len(rejoins)==2 and all(n>0 for n in checks['cycle_requests'])
                and checks['connects_increased'] and checks['final_connected_dhcp'])
        finally:
            if client:
                try:client.stop();cleanup['client_stopped']=True;cleanup['client_final_state']=dict(client.state)
                except BaseException as e:cleanup['client_stopped']=False;cleanup['error']=repr(e)
                finally:client.s.close()
            if proc and proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:proc.wait(timeout=15)
                except subprocess.TimeoutExpired:proc.kill();proc.wait();cleanup['guardian_forced_kill']=True
            if pumper:pumper.join(timeout=5);cleanup['console_reader_joined']=not pumper.is_alive()
            if proc and proc.stdout and not proc.stdout.closed and not (pumper and pumper.is_alive()):proc.stdout.close()
            cleanup['guardian_exit']=proc.returncode if proc else None
            guardian_cleanup=out/'guardian/cleanup.json'
            cleanup['guardian_cleanup_ok']=json.loads(guardian_cleanup.read_text()).get('ok') if guardian_cleanup.exists() else None
            passed=final_pass(ok,cleanup)
            (out/'controller-result.json').write_text(json.dumps({'pass':passed,'checks':checks,'actions':actions,'cycles':cycles,'cleanup':cleanup},indent=2))
    print(json.dumps({'pass':passed,'evidence':str(out),'checks':checks,'cleanup':cleanup},indent=2))
    return 0 if passed else 2
if __name__=='__main__':raise SystemExit(main())

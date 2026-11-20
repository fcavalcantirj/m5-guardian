#!/usr/bin/env python3
"""Bounded live Guardian host bridge. No emission unless --scenario requests it."""
import argparse,json,os,queue,re,signal,subprocess,sys,threading,time,uuid
from contextlib import contextmanager
from pathlib import Path
sys.path.insert(0,os.environ.get('GUARDIAN_RX_MODULE',str(Path(__file__).resolve().parents[1]/'receiver')))
from receiver import open_port,LineBuffer,decode
from control import ClockMap,validate_scope,RadioWitness,ListeningWitness
from transport import send_command
from evidence import AsyncLog
from assessment import assess
from cleanup import cleanup
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
import guardian_local  # owner-local settings: environment, else ~/.config/m5-guardian/local.conf (lab/local.conf.example)
class RunInterrupted(BaseException):
    def __init__(self,signum):
        self.signum=signum
        super().__init__('interrupted by signal '+str(signum))

_cancellation=None

def cancellation_checkpoint():
    if _cancellation and _cancellation[0] is not None:raise RunInterrupted(_cancellation[0])

@contextmanager
def interruptible():
    """Record the first signal; cancellation raises only at safe checkpoints.

    The same non-raising handler stays installed through cleanup, including
    context entry. Receipt errors do not replace the first signal exit status.
    """
    global _cancellation
    parent=_cancellation;pending=[None]
    previous={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
    def remember(signum,_frame):
        if pending[0] is None:pending[0]=signum
    _cancellation=pending
    try:
        for sig in previous:signal.signal(sig,remember)
        yield
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)
        _cancellation=parent
        if pending[0] is not None:raise RunInterrupted(pending[0])

@contextmanager
def finishing_cleanup():
    # No handler installation or cancellation checkpoint is permitted here.
    # interruptible()'s lifecycle-wide handler already defers every signal.
    yield

SERIAL=(guardian_local.get('GUARDIAN_LAB_CARDPUTER_MAC') or '').upper()   # the receiver board's USB serial number
def micros():return time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000

def reader(proc,events,log):
    try:
        for line in proc.stdout:
            log.write(line)
            try:events.put_nowait(json.loads(line))
            except (ValueError,queue.Full):pass
    finally:events.put({'event':'process_eof','returncode':proc.wait()})

class Session:
    receiver_serial=SERIAL
    receiver_banner=b'GRX1 INFO guardian-rx/1.2'
    def __init__(self,args):
        self.args=args;self.scope=validate_scope(json.loads(Path(args.config).read_text()));self.run_id=uuid.uuid4().hex[:10]
        self.root=Path(args.out).resolve();store=guardian_local.store()   # fail-closed: mounted share + sentinel
        if not self.root.is_relative_to(store):raise ValueError('output must be inside the artifact store (GUARDIAN_STORE)')
        self.root.mkdir(parents=True,exist_ok=False)
        self.mapping=ClockMap();self.stream=LineBuffer();self.boot=None;self.nonce=0;self.sync_pending={};self.sync_count=0;self.frames=0;self.bad=0;self.gaps=0;self.previous=None;self.heartbeat=None;self.state={};self.states=[];self.emitter=None;self.emitter_events=queue.Queue(1000);self.emitter_result=None;self.stop_sent=False
        self.engine_events=queue.Queue(1000);self.engine=None;self.witness=RadioWitness(self.scope["bssid"]);self.stop_ack_us=None;self.receiver_drops=0;self.association_baseline=0;self.ap_advert_times=[];self.listening_through_us=0;self.ap_actions=set();self.drop_budget=0;self.adapter_drops=0;self.coverage_adapter_drops=0;self.threads=[]
        self.listening=ListeningWitness(self.scope["channel"])
        self.save("scope.json",self.scope)
    def report(self,text):
        print(text,flush=True);self.console.write(text+'\n')
    def save(self,name,obj): (self.root/name).write_text(json.dumps(obj,indent=2)+'\n')
    def sync(self):
        self.nonce+=1;self.sync_pending[self.nonce]=micros();self.serial.write(f'sync {self.nonce}\n'.encode())
    def text(self,line):
        m=re.fullmatch(rb'GRX1 SYNC nonce=(\d+) boot=([0-9a-f]{16}) us=(\d+)',line)
        if m:
            nonce=int(m[1]);sent=self.sync_pending.pop(nonce,None)
            if sent is None:return
            boot=m[2].decode()
            if self.boot is not None and boot!=self.boot:raise RuntimeError('receiver rebooted')
            self.boot=boot;received=micros();device=int(m[3]);self.mapping.sample(sent,received,device);self.sync_count+=1
            self.raw.write(json.dumps({'event':'clock_sync','sent_us':sent,'received_us':received,'device_us':device,'uncertainty_us':self.mapping.uncertainty_us,'boot':boot})+'\n');return
        if line.startswith(b'GRX1 ERROR'):raise RuntimeError(line.decode())
    def send_engine(self,line):
        if self.engine.poll() is not None:raise RuntimeError('Guardian engine exited')
        send_command(self.engine.stdin,line+'\n')
    def process(self,line):
        if line.startswith((b'GRX1 SYNC ',b'GRX1 INFO ',b'GRX1 ERROR ')):self.text(line);return
        if not line.startswith(b'GRX1 '):return
        try:r=decode(line)
        except ValueError:self.bad+=1;raise RuntimeError('receiver transport corruption')
        if self.boot is None:return
        if r['boot']!=self.boot:raise RuntimeError('receiver boot changed')
        if self.previous is not None:
            gap=(r['sequence']-self.previous['sequence']-1)&0xffffffff
            if gap:self.gaps+=gap;raise RuntimeError('receiver sequence gap')
        self.previous=r;self.receiver_drops=max(self.receiver_drops,r['queue_drops']+r['bad_input'])
        r['host_received_us']=micros();r['mapped_acquired_ms']=self.mapping.map(r['acquired_us'])//1000;r['origin']='live';self.raw.write(json.dumps(r)+'\n')
        self.listening.observe(r,self.mapping.map(r['acquired_us']))
        if self.engine is None and not getattr(self,'board_ready',False):return
        if r['kind']==1:
            self.frames+=1
            b=bytes.fromhex(r['frame_hex'])
            if self.scope.get('ap_bssid') and len(b)>=24 and b[0] in (0x80,0x50) and b[16:22].hex()==self.scope['ap_bssid'].replace(':','') and not r['rx_state'] and not r['truncated']:self.ap_advert_times.append(r['mapped_acquired_ms']*1000)
            self.witness.observe(r["mapped_acquired_ms"]*1000,bytes.fromhex(r["frame_hex"]),r["rx_state"],r["truncated"])
            if self.drop_budget:
                self.drop_budget-=1;self.adapter_drops+=1;self.raw.write(json.dumps({'event':'deliberate_host_adapter_drop','sequence':r['sequence'],'acquired_ms':r['mapped_acquired_ms']})+'\n');return
            self.send_engine(f"FRAME {r['mapped_acquired_ms']} {r['channel']} {r['rssi']} {r['rx_state']} {int(r['truncated'])} {r['reported_length']} {r['frame_hex']}")
        elif r['kind'] in (2,4):
            before=self.heartbeat;self.heartbeat=r
            if r['flags']&1:self.listening_through_us=r['mapped_acquired_ms']*1000
            if before is None:return
            window=max(1,(r['acquired_us']-before['acquired_us'])//1000)
            if window>300000:raise RuntimeError('invalid coverage window')
            continuous=bool(r['flags']&1 and before['flags']&1 and r['channel']==before['channel'])
            delta=r['queue_drops']+r['bad_input']-before['queue_drops']-before['bad_input']
            if delta<0:raise RuntimeError('receiver counter reset')
            delta+=self.adapter_drops-self.coverage_adapter_drops;self.coverage_adapter_drops=self.adapter_drops
            self.send_engine(f"COVER {r['mapped_acquired_ms']} {r['channel']} {window} {window if continuous else 0} {delta} {int(continuous)}")
            if delta:self.send_engine("SNAPSHOT")
    def drain(self):
        cancellation_checkpoint()
        for line in self.stream.feed(self.serial.read(4096)):self.process(line)
        while not self.engine_events.empty():
            cancellation_checkpoint()
            e=self.engine_events.get_nowait()
            if e['event']=='state':self.state=e;self.states.append(e)
            elif e['event']=='process_eof':raise RuntimeError('Guardian process exited during live run')
        while not self.emitter_events.empty():
            cancellation_checkpoint()
            e=self.emitter_events.get_nowait()
            if e['event']=='ready':
                if e.get('role')=='test_ap' and self.args.scenario in ('settings','channel'):
                    if e.get('ap_bssid')!=self.scope['bssid'] or not self.heartbeat or not self.heartbeat['flags']&1 or self.heartbeat['channel']!=self.scope['channel']:raise RuntimeError('AP refused: no live scoped receiver')
                elif not self.state.get('has_security') or self.state.get('age_ms',999999)>3000:raise RuntimeError('emitter refused: no fresh scoped AP evidence')
                elif self.observed_scope_channel()!=self.scope['channel']:raise RuntimeError('emitter refused: scoped AP changed channel; requalify before another run')
                send_command(self.emitter.stdin,'GO\n')
            if e['event']=='group_done' and self.args.scenario=='stop' and not self.stop_sent:
                send_command(self.emitter.stdin,'STOP\n');self.stop_sent=True
            if e['event']=='stopped':self.emitter_result=e;self.stop_ack_us=micros()
            if e['event'] in ('error','failed_closed'):raise RuntimeError('emitter failed: '+str(e))
            if e['event']=='process_eof' and not self.emitter_result:raise RuntimeError('emitter exited without stop acknowledgement')
    def observed_scope_channel(self):
        # New engines expose advertised + receive channels; the board follows
        # valid advertisements. Older fixed-channel host engines retain their
        # live heartbeat interface rather than silently losing compatibility.
        channel=self.state.get('advertised_channel') or self.state.get('channel')
        if channel is not None:return channel
        heartbeat=getattr(self,'heartbeat',None)
        return heartbeat['channel'] if heartbeat and heartbeat['flags']&1 else None

    def prepare_emitter_logs(self):
        # Open evidence files BEFORE reception: an SMB open() in the store measured
        # 560-640 ms each (2026-11-15) and stalled board telemetry in the loop.
        if self.args.scenario not in ('burst','stop','stop-inflight','recovery','settings','channel','related-approved','related-unapproved'):return
        self.emitter_log=AsyncLog((self.root/'emitter.jsonl').open('w'));self.logs.append(self.emitter_log)
        self.emitter_err=(self.root/'emitter.stderr').open('w');self.logs.append(self.emitter_err)
    def start_emitter(self):
        if self.args.scenario not in ('burst','stop','stop-inflight','recovery','settings','channel','related-approved','related-unapproved'):return
        pi=guardian_local.require('GUARDIAN_LAB_PI_SSH',purpose='ssh target of the lab Pi');python=guardian_local.require('GUARDIAN_LAB_PI_PYTHON',purpose='Python on the lab Pi')
        tools=guardian_local.require('GUARDIAN_LAB_PI_TOOLS',purpose='lab tools folder on the Pi');chip=guardian_local.require('GUARDIAN_LAB_EMITTER_MAC',purpose='the emitter board')
        cmd=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8',pi,'env',f'GUARDIAN_LAB_EMITTER_MAC={chip}',python,f'{tools}/emitter.py','--emit']
        if self.args.scenario=='stop-inflight':cmd.append('--interrupt-batch')
        if self.args.scenario in ('settings','channel','related-approved','related-unapproved'):cmd[-2:]=[f'{tools}/ap_control.py']
        if getattr(self,'emitter_log',None) is None:raise RuntimeError('emitter logs must be prepared before reception')
        self.emitter=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.emitter_err,text=True,bufsize=1)
        thread=threading.Thread(target=reader,args=(self.emitter,self.emitter_events,self.emitter_log),daemon=True);self.threads.append(thread);thread.start()
        send_command(self.emitter.stdin,json.dumps(self.scope)+'\n')
    def confirm_receiver_stop(self):
        self.serial.reset_input_buffer();stream=LineBuffer()
        self.serial.write(b'stop\n');end=time.monotonic()+2
        receipt={'receiver_stop_sent':True,'receiver_stop_confirmed':False}
        while time.monotonic()<end:
            for line in stream.feed(self.serial.read(4096)):
                if not line.startswith(b'GRX1 '):continue
                try:r=decode(line)
                except ValueError:continue
                boot=getattr(self,'boot',None);previous=getattr(self,'previous',None)
                if boot is None or r['boot']!=boot:continue
                if previous is not None and (not 0<(r['sequence']-previous['sequence'])&0xffffffff<0x80000000
                    or r['acquired_us']<previous['acquired_us']):continue
                if r['kind']==4 and not r['flags']&1:
                    receipt.update(receiver_stop_confirmed=True,receiver_stop_status=r)
                    return receipt
        return receipt

    def identify_receiver(self,line):
        return line.startswith(self.receiver_banner)

    def create_engine(self):
        self.engine=subprocess.Popen([self.args.engine,'--live',self.scope['bssid'].replace(':',''),self.scope['ssid_hex'],uuid.uuid4().hex],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.engine_err,text=True,bufsize=1)
        thread=threading.Thread(target=reader,args=(self.engine,self.engine_events,self.engine_log),daemon=True);self.threads.append(thread);thread.start()
    def release_fixed_channel(self,seconds):
        raise RuntimeError('channel scenario requires a qualified discovery-capable receiver adapter')

    def start_receiver(self):
        self.serial.write(f"start {self.scope['channel']} {self.args.seconds}\n".encode())

    def inject_drop(self):
        self.drop_budget=24

    def run(self):
        from serial.tools import list_ports
        if not self.receiver_serial:raise ValueError('designated receiver not configured: GUARDIAN_LAB_CARDPUTER_MAC (receiver) or GUARDIAN_LAB_STICK_MAC (board run); see lab/local.conf.example')
        port=next((p for p in list_ports.comports() if p.serial_number==self.receiver_serial),None)
        if port is None:raise RuntimeError('designated receiver absent: '+self.receiver_serial)
        self.serial=None;self.logs=[];logs=self.logs
        try:
            self.console=AsyncLog((self.root/'console.log').open('w'));logs.append(self.console)
            self.raw=AsyncLog((self.root/'receiver.jsonl').open('w'));logs.append(self.raw)
            self.engine_log=AsyncLog((self.root/'guardian.jsonl').open('w'));logs.append(self.engine_log)
            self.engine_err=(self.root/'guardian.stderr').open('w');logs.append(self.engine_err)
            self.prepare_emitter_logs()
            cancellation_checkpoint()
            self.serial=open_port(port.device);self.serial.timeout=.01
            self.serial.write(b'info\n');end=time.monotonic()+4;identified=False
            while time.monotonic()<end:
                cancellation_checkpoint()
                for line in self.stream.feed(self.serial.read(4096)):
                    if self.identify_receiver(line):
                        identified=True;self.save('receiver-identity.json',{'banner':line.decode('ascii'),'serial':self.receiver_serial})
            if not identified:raise RuntimeError('synchronized receiver firmware required')
            self.serial.reset_input_buffer();self.stream=LineBuffer()
            for _ in range(3):
                self.sync();until=time.monotonic()+1
                while self.sync_pending and time.monotonic()<until:self.drain()
                if self.sync_pending:raise RuntimeError('clock sync timeout')
                time.sleep(.1)
            self.create_engine()
            if self.args.scenario in ('related-approved','related-unapproved'):
                self.send_engine(('APPROVE_AP ' if self.args.scenario=='related-approved' else 'WATCH_AP ')+self.scope['ap_bssid'].replace(':',''))
            self.start_receiver();start=time.monotonic();next_sync=start+3;next_display=start;acted=False;baseline=False
            while time.monotonic()-start<self.args.seconds:
                self.drain();now=time.monotonic();elapsed=now-start
                if now>=next_sync and not self.sync_pending:self.sync();next_sync=now+3
                if self.sync_pending and micros()-min(self.sync_pending.values())>1000000:raise RuntimeError('synchronization lost')
                if elapsed>=(12 if self.args.scenario in ('settings','channel') else 8) and not baseline:
                    if not self.state.get('has_security') or self.state.get('age_ms',999999)>3000:raise RuntimeError('no fresh scoped hotspot evidence')
                    self.send_engine('BASELINE');baseline=True
                if elapsed>=(1 if self.args.scenario in ('settings','channel') else 10) and not acted:
                    self.association_baseline=self.state.get('association_frames',0)
                    if self.args.scenario=='stale':self.serial.write(b'stop\n')
                    elif self.args.scenario=='drop':self.inject_drop()
                    else:self.start_emitter()
                    acted=True
                if self.args.scenario in ('settings','channel') and self.emitter:
                    schedule=[(14,'DISCOVER'),(20,'CHANNEL 6'),(40,'CHANNEL 13'),(60,'STOP')] if self.args.scenario=='channel' else [(20,'SWITCH 3'),(40,'SWITCH 2'),(60,'STOP')]
                    for when,command in schedule:
                        if elapsed>=when and when not in self.ap_actions:
                            if command=='DISCOVER':self.release_fixed_channel(max(1,self.args.seconds-int(elapsed)))
                            else:send_command(self.emitter.stdin,command+'\n')
                            self.ap_actions.add(when)
                elif self.args.scenario in ('related-approved','related-unapproved') and elapsed>=30 and not self.stop_sent and self.emitter:
                    send_command(self.emitter.stdin,'STOP\n');self.stop_sent=True
                if now>=next_display:
                    self.report(f"{self.args.scenario}: {elapsed:.0f}s | frames {self.frames} | age {self.state.get('age_ms','?')} ms | burst {self.state.get('burst',False)} | sync envelope {self.mapping.uncertainty_us/1000:.1f} ms")
                    self.raw.flush();self.engine_log.flush();next_display=now+5
            self.send_engine('SNAPSHOT');self.drain()
            post_stop_listening=self.listening.covers_after(self.stop_ack_us,self.mapping.uncertainty_us)
            summary={'scenario':self.args.scenario,'frames':self.frames,'clock_samples':self.sync_count,'clock_envelope_us':self.mapping.uncertainty_us,'transport_errors':self.bad,'sequence_gaps':self.gaps,'emitter':self.emitter_result,'last_state':self.state,'burst_observed':any(s.get('burst') for s in self.states),'full_L02_acceptance':False,'stimulus_template_frames':self.witness.count,'on_air_stop_observed':self.witness.stop_proven(self.stop_ack_us,micros(),self.mapping.uncertainty_us,self.emitter_result.get('submitted_groups',self.emitter_result['completed_groups']) if self.emitter_result else 0,post_stop_listening)}
            ap_stop=bool(self.ap_advert_times and self.stop_ack_us is not None and post_stop_listening and max(self.ap_advert_times)<=self.stop_ack_us+self.mapping.uncertainty_us)
            summary['test_ap_advertisements']=len(self.ap_advert_times);summary['test_ap_stop_observed']=ap_stop
            checks=assess(self.args.scenario,self.states,self.witness,self.emitter_result,self.stop_ack_us,micros(),self.mapping.uncertainty_us,self.scope['groups'],self.association_baseline,ap_stop,post_stop_listening)
            summary['post_stop_scoped_listening']=post_stop_listening;summary['adapter_drops']=self.adapter_drops;summary['checks']=checks;summary['receiver_drops']=self.receiver_drops;summary['stop_ack_received_host_us']=self.stop_ack_us
            ok=checks['pass'] and self.frames>0 and self.sync_count>=3 and not self.bad and not self.gaps and (not self.receiver_drops or self.args.scenario=='stale')
            summary['scenario_assertions_pass']=bool(ok);self.save('result.json',summary);self.report(json.dumps(summary,indent=2));return 0 if ok else 2
        except BaseException as exc:
            self.save("failure.json",{"error":str(exc),"scenario":self.args.scenario,"frames":self.frames,"state":self.state,"full_L02_acceptance":False});raise
        finally:
            with finishing_cleanup():
                outcome=cleanup(self.serial,self.engine,self.emitter,logs,threads=self.threads,confirm_receiver_stop=self.confirm_receiver_stop);self.save('cleanup.json',outcome)
                result_file=self.root/'result.json'
                if result_file.exists():
                    result=json.loads(result_file.read_text());result['cleanup_ok']=outcome['ok'];result.update(window_and_stop_drops(result,outcome));result['run_complete_pass']=bool(result['scenario_assertions_pass'] and outcome['ok']);self.save('result.json',result)
                if not outcome['ok']:raise RuntimeError('cleanup incomplete: '+str(outcome['errors']))

def window_and_stop_drops(result,cleanup_outcome):
    """Observation-window loss (asserted) vs discard at the post-window confirmed stop (reported)."""
    status=cleanup_outcome.get('receiver_stop_status')
    total=status['queue_drops']+status['bad_input'] if status else None
    return {'observation_receiver_drops':result['receiver_drops'],'post_window_stop_discards':None if total is None else total-result['receiver_drops']}

def main(session_class=Session):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True);p.add_argument('--engine');p.add_argument('--out',required=True);p.add_argument('--seconds',type=int,default=60);p.add_argument('--scenario',choices=['quiet','burst','stop','stop-inflight','stale','drop','recovery','reconnect','settings','channel','related-approved','related-unapproved'],default='quiet');a=p.parse_args()
    if session_class is Session and not a.engine:raise ValueError('--engine required for host runs')
    if not 15<=a.seconds<=300:raise ValueError('15..300 seconds required')
    if a.scenario=='stale' and a.seconds<45:raise ValueError('stale scenario needs >=45s')
    if a.scenario=='recovery' and a.seconds<85:raise ValueError('recovery scenario needs >=85s')
    if a.scenario in ('settings','channel') and a.seconds<70:raise ValueError('AP-change scenario needs >=70s')
    if a.scenario=='channel' and session_class is Session:raise ValueError('channel scenario requires the qualified board discovery adapter')
    if a.scenario.startswith('related-') and a.seconds<40:raise ValueError('related AP scenario needs >=40s')
    with interruptible():
        return session_class(a).run()
if __name__=='__main__':
    try:raise SystemExit(main())
    except RunInterrupted as e:raise SystemExit(128+e.signum)
    except (ValueError,RuntimeError,OSError) as e:raise SystemExit(str(e))

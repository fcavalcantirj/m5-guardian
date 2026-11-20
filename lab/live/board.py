"""G13 board transport: same L02 controller, witnesses, evidence and assertions.

No host engine is launched. FRAME/COVER records go only to independent transport
witnesses; parsing/detection/policy output must come from the selected StickS3.
"""
import json,time,zlib,re
from pathlib import Path
from run import Session,micros,guardian_local
class BoardSession(Session):
    receiver_serial=(guardian_local.get('GUARDIAN_LAB_STICK_MAC') or '').upper()   # the StickS3 under test
    receiver_banner=b'GRX1 INFO guardian-sticks3/1.0 '
    def __init__(self,args):
        config=json.loads(Path(args.config).read_text())
        country=config.get('country')
        if not isinstance(country,str) or len(country)!=2 or not country.isascii() or not country.isupper() or not country.isalpha():
            raise ValueError('explicit two-letter regulatory country required for board run')
        self.expected_elf=config.get('firmware_elf_sha256','')
        if not isinstance(self.expected_elf,str) or not re.fullmatch('[0-9a-f]{64}',self.expected_elf) or self.expected_elf=='0'*64:
            raise ValueError('exact reviewed firmware_elf_sha256 required for board run')
        if type(args.seconds) is not int or not 1<=args.seconds<=300-self.BACKSTOP_S:raise ValueError('board run needs 1..295 seconds (firmware backstop cap 300)')
        self.country=country;self.board_ready=False;self.selection_ack=False
        super().__init__(args)
        self.save('board-adapter.json',{'target':'StickS3','serial':self.receiver_serial,'country':country,'library_execution':'on-board','physical_acceptance':False,'expected_elf_sha256':self.expected_elf})
    def identify_receiver(self,line):
        if not line.startswith(self.receiver_banner):return False
        values=dict(field.split(b'=',1) for field in line.split() if b'=' in field)
        if values.get(b'mac',b'').decode('ascii').lower()!=self.receiver_serial.lower() or values.get(b'elf',b'').decode('ascii')!=self.expected_elf:
            raise RuntimeError('board MAC or reviewed ELF identity mismatch')
        return True
    def create_engine(self):
        self.serial.write(('select '+self.scope['bssid'].replace(':','')+' '+(self.scope['ssid_hex'] or '-')+' '+self.country+'\n').encode())
        end=time.monotonic()+4
        while not self.selection_ack and time.monotonic()<end:self.drain()
        if not self.selection_ack:raise RuntimeError('board did not confirm selection')
        self.board_ready=True;self.last_board_state_us=micros()
    def drain(self):
        super().drain()
        if self.board_ready and micros()-self.last_board_state_us>2500000:
            raise RuntimeError('board core telemetry stopped while receiver remains active')
    def send_engine(self,line):
        if line.startswith(('FRAME ','COVER ')):return
        if line!='SNAPSHOT' and line!='BASELINE' and not line.startswith(('WATCH_AP ','APPROVE_AP ')):
            raise RuntimeError('unsupported board control command')
        self.serial.write((line+'\n').encode())
    # The board's own receiver deadline is only a backstop: it must expire after
    # the host window, or its stop can discard a queued record inside the final
    # drain (reconnect-02, 2026-11-15). The host ends reception via confirmed
    # cleanup stop. Board firmware accepts 1..300 s.
    BACKSTOP_S=5
    def start_receiver(self):
        if type(self.args.seconds) is not int or not 1<=self.args.seconds<=300-self.BACKSTOP_S:raise ValueError('board run needs 1..295 seconds (firmware backstop cap 300)')
        # The controlled AP does not exist yet in settings: hold its exact
        # scoped channel, proving listening before the controller starts it.
        verb='listen' if self.args.scenario in ('settings','channel') else 'start'
        self.serial.write(f"{verb} {self.scope['channel']} {self.args.seconds+self.BACKSTOP_S}\n".encode())

    def release_fixed_channel(self,seconds):
        if type(seconds) is not int or not 1<=seconds<=300-self.BACKSTOP_S:raise ValueError('bounded discovery duration required')
        self.serial.write(f"stop\nstart {self.scope['channel']} {seconds+self.BACKSTOP_S}\n".encode())

    def inject_drop(self):
        self.serial.write(b'DROP 24\n')
        self.drop_requested=True
        self.raw.write(json.dumps({'event':'requested_board_adapter_drop','count':24})+'\n')
    def process(self,line):
        if line==b'G13 ACK selected':self.selection_ack=True;return
        if line==b'G13 ACK drop_completed_24':self.adapter_drops+=24
        if line.startswith(b'G13 ACK '):
            self.engine_log.write(json.dumps({'event':'board_ack','text':line.decode('ascii')})+'\n');return
        if not line.startswith(b'G13 '):return super().process(line)
        if not self.board_ready:return
        try:
            _,boot,checksum,payload=line.split(b' ',3)
            if len(checksum)!=8 or int(checksum,16)!=zlib.crc32(payload):raise RuntimeError('board telemetry CRC mismatch')
            e=json.loads(payload)
            if boot.decode()!=self.boot:raise RuntimeError('board state boot changed')
            if e.get('event')!='state' or e.get('origin')!='live' or e.get('bssid')!=self.scope['bssid'].replace(':','') or e.get('ssid_hex')!=self.scope['ssid_hex']:
                raise RuntimeError('board state has wrong origin or selected identity')
            for name in ('now_ms','age_ms','burst_acquired_ms','burst_count'):
                if type(e.get(name)) is not int or not 0<=e[name]<2**63:raise RuntimeError('invalid board timestamp/count')
            mapped=self.mapping.map(e['now_ms']*1000)//1000;received=micros()//1000
            if received<mapped or received-mapped>250:raise RuntimeError('board telemetry timing unavailable or delayed')
            e['board_now_ms']=e['now_ms'];e['now_ms']=received;e['age_ms']+=received-mapped
            e['board_burst_acquired_ms']=e['burst_acquired_ms']
            if e['burst_count']:e['burst_acquired_ms']=self.mapping.map(e['burst_acquired_ms']*1000)//1000
            e['execution_target']='sticks3';e['boot']=self.boot
            e['wire_json']=payload.decode('ascii');e['wire_crc32']=checksum.decode('ascii')
        except (ValueError,KeyError,TypeError) as exc:raise RuntimeError('invalid board telemetry') from exc
        self.engine_log.write(json.dumps(e)+'\n');self.state=e;self.states.append(e);self.last_board_state_us=micros()

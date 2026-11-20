#!/usr/bin/env python3
"""Explicitly launched controller for the already-backed-up Pi WROOM.

No firmware writes. At most eight count=1 batches, one outstanding at a time.
A batch is at most three TX calls in the inspected firmware; on-air truth must
come from the separate receiver. STOP/EOF stops scheduling immediately. A lost
completion or stop acknowledgement triggers ROM bootloader reset, not a retry.
"""
import argparse,json,os,signal,subprocess,sys,threading,time
from pathlib import Path
from control import BatchState,validate_scope
PORT='/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0'
EXPECTED_HELP='commands: scan | deauth <bssid> <channel> <count> | stop | help'
def chip_mac():
 """The emitter board's own address, from GUARDIAN_LAB_EMITTER_MAC (run.py passes it over ssh)."""
 mac=os.environ.get('GUARDIAN_LAB_EMITTER_MAC','').strip().lower()
 if not mac:raise RuntimeError('GUARDIAN_LAB_EMITTER_MAC not set: the emitter identity cannot be checked')
 return mac
stop_event=threading.Event()
def emit(event,**kwargs):print(json.dumps(dict(event=event,monotonic_ns=time.monotonic_ns(),**kwargs)),flush=True)
def read_line(port):
 raw=port.readline(512)
 if len(raw)==512 and not raw.endswith(b'\n'):raise RuntimeError('oversized firmware line')
 line=raw.decode('ascii','replace').strip()
 if line:emit('serial',text=line)
 if 'Brownout' in line:raise RuntimeError('brownout observed')
 return line

def await_line(port,expected,seconds):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  line=read_line(port)
  if line.startswith('ERR'):raise RuntimeError(line)
  if line==expected:return
 raise RuntimeError('missing response: '+expected)

def bootloader_stop(port):
 from esptool.reset import classic_bootloader_reset
 start=time.monotonic();port.reset_input_buffer();classic_bootloader_reset(port)
 end=time.monotonic()+2;seen=False
 while time.monotonic()<end:
  line=read_line(port)
  if 'DOWNLOAD_BOOT' in line or 'waiting for download' in line:seen=True;break
 emit('bootloader_stop',confirmed=seen,elapsed_ms=round((time.monotonic()-start)*1000,2))
 if not seen:raise RuntimeError('bootloader stop unconfirmed; physical stop needed')

def open_port():
 import serial
 s=serial.Serial(port=None,baudrate=115200,timeout=.05,write_timeout=.3,exclusive=True);s.dtr=False;s.rts=False;s.port=PORT;s.open();return s

def identify(s):
 deadline=time.monotonic()+5;next_query=0.0
 while time.monotonic()<deadline:
  if time.monotonic()>=next_query:s.write(b'info\nhelp\n');next_query=time.monotonic()+.5
  line=read_line(s)
  if line.startswith(('GLAB1 INFO native-emitter/1.2 ','GLAB1 INFO native-emitter/1.3 ')):
   if f'mac={chip_mac()} ' not in line or 'country=BR channels=1..13 ' not in line:raise RuntimeError('native emitter identity/country mismatch')
   return 'native'
  if line==EXPECTED_HELP:return 'legacy'
 raise RuntimeError('expected emitter help banner absent')

def restore_application():
 cmd=[sys.executable,'-m','esptool','--chip','esp32','--port',PORT,'--after','hard-reset','chip-id']
 p=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
 mac=chip_mac()
 if p.returncode or mac not in p.stdout.lower():raise RuntimeError('expected chip identity not confirmed on restore')
 emit('application_reset',chip_mac=mac)

def watch_stdin():
 for line in sys.stdin:
  if line.strip()=='STOP':stop_event.set();return
 stop_event.set() # lost SSH/control pipe: stop instead of continuing autonomously

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--qualify-stop',action='store_true');p.add_argument('--emit',action='store_true');p.add_argument('--interrupt-batch',action='store_true');a=p.parse_args()
 if a.qualify_stop==a.emit:raise ValueError('choose exactly one explicit operation')
 if not Path(PORT).exists():raise RuntimeError('known WROOM serial path absent')
 signal.signal(signal.SIGTERM,lambda *_:stop_event.set());signal.signal(signal.SIGINT,lambda *_:stop_event.set())
 if a.qualify_stop:
  with open_port() as s:
   identify(s);s.write(b'stop\n');await_line(s,'OK stop',1);emit('idle_stop_acknowledged');bootloader_stop(s)
  restore_application()
  with open_port() as s:identify(s)
  emit('qualification_complete',rf_commands_sent=0,live_stop_still_requires_receiver=True);return
 scope=validate_scope(json.loads(sys.stdin.readline()))
 with open_port() as s:
  backend=identify(s)
  if backend!='native':raise RuntimeError('emission refused: qualified native identity required')
  s.write(b'stop\n');await_line(s,'OK stop',1)
  emit('ready',scope=scope,backend=backend)
  # Host must confirm its live receiver is already running before GO.
  if sys.stdin.readline().strip()!='GO':raise RuntimeError('receiver-ready GO missing')
  if backend=='native':
   s.write(f"arm {scope['bssid']} {scope['channel']}\n".encode());await_line(s,'OK armed',1)
  threading.Thread(target=watch_stdin,daemon=True).start()
  state=BatchState();deadline=time.monotonic()+scope['deadline_s'];failed=False
  try:
   if a.interrupt_batch:
    if backend!='native':raise RuntimeError('in-flight stop requires native emitter')
    s.write(f"deauth {scope['bssid']} {scope['channel']} 1\n".encode());await_line(s,'OK deauth start count=1',1)
    start=time.monotonic();s.write(b'stop\n');await_line(s,'OK stop',1)
    emit('stopped',completed_groups=0,submitted_groups=1,stop_requested=True,interrupted_inflight=True,ack_ms=round((time.monotonic()-start)*1000,2),tx_success_unverified=True);return
   for _ in range(scope['groups']):
    if stop_event.is_set():state.stop();break
    if time.monotonic()>=deadline:raise RuntimeError('overall deadline reached')
    state.begin(time.monotonic());s.write(f"deauth {scope['bssid']} {scope['channel']} 1\n".encode())
    while state.pending:
     if state.expired(time.monotonic()) or time.monotonic()>=deadline:raise RuntimeError('completion deadline reached')
     # A STOP requests no further batches. The one bounded in-flight batch is
     # allowed to finish; expiry instead resets the chip, never retransmits.
     if state.line(read_line(s)):emit('group_done',completed=state.completed)
    if stop_event.wait(.2):state.stop();break
   t=time.monotonic();s.write(b'stop\n');await_line(s,'OK stop',1)
   emit('stopped',completed_groups=state.completed,stop_requested=stop_event.is_set(),ack_ms=round((time.monotonic()-t)*1000,2),tx_success_unverified=True)
  except BaseException:
   try:bootloader_stop(s)
   except BaseException:
    emit('stop_unconfirmed',left_in_bootloader=False);raise
   emit('failed_closed',left_in_bootloader=True);raise
if __name__=='__main__':
 try:main()
 except Exception as e:emit('error',message=str(e));raise SystemExit(2)

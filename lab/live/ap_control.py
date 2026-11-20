#!/usr/bin/env python3
"""Explicit bounded real-AP fixture controller. No clients, services or passwords logged."""
import json,queue,re,signal,sys,threading,time
from emitter import open_port,identify,read_line,await_line,bootloader_stop,emit
from control import validate_scope

def ap_command(ssid_hex,mode,seconds):
 try:ssid=bytes.fromhex(ssid_hex)
 except (ValueError,TypeError) as e:raise ValueError('SSID hex required') from e
 if not 1<=len(ssid)<=32 or any(c<32 or c>126 for c in ssid):raise ValueError('visible lab SSID required')
 if type(mode) is not int or mode not in (2,3) or type(seconds) is not int or not 1<=seconds<=120:raise ValueError('bounded AP mode/duration required')
 return f'ap {mode} {seconds} {ssid.hex()}\n'.encode()

def ap_channel_command(channel):
 if type(channel) is not int or not 1<=channel<=13:raise ValueError('qualified AP channel 1..13 required')
 return f'apchannel {channel}\n'.encode()

def start_test_ap(s,ssid_hex,mode,seconds,channel):
 start=ap_command(ssid_hex,mode,seconds);retune=ap_channel_command(channel)
 s.write(start);await_line(s,f'OK ap_started security={mode} seconds={seconds} channel=13',2)
 if channel!=13:s.write(retune);await_line(s,f'OK ap_channel channel={channel}',2)

def main():
 scope=validate_scope(json.loads(sys.stdin.readline()));expected=scope.get('ap_bssid')
 if not isinstance(expected,str) or not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',expected):raise ValueError('explicit qualified AP MAC required')
 ap_command(scope['ssid_hex'],2,90);halt=threading.Event();commands=queue.Queue(8)
 signal.signal(signal.SIGINT,lambda *_:halt.set());signal.signal(signal.SIGTERM,lambda *_:halt.set())
 def stdin_reader():
  for line in sys.stdin:
   line=line.strip()
   if line=='STOP':halt.set();return
   try:commands.put_nowait(line)
   except queue.Full:halt.set();return
  halt.set()
 with open_port() as s:
  if identify(s)!='native':raise RuntimeError('native AP fixture required')
  end=time.monotonic()+1;found=False
  while time.monotonic()<end:
   line=read_line(s)
   if line.startswith('GLAB1 AP '):
    if f'mac={expected} ' not in line:raise RuntimeError('AP MAC mismatch')
    found=True;break
  if not found:raise RuntimeError('native AP identity absent')
  s.write(b'stop\n');await_line(s,'OK stop',1);emit('ready',role='test_ap',ap_bssid=expected)
  if sys.stdin.readline().strip()!='GO':raise RuntimeError('live-receiver GO required')
  threading.Thread(target=stdin_reader,daemon=True).start();deadline=time.monotonic()+90
  def switch(mode):
   remaining=max(1,min(90,int(deadline-time.monotonic())))
   start_test_ap(s,scope['ssid_hex'],mode,remaining,scope['channel']);emit('ap_mode',role='test_ap',mode=mode,channel=scope['channel'],ssid_hex=scope['ssid_hex'],ap_bssid=expected)
  try:
   switch(2)
   while not halt.is_set() and time.monotonic()<deadline:
    try:line=commands.get(timeout=.05)
    except queue.Empty:continue
    if line.startswith('CHANNEL '):
     channel=int(line[8:]);s.write(ap_channel_command(channel));await_line(s,f'OK ap_channel channel={channel}',2);emit('ap_channel',role='test_ap',channel=channel)
    elif line in ('SWITCH 2','SWITCH 3'):switch(int(line[-1]))
    else:raise RuntimeError('unknown AP control message')
  finally:
   try:
    start=time.monotonic();s.write(b'stop\n');await_line(s,'OK stop',1);emit('stopped',role='test_ap',completed_groups=0,stop_requested=halt.is_set(),ack_ms=round((time.monotonic()-start)*1000,2))
   except BaseException:
    try:bootloader_stop(s)
    except BaseException:emit('stop_unconfirmed',left_in_bootloader=False);raise
    emit('failed_closed',left_in_bootloader=True);raise
if __name__=='__main__':
 try:main()
 except Exception as e:emit('error',role='test_ap',message=str(e));raise SystemExit(2)

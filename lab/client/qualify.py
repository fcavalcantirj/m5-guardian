#!/usr/bin/env python3
"""Explicit Cardputer lab-client qualification. Device: GUARDIAN_LAB_CARDPUTER_MAC only.

Phase A (no RF): identity, idle state, stop, rejected commands, no reboot.
Phase B (ordinary STA connection to the scoped AP, bounded on-device):
  B1 join for 10 s with the port open; the device must stop itself
     ("STOPPED deadline") in the same boot.
  B2 join for 10 s, close the host port for 15 s, reopen; the device must
     report the same boot nonce, active=0 and one more deadline stop whose
     device-recorded time is ~10 s after its join.
Credentials come only from the private local file and are never logged.
"""
import argparse,hashlib,json,time
from pathlib import Path
import reconnect as rc

def same_boot(client,boot):
    if client.boot!=boot:raise RuntimeError('client boot changed')

def deadline_window(state,seconds):
    span=state['last_stop_us']-state['last_join_us']
    if not seconds*1_000_000<=span<=seconds*1_000_000+500_000:raise RuntimeError(f'deadline stop outside window: {span} us')
    return span

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--config',required=True);a.add_argument('--client-elf',required=True);a.add_argument('--out',required=True);a.add_argument('--no-rf',action='store_true');args=a.parse_args()
    store=rc.guardian_local.store();out=Path(args.out).resolve()   # fail-closed: mounted share + sentinel
    if not out.is_relative_to(store):raise RuntimeError('evidence must go inside the artifact store (GUARDIAN_STORE)')
    cfg=json.loads(Path(args.config).read_text())
    password=None if args.no_rf else rc.load_password(cfg)
    elf=hashlib.sha256(Path(args.client_elf).read_bytes()).hexdigest()
    out.mkdir(parents=True,exist_ok=False);result={'pass':False,'elf_sha256':elf,'steps':{}};client=None
    with (out/'client.jsonl').open('w') as log:
        try:
            client=rc.Client(elf,log);boot=client.boot;client.wait(lambda:'active' in client.state,3)
            result['steps']['identity']={'info':client.info,'boot':boot,'idle_state':dict(client.state)}
            if client.state['active']!=0 or client.state['connected']!=0:raise RuntimeError('client not idle after boot')
            client.stop();same_boot(client,boot);result['steps']['stop_idle']=dict(client.state)
            client.errors=[]
            for line in (b'join bad\n',b'bogus\n',b'join 01aabbccddee 1 41 7465737431323334 5\n',b'x'*300+b'\n'):
                n=len(client.errors);client.s.write(line);client.wait(lambda:len(client.errors)>n,3)
            client.errors_seen=list(client.errors);client.errors=None
            end=time.monotonic()+1.5
            while time.monotonic()<end:client.read()
            same_boot(client,boot)
            result['steps']['rejected']={'errors':client.errors_seen,'state':dict(client.state)}
            expected=['GCLIENT ERROR invalid command']*3+['GCLIENT ERROR too long']
            if client.errors_seen!=expected or client.state['active']!=0:raise RuntimeError('unexpected command rejection behavior')
            if args.no_rf:result['pass']=True
            else:
                # B1: open-port autonomous expiry.
                before=client.state['deadline_stops'];joined=client.join(cfg,password,10)
                client.wait(lambda:client.state.get('deadline_stops',0)>before and client.state.get('active')==0,15);same_boot(client,boot)
                result['steps']['deadline_open']={'joined':joined,'stopped_state':dict(client.state),'device_span_us':deadline_window(client.state,10)}
                # B2: closed-port autonomous expiry, same boot after reopen.
                before=client.state['deadline_stops'];last_us=client.last_us;joined=client.join(cfg,password,10)
                closed=rc.host_us();client.s.close();time.sleep(15)
                client.s.open();client.buf=bytearray();client.state={};client.s.write(b'info\n')
                client.wait(lambda:'active' in client.state,5);reopened=rc.host_us();same_boot(client,boot)
                if client.last_us<=last_us or client.state['active']!=0 or client.state['deadline_stops']!=before+1:raise RuntimeError('closed-port deadline not proven')
                result['steps']['deadline_closed']={'joined':joined,'port_closed_us':closed,'port_reopened_us':reopened,'state_after_reopen':dict(client.state),'device_span_us':deadline_window(client.state,10)}
                result['pass']=True
        finally:
            if client:
                try:
                    client.errors=None;client.stop();result['final_state']=dict(client.state);result['final_boot_same']=client.boot==result['steps'].get('identity',{}).get('boot')
                except BaseException as e:result['pass']=False;result['cleanup_error']=repr(e)
                finally:client.s.close()
            (out/'result.json').write_text(json.dumps(result,indent=2))
            print(json.dumps({'pass':result['pass'],'evidence':str(out)},indent=2))
    return 0 if result['pass'] else 2
if __name__=='__main__':raise SystemExit(main())

"""Attempt every cleanup step even when a USB cable or subprocess disappeared."""
import subprocess
from transport import send_command

def cleanup(serial,engine,emitter,logs,threads=(),confirm_receiver_stop=None):
 errors=[];out={}
 def attempt(label,fn):
  try:return fn()
  except Exception as exc:errors.append({'step':label,'error':str(exc)});return None
 def stop_process(proc,label,command,timeout):
  if proc is None:return
  if proc.poll() is None:
   attempt(label+'_command',lambda:send_command(proc.stdin,command))
   if label=='emitter':attempt(label+'_stdin_close',proc.stdin.close)
   try:proc.wait(timeout=timeout)
   except subprocess.TimeoutExpired:
    attempt(label+'_terminate',proc.terminate)
    try:proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
     attempt(label+'_kill',proc.kill);attempt(label+'_reap',lambda:proc.wait(timeout=2))
  if getattr(proc,'stdin',None) is not None:attempt(label+'_stdin_close',proc.stdin.close)
  out[label+'_exit']=proc.poll()
  if proc.poll() is None:errors.append({'step':label,'error':'process still running'})
  elif proc.poll()!=0:errors.append({'step':label,'error':'process exited with status '+str(proc.poll())})
 attempt('emitter_cleanup',lambda:stop_process(emitter,'emitter','STOP\n',7))
 if serial is not None:
  out['receiver_stop_confirmed']=False
  if confirm_receiver_stop is None:
   out['receiver_stop_sent']=attempt('receiver_stop',lambda:(serial.write(b'stop\n'),True)[1]) is True
   errors.append({'step':'receiver_stop','error':'delivery only; stopped status unconfirmed'})
  else:
   receipt=attempt('receiver_stop',confirm_receiver_stop)
   if isinstance(receipt,dict):out.update(receipt)
   if not out['receiver_stop_confirmed']:errors.append({'step':'receiver_stop','error':'stopped status unconfirmed'})
  out['receiver_closed']=attempt('receiver_close',lambda:(serial.close(),True)[1]) is True
 attempt('engine_cleanup',lambda:stop_process(engine,'engine','QUIT\n',2))
 for i,thread in enumerate(threads):
  attempt('reader_join_'+str(i),lambda:thread.join(timeout=2))
  if thread.is_alive():errors.append({'step':'reader_join_'+str(i),'error':'reader still running'})
 for i,log in enumerate(logs):attempt('log_close_'+str(i),log.close)
 out['errors']=errors;out['ok']=not errors;return out

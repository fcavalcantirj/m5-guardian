"""Bounded disk writer: evidence I/O cannot silently stall frame acquisition."""
import queue,threading
class AsyncLog:
 def __init__(self,sink,capacity=4096):
  self.sink=sink;self.queue=queue.Queue(capacity);self.error=None;self.thread=threading.Thread(target=self._run,daemon=True);self.thread.start()
 def _run(self):
  try:
   while True:
    item=self.queue.get()
    if item is None:break
    if item is False:self.sink.flush()
    else:self.sink.write(item)
   self.sink.flush();self.sink.close()
  except BaseException as e:self.error=e
 def _put(self,item):
  if self.error:raise RuntimeError('evidence writer failed: '+str(self.error))
  try:self.queue.put_nowait(item)
  except queue.Full:raise RuntimeError('evidence buffer full; stop instead of losing observations')
 def write(self,text):self._put(text)
 def flush(self):self._put(False)
 def close(self):
  try:self.queue.put(None,timeout=2)
  except queue.Full:raise RuntimeError('evidence writer not draining')
  self.thread.join(timeout=10)
  if self.thread.is_alive():raise RuntimeError('evidence writer did not finish')
  if self.error:raise RuntimeError('evidence writer failed: '+str(self.error))

"""Bounded pipe commands; a wedged reader must not wedge cleanup."""
import io,os,select,time

def send_command(stream,text,timeout=.25):
    if isinstance(stream,io.StringIO):
        stream.write(text)  # In-memory test double; no blocking I/O.
        return
    data=text.encode('utf-8');fd=stream.fileno();blocking=os.get_blocking(fd)
    deadline=time.monotonic()+timeout
    try:
        os.set_blocking(fd,False)
        while data:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('command pipe deadline exceeded')
            if not select.select([],[fd],[],remaining)[1]:raise TimeoutError('command pipe not writable')
            try:n=os.write(fd,data)
            except BlockingIOError:continue
            if n<=0:raise BrokenPipeError('command pipe closed')
            data=data[n:]
    finally:os.set_blocking(fd,blocking)

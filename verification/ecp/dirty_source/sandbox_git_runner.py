"""Read-only Git adapter for a pre-isolated synthetic repository only.

Caller must put repository and logs inside a disposable namespace. No timeout,
signal, cleanup or process-tree proof is provided; a stuck process is UNKNOWN.
A record retains bounded observed streams even for failed and truncated calls.
"""
import base64
import hashlib
import os
import stat
import subprocess

GIT='/usr/bin/git'
MAX_CAPTURE=32*1024*1024
MAX_STDERR=65536
ALLOWED={('rev-parse','--verify','HEAD^{commit}'),('ls-files','--stage','-z'),('ls-files','-v','-z')}
class GitObservationError(RuntimeError):pass

class SandboxGitRunner:
 def __init__(self,rootfd,logfd):
    self.rootfd=rootfd;self.logfd=logfd;self.count=0;self.records=[];self.capture_bytes=0
    if not stat.S_ISDIR(os.fstat(rootfd).st_mode) or not stat.S_ISDIR(os.fstat(logfd).st_mode):raise GitObservationError('DIRECTORY_REQUIRED')
 def _capture(self,fd,limit):
    # Data may still change after direct-child exit; record endpoint samples and
    # never assert trusted EOF, independent identity or future immutability.
    result={'state':'UNKNOWN','size_before':None,'size_after':None,'captured_bytes':0,'captured_base64':'','captured_sha256':None,'truncated':None}
    if fd is None:return result
    parts=[];n=0
    try:
     before=os.fstat(fd).st_size;result['size_before']=before
     allowed=max(0,min(limit,MAX_CAPTURE-self.capture_bytes))
     os.lseek(fd,0,os.SEEK_SET)
     while n<allowed:
      block=os.read(fd,min(65536,allowed-n))
      if not block:break
      parts.append(block);n+=len(block)
     after=os.fstat(fd).st_size
     result.update(state='READ_RETURNED',size_after=after,truncated=(before>n or after>n))
    except (OSError,ValueError):result['state']='READ_UNKNOWN'
    data=b''.join(parts);self.capture_bytes+=len(data)
    result.update(captured_bytes=len(data),captured_base64=base64.b64encode(data).decode('ascii'),captured_sha256=hashlib.sha256(data).hexdigest())
    return result
 def __call__(self,args,limit):
    valid=(args in ALLOWED or (len(args)==4 and args[:3]==('ls-tree','-rz','--full-tree') and len(args[3]) in (40,64) and all(c in '0123456789abcdef' for c in args[3])) or (len(args)==3 and args[:2]==('cat-file','blob') and len(args[2]) in (40,64) and all(c in '0123456789abcdef' for c in args[2])))
    if not valid or type(limit) is not int or not 0<limit<=8*1024*1024:raise GitObservationError('INVALID_REQUEST')
    if self.count>=10000:raise GitObservationError('COMMAND_LIMIT')
    number=self.count;self.count+=1
    rec={'args':list(args),'launch_state':'NOT_STARTED','exit_code':None,'exit_state':'UNKNOWN','stdout':None,'stderr':None,'close_state':'NOT_ATTEMPTED','process_tree':'UNKNOWN'}
    out=err=None;failure=None
    try:
     out=os.open('%05d.out'%number,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.logfd)
     err=os.open('%05d.err'%number,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.logfd)
     env={'PATH':'/usr/bin','HOME':'/empty','LANG':'C','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_OPTIONAL_LOCKS':'0','GIT_ATTR_NOSYSTEM':'1','GIT_TERMINAL_PROMPT':'0','GIT_EXEC_PATH':'/usr/bin'}
     command=[GIT,'--no-pager','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','gc.auto=0','-c','diff.external=','-c','color.ui=false',*args]
     rec['launch_state']='POPEN_ATTEMPTED'
     child=subprocess.Popen(command,cwd='/proc/self/fd/%d'%self.rootfd,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,pass_fds=(self.rootfd,),close_fds=True)
     rec['launch_state']='POPEN_RETURNED'
     rec['exit_code']=child.wait() # no signals; caller must poll its outer session
     rec['exit_state']='WAIT_RETURNED'
     if rec['exit_code']!=0:failure='COMMAND_NONZERO'
    except Exception as exc:
     failure='RUNNER_EXCEPTION';rec['exception_type']=type(exc).__name__
    finally:
     rec['stdout']=self._capture(out,limit)
     rec['stderr']=self._capture(err,MAX_STDERR)
     close_ok=True;close_details={}
     for name,fd in (('stdout',out),('stderr',err)):
      if fd is None:close_details[name]='NOT_OPENED';continue
      try:os.close(fd);close_details[name]='CLOSED'
      except OSError:close_ok=False;close_details[name]='UNKNOWN'
     rec['close_state']='CLOSED' if close_ok else 'UNKNOWN';rec['close_details']=close_details
     self.records.append(rec)
    for name in ('stdout','stderr'):
     item=rec[name]
     if item['state']!='READ_RETURNED' or item['truncated'] is not False or item['size_before']!=item['size_after'] or item['size_after']!=item['captured_bytes']:
      failure=failure or 'STREAM_INCOMPLETE_OR_TRUNCATED'
    if rec['close_state']!='CLOSED':failure=failure or 'CLOSE_UNKNOWN'
    if rec['stderr']['captured_bytes']!=0:failure=failure or 'STDERR_NONEMPTY'
    if failure:
     rec['failure']=failure
     raise GitObservationError(failure)
    return base64.b64decode(rec['stdout']['captured_base64'],validate=True)

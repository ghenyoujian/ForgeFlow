"""P0-03 observation is blocked pending verified supervised execution.

Admission checks below are read-only observations, not source or authorization
proof. No workload is launched; empty returned streams mean NOT_CAPTURED.
Read-only pread may block on an untrusted or FUSE filesystem; no wall-clock
bound or persisted evidence or Gate is claimed.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import fcntl
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import time

MAX_REGISTRY = 2 * 1024 * 1024
MAX_STREAM = 2 * 1024 * 1024
SYSCALLS = ('socket', 'socketpair', 'connect', 'bind', 'listen', 'accept', 'accept4',
            'sendto', 'sendmsg', 'sendmmsg', 'recvfrom', 'recvmsg', 'recvmmsg',
            'io_uring_setup', 'io_uring_enter', 'io_uring_register', 'unshare', 'setns',
            'clone3', 'pidfd_getfd', 'ptrace', 'process_vm_readv', 'process_vm_writev', 'bpf')
WORKLOAD = {'runner': 'python_unittest', 'start_directory': 'ops/ecp/tests',
            'pattern': 'test_p003_contract.py', 'requires_non_skipped': True,
            'network_access': False, 'database_access': False}
LIMITATIONS = ['only caller-preverified trusted test source may be supplied; this is not an untrusted-code runner',
               'no aggregate cgroup, pids or memory budget is enforced',
               'source content and Git identity are not independently authenticated',
               'source content observation is not an atomic snapshot',
               'preflight marker precedes exec and does not prove unittest started',
               'workload outcomes and denominator require independent parsing',
               'file-backed or in-process databases are not blocked',
               'all kernel paths, escapes, CPU, memory and descendant lifetime are not proven',
               'principal, lease, independent execution authority and product Gate remain unverified']


def _memfd(name: str, allow_sealing: bool = False) -> int:
    flags = getattr(os, 'MFD_CLOEXEC', 1) | (getattr(os, 'MFD_ALLOW_SEALING', 2) if allow_sealing else 0)
    if hasattr(os, 'memfd_create'):
        return os.memfd_create(name, flags)
    libc = ctypes.CDLL(None, use_errno=True)
    create = getattr(libc, 'memfd_create', None)
    if create is None:
        raise ValueError('memfd unavailable')
    create.argtypes = [ctypes.c_char_p, ctypes.c_uint]; create.restype = ctypes.c_int
    fd = create(name.encode('ascii'), flags)
    if fd < 0:
        err = ctypes.get_errno(); raise OSError(err, os.strerror(err))
    return fd


def _sealed(data: bytes, name: str) -> int:
    fd = _memfd(name, True)
    try:
        remaining = memoryview(data)
        while remaining:
            n = os.write(fd, remaining)
            if n <= 0:
                raise OSError('short memfd write')
            remaining = remaining[n:]
        os.lseek(fd, 0, os.SEEK_SET)
        seals = getattr(fcntl, 'F_SEAL_WRITE', 8) | getattr(fcntl, 'F_SEAL_GROW', 4) | getattr(fcntl, 'F_SEAL_SHRINK', 2) | getattr(fcntl, 'F_SEAL_SEAL', 1)
        fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), seals)
        if fcntl.fcntl(fd, getattr(fcntl, 'F_GET_SEALS', 1034)) & seals != seals:
            raise ValueError('memfd sealing failed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _filter() -> tuple[int, str, dict[str, int]]:
    """Filter construction is disabled until process supervision is verified."""
    raise RuntimeError('P003 filter construction blocked: supervised process lifecycle is unverified')


def _registry(fd: int, expected: str) -> bytes:
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('registry SHA-256 is required')
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    before = os.fstat(fd)
    if flags & os.O_ACCMODE != os.O_RDONLY or flags & getattr(os, 'O_PATH', 0):
        raise ValueError('registry FD must be read-only')
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_REGISTRY:
        raise ValueError('registry FD must be a bounded singly-linked regular file')
    data = bytearray()
    while len(data) < before.st_size:
        chunk = os.pread(fd, min(65536, before.st_size - len(data)), len(data))
        if not chunk:
            raise ValueError('short registry read')
        data.extend(chunk)
    after = os.fstat(fd)
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, k) != getattr(after, k) for k in keys) or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('registry changed or digest mismatch')
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError('duplicate registry key')
            result[k] = v
        return result
    value = json.loads(data, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid JSON constant')))
    suites = value.get('suites') if isinstance(value, dict) else None
    matches = [s for s in suites if isinstance(s, dict) and s.get('suite_id') == 'ECP-P0-03'] if isinstance(suites, list) else []
    if len(matches) != 1 or matches[0].get('offline_workload') != WORKLOAD or matches[0].get('implementation_entrypoint') != 'control/ops/ecp/verify':
        raise ValueError('P0-03 registry binding is missing or ambiguous')
    return bytes(data)


def _base() -> list[str]:
    return ['/usr/bin/bwrap', '--die-with-parent', '--unshare-user', '--unshare-pid', '--unshare-net',
            '--unshare-ipc', '--unshare-uts', '--cap-drop', 'ALL', '--ro-bind', '/usr', '/usr',
            '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--size', str(128 * 1024 * 1024), '--tmpfs', '/tmp']


def _bounded(command: list[str], fds: tuple[int, ...], timeout: float, limit: int) -> dict:
    """Private historical helper is disabled until supervised execution is verified."""
    raise RuntimeError('P003 execution blocked: supervised process lifecycle is unverified')


_PREFLIGHT = r'''import ctypes,errno,hashlib,json,os,stat,subprocess,sys
source_dev,source_ino,registry_dev,registry_ino=map(int,sys.argv[1:5]); hostnet,digest=sys.argv[5:7]
assert os.readlink('/proc/self/ns/net') != hostnet
assert next(v.split()[1] for v in open('/proc/self/status') if v.startswith('CapEff:')) == '0000000000000000'
assert os.statvfs('/src').f_flag & os.ST_RDONLY
assert (os.stat('/src').st_dev,os.stat('/src').st_ino) == (source_dev,source_ino)
assert os.statvfs('/planning/suite_registry.json').f_flag & os.ST_RDONLY
assert hashlib.sha256(open('/planning/suite_registry.json','rb').read()).hexdigest() == digest
assert os.readlink('/proc/self/fd/0') == '/dev/null'
assert not os.path.exists(os.environ['HOME'])
for name in os.listdir('/proc/self/fd'):
 try: st=os.fstat(int(name))
 except OSError: continue
 assert not stat.S_ISSOCK(st.st_mode)
 assert (st.st_dev,st.st_ino) not in ((source_dev,source_ino),(registry_dev,registry_ino))
l=ctypes.CDLL(None,use_errno=True)
for nr in (41,53,42,425,426,427,272,308):
 ctypes.set_errno(0); result=l.syscall(nr,0,0,0,0,0,0)
 assert result == -1 and ctypes.get_errno() == errno.EPERM
for code in ("import ctypes;ctypes.CDLL(None).syscall(0x40000000|39)",
 "import mmap,ctypes;m=mmap.mmap(-1,4096,prot=7);m.write(bytes.fromhex('b814000000cd80c3'));ctypes.CFUNCTYPE(ctypes.c_long)(ctypes.addressof(ctypes.c_char.from_buffer(m)))()"):
 p=subprocess.run(['/usr/bin/python3','-I','-S','-c',code],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 assert p.returncode == -31
print('ECP_P003_PREFLIGHT '+json.dumps({'source_fd_leaked':False,'registry_fd_leaked':False,'socket_fd_leaked':False,'seccomp_native_and_compat_checked':True},sort_keys=True),flush=True)
os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-S','-m','unittest','discover','-s','ops/ecp/tests','-p','test_p003_contract.py','-v'])
'''


def observe(source_fd: int, registry_fd: int, *, source_identity: tuple[int, int], registry_sha256: str,
            source_preverified: bool = False, timeout: float = 60.0, log_limit: int = MAX_STREAM) -> dict:
    """Read-only admission checks; execution is blocked until supervision is verified.

    Source trust, containment and persistence remain unverified. This retains
    the existing call signature but deliberately does not start a workload.
    """
    result = {'status': 'BLOCKED', 'qualification': 'NOT_RUN', 'product_gate_effect': 'NONE',
              'limitations': LIMITATIONS, 'stdout_bytes': b'', 'stderr_bytes': b'',
              'preflight_completed': False, 'workload_invoked': False, 'capture_state': 'NOT_CAPTURED',
              'reason_code': 'SUPERVISION_UNVERIFIED',
              'reason': 'supervised execution and cleanup are not verified'}
    try:
        if source_preverified is not True:
            raise ValueError('caller-preverified trusted test source is required')
        if type(source_fd) is not int or type(registry_fd) is not int or min(source_fd, registry_fd) < 3 or source_fd == registry_fd:
            raise ValueError('source and registry require separate non-stdio descriptors')
        if not (0 < timeout <= 300 and 1024 <= log_limit <= MAX_STREAM):
            raise ValueError('invalid runtime budget')
        flags, st = fcntl.fcntl(source_fd, fcntl.F_GETFL), os.fstat(source_fd)
        if flags & os.O_ACCMODE != os.O_RDONLY or flags & getattr(os, 'O_PATH', 0) or not stat.S_ISDIR(st.st_mode):
            raise ValueError('source FD must be a read-only directory')
        if type(source_identity) is not tuple or source_identity != (st.st_dev, st.st_ino):
            raise ValueError('trusted source directory identity is missing or mismatched')
        _registry(registry_fd, registry_sha256)
        result.update(source_identity=[st.st_dev, st.st_ino], registry_sha256=registry_sha256,
                      admission_checks='CHECKS_COMPLETED_UNVERIFIED')
    except (OSError, RecursionError) as exc:
        result.update(reason_code='ADMISSION_CHECK_UNAVAILABLE', reason=f'{type(exc).__name__}: {exc}',
                      admission_checks='UNKNOWN')
    except (ValueError, TypeError, OverflowError) as exc:
        result.update(reason_code='ADMISSION_REJECTED', reason=f'{type(exc).__name__}: {exc}',
                      admission_checks='REJECTED')
    return result

"""Research-only sealed dirty bundle writer; no source scan or authorization.

Caller owns input objects and must exclude concurrent mutation. A returned FD is
owned by caller. Before return every failure attempts to close the FD once; an
asynchronous exception between acquisition and registration remains UNKNOWN.
"""
import fcntl
import hashlib
import os
import re
import struct

MAGIC=b'FFDBND1\0'
MAX_MANIFEST=8*1024*1024
MAX_BLOB=8*1024*1024
MAX_TOTAL=32*1024*1024
MAX_COMMIT=2*1024*1024
MAX_BLOBS=4096
MAX_BUNDLE=48*1024*1024
REQUIRED_NAMES=('F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL')

class BundleWriteError(ValueError):
    pass


def _close_fd(fd):
    os.close(fd)


def encode(manifest_bytes, blobs, commit):
    """Serialize caller bytes; independent reader must validate semantics."""
    if type(manifest_bytes) is not bytes or not 0<len(manifest_bytes)<=MAX_MANIFEST:
        raise BundleWriteError('MANIFEST_LIMIT')
    if type(commit) is not bytes or not 0<len(commit)<=MAX_COMMIT:
        raise BundleWriteError('COMMIT_LIMIT')
    if type(blobs) is not dict or len(blobs)>MAX_BLOBS:
        raise BundleWriteError('BLOB_COUNT')
    size=0
    for key,data in blobs.items():
        if type(key) is not str or re.fullmatch('[0-9a-f]{64}',key) is None or type(data) is not bytes or len(data)>MAX_BLOB:
            raise BundleWriteError('BLOB_INVALID')
        if hashlib.sha256(data).hexdigest()!=key:
            raise BundleWriteError('BLOB_DIGEST')
        size+=len(data)
        if size>MAX_TOTAL: raise BundleWriteError('BLOB_TOTAL')
    total=20+len(manifest_bytes)+sum(36+len(x) for x in blobs.values())+len(commit)+32
    if total>MAX_BUNDLE: raise BundleWriteError('BUNDLE_LIMIT')
    parts=[struct.pack('!8sIII',MAGIC,len(manifest_bytes),len(blobs),len(commit)),manifest_bytes]
    for key in sorted(blobs):
        data=blobs[key]
        parts.extend((bytes.fromhex(key),struct.pack('!I',len(data)),data))
    parts.append(commit)
    digest=hashlib.sha256()
    for part in parts: digest.update(part)
    parts.append(digest.digest())
    return b''.join(parts)


def create(manifest_bytes, blobs, commit):
    """Return owned sealed FD; cleanup ledger is attached to exceptions."""
    data=encode(manifest_bytes,blobs,commit)
    if not all(hasattr(fcntl,k) for k in (*REQUIRED_NAMES,'F_ADD_SEALS','F_GET_SEALS')) or not all(hasattr(os,k) for k in ('memfd_create','MFD_ALLOW_SEALING','MFD_CLOEXEC')):
        raise BundleWriteError('SEAL_API_UNAVAILABLE')
    flags=0
    for name in REQUIRED_NAMES: flags |= getattr(fcntl,name)
    fd=None
    try:
        fd=os.memfd_create('forgeflow-dirty-bundle-research',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
        offset=0;view=memoryview(data)
        while offset<len(data):
            n=os.write(fd,view[offset:])
            if n<=0 or n>len(data)-offset: raise BundleWriteError('WRITE_INCOMPLETE')
            offset+=n
        if os.fstat(fd).st_size!=len(data): raise BundleWriteError('SIZE_MISMATCH')
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,flags)
        if fcntl.fcntl(fd,fcntl.F_GET_SEALS)&flags!=flags: raise BundleWriteError('SEAL_MISMATCH')
        result=fd
        fd=None
        return result
    except BaseException as original:
        close_state='NOT_ACQUIRED';close_error=None;close_interrupt=None
        if fd is not None:
            current=fd;fd=None
            try:
                _close_fd(current);close_state='CLOSED'
            except BaseException as exc:
                close_state='UNKNOWN';close_error=type(exc).__name__
                if not isinstance(exc,Exception): close_interrupt=exc
        if close_interrupt is not None and isinstance(original,Exception):
            close_interrupt.bundle_prior_error=original
            close_interrupt.bundle_close_state=close_state
            raise close_interrupt from original
        original.bundle_close_state=close_state
        original.bundle_close_error_type=close_error
        if close_interrupt is not None: original.bundle_close_interruption=close_interrupt
        raise

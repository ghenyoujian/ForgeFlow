"""Independent, bounded research oracle for a restricted dirty Git candidate.

No Git, subprocess or producer imports. Caller supplies an open root directory
FD and an untrusted declaration/blob bundle. Success is an endpoint observation
under the caller's isolation assumptions, never source authentication or Gate.
"""
import base64
import bisect
import ctypes
from contextlib import ExitStack
import hashlib
import json
import os
import re
import resource
import stat
import struct
import zlib

MAX_ROWS = 4096
MAX_PATH = 4096
MAX_TOTAL_PATH_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 128
MAX_COMPONENT = 255
MAX_BLOB = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_INDEX = 8 * 1024 * 1024
MAX_COMPRESSED = MAX_BLOB + 65536
MAX_OBJECTS = 8192
MAX_JSON = 16 * 1024 * 1024
MAX_JSON_NODES = 100000
MAX_JSON_STRING = 8192
MAX_TREE_ENTRIES = 20000
MAX_OPEN_FDS = 4096
FD_RESERVE = 16
MAX_SYMLINK_BYTES = 4095
MAX_REF_COMPONENTS = 16
MAX_DERIVED_DIRS = 20000
MAX_DERIVED_DIR_BYTES = 2 * 1024 * 1024
MAX_CLOSE_EVENTS = 100000

class OracleError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise OracleError(code)


def canonical(value):
    stack = [(value, 0)]; count = 0
    while stack:
        item, depth = stack.pop(); count += 1
        need(count <= MAX_JSON_NODES and depth <= 16, 'MANIFEST_BUDGET')
        if type(item) is dict:
            need(len(item) <= MAX_ROWS * 2, 'MANIFEST_BUDGET')
            for key, child in item.items():
                need(type(key) is str and len(key) <= MAX_JSON_STRING, 'MANIFEST_ENCODING')
                stack.append((child, depth + 1))
        elif type(item) is list:
            need(len(item) <= MAX_ROWS * 2, 'MANIFEST_BUDGET')
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            need(len(item) <= MAX_JSON_STRING, 'MANIFEST_BUDGET')
        elif item is None or type(item) is bool:
            pass
        elif type(item) is int:
            need(item.bit_length() <= 63, 'MANIFEST_BUDGET')
        else:
            raise OracleError('MANIFEST_ENCODING')
    chunks = []; length = 0
    try:
        for chunk in json.JSONEncoder(sort_keys=True, ensure_ascii=True,
                                      separators=(',', ':'), allow_nan=False).iterencode(value):
            length += len(chunk); need(length <= MAX_JSON, 'MANIFEST_BUDGET')
            chunks.append(chunk)
        return ''.join(chunks).encode('ascii')
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, OracleError): raise
        raise OracleError('MANIFEST_ENCODING') from exc


def path_bytes(encoded):
    need(type(encoded) is str and len(encoded) <= 4 * ((MAX_PATH + 2) // 3), 'PATH_INVALID')
    try: value = base64.b64decode(encoded, validate=True)
    except (ValueError, UnicodeError) as exc: raise OracleError('PATH_INVALID') from exc
    need(base64.b64encode(value).decode('ascii') == encoded, 'PATH_INVALID')
    validate_path(value)
    return value


def validate_path(value):
    need(type(value) is bytes and 0 < len(value) <= MAX_PATH, 'PATH_INVALID')
    parts = value.split(b'/')
    need(len(parts) <= MAX_DEPTH and all(part not in (b'',b'.',b'..') and
         b'\0' not in part and len(part) <= MAX_COMPONENT and part.lower() != b'.git'
         for part in parts), 'PATH_INVALID')


def blob_oid(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()


def load_declaration(manifest, expected_hash, blobs):
    need(type(manifest) is dict and type(blobs) is dict and len(blobs) <= MAX_ROWS, 'DECLARATION_INVALID')
    keys = {'schema','qualification','product_gate_effect','source_authentication','snapshot_atomicity',
            'completeness_authority','head_commit_claim','git_object_format_claim','coverage_claims',
            'head','index','tracked_worktree','untracked','excluded','staged_changes','unstaged_changes',
            'unknown_worktree_modes','input_bytes_counting_each_projection'}
    need(set(manifest)==keys and manifest.get('qualification')=='NOT_RUN' and
         manifest.get('product_gate_effect')=='NONE' and manifest.get('source_authentication')=='UNVERIFIED' and
         manifest.get('snapshot_atomicity')=='UNKNOWN' and
         manifest.get('completeness_authority')=='UNVERIFIED', 'DECLARATION_MARKERS_INVALID')
    need(type(expected_hash) is str and re.fullmatch(r'[0-9a-f]{64}', expected_hash) is not None,
         'MANIFEST_HASH_INVALID')
    need(hashlib.sha256(canonical(manifest)).hexdigest() == expected_hash, 'MANIFEST_HASH_MISMATCH')
    need(manifest.get('schema') == 'forgeflow.ecp-dirty-source-declaration.research.v1' and
         manifest.get('git_object_format_claim') == 'sha1' and
         type(manifest.get('head_commit_claim')) is str and
         re.fullmatch(r'[0-9a-f]{40}', manifest['head_commit_claim']) is not None,
         'DECLARATION_UNSUPPORTED')
    claims = manifest.get('coverage_claims')
    need(type(claims) is dict and set(claims) == {'head','index','worktree','exclusions'} and
         all(type(v) is bool for v in claims.values()) and
         all(claims[x] is True for x in ('head','index','worktree')), 'PROJECTION_CLAIM_INCOMPLETE')
    need(type(manifest.get('excluded')) is list and not manifest['excluded'], 'EXCLUSIONS_UNSUPPORTED')
    maps = {}; seen_blobs = set(); total_rows = 0; total_content = 0; total_paths = 0
    required = {'path_b64','kind','mode','byte_count','sha256','computed_git_blob_oid'}
    for label in ('head','index','tracked_worktree','untracked'):
        rows = manifest.get(label)
        need(type(rows) is list and len(rows) <= MAX_ROWS, 'ROWS_INVALID')
        entries = {}; previous_path = None
        for row in rows:
            need(type(row) is dict and set(row) == required, 'ROW_INVALID')
            path = path_bytes(row['path_b64']); need(path not in entries, 'DUPLICATE_PATH')
            need(previous_path is None or previous_path < path, 'ROW_ORDER_INVALID'); previous_path = path
            total_paths += len(path); need(total_paths <= MAX_TOTAL_PATH_BYTES, 'TOTAL_PATH_BUDGET')
            kind, mode, size, digest, oid = (row[k] for k in ('kind','mode','byte_count','sha256','computed_git_blob_oid'))
            need((kind,mode) in (('file','100644'),('file','100755'),('symlink','120000')), 'MODE_UNSUPPORTED')
            need(type(size) is int and 0 <= size <= MAX_BLOB and type(digest) is str and
                 re.fullmatch(r'[0-9a-f]{64}',digest) is not None and type(oid) is str and
                 re.fullmatch(r'[0-9a-f]{40}',oid) is not None, 'BLOB_REFERENCE_INVALID')
            raw = blobs.get(digest)
            need(type(raw) is bytes and len(raw) == size and hashlib.sha256(raw).hexdigest() == digest and
                 blob_oid(raw) == oid, 'BLOB_MISMATCH')
            need(kind != 'symlink' or (raw and b'\0' not in raw and len(raw)<=MAX_SYMLINK_BYTES), 'SYMLINK_INVALID')
            entries[path] = (kind,mode,raw,oid); seen_blobs.add(digest)
            total_rows += 1; total_content += len(raw)
            need(total_rows <= MAX_ROWS and total_content <= MAX_TOTAL, 'DECLARATION_BUDGET')
        maps[label] = entries
    need(set(blobs) == seen_blobs and total_rows > 0, 'BLOB_SET_OR_DENOMINATOR')
    need(not (set(maps['untracked']) & set(maps['index'])) and
         set(maps['tracked_worktree']) <= set(maps['index']), 'PROJECTION_RELATION_INVALID')
    for entries in (maps['head'], maps['index'], {**maps['tracked_worktree'], **maps['untracked']}):
        ordered = sorted(entries)
        for path in ordered:
            prefix=path+b'/'
            i=bisect.bisect_left(ordered,prefix)
            need(i==len(ordered) or not ordered[i].startswith(prefix), 'PATH_COLLISION')
    def derived_changes(left,right):
        changes=[]
        for path in sorted(set(left)|set(right)):
            old,new=left.get(path),right.get(path)
            if old==new: continue
            change='ADDED' if old is None else 'DELETED' if new is None else 'MODIFIED'
            changes.append({'path_b64':base64.b64encode(path).decode('ascii'),'change':change})
        return changes
    need(manifest.get('staged_changes')==derived_changes(maps['head'],maps['index']) and
         manifest.get('unstaged_changes')==derived_changes(maps['index'],maps['tracked_worktree']) and
         manifest.get('unknown_worktree_modes')==[] and
         type(manifest.get('input_bytes_counting_each_projection')) is int and
         manifest['input_bytes_counting_each_projection']==total_content, 'DERIVED_CLAIMS_MISMATCH')
    return maps


def sig(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_size,
            value.st_mtime_ns,value.st_ctime_ns)


class CloseLedger:
    """Tracks one close attempt per owner; incomplete bookkeeping fails closed."""
    def __init__(self):
        self.events=[];self.incomplete=False

    def close_once(self,fd,kind):
        failure=None
        try:os.close(fd)
        except BaseException as exc:failure=exc
        try:
            if len(self.events)>=MAX_CLOSE_EVENTS:
                self.incomplete=True
            else:
                self.events.append({'ordinal':len(self.events),'kind':kind,
                                    'state':'CLOSED' if failure is None else 'UNKNOWN',
                                    'error_type':None if failure is None else type(failure).__name__})
        except BaseException as bookkeeping:
            self.incomplete=True
            if failure is None or (isinstance(failure,Exception) and not isinstance(bookkeeping,Exception)):
                failure=bookkeeping
        return failure


class OwnedFD:
    """Explicit one-close owner; a caller's root FD is never wrapped here."""
    def __init__(self,fd,ledger,kind):self.fd=fd;self.ledger=ledger;self.kind=kind
    def __enter__(self):return self.fd
    def release(self):
        fd=self.fd;self.fd=None;return fd
    def __exit__(self,exc_type,body_error,traceback):
        fd=self.fd;self.fd=None
        if fd is None:return False
        close_error=self.ledger.close_once(fd,self.kind)
        if close_error is None:return False
        if body_error is None:
            if not isinstance(close_error,Exception):raise close_error
            raise OracleError('FD_CLOSE_UNKNOWN') from close_error
        if isinstance(body_error,Exception) and not isinstance(close_error,Exception):
            close_error.oracle_prior_error=body_error
            raise close_error from body_error
        # Preserve an existing interruption or ordinary body exception while
        # the ledger retains every subsequent close uncertainty.
        return False


def open_dir(parentfd, name, rootdev, ledger, *, expected=None):
    before = os.stat(name, dir_fd=parentfd, follow_symlinks=False)
    need(expected is None or sig(before)==sig(expected), 'DIRECTORY_IDENTITY_CHANGED')
    need(stat.S_ISDIR(before.st_mode) and before.st_dev == rootdev, 'DIRECTORY_UNSUPPORTED')
    owner=OwnedFD(os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=parentfd),
                  ledger,'DIRECTORY_ACQUISITION')
    with owner as fd:
        need(sig(os.fstat(fd)) == sig(before), 'DIRECTORY_CHANGED')
        return owner.release()


def read_file(parentfd, name, rootdev, limit, ledger, *, expected=None):
    before = os.stat(name, dir_fd=parentfd, follow_symlinks=False)
    need(expected is None or sig(before)==sig(expected), 'FILE_IDENTITY_CHANGED')
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_dev == rootdev and
         before.st_size <= limit, 'FILE_UNSUPPORTED')
    with OwnedFD(os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC, dir_fd=parentfd),
                 ledger,'FILE') as fd:
        need(sig(os.fstat(fd)) == sig(before), 'FILE_CHANGED')
        parts = []; total = 0
        while True:
            chunk = os.read(fd,min(65536,limit+1-total))
            if not chunk: break
            total += len(chunk); need(total <= limit, 'FILE_BUDGET'); parts.append(chunk)
        need(total == before.st_size and sig(os.fstat(fd)) == sig(before) and
             sig(os.stat(name,dir_fd=parentfd,follow_symlinks=False)) == sig(before), 'FILE_CHANGED')
        return b''.join(parts)


def absent(parentfd, name):
    try: os.stat(name,dir_fd=parentfd,follow_symlinks=False)
    except FileNotFoundError: return True
    return False


def read_head(gitfd, rootdev, ledger):
    head = read_file(gitfd,b'HEAD',rootdev,4096,ledger)
    if re.fullmatch(b'[0-9a-f]{40}\n',head): return head[:-1].decode('ascii')
    prefix=b'ref: refs/heads/'
    need(head.startswith(prefix) and head.endswith(b'\n'), 'HEAD_UNSUPPORTED')
    rest=head[len(prefix):-1]; validate_path(rest)
    # Deliberately narrower than Git's permitted refnames; no attempt to
    # normalize or guess aliases. The effective config is not authenticated.
    need(len(rest.split(b'/'))<=MAX_REF_COMPONENTS and
         all(re.fullmatch(b'[A-Za-z0-9][A-Za-z0-9._-]*',part) is not None and
             not part.endswith((b'.',b'.lock')) and b'..' not in part
             for part in rest.split(b'/')), 'HEAD_REF_UNSUPPORTED')
    with ExitStack() as stack:
        fd=gitfd
        for component in (b'refs',b'heads',*rest.split(b'/')[:-1]):
            fd=stack.enter_context(OwnedFD(open_dir(fd,component,rootdev,ledger),ledger,'REF_DIRECTORY'))
        value=read_file(fd,rest.split(b'/')[-1],rootdev,128,ledger)
    need(re.fullmatch(b'[0-9a-f]{40}\n',value) is not None, 'HEAD_REF_UNSUPPORTED')
    return value[:-1].decode('ascii')


def check_object_layout(objectsfd, rootdev, ledger):
    for dirname, names_forbidden in ((b'info',(b'alternates',b'http-alternates')),(b'pack',None)):
        if absent(objectsfd,dirname): continue
        with OwnedFD(open_dir(objectsfd,dirname,rootdev,ledger),ledger,'OBJECT_LAYOUT_DIRECTORY') as dfd:
            if names_forbidden is None:
                with os.scandir(dfd) as stream: need(next(stream,None) is None, 'PACK_UNSUPPORTED')
            else:
                for name in names_forbidden: need(absent(dfd,name), 'ALTERNATES_UNSUPPORTED')


def read_object(objectsfd, oid, rootdev, cache, ledger):
    need(type(oid) is str and re.fullmatch(r'[0-9a-f]{40}',oid) is not None, 'OID_INVALID')
    if oid in cache['objects']: return cache['objects'][oid]
    need(len(cache['objects']) < MAX_OBJECTS, 'OBJECT_COUNT_LIMIT')
    with OwnedFD(open_dir(objectsfd,oid[:2].encode('ascii'),rootdev,ledger),ledger,'OBJECT_DIRECTORY') as sub:
        compressed=read_file(sub,oid[2:].encode('ascii'),rootdev,MAX_COMPRESSED,ledger)
    cache['compressed'] += len(compressed)
    need(cache['compressed'] <= MAX_TOTAL, 'OBJECT_COMPRESSED_TOTAL_LIMIT')
    try:
        decompressor=zlib.decompressobj()
        decoded=decompressor.decompress(compressed,MAX_BLOB+65)
        need(decompressor.eof and not decompressor.unconsumed_tail and not decompressor.unused_data,
             'OBJECT_COMPRESSION_INVALID_OR_LIMIT')
    except zlib.error as exc: raise OracleError('OBJECT_COMPRESSION_INVALID_OR_LIMIT') from exc
    need(hashlib.sha1(decoded).hexdigest()==oid, 'OBJECT_OID_MISMATCH')
    header,sep,body=decoded.partition(b'\0')
    need(bool(sep) and len(header)<=64 and re.fullmatch(b'(?:commit|tree|blob) (?:0|[1-9][0-9]*)',header) is not None,
         'OBJECT_HEADER_INVALID')
    kind,size=header.split(b' ');need(int(size)==len(body) and len(body)<=MAX_BLOB, 'OBJECT_SIZE_INVALID')
    cache['decoded'] += len(body)
    need(cache['decoded'] <= MAX_TOTAL, 'OBJECT_DECODED_TOTAL_LIMIT')
    cache['objects'][oid]=(kind,body);return kind,body


def parse_tree(objectsfd, rootdev, root_oid, cache, ledger):
    rows={}; pending=[(b'',root_oid,0)]; total=0; path_total=0
    while pending:
        prefix,oid,depth=pending.pop();need(depth<=MAX_DEPTH, 'TREE_DEPTH')
        kind,body=read_object(objectsfd,oid,rootdev,cache,ledger);need(kind==b'tree','TREE_TYPE')
        need(not prefix or bool(body), 'EMPTY_SUBTREE_UNSUPPORTED')
        pos=0;previous=None;names=set()
        while pos<len(body):
            space=body.find(b' ',pos);zero=body.find(b'\0',space+1) if space>=0 else -1
            need(space>pos and zero>space+1 and zero+21<=len(body), 'TREE_ENCODING')
            mode,name,raw_oid=body[pos:space],body[space+1:zero],body[zero+1:zero+21]
            need(mode in (b'40000',b'100644',b'100755',b'120000') and b'/' not in name and
                 name not in (b'',b'.',b'..') and b'\0' not in name and name.lower()!=b'.git' and
                 len(name)<=MAX_COMPONENT and name not in names, 'TREE_ENTRY_UNSUPPORTED')
            names.add(name);sortkey=name+(b'/' if mode==b'40000' else b'\0')
            need(previous is None or previous<sortkey, 'TREE_ORDER_INVALID');previous=sortkey
            path=prefix+name;validate_path(path);child=raw_oid.hex();pos=zero+21
            path_total+=len(path);need(path_total<=MAX_TOTAL_PATH_BYTES,'TREE_PATH_BUDGET')
            total+=1;need(total<=MAX_TREE_ENTRIES,'TREE_ENTRY_LIMIT')
            if mode==b'40000': pending.append((path+b'/',child,depth+1))
            else:
                need(path not in rows,'TREE_DUPLICATE');rows[path]=(mode.decode('ascii'),child)
    return rows


def parse_index(data):
    need(len(data)>=32 and len(data)<=MAX_INDEX and data[:4]==b'DIRC','INDEX_INVALID')
    version,count=struct.unpack_from('!II',data,4)
    need(version==2 and count<=MAX_ROWS, 'INDEX_UNSUPPORTED')
    need(hashlib.sha1(data[:-20]).digest()==data[-20:], 'INDEX_CHECKSUM')
    pos=12; result={}; previous=None;path_total=0
    for _ in range(count):
        start=pos;need(pos+62<=len(data)-20,'INDEX_TRUNCATED')
        fields=struct.unpack_from('!10I20sH',data,pos);mode=fields[6];oid=fields[10].hex();flags=fields[11]
        need(not (flags & 0xf000) and mode in (0o100644,0o100755,0o120000),'INDEX_FLAGS_OR_MODE_UNSUPPORTED')
        pos+=62;end=data.find(b'\0',pos,len(data)-20);need(end>=0,'INDEX_TRUNCATED')
        path=data[pos:end];validate_path(path)
        path_total+=len(path);need(path_total<=MAX_TOTAL_PATH_BYTES,'INDEX_PATH_BUDGET')
        need((flags & 0xfff)==min(len(path),0xfff) and (previous is None or previous<path),'INDEX_PATH_OR_ORDER')
        previous=path;pos=start+((end+1-start+7)//8)*8
        need(pos<=len(data)-20 and not any(data[end+1:pos]),'INDEX_PADDING')
        result[path]=(format(mode,'06o'),oid)
    # Only the exact root cache-tree invalidation is admitted. Any other
    # extension, duplicate, payload, or trailing byte remains unsupported.
    # The index checksum above covers both its framing and payload.
    tail=data[pos:-20]
    if not tail:
        index_format='SHA1_V2_NO_EXTENSIONS'
    else:
        need(len(tail)>=8,'INDEX_EXTENSION_TRUNCATED')
        signature=tail[:4]; size=struct.unpack_from('!I',tail,4)[0]
        need(signature==b'TREE','INDEX_EXTENSION_UNSUPPORTED')
        need(size<=len(tail)-8,'INDEX_EXTENSION_TRUNCATED')
        need(size==len(tail)-8,'INDEX_EXTENSION_UNSUPPORTED')
        need(tail[8:]==b'\0-1 0\n','INDEX_TREE_UNSUPPORTED')
        index_format='SHA1_V2_TREE_INVALID_ROOT_ONLY'
    return result,index_format


def _resource_preflight(expected):
    # Unexpected directories are rejected before open by scan_worktree, so
    # recursion can only enter directory prefixes in this declaration.
    try:
        soft,_hard=resource.getrlimit(resource.RLIMIT_NOFILE)
        count=0
        with os.scandir('/proc/self/fd') as stream:
            for _ in stream:
                count+=1;need(count<=MAX_OPEN_FDS,'FD_INVENTORY_LIMIT')
    except OracleError:raise
    except (OSError,ValueError) as exc:raise OracleError('FD_INVENTORY_UNAVAILABLE') from exc
    max_components=max((len(path.split(b'/')) for path in expected),default=0)
    # HEAD resolution uses up to MAX_REF_COMPONENTS plus refs/heads and
    # Git root descriptors. Worktree scan opens only declared prefixes.
    required_extra=max(4,max_components+1,MAX_REF_COMPONENTS+4)+FD_RESERVE
    need(soft==resource.RLIM_INFINITY or (type(soft) is int and soft>=0 and
         count+required_extra<=soft),'FD_BUDGET')
    return {'observed_open_fds_including_scan':count,'max_worktree_components':max_components,
            'reserved_fds':FD_RESERVE,'soft_nofile':None if soft==resource.RLIM_INFINITY else soft,
            'dynamic_limits_and_concurrent_fds':'UNVERIFIED'}


def _bounded_readlink(parentfd, name):
    # Fixed-size readlinkat buffer; a return filling all 4096 bytes is
    # rejected, never interpreted as an untruncated value. The 4095 limit is
    # an input budget, not a discovered filesystem limit.
    libc=ctypes.CDLL(None,use_errno=True);fn=getattr(libc,'readlinkat',None)
    if fn is None:raise OracleError('READLINKAT_UNAVAILABLE')
    fn.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t)
    fn.restype=ctypes.c_ssize_t
    buf=ctypes.create_string_buffer(MAX_SYMLINK_BYTES+1)
    amount=fn(parentfd,name,ctypes.addressof(buf),len(buf))
    if amount<0:
        error=ctypes.get_errno();raise OSError(error,os.strerror(error))
    need(0<amount<=MAX_SYMLINK_BYTES,'SYMLINK_TARGET_LIMIT')
    raw=buf.raw[:amount];need(b'\0' not in raw,'SYMLINK_INVALID')
    return raw


def _expected_directories(expected):
    dirs=set();total_bytes=0
    for path in expected:
        prefix=b''
        for component in path.split(b'/')[:-1]:
            prefix=component if not prefix else prefix+b'/'+component
            if prefix in dirs:continue
            need(len(dirs)<MAX_DERIVED_DIRS and total_bytes+len(prefix)<=MAX_DERIVED_DIR_BYTES,
                 'DERIVED_DIRECTORY_BUDGET')
            dirs.add(prefix);total_bytes+=len(prefix)
    return dirs, total_bytes


def scan_worktree(rootfd, rootdev, expected, expected_dirs, ledger):
    entries={};dirs=set();total=[0];count=[0]
    def visit(fd,prefix,depth):
        need(depth<=MAX_DEPTH,'WORKTREE_DEPTH');before=sig(os.fstat(fd));names=[]
        with os.scandir(fd) as stream:
            for ent in stream:
                count[0]+=1;need(count[0]<=MAX_TREE_ENTRIES,'WORKTREE_ENTRY_LIMIT');names.append(os.fsencode(ent.name))
        need(len(names)==len(set(names)),'WORKTREE_DUPLICATE')
        for name in sorted(names):
            if not prefix and name==b'.git': continue
            path=prefix+name;validate_path(path);st=os.stat(name,dir_fd=fd,follow_symlinks=False)
            need(st.st_dev==rootdev,'WORKTREE_MOUNT_UNSUPPORTED')
            if stat.S_ISDIR(st.st_mode):
                need(path in expected_dirs,'WORKTREE_DIRECTORY_MISMATCH')
                dirs.add(path)
                with OwnedFD(open_dir(fd,name,rootdev,ledger,expected=st),ledger,'WORKTREE_DIRECTORY') as child:
                    visit(child,path+b'/',depth+1)
                    need(sig(os.fstat(child))==sig(st) and
                         sig(os.stat(name,dir_fd=fd,follow_symlinks=False))==sig(st),'WORKTREE_CHANGED')
            elif stat.S_ISREG(st.st_mode):
                need(path in expected,'WORKTREE_MISMATCH')
                raw=read_file(fd,name,rootdev,MAX_BLOB,ledger,expected=st);mode='100755' if st.st_mode & 0o100 else '100644'
                total[0]+=len(raw);need(total[0]<=MAX_TOTAL,'WORKTREE_CONTENT_LIMIT')
                entries[path]=('file',mode,raw)
            elif stat.S_ISLNK(st.st_mode):
                need(path in expected,'WORKTREE_MISMATCH')
                need(st.st_nlink==1,'WORKTREE_LINK_UNSUPPORTED');raw=_bounded_readlink(fd,name)
                need(type(raw) is bytes and sig(os.stat(name,dir_fd=fd,follow_symlinks=False))==sig(st),'WORKTREE_CHANGED')
                total[0]+=len(raw);need(total[0]<=MAX_TOTAL,'WORKTREE_CONTENT_LIMIT')
                entries[path]=('symlink','120000',raw)
            else:raise OracleError('WORKTREE_TYPE_UNSUPPORTED')
        need(sig(os.fstat(fd))==before,'WORKTREE_CHANGED')
    visit(rootfd,b'',0)
    return entries,dirs,total[0]


def _review_inner(rootfd, manifest, manifest_sha256, blobs, ledger):
        maps=load_declaration(manifest,manifest_sha256,blobs)
        expected={p:(v[0],v[1],v[2]) for p,v in {**maps['tracked_worktree'],**maps['untracked']}.items()}
        expected_dirs,derived_dir_bytes=_expected_directories(expected)
        fd_budget=_resource_preflight(expected)
        root=os.fstat(rootfd);need(stat.S_ISDIR(root.st_mode),'ROOT_INVALID');rootdev=root.st_dev
        with OwnedFD(open_dir(rootfd,b'.git',rootdev,ledger),ledger,'GIT_DIRECTORY') as gitfd:
            need(absent(gitfd,b'commondir') and absent(gitfd,b'shallow'),'GIT_LAYOUT_UNSUPPORTED')
            head=read_head(gitfd,rootdev,ledger);need(head==manifest['head_commit_claim'],'HEAD_MISMATCH')
            with OwnedFD(open_dir(gitfd,b'objects',rootdev,ledger),ledger,'OBJECTS_DIRECTORY') as objectsfd:
                check_object_layout(objectsfd,rootdev,ledger);cache={'objects':{},'compressed':0,'decoded':0}
                kind,commit=read_object(objectsfd,head,rootdev,cache,ledger);need(kind==b'commit','COMMIT_TYPE')
                header,sep,_=commit.partition(b'\n\n');lines=header.split(b'\n')
                need(bool(sep) and lines and re.fullmatch(b'tree [0-9a-f]{40}',lines[0]) is not None and
                     not any(line.startswith(b'tree ') for line in lines[1:]),'COMMIT_HEADER_UNSUPPORTED')
                actual_head=parse_tree(objectsfd,rootdev,lines[0][5:].decode('ascii'),cache,ledger)
                expected_head={p:(entry[1],entry[3]) for p,entry in maps['head'].items()}
                need(actual_head==expected_head,'HEAD_TREE_MISMATCH')
                index,index_format=parse_index(read_file(gitfd,b'index',rootdev,MAX_INDEX,ledger))
                expected_index={p:(entry[1],entry[3]) for p,entry in maps['index'].items()}
                need(index==expected_index,'INDEX_MISMATCH')
                for entries in (maps['head'],maps['index']):
                    for _path,entry in sorted(entries.items()):
                        kind,raw=read_object(objectsfd,entry[3],rootdev,cache,ledger)
                        need(kind==b'blob' and raw==entry[2],'GIT_BLOB_MISMATCH')
        work,dirs,work_bytes=scan_worktree(rootfd,rootdev,expected,expected_dirs,ledger)
        need(work==expected,'WORKTREE_MISMATCH')
        need(dirs==expected_dirs,'WORKTREE_DIRECTORY_MISMATCH')
        need(sig(os.fstat(rootfd))==sig(root),'ROOT_CHANGED')
        return {'status':'OBSERVED_RESEARCH_ONLY','qualification':'NOT_RUN','product_gate_effect':'NONE',
                'manifest_sha256':manifest_sha256,'head_oid':head,'head_rows':len(maps['head']),
                'index_rows':len(index),'worktree_rows':len(work),'untracked_rows':len(maps['untracked']),
                'worktree_bytes':work_bytes,'git_objects_read':len(cache['objects']),'index_format':index_format,
                'git_ignore_classification':'NOT_MEASURED','git_effective_config':'NOT_MEASURED',
                'index_stat_cache':'NOT_MEASURED','object_store_inventory':'NOT_MEASURED',
                'git_replace_refs':'NOT_MEASURED',
                'history_completeness':'NOT_MEASURED','source_authentication':'UNVERIFIED',
                'coverage_authority':'CALLER_UNVERIFIED','exclusion_coverage':'UNVERIFIED' if manifest['coverage_claims']['exclusions'] else 'UNKNOWN',
                'snapshot_atomicity':'UNKNOWN',
                'continuous_immutability':'UNKNOWN','principal_lease':'UNVERIFIED',
                'process_tree':'NOT_MEASURED','fd_preflight':fd_budget,
                'derived_directory_count':len(expected_dirs),'derived_directory_bytes':derived_dir_bytes}


def review(rootfd, manifest, manifest_sha256, blobs):
    """Review restricted target; no source/lease/atomicity or Git Gate claim.

    All explicit FD owners share one bounded close ledger. Ordinary body errors
    are preserved; asynchronous interruptions outrank ordinary close errors.
    Async acquisition/bookkeeping gaps remain UNKNOWN and are not retried.
    """
    ledger=CloseLedger()
    try:
        result=_review_inner(rootfd,manifest,manifest_sha256,blobs,ledger)
    except BaseException as primary:
        outcomes=tuple(ledger.events)
        unknown=any(event['state']=='UNKNOWN' for event in outcomes)
        if not isinstance(primary,Exception):
            primary.oracle_close_outcomes=outcomes
            primary.oracle_ledger_incomplete=ledger.incomplete
            primary.oracle_unregistered_fd_state='UNKNOWN_ON_ASYNC_INTERRUPTION'
            raise
        if unknown or ledger.incomplete:
            error=OracleError('FD_CLOSE_UNKNOWN' if unknown else 'FD_LEDGER_INCOMPLETE')
            error.close_outcomes=outcomes;error.oracle_primary_error=primary
            error.oracle_ledger_incomplete=ledger.incomplete
            raise error from primary
        if isinstance(primary,OracleError):
            primary.close_outcomes=outcomes;raise
        if isinstance(primary,(OSError,ValueError,UnicodeError,OverflowError,struct.error)):
            error=OracleError('OBSERVATION_INCOMPLETE');error.close_outcomes=outcomes
            error.oracle_primary_error=primary;raise error from primary
        raise
    if ledger.incomplete or any(event['state']!='CLOSED' for event in ledger.events):
        error=OracleError('FD_LEDGER_INCOMPLETE' if ledger.incomplete else 'FD_CLOSE_UNKNOWN')
        error.close_outcomes=tuple(ledger.events);error.oracle_ledger_incomplete=ledger.incomplete
        raise error
    result['close_outcomes']=tuple(ledger.events)
    return result

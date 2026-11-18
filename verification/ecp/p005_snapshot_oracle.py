#!/usr/bin/env python3
"""Independently compare a Git-free P0-01 candidate with pinned Git objects.

This read-only oracle cannot authenticate the caller, principal, lease, build,
or product Gate. It accepts only clean, completely inventoried source and the
pre-registered exclusion policy; a successful observation is never a Gate.
"""
from __future__ import annotations
import argparse
import fcntl
from datetime import datetime
from collections import deque
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

# Independent, fixed copy of the P0-01 exclusion policy. Policy changes require
# explicit review of this oracle; caller-supplied extra omissions are rejected.
EXCLUDES = ('.git/', '.local/', '.env', 'target/', 'node_modules/', '**/node_modules/',
            'console/node_modules/', 'console/dist/', 'console/test-results/',
            'console/playwright-report/', '.pytest_cache/', 'evidence/', 'audit/',
            'benchmarks/evidence/', 'crates/executors/qualification/', 'crates/**/evidence/',
            'verification/evidence/', 'docs/idea/ForgeFlow_ECP_完整开发规划/evidence/',
            '*.log', '*.png', '*.tar.gz', '__pycache__/', '*/__pycache__/', '*.pyc')
# Independently registered v3 policy: extension alone does not classify source.
# The legacy EXCLUDES above remains fixed for v2 and its historical semantics.
V3_EXCLUDES = ('.git/', '.local/', '.env', 'target/', 'node_modules/',
               'console/node_modules/', 'console/dist/', 'console/test-results/',
               'console/playwright-report/', '.pytest_cache/', 'evidence/', 'audit/',
               'benchmarks/evidence/', 'crates/executors/qualification/',
               'verification/evidence/', 'docs/idea/ForgeFlow_ECP_完整开发规划/evidence/',
               '__pycache__/')
MAX_TREE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024 * 1024
SOURCE_SCAN_SECONDS = 180
MAX_BLOB_BYTES = 64 * 1024 * 1024
MAX_TREE_ENTRIES = 100_000
MAX_GIT_METADATA = 16 * 1024 * 1024
MAX_PHYSICAL_INDEX_BYTES = 16 * 1024 * 1024
MAX_SCAN_IDENTITY_BYTES = 64 * 1024 * 1024
SOURCE_FIELDS = frozenset({'schema_version', 'source_root', 'head', 'worktree_state',
    'exclude_patterns', 'untracked_scan_mode', 'untracked_scan_roots', 'tracked_changes',
    'untracked_business_files', 'excluded_generated_files', 'patch_sha256', 'manifest_sha256',
    'created_at', 'release_qualifiable', 'inventory_complete', 'inventory_error',
    'index_visibility_exceptions'})
V3_SCAN_ROOTS = ('ops/ecp/', 'verification/', 'contracts/ecp/', 'docs/ecp/',
                 '.github/workflows/', 'deploy/', 'console/', 'crates/', 'migrations/', 'benchmarks/ecp/')

class Invalid(ValueError):
    pass

class Indeterminate(RuntimeError):
    pass

class GitTerminationUnconfirmed(Indeterminate):
    """Bounded Git capture ended without verified leader/group termination."""
    def __init__(self, signal_status, leader_reaped, stdout, stderr, wait_error=None):
        super().__init__(f'Git process termination unconfirmed: signal={signal_status}, leader_reaped={leader_reaped}')
        self.signal_status = signal_status
        self.leader_reaped = leader_reaped
        self.descendants_terminated = None
        self.wait_error = wait_error
        # Retained as bounded raw evidence; never interpolate output in errors.
        self.stdout_bytes = bytes(stdout)
        self.stderr_bytes = bytes(stderr)

def require(value, message):
    if not value:
        raise Invalid(message)

def excludes(path, patterns=EXCLUDES):
    for pattern in patterns:
        if pattern.endswith('/'):
            parts = path.rstrip('/').split('/')
            if any(fnmatch.fnmatch('/'.join(parts[:end]), pattern[:-1]) for end in range(1, len(parts)+1)):
                return True
        if fnmatch.fnmatch(path, pattern):
            return True
    return False

def safe_path(value):
    require(isinstance(value, str) and value and '\\' not in value, 'unsafe source path')
    value.encode('utf-8', 'strict')
    parts = value.split('/')
    require(all(part not in ('', '.', '..') and not any(ord(c) < 32 for c in part) for part in parts), 'unsafe source path')
    require(not value.startswith('/'), 'absolute source path')
    return PurePosixPath(value)

def safe_link(path, target):
    require(isinstance(target, str) and target and not target.startswith('/') and '\\' not in target, 'unsafe symlink target')
    parts = list(path.parts[:-1])
    for part in target.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            require(bool(parts), 'symlink escapes candidate')
            parts.pop()
        else:
            require(not any(ord(c) < 32 for c in part), 'unsafe symlink target')
            parts.append(part)

def _v3_link_syntax(target):
    """Validate syntax only; graph traversal checks dynamic containment."""
    require(isinstance(target, str) and target and not target.startswith('/') and '\\' not in target,
            'unsafe symlink target')
    raw = target.encode('utf-8', 'strict')
    require(len(raw) <= 4096 and not any(ord(c) < 32 or ord(c) == 127 for c in target),
            'invalid symlink target bytes')


def open_directory(path):
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd);fd = child
        return path, fd
    except BaseException:
        os.close(fd)
        raise

def no_symlink_directory(path):
    path, fd = open_directory(path)
    os.close(fd)
    return path

def run_git(root, args, data=None, timeout=45, limit=MAX_GIT_METADATA):
    # No inherited GIT_* redirection, user/global config, fsmonitor or hooks.
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LC_ALL': 'C',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
           'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1'}
    command = ['/usr/bin/git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-C', str(root), *args]
    require(data is None or len(data) <= MAX_GIT_METADATA, 'Git input exceeds bounded oracle budget')
    with tempfile.TemporaryFile() as input_file:
        if data is not None:
            input_file.write(data);input_file.seek(0)
        proc = subprocess.Popen(command, stdin=input_file, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, start_new_session=True)
        output, error = bytearray(), bytearray()
        selector = None
        try:
            # Selector construction and both registrations must be inside the
            # cleanup region: the child already exists when these can fail.
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ, output)
            selector.register(proc.stderr, selectors.EVENT_READ, error)
            deadline = time.monotonic()+timeout
            while selector.get_map():
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command,timeout)
                for key,_ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        key.data.extend(chunk)
                        require(len(output) <= limit and len(error) <= 1024*1024, 'Git output exceeds bounded oracle budget')
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command,timeout)
            code = proc.wait(timeout=remaining)
        except BaseException as original:
            # Once wait/poll has reaped the leader, its PID/PGID may be reused.
            # Never signal that number again; escaped or lingering descendants
            # remain UNKNOWN. This assumes no external reaper of our Popen child.
            leader_reaped = proc.returncode is not None
            signal_status = 'NOT_SENT_LEADER_REAPED' if leader_reaped else 'SENT'
            wait_error = None
            if not leader_reaped:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    signal_status = 'NO_SUCH_GROUP'
                except BaseException:
                    signal_status = 'FAILED'
                try:
                    proc.wait(timeout=3)
                    leader_reaped = True
                except BaseException as exc:
                    wait_error = type(exc).__name__
            if signal_status in ('FAILED','NOT_SENT_LEADER_REAPED') or not leader_reaped:
                raise GitTerminationUnconfirmed(signal_status,leader_reaped,output,error,wait_error) from original
            raise
        finally:
            # Attempt each close even if a previous close fails; never hide an
            # unconfirmed termination behind a later cleanup exception.
            active_error = sys.exc_info()[1]
            close_errors = []
            for resource in (selector, proc.stdout, proc.stderr):
                if resource is not None:
                    try: resource.close()
                    except Exception as exc: close_errors.append(type(exc).__name__)
            if close_errors:
                note = 'Git capture descriptor cleanup failed: ' + ','.join(close_errors)
                if active_error is not None:
                    if hasattr(active_error,'add_note'): active_error.add_note(note)
                else:
                    raise Indeterminate(note)
    if code:
        raise OSError('Git inspection failed with exit code ' + str(code))
    return bytes(output)

def object_tree(root, sha, patterns=EXCLUDES):
    fmt = run_git(root, ['rev-parse', '--show-object-format']).decode('ascii').strip()
    require(fmt in ('sha1', 'sha256'), 'unsupported Git object format')
    oid_length = 40 if fmt == 'sha1' else 64
    require(re.fullmatch('[0-9a-f]{%d}' % oid_length, sha) is not None, 'source SHA format mismatch')
    raw = run_git(root, ['ls-tree', '-rz', '--full-tree', sha])
    entries = {}
    require(raw.endswith(b'\0') and raw.count(b'\0') <= MAX_TREE_ENTRIES,
            'Git tree exceeds bounded entry count or has invalid termination')
    raw_entries = raw.split(b'\0')
    for item in raw_entries:
        if not item:
            continue
        metadata, name = item.split(b'\t', 1)
        mode, kind, oid = metadata.decode('ascii').split(' ')
        path = name.decode('utf-8', 'strict')
        safe_path(path)
        if tuple(patterns) == V3_EXCLUDES:
            require(mode != '120000' or path != '.env', 'excluded symlink boundary')
            if _v3_exclusion(path):
                continue
            require(mode != '120000' or not _v3_exclusion(path + '/'), 'excluded symlink boundary')
        elif excludes(path, patterns):
            continue
        require(mode in ('100644', '100755', '120000') and kind == 'blob', 'unsupported Git tree entry')
        require(re.fullmatch('[0-9a-f]{%d}' % oid_length, oid) is not None and path not in entries, 'invalid or duplicate Git tree entry')
        entries[path] = (mode, oid)
    require(entries, 'Git tree has no included files')
    oids = list(dict.fromkeys(oid for _, oid in entries.values()))
    request = ''.join(oid + '\n' for oid in oids).encode('ascii')
    sizes = run_git(root, ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'], request).splitlines()
    require(len(sizes) == len(oids), 'incomplete Git object size output')
    size_by_oid = {}
    for oid, line in zip(oids, sizes):
        fields = line.decode('ascii').split(' ')
        require(len(fields) == 3 and fields[0] == oid and fields[1] == 'blob' and fields[2].isdigit(), 'invalid Git object size')
        size = int(fields[2]);size_by_oid[oid] = size
        require(size <= MAX_BLOB_BYTES, 'Git object size exceeds bounded oracle budget')
    # The same blob can appear at many paths. Bound bytes read from the actual
    # candidate, not merely bytes of unique Git objects.
    require(sum(size_by_oid[oid] for _,oid in entries.values()) <= MAX_TREE_BYTES,
            'Git tree path bytes exceed bounded oracle budget')
    stream = run_git(root, ['cat-file', '--batch'], request, timeout=120,
                     limit=MAX_TREE_BYTES + len(oids)*96)
    index = 0
    blobs = {}
    for oid in oids:
        end = stream.find(b'\n', index)
        require(end >= 0, 'truncated Git object header')
        header = stream[index:end].decode('ascii').split(' ')
        require(len(header) == 3 and header[0] == oid and header[1] == 'blob' and header[2].isdigit(), 'invalid Git object header')
        size = int(header[2]); index = end+1
        require(size <= MAX_BLOB_BYTES and index + size < len(stream), 'truncated Git object')
        payload = stream[index:index+size]; index += size
        require(stream[index:index+1] == b'\n', 'missing Git object separator'); index += 1
        digest = hashlib.new(fmt, b'blob ' + str(size).encode('ascii') + b'\0' + payload).hexdigest()
        require(digest == oid, 'Git object content does not match object identity')
        blobs[oid] = payload
    require(index == len(stream), 'unexpected trailing Git object data')
    return entries, blobs, fmt

def git_source_index(root, sha):
    actual_root = run_git(root, ['rev-parse', '--show-toplevel']).decode('utf-8', 'strict').strip()
    require(os.path.abspath(actual_root) == str(root), 'source is not a Git worktree root')
    require(run_git(root, ['rev-parse', '--verify', 'HEAD^{commit}']).decode('ascii').strip() == sha, 'source HEAD changed')
    fmt = run_git(root, ['rev-parse', '--show-object-format']).decode('ascii').strip()
    require(fmt in ('sha1', 'sha256'), 'unsupported Git object format')
    oid_length = 40 if fmt == 'sha1' else 64
    flags = run_git(root, ['ls-files', '-v', '-z', '--cached'])
    require(flags.endswith(b'\0') and flags.count(b'\0') <= MAX_TREE_ENTRIES,
            'source index visibility is malformed or too large')
    require(all(not item or item.startswith(b'H ') for item in flags.split(b'\0')), 'source index contains hidden or unsupported flags')
    raw_index = run_git(root, ['ls-files', '--stage', '-z'])
    require(raw_index.endswith(b'\0') and raw_index.count(b'\0') <= MAX_TREE_ENTRIES, 'source index is malformed or too large')
    indexed = {}
    for item in raw_index.split(b'\0'):
        if not item: continue
        metadata, name = item.split(b'\t', 1)
        mode, oid, stage = metadata.decode('ascii').split(' ')
        path = name.decode('utf-8', 'strict');safe_path(path)
        require(stage == '0' and mode in ('100644', '100755', '120000') and
                re.fullmatch('[0-9a-f]{%d}' % oid_length, oid) is not None and path not in indexed,
                'source index has unmerged, unsupported or duplicate entries')
        indexed[path] = (mode, oid)
    flag_paths = [item[2:].decode('utf-8', 'strict') for item in flags.split(b'\0') if item]
    require(len(flag_paths) == len(indexed) and set(flag_paths) == set(indexed),
            'source index visibility listing is incomplete or ambiguous')
    raw_tree = run_git(root, ['ls-tree', '-rz', '--full-tree', sha])
    require(raw_tree.endswith(b'\0') and raw_tree.count(b'\0') <= MAX_TREE_ENTRIES, 'source Git tree is malformed or too large')
    committed = {}
    for item in raw_tree.split(b'\0'):
        if not item: continue
        metadata, name = item.split(b'\t', 1)
        mode, kind, oid = metadata.decode('ascii').split(' ')
        path = name.decode('utf-8', 'strict');safe_path(path)
        require(kind == 'blob' and mode in ('100644','100755','120000') and
                re.fullmatch('[0-9a-f]{%d}' % oid_length, oid) is not None and path not in committed,
                'source Git tree has unsupported or duplicate entries')
        committed[path] = (mode, oid)
    require(indexed and indexed == committed, 'source index differs from Git HEAD')
    return indexed, fmt, raw_index, flags

def tracked_sizes(root, entries):
    oids = list(dict.fromkeys(oid for _,oid in entries.values()))
    request = ''.join(oid+'\n' for oid in oids).encode('ascii')
    lines = run_git(root, ['cat-file','--batch-check=%(objectname) %(objecttype) %(objectsize)'], request).splitlines()
    require(len(lines) == len(oids), 'source blob size listing incomplete')
    sizes = {}
    for oid,line in zip(oids,lines):
        fields=line.decode('ascii').split(' ')
        require(len(fields)==3 and fields[0]==oid and fields[1]=='blob' and fields[2].isdigit(), 'invalid source blob size')
        sizes[oid]=int(fields[2])
    total=sum(sizes[oid] for _,oid in entries.values())
    require(total <= MAX_SOURCE_BYTES, 'source tracked bytes exceed 512 MiB budget')
    return sizes,total

def source_mode_availability(root):
    # DrvFS/9p and unknown filesystems do not provide trustworthy POSIX
    # executable mode. Do not equate their emulated st_mode with Git mode.
    best = ('', '')
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, separator, right = line.partition(' - ')
        if not separator: continue
        fields=left.split(); after=right.split()
        if len(fields)<5 or not after: continue
        mount=re.sub(r'\\([0-7]{3})', lambda m:chr(int(m.group(1),8)), fields[4])
        if (str(root)==mount or str(root).startswith(mount.rstrip('/')+'/')) and len(mount)>len(best[0]):
            best=(mount,after[0])
    if best[1] in ('ext2','ext3','ext4','xfs','btrfs','tmpfs','overlay','zfs'):
        return 'VERIFIED',best[1]
    return 'UNAVAILABLE',best[1] or 'unknown'

def path_signature(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

def open_parent(root_fd, path):
    parts=path.split('/');fd=os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        return fd,parts[-1]
    except BaseException:
        os.close(fd);raise


def _bounded_directory_events(root_fd, descend, deadline):
    """Stream directory entries through root-anchored, no-follow FDs.

    Unlike fwalk, this never first collects an entire directory into a list.
    Directory identities and traversal memory are bounded and checked again.
    """
    initial = path_signature(os.fstat(root_fd)); pending = [('.', initial)]
    visited = 0; identity_bytes = 0; directory_count = 0
    while pending:
        relative, expected = pending.pop()
        if time.monotonic() > deadline:
            raise Indeterminate('source or candidate directory scan time budget exceeded')
        fd = os.dup(root_fd)
        try:
            if relative != '.':
                for part in relative.split('/'):
                    child = os.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd); fd = child
            before = os.fstat(fd)
            require(stat.S_ISDIR(before.st_mode) and path_signature(before) == expected,
                    'directory changed before opening')
            directory_count += 1
            require(directory_count <= MAX_TREE_ENTRIES, 'directory count exceeds budget')
            yield 'begin', relative, None, before, fd
            with os.scandir(fd) as entries:
                for item in entries:
                    visited += 1
                    require(visited <= MAX_TREE_ENTRIES * 4, 'filesystem entry count exceeds budget')
                    if time.monotonic() > deadline:
                        raise Indeterminate('source or candidate directory scan time budget exceeded')
                    path = item.name if relative == '.' else relative + '/' + item.name
                    path.encode('utf-8', 'strict')
                    identity_bytes += len(path.encode('utf-8')) + 256
                    require(identity_bytes <= MAX_SCAN_IDENTITY_BYTES, 'filesystem identity budget exceeded')
                    info = os.stat(item.name, dir_fd=fd, follow_symlinks=False)
                    yield 'entry', path, item.name, info, fd
                    if stat.S_ISDIR(info.st_mode) and descend(path, info):
                        pending.append((path, path_signature(info)))
            after = os.fstat(fd)
            require(path_signature(after) == expected, 'directory changed during scan')
            yield 'end', relative, None, after, fd
        finally:
            os.close(fd)

def source_untracked(root_fd, tracked, deadline, patterns=EXCLUDES):
    tracked_dirs={PurePosixPath(path).parents[i].as_posix() for path in tracked
                  for i in range(len(PurePosixPath(path).parents))} - {'.'}
    untracked_dirs=[]
    v3 = tuple(patterns) == V3_EXCLUDES
    def directory_excluded(path):
        return bool(_v3_exclusion(path + '/')) if v3 else excludes(path + '/', patterns)
    for event,rel,_,info,_ in _bounded_directory_events(root_fd,lambda path, _:not directory_excluded(path),deadline):
        if event != 'entry':continue
        if v3:
            if stat.S_ISLNK(info.st_mode):
                require(rel != '.env' and not directory_excluded(rel), 'excluded symlink boundary')
            elif stat.S_ISREG(info.st_mode):
                if rel in ('.git', '.env'):
                    continue
            elif not stat.S_ISDIR(info.st_mode):
                raise Invalid('unsupported source entry type')
        if stat.S_ISDIR(info.st_mode):
            if not directory_excluded(rel):
                safe_path(rel)
                if rel not in tracked_dirs:untracked_dirs.append(rel)
        elif not (_v3_exclusion(rel) if v3 else excludes(rel, patterns)):
            safe_path(rel);require(rel in tracked,'untracked source file')
    return sorted(untracked_dirs)

def source_clean_begin(root, sha, patterns=EXCLUDES):
    entries,fmt,raw_index,flags=git_source_index(root,sha)
    # A tracked private file is not eligible for v3 observation.  Do not read
    # its worktree bytes or ask Git to retrieve its blob; v2 remains unchanged.
    if tuple(patterns) == V3_EXCLUDES and '.env' in entries:
        raise Invalid('tracked private .env cannot be independently observed')
    sizes,total=tracked_sizes(root,entries) # budget checked before opening any tracked file
    mode_status,fs_type=source_mode_availability(root)
    deadline=time.monotonic()+SOURCE_SCAN_SECONDS
    _,root_fd=open_directory(root)
    signatures={};observed=0
    try:
        untracked_dirs=source_untracked(root_fd,entries,deadline,patterns)
        for path,(mode,oid) in sorted(entries.items()):
            if time.monotonic()>deadline:raise Indeterminate('source tracked scan time budget exceeded')
            parent,name=open_parent(root_fd,path)
            try:
                before=os.stat(name,dir_fd=parent,follow_symlinks=False)
                size=sizes[oid]
                if mode=='120000':
                    require(stat.S_ISLNK(before.st_mode),'source tracked file type mismatch')
                    target=os.readlink(name,dir_fd=parent)
                    if tuple(patterns) == V3_EXCLUDES:
                        _v3_link_syntax(target)
                    else:
                        safe_link(PurePosixPath(path),target)
                    raw=os.fsencode(target)
                    require(len(raw)==size,'source symlink size mismatch')
                    digest=hashlib.new(fmt,b'blob '+str(size).encode('ascii')+b'\0'+raw).hexdigest()
                    after=os.stat(name,dir_fd=parent,follow_symlinks=False)
                    observed+=len(raw)
                else:
                    require(stat.S_ISREG(before.st_mode) and before.st_size==size,'source tracked file type or size mismatch')
                    if mode_status=='VERIFIED':
                        require(bool(before.st_mode & 0o111)==(mode=='100755'),'source executable mode differs from Git')
                    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                    try:
                        opened=os.fstat(fd);require(path_signature(opened)==path_signature(before),'source changed before open')
                        h=hashlib.new(fmt,b'blob '+str(size).encode('ascii')+b'\0');read=0
                        while read < size:
                            chunk=os.read(fd,min(1024*1024,size-read))
                            if not chunk:break
                            read+=len(chunk);observed+=len(chunk)
                            require(read<=size and observed<=MAX_SOURCE_BYTES,'source read exceeds declared budget')
                            h.update(chunk)
                        require(read==size,'source file size changed during read')
                        digest=h.hexdigest();after=os.fstat(fd)
                    finally:os.close(fd)
                require(path_signature(before)==path_signature(after),'source changed during read')
                if digest != oid:raise Indeterminate('raw source bytes differ from Git; possible filter, newline conversion or modification')
                signatures[path]=path_signature(after)
            finally:os.close(parent)
        require(observed==total,'source read denominator differs from Git object sizes')
        return {'entries':entries,'format':fmt,'index':raw_index,'flags':flags,'signatures':signatures,
                'source_tracked_bytes':observed,'source_tracked_count':len(entries),
                'source_execution_mode':mode_status,'source_filesystem_type':fs_type,
                'source_untracked_directories':untracked_dirs,
                'exclusion_patterns':tuple(patterns), 'source_scan_deadline':deadline}
    finally:os.close(root_fd)

def source_clean_end(root, sha, state, patterns=EXCLUDES):
    require(state.get('exclusion_patterns') == tuple(patterns), 'source exclusion policy changed')
    entries,fmt,index,flags=git_source_index(root,sha)
    require(entries==state['entries'] and fmt==state['format'] and index==state['index'] and flags==state['flags'],
            'source Git index changed during verification')
    _,root_fd=open_directory(root)
    try:
        require(source_untracked(root_fd,entries,state['source_scan_deadline'],patterns) == state['source_untracked_directories'],
                'source untracked directories changed during verification')
        for path in sorted(entries):
            if time.monotonic()>state['source_scan_deadline']:raise Indeterminate('source recheck time budget exceeded')
            parent,name=open_parent(root_fd,path)
            try:
                current=os.stat(name,dir_fd=parent,follow_symlinks=False)
                require(path_signature(current)==state['signatures'][path],'source changed after content read')
            finally:os.close(parent)
    finally:os.close(root_fd)
    entries,fmt,index,flags=git_source_index(root,sha)
    require(entries==state['entries'] and fmt==state['format'] and index==state['index'] and flags==state['flags'],
            'source Git index changed during final recheck')

def candidate_inventory(root, expected, blobs):
    expected_dirs = {PurePosixPath(path).parents[i].as_posix() for path in expected
                     for i in range(len(PurePosixPath(path).parents))} - {'.'}
    def walk_error(exc):
        raise exc
    _, root_fd = open_directory(root)
    try:
        return _candidate_inventory_fds(root_fd, expected, blobs, expected_dirs, walk_error)
    finally:
        os.close(root_fd)

def _candidate_inventory_fds(root_fd, expected, blobs, expected_dirs, walk_error):
    entries = []
    found = set()
    total_bytes = 0
    for directory, dirs, files, dir_fd in os.fwalk('.', topdown=True, follow_symlinks=False,
                                                   onerror=walk_error, dir_fd=root_fd):
        base = PurePosixPath(directory)
        keep = []
        for name in dirs:
            child = base/name
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                files.append(name)
            else:
                require(child.as_posix() in expected_dirs, 'candidate contains unexpected directory')
                keep.append(name)
        dirs[:] = keep
        for name in files:
            path = base/name; rel = path.as_posix(); safe_path(rel)
            require(rel in expected and rel not in found, 'candidate contains unexpected file')
            found.add(rel)
            mode, oid = expected[rel]; payload = blobs[oid]
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            record = {'path': rel, 'mode': f'{stat.S_IMODE(info.st_mode):04o}'}
            if stat.S_ISLNK(info.st_mode):
                require(mode == '120000', 'candidate type mismatch')
                target = os.readlink(name, dir_fd=dir_fd); safe_link(PurePosixPath(rel), target)
                value = os.fsencode(target)
                require(value == payload, 'candidate symlink target differs from Git')
                record.update(kind='symlink', target=target, sha256=hashlib.sha256(value).hexdigest())
            else:
                require(stat.S_ISREG(info.st_mode) and mode in ('100644', '100755'), 'candidate type mismatch')
                require(bool(info.st_mode & 0o111) == (mode == '100755'), 'candidate executable mode differs from Git')
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
                try:
                    before = os.fstat(fd)
                    require(stat.S_ISREG(before.st_mode) and before.st_size == len(payload), 'candidate size mismatch')
                    digest = hashlib.sha256()
                    read = 0
                    while read < len(payload):
                        chunk = os.read(fd, min(1024*1024, len(payload)-read))
                        if not chunk: break
                        read += len(chunk)
                        digest.update(chunk)
                    require(read == len(payload), 'candidate file size changed during read')
                    after = os.fstat(fd)
                    require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
                            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns), 'candidate changed during read')
                finally:
                    os.close(fd)
                require(digest.digest() == hashlib.sha256(payload).digest(), 'candidate bytes differ from Git')
                total_bytes += len(payload)
                record.update(kind='file', sha256=digest.hexdigest())
            entries.append(record)
    require(found == set(expected), 'candidate is missing Git files')
    entries.sort(key=lambda e:e['path'])
    encoded = json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return {'candidate_inventory_sha256': hashlib.sha256(encoded).hexdigest(),
            'candidate_file_count': len(entries), 'candidate_tree_bytes': total_bytes}

def _parse_unique_json(data):
    def pairs(values):
        out={}
        for key,value in values:
            require(key not in out, 'duplicate JSON key');out[key]=value
        return out
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Invalid('non-finite JSON value')))
    except RecursionError as exc:
        raise Invalid('JSON nesting exceeds parser limit') from exc


def load_unique(path, limit=4*1024*1024):
    path = Path(os.path.abspath(path))
    _, parent_fd = open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'JSON input must be a regular file')
        data = b''
        while len(data) <= limit:
            chunk = os.read(fd, min(1024*1024, limit+1-len(data)))
            if not chunk: break
            data += chunk
        after = os.fstat(fd)
        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns), 'JSON input changed during read')
    finally:
        os.close(fd)
    require(len(data)<=limit, 'JSON input too large')
    return _parse_unique_json(data)


def _load_unique_fd_identity(fd, limit=4*1024*1024):
    """Read pinned evidence and its identity without changing the caller's offset."""
    require(type(fd) is int and fd >= 3 and type(limit) is int and limit > 0, 'invalid evidence file descriptor')
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    require(flags & os.O_ACCMODE == os.O_RDONLY and not flags & getattr(os, 'O_PATH', 0),
            'evidence file descriptor must be readable and read-only')
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'evidence descriptor must be a singly linked regular file')
    require(before.st_size <= limit, 'JSON input too large')
    data = bytearray();offset = 0
    while offset < before.st_size:
        chunk = os.pread(fd, min(1024*1024, before.st_size-offset), offset)
        if not chunk:break
        data.extend(chunk);offset += len(chunk)
    after = os.fstat(fd)
    keys = ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    require(offset == before.st_size and all(getattr(before,key) == getattr(after,key) for key in keys),
            'JSON input changed during read')
    return _parse_unique_json(bytes(data)), {
        'signature': [getattr(after, key) for key in keys],
        'sha256': hashlib.sha256(data).hexdigest(),
    }


def load_unique_fd(fd, limit=4*1024*1024):
    """Read a pinned read-only evidence file without changing the caller's offset."""
    return _load_unique_fd_identity(fd, limit)[0]

def review(source, candidate, manifest_path, receipt_path, source_sha, pinned_digest):
    source, candidate = no_symlink_directory(source), no_symlink_directory(candidate)
    require(source != candidate and source not in candidate.parents and candidate not in source.parents, 'source and candidate overlap')
    require(isinstance(source_sha, str) and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', source_sha) is not None, 'invalid source SHA')
    require(isinstance(pinned_digest, str) and re.fullmatch(r'[0-9a-f]{64}', pinned_digest) is not None, 'invalid pinned manifest digest')
    manifest = load_unique(manifest_path); receipt = load_unique(receipt_path)
    require(isinstance(manifest, dict) and isinstance(receipt, dict), 'invalid input JSON')
    require(set(manifest) == SOURCE_FIELDS, 'source manifest has missing or unknown fields')
    require(manifest.get('schema_version') == 'forgeflow.ecp-source-manifest.v2', 'wrong manifest schema')
    canonical = {k:v for k,v in manifest.items() if k not in ('manifest_sha256','created_at','release_qualifiable')}
    calculated = hashlib.sha256(json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    require(calculated == pinned_digest == manifest.get('manifest_sha256'), 'source manifest digest mismatch')
    require(manifest.get('source_root') == str(source) and manifest.get('head') == source_sha, 'manifest source mismatch')
    require(manifest.get('worktree_state') == 'CLEAN' and manifest.get('inventory_complete') is True and manifest.get('release_qualifiable') is True, 'source manifest not clean and complete')
    require(manifest.get('inventory_error') is None and type(manifest.get('index_visibility_exceptions')) is list
            and not manifest['index_visibility_exceptions'], 'source inventory metadata is contradictory')
    require(manifest.get('untracked_scan_mode') in ('all', 'bounded')
            and type(manifest.get('untracked_scan_roots')) is list
            and all(isinstance(item, str) for item in manifest['untracked_scan_roots']), 'invalid scan settings')
    require(manifest.get('patch_sha256') == hashlib.sha256(b'').hexdigest(), 'clean source has nonempty patch')
    stamp = manifest.get('created_at')
    require(isinstance(stamp, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})', stamp) is not None,
            'invalid source manifest timestamp')
    try:
        require(datetime.fromisoformat(stamp.replace('Z', '+00:00')).utcoffset() is not None,
                'source manifest timestamp must include a timezone')
    except ValueError as exc:
        raise Invalid('invalid source manifest timestamp') from exc
    require(manifest.get('exclude_patterns') == list(EXCLUDES), 'unregistered source exclusion policy')
    require(manifest.get('tracked_changes') == [] and type(manifest.get('tracked_changes')) is list
            and manifest.get('untracked_business_files') == [] and type(manifest.get('untracked_business_files')) is list
            and manifest.get('excluded_generated_files') == [] and type(manifest.get('excluded_generated_files')) is list,
            'manifest contains source changes or malformed inventory')
    material = receipt.get('materialization', receipt)
    require(isinstance(material, dict) and material.get('status') == 'PASS', 'materialization receipt unavailable')
    require(material.get('candidate_root') == str(candidate) and material.get('source_manifest_sha256') == pinned_digest, 'materialization receipt binding mismatch')
    source_state = source_clean_begin(source, source_sha)
    expected, blobs, fmt = object_tree(source, source_sha)
    actual = candidate_inventory(candidate, expected, blobs)
    for key,value in actual.items():
        require(type(material.get(key)) is type(value) and material.get(key) == value,
                'materialization receipt inventory mismatch: ' + key)
    require(material.get('git_metadata_removed') is True and material.get('source_unchanged') is True, 'materialization receipt lacks required facts')
    source_clean_end(source, source_sha, source_state)
    untracked_dirs=source_state['source_untracked_directories']
    return {'status':'INCONCLUSIVE' if untracked_dirs else 'OBSERVED_NOT_GATE',
            'reason':'non-excluded untracked directories may affect build inputs' if untracked_dirs else None,
            'product_gate_effect':'NONE', 'source_sha':source_sha,
            'source_manifest_sha256':pinned_digest, 'git_object_format':fmt, **actual,
            'source_tracked_count':source_state['source_tracked_count'],
            'source_tracked_bytes':source_state['source_tracked_bytes'],
            'source_tracked_budget_bytes':MAX_SOURCE_BYTES,
            'source_execution_mode':source_state['source_execution_mode'],
            'source_filesystem_type':source_state['source_filesystem_type'],
            'source_untracked_directories':untracked_dirs,
            'scope':'Streamed source and candidate content matched by Git object ID and SHA-256, not byte-by-byte comparison; no atomic snapshot, caller identity, authorization, build or artifact provenance verified'}


def _v3_canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8', 'strict')


def _v3_path(path):
    if path == '.':
        return
    safe_path(path)
    require(not any(ord(ch) == 127 for ch in path), 'source path contains a control character')


def _v3_exclusion(path):
    # Independent literal policy: directory rules apply only to real directory
    # components; a trailing slash denotes that the leaf is a directory.
    directory = path.endswith('/')
    clean = path.rstrip('/')
    parts = clean.split('/')
    count = len(parts) if directory else len(parts) - 1
    for end in range(1, count + 1):
        boundary = '/'.join(parts[:end]) + '/'
        if boundary in V3_EXCLUDES:
            return boundary
    if clean == '.env' and not directory:
        return '.env'
    return None

def _v3_mount_facts(root):
    """Capture ancestor/nested mount identities, including same-device bind mounts."""
    facts = []; nested = []
    for line in Path('/proc/self/mountinfo').read_text(encoding='utf-8').splitlines():
        left, separator, right = line.partition(' - ')
        fields = left.split(); tail = right.split()
        require(bool(separator) and len(fields) >= 6 and len(tail) >= 3, 'mount table is malformed')
        mount = re.sub(r'\\([0-7]{3})', lambda m:chr(int(m.group(1),8)), fields[4])
        inside = mount.startswith(str(root).rstrip('/') + '/')
        ancestor = str(root) == mount or str(root).startswith(mount.rstrip('/') + '/')
        if inside or ancestor:
            facts.append(line)
        if inside:
            nested.append(mount)
    require(bool(facts), 'mount identity is unavailable')
    require(not nested, 'source or candidate contains a nested mount')
    return tuple(sorted(facts))


def _v3_validate_link_graph(expected, blobs, deadline=None, *, projected_dirs=None):
    """Resolve links through the independently observed file/directory projection."""
    if projected_dirs is None:
        # Direct callers may use the Git tree's ancestor directories. The full
        # review instead supplies its independently observed projection, which
        # also includes valid exclusion-only container directories.
        directories = {'.'}
        for path in expected:
            if deadline is not None and time.monotonic() > deadline:
                raise Indeterminate('symlink graph time budget exceeded')
            directories.update(parent.as_posix() for parent in PurePosixPath(path).parents)
            require(len(directories) <= MAX_TREE_ENTRIES, 'symlink directory graph exceeds budget')
    else:
        directories = set(projected_dirs)
        require('.' in directories and len(directories) <= MAX_TREE_ENTRIES,
                'invalid symlink directory projection')
    require(not directories.intersection(expected), 'projected path is both file and directory')
    for path, (mode, oid) in expected.items():
        if deadline is not None and time.monotonic() > deadline:
            raise Indeterminate('symlink graph time budget exceeded')
        if mode != '120000':
            continue
        require(len(blobs[oid]) <= 4096, 'symlink target exceeds path budget')
        target = blobs[oid].decode('utf-8', 'strict')
        _v3_link_syntax(target)
        parent = PurePosixPath(path).parent.as_posix()
        require(parent in directories, 'symlink parent is not a projected directory')
        # The parent is a verified Git-projection directory; only components
        # actually traversed from the target consume the resolution budget.
        resolved = [] if parent == '.' else list(PurePosixPath(parent).parts)
        pending = deque(target.split('/'))
        require(len(pending) <= 4096, 'symlink pending component budget exceeded')
        # The reviewed symlink itself is the first expansion. A later visit to
        # the same link can be finite (for example a/../a/file), so bound the
        # total expansions rather than rejecting repeated path names.
        links = 1; steps = 0
        while pending:
            steps += 1
            require(steps <= 4096, 'symlink resolution step budget exceeded')
            if deadline is not None and time.monotonic() > deadline:
                raise Indeterminate('symlink graph time budget exceeded')
            part = pending.popleft()
            if part in ('', '.'):
                continue
            if part == '..':
                require(bool(resolved), 'symlink escapes candidate')
                resolved.pop(); continue
            require(not any(ord(ch) < 32 or ord(ch) == 127 for ch in part) and '\\' not in part,
                    'unsafe symlink target')
            resolved.append(part)
            current = '/'.join(resolved)
            require(_v3_exclusion(current + '/' if current in directories else current) is None,
                    'symlink resolves into excluded projection')
            entry = expected.get(current)
            if entry and entry[0] == '120000':
                links += 1
                require(links <= 40, 'symlink chain exceeds 40 expansions')
                require(len(blobs[entry[1]]) <= 4096, 'symlink target exceeds path budget')
                nested_target = blobs[entry[1]].decode('utf-8', 'strict')
                _v3_link_syntax(nested_target)
                resolved.pop()
                pending.extendleft(reversed(nested_target.split('/')))
                require(len(pending) <= 4096, 'symlink pending component budget exceeded')
            elif pending:
                # Even a following empty component, '.' or '..' requires the
                # current component to be a directory under real path rules.
                require(current in directories, 'symlink intermediate component is not a projected directory')
        final = '/'.join(resolved) or '.'
        require(final in expected or final in directories, 'symlink target outside observed projection')


def observe_v3_directories(root, indexed, mode_status, deadline):
    """Independently observe a bounded policy projection, not an atomic snapshot."""
    included = [path for path in indexed if not _v3_exclusion(path)]
    git_dirs = {p.as_posix() for path in included for p in PurePosixPath(path).parents} | {'.'}
    dirs = {}; boundaries = {}; signatures = {}; bad = set()
    _, root_fd = open_directory(root)
    try:
        root_device = os.fstat(root_fd).st_dev
        for event, relative, name, info, fd in _bounded_directory_events(
                root_fd, lambda path, _: _v3_exclusion(path + '/') is None, deadline):
            _v3_path(relative)
            require(info.st_dev == root_device, 'source contains a filesystem boundary')
            if event == 'end':
                continue
            if event == 'begin':
                signatures[('directory',relative)] = path_signature(info)
                dirs[relative] = {'path': relative, 'kind': 'directory',
                    'mode': f'{stat.S_IMODE(info.st_mode):04o}' if mode_status == 'VERIFIED' else None}
                continue
            parent = PurePosixPath(relative).parent.as_posix()
            reason = _v3_exclusion(relative + ('/' if stat.S_ISDIR(info.st_mode) else ''))
            if stat.S_ISLNK(info.st_mode):
                require(relative != '.env' and _v3_exclusion(relative + '/') is None
                        and reason is None and relative in indexed, 'excluded or untracked source symlink')
                if parent not in git_dirs: bad.add(parent)
            elif stat.S_ISDIR(info.st_mode):
                if reason:
                    boundaries[relative] = {'path':relative, 'kind':'directory', 'excluded_by':reason}
                    signatures[('boundary',relative)] = path_signature(info)
            elif stat.S_ISREG(info.st_mode):
                if relative == '.git':
                    continue  # A linked worktree uses a regular metadata marker.
                if parent not in git_dirs: bad.add(parent)
                require(reason is not None or relative in indexed, 'untracked source file')
            else:
                raise Invalid('unsupported source entry type')
    finally:
        os.close(root_fd)
    require(len(boundaries) <= MAX_TREE_ENTRIES, 'v3 excluded boundary count exceeds budget')
    boundary_ancestors = set()
    for path in boundaries:
        boundary_ancestors.update(p.as_posix() for p in PurePosixPath(path).parents)
    for path in sorted((p for p in dirs if p not in git_dirs), key=lambda p: p.count('/'), reverse=True):
        if path not in boundary_ancestors or path in bad:
            bad.add(path);bad.add(PurePosixPath(path).parent.as_posix())
    for path, row in dirs.items():
        row['origin'] = ('source_root' if path == '.' else 'git_ancestor' if path in git_dirs else
                         'excluded_container' if path in boundary_ancestors and path not in bad else 'untracked_business')
    by_bytes = lambda row: row['path'].encode('utf-8', 'strict')
    return (sorted(dirs.values(), key=by_bytes), sorted(boundaries.values(), key=by_bytes), signatures)


def candidate_inventory_v3(root, expected, blobs, directory_records, deadline, *, source_signatures=None,
                           with_signatures=False):
    """Stream the candidate via anchored directory FDs and verify Git blob bytes."""
    wanted_dirs = {row['path']: row['mode'] for row in directory_records}
    require(len(wanted_dirs) == len(directory_records) and '.' in wanted_dirs, 'duplicate or missing directory')
    files = []; directories = []; signatures = {}; found = set(); total_bytes = 0
    _, root_fd = open_directory(root)
    try:
        root_device = os.fstat(root_fd).st_dev
        for event, rel, name, before, fd in _bounded_directory_events(root_fd, lambda _path, _info: True, deadline):
            _v3_path(rel)
            require(before.st_dev == root_device, 'candidate contains a filesystem boundary')
            if event == 'end':
                continue
            if event == 'begin':
                mode = f'{stat.S_IMODE(before.st_mode):04o}'
                require(wanted_dirs.get(rel) == mode, 'candidate directory differs from projection')
                signatures[rel] = path_signature(before)
                directories.append({'path':rel, 'kind':'directory', 'mode':mode})
                continue
            if stat.S_ISDIR(before.st_mode):
                require(rel in wanted_dirs, 'unexpected candidate directory')
                continue
            require(rel in expected and rel not in found, 'unexpected or duplicate candidate file')
            require(before.st_nlink == 1, 'candidate file has external or multiple hardlinks')
            found.add(rel); gitmode, oid = expected[rel]; payload = blobs[oid]
            row = {'path':rel, 'mode':f'{stat.S_IMODE(before.st_mode):04o}'}
            if source_signatures is not None:
                require(rel in source_signatures and
                        stat.S_IMODE(before.st_mode) == stat.S_IMODE(source_signatures[rel][2]),
                        'candidate file permissions differ from live source')
            if stat.S_ISLNK(before.st_mode):
                require(gitmode == '120000', 'candidate symlink type differs from Git')
                target = os.readlink(name, dir_fd=fd);_v3_link_syntax(target)
                raw = os.fsencode(target);require(raw == payload, 'candidate symlink differs from Git')
                row.update(kind='symlink',target=target,sha256=hashlib.sha256(raw).hexdigest())
                after = os.stat(name, dir_fd=fd, follow_symlinks=False)
            else:
                require(stat.S_ISREG(before.st_mode) and gitmode in ('100644','100755'), 'candidate file type differs from Git')
                require(bool(before.st_mode & 0o111) == (gitmode == '100755'), 'candidate executable bit differs from Git')
                require(before.st_size == len(payload), 'candidate file size differs from Git')
                handle = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=fd)
                try:
                    require(path_signature(os.fstat(handle)) == path_signature(before), 'candidate changed before open')
                    h = hashlib.sha256(); size = 0
                    while size < len(payload):
                        part = os.read(handle, min(1024*1024, len(payload)-size))
                        if not part: break
                        size += len(part);h.update(part)
                        if time.monotonic() > deadline: raise Indeterminate('v3 candidate inventory time budget exceeded')
                    require(size == len(payload) and h.digest() == hashlib.sha256(payload).digest(), 'candidate bytes differ from Git')
                    after = os.fstat(handle)
                finally:
                    os.close(handle)
                total_bytes += size;row.update(kind='file',sha256=h.hexdigest())
            require(path_signature(before) == path_signature(after), 'candidate changed while reading')
            require(after.st_nlink == 1, 'candidate file hardlink count changed while reading')
            signatures[('file', rel)] = (*path_signature(after), after.st_nlink)
            files.append(row)
    finally:
        os.close(root_fd)
    require(found == set(expected) and {row['path'] for row in directories} == set(wanted_dirs), 'candidate is missing files or directories')
    by_bytes = lambda row: row['path'].encode('utf-8', 'strict')
    value = {'directories':sorted(directories,key=by_bytes), 'files':sorted(files,key=by_bytes)}
    result = {'candidate_inventory_v3_sha256':hashlib.sha256(_v3_canonical(value)).hexdigest(),
              'candidate_directory_count':len(directories), 'candidate_file_count':len(files),
              'candidate_tree_bytes':total_bytes}
    return (result,signatures) if with_signatures else result


def review_v3(source, candidate, manifest_path, receipt_path, source_sha, pinned_digest):
    """Independently check draft v3 observations; never authorize a build or Gate."""
    manifest = load_unique(manifest_path, 16*1024*1024); receipt = load_unique(receipt_path)
    return _review_v3_loaded(source, candidate, manifest, receipt, source_sha, pinned_digest)


def review_v3_fds(source, candidate, manifest_fd, receipt_fd, source_sha, pinned_digest):
    """Review caller-pinned evidence descriptors without resolving their paths."""
    manifest = load_unique_fd(manifest_fd, 16*1024*1024); receipt = load_unique_fd(receipt_fd)
    return _review_v3_loaded(source, candidate, manifest, receipt, source_sha, pinned_digest)


def _review_v3_loaded(source, candidate, manifest, receipt, source_sha, pinned_digest, *, identity_out=None):
    source, candidate = no_symlink_directory(source), no_symlink_directory(candidate)
    require(source != candidate and source not in candidate.parents and candidate not in source.parents,
            'source and candidate overlap')
    require(isinstance(source_sha, str) and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', source_sha), 'invalid source SHA')
    require(isinstance(pinned_digest, str) and re.fullmatch(r'[0-9a-f]{64}', pinned_digest), 'invalid pinned digest')
    require(isinstance(manifest, dict) and set(manifest) == SOURCE_FIELDS | {'directory_projection','projection_sha256'},
            'v3 manifest has missing or unknown fields')
    require(isinstance(receipt, dict), 'invalid materialization receipt')
    require(manifest.get('schema_version') == 'forgeflow.ecp-source-manifest.v3' and
            manifest.get('source_root') == str(source) and manifest.get('head') == source_sha, 'v3 source identity mismatch')
    require(manifest.get('worktree_state') == 'CLEAN' and manifest.get('inventory_complete') is True and
            manifest.get('release_qualifiable') is False and manifest.get('inventory_error') is None,
            'v3 source is not a complete clean draft')
    require(all(type(manifest.get(key)) is list and not manifest[key] for key in
                ('tracked_changes', 'untracked_business_files', 'excluded_generated_files', 'index_visibility_exceptions')),
            'v3 source inventory contains changes or malformed entries')
    require(manifest.get('patch_sha256') == hashlib.sha256(b'').hexdigest(), 'clean source has a patch')
    require(manifest.get('exclude_patterns') == list(V3_EXCLUDES), 'unregistered exclusion policy')
    require(manifest.get('untracked_scan_mode') in ('all','bounded') and
            manifest.get('untracked_scan_roots') == list(V3_SCAN_ROOTS), 'invalid scan settings')
    stamp = manifest.get('created_at')
    require(isinstance(stamp,str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',stamp), 'invalid v3 timestamp')
    try:
        datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as exc:
        raise Invalid('invalid v3 calendar timestamp') from exc
    canonical = {k:v for k,v in manifest.items() if k not in ('manifest_sha256','created_at','release_qualifiable')}
    require(hashlib.sha256(_v3_canonical(canonical)).hexdigest() == pinned_digest == manifest.get('manifest_sha256'),
            'v3 manifest digest mismatch')
    projection = manifest.get('directory_projection')
    require(isinstance(projection, dict) and set(projection) == {'version','mode_availability','exclusion_policy_sha256',
            'directories','excluded_directory_boundaries'}, 'invalid v3 directory projection')
    require(projection.get('version') == 'forgeflow.ecp-directory-projection.v1', 'invalid projection version')
    require(projection.get('exclusion_policy_sha256') == hashlib.sha256(_v3_canonical(list(V3_EXCLUDES))).hexdigest(),
            'directory projection policy digest mismatch')
    projection_digest = hashlib.sha256(_v3_canonical(projection)).hexdigest()
    require(manifest.get('projection_sha256') == projection_digest, 'directory projection digest mismatch')
    require(projection.get('mode_availability') in ('VERIFIED','UNAVAILABLE'), 'invalid directory mode availability')
    require(receipt.get('status') == 'OBSERVED_NOT_GATE' and receipt.get('qualification') == 'NOT_RUN' and
            receipt.get('product_gate_effect') == 'NONE' and receipt.get('release_qualifiable') is False,
            'materialization receipt claims an unsupported qualification')
    require(receipt.get('source_root') == str(source) and receipt.get('candidate_root') == str(candidate) and
            receipt.get('source_manifest_sha256') == pinned_digest and
            receipt.get('source_projection_sha256') == projection_digest, 'materialization receipt binding mismatch')
    require(receipt.get('source_unchanged') is True and receipt.get('git_metadata_removed') is True,
            'materialization receipt lacks required observations')
    _, initial_source_fd = open_directory(source)
    try:
        _, initial_candidate_fd = open_directory(candidate)
        try:
            initial_source_root = path_signature(os.fstat(initial_source_fd))
            initial_candidate_root = path_signature(os.fstat(initial_candidate_fd))
        finally:
            os.close(initial_candidate_fd)
    finally:
        os.close(initial_source_fd)
    source_mounts = _v3_mount_facts(source); candidate_mounts = _v3_mount_facts(candidate)
    source_state = source_clean_begin(source, source_sha, V3_EXCLUDES)
    actual_mode = source_state['source_execution_mode']
    require(projection['mode_availability'] == actual_mode, 'source directory mode availability differs')
    if actual_mode != 'VERIFIED':
        raise Indeterminate('source filesystem directory modes are unavailable')
    candidate_mode, candidate_fs = source_mode_availability(candidate)
    if candidate_mode != 'VERIFIED':
        raise Indeterminate('candidate filesystem directory modes are unavailable')
    dirs, boundaries, signatures = observe_v3_directories(source, source_state['entries'], actual_mode,
                                                           source_state['source_scan_deadline'])
    require(signatures.get(('directory','.')) == initial_source_root, 'source root identity changed during verification')
    require(dirs == projection.get('directories') and boundaries == projection.get('excluded_directory_boundaries'),
            'v3 source directory projection differs from independent observation')
    require(not any(row['origin'] == 'untracked_business' for row in dirs), 'untracked business directory')
    expected, blobs, fmt = object_tree(source, source_sha, V3_EXCLUDES)
    _v3_validate_link_graph(expected, blobs, source_state['source_scan_deadline'],
                            projected_dirs=(row['path'] for row in dirs))
    observed, candidate_signatures = candidate_inventory_v3(candidate, expected, blobs, dirs,
                                                            source_state['source_scan_deadline'],
                                                            source_signatures=source_state['signatures'], with_signatures=True)
    require(candidate_signatures.get('.') == initial_candidate_root, 'candidate root identity changed during verification')
    for key,value in observed.items():
        require(type(receipt.get(key)) is type(value) and receipt.get(key) == value, 'v3 receipt inventory mismatch: '+key)
    repeated, repeated_signatures = candidate_inventory_v3(candidate, expected, blobs, dirs,
                                                           source_state['source_scan_deadline'],
                                                           source_signatures=source_state['signatures'], with_signatures=True)
    require(repeated == observed and repeated_signatures == candidate_signatures,
            'candidate inventory or directory identities changed during independent verification')
    dirs2, boundaries2, signatures2 = observe_v3_directories(source, source_state['entries'], actual_mode,
                                                              source_state['source_scan_deadline'])
    require((dirs2,boundaries2,signatures2) == (dirs,boundaries,signatures), 'source directory projection changed during verification')
    source_clean_end(source, source_sha, source_state, V3_EXCLUDES)
    require(_v3_mount_facts(source) == source_mounts and _v3_mount_facts(candidate) == candidate_mounts,
            'source or candidate mount identity changed')
    require(source_mode_availability(source)[0] == actual_mode and source_mode_availability(candidate) == (candidate_mode,candidate_fs),
            'filesystem mode availability changed')
    if identity_out is not None:
        # Hash the complete bounded sets, not just content. The caller must hold
        # directory FDs throughout the workload and independently protect the
        # resulting baseline digest. Matching endpoints do not prove that no
        # transient change occurred in between them.
        def digest(value):
            return hashlib.sha256(_v3_canonical(value)).hexdigest()
        def items(value):
            return [[list(key) if isinstance(key, tuple) else key, list(sig)] for key, sig in sorted(value.items())]
        candidate_items = [[['file', key[1]] if isinstance(key, tuple) else ['directory', key], list(sig)]
                           for key, sig in candidate_signatures.items()]
        candidate_items.sort(key=lambda row: (row[0][0], row[0][1].encode('utf-8')))
        identity_out.update({
            'source_root': str(source), 'candidate_root': str(candidate), 'source_sha': source_sha,
            'source_manifest_sha256': pinned_digest, 'source_projection_sha256': projection_digest,
            'candidate_inventory_v3_sha256': observed['candidate_inventory_v3_sha256'],
            'source_root_signature': list(initial_source_root),
            'candidate_root_signature': list(initial_candidate_root),
            'source_tracked_signatures_sha256': digest(items(source_state['signatures'])),
            'source_directory_signatures_sha256': digest(items(signatures)),
            'candidate_signatures_sha256': digest(candidate_items),
            'source_git_stage_listing_sha256': hashlib.sha256(source_state['index']).hexdigest(),
            'source_git_visibility_listing_sha256': hashlib.sha256(source_state['flags']).hexdigest(),
            'source_physical_git_index_observed': False,
            'source_mount_facts_sha256': digest(source_mounts),
            'candidate_mount_facts_sha256': digest(candidate_mounts),
            'source_execution_mode': actual_mode, 'source_filesystem_type': source_state['source_filesystem_type'],
            'candidate_execution_mode': candidate_mode, 'candidate_filesystem_type': candidate_fs,
        })
    return {'status':'OBSERVED_NOT_GATE', 'qualification':'NOT_RUN', 'product_gate_effect':'NONE',
            'source_sha':source_sha, 'source_manifest_sha256':pinned_digest, 'source_projection_sha256':projection_digest,
            'source_execution_mode':actual_mode, 'candidate_filesystem_type':candidate_fs, 'git_object_format':fmt,
            'source_file_modes_bound_to_manifest':False,
            **observed, 'scope':'Source/candidate file modes were compared live but are not bound to the v3 manifest; observations are not atomic snapshot, caller, lease, build provenance or Gate'}


def _window_directory(fd, path):
    require(type(fd) is int and fd >= 3, 'invalid window directory descriptor')
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    require(flags & os.O_ACCMODE == os.O_RDONLY and not flags & getattr(os, 'O_PATH', 0),
            'window directory descriptor must be read-only')
    held = os.fstat(fd)
    require(stat.S_ISDIR(held.st_mode), 'window descriptor is not a directory')
    _, current = open_directory(path)
    try:
        require(path_signature(os.fstat(current)) == path_signature(held),
                'window path no longer binds the held directory')
    finally:
        os.close(current)
    return list(path_signature(held))


def capture_v3_window_fds(source, candidate, source_fd, candidate_fd, manifest_fd, receipt_fd,
                          source_sha, pinned_digest):
    """Capture non-authoritative endpoint identity for an external workload.

    The caller must retain all four descriptors and an independently protected
    SHA-256 baseline throughout the workload; this function never launches it.
    It does not continuously monitor writes or authenticate caller/lease/Gate.
    """
    require(len({source_fd, candidate_fd, manifest_fd, receipt_fd}) == 4,
            'window inputs require distinct descriptors')
    source_sig = _window_directory(source_fd, source)
    candidate_sig = _window_directory(candidate_fd, candidate)
    manifest, manifest_id = _load_unique_fd_identity(manifest_fd, 16*1024*1024)
    receipt, receipt_id = _load_unique_fd_identity(receipt_fd)
    identity = {}
    observed = _review_v3_loaded(source, candidate, manifest, receipt, source_sha, pinned_digest,
                                 identity_out=identity)
    require(_window_directory(source_fd, source) == source_sig and
            _window_directory(candidate_fd, candidate) == candidate_sig,
            'held window directory changed during observation')
    require(identity['source_root_signature'] == source_sig and identity['candidate_root_signature'] == candidate_sig,
            'review root identities differ from held window descriptors')
    manifest_after, manifest_after_id = _load_unique_fd_identity(manifest_fd, 16*1024*1024)
    receipt_after, receipt_after_id = _load_unique_fd_identity(receipt_fd)
    require((manifest_after, manifest_after_id) == (manifest, manifest_id) and
            (receipt_after, receipt_after_id) == (receipt, receipt_id),
            'window evidence changed during observation')
    identity.update(schema_version='forgeflow.ecp-window-identity.v1',
                    manifest_fd_identity=manifest_id, receipt_fd_identity=receipt_id)
    return {'status':'OBSERVED_NOT_GATE', 'qualification':'NOT_RUN', 'product_gate_effect':'NONE',
            'identity':identity, 'identity_sha256':hashlib.sha256(_v3_canonical(identity)).hexdigest(),
            'observation':observed,
            'scope':'Endpoint observations of the declared projection and selected Git facts only; '
                    'physical Git index identity and excluded contents are not inventoried, paths and FDs are not checked atomically; '
                    'no continuous monitoring, atomic snapshot, caller, lease, workload or Gate verified'}


def compare_v3_window_fds(source, candidate, source_fd, candidate_fd, manifest_fd, receipt_fd,
                          source_sha, pinned_digest, baseline, baseline_sha256):
    """Re-observe and compare against a caller-protected baseline digest."""
    require(isinstance(baseline, dict) and set(baseline) ==
            {'status','qualification','product_gate_effect','identity','identity_sha256','observation','scope'},
            'invalid window baseline')
    require(baseline['status'] == 'OBSERVED_NOT_GATE' and baseline['qualification'] == 'NOT_RUN' and
            baseline['product_gate_effect'] == 'NONE' and isinstance(baseline['identity'], dict),
            'window baseline makes an unsupported qualification')
    require(isinstance(baseline_sha256, str) and re.fullmatch(r'[0-9a-f]{64}', baseline_sha256) and
            hashlib.sha256(_v3_canonical(baseline['identity'])).hexdigest() == baseline_sha256 == baseline['identity_sha256'],
            'window baseline digest mismatch')
    current = capture_v3_window_fds(source, candidate, source_fd, candidate_fd, manifest_fd, receipt_fd,
                                    source_sha, pinned_digest)
    require(current['identity'] == baseline['identity'], 'window endpoint identities differ')
    return {'status':'INCONCLUSIVE', 'qualification':'NOT_RUN', 'product_gate_effect':'NONE',
            'baseline_sha256':baseline_sha256, 'current_sha256':current['identity_sha256'],
            'reason':'Endpoint identities match; uninterrupted immutability and workload authority remain unproven',
            'scope':current['scope']}


def _physical_index_observation(source, parent_path, parent_fd, index_fd):
    """Observe only the caller-opened index; never open an index named by Git.

    The parent path and FDs are caller-provided authorities, not authenticated
    identities. Git's resolved index name is used only as a binding check.
    Split indexes need separate shared-index identity and are not supported.
    """
    require(type(index_fd) is int and index_fd >= 3 and index_fd != parent_fd,
            'physical index requires distinct descriptors')
    parent_path = Path(os.path.abspath(parent_path))
    parent_signature = _window_directory(parent_fd, parent_path)
    flags = fcntl.fcntl(index_fd, fcntl.F_GETFL)
    require(flags & os.O_ACCMODE == os.O_RDONLY and not flags & getattr(os, 'O_PATH', 0),
            'physical index descriptor must be read-only')
    expected_path = str(parent_path / 'index')

    def git_index_path():
        value = run_git(source, ['rev-parse','--path-format=absolute','--git-path','index'])
        require(value.endswith(b'\n') and value.count(b'\n') == 1 and b'\0' not in value,
                'Git index path is malformed')
        path = value[:-1].decode('utf-8','strict')
        require(os.path.isabs(path) and os.path.normpath(path) == path and path == expected_path,
                'Git index path differs from caller-authorized parent')
        shared = run_git(source, ['rev-parse','--shared-index-path'])
        if shared not in (b'', b'\n'):
            raise Indeterminate('split Git index requires separate shared-index observation')
        return path

    def signature(info):
        return [info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
                info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns]

    before = os.fstat(index_fd)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size > 0,
            'physical Git index must be a nonempty singly-linked regular file')
    if before.st_size > MAX_PHYSICAL_INDEX_BYTES:
        raise Indeterminate('physical Git index exceeds observation byte budget')
    path = git_index_path()
    entry = os.stat('index', dir_fd=parent_fd, follow_symlinks=False)
    require(signature(entry) == signature(before), 'physical Git index path differs from held FD')
    digest = hashlib.sha256(); offset = 0
    while offset < before.st_size:
        data = os.pread(index_fd, min(1024 * 1024, before.st_size - offset), offset)
        require(bool(data), 'physical Git index was truncated during observation')
        digest.update(data); offset += len(data)
    after = os.fstat(index_fd)
    final_entry = os.stat('index', dir_fd=parent_fd, follow_symlinks=False)
    require(signature(before) == signature(after) == signature(final_entry),
            'physical Git index changed during observation')
    require(_window_directory(parent_fd, parent_path) == parent_signature and git_index_path() == path,
            'physical Git index parent or resolved name changed')
    require(signature(os.fstat(index_fd)) == signature(after) ==
            signature(os.stat('index', dir_fd=parent_fd, follow_symlinks=False)),
            'physical Git index changed during final name check')
    return {'path':path, 'parent_signature':parent_signature, 'file_signature':signature(after),
            'sha256':digest.hexdigest(), 'split_index':False}


def capture_v3_window_with_index_fds(source, candidate, source_fd, candidate_fd, manifest_fd, receipt_fd,
                                     source_sha, pinned_digest, index_parent_path, index_parent_fd, index_fd):
    """Capture selected endpoint facts plus an explicitly authorized index FD.

    Caller must hold all six FDs and protect the returned digest across the
    workload. Neither the caller-supplied FDs nor matching endpoint facts
    authenticate a principal/lease, freeze a filesystem, or grant a Gate.
    """
    require(len({source_fd,candidate_fd,manifest_fd,receipt_fd,index_parent_fd,index_fd}) == 6,
            'window and physical index inputs require distinct descriptors')
    first = _physical_index_observation(source,index_parent_path,index_parent_fd,index_fd)
    window = capture_v3_window_fds(source,candidate,source_fd,candidate_fd,manifest_fd,receipt_fd,
                                   source_sha,pinned_digest)
    second = _physical_index_observation(source,index_parent_path,index_parent_fd,index_fd)
    require(first == second, 'physical Git index changed across endpoint observation')
    identity = {'schema_version':'forgeflow.ecp-window-index-identity.v1',
                'window_identity_sha256':window['identity_sha256'],
                'window_receipt_sha256':hashlib.sha256(_v3_canonical(window)).hexdigest(),
                'physical_git_index':first}
    return {'status':'OBSERVED_NOT_GATE','qualification':'NOT_RUN','product_gate_effect':'NONE',
            'window':window,'identity':identity,
            'identity_sha256':hashlib.sha256(_v3_canonical(identity)).hexdigest(),
            'scope':'Endpoint facts only: caller FD authorization is unverified; split/shared index, '
                    'excluded contents, other Git metadata and continuous changes are not observed; '
                    'path binding and index reads are non-atomic; Git subprocess resources and filesystem I/O are not bounded; '
                    'continuous FD ownership or open-file-description identity across the workload is not verified; '
                    'no principal, lease, workload or Gate verified'}


def compare_v3_window_with_index_fds(source, candidate, source_fd, candidate_fd, manifest_fd, receipt_fd,
                                     source_sha, pinned_digest, index_parent_path, index_parent_fd, index_fd,
                                     baseline, baseline_sha256):
    """Compare bounded endpoint observations against a protected caller digest."""
    require(isinstance(baseline,dict) and set(baseline) ==
            {'status','qualification','product_gate_effect','window','identity','identity_sha256','scope'},
            'invalid physical-index window baseline')
    require(baseline['status'] == 'OBSERVED_NOT_GATE' and baseline['qualification'] == 'NOT_RUN' and
            baseline['product_gate_effect'] == 'NONE' and isinstance(baseline['identity'],dict),
            'physical-index baseline makes an unsupported qualification')
    require(isinstance(baseline_sha256,str) and re.fullmatch(r'[0-9a-f]{64}',baseline_sha256) and
            hashlib.sha256(_v3_canonical(baseline['identity'])).hexdigest() == baseline_sha256 == baseline['identity_sha256'],
            'physical-index baseline digest mismatch')
    require(isinstance(baseline['window'],dict) and baseline['window'].get('status') == 'OBSERVED_NOT_GATE' and
            baseline['window'].get('qualification') == 'NOT_RUN' and baseline['window'].get('product_gate_effect') == 'NONE' and
            baseline['window'].get('identity_sha256') == baseline['identity'].get('window_identity_sha256') and
            hashlib.sha256(_v3_canonical(baseline['window'])).hexdigest() == baseline['identity'].get('window_receipt_sha256'),
            'physical-index baseline window receipt mismatch')
    current = capture_v3_window_with_index_fds(source,candidate,source_fd,candidate_fd,manifest_fd,receipt_fd,
                                               source_sha,pinned_digest,index_parent_path,index_parent_fd,index_fd)
    require(current['identity'] == baseline['identity'], 'physical-index window endpoint identities differ')
    return {'status':'INCONCLUSIVE','qualification':'NOT_RUN','product_gate_effect':'NONE',
            'baseline_sha256':baseline_sha256,'current_sha256':current['identity_sha256'],
            'reason':'Observed endpoints match; continuous immutability and workload authority remain unproven',
            'scope':current['scope']}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','candidate','source-sha','manifest-sha256'):
        parser.add_argument('--'+name,required=True)
    manifest_group=parser.add_mutually_exclusive_group(required=True)
    manifest_group.add_argument('--manifest')
    manifest_group.add_argument('--manifest-fd', type=int)
    receipt_group=parser.add_mutually_exclusive_group(required=True)
    receipt_group.add_argument('--receipt')
    receipt_group.add_argument('--receipt-fd', type=int)
    parser.add_argument('--manifest-version', choices=('2','3'), default='2',
                        help='select the historical v2 or draft v3 observation path')
    args=parser.parse_args()
    if (args.manifest_fd is None) != (args.receipt_fd is None):
        parser.error('manifest and receipt must both use paths or both use inherited file descriptors')
    if args.manifest_fd is not None and args.manifest_version != '3':
        parser.error('inherited file descriptors require manifest version 3')
    try:
        if args.manifest_fd is not None:
            value=review_v3_fds(args.source,args.candidate,args.manifest_fd,args.receipt_fd,args.source_sha,args.manifest_sha256)
        else:
            reviewer = review_v3 if args.manifest_version == '3' else review
            value=reviewer(args.source,args.candidate,args.manifest,args.receipt,args.source_sha,args.manifest_sha256)
        code=20 if value['status']=='INCONCLUSIVE' else 0
    except GitTerminationUnconfirmed as exc:
        value={'status':'INCONCLUSIVE','qualification':'NOT_RUN','product_gate_effect':'NONE',
               'reason':'Git subprocess termination is unconfirmed','reason_code':'GIT_TERMINATION_UNCONFIRMED',
               'leader_reaped':exc.leader_reaped,'group_signal':exc.signal_status,'descendants_terminated':None,
               'git_capture':{'status':'UNKNOWN','wait_error':exc.wait_error,
                   'stdout_bytes':len(exc.stdout_bytes),'stdout_sha256':hashlib.sha256(exc.stdout_bytes).hexdigest(),
                   'stderr_bytes':len(exc.stderr_bytes),'stderr_sha256':hashlib.sha256(exc.stderr_bytes).hexdigest(),
                   'raw_output_persistence':'UNAVAILABLE'}}
        code=20
    except Indeterminate as exc:
        value={'status':'INCONCLUSIVE','product_gate_effect':'NONE','reason':str(exc)}
        code=20
    except (Invalid, ValueError, TypeError, UnicodeError, RecursionError) as exc:
        value={'status':'FAIL','product_gate_effect':'NONE','reason':str(exc)}
        code=10
    except (OSError, subprocess.SubprocessError) as exc:
        value={'status':'INCONCLUSIVE','product_gate_effect':'NONE','reason':str(exc)}
        code=20
    print(json.dumps(value,ensure_ascii=False,sort_keys=True));return code

if __name__=='__main__':
    raise SystemExit(main())

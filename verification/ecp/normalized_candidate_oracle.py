#!/usr/bin/env python3
"""Independent draft S/P/target observation; never authenticates a Gate.

The verifier has no write path and does not import the policy producer or the
materializer. Git and every file are read with bounded memory. Identity checks
are endpoint observations, not an atomic snapshot or an execution authority.
"""
from __future__ import annotations

import argparse
from contextvars import ContextVar
from datetime import datetime
import fnmatch
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

EXCLUDES = ('.git/', '.local/', '.env', 'target/', 'node_modules/',
            'console/node_modules/', 'console/dist/', 'console/test-results/',
            'console/playwright-report/', '.pytest_cache/', 'evidence/', 'audit/',
            'benchmarks/evidence/', 'crates/executors/qualification/',
            'verification/evidence/', 'docs/idea/ForgeFlow_ECP_完整开发规划/evidence/',
            '__pycache__/')
SCAN_ROOTS = ('ops/ecp/', 'verification/', 'contracts/ecp/', 'docs/ecp/',
              '.github/workflows/', 'deploy/', 'console/', 'crates/', 'migrations/', 'benchmarks/ecp/')
MAX_DOC = 16 * 1024 * 1024
MAX_GIT = 16 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_DEPTH = 128
MAX_PATH_OPERATIONS = 2_000_000
MAX_SCAN_IDENTITY_BYTES = 64 * 1024 * 1024
MAX_SCAN_SECONDS = 180
RECEIPT_MAX_JSON_BYTES = 16 * 1024 * 1024
RECEIPT_MAX_ENTRIES = 100_000
RECEIPT_MAX_NODES = 2_000_000
RECEIPT_MAX_DEPTH = 32
_DEADLINE = ContextVar('forgeflow_normalized_oracle_deadline', default=None)


class Invalid(ValueError):
    pass


class Unknown(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise Invalid(reason)


def checkpoint():
    deadline = _DEADLINE.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise Unknown('observation deadline exhausted')


def canonical(value):
    checkpoint()
    result = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    checkpoint()
    return result


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_uid, info.st_gid, info.st_nlink)


def no_duplicate_pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, 'duplicate JSON field')
        value[key] = item
    return value


def _integer(value):
    require(len(value.lstrip('-')) <= 32, 'JSON integer exceeds limit')
    return int(value)


def _float(value):
    require(len(value) <= 32, 'JSON number exceeds limit')
    result = float(value)
    require(math.isfinite(result), 'nonfinite number')
    return result


def absolute_directory(path):
    checkpoint()
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            checkpoint()
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        return path, fd
    except BaseException:
        os.close(fd)
        raise


def read_document(path, seen, *, raw_sha256=None):
    """Read a pinned, bounded regular file without following leaf symlinks."""
    path = Path(os.path.abspath(path))
    _, parent_fd = absolute_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= MAX_DOC, 'unbounded or non-regular evidence')
            require((before.st_dev, before.st_ino) not in seen, 'evidence files share an inode')
            seen.add((before.st_dev, before.st_ino))
            chunks, total = [], 0
            while True:
                checkpoint()
                chunk = os.read(fd, min(1024 * 1024, MAX_DOC + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                require(total <= MAX_DOC, 'evidence exceeds byte budget')
            require(total == before.st_size and signature(os.fstat(fd)) == signature(before), 'evidence changed while reading')
            data = b''.join(chunks)
            if raw_sha256 is not None:
                require(isinstance(raw_sha256, str) and re.fullmatch(r'[0-9a-f]{64}', raw_sha256),
                        'invalid receipt byte digest pin')
                require(hashlib.sha256(data).hexdigest() == raw_sha256, 'receipt byte digest differs from pin')
            try:
                result = json.loads(data.decode('utf-8', 'strict'), object_pairs_hook=no_duplicate_pairs,
                                    parse_int=_integer, parse_float=_float,
                                    parse_constant=lambda _: (_ for _ in ()).throw(Invalid('nonfinite JSON')))
                checkpoint()
                return result
            except (UnicodeError, RecursionError, ValueError) as exc:
                if isinstance(exc, Invalid):
                    raise
                raise Invalid('malformed or excessively nested JSON') from exc
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def bounded_git(root_fd, args, deadline):
    """Capture Git without inherited PATH/config or unbounded streams."""
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LC_ALL': 'C',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
           'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
           'GIT_NO_LAZY_FETCH': '1', 'GIT_ALLOW_PROTOCOL': 'file', 'GIT_ATTR_NOSYSTEM': '1',
           'GIT_CONFIG_COUNT': '4', 'GIT_CONFIG_KEY_0': 'core.fsmonitor', 'GIT_CONFIG_VALUE_0': 'false',
           'GIT_CONFIG_KEY_1': 'core.hooksPath', 'GIT_CONFIG_VALUE_1': '/dev/null',
           'GIT_CONFIG_KEY_2': 'core.attributesFile', 'GIT_CONFIG_VALUE_2': '/dev/null',
           'GIT_CONFIG_KEY_3': 'core.excludesFile', 'GIT_CONFIG_VALUE_3': '/dev/null'}
    if time.monotonic() >= deadline:
        raise Unknown('Git deadline exhausted')
    proc = subprocess.Popen(['/usr/bin/git', *args], cwd=f'/proc/self/fd/{root_fd}', pass_fds=(root_fd,),
                            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    stdout, stderr = bytearray(), bytearray()
    selector = None
    try:
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ, (stdout, MAX_GIT))
        selector.register(proc.stderr, selectors.EVENT_READ, (stderr, 65536))
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Unknown('Git capture timed out')
            for key, _ in selector.select(remaining):
                buf, limit = key.data
                data = os.read(key.fileobj.fileno(), min(65536, limit + 1 - len(buf)))
                if not data:
                    selector.unregister(key.fileobj)
                else:
                    buf.extend(data)
                    if len(buf) > limit:
                        raise Unknown('Git capture exceeded byte budget')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Unknown('Git wait deadline exhausted')
        try:
            code = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise Unknown('Git wait timed out') from exc
        if code:
            raise Unknown('Git returned a nonzero status')
        return bytes(stdout)
    except BaseException as original:
        if proc.returncode is None:
            signal_unknown = False
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                signal_unknown = True
            try:
                proc.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                raise Unknown('Git termination could not be confirmed') from original
            if signal_unknown:
                raise Unknown('Git process-group signal could not be confirmed') from original
        raise
    finally:
        if selector is not None:
            selector.close()
        proc.stdout.close()
        proc.stderr.close()


def safe_path(value, *, root=False):
    checkpoint()
    if root and value == '.':
        return value
    require(isinstance(value, str) and value and not value.startswith('/') and '\\' not in value,
            'invalid relative path')
    require(len(value.encode('utf-8', 'strict')) <= 4096, 'path exceeds byte budget')
    parts = value.split('/')
    require(len(parts) <= MAX_DEPTH and all(part not in ('', '.', '..') for part in parts), 'unsafe relative path')
    require(not any(ord(c) < 32 or ord(c) == 127 for c in value), 'control character in path')
    return value


def exclusion(path):
    # This oracle owns its fixed policy and computes directory ancestors itself.
    is_directory = path.endswith('/')
    clean = path.rstrip('/')
    components = clean.split('/')
    stop = len(components) if is_directory else len(components) - 1
    for depth in range(1, stop + 1):
        candidate = '/'.join(components[:depth]) + '/'
        if candidate in EXCLUDES:
            return candidate
    if clean == '.env' and not is_directory:
        return '.env'
    return None


def excluded(path):
    return exclusion(path) is not None


def parse_git_inventory(fd, head, deadline):
    fmt = 'sha1' if len(head) == 40 else 'sha256'
    sha = bounded_git(fd, ['rev-parse', '--verify', 'HEAD^{commit}'], deadline).decode('ascii', 'strict').strip()
    require(sha == head, 'Git HEAD differs from manifest')
    root = bounded_git(fd, ['rev-parse', '--show-prefix'], deadline)
    require(root in (b'', b'\n'), 'source is not worktree root')
    top = bounded_git(fd, ['rev-parse', '--show-toplevel'], deadline).decode('utf-8', 'strict')
    require(top.endswith('\n') and '\n' not in top[:-1] and os.path.isabs(top[:-1]), 'invalid Git worktree root')
    _, topfd = absolute_directory(top[:-1])
    try:
        require((os.fstat(topfd).st_dev, os.fstat(topfd).st_ino) == (os.fstat(fd).st_dev, os.fstat(fd).st_ino),
                'Git worktree differs from pinned source')
    finally:
        os.close(topfd)
    flags = bounded_git(fd, ['ls-files', '-v', '-z'], deadline)
    index = bounded_git(fd, ['ls-files', '--stage', '-z'], deadline)
    tree = bounded_git(fd, ['ls-tree', '-rz', '--full-tree', head], deadline)
    require(all(raw.endswith(b'\0') and raw.count(b'\0') <= MAX_ENTRIES for raw in (flags, index, tree)),
            'Git inventory is empty, malformed or exceeds budget')
    indexed, committed = {}, {}
    for raw, destination, is_tree in ((index, indexed, False), (tree, committed, True)):
        for row in raw.split(b'\0'):
            if not row:
                continue
            metadata, sep, path_bytes = row.partition(b'\t')
            require(sep == b'\t', 'Git record lacks path separator')
            fields = metadata.decode('ascii', 'strict').split(' ')
            require(len(fields) == 3, 'malformed Git record')
            mode, kind, tail = fields
            oid = tail if is_tree else kind
            path = safe_path(path_bytes.decode('utf-8', 'strict'))
            require(mode in ('100644', '100755', '120000') and (kind == 'blob' if is_tree else tail == '0')
                    and re.fullmatch(r'[0-9a-f]{%d}' % len(head), oid) and path not in destination,
                    'unsupported, duplicate or unmerged Git entry')
            destination[path] = (mode, oid)
    require(indexed and indexed == committed, 'Git index differs from committed tree')
    flag_paths = []
    for item in flags.split(b'\0'):
        if item:
            require(item.startswith(b'H '), 'Git index has hidden or unsupported entry')
            flag_paths.append(item[2:].decode('utf-8', 'strict'))
    require(len(flag_paths) == len(indexed) and set(flag_paths) == set(indexed), 'Git visibility listing differs')
    included = {}
    for path, value in indexed.items():
        mode = value[0]
        require(mode != '120000' or path != '.env', 'excluded symlink boundary')
        if excluded(path):
            continue
        require(mode != '120000' or not excluded(path + '/'), 'excluded symlink boundary')
        included[path] = value
    return included, fmt, index, flags


def _mount_table():
    lines = Path('/proc/self/mountinfo').read_text(encoding='utf-8', errors='strict').splitlines()
    table = []
    for line in lines:
        checkpoint()
        left, sep, right = line.partition(' - ')
        before, after = left.split(), right.split()
        if not sep or len(before) < 6 or len(after) < 1:
            raise Unknown('mount table is malformed')
        decode = lambda value: re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), value)
        table.append((before[0], before[2], decode(before[3]), decode(before[4]), after[0], line))
    return table


def mount_binding(path, fd):
    table = _mount_table()
    matches = [item for item in table if str(path) == item[3] or str(path).startswith(item[3].rstrip('/') + '/')]
    if not matches:
        raise Unknown('filesystem mount unavailable')
    selected = max(matches, key=lambda item: len(item[3]))
    info = Path(f'/proc/self/fdinfo/{fd}').read_text(encoding='ascii').splitlines()
    ids = [line.split(':', 1)[1].strip() for line in info if line.startswith('mnt_id:')]
    if len(ids) != 1 or ids[0] != selected[0] or os.readlink(f'/proc/self/fd/{fd}') != str(path):
        raise Unknown('root path or mount differs from held descriptor')
    if any(item[3].startswith(str(path).rstrip('/') + '/') for item in table):
        raise Unknown('nested mount cannot be qualified')
    rel = os.path.relpath(str(path), selected[3])
    backing = os.path.normpath(os.path.join(selected[2], '' if rel == '.' else rel))
    return selected[1], backing, selected[4], selected[5]


def _is_beneath(a, b):
    return a == b or a.startswith(b.rstrip('/') + '/')


def _open_at_root(root_fd, relative):
    fd = os.dup(root_fd)
    try:
        if relative != '.':
            for part in relative.split('/'):
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _acl_and_xattrs(fd):
    # Xattrs visible to this process only; it cannot authenticate another
    # principal or prove visibility under a different LSM/mount configuration.
    return tuple(sorted(os.listxattr(fd)))


def _digest_file(parent_fd, name, before, fmt, limits, deadline, *, source):
    require(before.st_size <= limits['max_file_bytes'], 'file exceeds policy size limit')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        require(signature(os.fstat(fd)) == signature(before), 'file changed before reading')
        size = before.st_size
        git = hashlib.new(fmt, b'blob ' + str(size).encode('ascii') + b'\0')
        sha = hashlib.sha256()
        read = 0
        while True:
            if time.monotonic() > deadline:
                raise Unknown('file scan deadline exhausted')
            chunk = os.read(fd, min(1024 * 1024, size + 1 - read))
            if not chunk:
                break
            read += len(chunk)
            require(read <= size, 'file grew during reading')
            git.update(chunk)
            sha.update(chunk)
        attrs = () if source else _acl_and_xattrs(fd)
        require(read == size and signature(os.fstat(fd)) == signature(before), 'file changed while reading')
        return git.hexdigest(), sha.hexdigest(), attrs
    finally:
        os.close(fd)


def _symlink(parent_fd, name, before, fmt, *, source):
    target = os.readlink(name, dir_fd=parent_fd)
    raw = target.encode('utf-8', 'strict')
    require(os.fsencode(target) == raw and len(raw) <= 4096, 'unsupported symlink target bytes')
    # /proc/self/fd resolves the held parent; do not follow the final symlink.
    attrs = () if source else tuple(sorted(os.listxattr(f'/proc/self/fd/{parent_fd}/{name}', follow_symlinks=False)))
    require(signature(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == signature(before),
            'symlink changed while reading')
    oid = hashlib.new(fmt, b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()
    return target, oid, hashlib.sha256(raw).hexdigest(), len(raw), attrs


def walk(root_fd, *, source, expected_files, expected_dirs, fmt, limits, deadline):
    """Read independently under rootfd, retaining only bounded metadata."""
    root_info = os.fstat(root_fd)
    pending = [('.', signature(root_info))]
    seen_dirs, seen_files, boundary, children = {}, {}, set(), {'.': []}
    counts, total, identity_bytes = 0, 0, 0
    while pending:
        if time.monotonic() > deadline:
            raise Unknown('tree scan deadline exhausted')
        rel, expected_identity = pending.pop()
        fd = _open_at_root(root_fd, rel)
        try:
            before_dir = os.fstat(fd)
            require(signature(before_dir) == expected_identity and stat.S_ISDIR(before_dir.st_mode),
                    'directory changed before opening')
            attrs = _acl_and_xattrs(fd) if not source else ()
            seen_dirs[rel] = {'mode': f'{stat.S_IMODE(before_dir.st_mode):04o}', 'uid': before_dir.st_uid,
                              'gid': before_dir.st_gid, 'xattrs': attrs, 'signature': signature(before_dir)}
            with os.scandir(fd) as it:
                for item in it:
                    counts += 1
                    if counts > limits['max_entries'] * 4:
                        raise Unknown('tree enumeration exceeded budget')
                    path = item.name if rel == '.' else rel + '/' + item.name
                    safe_path(path)
                    identity_bytes += len(path.encode('utf-8')) + 256
                    if identity_bytes > MAX_SCAN_IDENTITY_BYTES:
                        raise Unknown('tree identity budget exceeded')
                    if len(path.split('/')) > limits['max_depth']:
                        raise Unknown('path exceeds policy depth budget')
                    info = os.stat(item.name, dir_fd=fd, follow_symlinks=False)
                    require(info.st_dev == root_info.st_dev, 'filesystem boundary in tree')
                    is_dir = stat.S_ISDIR(info.st_mode)
                    if source:
                        if stat.S_ISLNK(info.st_mode):
                            require(path != '.env' and not excluded(path + '/'), 'excluded symlink boundary')
                        elif stat.S_ISREG(info.st_mode):
                            if path in ('.git', '.env'):
                                children[rel].append(('file', path))
                                continue
                        elif not is_dir:
                            raise Invalid('unsupported entry type')
                        if is_dir and excluded(path + '/'):
                            boundary.add(path)
                            children[rel].append(('boundary', path))
                            continue
                    if is_dir:
                        require(path in expected_dirs, 'unexpected directory')
                        children[rel].append(('directory', path))
                        children[path] = []
                        pending.append((path, signature(info)))
                        continue
                    children[rel].append(('file', path))
                    require(path in expected_files and path not in seen_files, 'unexpected or duplicate file')
                    require(info.st_nlink == 1 if not source else True, 'candidate file has hardlinks')
                    if stat.S_ISREG(info.st_mode):
                        oid, sha, attrs = _digest_file(fd, item.name, info, fmt, limits, deadline, source=source)
                        total += info.st_size
                        require(total <= limits['max_total_bytes'], 'tree file bytes exceed policy')
                        record = {'kind': 'file', 'size': info.st_size, 'git_oid': oid, 'sha256': sha}
                    elif stat.S_ISLNK(info.st_mode):
                        target, oid, sha, size, attrs = _symlink(fd, item.name, info, fmt, source=source)
                        total += size
                        require(total <= limits['max_total_bytes'], 'tree file bytes exceed policy')
                        record = {'kind': 'symlink', 'size': size, 'git_oid': oid, 'sha256': sha, 'target': target}
                    else:
                        raise Invalid('unsupported entry type')
                    record.update(mode=f'{stat.S_IMODE(info.st_mode):04o}', uid=info.st_uid, gid=info.st_gid,
                                  xattrs=attrs, signature=signature(info))
                    seen_files[path] = record
            require(signature(os.fstat(fd)) == signature(before_dir), 'directory changed during enumeration')
        finally:
            os.close(fd)
    require(set(seen_dirs) == set(expected_dirs), ('source' if source else 'candidate') + ' directory set differs')
    require(set(seen_files) == set(expected_files), ('source' if source else 'candidate') + ' file set differs')
    children = {path: sorted(items, key=lambda item: (item[0], item[1].encode('utf-8')))
                for path, items in children.items()}
    return seen_dirs, seen_files, boundary, total, children


def validate_link_graph(files, dirs):
    """Resolve every link through the explicit included graph only."""
    from collections import deque
    edges = {path: [] for path in dirs}
    for path in dirs:
        if path != '.':
            parent = PurePosixPath(path).parent.as_posix()
            require(parent in dirs, 'directory graph has missing parent')
            edges[parent].append(path)
    operations = 0
    for path, row in files.items():
        checkpoint()
        if row['kind'] != 'symlink':
            continue
        target = row['target']
        require(target and not target.startswith('/') and '\\' not in target, 'invalid symlink target')
        resolved = list(PurePosixPath(path).parent.parts)
        pending = deque(target.split('/'))
        require(len(pending) <= 4096, 'symlink pending component budget exceeded')
        # Count the already reviewed symlink as the first expansion, matching
        # the bound for an actual path open rather than only nested links.
        steps = 0; links = 1
        while pending:
            checkpoint()
            steps += 1
            operations += 1
            if operations > MAX_PATH_OPERATIONS:
                raise Unknown('aggregate symlink resolution budget exceeded')
            require(steps <= 4096, 'symlink resolution budget exceeded')
            part = pending.popleft()
            if part in ('', '.'):
                continue
            if part == '..':
                require(bool(resolved), 'symlink escapes projection')
                resolved.pop()
                continue
            require(not any(ord(ch) < 32 or ord(ch) == 127 for ch in part), 'invalid symlink component')
            resolved.append(part)
            current = '/'.join(resolved)
            require(not excluded(current + '/' if current in dirs else current),
                    'symlink enters excluded boundary')
            if current in files and files[current]['kind'] == 'symlink':
                links += 1
                require(links <= 40, 'symlink chain exceeds 40 expansions')
                nested = files[current]['target']
                require(nested and not nested.startswith('/') and '\\' not in nested, 'invalid nested symlink')
                resolved.pop()
                pending.extendleft(reversed(nested.split('/')))
                require(len(pending) <= 4096, 'symlink pending component budget exceeded')
            elif pending:
                require(current in dirs, 'symlink intermediate component missing')
        final = '/'.join(resolved) or '.'
        require(final in files or final in dirs, 'symlink target outside observed projection')
        if final in dirs:
            parent = PurePosixPath(path).parent.as_posix()
            require(parent in dirs, 'symlink parent is missing')
            edges[parent].append(final)
    # Directory entries already form a tree; links add edges that can create
    # cycles even when each individual symlink expansion terminates.
    colors = {}
    for start in edges:
        if colors.get(start, 0):
            continue
        colors[start] = 1
        stack = [(start, iter(edges[start]))]
        while stack:
            checkpoint()
            node, iterator = stack[-1]
            try:
                child = next(iterator)
            except StopIteration:
                colors[node] = 2
                stack.pop()
                continue
            require(colors.get(child, 0) != 1, 'directory symlink graph contains a cycle')
            if not colors.get(child, 0):
                colors[child] = 1
                stack.append((child, iter(edges[child])))


def _check_sorted(items, *, directories=False):
    require(isinstance(items, list) and 0 < len(items) <= MAX_ENTRIES, 'empty or oversized collection')
    values = {}
    prev = None
    for row in items:
        require(isinstance(row, dict), 'entry is not an object')
        path = safe_path(row.get('path'), root=directories)
        key = path.encode('utf-8', 'strict')
        require(prev is None or prev < key, 'paths are duplicate or not UTF-8 sorted')
        prev = key
        values[path] = row
    return values


def _mode(value, *, directory=False, git_mode=None):
    require(isinstance(value, str) and re.fullmatch(r'0[0-7]{3}', value), 'invalid target mode')
    number = int(value, 8)
    if not directory and git_mode == '100644':
        require(number & 0o111 == 0, 'non-executable Git blob has execution bits')
    elif not directory and git_mode == '100755':
        require(number & stat.S_IXUSR, 'executable Git blob lacks owner execute')
    return value


def _type_int(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def validate_documents(manifest, manifest_sha, supplement, supplement_sha, policy, policy_sha, source):
    for value in (manifest_sha, supplement_sha, policy_sha):
        require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value), 'invalid caller-pinned digest')
    fields_m = {'schema_version', 'source_root', 'head', 'worktree_state', 'exclude_patterns', 'untracked_scan_mode',
                'untracked_scan_roots', 'tracked_changes', 'untracked_business_files', 'excluded_generated_files',
                'patch_sha256', 'manifest_sha256', 'created_at', 'release_qualifiable', 'inventory_complete',
                'inventory_error', 'index_visibility_exceptions', 'directory_projection', 'projection_sha256'}
    require(isinstance(manifest, dict) and set(manifest) == fields_m, 'manifest fields differ from v3')
    require(manifest['schema_version'] == 'forgeflow.ecp-source-manifest.v3' and manifest['source_root'] == str(source)
            and manifest['worktree_state'] == 'CLEAN' and manifest['inventory_complete'] is True
            and manifest['release_qualifiable'] is False and manifest['inventory_error'] is None,
            'manifest is not a nonqualifying clean v3 source')
    require(manifest['exclude_patterns'] == list(EXCLUDES) and manifest['untracked_scan_roots'] == list(SCAN_ROOTS)
            and manifest['untracked_scan_mode'] in ('all', 'bounded') and manifest['patch_sha256'] == hashlib.sha256(b'').hexdigest()
            and all(manifest[k] == [] for k in ('tracked_changes', 'untracked_business_files',
                                                'excluded_generated_files', 'index_visibility_exceptions')),
            'manifest inventory or exclusion policy differs')
    stamp = manifest['created_at']
    require(isinstance(stamp, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', stamp),
            'invalid manifest timestamp')
    try:
        datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as exc:
        raise Invalid('invalid manifest calendar timestamp') from exc
    require(digest({k: v for k, v in manifest.items() if k not in ('manifest_sha256', 'created_at', 'release_qualifiable')})
            == manifest_sha == manifest['manifest_sha256'], 'manifest digest mismatch')
    head = manifest['head']
    require(isinstance(head, str) and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', head)
            and any(c != '0' for c in head), 'invalid Git commit')
    projection = manifest['directory_projection']
    require(isinstance(projection, dict) and set(projection) == {'version', 'mode_availability', 'exclusion_policy_sha256',
            'directories', 'excluded_directory_boundaries'} and projection['version'] == 'forgeflow.ecp-directory-projection.v1'
            and projection['mode_availability'] == 'UNAVAILABLE' and digest(projection) == manifest['projection_sha256']
            and projection['exclusion_policy_sha256'] == digest(list(EXCLUDES)), 'source projection is not unavailable v3')
    manifest_dirs = _check_sorted(projection['directories'], directories=True)
    require('.' in manifest_dirs, 'missing source root directory')
    for path, row in manifest_dirs.items():
        require(set(row) == {'path', 'kind', 'mode', 'origin'} and row['kind'] == 'directory' and row['mode'] is None
                and row['origin'] in ('source_root', 'git_ancestor', 'excluded_container')
                and (path == '.') == (row['origin'] == 'source_root'), 'invalid source directory row')
        if path != '.':
            require(PurePosixPath(path).parent.as_posix() in manifest_dirs and not excluded(path + '/'), 'invalid source parent')
    boundary_rows = projection['excluded_directory_boundaries']
    require(type(boundary_rows) is list and len(boundary_rows) <= MAX_ENTRIES, 'invalid excluded boundary list')
    boundaries = _check_sorted(boundary_rows) if boundary_rows else {}
    for path, row in boundaries.items():
        require(set(row) == {'path', 'kind', 'excluded_by'} and row['kind'] == 'directory'
                and PurePosixPath(path).parent.as_posix() in manifest_dirs and path not in manifest_dirs
                and row['excluded_by'] == exclusion(path + '/'), 'invalid excluded boundary')
    fields_s = {'schema_version', 'source_manifest_sha256', 'source_head', 'source_mode_claim', 'directories', 'entries',
                'qualification', 'product_gate_effect'}
    require(isinstance(supplement, dict) and set(supplement) == fields_s and digest(supplement) == supplement_sha
            and supplement['schema_version'] == 'forgeflow.ecp-source-supplement.v1'
            and supplement['source_manifest_sha256'] == manifest_sha and supplement['source_head'] == head
            and supplement['source_mode_claim'] == 'UNKNOWN' and supplement['qualification'] == 'NOT_RUN'
            and supplement['product_gate_effect'] == 'NONE', 'supplement binding differs')
    dirs = _check_sorted(supplement['directories'], directories=True)
    require(set(dirs) == set(manifest_dirs) and all(set(row) == {'path', 'origin'}
            and row['origin'] == manifest_dirs[path]['origin'] for path, row in dirs.items()), 'supplement directories differ')
    files = _check_sorted(supplement['entries'])
    require(sum(0 if path == '.' else len(path.split('/')) for path in (*dirs, *files, *boundaries)) <= MAX_PATH_OPERATIONS,
            'source path operation budget exceeded')
    for path, row in files.items():
        require(path not in dirs and not excluded(path)
                and (row.get('kind') != 'symlink' or not excluded(path + '/'))
                and PurePosixPath(path).parent.as_posix() in dirs, 'supplement file parent or path invalid')
        require(set(row) == ({'path', 'kind', 'git_mode', 'git_oid', 'size', 'sha256', 'target'}
                             if row.get('kind') == 'symlink' else {'path', 'kind', 'git_mode', 'git_oid', 'size', 'sha256'}),
                'supplement file fields differ')
        require(row['kind'] in ('file', 'symlink') and row['git_mode'] in ('100644', '100755', '120000')
                and (row['git_mode'] == '120000') == (row['kind'] == 'symlink')
                and isinstance(row['git_oid'], str) and re.fullmatch(r'[0-9a-f]{%d}' % len(head), row['git_oid'])
                and any(c != '0' for c in row['git_oid'])
                and _type_int(row['size'], MAX_FILE) and isinstance(row['sha256'], str)
                and re.fullmatch(r'[0-9a-f]{64}', row['sha256']), 'invalid supplement entry')
        if row['kind'] == 'symlink':
            target = row['target']
            require(isinstance(target, str) and target and not target.startswith('/') and '\\' not in target
                    and not any(ord(ch) < 32 or ord(ch) == 127 for ch in target), 'invalid symlink target')
            raw = target.encode('utf-8', 'strict')
            require(len(raw) <= 4096 and os.fsencode(target) == raw and row['size'] == len(raw)
                    and row['sha256'] == hashlib.sha256(raw).hexdigest()
                    and row['git_oid'] == hashlib.new('sha1' if len(head) == 40 else 'sha256',
                        b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest(),
                    'symlink supplement bytes or object identity differ')
    git_dirs = {PurePosixPath(path).parents[i].as_posix() for path in files
                for i in range(len(PurePosixPath(path).parents))} | {'.'}
    covered = set()
    for boundary in boundaries:
        checkpoint()
        covered.update(parent.as_posix() for parent in PurePosixPath(boundary).parents)
    for path, row in dirs.items():
        expected_origin = ('source_root' if path == '.' else 'git_ancestor' if path in git_dirs else 'excluded_container')
        require(row['origin'] == expected_origin, 'source directory origin differs from Git path graph')
        if expected_origin == 'excluded_container':
            require(path in covered, 'excluded container does not lead to an excluded boundary')
    fields_p = {'schema_version', 'source_manifest_sha256', 'source_supplement_sha256', 'source_head', 'source_mode_claim',
                'directories', 'entries', 'owner', 'attributes', 'limits', 'authority', 'status', 'qualification',
                'product_gate_effect'}
    require(isinstance(policy, dict) and set(policy) == fields_p and digest(policy) == policy_sha
            and policy['schema_version'] == 'forgeflow.ecp-normalization-policy.v1'
            and policy['source_manifest_sha256'] == manifest_sha and policy['source_supplement_sha256'] == supplement_sha
            and policy['source_head'] == head and policy['source_mode_claim'] == 'UNKNOWN'
            and policy['authority'] == 'UNVERIFIED' and policy['status'] == 'DRAFT'
            and policy['qualification'] == 'NOT_RUN' and policy['product_gate_effect'] == 'NONE', 'policy binding differs')
    require(policy['attributes'] == {'access_acl': 'ABSENT', 'default_acl': 'ABSENT', 'xattrs': 'NONE',
            'hardlinks': 'REJECT', 'symlinks': 'INTERNAL_PROJECTION_ONLY', 'umask': '0077'}, 'unsupported policy attributes')
    require(isinstance(policy['owner'], dict) and set(policy['owner']) == {'uid', 'gid'}
            and all(_type_int(policy['owner'][k], 2**32-2) for k in ('uid', 'gid')), 'invalid owner policy')
    limits = policy['limits']
    maxima = {'max_entries': MAX_ENTRIES, 'max_file_bytes': MAX_FILE, 'max_total_bytes': MAX_TOTAL, 'max_depth': MAX_DEPTH}
    require(isinstance(limits, dict) and set(limits) == set(maxima)
            and all(_type_int(limits[k], maxima[k]) and limits[k] > 0 for k in maxima), 'invalid policy limits')
    require(len(dirs) + len(files) <= limits['max_entries'] and sum(r['size'] for r in files.values()) <= limits['max_total_bytes'],
            'policy total budget exceeded')
    require(all(row['size'] <= limits['max_file_bytes'] for row in files.values())
            and all((0 if path == '.' else len(path.split('/'))) <= limits['max_depth']
                    for path in (*dirs, *files)), 'policy file or depth budget exceeded')
    pdirs = _check_sorted(policy['directories'], directories=True)
    pfiles = _check_sorted(policy['entries'])
    require(set(pdirs) == set(dirs) and set(pfiles) == set(files), 'policy path set differs')
    for path, row in pdirs.items():
        require(set(row) == {'path', 'mode'}, 'invalid directory policy')
        _mode(row['mode'], directory=True)
    for path, row in pfiles.items():
        require(set(row) == {'path', 'kind', 'mode'} and row['kind'] == files[path]['kind'], 'invalid file policy')
        if row['kind'] == 'symlink':
            require(row['mode'] is None, 'symlink mode must remain unspecified')
        else:
            _mode(row['mode'], git_mode=files[path]['git_mode'])
    validate_link_graph(files, dirs)
    return head, dirs, files, pdirs, pfiles, boundaries, limits


def _receipt_projection(directories, entries):
    """Reconstruct the materializer v1 list from this oracle's physical walk."""
    require(len(directories) + len(entries) <= RECEIPT_MAX_ENTRIES, 'receipt projection exceeds entry budget')
    result = []
    for path, row in directories.items():
        result.append({'path': path, 'kind': 'directory', 'mode': row['mode'], 'uid': row['uid'],
                       'gid': row['gid'], 'visible_xattrs': list(row['xattrs'])})
    for path, row in entries.items():
        item = {'path': path, 'kind': row['kind'], 'uid': row['uid'], 'gid': row['gid'],
                'nlink': row['signature'][-1], 'visible_xattrs': list(row['xattrs'])}
        if row['kind'] == 'file':
            item.update(mode=row['mode'], size=row['size'], sha256=row['sha256'])
        else:
            item['target'] = row['target']
        result.append(item)
    result.sort(key=lambda row: row['path'].encode('utf-8'))
    return result


def _receipt_v1_digest(value):
    """Independently enforce the producer's bounded canonical JSON subset."""
    pending, nodes = [(value, 0)], 0
    while pending:
        checkpoint()
        item, depth = pending.pop()
        nodes += 1
        require(nodes <= RECEIPT_MAX_NODES and depth <= RECEIPT_MAX_DEPTH, 'receipt projection shape exceeds budget')
        if type(item) is dict:
            require(len(item) <= RECEIPT_MAX_ENTRIES, 'receipt projection object exceeds budget')
            for key, child in item.items():
                require(type(key) is str and len(key.encode('utf-8', 'strict')) <= 4096,
                        'receipt projection key exceeds budget')
                pending.append((child, depth + 1))
        elif type(item) is list:
            require(len(item) <= RECEIPT_MAX_ENTRIES, 'receipt projection array exceeds budget')
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            require(len(item.encode('utf-8', 'strict')) <= 4096, 'receipt projection string exceeds budget')
        elif item is None or type(item) is bool:
            pass
        elif type(item) is int:
            require(0 <= item <= (1 << 63) - 1, 'receipt projection integer exceeds budget')
        else:
            raise Invalid('receipt projection contains unsupported value')
    h, size = hashlib.sha256(), 0
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    for chunk in encoder.iterencode(value):
        checkpoint()
        raw = chunk.encode('utf-8', 'strict')
        size += len(raw)
        require(size <= RECEIPT_MAX_JSON_BYTES, 'receipt projection JSON exceeds byte budget')
        h.update(raw)
    return h.hexdigest()


def _check_receipt(receipt, candidate, manifest_sha256, supplement_sha256, policy_sha256, directories, entries):
    """Check draft receipt consistency only; neither identity nor origin is authenticated."""
    fields = {'schema_version', 'status', 'qualification', 'product_gate_effect', 'source_mode_claim',
              'source_permissions_preserved', 'source_manifest_sha256', 'source_supplement_sha256',
              'policy_sha256', 'candidate_root', 'candidate_inventory_sha256', 'candidate_entry_count',
              'candidate_file_bytes', 'authority', 'sync_observation', 'continuous_sync_identity', 'limitations'}
    require(type(receipt) is dict and set(receipt) == fields, 'invalid draft receipt fields')
    require(receipt['schema_version'] == 'forgeflow.ecp-normalized-materialization.draft.v1'
            and receipt['status'] == 'OBSERVED_NOT_GATE' and receipt['qualification'] == 'NOT_RUN'
            and receipt['product_gate_effect'] == 'NONE' and receipt['authority'] == 'UNVERIFIED'
            and receipt['source_mode_claim'] == 'UNKNOWN' and receipt['source_permissions_preserved'] == 'UNKNOWN'
            and receipt['continuous_sync_identity'] == 'UNKNOWN', 'receipt claims unsupported qualification')
    require(receipt['source_manifest_sha256'] == manifest_sha256
            and receipt['source_supplement_sha256'] == supplement_sha256
            and receipt['policy_sha256'] == policy_sha256, 'receipt input binding differs')
    require(type(receipt['candidate_root']) is str and receipt['candidate_root'] == str(candidate),
            'receipt candidate path differs')
    require(type(receipt['candidate_entry_count']) is int
            and receipt['candidate_entry_count'] == len(directories) + len(entries)
            and type(receipt['candidate_file_bytes']) is int
            and receipt['candidate_file_bytes'] == sum(row['size'] for row in entries.values() if row['kind'] == 'file'),
            'receipt count or regular-file byte denominator differs')
    require(type(receipt['sync_observation']) is str and 0 < len(receipt['sync_observation']) <= 1024
            and type(receipt['limitations']) is list and 0 < len(receipt['limitations']) <= 32
            and all(type(item) is str and 0 < len(item) <= 1024 for item in receipt['limitations']),
            'invalid receipt informational fields')
    inventory_sha256 = _receipt_v1_digest(_receipt_projection(directories, entries))
    require(receipt['candidate_inventory_sha256'] == inventory_sha256, 'receipt candidate inventory differs')
    return inventory_sha256


def review_normalized(source, candidate, manifest_path, manifest_sha256, supplement_path, supplement_sha256,
                      policy_path, policy_sha256, *, receipt_path=None, receipt_sha256=None):
    """Review physical inputs; caller digest pins are not authentication."""
    source_fd = candidate_fd = None
    deadline = time.monotonic() + MAX_SCAN_SECONDS
    deadline_token = _DEADLINE.set(deadline)
    try:
        checkpoint()
        require((receipt_path is None) == (receipt_sha256 is None), 'receipt path and byte digest pin must be paired')
        source, source_fd = absolute_directory(source)
        candidate, candidate_fd = absolute_directory(candidate)
        require(source != candidate and source not in candidate.parents and candidate not in source.parents,
                'source and candidate paths overlap')
        before_source, before_candidate = signature(os.fstat(source_fd)), signature(os.fstat(candidate_fd))
        require((before_source[0], before_source[1]) != (before_candidate[0], before_candidate[1]),
                'source and candidate share a directory inode')
        smount, cmount = mount_binding(source, source_fd), mount_binding(candidate, candidate_fd)
        require(not (smount[0] == cmount[0] and (_is_beneath(smount[1], cmount[1]) or _is_beneath(cmount[1], smount[1]))),
                'source and candidate backing paths overlap')
        require(smount[2] not in ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'tmpfs', 'overlay', 'zfs'),
                'manifest claims source mode unavailable on a mode-observable filesystem')
        if cmount[2] not in ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'tmpfs', 'overlay', 'zfs'):
            raise Unknown('candidate filesystem permission semantics unavailable')
        seen = set()
        m = read_document(manifest_path, seen)
        s = read_document(supplement_path, seen)
        p = read_document(policy_path, seen)
        receipt = read_document(receipt_path, seen, raw_sha256=receipt_sha256) if receipt_path is not None else None
        head, dirs, files, pdirs, pfiles, boundaries, limits = validate_documents(
            m, manifest_sha256, s, supplement_sha256, p, policy_sha256, source)
        entries, fmt, index, flags = parse_git_inventory(source_fd, head, deadline)
        require(set(entries) == set(files) and all(entries[path] == (row['git_mode'], row['git_oid'])
                for path, row in files.items()), 'supplement and Git index differ')
        sd, sf, sb, sbytes, schildren = walk(source_fd, source=True, expected_files=files, expected_dirs=dirs,
                                  fmt=fmt, limits=limits, deadline=deadline)
        require(sb == set(boundaries), 'source exclusion boundaries differ')
        git_dirs = {PurePosixPath(path).parents[i].as_posix() for path in files
                    for i in range(len(PurePosixPath(path).parents))} | {'.'}
        origins = {'.': 'source_root'}
        for path in sorted((p for p in dirs if p != '.'), key=lambda p: (-p.count('/'), p.encode('utf-8'))):
            if path in git_dirs:
                origins[path] = 'git_ancestor'
            else:
                items = schildren[path]
                only_boundaries = bool(items) and all(kind == 'boundary' or
                    (kind == 'directory' and origins[child] == 'excluded_container') for kind, child in items)
                origins[path] = 'excluded_container' if only_boundaries else 'untracked_business'
            require(origins[path] == dirs[path]['origin'], 'source directory origin differs from observation')
        for path, actual in sf.items():
            expected = files[path]
            require(all(actual.get(k) == expected.get(k) for k in ('kind', 'size', 'git_oid', 'sha256'))
                    and (actual['kind'] != 'symlink' or actual['target'] == expected['target']),
                    'source bytes or type differ from independently pinned supplement')
        cd, cf, cb, cbytes, cchildren = walk(candidate_fd, source=False, expected_files=files, expected_dirs=dirs,
                                  fmt=fmt, limits=limits, deadline=deadline)
        require(not cb and cbytes == sbytes, 'candidate byte denominator differs')
        for path, actual in cd.items():
            require(actual['mode'] == pdirs[path]['mode'] and actual['uid'] == p['owner']['uid']
                    and actual['gid'] == p['owner']['gid'] and not actual['xattrs'], 'candidate directory policy differs')
        for path, actual in cf.items():
            expected = files[path]
            require(all(actual.get(k) == expected.get(k) for k in ('kind', 'size', 'git_oid', 'sha256'))
                    and actual['uid'] == p['owner']['uid'] and actual['gid'] == p['owner']['gid'] and not actual['xattrs'],
                    'candidate file content, identity or attributes differ')
            if actual['kind'] == 'file':
                require(actual['mode'] == pfiles[path]['mode'], 'candidate file mode differs')
            else:
                require(actual['target'] == expected['target'], 'candidate symlink differs')
        entries2, fmt2, index2, flags2 = parse_git_inventory(source_fd, head, deadline)
        require((entries2, fmt2, index2, flags2) == (entries, fmt, index, flags), 'source Git inventory changed')
        # Re-read both trees and compare full stat identities and contents. This
        # is not a continuous immutable snapshot or identity authentication.
        sd2, sf2, sb2, sbytes2, schildren2 = walk(source_fd, source=True, expected_files=files, expected_dirs=dirs,
                                      fmt=fmt, limits=limits, deadline=deadline)
        cd2, cf2, cb2, cbytes2, cchildren2 = walk(candidate_fd, source=False, expected_files=files, expected_dirs=dirs,
                                      fmt=fmt, limits=limits, deadline=deadline)
        require((sd, sf, sb, sbytes, schildren) == (sd2, sf2, sb2, sbytes2, schildren2)
                and (cd, cf, cb, cbytes, cchildren) == (cd2, cf2, cb2, cbytes2, cchildren2),
                'source or candidate changed during observation')
        if signature(os.fstat(source_fd)) != before_source or signature(os.fstat(candidate_fd)) != before_candidate:
            raise Unknown('held root changed during observation')
        if mount_binding(source, source_fd) != smount or mount_binding(candidate, candidate_fd) != cmount:
            raise Unknown('root mount changed during observation')
        # Document handles are not held throughout this experimental API;
        # matching re-read digests provide endpoint checks only.
        seen2 = set()
        m2, s2, p2 = (read_document(x, seen2) for x in (manifest_path, supplement_path, policy_path))
        require((m2, s2, p2) == (m, s, p), 'evidence documents changed during observation')
        if receipt_path is not None:
            receipt2 = read_document(receipt_path, seen2, raw_sha256=receipt_sha256)
            require(receipt2 == receipt, 'receipt changed during observation')
            receipt_inventory_sha256 = _check_receipt(receipt, candidate, manifest_sha256, supplement_sha256,
                                                     policy_sha256, cd, cf)
        inventory = {'directories': [{'path': path, 'mode': cd[path]['mode'], 'uid': cd[path]['uid'], 'gid': cd[path]['gid'],
                                      'visible_xattrs': list(cd[path]['xattrs'])}
                                     for path in sorted(cd, key=lambda x: x.encode('utf-8'))],
                     'entries': [{'path': path, 'kind': cf[path]['kind'], 'sha256': cf[path]['sha256'],
                                  'git_oid': cf[path]['git_oid'], 'size': cf[path]['size'],
                                  'mode': pfiles[path]['mode'], 'uid': cf[path]['uid'], 'gid': cf[path]['gid'],
                                  'nlink': cf[path]['signature'][-1], 'visible_xattrs': list(cf[path]['xattrs']),
                                  **({'target': cf[path]['target']} if cf[path]['kind'] == 'symlink' else {})}
                                 for path in sorted(cf, key=lambda x: x.encode('utf-8'))]}
        regular_bytes = sum(row['size'] for row in cf.values() if row['kind'] == 'file')
        symlink_target_bytes = sum(row['size'] for row in cf.values() if row['kind'] == 'symlink')
        require(regular_bytes + symlink_target_bytes == cbytes, 'candidate byte categories do not reconcile')
        result = {'status': 'OBSERVED_NOT_GATE', 'qualification': 'NOT_RUN', 'product_gate_effect': 'NONE',
                'source_manifest_sha256': manifest_sha256, 'source_supplement_sha256': supplement_sha256,
                'policy_sha256': policy_sha256, 'source_head': head, 'source_permissions_preserved': 'UNKNOWN',
                'candidate_inventory_projection_sha256': digest(inventory),
                'candidate_inventory_projection_scope': 'paths, kinds, blob hashes and sizes, policy modes, uid/gid, link count, visible xattrs and link targets; excludes inode, timestamps and mount identities',
                'denominator': {'directories': len(dirs), 'entries': len(files), 'bytes': cbytes,
                                'regular_file_bytes': regular_bytes, 'symlink_target_bytes': symlink_target_bytes,
                                'bytes_scope': 'regular_file_bytes_plus_symlink_target_bytes'},
                'limitations': ['endpoint observations are not atomic or continuous',
                                'source, policy, execution principal and lease are not authenticated',
                                'Git index physical identity and excluded execution inputs are not authenticated',
                                'xattr visibility is limited to the observing process',
                                'deadline is cooperative; a blocking filesystem or JSON call can exceed it',
                                'no filesystem equivalence, execution isolation, build or product Gate proven']}
        if receipt_path is not None:
            result['receipt_consistency'] = {'status': 'CONSISTENT_DRAFT', 'receipt_sha256': receipt_sha256,
                                             'candidate_inventory_sha256': receipt_inventory_sha256,
                                             'authority': 'UNVERIFIED', 'qualification': 'NOT_RUN',
                                             'product_gate_effect': 'NONE'}
            result['limitations'].extend([
                'receipt consistency does not authenticate its origin, publication or execution authority',
                'receipt v1 does not bind inode, mount or nonce; same-path same-content historical replay remains unknown',
                'receipt sync and limitation text are unverified self-reports'])
    except Invalid as exc:
        result = {'status': 'FAIL', 'qualification': 'NOT_RUN', 'product_gate_effect': 'NONE', 'reason': str(exc)}
    except (Unknown, OSError, UnicodeError, ValueError, TypeError, RecursionError, subprocess.SubprocessError) as exc:
        result = {'status': 'INCONCLUSIVE', 'qualification': 'NOT_RUN', 'product_gate_effect': 'NONE',
                  'reason_type': type(exc).__name__, 'reason': 'required observation could not be completed'}
    finally:
        close_failed = False
        for fd in (candidate_fd, source_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    close_failed = True
        _DEADLINE.reset(deadline_token)
    if close_failed:
        return {'status': 'INCONCLUSIVE', 'qualification': 'NOT_RUN', 'product_gate_effect': 'NONE',
                'reason': 'held directory descriptor closure could not be confirmed'}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'candidate', 'manifest', 'manifest-sha256', 'supplement', 'supplement-sha256',
                 'policy', 'policy-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--receipt')
    parser.add_argument('--receipt-sha256', help='independent SHA-256 pin of the exact receipt file bytes')
    args = parser.parse_args(argv)
    result = review_normalized(args.source, args.candidate, args.manifest, args.manifest_sha256,
                               args.supplement, args.supplement_sha256, args.policy, args.policy_sha256,
                               receipt_path=args.receipt, receipt_sha256=args.receipt_sha256)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return {'OBSERVED_NOT_GATE': 0, 'FAIL': 10, 'INCONCLUSIVE': 20}[result['status']]


if __name__ == '__main__':
    sys.exit(main())

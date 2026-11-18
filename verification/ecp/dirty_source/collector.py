"""Research dirty-source collector: no subprocess creation or source writes.

Caller supplies a trusted bounded Git runner bound to the same opened root FD.
The caller must isolate and supervise it and disable Git's optional index locks.
This collector is not a Git runner, snapshot, authorization, or Gate decision.
"""
import hashlib
import os
import re
import stat

MAX_ENTRIES = 4096
MAX_PATH = 4096
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_META = 4 * 1024 * 1024
MAX_DEPTH = 128

class Incomplete(ValueError):
    pass

def sig(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def git_blob(data, algorithm):
    return hashlib.new(algorithm, b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest().encode('ascii')

def path_ok(p):
    if type(p) is not bytes or not p or len(p) > MAX_PATH:
        raise Incomplete('INVALID_PATH')
    if any(part in (b'', b'.', b'..') or b'\0' in part or part.lower() == b'.git' for part in p.split(b'/')):
        raise Incomplete('UNSAFE_PATH')

def _rows(raw, tree, hash_len):
    if type(raw) is not bytes or len(raw) > MAX_META or (raw and not raw.endswith(b'\0')):
        raise Incomplete('GIT_ROWS_INVALID')
    result = {}
    rows = raw[:-1].split(b'\0') if raw else []
    if any(not row for row in rows): raise Incomplete('GIT_ROWS_INVALID')
    for row in rows:
        meta, sep, path = row.partition(b'\t')
        fields = meta.split(b' ')
        if not sep or len(fields) != 3: raise Incomplete('GIT_ROW_SHAPE')
        mode, kind_or_oid, oid_or_stage = fields
        if tree:
            kind, oid = kind_or_oid, oid_or_stage
            if kind != b'blob': raise Incomplete('UNSUPPORTED_TREE_TYPE')
        else:
            oid, stage = kind_or_oid, oid_or_stage
            if stage != b'0': raise Incomplete('UNMERGED_INDEX')
        path_ok(path)
        if mode not in (b'100644', b'100755', b'120000') or not re.fullmatch(b'[0-9a-f]{%d}' % hash_len, oid):
            raise Incomplete('UNSUPPORTED_MODE_OR_OID')
        if path in result: raise Incomplete('DUPLICATE_PATH')
        result[path] = (mode, oid)
        if len(result) > MAX_ENTRIES: raise Incomplete('ENTRY_LIMIT')
    return result

def _run(runner, args, limit):
    # runner must enforce deadline, bounded stdout/stderr, pidfd supervision and
    # sanitized env, and raise on nonzero exit. It is external to this module.
    try: data = runner(tuple(args), limit)
    except Exception as exc: raise Incomplete('GIT_RUNNER_FAILURE') from exc
    if type(data) is not bytes or len(data) > limit: raise Incomplete('GIT_OUTPUT_LIMIT')
    return data

def _git_state(runner):
    rawhead = _run(runner, ('rev-parse', '--verify', 'HEAD^{commit}'), 128)
    if not re.fullmatch(b'(?:[0-9a-f]{40}|[0-9a-f]{64})\n', rawhead): raise Incomplete('HEAD_INVALID')
    head = rawhead[:-1]
    tree = _run(runner, ('ls-tree', '-rz', '--full-tree', head.decode('ascii')), MAX_META)
    index = _run(runner, ('ls-files', '--stage', '-z'), MAX_META)
    flags = _run(runner, ('ls-files', '-v', '-z'), MAX_META)
    h, i = _rows(tree, True, len(head)), _rows(index, False, len(head))
    if flags and not flags.endswith(b'\0'): raise Incomplete('FLAGS_INVALID')
    seen = set()
    flag_rows = flags[:-1].split(b'\0') if flags else []
    if any(not row for row in flag_rows): raise Incomplete('FLAGS_INVALID')
    for row in flag_rows:
        if not row.startswith(b'H '): raise Incomplete('INDEX_VISIBILITY_UNSUPPORTED')
        path = row[2:]; path_ok(path)
        if path in seen: raise Incomplete('DUPLICATE_FLAG')
        seen.add(path)
    if seen != set(i): raise Incomplete('INDEX_FLAGS_MISMATCH')
    return head, tree, index, flags, h, i

def _objects(runner, entries, algorithm):
    result = {}; cache = {}; total = 0
    for path, (mode, oid) in sorted(entries.items()):
        if oid not in cache:
            data = _run(runner, ('cat-file', 'blob', oid.decode('ascii')), MAX_FILE)
            if git_blob(data, algorithm) != oid: raise Incomplete('GIT_BLOB_MISMATCH')
            cache[oid] = data
        data = cache[oid]; total += len(data)
        if total > MAX_TOTAL: raise Incomplete('GIT_CONTENT_LIMIT')
        result[path] = ('symlink' if mode == b'120000' else 'file', mode.decode('ascii'), data)
    return result

def _scan(rootfd, exec_mode):
    """Two callers can compare independent bounded scans; root FD never owned."""
    root = os.fstat(rootfd)
    if not stat.S_ISDIR(root.st_mode): raise Incomplete('ROOT_NOT_DIRECTORY')
    paths = {}; empty = []; count = [0]; total = [0]; git_present = [False]
    def visit(fd, prefix, depth):
        if depth > MAX_DEPTH: raise Incomplete('DEPTH_LIMIT')
        start = sig(os.fstat(fd))
        names = []
        try:
            with os.scandir(fd) as stream:
                for item in stream:
                    count[0] += 1
                    if count[0] > MAX_ENTRIES: raise Incomplete('ENTRY_LIMIT')
                    names.append(os.fsencode(item.name))
        except (OSError, UnicodeError) as exc: raise Incomplete('READ_DIRECTORY_FAILED') from exc
        if len(names) != len(set(names)): raise Incomplete('DUPLICATE_DIRECTORY_ENTRY')
        names.sort()
        children = 0
        for name in names:
            if prefix == b'' and name == b'.git':
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode): raise Incomplete('GIT_DIR_UNSUPPORTED')
                if info.st_dev != root.st_dev: raise Incomplete('GIT_DIRECTORY_MOUNT_UNSUPPORTED')
                git_present[0] = True
                continue
            if name.lower() == b'.git': raise Incomplete('NESTED_GIT_UNSUPPORTED')
            path = prefix + name; path_ok(path); children += 1
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if info.st_dev != root.st_dev: raise Incomplete('MOUNT_BOUNDARY_UNSUPPORTED')
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=fd)
                try:
                    if sig(os.fstat(child)) != sig(info): raise Incomplete('DIRECTORY_CHANGED')
                    visit(child, path + b'/', depth + 1)
                    if sig(os.stat(name, dir_fd=fd, follow_symlinks=False)) != sig(info): raise Incomplete('DIRECTORY_CHANGED')
                finally: os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1 or info.st_size > MAX_FILE: raise Incomplete('FILE_UNSUPPORTED_OR_LIMIT')
                child = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK, dir_fd=fd)
                try:
                    if sig(os.fstat(child)) != sig(info): raise Incomplete('FILE_CHANGED')
                    parts=[]; amount=0
                    while True:
                        part=os.read(child, min(65536, MAX_FILE + 1 - amount))
                        if not part: break
                        amount += len(part)
                        if amount > MAX_FILE: raise Incomplete('FILE_LIMIT')
                        parts.append(part)
                    if sig(os.fstat(child)) != sig(info) or sig(os.stat(name, dir_fd=fd, follow_symlinks=False)) != sig(info): raise Incomplete('FILE_CHANGED')
                finally: os.close(child)
                raw=b''.join(parts)
                if len(raw) != info.st_size: raise Incomplete('FILE_SHORT_READ')
                total[0] += len(raw)
                if total[0] > MAX_TOTAL: raise Incomplete('WORKTREE_LIMIT')
                mode = ('100755' if info.st_mode & 0o100 else '100644') if exec_mode else None
                paths[path]=('file',mode,raw)
            elif stat.S_ISLNK(info.st_mode):
                if info.st_nlink != 1: raise Incomplete('SYMLINK_HARDLINK_UNSUPPORTED')
                target=os.readlink(name, dir_fd=fd); raw=os.fsencode(target)
                if sig(os.stat(name, dir_fd=fd, follow_symlinks=False)) != sig(info): raise Incomplete('SYMLINK_CHANGED')
                total[0] += len(raw)
                if total[0] > MAX_TOTAL: raise Incomplete('WORKTREE_LIMIT')
                paths[path]=('symlink','120000',raw)
            else: raise Incomplete('SPECIAL_FILE_UNSUPPORTED')
        if not children and prefix: empty.append(prefix[:-1])
        if sig(os.fstat(fd)) != start: raise Incomplete('DIRECTORY_CHANGED')
    visit(rootfd,b'',0)
    if not git_present[0]: raise Incomplete('GIT_DIR_MISSING')
    if empty: raise Incomplete('EMPTY_DIRECTORY_UNSUPPORTED')
    if sig(os.fstat(rootfd)) != sig(root): raise Incomplete('ROOT_CHANGED')
    return paths

def collect(rootfd, runner, model, *, executable_mode_observed, unsupported_features_excluded):
    """Collect via open root FD and caller-supervised Git; raises on uncertainty.

    runner(args, max_stdout_bytes) must be bound to exactly this root, sanitize
    the environment/config, refuse any write and independently supervise all
    children. It must return captured bytes only after known exit 0; otherwise
    it must raise. No external identity or atomicity is established here.
    """
    if type(executable_mode_observed) is not bool: raise Incomplete('MODE_POLICY_INVALID')
    if unsupported_features_excluded is not True: raise Incomplete('FEATURE_ADMISSION_UNAVAILABLE')
    if not callable(runner) or not callable(getattr(model,'create',None)): raise Incomplete('CALLER_INVALID')
    try:
        before = _git_state(runner)
        algorithm = 'sha1' if len(before[0]) == 40 else 'sha256'
        head = _objects(runner,before[4],algorithm)
        index = _objects(runner,before[5],algorithm)
        first = _scan(rootfd,executable_mode_observed)
        second = _scan(rootfd,executable_mode_observed)
        after = _git_state(runner)
        if before[:4] != after[:4] or first != second: raise Incomplete('SOURCE_CHANGED')
        tracked = {p:value for p,value in first.items() if p in index}
        untracked = {p:value for p,value in first.items() if p not in index}
        result = model.create(head_commit=before[0].decode('ascii'), head=head, index=index,
            tracked_worktree=tracked, untracked=untracked, excluded={},
            coverage_claims={'head':True,'index':True,'worktree':True,'exclusions':False})
        return {'status':'OBSERVED_RESEARCH_ONLY','qualification':'NOT_RUN','product_gate_effect':'NONE',
                'source_authentication':'UNVERIFIED','snapshot_atomicity':'UNKNOWN',
                'runner_binding':'CALLER_UNVERIFIED','feature_exclusion_authority':'CALLER_UNVERIFIED','mode_policy':'OBSERVED_CLAIM' if executable_mode_observed else 'UNAVAILABLE',
                'access_time_impact':'POSSIBLE','included_git_ignored':'SCANNED_WITHOUT_GIT_EXCLUSIONS',
                'unsupported':'LINKED_WORKTREES,SUBMODULES,SPARSE,INDEX_FLAGS,EMPTY_DIRECTORIES,FILTERS,CONCURRENT_WRITERS',
                'declaration':result}
    except Incomplete: raise
    except (OSError, UnicodeError, ValueError, OverflowError) as exc: raise Incomplete('OBSERVATION_INCOMPLETE') from exc

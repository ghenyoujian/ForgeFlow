"""Research-only dirty declaration materializer; no subprocess is launched here.

Requires a caller-created, private, empty directory FD and a caller-provided
isolated Git runner bound to that same directory. Neither claim is authenticated.
Unsupported input or any failure raises; a partially created target is retained.
This is not a product collector, source authority or G0 qualification.
"""
import base64
import hashlib
import json
import os
import re
import resource
import stat

MAX_ROWS = 4096
MAX_PATH_BYTES = 4096
MAX_DEPTH = 128
MAX_TOTAL_PATH_BYTES = 2 * 1024 * 1024
MAX_BLOB = 8 * 1024 * 1024
MAX_TOTAL_CONTENT = 32 * 1024 * 1024
MAX_COMMANDS = 10000
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_JSON_NODES = 100_000
MAX_JSON_STRING_CHARS = 8192
MAX_COMMIT_BYTES = 2 * 1024 * 1024
MAX_OPEN_DIRECTORIES = 1024
MAX_EXISTING_FDS = 4096
FD_RESERVE = 16
MAX_COMPONENT_BYTES = 255
MAX_SYMLINK_TARGET_BYTES = 4095


class MaterializeError(ValueError):
    """code and phase identify the failure; partial output may remain."""
    def __init__(self, code, phase='VALIDATE', *, close_outcomes=()):
        self.code = code
        self.phase = phase
        self.close_outcomes = tuple(close_outcomes)
        self.partial_target = phase in ('GIT', 'WORKTREE')
        self.outcome = 'INCONCLUSIVE' if self.partial_target else 'REJECTED_BEFORE_MUTATION'
        super().__init__(code)


def _canonical(value):
    # Bound JSON shape and each scalar before the encoder can allocate a large
    # temporary string; caller-owned objects themselves already exist.
    stack = [(value, 0)]; nodes = 0
    while stack:
        item, depth = stack.pop(); nodes += 1
        if nodes > MAX_JSON_NODES or depth > 16:
            raise MaterializeError('MANIFEST_BUDGET_EXCEEDED')
        if type(item) is dict:
            if len(item) > MAX_ROWS * 2: raise MaterializeError('MANIFEST_BUDGET_EXCEEDED')
            for key, child in item.items():
                if type(key) is not str or len(key) > MAX_JSON_STRING_CHARS:
                    raise MaterializeError('MANIFEST_ENCODING_INVALID')
                stack.append((child, depth + 1))
        elif type(item) is list:
            if len(item) > MAX_ROWS * 2: raise MaterializeError('MANIFEST_BUDGET_EXCEEDED')
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > MAX_JSON_STRING_CHARS: raise MaterializeError('MANIFEST_BUDGET_EXCEEDED')
        elif item is None or type(item) in (bool, int):
            if type(item) is int and item.bit_length() > 63: raise MaterializeError('MANIFEST_BUDGET_EXCEEDED')
        else:
            raise MaterializeError('MANIFEST_ENCODING_INVALID')
    try:
        chunks = []; size = 0
        for chunk in json.JSONEncoder(sort_keys=True, ensure_ascii=True,
                                      separators=(',', ':'), allow_nan=False).iterencode(value):
            size += len(chunk)
            if size > MAX_MANIFEST_BYTES: raise MaterializeError('MANIFEST_BUDGET_EXCEEDED')
            chunks.append(chunk)
        return ''.join(chunks).encode('ascii')
    except MaterializeError:
        raise
    except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
        raise MaterializeError('MANIFEST_ENCODING_INVALID') from exc


def _decode_path(value):
    if type(value) is not str or len(value) > 4 * ((MAX_PATH_BYTES + 2) // 3):
        raise MaterializeError('PATH_INVALID')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise MaterializeError('PATH_INVALID') from exc
    parts = raw.split(b'/')
    if (not raw or len(raw) > MAX_PATH_BYTES or len(parts) > MAX_DEPTH or
        base64.b64encode(raw).decode('ascii') != value or
        any(p in (b'', b'.', b'..') or b'\0' in p or p.lower() == b'.git' for p in parts)):
        raise MaterializeError('PATH_INVALID')
    return raw


def _decode_rows(rows, blobs, *, allow_unknown=False):
    if type(rows) is not list or len(rows) > MAX_ROWS:
        raise MaterializeError('ROWS_INVALID')
    expected = {'path_b64', 'kind', 'mode', 'byte_count', 'sha256', 'computed_git_blob_oid'}
    result = {}
    path_total = content_total = 0
    for row in rows:
        if type(row) is not dict or set(row) != expected:
            raise MaterializeError('ROW_INVALID')
        path = _decode_path(row['path_b64'])
        if path in result:
            raise MaterializeError('DUPLICATE_PATH')
        path_total += len(path)
        if path_total > MAX_TOTAL_PATH_BYTES:
            raise MaterializeError('PATH_BUDGET_EXCEEDED')
        kind, mode, size, digest = (row[k] for k in ('kind', 'mode', 'byte_count', 'sha256'))
        if (kind, mode) not in (('file', '100644'), ('file', '100755'), ('symlink', '120000')):
            if allow_unknown and kind == 'file' and mode is None:
                raise MaterializeError('WORKTREE_MODE_UNAVAILABLE')
            raise MaterializeError('MODE_OR_KIND_UNSUPPORTED')
        if (type(size) is not int or size < 0 or size > MAX_BLOB or
            type(digest) is not str or not re.fullmatch(r'[0-9a-f]{64}', digest)):
            raise MaterializeError('BLOB_REFERENCE_INVALID')
        data = blobs.get(digest)
        if (type(data) is not bytes or len(data) != size or
            hashlib.sha256(data).hexdigest() != digest):
            raise MaterializeError('BLOB_CONTENT_MISMATCH')
        if kind == 'symlink' and (not data or b'\0' in data):
            raise MaterializeError('SYMLINK_TARGET_INVALID')
        content_total += len(data)
        if content_total > MAX_TOTAL_CONTENT:
            raise MaterializeError('CONTENT_BUDGET_EXCEEDED')
        result[path] = (kind, mode, data)
    return result, path_total, content_total


def prepare(manifest, manifest_sha256, blobs, commit_raw, model, head_object):
    """Validate all supplied data and return a private in-memory execution plan.

    True completeness and freshness are caller claims only. Exclusions and
    unknown worktree modes are rejected so this does not silently invent data.
    History and parent objects are not included or claimed to be complete.
    """
    if (type(manifest) is not dict or type(blobs) is not dict or len(blobs) > MAX_ROWS or
        type(commit_raw) is not bytes or len(commit_raw) > MAX_COMMIT_BYTES):
        raise MaterializeError('INPUT_INVALID')
    if (type(manifest_sha256) is not str or not re.fullmatch(r'[0-9a-f]{64}', manifest_sha256) or
        hashlib.sha256(_canonical(manifest)).hexdigest() != manifest_sha256):
        raise MaterializeError('MANIFEST_DIGEST_MISMATCH')
    if manifest.get('schema') != 'forgeflow.ecp-dirty-source-declaration.research.v1':
        raise MaterializeError('SCHEMA_UNSUPPORTED')
    if type(manifest.get('excluded')) is not list or manifest['excluded']:
        raise MaterializeError('EXCLUSION_UNSUPPORTED')
    coverage = manifest.get('coverage_claims')
    if (type(coverage) is not dict or set(coverage) != {'head','index','worktree','exclusions'} or
        any(type(v) is not bool for v in coverage.values()) or
        any(coverage[k] is not True for k in ('head','index','worktree'))):
        raise MaterializeError('PROJECTION_INCOMPLETE_CLAIM')
    maps = {}
    paths_total = content_total = rows_total = 0
    for label in ('head', 'index', 'tracked_worktree', 'untracked'):
        rows = manifest.get(label)
        entries, paths, content = _decode_rows(rows, blobs, allow_unknown=label in ('tracked_worktree','untracked'))
        maps[label] = entries
        rows_total += len(entries); paths_total += paths; content_total += content
        if rows_total > MAX_ROWS or paths_total > MAX_TOTAL_PATH_BYTES or content_total > MAX_TOTAL_CONTENT:
            raise MaterializeError('AGGREGATE_BUDGET_EXCEEDED')
    used = {hashlib.sha256(item[2]).hexdigest() for entries in maps.values() for item in entries.values()}
    if set(blobs) != used:
        raise MaterializeError('BLOB_SET_MISMATCH')
    try:
        reconstructed = model.create(head_commit=manifest.get('head_commit_claim'),
            head=maps['head'], index=maps['index'], tracked_worktree=maps['tracked_worktree'],
            untracked=maps['untracked'], excluded={}, coverage_claims=coverage)
    except Exception as exc:
        raise MaterializeError('MODEL_REJECTED') from exc
    if (type(reconstructed) is not dict or reconstructed.get('manifest') != manifest or
        reconstructed.get('manifest_sha256') != manifest_sha256 or reconstructed.get('blobs') != blobs):
        raise MaterializeError('DECLARATION_RECONSTRUCTION_MISMATCH')
    try:
        verified = head_object.verify(manifest, blobs, commit_raw)
        evidence = verified['evidence']
        if (evidence['commit_oid'] != manifest['head_commit_claim'] or
            evidence['object_format_claim'] != manifest['git_object_format_claim']):
            raise ValueError('head mismatch')
        tree_bodies = {}
        for oid, encoded in evidence['trees_base64'].items():
            if type(oid) is not str or type(encoded) is not str:
                raise ValueError('bad tree')
            body = base64.b64decode(encoded, validate=True)
            if base64.b64encode(body).decode('ascii') != encoded:
                raise ValueError('noncanonical tree')
            algorithm = manifest['git_object_format_claim']
            actual = hashlib.new(algorithm, b'tree ' + str(len(body)).encode('ascii') + b'\0' + body).hexdigest()
            if actual != oid:
                raise ValueError('tree oid mismatch')
            tree_bodies[oid] = body
    except Exception as exc:
        raise MaterializeError('HEAD_OBJECT_REJECTED') from exc
    algorithm = manifest['git_object_format_claim']
    required_oids = {}
    for label in ('head', 'index'):
        for _path, (_kind, _mode, data) in maps[label].items():
            oid = hashlib.new(algorithm, b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()
            if oid in required_oids and required_oids[oid] != data:
                raise MaterializeError('GIT_OID_COLLISION')
            required_oids[oid] = data
    commands = [(('init','--quiet','--object-format='+algorithm,'--template=/empty','.'), b'', b'')]
    for oid, data in sorted(required_oids.items()):
        commands.append((('hash-object','-w','-t','blob','--stdin'), data, (oid+'\n').encode('ascii')))
    for oid, data in sorted(tree_bodies.items()):
        commands.append((('hash-object','-w','-t','tree','--stdin'), data, (oid+'\n').encode('ascii')))
    commands.append((('hash-object','-w','-t','commit','--stdin'), commit_raw,
                     (manifest['head_commit_claim']+'\n').encode('ascii')))
    commands.append((('update-ref','HEAD',manifest['head_commit_claim']), b'', b''))
    commands.append((('read-tree','--empty'), b'', b''))
    index_data = b''.join(mode.encode('ascii') + b' ' +
        hashlib.new(algorithm,b'blob '+str(len(data)).encode('ascii')+b'\0'+data).hexdigest().encode('ascii') +
        b' 0\t' + path + b'\0' for path, (_kind,mode,data) in sorted(maps['index'].items()))
    commands.append((('update-index','-z','--index-info'), index_data, b''))
    if len(commands) > MAX_COMMANDS:
        raise MaterializeError('COMMAND_BUDGET_EXCEEDED')
    return {'manifest_sha256':manifest_sha256, 'head_commit':manifest['head_commit_claim'],
            'algorithm':algorithm, 'commands':commands,
            'worktree':{**maps['tracked_worktree'], **maps['untracked']},
            'index_count':len(maps['index']), 'head_count':len(maps['head']),
            'untracked_count':len(maps['untracked']),
            'scope':'CALLER_DECLARATION_ONLY', 'qualification':'NOT_RUN',
            'product_gate_effect':'NONE', 'completeness_authority':'UNVERIFIED',
            'exclusion_completeness_claim':coverage['exclusions'],
            'exclusion_coverage_state':'UNVERIFIED' if coverage['exclusions'] else 'UNKNOWN',
            'history_completeness':'NOT_MEASURED'}


def _sig(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _empty_private_root(rootfd):
    info = os.fstat(rootfd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise MaterializeError('ROOT_NOT_PRIVATE_DIRECTORY', 'ROOT_PREFLIGHT')
    with os.scandir(rootfd) as stream:
        if next(stream, None) is not None:
            raise MaterializeError('ROOT_NOT_EMPTY', 'ROOT_PREFLIGHT')
    if _sig(os.fstat(rootfd)) != _sig(info):
        raise MaterializeError('ROOT_CHANGED', 'ROOT_PREFLIGHT')
    return info


def _count_open_descriptors():
    # Count the proc enumeration FD too, a conservative extra slot.  If proc
    # cannot be inspected or the count exceeds our bound, refuse before Git.
    count = 0
    try:
        with os.scandir('/proc/self/fd') as stream:
            for _ in stream:
                count += 1
                if count > MAX_EXISTING_FDS:
                    raise MaterializeError('FD_INVENTORY_LIMIT', 'ROOT_PREFLIGHT')
    except MaterializeError:
        raise
    except OSError as exc:
        raise MaterializeError('FD_INVENTORY_UNAVAILABLE', 'ROOT_PREFLIGHT') from exc
    return count


def _resource_preflight(rootfd, worktree):
    # Repeated path prefixes are adjacent in byte sort order; calculate distinct
    # directory FDs without storing every prefix or expanding to O(depth²).
    previous = (); directory_count = 0
    try:
        name_max = os.fpathconf(rootfd, 'PC_NAME_MAX')
        symlink_max = os.fpathconf(rootfd, 'PC_SYMLINK_MAX')
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError) as exc:
        raise MaterializeError('TARGET_LIMITS_UNAVAILABLE', 'ROOT_PREFLIGHT') from exc
    if type(name_max) is not int or type(symlink_max) is not int or name_max == 0 or name_max < -1 or symlink_max == 0 or symlink_max < -1:
        raise MaterializeError('TARGET_LIMITS_INVALID', 'ROOT_PREFLIGHT')
    if name_max == -1:
        raise MaterializeError('TARGET_LIMITS_UNAVAILABLE', 'ROOT_PREFLIGHT')
    component_limit = min(name_max, MAX_COMPONENT_BYTES)
    # The fixed budget bounds inputs; it is not evidence of an OS limit.
    target_limit = min(symlink_max, MAX_SYMLINK_TARGET_BYTES) if symlink_max > 0 else MAX_SYMLINK_TARGET_BYTES
    for path, (kind, _mode, data) in sorted(worktree.items()):
        parts = tuple(path.split(b'/'))
        if any(len(part) > component_limit for part in parts):
            raise MaterializeError('TARGET_COMPONENT_LIMIT', 'ROOT_PREFLIGHT')
        if kind == 'symlink' and len(data) > target_limit:
            raise MaterializeError('TARGET_SYMLINK_LIMIT', 'ROOT_PREFLIGHT')
        parents = parts[:-1]; common = 0
        while common < len(previous) and common < len(parents) and previous[common] == parents[common]:
            common += 1
        directory_count += len(parents) - common
        if directory_count > MAX_OPEN_DIRECTORIES:
            raise MaterializeError('DIRECTORY_FD_BUDGET', 'ROOT_PREFLIGHT')
        previous = parents
    # A leaf file and a directory enumeration can each use one descriptor.
    # Runner is external and may use more than the reserve: still a caller
    # responsibility, and dynamic limit changes remain unverified.
    existing = _count_open_descriptors()
    required_extra = directory_count + 2 + FD_RESERVE
    if soft != resource.RLIM_INFINITY and (type(soft) is not int or soft < 0 or existing + required_extra > soft):
        raise MaterializeError('DIRECTORY_FD_BUDGET', 'ROOT_PREFLIGHT')
    return {'directory_fds':directory_count, 'observed_open_fds_including_scan':existing,
            'reserved_fds':FD_RESERVE, 'soft_nofile':None if soft == resource.RLIM_INFINITY else soft,
            'component_limit':component_limit,
            'symlink_target_input_budget':MAX_SYMLINK_TARGET_BYTES,
            'symlink_target_effective_preflight_limit':target_limit,
            'symlink_target_filesystem_limit':symlink_max if symlink_max > 0 else None,
            'component_limit_authority':'F_PATHCONF',
            'symlink_limit_authority':'F_PATHCONF' if symlink_max > 0 else 'UNKNOWN',
            'dynamic_fd_and_filesystem_limits':'UNVERIFIED'}


def _close_once(fd, kind, ordinal, outcomes):
    state = 'CLOSED'; exception_type = None; interruption = None
    try:
        os.close(fd)
    except BaseException as exc:
        # Even an asynchronous exception leaves close outcome indeterminate;
        # never retry this fd number, and continue every other close attempt.
        state = 'UNKNOWN'; exception_type = type(exc).__name__
        if not isinstance(exc, Exception): interruption = exc
    outcomes.append({'kind':kind, 'ordinal':ordinal, 'state':state,
                     'exception_type':exception_type})
    return state, interruption


def _write_all(fd, data):
    pos = 0
    while pos < len(data):
        n = os.write(fd, data[pos:])
        if n <= 0 or n > len(data) - pos:
            raise OSError('invalid write count')
        pos += n


def materialize(rootfd, manifest, manifest_sha256, blobs, commit_raw, model, head_object, runner, *, fresh_root_asserted):
    """Apply a validated plan to a new empty root; never cleans on error.

    Runner signature: ``runner(args: tuple[str,...], stdin: bytes, max_stdout:
    int) -> bytes``. It MUST be bound to exactly rootfd, use a private empty
    template at /empty, restrict commands to those supplied, sanitize Git env,
    supervise children and prove external containment. This function cannot
    establish these properties; they are unverified caller responsibilities.
    Caller must supply trusted model/head verifier objects, prevent mutation of
    inputs during the call and exclude hostile concurrent writers. Symlink
    targets are restored as opaque bytes and must not be followed by the caller.
    On any exception a new/partial Git directory and worktree may remain.
    """
    if fresh_root_asserted is not True or not callable(runner):
        raise MaterializeError('CALLER_ADMISSION_UNAVAILABLE', 'ROOT_PREFLIGHT')
    plan = prepare(manifest, manifest_sha256, blobs, commit_raw, model, head_object)
    try:
        before = _empty_private_root(rootfd)
    except MaterializeError:
        raise
    except OSError as exc:
        raise MaterializeError('ROOT_PREFLIGHT_UNKNOWN', 'ROOT_PREFLIGHT') from exc
    limits = _resource_preflight(rootfd, plan['worktree'])
    commands = plan.get('commands')
    if type(commands) is not list or not commands or len(commands) > MAX_COMMANDS:
        raise MaterializeError('PLAN_INVALID', 'ROOT_PREFLIGHT')
    for args, input_data, expected in commands:
        try:
            got = runner(args, input_data, max(128, len(expected)))
        except BaseException as exc:
            if isinstance(exc, Exception):
                raise MaterializeError('RUNNER_FAILED_PARTIAL_TARGET', 'GIT') from exc
            exc.materializer_outcome = 'INCONCLUSIVE'
            exc.materializer_partial_target = 'UNKNOWN'
            raise
        if type(got) is not bytes or got != expected:
            raise MaterializeError('RUNNER_OUTPUT_MISMATCH_PARTIAL_TARGET', 'GIT')
    opened = []
    close_outcomes = []
    body_error = None
    interruptions = []
    result = None
    file_ordinal = 0
    observed_symlinks = 0
    try:
        # The Git runner must have created only .git so working-tree writes
        # cannot replace an existing path, even if the runner was misdirected.
        with os.scandir(rootfd) as stream:
            first = next(stream, None); second = next(stream, None)
        if first is None or os.fsencode(first.name) != b'.git' or second is not None:
            raise MaterializeError('RUNNER_ROOT_CONTENT_UNEXPECTED', 'WORKTREE')
        git_info = os.stat(b'.git', dir_fd=rootfd, follow_symlinks=False)
        if not stat.S_ISDIR(git_info.st_mode) or git_info.st_dev != before.st_dev:
            raise MaterializeError('GIT_DIRECTORY_UNSUPPORTED', 'WORKTREE')
        worktree = plan['worktree']
        dirs = {b'':rootfd}
        for path, (kind,mode,data) in sorted(worktree.items()):
            parts = path.split(b'/')
            parent_path = b''
            for part in parts[:-1]:
                next_path = parent_path + part + b'/'
                if next_path not in dirs:
                    parent_fd = dirs[parent_path]
                    os.mkdir(part, 0o700, dir_fd=parent_fd)
                    info = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
                    child = os.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=parent_fd)
                    opened.append((child, len(opened)))
                    if not stat.S_ISDIR(info.st_mode) or info.st_dev != before.st_dev or _sig(os.fstat(child)) != _sig(info):
                        raise MaterializeError('DIRECTORY_IDENTITY_UNKNOWN', 'WORKTREE')
                    dirs[next_path] = child
                parent_path = next_path
            parent_fd, leaf = dirs[parent_path], parts[-1]
            if kind == 'symlink':
                try:
                    os.symlink(data, leaf, dir_fd=parent_fd)
                    info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                    if not stat.S_ISLNK(info.st_mode) or info.st_nlink != 1 or os.readlink(leaf, dir_fd=parent_fd) != data:
                        raise MaterializeError('SYMLINK_IDENTITY_UNKNOWN', 'WORKTREE')
                except OSError as exc:
                    raise MaterializeError('SYMLINK_OPERATION_FAILED_PARTIAL_TARGET', 'WORKTREE') from exc
                observed_symlinks += 1
            else:
                child = os.open(leaf, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
                current_ordinal = file_ordinal; file_ordinal += 1
                file_error = None
                try:
                    _write_all(child, data)
                    os.fchmod(child, 0o755 if mode == '100755' else 0o644)
                    os.fsync(child)
                    info = os.fstat(child)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_dev != before.st_dev or
                        info.st_size != len(data) or stat.S_IMODE(info.st_mode) != (0o755 if mode == '100755' else 0o644)):
                        raise MaterializeError('FILE_IDENTITY_UNKNOWN', 'WORKTREE')
                    os.lseek(child,0,os.SEEK_SET); digest = hashlib.sha256(); count = 0
                    while True:
                        block = os.read(child,65536)
                        if not block: break
                        count += len(block)
                        if count > len(data): raise MaterializeError('FILE_READBACK_MISMATCH', 'WORKTREE')
                        digest.update(block)
                    if count != len(data) or digest.digest() != hashlib.sha256(data).digest():
                        raise MaterializeError('FILE_READBACK_MISMATCH', 'WORKTREE')
                    if _sig(os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)) != _sig(info):
                        raise MaterializeError('FILE_IDENTITY_UNKNOWN', 'WORKTREE')
                except BaseException as exc:
                    file_error = exc
                finally:
                    file_close, file_interrupt = _close_once(child, 'FILE', current_ordinal, close_outcomes)
                if file_interrupt is not None:
                    if file_error is not None and not isinstance(file_error, Exception):
                        interruptions.append(file_interrupt)
                        raise file_error.with_traceback(file_error.__traceback__)
                    if file_error is not None:
                        file_interrupt.materializer_prior_error = file_error
                        raise file_interrupt from file_error
                    raise file_interrupt
                if file_error is not None:
                    raise file_error.with_traceback(file_error.__traceback__)
                if file_close != 'CLOSED':
                    raise MaterializeError('FILE_CLOSE_UNKNOWN_PARTIAL_TARGET', 'WORKTREE')
        result = {'status':'OBSERVED_RESEARCH_ONLY', 'qualification':'NOT_RUN', 'product_gate_effect':'NONE',
                  'manifest_sha256':plan['manifest_sha256'], 'head_commit':plan['head_commit'],
                  'head_count':plan['head_count'], 'index_count':plan['index_count'],
                  'worktree_count':len(worktree), 'untracked_count':plan['untracked_count'],
                  'root_freshness':'CALLER_UNVERIFIED', 'runner_binding':'CALLER_UNVERIFIED',
                  'history_completeness':'NOT_MEASURED', 'directory_durability':'NOT_VERIFIED',
                  'source_authentication':'UNVERIFIED', 'snapshot_atomicity':'UNKNOWN',
                  'exclusion_completeness_claim':plan['exclusion_completeness_claim'],
                  'exclusion_coverage_state':plan['exclusion_coverage_state'],
                  'target_limit_preflight':limits,
                  'observed_symlink_readbacks':observed_symlinks}
    except BaseException as exc:
        body_error = exc
    finally:
        # This ledger covers registered FDs for synchronous failures only.
        # Async interruption between open and registration remains UNKNOWN.
        for fd, ordinal in reversed(opened):
            _state, interruption = _close_once(fd, 'DIRECTORY', ordinal, close_outcomes)
            if interruption is not None: interruptions.append(interruption)
    primary_interrupt = body_error if body_error is not None and not isinstance(body_error, Exception) else (interruptions[0] if interruptions else None)
    if primary_interrupt is not None:
        primary_interrupt.materializer_close_outcomes = tuple(close_outcomes)
        primary_interrupt.materializer_untracked_fd_state = 'UNKNOWN_ON_ASYNC_INTERRUPTION'
        primary_interrupt.materializer_outcome = 'INCONCLUSIVE'
        primary_interrupt.materializer_partial_target = 'UNKNOWN'
        primary_interrupt.materializer_other_interruptions = tuple(x for x in interruptions if x is not primary_interrupt)
        if body_error is not None and primary_interrupt is not body_error:
            primary_interrupt.materializer_prior_error = body_error
            raise primary_interrupt from body_error
        raise primary_interrupt.with_traceback(primary_interrupt.__traceback__)
    if body_error is not None:
        if isinstance(body_error, MaterializeError):
            error = MaterializeError(body_error.code, body_error.phase, close_outcomes=close_outcomes)
        else:
            error = MaterializeError('WORKTREE_INCOMPLETE_PARTIAL_TARGET', 'WORKTREE', close_outcomes=close_outcomes)
        raise error from body_error
    if any(item['state'] != 'CLOSED' for item in close_outcomes):
        raise MaterializeError('CLOSE_OUTCOME_UNKNOWN_PARTIAL_TARGET', 'WORKTREE', close_outcomes=close_outcomes)
    result['close_outcomes'] = close_outcomes
    return result

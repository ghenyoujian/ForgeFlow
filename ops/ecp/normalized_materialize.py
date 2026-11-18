#!/usr/bin/env python3
"""Draft normalized candidate materialization; never an authorization or Gate.

The caller must supply separately pinned source, supplement and policy digests.
Same-UID peers, continuous immutability, an authenticated principal and lease,
and independent product verification are outside this observation's scope.
"""
from __future__ import annotations

from contextlib import ExitStack
import ctypes
import errno
import hashlib
import math
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import time
from typing import Any

import materialize_snapshot as legacy
import normalized_policy as policy_lib
import normalized_source
import source_snapshot as snapshot


class DraftIncomplete(RuntimeError):
    """The draft observation could not be completed; no success is implied."""


class DraftRetained(DraftIncomplete):
    """Staging may remain; unconfirmed content is never cleaned."""

    def __init__(self, message: str, *, stage_path: str, stage_attribution: str):
        super().__init__(message)
        self.stage_path = stage_path
        self.stage_attribution = stage_attribution


class DraftPublicationUncertain(DraftIncomplete):
    """A publish was attempted; the candidate and stage were not cleaned."""

    def __init__(self, message: str, *, stage_path: str, candidate_path: str):
        super().__init__(message)
        self.stage_path = stage_path
        self.candidate_path = candidate_path


def _sig(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _deadline(end: float) -> None:
    if time.monotonic() >= end:
        raise TimeoutError('draft materialization time budget exceeded')


def _parent(root_fd: int, relative: str) -> tuple[int, str]:
    snapshot._v3_checked_path(relative)
    parts = relative.split('/')
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            prior, fd = fd, child
            os.close(prior)
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError('candidate write made no progress')
        view = view[count:]


def _no_xattrs(fd: int) -> None:
    # Absence must be observed, not inferred from chmod. Unsupported or
    # unreadable xattrs raise rather than counting as an empty list.
    if os.listxattr(fd):
        raise ValueError('candidate has an unapproved xattr or POSIX ACL')


def _symlink_xattrs(parent_fd: int, name: str) -> None:
    path = f'/proc/self/fd/{parent_fd}/{name}'
    if os.listxattr(path, follow_symlinks=False):
        raise ValueError('candidate symlink has an unapproved xattr')


def _require_umask(expected: str) -> None:
    # Linux exposes this without changing the process-global setting.
    lines = Path('/proc/self/status').read_text(encoding='ascii').splitlines()
    values = [line.split(':', 1)[1].strip() for line in lines if line.startswith('Umask:')]
    if values != [expected]:
        raise DraftIncomplete('current process umask does not match the draft policy')


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    if rename is None:
        raise OSError(errno.ENOSYS, 'atomic no-replace rename unavailable')
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), 1) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def _check_directory(fd: int, expected_mode: str, uid: int, gid: int, device: int) -> os.stat_result:
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_dev != device or
            stat.S_IMODE(info.st_mode) != int(expected_mode, 8) or
            (info.st_uid, info.st_gid) != (uid, gid)):
        raise ValueError('candidate directory metadata differs from policy')
    _no_xattrs(fd)
    return info


def _inventory(root_fd: int, supplement: dict[str, Any], policy: dict[str, Any], end: float,
               synced_files: dict[str, tuple[int, ...]] | None = None,
               synced_directories: dict[str, tuple[int, ...]] | None = None,
               published: bool = False) -> dict[str, Any]:
    """Enumerate every candidate entry through streaming no-follow directory FDs."""
    directories = {row['path']: row['mode'] for row in policy['directories']}
    sources = {row['path']: row for row in supplement['entries']}
    modes = {row['path']: row for row in policy['entries']}
    expected = set(directories) | set(sources)
    found: set[str] = set()
    device = os.fstat(root_fd).st_dev
    uid, gid = policy['owner']['uid'], policy['owner']['gid']
    inventory: list[dict[str, Any]] = []
    frames: list[tuple[str, int, Any, os.stat_result]] = []
    total = 0

    def push(relative: str, fd: int) -> None:
        try:
            if relative in found or relative not in directories:
                raise ValueError('candidate has an extra or repeated directory')
            initial = _check_directory(fd, directories[relative], uid, gid, device)
            if synced_directories is not None:
                signature = synced_directories.get(relative)
                # Renaming the staging root may change its ctime. The rest of
                # its required metadata is checked by _check_directory.
                observed_signature = _sig(initial)
                if signature is None or (observed_signature[:-1] != signature[:-1] if published and relative == '.' else observed_signature != signature):
                    raise ValueError('candidate directory identity differs from fsynced directory')
            iterator = os.scandir(fd)
            try:
                found.add(relative)
                inventory.append({'path': relative, 'kind': 'directory', 'mode': directories[relative],
                                  'uid': uid, 'gid': gid, 'visible_xattrs': []})
                frames.append((relative, fd, iterator, initial))
            except BaseException:
                iterator.close()
                raise
        except BaseException:
            os.close(fd)
            raise

    try:
        push('.', os.dup(root_fd))
        while frames:
            _deadline(end)
            relative, fd, iterator, initial = frames[-1]
            entry = next(iterator, None)
            if entry is None:
                if _sig(os.fstat(fd)) != _sig(initial):
                    raise ValueError('candidate directory changed during inspection')
                frames.pop()
                try:
                    iterator.close()
                finally:
                    os.close(fd)
                continue
            path = entry.name if relative == '.' else relative + '/' + entry.name
            snapshot._v3_checked_path(path)
            if path not in expected or path in found:
                raise ValueError('candidate has an extra or repeated entry')
            before = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
            if before.st_dev != device:
                raise ValueError('candidate crosses a filesystem boundary')
            if path in directories:
                if not stat.S_ISDIR(before.st_mode):
                    raise ValueError('candidate directory changed type')
                if len(frames) >= policy['limits']['max_depth'] + 1:
                    raise ValueError('candidate directory depth exceeds policy')
                child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    opened = os.fstat(child)
                except BaseException:
                    os.close(child)
                    raise
                if _sig(opened) != _sig(before):
                    os.close(child)
                    raise ValueError('candidate directory changed while opening')
                push(path, child)
                continue
            spec, rule = sources[path], modes[path]
            if (before.st_uid, before.st_gid) != (uid, gid) or before.st_nlink != 1:
                raise ValueError('candidate entry identity or link count differs from policy')
            if spec['kind'] == 'symlink':
                if not stat.S_ISLNK(before.st_mode):
                    raise ValueError('candidate symlink changed type')
                target = os.readlink(entry.name, dir_fd=fd)
                _symlink_xattrs(fd, entry.name)
                after = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                if _sig(before) != _sig(after) or target != spec['target']:
                    raise ValueError('candidate symlink changed or differs from source')
                item = {'path': path, 'kind': 'symlink', 'target': target, 'uid': uid, 'gid': gid,
                        'nlink': 1, 'visible_xattrs': []}
            else:
                if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != int(rule['mode'], 8):
                    raise ValueError('candidate file mode or kind differs from policy')
                if synced_files is not None and synced_files.get(path) != _sig(before):
                    raise ValueError('candidate file identity differs from fsynced file')
                file_fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    if _sig(os.fstat(file_fd)) != _sig(before):
                        raise ValueError('candidate file changed while opening')
                    _no_xattrs(file_fd)
                    h = hashlib.sha256()
                    count = 0
                    while True:
                        _deadline(end)
                        block = os.read(file_fd, min(1024 * 1024, spec['size'] - count + 1))
                        if not block:
                            break
                        count += len(block)
                        if count > spec['size']:
                            raise ValueError('candidate file grew during inspection')
                        h.update(block)
                    if count != spec['size'] or h.hexdigest() != spec['sha256'] or _sig(os.fstat(file_fd)) != _sig(before):
                        raise ValueError('candidate file differs from supplement')
                finally:
                    os.close(file_fd)
                total += count
                item = {'path': path, 'kind': 'file', 'mode': rule['mode'], 'size': count,
                        'sha256': spec['sha256'], 'uid': uid, 'gid': gid, 'nlink': 1, 'visible_xattrs': []}
            found.add(path)
            inventory.append(item)
        if found != expected:
            raise ValueError('candidate inventory is incomplete')
        inventory.sort(key=lambda item: item['path'].encode('utf-8', 'strict'))
        return {'entries': inventory, 'count': len(inventory), 'file_bytes': total,
                'sha256': policy_lib.canonical_sha256(inventory)}
    finally:
        cleanup_error = None
        while frames:
            _, fd, iterator, _ = frames.pop()
            try:
                iterator.close()
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
            try:
                os.close(fd)
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if cleanup_error is not None:
            raise DraftIncomplete('candidate inventory cleanup could not be confirmed') from cleanup_error


def _copy_entry(source_fd: int, stage_fd: int, row: dict[str, Any], target: dict[str, Any],
                object_format: str, end: float) -> tuple[int, ...] | None:
    source_parent, name = _parent(source_fd, row['path'])
    try:
        target_parent, target_name = _parent(stage_fd, row['path'])
        try:
            before = os.stat(name, dir_fd=source_parent, follow_symlinks=False)
            if row['kind'] == 'symlink':
                if not stat.S_ISLNK(before.st_mode):
                    raise ValueError('source link changed type')
                target_value = os.readlink(name, dir_fd=source_parent)
                if (target_value != row['target'] or
                        _sig(os.stat(name, dir_fd=source_parent, follow_symlinks=False)) != _sig(before)):
                    raise ValueError('source link changed during copy')
                os.symlink(target_value, target_name, dir_fd=target_parent)
                _symlink_xattrs(target_parent, target_name)
                return
            if not stat.S_ISREG(before.st_mode) or before.st_size != row['size']:
                raise ValueError('source file changed type or size')
            src = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_parent)
            try:
                if _sig(os.fstat(src)) != _sig(before):
                    raise ValueError('source file changed while opening')
                dst = os.open(target_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=target_parent)
                try:
                    h = hashlib.sha256()
                    git_hash = hashlib.sha1() if object_format == 'sha1' else hashlib.sha256()
                    git_hash.update(b'blob ' + str(row['size']).encode('ascii') + b'\0')
                    size = 0
                    while True:
                        _deadline(end)
                        part = os.read(src, min(1024 * 1024, row['size'] - size + 1))
                        if not part:
                            break
                        size += len(part)
                        if size > row['size']:
                            raise ValueError('source file grew during copy')
                        h.update(part)
                        git_hash.update(part)
                        _write_all(dst, part)
                    if (size != row['size'] or h.hexdigest() != row['sha256'] or
                            git_hash.hexdigest() != row['git_oid'] or _sig(os.fstat(src)) != _sig(before)):
                        raise ValueError('source bytes changed or differ from Git')
                    os.fchmod(dst, int(target['mode'], 8))
                    _no_xattrs(dst)
                    return _sig(os.fstat(dst))
                finally:
                    os.close(dst)
            finally:
                os.close(src)
        finally:
            os.close(target_parent)
    finally:
        os.close(source_parent)


def _sync_batch(stage_fd: int, pending: list[tuple[dict[str, Any], tuple[int, ...]]], end: float,
                synced_files: dict[str, tuple[int, ...]] | None = None) -> None:
    """Sync at most eight previously closed files, one reopened FD at a time."""
    if len(pending) > 8:
        raise ValueError('file sync batch exceeds eight entries')
    for row, signature in pending:
        _deadline(end)
        parent_fd, name = _parent(stage_fd, row['path'])
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
            try:
                if _sig(os.fstat(fd)) != signature:
                    raise ValueError('candidate changed before deferred sync')
                _no_xattrs(fd)
                digest, size = hashlib.sha256(), 0
                while True:
                    _deadline(end)
                    block = os.read(fd, min(1024 * 1024, row['size'] - size + 1))
                    if not block:
                        break
                    size += len(block)
                    if size > row['size']:
                        raise ValueError('candidate grew before deferred sync')
                    digest.update(block)
                if size != row['size'] or digest.hexdigest() != row['sha256'] or _sig(os.fstat(fd)) != signature:
                    raise ValueError('candidate differs before deferred sync')
                os.fsync(fd)
                if (_sig(os.fstat(fd)) != signature or
                        _sig(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != signature):
                    raise ValueError('candidate changed during deferred sync')
                if synced_files is not None:
                    if row['path'] in synced_files:
                        raise ValueError('candidate file was synced more than once')
                    synced_files[row['path']] = signature
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
    pending.clear()


def _sync_directories(stage_fd: int, directories: list[dict[str, Any]], end: float) -> dict[str, tuple[int, ...]]:
    """Sync directory metadata bottom-up, including the stage root."""
    synced = {}
    for row in sorted(directories, key=lambda item: len(PurePosixPath(item['path']).parts), reverse=True):
        _deadline(end)
        fd = legacy._v3_open_relative_directory(stage_fd, row['path'])
        try:
            before = _sig(os.fstat(fd))
            os.fsync(fd)
            if _sig(os.fstat(fd)) != before:
                raise ValueError('candidate directory changed during fsync')
            synced[row['path']] = before
        finally:
            os.close(fd)
    return synced


def materialize_draft(source_root: Path, manifest: dict[str, Any], supplement: dict[str, Any],
                      policy: dict[str, Any], *, manifest_sha256: str, supplement_sha256: str,
                      policy_sha256: str, candidate_root: Path, timeout: float = 120.0) -> dict[str, Any]:
    """Materialize an explicit, unqualified policy into an owned empty path."""
    state: dict[str, Any] = {'attempted': False, 'stage_path': None, 'candidate_path': None,
                             'stage_attribution': 'NOT_ATTEMPTED'}
    try:
        return _materialize_draft(source_root, manifest, supplement, policy, manifest_sha256=manifest_sha256,
                                  supplement_sha256=supplement_sha256, policy_sha256=policy_sha256,
                                  candidate_root=candidate_root, timeout=timeout, state=state)
    except (DraftRetained, DraftPublicationUncertain):
        raise
    except BaseException as exc:
        # ExitStack cleanup runs after the body returns or raises. An error
        # during cleanup must not erase the publication/retention state.
        if state['attempted']:
            raise DraftPublicationUncertain('publication or cleanup is uncertain; no candidate was cleaned',
                                            stage_path=state['stage_path'], candidate_path=state['candidate_path']) from exc
        if state['stage_path'] is not None:
            raise DraftRetained('staging may remain; no content was cleaned', stage_path=state['stage_path'],
                                stage_attribution=state['stage_attribution']) from exc
        raise


def _materialize_draft(source_root: Path, manifest: dict[str, Any], supplement: dict[str, Any],
                       policy: dict[str, Any], *, manifest_sha256: str, supplement_sha256: str,
                       policy_sha256: str, candidate_root: Path, timeout: float,
                       state: dict[str, Any]) -> dict[str, Any]:
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 120:
        raise ValueError('invalid draft materialization timeout')
    policy_lib.validate_policy(policy, manifest, supplement, policy_sha256)
    if (manifest_sha256 != manifest['manifest_sha256'] or
            supplement_sha256 != policy_lib.canonical_sha256(supplement) or
            supplement_sha256 != policy['source_supplement_sha256']):
        raise ValueError('independent draft digest binding mismatch')
    if (policy['owner']['uid'], policy['owner']['gid']) != (os.geteuid(), os.getegid()):
        raise DraftIncomplete('draft candidate identity is not the current effective uid/gid')
    for row in policy['directories']:
        if int(row['mode'], 8) & 0o500 != 0o500:
            raise DraftIncomplete('draft directory mode does not permit independent owner read/traversal')
    for row in policy['entries']:
        if row['kind'] == 'file' and int(row['mode'], 8) & 0o400 == 0:
            raise DraftIncomplete('draft file mode does not permit independent owner read')
    _require_umask(policy['attributes']['umask'])
    source = Path(os.path.abspath(source_root))
    destination = Path(os.path.abspath(candidate_root))
    state['candidate_path'] = str(destination)
    parent = destination.parent
    snapshot._v3_checked_path(destination.name)
    if destination == source or source in destination.parents or destination in source.parents:
        raise ValueError('source and candidate must be disjoint')
    end = time.monotonic() + timeout
    with ExitStack() as stack:
        _, source_fd = legacy._v3_open_directory(source)
        stack.callback(os.close, source_fd)
        _, parent_fd = legacy._v3_open_directory(parent)
        stack.callback(os.close, parent_fd)
        info = os.fstat(parent_fd)
        if (info.st_uid != os.geteuid() or info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise DraftIncomplete('candidate parent must be owned by current uid/gid and mode 0700')
        _no_xattrs(parent_fd)
        legacy._v3_assert_output_parent_binding(parent, parent_fd, published=False)
        if legacy._v3_parent_within_source(parent_fd, source_fd) or legacy._v3_parent_mount_aliases_source(source, parent):
            raise ValueError('candidate parent aliases source')
        if snapshot._v3_mount_status(parent)[0] != 'VERIFIED':
            raise DraftIncomplete('candidate parent filesystem modes are unavailable')
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError('candidate path already exists')
        legacy._v3_assert_source_binding(source, source_fd)
        _deadline(end)
        observed = normalized_source.observe_source(source, manifest, manifest_sha256,
                            timeout=max(0.001, min(120.0, end-time.monotonic())), source_fd=source_fd)
        legacy._v3_assert_source_binding(source, source_fd)
        if policy_lib.canonical_sha256(observed) != supplement_sha256 or observed != supplement:
            raise ValueError('source differs from pinned supplemental observation')
        _deadline(end)
        stage_name = '.forgeflow-draft-' + secrets.token_hex(16)
        stage_path = str(parent / stage_name)
        state['stage_path'] = stage_path
        state['stage_attribution'] = 'UNCONFIRMED'
        os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
        state['stage_attribution'] = 'CREATION_RETURNED_NOT_AUTHENTICATED'
        attempted = False
        try:
            created = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
            stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            stack.callback(os.close, stage_fd)
            stage_info = os.fstat(stage_fd)
            if (_sig(created) != _sig(stage_info) or not stat.S_ISDIR(stage_info.st_mode) or
                    stage_info.st_uid != os.geteuid() or stage_info.st_gid != os.getegid() or
                    stat.S_IMODE(stage_info.st_mode) != 0o700):
                raise ValueError('created candidate staging identity changed')
            _no_xattrs(stage_fd)
            for row in sorted(policy['directories'], key=lambda item: (len(PurePosixPath(item['path']).parts), item['path'])):
                _deadline(end)
                fd = legacy._v3_open_relative_directory(stage_fd, row['path'], create=True)
                try:
                    _no_xattrs(fd)
                finally:
                    os.close(fd)
            targets = {row['path']: row for row in policy['entries']}
            object_format = 'sha1' if len(supplement['source_head']) == 40 else 'sha256'
            pending: list[tuple[dict[str, Any], tuple[int, ...]]] = []
            synced_files: dict[str, tuple[int, ...]] = {}
            for row in supplement['entries']:
                _deadline(end)
                signature = _copy_entry(source_fd, stage_fd, row, targets[row['path']], object_format, end)
                if signature is not None:
                    pending.append((row, signature))
                    if len(pending) == 8:
                        _sync_batch(stage_fd, pending, end, synced_files)
            _sync_batch(stage_fd, pending, end, synced_files)
            for row in sorted(policy['directories'], key=lambda item: len(PurePosixPath(item['path']).parts), reverse=True):
                fd = legacy._v3_open_relative_directory(stage_fd, row['path'])
                try:
                    os.fchmod(fd, int(row['mode'], 8))
                    _no_xattrs(fd)
                finally:
                    os.close(fd)
            if snapshot._v3_mount_status(Path(stage_path))[0] != 'VERIFIED':
                raise DraftIncomplete('staged candidate filesystem modes are unavailable')
            synced_directories = _sync_directories(stage_fd, policy['directories'], end)
            staged = _inventory(stage_fd, supplement, policy, end, synced_files, synced_directories)
            legacy._v3_assert_source_binding(source, source_fd)
            _deadline(end)
            after = normalized_source.observe_source(source, manifest, manifest_sha256,
                            timeout=max(0.001, min(120.0, end-time.monotonic())), source_fd=source_fd)
            legacy._v3_assert_source_binding(source, source_fd)
            if after != supplement or policy_lib.canonical_sha256(after) != supplement_sha256:
                raise ValueError('source changed during draft materialization')
            _deadline(end)
            _require_umask(policy['attributes']['umask'])
            _no_xattrs(parent_fd)
            legacy._v3_assert_output_parent_binding(parent, parent_fd, published=False)
            if _sig(os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)) != _sig(os.fstat(stage_fd)):
                raise ValueError('candidate staging path identity changed')
            _deadline(end)
            os.fsync(parent_fd)
            _deadline(end)
            legacy._v3_assert_output_parent_binding(parent, parent_fd, published=False)
            if _sig(os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)) != _sig(os.fstat(stage_fd)):
                raise ValueError('candidate staging path identity changed before publication')
            attempted = True
            state['attempted'] = True
            _rename_noreplace(parent_fd, stage_name, destination.name)
            _deadline(end)
            os.fsync(parent_fd)
            _deadline(end)
            legacy._v3_assert_output_parent_binding(parent, parent_fd, published=True)
            legacy._v3_assert_published_candidate(parent_fd, destination.name, stage_fd)
            if snapshot._v3_mount_status(destination)[0] != 'VERIFIED':
                raise DraftIncomplete('published candidate filesystem modes are unavailable')
            published = _inventory(stage_fd, supplement, policy, end, synced_files, synced_directories, published=True)
            if published != staged:
                raise ValueError('candidate changed after publication')
            legacy._v3_assert_output_parent_binding(parent, parent_fd, published=True)
            legacy._v3_assert_published_candidate(parent_fd, destination.name, stage_fd)
            legacy._v3_assert_output_parent_binding(parent, parent_fd, published=True)
            return {'schema_version': 'forgeflow.ecp-normalized-materialization.draft.v1',
                    'status': 'OBSERVED_NOT_GATE', 'qualification': 'NOT_RUN', 'product_gate_effect': 'NONE',
                    'source_mode_claim': 'UNKNOWN', 'source_permissions_preserved': 'UNKNOWN',
                    'source_manifest_sha256': manifest_sha256, 'source_supplement_sha256': supplement_sha256,
                    'policy_sha256': policy_sha256, 'candidate_root': str(destination),
                    'candidate_inventory_sha256': published['sha256'], 'candidate_entry_count': published['count'],
                    'candidate_file_bytes': published['file_bytes'], 'authority': 'UNVERIFIED',
                    'sync_observation': 'all file and directory fsync calls returned; observed identities matched at both inventory points; publication parent fsync calls returned',
                    'continuous_sync_identity': 'UNKNOWN',
                    'limitations': ['non-atomic source and candidate observation', 'same-UID peers not isolated',
                                    'filesystem calls have no hard wall-clock bound', 'no principal or lease authenticated',
                                    'xattr and ACL visibility is limited to the observing process',
                                    'experimental source observation may use two fused scans with one fewer intermediate sample than the older implementation; atomic or continuous invariance is not proven',
                                    'same-UID path exchanges between observations may be undetected; continuous sync identity is unknown',
                                    'successful fsync calls do not prove crash or power-loss durability',
                                    'candidate checks are not an independent oracle']}
        except BaseException as exc:
            if attempted:
                raise DraftPublicationUncertain('publication or subsequent observation is uncertain; no candidate was cleaned',
                                                stage_path=stage_path, candidate_path=str(destination)) from exc
            raise DraftRetained('staging may remain; no content was cleaned', stage_path=stage_path,
                                stage_attribution=state['stage_attribution']) from exc

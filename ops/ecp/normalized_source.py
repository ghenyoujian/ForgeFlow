#!/usr/bin/env python3
"""Draft supplemental source observation for explicit normalization research.

This read-only helper does not authenticate a principal, freeze a live tree,
approve a transformation or grant a Gate. The caller must pin the supplied v3
manifest independently and keep all resulting evidence outside the source.
"""
from __future__ import annotations

from collections import deque
from contextlib import ExitStack
import fcntl
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time
from typing import Any

import source_snapshot as snapshot

SCHEMA = 'forgeflow.ecp-source-supplement.v1'
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_ENTRIES = 100_000


def _signature(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _safe_links(entries: list[dict[str, Any]], directories: list[dict[str, str]], deadline: float) -> None:
    """Reject dangling, cyclic, excluded or escaping links in the projection."""
    by_path = {row['path']: row for row in entries}
    dirs = {row['path'] for row in directories}
    edges = {name: [] for name in dirs}
    indegree = {name: 0 for name in dirs}
    for name in dirs - {'.'}:
        parent = PurePosixPath(name).parent.as_posix()
        edges[parent].append(name)
        indegree[name] += 1
    operations = 0
    for row in entries:
        if row['kind'] != 'symlink':
            continue
        resolved = list(PurePosixPath(row['path']).parent.parts)
        if resolved == ['.']:
            resolved = []
        pending = deque(row['target'].split('/'))
        # The outer link whose target is being resolved counts as one.
        links = 1
        steps = 0
        while pending:
            steps += 1
            operations += 1
            if steps > 4096 or operations > 1_000_000 or time.monotonic() >= deadline:
                raise ValueError('symlink resolution budget exceeded')
            part = pending.popleft()
            if part in ('', '.'):
                continue
            if part == '..':
                if not resolved:
                    raise ValueError('symlink escapes source projection')
                resolved.pop()
                continue
            resolved.append(part)
            name = '/'.join(resolved)
            snapshot._v3_checked_path(name)
            child = by_path.get(name)
            kind = 'directory' if name in dirs else child['kind'] if child else None
            if kind is not None and snapshot.v3_excluded(name, kind):
                raise ValueError('symlink enters excluded projection')
            if child and child['kind'] == 'symlink':
                links += 1
                if links > 40:
                    raise ValueError('symlink cycle or depth exceeded')
                resolved.pop()
                pending.extendleft(reversed(child['target'].split('/')))
            elif pending and name not in dirs:
                raise ValueError('symlink traverses missing or non-directory entry')
        final = '/'.join(resolved) or '.'
        if final not in dirs and final not in by_path:
            raise ValueError('dangling symlink in source projection')
        if final in dirs:
            parent = PurePosixPath(row['path']).parent.as_posix()
            edges[parent].append(final)
            indegree[final] += 1
    ready = deque(name for name, count in indegree.items() if count == 0)
    visited = 0
    while ready:
        if time.monotonic() >= deadline:
            raise TimeoutError('directory link graph time budget exceeded')
        name = ready.popleft()
        visited += 1
        for child in edges[name]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if visited != len(dirs):
        raise ValueError('directory symlink graph contains a cycle')


def observe_source(root: Path, manifest: dict[str, Any], expected_manifest_sha256: str,
                   *, timeout: float = 120.0, source_fd: int | None = None) -> dict[str, Any]:
    """Observe included bytes, optionally using the caller's held source FD.

    The descriptor is duplicated, never closed on behalf of the caller, and
    compared with the visible root path. The observation remains non-atomic
    and does not authenticate the caller or source. Each of two complete
    endpoint scans derives the supplement from the same bytes used for Git
    object verification. Compared with the earlier draft this removes one
    additional intermediate source sampling; it is not equivalent to a
    continuous or immutable source observation.
    """
    if (not isinstance(expected_manifest_sha256, str) or
            re.fullmatch(r'[0-9a-f]{64}', expected_manifest_sha256) is None):
        raise ValueError('missing or malformed independently pinned manifest digest')
    if not isinstance(manifest, dict):
        raise ValueError('source manifest must be an object')
    core = {k: v for k, v in manifest.items() if k not in ('manifest_sha256', 'created_at', 'release_qualifiable')}
    digest = hashlib.sha256(snapshot._v3_canonical(core)).hexdigest()
    root = Path(os.path.abspath(root))
    projection = manifest.get('directory_projection')
    if (digest != expected_manifest_sha256 or manifest.get('manifest_sha256') != digest or
            manifest.get('schema_version') != snapshot.V3_SCHEMA or manifest.get('source_root') != str(root) or
            manifest.get('worktree_state') != 'CLEAN' or manifest.get('inventory_complete') is not True or
            manifest.get('release_qualifiable') is not False or
            not isinstance(projection, dict) or projection.get('mode_availability') != 'UNAVAILABLE'):
        raise ValueError('manifest is not a matching non-qualifying unknown-mode v3 observation')
    if timeout <= 0 or timeout > 120:
        raise ValueError('source observation timeout outside supported bounds')
    # The fused reader must never read past the supplemental contract's
    # limits, even if the v3 implementation's constants later diverge.
    if snapshot.V3_MAX_TRACKED_FILE_BYTES > MAX_FILE or snapshot.V3_MAX_TRACKED_BYTES > MAX_TOTAL:
        raise ValueError('v3 reader limits exceed supplemental source budget')
    rows = projection.get('directories')
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_ENTRIES:
        raise ValueError('source directory projection is missing or too large')
    directories = []
    previous = None
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {'path', 'kind', 'mode', 'origin'} or
                row['kind'] != 'directory' or row['mode'] is not None or
                row['origin'] not in ('source_root', 'git_ancestor', 'excluded_container')):
            raise ValueError('unsupported or non-null source directory observation')
        path = row['path']
        if path != '.':
            snapshot._v3_checked_path(path)
        if (path == '.') != (row['origin'] == 'source_root'):
            raise ValueError('invalid source root origin')
        key = path.encode('utf-8', 'strict')
        if previous is not None and key <= previous:
            raise ValueError('source directories are duplicated or out of order')
        previous = key
        directories.append({'path': path, 'origin': row['origin']})
    dirnames = {row['path'] for row in directories}
    if '.' not in dirnames or any(PurePosixPath(name).parent.as_posix() not in dirnames for name in dirnames - {'.'}):
        raise ValueError('source directory ancestry is incomplete')
    cleanup = ExitStack()
    try:
        if source_fd is None:
            root_fd = snapshot._v3_open_root_by_path(root)
        else:
            if type(source_fd) is not int or source_fd < 3:
                raise ValueError('source FD must be a readable directory descriptor')
            info = os.fstat(source_fd)
            flags = fcntl.fcntl(source_fd, fcntl.F_GETFL)
            if (not stat.S_ISDIR(info.st_mode) or flags & os.O_ACCMODE != os.O_RDONLY or
                    flags & getattr(os, 'O_PATH', 0)):
                raise ValueError('source FD must be a readable directory descriptor')
            root_fd = os.dup(source_fd)
        cleanup.callback(os.close, root_fd)
        before_root = _signature(os.fstat(root_fd))
        path_fd = snapshot._v3_open_root_by_path(root)
        try:
            path_info = os.fstat(path_fd)
            if (path_info.st_dev, path_info.st_ino) != before_root[:2]:
                raise ValueError('source FD differs from visible source root')
        finally:
            os.close(path_fd)
        pin = snapshot._V3_PINNED_ROOT.set((str(root), root_fd))
        cleanup.callback(snapshot._V3_PINNED_ROOT.reset, pin)
        git_pin = snapshot._V3_BOUNDED_GIT.set(True)
        cleanup.callback(snapshot._V3_BOUNDED_GIT.reset, git_pin)
        deadline = time.monotonic() + timeout
        deadline_token = snapshot._V3_TOTAL_DEADLINE.set(deadline)
        cleanup.callback(snapshot._V3_TOTAL_DEADLINE.reset, deadline_token)
        before, entries, head, raw_index, flags = snapshot._build_manifest_v3_bounded(
            root, snapshot.V3_EXCLUDES, manifest.get('untracked_scan_mode') == 'all',
            _collect_supplement=True)
        if before.get('manifest_sha256') != digest:
            raise ValueError('source differs from pinned manifest before observation')
        if head != manifest.get('head'):
            raise ValueError('source Git head differs from pinned manifest')
        if not 0 < len(entries) <= MAX_ENTRIES:
            raise ValueError('source projected file count is invalid')
        for row in entries:
            if PurePosixPath(row['path']).parent.as_posix() not in dirnames:
                raise ValueError('tracked file parent absent from source projection')
        _safe_links(entries, directories, deadline)
        after, entries_after, head_after, raw_index_after, flags_after = snapshot._build_manifest_v3_bounded(
            root, snapshot.V3_EXCLUDES, manifest.get('untracked_scan_mode') == 'all',
            _collect_supplement=True)
        if after.get('manifest_sha256') != digest:
            raise ValueError('source differs from pinned manifest after observation')
        if (entries_after != entries or head_after != head or raw_index_after != raw_index or flags_after != flags):
            raise ValueError('source supplemental bytes or Git index changed between observations')
        _safe_links(entries_after, directories, deadline)
        current_fd = snapshot._v3_open_root_by_path(root)
        try:
            if _signature(os.fstat(current_fd)) != before_root or _signature(os.fstat(root_fd)) != before_root:
                raise ValueError('source root changed during supplemental observation')
        finally:
            os.close(current_fd)
        return {'schema_version': SCHEMA, 'source_manifest_sha256': digest, 'source_head': head,
                'source_mode_claim': 'UNKNOWN', 'directories': directories, 'entries': entries,
                'qualification': 'NOT_RUN', 'product_gate_effect': 'NONE'}
    finally:
        cleanup.close()

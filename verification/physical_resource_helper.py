#!/usr/bin/env python3
"""Trusted finite helper for the real Rust supervised physical fence proof.

Reads its own actual cgroup only. It never changes a controller or membership.
CPU8s -> finite fork denial -> retained128MiB page touch (expected cgroup OOM).
"""
from __future__ import annotations
import argparse
import errno
import json
import os
from pathlib import Path
import sys
import time

EXPECTED = {'cpu.max': '25000 100000', 'memory.max': '67108864',
            'memory.swap.max': '0', 'pids.max': '8', 'memory.oom.group': '1'}
FILES = (*EXPECTED, 'cpu.stat', 'memory.current', 'memory.peak',
         'memory.events', 'memory.events.local', 'pids.current',
         'pids.events', 'cgroup.events', 'cgroup.procs')


def emit(stage: str, **fields) -> None:
    print(json.dumps({'schema_version': 'forgeflow.physical-helper-observation.v1',
                      'stage': stage, 'monotonic_ns': time.monotonic_ns(), **fields}), flush=True)


def values(root: Path) -> dict:
    result = {}
    for name in FILES:
        p = root / name
        result[name] = p.read_text().strip() if p.exists() else None
    return result


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    membership = Path('/proc/self/cgroup').read_text().strip()
    if not membership.startswith('0::/') or '\n' in membership:
        raise ValueError('One unified cgroup membership is required')
    group = membership[3:]
    root = Path('/sys/fs/cgroup') / group.lstrip('/')
    # Unit root/supervisor must never run the memory workload.
    if not any(part.startswith('forgeflow-worker-') and part.endswith('.service')
               for part in root.parts) or root.name == 'supervisor':
        raise ValueError('Helper is not in the dedicated attempt leaf')
    initial = values(root)
    if any(initial.get(k) != v for k, v in EXPECTED.items()):
        raise ValueError('Actual physical limit readbacks differ; no workload started')
    pid = os.getpid()
    stat_text = Path(f'/proc/{pid}/stat').read_text()
    start_ticks = stat_text[stat_text.rfind(')') + 2:].split()[19]
    emit('membership_before_work', pid=pid, start_ticks=start_ticks,
         boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
         membership=membership, cgroup_path=str(root), cgroup_inode=root.stat().st_ino,
         cgroup_device=root.stat().st_dev, actual_files=initial,
         workload_started=False)
    start = time.monotonic_ns()
    accumulator = 1
    iterations = 0
    while time.monotonic_ns() - start < 8_000_000_000:
        for _ in range(4096):
            accumulator = (accumulator * 1664525 + 1013904223) & 0xffffffff
        iterations += 4096
    emit('cpu_complete', elapsed_ns=time.monotonic_ns() - start,
         iterations=iterations, checksum=accumulator, actual_files=values(root))
    children = []
    read_fd, write_fd = os.pipe()
    failure_errno = None
    before_pids = values(root)
    try:
        for _ in range(16):
            try:
                child = os.fork()
            except OSError as exc:
                failure_errno = exc.errno
                break
            if child == 0:
                os.close(write_fd)
                try:
                    os.read(read_fd, 1)
                finally:
                    os._exit(0)
            children.append(child)
        emit('pids_denial', successful_forks=len(children), attempted_forks=len(children) + (failure_errno is not None),
             fork_errno=failure_errno, expected_errno=errno.EAGAIN,
             files_before=before_pids, actual_files=values(root))
    finally:
        os.close(read_fd)
        os.close(write_fd)
        for child in children:
            os.waitpid(child, 0)
    if failure_errno != errno.EAGAIN:
        raise ValueError('No actual EAGAIN at finite pids limit; refuse memory phase')
    emit('pids_children_reaped', child_count=len(children), actual_files=values(root))
    # mmap pages are touched explicitly; no unbounded allocation or host swap.
    import mmap
    chunks = []
    touched = 0
    emit('memory_begin', requested_bytes=128 * 1024 * 1024,
         chunk_bytes=4 * 1024 * 1024, page_bytes=os.sysconf('SC_PAGE_SIZE'),
         actual_files=values(root))
    for _ in range(32):
        chunk = mmap.mmap(-1, 4 * 1024 * 1024, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
        for offset in range(0, len(chunk), os.sysconf('SC_PAGE_SIZE')):
            chunk[offset] = 1
        chunks.append(chunk)
        touched += len(chunk)
        emit('memory_progress', touched_bytes=touched)
    emit('unexpected_memory_completion', touched_bytes=touched, actual_files=values(root))
    return 2

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        emit('helper_refused', error_type=type(error).__name__, reason=str(error))
        raise SystemExit(1)

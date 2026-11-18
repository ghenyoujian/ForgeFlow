#!/usr/bin/env python3
"""Prune obsolete local build artifacts while retaining sources and failure logs."""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import json
import os
import shutil
import stat

CHECKPOINTS = Path('/home/chenyoujian/.cache/forgeflow-build-checkpoints')
INCREMENTAL = Path('/home/chenyoujian/.cache/forgeflow-control-target/debug/incremental')
DEBUG = INCREMENTAL.parent
KEEP = {
    '30589608a687012d-j0pwekjg',  # actual native 4/10 and verifier isolation
    'b04fe9ada89338a7-zzmvwgi1',  # enterprise browser business validation
    '5d5dda99b313353e-5gqh853s',  # historical pressure/fault evidence
    '5f522fb76e91b0d5-pgqtckwi',  # original planning qualification
    '7a701f0792379e40-vy8qctgy',  # first native execution qualification
    '7a9b233a383aa79a-loil3wpq',  # authority qualification
}

def size(root):
    return sum(p.stat().st_size for p in files_under(root))

def files_under(root):
    if root.is_file() and not root.is_symlink():
        yield root
        return
    for parent, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if not (Path(parent) / name).is_symlink()]
        for name in files:
            path = Path(parent) / name
            if not path.is_symlink() and stat.S_ISREG(path.stat().st_mode):
                yield path

def is_generated_executable(path):
    if path.suffix or path.is_symlink() or not path.is_file():
        return False
    with path.open('rb') as stream:
        return stream.read(4) == b'\x7fELF'

def allocation_for_plan(plan):
    inodes = {}
    for entry in plan:
        for path in files_under(Path(entry['path'])):
            info = path.stat()
            key = (info.st_dev, info.st_ino)
            value = inodes.setdefault(key, {'allocated': info.st_blocks * 512, 'links': info.st_nlink, 'removed_links': 0})
            value['removed_links'] += 1
    return sum(value['allocated'] for value in inodes.values() if value['removed_links'] >= value['links'])

def write_receipt(path, report):
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(path)

def active_builds():
    found = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            executable = (proc / 'exe').resolve().name
            if executable in ('cargo', 'rustc'):
                found.append(int(proc.name))
        except OSError:
            pass
    return found

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--keep-checkpoint', action='append', default=[], help='Additional qualified/current checkpoint directory name to retain')
    parser.add_argument('--retain-only-listed-checkpoints', action='store_true', help='Retain only explicitly listed checkpoint binaries; keep every source, receipt and log')
    parser.add_argument('--clear-incremental', action='store_true', help='Remove regenerable Rust incremental units')
    parser.add_argument('--clear-generated-executables', action='store_true', help='Remove regenerable target binaries and test executables; retain dependency libraries')
    args = parser.parse_args()
    if active_builds():
        raise SystemExit('Cargo/rustc is active; pruning refused')
    built = []
    for checkpoint in CHECKPOINTS.iterdir():
        if checkpoint.is_symlink():
            continue
        receipt = checkpoint / 'receipt.json'
        if receipt.is_file():
            metadata = json.loads(receipt.read_text())
            if metadata.get('binaries') and any(c.get('exit_code') == 0 and 'build' in c.get('argv', []) for c in metadata.get('commands', [])):
                built.append((checkpoint, metadata))
    built.sort(key=lambda item: item[1]['created_at'], reverse=True)
    if not built:
        raise SystemExit('No qualified build receipt found; pruning refused')
    if args.retain_only_listed_checkpoints:
        if not args.keep_checkpoint:
            raise SystemExit('Explicit checkpoint retention list required')
        for name in args.keep_checkpoint:
            checkpoint = CHECKPOINTS / name
            if name in ('', '.', '..') or Path(name).name != name or checkpoint.is_symlink() or checkpoint.parent != CHECKPOINTS or not (checkpoint / 'receipt.json').is_file() or not (checkpoint / 'bin').is_dir():
                raise SystemExit('Retained checkpoint is missing or invalid: ' + name)
        protected = set(args.keep_checkpoint)
    else:
        protected = KEEP | set(args.keep_checkpoint) | {item[0].name for item in built[:2]}
    current = built[0][1]
    cutoff = datetime.fromisoformat(current['created_at']).timestamp() - 120
    plan = []
    for checkpoint in CHECKPOINTS.iterdir():
        if checkpoint.is_symlink() or not checkpoint.is_dir() or checkpoint.name in protected:
            continue
        binary_dir = checkpoint / 'bin'
        if binary_dir.is_dir() and not binary_dir.is_symlink():
            plan.append({'path': str(binary_dir), 'bytes': size(binary_dir), 'reason': 'obsolete intermediate/failed build; receipt, source and logs retained'})
    groups = {}
    for directory in INCREMENTAL.iterdir() if INCREMENTAL.is_dir() else []:
        if directory.is_dir() and not directory.is_symlink():
            groups.setdefault(directory.name.rsplit('-', 1)[0], []).append(directory)
    for directories in groups.values():
        directories.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        for directory in directories if args.clear_incremental else directories[2:]:
            if args.clear_incremental or directory.stat().st_mtime < cutoff:
                reason = 'regenerable incremental unit' if args.clear_incremental else 'old incremental unit; newest two per crate and current build units retained'
                plan.append({'path': str(directory), 'bytes': size(directory), 'reason': reason})
    if args.clear_generated_executables:
        for parent in (DEBUG, DEBUG / 'deps'):
            if parent.is_dir():
                for path in parent.iterdir():
                    if is_generated_executable(path):
                        plan.append({'path': str(path), 'bytes': size(path), 'reason': 'regenerable Cargo binary/test executable; pinned checkpoint copies retained'})
        examples = DEBUG / 'examples'
        if examples.is_dir() and not examples.is_symlink():
            plan.append({'path': str(examples), 'bytes': size(examples), 'reason': 'regenerable Cargo example build outputs'})
    live_paths = []
    for proc in Path('/proc').iterdir():
        if proc.name.isdigit():
            try:
                live_paths.append(str((proc / 'exe').resolve()))
            except OSError:
                pass
    for entry in plan:
        if any(path == entry['path'] or path.startswith(entry['path'] + '/') for path in live_paths):
            raise SystemExit('Active executable would be removed; pruning refused')
    allocated = allocation_for_plan(plan)
    report = {'schema_version': 'forgeflow.build-cache-cleanup.v1', 'observed_at': datetime.now(timezone.utc).isoformat(), 'applied': False, 'retained_checkpoint_binaries': sorted(protected), 'preserved': ['all source snapshots', 'all receipts', 'all successful/failed build and test logs', 'all runtime and qualification evidence', 'dependency libraries and build-script cache'], 'removed': plan, 'bytes_reclaimed': 0, 'allocated_bytes_planned': allocated, 'allocated_bytes_reclaimed': 0, 'free_bytes_before': shutil.disk_usage(CHECKPOINTS).free}
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    write_receipt(args.receipt, report)
    if args.apply:
        if active_builds():
            raise SystemExit('Cargo/rustc started during planning; pruning refused')
        for entry in plan:
            path = Path(entry['path'])
            if path.is_symlink():
                raise SystemExit('Cleanup target became a symlink; pruning stopped')
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            report['bytes_reclaimed'] += entry['bytes']
        report['applied'] = True
        report['allocated_bytes_reclaimed'] = allocated
        report['free_bytes_after'] = shutil.disk_usage(CHECKPOINTS).free
        write_receipt(args.receipt, report)
    print(json.dumps({'applied': report['applied'], 'entries': len(plan), 'bytes': report['bytes_reclaimed'] if args.apply else sum(e['bytes'] for e in plan), 'allocated_bytes': report['allocated_bytes_reclaimed'] if args.apply else allocated, 'receipt': str(args.receipt)}))

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""A00 bounded, coordinated local Cargo check. No cleanup or production access.

Use one small stable compilation snapshot so live edits cannot alter a running
check. The result is test evidence, never a product Gate or installation receipt.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
TARGET = Path('/home/chenyoujian/.cache/forgeflow-control-target')
CACHE = Path('/home/chenyoujian/.cache/forgeflow-build-checkpoints')
COMPILE_SOURCE = CACHE / 'next-compile-source'


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('--reuse-snapshot', type=Path, help='Reuse an earlier source-before.json if the stable compiler snapshot still matches')
    parser.add_argument('--sandbox-guard', type=Path, help='Explicit pinned local guard for real isolated verifier tests')
    parser.add_argument('--database-env', type=Path, help='Private config for this task isolated next_* database only')
    parser.add_argument('--pin-bins', nargs='+', choices=('forgeflow-server', 'forgeflow-worker', 'forgeflow-sandbox-guard', 'forgeflow'),
                        help='For an explicit successful build only: freeze requested binaries and one small source snapshot for packaging')
    parser.add_argument('cargo_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.label.replace('-', '').replace('_', '').isalnum():
        parser.error('label must be alphanumeric with hyphens/underscores')
    cargo_args = args.cargo_args[1:] if args.cargo_args[:1] == ['--'] else args.cargo_args
    if not cargo_args or cargo_args[0] not in ('test', 'check', 'build'):
        parser.error('only an explicit Cargo test, check or build is allowed')
    if args.pin_bins and cargo_args[0] != 'build':
        parser.error('--pin-bins requires a build command')
    if not 1 <= args.timeout <= 1800:
        parser.error('timeout must be 1..1800 seconds')
    # Import only the existing inventory functions; do not invoke its checkpoint,
    # retention, pinning or maintenance operations.
    spec = importlib.util.spec_from_file_location('checkpoint_inventory', ROOT / 'team/build_checkpoint.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    CACHE.mkdir(parents=True, exist_ok=True)
    with (CACHE / '.build.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('BUILD_SLOT_BUSY: no command started', flush=True)
            return 75
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        out = ROOT / 'evidence/next' / f'{stamp}-{args.label}'
        out.mkdir(parents=True, exist_ok=False)
        before = (json.loads(args.reuse_snapshot.read_text())
                  if args.reuse_snapshot else module.inventory(ROOT))
        (out / 'source-before.json').write_text(json.dumps(before, indent=2) + '\n')
        # Only 172 compilation inputs / ~4.1 MiB at the initial Next baseline.
        # Reuse this task's single source directory, never copy .git, benchmarks,
        # runtime ledgers, build products or a repository per test. This helper
        # only synchronizes this dedicated compiler directory under the lock.
        module.COMPILE_SOURCE = COMPILE_SOURCE
        if args.reuse_snapshot:
            if module.inventory(COMPILE_SOURCE) != before:
                raise RuntimeError('Requested prior snapshot no longer matches; no Cargo command started')
            frozen_source = COMPILE_SOURCE
        else:
            frozen_source = module.compile_source(ROOT, before)
        budget_before = module.enforce_cache_budget(TARGET, workspace_only=True)
        if budget_before['status'] not in ('within_budget', 'cleaned'):
            blocked = {'status': 'BUILD_BLOCKED_BY_TARGET_BUDGET', 'target_cache_before': budget_before,
                       'new_model_calls': 0, 'cargo_started': False,
                       'scope': 'Preserve referenced targets and third-party cache; no unbounded build growth.'}
            (out / 'result.json').write_text(json.dumps(blocked, indent=2) + '\n')
            print(json.dumps(blocked), flush=True)
            return 78
        cache_scope = module.activate_compile_source(frozen_source, before)
        environment = os.environ.copy()
        environment.update(CARGO_TARGET_DIR=str(TARGET), CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0')
        # Never inherit a production test DB accidentally.
        for key in ('DATABASE_URL', 'FORGEFLOW_DATABASE_URL', 'PGDATABASE', 'PGHOST', 'PGPORT', 'PGUSER', 'PGPASSWORD'):
            environment.pop(key, None)
        guard_pin = None
        if args.sandbox_guard:
            guard = args.sandbox_guard.resolve(strict=True)
            if not guard.is_file() or not os.access(guard, os.X_OK):
                raise RuntimeError('Explicit sandbox guard must be an executable regular file')
            guard_pin = {'path': str(guard), 'sha256': module.sha(guard)}
            environment['FORGEFLOW_TEST_SANDBOX_GUARD'] = str(guard)
        database_scope = None
        if args.database_env:
            private = args.database_env.resolve(strict=True)
            private_root = Path('/home/chenyoujian/.cache/forgeflow-next').resolve()
            if not private.is_relative_to(private_root) or private.stat().st_mode & 0o077:
                raise RuntimeError('Database config must be private and belong to the isolated Next test runtime')
            url = json.loads(private.read_text())['DATABASE_URL']
            parsed = urlsplit(url)
            if (parsed.scheme not in ('postgres', 'postgresql') or parsed.hostname not in ('127.0.0.1', '::1')
                or parsed.port in (None, 5432, 55432) or parsed.query or parsed.fragment
                or not parsed.path.lstrip('/').startswith('next_')):
                raise RuntimeError('Refusing any database outside the explicit isolated next_* scope')
            environment['DATABASE_URL'] = url
            database_scope = {'host': parsed.hostname, 'port': parsed.port, 'database': parsed.path.lstrip('/')}
        command = ['cargo', cargo_args[0], '--locked', '--offline', *cargo_args[1:]]
        started = time.monotonic()
        timed_out = False
        print(json.dumps({'started': str(out.relative_to(ROOT)), 'argv': command}), flush=True)
        with (out / 'command.log').open('wb') as log:
            proc = subprocess.Popen(command, cwd=frozen_source, env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                exit_code = proc.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                import signal
                timed_out = True
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                exit_code = 124
        after = module.inventory(frozen_source)
        changed = sorted(key for key in before.keys() | after.keys() if before.get(key) != after.get(key))
        test_counts = None
        empty_test_selection = False
        if cargo_args[0] == 'test' and '--no-run' not in cargo_args and '--list' not in cargo_args:
            summaries = re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',
                                   (out / 'command.log').read_text(errors='replace'))
            test_counts = {name: sum(int(row[index]) for row in summaries)
                           for index, name in enumerate(('passed', 'failed', 'ignored'))}
            empty_test_selection = exit_code == 0 and test_counts['passed'] + test_counts['failed'] == 0
        result = {'at': stamp, 'argv': command, 'exit_code': exit_code, 'timed_out': timed_out,
                  'elapsed_seconds': time.monotonic() - started,
                  'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  'source_stable': not changed, 'changed_inputs': changed,
                  'source_before_sha256': hashlib.sha256((out / 'source-before.json').read_bytes()).hexdigest(),
                  'log_sha256': hashlib.sha256((out / 'command.log').read_bytes()).hexdigest(),
                  'target_dir': str(TARGET), 'jobs': 2, 'new_model_calls': 0,
                  'compile_source': str(frozen_source), 'source_snapshot_bytes': sum((frozen_source / key).stat().st_size for key in before),
                  'reused_snapshot_ref': str(args.reuse_snapshot) if args.reuse_snapshot else None,
                  'cache_source_fence': cache_scope,
                  'target_cache_before': budget_before,
                  'observed_test_counts': test_counts, 'empty_test_selection': empty_test_selection,
                  'sandbox_guard_pin': guard_pin, 'isolated_database_scope': database_scope,
                  'production_access': False, 'cleanup_performed': False,
                  'claim': 'Scoped command result only; no product Gate.'}
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        if args.pin_bins and exit_code == 0 and not changed:
            # Checks/tests never create binary or source copies. A delivery has
            # one independently pinned copy outside the mutable Cargo target.
            checkpoint = CACHE / ('next-delivery-' + stamp)
            snapshot = checkpoint / 'source'
            snapshot.mkdir(parents=True, mode=0o700)
            for relative in before:
                target = snapshot / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(frozen_source / relative, target)
                target.chmod(0o444)
            if module.inventory(snapshot) != before:
                raise RuntimeError('Delivery source changed during pinning')
            pinned = checkpoint / 'bin'
            pinned.mkdir()
            binaries = {name: module.pin_binary(TARGET / 'debug' / name, pinned / name, CACHE)
                        for name in dict.fromkeys(args.pin_bins)}
            receipt = {
                'schema_version': 'forgeflow.build-checkpoint.v1',
                'created_at': stamp, 'source_root': str(ROOT), 'snapshot_root': str(snapshot),
                'compilation_source_root': str(frozen_source),
                'source_identity': hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'source_files': before, 'consistent_copy': True,
                'source_unchanged_after_build': True, 'source_unchanged_after_commands': True,
                'helper_sha256': module.sha(Path(__file__).resolve()),
                'commands': [{'argv': command, 'exit_code': 0, 'log': str(out / 'command.log'),
                              'log_sha256': result['log_sha256'], 'source_unchanged_after_command': True}],
                'binaries': binaries, 'cache_source_fence': cache_scope,
                'cargo_result_exit_code': 0, 'scope': 'Exact scoped build and pinned inputs/artifacts only; no product Gate.',
                'qualification': 'INCONCLUSIVE', 'new_model_calls': 0,
            }
            module.write_json(checkpoint / 'receipt.json', receipt)
            result['delivery_receipt'] = str(checkpoint / 'receipt.json')
            result['delivery_binaries_bytes'] = sum(value['size_bytes'] for value in binaries.values())
            (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        # Freeze delivery outputs before retiring any rebuildable workspace
        # artifacts. Checks/tests never acquire another source/binary copy.
        budget_after = module.enforce_cache_budget(TARGET, workspace_only=True)
        result['target_cache_after'] = budget_after
        result['cleanup_performed'] = any(value['reclaimed_allocated_bytes'] > 0 for value in (budget_before, budget_after))
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        return 76 if changed else 77 if empty_test_selection else exit_code or (0 if budget_after['status'] in ('within_budget', 'cleaned') else 78)


if __name__ == '__main__':
    raise SystemExit(main())

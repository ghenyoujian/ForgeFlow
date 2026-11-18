#!/usr/bin/env python3
"""Run explicit, scoped Cargo work against consistent frozen compilation inputs.

Run only in A00's coordinated Cargo slot. Build success is not a Gate.
Credentials and mutable runtime/qualification artifacts are never copied.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
TARGET = Path('/home/chenyoujian/.cache/forgeflow-control-target')
CACHE = Path('/home/chenyoujian/.cache/forgeflow-build-checkpoints')
COMPILE_SOURCE = CACHE / 'compile-source'
TARGET_BUDGET_BYTES = 2 * 1024 ** 3
BINARIES = ('forgeflow-server', 'forgeflow-worker', 'forgeflow-sandbox-guard', 'forgeflow')
PRUNED_DIRECTORIES = frozenset(('qualification', 'target', '__pycache__', 'node_modules', '.git'))


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def input_files(root: Path) -> list[Path]:
    files = [root / 'Cargo.toml', root / 'Cargo.lock']
    # The tutorial API embeds project plans and plugin sources with include_str!.
    # Freeze these asset roots as well, so embedded bytes participate in cache
    # identity and are available in both immutable and stable compiler copies.
    for directory in ('crates', 'migrations', 'contracts', '.cargo', 'project-packs', 'plugins'):
        base = root / directory
        if base.is_symlink():
            raise RuntimeError(f'Compilation input symlink requires explicit review: {directory}')
        if not base.exists():
            continue
        for current, directories, names in os.walk(base, followlinks=False):
            # Prune before descent: qualification trees can contain millions of files.
            directories[:] = [name for name in directories if name not in PRUNED_DIRECTORIES]
            for name in directories + names:
                path = Path(current) / name
                if path.is_symlink():
                    raise RuntimeError(f'Compilation input symlink requires explicit review: {path.relative_to(root)}')
                if path.is_file():
                    files.append(path)
    # Maintenance endpoints embed these scripts in the API binary. Their bytes
    # are compilation inputs and must travel with every frozen source identity.
    for name in ('rust-toolchain.toml', 'rust-toolchain', 'ops/backup.py', 'ops/restore.py'):
        if (root / name).exists():
            files.append(root / name)
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise RuntimeError('Workspace manifests and compilation inputs must be regular files')
    return sorted(set(files))


def inventory(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): sha(p) for p in input_files(root)}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def compile_source(snapshot: Path, expected: dict[str, str]) -> Path:
    """Keep Cargo input paths and unchanged mtimes stable under the build lock."""
    COMPILE_SOURCE.mkdir(parents=True, exist_ok=True, mode=0o700)
    for path in COMPILE_SOURCE.rglob('*'):
        if path.is_symlink():
            raise RuntimeError('Stable compiler source cannot contain symbolic links')
        if path.is_file() and str(path.relative_to(COMPILE_SOURCE)) not in expected:
            path.unlink()
    for relative, identity in expected.items():
        source, destination = snapshot / relative, COMPILE_SOURCE / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination.exists() and sha(destination) == identity:
            continue
        temporary = destination.with_name(destination.name + '.tmp-' + uuid.uuid4().hex)
        shutil.copyfile(source, temporary)
        temporary.chmod(0o444)
        os.replace(temporary, destination)
    if inventory(COMPILE_SOURCE) != expected:
        raise RuntimeError('Stable compiler source differs from checkpoint')
    return COMPILE_SOURCE


def activate_compile_source(source: Path, expected: dict[str, str]) -> dict:
    """Fence relative Cargo dep-info when two snapshot roots share a target.

    Cargo can consider an older input fresh against an artifact built later from
    another source root. Only a root switch refreshes our small workspace input
    timestamps; dependency caches remain reusable. Call under the build lock.
    """
    marker = TARGET / '.forgeflow-compile-source.json'
    active = None
    if marker.exists():
        try:
            active = json.loads(marker.read_text()).get('source_root')
        except (ValueError, OSError):
            pass
    identity = str(source.resolve())
    switched = active != identity
    if switched:
        # Do not copy files, clean the target, or mutate source bytes.
        now = time.time_ns()
        for relative in expected:
            os.utime(source / relative, ns=(now, now))
        TARGET.mkdir(parents=True, exist_ok=True)
        temporary = marker.with_name(marker.name + '.tmp-' + uuid.uuid4().hex)
        write_json(temporary, {'source_root': identity, 'activated_at_ns': now})
        os.replace(temporary, marker)
    return {'source_root': identity, 'source_root_changed': switched,
            'workspace_inputs_refreshed': len(expected) if switched else 0,
            'dependency_cache_cleaned': False}


def arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    builds = parser.add_mutually_exclusive_group()
    builds.add_argument('--build', action='store_true', help='Explicitly build and pin every workspace binary')
    builds.add_argument('--build-bins', nargs='+', choices=BINARIES, help='Build and pin only these binaries')
    parser.add_argument('--check', action='store_true', help='Cargo check without linking deployment binaries')
    parser.add_argument('--check-packages', nargs='+', help='Packages for --check; default entire workspace')
    parser.add_argument('--test', action='store_true', help='Run non-ignored tests; no preliminary binary build')
    parser.add_argument('--test-packages', nargs='+', help='Packages for --test; default entire workspace')
    parser.add_argument('--targeted-test', action='append', default=[], metavar='PACKAGE:TARGET[:FILTER]')
    parser.add_argument('--lib-test', action='append', default=[], metavar='PACKAGE:FILTER')
    parser.add_argument('--postgres-target', action='append', default=[], metavar='PACKAGE:TARGET[:FILTER]')
    parser.add_argument('--focused-filter', help='Name filter for explicit integration-test commands')
    parser.add_argument('--database-env', type=Path, help='Private JSON environment; only DATABASE_URL is read')
    parser.add_argument('--postgres-tests', action='store_true', help='Run ignored isolated-schema authority tests')
    parser.add_argument('--postgres-suites', nargs='+', choices=('authority', 'gateway', 'handoff-materialization', 'handoff-selector', 'collaboration'))
    parser.add_argument('--source-root', type=Path, default=ROOT)
    args = parser.parse_args(argv)
    if not any((args.build, args.build_bins, args.check, args.test, args.postgres_tests,
                args.targeted_test, args.postgres_target, args.lib_test)):
        parser.error('Choose an explicit build, check, or test operation; no empty checkpoints are created')
    for values, library in ((args.targeted_test, False), (args.postgres_target, False), (args.lib_test, True)):
        for selected in values:
            pieces = selected.split(':', 1 if library else 2)
            names = pieces[:1] if library else pieces[:2]
            if len(pieces) not in ((2,) if library else (2, 3)) or not all(re.fullmatch(r'[A-Za-z0-9_-]+', p) for p in names):
                parser.error('Focused targets must use PACKAGE:TARGET[:FILTER]; library tests use PACKAGE:FILTER')
            if (library or len(pieces) == 3) and (not pieces[-1] or pieces[-1].startswith('-')):
                parser.error('Test filters must be non-empty and must not begin with a dash')
    for option, enabled in ((args.test_packages, args.test), (args.check_packages, args.check),
                            (args.postgres_suites, args.postgres_tests)):
        if option and not enabled:
            parser.error('Package/suite selectors require their matching --test, --check, or --postgres-tests operation')
    for package in (args.test_packages or []) + (args.check_packages or []):
        if not re.fullmatch(r'[A-Za-z0-9_-]+', package):
            parser.error('Package names may contain only letters, digits, underscores and hyphens')
    if (args.postgres_target or args.postgres_tests) and not args.database_env:
        parser.error('PostgreSQL tests require --database-env')
    if args.focused_filter and (args.focused_filter.startswith('-') or not (args.targeted_test or args.postgres_target)):
        parser.error('--focused-filter requires an explicit integration-test target and must not begin with a dash')
    return args


def command_plan(args: argparse.Namespace, source: Path) -> list[tuple[str, list[str]]]:
    commands = []
    if args.build:
        commands.append(('build', ['cargo', 'build', '--locked', '--offline', '--workspace', '--bins']))
    elif args.build_bins:
        commands.append(('build', ['cargo', 'build', '--locked', '--offline', *[v for name in dict.fromkeys(args.build_bins) for v in ('--bin', name)]]))
    if args.check:
        package_args = [v for name in args.check_packages for v in ('-p', name)] if args.check_packages else ['--workspace']
        commands.append(('check', ['cargo', 'check', '--locked', '--offline', *package_args]))
    if args.test:
        package_args = [v for name in args.test_packages for v in ('-p', name)] if args.test_packages else ['--workspace']
        commands.append(('test', ['cargo', 'test', '--locked', '--offline', *package_args, '--no-fail-fast']))
    for selected in args.targeted_test:
        package, target, *filters = selected.split(':', 2)
        name_filter = filters[0] if filters else args.focused_filter
        commands.append((f'targeted-{package}-{target}', ['cargo', 'test', '--locked', '--offline', '-p', package, '--test', target, *([name_filter] if name_filter else [])]))
    for index, selected in enumerate(args.lib_test):
        package, name_filter = selected.split(':', 1)
        commands.append((f'lib-{package}-{index}', ['cargo', 'test', '--locked', '--offline', '-p', package, '--lib', name_filter, '--', '--test-threads=1']))
    for selected in args.postgres_target:
        package, target, *filters = selected.split(':', 2)
        name_filter = filters[0] if filters else args.focused_filter
        commands.append((f'postgres-{package}-{target}', ['cargo', 'test', '--locked', '--offline', '-p', package, '--test', target, *([name_filter] if name_filter else []), '--', '--ignored', '--nocapture', '--test-threads=1']))
    if args.postgres_tests:
        suites = set(args.postgres_suites or ('authority', 'gateway', 'handoff-materialization', 'handoff-selector', 'collaboration'))
        definitions = (
            ('authority', 'forgeflow-store', ['authority'], None),
            ('gateway', 'forgeflow-gateway', ['postgres_budget'], None),
            ('handoff-materialization', 'forgeflow-store', ['handoff', 'materialization'], 'crates/store/tests/handoff.rs'),
            ('handoff-selector', 'forgeflow-scheduler', ['handoff_selector'], 'crates/scheduler/tests/handoff_selector.rs'),
            ('collaboration', 'forgeflow-store', ['collaboration'], 'crates/store/tests/collaboration.rs'),
        )
        for name, package, targets, optional_path in definitions:
            if name in suites and (optional_path is None or (source / optional_path).exists()):
                commands.append((f'postgres-{name}', ['cargo', 'test', '--locked', '--offline', '-p', package, *[v for target in targets for v in ('--test', target)], '--', '--ignored', '--nocapture', '--test-threads=1']))
    return commands


def pin_binary(artifact: Path, destination: Path, checkpoints: Path) -> dict[str, object]:
    """Copy once out of mutable target; deduplicate only verified immutable pins."""
    if artifact.is_symlink() or not artifact.is_file():
        raise RuntimeError(f'Expected regular binary absent: {artifact.name}')
    identity = sha(artifact)
    reused = None
    for receipt_path in sorted(checkpoints.glob('*/receipt.json')):
        if receipt_path.parent == destination.parent.parent:
            continue
        try:
            record = json.loads(receipt_path.read_text()).get('binaries', {}).get(artifact.name, {})
            candidate = receipt_path.parent / 'bin' / artifact.name
            if record.get('sha256') != identity or candidate.resolve() != candidate.absolute() or not candidate.is_file():
                continue
            candidate_stat = candidate.stat()
            if stat.S_IMODE(candidate_stat.st_mode) & 0o222 or os.path.samefile(candidate, artifact):
                continue
            if sha(candidate) != identity:
                continue
            os.link(candidate, destination)
            reused = str(candidate)
            break
        except (OSError, ValueError, TypeError):
            continue
    if reused is None:
        shutil.copyfile(artifact, destination)
        destination.chmod(0o555)
    if os.path.samefile(artifact, destination) or sha(destination) != identity or sha(artifact) != identity:
        destination.unlink()
        raise RuntimeError(f'Binary changed during pinning: {artifact.name}')
    return {'path': str(destination), 'sha256': identity, 'size_bytes': destination.stat().st_size,
            'pin_method': 'checkpoint_hardlink' if reused else 'independent_copy',
            'reused_checkpoint_binary': reused, 'independent_of_mutable_target': True}


def allocated_bytes(root: Path) -> int:
    if not root.exists():
        return 0
    seen = set()
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        for path in [Path(current), *(Path(current) / name for name in files), *(Path(current) / name for name in directories if (Path(current) / name).is_symlink())]:
            info = path.lstat()
            key = (info.st_dev, info.st_ino)
            if key not in seen:
                seen.add(key)
                total += info.st_blocks * 512
    return total


def target_references(target: Path) -> list[str]:
    """Fail closed for unreadable same-user processes; never inspect environment."""
    references = []
    target = target.resolve()

    def under_target(value: str) -> bool:
        return value.removesuffix(' (deleted)') == str(target) or value.startswith(str(target) + '/')

    for process in Path('/proc').iterdir():
        if not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        try:
            same_user = process.stat().st_uid == os.getuid()
            command = (process / 'comm').read_text().strip()
            if command in ('cargo', 'rustc', 'rustdoc', 'cargo-clippy', 'clippy-driver'):
                references.append(f'COMPILER_PROCESS:{process.name}:{command}')
            # Foreign-user processes may hide links; same-user uncertainty blocks cleanup.
            for name in ('cwd', 'exe'):
                try:
                    if under_target(os.readlink(process / name)):
                        references.append(f'PROCESS_REFERENCE:{process.name}:{name}')
                except PermissionError:
                    if same_user:
                        references.append(f'UNREADABLE_PROCESS:{process.name}:{name}')
                except FileNotFoundError:
                    pass
            try:
                for fd in (process / 'fd').iterdir():
                    try:
                        if under_target(os.readlink(fd)):
                            references.append(f'PROCESS_REFERENCE:{process.name}:fd')
                    except FileNotFoundError:
                        pass
                maps = (process / 'maps').read_text()
                if any(under_target(line.split(maxsplit=5)[5]) for line in maps.splitlines() if len(line.split(maxsplit=5)) == 6):
                    references.append(f'PROCESS_REFERENCE:{process.name}:maps')
            except PermissionError:
                if same_user:
                    references.append(f'UNREADABLE_PROCESS:{process.name}:fd_or_maps')
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            references.append(f'UNREADABLE_PROCESS:{process.name}')
    return sorted(set(references))


def enforce_cache_budget(target: Path, limit: int = TARGET_BUDGET_BYTES, *, workspace_only: bool = False) -> dict[str, object]:
    before = allocated_bytes(target)
    report = {'budget_bytes': limit, 'allocated_bytes_before': before, 'allocated_bytes_after': before,
              'status': 'within_budget', 'reclaimed_allocated_bytes': 0,
              'retirement_scope': 'workspace_artifacts_only' if workspace_only else 'rebuildable_target'}
    if before <= limit:
        return report
    if target.is_symlink():
        return {**report, 'status': 'protected', 'reasons': ['TARGET_IS_SYMLINK']}
    references = target_references(target)
    if references:
        return {**report, 'status': 'protected', 'reasons': references}
    # Keep Cargo lock files in place: a subsequent unmanaged Cargo invocation must
    # wait on the same inode while cleanup runs, rather than obtain an orphan lock.
    with ExitStack() as locks:
        lock_paths = {target / 'debug' / '.cargo-lock', target / 'release' / '.cargo-lock'}
        for current, directories, files in os.walk(target, followlinks=False):
            if any((Path(current) / name).is_symlink() for name in directories + files):
                return {**report, 'status': 'protected', 'reasons': ['TARGET_CONTAINS_SYMLINK']}
            if '.cargo-lock' in files:
                lock_paths.add(Path(current) / '.cargo-lock')
        for lock_path in sorted(lock_paths):
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            stream = locks.enter_context(lock_path.open('a+'))
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {**report, 'status': 'protected', 'reasons': ['CARGO_TARGET_LOCK_BUSY']}
        references = target_references(target)
        if references:
            return {**report, 'status': 'protected', 'reasons': references}
        if workspace_only:
            # Keep third-party crates warm. Retire only this workspace's
            # rebuildable outputs, after process/Cargo lock checks above. If
            # dependencies alone exceed the budget, block rather than silently
            # deleting that expensive cache or continuing unbounded growth.
            for profile in ('debug', 'release'):
                base = target / profile
                for name in BINARIES:
                    for suffix in ('', '.d'):
                        (base / (name + suffix)).unlink(missing_ok=True)
                for area in ('deps', '.fingerprint', 'build', 'incremental'):
                    directory = base / area
                    if not directory.exists():
                        continue
                    for path in directory.iterdir():
                        if path.name.startswith(('forgeflow-', 'forgeflow_', 'libforgeflow_')):
                            if any(lock == path or path in lock.parents for lock in lock_paths):
                                continue
                            shutil.rmtree(path) if path.is_dir() else path.unlink()
        # Pins, source, deployment, database and evidence are all outside target.
        for current, directories, files in ([] if workspace_only else os.walk(target, topdown=False, followlinks=False)):
            for name in files:
                path = Path(current) / name
                if path not in lock_paths:
                    path.unlink()
            for name in directories:
                path = Path(current) / name
                try:
                    path.rmdir()
                except OSError:
                    if any(path == lock.parent or path in lock.parents for lock in lock_paths):
                        continue
                    raise
    after = allocated_bytes(target)
    return {**report, 'status': 'cleaned' if after <= limit else 'over_budget',
            'allocated_bytes_after': after, 'reclaimed_allocated_bytes': max(0, before - after)}


def checkpoint_retention(output: Path) -> object:
    spec = importlib.util.spec_from_file_location('forgeflow_storage_maintenance', ROOT / 'ops/storage-maintenance.py')
    if spec is None or spec.loader is None:
        raise RuntimeError('Storage maintenance module unavailable')
    module = importlib.util.module_from_spec(spec)
    # ProcessPoolExecutor pickles archive jobs by module name after fork.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.checkpoint_maintenance(output, keep_checkpoints=3)


def record_budget(receipt: dict, receipt_path: Path, phase: str) -> None:
    try:
        result = enforce_cache_budget(TARGET)
    except Exception as error:
        result = {'status': 'error', 'error_type': type(error).__name__, 'error': str(error)}
    receipt.setdefault('target_cache_maintenance', {})[phase] = result
    write_json(receipt_path, receipt)
    print(f'target-cache-{phase}: {result["status"]}', flush=True)


def execute(args: argparse.Namespace) -> int:
    source_root = args.source_root.resolve()
    before = inventory(source_root)
    commands = command_plan(args, source_root)
    if not commands:
        raise RuntimeError('No applicable Cargo command; no checkpoint created')
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(TARGET), CARGO_BUILD_JOBS='2')
    if args.database_env:
        private = json.loads(args.database_env.read_text())
        database_url = private['DATABASE_URL']
        if not isinstance(database_url, str) or not database_url:
            raise ValueError('DATABASE_URL must be a non-empty string')
        env['DATABASE_URL'] = env['FORGEFLOW_TEST_DATABASE_URL'] = database_url
    CACHE.mkdir(parents=True, exist_ok=True)
    identity = hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    checkpoint = Path(tempfile.mkdtemp(prefix=identity[:16] + '-', dir=CACHE))
    source = checkpoint / 'source'
    source.mkdir()
    for relative in before:
        destination = source / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / relative, destination)
    consistent = before == inventory(source_root) == inventory(source)
    receipt = {
        'schema_version': 'forgeflow.build-checkpoint.v1',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'source_root': str(source_root), 'snapshot_root': str(source), 'source_identity': identity,
        'helper_sha256': sha(Path(__file__).resolve()),
        'invocation': {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()},
        'source_files': before, 'consistent_copy': consistent, 'qualification': 'INCONCLUSIVE',
        'scope': 'Rust compilation inputs and pinned build outputs; excludes frontend and deployment qualification',
        'commands': [], 'binaries': {},
    }
    receipt_path = checkpoint / 'receipt.json'
    write_json(receipt_path, receipt)
    print(str(receipt_path), flush=True)
    code = 0
    try:
        if not consistent:
            print('Source changed during snapshot; nothing built.', flush=True)
            code = 2
            return code
        for path in input_files(source):
            path.chmod(0o444)
        compilation_source = compile_source(source, before)
        receipt['cache_source_fence'] = activate_compile_source(compilation_source, before)
        receipt['compilation_source_root'] = str(compilation_source)
        receipt['compilation_input_paths_stable'] = True
        record_budget(receipt, receipt_path, 'before')
        if receipt['target_cache_maintenance']['before']['status'] not in ('within_budget', 'cleaned'):
            receipt['build_blocked'] = 'Target cache exceeds budget and safe retirement is unavailable'
            code = 2
            return code
        for index, (kind, command) in enumerate(commands, 1):
            log = checkpoint / f'{index:02d}-{kind}.log'
            with log.open('wb') as output:
                result = subprocess.run(command, cwd=compilation_source, env=env, stdout=output, stderr=subprocess.STDOUT)
            code = result.returncode
            unchanged = inventory(source) == before and inventory(compilation_source) == before
            receipt['commands'].append({'argv': command, 'exit_code': code, 'log': str(log),
                                        'log_sha256': sha(log), 'source_unchanged_after_command': unchanged})
            receipt['source_unchanged_after_commands'] = unchanged
            write_json(receipt_path, receipt)
            print(f'{kind}: exit={code} log={log}', flush=True)
            if not unchanged:
                receipt['source_integrity_error'] = 'Snapshot compilation inputs changed during command'
                code = code or 2
                return code
            if code:
                return code
            if kind == 'build':
                pinned = checkpoint / 'bin'
                pinned.mkdir()
                for name in BINARIES if args.build else dict.fromkeys(args.build_bins):
                    receipt['binaries'][name] = pin_binary(TARGET / 'debug' / name, pinned / name, CACHE)
                receipt['source_unchanged_after_build'] = unchanged
                write_json(receipt_path, receipt)
        return code
    except BaseException as error:
        receipt['execution_error'] = {'type': type(error).__name__, 'message': str(error)}
        code = code or (130 if isinstance(error, KeyboardInterrupt) else 2)
        raise
    finally:
        receipt['cargo_result_exit_code'] = code
        record_budget(receipt, receipt_path, 'after')
        try:
            result = checkpoint_retention(checkpoint / 'retention-result.json')
            receipt['checkpoint_maintenance'] = {'status': 'completed', 'result_file': str(checkpoint / 'retention-result.json'), 'result': result}
        except Exception as error:
            receipt['checkpoint_maintenance'] = {'status': 'error', 'error_type': type(error).__name__, 'error': str(error)}
        receipt['finished_at'] = datetime.now(timezone.utc).isoformat()
        write_json(receipt_path, receipt)


def main(argv: list[str] | None = None) -> int:
    # Validate syntax and operation combinations before creating even a cache dir.
    args = arguments(argv)
    CACHE.mkdir(parents=True, exist_ok=True)
    with (CACHE / '.build.lock').open('a+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('The coordinated build slot is occupied; wait for the existing checkpoint.')
        return execute(args)


if __name__ == '__main__':
    raise SystemExit(main())

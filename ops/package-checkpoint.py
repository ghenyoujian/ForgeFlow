#!/usr/bin/env python3
"""Package existing pinned binaries and console assets without rebuilding.

This is a local engineering delivery checkpoint, not a production release.
Creation and installation require a fresh directory; no service is started.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'forgeflow.local-delivery.v1'
BINARIES = ('forgeflow-server', 'forgeflow-worker', 'forgeflow-sandbox-guard', 'forgeflow')
OPS = ('install-local.sh', 'package-checkpoint.py', 'release-receipt.py', 'postgres-local.sh', 'backup.py', 'restore.py', 'run-service.py', 'manage-service.py', 'run-delegated-worker.py', 'lite.py', 'project-pack.py', 'concurrency-readiness.py', 'concurrency-environment.py', 'concurrency-prepare.py', 'concurrency-workers.py', 'freeze-native-profile.py', 'native-runtime-closure.py', 'concurrency-reconcile.py', 'agent-context.py', 'native-context-history.py')
DELIVERY_FILES = ('deploy/RUNBOOK.md', 'deploy/QUICKSTART.zh-CN.md',
                  'deploy/DELIVERY_CONTENTS.md', 'deploy/WORKER_RESOURCES.zh-CN.md', 'deploy/env.example',
                  'deploy/Dockerfile', 'deploy/compose.yaml', 'deploy/compose.lite.yml', '.dockerignore',
                  'crates/api/HTTP_CONTRACT.md', 'crates/api/openapi.json',
                  'crates/api/routes.json', 'planning/tasks.json',
                  'planning/requirements.json', 'planning/gates.json',
                  'planning/known-risks.json', 'planning/source-request.txt',
                  'planning/ui-direction.md', 'planning/enterprise-ux.json',
                  'planning/dsh-mode-request.txt', 'crates/worker/README.md',
                  'crates/executors/README.md', 'crates/evidence/README.md',
                  'verification/README.md', 'verification/algorithm_check.py', 'verification/oracle.py',
                  'verification/fixtures/concurrency_verifier.py',
                  'planning/decoupling-20261106.json')
EVIDENCE_SCHEMA = 'forgeflow.delivery-evidence-index.v1'
LEGACY_SHA256 = '55cd9a9a4b4aaaeb4bf437ffb08249c51faf119e9790a7eaa0731cfc81c37dca'
DESIGN_SHA256 = '982d06d6a7d2921cf7ff8f91faf7d2880edf6fe7f79d1a9a15eb12c1d07342e1'
TRANSFER_STATS = {'hardlinked_files': 0, 'hardlinked_bytes': 0,
                  'copied_files': 0, 'copied_bytes': 0}


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def regular(path: Path) -> None:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f'Expected regular file, no symlinks: {path}')


def inventory(root: Path) -> dict[str, dict]:
    result = {}
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f'Expected directory, no symlinks: {root}')
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        regular(path)
        result[path.relative_to(root).as_posix()] = {
            'sha256': sha(path), 'bytes': path.stat().st_size,
            'mode': format(stat.S_IMODE(mode), '04o'),
        }
    return result


def write_json(path: Path, content: object) -> None:
    path.write_text(json.dumps(content, ensure_ascii=False, indent=2) + '\n')


def safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise ValueError('A nonempty relative POSIX path is required')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or path.as_posix() != value or '\\' in value:
        raise ValueError(f'Unsafe relative path: {value}')
    return path


def archive_inputs(archive: Path, prefix: str, receipt: dict,
                   additional: dict[str, str] | None = None) -> dict:
    """Inspect an archive without extracting or executing any source files."""
    regular(archive)
    prefix_path = safe_relative(prefix.rstrip('/'))
    expected = dict(receipt['source_files'])
    expected.update(additional or {})
    missing = set(expected)
    seen = set()
    files = 0
    with tarfile.open(archive, 'r:*') as stream:
        for member in stream:
            name = member.name.rstrip('/')
            member_path = safe_relative(name)
            if name in seen:
                raise ValueError(f'Duplicate source archive member: {name}')
            seen.add(name)
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f'Source archive member is not a regular file: {name}')
            files += 1
            try:
                relative = member_path.relative_to(prefix_path).as_posix()
            except ValueError:
                continue
            if relative not in expected:
                continue
            incoming = stream.extractfile(member)
            if incoming is None:
                raise ValueError(f'Cannot read source archive member: {name}')
            digest = hashlib.sha256()
            with incoming:
                for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
                    digest.update(chunk)
            if digest.hexdigest() != expected[relative]:
                raise ValueError(f'Source archive differs from pinned source: {relative}')
            missing.discard(relative)
    if missing:
        raise ValueError(f'Source archive is missing pinned files: {sorted(missing)[:5]}')
    return {'prefix': prefix_path.as_posix(), 'regular_files': files,
            'matched_compilation_inputs': len(receipt['source_files']),
            'matched_delivery_resources': len(additional or {})}


def evidence_inputs(index: Path, expected: str, root: Path) -> tuple[dict, list]:
    regular(index)
    if sha(index) != expected:
        raise ValueError('Evidence index digest does not match its explicit pin')
    value = json.loads(index.read_text())
    if value.get('schema_version') != EVIDENCE_SCHEMA or not isinstance(value.get('entries'), list):
        raise ValueError(f'Evidence index must use {EVIDENCE_SCHEMA} and an entries array')
    root = root.resolve(strict=True)
    seen = set()
    inputs = []
    for entry in value['entries']:
        relative = safe_relative(entry['path']).as_posix()
        if relative in seen:
            raise ValueError(f'Duplicate evidence entry: {relative}')
        seen.add(relative)
        source = root / relative
        if not source.resolve(strict=True).is_relative_to(root):
            raise ValueError(f'Evidence entry escapes evidence root: {relative}')
        for parent in source.parents:
            if parent == root:
                break
            if parent.is_symlink():
                raise ValueError(f'Evidence entry uses a symlinked directory: {relative}')
        regular(source)
        if sha(source) != entry['sha256']:
            raise ValueError(f'Evidence entry digest differs: {relative}')
        inputs.append((source, f'evidence/files/{relative}', False, entry['sha256']))
    return value, inputs


def fresh(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError('Destination must be an absolute path')
    parent = path.parent.resolve(strict=True)
    destination = parent / path.name
    destination.mkdir(mode=0o755)  # Atomic refusal of every existing destination.
    (destination / '.INCOMPLETE').write_text('Packaging or installation has not completed.\n')
    return destination


def file_identity(info: os.stat_result) -> tuple:
    # Hardlink creation changes ctime/nlink itself, so they are not drift fields.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns)


def immutable_link_source(source: Path, info: os.stat_result, mode: int) -> bool:
    if stat.S_IMODE(info.st_mode) != mode or info.st_mode & 0o222:
        return False
    resolved = source.resolve(strict=True)
    targets = {Path('/home/chenyoujian/.cache/forgeflow-control-target').resolve()}
    if os.environ.get('CARGO_TARGET_DIR'):
        targets.add(Path(os.environ['CARGO_TARGET_DIR']).resolve())
    if 'target' in resolved.parts or any(resolved.is_relative_to(root) for root in targets):
        return False
    # Also reject an older pin accidentally sharing an inode with a known
    # mutable target binary, even when that pin itself lives outside target.
    for root in targets:
        for profile in ('debug', 'release'):
            candidate = root / profile / source.name
            try:
                current = candidate.stat()
            except FileNotFoundError:
                continue
            if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
                return False
    return True


def copy_pinned(source: Path, destination: Path, expected: str | None = None,
                executable: bool = False, allow_hardlink: bool = False) -> None:
    regular(source)
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f'Input is no longer a regular file: {source.name}')
    observed = sha(source)
    if file_identity(before) != file_identity(source.lstat()):
        raise ValueError(f'Input identity/mode changed while hashing: {source.name}')
    if expected is not None and observed != expected:
        raise ValueError(f'Input digest does not match receipt: {source.name}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    mode = 0o555 if executable else 0o444
    linked = False
    if allow_hardlink and immutable_link_source(source, before, mode):
        try:
            os.link(source, destination, follow_symlinks=False)
            linked = True
        except OSError as error:
            if error.errno not in (errno.EXDEV, errno.EPERM, errno.EACCES, errno.ENOSYS,
                                   errno.EOPNOTSUPP, errno.EMLINK):
                raise
    if not linked:
        incoming_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(incoming_fd, 'rb') as incoming, destination.open('xb') as outgoing:
            if file_identity(os.fstat(incoming.fileno())) != file_identity(before):
                raise ValueError(f'Input identity/mode changed before copy: {source.name}')
            shutil.copyfileobj(incoming, outgoing)
        destination.chmod(mode)
    regular(destination)
    after = destination.lstat()
    valid_link = not linked or (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    if (not valid_link or file_identity(source.lstat()) != file_identity(before)
            or stat.S_IMODE(after.st_mode) != mode
            or sha(destination) != observed or sha(source) != observed):
        if linked:
            destination.unlink()
        raise ValueError(f'File identity/hash/mode changed while transferring: {source.name}')
    method = 'hardlinked' if linked else 'copied'
    TRANSFER_STATS[f'{method}_files'] += 1
    TRANSFER_STATS[f'{method}_bytes'] += before.st_size


def verify(package: Path, require_complete_source: bool = False) -> dict:
    package = package.absolute()
    regular(package / 'delivery-manifest.json')
    manifest = json.loads((package / 'delivery-manifest.json').read_text())
    if manifest.get('schema_version') != SCHEMA:
        raise ValueError('Unsupported delivery manifest schema')
    if manifest.get('qualification') != 'ENGINEERING_CHECKPOINT_ONLY':
        raise ValueError('Unexpected package qualification')
    observed = inventory(package)
    observed.pop('delivery-manifest.json')
    if observed != manifest.get('files'):
        raise ValueError('Package inventory, file hashes or permissions differ from manifest')
    required = {f'bin/{name}' for name in BINARIES} | {'console/index.html', 'build/receipt.json'}
    if not required.issubset(observed):
        raise ValueError('Required binary, console or build receipt is absent')
    for relative in observed:
        path = PurePosixPath(relative)
        if path.is_absolute() or '..' in path.parts or path.as_posix() != relative:
            raise ValueError('Manifest contains an unsafe relative path')
    receipt = json.loads((package / 'build/receipt.json').read_text())
    if sha(package / 'build/receipt.json') != manifest['build']['receipt_sha256']:
        raise ValueError('Original build receipt digest differs')
    for name in BINARIES:
        if observed[f'bin/{name}']['sha256'] != receipt['binaries'][name]['sha256']:
            raise ValueError(f'Packaged binary differs from original receipt: {name}')
    source = manifest.get('source')
    if require_complete_source and source is None:
        raise ValueError('Complete source delivery requires a pinned source archive')
    support = manifest.get('source_support', {})
    if require_complete_source and not {'legacy_archive', 'design_plan'}.issubset(support):
        raise ValueError('Complete source reproduction requires original Python baseline and parent design')
    for entry in support.values():
        relative = safe_relative(entry['path']).as_posix()
        if observed.get(relative, {}).get('sha256') != entry['sha256']:
            raise ValueError(f'Original source support input differs: {relative}')
    if source:
        archive_inputs(package / source['path'], source['prefix'], receipt,
                       source['additional_source_digests'])
        if sha(package / source['path']) != source['sha256']:
            raise ValueError('Packaged source archive digest differs')
    evidence = manifest.get('evidence')
    if evidence:
        index = json.loads((package / 'evidence/index.json').read_text())
        if index.get('schema_version') != EVIDENCE_SCHEMA:
            raise ValueError('Unsupported packaged evidence index')
        for entry in index['entries']:
            relative = safe_relative(entry['path']).as_posix()
            if observed.get(f'evidence/files/{relative}', {}).get('sha256') != entry['sha256']:
                raise ValueError(f'Packaged evidence entry differs: {relative}')
    return manifest


def create(args: argparse.Namespace) -> None:
    receipt_path = args.receipt.absolute()
    regular(receipt_path)
    receipt_digest = sha(receipt_path)
    receipt = json.loads(receipt_path.read_text())
    if receipt.get('schema_version') != 'forgeflow.build-checkpoint.v1':
        raise ValueError('A forgeflow.build-checkpoint.v1 receipt is required')
    if not receipt.get('consistent_copy') or not receipt.get('source_unchanged_after_build'):
        raise ValueError('Build receipt does not confirm consistent immutable compilation inputs')
    commands = receipt.get('commands', [])
    build_commands = [command for command in commands if command.get('argv', [])[:2] == ['cargo', 'build']]
    if not build_commands or any(command.get('exit_code') != 0 for command in build_commands):
        raise ValueError('Receipt has no successful actual Cargo build')
    # Engineering delivery can preserve a built candidate with failed checks.
    # A build log is mandatory; overwritten/missing test logs stay explicitly absent.
    available_logs = []
    unavailable_test_logs = []
    for index, command in enumerate(commands, 1):
        is_build = command.get('argv', [])[:2] == ['cargo', 'build']
        log = Path(command['log']) if command.get('log') else None
        expected = command.get('log_sha256')
        observed = None
        reason = None
        try:
            if log is None or not expected:
                raise ValueError('Original log path or digest is absent')
            regular(log)
            observed = sha(log)
            if observed != expected:
                raise ValueError('Original log bytes are unavailable or were overwritten')
        except (OSError, ValueError) as error:
            reason = str(error)
        if reason is None:
            available_logs.append((index, log, expected))
        elif is_build:
            raise ValueError(f'Actual Cargo build log cannot be verified: {reason}')
        else:
            unavailable_test_logs.append({'command_index': index, 'argv': command['argv'],
                                          'exit_code': command.get('exit_code'),
                                          'original_log_path': str(log) if log else None,
                                          'expected_sha256': expected,
                                          'observed_sha256': observed, 'reason': reason})
    console = args.console_dist.absolute()
    console_before = inventory(console)
    if 'index.html' not in console_before:
        raise ValueError('Built console/index.html is required')
    source_root = args.source_root.resolve(strict=True)
    inputs = []
    for name in OPS:
        inputs.append((source_root / 'ops' / name, f'ops/{name}', True))
    for relative in DELIVERY_FILES:
        inputs.append((source_root / relative, relative, False))
    for name in ('contracts', 'docs'):
        for relative in inventory(source_root / name):
            inputs.append((source_root / name / relative, f'{name}/{relative}', False))
    snapshot = Path(receipt['snapshot_root'])
    for relative in inventory(snapshot / 'migrations'):
        source = f'migrations/{relative}'
        if source not in receipt['source_files']:
            raise ValueError('Migration is not a pinned compilation input')
        if sha(snapshot / source) != receipt['source_files'][source]:
            raise ValueError('Migration bytes differ from the original build snapshot pin')
        inputs.append((snapshot / source, source, False))
    preset_root = snapshot / 'crates/executors/presets/forgeflow'
    if preset_root.exists():
        for relative in inventory(preset_root):
            expected = receipt['source_files'].get(f'crates/executors/presets/forgeflow/{relative}')
            if expected is None:
                raise ValueError('DSH preset is not a pinned compilation input')
            inputs.append((preset_root / relative, f'executors/presets/forgeflow/{relative}', False))
    source_digests = {relative: sha(path) for path, relative, _ in inputs}
    support_inputs = []
    source_support = {}
    for key, selected, selected_sha, fallback, known_sha, relative in (
        ('legacy_archive', args.legacy_archive, args.legacy_archive_sha256,
         source_root.parent / 'archive/forgeflow-python-baseline.tar.gz', LEGACY_SHA256,
         'source-support/archive/forgeflow-python-baseline.tar.gz'),
        ('design_plan', args.design_plan, args.design_plan_sha256,
         source_root.parent / 'docs/idea/ForgeFlow_Control_Design_Plan.md', DESIGN_SHA256,
         'source-support/docs/idea/ForgeFlow_Control_Design_Plan.md'),
    ):
        if selected is None and selected_sha:
            raise ValueError(f'{key} SHA requires an explicit source path')
        if selected is not None and not selected_sha:
            raise ValueError(f'Explicit {key} source requires its SHA256')
        path = selected or fallback
        if selected is None and not path.exists():
            continue
        regular(path)
        expected = selected_sha or known_sha
        if sha(path) != expected:
            raise ValueError(f'Original {key} bytes differ from their pin')
        support_inputs.append((path, relative, expected))
        source_support[key] = {'path': relative, 'sha256': expected,
                               'scope': 'Original input required for standalone source/benchmark reproduction'}
    source_metadata = None
    if args.source_archive is not None:
        if not args.source_archive_sha256:
            raise ValueError('--source-archive requires --source-archive-sha256')
        regular(args.source_archive)
        if sha(args.source_archive) != args.source_archive_sha256:
            raise ValueError('Source archive digest differs from its explicit pin')
        resource_digests = {
            (f'crates/{relative}' if relative.startswith('executors/') else relative): digest
            for relative, digest in source_digests.items()
        }
        additional_source = dict(resource_digests)
        for relative in inventory(source_root / 'console/src'):
            additional_source[f'console/src/{relative}'] = sha(source_root / 'console/src' / relative)
        for relative in ('console/package.json', 'console/package-lock.json',
                         'console/index.html', 'console/vite.config.ts'):
            additional_source[relative] = sha(source_root / relative)
        source_metadata = archive_inputs(args.source_archive, args.source_prefix,
                                         receipt, additional_source)
        source_metadata.update({'path': 'source/forgeflow-source.tar.gz',
                                'sha256': args.source_archive_sha256,
                                'delivery_resource_digests': resource_digests,
                                'additional_source_digests': additional_source,
                                'scope': 'Complete supplied archive; all original Rust compilation inputs and packaged delivery resources match exact archive bytes'})
    elif args.source_archive_sha256:
        raise ValueError('--source-archive-sha256 requires --source-archive')
    evidence_metadata = None
    evidence_files = []
    if args.evidence_index is not None:
        if not args.evidence_index_sha256:
            raise ValueError('--evidence-index requires --evidence-index-sha256')
        index_value, evidence_files = evidence_inputs(args.evidence_index,
                                                     args.evidence_index_sha256,
                                                     args.evidence_root or source_root)
        evidence_metadata = {'index_path': 'evidence/index.json',
                             'index_sha256': args.evidence_index_sha256,
                             'entries': len(index_value['entries']),
                             'scope': 'Original selected evidence bytes and declared scope/status; packaging does not turn failed or unverified gates into PASS'}
    elif args.evidence_index_sha256 or args.evidence_root:
        raise ValueError('Evidence pin/root require --evidence-index')
    destination = fresh(args.output)
    for name in BINARIES:
        pinned = receipt.get('binaries', {}).get(name)
        if not pinned:
            raise ValueError(f'Receipt lacks required binary: {name}')
        copy_pinned(Path(pinned['path']), destination / 'bin' / name, pinned['sha256'], True,
                    allow_hardlink=True)
    copy_pinned(receipt_path, destination / 'build/receipt.json', receipt_digest)
    for index, log, digest in available_logs:
        copy_pinned(log, destination / 'build/logs' / f'{index:02d}.log', digest)
    for relative, entry in console_before.items():
        copy_pinned(console / relative, destination / 'console' / relative, entry['sha256'])
    if inventory(console) != console_before:
        raise ValueError('Console build changed during packaging')
    for path, relative, executable in inputs:
        copy_pinned(path, destination / relative, source_digests[relative], executable)
    if source_metadata:
        copy_pinned(args.source_archive, destination / source_metadata['path'], source_metadata['sha256'])
    for path, relative, expected in support_inputs:
        copy_pinned(path, destination / relative, expected)
    if evidence_metadata:
        copy_pinned(args.evidence_index, destination / 'evidence/index.json', args.evidence_index_sha256)
        for path, relative, executable, expected in evidence_files:
            copy_pinned(path, destination / relative, expected, executable)
    # The preset content comes from the immutable source snapshot, not today's checkout.
    for relative in inventory(preset_root) if preset_root.exists() else ():
        pinned = receipt['source_files'][f'crates/executors/presets/forgeflow/{relative}']
        if sha(destination / 'executors/presets/forgeflow' / relative) != pinned:
            raise ValueError('Packaged DSH preset differs from build snapshot')
    if sha(receipt_path) != receipt_digest:
        raise ValueError('Build receipt changed during packaging; retry with a stable receipt')
    (destination / '.INCOMPLETE').unlink()
    manifest = {
        'schema_version': SCHEMA,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'qualification': 'ENGINEERING_CHECKPOINT_ONLY',
        'scope': 'Pinned Linux binaries, built console, migrations, API/Schema, templates, architecture, operations and optional complete source/evidence; no production or workload qualification is added',
        'source': source_metadata,
        'source_support': source_support,
        'evidence': evidence_metadata,
        'build': {
            'source_identity': receipt['source_identity'],
            'receipt_sha256': receipt_digest,
            'profile': 'release' if any('--release' in c['argv'] for c in build_commands) else 'debug',
            'original_qualification': receipt.get('qualification', 'INCONCLUSIVE'),
            'original_scope': receipt.get('scope'),
            'recorded_commands': [{'argv': c['argv'], 'exit_code': c['exit_code']} for c in commands],
            'verification_status': ('INCOMPLETE' if unavailable_test_logs or
                                    any(c.get('exit_code') != 0 for c in commands)
                                    else 'RECORDED_COMMANDS_SUCCEEDED'),
            'unavailable_test_logs': unavailable_test_logs,
        },
        'console': {'input_path': str(console), 'file_count': len(console_before),
                    'source_build_receipt': None, 'scope': 'Exact existing dist file bytes; Rust receipt does not qualify frontend source/build'},
        'requirements': ['Linux compatible with build host dynamic libraries', 'PostgreSQL and private service configuration',
                         'DSH runtime, model configuration and external sandbox tools separately installed and qualified before Worker use'],
        'limitations': ['Not a production release; debug artifacts are labelled debug',
                        'Package contains no database, private runtime configuration, model credentials or live state',
                        'Fresh install and health checks do not prove DSH, 128 channels, restore or 100+ production qualification'],
        'files': inventory(destination),
    }
    write_json(destination / 'delivery-manifest.json', manifest)
    (destination / 'delivery-manifest.json').chmod(0o444)
    verify(destination)
    print(json.dumps({'package': str(destination), 'manifest_sha256': sha(destination / 'delivery-manifest.json'),
                      'file_count': len(manifest['files']), 'build_profile': manifest['build']['profile'],
                      'qualification': manifest['qualification'], 'storage_transfer': TRANSFER_STATS}))


def install(args: argparse.Namespace) -> None:
    package = args.package.absolute()
    if args.prefix.resolve().is_relative_to(package.resolve()):
        raise ValueError('Installation destination cannot be inside the source package')
    manifest = verify(package)
    destination = fresh(args.prefix)
    for relative, entry in manifest['files'].items():
        copy_pinned(package / relative, destination / relative, entry['sha256'],
                    bool(int(entry['mode'], 8) & 0o111), allow_hardlink=True)
    copy_pinned(package / 'delivery-manifest.json', destination / 'delivery-manifest.json',
                allow_hardlink=True)
    (destination / '.INCOMPLETE').unlink()
    verify(destination)
    print(json.dumps({'installation': str(destination), 'manifest_sha256': sha(destination / 'delivery-manifest.json'),
                      'qualification': manifest['qualification'], 'services_started': False,
                      'storage_transfer': TRANSFER_STATS}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest='command', required=True)
    build = subparsers.add_parser('create', help='Copy an existing immutable build receipt and console into a fresh package')
    build.add_argument('--receipt', required=True, type=Path)
    build.add_argument('--console-dist', required=True, type=Path)
    build.add_argument('--output', required=True, type=Path)
    build.add_argument('--source-root', default=ROOT, type=Path)
    build.add_argument('--source-archive', type=Path, help='Fixed complete Git source archive, copied without extraction')
    build.add_argument('--source-archive-sha256', help='Explicit SHA256 of the supplied source archive')
    build.add_argument('--source-prefix', default='ForgeFlow/control', help='Control directory prefix inside the source archive')
    build.add_argument('--legacy-archive', type=Path, help='Original Python benchmark archive; auto-selects pinned parent archive if present')
    build.add_argument('--legacy-archive-sha256', help='Explicit SHA256 for a selected original Python archive')
    build.add_argument('--design-plan', type=Path, help='Original parent design Markdown; auto-selects pinned parent design if present')
    build.add_argument('--design-plan-sha256', help='Explicit SHA256 for a selected parent design')
    build.add_argument('--evidence-index', type=Path, help=f'Selected original proof index using {EVIDENCE_SCHEMA}')
    build.add_argument('--evidence-index-sha256', help='Explicit SHA256 of the selected evidence index')
    build.add_argument('--evidence-root', type=Path, help='Root for safe relative evidence paths; defaults to source root')
    check = subparsers.add_parser('verify', help='Verify exact packaged files, permissions and original binary pins')
    check.add_argument('--package', required=True, type=Path)
    check.add_argument('--require-complete-source', action='store_true')
    deploy = subparsers.add_parser('install', help='Install a verified package to a fresh directory without rebuilding')
    deploy.add_argument('--package', required=True, type=Path)
    deploy.add_argument('--prefix', required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'create':
            create(args)
        elif args.command == 'install':
            install(args)
        else:
            manifest = verify(args.package, args.require_complete_source)
            print(json.dumps({'package': str(args.package), 'verified_files': len(manifest['files']),
                              'qualification': manifest['qualification']}))
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(f'Package operation failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

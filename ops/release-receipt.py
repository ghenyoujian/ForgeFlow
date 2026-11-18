#!/usr/bin/env python3
"""Create/check portable release metadata from already built immutable artifacts.

No compilation, network, database, model or service operation is performed.
Dependency versions come from the exact source archive, not the current checkout.
All gate conclusions, including failures and unknowns, remain verbatim.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tarfile
import tomllib

SCHEMA = 'forgeflow.release-receipt.v1'


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def checker():
    spec = importlib.util.spec_from_file_location('delivery_checker', Path(__file__).with_name('package-checkpoint.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def package_facts(package):
    package = Path(package).resolve(strict=True)
    module = checker()
    manifest = module.verify(package, require_complete_source=True)
    receipt = load(package / 'build/receipt.json')
    if manifest['build']['source_identity'] != receipt['source_identity']:
        raise ValueError('Package/build source identity differs')
    archive = package / manifest['source']['path']
    locks = {}
    prefix = manifest['source']['prefix']
    with tarfile.open(archive, 'r:*') as stream:
        for relative in ('Cargo.lock', 'console/package-lock.json'):
            member = stream.getmember(prefix + '/' + relative)
            if not member.isfile():
                raise ValueError('Dependency lock must be a regular archived file')
            locks[relative] = stream.extractfile(member).read()
    cargo_hash = hashlib.sha256(locks['Cargo.lock']).hexdigest()
    npm_hash = hashlib.sha256(locks['console/package-lock.json']).hexdigest()
    if cargo_hash != receipt['source_files']['Cargo.lock']:
        raise ValueError('Cargo lock differs from actual compilation inputs')
    if npm_hash != manifest['source']['additional_source_digests']['console/package-lock.json']:
        raise ValueError('Console lock differs from archived frontend source')
    cargo = tomllib.loads(locks['Cargo.lock'].decode())
    npm = json.loads(locks['console/package-lock.json'])
    dependencies = {
        'schema_version': 'forgeflow.dependency-inventory.v1',
        'source_identity': receipt['source_identity'],
        'source_archive_sha256': manifest['source']['sha256'],
        'cargo': {'lock_sha256': cargo_hash, 'lock_version': cargo['version'], 'packages': cargo['package']},
        'npm': {'lock_sha256': npm_hash, 'lock_version': npm['lockfileVersion'], 'packages': npm['packages']},
        'external_runtime_requirements': manifest['requirements'],
        'external_runtime_scope': 'DSH/Node.js, PostgreSQL, Git and sandbox tools are supplied by separately qualified deployment profiles. Lock inventories describe archived ForgeFlow code, not those external installations.',
    }
    preset_paths = sorted(p for p in manifest['files'] if p.startswith('executors/presets/forgeflow/'))
    capabilities = {
        'schema_version': 'forgeflow.release-capabilities.v1',
        'source_identity': receipt['source_identity'],
        'configured_dsh_mode': load(package / 'executors/presets/forgeflow/mode.json'),
        'preset_files': {p: manifest['files'][p] for p in preset_paths},
        'declared_deployment': 'single-node PostgreSQL control plane, independent Worker, frozen headless profile',
        'configuration_is_runtime_qualification': False,
        'qualification': manifest['qualification'],
        'limitations': manifest['limitations'],
    }
    migrations = {}
    for path, entry in manifest['files'].items():
        if path.startswith('migrations/'):
            if receipt['source_files'].get(path) != entry['sha256']:
                raise ValueError('Migration does not match immutable compilation inputs')
            migrations[path] = entry
    if not migrations:
        raise ValueError('Migration inventory is empty')
    return manifest, receipt, dependencies, capabilities, migrations


def gate_facts(value):
    gates = value['product_gates']
    if {g['gate_id'] for g in gates} != {f'G{i:02d}' for i in range(21)} or len(gates) != 21:
        raise ValueError('All 21 original gate conclusions must be present exactly once')
    allowed = {'PASS', 'FAIL', 'BLOCKED', 'NOT_RUN', 'INCONCLUSIVE', 'VERIFIER_INVALID'}
    if any(g['status'] not in allowed or not g.get('acceptance') for g in gates):
        raise ValueError('Gate status/acceptance missing or invalid')
    return [g['gate_id'] for g in gates if g['status'] != 'PASS']


def check(package, directory, expected=None):
    directory = Path(directory).resolve(strict=True)
    receipt_path = directory / 'release-receipt.json'
    if expected is not None and sha(receipt_path) != expected:
        raise ValueError('Release receipt differs from externally pinned SHA256')
    value = load(receipt_path)
    if value['schema_version'] != SCHEMA:
        raise ValueError('Unknown release receipt schema')
    for relative, entry in value['metadata_files'].items():
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts or path.as_posix() != relative:
            raise ValueError('Unsafe metadata file path')
        source = directory / path
        if source.is_symlink() or not source.resolve(strict=True).is_relative_to(directory):
            raise ValueError('Metadata must remain inside the receipt directory')
        if sha(source) != entry['sha256'] or source.stat().st_size != entry['bytes']:
            raise ValueError('Release metadata bytes differ: ' + relative)
    manifest, build, dependencies, capabilities, migrations = package_facts(package)
    if value['manifest_sha256'] != sha(Path(package) / 'delivery-manifest.json'):
        raise ValueError('Wrong package manifest')
    if value['source_identity'] != build['source_identity'] or value['source_archive_sha256'] != manifest['source']['sha256']:
        raise ValueError('Release source identity differs')
    if value['binaries'] != {p: e for p, e in manifest['files'].items() if p.startswith('bin/')}:
        raise ValueError('Release binary inventory differs')
    if value['migrations'] != migrations:
        raise ValueError('Release migration inventory differs')
    if load(directory / 'dependency-inventory.json') != dependencies:
        raise ValueError('Dependency inventory differs from exact archived lockfiles')
    if load(directory / 'capabilities.json') != capabilities:
        raise ValueError('Capability declaration differs from frozen package')
    if value['unqualified_gates'] != gate_facts(load(directory / 'gate-conclusions.json')):
        raise ValueError('Gate conclusions differ')
    if value['product_qualified'] is not False or value['qualification'] != 'COMPLETE_METADATA_ENGINEERING_ONLY':
        raise ValueError('This engineering metadata cannot claim product qualification')
    return {'status': 'PASS_RELEASE_METADATA', 'receipt_sha256': sha(receipt_path),
            'source_identity': build['source_identity'], 'cargo_packages': len(dependencies['cargo']['packages']),
            'npm_package_locations': len(dependencies['npm']['packages']), 'migrations': len(migrations),
            'gate_conclusions': 21, 'unqualified_gates': value['unqualified_gates'], 'product_qualified': False}


def create(args):
    package = args.package.resolve(strict=True)
    output = args.output.absolute()
    if output.exists() or output.resolve().is_relative_to(package):
        raise ValueError('Use a fresh receipt directory outside the immutable package')
    manifest, build, dependencies, capabilities, migrations = package_facts(package)
    gates = load(args.gates)
    unqualified = gate_facts(gates)
    output.mkdir(parents=True)
    marker = output / '.INCOMPLETE'
    marker.write_text('Metadata generation has not completed\n')
    save(output / 'dependency-inventory.json', dependencies)
    save(output / 'capabilities.json', capabilities)
    (output / 'gate-conclusions.json').write_bytes(args.gates.read_bytes())
    (output / 'tools').mkdir()
    for name in ('release-receipt.py', 'package-checkpoint.py'):
        shutil.copyfile(Path(__file__).with_name(name), output / 'tools' / name)
    files = [output / name for name in ('dependency-inventory.json', 'capabilities.json', 'gate-conclusions.json')]
    files += [output / 'tools' / name for name in ('release-receipt.py', 'package-checkpoint.py')]
    value = {'schema_version': SCHEMA, 'created_at': datetime.now(timezone.utc).isoformat(),
             'qualification': 'COMPLETE_METADATA_ENGINEERING_ONLY', 'product_qualified': False,
             'source_identity': build['source_identity'], 'manifest_sha256': sha(package / 'delivery-manifest.json'),
             'source_archive_sha256': manifest['source']['sha256'],
             'original_build_receipt_sha256': manifest['build']['receipt_sha256'],
             'binaries': {p: e for p, e in manifest['files'].items() if p.startswith('bin/')},
             'migrations': migrations, 'unqualified_gates': unqualified,
             'metadata_files': {p.relative_to(output).as_posix(): {'sha256': sha(p), 'bytes': p.stat().st_size} for p in files},
             'scope': 'Portable exact release contents and all original conclusions; unchanged package and original failures. No new execution or production qualification.'}
    save(output / 'release-receipt.json', value)
    result = check(package, output)
    marker.unlink()
    print(json.dumps(result))


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    sub = cli.add_subparsers(dest='command', required=True)
    create_cli = sub.add_parser('create')
    create_cli.add_argument('--package', required=True, type=Path)
    create_cli.add_argument('--gates', required=True, type=Path)
    create_cli.add_argument('--output', required=True, type=Path)
    check_cli = sub.add_parser('check')
    check_cli.add_argument('--package', required=True, type=Path)
    check_cli.add_argument('--receipt-dir', required=True, type=Path)
    check_cli.add_argument('--expected-receipt-sha256', required=True)
    args = cli.parse_args()
    if args.command == 'create':
        create(args)
    else:
        print(json.dumps(check(args.package, args.receipt_dir, args.expected_receipt_sha256)))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        raise SystemExit(f'Release metadata rejected: {type(error).__name__}: {error}')

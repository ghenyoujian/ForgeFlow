"""Installed Node dependency/file inventory; no installation or import evaluation."""
import collections
import hashlib
import json
import os
from pathlib import Path

def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""): h.update(chunk)
    return h.hexdigest()

def installed_runtime_package_closure(seed_package):
    """Pin actual installed runtime packages using Node's ancestor resolution.

    No package installation, network, import evaluation or executable probe occurs.
    pnpm stores scoped packages below a per-version node_modules directory, so
    dependencies must be resolved from every ancestor rather than from a guessed
    global store name. Missing required dependencies are a preparation failure.
    """
    seed = Path(seed_package).resolve(strict=True)
    pending = collections.deque([seed])
    packages, files, missing_optional, edges = {}, {}, [], []

    def resolve_dependency(package, name):
        if not name or name.startswith('.') or '..' in name.split('/'):
            raise RuntimeError('invalid installed runtime dependency name: ' + name)
        for ancestor in (package, *package.parents):
            candidate = ancestor / 'node_modules' / name
            if (candidate / 'package.json').is_file():
                return candidate.resolve(strict=True)
        return None

    while pending:
        package = pending.popleft()
        if str(package) in packages:
            continue
        package_json = package / 'package.json'
        definition = json.loads(package_json.read_text())
        name, version = definition.get('name'), definition.get('version')
        if not isinstance(name, str) or not isinstance(version, str):
            raise RuntimeError('installed runtime package identity is incomplete: ' + str(package))
        packages[str(package)] = {'name': name, 'version': version, 'path': str(package),
                                  'package_sha256': digest(package_json)}
        for directory, child_dirs, names in os.walk(package, followlinks=False):
            child_dirs[:] = sorted(child for child in child_dirs if child not in ('node_modules', '.git'))
            for filename in sorted(names):
                path = Path(directory) / filename
                if not path.is_file():
                    continue
                actual = path.resolve(strict=True)
                raw = actual.read_bytes()
                files[str(actual)] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
        dependencies = dict(definition.get('dependencies', {}))
        optional = definition.get('optionalDependencies', {})
        dependencies.update(optional)
        for dependency, specifier in sorted(dependencies.items()):
            resolved = resolve_dependency(package, dependency)
            if resolved is None:
                if dependency in optional:
                    missing_optional.append({'package': name, 'dependency': dependency, 'declared': specifier})
                    continue
                raise RuntimeError('required installed runtime dependency absent: ' + name + ' -> ' + dependency)
            edges.append({'from': str(package), 'dependency': dependency,
                          'declared': specifier, 'resolved': str(resolved)})
            pending.append(resolved)
    return {'schema_version': 'forgeflow.installed-runtime-closure.v1',
            'seed_package': str(seed), 'resolution': 'INSTALLED_NODE_PACKAGE_RUNTIME_DEPENDENCIES',
            'packages': [packages[key] for key in sorted(packages)], 'files': files,
            'dependency_edges': edges, 'missing_optional_dependencies': missing_optional,
            'package_count': len(packages), 'file_count': len(files),
            'total_bytes': sum(value['bytes'] for value in files.values()),
            'scope': 'Actual installed declared runtime dependency closure and package file bytes; not runtime execution or qualification'}

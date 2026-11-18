#!/usr/bin/env python3
"""Prepare immutable managed inputs and resolve actual native configuration, without model calls."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PRESET = HERE.parents[1] / 'presets/forgeflow'
SOURCE = Path('/home/chenyoujian/.local/share/dsh-wsl/source')
DEFAULT_MODEL_HOME = Path('/home/chenyoujian/.cache/forgeflow-dsh-managed-probe/home')


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


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def private_write(path, data):
    path = Path(path)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)


def save(path, value, private=False):
    data = (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()
    private_write(path, data) if private else Path(path).write_bytes(data)


def prepare(private_root, source_home=DEFAULT_MODEL_HOME, profile_id='forgeflow-canonical-collaboration-v2', published_receipt=None, qualification=False, full_preset=False):
    published_receipt = Path(published_receipt) if published_receipt else HERE / ('fixture-ready-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.json')
    if published_receipt.exists():
        raise RuntimeError('preserve original preparation evidence: choose a new published receipt path')
    private_root = Path(private_root).resolve()
    private_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_root.chmod(0o700)
    if (private_root / 'managed-config.json').exists():
        raise RuntimeError('preserve prepared inputs: choose a new private root')
    bundle = private_root / 'bundle'
    bundle.mkdir(mode=0o700)
    originals = [PRESET / 'mode.json', PRESET / 'cordis.patch.yml', PRESET / 'managed-bridge.mjs',
                     PRESET / 'managed-sandbox.mjs', PRESET / 'native-ioctl-deny.c', HERE / 'probe-plugin.mjs',
                     HERE / 'artifact_oracle.py', Path(__file__)]
    if full_preset:
        originals += [PRESET / name for name in ('agent-roles.json', 'team-binding.mjs',
                                                'provider-policy.json', 'model-transport.mjs')]
    for original in originals:
        copied = bundle / original.name
        private_write(copied, original.read_bytes())
        copied.chmod(0o444)
    mode_id = json.loads((bundle / 'mode.json').read_text())['id']
    if mode_id == 'forgeflow-collaboration-v3' and not full_preset:
        raise RuntimeError('current v3 source requires --full-preset; preserve the complete role and provider composition')
    bundle.chmod(0o555)
    compiler = Path(shutil.which('cc') or '').resolve()
    if not compiler.is_file():
        raise RuntimeError('Landlock compiler absent; confinement cannot be bypassed')
    native_source = SOURCE / 'native/system/packages/entry/src/main.c'
    copied_source = private_root / 'landlock-main.c'
    private_write(copied_source, native_source.read_bytes())
    copied_source.chmod(0o444)
    launcher = private_root / 'landlock-run'
    compile_command = [str(compiler), '-std=c11', '-O2', '-static', '-Wall', '-Wextra', '-Werror', str(copied_source), '-o', str(launcher)]
    compiled = subprocess.run(compile_command, env={'PATH': '/usr/bin:/bin'}, capture_output=True, timeout=30)
    private_write(private_root / 'landlock-compile.stdout', compiled.stdout)
    private_write(private_root / 'landlock-compile.stderr', compiled.stderr)
    if compiled.returncode:
        raise RuntimeError('official launcher compilation failed; private diagnostic retained')
    launcher.chmod(0o555)
    probed = subprocess.run([str(launcher), '--probe'], env={'PATH': '/usr/bin:/bin'}, capture_output=True, timeout=5)
    private_write(private_root / 'landlock-probe.stdout', probed.stdout)
    private_write(private_root / 'landlock-probe.stderr', probed.stderr)
    official_enforcement = ('full' if probed.stdout.strip() == b'landlock: fully enforced' else
                            'partial' if probed.stdout.strip() == b'landlock: partially enforced (older ABI)' else 'unusable')
    if probed.returncode or official_enforcement == 'unusable':
        raise RuntimeError('official native Landlock enforcement was not observed')
    ioctl_source = bundle / 'native-ioctl-deny.c'
    copied_ioctl_source = private_root / 'native-ioctl-deny.c'
    private_write(copied_ioctl_source, ioctl_source.read_bytes())
    copied_ioctl_source.chmod(0o444)
    ioctl_guard = private_root / 'native-ioctl-deny'
    ioctl_compile_command = [str(compiler), '-std=c11', '-O2', '-static', '-Wall', '-Wextra', '-Werror', str(copied_ioctl_source), '-o', str(ioctl_guard)]
    ioctl_compiled = subprocess.run(ioctl_compile_command, env={'PATH': '/usr/bin:/bin'}, capture_output=True, timeout=30)
    private_write(private_root / 'ioctl-compile.stdout', ioctl_compiled.stdout)
    private_write(private_root / 'ioctl-compile.stderr', ioctl_compiled.stderr)
    if ioctl_compiled.returncode:
        raise RuntimeError('project seccomp ioctl guard compilation failed; diagnostic retained')
    ioctl_guard.chmod(0o555)
    ioctl_probe = subprocess.run([str(ioctl_guard), '--probe'], env={'PATH': '/usr/bin:/bin'}, capture_output=True, timeout=5)
    private_write(private_root / 'ioctl-probe.stdout', ioctl_probe.stdout)
    private_write(private_root / 'ioctl-probe.stderr', ioctl_probe.stderr)
    ioctl_facts = json.loads(ioctl_probe.stdout) if ioctl_probe.returncode == 0 else {}
    if ioctl_probe.returncode or ioctl_facts.get('landlock_abi', 0) < 3 or ioctl_facts.get('ioctl_after_errno') != 1 or ioctl_facts.get('child_exec_ioctl_denied') is not True:
        raise RuntimeError('actual inherited seccomp ioctl denial was not observed')
    anchor = SOURCE / 'packages/sandbox/sandbox-local/lib/index.js'
    sandbox_config = {'module_anchor': str(anchor), 'module_anchor_sha256': digest(anchor),
                      'launcher': str(launcher), 'launcher_sha256': digest(launcher),
                      'ioctl_guard': str(ioctl_guard), 'ioctl_guard_sha256': digest(ioctl_guard), 'probe_timeout_ms': 2000}
    save(private_root / 'native-sandbox-config.json', sandbox_config, private=True)
    sandbox_build = {'source_path': str(native_source), 'source_sha256': digest(native_source),
                     'copied_source_path': str(copied_source), 'copied_source_sha256': digest(copied_source),
                     'compiler_path': str(compiler), 'compiler_sha256': digest(compiler),
                     'compiler_version': subprocess.run([str(compiler), '--version'], capture_output=True, text=True, timeout=5).stdout,
                     'compile_command': compile_command, 'compile_exit_code': compiled.returncode,
                     'launcher_path': str(launcher), 'launcher_sha256': digest(launcher), 'launcher_mode': '0555',
                     'probe_exit_code': probed.returncode, 'probe_stdout': probed.stdout.decode(),
                     'probe_stderr': probed.stderr.decode(), 'official_enforcement': official_enforcement,
                     'ioctl_source_path': str(ioctl_source), 'ioctl_source_sha256': digest(ioctl_source),
                     'copied_ioctl_source_sha256': digest(copied_ioctl_source), 'ioctl_compile_command': ioctl_compile_command,
                     'ioctl_compile_exit_code': ioctl_compiled.returncode, 'ioctl_guard_path': str(ioctl_guard),
                     'ioctl_guard_sha256': digest(ioctl_guard), 'ioctl_probe': ioctl_facts,
                     'combination': 'official Landlock ABI>=3 filesystem mask plus inherited seccomp denial of ioctl except the ABI5-exempt FIONBIO',
                     'scope': 'Actual host probes only; PTC and inherited outer-worker boundary remain required'}
    save(private_root / 'native-sandbox-build.json', sandbox_build, private=True)
    model_rows = [row for row in yaml.safe_load((source_home / 'cordis.patch.yml').read_text())
                  if row.get('id') in ('agent-default-model', 'llm-pi-ai')]
    if len(model_rows) != 2 or {row.get('id') for row in model_rows} != {'agent-default-model', 'llm-pi-ai'}:
        raise RuntimeError('authorized source must supply exactly two distinct selected model rows')
    if any(row.get('disabled') is True or 'insert' in row for row in model_rows):
        raise RuntimeError('selected model rows cannot disable or insert plugins')
    if full_preset:
        for row in model_rows:
            if row['id'] == 'agent-default-model':
                row['config'] = {'provider': 'newapi', 'model': 'glm-5.3', 'reasoningEffort': 'max'}
            else:
                providers = row['config']['providers']
                if set(providers) != {'newapi'}:
                    raise RuntimeError('full GLM Max mode requires one canonical newapi provider route')
                provider = providers['newapi']
                provider.update(api='anthropic-messages', apiKeyEnv='FORGEFLOW_MODEL_RELAY_DUMMY',
                                baseURL='http://forgeflow-model.invalid')
                provider.setdefault('compat', {})['forceAdaptiveThinking'] = True
                provider.pop('modelOverrides', None)
                provider.pop('thinkingBudgets', None)
                provider['models'] = [{'id': 'glm-5.3', 'name': 'GLM-5.3 Max',
                    'contextWindow': 1000000, 'maxTokens': 131072, 'input': ['text'],
                    'reasoningEfforts': {'low': 'low', 'high': 'high', 'max': 'max'}}]
    selected = private_root / 'selected-model.json'
    credentials = private_root / '.credentials.yaml'
    save(selected, model_rows, private=True)
    private_write(credentials, (json.dumps({'version': 1, 'refs': {
        'FORGEFLOW_MODEL_RELAY_DUMMY': 'forgeflow-relay-no-provider-secret'}}) + '\n').encode()
        if full_preset else (source_home / '.credentials.yaml').read_bytes())
    # The qualification service overlay is explicit, pinned and separately named.
    # Production can use the unchanged preset without this bounded test tool.
    qualification_preset = private_root / 'qualification-preset.json'
    rows = yaml.safe_load((bundle / 'cordis.patch.yml').read_text())
    if full_preset:
        for row in rows:
            if row.get('id') == 'agent-default-model':
                row.setdefault('config', {}).update(provider='newapi', model='glm-5.3', reasoningEffort='max')
            for entry in row.get('insert', []):
                if entry.get('name', '').startswith('./'):
                    local = (bundle / entry['name'][2:]).resolve(strict=True)
                    if not local.is_relative_to(bundle):
                        raise RuntimeError('full preset local module escapes frozen bundle')
                    entry['name'] = local.as_uri()
    rows += [{'id': 'sandbox', 'disabled': True}, {'insert': [{'id': 'forgeflow-native-landlock',
              'name': str(bundle / 'managed-sandbox.mjs'), 'config': sandbox_config}]}]
    if qualification:
        rows.append({'insert': [{'id': 'forgeflow-canonical-qualification', 'name': str(bundle / 'probe-plugin.mjs')}]})
    save(qualification_preset, rows, private=True)
    home = private_root / 'doctor-home'
    profile_home = home / 'profiles/headless'
    profile_home.mkdir(parents=True, mode=0o700)
    home.chmod(0o700)
    private_write(home / 'cordis.patch.yml', selected.read_bytes())
    private_write(home / '.credentials.yaml', credentials.read_bytes())
    save(profile_home / 'package.json', {'name': 'forgeflow-managed-native-attempt', 'private': True,
         'dependencies': {}, 'dsh': {'profile': {'bundles': ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-headless']}}}, private=True)
    private_write(profile_home / 'cordis.patch.yml', b'[]\n')
    bridge_patch = private_root / 'doctor-bridge.patch.json'
    identity = {'project_id': 'doctor-only', 'task_id': 'doctor-only', 'attempt_id': 'doctor-only', 'generation': 1}
    bridge_config = {'socket_path': '/tmp/forgeflow/controller.sock', 'rpc_timeout_ms': 2000, **identity}
    if full_preset:
        bridge_config['model_relay'] = {
            'schema_version': 'forgeflow.model-uds.v1', 'sdk_origin': 'http://forgeflow-model.invalid',
            'socket_path': '/tmp/forgeflow/model.sock', 'max_request_bytes': 8388608,
            'response_idle_timeout_ms': 180000, 'provider_policy_id': 'glm-5.3-max.v1',
            'provider_policy_path': '/tmp/forgeflow/provider-policy.json'}
    save(bridge_patch, [{'insert': [{'id': 'forgeflow-managed-children', 'name': str(bundle / 'managed-bridge.mjs'),
         'config': bridge_config}]}], private=True)
    baseline = json.loads((HERE.parents[0] / 'headless-profile.json').read_text())
    pins = {}
    historical_missing = []
    for pin in baseline['artifact_pins']:
        path = Path(pin['path']).resolve()
        if path.is_relative_to(Path(baseline['home']).resolve()):
            continue  # Old private configuration is never imported into this home.
        if not path.is_file():
            if '/packages/local/forgeflow-ops/' not in pin['path']:
                raise RuntimeError('required native baseline file missing: ' + pin['path'])
            historical_missing.append({'path': pin['path'], 'resolved_path': str(path), 'historical_sha256': pin['sha256']})
            continue
        if digest(path) != pin['sha256']:
            raise RuntimeError('native baseline input changed: ' + str(path))
        pins[str(path)] = pin['sha256']
    runtime_package = SOURCE / 'apps/cli/package.json'
    extra_inputs = [bundle / 'managed-sandbox.mjs', bundle / 'native-ioctl-deny.c', launcher, native_source, copied_source, compiler, anchor,
                    ioctl_source, copied_ioctl_source, ioctl_guard, private_root / 'native-sandbox-config.json',
                    private_root / 'native-sandbox-build.json']
    if qualification:
        extra_inputs.append(bundle / 'probe-plugin.mjs')
        extra_inputs.append(bundle / 'artifact_oracle.py')
    for path in (bundle / 'mode.json', bundle / 'managed-bridge.mjs', bundle / 'cordis.patch.yml',
                 bundle / 'prepare.py', qualification_preset, selected, credentials, bridge_patch, runtime_package, *extra_inputs):
        pins[str(path.resolve())] = digest(path)
    runtime_closure = None
    if full_preset:
        for name in ('agent-roles.json', 'team-binding.mjs', 'provider-policy.json', 'model-transport.mjs'):
            path = bundle / name
            pins[str(path.resolve())] = digest(path)
        runtime_closure = installed_runtime_package_closure(
            SOURCE / 'packages/llm/llm-pi-ai/node_modules/@earendil-works/pi-ai')
        closure_path = private_root / 'sdk-runtime-closure.json'
        save(closure_path, runtime_closure, private=True)
        pins[str(closure_path)] = digest(closure_path)
        pins.update({path: fact['sha256'] for path, fact in runtime_closure['files'].items()})
    env = os.environ.copy()
    env.update(HOME=str(home), DSH_HOME=str(home))
    command = [baseline['program'], *(['--import', str(bundle / 'model-transport.mjs')] if full_preset else []),
               *baseline['prefix_args'], '--profile', 'headless',
               '--patch', str(qualification_preset), '--patch', str(bridge_patch), '--dump-config']
    process = subprocess.run(command, env=env, cwd=private_root, capture_output=True, timeout=45)
    composition = private_root / 'composition.yaml'
    private_write(composition, process.stdout)
    private_write(private_root / 'composition.stderr', process.stderr)
    if process.returncode:
        raise RuntimeError('native --dump-config failed; mode0600 raw diagnostic retained')
    class DumpLoader(yaml.SafeLoader):
        pass
    # DSH's config serializer tags inert expressions; never evaluate them.
    DumpLoader.add_constructor('tag:yaml.org,2002:js', lambda loader, node: loader.construct_scalar(node))
    try:
        resolved = yaml.load(process.stdout, Loader=DumpLoader)
    except yaml.YAMLError:
        raise RuntimeError('native composition is not parseable; private raw diagnostic retained') from None
    # Resolution must actually include the managed bridge and collaboration plugin.
    rendered = json.dumps(resolved)
    required_plugins = ['forgeflow-managed-children', 'forgeflow-native-landlock', 'agent-team', 'workflow-ptc']
    if full_preset:
        declared_presets = [entry['config']['id'] for row in rows for entry in row.get('insert', [])
                            if entry.get('name') == '@deepseek-ai/dsh-agent-preset']
        if len(declared_presets) != 62 or len(set(declared_presets)) != 62:
            raise RuntimeError('full source must preserve four generic and 58 specialized presets')
        required_plugins += ['forgeflow-team-binding', 'tool-agent-team', *declared_presets]
    if qualification:
        required_plugins.append('forgeflow-canonical-qualification')
    if not all(value in rendered for value in required_plugins):
        raise RuntimeError('native composition omitted required managed collaboration plugins')
    if 'forgeflow-ops' in rendered:
        raise RuntimeError('new managed composition imported unavailable historical local plugin')
    doctor_path = private_root / 'managed-doctor.json'
    doctor = {'schema_version': 'forgeflow.managed-doctor.v1', 'mode_id': mode_id,
              'executor_profile_id': profile_id, 'native_profile': 'headless',
              'bridge_schema_version': 'forgeflow.dsh-bridge.v2', 'runtime_package': str(runtime_package.resolve()),
              'runtime_version': json.loads(runtime_package.read_text())['version'], 'exit_code': process.returncode,
              'composition_sha256': hashlib.sha256(process.stdout).hexdigest(), 'artifact_sha256': dict(pins),
              'command': command, 'raw_composition_path': str(composition), 'raw_composition_mode': '0600',
              'scope': 'Actual supported CLI --dump-config; no model request or runtime qualification',
              'historical_missing_unused_local_plugin_pins': historical_missing,
              'inventory_limitations': ['External installed dependency content remains partially inventoried; these pins do not assert all transitive content coverage'],
              'created_at': datetime.now(timezone.utc).isoformat(), 'qualification': 'INCONCLUSIVE'}
    doctor['native_sandbox'] = sandbox_build
    if runtime_closure:
        doctor['sdk_runtime_closure'] = {key: runtime_closure[key] for key in (
            'seed_package', 'resolution', 'package_count', 'file_count', 'total_bytes', 'missing_optional_dependencies')}
        doctor['sdk_runtime_closure'].update(manifest_path=str(closure_path), manifest_sha256=digest(closure_path))
        doctor['inventory_limitations'] = ['Installed pi-ai runtime dependency closure is pinned; other external dependency closures and runtime behavior remain unqualified']
    save(doctor_path, doctor, private=True)
    pins[str(doctor_path)] = digest(doctor_path)
    profile = {'id': profile_id, 'program': baseline['program'], 'prefix_args': baseline['prefix_args'],
               'home': str(home), 'profile_name': 'headless',
               'artifact_pins': [{'path': path, 'sha256': sha} for path, sha in sorted(pins.items())],
               'resume_verified': False, 'model_route_id': 'newapi/glm-5.3' if full_preset else baseline['model_route_id'], 'gateway_coverage_verified': False}
    managed = {'mode_id': mode_id, 'mode_manifest': str(bundle / 'mode.json'),
               'preset_patch': str(qualification_preset), 'bridge_plugin': str(bundle / 'managed-bridge.mjs'),
               'selected_model_config': str(selected), 'credentials': str(credentials), 'doctor': str(doctor_path),
               'rpc_timeout_ms': 2000}
    if full_preset:
        managed['model_relay'] = {'schema_version': 'forgeflow.model-uds.v1',
            'transport_loader': str(bundle / 'model-transport.mjs'), 'sdk_origin': 'http://forgeflow-model.invalid',
            'max_request_bytes': 8388608, 'response_idle_timeout_ms': 180000,
            'provider_policy_id': 'glm-5.3-max.v1', 'provider_policy_path': str(bundle / 'provider-policy.json')}
    save(private_root / 'headless-profile.json', profile, private=True)
    save(private_root / 'managed-config.json', managed, private=True)
    save(private_root / 'executor-registration.json', {**profile, 'kind': 'DSH_MANAGED', 'native_mode': managed}, private=True)
    # Each new preparation has its own published receipt. Historical doctor and
    # source-ready files remain unchanged; private raw native config is not published.
    summary = {'schema_version': 'forgeflow.canonical-collaboration-source-ready.v1', 'status': 'SOURCE_READY',
               'private_root': str(private_root), 'mode_id': managed['mode_id'], 'profile_id': profile_id,
               'artifact_pin_count': len(profile['artifact_pins']), 'doctor_sha256': digest(doctor_path),
               'legacy_v1_archive_sha256': digest(HERE / 'legacy-v1-source/manifest.json'),
               'canonical_runtime_qualification': 'INCONCLUSIVE',
               'published_receipt': str(published_receipt.resolve()), 'doctor_receipt': doctor,
               'qualification_plugin_enabled': qualification, 'native_sandbox_config': sandbox_config,
               'not_proven': ['actual v2 finite native workload', 'actual v2 cancellation', 'financial/whole-egress/100+ qualification']}
    save(published_receipt, summary)
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-root', type=Path)
    parser.add_argument('--source-home', type=Path, default=DEFAULT_MODEL_HOME)
    parser.add_argument('--published-receipt', type=Path)
    parser.add_argument('--qualification', action='store_true', help='Explicitly add the finite qualification tool; ordinary mode preparation omits it')
    parser.add_argument('--full-preset', action='store_true', help='Freeze the full role binding, provider policy and actual installed pi-ai runtime closure')
    args = parser.parse_args()
    private_root = args.private_root or Path(tempfile.mkdtemp(prefix='ff-canon-', dir='/tmp'))
    prepared = prepare(private_root, args.source_home, published_receipt=args.published_receipt,
                       qualification=args.qualification, full_preset=args.full_preset)
    print(json.dumps({key: prepared[key] for key in ('status', 'private_root', 'mode_id', 'profile_id', 'artifact_pin_count', 'doctor_sha256', 'published_receipt', 'canonical_runtime_qualification')}))

#!/usr/bin/env python3
"""Launch the additive DSH mode in a separate home without changing user profiles."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import yaml

HERE = Path(__file__).resolve().parent
ROLES = ('lead', 'owner', 'implementer', 'verifier')


def resolve_local_plugins(rows):
    """A copied profile still loads each repository module from its exact source."""
    for row in rows:
        if str(row.get('name', '')).startswith('./'):
            path = (HERE / row['name']).resolve()
            if not path.is_file() or not path.is_relative_to(HERE):
                raise SystemExit('Declared local preset module is absent or escapes its source directory')
            row['name'] = str(path)
        if isinstance(row.get('insert'), list):
            resolve_local_plugins(row['insert'])
        plugins = row.get('config', {}).get('plugins')
        if isinstance(plugins, list):
            resolve_local_plugins(plugins)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=ROLES)
    parser.add_argument('--position', help='Select an explicit project roster position')
    parser.add_argument('--mode-dir', required=True, type=Path)
    parser.add_argument('--mode-home', required=True, type=Path)
    parser.add_argument('--runtime-entry', required=True, type=Path)
    parser.add_argument('--node', type=Path, default=Path('/usr/bin/node'))
    parser.add_argument('--provider', required=True)
    parser.add_argument('--model', required=True)
    parser.add_argument('--source-home', type=Path, required=True)
    parser.add_argument('--doctor', action='store_true')
    parser.add_argument('--controller-socket', type=Path)
    parser.add_argument('--controller-rpc-timeout-ms', type=int, default=15000)
    parser.add_argument('--identity-file', type=Path,
                        help='Controller-issued project_id, task_id, attempt_id and generation JSON')
    parser.add_argument('--qualification-plugin', type=Path,
                        help='Local qualification-only plugin; never production admission evidence')
    parser.add_argument('--resume-session', help='Adopt an existing native session with --session-id')
    parser.add_argument('task', nargs='?')
    args = parser.parse_args()
    catalog = json.loads((args.mode_dir / 'agent-roles.json').read_text())
    positions = {row['position_id']: row for row in catalog['roster']}
    if args.position and args.position not in positions:
        raise SystemExit('Position is not registered in the selected project pack')
    for runtime_path in (args.runtime_entry, args.node):
        if not runtime_path.is_absolute() or not runtime_path.is_file():
            raise SystemExit('Explicit existing absolute runtime entry and Node paths required')
    position = positions.get(args.position)
    if position and args.role and args.role != position['role']:
        raise SystemExit('Position and generic role do not match the frozen role catalog')
    role = position['role'] if position else (args.role or 'lead')
    preset_id = position['preset_id'] if position else f'forgeflow-{role}-v1'
    identity = json.loads(args.identity_file.read_text()) if args.identity_file else {}
    if not args.doctor and (not args.controller_socket or not all(
            key in identity for key in ('project_id', 'task_id', 'attempt_id', 'generation'))):
        raise SystemExit('Managed collaboration requires --controller-socket and --identity-file; use qualification/collaboration/probe.py for a finite local probe')
    if identity and (not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', str(identity.get('attempt_id', '')))
            or not isinstance(identity.get('generation'), int) or isinstance(identity['generation'], bool)
            or identity['generation'] < 1):
        raise SystemExit('Managed attempt identity is invalid')
    if args.controller_rpc_timeout_ms < 1:
        raise SystemExit('Controller RPC timeout must be positive')
    home = args.mode_home / (args.position or role)
    if identity:
        home = home / 'attempts' / identity['attempt_id']
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    home.chmod(0o700)
    source_patch = args.source_home / 'cordis.patch.yml'
    # Select only the already authorized model configuration. Never copy old plugin disables.
    model_rows = [row for row in yaml.safe_load(source_patch.read_text())
                  if row.get('id') in ('agent-default-model', 'llm-pi-ai')]
    if len(model_rows) != 2:
        raise SystemExit('Selected authorized model configuration is incomplete')
    provider = next(row['config'] for row in model_rows if row['id'] == 'llm-pi-ai').get('providers', {}).get(args.provider)
    if not isinstance(provider, dict) or not any(
            isinstance(model, dict) and model.get('id') == args.model
            for model in provider.get('models', [])):
        raise SystemExit('The selected source home does not register the explicit project provider/model route')
    for row in model_rows:
        if row['id'] == 'agent-default-model':
            row['config'].update(provider=args.provider, model=args.model)
    credential_source = args.source_home / '.credentials.yaml'
    if not credential_source.is_file():
        raise SystemExit('Selected credentials are not configured')
    for name, content in [('cordis.patch.yml', yaml.safe_dump(model_rows, sort_keys=False).encode()),
                          ('.credentials.yaml', credential_source.read_bytes())]:
        destination = home / name
        destination.write_bytes(content)
        destination.chmod(0o600)
    profile = home / 'profiles/headless'
    profile.mkdir(parents=True, exist_ok=True)
    (profile / 'package.json').write_text(json.dumps({'name': 'forgeflow-dsh-' + role,
        'private': True, 'dependencies': {}, 'dsh': {'profile': {'bundles':
        ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-headless']}}}, indent=2) + '\n')
    rows = yaml.safe_load((args.mode_dir / 'cordis.patch.yml').read_text())
    if args.controller_socket:
        rows.append({'insert': [{'id': 'forgeflow-managed-children',
            'name': str(HERE / 'managed-bridge.mjs'), 'config': {
                'socket_path': str(args.controller_socket.resolve()),
                'rpc_timeout_ms': args.controller_rpc_timeout_ms, **identity}}]})
    if args.qualification_plugin:
        rows.append({'insert': [{'id': 'forgeflow-qualification',
            'name': str(args.qualification_plugin.resolve())}]})
    for row in rows:
        for entry in row.get('insert', []):
            if entry['id'] == 'agent-preset-registry':
                entry['config']['default'] = preset_id
            if entry['id'] == 'forgeflow-team-binding':
                entry['config']['default_root_position_id'] = args.position
    resolve_local_plugins(rows)
    overlay = profile / 'cordis.patch.yml'
    overlay.write_text(yaml.safe_dump(rows, sort_keys=False, allow_unicode=True))
    overlay.chmod(0o600)
    env = os.environ.copy()
    env.update(HOME=str(home), DSH_HOME=str(home))
    command = [str(args.node), str(args.runtime_entry), '--profile', 'headless']
    if args.doctor:
        result = subprocess.run(command + ['--dump-config'], env=env, capture_output=True, timeout=30)
        raw = home / 'composition.yaml'
        raw.write_bytes(result.stdout)
        raw.chmod(0o600)
        (home / 'composition.stderr').write_bytes(result.stderr)
        print(json.dumps({'mode_id': 'forgeflow-collaboration-v3', 'role': role,
            'position_id': args.position, 'preset_id': preset_id,
            'exit_code': result.returncode, 'composition_sha256': hashlib.sha256(result.stdout).hexdigest(),
            'overlay_sha256': hashlib.sha256(overlay.read_bytes()).hexdigest(),
            'composition_path': str(raw), 'scope': 'boot-free native configuration resolution',
            'runtime_collaboration': 'UNVERIFIED', 'production_admission': 'BLOCKED_PENDING_MANAGED_CHILD_ACCOUNTING'}))
        return result.returncode
    if not args.task:
        raise SystemExit('Provide a finite task or use --doctor')
    # Real DSH protocol; the controller profile must separately qualify managed delegation.
    if args.resume_session:
        command += ['--session-id', args.resume_session]
    return subprocess.call(command + ['--json', args.task], env=env)


if __name__ == '__main__':
    sys.exit(main())

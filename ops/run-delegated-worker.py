#!/usr/bin/env python3
"""Prepare a private delegated user service; start is an explicit separate action.

No cgroup files or shared service limits are written by this launcher. The pinned
Worker/runtime owns only the dedicated service subtree discovered at bootstrap.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

SCHEMA = 'forgeflow.delegated-worker-launch.v1'
UNIT_RE = re.compile(r'forgeflow-worker-[0-9a-f]{32}\.service\Z')
CONTROLLERS = {'cpu', 'memory', 'pids'}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as s:
        for block in iter(lambda: s.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def regular(path: Path, private: bool = False) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Expected a regular nonsymlink file')
    if private and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError('Private configuration must be owned by current UID and mode0600')


def pin(path: Path, expected: str | None = None, private: bool = False) -> dict:
    path = path.absolute()
    regular(path, private)
    before = path.stat()
    observed = digest(path)
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('Input changed while pinning')
    if expected is not None and observed != expected:
        raise ValueError('Pinned input SHA256 differs')
    return {'path': str(path), 'sha256': observed, 'bytes': after.st_size}


def private_json(path: Path, value: object) -> str:
    with path.open('x', encoding='utf-8') as out:
        os.chmod(path, 0o600)
        out.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
        out.flush()
        os.fsync(out.fileno())
    return digest(path)


def ctl(*args: str, allow_missing: bool = False) -> str:
    env = dict(os.environ, XDG_RUNTIME_DIR=f'/run/user/{os.getuid()}',
               DBUS_SESSION_BUS_ADDRESS=f'unix:path=/run/user/{os.getuid()}/bus')
    result = subprocess.run(['/usr/bin/systemctl', '--user', *args], env=env,
                            text=True, capture_output=True, timeout=15)
    if result.returncode and not (allow_missing and result.stdout.strip() == 'not-found'):
        # Never include arbitrary service stderr or private configuration values.
        raise RuntimeError('systemctl operation failed with exit' + str(result.returncode))
    return result.stdout.strip()


def capability() -> dict:
    version = subprocess.run(['/usr/bin/systemctl', '--version'], text=True,
                             capture_output=True, check=True).stdout.splitlines()[0]
    match = re.search(r'systemd (\d+)', version)
    if not match or int(match.group(1)) < 254:
        raise ValueError('systemd254 or newer is required for DelegateSubgroup')
    controllers = set(Path('/sys/fs/cgroup/cgroup.controllers').read_text().split())
    if not CONTROLLERS <= controllers:
        raise ValueError('Unified cgroup CPU/memory/pids controllers are unavailable')
    properties = ctl('show', 'init.scope', '--property=ControlGroup', '--property=ActiveState')
    return {'systemd': version, 'uid': os.getuid(), 'controllers': sorted(controllers),
            'current_membership': Path('/proc/self/cgroup').read_text().strip(),
            'user_manager_reachable': 'ActiveState=active' in properties,
            'qualification': 'READ_ONLY_CAPABILITY_ONLY; actual delegation and fences are unverified'}


def quote_unit(value: str) -> str:
    if '\n' in value or '\r' in value or '\0' in value:
        raise ValueError('Unit argument contains a forbidden character')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def directory_unit(value: str) -> str:
    # WorkingDirectory is one path field, not the ExecStart argument grammar.
    # Double quotes remain literal there and make an absolute path invalid.
    if not value.startswith('/') or value.strip() != value or any(ord(c) < 32 for c in value):
        raise ValueError('Working directory must be an absolute single-line path')
    return value.replace('%', '%%')


def prepare(args: argparse.Namespace) -> None:
    caps = capability()
    program = pin(args.program, args.program_sha256)
    with Path(program['path']).open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            raise ValueError('The Worker/probe entry must be a pinned ELF binary')
    config = pin(args.config, private=True)
    value = json.loads(Path(config['path']).read_text())
    if not isinstance(value, dict):
        raise ValueError('Worker/probe config must be a JSON object')
    if 'cgroup_delegation' in value or value.get('delegation'):
        raise ValueError('Bootstrap discovers delegation; the input must not preselect a shared root')
    if args.kind == 'probe' and value.get('schema_version') != 'forgeflow.physical-resource-probe.v1':
        raise ValueError('Probe config schema must be forgeflow.physical-resource-probe.v1')
    argument_file_pins = []
    if args.kind == 'probe':
        # Pin the actual Python helper as well as its ELF interpreter, before exec.
        for argument in value.get('args', []):
            path = Path(argument)
            if path.is_absolute() and path.exists():
                argument_file_pins.append(pin(path))
    if args.kind == 'worker' and args.env_file is None:
        raise ValueError('Worker mode requires a private token environment file')
    env_pin = pin(args.env_file, private=True) if args.env_file else None
    if env_pin:
        secrets = json.loads(Path(env_pin['path']).read_text())
        if (not isinstance(secrets, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in secrets.items())
                or not set(secrets) <= {'FORGEFLOW_WORKER_TOKEN', 'RUST_LOG'}):
            raise ValueError('Private environment supports only Worker token and RUST_LOG')
        if not secrets.get('FORGEFLOW_WORKER_TOKEN'):
            raise ValueError('Worker service token is missing')
    python_path = Path(sys.executable).resolve(strict=True)
    python_pin = pin(python_path)
    launcher_pin = pin(Path(__file__).resolve(strict=True))
    destination = args.output.absolute()
    if not destination.is_absolute() or destination.parent.resolve(strict=True) != destination.parent:
        raise ValueError('Select an absolute destination with resolved parent')
    destination.mkdir(mode=0o700)
    run_id = uuid.uuid4().hex
    unit = f'forgeflow-worker-{run_id}.service'
    # No hyphens in this slice name: one new private branch, not shared app.slice.
    slice_name = f'forgeflowresources{run_id}.slice'
    plan = {'schema_version': SCHEMA, 'kind': args.kind, 'unit_name': unit,
            'slice_name': slice_name, 'private_root': str(destination),
            'program': program, 'config': config, 'environment': env_pin,
            'python': python_pin, 'launcher': launcher_pin,
            'argument_file_pins': argument_file_pins,
            'capability': caps, 'delegation': None, 'actor_started': False}
    plan_path = destination / 'launch-plan.json'
    plan_sha = private_json(plan_path, plan)
    command = [str(python_path), '-I', launcher_pin['path'], '_bootstrap',
               '--plan', str(plan_path), '--plan-sha256', plan_sha]
    unit_text = '\n'.join([
        '[Unit]', 'Description=ForgeFlow private delegated Worker/runtime', '',
        '[Service]', 'Type=exec', f'Slice={slice_name}', 'Delegate=cpu memory pids',
        'DelegateSubgroup=supervisor', 'KillMode=control-group', 'TimeoutStopSec=10s',
        'Restart=no', 'UMask=0077', 'NoNewPrivileges=yes',
        'WorkingDirectory=' + directory_unit(str(destination)),
        'ExecStart=' + ' '.join(quote_unit(v) for v in command),
        'StandardOutput=append:' + str(destination / 'service.stdout.log'),
        'StandardError=append:' + str(destination / 'service.stderr.log'), '',
    ])
    unit_path = destination / unit
    with unit_path.open('x') as out:
        os.chmod(unit_path, 0o600)
        out.write(unit_text)
    approval = {'plan_sha256': plan_sha, 'unit_sha256': digest(unit_path),
                'unit_path': str(unit_path), 'unit_name': unit, 'slice_name': slice_name}
    private_json(destination / 'preparation.json', approval)
    print(json.dumps({'status': 'PREPARED_NO_ACTOR', **approval,
                      'private_root': str(destination), 'config_sha256': config['sha256'],
                      'program_sha256': program['sha256'], 'secret_values_printed': False}))


def load_plan(path: Path, expected: str) -> dict:
    pin(path, expected, private=True)
    value = json.loads(path.read_text())
    if value.get('schema_version') != SCHEMA or not UNIT_RE.fullmatch(value.get('unit_name', '')):
        raise ValueError('Invalid private launch plan')
    for key in ('program', 'config', 'python', 'launcher'):
        item = value[key]
        pin(Path(item['path']), item['sha256'], private=(key == 'config'))
    if value['environment']:
        item = value['environment']
        pin(Path(item['path']), item['sha256'], private=True)
    for item in value.get('argument_file_pins', []):
        pin(Path(item['path']), item['sha256'])
    return value


def bootstrap(args: argparse.Namespace) -> None:
    plan = load_plan(args.plan, args.plan_sha256)
    group = ctl('show', plan['unit_name'], '--property=ControlGroup', '--value')
    properties = dict(line.split('=', 1) for line in ctl('show', plan['unit_name'],
                       '--property=Delegate', '--property=DelegateControllers',
                       '--property=DelegateSubgroup').splitlines() if '=' in line)
    root = Path('/sys/fs/cgroup') / group.lstrip('/')
    if (not group.startswith('/') or not group.endswith('/' + plan['unit_name'])
            or plan['slice_name'] not in group.split('/') or root.is_symlink()
            or root.resolve(strict=True) != root or root.stat().st_uid != os.getuid()):
        raise ValueError('Delegated root is not the exact owned private service')
    membership = Path('/proc/self/cgroup').read_text().strip()
    if membership != '0::' + group + '/supervisor':
        raise ValueError('Bootstrap is not in the dedicated supervisor leaf')
    if properties.get('Delegate') != 'yes' or properties.get('DelegateSubgroup') != 'supervisor':
        raise ValueError('Actual unit delegation properties differ')
    if not CONTROLLERS <= set(properties.get('DelegateControllers', '').split()):
        raise ValueError('Actual unit delegation controllers differ')
    if (root / 'cgroup.procs').read_text().strip():
        raise ValueError('Private delegated interior root is populated')
    if not CONTROLLERS <= set((root / 'cgroup.controllers').read_text().split()):
        raise ValueError('Controllers are missing at the private service root')
    delegation = {'unit_name': plan['unit_name'], 'root_path': str(root)}
    config = json.loads(Path(plan['config']['path']).read_text())
    config['cgroup_delegation' if plan['kind'] == 'worker' else 'delegation'] = delegation
    directory = Path(plan['private_root'])
    config_path = directory / 'delegated-config.json'
    config_sha = private_json(config_path, config)
    private_json(directory / 'delegation.json', {
        'schema_version': 'forgeflow.cgroup-delegation-discovery.v1',
        **delegation, 'supervisor_pid': os.getpid(), 'supervisor_membership': membership,
        'root_inode': root.stat().st_ino, 'root_device': root.stat().st_dev,
        'unit_properties': properties, 'input_config_sha256': plan['config']['sha256'],
        'delegated_config_sha256': config_sha, 'controller_writes_by_launcher': 0,
    })
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'RUST_LOG': 'warn'}
    if plan['environment']:
        env.update(json.loads(Path(plan['environment']['path']).read_text()))
    flag = '--config' if plan['kind'] == 'worker' else '--physical-resource-probe'
    program = plan['program']['path']
    pin(Path(program), plan['program']['sha256'])
    os.execve(program, [program, flag, str(config_path)], env)


def start(args: argparse.Namespace) -> None:
    plan = load_plan(args.plan, args.plan_sha256)
    prep_path = args.plan.parent / 'preparation.json'
    regular(prep_path, private=True)
    prep = json.loads(prep_path.read_text())
    unit = Path(prep['unit_path'])
    pin(unit, args.unit_sha256, private=True)
    if prep['unit_sha256'] != args.unit_sha256 or prep['plan_sha256'] != args.plan_sha256:
        raise ValueError('Reviewed preparation differs from selected pins')
    if not args.execute:
        print(json.dumps({'status': 'DRY_RUN_NO_ACTOR', 'unit_name': plan['unit_name'],
                          'unit_text': unit.read_text(), 'program_sha256': plan['program']['sha256'],
                          'config_sha256': plan['config']['sha256'], 'token_values_printed': False}))
        return
    if ctl('show', plan['unit_name'], '--property=LoadState', '--value', allow_missing=True) != 'not-found':
        raise ValueError('Unit already exists; use a fresh prepared identity')
    ctl('link', str(unit))
    ctl('daemon-reload')
    ctl('start', plan['unit_name'])
    print(json.dumps({'status': 'UNIT_START_REQUESTED', 'unit_name': plan['unit_name'],
                      'private_root': plan['private_root'], 'qualification': 'NOT_YET_VERIFIED'}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('capability', help='Read-only cgroup/systemd facts; no units or limits changed')
    p = sub.add_parser('prepare', help='Prepare private plan/unit files without starting actors')
    p.add_argument('--kind', choices=('worker', 'probe'), required=True)
    p.add_argument('--program', type=Path, required=True)
    p.add_argument('--program-sha256', required=True)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--env-file', type=Path)
    p.add_argument('--output', type=Path, required=True)
    for command in ('start', '_bootstrap'):
        p = sub.add_parser(command)
        p.add_argument('--plan', type=Path, required=True)
        p.add_argument('--plan-sha256', required=True)
        if command == 'start':
            p.add_argument('--unit-sha256', required=True)
            p.add_argument('--execute', action='store_true', help='Actually link/start the reviewed private unit; only after Root GO')
    args = parser.parse_args()
    try:
        if args.command == 'capability': print(json.dumps(capability()))
        elif args.command == 'prepare': prepare(args)
        elif args.command == 'start': start(args)
        else: bootstrap(args)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'REFUSED', 'error_type': type(error).__name__,
                          'message': 'Delegated launch failed; retained private files for diagnosis. No fallback to shared cgroups.'}), file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

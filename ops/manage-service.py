#!/usr/bin/env python3
"""Install and inspect a persistent, user-owned ForgeFlow systemd service."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def quote(value):
    value = str(value)
    if '\n' in value or '\r' in value:
        raise ValueError('Service paths cannot contain newlines')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('install', 'status'))
    parser.add_argument('--name', default='forgeflow-control')
    parser.add_argument('--release-dir', type=Path)
    parser.add_argument('--runtime-env', type=Path)
    parser.add_argument('--worker-config', type=Path)
    parser.add_argument('--verifier-cgroups', action='store_true',
                        help='Delegate CPU/memory/pids to this control service for required verifier profiles')
    parser.add_argument('--start', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch(r'forgeflow-[a-z0-9][a-z0-9-]*', args.name):
        parser.error('Service name must start with forgeflow- and use lowercase letters, digits or hyphens')
    unit_name = args.name + '.service'
    if args.verifier_cgroups and (args.worker_config or not re.fullmatch(r'forgeflow-control(?:-[0-9a-f]{32})?', args.name)):
        parser.error('--verifier-cgroups requires a dedicated forgeflow-control or forgeflow-control-32hex service, without --worker-config')
    if args.command == 'status':
        subprocess.run(['systemctl', '--user', 'show', unit_name, '--property=ActiveState,SubState,MainPID,ExecMainStatus,FragmentPath'], check=True)
        return
    if args.release_dir is None or args.runtime_env is None:
        parser.error('install requires --release-dir and --runtime-env')
    release = args.release_dir.resolve(strict=True)
    private = args.runtime_env.absolute()
    if not private.is_file():
        raise ValueError('Runtime environment is missing')
    launcher_source = Path(__file__).with_name('run-service.py')
    digest = hashlib.sha256(launcher_source.read_bytes()).hexdigest()
    launch_dir = Path.home() / '.local/share/forgeflow/launchers' / digest
    launch_dir.mkdir(parents=True, exist_ok=True)
    launcher = launch_dir / 'run-service.py'
    if not launcher.exists():
        shutil.copyfile(launcher_source, launcher)
        launcher.chmod(0o500)
    elif hashlib.sha256(launcher.read_bytes()).hexdigest() != digest:
        raise ValueError('Existing launcher pin differs')
    unit_dir = Path.home() / '.config/systemd/user'
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit = unit_dir / unit_name
    argv = ['--release-dir', quote(release), '--runtime-env', quote(private)]
    if args.worker_config:
        argv.extend(['--worker-config', quote(args.worker_config.resolve(strict=True))])
    delegation_lines = []
    if args.verifier_cgroups:
        argv.extend(['--verifier-cgroups', '--service-name', quote(unit_name)])
        suffix = args.name.removeprefix('forgeflow-control').removeprefix('-')
        delegation_lines = [f'Slice=forgeflowcontrolresources{suffix}.slice',
                            'Delegate=cpu memory pids', 'DelegateSubgroup=supervisor',
                            'NoNewPrivileges=yes']
    content = '\n'.join([
        '[Unit]', 'Description=ForgeFlow local control service',
        'StartLimitIntervalSec=60', 'StartLimitBurst=5', '', '[Service]',
        'Type=simple', *delegation_lines,
        'ExecStart=:/usr/bin/python3 ' + quote(launcher) + ' ' + ' '.join(argv),
        'Restart=on-failure', 'RestartSec=3', 'TimeoutStopSec=60',
        'KillMode=mixed', 'UMask=0077', '', '[Install]',
        'WantedBy=default.target', '',
    ])
    if unit.exists() and unit.read_text() != content:
        raise ValueError('Existing service differs; stop and review its version before replacing the unit')
    unit.write_text(content)
    unit.chmod(0o600)
    subprocess.run(['systemctl', '--user', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', '--user', 'enable', unit_name], check=True)
    if args.start:
        subprocess.run(['systemctl', '--user', 'start', unit_name], check=True)
    print(json.dumps({'unit': str(unit), 'launcher': str(launcher), 'launcher_sha256': digest,
                      'release': str(release), 'start_requested': args.start,
                      'secrets_in_unit': False, 'verifier_cgroups': args.verifier_cgroups}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f'ForgeFlow service management failed ({type(error).__name__}).', file=sys.stderr)
        sys.exit(1)

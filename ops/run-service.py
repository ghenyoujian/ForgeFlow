#!/usr/bin/env python3
"""Load private configuration and exec a pinned installed server or Worker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import re
import subprocess
import sys

VERIFIER_ENV = 'FORGEFLOW_VERIFIER_CGROUP_DELEGATION'


def verifier_delegation(unit_name):
    if not re.fullmatch(r'forgeflow-control(?:-[0-9a-f]{32})?\.service', unit_name or ''):
        raise ValueError('Verifier delegation requires an exact dedicated control unit')
    env = dict(os.environ, XDG_RUNTIME_DIR=f'/run/user/{os.getuid()}',
               DBUS_SESSION_BUS_ADDRESS=f'unix:path=/run/user/{os.getuid()}/bus')
    result = subprocess.run(['/usr/bin/systemctl', '--user', 'show', unit_name,
        '--property=ControlGroup', '--property=Delegate', '--property=DelegateControllers',
        '--property=DelegateSubgroup'], env=env, text=True, capture_output=True,
        timeout=15, check=True)
    props = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    group = props.get('ControlGroup', '')
    root = Path('/sys/fs/cgroup') / group.lstrip('/')
    if (not group.startswith('/') or not group.endswith('/'+unit_name)
            or root.is_symlink() or root.resolve(strict=True) != root
            or not root.is_dir() or root.stat().st_uid != os.getuid()):
        raise ValueError('Control root must be the exact owned canonical service cgroup')
    if Path('/proc/self/cgroup').read_text().strip() != '0::'+group+'/supervisor':
        raise ValueError('Control launcher is not in its own delegated supervisor')
    if props.get('Delegate') != 'yes' or props.get('DelegateSubgroup') != 'supervisor':
        raise ValueError('Actual control unit delegation differs')
    controllers = {'cpu', 'memory', 'pids'}
    if (not controllers <= set(props.get('DelegateControllers', '').split())
            or not controllers <= set((root/'cgroup.controllers').read_text().split())
            or (root/'cgroup.procs').read_text().strip()
            or (root/'cgroup.type').read_text().strip() != 'domain'):
        raise ValueError('Control delegation needs CPU/memory/pids and an empty interior root')
    whole_mount = False
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        before, _, after = line.partition(' - ')
        fields = before.split()
        if after.split()[:1] == ['cgroup2'] and len(fields) >= 5 and fields[3:5] == ['/', '/sys/fs/cgroup']:
            whole_mount = True
    if not whole_mount:
        raise ValueError('Whole-tree canonical cgroup v2 mount required')
    return {'unit_name': unit_name, 'root_path': str(root)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-dir', required=True, type=Path)
    parser.add_argument('--runtime-env', required=True, type=Path)
    parser.add_argument('--worker-config', type=Path)
    parser.add_argument('--verifier-cgroups', action='store_true')
    parser.add_argument('--service-name')
    args = parser.parse_args()
    fd = os.open(args.runtime_env, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('Private runtime environment must be an owned regular mode-0600 file')
        values = json.load(stream)
    if not isinstance(values, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in values.items()):
        raise ValueError('Private runtime environment must contain string keys and values')
    if VERIFIER_ENV in values:
        raise ValueError('Private configuration must not preselect verifier delegation')
    if args.verifier_cgroups and args.worker_config:
        raise ValueError('Verifier delegation belongs to the control service')
    if args.service_name and not args.verifier_cgroups:
        raise ValueError('Service binding requires explicit verifier delegation')
    environment = dict(os.environ, **values)
    # Only the explicit pinned launcher path may discover and inject this binding.
    environment.pop(VERIFIER_ENV, None)
    if args.verifier_cgroups:
        environment[VERIFIER_ENV] = json.dumps(verifier_delegation(args.service_name), separators=(',', ':'))
    name = 'forgeflow-worker' if args.worker_config else 'forgeflow-server'
    program = args.release_dir / 'bin' / name
    manifest = json.loads((args.release_dir / 'delivery-manifest.json').read_text())
    expected = manifest['files'][f'bin/{name}']['sha256']
    if program.is_symlink() or not program.is_file():
        raise ValueError('Installed program must be a regular file')
    digest = hashlib.sha256()
    with program.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ValueError('Installed program differs from its delivery pin')
    if not args.worker_config:
        values['FORGEFLOW_CONSOLE_DIR'] = str(args.release_dir / 'console')
        environment['FORGEFLOW_CONSOLE_DIR'] = values['FORGEFLOW_CONSOLE_DIR']
    argv = [str(program)]
    if args.worker_config:
        argv.extend(['--config', str(args.worker_config)])
    os.execve(str(program), argv, environment)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        # Never expose private JSON values or connection credentials in errors.
        print(f'ForgeFlow service configuration rejected ({type(error).__name__}).', file=sys.stderr)
        sys.exit(1)

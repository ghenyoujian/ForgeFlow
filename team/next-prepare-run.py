#!/usr/bin/env python3
"""A00 local experiment preparation; never runs a model or reuses an old database."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import urllib.request
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
RT = Path('/home/chenyoujian/.cache/forgeflow-next/20261015T005028Z-f01')
BASE = RT / 'dual-preparation-r2'

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--run-id', required=True)
    ap.add_argument('--first', choices=['dsh', 'claude'], required=True)
    ap.add_argument('--build-receipt', type=Path)
    ap.add_argument('--code-scope-mode', choices=['EXACT_FILE', 'OWNED_DIRECTORY'], default='EXACT_FILE')
    ap.add_argument('--dsh-code-scope-mode', choices=['EXACT_FILE', 'OWNED_DIRECTORY'])
    ap.add_argument('--total-requests', type=int, default=12)
    ap.add_argument('--per-executor-requests', type=int, default=6)
    args = ap.parse_args()
    if not 1 <= args.total_requests <= 12 or not 1 <= args.per_executor_requests <= 6:
        raise SystemExit('request caps can only tighten the original 12/6 boundary')
    if not args.run_id.startswith('next') or not args.run_id[4:].isdigit():
        raise SystemExit('run id must be next followed by digits')
    run = args.run_id
    prep = RT / ('dual-preparation-' + run)
    state = RT / ('dual-server-state-' + run)
    workers = RT / ('dual-workers-' + run)
    output = ROOT / 'evidence/next/20261015T003541Z-00f024640b' / ('dual-leaf-' + run)
    if any(p.exists() for p in [prep, state, workers, output]):
        raise SystemExit('fresh paths required; old evidence must be preserved')
    prep.mkdir(mode=0o700)
    (prep / 'claude-profile-home').mkdir(mode=0o700)
    api_port, proxy_port = port(), port()
    while proxy_port == api_port:
        proxy_port = port()
    old = json.loads((BASE / 'run-manifest.json').read_text())
    pins = None
    if args.build_receipt:
        pins = json.loads(args.build_receipt.resolve(strict=True).read_text())['binaries']
        for item in pins.values():
            if digest(item['path']) != item['sha256']:
                raise SystemExit('build receipt binary changed')
    def rewrite(v):
        if isinstance(v, dict): return {k: rewrite(x) for k, x in v.items()}
        if isinstance(v, list): return [rewrite(x) for x in v]
        if isinstance(v, str):
            return v.replace(str(BASE), str(prep)).replace('next002', run).replace(':39461', ':' + str(proxy_port))
        return v
    for name in ['owner-token', 'master-worker-token', 'claude-worker-token', 'dsh-worker-token', 'claude-forwarder-token', 'dsh-forwarder-token']:
        fd = os.open(prep / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f: f.write(secrets.token_hex(32))
    for name in ['claude-worker-template.json', 'dsh-worker-template.json', 'claude-profile.json', 'claude-route.json', 'dsh-route.json', 'claude-resource.json', 'dsh-resource.json', 'gateway-config.json', 'worker-credentials.json']:
        value = rewrite(json.loads((BASE / name).read_text()))
        if pins and 'sandbox' in value:
            value['sandbox'].update(guard_program=pins['forgeflow-sandbox-guard']['path'],
                                    guard_sha256=pins['forgeflow-sandbox-guard']['sha256'])
        if args.code_scope_mode == 'OWNED_DIRECTORY':
            target = value if name == 'claude-profile.json' else value.get('profile') if name == 'claude-worker-template.json' else None
            if target is not None:
                target.update(id='next-claude-owned-directory-v1', tools_allowlist=['Read', 'Edit'])
        if name == 'worker-credentials.json':
            for worker in value['workers']:
                kind = 'claude' if 'claude' in worker['worker_id'] else 'dsh'
                worker['token'] = (prep / (kind + '-worker-token')).read_text()
        save(prep / name, value)
    manifest = rewrite(old)
    manifest.update(local_state_mode='SHARED_SERVER_WORKER_ROOT', code_scope_mode=args.code_scope_mode,
        request_limits={'total_requests': args.total_requests, 'per_executor_requests': args.per_executor_requests},
        run_id=run, executor_order=[args.first, 'claude' if args.first == 'dsh' else 'dsh'],
        output_root=str(output), private_runtime_root=str(workers), server_data_root=str(state),
        api_origin=f'http://127.0.0.1:{api_port}', forwarder_port=proxy_port)
    if args.dsh_code_scope_mode:
        manifest['code_scope_modes'] = {'dsh': args.dsh_code_scope_mode, 'claude': args.code_scope_mode}
    if pins:
        manifest['worker_binary'] = {k: pins['forgeflow-worker'][k] for k in ['path', 'sha256']}
        manifest['server_executable_sha256'] = pins['forgeflow-server']['sha256']
        manifest['build_receipt'] = {'path': str(args.build_receipt.resolve()), 'sha256': digest(args.build_receipt)}
    for config in manifest['executors'].values():
        for key in ['worker_config_template', 'executor_profile', 'resource_profile', 'model_route']:
            config[key]['sha256'] = digest(config[key]['path'])
    pgroot = Path('/home/chenyoujian/.cache/forgeflow-postgres/root')
    env = {'PATH': '/usr/bin:/bin', 'LD_LIBRARY_PATH': str(pgroot / 'usr/lib/x86_64-linux-gnu')}
    database = 'next_dual' + run[4:]
    with (prep / 'createdb.log').open('xb') as log:
        subprocess.run([str(pgroot / 'usr/lib/postgresql/16/bin/createdb'), '-h', '127.0.0.1', '-p', '39001', '-U', 'next_test', database], env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    dburl = f'postgresql://next_test@127.0.0.1:39001/{database}'
    server = Path(pins['forgeflow-server']['path']) if pins else RT / 'bin/forgeflow-server'
    if digest(server) != manifest['server_executable_sha256']:
        raise SystemExit('server binary changed')
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'DATABASE_URL': dburl,
        'FORGEFLOW_BIND': f'127.0.0.1:{api_port}', 'FORGEFLOW_DATA_ROOT': str(state),
        'FORGEFLOW_CONSOLE_DIR': str(RT / 'console'),
        'FORGEFLOW_OWNER_TOKEN': (prep / 'owner-token').read_text(),
        'FORGEFLOW_WORKER_TOKEN': (prep / 'master-worker-token').read_text(),
        'FORGEFLOW_WORKER_CREDENTIALS_FILE': str(prep / 'worker-credentials.json'),
        'FORGEFLOW_GATEWAY_CONFIG': str(prep / 'gateway-config.json'), 'RUST_LOG': 'info'}
    with (prep / 'server.log').open('xb') as log:
        proc = subprocess.Popen([str(server)], env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    manifest['server_pid'] = proc.pid
    save(prep / 'private.json', {'runtime': str(RT), 'api_port': api_port, 'forwarder_port': proxy_port, 'DATABASE_URL': dburl, 'database': database, 'server_pid': proc.pid})
    save(prep / 'run-manifest.json', manifest)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if proc.poll() is not None: raise SystemExit('owned server exited; inspect private server.log')
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(manifest['api_origin'] + '/healthz', timeout=1) as reply:
                if reply.status == 200: break
        except OSError: time.sleep(0.2)
    else: raise SystemExit('owned server health timeout; preserved for inspection')
    print(json.dumps({'status': 'PREPARED_NOT_EXECUTED', 'manifest_path': str(prep / 'run-manifest.json'),
        'manifest_sha256': digest(prep / 'run-manifest.json'), 'server_pid': proc.pid,
        'api_origin': manifest['api_origin'], 'database': database, 'actual_model_calls': 0}))

if __name__ == '__main__': main()

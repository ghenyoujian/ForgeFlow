#!/usr/bin/env python3
"""Run bounded actual DSH collaboration with private credentials and local qualification grants."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import yaml

HERE = Path(__file__).resolve().parent
PRESET = HERE.parents[1] / 'presets/forgeflow'
SOURCE = Path('/home/chenyoujian/.local/share/dsh-wsl/source')
sys.path.insert(0, str(PRESET))
from managed_controller import serve


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def call(socket_path, identity, operation, **fields):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(15)
        stream.connect(str(socket_path))
        stream.sendall(json.dumps({'schema_version': 'forgeflow.dsh-bridge.v1', 'operation': operation,
                                 **identity, **fields}).encode() + b'\n')
        stream.shutdown(socket.SHUT_WR)
        return json.loads(stream.makefile('rb').readline())


def rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def group_processes(pgid):
    result = []
    for directory in Path('/proc').glob('[0-9]*'):
        try:
            fields = (directory / 'stat').read_text().split(') ', 1)[1].split()
            if int(fields[2]) == pgid:
                result.append({'pid': int(directory.name), 'state': fields[0]})
        except (OSError, ValueError, IndexError):
            continue
    return result


def redact(raw):
    credentials = yaml.safe_load(Path('/home/chenyoujian/.cache/forgeflow-dsh-managed-probe/home/.credentials.yaml').read_text())
    values = []
    def collect(value):
        if isinstance(value, dict):
            for nested in value.values(): collect(nested)
        elif isinstance(value, list):
            for nested in value: collect(nested)
        elif isinstance(value, str) and len(value) >= 16:
            values.append(value)
    collect(credentials)
    for secret in values:
        raw = raw.replace(secret.encode(), b'[REDACTED_CREDENTIAL]')
    return raw


def run_probe(mode):
    private_root = Path('/home/chenyoujian/.cache/forgeflow-dsh-managed-probe/collaboration')
    private_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_dir = Path(tempfile.mkdtemp(prefix=mode + '-', dir=private_root))
    identity = {'project_id': 'local-collaboration-qualification', 'task_id': mode,
                'attempt_id': str(uuid.uuid4()), 'generation': 1}
    policy = {**identity, 'provider': 'newapi', 'model': 'glm-5.3', 'max_depth': 2,
              'max_live_agents': 8, 'max_total_lifecycles': 16, 'max_model_requests': 32,
              'max_live_model_requests': 8,
              'max_output_tokens': 4096}
    artifact_hashes = {str(path.relative_to(HERE.parents[1])): digest(path) for path in
                      [PRESET / 'launch.py', PRESET / 'managed-bridge.mjs', PRESET / 'managed_controller.py', HERE / 'probe-plugin.mjs']}
    identity_file = run_dir / 'identity.json'
    identity_file.write_text(json.dumps(identity))
    socket_path, ledger = run_dir / 'controller.sock', run_dir / 'controller.ndjson'
    server, controller = serve(policy, socket_path, ledger)
    prompt = f'Explicit qualification request: use workflow, Agent Teams, and subagents. Call only forgeflow_collaboration_probe with mode "{mode}" exactly once, wait for its result, then report the result succinctly. Do not call any other tools, modify files, or delegate outside that probe.'
    command = ['python', str(PRESET / 'launch.py'), '--role', 'lead',
               '--controller-socket', str(socket_path), '--identity-file', str(identity_file),
               '--qualification-plugin', str(HERE / 'probe-plugin.mjs'), prompt]
    started = time.monotonic()
    timed_out = False
    revoked_at = None
    processes_at_revoke = []
    with (run_dir / 'stdout.ndjson').open('wb') as stdout, (run_dir / 'stderr.log').open('wb') as stderr:
        process = subprocess.Popen(command, cwd=run_dir, stdout=stdout, stderr=stderr, start_new_session=True)
        deadline = started + 180
        while process.poll() is None and time.monotonic() < deadline:
            if mode == 'cancel' and revoked_at is None:
                observed = rows(ledger)
                children = {row['native_session_id'] for row in observed if row['operation'] == 'admit' and row['parent_session_id'] is not None}
                if any(row['operation'] == 'model_request' and row['native_session_id'] in children for row in observed):
                    processes_at_revoke = group_processes(process.pid)
                    response = call(socket_path, identity, 'revoke', reason='actual_active_native_child_probe')
                    if response.get('ok'):
                        revoked_at = time.monotonic()
            time.sleep(0.1)
        if process.poll() is None:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    # DSH unloads plugin listeners before its root registry. Retain that allocation
    # until the independent supervisor observes process-group quiescence.
    remaining = group_processes(process.pid)
    if not remaining:
        call(socket_path, identity, 'observe', event='supervisor/process-group-exited',
             value={'pgid': process.pid, 'exit_code': process.returncode, 'remaining_process_group': []})
        for native, allocation in controller.allocations.items():
            if not allocation['released']:
                call(socket_path, identity, 'release', native_session_id=native,
                     allocation_id=allocation['allocation_id'], reason='supervisor_process_group_quiescent')
    # The controller stays alive until native lifecycle and observation events have settled.
    server.shutdown()
    server.server_close()
    controller.file.close()
    socket_path.unlink(missing_ok=True)
    for source, destination in [('stdout.ndjson', f'{mode}.stdout.ndjson'), ('stderr.log', f'{mode}.stderr.log'), ('controller.ndjson', f'{mode}.controller.ndjson')]:
        (HERE / destination).write_bytes(redact((run_dir / source).read_bytes()))
    receipt = {'schema_version': 'forgeflow.dsh-collaboration-probe.v1', 'mode': mode,
               'authority': 'LOCAL_QUALIFICATION_ONLY', 'identity': identity, 'policy': policy,
               'exit_code': process.returncode, 'timed_out': timed_out,
               'elapsed_seconds': round(time.monotonic() - started, 3),
               'revoke_issued': revoked_at is not None,
               'processes_at_revoke': processes_at_revoke, 'remaining_process_group': remaining,
               'native_root_session_id': controller.root,
               'program': '/usr/bin/node', 'entrypoint': str(SOURCE / 'apps/cli/lib/bin.js'),
               'cwd': str(run_dir), 'private_original_evidence_dir': str(run_dir),
               'model_route': {'provider': policy['provider'], 'model': policy['model']},
               'production_admission': 'BLOCKED_PENDING_CANONICAL_CHILD_ACCOUNTING',
               'unverified': ['PostgreSQL resource/fence authority', 'OS whole-egress containment',
                              'exact financial accounting with missing usage', '100+ real-session capacity'],
               'artifact_sha256': artifact_hashes,
               'evidence_sha256': {f'{mode}.{name}': digest(HERE / f'{mode}.{name}') for name in
                                   ['stdout.ndjson', 'stderr.log', 'controller.ndjson']}}
    (HERE / f'{mode}.receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['finite', 'cancel'], default='finite')
    run_probe(parser.parse_args().mode)

#!/usr/bin/env python3
"""Close one retained native parent through actual Worker recovery, without models."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

PSQL = Path('/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/postgresql/16/bin/psql')
PG_LIB = '/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/x86_64-linux-gnu'
PINNED = Path('/home/chenyoujian/.cache/forgeflow-build-checkpoints/703377a0da221e19-6yv0poas/receipt.json')
DEFAULT_PROJECT = 'canonical-native-dda412bc2121'
DEFAULT_ATTEMPT = 'f2a997b8-be18-48a4-aabb-8466346bf4a5'


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def proc(pid: int) -> dict | None:
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
        return {'pid': pid, 'state': fields[0], 'pgid': int(fields[2]),
                'start_ticks': int(fields[19]), 'exe': str(Path(f'/proc/{pid}/exe').resolve())}
    except (OSError, ValueError, IndexError):
        return None


def live_group(identity: dict) -> list[dict]:
    return [p for d in Path('/proc').iterdir() if d.name.isdigit()
            if (p := proc(int(d.name))) and p['pgid'] == identity['pgid']
            and p['state'] not in ('Z', 'X')]


class Evidence:
    def __init__(self, output: Path, env: dict, project: str, attempt: str, port: int):
        self.output, self.env, self.project, self.attempt = output, env, project, attempt
        self.base = f'http://127.0.0.1:{port}'
        self.http_count = 0
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(self, method: str, path: str, body: object = None) -> tuple[int, object]:
        self.http_count += 1
        headers = {'Authorization': 'Bearer ' + self.env['FORGEFLOW_OWNER_TOKEN']}
        if body is not None:
            headers.update({'Content-Type': 'application/json', 'Idempotency-Key': uuid.uuid4().hex})
        request = urllib.request.Request(self.base + path, method=method, headers=headers,
            data=None if body is None else json.dumps(body).encode())
        began = time.monotonic()
        try:
            with self.opener.open(request, timeout=8) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read()
        except OSError as error:
            save(self.output / f'http-{self.http_count:04}.json', {
                'method': method, 'path': path, 'request': body,
                'observed_at': utc(), 'transport_error': type(error).__name__,
            })
            raise
        response = json.loads(raw) if raw else None
        save(self.output / f'http-{self.http_count:04}.json', {
            'method': method, 'path': path, 'request': body, 'status': status,
            'observed_at': utc(), 'latency_ms': (time.monotonic() - began) * 1000,
            'response': response, 'response_sha256': hashlib.sha256(raw).hexdigest(),
        })
        return status, response

    def database(self, name: str) -> dict:
        # All identifiers are validated before interpolation. These transactions
        # are read-only; resource and state changes come solely from public APIs.
        project, attempt = self.project, self.attempt
        query = f"""BEGIN READ ONLY;
SELECT json_build_object(
 'database',current_database(),
 'projects',(SELECT json_agg(data) FROM projects WHERE project_id='{project}'),
 'attempts',(SELECT json_agg(row_to_json(x)) FROM attempts x WHERE project_id='{project}' AND attempt_id='{attempt}'),
 'allocations',(SELECT json_agg(row_to_json(x)) FROM resource_allocations x WHERE project_id='{project}' AND attempt_id='{attempt}'),
 'leases',(SELECT json_agg(row_to_json(x)) FROM leases x WHERE attempt_id='{attempt}'),
 'native_lifecycles',(SELECT json_agg(row_to_json(x)) FROM native_child_lifecycles x WHERE attempt_id='{attempt}'),
 'native_allocations',(SELECT json_agg(row_to_json(x)) FROM native_child_allocations x WHERE attempt_id='{attempt}'),
 'native_requests',(SELECT json_agg(row_to_json(x)) FROM native_model_requests x WHERE attempt_id='{attempt}'),
 'gateway_permits',(SELECT json_agg(row_to_json(x)) FROM model_request_permit x WHERE attempt_id='{attempt}'),
 'events',(SELECT json_agg(row_to_json(x)) FROM events x WHERE project_id='{project}' AND object_id='{attempt}'),
 'stop_outbox',(SELECT json_agg(row_to_json(x)) FROM outbox x WHERE project_id='{project}' AND payload->>'attempt_id'='{attempt}')
); COMMIT;"""
        process_env = os.environ.copy()
        process_env['LD_LIBRARY_PATH'] = PG_LIB
        result = subprocess.run([str(PSQL), '-X', '-t', '-A', '-d', self.env['DATABASE_URL'], '-c', query],
                                env=process_env, text=True, capture_output=True, timeout=15)
        if result.returncode:
            raise RuntimeError('read-only private database observation failed: ' + result.stderr[:500])
        rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        if len(rows) != 1:
            raise RuntimeError('unexpected private database observation shape')
        save(self.output / f'{name}.postgres.json', rows[0])
        return rows[0]


def copy_journal(journal: Path, output: Path) -> dict:
    manifest = {}
    names = ['envelope.json', 'execution-id.json', 'launch-intent.json', 'launch-receipt.json',
             'stop.json', 'result.json', 'result-ack.json', 'result-delivery-policy.json',
             'native-controller.json', 'native-rpc/transport-closed.json',
             'post-author-stop-result.json']
    names += [p.name for p in journal.glob('result-*-ack.json')]
    for name in names:
        source = journal / name
        if source.is_file():
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            manifest[name] = {'bytes': source.stat().st_size, 'sha256': sha(source)}
    save(output / 'manifest.json', manifest)
    return manifest


def stop_actor(actor: subprocess.Popen, expected: dict, output: Path, name: str) -> None:
    observed = proc(actor.pid)
    if actor.poll() is None:
        if observed is None or observed['start_ticks'] != expected['start_ticks'] or observed['exe'] != expected['exe']:
            raise RuntimeError(f'{name} process fingerprint changed; refuse signalling')
        actor.send_signal(signal.SIGTERM)
        try:
            actor.wait(timeout=25)
        except subprocess.TimeoutExpired:
            observed = proc(actor.pid)
            if observed and observed['start_ticks'] == expected['start_ticks'] and observed['exe'] == expected['exe']:
                actor.kill()
                actor.wait(timeout=5)
    save(output / f'{name}.stopped.json', {'pid': actor.pid, 'fingerprint': expected,
        'exit_code': actor.poll(), 'observed_at': utc(), 'process_after': proc(actor.pid)})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-root', type=Path, default=Path('/tmp/ff-canon-ec70e28e'))
    parser.add_argument('--receipt', type=Path, default=PINNED)
    parser.add_argument('--project', default=DEFAULT_PROJECT)
    parser.add_argument('--attempt', default=DEFAULT_ATTEMPT)
    parser.add_argument('--port', type=int, default=8796)
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.project != DEFAULT_PROJECT or args.attempt != DEFAULT_ATTEMPT:
        raise RuntimeError('this cleanup is scoped only to the explicitly authorized retained parent')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', args.project):
        raise RuntimeError('invalid project identity')
    uuid.UUID(args.attempt)
    args.output.mkdir(parents=True, exist_ok=False)
    env = json.loads((args.private_root / 'runtime-env.json').read_text())
    config = json.loads((args.private_root / 'worker-config.json').read_text())
    database = urllib.parse.urlsplit(env['DATABASE_URL']).path.lstrip('/')
    if database != 'ff_canonical_54926b9b6282408f' or config['project_id'] != args.project:
        raise RuntimeError('private database/project scope mismatch')
    with socket.socket() as check:
        if check.connect_ex(('127.0.0.1', args.port)) == 0:
            raise RuntimeError('cleanup API port already occupied; no replacement permitted')
    evidence = Evidence(args.output, env, args.project, args.attempt, args.port)
    before = evidence.database('before')
    if len(before['attempts'] or []) != 1 or not before['projects'][0]['paused']:
        raise RuntimeError('exact retained parent and already-paused project required')
    journal = Path(config['data_root']) / 'attempts' / args.attempt
    launch = json.loads((journal / 'launch-receipt.json').read_text())
    original_stop = json.loads((journal / 'stop.json').read_text())
    envelope = json.loads((journal / 'envelope.json').read_text())
    original_result = sha(journal / 'result.json')
    initial_group = live_group(launch['process'])
    save(args.output / 'original-process-observation.json', {
        'observed_at': utc(), 'process_identity': launch['process'], 'live_group': initial_group,
        'original_process': proc(launch['process']['pid']),
        'current_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'original_stop': original_stop,
    })
    if initial_group or not original_stop['process_exit_confirmed'] or envelope['worker_id'] != config['worker_id']:
        raise RuntimeError('requires actual original quiescence and matching frozen Worker identity')
    original_manifest = copy_journal(journal, args.output / 'journal-before')
    receipt = json.loads(args.receipt.read_text())
    for binary in ['forgeflow-server', 'forgeflow-worker']:
        binding = receipt['binaries'][binary]
        if sha(Path(binding['path'])) != binding['sha256']:
            raise RuntimeError('pinned executable content changed')
    shutil.copyfile(args.receipt, args.output / 'build.receipt.json')
    report = {'schema_version': 'forgeflow.native-parent-cleanup.v1', 'status': 'RUNNING',
              'project_id': args.project, 'attempt_id': args.attempt, 'database': database,
              'started_at': utc(), 'source_identity': receipt['source_identity'],
              'scope': 'existing native parent closure via Owner cancellation and actual Worker recovery; no new author/models',
              'before_parent_state': before['attempts'][0]['state'],
              'before_parent_allocation_count': len(before['allocations'] or []),
              'before_native_model_requests': len(before['native_requests'] or []),
              'original_journal_manifest': original_manifest, 'errors': []}
    save(args.output / 'report.json', report)
    server = worker = None
    actors = []
    process_env = os.environ.copy()
    process_env.update(env)
    process_env['FORGEFLOW_BIND'] = f'127.0.0.1:{args.port}'
    try:
        with (args.output / 'server.txt').open('wb') as log:
            server = subprocess.Popen([receipt['binaries']['forgeflow-server']['path']],
                                      env=process_env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        time.sleep(0.1)
        server_identity = proc(server.pid)
        if server_identity is None:
            raise RuntimeError('cleanup API failed to start')
        actors.append((server, server_identity, 'server'))
        ready_deadline = time.monotonic() + 20
        while time.monotonic() < ready_deadline:
            if server.poll() is not None:
                raise RuntimeError('cleanup API exited before ready')
            try:
                if evidence.api('GET', '/healthz')[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError('cleanup API health deadline exceeded')
        status, observed = evidence.api('GET', f'/api/v1/attempts/{args.attempt}?project_id={args.project}')
        if status != 200:
            raise RuntimeError('cannot observe exact original parent through public API')
        parent = observed['data']
        if parent['state'] not in ('CANCELLED', 'SUCCEEDED', 'FAILED', 'TIMED_OUT'):
            status, cancellation = evidence.api('POST', f'/api/v1/attempts/{args.attempt}/cancel', {
                'project_id': args.project, 'expected_revision': parent['revision'],
                'reason': 'Recover retained finite native parent after original API/Worker shutdown; no business acceptance or new execution',
            })
            if status != 200:
                raise RuntimeError('Owner cancellation rejected')
        recovery_config = dict(config)
        recovery_config['control_url'] = evidence.base
        private_config = args.private_root / f'worker-config.cleanup-{args.port}.json'
        private_config.write_text(json.dumps(recovery_config))
        private_config.chmod(0o600)
        save(args.output / 'worker-config-identity.json', {
            'original_sha256': sha(args.private_root / 'worker-config.json'),
            'recovery_sha256': sha(private_config), 'changed_fields': ['control_url'],
            'worker_id': config['worker_id'], 'project_id': config['project_id'],
            'data_root': config['data_root'], 'new_control_url': evidence.base,
            'original_envelope_sha256': sha(journal / 'envelope.json'),
        })
        with (args.output / 'worker.txt').open('wb') as log:
            worker = subprocess.Popen([receipt['binaries']['forgeflow-worker']['path'], '--config', str(private_config)],
                                      env=process_env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        time.sleep(0.1)
        worker_identity = proc(worker.pid)
        if worker_identity is None:
            raise RuntimeError('recovery Worker failed to start')
        actors.append((worker, worker_identity, 'worker'))
        save(args.output / 'live-handles.json', {'started_at': utc(), 'server': server_identity, 'worker': worker_identity})
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            if worker.poll() is not None:
                raise RuntimeError('recovery Worker exited before confirmed parent closure')
            status, observed = evidence.api('GET', f'/api/v1/attempts/{args.attempt}?project_id={args.project}')
            if status == 200 and observed['data']['state'] in ('CANCELLED', 'SUCCEEDED', 'FAILED', 'TIMED_OUT'):
                break
            time.sleep(0.5)
        else:
            raise RuntimeError('parent terminal closure deadline exceeded; preserve retained allocations')
        after = evidence.database('after')
        post_manifest = copy_journal(journal, args.output / 'journal-after')
        checks = {
            'parent_terminal': after['attempts'][0]['state'] in ('CANCELLED', 'SUCCEEDED', 'FAILED', 'TIMED_OUT'),
            'all_20_parent_allocations_released': len(after['allocations'] or []) == 20 and all(x['state'] == 'RELEASED' for x in after['allocations']),
            'exact_generation_worker_preserved': after['attempts'][0]['generation'] == envelope['generation'] and after['attempts'][0]['worker_id'] == envelope['worker_id'],
            'all_child_lifecycles_released': all(x['state'] == 'RELEASED' for x in after['native_lifecycles'] or []),
            'all_child_allocations_released': all(x['state'] == 'RELEASED' for x in after['native_allocations'] or []),
            'no_pending_models': all(x['status'] not in ('ADMITTED', 'QUARANTINED') for x in after['native_requests'] or []),
            'no_new_model_requests': len(after['native_requests'] or []) == len(before['native_requests'] or []),
            'original_result_bytes_preserved': sha(journal / 'result.json') == original_result,
            'original_stop_bytes_preserved': sha(journal / 'stop.json') == original_manifest['stop.json']['sha256'],
            'no_original_author_process': not live_group(launch['process']),
            'project_remains_paused': after['projects'][0]['paused'],
            'leases_revoked': all(x['revoked_at'] is not None for x in after['leases'] or []),
            'actual_worker_stop_callback_exists': 'post-author-stop-result.json' in post_manifest,
        }
        report.update({'checks': checks, 'after_parent_state': after['attempts'][0]['state'],
                       'after_parent_allocation_states': {s: sum(x['state'] == s for x in after['allocations'])
                                                        for s in ['HELD', 'RESERVED', 'QUARANTINED', 'RELEASED']},
                       'after_native_model_requests': len(after['native_requests'] or [])})
        if not all(checks.values()):
            raise RuntimeError('cleanup evidence did not satisfy all scoped closure checks')
        report['status'] = 'PASS'
    except Exception as error:
        report['status'] = 'FAIL'
        report['errors'].append({'type': type(error).__name__, 'message': str(error)})
    finally:
        for actor, identity, name in reversed(actors):
            try:
                stop_actor(actor, identity, args.output, name)
            except Exception as error:
                report['errors'].append({'actor': name, 'type': type(error).__name__, 'message': str(error)})
                report['status'] = 'FAIL'
        try:
            final = evidence.database('final-after-actors-stopped')
            report['retained_parent_allocations'] = sum(x['state'] != 'RELEASED' for x in final['allocations'] or [])
            report['actual_original_author_processes'] = live_group(launch['process'])
            if report['status'] == 'PASS' and report['retained_parent_allocations']:
                report['status'] = 'FAIL'
        except Exception as error:
            report['errors'].append({'type': type(error).__name__, 'message': str(error)})
            report['status'] = 'FAIL'
        report['ended_at'] = utc()
        report['http_observations'] = evidence.http_count
        save(args.output / 'report.json', report)
        save(args.output / 'artifact-manifest.json', {
            str(p.relative_to(args.output)): {'sha256': sha(p), 'bytes': p.stat().st_size}
            for p in args.output.rglob('*') if p.is_file() and p.name != 'artifact-manifest.json'
        })
    print(json.dumps({'status': report['status'], 'output': str(args.output),
                      'parent_state': report.get('after_parent_state'),
                      'retained_parent_allocations': report.get('retained_parent_allocations'),
                      'errors': report['errors']}, ensure_ascii=False))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

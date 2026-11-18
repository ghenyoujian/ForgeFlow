#!/usr/bin/env python3
"""One real offline restore of completed public-contract history; no model/Worker rerun."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ops'))
from backup import fingerprints, pg_environment, git

PG_BIN = Path('/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/postgresql/16/bin')
PG_LIBRARY = '/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/x86_64-linux-gnu'


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def save(path, value, private=False):
    if private:
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    else:
        Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def check(report, name, condition, facts=None):
    report['checks'].append({'name': name, 'status': 'PASS' if condition else 'FAIL', 'facts': facts})
    if not condition:
        raise RuntimeError(name)


def database(url, statement):
    env = pg_environment(url)
    env['LD_LIBRARY_PATH'] = PG_LIBRARY
    result = subprocess.run([str(PG_BIN / 'psql'), '-X', '--no-password', '-t', '-A', '--set', 'ON_ERROR_STOP=1', '--command', statement], env=env, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('PostgreSQL command failed; private connection values are withheld')
    return result.stdout.decode().strip()


def historical(url):
    # Immutable business history only; restored leases, current paths and auth intentionally change.
    queries = {
        'attempts': 'SELECT row_to_json(x) FROM (SELECT project_id,attempt_id,task_id,state,data,envelope FROM attempts ORDER BY attempt_id) x',
        'evidence': 'SELECT row_to_json(x) FROM (SELECT * FROM evidence_receipts ORDER BY receipt_id) x',
        'flows': 'SELECT row_to_json(x) FROM (SELECT * FROM flow_revisions ORDER BY project_id,flow_revision) x',
        'contracts_and_integration': "SELECT row_to_json(x) FROM (SELECT project_id,collection,document_id,revision,data FROM documents WHERE collection IN ('contract_versions','integration_receipts','verification_receipts','contract_freeze_requests') ORDER BY project_id,collection,document_id) x",
    }
    return {key: [json.loads(line) for line in database(url, query).splitlines() if line] for key, query in queries.items()}


def authoritative_artifacts(url, project_id):
    project = project_id.replace("'", "''")
    rows = database(url, "SELECT row_to_json(x) FROM (SELECT document_id,data FROM documents WHERE project_id='" + project + "' AND collection='artifacts' ORDER BY document_id) x")
    return [json.loads(line) for line in rows.splitlines() if line]


def request(report, output, base, method, path, token=None, body=None, sensitive=False):
    headers = {'Content-Type': 'application/json', 'Idempotency-Key': str(uuid.uuid4())}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), method=method, headers=headers)
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    except urllib.error.URLError:
        return 0, None
    index = len(report.setdefault('http', [])) + 1
    entry = {'method': method, 'path': path, 'status': status, 'response_sha256': hashlib.sha256(raw).hexdigest(), 'credentials_recorded': False}
    if not sensitive:
        file = output / f'http-{index:04d}.response.bin'
        file.write_bytes(raw)
        entry['response_file'] = file.name
    report['http'].append(entry)
    try:
        return status, json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return status, raw


def start(report, output, binary, env, name):
    port = int(env['FORGEFLOW_BIND'].rsplit(':', 1)[1])
    with socket.socket() as probe:
        if probe.connect_ex(('127.0.0.1', port)) == 0:
            raise RuntimeError('Dedicated restore API port is already in use; no actor restarted')
    log = (output / (name + '.server.txt')).open('wb')
    process = subprocess.Popen([binary], env={'PATH': '/usr/bin:/bin', **env}, stdout=log, stderr=subprocess.STDOUT)
    base = 'http://127.0.0.1:' + str(port)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log.close()
            raise RuntimeError(name + ' server exited before readiness')
        if request(report, output, base, 'GET', '/healthz')[0] == 200:
            return process, log, base
        time.sleep(.25)
    process.terminate()
    process.wait(timeout=25)
    log.close()
    raise RuntimeError(name + ' readiness timed out; same actor stopped with retained log')


def stop(process, log, report, name):
    if process is None:
        return
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=25)
    log.close()
    report.setdefault('shutdown', {})[name] = {'pid': process.pid, 'exit_code': process.returncode, 'exited': True}


def binary(receipt_path, report, name):
    receipt = json.loads(receipt_path.read_text())
    if not receipt.get('consistent_copy') or not receipt.get('source_unchanged_after_build') or any(command['exit_code'] for command in receipt['commands']):
        raise RuntimeError('Approved build receipt is not complete/consistent')
    pinned = receipt['binaries']['forgeflow-server']
    if sha(pinned['path']) != pinned['sha256']:
        raise RuntimeError('Server binary pin mismatch')
    report[name] = {'source_identity': receipt['source_identity'], 'receipt_sha256': sha(receipt_path), 'server': pinned, 'scope': receipt['scope']}
    return pinned['path']


def operation(output, name, argv, env):
    result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, timeout=180)
    (output / (name + '.stdout.txt')).write_bytes(result.stdout)
    (output / (name + '.stderr.txt')).write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError(name + ' failed; original logs retained')
    return json.loads(result.stdout)


def prepare(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema_version': 'forgeflow.restore-rehearsal.v1', 'at': datetime.now(timezone.utc).isoformat(),
              'status': 'INCONCLUSIVE', 'phase': 'PREPARING', 'checks': [], 'errors': [], 'model_requests': 0,
              'worker_processes_started': 0, 'production_qualified': False, 'credential_values_disclosed': False,
              'scope': 'Actual quiescent completed controlled public-contract history restored into a new database and directory; no producer/consumer/model rerun'}
    source = source_log = None
    try:
        history_report = json.loads(args.source_report.read_text())
        parent_path = Path(history_report['parent_evidence'])
        parent = json.loads((parent_path / 'report.json').read_text())
        check(report, 'reuses_closed_actual_history', history_report['status'] == parent['status'] == 'PASS' and all(p['exited'] for p in history_report['process_shutdown'].values()))
        source_private = Path(parent['private_root'])
        source_env = json.loads((args.source_env or source_private / 'runtime-env.json').read_text())
        expected_database = parent['isolated_database_name']
        check(report, 'source_is_exact_private_public_contract_database', urllib.parse.urlsplit(source_env['DATABASE_URL']).path == '/' + expected_database)
        private = Path(tempfile.mkdtemp(prefix='forgeflow-restore-rehearsal-', dir='/home/chenyoujian/.cache'))
        report.update(private_root=str(private), source_report=str(args.source_report.resolve()), source_report_sha256=sha(args.source_report), source_private_root=str(source_private), source_database_name=expected_database, project_id=history_report['project_id'])
        source_env.update(FORGEFLOW_BIND='127.0.0.1:8796')
        source_auth = json.loads((Path(source_env['FORGEFLOW_DATA_ROOT']) / 'auth.json').read_text())
        if source_auth.get('password_hash') and 'FORGEFLOW_OWNER_PASSWORD' not in source_env:
            raise RuntimeError('Source auth already initialized; supply prior private --source-env to preserve actual credentials')
        source_env.setdefault('FORGEFLOW_OWNER_PASSWORD', secrets.token_urlsafe(32))
        save(private / 'source-env.json', source_env, True)
        closed = database(source_env['DATABASE_URL'], "SELECT json_build_object('open_attempts',(SELECT count(*) FROM attempts WHERE terminal_at IS NULL),'open_allocations',(SELECT count(*) FROM resource_allocations WHERE state<>'RELEASED'),'unknown_models',(SELECT count(*) FROM model_request_permit WHERE status IN ('ADMITTED','QUARANTINED')))")
        check(report, 'source_quiescent_before_start', all(value == 0 for value in json.loads(closed).values()), json.loads(closed))
        server = binary(args.build_receipt, report, 'prepare_build')
        source, source_log, base = start(report, output, server, source_env, 'source')
        status, login = request(report, output, base, 'POST', '/api/v1/session', body={'password': source_env['FORGEFLOW_OWNER_PASSWORD']}, sensitive=True)
        check(report, 'source_owner_login_before_backup', status == 200)
        source_session = login['data']['token']
        project = request(report, output, base, 'GET', '/api/v1/projects/' + report['project_id'], source_env['FORGEFLOW_OWNER_TOKEN'])[1]['data']
        report['source_project_root'] = project['root_path']
        backup_path, restore_path = private / 'backup', private / 'restored'
        ops_env = {'PATH': str(PG_BIN) + ':' + os.environ['PATH'], 'LD_LIBRARY_PATH': PG_LIBRARY, 'PYTHONDONTWRITEBYTECODE': '1', **source_env, 'FORGEFLOW_API_URL': base}
        started = time.monotonic()
        result = operation(output, 'backup', [sys.executable, '-B', str(ROOT / 'ops/backup.py'), '--destination', str(backup_path), '--data-root', source_env['FORGEFLOW_DATA_ROOT'], '--repository', project['root_path']], ops_env)
        report['backup_seconds'] = time.monotonic() - started
        check(report, 'real_pg_dump_and_quiescent_file_backup', (backup_path / 'postgres.dump').stat().st_size > 0 and result['dispatch_paused'], result)
        baseline = historical(source_env['DATABASE_URL'])
        save(output / 'original-history.json', baseline)
        stop(source, source_log, report, 'source'); source = source_log = None
        name = 'ff_restore_rehearsal_' + uuid.uuid4().hex[:12]
        original = urllib.parse.urlsplit(source_env['DATABASE_URL'])
        admin = urllib.parse.urlunsplit(original._replace(path='/postgres'))
        database(admin, 'CREATE DATABASE "' + name + '"')
        restored_env = {**source_env, 'DATABASE_URL': urllib.parse.urlunsplit(original._replace(path='/' + name)),
                        'FORGEFLOW_BIND': '127.0.0.1:8797', 'FORGEFLOW_DATA_ROOT': str(restore_path / 'data'),
                        'FORGEFLOW_OWNER_TOKEN': secrets.token_urlsafe(40), 'FORGEFLOW_WORKER_TOKEN': secrets.token_urlsafe(40),
                        'FORGEFLOW_OWNER_PASSWORD': secrets.token_urlsafe(32), 'FORGEFLOW_RESTORE_MODE': '1',
                        'FORGEFLOW_WORKER_ID': 'restore-worker-' + uuid.uuid4().hex[:12], 'FORGEFLOW_WORKER_PROJECT_ID': report['project_id']}
        save(private / 'restored-env.json', restored_env, True)
        save(private / 'private-auth-state.json', {'source_session': source_session}, True)
        started = time.monotonic()
        result = operation(output, 'restore', [sys.executable, '-B', str(ROOT / 'ops/restore.py'), '--backup', str(backup_path), '--destination', str(restore_path), '--database-env', str(private / 'restored-env.json'), '--reset-owner-password'], ops_env)
        report['restore_seconds'] = time.monotonic() - started
        check(report, 'actual_restore_to_new_empty_database', historical(restored_env['DATABASE_URL']) == baseline, {'database_name': name})
        restored_auth = json.loads((restore_path / 'data/auth.json').read_text())
        check(report, 'restored_sessions_and_password_hash_cleared', not restored_auth['sessions'] and restored_auth['password_hash'] is None)
        manifest = json.loads((backup_path / 'manifest.json').read_text())
        mapping = json.loads((restore_path / 'restore-relocation.json').read_text())
        report.update(backup_path=str(backup_path), restore_path=str(restore_path), relocation_manifest=str(restore_path / 'restore-relocation.json'), backup_manifest_sha256=sha(backup_path / 'manifest.json'), postgres_dump_sha256=sha(backup_path / 'postgres.dump'), restored_database_name=name)
        check(report, 'strict_mapping_covers_actual_main_identity', mapping['repositories'][0]['main_sha'] == history_report['final_integrated_sha'] and manifest['unsettled_attempts'] == 0)
        save(output / 'restore-relocation.json', mapping)
        save(output / 'backup-manifest.json', manifest)
        report.update(phase='PREPARED_AWAITING_OFFLINE_BINARY', passed=sum(c['status']=='PASS' for c in report['checks']))
    except Exception as error:
        report['status'] = 'FAIL'; report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        stop(source, source_log, report, 'source')
        save(output / 'prepare-report.json', report)
        print(json.dumps({key: report.get(key) for key in ('status', 'phase', 'passed', 'private_root', 'errors')}), flush=True)
    return 0 if not report['errors'] else 1


def finish(args):
    output = args.prepared_report.resolve().parent
    if (output / 'offline-relocation.stdout.txt').exists():
        raise RuntimeError('Offline operation was already attempted; use --resume-from the retained failure report instead of replaying committed commands')
    report = json.loads(args.prepared_report.read_text())
    if report['phase'] != 'PREPARED_AWAITING_OFFLINE_BINARY' or report['errors']:
        raise RuntimeError('Prepared actual restore is not ready')
    private = Path(report['private_root'])
    source_env = json.loads((private / 'source-env.json').read_text())
    env = json.loads((private / 'restored-env.json').read_text())
    state = json.loads((private / 'private-auth-state.json').read_text())
    server = binary(args.build_receipt, report, 'offline_and_restart_build')
    process = log = None
    hidden = None
    source_root = Path(source_env['FORGEFLOW_DATA_ROOT'])
    try:
        result = operation(output, 'offline-relocation', [server, '--restore-relocation-manifest', report['relocation_manifest'], '--data-root', env['FORGEFLOW_DATA_ROOT']], {'PATH': '/usr/bin:/bin', 'DATABASE_URL': env['DATABASE_URL'], 'RUST_LOG': 'warn'})
        check(report, 'actual_offline_relocation', result['status'] == 'RELOCATED_REVIEW_REQUIRED' and not result['replayed'], result)
        process, log, base = start(report, output, server, env, 'restored-first')
        source_root = source_root.resolve(strict=True)
        if not source_root.is_relative_to(Path(report['source_private_root']).resolve(strict=True)):
            raise RuntimeError('Original state path is outside exact fixture scope; no rename performed')
        hidden = source_root.with_name(source_root.name + '.restore-hidden-' + uuid.uuid4().hex[:8])
        source_root.rename(hidden)
        check(report, 'original_data_and_repository_paths_unavailable', not source_root.exists() and not Path(report['source_project_root']).exists())
        for name, token in [('old_owner_service', source_env['FORGEFLOW_OWNER_TOKEN']), ('old_worker_service', source_env['FORGEFLOW_WORKER_TOKEN']), ('old_owner_session', state['source_session'])]:
            status = request(report, output, base, 'GET', '/api/v1/me', token)[0]
            check(report, name + '_rejected', status == 401)
        status = request(report, output, base, 'POST', '/api/v1/session', body={'password': source_env['FORGEFLOW_OWNER_PASSWORD']}, sensitive=True)[0]
        check(report, 'old_owner_password_rejected_after_explicit_reset', status == 401)
        status, login = request(report, output, base, 'POST', '/api/v1/session', body={'password': env['FORGEFLOW_OWNER_PASSWORD']}, sensitive=True)
        check(report, 'rotated_owner_password_real_login', status == 200)
        state['restored_session'] = login['data']['token']
        session_file = private / 'restored-session.json'; save(session_file, state, True)
        project = request(report, output, base, 'GET', '/api/v1/projects/' + report['project_id'], state['restored_session'])[1]['data']
        mappings = json.loads(Path(report['relocation_manifest']).read_text())['repositories']
        check(report, 'current_authority_uses_new_root_and_stays_paused', project['root_path'] == mappings[0]['new_path'] and project['paused'])
        check(report, 'all_git_refs_and_main_match_backup_after_old_root_removal', git(project['root_path'], 'show-ref') == json.loads((output/'backup-manifest.json').read_text())['repositories'][0]['git_refs'])
        baseline = json.loads((output/'original-history.json').read_text())
        check(report, 'immutable_attempt_flow_evidence_contract_history_preserved', historical(env['DATABASE_URL']) == baseline)
        status, artifacts = request(report, output, base, 'GET', '/api/v1/projects/' + report['project_id'] + '/documents/artifacts?limit=500', state['restored_session'])
        check(report, 'restored_artifact_catalog_real_history', status == 200 and len(artifacts['data']) > 0)
        for artifact in authoritative_artifacts(env['DATABASE_URL'], report['project_id']):
            artifact_id = artifact['document_id']
            status, content = request(report, output, base, 'GET', '/api/v1/artifacts/' + urllib.parse.quote(artifact_id, safe='') + '/content?project_id=' + report['project_id'], state['restored_session'])
            # Request helper retains raw bytes; hash the response file rather than reserialize JSON artifacts.
            response_path = output / report['http'][-1]['response_file']
            check(report, 'artifact_' + artifact_id + '_hash_after_old_root_removed', status == 200 and sha(response_path) == artifact['data']['sha256'])
        for attempt in baseline['attempts']:
            status, content = request(report, output, base, 'GET', '/api/v1/attempts/' + attempt['attempt_id'] + '/logs?limit_bytes=1048576', state['restored_session'])
            original_bytes = (hidden / 'attempts' / attempt['attempt_id'] / 'stdout.ndjson').read_bytes()
            check(report, 'historical_log_' + attempt['attempt_id'] + '_readable', status == 200 and content['data']['text'].encode() == original_bytes)
        old_workers = json.loads(database(env['DATABASE_URL'], "SELECT json_build_object('old_workers_epoch',(SELECT count(*) FROM workers WHERE heartbeat_at='epoch'::timestamptz),'workers',(SELECT count(*) FROM workers),'unrevoked_leases',(SELECT count(*) FROM leases WHERE revoked_at IS NULL))"))
        check(report, 'restore_mode_revokes_legacy_worker_and_lease_authority', old_workers['workers'] > 0 and old_workers['old_workers_epoch'] == old_workers['workers'] and old_workers['unrevoked_leases'] == 0, old_workers)
        registration = {'project_id': report['project_id'], 'executor_profile_ids': [], 'worker_id': env['FORGEFLOW_WORKER_ID'], 'boot_id': str(uuid.uuid4()), 'capabilities': []}
        status, registered = request(report, output, base, 'POST', '/api/v1/workers/register', env['FORGEFLOW_WORKER_TOKEN'], registration)
        check(report, 'new_worker_identity_registered_without_running_worker', status == 200 and registered['data']['registered'])
        stop(process, log, report, 'restored-first'); process = log = None
        restart_env = dict(env); restart_env.pop('FORGEFLOW_RESTORE_MODE')
        process, log, base = start(report, output, server, restart_env, 'restored-restart')
        check(report, 'rotated_owner_login_session_survives_restart_with_old_roots_missing', request(report, output, base, 'GET', '/api/v1/me', state['restored_session'])[0] == 200)
        check(report, 'history_survives_actual_restart_with_old_roots_missing', historical(env['DATABASE_URL']) == baseline)
        check(report, 'no_restored_task_or_model_rerun', int(database(env['DATABASE_URL'], 'SELECT count(*) FROM attempts')) == len(baseline['attempts']) and database(env['DATABASE_URL'], 'SELECT count(*) FROM native_model_requests') == '0')
        report.update(status='PASS', phase='RESTORE_HISTORY_AND_RELOCATION_COMPLETE', artifact_count=len(artifacts['data']), historical_attempts=len(baseline['attempts']), limitations=['No new task/external executor profile requalification performed', 'Measured local restore only; no power-loss or fleet/production qualification', 'Original root temporarily renamed during reads and actual restart, then restored for historical fixture preservation'])
    except Exception as error:
        report['status'] = 'FAIL'; report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        stop(process, log, report, 'restored-restart-or-failed')
        if hidden is not None and hidden.exists():
            hidden.rename(source_root)
            report['original_fixture_path_preserved_after_probe'] = source_root.exists()
        report.update(passed=sum(c['status']=='PASS' for c in report['checks']), assertions=len(report['checks']), failed=sum(c['status']=='FAIL' for c in report['checks']))
        save(output/'report.json', report)
        print(json.dumps({key:report.get(key) for key in ('status','phase','passed','assertions','failed','errors')}), flush=True)
    return 0 if report['status']=='PASS' else 1


def resume_finish(args):
    prior_path = args.resume_from.resolve()
    prior = json.loads(prior_path.read_text())
    passed_names = {case['name'] for case in prior['checks'] if case['status'] == 'PASS'}
    if prior['status'] != 'FAIL' or prior['errors'] != ["KeyError: 'artifact_id'"] or 'actual_offline_relocation' not in passed_names:
        raise RuntimeError('Continuation requires the exact retained artifact-id failure after a committed offline relocation')
    parent_output = prior_path.parent
    output = args.output.resolve() if args.output else parent_output / ('resume-artifacts-' + uuid.uuid4().hex[:8])
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema_version': 'forgeflow.restore-rehearsal-supplement.v1', 'at': datetime.now(timezone.utc).isoformat(),
              'status': 'INCONCLUSIVE', 'prior_report': str(prior_path), 'prior_report_sha256': sha(prior_path),
              'prior_passed_checks': len(passed_names), 'inherited_check_names': sorted(passed_names),
              'checks': [], 'errors': [], 'model_requests': 0, 'worker_processes_started': 0,
              'scope': 'Only remaining artifact/log reads, legacy authority read, new Worker metadata registration and restart with the old data root unavailable; no backup/restore/offline command/login/token checks replayed'}
    private = Path(prior['private_root'])
    env = json.loads((private / 'restored-env.json').read_text())
    env.pop('FORGEFLOW_RESTORE_MODE', None)  # Already applied on the first restored boot; no reconciliation replay.
    state = json.loads((private / 'restored-session.json').read_text())
    source_env = json.loads((private / 'source-env.json').read_text())
    process = log = hidden = None
    source_root = Path(source_env['FORGEFLOW_DATA_ROOT'])
    try:
        server = binary(args.build_receipt, report, 'supplement_build')
        process, log, base = start(report, output, server, env, 'resume-artifacts')
        source_root = source_root.resolve(strict=True)
        if not source_root.is_relative_to(Path(prior['source_private_root']).resolve(strict=True)):
            raise RuntimeError('Original state is outside the exact fixture scope; no rename performed')
        hidden = source_root.with_name(source_root.name + '.restore-hidden-' + uuid.uuid4().hex[:8])
        source_root.rename(hidden)
        if source_root.exists() or Path(prior['source_project_root']).exists():
            raise RuntimeError('Old roots remain accessible; remaining reads cannot prove independent storage')
        report['original_roots_unavailable_during_remaining_reads_and_restart'] = True
        artifacts = authoritative_artifacts(env['DATABASE_URL'], prior['project_id'])
        skipped = []
        for artifact in artifacts:
            artifact_id = artifact['document_id']
            name = 'artifact_' + artifact_id + '_hash_after_old_root_removed'
            if name in passed_names:
                skipped.append(artifact_id)
                continue
            status, _ = request(report, output, base, 'GET', '/api/v1/artifacts/' + urllib.parse.quote(artifact_id, safe='') + '/content?project_id=' + prior['project_id'], state['restored_session'])
            response_path = output / report['http'][-1]['response_file']
            check(report, name, status == 200 and sha(response_path) == artifact['data']['sha256'])
        report.update(artifact_catalog_count=len(artifacts), previously_passed_artifacts_not_repeated=skipped)
        baseline = json.loads((parent_output / 'original-history.json').read_text())
        for attempt in baseline['attempts']:
            name = 'historical_log_' + attempt['attempt_id'] + '_readable'
            if name in passed_names:
                continue
            status, content = request(report, output, base, 'GET', '/api/v1/attempts/' + attempt['attempt_id'] + '/logs?limit_bytes=1048576', state['restored_session'])
            original_bytes = (hidden / 'attempts' / attempt['attempt_id'] / 'stdout.ndjson').read_bytes()
            check(report, name, status == 200 and content['data']['text'].encode() == original_bytes)
        worker = env['FORGEFLOW_WORKER_ID'].replace("'", "''")
        old_workers = json.loads(database(env['DATABASE_URL'], "SELECT json_build_object('old_workers_epoch',(SELECT count(*) FROM workers WHERE worker_id<>'" + worker + "' AND heartbeat_at='epoch'::timestamptz),'workers',(SELECT count(*) FROM workers WHERE worker_id<>'" + worker + "'),'unrevoked_leases',(SELECT count(*) FROM leases WHERE revoked_at IS NULL))"))
        check(report, 'restore_mode_revokes_legacy_worker_and_lease_authority', old_workers['workers'] > 0 and old_workers['old_workers_epoch'] == old_workers['workers'] and old_workers['unrevoked_leases'] == 0, old_workers)
        existing_worker = database(env['DATABASE_URL'], "SELECT boot_id FROM workers WHERE worker_id='" + worker + "'")
        if not existing_worker:
            registration = {'project_id': prior['project_id'], 'executor_profile_ids': [], 'worker_id': env['FORGEFLOW_WORKER_ID'], 'boot_id': str(uuid.uuid4()), 'capabilities': []}
            status, registered = request(report, output, base, 'POST', '/api/v1/workers/register', env['FORGEFLOW_WORKER_TOKEN'], registration)
            check(report, 'new_worker_identity_registered_without_running_worker', status == 200 and registered['data']['registered'])
        else:
            report['new_worker_registration_command_not_replayed'] = True
        stop(process, log, report, 'resume-artifacts'); process = log = None
        process, log, base = start(report, output, server, env, 'resume-restart')
        check(report, 'rotated_owner_login_session_survives_restart_with_old_roots_missing', request(report, output, base, 'GET', '/api/v1/me', state['restored_session'])[0] == 200)
        check(report, 'history_survives_actual_restart_with_old_roots_missing', historical(env['DATABASE_URL']) == baseline)
        check(report, 'no_restored_task_or_model_rerun', int(database(env['DATABASE_URL'], 'SELECT count(*) FROM attempts')) == len(baseline['attempts']) and database(env['DATABASE_URL'], 'SELECT count(*) FROM native_model_requests') == '0')
        report.update(status='PASS', phase='REMAINING_RESTORE_HISTORY_CHECKS_COMPLETE', historical_attempts=len(baseline['attempts']),
                      limitations=['Prior failed report retained; earlier facts inherited by its exact hash', 'No new task or external executor qualification', 'Local recovery scope only; no power-loss or production claim'])
    except Exception as error:
        report['status'] = 'FAIL'; report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        stop(process, log, report, 'resume-restart-or-failed')
        if hidden is not None and hidden.exists():
            hidden.rename(source_root)
            report['original_fixture_path_preserved_after_probe'] = source_root.exists()
        report.update(passed=sum(case['status']=='PASS' for case in report['checks']), assertions=len(report['checks']), failed=sum(case['status']=='FAIL' for case in report['checks']))
        save(output / 'report.json', report)
        print(json.dumps({'status': report['status'], 'report': str(output / 'report.json'), 'prior_passed': len(passed_names), 'supplement_passed': report['passed'], 'errors': report['errors']}), flush=True)
    return 0 if report['status']=='PASS' else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='phase',required=True)
    first=commands.add_parser('prepare');first.add_argument('--source-report',type=Path,required=True);first.add_argument('--build-receipt',type=Path,required=True);first.add_argument('--output',type=Path,required=True);first.add_argument('--source-env',type=Path)
    second=commands.add_parser('finish');source=second.add_mutually_exclusive_group(required=True);source.add_argument('--prepared-report',type=Path);source.add_argument('--resume-from',type=Path);second.add_argument('--build-receipt',type=Path,required=True);second.add_argument('--output',type=Path)
    args=parser.parse_args()
    return prepare(args) if args.phase=='prepare' else (resume_finish(args) if args.resume_from else finish(args))


if __name__=='__main__':
    raise SystemExit(main())

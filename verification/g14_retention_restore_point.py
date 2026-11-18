#!/usr/bin/env python3
"""Real automatic-retention and restored-future-cursor points; prepare then Root GO.

All events come from legitimate Owner commands. Database observations are SELECT
only. Actual existing backup/restore and offline relocation operate exclusively
on two fresh private databases. No Worker, model, simulated expiry or event DELETE.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'verification'))
sys.path.insert(0, str(ROOT / 'benchmarks'))
from cross_project_business_chain import Client, git, private_bytes, save, wait
from guarded_api_chain import create_database, database_command, secure_save
from metrics import process_fingerprint

SOURCE = 'f9d2b78bf0aa015e49577904a4ce0a6853474a77fe118bf2541279d0784d23fd'
RECEIPT = 'b4ae5d2332d7d8de3ba4a6d38a730e90c8bd922bbdb5c38c64ff49194ca2b9a3'
PG_BIN = Path('/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/postgresql/16/bin')
PG_LIB = '/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/x86_64-linux-gnu'


def load(p):
    return json.loads(Path(p).read_text())


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main_identity():
    r = subprocess.run(['systemctl', '--user', 'show', 'forgeflow-control.service',
        '--property=MainPID', '--property=ActiveState'], capture_output=True, text=True,
        check=True, timeout=15)
    return dict(line.split('=', 1) for line in r.stdout.splitlines())


def prepare(args):
    r = load(args.build_receipt)
    assert sha(args.build_receipt) == RECEIPT and r['source_identity'] == SOURCE
    assert r['consistent_copy'] and r['source_unchanged_after_build']
    assert all(c['exit_code'] == 0 for c in r['commands'])
    b = r['binaries']['forgeflow-server']
    assert sha(b['path']) == b['sha256']
    assert args.port != args.restored_port and all(p not in (8787, 8788, 8793)
        and 1024 <= p <= 65535 for p in (args.port, args.restored_port))
    helpers = ['verification/g14_retention_restore_point.py', 'verification/cross_project_business_chain.py',
        'verification/guarded_api_chain.py', 'ops/backup.py', 'ops/restore.py', 'benchmarks/metrics.py']
    components = ['crates/store/src/event_retention.rs', 'migrations/0011_event_retention.sql',
        'crates/api/src/lib.rs', 'crates/server/src/main.rs', 'crates/server/src/restore.rs', 'crates/store/src/catalog.rs']
    frozen = Path(r['snapshot_root'])
    assert all(sha(frozen / p) == r['source_files'][p] for p in components)
    return {'schema_version': 'forgeflow.g14-retention-restore-source-plan.v1',
        'status': 'SOURCE_READY_NO_ACTORS', 'source_identity': SOURCE,
        'build_receipt': {'path': str(args.build_receipt.resolve()), 'sha256': RECEIPT},
        'server': b, 'driver_helper_pins': {p: sha(ROOT / p) for p in helpers},
        'postgres_tool_pins': {n: sha(PG_BIN / n) for n in ('pg_dump', 'pg_restore', 'psql')},
        'frozen_source_pins': {p: {'path': str(frozen / p), 'sha256': sha(frozen / p)} for p in components},
        'source_port': args.port, 'restored_port': args.restored_port, 'main_pid': args.main_pid,
        'actors': {'source_API': 1, 'restored_API': 1, 'maximum_simultaneous_APIs': 1,
            'offline_relocation_process': 1, 'Workers': 0, 'models': 0, 'verifiers': 0, 'Cargo': 0},
        'private_policy': {'retention_seconds': 1, 'archive_interval_seconds': 1},
        'source_commands': {'initial_requirements': 12, 'barrier_shift': 1,
            'retention_reconnect_event': 1, 'post_backup_requirements': 32,
            'restored_reconnect_event': 1},
        'requirements': ['Actual automatic prefix archival preserves every original event column except archived_at and retains latest hot event',
            'Expired actual cursor gets409 SNAPSHOT_REQUIRED, snapshot+latestcursor then genuine SSE event',
            'Actual own pg_dump/restore/offline relocation, prior source cursor strictly exceeds measured restored authority HEAD after all restore audit events',
            'Future cursor gets409 then actual snapshot/latestcursor/genuine SSE event, original backup history preserved'],
        'execution_requires_exact_Root_GO_plan_sha256': True,
        'actor_alarm_seconds': 420, 'cleanup': 'Export final original history and receipts, close owned actors, drop only both freshly created private databases after zero unsettled authority',
        'not_proven': ['Full browser suite', 'Long-term production retention sizing', 'Power loss', 'Fullfaultmatrix', 'Native DSH concurrency']}


def run(args, plan):
    plan_path = args.output / 'source-ready-plan.json'
    assert sha(plan_path) == args.expected_plan_sha256 and load(plan_path) == plan
    assert not (args.output / 'report.json').exists(), 'Refuse actor replay'
    original_main = main_identity()
    assert original_main == {'MainPID': str(args.main_pid), 'ActiveState': 'active'}
    for port in (args.port, args.restored_port):
        with socket.socket() as sk:
            assert sk.connect_ex(('127.0.0.1', port)) != 0
    private = Path(tempfile.mkdtemp(prefix='forgeflow-g14-retention-', dir='/home/chenyoujian/.cache'))
    private.chmod(0o700)
    (private / 'state').mkdir(mode=0o700)
    (private / 'diagnostics').mkdir(mode=0o700)
    maintenance = load(args.private_env)
    name = 'forgeflow_g14_source_' + uuid.uuid4().hex[:16]
    env = {'DATABASE_URL': create_database(maintenance, name, private),
        'FORGEFLOW_BIND': f'127.0.0.1:{args.port}', 'FORGEFLOW_DATA_ROOT': str(private / 'state'),
        'FORGEFLOW_OWNER_TOKEN': secrets.token_hex(32), 'FORGEFLOW_WORKER_TOKEN': secrets.token_hex(32),
        'FORGEFLOW_EVENT_RETENTION_SECONDS': '1', 'FORGEFLOW_EVENT_ARCHIVE_INTERVAL_SECONDS': '1', 'RUST_LOG': 'info'}
    secure_save(private / 'source-env.json', env)
    source = Client(f'http://127.0.0.1:{args.port}', env['FORGEFLOW_OWNER_TOKEN'], args.output / 'source-http', private / 'diagnostics/source')
    report = {'schema_version': 'forgeflow.g14-actual-retention-and-restore.v1', 'status': 'RUNNING',
        'source_identity': SOURCE, 'source_plan_sha256': sha(plan_path), 'private_root': str(private),
        'checks': [], 'errors': [], 'actors': [], 'models': 0, 'Workers': 0, 'verifiers': 0,
        'databases': [name], 'not_proven': plan['not_proven']}
    actors = []
    owned_dbs = [(name, env['DATABASE_URL'])]
    project = None
    restored_env = None
    observation_counts = {}

    def check(label, condition, facts=None):
        report['checks'].append({'name': label, 'status': 'PASS' if condition else 'FAIL', 'facts': facts})
        save(args.output / 'report.json', report)
        if not condition:
            raise RuntimeError('Actual point failed: ' + label)

    def query(url, sql):
        r = database_command(url, sql)
        if r.returncode:
            raise RuntimeError('Private SELECT or owned-database lifecycle command failed; original private state retained')
        return r.stdout

    def observe(url, label):
        raw = query(url, f"SELECT jsonb_build_object('head',(SELECT event_seq FROM projects WHERE project_id='{project}'),'events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY project_seq) FROM events e WHERE project_id='{project}'),'[]'::jsonb),'attempts',(SELECT count(*) FROM attempts),'workers',(SELECT count(*) FROM workers),'held',(SELECT count(*) FROM resource_allocations WHERE state<>'RELEASED'),'leases',(SELECT count(*) FROM leases WHERE revoked_at IS NULL),'models',(SELECT count(*) FROM model_request_permit));")
        observation_counts[label] = observation_counts.get(label, 0) + 1
        unique_label = label + f'-{observation_counts[label]:06d}'
        private_bytes(private / (unique_label + '.original-authority.bin'), raw)
        value = json.loads(raw)
        save(args.output / (unique_label + '.authority.json'), value)
        return value

    def start(label, runtime, client):
        log = os.fdopen(os.open(private / (label + '.log'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
        p = subprocess.Popen([plan['server']['path']], env={'PATH': '/usr/bin:/bin', **runtime}, stdout=log, stderr=subprocess.STDOUT)
        actor = {'label': label, 'process': p, 'log': log}
        actors.append(actor)
        def ready():
            assert p.poll() is None, label + ' API exited before readiness'
            try:
                return client.request('GET', '/me')[0] == 200
            except OSError:
                return False
        wait(ready, label + ' API readiness', 30)
        report['actors'].append({'label': label, 'identity': process_fingerprint(p.pid), 'server_sha256': plan['server']['sha256']})
        return actor

    def stop(actor):
        p = actor['process']
        if p.poll() is None:
            p.terminate()
            p.wait(timeout=35)
        if not actor['log'].closed:
            actor['log'].close()
        return {'label': actor['label'], 'pid': p.pid, 'exit_code': p.returncode, 'confirmed': p.poll() is not None}

    def requirement(client, identity):
        return client.api('POST', f'/projects/{project}/requirements', {'project_id': project,
            'requirement_id': identity, 'title': 'Actual retained event ' + identity,
            'source_anchor': 'g14-retention#' + identity, 'outcome': 'Genuine Owner-generated event continuity',
            'scope': 'Controlled private cursor point, no Worker/model execution',
            'acceptance': ['Authoritative requirement and original event remain traceable'],
            'priority': 1, 'weight': 1, 'deferred_reason': None, 'revision': 0})

    def reconnect(client, prefix):
        snap = client.api('GET', f'/projects/{project}/snapshot')
        cursor = client.api('GET', f'/projects/{project}/event-cursor')['cursor']
        result = {}
        launched = threading.Event()
        def read():
            try:
                request = urllib.request.Request(client.base_url + f'/api/v1/projects/{project}/events?after={cursor}',
                    headers={'Authorization': 'Bearer ' + client.token, 'Accept': 'text/event-stream'})
                launched.set()
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=12) as response:
                    lines = []
                    while True:
                        line = response.readline()
                        if not line:
                            raise RuntimeError('Event stream closed before a real event')
                        if line in (b'\n', b'\r\n'):
                            frame = b''.join(lines)
                            if b'data:' in frame:
                                result.update(status=response.status, raw=frame)
                                return
                            lines = []
                        else:
                            lines.append(line)
            except Exception as error:
                result['error'] = type(error).__name__ + ': ' + str(error)
        t = threading.Thread(target=read, daemon=True)
        t.start()
        assert launched.wait(3)
        requirement(client, prefix + '-new')
        t.join(15)
        assert not t.is_alive() and 'error' not in result, 'Real SSE reconnect failed'
        raw = result['raw']
        (args.output / (prefix + '.actual-sse.bin')).write_bytes(raw)
        fields = [line[5:].strip() for line in raw.splitlines() if line.startswith(b'data:')]
        event = json.loads(b'\n'.join(fields))
        check(prefix + '_snapshot_latest_cursor_actual_event_reconnect', result['status'] == 200
            and event['project_id'] == project and event['project_seq'] == cursor + 1
            and event['kind'] == 'requirement.created' and event['object_id'] == prefix + '-new',
            {'snapshot_revision': snap['revision'], 'reconnected_after': cursor, 'actual_event': event,
                'raw_sse_sha256': sha(args.output / (prefix + '.actual-sse.bin'))})

    def operation(label, argv, runtime):
        completed = subprocess.run(argv, cwd=ROOT, env=runtime, capture_output=True, timeout=180)
        private_bytes(private / (label + '.stdout.bin'), completed.stdout)
        private_bytes(private / (label + '.stderr.bin'), completed.stderr)
        save(args.output / (label + '.operation.json'), {'argv': argv, 'exit_code': completed.returncode,
            'stdout_original_sha256': sha(private / (label + '.stdout.bin')),
            'stderr_original_sha256': sha(private / (label + '.stderr.bin'))})
        if completed.returncode:
            raise RuntimeError('Actual ' + label + ' failed; private original output preserved')
        value = json.loads(completed.stdout)
        save(args.output / (label + '.receipt.json'), value)
        return value

    def interrupt(signum, frame):
        raise RuntimeError('Finite private actor phase interrupted')

    old_alarm = signal.signal(signal.SIGALRM, interrupt)
    old_term = signal.signal(signal.SIGTERM, interrupt)
    signal.alarm(plan['actor_alarm_seconds'])
    try:
        original_api = start('source-api', env, source)
        seed = private / 'seed'
        seed.mkdir()
        git(seed, 'init', '--initial-branch=main')
        (seed / 'README.txt').write_text('Actual private retention and restored cursor point, zero execution agents.\n')
        git(seed, 'add', 'README.txt')
        git(seed, '-c', 'user.name=G14 fixture', '-c', 'user.email=fixture@localhost', 'commit', '-m', 'Private event baseline')
        repo = private / 'source.git'
        subprocess.run(['git', 'clone', '--bare', '--no-hardlinks', str(seed), str(repo)], capture_output=True, check=True, timeout=30)
        project = 'g14-retention-' + uuid.uuid4().hex[:16]
        created = source.api('POST', '/projects', {'project_id': project, 'name': 'Actual retention and restore cursor',
            'root_path': str(repo), 'authority_mode': 'MANAGED', 'data_origin': 'NATIVE',
            'goal': 'Actual authoritative event retention and restored future-cursor recovery',
            'technology_stack': ['controlled event metadata'], 'timezone': 'Asia/Shanghai', 'paused': True, 'archived': False, 'revision': 0})
        report['project_id'] = project
        repo = Path(created['root_path'])
        for i in range(12):
            requirement(source, 'initial-' + str(i))
        before = observe(env['DATABASE_URL'], 'before-automatic-archive')
        original_fields = {e['event_id']: {k: v for k, v in e.items() if k != 'archived_at'} for e in before['events']}
        requirement(source, 'archive-barrier-shift')
        def archived():
            row = observe(env['DATABASE_URL'], 'automatic-archive-latest-observation')
            lookup = {e['event_id']: e for e in row['events']}
            return row if all(lookup[k]['archived_at'] is not None for k in original_fields) else None
        after = wait(archived, 'real one-second automatic prefix archival', 12)
        lookup = {e['event_id']: {k: v for k, v in e.items() if k != 'archived_at'} for e in after['events']}
        check('real_archival_preserves_all_original_history_fields', len(before['events']) >= 13
            and all(lookup[k] == v for k, v in original_fields.items())
            and any(e['archived_at'] is None for e in before['events'])
            and after['events'][-1]['archived_at'] is None,
            {'original_event_count': len(before['events']), 'after_event_count': len(after['events']),
                'archived_event_count': sum(e['archived_at'] is not None for e in after['events']),
                'latest_hot_seq': after['events'][-1]['project_seq']})
        status, error = source.request('GET', f'/projects/{project}/events?after=0')
        check('actual_retained_window_expiry_returns_409', status == 409 and error['code'] == 'SNAPSHOT_REQUIRED', error)
        reconnect(source, 'retention-reconnect')
        backup = private / 'backup'
        ops_env = {'PATH': str(PG_BIN) + ':/usr/bin:/bin', 'LD_LIBRARY_PATH': PG_LIB,
            'PYTHONDONTWRITEBYTECODE': '1', **env, 'FORGEFLOW_API_URL': source.base_url}
        b = operation('actual-backup', ['/usr/bin/python3', '-B', str(ROOT / 'ops/backup.py'), '--destination', str(backup),
            '--data-root', env['FORGEFLOW_DATA_ROOT'], '--repository', str(repo)], ops_env)
        backup_state = observe(env['DATABASE_URL'], 'actual-backup-watermark')
        manifest = load(backup / 'manifest.json')
        save(args.output / 'backup-manifest.json', manifest)
        backup_original_fields = {e['event_id']: {k: v for k, v in e.items() if k != 'archived_at'}
            for e in backup_state['events']}
        check('actual_quiescent_backup_with_original_event_watermark', b['dispatch_paused']
            and (backup / 'postgres.dump').stat().st_size > 0
            and manifest['project_event_watermarks'][project] == backup_state['head'],
            {'backup_head': backup_state['head'], 'postgres_dump_sha256': sha(backup / 'postgres.dump')})
        for i in range(32):
            requirement(source, 'post-backup-' + str(i))
        future = source.api('GET', f'/projects/{project}/event-cursor')['cursor']
        source_final = observe(env['DATABASE_URL'], 'original-source-final-history')
        stop(original_api)
        restore_name = 'forgeflow_g14_restore_' + uuid.uuid4().hex[:16]
        restore_creation = private / 'restore-database-creation'
        restore_creation.mkdir(mode=0o700)
        new_url = create_database(maintenance, restore_name, restore_creation)
        owned_dbs.append((restore_name, new_url))
        report['databases'].append(restore_name)
        destination = private / 'restored'
        restored_env = {**env, 'DATABASE_URL': new_url, 'FORGEFLOW_BIND': f'127.0.0.1:{args.restored_port}',
            'FORGEFLOW_DATA_ROOT': str(destination / 'data'), 'FORGEFLOW_OWNER_TOKEN': secrets.token_hex(32),
            'FORGEFLOW_WORKER_TOKEN': secrets.token_hex(32), 'FORGEFLOW_RESTORE_MODE': '1'}
        secure_save(private / 'restored-env.json', restored_env)
        operation('actual-restore', ['/usr/bin/python3', '-B', str(ROOT / 'ops/restore.py'), '--backup', str(backup),
            '--destination', str(destination), '--database-env', str(private / 'restored-env.json')], ops_env)
        mapping = destination / 'restore-relocation.json'
        offline = operation('actual-offline-relocation', [plan['server']['path'], '--restore-relocation-manifest', str(mapping),
            '--data-root', restored_env['FORGEFLOW_DATA_ROOT']], {'PATH': '/usr/bin:/bin', 'DATABASE_URL': new_url, 'RUST_LOG': 'warn'})
        check('actual_restore_and_reviewed_offline_relocation', offline['status'] == 'RELOCATED_REVIEW_REQUIRED', offline)
        restored = Client(f'http://127.0.0.1:{args.restored_port}', restored_env['FORGEFLOW_OWNER_TOKEN'],
            args.output / 'restored-http', private / 'diagnostics/restored')
        start('restored-api', restored_env, restored)
        restored_state = observe(new_url, 'restored-head-after-all-audits')
        restored_original = {e['event_id']: {k: v for k, v in e.items() if k != 'archived_at'} for e in restored_state['events']}
        check('restore_preserves_backup_original_events_and_really_has_older_head', future > restored_state['head']
            and source_final['head'] == future and restored_state['head'] >= backup_state['head']
            and all(restored_original[k] == v for k, v in backup_original_fields.items()),
            {'actual_pre_restore_live_cursor': future, 'actual_restored_head_including_locator_audits': restored_state['head'],
                'actual_backup_head': backup_state['head'], 'actual_post_backup_events': future - backup_state['head']})
        status, error = restored.request('GET', f'/projects/{project}/events?after={future}')
        check('actual_restore_future_cursor_returns_409', status == 409 and error['code'] == 'SNAPSHOT_REQUIRED', error)
        reconnect(restored, 'restore-reconnect')
        final = observe(new_url, 'restored-final-history')
        check('both_real_points_zero_execution_authority', all(v[k] == 0 for v in (source_final, final)
            for k in ('workers', 'attempts', 'held', 'leases', 'models')))
    except Exception as error:
        report['errors'].append({'type': type(error).__name__, 'message': str(error)})
    finally:
        signal.alarm(0)
        report['process_shutdown'] = []
        for actor in actors:
            try:
                report['process_shutdown'].append(stop(actor))
            except Exception as error:
                report['errors'].append({'cleanup': actor['label'], 'type': type(error).__name__})
        closed = all(a['process'].poll() is not None for a in actors)
        cleanup = []
        if closed:
            for dbname, url in owned_dbs:
                try:
                    rows = json.loads(query(url, "SELECT jsonb_build_object('attempts',(SELECT count(*) FROM attempts),'held',(SELECT count(*) FROM resource_allocations WHERE state<>'RELEASED'),'leases',(SELECT count(*) FROM leases WHERE revoked_at IS NULL),'models',(SELECT count(*) FROM model_request_permit));"))
                    assert all(v == 0 for v in rows.values())
                    original = query(url, "SELECT jsonb_build_object('projects',(SELECT jsonb_agg(to_jsonb(t)) FROM projects t),'events',(SELECT jsonb_agg(to_jsonb(t) ORDER BY project_id,project_seq) FROM events t),'requirements',(SELECT jsonb_agg(to_jsonb(t)) FROM requirements t),'outbox',(SELECT jsonb_agg(to_jsonb(t)) FROM outbox t));")
                    private_bytes(private / (dbname + '.final-original-history.bin'), original)
                    save(args.output / (dbname + '.final-public-history.json'), json.loads(original))
                    query(maintenance['DATABASE_URL'], 'DROP DATABASE "' + dbname + '";')
                    exists = int(query(maintenance['DATABASE_URL'], "SELECT count(*) FROM pg_database WHERE datname='" + dbname + "';").strip())
                    assert exists == 0
                    cleanup.append({'database': dbname, 'status': 'EXPORTED_AND_DROPPED',
                        'original_export_path': str(private / (dbname + '.final-original-history.bin')),
                        'original_export_sha256': sha(private / (dbname + '.final-original-history.bin')), 'zero_unsettled': rows})
                except Exception as error:
                    cleanup.append({'database': dbname, 'status': 'RETAINED', 'error_type': type(error).__name__})
                    report['errors'].append({'cleanup': dbname, 'type': type(error).__name__})
        report['main_after'] = main_identity()
        ports_closed = True
        for port in (args.port, args.restored_port):
            with socket.socket() as sk:
                ports_closed = ports_closed and sk.connect_ex(('127.0.0.1', port)) != 0
        report['checks'].append({'name': 'owned_actors_closed_main_unchanged_private_databases_exported', 'status': 'PASS'
            if closed and ports_closed and report['main_after'] == original_main
            and len(cleanup) == len(owned_dbs) and all(d['status'] == 'EXPORTED_AND_DROPPED' for d in cleanup) else 'FAIL'})
        save(args.output / 'cleanup.json', {'scope': 'Only two own freshly created databases, original main/history untouched',
            'databases': cleanup, 'process_shutdown': report['process_shutdown'], 'ports_closed': ports_closed,
            'main_after': report['main_after'], 'original_backup_files_retained_private': str(private / 'backup')})
        report['status'] = ('PASS_ACTUAL_RETENTION_AND_RESTORE_CURSOR' if not report['errors']
            and all(c['status'] == 'PASS' for c in report['checks']) else 'FAIL')
        report['raw_manifest'] = [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p), 'bytes': p.stat().st_size}
            for p in args.output.rglob('*') if p.is_file() and p.name != 'report.json']
        save(args.output / 'report.json', report)
        signal.signal(signal.SIGALRM, old_alarm)
        signal.signal(signal.SIGTERM, old_term)
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'report': str(args.output / 'report.json')}))
    return 0 if report['status'] == 'PASS_ACTUAL_RETENTION_AND_RESTORE_CURSOR' else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build-receipt', type=Path, required=True)
    p.add_argument('--private-env', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--main-pid', type=int, required=True)
    p.add_argument('--port', type=int, default=8897)
    p.add_argument('--restored-port', type=int, default=8898)
    p.add_argument('--execute-authorized', action='store_true')
    p.add_argument('--expected-plan-sha256')
    args = p.parse_args()
    args.output = args.output.resolve()
    assert args.output.is_relative_to((ROOT / 'evidence/goal-gap-points-r3/g14/retention-restore-r1').resolve())
    plan = prepare(args)
    if args.execute_authorized:
        return run(args, plan)
    args.output.mkdir(parents=True, exist_ok=True)
    assert not (args.output / 'source-ready-plan.json').exists()
    save(args.output / 'source-ready-plan.json', plan)
    print(json.dumps({'status': plan['status'], 'plan': str(args.output / 'source-ready-plan.json'), 'plan_sha256': sha(args.output / 'source-ready-plan.json')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""One genuine pre-rename launch receipt crash; retained quarantine is the oracle.

No Rust change, fabricated callback, receipt deletion, ledger repair or model.
Only the initial private Worker receives the preload. Recovery uses exact config.
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
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'verification'))
sys.path.insert(0, str(ROOT / 'verification/fixtures'))
from cross_project_business_chain import Client, git, paused, policy, provision, save, wait
from guarded_api_chain import create_database, database_command, secure_save
from metrics import process_fingerprint

SOURCE = '1938d068831a2e4f734b9ece0c4618e4978a1fffd66d34bb8660259dfaae8da3'
BUILD = ROOT / 'evidence/builds/release-retry-core-r1.json'
OUT = ROOT / 'evidence/goal-gap-points-r5/g16/launch-receipt-window-r1'
PRIVATE_ENV = Path('/home/chenyoujian/.local/state/forgeflow/control/runtime-env.json')

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def load(p):
    return json.loads(Path(p).read_text())

def main_identity():
    p = subprocess.run(['systemctl', '--user', 'show', 'forgeflow-control.service', '--property=MainPID', '--property=ActiveState'], check=True, capture_output=True, text=True, timeout=15)
    return dict(line.split('=', 1) for line in p.stdout.splitlines())

def same(a, b):
    return bool(a and b and all(a[k] == b[k] for k in ('pid', 'start_ticks', 'cmdline')))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--main-pid', type=int, required=True)
    parser.add_argument('--port', type=int, default=8902)
    parser.add_argument('--execute-authorized', action='store_true')
    args = parser.parse_args()
    assert args.execute_authorized, 'Root authorization required'
    assert args.port not in (8787, 8788)
    OUT.mkdir(parents=True, exist_ok=True)
    assert not (OUT / 'report.json').exists(), 'Never rerun an existing actual window'
    build = load(BUILD)
    assert build['source_identity'] == SOURCE and build['consistent_copy'] and build['source_unchanged_after_build']
    assert all(c['exit_code'] == 0 for c in build['commands'])
    assert all(sha(v['path']) == v['sha256'] for v in build['binaries'].values())
    before_main = main_identity()
    assert before_main == {'ActiveState': 'active', 'MainPID': str(args.main_pid)}
    with socket.socket() as sk:
        assert sk.connect_ex(('127.0.0.1', args.port)) != 0
    private = Path(tempfile.mkdtemp(prefix='forgeflow-g16-receipt-window-', dir='/home/chenyoujian/.cache'))
    private.chmod(0o700)
    (private / 'state').mkdir(mode=0o700)
    diagnostics = private / 'diagnostics'
    diagnostics.mkdir(mode=0o700)
    library = private / 'launch-receipt-fault.so'
    compiler = subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', str(ROOT / 'verification/fixtures/launch_receipt_rename_fault.c'), '-ldl', '-o', str(library)], capture_output=True, text=True, timeout=30)
    assert compiler.returncode == 0, compiler.stderr
    library.chmod(0o500)
    plan = {'schema_version': 'forgeflow.launch-receipt-window-plan.v1', 'source_identity': SOURCE,
        'build_receipt_sha256': sha(BUILD), 'binaries': build['binaries'],
        'pins': {p: sha(ROOT / p) for p in ['verification/g16_launch_receipt_window_point.py', 'verification/fixtures/launch_receipt_rename_fault.c', 'verification/cross_project_business_chain.py', 'verification/guarded_api_chain.py']},
        'preload_library_sha256': sha(library), 'main_before': before_main, 'port': args.port,
        'actors': {'private_API': 1, 'initial_Worker': 1, 'replacement_Worker': 1, 'controlled_authors': 1, 'models': 0, 'DSH': 0, 'Rust_builds': 0},
        'actor_deadline_seconds': 240, 'closure_seconds_per_actor': 15,
        'oracle': 'Receipt absent through actual crash and restart, original authority retained, no relaunch or ref advance. No receipt repair.',
        'not_proven': ['Automatic receipt-missing capacity settlement', 'Power loss', 'Full G16 fault matrix', 'Native DSH or production concurrency']}
    save(OUT / 'source-ready-plan.json', plan)
    report = {'schema_version': 'forgeflow.launch-receipt-window-report.v1', 'status': 'RUNNING', 'source_identity': SOURCE,
        'source_plan_sha256': sha(OUT / 'source-ready-plan.json'), 'private_root': str(private), 'checks': [], 'errors': [],
        'models': 0, 'DSH': 0, 'process_shutdown': {}, 'not_proven': plan['not_proven']}
    save(OUT / 'report.json', report)
    api = api_log = fixture = client = author = attempt = journal = None
    original_popen = subprocess.Popen
    database = 'forgeflow_g16_receipt_' + uuid.uuid4().hex[:16]
    report['retained_private_database'] = database

    def check(name, condition, facts=None):
        report['checks'].append({'name': name, 'status': 'PASS' if condition else 'FAIL', 'facts': facts})
        save(OUT / 'report.json', report)
        if not condition:
            raise RuntimeError('Actual window assertion failed: ' + name)

    def observe(label):
        aid, pid = attempt['attempt_id'], fixture['project_id']
        sql = f"SELECT jsonb_build_object('attempt',(SELECT data FROM attempts WHERE attempt_id='{aid}'),'attempt_count',(SELECT count(*) FROM attempts WHERE project_id='{pid}'),'held',(SELECT count(*) FROM resource_allocations WHERE attempt_id='{aid}' AND state<>'RELEASED'),'allocated',(SELECT COALESCE(sum(amount),0) FROM resource_allocations WHERE attempt_id='{aid}' AND state<>'RELEASED'),'leases',(SELECT count(*) FROM leases WHERE attempt_id='{aid}' AND revoked_at IS NULL),'evidence',(SELECT count(*) FROM evidence_receipts WHERE attempt_id='{aid}'),'merges',(SELECT count(*) FROM merge_intents WHERE attempt_id='{aid}'),'models',(SELECT count(*) FROM model_request_permit));"
        p = database_command(client.database_url, sql)
        assert p.returncode == 0, 'Read-only SQL observation failed'
        value = json.loads(p.stdout)
        save(OUT / (label + '.authority.json'), value)
        return value

    def alarm(signum, frame):
        raise RuntimeError('Bounded actor deadline reached')

    old_alarm = signal.signal(signal.SIGALRM, alarm)
    old_term = signal.signal(signal.SIGTERM, alarm)
    signal.alarm(240)
    try:
        env = {'DATABASE_URL': create_database(load(PRIVATE_ENV), database, private), 'FORGEFLOW_BIND': f'127.0.0.1:{args.port}',
            'FORGEFLOW_DATA_ROOT': str(private / 'state'), 'FORGEFLOW_OWNER_TOKEN': secrets.token_hex(32), 'FORGEFLOW_WORKER_TOKEN': secrets.token_hex(32), 'RUST_LOG': 'info'}
        secure_save(private / 'runtime-env.json', env)
        client = Client(f'http://127.0.0.1:{args.port}', env['FORGEFLOW_OWNER_TOKEN'], OUT, diagnostics)
        client.database_url = env['DATABASE_URL']
        client.worker_token = env['FORGEFLOW_WORKER_TOKEN']
        client.sensitive.add(client.worker_token)
        api_log = os.fdopen(os.open(private / 'api.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
        api = original_popen([build['binaries']['forgeflow-server']['path']], env={'PATH': '/usr/bin:/bin', **env}, stdout=api_log, stderr=subprocess.STDOUT)
        def healthy():
            assert api.poll() is None, 'Owned API exited before readiness'
            try: return client.request('GET', '/me')[0] == 200
            except OSError: return False
        wait(healthy, 'Private API readiness', 30)
        policy(client, 'global')
        marker = private / 'receipt-rename-blocked.txt'
        def initial_worker_popen(cmd, *a, **kw):
            if cmd[0] == build['binaries']['forgeflow-worker']['path']:
                kw['env'] = {**kw['env'], 'LD_PRELOAD': str(library), 'FORGEFLOW_QA_RECEIPT_ROOT': str(private / 'state/attempts'), 'FORGEFLOW_QA_RECEIPT_MARKER': str(marker)}
            return original_popen(cmd, *a, **kw)
        subprocess.Popen = initial_worker_popen
        try:
            fixture = provision(client, private, build, 'receipt-window', 1, 1, 917)
        finally:
            subprocess.Popen = original_popen
        baseline = git(fixture['canonical'], 'rev-parse', 'refs/heads/main')
        paused(client, fixture['project_id'], False)
        wait(lambda: marker.is_file() and len(marker.read_text().splitlines()) == 3, 'Actual receipt pre-rename block', 45)
        pid_text, temporary, destination = marker.read_text().splitlines()
        first = fixture['process']
        assert int(pid_text) == first.pid
        temporary, destination = Path(temporary), Path(destination)
        journal = destination.parent
        assert journal.is_relative_to(private / 'state/attempts') and temporary.parent == journal
        launch = load(temporary)
        intent = load(journal / 'launch-intent.json')
        attempt = client.api('GET', f"/attempts/{intent['attempt_id']}?project_id={fixture['project_id']}")
        report.update(project_id=fixture['project_id'], attempt_id=attempt['attempt_id'], execution_id=intent['execution_id'])
        author = process_fingerprint(launch['process']['pid'])
        worker_identity = process_fingerprint(first.pid)
        original_pins = {name: sha(journal / name) for name in ['launch-intent.json', 'launch.lock', 'execution-id.json', 'envelope.json']}
        temporary_sha = sha(temporary)
        config = fixture['root'] / 'worker-config.json'
        config_sha = sha(config)
        check('true_pre_rename_window_has_live_author_and_original_durable_authority', not destination.exists() and same(author, process_fingerprint(launch['process']['pid']))
            and launch['intent'] == intent and author['start_ticks'] == launch['process']['start_ticks']
            and launch['execution_id'] == intent['execution_id'] and intent['generation'] == attempt['generation']
            and intent['attempt_id'] == attempt['attempt_id'] and intent['worker_id'] == fixture['worker_id']
            and Path(f"/proc/{first.pid}/status").read_text().split('State:')[1].lstrip().startswith('T'),
            {'author': author, 'worker': worker_identity, 'temporary_original_receipt_sha256': temporary_sha, 'intent_sha256': original_pins['launch-intent.json'], 'final_receipt_exists': destination.exists()})
        paused(client, fixture['project_id'], True)
        before = observe('before-crash')
        check('single_attempt_reservations_held_before_crash', before['attempt_count'] == 1 and before['held'] == 28 and before['models'] == 0, before)
        assert same(worker_identity, process_fingerprint(first.pid))
        os.kill(first.pid, signal.SIGKILL)
        first.wait(timeout=10)
        check('owned_Worker_SIGKILL_before_final_receipt', first.returncode == -9 and process_fingerprint(first.pid) is None and not destination.exists(), {'pid': first.pid, 'exit_code': first.returncode})
        restarted_log = os.fdopen(os.open(private / 'worker-restarted.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
        second = original_popen([build['binaries']['forgeflow-worker']['path'], '--config', str(config)], env={'PATH': '/usr/bin:/bin', 'RUST_LOG': 'info', 'FORGEFLOW_WORKER_TOKEN': client.worker_token}, stdout=restarted_log, stderr=subprocess.STDOUT)
        client.workers.append({'process': second, 'log': restarted_log})
        def quarantined():
            assert second.poll() is None, 'Owned replacement Worker exited'
            row = client.api('GET', f"/attempts/{attempt['attempt_id']}?project_id={fixture['project_id']}")
            return row if row['state'] == 'RECOVERY_REQUIRED' else None
        wait(quarantined, 'Actual same-config missing receipt quarantine', 35)
        final = observe('after-restart')
        check('same_config_restart_preserves_missing_receipt_and_quarantine', final['attempt']['state'] == 'RECOVERY_REQUIRED' and sha(config) == config_sha
            and not destination.exists() and sha(temporary) == temporary_sha and all(sha(journal / n) == h for n, h in original_pins.items()),
            {'state': final['attempt']['state'], 'config_sha256': config_sha, 'temporary_sha256': temporary_sha, 'final_receipt_exists': destination.exists(), 'original_journal_pins': original_pins})
        # One actual polling interval after recovery verifies no duplicate launch.
        time.sleep(2)
        final = observe('stable-quarantine')
        check('no_second_attempt_false_release_merge_or_lease_borrow', final['attempt_count'] == 1 and final['held'] == before['held'] and final['allocated'] == before['allocated']
            and final['models'] == final['merges'] == final['evidence'] == 0 and final['attempt']['generation'] == attempt['generation']
            and final['attempt']['state'] == 'RECOVERY_REQUIRED' and not destination.exists(), final)
        check('canonical_ref_not_advanced', git(fixture['canonical'], 'rev-parse', 'refs/heads/main') == baseline, {'main_ref': baseline})
        report['retained_authority_scope'] = 'Private QA ledger intentionally remains unresolved with actual held resources. Manual physical actor cleanup does not invent stop/result/receipt or SQL settlement.'
        report['journal_manifest'] = [{'relative_path': str(p.relative_to(journal)), 'sha256': sha(p), 'bytes': p.stat().st_size} for p in journal.rglob('*') if p.is_file()]
    except Exception as error:
        report['errors'].append({'type': type(error).__name__, 'message': str(error)})
    finally:
        subprocess.Popen = original_popen
        signal.alarm(0)
        # Physical teardown is separate from controller settlement. Never fake it.
        if author and same(author, process_fingerprint(author['pid'])):
            os.kill(author['pid'], signal.SIGKILL)
            until = time.monotonic() + 10
            while process_fingerprint(author['pid']) and time.monotonic() < until:
                time.sleep(.1)
        actors = [(f'worker-{i}', w['process']) for i, w in enumerate(client.workers if client else [])]
        actors.append(('api', api))
        for label, p in actors:
            if p is None: continue
            if p.poll() is None:
                p.terminate()
                try: p.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=10)
            report['process_shutdown'][label] = {'pid': p.pid, 'exit_code': p.poll(), 'proc_absent': not Path(f'/proc/{p.pid}').exists()}
        for w in client.workers if client else []: w['log'].close()
        if api_log: api_log.close()
        with socket.socket() as sk: report['private_port_closed'] = sk.connect_ex(('127.0.0.1', args.port)) != 0
        report['main_after'] = main_identity()
        report['author_after_cleanup'] = process_fingerprint(author['pid']) if author else None
        closed = report['private_port_closed'] and report['main_after'] == before_main and all(v['proc_absent'] for v in report['process_shutdown'].values()) and report['author_after_cleanup'] is None
        report['checks'].append({'name': 'owned_actors_closed_main_identity_unchanged', 'status': 'PASS' if closed else 'FAIL'})
        if attempt and client:
            try: report['authority_after_physical_cleanup'] = observe('after-physical-cleanup')
            except Exception as error: report['errors'].append({'cleanup_authority_observation': type(error).__name__})
        report['status'] = 'PASS_ACTUAL_RECEIPT_MISSING_WINDOW_QUARANTINE' if not report['errors'] and all(c['status'] == 'PASS' for c in report['checks']) else 'FAIL'
        save(OUT / 'report.json', report)
        save(OUT / 'terminal-receipt.json', {'report_sha256': sha(OUT / 'report.json'), 'status': report['status'], 'process_shutdown': report['process_shutdown'], 'private_port_closed': report['private_port_closed'], 'author_after_cleanup': report['author_after_cleanup'], 'main_after': report['main_after']})
        signal.signal(signal.SIGALRM, old_alarm)
        signal.signal(signal.SIGTERM, old_term)
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'errors': report['errors'], 'report': str(OUT / 'report.json')}))
    return 0 if report['status'].startswith('PASS_') else 1

if __name__ == '__main__':
    raise SystemExit(main())

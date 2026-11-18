#!/usr/bin/env python3
"""One real Worker crash after author launch; prepare first, execute after Root GO.

Only the owned Worker PID is killed. The author may remain alive or stop through
its sandbox. Ledger release requires the authentic restarted Worker's stop proof.
No fabricated callbacks, receipt removal, SQL authority mutation or model calls.
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
from cross_project_business_chain import (Client, actual_running, git, paused,
    policy, private_bytes, process_fingerprint, provision, save, stop_attempt, wait)
from guarded_api_chain import create_database, database_command, secure_save

IDENTITY = '45ccbc23e24292368deff584beed1c43076a57357ca500eeb4202f04a74f2acb'
RECEIPT_SHA = 'c71f1c2640c5dcb9280cc35c9df23db1554f0fed4cd56a405829e45630eff126'


def load(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main_identity():
    text = subprocess.run(['systemctl', '--user', 'show', 'forgeflow-control.service',
        '--property=MainPID', '--property=ActiveState'], capture_output=True,
        text=True, check=True, timeout=15).stdout
    return dict(line.split('=', 1) for line in text.splitlines())


def matches(left, right):
    return bool(left and right and all(left[k] == right[k] for k in ('pid', 'start_ticks', 'cmdline')))


def prepare(args):
    r = load(args.build_receipt)
    assert sha(args.build_receipt) == RECEIPT_SHA and r['source_identity'] == IDENTITY
    assert r['consistent_copy'] and r['source_unchanged_after_build']
    assert all(c['exit_code'] == 0 for c in r['commands'])
    assert args.port not in (8787, 8788) and 1024 <= args.port <= 65535
    binaries = {name: r['binaries'][name] for name in ('forgeflow-server', 'forgeflow-worker')}
    assert all(sha(b['path']) == b['sha256'] for b in binaries.values())
    paths = ['verification/g16_worker_crash_point.py', 'verification/cross_project_business_chain.py',
        'verification/guarded_api_chain.py', 'verification/algorithm_check.py',
        'verification/fixtures/control_verifier.py', 'benchmarks/metrics.py']
    components = ['crates/worker/src/lib.rs', 'crates/runtime/src/process.rs',
        'crates/runtime/src/journal.rs', 'crates/store/src/lifecycle.rs', 'crates/api/src/workers.rs']
    frozen = Path(r['snapshot_root'])
    assert all(sha(frozen / p) == r['source_files'][p] for p in components)
    return {'schema_version': 'forgeflow.g16-worker-crash-source-plan.v1',
        'status': 'SOURCE_READY_NO_ACTORS', 'source_identity': IDENTITY,
        'build_receipt': {'path': str(args.build_receipt.resolve()), 'sha256': RECEIPT_SHA},
        'binaries': binaries, 'driver_and_fixture_pins': {p: sha(ROOT / p) for p in paths},
        'frozen_components': {p: {'path': str(frozen / p), 'sha256': sha(frozen / p)} for p in components},
        'port': args.port, 'main_pid': args.main_pid,
        'actors': {'private_apis': 1, 'Worker_initial_processes': 1, 'Worker_same_config_restarts': 1,
            'controlled_authors': 1, 'verifier_commands': 0, 'models': 0, 'Cargo': 0},
        'window': 'Original design11.4 process already launched then Worker crashes; one real SIGKILL9 of owned Worker PID, authentic same-data-root startup reconciliation.',
        'fixture': 'Existing real provision helper, count1, zero-model controlled author; LOCAL_TRUSTED_WORKTREE and logical active/coding/CPU/memory reservation, no OS physical-limit qualification.',
        'crash_oracle': 'Record author presence after crash without requiring it alive; held resources and unfinished authority must not be silently released before authentic stop settlement.',
        'recovery_oracle': 'Same original operation/attempt/generation/execution/launch receipt and output retained; no second author launch; authentic stop/result and legal terminal/resource release or explicit retained recovery with Owner stop.',
        'actor_phase_alarm_seconds': 240, 'finite_cleanup_seconds_per_process': 35,
        'source_ready_actors_started': 0, 'Root_GO_and_exact_plan_sha256_required': True,
        'not_proven': ['Receipt-missing launch micro-window', 'Heartbeat-expiry injection', 'Duplicate dispatch/ACK-loss injection',
            'Cancel-vs-success race', 'Power loss', 'Fullfaultmatrix', 'DSH/native/production100']}


def execute(args, plan):
    prepared = args.output / 'source-ready-plan.json'
    assert sha(prepared) == args.expected_plan_sha256 and load(prepared) == plan
    assert not (args.output / 'report.json').exists(), 'Refuse repeating an existing crash case'
    before_main = main_identity()
    assert before_main == {'MainPID': str(args.main_pid), 'ActiveState': 'active'}
    with socket.socket() as sk:
        assert sk.connect_ex(('127.0.0.1', args.port)) != 0
    private = Path(tempfile.mkdtemp(prefix='forgeflow-g16-worker-crash-', dir='/home/chenyoujian/.cache'))
    private.chmod(0o700)
    (private / 'state').mkdir(mode=0o700)
    diagnostics = private / 'diagnostics'
    diagnostics.mkdir(mode=0o700)
    database = 'forgeflow_g16_worker_' + uuid.uuid4().hex[:16]
    env = {'DATABASE_URL': create_database(load(args.private_env), database, private),
        'FORGEFLOW_BIND': f'127.0.0.1:{args.port}', 'FORGEFLOW_DATA_ROOT': str(private / 'state'),
        'FORGEFLOW_OWNER_TOKEN': secrets.token_hex(32), 'FORGEFLOW_WORKER_TOKEN': secrets.token_hex(32), 'RUST_LOG': 'info'}
    secure_save(private / 'runtime-env.json', env)
    client = Client(f'http://127.0.0.1:{args.port}', env['FORGEFLOW_OWNER_TOKEN'], args.output, diagnostics)
    client.database_url = env['DATABASE_URL']
    client.worker_token = env['FORGEFLOW_WORKER_TOKEN']
    client.sensitive.add(client.worker_token)
    report = {'schema_version': 'forgeflow.g16-actual-worker-crash-point.v1', 'status': 'RUNNING',
        'source_identity': IDENTITY, 'source_plan_sha256': sha(prepared), 'scope': plan['window'],
        'private_root': str(private), 'database_name': database, 'checks': [], 'errors': [],
        'process_shutdown': {}, 'models': 0, 'verifier_commands': 0, 'not_proven': plan['not_proven']}
    api = api_log = attempt = fixture = journal = author_identity = None
    replacement = None

    def check(name, condition, facts=None):
        report['checks'].append({'name': name, 'status': 'PASS' if condition else 'FAIL', 'facts': facts})
        save(args.output / 'report.json', report)
        if not condition:
            raise RuntimeError('Actual crash point assertion failed: ' + name)

    def observe(label):
        p, aid = fixture['project_id'], attempt['attempt_id']
        sql = f"SELECT jsonb_build_object('attempt',(SELECT data FROM attempts WHERE attempt_id='{aid}'),'attempt_count',(SELECT count(*) FROM attempts WHERE project_id='{p}'),'held',(SELECT count(*) FROM resource_allocations WHERE attempt_id='{aid}' AND state<>'RELEASED'),'allocations',COALESCE((SELECT jsonb_agg(to_jsonb(r)) FROM resource_allocations r WHERE attempt_id='{aid}'),'[]'::jsonb),'leases',COALESCE((SELECT jsonb_agg(to_jsonb(l)) FROM leases l WHERE attempt_id='{aid}'),'[]'::jsonb),'evidence_count',(SELECT count(*) FROM evidence_receipts WHERE attempt_id='{aid}'),'merge_count',(SELECT count(*) FROM merge_intents WHERE attempt_id='{aid}'),'models',(SELECT count(*) FROM model_request_permit),'worker_results',COALESCE((SELECT jsonb_agg(payload) FROM worker_event_ids WHERE attempt_id='{aid}'),'[]'::jsonb),'events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY project_seq) FROM events e WHERE project_id='{p}'),'[]'::jsonb),'outbox',COALESCE((SELECT jsonb_agg(to_jsonb(o)) FROM outbox o WHERE project_id='{p}'),'[]'::jsonb));"
        output = database_command(client.database_url, sql)
        assert output.returncode == 0, 'Read-only authority observation failed'
        private_bytes(private / (label + '.authority.bin'), output.stdout)
        value = json.loads(output.stdout)
        save(args.output / (label + '.authority.json'), value)
        return value

    def retain_journal(label):
        source = private / ('journal-' + label)
        source.mkdir(mode=0o700)
        facts = []
        for p in journal.rglob('*'):
            if not p.is_file():
                continue
            target = source / p.relative_to(journal)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Copy originals only into private mode0600 storage; publish pins.
            private_bytes(target, p.read_bytes())
            facts.append({'relative_path': str(p.relative_to(journal)), 'private_original_copy': str(target),
                'sha256': sha(target), 'bytes': target.stat().st_size})
        save(args.output / ('journal-' + label + '-manifest.json'), facts)
        return facts

    def interrupted(signum, frame):
        raise RuntimeError('Bounded actor deadline or termination received')

    previous_alarm = signal.signal(signal.SIGALRM, interrupted)
    previous_term = signal.signal(signal.SIGTERM, interrupted)
    signal.alarm(plan['actor_phase_alarm_seconds'])
    try:
        api_log = os.fdopen(os.open(private / 'api.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
        api = subprocess.Popen([plan['binaries']['forgeflow-server']['path']],
            env={'PATH': '/usr/bin:/bin', **env}, stdout=api_log, stderr=subprocess.STDOUT)

        def healthy():
            assert api.poll() is None, 'Owned API exited'
            try:
                return client.request('GET', '/me')[0] == 200
            except OSError:
                return False
        wait(healthy, 'one private API readiness', 30)
        policy(client, 'global')
        fixture = provision(client, private, load(args.build_receipt), 'g16-worker-crash', 1, 1, 163)
        report['project_id'] = fixture['project_id']
        paused(client, fixture['project_id'], False)
        running = wait(lambda: actual_running(client, [fixture['project_id']], private), 'one actual author RUNNING', 45)[0]
        attempt = running['attempt']
        report['attempt_id'] = attempt['attempt_id']
        journal = running['journal']
        author_identity = running['fingerprint']
        paused(client, fixture['project_id'], True)
        baseline = git(fixture['canonical'], 'rev-parse', 'refs/heads/main')
        output = private / 'state/worktrees' / attempt['attempt_id'] / 'result-0.json'
        original_output = output.read_bytes()
        (args.output / 'output-before-crash.json').write_bytes(original_output)
        config = fixture['root'] / 'worker-config.json'
        config_sha = sha(config)
        original_launch_sha = sha(journal / 'launch-receipt.json')
        original_intent_sha = sha(journal / 'launch-intent.json')
        original_execution = load(journal / 'execution-id.json')
        before = observe('before-crash')
        retain_journal('before-crash')
        check('original_live_author_and_single_attempt_before_crash', before['attempt']['state'] == 'RUNNING'
            and before['attempt_count'] == 1 and before['held'] == 28 and matches(process_fingerprint(author_identity['pid']), author_identity),
            {'author': author_identity, 'launch': load(journal / 'launch-receipt.json'),
                'execution_id': original_execution, 'output_sha256': sha(args.output / 'output-before-crash.json')})
        first = fixture['process']
        worker_identity = process_fingerprint(first.pid)
        check('owned_worker_identity_matches_before_SIGKILL', matches(process_fingerprint(first.pid), worker_identity)
            and plan['binaries']['forgeflow-worker']['path'] in worker_identity['cmdline'], worker_identity)
        os.kill(first.pid, signal.SIGKILL)
        first.wait(timeout=10)
        after = observe('after-worker-SIGKILL')
        report['after_crash_author_observation'] = process_fingerprint(author_identity['pid'])
        save(args.output / 'actual-worker-crash.json', {'worker_before': worker_identity,
            'worker_exit_code': first.returncode, 'worker_after': process_fingerprint(first.pid),
            'author_before': author_identity, 'author_after': report['after_crash_author_observation'],
            'note': 'Author presence is an observation, not a required result; sandbox parent-death may terminate it.'})
        check('actual_owned_Worker_SIGKILL9_keeps_occupied_authority', first.returncode == -9
            and process_fingerprint(first.pid) is None and after['held'] == 28
            and after['attempt']['terminal_at'] is None and after['attempt']['state'] in ('RUNNING', 'RECOVERY_REQUIRED', 'STOPPING'),
            {'attempt_state': after['attempt']['state'], 'held': after['held'], 'author_after': report['after_crash_author_observation']})
        # One replacement only, the same original byte-for-byte config/data root.
        assert sha(config) == config_sha
        second_log = os.fdopen(os.open(private / 'worker-restarted.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
        second = subprocess.Popen([plan['binaries']['forgeflow-worker']['path'], '--config', str(config)],
            env={'PATH': '/usr/bin:/bin', 'RUST_LOG': 'info', 'FORGEFLOW_WORKER_TOKEN': client.worker_token},
            stdout=second_log, stderr=subprocess.STDOUT)
        replacement = {'worker_id': fixture['worker_id'], 'process': second, 'log': second_log}
        client.workers.append(replacement)
        report['replacement_worker_identity'] = process_fingerprint(second.pid)

        def reconciled():
            assert second.poll() is None, 'Replacement Worker exited before reconciliation'
            if (journal / 'stop.json').exists() and (journal / 'result.json').exists():
                stop = load(journal / 'stop.json')
                return stop if stop['process_exit_confirmed'] else None
            return None
        stop = wait(reconciled, 'authentic replacement Worker stop/result journals', 45)
        check('authentic_restart_confirms_original_author_stop', stop['process_exit_confirmed']
            and process_fingerprint(author_identity['pid']) is None, stop)
        retained = observe('after-authentic-reconciliation')
        if retained['attempt']['state'] not in ('CANCELLED', 'FAILED'):
            # Legitimate Owner cancellation consumes the actual Worker stop proof.
            stop_attempt(client, retained['attempt'])

        def terminal():
            row = client.api('GET', f"/attempts/{attempt['attempt_id']}?project_id={fixture['project_id']}")
            return row if row['state'] in ('CANCELLED', 'FAILED', 'SUCCEEDED') else None
        final_attempt = wait(terminal, 'authentic or Owner-controlled recovery terminal', 35)
        final = observe('final-authority')
        retain_journal('after-recovery')
        (args.output / 'output-after-recovery.json').write_bytes(output.read_bytes())
        check('same_original_identity_no_relaunch_or_output_loss', sha(config) == config_sha
            and sha(journal / 'launch-receipt.json') == original_launch_sha
            and sha(journal / 'launch-intent.json') == original_intent_sha
            and load(journal / 'execution-id.json') == original_execution
            and output.read_bytes() == original_output and final['attempt_count'] == 1
            and final['attempt']['generation'] == before['attempt']['generation'],
            {'original_launch_sha256': original_launch_sha, 'original_execution': original_execution,
                'final_attempt': final_attempt, 'output_sha256': sha(args.output / 'output-after-recovery.json')})
        result = load(journal / 'result.json')
        check('real_reconciled_result_reaches_authority_once', result['outcome']['completion_reason'] == 'CANCELLED'
            and result['evidence']['process_exit_confirmed'] and any(r['event_id'] == result['event_id'] for r in final['worker_results']),
            {'result': result, 'result_ack_exists': (journal / 'result-ack.json').exists()})
        check('canonical_ref_not_advanced_and_failure_not_business_success', final['attempt']['state'] in ('CANCELLED', 'FAILED')
            and final['held'] == final['models'] == final['evidence_count'] == final['merge_count'] == 0
            and all(row['revoked_at'] for row in final['leases'])
            and git(fixture['canonical'], 'rev-parse', 'refs/heads/main') == baseline,
            {'state': final['attempt']['state'], 'held': final['held'], 'original_ref': baseline})
    except Exception as error:
        report['errors'].append({'type': type(error).__name__, 'message': str(error)})
    finally:
        signal.alarm(0)
        if attempt is not None and api is not None and api.poll() is None:
            try:
                stop_attempt(client, attempt)
            except Exception as error:
                report['errors'].append({'cleanup': 'Owner stop', 'type': type(error).__name__})
        # On a failed startup, stop only the positively identified fixture author;
        # never manufacture a Worker callback or release its unresolved DB ledger.
        current_author = process_fingerprint(author_identity['pid']) if author_identity else None
        if matches(current_author, author_identity):
            os.kill(author_identity['pid'], signal.SIGTERM)
            deadline = time.monotonic() + 5
            while process_fingerprint(author_identity['pid']) and time.monotonic() < deadline:
                time.sleep(.1)
            if matches(process_fingerprint(author_identity['pid']), author_identity):
                os.kill(author_identity['pid'], signal.SIGKILL)
            report['errors'].append({'cleanup': 'manual owned-author termination after failed reconciliation; authority not forced released'})
        actors = [(f'worker-{index}', worker['process']) for index, worker in enumerate(client.workers)]
        actors.append(('api', api))
        for label, process in actors:
            if process is None:
                continue
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    report['errors'].append({'cleanup': label, 'message': 'positive process exit unconfirmed'})
            report['process_shutdown'][label] = {'pid': process.pid, 'exit_code': process.poll(), 'confirmed': process.poll() is not None}
        for worker in client.workers:
            worker['log'].close()
        if api_log is not None:
            api_log.close()
        with socket.socket() as sk:
            report['private_port_closed'] = sk.connect_ex(('127.0.0.1', args.port)) != 0
        report['main_after'] = main_identity()
        report['checks'].append({'name': 'owned_actors_closed_main_unchanged', 'status': 'PASS'
            if report['private_port_closed'] and report['main_after'] == before_main
            and all(p['confirmed'] for p in report['process_shutdown'].values())
            and (not author_identity or process_fingerprint(author_identity['pid']) is None) else 'FAIL'})
        report['status'] = ('PASS_ACTUAL_WORKER_AFTER_LAUNCH_CRASH' if not report['errors']
            and all(c['status'] == 'PASS' for c in report['checks']) else 'FAIL')
        report['raw_manifest'] = [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p), 'bytes': p.stat().st_size}
            for p in args.output.rglob('*') if p.is_file() and p.name != 'report.json']
        save(args.output / 'report.json', report)
        signal.signal(signal.SIGALRM, previous_alarm)
        signal.signal(signal.SIGTERM, previous_term)
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'report': str(args.output / 'report.json')}))
    return 0 if report['status'] == 'PASS_ACTUAL_WORKER_AFTER_LAUNCH_CRASH' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-receipt', type=Path, required=True)
    parser.add_argument('--private-env', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--main-pid', type=int, required=True)
    parser.add_argument('--port', type=int, default=8896)
    parser.add_argument('--execute-authorized', action='store_true')
    parser.add_argument('--expected-plan-sha256')
    args = parser.parse_args()
    args.output = args.output.resolve()
    assert args.output.is_relative_to((ROOT / 'evidence/goal-gap-points-r3/g16/worker-after-launch-r1').resolve())
    plan = prepare(args)
    if args.execute_authorized:
        return execute(args, plan)
    args.output.mkdir(parents=True, exist_ok=True)
    assert not (args.output / 'source-ready-plan.json').exists()
    save(args.output / 'source-ready-plan.json', plan)
    print(json.dumps({'status': plan['status'], 'plan': str(args.output / 'source-ready-plan.json'),
        'plan_sha256': sha(args.output / 'source-ready-plan.json')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

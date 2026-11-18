#!/usr/bin/env python3
"""One actual product rejection: a staged rename whose old endpoint is allowed.

Preparation launches nothing. Root GO executes one isolated API, Worker and
controlled author. Fixture-only Git mutation happens after confirmed author stop.
No models, production-service writes, verifier commands or workspace compilation.
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
    policy, project_public, provision, save, stop_attempt, wait)
from guarded_api_chain import create_database, database_command, secure_save
from metrics import process_fingerprint

IDENTITY = 'c510f1a59bd4be871f5aed0a24407147ff726cad2c92e1e5b857179cae1b7116'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def main_identity():
    output = subprocess.run(['systemctl', '--user', 'show', 'forgeflow-control.service',
        '--property=MainPID', '--property=ActiveState'], capture_output=True, text=True,
        timeout=15, check=True).stdout
    return dict(line.split('=', 1) for line in output.splitlines())


def prepare(args):
    receipt = load(args.build_receipt)
    assert receipt['source_identity'] == IDENTITY
    assert receipt['consistent_copy'] and receipt['source_unchanged_after_build']
    assert all(c['exit_code'] == 0 for c in receipt['commands'])
    assert args.port not in (8787, 8788) and 1024 <= args.port <= 65535
    binaries = {n: receipt['binaries'][n] for n in ('forgeflow-server', 'forgeflow-worker')}
    assert all(sha(b['path']) == b['sha256'] for b in binaries.values())
    sources = ['verification/g09_git_boundary_point.py', 'verification/cross_project_business_chain.py',
        'verification/guarded_api_chain.py', 'verification/algorithm_check.py',
        'verification/fixtures/control_verifier.py', 'crates/git/src/lib.rs',
        'crates/git/tests/git_integration.rs', 'crates/api/src/operations.rs']
    old_receipt = load(ROOT / 'evidence/builds/7ea2d80547f69511/receipt.json')
    unchanged = {p: sha(ROOT / p) == old_receipt['source_files'][p] == receipt['source_files'][p]
        for p in ('crates/git/src/lib.rs', 'crates/git/tests/git_integration.rs')}
    assert all(unchanged.values())
    return {'schema_version': 'forgeflow.g09-new-rename-source-plan.v1',
        'status': 'SOURCE_READY_NO_ACTORS', 'source_identity': IDENTITY,
        'build_receipt': {'path': str(args.build_receipt.resolve()), 'sha256': sha(args.build_receipt)},
        'binaries': binaries, 'source_pins': {p: sha(ROOT / p) for p in sources},
        'historical_git_proof': {'receipt': str(ROOT / 'evidence/builds/7ea2d80547f69511/receipt.json'),
            'receipt_sha256': sha(ROOT / 'evidence/builds/7ea2d80547f69511/receipt.json'),
            'test_log': 'evidence/builds/7ea2d80547f69511/test.txt',
            'test_log_sha256': sha(ROOT / 'evidence/builds/7ea2d80547f69511/test.txt'),
            'exact_git_source_unchanged': unchanged,
            'scope': 'Historical actual mixed layers, old rename endpoint, deletion and staged-only negatives; exact unchanged Git source, not a new whole suite run'},
        'port': args.port, 'main_pid': args.main_pid,
        'actors': {'private_apis': 1, 'private_workers': 1, 'controlled_authors': 1,
            'models': 0, 'verifier_commands': 0, 'cargo': 0},
        'old_endpoint': 'result-0.json', 'new_endpoint': 'outside-new.json',
        'scope': 'Actual API refuses new renamed path when only old path belongs to Owner and task write set. Fixture controller stages rename after real author positive stop.',
        'execution_requires_exact_root_go_plan_sha256': True}


def execute(args, plan):
    path = args.output / 'source-ready-plan.json'
    assert sha(path) == args.expected_plan_sha256 and load(path) == plan
    assert not (args.output / 'report.json').exists(), 'Never rerun existing fixture'
    before_main = main_identity()
    assert before_main == {'MainPID': str(args.main_pid), 'ActiveState': 'active'}
    with socket.socket() as sk:
        assert sk.connect_ex(('127.0.0.1', args.port)) != 0
    private = Path(tempfile.mkdtemp(prefix='forgeflow-g09-point-', dir='/home/chenyoujian/.cache'))
    private.chmod(0o700)
    (private / 'state').mkdir(mode=0o700)
    diagnostics = private / 'diagnostics'
    diagnostics.mkdir(mode=0o700)
    database = 'forgeflow_g09_' + uuid.uuid4().hex[:16]
    env = {'DATABASE_URL': create_database(load(args.private_env), database, private),
        'FORGEFLOW_BIND': f'127.0.0.1:{args.port}', 'FORGEFLOW_DATA_ROOT': str(private / 'state'),
        'FORGEFLOW_OWNER_TOKEN': secrets.token_hex(32), 'FORGEFLOW_WORKER_TOKEN': secrets.token_hex(32),
        'RUST_LOG': 'info'}
    secure_save(private / 'runtime-env.json', env)
    client = Client(f'http://127.0.0.1:{args.port}', env['FORGEFLOW_OWNER_TOKEN'], args.output, diagnostics)
    client.database_url = env['DATABASE_URL']
    client.worker_token = env['FORGEFLOW_WORKER_TOKEN']
    client.sensitive.add(client.worker_token)
    report = {'schema_version': 'forgeflow.g09-actual-new-rename-rejection.v1', 'status': 'RUNNING',
        'source_identity': IDENTITY, 'source_plan_sha256': sha(path), 'private_root': str(private),
        'database_name': database, 'models': 0, 'checks': [], 'errors': [], 'process_shutdown': {},
        'not_proven': ['Fresh full Git regression', 'All product gates', 'Hostile sandbox security', 'DSH production scale']}
    server = log = attempt = fixture = None

    def check(name, condition, facts=None):
        report['checks'].append({'name': name, 'status': 'PASS' if condition else 'FAIL',
            'facts': project_public(facts)})
        save(args.output / 'report.json', report)
        if not condition:
            raise RuntimeError('Actual point assertion failed: ' + name)

    def observe():
        aid = attempt['attempt_id']
        query = f"SELECT jsonb_build_object('attempt',(SELECT data FROM attempts WHERE attempt_id='{aid}'),'evidence',(SELECT count(*) FROM evidence_receipts WHERE attempt_id='{aid}'),'merges',(SELECT count(*) FROM merge_intents WHERE attempt_id='{aid}'),'held',(SELECT count(*) FROM resource_allocations WHERE attempt_id='{aid}' AND state<>'RELEASED'),'leases',(SELECT count(*) FROM leases WHERE attempt_id='{aid}' AND revoked_at IS NULL),'models',(SELECT count(*) FROM model_request_permit));"
        result = database_command(client.database_url, query)
        assert result.returncode == 0, 'Read-only authority failed'
        return json.loads(result.stdout)

    try:
        log = os.fdopen(os.open(private / 'server.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
        server = subprocess.Popen([plan['binaries']['forgeflow-server']['path']],
            env={'PATH': '/usr/bin:/bin', **env}, stdout=log, stderr=subprocess.STDOUT)

        def healthy():
            assert server.poll() is None, 'Owned API exited'
            try:
                return client.request('GET', '/me')[0] == 200
            except OSError:
                return False
        wait(healthy, 'private API readiness', 30)
        policy(client, 'global')
        fixture = provision(client, private, load(args.build_receipt), 'g09-new-rename', 1, 1, 947)
        report['project_id'] = fixture['project_id']
        paused(client, fixture['project_id'], False)
        running = wait(lambda: actual_running(client, [fixture['project_id']], private), 'one genuine controlled author', 45)[0]
        attempt = running['attempt']
        report['attempt_id'] = attempt['attempt_id']
        identity = process_fingerprint(running['fingerprint']['pid'])
        assert identity and all(identity[k] == running['fingerprint'][k]
            for k in ('pid', 'start_ticks', 'cmdline')), 'Author PID identity drift'
        os.kill(identity['pid'], signal.SIGUSR1)

        def verifying():
            row = client.api('GET', f"/attempts/{attempt['attempt_id']}?project_id={fixture['project_id']}")
            assert row['state'] not in ('FAILED', 'CANCELLED', 'RECOVERY_REQUIRED'), row['state']
            return row if row['state'] == 'VERIFYING' else None
        attempt = wait(verifying, 'author positive stop reaches VERIFYING', 35)
        paused(client, fixture['project_id'], True)
        journal = private / 'state/attempts' / attempt['attempt_id']
        stop = load(journal / 'stop.json')
        check('genuine_author_confirmed_stopped_before_fixture_mutation', stop['process_exit_confirmed']
            and stop['exit_code'] == 0 and process_fingerprint(identity['pid']) is None,
            {'stop': stop, 'author_identity': identity})
        worktree = private / 'state/worktrees' / attempt['attempt_id']
        old, new = plan['old_endpoint'], plan['new_endpoint']
        task = next(iter(fixture['tasks'].values()))
        check('only_old_endpoint_allowed', task['write_set'] == [old] and new not in task['write_set'])
        old_bytes = (worktree / old).read_bytes()
        canonical_before = git(fixture['canonical'], 'rev-parse', 'refs/heads/main')
        git(worktree, 'add', '--', old)
        git(worktree, '-c', 'user.name=G09 fixture', '-c', 'user.email=fixture@localhost',
            'commit', '-m', 'Legal old-path fixture checkpoint before negative rename')
        candidate_before = git(worktree, 'rev-parse', 'HEAD')
        git(worktree, 'mv', '--', old, new)
        diff = subprocess.run(['git', '-C', str(worktree), 'diff', '--cached', '--name-status', '-z', '-M', '--'],
            capture_output=True, check=True, timeout=15).stdout
        (args.output / 'actual-staged-rename.bin').write_bytes(diff)
        check('actual_rename_has_both_endpoints_and_identical_blob', diff == f'R100\0{old}\0{new}\0'.encode()
            and (worktree / new).read_bytes() == old_bytes, {'raw_diff_sha256': sha(args.output / 'actual-staged-rename.bin')})
        accepted = client.api('POST', f"/attempts/{attempt['attempt_id']}/verify", {'project_id': fixture['project_id']})
        report['operation_id'] = accepted['operation_id']

        def rejected():
            op = client.api('GET', '/operations/' + accepted['operation_id'])
            return op if op['status'] in ('FAILED', 'SUCCEEDED', 'RECOVERY_REQUIRED') else None
        operation = wait(rejected, 'actual product Git-scope rejection', 35)
        check('product_rejects_new_endpoint_with_old_allowed', operation['status'] == 'FAILED'
            and operation['error']['code'] == 'GIT_INTEGRATION_FAILED'
            and new in operation['error']['message'], operation)
        git_dir = Path(git(worktree, 'rev-parse', '--absolute-git-dir'))
        rejected_path = git_dir / 'forgeflow-rejected-diff.json'
        manifest = load(rejected_path)
        (args.output / 'product-rejected-diff.json').write_bytes(rejected_path.read_bytes())
        check('production_manifest_records_true_rename', any(c['layer'] == 'staged' and c['status'] == 'R100'
            and c['path'] == new and c['old_path'] == old for c in manifest['changes']), manifest)
        authority = observe()
        save(args.output / 'authority-after-rejection.json', project_public(authority))
        role_reports = list((private / 'state/artifacts').rglob('verification-receipt.json'))
        check('rejection_preserves_unfinished_authority_and_canonical_ref', authority['attempt']['state'] == 'VERIFYING'
            and authority['attempt']['terminal_at'] is None and authority['evidence'] == authority['merges'] == authority['models'] == 0
            and not role_reports and git(worktree, 'rev-parse', 'HEAD') == candidate_before
            and git(fixture['canonical'], 'rev-parse', 'refs/heads/main') == canonical_before, authority)
        stop_attempt(client, attempt)
        final = observe()
        save(args.output / 'authority-after-owner-stop.json', project_public(final))
        check('real_owner_cancel_releases_held_resources', final['attempt']['state'] == 'CANCELLED'
            and final['held'] == final['leases'] == final['models'] == final['evidence'] == final['merges'] == 0, final)
    except Exception as error:
        report['errors'].append({'type': type(error).__name__, 'message': str(error)})
    finally:
        if attempt is not None and server is not None and server.poll() is None:
            try:
                stop_attempt(client, attempt)
            except Exception as error:
                report['errors'].append({'cleanup': type(error).__name__})
        for name, process in [(w['worker_id'], w['process']) for w in client.workers] + [('api', server)]:
            if process is None:
                continue
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    report['errors'].append({'cleanup': name, 'message': 'positive exit unconfirmed'})
            report['process_shutdown'][name] = {'pid': process.pid, 'exit_code': process.poll(), 'confirmed': process.poll() is not None}
        for worker in client.workers:
            worker['log'].close()
        if log is not None:
            log.close()
        with socket.socket() as sk:
            port_closed = sk.connect_ex(('127.0.0.1', args.port)) != 0
        report['main_after'] = main_identity()
        report['checks'].append({'name': 'owned_actors_closed_main_unchanged', 'status': 'PASS'
            if port_closed and report['main_after'] == before_main
            and all(v['confirmed'] for v in report['process_shutdown'].values()) else 'FAIL'})
        report['raw_manifest'] = [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p), 'bytes': p.stat().st_size}
            for p in args.output.rglob('*') if p.is_file() and p.name != 'report.json']
        report['status'] = 'PASS_SCOPED' if not report['errors'] and all(c['status'] == 'PASS' for c in report['checks']) else 'FAIL'
        save(args.output / 'report.json', report)
    print(json.dumps({'status': report['status'], 'report': str(args.output / 'report.json'), 'checks': len(report['checks'])}))
    return 0 if report['status'] == 'PASS_SCOPED' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-receipt', type=Path, required=True)
    parser.add_argument('--private-env', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--main-pid', type=int, required=True)
    parser.add_argument('--port', type=int, default=8895)
    parser.add_argument('--execute-authorized', action='store_true')
    parser.add_argument('--expected-plan-sha256')
    args = parser.parse_args()
    args.output = args.output.resolve()
    assert args.output.is_relative_to((ROOT / 'evidence/goal-gap-points-r1/g09').resolve())
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

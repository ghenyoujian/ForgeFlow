#!/usr/bin/env python3
"""Seven actual evidence refusals against one unfinished, genuinely verified task.

Prepare only by default. Frozen c510 binaries; isolated API/Worker, zero models.
No SQL authority mutation, integration, oracle replay or production source edits.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'verification'))
import physical_business_chain as business
from cross_project_business_chain import Client, ledger_totals, paused, save, stop_attempt, wait
from guarded_api_chain import create_database, database_command, secure_save

SOURCE = 'c510f1a59bd4be871f5aed0a24407147ff726cad2c92e1e5b857179cae1b7116'
CHECKPOINT = Path('/home/chenyoujian/.cache/forgeflow-build-checkpoints/c510f1a59bd4be87-k9o1twt2')
NAMES = ['absent_artifact_descriptor', 'absent_raw_artifact_bytes', 'zero_assertions',
         'all_skipped_claim', 'wrong_task_input', 'wrong_generation', 'wrong_contract_version']
CODES = ['NOT_FOUND', 'EVIDENCE_INCOMPLETE', 'VERIFIER_INVALID',
         'EVIDENCE_BINDING_MISMATCH', 'EVIDENCE_BINDING_MISMATCH', 'LEASE_STALE', 'VERIFIER_INVALID']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def loaded(path):
    return json.loads(Path(path).read_text())


def ctl(*args):
    subprocess.run(['systemctl', '--user', *args], check=True, capture_output=True, timeout=20)


def source_plan(args):
    receipt = loaded(args.build_receipt)
    if receipt['source_identity'] != SOURCE or not receipt['consistent_copy'] or not receipt['source_unchanged_after_build'] or any(c['exit_code'] for c in receipt['commands']):
        raise RuntimeError('Frozen successful c510 checkpoint required')
    binaries = []
    for name in ('forgeflow-server', 'forgeflow-worker', 'forgeflow-sandbox-guard'):
        value = receipt['binaries'][name]
        if sha(value['path']) != value['sha256']:
            raise RuntimeError('Frozen binary bytes changed: ' + name)
        binaries.append(dict(name=name, **value))
    manifest = loaded(args.runtime_release / 'delivery-manifest.json')
    if manifest['files']['bin/forgeflow-server']['sha256'] != receipt['binaries']['forgeflow-server']['sha256'] or sha(args.runtime_release / 'bin/forgeflow-server') != receipt['binaries']['forgeflow-server']['sha256']:
        raise RuntimeError('Runtime API must match c510 executable')
    if args.port != 8896 or not re.fullmatch(r'forgeflow-control-[0-9a-f]{32}', args.api_service_name):
        raise RuntimeError('Exact private port8896 and fresh 32hex owned unit required')
    # Provenance follows immutable compiled snapshot, never a concurrently edited
    # checkout API. Python execution helpers have separate current-byte pins.
    snapshot = Path(receipt['snapshot_root'])
    compiled = []
    for relative in ['crates/api/src/catalog.rs', 'crates/api/src/operations.rs',
                     'crates/api/src/lib.rs', 'crates/store/src/integration.rs',
                     'crates/store/src/lifecycle.rs', 'crates/evidence/src/lib.rs',
                     'crates/evidence/src/runner.rs']:
        path = snapshot / relative
        if sha(path) != receipt['source_files'][relative]:
            raise RuntimeError('Frozen compiled snapshot changed: ' + relative)
        compiled.append({'path': str(path), 'sha256': sha(path)})
    helpers = [Path(__file__), ROOT / 'verification/physical_business_chain.py',
               ROOT / 'verification/cross_project_business_chain.py', ROOT / 'verification/guarded_api_chain.py',
               ROOT / 'verification/algorithm_check.py', ROOT / 'benchmarks/metrics.py',
               ROOT / 'verification/fixtures/control_verifier.py', ROOT / 'ops/run-delegated-worker.py',
               ROOT / 'ops/manage-service.py', ROOT / 'ops/run-service.py',
               Path(sys.executable).resolve(), Path('/usr/bin/bwrap')]
    return {'schema_version': 'forgeflow.g11-evidence-point-plan.v1', 'status': 'SOURCE_READY_NO_ACTORS',
            'source_identity': SOURCE, 'build_receipt': {'path': str(args.build_receipt.resolve()), 'sha256': sha(args.build_receipt)},
            'binaries': binaries, 'compiled_snapshot_pins': compiled,
            'helper_pins': [{'path': str(p.resolve()), 'sha256': sha(p)} for p in helpers],
            'runtime_release': str(args.runtime_release.resolve()), 'manifest_sha256': sha(args.runtime_release / 'delivery-manifest.json'),
            'port': args.port, 'main_pid': args.main_pid, 'api_service_name': args.api_service_name,
            'physical_limits': business.POLICY, 'root_resources': business.REQUEST,
            'author_sha256': hashlib.sha256(business.VERIFIER_AUTHOR.encode()).hexdigest(),
            'positive': 'One real 3role/8case verification, REVIEW_READY without integration, positive closed physical groups',
            'negative_cases': [{'name': n, 'expected_code': c} for n, c in zip(NAMES, CODES)],
            'comparisons': 'Exact Attempt/revision/result/terminal, resource rows, evidence IDs/count, merges, native/model counts and target ref; lease identity/revocation and valid count, excluding concurrent heartbeat expiry timestamps.',
            'qualification': 'Actual malformed evidence submissions refused; contract mutation is durable-runner-manifest refusal, all-skipped mutation contradicts original actual counts. No isolated financial/hostile/version-matrix qualification.',
            'models': 0, 'apis_started': 0, 'workers_started': 0,
            'execution_requires_root_go_and_exact_plan_sha256': True}


def run(args, plan):
    prepared = args.output / 'source-ready-plan.json'
    if sha(prepared) != args.expected_plan_sha256 or loaded(prepared) != plan:
        raise RuntimeError('Approved plan differs; no actors started')
    if (args.output / 'report.json').exists():
        raise RuntimeError('Prior report exists; refuse actor replay')
    main = business.unit_properties('forgeflow-control.service')
    unit = args.api_service_name + '.service'
    slice_name = 'forgeflowcontrolresources' + args.api_service_name.removeprefix('forgeflow-control-') + '.slice'
    if main['MainPID'] != str(args.main_pid) or main['ActiveState'] != 'active' or business.unit_properties(unit)['LoadState'] != 'not-found':
        raise RuntimeError('Main or fresh private service identity differs')
    with socket.socket() as sk:
        if sk.connect_ex(('127.0.0.1', args.port)) == 0:
            raise RuntimeError('Private port occupied')
    private = Path(tempfile.mkdtemp(prefix='forgeflow-g11-point-', dir='/home/chenyoujian/.cache'))
    private.chmod(0o700)
    (private / 'state').mkdir(mode=0o700)
    diagnostics = private / 'diagnostics'; diagnostics.mkdir(mode=0o700)
    database = 'forgeflow_g11_point_' + uuid.uuid4().hex[:16]
    env = {'DATABASE_URL': create_database(loaded(args.private_env), database, private),
           'FORGEFLOW_BIND': f'127.0.0.1:{args.port}', 'FORGEFLOW_DATA_ROOT': str(private / 'state'),
           'FORGEFLOW_OWNER_TOKEN': secrets.token_hex(32), 'FORGEFLOW_WORKER_TOKEN': secrets.token_hex(32), 'RUST_LOG': 'info'}
    secure_save(private / 'runtime-env.json', env)
    client = Client(f'http://127.0.0.1:{args.port}', env['FORGEFLOW_OWNER_TOKEN'], args.output, diagnostics)
    client.worker_token = env['FORGEFLOW_WORKER_TOKEN']; client.database_url = env['DATABASE_URL']; client.sensitive.add(client.worker_token)
    report = {'schema_version': 'forgeflow.g11-actual-evidence-point.v1', 'status': 'RUNNING',
              'source_identity': SOURCE, 'source_plan_sha256': args.expected_plan_sha256,
              'private_root': str(private), 'database_name': database, 'models': 0,
              'checks': [], 'errors': [], 'negative_denominator': 7, 'positive_cases': 8,
              'scope': plan['qualification'], 'main_before': main}
    fixture = None; worker_unit = None; worker_plan = None; api_created = False; api_sha = None; zero = False
    log_path = None; backup = None

    def check(name, condition, facts=None):
        report['checks'].append({'name': name, 'status': 'PASS' if condition else 'FAIL', 'facts': facts})
        save(args.output / 'report.json', report)
        if not condition:
            raise RuntimeError(name)

    def observe():
        aid = report['attempt_id']
        query = f"SELECT jsonb_build_object('attempt',(SELECT data FROM attempts WHERE attempt_id='{aid}'),'allocations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY allocation_id) FROM resource_allocations r WHERE attempt_id='{aid}'),'limits',(SELECT jsonb_agg(to_jsonb(r) ORDER BY scope_id,dimension) FROM resource_limits r),'evidence',COALESCE((SELECT jsonb_agg(data ORDER BY receipt_id) FROM evidence_receipts WHERE attempt_id='{aid}'),'[]'::jsonb),'merges',COALESCE((SELECT jsonb_agg(data ORDER BY intent_id) FROM merge_intents WHERE attempt_id='{aid}'),'[]'::jsonb),'lease_identity',(SELECT jsonb_agg(jsonb_build_object('lease_id',lease_id,'generation',generation,'worker_id',worker_id,'revoked_at',revoked_at) ORDER BY lease_id) FROM leases WHERE attempt_id='{aid}'),'valid_leases',(SELECT count(*) FROM leases WHERE attempt_id='{aid}' AND revoked_at IS NULL AND expires_at>clock_timestamp()),'native',(SELECT count(*) FROM native_child_lifecycles WHERE attempt_id='{aid}' AND state<>'RELEASED'),'models',(SELECT count(*) FROM model_request_permit),'verifier_unsettled',(SELECT count(*) FROM documents r WHERE r.collection='operations' AND r.data->>'kind'='VERIFIER_PROCESS_ROOT' AND r.data->>'attempt_id'='{aid}' AND NOT EXISTS(SELECT 1 FROM documents s WHERE s.collection='operations' AND s.data->>'kind'='VERIFIER_PROCESS_SETTLED' AND s.data->>'registration_id'=r.document_id)));"
        value = database_command(client.database_url, query)
        if value.returncode:
            raise RuntimeError('Read-only authority observation failed')
        result = json.loads(value.stdout)
        result['target_ref'] = business.git(fixture['canonical'], 'rev-parse', 'refs/heads/main')
        return result

    try:
        business.child_json([str(Path(sys.executable).resolve()), str(ROOT / 'ops/manage-service.py'), 'install',
            '--name', args.api_service_name, '--release-dir', str(args.runtime_release),
            '--runtime-env', str(private / 'runtime-env.json'), '--verifier-cgroups', '--start'])
        api_created = True; api_sha = sha(Path.home() / '.config/systemd/user' / unit)
        def healthy():
            try: return client.request('GET', '/me')[0] == 200
            except OSError: return False
        wait(healthy, 'private API readiness', 30)
        receipt = loaded(args.build_receipt)
        fixture = business.create_fixture(client, private, receipt, False)
        fixture['verifier_physical'] = True  # Existing finite author, original oracle, no stress wrapper.
        report['project_id'] = fixture['project']
        launcher = ROOT / 'ops/run-delegated-worker.py'; python = str(Path(sys.executable).resolve())
        wp = business.child_json([python, str(launcher), 'prepare', '--kind', 'worker',
            '--program', receipt['binaries']['forgeflow-worker']['path'], '--program-sha256', receipt['binaries']['forgeflow-worker']['sha256'],
            '--config', str(fixture['config']), '--env-file', str(fixture['env']), '--output', str(private / 'delegated-worker')])
        worker_unit = wp['unit_name']; worker_plan = loaded(private / 'delegated-worker/launch-plan.json')
        business.child_json([python, str(launcher), 'start', '--plan', str(private / 'delegated-worker/launch-plan.json'),
            '--plan-sha256', wp['plan_sha256'], '--unit-sha256', wp['unit_sha256'], '--execute'])
        def registered():
            value = database_command(client.database_url, "SELECT count(*) FROM workers WHERE worker_id='" + fixture['worker'] + "'")
            return value.returncode == 0 and value.stdout.strip() in (b'1', '1')
        wait(registered, 'actual Worker registration', 30)
        business.finalize_fixture(client, private, fixture)
        task = fixture['task']
        client.api('POST', f"/projects/{fixture['project']}/queue-entries", {'task_id': task['task_id'],
            'expected_revision': task['revision'], 'worker_id': fixture['worker'], 'worker_scope_id': fixture['project'] + ':worker',
            'scope_ids': [], 'priority': 1, 'lease_seconds': 120})
        paused(client, fixture['project'], False)
        def verifying():
            state = client.api('GET', f"/projects/{fixture['project']}/snapshot")
            attempts = state['attempts']
            if attempts and attempts[0]['state'] in ('FAILED', 'CANCELLED', 'RECOVERY_REQUIRED'):
                raise RuntimeError('Controlled author failed before evidence point')
            return attempts[0] if attempts and attempts[0]['state'] == 'VERIFYING' else None
        attempt = wait(verifying, 'short author awaited stop', 45)
        report['attempt_id'] = attempt['attempt_id']; paused(client, fixture['project'], True)
        journal = private / 'state/attempts' / attempt['attempt_id']
        stop = loaded(journal / 'stop.json'); physical_stop = loaded(journal / 'cgroup-stop.json')
        check('actual_author_positive_stop', stop['process_exit_confirmed'] and stop['exit_code'] == 0 and physical_stop['process_exit_confirmed'] and not physical_stop['populated'])
        accepted = client.api('POST', f"/attempts/{attempt['attempt_id']}/verify", {'project_id': fixture['project']})
        report['verification_operation_id'] = accepted['operation_id']
        def verified():
            operation = client.api('GET', '/operations/' + accepted['operation_id'])
            if operation['status'] in ('FAILED', 'RECOVERY_REQUIRED'):
                raise RuntimeError('Positive independent verification failed')
            return operation if operation['status'] == 'SUCCEEDED' else None
        operation = wait(verified, 'one actual three-role positive verification', 90)
        evidence = operation['result']['evidence']; original = observe()
        check('genuine_positive_three_roles_eight_cases_still_unfinished', evidence['total'] == 8 and evidence['failed'] == evidence['skipped'] == 0 and
            evidence['details']['positive_cases'] == evidence['details']['negative_cases'] == 4 and original['attempt']['state'] == 'REVIEW_READY' and
            original['attempt']['terminal_at'] is None and len(original['allocations']) == 28 and all(r['state'] != 'RELEASED' for r in original['allocations']) and
            len(original['evidence']) == 1 and not original['merges'] and original['models'] == original['native'] == original['verifier_unsettled'] == 0 and
            original['valid_leases'] == 1 and original['target_ref'] == fixture['baseline'])
        artifact_root = private / 'state/artifacts' / accepted['operation_id']
        log_path = artifact_root / evidence['details']['log_path']
        manifest = artifact_root / 'verification-receipt.json'
        manifest_hash = sha(manifest); log_hash = sha(log_path)
        check('original_trusted_manifest_and_raw_bytes_match', loaded(manifest) == evidence['details'] and log_hash == evidence['artifact']['sha256'])
        context = loaded(artifact_root / 'verification-physical-context.json')
        closed = loaded(artifact_root / 'verification-physical-closed.json')
        commands = context['commands']
        role_stops = [loaded(artifact_root / 'verification-runs' / c['process_attempt_id'] / 'stop.json') for c in commands]
        check('exact_three_real_roles_positively_stopped_and_sealed', len(commands) == 3 and
            [c['role'] for c in commands] == ['author', 'consumer', 'independent'] and
            closed['runner_closed'] is True and not closed['unused_execution_ids'] and
            all(s['process_exit_confirmed'] is True and s['exit_code'] == 0 for s in role_stops))
        raw = args.output / 'raw'; raw.mkdir()
        for source in (manifest, log_path, artifact_root / 'verification-physical-context.json', artifact_root / 'verification-physical-closed.json',
                       *(artifact_root / (role + '.json') for role in ('author', 'consumer', 'independent'))):
            shutil.copyfile(source, raw / source.name)
        shutil.copytree(artifact_root / 'verification-runs', raw / 'verification-runs')
        save(args.output / 'before-negatives.json', original)
        report['original_manifest_sha256'] = manifest_hash; report['original_raw_log_sha256'] = log_hash
        report['positive_command_count'] = 3
        for index, (name, code) in enumerate(zip(NAMES, CODES)):
            body = copy.deepcopy(evidence); body['receipt_id'] = 'rejected-g11-' + name
            if index == 0: body['artifact']['artifact_id'] = 'nonexistent-g11-' + uuid.uuid4().hex
            elif index == 2: body['total'] = 0
            elif index == 3: body['skipped'] = body['total']
            elif index == 4: body['input_digest'] = hashlib.sha256((body['input_digest'] + ':wrong-task').encode()).hexdigest()
            elif index == 5: body['generation'] += 1
            elif index == 6: body['details']['binding']['contract_version'] += '-wrong-version'
            before = observe()
            if index == 1:
                backup = private / 'missing-log-original.bin'
                if backup.exists() or not log_path.resolve().is_relative_to(private.resolve()):
                    raise RuntimeError('Refuse moving an unowned raw log')
                log_path.rename(backup)
            try:
                status, response = client.request('POST', f"/projects/{fixture['project']}/evidence", body, 'g11-' + name)
            finally:
                if backup is not None and backup.exists():
                    if log_path.exists(): raise RuntimeError('Original log restore would overwrite unexpected file')
                    backup.rename(log_path); backup = None
            after = observe()
            unchanged = before == after == original and sha(log_path) == log_hash and sha(manifest) == manifest_hash
            check(name + '_rejected_without_completion_or_release', 400 <= status < 500 and response.get('code') == code and unchanged,
                  {'http_status': status, 'code': response.get('code'), 'state_unchanged': unchanged,
                   'receipt_id': body['receipt_id'], 'attempt_state': after['attempt']['state'], 'held_rows': len(after['allocations'])})
            save(args.output / (name + '-state-comparison.json'), {'before': before, 'after': after, 'unchanged': unchanged})
        report['negatives_passed'] = 7
    except Exception as error:
        report['errors'].append({'type': type(error).__name__, 'message': str(error)[:240]})
    finally:
        if backup is not None and backup.exists() and log_path is not None and not log_path.exists():
            backup.rename(log_path)
        if fixture is not None:
            try:
                paused(client, fixture['project'], True)
                state = client.api('GET', f"/projects/{fixture['project']}/snapshot")
                for attempt in state['attempts']:
                    if attempt['state'] not in ('SUCCEEDED', 'FAILED', 'CANCELLED'):
                        stop_attempt(client, attempt)
                state = client.api('GET', f"/projects/{fixture['project']}/snapshot"); ledger = ledger_totals({fixture['project']: state})
                zero = not ledger['mismatches'] and not ledger['allocated_vectors'] and all(l['revoked_at'] is not None for l in state['leases'])
                check('legal_cancel_real_stop_releases_unfinished_fixture', zero and all(a['state'] == 'CANCELLED' for a in state['attempts']), ledger)
            except Exception as error:
                report['errors'].append({'cleanup': 'authority', 'message': str(error)[:200]})
        else:
            zero = True  # No project/Attempt existed; owned supervisors have no execution authority.
        if zero:
            for owned, own_slice in [(worker_unit, worker_plan['slice_name'] if worker_plan else None), (unit if api_created else None, slice_name)]:
                if not owned: continue
                try:
                    pid = int(business.unit_properties(owned)['MainPID'])
                    if pid: os.kill(pid, signal.SIGTERM)
                    terminal = wait(lambda: business.unit_properties(owned) if business.unit_properties(owned)['MainPID'] == '0' else None, 'own supervisor stop', 35)
                    ctl('stop', owned, own_slice)
                    path = Path.home() / '.config/systemd/user' / owned
                    if owned == unit:
                        ctl('disable', owned)
                        if path.is_symlink() or sha(path) != api_sha: raise RuntimeError('Owned API file identity changed')
                    elif not path.is_symlink() or path.resolve() != private / 'delegated-worker' / owned:
                        raise RuntimeError('Owned Worker link identity changed')
                    path.unlink(); ctl('daemon-reload')
                    report.setdefault('owned_cleanup', []).append({'unit': owned, 'terminal': terminal, 'slice': business.unit_properties(own_slice), 'unlinked': not path.exists()})
                except Exception as error:
                    report['errors'].append({'cleanup': owned, 'message': str(error)[:180]})
        else:
            report['quarantine_retained'] = True
        after_main = business.unit_properties('forgeflow-control.service'); report['main_after'] = after_main
        if after_main['MainPID'] != str(args.main_pid) or after_main['ActiveState'] != 'active':
            report['errors'].append({'main': 'Main identity changed'})
        with socket.socket() as sk: report['private_port_closed'] = sk.connect_ex(('127.0.0.1', args.port)) != 0
        clean = report.get('owned_cleanup', [])
        good = zero and not report['errors'] and report.get('negatives_passed') == 7 and len(clean) == 2 and all(c['terminal']['ExecMainStatus'] == '0' and c['terminal']['MainPID'] == '0' and c['slice']['ActiveState'] == 'inactive' for c in clean) and report['private_port_closed']
        report['status'] = 'PASS_ACTUAL_G11_SEVEN_REJECTIONS_ONE_POSITIVE' if good else 'FAIL'
        report['assertions'] = len(report['checks']); report['failed'] = sum(c['status'] != 'PASS' for c in report['checks'])
        save(args.output / 'report.json', report)
    print(json.dumps({'status': report['status'], 'report': str(args.output / 'report.json'), 'private_root': str(private), 'models': 0}))
    return 0 if report['status'].startswith('PASS_') else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-receipt', type=Path, default=CHECKPOINT / 'receipt.json')
    parser.add_argument('--runtime-release', type=Path, default=Path('/home/chenyoujian/.local/share/forgeflow/releases/c510f1a-commit-stop-core-r1'))
    parser.add_argument('--private-env', type=Path, default=Path('/home/chenyoujian/.local/state/forgeflow/control/runtime-env.json'))
    parser.add_argument('--output', type=Path, default=ROOT / 'evidence/goal-gap-points-r1/g11')
    parser.add_argument('--port', type=int, default=8896)
    parser.add_argument('--main-pid', type=int, default=4023285)
    parser.add_argument('--api-service-name', required=True)
    parser.add_argument('--execute-authorized', action='store_true')
    parser.add_argument('--expected-plan-sha256')
    args = parser.parse_args(); args.output = args.output.resolve(); args.output.mkdir(parents=True, exist_ok=True)
    plan = source_plan(args)
    if not args.execute_authorized:
        path = args.output / 'source-ready-plan.json'
        secure_save(path, plan)
        print(json.dumps({'status': plan['status'], 'plan': str(path), 'sha256': sha(path), 'models': 0, 'actors': 0}))
        return 0
    if not args.expected_plan_sha256: raise RuntimeError('Exact Root-approved plan SHA required')
    return run(args, plan)


if __name__ == '__main__':
    sys.exit(main())

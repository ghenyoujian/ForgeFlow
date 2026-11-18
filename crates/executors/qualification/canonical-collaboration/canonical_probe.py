#!/usr/bin/env python3
"""Actual finite native v2 collaboration through an immutable API/Worker and PostgreSQL.

Creates an isolated database/server on 8793. Private original logs and credentials
remain mode0600. Published observations are producer evidence, pending root's
separate independent review; no business/production qualification is inferred.
"""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
import uuid
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'verification'))
sys.path.insert(0, str(ROOT / 'benchmarks'))
from algorithm_check import make_compile, refresh_digest, requirement_digest, vector
from control_load import Client
from live_control_adapter import api, git
from prepare import digest, private_write, save
from finite_re_evaluate import semantic_model_checks


def database(database_url, statement):
    parsed = urllib.parse.urlsplit(database_url)
    options = urllib.parse.parse_qs(parsed.query)
    psql = Path('/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/postgresql/16/bin/psql')
    env = {'PATH': '/usr/bin:/bin', 'PGHOST': options.get('host', [parsed.hostname or '127.0.0.1'])[0],
           'PGPORT': options.get('port', [str(parsed.port or 5432)])[0],
           'PGUSER': options.get('user', [urllib.parse.unquote(parsed.username or '')])[0],
           'PGPASSWORD': urllib.parse.unquote(parsed.password or ''), 'PGDATABASE': parsed.path.lstrip('/'),
           'LD_LIBRARY_PATH': str(psql.parents[3] / 'x86_64-linux-gnu')}
    process = subprocess.run([str(psql), '--no-psqlrc', '--no-password', '--tuples-only', '--no-align',
                              '--set', 'ON_ERROR_STOP=1', '--command', statement], env=env, capture_output=True, timeout=30)
    if process.returncode:
        raise RuntimeError('private PostgreSQL query failed; no credential diagnostics disclosed')
    return process.stdout


def query(database_url, sql):
    raw = database(database_url, sql).strip()
    return json.loads(raw) if raw else None


def wait_for(callback, timeout, description):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = callback()
        if value:
            return value
        time.sleep(.25)
    raise RuntimeError(description + ' timed out')


def group_processes(group):
    found = []
    for path in Path('/proc').glob('[0-9]*'):
        try:
            fields = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
            if int(fields[2]) == group and fields[0] not in {'Z', 'X'}:
                found.append(int(path.name))
        except (OSError, ValueError, IndexError):
            pass
    return found


def native_rows(database_url, attempt):
    # Attempt IDs are server-generated UUIDs; validate before SQL interpolation.
    uuid.UUID(attempt)
    tables = ('native_child_lifecycles', 'native_child_allocations', 'native_model_requests',
              'native_bridge_rpc', 'resource_allocations', 'leases', 'native_sessions')
    result = {}
    for table in tables:
        result[table] = query(database_url, f"SELECT COALESCE(json_agg(t),'[]'::json) FROM (SELECT * FROM {table} WHERE attempt_id='{attempt}') t")
    result['resource_limits'] = query(database_url, "SELECT COALESCE(json_agg(t),'[]'::json) FROM (SELECT * FROM resource_limits ORDER BY scope_id,dimension) t")
    return result


def verify_pins(profile):
    for pin in profile['artifact_pins']:
        if digest(pin['path']) != pin['sha256']:
            raise RuntimeError('prepared native input changed: ' + pin['path'])


def approved_checkpoint(path, source_authority='current-tree'):
    checkpoint = json.loads(path.read_text())
    if checkpoint.get('schema_version') != 'forgeflow.build-checkpoint.v1' or checkpoint.get('consistent_copy') is not True:
        raise RuntimeError('actual immutable build checkpoint required')
    commands = checkpoint.get('commands', [])
    if not commands or any(command.get('exit_code') != 0 for command in commands):
        raise RuntimeError('approved checkpoint still contains unfinished or failed build/check commands')
    if not any(command.get('argv', [])[:2] == ['cargo', 'build'] for command in commands):
        raise RuntimeError('approved checkpoint has no successful actual build command')
    snapshot = Path(checkpoint['snapshot_root'])
    for relative, frozen_sha256 in checkpoint['source_files'].items():
        if digest(snapshot / relative) != frozen_sha256:
            raise RuntimeError('immutable checkpoint source changed: ' + relative)
    current_ahead = []
    for relative in ('crates/store/src/collaboration.rs', 'migrations/0009_native_child_authority.sql',
                     'crates/store/src/lib.rs', 'crates/store/src/lifecycle.rs', 'crates/api/src/lib.rs',
                     'crates/api/src/auth.rs', 'crates/api/src/collaboration.rs', 'crates/worker/src/lib.rs',
                     'crates/worker/src/native_controller.rs'):
        if digest(ROOT / relative) != checkpoint.get('source_files', {}).get(relative):
            current_ahead.append(relative)
            if source_authority != 'checkpoint-snapshot':
                raise RuntimeError('current required native authority source differs from checkpoint: ' + relative)
    for name, binary in checkpoint.get('binaries', {}).items():
        if not binary.get('path') or digest(binary['path']) != binary.get('sha256'):
            raise RuntimeError('approved immutable binary changed: ' + name)
    checkpoint['actual_source_authority'] = source_authority
    checkpoint['current_source_ahead_paths'] = current_ahead
    return checkpoint


def redactor(managed, private):
    values = {private['FORGEFLOW_OWNER_TOKEN'], private['FORGEFLOW_WORKER_TOKEN']}
    def collect(value):
        if isinstance(value, dict):
            for nested in value.values(): collect(nested)
        elif isinstance(value, list):
            for nested in value: collect(nested)
        elif isinstance(value, str) and len(value) >= 16:
            values.add(value)
    collect(yaml.safe_load(Path(managed['credentials']).read_text()))
    def redact(data):
        for value in sorted(values, key=len, reverse=True):
            data = data.replace(value.encode(), b'[REDACTED_CREDENTIAL]')
        return data
    return redact


def observe_mode(mode, attempt, private, output, report):
    journal = Path(private['FORGEFLOW_DATA_ROOT']) / 'attempts' / attempt
    facts = native_rows(private['DATABASE_URL'], attempt)
    save(output / (mode + '.postgres.json'), facts)
    for name in ('envelope.json', 'execution-bindings.json', 'launch-receipt.json', 'stop.json',
                 'result.json', 'result-ack.json', 'sandbox.json', 'native-controller.json',
                 'managed-native-config.json', 'managed-native.patch.json', 'stdout.ndjson', 'stderr.log',
                 'cgroup-fence.json', 'cgroup-stop.json', 'cgroup-membership.json'):
        path = journal / name
        if path.exists():
            (output / (mode + '.' + name)).write_bytes(report['_redact'](path.read_bytes()))
    lifecycles = facts['native_child_lifecycles']
    models = facts['native_model_requests']
    stop = json.loads((journal / 'stop.json').read_text())
    launch = json.loads((journal / 'launch-receipt.json').read_text())
    result = json.loads((journal / 'result.json').read_text())
    observations = [row['request'] for row in facts['native_bridge_rpc'] if row['operation'] == 'observe']
    expected = ('ONE_SHOT_RECEIPT', 'WORKFLOW_RECEIPT', 'TEAM_RECEIPT', 'TEAM_RESUME_RECEIPT')
    expected_hashes = {value: hashlib.sha256(value.encode()).hexdigest() for value in expected}
    observed_hashes = {row.get('value', {}).get('assistant_text_sha256') for row in observations}
    checks = []
    def check(name, condition, details=None):
        checks.append({'name': name, 'status': 'PASS' if condition else 'FAIL', 'facts': details})
    check('real_managed_native_worker', result['evidence'].get('real_dsh') is True and result['evidence'].get('executor_kind') == 'DSH_MANAGED')
    check('strong_sandbox_launch', launch['command_program'] == '/usr/bin/bwrap' and '--unshare-pid' in launch['command_args'])
    check('supported_patch_arguments_before_json', '--patch' in launch['command_args'] and launch['command_args'].index('--patch') < launch['command_args'].index('--json'))
    check('positive_worker_process_stop', stop['process_exit_confirmed'] is True and not group_processes(launch['process']['pid']), {'exit_code': stop['exit_code'], 'stop_reason': stop['reason']})
    check('actual_canonical_rpc_and_root_binding', bool(facts['native_bridge_rpc']) and len(facts['native_sessions']) == 1 and any(row['borrowed_parent_reservation'] for row in lifecycles))
    check('v2_uuid_requests', all(row['request']['schema_version'] == 'forgeflow.dsh-bridge.v2' and str(uuid.UUID(row['request']['rpc_id'])) == row['request']['rpc_id'] for row in facts['native_bridge_rpc']))
    bindings = json.loads((journal / 'execution-bindings.json').read_text())
    pool = bindings.get('physical_resources')
    if pool:
        fence = json.loads((journal / 'cgroup-fence.json').read_text())
        physical_stop = json.loads((journal / 'cgroup-stop.json').read_text())
        membership = json.loads((journal / 'cgroup-membership.json').read_text())
        check('physical_pool_positive_fenced_empty_stop', pool['physical_limits']['required'] is True
              and fence['resource_binding_sha256'] == pool['reservation_sha256']
              and physical_stop['identity_sha256'] == membership['identity_sha256'] == fence['identity_sha256']
              and physical_stop['process_exit_confirmed'] is True and physical_stop['populated'] is False
              and not physical_stop['snapshot']['cgroup.procs'].strip()
              and membership['pid'] == launch['process']['pid'])
        admits = [row for row in facts['native_bridge_rpc'] if row['operation'] == 'admit']
        allocations = facts['resource_allocations']
        expected = {key: amount for key, amount in pool['reserved_resources'].items() if amount > 0}
        scope_ids = {row['scope_id'] for row in allocations}
        loans = all(len([rpc for rpc in admits if rpc['response'].get('allocation_id') == child['allocation_id']
              and rpc['response'].get('resource_accounting') == 'UPFRONT_NATIVE_POOL'
              and rpc['response'].get('physical_reservation_sha256') == pool['reservation_sha256']
              and rpc['response'].get('borrowed_resources') == (pool['root_resources'] if child['borrowed_parent_reservation'] else pool['native_child_resources'])
              and rpc['request'].get('native_session_id') == child['native_session_id']]) == 1 for child in lifecycles)
        check('physical_pool_loans_no_second_charge', pool['accounting_mode'] == 'UPFRONT_NATIVE_POOL'
              and bool(lifecycles) and loans and not facts['native_child_allocations'])
        check('physical_whole_pool_reserved_every_scope', scope_ids == {'global', 'project', 'worker', 'root-team', 'leaf-team'}
              and all({row['dimension']: row['amount'] for row in allocations if row['scope_id'] == scope} == expected for scope in scope_ids))
        check('native_resources_closed_after_positive_stop', bool(lifecycles) and all(row['state'] == 'RELEASED' for row in lifecycles)
              and not facts['native_child_allocations'])
    else:
        check('child_resources_charged_all_required_scopes', bool(facts['native_child_allocations']) and {row['scope_id'] for row in facts['native_child_allocations']} == {'global', 'project', 'worker', 'root-team', 'leaf-team'})
        check('native_resources_closed_after_positive_stop', bool(lifecycles) and all(row['state'] == 'RELEASED' for row in lifecycles) and all(row['state'] == 'RELEASED' for row in facts['native_child_allocations']))
    check('model_budget_rows_admitted_and_settled', bool(models) and all(row['status'] == 'SETTLED' and row['usage_complete'] and row['usage'] is not None for row in models))
    check('unknown_cost_preserved', bool(models) and all(row['cost_status'] == 'UNKNOWN' for row in models))
    if mode == 'finite':
        check('finite_lifecycle_denominator', len(lifecycles) == 5 and len({row['native_session_id'] for row in lifecycles}) == 4, {'lifecycles': len(lifecycles), 'agents': len({row['native_session_id'] for row in lifecycles})})
        check('actual_team_cold_resume', sum(row['source'] == 'resume' for row in lifecycles) == 1)
        semantic, identity_mapping = semantic_model_checks(facts, json.loads((journal / 'envelope.json').read_text()))
        checks.extend(row for row in semantic if not pool or row['name'] != 'native_lifecycles_and_child_resources_released')
        report['finite_model_identity_mapping'] = identity_mapping
        check('four_exact_native_output_oracles', all(value in observed_hashes for value in expected_hashes.values()), {'expected_sha256': expected_hashes})
        check('native_finite_exit_zero', stop['exit_code'] == 0)
    else:
        check('actual_cancel_after_wait_tool', report.get('cancel_trigger', {}).get('native_wait_observed') is True)
        check('no_admitted_model_after_cancel', not any(row['status'] in {'ADMITTED', 'QUARANTINED'} for row in models))
        check('parent_cancel_resources_closed', bool(facts['resource_allocations']) and all(row['state'] == 'RELEASED' for row in facts['resource_allocations']))
        cutoff = report.get('cancel_trigger', {}).get('canonical_cancel_requested_at')
        check('no_new_model_grants_after_revoke', bool(cutoff) and all(datetime.fromisoformat(row['admitted_at'].replace('Z', '+00:00')) <= datetime.fromisoformat(cutoff.replace('Z', '+00:00')) for row in models))
    receipt = {'schema_version': 'forgeflow.canonical-native-collaboration-probe.v2', 'mode': mode,
               'authority': 'CANONICAL_POSTGRESQL', 'project_id': report['project_id'], 'attempt_id': attempt,
               'checks': checks, 'assertions': len(checks), 'failed': sum(row['status'] == 'FAIL' for row in checks),
               'native_lifecycles': len(lifecycles), 'distinct_native_agents': len({row['native_session_id'] for row in lifecycles}),
               'model_requests': len(models), 'positive_worker_stop': stop['process_exit_confirmed'],
               'oracle_independence': 'PRODUCER_OBSERVATIONS_PENDING_ASSIGNED_INDEPENDENT_REVIEW',
               'native_process_stop': stop, 'build_receipt_sha256': report['build_receipt_sha256'],
               'profile_sha256': report['profile_sha256'], 'doctor_sha256': report['doctor_sha256'],
               'private_original_journal': str(journal), 'production_admission': 'BLOCKED_PENDING_MANAGED_CHILD_ACCOUNTING',
               'not_proven': report['not_proven']}
    receipt['status'] = 'FAIL' if receipt['failed'] else 'PASS_PRODUCER_FINITE_SCOPE'
    save(output / (mode + '.receipt.json'), receipt)
    return receipt


def run(args):
    modes = tuple(args.modes.split(','))
    if args.private_env.stat().st_mode & 0o077:
        raise RuntimeError('runtime credential config must have private 0600 permissions')
    with socket.socket() as probe:
        probe.settimeout(.2)
        if probe.connect_ex(('127.0.0.1', 8793)) == 0:
            raise RuntimeError('port8793 has a live authority; refuse duplicate/shared run')
    checkpoint = approved_checkpoint(args.build_receipt, args.source_authority)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError('preserve earlier evidence: use a new output directory')
    (output / 'build.receipt.json').write_bytes(args.build_receipt.read_bytes())
    for source in (Path(__file__), HERE / 'prepare.py', HERE / 'finite_re_evaluate.py', HERE / 'probe-plugin.mjs', HERE / 'artifact_oracle.py',
                   HERE.parents[1] / 'presets/forgeflow/managed-bridge.mjs', HERE.parents[1] / 'presets/forgeflow/mode.json'):
        (output / ('source-' + source.name)).write_bytes(source.read_bytes())
    profile = json.loads((args.prepared_root / 'headless-profile.json').read_text())
    managed = json.loads((args.prepared_root / 'managed-config.json').read_text())
    verify_pins(profile)
    private_root = Path('/tmp') / ('ff-canon-' + uuid.uuid4().hex[:8])
    private_root.mkdir(mode=0o700)
    state = private_root / 's'
    state.mkdir(mode=0o700)
    source_private = json.loads(args.private_env.read_text())
    database_name = 'ff_canonical_' + uuid.uuid4().hex[:16]
    database(source_private['DATABASE_URL'], 'CREATE DATABASE "' + database_name + '"')
    parsed = urllib.parse.urlsplit(source_private['DATABASE_URL'])
    private = {'DATABASE_URL': urllib.parse.urlunsplit(parsed._replace(path='/' + database_name)),
               'FORGEFLOW_BIND': '127.0.0.1:8793', 'FORGEFLOW_DATA_ROOT': str(state),
               'FORGEFLOW_OWNER_TOKEN': secrets.token_hex(32), 'FORGEFLOW_WORKER_TOKEN': secrets.token_hex(32),
               'FORGEFLOW_CONSOLE_DIR': str(ROOT / 'console/dist'), 'RUST_LOG': 'info'}
    save(private_root / 'runtime-env.json', private, private=True)
    report = {'schema_version': 'forgeflow.canonical-native-collaboration-run.v2', 'at': datetime.now(timezone.utc).isoformat(),
              'authority': 'CANONICAL_POSTGRESQL', 'private_root': str(private_root), 'database_name': database_name,
              'build_receipt_sha256': digest(args.build_receipt), 'binaries': checkpoint['binaries'],
              'source_identity': checkpoint['source_identity'],
              'actual_source_authority': checkpoint['actual_source_authority'], 'current_source_ahead_paths': checkpoint['current_source_ahead_paths'],
              'build_verification_scope': checkpoint.get('qualification'), 'postgres_verification': checkpoint.get('postgres_verification'),
              'profile_sha256': digest(args.prepared_root / 'headless-profile.json'), 'doctor_sha256': digest(managed['doctor']),
              'source_artifacts': {str(path.relative_to(ROOT)): digest(path) for path in (Path(__file__), HERE / 'prepare.py', HERE / 'probe-plugin.mjs', HERE / 'artifact_oracle.py')},
              'errors': [], 'attempts': {}, 'receipts': {}, 'shutdown': {},
              'not_proven': ['100+ real sessions', 'fork/remote provider workload', 'full OS/model egress', 'complete financial accounting', 'business acceptance or production gate']}
    report['_redact'] = redactor(managed, private)
    server = worker = None
    try:
        server_log = (private_root / 'server.log').open('wb')
        server = subprocess.Popen([checkpoint['binaries']['forgeflow-server']['path']], env={'PATH': '/usr/bin:/bin', **private}, stdout=server_log, stderr=subprocess.STDOUT)
        client = Client('http://127.0.0.1:8793', private['FORGEFLOW_OWNER_TOKEN'], output)
        def healthy():
            if server.poll() is not None:
                raise RuntimeError('isolated server exited before readiness')
            try: return client.request('GET', '/api/v1/me')[0] == 200
            except RuntimeError: return False
        wait_for(healthy, 40, 'isolated canonical API readiness')
        seed = private_root / 'seed'
        seed.mkdir()
        git(seed, 'init', '--initial-branch=main')
        (seed / 'baseline.txt').write_text('Finite native collaboration read-only fixture.\n')
        git(seed, 'add', '--all')
        git(seed, '-c', 'user.name=Canonical qualification', '-c', 'user.email=qualification@localhost', 'commit', '-m', 'Private canonical native baseline')
        base = git(seed, 'rev-parse', 'HEAD')
        project = 'canonical-native-' + uuid.uuid4().hex[:12]
        worker_id = 'canonical-worker-' + uuid.uuid4().hex[:12]
        report.update(project_id=project, worker_id=worker_id)
        created = api(client, 'POST', '/projects', {'project_id': project, 'name': 'Canonical finite native collaboration', 'root_path': str(seed), 'authority_mode': 'MANAGED', 'data_origin': 'NATIVE', 'goal': 'Finite workflow/team/subagent/resume/cancel with canonical grants', 'technology_stack': ['Actual installed native DSH'], 'timezone': 'Asia/Shanghai', 'paused': False, 'archived': False, 'revision': 0})['data']
        canonical = Path(created['root_path'])
        for team, parent in (('root', None), ('leaf', 'root')):
            api(client, 'POST', f'/projects/{project}/teams', {'project_id': project, 'team_id': team, 'parent_team_id': parent, 'name': team, 'paused': False, 'revision': 0})
        api(client, 'POST', f'/projects/{project}/owners', {'id': 'root', 'value': {'owner_id': 'root', 'root_team_id': 'root', 'include': ['baseline.txt'], 'exclude': []}})
        requirement = api(client, 'POST', f'/projects/{project}/requirements', {'project_id': project, 'requirement_id': 'R01', 'title': 'Actual canonical collaboration', 'source_anchor': 'canonical-native#R01', 'outcome': 'Actual finite native children, model reservations and positive Worker stop', 'scope': 'One root, finite in-process children, one Team cold resume and settled-tool cancellation', 'acceptance': ['native outputs match exact receipts and PostgreSQL lineage/budgets match actual Worker process'], 'priority': 1, 'weight': 1, 'deferred_reason': None, 'revision': 0})['data']
        readonly = [str(path) for path in map(Path, ('/usr', '/bin', '/lib', '/lib64', '/etc/resolv.conf', '/etc/hosts', '/etc/nsswitch.conf', '/etc/ssl/certs')) if path.exists()]
        readonly += [str(Path(profile['prefix_args'][0]).parents[3]), str(HERE / 'probe-plugin.mjs'), str(HERE / 'artifact_oracle.py')]
        frozen_bundle = Path(managed['mode_manifest']).parent
        native_sandbox = json.loads(Path(managed['doctor']).read_text()).get('native_sandbox')
        if native_sandbox:
            readonly += [str(frozen_bundle), native_sandbox['launcher_path'], native_sandbox['ioctl_guard_path']]
        sandbox = {'bwrap_program': '/usr/bin/bwrap', 'bwrap_sha256': digest('/usr/bin/bwrap'), 'guard_program': checkpoint['binaries']['forgeflow-sandbox-guard']['path'], 'guard_sha256': checkpoint['binaries']['forgeflow-sandbox-guard']['sha256'], 'readonly_paths': readonly, 'network_allowed': True}
        config = {'control_url': client.base_url, 'worker_id': worker_id, 'project_id': project, 'data_root': str(state), 'profile': profile, 'model_route_id': profile['model_route_id'], 'secret_files': {}, 'poll_seconds': 1, 'max_log_bytes': 8 * 1024 * 1024, 'max_active_attempts': 1, 'sandbox': sandbox, 'managed_dsh': managed}
        config_path = private_root / 'worker-config.json'
        save(config_path, config, private=True)
        save(output / 'worker-config.json', config)
        worker_log = (private_root / 'worker.log').open('wb')
        worker = subprocess.Popen([checkpoint['binaries']['forgeflow-worker']['path'], '--config', str(config_path)], env={'PATH': '/usr/bin:/bin', 'RUST_LOG': 'info', 'FORGEFLOW_WORKER_TOKEN': private['FORGEFLOW_WORKER_TOKEN']}, stdout=worker_log, stderr=subprocess.STDOUT)
        def registered():
            if worker.poll() is not None:
                raise RuntimeError('actual managed Worker exited before registration')
            return query(private['DATABASE_URL'], f"SELECT json_build_object('worker_id',worker_id,'project_id',project_id,'executor_profile_ids',executor_profile_ids) FROM workers WHERE worker_id='{worker_id}' AND project_id='{project}'")
        save(output / 'actual-worker-registration.json', wait_for(registered, 40, 'actual Worker registration'))
        limits = {**vector(8), 'cpu_units': 8, 'memory_bytes': 1024 * 1024 * 1024, 'provider_inflight': 8}
        for scope, scope_project, scope_team, scope_worker in (('global', None, None, None), ('project', project, None, None), ('worker', None, None, worker_id), ('root-team', project, 'root', None), ('leaf-team', project, 'leaf', None)):
            api(client, 'POST', '/resource-policies', {'policy': {'scope_id': scope, 'parent_scope_id': 'root-team' if scope == 'leaf-team' else None, 'project_id': scope_project, 'team_id': scope_team, 'worker_id': scope_worker, 'limits': limits, 'revision': 0, 'paused': False}})
        child_resources = {**vector(1), 'cpu_units': 1, 'memory_bytes': 64 * 1024 * 1024, 'provider_inflight': 1}
        child_policy = {'schema_version': 'forgeflow.native-child-policy.v1', 'enabled': True, 'max_live_agents': 4, 'max_lifecycles': 5, 'max_delegation_depth': 2, 'model_inflight_limit': 4, 'child_resources': child_resources}
        for collection, identity, value in (('executor_profiles', profile['id'], {**profile, 'kind': 'DSH_MANAGED', 'native_mode': managed}), ('resource_profiles', 'canonical-native.v2', {'id': 'canonical-native.v2', 'stage_resource_mode': 'ATTEMPT_RESERVATION', 'isolation_profile': 'BWRAP_LANDLOCK_EXACT', 'sandbox': sandbox, 'native_child_policy': child_policy}), ('model_routes', profile['model_route_id'], {'id': profile['model_route_id'], 'provider': 'newapi', 'model': 'glm-5.3', 'max_output_tokens': 4096})):
            api(client, 'POST', f'/projects/{project}/documents/{collection}', {'id': identity, 'value': value})
        manifest_text = json.dumps({'files': [], 'mandatory_paths': [], 'artifact_inputs': []}, separators=(',', ':'))
        manifest = api(client, 'POST', f'/projects/{project}/artifacts', {'content_utf8': manifest_text, 'kind': 'CONTEXT_MANIFEST'})['data']
        case = make_compile(len(modes))
        case['flow']['project_id'] = project
        meaning = requirement_digest(requirement)
        case['context'].update(owners=[{'owner_id': 'root', 'root_team_id': 'root', 'include': ['baseline.txt'], 'exclude': []}], current_inputs={}, requirement_semantic_digests={'R01': meaning}, requirements=[{'requirement_id': 'R01', 'source_document': 'canonical-native', 'anchor': 'R01', 'acceptance': '\n'.join(requirement['acceptance']), 'priority': 1, 'deferred_reason': None}])
        for mode, task in zip(modes, case['flow']['tasks']):
            prompt_text = f'Explicit qualification request: use workflow, Agent Teams, and subagents. Call only forgeflow_collaboration_probe with mode "{mode}" exactly once, wait for its result, then report the result including all exact receipt labels. Do not call any other tools, modify files, or delegate outside that probe.'
            prompt = api(client, 'POST', f'/projects/{project}/artifacts', {'content_utf8': prompt_text, 'kind': 'PROMPT'})['data']
            now = datetime.now(timezone.utc)
            plan_id = 'canonical-plan-' + mode
            task.update(project_id=project, owner_id='root', team_id='leaf', read_set=[], write_set=[], dependencies=[], resource_request=child_resources)
            spec = case['context']['task_specs'][task['task_id']]
            spec.update(inputs=[], mandatory_paths=[], dependency_refs=[], design_anchors=['canonical-native#R01'], requirement_digest_refs={'R01': meaning}, execution_profile=profile['id'], verification_plan=plan_id, verification_case_count=6, not_proven=['business verification not executed by this native workload probe'])
            task['envelope'] = {'schema_version': 'forgeflow.execution.v1', 'operation_id': 'pending-' + mode, 'project_id': project, 'task_id': task['task_id'], 'task_revision': 1, 'attempt_id': 'pending-' + mode, 'lease_id': 'pending-' + mode, 'generation': 1, 'worker_id': worker_id, 'workspace_root': str(canonical), 'base_sha': base,
                'context_manifest': {'artifact_id': manifest['artifact_id'], 'sha256': manifest['sha256'], 'mandatory_paths': [], 'rendered_utf8_bytes': len(manifest_text.encode()), 'token_estimate': None, 'tokenizer_id': None}, 'write_set': [], 'prompt_artifact': {'artifact_id': prompt['artifact_id'], 'sha256': prompt['sha256']}, 'model_route_id': profile['model_route_id'], 'executor_profile_id': profile['id'], 'resource_profile_id': 'canonical-native.v2', 'verification_plan_id': plan_id,
                'allowed_effects': ['READ_WORKSPACE', 'REQUEST_APPROVED_MODEL', 'RUN_APPROVED_COMMANDS'], 'issued_at': now.isoformat(), 'expires_at': (now + timedelta(seconds=120)).isoformat(), 'deadline_at': (now + timedelta(minutes=8)).isoformat(), 'artifact_prefix': str(state / 'artifacts'), 'secret_refs': [], 'idempotency_key': 'pending-' + mode, 'trace_id': 'canonical-' + mode,
                'enforcement': {'model_budget_mode': 'direct_observed', 'stage_resource_mode': 'ATTEMPT_RESERVATION', 'build_capable': False, 'gateway_coverage_receipt_id': None, 'tool_guard_receipt_id': None, 'attempt_reserved_build_permits': 0, 'all_model_routes_covered': False, 'disabled_tool_entry_ids': []}, 'session_purpose': 'REVIEW', 'max_model_requests': 8, 'resume_session_id': None, 'command': None}
            refresh_digest(task, spec)
            oracle = frozen_bundle / 'artifact_oracle.py' if (frozen_bundle / 'artifact_oracle.py').is_file() else HERE / 'artifact_oracle.py'
            commands = [{'role': role, 'program': '/usr/bin/python3', 'args': ['-I', '-B', str(oracle)], 'env': {}, 'executable_hash': digest('/usr/bin/python3'), 'bound_inputs': [{'path': str(oracle), 'sha256': digest(oracle)}], 'report_path': role + '.json', 'expected_cases': [{'name': 'finite_receipt_labels', 'kind': 'positive'}, {'name': 'empty_receipt_rejected', 'kind': 'negative'}], 'timeout_seconds': 20} for role in ('author', 'consumer', 'independent')]
            api(client, 'POST', f'/projects/{project}/documents/verification_plans', {'id': plan_id, 'value': {'plan_id': plan_id, 'task_revision': 1, 'contract_version': 'canonical-native.v2', 'input_hash': task['input_digest'], 'environment_profile': 'canonical-native.v2', 'oracle_id': 'canonical-finite-artifact.v1', 'verifier_id': 'registered-unexecuted-independent-artifact-oracle', 'author_id': worker_id, 'commands': commands}})
        saved = api(client, 'POST', f'/projects/{project}/flow-revisions', {'flow': case['flow'], 'context': case['context']})['data']
        committed = api(client, 'POST', f'/flows/{project}:1/commit', {'expected_revision': saved['revision']})['data']
        for mode, task in zip(modes, committed['tasks']):
            admitted = api(client, 'POST', f'/projects/{project}/admissions', {'actor_id': 'overwritten', 'idempotency_key': 'overwritten', 'project_id': project, 'task_id': task['task_id'], 'task_revision': task['task_revision'], 'flow_revision': task['flow_revision'], 'policy_revision': 1, 'input_digest': task['input_digest'], 'worker_id': worker_id, 'lease_seconds': 120, 'envelope': task['envelope']})['data']
            attempt = admitted['attempt']['attempt_id']
            report['attempts'][mode] = attempt
            journal = state / 'attempts' / attempt
            if mode == 'cancel':
                def waiting():
                    facts = native_rows(private['DATABASE_URL'], attempt)
                    requests = facts['native_model_requests']
                    waiting_tools = [row for row in facts['native_bridge_rpc'] if row['operation'] == 'observe' and row['request'].get('event') == 'tool/call' and row['request'].get('value', {}).get('name') == 'forgeflow_native_wait']
                    if requests and waiting_tools and all(row['status'] == 'SETTLED' for row in requests):
                        return facts
                    if (journal / 'stop.json').exists():
                        raise RuntimeError('native cancel workload stopped before finite wait trigger')
                    return None
                trigger = wait_for(waiting, 150, 'actual child finite wait after model settlement')
                save(output / 'cancel.before-revoke.postgres.json', trigger)
                current = api(client, 'GET', f'/attempts/{attempt}?project_id={project}')['data']
                api(client, 'POST', f'/attempts/{attempt}/cancel', {'project_id': project, 'expected_revision': current['revision'], 'reason': 'finite actual native child tool-wait cancellation'})
                report['cancel_trigger'] = {'native_wait_observed': True, 'settled_model_requests': len(trigger['native_model_requests']), 'canonical_cancel_requested_at': query(private['DATABASE_URL'], f"SELECT to_json(revoked_at) FROM leases WHERE attempt_id='{attempt}'")}
            def acknowledged():
                if worker.poll() is not None:
                    raise RuntimeError('managed Worker exited before native result acknowledgement')
                if (journal / 'result-ack.json').exists():
                    return True
                return False
            wait_for(acknowledged, 210, 'actual native Worker stop and canonical result acknowledgement')
            receipt = observe_mode(mode, attempt, private, output, report)
            report['receipts'][mode] = receipt
            if receipt['failed']:
                raise RuntimeError(mode + ' actual native producer observations failed')
            if mode == 'finite':
                # This probe does not run business verification. Its held parent
                # reservation is then closed by an explicit controller cleanup cancel.
                current = api(client, 'GET', f'/attempts/{attempt}?project_id={project}')['data']
                api(client, 'POST', f'/attempts/{attempt}/cancel', {'project_id': project, 'expected_revision': current['revision'], 'reason': 'finite qualification complete; explicit cleanup without business acceptance'})
                wait_for(lambda: api(client, 'GET', f'/attempts/{attempt}?project_id={project}')['data']['state'] == 'CANCELLED', 40, 'finite cleanup parent cancellation')
                save(output / 'finite.after-cleanup.postgres.json', native_rows(private['DATABASE_URL'], attempt))
    except Exception as error:
        report['errors'].append({'type': type(error).__name__, 'message': str(error)})
    finally:
        for name, process in (('worker', worker), ('server', server)):
            if process is None:
                continue
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try: process.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
                    report['errors'].append(name + ' required forced shutdown')
            report['shutdown'][name] = {'pid': process.pid, 'exit_code': process.returncode, 'process_exit_confirmed': process.poll() is not None}
            source = private_root / (name + '.log')
            if source.exists():
                (output / (name + '.log')).write_bytes(report['_redact'](source.read_bytes()))
        report.pop('_redact')
        report['status'] = 'FAIL' if report['errors'] else 'PASS_PRODUCER_FINITE_SCOPE'
        report['evidence_sha256'] = {path.name: digest(path) for path in output.iterdir() if path.is_file()}
        save(output / 'report.json', report)
        print(json.dumps({'status': report['status'], 'errors': report['errors'], 'attempts': report['attempts'], 'private_root': str(private_root), 'output': str(output)}))
    return 1 if report['errors'] else 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build-receipt', 'prepared-root', 'private-env', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--modes', choices=('finite,cancel', 'finite', 'cancel'), default='finite,cancel')
    parser.add_argument('--source-authority', choices=('current-tree', 'checkpoint-snapshot'), default='current-tree')
    raise SystemExit(run(parser.parse_args()))

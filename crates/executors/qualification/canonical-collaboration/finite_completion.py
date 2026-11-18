#!/usr/bin/env python3
"""One explicitly authorized finite native REVIEW task, with real artifact acceptance.

Default mode only prepares the correction plan; --run requires the frozen
7-request budget acknowledgement and a fresh output. Historical FAIL stays
immutable. No author replay, production capacity claim or invented Git receipt.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import urllib.parse
import time
import uuid
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
from canonical_probe import (approved_checkpoint, database, query, wait_for,
    native_rows, verify_pins, redactor, observe_mode, Client, api, git,
    make_compile, refresh_digest, requirement_digest, vector)
from prepare import digest, save

ORIGINAL = HERE / 'actual-7ea2d80547f69511-r2'


PHYSICAL_LIMITS = {'schema_version': 'forgeflow.physical-limits.v1', 'required': True,
    'cpu_units_per_cpu': 1000, 'period_us': 100000, 'pids_max': 256,
    'swap_max_bytes': 0, 'memory_oom_group': True}


class DelegatedWorker:
    """Only this freshly pinned private unit is controlled; no shared cgroup write."""
    def __init__(self, binary, config, private_root, private):
        self.root = private_root / 'delegated-worker'
        token = private_root / 'worker-env.json'
        save(token, {'FORGEFLOW_WORKER_TOKEN': private['FORGEFLOW_WORKER_TOKEN'], 'RUST_LOG': 'info'}, private=True)
        launcher = ROOT / 'ops/run-delegated-worker.py'
        def launch(arguments):
            process = subprocess.run([str(Path(sys.executable).resolve()), str(launcher), *arguments],
                                     capture_output=True, timeout=30)
            if process.returncode:
                raise RuntimeError('Pinned dedicated Worker launcher refused; no secret diagnostics exposed')
            return json.loads(process.stdout)
        plan = launch(['prepare', '--kind', 'worker', '--program', binary['path'], '--program-sha256', binary['sha256'],
                       '--config', str(config), '--env-file', str(token), '--output', str(self.root)])
        self.unit = plan['unit_name']
        launch(['start', '--plan', str(self.root / 'launch-plan.json'), '--plan-sha256', plan['plan_sha256'],
                '--unit-sha256', plan['unit_sha256'], '--execute'])
        self.pid = int(self.properties()['MainPID'])
        self.returncode = None
    def ctl(self, *args):
        process = subprocess.run(['systemctl', '--user', *args], capture_output=True, timeout=15)
        if process.returncode:
            raise RuntimeError('Owned dedicated Worker systemd operation failed')
        return process.stdout
    def properties(self):
        return dict(line.split('=', 1) for line in self.ctl('show', self.unit, '--property=MainPID',
            '--property=ActiveState', '--property=ExecMainStatus').decode().splitlines())
    def poll(self):
        properties = self.properties()
        if properties['ActiveState'] in ('active', 'activating') and int(properties['MainPID']) > 0:
            return None
        self.returncode = int(properties['ExecMainStatus'])
        return self.returncode
    def send_signal(self, sig):
        self.ctl('kill', '--kill-whom=main', '--signal=' + signal.Signals(sig).name, self.unit)
    def wait(self, timeout):
        deadline = time.monotonic() + timeout
        while self.poll() is None:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired('owned private Worker', timeout)
            time.sleep(.25)
        return self.returncode
    def kill(self):
        self.ctl('kill', '--kill-whom=all', '--signal=SIGKILL', self.unit)
    def retain_log(self, target):
        process = subprocess.run(['journalctl', '--user', '-u', self.unit, '--no-pager', '-o', 'cat'],
                                 capture_output=True, timeout=15)
        target.write_bytes(process.stdout)
    def cleanup(self):
        if self.poll() is None:
            return {'status': 'RETAINED_PRIVATE_UNIT_WORKER_STILL_LIVE'}
        plan = json.loads((self.root / 'launch-plan.json').read_text())
        self.ctl('stop', self.unit, plan['slice_name'])
        link = Path.home() / '.config/systemd/user' / self.unit
        if not link.is_symlink() or link.resolve() != self.root / self.unit:
            raise RuntimeError('Owned dedicated unit symlink changed; no unlink performed')
        link.unlink()
        self.ctl('daemon-reload')
        return {'status': 'OWNED_UNIT_AND_SLICE_STOPPED_AND_UNLINKED', 'unit_name': self.unit}


def parent_closure(attempt, facts, receipts, operation, state, output, redact, canonical, base):
    checks = []
    def check(name, condition, actual=None):
        checks.append({'name': name, 'status': 'PASS' if condition else 'FAIL', 'facts': actual})
    check('canonical_parent_SUCCEEDED', attempt['state'] == 'SUCCEEDED' and bool(attempt['terminal_at']),
          {'state': attempt['state'], 'generation': attempt['generation']})
    check('all_parent_allocations_released', bool(facts['resource_allocations']) and
          all(row['state'] == 'RELEASED' for row in facts['resource_allocations']))
    check('lease_released', bool(facts['leases']) and all(row['revoked_at'] for row in facts['leases']))
    check('native_lifecycle_resources_released', bool(facts['native_child_lifecycles']) and
          all(row['state'] == 'RELEASED' for row in facts['native_child_lifecycles']) and
          not facts['native_child_allocations'])
    check('every_actual_model_request_settled_with_usage', bool(facts['native_model_requests']) and
          len(facts['native_model_requests']) <= 7 and all(row['status'] == 'SETTLED' and row['usage_complete']
          and row['usage'] is not None for row in facts['native_model_requests']), len(facts['native_model_requests']))
    check('unknown_cost_not_fabricated', all(row['cost_status'] == 'UNKNOWN' for row in facts['native_model_requests']))
    check('independent_artifact_six_executed_cases', len(receipts) == 1 and all(row['kind'] == 'STRUCTURED_ARTIFACT'
          and row['total'] == 6 and row['failed'] == row['skipped'] == 0 and row['candidate_sha'] is None
          and row['integrated_sha'] is None and row['details']['independent'] is True
          and row['verifier_id'] != row['author_id'] for row in receipts))
    retained = []
    for receipt in receipts:
        details = receipt['details']
        path = state / 'artifacts' / operation['operation_id'] / details['log_path']
        matching = [path] if path.is_file() and digest(path) == details['log_hash'] else []
        check('actual_raw_verification_log:' + receipt['receipt_id'], len(matching) == 1)
        if len(matching) == 1:
            raw = matching[0].read_bytes()
            target = output / (receipt['receipt_id'] + '.raw-verification-log.bin')
            target.write_bytes(redact(raw))
            retained.append({'receipt_id': receipt['receipt_id'], 'original_sha256': details['log_hash'],
                             'published_sha256': digest(target), 'bytes': len(raw)})
    expected_refs = 'refs/heads/main ' + base
    canonical_refs = git(canonical, 'for-each-ref', '--format=%(refname) %(objectname)')
    bare = git(canonical, 'rev-parse', '--is-bare-repository') == 'true'
    seed = state.parent / 'seed'
    seed_refs = git(seed, 'for-each-ref', '--format=%(refname) %(objectname)')
    seed_clean = not git(seed, 'status', '--porcelain')
    original_seed = git(seed, 'rev-parse', 'HEAD') == base and seed_refs == expected_refs and seed_clean
    original_seed = original_seed and (seed / 'baseline.txt').read_bytes() == b'Finite native collaboration read-only fixture.\n'
    check('read_only_canonical_repository_unchanged', git(canonical, 'rev-parse', 'HEAD') == base
          and canonical_refs == seed_refs == expected_refs and original_seed
          and (bare or not git(canonical, 'status', '--porcelain')),
          {'base_sha': base, 'canonical_is_bare': bare, 'all_canonical_refs': canonical_refs,
           'expected_refs': expected_refs, 'original_seed_clean': seed_clean,
           'method': 'Complete refs and frozen baseline identity with original single-main-branch clean seed; bare repositories have no worktree status'})
    return {'checks': checks, 'failed': sum(row['status'] == 'FAIL' for row in checks),
            'actual_model_requests': len(facts['native_model_requests']), 'frozen_request_cap': 7,
            'verification_raw_logs': retained,
            'delivery_kind': 'READ_ONLY_ARTIFACT', 'code_integration_claimed': False}


def run(args):
    modes = ('finite',)
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
    for source in (Path(__file__), HERE / 'prepare.py', HERE / 'finite_re_evaluate.py', HERE / 'canonical_probe.py', HERE / 'probe-plugin.mjs', HERE / 'artifact_oracle.py',
                   HERE.parents[1] / 'presets/forgeflow/managed-bridge.mjs', HERE.parents[1] / 'presets/forgeflow/mode.json'):
        (output / ('source-' + source.name)).write_bytes(source.read_bytes())
    profile = json.loads((args.prepared_root / 'headless-profile.json').read_text())
    managed = json.loads((args.prepared_root / 'managed-config.json').read_text())
    # Supported finite transport allowance, frozen into actual Worker config.
    # This does not assert the historical failure was a timeout.
    managed['rpc_timeout_ms'] = 5000
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
    report = {'schema_version': 'forgeflow.native-finite-completion.v1', 'at': datetime.now(timezone.utc).isoformat(),
              'authority': 'CANONICAL_POSTGRESQL', 'private_root': str(private_root), 'database_name': database_name,
              'build_receipt_sha256': digest(args.build_receipt), 'binaries': checkpoint['binaries'],
              'source_identity': checkpoint['source_identity'],
              'actual_source_authority': checkpoint['actual_source_authority'], 'current_source_ahead_paths': checkpoint['current_source_ahead_paths'],
              'build_verification_scope': checkpoint.get('qualification'), 'postgres_verification': checkpoint.get('postgres_verification'),
              'profile_sha256': digest(args.prepared_root / 'headless-profile.json'), 'doctor_sha256': digest(managed['doctor']),
              'source_artifacts': {str(path.relative_to(ROOT)): digest(path) for path in (Path(__file__), HERE / 'canonical_probe.py', HERE / 'finite_re_evaluate.py', HERE / 'prepare.py', HERE / 'probe-plugin.mjs', HERE / 'artifact_oracle.py')},
              'errors': [], 'attempts': {}, 'receipts': {}, 'shutdown': {},
              'prior_failed_actual_models': 5, 'current_frozen_model_request_cap': 7, 'aggregate_request_cap': 12,
              'not_proven': ['100+ real sessions', 'fork/remote provider workload', 'full OS/model egress', 'complete financial accounting', 'code-writing Git integration', 'production qualification', 'strong physical/model egress containment']}
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
        worker = DelegatedWorker(checkpoint['binaries']['forgeflow-worker'], config_path, private_root, private)
        report['worker_unit'] = worker.unit
        def registered():
            if worker.poll() is not None:
                raise RuntimeError('actual managed Worker exited before registration')
            return query(private['DATABASE_URL'], f"SELECT json_build_object('worker_id',worker_id,'project_id',project_id,'executor_profile_ids',executor_profile_ids) FROM workers WHERE worker_id='{worker_id}' AND project_id='{project}'")
        save(output / 'actual-worker-registration.json', wait_for(registered, 40, 'actual Worker registration'))
        limits = {**vector(8), 'cpu_units': 8000, 'memory_bytes': 2 * 1024 * 1024 * 1024, 'provider_inflight': 8}
        for scope, scope_project, scope_team, scope_worker in (('global', None, None, None), ('project', project, None, None), ('worker', None, None, worker_id), ('root-team', project, 'root', None), ('leaf-team', project, 'leaf', None)):
            api(client, 'POST', '/resource-policies', {'policy': {'scope_id': scope, 'parent_scope_id': 'root-team' if scope == 'leaf-team' else None, 'project_id': scope_project, 'team_id': scope_team, 'worker_id': scope_worker, 'limits': limits, 'revision': 0, 'paused': False}})
        child_resources = {**vector(1), 'cpu_units': 500, 'memory_bytes': 128 * 1024 * 1024, 'provider_inflight': 1}
        root_resources = {**vector(1), 'cpu_units': 500, 'memory_bytes': 512 * 1024 * 1024, 'provider_inflight': 1}
        child_policy = {'schema_version': 'forgeflow.native-child-policy.v1', 'enabled': True, 'max_live_agents': 4, 'max_lifecycles': 5, 'max_delegation_depth': 2, 'model_inflight_limit': 4, 'child_resources': child_resources}
        for collection, identity, value in (('executor_profiles', profile['id'], {**profile, 'kind': 'DSH_MANAGED', 'native_mode': managed}), ('resource_profiles', 'canonical-native.v2', {'id': 'canonical-native.v2', 'stage_resource_mode': 'ATTEMPT_RESERVATION', 'isolation_profile': 'BWRAP_LANDLOCK_EXACT', 'sandbox': sandbox, 'native_child_policy': child_policy, 'physical_limits': PHYSICAL_LIMITS}), ('model_routes', profile['model_route_id'], {'id': profile['model_route_id'], 'provider': 'newapi', 'model': 'glm-5.3', 'max_output_tokens': 4096})):
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
            task.update(project_id=project, owner_id='root', team_id='leaf', read_set=[], write_set=[], dependencies=[], resource_request=root_resources)
            spec = case['context']['task_specs'][task['task_id']]
            spec.update(inputs=[], mandatory_paths=[], dependency_refs=[], design_anchors=['canonical-native#R01'], requirement_digest_refs={'R01': meaning}, execution_profile=profile['id'], verification_plan=plan_id, verification_case_count=6, not_proven=['code-writing integration and production100 remain unproven'])
            task['envelope'] = {'schema_version': 'forgeflow.execution.v1', 'operation_id': 'pending-' + mode, 'project_id': project, 'task_id': task['task_id'], 'task_revision': 1, 'attempt_id': 'pending-' + mode, 'lease_id': 'pending-' + mode, 'generation': 1, 'worker_id': worker_id, 'workspace_root': str(canonical), 'base_sha': base,
                'context_manifest': {'artifact_id': manifest['artifact_id'], 'sha256': manifest['sha256'], 'mandatory_paths': [], 'rendered_utf8_bytes': len(manifest_text.encode()), 'token_estimate': None, 'tokenizer_id': None}, 'write_set': [], 'prompt_artifact': {'artifact_id': prompt['artifact_id'], 'sha256': prompt['sha256']}, 'model_route_id': profile['model_route_id'], 'executor_profile_id': profile['id'], 'resource_profile_id': 'canonical-native.v2', 'verification_plan_id': plan_id,
                'allowed_effects': ['READ_WORKSPACE', 'REQUEST_APPROVED_MODEL', 'RUN_APPROVED_COMMANDS'], 'issued_at': now.isoformat(), 'expires_at': (now + timedelta(seconds=120)).isoformat(), 'deadline_at': (now + timedelta(minutes=8)).isoformat(), 'artifact_prefix': str(state / 'artifacts'), 'secret_refs': [], 'idempotency_key': 'pending-' + mode, 'trace_id': 'canonical-' + mode,
                'enforcement': {'model_budget_mode': 'direct_observed', 'stage_resource_mode': 'ATTEMPT_RESERVATION', 'build_capable': False, 'gateway_coverage_receipt_id': None, 'tool_guard_receipt_id': None, 'attempt_reserved_build_permits': 0, 'all_model_routes_covered': False, 'disabled_tool_entry_ids': []}, 'session_purpose': 'REVIEW', 'max_model_requests': 7, 'resume_session_id': None, 'command': None}
            refresh_digest(task, spec)
            oracle = frozen_bundle / 'artifact_oracle.py' if (frozen_bundle / 'artifact_oracle.py').is_file() else HERE / 'artifact_oracle.py'
            commands = [{'role': role, 'program': '/usr/bin/python3', 'args': ['-I', '-B', str(oracle)], 'env': {}, 'executable_hash': digest('/usr/bin/python3'), 'bound_inputs': [{'path': str(oracle), 'sha256': digest(oracle)}], 'report_path': role + '.json', 'expected_cases': [{'name': 'finite_receipt_labels', 'kind': 'positive'}, {'name': 'empty_receipt_rejected', 'kind': 'negative'}], 'timeout_seconds': 20} for role in ('author', 'consumer', 'independent')]
            api(client, 'POST', f'/projects/{project}/documents/verification_plans', {'id': plan_id, 'value': {'plan_id': plan_id, 'task_revision': 1, 'contract_version': 'canonical-native.v2', 'input_hash': task['input_digest'], 'environment_profile': 'canonical-native.v2', 'oracle_id': 'canonical-finite-artifact.v1', 'verifier_id': 'finite-native-independent-artifact-oracle', 'author_id': worker_id, 'commands': commands}})
        saved = api(client, 'POST', f'/projects/{project}/flow-revisions', {'flow': case['flow'], 'context': case['context']})['data']
        committed = api(client, 'POST', f'/flows/{project}:1/commit', {'expected_revision': saved['revision']})['data']
        for mode, task in zip(modes, committed['tasks']):
            admitted = api(client, 'POST', f'/projects/{project}/admissions', {'actor_id': 'overwritten', 'idempotency_key': 'overwritten', 'project_id': project, 'task_id': task['task_id'], 'task_revision': task['task_revision'], 'flow_revision': task['flow_revision'], 'policy_revision': 1, 'input_digest': task['input_digest'], 'worker_id': worker_id, 'lease_seconds': 120, 'envelope': task['envelope']})['data']
            attempt = admitted['attempt']['attempt_id']
            report['attempts'][mode] = attempt
            journal = state / 'attempts' / attempt
            def acknowledged():
                if worker.poll() is not None:
                    raise RuntimeError('managed Worker exited before native result acknowledgement')
                if (journal / 'result-ack.json').exists():
                    return True
                return False
            wait_for(acknowledged, 510, 'actual native Worker stop and canonical result acknowledgement')
            receipt = observe_mode(mode, attempt, private, output, report)
            report['receipts'][mode] = receipt
            if receipt['failed']:
                raise RuntimeError(mode + ' actual native producer observations failed')
            # The omitted business step in the historical probe is performed
            # through the real registered API verifier, never by fabricating a
            # receipt or treating the native exit code as completion.
            current = api(client, 'GET', f'/attempts/{attempt}?project_id={project}')['data']
            if current['state'] != 'VERIFYING':
                raise RuntimeError('actual finite parent must reach VERIFYING before independent artifact acceptance')
            accepted = api(client, 'POST', f'/attempts/{attempt}/verify', {'project_id': project})
            operation = accepted['operation_id']
            report['verification_operation_id'] = operation
            def verified():
                value = api(client, 'GET', f'/operations/{operation}')['data']
                if value['status'] in ('FAILED', 'CANCELLED', 'RECOVERY_REQUIRED'):
                    raise RuntimeError('actual independent finite artifact operation failed')
                return value if value['status'] == 'SUCCEEDED' else None
            completed_operation = wait_for(verified, 90, 'actual independent structured artifact acceptance')
            save(output / 'finite.verification-operation.json', completed_operation)
            current = api(client, 'GET', f'/attempts/{attempt}?project_id={project}')['data']
            facts = native_rows(private['DATABASE_URL'], attempt)
            save(output / 'finite.after-completion.postgres.json', facts)
            save(output / 'finite.completed-attempt.json', current)
            evidence = query(private['DATABASE_URL'], f"SELECT COALESCE(json_agg(data),'[]'::json) FROM evidence_receipts WHERE project_id='{project}' AND attempt_id='{attempt}'")
            save(output / 'finite.business-evidence.json', evidence)
            report['parent_closure'] = parent_closure(current, facts, evidence, completed_operation,
                                                     state, output, report['_redact'], canonical, base)
            if report['parent_closure']['failed']:
                raise RuntimeError('finite parent business closure failed; preserve actual evidence')
    except Exception as error:
        report['errors'].append({'type': type(error).__name__, 'message': str(error)})
    finally:
        if report['errors'] and report.get('attempts'):
            for attempt in report['attempts'].values():
                try:
                    current = api(client, 'GET', f'/attempts/{attempt}?project_id={project}')['data']
                    journal = state / 'attempts' / attempt
                    if current['state'] not in ('SUCCEEDED', 'FAILED', 'CANCELLED'):
                        if report.get('verification_operation_id'):
                            operation = api(client, 'GET', f"/operations/{report['verification_operation_id']}")['data']
                            if operation['status'] not in ('SUCCEEDED', 'FAILED', 'CANCELLED'):
                                raise RuntimeError('active verifier authority retained; cleanup requires separate explicit recovery')
                        api(client, 'POST', f'/attempts/{attempt}/cancel', {
                            'project_id': project, 'expected_revision': current['revision'],
                            'reason': 'isolated finite qualification failed; preserve original failed receipts'})
                        wait_for(lambda: api(client, 'GET', f'/attempts/{attempt}?project_id={project}')['data']['state'] in ('FAILED', 'CANCELLED'),
                                 40, 'actual isolated failed parent drain')
                    save(output / 'failed-parent-cleanup.postgres.json', native_rows(private['DATABASE_URL'], attempt))
                except Exception as cleanup_error:
                    report['errors'].append({'type': type(cleanup_error).__name__, 'message': str(cleanup_error)})
        for attempt in report.get('attempts', {}).values():
            try:
                final_facts = native_rows(private['DATABASE_URL'], attempt)
                save(output / 'final-authority.postgres.json', final_facts)
                report['final_actual_model_requests'] = len(final_facts['native_model_requests'])
                report['final_models_all_settled_with_usage'] = all(row['status'] == 'SETTLED' and row['usage_complete']
                    for row in final_facts['native_model_requests'])
                report['final_parent_held_allocations'] = sum(row['state'] != 'RELEASED' for row in final_facts['resource_allocations'])
                report['final_child_held_allocations'] = sum(row['state'] != 'RELEASED' for row in final_facts['native_child_allocations'])
                if report['errors']:
                    journal = state / 'attempts' / attempt
                    for filename in ('stdout.ndjson', 'stderr.log', 'stop.json', 'result.json', 'launch-receipt.json',
                                     'envelope.json', 'execution-bindings.json', 'cgroup-fence.json', 'cgroup-stop.json', 'cgroup-membership.json'):
                        source = journal / filename
                        if source.exists():
                            (output / ('failed.' + filename)).write_bytes(report['_redact'](source.read_bytes()))
            except Exception as error:
                report['errors'].append({'type': type(error).__name__, 'message': 'Final authority observation failed: ' + str(error)})
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
            if name == 'worker':
                worker.retain_log(private_root / 'worker.log')
                report['delegated_worker_cleanup'] = worker.cleanup()
            source = private_root / (name + '.log')
            if source.exists():
                (output / (name + '.log')).write_bytes(report['_redact'](source.read_bytes()))
        report.pop('_redact')
        report['status'] = 'FAIL' if report['errors'] else 'PASS_FINITE_NATIVE_PARENT_ARTIFACT_CLOSURE'
        report['evidence_sha256'] = {path.name: digest(path) for path in output.iterdir() if path.is_file()}
        save(output / 'report.json', report)
        print(json.dumps({'status': report['status'], 'errors': report['errors'], 'attempts': report['attempts'], 'private_root': str(private_root), 'output': str(output)}))
    return 1 if report['errors'] else 0


def prepare_report(args):
    original_report = json.loads((ORIGINAL / 'report.json').read_text())
    original_receipt = json.loads((ORIGINAL / 'finite.receipt.json').read_text())
    actual = json.loads((ORIGINAL / 'finite.result-ack.json').read_text())['controller_response']['data']
    paths = ('report.json', 'finite.receipt.json', 'finite.result-ack.json', 'finite.postgres.json',
             'finite.stdout.ndjson', 'finite.stop.json', 'finite.envelope.json')
    return {'schema_version': 'forgeflow.native-finite-completion-plan.v1',
        'status': 'PREPARED_NOT_EXECUTED', 'driver_sha256': digest(__file__),
        'original_status_preserved': original_report['status'],
        'original_failed_assertions': [row['name'] for row in original_receipt['checks'] if row['status'] == 'FAIL'],
        'original_parent_authority_state': actual['state'],
        'original_actual_model_requests': original_receipt['model_requests'],
        'original_evidence_sha256': {name: digest(ORIGINAL / name) for name in paths},
        'cause': 'Original fixed-eight-request oracle failed at actual seven; script raised before its cleanup and explicitly omitted independent business verification. Native result was completed/exit0 and parent was VERIFYING, not a failed native parent.',
        'correction': 'One new finite native read-only REVIEW attempt, actual causal model/lifecycle grant identity, followed by registered six-case independent artifact verification through API and SUCCEEDED/zero-held-resource closure.',
        'workload': ['one-shot native Subagent', 'one finite native Workflow child',
                     'one native Agent Team teammate plus real cold resume'],
        'frozen_max_model_requests': 7, 'automatic_retry': False,
        'new_model_requests_so_far': 0, 'prior_failed_actual_requests': 5, 'aggregate_max_requests': 12, 'production_source_changes': ['crates/executors/presets/forgeflow/managed-bridge.mjs'], 'physical_limits': PHYSICAL_LIMITS, 'reserved_pool_expected': {'cpu_units': 2000, 'memory_bytes': 896*1024*1024, 'max_concurrent_children': 3}, 'runtime_prepared_root': 'NEW_FROZEN_BUNDLE_REQUIRED_AFTER_RPC_DIAGNOSTIC_FIX', 'actual_run_output_must_be_fresh': True,
        'historical_attempt_mutation': False, 'code_integration_claimed': False,
        'not_proven': ['100+ native production', 'complete monetary accounting', 'hostile OS/model egress',
                       'code-writing Git integration', 'full fault campaign']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--approved-model-request-cap', type=int)
    for name in ('build-receipt', 'prepared-root', 'private-env'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'evidence/native-finite-completion-r1')
    parser.add_argument('--source-authority', choices=('current-tree', 'checkpoint-snapshot'), default='current-tree')
    args = parser.parse_args()
    if not args.run:
        args.output.mkdir(parents=True, exist_ok=True)
        target = args.output / 'correction-plan.json'
        with target.open('x') as stream:
            json.dump(prepare_report(args), stream, indent=2); stream.write('\n')
        print(json.dumps({'status': 'PREPARED_NOT_EXECUTED', 'model_request_cap': 7, 'output': str(target)}))
        return 0
    if args.approved_model_request_cap != 7 or any(getattr(args, field) is None
            for field in ('build_receipt', 'prepared_root', 'private_env')):
        parser.error('Actual run requires explicit root GO, --approved-model-request-cap 7 and all three frozen private/checkpoint inputs')
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())

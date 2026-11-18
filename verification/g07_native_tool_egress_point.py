#!/usr/bin/env python3
"""One stock Bash/PTC tool egress point, zero actual models and model-request grants.
Preparation creates source bindings only. Doctor and actors require Root GO.
"""
import argparse, json, os, secrets, signal, socket, subprocess, sys, time, urllib.parse, uuid
from datetime import datetime,timedelta,timezone
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
HERE=ROOT/'crates/executors/qualification/canonical-collaboration'
sys.dont_write_bytecode=True
sys.path.insert(0,str(HERE))
from canonical_probe import approved_checkpoint,database,query,wait_for,native_rows,verify_pins,redactor,Client,api,git,make_compile,refresh_digest,requirement_digest,vector
from prepare import digest,save
from finite_completion import DelegatedWorker,PHYSICAL_LIMITS

def run(args):
    modes = ('tools',)
    listener=None
    if args.private_env.stat().st_mode & 0o077:
        raise RuntimeError('runtime credential config must have private 0600 permissions')
    with socket.socket() as probe:
        probe.settimeout(.2)
        if probe.connect_ex(('127.0.0.1', 8897)) == 0:
            raise RuntimeError('port8897 has a live authority; refuse duplicate/shared run')
    checkpoint = approved_checkpoint(args.build_receipt, 'checkpoint-snapshot')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError('preserve earlier evidence: use a new output directory')
    (output / 'build.receipt.json').write_bytes(args.build_receipt.read_bytes())
    (output / 'source-native-tool-egress.mjs').write_bytes((args.prepared_root/'native-tool-egress.mjs').read_bytes())
    for source in (Path(__file__), HERE / 'prepare.py', HERE / 'finite_re_evaluate.py', HERE / 'canonical_probe.py', HERE / 'probe-plugin.mjs', HERE / 'artifact_oracle.py',
                   HERE.parents[1] / 'presets/forgeflow/managed-bridge.mjs', HERE.parents[1] / 'presets/forgeflow/mode.json'):
        (output / ('source-' + source.name)).write_bytes(source.read_bytes())
    profile = json.loads((args.prepared_root / 'headless-profile.json').read_text())
    managed = json.loads((args.prepared_root / 'managed-config.json').read_text())
    # Supported finite transport allowance, frozen into actual Worker config.
    # This does not assert the historical failure was a timeout.
    managed['rpc_timeout_ms'] = 5000
    if not managed.get('model_relay'): raise RuntimeError('strict relay bundle required')
    verify_pins(profile)
    private_root = Path('/tmp') / ('ff-native-tools-' + uuid.uuid4().hex[:8])
    private_root.mkdir(mode=0o700)
    state = private_root / 's'
    state.mkdir(mode=0o700)
    source_private = json.loads(args.private_env.read_text())
    database_name = 'ff_canonical_' + uuid.uuid4().hex[:16]
    database(source_private['DATABASE_URL'], 'CREATE DATABASE "' + database_name + '"')
    parsed = urllib.parse.urlsplit(source_private['DATABASE_URL'])
    private = {'DATABASE_URL': urllib.parse.urlunsplit(parsed._replace(path='/' + database_name)),
               'FORGEFLOW_BIND': '127.0.0.1:8897', 'FORGEFLOW_DATA_ROOT': str(state),
               'FORGEFLOW_OWNER_TOKEN': secrets.token_hex(32), 'FORGEFLOW_WORKER_TOKEN': secrets.token_hex(32),
               'FORGEFLOW_CONSOLE_DIR': str(ROOT / 'console/dist'), 'RUST_LOG': 'info'}
    save(private_root / 'runtime-env.json', private, private=True)
    report = {'schema_version': 'forgeflow.native-tool-egress-point.v1', 'at': datetime.now(timezone.utc).isoformat(),
              'authority': 'CANONICAL_POSTGRESQL', 'private_root': str(private_root), 'database_name': database_name,
              'build_receipt_sha256': digest(args.build_receipt), 'binaries': checkpoint['binaries'],
              'source_identity': checkpoint['source_identity'],
              'actual_source_authority': checkpoint['actual_source_authority'], 'current_source_ahead_paths': checkpoint['current_source_ahead_paths'],
              'build_verification_scope': checkpoint.get('qualification'), 'postgres_verification': checkpoint.get('postgres_verification'),
              'profile_sha256': digest(args.prepared_root / 'headless-profile.json'), 'doctor_sha256': digest(managed['doctor']),
              'source_artifacts': {str(path.relative_to(ROOT)): digest(path) for path in (Path(__file__), HERE / 'canonical_probe.py', HERE / 'finite_re_evaluate.py', HERE / 'prepare.py', HERE / 'probe-plugin.mjs', HERE / 'artifact_oracle.py')},
              'errors': [], 'attempts': {}, 'receipts': {}, 'shutdown': {},
              'actual_model_request_grants_expected': 0, 'unused_root_lifecycle_admission_budget_cap': 1, 'actual_provider_calls_max': 0, 'canonical_total_wire_token_cap': 20480,
              'not_proven': ['all transitive dependency content inventory', 'unconfigured remote provider workloads', 'production default tool presentation']}
    report['_redact'] = redactor(managed, private)
    server = worker = None
    try:
        execute_doctor(args.prepared_root)
        profile=json.loads((args.prepared_root/'headless-profile.json').read_text());verify_pins(profile)
        report.update(profile_sha256=digest(args.prepared_root/'headless-profile.json'),doctor_sha256=digest(managed['doctor']))
        listener=owned_listener()
        report['project_id'] = 'g07-native-' + uuid.uuid4().hex[:12]
        report['worker_id'] = 'g07-worker-' + uuid.uuid4().hex[:12]
        private.update(FORGEFLOW_WORKER_ID=report['worker_id'],FORGEFLOW_WORKER_PROJECT_ID=report['project_id'])
        server_log = (private_root / 'server.log').open('wb')
        server = subprocess.Popen([checkpoint['binaries']['forgeflow-server']['path']], env={'PATH': '/usr/bin:/bin', **private}, stdout=server_log, stderr=subprocess.STDOUT)
        client = Client('http://127.0.0.1:8897', private['FORGEFLOW_OWNER_TOKEN'], output)
        def healthy():
            if server.poll() is not None:
                raise RuntimeError('isolated server exited before readiness')
            try: return client.request('GET', '/api/v1/me')[0] == 200
            except RuntimeError: return False
        wait_for(healthy, 20, 'isolated canonical API readiness')
        seed = private_root / 'seed'
        seed.mkdir()
        git(seed, 'init', '--initial-branch=main')
        (seed / 'baseline.txt').write_text('Finite native collaboration read-only fixture.\n')
        git(seed, 'add', '--all')
        git(seed, '-c', 'user.name=Canonical qualification', '-c', 'user.email=qualification@localhost', 'commit', '-m', 'Private canonical native baseline')
        base = git(seed, 'rev-parse', 'HEAD')
        project = report['project_id']
        worker_id = report['worker_id']
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
        readonly += [str(Path(managed['model_relay']['transport_loader'])), str(args.prepared_root)]
        sandbox = {'bwrap_program': '/usr/bin/bwrap', 'bwrap_sha256': digest('/usr/bin/bwrap'), 'guard_program': checkpoint['binaries']['forgeflow-sandbox-guard']['path'], 'guard_sha256': checkpoint['binaries']['forgeflow-sandbox-guard']['sha256'], 'readonly_paths': readonly, 'network_allowed': False}
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
        save(output / 'actual-worker-registration.json', wait_for(registered, 20, 'actual Worker registration'))
        limits = {**vector(8), 'cpu_units': 8000, 'memory_bytes': 2 * 1024 * 1024 * 1024, 'provider_inflight': 8}
        for scope, scope_project, scope_team, scope_worker in (('global', None, None, None), ('project', project, None, None), ('worker', None, None, worker_id), ('root-team', project, 'root', None), ('leaf-team', project, 'leaf', None)):
            api(client, 'POST', '/resource-policies', {'policy': {'scope_id': scope, 'parent_scope_id': 'root-team' if scope == 'leaf-team' else None, 'project_id': scope_project, 'team_id': scope_team, 'worker_id': scope_worker, 'limits': limits, 'revision': 0, 'paused': False}})
        child_resources = {**vector(1), 'cpu_units': 500, 'memory_bytes': 128 * 1024 * 1024, 'provider_inflight': 1}
        root_resources = {**vector(1), 'cpu_units': 500, 'memory_bytes': 512 * 1024 * 1024, 'provider_inflight': 1}
        child_policy = {'schema_version': 'forgeflow.native-child-policy.v1', 'enabled': True, 'max_live_agents': 4, 'max_lifecycles': 5, 'max_delegation_depth': 2, 'model_inflight_limit': 4, 'child_resources': child_resources}
        for collection, identity, value in (('executor_profiles', profile['id'], {**profile, 'kind': 'DSH_MANAGED', 'native_mode': managed}), ('resource_profiles', 'canonical-native.v2', {'id': 'canonical-native.v2', 'stage_resource_mode': 'ATTEMPT_RESERVATION', 'isolation_profile': 'BWRAP_LANDLOCK_EXACT', 'sandbox': sandbox, 'native_child_policy': child_policy, 'physical_limits': PHYSICAL_LIMITS}), ('model_routes', profile['model_route_id'], {'id': profile['model_route_id'], 'provider': 'newapi', 'model': 'glm-5.3', 'max_output_tokens': 20480})):
            api(client, 'POST', f'/projects/{project}/documents/{collection}', {'id': identity, 'value': value})
        manifest_text = json.dumps({'files': [], 'mandatory_paths': [], 'artifact_inputs': []}, separators=(',', ':'))
        manifest = api(client, 'POST', f'/projects/{project}/artifacts', {'content_utf8': manifest_text, 'kind': 'CONTEXT_MANIFEST'})['data']
        case = make_compile(len(modes))
        case['flow']['project_id'] = project
        meaning = requirement_digest(requirement)
        case['context'].update(owners=[{'owner_id': 'root', 'root_team_id': 'root', 'include': ['baseline.txt'], 'exclude': []}], current_inputs={}, requirement_semantic_digests={'R01': meaning}, requirements=[{'requirement_id': 'R01', 'source_document': 'canonical-native', 'anchor': 'R01', 'acceptance': '\n'.join(requirement['acceptance']), 'priority': 1, 'deferred_reason': None}])
        for mode, task in zip(modes, case['flow']['tasks']):
            prompt_text = 'Zero-model qualification: pre-step plugin executes the stock tools and rejects this step. Never call a model, provider or delegate.'
            prompt = api(client, 'POST', f'/projects/{project}/artifacts', {'content_utf8': prompt_text, 'kind': 'PROMPT'})['data']
            now = datetime.now(timezone.utc)
            plan_id = 'canonical-plan-' + mode
            task.update(project_id=project, owner_id='root', team_id='leaf', read_set=[], write_set=[], dependencies=[], resource_request=root_resources)
            spec = case['context']['task_specs'][task['task_id']]
            spec.update(inputs=[], mandatory_paths=[], dependency_refs=[], design_anchors=['canonical-native#R01'], requirement_digest_refs={'R01': meaning}, execution_profile=profile['id'], verification_plan=plan_id, verification_case_count=6, not_proven=['code-writing integration and production100 remain unproven'])
            task['envelope'] = {'schema_version': 'forgeflow.execution.v1', 'operation_id': 'pending-' + mode, 'project_id': project, 'task_id': task['task_id'], 'task_revision': 1, 'attempt_id': 'pending-' + mode, 'lease_id': 'pending-' + mode, 'generation': 1, 'worker_id': worker_id, 'workspace_root': str(canonical), 'base_sha': base,
                'context_manifest': {'artifact_id': manifest['artifact_id'], 'sha256': manifest['sha256'], 'mandatory_paths': [], 'rendered_utf8_bytes': len(manifest_text.encode()), 'token_estimate': None, 'tokenizer_id': None}, 'write_set': [], 'prompt_artifact': {'artifact_id': prompt['artifact_id'], 'sha256': prompt['sha256']}, 'model_route_id': profile['model_route_id'], 'executor_profile_id': profile['id'], 'resource_profile_id': 'canonical-native.v2', 'verification_plan_id': plan_id,
                'allowed_effects': ['READ_WORKSPACE', 'REQUEST_APPROVED_MODEL', 'RUN_APPROVED_COMMANDS'], 'issued_at': now.isoformat(), 'expires_at': (now + timedelta(seconds=120)).isoformat(), 'deadline_at': (now + timedelta(minutes=8)).isoformat(), 'artifact_prefix': str(state / 'artifacts'), 'secret_refs': [], 'idempotency_key': 'pending-' + mode, 'trace_id': 'canonical-' + mode,
                'enforcement': {'model_budget_mode': 'direct_observed', 'stage_resource_mode': 'ATTEMPT_RESERVATION', 'build_capable': False, 'gateway_coverage_receipt_id': None, 'tool_guard_receipt_id': None, 'attempt_reserved_build_permits': 0, 'all_model_routes_covered': False, 'disabled_tool_entry_ids': []}, 'session_purpose': 'REVIEW', 'max_model_requests': 1, 'resume_session_id': None, 'command': None}
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
                stop_path = journal / 'stop.json'
                if stop_path.exists():
                    stopped = json.loads(stop_path.read_text())
                    if stopped.get('process_exit_confirmed') and stopped.get('exit_code') != 0:
                        # This zero-model plugin deliberately rejects the model pre-step.
                        # Stock CLI exits 1 for that blocked turn; still await the real ACK.
                        stdout_path = journal / 'stdout.ndjson'
                        observed = [json.loads(line) for line in stdout_path.read_text().splitlines() if line.strip()] if stdout_path.exists() else []
                        expected_reject = any(
                            event.get('type') == 'forgeflow_native_tool_proof'
                            and event.get('model_step_rejected') is True
                            and event.get('scope') == 'qualification_only_actual_stock_tool_entries'
                            for event in observed)
                        if stopped.get('exit_code') != 1 or not expected_reject:
                            raise RuntimeError('NATIVE_EXECUTOR_FAILED_BEFORE_ACK exit=' + str(stopped.get('exit_code')) + '; preserve original native session and transport quarantine')
                return False
            wait_for(acknowledged, 45, 'actual native Worker stop and canonical result acknowledgement')
            facts = native_rows(private['DATABASE_URL'], attempt)
            save(output / 'egress.native-facts.json', facts)
            models = facts['native_model_requests']
            if models: raise RuntimeError('ZERO_MODEL_POINT_UNEXPECTED_MODEL_GRANT')
            events=[json.loads(line) for line in (journal/'stdout.ndjson').read_text().splitlines() if line.strip()]
            proof=next((x for x in events if x.get('type')=='forgeflow_native_tool_proof'),None)
            if proof is None:raise RuntimeError('actual stock tools did not produce their proof')
            stopped = json.loads((journal / 'stop.json').read_text())
            blocked = any(x.get('type') == 'status' and x.get('reason', {}).get('kind') == 'blocked' for x in events)
            if stopped.get('exit_code') == 1 and (not proof.get('model_step_rejected') or not blocked):
                raise RuntimeError('native exit1 did not match the intentional blocked pre-step')
            save(output/'native-tool-proof.json',proof)
            report['tool_proof']=proof
            bash=proof['tools']['bash'];ptc=proof['tools']['ptc']
            if bash['isError'] or 'G07_BASH_TCP_DENIED' not in json.dumps(bash) or ptc['isError'] or ptc['value']['result']['tcp']['allowed'] or ptc['value']['result']['tcp'].get('code')=='TIMEOUT' or ptc['value']['result']['ambient_fetch']['allowed'] or proof['outside_grant_fetch'].get('code')!='FORGEFLOW_MODEL_TRANSPORT_DENIED':raise RuntimeError('actual native tool egress denial oracle failed')
            host_ns=os.readlink('/proc/self/ns/net')
            if proof['network_namespace']==host_ns or ptc['value']['result']['network_namespace']!=proof['network_namespace']:raise RuntimeError('native/PTC network namespace isolation binding mismatch')
            report['host_network_namespace']=host_ns
            if listener['hits']:raise RuntimeError('strict native tool reached owned host listener')
            current = api(client, 'GET', f'/attempts/{attempt}?project_id={project}')['data']
            if current['state'] not in ('SUCCEEDED','FAILED','CANCELLED'):
                api(client,'POST',f'/attempts/{attempt}/cancel',{'project_id':project,'expected_revision':current['revision'],'reason':'G07 one-request transport point complete; no business completion claim'})
                wait_for(lambda: api(client,'GET',f'/attempts/{attempt}?project_id={project}')['data']['state'] in ('FAILED','CANCELLED'),10,'legal point resource closure')
            report['actual_native_tool_entries'] = ['bash','run_code']
            report['gateway_coverage_verified'] = False
            report['business_completion_claimed'] = False
    except BaseException as error:
        report['interrupted'] = isinstance(error, (KeyboardInterrupt, SystemExit))
        report['errors'].append({'type': type(error).__name__, 'message': str(error)})
    finally:
        signal.alarm(0)
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
                                 10, 'actual isolated failed parent drain')
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
                try: process.wait(timeout=15)
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
        report['phase']='tools'
        report['provider_calls']=0
        if listener is not None:
            listener['stop'].set();listener['socket'].close();listener['thread'].join(3)
            report['owned_listener']={'hits':listener['hits'],'port':8898,'closed':not listener['thread'].is_alive()}
        report.pop('_redact')
        report['status'] = 'FAIL' if report['errors'] else 'PASS_ZERO_MODEL_NATIVE_TOOL_EGRESS_POINT'
        report['evidence_sha256'] = {path.name: digest(path) for path in output.iterdir() if path.is_file()}
        save(output / 'report.json', report)
        print(json.dumps({'status': report['status'], 'errors': report['errors'], 'attempts': report['attempts'], 'private_root': str(private_root), 'output': str(output)}))
    return 1 if report['errors'] else 0


def owned_listener():
    import threading
    sock=socket.socket();sock.bind(('127.0.0.1',8898));sock.listen(8);sock.settimeout(.2);state={'socket':sock,'hits':0,'stop':threading.Event()}
    def accept():
        while not state['stop'].is_set():
            try:c,_=sock.accept();state['hits']+=1;c.close()
            except socket.timeout:pass
            except OSError:break
    state['thread']=threading.Thread(target=accept,daemon=True);state['thread'].start();return state

def execute_doctor(root):
    profile=json.loads((root/'headless-profile.json').read_text());managed=json.loads((root/'managed-config.json').read_text());doctor=json.loads(Path(managed['doctor']).read_text())
    result=subprocess.run(doctor['command'],env={'PATH':'/usr/bin:/bin','HOME':profile['home'],'DSH_HOME':profile['home']},capture_output=True,timeout=30)
    save(root/'doctor-result.json',{'exit_code':result.returncode,'stdout_sha256':__import__('hashlib').sha256(result.stdout).hexdigest()})
    from prepare import private_write
    private_write(root/'actual-doctor.stdout',result.stdout);private_write(root/'actual-doctor.stderr',result.stderr)
    if result.returncode:raise RuntimeError('new actual stock CLI Doctor failed before business actor startup')
    doctor.update(exit_code=0,composition_sha256=__import__('hashlib').sha256(result.stdout).hexdigest(),qualification='INCONCLUSIVE',scope='Actual tool-only qualification plugin config dump; zero model/actual tool execution not yet claimed')
    Path(managed['doctor']).write_text(json.dumps(doctor,indent=2)+'\n')
    for pin in profile['artifact_pins']:
        if pin['path']==managed['doctor']:pin['sha256']=digest(managed['doctor'])
    (root/'headless-profile.json').write_text(json.dumps(profile,indent=2)+'\n')

def prepare_only(args):
    import tempfile,shutil,hashlib
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
    if any(out.iterdir()):raise RuntimeError('fresh source-only evidence path required')
    root=Path(tempfile.mkdtemp(prefix='ff-native-tool-prepared-',dir='/tmp'));root.chmod(0o700)
    oldprofile=json.loads((args.source_prepared/'headless-profile.json').read_text());managed=json.loads((args.source_prepared/'managed-config.json').read_text());olddoctor=json.loads(Path(managed['doctor']).read_text())
    plugin=root/'native-tool-egress.mjs';shutil.copyfile(HERE/'native-tool-egress.mjs',plugin);plugin.chmod(0o444)
    (out/'source-native-tool-egress.mjs').write_bytes(plugin.read_bytes())
    preset=json.loads(Path(managed['preset_patch']).read_text());preset += [{'id':'tools','config':{'mode':'both'}},{'insert':[{'id':'forgeflow-native-tool-egress','name':str(plugin),'config':{'host':'127.0.0.1','port':8898}}]}]
    patch=root/'qualification-preset.json';save(patch,preset,private=True);managed['preset_patch']=str(patch)
    doc=root/'managed-doctor.json';managed['doctor']=str(doc);profile={**oldprofile,'id':'forgeflow-native-tools-zero-model-v1'}
    inventory={pin['path']:pin['sha256'] for pin in oldprofile['artifact_pins'] if pin['path']!=str(Path(olddoctor.get('raw_composition_path','missing')).parent/'managed-doctor.json')};inventory.pop(str(json.loads((args.source_prepared/'managed-config.json').read_text())['doctor']),None)
    inventory[str(plugin)]=digest(plugin);inventory[str(patch)]=digest(patch)
    command=list(olddoctor['command']);index=command.index('--patch');command[index+1]=str(patch)
    doctor={**olddoctor,'executor_profile_id':profile['id'],'artifact_sha256':inventory,'command':command,'exit_code':None,'scope':'NEW_TOOL_PLUGIN_DOCTOR_NOT_RUN_WAIT_ROOT_GO','qualification':'INCONCLUSIVE'}
    save(doc,doctor,private=True);inventory[str(doc)]=digest(doc);profile['artifact_pins']=[{'path':k,'sha256':v} for k,v in sorted(inventory.items())]
    save(root/'headless-profile.json',profile,private=True);save(root/'managed-config.json',managed,private=True)
    plan={'status':'SOURCE_READY_DOCTOR_AND_ACTORS_NOT_RUN','driver_sha256':digest(__file__),'plugin_sha256':digest(plugin),'prepared_root':str(root),'baseline_stock_doctor_sha256':digest(json.loads((args.source_prepared/'managed-config.json').read_text())['doctor']),'doctor_command':command,'profile_template_sha256':digest(root/'headless-profile.json'),'Doctor_template_NOT_ACTUAL':True,'public_interface_source_pins':{str(p):digest(p) for p in [Path('/home/chenyoujian/.local/share/dsh-wsl/source/packages/core/tools/lib/index.js'),Path('/home/chenyoujian/.local/share/dsh-wsl/source/packages/core/agent-loop/src/agent.ts'),Path('/home/chenyoujian/.local/share/dsh-wsl/source/packages/shell/tool-bash/src/index.ts'),Path('/home/chenyoujian/.local/share/dsh-wsl/source/packages/ptc-runtime/ptc-runtime-node/src/index.ts')]},'model_calls_expected':0,'model_request_grants_expected':0,'root_lifecycle_unused_model_request_cap':1,'tools_mode':'both qualification-only vs native production default','owned_API_port':8897,'owned_TCP_listener_port':8898,'readonly_network_sandbox':True,'remote_scope':'Existing Doctor active subagent spawn/fork in-process; no configured remote provider endpoints imported. Transitive dependencies are not fully content inventoried. No broader remote qualification claimed.','actor_deadline_seconds':120,'bounded_cleanup_max_seconds':58,'remote_remote_network_inventory_scope':'No imported configured remote endpoint; active stock subagent spawn/fork in-process only, transitive content inventory unqualified','run_command':['/usr/bin/python3','-B',str(Path(__file__).resolve()),'--run','--prepared-root',str(root),'--private-env',str(args.private_env.resolve()),'--output',str(out/'actual-r1'),'--build-receipt','ROOT_FROZEN_B3_RECEIPT_REQUIRED']}
    save(out/'plan.json',plan);print(json.dumps({'plan':str(out/'plan.json'),'sha256':digest(out/'plan.json'),'driver_sha256':plan['driver_sha256'],'plugin_sha256':plan['plugin_sha256'],'prepared_root':str(root)}))

def main():
    p=argparse.ArgumentParser(description='One stock Bash/PTC tool egress point, zero models')
    p.add_argument('--prepare-only',action='store_true');p.add_argument('--run',action='store_true');p.add_argument('--source-prepared',type=Path)
    for k in ('prepared-root','private-env','output','build-receipt'):p.add_argument('--'+k,type=Path,required=k in ('private-env','output'))
    a=p.parse_args()
    if a.prepare_only:prepare_only(a);return
    if not a.run or not a.prepared_root or not a.build_receipt:raise SystemExit('Root GO required')
    def timeout(_signum,_frame):raise TimeoutError('native tool actor deadline120sec reached; bounded cleanup follows')
    signal.signal(signal.SIGALRM,timeout);signal.alarm(120)
    raise SystemExit(run(a))
if __name__=='__main__':main()

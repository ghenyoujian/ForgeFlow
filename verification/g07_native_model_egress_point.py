#!/usr/bin/env python3
"""G07 finite strict-native model transport point. One provider call; never a collaboration replay.
Historical FAIL evidence is immutable. Preparation has no models or service actors.
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

class Sentinel:
    def __init__(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        self.hit=threading.Event(); self.release=threading.Event(); self.count=0; self.body=None
        outer=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                outer.count+=1; outer.body=self.rfile.read(int(self.headers['Content-Length'])); outer.hit.set()
                if not outer.release.wait(25): self.send_error(504); return
                self.send_response(200); self.send_header('Content-Type','text/event-stream'); self.send_header('Connection','close'); self.end_headers()
                events=[('message_start',{'type':'message_start','message':{'id':'msg_sentinel','type':'message','role':'assistant','model':'glm-5.3','content':[],'stop_reason':None,'stop_sequence':None,'usage':{'input_tokens':4,'output_tokens':0}}}),('content_block_start',{'type':'content_block_start','index':0,'content_block':{'type':'text','text':''}}),('content_block_delta',{'type':'content_block_delta','index':0,'delta':{'type':'text_delta','text':'ONE_SHOT_RECEIPT WORKFLOW_RECEIPT TEAM_RECEIPT TEAM_RESUME_RECEIPT'}}),('content_block_stop',{'type':'content_block_stop','index':0}),('message_delta',{'type':'message_delta','delta':{'stop_reason':'end_turn','stop_sequence':None},'usage':{'output_tokens':4}}),('message_stop',{'type':'message_stop'})]
                for name,payload in events:self.wfile.write(('event: '+name+'\ndata: '+json.dumps(payload)+'\n\n').encode()); self.wfile.flush()
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def close(self):self.release.set();self.server.shutdown();self.server.server_close();self.thread.join(3)

def negative_dispatches(sentinel,private,project,worker,attempt,output):
    import hashlib, urllib.request, urllib.error
    row=query(private['DATABASE_URL'],f"SELECT row_to_json(r) FROM native_model_requests r WHERE attempt_id='{attempt}' AND dispatched_at IS NOT NULL LIMIT 1")
    if not row:raise RuntimeError('sentinel upstream hit lacks canonical consumed grant')
    body=sentinel.body
    headers={'Authorization':'Bearer '+private['FORGEFLOW_WORKER_TOKEN'],'Content-Type':'application/json','x-forgeflow-worker-id':worker,'x-forgeflow-project-id':project,'x-forgeflow-generation':str(row['generation']),'x-forgeflow-native-session-id':row['native_session_id'],'x-forgeflow-native-allocation-id':row['allocation_id'],'x-forgeflow-native-request-id':row['request_id'],'x-forgeflow-native-grant-id':row['request_grant_id'],'x-forgeflow-native-provider':row['provider']}
    url='http://127.0.0.1:8793/api/v1/attempts/'+attempt+'/native-model?project_id='+project
    def call(target,data,h):
        h={**h,'x-forgeflow-body-sha256':hashlib.sha256(data).hexdigest()}
        try:
            with urllib.request.urlopen(urllib.request.Request(target,data=data,headers=h),timeout=5) as response:return response.status,response.read(65536)
        except urllib.error.HTTPError as e:return e.code,e.read(65536)
    checks=[]
    for name in ('wrong-grant','wrong-model','wrong-cap','replay'):
        h=dict(headers);data=body
        if name=='wrong-grant':h['x-forgeflow-native-grant-id']=str(uuid.uuid4())
        if name in ('wrong-model','wrong-cap'):
            v=json.loads(body);v['model' if name=='wrong-model' else 'max_tokens']='unapproved-model' if name=='wrong-model' else 1;data=json.dumps(v).encode()
        status,raw=call(url,data,h);value=json.loads(raw);code=value.get('error',{}).get('code',value.get('code'))
        if status<400:raise RuntimeError('invalid native dispatch unexpectedly accepted')
        checks.append({'case':name,'status':status,'code':code,'response_sha256':hashlib.sha256(raw).hexdigest(),'upstream_count':sentinel.count})
    rpc={'schema_version':'forgeflow.dsh-bridge.v2','rpc_id':str(uuid.uuid4()),'operation':'model_settle','project_id':project,'task_id':row['task_id'] if 'task_id' in row else 't00000','attempt_id':attempt,'generation':row['generation'],'native_session_id':row['native_session_id'],'allocation_id':row['allocation_id'],'request_grant_id':row['request_grant_id'],'request_id':row['request_id'],'usage':{'input_tokens':0,'output_tokens':0},'usage_complete':True,'finish_reason':'stop'}
    # Canonical task identity comes from the actual root attempt, not a guessed row field.
    rpc['task_id']=query(private['DATABASE_URL'],f"SELECT to_json(task_id) FROM attempts WHERE attempt_id='{attempt}'")
    status,raw=call('http://127.0.0.1:8793/api/v1/attempts/'+attempt+'/native-controller',json.dumps(rpc).encode(),headers)
    reply=json.loads(raw)
    if reply.get('code')!='NATIVE_TRANSPORT_PENDING':raise RuntimeError('live transport settlement fence not observed')
    checks.append({'case':'live-transport-fence','status':status,'code':reply['code'],'upstream_count':sentinel.count})
    if sentinel.count!=1:raise RuntimeError('rejected probes caused upstream dispatch')
    save(output/'sentinel-negative-dispatches.json',{'checks':checks,'actual_upstream_count':sentinel.count,'model_provider_calls':0})
    sentinel.release.set()


class FixedCaptureRelay:
    """Diagnostic only: immutable server-owned upstream, one dispatch, bytes unchanged."""
    def __init__(self,gateway,private_root,prefix_limit):
        import threading, urllib.request, urllib.error, hashlib, hmac
        from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
        self.done=threading.Event();self.count=0;self.facts=None;self.directory=private_root/'upstream-capture';self.directory.mkdir(mode=0o700)
        endpoint=gateway['upstream_messages_url'];key=Path(gateway['upstream_secret_file']).read_text().strip();outer=self
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                if self.path!='/v1/messages' or not hmac.compare_digest(self.headers.get('x-api-key',''),key):self.send_error(403);return
                outer.count+=1
                if outer.count!=1:self.send_error(409);return
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=8388608:self.send_error(413);return
                body=self.rfile.read(size);headers={name:self.headers[name] for name in ('content-type','anthropic-version','anthropic-beta','accept','anthropic-dangerous-direct-browser-access') if self.headers.get(name) is not None};headers['x-api-key']=key
                facts={'provider_calls_actual':1,'fixed_endpoint_sha256':hashlib.sha256(endpoint.encode()).hexdigest(),'request_body_sha256':hashlib.sha256(body).hexdigest(),'request_header_names':sorted(headers),'redirects_allowed':False,'proxy_environment_used':False,'retries':0,'prefix_limit_bytes':prefix_limit,'received_bytes':0,'response_body_complete':False};sha=hashlib.sha256();prefix=bytearray();upstream=None
                try:
                    try:upstream=opener.open(urllib.request.Request(endpoint,data=body,headers=headers),timeout=120)
                    except urllib.error.HTTPError as error:upstream=error
                    facts['upstream_status']=upstream.status;facts['response_header_names']=sorted(name.lower() for name in upstream.headers.keys());facts['response_content_type']=upstream.headers.get('Content-Type','')
                    self.send_response(upstream.status)
                    for name in ('content-type','content-encoding','x-request-id','request-id'):
                        if upstream.headers.get(name) is not None:self.send_header(name,upstream.headers[name])
                    self.send_header('Connection','close');self.end_headers()
                    while True:
                        chunk=upstream.read1(8192)
                        if not chunk:facts['response_body_complete']=True;break
                        facts['received_bytes']+=len(chunk);sha.update(chunk)
                        if len(prefix)<prefix_limit:prefix.extend(chunk[:prefix_limit-len(prefix)])
                        if facts['received_bytes']>64*1024*1024:raise RuntimeError('UPSTREAM_RESPONSE_BOUND_EXCEEDED')
                        self.wfile.write(chunk);self.wfile.flush()
                except BaseException as error:
                    facts['error_type']=type(error).__name__
                finally:
                    if upstream is not None:upstream.close()
                    facts['received_body_sha256']=sha.hexdigest();facts['prefix_bytes']=len(prefix);facts['prefix_truncated']=facts['received_bytes']>len(prefix)
                    from prepare import private_write
                    private_write(outer.directory/'upstream-prefix.sse',bytes(prefix));save(outer.directory/'capture.json',facts,private=True);outer.facts=facts;outer.done.set()
        class Server(ThreadingHTTPServer):daemon_threads=True
        self.server=Server(('127.0.0.1',0),Handler);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.loopback_url=f'http://127.0.0.1:{self.server.server_port}/v1/messages'
    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(3)
        return {'request_count':self.count,'capture_private_root':str(self.directory),'capture_facts':self.facts,'listener_closed':not self.thread.is_alive(),'diagnostic_only_not_native_authority':True}


def run(args):
    modes = ('egress',)
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
    if not managed.get('model_relay'): raise RuntimeError('strict relay bundle required')
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
    gateway = json.loads(args.gateway_config.read_text())
    sentinel = Sentinel() if args.phase=='sentinel' else None
    if sentinel:
        secret=private_root/'sentinel.secret';secret.write_text('sentinel-no-provider-secret');secret.chmod(0o600)
        gateway.update(upstream_messages_url=f'http://127.0.0.1:{sentinel.server.server_port}/v1/messages',upstream_secret_file=str(secret))
        sentinel_config=private_root/'sentinel-gateway.json';save(sentinel_config,gateway,private=True)
        args.gateway_config=sentinel_config
    capture = FixedCaptureRelay(gateway,private_root,args.capture_upstream_prefix_bytes) if args.phase=='provider' and args.capture_upstream_prefix_bytes else None
    if capture:
        captured_gateway={**gateway,'upstream_messages_url':capture.loopback_url};capture_config=private_root/'captured-gateway.json';save(capture_config,captured_gateway,private=True);args.gateway_config=capture_config
    private['FORGEFLOW_GATEWAY_CONFIG'] = str(args.gateway_config.resolve())
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
              'current_frozen_model_request_cap': 1, 'actual_provider_calls_max': 1, 'canonical_total_wire_token_cap': args.wire_token_cap,
              'not_proven': ['100+ real sessions', 'fork/remote provider workload', 'full OS/model egress', 'complete financial accounting', 'code-writing Git integration', 'production qualification', 'PTC direct TCP separately requires actual tool coverage']}
    report['_redact'] = redactor(managed, private)
    server = worker = None
    try:
        report['project_id'] = 'g07-native-' + uuid.uuid4().hex[:12]
        report['worker_id'] = 'g07-worker-' + uuid.uuid4().hex[:12]
        private.update(FORGEFLOW_WORKER_ID=report['worker_id'],FORGEFLOW_WORKER_PROJECT_ID=report['project_id'])
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
        readonly += [str(Path(managed['model_relay']['transport_loader']))]
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
        save(output / 'actual-worker-registration.json', wait_for(registered, 40, 'actual Worker registration'))
        limits = {**vector(8), 'cpu_units': 8000, 'memory_bytes': 2 * 1024 * 1024 * 1024, 'provider_inflight': 8}
        for scope, scope_project, scope_team, scope_worker in (('global', None, None, None), ('project', project, None, None), ('worker', None, None, worker_id), ('root-team', project, 'root', None), ('leaf-team', project, 'leaf', None)):
            api(client, 'POST', '/resource-policies', {'policy': {'scope_id': scope, 'parent_scope_id': 'root-team' if scope == 'leaf-team' else None, 'project_id': scope_project, 'team_id': scope_team, 'worker_id': scope_worker, 'limits': limits, 'revision': 0, 'paused': False}})
        child_resources = {**vector(1), 'cpu_units': 500, 'memory_bytes': 128 * 1024 * 1024, 'provider_inflight': 1}
        root_resources = {**vector(1), 'cpu_units': 500, 'memory_bytes': 512 * 1024 * 1024, 'provider_inflight': 1}
        child_policy = {'schema_version': 'forgeflow.native-child-policy.v1', 'enabled': True, 'max_live_agents': 4, 'max_lifecycles': 5, 'max_delegation_depth': 2, 'model_inflight_limit': 4, 'child_resources': child_resources}
        for collection, identity, value in (('executor_profiles', profile['id'], {**profile, 'kind': 'DSH_MANAGED', 'native_mode': managed}), ('resource_profiles', 'canonical-native.v2', {'id': 'canonical-native.v2', 'stage_resource_mode': 'ATTEMPT_RESERVATION', 'isolation_profile': 'BWRAP_LANDLOCK_EXACT', 'sandbox': sandbox, 'native_child_policy': child_policy, 'physical_limits': PHYSICAL_LIMITS}), ('model_routes', profile['model_route_id'], {'id': profile['model_route_id'], 'provider': 'newapi', 'model': 'glm-5.3', 'max_output_tokens': args.wire_token_cap})):
            api(client, 'POST', f'/projects/{project}/documents/{collection}', {'id': identity, 'value': value})
        manifest_text = json.dumps({'files': [], 'mandatory_paths': [], 'artifact_inputs': []}, separators=(',', ':'))
        manifest = api(client, 'POST', f'/projects/{project}/artifacts', {'content_utf8': manifest_text, 'kind': 'CONTEXT_MANIFEST'})['data']
        case = make_compile(len(modes))
        case['flow']['project_id'] = project
        meaning = requirement_digest(requirement)
        case['context'].update(owners=[{'owner_id': 'root', 'root_team_id': 'root', 'include': ['baseline.txt'], 'exclude': []}], current_inputs={}, requirement_semantic_digests={'R01': meaning}, requirements=[{'requirement_id': 'R01', 'source_document': 'canonical-native', 'anchor': 'R01', 'acceptance': '\n'.join(requirement['acceptance']), 'priority': 1, 'deferred_reason': None}])
        for mode, task in zip(modes, case['flow']['tasks']):
            prompt_text = 'Read-only transport point. Do not call tools, workflow, subagents or modify files. Reply exactly: ONE_SHOT_RECEIPT WORKFLOW_RECEIPT TEAM_RECEIPT TEAM_RESUME_RECEIPT.'
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
            negative_checked=False
            def acknowledged():
                nonlocal negative_checked
                if sentinel and sentinel.hit.is_set() and not negative_checked:
                    negative_dispatches(sentinel,private,project,worker_id,attempt,output);negative_checked=True
                if worker.poll() is not None:
                    raise RuntimeError('managed Worker exited before native result acknowledgement')
                if (journal / 'result-ack.json').exists():
                    return True
                stop_path = journal / 'stop.json'
                if stop_path.exists():
                    stopped = json.loads(stop_path.read_text())
                    if stopped.get('process_exit_confirmed') and stopped.get('exit_code') != 0:
                        raise RuntimeError('NATIVE_EXECUTOR_FAILED_BEFORE_ACK exit=' + str(stopped.get('exit_code')) + '; preserve original native session and transport quarantine')
                return False
            wait_for(acknowledged, 510, 'actual native Worker stop and canonical result acknowledgement')
            facts = native_rows(private['DATABASE_URL'], attempt)
            save(output / 'egress.native-facts.json', facts)
            models = facts['native_model_requests']
            if len(models) != 1 or models[0]['status'] != 'SETTLED' or not models[0]['usage_complete']:
                raise RuntimeError('one actual native model request must settle with trusted complete usage')
            transport = query(private['DATABASE_URL'], f"SELECT json_build_object('dispatched',dispatched_at IS NOT NULL,'body_sha256',dispatch_body_sha256,'transport',dispatch_transport_settlement) FROM native_model_requests WHERE attempt_id='{attempt}'")
            save(output / 'egress.transport.json', transport)
            if not transport['dispatched'] or not transport['transport']['usage_complete'] or transport['transport']['outcome'] != 'RESPONSE_BODY_COMPLETED':
                raise RuntimeError('trusted production transport closure missing')
            relay_stop = json.loads((journal/'model-relay-stop.json').read_text()) if (journal/'model-relay-stop.json').exists() else None
            save(output / 'egress.relay-stop.json', relay_stop)
            current = api(client, 'GET', f'/attempts/{attempt}?project_id={project}')['data']
            if current['state'] not in ('SUCCEEDED','FAILED','CANCELLED'):
                api(client,'POST',f'/attempts/{attempt}/cancel',{'project_id':project,'expected_revision':current['revision'],'reason':'G07 one-request transport point complete; no business completion claim'})
                wait_for(lambda: api(client,'GET',f'/attempts/{attempt}?project_id={project}')['data']['state'] in ('FAILED','CANCELLED'),40,'legal point resource closure')
            report['actual_sdk_transport'] = 'STOCK_DSH_ANTHROPIC_STREAM_THROUGH_UDS_API_GATEWAY'
            report['gateway_coverage_verified'] = False
            report['business_completion_claimed'] = False
    except BaseException as error:
        report['interrupted'] = isinstance(error, (KeyboardInterrupt, SystemExit))
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
        if sentinel: sentinel.close()
        if capture: report['upstream_capture']=capture.close()
        report['phase']=args.phase
        report['provider_calls']=0 if sentinel else report.get('final_actual_model_requests',0)
        report.pop('_redact')
        report['status'] = 'FAIL' if report['errors'] else 'PASS_ONE_NATIVE_PROVIDER_TRANSPORT_POINT'
        report['evidence_sha256'] = {path.name: digest(path) for path in output.iterdir() if path.is_file()}
        save(output / 'report.json', report)
        print(json.dumps({'status': report['status'], 'errors': report['errors'], 'attempts': report['attempts'], 'private_root': str(private_root), 'output': str(output)}))
    return 1 if report['errors'] else 0


def prepare_point(args):
    import tempfile, shutil, hashlib
    from prepare import prepare, private_write
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    if any(output.iterdir()):raise RuntimeError('fresh prepare output required')
    old=json.loads((args.source_prepared/'managed-config.json').read_text())
    original_rows=json.loads(Path(old['selected_model_config']).read_text())
    selected=next(r['config'] for r in original_rows if r['id']=='agent-default-model');provider=selected['provider'];model=selected['model']
    providers=next(r['config']['providers'] for r in original_rows if r['id']=='llm-pi-ai');approved=providers[provider]
    original_credentials=yaml.safe_load(Path(old['credentials']).read_text());secret_value=original_credentials['refs'][approved['apiKeyEnv']]
    if not isinstance(secret_value,str) or not secret_value:raise RuntimeError('selected provider secret must be private scalar')
    private=Path(tempfile.mkdtemp(prefix='ff-g07-model-relay-',dir='/tmp'));private.chmod(0o700)
    source=private/'dummy-source';source.mkdir(mode=0o700)
    rows=json.loads(json.dumps(original_rows));dummy=next(r['config']['providers'][provider] for r in rows if r['id']=='llm-pi-ai')
    dummy['apiKeyEnv']='FORGEFLOW_MODEL_RELAY_DUMMY';dummy['baseURL']='http://forgeflow-model.invalid'
    private_write(source/'cordis.patch.yml',yaml.safe_dump(rows).encode());private_write(source/'.credentials.yaml',json.dumps({'version':1,'refs':{'FORGEFLOW_MODEL_RELAY_DUMMY':'forgeflow-relay-no-provider-secret'}}).encode())
    bundle_root=private/'prepared'
    prepare(bundle_root,source_home=source,profile_id='forgeflow-g07-strict-native-v1',published_receipt=output/'base-doctor-source-ready.json',qualification=False)
    bundle=bundle_root/'bundle';bundle.chmod(0o755);loader=bundle/'model-transport.mjs';private_write(loader,(ROOT/'crates/executors/presets/forgeflow/model-transport.mjs').read_bytes());loader.chmod(0o444);bundle.chmod(0o555)
    profile=json.loads((bundle_root/'headless-profile.json').read_text());managed=json.loads((bundle_root/'managed-config.json').read_text());doctor=json.loads(Path(managed['doctor']).read_text())
    relay={'schema_version':'forgeflow.model-uds.v1','transport_loader':str(loader),'sdk_origin':'http://forgeflow-model.invalid','max_request_bytes':8388608,'response_idle_timeout_ms':30000};managed['model_relay']=relay;managed['rpc_timeout_ms']=5000
    patch=bundle_root/'doctor-bridge-relay.patch.json';save(patch,[{'insert':[{'id':'forgeflow-managed-children','name':managed['bridge_plugin'],'config':{'socket_path':'/tmp/forgeflow/controller.sock','rpc_timeout_ms':5000,'project_id':'doctor-only','task_id':'doctor-only','attempt_id':'doctor-only','generation':1,'model_relay':{**relay,'socket_path':'/tmp/forgeflow/model.sock'}}}]}],private=True)
    # Bridge config has no transport_loader: that path belongs to the trusted Worker only.
    bridge=json.loads(patch.read_text());bridge[0]['insert'][0]['config']['model_relay'].pop('transport_loader');patch.write_text(json.dumps(bridge));patch.chmod(0o600)
    cmd=[profile['program'],'--import',str(loader),*profile['prefix_args'],'--profile','headless','--patch',managed['preset_patch'],'--patch',str(patch),'--dump-config']
    env={'PATH':'/usr/bin:/bin','HOME':profile['home'],'DSH_HOME':profile['home']}
    actual=subprocess.run(cmd,env=env,cwd=bundle_root,capture_output=True,timeout=45);private_write(bundle_root/'relay-doctor.stdout',actual.stdout);private_write(bundle_root/'relay-doctor.stderr',actual.stderr)
    if actual.returncode:raise RuntimeError('actual strict loader doctor failed; private diagnostics retained')
    inventory=dict(doctor['artifact_sha256']);inventory[str(loader)]=digest(loader);inventory[str(patch)]=digest(patch)
    doctor.update(command=cmd,exit_code=actual.returncode,composition_sha256=hashlib.sha256(actual.stdout).hexdigest(),artifact_sha256=inventory,scope='Actual stockCLI --import strict model loader --dump-config, dummy credentials; zero model calls; no runtime coverage claimed')
    Path(managed['doctor']).write_text(json.dumps(doctor,indent=2)+'\n');Path(managed['doctor']).chmod(0o600)
    inventory[str(Path(managed['doctor']))]=digest(managed['doctor']);profile['artifact_pins']=[{'path':k,'sha256':v} for k,v in sorted(inventory.items())]
    profile['gateway_coverage_verified']=False
    (bundle_root/'headless-profile.json').write_text(json.dumps(profile,indent=2)+'\n');(bundle_root/'managed-config.json').write_text(json.dumps(managed,indent=2)+'\n')
    secret=private/'provider.secret';private_write(secret,secret_value.encode());base=approved['baseURL'].rstrip('/');endpoint=(base+'/messages' if base.endswith('/v1') else base+'/v1/messages')+'?beta=true'
    gateway=private/'gateway.json';save(gateway,{'route_id':profile['model_route_id'],'model':model,'upstream_messages_url':endpoint,'upstream_secret_file':str(secret),'limits':{'per_attempt_inflight':1,'global_inflight':1,'project_inflight':1,'global_window_requests':2,'project_window_requests':2,'route_window_requests':2,'window_seconds':60},'timeout_seconds':120},private=True)
    common=['/usr/bin/python3','-B',str(Path(__file__).resolve()),'--run','--approved-model-request-cap','1','--prepared-root',str(bundle_root),'--private-env',str(args.private_env.resolve()),'--gateway-config',str(gateway),'--wire-token-cap',str(args.wire_token_cap),'--capture-upstream-prefix-bytes',str(args.capture_upstream_prefix_bytes)]
    plan={'status':'SOURCE_READY_WAITING_ROOT_BUILD_GO','driver_sha256':digest(__file__),'prepared_root':str(bundle_root),'profile_sha256':digest(bundle_root/'headless-profile.json'),'doctor_sha256':digest(managed['doctor']),'bridge_sha256':digest(managed['bridge_plugin']),'loader_sha256':digest(loader),'provider_config_private_path':str(gateway),'provider_calls_max':1,'sentinel_provider_calls':0,'sentinel_already_passed_not_repeated':True,'canonical_total_wire_token_cap':args.wire_token_cap,'thinking_budget_expected':16384 if args.wire_token_cap==20480 else 3072,'provider_query':'beta=true','diagnostic_capture_prefix_max_bytes':args.capture_upstream_prefix_bytes,'diagnostic_relay':{'fixed_upstream_only':True,'redirects':False,'retries':0,'proxy_environment':False,'private_capture_mode':'0600','native_models_max':1,'actual_provider_calls_max':1},'model_budget_mode':'direct_observed','gateway_coverage_verified':False,'commands':[common+['--phase',phase,'--output',str(output/('actual-'+phase+'-r1')),'--build-receipt','ROOT_FROZEN_RECEIPT_REQUIRED'] for phase in ('provider',)],'not_proven':['actual native runtime until GO','actual PTC direct TCP tool coverage','whole transitive dependency inventory','full enterprise native scale']}
    save(output/'plan.json',plan);print(json.dumps({'status':plan['status'],'plan_sha256':digest(output/'plan.json'),'prepared_root':str(bundle_root),'driver_sha256':plan['driver_sha256']}))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--wire-token-cap',type=int,choices=(4096,20480),default=4096)
    p.add_argument('--capture-upstream-prefix-bytes',type=int,choices=(0,65536),default=0)
    p.add_argument('--prepare-only',action='store_true');p.add_argument('--source-prepared',type=Path)
    p.add_argument('--phase',choices=('sentinel','provider'),default='provider')
    p.add_argument('--run',action='store_true');p.add_argument('--approved-model-request-cap',type=int)
    for name in ('build-receipt','prepared-root','private-env','gateway-config','output'):p.add_argument('--'+name,type=Path,required=name in ('private-env','output'))
    p.add_argument('--source-authority',choices=('current-tree','checkpoint-snapshot'),default='current-tree')
    a=p.parse_args()
    if a.prepare_only:
        if not a.source_prepared:raise SystemExit('prepare requires original private provider source bundle')
        prepare_point(a);return
    if not a.run or a.approved_model_request_cap!=1 or not a.build_receipt or not a.prepared_root or not a.gateway_config:raise SystemExit('Run requires Root GO and exact cap1 with frozen inputs')
    raise SystemExit(run(a))
if __name__=='__main__':main()

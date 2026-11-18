#!/usr/bin/env python3
"""One Root-approved real business Worker chain with required physical fencing.

Default prepares source/pin/limit facts only. Execution creates one private DB,
API and delegated business Worker, without a model call or main-service mutation.
Failures and exact credential-bearing HTTP/Worker files stay private; delivery
HTTP is the existing explicit redacted projection. Never rerun an actor here.
"""
from __future__ import annotations
import argparse
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
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'verification'))
sys.path.insert(0, str(ROOT / 'verification/fixtures'))
from cross_project_business_chain import (Client, Events, actual_running, git,
    ledger_totals, paused, private_bytes, project_public, save, stop_attempt, wait)
from guarded_api_chain import create_database, database_command, secure_save
from algorithm_check import make_compile, refresh_digest, requirement_digest, vector
from metrics import process_fingerprint
import control_verifier

PINNED = 'bec66d0ddfbbf645e025501c64890195bc738e871e292a8e5ff48823738a8dee'
RESOURCE_PROFILE = 'physical-controlled-root.v1'
POLICY = {'schema_version': 'forgeflow.physical-limits.v1', 'required': True,
          'cpu_units_per_cpu': 1000, 'period_us': 100000, 'pids_max': 64,
          'swap_max_bytes': 0, 'memory_oom_group': True}
REQUEST = dict(vector(1), coding_slot=1, cpu_units=250, memory_bytes=256*1024*1024)
EXPECTED = {'cpu.max': '25000 100000', 'memory.max': '268435456',
            'memory.swap.max': '0', 'pids.max': '64', 'memory.oom.group': '1'}
AUTHOR = '''import json,os,pathlib,sys,time
pathlib.Path(sys.argv[1]).write_text(json.dumps({'kind':'CONTROL_LOAD','seed':int(sys.argv[2])})+'\\n')
print(json.dumps({'kind':'CONTROL_LOAD','started':True,'pid':os.getpid()}),flush=True)
begin=time.monotonic_ns(); accumulator=1
while time.monotonic_ns()-begin < 8_000_000_000:
 for _ in range(4096):accumulator=(accumulator*1664525+1013904223)&0xffffffff
print(json.dumps({'kind':'CONTROL_LOAD','cpu_complete':True,'elapsed_ns':time.monotonic_ns()-begin,'checksum':accumulator}),flush=True)
'''
VERIFIER_AUTHOR = '''import json,os,pathlib,sys,time
pathlib.Path(sys.argv[1]).write_text(json.dumps({'kind':'CONTROL_LOAD','seed':int(sys.argv[2])})+'\\n')
print(json.dumps({'kind':'CONTROL_LOAD','started':True,'pid':os.getpid()}),flush=True)
time.sleep(2)
print(json.dumps({'kind':'CONTROL_LOAD','finite_output_ready':True}),flush=True)
'''
VERIFIER_WRAPPER = '''import json,os,runpy,time
role=os.environ['FORGEFLOW_VERIFICATION_ROLE'];begin=time.monotonic_ns();cpu_begin=time.process_time_ns();checksum=1
if role=='independent':
 while time.monotonic_ns()-begin < 2_000_000_000:
  for _ in range(4096):checksum=(checksum*1664525+1013904223)&0xffffffff
else:
 for _ in range(65536):checksum=(checksum*1664525+1013904223)&0xffffffff
print(json.dumps({{'kind':'VERIFIER_PHYSICAL_CPU','role':role,'elapsed_ns':time.monotonic_ns()-begin,'process_cpu_ns':time.process_time_ns()-cpu_begin,'checksum':checksum}}),flush=True)
module=runpy.run_path({oracle_path!r})
raise SystemExit(module['main']())
'''
REQUIRED_RAW = ('cgroup-fence.json', 'cgroup-membership.json', 'cgroup-stop.json',
                'launch-intent.json', 'launch-receipt.json', 'sandbox.json', 'stop.json')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unit_properties(name):
    result = subprocess.run(['systemctl', '--user', 'show', name, '--property=LoadState',
        '--property=ActiveState', '--property=SubState', '--property=MainPID',
        '--property=ControlGroup', '--property=Result', '--property=ExecMainStatus'],
        text=True, capture_output=True, check=True, timeout=15)
    return dict(line.split('=', 1) for line in result.stdout.splitlines())


def counters(text):
    return {line.split()[0]: int(line.split()[1]) for line in text.strip().splitlines()}


def loaded(path):
    return json.loads(Path(path).read_text())


def child_json(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Pinned delegated launcher refused; private preparation retained')
    return json.loads(result.stdout)


def source_plan(args):
    receipt = loaded(args.build_receipt)
    selected_identity=args.expected_source_identity if args.verifier_physical else PINNED
    if not selected_identity or receipt['source_identity'] != selected_identity or not receipt['consistent_copy'] or not receipt['source_unchanged_after_build'] or any(c['exit_code'] != 0 for c in receipt['commands']):
        raise RuntimeError('Exact successful Root-approved build required')
    pins = []
    for name in ('forgeflow-server', 'forgeflow-worker', 'forgeflow-sandbox-guard'):
        value = receipt['binaries'][name]
        if sha(value['path']) != value['sha256']:
            raise RuntimeError('Pinned current binary differs: '+name)
        pins.append(dict(name=name, **value))
    helper_paths = [Path(__file__), ROOT/'ops/run-delegated-worker.py',
        ROOT/'verification/cross_project_business_chain.py',
        ROOT/'verification/guarded_api_chain.py', ROOT/'verification/algorithm_check.py',
        ROOT/'verification/fixtures/control_verifier.py', Path('/usr/bin/python3').resolve(),
        Path('/usr/bin/bwrap')]
    if args.port in (8787, 8788) or not 1024 <= args.port <= 65535:
        raise RuntimeError('Refuse primary/old QA or invalid port')
    if args.verifier_physical:
        if args.runtime_release is None or args.api_service_name is None:
            raise RuntimeError('Verifier proof requires Root-pinned runtime release and exact fresh API service name')
        import re
        if not re.fullmatch(r'forgeflow-control-[0-9a-f]{32}',args.api_service_name):
            raise RuntimeError('Verifier proof uses only one unique dedicated API unit')
        manifest=loaded(args.runtime_release/'delivery-manifest.json')
        if manifest['files']['bin/forgeflow-server']['sha256']!=receipt['binaries']['forgeflow-server']['sha256']:
            raise RuntimeError('Installed candidate API differs from selected build')
        if sha(args.runtime_release/'bin/forgeflow-server')!=receipt['binaries']['forgeflow-server']['sha256']:
            raise RuntimeError('Candidate API installed bytes differ')
        helper_paths.extend([ROOT/'ops/manage-service.py',ROOT/'ops/run-service.py'])
    result={'schema_version':'forgeflow.physical-business-source-plan.v1',
        'status':'SOURCE_READY_NO_ACTORS', 'source_identity':selected_identity,
        'build_receipt':{'path':str(args.build_receipt.resolve()), 'sha256':sha(args.build_receipt)},
        'binaries':pins, 'source_pins':[{'path':str(p.resolve()), 'sha256':sha(p)} for p in helper_paths],
        'port':args.port, 'main_pid':args.main_pid, 'resource_profile_id':RESOURCE_PROFILE,
        'physical_limits':POLICY, 'root_resources':REQUEST, 'native_max_concurrent_children':0,
        'strong_sandbox':{'type':'BWRAP_LANDLOCK_EXACT','network_allowed':False,'host_cgroupfs_exposed':False},
        'author_seconds':0 if args.verifier_physical else 8,
        'author_sha256':hashlib.sha256((VERIFIER_AUTHOR if args.verifier_physical else AUTHOR).encode()).hexdigest(),
        'business_output':'result.json', 'candidate_expected_cases':8, 'integrated_expected_cases':8,
        'models':0, 'apis_started':0, 'workers_started':0,
        'execution_requires_explicit_root_go_and_plan_sha256':True,
        'qualification':'One API-admitted requiredphysical controlledroot, nativechildren0; noDSH/hostile/production100 qualification; API-verifier OS hardlimit remains unproven'}
    if args.verifier_physical:
        result.update(verifier_physical=True,api_unit_name=args.api_service_name+'.service',
            runtime_release={'path':str(args.runtime_release.resolve()),'manifest_sha256':sha(args.runtime_release/'delivery-manifest.json')},
            oracle_wrapper_sha256=hashlib.sha256(VERIFIER_WRAPPER.format(oracle_path=str(ROOT/'verification/fixtures/control_verifier.py')).encode()).hexdigest(),
            verifier_independent_cpu_seconds=2,qualification='One local admitted controlledroot and actual API-side candidate/integrated physical verifier6 sequentialcommands sharing frozen reservationSHA; noDSH/nativechild/hostile/production100 qualification')
    return result


def create_fixture(client, private, receipt, verifier_physical=False):
    """Use the existing compiler/semantic/verifier contracts for one changed profile."""
    project = 'physical-business-'+uuid.uuid4().hex[:16]
    seed = private/'seed';seed.mkdir()
    git(seed, 'init', '--initial-branch=main')
    (seed/'README.txt').write_text('One required physical controlledroot business delivery.\n')
    git(seed, 'add', 'README.txt')
    git(seed, '-c','user.name=Physical fixture','-c','user.email=fixture@localhost', 'commit','-m','Physical business baseline')
    baseline = git(seed,'rev-parse','HEAD')
    canonical = private/'canonical.git'
    subprocess.run(['git','clone','--bare','--no-hardlinks',str(seed),str(canonical)],check=True,capture_output=True)
    created = client.api('POST','/projects',{'project_id':project,'name':'Required physical controlled business chain',
        'root_path':str(canonical),'authority_mode':'MANAGED','data_origin':'NATIVE','goal':'Actual required physical admission, output, independent verification and fenced integration',
        'technology_stack':['controlled Python'],'timezone':'Asia/Shanghai','paused':True,'archived':False,'revision':0})
    canonical = Path(created['root_path'])
    for index in range(4):
        client.api('POST',f'/projects/{project}/teams',{'project_id':project,'team_id':f'level-{index}',
            'parent_team_id':f'level-{index-1}' if index else None,'name':f'Physical level {index}','paused':False,'revision':0})
    client.api('POST',f'/projects/{project}/owners',{'id':'level-3','value':{'owner_id':'level-3','root_team_id':'level-0','include':['result.json'],'exclude':[]}})
    req = client.api('POST',f'/projects/{project}/requirements',{'project_id':project,'requirement_id':'R01','title':'Physical business result',
        'source_anchor':'physical-business#R01','outcome':'Actual physically fenced controlled delivery','scope':'One declared finite JSON output',
        'acceptance':['Required CPU/memory/pids readback, verified output, fenced Git and positive physical release'],
        'priority':1,'weight':1,'deferred_reason':None,'revision':0})
    worker = 'worker-'+project
    home = private/'controlled-home';home.mkdir()
    program = '/usr/bin/python3'
    approved = {program:sha(program)}
    oracle = ROOT/'verification/fixtures/control_verifier.py'
    oracle_inputs=[oracle]
    if verifier_physical:
        wrapper=private/'registered-physical-verifier.py'
        private_bytes(wrapper,VERIFIER_WRAPPER.format(oracle_path=str(oracle)).encode())
        oracle_inputs.append(wrapper)
        oracle=wrapper
    sandbox = {'bwrap_program':'/usr/bin/bwrap','bwrap_sha256':sha('/usr/bin/bwrap'),
        'guard_program':receipt['binaries']['forgeflow-sandbox-guard']['path'],
        'guard_sha256':receipt['binaries']['forgeflow-sandbox-guard']['sha256'],
        'readonly_paths':[p for p in ('/usr','/bin','/lib','/lib64') if Path(p).exists()]+[str(p) for p in oracle_inputs],'network_allowed':False}
    config = {'control_url':client.base_url,'worker_id':worker,'project_id':project,'data_root':str(private/'state'),
        'model_route_id':'controlled-none','max_active_attempts':1,'poll_seconds':1,'max_log_bytes':1048576,
        'controlled_workload_programs':approved,'strict_resource_handoff':False,'sandbox':sandbox,
        'profile':{'id':'controlled-lightweight.v1','program':program,'prefix_args':[],'home':str(home),'profile_name':'headless',
            'artifact_pins':[],'resume_verified':False,'model_route_id':'controlled-none','gateway_coverage_verified':False}}
    config_path=private/'worker-config.json';secure_save(config_path,config)
    token_path=private/'worker-env.json';secure_save(token_path,{'FORGEFLOW_WORKER_TOKEN':client.worker_token,'RUST_LOG':'info'})
    return {'project':project,'worker':worker,'config':config_path,'env':token_path,
        'canonical':canonical,'baseline':baseline,'sandbox':sandbox,'requirement':req,
        'program':program,'approved_programs':approved,'oracle':oracle,'oracle_inputs':oracle_inputs,'verifier_physical':verifier_physical}


def finalize_fixture(client, private, fixture):
    # Worker scopes may only reference the actual protocol-created registration.
    # Keep the project paused until every immutable profile/Flow is committed.
    project=fixture['project'];worker=fixture['worker'];canonical=fixture['canonical'];baseline=fixture['baseline']
    sandbox=fixture['sandbox'];req=fixture['requirement'];program=fixture['program'];approved=fixture['approved_programs'];oracle=fixture['oracle']
    for collection, identity, value in [
        ('executor_profiles','controlled-lightweight.v1',{'id':'controlled-lightweight.v1','kind':'CONTROLLED_LIGHTWEIGHT','approved_programs':approved}),
        ('resource_profiles',RESOURCE_PROFILE,{'id':RESOURCE_PROFILE,'scope':'CONTROL_LOAD','stage_resource_mode':'ATTEMPT_RESERVATION',
            'max_log_bytes':1048576,'sandbox':sandbox,'physical_limits':POLICY}),
        ('model_routes','controlled-none',{'id':'controlled-none','kind':'NO_MODEL','model_requests':0})]:
        client.api('POST',f'/projects/{project}/documents/{collection}',{'id':identity,'value':value})
    scopes=[('global',None,None,None,None),(project+':project',project,None,None,'global'),
        (project+':worker',None,None,worker,'global')]+[(project+f':level-{i}',project,f'level-{i}',None,
        project+(f':level-{i-1}' if i else ':project')) for i in range(4)]
    for identity,p,t,w,parent in scopes:
        client.api('POST','/resource-policies',{'policy':{'scope_id':identity,'parent_scope_id':parent,'project_id':p,
            'team_id':t,'worker_id':w,'limits':REQUEST,'revision':0,'paused':False}})
    prompt=client.api('POST',f'/projects/{project}/artifacts',{'content_utf8':'Run the pinned finite CPU phase and declared result; no models.\n','kind':'PROMPT'})
    manifest_text='{"files":[],"mandatory_paths":[],"artifact_inputs":[]}'
    manifest=client.api('POST',f'/projects/{project}/artifacts',{'content_utf8':manifest_text,'kind':'CONTEXT_MANIFEST'})
    case=make_compile(1);case['flow']['project_id']=project
    meaning=requirement_digest(req)
    case['context'].update(owners=[{'owner_id':'level-3','root_team_id':'level-0','include':['result.json'],'exclude':[]}],
        current_inputs={},resolved_paths={},requirement_semantic_digests={'R01':meaning},requirements=[{'requirement_id':'R01',
        'source_document':'physical-business','anchor':'R01','acceptance':'\n'.join(req['acceptance']),'priority':1,'deferred_reason':None}])
    task=case['flow']['tasks'][0];plan_id='physical-verify-'+task['task_id'];seed_value=731
    task.update(project_id=project,owner_id='level-3',team_id='level-3',read_set=[],write_set=['result.json'],dependencies=[],resource_request=REQUEST)
    spec=case['context']['task_specs'][task['task_id']]
    spec.update(inputs=[],mandatory_paths=[],dependency_refs=[],requirement_digest_refs={'R01':meaning},
        design_anchors=['physical-business#R01'],execution_profile='controlled-lightweight.v1',verification_plan=plan_id,verification_case_count=8)
    now=datetime.now(timezone.utc)
    task['envelope']={'schema_version':'forgeflow.execution.v1','operation_id':'pending','project_id':project,'task_id':task['task_id'],
        'task_revision':1,'attempt_id':'pending','lease_id':'pending','generation':1,'worker_id':worker,'workspace_root':str(canonical),'base_sha':baseline,
        'context_manifest':{'artifact_id':manifest['artifact_id'],'sha256':manifest['sha256'],'mandatory_paths':[],
            'rendered_utf8_bytes':len(manifest_text),'token_estimate':None,'tokenizer_id':None},'write_set':['result.json'],
        'prompt_artifact':{'artifact_id':prompt['artifact_id'],'sha256':prompt['sha256']},'model_route_id':'controlled-none',
        'executor_profile_id':'controlled-lightweight.v1','resource_profile_id':RESOURCE_PROFILE,'verification_plan_id':plan_id,
        'allowed_effects':['READ_WORKSPACE','WRITE_DECLARED_PATHS','RUN_APPROVED_COMMANDS'],'issued_at':now.isoformat(),
        'expires_at':(now+timedelta(seconds=120)).isoformat(),'deadline_at':(now+timedelta(minutes=10)).isoformat(),
        'artifact_prefix':str(private/'state/artifacts'),'secret_refs':[],'idempotency_key':'pending','trace_id':'physical-business',
        'enforcement':{'model_budget_mode':'direct_observed','stage_resource_mode':'ATTEMPT_RESERVATION','build_capable':False,
            'gateway_coverage_receipt_id':None,'tool_guard_receipt_id':None,'attempt_reserved_build_permits':0,
            'all_model_routes_covered':False,'disabled_tool_entry_ids':[]},'session_purpose':'EXECUTION','max_model_requests':0,
        'resume_session_id':None,'command':{'program':program,'args':['-I','-B','-c',VERIFIER_AUTHOR if fixture['verifier_physical'] else AUTHOR,'result.json',str(seed_value)]}}
    refresh_digest(task,spec)
    commands=[{'role':role,'program':program,'args':['-I','-B',str(oracle)],'env':{'FORGEFLOW_VERIFICATION_ROLE':role,
        'FORGEFLOW_EXPECTED_SEED':str(seed_value),'FORGEFLOW_OUTPUT_PATH':'result.json'},'executable_hash':sha(program),
        'bound_inputs':[{'path':str(p),'sha256':sha(p)} for p in fixture['oracle_inputs']],'report_path':role+'.json',
        'expected_cases':[{'name':n,'kind':k} for n,k in control_verifier.CASES[role]],'timeout_seconds':30} for role in ('author','consumer','independent')]
    client.api('POST',f'/projects/{project}/documents/verification_plans',{'id':plan_id,'value':{'plan_id':plan_id,'task_revision':1,
        'input_hash':task['input_digest'],'contract_version':'controlled-output.v1','environment_profile':'bounded-physical-business-output',
        'oracle_id':control_verifier.ORACLE,'verifier_id':'independent-controlled-output-oracle','author_id':worker,'commands':commands}})
    saved=client.api('POST',f'/projects/{project}/flow-revisions',{'flow':case['flow'],'context':case['context']})
    committed=client.api('POST',f'/flows/{project}:1/commit',{'expected_revision':saved['revision']})
    fixture.update(task=committed['tasks'][0],scope_ids=[s[0] for s in scopes],
        expected_blob=(json.dumps({'kind':'CONTROL_LOAD','seed':seed_value})+'\n').encode())
    return fixture


def retain_verifier_physical(args, fixture, attempt, binding, verifier_sources, api_unit, report, check):
    """Read the actual completed six command journals and still-existing own leaves."""
    destination=args.output/'verifier-raw';destination.mkdir()
    stages=[];all_ids=set();busy_stages=[]
    expected_limits={'cpu_quota_us':25000,'cpu_period_us':100000,'memory_max_bytes':268435456,
        'memory_swap_max_bytes':0,'pids_max':64,'memory_oom_group':True}
    unit_root=Path('/sys/fs/cgroup')/unit_properties(api_unit)['ControlGroup'].lstrip('/')
    for stage, verifier_root, _ in verifier_sources:
        context=loaded(verifier_root/'verification-physical-context.json')
        closed=loaded(verifier_root/'verification-physical-closed.json')
        request=context['physical_request'];commands=context['commands']
        check(stage+'_exclusive_same_frozen_pool_context',context['schema_version']=='forgeflow.physical-verification.v1' and
            context['parent_attempt_id']==attempt['attempt_id'] and context['generation']==attempt['generation'] and
            Path(context['verifier_root'])==verifier_root and request['project_id']==fixture['project'] and
            request['resource_binding_sha256']==binding['reservation_sha256'] and request['limits']==expected_limits and
            request['delegation']=={'unit_name':api_unit,'root_path':str(unit_root)} and
            len(commands)==3 and [c['role'] for c in commands]==['author','consumer','independent'],context)
        stage_output=destination/stage;stage_output.mkdir()
        for name in ('verification-physical-context.json','verification-physical-closed.json'):
            target=stage_output/name;shutil.copyfile(verifier_root/name,target)
            report['raw_manifest'].append({'path':str(target.relative_to(ROOT)),'sha256':sha(target),'bytes':target.stat().st_size})
        observations=[]
        for command in commands:
            execution=command['execution_id'];check(stage+'_'+command['role']+'_unique_command_grant',execution not in all_ids,command);all_ids.add(execution)
            journal=verifier_root/'verification-runs'/command['process_attempt_id']
            command_record=loaded(journal/'verification-command.json');launch=loaded(journal/'launch-receipt.json')
            fence=loaded(journal/'cgroup-fence.json');member=loaded(journal/'cgroup-membership.json')
            stop=loaded(journal/'cgroup-stop.json');process_stop=loaded(journal/'stop.json')
            leaf=Path(fence['leaf_path'])
            check(stage+'_'+command['role']+'_actual_grant_launch_membership',command_record=={'context':context,'command':command} and
                fence['attempt_id']==command['process_attempt_id'] and fence['execution_id']==execution and
                fence['generation']==attempt['generation'] and fence['resource_binding_sha256']==binding['reservation_sha256'] and
                fence['limits']==expected_limits and fence['delegation']==request['delegation'] and leaf.parent==unit_root and
                leaf.stat().st_ino==fence['leaf_inode'] and launch['execution_id']==execution and member['identity_sha256']==fence['identity_sha256'] and
                member['pid']==launch['process']['pid'] and member['unified_membership']==str(leaf).removeprefix('/sys/fs/cgroup'),
                {'grant':command,'fence':fence,'membership':member,'launch':launch})
            observed={k:(leaf/k).read_text().strip() for k in (*EXPECTED,'cpu.stat','cgroup.events','cgroup.procs','pids.current','memory.current')}
            before_cpu=counters(member['snapshot']['cpu.stat']);after_cpu=counters(stop['snapshot']['cpu.stat'])
            delta={k:after_cpu.get(k,0)-before_cpu.get(k,0) for k in ('usage_usec','nr_throttled','throttled_usec')}
            records=[json.loads(line) for line in (journal/'stdout.ndjson').read_text().splitlines()]
            cpu=[r for r in records if r.get('kind')=='VERIFIER_PHYSICAL_CPU' and r.get('role')==command['role']]
            current=process_fingerprint(launch['process']['pid'])
            check(stage+'_'+command['role']+'_actual_limits_cpu_and_positive_stop',all(observed[k]==v for k,v in EXPECTED.items()) and
                counters(observed['cgroup.events']).get('populated')==0 and not observed['cgroup.procs'] and
                stop['identity_sha256']==fence['identity_sha256'] and not stop['populated'] and stop['process_exit_confirmed'] and
                not stop['snapshot']['cgroup.procs'].strip() and process_stop['process_exit_confirmed'] and process_stop['exit_code']==0 and
                (not current or current['start_ticks']!=launch['process']['start_ticks']) and len(cpu)==1 and cpu[0]['process_cpu_ns']>0 and delta['usage_usec']>0,
                {'actual_host_files':observed,'cpu_observation':cpu,'kernel_delta':delta,'physical_stop':stop})
            if command['role']=='independent':
                check(stage+'_independent_actual2sec_throttle',2_000_000_000<=cpu[0]['elapsed_ns']<=5_000_000_000 and
                    delta['nr_throttled']>0 and delta['throttled_usec']>0,{'cpu':cpu,'kernel_delta':delta});busy_stages.append(stage)
            role_output=stage_output/command['role'];role_output.mkdir()
            save(role_output/'actual-host-readback.json',{'leaf_path':str(leaf),'inode':leaf.stat().st_ino,'files':observed,
                'observed_at_monotonic_ns':time.monotonic_ns(),'scope':'Actualkernelread after awaitedstop while ownedAPIunitstillalive; runtimepreexec/stop alsovalidatealllimits'})
            report['raw_manifest'].append({'path':str((role_output/'actual-host-readback.json').relative_to(ROOT)),
                'sha256':sha(role_output/'actual-host-readback.json'),'bytes':(role_output/'actual-host-readback.json').stat().st_size})
            for name in ('verification-command.json',*REQUIRED_RAW[:5],'stop.json','stdout.ndjson','stderr.log'):
                source=journal/name;target=role_output/name;shutil.copyfile(source,target)
                report['raw_manifest'].append({'path':str(target.relative_to(ROOT)),'sha256':sha(target),'bytes':target.stat().st_size})
            observations.append({'command':command,'kernel_delta':delta,'leaf_path':str(leaf),'limits_readback':observed})
        check(stage+'_runner_sealed_no_unused_commands',closed['runner_closed'] is True and not closed['unused_execution_ids'],closed)
        stages.append({'stage':stage,'context':context,'commands':observations})
    check('six_sequential_verifier_grants_same_reservation',len(all_ids)==6 and len(stages)==2 and len(busy_stages)==2,
        {'stages':stages,'physical_pool_sha256':binding['reservation_sha256']})
    report['verifier_physical']={'scope':'Real6API-side rolecommands, sameheldrootpool, ownCPU/memory/pidsleaf percommand, actualkernelreadbacks andpositiveclosedgroup',
        'api_unit_name':api_unit,'stage_count':2,'command_count':6,'grants':stages}
    report['not_proven'].remove('API-verifier physicalhardlimits')


def run(args, plan):
    if sha(args.output/'source-ready-plan.json') != args.expected_plan_sha256 or loaded(args.output/'source-ready-plan.json') != plan:
        raise RuntimeError('Approved source plan pin differs; no actors started')
    if (args.output/'report.json').exists():raise RuntimeError('Prior runtime report exists; refuse replay')
    before=unit_properties('forgeflow-control.service')
    if before['MainPID']!=str(args.main_pid) or before['ActiveState']!='active':raise RuntimeError('Mainservice pin changed before test')
    with socket.socket() as connection:
        if connection.connect_ex(('127.0.0.1',args.port))==0:raise RuntimeError('Isolated port already occupied')
    receipt=loaded(args.build_receipt)
    private=Path(tempfile.mkdtemp(prefix='forgeflow-physical-business-',dir='/home/chenyoujian/.cache'));private.chmod(0o700)
    (private/'state').mkdir(mode=0o700)
    database='forgeflow_physical_business_'+uuid.uuid4().hex[:16]
    main_env=loaded(args.private_env)
    env={'DATABASE_URL':create_database(main_env,database,private),'FORGEFLOW_BIND':f'127.0.0.1:{args.port}',
        'FORGEFLOW_DATA_ROOT':str(private/'state'),'FORGEFLOW_OWNER_TOKEN':secrets.token_hex(32),
        'FORGEFLOW_WORKER_TOKEN':secrets.token_hex(32),'RUST_LOG':'info'}
    secure_save(private/'runtime-env.json',env)
    diagnostics=private/'diagnostics';diagnostics.mkdir(mode=0o700)
    client=Client(f'http://127.0.0.1:{args.port}',env['FORGEFLOW_OWNER_TOKEN'],args.output,diagnostics)
    client.worker_token=env['FORGEFLOW_WORKER_TOKEN'];client.database_url=env['DATABASE_URL'];client.sensitive.add(client.worker_token)
    report={'schema_version':'forgeflow.actual-physical-business-chain.v1','status':'RUNNING','source_identity':plan['source_identity'],
        'source_plan_sha256':args.expected_plan_sha256,'private_root':str(private),'database_name':database,'checks':[],'errors':[],
        'models':0,'real_dsh':False,'production_qualified':False,'main_before':before,'raw_manifest':[],
        'not_proven':['Nativechildpool execution','hostileDSH qualification','API-verifier physicalhardlimits','100+production','fullfaultmatrix']}
    server=None;stream=None;fixture=None;prepared=None;unit=None;attempt=None;positive_zero=False
    api_unit=None
    managed_api=False
    if args.verifier_physical:
        report['not_proven'].append('Hostileverifier/kernelattack qualification')
    def check(name,condition,facts=None):
        report['checks'].append({'name':name,'status':'PASS' if condition else 'FAIL','facts':project_public(facts)})
        save(args.output/'report.json',report)
        if not condition:raise RuntimeError('actual check failed: '+name)
    def snapshot():return client.api('GET',f"/projects/{fixture['project']}/snapshot")
    log=os.fdopen(os.open(private/'server.log',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb')
    try:
        if args.verifier_physical:
            api_unit=args.api_service_name+'.service'
            missing=subprocess.run(['systemctl','--user','show',api_unit,'--property=LoadState','--value'],capture_output=True,text=True,timeout=15)
            if missing.stdout.strip()!='not-found':raise RuntimeError('Unique private API unit already exists; refuse reuse')
            child_json([str(Path(sys.executable).resolve()),str(ROOT/'ops/manage-service.py'),'install','--name',args.api_service_name,
                '--release-dir',str(args.runtime_release),'--runtime-env',str(private/'runtime-env.json'),'--verifier-cgroups','--start'])
            managed_api=True
            report['api_unit_name']=api_unit
            api_unit_file=Path.home()/'.config/systemd/user'/api_unit
            if not api_unit_file.is_file() or api_unit_file.is_symlink():raise RuntimeError('Created control unit is not a regular file')
            report['api_unit_file_sha256']=sha(api_unit_file)
            shutil.copyfile(api_unit_file,private/'control-unit.service')
        else:
            server=subprocess.Popen([receipt['binaries']['forgeflow-server']['path']],env={'PATH':'/usr/bin:/bin',**env},stdout=log,stderr=subprocess.STDOUT)
        def healthy():
            if server is not None and server.poll() is not None:raise RuntimeError('Private API exited')
            if api_unit and unit_properties(api_unit)['ActiveState']!='active':raise RuntimeError('Private delegated API exited')
            try:return client.request('GET','/me')[0]==200
            except OSError:return False
        wait(healthy,'private API readiness',30)
        fixture=create_fixture(client,private,receipt,args.verifier_physical);report['project_id']=fixture['project']
        launcher=ROOT/'ops/run-delegated-worker.py';python=str(Path(sys.executable).resolve())
        prepared=child_json([python,str(launcher),'prepare','--kind','worker','--program',receipt['binaries']['forgeflow-worker']['path'],
            '--program-sha256',receipt['binaries']['forgeflow-worker']['sha256'],'--config',str(fixture['config']),
            '--env-file',str(fixture['env']),'--output',str(private/'delegated-worker')])
        unit=prepared['unit_name'];report['worker_unit_name']=unit
        start=[python,str(launcher),'start','--plan',str(private/'delegated-worker/launch-plan.json'),
            '--plan-sha256',prepared['plan_sha256'],'--unit-sha256',prepared['unit_sha256']]
        child_json(start);child_json(start+['--execute'])
        def registered():
            state=unit_properties(unit)
            if state['ActiveState']!='active':raise RuntimeError('Delegated business Worker exited before registration')
            row=database_command(client.database_url,"SELECT json_build_object('worker_id',worker_id,'project_id',project_id,'executor_profile_ids',executor_profile_ids) FROM workers WHERE worker_id='"+fixture['worker']+"'")
            return json.loads(row.stdout) if row.returncode==0 and row.stdout.strip() else None
        registration=wait(registered,'real delegated business Worker registration',30)
        check('actual_project_profile_bound_business_worker',registration['project_id']==fixture['project'] and 'controlled-lightweight.v1' in registration['executor_profile_ids'],registration)
        fixture=finalize_fixture(client,private,fixture)
        stream=Events(client,fixture['project'])
        task=fixture['task'];client.api('POST',f"/projects/{fixture['project']}/queue-entries",{'task_id':task['task_id'],
            'expected_revision':task['revision'],'worker_id':fixture['worker'],'worker_scope_id':fixture['project']+':worker',
            'scope_ids':[],'priority':1,'lease_seconds':120})
        paused(client,fixture['project'],False)
        running=wait(lambda:actual_running(client,[fixture['project']],private),'actual strongsandboxed physical author',45)[0]
        attempt=running['attempt'];report['attempt_id']=attempt['attempt_id'];journal=running['journal']
        bindings=loaded(journal/'execution-bindings.json');binding=bindings['physical_resources'];fence=loaded(journal/'cgroup-fence.json')
        check('admitted_rootonly_frozen_physical_reservation',binding['root_resources']==REQUEST and binding['reserved_resources']==REQUEST and
            binding['max_concurrent_children']==0 and binding['physical_limits']==POLICY and binding['reservation_sha256']==fence['resource_binding_sha256'],binding)
        leaf=Path(fence['leaf_path']);check('exact_private_leaf_bound_to_attempt',fence['project_id']==fixture['project'] and fence['attempt_id']==attempt['attempt_id'] and
            fence['generation']==attempt['generation'] and leaf.parent.name==unit and leaf.stat().st_ino==fence['leaf_inode'],fence)
        observed={name:(leaf/name).read_text().strip() for name in (*EXPECTED,'cpu.stat','cgroup.events','cgroup.procs','pids.current','memory.current')}
        observed_at=time.monotonic_ns();save(args.output/'host-live-cgroup.json',{'observed_at_monotonic_ns':observed_at,'files':observed,'leaf_path':str(leaf),'inode':leaf.stat().st_ino})
        check('actual_host_exact_limits_and_populated_group',all(observed[k]==v for k,v in EXPECTED.items()) and counters(observed['cgroup.events']).get('populated')==1 and bool(observed['cgroup.procs']),observed)
        state=snapshot();save(args.output/'running-snapshot.json',state)
        limits={(v['scope_id'],v['dimension']):v for v in state['resource_limits']}
        live_ledger=ledger_totals({fixture['project']:state})
        check('all_seven_dimensions_all_ancestors_reserved_once',not live_ledger['mismatches'] and
            all(limits[(s,d)]['allocated']==a for s in fixture['scope_ids'] for d,a in REQUEST.items()),live_ledger)
        def verifying():
            row=client.api('GET',f"/attempts/{attempt['attempt_id']}?project_id={fixture['project']}")
            if row['state'] in ('FAILED','CANCELLED','RECOVERY_REQUIRED'):raise RuntimeError('Physical business author ended '+row['state'])
            return row if row['state']=='VERIFYING' else None
        wait(verifying,'physical author exit and server accepted positive stop',45)
        stop=loaded(journal/'cgroup-stop.json');membership=loaded(journal/'cgroup-membership.json');sandbox=loaded(journal/'sandbox.json')
        actual_stop={name:(leaf/name).read_text().strip() for name in ('cgroup.events','cgroup.procs','cpu.stat','pids.current')}
        save(args.output/'host-stopped-cgroup.json',{'files':actual_stop,'leaf_path':str(leaf),'inode':leaf.stat().st_ino,'observed_at_monotonic_ns':time.monotonic_ns()})
        check('strong_sandbox_and_actual_attached_membership',sandbox['isolation_profile']=='BWRAP_LANDLOCK_EXACT' and
            sandbox['cpu_memory_enforcement']=='CGROUP_V2_ATTACH_AND_LIMITS_CONFIRMED' and membership['identity_sha256']==fence['identity_sha256'] and
            membership['unified_membership']==str(leaf).removeprefix('/sys/fs/cgroup') and membership['pid']==running['launch']['process']['pid'],sandbox)
        initial_cpu=counters(membership['snapshot']['cpu.stat']);final_cpu=counters(actual_stop['cpu.stat'])
        delta={k:final_cpu.get(k,0)-initial_cpu.get(k,0) for k in ('usage_usec','nr_throttled','throttled_usec')}
        rows=[json.loads(line) for line in (journal/'stdout.ndjson').read_text().splitlines()]
        cpu_rows=[r for r in rows if r.get('cpu_complete')]
        if args.verifier_physical:
            check('actual_finite_author_without_repeated_cpu_stress',any(r.get('finite_output_ready') is True for r in rows) and not cpu_rows,
                {'author_observations':rows,'kernel_delta':delta})
        else:
            check('actual_cpu_phase_and_kernel_throttling',len(cpu_rows)==1 and 8_000_000_000<=cpu_rows[0]['elapsed_ns']<=12_000_000_000 and
                delta['usage_usec']>0 and delta['nr_throttled']>0 and delta['throttled_usec']>0,{'author_observation':cpu_rows,'kernel_delta':delta})
        original_process=running['launch']['process']; current_process=process_fingerprint(original_process['pid'])
        check('positive_physical_empty_reap_before_verification',stop['process_exit_confirmed'] and not stop['populated'] and
            stop['identity_sha256']==fence['identity_sha256'] and not stop['snapshot']['cgroup.procs'].strip() and
            counters(actual_stop['cgroup.events']).get('populated')==0 and not actual_stop['cgroup.procs'] and
            (not current_process or current_process['start_ticks']!=original_process['start_ticks']),{'stop':stop,'host_after':actual_stop})
        accepted=client.api('POST',f"/attempts/{attempt['attempt_id']}/verify-and-integrate",{'project_id':fixture['project']})
        def operation():
            row=client.api('GET','/operations/'+accepted['operation_id'])
            if row['status'] in ('FAILED','RECOVERY_REQUIRED'):raise RuntimeError('Real independentverification/Git '+row['status'])
            return row if row['status']=='SUCCEEDED' else None
        result=wait(operation,'registered8case verification and Git integration',120);save(args.output/'verification-operation.json',result)
        db=database_command(client.database_url,"SELECT jsonb_build_object('merges',(SELECT jsonb_agg(data) FROM merge_intents WHERE project_id='"+fixture['project']+"'),'evidence',(SELECT jsonb_agg(data) FROM evidence_receipts WHERE project_id='"+fixture['project']+"'),'artifacts',(SELECT jsonb_agg(jsonb_build_object('artifact_id',document_id,'path',data->'path','sha256',data->'sha256')) FROM documents WHERE project_id='"+fixture['project']+"' AND collection='artifacts')); ")
        if db.returncode:raise RuntimeError('Readonly verification database query failed')
        facts=json.loads(db.stdout);save(args.output/'verification-database-facts.json',facts)
        state=snapshot();save(args.output/'final-snapshot.json',state)
        current=next(a for a in state['attempts'] if a['attempt_id']==attempt['attempt_id'])
        integrated=git(fixture['canonical'],'rev-parse','refs/heads/main')
        blob=subprocess.check_output(['git','-C',str(fixture['canonical']),'show',integrated+':result.json'])
        (args.output/'integrated-result.bin').write_bytes(blob)
        merges=facts['merges'] or [];evidence=facts['evidence'] or []
        check('actual_finalized_git_declared_exact_output',current['state']=='SUCCEEDED' and len(merges)==1 and
            merges[0]['state']=='FINALIZED' and merges[0]['integrated_sha']==integrated and integrated!=fixture['baseline'] and blob==fixture['expected_blob'],
            {'integrated_sha':integrated,'merges':merges,'blob_sha256':hashlib.sha256(blob).hexdigest()})
        independent=[r for r in evidence if r['kind']=='INDEPENDENT_VERIFICATION']
        integrated_verification=merges[0]['receipt']['verification']
        check('actual_eight_case_candidate_and_integrated_verification',len(independent)==1 and independent[0]['candidate_sha']==merges[0]['candidate_sha'] and
            independent[0]['integrated_sha'] is None and independent[0]['total']==8 and
            all(r['failed']==0 and r['skipped']==0 for r in evidence) and
            all(v['total']==8 and v['failed']==0 and v['skipped']==0 and v['positive_cases']==4 and v['negative_cases']==4 and v['independent']
                for v in (independent[0]['details'],integrated_verification)) and
            integrated_verification['binding']['integrated_sha']==integrated and integrated_verification['binding']['attempt_id']==attempt['attempt_id'],
            {'candidate':independent,'integrated':integrated_verification})
        paused(client,fixture['project'],True)
        final=snapshot();ledger=ledger_totals({fixture['project']:final})
        positive_zero=not ledger['mismatches'] and not ledger['allocated_vectors'] and all(a['state']=='RELEASED' for a in final['allocations']) and all(l['revoked_at'] is not None for l in final['leases'])
        check('positive_all_seven_scope_ledgers_released',positive_zero,ledger)
        zero=database_command(client.database_url,'SELECT count(*) FROM model_request_permit')
        check('actual_zero_model_permits',zero.returncode==0 and zero.stdout.strip() in (b'0','0'))
        raw=args.output/'raw';raw.mkdir()
        for name in (*REQUIRED_RAW,'stdout.ndjson','stderr.log'):
            source=journal/name;destination=raw/name;shutil.copyfile(source,destination)
            report['raw_manifest'].append({'path':str(destination.relative_to(ROOT)),'sha256':sha(destination),'bytes':destination.stat().st_size})
        candidate_artifact=next(a for a in facts['artifacts'] if a['artifact_id']==independent[0]['artifact']['artifact_id'])
        candidate_log=Path(candidate_artifact['path'])
        if sha(candidate_log)!=candidate_artifact['sha256']:raise RuntimeError('Registered candidate rawlog hash differs')
        integrated_log=Path(merges[0]['receipt']['artifact_root'])/integrated_verification['log_path']
        if sha(integrated_log)!=integrated_verification['log_hash']:raise RuntimeError('Finalized integrated rawlog hash differs')
        verification_sources=[('candidate',candidate_log.parent,candidate_log),
            ('integrated',Path(merges[0]['receipt']['verifier_scratch_root']),integrated_log)]
        for stage, reports_root, raw_log in verification_sources:
            sources=[(stage+'-raw.log',raw_log)]+[(stage+'-'+role+'.json',reports_root/(role+'.json')) for role in ('author','consumer','independent')]
            for name,source in sources:
                target=raw/name;shutil.copyfile(source,target)
                report['raw_manifest'].append({'path':str(target.relative_to(ROOT)),'sha256':sha(target),'bytes':target.stat().st_size})
        if args.verifier_physical:
            retain_verifier_physical(args,fixture,attempt,binding,verification_sources,api_unit,report,check)
    except Exception as error:
        report['errors'].append({'type':type(error).__name__,'message':str(error)[:250]})
    finally:
        if fixture:
            try:
                paused(client,fixture['project'],True)
                final=snapshot()
                for row in final['attempts']:
                    if row['state'] not in ('SUCCEEDED','FAILED','CANCELLED'):stop_attempt(client,row)
                final=snapshot();ledger=ledger_totals({fixture['project']:final})
                positive_zero=not ledger['mismatches'] and not ledger['allocated_vectors'] and not any(l['revoked_at'] is None for l in final['leases'])
                report['cleanup_authority']={'positive_zero':positive_zero,'ledger':ledger,'attempts':[{'attempt_id':a['attempt_id'],'state':a['state']} for a in final['attempts']]}
            except Exception as error:report['errors'].append({'cleanup':'authority','type':type(error).__name__,'message':str(error)[:200]})
        if stream:
            stream.close();save(args.output/'events.json',{'rows':stream.rows,'errors':stream.errors})
            report['event_denominator']={'count':len(stream.rows),'errors':stream.errors,'kinds':sorted({r['event'].get('kind','UNKNOWN') for r in stream.rows})}
        if unit:
            try:
                if not positive_zero:raise RuntimeError('No positive release; retain Worker/privateunit quarantine')
                # Only the prepared owned privateunit is signalled, after authority
                # zero and real stop. No forcedkill of an unresolved author.
                pid=int(unit_properties(unit)['MainPID'])
                if pid:os.kill(pid,signal.SIGTERM)
                terminal=wait(lambda:unit_properties(unit) if unit_properties(unit)['MainPID']=='0' else None,'owned business Worker positive exit',35)
                report['worker_shutdown']=terminal
                plan_value=loaded(private/'delegated-worker/launch-plan.json')
                subprocess.run(['systemctl','--user','stop',unit,plan_value['slice_name']],check=True,capture_output=True,timeout=15)
                link=Path.home()/'.config/systemd/user'/unit
                if not link.is_symlink() or link.resolve()!=private/'delegated-worker'/unit:raise RuntimeError('Privateunit link identity differs')
                link.unlink();subprocess.run(['systemctl','--user','daemon-reload'],check=True,capture_output=True,timeout=15)
                report['owned_unit_unlinked']=True
            except Exception as error:report['errors'].append({'cleanup':'worker','type':type(error).__name__,'message':str(error)[:200]})
        if server and (not unit or report.get('owned_unit_unlinked')):
            if server.poll() is None:
                server.send_signal(signal.SIGTERM)
                try:server.wait(timeout=35)
                except subprocess.TimeoutExpired:report['errors'].append({'cleanup':'server','error':'Positiveexitunconfirmed;retainedprivateprocess'})
            report['server_shutdown']={'pid':server.pid,'exit_code':server.poll(),'confirmed':server.poll() is not None}
        if managed_api and (not unit or report.get('owned_unit_unlinked')):
            try:
                state=unit_properties(api_unit);api_pid=int(state['MainPID'])
                if api_pid:os.kill(api_pid,signal.SIGTERM)
                terminal=wait(lambda:unit_properties(api_unit) if unit_properties(api_unit)['MainPID']=='0' else None,'owned delegated API positive exit',35)
                report['server_shutdown']={'pid':api_pid,'exit_code':int(terminal['ExecMainStatus']),'confirmed':True,'unit':terminal}
                slice_name='forgeflowcontrolresources'+args.api_service_name.removeprefix('forgeflow-control-')+'.slice'
                subprocess.run(['systemctl','--user','stop',api_unit,slice_name],check=True,capture_output=True,timeout=15)
                subprocess.run(['systemctl','--user','disable',api_unit],check=True,capture_output=True,timeout=15)
                api_file=Path.home()/'.config/systemd/user'/api_unit
                if api_file.is_symlink() or sha(api_file)!=report['api_unit_file_sha256']:raise RuntimeError('Owned API unit bytes changed; retain file')
                api_file.unlink();subprocess.run(['systemctl','--user','daemon-reload'],check=True,capture_output=True,timeout=15)
                report['owned_api_unit_unlinked']=True
                check('delegated_api_exit_and_private_slice_closed',terminal['ActiveState']=='inactive' and terminal['MainPID']=='0' and
                    unit_properties(slice_name)['ActiveState']=='inactive',{'api':terminal,'slice':unit_properties(slice_name)})
            except Exception as error:report['errors'].append({'cleanup':'delegated_api','type':type(error).__name__,'message':str(error)[:200]})
        log.close()
        after=unit_properties('forgeflow-control.service');report['main_after']=after
        if after['MainPID']!=str(args.main_pid) or after['ActiveState']!='active':report['errors'].append({'main':'Existingmainservice identity changed'})
        report['assertions']=len(report['checks']);report['failed']=sum(c['status']!='PASS' for c in report['checks'])
        report['status']='PASS_BOUNDED_ACTUAL_PHYSICAL_BUSINESS_CHAIN' if not report['errors'] and report['checks'] and not report['failed'] and positive_zero and report.get('owned_unit_unlinked') and (not args.verifier_physical or report.get('owned_api_unit_unlinked')) else 'FAIL'
        if args.verifier_physical and report['status'].startswith('PASS_'):
            report['status']='PASS_BOUNDED_ACTUAL_AUTHOR_AND_VERIFIER_PHYSICAL_CHAIN'
        report['ended_at']=datetime.now(timezone.utc).isoformat();save(args.output/'report.json',report)
    print(json.dumps({'status':report['status'],'report':str(args.output/'report.json'),'assertions':report['assertions'],'failed':report['failed'],'private_root':str(private)}))
    return 0 if report['status'].startswith('PASS_') else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-receipt',type=Path,required=True)
    parser.add_argument('--private-env',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/physical-business-chain-r1')
    parser.add_argument('--port',type=int,default=8881)
    parser.add_argument('--main-pid',type=int,default=3903103)
    parser.add_argument('--execute-authorized',action='store_true')
    parser.add_argument('--expected-plan-sha256')
    parser.add_argument('--verifier-physical',action='store_true',help='One actual delegated API+Worker chain, with physical3role candidate/integrated verification')
    parser.add_argument('--expected-source-identity')
    parser.add_argument('--runtime-release',type=Path)
    parser.add_argument('--api-service-name',help='Fresh forgeflow-control-32hex name for the isolated delegated API')
    args=parser.parse_args();plan=source_plan(args)
    args.output=args.output.resolve();args.output.mkdir(parents=True,exist_ok=True)
    if not args.execute_authorized:
        dest=args.output/'source-ready-plan.json'
        if dest.exists():raise RuntimeError('Source-ready plan exists; preserve original')
        secure_save(dest,plan)
        print(json.dumps({'status':plan['status'],'plan':str(dest),'plan_sha256':sha(dest),'models':0,'apis':0,'workers':0}))
        return 0
    if not args.expected_plan_sha256:raise RuntimeError('Root-approved sourceplan SHA required')
    return run(args,plan)


if __name__=='__main__':
    raise SystemExit(main())

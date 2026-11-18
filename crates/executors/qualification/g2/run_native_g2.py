#!/usr/bin/env python3
"""Real API -> template -> scheduler -> standalone Worker -> DSH -> oracle -> Git.

Uses a private authorized runtime file. No mock outcomes or inline model credentials.
Prepare can run before a coordinated server restart; execute requires actual template route.
"""
import argparse,hashlib,importlib.util,json,os,signal,subprocess,sys,time,uuid
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
CONTROL=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(CONTROL/'benchmarks'))
sys.path.insert(0,str(CONTROL/'verification'))
from control_load import Client
from algorithm_check import vector
from metrics import process_fingerprint

ACCEPTANCE='Implement exactly indexer.py using Python standard library. index_files(root: str) returns a list sorted by relative POSIX path containing path, size in bytes, and SHA256 for every regular non-symlink file recursively. Exclude every .git directory and do not follow file, directory or dangling symlinks; exclude FIFO/devices. CLI python3 indexer.py ROOT emits UTF8 JSON with ensure_ascii=False; missing ROOT exits nonzero. File content hashing must handle empty, binary, Unicode and files spanning 65536-byte boundaries.'
PROMPT='Implement the finite requirement in exactly indexer.py. Use one write operation if possible. Do not write tests, do not run tests, do not import the generated module, do not create bytecode, do not commit, do not install packages, do not spawn agents. Stop immediately after writing indexer.py and give a one-sentence final answer. Unicode requirement: 文件索引。\n'+ACCEPTANCE
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def git(root,*args):
    r=subprocess.run(['git','-C',str(root),'-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false',*args],capture_output=True,text=True,timeout=30)
    if r.returncode:raise RuntimeError(r.stderr[:600])
    return r.stdout.strip()
def request(client,method,path,body=None,key=None):
    status,value=client.request(method,'/api/v1'+path,body,{'Idempotency-Key':key or uuid.uuid4().hex})
    if status>=400:raise RuntimeError(f'API {method} {path}: HTTP {status}: {value.get("code","UNKNOWN")}')
    return value
def doc(client,p,collection,identity,value):return request(client,'POST',f'/projects/{p}/documents/{collection}',{'id':identity,'value':value,'expected_revision':None})
def save(path,value):Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def requirement_digest(r):
    frame=['forgeflow.requirement.semantic.v1',r['project_id'],r['requirement_id'],r['source_anchor'],r['outcome'],r['scope'],r['acceptance'],r['priority'],r['weight'],r['deferred_reason']]
    return hashlib.sha256(json.dumps(frame,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
def client_for(args,private,out):
    client=Client(args.url,private['FORGEFLOW_OWNER_TOKEN'],out)
    client.count=max([int(p.stem.split('-')[1]) for p in Path(out).glob('http-*.json')]+[0])
    return client

def prepare(args):
    out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
    if (out/'case.json').exists():print('existing prepared case retained');return
    private=json.loads(Path(args.private_env).read_text());client=client_for(args,private,out)
    identity='native-g2-'+uuid.uuid4().hex
    folder=Path('/home/chenyoujian/.cache/forgeflow-dsh-g2')/identity;folder.mkdir(parents=True,mode=0o700)
    source=folder/'source';source.mkdir();git(source,'init','--initial-branch=main')
    source_text='# Finite file-indexer acceptance\n'+ACCEPTANCE+'\n'
    (source/'README.md').write_text(source_text);git(source,'add','README.md')
    git(source,'-c','user.name=ForgeFlow G2 fixture','-c','user.email=g2@localhost','commit','-m','Finite source-bound indexer requirement')
    p=request(client,'POST','/projects',{'project_id':identity,'name':'Real DSH finite indexer G2','root_path':str(source),'authority_mode':'MANAGED','data_origin':'NATIVE','goal':ACCEPTANCE,'technology_stack':['Python standard library'],'timezone':'Asia/Shanghai','paused':False,'archived':False,'revision':0})['data']
    root=p['root_path'];team='native-indexer-owner';worker='native-worker-'+uuid.uuid4().hex[:12]
    request(client,'POST',f'/projects/{identity}/teams',{'project_id':identity,'team_id':team,'parent_team_id':None,'name':'Native finite author','paused':False,'revision':0})
    request(client,'POST',f'/projects/{identity}/owners',{'id':team,'expected_revision':None,'value':{'owner_id':team,'include':['indexer.py'],'exclude':[]}})
    imported=request(client,'POST',f'/projects/{identity}/source-imports',{'name':'Finite file indexer original requirement','format':'MARKDOWN','content':source_text})['data']
    requirements=request(client,'GET',f'/projects/{identity}/requirements')['data']
    profile=json.loads((Path(__file__).resolve().parents[1]/'headless-profile.json').read_text())
    profile['resume_verified']=False # Worker fresh-worktree platform resume is unsupported.
    resource_id='native-local-reservation.v1';plan_id='a10-indexer-template.v1'
    verifier=CONTROL/'verification/fixtures/indexer_verifier.py'
    spec=importlib.util.spec_from_file_location('pinned_indexer_oracle',verifier);oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
    program=str(Path(sys.executable).resolve())
    commands=[{'role':role,'program':program,'args':['-I','-B',str(verifier)],'env':{'FORGEFLOW_VERIFICATION_ROLE':role},'executable_hash':sha(program),'bound_inputs':[{'path':str(verifier),'sha256':sha(verifier)}],'report_path':role+'.json','expected_cases':[{'name':name,'kind':kind} for name,kind in oracle.CASES[role]],'timeout_seconds':45} for role in ['author','consumer','independent']]
    plan={'plan_id':plan_id,'task_revision':1,'contract_version':'finite-file-indexer.v1','input_hash':'a'*64,'environment_profile':'single-node-pinned-independent-oracle','oracle_id':oracle.ORACLE,'verifier_id':'A10-independent-indexer-oracle','author_id':worker,'commands':commands}
    doc(client,identity,'executor_profiles',profile['id'],profile)
    doc(client,identity,'resource_profiles',resource_id,{'id':resource_id,'build_capable':False,'stage_resource_mode':'ATTEMPT_RESERVATION','physical_boundary':'LOCAL_TRUSTED_WORKTREE','cgroup_fence':'UNVERIFIED'})
    doc(client,identity,'model_routes',profile['model_route_id'],{'id':profile['model_route_id'],'name':'Existing authorized local NewAPI route','model':'glm-5.3','protocol':'anthropic-messages','mode':'direct_observed','config_sha256':sha(Path(profile['home'])/'cordis.patch.yml'),'cost':'UNKNOWN','hard_request_coverage':'UNVERIFIED'})
    doc(client,identity,'verification_plans',plan_id,plan)
    # No handwritten envelope. The server assembler owns prompt, manifest, plan binding and lease-free template.
    task_id='native-file-indexer'
    task={'project_id':identity,'task_id':task_id,'task_revision':1,'flow_revision':1,'title':'Implement finite Unicode file indexer','owner_id':team,'team_id':team,'requirement_ids':[r['requirement_id'] for r in requirements],'read_set':[],'write_set':['indexer.py'],'dependencies':[],'state':'NEEDS_REVIEW','input_digest':'a'*64,'resource_request':vector(1),'envelope':None,'revision':1}
    task['resource_request'].update(coding_slot=1,cpu_units=1,memory_bytes=512*1024*1024,provider_inflight=0)
    anchors=[r['source_anchor'] for r in requirements]
    semantic={'outcome':ACCEPTANCE,'design_anchors':anchors,'inputs':[],'mandatory_paths':[],'dependency_refs':[],'contract_produces':[],'contract_consumes':[],'execution_profile':profile['id'],'verification_plan':plan_id,'verification_case_count':8,'rollback_plan':'Retain failed candidate; explicit verified revert required after integration','known_unknowns':['provider inflight and cost are not exposed in direct_observed mode'],'not_proven':['No full UI loop or production capacity qualification'],'isolated_contract_probe':False}
    flow={'project_id':identity,'flow_revision':1,'parent_revision':None,'state':'DRAFT','tasks':[task],'input_digest':'a'*64,'approved_by':None,'revision':1}
    context={'requirements':[],'owners':[],'task_specs':{task_id:semantic},'current_inputs':{},'resolved_paths':{},'contracts':[],'source_revision':'','observed_at':''}
    saved=request(client,'POST',f'/projects/{identity}/flow-revisions',{'flow':flow,'context':context,'expected_revision':None})['data']
    config={'control_url':args.url,'worker_id':worker,'project_id':identity,'data_root':private['FORGEFLOW_DATA_ROOT'],'profile':profile,'model_route_id':profile['model_route_id'],'secret_files':{},'poll_seconds':1,'max_log_bytes':64*1024*1024,'max_active_attempts':1,'controlled_workload_programs':{}}
    config_path=folder/'worker.json';save(config_path,config);config_path.chmod(0o600)
    case={'project_id':identity,'worker_id':worker,'team_id':team,'task_id':task_id,'authoritative_repository':root,'base_sha':git(root,'rev-parse','refs/heads/main'),'source_id':imported['source_id'],'source_text_sha256':hashlib.sha256(source_text.encode()).hexdigest(),'profile_id':profile['id'],'profile_sha256':hashlib.sha256(json.dumps(profile,sort_keys=True).encode()).hexdigest(),'model_route_id':profile['model_route_id'],'resource_profile_id':resource_id,'verification_plan_id':plan_id,'oracle_file':str(verifier),'oracle_sha256':sha(verifier),'worker_config':str(config_path),'data_root':private['FORGEFLOW_DATA_ROOT'],'draft_revision':saved['revision'],'scope':'API_TEMPLATE_SCHEDULER_REAL_WORKER_NATIVE_ORACLE_GIT','full_ui_loop':'INCONCLUSIVE','cross_project_qualification':'INCONCLUSIVE','model_budget_mode':'direct_observed','model_inflight':'UNVERIFIED','cost':'UNKNOWN'}
    save(out/'case.json',case);print(json.dumps({'prepared_project':identity,'draft_revision':saved['revision'],'model_executed':False}))

def operation(client,identity,seconds=90):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        op=request(client,'GET','/operations/'+identity)['data']
        if op.get('status') in ['SUCCEEDED','FAILED','RECOVERY_REQUIRED']:
            if op['status']!='SUCCEEDED':raise RuntimeError('operation '+identity+' '+op['status']+' '+op.get('error',{}).get('code',''))
            return op
        time.sleep(1)
    raise RuntimeError('operation timeout '+identity)

def metric(case):
    roots=[];attempts=Path(case['data_root'])/'attempts'
    if attempts.exists():
        for folder in attempts.iterdir():
            receipt=folder/'launch-receipt.json';envpath=folder/'envelope.json'
            if not receipt.exists() or not envpath.exists():continue
            env=json.loads(envpath.read_text())
            if env.get('project_id')!=case['project_id']:continue
            launch=json.loads(receipt.read_text());pid=launch['process']['pid'];observed=process_fingerprint(pid)
            valid=bool(observed and observed['start_ticks']==launch['process']['start_ticks'])
            rss=observed['rss_pages']*os.sysconf('SC_PAGE_SIZE') if valid else None
            roots.append({'attempt_id':env['attempt_id'],'pid':pid,'start_ticks':launch['process']['start_ticks'],'native_root_rss_bytes':rss,'live':valid,'execution_id':launch['intent'].get('execution_id')})
    return {'received_at':datetime.now(timezone.utc).isoformat(),'native_roots':roots,'model_inflight':'UNVERIFIED','cost':'UNKNOWN'}

def execute(args):
    out=Path(args.output).resolve();case=json.loads((out/'case.json').read_text());private=json.loads(Path(args.private_env).read_text());client=client_for(args,private,out)
    project=request(client,'GET','/projects/'+case['project_id'])['data']
    if project['paused']:
        revision=project['revision'];project['paused']=False
        request(client,'PATCH','/projects/'+case['project_id'],{'project':project,'expected_revision':revision})
    # Explicit owner review of the complete authoritative meanings. Legacy drafts are not
    # silently backfilled; this is a revision-checked public draft command before rebinding.
    flow=request(client,'GET',f'/flows/{case["project_id"]}:1')['data']
    context=request(client,'GET',f'/flows/{case["project_id"]}:1/context')['data']
    requirements=request(client,'GET',f'/projects/{case["project_id"]}/requirements')['data']
    digests={r['requirement_id']:requirement_digest(r) for r in requirements}
    context['requirement_semantic_digests']=digests
    for task in flow['tasks']:
        context['task_specs'][task['task_id']]['requirement_digest_refs']={k:digests[k] for k in task['requirement_ids']}
        task['envelope']=None # draft-only reseal; assembler issues a fresh version-bound template
    reviewed=request(client,'POST',f'/projects/{case["project_id"]}/flow-revisions',{'flow':flow,'context':context,'expected_revision':flow['revision']})['data']
    case['draft_revision']=reviewed['revision'];save(out/'case.json',case)
    binary=Path(args.worker_binary).resolve();worker_log=(out/'worker.log').open('ab')
    process=subprocess.Popen([str(binary),'--config',case['worker_config']],env={'PATH':'/usr/local/bin:/usr/bin:/bin','RUST_LOG':'info','FORGEFLOW_WORKER_TOKEN':private['FORGEFLOW_WORKER_TOKEN']},stdout=worker_log,stderr=subprocess.STDOUT,start_new_session=True)
    save(out/'worker-live.json',{'pid':process.pid,'binary':str(binary),'binary_sha256':sha('/proc/'+str(process.pid)+'/exe'),'started_at':datetime.now(timezone.utc).isoformat()})
    attempt=None;started=time.monotonic();result={'status':'INCONCLUSIVE','scope':case['scope'],'full_ui_loop':'INCONCLUSIVE','cost':'UNKNOWN','model_inflight':'UNVERIFIED'}
    try:
        time.sleep(2)
        if process.poll() is not None:raise RuntimeError('actual standalone Worker exited before registration')
        limits=vector(1);limits.update(coding_slot=1,cpu_units=2,memory_bytes=1024*1024*1024)
        policies=[]
        for kind,project,team,worker in [('global',None,None,None),('project',case['project_id'],None,None),('team',case['project_id'],case['team_id'],None),('worker',None,None,case['worker_id'])]:
            identity=kind+':'+case['project_id'];policies.append(identity)
            known=request(client,'GET','/resources')['data']
            existing=next((p for p in known if p.get('scope_id')==identity),None)
            if existing:
                assert existing['limits']==limits and existing.get('worker_id')==worker,'existing policy differs; explicit review required'
            else:
                body={'policy':{'scope_id':identity,'parent_scope_id':None,'project_id':project,'team_id':team,'worker_id':worker,'limits':limits,'revision':0,'paused':False},'expected_revision':None}
                end=time.monotonic()+30;key='create-policy-'+identity
                while True:
                    if process.poll() is not None:raise RuntimeError('actual standalone Worker exited before resource registration')
                    status,response=client.request('POST','/api/v1/resource-policies',body,{'Idempotency-Key':key})
                    if status<400:break
                    if not worker or response.get('code')!='REFERENCE_NOT_FOUND' or time.monotonic()>end:raise RuntimeError(f'policy registration HTTP {status}: {response.get("code")}')
                    time.sleep(1)
        bound=request(client,'POST',f'/flows/{case["project_id"]}:1/tasks/{case["task_id"]}/execution-templates',{'expected_revision':case['draft_revision'],'executor_profile_id':case['profile_id'],'resource_profile_id':case['resource_profile_id'],'verification_plan_id':case['verification_plan_id'],'prompt':PROMPT,'session_purpose':'EXECUTION','max_model_requests':8})
        binding=operation(client,bound['operation_id']);save(out/'template-operation.json',binding)
        flow=request(client,'GET',f'/flows/{case["project_id"]}:1')['data']
        checks=request(client,'POST',f'/flows/{case["project_id"]}:1/checks',{})['data'];save(out/'flow-checks.json',checks)
        if not checks['passed']:raise RuntimeError('actual Flow compile blocked: '+','.join(f['rule_id'] for f in checks['findings']))
        committed=request(client,'POST',f'/flows/{case["project_id"]}:1/commit',{'expected_revision':flow['revision']})['data'];task=next(t for t in committed['tasks'] if t['task_id']==case['task_id'])
        request(client,'POST',f'/projects/{case["project_id"]}/queue-entries',{'task_id':task['task_id'],'expected_revision':task['revision'],'worker_id':case['worker_id'],'worker_scope_id':'worker:'+case['project_id'],'scope_ids':policies,'priority':0,'lease_seconds':120})
        with (out/'metrics.jsonl').open('a') as measurements:
            while time.monotonic()-started<args.deadline:
                if process.poll() is not None:raise RuntimeError('actual Worker exited while attempt active')
                attempts=request(client,'GET',f'/projects/{case["project_id"]}/attempts')['data']
                if attempts:
                    attempt=next(a for a in attempts if a['task_id']==case['task_id'])
                    if attempt['state']=='VERIFYING':break
                    if attempt['state'] in ['FAILED','CANCELLED','RECOVERY_REQUIRED']:raise RuntimeError('native attempt '+attempt['state'])
                measurements.write(json.dumps(metric(case))+'\n');measurements.flush();time.sleep(2)
            else:raise RuntimeError('bounded native author deadline exceeded')
        aid=attempt['attempt_id'];journal=Path(case['data_root'])/'attempts'/aid
        author=json.loads((journal/'result.json').read_text());save(out/'actual-worker-result.json',author)
        if author.get('outcome',{}).get('completion_reason')!='EXECUTOR_COMPLETED':raise RuntimeError('native did not produce complete lifecycle')
        integration=request(client,'POST',f'/attempts/{aid}/verify-and-integrate',{'project_id':case['project_id']})
        settled=operation(client,integration['operation_id'],180);save(out/'verification-integration-operation.json',settled)
        final=request(client,'GET',f'/attempts/{aid}?project_id={case["project_id"]}')['data']
        snapshot=request(client,'GET',f'/projects/{case["project_id"]}/snapshot')['data'];save(out/'final-snapshot.json',snapshot)
        head=git(case['authoritative_repository'],'rev-parse','refs/heads/main')
        candidate=git(case['authoritative_repository'],'show',head+':indexer.py')
        allocations=[a for a in snapshot['allocations'] if a['attempt_id']==aid]
        if final['state']!='SUCCEEDED' or head==case['base_sha'] or not candidate or not allocations or any(a['state']!='RELEASED' for a in allocations):raise RuntimeError('authoritative terminal/mainline/allocation audit incomplete')
        raw=(journal/'stdout.ndjson').read_bytes();events=[json.loads(l) for l in raw.splitlines()]
        result.update(status='PASS',project_id=case['project_id'],attempt_id=aid,generation=attempt['generation'],operation_id=attempt['operation_id'],execution_id=author['outcome']['execution_id'],native_session_id=author['outcome']['upstream_session_id'],base_sha=case['base_sha'],integrated_sha=head,native_stdout_sha256=hashlib.sha256(raw).hexdigest(),native_stderr_sha256=sha(journal/'stderr.log'),native_step_starts=sum(e.get('phase')=='step_start' for e in events),native_reported_usage=[e['usage'] for e in events if 'usage' in e],usage_completeness='UNVERIFIED_FOR_ALL_MODEL_CALLS',author_result_sha256=sha(journal/'result.json'),verification_operation_id=integration['operation_id'],all_allocations_released=True,elapsed_seconds=time.monotonic()-started)
    except Exception as error:
        result.update(status='FAIL',error=str(error),elapsed_seconds=time.monotonic()-started)
        if attempt and attempt['state'] not in ['SUCCEEDED','FAILED','CANCELLED']:
            try:request(client,'POST','/attempts/'+attempt['attempt_id']+'/cancel',{'project_id':case['project_id'],'expected_revision':attempt['revision'],'reason':'bounded native G2 harness failure; preserve evidence'})
            except Exception as cleanup_error:result['cleanup_error']=str(cleanup_error)
    finally:
        save(out/'receipt.json',result)
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:process.wait(timeout=30)
            except subprocess.TimeoutExpired:result['worker_shutdown']='UNCONFIRMED';save(out/'receipt.json',result)
        worker_log.close()
    print(json.dumps(result));return 0 if result['status']=='PASS' else 1

def main():
    p=argparse.ArgumentParser();p.add_argument('phase',choices=['prepare','execute']);p.add_argument('--url',default='http://127.0.0.1:8787');p.add_argument('--private-env',default='/home/chenyoujian/.local/state/forgeflow/control/runtime-env.json');p.add_argument('--output',default=str(Path(__file__).resolve().parent));p.add_argument('--worker-binary',default='/home/chenyoujian/.cache/forgeflow-control-target/debug/forgeflow-worker');p.add_argument('--deadline',type=int,default=540);args=p.parse_args()
    if args.phase=='prepare':prepare(args);return 0
    return execute(args)
if __name__=='__main__':raise SystemExit(main())

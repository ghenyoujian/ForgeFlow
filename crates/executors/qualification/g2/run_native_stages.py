#!/usr/bin/env python3
"""Staged real 4/10 native sessions. Each replica has a disjoint path and real oracle/Git acceptance."""
import argparse,hashlib,importlib.util,json,os,signal,subprocess,sys,time,uuid
from pathlib import Path
import run_native_g2 as g
sys.dont_write_bytecode=True
def setup(args):
    first=json.loads((Path(__file__).resolve().parent/'receipt.json').read_text())
    if first['status']!='PASS':raise RuntimeError('first actual whole chain must pass before staged native sessions')
    parent=json.loads((Path(__file__).resolve().parent/'case.json').read_text());out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
    private=json.loads(Path(args.private_env).read_text());client=g.client_for(args,private,out)
    return parent,out,private,client
def prepare(args):
    parent,out,private,c=setup(args)
    first=json.loads((Path(__file__).resolve().parent/'receipt.json').read_text())
    if (out/'stage-case.json').exists():print('prepared stage retained');return
    p=parent['project_id'];run_id=args.run_id or uuid.uuid4().hex[:12];paths=[f'stage{args.count}/{run_id}/t{i:02d}/indexer.py' for i in range(args.count)]
    owners=g.request(c,'GET',f'/projects/{p}/owners')['data'];owner=next(o for o in owners if o['owner_id']==parent['team_id'])
    value={'owner_id':owner['owner_id'],'root_team_id':parent['team_id'],'include':sorted(set(owner['include']+paths)),'exclude':owner['exclude']}
    g.request(c,'POST',f'/projects/{p}/owners',{'id':owner['owner_id'],'expected_revision':owner['revision'],'value':value})
    latest=g.request(c,'GET',f'/projects/{p}/flows/latest')['data'];revision=latest['flow_revision']+1
    requirements=g.request(c,'GET',f'/projects/{p}/requirements')['data'];digests={r['requirement_id']:g.requirement_digest(r) for r in requirements}
    oracle=g.CONTROL/'verification/fixtures/indexer_verifier_v2.py';spec=importlib.util.spec_from_file_location('independent_staged_indexer',oracle);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    python=str(Path(sys.executable).resolve());resource=f'native-stage{args.count}-{run_id}-reservation.v1'
    g.doc(c,p,'resource_profiles',resource,{'id':resource,'build_capable':False,'stage_resource_mode':'ATTEMPT_RESERVATION','physical_boundary':'LOCAL_TRUSTED_WORKTREE','cgroup_fence':'UNVERIFIED','native_sessions':args.count})
    tasks=[];semantics={};plans={}
    for i,path in enumerate(paths):
        identity=f'native-stage{args.count}-{run_id}-{i:02d}';plan_id='a10-indexer-v2-'+identity
        commands=[{'role':role,'program':python,'args':['-I','-B',str(oracle)],'env':{'FORGEFLOW_VERIFICATION_ROLE':role,'FORGEFLOW_OUTPUT_PATH':path},'executable_hash':g.sha(python),'bound_inputs':[{'path':str(oracle),'sha256':g.sha(oracle)}],'report_path':role+'.json','expected_cases':[{'name':n,'kind':k} for n,k in module.CASES[role]],'timeout_seconds':45} for role in ['author','consumer','independent']]
        g.doc(c,p,'verification_plans',plan_id,{'plan_id':plan_id,'task_revision':1,'contract_version':'finite-file-indexer-capacity-replica.v2','input_hash':'a'*64,'environment_profile':'single-node-pinned-independent-oracle','oracle_id':module.ORACLE,'verifier_id':'A10-independent-indexer-v2','author_id':parent['worker_id'],'commands':commands})
        task={'project_id':p,'task_id':identity,'task_revision':1,'flow_revision':revision,'title':f'Real native capacity replica {i+1}/{args.count}','owner_id':parent['team_id'],'team_id':parent['team_id'],'requirement_ids':list(digests),'read_set':[],'write_set':[path],'dependencies':[],'state':'NEEDS_REVIEW','input_digest':'a'*64,'resource_request':g.vector(1),'envelope':None,'revision':1}
        task['resource_request'].update(coding_slot=1,cpu_units=1,memory_bytes=512*1024*1024)
        semantics[identity]={'outcome':g.ACCEPTANCE.replace('indexer.py',path),'requirement_digest_refs':digests,'design_anchors':[r['source_anchor'] for r in requirements],'inputs':[],'mandatory_paths':[],'dependency_refs':[],'contract_produces':[],'contract_consumes':[],'execution_profile':parent['profile_id'],'verification_plan':plan_id,'verification_case_count':8,'rollback_plan':'Retain failed candidate; explicit verified revert after integration','known_unknowns':['Provider inflight and cost not exposed in direct_observed'],'not_proven':['Capacity replica is not a distinct product-business-chain proof','No full UI or production capacity qualification'],'isolated_contract_probe':False};tasks.append(task);plans[identity]=plan_id
    flow={'project_id':p,'flow_revision':revision,'parent_revision':latest['flow_revision'],'state':'DRAFT','tasks':tasks,'input_digest':'a'*64,'approved_by':None,'revision':1}
    context={'requirements':[],'requirement_semantic_digests':digests,'owners':[],'task_specs':semantics,'current_inputs':{},'resolved_paths':{},'contracts':[],'source_revision':'','observed_at':''}
    saved=g.request(c,'POST',f'/projects/{p}/flow-revisions',{'flow':flow,'context':context,'expected_revision':None})['data']
    config_path=Path(parent['worker_config']);cfg=json.loads(config_path.read_text());cfg['max_active_attempts']=args.count;cfg['profile']=json.loads((Path(__file__).resolve().parent/'native-profile-v2.json').read_text())
    stage_config=config_path.parent/f'worker-stage{args.count}.json';g.save(stage_config,cfg);stage_config.chmod(0o600)
    stage={**parent,'run_id':run_id,'count':args.count,'flow_revision':revision,'draft_revision':saved['revision'],'paths':paths,'task_ids':[t['task_id'] for t in tasks],'plans':plans,'worker_config':str(stage_config),'resource_profile_id':resource,'oracle_sha256':g.sha(oracle),'previous_whole_chain':first['integrated_sha'],'scope':'REAL_NATIVE_STAGED_FINITE_CAPACITY_REPLICAS','product_chain_count':0,'launch_authorized_after_coordinated_checkpoint':False}
    g.save(out/'stage-case.json',stage);print(json.dumps({'prepared_native_sessions':args.count,'flow_revision':revision,'models_started':False}))
def execute(args):
    parent,out,private,c=setup(args);case=json.loads((out/'stage-case.json').read_text());p=case['project_id'];n=case['count'];flowkey=f'{p}:{case["flow_revision"]}'
    project=g.request(c,'GET','/projects/'+p)['data']
    if project['paused']:rev=project['revision'];project['paused']=False;g.request(c,'PATCH','/projects/'+p,{'project':project,'expected_revision':rev})
    binary=Path(args.worker_binary).resolve();log=(out/'worker.log').open('ab');process=subprocess.Popen([str(binary),'--config',case['worker_config']],env={'PATH':'/usr/local/bin:/usr/bin:/bin','RUST_LOG':'info','FORGEFLOW_WORKER_TOKEN':private['FORGEFLOW_WORKER_TOKEN']},stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    g.save(out/'worker-live.json',{'pid':process.pid,'binary':str(binary),'binary_sha256':g.sha('/proc/'+str(process.pid)+'/exe')})
    started=time.monotonic();observed={};result={'status':'INCONCLUSIVE','count':n,'scope':case['scope'],'cost':'UNKNOWN','model_inflight':'UNVERIFIED','full_ui_loop':'INCONCLUSIVE','product_chain_count':0};peak=0
    try:
        time.sleep(2)
        if process.poll() is not None:raise RuntimeError('real staged Worker startup failed')
        policies=g.request(c,'GET','/resources')['data'];seen=set()
        for policy in policies:
            if policy['scope_id'] in seen or policy['scope_id'] not in [kind+':'+p for kind in ['global','project','team','worker']]:continue
            seen.add(policy['scope_id']);limits=g.vector(n);limits.update(coding_slot=n,cpu_units=n*2,memory_bytes=n*1024*1024*1024)
            rev=policy['revision'];policy.update(limits=limits)
            g.request(c,'POST','/resource-policies',{'policy':policy,'expected_revision':rev})
        for identity in case['task_ids']:
            flow=g.request(c,'GET','/flows/'+flowkey)['data'];path=case['paths'][case['task_ids'].index(identity)]
            op=g.request(c,'POST',f'/flows/{flowkey}/tasks/{identity}/execution-templates',{'expected_revision':flow['revision'],'executor_profile_id':case['profile_id'],'resource_profile_id':case['resource_profile_id'],'verification_plan_id':case['plans'][identity],'prompt':g.PROMPT.replace('indexer.py',path),'session_purpose':'EXECUTION','max_model_requests':8})
            g.operation(c,op['operation_id'])
        flow=g.request(c,'GET','/flows/'+flowkey)['data'];checks=g.request(c,'POST','/flows/'+flowkey+'/checks',{})['data'];g.save(out/'flow-checks.json',checks)
        if not checks['passed']:raise RuntimeError('staged Flow compiler blocked: '+','.join(f['rule_id'] for f in checks['findings']))
        committed=g.request(c,'POST','/flows/'+flowkey+'/commit',{'expected_revision':flow['revision']})['data']
        for task in committed['tasks']:g.request(c,'POST',f'/projects/{p}/queue-entries',{'task_id':task['task_id'],'expected_revision':task['revision'],'worker_id':case['worker_id'],'worker_scope_id':'worker:'+p,'scope_ids':[kind+':'+p for kind in ['global','project','team','worker']],'priority':0,'lease_seconds':120})
        with (out/'metrics.jsonl').open('a') as meter:
            while time.monotonic()-started<args.deadline:
                if process.poll() is not None:raise RuntimeError('staged Worker exited while active')
                values=g.request(c,'GET',f'/projects/{p}/attempts?limit=200')['data'];observed={a['task_id']:a for a in values if a['task_id'] in case['task_ids']}
                m=g.metric(case);m['native_roots']=[r for r in m['native_roots'] if r['attempt_id'] in {a['attempt_id'] for a in observed.values()}];peak=max(peak,sum(r['live'] for r in m['native_roots']));meter.write(json.dumps(m)+'\n');meter.flush()
                if any(a['state'] in ['FAILED','CANCELLED','RECOVERY_REQUIRED'] for a in observed.values()):raise RuntimeError('actual native staged attempt failed')
                if len(observed)==n and all(a['state']=='VERIFYING' for a in observed.values()):break
                time.sleep(2)
            else:raise RuntimeError('bounded real staged deadline exceeded')
        outcomes=[];integrations=[]
        for identity in case['task_ids']:
            attempt=observed[identity];folder=Path(case['data_root'])/'attempts'/attempt['attempt_id'];r=json.loads((folder/'result.json').read_text());outcomes.append(r['outcome']);g.save(out/(identity+'-worker-result.json'),r)
            if r['outcome']['completion_reason']!='EXECUTOR_COMPLETED':raise RuntimeError('native completion lifecycle missing')
            op=g.request(c,'POST','/attempts/'+attempt['attempt_id']+'/verify-and-integrate',{'project_id':p});settled=g.operation(c,op['operation_id'],180);integrations.append(settled);g.save(out/(identity+'-verification.json'),settled)
        snapshot=g.request(c,'GET',f'/projects/{p}/snapshot')['data'];g.save(out/'final-snapshot.json',snapshot)
        finals={a['task_id']:a for a in snapshot['attempts'] if a['task_id'] in case['task_ids']};ids={a['attempt_id'] for a in finals.values()};allocations=[a for a in snapshot['allocations'] if a['attempt_id'] in ids]
        if len(finals)!=n or any(a['state']!='SUCCEEDED' for a in finals.values()) or any(a['state']!='RELEASED' for a in allocations):raise RuntimeError('staged terminal/allocation audit failed')
        head=g.git(case['authoritative_repository'],'rev-parse','refs/heads/main')
        for path in case['paths']:assert g.git(case['authoritative_repository'],'show',head+':'+path)
        if peak<n:raise RuntimeError(f'real concurrent native peak only {peak}/{n}; completed sessions do not prove requested concurrency')
        sessions=[o['upstream_session_id'] for o in outcomes]
        if len(set(sessions))!=n:raise RuntimeError('native sessions are not distinct')
        result.update(status='PASS',project_id=p,flow_revision=case['flow_revision'],peak_actual_native_processes=peak,native_session_ids=sessions,attempt_ids=list(ids),execution_ids=[o['execution_id'] for o in outcomes],integrated_sha=head,independent_cases=sum(op['result']['evidence']['total'] for op in integrations),independent_failed=sum(op['result']['evidence']['failed'] for op in integrations),independent_skipped=sum(op['result']['evidence']['skipped'] for op in integrations),all_allocations_released=True,elapsed_seconds=time.monotonic()-started)
    except Exception as error:
        result.update(status='FAIL',error=str(error),peak_actual_native_processes=peak,elapsed_seconds=time.monotonic()-started)
        for a in observed.values():
            if a['state'] not in ['FAILED','CANCELLED','SUCCEEDED']:
                try:
                    current=g.request(c,'GET',f'/attempts/{a["attempt_id"]}?project_id={p}')["data"]
                    if current['state'] not in ['FAILED','CANCELLED','SUCCEEDED']:g.request(c,'POST','/attempts/'+a['attempt_id']+'/cancel',{'project_id':p,'expected_revision':current['revision'],'reason':'bounded staged failure; preserve evidence'})
                except Exception as e:result.setdefault('cleanup_errors',[]).append(str(e))
    finally:
        g.save(out/'receipt.json',result)
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:process.wait(timeout=30)
            except subprocess.TimeoutExpired:result['worker_shutdown']='UNCONFIRMED';g.save(out/'receipt.json',result)
        log.close()
    print(json.dumps(result));return 0 if result['status']=='PASS' else 1
def main():
    a=argparse.ArgumentParser();a.add_argument('phase',choices=['prepare','execute']);a.add_argument('--count',type=int,choices=[4,10],required=True);a.add_argument('--url',default='http://127.0.0.1:8787');a.add_argument('--private-env',default='/home/chenyoujian/.local/state/forgeflow/control/runtime-env.json');a.add_argument('--output');a.add_argument('--run-id');a.add_argument('--worker-binary',required=True);a.add_argument('--deadline',type=int,default=600);args=a.parse_args();args.output=args.output or str(Path(__file__).resolve().parent/f'stage-{args.count}')
    if args.phase=='prepare':prepare(args);return 0
    return execute(args)
if __name__=='__main__':raise SystemExit(main())

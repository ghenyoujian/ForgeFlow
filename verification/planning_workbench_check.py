#!/usr/bin/env python3
"""Isolated planning acceptance. Synthetic fixtures never qualify real Agents.

setup starts a private candidate on a new database; check exercises public APIs;
cleanup stops only the recorded candidate and drops only its generated database.
"""
import argparse, datetime, hashlib, json, os, pathlib, secrets, shutil, signal
import socket, statistics, subprocess, time, urllib.error, urllib.parse, urllib.request
import psycopg
from psycopg.types.json import Jsonb

ROOT = pathlib.Path(__file__).resolve().parents[1]
PG = 'host=/home/chenyoujian/.local/state/forgeflow/postgres port=55432 user=forgeflow'
VECTOR = dict(active_slot=1, coding_slot=0, cpu_units=1, memory_bytes=1048576,
              build_permit=0, gpu_permit=0, provider_inflight=1)
LIMIT = dict(active_slot=32, coding_slot=32, cpu_units=128, memory_bytes=8*1073741824,
             build_permit=4, gpu_permit=0, provider_inflight=32)

def write(path, value, private=False):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')
    if private: path.chmod(0o600)

def request(run, route, body=None, key=None, token=True, method=None):
    headers = {'Accept':'application/json'}
    if token: headers['Authorization'] = 'Bearer '+run['token']
    if body is not None:
        headers.update({'Content-Type':'application/json', 'Idempotency-Key':key or secrets.token_hex(16)})
    req = urllib.request.Request(run['base']+'/api/v1'+route,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers, method=method)
    started=time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=180) as response: code=response.status; raw=response.read()
    except urllib.error.HTTPError as error: code=error.code; raw=error.read()
    elapsed=(time.perf_counter()-started)*1000
    try: result=json.loads(raw)
    except ValueError: result={'raw':raw[:300].decode(errors='replace')}
    return code,result,elapsed,len(raw)

def seed(run):
    with psycopg.connect(PG+' dbname='+run['database']) as db:
        for i in range(16):
            pid=f'p{i:02}'
            repository=pathlib.Path(run['repository']) if i==0 else pathlib.Path(run['output'])/'repositories'/pid
            if not repository.exists(): subprocess.run(['git','clone','--quiet','--bare',run['repository'],str(repository)],check=True)
            project=dict(project_id=pid,name=f'规划验收项目 {i+1:02}',root_path=str(repository),
                authority_mode='MANAGED',data_origin='DEMO',goal='独立合成数据：验证规划与交互，不授予真实执行资格',
                technology_stack=['Rust','React'],timezone='Asia/Shanghai',paused=True,archived=False,revision=1)
            db.execute("INSERT INTO projects(project_id,revision,event_seq,authority_mode,paused,data) VALUES(%s,1,0,'MANAGED',true,%s)",(pid,Jsonb(project)))
            for owner in ['owner-a','owner-b']:
                team=dict(project_id=pid,team_id=owner,parent_team_id=None,name=owner,paused=False,revision=1)
                db.execute('INSERT INTO owner_nodes(project_id,owner_id,paused,data) VALUES(%s,%s,false,%s)',(pid,owner,Jsonb(team)))
                db.execute('INSERT INTO owner_closure VALUES(%s,%s,%s,0)',(pid,owner,owner))
                territory=dict(owner_id=owner,root_team_id=owner,include=['src/'],exclude=[])
                # Disjoint ownership in the scale fixture.
                territory['include']=[f'src/{owner}/']
                db.execute("INSERT INTO documents VALUES(%s,'owners',%s,1,%s)",(pid,owner,Jsonb(territory)))
        def policy(scope, project=None, team=None, parent=None):
            value=dict(scope_id=scope,project_id=project,team_id=team,parent_scope_id=parent,worker_id=None,limits=LIMIT,revision=1,paused=False)
            db.execute('INSERT INTO resource_scopes(scope_id,parent_scope_id,project_id,team_id,revision,paused,data) VALUES(%s,%s,%s,%s,1,false,%s)',(scope,parent,project,team,Jsonb(value)))
            for dimension,limit in LIMIT.items(): db.execute('INSERT INTO resource_limits(scope_id,dimension,hard_limit) VALUES(%s,%s,%s)',(scope,dimension,limit))
        policy('global')
        for i in range(16):
            pid=f'p{i:02}';policy(pid,project=pid,parent='global')
            for owner in ['owner-a','owner-b']:policy(pid+':'+owner,project=pid,team=owner,parent=pid)
        reqs=[]
        for n in range(1,101):
            rid=f'r{n:03}';r=dict(project_id='p00',requirement_id=rid,title=f'需求 {n:03}',source_anchor=f'fixture#L{n}',outcome='保留需求与验收映射',scope='规划性能',acceptance=['独立回读'],priority=0,weight=1,deferred_reason='下一阶段' if 91<=n<=95 else None,revision=1)
            db.execute('INSERT INTO requirements VALUES(%s,%s,1,%s)',('p00',rid,Jsonb(r)));reqs.append(r)
        tasks=[];specs={};edges=[]
        for n in range(10000):
            tid=f't{n:05}';owner='owner-a' if n<2884 else 'owner-b';deps=[f't{i:05}' for i in [n-1,n-2] if i>=0]
            if n in [3,4,5]:deps.append('t00000')
            task=dict(project_id='p00',task_id=tid,task_revision=1,flow_revision=1,title=f'{"2884 范围" if n<2884 else "规模任务"} {n:05}',owner_id=owner,team_id=owner,requirement_ids=[f'r{n%90+1:03}'],read_set=[],write_set=[f'src/{owner}/{tid}.rs'],dependencies=deps,state='PLANNED',input_digest='a'*64,resource_request=VECTOR,envelope=None,revision=1)
            tasks.append(task);edges.extend(('p00',1,tid,dep) for dep in deps)
            specs[tid]=dict(outcome=task['title'],requirement_digest_refs={},design_anchors=[],inputs=[],mandatory_paths=task['write_set'],dependency_refs=[dict(task_id=d,project_id='p00',kind='integrated',binding_id=d+':integrated') for d in deps],contract_produces=[],contract_consumes=[],execution_profile='fixture-unbound',verification_plan='fixture-unbound',verification_case_count=1,rollback_plan='恢复原始基线',known_unknowns=[],not_proven=['真实 Agent 执行'],isolated_contract_probe=False)
        flow=dict(project_id='p00',flow_revision=1,parent_revision=None,state='DRAFT',tasks=tasks,input_digest='b'*64,approved_by=None,revision=1)
        db.execute("INSERT INTO flow_revisions VALUES('p00',1,1,'DRAFT',%s,%s)",('b'*64,Jsonb(flow)))
        with db.cursor().copy('COPY tasks(project_id,task_id,task_revision,flow_revision,team_id,owner_id,state,input_digest,revision,data) FROM STDIN') as cp:
            for t in tasks:cp.write_row(('p00',t['task_id'],1,1,t['team_id'],t['owner_id'],t['state'],t['input_digest'],1,Jsonb(t)))
        with db.cursor().copy('COPY task_revisions FROM STDIN') as cp:
            for t in tasks:cp.write_row(('p00',t['task_id'],1,Jsonb(t)))
        with db.cursor().copy('COPY task_dependencies FROM STDIN') as cp:
            for edge in edges:cp.write_row(edge)
        context=dict(requirements=[],requirement_semantic_digests={},owners=[],task_specs=specs,current_inputs={},resolved_paths={},contracts=[],source_revision='',observed_at='')
        db.execute("INSERT INTO documents VALUES('p00','flow_contexts','1',1,%s)",(Jsonb(context),))
        reference=dict(artifact_id='fixture-input',sha256='c'*64)
        db.execute("INSERT INTO documents VALUES('p00','artifacts','fixture-input',1,%s)",(Jsonb(dict(artifact_id='fixture-input',sha256='c'*64)),))
        for i in range(128):
            cid=f'ctx-{i:03}';value=dict(schema_version='forgeflow.agent-context.v1',project_id='p00',context_id=cid,position_id=f'role-{i:03}',model_route_id='unbound/no-model',input_manifest_ref=reference,prompt_ref=reference,history_refs=[],revision=1)
            db.execute("INSERT INTO documents VALUES('p00','agent_contexts',%s,1,%s)",(cid,Jsonb(value)))
        db.execute('ANALYZE')
        run['fixture']=dict(projects=16,tasks=len(tasks),dependencies=len(edges),contexts=128,filtered_cards=2884,real_agents=0)

def setup(args):
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    database='forgeflow_planning_'+secrets.token_hex(6)
    with psycopg.connect(PG+' dbname=postgres',autocommit=True) as db: db.execute('CREATE DATABASE '+database)
    repo=output/'repository';repo.mkdir()
    subprocess.run(['git','init','--quiet',str(repo)],check=True)
    (repo/'README.md').write_text('Synthetic isolated planning acceptance. No model invocation.\n')
    subprocess.run(['git','-C',str(repo),'add','README.md'],check=True)
    subprocess.run(['git','-C',str(repo),'-c','user.name=Planning verification','-c','user.email=planning@localhost','commit','--quiet','-m','Synthetic fixture'],check=True)
    with socket.socket() as sock: sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    run=dict(database=database,base=f'http://127.0.0.1:{port}',repository=str(repo),output=str(output),token=secrets.token_hex(32))
    console=args.console.resolve()
    if console.exists():
        shutil.copytree(console,output/'baseline-console')
        shutil.copytree(console,output/'candidate-console')
    env={k:v for k,v in os.environ.items() if not k.startswith('FORGEFLOW_') and k!='DATABASE_URL'}
    env.update(DATABASE_URL=f'postgresql://forgeflow@localhost:55432/{database}?host=/home/chenyoujian/.local/state/forgeflow/postgres',FORGEFLOW_BIND=f'127.0.0.1:{port}',FORGEFLOW_DATA_ROOT=str(output/'data'),FORGEFLOW_CONSOLE_DIR=str(output/'candidate-console'),FORGEFLOW_OWNER_TOKEN=run['token'],FORGEFLOW_WORKER_TOKEN=secrets.token_hex(32))
    log=open(output/'server.log','w')
    process=subprocess.Popen([str(args.server.resolve())],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    run['pid']=process.pid;write(output/'private.json',run,True)
    for _ in range(100):
        if process.poll() is not None: raise RuntimeError('Candidate startup failed; inspect '+str(output/'server.log'))
        try:
            if request(run,'/projects')[0]==200:break
        except OSError: pass
        time.sleep(.2)
    else: raise RuntimeError('Candidate did not start')
    seed(run);write(output/'private.json',run,True)
    public={k:v for k,v in run.items() if k!='token'};write(output/'setup.json',public)
    print(json.dumps({'status':'READY','base':run['base'],'output':str(output),'fixture':run['fixture']}))

def check(args):
    run=json.loads((args.output/'private.json').read_text());checks=[];timings={}
    report=dict(schema_version='forgeflow.planning-workbench-acceptance.v1',status='RUNNING',synthetic_only=True,model_calls=0,fixture=run['fixture'],checks=checks,timings=timings)
    def verify(name, condition):
        checks.append(dict(name=name,passed=bool(condition)))
        if not condition: raise AssertionError(name)
    def get(route):
        code,body,_,_=request(run,route);verify(route+' HTTP 200',code==200);return body
    try:
        data=get('/projects/p00/planning-overview')['data']
        verify('exact full planning counts',data['statistics']['task_count']==10000 and data['statistics']['dependency_count']==20000)
        verify('coverage includes gaps and deferred requirements',data['statistics']['covered']==90 and data['statistics']['uncovered']==5 and data['statistics']['deferred']==5)
        verify('contexts and attempts remain separate',data['capacity']['persistent_contexts']==128 and data['capacity']['active_attempts']==0 and data['capacity']['observed_native_sessions']==0)
        verify('summary grants no execution rights',data['execution_rights_granted'] is False)
        route='/projects/p00/tasks?q='+urllib.parse.quote('2884 范围')+'&limit=77&sort=title'
        page=get(route);verify('server search counts all 2884 matching tasks',page['total_count']==2884 and len(page['data'])==77)
        seen=[];cursor=None
        while True:
            page=get(route+('&cursor='+urllib.parse.quote(cursor) if cursor else ''));seen.extend(t['task_id'] for t in page['data']);cursor=page['next_cursor']
            if not cursor:break
        verify('sorted cursor traversal has no duplicates or omissions',len(seen)==2884 and len(set(seen))==2884)
        first=get('/projects/p00/tasks?limit=5&sort=title&order=desc')
        verify('descending tie-break is stable',first['data'][0]['task_id']=='t09999')
        cursor=first['next_cursor'];code,body,_,_=request(run,'/projects/p00/tasks?owner=owner-a&sort=title&order=desc&cursor='+urllib.parse.quote(cursor))
        verify('cursor rejects another filter',code==422 and body['code']=='INVALID_CURSOR')
        code,_,_,_=request(run,'/projects/p00/planning-overview',token=False);verify('summary requires authentication',code==401)
        other=get('/projects/p02/planning-overview')['data'];verify('projects do not share context or task counts',other['statistics']['task_count']==0 and other['capacity']['persistent_contexts']==0)
        portfolio=get('/portfolio')['data'];verify('portfolio collection preserves planning versus delivery scope',len(portfolio)==16 and next(p for p in portfolio if p['project']['project_id']=='p00')['task_progress'] is None)
        resources=get('/resource-usage');verify('resource collection covers all 16 projects',len(resources['version_vector'])==16 and len(resources['data']['policies'])==49 and resources['data']['allocation_scope']=='unreleased')
        assignment=get('/projects/p00/assignment-context')['data'];verify('assignment projection excludes private runtime bodies',assignment['attempts']==[] and len(assignment['teams'])==2 and 'envelope' not in json.dumps(assignment))
        inputs=get('/projects/p00/planning-inputs')['data']
        scenario=dict(input_revision=inputs['revision'],planning_input_digest=inputs['planning_input_digest'],start_at='2026-11-07T00:00:00Z',end_at='2026-11-14T00:00:00Z',duration_overrides={f't{i:05}':.01 for i in range(10000)},capacity_overrides={'p00':10})
        code,body,ms,_=request(run,'/projects/p00/planning-scenarios',scenario)
        write(args.output/'scenario.json',body);timings['scenario_10000_ms']=round(ms,2)
        scenario_samples=[ms]
        for _ in range(4):
            sample_code,sample_body,sample_ms,_=request(run,'/projects/p00/planning-scenarios',scenario)
            verify('repeated scenario remains complete',sample_code==200 and sample_body['data']['forecast']['complete'])
            scenario_samples.append(sample_ms)
        timings['scenario_10000']=dict(samples=5,p95_ms=round(max(scenario_samples),2),raw_ms=[round(value,2) for value in scenario_samples])
        verify('10000 task scenario computes the full graph',code==200 and body['data']['forecast']['complete'] and len(body['data']['forecast']['rows'])==10000)
        verify('scenario remains a projection',body['data']['execution_rights_granted'] is False and body['data']['capacity_overrides']=={'p00':10})
        for route in ['/projects/p00/planning-overview','/projects/p00/tasks?limit=100','/resource-usage','/portfolio','/projects/p00/snapshot']:
            samples=[];sizes=[]
            for _ in range(25):
                code,_,ms,size=request(run,route);verify('benchmark '+route+' success',code==200);samples.append(ms);sizes.append(size)
            timings[route]=dict(samples=25,p50_ms=round(statistics.median(samples),2),p95_ms=round(sorted(samples)[23],2),response_bytes=max(sizes))
        with psycopg.connect(PG+' dbname='+run['database']) as db:
            db.execute("UPDATE projects SET event_seq=event_seq+1 WHERE project_id='p00'")
        code,body,_,_=request(run,'/projects/p00/tasks?sort=title&order=desc&cursor='+urllib.parse.quote(cursor))
        verify('pagination rejects a changed project version',code==409 and body['code']=='SNAPSHOT_CHANGED')
        policy=get('/projects/p00/resources')['data'];policy=next(p for p in policy if p['scope_id']=='p00')
        update={'policy':dict(policy,limits=dict(policy['limits'],active_slot=10)),'expected_revision':policy['revision']};key=secrets.token_hex(16)
        code,one,_,_=request(run,'/projects/p00/resources',update,key=key);verify('capacity change waits for server receipt',code==200)
        code,two,_,_=request(run,'/projects/p00/resources',update,key=key);verify('duplicate capacity command replays one receipt',code==200 and one['data']==two['data'])
        code,body,_,_=request(run,'/projects/p00/resources',update);verify('second client stale resource version is rejected',code==409 and body['code']=='REVISION_CONFLICT')
        after=get('/projects/p00/planning-overview')['data'];verify('planning operations did not start attempts',after['capacity']['active_attempts']==0)
        report['status']='PASS'
    except Exception as error:
        report['status']='FAIL';report['error']=str(error);raise
    finally:
        report['source_sha256']={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in json.loads((ROOT/'planning/team-planning-round.json').read_text())['paths'] if (ROOT/p).is_file()}
        write(args.output/'api-report.json',report)
        print(json.dumps({'status':report['status'],'checks':len(checks),'timings':timings,'report':str(args.output/'api-report.json')}))

def workflow(args):
    import copy
    run=json.loads((args.output/'private.json').read_text());checks=[]
    def verify(name,condition):
        checks.append(dict(name=name,passed=bool(condition)))
        if not condition:raise AssertionError(name)
    report=dict(status='RUNNING',checks=checks,synthetic_only=True,model_calls=0)
    try:
        code,imported,_,_=request(run,'/projects/p01/source-imports',dict(name='独立验收来源',format='MARKDOWN',content='# 可回读的有限交付\n- 保留用户输入并能从服务端回读\n'))
        verify('import preserves source and requirement identity',code==200)
        requirements=request(run,'/projects/p01/requirements')[1]['data'];rid=requirements[0]['requirement_id']
        task=dict(project_id='p01',task_id='workflow-task',task_revision=1,flow_revision=1,title='验证草稿版本与冲突恢复',owner_id='owner-a',team_id='owner-a',requirement_ids=[rid],read_set=[],write_set=['src/owner-a/workflow.rs'],dependencies=[],state='PLANNED',input_digest='',resource_request=VECTOR,envelope=None,revision=1)
        spec=dict(outcome=task['title'],requirement_digest_refs={},design_anchors=[],inputs=[],mandatory_paths=task['write_set'],dependency_refs=[],contract_produces=[],contract_consumes=[],execution_profile='',verification_plan='',verification_case_count=0,rollback_plan='放弃未审定草稿',known_unknowns=[],not_proven=['真实执行及交付验收'],isolated_contract_probe=False)
        context=dict(requirements=[],requirement_semantic_digests={},owners=[],task_specs={'workflow-task':spec},current_inputs={},resolved_paths={},contracts=[],source_revision='',observed_at='')
        flow=dict(project_id='p01',flow_revision=1,parent_revision=None,state='DRAFT',tasks=[task],input_digest='',approved_by=None,revision=1)
        code,body,ms,_=request(run,'/projects/p01/flow-revisions',dict(flow=flow,context=context))
        write(args.output/'workflow-create.json',body);verify('ordinary planning saves an incomplete draft without model calls',code==200)
        flow=request(run,'/flows/p01%3A1')[1]['data'];context=request(run,'/flows/p01%3A1/context/current')[1]['data']
        proposal=copy.deepcopy(flow);proposal.update(flow_revision=2,parent_revision=1,revision=1)
        proposal['tasks'][0].update(title='人工连续编辑后的新草稿',task_revision=2,flow_revision=2,state='NEEDS_REVIEW',envelope=None)
        code,preview,_,_=request(run,'/projects/p01/flow-checks',dict(flow=proposal,context=context));write(args.output/'workflow-impact.json',preview)
        verify('server previews task and dependency impact',code==200 and preview['data']['impact']['changed_task_ids']==['workflow-task'])
        guard=dict(flow_revision=1,revision=flow['revision'],source_revision=context['source_revision'])
        code,saved,ms,_=request(run,'/projects/p01/flow-revisions',dict(flow=proposal,context=context,parent_guard=guard));write(args.output/'workflow-save.json',saved)
        report['draft_save_ms']=round(ms,2);verify('new draft has a server-confirmed receipt',code==200)
        original=request(run,'/flows/p01%3A1')[1]['data'];verify('new draft preserves the previous planning version',original['tasks'][0]['title']=='验证草稿版本与冲突恢复')
        code,updated,_,_=request(run,'/projects/p01/flow-revisions',dict(flow=original,context=context,expected_revision=original['revision']))
        write(args.output/'workflow-second-client.json',updated);verify('second client changes original parent revision',code==200)
        conflict=copy.deepcopy(proposal);conflict['flow_revision']=3;conflict['tasks'][0]['flow_revision']=3
        code,rejected,_,_=request(run,'/projects/p01/flow-revisions',dict(flow=conflict,context=context,parent_guard=guard));write(args.output/'workflow-conflict.json',rejected)
        verify('stale client cannot save against the changed parent',code==409 and rejected['code']=='REVISION_CONFLICT')
        verify('planning does not grant execution rights',request(run,'/projects/p01/assignment-context')[1]['data']['attempts']==[])
        report['status']='PASS'
    except Exception as error:report['status']='FAIL';report['error']=str(error);raise
    finally:
        write(args.output/'workflow-report.json',report);print(json.dumps(report,ensure_ascii=False))

def restart(args):
    run=json.loads((args.output/'private.json').read_text())
    env=dict(item.split('=',1) for item in pathlib.Path(f"/proc/{run['pid']}/environ").read_bytes().decode().split('\0') if '=' in item)
    console_id=hashlib.sha256((args.console.resolve()/'index.html').read_bytes()).hexdigest()[:16]
    console_path=args.output.resolve()/('console-'+console_id)
    if not console_path.exists():shutil.copytree(args.console.resolve(),console_path)
    env['FORGEFLOW_CONSOLE_DIR']=str(console_path)
    binary_id=hashlib.sha256(args.server.resolve().read_bytes()).hexdigest()
    binary_path=args.output.resolve()/'bin'/('forgeflow-server-'+binary_id[:16]);binary_path.parent.mkdir(exist_ok=True)
    if not binary_path.exists():shutil.copy2(args.server.resolve(),binary_path)
    run['binary_sha256']=binary_id;run['server']=str(binary_path)
    os.kill(run['pid'],signal.SIGTERM)
    for _ in range(100):
        try:
            with socket.create_connection(('127.0.0.1',int(run['base'].rsplit(':',1)[1])),timeout=.1):pass
        except OSError:break
        time.sleep(.1)
    log=open(args.output/'server.log','a')
    process=subprocess.Popen([str(binary_path)],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    run['pid']=process.pid;write(args.output/'private.json',run,True)
    for _ in range(100):
        if process.poll() is not None:raise RuntimeError('restart failed; inspect candidate log')
        try:
            if request(run,'/projects')[0]==200:break
        except OSError:pass
        time.sleep(.1)
    print('Restarted isolated candidate with the current binary.')

def cleanup(args):
    run=json.loads((args.output/'private.json').read_text())
    if not run['database'].startswith('forgeflow_planning_'):raise RuntimeError('unrecognized disposable database')
    try:os.kill(run['pid'],signal.SIGTERM)
    except ProcessLookupError:pass
    with psycopg.connect(PG+' dbname=postgres',autocommit=True) as db:
        db.execute('DROP DATABASE '+run['database']+' WITH (FORCE)')
    print('Stopped isolated candidate and removed its generated database; evidence retained.')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['setup','check','workflow','restart','cleanup'])
    parser.add_argument('--output',type=pathlib.Path,required=True)
    parser.add_argument('--server',type=pathlib.Path,default=pathlib.Path('/home/chenyoujian/.cache/forgeflow-control-target/debug/forgeflow-server'))
    parser.add_argument('--console',type=pathlib.Path,default=ROOT/'console/dist')
    args=parser.parse_args();globals()[args.mode](args)

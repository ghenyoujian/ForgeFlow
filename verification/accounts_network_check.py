#!/usr/bin/env python3
"""Independent PostgreSQL/HTTP acceptance. Fixture identities; zero model calls."""
import argparse,datetime,hashlib,json,os,pathlib,secrets,shutil,signal,socket,subprocess,time,urllib.request,urllib.error,urllib.parse,uuid
import psycopg
ROOT=pathlib.Path(__file__).resolve().parents[1]
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}))
PG='host=/home/chenyoujian/.local/state/forgeflow/postgres port=55432 user=forgeflow'

def database_url(database: str) -> str:
    """Return the canonical URL accepted by both sqlx and libpq.

    SQLx treats an unescaped socket path in a query value as a relative URL;
    encoding the path and carrying the non-default port keeps disposable
    server probes and Rust PostgreSQL tests on the same authority.
    """
    socket_path = urllib.parse.quote('/home/chenyoujian/.local/state/forgeflow/postgres', safe='')
    return f'postgresql://forgeflow@localhost:55432/{database}?host={socket_path}&port=55432'
def write(path,value,private=False):
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
    if private:path.chmod(0o600)
def request(run,route,body=None,token=None,workspace=None,method=None,key=None,headers=None):
    h={'Accept':'application/json',**(headers or {})}
    if token:h['Authorization']='Bearer '+token
    if workspace:h['X-ForgeFlow-Workspace']=workspace
    if body is not None:h.update({'Content-Type':'application/json','Idempotency-Key':key or str(uuid.uuid4())})
    req=urllib.request.Request(run['base']+'/api/v1'+route,data=json.dumps(body).encode() if body is not None else None,headers=h,method=method)
    try:
        with OPENER.open(req,timeout=20) as res:return res.status,json.load(res),dict(res.headers)
    except urllib.error.HTTPError as error:return error.code,json.loads(error.read()),dict(error.headers)
def launch(run,server):
    env={k:v for k,v in os.environ.items() if not k.startswith('FORGEFLOW_') and k!='DATABASE_URL'}
    # Preserve opt-in ECP dispatcher mode for disposable live probes. The
    # default remains disabled; production/baseline launches do not inherit it.
    if os.environ.get('FORGEFLOW_ECP_DISPATCHER_ENABLED') == '1':
        env['FORGEFLOW_ECP_DISPATCHER_ENABLED'] = '1'
    env.update(DATABASE_URL=database_url(run['database']),FORGEFLOW_BIND=run['base'].replace('http://',''),FORGEFLOW_DATA_ROOT=run['output']+'/data',FORGEFLOW_CONSOLE_DIR=run['output']+'/candidate-console',FORGEFLOW_OWNER_TOKEN=run['token'],FORGEFLOW_WORKER_TOKEN=run['worker_token'],FORGEFLOW_OWNER_PASSWORD=run['password'])
    with open(pathlib.Path(run['output'])/'server.log','a') as log:process=subprocess.Popen([str(server)],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    run['pid']=process.pid;write(pathlib.Path(run['output'])/'private.json',run,True)
    for _ in range(150):
        if process.poll() is not None:raise RuntimeError('Candidate startup failed; inspect server.log')
        try:
            if request(run,'/projects',token=run['token'])[0]==200:return
        except OSError:pass
        time.sleep(.2)
    raise RuntimeError('Candidate startup timeout')
def stop(run):
    if 'pid' not in run:return
    cmd=pathlib.Path(f'/proc/{run["pid"]}/cmdline')
    if cmd.exists():
        assert b'forgeflow-server' in cmd.read_bytes()
        os.kill(run['pid'],signal.SIGTERM)
        for _ in range(150):
            try:
                if pathlib.Path(f'/proc/{run["pid"]}/stat').read_text().split()[2]=='Z':return
            except FileNotFoundError:return
            time.sleep(.1)
        raise RuntimeError('Candidate did not stop; no broad kill issued')
def setup(args):
    for label,source in [('server',args.server),('console',args.console),('baseline server',args.baseline_server)]:
        if source is not None and not source.exists():raise ValueError(f'{label} does not exist: {source}')
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    database='forgeflow_accounts_'+secrets.token_hex(6)
    with psycopg.connect(PG+' dbname=postgres',autocommit=True) as db:db.execute('CREATE DATABASE '+database)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    run=dict(database=database,base=f'http://127.0.0.1:{port}',output=str(output),token=secrets.token_hex(32),worker_token=secrets.token_hex(32),password=secrets.token_hex(16))
    write(output/'private.json',run,True)
    shutil.copytree(args.console,output/'candidate-console');(output/'bin').mkdir()
    binary=output/'bin/forgeflow-server';shutil.copy2(args.server,binary);run['server']=str(binary)
    if args.baseline_server:
        launch(run,args.baseline_server.resolve())
        repo=output/'legacy-repository';subprocess.run(['git','init','--quiet',str(repo)],check=True)
        (repo/'README.md').write_text('Independent migration fixture.\n');subprocess.run(['git','-C',str(repo),'add','README.md'],check=True)
        subprocess.run(['git','-C',str(repo),'-c','user.name=Fixture','-c','user.email=fixture@localhost','commit','--quiet','-m','Fixture'],check=True)
        project=dict(project_id='legacy-fixture',name='迁移前的原有项目',root_path=str(repo),authority_mode='MANAGED',data_origin='DEMO',goal='migration fixture',technology_stack=[],timezone='UTC',paused=True,archived=False,revision=0)
        code,body,_=request(run,'/projects',project,token=run['token']);assert code==200,body
        run['legacy_project']=body['data'];stop(run)
    launch(run,binary)
    write(output/'private.json',run,True)
    write(output/'setup.json',{'base':run['base'],'database':database,'server_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'production_changed':False,'model_calls':0})
    print(json.dumps({'status':'READY','base':run['base'],'output':str(output)}))
def check(args):
    run=json.loads((args.output/'private.json').read_text());checks=[]
    report={'status':'RUNNING','synthetic_identities':True,'model_calls':0,'checks':checks}
    def verify(name,condition):
        checks.append({'name':name,'passed':bool(condition)})
        if not condition:raise AssertionError(name)
    def call(route,body=None,user=None,workspace=None,expected=200,**kw):
        code,value,headers=request(run,route,body,token=user['token'] if user else None,workspace=workspace,**kw)
        verify(f'{route} HTTP {expected} (actual {code}, {value.get("code","OK")})',code==expected)
        return value.get('data',value),headers
    try:
        call('/registrations',{'email':'broken','display_name':'x','password':'long-password-example'},expected=422)
        users=[]
        for name in ['alice','bob']:
            password=secrets.token_hex(16);email=f'{name}-{secrets.token_hex(4)}@example.test'
            value,headers=call('/registrations',{'email':email,'display_name':name,'password':password})
            user=dict(token=value['token'],password=password,email=email,account_id=value['account']['account_id'],workspace=value['account']['workspace_id'],cookie=headers['set-cookie'].split(';')[0],csrf=value['csrf_token'])
            users.append(user)
        alice,bob=users
        run['users']=users;write(args.output/'private.json',run,True)
        verify('registration creates different personal workspaces',alice['workspace']!=bob['workspace'])
        a,_=call('/me',user=alice);verify('new user has personal role, never deployment owner',a['role']=='account' and len(a['workspaces'])==1)
        value,_=call('/projects',user=alice,workspace=alice['workspace']);verify('legacy projects hidden from new account',value==[])
        if run.get('legacy_project'):
            old,_=call('/projects/legacy-fixture',user={'token':run['token']});verify('migration preserves original project JSON',old==run['legacy_project'])
            call('/projects/legacy-fixture',user=alice,workspace=alice['workspace'],expected=403)
        for route in ['/system/info','/backups','/workers/register','/attempts/foreign','/operations/foreign']:
            call(route,{} if route=='/workers/register' else None,user=alice,workspace=alice['workspace'],expected=403)
        call('/workspaces',{'name':'wrong origin'},user=alice,headers={'Origin':'https://attacker.invalid'},expected=403)
        call('/workspaces',{'name':'no csrf'},headers={'Cookie':alice['cookie']},expected=401)
        own,_=call('/workspaces',{'name':'Cookie workspace'},headers={'Cookie':alice['cookie'],'X-CSRF-Token':alice['csrf']})
        verify('cookie command requires actual CSRF',bool(own['workspace_id']))
        new_id=str(uuid.uuid4());project=dict(project_id=new_id,name='个人网站案例',root_path='',authority_mode='MANAGED',data_origin='NATIVE',goal='independent acceptance',technology_stack=['React'],timezone='UTC',paused=True,archived=False,revision=0)
        bad={**project,'project_id':str(uuid.uuid4()),'root_path':'/etc'}
        call('/projects',bad,user=alice,workspace=alice['workspace'],expected=403)
        value,_=call('/projects',project,user=alice,workspace=alice['workspace'],key='create-site')
        replay,_=call('/projects',project,user=alice,workspace=alice['workspace'],key='create-site');verify('project create retry uses original identity',value==replay)
        verify('managed repository stays in workspace root',f'/workspaces/{alice["workspace"]}/repositories/' in value['root_path'])
        run['project']=new_id;write(args.output/'private.json',run,True)
        call('/projects/'+new_id,user=bob,workspace=bob['workspace'],expected=403)
        for collection in ['native_configuration_drafts','executor_profiles','worker_project_profiles']:
            call('/projects/'+new_id+'/documents/'+collection,user=alice,workspace=alice['workspace'],expected=403)
        call('/projects/'+new_id+'/tutorial/personal-site',{},user=alice,workspace=alice['workspace'],key='tutorial')
        value,_=call('/projects/'+new_id+'/tutorial/personal-site',{},user=alice,workspace=alice['workspace'],key='tutorial');verify('tutorial import retry is durable',value['replayed'] is True)
        cards,_=call('/projects/'+new_id+'/tasks',user=alice,workspace=alice['workspace']);verify('tutorial writes twelve real canonical tasks',len(cards)==12)
        call('/projects/'+new_id+'/tutorial/personal-site',{},user=alice,workspace=alice['workspace'],key='different-import',expected=409)
        invite,_=call('/workspaces/'+alice['workspace']+'/invitations',{'role':'EDITOR','email':bob['email']},user=alice)
        call('/invitations/accept',{'token':invite['invite_token']},user=bob)
        call('/invitations/accept',{'token':invite['invite_token']},user=bob)
        call('/projects/'+new_id,user=bob,workspace=alice['workspace'])
        own_projects,_=call('/projects',user=bob,workspace=bob['workspace']);verify('joining keeps personal workspace isolated',own_projects==[])
        roster=[]
        for user in users:
            connector,_=call('/projects/'+new_id+'/agent-network/integrations',{'name':user['email'].split('@')[0]},user=user,workspace=alice['workspace'])
            agent,_=call('/projects/'+new_id+'/agent-network/agents',{'native_agent_id':'fixture-'+user['account_id'],'name':'fixture-'+user['email'].split('@')[0]},user=connector,workspace=alice['workspace'])
            roster.append(dict(connector=connector,agent=agent))
        ca,cb=roster[0]['connector'],roster[1]['connector'];aa,ab=roster[0]['agent'],roster[1]['agent'];base='/projects/'+new_id+'/agent-network'
        call(base+'/agents',user={'token':run['token']},workspace=alice['workspace'],expected=403)
        renewed,_=call(base+'/integrations/'+ca['integration_id']+'/sessions',{},user=alice,workspace=alice['workspace'])
        restored,_=call(base+'/agents',{'native_agent_id':aa['native_agent_id'],'name':aa['name']},user=renewed,workspace=alice['workspace'])
        verify('credential renewal preserves canonical agent identity',restored['agent_id']==aa['agent_id'] and renewed['integration_id']==ca['integration_id'] and renewed['token']!=ca['token'])
        call('/projects/'+new_id,user=ca,workspace=alice['workspace'],expected=403)
        message=dict(client_message_id='stable-message',sender_agent_id=aa['agent_id'],recipient_agent_id=ab['agent_id'],parts=[dict(kind='text',text='Please review the API contract.')])
        sent,_=call(base+'/messages',message,user=ca,workspace=alice['workspace'])
        again,_=call(base+'/messages',message,user=ca,workspace=alice['workspace']);verify('identical retry returns one durable message',sent['message_id']==again['message_id'] and again['replayed'])
        call(base+'/messages',{**message,'parts':[dict(kind='text',text='different')]},user=ca,workspace=alice['workspace'],expected=409)
        call(base+'/messages',{**message,'client_message_id':'spoof','sender_agent_id':ab['agent_id']},user=ca,workspace=alice['workspace'],expected=403)
        inbox,_=call(base+'/messages?agent_id='+ab['agent_id'],user=cb,workspace=alice['workspace']);verify('second user connector receives first user message',len(inbox['items'])==1 and inbox['items'][0]['message_id']==sent['message_id'])
        hidden,_=call(base+'/messages?agent_id='+ab['agent_id'],user=ca,workspace=alice['workspace']);verify('connector cannot read another connector inbox',hidden['items']==[])
        call(base+'/messages/'+sent['message_id']+'/receipts',{'recipient_agent_id':ab['agent_id']},user=ca,workspace=alice['workspace'],expected=404)
        ack,_=call(base+'/messages/'+sent['message_id']+'/receipts',{'recipient_agent_id':ab['agent_id']},user=cb,workspace=alice['workspace']);verify('recipient receipt is persisted',ack['received_at'] is not None)
        reply,_=call(base+'/messages',dict(client_message_id='reply',sender_agent_id=ab['agent_id'],recipient_agent_id=aa['agent_id'],reply_to=sent['message_id'],parts=[dict(kind='data',data={'contract':'reviewed','task_complete':False})]),user=cb,workspace=alice['workspace']);verify('reply inherits original thread',reply['thread_id']==sent['thread_id'])
        log,_=call(base+'/messages',user=alice,workspace=alice['workspace']);verify('authorized members inspect shared project log',len(log['items'])==2)
        # History exceeds multiple pages. All rows are accepted through the real
        # send endpoint; no direct message-table fixtures or mocked responses.
        history=log['items'][:]
        for index in range(205):
            item,_=call(base+'/messages',{**message,'client_message_id':f'history-{index:03d}','parts':[dict(kind='text',text=f'Historical handoff {index:03d}')]},user=ca,workspace=alice['workspace'])
            history.append(item)
        recent,_=call(base+'/messages?latest=true',user=alice,workspace=alice['workspace'])
        verify('latest window contains exactly the newest hundred without replaying history',[m['message_id'] for m in recent['items']]==[m['message_id'] for m in history[-100:]] and recent['has_more'] and recent['direction']=='older')
        middle,_=call(base+'/messages?before='+str(recent['previous_cursor']),user=alice,workspace=alice['workspace'])
        oldest,_=call(base+'/messages?before='+str(middle['previous_cursor']),user=alice,workspace=alice['workspace'])
        verify('backwards history pages contain all accepted messages without gaps or duplicates',[m['message_id'] for m in oldest['items']+middle['items']+recent['items']]==[m['message_id'] for m in history] and len(oldest['items'])==7 and not oldest['has_more'])
        exact,_=call(base+'/messages?after='+str(history[-101]['sequence']),user=alice,workspace=alice['workspace'])
        verify('exactly one hundred remaining messages have no phantom next page',len(exact['items'])==100 and not exact['has_more'])
        owned,_=call(base+'/messages?latest=true',user=ca,workspace=alice['workspace'])
        verify('latest mode preserves connector inbox isolation',len(owned['items'])==1 and owned['items'][0]['message_id']==reply['message_id'])
        hidden,_=call(base+'/messages?latest=true&agent_id='+ab['agent_id'],user=ca,workspace=alice['workspace']);verify('latest agent filter cannot cross connector identities',not hidden['items'])
        for query in ['after=-1','before=0','after=0&latest=true','before=1&latest=true','before=1&after=0']:
            call(base+'/messages?'+query,user=alice,workspace=alice['workspace'],expected=422)
        samples=[]
        for _ in range(25):
            started=time.perf_counter();code,value,_=request(run,base+'/messages?latest=true',token=alice['token'],workspace=alice['workspace']);samples.append((time.perf_counter()-started)*1000);assert code==200 and len(value['data']['items'])==100
        report['latest_window_benchmark']={'accepted_messages':len(history),'samples':len(samples),'p95_ms':sorted(samples)[int(len(samples)*.95)],'returned_per_read':100,'scope':'local isolated synthetic messages; no model calls'}
        call(base+'/integrations/'+cb['integration_id']+'/revoke',{},user=bob,workspace=alice['workspace'])
        replay,_=call(base+'/messages',message,user=ca,workspace=alice['workspace'])
        verify('accepted message retry survives recipient revocation',replay['message_id']==sent['message_id'] and replay['replayed'])
        call(base+'/messages',{**message,'parts':[dict(kind='text',text='changed after revocation')]},user=ca,workspace=alice['workspace'],expected=409)
        call(base+'/messages',{**message,'client_message_id':'new-after-recipient-revoked'},user=ca,workspace=alice['workspace'],expected=404)
        directory,_=call(base+'/agents',user=alice,workspace=alice['workspace']);verify('revoked recipient is marked unavailable',any(a['agent_id']==ab['agent_id'] and not a['available'] for a in directory))
        call('/workspaces/'+alice['workspace']+'/members/'+bob['account_id'],{'role':'VIEWER'},user=alice,method='PATCH')
        call(base+'/agents',user=cb,workspace=alice['workspace'],expected=403)
        call(base+'/messages',message,user=bob,workspace=alice['workspace'],expected=403)
        call('/projects/'+new_id+'/flow-revisions',{},user=bob,workspace=alice['workspace'],expected=403)
        call('/projects/'+new_id,user=bob,workspace=alice['workspace'])
        stream_request=urllib.request.Request(run['base']+'/api/v1/projects/'+new_id+'/events',headers={'Authorization':'Bearer '+bob['token'],'X-ForgeFlow-Workspace':alice['workspace'],'Accept':'text/event-stream'})
        stream=OPENER.open(stream_request,timeout=5)
        verify('member SSE is connected before revocation',bool(stream.readline()))
        call('/workspaces/'+alice['workspace']+'/members/'+bob['account_id'],{'role':None},user=alice,method='PATCH')
        remaining=stream.read(1048576);stream.close();verify('membership removal closes existing SSE stream',len(remaining)<1048576)
        call('/projects/'+new_id,user=bob,workspace=alice['workspace'],expected=403)
        call('/invitations/accept',{'token':invite['invite_token']},user=bob,expected=422)
        call('/workspaces/'+alice['workspace']+'/members/'+alice['account_id'],{'role':None},user=alice,method='PATCH',expected=422)
        value,_=call('/resource-usage',user=alice,workspace=alice['workspace']);verify('resource read exposes no foreign project identifiers','legacy-fixture' not in json.dumps(value))
        revoked,_=call('/workspaces/'+alice['workspace']+'/invitations',{'role':'VIEWER','email':None},user=alice)
        call('/workspaces/'+alice['workspace']+'/invitations/'+revoked['invitation_id']+'/revoke',{},user=alice)
        call('/invitations/accept',{'token':revoked['invite_token']},user=bob,expected=422)
        transfer,_=call('/workspaces',{'name':'Ownership transfer fixture'},user=alice,key='creator-replay')
        invitation,_=call('/workspaces/'+transfer['workspace_id']+'/invitations',{'role':'EDITOR','email':bob['email']},user=alice)
        call('/invitations/accept',{'token':invitation['invite_token']},user=bob)
        call('/workspaces/'+transfer['workspace_id']+'/members/'+bob['account_id'],{'role':'OWNER'},user=alice,method='PATCH')
        call('/workspaces/'+transfer['workspace_id']+'/members/'+alice['account_id'],{'role':None},user=alice,method='PATCH')
        call('/workspaces',{'name':'Ownership transfer fixture'},user=alice,key='creator-replay',expected=403)
        call('/workspaces/'+transfer['workspace_id']+'/members',user=alice,expected=403)
        signed,_=call('/session',{'email':alice['email'].upper(),'password':alice['password']})
        verify('personal login accepts normalized email',signed['account']['account_id']==alice['account_id'])
        previous=dict(alice);new_password=secrets.token_hex(16)
        replacement,_=call('/account/password',{'current_password':alice['password'],'new_password':new_password},user=alice)
        alice['token']=replacement['token'];alice['password']=new_password
        call('/me',user=previous,expected=401)
        call(base+'/agents',user=ca,workspace=alice['workspace'],expected=401)
        call('/me',headers={'Cookie':previous['cookie']},expected=401)
        call('/me',user=alice)
        signed,_=call('/session',{'email':alice['email'],'password':new_password});verify('new password issues a valid new personal session',signed['account']['account_id']==alice['account_id'])
        admin,_=call('/session',{'password':run['password']});verify('legacy owner password session remains compatible',bool(admin['token']))
        auth_state=json.loads((args.output/'data/auth.json').read_text())
        verify('personal credentials stay outside the legacy Owner map',all(u['token'] not in auth_state['sessions'] and u['token'] in auth_state['account_sessions'] for u in users))
        # Retain fixtures privately for the real browser and installed plugin tests.
        run.update(users=users,roster=roster);write(args.output/'private.json',run,True)
        report['status']='PASS'
    except Exception as error:report['status']='FAIL';report['error']=str(error);raise
    finally:write(args.output/'accounts-api-report.json',report)
    print(json.dumps({'status':report['status'],'checks':len(checks),'model_calls':0}))
def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['setup','check','restart','cleanup']);parser.add_argument('--output',type=pathlib.Path,required=True);parser.add_argument('--server',type=pathlib.Path);parser.add_argument('--console',type=pathlib.Path,default=ROOT/'console/dist');parser.add_argument('--baseline-server',type=pathlib.Path);args=parser.parse_args()
    if args.action=='setup':setup(args)
    elif args.action=='check':check(args)
    else:
        run=json.loads((args.output/'private.json').read_text());stop(run)
        if args.action=='restart':
            if args.server:shutil.copy2(args.server,run['server'])
            shutil.rmtree(args.output/'candidate-console');shutil.copytree(args.console,args.output/'candidate-console');launch(run,pathlib.Path(run['server']))
        else:
            assert run['database'].startswith('forgeflow_accounts_')
            with psycopg.connect(PG+' dbname=postgres',autocommit=True) as db:db.execute('DROP DATABASE '+run['database'])
            write(args.output/'cleanup.json',{'stopped_pid':run['pid'],'dropped_database':run['database'],'production_changed':False})
if __name__=='__main__':main()

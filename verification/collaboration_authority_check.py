#!/usr/bin/env python3
"""Actual HTTP/PostgreSQL permission races in an isolated candidate; zero models."""
import argparse, concurrent.futures, hashlib, http.client, json, pathlib, secrets, shutil, socket, time, urllib.parse, urllib.request, urllib.error, uuid
import psycopg

ROOT=pathlib.Path(__file__).resolve().parents[1]
PG='host=/home/chenyoujian/.local/state/forgeflow/postgres port=55432 user=forgeflow'
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}))

def write(path,value,private=False):
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
    if private:path.chmod(0o600)

def request(run,route,body=None,user=None,workspace=None,method=None,key=None):
    headers={'Accept':'application/json'}
    if user:headers['Authorization']='Bearer '+user['token']
    if workspace:headers['X-ForgeFlow-Workspace']=workspace
    if body is not None:headers.update({'Content-Type':'application/json','Idempotency-Key':key or str(uuid.uuid4())})
    req=urllib.request.Request(run['base']+'/api/v1'+route,data=json.dumps(body).encode() if body is not None else None,headers=headers,method=method)
    try:
        response=OPENER.open(req,timeout=20)
    except urllib.error.HTTPError as error:response=error
    with response:
        raw=response.read()
        try:value=json.loads(raw)
        except (ValueError,UnicodeDecodeError):value={'code':'NON_JSON_VALIDATION_RESPONSE'}
        return response.status,value.get('data',value)

class SlowBody:
    """100 Continue proves the authorized middleware has started polling Body."""
    def __init__(self,run,route,body,user,workspace,key=None):
        url=urllib.parse.urlparse(run['base']);self.sock=socket.create_connection((url.hostname,url.port),timeout=10)
        self.body=json.dumps(body).encode()
        headers=[f'POST /api/v1{route} HTTP/1.1',f'Host: {url.netloc}',f'Authorization: Bearer {user["token"]}',f'X-ForgeFlow-Workspace: {workspace}','Content-Type: application/json',f'Idempotency-Key: {key or uuid.uuid4()}',f'Content-Length: {len(self.body)}','Expect: 100-continue','Connection: close','','']
        self.sock.sendall('\r\n'.join(headers).encode())
        reader=self.sock.makefile('rb');line=reader.readline()
        if b' 100 ' not in line:raise AssertionError('Expected real HTTP 100 Continue barrier, got '+line.decode().strip())
        while reader.readline() not in (b'\r\n',b''):pass
        reader.close()
    def finish(self):
        try:
            self.sock.sendall(self.body);response=http.client.HTTPResponse(self.sock);response.begin();raw=response.read()
            try:value=json.loads(raw)
            except (ValueError,UnicodeDecodeError):value={'code':'NON_JSON_VALIDATION_RESPONSE'}
            return response.status,value.get('data',value)
        finally:self.sock.close()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=pathlib.Path,required=True);parser.add_argument('--observe-before',action='store_true');args=parser.parse_args()
    out=args.output.resolve();run=json.loads((out/'private.json').read_text());tag='authority-before' if args.observe_before else 'authority-final'
    report={'status':'RUNNING','synthetic_accounts':True,'model_calls':0,'checks':[],'barriers':[],'runner_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(pathlib.Path(run['server']).read_bytes()).hexdigest()}
    shutil.copy2(__file__,out/(tag+'-runner.py'))
    def verify(name,passed):
        report['checks'].append({'name':name,'passed':bool(passed)})
        if not passed and not args.observe_before:raise AssertionError(name)
    def call(route,body=None,user=None,workspace=None,method=None,key=None):
        status,value=request(run,route,body,user,workspace,method,key)
        assert status==200,(route,status,value.get('code') if isinstance(value,dict) else '')
        return value
    def account(name):
        email=f'{name}-{uuid.uuid4()}@example.test';password=secrets.token_hex(16)
        value=call('/registrations',{'email':email,'display_name':name,'password':password})
        return {'email':email,'password':password,'token':value['token'],'account_id':value['account']['account_id'],'workspace':value['account']['workspace_id']}
    try:
        alice,bob=account('authority-owner'),account('authority-editor');workspace=alice['workspace']
        def members():return call(f'/workspaces/{workspace}/members',user=alice)
        def ensure_editor():
            member=next((v for v in members() if v['account_id']==bob['account_id']),None)
            if member is None:
                invite=call(f'/workspaces/{workspace}/invitations',{'role':'EDITOR','email':bob['email']},alice)
                call('/invitations/accept',{'token':invite['invite_token']},bob)
            elif member['role']!='EDITOR':call(f'/workspaces/{workspace}/members/{bob["account_id"]}',{'role':'EDITOR'},alice,method='PATCH')
        def downgrade(role='VIEWER'):return call(f'/workspaces/{workspace}/members/{bob["account_id"]}',{'role':role},alice,method='PATCH')
        def project(name):
            pid=str(uuid.uuid4());call('/projects',{'project_id':pid,'name':name,'root_path':'','authority_mode':'MANAGED','data_origin':'NATIVE','goal':'Isolated permission race','technology_stack':[],'timezone':'UTC','paused':True,'archived':False,'revision':0},alice,workspace);return pid
        p=project('Authority planning');ensure_editor()
        write(out/(tag+'-private.json'),{'alice':alice,'bob':bob,'workspace':workspace,'project':p},True)
        member_route=f'/workspaces/{workspace}/members/{bob["account_id"]}'
        for name,body in [('missing role',{}),('misspelled role',{'roel':'VIEWER'}),('unknown field',{'role':'VIEWER','unexpected':True}),('invalid role',{'role':'owner'}),('null with unknown field',{'role':None,'unexpected':True})]:
            ensure_editor();status,_=request(run,member_route,body,alice,method='PATCH');current=next((v for v in members() if v['account_id']==bob['account_id']),None)
            verify('member '+name+' is rejected without changing membership',status==422 and current is not None and current['role']=='EDITOR')
        ensure_editor()
        for name,body in [('misspelled email',{'role':'EDITOR','emali':bob['email']}),('unexpected invite field',{'role':'VIEWER','email':bob['email'],'unexpected':True})]:
            before_count=len(call(f'/workspaces/{workspace}/invitations',user=alice));status,_=request(run,f'/workspaces/{workspace}/invitations',body,alice);after_count=len(call(f'/workspaces/{workspace}/invitations',user=alice))
            verify('invitation '+name+' cannot silently widen or create an invitation',status==422 and before_count==after_count)
        downgrade(None);verify('explicit null still removes a member',not any(v['account_id']==bob['account_id'] for v in members()));ensure_editor()
        def requirement(label):return {'project_id':p,'requirement_id':label+'-'+uuid.uuid4().hex,'title':label,'source_anchor':'fixture#authority','outcome':'Only current editors may save','scope':'isolated','acceptance':['No late unauthorized write'],'priority':0,'weight':1,'deferred_reason':None,'revision':1}
        def exists(pid,rid):return any(v['requirement_id']==rid for v in call(f'/projects/{pid}/requirements',user=alice,workspace=workspace))
        for role,label in [('VIEWER','slow-downgrade'),(None,'slow-removal')]:
            ensure_editor();body=requirement(label);slow=SlowBody(run,f'/projects/{p}/requirements',body,bob,workspace);report['barriers'].append({'case':label,'barrier':'actual HTTP 100 Continue'});downgrade(role);status,_=slow.finish()
            verify(label+' cannot save after acknowledged role change',status==403 and not exists(p,body['requirement_id']))
        # The global coordination lock holds a fully uploaded catalog command
        # before its transaction can start applying writes. It is database-local.
        def wait_lock(fragment,timeout=5):
            deadline=time.monotonic()+timeout
            with psycopg.connect(PG+' dbname='+run['database'],autocommit=True) as observer:
                while time.monotonic()<deadline:
                    if observer.execute("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE %s)",('%'+fragment+'%',)).fetchone()[0]:return True
                    time.sleep(.01)
            return False
        def queued(route,body,label,key=None):
            ensure_editor()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                with psycopg.connect(PG+' dbname='+run['database']) as blocker:
                    blocker.execute('SELECT pg_advisory_xact_lock(46001337)')
                    future=pool.submit(request,run,route,body,bob,workspace,None,key)
                    try:
                        assert wait_lock('pg_advisory_xact_lock(46001337)'),label+' did not reach the real coordination lock'
                        report['barriers'].append({'case':label,'barrier':'observed PostgreSQL advisory-lock wait'});downgrade()
                    finally:blocker.rollback()
                    return future.result(timeout=15)
        body=requirement('queued-requirement');status,_=queued(f'/projects/{p}/requirements',body,'queued requirement')
        verify('fully uploaded queued command rechecks permission before writing',status==403 and not exists(p,body['requirement_id']))
        ensure_editor();replayed=requirement('replay');key='race-replay-'+str(uuid.uuid4());call(f'/projects/{p}/requirements',replayed,bob,workspace,key=key)
        status,_=queued(f'/projects/{p}/requirements',replayed,'queued idempotency replay',key)
        verify('idempotency replay cannot bypass current write authority',status==403 and exists(p,replayed['requirement_id']))
        tutorial=project('Authority tutorial');status,_=queued(f'/projects/{tutorial}/tutorial/personal-site',{},'queued tutorial')
        cards=call(f'/projects/{tutorial}/tasks',user=alice,workspace=workspace)
        verify('tutorial transaction rechecks permission and preserves an empty project',status==403 and not cards)
        new_pid=str(uuid.uuid4());body={'project_id':new_pid,'name':'Queued create','root_path':'','authority_mode':'MANAGED','data_origin':'NATIVE','goal':'No late project','technology_stack':[],'timezone':'UTC','paused':True,'archived':False,'revision':0}
        status,_=queued('/projects',body,'queued project create')
        projects=call('/projects',user=alice,workspace=workspace)
        verify('new project binding is rejected after queued creator loses editor role',status==403 and not any(v['project_id']==new_pid for v in projects))
        # In the opposite order, an already-authorized transaction must retain
        # the workspace read lock until commit, so revocation cannot acknowledge
        # first and then let that transaction write afterwards.
        ensure_editor();body=requirement('commit-before-revoke')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            with psycopg.connect(PG+' dbname='+run['database']) as blocker:
                blocker.execute('SELECT project_id FROM projects WHERE project_id=%s FOR UPDATE',(p,))
                saving=pool.submit(request,run,f'/projects/{p}/requirements',body,bob,workspace)
                assert wait_lock('FROM projects WHERE project_id=$1 FOR UPDATE'),'write did not reach project lock'
                revoking=pool.submit(request,run,member_route,{'role':'VIEWER'},alice,None,'PATCH')
                try:ordered=wait_lock('FROM workspaces WHERE workspace_id=$1 FOR UPDATE',timeout=1.5) and not revoking.done()
                finally:blocker.rollback()
                save_status,_=saving.result(timeout=15);revoke_status,_=revoking.result(timeout=15)
        verify('authorized commit and membership revocation have a consistent transaction order',ordered and save_status==200 and revoke_status==200 and exists(p,body['requirement_id']))
        # Network transactions already check membership; keep that guarantee.
        ensure_editor();base=f'/projects/{p}/agent-network';connector=call(base+'/integrations',{'name':'Authority recipient'},alice,workspace);agent=call(base+'/agents',{'native_agent_id':'fixture-'+str(uuid.uuid4()),'name':'Authority recipient'},connector,workspace)
        slow=SlowBody(run,base+'/messages',{'client_message_id':str(uuid.uuid4()),'recipient_agent_id':agent['agent_id'],'parts':[{'kind':'text','text':'Must reject after downgrade'}]},bob,workspace);downgrade();status,_=slow.finish()
        verify('network messages keep their existing transaction-level membership checks',status==403)
        ensure_editor();body=requirement('slow-logout');slow=SlowBody(run,f'/projects/{p}/requirements',body,bob,workspace);call('/logout',{},bob);status,_=slow.finish()
        verify('logout during body upload prevents the pending mutation',status==401 and not exists(p,body['requirement_id']))
        replacement=call('/session',{'email':bob['email'],'password':bob['password']});bob['token']=replacement['token']
        body=requirement('slow-password');slow=SlowBody(run,f'/projects/{p}/requirements',body,bob,workspace);password=secrets.token_hex(16);replacement=call('/account/password',{'current_password':bob['password'],'new_password':password},bob);bob.update(token=replacement['token'],password=password);status,_=slow.finish()
        verify('password rotation during body upload prevents the pending mutation',status==401 and not exists(p,body['requirement_id']))
        verify('replacement credential still permits an ordinary authorized save',request(run,f'/projects/{p}/requirements',requirement('ordinary-save'),bob,workspace)[0]==200)
        write(out/(tag+'-private.json'),{'alice':alice,'bob':bob,'workspace':workspace,'project':p},True)
        report['status']='OBSERVED_BASELINE' if args.observe_before else 'PASS'
    except Exception as error:report['status']='FAIL';report['error']=str(error);raise
    finally:write(out/(tag+'-report.json'),report)
    print(json.dumps({'status':report['status'],'checks':len(report['checks']),'failed':[c['name'] for c in report['checks'] if not c['passed']],'model_calls':0}))
if __name__=='__main__':main()

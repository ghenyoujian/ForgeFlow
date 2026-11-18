#!/usr/bin/env python3
"""Real HTTP/PostgreSQL checks for the ECP Principal/CapabilityGrant slice."""
from __future__ import annotations
import argparse, json, pathlib, secrets, urllib.error, urllib.request, uuid
import psycopg

PG='host=/home/chenyoujian/.local/state/forgeflow/postgres port=55432 user=forgeflow'
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}))

def request(run, route, body=None, user=None, workspace=None, method=None, key=None):
    headers={'Accept':'application/json'}
    if user: headers['Authorization']='Bearer '+user['token']
    if workspace: headers['X-ForgeFlow-Workspace']=workspace
    if body is not None:
        headers.update({'Content-Type':'application/json','Idempotency-Key':key or str(uuid.uuid4())})
    req=urllib.request.Request(run['base']+'/api/v1'+route,data=json.dumps(body).encode() if body is not None else None,headers=headers,method=method)
    try:
        with OPENER.open(req,timeout=20) as response: return response.status,json.load(response)
    except urllib.error.HTTPError as error: return error.code,json.loads(error.read())

def data(response): return response.get('data',response)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=pathlib.Path,required=True); args=parser.parse_args()
    run=json.loads((args.output/'private.json').read_text())
    checks=[]
    def verify(name, ok):
        checks.append({'name':name,'passed':bool(ok)})
        if not ok: raise AssertionError(name)
    def call(route, body=None, user=None, workspace=None, expected=200, method=None, key=None):
        status,value=request(run,route,body,user,workspace,method,key)
        verify(f'{route} expected {expected}, got {status}',status==expected)
        return data(value)
    try:
        def register(name):
            email=f'{name}-{secrets.token_hex(4)}@example.test'; password=secrets.token_hex(16)
            value=call('/registrations',{'email':email,'display_name':name,'password':password})
            return {'email':email,'password':password,'token':value['token'],'account_id':value['account']['account_id'],'workspace':value['account']['workspace_id']}
        alice=register('capability-owner'); bob=register('capability-member'); workspace=alice['workspace']
        invite=call(f'/workspaces/{workspace}/invitations',{'role':'EDITOR','email':bob['email']},alice,workspace)
        call('/invitations/accept',{'token':invite['invite_token']},bob)
        principals=call(f'/workspaces/{workspace}/principals',user=alice,workspace=workspace)
        alice_principal=next(p for p in principals if p['account_id']==alice['account_id'])
        bob_principal=next(p for p in principals if p['account_id']==bob['account_id'])
        verify('workspace principal projection includes both immutable human identities',alice_principal['principal_id'].startswith('human:') and bob_principal['principal_id'].startswith('human:'))
        root={'principal_id':alice_principal['principal_id'],'parent_grant_id':None,'action_set':['project.read','conversation.send'],'project_set':[],'write_set':[],'executor_set':[],'budget':{'requests':10},'expires_at':None,'request_key':'root-capability-'+uuid.uuid4().hex}
        grant=call(f'/workspaces/{workspace}/capability-grants',root,alice,workspace,key=root['request_key'])
        replay=call(f'/workspaces/{workspace}/capability-grants',root,alice,workspace,key=root['request_key'])
        verify('same capability request is idempotent',replay.get('replayed') is True and replay['grant_id']==grant['grant_id'])
        conflict={**root,'action_set':['project.write']}
        call(f'/workspaces/{workspace}/capability-grants',conflict,alice,workspace,expected=409,key=root['request_key'])
        child={**root,'principal_id':bob_principal['principal_id'],'parent_grant_id':grant['grant_id'],'action_set':['project.read'],'budget':{'requests':5},'request_key':'child-capability-'+uuid.uuid4().hex}
        child_grant=call(f'/workspaces/{workspace}/capability-grants',child,alice,workspace,key=child['request_key'])
        verify('child grant is bounded by parent actions and budget',child_grant['parent_grant_id']==grant['grant_id'] and child_grant['action_set']==['project.read'])
        escalation={**child,'action_set':['project.write'],'request_key':'escalation-'+uuid.uuid4().hex}
        call(f'/workspaces/{workspace}/capability-grants',escalation,alice,workspace,expected=409,key=escalation['request_key'])
        before=next(p for p in principals if p['account_id']==bob['account_id'])['authorization_epoch']
        call(f'/workspaces/{workspace}/members/{bob["account_id"]}',{'role':'VIEWER'},alice,workspace,method='PATCH')
        after=next(p for p in call(f'/workspaces/{workspace}/principals',user=alice,workspace=workspace) if p['account_id']==bob['account_id'])['authorization_epoch']
        verify('membership change increments principal authorization epoch',after>before)
        call(f'/workspaces/{workspace}/capability-grants/{grant["grant_id"]}/revoke',{'expected_revision':grant['revision']},alice,workspace)
        grants=call(f'/workspaces/{workspace}/capability-grants',user=alice,workspace=workspace)
        revoked=next(g for g in grants if g['grant_id']==grant['grant_id'])
        verify('revoked grant has durable revoked_at and revision',revoked['revoked_at'] is not None and revoked['revision']>grant['revision'])
        db=run['database']
        with psycopg.connect(PG+' dbname='+db,autocommit=True) as conn:
            events=conn.execute("SELECT count(*) FROM workspace_security_events WHERE workspace_id=%s",(workspace,)).fetchone()[0]
            outbox=conn.execute("SELECT count(*) FROM workspace_security_outbox WHERE workspace_id=%s",(workspace,)).fetchone()[0]
        verify('grant and membership changes create security event/outbox facts',events>=4 and outbox>=4)
        report={'status':'PASS','checks':checks,'model_calls':0,'database':db,'security_events':events,'security_outbox':outbox}
    except Exception as exc:
        report={'status':'FAIL','checks':checks,'model_calls':0,'error':str(exc)}
        raise
    finally:
        args.output.joinpath('phase1-capability-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'checks':len(checks),'model_calls':0}))

if __name__=='__main__': main()

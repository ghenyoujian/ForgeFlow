#!/usr/bin/env python3
"""Disposable PostgreSQL/API checks for the ECP 0017 messaging runtime."""
from __future__ import annotations
import argparse, json, pathlib, secrets, urllib.error, urllib.request, uuid
import psycopg

PG='host=/home/chenyoujian/.local/state/forgeflow/postgres port=55432 user=forgeflow'
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}))

def call(run,route,body=None,user=None,workspace=None,expected=200,key=None):
    headers={'Accept':'application/json'}
    if user: headers['Authorization']='Bearer '+user['token']
    if workspace: headers['X-ForgeFlow-Workspace']=workspace
    if body is not None: headers.update({'Content-Type':'application/json','Idempotency-Key':key or str(uuid.uuid4())})
    req=urllib.request.Request(run['base']+'/api/v1'+route,data=json.dumps(body).encode() if body is not None else None,headers=headers)
    try:
        with OPENER.open(req,timeout=20) as res: status,payload=res.status,json.load(res)
    except urllib.error.HTTPError as exc:
        raw=exc.read()
        try:
            payload=json.loads(raw)
        except (ValueError,UnicodeDecodeError):
            payload={'raw':raw.decode('utf-8','replace')}
        status=exc.code
    if status!=expected: raise AssertionError(f'{route}: expected {expected}, got {status}: {payload}')
    return payload.get('data',payload)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=pathlib.Path,required=True); args=parser.parse_args()
    run=json.loads((args.output/'private.json').read_text()); checks=[]
    def verify(name,ok):
        checks.append({'name':name,'passed':bool(ok)})
        if not ok: raise AssertionError(name)
    def register(label):
        email=f'{label}-{secrets.token_hex(3)}@example.test'; password=secrets.token_hex(16)
        value=call(run,'/registrations',{'email':email,'display_name':label,'password':password})
        return {'token':value['token'],'account_id':value['account']['account_id'],'workspace':value['account']['workspace_id'],'email':email}
    try:
        alice=register('message-owner'); bob=register('message-member'); workspace=alice['workspace']
        invite=call(run,f'/workspaces/{workspace}/invitations',{'role':'EDITOR','email':bob['email']},user=alice,workspace=workspace)
        call(run,'/invitations/accept',{'token':invite['invite_token']},user=bob)
        conversation_id='conversation-'+uuid.uuid4().hex; alice_principal='human:'+alice['account_id']; bob_principal='human:'+bob['account_id']
        conversation_key='conversation-create-'+uuid.uuid4().hex
        conversation=call(run,f'/workspaces/{workspace}/conversations',{'conversation_id':conversation_id,'project_id':None,'participant_principal_ids':[alice_principal,bob_principal],'request_key':conversation_key},user=alice,workspace=workspace,key=conversation_key)
        thread_id='thread-'+uuid.uuid4().hex; thread_key='thread-create-'+uuid.uuid4().hex; thread=call(run,f'/conversations/{conversation_id}/threads',{'thread_id':thread_id,'task_id':None,'request_key':thread_key},user=alice,workspace=workspace,key=thread_key)
        verify('conversation and thread are durable',conversation['conversation_id']==conversation_id and thread['thread_id']==thread_id)
        request_id='message-request-'+uuid.uuid4().hex; body={'thread_id':thread_id,'message_kind':'chat.message','client_request_id':request_id,'payload':{'text':'hello'},'correlation_id':None,'causation_id':None,'expires_at':None}
        first=call(run,f'/conversations/{conversation_id}/messages',body,user=alice,workspace=workspace,key=request_id)
        replay=call(run,f'/conversations/{conversation_id}/messages',body,user=alice,workspace=workspace,key=request_id)
        verify('sender idempotency replays the same sequence',replay['replayed'] is True and replay['sequence']==first['sequence'])
        conflict={**body,'payload':{'text':'changed'}}
        call(run,f'/conversations/{conversation_id}/messages',conflict,user=alice,workspace=workspace,expected=409,key=request_id)
        listed=call(run,f'/conversations/{conversation_id}/messages?after=0&limit=10',user=alice,workspace=workspace)
        verify('cursor list returns one committed message',len(listed['items'])==1 and listed['items'][0]['sequence']==first['sequence'])
        db=run['database']
        with psycopg.connect(PG+' dbname='+db,autocommit=True) as conn:
            row=conn.execute("SELECT delivery_id FROM ecp_deliveries WHERE message_id=%s",(first['message_id'],)).fetchone()
            outbox=conn.execute("SELECT count(*) FROM ecp_message_outbox WHERE message_id=%s AND delivered_at IS NULL",(first['message_id'],)).fetchone()[0]
        if not row: raise AssertionError('delivery missing')
        delivery=row[0]
        receipt_key='receipt-'+uuid.uuid4().hex
        receipt_body={'receipt_kind':'RECEIVED','data':{},'request_key':receipt_key}
        receipt=call(run,f'/deliveries/{delivery}/receipts',receipt_body,user=bob,workspace=workspace,key=receipt_key)
        receipt_replay=call(run,f'/deliveries/{delivery}/receipts',receipt_body,user=bob,workspace=workspace,key=receipt_key)
        verify('receipt retry is idempotent',receipt_replay['replayed'] is True and receipt_replay['receipt_id']==receipt['receipt_id'])
        receipt_conflict={**receipt_body,'data':{'changed':True}}
        call(run,f'/deliveries/{delivery}/receipts',receipt_conflict,user=bob,workspace=workspace,expected=409,key=receipt_key)
        with psycopg.connect(PG+' dbname='+db,autocommit=True) as conn:
            state=conn.execute("SELECT state FROM ecp_deliveries WHERE delivery_id=%s",(delivery,)).fetchone()[0]
            receipts=conn.execute("SELECT count(*) FROM ecp_delivery_receipts WHERE delivery_id=%s",(delivery,)).fetchone()[0]
        verify('message creates outbox delivery and ACK persists receipt',outbox==1 and state=='ACKED' and receipts==1 and receipt['delivery_id']==delivery)
        report={'status':'PASS','checks':checks,'model_calls':0,'database':db,'outbox_pending_before_ack':outbox,'delivery_state_after_ack':state}
    except Exception as exc:
        report={'status':'FAIL','checks':checks,'model_calls':0,'error':str(exc)}
        raise
    finally:
        args.output.joinpath('phase3-messaging-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'checks':len(checks),'model_calls':0}))

if __name__=='__main__': main()

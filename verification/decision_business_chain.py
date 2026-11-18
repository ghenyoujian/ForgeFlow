#!/usr/bin/env python3
"""One Owner decision GUI journey. Source preparation starts no actors.

Two isolated queued projects; only A becomes runnable after the real UI command.
CONTROLLED_LIGHTWEIGHT, no models/DSH, no code integration claim.
"""
import argparse, hashlib, json, os, secrets, signal, socket, subprocess, sys, tempfile, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'verification'), str(ROOT/'benchmarks'), str(ROOT/'verification/fixtures')]
from cross_project_business_chain import Client, actual_running, paused, policy, provision, save, stop_attempt, wait, process_fingerprint
from guarded_api_chain import create_database, database_command, secure_save
SOURCES = ['verification/decision_business_chain.py','verification/decision_browser_point.mjs','verification/cross_project_business_chain.py','verification/guarded_api_chain.py','verification/algorithm_check.py','verification/fixtures/control_verifier.py','benchmarks/metrics.py']
CHROME = '/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome'
NODE = '/home/chenyoujian/miniconda/lib/python3.13/site-packages/playwright/driver/node'
def load(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def exclusive(p,v):
    Path(p).parent.mkdir(parents=True,exist_ok=True)
    with Path(p).open('x') as f:json.dump(v,f,ensure_ascii=False,indent=2);f.write('\n')
def tree_sha(root):
    return hashlib.sha256(json.dumps({str(p.relative_to(root)):sha(p) for p in sorted(Path(root).rglob('*')) if p.is_file()},sort_keys=True,separators=(',',':')).encode()).hexdigest()
def main_identity():
    r=subprocess.run(['systemctl','--user','show','forgeflow-control.service','--property=MainPID','--property=ActiveState'],capture_output=True,text=True,timeout=10,check=True)
    return dict(x.split('=',1) for x in r.stdout.splitlines())
def prepare(args):
    plan={'schema_version':'forgeflow.decision-business-chain-plan.v1','status':'SOURCE_READY_NO_ACTORS','port':args.port,'actor_phase_alarm_seconds':360,'cleanup_seconds_per_process':25,'actors':{'private_API':1,'project_Workers':2,'maximum_live_authors':1,'browser':1,'models':0,'DSH':0,'verifier_commands':0},'source_pins':{p:sha(ROOT/p) for p in SOURCES},'runtime_pins':{p:sha(p) for p in [NODE,CHROME]},'build_receipt':'ROOT_CANDIDATE_RECEIPT_PLACEHOLDER','console_tree_sha256':'ROOT_CONSOLE_BUILD_PLACEHOLDER','fixture':'existing cross_project_business_chain.provision count1 per project, global active1; project.paused=false, project ResourcePolicy.paused=true','business_oracle':['actual GUI B create/ack/defer future leaves its policy unchanged','actual GUI A create/ack/resolve changes only bound paused policy once','actual Scheduler/Worker A author RUNNING with authentic PID/journal; B QUEUED/noattempt','Worker403, cross-project policy拒绝, stale decision409, replay same UI resolution Idempotency-Key no new sideeffect','Owner cancel actual A; process stopped, held0; all owned actors closed'], 'budget':{'wall_seconds_max':540,'CPUQuota':'400%','MemoryMax':'4G','TasksMax':256},'not_proven':['Git integration','DSH/native execution','100+ capacity','automatic deferred resume']}
    exclusive(args.output/'source-ready-plan.json',plan)
    exclusive(args.output/'run-command.json',{'argv':[sys.executable,'-B',str(ROOT/'verification/decision_business_chain.py'),'--run','--output',str(args.output),'--plan-sha256',sha(args.output/'source-ready-plan.json'),'--go',str(args.output/'go-approved-r1.json'),'--build-receipt','ROOT_CANDIDATE_RECEIPT_PLACEHOLDER','--console-dir','ROOT_CONSOLE_BUILD_PLACEHOLDER','--private-env','/home/chenyoujian/.cache/forgeflow-control-a10-qa/runtime-env.json','--port',str(args.port)],'outer_scope':['systemd-run','--user','--scope','--unit=forgeflow-decision-business-r1','--property=CPUQuota=400%','--property=MemoryMax=4G','--property=TasksMax=256']})
    print(json.dumps({'plan_sha256':sha(args.output/'source-ready-plan.json'),'driver_sha256':sha(__file__),'browser_sha256':sha(ROOT/'verification/decision_browser_point.mjs'),'port':args.port}))
    return 0

def execute(args):
    plan=load(args.output/'source-ready-plan.json');go=load(args.go);receipt=load(args.build_receipt)
    assert sha(args.output/'source-ready-plan.json')==args.plan_sha256==go['plan_sha256']
    assert sha(args.build_receipt)==go['build_receipt_sha256'] and receipt['source_identity']==go['source_identity']
    assert go['console_tree_sha256']==tree_sha(args.console_dir)
    assert all(sha(ROOT/p)==s for p,s in plan['source_pins'].items())
    assert all(sha(p)==s for p,s in plan['runtime_pins'].items())
    assert receipt['consistent_copy'] and receipt['source_unchanged_after_build'] and all(c['exit_code']==0 for c in receipt['commands'])
    for relative in ['crates/domain/src/decisions.rs','crates/store/src/decisions.rs','crates/api/src/decisions.rs','crates/api/src/lib.rs','crates/worker/src/lib.rs']:
        assert sha(Path(receipt['snapshot_root'])/relative)==receipt['source_files'][relative]
    bins={n:receipt['binaries'][n] for n in ['forgeflow-server','forgeflow-worker']};assert all(sha(b['path'])==b['sha256'] for b in bins.values())
    assert not (args.output/'report.json').exists(), 'No automatic repeat'
    before=main_identity();assert before['ActiveState']=='active' and before['MainPID']==str(go['main_pid'])
    with socket.socket() as sk:assert sk.connect_ex(('127.0.0.1',args.port))!=0
    private=Path(tempfile.mkdtemp(prefix='forgeflow-decision-business-',dir='/home/chenyoujian/.cache'));private.chmod(0o700)
    diagnostics=private/'diagnostics';diagnostics.mkdir(mode=0o700);(private/'state').mkdir(mode=0o700)
    report={'schema_version':'forgeflow.decision-business-chain.v1','status':'RUNNING','plan_sha256':args.plan_sha256,'build_receipt_sha256':sha(args.build_receipt),'source_identity':receipt['source_identity'],'console_tree_sha256':go['console_tree_sha256'],'checks':[],'errors':[],'private_root':str(private),'models':0,'DSH':0,'not_proven':plan['not_proven']}
    api=browser=api_log=browser_log=client=None;fixtures=[];running=None;env=None
    def check(name,yes,facts=None):
        report['checks'].append({'name':name,'status':'PASS' if yes else 'FAIL','facts':facts});save(args.output/'report.json',report)
        if not yes:raise RuntimeError('Actual business assertion failed: '+name)
    def set_paused_scope(project,value):
        rows=client.api('GET',f'/projects/{project}/resources');row=next(x for x in rows if x['scope_id']==project+':project')
        return client.api('POST','/resource-policies',{'policy':dict(row,paused=value),'expected_revision':row['revision']})
    def observe(label):
        ids=','.join("'"+f['project_id']+"'" for f in fixtures)
        sql=f"SELECT jsonb_build_object('attempts',COALESCE((SELECT jsonb_agg(data) FROM attempts WHERE project_id IN ({ids})),'[]'::jsonb),'held',(SELECT count(*) FROM resource_allocations WHERE project_id IN ({ids}) AND state<>'RELEASED'),'models',((SELECT count(*) FROM model_request_permit)+(SELECT count(*) FROM native_model_requests)+(SELECT count(*) FROM provider_requests)),'decisions',COALESCE((SELECT jsonb_agg(data) FROM documents WHERE project_id IN ({ids}) AND collection='decisions'),'[]'::jsonb));"
        raw=database_command(client.database_url,sql);assert raw.returncode==0
        value=json.loads(raw.stdout);secure_save(private/(label+'.json'),value);save(args.output/(label+'.authority.json'),value);return value
    def interrupted(*unused):raise RuntimeError('bounded actor deadline/interruption')
    oldalarm=signal.signal(signal.SIGALRM,interrupted);oldterm=signal.signal(signal.SIGTERM,interrupted);signal.alarm(plan['actor_phase_alarm_seconds'])
    try:
        database='forgeflow_decision_'+uuid.uuid4().hex[:16];report['database_name']=database
        env={'DATABASE_URL':create_database(load(args.private_env),database,private),'FORGEFLOW_BIND':f'127.0.0.1:{args.port}','FORGEFLOW_DATA_ROOT':str(private/'state'),'FORGEFLOW_CONSOLE_DIR':str(args.console_dir.resolve()),'FORGEFLOW_OWNER_TOKEN':secrets.token_hex(32),'FORGEFLOW_WORKER_TOKEN':secrets.token_hex(32),'RUST_LOG':'info'}
        secure_save(private/'runtime-env.json',env);client=Client(f'http://127.0.0.1:{args.port}',env['FORGEFLOW_OWNER_TOKEN'],args.output,diagnostics);client.database_url=env['DATABASE_URL'];client.worker_token=env['FORGEFLOW_WORKER_TOKEN'];client.sensitive.add(client.worker_token)
        api_log=os.fdopen(os.open(private/'api.log',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb');api=subprocess.Popen([bins['forgeflow-server']['path']],env={'PATH':'/usr/bin:/bin',**env},stdout=api_log,stderr=subprocess.STDOUT)
        def healthy():
            assert api.poll() is None
            try:return client.request('GET','/me')[0]==200
            except OSError:return False
        wait(healthy,'private API readiness',30);policy(client,'global',slots=1)
        for name in ['decision-a','decision-b']:
            f=provision(client,private,receipt,name,1,1,163);fixtures.append(f);f['paused_policy']=set_paused_scope(f['project_id'],True);paused(client,f['project_id'],False)
        a,b=fixtures;pa,pb=a['project_id'],b['project_id'];report['projects']={'a':pa,'b':pb}
        for f in fixtures:
            snap=client.api('GET',f"/projects/{f['project_id']}/snapshot");check('initial_'+f['project_id']+'_queued_blocked_noattempt',not snap['project']['paused'] and not snap['attempts'] and len(client.api('GET',f"/projects/{f['project_id']}/queue-entries"))==1,snap)
        worker_client=Client(client.base_url,client.worker_token,args.output/'worker-denial',private/'worker-denial');status,value=worker_client.request('POST',f'/projects/{pa}/decisions',{'scope_id':pa+':project','expected_policy_revision':a['paused_policy']['revision'],'note':'Worker must not decide'});check('Worker_decision403',status==403,{'status':status,'code':value.get('code')})
        status,value=client.request('POST',f'/projects/{pa}/decisions',{'scope_id':pb+':project','expected_policy_revision':b['paused_policy']['revision'],'note':'cross project must reject'});check('cross_project_policy_rejected',status in (403,409,422),{'status':status,'code':value.get('code')})
        ui={'url':client.base_url,'owner_token':env['FORGEFLOW_OWNER_TOKEN'],'a_project':pa,'b_project':pb,'a_scope':pa+':project','b_scope':pb+':project','chrome':CHROME,'revisit_local':(datetime.now(timezone.utc)+timedelta(days=1)).strftime('%Y-%m-%dT%H:%M'),'output':str(args.output),'actions_path':str(private/'browser-actions.json'),'facts_path':str(private/'browser-facts.json'),'report_path':str(private/'browser-report.json')};secure_save(private/'browser-input.json',ui)
        browser_log=os.fdopen(os.open(private/'browser.log',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb');browser=subprocess.Popen([NODE,str(ROOT/'verification/decision_browser_point.mjs'),str(private/'browser-input.json')],stdout=browser_log,stderr=subprocess.STDOUT)
        def actions():
            if (private/'browser-actions.json').exists():return load(private/'browser-actions.json')
            if browser.poll() is not None:raise RuntimeError('actual browser exited before commands; see owned private browser report')
            return None
        uiresult=wait(actions,'actual GUI create ack defer resolve',150);save(args.output/'browser-actions.json',uiresult)
        decision_a=uiresult['a_resolve']['decision'];decision_b=uiresult['b_defer']['decision'];resolved_policy=uiresult['a_resolve']['policy']
        check('GUI_A_resolved_only_bound_policy',decision_a['state']=='RESOLVED' and resolved_policy['scope_id']==pa+':project' and not resolved_policy['paused'] and resolved_policy['revision']==a['paused_policy']['revision']+1 and dict(resolved_policy,paused=True,revision=a['paused_policy']['revision'])==a['paused_policy'] and len(decision_a['blocked_tasks'])==1,uiresult['a_resolve'])
        check('GUI_B_deferred_future_no_policy_effect',decision_b['state']=='DEFERRED' and len(decision_b['blocked_tasks'])==1 and datetime.fromisoformat(decision_b['revisit_at'].replace('Z','+00:00'))>datetime.now(timezone.utc) and uiresult['b_defer']['policy']==b['paused_policy'],uiresult['b_defer'])
        command=next(x for x in uiresult['commands'] if x['path'].endswith('/resolutions'));status,replay=client.request('POST',command['path'].removeprefix('/api/v1'),command['body'],key=command['idempotency_key']);check('UI_resolution_same_key_replayed_once',status==200 and replay.get('replayed') is True and replay['data']==command['response']['data'],replay)
        stale=dict(command['body'],expected_revision=uiresult['a_open']['decision']['revision']);status,value=client.request('POST',command['path'].removeprefix('/api/v1'),stale);check('stale_decision_version409',status==409,{'status':status,'code':value.get('code')})
        running=wait(lambda:actual_running(client,[pa],private),'actual A Worker author RUNNING',45)[0]
        bs=client.api('GET',f'/projects/{pb}/snapshot');check('B_remains_noattempt_paused_scope',not bs['attempts'] and next(x for x in client.api('GET',f'/projects/{pb}/resources') if x['scope_id']==pb+':project')==b['paused_policy'],bs)
        facts={'project_id':pa,'attempt_id':running['attempt']['attempt_id'],'state':running['attempt']['state'],'actual_author_pid':running['fingerprint']['pid'],'actual_process_fingerprint':running['fingerprint'],'launch_receipt':running['launch'],'cost':'UNKNOWN_NO_MODEL_USAGE_RECORD'};secure_save(private/'browser-facts.json',facts);save(args.output/'actual-running.json',facts)
        browser.wait(timeout=75);br=load(private/'browser-report.json');save(args.output/'browser-report.json',br);check('actual_browser_commands_and_responsive_readback',browser.returncode==0 and br['status']=='PASS_ACTUAL_DECISION_GUI_COMMANDS' and br['browser_closed'],br)
        paused(client,pa,True);stop_attempt(client,running['attempt']);final=observe('final');check('A_real_cancel_stop_zeroheld_models',final['held']==0 and final['models']==0 and len(final['attempts'])==1 and final['attempts'][0]['state'] in ('CANCELLED','FAILED'),final)
        journal=running['journal'];wait(lambda:(journal/'result-ack.json').exists(),'real Worker result ACK',10);stop=load(journal/'stop.json');ack=load(journal/'result-ack.json');check('real_author_stop_and_ACK',stop['process_exit_confirmed'] and ack['terminal_confirmed'],{'stop':stop,'ack_event_id':ack['event_id']})
    except BaseException as error:report['errors'].append({'type':type(error).__name__,'message':str(error),'interrupted':isinstance(error,(KeyboardInterrupt,SystemExit))})
    finally:
        signal.alarm(0)
        if client and api and api.poll() is None:
            for f in fixtures:
                try:
                    paused(client,f['project_id'],True)
                    for attempt in client.api('GET',f"/projects/{f['project_id']}/snapshot")['attempts']:stop_attempt(client,attempt)
                except BaseException as e:report['errors'].append({'cleanup':'legal Owner cancel','type':type(e).__name__})
            try:report['final_authority']=observe('cleanup-final')
            except BaseException as e:report['errors'].append({'cleanup':'final authority observation','type':type(e).__name__})
        report['shutdown']={}
        processes=[('browser',browser)]+[(f['worker_id'],f['process']) for f in (client.workers if client else [])]+[('api',api)]
        for name,process in processes:
            if process is None:continue
            try:
                if process.poll() is None:process.terminate();process.wait(timeout=25)
            except BaseException as e:report['errors'].append({'cleanup':name,'type':type(e).__name__})
            report['shutdown'][name]={'pid':process.pid,'exit_code':process.poll(),'confirmed':process.poll() is not None}
        for f in (client.workers if client else []):f['log'].close()
        if api_log:api_log.close()
        if browser_log:browser_log.close()
        with socket.socket() as sk:report['owned_port_closed']=sk.connect_ex(('127.0.0.1',args.port))!=0
        report['database_retained_for_original_evidence']=bool(env)
        if env:
            try:
                connection_rows=database_command(env['DATABASE_URL'],"SELECT json_build_object('other_database_connections',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()));")
                assert connection_rows.returncode==0
                report['database_connection_closure']=json.loads(connection_rows.stdout)
                if report['database_connection_closure']['other_database_connections']!=0:report['errors'].append({'cleanup':'owned database still has live connections'})
            except BaseException as e:report['errors'].append({'cleanup':'database connection closure','type':type(e).__name__})
        report['main_before']=before;report['main_after']=main_identity()
        report['cleanup_confirmed']=report['owned_port_closed'] and report['main_after']==before and all(x['confirmed'] for x in report['shutdown'].values()) and (not running or process_fingerprint(running['fingerprint']['pid']) is None)
        report['status']='PASS_ACTUAL_DECISION_GUI_BUSINESS_CHAIN' if not report['errors'] and report['cleanup_confirmed'] and report['checks'] and all(x['status']=='PASS' for x in report['checks']) else 'FAIL'
        save(args.output/'report.json',report);signal.signal(signal.SIGALRM,oldalarm);signal.signal(signal.SIGTERM,oldterm)
    print(json.dumps({'status':report['status'],'report':str(args.output/'report.json'),'checks':len(report['checks'])}));return 0 if report['status'].startswith('PASS') else 1

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--port',type=int,default=8899);p.add_argument('--run',action='store_true');p.add_argument('--plan-sha256');p.add_argument('--go',type=Path);p.add_argument('--build-receipt',type=Path);p.add_argument('--console-dir',type=Path);p.add_argument('--private-env',type=Path);args=p.parse_args();args.output=args.output.resolve();assert args.output.is_relative_to(ROOT/'evidence/decision-business-chain-r1');assert args.port==8899
    if args.run:
        assert all([args.plan_sha256,args.go,args.build_receipt,args.console_dir,args.private_env]);return execute(args)
    return prepare(args)
if __name__=='__main__':raise SystemExit(main())

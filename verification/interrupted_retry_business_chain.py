#!/usr/bin/env python3
"""BC06: GUI interrupt, legal stop, Owner child version, GUI retry and delivery.

Prepare only by default. Isolated DB and delegated API/Worker; zero models/DSH.
No crash replay, SQL business mutation or inferred release. Exact RootGO required.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, os, re, secrets, shutil, signal, socket, subprocess, sys, tempfile, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'verification'))
import physical_business_chain as business
from cross_project_business_chain import Client, actual_running, ledger_totals, paused, save, stop_attempt, wait
from guarded_api_chain import create_database, database_command, secure_save
from algorithm_check import refresh_digest
SOURCE='1938d068831a2e4f734b9ece0c4618e4978a1fffd66d34bb8660259dfaae8da3'
NODE='/home/chenyoujian/miniconda/lib/python3.13/site-packages/playwright/driver/node'
CHROME='/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome'
SOURCES=['verification/interrupted_retry_business_chain.py','verification/interrupted_retry_browser_point.mjs','verification/physical_business_chain.py','verification/cross_project_business_chain.py','verification/guarded_api_chain.py','verification/algorithm_check.py','verification/oracle.py','verification/fixtures/control_verifier.py','benchmarks/metrics.py','ops/run-delegated-worker.py','ops/manage-service.py','ops/run-service.py']
SHORT_AUTHOR=business.VERIFIER_AUTHOR
LONG_AUTHOR=SHORT_AUTHOR.replace('time.sleep(2)','time.sleep(30)')
def load(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def value_sha(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def tree_sha(p):return value_sha({str(f.relative_to(p)):sha(f) for f in sorted(Path(p).rglob('*')) if f.is_file()})
def semantic_flow(v):return {k:x for k,x in v.items() if k not in ('state','revision')}
def ctl(*args):subprocess.run(['systemctl','--user',*args],capture_output=True,check=True,timeout=15)
def prepare(args):
 plan={'schema_version':'forgeflow.interrupted-retry-plan.v1','status':'SOURCE_READY_NO_ACTORS','source_identity':SOURCE,'port':args.port,'actor_phase_alarm_seconds':360,'cleanup_alarm_seconds':60,'source_pins':{p:sha(ROOT/p) for p in SOURCES},'runtime_pins':{p:sha(p) for p in [NODE,CHROME,str(Path(sys.executable).resolve()),'/usr/bin/python3','/usr/bin/bwrap']},'author_sha256':{'old_30s':hashlib.sha256(LONG_AUTHOR.encode()).hexdigest(),'new_2s':hashlib.sha256(SHORT_AUTHOR.encode()).hexdigest()},'actors':{'owned_private_API':1,'delegated_Worker':1,'maximum_live_authors':1,'browser':1,'models':0,'DSH':0,'verifier_commands':6},'physical_limits':business.POLICY,'root_resources':business.REQUEST,'business_oracle':['Actual GUI cancels a physically fenced RUNNING author; positive whole-group stop and all seven-scope ledgers zero before replan','Owner public API preserves Flow1/taskRev1/binding/journal and creates child Flow2/taskRev2 with new outcome/seed732/independentPlan2/canonical base; no old Attempt revival','Actual Tasks detail GUI singular retry route issues canonical queue; new Attempt/lease/operation/generation2 distinct','Old Attempt exact heartbeat and new Attempt old-generation heartbeat both 409 LEASE_STALE; authoritative execution custody/resources/evidence/ref unchanged','Actual new finite author seed732, actual GUI verify-and-integrate, candidate and integrated independent 3role/8case each, finalized canonical Git exact blob','Old CANCELLED/new SUCCEEDED remain visible in GUI; all own resource rows released/leases revoked, zero models; owned actors positively shut down'], 'qualification':'One finite user-interruption/replan/retry/new-delivery chain; no COMMIT_DECIDED crash replay, callback matrix, capacity or DSH claim','execution_requires_exact_root_go':True}
 secure_save(args.output/'source-ready-plan.json',plan)
 secure_save(args.output/'run-command.json',{'argv':[sys.executable,'-B',str(Path(__file__).resolve()),'--run','--output',str(args.output),'--plan-sha256',sha(args.output/'source-ready-plan.json'),'--go',str(args.output/'go-approved-r1.json'),'--build-receipt','ROOT_1938_RECEIPT','--runtime-release','ROOT_1938_RELEASE','--console-dir','ROOT_FINAL_CONSOLE_DIST','--private-env','ROOT_PRIVATE_ENV','--port',str(args.port)],'outer_scope':['systemd-run','--user','--scope','--unit=forgeflow-interrupted-retry-r1','--property=CPUQuota=400%','--property=MemoryMax=4G','--property=TasksMax=256']})
 print(json.dumps({'status':plan['status'],'plan_sha256':sha(args.output/'source-ready-plan.json'),'driver_sha256':sha(__file__),'browser_sha256':sha(ROOT/SOURCES[1]),'actors':0,'models':0}));return 0

def execute(args):
 plan=load(args.output/'source-ready-plan.json');go=load(args.go);receipt=load(args.build_receipt)
 assert sha(args.output/'source-ready-plan.json')==args.plan_sha256==go['plan_sha256']
 assert receipt['source_identity']==SOURCE==go['source_identity'] and sha(args.build_receipt)==go['build_receipt_sha256']
 assert receipt['consistent_copy'] and receipt['source_unchanged_after_build'] and all(c['exit_code']==0 for c in receipt['commands'])
 assert tree_sha(args.console_dir)==go['console_tree_sha256']
 assert re.fullmatch(r'forgeflow-control-[0-9a-f]{32}',go['api_service_name'])
 assert all(sha(ROOT/p)==s for p,s in plan['source_pins'].items()) and all(sha(p)==s for p,s in plan['runtime_pins'].items())
 for p in ['crates/api/src/catalog.rs','crates/api/src/workers.rs','crates/store/src/catalog.rs','crates/store/src/admission.rs','crates/store/src/lifecycle.rs','crates/store/src/lib.rs','crates/api/src/operations.rs','crates/evidence/src/runner.rs']:
  assert sha(Path(receipt['snapshot_root'])/p)==receipt['source_files'][p]
 for n in ['forgeflow-server','forgeflow-worker','forgeflow-sandbox-guard']:assert sha(receipt['binaries'][n]['path'])==receipt['binaries'][n]['sha256']
 assert sha(args.runtime_release/'bin/forgeflow-server')==receipt['binaries']['forgeflow-server']['sha256']
 assert sha(args.runtime_release/'delivery-manifest.json')==go['runtime_manifest_sha256']
 assert not (args.output/'report.json').exists(),'No automatic actor replay'
 main=business.unit_properties('forgeflow-control.service');assert main['MainPID']==str(go['main_pid']) and main['ActiveState']=='active'
 unit=go['api_service_name']+'.service';slice_name='forgeflowcontrolresources'+go['api_service_name'].removeprefix('forgeflow-control-')+'.slice'
 assert business.unit_properties(unit)['LoadState']=='not-found'
 with socket.socket() as sk:assert sk.connect_ex(('127.0.0.1',args.port))!=0
 private=Path(tempfile.mkdtemp(prefix='forgeflow-interrupted-retry-',dir='/home/chenyoujian/.cache'));private.chmod(0o700);(private/'state').mkdir(mode=0o700);diagnostics=private/'diagnostics';diagnostics.mkdir(mode=0o700)
 report={'schema_version':'forgeflow.interrupted-retry-business.v1','status':'RUNNING','source_identity':SOURCE,'plan_sha256':args.plan_sha256,'build_receipt_sha256':sha(args.build_receipt),'console_tree_sha256':go['console_tree_sha256'],'private_root':str(private),'checks':[],'errors':[],'models':0,'DSH':0,'main_before':main,'qualification':plan['qualification'],'raw_manifest':[]}
 fixture=client=browser=browser_log=worker_unit=worker_plan=None;api_created=False;api_sha=None;zero=False;final_delivered=False
 def check(name,yes,facts=None):
  report['checks'].append({'name':name,'status':'PASS' if yes else 'FAIL','facts':facts});save(args.output/'report.json',report)
  if not yes:raise RuntimeError('Actual BC06 assertion failed: '+name)
 def snapshot():return client.api('GET',f"/projects/{fixture['project']}/snapshot")
 def retain(p,name):
  dest=args.output/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest);row={'path':str(dest.relative_to(ROOT)),'sha256':sha(dest),'bytes':dest.stat().st_size};report['raw_manifest'].append(row);return row
 def observe(label):
  p=fixture['project'];sql=f"SELECT jsonb_build_object('attempt_custody',COALESCE((SELECT jsonb_agg(jsonb_build_object('attempt_id',attempt_id,'state',state,'generation',generation,'data',data-'revision') ORDER BY attempt_id) FROM attempts WHERE project_id='{p}'),'[]'::jsonb),'allocations',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY allocation_id) FROM resource_allocations r WHERE project_id='{p}'),'[]'::jsonb),'leases',COALESCE((SELECT jsonb_agg(jsonb_build_object('lease_id',lease_id,'attempt_id',attempt_id,'generation',generation,'worker_id',worker_id,'revoked_at',revoked_at) ORDER BY lease_id) FROM leases WHERE project_id='{p}'),'[]'::jsonb),'evidence',COALESCE((SELECT jsonb_agg(data ORDER BY receipt_id) FROM evidence_receipts WHERE project_id='{p}'),'[]'::jsonb),'merges',COALESCE((SELECT jsonb_agg(data ORDER BY intent_id) FROM merge_intents WHERE project_id='{p}'),'[]'::jsonb),'models',((SELECT count(*) FROM model_request_permit)+(SELECT count(*) FROM native_model_requests)+(SELECT count(*) FROM provider_requests)),'valid_leases',(SELECT count(*) FROM leases WHERE project_id='{p}' AND revoked_at IS NULL AND expires_at>clock_timestamp()));"
  r=database_command(client.database_url,sql);assert r.returncode==0;v=json.loads(r.stdout);v['target_ref']=business.git(fixture['canonical'],'rev-parse','refs/heads/main');save(args.output/(label+'.authority.json'),v);return v
 def ui_file(name):
  p=private/(name+'.json')
  def ready():
   if p.exists():return load(p)
   if browser.poll() is not None:raise RuntimeError('GUI exited before '+name+'; original private report retained')
   return None
  return wait(ready,'actual GUI '+name,45)
 def interrupted(*unused):raise RuntimeError('Bounded BC06 actor/cleanup deadline')
 oldalarm=signal.signal(signal.SIGALRM,interrupted);oldterm=signal.signal(signal.SIGTERM,interrupted);signal.alarm(360)
 try:
  database='forgeflow_interrupted_retry_'+uuid.uuid4().hex[:16];report['database_name']=database
  env={'DATABASE_URL':create_database(load(args.private_env),database,private),'FORGEFLOW_BIND':f'127.0.0.1:{args.port}','FORGEFLOW_DATA_ROOT':str(private/'state'),'FORGEFLOW_CONSOLE_DIR':str(args.console_dir.resolve()),'FORGEFLOW_OWNER_TOKEN':secrets.token_hex(32),'FORGEFLOW_WORKER_TOKEN':secrets.token_hex(32),'RUST_LOG':'info'}
  secure_save(private/'runtime-env.json',env);client=Client(f'http://127.0.0.1:{args.port}',env['FORGEFLOW_OWNER_TOKEN'],args.output,diagnostics);client.database_url=env['DATABASE_URL'];client.worker_token=env['FORGEFLOW_WORKER_TOKEN'];client.sensitive.add(client.worker_token)
  business.child_json([sys.executable,str(ROOT/'ops/manage-service.py'),'install','--name',go['api_service_name'],'--release-dir',str(args.runtime_release),'--runtime-env',str(private/'runtime-env.json'),'--verifier-cgroups','--start']);api_created=True;api_sha=sha(Path.home()/'.config/systemd/user'/unit)
  def healthy():
   try:return client.request('GET','/me')[0]==200
   except OSError:return False
  wait(healthy,'owned API ready',30)
  fixture=business.create_fixture(client,private,receipt,False);fixture['verifier_physical']=True;report['project_id']=fixture['project']
  launcher=ROOT/'ops/run-delegated-worker.py';wp=business.child_json([sys.executable,str(launcher),'prepare','--kind','worker','--program',receipt['binaries']['forgeflow-worker']['path'],'--program-sha256',receipt['binaries']['forgeflow-worker']['sha256'],'--config',str(fixture['config']),'--env-file',str(fixture['env']),'--output',str(private/'delegated-worker')]);worker_unit=wp['unit_name'];worker_plan=load(private/'delegated-worker/launch-plan.json')
  business.child_json([sys.executable,str(launcher),'start','--plan',str(private/'delegated-worker/launch-plan.json'),'--plan-sha256',wp['plan_sha256'],'--unit-sha256',wp['unit_sha256'],'--execute'])
  def registered():
   r=database_command(client.database_url,f"SELECT count(*) FROM workers WHERE worker_id='{fixture['worker']}'");return r.returncode==0 and r.stdout.strip() in (b'1','1')
  wait(registered,'actual Worker registration',30)
  business.VERIFIER_AUTHOR=LONG_AUTHOR
  try:business.finalize_fixture(client,private,fixture)
  finally:business.VERIFIER_AUTHOR=SHORT_AUTHOR
  task=fixture['task'];project=fixture['project'];tid=task['task_id'];report['task_id']=tid
  old_flow=client.api('GET',f'/flows/{project}:1');old_context=client.api('GET',f'/flows/{project}:1/context');save(args.output/'flow1.json',old_flow);save(args.output/'flow1-context.json',old_context)
  client.api('POST',f'/projects/{project}/queue-entries',{'task_id':tid,'expected_revision':task['revision'],'worker_id':fixture['worker'],'worker_scope_id':project+':worker','scope_ids':[],'priority':1,'lease_seconds':120});paused(client,project,False)
  running=wait(lambda:actual_running(client,[project],private),'old author really RUNNING',40)[0];old=running['attempt'];oldid=old['attempt_id'];report['old_attempt_id']=oldid
  live=snapshot();check('old_actual_running_full_pool_before_GUI_interrupt',old['state']=='RUNNING' and old['generation']==1 and not ledger_totals({project:live})['mismatches'] and sum(a['state']!='RELEASED' for a in live['allocations'])==28,{'attempt':old,'launch':running['launch']})
  ui={'url':client.base_url,'owner_token':env['FORGEFLOW_OWNER_TOKEN'],'project_id':project,'task_id':tid,'old_attempt_id':oldid,'chrome':CHROME,'output':str(args.output),'cancel_path':str(private/'cancel.json'),'retry_input_path':str(private/'retry-input.json'),'retry_path':str(private/'retry.json'),'integrate_input_path':str(private/'integrate-input.json'),'integrate_path':str(private/'integrate.json'),'final_input_path':str(private/'final-input.json'),'report_path':str(private/'browser-report.json')};secure_save(private/'browser-input.json',ui)
  browser_log=os.fdopen(os.open(private/'browser.log',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb');browser=subprocess.Popen([NODE,str(ROOT/SOURCES[1]),str(private/'browser-input.json')],stdout=browser_log,stderr=subprocess.STDOUT)
  cancel=ui_file('cancel');save(args.output/'gui-cancel.json',cancel)
  paused(client,project,True)
  stopped=wait(lambda:next((a for a in snapshot()['attempts'] if a['attempt_id']==oldid and a['state']=='CANCELLED'),None),'old real positive stop accepted',45)
  oldjournal=running['journal'];wait(lambda:(oldjournal/'result-ack.json').exists(),'old stopped Worker ACK',10);physical=load(oldjournal/'cgroup-stop.json');stop=load(oldjournal/'stop.json');released=snapshot();oldledger=ledger_totals({project:released})
  check('GUI_cancel_actual_stop_and_all_resources_released_before_replan',stop['process_exit_confirmed'] and physical['process_exit_confirmed'] and not physical['populated'] and not physical['snapshot']['cgroup.procs'].strip() and not oldledger['mismatches'] and not oldledger['allocated_vectors'] and all(l['revoked_at'] is not None for l in released['leases']),{'stop':stop,'physical_stop':physical,'ledger':oldledger})
  oldpins={n:sha(oldjournal/n) for n in (*business.REQUIRED_RAW,'execution-bindings.json','envelope.json','result-ack.json')};[retain(oldjournal/n,'old-author/'+n) for n in oldpins if n!='envelope.json']
  flow2=copy.deepcopy(old_flow);context2=copy.deepcopy(old_context);flow2.update(flow_revision=2,parent_revision=1,state='DRAFT',revision=1,approved_by=None)
  t2=flow2['tasks'][0];t2.update(task_revision=2,flow_revision=2,revision=task['revision']+1,state='NEEDS_REVIEW',title='Owner revised finite delivery seed732')
  spec=context2['task_specs'][tid];planid='interrupted-retry-verify-r2-'+tid;spec.update(outcome='Owner revised finite output seed732 after acknowledged user interruption',verification_plan=planid)
  envelope=t2['envelope'];now=datetime.now(timezone.utc);envelope.update(task_revision=2,base_sha=business.git(fixture['canonical'],'rev-parse','refs/heads/main'),verification_plan_id=planid,issued_at=now.isoformat(),expires_at=(now+timedelta(seconds=120)).isoformat(),deadline_at=(now+timedelta(minutes=5)).isoformat());envelope['command']['args']=['-I','-B','-c',SHORT_AUTHOR,'result.json','732'];refresh_digest(t2,spec)
  plan1=next(v for v in client.api('GET',f'/projects/{project}/documents/verification_plans') if v['plan_id']==task['envelope']['verification_plan_id']);plan2=copy.deepcopy(plan1);plan2.pop('revision',None);plan2.update(plan_id=planid,task_revision=2,input_hash=t2['input_digest']);[c['env'].update(FORGEFLOW_EXPECTED_SEED='732') for c in plan2['commands']]
  client.api('POST',f'/projects/{project}/documents/verification_plans',{'id':planid,'value':plan2})
  saved=client.api('POST',f'/projects/{project}/flow-revisions',{'flow':flow2,'context':context2});committed=client.api('POST',f'/flows/{project}:2/commit',{'expected_revision':saved['revision']});newtask=committed['tasks'][0]
  save(args.output/'flow2.json',committed);save(args.output/'flow2-context.json',client.api('GET',f'/flows/{project}:2/context'));save(args.output/'verification-plan2.json',plan2)
  unchanged1=client.api('GET',f'/flows/{project}:1');check('Owner_new_child_version_preserves_old_definitions_and_stopped_attempt',semantic_flow(unchanged1)==semantic_flow(old_flow) and unchanged1['state']=='SUPERSEDED' and client.api('GET',f'/flows/{project}:1/context')==old_context and newtask['task_revision']==2 and newtask['input_digest']!=task['input_digest'] and newtask['envelope']['base_sha']==fixture['baseline'] and all(sha(oldjournal/n)==s for n,s in oldpins.items()) and next(a for a in snapshot()['attempts'] if a['attempt_id']==oldid)==stopped,{'flow1_sha256':value_sha(old_flow),'flow1_context_sha256':value_sha(old_context),'flow2_sha256':value_sha(committed),'plan1_sha256':value_sha(plan1),'plan2_sha256':value_sha(plan2),'old_journal_sha256':oldpins})
  secure_save(private/'retry-input.json',{'task_revision':2,'flow_revision':2});retry=ui_file('retry');save(args.output/'gui-retry.json',retry);paused(client,project,False)
  def newverifying():
   rows=[a for a in snapshot()['attempts'] if a['attempt_id']!=oldid]
   if rows and rows[0]['state'] in ('FAILED','CANCELLED','RECOVERY_REQUIRED'):raise RuntimeError('New controlled author failed '+rows[0]['state'])
   return rows[0] if rows and rows[0]['state']=='VERIFYING' else None
  new=wait(newverifying,'canonical retry produces new finite author',45);newid=new['attempt_id'];report['new_attempt_id']=newid;paused(client,project,True);newjournal=private/'state/attempts'/newid;bindings=load(newjournal/'execution-bindings.json');newstop=load(newjournal/'stop.json')
  check('canonical_new_attempt_new_lease_generation2_real_execution',new['task_revision']==2 and load(newjournal/'envelope.json')['task_revision']==2 and new['generation']==2 and new['lease_id']!=old['lease_id'] and new['operation_id']!=old['operation_id'] and load(newjournal/'envelope.json')['generation']==2 and load(newjournal/'envelope.json')['command']['args'][-1]=='732' and newstop['process_exit_confirmed'] and newstop['exit_code']==0,{'old':old,'new':new,'bindings_sha256':sha(newjournal/'execution-bindings.json')})
  wc=Client(client.base_url,client.worker_token,args.output/'stale-worker',private/'stale-worker');wc.sensitive.add(client.worker_token);before=observe('before-old-fences')
  for label,aid in [('old_exact_attempt',oldid),('new_attempt_old_generation',newid)]:
   status,value=wc.request('POST',f'/attempts/{aid}/heartbeat',{'project_id':project,'attempt_id':aid,'generation':old['generation'],'worker_id':fixture['worker'],'lease_seconds':120});after=observe(label)
   check(label+'_409_and_custody_resources_evidence_ref_unchanged',status==409 and value.get('code')=='LEASE_STALE' and before==after,{'http_status':status,'code':value.get('code'),'authority_unchanged':before==after})
  secure_save(private/'integrate-input.json',{'attempt_id':newid});integration=ui_file('integrate');save(args.output/'gui-integrate.json',integration);opid=integration['integrate']['operation_id'];report['verification_operation_id']=opid
  def completed():
   row=client.api('GET','/operations/'+opid)
   if row['status'] in ('FAILED','RECOVERY_REQUIRED'):raise RuntimeError('Actual independent verification/Git '+row['status'])
   return row if row['status']=='SUCCEEDED' else None
  operation=wait(completed,'new candidate and integrated verification/Git',100);save(args.output/'verification-operation.json',operation);facts=observe('delivered');final=snapshot();oldfinal=next(a for a in final['attempts'] if a['attempt_id']==oldid);newfinal=next(a for a in final['attempts'] if a['attempt_id']==newid)
  merge=facts['merges'][0];candidate=[r for r in facts['evidence'] if r['kind']=='INDEPENDENT_VERIFICATION'];integrated=merge['receipt']['verification'];ref=facts['target_ref'];blob=subprocess.check_output(['git','-C',str(fixture['canonical']),'show',ref+':result.json']);(args.output/'integrated-result.bin').write_bytes(blob)
  check('new_candidate_and_integrated_real_independent_eight_cases',len(candidate)==1 and candidate[0]['attempt_id']==newid and candidate[0]['details']['binding']['task_revision']==2 and candidate[0]['total']==8 and candidate[0]['failed']==candidate[0]['skipped']==0 and all(v['total']==8 and v['failed']==v['skipped']==0 and v['positive_cases']==v['negative_cases']==4 and v['independent'] for v in [candidate[0]['details'],integrated]) and integrated['binding']['attempt_id']==newid and integrated['binding']['generation']==2,{'candidate':candidate,'integrated':integrated,'assertions_per_stage':8,'command_denominator':6})
  check('new_finalized_Git_seed732_old_CANCELLED_preserved',merge['state']=='FINALIZED' and merge['integrated_sha']==ref and ref!=fixture['baseline'] and blob==(json.dumps({'kind':'CONTROL_LOAD','seed':732})+'\n').encode() and newfinal['state']=='SUCCEEDED' and oldfinal==stopped and all(sha(oldjournal/n)==s for n,s in oldpins.items()),{'integrated_sha':ref,'blob_sha256':hashlib.sha256(blob).hexdigest(),'old_attempt':oldfinal,'new_attempt':newfinal})
  artifacts=client.api('GET',f'/projects/{project}/documents/artifacts');artifact=next(a for a in artifacts if a.get('artifact_id')==candidate[0]['artifact']['artifact_id']);candidate_log=Path(artifact['path']);integrated_log=Path(merge['receipt']['artifact_root'])/integrated['log_path'];assert sha(candidate_log)==artifact['sha256'] and sha(integrated_log)==integrated['log_hash'];retain(candidate_log,'candidate-verification/log.ndjson');retain(integrated_log,'integrated-verification/log.ndjson')
  closed=[]
  for stage,root in [('candidate',candidate_log.parent),('integrated',Path(merge['receipt']['artifact_root']))]:
   context=load(root/'verification-physical-context.json');seal=load(root/'verification-physical-closed.json');assert seal['context']==context and seal['runner_closed'] and context['parent_attempt_id']==newid and context['generation']==2 and len(context['commands'])==3
   retain(root/'verification-physical-context.json',stage+'-verification/context.json');retain(root/'verification-physical-closed.json',stage+'-verification/closed.json')
   for command in context['commands']:
    journal=root/'verification-runs'/command['process_attempt_id'];pstop=load(journal/'cgroup-stop.json');s=load(journal/'stop.json');assert s['process_exit_confirmed'] and pstop['process_exit_confirmed'] and not pstop['populated'] and not pstop['snapshot']['cgroup.procs'].strip()
    for n in (*business.REQUIRED_RAW[:5],'stop.json','verification-command.json'):retain(journal/n,stage+'-verification/'+command['role']+'/'+n)
    closed.append({'stage':stage,'command':command,'positive_stop_sha256':sha(journal/'cgroup-stop.json')})
  check('six_verifier_physical_stops_and_sequencer_closure',len(closed)==6 and len({c['command']['execution_id'] for c in closed})==6,closed)
  ledger=ledger_totals({project:final});zero=not ledger['mismatches'] and not ledger['allocated_vectors'] and all(a['state']=='RELEASED' for a in final['allocations']) and all(l['revoked_at'] is not None for l in final['leases'])
  check('final_all_scopes_released_no_valid_lease_zero_models',zero and facts['valid_leases']==facts['models']==0,ledger)
  for n in (*business.REQUIRED_RAW,'execution-bindings.json','result-ack.json'):retain(newjournal/n,'new-author/'+n)
  secure_save(private/'final-input.json',{'old_attempt_id':oldid,'new_attempt_id':newid,'old_state':'CANCELLED','new_state':'SUCCEEDED','integrated_sha':ref,'held':0});browser.wait(timeout=35);br=load(private/'browser-report.json');save(args.output/'browser-report.json',br);check('actual_GUI_cancel_retry_integration_and_history_readback',browser.returncode==0 and br['status']=='PASS_ACTUAL_INTERRUPT_RETRY_GUI' and br['browser_closed'] and len(br['commands'])==3 and len(br['pages'])==2,br);final_delivered=True
 except BaseException as e:report['errors'].append({'type':type(e).__name__,'message':str(e)[:350]})
 finally:
  signal.alarm(60)
  try:
   if fixture is not None:
    paused(client,fixture['project'],True)
    for a in snapshot()['attempts']:
     if a['state'] not in ('SUCCEEDED','CANCELLED','FAILED'):stop_attempt(client,a)
    state=snapshot();ledger=ledger_totals({fixture['project']:state});zero=not ledger['mismatches'] and not ledger['allocated_vectors'] and all(l['revoked_at'] is not None for l in state['leases']);report['cleanup_authority']=state;check('cleanup_legal_stop_zero_resources',zero,ledger)
   else:zero=True
   if browser is not None and browser.poll() is None:browser.terminate();browser.wait(timeout=5)
   if zero:
    for owned,own_slice in [(worker_unit,worker_plan['slice_name'] if worker_plan else None),(unit if api_created else None,slice_name)]:
     if not owned:continue
     pid=int(business.unit_properties(owned)['MainPID'])
     if pid:os.kill(pid,signal.SIGTERM)
     terminal=wait(lambda:business.unit_properties(owned) if business.unit_properties(owned)['MainPID']=='0' else None,'own supervisor stop',20);ctl('stop',owned,own_slice)
     path=Path.home()/'.config/systemd/user'/owned
     if owned==unit:
      ctl('disable',owned);assert not path.is_symlink() and sha(path)==api_sha
     else:assert path.is_symlink() and path.resolve()==private/'delegated-worker'/owned
     path.unlink();ctl('daemon-reload');report.setdefault('owned_cleanup',[]).append({'unit':owned,'terminal':terminal,'slice':business.unit_properties(own_slice),'unlinked':not path.exists()})
   else:report['quarantine_retained']=True
  except BaseException as e:report['errors'].append({'cleanup':type(e).__name__,'message':str(e)[:200]})
  signal.alarm(0)
  if browser_log:browser_log.close()
  report['main_after']=business.unit_properties('forgeflow-control.service')
  with socket.socket() as sk:report['private_port_closed']=sk.connect_ex(('127.0.0.1',args.port))!=0
  clean=report.get('owned_cleanup',[]);good=final_delivered and zero and not report['errors'] and len(clean)==2 and all(c['terminal']['MainPID']=='0' and c['terminal']['ExecMainStatus']=='0' and c['slice']['ActiveState']=='inactive' for c in clean) and report['private_port_closed'] and report['main_after']['MainPID']==main['MainPID'] and report['main_after']['ActiveState']=='active'
  report['status']='PASS_ACTUAL_INTERRUPTED_RETRY_NEW_DELIVERY' if good else 'FAIL';report['assertions']=len(report['checks']);report['failed']=sum(c['status']!='PASS' for c in report['checks']);save(args.output/'report.json',report);signal.signal(signal.SIGALRM,oldalarm);signal.signal(signal.SIGTERM,oldterm)
 print(json.dumps({'status':report['status'],'report':str(args.output/'report.json'),'private_root':str(private),'models':0,'DSH':0}));return 0 if good else 1

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ROOT/'evidence/interrupted-retry-business-chain-r1');p.add_argument('--port',type=int,default=8897);p.add_argument('--run',action='store_true');p.add_argument('--plan-sha256');p.add_argument('--go',type=Path);p.add_argument('--build-receipt',type=Path);p.add_argument('--runtime-release',type=Path);p.add_argument('--console-dir',type=Path);p.add_argument('--private-env',type=Path);a=p.parse_args();a.output=a.output.resolve();assert a.output.is_relative_to(ROOT/'evidence/interrupted-retry-business-chain-r1') and a.port==8897;a.output.mkdir(parents=True,exist_ok=True)
 if a.run:
  assert all([a.go,a.build_receipt,a.runtime_release,a.console_dir,a.private_env,a.plan_sha256]);return execute(a)
 return prepare(a)
if __name__=='__main__':sys.exit(main())

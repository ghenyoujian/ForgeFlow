#!/usr/bin/env python3
"""Continue the original BC06 fixture from its rejected new-admission edge only.

No original cancel/replan rerun, no production source change or SQL authority write.
Original FAIL, old definitions/journals and released custody stay immutable.
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
SOURCES=['verification/interrupted_retry_point_continuation.py','verification/interrupted_retry_business_chain.py','verification/interrupted_retry_browser_point.mjs','verification/physical_business_chain.py','verification/cross_project_business_chain.py','verification/guarded_api_chain.py','verification/algorithm_check.py','verification/oracle.py','verification/fixtures/control_verifier.py','benchmarks/metrics.py','ops/run-delegated-worker.py','ops/manage-service.py','ops/run-service.py']
SHORT_AUTHOR=business.VERIFIER_AUTHOR
LONG_AUTHOR=SHORT_AUTHOR.replace('time.sleep(2)','time.sleep(30)')
def load(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def value_sha(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def tree_sha(p):return value_sha({str(f.relative_to(p)):sha(f) for f in sorted(Path(p).rglob('*')) if f.is_file()})
def semantic_flow(v):return {k:x for k,x in v.items() if k not in ('state','revision')}
def canonical_ack(value):
 value=copy.deepcopy(value)
 if isinstance(value.get('controller_response'),dict):value['controller_response'].pop('observed_at',None)
 return value
def ctl(*args):subprocess.run(['systemctl','--user',*args],capture_output=True,check=True,timeout=15)
ORIGINAL=ROOT/'evidence/interrupted-retry-business-chain-r1'
ORIGINAL_PRIVATE=Path('/home/chenyoujian/.cache/forgeflow-interrupted-retry-t9xzneyq')
ORIGINAL_FAIL_SHA='8ed0e0135196c81779d1d78c92c083049c12fa0ecd18b4d53afce3fb7c754d99'
CONTINUATION_R1_FAIL_SHA='8a7d664710e30559135330b6a7722de610f1cb896620f87338a3d5a4288a7f74'
CONTINUATION_R2_FAIL_SHA='4732013a37b25a973e385bb9014fd05cf49684fb54f0338f10792a71aa85ecb0'
CONTINUATION_R3_FAIL_SHA='4c3c25325da606e568e15b33a89a29c81fd44832bad42203d0fc3b4ea1392e2b'
def browser_source():
 source=(ROOT/'verification/interrupted_retry_browser_point.mjs').read_text()
 start=source.index(' await visitRun(input.old_attempt_id);')
 end=source.index(' const retry=await awaitFile(input.retry_input_path);')
 source=source[:start]+source[end:]
 return source.replace("len(br['commands'])==3", "len(br['commands'])==2")
def prepare(args):
 assert sha(ORIGINAL/'report.json')==ORIGINAL_FAIL_SHA
 assert sha(ORIGINAL/'point-continuation-r1/report.json')==CONTINUATION_R1_FAIL_SHA
 assert sha(ORIGINAL/'point-continuation-r2/report.json')==CONTINUATION_R2_FAIL_SHA
 assert sha(ORIGINAL/'point-continuation-r3/report.json')==CONTINUATION_R3_FAIL_SHA
 original=load(ORIGINAL/'report.json');assert original['status']=='FAIL' and len(original['checks'])==4 and all(c['status']=='PASS' for c in original['checks'])
 assert original['private_port_closed'] and len(original['owned_cleanup'])==2
 pins={p:sha(ROOT/p) for p in SOURCES}
 plan={'schema_version':'forgeflow.interrupted-retry-continuation-plan.v1','status':'SOURCE_READY_NO_ACTORS','source_identity':SOURCE,'port':8897,'actor_phase_alarm_seconds':360,'cleanup_alarm_seconds':60,'source_pins':pins,'runtime_pins':{p:sha(p) for p in [NODE,CHROME,str(Path(sys.executable).resolve()),'/usr/bin/python3','/usr/bin/bwrap']},'original_report':{'path':str(ORIGINAL/'report.json'),'sha256':ORIGINAL_FAIL_SHA},'continuation_r3_report_sha256':CONTINUATION_R3_FAIL_SHA,'continuation_r3_source_sha256':sha(ORIGINAL/'point-continuation-r3/source-frozen-r3.py'),'continuation_r2_report_sha256':CONTINUATION_R2_FAIL_SHA,'continuation_r2_source_sha256':sha(ORIGINAL/'point-continuation-r2/source-frozen-r2.py'),'continuation_r1_report_sha256':CONTINUATION_R1_FAIL_SHA,'continuation_r1_source_sha256':sha(ORIGINAL/'point-continuation-r1/source-frozen-r1.py'),'original_plan_sha256':sha(ORIGINAL/'source-ready-plan.json'),'private_fixture_pins':{str(ORIGINAL_PRIVATE/p):sha(ORIGINAL_PRIVATE/p) for p in ['runtime-env.json','worker-config.json','worker-env.json','retry.json','cancel.json']},'derived_browser_sha256':hashlib.sha256(browser_source().encode()).hexdigest(),'business_oracle':['Reuse actual committed Flow3/taskRev3/correct immutable plan3; retain all prior failures and both cancelled Attempts; no repeated plan3/Flow3 creation','Retry current taskRev3; only if its actual template expired create child4/taskRev4/newplan4, binding API-saved authoritative digest before compile/commit','Same original database/project/Worker profile, new owned supervisors; actual GUI retry, new Attempt with strictly newer actual generation; no original author/cancel replay','Both old exact heartbeat and new Attempt old generation rejected 409 with identical resource/custody/evidence/ref projections','One real finite new author seed732, GUI independent verification and finalized Git integration; candidate/integrated each3roles8cases with positive physical stop','Original FAIL and prior continuation failures and passed facts retained; old CANCELLED journal remains fixed, new SUCCEEDED history GUI; legal shutdown/zero resources/no model'], 'qualification':'Point continuation from never-admitted retry edge. Original timeout is retained as fixture preparation failure, never overwritten or counted as success. No production retry authority relaxation.','actors':{'ownedAPI':1,'ownedWorker':1,'newAuthors':1,'originalAuthors':0,'verifier_commands':6,'models':0,'DSH':0}}
 secure_save(args.output/'source-ready-plan.json',plan)
 business.private_bytes(args.output/'derived-browser-source.mjs',browser_source().encode())
 print(json.dumps({'status':plan['status'],'plan_sha256':sha(args.output/'source-ready-plan.json'),'driver_sha256':sha(__file__),'browser_sha256':plan['derived_browser_sha256'],'models':0,'actors':0}));return 0
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
 assert sha(ORIGINAL/'report.json')==ORIGINAL_FAIL_SHA
 assert sha(ORIGINAL/'point-continuation-r1/report.json')==CONTINUATION_R1_FAIL_SHA
 assert sha(ORIGINAL/'point-continuation-r2/report.json')==CONTINUATION_R2_FAIL_SHA
 assert sha(ORIGINAL/'point-continuation-r3/report.json')==CONTINUATION_R3_FAIL_SHA
 assert all(sha(p)==v for p,v in plan['private_fixture_pins'].items())
 assert hashlib.sha256(browser_source().encode()).hexdigest()==plan['derived_browser_sha256']
 assert not (args.output/'report.json').exists(),'No automatic actor replay'
 main=business.unit_properties('forgeflow-control.service');assert main['MainPID']==str(go['main_pid']) and main['ActiveState']=='active'
 unit=go['api_service_name']+'.service';slice_name='forgeflowcontrolresources'+go['api_service_name'].removeprefix('forgeflow-control-')+'.slice'
 assert business.unit_properties(unit)['LoadState']=='not-found'
 with socket.socket() as sk:assert sk.connect_ex(('127.0.0.1',args.port))!=0
 private=ORIGINAL_PRIVATE;run_private=private/'point-continuation-r4';run_private.mkdir(mode=0o700);diagnostics=run_private/'diagnostics';diagnostics.mkdir(mode=0o700)
 original=load(ORIGINAL/'report.json')
 report={'schema_version':'forgeflow.interrupted-retry-point-continuation.v1','status':'RUNNING','source_identity':SOURCE,'plan_sha256':args.plan_sha256,'build_receipt_sha256':sha(args.build_receipt),'console_tree_sha256':go['console_tree_sha256'],'private_root':str(private),'continuation_private_root':str(run_private),'original_fail_sha256':ORIGINAL_FAIL_SHA,'original_passed_fact_count':4,'checks':[],'errors':[],'models':0,'DSH':0,'main_before':main,'qualification':plan['qualification'],'raw_manifest':[]}
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
  p=run_private/(name+'.json')
  def ready():
   if p.exists():return load(p)
   if browser.poll() is not None:raise RuntimeError('GUI exited before '+name+'; original private report retained')
   return None
  return wait(ready,'actual GUI '+name,45)
 def interrupted(*unused):raise RuntimeError('Bounded BC06 actor/cleanup deadline')
 oldalarm=signal.signal(signal.SIGALRM,interrupted);oldterm=signal.signal(signal.SIGTERM,interrupted);signal.alarm(360)
 try:
  env=load(private/'runtime-env.json');assert env['FORGEFLOW_BIND']=='127.0.0.1:8897' and env['FORGEFLOW_CONSOLE_DIR']==str(args.console_dir.resolve())
  client=Client('http://127.0.0.1:8897',env['FORGEFLOW_OWNER_TOKEN'],args.output,diagnostics);client.database_url=env['DATABASE_URL'];client.worker_token=env['FORGEFLOW_WORKER_TOKEN'];client.sensitive.add(client.worker_token)
  business.child_json([sys.executable,str(ROOT/'ops/manage-service.py'),'install','--name',go['api_service_name'],'--release-dir',str(args.runtime_release),'--runtime-env',str(private/'runtime-env.json'),'--verifier-cgroups','--start']);api_created=True;api_sha=sha(Path.home()/'.config/systemd/user'/unit)
  def healthy():
   try:return client.request('GET','/me')[0]==200
   except OSError:return False
  wait(healthy,'owned continuation API ready',30)
  workerconfig=load(private/'worker-config.json');project=workerconfig['project_id'];tid=original['task_id'];oldid=original['old_attempt_id'];oldjournal=private/'state/attempts'/oldid;old=load(oldjournal/'envelope.json')
  fixture={'project':project,'worker':workerconfig['worker_id'],'config':private/'worker-config.json','env':private/'worker-env.json','canonical':private/'canonical.git','baseline':load(ORIGINAL/'flow2.json')['tasks'][0]['envelope']['base_sha']};report['project_id']=project;report['task_id']=tid;report['old_attempt_id']=oldid
  state=snapshot();prior_attempt_ids={a['attempt_id'] for a in state['attempts']};stopped=next(a for a in state['attempts'] if a['attempt_id']==oldid);old=stopped;ledger=ledger_totals({project:state})
  oldpins=original['checks'][2]['facts']['old_journal_sha256']
  check('same_original_never_admitted_edge_and_released_old_history',len(state['attempts'])==2 and all(a['state']=='CANCELLED' for a in state['attempts']) and stopped['state']=='CANCELLED' and state['project']['paused'] and not ledger['mismatches'] and not ledger['allocated_vectors'] and all(sha(oldjournal/n)==v for n,v in oldpins.items() if n!='result-ack.json'),{'old_attempt':stopped,'ledger':ledger,'old_journal_sha256':oldpins})
  original_ack=load(ORIGINAL/'old-author/result-ack.json');current_ack=load(oldjournal/'result-ack.json')
  report['old_ack_observation']={'original_sha256':oldpins['result-ack.json'],'current_sha256':sha(oldjournal/'result-ack.json'),'canonical_without_query_observed_at_equal':canonical_ack(original_ack)==canonical_ack(current_ack),'query_timestamp_is_immutable_execution_evidence':False}
  if canonical_ack(original_ack)!=canonical_ack(current_ack):report.setdefault('observations',[]).append({'status':'UNKNOWN','name':'old_ACK_canonical_observation_differs','effect':'No execution authority derived from query ACK; original immutable launch/stop/envelope still enforced'})
  task3=client.api('GET',f'/projects/{project}/tasks/{tid}');assert task3['task_revision']==3 and task3['flow_revision']==3
  flow3=client.api('GET',f'/flows/{project}:3');context3=client.api('GET',f'/flows/{project}:3/context');planid=task3['envelope']['verification_plan_id'];registered=next(v for v in client.api('GET',f'/projects/{project}/documents/verification_plans') if v['plan_id']==planid)
  assert flow3['state']=='COMMITTED' and registered['input_hash']==task3['input_digest'] and registered['task_revision']==3
  now=datetime.now(timezone.utc);expired=datetime.fromisoformat(task3['envelope']['expires_at'].replace('Z','+00:00'))<=now or datetime.fromisoformat(task3['envelope']['deadline_at'].replace('Z','+00:00'))<=now
  if expired:
   child=copy.deepcopy(flow3);ctx=copy.deepcopy(context3);child.update(flow_revision=4,parent_revision=3,state='DRAFT',revision=1,approved_by=None);t=child['tasks'][0];t.update(task_revision=4,flow_revision=4,revision=task3['revision']+1,state='NEEDS_REVIEW')
   nextplan='interrupted-retry-verify-r4-'+tid;assert all(v['plan_id']!=nextplan for v in client.api('GET',f'/projects/{project}/documents/verification_plans'))
   ctx['task_specs'][tid]['verification_plan']=nextplan;e=t['envelope'];e.update(task_revision=4,base_sha=business.git(fixture['canonical'],'rev-parse','refs/heads/main'),verification_plan_id=nextplan,issued_at=now.isoformat(),expires_at=(now+timedelta(seconds=180)).isoformat(),deadline_at=(now+timedelta(minutes=5)).isoformat())
   saved=client.api('POST',f'/projects/{project}/flow-revisions',{'flow':child,'context':ctx});canonical_digest=saved['tasks'][0]['input_digest'];newplan=copy.deepcopy(registered);newplan.pop('revision');newplan.update(plan_id=nextplan,task_revision=4,input_hash=canonical_digest)
   client.api('POST',f'/projects/{project}/documents/verification_plans',{'id':nextplan,'value':newplan});committed=client.api('POST',f'/flows/{project}:4/commit',{'expected_revision':saved['revision']});newtask=committed['tasks'][0]
   registered4=next(v for v in client.api('GET',f'/projects/{project}/documents/verification_plans') if v['plan_id']==nextplan);assert newtask['input_digest']==canonical_digest==registered4['input_hash'] and registered4['revision']==1
   save(args.output/'necessary-fresh-child4.json',committed);save(args.output/'necessary-fresh-plan4.json',registered4)
   preserved=client.api('GET',f'/flows/{project}:3');assert semantic_flow(preserved)==semantic_flow(flow3) and preserved['state']=='SUPERSEDED' and next(v for v in client.api('GET',f'/projects/{project}/documents/verification_plans') if v['plan_id']==planid)==registered
  else:newtask=task3
  fencequery=database_command(client.database_url,f"SELECT fence_epoch FROM tasks WHERE project_id='{project}' AND task_id='{tid}';");assert fencequery.returncode==0;pre_retry_epoch=int(fencequery.stdout.strip())
  check('reuse_current_task_plan_or_only_expired_rebase',newtask['envelope']['base_sha']==fixture['baseline'] and datetime.fromisoformat(newtask['envelope']['expires_at'].replace('Z','+00:00'))>datetime.now(timezone.utc),{'actual_template_expired':expired,'task_revision':newtask['task_revision'],'flow_revision':newtask['flow_revision'],'pre_retry_fence_epoch':pre_retry_epoch,'plan3_preserved_sha256':value_sha(registered)})
  expected_task_revision=newtask['task_revision'];report['new_task_revision']=expected_task_revision
  launcher=ROOT/'ops/run-delegated-worker.py';wp=business.child_json([sys.executable,str(launcher),'prepare','--kind','worker','--program',receipt['binaries']['forgeflow-worker']['path'],'--program-sha256',receipt['binaries']['forgeflow-worker']['sha256'],'--config',str(fixture['config']),'--env-file',str(fixture['env']),'--output',str(run_private/'delegated-worker')]);worker_unit=wp['unit_name'];worker_plan=load(run_private/'delegated-worker/launch-plan.json')
  business.child_json([sys.executable,str(launcher),'start','--plan',str(run_private/'delegated-worker/launch-plan.json'),'--plan-sha256',wp['plan_sha256'],'--unit-sha256',wp['unit_sha256'],'--execute'])
  def workerready():
   r=database_command(client.database_url,f"SELECT count(*) FROM workers WHERE worker_id='{fixture['worker']}' AND heartbeat_at>clock_timestamp()-interval '5 seconds';");return r.returncode==0 and r.stdout.strip() in (b'1','1')
  wait(workerready,'same Worker profile actual registration',30)
  ui={'url':client.base_url,'owner_token':env['FORGEFLOW_OWNER_TOKEN'],'project_id':project,'task_id':tid,'old_attempt_id':oldid,'chrome':CHROME,'output':str(args.output),'retry_input_path':str(run_private/'retry-input.json'),'retry_path':str(run_private/'retry.json'),'integrate_input_path':str(run_private/'integrate-input.json'),'integrate_path':str(run_private/'integrate.json'),'final_input_path':str(run_private/'final-input.json'),'report_path':str(run_private/'browser-report.json')};secure_save(run_private/'browser-input.json',ui);business.private_bytes(run_private/'browser.mjs',browser_source().encode());assert sha(run_private/'browser.mjs')==plan['derived_browser_sha256']
  browser_log=os.fdopen(os.open(run_private/'browser.log',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb');browser=subprocess.Popen([NODE,str(run_private/'browser.mjs'),str(run_private/'browser-input.json')],stdout=browser_log,stderr=subprocess.STDOUT)
  secure_save(run_private/'retry-input.json',{'task_revision':expected_task_revision,'flow_revision':newtask['flow_revision']});retry=ui_file('retry');save(args.output/'gui-retry.json',retry);paused(client,project,False)
  def newverifying():
   rows=[a for a in snapshot()['attempts'] if a['attempt_id'] not in prior_attempt_ids]
   if rows and rows[0]['state'] in ('FAILED','CANCELLED','RECOVERY_REQUIRED'):raise RuntimeError('New controlled author failed '+rows[0]['state'])
   return rows[0] if rows and rows[0]['state']=='VERIFYING' else None
  new=wait(newverifying,'canonical retry produces new finite author',45);newid=new['attempt_id'];report['new_attempt_id']=newid;paused(client,project,True);newjournal=private/'state/attempts'/newid;bindings=load(newjournal/'execution-bindings.json');newstop=load(newjournal/'stop.json')
  check('canonical_new_attempt_new_lease_monotonic_generation_real_execution',new['task_revision']==expected_task_revision and load(newjournal/'envelope.json')['task_revision']==expected_task_revision and new['generation']>old['generation'] and new['generation']>pre_retry_epoch and new['lease_id']!=old['lease_id'] and new['operation_id']!=old['operation_id'] and load(newjournal/'envelope.json')['generation']==new['generation'] and load(newjournal/'envelope.json')['command']['args'][-1]=='732' and newstop['process_exit_confirmed'] and newstop['exit_code']==0,{'old':old,'new':new,'bindings_sha256':sha(newjournal/'execution-bindings.json')})
  wc=Client(client.base_url,client.worker_token,args.output/'stale-worker',run_private/'stale-worker');wc.sensitive.add(client.worker_token);before=observe('before-old-fences')
  for label,aid in [('old_exact_attempt',oldid),('new_attempt_old_generation',newid)]:
   status,value=wc.request('POST',f'/attempts/{aid}/heartbeat',{'project_id':project,'attempt_id':aid,'generation':old['generation'],'worker_id':fixture['worker'],'lease_seconds':120});after=observe(label)
   check(label+'_409_and_custody_resources_evidence_ref_unchanged',status==409 and value.get('code')=='LEASE_STALE' and before['allocations']==after['allocations'] and before['evidence']==after['evidence'] and before['merges']==after['merges'] and before['target_ref']==after['target_ref'],{'http_status':status,'code':value.get('code'),'authority_unchanged':before==after})
  secure_save(run_private/'integrate-input.json',{'attempt_id':newid});integration=ui_file('integrate');save(args.output/'gui-integrate.json',integration);opid=integration['integrate']['operation_id'];report['verification_operation_id']=opid
  def completed():
   row=client.api('GET','/operations/'+opid)
   if row['status'] in ('FAILED','RECOVERY_REQUIRED'):raise RuntimeError('Actual independent verification/Git '+row['status'])
   return row if row['status']=='SUCCEEDED' else None
  operation=wait(completed,'new candidate and integrated verification/Git',100);save(args.output/'verification-operation.json',operation);facts=observe('delivered');final=snapshot();oldfinal=next(a for a in final['attempts'] if a['attempt_id']==oldid);newfinal=next(a for a in final['attempts'] if a['attempt_id']==newid)
  merge=facts['merges'][0];candidate=[r for r in facts['evidence'] if r['kind']=='INDEPENDENT_VERIFICATION'];integrated=merge['receipt']['verification'];ref=facts['target_ref'];blob=subprocess.check_output(['git','-C',str(fixture['canonical']),'show',ref+':result.json']);(args.output/'integrated-result.bin').write_bytes(blob)
  check('new_candidate_and_integrated_real_independent_eight_cases',len(candidate)==1 and candidate[0]['attempt_id']==newid and candidate[0]['details']['binding']['task_revision']==expected_task_revision and candidate[0]['total']==8 and candidate[0]['failed']==candidate[0]['skipped']==0 and all(v['total']==8 and v['failed']==v['skipped']==0 and v['positive_cases']==v['negative_cases']==4 and v['independent'] for v in [candidate[0]['details'],integrated]) and integrated['binding']['attempt_id']==newid and integrated['binding']['generation']==new['generation'],{'candidate':candidate,'integrated':integrated,'assertions_per_stage':8,'command_denominator':6})
  check('new_finalized_Git_seed732_old_CANCELLED_preserved',merge['state']=='FINALIZED' and merge['integrated_sha']==ref and ref!=fixture['baseline'] and blob==(json.dumps({'kind':'CONTROL_LOAD','seed':732})+'\n').encode() and newfinal['state']=='SUCCEEDED' and oldfinal==stopped and all(sha(oldjournal/n)==s for n,s in oldpins.items() if n!='result-ack.json'),{'integrated_sha':ref,'blob_sha256':hashlib.sha256(blob).hexdigest(),'old_attempt':oldfinal,'new_attempt':newfinal})
  artifacts=client.api('GET',f'/projects/{project}/documents/artifacts');artifact=next(a for a in artifacts if a.get('artifact_id')==candidate[0]['artifact']['artifact_id']);candidate_log=Path(artifact['path']);integrated_log=Path(merge['receipt']['artifact_root'])/integrated['log_path'];assert sha(candidate_log)==artifact['sha256'] and sha(integrated_log)==integrated['log_hash'];retain(candidate_log,'candidate-verification/log.ndjson');retain(integrated_log,'integrated-verification/log.ndjson')
  closed=[]
  for stage,root in [('candidate',candidate_log.parent),('integrated',Path(merge['receipt']['artifact_root']))]:
   context=load(root/'verification-physical-context.json');seal=load(root/'verification-physical-closed.json');assert seal['context']==context and seal['runner_closed'] and context['parent_attempt_id']==newid and context['generation']==new['generation'] and len(context['commands'])==3
   retain(root/'verification-physical-context.json',stage+'-verification/context.json');retain(root/'verification-physical-closed.json',stage+'-verification/closed.json')
   for command in context['commands']:
    journal=root/'verification-runs'/command['process_attempt_id'];pstop=load(journal/'cgroup-stop.json');s=load(journal/'stop.json');assert s['process_exit_confirmed'] and pstop['process_exit_confirmed'] and not pstop['populated'] and not pstop['snapshot']['cgroup.procs'].strip()
    for n in (*business.REQUIRED_RAW[:5],'stop.json','verification-command.json'):retain(journal/n,stage+'-verification/'+command['role']+'/'+n)
    closed.append({'stage':stage,'command':command,'positive_stop_sha256':sha(journal/'cgroup-stop.json')})
  check('six_verifier_physical_stops_and_sequencer_closure',len(closed)==6 and len({c['command']['execution_id'] for c in closed})==6,closed)
  ledger=ledger_totals({project:final});zero=not ledger['mismatches'] and not ledger['allocated_vectors'] and all(a['state']=='RELEASED' for a in final['allocations']) and all(l['revoked_at'] is not None for l in final['leases'])
  check('final_all_scopes_released_no_valid_lease_zero_models',zero and facts['valid_leases']==facts['models']==0,ledger)
  for n in (*business.REQUIRED_RAW,'execution-bindings.json','result-ack.json'):retain(newjournal/n,'new-author/'+n)
  secure_save(run_private/'final-input.json',{'old_attempt_id':oldid,'new_attempt_id':newid,'old_state':'CANCELLED','new_state':'SUCCEEDED','integrated_sha':ref,'held':0});browser.wait(timeout=35);br=load(run_private/'browser-report.json');save(args.output/'browser-report.json',br);check('actual_GUI_retry_integration_and_original_history_readback',browser.returncode==0 and br['status']=='PASS_ACTUAL_INTERRUPT_RETRY_GUI' and br['browser_closed'] and len(br['commands'])==2 and len(br['pages'])==2,br);final_delivered=True
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
     else:assert path.is_symlink() and path.resolve()==run_private/'delegated-worker'/owned
     path.unlink();ctl('daemon-reload');report.setdefault('owned_cleanup',[]).append({'unit':owned,'terminal':terminal,'slice':business.unit_properties(own_slice),'unlinked':not path.exists()})
   else:report['quarantine_retained']=True
  except BaseException as e:report['errors'].append({'cleanup':type(e).__name__,'message':str(e)[:200]})
  signal.alarm(0)
  if browser_log:browser_log.close()
  report['original_fail_unchanged']=sha(ORIGINAL/'report.json')==ORIGINAL_FAIL_SHA and sha(ORIGINAL/'point-continuation-r1/report.json')==CONTINUATION_R1_FAIL_SHA and sha(ORIGINAL/'point-continuation-r2/report.json')==CONTINUATION_R2_FAIL_SHA and sha(ORIGINAL/'point-continuation-r3/report.json')==CONTINUATION_R3_FAIL_SHA
  report['main_after']=business.unit_properties('forgeflow-control.service')
  with socket.socket() as sk:report['private_port_closed']=sk.connect_ex(('127.0.0.1',args.port))!=0
  clean=report.get('owned_cleanup',[]);good=report['original_fail_unchanged'] and final_delivered and zero and not report['errors'] and len(clean)==2 and all(c['terminal']['MainPID']=='0' and c['terminal']['ExecMainStatus']=='0' and c['slice']['ActiveState']=='inactive' for c in clean) and report['private_port_closed'] and report['main_after']['MainPID']==main['MainPID'] and report['main_after']['ActiveState']=='active'
  report['status']='PASS_ACTUAL_INTERRUPTED_RETRY_POINT_CONTINUATION' if good else 'FAIL';report['assertions']=len(report['checks']);report['failed']=sum(c['status']!='PASS' for c in report['checks']);save(args.output/'report.json',report);signal.signal(signal.SIGALRM,oldalarm);signal.signal(signal.SIGTERM,oldterm)
 print(json.dumps({'status':report['status'],'report':str(args.output/'report.json'),'private_root':str(private),'models':0,'DSH':0}));return 0 if good else 1

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ORIGINAL/'point-continuation-r4');p.add_argument('--port',type=int,default=8897);p.add_argument('--run',action='store_true');p.add_argument('--plan-sha256');p.add_argument('--go',type=Path);p.add_argument('--build-receipt',type=Path);p.add_argument('--runtime-release',type=Path);p.add_argument('--console-dir',type=Path);a=p.parse_args();a.output=a.output.resolve();assert a.output.is_relative_to(ORIGINAL.resolve()) and a.port==8897;a.output.mkdir(parents=True,exist_ok=True)
 if a.run:
  assert all([a.go,a.build_receipt,a.runtime_release,a.console_dir,a.plan_sha256]);return execute(a)
 return prepare(a)
if __name__=='__main__':sys.exit(main())

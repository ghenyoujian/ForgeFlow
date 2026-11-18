#!/usr/bin/env python3
"""One finite decided/CAS-lock-failure/ref-old API crash and Owner recovery.

Prepare only by default. No SQL mutation, model, CPU stress, or actor replay.
The observed window is after a real failed first CAS, not an instruction-level
pre-CAS interruption. Existing business and physical launcher helpers are reused.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'verification'))
import physical_business_chain as business
from cross_project_business_chain import Client, ledger_totals, paused, save, wait
from guarded_api_chain import create_database, database_command, secure_save

SOURCE = '3ad30894d74a0b57c64a2ac6acda6e49d2697eea0658299850945b054000c512'
RAW = ('verification-command.json', 'launch-intent.json', 'launch-receipt.json',
       'cgroup-fence.json', 'cgroup-membership.json', 'cgroup-stop.json',
       'stop.json', 'stdout.ndjson', 'stderr.log')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def loaded(path):
    return json.loads(Path(path).read_text())


def ctl(*args):
    return subprocess.run(['systemctl','--user',*args], check=True,
                          capture_output=True, text=True, timeout=20)


def plan(args):
    receipt = loaded(args.build_receipt)
    assert re.fullmatch(r'[0-9a-f]{64}',args.expected_source_identity)
    assert re.fullmatch(r'forgeflow-control-[0-9a-f]{32}',args.api_service_name)
    assert receipt['source_identity']==args.expected_source_identity and receipt['consistent_copy'] and receipt['source_unchanged_after_build']
    assert all(c['exit_code']==0 for c in receipt['commands'])
    pins = []
    for name in ('forgeflow-server','forgeflow-worker','forgeflow-sandbox-guard'):
        row=receipt['binaries'][name];assert sha(row['path'])==row['sha256'];pins.append(dict(name=name,**row))
    manifest=loaded(args.runtime_release/'delivery-manifest.json')
    assert manifest['files']['bin/forgeflow-server']['sha256']==receipt['binaries']['forgeflow-server']['sha256']
    assert sha(args.runtime_release/'bin/forgeflow-server')==receipt['binaries']['forgeflow-server']['sha256']
    helpers=[Path(__file__),ROOT/'verification/physical_business_chain.py',ROOT/'verification/cross_project_business_chain.py',
             ROOT/'verification/guarded_api_chain.py',ROOT/'verification/algorithm_check.py',ROOT/'verification/fixtures/control_verifier.py',
             ROOT/'ops/manage-service.py',ROOT/'ops/run-service.py',ROOT/'ops/run-delegated-worker.py',
             Path('/usr/bin/python3').resolve(),Path('/usr/bin/bwrap')]
    assert args.port==8883 and args.main_pid==3998834
    return {'schema_version':'forgeflow.commit-decision-crash-source-plan.v1','status':'SOURCE_READY_NO_ACTORS',
            'source_identity':args.expected_source_identity,'receipt':{'path':str(args.build_receipt.resolve()),'sha256':sha(args.build_receipt)},
            'binaries':pins,'source_pins':[{'path':str(p.resolve()),'sha256':sha(p)} for p in helpers],
            'runtime_release':{'path':str(args.runtime_release.resolve()),'manifest_sha256':sha(args.runtime_release/'delivery-manifest.json')},
            'api_unit':args.api_service_name+'.service','port':args.port,'main_pid':args.main_pid,'models':0,
            'author_sha256':hashlib.sha256(business.VERIFIER_AUTHOR.encode()).hexdigest(),
            'author_sleep_seconds':2,'verifiers':'Existing original control_verifier roles; no CPU wrapper/stressor',
            'physical_limits':business.POLICY,'root_resources':business.REQUEST,'native_max_children':0,
            'window':'Durable decision; first real CAS fails on owned main.lock; target ref still expected; actual API SIGKILL',
            'recovery':'Same intent, Owner HTTP command, no author/verifier/Worker relaunch',
            'fixed_author_callback':'Await genuine Worker author_stop_only accepted with exact original execution/lease/generation before crash; irreversible intent and attempt remain RECOVERY_REQUIRED, terminal null, held28, lease/native counts unchanged',
            'cleanup':'Positive journal stops before crash, own API/Worker units and slices only, release checked via authority',
            'qualification':'One local process crash window; no power-loss/fullfaultmatrix/production promotion',
            'actors_started':0,'execution_requires_root_go_and_exact_plan_sha256':True}


def run(args, prepared_plan):
    UNIT=args.api_service_name+'.service'
    SLICE='forgeflowcontrolresources'+args.api_service_name.removeprefix('forgeflow-control-')+'.slice'
    source=args.output/'source-ready-plan.json'
    assert sha(source)==args.expected_plan_sha256 and loaded(source)==prepared_plan
    assert not (args.output/'report.json').exists(), 'Refuse actor replay'
    main=business.unit_properties('forgeflow-control.service')
    assert main['MainPID']==str(args.main_pid) and main['ActiveState']=='active'
    assert business.unit_properties(UNIT)['LoadState']=='not-found'
    with socket.socket() as sk:assert sk.connect_ex(('127.0.0.1',args.port))!=0
    private=Path(tempfile.mkdtemp(prefix='forgeflow-commit-crash-',dir='/home/chenyoujian/.cache'));private.chmod(0o700)
    (private/'state').mkdir(mode=0o700);diagnostics=private/'diagnostics';diagnostics.mkdir(mode=0o700)
    receipt=loaded(args.build_receipt);base_env=loaded(args.private_env);database='forgeflow_commit_crash_'+uuid.uuid4().hex[:16]
    env={'DATABASE_URL':create_database(base_env,database,private),'FORGEFLOW_BIND':f'127.0.0.1:{args.port}',
         'FORGEFLOW_DATA_ROOT':str(private/'state'),'FORGEFLOW_OWNER_TOKEN':secrets.token_hex(32),
         'FORGEFLOW_WORKER_TOKEN':secrets.token_hex(32),'RUST_LOG':'info'}
    secure_save(private/'runtime-env.json',env)
    client=Client(f'http://127.0.0.1:{args.port}',env['FORGEFLOW_OWNER_TOKEN'],args.output,diagnostics)
    client.worker_token=env['FORGEFLOW_WORKER_TOKEN'];client.database_url=env['DATABASE_URL'];client.sensitive.add(client.worker_token)
    report={'schema_version':'forgeflow.actual-commit-decision-crash.v1','status':'RUNNING','source_identity':args.expected_source_identity,
            'source_plan_sha256':args.expected_plan_sha256,'private_root':str(private),'database_name':database,
            'checks':[],'errors':[],'raw_manifest':[],'models':0,'main_before':main,
            'scope':prepared_plan['window'],'not_proven':['Instruction-level pre-CAS interruption','Power-loss durability','Fullfaultmatrix','Hostile/kernel attacks','Production100+']}
    api_created=False;worker_unit=None;worker_plan=None;fixture=None;lock=None;lock_identity=None;api_sha=None;zero=False

    def check(name,value,facts=None):
        report['checks'].append({'name':name,'status':'PASS' if value else 'FAIL','facts':facts});save(args.output/'report.json',report)
        if not value:raise RuntimeError(name)

    def observe():
        p=fixture['project'];aid=report['attempt_id']
        sql=f"SELECT jsonb_build_object('attempt',(SELECT data FROM attempts WHERE attempt_id='{aid}'),'merges',COALESCE((SELECT jsonb_agg(data) FROM merge_intents WHERE attempt_id='{aid}'),'[]'::jsonb),'evidence',COALESCE((SELECT jsonb_agg(data) FROM evidence_receipts WHERE attempt_id='{aid}'),'[]'::jsonb),'settlements',COALESCE((SELECT jsonb_agg(data) FROM documents WHERE project_id='{p}' AND collection='operations' AND data->>'kind'='VERIFIER_PROCESS_SETTLED' AND data->>'attempt_id'='{aid}'),'[]'::jsonb),'author_stop_callbacks',COALESCE((SELECT jsonb_agg(payload) FROM worker_event_ids WHERE payload->>'attempt_id'='{aid}' AND payload->'evidence'->>'author_stop_only'='true'),'[]'::jsonb),'held',(SELECT count(*) FROM resource_allocations WHERE attempt_id='{aid}' AND state<>'RELEASED'),'native_held',(SELECT count(*) FROM native_child_allocations WHERE attempt_id='{aid}' AND state<>'RELEASED'),'models',(SELECT count(*) FROM model_request_permit),'leases',(SELECT count(*) FROM leases WHERE attempt_id='{aid}' AND revoked_at IS NULL));"
        value=database_command(client.database_url,sql)
        if value.returncode:raise RuntimeError('Read-only authority observation failed')
        return json.loads(value.stdout)

    def copy_raw(source,target):
        target=args.output/'raw'/target;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        report['raw_manifest'].append({'path':str(target.relative_to(ROOT)),'sha256':sha(target),'bytes':target.stat().st_size})

    def healthy():
        try:return client.request('GET','/me')[0]==200
        except OSError:return False

    try:
        business.child_json([str(Path(sys.executable).resolve()),str(ROOT/'ops/manage-service.py'),'install','--name',UNIT.removesuffix('.service'),
            '--release-dir',str(args.runtime_release),'--runtime-env',str(private/'runtime-env.json'),'--verifier-cgroups','--start'])
        api_created=True;unit_file=Path.home()/'.config/systemd/user'/UNIT;api_sha=sha(unit_file);shutil.copyfile(unit_file,private/'control-unit.service')
        wait(healthy,'private control readiness',30)
        fixture=business.create_fixture(client,private,receipt,False)
        # Select the existing short author while retaining the original oracle.
        fixture['verifier_physical']=True;report['project_id']=fixture['project']
        launcher=ROOT/'ops/run-delegated-worker.py';python=str(Path(sys.executable).resolve())
        wp=business.child_json([python,str(launcher),'prepare','--kind','worker','--program',receipt['binaries']['forgeflow-worker']['path'],
            '--program-sha256',receipt['binaries']['forgeflow-worker']['sha256'],'--config',str(fixture['config']),
            '--env-file',str(fixture['env']),'--output',str(private/'delegated-worker')])
        worker_unit=wp['unit_name'];worker_plan=loaded(private/'delegated-worker/launch-plan.json');report['worker_unit']=worker_unit
        business.child_json([python,str(launcher),'start','--plan',str(private/'delegated-worker/launch-plan.json'),
            '--plan-sha256',wp['plan_sha256'],'--unit-sha256',wp['unit_sha256'],'--execute'])
        def registered():
            r=database_command(client.database_url,"SELECT count(*) FROM workers WHERE worker_id='"+fixture['worker']+"'")
            return r.returncode==0 and r.stdout.strip()==b'1'
        wait(registered,'actual business Worker registration',30);business.finalize_fixture(client,private,fixture)
        task=fixture['task'];client.api('POST',f"/projects/{fixture['project']}/queue-entries",{'task_id':task['task_id'],
            'expected_revision':task['revision'],'worker_id':fixture['worker'],'worker_scope_id':fixture['project']+':worker',
            'scope_ids':[],'priority':1,'lease_seconds':120});paused(client,fixture['project'],False)
        def verifying():
            s=client.api('GET',f"/projects/{fixture['project']}/snapshot")
            rows=s['attempts']
            return rows[0] if rows and rows[0]['state']=='VERIFYING' else None
        attempt=wait(verifying,'short author awaited stop',45);report['attempt_id']=attempt['attempt_id'];journal=private/'state/attempts'/attempt['attempt_id']
        paused(client,fixture['project'],True)
        author_stop=loaded(journal/'stop.json');physical_stop=loaded(journal/'cgroup-stop.json')
        check('author_awaited_positive_stop',author_stop['process_exit_confirmed'] and author_stop['exit_code']==0 and physical_stop['process_exit_confirmed'] and not physical_stop['populated'])
        lock=fixture['canonical']/'refs/heads/main.lock';lock.parent.mkdir(parents=True,exist_ok=True)
        payload=('Owned finite crash barrier '+uuid.uuid4().hex+'\n').encode();fd=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(payload);stream.flush();os.fsync(stream.fileno())
        lock_identity={'path':str(lock),'inode':lock.stat().st_ino,'sha256':sha(lock)}
        accepted=client.api('POST',f"/attempts/{attempt['attempt_id']}/verify-and-integrate",{'project_id':fixture['project']})
        report['original_operation_id']=accepted['operation_id']
        def window():
            facts=observe()
            if facts['merges'] and facts['merges'][0]['state']=='RECOVERY_REQUIRED':return facts
            op=client.api('GET','/operations/'+accepted['operation_id'])
            if op['status']=='FAILED':raise RuntimeError('Failed before durable CAS-lock window')
            return None
        before=wait(window,'real decided first CAS lock failure',90);intent=before['merges'][0];report['intent_id']=intent['intent_id']
        old=business.git(fixture['canonical'],'rev-parse','refs/heads/main')
        check('durable_decision_first_CAS_failed_ref_still_old',len(before['merges'])==1 and intent['receipt']['commit_decided'] is True and
              not intent['receipt'].get('ref_updated',False) and old==intent['expected_sha'] and old!=intent['integrated_sha'] and before['held']>0,
              {'intent':intent,'target_ref':old,'held':before['held'],'lock':lock_identity})
        check('six_short_verifiers_settled_before_crash',len(before['settlements'])==2 and all(len(v['physical_evidence'])==3 and all(c['status']=='STOPPED' for c in v['physical_evidence']) for v in before['settlements']))
        original_launch=loaded(journal/'launch-receipt.json')
        def real_callback():
            facts=observe()
            if facts['author_stop_callbacks']:return facts
            if facts['attempt']['state']!='RECOVERY_REQUIRED' or facts['attempt']['terminal_at'] is not None:
                raise RuntimeError('Attempt lost irreversible recovery authority before genuine Worker callback')
            return None
        callback_facts=wait(real_callback,'genuine Worker author-stop callback accepted',45)
        callbacks=callback_facts['author_stop_callbacks'];callback=callbacks[0]
        original_envelope=loaded(journal/'envelope.json')
        expected_event=original_envelope['operation_id']+':post-author-stop-confirmation'
        check('genuine_Worker_stop_callback_accepted_preserves_irreversible_authority',len(callbacks)==1 and
              callback['event_id']==expected_event and callback['attempt_id']==attempt['attempt_id'] and
              callback['worker_id']==fixture['worker'] and callback['lease_id']==attempt['lease_id'] and
              callback['generation']==attempt['generation'] and callback['outcome']['execution_id']==original_launch['execution_id'] and
              callback['evidence']['author_stop_only'] is True and callback['evidence']['process_exit_confirmed'] is True and
              callback_facts['attempt']['state']=='RECOVERY_REQUIRED' and callback_facts['attempt']['terminal_at'] is None and
              callback_facts['held']==before['held']==28 and callback_facts['leases']==before['leases'] and
              callback_facts['native_held']==before['native_held']==0 and callback_facts['models']==before['models']==0 and
              len(callback_facts['merges'])==1 and callback_facts['merges'][0]['state']=='RECOVERY_REQUIRED' and
              callback_facts['merges'][0]['receipt']['commit_decided'] is True and
              business.git(fixture['canonical'],'rev-parse','refs/heads/main')==old,
              {'accepted_event':callback,'authority':callback_facts})
        save(args.output/'accepted-Worker-stop-before-crash.json',callback_facts)
        before=callback_facts
        frozen=Path(intent['receipt']['artifact_root']);frozen_files={name:sha(frozen/name) for name in ('forgeflow-verification.json',intent['receipt']['verification']['log_path'])}
        save(args.output/'before-crash.json',{'authority':before,'ref':old,'immutable_files':frozen_files,'lock':lock_identity})
        for name in RAW[1:]:copy_raw(journal/name,Path('author')/name)
        for stage,root in [('candidate',private/'state/artifacts'/accepted['operation_id']),('integrated',Path(intent['receipt']['verifier_scratch_root']))]:
            ctx=loaded(root/'verification-physical-context.json')
            for name in ('verification-physical-context.json','verification-physical-closed.json','author.json','consumer.json','independent.json'):
                copy_raw(root/name,Path(stage)/name)
            for command in ctx['commands']:
                for name in RAW:copy_raw(root/'verification-runs'/command['process_attempt_id']/name,Path(stage)/command['role']/name)
        for name in frozen_files:copy_raw(frozen/name,Path('canonical')/name)
        # Freeze the own API first; its stop job then prevents failure restart.
        crash_before=business.unit_properties(UNIT);ctl('kill','--kill-whom=main','--signal=SIGSTOP',UNIT)
        ctl('stop','--no-block',UNIT);ctl('kill','--kill-whom=all','--signal=SIGKILL',UNIT)
        crash=wait(lambda:business.unit_properties(UNIT) if business.unit_properties(UNIT)['MainPID']=='0' else None,'actual API crash exit',30)
        root=Path('/sys/fs/cgroup')/crash_before['ControlGroup'].lstrip('/')
        empty=not root.exists() or not any(p.read_text().strip() for p in root.rglob('cgroup.procs'))
        check('actual_owned_API_SIGKILL_and_group_empty',crash['ExecMainStatus']=='9' and crash['MainPID']=='0' and empty,{'before':crash_before,'after':crash,'group_empty':empty})
        save(args.output/'actual-crash.json',{'before':crash_before,'after':crash,'group_empty':empty,'authority':observe()})
        assert lock.stat().st_ino==lock_identity['inode'] and sha(lock)==lock_identity['sha256'] and not lock.is_symlink()
        lock.unlink();lock=None
        ctl('reset-failed',UNIT);ctl('start',UNIT);wait(healthy,'same API restart readiness',30)
        reviewed=observe()['merges'][0];key=uuid.uuid4().hex
        body={'project_id':fixture['project'],'intent_id':intent['intent_id'],'expected_intent_revision':reviewed['revision'],
              'reason':'Recover original durable decision after real first CAS lock failure and own API SIGKILL; no author/verifier replay'}
        status,ack=client.request('POST',f"/attempts/{attempt['attempt_id']}/integration-recovery",body,key)
        check('Owner_recovery_accepted',status==202,ack);recovery=ack['operation_id']
        def settled():
            op=client.api('GET','/operations/'+recovery)
            if op['status'] in ('FAILED','RECOVERY_REQUIRED'):raise RuntimeError('Same intent recovery failed')
            return op if op['status']=='SUCCEEDED' else None
        done=wait(settled,'same intent durable recovered finalization',90);after=observe();new=business.git(fixture['canonical'],'rev-parse','refs/heads/main')
        check('same_intent_candidate_integrated_and_single_ref_advance',len(after['merges'])==1 and after['attempt']['state']=='SUCCEEDED' and
              after['merges'][0]['state']=='FINALIZED' and all(after['merges'][0][k]==intent[k] for k in ('intent_id','candidate_sha','integrated_sha','expected_sha')) and
              new==intent['integrated_sha'] and subprocess.check_output(['git','-C',str(fixture['canonical']),'show',new+':result.json'])==fixture['expected_blob'])
        check('immutable_receipt_logs_and_no_reexecution',all(sha(frozen/name)==h for name,h in frozen_files.items()) and
              done['result']['author_reexecuted'] is False and done['result']['verification_commands_rerun']==0 and done['result']['model_requests_started']==0)
        status,replay=client.request('POST',f"/attempts/{attempt['attempt_id']}/integration-recovery",body,key)
        check('same_key_replay_without_new_merge_or_ref_change',status==202 and replay.get('replayed') is True and replay['operation_id']==recovery and
              len(observe()['merges'])==1 and business.git(fixture['canonical'],'rev-parse','refs/heads/main')==new)
        final=client.api('GET',f"/projects/{fixture['project']}/snapshot");ledger=ledger_totals({fixture['project']:final})
        zero=not ledger['mismatches'] and not ledger['allocated_vectors'] and all(l['revoked_at'] is not None for l in final['leases'])
        check('all_scope_seven_dimensions_released_models_zero',zero and after['held']==0 and after['leases']==0 and after['models']==0,ledger)
        save(args.output/'after-recovery.json',{'authority':after,'operation':done,'target_ref':new,'ledger':ledger})
    except Exception as error:
        report['errors'].append({'type':type(error).__name__,'message':str(error)[:240]})
    finally:
        if lock is not None:
            try:
                if lock_identity and not lock.is_symlink() and lock.stat().st_ino==lock_identity['inode'] and sha(lock)==lock_identity['sha256']:lock.unlink()
            except Exception as error:report['errors'].append({'cleanup':'lock','message':str(error)[:160]})
        # Signals target only supervisors. A failed authority retains its DB,
        # original journals and quarantined capacity; no SQL release is invented.
        for unit,sl in [(worker_unit,worker_plan['slice_name'] if worker_plan else None),(UNIT if api_created else None,SLICE)]:
            if not unit:continue
            try:
                before_stop=business.unit_properties(unit);pid=int(before_stop['MainPID'])
                if pid:os.kill(pid,signal.SIGTERM)
                terminal=wait(lambda:business.unit_properties(unit) if business.unit_properties(unit)['MainPID']=='0' else None,'own supervisor stop',35)
                ctl('stop',unit,sl)
                path=Path.home()/'.config/systemd/user'/unit
                if unit==UNIT:
                    ctl('disable',unit);assert not path.is_symlink() and sha(path)==api_sha
                else:assert path.is_symlink() and path.resolve()==private/'delegated-worker'/unit
                path.unlink();ctl('daemon-reload')
                report.setdefault('owned_cleanup',[]).append({'unit':unit,'terminal':terminal,'slice':business.unit_properties(sl),'unit_unlinked':not path.exists()})
            except Exception as error:report['errors'].append({'cleanup':unit,'message':str(error)[:180]})
        after_main=business.unit_properties('forgeflow-control.service');report['main_after']=after_main
        if after_main['MainPID']!=str(args.main_pid) or after_main['ActiveState']!='active':report['errors'].append({'main':'Main identity changed'})
        with socket.socket() as sk:report['private_port_closed']=sk.connect_ex(('127.0.0.1',args.port))!=0
        report['assertions']=len(report['checks']);report['failed']=sum(c['status']!='PASS' for c in report['checks'])
        clean=report.get('owned_cleanup',[])
        good=zero and not report['errors'] and not report['failed'] and len(clean)==2 and all(c['terminal']['ExecMainStatus']=='0' and c['terminal']['MainPID']=='0' and c['slice']['ActiveState']=='inactive' for c in clean) and report['private_port_closed']
        report['status']='PASS_ACTUAL_DECIDED_CAS_FAILURE_API_CRASH_RECOVERY' if good else 'FAIL'
        save(args.output/'report.json',report)
    print(json.dumps({'status':report['status'],'report':str(args.output/'report.json'),'assertions':report['assertions'],'failed':report['failed'],'private_root':str(private)}))
    return 0 if report['status'].startswith('PASS_') else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-receipt',type=Path,required=True);parser.add_argument('--runtime-release',type=Path,required=True)
    parser.add_argument('--private-env',type=Path,required=True);parser.add_argument('--output',type=Path,default=ROOT/'evidence/commit-decision-crash-r1')
    parser.add_argument('--expected-source-identity',default=SOURCE)
    parser.add_argument('--api-service-name',required=True,help='Fresh dedicated forgeflow-control-32hex unit')
    parser.add_argument('--port',type=int,default=8883);parser.add_argument('--main-pid',type=int,default=3998834)
    parser.add_argument('--execute-authorized',action='store_true');parser.add_argument('--expected-plan-sha256')
    args=parser.parse_args();args.output=args.output.resolve();args.output.mkdir(parents=True,exist_ok=True);value=plan(args)
    if not args.execute_authorized:
        path=args.output/'source-ready-plan.json';assert not path.exists();secure_save(path,value)
        print(json.dumps({'status':value['status'],'plan':str(path),'plan_sha256':sha(path),'driver_sha256':sha(__file__),'actors':0,'models':0}));return 0
    assert args.expected_plan_sha256, 'Exact Root approved plan required'
    return run(args,value)


if __name__=='__main__':
    raise SystemExit(main())

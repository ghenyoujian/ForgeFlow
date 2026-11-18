#!/usr/bin/env python3
"""One actual delivery-bundle Release GUI chain on a real accepted-milestone DB clone.

Preparation starts no actors. Runtime dumps the old DB read-only, restores a new
private DB, preserves original registered artifact/repository identities and
writes exports only into its new private namespace. No Worker/model replay.
"""
import argparse, hashlib, json, os, secrets, signal, socket, subprocess, sys, tarfile, tempfile, urllib.parse, uuid
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'verification'),str(ROOT/'benchmarks')]
from cross_project_business_chain import Client, save, wait
from guarded_api_chain import create_database, database_command, secure_save
from decision_business_chain import main_identity, tree_sha
HANDOFF=ROOT/'evidence/business-chain-semantic-replanning-r1/selector-corrected-run/delivery-continuation-r1/handoff.json'
MILESTONE=ROOT/'evidence/milestone-acceptance-r1/descriptor-corrected-continuation-r1'
PG=Path('/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/postgresql/16/bin')
NODE=Path('/home/chenyoujian/miniconda/lib/python3.13/site-packages/playwright/driver/node')
CHROME=Path('/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome')
SOURCES=['verification/release_business_chain.py','verification/release_browser_point.mjs','verification/decision_business_chain.py','verification/cross_project_business_chain.py','verification/guarded_api_chain.py','benchmarks/metrics.py']
def load(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def exclusive(p,v):
    Path(p).parent.mkdir(parents=True,exist_ok=True)
    with Path(p).open('x') as f:json.dump(v,f,indent=2,ensure_ascii=False);f.write('\n')
def pg_env(url):
    u=urllib.parse.urlsplit(url);assert u.scheme in ('postgres','postgresql');q=urllib.parse.parse_qs(u.query)
    return {'PATH':str(PG)+':/usr/bin:/bin','LD_LIBRARY_PATH':'/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/x86_64-linux-gnu','PGHOST':q.get('host',[u.hostname or '127.0.0.1'])[0],'PGPORT':q.get('port',[str(u.port or 5432)])[0],'PGUSER':q.get('user',[urllib.parse.unquote(u.username or '')])[0],'PGPASSWORD':urllib.parse.unquote(u.password or ''),'PGDATABASE':u.path.lstrip('/')}
def git_main(repo):
    r=subprocess.run(['git','-C',str(repo),'rev-parse','refs/heads/main'],capture_output=True,text=True,timeout=10,check=True);return r.stdout.strip()
def originals(root):return {str(p.relative_to(root)):{'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(root.rglob('*')) if p.is_file()}
def safe_extract(archive,destination):
    names=[];total=0
    with tarfile.open(archive,'r:*') as tar:
        for member in tar:
            rel=Path(member.name)
            assert not rel.is_absolute() and '..' not in rel.parts
            assert member.isdir() or member.isfile(), 'bundle has unsupported link/device entry'
            total+=member.size;assert len(names)<1024 and total<=64*1024*1024
            target=destination/rel;assert target.resolve().is_relative_to(destination.resolve())
            if member.isdir():target.mkdir(parents=True,exist_ok=True)
            else:
                target.parent.mkdir(parents=True,exist_ok=True)
                with target.open('xb') as f:f.write(tar.extractfile(member).read())
            names.append(member.name)
    return names

def prepare(args):
    h=load(HANDOFF);m=load(MILESTONE/'report.json');accepted=load(MILESTONE/'retained-acceptances.json')
    assert m['status']=='PASS' and m['new_model_requests']==m['workers_started']==0 and m['cleanup']['quiescent']
    assert len(accepted)==2 and {x['baseline_version'] for x in accepted}=={1,2} and all(x['status']=='ACCEPTED' for x in accepted)
    assert git_main(h['canonical_repository'])==h['integrated_sha']
    paths=[HANDOFF,MILESTONE/'report.json',MILESTONE/'retained-baselines.json',MILESTONE/'retained-acceptances.json']
    artifacts=originals(Path(h['data_root'])/'artifacts');assert len(artifacts)<=256 and sum(x['bytes'] for x in artifacts.values())<=64*1024*1024
    plan={'schema_version':'forgeflow.release-business-chain-plan.v1','status':'SOURCE_READY_NO_ACTORS','port':8900,'source_pins':{p:sha(ROOT/p) for p in SOURCES},'runtime_pins':{str(p):sha(p) for p in [NODE,CHROME,PG/'pg_dump',PG/'pg_restore',PG/'psql',Path('/usr/bin/git'),Path('/usr/bin/tar')]},'historical_evidence_pins':{str(p.relative_to(ROOT)):sha(p) for p in paths},'handoff':str(HANDOFF),'project_id':h['project_id'],'milestone_id':m['milestone_id'],'main_sha':h['integrated_sha'],'original_artifacts':artifacts,'original_artifact_root':str(Path(h['data_root'])/'artifacts'),'clone':'real pg_dump custom-format read-only snapshot + pg_restore into fresh PostgreSQL URL DB; no TEMPLATE/old DB writes','export':'actual new API private artifacts namespace; real downloadable manifest+registered files+frozen Git source archive+installation bundle','actors':{'API':1,'browser':1,'Worker':0,'model_calls':0,'DSH':0},'actor_seconds':360,'cleanup_seconds':60,'scope':{'CPUQuota':'400%','MemoryMax':'4G','TasksMax':256},'build_receipt':'ROOT_CANDIDATE_RECEIPT_PLACEHOLDER','console':'ROOT_CONSOLE_BUILD_PLACEHOLDER','not_proven':['all historical log bundling','global production Gates','fresh Worker/DSH qualification','automatic dispatch after reopen']}
    exclusive(args.output/'source-ready-plan.json',plan)
    exclusive(args.output/'run-command.json',{'argv':[sys.executable,'-B',str(ROOT/'verification/release_business_chain.py'),'--run','--output',str(args.output),'--plan-sha256',sha(args.output/'source-ready-plan.json'),'--go',str(args.output/'go-approved-r1.json'),'--build-receipt','ROOT_CANDIDATE_RECEIPT_PLACEHOLDER','--console-dir','ROOT_CONSOLE_BUILD_PLACEHOLDER'],'outer_scope':['systemd-run','--user','--scope','--unit=forgeflow-release-business-r1','--property=CPUQuota=400%','--property=MemoryMax=4G','--property=TasksMax=256']})
    exclusive(args.output/'go-template.json',{'plan_sha256':sha(args.output/'source-ready-plan.json'),'build_receipt_sha256':'ROOT_CANDIDATE_RECEIPT_SHA256','source_identity':'ROOT_CANDIDATE_SOURCE_IDENTITY','console_tree_sha256':'ROOT_CONSOLE_TREE_SHA256','main_pid':'ROOT_CURRENT_MAIN_PID'})
    print(json.dumps({'plan_sha256':sha(args.output/'source-ready-plan.json'),'driver_sha256':sha(__file__),'browser_sha256':sha(ROOT/'verification/release_browser_point.mjs')}));return 0

def execute(args):
    plan=load(args.output/'source-ready-plan.json');go=load(args.go);receipt=load(args.build_receipt)
    assert sha(args.output/'source-ready-plan.json')==args.plan_sha256==go['plan_sha256']
    assert sha(args.build_receipt)==go['build_receipt_sha256'] and receipt['source_identity']==go['source_identity']
    assert tree_sha(args.console_dir)==go['console_tree_sha256']
    assert all(sha(ROOT/p)==s for p,s in plan['source_pins'].items()) and all(sha(p)==s for p,s in plan['runtime_pins'].items()) and all(sha(ROOT/p)==s for p,s in plan['historical_evidence_pins'].items())
    assert receipt['consistent_copy'] and receipt['source_unchanged_after_build'] and all(c['exit_code']==0 for c in receipt['commands'])
    for p in ['crates/domain/src/releases.rs','crates/store/src/releases.rs','crates/api/src/releases.rs','crates/api/src/lib.rs']:assert sha(Path(receipt['snapshot_root'])/p)==receipt['source_files'][p]
    binary=receipt['binaries']['forgeflow-server'];assert sha(binary['path'])==binary['sha256'];assert not (args.output/'report.json').exists()
    before=main_identity();assert before=={'MainPID':str(go['main_pid']),'ActiveState':'active'}
    with socket.socket() as sk:assert sk.connect_ex(('127.0.0.1',8900))!=0
    h=load(plan['handoff']);oldenv=load(h['runtime_env_path']);source_root=Path(plan['original_artifact_root']);assert originals(source_root)==plan['original_artifacts'];assert git_main(h['canonical_repository'])==plan['main_sha']
    private=Path(tempfile.mkdtemp(prefix='forgeflow-release-business-',dir='/home/chenyoujian/.cache'));private.chmod(0o700)
    report={'schema_version':'forgeflow.release-business-chain.v1','status':'RUNNING','business_chain':'3.12','project_id':h['project_id'],'source_identity':receipt['source_identity'],'build_receipt_sha256':sha(args.build_receipt),'plan_sha256':args.plan_sha256,'console_tree_sha256':go['console_tree_sha256'],'private_root':str(private),'checks':[],'errors':[],'Worker_started':0,'new_model_calls':'NOT_YET_OBSERVED','DSH_started':0,'not_proven':plan['not_proven']}
    api=browser=client=apilog=blog=env=None
    def check(name,condition,facts=None):
        report['checks'].append({'name':name,'status':'PASS' if condition else 'FAIL','facts':facts});save(args.output/'report.json',report)
        if not condition:raise RuntimeError('actual Release assertion failed: '+name)
    def observe(url,label):
        p=h['project_id'];sql=f"SELECT jsonb_build_object('project',(SELECT data FROM projects WHERE project_id='{p}'),'models',COALESCE((SELECT jsonb_agg(request_id ORDER BY request_id) FROM model_request_permit),'[]'::jsonb),'native_models',COALESCE((SELECT jsonb_agg(request_id ORDER BY request_id) FROM native_model_requests),'[]'::jsonb),'attempts',COALESCE((SELECT jsonb_agg(data ORDER BY attempt_id) FROM attempts WHERE project_id='{p}'),'[]'::jsonb),'held',(SELECT count(*) FROM resource_allocations WHERE project_id='{p}' AND state<>'RELEASED'),'active',(SELECT count(*) FROM attempts WHERE project_id='{p}' AND state NOT IN ('SUCCEEDED','FAILED','CANCELLED')),'valid_leases',(SELECT count(*) FROM leases WHERE project_id='{p}' AND revoked_at IS NULL AND expires_at>clock_timestamp()),'baselines',COALESCE((SELECT jsonb_agg(data ORDER BY document_id) FROM documents WHERE project_id='{p}' AND collection='milestone_baselines'),'[]'::jsonb),'acceptances',COALESCE((SELECT jsonb_agg(data ORDER BY document_id) FROM documents WHERE project_id='{p}' AND collection='milestone_acceptances'),'[]'::jsonb),'artifact_rows',COALESCE((SELECT jsonb_agg(data ORDER BY document_id) FROM documents WHERE project_id='{p}' AND collection='artifacts'),'[]'::jsonb),'events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY project_seq) FROM events e WHERE project_id='{p}'),'[]'::jsonb));"
        q=database_command(url,sql);assert q.returncode==0;value=json.loads(q.stdout);secure_save(private/(label+'.json'),value);save(args.output/(label+'.authority.json'),value);return value
    def interrupted(*unused):raise RuntimeError('bounded Release point interrupted/deadline')
    oldalarm=signal.signal(signal.SIGALRM,interrupted);oldterm=signal.signal(signal.SIGTERM,interrupted);signal.alarm(360)
    try:
        oldfacts=observe(oldenv['DATABASE_URL'],'original-readonly-before');check('original_quiescent_real_accepted_fixture',oldfacts['held']==oldfacts['active']==oldfacts['valid_leases']==0 and len(oldfacts['acceptances'])==2 and all(x['status']=='ACCEPTED' for x in oldfacts['acceptances']),{'held':oldfacts['held'],'acceptances':oldfacts['acceptances']})
        mirror=private/'original-artifacts-readonly';mirror.mkdir(mode=0o700)
        for rel in plan['original_artifacts']:
            target=mirror/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((source_root/rel).read_bytes());target.chmod(0o444)
        assert originals(mirror)==plan['original_artifacts']
        dump=private/'original.postgres.dump';pglog=private/'pg-tools.log'
        with pglog.open('xb') as log:
            os.chmod(pglog,0o600)
            q=subprocess.run([str(PG/'pg_dump'),'--format=custom','--no-owner','--no-privileges','--file',str(dump)],env=pg_env(oldenv['DATABASE_URL']),stdout=log,stderr=log,timeout=60);assert q.returncode==0,'read-only pg_dump failed; private diagnostics preserved'
        dump.chmod(0o600);database='forgeflow_release_'+uuid.uuid4().hex[:16];newurl=create_database(oldenv,database,private);report['database_name']=database
        with pglog.open('ab') as log:q=subprocess.run([str(PG/'pg_restore'),'--no-owner','--no-privileges','--exit-on-error','--dbname',database,str(dump)],env=pg_env(newurl),stdout=log,stderr=log,timeout=60)
        assert q.returncode==0,'new private DB restore failed; original untouched';report['pg_dump_sha256']=sha(dump)
        (private/'state').mkdir(mode=0o700);diagnostics=private/'diagnostics';diagnostics.mkdir(mode=0o700)
        env={'DATABASE_URL':newurl,'FORGEFLOW_BIND':'127.0.0.1:8900','FORGEFLOW_DATA_ROOT':str(private/'state'),'FORGEFLOW_CONSOLE_DIR':str(args.console_dir.resolve()),'FORGEFLOW_OWNER_TOKEN':secrets.token_hex(32),'FORGEFLOW_WORKER_TOKEN':secrets.token_hex(32),'RUST_LOG':'info'};secure_save(private/'runtime-env.json',env)
        client=Client('http://127.0.0.1:8900',env['FORGEFLOW_OWNER_TOKEN'],args.output,diagnostics)
        apilog=os.fdopen(os.open(private/'api.log',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb');api=subprocess.Popen([binary['path']],env={'PATH':'/usr/bin:/bin',**env},stdout=apilog,stderr=subprocess.STDOUT)
        def healthy():
            assert api.poll() is None
            try:return client.request('GET','/me')[0]==200
            except OSError:return False
        wait(healthy,'private clone API readiness',30)
        clone=observe(newurl,'clone-before');check('real_dump_clone_preserves_history_no_reexecution',clone['attempts']==oldfacts['attempts'] and clone['models']==oldfacts['models'] and clone['native_models']==oldfacts['native_models'] and clone['acceptances']==oldfacts['acceptances'] and clone['baselines']==oldfacts['baselines'],{'dump_sha256':sha(dump),'two_accepted_baselines':True})
        project=client.api('GET',f"/projects/{h['project_id']}");assert project['paused'] and not project['archived']
        ui={'url':client.base_url,'owner_token':env['FORGEFLOW_OWNER_TOKEN'],'project_id':h['project_id'],'milestone_id':plan['milestone_id'],'main_sha':plan['main_sha'],'chrome':str(CHROME),'output':str(args.output),'report_path':str(private/'browser-report.json'),'download_path':str(private/'downloaded-bundle.tar'),'export_ready_path':str(private/'browser-export-ready.json'),'clean_verified_path':str(private/'clean-verified.json')};secure_save(private/'browser-input.json',ui)
        blog=os.fdopen(os.open(private/'browser.log',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb');browser=subprocess.Popen([str(NODE),str(ROOT/'verification/release_browser_point.mjs'),str(private/'browser-input.json')],stdout=blog,stderr=subprocess.STDOUT)
        def export_ready():
            if (private/'browser-export-ready.json').exists():return load(private/'browser-export-ready.json')
            if browser.poll() is not None:
                if (private/'browser-report.json').exists():
                    failed=load(private/'browser-report.json');save(args.output/'browser-report.json',failed)
                    raise RuntimeError('actual browser failed before export: '+json.dumps(failed['errors'],ensure_ascii=False))
                raise RuntimeError('actual browser failed before export; private report retained')
            return None
        ready=wait(export_ready,'actual GUI draft candidate accepted export bundle download',120)
        accepted=ready['accepted']['release'];export=ready['exported']['export'];bundle=private/'downloaded-bundle.tar'
        clean=private/'independent-clean-readback';clean.mkdir(mode=0o700)
        members=safe_extract(bundle,clean)
        manifest=load(clean/'manifest.json');digest=sha(clean/'manifest.json')
        check('downloaded_real_bundle_and_frozen_manifest_hash',sha(bundle)==export['bundle']['sha256'] and bundle.stat().st_size==export['bundle_bytes'] and digest==accepted['manifest_sha256']==export['manifest_sha256'] and manifest==accepted['manifest'] and manifest['main_sha']==plan['main_sha'] and manifest['export_scope']=='MANIFEST_SOURCE_AND_BOUND_ARTIFACTS_BUNDLE',{'bundle_sha256':sha(bundle),'bundle_bytes':bundle.stat().st_size,'manifest_sha256':digest,'tar_members':members})
        identities=[]
        for file in manifest['files']:
            target=clean/'artifacts'/file['artifact_id'];assert target.is_file() and sha(target)==file['sha256'] and target.stat().st_size==file['bytes'];identities.append({'artifact_id':file['artifact_id'],'sha256':sha(target),'bytes':target.stat().st_size})
        assert identities and (clean/'INSTALLATION.txt').read_bytes()==manifest['installation'].encode()
        source=clean/'source.tar';source_dir=clean/'source';source_dir.mkdir(mode=0o700);safe_extract(source,source_dir)
        source_commit=subprocess.run(['git','get-tar-commit-id'],input=source.read_bytes(),capture_output=True,timeout=10,check=True).stdout.decode().strip();assert source_commit==manifest['main_sha'] and sha(source)==export['source_archive_sha256']
        entries=subprocess.run(['git','-C',h['canonical_repository'],'ls-tree','-rz',manifest['main_sha']],capture_output=True,timeout=10,check=True).stdout.split(b'\0');source_files=[]
        for entry in entries:
            if not entry:continue
            metadata,name=entry.split(b'\t',1);mode,kind,oid=metadata.split();assert kind==b'blob' and mode in (b'100644',b'100755')
            rel=name.decode();data=(source_dir/rel).read_bytes();blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest();assert blob==oid.decode();source_files.append({'path':rel,'sha256':hashlib.sha256(data).hexdigest(),'git_blob_oid':blob})
        check('independent_clean_bundle_artifacts_source_and_installation_verified',bool(source_files),{'directory':str(clean),'registered_files':identities,'source_main_sha':source_commit,'source_files':source_files,'only_downloaded_bundle_used':True})
        secure_save(private/'clean-verified.json',{'passed':True,'bundle_sha256':sha(bundle),'manifest_sha256':digest,'main_sha':source_commit})
        browser.wait(timeout=75)
        br=load(private/'browser-report.json');save(args.output/'browser-report.json',br);check('actual_Release_GUI_lifecycle_download_history',browser.returncode==0 and br['status']=='PASS_ACTUAL_RELEASE_GUI_CHAIN' and br['browser_closed'],br)
        reopened=br['reopened']
        registered=next(x for x in observe(newurl,'export-final')['artifact_rows'] if x['artifact_id']==export['bundle']['artifact_id']);check('export_written_only_new_private_namespace',Path(registered['path']).is_relative_to(private/'state/artifacts') and sha(registered['path'])==sha(bundle),{'registered_export':registered})
        final=observe(newurl,'clone-final');afterold=observe(oldenv['DATABASE_URL'],'original-readonly-after')
        audit={x['kind'] for x in final['events']};check('release_archive_reopen_audit_events',all(x in audit for x in ['release.candidate.created','release.accepted','export.completed','project.archived','project.reopened']),{'events':sorted(audit)})
        check('archive_then_fresh_phase_paused_history_preserved',br['archived']['project']['archived'] and not reopened['project']['archived'] and reopened['project']['paused'] and reopened['phase']['phase_id']!=br['draft']['phase']['phase_id'] and reopened['phase']['ordinal']==br['draft']['phase']['ordinal']+1 and reopened['phase']['previous_release_id']==accepted['release_id'] and final['acceptances']==clone['acceptances'] and final['baselines']==clone['baselines'],reopened)
        report['new_model_calls']=0;check('no_original_mutation_no_model_or_attempt_replay',afterold==oldfacts and originals(source_root)==plan['original_artifacts'] and git_main(h['canonical_repository'])==plan['main_sha'] and final['models']==clone['models'] and final['native_models']==clone['native_models'] and final['attempts']==clone['attempts'] and final['held']==final['active']==final['valid_leases']==0,{'historical_models_retained':len(final['models']),'new_models':0,'original_DB_unchanged':True})
    except BaseException as e:report['errors'].append({'type':type(e).__name__,'message':str(e),'interrupted':isinstance(e,(KeyboardInterrupt,SystemExit))})
    finally:
        signal.alarm(0);report['shutdown']={}
        for label,process in [('browser',browser),('api',api)]:
            if process is None:continue
            try:
                if process.poll() is None:process.terminate();process.wait(timeout=25)
            except BaseException as e:report['errors'].append({'cleanup':label,'type':type(e).__name__})
            report['shutdown'][label]={'pid':process.pid,'exit_code':process.poll(),'confirmed':process.poll() is not None}
        if apilog:apilog.close()
        if blog:blog.close()
        if env:
            try:
                q=database_command(env['DATABASE_URL'],"SELECT json_build_object('other_database_connections',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()));");assert q.returncode==0;report['database_closure']=json.loads(q.stdout);assert report['database_closure']['other_database_connections']==0
            except BaseException as e:report['errors'].append({'cleanup':'private DB connections','type':type(e).__name__})
        with socket.socket() as sk:report['port_closed']=sk.connect_ex(('127.0.0.1',8900))!=0
        report['main_after']=main_identity();report['main_before']=before;report['private_DB_retained_for_evidence']=bool(env);report['cleanup_confirmed']=report['port_closed'] and report['main_after']==before and all(x['confirmed'] for x in report['shutdown'].values())
        report['status']='PASS_ACTUAL_RELEASE_GUI_BUSINESS_CHAIN' if not report['errors'] and report['cleanup_confirmed'] and all(x['status']=='PASS' for x in report['checks']) else 'FAIL';save(args.output/'report.json',report);signal.signal(signal.SIGALRM,oldalarm);signal.signal(signal.SIGTERM,oldterm)
    print(json.dumps({'status':report['status'],'checks':len(report['checks']),'report':str(args.output/'report.json')}));return 0 if report['status'].startswith('PASS') else 1

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--run',action='store_true');p.add_argument('--plan-sha256');p.add_argument('--go',type=Path);p.add_argument('--build-receipt',type=Path);p.add_argument('--console-dir',type=Path);args=p.parse_args();args.output=args.output.resolve();assert args.output.is_relative_to(ROOT/'evidence/release-business-chain-r1')
    if args.run:
        assert args.plan_sha256 and args.go and args.build_receipt and args.console_dir;return execute(args)
    return prepare(args)
if __name__=='__main__':raise SystemExit(main())

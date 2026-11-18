#!/usr/bin/env python3
"""One bounded, read-only GUI continuation of the retained contract execution."""
import argparse, asyncio, hashlib, json, os, signal, socket, subprocess, time, urllib.request, urllib.parse
from pathlib import Path
import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg import sql
from playwright.async_api import async_playwright
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'evidence/public-contract-gui-readback-r1'
ORIGINAL=Path('/home/chenyoujian/.cache/forgeflow-public-contract-mjhfp8_x')
PRIVATE=Path('/home/chenyoujian/.cache/forgeflow-contract-gui-20261010-r1')
CLONE='forgeflow_contract_gui_20261010_r1'
PROJECT='public-contract-2f5bd191a4d5468c'
ATTEMPT='42fee148-a9f0-4a80-86e0-4deb25b89eb2'
MAIN='56ad74d821cb0b66cf6e51cffc71dd9b94bf5db7'
SERVER=Path('/home/chenyoujian/.local/share/forgeflow/releases/decision-core-r1/bin/forgeflow-server')
CONSOLE=Path('/home/chenyoujian/.local/share/forgeflow/releases/decision-core-r1/console')
PG=Path('/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/postgresql/16/bin')
CHROME='/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome'
PORT=8899
TABLES=['projects','documents','tasks','attempts','leases','resource_allocations','contract_versions','evidence_receipts','merge_intents']
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,default=str,separators=(',',':')).encode()).hexdigest()
def filehash(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(name,value):
 p=OUT/name
 p.write_text(json.dumps(value,ensure_ascii=False,indent=2,default=str)+'\n')
def pg_env(url):
 result=os.environ.copy()
 names={'host':'PGHOST','port':'PGPORT','user':'PGUSER','password':'PGPASSWORD','dbname':'PGDATABASE'}
 for k,v in conninfo_to_dict(url).items():
  if k in names:result[names[k]]=v
 return result
def snapshot(url):
 result={}
 with psycopg.connect(url,autocommit=True,options='-c default_transaction_read_only=on') as db:
  with db.cursor() as q:
   for table in TABLES:
    q.execute(sql.SQL('SELECT to_jsonb(t) FROM {} t').format(sql.Identifier(table)))
    rows=sorted((json.dumps(x[0],sort_keys=True,default=str,separators=(',',':')) for x in q.fetchall()))
    result[table]={'rows':len(rows),'sha256':digest(rows)}
   q.execute('SELECT data FROM contract_versions WHERE project_id=%s AND contract_id=%s AND version=1',(PROJECT,'typed-index'));result['contract']=q.fetchone()[0]
   q.execute('SELECT data,envelope,state,generation,task_id FROM attempts WHERE attempt_id=%s',(ATTEMPT,));row=q.fetchone();assert row,'exact historical Attempt missing';result['attempt']={'data':row[0],'envelope':row[1],'state':row[2],'generation':row[3],'task_id':row[4]}
   q.execute('SELECT data FROM evidence_receipts WHERE attempt_id=%s',(ATTEMPT,));result['receipts']=[x[0] for x in q.fetchall()]
   q.execute('SELECT data,paused FROM projects WHERE project_id=%s',(PROJECT,));r=q.fetchone();result['project']=r[0];result['project_paused']=r[1]
   q.execute('SELECT version FROM _sqlx_migrations ORDER BY version');result['migrations']=[x[0] for x in q.fetchall()]
 return result
def safe(v):
 if isinstance(v,dict):return {k:('[REDACTED]' if any(x in k.lower() for x in ['password','credential','owner_token','worker_token']) else safe(x)) for k,x in v.items()}
 if isinstance(v,list):return [safe(x) for x in v]
 return v
def main_pid():
 r=subprocess.run(['systemctl','--user','show','forgeflow-control.service','--property=MainPID','--value'],capture_output=True,text=True,timeout=5)
 return r.stdout.strip()
def get(path,token):
 req=urllib.request.Request(f'http://127.0.0.1:{PORT}'+path,headers={'Authorization':'Bearer '+token})
 with urllib.request.urlopen(req,timeout=10) as response:return json.load(response)
def unwrap(d):
 if isinstance(d,dict) and 'data' in d:return d['data']
 return d
async def browser(token,source,report,resume_gui=False):
 observed=[];errors=[];mutations=[]
 async with async_playwright() as p:
  b=await p.chromium.launch(executable_path=CHROME,headless=True,args=['--no-proxy-server'])
  try:
   ctx=await b.new_context(viewport={'width':1440,'height':1000})
   await ctx.add_init_script("sessionStorage.setItem('forgeflow.owner-token',"+json.dumps(token)+");localStorage.setItem('forgeflow.project',"+json.dumps(PROJECT)+");")
   async def readonly(route):
    req=route.request
    if req.method not in ['GET','HEAD','OPTIONS']:
     mutations.append({'method':req.method,'path':req.url.split('127.0.0.1:'+str(PORT))[-1]});await route.abort();return
    await route.continue_()
   await ctx.route('**/api/**',readonly)
   page=await ctx.new_page();page.on('pageerror',lambda e:errors.append(str(e)))
   page.on('response',lambda r:observed.append({'url':r.url.split('127.0.0.1:'+str(PORT))[-1],'status':r.status,'method':r.request.method}) if '/api/' in r.url else None)
   if not resume_gui:
    await page.goto(f'http://127.0.0.1:{PORT}/projects/{PROJECT}/contracts',wait_until='domcontentloaded',timeout=25000)
    row=page.get_by_role('row').filter(has_text='typed-index');await row.wait_for(timeout=20000);await row.click()
    await page.get_by_text('消费者兼容矩阵',exact=True).wait_for(timeout=10000)
    text=await page.locator('body').inner_text()
    for value in ['typed-index',source['contract']['spec_sha256'],source['contract']['source_sha256'],'t00000','t00001']:
     assert value in text,'missing rendered contract fact: '+value
    assert 'FROZEN' in text or '已冻结' in text or '冻结' in text
    assert 'PASS' in text or '通过' in text
    await page.screenshot(path=str(OUT/'desktop-contract.png'),full_page=True)
    report['checks'].append({'name':'same_frozen_contract_identity_and_consumer_matrix_rendered','status':'PASS'})
    await page.goto(f'http://127.0.0.1:{PORT}/projects/{PROJECT}/evidence',wait_until='domcontentloaded',timeout=25000)
    row=page.get_by_role('row').filter(has_text=ATTEMPT);await row.first.wait_for(timeout=20000)
    receipts=source['receipts'];assert receipts,'ordinary consumer receipts missing'
    receipt_id=receipts[-1]['receipt_id'];chosen=page.get_by_role('row').filter(has_text=receipt_id)
    await chosen.first.click();await page.get_by_text('输入指纹',exact=True).wait_for(timeout=10000)
    body=await page.locator('body').inner_text();assert ATTEMPT in body and receipt_id in body
    report['checks'].append({'name':'same_ordinary_consumer_receipt_and_attempt_rendered','status':'PASS','receipt_id':receipt_id})
    await page.screenshot(path=str(OUT/'consumer-evidence.png'),full_page=True)
   await page.goto(f'http://127.0.0.1:{PORT}/runs/{ATTEMPT}?project={PROJECT}',wait_until='domcontentloaded',timeout=25000)
   await page.get_by_text(ATTEMPT,exact=False).first.wait_for(timeout=20000)
   await page.get_by_role('button',name='完整身份与结果',exact=True).wait_for(timeout=20000)
   await page.get_by_role('button',name='完整身份与结果',exact=True).click()
   await page.get_by_text(MAIN,exact=False).first.wait_for(timeout=15000)
   body=await page.locator('body').inner_text();assert 'SUCCEEDED' in body and MAIN in body and ATTEMPT in body
   await page.screenshot(path=str(OUT/'consumer-result.png'),full_page=True)
   report['checks'].append({'name':'same_successful_attempt_and_integrated_main_rendered','status':'PASS','attempt_id':ATTEMPT,'main':MAIN,'mechanism':'existing complete identity/result tab; completed merges not in pending queue'})
   assert not mutations,'browser attempted a mutation';assert not errors,errors
   save('browser-report.json',{'status':'PASS','api_responses':observed,'attempted_mutations':mutations,'errors':errors,'project_id':PROJECT,'attempt_id':ATTEMPT,'screenshots':['desktop-contract.png','consumer-evidence.png','consumer-result.png']})
  finally:await b.close()
def run():
 parser=argparse.ArgumentParser();parser.add_argument('--go',required=True);parser.add_argument('--resume-clone',action='store_true');parser.add_argument('--plan',default=str(OUT/'plan.json'));parser.add_argument('--resume-gui',action='store_true');cli_args=parser.parse_args()
 go=json.loads(Path(cli_args.go).read_text());plan=json.loads(Path(cli_args.plan).read_text());assert go['decision']=='GO' and go['plan_sha256']==filehash(cli_args.plan),'exact Root GO missing';assert go['script_sha256']==filehash(__file__)==plan['script_sha256'],'script drift from exact GO'
 start=time.monotonic();deadline=start+360;signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('finite deadline')));signal.alarm(360)
 e=json.loads((ORIGINAL/'runtime-env.json').read_text());url=e['DATABASE_URL'];source=snapshot(url);assert source['project_paused'] and source['attempt']['state']=='SUCCEEDED';assert source['contract']['frozen']
 repo=Path(source['project']['root_path']);assert subprocess.check_output(['git','--git-dir',str(repo),'rev-parse','refs/heads/main'],text=True,timeout=10).strip()==MAIN
 assert filehash(SERVER)==plan['server_sha256'];assert cli_args.resume_clone or not PRIVATE.exists(),'dedicated private root already exists';PRIVATE.mkdir(mode=0o700,exist_ok=cli_args.resume_clone)
 pid_before=main_pid();server=None;report={'schema_version':'forgeflow.public-contract-gui-readback.v1','status':'RUNNING','project_id':PROJECT,'attempt_id':ATTEMPT,'source_identity':plan['source_identity'],'frontend_tree_sha256':plan['frontend_tree_sha256'],'historical_execution_reports':plan['historical_execution_reports'],'models':0,'Workers':0,'checks':[],'original_snapshot':safe(source),'limitations':['Historical actual execution + current pinned read-only GUI continuation; no current author qualification.']};clone_url=None
 if cli_args.resume_gui:
  prior_path=OUT/'startup-failure-r3.json';prior=json.loads(prior_path.read_text());report['inherited_gui_checks']={'path':str(prior_path.relative_to(ROOT)),'sha256':filehash(prior_path),'original_status':prior['status'],'checks':[x for x in prior['checks'] if x['name'] in ['same_frozen_contract_identity_and_consumer_matrix_rendered','same_ordinary_consumer_receipt_and_attempt_rendered']]};assert len(report['inherited_gui_checks']['checks'])==2;report['checks']+=report['inherited_gui_checks']['checks']
 try:
  parsed=urllib.parse.urlsplit(url);assert parsed.scheme in ['postgresql','postgres'];clone_url=urllib.parse.urlunsplit(parsed._replace(path='/'+urllib.parse.quote(CLONE,safe='')))
  if not cli_args.resume_clone:
   with psycopg.connect(url,autocommit=True) as db:
    with db.cursor() as q:q.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(CLONE)))
   dump=PRIVATE/'history.dump'
   with dump.open('wb') as f:subprocess.run([str(PG/'pg_dump'),'-Fc','--no-owner','--no-privileges'],env=pg_env(url),stdout=f,stderr=subprocess.PIPE,check=True,timeout=min(100,deadline-time.monotonic()))
   subprocess.run([str(PG/'pg_restore'),'--no-owner','--no-privileges','-d',CLONE,str(dump)],env=pg_env(clone_url),capture_output=True,check=True,timeout=min(100,deadline-time.monotonic()))
  clone_start=snapshot(clone_url);assert all(clone_start[x]==source[x] for x in TABLES+['contract','attempt','receipts','project','project_paused']),'restored original business history mismatch';report['clone_start_migrations']=clone_start['migrations']
  report['checks'].append({'name':'same_retained_history_clone_reused_without_mutation' if cli_args.resume_clone else 'exact_retained_DB_cloned_without_history_changes','status':'PASS','new_database_preparation':not cli_args.resume_clone})
  data=PRIVATE/'state';data.mkdir(exist_ok=True);launch_argv=['/usr/bin/bwrap','--ro-bind','/','/','--bind',str(PRIVATE),str(PRIVATE),'--proc','/proc','--dev','/dev']
  for child in (ORIGINAL/'state').iterdir():
   if child.is_dir():
    target=data/child.name;target.mkdir(exist_ok=True);launch_argv += ['--ro-bind',str(child),str(target)]
  env={k:v for k,v in os.environ.items() if not k.startswith('FORGEFLOW_')};env.update(e);env.update({'DATABASE_URL':clone_url,'FORGEFLOW_BIND':f'127.0.0.1:{PORT}','FORGEFLOW_DATA_ROOT':str(data),'FORGEFLOW_CONSOLE_DIR':str(CONSOLE),'FORGEFLOW_EVENT_RETENTION_SECONDS':'315360000','RUST_LOG':'warn'})
  with socket.socket() as s:s.bind(('127.0.0.1',PORT))
  log=(PRIVATE/'api.log').open('wb');server=subprocess.Popen(launch_argv+['--',str(SERVER)],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);report['api_pid']=server.pid;signal.alarm(min(180,max(1,int(deadline-time.monotonic()))))
  for _ in range(120):
   if server.poll() is not None:raise RuntimeError('private API exited; see private log')
   try:get('/healthz',e['FORGEFLOW_OWNER_TOKEN']);break
   except Exception:time.sleep(.25)
  else:raise TimeoutError('private API startup')
  reads={}
  for path in [f'/api/v1/projects/{PROJECT}/contract-versions',f'/api/v1/attempts/{ATTEMPT}',f'/api/v1/projects/{PROJECT}/evidence',f'/api/v1/projects/{PROJECT}/integration-queue']:
   reads[path]=safe(get(path,e['FORGEFLOW_OWNER_TOKEN']))
  save('http-readbacks.json',reads)
  asyncio.run(browser(e['FORGEFLOW_OWNER_TOKEN'],source,report,cli_args.resume_gui))
  report['clone_after']=safe(snapshot(clone_url));report['checks'].append({'name':'no_new_worker_model_or_original_business_authority_change','status':'PASS' if all(report['clone_after'][x]==source[x] for x in TABLES) else 'FAIL'})
  assert all(report['clone_after'][x]==source[x] for x in TABLES),'cloned business authority changed'
  report['status']='PASS_ACTUAL_SAME_CONTRACT_GUI_DB_CHAIN'
 except Exception as ex:
  report['status']='FAIL';report['error']={'class':type(ex).__name__,'message':str(ex)[:600]}
 finally:
  signal.alarm(0)
  cleanup={'api':None,'source_DB_unchanged':False,'main_pid_before':pid_before,'main_pid_after':main_pid(),'new_worker_or_model_processes':0,'clone_database_retained':CLONE}
  if server:
   if server.poll() is None:
    os.killpg(server.pid,signal.SIGTERM)
    try:server.wait(timeout=12)
    except subprocess.TimeoutExpired:os.killpg(server.pid,signal.SIGKILL);server.wait(timeout=5)
   cleanup['api']={'pid':server.pid,'exit_code':server.returncode,'confirmed':True}
  cleanup['source_DB_unchanged']=snapshot(url)==source;cleanup['main_unchanged']=cleanup['main_pid_before']==cleanup['main_pid_after'];assert cleanup['source_DB_unchanged'] and cleanup['main_unchanged']
  with socket.socket() as s:cleanup['owned_port_closed']=s.connect_ex(('127.0.0.1',PORT))!=0
  cleanup['elapsed_seconds']=time.monotonic()-start;save('cleanup.json',cleanup);report['cleanup']=cleanup;save('report.json',safe(report));print(json.dumps({'status':report['status'],'checks':len(report['checks']),'elapsed_seconds':cleanup['elapsed_seconds']}))
 if report['status']!='PASS_ACTUAL_SAME_CONTRACT_GUI_DB_CHAIN':raise SystemExit(1)
if __name__=='__main__':run()

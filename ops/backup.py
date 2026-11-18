#!/usr/bin/env python3
"""Stop-dispatch consistent backup. Refuses unsettled attempts; never implies pg_dump makes files consistent."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, urllib.request, urllib.parse, uuid
from datetime import datetime, timezone

def progress(path, phase, **details):
    if path is None:return
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    with temporary.open('x',encoding='utf-8') as file:
        temporary.chmod(0o600)
        json.dump(dict(phase=phase,observed_at=datetime.now(timezone.utc).isoformat(),**details),file)
        file.flush();os.fsync(file.fileno())
    os.replace(temporary,path)

def require_quiescence():
    readiness=api('/backup-readiness')
    if readiness.get('ready') is not True:
        raise SystemExit('Backup blocked by unsettled attempts, model custody, resources, integration or unavailable repositories. Review /backup-readiness; nothing is force-released.')
    return readiness

def pg_environment(url):
    parsed=urllib.parse.urlsplit(url);options=urllib.parse.parse_qs(parsed.query);env=os.environ.copy()
    env.update(PGHOST=options.get('host',[parsed.hostname or '127.0.0.1'])[0],PGPORT=options.get('port',[str(parsed.port or 5432)])[0],PGUSER=options.get('user',[urllib.parse.unquote(parsed.username or '')])[0],PGPASSWORD=options.get('password',[urllib.parse.unquote(parsed.password or '')])[0],PGDATABASE=urllib.parse.unquote(parsed.path.lstrip('/')))
    for key,target in [('sslmode','PGSSLMODE'),('sslrootcert','PGSSLROOTCERT'),('options','PGOPTIONS')]:
        if key in options:env[target]=options[key][0]
    return env

def envelope(path,body=None,method=None):
    req=urllib.request.Request(os.environ.get('FORGEFLOW_API_URL','http://127.0.0.1:8787')+'/api/v1'+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Authorization':'Bearer '+os.environ['FORGEFLOW_OWNER_TOKEN'],'Content-Type':'application/json','Idempotency-Key':str(uuid.uuid4())})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=30) as response:return json.load(response)

def api(path,body=None,method=None):return envelope(path,body,method)['data']

def collect(path):
    items=[];cursor=None;seen=set();version=None
    while True:
        query=path+('?' if '?' not in path else '&')+'limit=500'+('' if cursor is None else '&cursor='+urllib.parse.quote(cursor,safe=''))
        page=envelope(query);current=page.get('read_model_version')
        if version is not None and current is not None and current!=version:raise SystemExit('Authority changed during pagination; retry during quiescence.')
        version=current if current is not None else version;items.extend(page['data']);cursor=page.get('next_cursor')
        if cursor is None:return items
        if cursor in seen:raise SystemExit('Cursor repeated; backup rejected.')
        seen.add(cursor)

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda:file.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def fingerprints(root,exclude_backups=False):
    return {str(p.relative_to(root)):('SYMLINK:'+os.readlink(p) if p.is_symlink() else digest(p)) for p in sorted(root.rglob('*')) if (p.is_file() or p.is_symlink()) and not (exclude_backups and p.relative_to(root).parts[0]=='backups')}

def git(repository,*args):
    result=subprocess.run(['git','--no-replace-objects','-C',str(repository),*args],capture_output=True,text=True,timeout=30)
    if result.returncode:raise SystemExit('Repository identity lookup failed; no valid backup issued.')
    return result.stdout.strip()

def watermarks(projects):
    return {p['project_id']:api('/projects/'+p['project_id']+'/event-cursor')['cursor'] for p in projects}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--destination',required=True,type=pathlib.Path);parser.add_argument('--data-root',required=True,type=pathlib.Path);parser.add_argument('--repository',action='append',default=[],type=pathlib.Path);parser.add_argument('--progress-file',type=pathlib.Path);args=parser.parse_args()
    args.data_root=args.data_root.resolve(strict=True)
    if os.path.lexists(args.destination):raise SystemExit('Backup destination already exists; choose a fresh directory.')
    if args.destination.resolve().is_relative_to(args.data_root):raise SystemExit('Backup destination must be outside data root for consistency validation.')
    if args.progress_file and (args.progress_file.resolve().is_relative_to(args.data_root) or args.progress_file.resolve().is_relative_to(args.destination.resolve())):raise SystemExit('Progress file must be outside authoritative data and the snapshot.')
    info=api('/system/info')
    if pathlib.Path(info.get('data_root','')).resolve(strict=True)!=args.data_root:raise SystemExit('Configured API belongs to another data root; no projects paused and no backup issued.')
    progress(args.progress_file,'CHECKING_CUSTODY')
    require_quiescence()
    projects=collect('/projects');paused=[]
    progress(args.progress_file,'PAUSING_DISPATCH',project_count=len(projects))
    for project in projects:
        if not project['paused']:
            updated=dict(project,paused=True);api('/projects/'+project['project_id'],{'project':updated,'expected_revision':project['revision']},'PATCH');paused.append(project['project_id'])
    projects=collect('/projects')
    repositories=[repository.resolve(strict=True) for repository in args.repository]
    if len(set(repositories))!=len(repositories):raise SystemExit('Duplicate repository paths.')
    for project in projects:
        active=[a for a in collect('/projects/'+project['project_id']+'/attempts') if a['state'] not in ('SUCCEEDED','FAILED','CANCELLED')]
        if active:raise SystemExit('Dispatch paused; unsettled attempts remain. Wait or cancel and confirm stop, then rerun backup. IDs: '+','.join(a['attempt_id'] for a in active))
        if project['authority_mode']=='MANAGED' and pathlib.Path(project['root_path']).resolve(strict=True) not in repositories:raise SystemExit('Every managed project repository must be explicitly included.')
    require_quiescence()
    progress(args.progress_file,'READING_INVENTORY',repository_count=len(repositories))
    before_watermarks=watermarks(projects)
    before_policies=api('/resources')
    before_files=fingerprints(args.data_root,True)
    before_repositories={str(repository):fingerprints(repository) for repository in repositories}
    before_refs={str(repository):git(repository,'show-ref') for repository in repositories}
    args.destination.mkdir(parents=True,mode=0o700)
    progress(args.progress_file,'EXPORTING_DATABASE')
    dump=subprocess.run(['pg_dump','--format=custom','--file',str(args.destination/'postgres.dump')],env=pg_environment(os.environ['DATABASE_URL']),capture_output=True,timeout=120)
    if dump.returncode:raise SystemExit('pg_dump failed; no valid manifest issued. Check private database configuration.')
    progress(args.progress_file,'COPYING_DATA',file_count=len(before_files))
    shutil.copytree(args.data_root,args.destination/'data',symlinks=True,ignore=lambda directory,names:['backups'] if pathlib.Path(directory)==args.data_root and 'backups' in names else [])
    repos=[]
    for i,repository in enumerate(repositories):
        progress(args.progress_file,'COPYING_REPOSITORIES',completed=i,total=len(repositories))
        relative=repository.relative_to(args.data_root) if repository.is_relative_to(args.data_root) else None
        # Reuse the already copied data snapshot; never hard-link mutable source files.
        if relative is not None and relative.parts and relative.parts[0]!='backups':
            target=args.destination/'data'/relative
        else:
            target=args.destination/'repositories'/str(i);shutil.copytree(repository,target,symlinks=True)
        if fingerprints(target)!=before_repositories[str(repository)] or git(target,'show-ref')!=before_refs[str(repository)]:raise SystemExit('Copied repository differs from source; backup rejected.')
        repos.append({'original':str(repository),'snapshot':str(target.relative_to(args.destination)),'main_sha':git(target,'rev-parse','refs/heads/main'),'git_refs':before_refs[str(repository)],'project_ids':[p['project_id'] for p in projects if pathlib.Path(p['root_path']).resolve(strict=True)==repository]})
    progress(args.progress_file,'CHECKING_QUIESCENCE')
    require_quiescence()
    after_watermarks=watermarks(projects)
    after_files=fingerprints(args.data_root,True)
    after_repositories={str(repository):fingerprints(repository) for repository in repositories}
    if {p['project_id'] for p in projects}!={p['project_id'] for p in collect('/projects')} or before_watermarks!=after_watermarks or before_policies!=api('/resources') or before_files!=after_files or before_repositories!=after_repositories or before_refs!={str(repository):git(repository,'show-ref') for repository in repositories}:
        (args.destination/'INCONSISTENT.json').write_text(json.dumps({'before':before_watermarks,'after':after_watermarks,'status':'REJECTED_CONCURRENT_WRITE'},indent=2))
        raise SystemExit('Concurrent authoritative or file writes detected; backup REJECTED. Dispatch remains paused; choose a fresh destination and retry during quiescence.')
    copied_files=fingerprints(args.destination/'data')
    if copied_files!=before_files:raise SystemExit('Copied data differs from quiescent source; backup rejected.')
    progress(args.progress_file,'SEALING_MANIFEST')
    hashes={str(p.relative_to(args.destination)):digest(p) for p in sorted(args.destination.rglob('*')) if p.is_file() and not p.is_symlink()}
    links={str(p.relative_to(args.destination)):os.readlink(p) for p in sorted(args.destination.rglob('*')) if p.is_symlink()}
    manifest={'schema_version':'forgeflow.backup.v1','data_root_original':str(args.data_root.resolve()),'projects':[{key:p[key] for key in ('project_id','root_path','authority_mode','paused','revision')} for p in projects],'project_event_watermarks':after_watermarks,'file_quiescence_checked':True,'project_revisions':{p['project_id']:api('/projects/'+p['project_id'])['revision'] for p in projects},'paused_projects':paused,'repositories':repos,'sha256':hashes,'symlinks':links,'dispatch_paused':True,'unsettled_attempts':0}
    manifest_path=args.destination/'manifest.json'
    with manifest_path.open('x',encoding='utf-8') as file:
        manifest_path.chmod(0o600);json.dump(manifest,file,indent=2);file.flush();os.fsync(file.fileno())
    progress(args.progress_file,'SNAPSHOT_VERIFIED',file_count=len(hashes),dispatch_paused=True)
    print(json.dumps({'backup':str(args.destination),'files':len(hashes),'dispatch_paused':True,'instruction':'Validate backup; explicitly resume projects after backup review.'}))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Restore into fresh directories and an explicitly empty isolated PostgreSQL database."""
import argparse,hashlib,json,pathlib,shutil,subprocess,os,tarfile,re,gzip
from backup import fingerprints,pg_environment

def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()

MAX_MANIFEST_BYTES=64*1024*1024
MAX_MEMBERS=500000
DEFAULT_MAX_UNPACKED=32*1024**3

class BoundedTarInfo(tarfile.TarInfo):
 @classmethod
 def frombuf(cls,buf,encoding,errors):
  member=super().frombuf(buf,encoding,errors)
  if member.type in (tarfile.XHDTYPE,tarfile.XGLTYPE,tarfile.GNUTYPE_LONGNAME,tarfile.GNUTYPE_LONGLINK) and member.size>1024*1024:raise SystemExit('Archive extended metadata exceeds the supported limit.')
  return member

class BoundedArchiveReader:
 def __init__(self,source,limit):self.source=source;self.limit=limit;self.total=0
 def read(self,size):
  data=self.source.read(min(size,65536));self.total+=len(data)
  if self.total>self.limit:raise SystemExit('Archive decompressed stream exceeds the configured limit.')
  return data

def safe_relative(relative,archive=False):
 if archive:
  while relative.startswith('./'):relative=relative[2:]
  relative=relative.rstrip('/')
 if archive and relative in ('','.'):return ''
 path=pathlib.PurePosixPath(relative)
 if not relative or path.is_absolute() or '..' in path.parts or str(path)!=relative or '\\' in relative or '\x00' in relative:raise SystemExit('Unsafe backup member path.')
 return relative

def validate_manifest(m):
 if m.get('schema_version')!='forgeflow.backup.v1' or m.get('unsettled_attempts')!=0 or m.get('dispatch_paused') is not True or m.get('file_quiescence_checked') is not True:raise SystemExit('Unsupported, unverified or unsettled backup.')
 hashes=m.get('sha256');links=m.get('symlinks',{})
 if not isinstance(hashes,dict) or not isinstance(links,dict) or len(hashes)+len(links)>MAX_MEMBERS:raise SystemExit('Invalid or oversized backup inventory.')
 if set(hashes)&set(links) or 'manifest.json' in hashes or 'manifest.json' in links:raise SystemExit('Ambiguous backup inventory.')
 for relative,value in hashes.items():
  safe_relative(relative)
  if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value):raise SystemExit('Invalid backup file digest.')
 for relative,value in links.items():
  safe_relative(relative)
  if not isinstance(value,str) or '\x00' in value:raise SystemExit('Invalid backup symlink.')
 for relative in list(hashes)+list(links):
  if any(str(parent) in links for parent in pathlib.PurePosixPath(relative).parents):raise SystemExit('Backup member descends through a symbolic link.')
 if 'postgres.dump' not in hashes:raise SystemExit('Database export is missing from backup.')
 projects=m.get('projects',[]);repositories=m.get('repositories',[])
 if not isinstance(projects,list) or not isinstance(repositories,list):raise SystemExit('Invalid repository/project mapping.')
 for repo in repositories:
  relative=safe_relative(repo.get('snapshot',''))
  if not (relative.startswith('data/') or relative.startswith('repositories/')):raise SystemExit('Repository snapshot escapes backup roots.')
  if not isinstance(repo.get('main_sha'),str) or not re.fullmatch('[a-f0-9]{40,64}',repo['main_sha']):raise SystemExit('Invalid repository main identity.')
  if not any(name.startswith(relative+'/') for name in hashes):raise SystemExit('Repository snapshot files are missing.')
 for project in projects:
  if not isinstance(project,dict) or project.get('paused') is not True:raise SystemExit('Backup contains an unpaused project.')
  if project.get('authority_mode')=='MANAGED' and len([r for r in repositories if project.get('project_id') in r.get('project_ids',[])])!=1:raise SystemExit('Managed repository mapping is incomplete.')
 return dict(hashes,**{relative:'SYMLINK:'+target for relative,target in links.items()})

def verify_backup(backup=None,archive=None,max_unpacked=DEFAULT_MAX_UNPACKED):
 """Read and hash only. Never extracts archive members, copies state or contacts SQL."""
 if not 1<=max_unpacked<=1024**4:raise SystemExit('Invalid unpacked-byte limit.')
 total=0
 if backup is not None:
  manifest_path=backup/'manifest.json'
  if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size>MAX_MANIFEST_BYTES:raise SystemExit('Invalid backup manifest file.')
  m=json.loads(manifest_path.read_text());expected=validate_manifest(m)
  observed={};files=[];entries=0
  for item in backup.rglob('*'):
   entries+=1
   if entries>MAX_MEMBERS:raise SystemExit('Backup member limit exceeded.')
   name=str(item.relative_to(backup))
   if name=='manifest.json':continue
   if item.is_symlink():observed[name]='SYMLINK:'+os.readlink(item)
   elif item.is_file():
    total+=item.stat().st_size
    if total>max_unpacked:raise SystemExit('Backup exceeds the configured unpacked-byte limit.')
    files.append((name,item))
   elif not item.is_dir():raise SystemExit('Special backup members are unsupported.')
  for name,item in files:observed[name]=digest(item)
 else:
  if archive.is_symlink() or not archive.is_file():raise SystemExit('Archive must be a regular private backup file.')
  observed={};seen=set();links=set();m=None
  compressed_bytes=archive.stat().st_size
  stream_limit=min(max_unpacked, max(1,compressed_bytes)*2000)+MAX_MEMBERS*1024+MAX_MANIFEST_BYTES
  with gzip.open(archive,'rb') as decompressed,tarfile.open(fileobj=BoundedArchiveReader(decompressed,stream_limit),mode='r|',tarinfo=BoundedTarInfo) as stream:
   for member in stream:
    name=safe_relative(member.name,True)
    if not name:
     if not member.isdir():raise SystemExit('Invalid archive root member.')
     continue
    if name in seen:raise SystemExit('Duplicate archive member.')
    seen.add(name)
    if len(seen)>MAX_MEMBERS:raise SystemExit('Archive member limit exceeded.')
    if member.isdir():continue
    if member.issym():
     if name=='manifest.json' or '\x00' in member.linkname:raise SystemExit('Invalid archive symlink.')
     links.add(name);observed[name]='SYMLINK:'+member.linkname;continue
    if not member.isfile():raise SystemExit('Hard links and special archive members are unsupported; nothing extracted.')
    total+=member.size
    if total>max_unpacked or total>max(1,compressed_bytes)*2000:raise SystemExit('Archive expansion limit exceeded; nothing extracted.')
    source=stream.extractfile(member)
    if source is None:raise SystemExit('Archive file content is missing.')
    if name=='manifest.json':
     if member.size>MAX_MANIFEST_BYTES:raise SystemExit('Archive manifest is oversized.')
     m=json.loads(source.read(MAX_MANIFEST_BYTES+1));continue
    h=hashlib.sha256()
    for chunk in iter(lambda:source.read(1024*1024),b''):h.update(chunk)
    observed[name]=h.hexdigest()
  if m is None:raise SystemExit('Archive manifest is missing.')
  expected=validate_manifest(m)
  for name in seen:
   if any(str(parent) in links for parent in pathlib.PurePosixPath(name).parents):raise SystemExit('Archive member descends through a symbolic link.')
 if observed!=expected:raise SystemExit('Backup file inventory/hash/symlink mismatch; no copy or SQL performed.')
 return m,{'status':'VERIFIED','schema_version':m['schema_version'],'file_count':len(m['sha256']),'symlink_count':len(m.get('symlinks',{})),'unpacked_bytes':total,'projects':m.get('projects',[]),'repositories':m.get('repositories',[]),'dispatch_paused':True,'sql_executed':False,'state_copied':False,'required_before_restore':['Choose a fresh isolated directory and an explicitly empty PostgreSQL database.','Restore, relocate and start read-only with new Owner/Worker credentials.','Review Git, evidence, paths and pending custody before any explicit dispatch resume.'],'external_symlinks_require_review':bool(m.get('symlinks'))}

def main():
 p=argparse.ArgumentParser();source=p.add_mutually_exclusive_group(required=True);source.add_argument('--backup',type=pathlib.Path);source.add_argument('--archive',type=pathlib.Path);p.add_argument('--destination',type=pathlib.Path);p.add_argument('--verify-only',action='store_true');p.add_argument('--max-unpacked-bytes',type=int,default=DEFAULT_MAX_UNPACKED)
 database=p.add_mutually_exclusive_group();database.add_argument('--empty-database-url');database.add_argument('--database-env',type=pathlib.Path,help='Private mode0600 JSON containing DATABASE_URL; keeps credentials out of command arguments')
 p.add_argument('--reset-owner-password',action='store_true',help='Clear old password hash; initialize new password from server environment after restore');a=p.parse_args()
 m,preview=verify_backup(a.backup,a.archive,a.max_unpacked_bytes)
 if a.verify_only:
  if a.destination or a.empty_database_url or a.database_env or a.reset_owner_password:p.error('--verify-only does not accept restore destinations, databases or password changes')
  print(json.dumps(preview));return
 if a.archive:p.error('Archive verification is read-only. Extract a verified archive into an isolated directory before --backup restore.')
 if not a.destination or not (a.empty_database_url or a.database_env):p.error('Restore requires --destination and an explicitly empty database')
 if os.path.lexists(a.destination):raise SystemExit('Restore destination must not exist.')
 if a.database_env:
  if a.database_env.is_symlink() or a.database_env.stat().st_mode&0o077:raise SystemExit('Database environment must be a private mode0600 regular file.')
  url=json.loads(a.database_env.read_text())['DATABASE_URL']
 else:url=a.empty_database_url
 env=pg_environment(url)
 query="SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','v','m','S','f')"
 result=subprocess.run(['psql','-X','--no-password','-t','-A','--set','ON_ERROR_STOP=1','--command',query],env=env,capture_output=True,text=True,timeout=30)
 if result.returncode or result.stdout.strip()!='0':raise SystemExit('Target database must be reachable and contain no user relations; existing databases are never overwritten.')
 a.destination.mkdir(parents=True,mode=0o700);shutil.copytree(a.backup/'data',a.destination/'data',symlinks=True)
 if (a.backup/'repositories').exists():shutil.copytree(a.backup/'repositories',a.destination/'repositories',symlinks=True)
 auth=a.destination/'data'/'auth.json'
 if auth.exists():
  data=json.loads(auth.read_text());data['sessions']={}
  if a.reset_owner_password:data['password_hash']=None
  auth.write_text(json.dumps(data));auth.chmod(0o600)
 result=subprocess.run(['pg_restore','--exit-on-error','--single-transaction','--no-owner','--dbname',env['PGDATABASE'],str(a.backup/'postgres.dump')],env=env,capture_output=True,timeout=120)
 if result.returncode:raise SystemExit('pg_restore failed; database transaction rolled back. Retain failed files and select a fresh directory after correcting configuration.')
 mapping_path=None
 if m.get('data_root_original') and m.get('projects'):
  repositories=[]
  for project in m['projects']:
   matches=[repo for repo in m['repositories'] if project['project_id'] in repo.get('project_ids',[])]
   if project['authority_mode']=='MANAGED' and len(matches)!=1:raise SystemExit('Restored state retained, but managed repository mapping is incomplete; do not start dispatch.')
   if matches:
    repo=matches[0];repositories.append({'project_id':project['project_id'],'old_path':project['root_path'],'new_path':str((a.destination/repo['snapshot']).resolve(strict=True)),'main_sha':repo['main_sha']})
  payload={'old_data_root':m['data_root_original'],'new_data_root':str((a.destination/'data').resolve(strict=True)),'repositories':repositories}
  mapping=dict(payload,manifest_hash=hashlib.sha256(json.dumps(payload,ensure_ascii=False,separators=(',',':')).encode('utf-8')).hexdigest())
  mapping_path=a.destination/'restore-relocation.json';mapping_path.write_text(json.dumps(mapping,ensure_ascii=False,indent=2)+'\n');mapping_path.chmod(0o600)
 # Every project was paused before snapshot. Old worker authority must be re-registered with a NEW deployment token.
 print(json.dumps({'destination':str(a.destination),'dispatch_paused':True,'owner_sessions_cleared':True,'owner_password_reset_requested':a.reset_owner_password,'relocation_manifest':str(mapping_path) if mapping_path else None,'next':'Run the pinned server offline relocation first; then start with FORGEFLOW_RESTORE_MODE=1 and NEW distinct service tokens/password. Verify history, register NEW worker IDs, and explicitly review before resuming.'}))
if __name__=='__main__':main()

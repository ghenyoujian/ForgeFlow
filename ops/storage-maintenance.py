#!/usr/bin/env python3
"""Audit and retire inactive ForgeFlow storage with lossless content archives.

Default is read-only. Apply is tied to an exact audited plan. Canonical task,
model, integration, and financial records are never edited. Restored Git files
are independent copies; live sandbox repositories never share archive inodes.
"""
from __future__ import annotations
import argparse
import ctypes
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
import gzip
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
import uuid
import zlib

HOME_BASE = Path.home()
STATE = HOME_BASE / '.local/state/forgeflow'
ROOTS = {'worktrees': STATE/'control/worktrees',
         'checkpoints': HOME_BASE/'.cache/forgeflow-build-checkpoints',
         'releases': HOME_BASE/'.local/share/forgeflow/releases'}
ARCHIVE = STATE/'storage-archive'
PROFILE_CACHE = {'key':None,'rows':None,'refs':None}
PROFILE_LOCK = threading.RLock()
TERMINAL = {'SUCCEEDED','FAILED','CANCELLED','REJECTED','INTERRUPTED'}
UUID = re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}')


def digest(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def write_json(path, value):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temporary = path.with_name(path.name+'.tmp-'+uuid.uuid4().hex)
    with os.fdopen(os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as f:
        f.write(canonical(value)+b'\n');f.flush();os.fsync(f.fileno())
    os.replace(temporary,path)


def private_json(path):
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError('Private runtime configuration is invalid')
    return json.loads(path.read_bytes())


def canonical_state():
    import psycopg
    cfg=private_json(STATE/'control/runtime-env.json')
    with psycopg.connect(cfg['DATABASE_URL'],connect_timeout=10) as db:
        db.execute('SET TRANSACTION READ ONLY')
        attempts={a:{'project_id':p,'state':s,'task_id':t} for p,a,s,t in db.execute("SELECT project_id,attempt_id,state,data->>'task_id' FROM attempts")}
        unresolved=set()
        for intent,aid in db.execute("SELECT intent_id,attempt_id FROM merge_intents WHERE state IN ('PREPARED','COMMIT_DECIDED','COMMITTED','RECOVERY_REQUIRED')"):
            unresolved.add(aid)
            for name in ['integration-'+intent,'integration-'+intent.replace('-','')]:unresolved.update([name,name+'-verification'])
        key=tuple(db.execute("SELECT project_id,document_id,revision FROM documents WHERE collection='executor_profiles' ORDER BY project_id,document_id").fetchall())
        with PROFILE_LOCK:
            if key!=PROFILE_CACHE['key']:
                PROFILE_CACHE.update(key=key,rows=[v for v, in db.execute("SELECT data FROM documents WHERE collection='executor_profiles'")],refs=None)
            profiles=PROFILE_CACHE['rows']
    return attempts,unresolved,profiles


def process_references():
    paths=[]
    for pid in Path('/proc').iterdir():
        if not pid.name.isdigit():continue
        try:
            if pid.stat().st_uid != os.getuid():continue
            for name in ['cwd','exe']:
                try:paths.append(os.readlink(pid/name).removesuffix(' (deleted)'))
                except OSError:pass
            try:
                paths.extend(x.decode(errors='replace') for x in (pid/'cmdline').read_bytes().split(b'\0') if x)
            except OSError:pass
            try:
                for fd in (pid/'fd').iterdir():
                    try:paths.append(os.readlink(fd).removesuffix(' (deleted)'))
                    except OSError:pass
            except OSError:pass
            try:
                paths.extend(line.split(maxsplit=5)[-1] for line in (pid/'maps').read_text().splitlines() if len(line.split(maxsplit=5))==6)
            except OSError:pass
        except OSError:pass
    return paths


def referenced_roots(texts):
    result={key:set() for key in ROOTS}
    for key,root in ROOTS.items():
        pattern=re.compile(re.escape(str(root))+r'/([^/\s\x00"\'<>;]+)')
        for text in texts:result[key].update(pattern.findall(text))
    return result


def live_references(profiles):
    texts=process_references()
    # Retain installed service definitions, even stopped Workers, so restart is safe.
    for path in (HOME_BASE/'.config/systemd/user').glob('*.service'):
        texts.append(path.read_text(errors='replace'))
    runtime=private_json(STATE/'control/runtime-env.json');texts.append(json.dumps(runtime))
    mapping=runtime.get('FORGEFLOW_NATIVE_DELIVERY_CONFIGS_FILE')
    if mapping and Path(mapping).exists():
        for path in private_json(Path(mapping)).values():
            if Path(path).exists():texts.append(json.dumps(private_json(Path(path))))
    # Pinned registered profiles remain readable, including their sandbox guard.
    with PROFILE_LOCK:
        if profiles is PROFILE_CACHE['rows'] and PROFILE_CACHE['refs'] is None:
            PROFILE_CACHE['refs']=referenced_roots([json.dumps(profile) for profile in profiles])
        pinned=PROFILE_CACHE['refs'] if profiles is PROFILE_CACHE['rows'] else referenced_roots([json.dumps(profile) for profile in profiles])
        result=referenced_roots(texts)
        for family in result:result[family].update(pinned[family])
        return result


def size(root):
    if not root.exists():return {'allocated_bytes':0,'logical_bytes':0}
    a=subprocess.check_output(['du','-sx','-B1',str(root)],text=True).split()[0]
    b=subprocess.check_output(['du','-sx','-B1','--apparent-size',str(root)],text=True).split()[0]
    return {'allocated_bytes':int(a),'logical_bytes':int(b)}


def git_audit(path):
    if not (path/'.git').exists():return {'repository':False,'dirty_entries':0}
    env=dict(os.environ,GIT_OPTIONAL_LOCKS='0')
    def run(args):
        r=subprocess.run(['git','-C',str(path),*args],env=env,capture_output=True,timeout=90)
        if r.returncode:raise ValueError('Git audit failed for '+path.name)
        return r.stdout
    head=run(['rev-parse','HEAD']).decode().strip()
    status=run(['status','--porcelain=v1','-z','--untracked-files=all'])
    return {'repository':True,'head':head,'status_sha256':digest(status),
            'dirty_entries':sum(bool(row) for row in status.split(b'\0')),
            'status_hex':status.hex()}


def audit(output, families=None, keep_checkpoints=3):
    families=set(families or ROOTS)
    if not families.issubset(ROOTS) or keep_checkpoints < 1:raise ValueError('Invalid storage retention scope')
    attempts,unresolved,profiles=canonical_state();refs=live_references(profiles)
    newest=sorted((p for p in ROOTS['checkpoints'].iterdir()
                   if p.is_dir() and not p.is_symlink() and (p/'receipt.json').is_file()
                   and not (p/'storage-archive.json').exists()),
                  key=lambda p:p.stat().st_mtime_ns,reverse=True)[:keep_checkpoints]
    refs['checkpoints'].update(p.name for p in newest)
    # The immediately preceding Core is the explicit hot rollback version.
    rollback='release-dsh-physical-recovery-takeover-r5'
    if (ROOTS['releases']/rollback).exists():refs['releases'].add(rollback)
    entries=[]
    trees=sorted(p for p in ROOTS['worktrees'].iterdir() if p.is_dir() and not p.is_symlink()) if 'worktrees' in families else []
    with ThreadPoolExecutor(max_workers=4) as pool:
        for index,(path,git) in enumerate(zip(trees,pool.map(git_audit,trees)),1):
            match=UUID.search(path.name);aid=match.group() if match else None;a=attempts.get(aid,{})
            reasons=[]
            if path.name in refs['worktrees']:reasons.append('PROCESS_OR_CONFIGURATION_REFERENCE')
            if aid in unresolved or path.name in unresolved:reasons.append('UNRESOLVED_INTEGRATION')
            if a and a['state'] not in TERMINAL:reasons.append('NONTERMINAL_CANONICAL_ATTEMPT')
            if not aid and not re.fullmatch(r'integration-[0-9a-f]{32}(?:-verification)?',path.name):reasons.append('UNKNOWN_DIRECTORY_IDENTITY')
            entries.append({'family':'worktrees','name':path.name,'path':str(path),'attempt_id':aid,
                            'canonical':a or None,'git':git,'keep_reasons':reasons,
                            'action':'KEEP' if reasons else 'ARCHIVE_AND_RETIRE'})
            if index%20==0:print(json.dumps({'audited_worktrees':index,'total':len(trees)}),flush=True)
    for family in ['checkpoints','releases']:
        if family not in families:continue
        for path in sorted(ROOTS[family].iterdir()):
            if not path.is_dir() or path.is_symlink():continue
            reasons=['RUNTIME_REGISTERED_OR_ROLLBACK_REFERENCE'] if path.name in refs[family] else []
            if family=='checkpoints' and path.name=='compile-source':reasons.append('STABLE_COMPILER_INPUT_SOURCE')
            if family=='checkpoints' and not (path/'receipt.json').is_file():reasons.append('UNKNOWN_CHECKPOINT_IDENTITY')
            if (path/'storage-archive.json').exists():reasons.append('ALREADY_RETIRED_METADATA')
            entries.append({'family':family,'name':path.name,'path':str(path),'keep_reasons':reasons,
                            'action':'KEEP' if reasons else 'ARCHIVE_PAYLOAD'})
    value={'schema_version':'forgeflow.storage-maintenance-plan.v1','created_at':datetime.now(timezone.utc).isoformat(),
           'families':sorted(families),'keep_checkpoints':keep_checkpoints,
           'roots':{k:str(v) for k,v in ROOTS.items()},'archive_root':str(ARCHIVE),
           'before':{k:size(v) for k,v in ROOTS.items()},'entries':entries,
           'preservation':'All Git history, dirty and untracked/ignored files archived before retirement; canonical records unchanged.',
           'authority':'Explicit user cleanup request; no task or model qualification credit'}
    write_json(output,value)
    print(json.dumps({'plan':str(output),'plan_sha256':digest(output.read_bytes()),
        'counts':{k:{act:sum(e['family']==k and e['action']==act for e in entries) for act in ['KEEP','ARCHIVE_AND_RETIRE','ARCHIVE_PAYLOAD']} for k in ROOTS},
        'dirty_worktrees':sum(e['family']=='worktrees' and e['git']['dirty_entries']>0 for e in entries)}),flush=True)


def checkpoint_maintenance(output, keep_checkpoints=3):
    """Called by the coordinated builder while it owns .build.lock.

    Only old checkpoint payloads are retired. Production references are read
    again before archiving; inability to read authority stops retirement.
    """
    if keep_checkpoints < 1:raise ValueError('At least one checkpoint must be retained')
    candidates=[p for p in ROOTS['checkpoints'].iterdir()
                if p.is_dir() and not p.is_symlink() and (p/'receipt.json').is_file()
                and not (p/'storage-archive.json').exists()]
    if len(candidates)<=keep_checkpoints:
        result={'status':'WITHIN_RETENTION','active_checkpoints':len(candidates),'keep_checkpoints':keep_checkpoints}
        write_json(output,result);return result
    plan=output.with_name(output.stem+'-plan.json')
    audit(plan, families=['checkpoints'], keep_checkpoints=keep_checkpoints)
    apply(plan,digest(plan.read_bytes()),output)
    return json.loads(output.read_bytes())


class ObjectArchive:
    def __init__(self):
        self.verified=set();self.created=0
        (ARCHIVE/'objects').mkdir(parents=True,exist_ok=True,mode=0o700)
    def object_path(self,key,codec):return ARCHIVE/'objects'/key[:2]/(key[2:]+('.zlib' if codec=='zlib' else '.raw'))
    def put(self,raw):
        key=digest(raw);codec='zlib' if len(raw)>65536 else 'raw';path=self.object_path(key,codec)
        if not path.exists():
            path.parent.mkdir(exist_ok=True,mode=0o700)
            temp=path.with_name(path.name+'.tmp-'+uuid.uuid4().hex)
            data=zlib.compress(raw,3) if codec=='zlib' else raw
            with os.fdopen(os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o400),'wb') as f:f.write(data)
            os.replace(temp,path);self.created+=1
        if key not in self.verified:
            stored=path.read_bytes();stored=zlib.decompress(stored) if codec=='zlib' else stored
            if digest(stored)!=key or len(stored)!=len(raw):raise ValueError('Archive content verification failed')
            self.verified.add(key)
        return key,codec
    def get(self,entry):
        if not re.fullmatch(r'[0-9a-f]{64}',entry['sha256']) or entry['codec'] not in {'raw','zlib'}:raise ValueError('Archive object identity invalid')
        path=self.object_path(entry['sha256'],entry['codec']);raw=path.read_bytes()
        if entry['codec']=='zlib':raw=zlib.decompress(raw)
        if digest(raw)!=entry['sha256'] or len(raw)!=entry['bytes']:raise ValueError('Archive content verification failed')
        return raw


def sync_archive():
    """Commit file contents and directory entries in one filesystem barrier."""
    fd=os.open(ARCHIVE,os.O_RDONLY|os.O_DIRECTORY)
    try:
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.syncfs(fd)!=0:raise OSError(ctypes.get_errno(),'Archive durability barrier failed')
    finally:os.close(fd)


def signature(st):return [st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns,stat.S_IMODE(st.st_mode)]
def snapshot(path,entry,objects,run):
    records=[]
    for directory,dirs,files in os.walk(path,followlinks=False):
        dirs.sort();files.sort();base=Path(directory)
        for name in dirs+files:
            p=base/name;st=p.lstat();rel=p.relative_to(path).as_posix()
            if stat.S_ISLNK(st.st_mode):raise ValueError('Symbolic link requires separate review: '+entry['name'])
            record={'path':rel,'mode':stat.S_IMODE(st.st_mode),'mtime_ns':st.st_mtime_ns,'signature':signature(st)}
            if stat.S_ISDIR(st.st_mode):record['kind']='directory'
            elif stat.S_ISREG(st.st_mode):
                raw=p.read_bytes()
                if signature(p.lstat())!=record['signature']:raise ValueError('Source changed during archive')
                key,codec=objects.put(raw);record.update(kind='file',sha256=key,codec=codec,bytes=len(raw))
            else:raise ValueError('Special file requires separate review: '+entry['name'])
            records.append(record)
    # Verify the complete source inventory is unchanged before deleting copies.
    seen=set()
    for directory,dirs,files in os.walk(path,followlinks=False):
        for name in dirs+files:seen.add((Path(directory)/name).relative_to(path).as_posix())
    if seen!={v['path'] for v in records}:raise ValueError('Source inventory changed during archive')
    for record in records:
        if signature((path/record['path']).lstat())!=record['signature']:raise ValueError('Source changed before retirement')
    manifest={'schema_version':'forgeflow.storage-archive.v1','original_path':str(path),'root_mode':stat.S_IMODE(path.stat().st_mode),
              'entry':entry,'records':records,'created_at':datetime.now(timezone.utc).isoformat(),
              'all_content_verified':True,'canonical_state_modified':False,'restore_creates_independent_inodes':True}
    archive_path=ARCHIVE/'manifests'/run/entry['family']/(entry['name']+'.json.gz')
    archive_path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    raw=canonical(manifest);packed=gzip.compress(raw,compresslevel=6,mtime=0)
    with os.fdopen(os.open(archive_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o400),'wb') as f:f.write(packed);f.flush();os.fsync(f.fileno())
    sync_archive()
    if digest(gzip.decompress(archive_path.read_bytes()))!=digest(raw):raise ValueError('Archive manifest verification failed')
    return archive_path,digest(packed),len(records)


def retire_entry(entry,objects,run,plan_sha):
    path=Path(entry['path'])
    if path.parent!=ROOTS[entry['family']] or path.name!=entry['name'] or path.is_symlink():raise ValueError('Storage path identity changed')
    attempts,unresolved,profiles=canonical_state();refs=live_references(profiles)
    if entry['name'] in refs[entry['family']]:raise ValueError('New live storage reference; rerun audit')
    aid=entry.get('attempt_id');state=attempts.get(aid,{})
    if aid in unresolved or path.name in unresolved or state and state['state'] not in TERMINAL:raise ValueError('Canonical attempt became active; rerun audit')
    if entry['family']=='worktrees' and git_audit(path)!=entry['git']:raise ValueError('Git state changed after audit')
    manifest,archive_sha,count=snapshot(path,entry,objects,run)
    if entry['name'] in referenced_roots(process_references())[entry['family']]:raise ValueError('Process opened source before retirement')
    retired={'family':entry['family'],'name':entry['name'],'manifest':str(manifest),'archive_sha256':archive_sha,'entries':count,
             'dirty_entries_preserved':entry.get('git',{}).get('dirty_entries',0),'original_path':str(path)}
    holding=path.with_name('.retiring-'+entry['name']+'-'+uuid.uuid4().hex[:8])
    journal=ARCHIVE/'journals'/run/entry['family']/(entry['name']+'.json')
    fact={'plan_sha256':plan_sha,'entry':retired,'holding':str(holding),'status':'ARCHIVE_VERIFIED_BEFORE_RETIREMENT'}
    write_json(journal,fact)
    if entry['family']=='worktrees':path.rename(holding);shutil.rmtree(holding)
    else:
        remove_archived_payload(path,entry['family'])
        write_json(path/'storage-archive.json',retired)
    fact['status']='RETIRED';write_json(journal,fact)
    return retired


def remove_archived_payload(path,family):
    # Immutable release directories may be 0500. Their original modes are
    # already preserved in the verified archive; grant only directory removal.
    path.chmod(0o700)
    payloads=['source','bin'] if family=='checkpoints' else [p.name for p in path.iterdir() if p.is_dir()]
    for name in payloads:
        target=path/name
        if target.is_dir():
            for directory,dirs,files in os.walk(target):Path(directory).chmod(0o700)
            shutil.rmtree(target)


def finish_verified_retirement(fact,expected_sha):
    entry=fact['entry'];path=Path(entry['original_path']);family=entry['family']
    if fact['plan_sha256']!=expected_sha or path.parent!=ROOTS[family]:raise ValueError('Retirement journal identity differs')
    attempts,unresolved,profiles=canonical_state();refs=live_references(profiles)
    if path.name in refs[family]:raise ValueError('Interrupted source now has a live reference')
    packed=Path(entry['manifest']).read_bytes()
    if digest(packed)!=entry['archive_sha256']:raise ValueError('Retirement archive identity differs')
    manifest=json.loads(gzip.decompress(packed));records={r['path']:r for r in manifest['records']}
    archive=ObjectArchive();verified=set()
    for record in records.values():
        if record['kind']=='file' and record['sha256'] not in verified:archive.get(record);verified.add(record['sha256'])
    holding=Path(fact['holding'])
    for source in [path,holding]:
        if not source.exists():continue
        if source.is_symlink() or source.parent!=ROOTS[family]:raise ValueError('Interrupted source path differs')
        for p in source.rglob('*'):
            rel=p.relative_to(source).as_posix()
            if rel=='storage-archive.json':
                if json.loads(p.read_bytes()).get('archive_sha256')!=entry['archive_sha256']:raise ValueError('Retirement marker changed')
                continue
            record=records.get(rel)
            if p.is_symlink() or not record:raise ValueError('Unarchived content appeared after interruption')
            if p.is_file() and (record['kind']!='file' or digest(p.read_bytes())!=record['sha256']):raise ValueError('Source content changed after interruption')
        if family=='worktrees':
            aid=manifest['entry'].get('attempt_id');state=attempts.get(aid,{})
            if aid in unresolved or path.name in unresolved or state and state['state'] not in TERMINAL:raise ValueError('Interrupted attempt is active')
            for directory,dirs,files in os.walk(source):Path(directory).chmod(0o700)
            source.chmod(0o700);shutil.rmtree(source)
        else:remove_archived_payload(source,family);write_json(source/'storage-archive.json',entry)
    fact['status']='RETIRED'
    return entry


WORKER_ARCHIVE=None
def archive_worker_init():
    global WORKER_ARCHIVE
    WORKER_ARCHIVE=ObjectArchive()

def archive_worker_job(args):
    entry,run,plan_sha=args
    return retire_entry(entry,WORKER_ARCHIVE,run,plan_sha)


def apply(plan_path,expected_sha,output):
    if digest(plan_path.read_bytes())!=expected_sha:raise ValueError('Plan identity changed')
    plan=json.loads(plan_path.read_bytes())
    if plan['roots']!={k:str(v) for k,v in ROOTS.items()} or plan['archive_root']!=str(ARCHIVE):raise ValueError('Unapproved storage roots')
    ARCHIVE.mkdir(parents=True,exist_ok=True,mode=0o700)
    import fcntl
    with os.fdopen(os.open(ARCHIVE/'maintenance.lock',os.O_CREAT|os.O_RDWR,0o600),'r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        objects=ObjectArchive();run=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
        result={'schema_version':'forgeflow.storage-maintenance-result.v1','started_at':datetime.now(timezone.utc).isoformat(),
                'plan_sha256':expected_sha,'before':plan['before'],'retired':[],'kept':[],'canonical_records_modified':False,
                'model_calls':0,'original_card_completion_credit':0,'archive_root':str(ARCHIVE)}
        if output.exists():
            previous=json.loads(output.read_bytes())
            if previous.get('plan_sha256')!=expected_sha:raise ValueError('Existing progress belongs to another plan')
            result=previous
        completed={(e['family'],e['name']) for e in result['retired']}
        # A durable journal can recover a completed retirement whose final HTTP/
        # process progress write was interrupted. An incomplete removal is left
        # explicit for restoration rather than inferred from a missing source.
        for journal in (ARCHIVE/'journals').rglob('*.json') if (ARCHIVE/'journals').exists() else []:
            fact=json.loads(journal.read_bytes());e=fact['entry'];identity=(e['family'],e['name'])
            if fact['plan_sha256']==expected_sha and identity not in completed:
                if fact['status']!='RETIRED':
                    e=finish_verified_retirement(fact,expected_sha);write_json(journal,fact)
                result['retired'].append(e);completed.add(identity)
                write_json(output,result)
        result['kept']=[{k:v for k,v in e.items() if k!='git'} for e in plan['entries'] if e['action']=='KEEP']
        pending=[e for e in plan['entries'] if e['action']!='KEEP' and (e['family'],e['name']) not in completed]
        result['archive_parallelism']=4;write_json(output,result)
        canonical_state()
        with ProcessPoolExecutor(max_workers=4,mp_context=multiprocessing.get_context('fork'),initializer=archive_worker_init) as pool:
            futures={pool.submit(archive_worker_job,(e,run,expected_sha)):e for e in pending}
            for future in as_completed(futures):
                retired=future.result();result['retired'].append(retired);write_json(output,result)
                print(json.dumps({'retired':len(result['retired']),'planned_retirements':len(completed)+len(pending),
                                  'family':retired['family'],'name':retired['name'],'archive_workers':4}),flush=True)
        result.update(finished_at=datetime.now(timezone.utc).isoformat(),after={k:size(v) for k,v in ROOTS.items()},archive_size=size(ARCHIVE),all_archives_verified=True)
        write_json(output,result);print(json.dumps({'result':str(output),'retired':len(result['retired']),'after':result['after'],'archive_size':result['archive_size']}),flush=True)


def restore(manifest_path,sha,target):
    if digest(manifest_path.read_bytes())!=sha:raise ValueError('Archive manifest identity changed')
    if target.is_symlink():raise ValueError('Restore cannot follow a symbolic link')
    manifest=json.loads(gzip.decompress(manifest_path.read_bytes()));objects=ObjectArchive()
    overlay=False
    if target.exists():
        marker=target/'storage-archive.json'
        if not marker.is_file() or str(target)!=manifest['original_path'] or json.loads(marker.read_bytes()).get('archive_sha256')!=sha:
            raise ValueError('Restore requires a fresh destination or this exact retired metadata stub')
        expected={r['path']:r for r in manifest['records'] if r['kind']=='file'}
        for path in target.rglob('*'):
            if path==marker:continue
            rel=path.relative_to(target).as_posix()
            if path.is_symlink() or not path.is_file() or rel not in expected or digest(path.read_bytes())!=expected[rel]['sha256']:
                raise ValueError('Retired metadata changed; restoration will not overwrite it')
        overlay=True
    else:target.mkdir(mode=0o700,parents=True)
    for entry in manifest['records']:
        rel=Path(entry['path'])
        if rel.is_absolute() or '..' in rel.parts:raise ValueError('Archive contains an escaping path')
        path=target/rel
        if entry['kind']=='directory':path.mkdir(mode=0o700,parents=True,exist_ok=True)
        else:
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            if overlay and path.exists():continue
            with os.fdopen(os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as f:f.write(objects.get(entry))
            path.chmod(entry['mode']);os.utime(path,ns=(entry['mtime_ns'],entry['mtime_ns']))
    for entry in reversed(manifest['records']):
        if entry['kind']=='directory':(target/entry['path']).chmod(entry['mode'])
    target.chmod(manifest['root_mode'])
    if manifest['entry']['family']=='worktrees' and git_audit(target)!=manifest['entry']['git']:raise ValueError('Restored Git identity or dirty content differs')
    if overlay:(target/'storage-archive.json').unlink()
    print(json.dumps({'restored':str(target),'entries':len(manifest['records']),'content_verified':True,'independent_git_inodes':True}))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['audit','apply','restore','checkpoint-maintenance']);p.add_argument('--output',type=Path);p.add_argument('--plan',type=Path);p.add_argument('--plan-sha256');p.add_argument('--manifest',type=Path);p.add_argument('--manifest-sha256');p.add_argument('--destination',type=Path);p.add_argument('--keep-checkpoints',type=int,default=3);a=p.parse_args()
    if a.command=='audit':
        if not a.output:p.error('audit requires --output')
        audit(a.output,keep_checkpoints=a.keep_checkpoints)
    elif a.command=='checkpoint-maintenance':
        if not a.output:p.error('checkpoint-maintenance requires --output')
        import fcntl
        with (ROOTS['checkpoints']/'.build.lock').open('a+') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            checkpoint_maintenance(a.output,a.keep_checkpoints)
    elif a.command=='apply':
        if not all([a.output,a.plan,a.plan_sha256]):p.error('apply requires --output, --plan, --plan-sha256')
        apply(a.plan,a.plan_sha256,a.output)
    else:
        if not all([a.manifest,a.manifest_sha256,a.destination]):p.error('restore requires --manifest, --manifest-sha256, --destination')
        restore(a.manifest,a.manifest_sha256,a.destination)

if __name__=='__main__':
    try:main()
    except Exception as e:
        print(json.dumps({'error':type(e).__name__,'message':str(e)[:300]}),file=sys.stderr);raise SystemExit(1)

#!/usr/bin/env python3
"""Read-only P0-05 evidence consistency check, never proof of execution/Gate."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import argparse

PHASES=('npm_ci','cargo_build','cargo_test','npm_build')
COMMANDS={'npm_ci':['npm','ci','--offline','--cache','/cache'],
          'cargo_build':['cargo','build','--locked','--offline','--workspace','--bins'],
          'cargo_test':['cargo','test','--locked','--offline','--workspace','--lib'],
          'npm_build':['npm','run','build']}
MAX_JSON=4*1024*1024
MAX_LOG=16*1024*1024
TARGET=Path('/home/chenyoujian/.cache/forgeflow-control-target')
MAX_ARTIFACT_BYTES=512*1024*1024
class Invalid(ValueError):pass

def need(value,reason):
    if not value:raise Invalid(reason)

def open_dir(path):
    path=Path(os.path.abspath(path));fd=os.open(path.anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        return fd
    except BaseException:
        os.close(fd);raise

def read_file(rootfd,name,limit):
    need(isinstance(name,str) and '/' not in name and name not in ('','.','..'),'unsafe evidence file path')
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=rootfd)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_size<=limit,'invalid evidence file')
        chunks=[];remaining=limit+1
        while remaining:
            data=os.read(fd,min(1024*1024,remaining))
            if not data:break
            chunks.append(data);remaining-=len(data)
        after=os.fstat(fd)
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'evidence changed during reading')
        value=b''.join(chunks);need(len(value)<=limit,'evidence exceeds budget');return value
    finally:os.close(fd)

def parse_json(value):
    def pairs(rows):
        out={}
        for key,entry in rows:
            need(key not in out,'duplicate JSON key');out[key]=entry
        return out
    return json.loads(value,object_pairs_hook=pairs)

def hash_file(rootfd,name,remaining):
    need(isinstance(name,str) and '/' not in name and name not in ('','.','..'),'unsafe artifact path')
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=rootfd)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_size<=remaining,'artifact exceeds budget or is not regular')
        digest=hashlib.sha256();read=0
        while read<before.st_size:
            data=os.read(fd,min(1024*1024,before.st_size-read))
            if not data:break
            read+=len(data);digest.update(data)
        after=os.fstat(fd)
        need(read==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'artifact changed during reading')
        return digest.hexdigest(),read
    finally:os.close(fd)

def rust_counts(raw):
    value=raw.decode('utf-8','strict')
    runs=[int(x) for x in re.findall(r'^running (\d+) tests?$',value,re.M)]
    rows=re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;',value,re.M)
    need(rows and len(rows)==len(runs),'missing Rust test denominator')
    total=0
    for count,(status,p,f,i,_,filtered) in zip(runs,rows):
        p,f,i,filtered=map(int,(p,f,i,filtered))
        need(status=='ok' and count==p+f+i and f==0 and i==0 and filtered==0,'Rust tests failed, skipped or have inconsistent counts')
        total+=p
    need(total>0,'Rust test denominator is zero');return total

def artifact_inventory(run_dir, target=TARGET):
    run_dir=Path(os.path.abspath(run_dir)); allowed=Path(os.path.abspath(target))/'ecp-p005'
    need(run_dir.parent==allowed and run_dir.name not in ('','.','..'), 'artifact root is outside registered target')
    root=open_dir(run_dir)
    try:
        values={};total=0
        for name in ('forgeflow-server','forgeflow-worker','forgeflow-sandbox-guard','forgeflow'):
            sub=os.dup(root)
            try:
                for part in ('target','debug'):
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=sub);os.close(sub);sub=child
                digest,size=hash_file(sub,name,MAX_ARTIFACT_BYTES-total)
            finally:os.close(sub)
            total+=size;need(total<=MAX_ARTIFACT_BYTES,'artifact bytes exceed budget')
            values[name]=digest
        dist=os.open('dist',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
        try:
            files={};count=0
            for directory,dirs,names,fd in os.fwalk('.',dir_fd=dist,follow_symlinks=False):
                for name in dirs:
                    info=os.stat(name,dir_fd=fd,follow_symlinks=False)
                    need(stat.S_ISDIR(info.st_mode),'frontend contains symlink or non-directory')
                for name in names:
                    count+=1;need(count<=10000,'frontend inventory exceeds entry budget')
                    relative=(Path(directory)/name).as_posix()
                    need(not relative.startswith('/') and '..' not in Path(relative).parts,'unsafe frontend path')
                    digest,size=hash_file(fd,name,MAX_ARTIFACT_BYTES-total)
                    total+=size;need(total<=MAX_ARTIFACT_BYTES,'artifact bytes exceed budget')
                    files[relative]=digest
            need(bool(files),'frontend bundle is empty');values['frontend']=files
        finally:os.close(dist)
        return values
    finally:os.close(root)

def review(evidence,expected_sha,expected_manifest, target=TARGET):
    need(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}',expected_sha) is not None,'invalid expected source SHA')
    need(re.fullmatch(r'[0-9a-f]{64}',expected_manifest) is not None,'invalid expected manifest digest')
    root=open_dir(evidence)
    try:
        source=parse_json(read_file(root,'source-review.json',MAX_JSON))
        need(source.get('status')=='OBSERVED_NOT_GATE' and source.get('product_gate_effect')=='NONE', 'independent source review unresolved')
        need(source.get('source_sha')==expected_sha and source.get('source_manifest_sha256')==expected_manifest,'source binding mismatch')
        inventory=source.get('candidate_inventory_sha256')
        need(isinstance(inventory,str) and re.fullmatch(r'[0-9a-f]{64}',inventory),'missing source inventory')
        workload=parse_json(read_file(root,'workload.json',MAX_JSON))
        need(workload.get('source_sha')==expected_sha and workload.get('source_manifest_sha256')==expected_manifest,
             'workload source mismatch')
        need(workload.get('candidate_inventory_sha256')==inventory,'workload candidate mismatch')
        tools=workload.get('tool_identity');quota=workload.get('quota')
        need(isinstance(tools,dict) and set(tools)=={'cargo','rustc','node','npm'} and all(isinstance(v,dict) for v in tools.values()),
             'workload tool identity unavailable')
        need(isinstance(quota,dict) and quota.get('status')=='PASS','workload quota observation unavailable')
        for name in PHASES:
            phase=parse_json(read_file(root,name+'.json',MAX_JSON))
            need(phase.get('name')==name and phase.get('command')==COMMANDS[name], 'missing or mismatched phase')
            need(phase.get('source_sha')==expected_sha and phase.get('candidate_inventory_sha256')==inventory,'phase source mismatch')
            need(type(phase.get('exit_code')) is int and phase['exit_code']==0 and phase.get('logs_complete') is True, 'phase not complete')
            need(phase.get('tool_identity')==tools,'phase tool identity drift')
            after=phase.get('source_after');phase_quota=phase.get('quota_after')
            need(isinstance(after,dict) and after.get('candidate_inventory_sha256')==inventory,
                 'phase source identity drift')
            need(isinstance(phase_quota,dict) and phase_quota.get('project_id')==quota.get('project_id')
                 and phase_quota.get('hard_limit_bytes')==quota.get('hard_limit_bytes'), 'phase quota drift')
            stdout=read_file(root,name+'.stdout',MAX_LOG);stderr=read_file(root,name+'.stderr',MAX_LOG)
            need(hashlib.sha256(stdout).hexdigest()==phase.get('stdout_sha256') and
                 hashlib.sha256(stderr).hexdigest()==phase.get('stderr_sha256'),'phase log hash mismatch')
            if name=='cargo_test':rust_counts(stdout)
        need(isinstance(workload.get('run_dir'),str) and isinstance(workload.get('artifacts'),dict),'workload artifact record unavailable')
        need(artifact_inventory(workload['run_dir'],target)==workload['artifacts'],'artifact hashes do not match files')
        return {'status':'INCONCLUSIVE','product_gate_effect':'NONE','source_sha':expected_sha,
                'reason':'Structured logs and hashes cannot authenticate real execution, principal, lease or artifact provenance'}
    finally:os.close(root)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('evidence','source-sha','manifest-sha256'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    try:
        value=review(args.evidence,args.source_sha,args.manifest_sha256);code=20
    except (Invalid,ValueError,TypeError,UnicodeError) as exc:
        value={'status':'FAIL','product_gate_effect':'NONE','reason':str(exc)};code=10
    except OSError as exc:
        value={'status':'INCONCLUSIVE','product_gate_effect':'NONE','reason':str(exc)};code=20
    print(json.dumps(value,ensure_ascii=False,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())

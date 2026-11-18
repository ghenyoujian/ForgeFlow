#!/usr/bin/env python3
"""Bounded offline P0-05 build observation; never issues a product Gate.

A real run requires a fresh P0-01 candidate, independent source review, a
project-quota-protected shared Cargo target, a coordinated build lock and an
actually functioning read-only bwrap sandbox. Missing capabilities block before
starting the corresponding command. The runner never cleans the shared cache.
"""
from __future__ import annotations
import argparse
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
TARGET = Path('/home/chenyoujian/.cache/forgeflow-control-target')
BUILD_LOCK = Path('/home/chenyoujian/.cache/forgeflow-build-checkpoints/.build.lock')
TARGET_BUDGET = 2 * 1024**3
MAX_TARGET_ENTRIES = 200_000
MAX_LOG_BYTES = 16 * 1024 * 1024
FS_IOC_FSGETXATTR = 0x801c581f
FS_XFLAG_PROJINHERIT = 0x200
Q_GETQUOTA_PRJ = (0x800007 << 8) | 2
QIF_BLIMITS_SPACE = 3

class Blocked(RuntimeError):
    pass

class Failed(RuntimeError):
    pass

def need(value, reason):
    if not value: raise Blocked(reason)

def module(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result

def no_symlink_dir(path):
    path=Path(os.path.abspath(path));fd=os.open(path.anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        return path,fd
    except BaseException:
        os.close(fd);raise

def scan_target(target):
    """Measure allocated blocks without following or retiring anything."""
    target,fd=no_symlink_dir(target);seen=set();count=0;total=0;reasons=set();deadline=time.monotonic()+60
    def fail(exc):raise exc
    try:
        for _,dirs,files,dirfd in os.fwalk('.',dir_fd=fd,topdown=True,follow_symlinks=False,onerror=fail):
            names=['.']+dirs+files
            for name in names:
                need(time.monotonic()<=deadline,'target inode scan time budget exceeded')
                info=os.stat(name,dir_fd=dirfd,follow_symlinks=False)
                count+=1;need(count<=MAX_TARGET_ENTRIES,'target inode scan exceeds budget')
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    reasons.add('target contains symlink or unsupported entry')
                if info.st_uid!=os.getuid():reasons.add('target contains an inode not owned by caller')
                if stat.S_ISREG(info.st_mode) and info.st_nlink!=1:reasons.add('target contains a hardlinked file')
                key=(info.st_dev,info.st_ino)
                if key not in seen:seen.add(key);total+=info.st_blocks*512
                if total>TARGET_BUDGET:
                    return {'status':'BLOCKED','reason':'target allocated bytes exceed fixed budget',
                            'allocated_bytes_lower_bound':total,'budget_bytes':TARGET_BUDGET,'entries_seen':count,
                            'additional_reasons':sorted(reasons)}
    finally:os.close(fd)
    return {'status':'BLOCKED' if reasons else 'PASS','allocated_bytes':total,'budget_bytes':TARGET_BUDGET,
            'entries_seen':count,'additional_reasons':sorted(reasons)}

def mount_for(path):
    best=None
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left,sep,right=line.partition(' - ')
        if not sep:continue
        a=left.split();b=right.split()
        if len(a)<6 or len(b)<3:continue
        mount=re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),a[4])
        if str(path)==mount or str(path).startswith(mount.rstrip('/')+'/'):
            value={'mount':mount,'fstype':b[0],'device':b[1],
                   'options':sorted(set(a[5].split(','))|set(b[2].split(',')))}
            if best is None or len(mount)>len(best['mount']):best=value
    need(best is not None,'target mount identity unavailable')
    return best

def inode_project(fd):
    data=bytearray(28);fcntl.ioctl(fd,FS_IOC_FSGETXATTR,data,True)
    flags,_,_,project,_,_,_=struct.unpack('=7I',data)
    return flags,project

class Dqblk(ctypes.Structure):
    _fields_=[('bhardlimit',ctypes.c_uint64),('bsoftlimit',ctypes.c_uint64),
              ('curspace',ctypes.c_uint64),('ihardlimit',ctypes.c_uint64),
              ('isoftlimit',ctypes.c_uint64),('curinodes',ctypes.c_uint64),
              ('btime',ctypes.c_uint64),('itime',ctypes.c_uint64),('valid',ctypes.c_uint32)]

def query_quota(device, project):
    libc=ctypes.CDLL(None,use_errno=True);quota=Dqblk()
    libc.quotactl.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_void_p]
    libc.quotactl.restype=ctypes.c_int
    if libc.quotactl(Q_GETQUOTA_PRJ,os.fsencode(device),project,ctypes.byref(quota)):
        raise OSError(ctypes.get_errno(),'project quota query failed')
    return quota

def project_quota(target, *, allow_inherited_symlinks=False):
    """Read project quota and inode inheritance; never configure filesystem."""
    mount=mount_for(target)
    need(mount['fstype']=='ext4' and ('prjquota' in mount['options'] or 'pquota' in mount['options']),
         'enforced ext4 project quota is unavailable')
    need(mount['device'].startswith('/dev/'),'quota device is not an explicit local block device')
    target,rootfd=no_symlink_dir(target)
    try:
        root_flags,project=inode_project(rootfd)
        need(project>0 and project<=0x7fffffff and root_flags&FS_XFLAG_PROJINHERIT,
             'target lacks a bounded inheritable project ID')
        count=0;deadline=time.monotonic()+60
        def fail(exc):raise exc
        for _,dirs,files,dirfd in os.fwalk('.',dir_fd=rootfd,topdown=True,follow_symlinks=False,onerror=fail):
            for name in ['.']+dirs+files:
                need(time.monotonic()<=deadline,'project inode scan time budget exceeded')
                info=os.stat(name,dir_fd=dirfd,follow_symlinks=False);count+=1
                need(count<=MAX_TARGET_ENTRIES,'project inode scan exceeds budget')
                if stat.S_ISLNK(info.st_mode):
                    # The initial scan must reject every pre-existing link.
                    # Links created later inside the isolated mount inherit the
                    # verified parent project; fwalk never follows them.
                    need(allow_inherited_symlinks,'project subtree contains an unverified symlink')
                    continue
                need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),'project subtree contains unsupported entry')
                flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
                if stat.S_ISDIR(info.st_mode):flags|=os.O_DIRECTORY
                fd=os.open(name,flags,dir_fd=dirfd)
                try:child_flags,child_project=inode_project(fd)
                finally:os.close(fd)
                need(child_project==project,'target inode belongs to another project')
                if stat.S_ISDIR(info.st_mode):need(child_flags&FS_XFLAG_PROJINHERIT,'directory does not inherit target project')
        quota=query_quota(mount['device'],project)
        hard=int(quota.bhardlimit)*1024
        need(quota.valid&QIF_BLIMITS_SPACE==QIF_BLIMITS_SPACE,'project quota limit/usage unavailable')
        need(0<hard<=TARGET_BUDGET and quota.curspace<=hard,'project quota hard limit missing or exceeds target budget')
        return {'status':'PASS','project_id':project,'hard_limit_bytes':hard,'usage_bytes':int(quota.curspace),
                'mount':mount['mount'],'device':mount['device'],'fstype':mount['fstype'],'entries_seen':count}
    finally:os.close(rootfd)

def symlink_quota_probe(directory, quota):
    """Check kernel accounting for one long, block-allocating symlink."""
    before=query_quota(quota['device'],quota['project_id'])
    need(before.valid & 10 == 10, 'project inode or space usage is unavailable')
    _,fd=no_symlink_dir(directory)
    name='.ecp-symlink-probe-'+os.urandom(12).hex();created=None
    try:
        os.symlink('x'*2048,name,dir_fd=fd)
        created=os.stat(name,dir_fd=fd,follow_symlinks=False)
        need(created.st_blocks>0,'long symlink did not allocate blocks; accounting unproven')
        deadline=time.monotonic()+5
        while True:
            during=query_quota(quota['device'],quota['project_id'])
            if (during.valid & 10 == 10 and during.curinodes==before.curinodes+1
                    and during.curspace==before.curspace+created.st_blocks*512):break
            if time.monotonic()>=deadline:raise Blocked('project did not confirm long symlink inode and space accounting')
            time.sleep(.1)
    finally:
        try:
            if created is not None:
                current=os.stat(name,dir_fd=fd,follow_symlinks=False)
                need((current.st_dev,current.st_ino)==(created.st_dev,created.st_ino) and stat.S_ISLNK(current.st_mode),
                     'symlink probe identity changed; retained')
                os.unlink(name,dir_fd=fd)
        finally:
            os.close(fd)
    deadline=time.monotonic()+5
    while True:
        after=query_quota(quota['device'],quota['project_id'])
        if after.valid & 10 == 10 and after.curinodes==before.curinodes and after.curspace==before.curspace:break
        if time.monotonic()>=deadline:raise Blocked('symlink probe quota did not return to baseline')
        time.sleep(.1)
    return {'status':'PASS','project_id':quota['project_id'],'inode_before':before.curinodes,
            'inode_during':during.curinodes,'inode_after':after.curinodes,
            'space_before':before.curspace,'space_during':during.curspace,'space_after':after.curspace,
            'symlink_allocated_bytes':created.st_blocks*512}

def artifact_digest(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode),'artifact is not a regular file')
        h=hashlib.sha256()
        while True:
            value=os.read(fd,1024*1024)
            if not value:break
            h.update(value)
        after=os.fstat(fd)
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'artifact changed while hashing')
        return h.hexdigest()
    finally:os.close(fd)

PHASES = ('npm_ci','cargo_build','cargo_test','npm_build')
COMMANDS = {
    'npm_ci':['npm','ci','--offline','--cache','/cache'],
    'cargo_build':['cargo','build','--locked','--offline','--workspace','--bins'],
    'cargo_test':['cargo','test','--locked','--offline','--workspace','--lib'],
    'npm_build':['npm','run','build'],
}

def require_process_tree_supervisor():
    """Refuse execution until bounded, authenticated tree supervision exists.

    A direct-child pidfd alone cannot establish that descendants terminated or
    that it is safe to release the shared-target lock. No process is started.
    """
    raise Blocked('bounded process-tree supervision is unavailable')


def run_bounded(command, stdout_path, stderr_path, *, env, pass_fds=(), timeout=900):
    """Refuse before opening logs or launching an unsupervised child."""
    require_process_tree_supervisor()
    # The check currently never returns. Do not add a fallback process launch;
    # implement and independently review a real supervisor before enabling it.
    raise Blocked('bounded process runner is not implemented')


def sandbox_inputs(run_dir, source_dir):
    home=Path.home()
    need(home == Path('/home/chenyoujian'),'unregistered sandbox home path')
    need(not os.environ.get('CARGO_HOME') and not os.environ.get('RUSTUP_HOME'), 'custom Rust home is not bound')
    inputs={
        'usr':Path('/usr'), 'rustup':home/'.rustup', 'cargo_bin':home/'.cargo/bin',
        'cargo_registry':home/'.cargo/registry', 'npm_cache':home/'.npm/_cacache',
        'source':source_dir, 'target':run_dir/'target', 'modules':run_dir/'node_modules',
        'dist':run_dir/'dist', 'cache':run_dir/'npm-cache',
    }
    fds={}
    try:
        for name,path in inputs.items():
            _,fds[name]=no_symlink_dir(path)
        return fds
    except BaseException:
        for fd in fds.values():os.close(fd)
        raise

def sandbox_command(fds, command, cwd):
    # No host HOME, /run, /mnt or real /tmp is mounted. Dependency caches are
    # individually read-only; only project-quota-bound run subdirectories write.
    return ['/usr/bin/bwrap','--die-with-parent','--unshare-user','--unshare-pid',
            '--unshare-net','--unshare-ipc','--unshare-uts','--cap-drop','ALL',
            '--ro-bind-fd',str(fds['usr']),'/usr',
            '--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
            '--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev',
            '--size',str(128*1024*1024),'--tmpfs','/tmp',
            '--dir','/home','--dir','/home/chenyoujian','--dir','/home/chenyoujian/.cargo',
            '--dir','/home/chenyoujian/.cache',
            '--ro-bind-fd',str(fds['rustup']),'/home/chenyoujian/.rustup',
            '--ro-bind-fd',str(fds['cargo_bin']),'/home/chenyoujian/.cargo/bin',
            '--ro-bind-fd',str(fds['cargo_registry']),'/home/chenyoujian/.cargo/registry',
            '--bind-fd',str(fds['target']),str(TARGET),
            '--ro-bind-fd',str(fds['source']),'/src',
            '--bind-fd',str(fds['modules']),'/src/console/node_modules',
            '--bind-fd',str(fds['dist']),'/src/console/dist',
            '--bind-fd',str(fds['cache']),'/cache',
            '--ro-bind-fd',str(fds['npm_cache']),'/cache/_cacache',
            '--chdir',cwd,'--',*command]

def safe_environment():
    # Preserve the user's home value; never redirect HOME to a fabricated path.
    home=os.environ.get('HOME')
    need(home=='/home/chenyoujian','unregistered HOME for sandbox')
    bad=('RUSTC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_RUSTC',
         'CARGO_BUILD_RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
         'BASH_ENV','ENV','LD_PRELOAD','NODE_OPTIONS')
    need(not any(os.environ.get(name) for name in bad),'unsafe compiler or interpreter override')
    # No database credentials, model credentials, proxy settings, user hooks or
    # dynamic library preload controls are inherited.
    return {'HOME':home,'PATH':home+'/.cargo/bin:/usr/bin:/bin','LANG':'C.UTF-8',
            'CARGO_TARGET_DIR':str(TARGET),'CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0',
            'CARGO_NET_OFFLINE':'true','TMPDIR':'/tmp','npm_config_cache':'/cache',
            'npm_config_update_notifier':'false','npm_config_audit':'false','npm_config_fund':'false'}

def save_json(path, value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2,sort_keys=True);stream.write('\n')

def rust_test_counts(stdout):
    text=Path(stdout).read_text(errors='strict')
    running=[int(x) for x in re.findall(r'^running (\d+) tests?$',text,re.M)]
    results=re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;',text,re.M)
    if not results or len(results)!=len(running):return None
    passed=failed=ignored=filtered=0
    for n,(status,p,f,i,m,flt) in zip(running,results):
        p,f,i,flt=map(int,(p,f,i,flt))
        if n!=p+f+i or status!='ok':return None
        passed+=p;failed+=f;ignored+=i;filtered+=flt
    if passed<=0 or failed or ignored or filtered:return None
    return {'total':passed,'passed':passed,'failed':0,'ignored':0,'filtered_out':0}

def capture_tools(build_module, root, env):
    previous=dict(os.environ)
    try:
        os.environ.clear();os.environ.update(env)
        return {name:build_module.executable_identity(name,root) for name in ('cargo','rustc','node','npm')}
    finally:
        os.environ.clear();os.environ.update(previous)

def check_source_copy(snapshot_module, source_copy, expected, blobs, expected_inventory):
    # Mountpoint directories are known empty host directories, visible only as
    # writable overlays inside the namespace. Never remove nonempty contents.
    mounts=(source_copy/'console/node_modules',source_copy/'console/dist')
    for path in mounts:path.rmdir()
    try:
        inventory=snapshot_module.candidate_inventory(source_copy,expected,blobs)
        need(inventory==expected_inventory,'isolated source candidate drifted')
    finally:
        for path in mounts:
            if not path.exists():path.mkdir(mode=0o700)
    return inventory

def sandbox_probe(fds, evidence, env):
    # No writable real home/network socket/host temporary directory is mounted.
    code=("import errno,json,os,socket,subprocess\n"
          "s=os.stat('"+str(TARGET)+"');v={'net':os.readlink('/proc/self/ns/net'),'target_dev':s.st_dev,'target_ino':s.st_ino}\n"
          "try:\n open('/src/Cargo.toml','ab').close();v['source_readonly']=False\n"
          "except OSError as e:\n v['source_readonly']=e.errno in (errno.EROFS,errno.EACCES,errno.EPERM)\n"
          "v['caps_zero']=next(x.split()[1] for x in open('/proc/self/status') if x.startswith('CapEff:'))=='0000000000000000'\n"
          "v['remount_refused']=subprocess.run(['/usr/bin/mount','-o','remount,rw','/src'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10).returncode!=0\n"
          "v['host_socket_absent']=not os.path.exists('/run/postgresql');print(json.dumps(v))\n")
    command=sandbox_command(fds,['/usr/bin/python3','-c',code],'/src')
    out=evidence/'sandbox-probe.stdout';err=evidence/'sandbox-probe.stderr'
    record=run_bounded(command,out,err,env=env,pass_fds=fds.values(),timeout=30)
    need(record['exit_code']==0 and record['logs_complete'],'read-only sandbox probe failed')
    result=json.loads(out.read_text());host=os.stat(fds['target'])
    need(result.get('source_readonly') is True and result.get('host_socket_absent') is True
         and result.get('caps_zero') is True and result.get('remount_refused') is True,
         'sandbox source or host socket isolation unavailable')
    need(result.get('net')!=os.readlink('/proc/self/ns/net'),'sandbox network namespace not isolated')
    need((result.get('target_dev'),result.get('target_ino'))==(host.st_dev,host.st_ino),
         'sandbox target binding does not match private quota subtree')
    return record

def artifact_inventory(build_module, run_dir):
    target=run_dir/'target';values={}
    for name in ('forgeflow-server','forgeflow-worker','forgeflow-sandbox-guard','forgeflow'):
        fd=build_module.open_artifact(target,Path('debug')/name)
        try:values[name]=build_module.digest_fd(fd)
        finally:os.close(fd)
    _,fd=no_symlink_dir(run_dir/'dist')
    try:values['frontend']=build_module.bundle_inventory(fd)
    finally:os.close(fd)
    need(bool(values['frontend']),'frontend bundle is empty')
    return values

def materialize_git_objects(destination, expected, blobs, snapshot):
    """Construct private source from already-verified Git blobs, not live paths."""
    destination.mkdir(mode=0o700)
    _,rootfd=no_symlink_dir(destination)
    try:
        for path,(mode,oid) in sorted(expected.items()):
            relative=snapshot.safe_path(path);fd=os.dup(rootfd)
            try:
                for part in relative.parts[:-1]:
                    try:os.mkdir(part,0o700,dir_fd=fd)
                    except FileExistsError:pass
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                    os.close(fd);fd=child
                payload=blobs[oid];name=relative.parts[-1]
                if mode=='120000':
                    target=os.fsdecode(payload);snapshot.safe_link(relative,target)
                    os.symlink(target,name,dir_fd=fd)
                else:
                    need(mode in ('100644','100755'),'unsupported Git source mode')
                    out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
                    try:
                        for start in range(0,len(payload),1024*1024):
                            data=memoryview(payload)[start:start+1024*1024]
                            while data:data=data[os.write(out,data):]
                        os.fchmod(out,0o755 if mode=='100755' else 0o644)
                    finally:os.close(out)
            finally:os.close(fd)
    finally:os.close(rootfd)

def run_workload(source, candidate, manifest, p001_receipt, source_sha, manifest_sha, evidence, quota, progress):
    require_process_tree_supervisor()
    snapshot=module(source/'verification/ecp/p005_snapshot_oracle.py','p005_source_oracle')
    build=module(source/'ops/ecp/build_manifest.py','p005_build_identity')
    review=snapshot.review(str(source),str(candidate),str(manifest),str(p001_receipt),source_sha,manifest_sha)
    save_json(evidence/'source-review.json',review)
    need(review.get('status')=='OBSERVED_NOT_GATE' and review.get('source_execution_mode')=='VERIFIED',
         'independent source review or source execution mode is not conclusive')
    progress['source_review']='OBSERVED_NOT_GATE'
    expected,blobs,_=snapshot.object_tree(source,source_sha)
    expected_inventory={k:review[k] for k in ('candidate_inventory_sha256','candidate_file_count','candidate_tree_bytes')}
    env=safe_environment()
    before_tools=capture_tools(build,candidate,env)
    # The only fresh output directory is created inside the pre-verified shared
    # target project. Its allocation cannot escape the project hard limit.
    parent=TARGET/'ecp-p005'
    if not parent.exists():parent.mkdir(mode=0o700)
    need(parent.is_dir() and not parent.is_symlink(),'private build parent is unsafe')
    run_dir=parent/(evidence.name+'-'+os.urandom(8).hex());run_dir.mkdir(mode=0o700)
    progress['run_dir']=str(run_dir)
    for name in ('target','node_modules','dist','npm-cache'):(run_dir/name).mkdir(mode=0o700)
    (run_dir/'npm-cache'/'_cacache').mkdir(mode=0o700)
    before_links=project_quota(TARGET)
    need(before_links['project_id']==quota['project_id'] and before_links['hard_limit_bytes']==quota['hard_limit_bytes'],
         'project quota changed before symlink accounting probe')
    link_probe=symlink_quota_probe(run_dir,before_links)
    save_json(evidence/'quota-symlink-probe.json',link_probe)
    source_copy=run_dir/'source';materialize_git_objects(source_copy,expected,blobs,snapshot)
    need(snapshot.candidate_inventory(source_copy,expected,blobs)==expected_inventory,'copied source differs from Git candidate')
    for path in (source_copy/'console/node_modules',source_copy/'console/dist'):path.mkdir(mode=0o700)
    # Verify the inheritance after creating all output directories and before
    # executing any dependency or compiler command.
    after_create=project_quota(TARGET,allow_inherited_symlinks=True)
    need(after_create['project_id']==quota['project_id'] and after_create['hard_limit_bytes']==quota['hard_limit_bytes'],
         'project quota changed while preparing sandbox')
    fds=sandbox_inputs(run_dir,source_copy)
    phases=[]
    try:
        sandbox=sandbox_probe(fds,evidence,env)
        progress['sandbox_probe']='PASS'
        for name in PHASES:
            command=sandbox_command(fds,COMMANDS[name],'/src/console' if name.startswith('npm_') else '/src')
            stdout=evidence/(name+'.stdout');stderr=evidence/(name+'.stderr')
            record=run_bounded(command,stdout,stderr,env=env,pass_fds=fds.values())
            record.update(name=name,command=COMMANDS[name],source_sha=source_sha,
                          candidate_inventory_sha256=expected_inventory['candidate_inventory_sha256'])
            phases.append(record)
            try:
                if record['exit_code']!=0 or not record['logs_complete']:
                    progress['workloads'][name]='FAIL'
                    raise Failed(name+' did not complete successfully')
                if name=='cargo_test':
                    record['denominator']=rust_test_counts(stdout)
                    if record['denominator'] is None:
                        progress['workloads'][name]='FAIL'
                        raise Failed('Rust tests have zero, skipped, failed or unverifiable denominator')
                record['source_after']=check_source_copy(snapshot,source_copy,expected,blobs,expected_inventory)
                record['tool_identity']=capture_tools(build,candidate,env)
                need(record['tool_identity']==before_tools,'build tool identity changed')
                current=project_quota(TARGET,allow_inherited_symlinks=True)
                need(current['project_id']==quota['project_id'] and current['hard_limit_bytes']==quota['hard_limit_bytes'],
                     'project quota changed during workload')
                record['quota_after']=current
                progress['workloads'][name]='PASS_OBSERVED'
            finally:
                save_json(evidence/(name+'.json'),record)
        artifacts=artifact_inventory(build,run_dir)
        return {'status':'INCONCLUSIVE','reason':'workload observed but independent authorized execution and product Gate remain unproven',
                'source_sha':source_sha,'source_manifest_sha256':manifest_sha,
                'candidate_inventory_sha256':expected_inventory['candidate_inventory_sha256'],
                'tool_identity':before_tools,'quota':quota,'sandbox_probe':sandbox,'phases':phases,
                'run_dir':str(run_dir),'artifacts':artifacts,'product_gate_effect':'NONE'}
    finally:
        for fd in fds.values():os.close(fd)

def execute_suite(args, source, source_sha, base_report):
    """Run fixed offline commands only after every local safety precondition."""
    report=dict(base_report)
    report.update(status='BLOCKED',qualification='NOT_RUN',suite_id='ECP-P0-05',
                  profile=args.profile,product_gate_effect='NONE',
                  reason='build preconditions not yet established',
                  workloads={name:'NOT_RUN' for name in PHASES},source_review='NOT_RUN',
                  sandbox_probe='NOT_RUN',checks=[])
    evidence=None;evidence_created=False;output=None;lockfd=None;code=20
    try:
        need(args.profile=='isolated','only isolated P0-05 profile is supported')
        need(source == ROOT and source == Path('/mnt/d/Product/ForgeFlow/control'), 'source root is not the registered product root')
        need(bool(source_sha),'source SHA is unavailable')
        need(bool(args.evidence_root),'fresh evidence root is required')
        evidence=Path(os.path.abspath(args.evidence_root))
        need(evidence!=source and source not in evidence.parents and evidence!=TARGET and TARGET not in evidence.parents,
             'evidence must be outside the source and build target')
        _,parentfd=no_symlink_dir(evidence.parent)
        try:os.mkdir(evidence.name,0o700,dir_fd=parentfd);evidence_created=True
        finally:os.close(parentfd)
        if args.output:
            output=Path(os.path.abspath(args.output))
            need(output!=source and source not in output.parents and output!=TARGET and TARGET not in output.parents,
                 'result output must be outside source and target')
            _,fd=no_symlink_dir(output.parent);os.close(fd)
            need(not os.path.lexists(output),'result output already exists')
            need(output==evidence/'result.json' or evidence not in output.parents,'external output may not collide with evidence files')
        # Evidence output is retained, but do not acquire a lock, scan or
        # mutate the shared target before tree supervision is available.
        require_process_tree_supervisor()
        lockfd=os.open(BUILD_LOCK,os.O_RDWR|os.O_NOFOLLOW)
        try:fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:raise Blocked('coordinated build lock is busy') from exc
        measured=scan_target(TARGET);report['checks'].append({'name':'target_budget',**measured})
        need(measured['status']=='PASS','shared build target is over budget or has unsafe entries')
        # Read-only process reference probe. Its uncertainty forbids a build;
        # unlike enforce_cache_budget it never retires or deletes any cache.
        checkpoint=module(source/'team/build_checkpoint.py','p005_checkpoint_readonly')
        refs=checkpoint.target_references(TARGET)
        report['checks'].append({'name':'target_references','status':'BLOCKED' if refs else 'PASS','references':refs})
        need(not refs,'shared build target has active or unreadable process references')
        quota=project_quota(TARGET);report['checks'].append({'name':'project_quota',**quota})
        need(bool(args.candidate_root) and bool(args.p005_manifest) and bool(args.p005_receipt)
             and bool(args.p005_manifest_sha256),'pinned P0-01 manifest, receipt and candidate are required')
        candidate=Path(os.path.abspath(args.candidate_root))
        need(candidate!=TARGET and TARGET not in candidate.parents and candidate not in TARGET.parents,
             'source candidate must be outside the shared target')
        need(evidence!=candidate and candidate not in evidence.parents and evidence not in candidate.parents,
             'evidence and candidate paths overlap')
        workload=run_workload(source,candidate,Path(args.p005_manifest),Path(args.p005_receipt),source_sha,
                              args.p005_manifest_sha256,evidence,quota,report)
        save_json(evidence/'workload.json',workload)
        oracle=module(source/'verification/ecp/p005_build_oracle.py','p005_independent_build_oracle')
        independent=oracle.review(str(evidence),source_sha,args.p005_manifest_sha256)
        save_json(evidence/'independent-review.json',independent)
        need(independent.get('status')=='INCONCLUSIVE' and independent.get('product_gate_effect')=='NONE',
             'independent build review did not preserve its trust boundary')
        report.update(status='INCONCLUSIVE',reason='workload observed; authorized A10 execution and product Gate remain unproven')
    except Failed as exc:
        report.update(status='FAIL',reason=str(exc));code=10
    except (Blocked,OSError,ValueError,TypeError,subprocess.SubprocessError) as exc:
        report.update(status='BLOCKED',reason=str(exc));code=20
    finally:
        if lockfd is not None:
            try:fcntl.flock(lockfd,fcntl.LOCK_UN)
            finally:os.close(lockfd)
    report['denominator']={'total':len(PHASES),'passed':sum(v=='PASS_OBSERVED' for v in report['workloads'].values()),
                           'failed':sum(v=='FAIL' for v in report['workloads'].values()),
                           'not_run':sum(v=='NOT_RUN' for v in report['workloads'].values()),
                           'blocked':0,'inconclusive':0,'skipped':0}
    if evidence_created:
        report['evidence_refs']=[str(evidence/name) for name in ('result.json','manifest.json','stdout.log','stderr.log')]
        save_json(evidence/'manifest.json',{'suite_id':'ECP-P0-05','source_sha':source_sha,
                  'status':report['status'],'product_gate_effect':'NONE','scope':'runner observation; no product Gate',
                  'workloads':report['workloads'],'checks':report['checks']})
        for name,value in [('stdout.log',json.dumps({'status':report['status'],'scope':'preflight and runner outcome'})+'\n'),
                           ('stderr.log',report['reason']+'\n')]:
            fd=os.open(evidence/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as stream:stream.write(value)
        save_json(evidence/'result.json',report)
        if output is not None and output!=evidence/'result.json':save_json(output,report)
    print(json.dumps(report,ensure_ascii=False,sort_keys=True))
    return report,code

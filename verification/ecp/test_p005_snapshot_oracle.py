from __future__ import annotations
import copy
import hashlib
import errno
import importlib.util
import contextlib
import io
import json
import os
import signal
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'ops/ecp'))
import source_snapshot
import materialize_snapshot
spec=importlib.util.spec_from_file_location('p005_snapshot_oracle', Path(__file__).with_name('p005_snapshot_oracle.py'))
oracle=importlib.util.module_from_spec(spec); spec.loader.exec_module(oracle)

class SnapshotOracleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='p005-oracle-'); self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name); self.fixture()

    def fixture(self, object_format='sha1'):
        self.source=self.base/('source-'+object_format);self.source.mkdir()
        command=['git','init','-q']
        if object_format=='sha256':command.append('--object-format=sha256')
        subprocess.run(command,cwd=self.source,check=True,capture_output=True)
        for name,value in [('user.name','Fixture'),('user.email','fixture@example.invalid')]:
            subprocess.run(['git','config',name,value],cwd=self.source,check=True)
        (self.source/'README').write_text('fixture text\n')
        (self.source/'src').mkdir();(self.source/'src'/'tool').write_text('#!/bin/sh\nexit 0\n')
        (self.source/'src'/'tool').chmod(0o755)
        (self.source/'src'/'link').symlink_to('../README')
        (self.source/'evidence').mkdir();(self.source/'evidence'/'tracked.txt').write_text('excluded yet tracked\n')
        subprocess.run(['git','add','.'],cwd=self.source,check=True)
        subprocess.run(['git','commit','-qm','fixture'],cwd=self.source,check=True)
        self.sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.source,text=True).strip()
        self.manifest=source_snapshot.build_manifest(self.source,source_snapshot.DEFAULT_EXCLUDES)
        self.assertEqual(self.manifest['worktree_state'],'CLEAN')
        self.candidate=self.base/('candidate-'+object_format)
        self.receipt=materialize_snapshot.materialize_snapshot(self.source,self.manifest,self.candidate)
        self.manifest_file=self.base/('manifest-'+object_format+'.json')
        self.receipt_file=self.base/('receipt-'+object_format+'.json')
        self.save()

    def test_git_capture_selector_setup_failure_reaps_only_owned_child(self):
        real_popen=subprocess.Popen;real_killpg=os.killpg
        for failure in ('selector','registration'):
            with self.subTest(failure=failure):
                children=[]
                sentinel=real_popen([sys.executable,'-c','import time;time.sleep(30)'],start_new_session=True)
                def start(_command,**kwargs):
                    proc=real_popen([sys.executable,'-c','import time;time.sleep(30)'],**kwargs)
                    children.append(proc);return proc
                selector=oracle.selectors.DefaultSelector()
                register=selector.register; calls=[]
                def register_once(*args,**kwargs):
                    calls.append(True)
                    if len(calls)==2:raise OSError('synthetic second registration failure')
                    return register(*args,**kwargs)
                selector_factory=(patch.object(oracle.selectors,'DefaultSelector',side_effect=OSError('synthetic selector failure'))
                    if failure=='selector' else patch.object(oracle.selectors,'DefaultSelector',return_value=selector))
                try:
                    with patch.object(oracle.subprocess,'Popen',side_effect=start), selector_factory:
                        if failure=='registration':
                            with patch.object(selector,'register',side_effect=register_once):
                                with self.assertRaises(OSError):oracle.run_git(self.source,['rev-parse','HEAD'])
                        else:
                            with self.assertRaises(OSError):oracle.run_git(self.source,['rev-parse','HEAD'])
                    self.assertEqual(len(children),1)
                    self.assertIsNotNone(children[0].poll(),'started child was not reaped')
                    self.assertIsNone(sentinel.poll(),'unrelated sentinel must remain running')
                finally:
                    selector.close()
                    for proc in children:
                        if proc.poll() is None:
                            try:real_killpg(proc.pid,signal.SIGKILL)
                            except ProcessLookupError:pass
                        proc.wait(timeout=5)
                    sentinel.terminate();sentinel.wait(timeout=5)

    def test_git_capture_signal_failure_reports_unknown_even_if_leader_exits(self):
        real_popen=subprocess.Popen;real_killpg=os.killpg;children=[]
        selector=oracle.selectors.DefaultSelector();real_select=selector.select;select_calls=[]
        def read_once_then_fail(timeout):
            select_calls.append(True)
            if len(select_calls)>1:raise OSError('synthetic select failure')
            return real_select(timeout)
        def start(_command,**kwargs):
            proc=real_popen([sys.executable,'-c','import os,time;os.write(1,b"partial");time.sleep(0.2)'],**kwargs)
            children.append(proc);return proc
        try:
            with patch.object(oracle.subprocess,'Popen',side_effect=start), \
                 patch.object(oracle.selectors,'DefaultSelector',return_value=selector), \
                 patch.object(selector,'select',side_effect=read_once_then_fail), \
                 patch.object(oracle.os,'killpg',side_effect=PermissionError('synthetic signal failure')):
                with self.assertRaises(getattr(oracle,'GitTerminationUnconfirmed',oracle.Indeterminate)) as caught:
                    oracle.run_git(self.source,['rev-parse','HEAD'])
            self.assertEqual(caught.exception.signal_status,'FAILED')
            self.assertTrue(caught.exception.leader_reaped)
            self.assertIsNone(caught.exception.descendants_terminated)
            self.assertEqual(caught.exception.stdout_bytes,b'partial')
            self.assertEqual(caught.exception.stderr_bytes,b'')
        finally:
            for proc in children:
                if proc.poll() is None:
                    try:real_killpg(proc.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                proc.wait(timeout=5)

    def test_git_capture_unconfirmed_leader_wait_is_not_a_plain_setup_error(self):
        real_popen=subprocess.Popen;real_killpg=os.killpg;children=[];waits=[]
        selector=oracle.selectors.DefaultSelector()
        def start(_command,**kwargs):
            proc=real_popen([sys.executable,'-c','import time;time.sleep(30)'],**kwargs)
            children.append(proc);real_wait=proc.wait;waits.append(real_wait)
            def unconfirmed(*_args,**_kwargs):raise subprocess.TimeoutExpired(proc.args,3)
            proc.wait=unconfirmed
            return proc
        try:
            with patch.object(oracle.subprocess,'Popen',side_effect=start), \
                 patch.object(oracle.selectors,'DefaultSelector',return_value=selector), \
                 patch.object(selector,'select',side_effect=OSError('synthetic select failure')), \
                 patch.object(oracle.os,'killpg',side_effect=PermissionError('synthetic signal failure')):
                with self.assertRaises(getattr(oracle,'GitTerminationUnconfirmed',oracle.Indeterminate)) as caught:
                    oracle.run_git(self.source,['rev-parse','HEAD'])
            self.assertEqual(caught.exception.signal_status,'FAILED')
            self.assertFalse(caught.exception.leader_reaped)
            self.assertIsNone(caught.exception.descendants_terminated)
            self.assertEqual(caught.exception.wait_error,'TimeoutExpired')
        finally:
            for proc,real_wait in zip(children,waits):
                try:real_killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                proc.wait=real_wait;proc.wait(timeout=5)

    def test_git_capture_start_failure_does_not_signal_unowned_process(self):
        with patch.object(oracle.subprocess,'Popen',side_effect=FileNotFoundError('missing git')), \
             patch.object(oracle.os,'killpg',side_effect=AssertionError('no process to signal')) as kill:
            with self.assertRaises(FileNotFoundError):oracle.run_git(self.source,['rev-parse','HEAD'])
        kill.assert_not_called()

    def test_git_termination_unknown_is_structured_in_cli_without_raw_output(self):
        failure=oracle.GitTerminationUnconfirmed('FAILED',False,b'private stdout',b'private stderr','TimeoutExpired')
        args=['oracle','--source','/source','--candidate','/candidate','--source-sha','a'*40,
              '--manifest-sha256','b'*64,'--manifest-version','3','--manifest-fd','3','--receipt-fd','4']
        output=io.StringIO()
        with patch.object(sys,'argv',args), patch.object(oracle,'review_v3_fds',side_effect=failure), \
             contextlib.redirect_stdout(output):
            code=oracle.main()
        text=output.getvalue();value=json.loads(text)
        self.assertEqual((code,value['status'],value['qualification'],value['product_gate_effect']),
                         (20,'INCONCLUSIVE','NOT_RUN','NONE'))
        self.assertEqual((value['reason_code'],value['leader_reaped'],value['group_signal'],value['descendants_terminated']),
                         ('GIT_TERMINATION_UNCONFIRMED',False,'FAILED',None))
        self.assertEqual(value['git_capture'],{'status':'UNKNOWN','wait_error':'TimeoutExpired',
            'stdout_bytes':len(b'private stdout'),'stdout_sha256':hashlib.sha256(b'private stdout').hexdigest(),
            'stderr_bytes':len(b'private stderr'),'stderr_sha256':hashlib.sha256(b'private stderr').hexdigest(),
            'raw_output_persistence':'UNAVAILABLE'})
        self.assertNotIn('private stdout',text);self.assertNotIn('private stderr',text)

    def test_git_capture_never_signals_after_wait_has_reaped_leader(self):
        real_popen=subprocess.Popen;real_killpg=os.killpg;children=[];real_waits=[]
        def start(_command,**kwargs):
            proc=real_popen([sys.executable,'-c','pass'],**kwargs);children.append(proc)
            real_wait=proc.wait;real_waits.append(real_wait)
            def reap_then_raise(*args,**kwargs):
                real_wait(*args,**kwargs)
                raise OSError('synthetic post-wait exception')
            proc.wait=reap_then_raise
            return proc
        try:
            with patch.object(oracle.subprocess,'Popen',side_effect=start), \
                 patch.object(oracle.os,'killpg',side_effect=AssertionError('reaped PID must not be signaled')) as kill:
                with self.assertRaises(oracle.GitTerminationUnconfirmed) as caught:
                    oracle.run_git(self.source,['rev-parse','HEAD'])
            kill.assert_not_called()
            self.assertEqual(caught.exception.signal_status,'NOT_SENT_LEADER_REAPED')
            self.assertTrue(caught.exception.leader_reaped)
            self.assertIsNone(caught.exception.descendants_terminated)
        finally:
            for proc,real_wait in zip(children,real_waits):
                proc.wait=real_wait
                if proc.poll() is None:
                    try:real_killpg(proc.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                proc.wait(timeout=5)

    def test_git_capture_close_failure_does_not_hide_primary_error(self):
        real_popen=subprocess.Popen;real_killpg=os.killpg;children=[]
        selector=oracle.selectors.DefaultSelector();real_close=selector.close
        def close_then_fail():
            real_close();raise OSError('synthetic close failure')
        def start(_command,**kwargs):
            proc=real_popen([sys.executable,'-c','import time;time.sleep(30)'],**kwargs)
            children.append(proc);return proc
        try:
            with patch.object(oracle.subprocess,'Popen',side_effect=start), \
                 patch.object(oracle.selectors,'DefaultSelector',return_value=selector), \
                 patch.object(selector,'select',side_effect=OSError('synthetic select failure')), \
                 patch.object(selector,'close',side_effect=close_then_fail):
                with self.assertRaisesRegex(OSError,'synthetic select failure') as caught:
                    oracle.run_git(self.source,['rev-parse','HEAD'])
            self.assertIsNotNone(children[0].poll())
            self.assertTrue(any('descriptor cleanup failed' in x for x in getattr(caught.exception,'__notes__',[])))
            self.assertTrue(children[0].stdout.closed)
            self.assertTrue(children[0].stderr.closed)
        finally:
            for proc in children:
                if proc.poll() is None:
                    try:real_killpg(proc.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                proc.wait(timeout=5)

    def save(self):
        self.manifest_file.write_text(json.dumps(self.manifest,ensure_ascii=False))
        self.receipt_file.write_text(json.dumps(self.receipt,ensure_ascii=False))

    def digest_manifest(self):
        value={k:v for k,v in self.manifest.items() if k not in ('manifest_sha256','created_at','release_qualifiable')}
        self.manifest['manifest_sha256']=hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def review(self):
        return oracle.review(str(self.source),str(self.candidate),str(self.manifest_file),str(self.receipt_file),self.sha,self.manifest['manifest_sha256'])

    def reject(self):
        with self.assertRaises((oracle.Invalid, OSError, ValueError, subprocess.SubprocessError)):
            self.review()

    def prepare_v3(self):
        # Construct the evidence independently of the v3 producer and materializer.
        prefix = Path('docs/idea/ForgeFlow_ECP_完整开发规划')
        boundary = self.source/prefix/'evidence'
        boundary.mkdir(parents=True)
        (boundary/'history.log').write_text('preserved history')
        (self.candidate/prefix).mkdir(parents=True)
        paths = ['.', 'docs', 'docs/idea', prefix.as_posix(), 'src']
        records = []
        for path in paths:
            source_path = self.source if path == '.' else self.source/path
            candidate_path = self.candidate if path == '.' else self.candidate/path
            mode = f'{source_path.stat().st_mode & 0o7777:04o}'
            candidate_path.chmod(int(mode, 8))
            records.append({'path':path, 'kind':'directory', 'mode':mode,
                            'origin':'source_root' if path == '.' else
                                     'git_ancestor' if path == 'src' else 'excluded_container'})
        projection = {'version':'forgeflow.ecp-directory-projection.v1', 'mode_availability':'VERIFIED',
                      'exclusion_policy_sha256':hashlib.sha256(oracle._v3_canonical(list(oracle.V3_EXCLUDES))).hexdigest(),
                      'directories':records, 'excluded_directory_boundaries':[
                          {'path':'.git','kind':'directory','excluded_by':'.git/'},
                          {'path':(prefix/'evidence').as_posix(),'kind':'directory',
                           'excluded_by':'docs/idea/ForgeFlow_ECP_完整开发规划/evidence/'},
                          {'path':'evidence','kind':'directory','excluded_by':'evidence/'},
                      ]}
        self.manifest.update(schema_version='forgeflow.ecp-source-manifest.v3', release_qualifiable=False,
                             exclude_patterns=list(oracle.V3_EXCLUDES), directory_projection=projection,
                             projection_sha256=hashlib.sha256(oracle._v3_canonical(projection)).hexdigest())
        self.digest_manifest()
        file_rows=[]; total=0
        for path in ('README','src/link','src/tool'):
            actual=self.candidate/path; info=actual.lstat()
            row={'path':path,'mode':f'{info.st_mode & 0o7777:04o}'}
            if actual.is_symlink():
                target=os.readlink(actual);payload=os.fsencode(target)
                row.update(kind='symlink',target=target,sha256=hashlib.sha256(payload).hexdigest())
            else:
                payload=actual.read_bytes();total+=len(payload)
                row.update(kind='file',sha256=hashlib.sha256(payload).hexdigest())
            file_rows.append(row)
        inventory={'directories':[{k:row[k] for k in ('path','kind','mode')} for row in records], 'files':file_rows}
        self.receipt={'status':'OBSERVED_NOT_GATE','qualification':'NOT_RUN','product_gate_effect':'NONE',
                      'release_qualifiable':False,'source_root':str(self.source),'candidate_root':str(self.candidate),
                      'source_manifest_sha256':self.manifest['manifest_sha256'],
                      'source_projection_sha256':self.manifest['projection_sha256'],
                      'candidate_inventory_v3_sha256':hashlib.sha256(oracle._v3_canonical(inventory)).hexdigest(),
                      'candidate_directory_count':len(records),'candidate_file_count':len(file_rows),
                      'candidate_tree_bytes':total,'source_unchanged':True,'git_metadata_removed':True}
        self.save()

    def review_v3(self):
        return oracle.review_v3(str(self.source),str(self.candidate),str(self.manifest_file),
                                str(self.receipt_file),self.sha,self.manifest['manifest_sha256'])

    def resign_v3(self):
        projection=self.manifest['directory_projection']
        self.manifest['projection_sha256']=hashlib.sha256(oracle._v3_canonical(projection)).hexdigest()
        self.digest_manifest()
        self.receipt['source_manifest_sha256']=self.manifest['manifest_sha256']
        self.receipt['source_projection_sha256']=self.manifest['projection_sha256']
        self.save()

    def window_fds(self):
        fds=[]
        try:
            for path,flags in ((self.source,os.O_RDONLY|os.O_DIRECTORY),
                               (self.candidate,os.O_RDONLY|os.O_DIRECTORY),
                               (self.manifest_file,os.O_RDONLY),(self.receipt_file,os.O_RDONLY)):
                fd=os.open(path,flags|os.O_NOFOLLOW);fds.append(fd)
                self.addCleanup(os.close,fd)
            return fds
        except BaseException:
            # addCleanup owns descriptors opened before a failure.
            raise

    def capture_window(self, fds):
        return oracle.capture_v3_window_fds(str(self.source),str(self.candidate),*fds,
                                             self.sha,self.manifest['manifest_sha256'])

    def compare_window(self, fds, baseline):
        return oracle.compare_v3_window_fds(str(self.source),str(self.candidate),*fds,
                                             self.sha,self.manifest['manifest_sha256'],baseline,
                                             baseline['identity_sha256'])

    def test_v3_window_unchanged_endpoints_are_inconclusive(self):
        self.prepare_v3();fds=self.window_fds()
        os.lseek(fds[2],7,os.SEEK_SET);os.lseek(fds[3],3,os.SEEK_SET)
        baseline=self.capture_window(fds)
        compared=self.compare_window(fds,baseline)
        self.assertEqual((compared['status'],compared['qualification'],compared['product_gate_effect']),
                         ('INCONCLUSIVE','NOT_RUN','NONE'))
        self.assertEqual(compared['baseline_sha256'],compared['current_sha256'])
        self.assertEqual((os.lseek(fds[2],0,os.SEEK_CUR),os.lseek(fds[3],0,os.SEEK_CUR)),(7,3))
        self.assertIn('uninterrupted immutability',compared['reason'])

    def test_v3_window_brackets_a_real_read_only_fixture_workload(self):
        self.prepare_v3();fds=self.window_fds();baseline=self.capture_window(fds)
        command=['/usr/bin/python3','-I','-S','-c',
                 "import hashlib,pathlib; print(hashlib.sha256(pathlib.Path('README').read_bytes()).hexdigest())"]
        run=subprocess.run(command,cwd=self.candidate,env={'PATH':'/usr/bin:/bin'},
                           stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10,check=True)
        self.assertEqual(run.stdout.strip(),hashlib.sha256((self.source/'README').read_bytes()).hexdigest())
        self.assertEqual(run.stderr,'')
        self.assertEqual(self.compare_window(fds,baseline)['status'],'INCONCLUSIVE')

    def test_v3_window_explicitly_does_not_monitor_excluded_contents(self):
        self.prepare_v3();fds=self.window_fds();baseline=self.capture_window(fds)
        history=self.source/'docs/idea/ForgeFlow_ECP_完整开发规划/evidence/history.log'
        history.write_text('changed excluded evidence')
        result=self.compare_window(fds,baseline)
        self.assertEqual(result['status'],'INCONCLUSIVE')
        self.assertIn('excluded contents are not inventoried',result['scope'])

    def test_v3_window_explicitly_does_not_monitor_physical_git_index(self):
        self.prepare_v3();fds=self.window_fds();baseline=self.capture_window(fds)
        index=self.source/'.git/index';before=index.stat();data=index.read_bytes()
        index.write_bytes(data);after=index.stat()
        self.assertEqual((before.st_dev,before.st_ino),(after.st_dev,after.st_ino))
        self.assertNotEqual((before.st_mtime_ns,before.st_ctime_ns),(after.st_mtime_ns,after.st_ctime_ns))
        self.assertEqual(index.read_bytes(),data)
        self.assertIs(baseline['identity']['source_physical_git_index_observed'],False)
        result=self.compare_window(fds,baseline)
        self.assertEqual(result['status'],'INCONCLUSIVE')
        self.assertIn('physical Git index identity',result['scope'])

    def physical_index_fds(self, parent):
        parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        self.addCleanup(os.close,parent_fd)
        index_fd=os.open('index',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent_fd)
        self.addCleanup(os.close,index_fd)
        return parent_fd,index_fd

    def capture_window_with_index(self, fds, parent, index_fds):
        return oracle.capture_v3_window_with_index_fds(str(self.source),str(self.candidate),*fds,
            self.sha,self.manifest['manifest_sha256'],str(parent),*index_fds)

    def compare_window_with_index(self, fds, parent, index_fds, baseline):
        return oracle.compare_v3_window_with_index_fds(str(self.source),str(self.candidate),*fds,
            self.sha,self.manifest['manifest_sha256'],str(parent),*index_fds,baseline,baseline['identity_sha256'])

    def test_v3_physical_index_endpoint_observation_and_same_byte_rewrite(self):
        self.prepare_v3();fds=self.window_fds();parent=self.source/'.git';index_fds=self.physical_index_fds(parent)
        os.lseek(index_fds[1],7,os.SEEK_SET)
        baseline=self.capture_window_with_index(fds,parent,index_fds)
        self.assertEqual(os.lseek(index_fds[1],0,os.SEEK_CUR),7)
        compared=self.compare_window_with_index(fds,parent,index_fds,baseline)
        self.assertEqual(compared['status'],'INCONCLUSIVE')
        self.assertIn('open-file-description identity',compared['scope'])
        self.assertFalse(baseline['identity']['physical_git_index']['split_index'])
        index=parent/'index';before=index.stat();original=index.read_bytes();index.write_bytes(original);after=index.stat()
        self.assertEqual((before.st_dev,before.st_ino),(after.st_dev,after.st_ino))
        self.assertNotEqual((before.st_mtime_ns,before.st_ctime_ns),(after.st_mtime_ns,after.st_ctime_ns))
        self.assertEqual(self.review_v3()['status'],'OBSERVED_NOT_GATE')
        with self.assertRaisesRegex(oracle.Invalid,'endpoint identities differ'):
            self.compare_window_with_index(fds,parent,index_fds,baseline)

    def test_v3_physical_index_rejects_inode_replacement(self):
        self.prepare_v3();fds=self.window_fds();parent=self.source/'.git';index_fds=self.physical_index_fds(parent)
        baseline=self.capture_window_with_index(fds,parent,index_fds)
        index=parent/'index';other=parent/'replacement-index';other.write_bytes(index.read_bytes())
        os.replace(other,index)
        with self.assertRaises((oracle.Invalid,OSError)):
            self.compare_window_with_index(fds,parent,index_fds,baseline)

    def test_v3_physical_index_does_not_prove_continuous_fd_ownership(self):
        self.prepare_v3();fds=self.window_fds();parent=self.source/'.git';index_fds=self.physical_index_fds(parent)
        baseline=self.capture_window_with_index(fds,parent,index_fds)
        fd=index_fds[1];before=os.fstat(fd);os.close(fd)
        reopened=os.open('index',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=index_fds[0])
        if reopened != fd:
            os.dup2(reopened,fd);os.close(reopened)
        after=os.fstat(fd)
        self.assertEqual((before.st_dev,before.st_ino),(after.st_dev,after.st_ino))
        result=self.compare_window_with_index(fds,parent,index_fds,baseline)
        self.assertEqual(result['status'],'INCONCLUSIVE')
        self.assertIn('continuous FD ownership',result['scope'])

    def test_v3_physical_index_rejects_forged_window_receipt(self):
        self.prepare_v3();fds=self.window_fds();parent=self.source/'.git';index_fds=self.physical_index_fds(parent)
        baseline=self.capture_window_with_index(fds,parent,index_fds)
        forged=copy.deepcopy(baseline);forged['window']['observation']['status']='PASS'
        with self.assertRaisesRegex(oracle.Invalid,'window receipt mismatch'):
            self.compare_window_with_index(fds,parent,index_fds,forged)

    def test_physical_index_rejects_symlink_parent_and_writable_fd(self):
        parent=self.source/'.git';fds=self.physical_index_fds(parent)
        alias=self.base/'alias';alias.symlink_to(parent,target_is_directory=True)
        with self.assertRaises((oracle.Invalid,OSError)):
            oracle._physical_index_observation(str(self.source),str(alias),*fds)
        writable=os.open(parent/'index',os.O_RDWR|os.O_NOFOLLOW);self.addCleanup(os.close,writable)
        with self.assertRaisesRegex(oracle.Invalid,'read-only'):
            oracle._physical_index_observation(str(self.source),str(parent),fds[0],writable)

    def test_v3_physical_index_rejects_replaced_parent_before_git_access(self):
        self.prepare_v3();fds=self.window_fds();parent=self.source/'.git';index_fds=self.physical_index_fds(parent)
        baseline=self.capture_window_with_index(fds,parent,index_fds)
        saved=self.source/'.git-original';parent.rename(saved);parent.mkdir()
        try:
            with self.assertRaises((oracle.Invalid,OSError)):
                self.compare_window_with_index(fds,parent,index_fds,baseline)
        finally:
            parent.rmdir();saved.rename(parent)

    def test_physical_index_supports_normal_and_linked_worktree_without_env_redirection(self):
        normal=self.source/'.git';normal_fds=self.physical_index_fds(normal)
        linked=self.base/'linked-source'
        subprocess.run(['git','worktree','add','--detach',str(linked),self.sha],cwd=self.source,
                       check=True,capture_output=True)
        path=subprocess.check_output(['git','-C',str(linked),'rev-parse','--path-format=absolute',
                                      '--git-path','index'],text=True).strip()
        linked_parent=Path(path).parent;linked_fds=self.physical_index_fds(linked_parent)
        foreign=self.base/'foreign-index';foreign.write_bytes(b'not a Git index')
        with patch.dict(os.environ,{'GIT_INDEX_FILE':str(foreign),'GIT_DIR':str(self.base/'wrong'),
                                    'GIT_WORK_TREE':str(self.base/'wrong')},clear=False):
            first=oracle._physical_index_observation(str(self.source),str(normal),*normal_fds)
            second=oracle._physical_index_observation(str(linked),str(linked_parent),*linked_fds)
        self.assertEqual(first['path'],str(normal/'index'))
        self.assertEqual(second['path'],str(linked_parent/'index'))
        self.assertEqual(foreign.read_bytes(),b'not a Git index')
        self.assertNotEqual(first['file_signature'][1],second['file_signature'][1])

    def test_v3_physical_index_full_window_on_real_linked_worktree(self):
        linked=self.base/'linked-window'
        subprocess.run(['git','worktree','add','--detach',str(linked),self.sha],cwd=self.source,
                       check=True,capture_output=True)
        manifest=source_snapshot.build_manifest_v3(linked,source_snapshot.V3_EXCLUDES)
        self.assertEqual(manifest['worktree_state'],'CLEAN')
        candidate=self.base/'linked-candidate'
        receipt=materialize_snapshot.materialize_snapshot_v3(linked,manifest,candidate)
        manifest_path=self.base/'linked-manifest.json';receipt_path=self.base/'linked-receipt.json'
        manifest_path.write_text(json.dumps(manifest));receipt_path.write_text(json.dumps(receipt))
        fds=[]
        for path,flags in ((linked,os.O_RDONLY|os.O_DIRECTORY),(candidate,os.O_RDONLY|os.O_DIRECTORY),
                           (manifest_path,os.O_RDONLY),(receipt_path,os.O_RDONLY)):
            fd=os.open(path,flags|os.O_NOFOLLOW);fds.append(fd);self.addCleanup(os.close,fd)
        index_path=subprocess.check_output(['git','-C',str(linked),'rev-parse','--path-format=absolute',
                                            '--git-path','index'],text=True).strip()
        parent=Path(index_path).parent; index_fds=self.physical_index_fds(parent)
        baseline=oracle.capture_v3_window_with_index_fds(str(linked),str(candidate),*fds,self.sha,
            manifest['manifest_sha256'],str(parent),*index_fds)
        compared=oracle.compare_v3_window_with_index_fds(str(linked),str(candidate),*fds,self.sha,
            manifest['manifest_sha256'],str(parent),*index_fds,baseline,baseline['identity_sha256'])
        self.assertEqual(compared['status'],'INCONCLUSIVE')
        self.assertEqual(baseline['identity']['physical_git_index']['path'],index_path)
        self.assertEqual(compared['qualification'],'NOT_RUN')

    def test_physical_index_requires_caller_authorized_parent_and_bounded_read(self):
        parent=self.source/'.git';fds=self.physical_index_fds(parent)
        other=self.base/'other-index-parent';other.mkdir();(other/'index').write_bytes(b'caller-owned sentinel')
        other_fds=self.physical_index_fds(other)
        with self.assertRaisesRegex(oracle.Invalid,'caller-authorized parent'):
            oracle._physical_index_observation(str(self.source),str(other),*other_fds)
        self.assertEqual((other/'index').read_bytes(),b'caller-owned sentinel')
        with patch.object(oracle,'MAX_PHYSICAL_INDEX_BYTES',1), patch.object(oracle,'run_git',side_effect=AssertionError('Git must not start')):
            with self.assertRaisesRegex(oracle.Indeterminate,'byte budget'):
                oracle._physical_index_observation(str(self.source),str(parent),*fds)

    def test_physical_index_rejects_split_index_without_claiming_full_observation(self):
        subprocess.run(['git','update-index','--split-index'],cwd=self.source,check=True,capture_output=True)
        parent=self.source/'.git';fds=self.physical_index_fds(parent)
        with self.assertRaisesRegex(oracle.Indeterminate,'split Git index'):
            oracle._physical_index_observation(str(self.source),str(parent),*fds)

    def test_v3_window_detects_same_content_candidate_replacement_that_two_reviews_miss(self):
        self.prepare_v3();fds=self.window_fds();baseline=self.capture_window(fds)
        original=self.candidate/'README'; replacement=self.candidate/'replacement'
        replacement.write_bytes(original.read_bytes());replacement.chmod(original.stat().st_mode & 0o7777)
        os.replace(replacement,original)
        self.assertEqual(self.review_v3()['status'],'OBSERVED_NOT_GATE')
        with self.assertRaises(oracle.Invalid):self.compare_window(fds,baseline)

    def test_v3_window_detects_same_content_source_rewrite_that_two_reviews_miss(self):
        self.prepare_v3();fds=self.window_fds();baseline=self.capture_window(fds)
        path=self.source/'README';data=path.read_bytes();path.write_bytes(data)
        self.assertEqual(self.review_v3()['status'],'OBSERVED_NOT_GATE')
        with self.assertRaises(oracle.Invalid):self.compare_window(fds,baseline)

    def test_v3_window_rejects_replaced_evidence_and_tampered_baseline(self):
        self.prepare_v3();fds=self.window_fds();baseline=self.capture_window(fds)
        forged=copy.deepcopy(baseline);forged['identity']['source_sha']='0'*40
        with self.assertRaises(oracle.Invalid):
            oracle.compare_v3_window_fds(str(self.source),str(self.candidate),*fds,self.sha,
                                         self.manifest['manifest_sha256'],forged,baseline['identity_sha256'])
        for invalid in (None,'','0'*64,'A'*64):
            with self.subTest(pin=invalid), self.assertRaises(oracle.Invalid):
                oracle.compare_v3_window_fds(str(self.source),str(self.candidate),*fds,self.sha,
                                             self.manifest['manifest_sha256'],baseline,invalid)
        forged=copy.deepcopy(baseline);forged['qualification']='PASS'
        with self.assertRaises(oracle.Invalid):self.compare_window(fds,forged)
        writable=os.open(self.manifest_file,os.O_RDWR|os.O_NOFOLLOW);self.addCleanup(os.close,writable)
        with self.assertRaises(oracle.Invalid):
            oracle.capture_v3_window_fds(str(self.source),str(self.candidate),fds[0],fds[1],writable,fds[3],
                                          self.sha,self.manifest['manifest_sha256'])
        replacement=self.base/'replacement.json';replacement.write_bytes(self.manifest_file.read_bytes())
        os.replace(replacement,self.manifest_file)
        with self.assertRaises(oracle.Invalid):self.compare_window(fds,baseline)

    def test_v3_window_rejects_root_replacement_and_duplicate_descriptor(self):
        self.prepare_v3();fds=self.window_fds();baseline=self.capture_window(fds)
        moved=self.base/'moved-candidate';self.candidate.rename(moved)
        shutil.copytree(moved,self.candidate,symlinks=True)
        self.assertEqual(self.review_v3()['status'],'OBSERVED_NOT_GATE')
        with self.assertRaises(oracle.Invalid):self.compare_window(fds,baseline)
        with self.assertRaises(oracle.Invalid):
            oracle.capture_v3_window_fds(str(self.source),str(self.candidate),fds[0],fds[0],fds[2],fds[3],
                                          self.sha,self.manifest['manifest_sha256'])

    def test_v3_directory_identity_names_cannot_collide_with_boundary_names(self):
        (self.source/'boundary:.git').mkdir()
        (self.source/'boundary:.git'/'file').write_text('tracked fixture')
        entries,_,_,_=oracle.git_source_index(self.source,self.sha)
        entries['boundary:.git/file']=('100644','fixture')
        _,_,signatures=oracle.observe_v3_directories(self.source,entries,'VERIFIED',time.monotonic()+10)
        self.assertIn(('boundary','.git'),signatures)
        self.assertIn(('directory','boundary:.git'),signatures)
        self.assertNotEqual(signatures[('boundary','.git')],signatures[('directory','boundary:.git')])

    def test_v3_real_git_projection_and_candidate_are_independently_verified(self):
        self.prepare_v3()
        with patch.object(oracle.os,'fwalk',side_effect=AssertionError('v3 audit must stream entries')):
            result=self.review_v3()
        self.assertEqual((result['status'],result['qualification'],result['product_gate_effect']),
                         ('OBSERVED_NOT_GATE','NOT_RUN','NONE'))
        self.assertEqual((result['candidate_directory_count'],result['candidate_file_count']),(5,3))
        self.assertTrue((self.source/'docs/idea/ForgeFlow_ECP_完整开发规划/evidence/history.log').is_file())
        self.assertFalse((self.candidate/'docs/idea/ForgeFlow_ECP_完整开发规划/evidence').exists())

    def test_v3_producer_projection_matches_independent_fixture(self):
        self.prepare_v3()
        produced=source_snapshot.build_manifest_v3(self.source,source_snapshot.V3_EXCLUDES)
        self.assertEqual(produced['directory_projection'],self.manifest['directory_projection'])
        self.assertEqual(produced['manifest_sha256'],self.manifest['manifest_sha256'])
        self.assertIs(produced['release_qualifiable'],False)

    def test_v3_real_producer_materializer_and_independent_oracle_roundtrip(self):
        self.prepare_v3()
        self.manifest=source_snapshot.build_manifest_v3(self.source,source_snapshot.V3_EXCLUDES)
        self.candidate=self.base/'candidate-v3-actual'
        self.receipt=materialize_snapshot.materialize_snapshot_v3(self.source,self.manifest,self.candidate)
        self.save()
        result=self.review_v3()
        self.assertEqual((result['status'],result['qualification'],result['product_gate_effect']),
                         ('OBSERVED_NOT_GATE','NOT_RUN','NONE'))
        self.assertEqual(result['candidate_inventory_v3_sha256'],self.receipt['candidate_inventory_v3_sha256'])
        self.assertTrue((self.source/'docs/idea/ForgeFlow_ECP_完整开发规划/evidence/history.log').is_file())
        self.assertFalse((self.candidate/'docs/idea/ForgeFlow_ECP_完整开发规划/evidence').exists())

    def test_v3_business_formats_and_directory_boundaries_are_independently_verified(self):
        # Real, disposable Git fixture: expected bytes and paths are specified
        # here independently of the producer's manifest and inventory.
        expected = {
            'src/logo.png': b'png-fixture\x00',
            'src/workload.log': b'business-log\n',
            'src/template.tar.gz': b'archive-fixture\x01',
            'src/fixture.pyc': b'bytecode-fixture\x02',
            'src/evidence2/keep.pyc': b'not-a-cache\x03',
        }
        (self.source/'src/evidence2').mkdir()
        for path, payload in expected.items():
            (self.source/path).write_bytes(payload)
        subprocess.run(['git','add','--',*expected],cwd=self.source,check=True,capture_output=True)
        subprocess.run(['git','commit','-qm','four source formats'],cwd=self.source,check=True,capture_output=True)
        self.sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.source,text=True).strip()
        legacy,_,_=oracle.object_tree(self.source,self.sha)
        current,_,_=oracle.object_tree(self.source,self.sha,oracle.V3_EXCLUDES)
        for path in expected:
            with self.subTest(path=path,check='git-object-policy-versions'):
                self.assertNotIn(path,legacy)
                self.assertIn(path,current)
        # These are explicitly registered exclusion boundaries, not a proof
        # that every directory with these names is non-business.
        for dirname in ('evidence','__pycache__'):
            (self.source/dirname).mkdir(exist_ok=True)
            for name in ('ignored.png','ignored.log','ignored.tar.gz','ignored.pyc'):
                (self.source/dirname/name).write_bytes(b'excluded-fixture')
        self.manifest=source_snapshot.build_manifest_v3(self.source,source_snapshot.V3_EXCLUDES)
        self.assertEqual(self.manifest['worktree_state'],'CLEAN')
        self.candidate=self.base/'candidate-v3-business-formats'
        self.receipt=materialize_snapshot.materialize_snapshot_v3(self.source,self.manifest,self.candidate)
        self.save()
        self.assertEqual(self.review_v3()['status'],'OBSERVED_NOT_GATE')
        for path, payload in expected.items():
            with self.subTest(path=path,check='tracked-byte-readback'):
                self.assertEqual((self.candidate/path).read_bytes(),payload)
            with self.subTest(path=path,check='candidate-tamper'):
                candidate=self.candidate/path
                candidate.write_bytes(payload+b'!')
                try:
                    with self.assertRaises((oracle.Invalid,oracle.Indeterminate,OSError)):
                        self.review_v3()
                finally:
                    candidate.write_bytes(payload)
            with self.subTest(path=path,check='candidate-missing'):
                candidate=self.candidate/path
                candidate.unlink()
                try:
                    with self.assertRaises((oracle.Invalid,oracle.Indeterminate,OSError)):
                        self.review_v3()
                finally:
                    candidate.write_bytes(payload)
        for name in ('untracked.png','untracked.log','untracked.tar.gz','untracked.pyc'):
            with self.subTest(name=name,check='untracked-source-rejection'):
                path=self.source/'src'/name
                path.write_bytes(b'untracked-business')
                try:
                    with self.assertRaises((oracle.Invalid,oracle.Indeterminate,OSError)):
                        self.review_v3()
                finally:
                    path.unlink()
        for path,payload in list(expected.items())[:4]:
            with self.subTest(path=path,check='tracked-source-change'):
                source=self.source/path
                source.write_bytes(payload+b'!')
                try:
                    with self.assertRaises((oracle.Invalid,oracle.Indeterminate,OSError)):
                        self.review_v3()
                finally:
                    source.write_bytes(payload)
        self.assertFalse((self.candidate/'evidence').exists())
        self.assertFalse((self.candidate/'__pycache__').exists())

    def test_v3_typed_boundary_names_bind_real_git_files_and_reject_symlinks(self):
        names = ('target', 'node_modules', '__pycache__', '.local')
        expected = {name: ('independent-' + name).encode() for name in names}
        for name, payload in expected.items():
            (self.source/name).write_bytes(payload)
        subprocess.run(['git','add','-f','--',*names], cwd=self.source, check=True, capture_output=True)
        subprocess.run(['git','commit','-qm','typed boundary files'], cwd=self.source, check=True, capture_output=True)
        self.sha = subprocess.check_output(['git','rev-parse','HEAD'], cwd=self.source, text=True).strip()
        git_entries, blobs, _ = oracle.object_tree(self.source, self.sha, oracle.V3_EXCLUDES)
        for name, payload in expected.items():
            self.assertIn(name, git_entries)
            self.assertEqual(blobs[git_entries[name][1]], payload)
        self.manifest = source_snapshot.build_manifest_v3(self.source, source_snapshot.V3_EXCLUDES)
        self.candidate = self.base/'typed-candidate'
        self.receipt = materialize_snapshot.materialize_snapshot_v3(self.source, self.manifest, self.candidate)
        self.save()
        self.assertEqual(self.review_v3()['status'], 'OBSERVED_NOT_GATE')
        for name, payload in expected.items():
            self.assertEqual((self.candidate/name).read_bytes(), payload)
            (self.candidate/name).write_bytes(payload+b'!')
            with self.assertRaises((oracle.Invalid, oracle.Indeterminate, OSError)):
                self.review_v3()
            (self.candidate/name).write_bytes(payload)
        for name in ('audit', '.pytest_cache'):
            path = self.source/name
            path.write_bytes(b'untracked business')
            with self.assertRaises((oracle.Invalid, oracle.Indeterminate, OSError)):
                self.review_v3()
            path.unlink()
        private = self.source/'.env'
        private.write_bytes(b'private fixture')
        real_open = os.open
        def deny_private_read(path, *args, **kwargs):
            if isinstance(path, (str, bytes)) and os.fsdecode(path).split('/')[-1] == '.env':
                raise AssertionError('private file must not be opened by the oracle')
            return real_open(path, *args, **kwargs)
        with patch.object(oracle.os, 'open', side_effect=deny_private_read):
            self.assertEqual(self.review_v3()['status'], 'OBSERVED_NOT_GATE')
        private.unlink(); private.symlink_to('README')
        with self.assertRaises((oracle.Invalid, oracle.Indeterminate, OSError)):
            self.review_v3()
        private.unlink(); private.mkdir()
        with self.assertRaises((oracle.Invalid, oracle.Indeterminate, OSError)):
            self.review_v3()
        private.rmdir(); os.mkfifo(private)
        with self.assertRaises((oracle.Invalid, oracle.Indeterminate, OSError)):
            self.review_v3()
        private.unlink()
        boundary = self.source/'target'
        boundary.unlink(); boundary.symlink_to('README')
        with self.assertRaises((oracle.Invalid, oracle.Indeterminate, OSError)):
            self.review_v3()
        subprocess.run(['git','add','-f','target'], cwd=self.source, check=True, capture_output=True)
        subprocess.run(['git','commit','-qm','boundary symlink'], cwd=self.source, check=True, capture_output=True)
        head = subprocess.check_output(['git','rev-parse','HEAD'], cwd=self.source, text=True).strip()
        with self.assertRaises(oracle.Invalid):
            oracle.object_tree(self.source, head, oracle.V3_EXCLUDES)

    def test_v3_git_tracked_env_directory_links_are_verified(self):
        env = self.source/'.env'; env.mkdir()
        (env/'input.txt').write_bytes(b'public business fixture')
        (self.source/'env-dir-link').symlink_to('.env')
        (self.source/'env-file-link').symlink_to('.env/input.txt')
        subprocess.run(['git','add','-f','--','.env/input.txt','env-dir-link','env-file-link'],
                       cwd=self.source, check=True, capture_output=True)
        subprocess.run(['git','commit','-qm','business directory links'], cwd=self.source,
                       check=True, capture_output=True)
        self.sha = subprocess.check_output(['git','rev-parse','HEAD'], cwd=self.source, text=True).strip()
        self.manifest = source_snapshot.build_manifest_v3(self.source, source_snapshot.V3_EXCLUDES)
        self.candidate = self.base/'env-links-candidate'
        self.receipt = materialize_snapshot.materialize_snapshot_v3(self.source,self.manifest,self.candidate)
        self.save()
        self.assertEqual(self.review_v3()['status'], 'OBSERVED_NOT_GATE')
        self.assertEqual((self.candidate/'env-file-link').read_bytes(), b'public business fixture')
        self.assertEqual(os.readlink(self.candidate/'env-dir-link'), '.env')
        for target in ('.env', 'evidence/secret'):
            with self.subTest(excluded_target=target), self.assertRaises(oracle.Invalid):
                oracle._v3_validate_link_graph({'bad':('120000','oid')}, {'oid':target.encode()},
                                               projected_dirs={'.'})

    def test_v3_tracked_private_env_fails_before_open_or_blob_lookup(self):
        private = self.source/'.env'
        private.write_bytes(b'synthetic private fixture')
        subprocess.run(['git','add','-f','--','.env'], cwd=self.source, check=True, capture_output=True)
        subprocess.run(['git','commit','-qm','tracked private fixture'], cwd=self.source, check=True, capture_output=True)
        head = subprocess.check_output(['git','rev-parse','HEAD'], cwd=self.source, text=True).strip()
        actual_open = os.open
        def deny_private_open(path, *args, **kwargs):
            if isinstance(path, (str, bytes)) and os.fsdecode(path).split('/')[-1] == '.env':
                raise AssertionError('private file must not be opened')
            return actual_open(path, *args, **kwargs)
        with patch.object(oracle.os, 'open', side_effect=deny_private_open), \
             patch.object(oracle, 'tracked_sizes', side_effect=AssertionError('private blob lookup must not run')):
            with self.assertRaisesRegex(oracle.Invalid, 'tracked private .env'):
                oracle.source_clean_begin(self.source, head, oracle.V3_EXCLUDES)

    def test_v3_independent_policy_is_pinned_and_legacy_or_tampered_policy_rejected(self):
        self.assertEqual(hashlib.sha256(oracle._v3_canonical(list(oracle.EXCLUDES))).hexdigest(),
                         'd839d523d6af3b32855d03570ddd1856c7d546c9dd8b39e3b9c9314b2c566c35')
        self.assertEqual(hashlib.sha256(oracle._v3_canonical(list(oracle.V3_EXCLUDES))).hexdigest(),
                         '693a01c306939936dea248c348d1ed09f44cfc230b27b7a6faeab85fb3926787')
        for name in ('png','log','tar.gz','pyc'):
            with self.subTest(name=name):
                self.assertTrue(oracle.excludes('src/business.'+name))
                self.assertFalse(oracle.excludes('src/business.'+name,oracle.V3_EXCLUDES))
                self.assertIsNone(oracle._v3_exclusion('src/evidence2/business.'+name))
                self.assertIsNotNone(oracle._v3_exclusion('evidence/business.'+name))
                self.assertIsNone(oracle._v3_exclusion('src/__pycache__/business.'+name))
                self.assertEqual(oracle._v3_exclusion('__pycache__/business.'+name), '__pycache__/')
        self.assertIsNone(oracle._v3_exclusion('crates/demo/src/evidence/real.txt'))
        self.prepare_v3()
        self.manifest['exclude_patterns']=list(oracle.EXCLUDES)
        self.manifest['directory_projection']['exclusion_policy_sha256']=hashlib.sha256(
            oracle._v3_canonical(list(oracle.EXCLUDES))).hexdigest()
        self.resign_v3()
        with self.assertRaisesRegex(oracle.Invalid,'unregistered exclusion policy'):
            self.review_v3()
        self.manifest['exclude_patterns']=list(oracle.V3_EXCLUDES)
        self.resign_v3()
        with self.assertRaisesRegex(oracle.Invalid,'directory projection policy digest mismatch'):
            self.review_v3()
        self.manifest['exclude_patterns'].append('src/')
        self.manifest['directory_projection']['exclusion_policy_sha256']=hashlib.sha256(
            oracle._v3_canonical(self.manifest['exclude_patterns'])).hexdigest()
        self.resign_v3()
        with self.assertRaisesRegex(oracle.Invalid,'unregistered exclusion policy'):
            self.review_v3()

    def test_v3_inherited_evidence_fds_are_pinned_and_do_not_change_offsets(self):
        self.prepare_v3()
        manifest_fd=os.open(self.manifest_file,os.O_RDONLY|os.O_NOFOLLOW)
        receipt_fd=os.open(self.receipt_file,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            os.lseek(manifest_fd,7,os.SEEK_SET);os.lseek(receipt_fd,3,os.SEEK_SET)
            result=oracle.review_v3_fds(str(self.source),str(self.candidate),manifest_fd,receipt_fd,
                                        self.sha,self.manifest['manifest_sha256'])
            self.assertEqual(result['status'],'OBSERVED_NOT_GATE')
            self.assertEqual((os.lseek(manifest_fd,0,os.SEEK_CUR),os.lseek(receipt_fd,0,os.SEEK_CUR)),(7,3))
            command=[sys.executable,str(Path(oracle.__file__)), '--manifest-version','3',
                     '--source',str(self.source),'--candidate',str(self.candidate),
                     '--manifest-fd',str(manifest_fd),'--receipt-fd',str(receipt_fd),
                     '--source-sha',self.sha,'--manifest-sha256',self.manifest['manifest_sha256']]
            process=subprocess.run(command,pass_fds=(manifest_fd,receipt_fd),text=True,capture_output=True,timeout=30)
            self.assertEqual(process.returncode,0,process.stderr)
            self.assertEqual(json.loads(process.stdout)['status'],'OBSERVED_NOT_GATE')
            self.assertEqual((os.lseek(manifest_fd,0,os.SEEK_CUR),os.lseek(receipt_fd,0,os.SEEK_CUR)),(7,3))
        finally:
            os.close(manifest_fd);os.close(receipt_fd)

    def test_v3_evidence_fd_remains_bound_after_path_replacement(self):
        self.prepare_v3()
        manifest_fd=os.open(self.manifest_file,os.O_RDONLY|os.O_NOFOLLOW)
        receipt_fd=os.open(self.receipt_file,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            self.manifest_file.rename(self.base/'original-manifest.json')
            self.manifest_file.write_text('{}',encoding='utf-8')
            value=oracle.review_v3_fds(str(self.source),str(self.candidate),manifest_fd,receipt_fd,
                                       self.sha,self.manifest['manifest_sha256'])
            self.assertEqual(value['status'],'OBSERVED_NOT_GATE')
            with self.assertRaises(oracle.Invalid):self.review_v3()
        finally:
            os.close(manifest_fd);os.close(receipt_fd)

    def test_v3_rejects_writable_nonregular_hardlinked_and_changed_fds(self):
        self.prepare_v3()
        writable=os.open(self.manifest_file,os.O_RDWR|os.O_NOFOLLOW)
        directory=os.open(self.base,os.O_RDONLY|os.O_DIRECTORY)
        try:
            for fd in (writable,directory):
                with self.subTest(fd=fd),self.assertRaises(oracle.Invalid):oracle.load_unique_fd(fd)
        finally:
            os.close(writable);os.close(directory)
        alias=self.base/'manifest-hardlink';os.link(self.manifest_file,alias)
        fd=os.open(self.manifest_file,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            with self.assertRaisesRegex(oracle.Invalid,'singly linked'):oracle.load_unique_fd(fd)
        finally:
            os.close(fd);alias.unlink()
        fd=os.open(self.manifest_file,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            with self.assertRaisesRegex(oracle.Invalid,'too large'):oracle.load_unique_fd(fd,4)
            original=oracle.os.pread;changed=False
            def mutate(read_fd,size,offset):
                nonlocal changed
                data=original(read_fd,size,offset)
                if not changed:
                    changed=True;self.manifest_file.write_text('{}',encoding='utf-8')
                return data
            with patch.object(oracle.os,'pread',side_effect=mutate):
                with self.assertRaisesRegex(oracle.Invalid,'changed during read'):oracle.load_unique_fd(fd)
        finally:
            os.close(fd)

    def test_evidence_fd_cli_rejects_mixed_modes_and_v2_fd_use(self):
        self.prepare_v3()
        manifest_fd=os.open(self.manifest_file,os.O_RDONLY|os.O_NOFOLLOW)
        receipt_fd=os.open(self.receipt_file,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            common=[sys.executable,str(Path(oracle.__file__)),'--source',str(self.source),
                    '--candidate',str(self.candidate),'--source-sha',self.sha,
                    '--manifest-sha256',self.manifest['manifest_sha256']]
            variants=(['--manifest-version','3','--manifest',str(self.manifest_file),'--receipt-fd',str(receipt_fd)],
                      ['--manifest-version','2','--manifest-fd',str(manifest_fd),'--receipt-fd',str(receipt_fd)])
            for arguments in variants:
                with self.subTest(arguments=arguments):
                    process=subprocess.run(common+arguments,pass_fds=(manifest_fd,receipt_fd),
                                           text=True,capture_output=True,timeout=20)
                    self.assertEqual(process.returncode,2)
                    self.assertFalse(process.stdout)
        finally:
            os.close(manifest_fd);os.close(receipt_fd)

    def test_v3_rejects_before_exceeding_scan_identity_budget(self):
        self.prepare_v3()
        with patch.object(oracle,'MAX_SCAN_IDENTITY_BYTES',1):
            with self.assertRaisesRegex(oracle.Invalid,'identity budget'):
                self.review_v3()

    def test_v3_json_reader_rejects_nonfinite_and_excessive_nesting(self):
        self.prepare_v3()
        for raw in ('{"x":NaN}', '[' * 2000 + '0' + ']' * 2000):
            with self.subTest(prefix=raw[:10]):
                self.manifest_file.write_text(raw,encoding='utf-8')
                with self.assertRaises(oracle.Invalid):self.review_v3()

    def test_v3_forged_self_consistent_projection_and_receipt_rejected(self):
        self.prepare_v3(); original=copy.deepcopy(self.manifest); original_receipt=copy.deepcopy(self.receipt)
        def omit_dir(p):p['directories'].pop(1)
        def reorder(p):p['directories'][1],p['directories'][2]=p['directories'][2],p['directories'][1]
        def origin(p):p['directories'][1]['origin']='git_ancestor'
        def boundary(p):p['excluded_directory_boundaries'].pop()
        for mutate in (omit_dir,reorder,origin,boundary):
            with self.subTest(mutation=mutate.__name__):
                self.manifest=copy.deepcopy(original);self.receipt=copy.deepcopy(original_receipt)
                mutate(self.manifest['directory_projection']);self.resign_v3()
                with self.assertRaises((oracle.Invalid,oracle.Indeterminate,OSError)):
                    self.review_v3()

    def test_v3_candidate_missing_extra_mode_and_receipt_tampering_rejected(self):
        self.prepare_v3()
        original_receipt=copy.deepcopy(self.receipt)
        directory=self.candidate/'docs/idea/ForgeFlow_ECP_完整开发规划'
        for mutation in ('missing','extra','mode','receipt'):
            with self.subTest(mutation=mutation):
                if mutation=='missing':directory.rmdir()
                elif mutation=='extra':(self.candidate/'unknown').mkdir()
                elif mutation=='mode':directory.chmod(0o700)
                else:self.receipt['candidate_inventory_v3_sha256']='0'*64;self.save()
                with self.assertRaises((oracle.Invalid,oracle.Indeterminate,OSError)):
                    self.review_v3()
                if mutation=='missing':directory.mkdir()
                elif mutation=='extra':(self.candidate/'unknown').rmdir()
                elif mutation=='mode':directory.chmod(self.source.joinpath('docs/idea/ForgeFlow_ECP_完整开发规划').stat().st_mode & 0o7777)
                else:self.receipt=copy.deepcopy(original_receipt);self.save()

    def test_v3_untracked_business_or_excluded_boundary_symlink_rejected(self):
        self.prepare_v3()
        extra=self.source/'docs'/'extra';extra.mkdir()
        with self.assertRaises((oracle.Invalid,oracle.Indeterminate,OSError)):self.review_v3()
        extra.rmdir()
        # A .log outside a registered directory boundary is an untracked
        # business input; its extension cannot hide it from the v3 oracle.
        untracked_file=self.source/'docs'/'extra.log';untracked_file.write_text('untracked business log')
        with self.assertRaises((oracle.Invalid,oracle.Indeterminate,OSError)):self.review_v3()
        untracked_file.unlink()
        boundary=self.source/'docs/idea/ForgeFlow_ECP_完整开发规划/evidence'
        shutil.rmtree(boundary);boundary.symlink_to('/tmp',target_is_directory=True)
        with self.assertRaises((oracle.Invalid,oracle.Indeterminate,OSError)):self.review_v3()

    def test_v3_mode_unavailable_and_source_drift_never_qualify(self):
        self.prepare_v3()
        with patch.object(oracle,'source_mode_availability',return_value=('UNAVAILABLE','9p')):
            with self.assertRaises((oracle.Invalid,oracle.Indeterminate)):self.review_v3()
        original=oracle.candidate_inventory_v3
        def mutate(*args,**kwargs):
            value=original(*args,**kwargs)
            (self.source/'docs'/'new-empty-dir').mkdir(exist_ok=True)
            return value
        with patch.object(oracle,'candidate_inventory_v3',side_effect=mutate):
            with self.assertRaises((oracle.Invalid,oracle.Indeterminate,OSError)):self.review_v3()

    def test_v3_rejects_git_clean_source_file_permission_mismatch(self):
        self.prepare_v3()
        self.source.joinpath('README').chmod(0o600)
        status=subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],cwd=self.source,text=True)
        self.assertEqual(status,'')
        with self.assertRaisesRegex(oracle.Invalid,'file permissions differ'):
            self.review_v3()

    def test_v3_rejects_candidate_file_hardlinked_to_source(self):
        self.prepare_v3()
        destination=self.candidate/'README';destination.unlink()
        os.link(self.source/'README',destination)
        self.assertEqual(destination.stat().st_ino, self.source.joinpath('README').stat().st_ino)
        with self.assertRaisesRegex(oracle.Invalid,'hardlinks'):
            self.review_v3()

    def test_v3_rejects_candidate_file_rewritten_and_restored_between_scans(self):
        self.prepare_v3()
        original=oracle.candidate_inventory_v3; calls=0
        def rewrite(*args,**kwargs):
            nonlocal calls
            value=original(*args,**kwargs);calls+=1
            if calls==1:
                path=self.candidate/'README';before=path.stat();data=path.read_bytes()
                path.write_bytes(b'temporary modification');path.write_bytes(data)
                os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns+1_000_000_000))
            return value
        with patch.object(oracle,'candidate_inventory_v3',side_effect=rewrite):
            with self.assertRaisesRegex(oracle.Invalid,'identities changed'):
                self.review_v3()

    def test_v3_rejects_excluded_targets_and_chained_or_cyclic_symlinks(self):
        cases = [({'link':('120000','a')}, {'a':b'evidence/secret'}),
                 ({'link':('120000','a'),'alias':('120000','b')}, {'a':b'alias','b':b'.git/config'}),
                 ({'link':('120000','a')}, {'a':b'link'}),
                 ({'link':('120000','a')}, {'a':b'../outside'})]
        for expected,blobs in cases:
            with self.subTest(expected=expected,blobs=blobs):
                with self.assertRaises(oracle.Invalid):oracle._v3_validate_link_graph(expected,blobs)
        oracle._v3_validate_link_graph({'src/link':('120000','a'),'README':('100644','b')},
                                       {'a':b'../README','b':b'ok'})
        oracle._v3_validate_link_graph({'src/link':('120000','a'),'src/alias':('120000','b'),
                                        'README':('100644','c')},
                                       {'a':b'alias','b':b'../README','c':b'ok'})

    def test_v3_full_oracle_rejects_missing_and_nondirectory_symlink_targets(self):
        # The producer does not sign its receipt: build private Git fixtures
        # and the receipt independently to exercise the whole A10 review.
        self.prepare_v3()
        self.assertEqual(self.review_v3()['status'],'OBSERVED_NOT_GATE')
        valid_targets=('../docs','../')
        for target in (*valid_targets,'missing','../README/child','../README/..','../README/.','../README/'):
            with self.subTest(target=target):
                source_link=self.source/'src/link'
                source_link.unlink();source_link.symlink_to(target)
                subprocess.run(['git','add','--','src/link'],cwd=self.source,check=True,capture_output=True)
                subprocess.run(['git','commit','-qm','invalid synthetic link'],cwd=self.source,check=True,capture_output=True)
                self.sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.source,text=True).strip()
                candidate_link=self.candidate/'src/link'
                candidate_link.unlink();candidate_link.symlink_to(target)
                self.manifest['head']=self.sha
                self.digest_manifest()
                self.receipt['source_manifest_sha256']=self.manifest['manifest_sha256']
                files=[];total=0
                for path in ('README','src/link','src/tool'):
                    actual=self.candidate/path;info=actual.lstat()
                    row={'path':path,'mode':f'{info.st_mode & 0o7777:04o}'}
                    if actual.is_symlink():
                        link=os.readlink(actual);payload=os.fsencode(link)
                        row.update(kind='symlink',target=link,sha256=hashlib.sha256(payload).hexdigest())
                    else:
                        payload=actual.read_bytes();total+=len(payload)
                        row.update(kind='file',sha256=hashlib.sha256(payload).hexdigest())
                    files.append(row)
                records=self.manifest['directory_projection']['directories']
                inventory={'directories':[{k:row[k] for k in ('path','kind','mode')} for row in records],
                           'files':files}
                self.receipt['candidate_inventory_v3_sha256']=hashlib.sha256(oracle._v3_canonical(inventory)).hexdigest()
                self.receipt['candidate_tree_bytes']=total
                self.save()
                if target in valid_targets:
                    self.assertEqual(self.review_v3()['status'],'OBSERVED_NOT_GATE')
                else:
                    with self.assertRaises(oracle.Invalid):
                        self.review_v3()

    def test_v3_revisit_and_linux_symlink_expansion_boundary(self):
        # Fresh Git fixture; receipt is deliberately synthesized independently
        # because the producer may reject >40 total before the oracle is called.
        (self.source/'src/dir').mkdir()
        (self.source/'src/dir/file').write_bytes(b'fixture-target\n')
        (self.source/'src/a').symlink_to('dir',target_is_directory=True)
        for nested in (2,39,40):
            with self.subTest(nested=nested,total=nested+1):
                target='a/../'*(nested-1)+'a/file'
                link=self.source/'src/link';link.unlink();link.symlink_to(target)
                subprocess.run(['git','add','--','src/a','src/dir/file','src/link'],cwd=self.source,check=True,capture_output=True)
                subprocess.run(['git','commit','-qm','synthetic finite symlink'],cwd=self.source,check=True,capture_output=True)
                self.sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.source,text=True).strip()
                if nested<40:
                    self.assertEqual(link.read_bytes(),b'fixture-target\n')
                else:
                    with self.assertRaises(OSError) as caught:link.read_bytes()
                    self.assertEqual(caught.exception.errno,errno.ELOOP)
                self.manifest=source_snapshot.build_manifest_v3(self.source,source_snapshot.V3_EXCLUDES)
                self.candidate=self.base/('candidate-revisit-'+str(nested));self.candidate.mkdir()
                records=self.manifest['directory_projection']['directories']
                self.assertEqual({x['path'] for x in records},{'.','src','src/dir'})
                for row in records:
                    path=self.candidate if row['path']=='.' else self.candidate/row['path']
                    path.mkdir(parents=True,exist_ok=True);path.chmod(int(row['mode'],8))
                for path in ('README','src/dir/file','src/tool'):
                    shutil.copy2(self.source/path,self.candidate/path)
                (self.candidate/'src/a').symlink_to('dir',target_is_directory=True)
                (self.candidate/'src/link').symlink_to(target)
                rows=[];total=0
                for path in ('README','src/a','src/dir/file','src/link','src/tool'):
                    actual=self.candidate/path;info=actual.lstat()
                    row={'path':path,'mode':f'{info.st_mode & 0o7777:04o}'}
                    if actual.is_symlink():
                        value=os.readlink(actual);payload=os.fsencode(value)
                        row.update(kind='symlink',target=value,sha256=hashlib.sha256(payload).hexdigest())
                    else:
                        payload=actual.read_bytes();total+=len(payload)
                        row.update(kind='file',sha256=hashlib.sha256(payload).hexdigest())
                    rows.append(row)
                inventory={'directories':[{k:row[k] for k in ('path','kind','mode')} for row in records], 'files':rows}
                self.receipt={'status':'OBSERVED_NOT_GATE','qualification':'NOT_RUN','product_gate_effect':'NONE',
                    'release_qualifiable':False,'source_root':str(self.source),'candidate_root':str(self.candidate),
                    'source_manifest_sha256':self.manifest['manifest_sha256'],
                    'source_projection_sha256':self.manifest['projection_sha256'],
                    'candidate_inventory_v3_sha256':hashlib.sha256(oracle._v3_canonical(inventory)).hexdigest(),
                    'candidate_directory_count':len(records),'candidate_file_count':len(rows),'candidate_tree_bytes':total,
                    'source_unchanged':True,'git_metadata_removed':True}
                self.save()
                if nested<40:
                    self.assertEqual(self.review_v3()['status'],'OBSERVED_NOT_GATE')
                else:
                    with self.assertRaisesRegex(oracle.Invalid,'symlink chain exceeds 40'):
                        self.review_v3()

    def test_v3_symlink_expansion_and_pending_budgets_are_bounded(self):
        expected={'src/link':('120000','link'),'src/a':('120000','alias'),'src/dir/file':('100644','data')}
        long_dots=(b'./'*1500)
        # Three finite alias visits exceed 4096 total processed components.
        blobs={'link':b'a/../a/../a/file','alias':long_dots+b'dir','data':b'x'}
        with self.assertRaisesRegex(oracle.Invalid,'symlink.*budget'):
            oracle._v3_validate_link_graph(expected,blobs)
        # Recursive alias expansion grows pending components beyond 4096 before
        # the 40-link limit; it must fail without unbounded queue growth.
        blobs={'link':b'a/file','alias':b'a/'+long_dots,'data':b'x'}
        with self.assertRaisesRegex(oracle.Invalid,'symlink.*budget'):
            oracle._v3_validate_link_graph(expected,blobs)

    def test_v3_dynamic_parent_resolution_and_true_escape(self):
        # Git paths are real private fixtures. x -> d/e changes the physical
        # meaning of subsequent '..' components; lexical reduction is wrong.
        (self.source/'d/e').mkdir(parents=True)
        (self.source/'d/e/marker').write_bytes(b'projected-directory\n')
        (self.source/'foo').write_bytes(b'private-root-target\n')
        (self.source/'x').symlink_to('d/e',target_is_directory=True)
        (self.base/'outside').write_bytes(b'private-outside-sentinel\n')
        for target in ('foo','x/../../foo','x/../../../outside'):
            with self.subTest(target=target):
                link=self.source/'link'
                if link.is_symlink():link.unlink()
                link.symlink_to(target)
                subprocess.run(['git','add','--','d/e/marker','foo','x','link'],cwd=self.source,check=True,capture_output=True)
                subprocess.run(['git','commit','-qm','dynamic symlink case'],cwd=self.source,check=True,capture_output=True)
                self.sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.source,text=True).strip()
                expected=b'private-outside-sentinel\n' if target.endswith('outside') else b'private-root-target\n'
                self.assertEqual(link.read_bytes(),expected)
                self.manifest=source_snapshot.build_manifest_v3(self.source,source_snapshot.V3_EXCLUDES)
                if not target.endswith('outside'):
                    self.candidate=self.base/('candidate-dynamic-'+str(len(target)))
                    self.receipt=materialize_snapshot.materialize_snapshot_v3(self.source,self.manifest,self.candidate)
                    self.save()
                    self.assertEqual(self.review_v3()['status'],'OBSERVED_NOT_GATE')
                    continue
                with self.assertRaises(ValueError):
                    materialize_snapshot.materialize_snapshot_v3(self.source,self.manifest,self.base/'producer-escape')
                # Bypass the producer using a deliberately untrusted synthetic
                # receipt: A10 must still reject the real escaping target.
                self.candidate=self.base/'candidate-escape'
                def ignore_root(path,names):
                    return {n for n in names if Path(path)==self.source and n in ('.git','evidence')}
                shutil.copytree(self.source,self.candidate,symlinks=True,ignore=ignore_root)
                rows=[];total=0
                for path in ('README','d/e/marker','foo','link','src/link','src/tool','x'):
                    actual=self.candidate/path;info=actual.lstat()
                    row={'path':path,'mode':f'{info.st_mode & 0o7777:04o}'}
                    if actual.is_symlink():
                        value=os.readlink(actual);payload=os.fsencode(value)
                        row.update(kind='symlink',target=value,sha256=hashlib.sha256(payload).hexdigest())
                    else:
                        payload=actual.read_bytes();total+=len(payload)
                        row.update(kind='file',sha256=hashlib.sha256(payload).hexdigest())
                    rows.append(row)
                records=self.manifest['directory_projection']['directories']
                inventory={'directories':[{k:row[k] for k in ('path','kind','mode')} for row in records], 'files':rows}
                self.receipt={'status':'OBSERVED_NOT_GATE','qualification':'NOT_RUN','product_gate_effect':'NONE',
                    'release_qualifiable':False,'source_root':str(self.source),'candidate_root':str(self.candidate),
                    'source_manifest_sha256':self.manifest['manifest_sha256'],
                    'source_projection_sha256':self.manifest['projection_sha256'],
                    'candidate_inventory_v3_sha256':hashlib.sha256(oracle._v3_canonical(inventory)).hexdigest(),
                    'candidate_directory_count':len(records),'candidate_file_count':len(rows),'candidate_tree_bytes':total,
                    'source_unchanged':True,'git_metadata_removed':True}
                self.save()
                with self.assertRaisesRegex(oracle.Invalid,'escapes'):
                    self.review_v3()
        cycle={'link':('120000','a'),'x':('120000','b'),'y':('120000','c')}
        with self.assertRaises(oracle.Invalid):
            oracle._v3_validate_link_graph(cycle,{'a':b'x','b':b'y','c':b'x'})

    def test_v3_target_step_budget_excludes_verified_parent_components(self):
        (self.source/'a/b/c').mkdir(parents=True)
        (self.source/'a/b/c/x').write_bytes(b'private-step-target\n')
        target='.'+'/'*4093+'x'  # 4095 bytes and 4094 target components
        link=self.source/'a/b/c/link'
        link.symlink_to(target)
        self.assertEqual(link.read_bytes(),b'private-step-target\n')
        subprocess.run(['git','add','--','a/b/c/link','a/b/c/x'],cwd=self.source,check=True,capture_output=True)
        subprocess.run(['git','commit','-qm','target step fixture'],cwd=self.source,check=True,capture_output=True)
        self.sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.source,text=True).strip()
        self.manifest=source_snapshot.build_manifest_v3(self.source,source_snapshot.V3_EXCLUDES)
        self.candidate=self.base/'candidate-target-steps'
        self.receipt=materialize_snapshot.materialize_snapshot_v3(self.source,self.manifest,self.candidate)
        self.save()
        self.assertEqual(self.review_v3()['status'],'OBSERVED_NOT_GATE')
        # Independent target with exactly 4096 components still meets the
        # registered target-step limit; parent path is already validated.
        oracle._v3_validate_link_graph({'a/b/c/link':('120000','l'),'a/b/c/x':('100644','x')},
            {'l':b'.'+b'/'*4095,'x':b'x'})

    def test_v3_rejects_mount_and_candidate_directory_identity_drift(self):
        self.prepare_v3()
        with patch.object(oracle,'_v3_mount_facts',side_effect=[('source',),('candidate',),('changed',)]):
            with self.assertRaises(oracle.Invalid):self.review_v3()
        original=oracle.candidate_inventory_v3; calls=0
        def replace_signature(*args,**kwargs):
            nonlocal calls
            calls+=1
            result,signatures=original(*args,**kwargs)
            if calls==2:signatures['.']=tuple(signatures['.'])+(999,)
            return result,signatures
        with patch.object(oracle,'candidate_inventory_v3',side_effect=replace_signature):
            with self.assertRaises(oracle.Invalid):self.review_v3()

    def test_v3_rejects_same_device_bind_mount_even_inside_excluded_tree(self):
        table = ('10 1 8:1 / / rw - ext4 /dev/a rw\n'
                 '11 10 8:1 /elsewhere /srv/project/evidence/hidden rw - ext4 /dev/a rw\n')
        with patch.object(oracle.Path, 'read_text', return_value=table):
            with self.assertRaisesRegex(oracle.Invalid,'nested mount'):
                oracle._v3_mount_facts(Path('/srv/project'))

    def test_v3_rejects_source_root_replacement_by_identical_clone(self):
        self.prepare_v3()
        original=oracle.source_clean_begin
        def replace_root(root, sha, patterns=oracle.EXCLUDES):
            moved=self.base/'old-source';self.source.rename(moved)
            shutil.copytree(moved,self.source,symlinks=True)
            return original(root,sha,patterns)
        with patch.object(oracle,'source_clean_begin',side_effect=replace_root):
            with self.assertRaisesRegex(oracle.Invalid,'source root identity changed'):
                self.review_v3()

    def test_real_git_sha1_and_sha256_round_trip(self):
        result=self.review()
        self.assertEqual(result['status'],'OBSERVED_NOT_GATE');self.assertEqual(result['product_gate_effect'],'NONE')
        self.assertEqual(result['git_object_format'],'sha1');self.assertEqual(result['candidate_file_count'],3)
        self.fixture('sha256')
        self.assertEqual(self.review()['git_object_format'],'sha256')

    def test_candidate_tamper_delete_extra_and_mode_are_rejected(self):
        file=self.candidate/'README';original=file.read_bytes()
        for mutation in ('tamper','delete','extra','emptydir','excluded-output','mode'):
            with self.subTest(mutation=mutation):
                if mutation=='tamper':file.write_text('evil\n')
                elif mutation=='delete':file.unlink()
                elif mutation=='extra':(self.candidate/'evil').write_text('extra')
                elif mutation=='emptydir':(self.candidate/'unknown').mkdir()
                elif mutation=='excluded-output':
                    (self.candidate/'target').mkdir();(self.candidate/'target'/'extra').write_text('generated')
                else:file.chmod(0o755)
                self.reject()
                if mutation in ('tamper','delete'):file.write_bytes(original)
                elif mutation=='extra':(self.candidate/'evil').unlink()
                elif mutation=='emptydir':(self.candidate/'unknown').rmdir()
                elif mutation=='excluded-output':shutil.rmtree(self.candidate/'target')
                else:file.chmod(0o644)

    def test_glob_excluded_directory_descendants_match_materialized_tree(self):
        # Git may track a file under an otherwise generated directory. The
        # independent oracle and materializer must agree on the exclusion.
        evidence = self.source/'crates'/'fixture'/'evidence'/'old.json'
        modules = self.source/'console'/'nested'/'node_modules'/'private.js'
        evidence.parent.mkdir(parents=True); modules.parent.mkdir(parents=True)
        evidence.write_text('historical evidence\n'); modules.write_text('generated dependency\n')
        subprocess.run(['git','add','-f',str(evidence.relative_to(self.source)),
                        str(modules.relative_to(self.source))],cwd=self.source,check=True)
        subprocess.run(['git','commit','-qm','tracked generated files'],cwd=self.source,check=True)
        self.sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.source,text=True).strip()
        self.manifest=source_snapshot.build_manifest(self.source,source_snapshot.DEFAULT_EXCLUDES)
        self.candidate=self.base/'generated-candidate'
        self.receipt=materialize_snapshot.materialize_snapshot(self.source,self.manifest,self.candidate)
        self.save()
        result=self.review()
        self.assertEqual(result['status'],'OBSERVED_NOT_GATE')
        self.assertEqual(result['candidate_file_count'],3)
        self.assertFalse((self.candidate/'crates'/'fixture'/'evidence').exists())
        self.assertFalse((self.candidate/'console'/'nested'/'node_modules').exists())
        self.assertIn('crates/fixture', self.receipt['pruned_empty_ancestors'])
        self.assertTrue(evidence.is_file(), 'materialization must not modify the source evidence')
        self.assertTrue(modules.is_file(), 'materialization must not modify the source dependencies')

    def test_wrong_hash_sha_and_unregistered_exclusions_rejected(self):
        original=self.sha;self.sha='0'*len(original);self.reject();self.sha=original
        self.manifest['exclude_patterns'].append('src/')
        self.digest_manifest();self.receipt['source_manifest_sha256']=self.manifest['manifest_sha256'];self.save()
        self.reject()

    def test_self_consistent_but_invalid_v2_manifests_are_rejected(self):
        original = copy.deepcopy(self.manifest)
        variants = [
            lambda d: d.update(inventory_error='contradictory'),
            lambda d: d.update(index_visibility_exceptions=[{'path':'README','gitlink':True}]),
            lambda d: d.update(excluded_generated_files=[{'path':'x','status':'??','reason':'x'}]),
            lambda d: d.update(unexpected='unregistered'),
            lambda d: d.pop('created_at'),
            lambda d: d.update(created_at='not-a-timestamp'),
            lambda d: d.update(untracked_scan_mode='unknown'),
            lambda d: d.update(patch_sha256='0'*64),
        ]
        for mutate in variants:
            with self.subTest(mutation=mutate):
                self.manifest = copy.deepcopy(original)
                mutate(self.manifest)
                self.digest_manifest()
                self.receipt['source_manifest_sha256'] = self.manifest['manifest_sha256']
                self.save()
                self.reject()

    def test_forged_receipt_and_duplicate_json_key_rejected(self):
        self.receipt['candidate_inventory_sha256']='0'*64;self.save();self.reject()
        self.manifest_file.write_text('{"head":"x","head":"y"}')
        self.reject()

    def test_git_environment_redirect_and_source_changes(self):
        with patch.dict(os.environ,{'GIT_DIR':'/not/repo','GIT_WORK_TREE':'/elsewhere',
                                    'GIT_OBJECT_DIRECTORY':'/wrong', 'GIT_CONFIG_COUNT':'1',
                                    'GIT_CONFIG_KEY_0':'core.worktree', 'GIT_CONFIG_VALUE_0':'/elsewhere'}):
            self.assertEqual(self.review()['source_sha'],self.sha)
        path=self.source/'README';original=path.read_text();path.write_text('changed')
        self.reject();path.write_text(original)
        (self.source/'untracked').write_text('business input');self.reject()

    def test_hidden_index_flags_are_rejected(self):
        for flag in ('--assume-unchanged','--skip-worktree'):
            subprocess.run(['git','update-index',flag,'README'],cwd=self.source,check=True)
            try:self.reject()
            finally:subprocess.run(['git','update-index',flag.replace('--','--no-'),'README'],cwd=self.source,check=True)

    def test_tracked_excluded_file_is_still_verified(self):
        path=self.source/'evidence'/'tracked.txt'
        path.write_text('untrusted alteration!\n')
        self.reject()

    def test_index_mode_and_unmerged_stage_are_rejected(self):
        subprocess.run(['git','update-index','--chmod=+x','README'],cwd=self.source,check=True)
        self.reject()
        subprocess.run(['git','reset','-q','HEAD','--','README'],cwd=self.source,check=True)
        oid=subprocess.check_output(['git','rev-parse','HEAD:README'],cwd=self.source,text=True).strip()
        subprocess.run(['git','update-index','--force-remove','README'],cwd=self.source,check=True)
        subprocess.run(['git','update-index','--index-info'],cwd=self.source,input=f'100644 {oid} 1\tREADME\n',text=True,check=True)
        self.reject()

    def test_source_execution_mode_unavailable_is_explicit(self):
        path=self.source/'README';path.chmod(0o755)
        with patch.object(oracle,'source_mode_availability',return_value=('VERIFIED','ext4')):
            self.reject()
        with patch.object(oracle,'source_mode_availability',return_value=('UNAVAILABLE','9p')):
            result=self.review()
        self.assertEqual(result['source_execution_mode'],'UNAVAILABLE')
        self.assertEqual(result['source_filesystem_type'],'9p')

    def test_crlf_conversion_is_never_accepted_as_raw_match(self):
        (self.source/'README').write_bytes(b'fixture text\r\n')
        self.reject()

    def test_untracked_business_directory_rejected_but_excluded_file_is_allowed(self):
        (self.source/'evidence'/'generated.log').write_text('allowed excluded file')
        self.assertEqual(self.review()['status'],'OBSERVED_NOT_GATE')
        (self.source/'unknown').mkdir()
        result=self.review()
        self.assertEqual(result['status'],'INCONCLUSIVE')
        self.assertEqual(result['source_untracked_directories'],['unknown'])

    def test_mutation_after_source_read_is_detected(self):
        original=oracle.object_tree
        def alter_source(*args):
            result=original(*args)
            (self.source/'README').write_text('fixture alter\n')
            return result
        with patch.object(oracle,'object_tree',side_effect=alter_source):
            self.reject()

    def test_source_byte_budget_is_checked_before_opening_any_tracked_file(self):
        with patch.object(oracle,'MAX_SOURCE_BYTES',1), patch.object(oracle,'open_parent',side_effect=AssertionError('must not read files')):
            with self.assertRaisesRegex(oracle.Invalid,'512 MiB budget'):
                oracle.source_clean_begin(self.source,self.sha)

    def test_candidate_symlink_replacement_and_escape_are_rejected(self):
        link=self.candidate/'src'/'link';link.unlink();link.symlink_to('../../outside');self.reject()
        link.unlink();link.symlink_to('../README')
        executable=self.candidate/'src'/'tool';executable.unlink();executable.symlink_to('/etc/passwd');self.reject()

    def test_source_or_evidence_symlink_ancestor_rejected(self):
        alias=self.base/'alias';alias.symlink_to(self.candidate,target_is_directory=True)
        with self.assertRaises((oracle.Invalid,OSError)):
            oracle.review(str(self.source),str(alias),str(self.manifest_file),str(self.receipt_file),self.sha,self.manifest['manifest_sha256'])
        link=self.base/'manifest-link';link.symlink_to(self.manifest_file)
        with self.assertRaises((oracle.Invalid,OSError)):
            oracle.review(str(self.source),str(self.candidate),str(link),str(self.receipt_file),self.sha,self.manifest['manifest_sha256'])

    def test_path_validation_and_authoritative_symlink_escape(self):
        for value in ('../a','a/../b','/absolute','a//b','a\\b','a/\n'):
            with self.subTest(value=value):
                with self.assertRaises(oracle.Invalid):oracle.safe_path(value)
        (self.source/'escape').symlink_to('../../outside')
        subprocess.run(['git','add','escape'],cwd=self.source,check=True)
        subprocess.run(['git','commit','-qm','escape'],cwd=self.source,check=True)
        self.sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.source,text=True).strip()
        self.manifest=source_snapshot.build_manifest(self.source,source_snapshot.DEFAULT_EXCLUDES)
        other=self.base/'escape-candidate'
        self.receipt=materialize_snapshot.materialize_snapshot(self.source,self.manifest,other)
        self.candidate=other;self.save();self.reject()

    def test_duplicate_blob_paths_count_against_total_byte_budget(self):
        payload=b'x'*600
        for name in ('same-1','same-2','same-3'):(self.source/name).write_bytes(payload)
        subprocess.run(['git','add','.'],cwd=self.source,check=True)
        subprocess.run(['git','commit','-qm','duplicated blob'],cwd=self.source,check=True)
        sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.source,text=True).strip()
        # One 600-byte Git object, three source paths: 1,800 bytes, not 600.
        with patch.object(oracle,'MAX_TREE_BYTES',1000):
            with self.assertRaisesRegex(oracle.Invalid,'path bytes'):
                oracle.object_tree(self.source,sha)
        with patch.object(oracle,'MAX_SOURCE_BYTES',1000), patch.object(oracle,'open_parent',side_effect=AssertionError('must not read files')):
            with self.assertRaisesRegex(oracle.Invalid,'512 MiB budget'):
                oracle.source_clean_begin(self.source,sha)

    def test_git_tree_count_and_output_are_bounded(self):
        with patch.object(oracle,'MAX_TREE_ENTRIES',2):
            with self.assertRaisesRegex(oracle.Invalid,'entry count'):
                oracle.object_tree(self.source,self.sha)
        with self.assertRaisesRegex(oracle.Invalid,'Git output exceeds'):
            oracle.run_git(self.source,['ls-tree','-rz','--full-tree',self.sha],limit=10)

if __name__=='__main__':unittest.main()

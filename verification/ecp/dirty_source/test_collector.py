"""Controlled synthetic filesystem tests; runner is in-memory, never Git."""
import hashlib
import base64
import types
import tempfile
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
collector=load('collector_research',HERE/'collector.py')
model=load('model_research',HERE/'model.py')
runner_module=load('sandbox_runner_research',HERE/'sandbox_git_runner.py')
def new_test_root(name):
    configured=os.environ.get('ECP_COLLECTOR_FIXTURE_ROOT')
    parent=Path(configured) if configured else Path(tempfile.mkdtemp(prefix='forgeflow-collector-test-'))
    root=parent/name;root.mkdir(mode=0o700)
    return root
H=b'a'*40

def oid(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest().encode()
def tree_row(path,data,mode=b'100644'):return mode+b' blob '+oid(data)+b'\t'+path+b'\0'
def index_row(path,data,mode=b'100644'):return mode+b' '+oid(data)+b' 0\t'+path+b'\0'

class CollectorTests(unittest.TestCase):
 def setUp(self):
    self.root=new_test_root(self._testMethodName);(self.root/'.git').mkdir();self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
    self.head={b'tracked':(b'old',b'100644')};self.index={b'tracked':(b'staged',b'100644')};(self.root/'tracked').write_bytes(b'worktree')
    self.objects={oid(b'old'):b'old',oid(b'staged'):b'staged'};self.commands=[]
 def tearDown(self):os.close(self.fd)
 def runner(self,args,limit):
    self.commands.append(args)
    if args==('rev-parse','--verify','HEAD^{commit}'):return H+b'\n'
    if args==('ls-tree','-rz','--full-tree',H.decode()):return b''.join(tree_row(k,v,m) for k,(v,m) in sorted(self.head.items()))
    if args==('ls-files','--stage','-z'):return b''.join(index_row(k,v,m) for k,(v,m) in sorted(self.index.items()))
    if args==('ls-files','-v','-z'):return b''.join(b'H '+k+b'\0' for k in sorted(self.index))
    if args[:2]==('cat-file','blob'):return self.objects[args[2].encode()]
    raise AssertionError(args)
 def collect(self,**kw):
    args={'executable_mode_observed':True,'unsupported_features_excluded':True};args.update(kw)
    return collector.collect(self.fd,self.runner,model,**args)
 def test_three_layers_are_distinct(self):
    result=self.collect();m=result['declaration']['manifest'];self.assertEqual([m[k][0]['sha256'] for k in ('head','index','tracked_worktree')],[hashlib.sha256(x).hexdigest() for x in (b'old',b'staged',b'worktree')]);self.assertEqual((len(m['staged_changes']),len(m['unstaged_changes'])),(1,1))
 def test_staged_delete_then_untracked(self):
    self.index={};result=self.collect();m=result['declaration']['manifest'];self.assertEqual(m['staged_changes'][0]['change'],'DELETED');self.assertEqual(len(m['untracked']),1)
 def test_ignored_file_is_not_silently_excluded(self):
    (self.root/'.gitignore').write_bytes(b'ignored\n');(self.root/'ignored').write_bytes(b'keep');m=self.collect()['declaration']['manifest'];self.assertEqual(len(m['untracked']),2);self.assertFalse(m['coverage_claims']['exclusions'])
 def test_group_only_execute_not_git_executable(self):
    os.chmod(self.root/'tracked',0o610);m=self.collect()['declaration']['manifest'];self.assertEqual(m['tracked_worktree'][0]['mode'],'100644')
 def test_unknown_mode_not_inferred(self):
    m=self.collect(executable_mode_observed=False)['declaration']['manifest'];self.assertIsNone(m['tracked_worktree'][0]['mode']);self.assertEqual(len(m['unknown_worktree_modes']),1)
 def test_symlink_as_data_not_followed(self):
    os.symlink('/outside',self.root/'newlink');m=self.collect()['declaration']['manifest'];self.assertEqual(m['untracked'][0]['kind'],'symlink')
 def test_non_utf8_path(self):
    fd=os.open(b'\xff',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=self.fd);os.write(fd,b'x');os.close(fd);m=self.collect()['declaration']['manifest'];self.assertEqual(len(m['untracked']),1)
 def test_empty_directory_rejected(self):
    (self.root/'empty').mkdir();self.assertRaisesRegex(collector.Incomplete,'EMPTY_DIRECTORY_UNSUPPORTED',self.collect)
 def test_nested_git_rejected(self):
    (self.root/'sub').mkdir();(self.root/'sub'/'.git').mkdir();self.assertRaisesRegex(collector.Incomplete,'NESTED_GIT_UNSUPPORTED',self.collect)
 def test_hardlink_rejected(self):
    os.link(self.root/'tracked',self.root/'second');self.assertRaisesRegex(collector.Incomplete,'FILE_UNSUPPORTED_OR_LIMIT',self.collect)
 def test_git_directory_linked_rejected(self):
    os.rmdir(self.root/'.git');os.symlink('tracked',self.root/'.git');self.assertRaisesRegex(collector.Incomplete,'GIT_DIR_UNSUPPORTED',self.collect)
 def test_git_root_missing_rejected(self):
    os.rmdir(self.root/'.git');self.assertRaisesRegex(collector.Incomplete,'GIT_DIR_MISSING',self.collect)
 def test_hidden_index_flags_rejected(self):
    original=self.runner
    def bad(args,limit):return b'S tracked\0' if args==('ls-files','-v','-z') else original(args,limit)
    with self.assertRaisesRegex(collector.Incomplete,'INDEX_VISIBILITY_UNSUPPORTED'):collector.collect(self.fd,bad,model,executable_mode_observed=True,unsupported_features_excluded=True)
 def test_unmerged_index_rejected(self):
    original=self.runner
    def bad(args,limit):return b'100644 '+oid(b'staged')+b' 2\ttracked\0' if args==('ls-files','--stage','-z') else original(args,limit)
    with self.assertRaisesRegex(collector.Incomplete,'UNMERGED_INDEX'):collector.collect(self.fd,bad,model,executable_mode_observed=True,unsupported_features_excluded=True)
 def test_git_blob_mismatch_rejected(self):
    self.objects[oid(b'old')]=b'wrong';self.assertRaisesRegex(collector.Incomplete,'GIT_BLOB_MISMATCH',self.collect)
 def test_runner_error_rejected(self):
    def bad(args,limit):raise RuntimeError('unknown')
    with self.assertRaisesRegex(collector.Incomplete,'GIT_RUNNER_FAILURE'):collector.collect(self.fd,bad,model,executable_mode_observed=True,unsupported_features_excluded=True)
 def test_feature_admission_required(self):self.assertRaisesRegex(collector.Incomplete,'FEATURE_ADMISSION_UNAVAILABLE',self.collect,unsupported_features_excluded=False)
 def test_git_metadata_change_rejected(self):
    original=self.runner;times=[0]
    def bad(args,limit):
        if args==('rev-parse','--verify','HEAD^{commit}'):
            times[0]+=1
            if times[0]>1:return b'b'*40+b'\n'
        if args[:3]==('ls-tree','-rz','--full-tree') and args[3]=='b'*40:
            return original(('ls-tree','-rz','--full-tree',H.decode()),limit)
        return original(args,limit)
    with self.assertRaisesRegex(collector.Incomplete,'SOURCE_CHANGED'):collector.collect(self.fd,bad,model,executable_mode_observed=True,unsupported_features_excluded=True)
 def test_second_scan_change_rejected(self):
    original=collector._scan;times=[0]
    def altered(*args):
        value=original(*args);times[0]+=1
        if times[0]==2:value[b'injected']=('file','100644',b'x')
        return value
    with patch.object(collector,'_scan',side_effect=altered):self.assertRaisesRegex(collector.Incomplete,'SOURCE_CHANGED',self.collect)
 def test_entry_budget(self):
    with patch.object(collector,'MAX_ENTRIES',1):self.assertRaisesRegex(collector.Incomplete,'ENTRY_LIMIT',self.collect)
 def test_mode_policy_type(self):self.assertRaisesRegex(collector.Incomplete,'MODE_POLICY_INVALID',self.collect,executable_mode_observed='yes')
 def test_extra_nul_in_index_is_rejected(self):
    original=self.runner
    def bad(args,limit):return original(args,limit)+b'\0' if args==('ls-files','--stage','-z') else original(args,limit)
    with self.assertRaisesRegex(collector.Incomplete,'GIT_ROWS_INVALID'):collector.collect(self.fd,bad,model,executable_mode_observed=True,unsupported_features_excluded=True)
 def test_extra_nul_in_flags_is_rejected(self):
    original=self.runner
    def bad(args,limit):return original(args,limit)+b'\0' if args==('ls-files','-v','-z') else original(args,limit)
    with self.assertRaisesRegex(collector.Incomplete,'FLAGS_INVALID'):collector.collect(self.fd,bad,model,executable_mode_observed=True,unsupported_features_excluded=True)
 def test_scandir_stops_at_budget_and_closes(self):
    seen=[];closed=[]
    class Stream:
        def __enter__(self):return self
        def __exit__(self,*args):closed.append(True)
        def __iter__(self):
            for name in ('one','two','three','must-not-be-read'):
                seen.append(name);yield types.SimpleNamespace(name=name)
    with patch.object(collector,'MAX_ENTRIES',2),patch.object(collector.os,'scandir',return_value=Stream()):
        self.assertRaisesRegex(collector.Incomplete,'ENTRY_LIMIT',self.collect)
    self.assertEqual(seen,['one','two','three']);self.assertEqual(closed,[True])
 def test_symlink_with_hardlink_rejected(self):
    os.symlink('tracked',self.root/'linkone');os.link(self.root/'linkone',self.root/'linktwo',follow_symlinks=False)
    self.assertEqual(os.lstat(self.root/'linkone').st_nlink,2)
    self.assertRaisesRegex(collector.Incomplete,'SYMLINK_HARDLINK_UNSUPPORTED',self.collect)
 def test_git_directory_cross_device_rejected(self):
    original=os.stat
    def changed(path,*args,**kw):
        value=original(path,*args,**kw)
        if path==b'.git':return types.SimpleNamespace(st_mode=value.st_mode,st_dev=value.st_dev+1)
        return value
    with patch.object(collector.os,'stat',side_effect=changed):self.assertRaisesRegex(collector.Incomplete,'GIT_DIRECTORY_MOUNT_UNSUPPORTED',self.collect)

class RunnerTests(unittest.TestCase):
 def setUp(self):
    self.root=new_test_root(self._testMethodName);self.log=self.root/'logs';self.log.mkdir();self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.logfd=os.open(self.log,os.O_RDONLY|os.O_DIRECTORY)
    self.runner=runner_module.SandboxGitRunner(self.fd,self.logfd);self.args=('rev-parse','--verify','HEAD^{commit}')
 def tearDown(self):os.close(self.logfd);os.close(self.fd)
 def child(self,out,err,code=0,wait_error=None):
    def fake(*args,**kw):
        os.write(kw['stdout'],out);os.write(kw['stderr'],err)
        class Child:
            def wait(self):
                if wait_error:raise wait_error
                return code
        return Child()
    return fake
 def test_nonzero_retains_raw_streams_and_exit(self):
    with patch.object(runner_module.subprocess,'Popen',side_effect=self.child(b'out',b'bad',7)):
        self.assertRaisesRegex(runner_module.GitObservationError,'COMMAND_NONZERO',self.runner,self.args,20)
    row=self.runner.records[0];self.assertEqual(row['exit_code'],7);self.assertEqual(row['exit_state'],'WAIT_RETURNED');self.assertEqual(base64.b64decode(row['stdout']['captured_base64']),b'out');self.assertEqual(base64.b64decode(row['stderr']['captured_base64']),b'bad');self.assertFalse(row['stdout']['truncated'])
 def test_oversized_stdout_retains_bounded_prefix(self):
    with patch.object(runner_module.subprocess,'Popen',side_effect=self.child(b'abcdef',b'')):
        self.assertRaisesRegex(runner_module.GitObservationError,'STREAM_INCOMPLETE_OR_TRUNCATED',self.runner,self.args,4)
    row=self.runner.records[0];self.assertEqual(base64.b64decode(row['stdout']['captured_base64']),b'abcd');self.assertTrue(row['stdout']['truncated']);self.assertEqual(row['stdout']['size_before'],6);self.assertEqual(row['exit_code'],0)
 def test_aggregate_capture_budget_includes_stderr(self):
    with patch.object(runner_module,'MAX_CAPTURE',4),patch.object(runner_module.subprocess,'Popen',side_effect=self.child(b'abc',b'xy')):
        self.assertRaises(runner_module.GitObservationError,self.runner,self.args,10)
    row=self.runner.records[0];self.assertEqual(self.runner.capture_bytes,4);self.assertEqual(base64.b64decode(row['stderr']['captured_base64']),b'x');self.assertTrue(row['stderr']['truncated'])
 def test_popen_failure_keeps_attempt_and_empty_streams(self):
    with patch.object(runner_module.subprocess,'Popen',side_effect=OSError('not started')):
        self.assertRaisesRegex(runner_module.GitObservationError,'RUNNER_EXCEPTION',self.runner,self.args,10)
    row=self.runner.records[0];self.assertEqual(row['launch_state'],'POPEN_ATTEMPTED');self.assertEqual(row['exit_state'],'UNKNOWN');self.assertIsNone(row['exit_code']);self.assertEqual(row['stdout']['captured_bytes'],0)
 def test_wait_failure_keeps_prefix_and_unknown_exit(self):
    with patch.object(runner_module.subprocess,'Popen',side_effect=self.child(b'partial',b'',wait_error=RuntimeError('unknown'))):
        self.assertRaisesRegex(runner_module.GitObservationError,'RUNNER_EXCEPTION',self.runner,self.args,10)
    row=self.runner.records[0];self.assertEqual(row['launch_state'],'POPEN_RETURNED');self.assertEqual(row['exit_state'],'UNKNOWN');self.assertEqual(base64.b64decode(row['stdout']['captured_base64']),b'partial');self.assertEqual(row['process_tree'],'UNKNOWN')
 def test_partial_capture_error_preserves_read_bytes(self):
    original=os.read;calls=[0]
    def failing(fd,n):
        calls[0]+=1
        if calls[0]==1:return original(fd,2)
        raise OSError('read failed')
    with patch.object(runner_module.subprocess,'Popen',side_effect=self.child(b'abcd',b'')),patch.object(runner_module.os,'read',side_effect=failing):
        self.assertRaises(runner_module.GitObservationError,self.runner,self.args,10)
    row=self.runner.records[0];self.assertEqual(row['stdout']['state'],'READ_UNKNOWN');self.assertEqual(base64.b64decode(row['stdout']['captured_base64']),b'ab');self.assertEqual(self.runner.capture_bytes,2)

if __name__=='__main__':unittest.main(verbosity=2)

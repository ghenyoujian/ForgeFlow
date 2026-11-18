"""Synthetic, private filesystem and fake-runner tests; never invokes Git."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent

def load(name):
    spec = importlib.util.spec_from_file_location('r40_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

model = load('model')
head_object = load('head_object')
materializer = load('materializer')
ROOT = None

def setUpModule():
    # A unique mode-0700 tree is retained for evidence; no automatic cleanup.
    # Explicit TMPDIR must not silently fall back to another filesystem.
    global ROOT
    if 'TMPDIR' in os.environ:
        parent = os.environ['TMPDIR']
        if not os.path.isabs(parent):
            raise ValueError('TMPDIR_MUST_BE_ABSOLUTE')
        ROOT = Path(tempfile.mkdtemp(prefix='forgeflow-materializer-', dir=parent))
    else:
        ROOT = Path(tempfile.mkdtemp(prefix='forgeflow-materializer-'))
    print('MATERIALIZER_FIXTURE_ROOT=' + str(ROOT), file=sys.stderr, flush=True)


def oid(kind, data):
    return hashlib.sha1(kind + b' ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
        separators=(',', ':'), allow_nan=False).encode('ascii')).hexdigest()


def fixture():
    head = {b'file': ('file','100644',b'head\n')}
    tree = b'100644 file\0' + bytes.fromhex(oid(b'blob',b'head\n'))
    commit = b'tree ' + oid(b'tree',tree).encode('ascii') + b'\nauthor a <a@invalid> 1 +0000\ncommitter a <a@invalid> 1 +0000\n\nfixture\n'
    item = model.create(head_commit=oid(b'commit',commit), head=head,
        index={b'file':('file','100644',b'staged\n'), b'nested/new':('file','100755',b'index\n')},
        tracked_worktree={b'file':('file','100644',b'work\n'), b'nested/new':('file','100755',b'index\n')},
        untracked={b'ignored.tmp':('file','100644',b'ignored\n'), b'link':('symlink','120000',b'nested/new')},
        excluded={}, coverage_claims={'head':True,'index':True,'worktree':True,'exclusions':False})
    return item, commit


class FakeGit:
    def __init__(self, rootfd, *, fail_at=None, wrong_at=None):
        self.rootfd=rootfd; self.calls=[]; self.fail_at=fail_at; self.wrong_at=wrong_at
    def __call__(self,args,data,limit):
        self.calls.append((args,data,limit)); n=len(self.calls)
        if n==self.fail_at: raise OSError('synthetic failure')
        if args[0]=='init': os.mkdir(b'.git',0o700,dir_fd=self.rootfd); out=b''
        elif args[0]=='hash-object': out=(oid(args[3].encode('ascii'),data)+'\n').encode('ascii')
        else: out=b''
        return b'wrong\n' if n==self.wrong_at else out


class MaterializerTests(unittest.TestCase):
    def setUp(self):
        # Deterministic synthetic limits; these are not observations of the FS.
        limits=patch.object(materializer.os,'fpathconf',side_effect=lambda fd,key: {'PC_NAME_MAX':255,'PC_SYMLINK_MAX':4095}[key])
        limits.start(); self.addCleanup(limits.stop)
        self.root=ROOT/self._testMethodName
        self.root.mkdir(mode=0o700)
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        self.item,self.commit=fixture();self.runner=FakeGit(self.fd)
    def tearDown(self): os.close(self.fd)
    def prepare(self): return materializer.prepare(self.item['manifest'],self.item['manifest_sha256'],self.item['blobs'],self.commit,model,head_object)
    def apply(self,*,asserted=True):
        return materializer.materialize(self.fd,self.item['manifest'],self.item['manifest_sha256'],self.item['blobs'],self.commit,model,head_object,self.runner,fresh_root_asserted=asserted)
    def test_plan_preserves_head_index_and_untracked(self):
        p=self.prepare();self.assertEqual((p['head_count'],p['index_count'],p['untracked_count']),(1,2,2));self.assertEqual(len(p['worktree']),4)
        self.assertEqual(p['worktree'][b'ignored.tmp'][2],b'ignored\n');self.assertEqual(p['qualification'],'NOT_RUN')
        index=[x for x in p['commands'] if x[0][0]=='update-index'][0][1]
        self.assertIn(b' 0\tfile\0',index);self.assertIn(b' 0\tnested/new\0',index)
    def test_complete_fake_runner_materializes_files_and_symlink(self):
        out=self.apply();self.assertEqual(out['status'],'OBSERVED_RESEARCH_ONLY');self.assertEqual(out['history_completeness'],'NOT_MEASURED');self.assertEqual(out['exclusion_coverage_state'],'UNKNOWN');self.assertIs(out['exclusion_completeness_claim'],False)
        self.assertEqual((self.root/'file').read_bytes(),b'work\n');self.assertEqual((self.root/'ignored.tmp').read_bytes(),b'ignored\n')
        self.assertEqual((self.root/'nested/new').read_bytes(),b'index\n');self.assertEqual(stat.S_IMODE((self.root/'nested/new').stat().st_mode),0o755)
        self.assertEqual(os.readlink(self.root/'link'),'nested/new');self.assertTrue((self.root/'.git').is_dir())
    def test_runner_failure_retains_partial_git_and_fails(self):
        self.runner.fail_at=2
        with self.assertRaisesRegex(materializer.MaterializeError,'RUNNER_FAILED_PARTIAL_TARGET'): self.apply()
        self.assertTrue((self.root/'.git').is_dir());self.assertFalse((self.root/'file').exists())
    def test_wrong_object_oid_rejected(self):
        self.runner.wrong_at=2
        with self.assertRaisesRegex(materializer.MaterializeError,'RUNNER_OUTPUT_MISMATCH_PARTIAL_TARGET'): self.apply()
        self.assertTrue((self.root/'.git').is_dir())
    def test_nonempty_root_never_calls_runner(self):
        (self.root/'existing').write_bytes(b'keep')
        with self.assertRaisesRegex(materializer.MaterializeError,'ROOT_NOT_EMPTY'): self.apply()
        self.assertEqual(self.runner.calls,[]);self.assertEqual((self.root/'existing').read_bytes(),b'keep')
    def test_nonprivate_root_never_calls_runner(self):
        os.chmod(self.root,0o755)
        with self.assertRaisesRegex(materializer.MaterializeError,'ROOT_NOT_PRIVATE_DIRECTORY'): self.apply()
        self.assertEqual(self.runner.calls,[])
    def test_freshness_assertion_required(self):
        with self.assertRaisesRegex(materializer.MaterializeError,'CALLER_ADMISSION_UNAVAILABLE'): self.apply(asserted=False)
        self.assertEqual(self.runner.calls,[])
    def test_manifest_digest_mismatch_before_runner(self):
        self.item['manifest']['head_commit_claim']='a'*40
        with self.assertRaisesRegex(materializer.MaterializeError,'MANIFEST_DIGEST_MISMATCH'): self.apply()
        self.assertEqual(self.runner.calls,[])
    def test_commit_mismatch_before_runner(self):
        self.commit += b'changed'
        with self.assertRaisesRegex(materializer.MaterializeError,'HEAD_OBJECT_REJECTED'): self.apply()
        self.assertEqual(self.runner.calls,[])
    def test_missing_blob_before_runner(self):
        self.item['blobs'].pop(next(iter(self.item['blobs'])))
        with self.assertRaisesRegex(materializer.MaterializeError,'BLOB_CONTENT_MISMATCH'): self.apply()
        self.assertEqual(self.runner.calls,[])
    def test_extra_blob_before_runner(self):
        self.item['blobs']['0'*64]=b'extra'
        with self.assertRaisesRegex(materializer.MaterializeError,'BLOB_SET_MISMATCH'): self.apply()
        self.assertEqual(self.runner.calls,[])
    def test_incomplete_projection_claim_rejected(self):
        self.item['manifest']['coverage_claims']['worktree']=False;self.item['manifest_sha256']=canonical(self.item['manifest'])
        with self.assertRaisesRegex(materializer.MaterializeError,'PROJECTION_INCOMPLETE_CLAIM'):self.apply()
    def test_unknown_worktree_mode_rejected(self):
        self.item['manifest']['tracked_worktree'][0]['mode']=None;self.item['manifest_sha256']=canonical(self.item['manifest'])
        with self.assertRaisesRegex(materializer.MaterializeError,'WORKTREE_MODE_UNAVAILABLE'):self.apply()
    def test_exclusion_rejected_even_if_claimed_complete(self):
        self.item['manifest']['excluded']=[{'path_b64':base64.b64encode(b'ignored').decode(),'reason':'x'}];self.item['manifest_sha256']=canonical(self.item['manifest'])
        with self.assertRaisesRegex(materializer.MaterializeError,'EXCLUSION_UNSUPPORTED'):self.apply()
    def test_path_traversal_rejected_before_runner(self):
        self.item['manifest']['untracked'][0]['path_b64']=base64.b64encode(b'../escape').decode();self.item['manifest_sha256']=canonical(self.item['manifest'])
        with self.assertRaisesRegex(materializer.MaterializeError,'PATH_INVALID'):self.apply()
        self.assertEqual(self.runner.calls,[])
    def test_noncanonical_or_forged_row_rejected(self):
        self.item['manifest']['index'][0]['computed_git_blob_oid']='0'*40;self.item['manifest_sha256']=canonical(self.item['manifest'])
        with self.assertRaisesRegex(materializer.MaterializeError,'DECLARATION_RECONSTRUCTION_MISMATCH'):self.apply()
    def test_git_metadata_in_input_path_rejected(self):
        self.item['manifest']['untracked'][0]['path_b64']=base64.b64encode(b'.GIT/config').decode();self.item['manifest_sha256']=canonical(self.item['manifest'])
        with self.assertRaisesRegex(materializer.MaterializeError,'PATH_INVALID'):self.apply()
    def test_unexpected_runner_file_does_not_get_overwritten(self):
        orig=self.runner
        def injected(args,data,limit):
            output=orig(args,data,limit)
            if args[0]=='init':
                fd=os.open(b'file',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=self.fd)
                try:os.write(fd,b'keep')
                finally:os.close(fd)
            return output
        self.runner=injected
        with self.assertRaisesRegex(materializer.MaterializeError,'RUNNER_ROOT_CONTENT_UNEXPECTED'):self.apply()
        self.assertEqual((self.root/'file').read_bytes(),b'keep')
    def test_short_writes_complete(self):
        real=os.write
        with patch.object(materializer.os,'write',side_effect=lambda fd,data:real(fd,data[:1])):
            self.apply()
        self.assertEqual((self.root/'file').read_bytes(),b'work\n')
    def test_zero_write_keeps_partial_target(self):
        with patch.object(materializer.os,'write',return_value=0):
            with self.assertRaisesRegex(materializer.MaterializeError,'WORKTREE_INCOMPLETE_PARTIAL_TARGET'):self.apply()
        self.assertTrue((self.root/'.git').is_dir())
    def test_opaque_absolute_symlink_is_not_followed(self):
        u={b'link':('symlink','120000',b'/not-followed')}
        orig=self.item['manifest'];item=model.create(head_commit=orig['head_commit_claim'],head={b'file':('file','100644',b'head\n')},index={b'file':('file','100644',b'head\n')},tracked_worktree={b'file':('file','100644',b'head\n')},untracked=u,excluded={},coverage_claims=orig['coverage_claims'])
        self.item=item;self.apply();self.assertEqual(os.readlink(self.root/'link'),'/not-followed')

    def test_manifest_oversize_scalar_is_rejected_before_runner(self):
        self.item['manifest']['unexpected']='x'*(materializer.MAX_JSON_STRING_CHARS+1)
        with self.assertRaisesRegex(materializer.MaterializeError,'MANIFEST_BUDGET_EXCEEDED'): self.apply()
        self.assertEqual(self.runner.calls,[])
    def test_worktree_path_prefix_collision_rejected_before_runner(self):
        m=self.item['manifest'];m['untracked'][0]['path_b64']=base64.b64encode(b'nested').decode();self.item['manifest_sha256']=canonical(m)
        with self.assertRaisesRegex(materializer.MaterializeError,'MODEL_REJECTED'): self.apply()
        self.assertEqual(self.runner.calls,[])
    def test_runner_initialization_missing_git_is_rejected(self):
        original=self.runner
        def injected(args,data,limit):
            if args[0]=='init':return b''
            return original(args,data,limit)
        self.runner=injected
        with self.assertRaisesRegex(materializer.MaterializeError,'RUNNER_ROOT_CONTENT_UNEXPECTED'):self.apply()
        self.assertFalse((self.root/'file').exists())

    def test_exclusion_coverage_true_still_unverified(self):
        self.item['manifest']['coverage_claims']['exclusions']=True
        self.item['manifest_sha256']=canonical(self.item['manifest'])
        out=self.apply()
        self.assertEqual(out['exclusion_coverage_state'],'UNVERIFIED')
        self.assertIs(out['exclusion_completeness_claim'],True)
    def test_fd_budget_rejected_before_any_runner_call(self):
        with patch.object(materializer.resource,'getrlimit',return_value=(20,20)), \
             patch.object(materializer,'_count_open_descriptors',return_value=4):
            with self.assertRaisesRegex(materializer.MaterializeError,'DIRECTORY_FD_BUDGET') as cm:self.apply()
        self.assertEqual(cm.exception.phase,'ROOT_PREFLIGHT');self.assertFalse(cm.exception.partial_target)
        self.assertEqual(self.runner.calls,[]);self.assertEqual(list(self.root.iterdir()),[])
    def test_fd_inventory_unavailable_refuses_before_runner(self):
        with patch.object(materializer,'_count_open_descriptors',side_effect=materializer.MaterializeError('FD_INVENTORY_UNAVAILABLE','ROOT_PREFLIGHT')):
            with self.assertRaisesRegex(materializer.MaterializeError,'FD_INVENTORY_UNAVAILABLE'):self.apply()
        self.assertEqual(self.runner.calls,[]);self.assertEqual(list(self.root.iterdir()),[])
    def test_target_name_limit_rejected_before_runner(self):
        old=self.item['manifest'];self.item=model.create(head_commit=old['head_commit_claim'],head={b'file':('file','100644',b'head\n')},index={b'file':('file','100644',b'head\n')},tracked_worktree={b'file':('file','100644',b'head\n')},untracked={b'x'*256:('file','100644',b'x')},excluded={},coverage_claims=old['coverage_claims'])
        with self.assertRaisesRegex(materializer.MaterializeError,'TARGET_COMPONENT_LIMIT'):self.apply()
        self.assertEqual(self.runner.calls,[]);self.assertEqual(list(self.root.iterdir()),[])
    def test_symlink_target_limit_rejected_before_runner(self):
        old=self.item['manifest'];self.item=model.create(head_commit=old['head_commit_claim'],head={b'file':('file','100644',b'head\n')},index={b'file':('file','100644',b'head\n')},tracked_worktree={b'file':('file','100644',b'head\n')},untracked={b'link':('symlink','120000',b'x'*4096)},excluded={},coverage_claims=old['coverage_claims'])
        with self.assertRaisesRegex(materializer.MaterializeError,'TARGET_SYMLINK_LIMIT'):self.apply()
        self.assertEqual(self.runner.calls,[]);self.assertEqual(list(self.root.iterdir()),[])
    def test_target_limit_unavailable_refuses_before_runner(self):
        with patch.object(materializer.os,'fpathconf',side_effect=OSError('unavailable')):
            with self.assertRaisesRegex(materializer.MaterializeError,'TARGET_LIMITS_UNAVAILABLE'):self.apply()
        self.assertEqual(self.runner.calls,[])
    def _add_second_directory(self):
        m=self.item['manifest'];self.item=model.create(head_commit=m['head_commit_claim'],head={b'file':('file','100644',b'head\n')},index={b'file':('file','100644',b'staged\n'),b'nested/new':('file','100755',b'index\n')},tracked_worktree={b'file':('file','100644',b'work\n'),b'nested/new':('file','100755',b'index\n')},untracked={b'zz/extra':('file','100644',b'extra\n')},excluded={},coverage_claims=m['coverage_claims'])
    def test_directory_close_failure_attempts_remaining_closes(self):
        self._add_second_directory();real=os.close;attempted=[]
        def flaky(fd):
            info=os.fstat(fd)
            if fd!=self.fd and stat.S_ISDIR(info.st_mode):
                attempted.append(fd);real(fd)
                if len(attempted)==1:raise OSError('synthetic unknown close')
                return
            return real(fd)
        with patch.object(materializer.os,'close',side_effect=flaky):
            with self.assertRaisesRegex(materializer.MaterializeError,'CLOSE_OUTCOME_UNKNOWN_PARTIAL_TARGET') as cm:self.apply()
        self.assertEqual(len(attempted),2);self.assertTrue(cm.exception.partial_target)
        dirs=[x['state'] for x in cm.exception.close_outcomes if x['kind']=='DIRECTORY']
        self.assertEqual(dirs,['UNKNOWN','CLOSED'])
        self.assertEqual((self.root/'zz/extra').read_bytes(),b'extra\n')
    def test_original_error_survives_directory_close_failure(self):
        self._add_second_directory();real_close=os.close;real_write=materializer._write_all;attempted=[]
        def flaky_close(fd):
            info=os.fstat(fd)
            if fd!=self.fd and stat.S_ISDIR(info.st_mode):
                attempted.append(fd);real_close(fd);raise OSError('synthetic unknown close')
            return real_close(fd)
        def fail_nested(fd,data):
            if data==b'index\n':raise materializer.MaterializeError('SYNTHETIC_ORIGINAL','WORKTREE')
            return real_write(fd,data)
        with patch.object(materializer.os,'close',side_effect=flaky_close), patch.object(materializer,'_write_all',side_effect=fail_nested):
            with self.assertRaisesRegex(materializer.MaterializeError,'SYNTHETIC_ORIGINAL') as cm:self.apply()
        self.assertEqual(cm.exception.code,'SYNTHETIC_ORIGINAL');self.assertTrue(cm.exception.partial_target)
        self.assertEqual(len(attempted),1)
        self.assertTrue(any(x['kind']=='DIRECTORY' and x['state']=='UNKNOWN' for x in cm.exception.close_outcomes))
    def test_file_close_failure_marks_unknown_and_stops(self):
        real=os.close;hit=[]
        def flaky(fd):
            info=os.fstat(fd)
            if stat.S_ISREG(info.st_mode) and not hit:
                hit.append(fd);real(fd);raise OSError('synthetic unknown close')
            return real(fd)
        with patch.object(materializer.os,'close',side_effect=flaky):
            with self.assertRaisesRegex(materializer.MaterializeError,'FILE_CLOSE_UNKNOWN_PARTIAL_TARGET') as cm:self.apply()
        self.assertTrue(cm.exception.partial_target)
        self.assertTrue(any(x['kind']=='FILE' and x['state']=='UNKNOWN' for x in cm.exception.close_outcomes))
        self.assertTrue((self.root/'file').is_file());self.assertFalse((self.root/'ignored.tmp').exists())

    def test_unknown_name_limit_fails_before_runner(self):
        with patch.object(materializer.os,'fpathconf',side_effect=lambda fd,key: {'PC_NAME_MAX':-1,'PC_SYMLINK_MAX':4095}[key]):
            with self.assertRaisesRegex(materializer.MaterializeError,'TARGET_LIMITS_UNAVAILABLE'): self.apply()
        self.assertEqual(self.runner.calls,[]); self.assertEqual(list(self.root.iterdir()),[])
    def test_unknown_symlink_limit_without_symlink_is_recorded(self):
        old=self.item['manifest']; self.item=model.create(head_commit=old['head_commit_claim'],head={b'file':('file','100644',b'head\n')},index={b'file':('file','100644',b'head\n')},tracked_worktree={b'file':('file','100644',b'head\n')},untracked={},excluded={},coverage_claims=old['coverage_claims'])
        with patch.object(materializer.os,'fpathconf',side_effect=lambda fd,key: {'PC_NAME_MAX':255,'PC_SYMLINK_MAX':-1}[key]): out=self.apply()
        limits=out['target_limit_preflight']; self.assertEqual(limits['symlink_limit_authority'],'UNKNOWN')
        self.assertIsNone(limits['symlink_target_filesystem_limit']);self.assertEqual(out['observed_symlink_readbacks'],0)
    def test_unknown_symlink_limit_creates_and_reads_dangling_target(self):
        old=self.item['manifest']; self.item=model.create(head_commit=old['head_commit_claim'],head={b'file':('file','100644',b'head\n')},index={b'file':('file','100644',b'head\n')},tracked_worktree={b'file':('file','100644',b'head\n')},untracked={b'link':('symlink','120000',b'../missing')},excluded={},coverage_claims=old['coverage_claims'])
        with patch.object(materializer.os,'fpathconf',side_effect=lambda fd,key: {'PC_NAME_MAX':255,'PC_SYMLINK_MAX':-1}[key]): out=self.apply()
        self.assertEqual(os.readlink(self.root/'link'),'../missing');self.assertTrue((self.root/'link').is_symlink())
        limits=out['target_limit_preflight'];self.assertEqual(limits['symlink_limit_authority'],'UNKNOWN')
        self.assertIsNone(limits['symlink_target_filesystem_limit']);self.assertEqual(limits['symlink_target_input_budget'],4095)
        self.assertEqual(out['observed_symlink_readbacks'],1)
    def test_known_symlink_limit_rejects_before_runner(self):
        with patch.object(materializer.os,'fpathconf',side_effect=lambda fd,key: {'PC_NAME_MAX':255,'PC_SYMLINK_MAX':5}[key]):
            with self.assertRaisesRegex(materializer.MaterializeError,'TARGET_SYMLINK_LIMIT') as cm:self.apply()
        self.assertFalse(cm.exception.partial_target);self.assertEqual(self.runner.calls,[]);self.assertEqual(list(self.root.iterdir()),[])
    def test_unknown_symlink_limit_input_budget_rejects_before_runner(self):
        old=self.item['manifest'];self.item=model.create(head_commit=old['head_commit_claim'],head={b'file':('file','100644',b'head\n')},index={b'file':('file','100644',b'head\n')},tracked_worktree={b'file':('file','100644',b'head\n')},untracked={b'link':('symlink','120000',b'x'*4096)},excluded={},coverage_claims=old['coverage_claims'])
        with patch.object(materializer.os,'fpathconf',side_effect=lambda fd,key: {'PC_NAME_MAX':255,'PC_SYMLINK_MAX':-1}[key]):
            with self.assertRaisesRegex(materializer.MaterializeError,'TARGET_SYMLINK_LIMIT'):self.apply()
        self.assertEqual(self.runner.calls,[]);self.assertEqual(list(self.root.iterdir()),[])
    def test_unknown_symlink_creation_failure_is_partial_inconclusive(self):
        with patch.object(materializer.os,'fpathconf',side_effect=lambda fd,key: {'PC_NAME_MAX':255,'PC_SYMLINK_MAX':-1}[key]), patch.object(materializer.os,'symlink',side_effect=OSError('synthetic failure')):
            with self.assertRaisesRegex(materializer.MaterializeError,'SYMLINK_OPERATION_FAILED_PARTIAL_TARGET') as cm:self.apply()
        self.assertTrue(cm.exception.partial_target);self.assertEqual(cm.exception.outcome,'INCONCLUSIVE');self.assertTrue((self.root/'.git').is_dir());self.assertTrue((self.root/'file').is_file())
    def test_unknown_symlink_readback_mismatch_is_partial_inconclusive(self):
        with patch.object(materializer.os,'fpathconf',side_effect=lambda fd,key: {'PC_NAME_MAX':255,'PC_SYMLINK_MAX':-1}[key]), patch.object(materializer.os,'readlink',return_value=b'wrong'):
            with self.assertRaisesRegex(materializer.MaterializeError,'SYMLINK_IDENTITY_UNKNOWN') as cm:self.apply()
        self.assertTrue(cm.exception.partial_target);self.assertEqual(cm.exception.outcome,'INCONCLUSIVE');self.assertTrue((self.root/'link').is_symlink());self.assertEqual(os.readlink(self.root/'link'),'nested/new')
    def test_runner_interruption_is_propagated_inconclusive(self):
        original=self.runner; interruption=KeyboardInterrupt('synthetic runner')
        def run(args,data,limit):
            value=original(args,data,limit)
            if args[0]=='init': raise interruption
            return value
        self.runner=run
        with self.assertRaises(KeyboardInterrupt) as cm:self.apply()
        self.assertIs(cm.exception,interruption);self.assertEqual(interruption.materializer_outcome,'INCONCLUSIVE')
        self.assertEqual(interruption.materializer_partial_target,'UNKNOWN');self.assertTrue((self.root/'.git').is_dir())
    def test_unknown_symlink_readback_failure_is_partial_inconclusive(self):
        with patch.object(materializer.os,'fpathconf',side_effect=lambda fd,key: {'PC_NAME_MAX':255,'PC_SYMLINK_MAX':-1}[key]), patch.object(materializer.os,'readlink',side_effect=OSError('synthetic failure')):
            with self.assertRaisesRegex(materializer.MaterializeError,'SYMLINK_OPERATION_FAILED_PARTIAL_TARGET') as cm:self.apply()
        self.assertTrue(cm.exception.partial_target);self.assertEqual(cm.exception.outcome,'INCONCLUSIVE');self.assertTrue((self.root/'link').is_symlink())
    def test_keyboard_interrupt_close_propagates_after_other_closes(self):
        self._add_second_directory(); real=os.close; attempted=[]; interruption=KeyboardInterrupt('synthetic')
        def flaky(fd):
            if fd != self.fd and stat.S_ISDIR(os.fstat(fd).st_mode):
                attempted.append(fd); real(fd)
                if len(attempted)==1: raise interruption
                return
            return real(fd)
        with patch.object(materializer.os,'close',side_effect=flaky):
            with self.assertRaises(KeyboardInterrupt) as cm: self.apply()
        self.assertIs(cm.exception,interruption); self.assertEqual(len(attempted),2)
        self.assertEqual([x['state'] for x in interruption.materializer_close_outcomes if x['kind']=='DIRECTORY'],['UNKNOWN','CLOSED'])
        self.assertEqual(interruption.materializer_untracked_fd_state,'UNKNOWN_ON_ASYNC_INTERRUPTION')
    def test_system_exit_close_preserves_prior_error(self):
        self._add_second_directory(); real=os.close; write=materializer._write_all; attempted=[]
        interruption=SystemExit(74); original=materializer.MaterializeError('SYNTHETIC_ORIGINAL','WORKTREE')
        def flaky(fd):
            if fd != self.fd and stat.S_ISDIR(os.fstat(fd).st_mode):
                attempted.append(fd); real(fd); raise interruption
            return real(fd)
        def fail(fd,data):
            if data==b'index\n': raise original
            return write(fd,data)
        with patch.object(materializer.os,'close',side_effect=flaky), patch.object(materializer,'_write_all',side_effect=fail):
            with self.assertRaises(SystemExit) as cm: self.apply()
        self.assertIs(cm.exception,interruption); self.assertIs(interruption.materializer_prior_error,original)
        self.assertEqual([x['state'] for x in interruption.materializer_close_outcomes if x['kind']=='DIRECTORY'],['UNKNOWN'])
    def test_body_interrupt_survives_directory_close_failure(self):
        self._add_second_directory(); real=os.close; write=materializer._write_all; interruption=KeyboardInterrupt('original')
        def flaky(fd):
            if fd != self.fd and stat.S_ISDIR(os.fstat(fd).st_mode): real(fd); raise OSError('synthetic')
            return real(fd)
        def fail(fd,data):
            if data==b'index\n': raise interruption
            return write(fd,data)
        with patch.object(materializer.os,'close',side_effect=flaky), patch.object(materializer,'_write_all',side_effect=fail):
            with self.assertRaises(KeyboardInterrupt) as cm: self.apply()
        self.assertIs(cm.exception,interruption)
        self.assertTrue(any(x['kind']=='DIRECTORY' and x['state']=='UNKNOWN' for x in interruption.materializer_close_outcomes))
        self.assertEqual(interruption.materializer_untracked_fd_state,'UNKNOWN_ON_ASYNC_INTERRUPTION')
    def test_file_close_interrupt_preserves_original_and_closes_directory(self):
        self._add_second_directory(); real=os.close; write=materializer._write_all; hit=[]
        interruption=KeyboardInterrupt('close'); original=materializer.MaterializeError('SYNTHETIC_ORIGINAL','WORKTREE')
        def flaky(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode) and os.readlink('/proc/self/fd/%d'%fd).endswith('/nested/new') and not hit:
                hit.append(fd); real(fd); raise interruption
            return real(fd)
        def fail(fd,data):
            if data==b'index\n': raise original
            return write(fd,data)
        with patch.object(materializer.os,'close',side_effect=flaky), patch.object(materializer,'_write_all',side_effect=fail):
            with self.assertRaises(KeyboardInterrupt) as cm: self.apply()
        self.assertIs(cm.exception,interruption); self.assertIs(interruption.materializer_prior_error,original)
        self.assertTrue(any(x['kind']=='FILE' and x['state']=='UNKNOWN' for x in interruption.materializer_close_outcomes))
        self.assertTrue(any(x['kind']=='DIRECTORY' and x['state']=='CLOSED' for x in interruption.materializer_close_outcomes))

if __name__=='__main__': unittest.main(verbosity=2)

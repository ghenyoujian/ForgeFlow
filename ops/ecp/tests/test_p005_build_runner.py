from __future__ import annotations
import contextlib,fcntl,hashlib,importlib.util,io,json,os,subprocess,tempfile,unittest
from pathlib import Path,PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('p005_build_runner',ROOT/'ops/ecp/p005_build_runner.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class BuildRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name)
        self.target=self.base/'target';self.target.mkdir()
        self.lock=self.base/'lock';self.lock.touch()
        self.real_source=Path('/mnt/d/Product/ForgeFlow/control')
        self.args=SimpleNamespace(profile='isolated',evidence_root=str(self.base/'evidence'),output=None,
            candidate_root=None,p005_manifest=None,p005_receipt=None,p005_manifest_sha256=None)
    def call(self):
        with patch.object(r,'ROOT',self.real_source),patch.object(r,'BUILD_LOCK',self.lock),patch.object(r,'TARGET',self.target),contextlib.redirect_stdout(io.StringIO()):
            return r.execute_suite(self.args,self.real_source,'a'*40,{'source_sha':'a'*40})

    def test_real_empty_target_does_not_make_quota_assumption(self):
        measured=r.scan_target(self.target)
        self.assertEqual(measured['status'],'PASS')
        with patch.object(r,'mount_for',return_value={'mount':'/','fstype':'ext4','device':'/dev/fixture','options':[]}):
            with self.assertRaisesRegex(r.Blocked,'quota is unavailable'):r.project_quota(self.target)
        result,code=self.call()
        self.assertEqual(code,20);self.assertEqual(result['status'],'BLOCKED');self.assertEqual(result['product_gate_effect'],'NONE')
        self.assertEqual(set(result['workloads'].values()),{'NOT_RUN'});self.assertTrue((self.base/'evidence/result.json').exists())

    def test_existing_evidence_is_never_modified(self):
        evidence=self.base/'evidence';evidence.mkdir();p=evidence/'result.json';p.write_text('original evidence')
        result,code=self.call();self.assertEqual(code,20);self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(p.read_text(),'original evidence')

    def test_evidence_inside_source_or_target_is_rejected(self):
        for location in (self.real_source/'_p005_invalid_evidence', self.target/'_p005_invalid_evidence'):
            with self.subTest(location=location):
                self.args.evidence_root=str(location)
                result,code=self.call()
                self.assertEqual(code,20);self.assertEqual(result['status'],'BLOCKED')
                self.assertFalse(location.exists())

    def test_coordinated_lock_busy_blocks_without_workloads(self):
        fd=os.open(self.lock,os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            # Exercise the earlier lock branch with a mock only; this cannot
            # authorize execution and no workload is reached.
            with patch.object(r,'require_process_tree_supervisor',return_value=None):
                result,code=self.call()
            self.assertEqual(code,20);self.assertIn('lock is busy',result['reason'])
            self.assertEqual(set(result['workloads'].values()),{'NOT_RUN'})
        finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

    def test_budget_hardlink_and_symlink_protect_target(self):
        f=self.target/'f';f.write_bytes(b'x'*4096)
        with patch.object(r,'TARGET_BUDGET',512):self.assertEqual(r.scan_target(self.target)['status'],'BLOCKED')
        (self.target/'link').symlink_to(f)
        self.assertEqual(r.scan_target(self.target)['status'],'BLOCKED');(self.target/'link').unlink()
        os.link(f,self.target/'hardlink');self.assertEqual(r.scan_target(self.target)['status'],'BLOCKED')
        self.assertEqual(f.read_bytes(),b'x'*4096)

    def test_quota_rejects_missing_inheritance_and_invalid_hard_limit(self):
        mount={'mount':'/','fstype':'ext4','device':'/dev/fixture','options':['prjquota']}
        with patch.object(r,'mount_for',return_value=mount),patch.object(r,'inode_project',return_value=(0,42)):
            with self.assertRaisesRegex(r.Blocked,'inheritable project'):r.project_quota(self.target)
        quota=r.Dqblk();quota.valid=3;quota.bhardlimit=(r.TARGET_BUDGET//1024)+1
        with patch.object(r,'mount_for',return_value=mount),patch.object(r,'inode_project',return_value=(r.FS_XFLAG_PROJINHERIT,42)),\
             patch.object(r,'query_quota',return_value=quota):
            with self.assertRaisesRegex(r.Blocked,'hard limit'):r.project_quota(self.target)

    def test_missing_supervision_blocks_before_logs_and_process(self):
        out=self.base/'stdout';err=self.base/'stderr'
        with patch.object(r.subprocess,'Popen',side_effect=AssertionError('unexpected process')) as spawn, \
             patch.object(r.os,'killpg',side_effect=AssertionError('unexpected signal')) as signal_group:
            with self.assertRaisesRegex(r.Blocked,'process-tree supervision'):
                r.run_bounded(['/untrusted/command'],out,err,env={},timeout=0.01)
        spawn.assert_not_called();signal_group.assert_not_called()
        self.assertFalse(os.path.lexists(out));self.assertFalse(os.path.lexists(err))

    def test_supervisor_check_cannot_enable_unimplemented_runner(self):
        out=self.base/'stdout';err=self.base/'stderr'
        with patch.object(r,'require_process_tree_supervisor',return_value=None), \
             patch.object(r.subprocess,'Popen',side_effect=AssertionError('unexpected process')) as spawn:
            with self.assertRaisesRegex(r.Blocked,'not implemented'):
                r.run_bounded(['/untrusted/command'],out,err,env={})
        spawn.assert_not_called();self.assertFalse(os.path.lexists(out));self.assertFalse(os.path.lexists(err))

    def test_test_denominator_requires_nonzero_and_no_ignored(self):
        p=self.base/'test.log'
        for n in [0,1]:
            p.write_text(f'running 1 test\ntest result: ok. {n} passed; 0 failed; {1-n} ignored; 0 measured; 0 filtered out; finished in 0.1s\n')
            self.assertEqual(r.rust_test_counts(p) is not None,n==1)

    def test_source_readonly_probe_failure_cannot_advance(self):
        targetfd=os.open(self.target,os.O_RDONLY|os.O_DIRECTORY)
        fds={k:targetfd for k in ('usr','rustup','cargo_bin','cargo_registry','npm_cache','source','target','modules','dist','cache')}
        def untrusted_probe(command,out,err,**kwargs):
            out.write_text(json.dumps({'source_readonly':False,'host_socket_absent':True,'net':'fixture'}))
            err.write_text('');return {'exit_code':0,'logs_complete':True}
        try:
            with patch.object(r,'run_bounded',side_effect=untrusted_probe):
                with self.assertRaisesRegex(r.Blocked,'source or host socket'):
                    r.sandbox_probe(fds,self.base,{'PATH':'/usr/bin:/bin'})
        finally:os.close(targetfd)

    def test_long_symlink_probe_requires_actual_inode_and_space_accounting(self):
        def q(inodes,space):
            v=r.Dqblk();v.valid=10;v.curinodes=inodes;v.curspace=space;return v
        with patch.object(r,'query_quota',side_effect=[q(20,10000),q(21,14096),q(20,10000)]):
            result=r.symlink_quota_probe(self.target,{'device':'/dev/fixture','project_id':42})
        self.assertEqual(result['symlink_allocated_bytes'],4096);self.assertEqual(list(self.target.iterdir()),[])
        for space in (10000,14097):
            with self.subTest(space=space), patch.object(r,'query_quota',side_effect=[q(20,10000),q(21,space)]),patch.object(r.time,'monotonic',side_effect=[0,6]):
                with self.assertRaisesRegex(r.Blocked,'symlink inode and space'):r.symlink_quota_probe(self.target,{'device':'/dev/fixture','project_id':42})
            self.assertEqual(list(self.target.iterdir()),[])

    def test_unavailable_source_mode_blocks_before_any_target_write(self):
        source=self.base/'source';source.mkdir();candidate=self.base/'candidate';candidate.mkdir()
        evidence=self.base/'mode-check';evidence.mkdir()
        snapshot=SimpleNamespace(review=lambda *a:{'status':'OBSERVED_NOT_GATE','source_execution_mode':'UNAVAILABLE'})
        progress={'workloads':{name:'NOT_RUN' for name in r.PHASES}}
        with patch.object(r,'require_process_tree_supervisor',return_value=None), \
             patch.object(r,'TARGET',self.target),patch.object(r,'module',return_value=snapshot):
            with self.assertRaisesRegex(r.Blocked,'execution mode'):
                r.run_workload(source,candidate,self.base/'manifest',self.base/'receipt','a'*40,'b'*64,evidence,{},progress)
        self.assertEqual(list(self.target.iterdir()),[])
        self.assertEqual(set(progress['workloads'].values()),{'NOT_RUN'})

    def test_synthetic_controlled_positive_path_runs_every_declared_phase_without_gate(self):
        # This isolates the state machine only: it does not represent a real
        # quota, authenticated executor, build, or product qualification.
        source=self.base/'source';source.mkdir();candidate=self.base/'candidate';(candidate/'console').mkdir(parents=True)
        (candidate/'Cargo.toml').write_text('[workspace]\n');(candidate/'console/package.json').write_text('{}')
        evidence=self.base/'positive';evidence.mkdir()
        inv={'candidate_inventory_sha256':'c'*64,'candidate_file_count':1,'candidate_tree_bytes':1}
        quota={'status':'PASS','project_id':42,'hard_limit_bytes':1024,'device':'/dev/fixture'}
        expected={'Cargo.toml':('100644','a'),'console/package.json':('100644','b')}
        blobs={'a':b'[workspace]\n','b':b'{}'}
        snapshot=SimpleNamespace(review=lambda *a:{'status':'OBSERVED_NOT_GATE','source_execution_mode':'VERIFIED',**inv},
                object_tree=lambda *a:(expected, blobs, 'sha1'),candidate_inventory=lambda *a:dict(inv),
                safe_path=lambda path:PurePosixPath(path),safe_link=lambda path,target:None)
        build=SimpleNamespace(executable_identity=lambda name,root:{'path':name})
        def module(path,name):return snapshot if name=='p005_source_oracle' else build
        def fake_run(command,out,err,**kwargs):
            stdout=(b'running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
                    if command==r.COMMANDS['cargo_test'] else b'synthetic phase')
            out.write_bytes(stdout);err.write_bytes(b'')
            return {'exit_code':0,'reason':None,'logs_complete':True,
                    'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'stderr_sha256':hashlib.sha256(b'').hexdigest()}
        progress={'workloads':{name:'NOT_RUN' for name in r.PHASES}}
        def open_fake_fds(*args):return {'fixture':os.open(self.target,os.O_RDONLY|os.O_DIRECTORY)}
        with patch.object(r,'require_process_tree_supervisor',return_value=None), \
             patch.object(r,'TARGET',self.target),patch.object(r,'module',side_effect=module),\
             patch.object(r,'safe_environment',return_value={'PATH':'/usr/bin:/bin'}),\
             patch.object(r,'project_quota',return_value=quota),patch.object(r,'symlink_quota_probe',return_value={'status':'PASS'}),\
             patch.object(r,'sandbox_inputs',side_effect=open_fake_fds),patch.object(r,'sandbox_probe',return_value={'exit_code':0}),\
             patch.object(r,'sandbox_command',side_effect=lambda fds,command,cwd:command),\
             patch.object(r,'run_bounded',side_effect=fake_run),patch.object(r,'artifact_inventory',return_value={'frontend':{'x':'fixture'}}):
            result=r.run_workload(source,candidate,self.base/'manifest',self.base/'receipt','a'*40,'b'*64,evidence,quota,progress)
        self.assertEqual(result['status'],'INCONCLUSIVE');self.assertEqual(result['product_gate_effect'],'NONE')
        self.assertEqual([phase['name'] for phase in result['phases']],list(r.PHASES))
        self.assertEqual(set(progress['workloads'].values()),{'PASS_OBSERVED'})

if __name__=='__main__':unittest.main()

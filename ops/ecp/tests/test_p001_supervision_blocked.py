"""P001 blocked-entry tests, pure mock; no execution or Gate is established.

Historical functional tests remain untouched and SUSPENDED. These tests cover
only named entry points, not private _v3_head_index, v2 Git, every process API,
continuous identity, other suites, or actual P001 effectiveness.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import types
import unittest
from unittest.mock import patch

import verify
import source_snapshot as snapshot
import normalized_source
import normalized_materialize
from verification.ecp.gates import g0_evidence_review as g0


class P001Blocked(unittest.TestCase):
    def blocked(self, result, code):
        self.assertEqual(code, 20)
        self.assertEqual((result['status'], result['qualification'], result['product_gate_effect']),
                         ('BLOCKED', 'NOT_RUN', 'NONE'))
        self.assertFalse(result['workload_invoked'])

    def test_suite_v3_blocks_before_source_resolution_and_output(self):
        args = argparse.Namespace(suite='ECP-P0-01', phase=None, source_manifest_version='3',
                                  profile='isolated', source_root='/bad/source', output='/bad/output')
        with patch.object(verify, 'resolve_source_root', side_effect=AssertionError('resolve')), \
             patch.object(verify, 'write_report', side_effect=AssertionError('write')), \
             patch.object(verify.subprocess, 'Popen') as popen, \
             patch.object(verify.subprocess, 'run') as run, \
             patch.object(verify.os, 'killpg') as killpg, \
             patch.object(verify.os, 'open', side_effect=AssertionError('open')), \
             patch.object(verify.os, 'mkdir', side_effect=AssertionError('mkdir')), contextlib.redirect_stdout(io.StringIO()) as printed:
            result, code = verify.suite(args)
        self.blocked(result, code); self.assertEqual(json.loads(printed.getvalue()), result)
        self.assertIsNone(result['source_root']); self.assertIsNone(result['source_sha'])
        self.assertEqual(result['denominator'], {'total':4,'passed':0,'failed':0,'blocked':1,'not_run':3,'inconclusive':0})
        self.assertEqual([c['status'] for c in result['checks']], ['BLOCKED','NOT_RUN','NOT_RUN','NOT_RUN'])
        for sentinel in (popen,run,killpg): sentinel.assert_not_called()

    def test_direct_v3_suite_blocks_without_touching_arguments(self):
        class Poison:
            def __fspath__(self): raise AssertionError('path access')
        with patch.object(verify.subprocess, 'Popen') as popen, \
             patch.object(verify.subprocess, 'run') as run, \
             patch.object(verify.os, 'killpg') as killpg, \
             patch.object(verify.os, 'open', side_effect=AssertionError('open')), \
             patch.object(verify.os, 'mkdir', side_effect=AssertionError('mkdir')), contextlib.redirect_stdout(io.StringIO()):
            result, code = verify.run_source_snapshot_v3_suite(argparse.Namespace(profile='test'), Poison(), 'f'*40, {'status':'PASS','source_sha':'e'*40})
        self.blocked(result, code); self.assertIsNone(result['source_root']); self.assertIsNone(result['source_sha'])
        self.assertNotIn('e'*40, json.dumps(result))
        for sentinel in (popen,run,killpg): sentinel.assert_not_called()

    def test_bounded_capture_refuses_before_path_open_and_process_calls(self):
        class Poison:
            def __fspath__(self): raise AssertionError('path access')
        with patch.object(verify.subprocess, 'Popen') as popen, \
             patch.object(verify.subprocess, 'run') as run, \
             patch.object(verify.os, 'killpg') as killpg, \
             patch.object(verify.os, 'open', side_effect=AssertionError('os.open')), \
             patch.object(verify.selectors, 'DefaultSelector', side_effect=AssertionError('selector')), \
             patch.object(Path, 'open', side_effect=AssertionError('open')):
            with self.assertRaises(verify.P001SupervisionUnavailable):
                verify.run_p003_bounded(['unused'], cwd=Poison(), env={}, stdout_path=Poison(), stderr_path=Poison())
        for sentinel in (popen,run,killpg): sentinel.assert_not_called()

    def test_bounded_git_refuses_before_root_and_process_calls(self):
        with patch.object(snapshot, '_v3_open_root', side_effect=AssertionError('root')), \
             patch.object(snapshot.subprocess, 'Popen') as popen, \
             patch.object(snapshot.subprocess, 'run') as run, \
             patch.object(snapshot.os, 'killpg') as killpg:
            with self.assertRaises(snapshot.P001SupervisionUnavailable):
                snapshot._v3_bounded_git(Path('/invalid/root'), ['unused'], -1)
        for sentinel in (popen,run,killpg): sentinel.assert_not_called()

    def test_v3_builders_refuse_before_path_resolution(self):
        class Poison:
            def __fspath__(self): raise AssertionError('path access')
        for builder in (snapshot.build_manifest_v3, snapshot._build_manifest_v3_bounded):
            with self.subTest(builder=builder.__name__), \
                 patch.object(snapshot.subprocess, 'Popen') as popen, \
                 patch.object(snapshot.subprocess, 'run') as run, \
                 patch.object(snapshot.os, 'killpg') as killpg:
                with self.assertRaises(snapshot.P001SupervisionUnavailable): builder(Poison())
                for sentinel in (popen,run,killpg): sentinel.assert_not_called()

    def test_cli_v3_blocks_before_existing_or_invalid_output_checks(self):
        # Path(__file__).resolve for the parser default still occurs first.
        # The sentinel only rejects resolution of supplied source/output paths.
        original_resolve = Path.resolve
        def resolve(path, *args, **kwargs):
            if str(path) in ('/invalid/source','/existing/output'):
                raise AssertionError('user path resolved')
            return original_resolve(path, *args, **kwargs)
        with patch.object(Path, 'resolve', autospec=True, side_effect=resolve), \
             patch.object(Path, 'expanduser', side_effect=AssertionError('expanduser')), \
             patch.object(snapshot.os.path, 'lexists', side_effect=AssertionError('output checked')), \
             patch.object(snapshot.subprocess, 'Popen') as popen, \
             patch.object(snapshot.subprocess, 'run') as run, \
             patch.object(snapshot.os, 'killpg') as killpg, contextlib.redirect_stdout(io.StringIO()) as printed:
            code = snapshot.main(['--manifest-version','3','--source-root','/invalid/source','--output','/existing/output'])
        self.blocked(json.loads(printed.getvalue()), code)
        for sentinel in (popen,run,killpg): sentinel.assert_not_called()

    def test_cli_special_exception_precedes_generic_runtimeerror(self):
        with patch.object(Path, 'resolve', autospec=True, side_effect=lambda p,*a,**k:p), \
             patch.object(snapshot.os.path, 'lexists', return_value=False), \
             patch.object(snapshot, 'build_manifest', side_effect=snapshot.P001SupervisionUnavailable('synthetic')), \
             patch.object(snapshot.subprocess, 'Popen') as popen, \
             patch.object(snapshot.subprocess, 'run') as run, \
             patch.object(snapshot.os, 'killpg') as killpg, contextlib.redirect_stdout(io.StringIO()) as printed:
            code = snapshot.main(['--manifest-version','2','--source-root','/a/source','--output','/b/output'])
        result = json.loads(printed.getvalue()); self.assertEqual(code, 20)
        self.assertEqual((result['status'],result['qualification'],result['product_gate_effect']),('BLOCKED','NOT_RUN','NONE'))
        self.assertIsNone(result['workload_invoked'])
        for sentinel in (popen,run,killpg): sentinel.assert_not_called()

    def test_no_boolean_or_environment_override(self):
        with patch.dict(os.environ, {'ECP_P001_ENABLE':'1','ECP_SUPERVISION_VERIFIED':'1'}), \
             patch.object(snapshot.subprocess, 'Popen') as popen:
            with self.assertRaises(snapshot.P001SupervisionUnavailable): snapshot.build_manifest_v3(Path('/unused'))
        popen.assert_not_called()

    def test_g0_pin_mismatch_fails_only_when_helper_loading_is_called(self):
        # Reading the fixed candidate file is test input; all helper open/read
        # calls are then mocked. No reviewer, source snapshot or workload runs.
        data = Path(snapshot.__file__).read_bytes()
        info = types.SimpleNamespace(st_mode=stat.S_IFREG|0o644, st_size=len(data), st_dev=1, st_ino=2,
                                     st_mtime_ns=3, st_ctime_ns=4)
        self.assertNotEqual(hashlib.sha256(data).hexdigest(), g0.SOURCE_SNAPSHOT_SHA256)
        with patch.object(g0.os, 'open', return_value=4321), \
             patch.object(g0.os, 'fstat', return_value=info), \
             patch.object(g0.os, 'read', side_effect=[data,b'']), \
             patch.object(g0.os, 'close') as close, \
             patch.object(g0.subprocess, 'Popen') as popen, \
             patch.object(g0.subprocess, 'run') as run:
            with self.assertRaises(g0.Incomplete): g0.source_snapshot_tool()
        close.assert_called_once_with(4321); popen.assert_not_called(); run.assert_not_called()

    def test_normalized_source_propagates_guard_without_converting_to_status(self):
        root = Path('/synthetic/source')
        core = {'schema_version':snapshot.V3_SCHEMA, 'source_root':str(root), 'worktree_state':'CLEAN',
                'inventory_complete':True, 'directory_projection':{'mode_availability':'UNAVAILABLE',
                    'directories':[{'path':'.','kind':'directory','mode':None,'origin':'source_root'}]}}
        digest = hashlib.sha256(snapshot._v3_canonical(core)).hexdigest()
        manifest = dict(core, manifest_sha256=digest, release_qualifiable=False)
        info = types.SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFDIR|0o700,st_size=0,st_mtime_ns=0,st_ctime_ns=0)
        with patch.object(snapshot, '_v3_open_root_by_path', side_effect=[101,102]), \
             patch.object(normalized_source.os, 'fstat', return_value=info), \
             patch.object(normalized_source.os, 'close'), \
             patch.object(snapshot.subprocess, 'Popen') as popen, \
             patch.object(snapshot.subprocess, 'run') as run:
            with self.assertRaises(snapshot.P001SupervisionUnavailable):
                normalized_source.observe_source(root, manifest, digest)
        popen.assert_not_called(); run.assert_not_called()

    def test_materialization_first_observation_error_precedes_mkdir(self):
        # Fake all filesystem interactions, including FD close and metadata.
        uid,gid = os.geteuid(),os.getegid(); digest='a'*64
        manifest={'manifest_sha256':digest}; supplement={}
        policy={'owner':{'uid':uid,'gid':gid},'directories':[],'entries':[],
                'attributes':{'umask':'077'},'source_supplement_sha256':digest}
        info=types.SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=stat.S_IFDIR|0o700)
        m=normalized_materialize
        with contextlib.ExitStack() as stack:
            for obj,name,kwargs in [
                (m.policy_lib,'validate_policy',{}),(m.policy_lib,'canonical_sha256',{'return_value':digest}),
                (m,'_require_umask',{}),(m.snapshot,'_v3_checked_path',{}),
                (m.legacy,'_v3_open_directory',{'side_effect':[(None,101),(None,102)]}),
                (m.os,'close',{}),(m.os,'fstat',{'return_value':info}),(m,'_no_xattrs',{}),
                (m.legacy,'_v3_assert_output_parent_binding',{}),(m.legacy,'_v3_parent_within_source',{'return_value':False}),
                (m.legacy,'_v3_parent_mount_aliases_source',{'return_value':False}),
                (m.snapshot,'_v3_mount_status',{'return_value':('VERIFIED','synthetic')}),
                (m.os,'stat',{'side_effect':FileNotFoundError()}),(m.legacy,'_v3_assert_source_binding',{}),
                (m.normalized_source,'observe_source',{'side_effect':snapshot.P001SupervisionUnavailable('injected')})]:
                stack.enter_context(patch.object(obj,name,**kwargs))
            mkdir=stack.enter_context(patch.object(m.os,'mkdir'))
            with self.assertRaises(snapshot.P001SupervisionUnavailable):
                m.materialize_draft(Path('/source'),manifest,supplement,policy,manifest_sha256=digest,
                                    supplement_sha256=digest,policy_sha256=digest,candidate_root=Path('/dest/child'))
            mkdir.assert_not_called()

    def test_materialization_second_observation_retains_mock_stage_and_cause(self):
        # Counterfactual branch: first observation is injected as successful;
        # all apparent stage operations below are mocks, no stage exists.
        uid,gid = os.geteuid(),os.getegid(); digest='a'*64
        manifest={'manifest_sha256':digest}; supplement={'source_head':'b'*40,'entries':[]}
        policy={'owner':{'uid':uid,'gid':gid},'directories':[],'entries':[],
                'attributes':{'umask':'077'},'source_supplement_sha256':digest}
        info=types.SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=stat.S_IFDIR|0o700,
            st_dev=1,st_ino=2,st_nlink=1,st_size=0,st_mtime_ns=3,st_ctime_ns=4)
        cause=snapshot.P001SupervisionUnavailable('second observation injected'); m=normalized_materialize
        def fake_stat(name, *args, **kwargs):
            if name == 'child': raise FileNotFoundError()
            return info
        with contextlib.ExitStack() as stack:
            for obj,name,kwargs in [
                (m.policy_lib,'validate_policy',{}),(m.policy_lib,'canonical_sha256',{'return_value':digest}),
                (m,'_require_umask',{}),(m.snapshot,'_v3_checked_path',{}),
                (m.legacy,'_v3_open_directory',{'side_effect':[(None,101),(None,102)]}),
                (m.os,'close',{}),(m.os,'fstat',{'return_value':info}),(m,'_no_xattrs',{}),
                (m.legacy,'_v3_assert_output_parent_binding',{}),(m.legacy,'_v3_parent_within_source',{'return_value':False}),
                (m.legacy,'_v3_parent_mount_aliases_source',{'return_value':False}),
                (m.snapshot,'_v3_mount_status',{'return_value':('VERIFIED','synthetic')}),
                (m.os,'stat',{'side_effect':fake_stat}),(m.legacy,'_v3_assert_source_binding',{}),
                (m.os,'open',{'return_value':103}),(m,'_sync_batch',{}),
                (m,'_sync_directories',{'return_value':{}}),(m,'_inventory',{'return_value':{}}),
                (m.secrets,'token_hex',{'return_value':'fixed'})]:
                stack.enter_context(patch.object(obj,name,**kwargs))
            observer=stack.enter_context(patch.object(m.normalized_source,'observe_source',side_effect=[supplement,cause]))
            mkdir=stack.enter_context(patch.object(m.os,'mkdir'))
            rename=stack.enter_context(patch.object(m,'_rename_noreplace'))
            unlink=stack.enter_context(patch.object(m.os,'unlink'))
            with self.assertRaises(m.DraftRetained) as caught:
                m.materialize_draft(Path('/source'),manifest,supplement,policy,manifest_sha256=digest,
                                    supplement_sha256=digest,policy_sha256=digest,candidate_root=Path('/dest/child'))
            self.assertIs(caught.exception.__cause__,cause)
            self.assertEqual(caught.exception.stage_path,'/dest/.forgeflow-draft-fixed')
            self.assertEqual(caught.exception.stage_attribution,'CREATION_RETURNED_NOT_AUTHENTICATED')
            self.assertEqual(observer.call_count,2)
            mkdir.assert_called_once(); rename.assert_not_called(); unlink.assert_not_called()

    def test_materialization_attempted_publication_remains_uncertain(self):
        cause=snapshot.P001SupervisionUnavailable('injected after attempted publish')
        def fail(*args, **kwargs):
            state=kwargs['state']; state.update(attempted=True,stage_path='/synthetic/stage',candidate_path='/synthetic/dest')
            raise cause
        m=normalized_materialize
        with patch.object(m,'_materialize_draft',side_effect=fail), patch.object(m.os,'mkdir') as mkdir:
            with self.assertRaises(m.DraftPublicationUncertain) as caught:
                m.materialize_draft(Path('/s'),{}, {}, {},manifest_sha256='a',supplement_sha256='b',policy_sha256='c',candidate_root=Path('/d'))
        self.assertIs(caught.exception.__cause__,cause); self.assertEqual(caught.exception.stage_path,'/synthetic/stage')
        self.assertEqual(caught.exception.candidate_path,'/synthetic/dest'); mkdir.assert_not_called()

if __name__ == '__main__': unittest.main()

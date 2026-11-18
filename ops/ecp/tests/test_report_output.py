"""Private retained fixtures only; never Git, DB, subprocess or production workload."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

source_stub=types.ModuleType('source_snapshot')
source_stub.DEFAULT_EXCLUDES=()
source_stub.build_manifest=lambda *_a,**_kw: None
sentinel=object()
old_src=sys.modules.get('source_snapshot',sentinel)
old_mod=sys.modules.get('r37_verify_candidate',sentinel)
sys.modules['source_snapshot']=source_stub
try:
    verify_path=os.environ.get('ECP_VERIFY_PATH') or str(Path(__file__).resolve().parent.parent / 'verify.py')
    spec=importlib.util.spec_from_file_location('r37_verify_candidate',verify_path)
    verify=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=verify
    spec.loader.exec_module(verify)
finally:
    if old_src is sentinel: sys.modules.pop('source_snapshot',None)
    else: sys.modules['source_snapshot']=old_src
    if old_mod is sentinel: sys.modules.pop('r37_verify_candidate',None)
    else: sys.modules['r37_verify_candidate']=old_mod

class OutputTests(unittest.TestCase):
    def setUp(self):
        requested_root=os.environ.get('ECP_REPORT_TEST_ROOT')
        if requested_root:
            self.root=Path(requested_root) / self._testMethodName
            self.root.mkdir(mode=0o700)
        else:
            # Private directories remain available for inspection; never delete
            # by pathname, since another same-UID actor could replace them.
            self.root=Path(tempfile.mkdtemp(prefix='forgeflow-report-output-'))
    def report(self,status='INCONCLUSIVE'):
        return {'status':status,'product_gate_effect':'NONE','reason':'synthetic','evidence_refs':['already']}
    def finish(self,report,output,code=20):
        if hasattr(verify,'finish_report'):
            return verify.finish_report(report,output,code)
        return verify.write_report(report,output),code
    def capture(self,report,output,code=20):
        out,err=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            value,rc=self.finish(report,str(output) if output is not None else None,code)
        return value,rc,out.getvalue(),err.getvalue()
    def blocked(self,report,output,reason='OUTPUT_ALREADY_EXISTS',code=20):
        value,rc,out,err=self.capture(report,output)
        self.assertEqual(rc,code);self.assertEqual(out,'')
        self.assertEqual(json.loads(err),value)
        self.assertEqual(value['status'],'FAIL' if code==10 else 'BLOCKED')
        self.assertEqual(value['reason'],reason)
        self.assertEqual(value['evidence_report'],report)
        self.assertNotIn(str(output),report['evidence_refs'])
        return value
    def test_no_output_preserves_report_and_stdout(self):
        r=self.report();value,rc,out,err=self.capture(r,None)
        self.assertIs(value,r);self.assertEqual(rc,20);self.assertEqual(json.loads(out),r);self.assertEqual(err,'')
    def test_fresh_output_is_single_complete_report(self):
        r=self.report();dst=self.root/'new.json';value,rc,out,err=self.capture(r,dst)
        self.assertEqual((rc,err),(20,''));self.assertEqual(json.loads(out),value)
        self.assertEqual(json.loads(dst.read_text()),value)
        self.assertEqual(value['evidence_refs'],sorted(['already',str(dst)]))
        self.assertEqual(dst.stat().st_mode & 0o777,0o600)
    def test_existing_output_is_preserved(self):
        dst=self.root/'exists';dst.write_bytes(b'user\x00data');v=self.blocked(self.report(),dst)
        self.assertEqual(v['output_status'],'NOT_CREATED_BY_THIS_CALL');self.assertEqual(dst.read_bytes(),b'user\x00data')
    def test_final_symlink_and_target_are_preserved(self):
        target=self.root/'target';target.write_bytes(b'target');link=self.root/'link';link.symlink_to(target)
        self.blocked(self.report(),link);self.assertTrue(link.is_symlink());self.assertEqual(target.read_bytes(),b'target')
    def test_dangling_final_symlink_is_preserved(self):
        target=self.root/'missing';link=self.root/'link';link.symlink_to(target)
        self.blocked(self.report(),link);self.assertTrue(link.is_symlink());self.assertFalse(target.exists())
    def test_intermediate_symlink_is_rejected(self):
        target=self.root/'target';target.mkdir();link=self.root/'link';link.symlink_to(target,target_is_directory=True)
        self.blocked(self.report(),link/'new','OUTPUT_PARENT_UNAVAILABLE')
        self.assertEqual(list(target.iterdir()),[])
    def test_missing_parent_not_created(self):
        parent=self.root/'missing';self.blocked(self.report(),parent/'new','OUTPUT_PARENT_UNAVAILABLE');self.assertFalse(parent.exists())
    def test_hardlink_output_does_not_change_other_name(self):
        original=self.root/'original';original.write_bytes(b'original');other=self.root/'other';os.link(original,other)
        self.blocked(self.report(),other);self.assertEqual(original.read_bytes(),b'original')
    def test_output_equals_report_input_does_not_destroy_input(self):
        target=self.root/'input.json';original=b'{"status":"INCONCLUSIVE","source_sha":"' + b'a'*40 + b'"}'
        target.write_bytes(original)
        args=verify.parser().parse_args(['report','--source-root',str(self.root),'--source-sha','a'*40,'--input',str(target),'--output',str(target)])
        out,err=io.StringIO(),io.StringIO()
        with patch.object(verify,'git_sha',side_effect=AssertionError('Git not permitted')),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            value,rc=verify.aggregate_reports(args)
        self.assertEqual((rc,out.getvalue()),(20,''));self.assertEqual(value['reason'],'OUTPUT_ALREADY_EXISTS')
        self.assertEqual(value['evidence_report']['input_count'],1);self.assertEqual(target.read_bytes(),original)
    def test_failure_status_is_preserved_when_output_exists(self):
        dst=self.root/'exists';dst.write_bytes(b'keep');self.blocked(self.report('FAIL'),dst,code=10);self.assertEqual(dst.read_bytes(),b'keep')
    def test_short_writes_are_completed(self):
        dst=self.root/'short';real=os.write
        with patch.object(verify.os,'write',side_effect=lambda fd,data:real(fd,data[:4])):
            value,rc,out,err=self.capture(self.report(),dst)
        self.assertEqual((rc,err),(20,''));self.assertEqual(json.loads(dst.read_text()),value);self.assertEqual(json.loads(out),value)
    def test_partial_write_failure_keeps_file_and_reports_unknown(self):
        dst=self.root/'partial';real=os.write;count=[0]
        def write(fd,data):
            count[0]+=1
            if count[0]==1:return real(fd,data[:5])
            raise OSError('injected failure')
        with patch.object(verify.os,'write',side_effect=write):
            value=self.blocked(self.report(),dst,'OUTPUT_WRITE_OR_CLOSE_UNKNOWN')
        self.assertEqual(value['output_status'],'UNKNOWN_PARTIAL');self.assertTrue(dst.exists());self.assertEqual(len(dst.read_bytes()),5)
    def test_fsync_failure_reports_unknown_and_retains_file(self):
        dst=self.root/'fsync'
        with patch.object(verify.os,'fsync',side_effect=OSError('injected failure')):
            value=self.blocked(self.report(),dst,'OUTPUT_WRITE_OR_CLOSE_UNKNOWN')
        self.assertEqual(value['output_status'],'UNKNOWN_PARTIAL');self.assertTrue(dst.exists())
    def test_close_failure_reports_unknown_and_retains_file(self):
        dst=self.root/'close';realopen=os.open;realclose=os.close;target=[]
        def opened(path,flags,*args,**kwargs):
            fd=realopen(path,flags,*args,**kwargs)
            if path=='close' and flags & os.O_CREAT:target.append(fd)
            return fd
        def closed(fd):
            realclose(fd)
            if target and fd==target[0]:raise OSError('injected close failure')
        with patch.object(verify.os,'open',side_effect=opened),patch.object(verify.os,'close',side_effect=closed):
            value=self.blocked(self.report(),dst,'OUTPUT_WRITE_OR_CLOSE_UNKNOWN')
        self.assertEqual(value['output_status'],'UNKNOWN_PARTIAL');self.assertTrue(dst.exists())
    def test_doctor_output_failure_returns_diagnostic(self):
        dst=self.root/'doctor';dst.write_bytes(b'keep')
        args=verify.parser().parse_args(['doctor','--source-root',str(self.root),'--output',str(dst)])
        c=verify.Check('synthetic','PASS','synthetic',{})
        out,err=io.StringIO(),io.StringIO()
        with patch.object(verify,'check_source_identity',return_value=(c,None,[])),patch.object(verify,'check_required_inputs',return_value=c),patch.object(verify,'check_tools',return_value=[]),patch.object(verify,'check_database_policy',return_value=c),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            value,rc=verify.doctor(args)
        self.assertEqual((rc,out.getvalue()),(20,''));self.assertEqual(value['status'],'BLOCKED');self.assertEqual(value['evidence_report']['command'],'doctor');self.assertEqual(dst.read_bytes(),b'keep')
    def test_suite_output_failure_returns_diagnostic(self):
        dst=self.root/'suite';dst.write_bytes(b'keep')
        args=verify.parser().parse_args(['suite','--suite','synthetic','--source-root',str(self.root),'--output',str(dst)])
        out,err=io.StringIO(),io.StringIO()
        with patch.object(verify,'git_sha',side_effect=AssertionError('Git forbidden')),patch.object(verify,'load_declared_suite',return_value=(None,{'suite_id':'synthetic'},None)),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            value,rc=verify.suite(args)
        self.assertEqual((rc,out.getvalue()),(20,''));self.assertEqual(value['status'],'BLOCKED');self.assertEqual(value['evidence_report']['status'],'NOT_RUN');self.assertEqual(dst.read_bytes(),b'keep')
    def test_dot_final_component_does_not_create_missing_target(self):
        missing=self.root/'missing'
        self.blocked(self.report(),str(missing)+'/.','OUTPUT_PATH_INVALID')
        self.assertFalse(missing.exists())
    def test_dot_final_component_preserves_existing_directory(self):
        directory=self.root/'directory';directory.mkdir();marker=directory/'marker';marker.write_bytes(b'keep')
        self.blocked(self.report(),str(directory)+'/.','OUTPUT_PATH_INVALID')
        self.assertTrue(directory.is_dir());self.assertEqual(marker.read_bytes(),b'keep')
    def test_unserializable_report_produces_safe_fallback(self):
        dst=self.root/'invalid';r=self.report();r['not_json']=b'bytes'
        value,rc,out,err=self.capture(r,dst)
        self.assertEqual((rc,out),(20,''));self.assertEqual(json.loads(err),value)
        self.assertEqual(value['status'],'BLOCKED');self.assertEqual(value['reason'],'OUTPUT_ENCODING_INVALID')
        self.assertEqual(value['output_status'],'NOT_CREATED_BY_THIS_CALL')
        self.assertIsNone(value['evidence_report']);self.assertEqual(value['evidence_report_state'],'UNSERIALIZABLE')
        self.assertEqual(value['original_status'],'INCONCLUSIVE');self.assertEqual(r['not_json'],b'bytes');self.assertFalse(dst.exists())
    def test_cyclic_report_produces_safe_fallback(self):
        dst=self.root/'cyclic';r=self.report('FAIL');r['cycle']=r
        value,rc,out,err=self.capture(r,dst,10)
        self.assertEqual((rc,out),(10,''));self.assertEqual(json.loads(err),value)
        self.assertEqual(value['status'],'FAIL');self.assertEqual(value['evidence_report_state'],'UNSERIALIZABLE')
        self.assertEqual(value['original_status'],'FAIL');self.assertIs(r['cycle'],r);self.assertFalse(dst.exists())
    def test_deep_report_produces_safe_fallback(self):
        dst=self.root/'deep';r=self.report();nested=[];r['nested']=nested
        for _ in range(1500):
            child=[];nested.append(child);nested=child
        value,rc,out,err=self.capture(r,dst)
        self.assertEqual((rc,out),(20,''));self.assertEqual(json.loads(err),value)
        self.assertEqual(value['reason'],'OUTPUT_ENCODING_INVALID')
        # On this fixture compact serialization succeeds even when the
        # indented file serialization exceeds Python's recursion limit.
        self.assertIs(value['evidence_report'],r)
        self.assertNotIn('evidence_report_state',value)
        self.assertFalse(dst.exists())
    def test_parent_traversal_is_rejected(self):
        directory=self.root/'dir';directory.mkdir()
        dst=directory/'..'/'new';self.blocked(self.report(),dst,'OUTPUT_PATH_INVALID');self.assertFalse((self.root/'new').exists())

if __name__=='__main__':unittest.main(verbosity=2)

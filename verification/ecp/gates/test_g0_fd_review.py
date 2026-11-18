"""Synthetic FD-observer tests. They do not qualify G0 or any caller."""
import copy
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('g0_fd_review_candidate', Path(__file__).with_name('g0_fd_review.py'))
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


class FdObservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='g0-fd-private-'); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.opened = []
        self.source = 'a' * 40
        self.plan = {'schema_version':'forgeflow.ecp-g0-review-plan.v1','source_sha':self.source,
                     'suites':[{'suite_id':sid,'case_ids':['one','two']} for sid in m.SUITES]}
        self.logbytes = {(sid, kind): (sid + ':' + kind + ':synthetic').encode() for sid in m.SUITES for kind in m.KINDS}
        self.runs = []
        for sid in m.SUITES:
            den = {'total':2, 'PASS':2, 'FAIL':0, 'BLOCKED':0, 'NOT_RUN':0, 'INCONCLUSIVE':0, 'SKIPPED':0}
            self.runs.append({'suite_id':sid,'cases':[{'case_id':'one','status':'PASS'},{'case_id':'two','status':'PASS'}],
                              'denominator':den,'exit_code':0,'logs':{kind:{'path':f'{sid}/{kind}.log',
                              'sha256':sha(self.logbytes[(sid, kind)])} for kind in m.KINDS}})
        self.receipt = {'schema_version':'forgeflow.ecp-g0-review-input.v1','run_id':'synthetic',
                        'source_sha':self.source,'plan_sha256':sha(encoded(self.plan)),'suites':self.runs}
        self.counter = 0

    def opened_fd(self, data, writable=False):
        self.counter += 1; path=self.base/f'file-{self.counter}'
        path.write_bytes(data); fd=os.open(path, (os.O_RDWR if writable else os.O_RDONLY) | os.O_CLOEXEC)
        self.opened.append(fd); self.addCleanup(os.close, fd)
        return fd

    def args(self, *, plan=None, receipt=None, plan_raw=None, receipt_raw=None):
        plan = self.plan if plan is None else plan
        receipt = self.receipt if receipt is None else receipt
        pb = encoded(plan) if plan_raw is None else plan_raw
        rb = encoded(receipt) if receipt_raw is None else receipt_raw
        pfd = self.opened_fd(pb); rfd = self.opened_fd(rb)
        fds = {role:self.opened_fd(data) for role,data in self.logbytes.items()}
        return pfd, rfd, fds, sha(pb)

    def trace_observe(self, plan_fd, receipt_fd, stream_fds, pin):
        # Map every fcntl duplicate back to the original supplied role.
        original_fcntl=m.fcntl.fcntl; original_fstat=os.fstat; original_pread=os.pread
        origins={};events=[]
        def tracked_fcntl(fd, operation, *args):
            origin=origins.get(fd,fd)
            if operation==m.fcntl.F_DUPFD_CLOEXEC:events.append(('dup',origin))
            result=original_fcntl(fd,operation,*args)
            if operation==m.fcntl.F_DUPFD_CLOEXEC:origins[result]=origin
            return result
        def tracked_fstat(fd):
            events.append(('fstat',origins.get(fd,fd)));return original_fstat(fd)
        def tracked_pread(fd,count,offset):
            events.append(('pread',origins.get(fd,fd)));return original_pread(fd,count,offset)
        with patch.object(m.fcntl,'fcntl',side_effect=tracked_fcntl), \
             patch.object(m.os,'fstat',side_effect=tracked_fstat), \
             patch.object(m.os,'pread',side_effect=tracked_pread):
            result=m.observe(plan_fd,receipt_fd,stream_fds,pin)
        return result,events

    def test_pin_failure_never_dup_fstat_or_pread_receipt_or_stream_objects(self):
        for variant in ('missing','malformed','wrong','invalid_plan'):
            with self.subTest(variant=variant):
                raw=b'{"schema_version":"x","schema_version":"y"}' if variant=='invalid_plan' else None
                pfd,rfd,fds,pin=self.args(plan_raw=raw)
                selected={'missing':None,'malformed':'wrong','wrong':'0'*64,'invalid_plan':pin}[variant]
                result,events=self.trace_observe(pfd,rfd,fds,selected)
                forbidden={rfd,*fds.values()}
                self.assertFalse(any(origin in forbidden for op,origin in events if op in ('dup','fstat','pread')))
                self.assertIsNone(result['receipt_checks_passed'])
                if variant in ('missing','malformed'):self.assertEqual(events,[])
                else:self.assertTrue(any(origin==pfd for op,origin in events))

    def test_distinct_fds_same_object_show_external_role_separation_premise(self):
        # This deliberately violates the precondition: plan and stream fd are
        # different integers for the same file; reading the plan then touches
        # that object before the stream's identity can be observed.
        pfd,rfd,fds,pin=self.args();role=(m.SUITES[0],'stdout');alias=os.dup(pfd);self.addCleanup(os.close,alias);fds[role]=alias
        identity=os.fstat(pfd);same=[];raw_pread=os.pread;raw_stat=os.fstat
        def observed(fd,count,offset):
            st=raw_stat(fd)
            if (st.st_dev,st.st_ino)==(identity.st_dev,identity.st_ino):same.append((count,offset))
            return raw_pread(fd,count,offset)
        with patch.object(m.os,'pread',side_effect=observed):result=m.observe(pfd,rfd,fds,pin)
        self.assertTrue(same,'plan already touched the same object; broker must prevent this')
        self.assertEqual(same,[(identity.st_size,0),(1,identity.st_size)])
        self.assertIn('FD_ALIAS_OBSERVATION_UNKNOWN',result['issues']);self.assertIsNone(result['streams'][role[0]][role[1]]['sha256_match'])

    def test_real_fds_all_green_is_only_an_unverified_observation(self):
        args=self.args(); result=m.observe(*args)
        self.assertEqual((result['status'],result['qualification'],result['product_gate_effect']),('INCONCLUSIVE','NOT_RUN','NONE'))
        self.assertTrue(result['plan_pin_match']); self.assertTrue(result['plan_checks_passed']); self.assertTrue(result['receipt_checks_passed'])
        self.assertTrue(result['source_claims_text_equal']); self.assertIsNone(result['source_sha'])
        self.assertFalse(result['document_contradictions_exhaustive'])
        for key in ('source_authentication','principal_authentication','lease_authentication','path_binding','execution_authentication'):
            self.assertIsNone(result[key])
        self.assertEqual(len(result['suite_counts']),7); self.assertEqual(result['document_contradictions'],[])
        self.assertTrue(all(result['streams'][sid][kind]['sha256_match'] is True for sid in m.SUITES for kind in m.KINDS))
        for fd in self.opened: os.fstat(fd)

    def test_wrong_plan_pin_never_touches_receipt_or_stream(self):
        pfd,rfd,fds,_=self.args(); actual=m._acquire
        with patch.object(m,'_acquire',wraps=actual) as called:
            result=m.observe(pfd,rfd,fds,'0'*64)
        self.assertFalse(result['plan_pin_match']); self.assertEqual([c.args[0] for c in called.call_args_list],[pfd])
        self.assertIsNone(result['receipt_checks_passed']); self.assertTrue(all(result['streams'][sid][kind]['sha256_match'] is None for sid in m.SUITES for kind in m.KINDS))

    def test_malformed_plan_pin_touches_no_fd(self):
        args=self.args()
        with patch.object(m,'_acquire',side_effect=AssertionError('unexpected touch')):
            result=m.observe(args[0],args[1],args[2],'BAD')
        self.assertIn('PLAN_PIN_INVALID',result['issues'])

    def test_wrong_receipt_pin_never_touches_streams(self):
        args=self.args(); actual=m._acquire
        with patch.object(m,'_acquire',wraps=actual) as called:
            result=m.observe(*args,expected_receipt_sha256='0'*64)
        self.assertFalse(result['receipt_pin_match']); self.assertEqual([c.args[0] for c in called.call_args_list],[args[0],args[1]])

    def test_missing_stream_never_touches_omitted_fd(self):
        pfd,rfd,fds,pin=self.args(); role=(m.SUITES[0],'stdout'); omitted=fds.pop(role); actual=m._acquire
        with patch.object(m,'_acquire',wraps=actual) as called:
            result=m.observe(pfd,rfd,fds,pin)
        self.assertNotIn(omitted,[c.args[0] for c in called.call_args_list]); self.assertFalse(result['streams'][role[0]][role[1]]['provided'])
        self.assertIsNone(result['streams'][role[0]][role[1]]['sha256_match']); os.fstat(omitted)

    def test_missing_stream_has_zero_dup_fstat_and_pread_at_object_level(self):
        pfd,rfd,fds,pin=self.args();role=(m.SUITES[0],'stdout');omitted=fds.pop(role)
        result,events=self.trace_observe(pfd,rfd,fds,pin)
        self.assertFalse(any(origin==omitted for op,origin in events if op in ('dup','fstat','pread')))
        self.assertIsNone(result['streams'][role[0]][role[1]]['sha256_match'])
        self.assertFalse(result['streams'][role[0]][role[1]]['provided'])

    def test_plan_receipt_same_fd_number_rejects_before_any_fd_syscall(self):
        pfd,_,fds,pin=self.args()
        with patch.object(m.fcntl,'fcntl',side_effect=AssertionError('fcntl touched')), \
             patch.object(m.os,'fstat',side_effect=AssertionError('fstat touched')), \
             patch.object(m.os,'pread',side_effect=AssertionError('pread touched')):
            result=m.observe(pfd,pfd,fds,pin)
        self.assertIn('FD_NUMBER_REUSED',result['issues']);self.assertIsNone(result['plan_pin_match'])

    def test_receipt_labels_never_open_paths_or_claim_binding(self):
        self.runs[0]['logs']['stdout']['path']='unapproved-but-syntactic/marker'
        args=self.args()
        with patch.object(os,'open',side_effect=AssertionError('receipt path opened')):
            result=m.observe(*args)
        self.assertTrue(result['streams'][m.SUITES[0]]['stdout']['sha256_match']); self.assertIsNone(result['path_binding'])

    def test_path_traversal_claim_rejected_before_stream_io(self):
        self.runs[0]['logs']['stdout']['path']='../synthetic-marker'
        pfd,rfd,fds,pin=self.args(); actual=m._acquire
        with patch.object(m,'_acquire',wraps=actual) as called:result=m.observe(pfd,rfd,fds,pin)
        self.assertFalse(result['receipt_checks_passed']); self.assertEqual([c.args[0] for c in called.call_args_list],[pfd,rfd])

    def test_untrusted_fail_claim_is_preserved_as_claim_not_product_verdict(self):
        run=self.runs[0];run['cases'][0]['status']='FAIL';run['denominator']['PASS']=1;run['denominator']['FAIL']=1
        result=m.observe(*self.args())
        self.assertEqual(result['status'],'INCONCLUSIVE');self.assertEqual(result['suite_counts'][m.SUITES[0]]['denominator']['FAIL'],1)
        self.assertIsNone(result['execution_authentication']); self.assertEqual(result['document_contradictions'],[])

    def test_source_claim_mismatch_is_not_source_observation(self):
        self.receipt['source_sha']='b'*40
        result=m.observe(*self.args());self.assertFalse(result['source_claims_text_equal'])
        self.assertIsNone(result['source_authentication']);self.assertIsNone(result['source_sha'])
        self.assertIn('PLAN_RECEIPT_SOURCE_CLAIM_MISMATCH',result['document_contradictions'])

    def test_bad_denominators_and_all_pass_nonzero_do_not_touch_streams(self):
        for mutation in ('bool','negative','total','exit','missing'):
            with self.subTest(mutation=mutation):
                receipt=copy.deepcopy(self.receipt);run=receipt['suites'][0]
                if mutation=='bool':run['denominator']['PASS']=True
                elif mutation=='negative':run['denominator']['PASS']=-1
                elif mutation=='total':run['denominator']['total']=1
                elif mutation=='exit':run['exit_code']=1
                else:del run['denominator']['SKIPPED']
                pfd,rfd,fds,pin=self.args(receipt=receipt);actual=m._acquire
                with patch.object(m,'_acquire',wraps=actual) as called:result=m.observe(pfd,rfd,fds,pin)
                self.assertFalse(result['receipt_checks_passed']);self.assertEqual([c.args[0] for c in called.call_args_list],[pfd,rfd])
                expected={'bool':'DENOMINATOR_VALUE_INVALID','negative':'DENOMINATOR_VALUE_INVALID','total':'DENOMINATOR_MISMATCH','exit':'ALL_PASS_NONZERO_EXIT','missing':'OBJECT_FIELDS_INVALID'}[mutation]
                self.assertIn('RECEIPT_'+expected,result['document_contradictions'])

    def test_missing_duplicate_suite_and_case_are_not_accepted(self):
        for mutation in ('missing_suite','duplicate_suite','duplicate_case','missing_case'):
            with self.subTest(mutation=mutation):
                receipt=copy.deepcopy(self.receipt)
                if mutation=='missing_suite':receipt['suites'].pop()
                elif mutation=='duplicate_suite':receipt['suites'][-1]=copy.deepcopy(receipt['suites'][0])
                elif mutation=='duplicate_case':receipt['suites'][0]['cases'][1]['case_id']='one'
                else:receipt['suites'][0]['cases'].pop()
                result=m.observe(*self.args(receipt=receipt));self.assertFalse(result['receipt_checks_passed'])

    def test_duplicate_json_key_and_bad_plan_shape_no_receipt_access(self):
        raw=b'{"schema_version":"a","schema_version":"b"}';pfd,rfd,fds,pin=self.args(plan_raw=raw)
        with patch.object(m,'_acquire',wraps=m._acquire) as called:result=m.observe(pfd,rfd,fds,pin)
        self.assertFalse(result['plan_checks_passed']);self.assertEqual([c.args[0] for c in called.call_args_list],[pfd])

    def test_case_budget_exceeded_stays_unknown(self):
        args=self.args()
        with patch.object(m,'MAX_CASES',1):result=m.observe(*args)
        self.assertIsNone(result['plan_checks_passed']);self.assertIn('PLAN_BUDGET_UNKNOWN',result['issues'])

    def test_receipt_plan_pin_mismatch_prevents_stream_read(self):
        self.receipt['plan_sha256']='b'*64;pfd,rfd,fds,pin=self.args();actual=m._acquire
        with patch.object(m,'_acquire',wraps=actual) as called:result=m.observe(pfd,rfd,fds,pin)
        self.assertFalse(result['receipt_checks_passed']);self.assertEqual([c.args[0] for c in called.call_args_list],[pfd,rfd])

    def test_known_claim_contradiction_survives_missing_stream_observations(self):
        self.receipt['source_sha']='b'*40
        pfd,rfd,_,pin=self.args();result=m.observe(pfd,rfd,{},pin)
        self.assertIn('PLAN_RECEIPT_SOURCE_CLAIM_MISMATCH',result['document_contradictions'])
        self.assertFalse(result['streams'][m.SUITES[0]]['stdout']['provided'])
        self.assertIsNone(result['streams'][m.SUITES[0]]['stdout']['sha256_match'])
        self.assertEqual(result['status'],'INCONCLUSIVE')

    def test_top_level_source_conflict_survives_later_denominator_conflict(self):
        self.receipt['source_sha']='b'*40;self.runs[0]['denominator']['total']=1
        result=m.observe(*self.args())
        self.assertFalse(result['source_claims_text_equal']);self.assertFalse(result['receipt_checks_passed'])
        self.assertIn('PLAN_RECEIPT_SOURCE_CLAIM_MISMATCH',result['document_contradictions'])
        self.assertIn('RECEIPT_DENOMINATOR_MISMATCH',result['document_contradictions'])
        self.assertFalse(result['document_contradictions_exhaustive']);self.assertEqual(result['status'],'INCONCLUSIVE')

    def test_source_claim_requires_v1_git_oid_syntax_but_never_authenticates(self):
        for claim in ('','a'*39,'A'*40,'z'*40):
            with self.subTest(plan_claim=claim):
                plan=copy.deepcopy(self.plan);plan['source_sha']=claim
                result=m.observe(*self.args(plan=plan));self.assertFalse(result['plan_checks_passed'])
                self.assertIn('PLAN_SOURCE_ID_INVALID',result['document_contradictions']);self.assertIsNone(result['source_authentication'])
        for claim in ('','a'*39,'A'*40,'z'*40):
            with self.subTest(receipt_claim=claim):
                receipt=copy.deepcopy(self.receipt);receipt['source_sha']=claim
                result=m.observe(*self.args(receipt=receipt));self.assertFalse(result['receipt_checks_passed'])
                self.assertIn('RECEIPT_SOURCE_ID_INVALID',result['document_contradictions']);self.assertIsNone(result['source_authentication'])
        receipt=copy.deepcopy(self.receipt);plan=copy.deepcopy(self.plan)
        plan['source_sha']='a'*64;receipt['source_sha']='a'*64;receipt['plan_sha256']=sha(encoded(plan))
        result=m.observe(*self.args(plan=plan,receipt=receipt));self.assertTrue(result['source_claims_text_equal']);self.assertIsNone(result['source_sha'])

    def test_missing_receipt_fd_preserves_unknown_and_no_stream_access(self):
        pfd,_,fds,pin=self.args();actual=m._acquire
        with patch.object(m,'_acquire',wraps=actual) as called:result=m.observe(pfd,-1,fds,pin)
        self.assertIn('RECEIPT_OBSERVATION_UNKNOWN',result['issues']);self.assertEqual([c.args[0] for c in called.call_args_list],[pfd,-1])

    def test_duplicate_stream_fd_numbers_reject_before_any_fd_syscall(self):
        pfd,rfd,fds,pin=self.args();one=(m.SUITES[0],'stdout');two=(m.SUITES[0],'stderr');fds[two]=fds[one]
        with patch.object(m.fcntl,'fcntl',side_effect=AssertionError('fcntl touched')), \
             patch.object(m.os,'fstat',side_effect=AssertionError('fstat touched')), \
             patch.object(m.os,'pread',side_effect=AssertionError('pread touched')):
            result=m.observe(pfd,rfd,fds,pin)
        self.assertIsNone(result['plan_pin_match']);self.assertIn('FD_NUMBER_REUSED',result['issues'])
        self.assertIsNone(result['streams'][one[0]][one[1]]['sha256_match']);self.assertIsNone(result['path_binding'])

    def test_real_hardlinked_stream_fds_are_not_read(self):
        pfd,rfd,fds,pin=self.args();one=(m.SUITES[0],'stdout');two=(m.SUITES[0],'stderr')
        st=os.fstat(fds[one]); match=next(p for p in self.base.iterdir() if p.stat().st_ino==st.st_ino)
        alias=self.base/'hardlink';os.link(match,alias);afd=os.open(alias,os.O_RDONLY|os.O_CLOEXEC);self.addCleanup(os.close,afd);fds[two]=afd
        original_pread=os.pread; original_fstat=os.fstat; identity=(st.st_dev,st.st_ino)
        def forbid_aliased(fd,count,offset):
            now=original_fstat(fd)
            if (now.st_dev,now.st_ino)==identity:raise AssertionError('aliased stream read')
            return original_pread(fd,count,offset)
        with patch.object(m.os,'pread',side_effect=forbid_aliased):result=m.observe(pfd,rfd,fds,pin)
        self.assertIn('FD_ALIAS_OBSERVATION_UNKNOWN',result['issues']);self.assertIsNone(result['streams'][one[0]][one[1]]['sha256_match'])
        self.assertIsNone(result['streams'][two[0]][two[1]]['sha256_match'])

    def test_plan_fd_number_reused_as_stream_rejects_before_any_fd_syscall(self):
        pfd,rfd,fds,pin=self.args();role=(m.SUITES[0],'stdout');fds[role]=pfd
        with patch.object(m.fcntl,'fcntl',side_effect=AssertionError('fcntl touched')), \
             patch.object(m.os,'fstat',side_effect=AssertionError('fstat touched')), \
             patch.object(m.os,'pread',side_effect=AssertionError('pread touched')):
            result=m.observe(pfd,rfd,fds,pin)
        self.assertIn('FD_NUMBER_REUSED',result['issues']);self.assertIsNone(result['plan_pin_match'])

    def test_mismatched_log_hash_is_observation_not_verdict(self):
        role=(m.SUITES[0],'stdout');self.runs[0]['logs']['stdout']['sha256']='b'*64
        result=m.observe(*self.args());self.assertFalse(result['streams'][role[0]][role[1]]['sha256_match'])
        self.assertEqual(result['status'],'INCONCLUSIVE');self.assertIsNone(result['execution_authentication'])
        self.assertIn('STREAM_FD_DIGEST_MISMATCH',result['issues']);self.assertEqual(result['document_contradictions'],[])

    def test_writable_stream_fd_is_not_read(self):
        pfd,rfd,fds,pin=self.args();role=(m.SUITES[0],'stdout');fds[role]=self.opened_fd(self.logbytes[role],writable=True)
        result=m.observe(pfd,rfd,fds,pin);self.assertIsNone(result['streams'][role[0]][role[1]]['sha256_match'])
        self.assertIn('STREAM_OBSERVATION_UNKNOWN',result['issues']);os.fstat(fds[role])

    def test_short_read_stays_unknown(self):
        pfd,rfd,fds,pin=self.args();role=(m.SUITES[0],'stdout');target=os.fstat(fds[role]);orig=m.os.pread
        def short(fd,count,offset):
            st=os.fstat(fd)
            return b'' if (st.st_dev,st.st_ino)==(target.st_dev,target.st_ino) else orig(fd,count,offset)
        with patch.object(m.os,'pread',side_effect=short):result=m.observe(pfd,rfd,fds,pin)
        self.assertIsNone(result['streams'][role[0]][role[1]]['sha256_match']);self.assertIn('STREAM_OBSERVATION_UNKNOWN',result['issues'])

    def test_total_budget_charged_and_excess_streams_remain_unknown(self):
        args=self.args();first=len(self.logbytes[(m.SUITES[0],'stdout')]);
        with patch.object(m,'MAX_TOTAL_LOG',first+1):result=m.observe(*args)
        self.assertTrue(result['streams'][m.SUITES[0]]['stdout']['sha256_match'])
        self.assertIsNone(result['streams'][m.SUITES[0]]['stderr']['sha256_match']);self.assertIn('STREAM_BUDGET_UNKNOWN',result['issues'])

    def test_size_zero_or_truncated_fstat_with_extra_bytes_stays_unknown(self):
        for reported in (0,2):
            with self.subTest(reported=reported):
                pfd,rfd,fds,pin=self.args();role=(m.SUITES[0],'stdout');target=os.fstat(fds[role]);real_fstat=os.fstat;real_pread=os.pread;probes=[]
                def sized(fd):
                    st=real_fstat(fd)
                    if (st.st_dev,st.st_ino)!=(target.st_dev,target.st_ino):return st
                    return types.SimpleNamespace(st_dev=st.st_dev,st_ino=st.st_ino,st_mode=st.st_mode,st_size=reported,st_mtime_ns=st.st_mtime_ns,st_ctime_ns=st.st_ctime_ns)
                def tracked(fd,count,offset):
                    st=real_fstat(fd)
                    if (st.st_dev,st.st_ino)==(target.st_dev,target.st_ino):probes.append((count,offset))
                    return real_pread(fd,count,offset)
                with patch.object(m.os,'fstat',side_effect=sized),patch.object(m.os,'pread',side_effect=tracked):
                    result=m.observe(pfd,rfd,fds,pin)
                self.assertIn((1,reported),probes);self.assertIsNone(result['streams'][role[0]][role[1]]['sha256_match'])
                self.assertIn('STREAM_OBSERVATION_UNKNOWN',result['issues'])

    def test_eof_probe_error_stays_unknown(self):
        pfd,rfd,fds,pin=self.args();role=(m.SUITES[0],'stdout');target=os.fstat(fds[role]);raw_stat=os.fstat;raw_pread=os.pread;probes=[]
        def failing(fd,count,offset):
            st=raw_stat(fd)
            if (st.st_dev,st.st_ino)==(target.st_dev,target.st_ino) and offset==target.st_size:
                probes.append((count,offset));raise OSError('synthetic EOF probe unavailable')
            return raw_pread(fd,count,offset)
        with patch.object(m.os,'pread',side_effect=failing):result=m.observe(pfd,rfd,fds,pin)
        self.assertEqual(probes,[(1,target.st_size)]);self.assertIsNone(result['streams'][role[0]][role[1]]['sha256_match'])
        self.assertIn('STREAM_OBSERVATION_UNKNOWN',result['issues'])

    def test_empty_regular_stream_requires_one_byte_eof_probe(self):
        role=(m.SUITES[0],'stdout');self.logbytes[role]=b'';self.runs[0]['logs']['stdout']['sha256']=sha(b'')
        pfd,rfd,fds,pin=self.args();target=os.fstat(fds[role]);raw_stat=os.fstat;raw_pread=os.pread;probes=[]
        def tracking(fd,count,offset):
            st=raw_stat(fd)
            if (st.st_dev,st.st_ino)==(target.st_dev,target.st_ino):probes.append((count,offset))
            return raw_pread(fd,count,offset)
        with patch.object(m.os,'pread',side_effect=tracking):result=m.observe(pfd,rfd,fds,pin)
        self.assertEqual(probes,[(1,0)]);self.assertTrue(result['streams'][role[0]][role[1]]['sha256_match'])

    def test_close_failure_before_kernel_close_is_not_retried(self):
        args=self.args();real=os.close;calls=[];left=[]
        def close_before(fd):
            calls.append(fd)
            if len(calls)==1:left.append(fd);raise OSError('synthetic error before close')
            real(fd)
        try:
            with patch.object(m.os,'close',side_effect=close_before):result=m.observe(*args)
            self.assertTrue(result['close_unknown']);self.assertEqual(len(calls),16)
            self.assertEqual(calls.count(left[0]),1);os.fstat(left[0])
            for fd in self.opened:os.fstat(fd)
        finally:
            if left:real(left[0])

    def test_close_uncertainty_is_reported_and_originals_remain_open(self):
        args=self.args();real=os.close;calls=[]
        def close_then_uncertain(fd):
            calls.append(fd);real(fd)
            if len(calls)==1:raise OSError('injected after close')
        with patch.object(m.os,'close',side_effect=close_then_uncertain):result=m.observe(*args)
        self.assertTrue(result['close_unknown']);self.assertEqual(len(calls),16)
        for fd in self.opened:os.fstat(fd)

    def test_cli_emits_no_success_status_and_zero_raw_logs(self):
        pfd,rfd,fds,pin=self.args();args=['--plan-fd',str(pfd),'--receipt-fd',str(rfd),'--plan-sha256',pin]
        for (sid,kind),fd in fds.items():args.extend(['--stream-fd',f'{sid}:{kind}:{fd}'])
        with patch.object(m.sys,'stdout',new_callable=io.StringIO) as output:code=m.main(args);text=output.getvalue()
        report=json.loads(text);self.assertEqual(code,20);self.assertEqual(report['status'],'INCONCLUSIVE')
        self.assertEqual(report['receipt_run_id_claim'],'synthetic')
        for raw in self.logbytes.values():self.assertNotIn(raw.decode(),text)

    def test_invalid_role_mapping_touches_no_fd(self):
        args=self.args()
        with patch.object(m,'_acquire',side_effect=AssertionError('unexpected touch')):
            result=m.observe(args[0],args[1],{('not-suite','stdout'):args[0]},args[3])
        self.assertIn('ROLE_MAP_INVALID',result['issues'])

    def test_distinct_claims_and_documents_produce_distinct_bound_reports(self):
        plan_b=copy.deepcopy(self.plan);plan_b['source_sha']='b'*40
        receipt_b=copy.deepcopy(self.receipt);receipt_b['source_sha']='b'*40;receipt_b['run_id']='synthetic_b';receipt_b['plan_sha256']=sha(encoded(plan_b))
        a=m.observe(*self.args());b=m.observe(*self.args(plan=plan_b,receipt=receipt_b))
        self.assertNotEqual(a['caller_expected_plan_sha256'],b['caller_expected_plan_sha256'])
        self.assertNotEqual(a['observed_plan_fd_sha256'],b['observed_plan_fd_sha256'])
        self.assertNotEqual(a['observed_receipt_fd_sha256'],b['observed_receipt_fd_sha256'])
        self.assertNotEqual(a['receipt_run_id_claim'],b['receipt_run_id_claim'])
        self.assertNotEqual(a['plan_source_sha_claim'],b['plan_source_sha_claim'])
        self.assertNotEqual(a['receipt_source_sha_claim'],b['receipt_source_sha_claim'])
        self.assertNotEqual(encoded(a),encoded(b))
        for result in (a,b):
            self.assertEqual((result['status'],result['qualification'],result['product_gate_effect']),('INCONCLUSIVE','NOT_RUN','NONE'))
            self.assertIsNone(result['source_sha']);self.assertIsNone(result['source_authentication']);self.assertIsNone(result['path_binding'])
            self.assertTrue(all(result['streams'][sid][kind]['sha256_match'] is True for sid in m.SUITES for kind in m.KINDS))
        legacy_keys=('caller_expected_plan_sha256','caller_expected_receipt_sha256','observed_plan_fd_sha256','observed_receipt_fd_sha256','plan_source_sha_claim','receipt_source_sha_claim','receipt_run_id_claim')
        for result in (a,b):
            for key in legacy_keys:result.pop(key)
        self.assertEqual(a,b)

    def test_valid_pins_and_digest_claims_are_labeled_not_authenticated(self):
        args=self.args();receipt_pin=sha(encoded(self.receipt));result=m.observe(*args,expected_receipt_sha256=receipt_pin)
        self.assertEqual(result['caller_expected_plan_sha256'],args[3]);self.assertEqual(result['observed_plan_fd_sha256'],args[3])
        self.assertEqual(result['caller_expected_receipt_sha256'],receipt_pin);self.assertEqual(result['observed_receipt_fd_sha256'],receipt_pin)
        self.assertEqual(result['plan_source_sha_claim'],self.source);self.assertEqual(result['receipt_source_sha_claim'],self.source);self.assertEqual(result['receipt_run_id_claim'],'synthetic')
        for sid,kind in self.logbytes:
            stream=result['streams'][sid][kind];self.assertEqual(stream['claimed_sha256'],sha(self.logbytes[(sid,kind)]));self.assertEqual(stream['observed_fd_sha256'],sha(self.logbytes[(sid,kind)]))
        self.assertIsNone(result['principal_authentication']);self.assertIsNone(result['execution_authentication']);self.assertIsNone(result['lease_authentication'])

    def test_wrong_plan_pin_preserves_observed_plan_only(self):
        pfd,rfd,fds,actual=self.args();original=m._acquire
        with patch.object(m,'_acquire',wraps=original) as called:result=m.observe(pfd,rfd,fds,'0'*64)
        self.assertEqual(result['caller_expected_plan_sha256'],'0'*64);self.assertEqual(result['observed_plan_fd_sha256'],actual)
        self.assertFalse(result['plan_pin_match']);self.assertEqual([c.args[0] for c in called.call_args_list],[pfd])
        self.assertIsNone(result['observed_receipt_fd_sha256']);self.assertIsNone(result['receipt_run_id_claim']);self.assertIsNone(result['plan_source_sha_claim'])
        self.assertTrue(all(result['streams'][sid][kind]['claimed_sha256'] is None and result['streams'][sid][kind]['observed_fd_sha256'] is None for sid in m.SUITES for kind in m.KINDS))

    def test_wrong_receipt_pin_records_observed_sha_but_does_not_parse_or_read_streams(self):
        args=self.args();original=m._acquire
        with patch.object(m,'_acquire',wraps=original) as called:result=m.observe(*args,expected_receipt_sha256='0'*64)
        self.assertEqual(result['caller_expected_receipt_sha256'],'0'*64);self.assertEqual(result['observed_receipt_fd_sha256'],sha(encoded(self.receipt)))
        self.assertFalse(result['receipt_pin_match']);self.assertIsNone(result['receipt_run_id_claim']);self.assertIsNone(result['receipt_source_sha_claim'])
        self.assertEqual([c.args[0] for c in called.call_args_list],[args[0],args[1]])
        self.assertTrue(all(result['streams'][sid][kind]['claimed_sha256'] is None and result['streams'][sid][kind]['observed_fd_sha256'] is None for sid in m.SUITES for kind in m.KINDS))

    def test_short_plan_never_fabricates_observed_identity(self):
        args=self.args();target=os.fstat(args[0]);original=m.os.pread;fstat=os.fstat
        def short(fd,count,offset):
            st=fstat(fd)
            return b'' if (st.st_dev,st.st_ino)==(target.st_dev,target.st_ino) else original(fd,count,offset)
        with patch.object(m.os,'pread',side_effect=short):result=m.observe(*args)
        self.assertEqual(result['caller_expected_plan_sha256'],args[3]);self.assertIsNone(result['observed_plan_fd_sha256']);self.assertIsNone(result['observed_receipt_fd_sha256'])
        self.assertIn('PLAN_OBSERVATION_UNKNOWN',result['issues'])

    def test_short_receipt_never_fabricates_observed_identity_or_claims(self):
        args=self.args();target=os.fstat(args[1]);original=m.os.pread;fstat=os.fstat
        def short(fd,count,offset):
            st=fstat(fd)
            return b'' if (st.st_dev,st.st_ino)==(target.st_dev,target.st_ino) else original(fd,count,offset)
        with patch.object(m.os,'pread',side_effect=short):result=m.observe(*args)
        self.assertEqual(result['observed_plan_fd_sha256'],args[3]);self.assertIsNone(result['observed_receipt_fd_sha256']);self.assertIsNone(result['receipt_run_id_claim'])
        self.assertIn('RECEIPT_OBSERVATION_UNKNOWN',result['issues'])

    def test_short_stream_has_claim_but_no_observed_digest(self):
        args=self.args();role=(m.SUITES[0],'stdout');target=os.fstat(args[2][role]);original=m.os.pread;fstat=os.fstat
        def short(fd,count,offset):
            st=fstat(fd)
            return b'' if (st.st_dev,st.st_ino)==(target.st_dev,target.st_ino) else original(fd,count,offset)
        with patch.object(m.os,'pread',side_effect=short):result=m.observe(*args)
        stream=result['streams'][role[0]][role[1]];self.assertEqual(stream['claimed_sha256'],sha(self.logbytes[role]));self.assertIsNone(stream['observed_fd_sha256']);self.assertIsNone(stream['sha256_match'])

    def test_digest_mismatch_reports_two_untrusted_labels_not_verdict(self):
        role=(m.SUITES[0],'stdout');self.runs[0]['logs']['stdout']['sha256']='0'*64
        result=m.observe(*self.args());stream=result['streams'][role[0]][role[1]]
        self.assertEqual(stream['claimed_sha256'],'0'*64);self.assertEqual(stream['observed_fd_sha256'],sha(self.logbytes[role]));self.assertFalse(stream['sha256_match'])
        self.assertEqual(result['status'],'INCONCLUSIVE');self.assertIsNone(result['execution_authentication'])

    def test_invalid_receipt_claims_are_not_echoed_but_bytes_remain_bound(self):
        self.receipt['source_sha']='not_git';self.receipt['run_id']='invalid id with spaces'
        result=m.observe(*self.args());self.assertEqual(result['observed_receipt_fd_sha256'],sha(encoded(self.receipt)))
        self.assertIsNone(result['receipt_source_sha_claim']);self.assertIsNone(result['receipt_run_id_claim']);self.assertFalse(result['receipt_checks_passed'])
        self.assertNotIn('invalid id with spaces',json.dumps(result))

    def test_close_uncertainty_keeps_labels_and_never_certifies_source(self):
        args=self.args();real=os.close;calls=[]
        def close_after(fd):
            calls.append(fd);real(fd)
            if len(calls)==1:raise OSError('synthetic after-close uncertainty')
        with patch.object(m.os,'close',side_effect=close_after):result=m.observe(*args)
        self.assertTrue(result['close_unknown']);self.assertEqual(result['observed_plan_fd_sha256'],args[3])
        self.assertEqual(result['observed_receipt_fd_sha256'],sha(encoded(self.receipt)));self.assertEqual(result['receipt_run_id_claim'],'synthetic')
        self.assertIsNone(result['source_authentication']);self.assertEqual(result['qualification'],'NOT_RUN')

    def test_invalid_pin_text_is_not_echoed_into_report(self):
        args=self.args();bad='sensitive_not_a_sha'
        result=m.observe(args[0],args[1],args[2],bad);self.assertIsNone(result['caller_expected_plan_sha256'])
        self.assertIsNone(result['observed_plan_fd_sha256']);self.assertNotIn(bad,json.dumps(result))


if __name__=='__main__': unittest.main()

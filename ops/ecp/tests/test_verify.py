from __future__ import annotations

import json
import os
import contextlib
import io
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
ENTRY = ROOT / "ops" / "ecp" / "verify"
sys.path.insert(0, str(ROOT / "ops" / "ecp"))
import verify


class VerifyCliTests(unittest.TestCase):
    def test_p002_descriptor_close_failure_is_reported_before_final_output(self) -> None:
        """Owned evidence/runner FD failures must not destroy the final report."""
        for failure in ('evidence_directory', 'runner_sealed', 'evidence_directory_consumed', 'runner_sealed_consumed'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix='p002-close-fault-') as directory:
                base = Path(directory); source = base/'source'; runner = source/'ops/ecp/test_database.sh'
                runner.parent.mkdir(parents=True)
                runner.write_text('#!/usr/bin/python3\nimport os,sys\n'
                    'b=b"{\\"status\\":\\"BLOCKED\\",\\"connections_attempted\\":0}\\n";'
                    'os.write(int(sys.argv[sys.argv.index("--output-fd")+1]),b);os.write(1,b);sys.exit(20)\n')
                runner.chmod(0o755)
                args = type('Args', (), {'run_store_test':False, 'profile':'isolated', 'output':None,
                                         'evidence_root':str(base/'evidence')})()
                expected = b'{"status":"BLOCKED","connections_attempted":0}\n'
                actual_open, actual_close, actual_memfd = os.open, os.close, os.memfd_create
                target = {}; attempted = []; sentinel = []; output = io.StringIO()
                failed_name = failure.removesuffix('_consumed')
                def track_open(path, flags, *pos, **kw):
                    value = actual_open(path, flags, *pos, **kw)
                    if path == 'evidence' and kw.get('dir_fd') is not None and 'evidence_directory' not in target:
                        target['evidence_directory'] = value
                    return value
                def track_memfd(name, flags=0):
                    value = actual_memfd(name, flags)
                    if name == 'forgeflow-p002-runner': target['runner_sealed'] = value
                    return value
                def close_fault(value):
                    if value == target.get(failed_name):
                        attempted.append(value)
                        if failure.endswith('_consumed') and len(attempted) == 1:
                            # close can succeed before an exception is reported;
                            # deliberately reuse the number to detect unsafe retries.
                            actual_close(value)
                            other = actual_open('/dev/null', os.O_RDONLY)
                            if other != value:
                                os.dup2(other, value); actual_close(other)
                            sentinel.append(value)
                        raise OSError('injected close failure, descriptor state unknown')
                    return actual_close(value)
                try:
                    with patch.dict(os.environ, {}, clear=True), patch.object(verify.os, 'open', side_effect=track_open), \
                         patch.object(verify.os, 'memfd_create', side_effect=track_memfd), \
                         patch.object(verify.os, 'close', side_effect=close_fault), contextlib.redirect_stdout(output):
                        value, code = verify.run_database_suite(args, source, 'a'*40,
                                                                verify.base_report('suite', source, 'a'*40))
                    self.assertEqual(len(attempted), 1, 'uncertain descriptor must not be closed twice')
                    self.assertEqual((value['status'], code), ('BLOCKED', 20))
                    self.assertIn('Runner reported the database identity guard blocked', value['reason'])
                    self.assertEqual(json.loads(output.getvalue()), value)
                    self.assertEqual(value['qualification'], 'NOT_RUN')
                    states=value['checks'][0]['details']['fd_close_states']
                    self.assertEqual(states[failed_name], 'UNKNOWN')
                    for other in (('receipt_memfd','runner_file','runner_directory','evidence_directory','evidence_parent')
                                  if failed_name=='runner_sealed' else ('evidence_parent',)):
                        self.assertEqual(states[other], 'CLOSED', (failed_name,other,states))
                    if sentinel: os.fstat(sentinel[0])
                    self.assertEqual((base/'evidence/stdout.log').read_bytes(), expected)
                    self.assertEqual((base/'evidence/database-probe.json').read_bytes(), expected)
                    self.assertEqual(json.loads((base/'evidence/result.json').read_text())['result_authority'], 'PROVISIONAL_ONLY')
                finally:
                    # The injected close deliberately leaves our own FD open; never retry in product code.
                    if attempted:
                        try: actual_close(attempted[0])
                        except OSError: pass

    def test_p002_preflight_close_failure_emits_one_conservative_report(self) -> None:
        for consumed in (False, True):
            with self.subTest(consumed=consumed), tempfile.TemporaryDirectory(prefix='p002-preflight-close-') as directory:
                base=Path(directory); source=base/'source'; source.mkdir()
                args=type('Args', (), {'run_store_test':False,'profile':'isolated','output':None,
                                       'evidence_root':str(base/'evidence')})()
                actual_open, actual_close, actual_mkdir = os.open, os.close, os.mkdir
                target=[]; attempted=[]; sentinel=[]; output=io.StringIO()
                def track_open(path, flags, *pos, **kw):
                    value=actual_open(path,flags,*pos,**kw)
                    if path==base.name and kw.get('dir_fd') is not None and not target: target.append(value)
                    return value
                def mkdir_fault(path, *pos, **kw):
                    if path=='evidence' and kw.get('dir_fd') is not None: raise OSError('injected preflight mkdir failure')
                    return actual_mkdir(path,*pos,**kw)
                def close_fault(value):
                    if target and value==target[0]:
                        attempted.append(value)
                        if consumed and len(attempted)==1:
                            actual_close(value); other=actual_open('/dev/null',os.O_RDONLY)
                            if other!=value: os.dup2(other,value);actual_close(other)
                            sentinel.append(value)
                        raise OSError('injected preflight cleanup failure')
                    return actual_close(value)
                try:
                    with patch.dict(os.environ,{},clear=True),patch.object(verify.os,'open',side_effect=track_open), \
                         patch.object(verify.os,'mkdir',side_effect=mkdir_fault), \
                         patch.object(verify.os,'close',side_effect=close_fault), \
                         patch.object(verify.subprocess,'Popen') as spawn, contextlib.redirect_stdout(output):
                        value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
                    spawn.assert_not_called()
                    self.assertEqual(len(attempted),1)
                    self.assertEqual((value['status'],code),('BLOCKED',20))
                    self.assertIn('evidence path is unsafe or unavailable',value['reason'])
                    self.assertEqual(json.loads(output.getvalue()),value)
                    self.assertEqual(value['checks'][0]['details']['fd_close_states']['evidence_parent'],'UNKNOWN')
                    self.assertEqual(value['qualification'],'NOT_RUN')
                    if sentinel: os.fstat(sentinel[0])
                finally:
                    if attempted:
                        try: actual_close(attempted[0])
                        except OSError: pass

    def test_p002_unverified_receipt_never_claims_logs_ready_for_acceptance(self) -> None:
        with tempfile.TemporaryDirectory(prefix='p002-receipt-limit-') as directory:
            base=Path(directory);source=base/'source';runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
            runner.write_text('#!/usr/bin/python3\nimport os,sys\nos.write(int(sys.argv[sys.argv.index("--output-fd")+1]),b"x"*65538)\nos.write(1,b"captured\\n")\n')
            runner.chmod(0o755)
            args=type('Args', (), {'run_store_test':False,'profile':'isolated','output':None,
                                   'evidence_root':str(base/'evidence')})()
            with patch.dict(os.environ,{},clear=True),contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            self.assertEqual((value['status'],code),('FAIL',10))
            details=value['checks'][0]['details']
            self.assertEqual(details['receipt_capture_state'],'UNKNOWN')
            self.assertFalse(details['raw_logs_complete_for_acceptance'])
            self.assertEqual((base/'evidence/stdout.log').read_bytes(),b'captured\n')

    def test_p002_close_unknown_never_hides_existing_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix='p002-fail-close-') as directory:
            base=Path(directory);source=base/'source';runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
            runner.write_text('#!/usr/bin/python3\nimport os,sys\nb=b"{\\"status\\":\\"FAIL\\",\\"connections_attempted\\":0}\\n";'
                              'os.write(int(sys.argv[sys.argv.index("--output-fd")+1]),b);os.write(1,b);sys.exit(10)\n')
            runner.chmod(0o755)
            args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':None,
                                 'evidence_root':str(base/'evidence')})()
            actual_open,actual_close=os.open,os.close; target=[];attempted=[]; output=io.StringIO()
            def track_open(path,flags,*pos,**kw):
                value=actual_open(path,flags,*pos,**kw)
                if path=='evidence' and kw.get('dir_fd') is not None and not target:target.append(value)
                return value
            def close_fault(value):
                if target and value==target[0]:attempted.append(value);raise OSError('injected evidence close failure')
                return actual_close(value)
            try:
                with patch.dict(os.environ,{},clear=True),patch.object(verify.os,'open',side_effect=track_open), \
                     patch.object(verify.os,'close',side_effect=close_fault),contextlib.redirect_stdout(output):
                    value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
                self.assertEqual(len(attempted),1)
                self.assertEqual((value['status'],code),('FAIL',10))
                self.assertIn('Runner reported the database identity guard failed',value['reason'])
                self.assertEqual(json.loads(output.getvalue()),value)
                self.assertEqual(value['checks'][0]['details']['fd_close_states']['evidence_directory'],'UNKNOWN')
                self.assertEqual(value['evidence_integrity_at_return'],'UNKNOWN')
                self.assertTrue((base/'evidence/stdout.log').read_bytes().startswith(b'{"status":"FAIL"'))
            finally:
                if attempted:
                    try:actual_close(attempted[0])
                    except OSError:pass

    def test_p002_close_unknown_keeps_store_block_and_inconclusive(self) -> None:
        for scenario in ('store_block','child_inconclusive'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory(prefix='p002-state-close-') as directory:
                base=Path(directory);source=base/'source';runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
                runner.write_text('#!/usr/bin/python3\nimport os,sys\nb=b"{\\"status\\":\\"INCONCLUSIVE\\",\\"connections_attempted\\":null}\\n";'
                                  'os.write(int(sys.argv[sys.argv.index("--output-fd")+1]),b);os.write(1,b);sys.exit(20)\n')
                runner.chmod(0o755)
                args=type('Args',(),{'run_store_test':scenario=='store_block','profile':'isolated','output':None,
                                     'evidence_root':str(base/'evidence')})()
                actual_open,actual_close=os.open,os.close;target=[];attempted=[];output=io.StringIO()
                def track_open(path,flags,*pos,**kw):
                    value=actual_open(path,flags,*pos,**kw)
                    if path=='evidence' and kw.get('dir_fd') is not None and not target:target.append(value)
                    return value
                def close_fault(value):
                    if target and value==target[0]:attempted.append(value);raise OSError('injected evidence close failure')
                    return actual_close(value)
                try:
                    with patch.dict(os.environ,{},clear=True),patch.object(verify.os,'open',side_effect=track_open), \
                         patch.object(verify.os,'close',side_effect=close_fault),contextlib.redirect_stdout(output):
                        value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
                    self.assertEqual(len(attempted),1)
                    self.assertEqual((value['status'],code),('BLOCKED',20) if scenario=='store_block' else ('INCONCLUSIVE',20))
                    self.assertEqual(json.loads(output.getvalue()),value)
                    self.assertEqual(value['checks'][0]['details']['fd_close_states']['evidence_directory'],'UNKNOWN')
                    self.assertTrue(any(c['name']=='descriptor_cleanup' and c['status']=='INCONCLUSIVE' for c in value['checks']))
                    if scenario=='store_block':
                        self.assertIn('Store execution requires',value['reason'])
                        self.assertFalse(value['checks'][0]['details']['workload_invoked'])
                        self.assertEqual(value['checks'][1]['status'],'BLOCKED')
                    else:
                        self.assertIn('Runner did not establish authenticated PostgreSQL identity',value['reason'])
                        self.assertTrue(value['checks'][0]['details']['workload_invoked'])
                finally:
                    if attempted:
                        try:actual_close(attempted[0])
                        except OSError:pass

    def test_p002_capture_signal_or_wait_failure_keeps_termination_unknown(self) -> None:
        for failure in ('signal', 'wait', 'signal_then_receipt_error'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix='p002-capture-') as directory:
                base = Path(directory); source = base / 'source'; runner = source / 'ops/ecp/test_database.sh'
                runner.parent.mkdir(parents=True)
                runner.write_text('#!/usr/bin/python3\nimport os,time\nos.write(1,b"x"*2048)\ntime.sleep(0.2)\n')
                runner.chmod(0o755)
                args = type('Args', (), {'run_store_test':False, 'profile':'isolated', 'output':None,
                                         'evidence_root':str(base/'evidence')})()
                real_popen = subprocess.Popen; real_pread = os.pread; started = []; read_errors = []
                def spawn(*pos, **kwargs):
                    child = real_popen(*pos, **kwargs)
                    real_wait = child.wait
                    if failure == 'wait':
                        def wait_timeout(timeout=None):
                            raise subprocess.TimeoutExpired(child.args, timeout)
                        child.wait = wait_timeout
                    started.append((child, real_wait))
                    return child
                def pread_once_then_fail(fd, size, offset):
                    if failure == 'signal_then_receipt_error' and started and not read_errors:
                        read_errors.append(True)
                        raise OSError('injected receipt read failure after signal failure')
                    return real_pread(fd, size, offset)
                try:
                    with patch.object(verify.subprocess, 'Popen', side_effect=spawn), \
                         patch.object(verify.os, 'killpg', side_effect=PermissionError('injected') if failure != 'wait' else None) as kill, \
                         patch.object(verify.os, 'pread', side_effect=pread_once_then_fail), \
                         patch.object(verify, 'P003_MAX_LOG_BYTES', 1024), contextlib.redirect_stdout(io.StringIO()):
                        value, code = verify.run_database_suite(args, source, 'a'*40,
                                                                verify.base_report('suite', source, 'a'*40))
                    self.assertEqual((value['status'], code), ('INCONCLUSIVE', 20))
                    self.assertEqual(value['qualification'], 'NOT_RUN')
                    details = value['checks'][0]['details']
                    self.assertEqual(details['termination_reason'], 'stream_limit')
                    self.assertEqual(details['group_signal'], 'SIGKILL_SENT' if failure == 'wait' else 'SIGNAL_FAILED')
                    self.assertEqual(details['leader_reaped'], failure != 'wait')
                    self.assertIsNone(details['descendants_terminated'])
                    self.assertIsNone(value['database_connections_attempted'])
                    if failure == 'signal_then_receipt_error':
                        self.assertEqual(read_errors, [True])
                        self.assertEqual(details['validation_error_type'], 'OSError')
                        self.assertEqual((base / 'evidence' / 'stdout.log').read_bytes(), b'x' * 1024)
                        self.assertEqual(details['stdout.log_original_bytes'], 1024)
                        self.assertEqual(details['stdout.log_capture_state'], 'PARTIAL')
                        self.assertEqual(details['receipt_capture_state'], 'UNKNOWN')
                        self.assertFalse(details['raw_logs_complete_for_acceptance'])
                    kill.assert_called_once()
                finally:
                    for child, real_wait in started:
                        child.wait = real_wait
                        try:
                            real_wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            real_wait(timeout=5)

    def test_p002_receipt_read_error_preserves_exact_url_redacted_capture(self) -> None:
        import hashlib
        with tempfile.TemporaryDirectory(prefix='p002-fault-redaction-') as directory:
            base = Path(directory); source = base / 'source'; runner = source / 'ops/ecp/test_database.sh'
            runner.parent.mkdir(parents=True)
            runner.write_text('#!/usr/bin/python3\nimport os\nos.write(1,("begin "+os.environ["ECP_DATABASE_URL"]+" end\\n").encode())\n')
            runner.chmod(0o755)
            url = 'postgresql://fixture_user@localhost:55479/ecp_disposable_fixture?host=%2Ffixture'
            expected = ('begin ' + url + ' end\n').encode()
            args = type('Args', (), {'run_store_test':False, 'profile':'isolated', 'output':None,
                                     'evidence_root':str(base/'evidence')})()
            real_popen = subprocess.Popen; real_pread = os.pread; started = []; injected = []
            def spawn(*pos, **kwargs):
                child = real_popen(*pos, **kwargs); started.append(child); return child
            def pread_once_then_fail(fd, size, offset):
                if started and not injected:
                    injected.append(True)
                    raise OSError('injected receipt failure')
                return real_pread(fd, size, offset)
            try:
                with patch.dict(os.environ, {'ECP_DATABASE_URL':url, 'ECP_DATABASE_DISPOSABLE':'0'}, clear=True), \
                     patch.object(verify.subprocess, 'Popen', side_effect=spawn), \
                     patch.object(verify.os, 'pread', side_effect=pread_once_then_fail), \
                     contextlib.redirect_stdout(io.StringIO()):
                    value, code = verify.run_database_suite(args, source, 'a'*40,
                                                            verify.base_report('suite', source, 'a'*40))
                self.assertEqual((value['status'], code), ('FAIL', 10))
                self.assertEqual(injected, [True])
                details = value['checks'][0]['details']
                self.assertEqual(details['stdout.log_original_bytes'], len(expected))
                self.assertEqual(details['stdout.log_original_sha256'], hashlib.sha256(expected).hexdigest())
                self.assertTrue(details['redaction_detected'])
                self.assertFalse(details['raw_logs_complete_for_acceptance'])
                self.assertEqual(details['receipt_capture_state'], 'UNKNOWN')
                self.assertEqual((base/'evidence/stdout.log').read_bytes(), b'begin [REDACTED COMPLETE DATABASE URL] end\n')
                for name in ('stdout.log', 'stderr.log', 'database-probe.json'):
                    self.assertNotIn(url.encode(), (base/'evidence'/name).read_bytes())
            finally:
                for child in started:
                    if child.poll() is None: child.kill()
                    child.wait(timeout=5)

    def test_p002_selector_setup_select_read_and_close_failures_preserve_capture(self) -> None:
        for failure in ('register', 'select', 'read', 'close'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix='p002-selector-fault-') as directory:
                base = Path(directory); source = base/'source'; runner = source/'ops/ecp/test_database.sh'
                runner.parent.mkdir(parents=True)
                runner.write_text('#!/usr/bin/python3\nimport os,time\nos.write(1,b"first")\ntime.sleep(0.12)\nos.write(1,b"second")\ntime.sleep(0.12)\n')
                runner.chmod(0o755)
                args = type('Args', (), {'run_store_test':False,'profile':'isolated','output':None,
                                         'evidence_root':str(base/'evidence')})()
                selector_factory = verify.selectors.DefaultSelector; real_read = os.read
                real_popen = subprocess.Popen; started = []; created = []; reads = []; injected = []
                class FaultSelector:
                    def __init__(self):
                        self.real = selector_factory(); self.registrations = 0; self.seen_ready = False; self.closed = False
                        created.append(self)
                    def register(self, *pos, **kwargs):
                        self.registrations += 1
                        if failure == 'register' and self.registrations == 2:
                            injected.append('register'); raise OSError('injected selector setup error')
                        return self.real.register(*pos, **kwargs)
                    def unregister(self, *pos, **kwargs): return self.real.unregister(*pos, **kwargs)
                    def get_map(self): return self.real.get_map()
                    def select(self, *pos, **kwargs):
                        if failure == 'select' and self.seen_ready:
                            injected.append('select'); raise OSError('injected selector polling error')
                        rows = self.real.select(*pos, **kwargs)
                        if rows: self.seen_ready = True
                        return rows
                    def close(self):
                        if failure == 'close' and not injected:
                            injected.append('close'); raise OSError('injected selector close error')
                        self.real.close(); self.closed = True
                def spawn(*pos, **kwargs):
                    child = real_popen(*pos, **kwargs); started.append(child); return child
                def read_with_error(fd, size):
                    if failure == 'read' and started and started[0].stdout and fd == started[0].stdout.fileno():
                        if reads:
                            injected.append('read'); raise OSError('injected read error')
                        data = real_read(fd, size); reads.append(len(data)); return data
                    return real_read(fd, size)
                try:
                    with patch.dict(os.environ, {}, clear=True), \
                         patch.object(verify.selectors, 'DefaultSelector', FaultSelector), \
                         patch.object(verify.subprocess, 'Popen', side_effect=spawn), \
                         patch.object(verify.os, 'read', side_effect=read_with_error), \
                         contextlib.redirect_stdout(io.StringIO()):
                        value, code = verify.run_database_suite(args, source, 'a'*40,
                                                                verify.base_report('suite', source, 'a'*40))
                    self.assertEqual(injected, [failure])
                    self.assertEqual(len(created), 1)
                    self.assertIn((value['status'],code), (('FAIL',10),('INCONCLUSIVE',20)))
                    details = value['checks'][0]['details']
                    if failure == 'close':
                        self.assertFalse(created[0].closed)
                        self.assertEqual(details['selector_close_state'], 'UNKNOWN')
                        self.assertEqual((value['status'],code), ('INCONCLUSIVE',20))
                    else:
                        self.assertTrue(created[0].closed, 'selector must be released after failure')
                        self.assertEqual(details['selector_close_state'], 'CLOSED')
                    self.assertTrue(details['leader_reaped'])
                    self.assertIsNone(details['descendants_terminated'])
                    self.assertFalse(details['raw_logs_complete_for_acceptance'])
                    self.assertEqual(details['stdout.log_capture_state'],'PARTIAL')
                    self.assertEqual(details['receipt_capture_state'],'UNKNOWN')
                    output = (base/'evidence/stdout.log').read_bytes()
                    self.assertEqual(len(output),details['stdout.log_original_bytes'])
                    if failure in ('select','read','close'): self.assertTrue(output.startswith(b'first'))
                finally:
                    for child in started:
                        if child.poll() is None: child.kill()
                        child.wait(timeout=5)
                    for sel in created:
                        if not sel.closed: sel.real.close()

    def test_p002_wait_reaped_then_error_never_signals_reused_group(self) -> None:
        with tempfile.TemporaryDirectory(prefix='p002-reaped-') as directory:
            base = Path(directory); source = base / 'source'; runner = source / 'ops/ecp/test_database.sh'
            runner.parent.mkdir(parents=True)
            runner.write_text('#!/usr/bin/python3\nimport os,sys\n'
                'b=b"{\\"status\\":\\"BLOCKED\\",\\"connections_attempted\\":0}\\n";'
                'os.write(int(sys.argv[sys.argv.index("--output-fd")+1]),b);os.write(1,b);sys.exit(20)\n')
            runner.chmod(0o755)
            args = type('Args', (), {'run_store_test':False,'profile':'isolated','output':None,
                                     'evidence_root':str(base/'evidence')})()
            sentinel = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], start_new_session=True)
            real_popen = subprocess.Popen
            started = []
            def spawn(*pos, **kwargs):
                child = real_popen(*pos, **kwargs)
                real_wait = child.wait
                def wait_then_raise(timeout=None):
                    real_wait(timeout=timeout)
                    raise OSError('injected after wait reaped leader')
                child.wait = wait_then_raise
                started.append((child, real_wait))
                return child
            try:
                with patch.object(verify.subprocess, 'Popen', side_effect=spawn), \
                     patch.object(verify.os, 'killpg') as kill, contextlib.redirect_stdout(io.StringIO()):
                    value, code = verify.run_database_suite(args, source, 'a'*40,
                                                            verify.base_report('suite', source, 'a'*40))
                self.assertEqual((value['status'], code), ('INCONCLUSIVE', 20))
                self.assertEqual(value['qualification'], 'NOT_RUN')
                details = value['checks'][0]['details']
                self.assertEqual(details['group_signal'], 'NOT_SENT_LEADER_REAPED')
                self.assertTrue(details['leader_reaped'])
                self.assertIsNone(details['descendants_terminated'])
                kill.assert_not_called()
                self.assertIsNone(sentinel.poll())
            finally:
                for child, real_wait in started:
                    if child.poll() is None:
                        child.kill()
                    real_wait(timeout=5)
                sentinel.terminate()
                sentinel.wait(timeout=5)

    def test_p001_v3_preserves_child_capture_outcomes_and_unknown_termination(self) -> None:
        protocol = json.dumps({"status":"INCONCLUSIVE","qualification":"NOT_RUN","product_gate_effect":"NONE",
                               "reason_code":"GIT_TERMINATION_UNCONFIRMED","leader_reaped":False,
                               "group_signal":"FAILED","descendants_terminated":None,
                               "git_capture":{"status":"UNKNOWN","stdout_bytes":0,"stdout_sha256":"a"*64,
                                              "stderr_bytes":0,"stderr_sha256":"b"*64,"raw_output_persistence":"UNAVAILABLE"}}).encode()
        cases = [
            (False, False, False, None, "NOT_SENT", b"", b"", "BLOCKED"),
            (True, False, False, None, "SIGNAL_FAILED", b"", b"", "INCONCLUSIVE"),
            (True, True, True, 1, "NOT_SENT", b"", b"ordinary error", "FAIL"),
            (True, True, True, 1, "NOT_SENT", b"", b"v3 Git process termination could not be confirmed", "INCONCLUSIVE"),
            (True, True, True, 1, "NOT_SENT", b"", b"Git object process-group termination could not be confirmed", "INCONCLUSIVE"),
            (True, True, True, 20, "NOT_SENT", protocol, b"", "INCONCLUSIVE"),
            (True, True, True, 20, "NOT_SENT", b'{"status":"INCONCLUSIVE","product_gate_effect":"NONE"}', b"", "INCONCLUSIVE"),
            (True, True, True, 20, "NOT_SENT", b'{malformed', b"", "INCONCLUSIVE"),
            (True, True, True, 1, "NOT_SENT", b'{"reason_code":"GIT_TERMINATION_UNCONFIRMED"}', b"", "INCONCLUSIVE"),
            (True, True, True, 1, "NOT_SENT", b'{"reason_code":"GIT_TERMINATION_UNCONFIRMED', b"", "INCONCLUSIVE"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); root = temp / "source"
            (root / "ops/ecp").mkdir(parents=True)
            shutil.copy2(ROOT / "ops/ecp/source_snapshot.py", root / "ops/ecp/source_snapshot.py")
            for index, (started, complete, reaped, exit_code, signal_state, stdout, stderr, expected) in enumerate(cases):
                with self.subTest(expected=expected, started=started, complete=complete):
                    evidence = temp / f"evidence-{index}"
                    args = type("Args", (), {"source_root":str(root),"evidence_root":str(evidence),
                                             "candidate_root":None,"output":None,"profile":"isolated"})()
                    def capture(*pos, **kw):
                        result = {"started":started,"capture_complete":complete,"leader_reaped":reaped,
                                  "exit_code":exit_code,"termination_reason":"timeout" if not complete else None,
                                  "group_signal":signal_state,"descendants_terminated":None}
                        for name, data in (("stdout", stdout), ("stderr", stderr)):
                            path = kw[name + "_path"]; path.write_bytes(data)
                            result[name+"_bytes"] = data
                            result[name+"_sha256"] = verify.sha256_bytes(data)
                            result[name+"_size"] = len(data)
                            result[name+"_identity"] = verify._p001_identity(path.stat())
                        return result
                    with patch.object(verify, "run_p003_bounded", side_effect=capture), contextlib.redirect_stdout(io.StringIO()):
                        value, code = verify.run_source_snapshot_v3_suite(args, root, "a"*40,
                                                                          verify.base_report("suite", root, "a"*40))
                    self.assertEqual((value["status"], code), (expected, verify.EXIT_CODES[expected]))
                    self.assertEqual(value["qualification"], "NOT_RUN")
                    self.assertEqual(value["checks"][0]["details"]["leader_reaped"], reaped)
                    self.assertIsNone(value["checks"][0]["details"]["descendants_terminated"])
                    self.assertTrue((evidence / "source.stderr.log").is_file())
                    if stdout == protocol:
                        details = value["checks"][0]["details"]
                        self.assertIsNone(details["nested_descendants_terminated"])
                        self.assertEqual(details["nested_git_capture"]["raw_output_persistence"], "UNAVAILABLE")

    def test_p001_v3_nested_unknown_retains_candidate_across_later_stages(self) -> None:
        protocol = json.dumps({"status":"INCONCLUSIVE","qualification":"NOT_RUN","product_gate_effect":"NONE",
                               "reason_code":"GIT_TERMINATION_UNCONFIRMED","leader_reaped":False,
                               "group_signal":"FAILED","descendants_terminated":None}).encode()
        for stage in ("materialization", "oracle"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                base=Path(directory); source=self.make_v3_source_root(base)
                evidence=base/'evidence'; candidate=base/'candidate'
                sha=subprocess.check_output(['/usr/bin/git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
                args=type('Args',(),{'profile':'isolated','evidence_root':str(evidence),'source_root':str(source),
                                     'candidate_root':str(candidate),'output':None})()
                original=verify.run_p003_bounded
                def inject(command,**kw):
                    is_oracle='--manifest-fd' in command
                    is_material=not is_oracle and any('materialize_snapshot' in str(arg) for arg in command)
                    if (stage == 'oracle' and is_oracle) or (stage == 'materialization' and is_material):
                        stdout = protocol if is_oracle else b''
                        stderr = b'' if is_oracle else b'Git object process-group termination could not be confirmed'
                        value={'started':True,'capture_complete':True,'leader_reaped':True,
                               'exit_code':20 if is_oracle else 1,'termination_reason':None,
                               'group_signal':'NOT_SENT','descendants_terminated':None}
                        for name,data in (("stdout",stdout),("stderr",stderr)):
                            path=kw[name+'_path'];path.write_bytes(data)
                            value[name+'_bytes']=data;value[name+'_sha256']=verify.sha256_bytes(data)
                            value[name+'_size']=len(data);value[name+'_identity']=verify._p001_identity(path.stat())
                        return value
                    return original(command,**kw)
                with patch.object(verify,'run_p003_bounded',side_effect=inject), contextlib.redirect_stdout(io.StringIO()):
                    value,code=verify.run_source_snapshot_v3_suite(args,source,sha,verify.base_report('suite',source,sha))
                self.assertEqual((value['status'],code),('INCONCLUSIVE',20))
                row=value['checks'][2 if stage=='oracle' else 1]
                self.assertTrue(row['details']['nested_process_termination_unknown'])
                self.assertIsNone(row['details']['descendants_terminated'])
                self.assertEqual(value['candidate_publication']['state'],'POSSIBLY_PUBLISHED_RETAINED')
                self.assertFalse(value['candidate_publication']['cleanup_attempted'])
                self.assertEqual(candidate.exists(),stage=='oracle')

    def test_p001_v3_retains_unknown_git_termination_before_evidence(self) -> None:
        import source_snapshot
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            candidate = Path(directory) / "candidate"
            args = verify.parser().parse_args(["suite", "--suite", "ECP-P0-01", "--source-manifest-version", "3",
                "--source-root", str(ROOT), "--evidence-root", str(evidence), "--candidate-root", str(candidate)])
            with patch.object(source_snapshot, "_v3_bounded_git", side_effect=RuntimeError("termination unknown")), \
                 patch.object(verify, "run_source_snapshot_v3_suite") as run, contextlib.redirect_stdout(io.StringIO()):
                value, code = verify.suite(args)
            self.assertEqual((value["status"], code), ("INCONCLUSIVE", 20))
            self.assertEqual(value["qualification"], "NOT_RUN")
            self.assertIsNone(value["leader_reaped"])
            self.assertIsNone(value["descendants_terminated"])
            self.assertFalse(evidence.exists())
            self.assertFalse(candidate.exists())
            run.assert_not_called()

    def test_v3_mount_backing_identifies_subdirectory_bind_alias(self) -> None:
        table = ('10 1 8:1 / / rw - ext4 /dev/a rw\n'
                 '11 10 8:1 /tmp/source/docs /alias\\040space rw - ext4 /dev/a rw\n')
        self.assertEqual(verify._p001_backing_path(Path('/tmp/source'),table),('8:1','/tmp/source'))
        self.assertEqual(verify._p001_backing_path(Path('/alias space/sub'),table),('8:1','/tmp/source/docs/sub'))
        with patch.object(Path,'read_text',return_value=table):
            self.assertTrue(verify._p001_parent_aliases_source(Path('/tmp/source'),Path('/alias space/sub')))
            self.assertFalse(verify._p001_parent_aliases_source(Path('/tmp/source'),Path('/elsewhere')))
        with self.assertRaises(ValueError):
            verify._p001_backing_path(Path('/tmp/source'),'malformed\n')

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.registry_path = Path(temporary.name) / 'suite_registry.json'
        self.registry = {'suites': [{
            'suite_id': 'ECP-P0-03',
            'implementation_entrypoint': 'control/ops/ecp/verify',
            'offline_workload': {
                'runner': 'python_unittest', 'start_directory': 'ops/ecp/tests',
                'pattern': 'test_p003_contract.py', 'requires_non_skipped': True,
                'network_access': False, 'database_access': False,
            },
        }]}
        self.registry_path.write_text(json.dumps(self.registry), encoding='utf-8')
        environment = patch.dict(os.environ, {'ECP_SUITE_REGISTRY': str(self.registry_path)})
        environment.start()
        self.addCleanup(environment.stop)

    def run_cli(self, *args: str) -> tuple[int, dict]:
        env = os.environ.copy()
        env["ECP_GIT_STATUS_TIMEOUT_SECONDS"] = "5"
        completed = subprocess.run([str(ENTRY), *args], cwd=ROOT, env=env, text=True, capture_output=True, check=False)
        self.assertTrue(completed.stdout, completed.stderr)
        return completed.returncode, json.loads(completed.stdout)

    def test_doctor_is_offline_and_structured(self) -> None:
        code, value = self.run_cli("doctor")
        self.assertIn(code, (0, 20))
        self.assertEqual(value["schema_version"], "forgeflow.ecp-verification.v1")
        self.assertEqual(value["product_gate_effect"], "NONE")
        self.assertEqual(value["database_connections_attempted"], 0)
        self.assertIn(value["status"], {"PASS", "BLOCKED", "NOT_RUN", "INCONCLUSIVE"})
        self.assertIn("denominator", value)

    def test_source_identity_uses_canonical_manifest_for_large_worktree(self) -> None:
        manifest = {
            "head": "a" * 40,
            "manifest_sha256": "b" * 64,
            "worktree_state": "DIRTY_UNFROZEN",
            "tracked_changes": [{"path": "tracked.py"}],
            "untracked_business_files": [{"path": "untracked.py"}, {"path": "new.py"}],
            "excluded_generated_files": [{"path": "evidence/run.log"}],
        }
        with patch.object(verify, "build_manifest", return_value=manifest) as build:
            check, source_sha, status_lines = verify.check_source_identity(ROOT)
        build.assert_called_once_with(ROOT, verify.DEFAULT_EXCLUDES)
        self.assertEqual(check.status, "INCONCLUSIVE")
        self.assertEqual(source_sha, "a" * 40)
        self.assertEqual(status_lines, [])
        self.assertEqual(check.details["source_manifest_sha256"], "b" * 64)
        self.assertEqual(check.details["status_entries"], 4)
        self.assertEqual(check.details["tracked_entries"], 1)
        self.assertEqual(check.details["untracked_entries"], 2)
        self.assertEqual(check.details["excluded_generated_entries"], 1)

    def test_source_identity_manifest_failure_is_inconclusive(self) -> None:
        with patch.object(verify, "build_manifest", side_effect=TimeoutError("manifest deadline")):
            check, source_sha, status_lines = verify.check_source_identity(ROOT)
        self.assertEqual(check.status, "INCONCLUSIVE")
        self.assertIsNone(source_sha)
        self.assertEqual(status_lines, [])
        self.assertIn("canonical source manifest unavailable", check.reason)

    def test_report_preserves_not_run_and_source_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "evidence.json"
            input_path.write_text(json.dumps({"status": "NOT_RUN", "source_sha": "a" * 40}), encoding="utf-8")
            code, value = self.run_cli("report", "--input", str(input_path), "--source-sha", "a" * 40)
            self.assertEqual(code, 20)
            self.assertEqual(value["status"], "NOT_RUN")
            self.assertEqual(value["database_connections_attempted"], 0)

    def test_report_requires_source_binding_for_every_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bound = Path(directory) / "bound.json"
            missing = Path(directory) / "missing.json"
            bound.write_text(json.dumps({"status": "PASS", "source_sha": "a" * 40}), encoding="utf-8")
            missing.write_text(json.dumps({"status": "PASS"}), encoding="utf-8")
            code, value = self.run_cli("report", "--input", str(bound), "--input", str(missing),
                                       "--source-sha", "a" * 40)
            self.assertEqual(code, 20)
            self.assertEqual(value["status"], "INCONCLUSIVE")
            self.assertTrue(any(c["name"] == "source_binding" and c["status"] == "INCONCLUSIVE"
                                for c in value["checks"]))

    def test_report_rejects_invalid_and_unauthenticated_matching_shas(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "claim.json"
            for source_sha, expected_status, expected_code in (("not-a-sha", "FAIL", 10),
                                                               ("a" * 40, "INCONCLUSIVE", 20)):
                with self.subTest(source_sha=source_sha):
                    evidence.write_text(json.dumps({"status": "PASS", "source_sha": source_sha}), encoding="utf-8")
                    code, value = self.run_cli("report", "--input", str(evidence), "--source-sha", source_sha)
                    self.assertEqual((code, value["status"]), (expected_code, expected_status))

    def test_base_report_does_not_execute_uname_from_caller_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp=Path(directory);tools=temp/"tools";tools.mkdir();marker=temp/"uname-ran"
            fake=tools/"uname";fake.write_text('#!/bin/sh\nprintf triggered > "$ECP_CANARY_MARKER"\nexit 95\n')
            fake.chmod(0o755)
            env=os.environ.copy();env.update(PATH=str(tools)+os.pathsep+"/usr/bin:/bin",ECP_CANARY_MARKER=str(marker))
            script=('import json,sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); '
                    'import verify; print(json.dumps(verify.base_report("suite",Path(sys.argv[2]),None)))')
            run=subprocess.run([sys.executable,'-I','-B','-S','-c',script,str(ROOT/'ops/ecp'),str(ROOT)],
                               cwd=ROOT,env=env,text=True,capture_output=True,timeout=15)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertFalse(marker.exists(),"base_report executed caller PATH uname")
            report=json.loads(run.stdout)
            self.assertEqual(report['product_gate_effect'],'NONE')

    def test_p001_v3_source_sha_does_not_execute_git_from_caller_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp=Path(directory);source=self.make_v3_source_root(temp,unavailable=True)
            expected=subprocess.check_output(['/usr/bin/git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
            tools=temp/'tools';tools.mkdir();marker=temp/'git-ran'
            fake=tools/'git';fake.write_text('#!/bin/sh\nprintf triggered > "$ECP_CANARY_MARKER"\nexit 95\n')
            fake.chmod(0o755)
            env=os.environ.copy();env.update(PATH=str(tools)+os.pathsep+'/usr/bin:/bin',ECP_CANARY_MARKER=str(marker))
            evidence=temp/'evidence';candidate=temp/'candidate'
            run=subprocess.run([sys.executable,'-B',str(ENTRY),'suite','--suite','ECP-P0-01',
                '--source-manifest-version','3','--source-root',str(source),'--evidence-root',str(evidence),
                '--candidate-root',str(candidate)],cwd=ROOT,env=env,text=True,capture_output=True,timeout=30)
            self.assertTrue(run.stdout,run.stderr)
            report=json.loads(run.stdout)
            self.assertFalse(marker.exists(),"P001 v3 executed caller PATH git")
            self.assertEqual(report['source_sha'],expected)
            self.assertEqual(report['product_gate_effect'],'NONE')
            self.assertEqual(report['qualification'],'NOT_RUN')
            self.assertIn(report['status'],('BLOCKED','INCONCLUSIVE','FAIL'))
            self.assertFalse(candidate.exists())

    def assert_p003_execution_blocked(self, code: int, value: dict) -> None:
        self.assertEqual((code, value["status"], value["qualification"], value["product_gate_effect"]),
                         (20, "BLOCKED", "NOT_RUN", "NONE"))
        for name in ("workload_invoked", "database_connections_attempted", "source_sha", "denominator", "checks"):
            self.assertIn(name, value)
        self.assertIs(value["workload_invoked"], False)
        self.assertIsNone(value["database_connections_attempted"])
        self.assertIsNone(value["source_sha"])
        self.assertEqual(value["denominator"], {"total": 1, "passed": 0, "failed": 0,
                                                "blocked": 1, "not_run": 0, "inconclusive": 0})
        self.assertEqual(len(value["checks"]), 1)
        self.assertEqual((value["checks"][0]["name"], value["checks"][0]["status"]),
                         ("execution_authority", "BLOCKED"))

    def test_p003_direct_entry_blocks_before_registry_or_workload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); evidence = temp / "evidence"; output = temp / "output.json"
            args = type("Args", (), {"evidence_root": str(evidence), "output": str(output),
                                     "profile": "isolated"})()
            report = {"source_sha": "a" * 40, "database_connections_attempted": 0,
                      "product_gate_effect": "NONE"}
            with patch.object(verify, "load_declared_suite", side_effect=AssertionError("registry read")), \
                 patch.object(verify, "source_manifest_identity", side_effect=AssertionError("source scan")), \
                 patch.object(verify, "validate_p003_workload", side_effect=AssertionError("workload validation")), \
                 patch.object(verify, "run_p003_bounded", side_effect=AssertionError("child started")), \
                 patch.object(verify.subprocess, "Popen", side_effect=AssertionError("subprocess started")), \
                 patch.object(verify.platform, "platform", side_effect=AssertionError("platform subprocess")), \
                 contextlib.redirect_stdout(io.StringIO()):
                value, code = verify.run_phase0_offline_suite(args, ROOT, "a" * 40, report)
            self.assert_p003_execution_blocked(code, value)
            self.assertFalse(evidence.exists())
            self.assertFalse(output.exists())

    def test_p003_direct_entry_preserves_existing_files_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp=Path(directory); evidence=temp / "evidence"; evidence.mkdir()
            marker=evidence / "stdout.log"; marker.write_bytes(b"user evidence\x00")
            output=temp / "existing.json"; output.write_bytes(b"user output\x00")
            alias=temp / "alias"; alias.symlink_to(evidence, target_is_directory=True)
            for root in (evidence, alias):
                with self.subTest(root=root):
                    args=type("Args", (), {"evidence_root":str(root),"output":str(output),"profile":"isolated"})()
                    report={"source_sha": "a" * 40,"database_connections_attempted":0,"product_gate_effect":"NONE"}
                    with patch.object(verify, "run_p003_bounded", side_effect=AssertionError("child started")), \
                         contextlib.redirect_stdout(io.StringIO()):
                        value,code=verify.run_phase0_offline_suite(args,ROOT,"a"*40,report)
                    self.assert_p003_execution_blocked(code,value)
                    self.assertEqual(marker.read_bytes(),b"user evidence\x00")
                    self.assertEqual(output.read_bytes(),b"user output\x00")
                    self.assertTrue(alias.is_symlink())
                    self.assertEqual(sorted(x.name for x in evidence.iterdir()),["stdout.log"])

    def test_p003_cli_dirty_root_and_path_canaries_never_execute(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp=Path(directory);source=self.make_source_root(temp,dirty=True)
            shutil.copy2(ENTRY,source / "ops/ecp/verify")
            test_dir=source / "ops/ecp/tests";test_dir.mkdir()
            workload_marker=temp / "workload-ran"
            (test_dir / "test_p003_contract.py").write_text(
                "from pathlib import Path\nPath("+repr(str(workload_marker))+").write_text('unexpected')\n")
            tool_dir=temp / "tools";tool_dir.mkdir();marker_dir=temp / "markers";marker_dir.mkdir()
            for name in ("git", "uname"):
                tool=tool_dir/name
                tool.write_text("#!/bin/sh\nprintf triggered > \"$P003_CANARY_DIR/"+name+"\"\nexit 95\n")
                tool.chmod(0o755)
            evidence=temp / "evidence";output=temp / "user.json";output.write_bytes(b"keep user output\x00")
            env=os.environ.copy();env.update(PATH=str(tool_dir)+os.pathsep+"/usr/bin:/bin",P003_CANARY_DIR=str(marker_dir))
            env["PYTHONDONTWRITEBYTECODE"]="1"
            run=subprocess.run([sys.executable,"-B",str(ENTRY),"suite","--suite","ECP-P0-03",
                 "--source-root",str(source),"--profile","isolated","--evidence-root",str(evidence),
                 "--output",str(output)],cwd=ROOT,env=env,text=True,capture_output=True,timeout=15)
            self.assertTrue(run.stdout,run.stderr)
            for name,path in (("workload",workload_marker),("git",marker_dir/"git"),("uname",marker_dir/"uname"),
                              ("evidence",evidence)):
                with self.subTest(effect=name):self.assertFalse(path.exists())
            with self.subTest(effect="output"):
                self.assertEqual(output.read_bytes(),b"keep user output\x00")
            with self.subTest(effect="source"):
                self.assertEqual((source / "Cargo.toml").read_text(),"[workspace]\n# dirty\n")
            with self.subTest(effect="report"):
                self.assert_p003_execution_blocked(run.returncode,json.loads(run.stdout))

    def test_p003_cli_without_evidence_and_unsupported_profile_remains_blocked(self) -> None:
        for profile in ("isolated", "unknown-profile"):
            with self.subTest(profile=profile):
                code,value=self.run_cli("--suite","ECP-P0-03","--profile",profile)
                self.assert_p003_execution_blocked(code,value)

    def test_p003_cli_v3_option_blocks_before_git_and_platform_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp=Path(directory);tools=temp/'tools';tools.mkdir();markers=temp/'markers';markers.mkdir()
            for name in ('git','uname'):
                tool=tools/name
                tool.write_text('#!/bin/sh\nprintf triggered > "$ECP_CANARY_DIR/'+name+'"\nexit 95\n')
                tool.chmod(0o755)
            env=os.environ.copy();env.update(PATH=str(tools)+os.pathsep+'/usr/bin:/bin',ECP_CANARY_DIR=str(markers))
            evidence=temp/'evidence'
            run=subprocess.run([sys.executable,'-B',str(ENTRY),'suite','--suite','ECP-P0-03',
                '--source-manifest-version','3','--source-root',str(ROOT),'--evidence-root',str(evidence)],
                cwd=ROOT,env=env,text=True,capture_output=True,timeout=15)
            self.assertTrue(run.stdout,run.stderr)
            with self.subTest(effect='git'):self.assertFalse((markers/'git').exists())
            with self.subTest(effect='uname'):self.assertFalse((markers/'uname').exists())
            with self.subTest(effect='evidence'):self.assertFalse(evidence.exists())
            with self.subTest(effect='report'):self.assert_p003_execution_blocked(run.returncode,json.loads(run.stdout))

    def test_p003_cli_does_not_import_dirty_source_test_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp=Path(directory);source=self.make_source_root(temp,dirty=True)
            shutil.copy2(ENTRY,source / "ops/ecp/verify")
            test_dir=source / "ops/ecp/tests";test_dir.mkdir()
            marker=temp / "module-imported"
            (test_dir / "test_p003_contract.py").write_text(
                "from pathlib import Path\nPath("+repr(str(marker))+").write_text('unexpected')\n")
            evidence=temp/"evidence"
            env=os.environ.copy();env["PYTHONDONTWRITEBYTECODE"]="1"
            run=subprocess.run([sys.executable,"-B",str(ENTRY),"suite","--suite","ECP-P0-03",
                "--source-root",str(source),"--evidence-root",str(evidence)],cwd=ROOT,env=env,
                text=True,capture_output=True,timeout=20)
            self.assertTrue(run.stdout,run.stderr)
            with self.subTest(effect="module import"):self.assertFalse(marker.exists())
            with self.subTest(effect="evidence"):self.assertFalse(evidence.exists())
            with self.subTest(effect="report"):self.assert_p003_execution_blocked(run.returncode,json.loads(run.stdout))

    def test_p003_cli_never_writes_inside_source_or_colliding_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp=Path(directory);source=self.make_source_root(temp,dirty=True)
            for evidence in (source / "unsafe-evidence",temp / "outside-evidence"):
                with self.subTest(evidence=evidence):
                    output=evidence/"stdout.log"
                    code,value=self.run_cli("--suite","ECP-P0-03","--source-root",str(source),
                                            "--evidence-root",str(evidence),"--output",str(output))
                    self.assert_p003_execution_blocked(code,value)
                    self.assertFalse(evidence.exists())




    def test_p003_bounded_runner_preserves_raw_bytes_and_refuses_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out, err = Path(directory) / "out", Path(directory) / "err"
            command = [sys.executable, "-c", "import os; os.write(1,b'\\xff\\x00'); os.write(2,b'hello\\n')"]
            result = verify.run_p003_bounded(command, cwd=ROOT, env=os.environ.copy(),
                                             stdout_path=out, stderr_path=err, timeout=5, log_limit=128)
            self.assertTrue(result["capture_complete"])
            self.assertTrue(result["leader_reaped"])
            self.assertEqual(result["exit_code"], 0)
            self.assertIsNone(result["descendants_terminated"])
            self.assertEqual((out.read_bytes(), err.read_bytes()), (b"\xff\x00", b"hello\n"))
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(err.stat().st_mode), 0o600)
            self.assertEqual(result["stdout_sha256"], verify.sha256_bytes(out.read_bytes()))
            with self.assertRaises(FileExistsError):
                verify.run_p003_bounded(command, cwd=ROOT, env=os.environ.copy(),
                                        stdout_path=out, stderr_path=err, timeout=5, log_limit=128)
            self.assertEqual(out.read_bytes(), b"\xff\x00")

    def test_p003_existing_stderr_is_not_overwritten_or_used_to_start_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out, err = Path(directory) / "out", Path(directory) / "err"
            err.write_bytes(b"previous evidence")
            with patch.object(verify.subprocess, "Popen", side_effect=AssertionError("must not start")):
                with self.assertRaises(FileExistsError):
                    verify.run_p003_bounded([sys.executable, "-c", "pass"], cwd=ROOT, env=os.environ.copy(),
                                            stdout_path=out, stderr_path=err, timeout=5, log_limit=128)
            self.assertEqual(err.read_bytes(), b"previous evidence")

    def test_p003_capture_failure_reaps_its_own_leader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out, err = Path(directory) / "out", Path(directory) / "err"
            started = []
            popen = subprocess.Popen
            def start(*args, **kwargs):
                result = popen(*args, **kwargs)
                started.append(result)
                return result
            with patch.object(verify.subprocess, "Popen", side_effect=start), \
                 patch.object(verify.selectors, "DefaultSelector") as selector:
                selector.return_value.get_map.return_value = {1: True}
                selector.return_value.select.side_effect = OSError("synthetic capture failure")
                with self.assertRaises(OSError):
                    verify.run_p003_bounded([sys.executable, "-c", "import time; time.sleep(30)"],
                                            cwd=ROOT, env=os.environ.copy(), stdout_path=out,
                                            stderr_path=err, timeout=5, log_limit=128)
            self.assertEqual(len(started), 1)
            self.assertIsNotNone(started[0].returncode)

    def test_bounded_capture_reports_unknown_when_signal_and_wait_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sentinel = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
            started = []
            real_popen, real_killpg = subprocess.Popen, os.killpg
            def spawn(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                real_wait = child.wait
                child.wait = lambda timeout=None: real_wait(timeout=min(timeout or 0.1, 0.1))
                started.append((child, real_wait))
                return child
            try:
                with patch.object(verify.subprocess, "Popen", side_effect=spawn), \
                     patch.object(verify.selectors, "DefaultSelector") as selector, \
                     patch.object(verify.os, "killpg", side_effect=PermissionError("injected signal failure")) as kill:
                    selector.return_value.get_map.return_value = {1: True}
                    selector.return_value.select.side_effect = OSError("injected selector failure")
                    with self.assertRaisesRegex(RuntimeError, "termination could not be confirmed"):
                        verify.run_p003_bounded([sys.executable, "-c", "import time; time.sleep(30)"],
                            cwd=ROOT, env=os.environ.copy(), stdout_path=Path(directory)/"out",
                            stderr_path=Path(directory)/"err", timeout=5, log_limit=128)
                self.assertEqual(len(started), 1)
                self.assertIsNone(started[0][0].poll())
                self.assertEqual(kill.call_args.args[0], started[0][0].pid)
                self.assertIsNone(sentinel.poll())
            finally:
                for child, real_wait in started:
                    if child.poll() is None:
                        real_killpg(child.pid, 9)
                    real_wait(timeout=5)
                sentinel.terminate()
                sentinel.wait(timeout=5)

    def test_bounded_capture_never_signals_after_wait_reaps_leader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sentinel = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
            real_popen = subprocess.Popen
            started = []
            def spawn(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                real_wait = child.wait
                def wait_then_raise(timeout=None):
                    real_wait(timeout=timeout)
                    raise OSError("injected after wait reaped leader")
                child.wait = wait_then_raise
                started.append((child, real_wait))
                return child
            try:
                with patch.object(verify.subprocess, "Popen", side_effect=spawn), \
                     patch.object(verify.os, "killpg") as kill:
                    with self.assertRaisesRegex(RuntimeError, "termination could not be confirmed"):
                        verify.run_p003_bounded([sys.executable, "-c", "pass"], cwd=ROOT, env=os.environ.copy(),
                            stdout_path=Path(directory)/"out", stderr_path=Path(directory)/"err", timeout=5)
                self.assertIsNotNone(started[0][0].returncode)
                kill.assert_not_called()
                self.assertIsNone(sentinel.poll())
            finally:
                for child, real_wait in started:
                    if child.poll() is None:
                        child.kill()
                    real_wait(timeout=5)
                sentinel.terminate()
                sentinel.wait(timeout=5)

    def test_p003_log_limit_kills_only_its_own_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sentinel = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                        start_new_session=True)
            try:
                out, err = Path(directory) / "out", Path(directory) / "err"
                command = [sys.executable, "-c", "import os; [(os.write(1,b'a'*4096), os.write(2,b'b'*4096)) for _ in range(10000)]"]
                result = verify.run_p003_bounded(command, cwd=ROOT, env=os.environ.copy(),
                                                 stdout_path=out, stderr_path=err, timeout=5, log_limit=1024)
                self.assertEqual(result["termination_reason"], "log_limit_exceeded")
                self.assertFalse(result["capture_complete"])
                self.assertEqual(result["group_signal"], "SIGKILL_SENT")
                self.assertTrue(result["leader_reaped"])
                self.assertLessEqual(out.stat().st_size, 1024)
                self.assertLessEqual(err.stat().st_size, 1024)
                self.assertEqual(result["stdout_sha256"], verify.sha256_bytes(out.read_bytes()))
                self.assertEqual(result["stderr_sha256"], verify.sha256_bytes(err.read_bytes()))
                self.assertIsNone(sentinel.poll())
            finally:
                sentinel.terminate()
                sentinel.wait(timeout=5)


    def test_p003_timeout_terminates_owned_child_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out, err = Path(directory) / "out", Path(directory) / "err"
            script = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); print(p.pid,flush=True); time.sleep(30)"
            result = verify.run_p003_bounded([sys.executable, "-c", script], cwd=ROOT,
                                             env=os.environ.copy(), stdout_path=out, stderr_path=err,
                                             timeout=1, log_limit=1024)
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["group_signal"], "SIGKILL_SENT")
            self.assertTrue(result["leader_reaped"])
            self.assertFalse(result["capture_complete"])
            pid = int(out.read_text().strip())
            deadline = time.monotonic() + 3
            state = None
            while time.monotonic() < deadline:
                try:
                    # Linux task state follows the final ')' of the command.
                    state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].strip().split()[0]
                except FileNotFoundError:
                    state = None
                if state in (None, "Z", "X"):
                    break
                time.sleep(0.05)
            self.assertIn(state, (None, "Z", "X"))

    def test_suite_command_is_explicitly_not_run(self) -> None:
        code, value = self.run_cli("--suite", "ECP-P0-01", "--profile", "isolated")
        self.assertEqual(code, 20)
        self.assertEqual(value["status"], "NOT_RUN")
        self.assertEqual(value["denominator"]["total"], 1)
        self.assertEqual(value["product_gate_effect"], "NONE")

    def test_unittest_denominator_rejects_empty_and_all_skipped(self) -> None:
        status, counts, reason = verify.parse_unittest_denominator("", "", 0)
        self.assertEqual(status, "FAIL")
        self.assertEqual(counts["total"], 0)
        self.assertEqual(counts["not_run"], 0)
        self.assertIn("no unittest denominator", reason)
        status, counts, reason = verify.parse_unittest_denominator(
            "Ran 2 tests in 0.01s\nOK (skipped=2)", "", 0
        )
        self.assertEqual(status, "FAIL")
        self.assertEqual(counts["total"], 2)
        self.assertEqual(counts["skipped"], 2)
        self.assertIn("all discovered tests", reason)

    def test_unknown_suite_is_blocked_by_registry(self) -> None:
        code, value = self.run_cli("--suite", "ECP-P0-UNKNOWN", "--profile", "isolated")
        self.assertEqual(code, 20)
        self.assertEqual(value["status"], "BLOCKED")
        self.assertEqual(value["checks"][0]["name"], "suite_registry")









    def make_source_root(self, parent: Path, dirty: bool) -> Path:
        source = parent / "source"
        (source / "ops" / "ecp").mkdir(parents=True)
        shutil.copy2(ROOT / "ops" / "ecp" / "source_snapshot.py", source / "ops" / "ecp" / "source_snapshot.py")
        (source / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(source), "config", "user.name", "ECP test"], check=True)
        subprocess.run(["git", "-C", str(source), "add", "Cargo.toml", "ops/ecp/source_snapshot.py"], check=True)
        subprocess.run(["git", "-C", str(source), "commit", "-qm", "baseline"], check=True)
        if dirty:
            (source / "Cargo.toml").write_text("[workspace]\n# dirty\n", encoding="utf-8")
        return source

    def make_v3_source_root(self, parent: Path, *, unavailable: bool = False,
                            failing: bool = False, oracle_fd_support: bool = True) -> Path:
        source = parent / 'v3-source'
        for relative in ('ops/ecp/source_snapshot.py','ops/ecp/materialize_snapshot.py',
                         'verification/ecp/p005_snapshot_oracle.py'):
            destination = source / relative
            destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT / relative,destination)
            destination.chmod(0o644)
        snapshot = source/'ops/ecp/source_snapshot.py'
        if unavailable:
            with snapshot.open('a',encoding='utf-8') as stream:
                stream.write("\n_original_mode = _v3_mount_status\ndef _v3_mount_status(root):\n    _, info = _original_mode(root)\n    return 'UNAVAILABLE', info\n")
        if failing:
            with snapshot.open('a',encoding='utf-8') as stream:
                stream.write("\ndef build_manifest_v3(*args, **kwargs):\n    raise RuntimeError('synthetic source failure')\n")
        if not oracle_fd_support:
            path = source/'verification/ecp/p005_snapshot_oracle.py'
            value = path.read_text(encoding='utf-8').replace('--manifest-fd','--manifest-removed')
            path.write_text(value,encoding='utf-8')
        (source/'README').write_text('versioned source fixture\n',encoding='utf-8')
        subprocess.run(['git','init','-q',str(source)],check=True)
        subprocess.run(['git','-C',str(source),'config','user.email','test@example.invalid'],check=True)
        subprocess.run(['git','-C',str(source),'config','user.name','P001 fixture'],check=True)
        subprocess.run(['git','-C',str(source),'add','.'],check=True)
        subprocess.run(['git','-C',str(source),'commit','-qm','fixture'],check=True)
        return source

    def test_p001_v3_fixture_tools_use_explicit_mode_without_mutating_sources(self) -> None:
        relatives = ('ops/ecp/source_snapshot.py', 'ops/ecp/materialize_snapshot.py',
                     'verification/ecp/p005_snapshot_oracle.py')
        before = {name: ((ROOT / name).stat().st_mode & 0o7777, (ROOT / name).read_bytes())
                  for name in relatives}
        with tempfile.TemporaryDirectory() as directory:
            source = self.make_v3_source_root(Path(directory))
            for name in relatives:
                self.assertEqual((source / name).stat().st_mode & 0o7777, 0o644, name)
                self.assertEqual((source / name).read_bytes(), before[name][1], name)
                self.assertEqual(((ROOT / name).stat().st_mode & 0o7777, (ROOT / name).read_bytes()),
                                 before[name], name)

    def test_p001_v3_rejected_for_p002_before_database_or_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence=Path(directory)/'evidence'
            args=verify.parser().parse_args(['suite','--suite','ECP-P0-02','--source-manifest-version','3',
                                             '--source-root',str(ROOT),'--evidence-root',str(evidence)])
            with patch.object(verify,'run_database_suite',side_effect=AssertionError('database dispatch occurred')) as database, contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.suite(args)
            database.assert_not_called()
            self.assertEqual((code,value['status'],value['qualification']),(20,'BLOCKED','NOT_RUN'))
            self.assertEqual(value['database_connections_attempted'],0)
            self.assertIn('only supported by ECP-P0-01',value['reason'])
            self.assertFalse(evidence.exists())

    def test_p001_v3_real_chain_preserves_non_gate_status_and_raw_logs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); source=self.make_v3_source_root(base)
            evidence=base/'evidence'; candidate=base/'candidate'
            code,value=self.run_cli('--suite','ECP-P0-01','--source-manifest-version','3',
                                    '--source-root',str(source),'--evidence-root',str(evidence),
                                    '--candidate-root',str(candidate))
            self.assertEqual((code,value['status'],value['qualification'],value['product_gate_effect']),
                             (20,'INCONCLUSIVE','NOT_RUN','NONE'))
            self.assertFalse(value['independent_execution_authority_verified'])
            self.assertEqual(value['denominator'],{'total':3,'passed':0,'failed':0,'blocked':0,
                                                  'not_run':0,'inconclusive':3})
            self.assertEqual(value['oracle']['status'],'OBSERVED_NOT_GATE')
            self.assertEqual(value['oracle']['candidate_inventory_v3_sha256'],
                             value['materialization']['candidate_inventory_v3_sha256'])
            for name in ('source-snapshot.json','materialization.json','oracle.json','result.json',
                         'source.stdout.log','source.stderr.log','materialization.stdout.log',
                         'materialization.stderr.log','oracle.stdout.log','oracle.stderr.log'):
                self.assertTrue((evidence/name).is_file(),name)
            self.assertEqual((candidate/'README').read_text(encoding='utf-8'),'versioned source fixture\n')

    def test_p001_v3_tool_memfd_is_immutable_and_libc_fallback_works(self) -> None:
        def assert_immutable(fd):
            try:
                self.assertEqual(os.pread(fd,64,0),b'fixed bytes')
                with self.assertRaises(OSError):os.pwrite(fd,b'x',0)
                with self.assertRaises(OSError):os.ftruncate(fd,0)
            finally:
                os.close(fd)
        assert_immutable(verify._p001_seal_tool(b'fixed bytes'))
        # Force the libc path even when the interpreter has its own wrapper.
        with patch.dict(os.__dict__):
            os.__dict__.pop('memfd_create',None)
            assert_immutable(verify._p001_seal_tool(b'fixed bytes'))

    def test_p001_v3_source_only_and_unavailable_mode_do_not_create_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base,unavailable=True)
            evidence=base/'source-only'
            code,value=self.run_cli('--suite','ECP-P0-01','--source-manifest-version','3',
                                    '--source-root',str(source),'--evidence-root',str(evidence))
            self.assertEqual((code,value['status'],value['qualification']),(20,'INCONCLUSIVE','NOT_RUN'))
            self.assertEqual(value['source_snapshot']['directory_mode'],'UNAVAILABLE')
            self.assertTrue(value['checks'][0]['details']['leader_reaped'])
            self.assertIsNone(value['checks'][0]['details']['descendants_terminated'])
            self.assertEqual(value['denominator']['not_run'],2)
            candidate=base/'candidate';evidence2=base/'unavailable'
            code,value=self.run_cli('--suite','ECP-P0-01','--source-manifest-version','3',
                                    '--source-root',str(source),'--evidence-root',str(evidence2),
                                    '--candidate-root',str(candidate))
            self.assertEqual((code,value['status'],value['qualification']),(20,'BLOCKED','NOT_RUN'))
            self.assertEqual(value['checks'][1]['status'],'BLOCKED')
            self.assertFalse(candidate.exists())

    def test_p001_v3_source_failure_preserves_raw_stderr_and_no_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base,failing=True)
            evidence=base/'error';candidate=base/'candidate'
            code,value=self.run_cli('--suite','ECP-P0-01','--source-manifest-version','3',
                                    '--source-root',str(source),'--evidence-root',str(evidence),
                                    '--candidate-root',str(candidate))
            self.assertEqual((code,value['status'],value['qualification']),(10,'FAIL','NOT_RUN'))
            self.assertIn('synthetic source failure',(evidence/'source.stderr.log').read_text(encoding='utf-8'))
            self.assertFalse(candidate.exists())

    def test_p001_v3_missing_fd_oracle_blocks_before_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base,oracle_fd_support=False)
            evidence=base/'unbound';candidate=base/'candidate'
            code,value=self.run_cli('--suite','ECP-P0-01','--source-manifest-version','3',
                                    '--source-root',str(source),'--evidence-root',str(evidence),
                                    '--candidate-root',str(candidate))
            self.assertEqual((code,value['status']),(20,'BLOCKED'))
            self.assertIn('pinned evidence FDs',value['reason'])
            self.assertFalse(candidate.exists())

    def test_p001_v3_refuses_existing_evidence_and_source_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base)
            evidence=base/'exists';evidence.mkdir();sentinel=evidence/'sentinel';sentinel.write_text('keep')
            code,value=self.run_cli('--suite','ECP-P0-01','--source-manifest-version','3',
                                    '--source-root',str(source),'--evidence-root',str(evidence))
            self.assertEqual((code,value['status']),(20,'BLOCKED'))
            self.assertEqual(sentinel.read_text(),'keep')
            alias=base/'alias';alias.symlink_to(source,target_is_directory=True)
            code,value=self.run_cli('--suite','ECP-P0-01','--source-manifest-version','3',
                                    '--source-root',str(alias),'--evidence-root',str(base/'untouched'))
            self.assertEqual((code,value['status']),(20,'BLOCKED'))
            self.assertFalse((base/'untouched').exists())

    def test_p001_v3_rejects_manifest_fd_change_even_when_json_is_equivalent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base)
            evidence=base/'evidence';candidate=base/'candidate'
            sha=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
            args=type('Args',(),{'profile':'isolated','evidence_root':str(evidence),'source_root':str(source),
                                 'candidate_root':str(candidate),'output':None})()
            original=verify.run_p003_bounded
            def tamper(command,**kwargs):
                if '--manifest-fd' in command:
                    path=evidence/'source-snapshot.json'
                    path.write_bytes(path.read_bytes()+b' ')
                return original(command,**kwargs)
            with patch.object(verify,'run_p003_bounded',side_effect=tamper), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_source_snapshot_v3_suite(args,source,sha,verify.base_report('suite',source,sha))
            self.assertEqual((code,value['status'],value['qualification']),(10,'FAIL','NOT_RUN'))
            self.assertTrue(any('changed during observation' in c['reason'] for c in value['checks']))
            self.assertTrue(candidate.is_dir(),'published candidate is retained on evidence mutation')
            self.assertTrue((evidence/'oracle.stdout.log').exists(),'oracle raw output is preserved')

    def test_p001_v3_evidence_directory_drift_sets_failed_denominator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base)
            evidence=base/'evidence'
            sha=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
            args=type('Args',(),{'profile':'isolated','evidence_root':str(evidence),'source_root':str(source),
                                 'candidate_root':None,'output':None})()
            original=verify._p001_same_directory
            def drift(path,fd):
                return False if path == evidence else original(path,fd)
            with patch.object(verify,'_p001_same_directory',side_effect=drift), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_source_snapshot_v3_suite(args,source,sha,verify.base_report('suite',source,sha))
            self.assertEqual((code,value['status']),(10,'FAIL'))
            self.assertEqual(value['denominator']['failed'],1)
            self.assertEqual(value['denominator']['total'],4)
            self.assertTrue((evidence/'result.json').exists())

    def test_p001_v3_source_only_detects_evidence_file_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base)
            evidence=base/'evidence'
            sha=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
            args=type('Args',(),{'profile':'isolated','evidence_root':str(evidence),'source_root':str(source),
                                 'candidate_root':None,'output':None})()
            original=verify._p001_write_json
            def tamper(dirfd,name,value):
                result=original(dirfd,name,value)
                if name=='source-snapshot.json':
                    fd=os.open(name,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW,dir_fd=dirfd)
                    try:os.write(fd,b' ')
                    finally:os.close(fd)
                return result
            with patch.object(verify,'_p001_write_json',side_effect=tamper), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_source_snapshot_v3_suite(args,source,sha,verify.base_report('suite',source,sha))
            self.assertEqual((code,value['status'],value['qualification']),(10,'FAIL','NOT_RUN'))
            self.assertTrue(any(c['name']=='evidence_integrity' and c['status']=='FAIL' for c in value['checks']))

    def test_p001_v3_detects_raw_source_log_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base)
            evidence=base/'evidence'
            sha=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
            args=type('Args',(),{'profile':'isolated','evidence_root':str(evidence),'source_root':str(source),
                                 'candidate_root':None,'output':None})()
            original=verify.run_p003_bounded
            def tamper(command,**kwargs):
                result=original(command,**kwargs)
                log=evidence/'source.stderr.log'
                log.write_bytes(b'tampered')
                return result
            with patch.object(verify,'run_p003_bounded',side_effect=tamper), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_source_snapshot_v3_suite(args,source,sha,verify.base_report('suite',source,sha))
            self.assertEqual((code,value['status']),(10,'FAIL'))
            self.assertTrue(any(c['name']=='evidence_integrity' and c['status']=='FAIL' for c in value['checks']))

    def test_p001_v3_partial_capture_is_retained_and_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base);evidence=base/'evidence'
            sha=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
            args=type('Args',(),{'profile':'isolated','evidence_root':str(evidence),'source_root':str(source),
                                 'candidate_root':None,'output':None})()
            def fail_capture(command,**kwargs):
                kwargs['stdout_path'].write_bytes(b'partial raw output')
                raise OSError('synthetic capture failure')
            with patch.object(verify,'run_p003_bounded',side_effect=fail_capture), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_source_snapshot_v3_suite(args,source,sha,verify.base_report('suite',source,sha))
            self.assertEqual((code,value['status']),(20,'INCONCLUSIVE'))
            self.assertFalse(value['artifact_digests']['source.stdout.log']['capture_complete'])
            self.assertEqual(value['artifact_digests']['source.stdout.log']['state'], 'UNATTRIBUTED_RETAINED')
            self.assertNotIn(str(evidence/'source.stdout.log'), value['evidence_refs'])
            self.assertEqual(value['artifact_digests']['source.stderr.log']['state'],'NOT_CREATED')
            self.assertEqual((evidence/'source.stdout.log').read_bytes(),b'partial raw output')
            self.assertEqual(value['checks'][0]['details']['capture_stage'], 'source')
            self.assertIsNone(value['checks'][0]['details']['leader_reaped'])
            self.assertIsNone(value['checks'][0]['details']['descendants_terminated'])

    def test_p001_v3_detects_same_bytes_evidence_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base);evidence=base/'evidence'
            sha=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
            args=type('Args',(),{'profile':'isolated','evidence_root':str(evidence),'source_root':str(source),
                                 'candidate_root':None,'output':None})()
            original=verify._p001_write_json
            def replace_file(dirfd,name,value):
                written=original(dirfd,name,value)
                if name=='source-snapshot.json':
                    os.rename(name,'source-original.json',src_dir_fd=dirfd,dst_dir_fd=dirfd)
                    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dirfd)
                    try:os.write(fd,written[0])
                    finally:os.close(fd)
                return written
            with patch.object(verify,'_p001_write_json',side_effect=replace_file), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_source_snapshot_v3_suite(args,source,sha,verify.base_report('suite',source,sha))
            self.assertEqual((code,value['status']),(10,'FAIL'))
            self.assertTrue(any(c['status']=='FAIL' for c in value['checks']))
            self.assertTrue((evidence/'source-original.json').exists())

    def test_p001_v3_parent_replacement_never_redirects_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base);evidence=base/'evidence'
            parent=base/'parent';parent.mkdir();candidate=parent/'candidate';moved=base/'moved'
            sha=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
            args=type('Args',(),{'profile':'isolated','evidence_root':str(evidence),'source_root':str(source),
                                 'candidate_root':str(candidate),'output':None})()
            original=verify.run_p003_bounded
            def replace_parent(command,**kwargs):
                if 'materialization.stdout.log' in str(kwargs['stdout_path']):
                    parent.rename(moved);parent.mkdir();(parent/'foreign').write_text('preserve')
                return original(command,**kwargs)
            with patch.object(verify,'run_p003_bounded',side_effect=replace_parent), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_source_snapshot_v3_suite(args,source,sha,verify.base_report('suite',source,sha))
            self.assertEqual((code,value['status']),(10,'FAIL'))
            self.assertEqual(value['candidate_publication']['state'],'POSSIBLY_PUBLISHED_RETAINED')
            self.assertFalse(value['candidate_publication']['cleanup_attempted'])
            self.assertFalse((parent/'candidate').exists());self.assertFalse((moved/'candidate').exists())
            self.assertEqual((parent/'foreign').read_text(),'preserve')

    def test_p001_v3_corrupt_postpublication_receipt_preserves_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base);evidence=base/'evidence';candidate=base/'candidate'
            sha=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
            args=type('Args',(),{'profile':'isolated','evidence_root':str(evidence),'source_root':str(source),
                                 'candidate_root':str(candidate),'output':None})()
            original=verify.run_p003_bounded
            def corrupt(command,**kwargs):
                value=original(command,**kwargs)
                if 'materialization.stdout.log' in str(kwargs['stdout_path']):
                    value['stdout_bytes']=b'{corrupt'
                return value
            with patch.object(verify,'run_p003_bounded',side_effect=corrupt), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_source_snapshot_v3_suite(args,source,sha,verify.base_report('suite',source,sha))
            self.assertEqual((code,value['status']),(10,'FAIL'))
            self.assertEqual(value['candidate_publication']['state'],'POSSIBLY_PUBLISHED_RETAINED')
            self.assertEqual(value['candidate_publication']['candidate_root'],str(candidate))
            self.assertFalse(value['candidate_publication']['cleanup_attempted'])
            self.assertTrue((candidate/'README').is_file())

    def test_p001_v3_rejects_missing_or_invalid_candidate_digests(self) -> None:
        for target, invalid in ((2,None),(2,'z'*64),(2,'A'*64),(3,None),(3,'z'*64),(3,'0'*64)):
            with self.subTest(target=target,invalid=invalid), tempfile.TemporaryDirectory() as directory:
                base=Path(directory);source=self.make_v3_source_root(base);evidence=base/'evidence';candidate=base/'candidate'
                sha=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
                args=type('Args',(),{'profile':'isolated','evidence_root':str(evidence),'source_root':str(source),
                                     'candidate_root':str(candidate),'output':None})()
                original=verify._p001_json
                count=0
                def alter(data):
                    nonlocal count
                    value=original(data);count+=1
                    if count==target:
                        if invalid is None:value.pop('candidate_inventory_v3_sha256',None)
                        else:value['candidate_inventory_v3_sha256']=invalid
                    return value
                with patch.object(verify,'_p001_json',side_effect=alter), contextlib.redirect_stdout(io.StringIO()):
                    value,code=verify.run_source_snapshot_v3_suite(args,source,sha,verify.base_report('suite',source,sha))
                self.assertEqual((code,value['status']),(10,'FAIL'))
                self.assertEqual(value['candidate_publication']['state'],'POSSIBLY_PUBLISHED_RETAINED')
                self.assertTrue((candidate/'README').is_file())
                self.assertEqual(value['checks'][target-1]['status'],'FAIL')

    def test_p001_v3_receipt_write_error_after_publication_preserves_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base);evidence=base/'evidence';candidate=base/'candidate'
            sha=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
            args=type('Args',(),{'profile':'isolated','evidence_root':str(evidence),'source_root':str(source),
                                 'candidate_root':str(candidate),'output':None})()
            original=verify._p001_write_json
            def fail_receipt(dirfd,name,value):
                if name=='materialization.json':raise OSError('synthetic receipt write error')
                return original(dirfd,name,value)
            with patch.object(verify,'_p001_write_json',side_effect=fail_receipt), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_source_snapshot_v3_suite(args,source,sha,verify.base_report('suite',source,sha))
            self.assertEqual((code,value['status']),(10,'FAIL'))
            self.assertEqual(value['candidate_publication']['state'],'POSSIBLY_PUBLISHED_RETAINED')
            self.assertFalse(value['candidate_publication']['cleanup_attempted'])
            self.assertTrue((candidate/'README').is_file())

    def test_p001_v3_rejects_output_outside_evidence_and_symlink_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=self.make_v3_source_root(base)
            evidence=base/'evidence';output=base/'other.json'
            code,value=self.run_cli('--suite','ECP-P0-01','--source-manifest-version','3',
                                    '--source-root',str(source),'--evidence-root',str(evidence),
                                    '--output',str(output))
            self.assertEqual((code,value['status']),(20,'BLOCKED'))
            self.assertFalse(output.exists());self.assertFalse(evidence.exists())
            alias=base/'alias-parent';alias.symlink_to(base,target_is_directory=True)
            code,value=self.run_cli('--suite','ECP-P0-01','--source-manifest-version','3',
                                    '--source-root',str(source),'--evidence-root',str(alias/'evidence'))
            self.assertEqual((code,value['status']),(20,'BLOCKED'))
            self.assertFalse(evidence.exists())

    def test_p001_binds_dirty_snapshot_but_never_qualifies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            source = self.make_source_root(temp, dirty=True)
            evidence = temp / "evidence" / "run-1"
            code, value = self.run_cli("--suite", "ECP-P0-01", "--source-root", str(source),
                                       "--evidence-root", str(evidence))
            self.assertEqual(code, 20)
            self.assertEqual(value["status"], "INCONCLUSIVE")
            self.assertEqual(value["product_gate_effect"], "NONE")
            self.assertEqual(value["qualification"], "NOT_RUN")
            self.assertEqual(value["source_snapshot"]["worktree_state"], "DIRTY_UNFROZEN")
            self.assertEqual(value["denominator"], {"total": 2, "passed": 0, "failed": 0,
                "blocked": 0, "not_run": 1, "inconclusive": 1})
            self.assertTrue((evidence / "source-snapshot.json").is_file())
            self.assertEqual(value["checks"][1]["status"], "NOT_RUN")

    def test_p001_clean_snapshot_still_not_run_without_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            source = self.make_source_root(temp, dirty=False)
            evidence = temp / "evidence" / "run-2"
            code, value = self.run_cli("--suite", "ECP-P0-01", "--source-root", str(source),
                                       "--evidence-root", str(evidence))
            self.assertEqual(code, 20)
            self.assertEqual(value["status"], "INCONCLUSIVE")
            self.assertEqual(value["qualification"], "NOT_RUN")
            self.assertEqual(value["source_snapshot"]["worktree_state"], "CLEAN")
            self.assertEqual(value["denominator"]["passed"], 1)
            self.assertEqual(value["denominator"]["not_run"], 1)
            self.assertIn("pass --candidate-root", value["checks"][1]["reason"])

    def test_p001_explicit_candidate_materialization_is_bound_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            source = self.make_source_root(temp, dirty=False)
            # A minimal, independently tracked source tree plus required P0 inputs.
            for relative in ("Cargo.lock", "migrations", "crates/store/src/lib.rs",
                             "planning/tasks.json", "planning/gates.json", "console/package.json"):
                target = source / relative
                if relative.endswith("/"):
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source), "add", "Cargo.lock", "migrations",
                            "crates/store/src/lib.rs", "planning/tasks.json", "planning/gates.json",
                            "console/package.json"], check=True)
            subprocess.run(["git", "-C", str(source), "commit", "-qm", "required inputs"], check=True)
            evidence = temp / "evidence" / "p001-materialized"
            candidate = temp / "candidate"
            original_status = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
                                             check=True, capture_output=True, text=True).stdout
            code, value = self.run_cli("--suite", "ECP-P0-01", "--source-root", str(source),
                                       "--evidence-root", str(evidence), "--candidate-root", str(candidate))
            self.assertEqual(code, 0)
            self.assertEqual(value["status"], "PASS")
            self.assertEqual(value["checks"][1]["status"], "PASS")
            self.assertTrue(value["materialization"]["git_metadata_removed"])
            self.assertTrue((candidate / "Cargo.toml").is_file())
            self.assertFalse((candidate / ".git").exists())
            final_status = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
                                          check=True, capture_output=True, text=True).stdout
            self.assertEqual(final_status, original_status)

    def test_p001_refuses_to_overwrite_snapshot_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            source = self.make_source_root(temp, dirty=False)
            evidence = temp / "evidence" / "run-3"
            evidence.mkdir(parents=True)
            existing = evidence / "source-snapshot.json"
            existing.write_text('{"immutable":true}\n', encoding="utf-8")
            code, value = self.run_cli("--suite", "ECP-P0-01", "--source-root", str(source),
                                       "--evidence-root", str(evidence))
            self.assertEqual(code, 20)
            self.assertEqual(value["status"], "BLOCKED")
            self.assertEqual(existing.read_text(encoding="utf-8"), '{"immutable":true}\n')

    def test_p001_rejects_evidence_or_output_inside_source_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            source = self.make_source_root(temp, dirty=False)
            before = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
                                    check=True, capture_output=True, text=True).stdout
            unsafe_evidence = source / "evidence"
            code, value = self.run_cli("--suite", "ECP-P0-01", "--source-root", str(source),
                                       "--evidence-root", str(unsafe_evidence))
            self.assertEqual(code, 20)
            self.assertEqual(value["status"], "BLOCKED")
            self.assertEqual(value["checks"][0]["name"], "evidence_path_safety")
            self.assertFalse(unsafe_evidence.exists())

            safe_evidence = temp / "external-evidence"
            unsafe_output = source / "report.json"
            code, value = self.run_cli("--suite", "ECP-P0-01", "--source-root", str(source),
                                       "--evidence-root", str(safe_evidence), "--output", str(unsafe_output))
            self.assertEqual(code, 20)
            self.assertEqual(value["status"], "BLOCKED")
            self.assertEqual(value["checks"][0]["name"], "evidence_path_safety")
            self.assertFalse(unsafe_output.exists())
            after = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
                                   check=True, capture_output=True, text=True).stdout
            self.assertEqual(after, before)

    def test_p001_requires_explicit_evidence_root(self) -> None:
        code, value = self.run_cli("--suite", "ECP-P0-01", "--source-root", str(ROOT))
        self.assertEqual(code, 20)
        self.assertEqual(value["status"], "NOT_RUN")
        self.assertFalse(value["checks"][0]["details"]["source_snapshot_invoked"])

    def test_database_suite_uses_guarded_runner_without_implicit_connection(self) -> None:
        env = {key: value for key, value in os.environ.items() if key not in {"ECP_DATABASE_DISPOSABLE", "ECP_DATABASE_URL"}}
        completed = subprocess.run(
            [str(ENTRY), "--suite", "ECP-P0-02", "--profile", "isolated"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertTrue(completed.stdout, completed.stderr)
        value = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 20)
        self.assertEqual(value["status"], "BLOCKED")
        self.assertIsNone(value["database_connections_attempted"])
        self.assertEqual(value["checks"][0]["details"]["explicit_disposable_guard"], False)

    def test_p002_public_launcher_ignores_untrusted_path_and_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix='p002-entry-hooks-') as directory:
            root=Path(directory); fake=root/'bin';fake.mkdir();marker=root/'invoked'
            for name in ('git','uname','python3','bash'):
                path=fake/name;path.write_text('#!/bin/sh\nprintf invoked >> "'+str(marker)+'"\nexit 1\n');path.chmod(0o755)
            (fake/'sitecustomize.py').write_text('open('+repr(str(marker))+',"a").write("invoked")\n')
            hook=root/'bash-env';hook.write_text('printf invoked >> "'+str(marker)+'"\n')
            env={k:v for k,v in os.environ.items() if not k.startswith('ECP_DATABASE_')}
            env.update(PATH=str(fake)+':/usr/bin:/bin',BASH_ENV=str(hook),PYTHONPATH=str(fake))
            result=subprocess.run([str(ENTRY),'suite','--suite','ECP-P0-02','--profile','isolated',
                                   '--evidence-root',str(root/'evidence')],cwd=ROOT,env=env,
                                  capture_output=True,text=True,timeout=20)
            value=json.loads(result.stdout)
            self.assertEqual((result.returncode,value['status']),(20,'BLOCKED'),result.stderr)
            self.assertIsNone(value['source_sha'])
            self.assertIsNone(value['database_connections_attempted'])
            self.assertFalse(marker.exists())

    def test_p002_v3_rejection_never_writes_output_or_runs_git(self) -> None:
        with tempfile.TemporaryDirectory(prefix='p002-v3-output-') as directory:
            root=Path(directory);fake=root/'bin';fake.mkdir();marker=root/'invoked'
            for name in ('git','uname','python3'):
                path=fake/name;path.write_text('#!/bin/sh\nprintf invoked >> "'+str(marker)+'"\nexit 1\n');path.chmod(0o755)
            victim=root/'victim';victim.write_text('retain');link=root/'link';link.symlink_to(victim)
            env=dict(os.environ,PATH=str(fake)+':/usr/bin:/bin')
            for output in (victim,link):
                evidence=root/('evidence-'+output.name)
                result=subprocess.run([str(ENTRY),'suite','--suite','ECP-P0-02','--source-manifest-version','3',
                                       '--evidence-root',str(evidence),'--output',str(output)],cwd=ROOT,env=env,
                                      capture_output=True,text=True,timeout=20)
                value=json.loads(result.stdout)
                self.assertEqual((result.returncode,value['status']),(20,'BLOCKED'),result.stderr)
                self.assertEqual(value['database_connections_attempted'],0)
                self.assertIsNone(value['source_sha'])
                self.assertEqual(victim.read_text(),'retain')
                self.assertTrue(link.is_symlink());self.assertFalse(evidence.exists())
                self.assertFalse(marker.exists())

    def test_p002_identity_only_preserves_unrun_migrations_and_history(self) -> None:
        payload = {"status":"PASS", "reason":"identity only", "connections_attempted":1,
                   "store_migration_test":"NOT_RUN", "database":"ecp_disposable_test", "user":"fixture", "server_version_num":"160000"}
        value, code = self._fake_p002_result(payload, 0)
        self.assertEqual((code, value["status"], value["qualification"]), (20,"INCONCLUSIVE","NOT_RUN"))
        self.assertEqual(value["denominator"], {"total":3,"passed":0,"failed":0,"blocked":0,
                                                "not_run":2,"inconclusive":1})
        self.assertEqual([check["status"] for check in value["checks"]], ["INCONCLUSIVE","NOT_RUN","NOT_RUN"])
        self.assertIsNone(value['database_connections_attempted'])
        self.assertEqual(value['checks'][0]['details']['child_reported_connections_attempted'],1)
        self.assertEqual(value['checks'][0]['details']['child_connection_claim_authority'],'UNVERIFIED')

    def test_p002_inconclusive_child_never_promotes_identity(self) -> None:
        payload = {'status':'INCONCLUSIVE','reason':'fixture','connections_attempted':0,
                   'identity_authority':'UNVERIFIED','store_migration_test':'NOT_RUN'}
        value, code = self._fake_p002_result(payload,20)
        self.assertEqual((code,value['status'],value['checks'][0]['status']), (20,'INCONCLUSIVE','INCONCLUSIVE'))
        self.assertIsNone(value['database_connections_attempted'])
        self.assertEqual(value['checks'][0]['details']['child_reported_connections_attempted'],0)

    def test_p002_blocked_child_with_positive_connection_claim_is_rejected(self) -> None:
        value,code=self._fake_p002_result({'status':'BLOCKED','connections_attempted':1},20)
        self.assertEqual((code,value['status']),(10,'FAIL'))
        self.assertIsNone(value['database_connections_attempted'])

    def test_p002_blocked_runner_cannot_certify_zero_connections(self) -> None:
        # A fake local listener is deliberately not PostgreSQL. The child
        # connects to it and lies that it made no connections.
        import socket
        with tempfile.TemporaryDirectory(prefix='p002-conn-') as directory:
            base=Path(directory); source=base/'source'; runner=source/'ops/ecp/test_database.sh'
            runner.parent.mkdir(parents=True); sockpath=base/'socket'
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.addCleanup(listener.close); listener.bind(str(sockpath)); listener.listen(1); listener.settimeout(5)
            runner.write_text('#!/usr/bin/python3\nimport os,socket,sys\n'
                's=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect('+repr(str(sockpath))+');s.close()\n'
                'b=b"{\\"status\\":\\"BLOCKED\\",\\"connections_attempted\\":0}\\n"\n'
                'os.write(int(sys.argv[sys.argv.index("--output-fd")+1]),b);os.write(1,b);sys.exit(20)\n')
            runner.chmod(0o755)
            args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':None,'evidence_root':str(base/'evidence')})()
            with contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            connection,_=listener.accept();connection.close()
            self.assertEqual((code,value['status']),(20,'BLOCKED'))
            self.assertIsNone(value['database_connections_attempted'])
            self.assertEqual(value['checks'][0]['details']['child_reported_connections_attempted'],0)

    def test_p002_store_request_never_starts_runner_without_controlled_executor(self) -> None:
        import contextlib,io
        with tempfile.TemporaryDirectory(prefix='p002-store-request-') as directory:
            source=Path(directory);runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
            marker=source/'unexpected-execution';runner.write_text('#!/bin/sh\ntouch '+str(marker)+'\n');runner.chmod(0o755)
            args=type('Args',(),{'run_store_test':True,'profile':'isolated','output':None})()
            with contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            self.assertEqual((code,value['status'],value['database_connections_attempted']),(20,'BLOCKED',0))
            self.assertEqual([c['status'] for c in value['checks']],['NOT_RUN','BLOCKED','NOT_RUN'])
            self.assertFalse(marker.exists())

    def test_p002_never_promotes_invalid_or_contradictory_child_result(self) -> None:
        base = {"status":"PASS", "reason":"identity only", "connections_attempted":1,
                "store_migration_test":"NOT_RUN", "database":"ecp_disposable_test", "user":"fixture", "server_version_num":"160000"}
        variants = [
            (base, 10, True),
            ({k:v for k,v in base.items() if k != "connections_attempted"}, 0, True),
            ({**base,"connections_attempted":True}, 0, True),
            ({**base,"store_migration_test":"FAIL"}, 0, True),
            ({**base,"store_migration_test":"PASS"}, 0, True),
            ({k:v for k,v in base.items() if k != 'database'}, 0, True),
            ({**base,'database':'ecp_disposable_other'}, 0, True),
            ({**base,'user':'other'}, 0, True),
            ({**base,'server_version_num':'invalid'}, 0, True),
            (base, 0, False),
        ]
        for payload, exit_code, valid_receipt in variants:
            with self.subTest(payload=payload,exit_code=exit_code,valid_receipt=valid_receipt):
                value, code = self._fake_p002_result(payload, exit_code, valid_receipt)
                self.assertEqual((code,value["status"],value["qualification"]),(10,"FAIL","NOT_RUN"))
                self.assertNotEqual(value["denominator"]["passed"],value["denominator"]["total"])

    def test_p002_output_rejects_existing_source_and_symlink_before_running_child(self) -> None:
        import contextlib,io
        with tempfile.TemporaryDirectory(prefix='p002-output-') as directory:
            base=Path(directory);source=base/'source';runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
            marker=base/'child-ran';runner.write_text('#!/bin/sh\ntouch '+str(marker)+'\n');runner.chmod(0o755)
            existing=base/'existing.json';existing.write_text('original evidence')
            link=base/'alias';link.symlink_to(base,target_is_directory=True)
            for output in (existing,source/'unsafe.json',link/'receipt.json'):
                with self.subTest(output=output):
                    args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':str(output)})()
                    with contextlib.redirect_stdout(io.StringIO()):
                        value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
                    self.assertEqual((code,value['status']),(20,'BLOCKED'))
                    self.assertFalse(marker.exists())
                    self.assertEqual(existing.read_text(),'original evidence')
                    if output!=existing:self.assertFalse(output.exists())

    def test_p002_output_parent_replacement_never_writes_into_replacement(self) -> None:
        import contextlib,io
        with tempfile.TemporaryDirectory(prefix='p002-output-race-') as directory:
            base=Path(directory);source=base/'source';runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
            parent=base/'output';parent.mkdir();old=base/'old'
            runner.write_text('#!/usr/bin/python3\nimport json,os,pathlib,sys\n'
              'p=pathlib.Path('+repr(str(parent))+');p.rename(p.with_name("old"));p.mkdir();'
              '(p/"sentinel").write_text("preserved");'
              'v=json.dumps({"status":"BLOCKED","reason":"fixture","connections_attempted":0});'
              'os.write(int(sys.argv[sys.argv.index("--output-fd")+1]),(v+"\\n").encode());print(v);sys.exit(20)\n')
            runner.chmod(0o755)
            args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':str(parent/'evidence'/'result.json'),'evidence_root':str(parent/'evidence')})()
            with contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            self.assertEqual((code,value['status']),(10,'FAIL'))
            self.assertEqual((parent/'sentinel').read_text(),'preserved')
            self.assertFalse((parent/'evidence').exists());self.assertTrue((old/'evidence').exists())

    def test_p002_output_is_exclusive_and_matches_returned_result(self) -> None:
        import contextlib,io
        with tempfile.TemporaryDirectory(prefix='p002-output-success-') as directory:
            base=Path(directory);source=base/'source';runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
            evidence=base/'evidence'; output=evidence/'result.json'
            runner.write_text('#!/usr/bin/python3\nimport json,os,pathlib,sys\n'
              'v=json.dumps({"status":"BLOCKED","reason":"fixture","connections_attempted":0});'
              'os.write(int(sys.argv[sys.argv.index("--output-fd")+1]),(v+"\\n").encode());print(v);sys.exit(20)\n')
            runner.chmod(0o755)
            args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':str(output),'evidence_root':str(evidence)})()
            with contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            self.assertEqual((code,value['status']),(20,'BLOCKED'))
            persisted=json.loads(output.read_text())
            self.assertEqual((persisted['status'],persisted['result_authority']),('NOT_RUN','PROVISIONAL_ONLY'))
            self.assertEqual(value['evidence_integrity_at_return'],'VERIFIED_NONATOMIC')
            self.assertEqual(output.stat().st_mode & 0o777,0o600)
            self.assertIn(str(output),value['evidence_refs'])

    def _fake_p002_result(self, payload: dict, exit_code: int, valid_receipt: bool = True) -> tuple[dict, int]:
        # Controlled child process only; never connects to PostgreSQL or runs Cargo.
        import contextlib, io
        with tempfile.TemporaryDirectory(prefix="p002-receipt-fixture-") as directory:
            source=Path(directory);runner=source/"ops/ecp/test_database.sh";runner.parent.mkdir(parents=True)
            output=json.dumps(payload,separators=(',',':'))
            script=("#!/usr/bin/python3\nimport os,sys\nvalue="+repr(output)+"\n"
                    + ("os.write(int(sys.argv[sys.argv.index('--output-fd')+1]),(value+'\\n').encode())\n" if valid_receipt else "")
                    + "print(value)\nsys.exit("+str(exit_code)+")\n")
            runner.write_text(script,encoding='utf-8');runner.chmod(0o755)
            args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':None})()
            from unittest.mock import patch
            with patch.dict(os.environ,{'ECP_DATABASE_URL':'postgresql://fixture@localhost:5432/ecp_disposable_test?host=%2Ftmp%2Ffixture',
                                       'ECP_DATABASE_DISPOSABLE':'1','ECP_DATABASE_EXPECTED_DATA_DIR':'/tmp/fixture/data'}), contextlib.redirect_stdout(io.StringIO()):
                return verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))

    def test_p002_exact_url_echo_is_redacted_before_evidence_and_env_is_restricted(self) -> None:
        import contextlib, io
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='p002-redaction-') as directory:
            base=Path(directory); source=base/'source'; runner=source/'ops/ecp/test_database.sh'; runner.parent.mkdir(parents=True)
            evidence=base/'evidence'
            runner.write_text('#!/usr/bin/python3\nimport os,sys\n'
                'u=os.environ["ECP_DATABASE_URL"]; b=(u+"\\n").encode();'
                'assert all(k not in os.environ for k in ("OPENAI_API_KEY","LD_PRELOAD","PYTHONPATH","BASH_ENV","PGHOST"));'
                'os.write(int(sys.argv[sys.argv.index("--output-fd")+1]),b);os.write(1,b);os.write(2,b)\n')
            runner.chmod(0o755)
            synthetic='postgresql://fixture@localhost:5432/ecp_disposable_test?host=%2Ftmp%2Ffixture'
            args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':str(evidence/'result.json'),'evidence_root':str(evidence)})()
            environment={'ECP_DATABASE_URL':synthetic,'ECP_DATABASE_DISPOSABLE':'1','OPENAI_API_KEY':'fixture',
                         'LD_PRELOAD':'fixture','PYTHONPATH':'fixture','BASH_ENV':'fixture','PGHOST':'fixture'}
            captured=io.StringIO()
            with patch.dict(os.environ,environment), contextlib.redirect_stdout(captured):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            self.assertEqual((code,value['status']),(10,'FAIL'))
            details=value['checks'][0]['details']
            self.assertTrue(details['redaction_detected'])
            self.assertFalse(details['raw_logs_complete_for_acceptance'])
            self.assertEqual(details['stdout.log_original_sha256'],verify.sha256_bytes((synthetic+'\n').encode()))
            self.assertEqual(evidence.stat().st_mode & 0o777,0o700)
            self.assertNotIn(synthetic,captured.getvalue())
            for file in evidence.iterdir():
                self.assertNotIn(synthetic.encode(),file.read_bytes())
            persisted=json.loads((evidence/'result.json').read_text())
            self.assertEqual((persisted['status'],persisted['result_authority']),('NOT_RUN','PROVISIONAL_ONLY'))
            self.assertEqual(value['evidence_integrity_at_return'],'VERIFIED_NONATOMIC')
            self.assertEqual(json.loads((evidence/'manifest.json').read_text())['stored_sha256']['stderr.log'],
                             verify.sha256_bytes((evidence/'stderr.log').read_bytes()))

    def test_p002_password_url_and_evidence_collisions_block_before_child(self) -> None:
        import contextlib, io
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='p002-preflight-') as directory:
            base=Path(directory); source=base/'source'; runner=source/'ops/ecp/test_database.sh'; runner.parent.mkdir(parents=True)
            marker=base/'child'; runner.write_text('#!/bin/sh\ntouch '+str(marker)+'\n'); runner.chmod(0o755)
            existing=base/'existing'; existing.mkdir(); (existing/'sentinel').write_text('untouched')
            alias=base/'alias'; alias.symlink_to(base,target_is_directory=True)
            for i,evidence in enumerate((existing,source/'evidence',alias/'evidence')):
                args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':None,'evidence_root':str(evidence)})()
                with contextlib.redirect_stdout(io.StringIO()):
                    value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
                self.assertEqual((code,value['status']),(20,'BLOCKED'))
                self.assertFalse(marker.exists())
            self.assertEqual((existing/'sentinel').read_text(),'untouched')
            args.evidence_root=str(base/'secret-rejected')
            with patch.dict(os.environ,{'ECP_DATABASE_URL':'postgresql://fixture:password@localhost:5432/ecp_disposable_test?host=%2Ftmp%2Ffixture'}), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            self.assertEqual((code,value['status']),(20,'BLOCKED'))
            self.assertFalse(marker.exists())
            self.assertNotIn('password',json.dumps(value))

    def test_p002_evidence_parent_replacement_retains_and_never_overwrites(self) -> None:
        import contextlib, io
        with tempfile.TemporaryDirectory(prefix='p002-evidence-race-') as directory:
            base=Path(directory);source=base/'source';runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
            parent=base/'parent';parent.mkdir();evidence=parent/'evidence'
            runner.write_text('#!/usr/bin/python3\nimport os,pathlib,sys\n'
                'p=pathlib.Path('+repr(str(parent))+');p.rename(p.with_name("old"));p.mkdir();(p/"sentinel").write_text("preserved");'
                'b=b"{\\"status\\":\\"BLOCKED\\",\\"connections_attempted\\":0}\\n";'
                'os.write(int(sys.argv[sys.argv.index("--output-fd")+1]),b);os.write(1,b);sys.exit(20)\n')
            runner.chmod(0o755)
            args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':None,'evidence_root':str(evidence)})()
            with contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            self.assertEqual((code,value['status']),(10,'FAIL'))
            self.assertEqual((parent/'sentinel').read_text(),'preserved')
            self.assertTrue((base/'old'/'evidence').is_dir())
            self.assertFalse(evidence.exists())

    def test_p002_mountinfo_alias_and_changed_runner_block(self) -> None:
        import contextlib, io
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='p002-binding-') as directory:
            base=Path(directory);source=base/'source';runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
            runner.write_text('#!/bin/sh\nexit 20\n');runner.chmod(0o755)
            alias=base/'alias';alias.mkdir();marker=base/'malicious'
            table=(f'41 1 0:1 / / rw - ext4 /dev/a rw\n'
                   f'42 41 0:2 /tree {source} rw - ext4 /dev/b rw\n'
                   f'43 41 0:2 /tree/ops {alias} rw - ext4 /dev/b rw\n')
            read_text=Path.read_text
            def fake_read(path,*args,**kwargs):
                return table if str(path)=='/proc/self/mountinfo' else read_text(path,*args,**kwargs)
            args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':None,'evidence_root':str(alias/'evidence')})()
            with patch.object(Path,'read_text',fake_read), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            self.assertEqual((code,value['status']),(20,'BLOCKED'));self.assertFalse((alias/'evidence').exists())
            runner.write_text('#!/usr/bin/python3\nimport os,sys\nb=b"{\\"status\\":\\"BLOCKED\\",\\"connections_attempted\\":0}\\n";'
                              'os.write(int(sys.argv[sys.argv.index("--output-fd")+1]),b);os.write(1,b);sys.exit(20)\n')
            args.evidence_root=str(base/'safe-evidence')
            popen=verify.subprocess.Popen
            def replace_runner(command,*a,**kw):
                runner.rename(runner.with_name('runner-original'))
                runner.write_text('#!/bin/sh\ntouch '+str(marker)+'\n');runner.chmod(0o755)
                return popen(command,*a,**kw)
            with patch.object(verify.subprocess,'Popen',side_effect=replace_runner), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            self.assertEqual((code,value['status']),(10,'FAIL'))
            self.assertFalse(marker.exists(),'replacement runner must never execute')
            self.assertEqual((base/'safe-evidence'/'stdout.log').read_text(),'{"status":"BLOCKED","connections_attempted":0}\n')

    def test_p002_changed_evidence_detected_before_result(self) -> None:
        import contextlib, io
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='p002-evidence-change-') as directory:
            base=Path(directory);source=base/'source';runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
            runner.write_text('#!/usr/bin/python3\nimport os,sys\nb=b"{\\"status\\":\\"BLOCKED\\",\\"connections_attempted\\":0}\\n";'
                              'os.write(int(sys.argv[sys.argv.index("--output-fd")+1]),b);os.write(1,b);sys.exit(20)\n')
            runner.chmod(0o755); evidence=base/'evidence'; real_fsync=os.fsync; changed=[False]
            def tamper(fd):
                real_fsync(fd)
                if not changed[0] and (evidence/'stderr.log').exists() and (evidence/'stdout.log').exists():
                    (evidence/'stdout.log').write_bytes(b'tampered');changed[0]=True
            args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':None,'evidence_root':str(evidence)})()
            with patch.object(verify.os,'fsync',side_effect=tamper), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            self.assertTrue(changed[0]);self.assertEqual((code,value['status']),(10,'FAIL'))
            self.assertFalse((evidence/'result.json').exists())
            self.assertEqual((evidence/'stdout.log').read_bytes(),b'tampered')

    def test_p002_runner_seal_failure_blocks_before_child(self) -> None:
        import contextlib, io
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='p002-seal-unavailable-') as directory:
            base=Path(directory);source=base/'source';runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
            marker=base/'child';runner.write_text('#!/bin/sh\ntouch '+str(marker)+'\n');runner.chmod(0o755)
            args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':None,'evidence_root':str(base/'evidence')})()
            with patch('fcntl.fcntl',side_effect=OSError('injected sealing failure')), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            self.assertEqual((code,value['status']),(20,'BLOCKED'));self.assertFalse(marker.exists())


    def test_p002_timeout_signals_group_before_reaping_exited_leader(self) -> None:
        import contextlib, io, time
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='p002-dead-leader-') as directory:
            base=Path(directory);source=base/'source';runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
            marker=base/'child-pid'
            runner.write_text('#!/usr/bin/python3\nimport os,pathlib,time\np=os.fork()\n'
                'if p==0:\n pathlib.Path('+repr(str(marker))+').write_text(str(os.getpid()))\n time.sleep(8)\n os._exit(0)\n'
                'while not pathlib.Path('+repr(str(marker))+').exists(): time.sleep(.01)\nos._exit(0)\n')
            runner.chmod(0o755)
            args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':None,'evidence_root':str(base/'evidence')})()
            sentinel=subprocess.Popen(['/bin/sleep','8'],start_new_session=True)
            try:
                with patch.object(verify,'bounded_child_timeout',return_value=.4), contextlib.redirect_stdout(io.StringIO()):
                    value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
                details=value['checks'][0]['details']
                self.assertEqual((code,value['status']),(10,'FAIL'))
                self.assertEqual(details['group_signal'],'SIGKILL_SENT')
                self.assertTrue(details['leader_reaped']);self.assertIsNone(details['descendants_terminated'])
                self.assertIsNone(sentinel.poll())
                child=int(marker.read_text());state_path=Path('/proc')/str(child)/'stat'
                deadline=time.monotonic()+2
                while state_path.exists() and time.monotonic()<deadline:
                    try:state=state_path.read_text().split(') ',1)[1][0]
                    except FileNotFoundError:break
                    if state=='Z':break
                    time.sleep(.02)
                else:
                    if state_path.exists():self.fail('same-group descendant still running after SIGKILL')
            finally:
                sentinel.terminate();sentinel.wait(timeout=3)

    def test_p002_persisted_result_remains_provisional_when_postwrite_check_fails(self) -> None:
        import contextlib, io
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='p002-postwrite-') as directory:
            base=Path(directory);source=base/'source';runner=source/'ops/ecp/test_database.sh';runner.parent.mkdir(parents=True)
            runner.write_text('#!/usr/bin/python3\nimport os,sys\nb=b"{\\"status\\":\\"BLOCKED\\",\\"connections_attempted\\":0}\\n";'
                              'os.write(int(sys.argv[sys.argv.index("--output-fd")+1]),b);os.write(1,b);sys.exit(20)\n')
            runner.chmod(0o755);evidence=base/'evidence';real_fsync=os.fsync;changed=[False]
            def tamper(fd):
                real_fsync(fd)
                if not changed[0] and (evidence/'result.json').exists():
                    (evidence/'stdout.log').write_bytes(b'tampered');changed[0]=True
            args=type('Args',(),{'run_store_test':False,'profile':'isolated','output':None,'evidence_root':str(evidence)})()
            with patch.object(verify.os,'fsync',side_effect=tamper), contextlib.redirect_stdout(io.StringIO()):
                value,code=verify.run_database_suite(args,source,'a'*40,verify.base_report('suite',source,'a'*40))
            self.assertTrue(changed[0]);self.assertEqual((code,value['status']),(10,'FAIL'))
            self.assertEqual(value['evidence_integrity_at_return'],'FAILED')
            persisted=json.loads((evidence/'result.json').read_text())
            self.assertEqual((persisted['status'],persisted['result_authority'],persisted['qualification']),
                             ('NOT_RUN','PROVISIONAL_ONLY','NOT_RUN'))

    def test_report_rejects_mismatched_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "evidence.json"
            input_path.write_text(json.dumps({"status": "PASS", "source_sha": "a" * 40}), encoding="utf-8")
            code, value = self.run_cli("report", "--input", str(input_path), "--source-sha", "b" * 40)
            self.assertEqual(code, 10)
            self.assertEqual(value["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()

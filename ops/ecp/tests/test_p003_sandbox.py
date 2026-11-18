from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'ops/ecp'))
import p003_sandbox as sandbox


@unittest.skip('Historical execution checks disabled: P003 observation is BLOCKED; skip is not success')
class P003SandboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='p003-sandbox-test-')
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        for name in ('ops/ecp/verify.py', 'ops/ecp/verify', 'ops/ecp/source_snapshot.py', 'ops/ecp/tests/test_p003_contract.py'):
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        self.registry = self.base / 'registry.json'
        self.registry.write_text(json.dumps({'suites': [{'suite_id': 'ECP-P0-03',
            'implementation_entrypoint': 'control/ops/ecp/verify', 'offline_workload': sandbox.WORKLOAD}]}))
        self.source_fd = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        self.registry_fd = os.open(self.registry, os.O_RDONLY)
        st = os.fstat(self.source_fd)
        self.identity = (st.st_dev, st.st_ino)
        self.digest = hashlib.sha256(self.registry.read_bytes()).hexdigest()

    def tearDown(self):
        os.close(self.registry_fd)
        os.close(self.source_fd)
        self.temp.cleanup()

    def observe(self, **overrides):
        args = {'source_identity': self.identity, 'registry_sha256': self.digest, 'source_preverified': True}
        args.update(overrides)
        return sandbox.observe(self.source_fd, self.registry_fd, **args)

    def test_bad_identity_and_registry_digest_block_without_launch(self):
        for kwargs in ({'source_identity': (0, 0)}, {'registry_sha256': '0' * 64}):
            with self.subTest(kwargs=kwargs), patch.object(sandbox, '_bounded') as launch:
                result = self.observe(**kwargs)
                self.assertEqual(result['status'], 'BLOCKED')
                self.assertFalse(result['workload_invoked'])
                launch.assert_not_called()

    def test_missing_dependencies_and_invalid_descriptors_block(self):
        with patch.object(sandbox, '_filter', side_effect=ValueError('seccomp unavailable')):
            self.assertEqual(self.observe()['status'], 'BLOCKED')
        with patch.object(sandbox.os.path, 'isfile', return_value=False):
            self.assertEqual(self.observe()['status'], 'BLOCKED')
        result = sandbox.observe(-1, self.registry_fd, source_identity=self.identity, registry_sha256=self.digest, source_preverified=True)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertFalse(result['workload_invoked'])

    def test_preflight_failure_never_invokes_workload(self):
        failed = {'exit_code': 1, 'capture_complete': True, 'termination_reason': None,
                  'stdout_bytes': b'', 'stderr_bytes': b'preflight failed', 'stdout_sha256': '',
                  'stderr_sha256': '', 'descendants_terminated': None, 'leader_reaped': True, 'group_signal': 'NOT_SENT'}
        with patch.object(sandbox, '_bounded', return_value=failed):
            result = self.observe()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertFalse(result['workload_invoked'])
        self.assertEqual(result['stderr_bytes'], b'preflight failed')

    def test_preflight_marker_does_not_prove_execution_and_truncation_is_inconclusive(self):
        proof = {'source_fd_leaked': False, 'registry_fd_leaked': False,
                 'socket_fd_leaked': False, 'seccomp_native_and_compat_checked': True}
        marker = b'ECP_P003_PREFLIGHT ' + json.dumps(proof, sort_keys=True).encode() + b'\n'
        for reason in ('timeout', 'log_limit_exceeded', 'capture_error:OSError'):
            raw = {'exit_code': -9, 'capture_complete': False, 'termination_reason': reason,
                   'stdout_bytes': marker, 'stderr_bytes': b'partial', 'stdout_sha256': '',
                   'stderr_sha256': '', 'descendants_terminated': None,
                   'leader_reaped': True, 'group_signal': 'SENT'}
            with self.subTest(reason=reason), patch.object(sandbox, '_bounded', return_value=raw):
                result = self.observe()
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertTrue(result['preflight_completed'])
            self.assertIsNone(result['workload_invoked'])
            self.assertEqual(result['stderr_bytes'], b'partial')
        raw.update(exit_code=1, capture_complete=True, termination_reason=None, group_signal='NOT_SENT')
        with patch.object(sandbox, '_bounded', return_value=raw):
            result = self.observe()
        self.assertEqual(result['status'], 'FAIL')
        self.assertIsNone(result['workload_invoked'])

    def test_bad_registry_json_blocks(self):
        data = b'{"suites":[],"suites":[]}'
        self.registry.write_bytes(data)
        result = self.observe(registry_sha256=hashlib.sha256(data).hexdigest())
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertIn('duplicate registry key', result['reason'])

    def test_duplicate_registry_entry_and_writable_fd_are_rejected(self):
        value = json.loads(self.registry.read_text())
        value['suites'].append(value['suites'][0])
        self.registry.write_text(json.dumps(value))
        digest = hashlib.sha256(self.registry.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            sandbox._registry(self.registry_fd, digest)
        writable = os.open(self.registry, os.O_RDWR)
        try:
            with self.assertRaisesRegex(ValueError, 'read-only'):
                sandbox._registry(writable, digest)
        finally:
            os.close(writable)

    def test_filter_and_registry_are_sealed(self):
        fd = sandbox._sealed(b'fixed', 'test')
        try:
            with self.assertRaises(OSError): os.pwrite(fd, b'x', 0)
            with self.assertRaises(OSError): os.ftruncate(fd, 0)
        finally:
            os.close(fd)

    def test_capture_setup_exception_kills_and_reaps_own_group(self):
        with patch.object(sandbox.selectors, 'DefaultSelector', side_effect=OSError('injected')):
            result = sandbox._bounded(['/usr/bin/python3', '-c', 'import time;time.sleep(30)'], (), 5, 1024)
        self.assertEqual(result['termination_reason'], 'capture_error:OSError')
        self.assertTrue(result['leader_reaped'])
        self.assertIn(result['group_signal'], ('SENT', 'NO_SUCH_GROUP'))
        self.assertFalse(result['capture_complete'])

    def test_unknown_termination_remains_inconclusive(self):
        class Child:
            pid = 12345
            stdout = io.BytesIO()
            stderr = io.BytesIO()
            def wait(self, timeout): raise subprocess.TimeoutExpired('test', timeout)
        with patch.object(sandbox.subprocess, 'Popen', return_value=Child()), \
             patch.object(sandbox.selectors, 'DefaultSelector', side_effect=OSError('injected')), \
             patch.object(sandbox.os, 'killpg', side_effect=OSError('injected')):
            raw = sandbox._bounded(['unused'], (), 5, 1024)
        self.assertFalse(raw['leader_reaped'])
        self.assertEqual(raw['group_signal'], 'UNKNOWN')
        with patch.object(sandbox, '_bounded', return_value=raw):
            result = self.observe()
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        self.assertIsNone(result['workload_invoked'])
        self.assertEqual(result['product_gate_effect'], 'NONE')

    def test_missing_trusted_source_assertion_blocks(self):
        with patch.object(sandbox, '_bounded') as launch:
            result = self.observe(source_preverified=False)
        self.assertEqual(result['status'], 'BLOCKED')
        launch.assert_not_called()

    def test_log_limit_is_bounded_and_preserves_prefix(self):
        run = sandbox._bounded(['/usr/bin/python3', '-c', "import os;os.write(1,b'x'*5000)"], (), 5, 1024)
        self.assertEqual(run['termination_reason'], 'log_limit_exceeded')
        self.assertEqual(run['stdout_bytes'], b'x' * 1024)
        self.assertFalse(run['capture_complete'])

    def test_real_workload_under_sandbox(self):
        result = self.observe()
        if result['status'] == 'BLOCKED' and not result['workload_invoked']:
            self.skipTest('host sandbox unavailable: ' + result.get('reason', '') +
                          result['stderr_bytes'].decode('utf-8', 'replace')[:300])
        self.assertEqual(result['status'], 'INCONCLUSIVE', result['stderr_bytes'])
        self.assertTrue(result['preflight_completed'])
        self.assertIsNone(result['workload_invoked'])
        self.assertEqual(result['qualification'], 'NOT_RUN')
        self.assertEqual(result['product_gate_effect'], 'NONE')
        self.assertTrue(result['capture_complete'])
        self.assertEqual(result['exit_code'], 0)
        self.assertIn(b'Ran 10 tests', result['stderr_bytes'])
        self.assertTrue(result['stderr_bytes'].rstrip().endswith(b'OK'))
        self.assertEqual(result['preflight'], {'source_fd_leaked': False, 'registry_fd_leaked': False,
            'socket_fd_leaked': False, 'seccomp_native_and_compat_checked': True})

    def test_same_host_unix_socket_negative_control(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(self.base / 'host.sock')); sock.listen(2)
        fd = None
        try:
            try:
                fd, _, _ = sandbox._filter()
                common = sandbox._base() + ['--ro-bind', str(self.base), '/tmp/probe',
                          '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin']
                code = ("import errno,json,socket\ntry:\n s=socket.socket(socket.AF_UNIX);"
                        "s.connect('/tmp/probe/host.sock');print(json.dumps({'connected':True}))\n"
                        "except OSError as e:print(json.dumps({'errno':e.errno}))")
                command = ['--', '/usr/bin/python3', '-c', code]
                control = sandbox._bounded(common + command, (), 15, 4096)
                filtered = sandbox._bounded(common + ['--seccomp', str(fd)] + command, (fd,), 15, 4096)
                if control['exit_code'] != 0 or filtered['exit_code'] != 0:
                    self.skipTest('host bubblewrap/seccomp unavailable: ' +
                                  (control['stderr_bytes'] + filtered['stderr_bytes']).decode('utf-8', 'replace')[:300])
            except (OSError, ValueError) as exc:
                self.skipTest('host bubblewrap/seccomp unavailable: ' + str(exc))
            self.assertEqual(json.loads(control['stdout_bytes']), {'connected': True})
            self.assertEqual(json.loads(filtered['stdout_bytes']), {'errno': errno.EPERM})
        finally:
            if fd is not None: os.close(fd)
            sock.close()


class P003FailClosedTests(unittest.TestCase):
    """Admission observations only: no real workload or process is started."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='p003-blocked-')
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        source = base / 'source'; source.mkdir()
        registry = base / 'registry.json'
        data = json.dumps({'suites': [{'suite_id': 'ECP-P0-03',
            'implementation_entrypoint': 'control/ops/ecp/verify',
            'offline_workload': sandbox.WORKLOAD}]}).encode()
        registry.write_bytes(data)
        self.source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
        self.registry_fd = os.open(registry, os.O_RDONLY)
        self.addCleanup(os.close, self.source_fd); self.addCleanup(os.close, self.registry_fd)
        st = os.fstat(self.source_fd)
        self.kw = {'source_identity': (st.st_dev, st.st_ino), 'registry_sha256': hashlib.sha256(data).hexdigest(),
                   'source_preverified': True}
        self.registry = registry

    def observe(self, **updates):
        args = dict(self.kw); args.update(updates)
        return sandbox.observe(self.source_fd, self.registry_fd, **args)

    def test_valid_admission_stays_blocked_without_launch_or_filter(self):
        with patch.object(sandbox.subprocess, 'Popen') as popen, \
             patch.object(sandbox.subprocess, 'run') as run, \
             patch.object(sandbox, '_bounded') as bounded, \
             patch.object(sandbox, '_filter') as filtr, \
             patch.object(sandbox, '_sealed') as sealed:
            result = self.observe()
        self.assertEqual((result['status'], result['qualification'], result['product_gate_effect']),
                         ('BLOCKED', 'NOT_RUN', 'NONE'))
        self.assertEqual(result['reason_code'], 'SUPERVISION_UNVERIFIED')
        self.assertEqual(result['admission_checks'], 'CHECKS_COMPLETED_UNVERIFIED')
        self.assertFalse(result['workload_invoked']); self.assertFalse(result['preflight_completed'])
        self.assertEqual((result['stdout_bytes'], result['stderr_bytes']), (b'', b''))
        self.assertEqual(result['capture_state'], 'NOT_CAPTURED')
        for call in (popen, run, bounded, filtr, sealed): call.assert_not_called()
        os.fstat(self.source_fd); os.fstat(self.registry_fd)

    def test_untrusted_or_bad_source_identity_is_rejected(self):
        for change in ({'source_preverified': False}, {'source_identity': (0, 0)}):
            with self.subTest(change=change), patch.object(sandbox.subprocess, 'Popen') as popen:
                result = self.observe(**change)
                self.assertEqual(result['reason_code'], 'ADMISSION_REJECTED')
                self.assertEqual(result['status'], 'BLOCKED'); popen.assert_not_called()

    def test_invalid_registry_digest_and_duplicate_keys_are_rejected(self):
        result = self.observe(registry_sha256='0' * 64)
        self.assertEqual(result['reason_code'], 'ADMISSION_REJECTED')
        data = b'{"suites":[],"suites":[]}'
        self.registry.write_bytes(data)
        result = self.observe(registry_sha256=hashlib.sha256(data).hexdigest())
        self.assertIn('duplicate registry key', result['reason'])
        self.assertEqual(result['status'], 'BLOCKED')

    def test_writable_or_aliased_registry_descriptors_are_rejected(self):
        writable = os.open(self.registry, os.O_RDWR); self.addCleanup(os.close, writable)
        result = sandbox.observe(self.source_fd, writable, **self.kw)
        self.assertEqual(result['reason_code'], 'ADMISSION_REJECTED')
        result = sandbox.observe(self.source_fd, self.source_fd, **self.kw)
        self.assertEqual(result['reason_code'], 'ADMISSION_REJECTED')

    def test_invalid_runtime_budget_does_not_launch(self):
        for change in ({'timeout': 0}, {'timeout': 301}, {'log_limit': 1}, {'log_limit': sandbox.MAX_STREAM+1}):
            with self.subTest(change=change), patch.object(sandbox.subprocess, 'Popen') as popen:
                self.assertEqual(self.observe(**change)['reason_code'], 'ADMISSION_REJECTED'); popen.assert_not_called()

    def test_private_process_helper_is_unconditionally_disabled(self):
        with patch.object(sandbox.subprocess, 'Popen') as popen, patch.object(sandbox.os, 'killpg') as killpg:
            with self.assertRaisesRegex(RuntimeError, 'supervised process lifecycle'):
                sandbox._bounded(['unused'], (), 1, 1024)
        popen.assert_not_called(); killpg.assert_not_called()

    def test_mock_preflight_result_cannot_be_used_to_bypass_block(self):
        fake = {'capture_complete': True, 'exit_code': 0, 'stdout_bytes': b'ECP_P003_PREFLIGHT {}\n',
                'stderr_bytes': b'OK', 'leader_reaped': True, 'group_signal': 'NOT_SENT'}
        with patch.object(sandbox, '_bounded', return_value=fake) as bounded:
            result = self.observe()
        bounded.assert_not_called(); self.assertEqual(result['status'], 'BLOCKED')
        self.assertFalse(result['preflight_completed']); self.assertFalse(result['workload_invoked'])
        self.assertEqual(result['stdout_bytes'], b'')

    def test_environment_does_not_unlock_execution(self):
        with patch.dict(os.environ, {'P003_SUPERVISED':'1', 'ECP_P003_ENABLE':'1'}), \
             patch.object(sandbox.subprocess, 'Popen') as popen:
            result = self.observe()
        self.assertEqual(result['status'], 'BLOCKED'); popen.assert_not_called()

    def test_check_errors_are_unknown_and_invalid_inputs_are_rejected(self):
        for error in (OSError('unavailable'), RecursionError('limit')):
            with self.subTest(error=type(error).__name__), patch.object(sandbox, '_registry', side_effect=error), \
                 patch.object(sandbox.subprocess, 'Popen') as popen:
                result = self.observe()
                self.assertEqual((result['status'], result['reason_code'], result['admission_checks']),
                                 ('BLOCKED', 'ADMISSION_CHECK_UNAVAILABLE', 'UNKNOWN'))
                popen.assert_not_called()
        with patch.object(sandbox, '_registry', side_effect=ValueError('invalid')):
            self.assertEqual(self.observe()['reason_code'], 'ADMISSION_REJECTED')

    def test_common_execution_apis_not_called_by_observe_or_bounded(self):
        # These sentinels cover the named APIs, not every possible process API.
        with patch.object(sandbox.subprocess, 'Popen') as popen, \
             patch.object(sandbox.subprocess, 'run') as run, \
             patch.object(sandbox.os, 'fork') as fork, \
             patch.object(sandbox.os, 'execve') as execve, \
             patch.object(sandbox.os, 'posix_spawn') as spawn, \
             patch.object(sandbox.os, 'system') as system, \
             patch.object(sandbox.os, 'killpg') as killpg:
            self.assertEqual(self.observe()['status'], 'BLOCKED')
            with self.assertRaises(RuntimeError): sandbox._bounded(['unused'], (), 1, 1024)
        for sentinel in (popen, run, fork, execve, spawn, system, killpg): sentinel.assert_not_called()

    def test_duplicate_suite_binding_is_rejected(self):
        data = json.loads(self.registry.read_bytes())
        data['suites'].append(data['suites'][0])
        raw = json.dumps(data).encode(); self.registry.write_bytes(raw)
        result = self.observe(registry_sha256=hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['reason_code'], 'ADMISSION_REJECTED')
        self.assertIn('ambiguous', result['reason'])

    def test_sealed_memory_file_rejects_modification(self):
        # This tests an existing isolated memory helper only; observe never calls it.
        fd = sandbox._sealed(b'fixed', 'test'); self.addCleanup(os.close, fd)
        with self.assertRaises(OSError): os.pwrite(fd, b'x', 0)
        with self.assertRaises(OSError): os.ftruncate(fd, 0)

    def test_filter_construction_is_disabled_before_library_lookup(self):
        with patch.object(sandbox.ctypes.util, 'find_library') as lookup, \
             patch.object(sandbox.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(RuntimeError, 'filter construction blocked'):
                sandbox._filter()
        lookup.assert_not_called(); popen.assert_not_called()

    def test_existing_observe_signature_is_unchanged(self):
        import inspect
        self.assertEqual(list(inspect.signature(sandbox.observe).parameters),
                         ['source_fd','registry_fd','source_identity','registry_sha256','source_preverified','timeout','log_limit'])

    def test_registry_is_only_a_read_only_observation(self):
        data = sandbox._registry(self.registry_fd, self.kw['registry_sha256'])
        self.assertEqual(hashlib.sha256(data).hexdigest(), self.kw['registry_sha256'])
        self.assertEqual(self.observe()['status'], 'BLOCKED')


if __name__ == '__main__':
    unittest.main()

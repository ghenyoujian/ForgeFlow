"""Private synthetic no-clobber tests; NOT a product Gate or identity oracle."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

_spec = importlib.util.spec_from_file_location('candidate_g0_output', Path(__file__).with_name('g0.py'))
g0 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(g0)


class OutputPreservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='g0-output-synthetic-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def rejected(self, output, evidence=()):
        with self.assertRaises(g0.OutputUnavailable):
            g0.write_report_exclusive(output, list(evidence), 'new-data')

    def test_new_output_contents(self):
        output = self.root / 'new.json'
        g0.write_report_exclusive(output, [], 'new-data')
        self.assertEqual(output.read_bytes(), b'new-data')
        self.assertEqual(output.stat().st_mode & 0o077, 0)

    def test_existing_regular_unchanged(self):
        output = self.root / 'old'; output.write_bytes(b'ORIGINAL')
        self.rejected(output); self.assertEqual(output.read_bytes(), b'ORIGINAL')

    def test_hardlink_to_evidence_unchanged(self):
        evidence = self.root / 'input'; evidence.write_bytes(b'ORIGINAL')
        output = self.root / 'hard'; os.link(evidence, output)
        self.rejected(output, [evidence]); self.assertEqual(evidence.read_bytes(), b'ORIGINAL')
        self.assertTrue(os.path.samefile(evidence, output))

    def test_output_symlink_to_existing_file_unchanged(self):
        target = self.root / 'target'; target.write_bytes(b'ORIGINAL')
        output = self.root / 'link'; output.symlink_to(target)
        self.rejected(output); self.assertTrue(output.is_symlink()); self.assertEqual(target.read_bytes(), b'ORIGINAL')

    def test_output_dangling_symlink_is_preserved(self):
        target = self.root / 'absent'; output = self.root / 'link'; output.symlink_to(target)
        self.rejected(output); self.assertTrue(output.is_symlink()); self.assertFalse(target.exists())

    def test_existing_input_same_path_unchanged(self):
        evidence = self.root / 'same'; evidence.write_bytes(b'ORIGINAL')
        self.rejected(evidence, [evidence]); self.assertEqual(evidence.read_bytes(), b'ORIGINAL')

    def test_absent_input_same_path_is_not_created(self):
        evidence = self.root / 'missing'; self.rejected(evidence, [evidence]); self.assertFalse(evidence.exists())

    def test_absent_input_parent_symlink_alias_is_not_created(self):
        directory = self.root / 'directory'; directory.mkdir()
        alias = self.root / 'alias'; alias.symlink_to(directory, target_is_directory=True)
        evidence = directory / 'missing'; self.rejected(alias / 'missing', [evidence]); self.assertFalse(evidence.exists())

    def test_dangling_input_link_to_future_output_is_not_created(self):
        target = self.root / 'future'; evidence = self.root / 'input-link'; evidence.symlink_to(target)
        self.rejected(target, [evidence]); self.assertTrue(evidence.is_symlink()); self.assertFalse(target.exists())

    def test_missing_evidence_used_as_output_parent_is_not_created(self):
        evidence = self.root / 'missing-evidence'
        self.rejected(evidence / 'report.json', [evidence])
        self.assertFalse(evidence.exists())

    def test_ordinary_missing_output_parent_is_not_created(self):
        parent = self.root / 'missing-parent'
        self.rejected(parent / 'report.json')
        self.assertFalse(parent.exists())

    def test_output_is_missing_evidence_ancestor_and_not_created(self):
        output = self.root / 'missing-ancestor'
        self.rejected(output, [output / 'input.json'])
        self.assertFalse(output.exists())

    def test_existing_output_has_precise_noncreation_status(self):
        output = self.root / 'existing'; output.write_bytes(b'ORIGINAL')
        with self.assertRaises(g0.OutputUnavailable) as caught:
            g0.write_report_exclusive(output, [], 'new')
        self.assertEqual(str(caught.exception), 'OUTPUT_ALREADY_EXISTS')
        self.assertEqual(caught.exception.output_state, 'NOT_CREATED_BY_THIS_CALL')
        self.assertEqual(output.read_bytes(), b'ORIGINAL')

    def test_other_open_errors_have_unknown_creation_status(self):
        output = self.root / 'unknown-open'
        with patch.object(g0.os, 'open', side_effect=OSError('synthetic open error')):
            with self.assertRaises(g0.OutputUnavailable) as caught:
                g0.write_report_exclusive(output, [], 'new')
        self.assertEqual(str(caught.exception), 'OUTPUT_CREATE_UNKNOWN')
        self.assertEqual(caught.exception.output_state, 'CREATE_OUTCOME_UNKNOWN')

    def test_conservative_casefold_rejects_distinct_uncreated_names(self):
        output = self.root / 'A'; evidence = self.root / 'a'
        self.rejected(output, [evidence]); self.assertFalse(output.exists())

    def test_short_writes_are_completed(self):
        output = self.root / 'short'; original = os.write
        def short(fd, data): return original(fd, data[:2])
        with patch.object(g0.os, 'write', side_effect=short):
            g0.write_report_exclusive(output, [], 'abcdef')
        self.assertEqual(output.read_bytes(), b'abcdef')

    def test_write_error_keeps_partial_file_and_reports_unknown(self):
        output = self.root / 'partial'; original = os.write; calls = 0
        def partial_then_fail(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1: return original(fd, data[:2])
            raise OSError('synthetic write failure')
        with patch.object(g0.os, 'write', side_effect=partial_then_fail):
            with self.assertRaises(g0.OutputUnavailable) as caught:
                g0.write_report_exclusive(output, [], 'abcdef')
        self.assertEqual(caught.exception.output_state, 'UNKNOWN_PARTIAL')
        self.assertEqual(output.read_bytes(), b'ab')

    def test_fsync_error_keeps_new_file(self):
        output = self.root / 'sync-error'
        with patch.object(g0.os, 'fsync', side_effect=OSError('synthetic fsync failure')):
            with self.assertRaises(g0.OutputUnavailable) as caught:
                g0.write_report_exclusive(output, [], 'abcdef')
        self.assertEqual(caught.exception.output_state, 'UNKNOWN_PARTIAL')
        self.assertEqual(output.read_bytes(), b'abcdef')

    def test_close_error_is_unknown_and_never_retried(self):
        output = self.root / 'close-error'; original = os.close; calls = []
        def close_then_error(fd):
            calls.append(fd); original(fd); raise OSError('synthetic close failure')
        with patch.object(g0.os, 'close', side_effect=close_then_error):
            with self.assertRaises(g0.OutputUnavailable) as caught:
                g0.write_report_exclusive(output, [], 'abcdef')
        self.assertEqual(caught.exception.output_state, 'UNKNOWN_PARTIAL'); self.assertEqual(len(calls), 1)
        self.assertEqual(output.read_bytes(), b'abcdef')

    def test_sequential_second_writer_is_rejected(self):
        output = self.root / 'sequential'
        g0.write_report_exclusive(output, [], 'first')
        self.rejected(output)
        self.assertEqual(output.read_bytes(), b'first')

    def test_output_failure_reports_fail_and_preserves_failure_claim(self):
        argv = ['g0.py', '--evidence', 'input', '--output', 'out']
        out = io.StringIO(); err = io.StringIO()
        with patch.object(sys, 'argv', argv), patch.object(g0.Path, 'exists', return_value=True), \
             patch.object(g0, 'load', return_value={'status': 'FAIL'}), \
             patch.object(g0, 'write_report_exclusive', side_effect=g0.OutputUnavailable('OUTPUT_ALREADY_EXISTS', 'NOT_CREATED_BY_THIS_CALL')), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = g0.main()
        self.assertEqual(code, 10); self.assertEqual(out.getvalue(), '')
        diag = json.loads(err.getvalue()); self.assertEqual(diag['status'], 'FAIL')
        self.assertEqual(diag['evidence_report']['status'], 'FAIL'); self.assertEqual(diag['product_gate_effect'], 'NONE')
        self.assertIn('not independently authenticated', diag['evidence_report']['reason'])
        self.assertEqual(diag['output_status'], 'NOT_CREATED_BY_THIS_CALL')

    def test_strict_utf8_failure_keeps_fail_missing_and_lone_surrogate(self):
        missing = 'missing-' + chr(0xD800)
        argv = ['g0.py', '--evidence', 'failed', '--evidence', missing, '--output', 'out']
        out_bytes = io.BytesIO(); err_bytes = io.BytesIO()
        out = io.TextIOWrapper(out_bytes, encoding='utf-8', errors='strict', write_through=True)
        err = io.TextIOWrapper(err_bytes, encoding='utf-8', errors='strict', write_through=True)
        with patch.object(sys, 'argv', argv), \
             patch.object(g0.Path, 'exists', autospec=True, side_effect=lambda path: str(path) == 'failed'), \
             patch.object(g0, 'load', return_value={'status': 'FAIL'}), \
             patch.object(g0, 'write_report_exclusive', side_effect=g0.OutputUnavailable('OUTPUT_WRITE_OR_CLOSE_UNKNOWN', 'UNKNOWN_PARTIAL')), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = g0.main()
        self.assertEqual(code, 10); self.assertEqual(out_bytes.getvalue(), b'')
        raw = err_bytes.getvalue(); raw.decode('ascii')
        diag = json.loads(raw); self.assertEqual(diag['status'], 'FAIL')
        self.assertEqual(diag['output_status'], 'UNKNOWN_PARTIAL')
        self.assertEqual(diag['evidence_report']['missing'], [missing])
        self.assertEqual(diag['evidence_report']['observed_statuses'], ['FAIL'])
        self.assertIn('not independently authenticated', diag['evidence_report']['reason'])
        self.assertEqual(diag['product_gate_effect'], 'NONE')
        out.detach(); err.detach()

    def test_strict_utf8_successful_report_escapes_lone_surrogate(self):
        output = self.root / 'strict-output.json'
        surrogate = chr(0xD800)
        argv = ['g0.py', '--evidence', 'failed', '--evidence', 'invalid', '--output', str(output)]
        out_bytes = io.BytesIO(); err_bytes = io.BytesIO()
        out = io.TextIOWrapper(out_bytes, encoding='utf-8', errors='strict', write_through=True)
        err = io.TextIOWrapper(err_bytes, encoding='utf-8', errors='strict', write_through=True)
        def fake_load(path):
            return {'status': 'FAIL'} if str(path) == 'failed' else {'status': surrogate}
        with patch.object(sys, 'argv', argv), patch.object(g0.Path, 'exists', return_value=True), \
             patch.object(g0, 'load', side_effect=fake_load), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = g0.main()
        self.assertEqual(code, 10); self.assertEqual(err_bytes.getvalue(), b'')
        file_raw = output.read_bytes(); file_raw.decode('ascii'); out_bytes.getvalue().decode('ascii')
        report = json.loads(file_raw); self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(report['observed_statuses'], ['FAIL', surrogate])
        self.assertEqual(report['product_gate_effect'], 'NONE')
        self.assertEqual(json.loads(out_bytes.getvalue()), report)
        out.detach(); err.detach()

    def test_output_failure_without_fail_is_blocked_and_keeps_report(self):
        argv = ['g0.py', '--evidence', 'okay', '--output', 'out']
        out = io.StringIO(); err = io.StringIO()
        with patch.object(sys, 'argv', argv), patch.object(g0.Path, 'exists', return_value=True), \
             patch.object(g0, 'load', return_value={'status': 'PASS'}), \
             patch.object(g0, 'write_report_exclusive', side_effect=g0.OutputUnavailable('OUTPUT_CREATE_UNKNOWN', 'CREATE_OUTCOME_UNKNOWN')), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = g0.main()
        self.assertEqual(code, 20); self.assertEqual(out.getvalue(), '')
        diag = json.loads(err.getvalue()); self.assertEqual(diag['status'], 'BLOCKED')
        self.assertEqual(diag['output_status'], 'CREATE_OUTCOME_UNKNOWN')
        self.assertEqual(diag['evidence_report']['status'], 'INCONCLUSIVE')
        self.assertEqual(diag['evidence_report']['observed_statuses'], ['PASS'])
        self.assertEqual(diag['product_gate_effect'], 'NONE')

    def test_output_failure_preserves_failure_and_missing_evidence(self):
        argv = ['g0.py', '--evidence', 'failed', '--evidence', 'missing', '--output', 'out']
        out = io.StringIO(); err = io.StringIO()
        with patch.object(sys, 'argv', argv), \
             patch.object(g0.Path, 'exists', autospec=True, side_effect=lambda path: str(path) == 'failed'), \
             patch.object(g0, 'load', return_value={'status': 'FAIL'}), \
             patch.object(g0, 'write_report_exclusive', side_effect=g0.OutputUnavailable('OUTPUT_WRITE_OR_CLOSE_UNKNOWN', 'UNKNOWN_PARTIAL')), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = g0.main()
        self.assertEqual(code, 10); self.assertEqual(out.getvalue(), '')
        diag = json.loads(err.getvalue()); self.assertEqual(diag['status'], 'FAIL')
        self.assertEqual(diag['output_status'], 'UNKNOWN_PARTIAL')
        self.assertEqual(diag['evidence_report']['missing'], ['missing'])
        self.assertEqual(diag['evidence_report']['observed_statuses'], ['FAIL'])
        self.assertEqual(diag['evidence_report']['invalid'], [])
        self.assertIn('not independently authenticated', diag['evidence_report']['reason'])
        self.assertEqual(diag['product_gate_effect'], 'NONE')


if __name__ == '__main__':
    unittest.main()

"""Research-only aggregate claims with in-memory inputs; no Git or workload.

The subject is the repository-relative verifier. No external private candidate
path, source snapshot, database, subprocess or temporary directory is needed.
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


def load_subject():
    path = Path(__file__).resolve().parent.parent / 'verify.py'
    stub = types.ModuleType('source_snapshot')
    stub.DEFAULT_EXCLUDES = ()
    stub.build_manifest = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError('snapshot forbidden'))
    previous = sys.modules.get('source_snapshot')
    module_name = 'r17_aggregate_subject'
    old_subject = sys.modules.get(module_name)
    try:
        sys.modules['source_snapshot'] = stub
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        if previous is None:
            sys.modules.pop('source_snapshot', None)
        else:
            sys.modules['source_snapshot'] = previous
        if old_subject is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = old_subject


verify = load_subject()
SHA = 'a' * 40


class AggregateClaimTests(unittest.TestCase):
    def report(self, inputs, source_sha=SHA):
        root = Path('/synthetic-source')
        paths = [str(root / f'input-{i}.json') for i in range(len(inputs))]
        encoded = {path: json.dumps(value, ensure_ascii=True) for path, value in zip(paths, inputs)}
        trace = {'schema': 'forgeflow.ecp-aggregate-fixture-trace.v1',
                 'test_method': self._testMethodName, 'source_sha': source_sha, 'inputs': inputs}
        def read_input(path, *args, **kwargs):
            if str(path) not in encoded:
                raise AssertionError('unexpected filesystem read')
            return encoded[str(path)]
        args = argparse.Namespace(source_root=str(root), source_sha=source_sha, input=paths, output=None)
        try:
            with patch.object(verify, 'resolve_source_root', return_value=root), \
                 patch.object(Path, 'expanduser', autospec=True, side_effect=lambda path: path), \
                 patch.object(Path, 'resolve', autospec=True, side_effect=lambda path: path), \
                 patch.object(Path, 'read_text', autospec=True, side_effect=read_input), \
                 patch.object(verify, 'git_sha', side_effect=AssertionError('Git forbidden')), \
                 patch.object(verify, 'run_git', side_effect=AssertionError('Git forbidden')), \
                 patch.object(verify.subprocess, 'Popen', side_effect=AssertionError('subprocess forbidden')), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                result, code = verify.aggregate_reports(args)
        except BaseException as exc:
            trace['observation'] = {'kind': 'exception', 'type': type(exc).__name__}
            print(json.dumps(trace, ensure_ascii=True, sort_keys=True), flush=True)
            raise
        trace['observation'] = {'kind': 'returned', 'exit_code': code,
            'status': result.get('status'), 'product_gate_effect': result.get('product_gate_effect'),
            'denominator': result.get('denominator'), 'denominator_scope': result.get('denominator_scope'),
            'checks': result.get('checks')}
        print(json.dumps(trace, ensure_ascii=True, sort_keys=True), flush=True)
        self.assertEqual(json.loads(output.getvalue()), result)
        self.assertEqual(result['product_gate_effect'], 'NONE')
        return result, code

    @staticmethod
    def inputs(report):
        return [row for row in report['checks'] if row['name'].startswith('input:')]

    def assert_pass_claim_unverified(self, report):
        rows = self.inputs(report)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['status'], 'INCONCLUSIVE')
        self.assertEqual(rows[0]['details']['declared_status'], 'PASS')
        self.assertEqual(report['denominator']['passed'], 0)

    def test_legacy_pass_without_denominator_remains_unverified_claim(self):
        report, code = self.report([{'status': 'PASS', 'source_sha': SHA}])
        self.assertEqual((report['status'], code), ('INCONCLUSIVE', 20))
        self.assert_pass_claim_unverified(report)

    def test_zero_inconsistent_and_skipped_denominators_never_count_as_pass(self):
        for denominator in ({'total': 0, 'passed': 0}, {'total': 1, 'passed': 5},
                            {'total': 2, 'passed': 1, 'skipped': 1}):
            with self.subTest(denominator=denominator):
                report, code = self.report([{'status': 'PASS', 'source_sha': SHA, 'denominator': denominator}])
                self.assertEqual((report['status'], code), ('INCONCLUSIVE', 20))
                self.assert_pass_claim_unverified(report)

    def test_required_nested_unrun_or_blocked_never_counts_as_pass(self):
        for state in ('NOT_RUN', 'BLOCKED', 'INCONCLUSIVE', 'SKIPPED'):
            with self.subTest(state=state):
                report, code = self.report([{'status': 'PASS', 'source_sha': SHA,
                    'checks': [{'name': 'required', 'status': state}]}])
                self.assertEqual((report['status'], code), ('INCONCLUSIVE', 20))
                self.assert_pass_claim_unverified(report)

    def test_local_pass_with_nonzero_denominator_and_not_run_qualification_is_a_claim(self):
        doc = {'status': 'PASS', 'source_sha': SHA, 'qualification': 'NOT_RUN',
               'reason': 'local readback observed', 'denominator': {'total': 2, 'passed': 2}}
        report, code = self.report([doc])
        self.assertEqual((report['status'], code), ('INCONCLUSIVE', 20))
        self.assert_pass_claim_unverified(report)
        details = self.inputs(report)[0]['details']
        self.assertEqual(details['declared_reason'], doc['reason'])
        self.assertEqual(details['declared_qualification'], 'NOT_RUN')
        self.assertTrue(details['declared_reason_recorded'])
        self.assertTrue(details['declared_qualification_recorded'])

    def test_status_fields_are_preserved_as_separately_scoped_claims(self):
        doc = {'status': 'PASS', 'overall_status': 'NOT_RUN', 'gate_status': 'FAIL', 'source_sha': SHA}
        report, code = self.report([doc])
        self.assertEqual((report['status'], code), ('INCONCLUSIVE', 20))
        self.assert_pass_claim_unverified(report)
        self.assertEqual(self.inputs(report)[0]['details']['declared_status_fields'],
                         {'status': 'PASS', 'overall_status': 'NOT_RUN', 'gate_status': 'FAIL'})

    def test_unresolved_top_level_states_remain_declared(self):
        for state in ('BLOCKED', 'NOT_RUN', 'INCONCLUSIVE'):
            with self.subTest(state=state):
                report, code = self.report([{'status': state, 'source_sha': SHA, 'reason': 'reported only'}])
                self.assertEqual((report['status'], code), (state, 20))
                row = self.inputs(report)[0]
                self.assertEqual((row['status'], row['details']['declared_status']), (state, state))
                self.assertEqual(row['details']['declared_reason'], 'reported only')
                self.assertEqual(report['denominator']['passed'], 0)

    def test_failure_and_not_run_are_both_preserved(self):
        report, code = self.report([{'status': 'FAIL', 'source_sha': SHA},
                                    {'status': 'NOT_RUN', 'source_sha': SHA}])
        self.assertEqual((report['status'], code), ('FAIL', 10))
        self.assertEqual([r['status'] for r in self.inputs(report)], ['FAIL', 'NOT_RUN'])
        self.assertEqual(report['denominator']['passed'], 0)

    def test_source_mismatch_remains_failure_without_pass_count(self):
        report, code = self.report([{'status': 'PASS', 'source_sha': 'b' * 40}])
        self.assertEqual((report['status'], code), ('FAIL', 10))
        self.assertEqual(report['denominator']['passed'], 0)
        self.assertTrue(any(r['name'] == 'source_binding' and r['status'] == 'FAIL' for r in report['checks']))

    def test_explicit_source_sha_does_not_invoke_git(self):
        report, code = self.report([{'status': 'PASS', 'source_sha': SHA}], source_sha=SHA)
        self.assertEqual((report['status'], code), ('INCONCLUSIVE', 20))
        self.assert_pass_claim_unverified(report)

    def test_no_inputs_is_not_run_without_git(self):
        report, code = self.report([], source_sha=SHA)
        self.assertEqual((report['status'], code), ('NOT_RUN', 20))
        self.assertEqual(report['denominator']['total'], 0)

    def test_aggregate_denominator_scope_is_not_nested_test_count(self):
        report, _ = self.report([{'status': 'NOT_RUN', 'source_sha': SHA,
                                  'denominator': {'total': 50, 'not_run': 50}}])
        self.assertEqual(report['denominator_scope'], 'input_claims_and_source_binding_diagnostics')
        self.assertEqual(report['denominator']['total'], 1)

    def test_unserializable_or_oversized_text_claims_are_not_interpreted(self):
        for value in ({'reason': ['nested']}, {'reason': 'x' * 4097},
                      {'reason': '\ud800'}, {'qualification': ['NOT_RUN']},
                      {'qualification': '\ud800'}):
            with self.subTest(value=value):
                report, code = self.report([{'status': 'PASS', 'source_sha': SHA, **value}])
                self.assertEqual((report['status'], code), ('INCONCLUSIVE', 20))
                self.assert_pass_claim_unverified(report)
                details = self.inputs(report)[0]['details']
                key = 'declared_reason_recorded' if 'reason' in value else 'declared_qualification_recorded'
                self.assertFalse(details[key])


if __name__ == '__main__':
    unittest.main()
